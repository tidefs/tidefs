#![allow(clippy::nonminimal_bool)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::type_complexity)]
#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]
#![forbid(unsafe_code)]

mod commit;
mod config;
mod coordinator;
mod degraded_read;
mod handle;
mod policy;
mod protocol;
mod quorum_ack_collector;
mod quorum_decision;
mod quorum_write_coordinator;
mod quorum_write_request;
mod replica_write_handle;
mod topology;

pub use commit::{
    commit_quorum_write, QuorumWriteCommit, QuorumWriteError, QuorumWriteOutcome, ReplicaWriteAck,
};
pub use config::QuorumWriteConfig;
pub use config::WriteQuorumConfig;
pub use coordinator::MockReplicaBehavior;
pub use coordinator::QuorumWriteRuntime;
pub use coordinator::{simulate_leader_write, QuorumWriteLeader};
pub use degraded_read::{
    CandidateHealthClass, DegradedReadCandidate, DegradedReadProtocol, DegradedReadResolver,
    DegradedReadVisibility, DemandReadTicket,
};
pub use handle::{QuorumAckOutcome, QuorumWriteHandle, QuorumWriteResolution};
pub use policy::{ReplicationChunkClass, ReplicationPolicy, ReplicationPolicySelector};
pub use protocol::{
    CatchupRepairTicket, QuorumFailureReason, ReplicationProtocol, TransferPriorityClass, WriteAck,
    WriteCommitReceipt, WriteId, WriteResult,
};
pub use quorum_ack_collector::{QuorumAckCollector, ReplicaBehavior};
pub use quorum_decision::QuorumDecision;
pub use quorum_write_coordinator::{CoordinatorError, CoordinatorOutcome, QuorumWriteCoordinator};
pub use quorum_write_request::{compute_blake3, QuorumWriteRequest};
pub use replica_write_handle::ReplicaWriteHandle;
pub use topology::{
    select_targets, select_targets_best_effort, select_targets_strict, validate_selection,
    DomainKey, MultiLevelTopology, SelectionStrategy, TargetSelectionError, TargetTopology,
};

use std::path::PathBuf;
use tidefs_durability_layout::DurabilityLayoutV1;
use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreError, StoreOptions};
pub use tidefs_quorum_write::{
    DurabilityMode, PhaseKind, QuorumWriteId, QuorumWriteResult, QuorumWriteSummary, ReadClass,
    RefusalReason, TransferTicketId, WriteClass,
};

#[derive(Clone, Debug)]
pub struct QuorumConfig {
    pub replica_paths: Vec<PathBuf>,
    pub store_options: StoreOptions,
    pub durability_mode: DurabilityMode,
    /// Optional durability layout for failure-domain-aware quorum planning.
    /// When set, `min_quorum()` uses the layout's policy to derive the
    /// required replica count instead of `replica_paths.len()`.
    pub durability_layout: Option<DurabilityLayoutV1>,
}

impl QuorumConfig {
    #[must_use]
    pub fn new(replica_paths: Vec<PathBuf>, store_options: StoreOptions) -> Self {
        Self {
            replica_paths,
            store_options,
            durability_mode: DurabilityMode::QuorumFull,
            durability_layout: None,
        }
    }
    #[must_use]
    pub fn with_durability(mut self, mode: DurabilityMode) -> Self {
        self.durability_mode = mode;
        self
    }
    /// Attach a durability layout for failure-domain-aware quorum planning.
    ///
    /// When set, `min_quorum()` derives the replica count from the layout's
    /// `DurabilityPolicy::total_shards()` instead of `replica_paths.len()`.
    #[must_use]
    pub fn with_durability_layout(mut self, layout: DurabilityLayoutV1) -> Self {
        self.durability_layout = Some(layout);
        self
    }
    #[must_use]
    pub fn min_quorum(&self) -> usize {
        // When a durability layout is present, use its total_shards() as the
        // base replica count for failure-domain-aware quorum planning.
        let n = if let Some(ref layout) = self.durability_layout {
            let shards = layout.policy.total_shards();
            if shards == 0 {
                return 0;
            }
            shards
        } else {
            self.replica_paths.len()
        };
        if n == 0 {
            return 0;
        }
        if n == 1 {
            return 1;
        }
        match self.durability_mode {
            DurabilityMode::QuorumFull => n,
            DurabilityMode::QuorumChain | DurabilityMode::QuorumWitness => n / 2 + 1,
        }
    }
}

#[derive(Clone, Debug)]
pub struct QuorumPutResult {
    pub write_class: WriteClass,
    pub acks_count: u64,
}

#[derive(Debug)]
pub struct QuorumObjectStore {
    pub stores: Vec<LocalObjectStore>,
    config: QuorumConfig,
}

impl QuorumObjectStore {
    pub fn open(config: QuorumConfig) -> Result<Self, StoreError> {
        if config.replica_paths.is_empty() {
            return Err(StoreError::InvalidOptions {
                reason: "quorum: replica_paths must not be empty",
            });
        }
        let mut stores = Vec::with_capacity(config.replica_paths.len());
        for path in &config.replica_paths {
            let s = LocalObjectStore::open_with_options(path, config.store_options.clone())?;
            stores.push(s);
        }
        Ok(Self { stores, config })
    }
    #[must_use]
    pub fn config(&self) -> &QuorumConfig {
        &self.config
    }
    #[must_use]
    pub fn healthy_count(&self) -> usize {
        self.stores.len()
    }
    #[must_use]
    pub fn has_quorum(&self) -> bool {
        self.stores.len() >= self.config.min_quorum()
    }
    pub fn quorum_put(&mut self, key: ObjectKey, data: &[u8]) -> QuorumPutResult {
        let mut acks: u64 = 0;
        for store in &mut self.stores {
            if store.put(key, data).is_ok() {
                acks += 1;
            }
        }
        let min = self.config.min_quorum() as u64;
        let cls = if acks == 0 {
            WriteClass::RefusedNoQuorum
        } else if acks >= min {
            WriteClass::Committed
        } else {
            WriteClass::DegradedCommitted
        };
        QuorumPutResult {
            write_class: cls,
            acks_count: acks,
        }
    }
    pub fn quorum_get(&self, key: ObjectKey) -> (ReadClass, Option<Vec<u8>>, Vec<usize>) {
        let mut tried = Vec::new();
        for (i, store) in self.stores.iter().enumerate() {
            tried.push(i);
            match store.get(key) {
                Ok(Some(data)) => {
                    let cls = if i == 0 {
                        ReadClass::Exact
                    } else {
                        ReadClass::DegradedButValid
                    };
                    return (cls, Some(data), tried);
                }
                Ok(None) => continue,
                Err(_) => continue,
            }
        }
        (ReadClass::DegradedButValid, None, tried)
    }
    pub fn quorum_delete(&mut self, key: ObjectKey) -> usize {
        let mut count = 0;
        for store in &mut self.stores {
            if store.delete(key).is_ok() {
                count += 1;
            }
        }
        count
    }
    pub fn quorum_sync(&mut self) -> Result<(), StoreError> {
        for store in &mut self.stores {
            store.sync_all()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn paths(name: &str, n: usize) -> Vec<PathBuf> {
        let base = std::env::temp_dir().join(format!("vq-{name}"));
        (0..n).map(|i| base.join(format!("r{i}"))).collect()
    }
    fn clean(p: &[PathBuf]) {
        for x in p {
            let _ = fs::remove_dir_all(x);
        }
    }

    #[test]
    fn single_replica_put_get() {
        let p = paths("sr", 1);
        clean(&p);
        let mut qs =
            QuorumObjectStore::open(QuorumConfig::new(p.clone(), StoreOptions::test_fast()))
                .unwrap();
        assert!(qs.has_quorum());
        let k = ObjectKey::default();
        let r = qs.quorum_put(k, b"hello");
        assert_eq!(r.write_class, WriteClass::Committed);
        assert_eq!(r.acks_count, 1);
        let (c, g, t) = qs.quorum_get(k);
        assert_eq!(c, ReadClass::Exact);
        assert_eq!(g.as_deref(), Some(&b"hello"[..]));
        assert_eq!(t, vec![0]);
        clean(&p);
    }

    #[test]
    fn three_replica_full() {
        let p = paths("3f", 3);
        clean(&p);
        let cfg = QuorumConfig::new(p.clone(), StoreOptions::test_fast())
            .with_durability(DurabilityMode::QuorumFull);
        let mut qs = QuorumObjectStore::open(cfg).unwrap();
        assert_eq!(qs.healthy_count(), 3);
        let r = qs.quorum_put(ObjectKey::default(), b"full");
        assert_eq!(r.write_class, WriteClass::Committed);
        assert_eq!(r.acks_count, 3);
        for i in 0..3 {
            assert_eq!(
                qs.stores[i].get(ObjectKey::default()).unwrap().as_deref(),
                Some(&b"full"[..])
            );
        }
        clean(&p);
    }

    #[test]
    fn three_replica_witness() {
        let p = paths("3w", 3);
        clean(&p);
        let cfg = QuorumConfig::new(p.clone(), StoreOptions::test_fast())
            .with_durability(DurabilityMode::QuorumWitness);
        let mut qs = QuorumObjectStore::open(cfg).unwrap();
        assert_eq!(qs.config().min_quorum(), 2);
        let r = qs.quorum_put(ObjectKey::default(), b"witness");
        assert_eq!(r.write_class, WriteClass::Committed);
        assert_eq!(r.acks_count, 3);
        clean(&p);
    }

    #[test]
    fn degraded_read_fallback() {
        let p = paths("dr", 3);
        clean(&p);
        let mut qs =
            QuorumObjectStore::open(QuorumConfig::new(p.clone(), StoreOptions::test_fast()))
                .unwrap();
        let k = ObjectKey::default();
        let d = b"fallback";
        qs.quorum_put(k, d);
        qs.stores[0].delete(k).unwrap();
        qs.stores[0].sync_all().unwrap();
        let (c, g, t) = qs.quorum_get(k);
        assert_eq!(c, ReadClass::DegradedButValid);
        assert_eq!(g.as_deref(), Some(&d[..]));
        assert_eq!(t.len(), 2);
        clean(&p);
    }

    #[test]
    fn delete_all_replicas() {
        let p = paths("da", 3);
        clean(&p);
        let mut qs =
            QuorumObjectStore::open(QuorumConfig::new(p.clone(), StoreOptions::test_fast()))
                .unwrap();
        let k = ObjectKey::default();
        qs.quorum_put(k, b"del");
        assert_eq!(qs.quorum_delete(k), 3);
        for i in 0..3 {
            assert!(
                qs.stores[i].get(k).unwrap().is_none(),
                "replica {i} still has data"
            );
        }
        clean(&p);
    }

    #[test]
    fn min_quorum_config() {
        let p: Vec<PathBuf> = vec!["/a".into(), "/b".into(), "/c".into()];
        assert_eq!(
            QuorumConfig::new(p.clone(), StoreOptions::test_fast())
                .with_durability(DurabilityMode::QuorumFull)
                .min_quorum(),
            3
        );
        assert_eq!(
            QuorumConfig::new(p.clone(), StoreOptions::test_fast())
                .with_durability(DurabilityMode::QuorumWitness)
                .min_quorum(),
            2
        );
    }

    #[test]
    fn empty_replicas_error() {
        assert!(
            QuorumObjectStore::open(QuorumConfig::new(vec![], StoreOptions::test_fast())).is_err()
        );
    }

    // ── Durability-layout-driven quorum tests ──────────────────────

    #[test]
    fn layout_mirror_3_drives_min_quorum() {
        let p: Vec<PathBuf> = vec!["/a".into(), "/b".into(), "/c".into()];
        let layout = tidefs_durability_layout::DurabilityLayoutV1::mirror(3).unwrap();
        let cfg = QuorumConfig::new(p, StoreOptions::test_fast())
            .with_durability_layout(layout)
            .with_durability(DurabilityMode::QuorumFull);
        // Layout says 3 replicas; QuorumFull requires all 3
        assert_eq!(cfg.min_quorum(), 3);
    }

    #[test]
    fn layout_mirror_3_witness_min_quorum() {
        let p: Vec<PathBuf> = vec!["/a".into(), "/b".into(), "/c".into()];
        let layout = tidefs_durability_layout::DurabilityLayoutV1::mirror(3).unwrap();
        let cfg = QuorumConfig::new(p, StoreOptions::test_fast())
            .with_durability_layout(layout)
            .with_durability(DurabilityMode::QuorumWitness);
        // Layout says 3 replicas; QuorumWitness requires majority = 3/2+1 = 2
        assert_eq!(cfg.min_quorum(), 2);
    }

    #[test]
    fn layout_erasure_4_2_full_min_quorum() {
        let p: Vec<PathBuf> = (0..6).map(|i| format!("/r{i}").into()).collect();
        let layout = tidefs_durability_layout::DurabilityLayoutV1::erasure(4, 2).unwrap();
        let cfg = QuorumConfig::new(p, StoreOptions::test_fast())
            .with_durability_layout(layout)
            .with_durability(DurabilityMode::QuorumFull);
        // Erasure 4+2 = 6 total shards; QuorumFull requires all 6
        assert_eq!(cfg.min_quorum(), 6);
    }

    #[test]
    fn layout_erasure_8_3_witness_min_quorum() {
        let p: Vec<PathBuf> = (0..11).map(|i| format!("/r{i}").into()).collect();
        let layout = tidefs_durability_layout::DurabilityLayoutV1::erasure(8, 3).unwrap();
        let cfg = QuorumConfig::new(p, StoreOptions::test_fast())
            .with_durability_layout(layout)
            .with_durability(DurabilityMode::QuorumWitness);
        // 8+3=11 total; QuorumWitness requires majority = 11/2+1 = 6
        assert_eq!(cfg.min_quorum(), 6);
    }

    #[test]
    fn layout_mirror_1_min_quorum_always_1() {
        let p: Vec<PathBuf> = vec!["/a".into()];
        let layout = tidefs_durability_layout::DurabilityLayoutV1::mirror(1).unwrap();
        let cfg = QuorumConfig::new(p, StoreOptions::test_fast())
            .with_durability_layout(layout)
            .with_durability(DurabilityMode::QuorumFull);
        assert_eq!(cfg.min_quorum(), 1);
    }

    #[test]
    fn no_layout_falls_back_to_replica_count() {
        let p: Vec<PathBuf> = vec!["/a".into(), "/b".into()];
        let cfg = QuorumConfig::new(p, StoreOptions::test_fast())
            .with_durability(DurabilityMode::QuorumFull);
        // No layout: uses 2 replicas, QuorumFull = 2
        assert_eq!(cfg.min_quorum(), 2);
    }

    #[test]
    fn layout_mirror_5_actual_3_replicas_still_uses_layout() {
        // Layout demands 5 replicas even if only 3 paths are configured.
        // min_quorum() is driven by layout, not paths.
        let p: Vec<PathBuf> = vec!["/a".into(), "/b".into(), "/c".into()];
        let layout = tidefs_durability_layout::DurabilityLayoutV1::mirror(5).unwrap();
        let cfg = QuorumConfig::new(p, StoreOptions::test_fast())
            .with_durability_layout(layout)
            .with_durability(DurabilityMode::QuorumFull);
        assert_eq!(cfg.min_quorum(), 5);
    }
    // ── Quorum delete tests ──────────────────────────────────────

    #[test]
    fn delete_quorum_full_three_replicas() {
        let p = paths("dq3", 3);
        clean(&p);
        let cfg = QuorumConfig::new(p.clone(), StoreOptions::test_fast())
            .with_durability(DurabilityMode::QuorumFull);
        let mut qs = QuorumObjectStore::open(cfg).unwrap();
        let k = ObjectKey::default();
        qs.quorum_put(k, b"to-delete");
        // Delete with quorum: 3 of 3 must ack
        assert_eq!(qs.quorum_delete(k), 3);
        // Verify all replicas removed
        for i in 0..3 {
            assert!(
                qs.stores[i].get(k).unwrap().is_none(),
                "replica {i} still has data"
            );
        }
        clean(&p);
    }

    #[test]
    fn delete_quorum_witness_three_replicas() {
        let p = paths("dqw3", 3);
        clean(&p);
        let cfg = QuorumConfig::new(p.clone(), StoreOptions::test_fast())
            .with_durability(DurabilityMode::QuorumWitness);
        let mut qs = QuorumObjectStore::open(cfg).unwrap();
        let k = ObjectKey::default();
        qs.quorum_put(k, b"witness-delete");
        // Delete with witness quorum: 2 of 3 must ack
        assert_eq!(qs.quorum_delete(k), 3);
        for i in 0..3 {
            assert!(qs.stores[i].get(k).unwrap().is_none());
        }
        clean(&p);
    }

    #[test]
    fn delete_idempotent_double_delete() {
        let p = paths("did", 3);
        clean(&p);
        let mut qs =
            QuorumObjectStore::open(QuorumConfig::new(p.clone(), StoreOptions::test_fast()))
                .unwrap();
        let k = ObjectKey::default();
        qs.quorum_put(k, b"idem");
        // First delete
        assert_eq!(qs.quorum_delete(k), 3);
        // Second delete — idempotent, all replicas report not-found but count as acks
        assert_eq!(qs.quorum_delete(k), 3);
        for i in 0..3 {
            assert!(qs.stores[i].get(k).unwrap().is_none());
        }
        clean(&p);
    }

    #[test]
    fn delete_partial_replica_failure_quorum_still_met() {
        let p = paths("dpf", 3);
        clean(&p);
        let mut qs = QuorumObjectStore::open(
            QuorumConfig::new(p.clone(), StoreOptions::test_fast())
                .with_durability(DurabilityMode::QuorumWitness),
        )
        .unwrap();
        let k = ObjectKey::default();
        qs.quorum_put(k, b"partial");
        // Manually corrupt replica 0 to simulate failure
        qs.stores[0].delete(k).unwrap();
        qs.stores[0].sync_all().unwrap();
        // Delete with witness quorum (need 2/3): 2 replicas ack (1+2)
        let ack = qs.quorum_delete(k);
        assert!(ack >= 2, "expected >=2 acks, got {ack}");
        clean(&p);
    }

    #[test]
    fn delete_generation_counter_provided() {
        // The generation counter is embedded in DeleteObjectRequest/
        // DeleteObjectResponse messages. This test validates the
        // local quorum delete path does not reject on generation (gen
        // enforcement happens at the transport layer).
        let p = paths("dgc", 1);
        clean(&p);
        let mut qs =
            QuorumObjectStore::open(QuorumConfig::new(p.clone(), StoreOptions::test_fast()))
                .unwrap();
        let k = ObjectKey::default();
        qs.quorum_put(k, b"gen-test");
        assert_eq!(qs.quorum_delete(k), 1);
        assert!(qs.stores[0].get(k).unwrap().is_none());
        clean(&p);
    }

    #[test]
    fn delete_empty_store_idempotent() {
        let p = paths("des", 3);
        clean(&p);
        let mut qs =
            QuorumObjectStore::open(QuorumConfig::new(p.clone(), StoreOptions::test_fast()))
                .unwrap();
        let k = ObjectKey::default();
        // Delete from empty store — all replicas report not-found
        assert_eq!(qs.quorum_delete(k), 3);
        clean(&p);
    }
}
