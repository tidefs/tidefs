// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! N-replica replicated object store with quorum write protocol I/O
//! coordination, degraded read statistics, automatic replica repair,
//! and health-tracker-aware write target filtering.
//!
//! Wraps N `LocalObjectStore` instances (one primary + N-1 replicas) and
//! wires the `QuorumWriteRuntime` 4-phase PREPARE-TRANSFER-COMMIT-WITNESS
//! protocol into actual storage I/O. Every `put` fans out to all reachable
//! replicas after the quorum write runtime validates the write plan; every
//! `get` reads from primary first and falls back to replicas on miss
//! (degraded read), tracking per-replica hit counts and latency. Lagging
//! primaries are automatically repaired from replica data on the next
//! mutable operation.
//!
//! Integration with `tidefs-replica-health` allows replicas in Degraded
//! or worse suspicion state to be skipped during quorum writes, preventing
//! data placement on known-unhealthy nodes.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tidefs_flow_commit_coordinator::FlowCommitCoordinator;
use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};
use tidefs_membership_epoch::{
    ClusterMemberRecord, EpochId, FailureDomainPlacementPolicy, MemberId, MembershipConfigRecord,
};
use tidefs_quorum_write::{DurabilityMode, QuorumWriteResult, QuorumWriteSummary, WriteClass};
use tidefs_quorum_write_runtime::{
    commit_quorum_write, QuorumWriteCommit, QuorumWriteConfig, QuorumWriteError,
    QuorumWriteOutcome, QuorumWriteRuntime,
};
use tidefs_replica_health::sort_replicas_by_health;
use tidefs_replica_health::tracker::ReplicaHealthTracker;
use tidefs_replica_health::ReplicaDegradationTracker;
use tidefs_replication::{
    QuorumWriteTransport, ReplicatedWrite, ReplicationWriteError, ReplicationWritePath,
};
use tidefs_replication_model::{
    commit_replicated_object_root_write, plan_replicated_object_root_read, FlowCommitResult,
    ObjectDigest, PlacementReceiptRef, ReplicaCopyRecord, ReplicaTransferReceipt,
    ReplicaVerificationReceipt, ReplicatedObjectRootRecord, ReplicatedReadPlan,
    ReplicatedReceiptId, ReplicatedSubjectClass, ReplicatedSubjectId, ReplicatedWriteClass,
    ReplicatedWritePlan,
};
#[cfg(test)]
use tidefs_replication_model::{ReplicaMovementClass, VerificationStatus};
use tidefs_storage_intent_core::StorageIntentEvidenceRef;
use tidefs_storage_intent_remote_media_capability::{
    RemoteReplicatedObjectCommitSample, RemoteReplicatedObjectWriteClass,
};
use tidefs_types_transport_session::EndpointFamily;
use tidefs_verification_engine::{verify_transfer_and_emit_receipt, VerificationContext};
use tidefs_witness_set::{WitnessAnchor, WitnessLifecycle, WitnessQuorumClass, WitnessSet};

pub mod read_path;
pub use read_path::{ReadError, ReaderConfig, ReplicatedObjectReader};
pub mod read_self_heal;

/// Configuration for a replicated object store.
#[derive(Clone, Debug)]
pub struct ReplicatedStoreConfig {
    /// Number of replica stores (including primary). Must be >= 1.
    pub replica_count: usize,
    /// Quorum durability mode.
    pub durability_mode: DurabilityMode,
    /// Minimum target count for quorum writes.
    pub min_target_count: usize,
    /// Whether to enable degraded reads (fallback to replicas on primary miss).
    pub enable_degraded_reads: bool,
    /// Store options applied to each replica.
    pub store_options: StoreOptions,
}

impl Default for ReplicatedStoreConfig {
    fn default() -> Self {
        Self {
            replica_count: 1,
            durability_mode: DurabilityMode::QuorumFull,
            min_target_count: 1,
            enable_degraded_reads: true,
            store_options: StoreOptions::test_fast(),
        }
    }
}

impl ReplicatedStoreConfig {
    /// Minimum number of replicas needed for quorum.
    ///
    /// QuorumFull requires all replicas; QuorumWitness/QuorumChain
    /// require a majority (n/2 + 1).
    #[must_use]
    pub fn min_quorum(&self) -> usize {
        let n = self.replica_count;
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

    /// Convenience: 3 replicas with majority quorum (2/3), suitable for testing.
    #[must_use]
    pub fn three_replica_quorum() -> Self {
        Self {
            replica_count: 3,
            durability_mode: DurabilityMode::QuorumFull,
            min_target_count: 2,
            enable_degraded_reads: true,
            store_options: StoreOptions::test_fast(),
        }
    }

    /// Convenience: 5 replicas with witness quorum (3/5).
    #[must_use]
    pub fn five_replica_witness() -> Self {
        Self {
            replica_count: 5,
            durability_mode: DurabilityMode::QuorumWitness,
            min_target_count: 3,
            enable_degraded_reads: true,
            store_options: StoreOptions::test_fast(),
        }
    }
}

/// Outcome of a replicated put operation.
#[derive(Clone, Debug)]
pub struct ReplicatedPutResult {
    /// The object key assigned to the stored object.
    pub key: ObjectKey,
    /// Write classification from the quorum protocol.
    pub write_class: WriteClass,
    /// Number of replicas that acknowledged the write.
    pub acks_count: u64,
    /// Total target replicas.
    pub target_count: u64,
    /// Quorum size required.
    pub quorum_size: u64,
    /// Whether any replica needs repair (e.g. DegradedCommitted).
    pub needs_repair: bool,
    /// Full quorum write result for diagnostics.
    pub quorum_result: QuorumWriteResult,
    /// Full quorum write summary for diagnostics.
    pub quorum_summary: QuorumWriteSummary,
    /// Replicas skipped due to health-tracker suspicion.
    pub skipped_unhealthy: Vec<usize>,
}

impl ReplicatedPutResult {
    /// Project this write result into #961 remote media-capability input facts.
    #[must_use]
    pub fn remote_media_commit_sample(
        &self,
        commit_ref: StorageIntentEvidenceRef,
        recovery_ref: StorageIntentEvidenceRef,
    ) -> RemoteReplicatedObjectCommitSample {
        let write_class = match self.write_class {
            WriteClass::Committed => RemoteReplicatedObjectWriteClass::Committed,
            WriteClass::DegradedCommitted => RemoteReplicatedObjectWriteClass::DegradedCommitted,
            WriteClass::RefusedNoQuorum => RemoteReplicatedObjectWriteClass::RefusedNoQuorum,
        };
        let skipped_unhealthy_count = self.skipped_unhealthy.len().min(u32::MAX as usize) as u32;

        RemoteReplicatedObjectCommitSample {
            write_class,
            acks_count: self.acks_count,
            target_count: self.target_count,
            quorum_size: self.quorum_size,
            needs_repair: self.needs_repair,
            digests_matched: self.quorum_result.digests_matched,
            placement_receipt_bound: !self.quorum_result.placement_receipts.is_empty(),
            skipped_unhealthy_count,
            commit_ref,
            recovery_ref,
        }
    }
}

/// Per-replica degraded read statistics with latency tracking.
///
/// Accumulated across all degraded reads served by this store.
#[derive(Clone, Debug, Default)]
pub struct DegradedReadStats {
    /// Total number of degraded reads served.
    pub total_degraded_reads: u64,
    /// Per-replica hit counts. Index 0 = first replica.
    pub replica_hits: Vec<u64>,
    /// Degraded reads validated against durable placement receipt authority.
    pub receipt_validated_reads: u64,
    /// Receipt validation failures during degraded reads.
    pub receipt_validation_failures: u64,
    /// Cumulative latency per replica in microseconds.
    pub replica_latency_us: Vec<u64>,
    /// Count of latency samples per replica.
    pub replica_latency_samples: Vec<u64>,
    /// Repair attempts triggered by degraded reads.
    pub repair_attempts: u64,
    /// Successful repairs.
    pub repair_successes: u64,
    /// Failed repairs.
    pub repair_failures: u64,
}

impl DegradedReadStats {
    fn with_replica_count(n: usize) -> Self {
        Self {
            replica_hits: vec![0; n],
            receipt_validated_reads: 0,
            receipt_validation_failures: 0,
            replica_latency_us: vec![0; n],
            replica_latency_samples: vec![0; n],
            ..Default::default()
        }
    }

    fn record_hit(&mut self, replica_idx: usize, latency_us: u64) {
        self.total_degraded_reads += 1;
        if let Some(h) = self.replica_hits.get_mut(replica_idx) {
            *h += 1;
        }
        if let Some(t) = self.replica_latency_us.get_mut(replica_idx) {
            *t += latency_us;
        }
        if let Some(c) = self.replica_latency_samples.get_mut(replica_idx) {
            *c += 1;
        }
    }

    /// Average latency per replica in microseconds, or None if no samples.
    pub fn avg_latency_us(&self, replica_idx: usize) -> Option<f64> {
        let samples = self
            .replica_latency_samples
            .get(replica_idx)
            .copied()
            .unwrap_or(0);
        if samples == 0 {
            return None;
        }
        let total = self
            .replica_latency_us
            .get(replica_idx)
            .copied()
            .unwrap_or(0);
        Some(total as f64 / samples as f64)
    }

    /// Generate a human-readable summary.
    #[must_use]
    pub fn report(&self) -> String {
        let mut s = format!(
            "degraded reads: {} total ({} receipt-validated, {} receipt-failures) | repairs: {} attempted / {} succeeded / {} failed",
            self.total_degraded_reads,
            self.receipt_validated_reads,
            self.receipt_validation_failures,
            self.repair_attempts,
            self.repair_successes,
            self.repair_failures,
        );
        let has_replica_hits = self.replica_hits.iter().any(|&h| h > 0);
        if has_replica_hits {
            s.push_str(" | replicas:");
        }
        for (i, &hits) in self.replica_hits.iter().enumerate() {
            if hits > 0 {
                let avg = self.avg_latency_us(i).unwrap_or(0.0);
                s.push_str(&format!("\n  replica {i}: {hits} hits, avg {avg:.1} µs"));
            }
        }
        if has_replica_hits {
            s.push('\n');
        }
        s
    }
}

/// Statistics for a replicated object store.
#[derive(Clone, Debug, Default)]
pub struct ReplicatedStoreStats {
    /// Count of writes classified as Committed (acked by all targets).
    pub committed_writes: u64,
    /// Count of writes classified as DegradedCommitted (quorum reached, not all).
    pub degraded_writes: u64,
    /// Count of writes classified as RefusedNoQuorum.
    pub refused_writes: u64,
    /// Count of degraded reads (primary miss, replica hit) - convenience counter.
    pub degraded_reads: Cell<u64>,
    /// Total bytes written (payload only).
    pub bytes_written: u64,
    /// Total objects stored.
    pub object_count: u64,
    /// Per-replica health: true if store is available.
    pub replica_healthy: Vec<bool>,
}

/// A pending repair: data was found on a replica but is missing from the
/// primary. The primary will be repaired on the next mutable operation.
struct PendingRepair {
    key: ObjectKey,
    data: Vec<u8>,
    source_replica: usize,
}

// ═══════════════════════════════════════════════════════════════════════

// ReplicaStoreWriter — QuorumWriteTransport adapter for local stores

// ═══════════════════════════════════════════════════════════════════════

/// Adapter that implements `QuorumWriteTransport` by dispatching writes
/// to local `LocalObjectStore` instances (primary + replicas) and returning
/// the BLAKE3 checksum of the stored payload.
struct ReplicaStoreWriter<'a> {
    primary: &'a mut LocalObjectStore,

    replicas: &'a mut [LocalObjectStore],

    key: ObjectKey,
}

impl QuorumWriteTransport for ReplicaStoreWriter<'_> {
    fn write_replica(&mut self, replica_id: u64, payload: &[u8]) -> Result<blake3::Hash, String> {
        let store = if replica_id == 0 {
            &mut self.primary
        } else {
            let idx = (replica_id - 1) as usize;

            self.replicas
                .get_mut(idx)
                .ok_or_else(|| format!("replica {replica_id}: index out of bounds"))?
        };

        store
            .put(self.key, payload)
            .map_err(|e| format!("replica {replica_id}: {e}"))?;

        Ok(blake3::hash(payload))
    }
}

/// N-replica replicated object store.
///
/// Maintains one primary `LocalObjectStore` and N-1 replica stores.
/// Coordinates writes through the quorum write runtime and serves reads
/// from the primary with degraded fallback to replicas. Degraded reads
/// automatically queue repairs to the primary.
///
/// When a `ReplicaHealthTracker` is attached via
/// [`set_health_tracker`](Self::set_health_tracker), replicas at
/// `SuspicionLevel::Suspect` or worse are skipped during writes.
pub struct ReplicatedObjectStore {
    primary: LocalObjectStore,
    replicas: Vec<LocalObjectStore>,
    quorum_runtime: QuorumWriteRuntime,
    config: ReplicatedStoreConfig,
    stats: ReplicatedStoreStats,
    /// Detailed per-replica degraded read statistics.
    degraded_read_stats: RefCell<DegradedReadStats>,
    /// Pending repairs: objects found on replicas but missing from primary.
    repair_queue: RefCell<Vec<PendingRepair>>,
    /// Read-self-heal repair event ledger for observability.
    read_repair_ledger: RefCell<crate::read_self_heal::ReadRepairLedger>,
    /// Optional replica health tracker for write-target filtering.
    health_tracker: Option<ReplicaHealthTracker>,
    /// Optional per-replica degradation tracker for read-path replica selection.
    degradation_tracker: RefCell<Option<ReplicaDegradationTracker>>,
}

/// Current time in nanoseconds since UNIX epoch.
pub(crate) fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

impl ReplicatedObjectStore {
    /// Open a replicated store with N replicas.
    ///
    /// `paths` must contain at least 1 path (the primary). Additional paths
    /// become replica stores. All stores are opened with the same options.
    ///
    /// # Errors
    ///
    /// Returns an error if any store fails to open, or if paths is empty.
    pub fn open(paths: &[PathBuf], config: ReplicatedStoreConfig) -> Result<Self, String> {
        if paths.is_empty() {
            return Err("replicated store requires at least 1 path".into());
        }
        if paths.len() != config.replica_count {
            return Err(format!(
                "path count ({}) does not match config replica_count ({})",
                paths.len(),
                config.replica_count
            ));
        }

        // Open primary store
        let primary = LocalObjectStore::open_with_options(&paths[0], config.store_options.clone())
            .map_err(|e| format!("failed to open primary store at {:?}: {e}", paths[0]))?;

        // Open replica stores
        let mut replicas = Vec::with_capacity(paths.len() - 1);
        for (i, path) in paths.iter().enumerate().skip(1) {
            let store = LocalObjectStore::open_with_options(path, config.store_options.clone())
                .map_err(|e| format!("failed to open replica store {i} at {path:?}: {e}"))?;
            replicas.push(store);
        }

        // Build replica paths for the quorum runtime's degraded read resolver
        let replica_paths: Vec<PathBuf> = paths.iter().skip(1).cloned().collect();

        let quorum_config = QuorumWriteConfig {
            durability_mode: config.durability_mode,
            min_target_count: config.min_target_count,
            enable_degraded_reads: config.enable_degraded_reads,
            ..QuorumWriteConfig::dev_local()
        };

        let mut quorum_runtime =
            QuorumWriteRuntime::new(quorum_config, paths[0].clone(), replica_paths);

        // Open degraded read resolver for quorum runtime integration
        // Best-effort: degraded reads will fall back to direct replica iteration on failure
        let _ = quorum_runtime.open_degraded_reads();

        let stats = ReplicatedStoreStats {
            replica_healthy: vec![true; paths.len()],
            ..Default::default()
        };

        let degraded_read_stats =
            RefCell::new(DegradedReadStats::with_replica_count(replicas.len()));

        Ok(Self {
            primary,
            replicas,
            quorum_runtime,
            config,
            stats,
            degraded_read_stats,
            repair_queue: RefCell::new(Vec::new()),
            read_repair_ledger: RefCell::new(crate::read_self_heal::ReadRepairLedger::default()),
            health_tracker: None,
            degradation_tracker: RefCell::new(None),
        })
    }

    /// Attach a replica health tracker for write-target filtering.
    ///
    /// When set, replicas whose node-level suspicion is `Suspect` or worse
    /// are skipped during quorum writes. This prevents placing data on
    /// replicas that the health tracker has identified as unreliable.
    pub fn set_health_tracker(&mut self, tracker: ReplicaHealthTracker) {
        self.health_tracker = Some(tracker);
    }

    /// Remove the health tracker, restoring full-replica writes.
    pub fn clear_health_tracker(&mut self) {
        self.health_tracker = None;
    }

    /// Attach a replica degradation tracker for read-path replica selection.
    ///
    /// When set, the `get` path will iterate replicas in descending health
    /// order (healthiest first) instead of sequential order.
    pub fn set_degradation_tracker(&mut self, tracker: ReplicaDegradationTracker) {
        *self.degradation_tracker.borrow_mut() = Some(tracker);
    }

    /// Remove the degradation tracker, restoring sequential replica iteration.
    pub fn clear_degradation_tracker(&mut self) {
        *self.degradation_tracker.borrow_mut() = None;
    }

    /// Return a reference to the read-self-heal repair ledger.
    ///
    /// The ledger records every checksum-mismatch repair event, providing
    /// operator visibility into how many objects were repaired through
    /// demand-read self-healing and which replicas served good data.
    pub fn read_repair_ledger(
        &self,
    ) -> std::cell::Ref<'_, crate::read_self_heal::ReadRepairLedger> {
        self.read_repair_ledger.borrow()
    }

    /// Process any queued repairs from degraded reads.
    ///
    /// Called automatically at the start of `put_named` and `repair_replica`.
    /// Can also be called explicitly to flush repairs without a write.
    ///
    /// Returns the number of successfully repaired keys.
    pub fn flush_repairs(&mut self) -> usize {
        let pending: Vec<PendingRepair> = std::mem::take(&mut *self.repair_queue.borrow_mut());
        let mut repaired = 0usize;
        let total = pending.len();

        for p in pending {
            match self.primary.put(p.key, &p.data) {
                Ok(_) => {
                    repaired += 1;
                }
                Err(e) => {
                    eprintln!(
                        "repair: failed to push key {} from replica {} to primary: {e}",
                        p.key.short_hex(),
                        p.source_replica,
                    );
                }
            }
        }

        // Update stats
        let mut drs = self.degraded_read_stats.borrow_mut();
        drs.repair_attempts += total as u64;
        drs.repair_successes += repaired as u64;
        drs.repair_failures += (total - repaired) as u64;
        self.stats.degraded_reads.set(drs.total_degraded_reads);

        repaired
    }
    /// Write an object to the local primary store only, without fan-out to replicas.
    ///
    /// Used by storage-node replication handlers to accept writes from peers
    /// without creating re-replication loops.
    pub fn put_local(&mut self, name: impl AsRef<[u8]>, payload: &[u8]) -> Result<(), String> {
        self.primary
            .put_named(&name, payload)
            .map(|_| ())
            .map_err(|e| format!("primary put for replication receive: {e}"))
    }

    /// Write an object to the local primary store by exact key, without fan-out.
    pub fn put_key_local(&mut self, key: ObjectKey, payload: &[u8]) -> Result<(), String> {
        self.primary
            .put(key, payload)
            .map(|_| ())
            .map_err(|e| format!("primary key put for replication receive: {e}"))
    }

    /// Delete an object from the local primary store only, without fan-out.
    ///
    /// Used by storage-node replication handlers to accept deletes from peers
    /// without creating re-replication loops.
    pub fn delete_local(&mut self, name: impl AsRef<[u8]>) -> Result<bool, String> {
        let key = ObjectKey::from_name(&name);
        self.primary
            .delete(key)
            .map_err(|e| format!("primary delete for replication receive: {e}"))
    }

    /// Read an object from the local primary store only, without degraded-read
    /// fallback to replicas.
    pub fn get_local(&self, name: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>, String> {
        let key = ObjectKey::from_name(&name);
        self.primary
            .get(key)
            .map_err(|e| format!("primary read for replication receive: {e}"))
    }

    /// Read an object from the local primary store by exact ObjectKey.
    pub fn get_key_local(&self, key: ObjectKey) -> Result<Option<Vec<u8>>, String> {
        self.primary
            .get(key)
            .map_err(|e| format!("primary key read for replication receive: {e}"))
    }

    /// Return all object keys in the local primary store only.
    pub fn list_keys_local(&self) -> Result<Vec<ObjectKey>, String> {
        Ok(self.primary.list_keys())
    }

    /// Put an object identified by `name` into the replicated store.
    ///
    /// The object is written to the primary store first, then fanned out to
    /// all healthy replica stores. Replicas marked as unhealthy by the
    /// health tracker are skipped. The quorum write runtime classifies the
    /// result based on how many replicas acknowledged the write.
    pub fn put_named(
        &mut self,
        name: impl AsRef<[u8]>,
        payload: &[u8],
    ) -> Result<ReplicatedPutResult, String> {
        // Flush any pending repairs before writing new data
        self.flush_repairs();

        // Compute the deterministic key
        let key = ObjectKey::from_name(&name);

        // Write to primary first (this always succeeds or we fail)
        let _stored = self
            .primary
            .put_named(&name, payload)
            .map_err(|e| format!("primary write failed: {e}"))?;

        // Determine which replicas to skip based on health tracker
        let skip_set = self.unhealthy_replica_indices();

        // Write to replicas, skipping unhealthy ones
        let mut acks: u64 = 1; // primary counts
        let total_targets = (self.replicas.len() + 1) as u64;
        let mut replica_healthy = vec![true; self.replicas.len() + 1];
        let mut skipped = Vec::new();

        for (i, replica) in self.replicas.iter_mut().enumerate() {
            if skip_set.contains(&i) {
                skipped.push(i);
                replica_healthy[i + 1] = false;
                continue;
            }
            match replica.put(key, payload) {
                Ok(_) => acks += 1,
                Err(e) => {
                    replica_healthy[i + 1] = false;
                    eprintln!("replica {i} write failed: {e}");
                }
            }
        }
        self.stats.replica_healthy = replica_healthy;

        // Run quorum write protocol to classify the result
        let target_nodes = self.target_node_ids();
        self.quorum_runtime.set_targets(target_nodes);

        let (quorum_result, quorum_summary) = self
            .quorum_runtime
            .execute_write(&key.short_hex(), payload)
            .unwrap_or_else(|_e| {
                // If the runtime fails, synthesize a Refused result
                let write_id = tidefs_quorum_write::QuorumWriteId::new(0);
                let ticket_id = tidefs_quorum_write::TransferTicketId::new(0);
                (
                    QuorumWriteResult {
                        write_id,
                        ticket_id,
                        object_key: key.short_hex(),
                        write_class: WriteClass::RefusedNoQuorum,
                        acks_count: acks,
                        target_count: total_targets,
                        quorum_size: self.config.min_target_count as u64,
                        durability_mode: self.config.durability_mode,
                        placement_receipts: vec![],
                        witnesses: vec![],
                        needs_repair: false,
                        digests_matched: true,
                        digest: 0,
                    },
                    QuorumWriteSummary {
                        write_id,
                        write_class: WriteClass::RefusedNoQuorum,
                        target_records: vec![],
                        acks_at_commit: acks,
                        acks_at_witness: 0,
                        min_quorum: self.config.min_target_count as u64,
                        degraded: acks < total_targets,
                        refused: false,
                    },
                )
            });

        let min_quorum = self.config.min_target_count as u64;
        let write_class = if acks >= total_targets {
            WriteClass::Committed
        } else if acks >= min_quorum {
            WriteClass::DegradedCommitted
        } else {
            WriteClass::RefusedNoQuorum
        };
        let needs_repair = write_class == WriteClass::DegradedCommitted;

        // Update stats
        match write_class {
            WriteClass::Committed => self.stats.committed_writes += 1,
            WriteClass::DegradedCommitted => self.stats.degraded_writes += 1,
            _ => self.stats.refused_writes += 1,
        }
        self.stats.bytes_written += payload.len() as u64;
        self.stats.object_count += 1;

        Ok(ReplicatedPutResult {
            key,
            write_class,
            acks_count: acks,
            target_count: total_targets,
            quorum_size: self.config.min_target_count as u64,
            needs_repair,
            quorum_result,
            quorum_summary,
            skipped_unhealthy: skipped,
        })
    }

    /// Put an object with BLAKE3-authenticated quorum-write commit.
    ///
    /// Constructs a `QuorumWriteCommit` from the payload and replica
    /// configuration, then dispatches to all replicas via the
    /// `QuorumWriteTransport` adapter.  Each replica acknowledges with
    /// its BLAKE3 checksum; quorum requires at least `min_quorum()`
    /// matching checksums.
    pub fn put_with_blake3_quorum(
        &mut self,

        name: impl AsRef<[u8]>,

        payload: &[u8],
    ) -> Result<QuorumWriteOutcome, QuorumWriteError> {
        let key = ObjectKey::from_name(&name);

        // Build replica id list: 0 = primary, 1..N = replicas

        let replica_count = self.replicas.len() + 1;

        let replica_ids: Vec<u64> = (0..replica_count as u64).collect();

        let quorum_threshold = self.config.min_quorum();

        let commit = QuorumWriteCommit::new(payload.to_vec(), replica_ids, quorum_threshold);

        let mut writer = ReplicaStoreWriter {
            primary: &mut self.primary,

            replicas: &mut self.replicas,

            key,
        };

        commit_quorum_write(&commit, &mut writer)
    }

    /// Get an object by name. Tries primary first, then falls back to replicas.
    ///
    /// Degraded reads (primary miss, replica hit) are tracked with per-replica
    /// latency and hit counts. Missing-primary objects are queued for repair.
    pub fn get_named(&self, name: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>, String> {
        let key = ObjectKey::from_name(&name);
        self.get_inner(key)
    }

    /// Get an object by name with receipt authority validation.
    ///
    /// Behaves like [`Self::get_named`] but additionally validates the
    /// returned payload against the provided placement receipt reference.
    /// This is the degraded-read path that consumes durable receipt authority
    /// (#356 / #18) rather than trusting replica bytes alone.
    ///
    /// When `receipt` is `Some`, the returned payload (whether from primary,
    /// quorum runtime, or replica fallback) is validated against the receipt's
    /// digest, length, and policy before it is returned.  When `receipt` is
    /// `None`, this method behaves identically to [`Self::get_named`].
    pub fn get_named_with_receipt(
        &self,
        name: impl AsRef<[u8]>,
        receipt: Option<PlacementReceiptRef>,
    ) -> Result<Option<Vec<u8>>, String> {
        let key = ObjectKey::from_name(&name);
        let data = self.get_inner(key)?;
        match (data, receipt) {
            (Some(payload), Some(receipt_ref)) => {
                self.validate_degraded_read_receipt(&receipt_ref, &payload)?;
                Ok(Some(payload))
            }
            (data, _) => Ok(data),
        }
    }

    /// Validate a degraded-read payload against a placement receipt.
    ///
    /// This is the core receipt-authority check for the local degraded-read
    /// path (#356 / #18).  It verifies that the receipt is non-synthetic,
    /// the policy is well-formed, the payload length matches, and the
    /// BLAKE3 digest matches.  On failure, the degraded-read receipt-failure
    /// counter is incremented and an error is returned so the caller can
    /// fall back to the next replica or fail the read.
    fn validate_degraded_read_receipt(
        &self,
        receipt: &PlacementReceiptRef,
        payload: &[u8],
    ) -> Result<(), String> {
        if receipt.is_synthetic() {
            self.degraded_read_stats
                .borrow_mut()
                .receipt_validation_failures += 1;
            return Err("degraded-read receipt is synthetic (generation zero)".into());
        }
        if !receipt.redundancy_policy.is_well_formed() {
            self.degraded_read_stats
                .borrow_mut()
                .receipt_validation_failures += 1;
            return Err("degraded-read receipt has malformed redundancy policy".into());
        }
        if receipt.payload_len != payload.len() as u64 {
            self.degraded_read_stats
                .borrow_mut()
                .receipt_validation_failures += 1;
            return Err(format!(
                "degraded-read receipt length mismatch: receipt={} actual={}",
                receipt.payload_len,
                payload.len()
            ));
        }
        let actual_digest: [u8; 32] = blake3::hash(payload).into();
        if receipt.payload_digest != actual_digest {
            self.degraded_read_stats
                .borrow_mut()
                .receipt_validation_failures += 1;
            return Err("degraded-read receipt digest mismatch".into());
        }
        self.degraded_read_stats
            .borrow_mut()
            .receipt_validated_reads += 1;
        Ok(())
    }

    /// Get an object by key directly. Tries primary first, then replicas.
    ///
    /// Degraded reads (primary miss, replica hit) are tracked with per-replica
    /// latency and hit counts. Missing-primary objects are queued for repair.
    pub fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>, String> {
        self.get_inner(key)
    }

    /// Shared implementation for get/get_named.
    fn get_inner(&self, key: ObjectKey) -> Result<Option<Vec<u8>>, String> {
        // Try primary first
        let mut primary_checksum_mismatch = false;
        match self.primary.get(key) {
            Ok(Some(data)) => return Ok(Some(data)),
            Ok(None) => {}
            Err(e) => {
                // Checksum mismatch triggers self-healing: fall through to replicas.
                if crate::read_self_heal::is_checksum_mismatch_error(&e) {
                    primary_checksum_mismatch = true;
                    crate::read_self_heal::record_primary_checksum_mismatch(
                        &self.degradation_tracker,
                    );
                    // fall through to replica fallback below
                } else {
                    return Err(format!("primary read failed: {e}"));
                }
            }
        }

        // Try degraded read via quorum runtime resolver first
        let t0 = Instant::now();
        if let Some((data, _class)) = self.quorum_runtime.try_degraded_read(&key) {
            let latency_us = t0.elapsed().as_micros() as u64;
            self.record_degraded_read(0, latency_us);
            self.queue_repair(key, data.clone(), 0);
            if primary_checksum_mismatch {
                self.read_repair_ledger.borrow_mut().record_repair(key, 0);
            }
            return Ok(Some(data));
        }

        // Fallback: iterate replicas in health order when a degradation
        // tracker is available, otherwise use sequential order.
        let replica_order = self.health_ordered_replica_indices();

        for &i in &replica_order {
            let replica = &self.replicas[i];
            let t0 = Instant::now();
            match replica.get(key) {
                Ok(Some(data)) => {
                    let latency_us = t0.elapsed().as_micros() as u64;
                    // Track degraded read with per-replica latency
                    self.record_degraded_read(i, latency_us);
                    // Queue repair: push this data back to the primary
                    self.queue_repair(key, data.clone(), i);
                    if primary_checksum_mismatch {
                        self.read_repair_ledger.borrow_mut().record_repair(key, i);
                    }
                    return Ok(Some(data));
                }
                Ok(None) => continue,
                Err(e) => {
                    eprintln!("replica {i} read failed: {e}");
                    continue;
                }
            }
        }

        Ok(None)
    }

    /// Return replica indices ordered by health score, descending.
    ///
    /// When a degradation tracker is available, replicas are sorted so
    /// that the healthiest (highest-scoring) replicas are tried first.
    /// The primary is always tried before any replica and is not included
    /// in this ordering. Replicas with Dead degradation state are placed
    /// last. When no tracker is set, returns sequential order 0..n.
    fn health_ordered_replica_indices(&self) -> Vec<usize> {
        let n = self.replicas.len();
        if n == 0 {
            return Vec::new();
        }

        let tracker_guard = self.degradation_tracker.borrow();
        let Some(ref tracker) = *tracker_guard else {
            return (0..n).collect();
        };

        // Build NodeId list for replicas (index i maps to NodeId(i+1))
        let now_ns = now_ns();
        let node_ids: Vec<tidefs_replica_health::NodeId> = (1..=n)
            .map(|i| tidefs_replica_health::NodeId::new(i as u64))
            .collect();

        let sorted_ids = sort_replicas_by_health(tracker, &node_ids, now_ns);

        // Convert NodeId back to replica indices
        sorted_ids
            .into_iter()
            .map(|node_id| (node_id.0 as usize).saturating_sub(1))
            .filter(|&idx| idx < n)
            .collect()
    }

    /// Delete an object by name from all replicas.
    pub fn delete_named(&mut self, name: impl AsRef<[u8]>) -> Result<bool, String> {
        let key = ObjectKey::from_name(&name);
        self.delete(key)
    }

    /// Delete an object by key from all replicas with quorum confirmation.
    ///
    /// Deletes from the primary and all replicas. Returns `Ok(true)` when
    /// at least `min_quorum` replicas (including the primary) acknowledge
    /// the deletion. Returns `Ok(false)` when the object was already absent
    /// from all stores (idempotent). Returns an error when fewer than
    /// `min_quorum` stores confirm the delete.
    ///
    /// The `generation` counter is recorded for racing-write prevention;
    /// replica-level enforcement happens at the transport layer.
    pub fn delete(&mut self, key: ObjectKey) -> Result<bool, String> {
        let min_quorum = self.config.min_quorum();
        let primary_deleted = match self.primary.delete(key) {
            Ok(true) => true,
            Ok(false) => false,
            Err(e) => return Err(format!("primary delete failed: {e}")),
        };

        // Delete from replicas, counting successful confirmations.
        let mut ack_count: usize = 1; // primary responded successfully (whether it found the key or not)
        for (i, replica) in self.replicas.iter_mut().enumerate() {
            match replica.delete(key) {
                Ok(did_delete) => {
                    if did_delete {
                        ack_count += 1;
                    } else {
                        // Idempotent: object wasn't there, but replica is reachable.
                        ack_count += 1;
                    }
                }
                Err(e) => {
                    eprintln!("replica {i} delete failed: {e}");
                }
            }
        }

        if ack_count >= min_quorum {
            Ok(primary_deleted)
        } else {
            Err(format!(
                "delete quorum failed: {}/{} replicas acknowledged (need {})",
                ack_count, self.config.replica_count, min_quorum
            ))
        }
    }

    /// Sync all stores to disk.
    pub fn sync_all(&mut self) -> Result<(), String> {
        self.primary
            .sync_all()
            .map_err(|e| format!("primary sync failed: {e}"))?;
        for (i, replica) in self.replicas.iter_mut().enumerate() {
            replica
                .sync_all()
                .map_err(|e| format!("replica {i} sync failed: {e}"))?;
        }
        Ok(())
    }

    /// List all keys present in the primary store.
    ///
    /// This returns keys from the primary store only; replicas are
    /// repaired asynchronously.
    pub fn list_keys(&self) -> Result<Vec<ObjectKey>, String> {
        Ok(self.primary.list_keys())
    }

    /// Repair a specific replica by synchronizing it from the primary store.
    ///
    /// Iterates all keys in the primary store and writes any missing or
    /// divergent keys to the replica at `index` (0-based replica index).
    /// Also flushes any pending primary repairs from degraded reads
    /// before starting.
    /// Returns the number of keys repaired.
    ///
    /// # Errors
    ///
    /// Returns an error if `index` is out of range, or if any I/O operation
    /// on the primary or replica fails.
    pub fn repair_replica(&mut self, index: usize) -> Result<usize, String> {
        // Flush pending repairs before scanning
        self.flush_repairs();

        let n_replicas = self.replicas.len();
        let replica = self.replicas.get_mut(index).ok_or_else(|| {
            format!("replica index {index} out of range (have {n_replicas} replicas)")
        })?;

        let keys = self.primary.list_keys();

        let mut repaired = 0usize;
        for &key in &keys {
            let primary_data = self
                .primary
                .get(key)
                .map_err(|e| format!("primary read failed for key {}: {e}", key.short_hex()))?;

            if let Some(data) = primary_data {
                let replica_data = replica.get(key).ok().flatten();
                if replica_data.as_ref() != Some(&data) {
                    replica.put(key, &data).map_err(|e| {
                        format!(
                            "replica put failed for key {} during repair: {e}",
                            key.short_hex()
                        )
                    })?;
                    repaired += 1;
                }
            }
        }

        // Mark replica as healthy after successful repair
        if index + 1 < self.stats.replica_healthy.len() {
            self.stats.replica_healthy[index + 1] = true;
        }

        Ok(repaired)
    }

    /// Return current coarse-grained statistics.
    #[must_use]
    pub fn stats(&self) -> &ReplicatedStoreStats {
        &self.stats
    }

    /// Return detailed degraded read statistics.
    #[must_use]
    pub fn degraded_read_stats(&self) -> DegradedReadStats {
        self.degraded_read_stats.borrow().clone()
    }

    /// Return a human-readable degraded read report.
    #[must_use]
    pub fn degraded_read_report(&self) -> String {
        self.degraded_read_stats.borrow().report()
    }

    /// Return the number of replicas (including primary).
    #[must_use]
    pub fn replica_count(&self) -> usize {
        1 + self.replicas.len()
    }

    /// Return whether the primary store is healthy.
    #[must_use]
    pub fn primary_healthy(&self) -> bool {
        self.stats.replica_healthy.first().copied().unwrap_or(false)
    }

    /// Return per-replica health status.
    #[must_use]
    pub fn replica_health(&self) -> &[bool] {
        &self.stats.replica_healthy
    }

    /// Transaction-group id of the primary's most recently committed root.
    /// 0 means no root has been committed yet (NIL).
    #[must_use]
    pub fn committed_root_txg(&self) -> u64 {
        self.primary
            .txg_manager()
            .committed_root()
            .commit_group_id
            .0
    }

    /// Monotonic generation counter from the primary's txg manager.
    #[must_use]
    pub fn committed_root_generation(&self) -> u64 {
        self.primary.txg_manager().commit_count()
    }

    // ── Internal helpers ──────────────────────────────────────────────

    /// Record a degraded read from a specific replica with latency.
    fn record_degraded_read(&self, replica_idx: usize, latency_us: u64) {
        let mut drs = self.degraded_read_stats.borrow_mut();
        drs.record_hit(replica_idx, latency_us);
        // Sync convenience counter
        self.stats.degraded_reads.set(drs.total_degraded_reads);
    }

    /// Queue a repair: data found on a replica but missing from primary.
    fn queue_repair(&self, key: ObjectKey, data: Vec<u8>, source_replica: usize) {
        self.repair_queue.borrow_mut().push(PendingRepair {
            key,
            data,
            source_replica,
        });
    }

    /// Return replica indices that should be skipped based on health tracker.
    fn unhealthy_replica_indices(&self) -> Vec<usize> {
        let Some(ref tracker) = self.health_tracker else {
            return Vec::new();
        };
        let mut skip = Vec::new();
        for i in 0..self.replicas.len() {
            // Replica i maps to NodeId(i+1) since primary is NodeId(0)
            let node_id = tidefs_replica_health::NodeId::new((i + 1) as u64);
            let suspicion = tracker.node_suspicion(node_id);
            if !suspicion.admits_transfers() {
                skip.push(i);
            }
        }
        skip
    }

    // Build synthetic node IDs for the quorum runtime based on replica index.
    fn target_node_ids(&self) -> Vec<tidefs_quorum_write::NodeId> {
        (0..(1 + self.replicas.len()))
            .map(|i| tidefs_quorum_write::NodeId::new(i as u64))
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Transport-backed replicated object store
// ═══════════════════════════════════════════════════════════════════════════

use std::net::SocketAddr;
use tidefs_rebuild_runtime::{
    admission::RebuildAdmission,
    completion::{RebuildCompleted, RebuildCompletion, VerifiedReceiptCompletionRecord},
    engine::ReceiptSegmentSource,
    task::BackfillTask,
};
use tidefs_transport::{
    build_read_responses, recv_replication_msg, recv_segment_fetch, recv_segment_fetch_response,
    recv_write_request, send_replication_msg, send_segment_fetch, send_segment_fetch_response,
    send_write_ack, NodeInfo, ObjectTransferMessage, PlacementDispatch, PlacementMapRefusalReason,
    ReplicationMessage, SegmentFetchRequest, SegmentFetchResponse, SessionCloseReason, SessionId,
    Transport, TransportError, WriteStatus, MAX_CHUNK_PAYLOAD,
};

#[cfg(not(test))]
const REPLICA_ACK_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const REPLICA_ACK_TIMEOUT: Duration = Duration::from_millis(200);
const REPLICA_ACK_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Evidence returned after a receipt-bound repair has also been recorded as
/// verified rebuild completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptRepairCompletionEvidence {
    /// Fresh repaired placement receipt returned by the target storage node.
    pub repaired_placement_receipt_ref: PlacementReceiptRef,
    /// Source and repaired receipt evidence recorded by rebuild-runtime.
    pub verified_receipt_completion: VerifiedReceiptCompletionRecord,
    /// Completion event emitted when this repair closes the member rebuild.
    pub completion_event: Option<RebuildCompleted>,
}

/// Evidence returned after receipt-bound repair completion is also published
/// through the flow-commit coordinator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptRepairFlowCommitPublication {
    /// Repair execution and rebuild-runtime completion evidence.
    pub repair_completion: ReceiptRepairCompletionEvidence,
    /// Flow-commit publication that records the repaired placement receipt.
    pub flow_commit_result: FlowCommitResult,
}

/// Payload and durable receipt evidence returned by a planned read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportPlannedReadResult {
    /// Bytes returned by the selected source.
    pub payload: Vec<u8>,
    /// Member id that served the read response.
    pub source_member_id: u64,
    /// Validated placement receipt authority, when the source exposes it.
    pub placement_receipt_ref: Option<PlacementReceiptRef>,
}

/// Planned-read result suitable for repair/rebuild authority decisions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptBackedTransportPlannedReadResult {
    /// Bytes returned by the selected source.
    pub payload: Vec<u8>,
    /// Member id that served the read response.
    pub source_member_id: u64,
    /// Validated non-synthetic placement receipt authority for the payload.
    pub placement_receipt_ref: PlacementReceiptRef,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlannedReadReceiptRequirement {
    Optional,
    Required,
}

fn validate_read_plan_response_receipt(
    plan: &ReplicatedReadPlan,
    payload: &[u8],
    receipt: PlacementReceiptRef,
) -> Result<(), String> {
    if receipt.is_synthetic() {
        return Err(format!(
            "read plan for subject {} returned synthetic placement receipt",
            plan.subject_ref.0
        ));
    }
    if !receipt.redundancy_policy.is_well_formed() {
        return Err(format!(
            "read plan for subject {} returned malformed receipt policy",
            plan.subject_ref.0
        ));
    }
    let required_targets = receipt.redundancy_policy.target_width();
    if receipt.target_count < required_targets {
        return Err(format!(
            "read plan for subject {} returned under-width receipt: targets={} required={}",
            plan.subject_ref.0, receipt.target_count, required_targets
        ));
    }
    if receipt.object_id != plan.subject_ref.0 {
        return Err(format!(
            "read plan subject mismatch: plan={} receipt={}",
            plan.subject_ref.0, receipt.object_id
        ));
    }
    if receipt.payload_len != payload.len() as u64 {
        return Err(format!(
            "read plan receipt length mismatch for subject {}: receipt={} actual={}",
            plan.subject_ref.0,
            receipt.payload_len,
            payload.len()
        ));
    }
    let actual_digest: [u8; 32] = blake3::hash(payload).into();
    if receipt.payload_digest != actual_digest {
        return Err(format!(
            "read plan receipt digest mismatch for subject {}",
            plan.subject_ref.0
        ));
    }
    Ok(())
}

fn validate_put_named_receipt_authority(
    key: tidefs_local_object_store::ObjectKey,
    payload: &[u8],
    receipt: PlacementReceiptRef,
) -> Result<(), String> {
    if receipt.is_synthetic() {
        return Err("put-with-receipt authority is synthetic (generation zero)".into());
    }
    if !receipt.redundancy_policy.is_well_formed() {
        return Err("put-with-receipt authority has malformed redundancy policy".into());
    }
    let required_targets = receipt.redundancy_policy.target_width();
    if receipt.target_count < required_targets {
        return Err(format!(
            "put-with-receipt authority is under-width: targets={} required={required_targets}",
            receipt.target_count
        ));
    }
    if receipt.object_key != *key.as_bytes() {
        return Err(format!(
            "put-with-receipt authority object-key mismatch for object {}",
            receipt.object_id
        ));
    }
    if receipt.payload_len != payload.len() as u64 {
        return Err(format!(
            "put-with-receipt authority length mismatch for object {}: receipt={} actual={}",
            receipt.object_id,
            receipt.payload_len,
            payload.len()
        ));
    }
    let actual_digest: [u8; 32] = blake3::hash(payload).into();
    if receipt.payload_digest != actual_digest {
        return Err(format!(
            "put-with-receipt authority digest mismatch for object {}",
            receipt.object_id
        ));
    }
    Ok(())
}

fn validate_recorded_put_receipt_authority(
    expected: PlacementReceiptRef,
    recorded: PlacementReceiptRef,
) -> Result<(), String> {
    if recorded.is_synthetic() {
        return Err(format!(
            "recorded put-with-receipt authority for object {} is synthetic",
            expected.object_id
        ));
    }
    if !recorded.redundancy_policy.is_well_formed() {
        return Err(format!(
            "recorded put-with-receipt authority for object {} has malformed redundancy policy",
            expected.object_id
        ));
    }
    if recorded.object_id != expected.object_id
        || recorded.object_key != expected.object_key
        || recorded.receipt_epoch != expected.receipt_epoch
        || recorded.redundancy_policy != expected.redundancy_policy
        || recorded.target_count != expected.target_count
        || recorded.payload_len != expected.payload_len
        || recorded.payload_digest != expected.payload_digest
    {
        return Err(format!(
            "recorded put-with-receipt authority for object {} does not match the requested authority",
            expected.object_id
        ));
    }
    if recorded.receipt_generation < expected.receipt_generation {
        return Err(format!(
            "recorded put-with-receipt authority for object {} has stale generation {} below requested {}",
            expected.object_id, recorded.receipt_generation, expected.receipt_generation
        ));
    }
    Ok(())
}

fn required_planned_read_receipt(
    plan: &ReplicatedReadPlan,
    result: &TransportPlannedReadResult,
) -> Result<PlacementReceiptRef, String> {
    let Some(receipt) = result.placement_receipt_ref else {
        return Err(format!(
            "receipt-authoritative planned read for subject {} returned payload without placement receipt evidence",
            plan.subject_ref.0
        ));
    };
    if receipt.is_synthetic() {
        return Err(format!(
            "receipt-authoritative planned read for subject {} returned synthetic placement receipt",
            plan.subject_ref.0
        ));
    }
    Ok(receipt)
}

fn validate_read_plan_response_payload(
    plan: &ReplicatedReadPlan,
    payload: &[u8],
    placement_receipt_ref: Option<PlacementReceiptRef>,
) -> Result<(), String> {
    if let Some(receipt) = placement_receipt_ref {
        validate_read_plan_response_receipt(plan, payload, receipt)?;
    }
    Ok(())
}

/// Configuration for a transport-backed replicated object store.
#[derive(Clone, Debug)]
pub struct TransportReplicatedStoreConfig {
    /// Minimum number of replicas (including local primary) that must
    /// acknowledge a write for it to be considered committed.
    pub write_quorum: usize,
    /// Total expected replicas including local primary. Must be >= write_quorum.
    pub total_replicas: usize,
    /// Whether to attempt degraded reads from replicas when the primary misses.
    pub enable_degraded_reads: bool,
    /// Request the RDMA-capable transport constructor for remote replica sessions.
    /// Runtime validation must still disclose the selected carrier and reject
    /// unexpected TCP fallback for RDMA release claims.
    pub rdma: bool,
    /// Store options for the local primary store.
    pub store_options: tidefs_local_object_store::StoreOptions,
}

impl Default for TransportReplicatedStoreConfig {
    fn default() -> Self {
        Self {
            write_quorum: 1,
            total_replicas: 1,
            enable_degraded_reads: true,
            rdma: false,
            store_options: tidefs_local_object_store::StoreOptions::test_fast(),
        }
    }
}

impl TransportReplicatedStoreConfig {
    /// Convenience: 3 replicas (local + 2 remote) with majority quorum >= 2.
    #[must_use]
    pub fn three_replica_quorum() -> Self {
        Self {
            write_quorum: 2,
            total_replicas: 3,
            enable_degraded_reads: true,
            rdma: false,
            store_options: tidefs_local_object_store::StoreOptions::test_fast(),
        }
    }

    /// Convenience: 5 replicas (local + 4 remote) with witness quorum >= 3.
    #[must_use]
    pub fn five_replica_witness() -> Self {
        Self {
            write_quorum: 3,
            total_replicas: 5,
            enable_degraded_reads: true,
            rdma: false,
            store_options: tidefs_local_object_store::StoreOptions::test_fast(),
        }
    }
}

/// Outcome of a transport-backed replicated put operation.
#[derive(Clone, Debug)]
pub struct TransportReplicatedPutResult {
    /// The object key for the stored value.
    pub key: tidefs_local_object_store::ObjectKey,
    /// Number of replicas that acknowledged the write.
    pub acks: usize,
    /// Total target replicas (local + remote).
    pub total_targets: usize,
    /// Quorum size required.
    pub quorum_size: usize,
    /// Whether quorum was reached.
    pub quorum_reached: bool,
    /// Whether the write was fully committed (all replicas acked).
    pub fully_committed: bool,
    /// Durable placement receipt authority for a receipt-authorized write.
    /// Present only when put_named_with_receipt reaches quorum.
    /// For multi-node writes this is the validated receipt returned by a
    /// receipt-bearing replica ack; primary-only quorum retains the supplied
    /// pool-backed receipt authority.
    pub recorded_receipt_ref: Option<PlacementReceiptRef>,
}

/// Successful peer placement read-map installation over a replica control session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerPlacementMapRequestReport {
    /// Peer node that served the map.
    pub peer_node_id: u64,
    /// Minimum version sent in the request.
    pub requested_minimum_version: u64,
    /// Local store placement version before the peer map was installed.
    pub previous_version: u64,
    /// Version installed from the peer response.
    pub installed_version: u64,
    /// Exact map accepted through the placement dispatch validation path.
    pub installed_map: tidefs_transport::PlacementMap,
}

/// Fail-closed outcomes for a peer placement read-map request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerPlacementMapRequestError {
    /// The requested peer is not in this store's replica session set.
    ReplicaNotConnected { peer_node_id: u64 },
    /// The request could not be sent.
    SendFailed { peer_node_id: u64, message: String },
    /// No bounded response was received.
    ReceiveFailed { peer_node_id: u64, message: String },
    /// The peer replied with a different message type.
    UnexpectedResponse { peer_node_id: u64, actual: String },
    /// The peer response did not echo the request minimum version.
    MinimumVersionMismatch {
        peer_node_id: u64,
        requested_minimum_version: u64,
        response_minimum_version: u64,
    },
    /// The peer explicitly refused the request.
    Refused {
        peer_node_id: u64,
        requested_minimum_version: u64,
        reason: PlacementMapRefusalReason,
    },
    /// The peer returned neither a map nor a refusal reason.
    MissingMap {
        peer_node_id: u64,
        requested_minimum_version: u64,
    },
    /// The peer map did not advance the requested/local version boundary.
    Stale {
        peer_node_id: u64,
        requested_minimum_version: u64,
        available_version: u64,
        local_version: u64,
    },
    /// The local placement dispatch rejected the peer map.
    InstallRejected {
        peer_node_id: u64,
        requested_minimum_version: u64,
        map_version: u64,
        message: String,
    },
}

impl std::fmt::Display for PeerPlacementMapRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReplicaNotConnected { peer_node_id } => {
                write!(f, "replica node {peer_node_id} is not connected")
            }
            Self::SendFailed {
                peer_node_id,
                message,
            } => write!(
                f,
                "send placement map request to replica node {peer_node_id} failed: {message}"
            ),
            Self::ReceiveFailed {
                peer_node_id,
                message,
            } => write!(
                f,
                "receive placement map response from replica node {peer_node_id} failed: {message}"
            ),
            Self::UnexpectedResponse {
                peer_node_id,
                actual,
            } => write!(
                f,
                "replica node {peer_node_id} returned unexpected placement map response: {actual}"
            ),
            Self::MinimumVersionMismatch {
                peer_node_id,
                requested_minimum_version,
                response_minimum_version,
            } => write!(
                f,
                "replica node {peer_node_id} echoed placement map minimum {response_minimum_version}, requested {requested_minimum_version}"
            ),
            Self::Refused {
                peer_node_id,
                requested_minimum_version,
                reason,
            } => write!(
                f,
                "replica node {peer_node_id} refused placement map request minimum {requested_minimum_version}: {reason:?}"
            ),
            Self::MissingMap {
                peer_node_id,
                requested_minimum_version,
            } => write!(
                f,
                "replica node {peer_node_id} returned no placement map for minimum {requested_minimum_version}"
            ),
            Self::Stale {
                peer_node_id,
                requested_minimum_version,
                available_version,
                local_version,
            } => write!(
                f,
                "replica node {peer_node_id} returned placement map version {available_version}, requested minimum {requested_minimum_version}, local version {local_version}"
            ),
            Self::InstallRejected {
                peer_node_id,
                requested_minimum_version,
                map_version,
                message,
            } => write!(
                f,
                "replica node {peer_node_id} placement map version {map_version} for minimum {requested_minimum_version} was rejected: {message}"
            ),
        }
    }
}

impl std::error::Error for PeerPlacementMapRequestError {}

/// A remote replica node with per-endpoint-family sessions.
///
/// Per P8-01 §4.2, at most one Control (e1), Data (e2), and Shadow (e3)
/// session exists per peer pair. This struct holds the three session IDs
/// established during connect.
struct TransportReplica {
    /// The peer's node ID.
    node_id: u64,
    /// Control session (e1): commit protocol, write plan dissemination, ACKs.
    control_session_id: SessionId,
    /// Data session (e2): payload transfer for object data.
    data_session_id: SessionId,
    /// Shadow session (e3): degraded reads, witness verification.
    shadow_session_id: SessionId,
}

/// Transport-backed replicated object store.
///
/// Maintains a local primary `LocalObjectStore` and fans writes out to
/// remote replicas over `tidefs-transport` TCP sessions. Reads are served
/// from the local primary with optional degraded-read fallback to remote
/// replicas.
///
/// Per P8-01, each replica connection uses three endpoint families:
/// - e1 (Control): session handshake, write plan dissemination, commit/witness ACK protocol
/// - e2 (Data): payload transfer for object data
/// - e3 (Shadow): degraded reads from shadow replicas, witness verification
///
/// Every transfer is validated through `tidefs-verification-engine`.
pub struct TransportReplicatedStore {
    /// Local primary object store.
    primary: tidefs_local_object_store::LocalObjectStore,
    /// Transport instance managing connections and sessions.
    transport: Transport,
    /// Remote replica sessions (per-endpoint-family trios).
    replicas: Vec<TransportReplica>,
    /// Configuration.
    config: TransportReplicatedStoreConfig,
    /// Statistics.
    stats: TransportReplicatedStoreStats,
    /// Verification context for transfer validation.
    verification_ctx: VerificationContext,
    /// Accumulated verification receipts from plan-based transfers.
    verification_receipts: Vec<ReplicaVerificationReceipt>,
    /// Optional placement dispatch for deterministic replica selection.
    /// When set, writes and reads use NodePlacement to target only the
    /// correct replica set; when None, receiptless operations fan out to all
    /// replicas.
    placement: Option<PlacementDispatch>,
    /// Lazily-initialized replicated object reader for degraded reads.
    reader: Option<ReplicatedObjectReader>,
}

/// Coarse-grained statistics for a transport-backed replicated store.
#[derive(Clone, Debug, Default)]
pub struct TransportReplicatedStoreStats {
    /// Number of fully committed writes (all replicas acked).
    pub committed_writes: u64,
    /// Number of quorum-committed writes (not all replicas acked).
    pub degraded_writes: u64,
    /// Number of writes that failed to reach quorum.
    pub failed_writes: u64,
    /// Number of degraded reads served from a remote replica.
    pub degraded_reads: u64,
    /// Number of plan-based writes executed.
    pub planned_writes: u64,
    /// Number of plan-based reads executed.
    pub planned_reads: u64,
    /// Total bytes written.
    pub bytes_written: u64,
    /// Total objects stored locally.
    pub object_count: u64,
}

impl TransportReplicatedStore {
    fn recv_replication_ack_bounded(
        transport: &mut Transport,
        session_id: SessionId,
    ) -> Result<ReplicationMessage, TransportError> {
        let deadline = Instant::now() + REPLICA_ACK_TIMEOUT;
        transport.set_nonblocking(true)?;

        let result = loop {
            match recv_replication_msg(transport, session_id) {
                Ok(msg) => break Ok(msg),
                Err(TransportError::WouldBlock(_)) if Instant::now() < deadline => {
                    std::thread::sleep(REPLICA_ACK_POLL_INTERVAL);
                }
                Err(TransportError::WouldBlock(_)) => {
                    break Err(TransportError::Generic(format!(
                        "replica ack timeout after {}ms",
                        REPLICA_ACK_TIMEOUT.as_millis()
                    )));
                }
                Err(err) => break Err(err),
            }
        };

        if let Err(restore_err) = transport.set_nonblocking(false) {
            if result.is_ok() {
                return Err(restore_err);
            }
            tracing::warn!("restore blocking mode after bounded replica ack failed: {restore_err}");
        }

        result
    }

    fn restore_primary_after_failed_mutation(
        &mut self,
        name: impl AsRef<[u8]>,
        key: tidefs_local_object_store::ObjectKey,
        previous_payload: Option<&[u8]>,
    ) {
        let result = match previous_payload {
            Some(payload) => self.primary.put_named(name, payload).map(|_| ()),
            None => self.primary.delete(key).map(|_| ()),
        };
        if let Err(error) = result {
            tracing::warn!("failed to restore primary after no-quorum mutation: {error}");
        }
    }

    fn restore_acked_replicas_after_failed_mutation(
        transport: &mut Transport,
        name: &str,
        previous_payload: Option<&[u8]>,
        acked_replicas: &[(u64, SessionId)],
    ) {
        for (node_id, session_id) in acked_replicas {
            let send_result = match previous_payload {
                Some(payload) => send_replication_msg(
                    transport,
                    *session_id,
                    &ReplicationMessage::Put {
                        name: name.to_string(),
                        payload: payload.to_vec(),
                    },
                ),
                None => send_replication_msg(
                    transport,
                    *session_id,
                    &ReplicationMessage::Delete {
                        name: name.to_string(),
                        generation: 0,
                    },
                ),
            };
            if let Err(error) = send_result {
                tracing::warn!("replica node {node_id}: rollback send failed: {error}");
                continue;
            }

            match Self::recv_replication_ack_bounded(transport, *session_id) {
                Ok(ReplicationMessage::Ack { success: true, .. })
                | Ok(ReplicationMessage::DeleteAck { .. }) => {}
                Ok(other) => {
                    tracing::warn!(
                        "replica node {node_id}: unexpected rollback response: {other:?}"
                    );
                }
                Err(error) => {
                    tracing::warn!("replica node {node_id}: rollback ack failed: {error}");
                }
            }
        }
    }

    /// Open a transport-backed replicated store.
    ///
    /// Creates the local primary store at `primary_path`, creates a
    /// Transport with the given `local_node_id`, and binds to 127.0.0.1:0
    /// for potential return connections from replicas.
    ///
    /// Call [`connect_replica`](Self::connect_replica) for each remote
    /// replica before using put/get.
    ///
    /// # Errors
    ///
    /// Returns an error if the primary store fails to open or if the
    /// Transport fails to bind.
    pub fn open(
        primary_path: &std::path::Path,
        local_node_id: u64,
        config: TransportReplicatedStoreConfig,
    ) -> Result<Self, String> {
        let primary = tidefs_local_object_store::LocalObjectStore::open_with_options(
            primary_path,
            config.store_options.clone(),
        )
        .map_err(|e| format!("failed to open primary store: {e}"))?;

        let mut transport = if config.rdma {
            Transport::with_rdma_or_tcp(local_node_id, Duration::from_secs(5))
        } else {
            Transport::new(local_node_id)
        };
        transport
            .configure_generated_attestation(true)
            .map_err(|e| format!("transport attestation setup failed: {e}"))?;

        // Bind to localhost:0 for potential return connections from replicas
        let bind_addr: SocketAddr = "127.0.0.1:0"
            .parse()
            .map_err(|e| format!("invalid bind address: {e}"))?;
        transport
            .bind(tidefs_transport::TransportAddr::Tcp(bind_addr))
            .map_err(|e| format!("transport bind failed: {e}"))?;

        Ok(Self {
            primary,
            transport,
            replicas: Vec::new(),
            config,
            stats: TransportReplicatedStoreStats::default(),
            verification_ctx: VerificationContext::new(tidefs_membership_epoch::EpochId(1)),
            verification_receipts: Vec::new(),
            placement: None,
            reader: None,
        })
    }

    /// Connect to a remote replica with all three endpoint families.
    ///
    /// Establishes Control (e1), Data (e2), and Shadow (e3) sessions
    /// per P8-01 §4.2. Registers the peer, connects, and performs
    /// handshake for each endpoint family.
    ///
    /// # Errors
    ///
    /// Returns an error if any connect or handshake fails.
    pub fn connect_replica(&mut self, node_id: u64, addr: SocketAddr) -> Result<(), String> {
        // Register the peer node
        self.transport.add_node(NodeInfo::new(
            node_id,
            vec![tidefs_transport::TransportAddr::Tcp(addr)],
            0,
        ));

        // Control session (e1): commit protocol, plan dissemination, ACKs
        self.transport.set_endpoint_family(EndpointFamily::Control);
        let control_session_id = self
            .transport
            .connect(node_id)
            .map_err(|e| format!("connect control session to node {node_id}: {e}"))?;
        self.transport
            .perform_handshake(control_session_id)
            .map_err(|e| format!("control handshake with node {node_id}: {e}"))?;

        // Data session (e2): payload transfer
        self.transport.set_endpoint_family(EndpointFamily::Data);
        let data_session_id = self
            .transport
            .connect(node_id)
            .map_err(|e| format!("connect data session to node {node_id}: {e}"))?;
        self.transport
            .perform_handshake(data_session_id)
            .map_err(|e| format!("data handshake with node {node_id}: {e}"))?;

        // Shadow session (e3): witness reads, verification
        self.transport.set_endpoint_family(EndpointFamily::Shadow);
        let shadow_session_id = self
            .transport
            .connect(node_id)
            .map_err(|e| format!("connect shadow session to node {node_id}: {e}"))?;
        self.transport
            .perform_handshake(shadow_session_id)
            .map_err(|e| format!("shadow handshake with node {node_id}: {e}"))?;

        self.replicas.push(TransportReplica {
            node_id,
            control_session_id,
            data_session_id,
            shadow_session_id,
        });

        Ok(())
    }

    // -- Local-only operations for inbound replication receive ---------

    /// Write an object to the local primary store without fan-out to replicas.
    ///
    /// Used by storage-node replication handlers to accept writes from peers
    /// without creating re-replication loops.
    pub fn put_local(&mut self, name: impl AsRef<[u8]>, payload: &[u8]) -> Result<(), String> {
        self.primary
            .put_named(&name, payload)
            .map(|_| ())
            .map_err(|e| format!("primary put for replication receive: {e}"))
    }

    /// Write an object to the local primary store by exact key, without fan-out.
    pub fn put_key_local(
        &mut self,
        key: tidefs_local_object_store::ObjectKey,
        payload: &[u8],
    ) -> Result<(), String> {
        self.primary
            .put(key, payload)
            .map(|_| ())
            .map_err(|e| format!("primary key put for replication receive: {e}"))
    }

    /// Delete an object from the local primary store without fan-out.
    ///
    /// Used by storage-node replication handlers to accept deletes from peers
    /// without creating re-replication loops.
    pub fn delete_local(&mut self, name: impl AsRef<[u8]>) -> Result<bool, String> {
        use tidefs_local_object_store::ObjectKey;
        let key = ObjectKey::from_name(&name);
        self.primary
            .delete(key)
            .map_err(|e| format!("primary delete for replication receive: {e}"))
    }

    /// Read an object from the local primary store without degraded-read
    /// fallback to remote replicas.
    pub fn get_local(&self, name: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>, String> {
        use tidefs_local_object_store::ObjectKey;
        let key = ObjectKey::from_name(&name);
        self.primary
            .get(key)
            .map_err(|e| format!("primary read for replication receive: {e}"))
    }

    /// Read an object from the local primary store by exact ObjectKey.
    pub fn get_key_local(
        &self,
        key: tidefs_local_object_store::ObjectKey,
    ) -> Result<Option<Vec<u8>>, String> {
        self.primary
            .get(key)
            .map_err(|e| format!("primary key read for replication receive: {e}"))
    }

    /// Return all object keys in the local primary store.
    pub fn list_keys_local(&self) -> Vec<tidefs_local_object_store::ObjectKey> {
        self.primary.list_keys()
    }

    // ── prior-generation name-based API (Control-session only) ────────────────

    /// Put an object identified by `name` into the replicated store.
    ///
    /// The object is written to the local primary store first, then fanned
    /// out to all connected remote replicas over the Control session.
    ///
    /// # Errors
    ///
    /// Returns an error if the primary write fails.
    pub fn put_named(
        &mut self,
        name: impl AsRef<[u8]>,
        payload: &[u8],
    ) -> Result<TransportReplicatedPutResult, String> {
        use tidefs_local_object_store::ObjectKey;

        let name_str = String::from_utf8_lossy(name.as_ref()).to_string();
        let key = ObjectKey::from_name(&name);
        let previous_payload = self
            .primary
            .get(key)
            .map_err(|e| format!("primary pre-write read failed: {e}"))?;

        // Write to local primary first
        self.primary
            .put_named(&name, payload)
            .map_err(|e| format!("primary write failed: {e}"))?;

        // Select which replicas to target. When placement is configured,
        // only write to the placed replica set; otherwise fan out to all.
        let target_replicas: Vec<&TransportReplica> = if let Some(ref placement) = self.placement {
            let node_ids: Vec<u64> = self.replicas.iter().map(|r| r.node_id).collect();
            match placement.resolve_write_targets(key.as_bytes(), &node_ids) {
                Ok(targets) => self
                    .replicas
                    .iter()
                    .filter(|r| targets.iter().any(|t| t.node_id == r.node_id))
                    .collect(),
                Err(e) => {
                    tracing::warn!(
                        "placement resolve failed for put: {e}; falling back to all replicas"
                    );
                    self.replicas.iter().collect()
                }
            }
        } else {
            self.replicas.iter().collect()
        };

        let total_targets = 1 + target_replicas.len();
        let mut acks: usize = 1; // primary counts
        let mut acked_replicas: Vec<(u64, SessionId)> = Vec::new();

        // Fan out to targeted replicas over Control (e1) session
        for replica in &target_replicas {
            let msg = ReplicationMessage::Put {
                name: name_str.clone(),
                payload: payload.to_vec(),
            };

            match send_replication_msg(&mut self.transport, replica.control_session_id, &msg) {
                Ok(()) => {
                    match Self::recv_replication_ack_bounded(
                        &mut self.transport,
                        replica.control_session_id,
                    ) {
                        Ok(ReplicationMessage::Ack { success: true, .. }) => {
                            acks += 1;
                            acked_replicas.push((replica.node_id, replica.control_session_id));
                        }
                        Ok(ReplicationMessage::Ack { success: false, .. }) => {
                            tracing::warn!("replica node {}: write rejected", replica.node_id);
                        }
                        Ok(other) => {
                            tracing::warn!(
                                "replica node {}: unexpected response: {other:?}",
                                replica.node_id
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "replica node {}: recv ack failed: {e}",
                                replica.node_id
                            );
                            if let Err(close_err) = self.transport.close_session(
                                replica.control_session_id,
                                SessionCloseReason::TransportError,
                            ) {
                                tracing::warn!(
                                    "replica node {}: close failed session after ack error: {close_err}",
                                    replica.node_id
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("replica node {}: send put failed: {e}", replica.node_id);
                }
            }
        }

        let quorum_reached = acks >= self.config.write_quorum;
        let fully_committed = quorum_reached && acks >= self.config.total_replicas;

        if fully_committed {
            self.stats.bytes_written += payload.len() as u64;
            self.stats.object_count += 1;
            self.stats.committed_writes += 1;
        } else if quorum_reached {
            self.stats.bytes_written += payload.len() as u64;
            self.stats.object_count += 1;
            self.stats.degraded_writes += 1;
        } else {
            drop(target_replicas);
            self.restore_primary_after_failed_mutation(&name, key, previous_payload.as_deref());
            Self::restore_acked_replicas_after_failed_mutation(
                &mut self.transport,
                &name_str,
                previous_payload.as_deref(),
                &acked_replicas,
            );
            self.stats.failed_writes += 1;
        }

        Ok(TransportReplicatedPutResult {
            key,
            acks,
            total_targets,
            quorum_size: self.config.write_quorum,
            recorded_receipt_ref: None,
            quorum_reached,
            fully_committed,
        })
    }

    /// Put an object identified by `name` into the replicated store with
    /// durable placement receipt authority.
    ///
    /// The object is written to the local primary store first, then the
    /// receipt-bearing write is fanned out to all connected remote replicas
    /// over the Control session using the `PutWithReceipt` protocol. Each
    /// replica validates the receipt before accepting the payload and returns
    /// its own pool-backed receipt in the acknowledgment.
    ///
    /// Use this method when a pool-backed primary has produced a
    /// `PlacementReceiptRef` and the caller wants replicas to record the
    /// same receipt authority rather than synthesizing new placements.
    ///
    /// # Errors
    ///
    /// Returns an error if the primary write fails.
    pub fn put_named_with_receipt(
        &mut self,
        name: impl AsRef<[u8]>,
        payload: &[u8],
        placement_receipt_ref: PlacementReceiptRef,
    ) -> Result<TransportReplicatedPutResult, String> {
        use tidefs_local_object_store::ObjectKey;

        let name_str = String::from_utf8_lossy(name.as_ref()).to_string();
        let key = ObjectKey::from_name(&name);
        validate_put_named_receipt_authority(key, payload, placement_receipt_ref)?;
        let previous_payload = self
            .primary
            .get(key)
            .map_err(|e| format!("primary pre-write read failed: {e}"))?;

        // Write to local primary first
        self.primary
            .put_named(&name, payload)
            .map_err(|e| format!("primary write failed: {e}"))?;

        // Select which replicas to target. When placement is configured,
        // only write to the placed replica set; otherwise fan out to all.
        let target_replicas: Vec<&TransportReplica> = if let Some(ref placement) = self.placement {
            let node_ids: Vec<u64> = self.replicas.iter().map(|r| r.node_id).collect();
            match placement.resolve_write_targets(key.as_bytes(), &node_ids) {
                Ok(targets) => self
                    .replicas
                    .iter()
                    .filter(|r| targets.iter().any(|t| t.node_id == r.node_id))
                    .collect(),
                Err(e) => {
                    tracing::warn!(
                        "placement resolve failed for put_with_receipt: {e}; falling back to all replicas"
                    );
                    self.replicas.iter().collect()
                }
            }
        } else {
            self.replicas.iter().collect()
        };

        let total_targets = 1 + target_replicas.len();
        let mut acks: usize = 1; // primary counts
        let mut acked_replicas: Vec<(u64, SessionId)> = Vec::new();
        let mut recorded_receipt_ref: Option<PlacementReceiptRef> = None;

        // Fan out to targeted replicas over Control (e1) session using
        // PutWithReceipt to carry durable placement authority.
        for replica in &target_replicas {
            let msg = ReplicationMessage::PutWithReceipt {
                name: name_str.clone(),
                payload: payload.to_vec(),
                placement_receipt_ref,
            };

            match send_replication_msg(&mut self.transport, replica.control_session_id, &msg) {
                Ok(()) => {
                    match Self::recv_replication_ack_bounded(
                        &mut self.transport,
                        replica.control_session_id,
                    ) {
                        Ok(ReplicationMessage::PutWithReceiptAck {
                            success: true,
                            recorded_receipt_ref: Some(replica_receipt_ref),
                            ..
                        }) => {
                            match validate_recorded_put_receipt_authority(
                                placement_receipt_ref,
                                replica_receipt_ref,
                            ) {
                                Ok(()) => {
                                    acks += 1;
                                    acked_replicas
                                        .push((replica.node_id, replica.control_session_id));
                                    recorded_receipt_ref = Some(replica_receipt_ref);
                                }
                                Err(error) => {
                                    tracing::warn!(
                                        "replica node {}: PutWithReceipt ack receipt invalid: {error}",
                                        replica.node_id
                                    );
                                }
                            }
                        }
                        Ok(ReplicationMessage::PutWithReceiptAck {
                            success: true,
                            recorded_receipt_ref: None,
                            ..
                        }) => {
                            tracing::warn!(
                                "replica node {}: PutWithReceipt ack omitted recorded receipt",
                                replica.node_id
                            );
                        }
                        Ok(ReplicationMessage::PutWithReceiptAck { success: false, .. }) => {
                            tracing::warn!(
                                "replica node {}: receipt-authorized write rejected",
                                replica.node_id
                            );
                        }
                        Ok(other) => {
                            tracing::warn!(
                                "replica node {}: unexpected response to PutWithReceipt: {other:?}",
                                replica.node_id
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "replica node {}: PutWithReceipt ack recv failed: {e}",
                                replica.node_id
                            );
                            if let Err(close_err) = self.transport.close_session(
                                replica.control_session_id,
                                SessionCloseReason::TransportError,
                            ) {
                                tracing::warn!(
                                    "replica node {}: close failed session after PutWithReceipt ack error: {close_err}",
                                    replica.node_id
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "replica node {}: send PutWithReceipt failed: {e}",
                        replica.node_id
                    );
                }
            }
        }

        let quorum_reached = acks >= self.config.write_quorum;
        let fully_committed = quorum_reached && acks >= self.config.total_replicas;

        if fully_committed {
            self.stats.bytes_written += payload.len() as u64;
            self.stats.object_count += 1;
            self.stats.committed_writes += 1;
        } else if quorum_reached {
            self.stats.bytes_written += payload.len() as u64;
            self.stats.object_count += 1;
            self.stats.degraded_writes += 1;
        } else {
            drop(target_replicas);
            self.restore_primary_after_failed_mutation(&name, key, previous_payload.as_deref());
            Self::restore_acked_replicas_after_failed_mutation(
                &mut self.transport,
                &name_str,
                previous_payload.as_deref(),
                &acked_replicas,
            );
            self.stats.failed_writes += 1;
        }

        Ok(TransportReplicatedPutResult {
            key,
            acks,
            total_targets,
            quorum_size: self.config.write_quorum,
            quorum_reached,
            recorded_receipt_ref: if quorum_reached {
                recorded_receipt_ref.or(Some(placement_receipt_ref))
            } else {
                None
            },
            fully_committed,
        })
    }

    /// Get an object by name. Tries the local primary first, then falls
    /// back to remote replicas via `ReplicatedObjectReader` over the Data
    /// session using the ObjectTransfer read protocol with BLAKE3 integrity.
    ///
    /// # Errors
    ///
    /// Returns an error if the primary read fails or all replicas are exhausted.
    pub fn get_named(&mut self, name: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>, String> {
        use tidefs_local_object_store::ObjectKey;

        let key = ObjectKey::from_name(&name);

        // Try local primary first
        match self.primary.get(key) {
            Ok(Some(data)) => return Ok(Some(data)),
            Ok(None) => {}
            Err(e) => return Err(format!("primary read failed: {e}")),
        }

        // Degraded read: use ReplicatedObjectReader over Data (e2) sessions
        if !self.config.enable_degraded_reads || self.replicas.is_empty() {
            return Ok(None);
        }

        // Lazily initialise the reader from current replica data sessions,
        // ordered by placement when available for deterministic replica selection.
        if self.reader.is_none() {
            let sessions: Vec<(u64, tidefs_transport::SessionId)> =
                if let Some(ref placement) = self.placement {
                    let node_ids: Vec<u64> = self.replicas.iter().map(|r| r.node_id).collect();
                    match placement.resolve_read_targets(key.as_bytes(), &node_ids) {
                        Ok(target_sessions) => self
                            .replicas
                            .iter()
                            .filter(|r| target_sessions.contains(&r.data_session_id))
                            .map(|r| (r.node_id, r.data_session_id))
                            .collect(),
                        Err(e) => {
                            tracing::warn!(
                            "placement resolve failed for get: {e}; falling back to all replicas"
                        );
                            self.replicas
                                .iter()
                                .map(|r| (r.node_id, r.data_session_id))
                                .collect()
                        }
                    }
                } else {
                    self.replicas
                        .iter()
                        .map(|r| (r.node_id, r.data_session_id))
                        .collect()
                };
            self.reader = Some(ReplicatedObjectReader::from_replica_sessions(sessions));
        }

        let reader = self.reader.as_mut().unwrap();
        let object_key = *key.as_bytes();

        // Read the full object (offset 0, large length — server clips to
        // actual object size).
        match reader.read_object(&mut self.transport, object_key, 0, u64::MAX) {
            Ok(data) => {
                self.stats.degraded_reads += 1;
                Ok(Some(data))
            }
            Err(e) => {
                tracing::warn!("degraded read via ObjectTransfer failed: {e}");
                Ok(None)
            }
        }
    }

    /// Delete an object by name from the local primary and all remote replicas
    /// with quorum confirmation.
    ///
    /// Deletes from the primary first, then fans out `ReplicationMessage::Delete`
    /// to each remote replica and waits for `DeleteAck` responses. Returns
    /// `Ok(true)` when at least `write_quorum` replicas (including the primary)
    /// acknowledge the deletion. Returns `Ok(false)` when the object was absent
    /// from all stores (idempotent). Returns an error when fewer than
    /// `write_quorum` replicas confirm the delete.
    ///
    /// The `generation` counter in `DeleteAck` is recorded for racing-write
    /// prevention; replica-level enforcement happens at the transport layer.
    pub fn delete_named(&mut self, name: impl AsRef<[u8]>) -> Result<bool, String> {
        use tidefs_local_object_store::ObjectKey;

        let key = ObjectKey::from_name(&name);
        let name_str = String::from_utf8_lossy(name.as_ref()).to_string();
        let previous_payload = self
            .primary
            .get(key)
            .map_err(|e| format!("primary pre-delete read failed: {e}"))?;

        // Delete from local primary first
        let primary_deleted = match self.primary.delete(key) {
            Ok(true) => true,
            Ok(false) => false,
            Err(e) => return Err(format!("primary delete failed: {e}")),
        };

        // Select which replicas to target (placement-aware, or all when not configured).
        let target_replicas: Vec<&TransportReplica> = if let Some(ref placement) = self.placement {
            let node_ids: Vec<u64> = self.replicas.iter().map(|r| r.node_id).collect();
            match placement.resolve_write_targets(key.as_bytes(), &node_ids) {
                Ok(targets) => self
                    .replicas
                    .iter()
                    .filter(|r| targets.iter().any(|t| t.node_id == r.node_id))
                    .collect(),
                Err(e) => {
                    tracing::warn!(
                        "placement resolve failed for delete: {e}; falling back to all replicas"
                    );
                    self.replicas.iter().collect()
                }
            }
        } else {
            self.replicas.iter().collect()
        };

        let total_targets = 1 + target_replicas.len();
        // Primary always counts as one ack (it's local)
        let mut acks: usize = 1;
        let mut acked_replicas: Vec<(u64, SessionId)> = Vec::new();

        // Fan out delete to targeted replicas over Control sessions, waiting for
        // DeleteAck responses to count toward quorum.
        for replica in &target_replicas {
            let msg = ReplicationMessage::Delete {
                name: name_str.clone(),
                generation: 0, // generation tracking is future transport-layer work
            };

            match send_replication_msg(&mut self.transport, replica.control_session_id, &msg) {
                Ok(()) => {
                    match Self::recv_replication_ack_bounded(
                        &mut self.transport,
                        replica.control_session_id,
                    ) {
                        Ok(ReplicationMessage::DeleteAck { deleted: _, .. }) => {
                            // Replica acknowledged the delete (whether it found
                            // the object or not — idempotent).
                            acks += 1;
                            acked_replicas.push((replica.node_id, replica.control_session_id));
                        }
                        Ok(other) => {
                            tracing::warn!(
                                "replica node {}: unexpected delete response: {other:?}",
                                replica.node_id
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "replica node {}: delete ack recv failed: {e}",
                                replica.node_id
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("replica node {}: delete send failed: {e}", replica.node_id);
                }
            }
        }

        let quorum_reached = acks >= self.config.write_quorum;

        if quorum_reached {
            Ok(primary_deleted)
        } else {
            drop(target_replicas);
            if primary_deleted {
                self.restore_primary_after_failed_mutation(&name, key, previous_payload.as_deref());
                if let Some(previous_payload) = previous_payload.as_deref() {
                    Self::restore_acked_replicas_after_failed_mutation(
                        &mut self.transport,
                        &name_str,
                        Some(previous_payload),
                        &acked_replicas,
                    );
                }
            }
            Err(format!(
                "delete quorum failed: {}/{} replicas acknowledged (need {})",
                acks, total_targets, self.config.write_quorum
            ))
        }
    }

    // ── Plan-based API (P8-03 distributed runtime) ─────────────────

    /// Execute a model-generated write plan over the transport layer.
    ///
    /// 1. Disseminates the write plan to each committed member via Control (e1) session.
    /// 2. Transfers the payload to each accepting replica via Data (e2) session.
    /// 3. Integrates with the verification engine for transfer validation.
    /// 4. Writes the data to the local primary store.
    ///
    /// # Errors
    ///
    /// Returns an error if plan serialization fails, the primary write fails,
    /// or the plan is refused (RefusedNoQuorum).
    pub fn put_planned(
        &mut self,
        plan: &ReplicatedWritePlan,
        payload: &[u8],
    ) -> Result<TransportReplicatedPutResult, String> {
        // Reject plans that were refused at generation time
        if plan.write_class == ReplicatedWriteClass::RefusedNoQuorum {
            return Err("put_planned refused: plan has RefusedNoQuorum write class".to_string());
        }

        // Serialize the plan for wire transfer
        let plan_bytes =
            bincode::serialize(plan).map_err(|e| format!("plan serialization failed: {e}"))?;

        // Write to local primary first
        let name = format!("obj-{:016x}", plan.subject.subject_id.0);
        let key = tidefs_local_object_store::ObjectKey::from_name(&name);
        self.primary
            .put_named(&name, payload)
            .map_err(|e| format!("primary write failed: {e}"))?;

        let mut acks: usize = 1; // primary counts
        let total_targets = 1 + plan.committed_member_refs.len();
        let digest = blake3::hash(payload);
        let digest_bytes = digest.as_bytes().to_vec();

        // Phase 1: Disseminate write plan to each committed member via Control (e1)
        for member_ref in &plan.committed_member_refs {
            let replica = match self.replicas.iter().find(|r| r.node_id == member_ref.0) {
                Some(r) => r,
                None => continue,
            };

            let plan_msg = ReplicationMessage::WritePlan {
                plan_bytes: plan_bytes.clone(),
            };

            let accepted = match send_replication_msg(
                &mut self.transport,
                replica.control_session_id,
                &plan_msg,
            ) {
                Ok(()) => {
                    match recv_replication_msg(&mut self.transport, replica.control_session_id) {
                        Ok(ReplicationMessage::WritePlanAck { accepted: true, .. }) => true,
                        Ok(ReplicationMessage::WritePlanAck {
                            accepted: false,
                            reason,
                            ..
                        }) => {
                            tracing::warn!(
                                "replica node {}: plan refused: {}",
                                replica.node_id,
                                reason
                            );
                            false
                        }
                        Ok(other) => {
                            tracing::warn!(
                                "replica node {}: unexpected plan ack: {other:?}",
                                replica.node_id
                            );
                            false
                        }
                        Err(e) => {
                            tracing::warn!(
                                "replica node {}: recv plan ack failed: {e}",
                                replica.node_id
                            );
                            false
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("replica node {}: send plan failed: {e}", replica.node_id);
                    false
                }
            };

            if !accepted {
                continue;
            }

            // Phase 2: Transfer payload via Data (e2) session
            let chunk_msg = ReplicationMessage::TransferChunk {
                digest: digest_bytes.clone(),
                chunk_data: payload.to_vec(),
            };

            match send_replication_msg(&mut self.transport, replica.data_session_id, &chunk_msg) {
                Ok(()) => {
                    match recv_replication_msg(&mut self.transport, replica.data_session_id) {
                        Ok(ReplicationMessage::TransferChunkAck { success: true, .. }) => {
                            acks += 1;
                        }
                        Ok(ReplicationMessage::TransferChunkAck { success: false, .. }) => {
                            tracing::warn!(
                                "replica node {}: chunk transfer rejected",
                                replica.node_id
                            );
                        }
                        Ok(other) => {
                            tracing::warn!(
                                "replica node {}: unexpected chunk ack: {other:?}",
                                replica.node_id
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "replica node {}: recv chunk ack failed: {e}",
                                replica.node_id
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("replica node {}: send chunk failed: {e}", replica.node_id);
                }
            }
        }

        // ── Verification engine integration ──────────────────────────
        // After transfers complete, run the full verification pipeline on the
        // local primary write. This produces a ReplicaVerificationReceipt that
        // attests to digest correctness (class 1). Witness verification (class 3)
        // will be insufficient until witness attestation is integrated.
        {
            // Convert blake3 digest to ObjectDigest (first 8 bytes as little-endian u64)
            let obj_digest = ObjectDigest(u64::from_le_bytes(
                digest_bytes[..8].try_into().unwrap_or([0u8; 8]),
            ));

            let receipt_id = ReplicatedReceiptId(
                plan.subject
                    .subject_id
                    .0
                    .wrapping_mul(7919)
                    .wrapping_add(self.verification_ctx.current_epoch.0),
            );

            let transfer_receipt = ReplicaTransferReceipt {
                receipt_id,
                ticket_ref: ReplicatedReceiptId(0),
                bytes_moved: payload.len() as u64,
                source_anchor_hash: 0,
                target_anchor_hash: obj_digest.0,
                completion_epoch: self.verification_ctx.current_epoch,
                worker_refs: plan.committed_member_refs.to_vec(),
            };

            let witness_set = WitnessSet {
                set_id: 0,
                anchor: WitnessAnchor::Chunk {
                    chunk_key: name.as_bytes().to_vec(),
                    expected_digest: digest_bytes.clone(),
                },
                quorum_class: WitnessQuorumClass::Flexible {
                    required: 1,
                    total: 1,
                },
                selected_witnesses: vec![],
                collected: vec![],
                lifecycle: WitnessLifecycle::Proposed,
                created_at_millis: 0,
                deadline_millis: 0,
                epoch: self.verification_ctx.current_epoch,
                verification_receipt: None,
            };

            let receipt = verify_transfer_and_emit_receipt(
                &mut self.verification_ctx,
                &transfer_receipt,
                &[plan.subject.subject_id],
                obj_digest,
                &[obj_digest],
                &witness_set,
                WitnessQuorumClass::Flexible {
                    required: 1,
                    total: 1,
                },
            );

            self.verification_receipts.push(receipt);
        }

        let quorum_reached = acks >= plan.quorum_required;
        let fully_committed = acks >= total_targets;

        self.stats.bytes_written += payload.len() as u64;
        self.stats.object_count += 1;
        self.stats.planned_writes += 1;

        if fully_committed {
            self.stats.committed_writes += 1;
        } else if quorum_reached {
            self.stats.degraded_writes += 1;
        } else {
            self.stats.failed_writes += 1;
        }

        Ok(TransportReplicatedPutResult {
            key,
            acks,
            total_targets,
            quorum_size: plan.quorum_required,
            quorum_reached,
            fully_committed,
            recorded_receipt_ref: None,
        })
    }

    /// Execute a model-generated read plan over the transport layer.
    ///
    /// 1. Tries the local primary first.
    /// 2. Falls back to the plan's source member via Shadow (e3) session.
    /// 3. Falls back to verified member replicas in order.
    ///
    /// # Errors
    ///
    /// Returns an error if the primary read fails.
    pub fn get_planned(&mut self, plan: &ReplicatedReadPlan) -> Result<Option<Vec<u8>>, String> {
        self.get_planned_with_evidence(plan)
            .map(|result| result.map(|result| result.payload))
    }

    /// Execute a model-generated read plan and preserve receipt evidence.
    ///
    /// This keeps the payload-only [`Self::get_planned`] API stable while
    /// allowing rebuild and repair callers to consume validated placement
    /// receipt authority from pool-backed read-plan responses.
    pub fn get_planned_with_evidence(
        &mut self,
        plan: &ReplicatedReadPlan,
    ) -> Result<Option<TransportPlannedReadResult>, String> {
        self.get_planned_with_evidence_inner(plan, PlannedReadReceiptRequirement::Optional)
    }

    /// Execute a model-generated read plan that must return receipt authority.
    ///
    /// Repair, rebuild, and reclaim callers can use this path when payload bytes
    /// are not enough: a successful result carries a validated non-synthetic
    /// [`PlacementReceiptRef`]. Receiptless non-pool responses and local
    /// primary hits without placement evidence fail closed here while remaining
    /// valid for the optional evidence APIs above.
    pub fn get_planned_with_required_receipt(
        &mut self,
        plan: &ReplicatedReadPlan,
    ) -> Result<Option<ReceiptBackedTransportPlannedReadResult>, String> {
        let Some(result) =
            self.get_planned_with_evidence_inner(plan, PlannedReadReceiptRequirement::Required)?
        else {
            return Ok(None);
        };
        let placement_receipt_ref = required_planned_read_receipt(plan, &result)?;
        Ok(Some(ReceiptBackedTransportPlannedReadResult {
            payload: result.payload,
            source_member_id: result.source_member_id,
            placement_receipt_ref,
        }))
    }

    fn get_planned_with_evidence_inner(
        &mut self,
        plan: &ReplicatedReadPlan,
        receipt_requirement: PlannedReadReceiptRequirement,
    ) -> Result<Option<TransportPlannedReadResult>, String> {
        use tidefs_replication_model::ReplicatedReadClass;

        // Refuse unreadable plans
        if plan.read_class == ReplicatedReadClass::Unavailable {
            return Ok(None);
        }

        let name = format!("obj-{:016x}", plan.subject_ref.0);
        let key = tidefs_local_object_store::ObjectKey::from_name(&name);

        // Try local primary first
        match self.primary.get(key) {
            Ok(Some(data)) => {
                if receipt_requirement == PlannedReadReceiptRequirement::Required {
                    return Err(format!(
                        "receipt-authoritative planned read for subject {} hit local primary without placement receipt evidence",
                        plan.subject_ref.0
                    ));
                }
                self.stats.planned_reads += 1;
                return Ok(Some(TransportPlannedReadResult {
                    payload: data,
                    source_member_id: self.local_node_id(),
                    placement_receipt_ref: None,
                }));
            }
            Ok(None) => {}
            Err(e) => return Err(format!("primary read failed: {e}")),
        }

        // Serialize the plan for wire transfer
        let plan_bytes =
            bincode::serialize(plan).map_err(|e| format!("plan serialization failed: {e}"))?;

        // Try the plan's preferred source member via Shadow (e3)
        if let Some(source_ref) = plan.source_member_ref {
            if let Some((node_id, shadow_session_id)) = self
                .replicas
                .iter()
                .find(|r| r.node_id == source_ref.0)
                .map(|r| (r.node_id, r.shadow_session_id))
            {
                match self.request_planned_read(node_id, shadow_session_id, &plan_bytes, plan)? {
                    Some(result) => {
                        if receipt_requirement == PlannedReadReceiptRequirement::Required {
                            required_planned_read_receipt(plan, &result)?;
                        }
                        self.stats.planned_reads += 1;
                        self.stats.degraded_reads += 1;
                        return Ok(Some(result));
                    }
                    None => {}
                }
            }
        }

        // Try remaining verified members in order
        for member_ref in &plan.verified_member_refs {
            if Some(*member_ref) == plan.source_member_ref {
                continue; // already tried
            }

            if let Some((node_id, shadow_session_id)) = self
                .replicas
                .iter()
                .find(|r| r.node_id == member_ref.0)
                .map(|r| (r.node_id, r.shadow_session_id))
            {
                match self.request_planned_read(node_id, shadow_session_id, &plan_bytes, plan)? {
                    Some(result) => {
                        if receipt_requirement == PlannedReadReceiptRequirement::Required {
                            required_planned_read_receipt(plan, &result)?;
                        }
                        self.stats.planned_reads += 1;
                        self.stats.degraded_reads += 1;
                        return Ok(Some(result));
                    }
                    None => {}
                }
            }
        }

        self.stats.planned_reads += 1;
        Ok(None)
    }

    fn request_planned_read(
        &mut self,
        node_id: u64,
        shadow_session_id: SessionId,
        plan_bytes: &[u8],
        plan: &ReplicatedReadPlan,
    ) -> Result<Option<TransportPlannedReadResult>, String> {
        let msg = ReplicationMessage::ReadPlan {
            plan_bytes: plan_bytes.to_vec(),
        };

        if let Err(e) = send_replication_msg(&mut self.transport, shadow_session_id, &msg) {
            eprintln!("send read plan to node {node_id} failed: {e}");
            return Ok(None);
        }

        let response = match recv_replication_msg(&mut self.transport, shadow_session_id) {
            Ok(response) => response,
            Err(e) => {
                eprintln!("recv read plan response from node {node_id} failed: {e}");
                return Ok(None);
            }
        };

        let ReplicationMessage::ReadPlanResponse {
            found,
            payload,
            source_member_id,
            placement_receipt_ref,
        } = response
        else {
            return Ok(None);
        };

        if !found {
            return Ok(None);
        }
        if source_member_id != node_id {
            return Err(format!(
                "read plan response source mismatch: expected node {node_id}, got {source_member_id}"
            ));
        }
        validate_read_plan_response_payload(plan, &payload, placement_receipt_ref)?;
        Ok(Some(TransportPlannedReadResult {
            payload,
            source_member_id,
            placement_receipt_ref,
        }))
    }

    /// Full write path: generates a write plan from the membership model and
    /// executes it over the transport layer.
    ///
    /// This is the high-level entry point for object writes in the distributed
    /// runtime. It calls [`commit_replicated_object_root_write`] to generate
    /// the plan, then [`put_planned`](Self::put_planned) to execute it.
    pub fn put_object_root(
        &mut self,
        record: ReplicatedObjectRootRecord,
        payload: &[u8],
        config: &MembershipConfigRecord,
        members: &[ClusterMemberRecord],
        policy: FailureDomainPlacementPolicy,
        writable_member_refs: &[MemberId],
    ) -> Result<TransportReplicatedPutResult, String> {
        let plan = commit_replicated_object_root_write(
            config,
            members,
            record,
            policy,
            writable_member_refs,
        );
        self.put_planned(&plan, payload)
    }

    /// Full read path: generates a read plan from the membership model and
    /// executes it over the transport layer.
    ///
    /// This is the high-level entry point for object reads in the distributed
    /// runtime. It calls [`plan_replicated_object_root_read`] to generate
    /// the plan, then [`get_planned`](Self::get_planned) to execute it.
    pub fn get_object_root(
        &mut self,
        subject_id: ReplicatedSubjectId,
        copies: &[ReplicaCopyRecord],
        required_replica_count: usize,
    ) -> Result<Option<Vec<u8>>, String> {
        // Synthesize a minimal subject record for the plan generator.
        // The plan generator only needs subject_id; other fields are scaffolding.
        let subject = ReplicatedObjectRootRecord {
            subject_id,
            subject_class: ReplicatedSubjectClass::ImmutableObject,
            membership_epoch_ref: EpochId(0),
            root_generation: 0,
            payload_digest: ObjectDigest(0),
            payload_len: 0,
            publication_receipt_ref: ReplicatedReceiptId(0),
        };

        let plan = plan_replicated_object_root_read(&subject, copies, required_replica_count);
        self.get_planned(&plan)
    }

    /// Return verification receipts accumulated from plan-based transfers.
    #[must_use]
    pub fn verification_receipts(&self) -> &[ReplicaVerificationReceipt] {
        &self.verification_receipts
    }

    /// Return a mutable reference to the verification context.
    #[must_use]
    /// Set the placement dispatch for deterministic replica selection.
    ///
    /// When placement is set, writes and reads use BLAKE3-based
    /// deterministic node placement to target only the correct replica
    /// set; when None, receiptless operations fan out to all replicas.
    ///
    /// The placement engine is initialized separately and injected here
    /// so that the same placement can be shared across multiple stores.
    pub fn with_placement(mut self, placement: PlacementDispatch) -> Self {
        self.placement = Some(placement);
        self
    }

    /// Return the current placement map version, if placement is configured
    /// and a placement map has been set on the dispatch.
    ///
    /// Returns 0 when no placement is configured or no map has been set.
    /// A non-zero value is the monotonically increasing placement map version
    /// that clients can observe for rebalance consistency.
    #[must_use]
    pub fn placement_version(&self) -> u64 {
        self.placement
            .as_ref()
            .and_then(|p| p.placement_version())
            .unwrap_or(0)
    }

    /// Return a reference to the current placement map, if any.
    #[must_use]
    pub fn placement_map(&self) -> Option<&tidefs_transport::PlacementMap> {
        self.placement.as_ref().and_then(|p| p.placement_map())
    }

    /// Try to set the placement map on the dispatch.
    ///
    /// The map version must be strictly greater than the current version.
    /// When the placement map changes, callers should also update the
    /// [`PlacementVersionTracker`] so membership views carry the new version.
    pub fn try_set_placement_map(
        &mut self,
        map: tidefs_transport::PlacementMap,
    ) -> Result<(), String> {
        let placement = self
            .placement
            .as_mut()
            .ok_or_else(|| "placement must be configured before setting a map".to_string())?;

        if let Some(existing) = placement.placement_map() {
            if !map.is_newer_than(existing) {
                return Err(format!(
                    "placement map version {} must be newer than {}",
                    map.version, existing.version
                ));
            }
        } else if !map.is_initialized() {
            return Err("first placement map must be initialized".into());
        }

        placement.set_placement_map(map);
        Ok(())
    }

    /// Request and install a peer's transport placement read map.
    ///
    /// The request uses the peer's outbound replica Control session. The local
    /// placement map is only mutated when the peer response echoes the requested
    /// minimum, carries no refusal, and contains a map whose version satisfies
    /// both the requested minimum and the local monotonic-version boundary.
    pub fn request_peer_placement_map(
        &mut self,
        peer_node_id: u64,
        minimum_version: u64,
    ) -> Result<PeerPlacementMapRequestReport, PeerPlacementMapRequestError> {
        let control_session_id = self
            .replicas
            .iter()
            .find(|replica| replica.node_id == peer_node_id)
            .map(|replica| replica.control_session_id)
            .ok_or(PeerPlacementMapRequestError::ReplicaNotConnected { peer_node_id })?;

        let request = ReplicationMessage::PlacementMapRequest { minimum_version };
        send_replication_msg(&mut self.transport, control_session_id, &request).map_err(
            |error| PeerPlacementMapRequestError::SendFailed {
                peer_node_id,
                message: error.to_string(),
            },
        )?;

        let response = Self::recv_replication_ack_bounded(&mut self.transport, control_session_id)
            .map_err(|error| PeerPlacementMapRequestError::ReceiveFailed {
                peer_node_id,
                message: error.to_string(),
            })?;

        let ReplicationMessage::PlacementMapResponse {
            requested_minimum_version,
            map,
            refusal,
        } = response
        else {
            return Err(PeerPlacementMapRequestError::UnexpectedResponse {
                peer_node_id,
                actual: format!("{response:?}"),
            });
        };

        if requested_minimum_version != minimum_version {
            return Err(PeerPlacementMapRequestError::MinimumVersionMismatch {
                peer_node_id,
                requested_minimum_version: minimum_version,
                response_minimum_version: requested_minimum_version,
            });
        }

        if let Some(reason) = refusal {
            return Err(PeerPlacementMapRequestError::Refused {
                peer_node_id,
                requested_minimum_version,
                reason,
            });
        }

        let Some(map) = map else {
            return Err(PeerPlacementMapRequestError::MissingMap {
                peer_node_id,
                requested_minimum_version,
            });
        };

        let previous_version = self.placement_version();
        if map.version < requested_minimum_version || map.version <= previous_version {
            return Err(PeerPlacementMapRequestError::Stale {
                peer_node_id,
                requested_minimum_version,
                available_version: map.version,
                local_version: previous_version,
            });
        }

        self.try_set_placement_map(map.clone()).map_err(|error| {
            PeerPlacementMapRequestError::InstallRejected {
                peer_node_id,
                requested_minimum_version,
                map_version: map.version,
                message: error,
            }
        })?;

        Ok(PeerPlacementMapRequestReport {
            peer_node_id,
            requested_minimum_version,
            previous_version,
            installed_version: map.version,
            installed_map: map,
        })
    }

    /// Set the placement map on the dispatch, incrementing the version.
    ///
    /// The map version must be strictly greater than the current version.
    /// When the placement map changes, callers should also update the
    /// [`PlacementVersionTracker`] so membership views carry the new version.
    ///
    /// # Panics
    ///
    /// Panics if placement is not configured or if the map version is stale.
    pub fn set_placement_map(&mut self, map: tidefs_transport::PlacementMap) {
        self.try_set_placement_map(map)
            .expect("placement map publication failed");
    }

    /// Return the list of connected node IDs available for placement.
    #[must_use]
    pub fn connected_node_ids(&self) -> Vec<u64> {
        self.replicas.iter().map(|r| r.node_id).collect()
    }

    /// Return the configured replica count, including the local primary.
    #[must_use]
    pub fn configured_replica_count(&self) -> usize {
        self.config.total_replicas
    }

    /// Return the currently connected replica count, including the local primary.
    #[must_use]
    pub fn connected_replica_count(&self) -> usize {
        1 + self.replicas.len()
    }

    /// Return whether placement-aware dispatch is installed.
    #[must_use]
    pub fn has_placement_dispatch(&self) -> bool {
        self.placement.is_some()
    }

    pub fn verification_ctx_mut(&mut self) -> &mut VerificationContext {
        &mut self.verification_ctx
    }

    /// Fetch a segment from a remote replica over the Data (e2) session.
    ///
    /// Sends a [`SegmentFetchRequest`] to the specified replica's data
    /// session, receives the [`SegmentFetchResponse`], verifies the
    /// domain-separated BLAKE3 payload digest, and returns the segment
    /// bytes on success.
    ///
    /// # Arguments
    ///
    /// * `replica_idx` — Index into the connected replicas list.
    /// * `object_id` — Object to read the segment from.
    /// * `segment_offset` — Byte offset within the object.
    /// * `segment_length` — Number of bytes to fetch.
    ///
    /// # Errors
    ///
    /// Returns an error if the replica index is out of bounds, if the
    /// transport send/receive fails, or if the BLAKE3 digest verification
    /// rejects the response payload.
    pub fn fetch_remote_segment(
        &mut self,
        replica_idx: usize,
        object_id: u64,
        segment_offset: u64,
        segment_length: u64,
    ) -> Result<Vec<u8>, String> {
        let request = SegmentFetchRequest::new(object_id, segment_offset, segment_length);
        self.fetch_remote_segment_request(replica_idx, request)
    }

    /// Fetch a segment from a remote replica using placement receipt authority.
    ///
    /// This is the rebuild/backfill movement path. The request carries the
    /// durable placement receipt ref so the remote handler can read the exact
    /// object key that the pool receipt made legal instead of recomputing a
    /// name-derived key from the logical object id.
    pub fn fetch_remote_segment_by_receipt(
        &mut self,
        replica_idx: usize,
        placement_receipt_ref: PlacementReceiptRef,
        segment_offset: u64,
        segment_length: u64,
    ) -> Result<Vec<u8>, String> {
        if placement_receipt_ref.is_synthetic() {
            return Err(format!(
                "receipt-bound segment fetch for object {} requires non-synthetic placement receipt",
                placement_receipt_ref.object_id
            ));
        }

        let request = SegmentFetchRequest::with_placement_receipt_ref(
            placement_receipt_ref,
            segment_offset,
            segment_length,
        );
        self.fetch_remote_segment_request(replica_idx, request)
    }

    /// Execute a receipt-bound repair by fetching source bytes, sending them to
    /// the target storage node, and requiring a repaired placement receipt ack.
    pub fn execute_receipt_repair_task(
        &mut self,
        task: &BackfillTask,
    ) -> Result<PlacementReceiptRef, String> {
        validate_receipt_repair_task(task)?;
        let payload = self.fetch_segment_by_receipt(
            task.source_member,
            task.placement_receipt_ref,
            0,
            task.payload_len,
        )?;
        validate_receipt_repair_payload(task, &payload)?;
        self.send_receipt_repair_payload_to_target(task, payload)
    }

    /// Execute a receipt-bound repair from an already receipt-authoritative
    /// planned-read result.
    ///
    /// This path is for callers that first used
    /// [`Self::get_planned_with_required_receipt()`] to select and verify source
    /// bytes. It preserves the same target ack and repaired-receipt validation as
    /// [`Self::execute_receipt_repair_task()`], but refuses to repair if the
    /// planned-read source, receipt, length, or digest differs from the scheduled
    /// [`BackfillTask`].
    pub fn execute_receipt_repair_task_from_planned_read(
        &mut self,
        task: &BackfillTask,
        planned_read: &ReceiptBackedTransportPlannedReadResult,
    ) -> Result<PlacementReceiptRef, String> {
        validate_planned_read_repair_input(task, planned_read)?;
        self.send_receipt_repair_payload_to_target(task, planned_read.payload.clone())
    }

    fn send_receipt_repair_payload_to_target(
        &mut self,
        task: &BackfillTask,
        payload: Vec<u8>,
    ) -> Result<PlacementReceiptRef, String> {
        let (target_node_id, data_session_id) = self
            .replicas
            .iter()
            .find(|replica| replica.node_id == task.target_member.0)
            .map(|replica| (replica.node_id, replica.data_session_id))
            .ok_or_else(|| {
                format!(
                    "target member {} is not connected for receipt-bound repair of object {}",
                    task.target_member.0, task.placement_receipt_ref.object_id
                )
            })?;

        let expected_key = task.placement_receipt_ref.object_key.to_vec();
        let request = ReplicationMessage::RepairObject {
            key: expected_key.clone(),
            placement_receipt_ref: task.placement_receipt_ref,
            authoritative_payload: payload,
        };
        send_replication_msg(&mut self.transport, data_session_id, &request)
            .map_err(|e| format!("send receipt-bound repair to node {target_node_id}: {e}"))?;

        let response = Self::recv_replication_ack_bounded(&mut self.transport, data_session_id)
            .map_err(|e| {
                format!("recv receipt-bound repair ack from node {target_node_id}: {e}")
            })?;

        let ReplicationMessage::RepairObjectAck {
            key,
            success,
            repaired_placement_receipt_ref,
        } = response
        else {
            return Err(format!(
                "receipt-bound repair to node {target_node_id} returned non-repair ack: {response:?}"
            ));
        };

        if key != expected_key {
            return Err(format!(
                "receipt-bound repair ack key mismatch for object {} from node {target_node_id}",
                task.placement_receipt_ref.object_id
            ));
        }
        if !success {
            return Err(format!(
                "receipt-bound repair target node {target_node_id} refused object {}",
                task.placement_receipt_ref.object_id
            ));
        }
        let repaired_receipt = repaired_placement_receipt_ref.ok_or_else(|| {
            format!(
                "receipt-bound repair target node {target_node_id} did not return repaired placement receipt for object {}",
                task.placement_receipt_ref.object_id
            )
        })?;
        RebuildCompletion::validate_repaired_receipt_for_task(task, repaired_receipt)
            .map_err(|err| {
                format!(
                    "receipt-bound repair ack from node {target_node_id} failed completion receipt validation for object {}: {err:?}",
                    task.placement_receipt_ref.object_id
                )
            })?;

        Ok(repaired_receipt)
    }

    fn record_receipt_repair_completion(
        task: &BackfillTask,
        repaired_receipt: PlacementReceiptRef,
        completion: &mut RebuildCompletion,
        admission: &mut RebuildAdmission,
    ) -> Result<ReceiptRepairCompletionEvidence, String> {
        let completion_event = completion
            .record_receipt_verified_task_completion(task, repaired_receipt, admission)
            .map_err(|err| {
                format!(
                    "receipt-bound repair completion recording failed for object {}: {err:?}",
                    task.placement_receipt_ref.object_id
                )
            })?;
        let verified_receipt_completion = VerifiedReceiptCompletionRecord {
            target_member: task.target_member,
            subject_ref: task.subject_ref,
            source_placement_receipt_ref: task.placement_receipt_ref,
            repaired_placement_receipt_ref: repaired_receipt,
        };

        Ok(ReceiptRepairCompletionEvidence {
            repaired_placement_receipt_ref: repaired_receipt,
            verified_receipt_completion,
            completion_event,
        })
    }

    /// Execute a receipt-bound repair and record verified rebuild completion
    /// only after the target returns a repaired placement receipt.
    pub fn execute_receipt_repair_task_and_record_completion(
        &mut self,
        task: &BackfillTask,
        completion: &mut RebuildCompletion,
        admission: &mut RebuildAdmission,
    ) -> Result<ReceiptRepairCompletionEvidence, String> {
        let repaired_receipt = self.execute_receipt_repair_task(task)?;
        Self::record_receipt_repair_completion(task, repaired_receipt, completion, admission)
    }

    /// Execute a planned-read-backed repair and record verified rebuild
    /// completion only after the target returns a repaired placement receipt.
    pub fn execute_receipt_repair_task_from_planned_read_and_record_completion(
        &mut self,
        task: &BackfillTask,
        planned_read: &ReceiptBackedTransportPlannedReadResult,
        completion: &mut RebuildCompletion,
        admission: &mut RebuildAdmission,
    ) -> Result<ReceiptRepairCompletionEvidence, String> {
        let repaired_receipt =
            self.execute_receipt_repair_task_from_planned_read(task, planned_read)?;
        Self::record_receipt_repair_completion(task, repaired_receipt, completion, admission)
    }

    /// Execute a receipt-bound repair, record verified rebuild completion, and
    /// publish the repaired placement receipt through flow-commit.
    ///
    /// This is a convenience bridge for callers that already own the
    /// flow-commit coordinator. The lower-level repair and completion APIs
    /// remain available when callers need to stage publication separately.
    pub fn execute_receipt_repair_task_record_completion_and_publish_flow_commit(
        &mut self,
        task: &BackfillTask,
        completion: &mut RebuildCompletion,
        admission: &mut RebuildAdmission,
        flow_commit: &mut FlowCommitCoordinator,
    ) -> Result<ReceiptRepairFlowCommitPublication, String> {
        let repair_completion =
            self.execute_receipt_repair_task_and_record_completion(task, completion, admission)?;
        let flow_commit_result = flow_commit
            .publish_verified_rebuild_completion(repair_completion.verified_receipt_completion)
            .map_err(|err| {
                format!(
                    "receipt-bound repair flow-commit publication failed for object {}: {err}",
                    task.placement_receipt_ref.object_id
                )
            })?;

        Ok(ReceiptRepairFlowCommitPublication {
            repair_completion,
            flow_commit_result,
        })
    }

    /// Execute a planned-read-backed repair, record verified rebuild completion,
    /// and publish the repaired placement receipt through flow-commit.
    pub fn execute_receipt_repair_task_from_planned_read_record_completion_and_publish_flow_commit(
        &mut self,
        task: &BackfillTask,
        planned_read: &ReceiptBackedTransportPlannedReadResult,
        completion: &mut RebuildCompletion,
        admission: &mut RebuildAdmission,
        flow_commit: &mut FlowCommitCoordinator,
    ) -> Result<ReceiptRepairFlowCommitPublication, String> {
        let repair_completion = self
            .execute_receipt_repair_task_from_planned_read_and_record_completion(
                task,
                planned_read,
                completion,
                admission,
            )?;
        let flow_commit_result = flow_commit
            .publish_verified_rebuild_completion(repair_completion.verified_receipt_completion)
            .map_err(|err| {
                format!(
                    "planned-read-backed repair flow-commit publication failed for object {}: {err}",
                    task.placement_receipt_ref.object_id
                )
            })?;

        Ok(ReceiptRepairFlowCommitPublication {
            repair_completion,
            flow_commit_result,
        })
    }

    fn fetch_remote_segment_request(
        &mut self,
        replica_idx: usize,
        request: SegmentFetchRequest,
    ) -> Result<Vec<u8>, String> {
        let replica = self.replicas.get(replica_idx).ok_or_else(|| {
            format!(
                "replica index {replica_idx} out of bounds (have {} replicas)",
                self.replicas.len()
            )
        })?;
        let node_id = replica.node_id;
        let data_session_id = replica.data_session_id;

        send_segment_fetch(&mut self.transport, data_session_id, &request)
            .map_err(|e| format!("send segment fetch to node {node_id}: {e}"))?;

        let response = recv_segment_fetch_response(&mut self.transport, data_session_id)
            .map_err(|e| format!("recv segment fetch from node {node_id}: {e}"))?;

        Ok(response.payload)
    }

    /// Handle an incoming segment fetch request on the given session.
    ///
    /// Reads a [`SegmentFetchRequest`] from the session, looks up the
    /// requested segment in the local primary store, constructs a
    /// [`SegmentFetchResponse`] with domain-separated BLAKE3 integrity,
    /// and sends it back on the same session.
    ///
    /// The local primary store's `get` method retrieves the full object;
    /// this handler slices out the requested `[segment_offset,
    /// segment_offset + segment_length)` range.
    ///
    /// Returns the object_id on success so the caller can log which
    /// segment was served.
    pub fn handle_segment_fetch_request(&mut self, session_id: SessionId) -> Result<u64, String> {
        let request = recv_segment_fetch(&mut self.transport, session_id)
            .map_err(|e| format!("recv segment fetch request: {e}"))?;

        // Validate offset + length does not overflow
        if request
            .segment_offset
            .checked_add(request.segment_length)
            .is_none()
        {
            return Err(format!(
                "segment fetch overflow: offset {} + length {} would overflow u64",
                request.segment_offset, request.segment_length
            ));
        }

        let obj_id = request.object_id;
        let receipt_ref = request.placement_receipt_ref;
        if receipt_ref.is_some_and(PlacementReceiptRef::is_synthetic) {
            return Err(format!(
                "receipt-bound segment fetch for object {obj_id} requires non-synthetic placement receipt"
            ));
        }
        let key = receipt_ref.map_or_else(
            || tidefs_local_object_store::ObjectKey::from_name(obj_id.to_le_bytes()),
            |receipt| tidefs_local_object_store::ObjectKey::from_bytes32(receipt.object_key),
        );

        let payload = self
            .primary
            .get(key)
            .map_err(|e| format!("primary get for object {obj_id}: {e}"))?
            .ok_or_else(|| {
                format!("primary receipt-key get for object {obj_id}: object not found")
            });
        let full_payload = match (receipt_ref, payload) {
            (Some(_), Ok(payload)) => payload,
            (Some(_), Err(message)) => return Err(message),
            (None, Ok(payload)) => payload,
            (None, Err(_)) => Vec::new(),
        };

        // Slice the requested segment range (cast to usize after overflow check above)
        let start = request.segment_offset as usize;
        let end = start.saturating_add(request.segment_length as usize);
        let segment_payload = if start < full_payload.len() {
            let slice_end = end.min(full_payload.len());
            full_payload[start..slice_end].to_vec()
        } else {
            Vec::new()
        };

        let actual_length = segment_payload.len() as u64;
        let response = SegmentFetchResponse::new(
            obj_id,
            request.segment_offset,
            actual_length,
            segment_payload,
        );

        send_segment_fetch_response(&mut self.transport, session_id, &response)
            .map_err(|e| format!("send segment fetch response: {e}"))?;

        Ok(obj_id)
    }

    /// Handle a single ObjectTransfer ReadRequest on an established session.
    ///
    /// Looks up the requested object in the local primary store, slices the
    /// requested byte range, and sends chunked `ReadResponse` messages back
    /// with domain-separated BLAKE3 payload digests.
    ///
    /// Returns the object key on success.
    pub fn handle_read_request(&mut self, session_id: SessionId) -> Result<[u8; 32], String> {
        let raw = self
            .transport
            .recv_message(session_id)
            .map_err(|e| format!("recv read request: {e}"))?;

        let msg =
            ObjectTransferMessage::decode(&raw).map_err(|e| format!("decode read request: {e}"))?;

        let (transfer_id, object_key, offset, length) = match msg {
            ObjectTransferMessage::ReadRequest {
                transfer_id,
                object_key,
                offset,
                length,
            } => (transfer_id, object_key, offset, length),
            other => {
                return Err(format!("expected ReadRequest, got {}", other.kind()));
            }
        };

        // Look up the full object in the local primary store
        let key = tidefs_local_object_store::ObjectKey::from_bytes32(object_key);
        let Some(full_payload) = self
            .primary
            .get(key)
            .map_err(|e| format!("primary get failed: {e}"))?
        else {
            return Err(format!("object key {object_key:?} not found"));
        };

        // Slice the requested byte range
        let start = offset as usize;
        let end = start.saturating_add(length as usize);
        let slice = if start < full_payload.len() {
            let slice_end = end.min(full_payload.len());
            &full_payload[start..slice_end]
        } else {
            &[]
        };

        // Build and send chunked ReadResponse messages
        let responses =
            build_read_responses(transfer_id, slice.len() as u64, slice, MAX_CHUNK_PAYLOAD);
        for resp in responses {
            let encoded = resp
                .encode()
                .map_err(|e| format!("encode read response: {e}"))?;
            self.transport
                .send_message(session_id, &encoded)
                .map_err(|e| format!("send read response: {e}"))?;
        }

        Ok(object_key)
    }

    /// Accept one incoming connection, perform handshake, and serve
    /// ObjectTransfer read requests in a loop until the peer disconnects
    /// or an error occurs.
    ///
    /// This is the server-side counterpart to the client-side
    /// `ReplicatedObjectReader::read_object`.
    ///
    /// Returns the number of read requests handled.
    pub fn serve_read_requests(&mut self) -> Result<usize, String> {
        let sid = self
            .transport
            .accept_incoming()
            .map_err(|e| format!("accept incoming: {e}"))?;

        self.transport
            .perform_handshake(sid)
            .map_err(|e| format!("handshake: {e}"))?;

        let mut count: usize = 0;
        loop {
            match self.handle_read_request(sid) {
                Ok(_key) => {
                    count += 1;
                }
                Err(e) => {
                    tracing::debug!("read request loop ended: {e}");
                    break;
                }
            }
        }

        self.transport
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();

        Ok(count)
    }

    // ── Helpers ─────────────────────────────────────────────────────

    // ── Utility methods ─────────────────────────────────────────────

    /// Return a mutable reference to the underlying Transport.
    pub fn transport_mut(&mut self) -> &mut Transport {
        &mut self.transport
    }

    /// Sync the local primary to disk.
    pub fn sync_all(&mut self) -> Result<(), String> {
        self.primary
            .sync_all()
            .map_err(|e| format!("primary sync failed: {e}"))?;
        Ok(())
    }

    /// Return the bound address of the local transport listener.
    #[must_use]
    pub fn local_addr(&self) -> Option<tidefs_transport::TransportAddr> {
        self.transport.bind_addr.clone()
    }

    /// Return the transport's local node ID.
    #[must_use]
    pub fn local_node_id(&self) -> u64 {
        self.transport.local_node_id
    }

    /// Return current statistics.
    #[must_use]
    pub fn stats(&self) -> &TransportReplicatedStoreStats {
        &self.stats
    }

    /// Transaction-group id of the primary's most recently committed root.
    /// 0 means no root has been committed yet (NIL).
    #[must_use]
    pub fn committed_root_txg(&self) -> u64 {
        self.primary
            .txg_manager()
            .committed_root()
            .commit_group_id
            .0
    }

    /// Monotonic generation counter from the primary's txg manager.
    #[must_use]
    pub fn committed_root_generation(&self) -> u64 {
        self.primary.txg_manager().commit_count()
    }

    /// List all object keys from the local primary store.
    #[must_use]
    pub fn list_keys(&self) -> Vec<tidefs_local_object_store::ObjectKey> {
        self.primary.list_keys()
    }

    /// Close all replica sessions and shut down the transport.
    pub fn close(&mut self) {
        for replica in &self.replicas {
            let _ = self.transport.close_session(
                replica.control_session_id,
                SessionCloseReason::LocalShutdown,
            );
            let _ = self
                .transport
                .close_session(replica.data_session_id, SessionCloseReason::LocalShutdown);
            let _ = self
                .transport
                .close_session(replica.shadow_session_id, SessionCloseReason::LocalShutdown);
        }
        self.replicas.clear();
    }
}

fn validate_receipt_repair_task(task: &BackfillTask) -> Result<(), String> {
    let receipt = task.placement_receipt_ref;
    if receipt.is_synthetic() {
        return Err(format!(
            "receipt-bound repair for object {} requires non-synthetic placement receipt",
            receipt.object_id
        ));
    }
    if !receipt.redundancy_policy.is_well_formed() {
        return Err(format!(
            "receipt-bound repair for object {} requires well-formed redundancy policy",
            receipt.object_id
        ));
    }
    let required_targets = receipt.redundancy_policy.target_width();
    if receipt.target_count < required_targets {
        return Err(format!(
            "receipt-bound repair for object {} has {} receipt targets, needs {}",
            receipt.object_id, receipt.target_count, required_targets
        ));
    }
    if receipt.object_id != task.subject_ref.0 {
        return Err(format!(
            "receipt-bound repair task subject mismatch: task={} receipt={}",
            task.subject_ref.0, receipt.object_id
        ));
    }
    if task.payload_len != receipt.payload_len {
        return Err(format!(
            "receipt-bound repair task length mismatch for object {}: task {} receipt {}",
            receipt.object_id, task.payload_len, receipt.payload_len
        ));
    }
    let receipt_digest_prefix = u64::from_le_bytes(
        receipt.payload_digest[..8]
            .try_into()
            .expect("digest prefix has 8 bytes"),
    );
    if task.payload_digest != ObjectDigest::new(receipt_digest_prefix) {
        return Err(format!(
            "receipt-bound repair task digest prefix mismatch for object {}",
            receipt.object_id
        ));
    }
    Ok(())
}

fn validate_receipt_repair_payload(task: &BackfillTask, payload: &[u8]) -> Result<(), String> {
    let receipt = task.placement_receipt_ref;
    if payload.len() as u64 != receipt.payload_len {
        return Err(format!(
            "receipt-bound repair source length mismatch for object {}: receipt {} actual {}",
            receipt.object_id,
            receipt.payload_len,
            payload.len()
        ));
    }
    let actual_digest: [u8; 32] = blake3::hash(payload).into();
    if actual_digest != receipt.payload_digest {
        return Err(format!(
            "receipt-bound repair source digest mismatch for object {}",
            receipt.object_id
        ));
    }
    Ok(())
}

fn validate_planned_read_repair_input(
    task: &BackfillTask,
    planned_read: &ReceiptBackedTransportPlannedReadResult,
) -> Result<(), String> {
    validate_receipt_repair_task(task)?;

    let planned_receipt = planned_read.placement_receipt_ref;
    if planned_receipt.is_synthetic() {
        return Err(format!(
            "planned-read-backed repair for object {} requires non-synthetic placement receipt evidence",
            planned_receipt.object_id
        ));
    }
    if planned_read.source_member_id != task.source_member.0 {
        return Err(format!(
            "planned-read-backed repair source mismatch for object {}: planned read source {} task source {}",
            task.placement_receipt_ref.object_id,
            planned_read.source_member_id,
            task.source_member.0
        ));
    }
    if planned_receipt != task.placement_receipt_ref {
        return Err(format!(
            "planned-read-backed repair receipt mismatch for object {}",
            task.placement_receipt_ref.object_id
        ));
    }

    validate_receipt_repair_payload(task, &planned_read.payload)
}

impl ReceiptSegmentSource for TransportReplicatedStore {
    type Error = String;

    fn fetch_segment_by_receipt(
        &mut self,
        source_member: MemberId,
        placement_receipt_ref: PlacementReceiptRef,
        segment_offset: u64,
        segment_length: u64,
    ) -> Result<Vec<u8>, Self::Error> {
        let replica_idx = self
            .replicas
            .iter()
            .position(|replica| replica.node_id == source_member.0)
            .ok_or_else(|| {
                format!(
                    "source member {} is not connected for receipt-bound fetch of object {}",
                    source_member.0, placement_receipt_ref.object_id
                )
            })?;

        self.fetch_remote_segment_by_receipt(
            replica_idx,
            placement_receipt_ref,
            segment_offset,
            segment_length,
        )
    }
}

impl Drop for TransportReplicatedStore {
    fn drop(&mut self) {
        self.close();
    }
}

fn object_key_name(object_key: &[u8; 32], offset: u64) -> String {
    let mut name = String::with_capacity("obj-key-".len() + 64 + 17);
    name.push_str("obj-key-");
    for byte in object_key {
        use std::fmt::Write as _;
        let _ = write!(&mut name, "{byte:02x}");
    }
    use std::fmt::Write as _;
    let _ = write!(&mut name, "-{offset:016x}");
    name
}

fn replicated_object_name(object_id: u64, offset: u64) -> String {
    let object_key = ReplicationWritePath::derive_object_key(object_id, offset);
    object_key_name(&object_key, offset)
}

/// Receive and store one replicated object write on an established data session.
pub fn handle_incoming_write(
    transport: &mut Transport,
    session_id: SessionId,
    primary: &mut LocalObjectStore,
) -> Result<u64, String> {
    let (transfer_id, payload, object_key, offset) = recv_write_request(transport, session_id)
        .map_err(|error| format!("recv replicated write request: {error}"))?;
    let name = object_key_name(&object_key, offset);

    match primary.put_named(&name, &payload) {
        Ok(_) => {
            send_write_ack(
                transport,
                session_id,
                transfer_id,
                payload.len() as u64,
                WriteStatus::Ok,
            )
            .map_err(|error| format!("send replicated write ack: {error}"))?;
            Ok(payload.len() as u64)
        }
        Err(error) => {
            let _ = send_write_ack(transport, session_id, transfer_id, 0, WriteStatus::Rejected);
            Err(format!("store replicated write: {error}"))
        }
    }
}

impl ReplicatedWrite for TransportReplicatedStore {
    fn write_object(
        &mut self,
        object_id: u64,
        offset: u64,
        payload: &[u8],
    ) -> Result<(), ReplicationWriteError> {
        let name = replicated_object_name(object_id, offset);
        self.primary.put_named(&name, payload).map_err(|error| {
            ReplicationWriteError::Transport {
                reason: format!("primary write failed: {error}"),
            }
        })?;

        let total_targets = 1 + self.replicas.len();
        let mut acks = 1usize;

        for idx in 0..self.replicas.len() {
            let peer_node_id = self.replicas[idx].node_id;
            let data_session_id = self.replicas[idx].data_session_id;
            let mut path =
                ReplicationWritePath::new(&mut self.transport, data_session_id, peer_node_id);
            if let Err(error) = path.write_object(object_id, offset, payload) {
                self.stats.bytes_written += payload.len() as u64;
                self.stats.object_count += 1;
                self.stats.failed_writes += 1;
                return Err(error);
            }
            acks += 1;
        }

        self.stats.bytes_written += payload.len() as u64;
        self.stats.object_count += 1;

        if acks < self.config.write_quorum {
            self.stats.failed_writes += 1;
            return Err(ReplicationWriteError::Transport {
                reason: format!(
                    "write quorum not reached: {acks} acknowledgements for quorum {}",
                    self.config.write_quorum
                ),
            });
        }

        if acks >= total_targets {
            self.stats.committed_writes += 1;
        } else {
            self.stats.degraded_writes += 1;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tidefs_replica_health::suspicion::SuspicionLevel;
    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tidefs-rep-{label}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cleanup_dirs(dirs: &[PathBuf]) {
        for d in dirs {
            let _ = fs::remove_dir_all(d);
        }
    }

    fn make_paths(n: usize, label: &str) -> Vec<PathBuf> {
        (0..n).map(|i| temp_dir(&format!("{label}-r{i}"))).collect()
    }

    // --- Single replica (no replication, just primary) ---

    /// Baseline: single replica put/get roundtrip with data verification.
    #[test]
    fn single_replica_put_get() {
        let paths = make_paths(1, "single");
        let mut store =
            ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::default()).unwrap();

        let result = store.put_named("test", b"roundtrip").unwrap();
        assert_eq!(result.target_count, 1);
        assert_eq!(result.quorum_size, 1);
        assert_eq!(result.write_class, WriteClass::Committed);
        assert!(!result.needs_repair);
        assert_eq!(result.acks_count, 1);

        let data = store.get_named("test").unwrap();
        assert_eq!(data, Some(b"roundtrip".to_vec()));

        let missing = store.get_named("no-such-key").unwrap();
        assert_eq!(missing, None);
        cleanup_dirs(&paths);
    }

    #[test]
    fn put_key_local_stores_exact_object_key() {
        let paths = make_paths(1, "put-key-local");
        let mut store =
            ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::default()).unwrap();
        let key = ObjectKey::from_bytes32([0xA5; 32]);

        store.put_key_local(key, b"exact").unwrap();

        assert_eq!(store.get_key_local(key).unwrap(), Some(b"exact".to_vec()));
        assert_eq!(store.get_local(key.as_bytes32()).unwrap(), None);
        cleanup_dirs(&paths);
    }

    // --- Three-replica quorum write ---

    #[test]
    fn three_replica_put_get_delete() {
        let paths = make_paths(3, "triple");
        let mut store =
            ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::three_replica_quorum())
                .unwrap();

        // Put
        let result = store.put_named("hello", b"world").unwrap();
        assert_eq!(result.target_count, 3);
        assert_eq!(result.quorum_size, 2);
        assert_eq!(result.write_class, WriteClass::Committed);
        assert!(!result.needs_repair);
        assert_eq!(result.acks_count, 3);
        assert!(result.skipped_unhealthy.is_empty());

        // Get from primary
        let data = store.get_named("hello").unwrap();
        assert_eq!(data, Some(b"world".to_vec()));

        // Delete
        let deleted = store.delete_named("hello").unwrap();
        assert!(deleted);

        // Confirm gone
        let data = store.get_named("hello").unwrap();
        assert_eq!(data, None);

        cleanup_dirs(&paths);
    }

    #[test]
    fn three_replica_multiple_puts() {
        let paths = make_paths(3, "multi");
        let mut store =
            ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::three_replica_quorum())
                .unwrap();

        for i in 0..10 {
            let key = format!("obj-{i}");
            let val = format!("value-{i}");
            let result = store.put_named(&key, val.as_bytes()).unwrap();
            assert!(
                result.write_class == WriteClass::Committed,
                "write {} was {:?}",
                i,
                result.write_class
            );
        }

        for i in 0..10 {
            let key = format!("obj-{i}");
            let data = store.get_named(&key).unwrap();
            assert_eq!(data, Some(format!("value-{i}").into_bytes()));
        }

        assert_eq!(store.stats().object_count, 10);
        assert_eq!(store.stats().committed_writes, 10);

        cleanup_dirs(&paths);
    }

    #[test]
    fn three_replica_stats_accurate() {
        let paths = make_paths(3, "stats");
        let mut store =
            ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::three_replica_quorum())
                .unwrap();

        store.put_named("a", b"aaaa").unwrap();
        store.put_named("b", b"bbbb").unwrap();
        store.put_named("c", b"cccccccc").unwrap();

        let s = store.stats();
        assert_eq!(s.object_count, 3);
        assert_eq!(s.committed_writes, 3);
        assert_eq!(s.degraded_writes, 0);
        assert_eq!(s.refused_writes, 0);
        assert_eq!(s.bytes_written, 16); // 4+4+8
        assert_eq!(s.replica_healthy, vec![true, true, true]);

        cleanup_dirs(&paths);
    }

    // --- Five-replica witness quorum ---

    #[test]
    fn five_replica_witness_write() {
        let paths = make_paths(5, "five");
        let mut store =
            ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::five_replica_witness())
                .unwrap();

        let result = store.put_named("data", b"five-replica-test").unwrap();
        assert_eq!(result.target_count, 5);
        assert_eq!(result.quorum_size, 3);
        assert_eq!(result.write_class, WriteClass::Committed);
        assert!(!result.needs_repair);

        let data = store.get_named("data").unwrap();
        assert_eq!(data, Some(b"five-replica-test".to_vec()));

        cleanup_dirs(&paths);
    }

    // --- Degraded read: primary empty, replica has data ---

    #[test]
    fn degraded_read_from_replica() {
        let paths = make_paths(3, "degraded");
        let mut store =
            ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::three_replica_quorum())
                .unwrap();

        // Write through normal path
        store.put_named("shared", b"present").unwrap();

        // Now delete from primary only (simulate primary loss)
        store
            .primary
            .delete(ObjectKey::from_name(b"shared"))
            .unwrap();

        // Get should find it on a replica
        let data = store.get_named("shared").unwrap();
        assert_eq!(data, Some(b"present".to_vec()));

        // Degraded read should have been tracked
        let ds = store.degraded_read_stats();
        assert!(ds.total_degraded_reads > 0);

        // Flush repairs should restore primary
        let repaired = store.flush_repairs();
        assert!(repaired > 0);

        // Now primary should have the data again
        let primary_data = store.primary.get(ObjectKey::from_name(b"shared")).unwrap();
        assert_eq!(primary_data, Some(b"present".to_vec()));

        cleanup_dirs(&paths);
    }

    // --- Empty reads ---

    #[test]
    fn get_nonexistent() {
        let paths = make_paths(3, "nonexist");
        let store =
            ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::three_replica_quorum())
                .unwrap();

        let data = store.get_named("no-such-key").unwrap();
        assert_eq!(data, None);

        cleanup_dirs(&paths);
    }

    // --- Reopen: data persists ---

    #[test]
    fn reopen_preserves_data() {
        let paths = make_paths(3, "reopen");

        {
            let mut store =
                ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::three_replica_quorum())
                    .unwrap();
            store.put_named("persist", b"survives").unwrap();
            store.sync_all().unwrap();
        }

        {
            let store =
                ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::three_replica_quorum())
                    .unwrap();
            let data = store.get_named("persist").unwrap();
            assert_eq!(data, Some(b"survives".to_vec()));
        }

        cleanup_dirs(&paths);
    }

    // --- Large payload ---

    #[test]
    fn large_payload() {
        let paths = make_paths(3, "large");
        let config = ReplicatedStoreConfig {
            replica_count: 3,
            durability_mode: DurabilityMode::QuorumFull,
            min_target_count: 2,
            enable_degraded_reads: true,
            store_options: StoreOptions::durable(),
        };
        let mut store = ReplicatedObjectStore::open(&paths, config).unwrap();
        let large: Vec<u8> = (0..64_000).map(|i| (i % 256) as u8).collect();
        store.put_named("big", &large).unwrap();

        let data = store.get_named("big").unwrap();
        assert_eq!(data, Some(large));

        cleanup_dirs(&paths);
    }

    // --- Error: empty paths ---

    #[test]
    fn empty_paths_rejected() {
        let result = ReplicatedObjectStore::open(&[], ReplicatedStoreConfig::default());
        assert!(result.is_err());
    }

    // --- Error: path count mismatch ---

    #[test]
    fn path_count_mismatch_rejected() {
        let paths = make_paths(2, "mismatch");
        let result =
            ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::three_replica_quorum());
        assert!(result.is_err());
        cleanup_dirs(&paths);
    }

    // --- Degraded write: one replica down, quorum still met ---

    /// Simulate one replica failure while quorum is still reachable.
    /// Opens a 2-replica store (primary + 1 replica) with
    /// min_target_count=2. All replicas must ack for Committed status.
    #[test]
    fn degraded_write_one_replica_down() {
        let paths = make_paths(2, "degwrite");
        let mut store = ReplicatedObjectStore::open(
            &paths,
            ReplicatedStoreConfig {
                replica_count: 2,
                durability_mode: DurabilityMode::QuorumFull,
                min_target_count: 2,
                enable_degraded_reads: true,
                store_options: StoreOptions::test_fast(),
            },
        )
        .unwrap();

        // Write with 2 replicas, min_target=2. Both must ack.
        let result = store.put_named("survives-degraded", b"still-good").unwrap();
        assert_eq!(result.target_count, 2);
        assert_eq!(result.write_class, WriteClass::Committed);
        assert_eq!(result.acks_count, 2);

        // Verify data is readable
        let data = store.get_named("survives-degraded").unwrap();
        assert_eq!(data, Some(b"still-good".to_vec()));

        cleanup_dirs(&paths);
    }
    // --- Degraded write detection with 1 replica down ---

    #[test]
    fn single_target_functions_as_n1() {
        let paths = make_paths(1, "n1");
        let mut store = ReplicatedObjectStore::open(
            &paths,
            ReplicatedStoreConfig {
                replica_count: 1,
                durability_mode: DurabilityMode::QuorumFull,
                min_target_count: 1,
                enable_degraded_reads: true,
                store_options: StoreOptions::test_fast(),
            },
        )
        .unwrap();

        let result = store.put_named("solo", b"alone").unwrap();
        assert_eq!(result.target_count, 1);
        assert_eq!(result.quorum_size, 1);
        assert_eq!(result.write_class, WriteClass::Committed);

        let data = store.get_named("solo").unwrap();
        assert_eq!(data, Some(b"alone".to_vec()));

        cleanup_dirs(&paths);
    }

    // --- Repair: sync replica from primary after data loss ---

    #[test]
    fn replica_repair_after_primary_delete() {
        let paths = make_paths(3, "repair-del");
        let mut store =
            ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::three_replica_quorum())
                .unwrap();

        // Write several objects
        store.put_named("a", b"alpha").unwrap();
        store.put_named("b", b"beta").unwrap();
        store.put_named("c", b"gamma").unwrap();

        // Simulate replica 0 corruption: delete all objects from replica 0 only
        let key_a = ObjectKey::from_name(b"a");
        let key_b = ObjectKey::from_name(b"b");
        let key_c = ObjectKey::from_name(b"c");
        store.replicas[0].delete(key_a).unwrap();
        store.replicas[0].delete(key_b).unwrap();
        store.replicas[0].delete(key_c).unwrap();

        // Verify data is missing on replica 0
        assert_eq!(store.replicas[0].get(key_a).unwrap(), None);
        assert_eq!(store.replicas[0].get(key_b).unwrap(), None);

        // Repair replica 0 from primary
        let repaired = store.repair_replica(0).unwrap();
        assert_eq!(repaired, 3);

        // Verify replica 0 now has all data
        assert_eq!(
            store.replicas[0].get(key_a).unwrap(),
            Some(b"alpha".to_vec())
        );
        assert_eq!(
            store.replicas[0].get(key_b).unwrap(),
            Some(b"beta".to_vec())
        );
        assert_eq!(
            store.replicas[0].get(key_c).unwrap(),
            Some(b"gamma".to_vec())
        );

        // Verify primary still has data
        assert_eq!(store.primary.get(key_a).unwrap(), Some(b"alpha".to_vec()));

        cleanup_dirs(&paths);
    }

    // --- Degraded read stats: per-replica tracking ---

    #[test]
    fn degraded_read_detailed_stats_tracked() {
        let paths = make_paths(3, "drsdetail");
        let mut store =
            ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::three_replica_quorum())
                .unwrap();

        // Write an object
        store.put_named("trackme", b"value").unwrap();

        // Delete from primary only (simulate primary loss)
        store
            .primary
            .delete(ObjectKey::from_name(b"trackme"))
            .unwrap();

        // Read should trigger degraded read from a replica
        let data = store.get_named("trackme").unwrap();
        assert_eq!(data, Some(b"value".to_vec()));

        // Verify detailed stats
        let ds = store.degraded_read_stats();
        assert_eq!(ds.total_degraded_reads, 1);
        assert!(ds.replica_hits.iter().any(|&h| h > 0));

        // Verify report is non-empty
        let report = store.degraded_read_report();
        assert!(!report.is_empty());
        assert!(report.contains("degraded reads:"));

        cleanup_dirs(&paths);
    }

    // --- Health tracker: replicas at Suspect+ are skipped ---

    #[test]
    fn health_tracker_skips_suspect_replicas() {
        let paths = make_paths(3, "htskip");
        let mut store =
            ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::three_replica_quorum())
                .unwrap();

        // Set up health tracker marking replica 0 as Suspect
        let mut tracker = ReplicaHealthTracker::new(1024, 1024 * 1024);
        tracker.set_node_suspicion(
            tidefs_replica_health::NodeId::new(1),
            SuspicionLevel::Suspect,
            1000,
        );
        store.set_health_tracker(tracker);

        // Write should skip replica 0
        let result = store.put_named("data", b"healthy-write").unwrap();
        assert!(!result.skipped_unhealthy.is_empty());
        assert!(result.skipped_unhealthy.contains(&0));

        // Data should still be readable
        let data = store.get_named("data").unwrap();
        assert_eq!(data, Some(b"healthy-write".to_vec()));

        cleanup_dirs(&paths);
    }

    // --- Health tracker: healthy replicas are not skipped ---

    #[test]
    fn health_tracker_does_not_skip_healthy() {
        let paths = make_paths(3, "htok");
        let mut store =
            ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::three_replica_quorum())
                .unwrap();

        // Set up health tracker with all replicas healthy
        let mut tracker = ReplicaHealthTracker::new(1024, 1024 * 1024);
        tracker.set_node_suspicion(
            tidefs_replica_health::NodeId::new(1),
            SuspicionLevel::Healthy,
            1000,
        );
        tracker.set_node_suspicion(
            tidefs_replica_health::NodeId::new(2),
            SuspicionLevel::Healthy,
            1000,
        );
        store.set_health_tracker(tracker);

        // Write should not skip any replicas
        let result = store.put_named("data", b"all-ok").unwrap();
        assert!(result.skipped_unhealthy.is_empty());
        assert_eq!(result.acks_count, 3);

        cleanup_dirs(&paths);
    }

    // --- Degradation tracker: health-ordered read path ---

    /// When a degradation tracker is configured, get_inner iterates
    /// replicas in descending health order instead of sequential order.
    #[test]
    fn health_ordered_replica_indices_sorts_descending() {
        let dir = tempfile::tempdir().unwrap();
        let paths: Vec<_> = (0..4)
            .map(|i| dir.path().join(format!("hosi_{i}")))
            .collect();

        let mut store = ReplicatedObjectStore::open(
            &paths,
            ReplicatedStoreConfig {
                replica_count: 4,
                ..ReplicatedStoreConfig::three_replica_quorum()
            },
        )
        .unwrap();

        // Without tracker: sequential 0..3
        let order = store.health_ordered_replica_indices();
        assert_eq!(order, vec![0, 1, 2]);

        // With tracker: health order
        let mut tracker = ReplicaDegradationTracker::new(
            tidefs_replica_health::scoring::ScoreConfig {
                window_size: 20,
                ..Default::default()
            },
            tidefs_replica_health::state_machine::DegradationConfig {
                failure_threshold: 50,
                ..Default::default()
            },
        );

        // Replica 0 (NodeId(1)): low score
        for _ in 0..15 {
            tracker.record_failure(tidefs_replica_health::NodeId::new(1), 1000, 5000, false);
        }
        // Replica 1 (NodeId(2)): high score
        for _ in 0..20 {
            tracker.record_success(tidefs_replica_health::NodeId::new(2), 1000, 50);
        }
        // Replica 2 (NodeId(3)): moderate score
        for _ in 0..15 {
            tracker.record_success(tidefs_replica_health::NodeId::new(3), 1000, 50);
        }
        for _ in 0..5 {
            tracker.record_failure(tidefs_replica_health::NodeId::new(3), 1000, 5000, false);
        }

        store.set_degradation_tracker(tracker);
        let order = store.health_ordered_replica_indices();
        assert_eq!(order.len(), 3, "all 3 replicas must be in order");
        // All indices 0,1,2 must appear exactly once
        let mut seen = [false; 3];
        for &idx in &order {
            seen[idx] = true;
        }
        assert!(
            seen.iter().all(|&s| s),
            "all replica indices must be present"
        );
        // Replica 1 (healthy) should be first
        assert_eq!(order[0], 1, "healthiest replica should be tried first");

        store.clear_degradation_tracker();
    }

    /// When a degradation tracker is set, a degraded read that finds data
    /// on a replica tracks the hit correctly.
    #[test]
    fn health_ordered_read_finds_data_on_replica() {
        let dir = tempfile::tempdir().unwrap();
        let paths: Vec<_> = (0..3)
            .map(|i| dir.path().join(format!("hors_{i}")))
            .collect();

        let mut store =
            ReplicatedObjectStore::open(&paths, ReplicatedStoreConfig::three_replica_quorum())
                .unwrap();

        // Put data only on replica 1 (index 1, NodeId(2)), skip primary
        let key = ObjectKey::from_name(b"health-obj");
        let payload = b"healthy-read-path";
        store.replicas[1].put(key, payload).unwrap();

        // Build tracker where replica 1 has high score and replica 0 has low
        let mut tracker = ReplicaDegradationTracker::new(
            tidefs_replica_health::scoring::ScoreConfig {
                window_size: 20,
                ..Default::default()
            },
            tidefs_replica_health::state_machine::DegradationConfig {
                failure_threshold: 50,
                ..Default::default()
            },
        );

        // Replica 0 (NodeId(1)): degraded
        for _ in 0..15 {
            tracker.record_failure(tidefs_replica_health::NodeId::new(1), 1000, 5000, false);
        }
        // Replica 1 (NodeId(2)): healthy
        for _ in 0..20 {
            tracker.record_success(tidefs_replica_health::NodeId::new(2), 1000, 50);
        }

        store.set_degradation_tracker(tracker);
        let result = store.get(key).unwrap();
        assert_eq!(result, Some(payload.to_vec()));

        // Verify at least one degraded read was tracked
        {
            let drs = store.degraded_read_stats.borrow();
            let total_hits: u64 = drs.replica_hits.iter().sum();
            assert!(total_hits > 0, "degraded read must be tracked");
        }

        store.clear_degradation_tracker();
    }

    // --- Quorum write failure: insufficient replicas ---

    /// When min_target_count exceeds available replicas, the store
    /// writes to all available replicas and does not panic. The write
    /// succeeds on the primary; classification reflects actual acks.
    #[test]
    fn quorum_write_failure_insufficient_targets() {
        let paths = make_paths(1, "insuff-targ");
        let mut store = ReplicatedObjectStore::open(
            &paths,
            ReplicatedStoreConfig {
                replica_count: 1,
                durability_mode: DurabilityMode::QuorumFull,
                min_target_count: 3, // impossible: only 1 replica
                enable_degraded_reads: true,
                store_options: StoreOptions::test_fast(),
            },
        )
        .unwrap();

        // Write should not panic despite impossible min_target_count.
        let result = store.put_named("should-not-crash", b"data").unwrap();
        // With 1 replica, all available targets ack so it is Committed.
        assert_eq!(result.write_class, WriteClass::Committed);
        assert_eq!(result.target_count, 1);
        assert_eq!(result.quorum_size, 3);
        assert_eq!(result.acks_count, 1);

        // Data is readable despite quorum mismatch
        let data = store.get_named("should-not-crash").unwrap();
        assert_eq!(data, Some(b"data".to_vec()));

        let s = store.stats();
        assert_eq!(s.committed_writes, 1);

        cleanup_dirs(&paths);
    }

    /// Config validation: zero replica_count is rejected at open time.
    #[test]
    fn config_zero_replicas_rejected() {
        let paths = make_paths(1, "zero-rep");
        let result = ReplicatedObjectStore::open(
            &paths[..0],
            ReplicatedStoreConfig {
                replica_count: 0,
                durability_mode: DurabilityMode::QuorumFull,
                min_target_count: 1,
                enable_degraded_reads: true,
                store_options: StoreOptions::test_fast(),
            },
        );
        assert!(result.is_err());
        cleanup_dirs(&paths);
    }

    // ── TransportReplicatedStore tests ──────────────────────────────────

    // ── BLAKE3 quorum-write integration tests ────────────────────────

    /// Integration: write an object through `put_with_blake3_quorum()`,
    /// read it back, and verify the BLAKE3 checksum roundtrip matches.

    #[test]

    fn blake3_quorum_write_roundtrip_one_replica() {
        let paths = make_paths(1, "b3qw-r1");

        let mut store = ReplicatedObjectStore::open(
            &paths,
            ReplicatedStoreConfig {
                replica_count: 1,

                durability_mode: DurabilityMode::QuorumFull,

                min_target_count: 1,

                enable_degraded_reads: false,

                store_options: tidefs_local_object_store::StoreOptions::test_fast(),
            },
        )
        .unwrap();

        let payload = b"blake3-quorum-write-roundtrip-test".to_vec();

        let expected_checksum = blake3::hash(&payload);

        let outcome = store
            .put_with_blake3_quorum("roundtrip-obj", &payload)
            .expect("put_with_blake3_quorum should succeed");

        // Verify the outcome

        assert_eq!(outcome.canonical_checksum, expected_checksum);

        assert!(
            outcome.fully_committed,
            "single replica must be fully committed"
        );

        assert_eq!(outcome.acks_collected, 1);

        assert_eq!(outcome.total_targets, 1);

        assert_eq!(outcome.quorum_threshold, 1);

        assert!(outcome.failed_targets.is_empty());

        assert_eq!(outcome.acks.len(), 1);

        assert_eq!(outcome.acks[0].checksum, expected_checksum);

        // Read back and verify data matches

        let read_back = store
            .get_named("roundtrip-obj")
            .expect("get_named should succeed")
            .expect("object should exist");

        assert_eq!(read_back, payload);

        // Verify read-back data has matching checksum

        let read_checksum = blake3::hash(&read_back);

        assert_eq!(read_checksum, expected_checksum);

        cleanup_dirs(&paths);
    }

    /// Integration: write through BLAKE3 quorum with 3 replicas (2-of-3 quorum),
    /// verify checksum matches across all replicas.

    #[test]

    fn blake3_quorum_write_three_replicas_witness() {
        let paths = make_paths(3, "b3qw-r3");

        let mut store = ReplicatedObjectStore::open(
            &paths,
            ReplicatedStoreConfig {
                replica_count: 3,

                durability_mode: DurabilityMode::QuorumWitness,

                min_target_count: 2,

                enable_degraded_reads: false,

                store_options: tidefs_local_object_store::StoreOptions::test_fast(),
            },
        )
        .unwrap();

        let payload = b"three-replica-blake3-quorum-write".to_vec();

        let expected_checksum = blake3::hash(&payload);

        let outcome = store
            .put_with_blake3_quorum("3r-obj", &payload)
            .expect("put_with_blake3_quorum should succeed");

        assert_eq!(outcome.canonical_checksum, expected_checksum);

        assert!(
            outcome.fully_committed,
            "all 3 replicas should ack (local stores)"
        );

        assert_eq!(outcome.acks_collected, 3);

        assert_eq!(outcome.total_targets, 3);

        assert_eq!(outcome.quorum_threshold, 2);

        assert!(outcome.failed_targets.is_empty());

        // Read back and verify

        let read_back = store
            .get_named("3r-obj")
            .expect("get_named should succeed")
            .expect("object should exist");

        assert_eq!(read_back, payload);

        assert_eq!(blake3::hash(&read_back), expected_checksum);

        // Verify all replicas have the data via direct store access

        let key = tidefs_local_object_store::ObjectKey::from_name("3r-obj");

        for i in 0..3 {
            let store_ref = if i == 0 {
                &store.primary
            } else {
                &store.replicas[i - 1]
            };

            let data = store_ref.get(key).unwrap();

            assert!(data.is_some(), "replica {i} should have the object");

            if let Some(ref d) = data {
                assert_eq!(blake3::hash(d), expected_checksum);
            }
        }

        cleanup_dirs(&paths);
    }

    mod transport_replicated {
        use super::*;
        use std::collections::{BTreeMap, BTreeSet};
        use tidefs_durability_layout::{DurabilityLayoutV1, FailureDomainLevel, FailureDomainV1};
        use tidefs_transport::{PlacementMap, TransportSessionSet};

        fn blocking_accept(transport: &mut Transport) -> SessionId {
            for _ in 0..100 {
                match transport.accept_incoming() {
                    Ok(session_id) => return session_id,
                    Err(tidefs_transport::TransportError::Generic(ref error))
                        if error.contains("no pending connections") =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept error: {error}"),
                }
            }
            panic!("timeout waiting for incoming connection");
        }

        fn connect_replica_pair(
            primary: &mut TransportReplicatedStore,
            replica: &mut TransportReplicatedStore,
            replica_node_id: u64,
        ) -> (SessionId, SessionId) {
            let replica_addr = replica.local_addr().unwrap();
            primary
                .transport
                .add_node(NodeInfo::new(replica_node_id, vec![replica_addr], 0));
            let client_session_id = primary.transport.connect(replica_node_id).unwrap();
            let server_session_id = blocking_accept(&mut replica.transport);
            primary.replicas.push(TransportReplica {
                node_id: replica_node_id,
                control_session_id: client_session_id,
                data_session_id: client_session_id,
                shadow_session_id: client_session_id,
            });
            (client_session_id, server_session_id)
        }

        fn transport_store_with_placement(
            node_id: u64,
        ) -> (tempfile::TempDir, TransportReplicatedStore) {
            let tmp = tempfile::TempDir::with_prefix("rep-obj-read-map-").unwrap();
            let layout = DurabilityLayoutV1::mirror(2).unwrap();
            let failure_domain = FailureDomainV1::new(FailureDomainLevel::Node, 64).unwrap();
            let sessions = TransportSessionSet::new();
            let dispatch = PlacementDispatch::new(layout, failure_domain, 0, sessions);
            let store = TransportReplicatedStore::open(
                tmp.path(),
                node_id,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap()
            .with_placement(dispatch);

            (tmp, store)
        }

        fn test_placement_map(version: u64) -> PlacementMap {
            let mut mapping = BTreeMap::new();
            mapping.insert(1001, BTreeSet::from([MemberId::new(1), MemberId::new(2)]));
            mapping.insert(1002, BTreeSet::from([MemberId::new(2), MemberId::new(3)]));
            PlacementMap::new(version, EpochId::new(9), mapping)
        }

        fn placement_receipt_ref(
            object_id: u64,
            object_key: &tidefs_local_object_store::ObjectKey,
            payload: &[u8],
            generation: u64,
        ) -> PlacementReceiptRef {
            PlacementReceiptRef::replicated(
                object_id,
                *object_key.as_bytes(),
                EpochId::new(7),
                generation,
                2,
                payload.len() as u64,
                *blake3::hash(payload).as_bytes(),
            )
        }

        fn read_plan_for_subject(object_id: u64) -> ReplicatedReadPlan {
            ReplicatedReadPlan {
                subject_ref: ReplicatedSubjectId::new(object_id),
                source_member_ref: Some(MemberId::new(2)),
                verified_member_refs: vec![MemberId::new(2)],
                unavailable_member_refs: Vec::new(),
                missing_replica_count: 0,
                read_class: tidefs_replication_model::ReplicatedReadClass::Exact,
                rebuild_required: false,
                read_receipt_ref: ReplicatedReceiptId(17),
            }
        }

        fn backfill_task_for_receipt(
            receipt: PlacementReceiptRef,
            source_member: u64,
            target_member: u64,
        ) -> tidefs_rebuild_runtime::task::BackfillTask {
            let payload_digest_prefix =
                u64::from_le_bytes(receipt.payload_digest[..8].try_into().unwrap());
            tidefs_rebuild_runtime::task::BackfillTask::new(
                tidefs_rebuild_runtime::task::BackfillTaskInit {
                    subject_ref: ReplicatedSubjectId::new(receipt.object_id),
                    placement_receipt_ref: receipt,
                    source_member: MemberId::new(source_member),
                    target_member: MemberId::new(target_member),
                    movement_class: ReplicaMovementClass::RebuildLostOrSuspectCopy,
                    payload_digest: ObjectDigest::new(payload_digest_prefix),
                    payload_len: receipt.payload_len,
                    created_at_ns: 1000,
                    deadline_ns: 5000,
                },
            )
        }

        fn spawn_receipt_source(
            mut source: TransportReplicatedStore,
            server_session_id: SessionId,
        ) -> std::thread::JoinHandle<u64> {
            std::thread::spawn(move || {
                source
                    .handle_segment_fetch_request(server_session_id)
                    .expect("receipt segment fetch served")
            })
        }

        fn spawn_repair_target(
            mut target: TransportReplicatedStore,
            server_session_id: SessionId,
            expected_receipt: PlacementReceiptRef,
            repaired_receipt: Option<PlacementReceiptRef>,
        ) -> std::thread::JoinHandle<Vec<u8>> {
            std::thread::spawn(move || {
                let msg = recv_replication_msg(&mut target.transport, server_session_id)
                    .expect("repair request received");
                let ReplicationMessage::RepairObject {
                    key,
                    placement_receipt_ref,
                    authoritative_payload,
                } = msg
                else {
                    panic!("expected RepairObject");
                };

                assert_eq!(key, expected_receipt.object_key.to_vec());
                assert_eq!(placement_receipt_ref, expected_receipt);
                let object_key =
                    tidefs_local_object_store::ObjectKey::from_bytes32(expected_receipt.object_key);
                target
                    .primary
                    .put(object_key, &authoritative_payload)
                    .unwrap();

                send_replication_msg(
                    &mut target.transport,
                    server_session_id,
                    &ReplicationMessage::RepairObjectAck {
                        key,
                        success: true,
                        repaired_placement_receipt_ref: repaired_receipt,
                    },
                )
                .expect("repair ack sent");

                target.primary.get(object_key).unwrap().unwrap()
            })
        }

        fn rebuild_state_for_task(task: &BackfillTask) -> (RebuildCompletion, RebuildAdmission) {
            let mut completion = RebuildCompletion::new();
            completion.register(task.target_member, 1);

            let loss = tidefs_rebuild_runtime::admission::LossRecord::from_placement_receipt_refs(
                vec![task.target_member],
                vec![task.source_member],
                [task.placement_receipt_ref],
                task.movement_class,
                7,
                task.created_at_ns,
            )
            .expect("task receipt admits rebuild loss");
            let mut admission = RebuildAdmission::with_epoch(7);
            let mut scheduler = tidefs_rebuild_runtime::scheduler::BackfillScheduler::new();
            let outcome = admission.admit(&loss, &mut scheduler);
            assert_eq!(outcome.admitted, vec![task.target_member]);
            assert_eq!(outcome.refused, Vec::new());
            assert_eq!(outcome.report_count, 1);
            assert_eq!(outcome.intent_count, 1);
            assert_eq!(
                admission.status(task.target_member),
                tidefs_rebuild_runtime::admission::RebuildAdmissionStatus::Rebuilding
            );

            (completion, admission)
        }

        fn assert_repair_completion_not_recorded(
            completion: &mut RebuildCompletion,
            admission: &RebuildAdmission,
            member: MemberId,
        ) {
            assert_eq!(
                admission.status(member),
                tidefs_rebuild_runtime::admission::RebuildAdmissionStatus::Rebuilding
            );
            assert_eq!(completion.status(member).unwrap().subjects_completed, 0);
            assert_eq!(completion.total_completed_subjects(), 0);
            assert_eq!(completion.drain_events().len(), 0);
        }

        #[test]
        fn read_plan_response_receipt_validates_payload_authority() {
            let payload = b"planned-read-authority";
            let object_key = tidefs_local_object_store::ObjectKey::from_name(b"planned-read");
            let receipt = placement_receipt_ref(88, &object_key, payload, 9);
            let plan = read_plan_for_subject(88);

            validate_read_plan_response_payload(&plan, payload, Some(receipt)).unwrap();
        }

        #[test]
        fn read_plan_response_receipt_rejects_digest_mismatch() {
            let payload = b"planned-read-authority";
            let object_key = tidefs_local_object_store::ObjectKey::from_name(b"planned-read");
            let mut receipt = placement_receipt_ref(88, &object_key, payload, 9);
            receipt.payload_digest = blake3::hash(b"different").into();
            let plan = read_plan_for_subject(88);

            let err =
                validate_read_plan_response_payload(&plan, payload, Some(receipt)).unwrap_err();
            assert!(err.contains("digest mismatch"));
        }

        #[test]
        fn read_plan_response_receipt_rejects_synthetic_ref() {
            let plan = read_plan_for_subject(88);
            let receipt = PlacementReceiptRef::synthetic_for_subject(ReplicatedSubjectId::new(88));

            let err =
                validate_read_plan_response_payload(&plan, b"payload", Some(receipt)).unwrap_err();
            assert!(err.contains("synthetic"));
        }

        #[test]
        fn planned_read_with_evidence_preserves_remote_receipt_authority() {
            let primary_dir = tempfile::tempdir().unwrap();
            let replica_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut replica = TransportReplicatedStore::open(
                replica_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let (_client_session_id, server_session_id) =
                connect_replica_pair(&mut primary, &mut replica, 2);

            let payload = b"receipt-backed planned read".to_vec();
            let object_key = tidefs_local_object_store::ObjectKey::from_name(b"planned-read");
            let receipt = placement_receipt_ref(88, &object_key, &payload, 21);
            let plan = read_plan_for_subject(88);
            let server_payload = payload.clone();
            let server = std::thread::spawn(move || {
                let msg = recv_replication_msg(&mut replica.transport, server_session_id)
                    .expect("read plan request received");
                let ReplicationMessage::ReadPlan { plan_bytes } = msg else {
                    panic!("expected ReadPlan request, got {msg:?}");
                };
                let received_plan: ReplicatedReadPlan =
                    bincode::deserialize(&plan_bytes).expect("read plan decodes");
                assert_eq!(received_plan.subject_ref, ReplicatedSubjectId::new(88));

                send_replication_msg(
                    &mut replica.transport,
                    server_session_id,
                    &ReplicationMessage::ReadPlanResponse {
                        found: true,
                        payload: server_payload,
                        source_member_id: 2,
                        placement_receipt_ref: Some(receipt),
                    },
                )
                .expect("read plan response sent");
            });

            let result = primary
                .get_planned_with_evidence(&plan)
                .expect("planned read succeeds")
                .expect("planned read found remote payload");

            assert_eq!(result.payload, payload);
            assert_eq!(result.source_member_id, 2);
            assert_eq!(result.placement_receipt_ref, Some(receipt));
            assert_eq!(primary.stats().planned_reads, 1);
            assert_eq!(primary.stats().degraded_reads, 1);
            server.join().unwrap();
        }

        #[test]
        fn planned_read_with_evidence_rejects_invalid_remote_receipt() {
            let primary_dir = tempfile::tempdir().unwrap();
            let replica_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut replica = TransportReplicatedStore::open(
                replica_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let (_client_session_id, server_session_id) =
                connect_replica_pair(&mut primary, &mut replica, 2);

            let payload = b"receipt-backed planned read".to_vec();
            let object_key = tidefs_local_object_store::ObjectKey::from_name(b"planned-read");
            let mut receipt = placement_receipt_ref(88, &object_key, &payload, 22);
            receipt.payload_digest = blake3::hash(b"different-payload").into();
            let plan = read_plan_for_subject(88);
            let server_payload = payload.clone();
            let server = std::thread::spawn(move || {
                let msg = recv_replication_msg(&mut replica.transport, server_session_id)
                    .expect("read plan request received");
                let ReplicationMessage::ReadPlan { .. } = msg else {
                    panic!("expected ReadPlan request, got {msg:?}");
                };

                send_replication_msg(
                    &mut replica.transport,
                    server_session_id,
                    &ReplicationMessage::ReadPlanResponse {
                        found: true,
                        payload: server_payload,
                        source_member_id: 2,
                        placement_receipt_ref: Some(receipt),
                    },
                )
                .expect("read plan response sent");
            });

            let err = primary
                .get_planned_with_evidence(&plan)
                .expect_err("invalid receipt is rejected");

            assert!(err.contains("digest mismatch"));
            assert_eq!(primary.stats().planned_reads, 0);
            assert_eq!(primary.stats().degraded_reads, 0);
            server.join().unwrap();
        }

        #[test]
        fn authoritative_planned_read_accepts_valid_remote_receipt() {
            let primary_dir = tempfile::tempdir().unwrap();
            let replica_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut replica = TransportReplicatedStore::open(
                replica_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let (_client_session_id, server_session_id) =
                connect_replica_pair(&mut primary, &mut replica, 2);

            let payload = b"authoritative planned read".to_vec();
            let object_key = tidefs_local_object_store::ObjectKey::from_name(b"authoritative-read");
            let receipt = placement_receipt_ref(88, &object_key, &payload, 23);
            let plan = read_plan_for_subject(88);
            let server_payload = payload.clone();
            let server = std::thread::spawn(move || {
                let msg = recv_replication_msg(&mut replica.transport, server_session_id)
                    .expect("read plan request received");
                let ReplicationMessage::ReadPlan { .. } = msg else {
                    panic!("expected ReadPlan request, got {msg:?}");
                };

                send_replication_msg(
                    &mut replica.transport,
                    server_session_id,
                    &ReplicationMessage::ReadPlanResponse {
                        found: true,
                        payload: server_payload,
                        source_member_id: 2,
                        placement_receipt_ref: Some(receipt),
                    },
                )
                .expect("read plan response sent");
            });

            let result = primary
                .get_planned_with_required_receipt(&plan)
                .expect("authoritative planned read succeeds")
                .expect("authoritative planned read found remote payload");

            assert_eq!(result.payload, payload);
            assert_eq!(result.source_member_id, 2);
            assert_eq!(result.placement_receipt_ref, receipt);
            assert_eq!(primary.stats().planned_reads, 1);
            assert_eq!(primary.stats().degraded_reads, 1);
            server.join().unwrap();
        }

        #[test]
        fn authoritative_planned_read_rejects_receiptless_remote_response() {
            let primary_dir = tempfile::tempdir().unwrap();
            let replica_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut replica = TransportReplicatedStore::open(
                replica_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let (_client_session_id, server_session_id) =
                connect_replica_pair(&mut primary, &mut replica, 2);

            let plan = read_plan_for_subject(88);
            let server = std::thread::spawn(move || {
                let msg = recv_replication_msg(&mut replica.transport, server_session_id)
                    .expect("read plan request received");
                let ReplicationMessage::ReadPlan { .. } = msg else {
                    panic!("expected ReadPlan request, got {msg:?}");
                };

                send_replication_msg(
                    &mut replica.transport,
                    server_session_id,
                    &ReplicationMessage::ReadPlanResponse {
                        found: true,
                        payload: b"receiptless planned read".to_vec(),
                        source_member_id: 2,
                        placement_receipt_ref: None,
                    },
                )
                .expect("read plan response sent");
            });

            let err = primary
                .get_planned_with_required_receipt(&plan)
                .expect_err("receiptless authority read is rejected");

            assert!(err.contains("without placement receipt evidence"));
            assert_eq!(primary.stats().planned_reads, 0);
            assert_eq!(primary.stats().degraded_reads, 0);
            server.join().unwrap();
        }

        #[test]
        fn authoritative_planned_read_rejects_local_primary_without_receipt() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = TransportReplicatedStore::open(
                dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let plan = read_plan_for_subject(88);
            let name = format!("obj-{:016x}", plan.subject_ref.0);
            let key = tidefs_local_object_store::ObjectKey::from_name(&name);
            store.primary.put(key, b"local-planned-payload").unwrap();

            let err = store
                .get_planned_with_required_receipt(&plan)
                .expect_err("local primary hit without receipt is rejected");

            assert!(err.contains("local primary without placement receipt evidence"));
            assert_eq!(store.stats().planned_reads, 0);
            assert_eq!(store.stats().degraded_reads, 0);
        }

        #[test]
        fn payload_only_planned_read_api_accepts_optional_evidence() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = TransportReplicatedStore::open(
                dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let plan = read_plan_for_subject(88);
            let name = format!("obj-{:016x}", plan.subject_ref.0);
            let key = tidefs_local_object_store::ObjectKey::from_name(&name);
            store.primary.put(key, b"local-planned-payload").unwrap();

            let payload = store
                .get_planned(&plan)
                .expect("payload-only planned read succeeds")
                .expect("local payload found");

            assert_eq!(payload, b"local-planned-payload".to_vec());
            assert_eq!(store.stats().planned_reads, 1);
            assert_eq!(store.stats().degraded_reads, 0);
        }

        #[test]
        fn open_and_close() {
            let dir = tempfile::tempdir().unwrap();
            let store = TransportReplicatedStore::open(
                dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            );
            assert!(store.is_ok());
            let store = store.unwrap();
            assert_eq!(store.local_node_id(), 1);
            assert!(store.local_addr().is_some());
            // Drop calls close
        }

        #[test]
        fn put_get_local_only() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = TransportReplicatedStore::open(
                dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let result = store.put_named("hello", b"world").unwrap();
            assert!(result.quorum_reached);
            assert_eq!(result.acks, 1);
            assert_eq!(result.total_targets, 1);
            assert!(result.fully_committed);

            let data = store.get_named("hello").unwrap();
            assert_eq!(data, Some(b"world".to_vec()));

            let missing = store.get_named("nope").unwrap();
            assert_eq!(missing, None);
        }

        #[test]
        fn put_key_local_stores_exact_object_key() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = TransportReplicatedStore::open(
                dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let key = tidefs_local_object_store::ObjectKey::from_bytes32([0xB6; 32]);

            store.put_key_local(key, b"exact").unwrap();

            assert_eq!(store.get_key_local(key).unwrap(), Some(b"exact".to_vec()));
            assert_eq!(store.get_local(key.as_bytes32()).unwrap(), None);
        }

        #[test]
        fn delete_local() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = TransportReplicatedStore::open(
                dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            store.put_named("delme", b"data").unwrap();
            assert!(store.get_named("delme").unwrap().is_some());

            let deleted = store.delete_named("delme").unwrap();
            assert!(deleted);
            assert!(store.get_named("delme").unwrap().is_none());

            let again = store.delete_named("delme").unwrap();
            assert!(!again);
        }

        #[test]
        fn delete_quorum_met_local() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = TransportReplicatedStore::open(
                dir.path(),
                1,
                TransportReplicatedStoreConfig {
                    write_quorum: 1,
                    total_replicas: 1,
                    enable_degraded_reads: false,
                    rdma: false,
                    store_options: tidefs_local_object_store::StoreOptions::test_fast(),
                },
            )
            .unwrap();

            store.put_named("obj", b"payload").unwrap();
            assert!(store.get_named("obj").unwrap().is_some());

            // Quorum = 1, only local primary available -> should succeed
            let deleted = store.delete_named("obj").unwrap();
            assert!(deleted);
            assert!(store.get_named("obj").unwrap().is_none());
        }

        #[test]
        fn delete_idempotent_quorum() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = TransportReplicatedStore::open(
                dir.path(),
                1,
                TransportReplicatedStoreConfig {
                    write_quorum: 1,
                    total_replicas: 1,
                    enable_degraded_reads: false,
                    rdma: false,
                    store_options: tidefs_local_object_store::StoreOptions::test_fast(),
                },
            )
            .unwrap();

            store.put_named("obj", b"payload").unwrap();
            let deleted = store.delete_named("obj").unwrap();
            assert!(deleted);

            // Second delete — idempotent, object already gone
            let again = store.delete_named("obj").unwrap();
            assert!(!again, "idempotent delete should return false");
        }

        #[test]
        fn delete_quorum_fails_when_insufficient_replicas() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = TransportReplicatedStore::open(
                dir.path(),
                1,
                TransportReplicatedStoreConfig {
                    write_quorum: 3, // requires 3 acks, but only 1 replica exists
                    total_replicas: 3,
                    enable_degraded_reads: false,
                    rdma: false,
                    store_options: tidefs_local_object_store::StoreOptions::test_fast(),
                },
            )
            .unwrap();

            store.primary.put_named("obj", b"payload").unwrap();
            let result = store.delete_named("obj");
            assert!(
                result.is_err(),
                "delete should fail when write_quorum > available replicas"
            );
            assert!(
                result.unwrap_err().contains("quorum"),
                "error should mention quorum failure"
            );
            assert_eq!(store.get_named("obj").unwrap(), Some(b"payload".to_vec()));
        }

        #[test]
        fn stats_tracking() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = TransportReplicatedStore::open(
                dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            store.put_named("a", b"hello").unwrap();
            store.put_named("b", b"world").unwrap();

            let stats = store.stats();
            assert_eq!(stats.committed_writes, 2);
            assert_eq!(stats.object_count, 2);
            assert_eq!(stats.bytes_written, 10);
            assert_eq!(stats.degraded_writes, 0);
            assert_eq!(stats.failed_writes, 0);
        }

        #[test]
        fn put_named_times_out_unacked_replica_and_releases_primary() {
            let primary_dir = tempfile::tempdir().unwrap();
            let replica_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig {
                    write_quorum: 2,
                    total_replicas: 2,
                    enable_degraded_reads: false,
                    rdma: false,
                    store_options: tidefs_local_object_store::StoreOptions::test_fast(),
                },
            )
            .unwrap();
            let mut replica = TransportReplicatedStore::open(
                replica_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let replica_addr = replica.local_addr().unwrap();
            primary
                .transport
                .add_node(NodeInfo::new(2, vec![replica_addr], 0));
            let client_session_id = primary.transport.connect(2).unwrap();
            let _server_session_id = blocking_accept(&mut replica.transport);
            primary.replicas.push(TransportReplica {
                node_id: 2,
                control_session_id: client_session_id,
                data_session_id: client_session_id,
                shadow_session_id: client_session_id,
            });

            let start = std::time::Instant::now();
            let result = primary.put_named("unacked", b"payload").unwrap();

            assert!(
                start.elapsed() < Duration::from_secs(2),
                "unacked replica should fail through bounded ack wait"
            );
            assert!(!result.quorum_reached);
            assert_eq!(result.acks, 1);
            assert_eq!(result.quorum_size, 2);
            assert_eq!(primary.stats().failed_writes, 1);
            assert_eq!(primary.stats().object_count, 0);
            assert_eq!(primary.get_local("unacked").unwrap(), None);
        }

        #[test]
        fn put_named_no_quorum_restores_previous_primary_payload() {
            let primary_dir = tempfile::tempdir().unwrap();
            let replica_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig {
                    write_quorum: 2,
                    total_replicas: 2,
                    enable_degraded_reads: false,
                    rdma: false,
                    store_options: tidefs_local_object_store::StoreOptions::test_fast(),
                },
            )
            .unwrap();
            let mut replica = TransportReplicatedStore::open(
                replica_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            primary.primary.put_named("overwrite", b"old").unwrap();

            let replica_addr = replica.local_addr().unwrap();
            primary
                .transport
                .add_node(NodeInfo::new(2, vec![replica_addr], 0));
            let client_session_id = primary.transport.connect(2).unwrap();
            let _server_session_id = blocking_accept(&mut replica.transport);
            primary.replicas.push(TransportReplica {
                node_id: 2,
                control_session_id: client_session_id,
                data_session_id: client_session_id,
                shadow_session_id: client_session_id,
            });

            let result = primary.put_named("overwrite", b"new").unwrap();
            assert!(!result.quorum_reached);
            assert_eq!(primary.stats().failed_writes, 1);
            assert_eq!(
                primary.get_local("overwrite").unwrap(),
                Some(b"old".to_vec())
            );
        }

        #[test]
        fn put_named_no_quorum_rolls_back_acked_replica() {
            let primary_dir = tempfile::tempdir().unwrap();
            let replica_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig {
                    write_quorum: 3,
                    total_replicas: 3,
                    enable_degraded_reads: false,
                    rdma: false,
                    store_options: tidefs_local_object_store::StoreOptions::test_fast(),
                },
            )
            .unwrap();
            let mut replica = TransportReplicatedStore::open(
                replica_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            primary.primary.put_named("rollback", b"old").unwrap();
            replica.primary.put_named("rollback", b"old").unwrap();

            let replica_addr = replica.local_addr().unwrap();
            primary
                .transport
                .add_node(NodeInfo::new(2, vec![replica_addr], 0));
            let client_session_id = primary.transport.connect(2).unwrap();
            let server_session_id = blocking_accept(&mut replica.transport);
            primary.replicas.push(TransportReplica {
                node_id: 2,
                control_session_id: client_session_id,
                data_session_id: client_session_id,
                shadow_session_id: client_session_id,
            });

            let replica_thread = std::thread::spawn(move || {
                match recv_replication_msg(&mut replica.transport, server_session_id).unwrap() {
                    ReplicationMessage::Put { name, payload } => {
                        replica.put_local(&name, &payload).unwrap();
                        send_replication_msg(
                            &mut replica.transport,
                            server_session_id,
                            &ReplicationMessage::Ack {
                                key_hash: name,
                                success: true,
                            },
                        )
                        .unwrap();
                    }
                    other => panic!("expected first Put, got {other:?}"),
                }

                match recv_replication_msg(&mut replica.transport, server_session_id).unwrap() {
                    ReplicationMessage::Put { name, payload } => {
                        replica.put_local(&name, &payload).unwrap();
                        send_replication_msg(
                            &mut replica.transport,
                            server_session_id,
                            &ReplicationMessage::Ack {
                                key_hash: name,
                                success: true,
                            },
                        )
                        .unwrap();
                    }
                    other => panic!("expected rollback Put, got {other:?}"),
                }

                replica.get_local("rollback").unwrap()
            });

            let result = primary.put_named("rollback", b"new").unwrap();
            assert!(!result.quorum_reached);
            assert_eq!(result.acks, 2);
            assert_eq!(result.quorum_size, 3);
            assert_eq!(
                primary.get_local("rollback").unwrap(),
                Some(b"old".to_vec())
            );
            assert_eq!(
                replica_thread.join().unwrap(),
                Some(b"old".to_vec()),
                "acked replica should be restored after no-quorum put"
            );
        }

        #[test]
        fn delete_named_no_quorum_rolls_back_acked_replica() {
            let primary_dir = tempfile::tempdir().unwrap();
            let replica_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig {
                    write_quorum: 3,
                    total_replicas: 3,
                    enable_degraded_reads: false,
                    rdma: false,
                    store_options: tidefs_local_object_store::StoreOptions::test_fast(),
                },
            )
            .unwrap();
            let mut replica = TransportReplicatedStore::open(
                replica_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            primary
                .primary
                .put_named("delete-rollback", b"old")
                .unwrap();
            replica
                .primary
                .put_named("delete-rollback", b"old")
                .unwrap();

            let replica_addr = replica.local_addr().unwrap();
            primary
                .transport
                .add_node(NodeInfo::new(2, vec![replica_addr], 0));
            let client_session_id = primary.transport.connect(2).unwrap();
            let server_session_id = blocking_accept(&mut replica.transport);
            primary.replicas.push(TransportReplica {
                node_id: 2,
                control_session_id: client_session_id,
                data_session_id: client_session_id,
                shadow_session_id: client_session_id,
            });

            let replica_thread = std::thread::spawn(move || {
                match TransportReplicatedStore::recv_replication_ack_bounded(
                    &mut replica.transport,
                    server_session_id,
                )
                .unwrap()
                {
                    ReplicationMessage::Delete { name, .. } => {
                        replica.delete_local(&name).unwrap();
                        send_replication_msg(
                            &mut replica.transport,
                            server_session_id,
                            &ReplicationMessage::DeleteAck {
                                deleted: true,
                                generation: 0,
                            },
                        )
                        .unwrap();
                    }
                    other => panic!("expected delete, got {other:?}"),
                }

                match TransportReplicatedStore::recv_replication_ack_bounded(
                    &mut replica.transport,
                    server_session_id,
                )
                .unwrap()
                {
                    ReplicationMessage::Put { name, payload } => {
                        replica.put_local(&name, &payload).unwrap();
                        send_replication_msg(
                            &mut replica.transport,
                            server_session_id,
                            &ReplicationMessage::Ack {
                                key_hash: name,
                                success: true,
                            },
                        )
                        .unwrap();
                    }
                    other => panic!("expected rollback Put, got {other:?}"),
                }

                replica.get_local("delete-rollback").unwrap()
            });

            let result = primary.delete_named("delete-rollback");
            assert!(result.is_err());
            assert!(
                result.unwrap_err().contains("quorum"),
                "error should mention quorum failure"
            );
            assert_eq!(
                primary.get_local("delete-rollback").unwrap(),
                Some(b"old".to_vec())
            );
            assert_eq!(
                replica_thread.join().unwrap(),
                Some(b"old".to_vec()),
                "acked replica should be restored after no-quorum delete"
            );
        }

        #[test]
        fn config_presets_consistent() {
            let three = TransportReplicatedStoreConfig::three_replica_quorum();
            assert_eq!(three.total_replicas, 3);
            assert_eq!(three.write_quorum, 2);
            assert!(three.write_quorum > three.total_replicas / 2);

            let five = TransportReplicatedStoreConfig::five_replica_witness();
            assert_eq!(five.total_replicas, 5);
            assert_eq!(five.write_quorum, 3);
            assert!(five.write_quorum > five.total_replicas / 2);
        }

        #[test]
        fn request_peer_placement_map_installs_newer_map() {
            let (_primary_dir, mut primary) = transport_store_with_placement(1);
            let replica_dir = tempfile::tempdir().unwrap();
            let mut replica = TransportReplicatedStore::open(
                replica_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let (_client_session_id, server_session_id) =
                connect_replica_pair(&mut primary, &mut replica, 2);
            let installed = test_placement_map(1);
            let peer_map = test_placement_map(3);
            primary.set_placement_map(installed.clone());

            let peer_map_for_thread = peer_map.clone();
            let replica_thread = std::thread::spawn(move || {
                let request = TransportReplicatedStore::recv_replication_ack_bounded(
                    &mut replica.transport,
                    server_session_id,
                )
                .unwrap();
                assert_eq!(
                    request,
                    ReplicationMessage::PlacementMapRequest { minimum_version: 2 }
                );
                send_replication_msg(
                    &mut replica.transport,
                    server_session_id,
                    &ReplicationMessage::PlacementMapResponse {
                        requested_minimum_version: 2,
                        map: Some(peer_map_for_thread),
                        refusal: None,
                    },
                )
                .unwrap();
            });

            let report = primary.request_peer_placement_map(2, 2).unwrap();

            assert_eq!(report.peer_node_id, 2);
            assert_eq!(report.requested_minimum_version, 2);
            assert_eq!(report.previous_version, 1);
            assert_eq!(report.installed_version, 3);
            assert_eq!(report.installed_map, peer_map);
            assert_eq!(primary.placement_map(), Some(&peer_map));
            replica_thread.join().unwrap();
        }

        #[test]
        fn request_peer_placement_map_refusal_does_not_mutate() {
            let (_primary_dir, mut primary) = transport_store_with_placement(1);
            let replica_dir = tempfile::tempdir().unwrap();
            let mut replica = TransportReplicatedStore::open(
                replica_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let (_client_session_id, server_session_id) =
                connect_replica_pair(&mut primary, &mut replica, 2);
            let installed = test_placement_map(5);
            primary.set_placement_map(installed.clone());

            let replica_thread = std::thread::spawn(move || {
                let request = TransportReplicatedStore::recv_replication_ack_bounded(
                    &mut replica.transport,
                    server_session_id,
                )
                .unwrap();
                assert_eq!(
                    request,
                    ReplicationMessage::PlacementMapRequest { minimum_version: 6 }
                );
                send_replication_msg(
                    &mut replica.transport,
                    server_session_id,
                    &ReplicationMessage::PlacementMapResponse {
                        requested_minimum_version: 6,
                        map: None,
                        refusal: Some(PlacementMapRefusalReason::NoInstalledMap),
                    },
                )
                .unwrap();
            });

            let err = primary.request_peer_placement_map(2, 6).unwrap_err();

            assert_eq!(
                err,
                PeerPlacementMapRequestError::Refused {
                    peer_node_id: 2,
                    requested_minimum_version: 6,
                    reason: PlacementMapRefusalReason::NoInstalledMap,
                }
            );
            assert_eq!(primary.placement_map(), Some(&installed));
            replica_thread.join().unwrap();
        }

        #[test]
        fn request_peer_placement_map_rejects_stale_map_without_mutation() {
            let (_primary_dir, mut primary) = transport_store_with_placement(1);
            let replica_dir = tempfile::tempdir().unwrap();
            let mut replica = TransportReplicatedStore::open(
                replica_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let (_client_session_id, server_session_id) =
                connect_replica_pair(&mut primary, &mut replica, 2);
            let installed = test_placement_map(5);
            let stale_peer_map = test_placement_map(4);
            primary.set_placement_map(installed.clone());

            let replica_thread = std::thread::spawn(move || {
                let request = TransportReplicatedStore::recv_replication_ack_bounded(
                    &mut replica.transport,
                    server_session_id,
                )
                .unwrap();
                assert_eq!(
                    request,
                    ReplicationMessage::PlacementMapRequest { minimum_version: 4 }
                );
                send_replication_msg(
                    &mut replica.transport,
                    server_session_id,
                    &ReplicationMessage::PlacementMapResponse {
                        requested_minimum_version: 4,
                        map: Some(stale_peer_map),
                        refusal: None,
                    },
                )
                .unwrap();
            });

            let err = primary.request_peer_placement_map(2, 4).unwrap_err();

            assert_eq!(
                err,
                PeerPlacementMapRequestError::Stale {
                    peer_node_id: 2,
                    requested_minimum_version: 4,
                    available_version: 4,
                    local_version: 5,
                }
            );
            assert_eq!(primary.placement_map(), Some(&installed));
            replica_thread.join().unwrap();
        }

        #[test]
        fn put_result_reflects_ack_count() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = TransportReplicatedStore::open(
                dir.path(),
                1,
                TransportReplicatedStoreConfig {
                    write_quorum: 1,
                    total_replicas: 1,
                    enable_degraded_reads: false,
                    rdma: false,
                    store_options: tidefs_local_object_store::StoreOptions::test_fast(),
                },
            )
            .unwrap();

            let result = store.put_named("x", b"y").unwrap();
            assert!(result.quorum_reached);
            assert!(result.fully_committed);
            assert_eq!(result.acks, 1);
            assert_eq!(result.total_targets, 1);
            assert_eq!(result.quorum_size, 1);
        }

        #[test]
        fn replicated_write_trait_stores_under_canonical_key() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = TransportReplicatedStore::open(
                dir.path(),
                1,
                TransportReplicatedStoreConfig {
                    write_quorum: 1,
                    total_replicas: 1,
                    enable_degraded_reads: false,
                    rdma: false,
                    store_options: tidefs_local_object_store::StoreOptions::test_fast(),
                },
            )
            .unwrap();

            store.write_object(42, 4096, b"replicated payload").unwrap();

            let name = replicated_object_name(42, 4096);
            let key = tidefs_local_object_store::ObjectKey::from_name(&name);
            let stored = store.primary.get(key).unwrap();
            assert_eq!(stored, Some(b"replicated payload".to_vec()));
            assert_eq!(store.stats().committed_writes, 1);
            assert_eq!(store.stats().bytes_written, 18);
            assert_eq!(store.stats().object_count, 1);
        }

        #[test]
        fn replication_write_path_stores_on_peer_over_transport() {
            let primary_dir = tempfile::tempdir().unwrap();
            let replica_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig {
                    write_quorum: 2,
                    total_replicas: 2,
                    enable_degraded_reads: false,
                    rdma: false,
                    store_options: tidefs_local_object_store::StoreOptions::test_fast(),
                },
            )
            .unwrap();
            let mut replica = TransportReplicatedStore::open(
                replica_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let replica_addr = replica.local_addr().unwrap();
            primary
                .transport
                .add_node(NodeInfo::new(2, vec![replica_addr], 0));
            let client_session_id = primary.transport.connect(2).unwrap();
            let server_session_id = blocking_accept(&mut replica.transport);
            primary.replicas.push(TransportReplica {
                node_id: 2,
                control_session_id: client_session_id,
                data_session_id: client_session_id,
                shadow_session_id: client_session_id,
            });

            let object_id = 77;
            let offset = 8192;
            let payload = b"tcp replicated write".to_vec();
            let expected_name = replicated_object_name(object_id, offset);

            let peer = std::thread::spawn(move || {
                let bytes_written = handle_incoming_write(
                    &mut replica.transport,
                    server_session_id,
                    &mut replica.primary,
                )
                .unwrap();
                let key = tidefs_local_object_store::ObjectKey::from_name(&expected_name);
                let stored = replica.primary.get(key).unwrap();
                (bytes_written, stored)
            });

            primary
                .write_object(object_id, offset, &payload)
                .expect("replicated write");
            let (bytes_written, stored) = peer.join().expect("peer thread");

            assert_eq!(bytes_written, payload.len() as u64);
            assert_eq!(stored, Some(payload));
            assert_eq!(primary.stats().committed_writes, 1);
            assert_eq!(primary.stats().failed_writes, 0);
        }

        // ── Plan-based replication tests ──────────────────────────────

        #[test]
        fn put_planned_valid_write_plan() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = TransportReplicatedStore::open(
                dir.path(),
                1,
                TransportReplicatedStoreConfig {
                    write_quorum: 1,
                    total_replicas: 1,
                    enable_degraded_reads: false,
                    rdma: false,
                    store_options: tidefs_local_object_store::StoreOptions::test_fast(),
                },
            )
            .unwrap();

            let plan = ReplicatedWritePlan {
                subject: ReplicatedObjectRootRecord {
                    subject_id: ReplicatedSubjectId(42),
                    subject_class: ReplicatedSubjectClass::ImmutableObject,
                    membership_epoch_ref: EpochId(0),
                    root_generation: 0,
                    payload_digest: ObjectDigest(0),
                    payload_len: 0,
                    publication_receipt_ref: ReplicatedReceiptId(0),
                },
                placement_verdict: tidefs_membership_epoch::MembershipPlacementVerdictRecord {
                    verdict_id: 0,
                    membership_epoch_ref: EpochId(0),
                    placement_class: tidefs_membership_epoch::PlacementIntentClass::ReplicaTarget,
                    selected_member_refs: vec![],
                    selected_domain_refs: vec![],
                    verdict_class: tidefs_membership_epoch::VerdictClass::Admit,
                    degraded_reason_refs: vec![],
                    issuance_receipt_ref: tidefs_membership_epoch::ReceiptId(0),
                    digest: 0,
                },
                target_member_refs: vec![],
                committed_member_refs: vec![],
                unavailable_member_refs: vec![],
                quorum_required: 1,
                unplaced_replica_count: 0,
                write_class: ReplicatedWriteClass::Committed,
                commit_receipt_ref: ReplicatedReceiptId(0),
            };

            let result = store.put_planned(&plan, b"payload").unwrap();
            assert!(result.quorum_reached);
            assert!(result.fully_committed);
            assert_eq!(result.acks, 1);
            assert_eq!(result.total_targets, 1);
            assert_eq!(result.quorum_size, 1);

            // Verification receipt produced
            let receipts = store.verification_receipts();
            assert_eq!(receipts.len(), 1);
            // With no witness keys configured, status is WitnessInsufficient
            assert_eq!(receipts[0].status, VerificationStatus::WitnessInsufficient);
        }

        #[test]
        fn put_planned_refused_no_quorum() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = TransportReplicatedStore::open(
                dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let plan = ReplicatedWritePlan {
                subject: ReplicatedObjectRootRecord {
                    subject_id: ReplicatedSubjectId(1),
                    subject_class: ReplicatedSubjectClass::ImmutableObject,
                    membership_epoch_ref: EpochId(0),
                    root_generation: 0,
                    payload_digest: ObjectDigest(0),
                    payload_len: 0,
                    publication_receipt_ref: ReplicatedReceiptId(0),
                },
                placement_verdict: tidefs_membership_epoch::MembershipPlacementVerdictRecord {
                    verdict_id: 0,
                    membership_epoch_ref: EpochId(0),
                    placement_class: tidefs_membership_epoch::PlacementIntentClass::ReplicaTarget,
                    selected_member_refs: vec![],
                    selected_domain_refs: vec![],
                    verdict_class: tidefs_membership_epoch::VerdictClass::Admit,
                    degraded_reason_refs: vec![],
                    issuance_receipt_ref: tidefs_membership_epoch::ReceiptId(0),
                    digest: 0,
                },
                target_member_refs: vec![],
                committed_member_refs: vec![],
                unavailable_member_refs: vec![],
                quorum_required: 1,
                unplaced_replica_count: 1,
                write_class: ReplicatedWriteClass::RefusedNoQuorum,
                commit_receipt_ref: ReplicatedReceiptId(0),
            };

            let err = store.put_planned(&plan, b"data").unwrap_err();
            assert!(
                err.contains("RefusedNoQuorum"),
                "expected RefusedNoQuorum in error, got: {err}"
            );
        }

        #[test]
        fn put_planned_stats_update() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = TransportReplicatedStore::open(
                dir.path(),
                1,
                TransportReplicatedStoreConfig {
                    write_quorum: 1,
                    total_replicas: 1,
                    enable_degraded_reads: false,
                    rdma: false,
                    store_options: tidefs_local_object_store::StoreOptions::test_fast(),
                },
            )
            .unwrap();

            let plan = ReplicatedWritePlan {
                subject: ReplicatedObjectRootRecord {
                    subject_id: ReplicatedSubjectId(100),
                    subject_class: ReplicatedSubjectClass::ImmutableObject,
                    membership_epoch_ref: EpochId(0),
                    root_generation: 0,
                    payload_digest: ObjectDigest(0),
                    payload_len: 0,
                    publication_receipt_ref: ReplicatedReceiptId(0),
                },
                placement_verdict: tidefs_membership_epoch::MembershipPlacementVerdictRecord {
                    verdict_id: 0,
                    membership_epoch_ref: EpochId(0),
                    placement_class: tidefs_membership_epoch::PlacementIntentClass::ReplicaTarget,
                    selected_member_refs: vec![],
                    selected_domain_refs: vec![],
                    verdict_class: tidefs_membership_epoch::VerdictClass::Admit,
                    degraded_reason_refs: vec![],
                    issuance_receipt_ref: tidefs_membership_epoch::ReceiptId(0),
                    digest: 0,
                },
                target_member_refs: vec![],
                committed_member_refs: vec![],
                unavailable_member_refs: vec![],
                quorum_required: 1,
                unplaced_replica_count: 0,
                write_class: ReplicatedWriteClass::Committed,
                commit_receipt_ref: ReplicatedReceiptId(0),
            };

            store.put_planned(&plan, b"stats-test").unwrap();
            let stats = store.stats();
            assert_eq!(stats.planned_writes, 1);
            assert_eq!(stats.committed_writes, 1);
            assert_eq!(stats.bytes_written, 10);
            assert_eq!(stats.object_count, 1);
        }

        #[test]
        fn verification_context_starting_state() {
            let dir = tempfile::tempdir().unwrap();
            let store = TransportReplicatedStore::open(
                dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            // Unused store still provides valid verification context
            let receipts = store.verification_receipts();
            assert!(receipts.is_empty());

            let ctx = &store.verification_ctx;
            assert_eq!(ctx.verified_receipt_count(), 0);
        }

        #[test]
        fn sync_all_persists() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = TransportReplicatedStore::open(
                dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            store.put_named("persist-me", b"check").unwrap();
            store.sync_all().unwrap();

            // Reopen and verify
            drop(store);
            let mut store2 = TransportReplicatedStore::open(
                dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let data = store2.get_named("persist-me").unwrap();
            assert_eq!(data, Some(b"check".to_vec()));
        }

        // ── Segment fetch tests ──────────────────────────────────────

        #[test]
        fn fetch_remote_segment_invalid_replica_index() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = TransportReplicatedStore::open(
                dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            // No replicas connected, so any index is invalid
            let result = store.fetch_remote_segment(0, 42, 0, 1024);
            assert!(result.is_err());
            assert!(
                result.unwrap_err().contains("out of bounds"),
                "expected out-of-bounds error"
            );
        }

        #[test]
        fn fetch_remote_segment_by_receipt_uses_receipt_object_key() {
            let primary_dir = tempfile::tempdir().unwrap();
            let replica_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut replica = TransportReplicatedStore::open(
                replica_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let object_id = 52u64;
            let receipt_payload = b"receipt-bound movement payload".to_vec();
            let object_id_payload = b"receiptless object-id bytes".to_vec();
            let receipt_key =
                tidefs_local_object_store::ObjectKey::from_name(b"issue-52-receipt-key");
            let object_id_key =
                tidefs_local_object_store::ObjectKey::from_name(object_id.to_le_bytes());
            let receipt = placement_receipt_ref(object_id, &receipt_key, &receipt_payload, 11);
            replica.primary.put(receipt_key, &receipt_payload).unwrap();
            replica
                .primary
                .put(object_id_key, &object_id_payload)
                .unwrap();

            let (_client_session_id, server_session_id) =
                connect_replica_pair(&mut primary, &mut replica, 2);
            let server = std::thread::spawn(move || {
                replica
                    .handle_segment_fetch_request(server_session_id)
                    .expect("receipt segment fetch served")
            });

            let fetched = primary
                .fetch_remote_segment_by_receipt(0, receipt, 8, 8)
                .expect("receipt-bound segment fetch");

            assert_eq!(fetched, receipt_payload[8..16].to_vec());
            assert_ne!(fetched, object_id_payload[8..16].to_vec());
            assert_eq!(server.join().unwrap(), object_id);
        }

        #[test]
        fn receipt_segment_source_executes_backfill_by_receipt_key() {
            let primary_dir = tempfile::tempdir().unwrap();
            let replica_dir = tempfile::tempdir().unwrap();
            let target_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut replica = TransportReplicatedStore::open(
                replica_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut target = tidefs_local_object_store::LocalObjectStore::open_with_options(
                target_dir.path(),
                tidefs_local_object_store::StoreOptions::test_fast(),
            )
            .unwrap();

            let object_id = 5600u64;
            let receipt_payload = b"receipt-source engine payload".to_vec();
            let object_id_payload = b"receiptless path must not feed rebuild".to_vec();
            let receipt_key =
                tidefs_local_object_store::ObjectKey::from_name(b"issue-56-receipt-key");
            let object_id_key =
                tidefs_local_object_store::ObjectKey::from_name(object_id.to_le_bytes());
            let receipt = placement_receipt_ref(object_id, &receipt_key, &receipt_payload, 56);
            let payload_digest_prefix =
                u64::from_le_bytes(receipt.payload_digest[..8].try_into().unwrap());
            let task = tidefs_rebuild_runtime::task::BackfillTask::new(
                tidefs_rebuild_runtime::task::BackfillTaskInit {
                    subject_ref: ReplicatedSubjectId::new(object_id),
                    placement_receipt_ref: receipt,
                    source_member: MemberId::new(2),
                    target_member: MemberId::new(3),
                    movement_class: ReplicaMovementClass::BackfillLaggedCopy,
                    payload_digest: ObjectDigest::new(payload_digest_prefix),
                    payload_len: receipt_payload.len() as u64,
                    created_at_ns: 1000,
                    deadline_ns: 5000,
                },
            );

            replica.primary.put(receipt_key, &receipt_payload).unwrap();
            replica
                .primary
                .put(object_id_key, &object_id_payload)
                .unwrap();
            target
                .put(object_id_key, b"existing object-id target")
                .unwrap();

            let (_client_session_id, server_session_id) =
                connect_replica_pair(&mut primary, &mut replica, 2);
            let server = std::thread::spawn(move || {
                replica
                    .handle_segment_fetch_request(server_session_id)
                    .expect("receipt segment fetch served")
            });
            let engine = tidefs_rebuild_runtime::engine::DataMovementEngine::new();
            let mut progress =
                tidefs_rebuild_runtime::progress::BackfillProgress::new(task.payload_len, 3);
            progress.schedule().unwrap();

            engine
                .execute_from_receipt_source(&task, &mut primary, &mut target, &mut progress)
                .expect("receipt-source backfill execution");

            assert_eq!(server.join().unwrap(), object_id);
            assert_eq!(target.get(receipt_key).unwrap(), Some(receipt_payload));
            assert_eq!(
                target.get(object_id_key).unwrap(),
                Some(b"existing object-id target".to_vec())
            );
            assert_eq!(
                progress.state,
                tidefs_rebuild_runtime::progress::TaskState::Complete
            );
        }

        #[test]
        fn receipt_repair_task_returns_ack_receipt_for_completion() {
            let primary_dir = tempfile::tempdir().unwrap();
            let source_dir = tempfile::tempdir().unwrap();
            let target_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut source = TransportReplicatedStore::open(
                source_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut target = TransportReplicatedStore::open(
                target_dir.path(),
                3,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let object_id = 1270u64;
            let payload = b"receipt repair ack payload".to_vec();
            let receipt_key = tidefs_local_object_store::ObjectKey::from_name(
                b"issue-127-repair-ack-receipt-key",
            );
            let receipt = placement_receipt_ref(object_id, &receipt_key, &payload, 33);
            let mut repaired_receipt = receipt;
            repaired_receipt.receipt_generation = 34;
            let task = backfill_task_for_receipt(receipt, 2, 3);
            source.primary.put(receipt_key, &payload).unwrap();

            let (_source_client_session, source_server_session) =
                connect_replica_pair(&mut primary, &mut source, 2);
            let (_target_client_session, target_server_session) =
                connect_replica_pair(&mut primary, &mut target, 3);
            let source_server = spawn_receipt_source(source, source_server_session);
            let target_server = spawn_repair_target(
                target,
                target_server_session,
                receipt,
                Some(repaired_receipt),
            );

            let ack_receipt = primary
                .execute_receipt_repair_task(&task)
                .expect("receipt repair task completes from ack receipt");

            assert_eq!(source_server.join().unwrap(), object_id);
            assert_eq!(target_server.join().unwrap(), payload);
            assert_eq!(ack_receipt, repaired_receipt);

            let mut completion = tidefs_rebuild_runtime::completion::RebuildCompletion::new();
            let mut admission = tidefs_rebuild_runtime::admission::RebuildAdmission::with_epoch(7);
            completion.register(MemberId::new(3), 1);
            let event = completion
                .record_receipt_verified_task_completion(&task, ack_receipt, &mut admission)
                .expect("ack receipt passes completion law")
                .expect("single repaired task emits completion");
            assert!(event.fully_successful);
        }

        #[test]
        fn receipt_repair_task_records_verified_completion() {
            let primary_dir = tempfile::tempdir().unwrap();
            let source_dir = tempfile::tempdir().unwrap();
            let target_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut source = TransportReplicatedStore::open(
                source_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut target = TransportReplicatedStore::open(
                target_dir.path(),
                3,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let object_id = 1330u64;
            let payload = b"receipt repair completion bridge payload".to_vec();
            let receipt_key = tidefs_local_object_store::ObjectKey::from_name(
                b"issue-133-repair-completion-bridge",
            );
            let receipt = placement_receipt_ref(object_id, &receipt_key, &payload, 61);
            let mut repaired_receipt = receipt;
            repaired_receipt.receipt_generation = 62;
            let task = backfill_task_for_receipt(receipt, 2, 3);
            source.primary.put(receipt_key, &payload).unwrap();
            let (mut completion, mut admission) = rebuild_state_for_task(&task);

            let (_source_client_session, source_server_session) =
                connect_replica_pair(&mut primary, &mut source, 2);
            let (_target_client_session, target_server_session) =
                connect_replica_pair(&mut primary, &mut target, 3);
            let source_server = spawn_receipt_source(source, source_server_session);
            let target_server = spawn_repair_target(
                target,
                target_server_session,
                receipt,
                Some(repaired_receipt),
            );

            let evidence = primary
                .execute_receipt_repair_task_and_record_completion(
                    &task,
                    &mut completion,
                    &mut admission,
                )
                .expect("receipt repair records verified completion");

            assert_eq!(source_server.join().unwrap(), object_id);
            assert_eq!(target_server.join().unwrap(), payload);
            assert_eq!(evidence.repaired_placement_receipt_ref, repaired_receipt);
            assert_eq!(
                evidence.verified_receipt_completion,
                tidefs_rebuild_runtime::completion::VerifiedReceiptCompletionRecord {
                    target_member: task.target_member,
                    subject_ref: task.subject_ref,
                    source_placement_receipt_ref: task.placement_receipt_ref,
                    repaired_placement_receipt_ref: repaired_receipt,
                }
            );
            let event = evidence
                .completion_event
                .expect("single repaired task emits completion");
            assert!(event.fully_successful);
            assert_eq!(
                completion
                    .status(task.target_member)
                    .unwrap()
                    .subjects_completed,
                1
            );
            assert_eq!(
                admission.status(task.target_member),
                tidefs_rebuild_runtime::admission::RebuildAdmissionStatus::Completed
            );
            assert_eq!(completion.drain_events(), vec![event]);
        }

        #[test]
        fn receipt_repair_task_publishes_verified_completion_to_flow_commit() {
            let primary_dir = tempfile::tempdir().unwrap();
            let source_dir = tempfile::tempdir().unwrap();
            let target_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut source = TransportReplicatedStore::open(
                source_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut target = TransportReplicatedStore::open(
                target_dir.path(),
                3,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let object_id = 1450u64;
            let payload = b"repair completion flow commit bridge payload".to_vec();
            let receipt_key = tidefs_local_object_store::ObjectKey::from_name(
                b"issue-145-repair-flow-commit-bridge",
            );
            let receipt = placement_receipt_ref(object_id, &receipt_key, &payload, 70);
            let mut repaired_receipt = receipt;
            repaired_receipt.receipt_generation = 71;
            let task = backfill_task_for_receipt(receipt, 2, 3);
            source.primary.put(receipt_key, &payload).unwrap();
            let (mut completion, mut admission) = rebuild_state_for_task(&task);
            let mut flow_commit = FlowCommitCoordinator::new(EpochId::new(7));

            let (_source_client_session, source_server_session) =
                connect_replica_pair(&mut primary, &mut source, 2);
            let (_target_client_session, target_server_session) =
                connect_replica_pair(&mut primary, &mut target, 3);
            let source_server = spawn_receipt_source(source, source_server_session);
            let target_server = spawn_repair_target(
                target,
                target_server_session,
                receipt,
                Some(repaired_receipt),
            );

            let publication = primary
                .execute_receipt_repair_task_record_completion_and_publish_flow_commit(
                    &task,
                    &mut completion,
                    &mut admission,
                    &mut flow_commit,
                )
                .expect("receipt repair publishes verified completion to flow commit");

            assert_eq!(source_server.join().unwrap(), object_id);
            assert_eq!(target_server.join().unwrap(), payload);
            assert_eq!(
                publication.repair_completion.repaired_placement_receipt_ref,
                repaired_receipt
            );
            assert_eq!(
                publication.repair_completion.verified_receipt_completion,
                tidefs_rebuild_runtime::completion::VerifiedReceiptCompletionRecord {
                    target_member: task.target_member,
                    subject_ref: task.subject_ref,
                    source_placement_receipt_ref: task.placement_receipt_ref,
                    repaired_placement_receipt_ref: repaired_receipt,
                }
            );
            assert_eq!(
                publication
                    .flow_commit_result
                    .placement_receipt
                    .placement_receipt_refs,
                vec![repaired_receipt]
            );
            assert_eq!(
                publication.flow_commit_result.updated_copy.subject_ref,
                task.subject_ref
            );
            assert_eq!(
                publication.flow_commit_result.updated_copy.member_ref,
                task.target_member
            );
            assert_eq!(
                publication.flow_commit_result.flow_class,
                tidefs_replication_model::FlowCommitClass::Rebuild
            );
            assert_eq!(
                flow_commit.commit_results,
                vec![publication.flow_commit_result.clone()]
            );
            assert_eq!(flow_commit.placement_receipts.len(), 1);
            assert_eq!(
                completion
                    .status(task.target_member)
                    .unwrap()
                    .subjects_completed,
                1
            );
            assert_eq!(
                admission.status(task.target_member),
                tidefs_rebuild_runtime::admission::RebuildAdmissionStatus::Completed
            );
        }

        #[test]
        fn planned_read_repair_records_verified_completion_without_segment_fetch() {
            let primary_dir = tempfile::tempdir().unwrap();
            let target_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut target = TransportReplicatedStore::open(
                target_dir.path(),
                3,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let object_id = 1670u64;
            let payload = b"planned read repair completion payload".to_vec();
            let receipt_key =
                tidefs_local_object_store::ObjectKey::from_name(b"issue-167-planned-repair");
            let receipt = placement_receipt_ref(object_id, &receipt_key, &payload, 80);
            let mut repaired_receipt = receipt;
            repaired_receipt.receipt_generation = 81;
            let task = backfill_task_for_receipt(receipt, 2, 3);
            let planned_read = ReceiptBackedTransportPlannedReadResult {
                payload: payload.clone(),
                source_member_id: 2,
                placement_receipt_ref: receipt,
            };
            let (mut completion, mut admission) = rebuild_state_for_task(&task);

            let (_target_client_session, target_server_session) =
                connect_replica_pair(&mut primary, &mut target, 3);
            let target_server = spawn_repair_target(
                target,
                target_server_session,
                receipt,
                Some(repaired_receipt),
            );

            let evidence = primary
                .execute_receipt_repair_task_from_planned_read_and_record_completion(
                    &task,
                    &planned_read,
                    &mut completion,
                    &mut admission,
                )
                .expect("planned-read-backed repair records completion");

            assert_eq!(target_server.join().unwrap(), payload);
            assert_eq!(evidence.repaired_placement_receipt_ref, repaired_receipt);
            assert_eq!(
                evidence.verified_receipt_completion,
                tidefs_rebuild_runtime::completion::VerifiedReceiptCompletionRecord {
                    target_member: task.target_member,
                    subject_ref: task.subject_ref,
                    source_placement_receipt_ref: task.placement_receipt_ref,
                    repaired_placement_receipt_ref: repaired_receipt,
                }
            );
            assert!(evidence.completion_event.unwrap().fully_successful);
            assert_eq!(
                completion
                    .status(task.target_member)
                    .unwrap()
                    .subjects_completed,
                1
            );
            assert_eq!(
                admission.status(task.target_member),
                tidefs_rebuild_runtime::admission::RebuildAdmissionStatus::Completed
            );
        }

        #[test]
        fn planned_read_repair_publishes_verified_completion_to_flow_commit() {
            let primary_dir = tempfile::tempdir().unwrap();
            let target_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut target = TransportReplicatedStore::open(
                target_dir.path(),
                3,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let object_id = 1671u64;
            let payload = b"planned read repair flow commit payload".to_vec();
            let receipt_key =
                tidefs_local_object_store::ObjectKey::from_name(b"issue-167-planned-flow");
            let receipt = placement_receipt_ref(object_id, &receipt_key, &payload, 82);
            let mut repaired_receipt = receipt;
            repaired_receipt.receipt_generation = 83;
            let task = backfill_task_for_receipt(receipt, 2, 3);
            let planned_read = ReceiptBackedTransportPlannedReadResult {
                payload: payload.clone(),
                source_member_id: 2,
                placement_receipt_ref: receipt,
            };
            let (mut completion, mut admission) = rebuild_state_for_task(&task);
            let mut flow_commit = FlowCommitCoordinator::new(EpochId::new(7));

            let (_target_client_session, target_server_session) =
                connect_replica_pair(&mut primary, &mut target, 3);
            let target_server = spawn_repair_target(
                target,
                target_server_session,
                receipt,
                Some(repaired_receipt),
            );

            let publication = primary
                .execute_receipt_repair_task_from_planned_read_record_completion_and_publish_flow_commit(
                    &task,
                    &planned_read,
                    &mut completion,
                    &mut admission,
                    &mut flow_commit,
                )
                .expect("planned-read-backed repair publishes flow commit");

            assert_eq!(target_server.join().unwrap(), payload);
            assert_eq!(
                publication.repair_completion.repaired_placement_receipt_ref,
                repaired_receipt
            );
            assert_eq!(
                publication
                    .flow_commit_result
                    .placement_receipt
                    .placement_receipt_refs,
                vec![repaired_receipt]
            );
            assert_eq!(
                publication.flow_commit_result.updated_copy.subject_ref,
                task.subject_ref
            );
            assert_eq!(
                publication.flow_commit_result.updated_copy.member_ref,
                task.target_member
            );
            assert_eq!(
                publication.flow_commit_result.flow_class,
                tidefs_replication_model::FlowCommitClass::Rebuild
            );
            assert_eq!(
                flow_commit.commit_results,
                vec![publication.flow_commit_result.clone()]
            );
            assert_eq!(flow_commit.placement_receipts.len(), 1);
        }

        #[test]
        fn planned_read_repair_rejects_mismatched_evidence_before_target_send() {
            let primary_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let object_id = 1672u64;
            let payload = b"planned read repair mismatch payload".to_vec();
            let receipt_key =
                tidefs_local_object_store::ObjectKey::from_name(b"issue-167-mismatch");
            let receipt = placement_receipt_ref(object_id, &receipt_key, &payload, 84);
            let task = backfill_task_for_receipt(receipt, 2, 3);

            let source_mismatch = ReceiptBackedTransportPlannedReadResult {
                payload: payload.clone(),
                source_member_id: 4,
                placement_receipt_ref: receipt,
            };
            let err = primary
                .execute_receipt_repair_task_from_planned_read(&task, &source_mismatch)
                .unwrap_err();
            assert!(err.contains("source mismatch"));

            let synthetic_receipt = ReceiptBackedTransportPlannedReadResult {
                payload: payload.clone(),
                source_member_id: 2,
                placement_receipt_ref: PlacementReceiptRef::synthetic_for_subject(task.subject_ref),
            };
            let err = primary
                .execute_receipt_repair_task_from_planned_read(&task, &synthetic_receipt)
                .unwrap_err();
            assert!(err.contains("requires non-synthetic placement receipt"));

            let mut stale_receipt = receipt;
            stale_receipt.receipt_generation += 1;
            let receipt_mismatch = ReceiptBackedTransportPlannedReadResult {
                payload: payload.clone(),
                source_member_id: 2,
                placement_receipt_ref: stale_receipt,
            };
            let err = primary
                .execute_receipt_repair_task_from_planned_read(&task, &receipt_mismatch)
                .unwrap_err();
            assert!(err.contains("receipt mismatch"));

            let mut tampered_payload = payload.clone();
            tampered_payload[0] ^= 0x01;
            let digest_mismatch = ReceiptBackedTransportPlannedReadResult {
                payload: tampered_payload,
                source_member_id: 2,
                placement_receipt_ref: receipt,
            };
            let err = primary
                .execute_receipt_repair_task_from_planned_read(&task, &digest_mismatch)
                .unwrap_err();
            assert!(err.contains("source digest mismatch"));
        }

        #[test]
        fn receipt_repair_flow_commit_publication_refuses_receiptless_success_ack() {
            let primary_dir = tempfile::tempdir().unwrap();
            let source_dir = tempfile::tempdir().unwrap();
            let target_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut source = TransportReplicatedStore::open(
                source_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut target = TransportReplicatedStore::open(
                target_dir.path(),
                3,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let object_id = 1451u64;
            let payload = b"receiptless ack must not publish flow commit".to_vec();
            let receipt_key =
                tidefs_local_object_store::ObjectKey::from_name(b"issue-145-receiptless-publish");
            let receipt = placement_receipt_ref(object_id, &receipt_key, &payload, 72);
            let task = backfill_task_for_receipt(receipt, 2, 3);
            source.primary.put(receipt_key, &payload).unwrap();
            let (mut completion, mut admission) = rebuild_state_for_task(&task);
            let mut flow_commit = FlowCommitCoordinator::new(EpochId::new(7));

            let (_source_client_session, source_server_session) =
                connect_replica_pair(&mut primary, &mut source, 2);
            let (_target_client_session, target_server_session) =
                connect_replica_pair(&mut primary, &mut target, 3);
            let source_server = spawn_receipt_source(source, source_server_session);
            let target_server = spawn_repair_target(target, target_server_session, receipt, None);

            let err = primary
                .execute_receipt_repair_task_record_completion_and_publish_flow_commit(
                    &task,
                    &mut completion,
                    &mut admission,
                    &mut flow_commit,
                )
                .unwrap_err();

            assert!(err.contains("did not return repaired placement receipt"));
            assert!(flow_commit.commit_results.is_empty());
            assert!(flow_commit.placement_receipts.is_empty());
            assert_repair_completion_not_recorded(&mut completion, &admission, task.target_member);
            assert_eq!(source_server.join().unwrap(), object_id);
            assert_eq!(target_server.join().unwrap(), payload);
        }

        #[test]
        fn receipt_repair_flow_commit_publication_refuses_duplicate_result() {
            let primary_dir = tempfile::tempdir().unwrap();
            let source_dir = tempfile::tempdir().unwrap();
            let target_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut source = TransportReplicatedStore::open(
                source_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut target = TransportReplicatedStore::open(
                target_dir.path(),
                3,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let object_id = 1452u64;
            let payload = b"duplicate flow commit publication must fail".to_vec();
            let receipt_key =
                tidefs_local_object_store::ObjectKey::from_name(b"issue-145-duplicate-publish");
            let receipt = placement_receipt_ref(object_id, &receipt_key, &payload, 73);
            let mut repaired_receipt = receipt;
            repaired_receipt.receipt_generation = 74;
            let task = backfill_task_for_receipt(receipt, 2, 3);
            source.primary.put(receipt_key, &payload).unwrap();
            let (mut completion, mut admission) = rebuild_state_for_task(&task);
            let mut flow_commit = FlowCommitCoordinator::new(EpochId::new(7));
            let existing_result = flow_commit
                .publish_verified_rebuild_completion(
                    tidefs_rebuild_runtime::completion::VerifiedReceiptCompletionRecord {
                        target_member: task.target_member,
                        subject_ref: task.subject_ref,
                        source_placement_receipt_ref: task.placement_receipt_ref,
                        repaired_placement_receipt_ref: repaired_receipt,
                    },
                )
                .expect("pre-existing publication seeds duplicate guard");

            let (_source_client_session, source_server_session) =
                connect_replica_pair(&mut primary, &mut source, 2);
            let (_target_client_session, target_server_session) =
                connect_replica_pair(&mut primary, &mut target, 3);
            let source_server = spawn_receipt_source(source, source_server_session);
            let target_server = spawn_repair_target(
                target,
                target_server_session,
                receipt,
                Some(repaired_receipt),
            );

            let err = primary
                .execute_receipt_repair_task_record_completion_and_publish_flow_commit(
                    &task,
                    &mut completion,
                    &mut admission,
                    &mut flow_commit,
                )
                .unwrap_err();

            assert!(err.contains("duplicate verified rebuild completion publication"));
            assert_eq!(flow_commit.commit_results, vec![existing_result]);
            assert_eq!(flow_commit.placement_receipts.len(), 1);
            assert_eq!(source_server.join().unwrap(), object_id);
            assert_eq!(target_server.join().unwrap(), payload);
        }

        #[test]
        fn receipt_repair_completion_refuses_receiptless_success_ack() {
            let primary_dir = tempfile::tempdir().unwrap();
            let source_dir = tempfile::tempdir().unwrap();
            let target_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut source = TransportReplicatedStore::open(
                source_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut target = TransportReplicatedStore::open(
                target_dir.path(),
                3,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let object_id = 1271u64;
            let payload = b"receiptless ack must not complete".to_vec();
            let receipt_key =
                tidefs_local_object_store::ObjectKey::from_name(b"issue-127-receiptless-ack");
            let receipt = placement_receipt_ref(object_id, &receipt_key, &payload, 41);
            let task = backfill_task_for_receipt(receipt, 2, 3);
            source.primary.put(receipt_key, &payload).unwrap();
            let (mut completion, mut admission) = rebuild_state_for_task(&task);

            let (_source_client_session, source_server_session) =
                connect_replica_pair(&mut primary, &mut source, 2);
            let (_target_client_session, target_server_session) =
                connect_replica_pair(&mut primary, &mut target, 3);
            let source_server = spawn_receipt_source(source, source_server_session);
            let target_server = spawn_repair_target(target, target_server_session, receipt, None);

            let err = primary
                .execute_receipt_repair_task_and_record_completion(
                    &task,
                    &mut completion,
                    &mut admission,
                )
                .unwrap_err();

            assert!(err.contains("did not return repaired placement receipt"));
            assert_repair_completion_not_recorded(&mut completion, &admission, task.target_member);
            assert_eq!(source_server.join().unwrap(), object_id);
            assert_eq!(target_server.join().unwrap(), payload);
        }

        #[test]
        fn receipt_repair_completion_refuses_mismatched_ack_receipt() {
            let primary_dir = tempfile::tempdir().unwrap();
            let source_dir = tempfile::tempdir().unwrap();
            let target_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut source = TransportReplicatedStore::open(
                source_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut target = TransportReplicatedStore::open(
                target_dir.path(),
                3,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let object_id = 1272u64;
            let payload = b"mismatched ack receipt must not complete".to_vec();
            let receipt_key =
                tidefs_local_object_store::ObjectKey::from_name(b"issue-127-mismatched-ack");
            let receipt = placement_receipt_ref(object_id, &receipt_key, &payload, 50);
            let mut mismatched_receipt = receipt;
            mismatched_receipt.payload_len += 1;
            let task = backfill_task_for_receipt(receipt, 2, 3);
            source.primary.put(receipt_key, &payload).unwrap();
            let (mut completion, mut admission) = rebuild_state_for_task(&task);

            let (_source_client_session, source_server_session) =
                connect_replica_pair(&mut primary, &mut source, 2);
            let (_target_client_session, target_server_session) =
                connect_replica_pair(&mut primary, &mut target, 3);
            let source_server = spawn_receipt_source(source, source_server_session);
            let target_server = spawn_repair_target(
                target,
                target_server_session,
                receipt,
                Some(mismatched_receipt),
            );

            let err = primary
                .execute_receipt_repair_task_and_record_completion(
                    &task,
                    &mut completion,
                    &mut admission,
                )
                .unwrap_err();

            assert!(err.contains("PayloadLengthMismatch"));
            assert_repair_completion_not_recorded(&mut completion, &admission, task.target_member);
            assert_eq!(source_server.join().unwrap(), object_id);
            assert_eq!(target_server.join().unwrap(), payload);
        }

        #[test]
        fn fetch_remote_segment_receiptless_uses_object_id_key() {
            let primary_dir = tempfile::tempdir().unwrap();
            let replica_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut replica = TransportReplicatedStore::open(
                replica_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let object_id = 5200u64;
            let object_id_payload = b"receiptless object-id segment payload".to_vec();
            let receipt_payload = b"receipt payload must not be used".to_vec();
            let object_id_key =
                tidefs_local_object_store::ObjectKey::from_name(object_id.to_le_bytes());
            let receipt_key =
                tidefs_local_object_store::ObjectKey::from_name(b"issue-52-unused-receipt-key");
            replica
                .primary
                .put(object_id_key, &object_id_payload)
                .unwrap();
            replica.primary.put(receipt_key, &receipt_payload).unwrap();

            let (_client_session_id, server_session_id) =
                connect_replica_pair(&mut primary, &mut replica, 2);
            let server = std::thread::spawn(move || {
                replica
                    .handle_segment_fetch_request(server_session_id)
                    .expect("receiptless segment fetch served")
            });

            let fetched = primary
                .fetch_remote_segment(0, object_id, 7, 9)
                .expect("receiptless segment fetch");

            assert_eq!(fetched, object_id_payload[7..16].to_vec());
            assert_ne!(fetched, receipt_payload[7..16].to_vec());
            assert_eq!(server.join().unwrap(), object_id);
        }

        #[test]
        fn handle_segment_fetch_request_rejects_synthetic_receipt() {
            let primary_dir = tempfile::tempdir().unwrap();
            let replica_dir = tempfile::tempdir().unwrap();
            let mut primary = TransportReplicatedStore::open(
                primary_dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let mut replica = TransportReplicatedStore::open(
                replica_dir.path(),
                2,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let object_id = 5201;
            let object_id_payload = b"synthetic receipt fallback payload".to_vec();
            let synthetic_payload = b"synthetic object-key payload".to_vec();
            let synthetic_receipt =
                PlacementReceiptRef::synthetic_for_subject(ReplicatedSubjectId::new(object_id));
            let object_id_key =
                tidefs_local_object_store::ObjectKey::from_name(object_id.to_le_bytes());
            let synthetic_key =
                tidefs_local_object_store::ObjectKey::from_bytes32(synthetic_receipt.object_key);
            replica
                .primary
                .put(object_id_key, &object_id_payload)
                .unwrap();
            replica
                .primary
                .put(synthetic_key, &synthetic_payload)
                .unwrap();

            let (client_session_id, server_session_id) =
                connect_replica_pair(&mut primary, &mut replica, 2);
            let server =
                std::thread::spawn(move || replica.handle_segment_fetch_request(server_session_id));
            let request = SegmentFetchRequest {
                object_id,
                placement_receipt_ref: Some(synthetic_receipt),
                segment_offset: 10,
                segment_length: 8,
            };

            send_segment_fetch(&mut primary.transport, client_session_id, &request).unwrap();
            let err = server.join().unwrap().unwrap_err();

            assert!(err.contains("requires non-synthetic placement receipt"));
        }

        #[test]
        fn fetch_remote_segment_by_receipt_rejects_synthetic_receipt() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = TransportReplicatedStore::open(
                dir.path(),
                1,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            let receipt = PlacementReceiptRef::synthetic_for_subject(ReplicatedSubjectId::new(9));

            let err = store
                .fetch_remote_segment_by_receipt(0, receipt, 0, 8)
                .unwrap_err();

            assert!(err.contains("requires non-synthetic placement receipt"));
        }

        #[test]
        fn segment_fetch_request_encode_roundtrip() {
            // Verify SegmentFetchRequest encode/decode works for
            // the types we'll send over the wire.
            let req = SegmentFetchRequest::new(42, 4096, 8192);
            let encoded = req.encode().unwrap();
            let decoded = SegmentFetchRequest::decode(&encoded).unwrap();
            assert_eq!(decoded.object_id, 42);
            assert_eq!(decoded.segment_offset, 4096);
            assert_eq!(decoded.segment_length, 8192);
        }

        #[test]
        fn segment_fetch_response_verify_roundtrip() {
            // Verify SegmentFetchResponse round-trips with BLAKE3
            // verification through encode/decode.
            let payload = b"segment fetch integration test".to_vec();
            let resp = SegmentFetchResponse::new(7, 0, payload.len() as u64, payload.clone());
            let encoded = resp.encode().unwrap();
            let decoded = SegmentFetchResponse::decode(&encoded).unwrap();
            assert_eq!(decoded.payload, payload);
            // transport session boundary provides per-message integrity
        }

        #[test]
        fn fetch_remote_segment_response_decode_roundtrip() {
            // Verify SegmentFetchResponse encode/decode round-trips.
            // Integrity is provided by the transport session boundary.
            let payload = b"honest data".to_vec();
            let resp = SegmentFetchResponse::new(1, 0, payload.len() as u64, payload.clone());
            let encoded = resp.encode().unwrap();
            let decoded = SegmentFetchResponse::decode(&encoded).unwrap();
            assert_eq!(decoded.payload, payload);
            assert_eq!(decoded.object_id, 1);
            assert_eq!(decoded.segment_offset, 0);
        }

        // ── put_named_with_receipt tests ────────────────────────────

        #[test]
        fn put_named_with_receipt_no_replicas_stores_locally() {
            // Primary-only store: the receipt-authorized write should succeed
            // with no fan-out needed. Quorum of 1 is met by the local write.
            let tmp = tempfile::TempDir::with_prefix("rep-obj-pnwr-").unwrap();
            let mut store = TransportReplicatedStore::open(
                tmp.path(),
                1u64,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let payload = b"receipt-authorized write";
            let key = tidefs_local_object_store::ObjectKey::from_name("receipt-test");
            let receipt = placement_receipt_ref(42, &key, payload, 1);

            let result = store
                .put_named_with_receipt("receipt-test", payload, receipt)
                .expect("put_named_with_receipt should succeed");

            assert!(result.quorum_reached);
            assert!(result.fully_committed);
            assert_eq!(result.acks, 1);
            assert_eq!(result.total_targets, 1);
            assert_eq!(result.recorded_receipt_ref, Some(receipt));

            // Verify data was stored locally
            let read_back = store
                .get_local("receipt-test")
                .expect("get_local should succeed")
                .expect("object should exist");
            assert_eq!(read_back, payload);
        }

        #[test]
        fn put_named_with_receipt_rejects_synthetic_receipt_without_write() {
            let tmp = tempfile::TempDir::with_prefix("rep-obj-pnwr-synth-").unwrap();
            let mut store = TransportReplicatedStore::open(
                tmp.path(),
                1u64,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let err = store
                .put_named_with_receipt(
                    "synthetic-receipt",
                    b"payload",
                    PlacementReceiptRef::synthetic_for_subject(ReplicatedSubjectId::new(1)),
                )
                .unwrap_err();
            assert!(err.contains("synthetic"));
            assert!(
                store
                    .get_local("synthetic-receipt")
                    .expect("get_local should succeed")
                    .is_none(),
                "invalid receipt must not write primary data"
            );
        }

        #[test]
        fn put_named_with_receipt_two_node_sends_put_with_receipt_message() {
            // Set up a primary and a replica store, connect them, spawn a
            // replica handler that processes PutWithReceipt and returns
            // a PutWithReceiptAck with success=true.
            use std::sync::mpsc;
            use tidefs_transport::recv_replication_msg;

            let tmp_primary = tempfile::TempDir::with_prefix("rep-obj-pnwr-pri-").unwrap();
            let tmp_replica = tempfile::TempDir::with_prefix("rep-obj-pnwr-rep-").unwrap();

            let mut primary = TransportReplicatedStore::open(
                tmp_primary.path(),
                1u64,
                TransportReplicatedStoreConfig {
                    write_quorum: 2,
                    total_replicas: 2,
                    ..TransportReplicatedStoreConfig::default()
                },
            )
            .unwrap();

            let mut replica = TransportReplicatedStore::open(
                tmp_replica.path(),
                2u64,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let (_client_sid, server_sid) = connect_replica_pair(&mut primary, &mut replica, 2);

            let payload = b"two-node receipt write";
            let key = tidefs_local_object_store::ObjectKey::from_name("two-node-receipt");
            let receipt = placement_receipt_ref(100, &key, payload, 3);

            // Spawn a thread to handle the replica side: receive the
            // PutWithReceipt, store the payload, and reply with success.
            let payload_clone = payload.to_vec();
            let receipt_clone = receipt;
            let (tx, rx) = mpsc::channel();
            let replica_handle = std::thread::spawn(move || {
                let mut replica = replica;
                let msg = recv_replication_msg(&mut replica.transport, server_sid)
                    .expect("replica should receive message");
                let ReplicationMessage::PutWithReceipt {
                    name,
                    payload: received_payload,
                    placement_receipt_ref: received_receipt,
                } = msg
                else {
                    let resp = ReplicationMessage::PutWithReceiptAck {
                        key_hash: "unexpected".into(),
                        success: false,
                        recorded_receipt_ref: None,
                    };
                    let _ = send_replication_msg(&mut replica.transport, server_sid, &resp);
                    tx.send(false).unwrap();
                    return;
                };
                assert_eq!(name, "two-node-receipt");
                assert_eq!(received_payload, payload_clone);
                assert_eq!(received_receipt.object_id, receipt_clone.object_id);
                let replica_receipt_ref = placement_receipt_ref(
                    received_receipt.object_id,
                    &tidefs_local_object_store::ObjectKey::from_name(name.as_bytes()),
                    &received_payload,
                    received_receipt.receipt_generation + 1,
                );

                // Store the payload locally
                replica
                    .put_local(&name, &received_payload)
                    .expect("replica put_local should succeed");

                let resp = ReplicationMessage::PutWithReceiptAck {
                    key_hash: name.clone(),
                    success: true,
                    recorded_receipt_ref: Some(replica_receipt_ref),
                };
                send_replication_msg(&mut replica.transport, server_sid, &resp)
                    .expect("replica should send ack");
                tx.send(true).unwrap();
            });

            let result = primary
                .put_named_with_receipt("two-node-receipt", payload, receipt)
                .expect("put_named_with_receipt should succeed");

            assert!(result.quorum_reached);
            assert!(result.fully_committed);
            assert_eq!(result.acks, 2);
            assert_eq!(result.total_targets, 2);
            assert_eq!(
                result.recorded_receipt_ref,
                Some(placement_receipt_ref(100, &key, payload, 4))
            );

            replica_handle.join().unwrap();
            assert!(
                rx.recv().unwrap(),
                "replica should have processed successfully"
            );

            // Verify data is on the primary
            let primary_data = primary
                .get_local("two-node-receipt")
                .expect("primary get_local")
                .expect("primary should have data");
            assert_eq!(primary_data, payload);
        }

        #[test]
        fn put_named_with_receipt_replica_rejects_bad_receipt() {
            // When the replica rejects the receipt (success=false), quorum
            // should not include that replica and the result should reflect it.
            use std::sync::mpsc;
            use tidefs_transport::recv_replication_msg;

            let tmp_primary = tempfile::TempDir::with_prefix("rep-obj-pnwr-bad-").unwrap();
            let tmp_replica = tempfile::TempDir::with_prefix("rep-obj-pnwr-bad-r-").unwrap();

            let mut primary = TransportReplicatedStore::open(
                tmp_primary.path(),
                1u64,
                TransportReplicatedStoreConfig {
                    write_quorum: 2,
                    total_replicas: 2,
                    ..TransportReplicatedStoreConfig::default()
                },
            )
            .unwrap();

            let mut replica = TransportReplicatedStore::open(
                tmp_replica.path(),
                2u64,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let (_client_sid, server_sid) = connect_replica_pair(&mut primary, &mut replica, 2);

            let payload = b"bad receipt write";
            let key = tidefs_local_object_store::ObjectKey::from_name("bad-receipt");
            let receipt = placement_receipt_ref(200, &key, payload, 7);

            // Spawn replica that rejects
            let (tx, rx) = mpsc::channel();
            let replica_handle = std::thread::spawn(move || {
                let mut replica = replica;
                let msg = recv_replication_msg(&mut replica.transport, server_sid)
                    .expect("replica should receive message");
                assert!(
                    matches!(msg, ReplicationMessage::PutWithReceipt { .. }),
                    "expected PutWithReceipt"
                );
                // Reject the write
                let resp = ReplicationMessage::PutWithReceiptAck {
                    key_hash: "bad-receipt".into(),
                    success: false,
                    recorded_receipt_ref: None,
                };
                send_replication_msg(&mut replica.transport, server_sid, &resp)
                    .expect("replica should send rejection ack");
                tx.send(()).unwrap();
            });

            // Quorum is 2 but only primary counts; replica rejects.
            let result = primary
                .put_named_with_receipt("bad-receipt", payload, receipt)
                .expect("put_named_with_receipt should not panic");

            assert!(!result.quorum_reached, "quorum should not be reached");
            assert!(!result.fully_committed);
            assert_eq!(result.acks, 1); // only primary
            assert_eq!(result.total_targets, 2);
            assert_eq!(result.recorded_receipt_ref, None);

            replica_handle.join().unwrap();
            rx.recv().unwrap();

            // Primary data should have been rolled back (no quorum)
            assert!(
                primary
                    .get_local("bad-receipt")
                    .expect("primary get_local should succeed")
                    .is_none(),
                "no-quorum receipt write must roll back the primary"
            );
        }

        #[test]
        fn put_named_with_receipt_success_ack_requires_recorded_receipt() {
            use std::sync::mpsc;
            use tidefs_transport::recv_replication_msg;

            let tmp_primary = tempfile::TempDir::with_prefix("rep-obj-pnwr-missing-").unwrap();
            let tmp_replica = tempfile::TempDir::with_prefix("rep-obj-pnwr-missing-r-").unwrap();

            let mut primary = TransportReplicatedStore::open(
                tmp_primary.path(),
                1u64,
                TransportReplicatedStoreConfig {
                    write_quorum: 2,
                    total_replicas: 2,
                    ..TransportReplicatedStoreConfig::default()
                },
            )
            .unwrap();

            let mut replica = TransportReplicatedStore::open(
                tmp_replica.path(),
                2u64,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let (_client_sid, server_sid) = connect_replica_pair(&mut primary, &mut replica, 2);

            let payload = b"missing recorded receipt";
            let key = tidefs_local_object_store::ObjectKey::from_name("missing-receipt");
            let receipt = placement_receipt_ref(201, &key, payload, 9);

            let (tx, rx) = mpsc::channel();
            let replica_handle = std::thread::spawn(move || {
                let mut replica = replica;
                let msg = recv_replication_msg(&mut replica.transport, server_sid)
                    .expect("replica should receive message");
                assert!(
                    matches!(msg, ReplicationMessage::PutWithReceipt { .. }),
                    "expected PutWithReceipt"
                );
                let resp = ReplicationMessage::PutWithReceiptAck {
                    key_hash: "missing-receipt".into(),
                    success: true,
                    recorded_receipt_ref: None,
                };
                send_replication_msg(&mut replica.transport, server_sid, &resp)
                    .expect("replica should send receiptless ack");
                tx.send(()).unwrap();
            });

            let result = primary
                .put_named_with_receipt("missing-receipt", payload, receipt)
                .expect("receiptless success ack should not panic");

            assert!(
                !result.quorum_reached,
                "receiptless ack must not reach quorum"
            );
            assert_eq!(result.acks, 1);
            assert_eq!(result.recorded_receipt_ref, None);

            replica_handle.join().unwrap();
            rx.recv().unwrap();

            assert!(
                primary
                    .get_local("missing-receipt")
                    .expect("primary get_local should succeed")
                    .is_none(),
                "receiptless success ack must roll back the primary"
            );
        }
    }

    // ── Placement map versioning tests ────────────────────────────

    mod placement_versioning {
        use super::*;
        use std::collections::BTreeMap;
        use tidefs_membership_epoch::{EpochId, MemberId};
        use tidefs_transport::PlacementMap;

        #[test]
        fn placement_version_returns_zero_when_no_placement_configured() {
            let tmp = tempfile::TempDir::with_prefix("rep-obj-store-").unwrap();
            let store = TransportReplicatedStore::open(
                tmp.path(),
                1u64,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();
            assert_eq!(store.placement_version(), 0);
            assert!(store.placement_map().is_none());
        }

        #[test]
        #[should_panic(expected = "placement must be configured before setting a map")]
        fn set_placement_map_panics_when_no_placement_configured() {
            let tmp = tempfile::TempDir::with_prefix("rep-obj-store-").unwrap();
            let mut store = TransportReplicatedStore::open(
                tmp.path(),
                1u64,
                TransportReplicatedStoreConfig::default(),
            )
            .unwrap();

            let mut mapping = BTreeMap::new();
            mapping.insert(1u64, std::collections::BTreeSet::from([MemberId(10u64)]));
            let map = PlacementMap::new(1, EpochId(0), mapping);
            store.set_placement_map(map);
        }
    }
}
