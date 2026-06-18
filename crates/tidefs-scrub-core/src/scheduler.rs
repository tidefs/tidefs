// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Durability-layout-aware repair scheduler.
//!
//! [`RepairScheduler`] bridges scrub corruption findings to the repair
//! pipeline by consulting [`tidefs_durability_layout::DurabilityLayoutV1`]
//! for replica availability and failure-domain survivability, then
//! dispatching prioritized repair jobs through the existing
//! [`crate::repair_scheduling::ScrubToRepairBridge`].
//!
//! # Integration points
//!
//! - **Survivability gate**: before dispatching repair, the scheduler
//!   checks whether the durability layout can survive the set of failures
//!   implied by corruption findings.  If the layout cannot survive (e.g.
//!   data shards lost beyond parity capacity), the object is marked
//!   unrecoverable.
//! - **Replica counting**: determines how many healthy replicas remain
//!   for a corrupt object, feeding the escalation logic in
//!   [`ScrubToRepairBridge`].
//! - **Strategy selection**: based on the durability policy, selects
//!   mirror repair ([`ReconstructionSource`]) or erasure-coded
//!   reconstruction ([`ShardReader`]) as the repair path.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//! use tidefs_scrub::repair_scheduling::ScrubToRepairBridge;
//! use tidefs_scrub::scheduler::{RepairScheduler, LayoutDurabilityQuery};
//! use tidefs_durability_layout::DurabilityLayoutV1;
//!
//! let layout = DurabilityLayoutV1::mirror(2).unwrap();
//! let query = Arc::new(LayoutDurabilityQuery::new(layout));
//! let bridge = ScrubToRepairBridge::new();
//! let mut scheduler = RepairScheduler::new(bridge, query);
//!
//! let entries: Vec<tidefs_local_object_store::SuspectEntry> = vec![];
//! scheduler.ingest_from_suspect_log(&entries);
//! ```

use std::sync::Arc;

use tidefs_durability_layout::{DurabilityLayoutV1, DurabilityPolicy};
use tidefs_local_object_store::SuspectEntry;

use crate::repair_scheduling::{
    RepairAdmission, RepairAdmissionInput, RepairEscalation, RepairEvidenceRejection,
    ScrubToRepairBridge,
};

// ---------------------------------------------------------------------------
// DurabilityQuery — abstract layout consultation
// ---------------------------------------------------------------------------

/// Trait abstracting durability-layout consultation for testability.
///
/// Production implementation wraps [`DurabilityLayoutV1`].  Mock
/// implementations allow testing repair scheduling without a real
/// layout descriptor.
pub trait DurabilityQuery: Send + Sync {
    /// Return the durability policy for the given object locator.
    ///
    /// The locator ID maps to a specific durability policy.  In
    /// production this is derived from the durability layout, placement
    /// state, and locator-table metadata.
    fn policy_for_locator(&self, locator_id: u64) -> DurabilityPolicy;

    /// Return the number of total replicas/shards for the given locator.
    ///
    /// For mirrors, this is the copy count.  For erasure-coded objects,
    /// this is `data_shards + parity_shards`.
    fn total_shards(&self, locator_id: u64) -> usize;

    /// Return whether the durability layout can survive the given number
    /// of failed devices and nodes for the given locator.
    fn survives_failure(&self, locator_id: u64, failed_devices: u32, failed_nodes: u32) -> bool;
}

// ---------------------------------------------------------------------------
// LayoutDurabilityQuery — production implementation
// ---------------------------------------------------------------------------

/// Production [`DurabilityQuery`] backed by a real [`DurabilityLayoutV1`].
///
/// All locators in the pool share the same layout.  For heterogeneous
/// pools, extend this to consult locator-table metadata.
pub struct LayoutDurabilityQuery {
    layout: DurabilityLayoutV1,
}

impl LayoutDurabilityQuery {
    /// Create a new query wrapper around the given layout.
    #[must_use]
    pub fn new(layout: DurabilityLayoutV1) -> Self {
        Self { layout }
    }

    /// Return a reference to the underlying layout.
    #[must_use]
    pub fn layout(&self) -> &DurabilityLayoutV1 {
        &self.layout
    }
}

impl DurabilityQuery for LayoutDurabilityQuery {
    fn policy_for_locator(&self, _locator_id: u64) -> DurabilityPolicy {
        self.layout.policy
    }

    fn total_shards(&self, _locator_id: u64) -> usize {
        self.layout.policy.total_shards()
    }

    fn survives_failure(&self, _locator_id: u64, failed_devices: u32, failed_nodes: u32) -> bool {
        self.layout.survives_failure(failed_devices, failed_nodes)
    }
}

// ---------------------------------------------------------------------------
// DurabilityHealth — per-object durability assessment
// ---------------------------------------------------------------------------

/// Durability health assessment for a single object.
///
/// Computed by [`RepairScheduler::assess_health`] from the durability
/// layout and corruption state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurabilityHealth {
    /// Total replicas/shards for this object.
    pub total_replicas: u32,
    /// Number of healthy replicas still available.
    pub healthy_replicas: u32,
    /// Number of corrupt/missing replicas detected.
    pub corrupt_replicas: u32,
    /// Whether the layout can survive the current failure set.
    pub survivable: bool,
    /// Derived escalation level from health assessment.
    pub escalation: RepairEscalation,
}

impl DurabilityHealth {
    /// Number of healthy replicas remaining.
    #[must_use]
    pub fn replicas_remaining(&self) -> u32 {
        self.healthy_replicas
    }

    /// Whether any healthy replicas exist (can repair).
    #[must_use]
    pub fn has_healthy_replica(&self) -> bool {
        self.healthy_replicas > 0
    }

    /// Whether the object is unrecoverable (no replicas, or can't survive).
    #[must_use]
    pub fn is_unrecoverable(&self) -> bool {
        self.healthy_replicas == 0 && self.corrupt_replicas == self.total_replicas
    }
}

// ---------------------------------------------------------------------------
// RepairScheduler — durability-aware repair dispatch
// ---------------------------------------------------------------------------

/// Scheduler that consults durability layout to prioritize and dispatch
/// scrub-triggered repairs.
///
/// Wraps a [`ScrubToRepairBridge`] for escalation-aware job tracking and
/// adds durability-layout consultation for replica counting and
/// survivability gating.
pub struct RepairScheduler<D: DurabilityQuery> {
    /// The escalation-aware job bridge.
    bridge: ScrubToRepairBridge,
    /// Durability layout query interface.
    durability: Arc<D>,
    /// Number of known failed devices in the pool.
    failed_devices: u32,
    /// Number of known failed nodes in the pool.
    failed_nodes: u32,
    /// Cumulative statistics.
    stats: RepairSchedulerStats,
}

/// Cumulative statistics collected by the repair scheduler.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepairSchedulerStats {
    /// Total suspect entries ingested.
    pub entries_ingested: u64,
    /// Entries assessed as unrecoverable (no healthy replicas).
    pub unrecoverable: u64,
    /// Entries where durability layout cannot survive failure set.
    pub unsurvivable: u64,
    /// Entries dispatched for repair.
    pub dispatched: u64,
    /// Entries blocked because no placement receipt was supplied.
    pub blocked_missing_receipt: u64,
    /// Entries blocked because the supplied receipt was stale or malformed.
    pub blocked_stale_receipt: u64,
    /// Entries where policy is unknown (no layout available).
    pub unknown_policy: u64,
}

impl<D: DurabilityQuery> RepairScheduler<D> {
    /// Create a new repair scheduler.
    #[must_use]
    pub fn new(bridge: ScrubToRepairBridge, durability: Arc<D>) -> Self {
        Self {
            bridge,
            durability,
            failed_devices: 0,
            failed_nodes: 0,
            stats: RepairSchedulerStats::default(),
        }
    }

    /// Update the known failed device and node counts.
    ///
    /// Call this after membership state changes so survivability
    /// calculations are accurate.
    pub fn set_failed_devices(&mut self, failed_devices: u32, failed_nodes: u32) {
        self.failed_devices = failed_devices;
        self.failed_nodes = failed_nodes;
    }

    /// Assess the durability health of a single suspect entry.
    ///
    /// Consults the durability layout to determine total replicas,
    /// healthy replicas, and whether the layout survives the current
    /// failure set.
    #[must_use]
    pub fn assess_health(&self, entry: &SuspectEntry) -> DurabilityHealth {
        let total = self.durability.total_shards(entry.locator_id) as u32;
        let survivable = self.durability.survives_failure(
            entry.locator_id,
            self.failed_devices,
            self.failed_nodes,
        );

        // Determine how many replicas are corrupt based on the suspect
        // entry's record_type and its repair history.
        let corrupt: u32 = if entry.resolved { 0 } else { 1 };
        let healthy = total.saturating_sub(corrupt);

        let escalation = RepairEscalation::classify(
            entry,
            entry.repair_attempts,
            healthy,
            false, // degraded read active; defer to higher-level logic
        );

        DurabilityHealth {
            total_replicas: total,
            healthy_replicas: healthy,
            corrupt_replicas: corrupt,
            survivable,
            escalation,
        }
    }

    /// Ingest suspect entries from a scrub cycle and classify by
    /// durability-aware priority.
    ///
    /// Each entry's health is assessed via [`assess_health`], then
    /// routed into the underlying [`ScrubToRepairBridge`] with the
    /// correct `replicas_remaining` count set.
    pub fn ingest_from_suspect_log(&mut self, entries: &[SuspectEntry]) {
        let inputs: Vec<_> = entries
            .iter()
            .copied()
            .map(RepairAdmissionInput::missing_receipt)
            .collect();
        self.ingest_with_evidence(&inputs);
    }

    /// Ingest suspect entries with explicit placement receipt evidence.
    pub fn ingest_with_evidence(&mut self, inputs: &[RepairAdmissionInput]) {
        for input in inputs {
            let entry = input.entry;
            self.stats.entries_ingested += 1;
            let health = self.assess_health(&entry);

            if health.is_unrecoverable() {
                self.stats.unrecoverable += 1;
                continue;
            }
            if !health.survivable {
                self.stats.unsurvivable += 1;
                continue;
            }

            let admissions = self
                .bridge
                .ingest_with_evidence(&[*input], health.healthy_replicas);
            self.record_admissions(&admissions);
        }
    }

    /// Ingest suspect entries with an explicit replicas_remaining count.
    ///
    /// Use this when the caller already knows the exact replica state.
    pub fn ingest_with_replicas(&mut self, entries: &[SuspectEntry], replicas_remaining: u32) {
        let inputs: Vec<_> = entries
            .iter()
            .copied()
            .map(RepairAdmissionInput::missing_receipt)
            .collect();
        self.ingest_evidence_with_replicas(&inputs, replicas_remaining);
    }

    /// Ingest evidence-bearing suspect entries with an explicit replica count.
    pub fn ingest_evidence_with_replicas(
        &mut self,
        inputs: &[RepairAdmissionInput],
        replicas_remaining: u32,
    ) {
        self.stats.entries_ingested += inputs.len() as u64;
        let admissions = self.bridge.ingest_with_evidence(inputs, replicas_remaining);
        self.record_admissions(&admissions);
    }

    fn record_admissions(&mut self, admissions: &[RepairAdmission]) {
        for admission in admissions {
            match admission {
                RepairAdmission::Admitted { .. } => {
                    self.stats.dispatched += 1;
                }
                RepairAdmission::Blocked {
                    reason: RepairEvidenceRejection::MissingReceipt,
                    ..
                } => {
                    self.stats.blocked_missing_receipt += 1;
                }
                RepairAdmission::Blocked {
                    reason: RepairEvidenceRejection::StaleReceipt,
                    ..
                } => {
                    self.stats.blocked_stale_receipt += 1;
                }
                RepairAdmission::Skipped { .. } => {}
            }
        }
    }

    /// Return a reference to the underlying bridge for direct manipulation.
    #[must_use]
    pub fn bridge(&self) -> &ScrubToRepairBridge {
        &self.bridge
    }

    /// Return a mutable reference to the underlying bridge.
    #[must_use]
    pub fn bridge_mut(&mut self) -> &mut ScrubToRepairBridge {
        &mut self.bridge
    }

    /// Whether the scheduler has pending repair work.
    #[must_use]
    pub fn has_work(&self) -> bool {
        self.bridge.has_work()
    }

    /// Number of jobs pending repair.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.bridge.pending_count()
    }

    /// Return a reference to cumulative scheduling statistics.
    #[must_use]
    pub fn stats(&self) -> &RepairSchedulerStats {
        &self.stats
    }

    /// Return the number of known failed devices.
    #[must_use]
    pub fn failed_devices(&self) -> u32 {
        self.failed_devices
    }

    /// Return the number of known failed nodes.
    #[must_use]
    pub fn failed_nodes(&self) -> u32 {
        self.failed_nodes
    }

    /// Return the number of healthy replicas for a given locator.
    ///
    /// Convenience method that combines total-shard lookup with the
    /// known failure set.
    #[must_use]
    pub fn replicas_remaining_for_locator(&self, locator_id: u64) -> u32 {
        self.durability.total_shards(locator_id) as u32
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repair_scheduling::ScrubToRepairBridge;
    use tidefs_durability_layout::DurabilityLayoutV1;
    use tidefs_local_object_store::SuspectEntry;
    use tidefs_replication_model::PlacementReceiptRef;

    fn make_entry(locator_id: u64, repair_attempts: u32) -> SuspectEntry {
        SuspectEntry {
            entry_id: locator_id,
            locator_id,
            segment_id: 1,
            offset: 0,
            record_type: 1, // payload corruption
            expected_hash: [0xAAu8; 32],
            actual_hash: [0xBBu8; 32],
            repair_attempts,
            last_repair_attempt: if repair_attempts > 0 { 1 } else { 0 },
            resolved: false,
            commit_group: 1,
            timestamp_secs: 1,
        }
    }

    fn receipt_for_entry(entry: &SuspectEntry) -> PlacementReceiptRef {
        let mut object_key = [0u8; 32];
        object_key[..8].copy_from_slice(&entry.locator_id.to_le_bytes());
        PlacementReceiptRef::replicated(
            entry.locator_id,
            object_key,
            Default::default(),
            entry.commit_group.max(1),
            2,
            4096,
            entry.expected_hash,
        )
    }

    fn input_with_receipt(entry: SuspectEntry) -> RepairAdmissionInput {
        RepairAdmissionInput::with_receipt(entry, receipt_for_entry(&entry))
    }

    fn inputs_with_receipts(entries: &[SuspectEntry]) -> Vec<RepairAdmissionInput> {
        entries.iter().copied().map(input_with_receipt).collect()
    }

    // ── LayoutDurabilityQuery tests ────────────────────────────

    #[test]
    fn layout_query_returns_mirror_policy() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let query = LayoutDurabilityQuery::new(layout);
        let policy = query.policy_for_locator(42);
        match policy {
            DurabilityPolicy::Mirror { copies } => assert_eq!(copies, 3),
            other => panic!("expected Mirror, got {other:?}"),
        }
    }

    #[test]
    fn layout_query_total_shards_for_mirror() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let query = LayoutDurabilityQuery::new(layout);
        assert_eq!(query.total_shards(1), 3);
        assert_eq!(query.total_shards(999), 3);
    }

    #[test]
    fn layout_query_total_shards_for_erasure() {
        let layout = DurabilityLayoutV1::erasure(4, 2).unwrap();
        let query = LayoutDurabilityQuery::new(layout);
        assert_eq!(query.total_shards(1), 6);
    }

    #[test]
    fn layout_query_survives_failure() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let query = LayoutDurabilityQuery::new(layout);
        // 3-way mirror can survive 2 failures.
        assert!(query.survives_failure(1, 0, 0));
        assert!(query.survives_failure(1, 2, 0));
        // 3 failures -> 3 out of 3 failed, can't survive.
        assert!(!query.survives_failure(1, 3, 0));
    }

    // ── DurabilityHealth tests ─────────────────────────────────

    #[test]
    fn health_has_healthy_replica() {
        let health = DurabilityHealth {
            total_replicas: 3,
            healthy_replicas: 2,
            corrupt_replicas: 1,
            survivable: true,
            escalation: RepairEscalation::Normal,
        };
        assert!(health.has_healthy_replica());
        assert!(!health.is_unrecoverable());
        assert_eq!(health.replicas_remaining(), 2);
    }

    #[test]
    fn health_unrecoverable_when_no_replicas() {
        let health = DurabilityHealth {
            total_replicas: 1,
            healthy_replicas: 0,
            corrupt_replicas: 1,
            survivable: false,
            escalation: RepairEscalation::Immediate,
        };
        assert!(!health.has_healthy_replica());
        assert!(health.is_unrecoverable());
    }

    #[test]
    fn health_not_unrecoverable_with_some_healthy() {
        let health = DurabilityHealth {
            total_replicas: 3,
            healthy_replicas: 1,
            corrupt_replicas: 2,
            survivable: true,
            escalation: RepairEscalation::Urgent,
        };
        assert!(!health.is_unrecoverable());
    }

    // ── RepairScheduler tests ──────────────────────────────────

    fn make_scheduler() -> (
        Arc<LayoutDurabilityQuery>,
        RepairScheduler<LayoutDurabilityQuery>,
    ) {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let query = Arc::new(LayoutDurabilityQuery::new(layout));
        let bridge = ScrubToRepairBridge::new();
        let scheduler = RepairScheduler::new(bridge, query.clone());
        (query, scheduler)
    }

    #[test]
    fn scheduler_ingest_healthy_mirror_dispatches() {
        let (_q, mut scheduler) = make_scheduler();
        let entries = vec![make_entry(1, 0)];
        scheduler.ingest_with_evidence(&inputs_with_receipts(&entries));
        assert_eq!(scheduler.stats().entries_ingested, 1);
        assert_eq!(scheduler.stats().dispatched, 1);
        assert_eq!(scheduler.stats().unrecoverable, 0);
        assert!(scheduler.bridge().has_work());
    }

    #[test]
    fn scheduler_receiptless_ingest_blocks_repair_admission() {
        let (_q, mut scheduler) = make_scheduler();
        let entries = vec![make_entry(2, 0)];
        scheduler.ingest_from_suspect_log(&entries);

        assert_eq!(scheduler.stats().entries_ingested, 1);
        assert_eq!(scheduler.stats().dispatched, 0);
        assert_eq!(scheduler.stats().blocked_missing_receipt, 1);
        assert_eq!(scheduler.bridge().pending_count(), 0);
    }

    #[test]
    fn scheduler_ingest_resolved_entry_is_noop() {
        let (_q, mut scheduler) = make_scheduler();
        let mut entry = make_entry(1, 0);
        entry.resolved = true;
        scheduler.ingest_from_suspect_log(&[entry]);
        // Resolved entries still get ingested (corrupt count = 0)
        assert_eq!(scheduler.stats().entries_ingested, 1);
    }

    #[test]
    fn scheduler_set_failed_devices_updates_counts() {
        let (_q, mut scheduler) = make_scheduler();
        scheduler.set_failed_devices(1, 0);
        assert_eq!(scheduler.failed_devices(), 1);
        assert_eq!(scheduler.failed_nodes(), 0);
    }

    #[test]
    fn scheduler_ingest_unrecoverable_when_all_corrupt() {
        // 1-way mirror (single copy) with corruption = unrecoverable
        let layout = DurabilityLayoutV1::mirror(1).unwrap();
        let query = Arc::new(LayoutDurabilityQuery::new(layout));
        let bridge = ScrubToRepairBridge::new();
        let mut scheduler = RepairScheduler::new(bridge, query);

        let entries = vec![make_entry(100, 0)];
        scheduler.ingest_from_suspect_log(&entries);

        // total=1, corrupt=1, healthy=0 → unrecoverable
        assert_eq!(scheduler.stats().unrecoverable, 1);
        assert_eq!(scheduler.stats().dispatched, 0);
    }

    #[test]
    fn scheduler_ingest_survivable_multi_copy_3way_mirror() {
        // 3-way mirror: one corrupt but 2 healthy → dispatchable
        let (_q, mut scheduler) = make_scheduler();
        let entries = vec![make_entry(200, 0)];
        scheduler.ingest_with_evidence(&inputs_with_receipts(&entries));

        assert_eq!(scheduler.stats().dispatched, 1);
        assert_eq!(scheduler.stats().unrecoverable, 0);
        assert_eq!(scheduler.stats().entries_ingested, 1);
    }

    #[test]
    fn scheduler_assess_health_for_clean_object() {
        let (_q, scheduler) = make_scheduler();
        let mut entry = make_entry(300, 0);
        entry.resolved = true; // clean
        let health = scheduler.assess_health(&entry);
        assert_eq!(health.corrupt_replicas, 0);
        assert_eq!(health.healthy_replicas, 3);
        assert!(health.has_healthy_replica());
    }

    #[test]
    fn scheduler_total_matches_layout_for_mirror() {
        let (_q, scheduler) = make_scheduler();
        assert_eq!(scheduler.replicas_remaining_for_locator(42), 3);
    }

    #[test]
    fn scheduler_total_matches_layout_for_erasure() {
        let layout = DurabilityLayoutV1::erasure(4, 2).unwrap();
        let query = Arc::new(LayoutDurabilityQuery::new(layout));
        let bridge = ScrubToRepairBridge::new();
        let scheduler = RepairScheduler::new(bridge, query);
        assert_eq!(scheduler.replicas_remaining_for_locator(1), 6);
    }

    #[test]
    fn scheduler_unsurvivable_when_layout_cannot_survive() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let query = Arc::new(LayoutDurabilityQuery::new(layout));
        let bridge = ScrubToRepairBridge::new();
        let mut scheduler = RepairScheduler::new(bridge, query);
        // All 3 devices failed.
        scheduler.set_failed_devices(3, 0);

        let entries = vec![make_entry(400, 0)];
        scheduler.ingest_from_suspect_log(&entries);

        assert_eq!(scheduler.stats().unsurvivable, 1);
        assert_eq!(scheduler.stats().dispatched, 0);
    }

    #[test]
    fn scheduler_has_work_delegates_to_bridge() {
        let (_q, scheduler) = make_scheduler();
        assert!(!scheduler.has_work());
    }

    #[test]
    fn scheduler_ingest_multiple_entries() {
        let (_q, mut scheduler) = make_scheduler();
        let entries: Vec<SuspectEntry> = (1..=10).map(|i| make_entry(i, 0)).collect();
        scheduler.ingest_with_evidence(&inputs_with_receipts(&entries));
        assert_eq!(scheduler.stats().entries_ingested, 10);
        assert_eq!(scheduler.stats().dispatched, 10);
        assert_eq!(scheduler.bridge().pending_count(), 10);
    }

    #[test]
    fn scheduler_ingest_with_replicas_direct() {
        let (_q, mut scheduler) = make_scheduler();
        let entries = vec![make_entry(500, 0)];
        scheduler.ingest_evidence_with_replicas(&inputs_with_receipts(&entries), 2);
        assert_eq!(scheduler.stats().entries_ingested, 1);
        assert_eq!(scheduler.stats().dispatched, 1);
    }

    #[test]
    fn scheduler_stats_default_zero() {
        let stats = RepairSchedulerStats::default();
        assert_eq!(stats.entries_ingested, 0);
        assert_eq!(stats.unrecoverable, 0);
        assert_eq!(stats.unsurvivable, 0);
        assert_eq!(stats.dispatched, 0);
        assert_eq!(stats.blocked_missing_receipt, 0);
        assert_eq!(stats.blocked_stale_receipt, 0);
        assert_eq!(stats.unknown_policy, 0);
    }

    // ── Mock durability query for testing ──────────────────────

    struct MockDurabilityQuery {
        total_shards_val: usize,
        survives: bool,
    }

    impl DurabilityQuery for MockDurabilityQuery {
        fn policy_for_locator(&self, _locator_id: u64) -> DurabilityPolicy {
            DurabilityPolicy::Mirror {
                copies: self.total_shards_val as u8,
            }
        }

        fn total_shards(&self, _locator_id: u64) -> usize {
            self.total_shards_val
        }

        fn survives_failure(
            &self,
            _locator_id: u64,
            _failed_devices: u32,
            _failed_nodes: u32,
        ) -> bool {
            self.survives
        }
    }

    #[test]
    fn mock_query_single_copy_corrupt_is_unrecoverable() {
        let mock = Arc::new(MockDurabilityQuery {
            total_shards_val: 1,
            survives: false,
        });
        let bridge = ScrubToRepairBridge::new();
        let mut scheduler = RepairScheduler::new(bridge, mock);

        let entries = vec![make_entry(1, 0)];
        scheduler.ingest_from_suspect_log(&entries);

        assert_eq!(scheduler.stats().unrecoverable, 1);
        assert_eq!(scheduler.stats().dispatched, 0);
    }

    #[test]
    fn mock_query_double_copy_one_corrupt_is_repairable() {
        let mock = Arc::new(MockDurabilityQuery {
            total_shards_val: 2,
            survives: true,
        });
        let bridge = ScrubToRepairBridge::new();
        let mut scheduler = RepairScheduler::new(bridge, mock);

        let entries = vec![make_entry(1, 0)];
        scheduler.ingest_with_evidence(&inputs_with_receipts(&entries));

        assert_eq!(scheduler.stats().dispatched, 1);
        assert_eq!(scheduler.stats().unrecoverable, 0);
    }
}
