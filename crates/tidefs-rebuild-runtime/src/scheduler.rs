// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! BackfillScheduler: consumes degraded-replica reports, deduplicates
//! tasks by (subject, target) key, and applies per-node transfer
//! capacity limits to avoid overloading a single target.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::task::{BackfillTask, BackfillTaskInit};
use tidefs_membership_epoch::MemberId;
use tidefs_replication_model::{PlacementReceiptRef, ReplicaMovementClass, ReplicatedSubjectId};

/// Maximum concurrent transfers a single target node can accept.
pub const DEFAULT_NODE_CAPACITY: usize = 4;

/// A report of degraded replica state feeding the scheduler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DegradedReplicaReport {
    /// Affected subject.
    pub subject_ref: ReplicatedSubjectId,
    /// Placement receipt that authorizes the healthy source bytes.
    pub placement_receipt_ref: PlacementReceiptRef,
    /// Healthy source members with a valid copy.
    pub healthy_sources: Vec<MemberId>,
    /// Node(s) missing a healthy replica.
    pub missing_targets: Vec<MemberId>,
    /// Movement urgency.
    pub movement_class: ReplicaMovementClass,
    /// Expected payload digest.
    pub payload_digest: tidefs_replication_model::ObjectDigest,
    /// Payload size.
    pub payload_len: u64,
    /// Monotonic timestamp for deadline computation.
    pub now_ns: u64,
    /// Deadline (ns) relative to now for this task class.
    pub deadline_offset_ns: u64,
}

/// Scheduler that turns degraded-replica reports into ordered,
/// deduplicated BackfillTask sequences with per-node capacity limits.
#[derive(Clone, Debug, Default)]
pub struct BackfillScheduler {
    /// Per-node transfer capacity.
    node_capacity: BTreeMap<MemberId, usize>,
    /// Default capacity for nodes not explicitly configured.
    default_capacity: usize,
    /// Active (subject, target, placement receipt) triples already scheduled.
    active_dedup: BTreeSet<(ReplicatedSubjectId, MemberId, PlacementReceiptRef)>,
    /// Pending tasks in priority order.
    pending: VecDeque<BackfillTask>,
}

impl BackfillScheduler {
    /// Create a scheduler with the default per-node capacity.
    #[must_use]
    pub fn new() -> Self {
        Self {
            node_capacity: BTreeMap::new(),
            default_capacity: DEFAULT_NODE_CAPACITY,
            active_dedup: BTreeSet::new(),
            pending: VecDeque::new(),
        }
    }

    /// Set a custom capacity for a specific node.
    pub fn set_node_capacity(&mut self, node: MemberId, capacity: usize) {
        self.node_capacity.insert(node, capacity);
    }

    /// Return the effective capacity for a node.
    fn effective_capacity(&self, node: MemberId) -> usize {
        self.node_capacity
            .get(&node)
            .copied()
            .unwrap_or(self.default_capacity)
    }

    /// Ingest degraded-replica reports and produce deduplicated tasks.
    ///
    /// For each report, the scheduler picks a healthy source (first available)
    /// and creates tasks for each missing target. Duplicate (subject, target)
    /// pairs are skipped.
    pub fn ingest(&mut self, reports: &[DegradedReplicaReport]) {
        for report in reports {
            let Some(source) = report.healthy_sources.first().copied() else {
                continue;
            };

            for &target in &report.missing_targets {
                let dedup = (report.subject_ref, target, report.placement_receipt_ref);
                if self.active_dedup.contains(&dedup) {
                    continue;
                }

                let task = BackfillTask::new(BackfillTaskInit {
                    subject_ref: report.subject_ref,
                    placement_receipt_ref: report.placement_receipt_ref,
                    source_member: source,
                    target_member: target,
                    movement_class: report.movement_class,
                    payload_digest: report.payload_digest,
                    payload_len: report.payload_len,
                    created_at_ns: report.now_ns,
                    deadline_ns: report.now_ns.saturating_add(report.deadline_offset_ns),
                });

                self.active_dedup.insert(dedup);
                self.pending.push_back(task);
            }
        }

        // Re-sort by priority (highest first = lowest MovementPriority number)
        self.sort_by_priority();
    }

    fn sort_by_priority(&mut self) {
        let mut tasks: Vec<BackfillTask> = self.pending.drain(..).collect();
        tasks.sort_by_key(|t| {
            use crate::MovementPriority;
            let prio: MovementPriority = t.movement_class.into();
            std::cmp::Reverse(prio)
        });
        self.pending = tasks.into();
    }

    /// Drain the next batch of tasks respecting per-node capacity limits.
    ///
    /// Each call consumes tasks from the internal priority queue, respecting
    /// the configured per-node concurrency limit. Returns tasks that are
    /// eligible for immediate dispatch.
    #[must_use]
    pub fn drain_eligible(&mut self) -> Vec<BackfillTask> {
        let mut dispatched = Vec::new();
        let mut node_usage: BTreeMap<MemberId, usize> = BTreeMap::new();
        let mut remaining = VecDeque::new();

        while let Some(task) = self.pending.pop_front() {
            let cap = self.effective_capacity(task.target_member);
            let used = node_usage.get(&task.target_member).copied().unwrap_or(0);
            if used < cap {
                *node_usage.entry(task.target_member).or_insert(0) += 1;
                dispatched.push(task);
            } else {
                remaining.push_back(task);
            }
        }

        self.pending = remaining;
        dispatched
    }

    /// Mark a task as completed, freeing its dedup slot.
    pub fn mark_completed(&mut self, task: &BackfillTask) {
        self.active_dedup.remove(&task.dedup_key());
    }

    /// Number of deduplicated active entries.
    #[must_use]
    pub fn dedup_count(&self) -> usize {
        self.active_dedup.len()
    }

    /// Number of pending tasks in the queue.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Whether the scheduler has no pending or active work.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.pending.is_empty() && self.active_dedup.is_empty()
    }

    /// Clear all state (useful for testing).
    pub fn reset(&mut self) {
        self.active_dedup.clear();
        self.pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_replication_model::ObjectDigest;

    fn receipt_ref(subject: u64, generation: u64) -> PlacementReceiptRef {
        let mut object_key = [0xA5; 32];
        object_key[..8].copy_from_slice(&subject.to_le_bytes());
        let mut digest = [0x5A; 32];
        digest[..8].copy_from_slice(&subject.to_le_bytes());
        digest[8..16].copy_from_slice(&generation.to_le_bytes());
        PlacementReceiptRef::replicated(
            subject,
            object_key,
            tidefs_membership_epoch::EpochId::new(1),
            generation,
            2,
            4096,
            digest,
        )
    }

    fn report(
        subject: u64,
        source: u64,
        missing: &[u64],
        class: ReplicaMovementClass,
        now: u64,
    ) -> DegradedReplicaReport {
        report_with_receipt(
            subject,
            source,
            missing,
            class,
            now,
            receipt_ref(subject, 1),
        )
    }

    fn report_with_receipt(
        subject: u64,
        source: u64,
        missing: &[u64],
        class: ReplicaMovementClass,
        now: u64,
        placement_receipt_ref: PlacementReceiptRef,
    ) -> DegradedReplicaReport {
        DegradedReplicaReport {
            subject_ref: ReplicatedSubjectId::new(subject),
            placement_receipt_ref,
            healthy_sources: vec![MemberId::new(source)],
            missing_targets: missing.iter().map(|&m| MemberId::new(m)).collect(),
            movement_class: class,
            payload_digest: ObjectDigest::new(subject * 100),
            payload_len: 4096,
            now_ns: now,
            deadline_offset_ns: 10_000_000_000,
        }
    }

    #[test]
    fn ingests_and_drains() {
        let mut s = BackfillScheduler::new();
        s.ingest(&[report(
            1,
            10,
            &[20],
            ReplicaMovementClass::BackfillLaggedCopy,
            1000,
        )]);

        assert_eq!(s.pending_count(), 1);
        assert_eq!(s.dedup_count(), 1);

        let tasks = s.drain_eligible();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].subject_ref, ReplicatedSubjectId::new(1));
        assert_eq!(tasks[0].source_member, MemberId::new(10));
        assert_eq!(tasks[0].target_member, MemberId::new(20));

        assert!(s.pending.is_empty());
        // dedup slot still held until mark_completed
        assert_eq!(s.dedup_count(), 1);
    }

    #[test]
    fn deduplicates_duplicate_subject_target() {
        let mut s = BackfillScheduler::new();
        // Same (subject=42, target=20) twice
        s.ingest(&[
            report(
                42,
                10,
                &[20],
                ReplicaMovementClass::BackfillLaggedCopy,
                1000,
            ),
            report(
                42,
                99,
                &[20],
                ReplicaMovementClass::BackfillLaggedCopy,
                1000,
            ),
        ]);

        assert_eq!(s.pending_count(), 1);
        assert_eq!(s.dedup_count(), 1);
    }

    #[test]
    fn distinct_receipt_refs_do_not_deduplicate_subject_target() {
        let mut s = BackfillScheduler::new();
        s.ingest(&[
            report_with_receipt(
                42,
                10,
                &[20],
                ReplicaMovementClass::BackfillLaggedCopy,
                1000,
                receipt_ref(42, 1),
            ),
            report_with_receipt(
                42,
                99,
                &[20],
                ReplicaMovementClass::BackfillLaggedCopy,
                1000,
                receipt_ref(42, 2),
            ),
        ]);

        assert_eq!(s.pending_count(), 2);
        assert_eq!(s.dedup_count(), 2);

        let mut generations: Vec<u64> = s
            .drain_eligible()
            .iter()
            .map(|task| task.placement_receipt_ref.receipt_generation)
            .collect();
        generations.sort_unstable();
        assert_eq!(generations, vec![1, 2]);
    }

    #[test]
    fn respects_node_capacity() {
        let mut s = BackfillScheduler::new();
        s.set_node_capacity(MemberId::new(20), 2);

        // 3 tasks all targeting node 20
        s.ingest(&[
            report(
                1,
                10,
                &[20],
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                1000,
            ),
            report(
                2,
                11,
                &[20],
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                1000,
            ),
            report(
                3,
                12,
                &[20],
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                1000,
            ),
        ]);

        let tasks = s.drain_eligible();
        assert_eq!(tasks.len(), 2, "only 2 should dispatch; node capacity is 2");
        assert_eq!(s.pending_count(), 1, "1 task remains pending");
    }

    #[test]
    fn mark_completed_frees_dedup_slot() {
        let mut s = BackfillScheduler::new();
        s.ingest(&[report(
            99,
            1,
            &[2],
            ReplicaMovementClass::RebuildLostOrSuspectCopy,
            0,
        )]);
        let tasks = s.drain_eligible();
        assert_eq!(s.dedup_count(), 1);

        s.mark_completed(&tasks[0]);
        assert_eq!(s.dedup_count(), 0);

        // Same subject+target can now be re-ingested
        s.ingest(&[report(
            99,
            5,
            &[2],
            ReplicaMovementClass::RebuildLostOrSuspectCopy,
            0,
        )]);
        assert_eq!(s.pending_count(), 1);
    }

    #[test]
    fn priority_ordering_rebuild_before_backfill() {
        let mut s = BackfillScheduler::new();
        s.ingest(&[
            report(1, 10, &[20], ReplicaMovementClass::BackfillLaggedCopy, 0),
            report(
                2,
                11,
                &[21],
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                0,
            ),
            report(
                3,
                12,
                &[22],
                ReplicaMovementClass::RebalanceCapacityPressure,
                0,
            ),
        ]);

        let tasks = s.drain_eligible();
        assert_eq!(tasks.len(), 3);
        assert_eq!(
            tasks[0].movement_class,
            ReplicaMovementClass::RebuildLostOrSuspectCopy
        );
        assert_eq!(
            tasks[1].movement_class,
            ReplicaMovementClass::BackfillLaggedCopy
        );
        assert_eq!(
            tasks[2].movement_class,
            ReplicaMovementClass::RebalanceCapacityPressure
        );
    }

    #[test]
    fn idle_when_empty() {
        let s = BackfillScheduler::new();
        assert!(s.is_idle());
    }

    #[test]
    fn not_idle_when_pending() {
        let mut s = BackfillScheduler::new();
        s.ingest(&[report(
            1,
            10,
            &[20],
            ReplicaMovementClass::BackfillLaggedCopy,
            0,
        )]);
        assert!(!s.is_idle());
    }

    #[test]
    fn reset_clears_all_state() {
        let mut s = BackfillScheduler::new();
        s.ingest(&[report(
            1,
            10,
            &[20],
            ReplicaMovementClass::BackfillLaggedCopy,
            0,
        )]);
        s.reset();
        assert!(s.is_idle());
        assert_eq!(s.pending_count(), 0);
        assert_eq!(s.dedup_count(), 0);
    }

    #[test]
    fn skipped_when_no_healthy_source() {
        let mut s = BackfillScheduler::new();
        let report = DegradedReplicaReport {
            subject_ref: ReplicatedSubjectId::new(1),
            placement_receipt_ref: receipt_ref(1, 1),
            healthy_sources: vec![],
            missing_targets: vec![MemberId::new(20)],
            movement_class: ReplicaMovementClass::BackfillLaggedCopy,
            payload_digest: ObjectDigest::new(100),
            payload_len: 4096,
            now_ns: 0,
            deadline_offset_ns: 10_000_000_000,
        };
        s.ingest(&[report]);
        assert!(s.is_idle());
    }
}
