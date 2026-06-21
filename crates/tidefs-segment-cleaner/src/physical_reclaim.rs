// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Receipt-bound physical reclaim bridge for the segment cleaner.
//!
//! Segment cleaning decides which segments are safe and worthwhile to clean,
//! but physical reuse of dead storage must stay bound to the durable reclaim
//! evidence already owned by `tidefs-reclaim`.  This module is the
//! segment-cleaner-facing adapter for that authority chain:
//!
//! ```text
//! DeadObjectReclaimQueue -> ReclaimReceipt -> SegmentFreer -> capacity input
//! ```
//!
//! The caller still owns persistence of source-queue acknowledgements and any
//! capacity-accounting projection.  The receipt returned by
//! [`drain_receipt_bound_physical_reclaim`] is the durable evidence that a
//! segment was physically released after replacement/deadlist/pin clearance.

use core::fmt;

use tidefs_reclaim::{
    drain_receipt_bound_dead_objects, DrainError, ReceiptBoundDeadObjectDrain,
    ReclaimConsumerConfig, ReclaimConsumerStats, ReclaimGate, ReclaimReceipt, SegmentFreer,
    SegmentLiveCounts, SegmentResolver,
};
use tidefs_reclaim_queue_core::DeadObjectReclaimQueue;
use tidefs_types_reclaim_queue_core::ObjectKey;

/// Authority names for the physical-reclaim path consumed by segment cleaner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalReclaimAuthority {
    /// Durable receipt authority that proves committed physical release.
    pub durable_receipt: &'static str,
    /// Lower allocator/free-space authority that performs the actual release.
    pub allocator: &'static str,
    /// Mounted capacity authority that may consume committed reclaim evidence.
    pub capacity: &'static str,
}

impl PhysicalReclaimAuthority {
    /// Current authority boundary for issue #791.
    pub const CURRENT: Self = Self {
        durable_receipt: "tidefs_reclaim::ReclaimReceipt",
        allocator: "tidefs_reclaim::SegmentFreer",
        capacity: "tidefs-local-filesystem::CapacityAuthority input",
    };
}

/// Configuration for one receipt-bound physical reclaim drain.
#[derive(Clone, Debug, PartialEq)]
pub struct PhysicalReclaimConfig {
    /// Stable committed transaction group used by the dead-object queue gate.
    pub stable_committed_txg: u64,
    /// Stable replacement receipt generation allowed to authorize reclaim.
    pub stable_committed_generation: u64,
    /// Maximum dead-object entries selected from the queue in this call.
    pub max_entries: usize,
    /// Shared reclaim consumer limits.
    pub consumer: ReclaimConsumerConfig,
}

impl PhysicalReclaimConfig {
    /// Create a drain config with explicit stable transaction evidence.
    #[must_use]
    pub fn new(
        stable_committed_txg: u64,
        stable_committed_generation: u64,
        max_entries: usize,
    ) -> Self {
        Self {
            stable_committed_txg,
            stable_committed_generation,
            max_entries,
            consumer: ReclaimConsumerConfig::default(),
        }
    }
}

impl Default for PhysicalReclaimConfig {
    fn default() -> Self {
        Self::new(0, 0, ReclaimConsumerConfig::default().max_entries_per_drain)
    }
}

/// Result returned to segment-cleaner callers after one physical reclaim drain.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PhysicalReclaimDrain {
    /// Reclaim accounting produced by the shared dead-object consumer.
    pub stats: ReclaimConsumerStats,
    /// Dead-object ids that may be acknowledged after queue persistence.
    pub ack_object_ids: Vec<ObjectKey>,
    /// Exact segments returned to the allocator/free-space authority.
    pub reclaimed_segment_ids: Vec<u64>,
    /// Durable physical-reclaim evidence for freed extents.
    pub receipt: Option<ReclaimReceipt>,
}

impl PhysicalReclaimDrain {
    /// True when this drain did not select or free any physical reclaim work.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.stats.is_idle()
            && self.ack_object_ids.is_empty()
            && self.reclaimed_segment_ids.is_empty()
            && self.receipt.is_none()
    }

    /// Total committed bytes/objects represented by the receipt surface.
    ///
    /// The receipt records exact extent/object keys, not byte lengths, so this
    /// exposes the same object-count unit as `ReclaimConsumerStats::blocks_freed`.
    #[must_use]
    pub fn receipt_extent_count(&self) -> usize {
        self.receipt.as_ref().map_or(0, ReclaimReceipt::len)
    }
}

impl From<ReceiptBoundDeadObjectDrain> for PhysicalReclaimDrain {
    fn from(value: ReceiptBoundDeadObjectDrain) -> Self {
        Self {
            stats: value.stats,
            ack_object_ids: value.ack_object_ids,
            reclaimed_segment_ids: value.reclaimed_segment_ids,
            receipt: value.receipt,
        }
    }
}

/// Drain receipt-authorized dead objects and physically free fully-dead segments.
///
/// This is the smallest segment-cleaner physical reclaim slice: it reuses the
/// durable dead-object queue and [`ReclaimReceipt`] wire format instead of
/// inventing segment-cleaner-local free-space authority.  Entries lacking stable
/// replacement receipts, sufficient generation, or gate clearance remain queued.
///
/// The caller must persist the source queue before acknowledging
/// [`PhysicalReclaimDrain::ack_object_ids`] and must feed any resulting capacity
/// projection through the mounted capacity authority.
pub fn drain_receipt_bound_physical_reclaim<R, F>(
    queue: &DeadObjectReclaimQueue,
    resolver: &impl SegmentResolver<Error = R>,
    freer: &mut impl SegmentFreer<Error = F>,
    live_counts: &mut SegmentLiveCounts,
    gate: &impl ReclaimGate,
    config: &PhysicalReclaimConfig,
) -> Result<PhysicalReclaimDrain, DrainError<R, F>>
where
    R: fmt::Debug + fmt::Display,
    F: fmt::Debug + fmt::Display,
{
    drain_receipt_bound_dead_objects(
        queue,
        config.stable_committed_txg,
        config.stable_committed_generation,
        config.max_entries,
        resolver,
        freer,
        live_counts,
        &config.consumer,
        gate,
    )
    .map(PhysicalReclaimDrain::from)
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap};

    use tidefs_reclaim::{
        ClearanceEvidence, GateDecision, GateDenyReason, ReclaimGate, ReclaimReceiptExtent,
        SegmentFreer, SegmentLiveCounts, SegmentResolver,
    };
    use tidefs_reclaim_queue_core::DeadObjectReclaimQueue;
    use tidefs_types_reclaim_queue_core::{
        DeadObjectEntry, DeadObjectReceiptPolicy, DeadObjectReplacementReceipt, ObjectKey,
    };

    use super::*;

    #[derive(Default)]
    struct MockResolver {
        by_key: BTreeMap<ObjectKey, u64>,
    }

    impl MockResolver {
        fn set(&mut self, id: u8, segment_id: u64) {
            self.by_key.insert(obj_key(id), segment_id);
        }
    }

    impl SegmentResolver for MockResolver {
        type Error = String;

        fn resolve(&self, key: &ObjectKey) -> Result<Option<u64>, Self::Error> {
            Ok(self.by_key.get(key).copied())
        }
    }

    #[derive(Default)]
    struct MockFreer {
        freed: RefCell<Vec<u64>>,
    }

    impl MockFreer {
        fn freed_segments(&self) -> Vec<u64> {
            self.freed.borrow().clone()
        }
    }

    impl SegmentFreer for MockFreer {
        type Error = String;

        fn free_segment(&mut self, segment_id: u64) -> Result<(), Self::Error> {
            self.freed.borrow_mut().push(segment_id);
            Ok(())
        }
    }

    struct AllowAllGate;

    impl ReclaimGate for AllowAllGate {
        fn check_extent(&self, _extent_key: &ObjectKey) -> GateDecision {
            GateDecision::Allow(ClearanceEvidence::Verified {
                deadlist_committed_txg: 12,
                pin_clearance_epoch: 7,
            })
        }
    }

    struct DenyKeyGate {
        deny: ObjectKey,
    }

    impl ReclaimGate for DenyKeyGate {
        fn check_extent(&self, extent_key: &ObjectKey) -> GateDecision {
            if *extent_key == self.deny {
                GateDecision::Deny(GateDenyReason::SnapshotPinned)
            } else {
                GateDecision::Allow(ClearanceEvidence::Verified {
                    deadlist_committed_txg: 12,
                    pin_clearance_epoch: 7,
                })
            }
        }
    }

    fn obj_key(id: u8) -> ObjectKey {
        let mut key = [0; 32];
        key[0] = id;
        ObjectKey(key)
    }

    fn receipt_for(key: ObjectKey, generation: u64) -> DeadObjectReplacementReceipt {
        let mut digest = [0; 32];
        digest[0] = key.0[0];
        digest[8..16].copy_from_slice(&generation.to_le_bytes());
        DeadObjectReplacementReceipt::replicated(key, 1, generation, 2, 4096, digest)
    }

    fn malformed_receipt_for(key: ObjectKey, generation: u64) -> DeadObjectReplacementReceipt {
        let mut digest = [0; 32];
        digest[0] = key.0[0];
        DeadObjectReplacementReceipt::new(
            key,
            1,
            generation,
            DeadObjectReceiptPolicy::Replicated { copies: 0 },
            4096,
            digest,
            0,
        )
    }

    fn dead_entry(
        id: u8,
        death_commit_group: u64,
        replacement_generation: Option<u64>,
    ) -> DeadObjectEntry {
        let key = obj_key(id);
        let entry =
            DeadObjectEntry::new(key, [id; 16], death_commit_group, true, death_commit_group);
        match replacement_generation {
            Some(generation) => entry.with_replacement_receipt(receipt_for(key, generation)),
            None => entry,
        }
    }

    #[test]
    fn physical_reclaim_authority_names_receipt_allocator_and_capacity_boundaries() {
        assert_eq!(
            PhysicalReclaimAuthority::CURRENT.durable_receipt,
            "tidefs_reclaim::ReclaimReceipt"
        );
        assert_eq!(
            PhysicalReclaimAuthority::CURRENT.allocator,
            "tidefs_reclaim::SegmentFreer"
        );
        assert!(PhysicalReclaimAuthority::CURRENT
            .capacity
            .contains("CapacityAuthority"));
    }

    #[test]
    fn receipt_bound_physical_reclaim_frees_segment_and_returns_receipt() {
        let mut queue = DeadObjectReclaimQueue::new();
        queue.enqueue(dead_entry(1, 10, Some(4)));
        queue.enqueue(dead_entry(2, 10, Some(4)));

        let mut resolver = MockResolver::default();
        resolver.set(1, 44);
        resolver.set(2, 44);

        let mut live_counts = SegmentLiveCounts::new();
        live_counts.set_live_count(44, 2);
        let mut freer = MockFreer::default();
        let config = PhysicalReclaimConfig::new(11, 4, 16);

        let drain = drain_receipt_bound_physical_reclaim(
            &queue,
            &resolver,
            &mut freer,
            &mut live_counts,
            &AllowAllGate,
            &config,
        )
        .expect("receipt-bound physical reclaim");

        assert_eq!(drain.ack_object_ids, vec![obj_key(1), obj_key(2)]);
        assert_eq!(drain.reclaimed_segment_ids, vec![44]);
        assert_eq!(freer.freed_segments(), vec![44]);
        assert_eq!(drain.stats.segments_reclaimed, 1);
        assert_eq!(drain.stats.blocks_freed, 2);
        assert_eq!(drain.stats.reclaim_queue_depth, 0);
        assert!(live_counts.is_dead(44));
        let receipt_extent_count = drain.receipt_extent_count();
        let receipt = drain.receipt.expect("durable reclaim receipt");
        assert_eq!(
            receipt.freed_segment_extents,
            vec![
                ReclaimReceiptExtent::new(44, obj_key(1)),
                ReclaimReceiptExtent::new(44, obj_key(2)),
            ]
        );
        assert_eq!(receipt.deadlist_committed_txg, 12);
        assert_eq!(receipt.pin_clearance_epoch, 7);
        assert_eq!(receipt.len(), receipt_extent_count);
    }

    #[test]
    fn receipt_bound_physical_reclaim_keeps_unstable_receipts_queued() {
        let mut queue = DeadObjectReclaimQueue::new();
        queue.enqueue(dead_entry(1, 10, Some(5)));
        queue.enqueue(dead_entry(2, 10, None));
        let malformed = dead_entry(3, 10, Some(5))
            .with_replacement_receipt(malformed_receipt_for(obj_key(3), 5));
        queue.enqueue(malformed);

        let mut resolver = MockResolver::default();
        resolver.set(1, 44);
        resolver.set(2, 44);
        resolver.set(3, 44);
        let mut live_counts = SegmentLiveCounts::new();
        live_counts.set_live_count(44, 3);
        let mut freer = MockFreer::default();
        let config = PhysicalReclaimConfig::new(11, 4, 16);

        let drain = drain_receipt_bound_physical_reclaim(
            &queue,
            &resolver,
            &mut freer,
            &mut live_counts,
            &AllowAllGate,
            &config,
        )
        .expect("unstable receipt drain");

        assert!(drain.is_idle());
        assert_eq!(drain.stats.reclaim_queue_depth, 3);
        assert!(freer.freed_segments().is_empty());
        assert_eq!(live_counts.live_count(44), 3);
    }

    #[test]
    fn receipt_bound_physical_reclaim_keeps_gate_denied_segment_queued() {
        let mut queue = DeadObjectReclaimQueue::new();
        queue.enqueue(dead_entry(1, 10, Some(4)));
        queue.enqueue(dead_entry(2, 10, Some(4)));

        let mut resolver = MockResolver::default();
        resolver.set(1, 44);
        resolver.set(2, 44);
        let mut live_counts = SegmentLiveCounts::new();
        live_counts.set_live_count(44, 2);
        let mut freer = MockFreer::default();
        let config = PhysicalReclaimConfig::new(11, 4, 16);

        let drain = drain_receipt_bound_physical_reclaim(
            &queue,
            &resolver,
            &mut freer,
            &mut live_counts,
            &DenyKeyGate { deny: obj_key(2) },
            &config,
        )
        .expect("gate-denied physical reclaim");

        assert!(drain.ack_object_ids.is_empty());
        assert!(drain.reclaimed_segment_ids.is_empty());
        assert!(drain.receipt.is_none());
        assert_eq!(drain.stats.entries_processed, 2);
        assert_eq!(drain.stats.gate_segments_skipped, 1);
        assert_eq!(drain.stats.gate_extents_denied, 1);
        assert_eq!(drain.stats.reclaim_queue_depth, 2);
        assert!(freer.freed_segments().is_empty());
    }
}
