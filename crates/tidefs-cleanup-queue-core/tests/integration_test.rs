// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests for the cleanup-queue ledger exercising the full
//! pipeline: enqueue FreedExtents → verify_dead → reconcile_with
//! (mock allocator free) → assert space tracking.
//!
//! Uses a `MockAllocator` implementing [`CleanupFreeTarget`] to track
//! freed bytes without depending on tidefs-block-allocator.

use std::collections::HashSet;

use tidefs_cleanup_queue_core::ledger::{
    CleanupFreeTarget, CleanupQueueConfig, CleanupQueueError, CleanupQueueLedger, CleanupStatus,
};
use tidefs_reclaim_queue_core::FreedExtent;

// ── MockAllocator ──────────────────────────────────────────────────

/// In-memory mock allocator that tracks freed extents and byte counts.
struct MockAllocator {
    freed_bytes: u64,
    freed_extent_ids: HashSet<u64>,
}

impl MockAllocator {
    fn new() -> Self {
        Self {
            freed_bytes: 0,
            freed_extent_ids: HashSet::new(),
        }
    }

    fn freed_bytes(&self) -> u64 {
        self.freed_bytes
    }

    fn free_count(&self) -> usize {
        self.freed_extent_ids.len()
    }
}

impl CleanupFreeTarget for MockAllocator {
    fn free_extent(&mut self, extent: &FreedExtent) -> Result<(), CleanupQueueError> {
        // Track the free — idempotent by device_id+offset key.
        let key = extent.device_id ^ extent.physical_offset;
        if self.freed_extent_ids.insert(key) {
            self.freed_bytes += extent.length;
        }
        Ok(())
    }
}

// ── Helper ─────────────────────────────────────────────────────────

fn fe(seed: u8) -> FreedExtent {
    FreedExtent::new(
        u64::from(seed) * 100,  // device_id
        u64::from(seed) * 4096, // physical_offset
        8192,                   // length
        [seed; 32],             // blake3_hash
        u64::from(seed),        // freed_at_txg
    )
}

// ── Full pipeline integration ──────────────────────────────────────

#[test]
fn full_pipeline_enqueue_verify_reconcile_increases_free_space() {
    let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
    let mut alloc = MockAllocator::new();

    // Stage 1: enqueue freed extents from reclaim queue.
    let ids = ledger.enqueue_batch(vec![fe(1), fe(2), fe(3)]);
    assert_eq!(ids.len(), 3);
    assert_eq!(ledger.count_by_status(CleanupStatus::Pending), 3);
    assert_eq!(alloc.freed_bytes(), 0);
    assert_eq!(alloc.free_count(), 0);

    // Stage 2: verify_dead — hash mismatch confirms dead.
    for &id in &ids {
        ledger.verify_dead(id, &[0xFF; 32]).unwrap();
    }
    assert_eq!(ledger.count_by_status(CleanupStatus::Verified), 3);
    assert_eq!(alloc.freed_bytes(), 0); // Not freed yet.

    // Stage 3: reconcile_with — calls allocator free.
    for &id in &ids {
        ledger.reconcile_with(id, &mut alloc).unwrap();
    }
    assert_eq!(ledger.count_by_status(CleanupStatus::Reconciled), 3);
    assert_eq!(alloc.freed_bytes(), 3 * 8192);
    assert_eq!(alloc.free_count(), 3);
}

#[test]
fn reconcile_already_reconciled_is_idempotent_with_allocator() {
    let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
    let mut alloc = MockAllocator::new();

    let id = ledger.enqueue(fe(1));
    ledger.verify_dead(id, &[0xFF; 32]).unwrap();

    // First reconcile: frees extent.
    ledger.reconcile_with(id, &mut alloc).unwrap();
    assert_eq!(alloc.freed_bytes(), 8192);
    assert_eq!(alloc.free_count(), 1);

    // Second reconcile: idempotent — no double-free.
    ledger.reconcile_with(id, &mut alloc).unwrap();
    assert_eq!(alloc.freed_bytes(), 8192);
    assert_eq!(alloc.free_count(), 1);
}

#[test]
fn crash_recovery_replay_preserves_fifo_and_no_double_free() {
    let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
    let mut alloc = MockAllocator::new();

    // Enqueue and process first two entries.
    let id1 = ledger.enqueue(fe(1));
    let id2 = ledger.enqueue(fe(2));
    let id3 = ledger.enqueue(fe(3));

    ledger.verify_dead(id1, &[0xFF; 32]).unwrap();
    ledger.verify_dead(id2, &[0xAA; 32]).unwrap();

    ledger.reconcile_with(id1, &mut alloc).unwrap();
    // id2 verified but NOT reconciled (simulates mid-reconcile crash).

    // Save records for "crash recovery".
    let records = ledger.all_records();

    // Simulate crash: create a fresh ledger and replay.
    let mut recovered = CleanupQueueLedger::new(CleanupQueueConfig::default());
    recovered.replay_records(&records).unwrap();

    let mut alloc2 = MockAllocator::new();

    // Entry 1 was already reconciled; reconciling again is idempotent.
    recovered.reconcile_with(id1, &mut alloc2).unwrap();
    assert_eq!(alloc2.freed_bytes(), 8192);
    assert_eq!(alloc2.free_count(), 1);

    // Entry 2 was verified but not reconciled; now reconcile it.
    recovered.reconcile_with(id2, &mut alloc2).unwrap();
    assert_eq!(alloc2.freed_bytes(), 2 * 8192);
    assert_eq!(alloc2.free_count(), 2);

    // Entry 3 should still be pending.
    assert_eq!(recovered.get(id3).unwrap().status, CleanupStatus::Pending);
}

#[test]
fn verify_dead_failure_does_not_reconcile() {
    let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
    let mut alloc = MockAllocator::new();

    let id = ledger.enqueue(fe(1));
    // Same hash means extent data still matches — not yet dead.
    let result = ledger.verify_dead(id, &[1; 32]);
    assert!(result.is_err());

    // Attempting to reconcile a Pending entry should fail.
    let err = ledger.reconcile_with(id, &mut alloc).unwrap_err();
    assert!(matches!(
        err,
        CleanupQueueError::InvalidStatusTransition { .. }
    ));
    assert_eq!(alloc.freed_bytes(), 0);
}

#[test]
fn batch_processing_fifo_order_through_pipeline() {
    let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
    let mut alloc = MockAllocator::new();

    let ids = ledger.enqueue_batch(vec![fe(1), fe(2), fe(3), fe(4), fe(5)]);

    // Process in FIFO order: verify_dead → reconcile_with.
    for &id in &ids[..3] {
        ledger.verify_dead(id, &[0xFF; 32]).unwrap();
    }
    // ids[3] and ids[4] stay pending.

    let pending = ledger.pending_batch(10);
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].entry_id, ids[3]);
    assert_eq!(pending[1].entry_id, ids[4]);

    let verified = ledger.verified_batch(10);
    assert_eq!(verified.len(), 3);
    assert_eq!(verified[0].entry_id, ids[0]);
    assert_eq!(verified[1].entry_id, ids[1]);
    assert_eq!(verified[2].entry_id, ids[2]);

    // Reconcile the verified ones.
    for &id in &ids[..3] {
        ledger.reconcile_with(id, &mut alloc).unwrap();
    }
    assert_eq!(alloc.freed_bytes(), 3 * 8192);

    // Purge terminal leaves only pending entries.
    ledger.purge_terminal();
    assert_eq!(ledger.len(), 2);
    assert_eq!(ledger.count_by_status(CleanupStatus::Pending), 2);
}

#[test]
fn max_retries_transition_to_failed_prevents_reconcile() {
    let config = CleanupQueueConfig {
        max_retries: 1,
        ..CleanupQueueConfig::default()
    };
    let mut ledger = CleanupQueueLedger::new(config);
    let mut alloc = MockAllocator::new();

    let id = ledger.enqueue(fe(1));
    // First attempt: retry_count = 1, 1 >= 1 → Failed.
    let _ = ledger.verify_dead(id, &[1; 32]);
    assert_eq!(ledger.get(id).unwrap().status, CleanupStatus::Failed);

    // Reconciling a Failed entry is an error.
    let err = ledger.reconcile_with(id, &mut alloc).unwrap_err();
    assert!(matches!(err, CleanupQueueError::AlreadyFailed { .. }));
    assert_eq!(alloc.freed_bytes(), 0);
}

#[test]
fn purge_terminal_after_full_pipeline_cleans_up_ledger() {
    let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
    let mut alloc = MockAllocator::new();

    let id1 = ledger.enqueue(fe(1));
    let id2 = ledger.enqueue(fe(2));

    ledger.verify_dead(id1, &[0xFF; 32]).unwrap();
    ledger.reconcile_with(id1, &mut alloc).unwrap();
    // id2 stays pending.

    assert_eq!(ledger.len(), 2);
    let purged = ledger.purge_terminal();
    assert_eq!(purged, 1); // Only reconciled entry purged.
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger.get(id2).unwrap().status, CleanupStatus::Pending);
    assert!(ledger.get(id1).is_none());
}
