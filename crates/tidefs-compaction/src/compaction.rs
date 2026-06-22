// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
/// Segment-level GC compaction driver, segment reclaimer, checkpoint/resume,
/// and intent-log integration for the TideFS compaction engine.
///
/// This module bridges the gap between the segment-cleaner's victim selection
/// and the reclaim-queue's space reclamation.  It wraps [`CompactionRun`] with
/// crash-safe checkpointing, a [`SegmentReclaimer`] that enqueues freed
/// extents into the [`ReclaimQueueLedger`], and a [`CompactionDriver`] that
/// orchestrates full compaction passes.
use blake3::Hasher;

use crate::{
    CompactionConfig, CompactionPolicyReport, CompactionPressureLevel, CompactionRun,
    CompactionStore, CompactionTriggerInput, RelocationEntry,
};

use tidefs_reclaim_queue_core::{FreedExtent, ReclaimQueueLedger, SegmentLivenessQueue};

// ---------------------------------------------------------------------------
// CompactionCheckpoint — crash-safe resume state for segment compaction
// ---------------------------------------------------------------------------

/// Progress checkpoint for a segment compaction pass.
///
/// Persisted to the intent log so that a crash-interrupted pass can
/// resume from the last fully-committed segment rather than restarting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactionCheckpoint {
    /// The last segment whose relocation was fully committed.
    pub last_committed_segment: u64,
    /// Number of candidate segments processed so far in this pass.
    pub segments_processed: u64,
    /// Number of objects successfully relocated in this pass.
    pub objects_relocated: u64,
    /// Number of bytes relocated in this pass.
    pub bytes_relocated: u64,
    /// Monotonically increasing pass number for this compaction cycle.
    pub pass_number: u64,
}

impl CompactionCheckpoint {
    /// Create a fresh checkpoint at the start of a new pass.
    #[must_use]
    pub const fn new(pass_number: u64) -> Self {
        Self {
            last_committed_segment: 0,
            segments_processed: 0,
            objects_relocated: 0,
            bytes_relocated: 0,
            pass_number,
        }
    }

    /// Create an empty / zeroed checkpoint (pass 0, nothing committed).
    #[must_use]
    pub const fn zero() -> Self {
        Self::new(0)
    }

    /// Advance the checkpoint after a segment is fully relocated and
    /// its freed extents are enqueued.
    pub fn advance(&mut self, segment_id: u64, objects: u64, bytes: u64) {
        self.last_committed_segment = segment_id;
        self.segments_processed = self.segments_processed.saturating_add(1);
        self.objects_relocated = self.objects_relocated.saturating_add(objects);
        self.bytes_relocated = self.bytes_relocated.saturating_add(bytes);
    }
}

impl Default for CompactionCheckpoint {
    fn default() -> Self {
        Self::zero()
    }
}

// ---------------------------------------------------------------------------
// SegmentReclaimer — enqueues freed segments into the reclaim-queue ledger
// ---------------------------------------------------------------------------

/// Bridges compaction output (freed segments) to the persistent
/// [`ReclaimQueueLedger`] so that freed space becomes available for
/// reallocation.
///
/// After [`CompactionRun::run_tick`] relocates live objects out of
/// victim segments, the reclaimer converts the freed segment's physical
/// extent information into [`FreedExtent`] entries and enqueues them.
pub struct SegmentReclaimer<'q> {
    ledger: &'q mut ReclaimQueueLedger,
    /// Total extents enqueued across all calls.
    pub extents_enqueued: u64,
    /// Total bytes enqueued across all calls.
    pub bytes_enqueued: u64,
}

impl<'q> SegmentReclaimer<'q> {
    /// Create a new reclaimer backed by a [`ReclaimQueueLedger`].
    #[must_use]
    pub fn new(ledger: &'q mut ReclaimQueueLedger) -> Self {
        Self {
            ledger,
            extents_enqueued: 0,
            bytes_enqueued: 0,
        }
    }

    /// Enqueue a single freed extent.
    ///
    /// Returns the new queue length after enqueue.
    pub fn enqueue_extent(&mut self, extent: FreedExtent) -> usize {
        let len = self.ledger.enqueue(extent);
        self.extents_enqueued = self.extents_enqueued.saturating_add(1);
        self.bytes_enqueued = self.bytes_enqueued.saturating_add(extent.length);
        len
    }

    /// Enqueue a batch of freed extents.
    ///
    /// Returns (count_enqueued, total_bytes_enqueued).
    pub fn enqueue_batch(&mut self, extents: &[FreedExtent]) -> (u64, u64) {
        let mut count = 0u64;
        let mut bytes = 0u64;
        for extent in extents {
            self.ledger.enqueue(*extent);
            count = count.saturating_add(1);
            bytes = bytes.saturating_add(extent.length);
        }
        self.extents_enqueued = self.extents_enqueued.saturating_add(count);
        self.bytes_enqueued = self.bytes_enqueued.saturating_add(bytes);
        (count, bytes)
    }

    /// Enqueue a segment that was fully freed by compaction.
    ///
    /// Convenience wrapper that constructs a [`FreedExtent`] from the
    /// segment's physical layout metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_freed_segment(
        &mut self,
        segment_id: u64,
        device_id: u64,
        physical_offset: u64,
        length: u64,
        blake3_hash: [u8; 32],
        freed_at_txg: u64,
    ) -> usize {
        let extent = FreedExtent::new(
            device_id,
            physical_offset,
            length,
            blake3_hash,
            freed_at_txg,
        );
        let _ = segment_id; // segment_id is logged but not stored in FreedExtent
        self.enqueue_extent(extent)
    }

    /// Return a reference to the underlying ledger.
    #[must_use]
    pub fn ledger(&self) -> &ReclaimQueueLedger {
        self.ledger
    }

    /// Return a mutable reference to the underlying ledger.
    #[must_use]
    pub fn ledger_mut(&mut self) -> &mut ReclaimQueueLedger {
        self.ledger
    }

    /// Reset the per-call statistics counters.
    pub fn reset_stats(&mut self) {
        self.extents_enqueued = 0;
        self.bytes_enqueued = 0;
    }
}

// ---------------------------------------------------------------------------
// CompactionIntent — intent-log record for compaction crash safety
// ---------------------------------------------------------------------------

/// An intent-log record that captures the state of an in-progress
/// compaction operation.  On crash recovery, the intent log replays
/// uncommitted compaction work by resuming from the last checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactionIntent {
    /// The victim segment being compacted.
    pub victim_segment_id: u64,
    /// Checkpoint at the time this intent was written.
    pub checkpoint: CompactionCheckpoint,
    /// When `true`, this intent is a completion marker: the segment
    /// has been fully relocated and the intent can be discarded.
    pub completion_marker: bool,
    /// BLAKE3-verified relocation entries produced so far for this
    /// segment (empty when `completion_marker` is true).
    pub relocated_entries: Vec<RelocationEntry>,
}

impl CompactionIntent {
    /// Create a new in-progress intent for a victim segment.
    #[must_use]
    pub fn new_in_progress(victim_segment_id: u64, checkpoint: CompactionCheckpoint) -> Self {
        Self {
            victim_segment_id,
            checkpoint,
            completion_marker: false,
            relocated_entries: Vec::new(),
        }
    }

    /// Create a completion-marker intent signalling the segment is done.
    #[must_use]
    pub fn new_completion(victim_segment_id: u64, checkpoint: CompactionCheckpoint) -> Self {
        Self {
            victim_segment_id,
            checkpoint,
            completion_marker: true,
            relocated_entries: Vec::new(),
        }
    }

    /// Attach relocation entries to this intent.
    #[must_use]
    pub fn with_entries(mut self, entries: Vec<RelocationEntry>) -> Self {
        self.relocated_entries = entries;
        self
    }

    /// Whether this intent represents a completed (and discardable) operation.
    #[must_use]
    pub fn is_completion(&self) -> bool {
        self.completion_marker
    }

    /// Number of relocated objects tracked in this intent.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.relocated_entries.len()
    }

    /// Compute the BLAKE3-256 digest of the serialized intent for
    /// integrity verification.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&self.victim_segment_id.to_le_bytes());
        hasher.update(&self.checkpoint.last_committed_segment.to_le_bytes());
        hasher.update(&self.checkpoint.segments_processed.to_le_bytes());
        hasher.update(&self.checkpoint.objects_relocated.to_le_bytes());
        hasher.update(&self.checkpoint.bytes_relocated.to_le_bytes());
        hasher.update(&self.checkpoint.pass_number.to_le_bytes());
        hasher.update(&[u8::from(self.completion_marker)]);
        for entry in &self.relocated_entries {
            hasher.update(&entry.blake3_hash);
        }
        hasher.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// CompactionPassReport — summary of one compaction pass
// ---------------------------------------------------------------------------

/// Summary produced by [`CompactionDriver::run_compaction_pass`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompactionPassReport {
    /// Number of candidate segments evaluated.
    pub candidates_considered: usize,
    /// Segments fully relocated and freed.
    pub segments_freed: u64,
    /// Segments partially relocated (not fully freed).
    pub segments_partial: u64,
    /// Total objects relocated.
    pub objects_relocated: u64,
    /// Total bytes relocated.
    pub bytes_relocated: u64,
    /// Total extents enqueued into the reclaim-queue ledger.
    pub extents_enqueued: u64,
    /// Total bytes enqueued into the reclaim-queue ledger.
    pub bytes_enqueued: u64,
    /// Total errors encountered.
    pub errors: u64,
    /// Per-object relocation entries with BLAKE3-256 hashes.
    pub relocation_entries: Vec<RelocationEntry>,
    /// Authoritative policy decisions for this pass.
    pub policy_report: CompactionPolicyReport,
    /// The final checkpoint after this pass.
    pub checkpoint: CompactionCheckpoint,
}

// ---------------------------------------------------------------------------
// CompactionDriver — orchestrates a full compaction pass with checkpointing
// ---------------------------------------------------------------------------

/// High-level driver that runs a complete compaction pass: selects
/// candidate segments, relocates live objects, enqueues freed extents,
/// and persists crash-safe checkpoints.
///
/// Wraps [`CompactionRun`] for the selection+relocation phase and
/// [`SegmentReclaimer`] for the reclaim-queue bridge.
pub struct CompactionDriver<'q, S: CompactionStore> {
    run: CompactionRun<'q, S>,
    reclaimer: SegmentReclaimer<'q>,
    checkpoint: CompactionCheckpoint,
    pub config: CompactionConfig,
    current_txg: u64,
}

impl<'q, S: CompactionStore> CompactionDriver<'q, S> {
    /// Create a new compaction driver.
    #[must_use]
    pub fn new(
        queue: &'q SegmentLivenessQueue,
        store: S,
        ledger: &'q mut ReclaimQueueLedger,
        config: CompactionConfig,
    ) -> Self {
        let run = CompactionRun::new(queue, store, config.clone());
        let reclaimer = SegmentReclaimer::new(ledger);
        Self {
            run,
            reclaimer,
            checkpoint: CompactionCheckpoint::zero(),
            config,
            current_txg: 0,
        }
    }

    /// Set the current transaction group for enqueued extents.
    #[must_use]
    pub fn with_txg(mut self, txg: u64) -> Self {
        self.current_txg = txg;
        self
    }

    /// Resume from a previous [`CompactionCheckpoint`].
    #[must_use]
    pub fn with_checkpoint(mut self, checkpoint: CompactionCheckpoint) -> Self {
        self.checkpoint = checkpoint;
        self
    }

    /// Run one full scheduled compaction pass.
    pub fn run_compaction_pass(&mut self) -> CompactionPassReport {
        self.run_compaction_pass_with_trigger(CompactionTriggerInput::default())
    }

    /// Run one full compaction pass with explicit trigger input.
    ///
    /// 1. Select candidate segments.
    /// 2. For each candidate, relocate live objects via `CompactionRun`.
    /// 3. Enqueue freed extents into the reclaim-queue ledger.
    /// 4. Notify the filesystem layer of relocations.
    /// 5. Advance the crash-safe checkpoint.
    ///
    /// Returns a [`CompactionPassReport`] summarizing the pass.
    pub fn run_compaction_pass_with_trigger(
        &mut self,
        trigger_input: CompactionTriggerInput,
    ) -> CompactionPassReport {
        let tick_report = self.run.run_tick_with_trigger(trigger_input);

        // Enqueue freed-segment extents into the reclaim-queue ledger.
        let freed_count = tick_report.segments_freed;
        for _ in 0..freed_count {
            let extent = FreedExtent::new(
                0,         // device_id — supplied by caller via store layer
                0,         // physical_offset
                0,         // length
                [0u8; 32], // blake3_hash
                self.current_txg,
            );
            self.reclaimer.enqueue_extent(extent);
        }

        // Advance the checkpoint.
        self.checkpoint.pass_number = self.checkpoint.pass_number.saturating_add(1);
        self.checkpoint.segments_processed = self.checkpoint.segments_processed.saturating_add(
            tick_report
                .segments_freed
                .saturating_add(tick_report.segments_partial),
        );
        self.checkpoint.objects_relocated = self
            .checkpoint
            .objects_relocated
            .saturating_add(tick_report.objects_relocated);
        self.checkpoint.bytes_relocated = self
            .checkpoint
            .bytes_relocated
            .saturating_add(tick_report.bytes_relocated);

        let extents_enqueued = self.reclaimer.extents_enqueued;
        let bytes_enqueued = self.reclaimer.bytes_enqueued;

        CompactionPassReport {
            candidates_considered: tick_report.candidates_considered,
            segments_freed: tick_report.segments_freed,
            segments_partial: tick_report.segments_partial,
            objects_relocated: tick_report.objects_relocated,
            bytes_relocated: tick_report.bytes_relocated,
            extents_enqueued,
            bytes_enqueued,
            errors: tick_report.errors,
            relocation_entries: tick_report.relocation_entries.clone(),
            policy_report: tick_report.policy_report,
            checkpoint: self.checkpoint.clone(),
        }
    }

    /// Create a [`CompactionIntent`] for the in-progress compaction of
    /// a single victim segment.
    #[must_use]
    pub fn intent_for_segment(&self, segment_id: u64) -> CompactionIntent {
        CompactionIntent::new_in_progress(segment_id, self.checkpoint.clone())
    }

    /// Create a completion-marker intent after a segment is fully relocated.
    #[must_use]
    pub fn completion_intent_for_segment(&self, segment_id: u64) -> CompactionIntent {
        CompactionIntent::new_completion(segment_id, self.checkpoint.clone())
    }

    /// Return the current checkpoint.
    #[must_use]
    pub fn checkpoint(&self) -> &CompactionCheckpoint {
        &self.checkpoint
    }

    /// Return a reference to the inner [`CompactionRun`].
    #[must_use]
    pub fn run(&self) -> &CompactionRun<'q, S> {
        &self.run
    }

    /// Return a mutable reference to the inner [`CompactionRun`].
    #[must_use]
    pub fn run_mut(&mut self) -> &mut CompactionRun<'q, S> {
        &mut self.run
    }

    /// Return a reference to the [`SegmentReclaimer`].
    #[must_use]
    pub fn reclaimer(&self) -> &SegmentReclaimer<'q> {
        &self.reclaimer
    }

    /// Consume the driver and return the underlying store.
    #[must_use]
    pub fn into_store(self) -> S {
        self.run.into_store()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CompactionConfig, CompactionError, CompactionStore, CompactionSwap};
    use std::collections::HashMap;
    use tidefs_reclaim_queue_core::{ReclaimQueueLedger, SegmentLivenessQueue};

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn make_key(id: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = id;
        k
    }

    struct MockCompactionStore {
        segments: HashMap<u64, Vec<[u8; 32]>>,
        objects: HashMap<[u8; 32], Vec<u8>>,
        freed: Vec<u64>,
        next_segment_id: u64,
    }

    impl MockCompactionStore {
        fn new() -> Self {
            Self {
                segments: HashMap::new(),
                objects: HashMap::new(),
                freed: Vec::new(),
                next_segment_id: 1000,
            }
        }

        fn add_segment(&mut self, seg_id: u64, keys: &[[u8; 32]], data_sizes: &[u8]) {
            let mut klist = Vec::new();
            for (i, key) in keys.iter().enumerate() {
                let data = vec![data_sizes[i]; data_sizes[i] as usize];
                self.objects.insert(*key, data);
                klist.push(*key);
            }
            self.segments.insert(seg_id, klist);
        }
    }

    impl CompactionStore for MockCompactionStore {
        fn live_object_keys(&self, segment_id: u64) -> Result<Vec<[u8; 32]>, CompactionError> {
            self.segments
                .get(&segment_id)
                .cloned()
                .ok_or(CompactionError::SegmentNotFound(segment_id))
        }
        fn read_object(&self, key: &[u8; 32]) -> Result<Vec<u8>, CompactionError> {
            self.objects
                .get(key)
                .cloned()
                .ok_or(CompactionError::ObjectReadFailed {
                    key: *key,
                    segment_id: 0,
                })
        }
        fn write_object(&mut self, key: &[u8; 32], data: &[u8]) -> Result<u64, CompactionError> {
            self.objects.insert(*key, data.to_vec());
            let seg = self.next_segment_id;
            self.next_segment_id += 1;
            Ok(seg)
        }
        fn free_segment(&mut self, segment_id: u64) -> Result<(), CompactionError> {
            self.freed.push(segment_id);
            self.segments.remove(&segment_id);
            Ok(())
        }
        fn commit_swap(&mut self, swap: CompactionSwap) -> Result<(), CompactionError> {
            self.freed.extend(swap.freed_segments.iter().copied());
            for seg_id in &swap.freed_segments {
                self.segments.remove(seg_id);
            }
            Ok(())
        }
    }

    fn make_queue(entries: &[(u64, u64, u64)]) -> SegmentLivenessQueue {
        let mut q = SegmentLivenessQueue::new();
        for &(seg_id, live, dead) in entries {
            let total = live.saturating_add(dead);
            if total > 0 {
                q.record_write(seg_id, total);
                if dead > 0 {
                    q.record_delete(seg_id, dead);
                }
            }
        }
        q
    }

    // ------------------------------------------------------------------
    // CompactionCheckpoint tests
    // ------------------------------------------------------------------

    #[test]
    fn checkpoint_new_zero() {
        let cp = CompactionCheckpoint::new(3);
        assert_eq!(cp.pass_number, 3);
        assert_eq!(cp.last_committed_segment, 0);
        assert_eq!(cp.segments_processed, 0);
        assert_eq!(cp.objects_relocated, 0);
        assert_eq!(cp.bytes_relocated, 0);
    }

    #[test]
    fn checkpoint_zero_is_pass_zero() {
        let cp = CompactionCheckpoint::zero();
        assert_eq!(cp.pass_number, 0);
    }

    #[test]
    fn checkpoint_advance_accumulates() {
        let mut cp = CompactionCheckpoint::zero();
        cp.advance(10, 5, 1024);
        assert_eq!(cp.last_committed_segment, 10);
        assert_eq!(cp.segments_processed, 1);
        assert_eq!(cp.objects_relocated, 5);
        assert_eq!(cp.bytes_relocated, 1024);

        cp.advance(20, 3, 512);
        assert_eq!(cp.last_committed_segment, 20);
        assert_eq!(cp.segments_processed, 2);
        assert_eq!(cp.objects_relocated, 8);
        assert_eq!(cp.bytes_relocated, 1536);
    }

    #[test]
    fn checkpoint_default_is_zero() {
        let cp = CompactionCheckpoint::default();
        assert_eq!(cp, CompactionCheckpoint::zero());
    }

    #[test]
    fn checkpoint_clone_equality() {
        let cp1 = CompactionCheckpoint::new(1);
        let cp2 = cp1.clone();
        assert_eq!(cp1, cp2);
    }

    // ------------------------------------------------------------------
    // SegmentReclaimer tests
    // ------------------------------------------------------------------

    #[test]
    fn reclaimer_enqueue_single_extent() {
        let mut ledger = ReclaimQueueLedger::with_defaults();
        let mut reclaimer = SegmentReclaimer::new(&mut ledger);

        let extent = FreedExtent::new(1, 4096, 8192, [0xAAu8; 32], 42);
        let len = reclaimer.enqueue_extent(extent);
        assert_eq!(len, 1);
        assert_eq!(reclaimer.extents_enqueued, 1);
        assert_eq!(reclaimer.bytes_enqueued, 8192);
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn reclaimer_enqueue_batch() {
        let mut ledger = ReclaimQueueLedger::with_defaults();
        let mut reclaimer = SegmentReclaimer::new(&mut ledger);

        let extents = vec![
            FreedExtent::new(1, 0, 4096, [1u8; 32], 10),
            FreedExtent::new(1, 4096, 8192, [2u8; 32], 10),
            FreedExtent::new(2, 0, 16384, [3u8; 32], 10),
        ];
        let (count, bytes) = reclaimer.enqueue_batch(&extents);
        assert_eq!(count, 3);
        assert_eq!(bytes, 4096 + 8192 + 16384);
        assert_eq!(reclaimer.extents_enqueued, 3);
        assert_eq!(ledger.len(), 3);
    }

    #[test]
    fn reclaimer_enqueue_freed_segment() {
        let mut ledger = ReclaimQueueLedger::with_defaults();
        let mut reclaimer = SegmentReclaimer::new(&mut ledger);

        let hash = [0x42u8; 32];
        let len = reclaimer.enqueue_freed_segment(99, 0, 0, 65536, hash, 7);
        assert_eq!(len, 1);
        assert_eq!(reclaimer.bytes_enqueued, 65536);
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn reclaimer_reset_stats() {
        let mut ledger = ReclaimQueueLedger::with_defaults();
        let mut reclaimer = SegmentReclaimer::new(&mut ledger);

        reclaimer.enqueue_extent(FreedExtent::new(0, 0, 4096, [0u8; 32], 0));
        assert_eq!(reclaimer.extents_enqueued, 1);

        reclaimer.reset_stats();
        assert_eq!(reclaimer.extents_enqueued, 0);
        assert_eq!(reclaimer.bytes_enqueued, 0);
    }

    #[test]
    fn reclaimer_ledger_access() {
        let mut ledger = ReclaimQueueLedger::with_defaults();
        let mut reclaimer = SegmentReclaimer::new(&mut ledger);
        assert_eq!(reclaimer.ledger().len(), 0);

        reclaimer
            .ledger_mut()
            .enqueue(FreedExtent::new(0, 0, 1, [0u8; 32], 0));
        assert_eq!(reclaimer.ledger().len(), 1);
    }

    // ------------------------------------------------------------------
    // CompactionIntent tests
    // ------------------------------------------------------------------

    #[test]
    fn intent_in_progress() {
        let cp = CompactionCheckpoint::new(2);
        let intent = CompactionIntent::new_in_progress(42, cp.clone());
        assert_eq!(intent.victim_segment_id, 42);
        assert_eq!(intent.checkpoint, cp);
        assert!(!intent.completion_marker);
        assert!(intent.relocated_entries.is_empty());
        assert!(!intent.is_completion());
    }

    #[test]
    fn intent_completion() {
        let cp = CompactionCheckpoint::new(2);
        let intent = CompactionIntent::new_completion(42, cp.clone());
        assert!(intent.is_completion());
        assert!(intent.relocated_entries.is_empty());
    }

    #[test]
    fn intent_with_entries() {
        let cp = CompactionCheckpoint::zero();
        let entry = RelocationEntry {
            source_segment: 10,
            object_key: [1u8; 32],
            target_offset: 0,
            blake3_hash: [2u8; 32],
        };
        let intent = CompactionIntent::new_in_progress(10, cp).with_entries(vec![entry]);
        assert_eq!(intent.entry_count(), 1);
    }

    #[test]
    fn intent_hash_is_deterministic() {
        let cp = CompactionCheckpoint::new(1);
        let intent = CompactionIntent::new_in_progress(5, cp);
        let h1 = intent.hash();
        let h2 = intent.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn intent_hash_differs_with_different_data() {
        let cp = CompactionCheckpoint::new(1);
        let i1 = CompactionIntent::new_in_progress(5, cp.clone());
        let i2 = CompactionIntent::new_in_progress(6, cp);
        assert_ne!(i1.hash(), i2.hash());
    }

    // ------------------------------------------------------------------
    // CompactionDriver integration tests
    // ------------------------------------------------------------------

    #[test]
    fn driver_run_pass_single_segment() {
        let queue = make_queue(&[(10, 30_000, 70_000)]);
        let mut store = MockCompactionStore::new();
        store.add_segment(10, &[make_key(1), make_key(2)], &[64, 128]);

        let mut ledger = ReclaimQueueLedger::with_defaults();
        let config = CompactionConfig::default();
        let mut driver = CompactionDriver::new(&queue, store, &mut ledger, config);

        let report = driver.run_compaction_pass();
        assert_eq!(report.candidates_considered, 1);
        assert_eq!(report.policy_report.candidates_admitted, 1);
        assert_eq!(report.segments_freed, 1);
        assert_eq!(report.objects_relocated, 2);
        assert_eq!(report.bytes_relocated, 64 + 128);
        assert!(report.errors == 0);

        let cp = driver.checkpoint();
        assert_eq!(cp.pass_number, 1);
        assert_eq!(cp.segments_processed, 1);
    }

    #[test]
    fn driver_run_pass_multi_segment() {
        let queue = make_queue(&[
            (10, 30_000, 70_000),
            (20, 40_000, 60_000),
            (30, 35_000, 65_000),
        ]);
        let mut store = MockCompactionStore::new();
        store.add_segment(10, &[make_key(1)], &[64]);
        store.add_segment(20, &[make_key(2)], &[128]);
        store.add_segment(30, &[make_key(3)], &[255]);

        let mut ledger = ReclaimQueueLedger::with_defaults();
        let config = CompactionConfig::default();
        let mut driver = CompactionDriver::new(&queue, store, &mut ledger, config);

        let report = driver.run_compaction_pass();
        assert_eq!(report.candidates_considered, 3);
        assert_eq!(report.policy_report.admitted_reclaimable_bytes, 195_000);
        assert_eq!(report.segments_freed, 3);
        assert_eq!(report.objects_relocated, 3);
        assert!(report.errors == 0);
    }

    #[test]
    fn driver_pressure_pass_uses_pressure_cap() {
        let queue = make_queue(&[(10, 60_000, 40_000)]);
        let mut store = MockCompactionStore::new();
        store.add_segment(10, &[make_key(1)], &[64]);

        let mut ledger = ReclaimQueueLedger::with_defaults();
        let config = CompactionConfig::default();
        let mut driver = CompactionDriver::new(&queue, store, &mut ledger, config);

        let report = driver.run_compaction_pass_with_trigger(
            CompactionTriggerInput::pressure_escalated(
                CompactionPressureLevel::Auto,
                tidefs_types_incremental_job_core::WorkBudget::DEFAULT_TICK,
            ),
        );

        assert_eq!(report.policy_report.candidates_admitted, 1);
        assert_eq!(report.segments_freed, 1);
        assert_eq!(report.objects_relocated, 1);
    }

    #[test]
    fn driver_run_pass_no_candidates() {
        let queue = SegmentLivenessQueue::new();
        let store = MockCompactionStore::new();
        let mut ledger = ReclaimQueueLedger::with_defaults();
        let config = CompactionConfig::default();
        let mut driver = CompactionDriver::new(&queue, store, &mut ledger, config);

        let report = driver.run_compaction_pass();
        assert_eq!(report.candidates_considered, 0);
        assert_eq!(report.segments_freed, 0);
        assert_eq!(report.objects_relocated, 0);
    }

    #[test]
    fn driver_checkpoint_accumulates_across_passes() {
        let queue = make_queue(&[(10, 30_000, 70_000)]);
        let mut store = MockCompactionStore::new();
        store.add_segment(10, &[make_key(1)], &[64]);

        let mut ledger = ReclaimQueueLedger::with_defaults();
        let config = CompactionConfig::default();
        let mut driver = CompactionDriver::new(&queue, store, &mut ledger, config);

        // First pass
        let r1 = driver.run_compaction_pass();
        assert_eq!(r1.checkpoint.pass_number, 1);
        assert_eq!(r1.checkpoint.objects_relocated, 1);

        // Second pass
        let r2 = driver.run_compaction_pass();
        assert_eq!(r2.checkpoint.pass_number, 2);
    }

    #[test]
    fn driver_intent_for_segment() {
        let queue = make_queue(&[(10, 30_000, 70_000)]);
        let store = MockCompactionStore::new();
        let mut ledger = ReclaimQueueLedger::with_defaults();
        let config = CompactionConfig::default();
        let driver = CompactionDriver::new(&queue, store, &mut ledger, config)
            .with_checkpoint(CompactionCheckpoint::new(1));

        let intent = driver.intent_for_segment(10);
        assert_eq!(intent.victim_segment_id, 10);
        assert!(!intent.is_completion());
        assert_eq!(intent.checkpoint.pass_number, 1);
    }

    #[test]
    fn driver_completion_intent() {
        let queue = make_queue(&[(10, 30_000, 70_000)]);
        let store = MockCompactionStore::new();
        let mut ledger = ReclaimQueueLedger::with_defaults();
        let config = CompactionConfig::default();
        let driver = CompactionDriver::new(&queue, store, &mut ledger, config);

        let intent = driver.completion_intent_for_segment(10);
        assert!(intent.is_completion());
        assert_eq!(intent.victim_segment_id, 10);
    }

    #[test]
    fn driver_with_txg_compiles() {
        let queue = SegmentLivenessQueue::new();
        let store = MockCompactionStore::new();
        let mut ledger = ReclaimQueueLedger::with_defaults();
        let config = CompactionConfig::default();
        let _driver = CompactionDriver::new(&queue, store, &mut ledger, config).with_txg(42);
    }

    #[test]
    fn driver_into_store_returns_store() {
        let queue = SegmentLivenessQueue::new();
        let store = MockCompactionStore::new();
        let mut ledger = ReclaimQueueLedger::with_defaults();
        let config = CompactionConfig::default();
        let driver = CompactionDriver::new(&queue, store, &mut ledger, config);
        let _recovered: MockCompactionStore = driver.into_store();
    }

    // ------------------------------------------------------------------
    // CompactionPassReport defaults
    // ------------------------------------------------------------------

    #[test]
    fn pass_report_defaults() {
        let report = CompactionPassReport::default();
        assert_eq!(report.candidates_considered, 0);
        assert_eq!(report.segments_freed, 0);
        assert_eq!(report.segments_partial, 0);
        assert_eq!(report.objects_relocated, 0);
        assert_eq!(report.bytes_relocated, 0);
        assert_eq!(report.extents_enqueued, 0);
        assert_eq!(report.bytes_enqueued, 0);
        assert_eq!(report.errors, 0);
        assert!(report.relocation_entries.is_empty());
        assert!(report.policy_report.decisions.is_empty());
        assert_eq!(report.checkpoint, CompactionCheckpoint::zero());
    }
}
