// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! DataCleanerService: **model / library surface** for reclaim-queue draining.
//!
//! # Status
//!
//! This crate is a model IncrementalJob implementation. It is **not wired**
//! into the mounted product path (LocalFileSystem, LocalObjectStore, FUSE,
//! storage-node, or kernel-cutover runtime).
//!
//! Live mounted-pool physical reclaim requires the receipt-bound dead-object
//! drain in `tidefs-local-object-store`. `LocalObjectStore::drain_dead_segments`
//! only inspects the older reclaim queue and fails closed without committed
//! clearance evidence.
//!
//! ## Model Architecture
//!
//! ```text
//! ReclaimQueue (B+tree keyed by ObjectKey)
//!       │
//!       │ dequeue batch (bounded by WorkBudget)
//!       ▼
//!   DataCleanerService::step()
//!       │
//!       ├── resolve ObjectKey → segment_id (via DataCleanerResolver)
//!       ├── apply refcount delta → SegmentLiveCounts
//!       └── record durable liveness/deadlist handoff evidence
//!           (via DataCleanerHandoffSink)
//! ```
//!
//! ## Resume limitation
//!
//! `IncrementalJob::resume()` rebuilds with an empty queue, empty live
//! counts, no resolver, and no handoff sink -- it cannot perform useful
//! reclaim work. Production wiring requires injecting a durable reclaim
//! queue, durable liveness state, resolver, and handoff sink via
//! `DataCleanerService::new()` before stepping.
//!
//! ## When to wire
//!
//! Wire this crate into the mounted runtime only after:
//!
//! 1. The `resume()` path receives the durable reclaim queue, live counts,
//!    resolver, and handoff sink from the caller (or from persistent storage).
//! 2. The service is registered in `BackgroundScheduler` in
//!    `LocalFileSystem::open()` or `LocalObjectStore` open path.
//! 3. The `DataCleanerResolver` and `DataCleanerHandoffSink` trait objects are
//!    backed by real locator/deadlist/liveness implementations.
//! 4. Integration tests confirm end-to-end reclaim with crash-restart
//!    resume.

use tidefs_cleanup_job_core::{
    CleanupReceiptValidationTier, CleanupWorkItemId, ReclaimEvidenceProducer,
    ReclaimEvidenceRefusal, ReclaimEvidenceRefusalReason,
};
use tidefs_incremental_job_core::IncrementalJob;
use tidefs_reclaim::SegmentLiveCounts;
use tidefs_reclaim_queue_core::BPlusTreeReclaimQueue;
use tidefs_types_incremental_job_core::{
    Checkpoint, CursorState, JobError, JobId, JobKind, JobProgress, StepResult, WorkBudget,
};
use tidefs_types_reclaim_queue_core::ObjectKey;

// ---------------------------------------------------------------------------
// DataCleanerResolver — object-safe segment resolution
// ---------------------------------------------------------------------------

/// Resolves an [`ObjectKey`] to a segment identifier so the data cleaner
/// can track per-segment refcount deltas.
pub trait DataCleanerResolver: Send {
    /// Map an object key to its owning segment, if known.
    ///
    /// Returns `Ok(None)` when the object is not currently tracked.
    /// Returns `Err(msg)` on resolution failure.
    fn resolve(&self, key: &ObjectKey) -> Result<Option<u64>, String>;
}

// ---------------------------------------------------------------------------
// DataCleanerHandoffSink -- object-safe durable handoff recording
// ---------------------------------------------------------------------------

/// Handoff state produced after a refcount delta is drained.
///
/// These records are the data-cleaner boundary with segment cleaner and
/// compaction: they describe liveness/deadlist state that another authority
/// may consume later. They do not authorize physical segment release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataCleanerHandoffState {
    /// The segment still has live references and remains liveness input.
    Liveness { live_refs: u64 },
    /// The drained object/segment transition reached zero live references and
    /// must be handed to the deadlist/cleaner path before any physical release.
    Deadlist,
}

/// Durable handoff evidence emitted by [`DataCleanerService`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataCleanerHandoff {
    /// Object whose refcount delta was drained.
    pub object_key: ObjectKey,
    /// Segment resolved from the object key.
    pub segment_id: u64,
    /// Refcount delta applied to the segment liveness state.
    pub delta: i64,
    /// Live references remaining after the delta was applied.
    pub live_refs_after: u64,
    /// Handoff state consumed by downstream liveness/deadlist authorities.
    pub state: DataCleanerHandoffState,
}

impl DataCleanerHandoff {
    /// Create a liveness handoff for a segment that remains live.
    #[must_use]
    pub const fn liveness(
        object_key: ObjectKey,
        segment_id: u64,
        delta: i64,
        live_refs_after: u64,
    ) -> Self {
        Self {
            object_key,
            segment_id,
            delta,
            live_refs_after,
            state: DataCleanerHandoffState::Liveness {
                live_refs: live_refs_after,
            },
        }
    }

    /// Create a deadlist handoff for a zero-refcount transition.
    #[must_use]
    pub const fn deadlist(object_key: ObjectKey, segment_id: u64, delta: i64) -> Self {
        Self {
            object_key,
            segment_id,
            delta,
            live_refs_after: 0,
            state: DataCleanerHandoffState::Deadlist,
        }
    }

    /// Returns `true` when this record is deadlist handoff evidence.
    #[must_use]
    pub const fn is_deadlist(self) -> bool {
        match self.state {
            DataCleanerHandoffState::Deadlist => true,
            DataCleanerHandoffState::Liveness { .. } => false,
        }
    }

    /// Explain why this handoff is not committed physical reclaim evidence.
    ///
    /// Data cleaner handoffs publish liveness/deadlist state for downstream
    /// cleaner authorities. They do not prove that allocator blocks or object
    /// store segments were physically released.
    #[must_use]
    pub const fn committed_reclaim_refusal(
        self,
        job_id: JobId,
        estimated_bytes: u64,
        validation_tier: CleanupReceiptValidationTier,
    ) -> ReclaimEvidenceRefusal {
        ReclaimEvidenceRefusal::new(
            ReclaimEvidenceProducer::DataCleaner,
            job_id,
            CleanupWorkItemId::NONE,
            ReclaimEvidenceRefusalReason::ModelOnlyDrain,
            estimated_bytes,
            1,
            validation_tier,
        )
    }
}

/// Persists liveness/deadlist handoff evidence from drained refcount deltas.
pub trait DataCleanerHandoffSink: Send {
    /// Record a handoff in durable liveness/deadlist state.
    ///
    /// Implementations must make this idempotent across checkpoint replay.
    fn record_handoff(&mut self, handoff: DataCleanerHandoff);
}

// ---------------------------------------------------------------------------
// DataCleanerStats
// ---------------------------------------------------------------------------

/// Accumulated statistics for the DataCleanerService.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DataCleanerStats {
    /// Total refcount deltas processed since job start.
    pub deltas_processed: u64,
    /// Number of liveness handoff records produced for still-live segments.
    pub liveness_handoffs: u64,
    /// Number of deadlist handoff records produced for zero-refcount transitions.
    pub deadlist_handoffs: u64,
    /// Estimated bytes represented by deadlist handoff records.
    pub deadlist_bytes_estimate: u64,
    /// Number of segments whose refcount is still non-zero.
    pub segments_retained: u64,
}

impl DataCleanerStats {
    /// Zero-valued stats.
    pub const ZERO: Self = Self {
        deltas_processed: 0,
        liveness_handoffs: 0,
        deadlist_handoffs: 0,
        deadlist_bytes_estimate: 0,
        segments_retained: 0,
    };
}

// ---------------------------------------------------------------------------
// Cursor encoding helpers
// ---------------------------------------------------------------------------

/// Encode the last-processed ObjectKey into cursor state bytes.
///
/// Format: 32 bytes of the ObjectKey, or empty for start-of-queue.
fn encode_cursor(key: Option<&ObjectKey>) -> CursorState {
    match key {
        None => CursorState::empty(),
        Some(k) => CursorState(k.0.to_vec()),
    }
}

/// Decode a cursor state back into an Option<ObjectKey>.
fn decode_cursor(state: &CursorState) -> Option<ObjectKey> {
    if state.is_empty() || state.len() < 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&state.as_bytes()[..32]);
    Some(ObjectKey(key))
}

// ---------------------------------------------------------------------------
// DataCleanerService
// ---------------------------------------------------------------------------

/// IncrementalJob that drains the reclaim queue into liveness/deadlist
/// handoff state.
///
/// # Lifecycle
///
/// 1. `resume(None)`: creates a fresh job from a queue and live-counts.
/// 2. `step(budget)`: dequeues up to `budget.max_items` entries,
///    resolves each to its segment, applies the refcount delta, and
///    records liveness or deadlist handoff evidence.
/// 3. `persist_checkpoint(cp)`: no-op (caller handles persistence).
/// 4. `complete()`: no-op.
pub struct DataCleanerService {
    job_id: JobId,
    queue: BPlusTreeReclaimQueue,
    live_counts: SegmentLiveCounts,
    cursor: Option<ObjectKey>,
    stats: DataCleanerStats,
    segment_bytes_estimate: u64,
    resolver: Option<Box<dyn DataCleanerResolver>>,
    handoff_sink: Option<Box<dyn DataCleanerHandoffSink>>,
}

impl DataCleanerService {
    /// Create a fresh DataCleanerService.
    ///
    /// `queue`: the reclaim queue to drain.
    /// `live_counts`: initial per-segment live object counts (populated
    /// from the extent map or locator table).
    /// `segment_bytes_estimate`: approximate bytes per segment for handoff
    /// stats.
    /// `resolver`: optional segment resolver; if `None`, segment
    /// resolution is skipped and only cursor advancement occurs.
    /// `handoff_sink`: optional durable sink; if `None`, handoff recording is
    /// skipped and only cursor/live-count state advances.
    #[must_use]
    pub fn new(
        queue: BPlusTreeReclaimQueue,
        live_counts: SegmentLiveCounts,
        segment_bytes_estimate: u64,
        resolver: Option<Box<dyn DataCleanerResolver>>,
        handoff_sink: Option<Box<dyn DataCleanerHandoffSink>>,
    ) -> Self {
        Self {
            job_id: JobId::NONE,
            queue,
            live_counts,
            cursor: None,
            stats: DataCleanerStats::ZERO,
            segment_bytes_estimate,
            resolver,
            handoff_sink,
        }
    }

    /// Create a fresh DataCleanerService with `JobId`.
    #[must_use]
    pub fn with_job_id(mut self, job_id: JobId) -> Self {
        self.job_id = job_id;
        self
    }

    /// Current statistics.
    #[must_use]
    pub fn stats(&self) -> DataCleanerStats {
        self.stats
    }

    /// Source evidence that current data-cleaner progress is model-only.
    ///
    /// Deadlist byte totals here remain estimates until a downstream cleaner
    /// emits committed physical reclaim evidence.
    #[must_use]
    pub const fn reclaim_progress_refusal(
        &self,
        validation_tier: CleanupReceiptValidationTier,
    ) -> ReclaimEvidenceRefusal {
        ReclaimEvidenceRefusal::new(
            ReclaimEvidenceProducer::DataCleaner,
            self.job_id,
            CleanupWorkItemId::NONE,
            ReclaimEvidenceRefusalReason::ModelOnlyDrain,
            self.stats.deadlist_bytes_estimate,
            self.stats.deadlist_handoffs,
            validation_tier,
        )
    }

    /// Reference to the live-counts tracker.
    #[must_use]
    pub fn live_counts(&self) -> &SegmentLiveCounts {
        &self.live_counts
    }

    /// Mutable reference to the live-counts tracker.
    pub fn live_counts_mut(&mut self) -> &mut SegmentLiveCounts {
        &mut self.live_counts
    }
}

impl IncrementalJob for DataCleanerService {
    fn resume(state: Option<Checkpoint>) -> Result<Self, JobError>
    where
        Self: Sized,
    {
        match state {
            Some(cp) => {
                let cursor = decode_cursor(&cp.cursor_state);
                Ok(DataCleanerService {
                    job_id: cp.job_id,
                    queue: BPlusTreeReclaimQueue::new(),
                    live_counts: SegmentLiveCounts::new(),
                    cursor,
                    stats: DataCleanerStats {
                        deltas_processed: cp.progress.items_processed,
                        liveness_handoffs: 0,
                        deadlist_handoffs: 0,
                        deadlist_bytes_estimate: cp.progress.bytes_processed,
                        segments_retained: 0,
                    },
                    segment_bytes_estimate: 0,
                    resolver: None,
                    handoff_sink: None,
                })
            }
            None => Ok(DataCleanerService {
                job_id: JobId::NONE,
                queue: BPlusTreeReclaimQueue::new(),
                live_counts: SegmentLiveCounts::new(),
                cursor: None,
                stats: DataCleanerStats::ZERO,
                segment_bytes_estimate: 0,
                resolver: None,
                handoff_sink: None,
            }),
        }
    }

    fn step(&mut self, budget: WorkBudget) -> Result<StepResult, JobError> {
        let limit = if budget.max_items > 0 {
            (budget.max_items as usize).min(1024)
        } else {
            1024
        };

        let entries = self.queue.dequeue_batch(self.cursor.as_ref(), limit);

        if entries.is_empty() {
            let checkpoint = Checkpoint {
                job_id: self.job_id,
                job_kind: JobKind::DataCleaner,
                epoch: 1,
                cursor_state: encode_cursor(self.cursor.as_ref()),
                progress: JobProgress {
                    items_processed: self.stats.deltas_processed,
                    items_total_estimate: self.stats.deltas_processed,
                    bytes_processed: self.stats.deadlist_bytes_estimate,
                    bytes_total_estimate: self.stats.deadlist_bytes_estimate,
                    elapsed_ms: 0,
                },
            };
            return Ok(StepResult::complete(checkpoint));
        }

        for (obj_key, entry) in &entries {
            // Resolve object key to segment id, if resolver is available
            let segment_id = match &self.resolver {
                Some(resolver) => match resolver.resolve(obj_key) {
                    Ok(Some(sid)) => Some(sid),
                    Ok(None) => None,
                    Err(_) => None,
                },
                None => None,
            };

            if let Some(sid) = segment_id {
                let live_refs_before = self.live_counts.live_count(sid);
                if entry.delta < 0 && live_refs_before < entry.delta.unsigned_abs() {
                    return Err(JobError::Other(format!(
                        "data-cleaner refcount underflow: segment={sid} live_refs={live_refs_before} delta={}",
                        entry.delta
                    )));
                }

                let new_count = self.live_counts.apply_delta(sid, entry.delta);
                let handoff = if new_count == 0 {
                    self.stats.deadlist_handoffs += 1;
                    self.stats.deadlist_bytes_estimate = self
                        .stats
                        .deadlist_bytes_estimate
                        .saturating_add(self.segment_bytes_estimate);
                    DataCleanerHandoff::deadlist(*obj_key, sid, entry.delta)
                } else {
                    self.stats.liveness_handoffs += 1;
                    DataCleanerHandoff::liveness(*obj_key, sid, entry.delta, new_count)
                };

                if let Some(sink) = &mut self.handoff_sink {
                    sink.record_handoff(handoff);
                }
            }

            self.stats.deltas_processed += 1;
        }

        // Advance cursor to last processed entry
        if let Some((last_key, _)) = entries.last() {
            self.cursor = Some(*last_key);
        }

        self.stats.segments_retained = self.live_counts.len() as u64;
        let is_complete = self.queue.dequeue_batch(self.cursor.as_ref(), 1).is_empty();

        let checkpoint = Checkpoint {
            job_id: self.job_id,
            job_kind: JobKind::DataCleaner,
            epoch: 1,
            cursor_state: encode_cursor(self.cursor.as_ref()),
            progress: JobProgress {
                items_processed: self.stats.deltas_processed,
                items_total_estimate: 0,
                bytes_processed: self.stats.deadlist_bytes_estimate,
                bytes_total_estimate: 0,
                elapsed_ms: 0,
            },
        };

        if is_complete {
            Ok(StepResult::complete(checkpoint))
        } else {
            Ok(StepResult::in_progress(checkpoint))
        }
    }

    fn persist_checkpoint(&self, _checkpoint: &Checkpoint) -> Result<(), JobError> {
        Ok(())
    }

    fn complete(self) -> Result<(), JobError> {
        Ok(())
    }

    fn job_id(&self) -> JobId {
        self.job_id
    }

    fn job_kind(&self) -> JobKind {
        JobKind::DataCleaner
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tidefs_types_reclaim_queue_core::{QueueFamily, ReclaimQueueEntry};

    // ── Test helpers ──────────────────────────────────────────────────

    fn obj_key(id: u8) -> ObjectKey {
        let mut k = [0u8; 32];
        k[0] = id;
        ObjectKey(k)
    }

    fn entry(id: u8, delta: i64) -> ReclaimQueueEntry {
        ReclaimQueueEntry::new(obj_key(id), delta, QueueFamily::Extent)
    }

    /// Mock resolver: maps ObjectKey byte 0 → segment ID 100 + byte 0.
    struct MockResolver;
    impl DataCleanerResolver for MockResolver {
        fn resolve(&self, key: &ObjectKey) -> Result<Option<u64>, String> {
            Ok(Some(100 + key.0[0] as u64))
        }
    }

    /// Mock handoff sink: records liveness/deadlist handoff evidence.
    #[derive(Clone, Default)]
    struct MockHandoffSink {
        handoffs: Arc<Mutex<Vec<DataCleanerHandoff>>>,
    }

    impl MockHandoffSink {
        fn new() -> Self {
            Self::default()
        }

        fn handoffs(&self) -> Vec<DataCleanerHandoff> {
            self.handoffs.lock().unwrap().clone()
        }
    }

    impl DataCleanerHandoffSink for MockHandoffSink {
        fn record_handoff(&mut self, handoff: DataCleanerHandoff) {
            self.handoffs.lock().unwrap().push(handoff);
        }
    }

    // ── Cursor encoding round-trip ────────────────────────────────────

    #[test]
    fn cursor_roundtrip_empty() {
        let encoded = encode_cursor(None);
        assert!(encoded.is_empty());
        let decoded = decode_cursor(&encoded);
        assert!(decoded.is_none());
    }

    #[test]
    fn cursor_roundtrip_some() {
        let key = obj_key(42);
        let encoded = encode_cursor(Some(&key));
        let decoded = decode_cursor(&encoded);
        assert_eq!(decoded, Some(key));
    }

    #[test]
    fn cursor_decode_short_data_returns_none() {
        let short = CursorState(vec![0xAA]);
        assert!(decode_cursor(&short).is_none());
    }

    // ── DataCleanerStats ──────────────────────────────────────────────

    #[test]
    fn stats_zero() {
        let s = DataCleanerStats::ZERO;
        assert_eq!(s.deltas_processed, 0);
        assert_eq!(s.liveness_handoffs, 0);
        assert_eq!(s.deadlist_handoffs, 0);
        assert_eq!(s.deadlist_bytes_estimate, 0);
        assert_eq!(s.segments_retained, 0);
    }

    // ── Construction ──────────────────────────────────────────────────

    #[test]
    fn service_new_has_empty_queue_and_counts() {
        let queue = BPlusTreeReclaimQueue::new();
        let counts = SegmentLiveCounts::new();
        let svc = DataCleanerService::new(queue, counts, 4096, None, None);
        assert_eq!(svc.job_id(), JobId::NONE);
        assert_eq!(svc.job_kind(), JobKind::DataCleaner);
        assert_eq!(svc.stats(), DataCleanerStats::ZERO);
        assert!(svc.live_counts().is_empty());
    }

    #[test]
    fn service_with_job_id() {
        let queue = BPlusTreeReclaimQueue::new();
        let counts = SegmentLiveCounts::new();
        let svc = DataCleanerService::new(queue, counts, 8192, None, None).with_job_id(JobId(77));
        assert_eq!(svc.job_id(), JobId(77));
    }

    // ── step() cursor advance (no resolver/sink) ──────────────────────

    #[test]
    fn step_advances_cursor_through_queue() {
        let mut queue = BPlusTreeReclaimQueue::new();
        for i in 0..10u8 {
            queue.insert(entry(i, -1));
        }
        let counts = SegmentLiveCounts::new();
        let mut svc = DataCleanerService::new(queue, counts, 4096, None, None);

        let budget = WorkBudget {
            max_items: 3,
            ..WorkBudget::default()
        };

        let result = svc.step(budget).unwrap();
        assert!(!result.is_complete);
        let decoded = decode_cursor(&result.checkpoint.cursor_state);
        assert_eq!(decoded, Some(obj_key(2)));
        assert_eq!(svc.stats().deltas_processed, 3);
    }

    #[test]
    fn step_exhausts_queue_and_completes() {
        let mut queue = BPlusTreeReclaimQueue::new();
        for i in 0..5u8 {
            queue.insert(entry(i, -1));
        }
        let counts = SegmentLiveCounts::new();
        let mut svc = DataCleanerService::new(queue, counts, 4096, None, None);

        let budget = WorkBudget {
            max_items: 100,
            ..WorkBudget::default()
        };

        let result = svc.step(budget).unwrap();
        assert!(result.is_complete);
        assert_eq!(svc.stats().deltas_processed, 5);
    }

    #[test]
    fn step_empty_queue_completes_immediately() {
        let queue = BPlusTreeReclaimQueue::new();
        let counts = SegmentLiveCounts::new();
        let mut svc = DataCleanerService::new(queue, counts, 4096, None, None);

        let result = svc.step(WorkBudget::DEFAULT_TICK).unwrap();
        assert!(result.is_complete);
        assert_eq!(svc.stats().deltas_processed, 0);
    }

    // ── step() with resolver and handoff sink ─────────────────────────

    #[test]
    fn step_with_resolver_records_deadlist_handoffs() {
        let mut queue = BPlusTreeReclaimQueue::new();
        queue.insert(entry(1, -1));
        queue.insert(entry(2, -1));
        queue.insert(entry(3, -1));

        let mut counts = SegmentLiveCounts::new();
        counts.set_live_count(101, 1);
        counts.set_live_count(102, 1);
        counts.set_live_count(103, 1);

        let sink = MockHandoffSink::new();
        let mut svc = DataCleanerService::new(
            queue,
            counts,
            4096,
            Some(Box::new(MockResolver) as Box<dyn DataCleanerResolver>),
            Some(Box::new(sink.clone()) as Box<dyn DataCleanerHandoffSink>),
        )
        .with_job_id(JobId(9));

        let budget = WorkBudget {
            max_items: 10,
            ..WorkBudget::default()
        };

        let result = svc.step(budget).unwrap();
        assert!(result.is_complete);
        assert_eq!(svc.stats().deltas_processed, 3);
        assert_eq!(svc.stats().deadlist_handoffs, 3);
        assert_eq!(svc.stats().liveness_handoffs, 0);
        assert_eq!(svc.stats().deadlist_bytes_estimate, 3 * 4096);
        assert_eq!(svc.stats().segments_retained, 0);
        let handoffs = sink.handoffs();
        assert_eq!(
            handoffs,
            vec![
                DataCleanerHandoff::deadlist(obj_key(1), 101, -1),
                DataCleanerHandoff::deadlist(obj_key(2), 102, -1),
                DataCleanerHandoff::deadlist(obj_key(3), 103, -1),
            ]
        );

        let handoff_refusal = handoffs[0].committed_reclaim_refusal(
            JobId(9),
            4096,
            CleanupReceiptValidationTier::CargoUnit,
        );
        assert_eq!(
            handoff_refusal.producer,
            ReclaimEvidenceProducer::DataCleaner
        );
        assert_eq!(
            handoff_refusal.reason,
            ReclaimEvidenceRefusalReason::ModelOnlyDrain
        );
        assert_eq!(handoff_refusal.estimated_bytes, 4096);
        assert!(!handoff_refusal.is_committed_physical_reclaim());

        let progress_refusal =
            svc.reclaim_progress_refusal(CleanupReceiptValidationTier::CargoUnit);
        assert_eq!(progress_refusal.job_id, JobId(9));
        assert_eq!(progress_refusal.estimated_bytes, 3 * 4096);
        assert_eq!(progress_refusal.units, 3);
        assert!(!progress_refusal.is_committed_physical_reclaim());
    }

    #[test]
    fn step_with_refcount_increment_records_liveness_handoff() {
        let mut queue = BPlusTreeReclaimQueue::new();
        queue.insert(entry(1, 5));

        let mut counts = SegmentLiveCounts::new();
        counts.set_live_count(101, 1);

        let resolver: Box<dyn DataCleanerResolver> = Box::new(MockResolver);
        let sink = MockHandoffSink::new();
        let mut svc = DataCleanerService::new(
            queue,
            counts,
            4096,
            Some(resolver),
            Some(Box::new(sink.clone()) as Box<dyn DataCleanerHandoffSink>),
        );

        svc.step(WorkBudget::DEFAULT_TICK).unwrap();
        assert_eq!(svc.stats().deadlist_handoffs, 0);
        assert_eq!(svc.stats().liveness_handoffs, 1);
        assert_eq!(svc.live_counts().live_count(101), 6);
        assert_eq!(
            sink.handoffs(),
            vec![DataCleanerHandoff::liveness(obj_key(1), 101, 5, 6)]
        );
    }

    #[test]
    fn refcount_underflow_does_not_emit_deadlist_handoff() {
        let mut queue = BPlusTreeReclaimQueue::new();
        queue.insert(entry(1, -5));

        let mut counts = SegmentLiveCounts::new();
        counts.set_live_count(101, 1);

        let sink = MockHandoffSink::new();
        let mut svc = DataCleanerService::new(
            queue,
            counts,
            4096,
            Some(Box::new(MockResolver) as Box<dyn DataCleanerResolver>),
            Some(Box::new(sink.clone()) as Box<dyn DataCleanerHandoffSink>),
        );

        let err = svc.step(WorkBudget::DEFAULT_TICK).unwrap_err();
        assert!(matches!(err, JobError::Other(msg) if msg.contains("underflow")));
        assert!(sink.handoffs().is_empty());
        assert_eq!(svc.stats().deltas_processed, 0);
        assert_eq!(svc.live_counts().live_count(101), 1);
    }

    // ── resume from checkpoint ───────────────────────────────────────

    #[test]
    fn resume_from_checkpoint_restores_cursor_and_requires_injected_state() {
        let mut queue = BPlusTreeReclaimQueue::new();
        for i in 0..20u8 {
            queue.insert(entry(i, -1));
        }
        let counts = SegmentLiveCounts::new();
        let mut svc = DataCleanerService::new(queue, counts, 4096, None, None);

        let budget = WorkBudget {
            max_items: 5,
            ..WorkBudget::default()
        };
        let result = svc.step(budget).unwrap();
        let saved_cp = result.checkpoint.clone();

        let resumed = DataCleanerService::resume(Some(saved_cp)).unwrap();
        assert_eq!(resumed.stats.deltas_processed, 5);
        assert_eq!(resumed.cursor, Some(obj_key(4)));
        assert!(resumed.live_counts().is_empty());
        assert!(resumed.resolver.is_none());
        assert!(resumed.handoff_sink.is_none());
    }

    // ── live_counts integration ──────────────────────────────────────

    #[test]
    fn live_counts_tracks_segment_refs() {
        let mut counts = SegmentLiveCounts::new();
        counts.set_live_count(100, 3);
        assert_eq!(counts.live_count(100), 3);

        counts.apply_delta(100, -1);
        assert_eq!(counts.live_count(100), 2);

        counts.apply_delta(100, -2);
        assert_eq!(counts.live_count(100), 0);
        assert!(counts.is_dead(100));
    }

    #[test]
    fn live_counts_increment_refs() {
        let mut counts = SegmentLiveCounts::new();
        counts.apply_delta(200, 5);
        assert_eq!(counts.live_count(200), 5);

        counts.apply_delta(200, 3);
        assert_eq!(counts.live_count(200), 8);
    }

    #[test]
    fn live_counts_clamp_at_zero() {
        let mut counts = SegmentLiveCounts::new();
        counts.set_live_count(300, 1);
        counts.apply_delta(300, -5);
        assert!(counts.is_dead(300));
    }

    // ── trait object dispatch ─────────────────────────────────────────

    #[test]
    fn service_trait_object_dispatch() {
        let queue = BPlusTreeReclaimQueue::new();
        let counts = SegmentLiveCounts::new();
        let mut svc = DataCleanerService::new(queue, counts, 4096, None, None);
        let dyn_job: &mut dyn IncrementalJob = &mut svc;
        assert_eq!(dyn_job.job_kind(), JobKind::DataCleaner);
    }

    // ── budget respect ────────────────────────────────────────────────

    #[test]
    fn step_respects_budget_max_items() {
        let mut queue = BPlusTreeReclaimQueue::new();
        for i in 0..100u8 {
            queue.insert(entry(i, -1));
        }
        let counts = SegmentLiveCounts::new();
        let mut svc = DataCleanerService::new(queue, counts, 4096, None, None);

        let result = svc
            .step(WorkBudget {
                max_items: 7,
                ..WorkBudget::default()
            })
            .unwrap();

        assert_eq!(svc.stats.deltas_processed, 7);
        assert!(!result.is_complete);
    }

    // ── stats accumulation across steps ───────────────────────────────

    #[test]
    fn stats_accumulate_across_steps() {
        let mut queue = BPlusTreeReclaimQueue::new();
        for i in 0..20u8 {
            queue.insert(entry(i, -1));
        }
        let counts = SegmentLiveCounts::new();
        let mut svc = DataCleanerService::new(queue, counts, 4096, None, None);

        svc.step(WorkBudget {
            max_items: 10,
            ..WorkBudget::default()
        })
        .unwrap();
        assert_eq!(svc.stats.deltas_processed, 10);

        let result = svc
            .step(WorkBudget {
                max_items: 10,
                ..WorkBudget::default()
            })
            .unwrap();
        assert_eq!(svc.stats.deltas_processed, 20);
        assert!(result.is_complete);
    }
}
