#![forbid(unsafe_code)]

//! DataCleanerService: **model / library surface** for reclaim-queue draining.
//!
//! # Status
//!
//! This crate is a model IncrementalJob implementation. It is **not wired**
//! into the mounted product path (LocalFileSystem, LocalObjectStore, FUSE,
//! storage-node, or kernel-cutover runtime).
//!
//! The live mounted-pool reclaim authority is
//! `LocalObjectStore::drain_dead_segments` in `tidefs-local-object-store`,
//! which owns the durable reclaim queue, SegmentLiveCounts, segment
//! resolution, spacemap checkpointing, and segment-liveness persistence.
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
//!       ├── detect zero-refcount segments
//!       └── free segments (via DataCleanerFreer)
//! ```
//!
//! ## Resume limitation
//!
//! `IncrementalJob::resume()` rebuilds with an empty queue, empty live
//! counts, no resolver, and no freer — it cannot perform useful reclaim
//! work. Production wiring requires injecting a real queue, live counts,
//! resolver, and freer via `DataCleanerService::new()` before stepping.
//!
//! ## When to wire
//!
//! Wire this crate into the mounted runtime only after:
//!
//! 1. The `resume()` path receives the durable reclaim queue, live counts,
//!    resolver, and freer from the caller (or from persistent storage).
//! 2. The service is registered in `BackgroundScheduler` in
//!    `LocalFileSystem::open()` or `LocalObjectStore` open path.
//! 3. The `DataCleanerResolver` and `DataCleanerFreer` trait objects are
//!    backed by real index/allocator implementations.
//! 4. Integration tests confirm end-to-end reclaim with crash-restart
//!    resume.

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
// DataCleanerFreer — object-safe segment freeing
// ---------------------------------------------------------------------------

/// Frees a physical segment, returning its blocks to the free pool.
pub trait DataCleanerFreer: Send {
    /// Release a segment back to the free pool. Must be idempotent.
    ///
    /// Returns `Err(msg)` on failure.
    fn free_segment(&mut self, segment_id: u64) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// DataCleanerStats
// ---------------------------------------------------------------------------

/// Accumulated statistics for the DataCleanerService.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DataCleanerStats {
    /// Total refcount deltas processed since job start.
    pub deltas_processed: u64,
    /// Number of segments freed (refcount reached zero).
    pub segments_freed: u64,
    /// Estimated bytes reclaimed (segments_freed × estimated segment size).
    pub bytes_reclaimed: u64,
    /// Number of segments whose refcount is still non-zero.
    pub segments_retained: u64,
}

impl DataCleanerStats {
    /// Zero-valued stats.
    pub const ZERO: Self = Self {
        deltas_processed: 0,
        segments_freed: 0,
        bytes_reclaimed: 0,
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

/// IncrementalJob that drains the reclaim queue and frees zero-refcount
/// segments.
///
/// # Lifecycle
///
/// 1. `resume(None)`: creates a fresh job from a queue and live-counts.
/// 2. `step(budget)`: dequeues up to `budget.max_items` entries,
///    resolves each to its segment, applies the refcount delta, and
///    frees fully-dead segments.
/// 3. `persist_checkpoint(cp)`: no-op (caller handles persistence).
/// 4. `complete()`: no-op.
pub struct DataCleanerService {
    job_id: JobId,
    queue: BPlusTreeReclaimQueue,
    live_counts: SegmentLiveCounts,
    cursor: Option<ObjectKey>,
    stats: DataCleanerStats,
    segment_bytes: u64,
    resolver: Option<Box<dyn DataCleanerResolver>>,
    freer: Option<Box<dyn DataCleanerFreer>>,
}

impl DataCleanerService {
    /// Create a fresh DataCleanerService.
    ///
    /// `queue`: the reclaim queue to drain.
    /// `live_counts`: initial per-segment live object counts (populated
    /// from the extent map or locator table).
    /// `segment_bytes`: approximate bytes per segment for stats.
    /// `resolver`: optional segment resolver; if `None`, segment
    /// resolution is skipped and only cursor advancement occurs.
    /// `freer`: optional segment freer; if `None`, freeing is skipped.
    #[must_use]
    pub fn new(
        queue: BPlusTreeReclaimQueue,
        live_counts: SegmentLiveCounts,
        segment_bytes: u64,
        resolver: Option<Box<dyn DataCleanerResolver>>,
        freer: Option<Box<dyn DataCleanerFreer>>,
    ) -> Self {
        Self {
            job_id: JobId::NONE,
            queue,
            live_counts,
            cursor: None,
            stats: DataCleanerStats::ZERO,
            segment_bytes,
            resolver,
            freer,
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
                        segments_freed: 0,
                        bytes_reclaimed: cp.progress.bytes_processed,
                        segments_retained: 0,
                    },
                    segment_bytes: 0,
                    resolver: None,
                    freer: None,
                })
            }
            None => Ok(DataCleanerService {
                job_id: JobId::NONE,
                queue: BPlusTreeReclaimQueue::new(),
                live_counts: SegmentLiveCounts::new(),
                cursor: None,
                stats: DataCleanerStats::ZERO,
                segment_bytes: 0,
                resolver: None,
                freer: None,
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
                    bytes_processed: self.stats.bytes_reclaimed,
                    bytes_total_estimate: self.stats.bytes_reclaimed,
                    elapsed_ms: 0,
                },
            };
            return Ok(StepResult::complete(checkpoint));
        }

        for (obj_key, entry) in &entries {
            self.stats.deltas_processed += 1;

            // Resolve object key to segment id, if resolver is available
            let segment_id = match &self.resolver {
                Some(resolver) => match resolver.resolve(obj_key) {
                    Ok(Some(sid)) => Some(sid),
                    Ok(None) => None,
                    Err(_) => None,
                },
                None => None,
            };

            // Apply refcount delta to the segment's live count
            if let Some(sid) = segment_id {
                let new_count = self.live_counts.apply_delta(sid, entry.delta);

                // If refcount reached zero, try to free the segment
                if new_count == 0 {
                    if let Some(freer) = &mut self.freer {
                        if freer.free_segment(sid).is_ok() {
                            self.live_counts.remove(sid);
                            self.stats.segments_freed += 1;
                            self.stats.bytes_reclaimed += self.segment_bytes;
                            continue;
                        }
                    }
                    // Free failed or no freer: retain with count=1 so it
                    // stays tracked for next attempt
                    self.live_counts.set_live_count(sid, 1);
                }
            }
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
                bytes_processed: self.stats.bytes_reclaimed,
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

    /// Mock freer: records freed segments.
    struct MockFreer {
        freed: Vec<u64>,
    }
    impl MockFreer {
        fn new() -> Self {
            Self { freed: Vec::new() }
        }
    }
    impl DataCleanerFreer for MockFreer {
        fn free_segment(&mut self, segment_id: u64) -> Result<(), String> {
            self.freed.push(segment_id);
            Ok(())
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
        assert_eq!(s.segments_freed, 0);
        assert_eq!(s.bytes_reclaimed, 0);
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

    // ── step() cursor advance (no resolver/freer) ─────────────────────

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

    // ── step() with resolver and freer ────────────────────────────────

    #[test]
    fn step_with_resolver_and_freer_frees_dead_segments() {
        let mut queue = BPlusTreeReclaimQueue::new();
        queue.insert(entry(1, -1));
        queue.insert(entry(2, -1));
        queue.insert(entry(3, -1));

        let mut counts = SegmentLiveCounts::new();
        counts.set_live_count(101, 1);
        counts.set_live_count(102, 1);
        counts.set_live_count(103, 1);

        let mut svc = DataCleanerService::new(
            queue,
            counts,
            4096,
            Some(Box::new(MockResolver) as Box<dyn DataCleanerResolver>),
            Some(Box::new(MockFreer::new()) as Box<dyn DataCleanerFreer>),
        );

        let budget = WorkBudget {
            max_items: 10,
            ..WorkBudget::default()
        };

        let result = svc.step(budget).unwrap();
        assert!(result.is_complete);
        assert_eq!(svc.stats().deltas_processed, 3);
        assert_eq!(svc.stats().segments_freed, 3);
        assert_eq!(svc.stats().bytes_reclaimed, 3 * 4096);
        assert_eq!(svc.stats().segments_retained, 0);
    }

    #[test]
    fn step_with_refcount_increment_does_not_free() {
        let mut queue = BPlusTreeReclaimQueue::new();
        queue.insert(entry(1, 5));

        let mut counts = SegmentLiveCounts::new();
        counts.set_live_count(101, 1);

        let _resolver: Box<dyn DataCleanerResolver> = Box::new(MockResolver);
        let _freer: Box<dyn DataCleanerFreer> = Box::new(MockFreer::new());
        let mut svc = DataCleanerService::new(queue, counts, 4096, Some(_resolver), Some(_freer));

        svc.step(WorkBudget::DEFAULT_TICK).unwrap();
        assert_eq!(svc.stats().segments_freed, 0);
        assert_eq!(svc.live_counts().live_count(101), 6);
    }

    // ── resume from checkpoint ───────────────────────────────────────

    #[test]
    fn resume_from_checkpoint_restores_cursor() {
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
