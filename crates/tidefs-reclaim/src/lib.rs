// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Background segment reclaim pipeline for TideFS local object store.
//!
//! Two complementary facilities:
//!
//! 1. **Segment compaction** ([`ReclaimScheduler`], [`ReclaimPlan`]):
//!    waste-ratio-based compaction of partially-dead segments.
//!
//! 2. **Reclaim-queue consumer** ([`drain_reclaim_queue_gated`],
//!    [`ReclaimConsumerStats`]): drains entries populated by object
//!    delete and overwrite, groups them by segment, computes per-segment
//!    liveness, and returns fully-dead segments to the free pool.
//!
//! # Architecture
//!
//! ```text
//! ReclaimQueueEntry ──► SegmentResolver ──► group by segment
//!       │                                            │
//!       │                              SegmentLiveCounts (per-seg refs)
//!       │                                            │
//!       ▼                                            ▼
//!   drain_reclaim_queue_gated() ─► ReclaimGate ─► SegmentFreer
//! ```

#![forbid(unsafe_code)]

use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    fmt,
};

use tidefs_reclaim_queue_core::DeadObjectReclaimQueue;
use tidefs_types_reclaim_queue_core::{ObjectKey, ReclaimQueueEntry};

/// Configuration for the reclaim pipeline.
#[derive(Debug, Clone)]
pub struct ReclaimConfig {
    /// Waste ratio threshold: segments with waste_ratio above this are
    /// candidates for compaction. Default: 0.3 (30% waste).
    pub waste_threshold: f64,
    /// Maximum number of segments to compact in one batch.
    /// Default: 8.
    pub batch_size: usize,
    /// Minimum number of segment rotations between reclaim batches.
    /// Prevents reclaim from triggering on every rotation in a tight loop.
    /// Default: 4.
    pub cooldown_segments: usize,
}

impl Default for ReclaimConfig {
    fn default() -> Self {
        Self {
            waste_threshold: 0.3,
            batch_size: 8,
            cooldown_segments: 4,
        }
    }
}

/// Segment-level reclaim metrics supplied by the object store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReclaimSegment {
    /// Stable segment identifier used for deterministic tie-breaking.
    pub segment_id: u64,
    /// Bytes that must be retained if the segment is compacted.
    pub live_bytes: u64,
    /// Bytes that can be reclaimed by compacting the segment.
    pub reclaimable_bytes: u64,
}

impl ReclaimSegment {
    /// Create segment metrics for reclaim planning.
    pub const fn new(segment_id: u64, live_bytes: u64, reclaimable_bytes: u64) -> Self {
        Self {
            segment_id,
            live_bytes,
            reclaimable_bytes,
        }
    }

    /// Total accounted bytes in the segment.
    pub const fn total_bytes(&self) -> u128 {
        self.live_bytes as u128 + self.reclaimable_bytes as u128
    }

    /// Fraction of the segment that can be reclaimed.
    pub fn waste_ratio(&self) -> f64 {
        let total_bytes = self.total_bytes();
        if total_bytes == 0 {
            return 0.0;
        }

        self.reclaimable_bytes as f64 / total_bytes as f64
    }
}

/// A reclaim candidate selected for the next compaction batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReclaimCandidate {
    /// Stable segment identifier to compact.
    pub segment_id: u64,
    /// Bytes that must be copied forward before reclaiming the segment.
    pub live_bytes: u64,
    /// Bytes expected to be released by reclaiming the segment.
    pub reclaimable_bytes: u64,
}

impl ReclaimCandidate {
    /// Total accounted bytes in the candidate segment.
    pub const fn total_bytes(&self) -> u128 {
        self.live_bytes as u128 + self.reclaimable_bytes as u128
    }

    /// Fraction of the candidate segment expected to be reclaimed.
    pub fn waste_ratio(&self) -> f64 {
        let total_bytes = self.total_bytes();
        if total_bytes == 0 {
            return 0.0;
        }

        self.reclaimable_bytes as f64 / total_bytes as f64
    }
}

impl From<ReclaimSegment> for ReclaimCandidate {
    fn from(segment: ReclaimSegment) -> Self {
        Self {
            segment_id: segment.segment_id,
            live_bytes: segment.live_bytes,
            reclaimable_bytes: segment.reclaimable_bytes,
        }
    }
}

/// Deterministic reclaim plan for one compaction batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimPlan {
    /// Ordered candidates selected for this batch.
    pub candidates: Vec<ReclaimCandidate>,
    /// Sum of reclaimable bytes across selected candidates.
    pub total_reclaimable_bytes: u128,
}

impl ReclaimPlan {
    /// Whether the planner found no useful candidates.
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// Number of selected candidates.
    pub fn len(&self) -> usize {
        self.candidates.len()
    }
}

/// Reported result for one selected reclaim candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclaimCompletionOutcome {
    /// The segment was reclaimed successfully.
    Reclaimed { segment_id: u64 },
    /// The segment could not be reclaimed and should remain retryable.
    Failed { segment_id: u64 },
}

impl ReclaimCompletionOutcome {
    /// Segment id referenced by this outcome.
    pub const fn segment_id(&self) -> u64 {
        match self {
            Self::Reclaimed { segment_id } | Self::Failed { segment_id } => *segment_id,
        }
    }
}

/// Deterministic accounting for one completed reclaim batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimCompletionPlan {
    /// Candidates reported as successfully reclaimed, in selected candidate order.
    pub reclaimed_candidates: Vec<ReclaimCandidate>,
    /// Candidates reported as failed and retained, in selected candidate order.
    pub retained_failures: Vec<ReclaimCandidate>,
    /// Selected candidates without a reported completion outcome.
    pub pending_candidates: Vec<ReclaimCandidate>,
    /// Candidates that can be retried because they were not successfully reclaimed.
    pub retryable_candidates: Vec<ReclaimCandidate>,
    /// Sum of reclaimable bytes for successfully reclaimed candidates.
    pub total_reclaimed_bytes: u128,
}

/// Invalid reclaim completion input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclaimCompletionPlanError {
    /// A selected batch contained the same segment more than once.
    DuplicateSelectedCandidate { segment_id: u64 },
    /// More than one outcome was reported for the same selected segment.
    DuplicateOutcome { segment_id: u64 },
    /// An outcome referenced a segment that was not selected for this batch.
    UnplannedOutcome { segment_id: u64 },
}

/// Account for reported completion outcomes after a reclaim batch was selected.
///
/// The planner preserves selected candidate order in all output vectors. It
/// does not mutate lower storage state; callers can use the accounting result
/// to update scheduler and retry state after compaction attempts complete.
pub fn plan_reclaim_completion(
    selected_candidates: impl IntoIterator<Item = ReclaimCandidate>,
    outcomes: impl IntoIterator<Item = ReclaimCompletionOutcome>,
) -> Result<ReclaimCompletionPlan, ReclaimCompletionPlanError> {
    let selected_candidates: Vec<_> = selected_candidates.into_iter().collect();
    let mut selected_ids = HashSet::with_capacity(selected_candidates.len());

    for candidate in &selected_candidates {
        if !selected_ids.insert(candidate.segment_id) {
            return Err(ReclaimCompletionPlanError::DuplicateSelectedCandidate {
                segment_id: candidate.segment_id,
            });
        }
    }

    let mut outcome_by_segment_id = HashMap::with_capacity(selected_candidates.len());
    for outcome in outcomes {
        let segment_id = outcome.segment_id();
        if !selected_ids.contains(&segment_id) {
            return Err(ReclaimCompletionPlanError::UnplannedOutcome { segment_id });
        }
        if outcome_by_segment_id.insert(segment_id, outcome).is_some() {
            return Err(ReclaimCompletionPlanError::DuplicateOutcome { segment_id });
        }
    }

    let mut reclaimed_candidates = Vec::new();
    let mut retained_failures = Vec::new();
    let mut pending_candidates = Vec::new();
    let mut retryable_candidates = Vec::new();
    let mut total_reclaimed_bytes = 0_u128;

    for candidate in selected_candidates {
        match outcome_by_segment_id.get(&candidate.segment_id) {
            Some(ReclaimCompletionOutcome::Reclaimed { .. }) => {
                total_reclaimed_bytes += candidate.reclaimable_bytes as u128;
                reclaimed_candidates.push(candidate);
            }
            Some(ReclaimCompletionOutcome::Failed { .. }) => {
                retained_failures.push(candidate);
                retryable_candidates.push(candidate);
            }
            None => {
                pending_candidates.push(candidate);
                retryable_candidates.push(candidate);
            }
        }
    }

    Ok(ReclaimCompletionPlan {
        reclaimed_candidates,
        retained_failures,
        pending_candidates,
        retryable_candidates,
        total_reclaimed_bytes,
    })
}

/// Select a deterministic batch of reclaim candidates.
///
/// Candidates must have non-zero reclaimable bytes and meet the configured
/// waste threshold. Ordering prefers higher waste ratio, then higher reclaimable
/// bytes, then lower segment id so repeated runs choose the same segments.
pub fn plan_reclaim_batch(
    config: &ReclaimConfig,
    segments: impl IntoIterator<Item = ReclaimSegment>,
) -> ReclaimPlan {
    let mut candidates: Vec<_> = segments
        .into_iter()
        .filter(|segment| is_reclaim_candidate(config, segment))
        .map(ReclaimCandidate::from)
        .collect();

    candidates.sort_by(compare_reclaim_candidates);
    candidates.truncate(config.batch_size);

    let total_reclaimable_bytes = candidates
        .iter()
        .map(|candidate| candidate.reclaimable_bytes as u128)
        .sum();

    ReclaimPlan {
        candidates,
        total_reclaimable_bytes,
    }
}

fn is_reclaim_candidate(config: &ReclaimConfig, segment: &ReclaimSegment) -> bool {
    segment.total_bytes() > 0
        && segment.reclaimable_bytes > 0
        && segment.waste_ratio() >= config.waste_threshold
}

fn compare_reclaim_candidates(left: &ReclaimCandidate, right: &ReclaimCandidate) -> Ordering {
    let left_waste = left.reclaimable_bytes as u128 * right.total_bytes();
    let right_waste = right.reclaimable_bytes as u128 * left.total_bytes();

    right_waste
        .cmp(&left_waste)
        .then_with(|| right.reclaimable_bytes.cmp(&left.reclaimable_bytes))
        .then_with(|| left.segment_id.cmp(&right.segment_id))
        .then_with(|| left.live_bytes.cmp(&right.live_bytes))
}

/// The reclaim scheduler.
///
/// Tracks reclaim state (active/inactive), batch accounting, and
/// cooldown between batches. The actual compaction work is performed
/// by the caller (usually `LocalObjectStore::rotate_segment`) which
/// queries the scheduler for state and reports batch results.
#[derive(Debug)]
pub struct ReclaimScheduler {
    config: ReclaimConfig,
    active: bool,
    /// Count of segments reclaimed in the current pressure episode.
    total_reclaimed: u64,
    /// Count of reclaim batches executed in the current episode.
    batches: u64,
    /// Segment id at which the last reclaim batch was initiated.
    /// Used with [`ReclaimConfig::cooldown_segments`] to prevent
    /// reclaim from triggering on every rotation.
    last_reclaim_at: u64,
}

impl ReclaimScheduler {
    /// Create a new reclaim scheduler with the given configuration.
    pub fn new(config: ReclaimConfig) -> Self {
        Self {
            config,
            active: false,
            total_reclaimed: 0,
            batches: 0,
            last_reclaim_at: 0,
        }
    }

    /// Mark reclaim as active (entering space pressure).
    pub fn activate(&mut self) {
        self.active = true;
        self.total_reclaimed = 0;
        self.batches = 0;
        self.last_reclaim_at = 0;
    }

    /// Mark reclaim as inactive (exiting space pressure or compaction failure).
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Whether the reclaim pipeline is currently active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Total segments reclaimed across all batches in the current episode.
    pub fn total_reclaimed(&self) -> u64 {
        self.total_reclaimed
    }

    /// Number of reclaim batches executed in the current episode.
    pub fn batches(&self) -> u64 {
        self.batches
    }

    /// Record a completed batch: `segments_freed` segments were retired.
    pub fn record_batch(&mut self, segments_freed: u64) {
        self.total_reclaimed += segments_freed;
        self.batches += 1;
    }

    /// Whether reclaim is allowed at the given segment id, considering
    /// the cooldown configured in [`ReclaimConfig::cooldown_segments`].
    pub fn can_reclaim(&self, current_segment_id: u64) -> bool {
        if self.last_reclaim_at == 0 {
            return true;
        }
        current_segment_id.wrapping_sub(self.last_reclaim_at)
            >= self.config.cooldown_segments as u64
    }

    /// Record that a reclaim batch was just initiated at the given
    /// segment id for cooldown tracking.
    pub fn mark_reclaimed(&mut self, segment_id: u64) {
        self.last_reclaim_at = segment_id;
    }

    /// The configured waste ratio threshold.
    pub fn waste_threshold(&self) -> f64 {
        self.config.waste_threshold
    }

    /// Select the next reclaim batch according to this scheduler's config.
    pub fn plan_batch(&self, segments: impl IntoIterator<Item = ReclaimSegment>) -> ReclaimPlan {
        plan_reclaim_batch(&self.config, segments)
    }
}

// =========================================================================
// Reclaim-queue consumer: drains reclaim-queue entries, groups by segment,
// computes per-segment liveness, and returns fully-dead segments to the
// free pool via the SegmentFreer trait.
// =========================================================================

/// Resolves an [`ObjectKey`] to a stable segment identifier.
///
/// Implementations typically query the locator table or extent map
/// to determine which segment holds a given object.
pub trait SegmentResolver {
    /// Error type returned when resolution fails.
    type Error: fmt::Debug + fmt::Display;

    /// Map an object key to its owning segment, if one is known.
    ///
    /// Returns `Ok(None)` when the object is not currently tracked in
    /// any segment (e.g. it was already reclaimed by a prior drain).
    fn resolve(&self, key: &ObjectKey) -> Result<Option<u64>, Self::Error>;
}

/// Frees a segment, returning its blocks to the free pool.
///
/// The canonical production implementation delegates to
/// [`PoolAllocator::add_free`](tidefs_pool_allocator::PoolAllocator::add_free).
pub trait SegmentFreer {
    /// Error type returned when freeing fails.
    type Error: fmt::Debug + fmt::Display;

    /// Release a segment back to the free pool.
    ///
    /// Must be idempotent: freeing an already-free segment is a no-op.
    fn free_segment(&mut self, segment_id: u64) -> Result<(), Self::Error>;
}

/// Per-segment live-object reference tracker.
///
/// Tracks how many live object references remain in each segment.
/// Callers initialise counts from the extent map (or locator table),
/// then apply deltas from reclaim-queue entries.  A segment whose
/// live count reaches zero is fully dead and can be reclaimed.
#[derive(Clone, Debug, Default)]
pub struct SegmentLiveCounts {
    counts: HashMap<u64, u64>,
}

impl SegmentLiveCounts {
    /// Create an empty live-count tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    /// Number of tracked segments.
    #[must_use]
    pub fn len(&self) -> usize {
        self.counts.len()
    }

    /// Returns `true` if no segments are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    /// Set (or replace) the live object count for a segment.
    pub fn set_live_count(&mut self, segment_id: u64, count: u64) {
        if count == 0 {
            self.counts.remove(&segment_id);
        } else {
            self.counts.insert(segment_id, count);
        }
    }

    /// Get the current live object count for a segment.
    #[must_use]
    pub fn live_count(&self, segment_id: u64) -> u64 {
        self.counts.get(&segment_id).copied().unwrap_or(0)
    }

    /// Apply a refcount delta to a segment, returning the new live count.
    ///
    /// Positive deltas increment the live count (e.g. a snapshot clone
    /// added a reference).  Negative deltas decrement it (e.g. a delete
    /// or overwrite dropped a reference).  The count is clamped at zero.
    pub fn apply_delta(&mut self, segment_id: u64, delta: i64) -> u64 {
        if delta == 0 {
            return self.live_count(segment_id);
        }
        let entry = self.counts.entry(segment_id).or_insert(0);
        if delta > 0 {
            *entry = entry.saturating_add(delta as u64);
        } else {
            let abs_delta = delta.unsigned_abs();
            *entry = entry.saturating_sub(abs_delta);
        }
        if *entry == 0 {
            self.counts.remove(&segment_id);
            return 0;
        }
        *entry
    }

    /// Returns `true` if the segment is fully dead (live count is zero).
    #[must_use]
    pub fn is_dead(&self, segment_id: u64) -> bool {
        self.live_count(segment_id) == 0
    }

    /// Remove a segment from tracking after it has been reclaimed.
    ///
    /// Returns the previous live count, if any.
    pub fn remove(&mut self, segment_id: u64) -> Option<u64> {
        self.counts.remove(&segment_id)
    }
}

/// Configuration for the reclaim-queue consumer drain loop.
#[derive(Clone, Debug, PartialEq)]
pub struct ReclaimConsumerConfig {
    /// Maximum reclaim-queue entries to process in one drain call
    /// (default: 1024).
    pub max_entries_per_drain: usize,

    /// Maximum number of dead segments to free in one batch before
    /// committing a spacemap checkpoint (default: 64).
    pub max_free_batch: usize,
}

impl Default for ReclaimConsumerConfig {
    fn default() -> Self {
        Self {
            max_entries_per_drain: 1024,
            max_free_batch: 64,
        }
    }
}

/// Accumulated statistics for one invocation of [`drain_reclaim_queue`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReclaimConsumerStats {
    /// Number of reclaim-queue entries examined.
    pub entries_processed: usize,

    /// Number of segments identified as fully dead and returned to the
    /// free pool.
    pub segments_reclaimed: u64,

    /// Number of dead-object bytes freed (sum of dead_bytes from the
    /// liveness queue for freed segments).
    pub blocks_freed: u64,

    /// Number of entries remaining in the queue after this drain.
    pub reclaim_queue_depth: usize,

    /// Number of segments skipped because at least one extent was denied by the reclaim gate.
    pub gate_segments_skipped: u64,

    /// Number of extents denied by the reclaim gate (deadlist or pin clearance).
    pub gate_extents_denied: u64,

    /// Number of dead-segment batches that triggered a spacemap
    /// checkpoint commit.
    pub checkpoint_batches: usize,
}

impl ReclaimConsumerStats {
    /// Zero-valued stats.
    pub const ZERO: Self = Self {
        entries_processed: 0,
        segments_reclaimed: 0,
        blocks_freed: 0,
        reclaim_queue_depth: 0,
        checkpoint_batches: 0,
        gate_segments_skipped: 0,
        gate_extents_denied: 0,
    };

    /// Returns `true` if no work was done.
    #[must_use]
    pub const fn is_idle(self) -> bool {
        self.entries_processed == 0 && self.segments_reclaimed == 0
    }
}

/// Result of one receipt-bound dead-object drain.
///
/// The consumer does not mutate the source [`DeadObjectReclaimQueue`]. After
/// the caller has durably persisted queue state, it can pass
/// [`ack_object_ids`](Self::ack_object_ids) to
/// [`DeadObjectReclaimQueue::ack_reclaimed`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReceiptBoundDeadObjectDrain {
    /// Segment reclaim accounting for this drain.
    pub stats: ReclaimConsumerStats,
    /// Exact dead-object ids whose segment was reclaimed and may be
    /// acknowledged after queue persistence succeeds.
    pub ack_object_ids: Vec<ObjectKey>,
    /// Exact segment ids returned to the free pool by this drain.
    pub reclaimed_segment_ids: Vec<u64>,
    /// Committed receipt for extents actually freed by this drain.
    pub receipt: Option<ReclaimReceipt>,
}

impl ReceiptBoundDeadObjectDrain {
    /// True when the drain selected no acknowledgeable dead objects and freed
    /// no segments.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.stats.is_idle()
            && self.ack_object_ids.is_empty()
            && self.reclaimed_segment_ids.is_empty()
            && self.receipt.is_none()
    }
}

/// Errors that can occur during a drain cycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DrainError<R: fmt::Debug + fmt::Display, F: fmt::Debug + fmt::Display> {
    /// The segment resolver failed for one or more entries.
    ResolveError { key: ObjectKey, error: R },
    /// The segment freer failed for one or more segments.
    FreeError { segment_id: u64, error: F },
}

impl<R: fmt::Debug + fmt::Display, F: fmt::Debug + fmt::Display> fmt::Display for DrainError<R, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResolveError { key, error } => {
                write!(f, "segment resolve error for key {key}: {error}")
            }
            Self::FreeError { segment_id, error } => {
                write!(f, "segment free error for segment {segment_id}: {error}")
            }
        }
    }
}

// =========================================================================
// ReclaimGate — deadlist and snapshot-pin clearance gating
// =========================================================================

/// Clearance evidence recorded in a reclaim receipt for each freed extent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClearanceEvidence {
    /// Extent was cleared by deadlist and pin-set verification.
    Verified {
        /// Committed deadlist txg at time of clearance.
        deadlist_committed_txg: u64,
        /// Snapshot pin-set epoch at time of clearance.
        pin_clearance_epoch: u64,
    },
}

impl ClearanceEvidence {
    /// The deadlist commit_group used for clearance, if any.
    #[must_use]
    pub const fn deadlist_txg(self) -> Option<u64> {
        match self {
            Self::Verified {
                deadlist_committed_txg,
                ..
            } => Some(deadlist_committed_txg),
        }
    }

    /// The pin-set epoch used for clearance, if any.
    #[must_use]
    pub const fn pin_epoch(self) -> Option<u64> {
        match self {
            Self::Verified {
                pin_clearance_epoch,
                ..
            } => Some(pin_clearance_epoch),
        }
    }
}

/// Gating decisions produced by [`ReclaimGate::check_extent`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateDecision {
    /// Extent may be freed.
    Allow(ClearanceEvidence),
    /// Extent must be skipped (still deadlist-referenced or snapshot-pinned).
    Deny(GateDenyReason),
}

impl GateDecision {
    /// Whether the extent is allowed to be freed.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allow(_))
    }

    /// Whether the extent is denied.
    #[must_use]
    pub const fn is_denied(self) -> bool {
        matches!(self, Self::Deny(_))
    }
}

/// Reason an extent was denied by the reclaim gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateDenyReason {
    /// Extent is still referenced by a committed deadlist entry.
    DeadlistReferenced,
    /// Extent is still pinned by at least one live snapshot.
    SnapshotPinned,
}

impl fmt::Display for GateDenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeadlistReferenced => f.write_str("extent still referenced by deadlist"),
            Self::SnapshotPinned => f.write_str("extent still pinned by live snapshot"),
        }
    }
}

/// Trait for checking deadlist and snapshot-pin clearance before freeing
/// an extent.
///
/// Implementations consult the committed deadlist (to confirm the extent
/// is eligible for reclamation) and the snapshot pin set (to confirm no
/// live snapshot still references the extent).
pub trait ReclaimGate {
    /// Check whether `extent_key` may be freed.
    ///
    /// Returns [`GateDecision::Allow`] with clearance evidence when the
    /// extent passes both deadlist and snapshot-pin checks.
    /// Returns [`GateDecision::Deny`] with a reason when the extent
    /// must be skipped.
    fn check_extent(&self, extent_key: &ObjectKey) -> GateDecision;
}

// =========================================================================
// ReclaimReceipt — committed evidence of freed extents
// =========================================================================

/// A durable receipt recording a batch of freed extents together with the
/// deadlist and snapshot-pin clearance evidence at time of free.
///
/// Receipts are persisted and loaded during store open as committed evidence
/// for extents that were physically freed after deadlist and snapshot-pin
/// clearance. Corrupt receipt logs must fail closed at open so recovery does
/// not silently lose that clearance evidence.
///
/// # Wire format
///
/// ```text
/// MAGIC:     4 bytes  "RCRP"
/// VERSION:   4 bytes  LE u32 = 2
/// COUNT:     4 bytes  LE u32 (number of extents)
/// EVIDENCE:  16 bytes (deadlist_txg: u64 LE, pin_epoch: u64 LE)
/// EXTENTS:   COUNT * 40 bytes (segment_id: u64 LE, ObjectKey: [u8; 32])
/// CHECKSUM:  32 bytes BLAKE3-256 over MAGIC..EXTENTS
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReclaimReceiptExtent {
    /// Exact segment id that held the freed extent at reclaim time.
    pub segment_id: u64,
    /// Exact extent key freed from `segment_id`.
    pub extent_key: tidefs_types_reclaim_queue_core::ObjectKey,
}

impl ReclaimReceiptExtent {
    /// Create a segment-scoped receipt extent record.
    #[must_use]
    pub const fn new(
        segment_id: u64,
        extent_key: tidefs_types_reclaim_queue_core::ObjectKey,
    ) -> Self {
        Self {
            segment_id,
            extent_key,
        }
    }
}

/// Durable reclaim evidence for one committed physical-reclaim batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReclaimReceipt {
    /// Extent keys freed in this batch, derived from
    /// [`freed_segment_extents`](Self::freed_segment_extents).
    pub freed_extents: Vec<tidefs_types_reclaim_queue_core::ObjectKey>,
    /// Exact segment/extent pairs freed in this batch.
    pub freed_segment_extents: Vec<ReclaimReceiptExtent>,
    /// Committed deadlist txg at time of clearance.
    pub deadlist_committed_txg: u64,
    /// Snapshot pin-set epoch at time of clearance.
    pub pin_clearance_epoch: u64,
}

impl ReclaimReceipt {
    /// Magic bytes for the reclaim receipt wire format.
    pub const MAGIC: &[u8; 4] = b"RCRP";
    /// Current wire format version.
    pub const VERSION: u32 = 2;
    /// Size of the fixed header (magic + version + count + evidence).
    pub const HEADER_SIZE: usize = 28;
    /// Size of one extent entry in the wire format.
    pub const EXTENT_ENTRY_SIZE: usize = 40;

    /// Create a new receipt with the given clearance evidence.
    #[must_use]
    pub fn new(
        freed_segment_extents: Vec<ReclaimReceiptExtent>,
        deadlist_committed_txg: u64,
        pin_clearance_epoch: u64,
    ) -> Self {
        let freed_extents = freed_segment_extents
            .iter()
            .map(|extent| extent.extent_key)
            .collect();
        Self {
            freed_extents,
            freed_segment_extents,
            deadlist_committed_txg,
            pin_clearance_epoch,
        }
    }

    /// Whether the receipt records any freed extents.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.freed_segment_extents.is_empty()
    }

    /// Number of freed extents recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.freed_segment_extents.len()
    }

    /// Encode the receipt to its wire format including the BLAKE3
    /// integrity checksum.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let extent_bytes = self.len() * Self::EXTENT_ENTRY_SIZE;
        let payload_len = Self::HEADER_SIZE + extent_bytes;
        let checksum_len = 32;
        let total = payload_len + checksum_len;

        let mut buf = Vec::with_capacity(total);

        // Magic
        buf.extend_from_slice(Self::MAGIC);
        // Version
        buf.extend_from_slice(&Self::VERSION.to_le_bytes());
        // Count
        buf.extend_from_slice(&(self.len() as u32).to_le_bytes());
        // Evidence
        buf.extend_from_slice(&self.deadlist_committed_txg.to_le_bytes());
        buf.extend_from_slice(&self.pin_clearance_epoch.to_le_bytes());
        // Extents
        for extent in &self.freed_segment_extents {
            buf.extend_from_slice(&extent.segment_id.to_le_bytes());
            buf.extend_from_slice(&extent.extent_key.0);
        }

        // BLAKE3-256 integrity checksum
        let checksum = *blake3::hash(&buf).as_bytes();
        buf.extend_from_slice(&checksum);

        buf
    }

    /// Decode a receipt from its wire format.
    ///
    /// # Errors
    ///
    /// Returns `ReclaimReceiptDecodeError` for truncated input, invalid
    /// magic, unsupported version, trailing bytes, or checksum mismatch.
    pub fn decode(data: &[u8]) -> Result<Self, ReclaimReceiptDecodeError> {
        if data.len() < Self::HEADER_SIZE + 32 {
            return Err(ReclaimReceiptDecodeError::Truncated);
        }

        // Magic
        if &data[0..4] != Self::MAGIC {
            return Err(ReclaimReceiptDecodeError::InvalidMagic);
        }

        // Version
        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if version != Self::VERSION {
            return Err(ReclaimReceiptDecodeError::UnsupportedVersion {
                found: version,
                expected: Self::VERSION,
            });
        }

        // Count
        let count = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;

        // Evidence
        let deadlist_committed_txg = u64::from_le_bytes(data[12..20].try_into().unwrap());
        let pin_clearance_epoch = u64::from_le_bytes(data[20..28].try_into().unwrap());

        // Length check (header + extents + checksum)
        let expected_len = Self::HEADER_SIZE + count * Self::EXTENT_ENTRY_SIZE + 32;
        if data.len() < expected_len {
            return Err(ReclaimReceiptDecodeError::Truncated);
        }
        if data.len() > expected_len {
            return Err(ReclaimReceiptDecodeError::TrailingBytes);
        }

        // Verify checksum
        let payload_end = expected_len - 32;
        let expected_checksum = *blake3::hash(&data[..payload_end]).as_bytes();
        let stored_checksum: [u8; 32] = data[payload_end..payload_end + 32].try_into().unwrap();
        if expected_checksum != stored_checksum {
            return Err(ReclaimReceiptDecodeError::ChecksumMismatch);
        }

        // Decode extents
        let mut freed_segment_extents = Vec::with_capacity(count);
        for i in 0..count {
            let start = Self::HEADER_SIZE + i * Self::EXTENT_ENTRY_SIZE;
            let end = start + Self::EXTENT_ENTRY_SIZE;
            let segment_id = u64::from_le_bytes(data[start..start + 8].try_into().unwrap());
            let key_bytes: [u8; 32] = data[start + 8..end].try_into().unwrap();
            let extent_key = tidefs_types_reclaim_queue_core::ObjectKey(key_bytes);
            freed_segment_extents.push(ReclaimReceiptExtent::new(segment_id, extent_key));
        }

        Ok(Self::new(
            freed_segment_extents,
            deadlist_committed_txg,
            pin_clearance_epoch,
        ))
    }

    /// Predicted encoded length for a receipt with `count` extents.
    #[must_use]
    pub const fn encoded_len(count: usize) -> usize {
        Self::HEADER_SIZE + count * Self::EXTENT_ENTRY_SIZE + 32
    }
}

/// Errors returned by [`ReclaimReceipt::decode`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReclaimReceiptDecodeError {
    /// Input too short for header and checksum.
    Truncated,
    /// Magic bytes do not match expected value.
    InvalidMagic,
    /// Version field is not the current version.
    UnsupportedVersion { found: u32, expected: u32 },
    /// Input contains bytes after the expected receipt frame.
    TrailingBytes,
    /// Checksum verification failed (corruption or tampering).
    ChecksumMismatch,
}

impl fmt::Display for ReclaimReceiptDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("reclaim receipt truncated"),
            Self::InvalidMagic => f.write_str("reclaim receipt invalid magic"),
            Self::UnsupportedVersion { found, expected } => {
                write!(
                    f,
                    "reclaim receipt unsupported version {found} (expected {expected})"
                )
            }
            Self::TrailingBytes => f.write_str("reclaim receipt has trailing bytes"),
            Self::ChecksumMismatch => f.write_str("reclaim receipt checksum mismatch"),
        }
    }
}

// Test-only legacy helper retained for historical consumer coverage. Release
// reclaim paths must use `drain_reclaim_queue_gated` or
// `drain_receipt_bound_dead_objects`.
#[cfg(test)]
pub fn drain_reclaim_queue<R, F>(
    entries: &[(ObjectKey, ReclaimQueueEntry)],
    resolver: &impl SegmentResolver<Error = R>,
    freer: &mut impl SegmentFreer<Error = F>,
    live_counts: &mut SegmentLiveCounts,
    config: &ReclaimConsumerConfig,
) -> Result<ReclaimConsumerStats, DrainError<R, F>>
where
    R: fmt::Debug + fmt::Display,
    F: fmt::Debug + fmt::Display,
{
    if entries.is_empty() {
        return Ok(ReclaimConsumerStats {
            reclaim_queue_depth: 0,
            ..ReclaimConsumerStats::ZERO
        });
    }

    let mut stats = ReclaimConsumerStats {
        reclaim_queue_depth: entries.len(),
        ..ReclaimConsumerStats::ZERO
    };

    // Phase 1: resolve segments and apply deltas.
    let mut segment_entries: HashMap<u64, Vec<(ObjectKey, i64)>> = HashMap::new();
    let mut segment_prior_counts: HashMap<u64, u64> = HashMap::new();

    for (key, entry) in entries.iter().take(config.max_entries_per_drain) {
        let segment_id = resolver
            .resolve(key)
            .map_err(|e| DrainError::ResolveError {
                key: *key,
                error: e,
            })?;

        let sid = match segment_id {
            Some(id) => id,
            None => continue, // object already reclaimed; skip
        };

        segment_prior_counts
            .entry(sid)
            .or_insert_with(|| live_counts.live_count(sid));
        live_counts.apply_delta(sid, entry.delta);
        segment_entries
            .entry(sid)
            .or_default()
            .push((*key, entry.delta));
        stats.entries_processed += 1;
    }

    // Phase 2: collect fully-dead segments.
    let dead_segments: Vec<u64> = segment_entries
        .keys()
        .copied()
        .filter(|sid| live_counts.is_dead(*sid))
        .collect();

    if dead_segments.is_empty() {
        return Ok(stats);
    }

    // Phase 3: batch-free dead segments.
    for batch in dead_segments.chunks(config.max_free_batch) {
        for &segment_id in batch {
            freer
                .free_segment(segment_id)
                .map_err(|e| DrainError::FreeError {
                    segment_id,
                    error: e,
                })?;
            live_counts.remove(segment_id);
            stats.segments_reclaimed += 1;
            // Count objects freed in this dead segment (sum of
            // |negative deltas| from the reclaim-queue entries).
            let seg_obj_count = segment_entries
                .get(&segment_id)
                .map(|entries| entries.iter().filter(|(_, d)| *d < 0).count() as u64)
                .unwrap_or(0);
            stats.blocks_freed += seg_obj_count;
        }
        stats.checkpoint_batches += 1;
    }

    Ok(stats)
}

/// Result of a gated drain operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatedDrainResult {
    /// Segment reclaim accounting for this drain.
    pub stats: ReclaimConsumerStats,
    /// Reclaim receipt recording freed extents and clearance evidence.
    /// `None` if no extents were freed.
    pub receipt: Option<ReclaimReceipt>,
}

impl GatedDrainResult {
    /// Whether the drain freed no segments and recorded no extents.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.stats.is_idle() && self.receipt.as_ref().is_none_or(|r| r.is_empty())
    }
}

/// Drain reclaim-queue entries, identify fully-dead segments, gate each
/// extent through [`ReclaimGate`] (deadlist + snapshot-pin clearance),
/// and return fully-cleared dead segments to the free pool.
///
/// # Gate behaviour
///
/// Each extent in a fully-dead segment is checked via
/// [`ReclaimGate::check_extent`].
/// If any extent in the segment is denied, the entire segment is
/// skipped and remains in `live_counts`. This conservative
/// all-or-none rule prevents partial segment freeing, which the
/// segment-based allocator does not support.
///
/// # Flow
///
/// 1. Extract up to `config.max_entries_per_drain` entries from `queue`.
/// 2. Resolve each entry's object key to a segment id via `resolver`.
/// 3. Apply the entry's refcount delta to `live_counts` for that segment.
/// 4. After processing all entries, scan for segments whose live count
///    reached zero (fully dead).
/// 5. For each fully-dead segment, check every extent against the gate;
///    skip the segment if any extent is denied.
/// 6. Batch-free the gated dead segments via `freer`.
/// 7. Remove freed segments from `live_counts`.
/// 8. Build a [`ReclaimReceipt`] if any extents were freed.
///
/// # Errors
///
/// Returns `DrainError::ResolveError` if the resolver cannot map a key.
/// Returns `DrainError::FreeError` if the freer cannot release a segment.
///
/// # Panics
///
/// Does not panic on valid input.
pub fn drain_reclaim_queue_gated<R, F>(
    entries: &[(ObjectKey, ReclaimQueueEntry)],
    resolver: &impl SegmentResolver<Error = R>,
    freer: &mut impl SegmentFreer<Error = F>,
    live_counts: &mut SegmentLiveCounts,
    config: &ReclaimConsumerConfig,
    gate: &impl ReclaimGate,
) -> Result<GatedDrainResult, DrainError<R, F>>
where
    R: fmt::Debug + fmt::Display,
    F: fmt::Debug + fmt::Display,
{
    if entries.is_empty() {
        return Ok(GatedDrainResult {
            stats: ReclaimConsumerStats {
                reclaim_queue_depth: 0,
                ..ReclaimConsumerStats::ZERO
            },
            receipt: None,
        });
    }

    let mut stats = ReclaimConsumerStats {
        reclaim_queue_depth: entries.len(),
        ..ReclaimConsumerStats::ZERO
    };

    // Phase 1: resolve segments and apply deltas.
    let mut segment_entries: HashMap<u64, Vec<(ObjectKey, i64)>> = HashMap::new();
    let mut segment_prior_counts: HashMap<u64, u64> = HashMap::new();

    for (key, entry) in entries.iter().take(config.max_entries_per_drain) {
        let segment_id = resolver
            .resolve(key)
            .map_err(|e| DrainError::ResolveError {
                key: *key,
                error: e,
            })?;

        let sid = match segment_id {
            Some(id) => id,
            None => continue,
        };

        segment_prior_counts
            .entry(sid)
            .or_insert_with(|| live_counts.live_count(sid));
        live_counts.apply_delta(sid, entry.delta);
        segment_entries
            .entry(sid)
            .or_default()
            .push((*key, entry.delta));
        stats.entries_processed += 1;
    }

    // Phase 2: collect fully-dead segments.
    let dead_segments: Vec<u64> = segment_entries
        .keys()
        .copied()
        .filter(|sid| live_counts.is_dead(*sid))
        .collect();

    if dead_segments.is_empty() {
        return Ok(GatedDrainResult {
            stats,
            receipt: None,
        });
    }

    // Phase 3: gate each dead segment before freeing.
    let mut freed_extents: Vec<ReclaimReceiptExtent> = Vec::new();
    let mut clearance_deadlist_txg: Option<u64> = None;
    let mut clearance_pin_epoch: Option<u64> = None;

    for batch in dead_segments.chunks(config.max_free_batch) {
        for &segment_id in batch {
            // Gate: check every extent in this segment
            let mut segment_allowed = true;
            if let Some(extent_entries) = segment_entries.get(&segment_id) {
                for (object_key, _delta) in extent_entries {
                    let decision = gate.check_extent(object_key);
                    match decision {
                        GateDecision::Allow(evidence) => {
                            // Record clearance evidence from first allowed extent.
                            if clearance_deadlist_txg.is_none() {
                                clearance_deadlist_txg = evidence.deadlist_txg();
                                clearance_pin_epoch = evidence.pin_epoch();
                            }
                        }
                        GateDecision::Deny(_reason) => {
                            segment_allowed = false;
                            stats.gate_extents_denied += 1;
                            break;
                        }
                    }
                }
            }

            if !segment_allowed {
                if let Some(previous) = segment_prior_counts.get(&segment_id) {
                    live_counts.set_live_count(segment_id, *previous);
                }
                stats.gate_segments_skipped += 1;
                continue;
            }

            freer
                .free_segment(segment_id)
                .map_err(|e| DrainError::FreeError {
                    segment_id,
                    error: e,
                })?;
            live_counts.remove(segment_id);
            stats.segments_reclaimed += 1;

            // Collect freed extents for the receipt
            if let Some(extent_entries) = segment_entries.get(&segment_id) {
                let obj_count = extent_entries.iter().filter(|(_, d)| *d < 0).count() as u64;
                stats.blocks_freed += obj_count;
                for (object_key, delta) in extent_entries {
                    if *delta < 0 {
                        freed_extents.push(ReclaimReceiptExtent::new(segment_id, *object_key));
                    }
                }
            }
        }
        stats.checkpoint_batches += 1;
    }

    let receipt = if !freed_extents.is_empty() {
        Some(ReclaimReceipt::new(
            freed_extents,
            clearance_deadlist_txg.unwrap_or(0),
            clearance_pin_epoch.unwrap_or(0),
        ))
    } else {
        None
    };

    Ok(GatedDrainResult { stats, receipt })
}
/// Drain receipt-authorized dead objects into segment liveness accounting.
///
/// This is the release-facing dead-object physical reclaim entry point: it
/// selects candidates through
/// [`DeadObjectReclaimQueue::dequeue_receipt_bound_batch_with_stable_generation`]
/// so legacy, synthetic, malformed, under-width, ineligible, or
/// generation-unstable entries remain queued. A selected segment is only
/// eligible for liveness mutation when the current batch covers enough extents
/// to reclaim the whole segment; partial segment batches stay queued so a
/// later free cannot bypass clearance checks for extents acknowledged earlier.
/// Each eligible fully-dead segment is then checked through `gate`; denied
/// segments remain queued. The caller owns source-queue mutation and should
/// acknowledge only the returned object ids after any queue persistence
/// succeeds.
pub fn drain_receipt_bound_dead_objects<R, F>(
    queue: &DeadObjectReclaimQueue,
    stable_committed_txg: u64,
    stable_committed_generation: u64,
    max_count: usize,
    resolver: &impl SegmentResolver<Error = R>,
    freer: &mut impl SegmentFreer<Error = F>,
    live_counts: &mut SegmentLiveCounts,
    config: &ReclaimConsumerConfig,
    gate: &impl ReclaimGate,
) -> Result<ReceiptBoundDeadObjectDrain, DrainError<R, F>>
where
    R: fmt::Debug + fmt::Display,
    F: fmt::Debug + fmt::Display,
{
    let limit = max_count.min(config.max_entries_per_drain);
    let mut stats = ReclaimConsumerStats {
        reclaim_queue_depth: queue.len(),
        ..ReclaimConsumerStats::ZERO
    };

    if limit == 0 || queue.is_empty() {
        return Ok(ReceiptBoundDeadObjectDrain {
            stats,
            ack_object_ids: Vec::new(),
            reclaimed_segment_ids: Vec::new(),
            receipt: None,
        });
    }

    let entries = queue.dequeue_receipt_bound_batch_with_stable_generation(
        limit,
        stable_committed_txg,
        stable_committed_generation,
    );
    if entries.is_empty() {
        return Ok(ReceiptBoundDeadObjectDrain {
            stats,
            ack_object_ids: Vec::new(),
            reclaimed_segment_ids: Vec::new(),
            receipt: None,
        });
    }

    let mut segment_entries: HashMap<u64, Vec<ObjectKey>> = HashMap::new();
    let mut queued_segment_entries: HashMap<u64, usize> = HashMap::new();

    for entry in queue.all_entries() {
        let key = entry.object_id;
        let Some(segment_id) = resolver
            .resolve(&key)
            .map_err(|error| DrainError::ResolveError { key, error })?
        else {
            continue;
        };
        *queued_segment_entries.entry(segment_id).or_default() += 1;
    }

    for entry in &entries {
        let key = entry.object_id;
        let Some(segment_id) = resolver
            .resolve(&key)
            .map_err(|error| DrainError::ResolveError { key, error })?
        else {
            continue;
        };

        segment_entries.entry(segment_id).or_default().push(key);
        stats.entries_processed += 1;
    }

    let dead_segments: Vec<u64> = segment_entries
        .iter()
        .filter_map(|(segment_id, extents)| {
            let live_count = live_counts.live_count(*segment_id);
            let selected_entries = extents.len();
            let queued_entries = queued_segment_entries
                .get(segment_id)
                .copied()
                .unwrap_or(selected_entries);
            let covers_liveness = live_count == 0 || live_count <= selected_entries as u64;
            (covers_liveness && selected_entries == queued_entries).then_some(*segment_id)
        })
        .collect();

    let mut freed_extents = Vec::new();
    let mut reclaimed_segment_ids = Vec::new();
    let mut ack_object_ids = Vec::new();
    let mut clearance_deadlist_txg: Option<u64> = None;
    let mut clearance_pin_epoch: Option<u64> = None;

    for batch in dead_segments.chunks(config.max_free_batch) {
        for &segment_id in batch {
            let Some(extent_entries) = segment_entries.get(&segment_id) else {
                continue;
            };

            let mut segment_allowed = true;
            for object_key in extent_entries {
                match gate.check_extent(object_key) {
                    GateDecision::Allow(evidence) => {
                        if clearance_deadlist_txg.is_none() {
                            clearance_deadlist_txg = evidence.deadlist_txg();
                            clearance_pin_epoch = evidence.pin_epoch();
                        }
                    }
                    GateDecision::Deny(_reason) => {
                        segment_allowed = false;
                        stats.gate_extents_denied += 1;
                        break;
                    }
                }
            }

            if !segment_allowed {
                stats.gate_segments_skipped += 1;
                continue;
            }

            freer
                .free_segment(segment_id)
                .map_err(|error| DrainError::FreeError { segment_id, error })?;
            live_counts.remove(segment_id);
            ack_object_ids.extend(extent_entries.iter().copied());
            reclaimed_segment_ids.push(segment_id);
            stats.segments_reclaimed += 1;
            stats.blocks_freed += extent_entries.len() as u64;
            freed_extents.extend(
                extent_entries
                    .iter()
                    .copied()
                    .map(|extent_key| ReclaimReceiptExtent::new(segment_id, extent_key)),
            );
        }
        stats.checkpoint_batches += 1;
    }

    stats.reclaim_queue_depth = queue.len().saturating_sub(ack_object_ids.len());
    let receipt = if freed_extents.is_empty() {
        None
    } else {
        Some(ReclaimReceipt::new(
            freed_extents,
            clearance_deadlist_txg.unwrap_or(0),
            clearance_pin_epoch.unwrap_or(0),
        ))
    };

    Ok(ReceiptBoundDeadObjectDrain {
        stats,
        ack_object_ids,
        reclaimed_segment_ids,
        receipt,
    })
}

// =========================================================================
// PoolAllocator SegmentFreer implementation
// =========================================================================

use tidefs_pool_allocator::PoolAllocator;

impl SegmentFreer for PoolAllocator {
    type Error = tidefs_pool_allocator::PoolAllocatorError;

    fn free_segment(&mut self, segment_id: u64) -> Result<(), Self::Error> {
        self.add_free(segment_id)
    }
}

// =========================================================================
// ReclaimConsumerService -- callable entry point for reclaim-queue draining
// =========================================================================

/// Callable service entry point for gated reclaim drains.
///
/// The service bundles configuration and live-count state so callers do not
/// need to thread them through every drain invocation. For each drain call,
/// the caller supplies eligible entries, a resolver, a freer, and a
/// [`ReclaimGate`] that proves deadlist and snapshot-pin clearance before
/// physical segment release.
///
/// # Example
///
/// ```ignore
/// let config = ReclaimConsumerConfig::default();
/// let mut counts = SegmentLiveCounts::new();
/// // initialise counts from the extent map / locator table
/// let mut service = ReclaimConsumerService::new(config, counts);
///
/// let entries: Vec<(ObjectKey, ReclaimQueueEntry)> = reclaim_queue.dequeue_batch(None, 1024);
/// let resolver = LocatorTableResolver::new(&locator_table);
/// let mut allocator = pool_allocator.clone();
/// let gate = CommittedClearanceGate::new(...);
///
/// let result = service.gated_drain(&entries, &resolver, &mut allocator, &gate)?;
/// ```
#[derive(Clone, Debug)]
pub struct ReclaimConsumerService {
    config: ReclaimConsumerConfig,
    live_counts: SegmentLiveCounts,
}

impl ReclaimConsumerService {
    /// Create a new reclaim consumer service.
    ///
    /// `live_counts` should be initialised from the current extent-map or
    /// locator-table state before the first drain so that per-segment
    /// liveness tracking has an accurate starting point.
    #[must_use]
    pub fn new(config: ReclaimConsumerConfig, live_counts: SegmentLiveCounts) -> Self {
        Self {
            config,
            live_counts,
        }
    }

    /// Drain a batch of reclaim-queue entries, freeing fully-dead segments.
    ///
    /// Accepts entries produced by the reclaim-queue B+tree, resolves each
    /// object key to its owning segment via `resolver`, applies refcount
    /// deltas to `self.live_counts`, and calls `freer.free_segment()` for
    /// every segment whose live count reaches zero.
    ///
    /// The per-segment live counts persist across calls so repeated drains
    /// make progress toward zero on partially-dead segments.
    ///
    /// # Errors
    ///
    /// Returns [`DrainError::ResolveError`] when the resolver cannot map an
    /// object key, or [`DrainError::FreeError`] when `freer` fails.
    #[cfg(test)]
    pub fn drain<R, F>(
        &mut self,
        entries: &[(ObjectKey, ReclaimQueueEntry)],
        resolver: &impl SegmentResolver<Error = R>,
        freer: &mut impl SegmentFreer<Error = F>,
    ) -> Result<ReclaimConsumerStats, DrainError<R, F>>
    where
        R: fmt::Debug + fmt::Display,
        F: fmt::Debug + fmt::Display,
    {
        drain_reclaim_queue(
            entries,
            resolver,
            freer,
            &mut self.live_counts,
            &self.config,
        )
    }

    /// Drain receipt-authorized dead objects while preserving queue mutation
    /// authority for the caller.
    pub fn gated_drain<R, F>(
        &mut self,
        entries: &[(ObjectKey, ReclaimQueueEntry)],
        resolver: &impl SegmentResolver<Error = R>,
        freer: &mut impl SegmentFreer<Error = F>,
        gate: &impl ReclaimGate,
    ) -> Result<GatedDrainResult, DrainError<R, F>>
    where
        R: fmt::Debug + fmt::Display,
        F: fmt::Debug + fmt::Display,
    {
        drain_reclaim_queue_gated(
            entries,
            resolver,
            freer,
            &mut self.live_counts,
            &self.config,
            gate,
        )
    }

    pub fn drain_receipt_bound_dead_objects<R, F>(
        &mut self,
        queue: &DeadObjectReclaimQueue,
        stable_committed_txg: u64,
        stable_committed_generation: u64,
        max_count: usize,
        resolver: &impl SegmentResolver<Error = R>,
        freer: &mut impl SegmentFreer<Error = F>,
        gate: &impl ReclaimGate,
    ) -> Result<ReceiptBoundDeadObjectDrain, DrainError<R, F>>
    where
        R: fmt::Debug + fmt::Display,
        F: fmt::Debug + fmt::Display,
    {
        drain_receipt_bound_dead_objects(
            queue,
            stable_committed_txg,
            stable_committed_generation,
            max_count,
            resolver,
            freer,
            &mut self.live_counts,
            &self.config,
            gate,
        )
    }

    /// Access the live-counts state for inspection or persistence.
    #[must_use]
    pub fn live_counts(&self) -> &SegmentLiveCounts {
        &self.live_counts
    }

    /// Mutable access to live counts (e.g. for re-initialisation after
    /// a state transfer or pool import).
    pub fn live_counts_mut(&mut self) -> &mut SegmentLiveCounts {
        &mut self.live_counts
    }

    /// The active consumer configuration.
    #[must_use]
    pub fn config(&self) -> &ReclaimConsumerConfig {
        &self.config
    }
}

// =========================================================================
// DedupReclaimWriter — bridges dedup canonical-object lifetime outcomes
// into the reclaim pipeline.
// =========================================================================

#[cfg(test)]
use tidefs_dedup::{locator_id_to_object_key, RemoveConsumerOutcome};

/// Accumulated stats for one [`DedupReclaimWriter::process_outcomes`] call.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DedupReclaimStats {
    /// Number of dedup outcomes examined.
    pub outcomes_processed: usize,
    /// Number of CanonicalDead outcomes that produced reclaim entries.
    pub dead_locators_queued: usize,
    /// Number of segments that became fully dead and were freed.
    pub segments_reclaimed: u64,
    /// Number of dead-object entries fed to the segment live-count tracker.
    pub deltas_applied: usize,
}

#[cfg(test)]
impl DedupReclaimStats {
    /// Zero-valued stats.
    pub const ZERO: Self = Self {
        outcomes_processed: 0,
        dead_locators_queued: 0,
        segments_reclaimed: 0,
        deltas_applied: 0,
    };

    /// Returns `true` if no work was done.
    #[must_use]
    pub const fn is_idle(self) -> bool {
        self.outcomes_processed == 0
            && self.dead_locators_queued == 0
            && self.segments_reclaimed == 0
    }
}

/// Bridges dedup canonical-object lifetime outcomes into the segment
/// reclaim pipeline.
///
/// Consumes [`RemoveConsumerOutcome`] values produced by
/// [`DedupTable::remove_consumer`](tidefs_dedup::DedupTable::remove_consumer),
/// resolves each dead canonical locator to its owning segment via
/// [`SegmentResolver`], decrements the segment's live count in
/// [`SegmentLiveCounts`], and frees fully-dead segments via
/// [`SegmentFreer`].
///
/// # Usage
///
/// ```ignore
/// let outcomes = vec![
///     ddt.remove_consumer(&hash_a, len_a),
///     ddt.remove_consumer(&hash_b, len_b),
/// ];
/// let mut writer = DedupReclaimWriter::new(live_counts);
/// let stats = writer.process_outcomes(
///     &outcomes,
///     &resolver,
///     &mut freer,
/// );
/// ```text
#[cfg(test)]
pub struct DedupReclaimWriter {
    live_counts: SegmentLiveCounts,
}

#[cfg(test)]
impl DedupReclaimWriter {
    /// Create a new writer wrapping the given live-counts state.
    ///
    /// The live counts should be initialised from the current extent-map
    /// or locator-table state before the first call.
    #[must_use]
    pub fn new(live_counts: SegmentLiveCounts) -> Self {
        Self { live_counts }
    }

    /// Access the live-counts state for inspection or persistence.
    #[must_use]
    pub fn live_counts(&self) -> &SegmentLiveCounts {
        &self.live_counts
    }

    /// Mutable access to live counts (e.g. for re-initialisation after
    /// a state transfer or pool import).
    pub fn live_counts_mut(&mut self) -> &mut SegmentLiveCounts {
        &mut self.live_counts
    }

    /// Process a batch of dedup remove-consumer outcomes.
    ///
    /// For each [`RemoveConsumerOutcome::CanonicalDead`], the canonical
    /// locator is converted to an [`ObjectKey`], resolved to its owning
    /// segment, and the segment's live count is decremented.  Segments
    /// whose live count reaches zero are freed via `freer`.
    ///
    /// # Errors
    ///
    /// Returns [`DedupReclaimError::ResolveFailed`] when `resolver` cannot
    /// map a locator-derived object key to a segment.
    /// Returns [`DedupReclaimError::FreeFailed`] when `freer` fails.
    pub fn process_outcomes<R, F>(
        &mut self,
        outcomes: &[RemoveConsumerOutcome],
        resolver: &impl SegmentResolver<Error = R>,
        freer: &mut impl SegmentFreer<Error = F>,
    ) -> Result<DedupReclaimStats, DedupReclaimError<R, F>>
    where
        R: fmt::Debug + fmt::Display,
        F: fmt::Debug + fmt::Display,
    {
        let mut stats = DedupReclaimStats::ZERO;
        stats.outcomes_processed = outcomes.len();

        for outcome in outcomes {
            let locator = match outcome.dead_locator() {
                Some(l) => l,
                None => continue,
            };

            let object_key = locator_id_to_object_key(locator);
            let segment_id = resolver
                .resolve(&object_key)
                .map_err(|e| DedupReclaimError::ResolveFailed {
                    object_key,
                    source: e,
                })?
                .unwrap_or(0);

            if segment_id == 0 {
                // Object not tracked in any segment; may have been
                // reclaimed already.  Skip without error.
                continue;
            }

            // Decrement the segment's live count by 1
            let new_count = self.live_counts.apply_delta(segment_id, -1);
            stats.deltas_applied = stats.deltas_applied.saturating_add(1);
            stats.dead_locators_queued = stats.dead_locators_queued.saturating_add(1);

            // If the segment is now fully dead, free it
            if new_count == 0 {
                freer
                    .free_segment(segment_id)
                    .map_err(|e| DedupReclaimError::FreeFailed {
                        segment_id,
                        source: e,
                    })?;
                self.live_counts.remove(segment_id);
                stats.segments_reclaimed = stats.segments_reclaimed.saturating_add(1);
            }
        }

        Ok(stats)
    }
}

/// Errors returned by [`DedupReclaimWriter::process_outcomes`].
#[cfg(test)]
#[derive(Debug)]
pub enum DedupReclaimError<R: fmt::Debug + fmt::Display, F: fmt::Debug + fmt::Display> {
    /// The segment resolver failed to map a locator-derived object key.
    ResolveFailed {
        /// The object key that could not be resolved.
        object_key: ObjectKey,
        /// The underlying resolver error.
        source: R,
    },
    /// The segment freer failed.
    FreeFailed {
        /// The segment that could not be freed.
        segment_id: u64,
        /// The underlying freer error.
        source: F,
    },
}

#[cfg(test)]
impl<R: fmt::Debug + fmt::Display, F: fmt::Debug + fmt::Display> fmt::Display
    for DedupReclaimError<R, F>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResolveFailed { object_key, source } => {
                write!(
                    f,
                    "dedup reclaim: failed to resolve object key {object_key}: {source}"
                )
            }
            Self::FreeFailed { segment_id, source } => {
                write!(
                    f,
                    "dedup reclaim: failed to free segment {segment_id}: {source}"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_reclaim_queue_core::QueueFamily;

    #[test]
    fn activate_resets_counters() {
        let mut s = ReclaimScheduler::new(ReclaimConfig::default());
        s.record_batch(3);
        s.activate();
        assert!(s.is_active());
        assert_eq!(s.total_reclaimed(), 0);
        assert_eq!(s.batches(), 0);
    }

    #[test]
    fn deactivate_clears_active() {
        let mut s = ReclaimScheduler::new(ReclaimConfig::default());
        s.activate();
        s.deactivate();
        assert!(!s.is_active());
    }

    #[test]
    fn record_batch_accumulates() {
        let mut s = ReclaimScheduler::new(ReclaimConfig::default());
        s.record_batch(5);
        s.record_batch(3);
        assert_eq!(s.total_reclaimed(), 8);
        assert_eq!(s.batches(), 2);
    }

    #[test]
    fn default_config_values() {
        let c = ReclaimConfig::default();
        assert!((c.waste_threshold - 0.3).abs() < f64::EPSILON);
        assert_eq!(c.batch_size, 8);
        assert_eq!(c.cooldown_segments, 4);
    }

    #[test]
    fn can_reclaim_within_cooldown_denied() {
        let mut s = ReclaimScheduler::new(ReclaimConfig::default());
        s.activate();
        assert!(s.can_reclaim(100));
        s.mark_reclaimed(100);
        // cooldown_segments = 4, so 100+1..100+3 should be denied
        assert!(!s.can_reclaim(101));
        assert!(!s.can_reclaim(103));
        assert!(s.can_reclaim(104)); // exactly 4 apart, allowed
    }

    #[test]
    fn activate_resets_cooldown() {
        let mut s = ReclaimScheduler::new(ReclaimConfig::default());
        s.activate();
        s.mark_reclaimed(50);
        assert!(!s.can_reclaim(51));
        // re-activate clears last_reclaim_at
        s.activate();
        assert!(s.can_reclaim(1));
        assert!(s.can_reclaim(51));
    }

    #[test]
    fn candidate_plan_filters_below_threshold() {
        let config = ReclaimConfig {
            waste_threshold: 0.5,
            batch_size: 8,
            cooldown_segments: 4,
        };

        let plan = plan_reclaim_batch(
            &config,
            [
                ReclaimSegment::new(1, 70, 30),
                ReclaimSegment::new(2, 50, 50),
                ReclaimSegment::new(3, 10, 90),
            ],
        );

        assert_eq!(candidate_ids(&plan), vec![3, 2]);
        assert_eq!(plan.total_reclaimable_bytes, 140);
    }

    #[test]
    fn candidate_plan_limits_batch_by_priority() {
        let config = ReclaimConfig {
            waste_threshold: 0.0,
            batch_size: 2,
            cooldown_segments: 4,
        };

        let plan = plan_reclaim_batch(
            &config,
            [
                ReclaimSegment::new(1, 10, 90),
                ReclaimSegment::new(2, 1, 9),
                ReclaimSegment::new(3, 50, 50),
            ],
        );

        assert_eq!(candidate_ids(&plan), vec![1, 2]);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan.total_reclaimable_bytes, 99);
    }

    #[test]
    fn candidate_plan_orders_ties_deterministically() {
        let config = ReclaimConfig {
            waste_threshold: 0.25,
            batch_size: 8,
            cooldown_segments: 4,
        };

        let plan = plan_reclaim_batch(
            &config,
            [
                ReclaimSegment::new(4, 5, 5),
                ReclaimSegment::new(2, 25, 25),
                ReclaimSegment::new(5, 50, 50),
                ReclaimSegment::new(1, 25, 25),
            ],
        );

        assert_eq!(candidate_ids(&plan), vec![5, 1, 2, 4]);
    }

    #[test]
    fn candidate_plan_selects_same_batch_from_permuted_inputs() {
        let config = ReclaimConfig {
            waste_threshold: 0.0,
            batch_size: 4,
            cooldown_segments: 4,
        };

        let forward = plan_reclaim_batch(
            &config,
            [
                ReclaimSegment::new(40, 90, 10),
                ReclaimSegment::new(10, 10, 90),
                ReclaimSegment::new(30, 20, 80),
                ReclaimSegment::new(20, 20, 80),
                ReclaimSegment::new(50, 60, 40),
                ReclaimSegment::new(60, 10, 40),
            ],
        );
        let reversed = plan_reclaim_batch(
            &config,
            [
                ReclaimSegment::new(60, 10, 40),
                ReclaimSegment::new(50, 60, 40),
                ReclaimSegment::new(20, 20, 80),
                ReclaimSegment::new(30, 20, 80),
                ReclaimSegment::new(10, 10, 90),
                ReclaimSegment::new(40, 90, 10),
            ],
        );

        assert_eq!(candidate_ids(&forward), vec![10, 20, 30, 60]);
        assert_eq!(candidate_ids(&reversed), candidate_ids(&forward));
        assert_eq!(forward.total_reclaimable_bytes, 290);
        assert_eq!(reversed.total_reclaimable_bytes, 290);
    }

    #[test]
    fn candidate_plan_ignores_zero_byte_segments() {
        let config = ReclaimConfig {
            waste_threshold: 0.0,
            batch_size: 8,
            cooldown_segments: 4,
        };

        let plan = plan_reclaim_batch(
            &config,
            [
                ReclaimSegment::new(1, 0, 0),
                ReclaimSegment::new(2, 10, 0),
                ReclaimSegment::new(3, 0, 10),
            ],
        );

        assert_eq!(candidate_ids(&plan), vec![3]);
        assert_eq!(plan.total_reclaimable_bytes, 10);
    }

    #[test]
    fn candidate_plan_includes_threshold_boundary() {
        let config = ReclaimConfig {
            waste_threshold: 0.3,
            batch_size: 8,
            cooldown_segments: 4,
        };

        let plan = plan_reclaim_batch(&config, [ReclaimSegment::new(7, 70, 30)]);

        assert_eq!(candidate_ids(&plan), vec![7]);
    }

    #[test]
    fn scheduler_plans_candidate_batch_with_own_config() {
        let scheduler = ReclaimScheduler::new(ReclaimConfig {
            waste_threshold: 0.4,
            batch_size: 1,
            cooldown_segments: 4,
        });

        let plan = scheduler.plan_batch([
            ReclaimSegment::new(10, 90, 10),
            ReclaimSegment::new(11, 20, 80),
            ReclaimSegment::new(12, 30, 70),
        ]);

        assert_eq!(candidate_ids(&plan), vec![11]);
        assert_eq!(plan.total_reclaimable_bytes, 80);
    }

    #[test]
    fn candidate_plan_is_empty_when_batch_size_is_zero() {
        let config = ReclaimConfig {
            waste_threshold: 0.0,
            batch_size: 0,
            cooldown_segments: 4,
        };

        let plan = plan_reclaim_batch(&config, [ReclaimSegment::new(1, 1, 9)]);

        assert!(plan.is_empty());
        assert_eq!(plan.total_reclaimable_bytes, 0);
    }

    #[test]
    fn candidate_plan_zero_budget_keeps_candidates_available_for_later_plan() {
        let zero_budget_config = ReclaimConfig {
            waste_threshold: 0.0,
            batch_size: 0,
            cooldown_segments: 4,
        };
        let non_zero_budget_config = ReclaimConfig {
            waste_threshold: 0.0,
            batch_size: 3,
            cooldown_segments: 4,
        };
        let segments = [
            ReclaimSegment::new(40, 90, 10),
            ReclaimSegment::new(10, 10, 90),
            ReclaimSegment::new(30, 20, 80),
            ReclaimSegment::new(20, 20, 80),
        ];

        let zero_budget_plan = plan_reclaim_batch(&zero_budget_config, segments);
        let later_plan = plan_reclaim_batch(&non_zero_budget_config, segments);

        assert!(zero_budget_plan.is_empty());
        assert_eq!(zero_budget_plan.total_reclaimable_bytes, 0);
        assert_eq!(candidate_ids(&later_plan), vec![10, 20, 30]);
        assert_eq!(later_plan.total_reclaimable_bytes, 250);
        assert_eq!(
            later_plan.candidates,
            vec![
                ReclaimCandidate::from(ReclaimSegment::new(10, 10, 90)),
                ReclaimCandidate::from(ReclaimSegment::new(20, 20, 80)),
                ReclaimCandidate::from(ReclaimSegment::new(30, 20, 80)),
            ]
        );
    }

    #[test]
    fn completion_plan_accounts_successful_reclaims() {
        let plan = plan_reclaim_completion(
            [
                ReclaimCandidate::from(ReclaimSegment::new(1, 10, 90)),
                ReclaimCandidate::from(ReclaimSegment::new(2, 20, 80)),
            ],
            [
                ReclaimCompletionOutcome::Reclaimed { segment_id: 1 },
                ReclaimCompletionOutcome::Reclaimed { segment_id: 2 },
            ],
        )
        .expect("completion plan");

        assert_eq!(
            candidate_ids_from_slice(&plan.reclaimed_candidates),
            vec![1, 2]
        );
        assert!(plan.retained_failures.is_empty());
        assert!(plan.pending_candidates.is_empty());
        assert!(plan.retryable_candidates.is_empty());
        assert_eq!(plan.total_reclaimed_bytes, 170);
    }

    #[test]
    fn completion_plan_retains_failures_in_candidate_order() {
        let plan = plan_reclaim_completion(
            [
                ReclaimCandidate::from(ReclaimSegment::new(1, 10, 90)),
                ReclaimCandidate::from(ReclaimSegment::new(2, 20, 80)),
                ReclaimCandidate::from(ReclaimSegment::new(3, 30, 70)),
            ],
            [
                ReclaimCompletionOutcome::Failed { segment_id: 2 },
                ReclaimCompletionOutcome::Reclaimed { segment_id: 3 },
                ReclaimCompletionOutcome::Failed { segment_id: 1 },
            ],
        )
        .expect("completion plan");

        assert_eq!(
            candidate_ids_from_slice(&plan.reclaimed_candidates),
            vec![3]
        );
        assert_eq!(
            candidate_ids_from_slice(&plan.retained_failures),
            vec![1, 2]
        );
        assert!(plan.pending_candidates.is_empty());
        assert_eq!(
            candidate_ids_from_slice(&plan.retryable_candidates),
            vec![1, 2]
        );
        assert_eq!(plan.total_reclaimed_bytes, 70);
    }

    #[test]
    fn completion_plan_tracks_pending_candidates_as_retryable() {
        let plan = plan_reclaim_completion(
            [
                ReclaimCandidate::from(ReclaimSegment::new(1, 10, 90)),
                ReclaimCandidate::from(ReclaimSegment::new(2, 20, 80)),
            ],
            [ReclaimCompletionOutcome::Reclaimed { segment_id: 2 }],
        )
        .expect("completion plan");

        assert_eq!(
            candidate_ids_from_slice(&plan.reclaimed_candidates),
            vec![2]
        );
        assert!(plan.retained_failures.is_empty());
        assert_eq!(candidate_ids_from_slice(&plan.pending_candidates), vec![1]);
        assert_eq!(
            candidate_ids_from_slice(&plan.retryable_candidates),
            vec![1]
        );
        assert_eq!(plan.total_reclaimed_bytes, 80);
    }

    #[test]
    fn completion_plan_rejects_unplanned_outcome() {
        let error = plan_reclaim_completion(
            [ReclaimCandidate::from(ReclaimSegment::new(1, 10, 90))],
            [ReclaimCompletionOutcome::Reclaimed { segment_id: 99 }],
        )
        .expect_err("unplanned outcome should fail");

        assert_eq!(
            error,
            ReclaimCompletionPlanError::UnplannedOutcome { segment_id: 99 }
        );
    }

    #[test]
    fn completion_plan_rejects_duplicate_outcomes() {
        let error = plan_reclaim_completion(
            [ReclaimCandidate::from(ReclaimSegment::new(1, 10, 90))],
            [
                ReclaimCompletionOutcome::Failed { segment_id: 1 },
                ReclaimCompletionOutcome::Reclaimed { segment_id: 1 },
            ],
        )
        .expect_err("duplicate outcome should fail");

        assert_eq!(
            error,
            ReclaimCompletionPlanError::DuplicateOutcome { segment_id: 1 }
        );
    }

    #[test]
    fn completion_plan_rejects_duplicate_selected_candidates() {
        let error = plan_reclaim_completion(
            [
                ReclaimCandidate::from(ReclaimSegment::new(1, 10, 90)),
                ReclaimCandidate::from(ReclaimSegment::new(1, 20, 80)),
            ],
            [ReclaimCompletionOutcome::Reclaimed { segment_id: 1 }],
        )
        .expect_err("duplicate selected candidate should fail");

        assert_eq!(
            error,
            ReclaimCompletionPlanError::DuplicateSelectedCandidate { segment_id: 1 }
        );
    }

    #[test]
    fn completion_plan_uses_u128_reclaimed_byte_accounting() {
        let plan = plan_reclaim_completion(
            [
                ReclaimCandidate::from(ReclaimSegment::new(1, 0, u64::MAX)),
                ReclaimCandidate::from(ReclaimSegment::new(2, 0, u64::MAX)),
            ],
            [
                ReclaimCompletionOutcome::Reclaimed { segment_id: 1 },
                ReclaimCompletionOutcome::Reclaimed { segment_id: 2 },
            ],
        )
        .expect("completion plan");

        assert_eq!(plan.total_reclaimed_bytes, u64::MAX as u128 * 2);
    }

    fn candidate_ids(plan: &ReclaimPlan) -> Vec<u64> {
        plan.candidates
            .iter()
            .map(|candidate| candidate.segment_id)
            .collect()
    }

    fn candidate_ids_from_slice(candidates: &[ReclaimCandidate]) -> Vec<u64> {
        candidates
            .iter()
            .map(|candidate| candidate.segment_id)
            .collect()
    }

    // ==================================================================
    // Reclaim-queue consumer tests
    // ==================================================================

    // -- mock implementations --

    /// Mock segment resolver: maps ObjectKey[0] -> segment_id.
    #[derive(Clone)]
    struct MockResolver {
        mapping: std::collections::HashMap<u8, u64>,
    }

    impl MockResolver {
        fn new() -> Self {
            Self {
                mapping: std::collections::HashMap::new(),
            }
        }

        fn set(&mut self, key_byte: u8, segment_id: u64) {
            self.mapping.insert(key_byte, segment_id);
        }
    }

    impl SegmentResolver for MockResolver {
        type Error = String;

        fn resolve(&self, key: &ObjectKey) -> Result<Option<u64>, Self::Error> {
            Ok(self.mapping.get(&key.0[0]).copied())
        }
    }

    /// Mock segment freer: records freed segment ids.
    #[derive(Clone, Default)]
    struct MockFreer {
        freed: std::cell::RefCell<Vec<u64>>,
        fail_on: std::cell::RefCell<Option<u64>>,
    }

    impl MockFreer {
        fn new() -> Self {
            Self::default()
        }

        fn set_fail_on(&self, segment_id: u64) {
            *self.fail_on.borrow_mut() = Some(segment_id);
        }

        fn freed_segments(&self) -> Vec<u64> {
            self.freed.borrow().clone()
        }
    }

    impl SegmentFreer for MockFreer {
        type Error = String;

        fn free_segment(&mut self, segment_id: u64) -> Result<(), Self::Error> {
            if self.fail_on.borrow().as_ref() == Some(&segment_id) {
                return Err(format!("mock free failure for segment {segment_id}"));
            }
            self.freed.borrow_mut().push(segment_id);
            Ok(())
        }
    }

    /// Gate that allows everything with stable committed clearance evidence.
    struct AllowAllGate;
    impl ReclaimGate for AllowAllGate {
        fn check_extent(&self, _extent_key: &ObjectKey) -> GateDecision {
            GateDecision::Allow(ClearanceEvidence::Verified {
                deadlist_committed_txg: 100,
                pin_clearance_epoch: 10,
            })
        }
    }

    /// Gate that denies extents whose key[0] is in a deny set.
    struct DenySetGate {
        deny_keys: Vec<u8>,
        reason: GateDenyReason,
    }
    impl ReclaimGate for DenySetGate {
        fn check_extent(&self, extent_key: &ObjectKey) -> GateDecision {
            if self.deny_keys.contains(&extent_key.0[0]) {
                GateDecision::Deny(self.reason)
            } else {
                GateDecision::Allow(ClearanceEvidence::Verified {
                    deadlist_committed_txg: 100,
                    pin_clearance_epoch: 10,
                })
            }
        }
    }

    // Helper: create an ObjectKey from a u8.
    fn obj_key(id: u8) -> ObjectKey {
        let mut k = [0u8; 32];
        k[0] = id;
        ObjectKey(k)
    }

    // Helper: create a ReclaimQueueEntry.
    fn entry(id: u8, delta: i64) -> ReclaimQueueEntry {
        let mut k = [0u8; 32];
        k[0] = id;
        ReclaimQueueEntry::new(
            ObjectKey(k),
            delta,
            tidefs_types_reclaim_queue_core::QueueFamily::Extent,
        )
    }

    fn receipt_for(
        key: ObjectKey,
        generation: u64,
    ) -> tidefs_types_reclaim_queue_core::DeadObjectReplacementReceipt {
        let mut digest = [0u8; 32];
        digest[0] = key.0[0];
        digest[8..16].copy_from_slice(&generation.to_le_bytes());
        tidefs_types_reclaim_queue_core::DeadObjectReplacementReceipt::replicated(
            key, 1, generation, 2, 4096, digest,
        )
    }

    fn erasure_receipt_for(
        key: ObjectKey,
        generation: u64,
        data_shards: u8,
        parity_shards: u8,
    ) -> tidefs_types_reclaim_queue_core::DeadObjectReplacementReceipt {
        let mut digest = [0u8; 32];
        digest[0] = key.0[0];
        digest[8..16].copy_from_slice(&generation.to_le_bytes());
        tidefs_types_reclaim_queue_core::DeadObjectReplacementReceipt::erasure_coded(
            key,
            1,
            generation,
            data_shards,
            parity_shards,
            4096,
            digest,
        )
    }

    fn dead_entry(
        id: u8,
        death_commit_group: u64,
        eligible: bool,
        receipt_generation: Option<u64>,
    ) -> tidefs_types_reclaim_queue_core::DeadObjectEntry {
        let key = obj_key(id);
        let entry = tidefs_types_reclaim_queue_core::DeadObjectEntry::new(
            key,
            [id; 16],
            death_commit_group,
            eligible,
            death_commit_group,
        );
        match receipt_generation {
            Some(generation) => entry.with_replacement_receipt(receipt_for(key, generation)),
            None => entry,
        }
    }

    fn dead_erasure_entry(
        id: u8,
        death_commit_group: u64,
        eligible: bool,
        receipt_generation: Option<u64>,
        data_shards: u8,
        parity_shards: u8,
    ) -> tidefs_types_reclaim_queue_core::DeadObjectEntry {
        let key = obj_key(id);
        let entry = tidefs_types_reclaim_queue_core::DeadObjectEntry::new(
            key,
            [id; 16],
            death_commit_group,
            eligible,
            death_commit_group,
        );
        match receipt_generation {
            Some(generation) => entry.with_replacement_receipt(erasure_receipt_for(
                key,
                generation,
                data_shards,
                parity_shards,
            )),
            None => entry,
        }
    }

    // -- drain_reclaim_queue tests --

    #[test]
    fn drain_empty_entries_is_noop() {
        let mut live_counts = SegmentLiveCounts::new();
        let resolver = MockResolver::new();
        let mut freer = MockFreer::new();
        let config = ReclaimConsumerConfig::default();

        let stats = drain_reclaim_queue(&[], &resolver, &mut freer, &mut live_counts, &config)
            .expect("drain should succeed on empty input");

        assert!(stats.is_idle());
        assert_eq!(stats.entries_processed, 0);
        assert_eq!(stats.segments_reclaimed, 0);
        assert_eq!(stats.blocks_freed, 0);
        assert!(freer.freed_segments().is_empty());
    }

    #[test]
    fn drain_single_fully_dead_segment_frees_it() {
        let mut resolver = MockResolver::new();
        resolver.set(1, 100);
        resolver.set(2, 100);

        let mut live_counts = SegmentLiveCounts::new();
        // Segment 100 has two live objects
        live_counts.set_live_count(100, 2);

        let mut freer = MockFreer::new();
        let config = ReclaimConsumerConfig::default();

        let entries = vec![(obj_key(1), entry(1, -1)), (obj_key(2), entry(2, -1))];

        let stats = drain_reclaim_queue(&entries, &resolver, &mut freer, &mut live_counts, &config)
            .expect("drain should succeed");

        assert_eq!(stats.entries_processed, 2);
        assert_eq!(stats.segments_reclaimed, 1);
        assert!(stats.checkpoint_batches >= 1);
        assert_eq!(freer.freed_segments(), vec![100]);
        assert!(!live_counts.is_empty() || live_counts.live_count(100) == 0);
    }

    #[test]
    fn drain_partially_live_segment_not_freed() {
        let mut resolver = MockResolver::new();
        resolver.set(1, 100);
        resolver.set(2, 100);
        resolver.set(3, 100);

        let mut live_counts = SegmentLiveCounts::new();
        // Segment 100 has 3 live objects; we delete only 1
        live_counts.set_live_count(100, 3);

        let mut freer = MockFreer::new();
        let config = ReclaimConsumerConfig::default();

        let entries = vec![(obj_key(1), entry(1, -1))];

        let stats = drain_reclaim_queue(&entries, &resolver, &mut freer, &mut live_counts, &config)
            .expect("drain should succeed");

        assert_eq!(stats.entries_processed, 1);
        assert_eq!(stats.segments_reclaimed, 0);
        assert!(freer.freed_segments().is_empty());
        // Segment 100 still has 2 live objects
        assert_eq!(live_counts.live_count(100), 2);
    }

    #[test]
    fn drain_respects_max_entries_per_drain() {
        let mut resolver = MockResolver::new();
        for i in 0..20u8 {
            resolver.set(i, (i % 4) as u64);
        }

        let mut live_counts = SegmentLiveCounts::new();
        for seg in 0..4u64 {
            live_counts.set_live_count(seg, 5); // each segment has 5 objects
        }

        let mut freer = MockFreer::new();
        let config = ReclaimConsumerConfig {
            max_entries_per_drain: 10,
            ..ReclaimConsumerConfig::default()
        };

        let entries: Vec<_> = (0..20u8).map(|i| (obj_key(i), entry(i, -1))).collect();

        let stats = drain_reclaim_queue(&entries, &resolver, &mut freer, &mut live_counts, &config)
            .expect("drain should succeed");

        // Only first 10 entries processed
        assert_eq!(stats.entries_processed, 10);
        // None should be dead yet (5 initial - ~2 deletes per seg = still live)
        assert_eq!(stats.segments_reclaimed, 0);
    }

    #[test]
    fn drain_batching_accumulates_dead_segments() {
        let mut resolver = MockResolver::new();
        for seg in 0..10u64 {
            for obj in 0..2u8 {
                resolver.set((seg * 2 + obj as u64) as u8, seg);
            }
        }

        let mut live_counts = SegmentLiveCounts::new();
        for seg in 0..10u64 {
            live_counts.set_live_count(seg, 2); // 2 objects per segment
        }

        let mut freer = MockFreer::new();
        let config = ReclaimConsumerConfig {
            max_entries_per_drain: 100,
            max_free_batch: 3, // batch size of 3
        };

        let entries: Vec<_> = (0..10u64)
            .flat_map(|seg| {
                let obj1 = (seg * 2) as u8;
                let obj2 = (seg * 2 + 1) as u8;
                vec![
                    (obj_key(obj1), entry(obj1, -1)),
                    (obj_key(obj2), entry(obj2, -1)),
                ]
            })
            .collect();

        let stats = drain_reclaim_queue(&entries, &resolver, &mut freer, &mut live_counts, &config)
            .expect("drain should succeed");

        assert_eq!(stats.entries_processed, 20);
        assert_eq!(stats.segments_reclaimed, 10);
        // 10 dead segments, max_free_batch=3 -> ceil(10/3) = 4 batches
        assert_eq!(stats.checkpoint_batches, 4);
        assert_eq!(freer.freed_segments().len(), 10);
    }

    #[test]
    fn drain_unknown_object_key_skipped() {
        let mut resolver = MockResolver::new();
        // Object 1 and 3 are known, 2 is not
        resolver.set(1, 100);
        resolver.set(3, 100);

        let mut live_counts = SegmentLiveCounts::new();
        live_counts.set_live_count(100, 2);

        let mut freer = MockFreer::new();
        let config = ReclaimConsumerConfig::default();

        let entries = vec![
            (obj_key(1), entry(1, -1)),
            (obj_key(2), entry(2, -1)), // unknown -> skip
            (obj_key(3), entry(3, -1)),
        ];

        let stats = drain_reclaim_queue(&entries, &resolver, &mut freer, &mut live_counts, &config)
            .expect("drain should succeed");

        // 2 resolved + processed, 3rd skipped
        assert_eq!(stats.entries_processed, 2);
        assert_eq!(stats.segments_reclaimed, 1);
        assert_eq!(freer.freed_segments(), vec![100]);
    }

    #[test]
    fn drain_positive_delta_increments_live_count() {
        let mut resolver = MockResolver::new();
        resolver.set(1, 100);
        resolver.set(2, 100);

        let mut live_counts = SegmentLiveCounts::new();
        live_counts.set_live_count(100, 1);

        let mut freer = MockFreer::new();
        let config = ReclaimConsumerConfig::default();

        // Deletion then re-addition (snapshot clone reference)
        let entries = vec![
            (obj_key(1), entry(1, -1)), // live_count -> 0 (dead)
            (obj_key(2), entry(2, 1)),  // live_count -> 1 (revived)
        ];

        let stats = drain_reclaim_queue(&entries, &resolver, &mut freer, &mut live_counts, &config)
            .expect("drain should succeed");

        assert_eq!(stats.entries_processed, 2);
        // Segment went to 0 then back to 1; should not be freed
        assert_eq!(stats.segments_reclaimed, 0);
        assert!(freer.freed_segments().is_empty());
        assert_eq!(live_counts.live_count(100), 1);
    }

    #[test]
    fn drain_freer_error_propagates() {
        let mut resolver = MockResolver::new();
        resolver.set(1, 100);
        resolver.set(2, 100);

        let mut live_counts = SegmentLiveCounts::new();
        live_counts.set_live_count(100, 2);

        let mut freer = MockFreer::new();
        freer.set_fail_on(100); // will fail on first free

        let config = ReclaimConsumerConfig::default();

        let entries = vec![(obj_key(1), entry(1, -1)), (obj_key(2), entry(2, -1))];

        let result =
            drain_reclaim_queue(&entries, &resolver, &mut freer, &mut live_counts, &config);

        assert!(result.is_err());
        match result {
            Err(DrainError::FreeError { segment_id, .. }) => {
                assert_eq!(segment_id, 100);
            }
            _ => panic!("expected FreeError"),
        }
    }

    #[test]
    fn receipt_bound_dead_object_drain_frees_authorized_segment() {
        let mut queue = DeadObjectReclaimQueue::new();
        queue.enqueue(dead_entry(1, 5, true, Some(10)));
        queue.enqueue(dead_entry(2, 5, true, Some(11)));
        queue.enqueue(dead_entry(3, 5, true, None));

        let mut resolver = MockResolver::new();
        resolver.set(1, 100);
        resolver.set(2, 100);
        resolver.set(3, 101);

        let mut live_counts = SegmentLiveCounts::new();
        live_counts.set_live_count(100, 2);
        let mut freer = MockFreer::new();
        let config = ReclaimConsumerConfig::default();

        let drain = drain_receipt_bound_dead_objects(
            &queue,
            6,
            11,
            16,
            &resolver,
            &mut freer,
            &mut live_counts,
            &config,
            &AllowAllGate,
        )
        .expect("receipt-bound drain");

        assert_eq!(drain.ack_object_ids, vec![obj_key(1), obj_key(2)]);
        assert_eq!(drain.stats.entries_processed, 2);
        assert_eq!(drain.stats.segments_reclaimed, 1);
        assert_eq!(drain.stats.blocks_freed, 2);
        assert_eq!(drain.stats.reclaim_queue_depth, 1);
        assert_eq!(
            drain.receipt.as_ref().map(|receipt| (
                receipt.freed_extents.clone(),
                receipt.freed_segment_extents.clone(),
                receipt.deadlist_committed_txg,
                receipt.pin_clearance_epoch,
            )),
            Some((
                vec![obj_key(1), obj_key(2)],
                vec![
                    ReclaimReceiptExtent::new(100, obj_key(1)),
                    ReclaimReceiptExtent::new(100, obj_key(2)),
                ],
                100,
                10,
            ))
        );
        assert_eq!(freer.freed_segments(), vec![100]);
        assert!(live_counts.is_dead(100));
    }

    #[test]
    fn receipt_bound_dead_object_drain_skips_gate_denied_segment() {
        let mut queue = DeadObjectReclaimQueue::new();
        queue.enqueue(dead_entry(1, 5, true, Some(10)));
        queue.enqueue(dead_entry(2, 5, true, Some(11)));

        let mut resolver = MockResolver::new();
        resolver.set(1, 100);
        resolver.set(2, 100);

        let mut live_counts = SegmentLiveCounts::new();
        live_counts.set_live_count(100, 2);
        let mut freer = MockFreer::new();
        let config = ReclaimConsumerConfig::default();
        let gate = DenySetGate {
            deny_keys: vec![2],
            reason: GateDenyReason::DeadlistReferenced,
        };

        let drain = drain_receipt_bound_dead_objects(
            &queue,
            6,
            11,
            16,
            &resolver,
            &mut freer,
            &mut live_counts,
            &config,
            &gate,
        )
        .expect("receipt-bound gated drain");

        assert!(drain.ack_object_ids.is_empty());
        assert_eq!(drain.stats.entries_processed, 2);
        assert_eq!(drain.stats.segments_reclaimed, 0);
        assert_eq!(drain.stats.gate_segments_skipped, 1);
        assert_eq!(drain.stats.gate_extents_denied, 1);
        assert_eq!(drain.stats.reclaim_queue_depth, 2);
        assert!(drain.receipt.is_none());
        assert_eq!(live_counts.live_count(100), 2);
        assert!(freer.freed_segments().is_empty());
    }

    #[test]
    fn receipt_bound_dead_object_drain_keeps_partial_segment_entries_queued() {
        let mut queue = DeadObjectReclaimQueue::new();
        queue.enqueue(dead_entry(1, 5, true, Some(10)));
        queue.enqueue(dead_entry(2, 5, true, Some(11)));

        let mut resolver = MockResolver::new();
        resolver.set(1, 100);
        resolver.set(2, 100);

        let mut live_counts = SegmentLiveCounts::new();
        live_counts.set_live_count(100, 2);
        let mut freer = MockFreer::new();
        let config = ReclaimConsumerConfig::default();

        let partial = drain_receipt_bound_dead_objects(
            &queue,
            6,
            11,
            1,
            &resolver,
            &mut freer,
            &mut live_counts,
            &config,
            &AllowAllGate,
        )
        .expect("receipt-bound partial drain");

        assert!(partial.ack_object_ids.is_empty());
        assert_eq!(partial.stats.entries_processed, 1);
        assert_eq!(partial.stats.segments_reclaimed, 0);
        assert_eq!(partial.stats.reclaim_queue_depth, 2);
        assert!(partial.receipt.is_none());
        assert_eq!(live_counts.live_count(100), 2);
        assert!(freer.freed_segments().is_empty());

        let gate = DenySetGate {
            deny_keys: vec![1],
            reason: GateDenyReason::SnapshotPinned,
        };
        let denied = drain_receipt_bound_dead_objects(
            &queue,
            6,
            11,
            16,
            &resolver,
            &mut freer,
            &mut live_counts,
            &config,
            &gate,
        )
        .expect("receipt-bound denied full drain");

        assert!(denied.ack_object_ids.is_empty());
        assert_eq!(denied.stats.entries_processed, 2);
        assert_eq!(denied.stats.segments_reclaimed, 0);
        assert_eq!(denied.stats.gate_segments_skipped, 1);
        assert_eq!(denied.stats.gate_extents_denied, 1);
        assert_eq!(denied.stats.reclaim_queue_depth, 2);
        assert!(denied.receipt.is_none());
        assert_eq!(live_counts.live_count(100), 2);
        assert!(freer.freed_segments().is_empty());
    }

    #[test]
    fn receipt_bound_dead_object_drain_refuses_legacy_and_unstable_entries() {
        let mut queue = DeadObjectReclaimQueue::new();
        queue.enqueue(dead_entry(1, 5, true, None));
        queue.enqueue(dead_entry(2, 5, true, Some(0)));
        queue.enqueue(dead_entry(3, 7, true, Some(12)));
        queue.enqueue(dead_entry(4, 5, false, Some(13)));
        queue.enqueue(dead_entry(5, 5, true, Some(12)));

        let mut resolver = MockResolver::new();
        for id in 1..=5u8 {
            resolver.set(id, 100);
        }

        let mut live_counts = SegmentLiveCounts::new();
        live_counts.set_live_count(100, 5);
        let mut freer = MockFreer::new();
        let config = ReclaimConsumerConfig::default();

        let drain = drain_receipt_bound_dead_objects(
            &queue,
            6,
            11,
            16,
            &resolver,
            &mut freer,
            &mut live_counts,
            &config,
            &AllowAllGate,
        )
        .expect("receipt-bound drain");

        assert!(drain.is_idle());
        assert_eq!(drain.stats.reclaim_queue_depth, 5);
        assert_eq!(live_counts.live_count(100), 5);
        assert!(freer.freed_segments().is_empty());
    }

    #[test]
    fn receipt_bound_dead_object_drain_waits_for_stable_generation() {
        let mut queue = DeadObjectReclaimQueue::new();
        queue.enqueue(dead_entry(1, 4, true, Some(7)));

        let mut resolver = MockResolver::new();
        resolver.set(1, 100);

        let mut live_counts = SegmentLiveCounts::new();
        live_counts.set_live_count(100, 1);
        let mut freer = MockFreer::new();
        let config = ReclaimConsumerConfig::default();

        let held = drain_receipt_bound_dead_objects(
            &queue,
            6,
            6,
            16,
            &resolver,
            &mut freer,
            &mut live_counts,
            &config,
            &AllowAllGate,
        )
        .expect("receipt-bound held drain");

        assert!(held.is_idle());
        assert_eq!(held.stats.reclaim_queue_depth, 1);
        assert_eq!(live_counts.live_count(100), 1);
        assert!(freer.freed_segments().is_empty());

        let drained = drain_receipt_bound_dead_objects(
            &queue,
            6,
            7,
            16,
            &resolver,
            &mut freer,
            &mut live_counts,
            &config,
            &AllowAllGate,
        )
        .expect("receipt-bound stable drain");

        assert_eq!(drained.ack_object_ids, vec![obj_key(1)]);
        assert_eq!(drained.stats.entries_processed, 1);
        assert_eq!(drained.stats.segments_reclaimed, 1);
        assert_eq!(freer.freed_segments(), vec![100]);
        assert!(live_counts.is_dead(100));
    }

    #[test]
    fn receipt_bound_dead_object_drain_respects_service_limit() {
        let mut queue = DeadObjectReclaimQueue::new();
        for id in 1..=4u8 {
            queue.enqueue(dead_entry(id, 5, true, Some(id as u64 + 10)));
        }

        let mut resolver = MockResolver::new();
        for id in 1..=4u8 {
            resolver.set(id, 200);
        }

        let mut live_counts = SegmentLiveCounts::new();
        live_counts.set_live_count(200, 4);
        let mut freer = MockFreer::new();
        let config = ReclaimConsumerConfig {
            max_entries_per_drain: 2,
            ..ReclaimConsumerConfig::default()
        };

        let drain = drain_receipt_bound_dead_objects(
            &queue,
            6,
            14,
            4,
            &resolver,
            &mut freer,
            &mut live_counts,
            &config,
            &AllowAllGate,
        )
        .expect("receipt-bound drain");

        assert!(drain.ack_object_ids.is_empty());
        assert_eq!(drain.stats.entries_processed, 2);
        assert_eq!(drain.stats.segments_reclaimed, 0);
        assert_eq!(drain.stats.reclaim_queue_depth, 4);
        assert_eq!(live_counts.live_count(200), 4);
        assert!(freer.freed_segments().is_empty());
    }

    #[test]
    fn consumer_service_drains_receipt_bound_dead_objects() {
        let mut queue = DeadObjectReclaimQueue::new();
        queue.enqueue(dead_entry(8, 5, true, Some(18)));

        let mut resolver = MockResolver::new();
        resolver.set(8, 300);

        let mut live_counts = SegmentLiveCounts::new();
        live_counts.set_live_count(300, 1);
        let mut service =
            ReclaimConsumerService::new(ReclaimConsumerConfig::default(), live_counts);
        let mut freer = MockFreer::new();

        let drain = service
            .drain_receipt_bound_dead_objects(
                &queue,
                6,
                18,
                8,
                &resolver,
                &mut freer,
                &AllowAllGate,
            )
            .expect("service receipt-bound drain");

        assert_eq!(drain.ack_object_ids, vec![obj_key(8)]);
        assert_eq!(drain.stats.segments_reclaimed, 1);
        assert_eq!(freer.freed_segments(), vec![300]);
        assert!(service.live_counts().is_dead(300));
    }

    #[test]
    fn receipt_bound_dead_object_drain_keeps_erasure_partial_segment_queued() {
        let mut queue = DeadObjectReclaimQueue::new();
        queue.enqueue(dead_erasure_entry(1, 4, true, Some(10), 3, 2));
        queue.enqueue(dead_erasure_entry(2, 4, true, Some(11), 3, 2));
        queue.enqueue(dead_entry(3, 4, true, None));

        let mut resolver = MockResolver::new();
        resolver.set(1, 100);
        resolver.set(2, 100);
        resolver.set(3, 100);

        let mut live_counts = SegmentLiveCounts::new();
        live_counts.set_live_count(100, 3);
        let mut freer = MockFreer::new();
        let config = ReclaimConsumerConfig::default();

        let drain = drain_receipt_bound_dead_objects(
            &queue,
            6,
            11,
            16,
            &resolver,
            &mut freer,
            &mut live_counts,
            &config,
            &AllowAllGate,
        )
        .expect("receipt-bound erasure drain");

        assert!(drain.ack_object_ids.is_empty());
        assert_eq!(drain.stats.entries_processed, 2);
        assert_eq!(drain.stats.segments_reclaimed, 0);
        assert_eq!(drain.stats.reclaim_queue_depth, 3);
        assert!(drain.receipt.is_none());
        assert!(freer.freed_segments().is_empty());
        assert!(!live_counts.is_dead(100));
        assert_eq!(live_counts.live_count(100), 3);
    }

    #[test]
    fn receipt_bound_dead_object_drain_frees_erasure_segment() {
        let mut queue = DeadObjectReclaimQueue::new();
        queue.enqueue(dead_erasure_entry(1, 4, true, Some(10), 2, 1));

        let mut resolver = MockResolver::new();
        resolver.set(1, 200);

        let mut live_counts = SegmentLiveCounts::new();
        live_counts.set_live_count(200, 1);
        let mut freer = MockFreer::new();
        let config = ReclaimConsumerConfig::default();

        let drain = drain_receipt_bound_dead_objects(
            &queue,
            6,
            10,
            16,
            &resolver,
            &mut freer,
            &mut live_counts,
            &config,
            &AllowAllGate,
        )
        .expect("receipt-bound erasure segment drain");

        assert_eq!(drain.ack_object_ids, vec![obj_key(1)]);
        assert_eq!(drain.stats.segments_reclaimed, 1);
        assert_eq!(drain.stats.blocks_freed, 1);
        assert_eq!(freer.freed_segments(), vec![200]);
        assert!(live_counts.is_dead(200));
    }

    #[test]
    fn receipt_bound_dead_object_drain_mixed_replicated_and_erasure() {
        let mut queue = DeadObjectReclaimQueue::new();
        queue.enqueue(dead_entry(1, 4, true, Some(10)));
        queue.enqueue(dead_erasure_entry(2, 4, true, Some(11), 2, 1));
        queue.enqueue(dead_entry(3, 4, true, Some(12)));
        queue.enqueue(dead_erasure_entry(4, 4, true, Some(13), 3, 2));

        let mut resolver = MockResolver::new();
        for id in 1..=4u8 {
            resolver.set(id, 300);
        }

        let mut live_counts = SegmentLiveCounts::new();
        live_counts.set_live_count(300, 4);
        let mut freer = MockFreer::new();
        let config = ReclaimConsumerConfig::default();

        let drain = drain_receipt_bound_dead_objects(
            &queue,
            6,
            13,
            16,
            &resolver,
            &mut freer,
            &mut live_counts,
            &config,
            &AllowAllGate,
        )
        .expect("mixed receipt-bound drain");

        assert_eq!(drain.ack_object_ids.len(), 4);
        assert_eq!(drain.stats.entries_processed, 4);
        assert_eq!(drain.stats.segments_reclaimed, 1);
        assert_eq!(drain.stats.blocks_freed, 4);
        assert_eq!(freer.freed_segments(), vec![300]);
        assert!(live_counts.is_dead(300));
    }

    // -- SegmentLiveCounts tests --

    #[test]
    fn live_counts_new_is_empty() {
        let c = SegmentLiveCounts::new();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn live_counts_set_and_get() {
        let mut c = SegmentLiveCounts::new();
        c.set_live_count(42, 5);
        assert_eq!(c.live_count(42), 5);
        assert_eq!(c.len(), 1);
        assert!(!c.is_empty());
        assert!(!c.is_dead(42));
    }

    #[test]
    fn live_counts_apply_negative_delta() {
        let mut c = SegmentLiveCounts::new();
        c.set_live_count(1, 10);
        assert_eq!(c.apply_delta(1, -3), 7);
        assert_eq!(c.live_count(1), 7);
    }

    #[test]
    fn live_counts_apply_positive_delta() {
        let mut c = SegmentLiveCounts::new();
        c.set_live_count(1, 5);
        assert_eq!(c.apply_delta(1, 3), 8);
        assert_eq!(c.live_count(1), 8);
    }

    #[test]
    fn live_counts_apply_zero_delta_noop() {
        let mut c = SegmentLiveCounts::new();
        c.set_live_count(1, 5);
        assert_eq!(c.apply_delta(1, 0), 5);
    }

    #[test]
    fn live_counts_clamped_at_zero() {
        let mut c = SegmentLiveCounts::new();
        c.set_live_count(1, 3);
        assert_eq!(c.apply_delta(1, -10), 0);
        assert!(c.is_dead(1));
        // Should be removed from tracking when count hits 0
        assert_eq!(c.live_count(1), 0);
    }

    #[test]
    fn live_counts_zero_count_removes_segment() {
        let mut c = SegmentLiveCounts::new();
        c.set_live_count(1, 0); // setting to zero should remove
        assert_eq!(c.live_count(1), 0);
        assert!(c.is_dead(1));
    }

    #[test]
    fn live_counts_is_dead_only_zero_count() {
        let mut c = SegmentLiveCounts::new();
        c.set_live_count(1, 1);
        assert!(!c.is_dead(1));
        c.apply_delta(1, -1);
        assert!(c.is_dead(1));
    }

    #[test]
    fn live_counts_remove_returns_previous() {
        let mut c = SegmentLiveCounts::new();
        c.set_live_count(1, 5);
        assert_eq!(c.remove(1), Some(5));
        assert_eq!(c.live_count(1), 0);
        assert_eq!(c.remove(1), None);
    }

    #[test]
    fn live_counts_unknown_segment_is_dead() {
        let c = SegmentLiveCounts::new();
        // A segment not in the map has zero live objects = dead
        assert!(c.is_dead(999));
    }

    // -- ReclaimConsumerStats tests --

    #[test]
    fn consumer_stats_zero_is_idle() {
        assert!(ReclaimConsumerStats::ZERO.is_idle());
    }

    #[test]
    fn consumer_stats_active_is_not_idle() {
        let s = ReclaimConsumerStats {
            entries_processed: 1,
            ..ReclaimConsumerStats::ZERO
        };
        assert!(!s.is_idle());
    }

    // -- ReclaimConsumerConfig tests --

    #[test]
    fn consumer_config_default_values() {
        let c = ReclaimConsumerConfig::default();
        assert_eq!(c.max_entries_per_drain, 1024);
        assert_eq!(c.max_free_batch, 64);
    }

    // -- DrainError Display tests --

    #[test]
    fn drain_error_display_resolve() {
        let err: DrainError<String, String> = DrainError::ResolveError {
            key: obj_key(5),
            error: "not found".into(),
        };
        let s = format!("{err}");
        assert!(s.contains("segment resolve error"));
        assert!(s.contains("not found"));
    }

    #[test]
    fn drain_error_display_free() {
        let err: DrainError<String, String> = DrainError::FreeError {
            segment_id: 42,
            error: "disk full".into(),
        };
        let s = format!("{err}");
        assert!(s.contains("segment free error"));
        assert!(s.contains("segment 42"));
        assert!(s.contains("disk full"));
    }

    // -- Integration scenario: write, delete, drain, reallocate --

    #[test]
    fn integration_write_delete_drain_reallocate() {
        let mut resolver = MockResolver::new();
        // 3 segments (10, 20, 30), each with 2 objects
        resolver.set(1, 10);
        resolver.set(2, 10);
        resolver.set(3, 20);
        resolver.set(4, 20);
        resolver.set(5, 30);
        resolver.set(6, 30);

        let mut live_counts = SegmentLiveCounts::new();
        live_counts.set_live_count(10, 2);
        live_counts.set_live_count(20, 2);
        live_counts.set_live_count(30, 2);

        let mut freer = MockFreer::new();
        let config = ReclaimConsumerConfig::default();

        // Delete all objects in segment 10 and 30, but only one in 20
        let entries = vec![
            (obj_key(1), entry(1, -1)),
            (obj_key(2), entry(2, -1)), // seg 10 -> fully dead
            (obj_key(3), entry(3, -1)), // seg 20 -> partially dead
            (obj_key(5), entry(5, -1)),
            (obj_key(6), entry(6, -1)), // seg 30 -> fully dead
        ];

        let stats = drain_reclaim_queue(&entries, &resolver, &mut freer, &mut live_counts, &config)
            .expect("drain should succeed");

        assert_eq!(stats.entries_processed, 5);
        assert_eq!(stats.segments_reclaimed, 2); // segs 10 and 30

        let freed = freer.freed_segments();
        assert!(freed.contains(&10));
        assert!(freed.contains(&30));
        assert!(!freed.contains(&20));

        // Segment 20 still has 1 live object
        assert_eq!(live_counts.live_count(20), 1);
        assert!(!live_counts.is_dead(20));

        // Verify dead segments are no longer tracked
        assert!(live_counts.is_dead(10));
        assert!(live_counts.is_dead(30));
    }

    // ==================================================================
    // ReclaimConsumerService tests
    // ==================================================================

    #[test]
    fn consumer_service_new_has_config_and_live_counts() {
        let config = ReclaimConsumerConfig {
            max_entries_per_drain: 500,
            max_free_batch: 32,
        };
        let mut counts = SegmentLiveCounts::new();
        counts.set_live_count(10, 5);

        let svc = ReclaimConsumerService::new(config.clone(), counts.clone());
        assert_eq!(svc.config().max_entries_per_drain, 500);
        assert_eq!(svc.config().max_free_batch, 32);
        assert_eq!(svc.live_counts().live_count(10), 5);
        assert_eq!(svc.live_counts().live_count(20), 0);
    }

    #[test]
    fn consumer_service_drain_delegates_to_drain_reclaim_queue() {
        let config = ReclaimConsumerConfig::default();

        let mut resolver = MockResolver::new();
        resolver.set(1, 100);
        resolver.set(2, 100);

        let mut live_counts = SegmentLiveCounts::new();
        live_counts.set_live_count(100, 2);

        let mut svc = ReclaimConsumerService::new(config, live_counts);

        let mut freer = MockFreer::new();
        let entries = vec![(obj_key(1), entry(1, -1)), (obj_key(2), entry(2, -1))];

        let stats = svc
            .drain(&entries, &resolver, &mut freer)
            .expect("drain should succeed");

        assert_eq!(stats.entries_processed, 2);
        assert_eq!(stats.segments_reclaimed, 1);
        assert_eq!(freer.freed_segments(), vec![100]);
    }

    #[test]
    fn consumer_service_accumulates_across_drains() {
        let config = ReclaimConsumerConfig::default();

        let mut resolver = MockResolver::new();
        resolver.set(1, 100);
        resolver.set(2, 100);
        resolver.set(3, 100);

        // Segment 100 starts with 3 live objects
        let mut live_counts = SegmentLiveCounts::new();
        live_counts.set_live_count(100, 3);

        let mut svc = ReclaimConsumerService::new(config, live_counts);

        let mut freer = MockFreer::new();

        // First drain: delete object 1 only
        let entries_1 = vec![(obj_key(1), entry(1, -1))];
        let stats_1 = svc
            .drain(&entries_1, &resolver, &mut freer)
            .expect("first drain");
        assert_eq!(stats_1.entries_processed, 1);
        assert_eq!(stats_1.segments_reclaimed, 0);
        assert_eq!(svc.live_counts().live_count(100), 2);

        // Second drain: delete objects 2 and 3 -> segment fully dead
        let entries_2 = vec![(obj_key(2), entry(2, -1)), (obj_key(3), entry(3, -1))];
        let stats_2 = svc
            .drain(&entries_2, &resolver, &mut freer)
            .expect("second drain");
        assert_eq!(stats_2.entries_processed, 2);
        assert_eq!(stats_2.segments_reclaimed, 1);
        assert_eq!(freer.freed_segments(), vec![100]);
        assert!(svc.live_counts().is_dead(100));
    }

    #[test]
    fn consumer_service_live_counts_mut_allows_reinitialisation() {
        let config = ReclaimConsumerConfig::default();
        let counts = SegmentLiveCounts::new();
        let mut svc = ReclaimConsumerService::new(config, counts);

        svc.live_counts_mut().set_live_count(42, 10);
        assert_eq!(svc.live_counts().live_count(42), 10);
    }

    #[test]
    fn consumer_service_empty_entries_returns_idle_stats() {
        let config = ReclaimConsumerConfig::default();
        let counts = SegmentLiveCounts::new();
        let mut svc = ReclaimConsumerService::new(config, counts);

        let resolver = MockResolver::new();
        let mut freer = MockFreer::new();

        let stats = svc.drain(&[], &resolver, &mut freer).expect("empty drain");
        assert!(stats.is_idle());
        assert_eq!(stats.entries_processed, 0);
        assert_eq!(stats.segments_reclaimed, 0);
        assert!(freer.freed_segments().is_empty());
    }

    // ==================================================================
    // DedupReclaimWriter tests
    // ==================================================================

    // Helper: build a CanonicalDead outcome for a given LocatorId.
    fn make_dead_outcome(locator: u64) -> RemoveConsumerOutcome {
        RemoveConsumerOutcome::CanonicalDead {
            canonical_locator: tidefs_dedup::LocatorId(locator),
        }
    }

    /// A segment resolver that maps LocatorIds to segments by internally
    /// using `locator_id_to_object_key` and a HashMap.
    struct LocatorResolver {
        map: std::collections::HashMap<tidefs_dedup::LocatorId, u64>,
    }

    impl LocatorResolver {
        fn new() -> Self {
            Self {
                map: std::collections::HashMap::new(),
            }
        }

        fn set(&mut self, locator: u64, segment_id: u64) {
            self.map
                .insert(tidefs_dedup::LocatorId(locator), segment_id);
        }
    }

    impl SegmentResolver for LocatorResolver {
        type Error = String;

        fn resolve(&self, key: &ObjectKey) -> Result<Option<u64>, Self::Error> {
            // Extract LocatorId from ObjectKey by reading the first 8 bytes as big-endian u64
            let mut loc_bytes = [0u8; 8];
            loc_bytes.copy_from_slice(&key.0[..8]);
            let loc_id = tidefs_dedup::LocatorId(u64::from_be_bytes(loc_bytes));
            Ok(self.map.get(&loc_id).copied())
        }
    }

    #[test]
    fn dedup_writer_no_dead_outcomes_is_idle() {
        let counts = SegmentLiveCounts::new();
        let mut writer = DedupReclaimWriter::new(counts);
        let resolver = LocatorResolver::new();
        let mut freer = MockFreer::new();

        let outcomes = [RemoveConsumerOutcome::StillAlive; 3];
        let stats = writer
            .process_outcomes(&outcomes, &resolver, &mut freer)
            .expect("process should succeed");
        assert_eq!(stats.outcomes_processed, 3);
        assert_eq!(stats.dead_locators_queued, 0);
        assert_eq!(stats.segments_reclaimed, 0);
        assert!(freer.freed_segments().is_empty());
    }

    #[test]
    fn dedup_writer_single_dead_frees_segment() {
        let mut counts = SegmentLiveCounts::new();
        counts.set_live_count(100, 1); // one live object in segment 100

        let mut writer = DedupReclaimWriter::new(counts);

        let mut resolver = LocatorResolver::new();
        resolver.set(1, 100); // locator 1 → segment 100

        let mut freer = MockFreer::new();

        let outcomes = [make_dead_outcome(1)];
        let stats = writer
            .process_outcomes(&outcomes, &resolver, &mut freer)
            .expect("process should succeed");

        assert_eq!(stats.outcomes_processed, 1);
        assert_eq!(stats.dead_locators_queued, 1);
        assert_eq!(stats.deltas_applied, 1);
        assert_eq!(stats.segments_reclaimed, 1);
        assert_eq!(freer.freed_segments(), vec![100]);
        assert!(writer.live_counts().is_dead(100));
    }

    #[test]
    fn dedup_writer_partial_segment_not_freed() {
        let mut counts = SegmentLiveCounts::new();
        counts.set_live_count(200, 3); // 3 live objects in segment 200

        let mut writer = DedupReclaimWriter::new(counts);

        let mut resolver = LocatorResolver::new();
        resolver.set(2, 200);

        let mut freer = MockFreer::new();

        let outcomes = [make_dead_outcome(2)];
        let stats = writer
            .process_outcomes(&outcomes, &resolver, &mut freer)
            .expect("process should succeed");

        assert_eq!(stats.dead_locators_queued, 1);
        assert_eq!(stats.deltas_applied, 1);
        assert_eq!(stats.segments_reclaimed, 0); // not fully dead yet
        assert!(freer.freed_segments().is_empty());
        assert_eq!(writer.live_counts().live_count(200), 2);
    }

    #[test]
    fn dedup_writer_multiple_dead_two_segments() {
        let mut counts = SegmentLiveCounts::new();
        counts.set_live_count(10, 2); // 2 objects in segment 10
        counts.set_live_count(20, 3); // 3 objects in segment 20

        let mut writer = DedupReclaimWriter::new(counts);

        let mut resolver = LocatorResolver::new();
        resolver.set(5, 10);
        resolver.set(6, 10); // both in segment 10
        resolver.set(7, 20);

        let mut freer = MockFreer::new();

        let outcomes = [
            make_dead_outcome(5),
            make_dead_outcome(6), // segment 10 becomes fully dead here
            make_dead_outcome(7), // segment 20 goes to 2, not dead
        ];
        let stats = writer
            .process_outcomes(&outcomes, &resolver, &mut freer)
            .expect("process should succeed");

        assert_eq!(stats.outcomes_processed, 3);
        assert_eq!(stats.dead_locators_queued, 3);
        assert_eq!(stats.deltas_applied, 3);
        assert_eq!(stats.segments_reclaimed, 1); // only segment 10 freed
        assert_eq!(freer.freed_segments(), vec![10]);
        assert!(writer.live_counts().is_dead(10));
        assert_eq!(writer.live_counts().live_count(20), 2);
    }

    #[test]
    fn dedup_writer_unknown_locator_skipped() {
        let counts = SegmentLiveCounts::new();
        let mut writer = DedupReclaimWriter::new(counts);

        let resolver = LocatorResolver::new(); // no mappings
        let mut freer = MockFreer::new();

        let outcomes = [make_dead_outcome(999)];
        let stats = writer
            .process_outcomes(&outcomes, &resolver, &mut freer)
            .expect("process should succeed");

        assert_eq!(stats.outcomes_processed, 1);
        assert_eq!(stats.dead_locators_queued, 0); // skipped (resolved to None → segment 0 → skipped)
        assert_eq!(stats.segments_reclaimed, 0);
        assert!(freer.freed_segments().is_empty());
    }

    #[test]
    fn dedup_writer_mixed_outcomes() {
        let mut counts = SegmentLiveCounts::new();
        counts.set_live_count(42, 1);

        let mut writer = DedupReclaimWriter::new(counts);

        let mut resolver = LocatorResolver::new();
        resolver.set(3, 42);

        let mut freer = MockFreer::new();

        let outcomes = [
            RemoveConsumerOutcome::StillAlive,
            make_dead_outcome(3),
            RemoveConsumerOutcome::StillAlive,
        ];
        let stats = writer
            .process_outcomes(&outcomes, &resolver, &mut freer)
            .expect("process should succeed");

        assert_eq!(stats.outcomes_processed, 3);
        assert_eq!(stats.dead_locators_queued, 1);
        assert_eq!(stats.segments_reclaimed, 1);
        assert_eq!(freer.freed_segments(), vec![42]);
    }

    // ==================================================================
    // SegmentFreer for PoolAllocator tests
    // ==================================================================

    #[test]
    fn pool_allocator_segment_freer_frees_segment() {
        use tidefs_pool_allocator::PoolAllocator;
        use tidefs_spacemap_allocator::SegmentFreeMap;

        // 4 segments, all free initially: [0,4)
        let free_map = SegmentFreeMap::new(4, vec![(0, 4)]).expect("valid free map");
        let mut allocator = PoolAllocator::new(free_map);

        // Allocate segment 0
        let seg = allocator.allocate().expect("alloc");
        assert_eq!(seg, 0);
        assert!(!allocator.is_free(0));

        // Free it via the SegmentFreer impl
        <PoolAllocator as SegmentFreer>::free_segment(&mut allocator, 0).expect("free via trait");

        assert!(allocator.is_free(0));
    }

    #[test]
    fn pool_allocator_segment_freer_is_idempotent() {
        use tidefs_pool_allocator::PoolAllocator;
        use tidefs_spacemap_allocator::SegmentFreeMap;

        let free_map = SegmentFreeMap::new(4, vec![(0, 4)]).expect("valid free map");
        let mut allocator = PoolAllocator::new(free_map);

        // Segment 0 is already free; freeing again should not error
        let result = <PoolAllocator as SegmentFreer>::free_segment(&mut allocator, 0);
        assert!(result.is_ok(), "add_free must be idempotent");

        // Allocate then free twice
        let seg = allocator.allocate().expect("alloc");
        assert_eq!(seg, 0);
        <PoolAllocator as SegmentFreer>::free_segment(&mut allocator, seg).expect("first free");
        let result2 = <PoolAllocator as SegmentFreer>::free_segment(&mut allocator, seg);
        assert!(
            result2.is_ok(),
            "second free of same segment should be idempotent"
        );
        assert!(allocator.is_free(seg));
    }

    // -- ReclaimReceipt tests -------------------------------------------------

    fn receipt_extent_key(id: u8) -> ObjectKey {
        let mut k = [0u8; 32];
        k[0] = id;
        ObjectKey(k)
    }

    fn receipt_extent(segment_id: u64, id: u8) -> ReclaimReceiptExtent {
        ReclaimReceiptExtent::new(segment_id, receipt_extent_key(id))
    }

    #[test]
    fn reclaim_receipt_encode_decode_roundtrip_empty() {
        let receipt = ReclaimReceipt::new(Vec::new(), 100, 5);
        let encoded = receipt.encode();
        let decoded = ReclaimReceipt::decode(&encoded).unwrap();
        assert_eq!(decoded, receipt);
        assert!(decoded.is_empty());
    }

    #[test]
    fn reclaim_receipt_encode_decode_roundtrip_single_extent() {
        let receipt = ReclaimReceipt::new(vec![receipt_extent(9, 1)], 42, 7);
        let encoded = receipt.encode();
        assert_eq!(encoded.len(), ReclaimReceipt::encoded_len(1));
        let decoded = ReclaimReceipt::decode(&encoded).unwrap();
        assert_eq!(decoded, receipt);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded.freed_extents, vec![receipt_extent_key(1)]);
        assert_eq!(decoded.freed_segment_extents, vec![receipt_extent(9, 1)]);
    }

    #[test]
    fn reclaim_receipt_encode_decode_roundtrip_many_extents() {
        let extents: Vec<ReclaimReceiptExtent> = (0u8..128)
            .map(|id| receipt_extent(u64::from(id) + 10, id))
            .collect();
        let extent_keys: Vec<ObjectKey> = extents.iter().map(|extent| extent.extent_key).collect();
        let receipt = ReclaimReceipt::new(extents.clone(), u64::MAX, u64::MAX);
        let encoded = receipt.encode();
        let decoded = ReclaimReceipt::decode(&encoded).unwrap();
        assert_eq!(decoded.freed_extents, extent_keys);
        assert_eq!(decoded.freed_segment_extents, extents);
        assert_eq!(decoded.deadlist_committed_txg, u64::MAX);
        assert_eq!(decoded.pin_clearance_epoch, u64::MAX);
    }

    #[test]
    fn reclaim_receipt_decode_rejects_truncated() {
        let receipt = ReclaimReceipt::new(vec![receipt_extent(1, 1)], 1, 1);
        let encoded = receipt.encode();
        let truncated = &encoded[..10];
        assert_eq!(
            ReclaimReceipt::decode(truncated),
            Err(ReclaimReceiptDecodeError::Truncated)
        );
    }

    #[test]
    fn reclaim_receipt_decode_rejects_invalid_magic() {
        let receipt = ReclaimReceipt::new(vec![receipt_extent(1, 1)], 1, 1);
        let mut encoded = receipt.encode();
        encoded[0] = b'X';
        assert_eq!(
            ReclaimReceipt::decode(&encoded),
            Err(ReclaimReceiptDecodeError::InvalidMagic)
        );
    }

    #[test]
    fn reclaim_receipt_decode_rejects_unsupported_version() {
        let receipt = ReclaimReceipt::new(vec![receipt_extent(1, 1)], 1, 1);
        let mut encoded = receipt.encode();
        encoded[4..8].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(
            ReclaimReceipt::decode(&encoded),
            Err(ReclaimReceiptDecodeError::UnsupportedVersion {
                found: 99,
                expected: ReclaimReceipt::VERSION,
            })
        );
    }

    #[test]
    fn reclaim_receipt_decode_rejects_checksum_mismatch() {
        let receipt = ReclaimReceipt::new(vec![receipt_extent(1, 1)], 1, 1);
        let mut encoded = receipt.encode();
        // Flip a byte in the extents area
        let flip_idx = encoded.len() - 33;
        encoded[flip_idx] ^= 0xFF;
        assert_eq!(
            ReclaimReceipt::decode(&encoded),
            Err(ReclaimReceiptDecodeError::ChecksumMismatch)
        );
    }

    #[test]
    fn reclaim_receipt_decode_rejects_trailing_bytes() {
        let receipt = ReclaimReceipt::new(vec![receipt_extent(1, 1)], 1, 1);
        let mut encoded = receipt.encode();
        encoded.extend_from_slice(b"extra");
        assert_eq!(
            ReclaimReceipt::decode(&encoded),
            Err(ReclaimReceiptDecodeError::TrailingBytes)
        );
    }

    #[test]
    fn reclaim_receipt_decode_error_display_non_empty() {
        let errors = [
            ReclaimReceiptDecodeError::Truncated,
            ReclaimReceiptDecodeError::InvalidMagic,
            ReclaimReceiptDecodeError::UnsupportedVersion {
                found: 2,
                expected: ReclaimReceipt::VERSION,
            },
            ReclaimReceiptDecodeError::TrailingBytes,
            ReclaimReceiptDecodeError::ChecksumMismatch,
        ];
        for err in &errors {
            let s = format!("{err}");
            assert!(!s.is_empty(), "Display empty for {err:?}");
        }
    }

    // -- ReclaimGate tests ----------------------------------------------------

    /// Mock resolver: maps key[0] directly as segment id.
    struct MockSegmentResolver;
    impl SegmentResolver for MockSegmentResolver {
        type Error = &'static str;
        fn resolve(&self, key: &ObjectKey) -> Result<Option<u64>, Self::Error> {
            Ok(Some(key.0[0] as u64))
        }
    }

    /// Mock freer: records freed segments.
    #[derive(Default)]
    struct MockSegmentFreer {
        freed: Vec<u64>,
        fail_on: Option<u64>,
    }
    impl SegmentFreer for MockSegmentFreer {
        type Error = &'static str;
        fn free_segment(&mut self, segment_id: u64) -> Result<(), Self::Error> {
            if self.fail_on == Some(segment_id) {
                return Err("mock free failure");
            }
            self.freed.push(segment_id);
            Ok(())
        }
    }

    #[test]
    fn gated_drain_allows_when_no_denials() {
        let mut live_counts = SegmentLiveCounts::new();
        live_counts.apply_delta(1, 2);
        live_counts.apply_delta(2, 1);

        // Two entries that make segments 1 and 2 dead
        let entries = vec![
            (
                receipt_extent_key(1),
                ReclaimQueueEntry::new(receipt_extent_key(1), -2, QueueFamily::Extent),
            ),
            (
                receipt_extent_key(2),
                ReclaimQueueEntry::new(receipt_extent_key(2), -1, QueueFamily::Extent),
            ),
        ];

        let resolver = MockSegmentResolver;
        let mut freer = MockSegmentFreer::default();
        let gate = AllowAllGate;
        let config = ReclaimConsumerConfig::default();

        let result = drain_reclaim_queue_gated(
            &entries,
            &resolver,
            &mut freer,
            &mut live_counts,
            &config,
            &gate,
        )
        .unwrap();

        assert_eq!(result.stats.segments_reclaimed, 2);
        assert_eq!(result.stats.gate_segments_skipped, 0);
        assert_eq!(result.stats.gate_extents_denied, 0);
        assert!(result.receipt.is_some());
        let receipt = result.receipt.unwrap();
        assert_eq!(receipt.freed_extents.len(), 2);
        assert_eq!(
            receipt.freed_segment_extents,
            vec![
                ReclaimReceiptExtent::new(1, receipt_extent_key(1)),
                ReclaimReceiptExtent::new(2, receipt_extent_key(2)),
            ]
        );
        assert_eq!(receipt.deadlist_committed_txg, 100);
        assert_eq!(receipt.pin_clearance_epoch, 10);
    }

    #[test]
    fn gated_drain_skips_deadlist_referenced_extent() {
        let mut live_counts = SegmentLiveCounts::new();
        live_counts.apply_delta(1, 2); // seg 1 needs -2 to be dead

        let entries = vec![(
            receipt_extent_key(1),
            ReclaimQueueEntry::new(receipt_extent_key(1), -2, QueueFamily::Extent),
        )];

        let resolver = MockSegmentResolver;
        let mut freer = MockSegmentFreer::default();
        let gate = DenySetGate {
            deny_keys: vec![1], // deny extent key 1 as deadlist-referenced
            reason: GateDenyReason::DeadlistReferenced,
        };
        let config = ReclaimConsumerConfig::default();

        let result = drain_reclaim_queue_gated(
            &entries,
            &resolver,
            &mut freer,
            &mut live_counts,
            &config,
            &gate,
        )
        .unwrap();

        assert_eq!(result.stats.segments_reclaimed, 0);
        assert_eq!(result.stats.gate_segments_skipped, 1);
        assert_eq!(result.stats.gate_extents_denied, 1);
        assert!(freer.freed.is_empty());
        assert!(result.receipt.is_none());
        assert_eq!(live_counts.live_count(1), 2);
    }

    #[test]
    fn gated_drain_skips_snapshot_pinned_extent() {
        let mut live_counts = SegmentLiveCounts::new();
        live_counts.apply_delta(2, 1); // seg 2 needs -1 to be dead

        let entries = vec![(
            receipt_extent_key(2),
            ReclaimQueueEntry::new(receipt_extent_key(2), -1, QueueFamily::Extent),
        )];

        let resolver = MockSegmentResolver;
        let mut freer = MockSegmentFreer::default();
        let gate = DenySetGate {
            deny_keys: vec![2], // deny extent key 2 as snapshot-pinned
            reason: GateDenyReason::SnapshotPinned,
        };
        let config = ReclaimConsumerConfig::default();

        let result = drain_reclaim_queue_gated(
            &entries,
            &resolver,
            &mut freer,
            &mut live_counts,
            &config,
            &gate,
        )
        .unwrap();

        assert_eq!(result.stats.segments_reclaimed, 0);
        assert_eq!(result.stats.gate_segments_skipped, 1);
        assert_eq!(result.stats.gate_extents_denied, 1);
        assert!(freer.freed.is_empty());
        assert_eq!(live_counts.live_count(2), 1);
    }

    #[test]
    fn gated_drain_frees_extent_after_pin_release() {
        let mut live_counts = SegmentLiveCounts::new();
        live_counts.apply_delta(3, 1);

        let entries = vec![(
            receipt_extent_key(3),
            ReclaimQueueEntry::new(receipt_extent_key(3), -1, QueueFamily::Extent),
        )];

        let resolver = MockSegmentResolver;
        let mut freer = MockSegmentFreer::default();
        let gate = AllowAllGate; // simulate pin released
        let config = ReclaimConsumerConfig::default();

        let result = drain_reclaim_queue_gated(
            &entries,
            &resolver,
            &mut freer,
            &mut live_counts,
            &config,
            &gate,
        )
        .unwrap();

        assert_eq!(result.stats.segments_reclaimed, 1);
        assert_eq!(result.stats.gate_segments_skipped, 0);
        assert_eq!(freer.freed, vec![3]);
    }

    #[test]
    fn gated_drain_receipt_is_empty_when_no_freed_extents() {
        let mut live_counts = SegmentLiveCounts::new();
        live_counts.apply_delta(5, 10); // seg 5 not dead with -1

        let entries = vec![(
            receipt_extent_key(5),
            ReclaimQueueEntry::new(receipt_extent_key(5), -1, QueueFamily::Extent),
        )];

        let resolver = MockSegmentResolver;
        let mut freer = MockSegmentFreer::default();
        let gate = AllowAllGate;
        let config = ReclaimConsumerConfig::default();

        let result = drain_reclaim_queue_gated(
            &entries,
            &resolver,
            &mut freer,
            &mut live_counts,
            &config,
            &gate,
        )
        .unwrap();

        assert_eq!(result.stats.segments_reclaimed, 0);
        assert!(result.receipt.is_none());
    }

    #[test]
    fn gated_drain_result_is_idle_when_no_work() {
        let result = GatedDrainResult {
            stats: ReclaimConsumerStats::ZERO,
            receipt: None,
        };
        assert!(result.is_idle());
    }

    #[test]
    fn gate_decision_is_allowed_and_denied() {
        let allow = GateDecision::Allow(ClearanceEvidence::Verified {
            deadlist_committed_txg: 1,
            pin_clearance_epoch: 2,
        });
        assert!(allow.is_allowed());
        assert!(!allow.is_denied());

        let deny = GateDecision::Deny(GateDenyReason::SnapshotPinned);
        assert!(!deny.is_allowed());
        assert!(deny.is_denied());
    }

    #[test]
    fn gate_deny_reason_display_non_empty() {
        assert!(!format!("{}", GateDenyReason::DeadlistReferenced).is_empty());
        assert!(!format!("{}", GateDenyReason::SnapshotPinned).is_empty());
    }

    #[test]
    fn clearance_evidence_deadlist_txg_and_pin_epoch() {
        let evidence = ClearanceEvidence::Verified {
            deadlist_committed_txg: 42,
            pin_clearance_epoch: 7,
        };
        assert_eq!(evidence.deadlist_txg(), Some(42));
        assert_eq!(evidence.pin_epoch(), Some(7));
    }
}

// =========================================================================
// ReclaimQueue binary wire format: CRC32C-protected framing for on-disk
// persistence. Wraps arbitrary payload bytes (e.g. serialised
// SegmentLivenessQueue) with a versioned header and CRC32C integrity
// footer so that corruption is detectable before deserialisation.
//
// Wire format (little-endian):
//   [0..4)     magic: b"RCLF"
//   [4..8)     version: u32 LE
//   [8..12)    payload length: u32 LE
//   [12..N+12) payload: variable bytes
//   [N+12..N+16) crc32c: u32 LE over bytes [0..N+12)
//
// Overhead: 16 bytes (12 header + 4 footer).
// =========================================================================

/// Magic bytes identifying a reclaim-queue wire-format frame.
const RECLAIM_WIRE_MAGIC: &[u8; 4] = b"RCLF";

/// Current wire-format version.
const RECLAIM_WIRE_VERSION: u32 = 1;

/// Header size in bytes: magic (4) + version (4) + payload length (4).
const RECLAIM_WIRE_HEADER_SIZE: usize = 12;

/// CRC32C footer size in bytes.
const RECLAIM_WIRE_FOOTER_SIZE: usize = 4;

/// Minimum valid frame size: header + footer (no payload).
const RECLAIM_WIRE_MIN_SIZE: usize = RECLAIM_WIRE_HEADER_SIZE + RECLAIM_WIRE_FOOTER_SIZE;

// ---------------------------------------------------------------------------
// ReclaimWireError
// ---------------------------------------------------------------------------

/// Errors returned when decoding a reclaim-queue wire-format frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReclaimWireError {
    /// Data is shorter than the minimum frame (header + CRC footer).
    Truncated,
    /// Magic bytes do not match the expected value.
    InvalidMagic,
    /// The wire-format version is not supported by this implementation.
    UnsupportedVersion { found: u32, expected: u32 },
    /// Claimed payload length overflows or exceeds available data.
    PayloadLengthOverflow,
    /// The CRC32C integrity check failed (data corruption).
    ChecksumMismatch,
}

impl fmt::Display for ReclaimWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated reclaim wire-format frame"),
            Self::InvalidMagic => f.write_str("invalid reclaim wire-format magic bytes"),
            Self::UnsupportedVersion { found, expected } => write!(
                f,
                "unsupported reclaim wire-format version: found {found}, expected {expected}"
            ),
            Self::PayloadLengthOverflow => {
                f.write_str("reclaim wire-format payload length overflow")
            }
            Self::ChecksumMismatch => f.write_str("reclaim wire-format CRC32C checksum mismatch"),
        }
    }
}

// ---------------------------------------------------------------------------
// ReclaimWireFrame
// ---------------------------------------------------------------------------

/// Result of decoding a reclaim-queue wire-format frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReclaimWireFrame {
    /// Wire-format version found during decode.
    pub version: u32,
    /// The verified payload bytes.
    pub payload: Vec<u8>,
}

// ---------------------------------------------------------------------------
// encode / decode
// ---------------------------------------------------------------------------

/// Encode a payload into a CRC32C-protected reclaim-queue wire-format frame.
///
/// Returns a byte vector suitable for writing to stable storage. The
/// frame includes a magic marker, version, payload length, the payload
/// itself, and a CRC32C integrity footer covering all preceding bytes.
#[must_use]
pub fn encode_reclaim_wire(payload: &[u8]) -> Vec<u8> {
    let payload_len = payload.len() as u32;
    let header_len = RECLAIM_WIRE_HEADER_SIZE + payload.len();
    let mut buf = Vec::with_capacity(header_len + RECLAIM_WIRE_FOOTER_SIZE);

    // Header: magic (4) + version (4) + payload_length (4)
    buf.extend_from_slice(RECLAIM_WIRE_MAGIC);
    buf.extend_from_slice(&RECLAIM_WIRE_VERSION.to_le_bytes());
    buf.extend_from_slice(&payload_len.to_le_bytes());

    // Payload
    buf.extend_from_slice(payload);

    // CRC32C footer over header + payload
    let crc = tidefs_binary_schema_checksum::crc32c(&buf);
    buf.extend_from_slice(&crc.to_le_bytes());

    buf
}

/// Decode a CRC32C-protected reclaim-queue wire-format frame.
///
/// Verifies magic, version, payload bounds, and CRC32C integrity before
/// returning the payload bytes. Returns [`ReclaimWireError`] on any
/// structural or integrity violation.
pub fn decode_reclaim_wire(data: &[u8]) -> Result<ReclaimWireFrame, ReclaimWireError> {
    if data.len() < RECLAIM_WIRE_MIN_SIZE {
        return Err(ReclaimWireError::Truncated);
    }

    // Magic check
    if &data[0..4] != RECLAIM_WIRE_MAGIC {
        return Err(ReclaimWireError::InvalidMagic);
    }

    // Version check
    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if version != RECLAIM_WIRE_VERSION {
        return Err(ReclaimWireError::UnsupportedVersion {
            found: version,
            expected: RECLAIM_WIRE_VERSION,
        });
    }

    // Payload length
    let payload_len = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
    let expected_frame_len = RECLAIM_WIRE_HEADER_SIZE
        .checked_add(payload_len)
        .ok_or(ReclaimWireError::PayloadLengthOverflow)?
        .checked_add(RECLAIM_WIRE_FOOTER_SIZE)
        .ok_or(ReclaimWireError::PayloadLengthOverflow)?;

    if data.len() < expected_frame_len {
        return Err(ReclaimWireError::PayloadLengthOverflow);
    }

    // CRC32C verification over header + payload
    let covered = &data[..RECLAIM_WIRE_HEADER_SIZE + payload_len];
    let footer_start = RECLAIM_WIRE_HEADER_SIZE + payload_len;
    let expected_crc_bytes: &[u8; 4] = data[footer_start..footer_start + 4].try_into().unwrap();
    let expected_crc = u32::from_le_bytes(*expected_crc_bytes);
    let actual_crc = tidefs_binary_schema_checksum::crc32c(covered);
    if actual_crc != expected_crc {
        return Err(ReclaimWireError::ChecksumMismatch);
    }

    Ok(ReclaimWireFrame {
        version,
        payload: covered[RECLAIM_WIRE_HEADER_SIZE..].to_vec(),
    })
}

/// Return the on-disk byte size for a wire-format frame with the given
/// payload length.
#[must_use]
pub const fn reclaim_wire_encoded_len(payload_len: usize) -> usize {
    RECLAIM_WIRE_HEADER_SIZE + payload_len + RECLAIM_WIRE_FOOTER_SIZE
}

#[cfg(test)]
mod reclaim_wire_tests {
    use super::*;

    // -- encode / decode round-trip --

    #[test]
    fn roundtrip_empty_payload() {
        let frame = encode_reclaim_wire(b"");
        assert_eq!(frame.len(), RECLAIM_WIRE_MIN_SIZE);
        let decoded = decode_reclaim_wire(&frame).unwrap();
        assert_eq!(decoded.version, RECLAIM_WIRE_VERSION);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn roundtrip_small_payload() {
        let payload = b"hello reclaim wire format";
        let frame = encode_reclaim_wire(payload);
        let decoded = decode_reclaim_wire(&frame).unwrap();
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn roundtrip_large_payload() {
        let payload = vec![0xABu8; 65536];
        let frame = encode_reclaim_wire(&payload);
        let decoded = decode_reclaim_wire(&frame).unwrap();
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.version, RECLAIM_WIRE_VERSION);
    }

    #[test]
    fn roundtrip_preserves_version() {
        let frame = encode_reclaim_wire(b"data");
        let decoded = decode_reclaim_wire(&frame).unwrap();
        assert_eq!(decoded.version, RECLAIM_WIRE_VERSION);
    }

    #[test]
    fn encoded_len_formula() {
        let payload = vec![0u8; 42];
        let frame = encode_reclaim_wire(&payload);
        assert_eq!(frame.len(), reclaim_wire_encoded_len(payload.len()));
        assert_eq!(
            frame.len(),
            RECLAIM_WIRE_HEADER_SIZE + 42 + RECLAIM_WIRE_FOOTER_SIZE
        );
    }

    #[test]
    fn encode_is_deterministic() {
        let payload = b"deterministic test";
        let f1 = encode_reclaim_wire(payload);
        let f2 = encode_reclaim_wire(payload);
        assert_eq!(f1, f2);
        let decoded = decode_reclaim_wire(&f1).unwrap();
        assert_eq!(decoded.payload, payload);
    }

    // -- Decode error: truncated --

    #[test]
    fn decode_rejects_empty() {
        assert_eq!(decode_reclaim_wire(&[]), Err(ReclaimWireError::Truncated));
    }

    #[test]
    fn decode_rejects_too_short() {
        assert_eq!(
            decode_reclaim_wire(&[0u8; 15]),
            Err(ReclaimWireError::Truncated)
        );
    }

    #[test]
    fn decode_rejects_header_only() {
        let mut data = vec![0u8; 12];
        data[0..4].copy_from_slice(b"RCLF");
        data[4..8].copy_from_slice(&RECLAIM_WIRE_VERSION.to_le_bytes());
        data[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(decode_reclaim_wire(&data), Err(ReclaimWireError::Truncated));
    }

    // -- Decode error: invalid magic --

    #[test]
    fn decode_rejects_bad_magic() {
        let mut data = vec![0u8; RECLAIM_WIRE_MIN_SIZE];
        data[0..4].copy_from_slice(b"XXXX");
        data[4..8].copy_from_slice(&RECLAIM_WIRE_VERSION.to_le_bytes());
        data[8..12].copy_from_slice(&0u32.to_le_bytes());
        let crc = tidefs_binary_schema_checksum::crc32c(&data[..12]);
        data[12..16].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            decode_reclaim_wire(&data),
            Err(ReclaimWireError::InvalidMagic)
        );
    }

    // -- Decode error: unsupported version --

    #[test]
    fn decode_rejects_future_version() {
        let mut data = vec![0u8; RECLAIM_WIRE_MIN_SIZE];
        data[0..4].copy_from_slice(b"RCLF");
        data[4..8].copy_from_slice(&99u32.to_le_bytes());
        data[8..12].copy_from_slice(&0u32.to_le_bytes());
        let crc = tidefs_binary_schema_checksum::crc32c(&data[..12]);
        data[12..16].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            decode_reclaim_wire(&data),
            Err(ReclaimWireError::UnsupportedVersion {
                found: 99,
                expected: RECLAIM_WIRE_VERSION,
            })
        );
    }

    // -- Decode error: payload length overflow --

    #[test]
    fn decode_rejects_payload_overflow() {
        let mut data = vec![0u8; RECLAIM_WIRE_MIN_SIZE];
        data[0..4].copy_from_slice(b"RCLF");
        data[4..8].copy_from_slice(&RECLAIM_WIRE_VERSION.to_le_bytes());
        data[8..12].copy_from_slice(&(u32::MAX).to_le_bytes());
        let crc = tidefs_binary_schema_checksum::crc32c(&data[..12]);
        data[12..16].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            decode_reclaim_wire(&data),
            Err(ReclaimWireError::PayloadLengthOverflow)
        );
    }

    // -- Decode error: checksum mismatch (corruption) --

    #[test]
    fn decode_detects_corrupted_magic() {
        let mut frame = encode_reclaim_wire(b"corrupt me");
        frame[0] ^= 0xFF;
        let result = decode_reclaim_wire(&frame);
        assert!(result.is_err());
    }

    #[test]
    fn decode_detects_corrupted_payload() {
        let mut frame = encode_reclaim_wire(b"important data");
        frame[14] ^= 0x01;
        assert_eq!(
            decode_reclaim_wire(&frame),
            Err(ReclaimWireError::ChecksumMismatch)
        );
    }

    #[test]
    fn decode_detects_corrupted_crc_footer() {
        let mut frame = encode_reclaim_wire(b"data with footer");
        let last = frame.len() - 1;
        frame[last] ^= 0xFF;
        assert_eq!(
            decode_reclaim_wire(&frame),
            Err(ReclaimWireError::ChecksumMismatch)
        );
    }

    #[test]
    fn decode_detects_single_bit_flip() {
        let frame = encode_reclaim_wire(b"single bit error test");
        for bit_pos in 0..frame.len() {
            let mut corrupted = frame.clone();
            corrupted[bit_pos] ^= 0x01;
            let result = decode_reclaim_wire(&corrupted);
            assert!(
                result.is_err(),
                "single bit flip at offset {bit_pos} should be detected"
            );
        }
    }

    #[test]
    fn decode_detects_truncated_payload() {
        let frame = encode_reclaim_wire(b"payload gets truncated");
        let truncated = &frame[..frame.len() - 3];
        assert!(decode_reclaim_wire(truncated).is_err());
    }

    // -- WireError Display --

    #[test]
    fn wire_error_display_non_empty() {
        let errors = [
            ReclaimWireError::Truncated,
            ReclaimWireError::InvalidMagic,
            ReclaimWireError::UnsupportedVersion {
                found: 2,
                expected: 1,
            },
            ReclaimWireError::PayloadLengthOverflow,
            ReclaimWireError::ChecksumMismatch,
        ];
        for err in &errors {
            let s = format!("{err}");
            assert!(!s.is_empty(), "Display empty for {err:?}");
        }
    }

    // -- Encode / decode with realistic reclaim payload --

    #[test]
    fn roundtrip_realistic_segment_liveness_payload() {
        // Simulate a SegmentLivenessQueue payload: 128 segments * 24 bytes
        let mut payload = Vec::with_capacity(128 * 24);
        for seg in 0..128u64 {
            payload.extend_from_slice(&seg.to_le_bytes());
            payload.extend_from_slice(&(seg * 1000).to_le_bytes());
            payload.extend_from_slice(&(seg * 300).to_le_bytes());
        }
        let frame = encode_reclaim_wire(&payload);
        let decoded = decode_reclaim_wire(&frame).unwrap();
        assert_eq!(decoded.payload, payload);
        assert_eq!(frame.len(), reclaim_wire_encoded_len(payload.len()));
    }

    #[test]
    fn decode_tolerates_extra_trailing_bytes() {
        let mut frame = encode_reclaim_wire(b"data");
        frame.push(0xFF);
        // Extra trailing bytes after the CRC footer are ignored by design:
        // the CRC covers header + payload; padding is benign.
        let decoded = decode_reclaim_wire(&frame).unwrap();
        assert_eq!(decoded.payload, b"data");
    }
}
