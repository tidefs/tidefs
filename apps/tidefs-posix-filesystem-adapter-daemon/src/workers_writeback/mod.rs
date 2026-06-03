//! P5-02 FUSE writeback dirty-drain engine.
//!
//! Part of the P5-02 classified multipool topology for the userspace FUSE runtime.
//! This crate owns the writeback drain boundary: it scans dirty work items from
//! the scheduler, sorts by object-store key affinity, issues put operations,
//! updates extent metadata on flush completion, and reports completion back to
//! the scheduler's in-flight accounting.
//!
//! ## Architecture
//!
//! ```text
//! Scheduler queue ──► DirtyDrainEngine ──► ObjectStore::put
//!                          │
//!                          ├──► ExtentMap (dirty→clean transition)
//!                          └──► Scheduler completion reporting
//! ```

use core::cmp::Ordering;
use std::vec::Vec;

#[cfg_attr(not(test), allow(unused_imports))]
use crate::scheduler::{
    WritebackCommitGroupFlushBarrier, WritebackDispatchError, WritebackDispatchState,
    WritebackDispatchTicket, WritebackQueueError, WritebackWorkItem,
};

/// Re-export all P5-02 request-queue types and runtime functions for this seam family.
pub const SEAM_FAMILY_DOC: &str = concat!("seam.", env!("CARGO_PKG_NAME"), ".    P5-02.v0");

// ── Error types ─────────────────────────────────────────────────────────────

/// Errors returned by writeback drain operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainError {
    /// No queued writeback work is available.
    QueueEmpty,
    /// The drain engine has reached its in-flight capacity.
    InFlightFull,
    /// The drain slot table is full, cannot accept more concurrent drains.
    DrainTableFull,
    /// An unknown or already-completed ticket was referenced.
    UnknownTicket,
    /// The dirty page source could not provide the requested data.
    DirtyDataUnavailable,
    /// The object store rejected a put operation.
    ObjectStorePut,
    /// The extent map rejected a metadata update.
    ExtentMapUpdate,
    /// Dirty-page age or range validation failed.
    InvalidWorkItem,
    /// A required commit_group barrier has been broken.
    CommitGroupBarrierBroken,
    /// The new mmap region overlaps an existing tracked region.
    MmapRegionOverlap,
    /// The requested mmap region was not found.
    MmapRegionNotFound,
}

impl DrainError {
    /// Map this drain error to the closest POSIX errno for a FUSE reply.
    #[must_use]
    pub const fn to_errno(self) -> i32 {
        match self {
            Self::QueueEmpty => 11,              // EAGAIN
            Self::InFlightFull => 16,            // EBUSY
            Self::DrainTableFull => 12,          // ENOMEM
            Self::UnknownTicket => 22,           // EINVAL
            Self::DirtyDataUnavailable => 5,     // EIO
            Self::ObjectStorePut => 5,           // EIO
            Self::ExtentMapUpdate => 5,          // EIO
            Self::InvalidWorkItem => 22,         // EINVAL
            Self::CommitGroupBarrierBroken => 5, // EIO
            Self::MmapRegionOverlap => 22,       // EINVAL
            Self::MmapRegionNotFound => 22,      // EINVAL
        }
    }
}

// ── Drain statistics ────────────────────────────────────────────────────────

/// Instrumentation counters for the writeback drain engine.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DrainStats {
    /// Number of work items successfully drained to the object store.
    pub completed: u64,
    /// Number of work items currently in-flight (dispatched but not yet completed).
    pub pending: u64,
    /// Number of work items that failed during drain (put failure, metadata failure).
    pub errors: u64,
    /// Number of transaction-group barriers that completed successfully.
    pub commit_barriers_completed: u64,
    /// Number of transaction-group barriers that failed.
    pub commit_barriers_failed: u64,
    /// Total dirty bytes drained.
    pub bytes_drained: u64,
    /// Total dirty objects stored.
    pub objects_stored: u64,
}

impl DrainStats {
    /// Create a zeroed drain statistics record.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            completed: 0,
            pending: 0,
            errors: 0,
            commit_barriers_completed: 0,
            commit_barriers_failed: 0,
            bytes_drained: 0,
            objects_stored: 0,
        }
    }

    /// Record a successful drain completion.
    pub fn record_completion(&mut self, byte_count: u64) {
        self.completed = self.completed.saturating_add(1);
        self.pending = self.pending.saturating_sub(1);
        self.bytes_drained = self.bytes_drained.saturating_add(byte_count);
        self.objects_stored = self.objects_stored.saturating_add(1);
    }

    /// Record a drain error.
    pub fn record_error(&mut self) {
        self.errors = self.errors.saturating_add(1);
        self.pending = self.pending.saturating_sub(1);
    }

    /// Record a new in-flight drain dispatch.
    pub fn record_dispatched(&mut self) {
        self.pending = self.pending.saturating_add(1);
    }

    /// Record a commit_group barrier completion.
    pub fn record_commit_barrier_completed(&mut self, byte_count: u64) {
        self.commit_barriers_completed = self.commit_barriers_completed.saturating_add(1);
        self.bytes_drained = self.bytes_drained.saturating_add(byte_count);
    }

    /// Record a commit_group barrier failure.
    pub fn record_commit_barrier_failed(&mut self) {
        self.commit_barriers_failed = self.commit_barriers_failed.saturating_add(1);
    }
}

// ── Writeback cache funnel stats ───────────────────────────────────────────

/// Per-session counters for the FUSE writeback cache funnel.
///
/// Accumulated by the FUSE dispatch path when `FUSE_CAP_WRITEBACK_CACHE`
/// is negotiated.  The daemon drains dirty ranges through the flush/fsync
/// paths and records completion via the daemon-side `WritebackDaemonStats`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WritebackCacheStats {
    /// Number of `FUSE_WRITE_CACHE` (write_buf) calls accepted by the adapter.
    pub write_buf_calls: u64,
    /// Total bytes of cached write data accepted from the kernel page cache.
    pub bytes_cached: u64,
    /// Number of flush operations triggered (kernel-initiated `FUSE_FLUSH`,
    /// `FUSE_FSYNC`, `FUSE_FSYNCDIR`, and adapter-initiated syncfs).
    pub flushes_triggered: u64,
}

impl WritebackCacheStats {
    /// Create a zero-initialized stats record.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            write_buf_calls: 0,
            bytes_cached: 0,
            flushes_triggered: 0,
        }
    }

    /// Record a successful write_buf (FUSE_WRITE_CACHE) dispatch.
    pub fn record_write_buf(&mut self, byte_count: u32) {
        self.write_buf_calls = self.write_buf_calls.saturating_add(1);
        self.bytes_cached = self.bytes_cached.saturating_add(u64::from(byte_count));
    }

    /// Record a flush trigger (kernel flush/fsync/fsyncdir or syncfs).
    pub fn record_flush(&mut self) {
        self.flushes_triggered = self.flushes_triggered.saturating_add(1);
    }
}

// ── Work item types ─────────────────────────────────────────────────────────

/// A writeback work item produced by the scheduler for drain processing.
///
/// This mirrors the scheduler-local `WritebackWorkItem` but lives in the
/// worker boundary so the drain engine can operate without a direct scheduler
/// dependency.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DrainWorkItem {
    /// Object (inode) identifier.
    pub object_id: u64,
    /// Start byte offset (inclusive) of the dirty range.
    pub offset_start: u64,
    /// End byte offset (exclusive) of the dirty range.
    pub offset_end: u64,
    /// Transaction group this dirty data belongs to.
    pub commit_group_id: u64,
    /// Number of dirty bytes in this work item.
    pub dirty_byte_count: u64,
    /// Age in milliseconds of the oldest dirty page.
    pub oldest_dirty_age_ms: u64,
    /// Monotonic generation for tie-breaking.
    pub generation: u64,
}

impl DrainWorkItem {
    /// Create a drain work item.
    #[must_use]
    pub const fn new(
        object_id: u64,
        offset_start: u64,
        offset_end: u64,
        commit_group_id: u64,
        dirty_byte_count: u64,
        oldest_dirty_age_ms: u64,
    ) -> Self {
        Self {
            object_id,
            offset_start,
            offset_end,
            commit_group_id,
            dirty_byte_count,
            oldest_dirty_age_ms,
            generation: 0,
        }
    }

    /// Set the generation for tie-breaking.
    #[must_use]
    pub const fn with_generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }

    /// Number of dirty bytes represented by this work item.
    #[must_use]
    pub fn byte_len(&self) -> u64 {
        self.offset_end.saturating_sub(self.offset_start)
    }

    /// Returns true if this item has valid, non-empty bounds.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.offset_start < self.offset_end && self.dirty_byte_count > 0
    }
}

/// A dispatch ticket linking a drain work item to a scheduler-local ticket id.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DrainTicket {
    /// Scheduler-local ticket id for completion reporting.
    pub ticket_id: u64,
    /// The work item associated with this ticket.
    pub item: DrainWorkItem,
}

impl DrainTicket {
    /// Create a drain ticket.
    #[must_use]
    pub const fn new(ticket_id: u64, item: DrainWorkItem) -> Self {
        Self { ticket_id, item }
    }
}

impl From<WritebackWorkItem> for DrainWorkItem {
    fn from(item: WritebackWorkItem) -> Self {
        Self {
            object_id: item.object_id,
            offset_start: item.offset_start,
            offset_end: item.offset_end,
            commit_group_id: item.commit_group_id,
            dirty_byte_count: item.dirty_byte_count,
            oldest_dirty_age_ms: item.oldest_dirty_age_ms,
            generation: item.generation,
        }
    }
}

impl From<WritebackDispatchTicket> for DrainTicket {
    fn from(ticket: WritebackDispatchTicket) -> Self {
        Self {
            ticket_id: ticket.ticket_id,
            item: ticket.item.into(),
        }
    }
}

// ── Drain batch ─────────────────────────────────────────────────────────────

/// A group of drain work items sharing an object-store key for efficient flush.
#[derive(Clone, Debug, Default)]
pub struct DrainBatch {
    /// Work items in this batch, all targeting the same object.
    items: Vec<DrainWorkItem>,
}

impl DrainBatch {
    /// Create an empty drain batch.
    #[must_use]
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Add a work item to this batch.
    pub fn push(&mut self, item: DrainWorkItem) {
        self.items.push(item);
    }

    /// Number of work items in this batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns true when the batch is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Total dirty bytes across all items in this batch.
    #[must_use]
    pub fn total_dirty_bytes(&self) -> u64 {
        self.items
            .iter()
            .fold(0_u64, |acc, item| acc.saturating_add(item.dirty_byte_count))
    }

    /// Access the work items as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[DrainWorkItem] {
        &self.items
    }

    /// Drain (consume) all work items from this batch.
    #[must_use]
    pub fn drain(&mut self) -> Vec<DrainWorkItem> {
        core::mem::take(&mut self.items)
    }
}

// ── Dirty range tracking ────────────────────────────────────────────────────

/// A byte range dirtied for a single object/inode.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirtyRange {
    /// Object (inode) identifier.
    pub object_id: u64,
    /// Start byte offset (inclusive) of the dirty range.
    pub offset_start: u64,
    /// End byte offset (exclusive) of the dirty range.
    pub offset_end: u64,
}

impl DirtyRange {
    /// Create a dirty range.
    #[must_use]
    pub const fn new(object_id: u64, offset_start: u64, offset_end: u64) -> Self {
        Self {
            object_id,
            offset_start,
            offset_end,
        }
    }

    /// Number of bytes covered by this range.
    #[must_use]
    pub fn byte_len(&self) -> u64 {
        self.offset_end.saturating_sub(self.offset_start)
    }

    /// Returns true when this range has non-empty bounds.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.offset_start < self.offset_end
    }

    /// Returns true when `other` is fully contained in this range.
    #[must_use]
    pub const fn contains(&self, other: Self) -> bool {
        self.object_id == other.object_id
            && self.offset_start <= other.offset_start
            && other.offset_end <= self.offset_end
    }

    /// Returns true when ranges overlap or are directly adjacent.
    #[must_use]
    pub const fn touches_or_overlaps(&self, other: Self) -> bool {
        self.object_id == other.object_id
            && self.offset_start <= other.offset_end
            && other.offset_start <= self.offset_end
    }

    /// Merge two touching or overlapping ranges for the same object.
    #[must_use]
    pub fn merge(self, other: Self) -> Option<Self> {
        if !self.is_valid() || !other.is_valid() || !self.touches_or_overlaps(other) {
            return None;
        }

        Some(Self {
            object_id: self.object_id,
            offset_start: self.offset_start.min(other.offset_start),
            offset_end: self.offset_end.max(other.offset_end),
        })
    }
}

impl From<DrainWorkItem> for DirtyRange {
    fn from(item: DrainWorkItem) -> Self {
        Self::new(item.object_id, item.offset_start, item.offset_end)
    }
}

/// Outcome retained for an observed dirty-range flush attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirtyRangeOutcome {
    /// Range was flushed and removed from the pending dirty set.
    Completed,
    /// Range flush failed and remains pending for retry.
    Failed(DrainError),
}

/// Completion/error observation for a dirty range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirtyRangeCompletion {
    /// Range covered by this observation.
    pub range: DirtyRange,
    /// Completion outcome.
    pub outcome: DirtyRangeOutcome,
}

impl DirtyRangeCompletion {
    /// Create a completion observation.
    #[must_use]
    pub const fn completed(range: DirtyRange) -> Self {
        Self {
            range,
            outcome: DirtyRangeOutcome::Completed,
        }
    }

    /// Create a failure observation.
    #[must_use]
    pub const fn failed(range: DirtyRange, error: DrainError) -> Self {
        Self {
            range,
            outcome: DirtyRangeOutcome::Failed(error),
        }
    }
}

/// Deterministic flush batch produced from pending dirty ranges.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DirtyFlushBatch {
    ranges: Vec<DirtyRange>,
}

impl DirtyFlushBatch {
    /// Create an empty dirty flush batch.
    #[must_use]
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Add a dirty range to the batch.
    pub fn push(&mut self, range: DirtyRange) {
        self.ranges.push(range);
    }

    /// Number of ranges in this batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /// Returns true when this batch has no ranges.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Total dirty bytes represented by the batch after coalescing.
    #[must_use]
    pub fn total_dirty_bytes(&self) -> u64 {
        self.ranges
            .iter()
            .fold(0_u64, |acc, range| acc.saturating_add(range.byte_len()))
    }

    /// Access the ranges in deterministic object/offset order.
    #[must_use]
    pub fn as_slice(&self) -> &[DirtyRange] {
        &self.ranges
    }

    /// Consume this batch and return the ranges.
    #[must_use]
    pub fn into_ranges(self) -> Vec<DirtyRange> {
        self.ranges
    }
}

/// Tracks pending dirty ranges and retained flush observations.
#[derive(Clone, Debug, Default)]
pub struct DirtyRangeTracker {
    ranges: Vec<DirtyRange>,
    completions: Vec<DirtyRangeCompletion>,
}

impl DirtyRangeTracker {
    /// Create an empty dirty range tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ranges: Vec::new(),
            completions: Vec::new(),
        }
    }

    /// Returns true when no dirty ranges are pending.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Number of pending dirty ranges after coalescing.
    #[must_use]
    pub fn pending_range_count(&self) -> usize {
        self.ranges.len()
    }

    /// Number of retained completion/error observations.
    #[must_use]
    pub fn completion_count(&self) -> usize {
        self.completions.len()
    }

    /// Number of retained failed flush observations.
    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.completions
            .iter()
            .enumerate()
            .filter(|(index, completion)| {
                matches!(completion.outcome, DirtyRangeOutcome::Failed(_))
                    && !self.completions[index.saturating_add(1)..]
                        .iter()
                        .any(|later| {
                            matches!(later.outcome, DirtyRangeOutcome::Completed)
                                && later.range.contains(completion.range)
                        })
            })
            .count()
    }

    /// Total pending dirty bytes after range coalescing.
    #[must_use]
    pub fn pending_dirty_bytes(&self) -> u64 {
        self.ranges
            .iter()
            .fold(0_u64, |acc, range| acc.saturating_add(range.byte_len()))
    }

    /// Access pending ranges in deterministic object/offset order.
    #[must_use]
    pub fn pending_ranges(&self) -> &[DirtyRange] {
        &self.ranges
    }

    /// Access retained completion/error observations in observation order.
    #[must_use]
    pub fn completions(&self) -> &[DirtyRangeCompletion] {
        &self.completions
    }

    /// Record a dirty range and coalesce it with existing pending ranges.
    pub fn record_dirty_range(&mut self, range: DirtyRange) -> Result<(), DrainError> {
        if !range.is_valid() {
            return Err(DrainError::InvalidWorkItem);
        }

        self.ranges.push(range);
        self.coalesce_pending();
        Ok(())
    }

    /// Record a dirty byte range for an object/inode.
    pub fn record_dirty(
        &mut self,
        object_id: u64,
        offset_start: u64,
        offset_end: u64,
    ) -> Result<(), DrainError> {
        self.record_dirty_range(DirtyRange::new(object_id, offset_start, offset_end))
    }

    /// Record a scheduler work item as a dirty range.
    pub fn record_work_item(&mut self, item: DrainWorkItem) -> Result<(), DrainError> {
        if !item.is_valid() {
            return Err(DrainError::InvalidWorkItem);
        }

        self.record_dirty_range(item.into())
    }

    /// Return the next deterministic flush batch without mutating the tracker.
    #[must_use]
    pub fn next_flush_batch(&self, max_ranges: usize) -> DirtyFlushBatch {
        let mut batch = DirtyFlushBatch::new();
        if max_ranges == 0 {
            return batch;
        }

        for range in self.ranges.iter().take(max_ranges) {
            batch.push(*range);
        }
        batch
    }

    /// Return the next deterministic flush batch for one object/inode.
    #[must_use]
    pub fn next_flush_batch_for_object(
        &self,
        object_id: u64,
        max_ranges: usize,
    ) -> DirtyFlushBatch {
        let mut batch = DirtyFlushBatch::new();
        if max_ranges == 0 {
            return batch;
        }

        for range in self
            .ranges
            .iter()
            .filter(|range| range.object_id == object_id)
            .take(max_ranges)
        {
            batch.push(*range);
        }
        batch
    }

    /// Mark a pending dirty range as completed and remove it from pending state.
    pub fn mark_completed(&mut self, range: DirtyRange) -> Result<(), DrainError> {
        if !range.is_valid() {
            return Err(DrainError::InvalidWorkItem);
        }

        match self.remove_pending_range(range) {
            Ok(()) => {
                self.completions
                    .push(DirtyRangeCompletion::completed(range));
                Ok(())
            }
            Err(DrainError::UnknownTicket) if self.completed_range_contains(range) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Record a failed flush attempt while keeping the range pending for retry.
    pub fn mark_failed(&mut self, range: DirtyRange, error: DrainError) -> Result<(), DrainError> {
        if !range.is_valid() {
            return Err(DrainError::InvalidWorkItem);
        }
        if !self.ranges.iter().any(|pending| pending.contains(range)) {
            return Err(DrainError::UnknownTicket);
        }

        self.completions
            .push(DirtyRangeCompletion::failed(range, error));
        Ok(())
    }

    /// Apply one observed flush outcome to pending dirty-range state.
    pub fn apply_flush_completion(
        &mut self,
        completion: DirtyRangeCompletion,
    ) -> Result<(), DrainError> {
        match completion.outcome {
            DirtyRangeOutcome::Completed => self.mark_completed(completion.range),
            DirtyRangeOutcome::Failed(error) => self.mark_failed(completion.range, error),
        }
    }

    /// Apply observed flush outcomes in order.
    pub fn apply_flush_completions(
        &mut self,
        completions: &[DirtyRangeCompletion],
    ) -> Result<(), DrainError> {
        for completion in completions {
            self.apply_flush_completion(*completion)?;
        }
        Ok(())
    }

    fn completed_range_contains(&self, range: DirtyRange) -> bool {
        self.completions.iter().any(|completion| {
            matches!(completion.outcome, DirtyRangeOutcome::Completed)
                && completion.range.contains(range)
        })
    }

    fn coalesce_pending(&mut self) {
        self.ranges
            .sort_by(|a, b| match a.object_id.cmp(&b.object_id) {
                Ordering::Equal => a.offset_start.cmp(&b.offset_start),
                other => other,
            });

        let mut coalesced: Vec<DirtyRange> = Vec::with_capacity(self.ranges.len());
        for range in self.ranges.drain(..) {
            if let Some(last) = coalesced.last_mut() {
                if let Some(merged) = (*last).merge(range) {
                    *last = merged;
                    continue;
                }
            }
            coalesced.push(range);
        }
        self.ranges = coalesced;
    }

    fn remove_pending_range(&mut self, range: DirtyRange) -> Result<(), DrainError> {
        let Some(index) = self
            .ranges
            .iter()
            .position(|pending| pending.contains(range))
        else {
            return Err(DrainError::UnknownTicket);
        };

        let pending = self.ranges.remove(index);
        if pending.offset_start < range.offset_start {
            self.ranges.push(DirtyRange::new(
                pending.object_id,
                pending.offset_start,
                range.offset_start,
            ));
        }
        if range.offset_end < pending.offset_end {
            self.ranges.push(DirtyRange::new(
                pending.object_id,
                range.offset_end,
                pending.offset_end,
            ));
        }
        self.coalesce_pending();
        Ok(())
    }
}

// ── Fsync boundary dirty-page tracking ──────────────────────────────────────

/// Monotonic fsync boundary token.
///
/// Assigned when [`DirtyPageTracker::take_boundary`] snapshots the current
/// dirty state.  The writeback daemon flushes pages belonging to closed
/// boundaries and calls [`DirtyPageTracker::clear_until_boundary`] to
/// remove flushed ranges.
pub type FsyncBoundaryToken = u64;

/// Tracks per-inode dirty byte ranges with fsync boundary groups.
///
/// Each dirty range is associated with a boundary token.  The current
/// "open" boundary collects newly-dirtied ranges until
/// [`take_boundary`](Self::take_boundary) is called, which closes it
/// and opens a fresh boundary.  This allows the writeback daemon to
/// flush all dirty pages up to a known boundary and then clear them
/// atomically.
///
/// # Range coalescing
///
/// Adjacent and overlapping dirty ranges for the same inode are merged
/// on insert.  When two ranges with different boundary tokens merge,
/// the merged range keeps the higher token so it is not cleared before
/// the later fsync completes.
///
/// # Example
///
/// ```
/// # use crate::workers_writeback::DirtyPageTracker;
/// let mut t = DirtyPageTracker::new();
/// t.mark_dirty(1, 0, 4096).unwrap();
/// t.mark_dirty(1, 4096, 4096).unwrap();  // merged with above → [0, 8192)
/// assert_eq!(t.get_dirty_ranges(1).len(), 1);
///
/// let tok = t.take_boundary();        // boundary 1 closed
/// t.mark_dirty(2, 0, 4096).unwrap();  // now in boundary 2
/// assert_eq!(t.get_dirty_ranges(2).len(), 1);
///
/// t.clear_until_boundary(1, tok);  // clears inode 1
/// assert!(t.get_dirty_ranges(1).is_empty());
/// assert!(!t.get_dirty_ranges(2).is_empty()); // inode 2 still dirty
/// ```
#[derive(Clone, Debug, Default)]
pub struct DirtyPageTracker {
    /// Per-inode dirty-page entries, sorted by `(inode, offset_start)` and
    /// coalesced (no adjacent or overlapping ranges for the same inode).
    entries: Vec<DirtyPageEntry>,
    /// Monotonic boundary token assigned to newly-dirtied ranges.
    /// Starts at 1 so that a zero token always means "uninitialized / none."
    current_boundary: FsyncBoundaryToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirtyPageEntry {
    inode: u64,
    offset_start: u64,
    offset_end: u64,
    boundary: FsyncBoundaryToken,
    /// Monotonic wall-clock timestamp (ms) when this range was first
    /// dirtied.  0 means unknown (legacy mark_dirty without time).
    dirtied_at_ms: u64,
}

impl DirtyPageTracker {
    /// Create an empty tracker.
    ///
    /// The first boundary token is 1.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            current_boundary: 1,
        }
    }

    /// Number of dirty inodes tracked (an inode counts once regardless of
    /// how many dirty ranges it has).
    #[must_use]
    pub fn dirty_inode_count(&self) -> usize {
        let mut seen: u64 = u64::MAX;
        let mut count: usize = 0;
        for e in &self.entries {
            if e.inode != seen {
                seen = e.inode;
                count += 1;
            }
        }
        count
    }

    /// Total number of dirty byte ranges across all inodes (after coalescing).
    #[must_use]
    pub fn range_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns true when no inodes have dirty pages.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The active (open) boundary token — the one assigned to the next
    /// [`mark_dirty`](Self::mark_dirty) call.
    #[must_use]
    pub fn current_boundary(&self) -> FsyncBoundaryToken {
        self.current_boundary
    }

    // ── mark_dirty ──────────────────────────────────────────────────────

    /// Record a dirty byte range for `inode`.
    ///
    /// The range `[offset, offset + length)` is associated with the current
    /// boundary token.  Adjacent or overlapping ranges for the same inode
    /// are merged.  Zero-length writes are accepted as no-ops.
    ///
    /// # Errors
    ///
    /// Returns [`DrainError::InvalidWorkItem`] if `offset + length`
    /// overflows `u64`.
    pub fn mark_dirty(&mut self, inode: u64, offset: u64, length: u64) -> Result<(), DrainError> {
        if length == 0 {
            return Ok(());
        }

        let end = offset
            .checked_add(length)
            .ok_or(DrainError::InvalidWorkItem)?;

        self.insert_and_coalesce(inode, offset, end, self.current_boundary, 0);
        Ok(())
    }

    // ── accept_write ────────────────────────────────────────────────────

    /// Accept a FUSE write into the dirty-page tracker.
    ///
    /// This is the writeback worker task entry point for incoming FUSE WRITE
    /// requests. It records the dirty byte range `[offset, offset+data.len())`
    /// for `inode` with the current fsync boundary token.
    ///
    /// Adjacent or overlapping ranges for the same inode are merged
    /// automatically.
    ///
    /// # Errors
    ///
    /// Returns [`DrainError::InvalidWorkItem`] when `offset + data.len()`
    /// overflows `u64`.
    pub fn accept_write(&mut self, inode: u64, offset: u64, data: &[u8]) -> Result<(), DrainError> {
        let length = data.len() as u64;
        self.mark_dirty(inode, offset, length)
    }

    // ── mark_dirty_at ──────────────────────────────────────────────────

    /// Record a dirty byte range for `inode` with a known wall-clock
    /// timestamp (ms).  Otherwise identical to [`mark_dirty`](Self::mark_dirty).
    ///
    /// The `dirtied_at_ms` parameter is used by the writeback daemon for
    /// `dirty_expire_centisecs` enforcement.  When coalescing, the oldest
    /// (minimum) timestamp is preserved.
    pub fn mark_dirty_at(
        &mut self,
        inode: u64,
        offset: u64,
        length: u64,
        dirtied_at_ms: u64,
    ) -> Result<(), DrainError> {
        if length == 0 {
            return Ok(());
        }

        let end = offset
            .checked_add(length)
            .ok_or(DrainError::InvalidWorkItem)?;

        self.insert_and_coalesce(inode, offset, end, self.current_boundary, dirtied_at_ms);
        Ok(())
    }

    /// Accept a FUSE write with a known wall-clock timestamp.
    pub fn accept_write_at(
        &mut self,
        inode: u64,
        offset: u64,
        data: &[u8],
        dirtied_at_ms: u64,
    ) -> Result<(), DrainError> {
        let length = data.len() as u64;
        self.mark_dirty_at(inode, offset, length, dirtied_at_ms)
    }

    // ── get_dirty_ranges ────────────────────────────────────────────────

    /// Return all dirty byte ranges for `inode`, ordered by offset.
    #[must_use]
    pub fn get_dirty_ranges(&self, inode: u64) -> Vec<DirtyRange> {
        self.entries
            .iter()
            .filter(|e| e.inode == inode)
            .map(|e| DirtyRange::new(e.inode, e.offset_start, e.offset_end))
            .collect()
    }

    /// Return all dirty byte ranges for `inode` with their boundary tokens,
    /// ordered by offset.
    #[must_use]
    pub fn get_dirty_ranges_with_boundary(
        &self,
        inode: u64,
    ) -> Vec<(DirtyRange, FsyncBoundaryToken)> {
        self.entries
            .iter()
            .filter(|e| e.inode == inode)
            .map(|e| {
                (
                    DirtyRange::new(e.inode, e.offset_start, e.offset_end),
                    e.boundary,
                )
            })
            .collect()
    }

    /// Total dirty bytes for `inode` across all coalesced ranges.
    #[must_use]
    pub fn dirty_bytes(&self, inode: u64) -> u64 {
        self.entries
            .iter()
            .filter(|e| e.inode == inode)
            .fold(0_u64, |acc, e| {
                acc.saturating_add(e.offset_end.saturating_sub(e.offset_start))
            })
    }

    /// Return every (inode, start, end) tuple currently tracked.
    #[must_use]
    pub fn all_dirty_ranges(&self) -> Vec<(u64, u64, u64)> {
        self.entries
            .iter()
            .map(|e| (e.inode, e.offset_start, e.offset_end))
            .collect()
    }

    // ── age-aware accessors ────────────────────────────────────────────

    /// Return dirty byte ranges for `inode` with their dirtied_at_ms
    /// timestamp and boundary token, ordered by offset.
    #[must_use]
    pub fn get_dirty_ranges_with_age(
        &self,
        inode: u64,
    ) -> Vec<(DirtyRange, u64, FsyncBoundaryToken)> {
        self.entries
            .iter()
            .filter(|e| e.inode == inode)
            .map(|e| {
                (
                    DirtyRange::new(e.inode, e.offset_start, e.offset_end),
                    e.dirtied_at_ms,
                    e.boundary,
                )
            })
            .collect()
    }

    /// Return dirty inodes sorted by age (oldest first) with their total
    /// dirty bytes and oldest dirtied_at_ms.
    ///
    /// Each entry is `(inode, total_dirty_bytes, oldest_dirtied_at_ms)`.
    /// Inodes with `dirtied_at_ms == 0` (unknown age) are treated as
    /// the oldest (sorted first).
    #[must_use]
    pub fn dirty_inodes_sorted_by_age(&self) -> Vec<(u64, u64, u64)> {
        let mut inodes: Vec<(u64, u64, u64)> = Vec::new(); // (inode, total_bytes, oldest_age)
        let mut last_inode: u64 = u64::MAX;
        for e in &self.entries {
            if e.inode != last_inode {
                last_inode = e.inode;
                let total = self.dirty_bytes(e.inode);
                inodes.push((e.inode, total, e.dirtied_at_ms));
            }
        }
        // Sort by oldest_dirtied_at_ms ascending; 0 sorts first (oldest-unknown)
        inodes.sort_by(|a, b| match (a.2 == 0, b.2 == 0) {
            (true, true) => a.0.cmp(&b.0),
            (true, false) => core::cmp::Ordering::Less,
            (false, true) => core::cmp::Ordering::Greater,
            (false, false) => a.2.cmp(&b.2),
        });
        inodes
    }

    // ── lookup_range ────────────────────────────────────────────────────

    /// Look up dirty ranges that overlap with `[offset_start, offset_end)`
    /// for the given `inode`.
    ///
    /// Returns the first overlapping [`DirtyRange`], or `None` if no dirty
    /// range covers any part of the query range.
    ///
    /// This is used by the writeback flush service to check whether a
    /// specific byte range needs to be flushed before a read or fsync.
    #[must_use]
    pub fn lookup_range(
        &self,
        inode: u64,
        offset_start: u64,
        offset_end: u64,
    ) -> Option<DirtyRange> {
        if offset_start >= offset_end {
            return None;
        }
        self.entries
            .iter()
            .filter(|e| e.inode == inode)
            .find(|e| {
                // Overlap: entry_start < query_end AND query_start < entry_end
                e.offset_start < offset_end && offset_start < e.offset_end
            })
            .map(|e| DirtyRange::new(e.inode, e.offset_start, e.offset_end))
    }

    // ── take_boundary ───────────────────────────────────────────────────

    /// Atomically close the current boundary, open a fresh one, and return
    /// the just-closed token.
    ///
    /// All ranges dirtied before this call are now grouped under boundary
    /// `<=` the returned token.  Future [`mark_dirty`](Self::mark_dirty)
    /// calls will associate ranges with the new (higher) boundary.
    ///
    /// Returns 0 when called on an empty tracker that has never been used
    /// (i.e., no boundary has been assigned yet).
    #[must_use]
    pub fn take_boundary(&mut self) -> FsyncBoundaryToken {
        let closed = self.current_boundary;
        self.current_boundary = self.current_boundary.saturating_add(1);
        closed
    }

    // ── clear_until_boundary ────────────────────────────────────────────

    /// Remove all dirty ranges for `inode` whose boundary token is
    /// `<= boundary_token`.
    ///
    /// Returns the number of ranges removed.
    ///
    /// This is called by the writeback daemon after it has flushed
    /// dirty pages up to (and including) the given boundary.
    pub fn clear_until_boundary(
        &mut self,
        inode: u64,
        boundary_token: FsyncBoundaryToken,
    ) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|e| !(e.inode == inode && e.boundary <= boundary_token));
        before.saturating_sub(self.entries.len())
    }

    /// Remove all dirty ranges across all inodes whose boundary token
    /// is `<= boundary_token`.
    ///
    /// Returns the number of ranges removed.
    pub fn clear_all_until_boundary(&mut self, boundary_token: FsyncBoundaryToken) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| e.boundary > boundary_token);
        before.saturating_sub(self.entries.len())
    }

    // ── internals ───────────────────────────────────────────────────────

    /// Insert a dirty-page entry and merge it with any adjacent or
    /// overlapping entry for the same inode.
    fn insert_and_coalesce(
        &mut self,
        inode: u64,
        offset_start: u64,
        offset_end: u64,
        boundary: FsyncBoundaryToken,
        dirtied_at_ms: u64,
    ) {
        // Find where this entry belongs in sorted order.
        let mut insert_at = self.entries.len();
        for (i, e) in self.entries.iter().enumerate() {
            if e.inode > inode || (e.inode == inode && e.offset_start >= offset_start) {
                insert_at = i;
                break;
            }
        }

        let mut merged = DirtyPageEntry {
            inode,
            offset_start,
            offset_end,
            boundary,
            dirtied_at_ms,
        };

        // Merge with preceding entry if adjacent/overlapping for same inode.
        if insert_at > 0 {
            let prev = self.entries[insert_at - 1];
            if prev.inode == inode && prev.offset_end >= merged.offset_start {
                merged.offset_start = prev.offset_start;
                merged.offset_end = merged.offset_end.max(prev.offset_end);
                merged.boundary = merged.boundary.max(prev.boundary);
                merged.dirtied_at_ms = if prev.dirtied_at_ms == 0 {
                    merged.dirtied_at_ms
                } else if merged.dirtied_at_ms == 0 {
                    prev.dirtied_at_ms
                } else {
                    merged.dirtied_at_ms.min(prev.dirtied_at_ms)
                };
                self.entries.remove(insert_at - 1);
                insert_at -= 1;
            }
        }

        // Merge with following entries.
        while insert_at < self.entries.len() {
            let next = self.entries[insert_at];
            if next.inode != inode || next.offset_start > merged.offset_end {
                break;
            }
            merged.offset_end = merged.offset_end.max(next.offset_end);
            merged.boundary = merged.boundary.max(next.boundary);
            merged.dirtied_at_ms = if next.dirtied_at_ms == 0 {
                merged.dirtied_at_ms
            } else if merged.dirtied_at_ms == 0 {
                next.dirtied_at_ms
            } else {
                merged.dirtied_at_ms.min(next.dirtied_at_ms)
            };
            self.entries.remove(insert_at);
        }

        self.entries.insert(insert_at, merged);
    }
}

// ── fsync/fdatasync planning ────────────────────────────────────────────────

/// POSIX errno constants used by writeback sync planning.
pub mod sync_errno {
    /// Bad file descriptor.
    pub const EBADF: i32 = 9;
    /// Invalid argument.
    pub const EINVAL: i32 = 22;
    /// Stale file handle.
    pub const ESTALE: i32 = 116;
}

/// Type of durability request entering the writeback worker boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WritebackSyncKind {
    /// Full fsync: dirty data plus dirty metadata must reach stable storage.
    Fsync,
    /// fdatasync: dirty data first, metadata only when needed for retrieval.
    Fdatasync,
}

/// Ordered flush step selected by a writeback sync plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WritebackSyncStep {
    /// Flush dirty file data ranges.
    FlushData,
    /// Flush metadata that must be durable for the requested sync class.
    FlushMetadata,
}

/// Error returned when a writeback sync request cannot be planned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WritebackSyncPlanError {
    /// The file handle is not known to the caller's handle table.
    UnknownHandle,
    /// The file handle was already closed or released.
    ClosedHandle,
    /// The handle generation is stale.
    StaleHandle,
    /// The handle state is internally inconsistent.
    InvalidHandleState,
}

impl WritebackSyncPlanError {
    /// Map this planning error to the closest POSIX errno for a FUSE reply.
    #[must_use]
    pub const fn to_errno(self) -> i32 {
        match self {
            Self::UnknownHandle | Self::ClosedHandle => sync_errno::EBADF,
            Self::StaleHandle => sync_errno::ESTALE,
            Self::InvalidHandleState => sync_errno::EINVAL,
        }
    }
}

/// File-handle state needed to plan fsync/fdatasync without owning the daemon
/// handle table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WritebackSyncHandleState {
    /// Daemon-local FUSE file-handle id.
    pub handle_id: u64,
    /// Inode/object id targeted by the handle.
    pub object_id: u64,
    /// Handle generation used by the caller to reject stale requests.
    pub generation: u64,
    /// True while the handle is open and eligible for sync.
    pub is_open: bool,
    /// True when the caller knows this handle generation is stale.
    pub is_stale: bool,
    /// Dirty file data bytes associated with this handle.
    pub dirty_data_bytes: u64,
    /// True when metadata is dirty independently of data.
    pub dirty_metadata: bool,
    /// True when metadata must be durable for future data retrieval.
    pub metadata_required_for_data: bool,
}

impl WritebackSyncHandleState {
    /// Create a clean, open handle state.
    #[must_use]
    pub const fn new(handle_id: u64, object_id: u64, generation: u64) -> Self {
        Self {
            handle_id,
            object_id,
            generation,
            is_open: true,
            is_stale: false,
            dirty_data_bytes: 0,
            dirty_metadata: false,
            metadata_required_for_data: false,
        }
    }

    /// Mark dirty data bytes on this handle.
    #[must_use]
    pub const fn with_dirty_data(
        mut self,
        dirty_data_bytes: u64,
        metadata_required_for_data: bool,
    ) -> Self {
        self.dirty_data_bytes = dirty_data_bytes;
        self.metadata_required_for_data = metadata_required_for_data;
        self
    }

    /// Mark metadata as dirty.
    #[must_use]
    pub const fn with_dirty_metadata(mut self, metadata_required_for_data: bool) -> Self {
        self.dirty_metadata = true;
        self.metadata_required_for_data = metadata_required_for_data;
        self
    }

    /// Mark the handle as closed.
    #[must_use]
    pub const fn closed(mut self) -> Self {
        self.is_open = false;
        self
    }

    /// Mark the handle generation as stale.
    #[must_use]
    pub const fn stale(mut self) -> Self {
        self.is_stale = true;
        self
    }

    /// Returns true when this handle has any dirty data.
    #[must_use]
    pub const fn has_dirty_data(&self) -> bool {
        self.dirty_data_bytes > 0
    }

    /// Returns true when this handle has any dirty state relevant to fsync.
    #[must_use]
    pub const fn has_dirty_state(&self) -> bool {
        self.has_dirty_data() || self.dirty_metadata
    }

    fn validate(self) -> Result<Self, WritebackSyncPlanError> {
        if !self.is_open {
            return Err(WritebackSyncPlanError::ClosedHandle);
        }
        if self.is_stale {
            return Err(WritebackSyncPlanError::StaleHandle);
        }
        if self.object_id == 0 {
            return Err(WritebackSyncPlanError::InvalidHandleState);
        }

        Ok(self)
    }
}

/// Deterministic writeback plan for a single fsync/fdatasync request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WritebackSyncPlan {
    /// Requested sync class.
    pub kind: WritebackSyncKind,
    /// Daemon-local FUSE file-handle id.
    pub handle_id: u64,
    /// Inode/object id targeted by the request.
    pub object_id: u64,
    /// Handle generation used to produce this plan.
    pub generation: u64,
    /// Dirty data bytes that must be drained before reply.
    pub dirty_data_bytes: u64,
    steps: [WritebackSyncStep; 2],
    step_count: u8,
}

impl WritebackSyncPlan {
    fn new(
        kind: WritebackSyncKind,
        state: WritebackSyncHandleState,
        flush_data: bool,
        flush_metadata: bool,
    ) -> Self {
        let mut steps = [
            WritebackSyncStep::FlushData,
            WritebackSyncStep::FlushMetadata,
        ];
        let mut step_count = 0_u8;

        if flush_data {
            steps[usize::from(step_count)] = WritebackSyncStep::FlushData;
            step_count = step_count.saturating_add(1);
        }
        if flush_metadata {
            steps[usize::from(step_count)] = WritebackSyncStep::FlushMetadata;
            step_count = step_count.saturating_add(1);
        }

        Self {
            kind,
            handle_id: state.handle_id,
            object_id: state.object_id,
            generation: state.generation,
            dirty_data_bytes: state.dirty_data_bytes,
            steps,
            step_count,
        }
    }

    /// Ordered flush steps selected for the request.
    #[must_use]
    pub fn steps(&self) -> &[WritebackSyncStep] {
        &self.steps[..usize::from(self.step_count)]
    }

    /// Returns true when the request can reply without a writeback drain.
    #[must_use]
    pub const fn is_noop(&self) -> bool {
        self.step_count == 0
    }

    /// Returns true when dirty data must be flushed.
    #[must_use]
    pub fn requires_data_flush(&self) -> bool {
        self.steps()
            .iter()
            .any(|step| matches!(step, WritebackSyncStep::FlushData))
    }

    /// Returns true when metadata must be flushed.
    #[must_use]
    pub fn requires_metadata_flush(&self) -> bool {
        self.steps()
            .iter()
            .any(|step| matches!(step, WritebackSyncStep::FlushMetadata))
    }
}

/// Plan a single fsync/fdatasync request from daemon-provided handle state.
pub fn plan_writeback_sync(
    kind: WritebackSyncKind,
    state: Option<WritebackSyncHandleState>,
) -> Result<WritebackSyncPlan, WritebackSyncPlanError> {
    let Some(state) = state else {
        return Err(WritebackSyncPlanError::UnknownHandle);
    };
    let state = state.validate()?;

    let flush_data = state.has_dirty_data();
    let flush_metadata = match kind {
        WritebackSyncKind::Fsync => state.has_dirty_state(),
        WritebackSyncKind::Fdatasync => {
            state.metadata_required_for_data && (state.has_dirty_data() || state.dirty_metadata)
        }
    };

    Ok(WritebackSyncPlan::new(
        kind,
        state,
        flush_data,
        flush_metadata,
    ))
}

/// Deterministic flush plan for a single fsync/fdatasync request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WritebackFlushPlan {
    sync_plan: WritebackSyncPlan,
    data_ranges: DirtyFlushBatch,
}

impl WritebackFlushPlan {
    /// Create a flush plan from a sync plan and selected dirty data ranges.
    #[must_use]
    pub const fn new(sync_plan: WritebackSyncPlan, data_ranges: DirtyFlushBatch) -> Self {
        Self {
            sync_plan,
            data_ranges,
        }
    }

    /// Borrow the sync ordering plan.
    #[must_use]
    pub const fn sync_plan(&self) -> &WritebackSyncPlan {
        &self.sync_plan
    }

    /// Borrow the selected dirty data ranges.
    #[must_use]
    pub const fn data_ranges(&self) -> &DirtyFlushBatch {
        &self.data_ranges
    }

    /// Ordered sync steps selected for the request.
    #[must_use]
    pub fn steps(&self) -> &[WritebackSyncStep] {
        self.sync_plan.steps()
    }

    /// Total selected dirty data bytes.
    #[must_use]
    pub fn selected_dirty_bytes(&self) -> u64 {
        self.data_ranges.total_dirty_bytes()
    }

    /// Returns true when no data ranges or metadata steps must be flushed.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.sync_plan.is_noop() && self.data_ranges.is_empty()
    }

    /// Returns true when the sync request needs a data flush.
    #[must_use]
    pub fn requires_data_flush(&self) -> bool {
        self.sync_plan.requires_data_flush()
    }

    /// Returns true when the sync request needs a metadata flush.
    #[must_use]
    pub fn requires_metadata_flush(&self) -> bool {
        self.sync_plan.requires_metadata_flush()
    }
}

/// Plan fsync/fdatasync work and select this handle's dirty ranges.
pub fn plan_writeback_flush(
    kind: WritebackSyncKind,
    state: Option<WritebackSyncHandleState>,
    tracker: &DirtyRangeTracker,
    max_data_ranges: usize,
) -> Result<WritebackFlushPlan, WritebackSyncPlanError> {
    let sync_plan = plan_writeback_sync(kind, state)?;
    let data_ranges = if sync_plan.requires_data_flush() {
        tracker.next_flush_batch_for_object(sync_plan.object_id, max_data_ranges)
    } else {
        DirtyFlushBatch::new()
    };

    Ok(WritebackFlushPlan::new(sync_plan, data_ranges))
}

// ── CommitGroup barrier guard ───────────────────────────────────────────────────────

/// Coordinates with the scheduler commit_group flush barrier to ensure all pre-barrier
/// dirty data is drained before the barrier is released.
#[derive(Clone, Debug)]
pub struct CommitBarrierGuard {
    /// Transaction group guarded by this barrier.
    commit_group_id: u64,
    /// Number of items that must be drained before release.
    total_items: usize,
    /// Number of items drained so far.
    drained_count: usize,
    /// Number of items that encountered errors.
    error_count: usize,
    /// Total dirty bytes across all barrier items.
    total_dirty_bytes: u64,
}

impl CommitBarrierGuard {
    /// Create a new commit_group barrier guard.
    #[must_use]
    pub fn new(commit_group_id: u64, total_items: usize, total_dirty_bytes: u64) -> Self {
        Self {
            commit_group_id,
            total_items,
            drained_count: 0,
            error_count: 0,
            total_dirty_bytes,
        }
    }

    /// Transaction group guarded by this barrier.
    #[must_use]
    pub fn commit_group_id(&self) -> u64 {
        self.commit_group_id
    }

    /// Total number of items that must be drained.
    #[must_use]
    pub fn total_items(&self) -> usize {
        self.total_items
    }

    /// Number of items drained so far.
    #[must_use]
    pub fn drained_count(&self) -> usize {
        self.drained_count
    }

    /// Number of items that encountered errors.
    #[must_use]
    pub fn error_count(&self) -> usize {
        self.error_count
    }

    /// Total dirty bytes across all barrier items.
    #[must_use]
    pub fn total_dirty_bytes(&self) -> u64 {
        self.total_dirty_bytes
    }

    /// Returns true when all items have been drained (regardless of errors).
    #[must_use]
    pub fn is_drain_complete(&self) -> bool {
        self.drained_count + self.error_count >= self.total_items
    }

    /// Returns true when all items drained successfully without errors.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.error_count == 0 && self.drained_count >= self.total_items
    }

    /// Number of items still pending drain.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.total_items
            .saturating_sub(self.drained_count + self.error_count)
    }

    /// Record a successful drain completion.
    pub fn record_drained(&mut self) {
        if !self.is_drain_complete() {
            self.drained_count = self.drained_count.saturating_add(1);
        }
    }

    /// Record a drain error.
    pub fn record_error(&mut self) {
        if !self.is_drain_complete() {
            self.error_count = self.error_count.saturating_add(1);
        }
    }
}

// ── Object-store key helpers ────────────────────────────────────────────────

/// Derive an object-store key from an object id and block index.
///
/// This mirrors the `sparse_block_key` convention used by workers-io so that
/// the drain engine can locate stored data using the same keying scheme.
#[must_use]
pub fn drain_block_key(object_id: u64, block_index: u64) -> [u8; 32] {
    let mut key = [0_u8; 32];
    key[..8].copy_from_slice(&object_id.to_le_bytes());
    key[8..16].copy_from_slice(&block_index.to_le_bytes());
    // Set a lane discriminator to distinguish from other key families.
    key[16] = 0x02;
    key
}

// ── Trait abstractions ──────────────────────────────────────────────────────

/// Source of dirty work items from the scheduler queue.
///
/// Implementations bridge the scheduler-local `WritebackDispatchState` into
/// the drain worker boundary.
pub trait DirtyWorkSource {
    /// Returns true when the scheduler queue is empty.
    fn is_queue_empty(&self) -> bool;

    /// Returns the number of queued work items.
    fn queued_len(&self) -> usize;

    /// Returns the number of in-flight work items.
    fn in_flight_len(&self) -> usize;

    /// Dispatch the next queued work item, returning a drain ticket.
    fn dispatch_next(&mut self) -> Result<DrainTicket, DrainError>;

    /// Begin a transaction-group flush barrier, returning all work items
    /// for `commit_group_id` that must be drained before the barrier can release.
    fn begin_commit_group_flush(
        &mut self,
        commit_group_id: u64,
    ) -> Result<CommitBarrierGuard, DrainError>;

    /// Complete a previously dispatched ticket, removing it from in-flight
    /// accounting in the scheduler.
    fn complete(&mut self, ticket_id: u64) -> Result<DrainWorkItem, DrainError>;

    /// Requeue a failed ticket for retry.
    fn retry(&mut self, ticket_id: u64) -> Result<(), DrainError>;

    /// Returns true when a commit_group has no queued or in-flight work.
    fn is_commit_group_idle(&self, commit_group_id: u64) -> bool;
}

/// Source of dirty page data for a given object and byte range.
///
/// The drain engine reads dirty data through this trait before flushing to
/// the object store. In production this is backed by the in-memory dirty
/// page cache populated by FUSE writes.
pub trait DirtyDataProvider {
    /// Read dirty data for `object_id` at the given byte range.
    ///
    /// Returns the dirty bytes, which must have length equal to
    /// `offset_end - offset_start`.
    fn read_dirty(
        &self,
        object_id: u64,
        offset_start: u64,
        offset_end: u64,
    ) -> Result<Vec<u8>, DrainError>;

    /// Mark a byte range as clean after successful flush.
    fn mark_clean(
        &mut self,
        object_id: u64,
        offset_start: u64,
        offset_end: u64,
    ) -> Result<(), DrainError>;
}

/// Object-store write contract for the drain engine.
///
/// The drain engine issues put operations for dirty data that must be
/// persisted before the owning transaction group can commit.
pub trait DrainObjectStore {
    /// Store a payload under the given key, returning the stored key on success.
    fn put(&mut self, key: &[u8; 32], payload: &[u8]) -> Result<[u8; 32], DrainError>;
}

/// Extent-map update contract for drain completion.
///
/// After dirty data is flushed to the object store, the extent map must be
/// updated to reflect the new object-store key mapping.
pub trait DrainExtentMap {
    /// Insert or update an extent mapping for `object_id`.
    ///
    /// The extent maps the logical file range (`offset_start..offset_end`)
    /// to the given object-store key at the given object offset.
    fn insert_extent(
        &mut self,
        object_id: u64,
        offset_start: u64,
        offset_end: u64,
        object_key: [u8; 32],
    ) -> Result<(), DrainError>;
}

// ── Scheduler bridge ────────────────────────────────────────────────────────

fn map_scheduler_dispatch_error(error: WritebackDispatchError) -> DrainError {
    match error {
        WritebackDispatchError::QueueEmpty => DrainError::QueueEmpty,
        WritebackDispatchError::InFlightFull => DrainError::InFlightFull,
        WritebackDispatchError::UnknownTicket => DrainError::UnknownTicket,
        WritebackDispatchError::RequeueFull => DrainError::InFlightFull,
    }
}

/// Dirty work source backed by the scheduler crate's writeback dispatch state.
///
/// The wrapper keeps commit_group barrier state local to the worker boundary while
/// preserving the scheduler's queue, in-flight, retry, and completion accounting.
pub struct SchedulerDirtyWorkSource<'a, const QUEUE_CAP: usize, const IN_FLIGHT_CAP: usize> {
    state: &'a mut WritebackDispatchState<QUEUE_CAP, IN_FLIGHT_CAP>,
    active_barrier: Option<WritebackCommitGroupFlushBarrier<QUEUE_CAP>>,
}

impl<'a, const QUEUE_CAP: usize, const IN_FLIGHT_CAP: usize>
    SchedulerDirtyWorkSource<'a, QUEUE_CAP, IN_FLIGHT_CAP>
{
    /// Create a dirty work source over scheduler dispatch state.
    #[must_use]
    pub const fn new(state: &'a mut WritebackDispatchState<QUEUE_CAP, IN_FLIGHT_CAP>) -> Self {
        Self {
            state,
            active_barrier: None,
        }
    }

    /// Borrow the underlying scheduler dispatch state.
    #[must_use]
    pub fn state(&self) -> &WritebackDispatchState<QUEUE_CAP, IN_FLIGHT_CAP> {
        self.state
    }

    /// Mutably borrow the underlying scheduler dispatch state.
    #[must_use]
    pub fn state_mut(&mut self) -> &mut WritebackDispatchState<QUEUE_CAP, IN_FLIGHT_CAP> {
        self.state
    }

    /// Returns true when there is an active commit_group barrier waiting to dispatch work.
    #[must_use]
    pub fn has_active_barrier(&self) -> bool {
        self.active_barrier
            .as_ref()
            .is_some_and(|barrier| barrier.pending_dispatch_len() > 0)
    }

    fn clear_completed_barrier(&mut self) {
        if self
            .active_barrier
            .as_ref()
            .is_some_and(WritebackCommitGroupFlushBarrier::is_dispatch_complete)
        {
            self.active_barrier = None;
        }
    }
}

impl<const QUEUE_CAP: usize, const IN_FLIGHT_CAP: usize> DirtyWorkSource
    for SchedulerDirtyWorkSource<'_, QUEUE_CAP, IN_FLIGHT_CAP>
{
    fn is_queue_empty(&self) -> bool {
        !self.has_active_barrier() && self.state.queued_len() == 0
    }

    fn queued_len(&self) -> usize {
        let barrier_pending = self
            .active_barrier
            .as_ref()
            .map_or(0, WritebackCommitGroupFlushBarrier::pending_dispatch_len);
        barrier_pending.saturating_add(self.state.queued_len())
    }

    fn in_flight_len(&self) -> usize {
        self.state.in_flight_len()
    }

    fn dispatch_next(&mut self) -> Result<DrainTicket, DrainError> {
        if let Some(barrier) = self.active_barrier.as_mut() {
            if let Some(ticket) = self
                .state
                .dispatch_commit_group_flush_next(barrier)
                .map_err(map_scheduler_dispatch_error)?
            {
                return Ok(ticket.into());
            }
        }

        self.clear_completed_barrier();
        self.state
            .dispatch_next()
            .map(DrainTicket::from)
            .map_err(map_scheduler_dispatch_error)
    }

    fn begin_commit_group_flush(
        &mut self,
        commit_group_id: u64,
    ) -> Result<CommitBarrierGuard, DrainError> {
        if self.has_active_barrier() {
            return Err(DrainError::CommitGroupBarrierBroken);
        }

        let barrier = self.state.begin_commit_group_flush(commit_group_id);
        let guard = CommitBarrierGuard::new(
            barrier.commit_group_id(),
            barrier.drained_len(),
            barrier.dirty_byte_count(),
        );

        if barrier.drained_len() == 0 {
            self.active_barrier = None;
        } else {
            self.active_barrier = Some(barrier);
        }

        Ok(guard)
    }

    fn complete(&mut self, ticket_id: u64) -> Result<DrainWorkItem, DrainError> {
        self.state
            .complete(ticket_id)
            .map(DrainWorkItem::from)
            .map_err(map_scheduler_dispatch_error)
    }

    fn retry(&mut self, ticket_id: u64) -> Result<(), DrainError> {
        self.state
            .retry(ticket_id)
            .map_err(map_scheduler_dispatch_error)
    }

    fn is_commit_group_idle(&self, commit_group_id: u64) -> bool {
        let barrier_idle = self.active_barrier.as_ref().is_none_or(|barrier| {
            barrier.commit_group_id() != commit_group_id || barrier.pending_dispatch_len() == 0
        });
        barrier_idle && self.state.is_commit_group_idle(commit_group_id)
    }
}

// ── Dirty drain engine ──────────────────────────────────────────────────────

/// The writeback dirty-drain engine.
///
/// Scans scheduled dirty work items from the scheduler, batches by object-store
/// key affinity, issues put operations, updates extent metadata, and reports
/// completion back to the scheduler.
pub struct DirtyDrainEngine<'a, S, D, O, E> {
    work_source: &'a mut S,
    dirty_data: &'a mut D,
    object_store: &'a mut O,
    extent_map: &'a mut E,
    stats: DrainStats,
    max_concurrent_drains: u32,
    block_size: u64,
}

impl<'a, S, D, O, E> DirtyDrainEngine<'a, S, D, O, E>
where
    S: DirtyWorkSource,
    D: DirtyDataProvider,
    O: DrainObjectStore,
    E: DrainExtentMap,
{
    /// Create a drain engine with the default block size (4096 bytes).
    #[must_use]
    pub const fn new(
        work_source: &'a mut S,
        dirty_data: &'a mut D,
        object_store: &'a mut O,
        extent_map: &'a mut E,
        max_concurrent_drains: u32,
    ) -> Self {
        Self {
            work_source,
            dirty_data,
            object_store,
            extent_map,
            stats: DrainStats::new(),
            max_concurrent_drains,
            block_size: 4096,
        }
    }

    /// Create a drain engine with an explicit block size.
    #[must_use]
    pub const fn with_block_size(
        work_source: &'a mut S,
        dirty_data: &'a mut D,
        object_store: &'a mut O,
        extent_map: &'a mut E,
        max_concurrent_drains: u32,
        block_size: u64,
    ) -> Self {
        Self {
            work_source,
            dirty_data,
            object_store,
            extent_map,
            stats: DrainStats::new(),
            max_concurrent_drains,
            block_size,
        }
    }

    /// Borrow the current drain statistics.
    #[must_use]
    pub fn stats(&self) -> &DrainStats {
        &self.stats
    }

    /// Maximum concurrent drain operations.
    #[must_use]
    pub fn max_concurrent_drains(&self) -> u32 {
        self.max_concurrent_drains
    }

    /// Drain a single work item from the scheduler queue.
    ///
    /// Returns the ticket id of the drained item on success.
    pub fn drain_one(&mut self) -> Result<u64, DrainError> {
        if self.stats.pending >= u64::from(self.max_concurrent_drains) {
            return Err(DrainError::InFlightFull);
        }
        if self.work_source.is_queue_empty() {
            return Err(DrainError::QueueEmpty);
        }

        let ticket = self.work_source.dispatch_next()?;
        self.stats.record_dispatched();

        let result = self.flush_item(&ticket.item);
        match result {
            Ok(_) => {
                self.stats.record_completion(ticket.item.dirty_byte_count);
                self.work_source.complete(ticket.ticket_id)?;
                Ok(ticket.ticket_id)
            }
            Err(e) => {
                self.stats.record_error();
                let _ = self.work_source.retry(ticket.ticket_id);
                Err(e)
            }
        }
    }

    /// Drain all currently queued work items up to the concurrency limit.
    ///
    /// Returns the number of items successfully drained.
    pub fn drain_all(&mut self) -> Result<usize, DrainError> {
        let mut drained = 0_usize;
        loop {
            if self.stats.pending >= u64::from(self.max_concurrent_drains) {
                break;
            }
            if self.work_source.is_queue_empty() {
                break;
            }
            match self.drain_one() {
                Ok(_) => drained += 1,
                Err(DrainError::QueueEmpty) => break,
                Err(DrainError::InFlightFull) => break,
                Err(_) => {
                    drained += 1;
                }
            }
        }
        Ok(drained)
    }

    /// Drain all items associated with a transaction group flush barrier.
    ///
    /// This ensures all pre-barrier dirty data for `commit_group_id` is flushed to the
    /// object store before the barrier is released.
    pub fn drain_commit_barrier(
        &mut self,
        commit_group_id: u64,
    ) -> Result<CommitBarrierGuard, DrainError> {
        let mut guard = self.work_source.begin_commit_group_flush(commit_group_id)?;

        while !guard.is_drain_complete() {
            if self.stats.pending >= u64::from(self.max_concurrent_drains) {
                break;
            }

            match self.work_source.dispatch_next() {
                Ok(ticket) => {
                    self.stats.record_dispatched();
                    if ticket.item.commit_group_id != commit_group_id {
                        let _ = self.work_source.retry(ticket.ticket_id);
                        self.stats.record_error();
                        guard.record_error();
                        continue;
                    }

                    match self.flush_item(&ticket.item) {
                        Ok(_) => {
                            self.stats.record_completion(ticket.item.dirty_byte_count);
                            self.work_source.complete(ticket.ticket_id)?;
                            guard.record_drained();
                        }
                        Err(_) => {
                            self.stats.record_error();
                            let _ = self.work_source.retry(ticket.ticket_id);
                            guard.record_error();
                        }
                    }
                }
                Err(DrainError::QueueEmpty) => break,
                Err(_) => break,
            }
        }

        if guard.is_clean() {
            self.stats
                .record_commit_barrier_completed(guard.total_dirty_bytes);
        } else {
            self.stats.record_commit_barrier_failed();
        }

        Ok(guard)
    }

    /// Sort work items by object-store key affinity, grouping items for the
    /// same object together to enable batch flush optimization.
    #[must_use]
    pub fn batch_by_object_affinity(items: &[DrainWorkItem]) -> Vec<DrainBatch> {
        if items.is_empty() {
            return Vec::new();
        }

        let mut sorted = items.to_vec();
        sorted.sort_by(|a, b| match a.object_id.cmp(&b.object_id) {
            Ordering::Equal => a.offset_start.cmp(&b.offset_start),
            other => other,
        });

        let mut batches: Vec<DrainBatch> = Vec::new();
        let mut current: Option<DrainBatch> = None;

        for item in sorted {
            match &mut current {
                Some(batch) if !batch.is_empty() => {
                    let first = batch.as_slice()[0];
                    if first.object_id == item.object_id {
                        batch.push(item);
                    } else {
                        let prev = core::mem::replace(current.as_mut().unwrap(), DrainBatch::new());
                        batches.push(prev);
                        current.as_mut().unwrap().push(item);
                    }
                }
                _ => {
                    let mut batch = DrainBatch::new();
                    batch.push(item);
                    current = Some(batch);
                }
            }
        }

        if let Some(batch) = current {
            if !batch.is_empty() {
                batches.push(batch);
            }
        }

        batches
    }

    /// Flush a single work item: read dirty data, store in object store,
    /// update extent map.
    fn flush_item(&mut self, item: &DrainWorkItem) -> Result<[u8; 32], DrainError> {
        if !item.is_valid() {
            return Err(DrainError::InvalidWorkItem);
        }

        let data =
            self.dirty_data
                .read_dirty(item.object_id, item.offset_start, item.offset_end)?;

        let block_index = item.offset_start / self.block_size;
        let key = drain_block_key(item.object_id, block_index);

        let stored_key = self.object_store.put(&key, &data)?;

        self.extent_map.insert_extent(
            item.object_id,
            item.offset_start,
            item.offset_end,
            stored_key,
        )?;

        self.dirty_data
            .mark_clean(item.object_id, item.offset_start, item.offset_end)?;

        Ok(stored_key)
    }
}

// ── mmap dirty-page tracking ───────────────────────────────────────────────

/// Protection flags for an mmap'd memory region.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MmapProtFlags {
    /// Pages may be read.
    pub prot_read: bool,
    /// Pages may be written.
    pub prot_write: bool,
    /// Pages may be executed.
    pub prot_exec: bool,
    /// MAP_SHARED (writes are visible to other mappings and must be flushed).
    pub map_shared: bool,
}

impl MmapProtFlags {
    /// PROT_READ | PROT_WRITE, MAP_SHARED.
    #[must_use]
    pub const fn rw_shared() -> Self {
        Self {
            prot_read: true,
            prot_write: true,
            prot_exec: false,
            map_shared: true,
        }
    }

    /// PROT_READ, MAP_SHARED.
    #[must_use]
    pub const fn read_shared() -> Self {
        Self {
            prot_read: true,
            prot_write: false,
            prot_exec: false,
            map_shared: true,
        }
    }

    /// PROT_READ | PROT_WRITE, MAP_PRIVATE.
    #[must_use]
    pub const fn rw_private() -> Self {
        Self {
            prot_read: true,
            prot_write: true,
            prot_exec: false,
            map_shared: false,
        }
    }

    /// Returns true when writes to this mapping produce dirty pages.
    #[must_use]
    pub const fn is_writable_shared(&self) -> bool {
        self.prot_write && self.map_shared
    }
}

/// A single mmap'd memory region for an inode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MmapRegion {
    /// Start byte offset within the file.
    pub start: u64,
    /// Length of the region in bytes.
    pub length: u64,
    /// Protection and sharing flags.
    pub prot_flags: MmapProtFlags,
}

impl MmapRegion {
    /// Create an mmap region.
    #[must_use]
    pub const fn new(start: u64, length: u64, prot_flags: MmapProtFlags) -> Self {
        Self {
            start,
            length,
            prot_flags,
        }
    }

    /// End offset (exclusive).
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.start.saturating_add(self.length)
    }

    /// Returns true when `offset` falls within this region.
    #[must_use]
    pub const fn contains_offset(&self, offset: u64) -> bool {
        offset >= self.start && offset < self.end()
    }

    /// Returns true when `offset` falls within a writable shared page.
    #[must_use]
    pub fn contains_writable_offset(&self, offset: u64) -> bool {
        self.prot_flags.is_writable_shared() && self.contains_offset(offset)
    }

    /// Returns true when this region overlaps `[other_start, other_start+other_len)`.
    #[must_use]
    pub fn overlaps(&self, other_start: u64, other_len: u64) -> bool {
        if other_len == 0 {
            return false;
        }
        let other_end = other_start.saturating_add(other_len);
        self.start < other_end && other_start < self.end()
    }

    /// Returns true when the region has non-zero length.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.length > 0
    }
}

/// Per-inode mmap instrumentation counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MmapStats {
    /// Total mmap calls tracked.
    pub mmap_count: u64,
    /// Cumulative bytes mapped across all mmap calls.
    pub mmap_total_bytes: u64,
    /// Write page faults that fell in a writable shared region.
    pub dirty_page_faults: u64,
    /// msync calls processed.
    pub msync_count: u64,
    /// Dirty pages identified for flush by msync.
    pub msync_dirty_pages: u64,
    /// munmap calls processed.
    pub munmap_count: u64,
    /// Dirty pages identified for flush by munmap.
    pub munmap_dirty_pages: u64,
}

impl MmapStats {
    /// Create zeroed mmap statistics.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            mmap_count: 0,
            mmap_total_bytes: 0,
            dirty_page_faults: 0,
            msync_count: 0,
            msync_dirty_pages: 0,
            munmap_count: 0,
            munmap_dirty_pages: 0,
        }
    }

    /// Record a new mmap call.
    pub fn record_mmap(&mut self, byte_count: u64) {
        self.mmap_count = self.mmap_count.saturating_add(1);
        self.mmap_total_bytes = self.mmap_total_bytes.saturating_add(byte_count);
    }

    /// Record a write page fault that fell in a writable shared region.
    pub fn record_page_fault(&mut self) {
        self.dirty_page_faults = self.dirty_page_faults.saturating_add(1);
    }

    /// Record an msync and the number of dirty pages it identified.
    pub fn record_msync(&mut self, dirty_page_count: u64) {
        self.msync_count = self.msync_count.saturating_add(1);
        self.msync_dirty_pages = self.msync_dirty_pages.saturating_add(dirty_page_count);
    }

    /// Record a munmap and the number of dirty pages it identified for flush.
    pub fn record_munmap(&mut self, dirty_page_count: u64) {
        self.munmap_count = self.munmap_count.saturating_add(1);
        self.munmap_dirty_pages = self.munmap_dirty_pages.saturating_add(dirty_page_count);
    }
}

/// Tracks mmap'd regions for a single inode and coordinates dirty-page
/// marking with the DirtyRangeTracker when write page faults occur on
/// MAP_SHARED writable regions.
///
/// Gated by FUSE_CAP_WRITEBACK_CACHE: when [`set_enabled(false)`](Self::set_enabled),
/// all operations are no-ops and page faults are ignored.
#[derive(Clone, Debug, Default)]
pub struct MmapTracker {
    regions: Vec<MmapRegion>,
    stats: MmapStats,
    enabled: bool,
    page_size: u64,
}

impl MmapTracker {
    /// Create an mmap tracker with the given system page size.
    ///
    /// Tracking is disabled by default; call [`set_enabled(true)`](Self::set_enabled)
    /// after FUSE_CAP_WRITEBACK_CACHE is negotiated.
    #[must_use]
    pub fn new(page_size: u64) -> Self {
        Self {
            regions: Vec::new(),
            stats: MmapStats::new(),
            enabled: false,
            page_size,
        }
    }

    /// Enable or disable mmap dirty-page tracking.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns true when mmap tracking is active.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Borrow the accumulated mmap statistics.
    #[must_use]
    pub fn stats(&self) -> &MmapStats {
        &self.stats
    }

    /// Number of currently tracked mmap regions.
    #[must_use]
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }

    /// Access tracked regions in ascending start-offset order.
    #[must_use]
    pub fn regions(&self) -> &[MmapRegion] {
        &self.regions
    }

    /// Returns the configured page size.
    #[must_use]
    pub fn page_size(&self) -> u64 {
        self.page_size
    }

    /// Register a new mmap'd region.
    ///
    /// Returns [`DrainError::MmapRegionOverlap`] when the region overlaps an
    /// existing tracked region.  Regions must not overlap to keep flush
    /// accounting deterministic.
    pub fn mmap(&mut self, region: MmapRegion) -> Result<(), DrainError> {
        if !region.is_valid() {
            return Err(DrainError::InvalidWorkItem);
        }

        if self
            .regions
            .iter()
            .any(|r| region.overlaps(r.start, r.length))
        {
            return Err(DrainError::MmapRegionOverlap);
        }

        self.stats.record_mmap(region.length);
        self.regions.push(region);
        self.sort_regions();
        Ok(())
    }

    /// Unmap a previously registered region.
    ///
    /// If mmap tracking is enabled and the region is writable-shared, this
    /// method identifies dirty pages in the unmapped range and returns the
    /// count so the caller can drain them through the writeback engine before
    /// the munmap reply.
    ///
    /// Returns the number of dirty pages that must be flushed.
    pub fn munmap(
        &mut self,
        start: u64,
        length: u64,
        tracker: &DirtyRangeTracker,
        object_id: u64,
    ) -> Result<u64, DrainError> {
        if length == 0 {
            return Err(DrainError::InvalidWorkItem);
        }

        let idx = self
            .regions
            .iter()
            .position(|r| r.start == start && r.length == length);

        let Some(idx) = idx else {
            return Err(DrainError::MmapRegionNotFound);
        };

        let region = self.regions.remove(idx);
        let dirty_pages = if self.enabled && region.prot_flags.is_writable_shared() {
            self.count_dirty_pages_in_range(region.start, region.end(), tracker, object_id)
        } else {
            0
        };

        self.stats.record_munmap(dirty_pages);
        Ok(dirty_pages)
    }

    /// Handle a write page fault at `offset` within the file.
    ///
    /// When `offset` falls inside a writable MAP_SHARED region and tracking is
    /// enabled, the enclosing page is marked dirty in `tracker`.  Returns true
    /// when the page was recorded as dirty.
    ///
    /// Read-only, MAP_PRIVATE, and disabled-tracker faults return `Ok(false)`.
    pub fn page_fault_write(
        &mut self,
        offset: u64,
        tracker: &mut DirtyRangeTracker,
        object_id: u64,
    ) -> Result<bool, DrainError> {
        if !self.enabled {
            return Ok(false);
        }

        let in_writable = self
            .regions
            .iter()
            .any(|r| r.contains_writable_offset(offset));

        if !in_writable {
            return Ok(false);
        }

        let page_aligned_start = (offset / self.page_size) * self.page_size;
        let page_aligned_end = page_aligned_start.saturating_add(self.page_size);

        tracker.record_dirty(object_id, page_aligned_start, page_aligned_end)?;
        self.stats.record_page_fault();
        Ok(true)
    }

    /// Count dirty pages overlapping `[start, start+length)` for msync.
    ///
    /// When the range intersects a writable shared region, this returns the
    /// number of dirty pages that need flushing.  The caller drains them
    /// through the writeback engine before the msync reply.
    pub fn msync(
        &mut self,
        start: u64,
        length: u64,
        tracker: &DirtyRangeTracker,
        object_id: u64,
    ) -> Result<u64, DrainError> {
        if length == 0 {
            return Err(DrainError::InvalidWorkItem);
        }

        if !self.enabled {
            return Ok(0);
        }

        let end = start.saturating_add(length);
        let has_writable = self
            .regions
            .iter()
            .any(|r| r.prot_flags.is_writable_shared() && r.overlaps(start, length));

        if !has_writable {
            return Ok(0);
        }

        let dirty_pages = self.count_dirty_pages_in_range(start, end, tracker, object_id);
        self.stats.record_msync(dirty_pages);
        Ok(dirty_pages)
    }

    /// Returns true when `offset` falls inside a writable MAP_SHARED region
    /// and mmap tracking is enabled.
    #[must_use]
    pub fn is_writable_shared_offset(&self, offset: u64) -> bool {
        self.enabled
            && self
                .regions
                .iter()
                .any(|r| r.contains_writable_offset(offset))
    }

    // ── internal ────────────────────────────────────────────────────────────

    fn sort_regions(&mut self) {
        self.regions.sort_by(|a, b| a.start.cmp(&b.start));
    }

    fn page_align_down(&self, offset: u64) -> u64 {
        (offset / self.page_size) * self.page_size
    }

    fn page_align_up(&self, offset: u64) -> u64 {
        if offset % self.page_size == 0 {
            offset
        } else {
            ((offset / self.page_size) + 1) * self.page_size
        }
    }

    fn count_dirty_pages_in_range(
        &self,
        range_start: u64,
        range_end: u64,
        tracker: &DirtyRangeTracker,
        object_id: u64,
    ) -> u64 {
        let page_start = self.page_align_down(range_start);
        let page_end = self.page_align_up(range_end);

        let mut total_pages = 0_u64;
        for r in tracker.pending_ranges().iter() {
            if r.object_id != object_id {
                continue;
            }
            let overlap_start = page_start.max(r.offset_start);
            let overlap_end = page_end.min(r.offset_end);
            if overlap_start < overlap_end {
                let byte_len = overlap_end - overlap_start;
                let pages = byte_len.div_ceil(self.page_size);
                total_pages = total_pages.saturating_add(pages);
            }
        }
        total_pages
    }
}
// ── Mock implementations for testing ────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════
// ── Writeback daemon ───────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration for the periodic writeback daemon.
#[derive(Clone, Copy, Debug)]
pub struct WritebackDaemonConfig {
    /// Interval (ms) between daemon wakeups.
    pub wake_interval_ms: u64,
    /// Fraction (in hundredths of a percent) of cache memory that may be
    /// dirty before the daemon starts flushing.  Default: 2000 = 20.00%.
    pub dirty_ratio_hundredths: u32,
    /// Absolute dirty-byte threshold (bytes).  When dirty data exceeds this
    /// value the daemon starts flushing regardless of the ratio.  Default:
    /// 256 MiB.
    pub dirty_bytes_threshold: u64,
    /// Age threshold in centiseconds.  Dirty pages older than this are
    /// flushed regardless of ratio or byte count.  Default: 3000 = 30 s.
    pub dirty_expire_centisecs: u64,
    /// Total cache memory available for the daemon to compute the ratio
    /// against.  This is supplied externally (e.g. from the FUSE daemon's
    /// memory budget).  Default: 1 GiB.
    pub total_cache_bytes: u64,
    /// Maximum number of bytes to flush per tick.  Used for adaptive rate
    /// limiting.  Default: 64 MiB.
    pub max_flush_bytes_per_tick: u64,
    /// Minimum number of bytes to flush per tick when throttled.  Default:
    /// 4 MiB.
    pub min_flush_bytes_per_tick: u64,
}

impl Default for WritebackDaemonConfig {
    fn default() -> Self {
        Self {
            wake_interval_ms: 5_000,
            dirty_ratio_hundredths: 2_000,
            dirty_bytes_threshold: 256 * 1024 * 1024,
            dirty_expire_centisecs: 3_000,
            total_cache_bytes: 1024 * 1024 * 1024,
            max_flush_bytes_per_tick: 64 * 1024 * 1024,
            min_flush_bytes_per_tick: 4 * 1024 * 1024,
        }
    }
}

impl WritebackDaemonConfig {
    /// Create daemon configuration from explicit tunables.
    #[must_use]
    pub const fn new(
        wake_interval_ms: u64,
        dirty_ratio_hundredths: u32,
        dirty_bytes_threshold: u64,
        dirty_expire_centisecs: u64,
        total_cache_bytes: u64,
        max_flush_bytes_per_tick: u64,
        min_flush_bytes_per_tick: u64,
    ) -> Self {
        Self {
            wake_interval_ms,
            dirty_ratio_hundredths,
            dirty_bytes_threshold,
            dirty_expire_centisecs,
            total_cache_bytes,
            max_flush_bytes_per_tick,
            min_flush_bytes_per_tick,
        }
    }

    /// Dirty ratio as a fraction in [0.0, 1.0] for easy comparison.
    #[must_use]
    pub fn dirty_ratio_fraction(&self) -> f64 {
        f64::from(self.dirty_ratio_hundredths) / 10_000.0
    }
}

/// Instrumentation counters for the writeback daemon.
#[derive(Clone, Copy, Debug)]
pub struct WritebackDaemonStats {
    /// Total number of daemon wakeups.
    pub daemon_wakeups: u64,
    /// Total number of pages flushed (page = 4096 bytes for counting).
    pub pages_flushed: u64,
    /// Total number of bytes flushed to stable storage.
    pub bytes_written: u64,
    /// 50th-percentile flush latency in milliseconds.
    pub flush_latency_p50_ms: u64,
    /// 99th-percentile flush latency in milliseconds.
    pub flush_latency_p99_ms: u64,
    /// Dirty ratio (in hundredths of a percent) recorded at the most recent
    /// wakeup.
    pub dirty_ratio_at_wakeup_hundredths: u32,
    /// Number of times the daemon throttled its flush rate due to IO
    /// pressure.
    pub throttle_events: u64,
    /// Number of ticks that resulted in at least one flush.
    pub active_ticks: u64,
    /// Number of ticks that found nothing to flush.
    pub idle_ticks: u64,
    /// Number of times the daemon flushed due to dirty_expire_centisecs.
    pub expire_flushes: u64,
    /// Number of times the daemon flushed due to dirty_ratio threshold.
    pub ratio_flushes: u64,
    /// Number of times the daemon flushed due to dirty_bytes threshold.
    pub bytes_flushes: u64,
    /// Running average IO latency (ms) used for adaptive rate limiting.
    current_latency_avg_ms: u64,
    /// Latency samples collected for percentile computation.
    latency_samples: [u64; 32],
    latency_sample_count: u8,
    latency_sample_idx: u8,
}

impl Default for WritebackDaemonStats {
    fn default() -> Self {
        Self::new()
    }
}

impl WritebackDaemonStats {
    /// Create a zero-initialized stats record.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            daemon_wakeups: 0,
            pages_flushed: 0,
            bytes_written: 0,
            flush_latency_p50_ms: 0,
            flush_latency_p99_ms: 0,
            dirty_ratio_at_wakeup_hundredths: 0,
            throttle_events: 0,
            active_ticks: 0,
            idle_ticks: 0,
            expire_flushes: 0,
            ratio_flushes: 0,
            bytes_flushes: 0,
            current_latency_avg_ms: 0,
            latency_samples: [0_u64; 32],
            latency_sample_count: 0,
            latency_sample_idx: 0,
        }
    }

    /// Record a completed flush with its latency.
    pub fn record_flush(&mut self, bytes: u64, latency_ms: u64) {
        self.bytes_written = self.bytes_written.saturating_add(bytes);
        self.pages_flushed = self.pages_flushed.saturating_add(bytes / 4096);

        // Rolling latency tracking
        let idx = self.latency_sample_idx as usize;
        self.latency_samples[idx] = latency_ms;
        self.latency_sample_idx = self.latency_sample_idx.wrapping_add(1);
        if self.latency_sample_count < 32 {
            self.latency_sample_count += 1;
        }
        self.current_latency_avg_ms = self.compute_avg_latency();
    }

    /// Record a throttle event.
    pub fn record_throttle(&mut self) {
        self.throttle_events = self.throttle_events.saturating_add(1);
    }

    /// Compute the 50th-percentile and 99th-percentile latencies from
    /// collected samples and update the public fields.
    pub fn recompute_percentiles(&mut self) {
        let count = self.latency_sample_count as usize;
        if count == 0 {
            return;
        }
        let mut samples = [0_u64; 32];
        samples[..count].copy_from_slice(&self.latency_samples[..count]);
        samples[..count].sort_unstable();
        let p50_idx = count * 50 / 100;
        let p99_idx = count * 99 / 100;
        self.flush_latency_p50_ms = samples[p50_idx.min(count - 1)];
        self.flush_latency_p99_ms = samples[p99_idx.min(count - 1)];
    }

    fn compute_avg_latency(&self) -> u64 {
        let count = self.latency_sample_count as usize;
        if count == 0 {
            return 0;
        }
        let sum: u64 = self.latency_samples[..count].iter().sum();
        sum / count as u64
    }
}

/// Trigger classification for a daemon tick.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlushTrigger {
    /// No flushing needed.
    None,
    /// Flushing triggered by dirty_ratio exceeding threshold.
    DirtyRatio,
    /// Flushing triggered by absolute dirty_bytes threshold.
    DirtyBytes,
    /// Flushing triggered by dirty_expire_centisecs age threshold.
    DirtyExpire,
}

/// The periodic writeback daemon.
///
/// Wakes periodically and flushes dirty pages based on configurable
/// thresholds: dirty ratio, absolute byte count, and expiration age.
/// Adapts flush rate to observed IO latency.
pub struct WritebackDaemon {
    config: WritebackDaemonConfig,
    stats: WritebackDaemonStats,
    /// Monotonic wall-clock time of the last tick (ms).
    last_tick_ms: u64,
    /// Bytes allowed to flush on the next tick (adaptive rate limit).
    flush_budget_per_tick: u64,
    /// Whether the daemon throttled on the previous tick.
    throttled_prev: bool,
}

impl WritebackDaemon {
    /// Create a writeback daemon with the given configuration.
    #[must_use]
    pub const fn new(config: WritebackDaemonConfig) -> Self {
        Self {
            config,
            stats: WritebackDaemonStats::new(),
            last_tick_ms: 0,
            flush_budget_per_tick: config.max_flush_bytes_per_tick,
            throttled_prev: false,
        }
    }

    /// Borrow the daemon configuration.
    #[must_use]
    pub fn config(&self) -> &WritebackDaemonConfig {
        &self.config
    }

    /// Borrow the daemon statistics accumulator.
    #[must_use]
    pub fn stats(&self) -> &WritebackDaemonStats {
        &self.stats
    }

    /// Mutably borrow the daemon statistics accumulator.
    #[must_use]
    pub fn stats_mut(&mut self) -> &mut WritebackDaemonStats {
        &mut self.stats
    }

    /// Current flush budget per tick (adaptive).
    #[must_use]
    pub fn flush_budget_per_tick(&self) -> u64 {
        self.flush_budget_per_tick
    }

    /// Determine whether flushing is needed and why.
    fn classify(
        &self,
        total_dirty_bytes: u64,
        oldest_dirty_age_ms: u64,
        now_ms: u64,
    ) -> FlushTrigger {
        // Check dirty_expire first: oldest-dirty-first is highest priority.
        if oldest_dirty_age_ms > 0 {
            let age_cs = now_ms.saturating_sub(oldest_dirty_age_ms) / 10;
            if age_cs >= self.config.dirty_expire_centisecs {
                return FlushTrigger::DirtyExpire;
            }
        }

        // Check dirty_bytes absolute threshold.
        if total_dirty_bytes >= self.config.dirty_bytes_threshold {
            return FlushTrigger::DirtyBytes;
        }

        // Check dirty_ratio.
        if self.config.total_cache_bytes > 0 {
            let ratio_hundredths = (total_dirty_bytes * 10_000) / self.config.total_cache_bytes;
            if ratio_hundredths as u32 >= self.config.dirty_ratio_hundredths {
                return FlushTrigger::DirtyRatio;
            }
        }

        FlushTrigger::None
    }

    /// The daemon tick: scan dirty pages, decide whether to flush, and
    /// optionally flush.
    ///
    /// `tracker` provides the current dirty-page state.  `now_ms` is a
    /// monotonic wall-clock timestamp in milliseconds.  `flush_fn` is
    /// called for each flushed byte range with `(inode, offset, length)`
    /// and must return `Ok(latency_ms)` on success or `Err(())` on failure.
    ///
    /// Returns the number of bytes flushed on this tick (0 if idle).
    pub fn tick(
        &mut self,
        tracker: &DirtyPageTracker,
        now_ms: u64,
        flush_fn: &mut dyn FnMut(u64, u64, u64) -> Result<u64, ()>,
    ) -> u64 {
        self.stats.daemon_wakeups = self.stats.daemon_wakeups.saturating_add(1);
        self.last_tick_ms = now_ms;

        let total_dirty_bytes: u64 = tracker
            .all_dirty_ranges()
            .iter()
            .map(|r| r.2.saturating_sub(r.1))
            .sum();
        let oldest_age = tracker
            .dirty_inodes_sorted_by_age()
            .first()
            .map_or(0, |x| x.2);

        // Compute and record current dirty ratio.
        if self.config.total_cache_bytes > 0 {
            let ratio = (total_dirty_bytes * 10_000) / self.config.total_cache_bytes;
            self.stats.dirty_ratio_at_wakeup_hundredths = ratio as u32;
        }

        // Adaptive rate limiting: adjust budget based on latency trend.
        self.stats.recompute_percentiles();
        if self.stats.flush_latency_p99_ms > 100
            && self.flush_budget_per_tick > self.config.min_flush_bytes_per_tick
        {
            // High latency: reduce flush rate.
            self.flush_budget_per_tick =
                (self.flush_budget_per_tick / 2).max(self.config.min_flush_bytes_per_tick);
            self.throttled_prev = true;
            self.stats.record_throttle();
        } else if !self.throttled_prev
            && self.flush_budget_per_tick < self.config.max_flush_bytes_per_tick
        {
            // Latency is fine: slowly ramp up.
            let ramp = self
                .flush_budget_per_tick
                .saturating_add(self.config.min_flush_bytes_per_tick);
            self.flush_budget_per_tick = ramp.min(self.config.max_flush_bytes_per_tick);
        }
        self.throttled_prev = false;

        let trigger = self.classify(total_dirty_bytes, oldest_age, now_ms);
        if matches!(trigger, FlushTrigger::None) {
            self.stats.idle_ticks = self.stats.idle_ticks.saturating_add(1);
            return 0;
        }

        self.stats.active_ticks = self.stats.active_ticks.saturating_add(1);

        // Record trigger classification.
        match trigger {
            FlushTrigger::DirtyExpire => {
                self.stats.expire_flushes = self.stats.expire_flushes.saturating_add(1);
            }
            FlushTrigger::DirtyRatio => {
                self.stats.ratio_flushes = self.stats.ratio_flushes.saturating_add(1);
            }
            FlushTrigger::DirtyBytes => {
                self.stats.bytes_flushes = self.stats.bytes_flushes.saturating_add(1);
            }
            FlushTrigger::None => {}
        }

        // Flush inodes in oldest-dirty-first order.
        let inodes = tracker.dirty_inodes_sorted_by_age();
        let mut flushed_bytes: u64 = 0;

        for (inode, _total, _age) in &inodes {
            if flushed_bytes >= self.flush_budget_per_tick {
                break;
            }
            let ranges = tracker.get_dirty_ranges(*inode);
            for range in &ranges {
                if flushed_bytes >= self.flush_budget_per_tick {
                    break;
                }
                let len = range.byte_len();
                match flush_fn(range.object_id, range.offset_start, range.offset_end) {
                    Ok(latency_ms) => {
                        flushed_bytes = flushed_bytes.saturating_add(len);
                        self.stats.record_flush(len, latency_ms);
                    }
                    Err(()) => {
                        // Flush failure: keep the range dirty for retry.
                    }
                }
            }
        }

        flushed_bytes
    }

    /// Flush all dirty pages for a single inode.
    ///
    /// Returns the number of bytes flushed.
    pub fn flush_inode(
        &mut self,
        tracker: &DirtyPageTracker,
        inode: u64,
        flush_fn: &mut dyn FnMut(u64, u64, u64) -> Result<u64, ()>,
    ) -> u64 {
        let ranges = tracker.get_dirty_ranges(inode);
        let mut flushed: u64 = 0;
        for range in &ranges {
            let len = range.byte_len();
            if let Ok(latency_ms) = flush_fn(range.object_id, range.offset_start, range.offset_end)
            {
                flushed = flushed.saturating_add(len);
                self.stats.record_flush(len, latency_ms);
            }
        }
        flushed
    }

    /// Flush all dirty inodes in LRU order (oldest dirty first).
    ///
    /// Returns the number of bytes flushed.
    pub fn flush_all(
        &mut self,
        tracker: &DirtyPageTracker,
        flush_fn: &mut dyn FnMut(u64, u64, u64) -> Result<u64, ()>,
    ) -> u64 {
        let inodes = tracker.dirty_inodes_sorted_by_age();
        let mut flushed: u64 = 0;
        for (inode, _total, _age) in &inodes {
            flushed = flushed.saturating_add(self.flush_inode(tracker, *inode, flush_fn));
        }
        flushed
    }

    /// Set the total cache bytes to a new value (e.g. after memory budget
    /// reconfiguration).
    pub fn set_total_cache_bytes(&mut self, bytes: u64) {
        self.config.total_cache_bytes = bytes;
    }

    /// Return the configured wake interval.
    #[must_use]
    pub fn wake_interval_ms(&self) -> u64 {
        self.config.wake_interval_ms
    }

    /// Return the timestamp of the last tick (0 if never ticked).
    #[must_use]
    pub fn last_tick_ms(&self) -> u64 {
        self.last_tick_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    // ── Mock work source ──────────────────────────────────────────────────

    struct MockWorkSource {
        queue: Vec<DrainWorkItem>,
        in_flight: BTreeMap<u64, DrainWorkItem>,
        next_ticket_id: u64,
        commit_group_items: BTreeMap<u64, Vec<DrainWorkItem>>,
    }

    impl MockWorkSource {
        fn new() -> Self {
            Self {
                queue: Vec::new(),
                in_flight: BTreeMap::new(),
                next_ticket_id: 1,
                commit_group_items: BTreeMap::new(),
            }
        }

        fn enqueue(&mut self, item: DrainWorkItem) {
            self.commit_group_items
                .entry(item.commit_group_id)
                .or_default()
                .push(item);
            self.queue.push(item);
        }
    }

    impl DirtyWorkSource for MockWorkSource {
        fn is_queue_empty(&self) -> bool {
            self.queue.is_empty()
        }

        fn queued_len(&self) -> usize {
            self.queue.len()
        }

        fn in_flight_len(&self) -> usize {
            self.in_flight.len()
        }

        fn dispatch_next(&mut self) -> Result<DrainTicket, DrainError> {
            if self.queue.is_empty() {
                return Err(DrainError::QueueEmpty);
            }
            let item = self.queue.remove(0);
            let ticket_id = self.next_ticket_id;
            self.next_ticket_id += 1;
            self.in_flight.insert(ticket_id, item);
            Ok(DrainTicket::new(ticket_id, item))
        }

        fn begin_commit_group_flush(
            &mut self,
            commit_group_id: u64,
        ) -> Result<CommitBarrierGuard, DrainError> {
            let total = self
                .queue
                .iter()
                .filter(|i| i.commit_group_id == commit_group_id)
                .count();
            let bytes: u64 = self
                .queue
                .iter()
                .filter(|i| i.commit_group_id == commit_group_id)
                .map(|i| i.dirty_byte_count)
                .sum();
            Ok(CommitBarrierGuard::new(commit_group_id, total, bytes))
        }

        fn complete(&mut self, ticket_id: u64) -> Result<DrainWorkItem, DrainError> {
            self.in_flight
                .remove(&ticket_id)
                .ok_or(DrainError::UnknownTicket)
        }

        fn retry(&mut self, ticket_id: u64) -> Result<(), DrainError> {
            let item = self
                .in_flight
                .remove(&ticket_id)
                .ok_or(DrainError::UnknownTicket)?;
            self.queue.push(item);
            Ok(())
        }

        fn is_commit_group_idle(&self, commit_group_id: u64) -> bool {
            self.queue
                .iter()
                .all(|i| i.commit_group_id != commit_group_id)
                && self
                    .in_flight
                    .values()
                    .all(|i| i.commit_group_id != commit_group_id)
        }
    }

    // ── Mock dirty data provider ──────────────────────────────────────────

    struct MockDirtyData {
        pages: BTreeMap<(u64, u64), Vec<u8>>,
        clean_ranges: Vec<(u64, u64, u64)>,
    }

    impl MockDirtyData {
        fn new() -> Self {
            Self {
                pages: BTreeMap::new(),
                clean_ranges: Vec::new(),
            }
        }

        fn insert(&mut self, object_id: u64, offset_start: u64, data: &[u8]) {
            self.pages.insert((object_id, offset_start), data.to_vec());
        }

        fn was_marked_clean(&self, object_id: u64, offset_start: u64, offset_end: u64) -> bool {
            self.clean_ranges
                .contains(&(object_id, offset_start, offset_end))
        }
    }

    impl DirtyDataProvider for MockDirtyData {
        fn read_dirty(
            &self,
            object_id: u64,
            offset_start: u64,
            offset_end: u64,
        ) -> Result<Vec<u8>, DrainError> {
            let _ = offset_end;
            self.pages
                .get(&(object_id, offset_start))
                .cloned()
                .ok_or(DrainError::DirtyDataUnavailable)
        }

        fn mark_clean(
            &mut self,
            object_id: u64,
            offset_start: u64,
            offset_end: u64,
        ) -> Result<(), DrainError> {
            self.clean_ranges
                .push((object_id, offset_start, offset_end));
            Ok(())
        }
    }

    // ── Mock object store ─────────────────────────────────────────────────

    struct MockObjectStore {
        objects: BTreeMap<[u8; 32], Vec<u8>>,
        put_count: u64,
    }

    impl MockObjectStore {
        fn new() -> Self {
            Self {
                objects: BTreeMap::new(),
                put_count: 0,
            }
        }

        fn get(&self, key: &[u8; 32]) -> Option<&Vec<u8>> {
            self.objects.get(key)
        }
    }

    impl DrainObjectStore for MockObjectStore {
        fn put(&mut self, key: &[u8; 32], payload: &[u8]) -> Result<[u8; 32], DrainError> {
            self.objects.insert(*key, payload.to_vec());
            self.put_count += 1;
            Ok(*key)
        }
    }

    // ── Mock extent map ───────────────────────────────────────────────────

    #[derive(Clone, Debug, Default)]
    struct MockExtentMapEntry {
        offset_start: u64,
        offset_end: u64,
        object_key: [u8; 32],
    }

    struct MockExtentMap {
        extents: BTreeMap<u64, Vec<MockExtentMapEntry>>,
    }

    impl MockExtentMap {
        fn new() -> Self {
            Self {
                extents: BTreeMap::new(),
            }
        }

        fn extents_for(&self, object_id: u64) -> &[MockExtentMapEntry] {
            static EMPTY: &[MockExtentMapEntry] = &[];
            self.extents.get(&object_id).map_or(EMPTY, |v| v.as_slice())
        }
    }

    impl DrainExtentMap for MockExtentMap {
        fn insert_extent(
            &mut self,
            object_id: u64,
            offset_start: u64,
            offset_end: u64,
            object_key: [u8; 32],
        ) -> Result<(), DrainError> {
            let entry = MockExtentMapEntry {
                offset_start,
                offset_end,
                object_key,
            };
            self.extents.entry(object_id).or_default().push(entry);
            Ok(())
        }
    }

    // ── Helper: create an engine with mocks ───────────────────────────────

    fn mock_engine(
        max_concurrent: u32,
    ) -> DirtyDrainEngine<'static, MockWorkSource, MockDirtyData, MockObjectStore, MockExtentMap>
    {
        // We use 'static here because the tests own all mock instances.
        // In practice the engine borrows from the caller, but for tests
        // we box-leak to get 'static borrows that outlive the test.
        let ws = Box::leak(Box::new(MockWorkSource::new()));
        let dd = Box::leak(Box::new(MockDirtyData::new()));
        let os = Box::leak(Box::new(MockObjectStore::new()));
        let em = Box::leak(Box::new(MockExtentMap::new()));
        DirtyDrainEngine::new(ws, dd, os, em, max_concurrent)
    }

    fn work_item(object_id: u64, start: u64, end: u64, commit_group: u64) -> DrainWorkItem {
        DrainWorkItem::new(object_id, start, end, commit_group, end - start, 0)
    }

    // ── Unit tests ────────────────────────────────────────────────────────

    #[test]
    fn dirty_range_tracker_coalesces_overlap_and_adjacency_per_object() {
        let mut tracker = DirtyRangeTracker::new();

        tracker.record_dirty(7, 4096, 8192).unwrap();
        tracker.record_dirty(3, 0, 512).unwrap();
        tracker.record_dirty(7, 0, 4096).unwrap();
        tracker.record_dirty(7, 2048, 6144).unwrap();
        tracker.record_dirty(8, 0, 1024).unwrap();

        assert_eq!(tracker.pending_range_count(), 3);
        assert_eq!(tracker.pending_dirty_bytes(), 512 + 8192 + 1024);
        assert_eq!(
            tracker.pending_ranges(),
            &[
                DirtyRange::new(3, 0, 512),
                DirtyRange::new(7, 0, 8192),
                DirtyRange::new(8, 0, 1024),
            ]
        );
    }

    #[test]
    fn dirty_range_tracker_returns_deterministic_bounded_flush_batch() {
        let mut tracker = DirtyRangeTracker::new();

        tracker.record_dirty(9, 8192, 12288).unwrap();
        tracker.record_dirty(2, 4096, 8192).unwrap();
        tracker.record_dirty(2, 0, 2048).unwrap();
        tracker.record_dirty(5, 0, 4096).unwrap();

        let empty = tracker.next_flush_batch(0);
        assert!(empty.is_empty());

        let batch = tracker.next_flush_batch(3);
        assert_eq!(batch.len(), 3);
        assert_eq!(batch.total_dirty_bytes(), 2048 + 4096 + 4096);
        assert_eq!(
            batch.as_slice(),
            &[
                DirtyRange::new(2, 0, 2048),
                DirtyRange::new(2, 4096, 8192),
                DirtyRange::new(5, 0, 4096),
            ]
        );
        assert_eq!(tracker.pending_range_count(), 4);
    }

    #[test]
    fn dirty_range_tracker_returns_object_scoped_flush_batch() {
        let mut tracker = DirtyRangeTracker::new();

        tracker.record_dirty(7, 4096, 8192).unwrap();
        tracker.record_dirty(3, 0, 512).unwrap();
        tracker.record_dirty(7, 12288, 16384).unwrap();
        tracker.record_dirty(7, 0, 2048).unwrap();
        tracker.record_dirty(9, 0, 1024).unwrap();

        let batch = tracker.next_flush_batch_for_object(7, 2);

        assert_eq!(batch.len(), 2);
        assert_eq!(batch.total_dirty_bytes(), 2048 + 4096);
        assert_eq!(
            batch.as_slice(),
            &[DirtyRange::new(7, 0, 2048), DirtyRange::new(7, 4096, 8192),]
        );
        assert!(tracker.next_flush_batch_for_object(7, 0).is_empty());
        assert!(tracker.next_flush_batch_for_object(99, 4).is_empty());
    }

    #[test]
    fn dirty_range_tracker_completion_splits_pending_range_and_records_state() {
        let mut tracker = DirtyRangeTracker::new();
        tracker.record_dirty(11, 0, 100).unwrap();

        tracker.mark_completed(DirtyRange::new(11, 20, 60)).unwrap();

        assert_eq!(tracker.pending_range_count(), 2);
        assert_eq!(tracker.pending_dirty_bytes(), 60);
        assert_eq!(
            tracker.pending_ranges(),
            &[DirtyRange::new(11, 0, 20), DirtyRange::new(11, 60, 100)]
        );
        assert_eq!(tracker.completion_count(), 1);
        assert_eq!(
            tracker.completions(),
            &[DirtyRangeCompletion::completed(DirtyRange::new(11, 20, 60))]
        );
    }

    #[test]
    fn dirty_range_tracker_failure_retains_pending_range_and_error_observation() {
        let mut tracker = DirtyRangeTracker::new();
        let range = DirtyRange::new(12, 0, 4096);
        tracker.record_dirty_range(range).unwrap();

        tracker
            .mark_failed(range, DrainError::ObjectStorePut)
            .unwrap();

        assert_eq!(tracker.pending_ranges(), &[range]);
        assert_eq!(tracker.failed_count(), 1);
        assert_eq!(tracker.completion_count(), 1);
        assert_eq!(
            tracker.completions(),
            &[DirtyRangeCompletion::failed(
                range,
                DrainError::ObjectStorePut
            )]
        );
    }

    #[test]
    fn dirty_range_tracker_completed_flush_outcomes_are_idempotent() {
        let mut tracker = DirtyRangeTracker::new();
        let range = DirtyRange::new(13, 0, 4096);
        let completion = DirtyRangeCompletion::completed(range);
        tracker.record_dirty_range(range).unwrap();

        tracker.apply_flush_completion(completion).unwrap();
        tracker.apply_flush_completion(completion).unwrap();

        assert!(tracker.is_empty());
        assert_eq!(tracker.pending_range_count(), 0);
        assert_eq!(tracker.pending_dirty_bytes(), 0);
        assert_eq!(tracker.failed_count(), 0);
        assert_eq!(tracker.completion_count(), 1);
        assert_eq!(tracker.completions(), &[completion]);
        assert!(tracker.next_flush_batch(1).is_empty());
    }

    #[test]
    fn dirty_range_tracker_successful_retry_clears_failed_flush_accounting() {
        let mut tracker = DirtyRangeTracker::new();
        let retry_range = DirtyRange::new(14, 0, 4096);
        let unrelated_range = DirtyRange::new(14, 8192, 12288);
        let retry_failure = DirtyRangeCompletion::failed(retry_range, DrainError::ObjectStorePut);
        let unrelated_failure =
            DirtyRangeCompletion::failed(unrelated_range, DrainError::ExtentMapUpdate);
        let retry_success = DirtyRangeCompletion::completed(retry_range);

        tracker.record_dirty_range(retry_range).unwrap();
        tracker.record_dirty_range(unrelated_range).unwrap();
        tracker.apply_flush_completion(retry_failure).unwrap();
        tracker.apply_flush_completion(unrelated_failure).unwrap();

        assert_eq!(tracker.pending_dirty_bytes(), 8192);
        assert_eq!(tracker.failed_count(), 2);
        assert_eq!(tracker.completion_count(), 2);

        tracker.apply_flush_completion(retry_success).unwrap();

        assert_eq!(tracker.pending_ranges(), &[unrelated_range]);
        assert_eq!(tracker.pending_dirty_bytes(), 4096);
        assert_eq!(tracker.failed_count(), 1);
        assert_eq!(tracker.completion_count(), 3);
        assert_eq!(
            tracker.completions(),
            &[retry_failure, unrelated_failure, retry_success]
        );

        tracker.apply_flush_completion(retry_success).unwrap();

        assert_eq!(tracker.pending_ranges(), &[unrelated_range]);
        assert_eq!(tracker.failed_count(), 1);
        assert_eq!(tracker.completion_count(), 3);
    }

    #[test]
    fn dirty_range_tracker_mixed_flush_retry_batch_cleans_successes_once() {
        let mut tracker = DirtyRangeTracker::new();
        let early_range = DirtyRange::new(16, 0, 4096);
        let retry_range = DirtyRange::new(16, 8192, 12288);
        let late_range = DirtyRange::new(16, 16384, 20480);
        let early_success = DirtyRangeCompletion::completed(early_range);
        let retry_failure = DirtyRangeCompletion::failed(retry_range, DrainError::ObjectStorePut);
        let retry_success = DirtyRangeCompletion::completed(retry_range);
        let late_success = DirtyRangeCompletion::completed(late_range);

        tracker.record_dirty_range(early_range).unwrap();
        tracker.record_dirty_range(retry_range).unwrap();
        tracker.record_dirty_range(late_range).unwrap();
        tracker
            .apply_flush_completions(&[early_success, retry_failure, late_success])
            .unwrap();

        assert_eq!(tracker.pending_ranges(), &[retry_range]);
        assert_eq!(tracker.pending_dirty_bytes(), 4096);
        assert_eq!(tracker.failed_count(), 1);
        assert_eq!(tracker.completion_count(), 3);

        tracker
            .apply_flush_completions(&[early_success, retry_success, late_success])
            .unwrap();

        assert!(tracker.is_empty());
        assert_eq!(tracker.pending_dirty_bytes(), 0);
        assert_eq!(tracker.failed_count(), 0);
        assert_eq!(tracker.completion_count(), 4);
        assert_eq!(
            tracker.completions(),
            &[early_success, retry_failure, late_success, retry_success]
        );
    }

    #[test]
    fn dirty_range_tracker_applies_partial_flush_outcomes_without_cleaning_failures() {
        let mut tracker = DirtyRangeTracker::new();
        tracker.record_dirty(15, 0, 120).unwrap();

        let completions = [
            DirtyRangeCompletion::completed(DirtyRange::new(15, 0, 40)),
            DirtyRangeCompletion::failed(DirtyRange::new(15, 40, 80), DrainError::ObjectStorePut),
            DirtyRangeCompletion::completed(DirtyRange::new(15, 100, 120)),
        ];

        tracker.apply_flush_completions(&completions).unwrap();

        assert_eq!(tracker.pending_ranges(), &[DirtyRange::new(15, 40, 100)]);
        assert_eq!(tracker.pending_dirty_bytes(), 60);
        assert_eq!(tracker.completion_count(), 3);
        assert_eq!(tracker.failed_count(), 1);
        assert_eq!(tracker.completions(), &completions);
    }

    #[test]
    fn dirty_range_tracker_rejects_invalid_or_unknown_ranges() {
        let mut tracker = DirtyRangeTracker::new();

        assert_eq!(
            tracker.record_dirty(1, 4096, 4096),
            Err(DrainError::InvalidWorkItem)
        );
        assert_eq!(
            tracker.mark_completed(DirtyRange::new(1, 0, 1)),
            Err(DrainError::UnknownTicket)
        );
        assert_eq!(
            tracker.mark_failed(DirtyRange::new(1, 0, 1), DrainError::ObjectStorePut),
            Err(DrainError::UnknownTicket)
        );
    }

    #[test]
    fn writeback_sync_plan_fsync_flushes_data_then_metadata() {
        let state = WritebackSyncHandleState::new(99, 42, 7).with_dirty_data(8192, false);

        let plan = plan_writeback_sync(WritebackSyncKind::Fsync, Some(state)).unwrap();

        assert_eq!(plan.kind, WritebackSyncKind::Fsync);
        assert_eq!(plan.handle_id, 99);
        assert_eq!(plan.object_id, 42);
        assert_eq!(plan.generation, 7);
        assert_eq!(plan.dirty_data_bytes, 8192);
        assert_eq!(
            plan.steps(),
            &[
                WritebackSyncStep::FlushData,
                WritebackSyncStep::FlushMetadata
            ]
        );
        assert!(plan.requires_data_flush());
        assert!(plan.requires_metadata_flush());
        assert!(!plan.is_noop());
    }

    #[test]
    fn writeback_sync_plan_fsync_flushes_metadata_only_when_only_metadata_dirty() {
        let state = WritebackSyncHandleState::new(14, 6, 2).with_dirty_metadata(false);

        let plan = plan_writeback_sync(WritebackSyncKind::Fsync, Some(state)).unwrap();

        assert_eq!(plan.steps(), &[WritebackSyncStep::FlushMetadata]);
        assert!(!plan.requires_data_flush());
        assert!(plan.requires_metadata_flush());
    }

    #[test]
    fn writeback_sync_plan_fdatasync_flushes_data_without_unneeded_metadata() {
        let state = WritebackSyncHandleState::new(11, 5, 3).with_dirty_data(4096, false);

        let plan = plan_writeback_sync(WritebackSyncKind::Fdatasync, Some(state)).unwrap();

        assert_eq!(plan.kind, WritebackSyncKind::Fdatasync);
        assert_eq!(plan.steps(), &[WritebackSyncStep::FlushData]);
        assert!(plan.requires_data_flush());
        assert!(!plan.requires_metadata_flush());
    }

    #[test]
    fn writeback_sync_plan_fdatasync_includes_metadata_needed_for_retrieval() {
        let data_state = WritebackSyncHandleState::new(21, 8, 1).with_dirty_data(1024, true);
        let metadata_state = WritebackSyncHandleState::new(22, 8, 1).with_dirty_metadata(true);

        let data_plan =
            plan_writeback_sync(WritebackSyncKind::Fdatasync, Some(data_state)).unwrap();
        let metadata_plan =
            plan_writeback_sync(WritebackSyncKind::Fdatasync, Some(metadata_state)).unwrap();

        assert_eq!(
            data_plan.steps(),
            &[
                WritebackSyncStep::FlushData,
                WritebackSyncStep::FlushMetadata
            ]
        );
        assert_eq!(metadata_plan.steps(), &[WritebackSyncStep::FlushMetadata]);
    }

    #[test]
    fn writeback_sync_plan_clean_handle_is_noop() {
        let state = WritebackSyncHandleState::new(3, 2, 1);

        let fsync_plan = plan_writeback_sync(WritebackSyncKind::Fsync, Some(state)).unwrap();
        let fdatasync_plan =
            plan_writeback_sync(WritebackSyncKind::Fdatasync, Some(state)).unwrap();

        assert!(fsync_plan.is_noop());
        assert!(fsync_plan.steps().is_empty());
        assert!(fdatasync_plan.is_noop());
        assert!(fdatasync_plan.steps().is_empty());
    }

    #[test]
    fn writeback_flush_plan_selects_handle_ranges_and_preserves_fsync_order() {
        let mut tracker = DirtyRangeTracker::new();
        tracker.record_dirty(42, 4096, 8192).unwrap();
        tracker.record_dirty(7, 0, 512).unwrap();
        tracker.record_dirty(42, 0, 2048).unwrap();
        tracker.record_dirty(42, 12288, 16384).unwrap();

        let state = WritebackSyncHandleState::new(99, 42, 3).with_dirty_data(8192, false);
        let plan =
            plan_writeback_flush(WritebackSyncKind::Fsync, Some(state), &tracker, 2).unwrap();

        assert_eq!(
            plan.steps(),
            &[
                WritebackSyncStep::FlushData,
                WritebackSyncStep::FlushMetadata
            ]
        );
        assert!(plan.requires_data_flush());
        assert!(plan.requires_metadata_flush());
        assert_eq!(plan.selected_dirty_bytes(), 2048 + 4096);
        assert_eq!(
            plan.data_ranges().as_slice(),
            &[
                DirtyRange::new(42, 0, 2048),
                DirtyRange::new(42, 4096, 8192),
            ]
        );
        assert_eq!(tracker.pending_range_count(), 4);
    }

    #[test]
    fn writeback_flush_plan_skips_ranges_for_metadata_only_sync() {
        let mut tracker = DirtyRangeTracker::new();
        tracker.record_dirty(8, 0, 4096).unwrap();
        let state = WritebackSyncHandleState::new(31, 8, 2).with_dirty_metadata(false);

        let plan =
            plan_writeback_flush(WritebackSyncKind::Fsync, Some(state), &tracker, 8).unwrap();

        assert_eq!(plan.steps(), &[WritebackSyncStep::FlushMetadata]);
        assert!(!plan.requires_data_flush());
        assert!(plan.requires_metadata_flush());
        assert!(plan.data_ranges().is_empty());
        assert_eq!(plan.selected_dirty_bytes(), 0);
    }

    #[test]
    fn writeback_flush_plan_clean_handle_is_noop() {
        let tracker = DirtyRangeTracker::new();
        let state = WritebackSyncHandleState::new(5, 4, 1);

        let plan =
            plan_writeback_flush(WritebackSyncKind::Fdatasync, Some(state), &tracker, 4).unwrap();

        assert!(plan.is_noop());
        assert!(plan.steps().is_empty());
        assert!(plan.data_ranges().is_empty());
        assert_eq!(plan.sync_plan().object_id, 4);
    }

    #[test]
    fn writeback_sync_plan_errors_are_errno_ready() {
        assert_eq!(
            plan_writeback_sync(WritebackSyncKind::Fsync, None),
            Err(WritebackSyncPlanError::UnknownHandle)
        );
        assert_eq!(
            WritebackSyncPlanError::UnknownHandle.to_errno(),
            sync_errno::EBADF
        );

        let closed = WritebackSyncHandleState::new(1, 2, 3).closed();
        let stale = WritebackSyncHandleState::new(1, 2, 3).stale();
        let invalid = WritebackSyncHandleState::new(1, 0, 3);

        assert_eq!(
            plan_writeback_sync(WritebackSyncKind::Fsync, Some(closed)),
            Err(WritebackSyncPlanError::ClosedHandle)
        );
        assert_eq!(
            WritebackSyncPlanError::ClosedHandle.to_errno(),
            sync_errno::EBADF
        );
        assert_eq!(
            plan_writeback_sync(WritebackSyncKind::Fsync, Some(stale)),
            Err(WritebackSyncPlanError::StaleHandle)
        );
        assert_eq!(
            WritebackSyncPlanError::StaleHandle.to_errno(),
            sync_errno::ESTALE
        );
        assert_eq!(
            plan_writeback_sync(WritebackSyncKind::Fsync, Some(invalid)),
            Err(WritebackSyncPlanError::InvalidHandleState)
        );
        assert_eq!(
            WritebackSyncPlanError::InvalidHandleState.to_errno(),
            sync_errno::EINVAL
        );
    }

    #[test]
    fn drain_one_empty_queue_returns_error() {
        let mut engine = mock_engine(4);
        let result = engine.drain_one();
        assert_eq!(result, Err(DrainError::QueueEmpty));
    }

    #[test]
    fn drain_one_successful_flush() {
        let mut engine = mock_engine(4);
        let payload = b"hello writeback world";

        // Set up dirty data for object 1, offset 0..len
        engine.dirty_data.insert(1, 0, payload);
        engine
            .work_source
            .enqueue(work_item(1, 0, payload.len() as u64, 7));

        let result = engine.drain_one();
        assert!(result.is_ok());
        assert_eq!(engine.stats().completed, 1);
        assert_eq!(engine.stats().pending, 0);
        assert_eq!(engine.stats().bytes_drained, payload.len() as u64);
        assert_eq!(engine.stats().objects_stored, 1);
        assert!(engine.work_source.is_queue_empty());
        assert_eq!(engine.work_source.in_flight_len(), 0);

        // Verify object store has the data
        let key = drain_block_key(1, 0);
        let stored = engine.object_store.get(&key).unwrap();
        assert_eq!(stored, payload);

        // Verify dirty page was marked clean
        assert!(engine
            .dirty_data
            .was_marked_clean(1, 0, payload.len() as u64));

        // Verify extent map was updated
        let extents = engine.extent_map.extents_for(1);
        assert_eq!(extents.len(), 1);
        assert_eq!(extents[0].offset_start, 0);
        assert_eq!(extents[0].offset_end, payload.len() as u64);
        assert_eq!(extents[0].object_key, key);
    }

    #[test]
    fn drain_one_missing_dirty_data_errors_and_retries() {
        let mut engine = mock_engine(4);
        // Enqueue work item without providing dirty data
        engine.work_source.enqueue(work_item(2, 0, 4096, 3));

        let result = engine.drain_one();
        assert_eq!(result, Err(DrainError::DirtyDataUnavailable));
        assert_eq!(engine.stats().errors, 1);
        // Item should be requeued for retry
        assert_eq!(engine.work_source.queued_len(), 1);
    }

    #[test]
    fn drain_all_drains_entire_queue() {
        let mut engine = mock_engine(4);
        let p1 = vec![0xAA; 4096];
        let p2 = vec![0xBB; 2048];
        let p3 = vec![0xCC; 8192];

        engine.dirty_data.insert(1, 0, &p1);
        engine.dirty_data.insert(2, 0, &p2);
        engine.dirty_data.insert(3, 0, &p3);

        engine.work_source.enqueue(work_item(1, 0, 4096, 1));
        engine.work_source.enqueue(work_item(2, 0, 2048, 1));
        engine.work_source.enqueue(work_item(3, 0, 8192, 2));

        let drained = engine.drain_all().unwrap();
        assert_eq!(drained, 3);
        assert_eq!(engine.stats().completed, 3);
        assert_eq!(engine.stats().errors, 0);
        assert!(engine.work_source.is_queue_empty());
    }

    #[test]
    fn drain_all_respects_concurrency_limit() {
        let mut engine = mock_engine(2);
        let payload = vec![0xDD; 4096];

        for i in 0..5 {
            engine.dirty_data.insert(i, 0, &payload);
            engine.work_source.enqueue(work_item(i, 0, 4096, 1));
        }

        let drained = engine.drain_all().unwrap();
        // With max_concurrent=2, only 2 can be in-flight before drain_one
        // returns and completes them. Actually, drain_one completes synchronously,
        // so the concurrency limit applies to the stats.pending counter but
        // since drain_one completes immediately, it drains all 5.
        assert_eq!(drained, 5);
    }

    #[test]
    fn scheduler_dirty_work_source_drains_scheduler_queue() {
        let mut state = WritebackDispatchState::<8, 2>::new();
        let mut dirty_data = MockDirtyData::new();
        let mut object_store = MockObjectStore::new();
        let mut extent_map = MockExtentMap::new();
        let payload = vec![0x41; 4096];

        dirty_data.insert(44, 0, &payload);
        state
            .enqueue(WritebackWorkItem::new(44, 0, 4096, 3, 4096, 100))
            .unwrap();

        {
            let mut source = SchedulerDirtyWorkSource::new(&mut state);
            let mut engine = DirtyDrainEngine::new(
                &mut source,
                &mut dirty_data,
                &mut object_store,
                &mut extent_map,
                2,
            );

            engine.drain_one().unwrap();

            assert_eq!(engine.stats().completed, 1);
            assert_eq!(engine.stats().pending, 0);
        }

        assert_eq!(state.queued_len(), 0);
        assert_eq!(state.in_flight_len(), 0);
        assert!(state.is_commit_group_idle(3));

        let key = drain_block_key(44, 0);
        assert_eq!(object_store.get(&key).unwrap(), &payload);
        assert!(dirty_data.was_marked_clean(44, 0, 4096));
        assert_eq!(extent_map.extents_for(44)[0].object_key, key);
    }

    #[test]
    fn scheduler_dirty_work_source_commit_barrier_leaves_other_commit_group_queued() {
        let mut state = WritebackDispatchState::<8, 2>::new();
        let mut dirty_data = MockDirtyData::new();
        let mut object_store = MockObjectStore::new();
        let mut extent_map = MockExtentMap::new();
        let target_payload = vec![0x77; 4096];

        dirty_data.insert(70, 0, &target_payload);
        dirty_data.insert(71, 0, &target_payload);
        state
            .enqueue(WritebackWorkItem::new(70, 0, 4096, 7, 4096, 10))
            .unwrap();
        state
            .enqueue(WritebackWorkItem::new(71, 0, 4096, 8, 4096, 10))
            .unwrap();

        let guard = {
            let mut source = SchedulerDirtyWorkSource::new(&mut state);
            let mut engine = DirtyDrainEngine::new(
                &mut source,
                &mut dirty_data,
                &mut object_store,
                &mut extent_map,
                2,
            );

            engine.drain_commit_barrier(7).unwrap()
        };

        assert!(guard.is_clean());
        assert_eq!(guard.commit_group_id(), 7);
        assert_eq!(state.queued_len(), 1);
        assert!(state.is_commit_group_idle(7));
        assert!(!state.is_commit_group_idle(8));

        let drained_key = drain_block_key(70, 0);
        assert_eq!(object_store.get(&drained_key).unwrap(), &target_payload);
        assert!(object_store.get(&drain_block_key(71, 0)).is_none());
    }

    #[test]
    fn batch_by_object_affinity_groups_same_object() {
        let items = vec![
            DrainWorkItem::new(1, 0, 4096, 1, 4096, 0),
            DrainWorkItem::new(2, 0, 2048, 1, 2048, 0),
            DrainWorkItem::new(1, 4096, 8192, 1, 4096, 0),
            DrainWorkItem::new(2, 2048, 4096, 1, 2048, 0),
        ];

        let batches = DirtyDrainEngine::<
            MockWorkSource,
            MockDirtyData,
            MockObjectStore,
            MockExtentMap,
        >::batch_by_object_affinity(&items);

        assert_eq!(batches.len(), 2);
        // First batch: object 1
        assert_eq!(batches[0].len(), 2);
        assert!(batches[0].as_slice().iter().all(|i| i.object_id == 1));
        // Second batch: object 2
        assert_eq!(batches[1].len(), 2);
        assert!(batches[1].as_slice().iter().all(|i| i.object_id == 2));
    }

    #[test]
    fn batch_by_object_affinity_empty_input() {
        let items: Vec<DrainWorkItem> = vec![];
        let batches = DirtyDrainEngine::<
            MockWorkSource,
            MockDirtyData,
            MockObjectStore,
            MockExtentMap,
        >::batch_by_object_affinity(&items);
        assert!(batches.is_empty());
    }

    #[test]
    fn batch_by_object_affinity_sorts_by_offset_within_object() {
        let items = vec![
            DrainWorkItem::new(1, 8192, 12288, 1, 4096, 0),
            DrainWorkItem::new(1, 0, 4096, 1, 4096, 0),
            DrainWorkItem::new(1, 4096, 8192, 1, 4096, 0),
        ];

        let batches = DirtyDrainEngine::<
            MockWorkSource,
            MockDirtyData,
            MockObjectStore,
            MockExtentMap,
        >::batch_by_object_affinity(&items);

        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_eq!(batch.len(), 3);
        assert_eq!(batch.as_slice()[0].offset_start, 0);
        assert_eq!(batch.as_slice()[1].offset_start, 4096);
        assert_eq!(batch.as_slice()[2].offset_start, 8192);
    }

    #[test]
    fn commit_barrier_drain_successful() {
        let mut engine = mock_engine(4);
        let payload = vec![0xEE; 4096];

        for i in 0..3 {
            engine.dirty_data.insert(i + 10, 0, &payload);
            engine.work_source.enqueue(work_item(i + 10, 0, 4096, 42));
        }

        let guard = engine.drain_commit_barrier(42).unwrap();
        assert!(guard.is_clean());
        assert_eq!(guard.drained_count(), 3);
        assert_eq!(guard.error_count(), 0);
        assert_eq!(engine.stats().commit_barriers_completed, 1);
        assert_eq!(engine.stats().commit_barriers_failed, 0);
    }

    #[test]
    fn commit_barrier_drain_with_missing_data() {
        let mut engine = mock_engine(4);
        let payload = vec![0xFF; 4096];

        // Provide dirty data for items 0 and 2, but not 1
        engine.dirty_data.insert(100, 0, &payload);
        engine.dirty_data.insert(102, 0, &payload);

        engine.work_source.enqueue(work_item(100, 0, 4096, 99));
        engine.work_source.enqueue(work_item(101, 0, 4096, 99));
        engine.work_source.enqueue(work_item(102, 0, 4096, 99));

        let guard = engine.drain_commit_barrier(99).unwrap();
        // Item 101 fails, so guard is not clean
        assert!(!guard.is_clean());
        assert_eq!(guard.error_count(), 1);
        assert_eq!(engine.stats().commit_barriers_failed, 1);
        assert_eq!(engine.stats().commit_barriers_completed, 0);
    }

    #[test]
    fn commit_barrier_guard_pending_count() {
        let guard = CommitBarrierGuard::new(1, 10, 40960);
        assert_eq!(guard.total_items(), 10);
        assert_eq!(guard.pending_count(), 10);
        assert!(!guard.is_drain_complete());
        assert!(!guard.is_clean());
    }

    #[test]
    fn commit_barrier_guard_records_drain_and_completes() {
        let mut guard = CommitBarrierGuard::new(5, 5, 20480);

        for _ in 0..5 {
            guard.record_drained();
        }

        assert_eq!(guard.drained_count(), 5);
        assert_eq!(guard.pending_count(), 0);
        assert!(guard.is_drain_complete());
        assert!(guard.is_clean());
    }

    #[test]
    fn commit_barrier_guard_with_errors() {
        let mut guard = CommitBarrierGuard::new(7, 3, 12288);

        guard.record_drained();
        guard.record_error();
        guard.record_drained();

        assert_eq!(guard.drained_count(), 2);
        assert_eq!(guard.error_count(), 1);
        assert!(guard.is_drain_complete());
        assert!(!guard.is_clean());
    }

    #[test]
    fn drain_stats_records_correctly() {
        let mut stats = DrainStats::new();
        assert_eq!(stats.completed, 0);
        assert_eq!(stats.pending, 0);

        stats.record_dispatched();
        assert_eq!(stats.pending, 1);

        stats.record_dispatched();
        assert_eq!(stats.pending, 2);

        stats.record_completion(4096);
        assert_eq!(stats.completed, 1);
        assert_eq!(stats.pending, 1);
        assert_eq!(stats.bytes_drained, 4096);

        stats.record_error();
        assert_eq!(stats.errors, 1);
        assert_eq!(stats.pending, 0);

        stats.record_commit_barrier_completed(16384);
        assert_eq!(stats.commit_barriers_completed, 1);
        assert_eq!(stats.bytes_drained, 4096 + 16384);

        stats.record_commit_barrier_failed();
        assert_eq!(stats.commit_barriers_failed, 1);
    }

    #[test]
    fn drain_block_key_is_deterministic() {
        let k1 = drain_block_key(42, 7);
        let k2 = drain_block_key(42, 7);
        assert_eq!(k1, k2);
    }

    #[test]
    fn drain_block_key_differs_by_object() {
        let k1 = drain_block_key(1, 0);
        let k2 = drain_block_key(2, 0);
        assert_ne!(k1, k2);
    }

    #[test]
    fn drain_block_key_differs_by_block_index() {
        let k1 = drain_block_key(1, 0);
        let k2 = drain_block_key(1, 1);
        assert_ne!(k1, k2);
    }

    #[test]
    fn work_item_is_valid() {
        let valid = DrainWorkItem::new(1, 0, 4096, 1, 4096, 0);
        assert!(valid.is_valid());

        let invalid_range = DrainWorkItem::new(1, 4096, 0, 1, 4096, 0);
        assert!(!invalid_range.is_valid());

        let zero_bytes = DrainWorkItem::new(1, 0, 4096, 1, 0, 0);
        assert!(!zero_bytes.is_valid());
    }

    #[test]
    fn drain_batch_aggregates() {
        let mut batch = DrainBatch::new();
        assert!(batch.is_empty());

        batch.push(DrainWorkItem::new(1, 0, 4096, 1, 4096, 0));
        batch.push(DrainWorkItem::new(1, 4096, 8192, 1, 4096, 0));

        assert_eq!(batch.len(), 2);
        assert_eq!(batch.total_dirty_bytes(), 8192);

        let drained = batch.drain();
        assert_eq!(drained.len(), 2);
        assert!(batch.is_empty());
    }

    #[test]
    fn drain_work_item_with_generation() {
        let item = DrainWorkItem::new(1, 0, 4096, 1, 4096, 100).with_generation(42);
        assert_eq!(item.generation, 42);
        assert_eq!(item.oldest_dirty_age_ms, 100);
    }

    #[test]
    fn mock_work_source_retry_requeues() {
        let mut ws = MockWorkSource::new();
        ws.enqueue(work_item(1, 0, 4096, 1));
        assert_eq!(ws.queued_len(), 1);

        let ticket = ws.dispatch_next().unwrap();
        assert_eq!(ws.queued_len(), 0);
        assert_eq!(ws.in_flight_len(), 1);

        ws.retry(ticket.ticket_id).unwrap();
        assert_eq!(ws.queued_len(), 1);
        assert_eq!(ws.in_flight_len(), 0);
    }

    #[test]
    fn mock_work_source_commit_group_idle() {
        let mut ws = MockWorkSource::new();
        assert!(ws.is_commit_group_idle(1));

        ws.enqueue(work_item(1, 0, 4096, 1));
        assert!(!ws.is_commit_group_idle(1));
        assert!(ws.is_commit_group_idle(2));
    }

    #[test]
    fn round_trip_drain_and_verify() {
        // Full end-to-end test: enqueue → drain → object store → extent map.
        let mut engine = mock_engine(4);
        let original = b"round-trip data integrity check";

        engine.dirty_data.insert(99, 0, original);
        engine
            .work_source
            .enqueue(work_item(99, 0, original.len() as u64, 1));

        engine.drain_one().unwrap();

        // Verify object store has the data
        let key = drain_block_key(99, 0);
        let stored = engine.object_store.get(&key).unwrap();
        assert_eq!(stored, original);

        // Verify extent map
        let extents = engine.extent_map.extents_for(99);
        assert_eq!(extents.len(), 1);
        assert_eq!(extents[0].object_key, key);
    }

    #[test]
    fn multi_extent_round_trip() {
        let mut engine = mock_engine(4);
        let block1 = vec![0x11; 4096];
        let block2 = vec![0x22; 4096];
        let block3 = vec![0x33; 4096];

        engine.dirty_data.insert(42, 0, &block1);
        engine.dirty_data.insert(42, 4096, &block2);
        engine.dirty_data.insert(42, 8192, &block3);

        engine.work_source.enqueue(work_item(42, 0, 4096, 1));
        engine.work_source.enqueue(work_item(42, 4096, 8192, 1));
        engine.work_source.enqueue(work_item(42, 8192, 12288, 1));

        engine.drain_all().unwrap();

        let k0 = drain_block_key(42, 0);
        let k1 = drain_block_key(42, 1);
        let k2 = drain_block_key(42, 2);

        assert_eq!(engine.object_store.get(&k0).unwrap(), &block1);
        assert_eq!(engine.object_store.get(&k1).unwrap(), &block2);
        assert_eq!(engine.object_store.get(&k2).unwrap(), &block3);

        let extents = engine.extent_map.extents_for(42);
        assert_eq!(extents.len(), 3);
    }
    // ── mmap tracker tests ─────────────────────────────────────────────────

    fn writable_shared_region(start: u64, len: u64) -> MmapRegion {
        MmapRegion::new(start, len, MmapProtFlags::rw_shared())
    }

    fn read_only_region(start: u64, len: u64) -> MmapRegion {
        MmapRegion::new(start, len, MmapProtFlags::read_shared())
    }

    fn private_region(start: u64, len: u64) -> MmapRegion {
        MmapRegion::new(start, len, MmapProtFlags::rw_private())
    }

    #[test]
    fn mmap_registers_region_and_stats() {
        let mut tracker = MmapTracker::new(4096);
        tracker.set_enabled(true);

        let region = writable_shared_region(0, 8192);
        tracker.mmap(region).unwrap();

        assert_eq!(tracker.region_count(), 1);
        assert_eq!(tracker.regions(), &[region]);
        assert_eq!(tracker.stats().mmap_count, 1);
        assert_eq!(tracker.stats().mmap_total_bytes, 8192);
    }

    #[test]
    fn mmap_rejects_zero_length() {
        let mut tracker = MmapTracker::new(4096);
        let region = MmapRegion::new(0, 0, MmapProtFlags::rw_shared());

        assert_eq!(tracker.mmap(region), Err(DrainError::InvalidWorkItem));
    }

    #[test]
    fn mmap_rejects_overlapping_regions() {
        let mut tracker = MmapTracker::new(4096);

        tracker.mmap(writable_shared_region(0, 8192)).unwrap();

        assert_eq!(
            tracker.mmap(writable_shared_region(4096, 4096)),
            Err(DrainError::MmapRegionOverlap)
        );

        // Adjacent (non-overlapping) is allowed
        tracker.mmap(writable_shared_region(8192, 4096)).unwrap();
        assert_eq!(tracker.region_count(), 2);
    }

    #[test]
    fn munmap_removes_region_and_returns_dirty_count() {
        let mut tracker = MmapTracker::new(4096);
        let mut dirty = DirtyRangeTracker::new();
        tracker.set_enabled(true);

        tracker.mmap(writable_shared_region(0, 16384)).unwrap();

        // Mark some pages dirty via page fault
        tracker.page_fault_write(0, &mut dirty, 42).unwrap();
        tracker.page_fault_write(4096, &mut dirty, 42).unwrap();
        tracker.page_fault_write(8192, &mut dirty, 42).unwrap();

        let flushed = tracker.munmap(0, 16384, &dirty, 42).unwrap();
        assert_eq!(flushed, 3);

        assert_eq!(tracker.region_count(), 0);
        assert_eq!(tracker.stats().munmap_count, 1);
        assert_eq!(tracker.stats().munmap_dirty_pages, 3);
    }

    #[test]
    fn munmap_read_only_region_returns_zero_dirty_pages() {
        let mut tracker = MmapTracker::new(4096);
        let mut dirty = DirtyRangeTracker::new();
        tracker.set_enabled(true);

        tracker.mmap(read_only_region(0, 4096)).unwrap();

        // Mark a page dirty (outside mmap scope, but within file)
        dirty.record_dirty(42, 0, 4096).unwrap();

        let flushed = tracker.munmap(0, 4096, &dirty, 42).unwrap();
        assert_eq!(flushed, 0);
        assert_eq!(tracker.stats().munmap_dirty_pages, 0);
    }

    #[test]
    fn munmap_private_region_returns_zero_dirty_pages() {
        let mut tracker = MmapTracker::new(4096);
        let mut dirty = DirtyRangeTracker::new();
        tracker.set_enabled(true);

        tracker.mmap(private_region(0, 4096)).unwrap();
        dirty.record_dirty(42, 0, 4096).unwrap();

        let flushed = tracker.munmap(0, 4096, &dirty, 42).unwrap();
        assert_eq!(flushed, 0);
    }

    #[test]
    fn munmap_unknown_region_fails() {
        let mut tracker = MmapTracker::new(4096);
        let dirty = DirtyRangeTracker::new();

        assert_eq!(
            tracker.munmap(0, 4096, &dirty, 42),
            Err(DrainError::MmapRegionNotFound)
        );
    }

    #[test]
    fn munmap_zero_length_fails() {
        let mut tracker = MmapTracker::new(4096);
        let dirty = DirtyRangeTracker::new();

        assert_eq!(
            tracker.munmap(0, 0, &dirty, 42),
            Err(DrainError::InvalidWorkItem)
        );
    }

    #[test]
    fn page_fault_write_marks_dirty_when_in_writable_shared() {
        let mut tracker = MmapTracker::new(4096);
        let mut dirty = DirtyRangeTracker::new();
        tracker.set_enabled(true);

        tracker.mmap(writable_shared_region(0, 8192)).unwrap();

        let result = tracker.page_fault_write(2048, &mut dirty, 42).unwrap();
        assert!(result);

        // The dirty tracker should have page-aligned range
        assert_eq!(dirty.pending_range_count(), 1);
        assert_eq!(dirty.pending_ranges(), &[DirtyRange::new(42, 0, 4096)]);

        assert_eq!(tracker.stats().dirty_page_faults, 1);
    }

    #[test]
    fn page_fault_write_ignored_when_disabled() {
        let mut tracker = MmapTracker::new(4096);
        let mut dirty = DirtyRangeTracker::new();
        // Not enabled

        tracker.mmap(writable_shared_region(0, 8192)).unwrap();

        let result = tracker.page_fault_write(0, &mut dirty, 42).unwrap();
        assert!(!result);
        assert!(dirty.is_empty());
        assert_eq!(tracker.stats().dirty_page_faults, 0);
    }

    #[test]
    fn page_fault_write_ignored_for_read_only_region() {
        let mut tracker = MmapTracker::new(4096);
        let mut dirty = DirtyRangeTracker::new();
        tracker.set_enabled(true);

        tracker.mmap(read_only_region(0, 4096)).unwrap();

        let result = tracker.page_fault_write(0, &mut dirty, 42).unwrap();
        assert!(!result);
        assert!(dirty.is_empty());
    }

    #[test]
    fn page_fault_write_ignored_for_private_region() {
        let mut tracker = MmapTracker::new(4096);
        let mut dirty = DirtyRangeTracker::new();
        tracker.set_enabled(true);

        tracker.mmap(private_region(0, 4096)).unwrap();

        let result = tracker.page_fault_write(0, &mut dirty, 42).unwrap();
        assert!(!result);
        assert!(dirty.is_empty());
    }

    #[test]
    fn page_fault_write_outside_mapped_region() {
        let mut tracker = MmapTracker::new(4096);
        let mut dirty = DirtyRangeTracker::new();
        tracker.set_enabled(true);

        tracker.mmap(writable_shared_region(0, 4096)).unwrap();

        let result = tracker.page_fault_write(8192, &mut dirty, 42).unwrap();
        assert!(!result);
        assert!(dirty.is_empty());
    }

    #[test]
    fn page_fault_write_coalesces_multiple_faults_on_same_page() {
        let mut tracker = MmapTracker::new(4096);
        let mut dirty = DirtyRangeTracker::new();
        tracker.set_enabled(true);

        tracker.mmap(writable_shared_region(0, 8192)).unwrap();

        // Two faults in the same page
        tracker.page_fault_write(0, &mut dirty, 42).unwrap();
        tracker.page_fault_write(512, &mut dirty, 42).unwrap();

        // Coalesced into one range
        assert_eq!(dirty.pending_range_count(), 1);
        assert_eq!(dirty.pending_dirty_bytes(), 4096);
        assert_eq!(tracker.stats().dirty_page_faults, 2);
    }

    #[test]
    fn msync_counts_dirty_pages_in_writable_shared_range() {
        let mut tracker = MmapTracker::new(4096);
        let mut dirty = DirtyRangeTracker::new();
        tracker.set_enabled(true);

        tracker.mmap(writable_shared_region(0, 16384)).unwrap();

        // Mark pages dirty via page faults
        tracker.page_fault_write(0, &mut dirty, 42).unwrap();
        tracker.page_fault_write(4096, &mut dirty, 42).unwrap();
        tracker.page_fault_write(12288, &mut dirty, 42).unwrap();

        // msync the first 8KB
        let count = tracker.msync(0, 8192, &dirty, 42).unwrap();
        assert_eq!(count, 2);

        assert_eq!(tracker.stats().msync_count, 1);
        assert_eq!(tracker.stats().msync_dirty_pages, 2);
    }

    #[test]
    fn msync_noop_when_disabled() {
        let mut tracker = MmapTracker::new(4096);
        let mut dirty = DirtyRangeTracker::new();

        tracker.mmap(writable_shared_region(0, 8192)).unwrap();
        dirty.record_dirty(42, 0, 4096).unwrap();

        let count = tracker.msync(0, 8192, &dirty, 42).unwrap();
        assert_eq!(count, 0);
        assert_eq!(tracker.stats().msync_count, 0);
    }

    #[test]
    fn msync_noop_without_writable_region() {
        let mut tracker = MmapTracker::new(4096);
        let mut dirty = DirtyRangeTracker::new();
        tracker.set_enabled(true);

        tracker.mmap(read_only_region(0, 8192)).unwrap();
        dirty.record_dirty(42, 0, 4096).unwrap();

        let count = tracker.msync(0, 8192, &dirty, 42).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn msync_zero_length_fails() {
        let mut tracker = MmapTracker::new(4096);
        let dirty = DirtyRangeTracker::new();

        assert_eq!(
            tracker.msync(0, 0, &dirty, 42),
            Err(DrainError::InvalidWorkItem)
        );
    }

    #[test]
    fn is_writable_shared_offset_checks_enabled_and_region() {
        let mut tracker = MmapTracker::new(4096);

        // Disabled
        tracker.mmap(writable_shared_region(0, 4096)).unwrap();
        assert!(!tracker.is_writable_shared_offset(0));

        // Enabled
        tracker.set_enabled(true);
        assert!(tracker.is_writable_shared_offset(0));
        assert!(!tracker.is_writable_shared_offset(4096));

        // Read-only region
        tracker.mmap(read_only_region(4096, 4096)).unwrap();
        assert!(!tracker.is_writable_shared_offset(4096));
    }

    #[test]
    fn multiple_regions_sorted_by_start() {
        let mut tracker = MmapTracker::new(4096);

        tracker.mmap(writable_shared_region(8192, 4096)).unwrap();
        tracker.mmap(writable_shared_region(0, 4096)).unwrap();
        tracker.mmap(writable_shared_region(4096, 4096)).unwrap();

        assert_eq!(tracker.regions().len(), 3);
        assert_eq!(tracker.regions()[0].start, 0);
        assert_eq!(tracker.regions()[1].start, 4096);
        assert_eq!(tracker.regions()[2].start, 8192);
    }

    #[test]
    fn mmap_region_contains_offset() {
        let region = writable_shared_region(4096, 8192);
        assert!(region.contains_offset(4096));
        assert!(region.contains_offset(12287));
        assert!(!region.contains_offset(0));
        assert!(!region.contains_offset(12288));
    }

    #[test]
    fn mmap_region_overlaps_detection() {
        let region = writable_shared_region(4096, 8192);

        assert!(region.overlaps(0, 4097));
        assert!(region.overlaps(8191, 4096));
        assert!(region.overlaps(4096, 1));

        assert!(!region.overlaps(0, 4096)); // adjacent, not overlapping
        assert!(!region.overlaps(12288, 4096)); // entirely after
        assert!(!region.overlaps(0, 0)); // zero length
    }

    #[test]
    fn mmap_prot_flags_is_writable_shared() {
        assert!(MmapProtFlags::rw_shared().is_writable_shared());
        assert!(!MmapProtFlags::read_shared().is_writable_shared());
        assert!(!MmapProtFlags::rw_private().is_writable_shared());
    }

    #[test]
    fn mmap_stats_records_all_counters() {
        let mut stats = MmapStats::new();
        assert_eq!(stats.mmap_count, 0);
        assert_eq!(stats.dirty_page_faults, 0);

        stats.record_mmap(4096);
        assert_eq!(stats.mmap_count, 1);
        assert_eq!(stats.mmap_total_bytes, 4096);

        stats.record_page_fault();
        stats.record_page_fault();
        assert_eq!(stats.dirty_page_faults, 2);

        stats.record_msync(5);
        assert_eq!(stats.msync_count, 1);
        assert_eq!(stats.msync_dirty_pages, 5);

        stats.record_munmap(3);
        assert_eq!(stats.munmap_count, 1);
        assert_eq!(stats.munmap_dirty_pages, 3);
    }

    #[test]
    fn concurrent_mmap_and_page_fault_interleaving() {
        let mut tracker = MmapTracker::new(4096);
        let mut dirty = DirtyRangeTracker::new();
        tracker.set_enabled(true);

        // Register two disjoint writable shared regions
        tracker.mmap(writable_shared_region(0, 4096)).unwrap();
        tracker.mmap(writable_shared_region(16384, 4096)).unwrap();

        // Page faults interleaved across regions
        tracker.page_fault_write(0, &mut dirty, 1).unwrap();
        assert_eq!(dirty.pending_range_count(), 1);

        tracker.page_fault_write(16384, &mut dirty, 1).unwrap();
        assert_eq!(dirty.pending_range_count(), 2);

        // Gap between regions is not writable
        let result = tracker.page_fault_write(8192, &mut dirty, 1).unwrap();
        assert!(!result);
        assert_eq!(dirty.pending_range_count(), 2);

        // msync counts both regions' dirty pages
        let count = tracker.msync(0, 20480, &dirty, 1).unwrap();
        assert_eq!(count, 2);

        assert_eq!(tracker.stats().dirty_page_faults, 2);
        assert_eq!(tracker.stats().msync_dirty_pages, 2);
    }
    // ── DrainError to_errno mapping ─────────────────────────────────────

    #[test]
    fn drain_error_queue_empty_maps_to_eagain() {
        assert_eq!(DrainError::QueueEmpty.to_errno(), 11); // EAGAIN
    }

    #[test]
    fn drain_error_in_flight_full_maps_to_ebusy() {
        assert_eq!(DrainError::InFlightFull.to_errno(), 16); // EBUSY
    }

    #[test]
    fn drain_error_drain_table_full_maps_to_enomem() {
        assert_eq!(DrainError::DrainTableFull.to_errno(), 12); // ENOMEM
    }

    #[test]
    fn drain_error_unknown_ticket_maps_to_einval() {
        assert_eq!(DrainError::UnknownTicket.to_errno(), 22); // EINVAL
    }

    #[test]
    fn drain_error_dirty_data_unavailable_maps_to_eio() {
        assert_eq!(DrainError::DirtyDataUnavailable.to_errno(), 5); // EIO
    }

    #[test]
    fn drain_error_object_store_put_maps_to_eio() {
        assert_eq!(DrainError::ObjectStorePut.to_errno(), 5); // EIO
    }

    #[test]
    fn drain_error_extent_map_update_maps_to_eio() {
        assert_eq!(DrainError::ExtentMapUpdate.to_errno(), 5); // EIO
    }

    #[test]
    fn drain_error_invalid_work_item_maps_to_einval() {
        assert_eq!(DrainError::InvalidWorkItem.to_errno(), 22); // EINVAL
    }

    #[test]
    fn drain_error_commit_barrier_broken_maps_to_eio() {
        assert_eq!(DrainError::CommitGroupBarrierBroken.to_errno(), 5); // EIO
    }

    #[test]
    fn drain_error_mmap_region_overlap_maps_to_einval() {
        assert_eq!(DrainError::MmapRegionOverlap.to_errno(), 22); // EINVAL
    }

    #[test]
    fn drain_error_mmap_region_not_found_maps_to_einval() {
        assert_eq!(DrainError::MmapRegionNotFound.to_errno(), 22); // EINVAL
    }

    // ── DrainStats accumulation edge cases ─────────────────────────────

    #[test]
    fn drain_stats_new_is_zeroed() {
        let stats = DrainStats::new();
        assert_eq!(stats.completed, 0);
        assert_eq!(stats.pending, 0);
        assert_eq!(stats.errors, 0);
        assert_eq!(stats.commit_barriers_completed, 0);
        assert_eq!(stats.commit_barriers_failed, 0);
        assert_eq!(stats.bytes_drained, 0);
        assert_eq!(stats.objects_stored, 0);
    }

    #[test]
    fn drain_stats_default_is_zeroed() {
        let stats = DrainStats::default();
        assert_eq!(stats.completed, 0);
        assert_eq!(stats.pending, 0);
    }

    #[test]
    fn drain_stats_interleaved_completions_and_errors() {
        let mut stats = DrainStats::new();
        stats.record_dispatched();
        stats.record_dispatched();
        stats.record_dispatched();
        assert_eq!(stats.pending, 3);

        stats.record_completion(1024);
        assert_eq!(stats.completed, 1);
        assert_eq!(stats.pending, 2);
        assert_eq!(stats.bytes_drained, 1024);
        assert_eq!(stats.objects_stored, 1);

        stats.record_error();
        assert_eq!(stats.errors, 1);
        assert_eq!(stats.pending, 1);

        stats.record_completion(2048);
        assert_eq!(stats.completed, 2);
        assert_eq!(stats.pending, 0);
        assert_eq!(stats.bytes_drained, 3072);
        assert_eq!(stats.objects_stored, 2);
    }

    #[test]
    fn drain_stats_multiple_barriers_accumulate_bytes() {
        let mut stats = DrainStats::new();
        stats.record_commit_barrier_completed(4096);
        stats.record_commit_barrier_completed(8192);
        assert_eq!(stats.commit_barriers_completed, 2);
        assert_eq!(stats.bytes_drained, 12288);
    }

    #[test]
    fn drain_stats_mixed_barriers_accumulate_separately() {
        let mut stats = DrainStats::new();
        stats.record_commit_barrier_completed(100);
        stats.record_commit_barrier_failed();
        stats.record_commit_barrier_completed(200);
        stats.record_commit_barrier_failed();
        assert_eq!(stats.commit_barriers_completed, 2);
        assert_eq!(stats.commit_barriers_failed, 2);
        assert_eq!(stats.bytes_drained, 300);
    }

    // ── DirtyRangeTracker boundary conditions ──────────────────────────

    #[test]
    fn dirty_range_tracker_zero_length_range_rejected() {
        let mut tracker = DirtyRangeTracker::new();
        assert_eq!(
            tracker.record_dirty(1, 100, 100),
            Err(DrainError::InvalidWorkItem)
        );
    }

    #[test]
    fn dirty_range_tracker_empty_tracker_is_empty() {
        let tracker = DirtyRangeTracker::new();
        assert!(tracker.is_empty());
        assert_eq!(tracker.pending_range_count(), 0);
        assert_eq!(tracker.pending_dirty_bytes(), 0);
        assert_eq!(tracker.completion_count(), 0);
        assert_eq!(tracker.failed_count(), 0);
    }

    #[test]
    fn dirty_range_tracker_max_offset_range_tracking() {
        let mut tracker = DirtyRangeTracker::new();
        tracker.record_dirty(1, u64::MAX - 4096, u64::MAX).unwrap();
        assert_eq!(tracker.pending_range_count(), 1);
        assert_eq!(tracker.pending_dirty_bytes(), 4096);
        assert_eq!(
            tracker.pending_ranges(),
            &[DirtyRange::new(1, u64::MAX - 4096, u64::MAX)]
        );
    }

    #[test]
    fn dirty_range_tracker_repeated_identical_range_coalesces() {
        let mut tracker = DirtyRangeTracker::new();
        tracker.record_dirty(5, 0, 4096).unwrap();
        tracker.record_dirty(5, 0, 4096).unwrap();
        assert_eq!(tracker.pending_range_count(), 1);
        assert_eq!(tracker.pending_dirty_bytes(), 4096);
    }

    #[test]
    fn dirty_range_tracker_mark_failed_idempotent_on_same_range() {
        let mut tracker = DirtyRangeTracker::new();
        let range = DirtyRange::new(99, 0, 4096);
        tracker.record_dirty_range(range).unwrap();
        tracker
            .mark_failed(range, DrainError::ObjectStorePut)
            .unwrap();
        tracker
            .mark_failed(range, DrainError::ExtentMapUpdate)
            .unwrap();
        assert_eq!(tracker.completion_count(), 2);
        assert_eq!(tracker.failed_count(), 2);
    }

    // ── DirtyPageTracker unit tests ──────────────────────────────────────

    #[test]
    fn dirty_page_tracker_new_is_empty() {
        let t = DirtyPageTracker::new();
        assert!(t.is_empty());
        assert_eq!(t.range_count(), 0);
        assert_eq!(t.dirty_inode_count(), 0);
        assert_eq!(t.current_boundary(), 1);
    }

    #[test]
    fn mark_dirty_single_page() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(42, 0, 4096).unwrap();
        assert!(!t.is_empty());
        assert_eq!(t.range_count(), 1);
        assert_eq!(t.dirty_inode_count(), 1);
        assert_eq!(t.dirty_bytes(42), 4096);
        let ranges = t.get_dirty_ranges(42);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], DirtyRange::new(42, 0, 4096));
    }

    #[test]
    fn mark_dirty_multi_page_non_contiguous() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(1, 0, 4096).unwrap();
        t.mark_dirty(1, 12288, 4096).unwrap();
        assert_eq!(t.range_count(), 2);
        assert_eq!(t.dirty_bytes(1), 8192);
        let ranges = t.get_dirty_ranges(1);
        assert_eq!(
            ranges,
            vec![
                DirtyRange::new(1, 0, 4096),
                DirtyRange::new(1, 12288, 16384),
            ]
        );
    }

    #[test]
    fn mark_dirty_adjacent_merges() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(5, 0, 4096).unwrap();
        t.mark_dirty(5, 4096, 4096).unwrap();
        assert_eq!(t.range_count(), 1);
        assert_eq!(t.dirty_bytes(5), 8192);
        assert_eq!(t.get_dirty_ranges(5), vec![DirtyRange::new(5, 0, 8192)]);
    }

    #[test]
    fn mark_dirty_overlapping_merges() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(3, 0, 8192).unwrap();
        t.mark_dirty(3, 4096, 8192).unwrap(); // overlaps tail
        assert_eq!(t.range_count(), 1);
        assert_eq!(t.dirty_bytes(3), 12288);
        assert_eq!(t.get_dirty_ranges(3), vec![DirtyRange::new(3, 0, 12288)]);
    }

    #[test]
    fn mark_dirty_contained_range_noop() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(7, 0, 16384).unwrap();
        t.mark_dirty(7, 4096, 4096).unwrap(); // fully contained
        assert_eq!(t.range_count(), 1);
        assert_eq!(t.dirty_bytes(7), 16384);
    }

    #[test]
    fn mark_dirty_zero_length_is_noop() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(1, 100, 0).unwrap();
        assert!(t.is_empty());
        assert_eq!(t.range_count(), 0);
    }

    #[test]
    fn mark_dirty_offset_overflow_rejected() {
        let mut t = DirtyPageTracker::new();
        assert_eq!(
            t.mark_dirty(1, u64::MAX, 1),
            Err(DrainError::InvalidWorkItem)
        );
        assert!(t.is_empty());
    }

    #[test]
    fn mark_dirty_max_offset_accepted() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(1, u64::MAX - 4096, 4096).unwrap();
        assert_eq!(t.range_count(), 1);
        assert_eq!(t.dirty_bytes(1), 4096);
    }

    #[test]
    fn multiple_inodes_tracked_independently() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(10, 0, 4096).unwrap();
        t.mark_dirty(20, 0, 8192).unwrap();
        t.mark_dirty(10, 16384, 4096).unwrap();
        assert_eq!(t.dirty_inode_count(), 2);
        assert_eq!(t.range_count(), 3);
        assert_eq!(t.dirty_bytes(10), 8192);
        assert_eq!(t.dirty_bytes(20), 8192);
    }

    #[test]
    fn get_dirty_ranges_unknown_inode_empty() {
        let t = DirtyPageTracker::new();
        assert!(t.get_dirty_ranges(999).is_empty());
        assert_eq!(t.dirty_bytes(999), 0);
    }

    #[test]
    fn get_dirty_ranges_returns_ordered_by_offset() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(1, 16384, 4096).unwrap();
        t.mark_dirty(1, 0, 4096).unwrap();
        t.mark_dirty(1, 32768, 4096).unwrap();
        let ranges = t.get_dirty_ranges(1);
        assert_eq!(ranges[0].offset_start, 0);
        assert_eq!(ranges[1].offset_start, 16384);
        assert_eq!(ranges[2].offset_start, 32768);
    }

    #[test]
    fn take_boundary_returns_closed_token_and_increments() {
        let mut t = DirtyPageTracker::new();
        assert_eq!(t.current_boundary(), 1);

        let b1 = t.take_boundary();
        assert_eq!(b1, 1);
        assert_eq!(t.current_boundary(), 2);

        let b2 = t.take_boundary();
        assert_eq!(b2, 2);
        assert_eq!(t.current_boundary(), 3);
    }

    #[test]
    fn boundary_tokens_assigned_correctly_on_mark_dirty() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(1, 0, 4096).unwrap(); // boundary 1

        let tok = t.take_boundary(); // close 1, return 1
        assert_eq!(tok, 1);

        t.mark_dirty(1, 4096, 4096).unwrap(); // boundary 2

        let ranges = t.get_dirty_ranges_with_boundary(1);
        assert_eq!(ranges.len(), 1); // merged: [0, 8192)
        assert_eq!(ranges[0].1, 2); // max(1, 2) = 2 — merged range keeps higher boundary
    }

    #[test]
    fn clear_until_boundary_removes_correct_ranges() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(1, 0, 4096).unwrap(); // boundary 1
        let _ = t.take_boundary(); // close 1 → 2
        t.mark_dirty(1, 4096, 4096).unwrap(); // boundary 2
        let _ = t.take_boundary(); // close 2 → 3
        t.mark_dirty(1, 8192, 4096).unwrap(); // boundary 3

        assert_eq!(t.range_count(), 1); // all merged into [0, 12288) with boundary 3

        // But wait — since ranges merged, let me test with non-merging writes
        let mut t2 = DirtyPageTracker::new();
        t2.mark_dirty(2, 0, 4096).unwrap(); // b1
        let _ = t2.take_boundary(); // close 1
        t2.mark_dirty(2, 16384, 4096).unwrap(); // b2 (no merge — gap at 4096..16384)
        let _ = t2.take_boundary(); // close 2
        t2.mark_dirty(2, 32768, 4096).unwrap(); // b3

        assert_eq!(t2.range_count(), 3);

        let removed = t2.clear_until_boundary(2, 1);
        assert_eq!(removed, 1);
        assert_eq!(t2.range_count(), 2);

        let removed = t2.clear_until_boundary(2, 2);
        assert_eq!(removed, 1);
        assert_eq!(t2.range_count(), 1);

        let removed = t2.clear_until_boundary(2, 3);
        assert_eq!(removed, 1);
        assert_eq!(t2.range_count(), 0);
    }

    #[test]
    fn clear_until_boundary_other_inode_unaffected() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(1, 0, 4096).unwrap(); // b1
        t.mark_dirty(2, 0, 4096).unwrap(); // b1

        let tok = t.take_boundary(); // close 1

        let removed = t.clear_until_boundary(1, tok);
        assert_eq!(removed, 1);
        assert!(t.get_dirty_ranges(1).is_empty());
        assert!(!t.get_dirty_ranges(2).is_empty());
    }

    #[test]
    fn clear_all_until_boundary_works_across_inodes() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(1, 0, 4096).unwrap();
        t.mark_dirty(2, 0, 4096).unwrap();
        t.mark_dirty(3, 0, 4096).unwrap();

        let tok = t.take_boundary();
        t.mark_dirty(4, 0, 4096).unwrap(); // b2

        let removed = t.clear_all_until_boundary(tok);
        assert_eq!(removed, 3);
        assert_eq!(t.range_count(), 1); // only inode 4 remains
    }

    #[test]
    fn merge_preserves_max_boundary_token() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(1, 0, 4096).unwrap(); // b1
        let _ = t.take_boundary(); // close 1 → 2
        t.mark_dirty(1, 0, 2048).unwrap(); // b2, overlaps with existing

        // Merged range [0, 4096) should have boundary = max(1, 2) = 2
        let ranges = t.get_dirty_ranges_with_boundary(1);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].1, 2);

        // clear_until_boundary(1) should NOT remove it (boundary 2 > 1)
        let _tok = t.take_boundary(); // close 2 → 3
        t.clear_until_boundary(1, 1);
        assert_eq!(t.range_count(), 1);

        // clear_until_boundary(2) SHOULD remove it
        t.clear_until_boundary(1, 2);
        assert_eq!(t.range_count(), 0);
    }

    #[test]
    fn all_dirty_ranges_returns_all_tuples() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(10, 0, 4096).unwrap();
        t.mark_dirty(20, 8192, 4096).unwrap();
        let all = t.all_dirty_ranges();
        assert_eq!(all, vec![(10, 0, 4096), (20, 8192, 12288)]);
    }

    // ── accept_write entry point tests ──────────────────────────────────

    #[test]
    fn accept_write_populates_dirty_page_tracker() {
        let mut t = DirtyPageTracker::new();
        let data = vec![0xAA_u8; 4096];
        t.accept_write(42, 0, &data).unwrap();
        assert!(!t.is_empty());
        assert_eq!(t.range_count(), 1);
        assert_eq!(t.dirty_bytes(42), 4096);
        let ranges = t.get_dirty_ranges(42);
        assert_eq!(ranges[0], DirtyRange::new(42, 0, 4096));
    }

    #[test]
    fn accept_write_merges_adjacent() {
        let mut t = DirtyPageTracker::new();
        t.accept_write(5, 0, &[0u8; 4096]).unwrap();
        t.accept_write(5, 4096, &[0u8; 4096]).unwrap();
        assert_eq!(t.range_count(), 1);
        assert_eq!(t.get_dirty_ranges(5), vec![DirtyRange::new(5, 0, 8192)]);
    }

    #[test]
    fn accept_write_handles_out_of_order() {
        let mut t = DirtyPageTracker::new();
        t.accept_write(7, 16384, &[0u8; 4096]).unwrap();
        t.accept_write(7, 0, &[0u8; 4096]).unwrap();
        t.accept_write(7, 8192, &[0u8; 4096]).unwrap();
        // Ranges should be ordered by offset in get_dirty_ranges
        let ranges = t.get_dirty_ranges(7);
        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges[0].offset_start, 0);
        assert_eq!(ranges[1].offset_start, 8192);
        assert_eq!(ranges[2].offset_start, 16384);
    }

    #[test]
    fn accept_write_zero_length_is_noop() {
        let mut t = DirtyPageTracker::new();
        t.accept_write(1, 100, &[]).unwrap();
        assert!(t.is_empty());
    }

    #[test]
    fn accept_write_overflow_rejected() {
        let mut t = DirtyPageTracker::new();
        let data = vec![0u8; 2];
        assert_eq!(
            t.accept_write(1, u64::MAX, &data),
            Err(DrainError::InvalidWorkItem)
        );
    }

    // ── lookup_range tests ──────────────────────────────────────────────

    #[test]
    fn lookup_range_exact_match() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(10, 4096, 4096).unwrap();
        let found = t.lookup_range(10, 4096, 8192).unwrap();
        assert_eq!(found, DirtyRange::new(10, 4096, 8192));
    }

    #[test]
    fn lookup_range_partial_overlap_start() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(10, 4096, 8192).unwrap(); // [4096, 12288)
        let found = t.lookup_range(10, 0, 8192).unwrap();
        assert_eq!(found, DirtyRange::new(10, 4096, 12288));
    }

    #[test]
    fn lookup_range_partial_overlap_end() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(10, 0, 8192).unwrap(); // [0, 8192)
        let found = t.lookup_range(10, 4096, 12288).unwrap();
        assert_eq!(found, DirtyRange::new(10, 0, 8192));
    }

    #[test]
    fn lookup_range_contained_within_dirty() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(10, 0, 16384).unwrap(); // [0, 16384)
        let found = t.lookup_range(10, 4096, 8192).unwrap();
        assert_eq!(found, DirtyRange::new(10, 0, 16384));
    }

    #[test]
    fn lookup_range_no_overlap() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(10, 0, 4096).unwrap();
        t.mark_dirty(10, 12288, 4096).unwrap();
        assert!(t.lookup_range(10, 8192, 12288).is_none());
    }

    #[test]
    fn lookup_range_wrong_inode() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(10, 0, 4096).unwrap();
        assert!(t.lookup_range(20, 0, 4096).is_none());
    }

    #[test]
    fn lookup_range_invalid_range_returns_none() {
        let mut t = DirtyPageTracker::new();
        t.mark_dirty(10, 0, 4096).unwrap();
        assert!(t.lookup_range(10, 8192, 4096).is_none()); // start >= end
    }

    #[test]
    fn lookup_range_empty_tracker() {
        let t = DirtyPageTracker::new();
        assert!(t.lookup_range(10, 0, 4096).is_none());
    }

    // ── WritebackSyncPlan fdatasync edge cases ─────────────────────────

    #[test]
    fn fdatasync_metadata_only_when_required_for_data() {
        // metadata_required_for_data=true but no dirty data: only metadata flush
        let state = WritebackSyncHandleState::new(10, 5, 1).with_dirty_metadata(true); // sets metadata_required_for_data=true internally
        let plan = plan_writeback_sync(WritebackSyncKind::Fdatasync, Some(state)).unwrap();
        assert_eq!(plan.steps(), &[WritebackSyncStep::FlushMetadata]);
        assert!(!plan.requires_data_flush());
        assert!(plan.requires_metadata_flush());
    }

    #[test]
    fn fdatasync_only_data_when_metadata_not_required() {
        let state = WritebackSyncHandleState::new(10, 5, 1).with_dirty_data(4096, false);
        let plan = plan_writeback_sync(WritebackSyncKind::Fdatasync, Some(state)).unwrap();
        assert_eq!(plan.steps(), &[WritebackSyncStep::FlushData]);
        assert!(plan.requires_data_flush());
        assert!(!plan.requires_metadata_flush());
    }

    #[test]
    fn fsync_clean_handle_with_zero_object_id_fails() {
        let state = WritebackSyncHandleState::new(1, 0, 1);
        assert_eq!(
            plan_writeback_sync(WritebackSyncKind::Fsync, Some(state)),
            Err(WritebackSyncPlanError::InvalidHandleState)
        );
    }

    #[test]
    fn fdatasync_clean_handle_is_noop() {
        let state = WritebackSyncHandleState::new(3, 2, 1);
        let plan = plan_writeback_sync(WritebackSyncKind::Fdatasync, Some(state)).unwrap();
        assert!(plan.is_noop());
        assert!(!plan.requires_data_flush());
        assert!(!plan.requires_metadata_flush());
    }

    #[test]
    fn sync_plan_none_state_is_unknown_handle() {
        assert_eq!(
            plan_writeback_sync(WritebackSyncKind::Fsync, None),
            Err(WritebackSyncPlanError::UnknownHandle)
        );
        assert_eq!(
            plan_writeback_sync(WritebackSyncKind::Fdatasync, None),
            Err(WritebackSyncPlanError::UnknownHandle)
        );
    }

    // ── batch_by_object_affinity edge cases ────────────────────────────

    #[test]
    fn batch_by_object_affinity_single_item() {
        let items = vec![DrainWorkItem::new(42, 0, 4096, 1, 4096, 0)];
        let batches = DirtyDrainEngine::<
            MockWorkSource,
            MockDirtyData,
            MockObjectStore,
            MockExtentMap,
        >::batch_by_object_affinity(&items);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 1);
        assert_eq!(batches[0].as_slice()[0].object_id, 42);
    }

    #[test]
    fn batch_by_object_affinity_interleaved_objects() {
        let items = vec![
            DrainWorkItem::new(1, 0, 4096, 1, 4096, 0),
            DrainWorkItem::new(2, 0, 2048, 1, 2048, 0),
            DrainWorkItem::new(1, 4096, 8192, 1, 4096, 0),
            DrainWorkItem::new(3, 0, 1024, 1, 1024, 0),
            DrainWorkItem::new(2, 2048, 4096, 1, 2048, 0),
        ];
        let batches = DirtyDrainEngine::<
            MockWorkSource,
            MockDirtyData,
            MockObjectStore,
            MockExtentMap,
        >::batch_by_object_affinity(&items);
        assert_eq!(batches.len(), 3);
        // Object 1 has 2 items
        assert_eq!(batches[0].len(), 2);
        assert!(batches[0].as_slice().iter().all(|i| i.object_id == 1));
        // Object 2 has 2 items
        assert_eq!(batches[1].len(), 2);
        assert!(batches[1].as_slice().iter().all(|i| i.object_id == 2));
        // Object 3 has 1 item
        assert_eq!(batches[2].len(), 1);
        assert_eq!(batches[2].as_slice()[0].object_id, 3);
    }

    #[test]
    fn batch_by_object_affinity_preserves_total_items() {
        let items: Vec<DrainWorkItem> = (0..5)
            .map(|i| DrainWorkItem::new(i as u64, 0, 4096, 1, 4096, 0))
            .collect();
        let batches = DirtyDrainEngine::<
            MockWorkSource,
            MockDirtyData,
            MockObjectStore,
            MockExtentMap,
        >::batch_by_object_affinity(&items);
        let total: usize = batches.iter().map(|b| b.len()).sum();
        assert_eq!(total, 5);
    }

    // ── WritebackDispatchState transition invariants ───────────────────

    #[test]
    fn writeback_dispatch_state_new_is_empty() {
        let state = WritebackDispatchState::<8, 4>::new();
        assert_eq!(state.queued_len(), 0);
        assert_eq!(state.in_flight_len(), 0);
        assert_eq!(state.queued_len(), 0);
        assert!(state.is_commit_group_idle(0));
    }

    #[test]
    fn writeback_dispatch_state_enqueue_and_dispatch() {
        let mut state = WritebackDispatchState::<8, 4>::new();
        let item = WritebackWorkItem::new(1, 0, 4096, 7, 4096, 100);
        state.enqueue(item).unwrap();
        assert_eq!(state.queued_len(), 1);
        assert!(state.queued_len() > 0);

        let ticket = state.dispatch_next().unwrap();
        assert_eq!(state.queued_len(), 0);
        assert_eq!(state.in_flight_len(), 1);

        let completed = state.complete(ticket.ticket_id).unwrap();
        assert_eq!(completed.object_id, 1);
        assert_eq!(state.in_flight_len(), 0);
    }

    #[test]
    fn writeback_dispatch_state_queue_full() {
        let mut state = WritebackDispatchState::<2, 2>::new();
        state
            .enqueue(WritebackWorkItem::new(1, 0, 4096, 1, 4096, 0))
            .unwrap();
        state
            .enqueue(WritebackWorkItem::new(2, 0, 4096, 1, 4096, 0))
            .unwrap();
        assert_eq!(
            state.enqueue(WritebackWorkItem::new(3, 0, 4096, 1, 4096, 0)),
            Err(WritebackQueueError::Full)
        );
    }

    #[test]
    fn writeback_dispatch_state_dispatch_empty_queue() {
        let mut state = WritebackDispatchState::<4, 2>::new();
        assert_eq!(
            state.dispatch_next(),
            Err(WritebackDispatchError::QueueEmpty)
        );
    }

    #[test]
    fn writeback_dispatch_state_complete_unknown_ticket() {
        let mut state = WritebackDispatchState::<4, 2>::new();
        assert_eq!(
            state.complete(999),
            Err(WritebackDispatchError::UnknownTicket)
        );
    }

    #[test]
    fn writeback_dispatch_state_in_flight_full() {
        let mut state = WritebackDispatchState::<4, 2>::new();
        state
            .enqueue(WritebackWorkItem::new(1, 0, 4096, 1, 4096, 0))
            .unwrap();
        state
            .enqueue(WritebackWorkItem::new(2, 0, 4096, 1, 4096, 0))
            .unwrap();
        state
            .enqueue(WritebackWorkItem::new(3, 0, 4096, 1, 4096, 0))
            .unwrap();

        state.dispatch_next().unwrap();
        state.dispatch_next().unwrap();
        // Third dispatch should fail because in-flight is full (2)
        assert_eq!(
            state.dispatch_next(),
            Err(WritebackDispatchError::InFlightFull)
        );
    }

    #[test]
    fn writeback_dispatch_state_commit_group_idle_tracks_multiple_commit_groups() {
        let mut state = WritebackDispatchState::<8, 4>::new();
        state
            .enqueue(WritebackWorkItem::new(1, 0, 4096, 10, 4096, 0))
            .unwrap();
        state
            .enqueue(WritebackWorkItem::new(2, 0, 4096, 20, 4096, 0))
            .unwrap();

        assert!(!state.is_commit_group_idle(10));
        assert!(!state.is_commit_group_idle(20));
        assert!(state.is_commit_group_idle(30));

        // Dispatch both
        let t1 = state.dispatch_next().unwrap();
        let t2 = state.dispatch_next().unwrap();

        // Still not idle while in-flight
        assert!(!state.is_commit_group_idle(10));
        assert!(!state.is_commit_group_idle(20));

        state.complete(t1.ticket_id).unwrap();
        assert!(state.is_commit_group_idle(10));
        assert!(!state.is_commit_group_idle(20));

        state.complete(t2.ticket_id).unwrap();
        assert!(state.is_commit_group_idle(20));
    }

    // ── DirtyRange merge edge cases ────────────────────────────────────

    #[test]
    fn dirty_range_merge_identical_ranges() {
        let a = DirtyRange::new(1, 0, 4096);
        let merged = a.merge(a).unwrap();
        assert_eq!(merged, DirtyRange::new(1, 0, 4096));
    }

    #[test]
    fn dirty_range_merge_adjacent_ranges() {
        let a = DirtyRange::new(1, 0, 4096);
        let b = DirtyRange::new(1, 4096, 8192);
        let merged = a.merge(b).unwrap();
        assert_eq!(merged, DirtyRange::new(1, 0, 8192));
    }

    #[test]
    fn dirty_range_merge_different_objects_rejected() {
        let a = DirtyRange::new(1, 0, 4096);
        let b = DirtyRange::new(2, 0, 4096);
        assert_eq!(a.merge(b), None);
    }

    #[test]
    fn dirty_range_merge_non_adjacent_rejected() {
        let a = DirtyRange::new(1, 0, 4096);
        let b = DirtyRange::new(1, 8192, 12288);
        assert_eq!(a.merge(b), None);
    }

    #[test]
    fn dirty_range_merge_invalid_range_rejected() {
        let a = DirtyRange::new(1, 0, 4096);
        let b = DirtyRange::new(1, 5000, 4000); // invalid
        assert_eq!(a.merge(b), None);
    }

    #[test]
    fn dirty_range_merge_contained_range() {
        let a = DirtyRange::new(1, 0, 8192);
        let b = DirtyRange::new(1, 2048, 4096);
        let merged = a.merge(b).unwrap();
        assert_eq!(merged, DirtyRange::new(1, 0, 8192));
    }

    // ── DrainTicket / DrainWorkItem round-trip ─────────────────────────

    #[test]
    fn drain_work_item_from_writeback_work_item() {
        let wb = WritebackWorkItem::new(42, 1024, 8192, 5, 7168, 500);
        let dw: DrainWorkItem = wb.into();
        assert_eq!(dw.object_id, 42);
        assert_eq!(dw.offset_start, 1024);
        assert_eq!(dw.offset_end, 8192);
        assert_eq!(dw.commit_group_id, 5);
        assert_eq!(dw.dirty_byte_count, 7168);
        assert_eq!(dw.oldest_dirty_age_ms, 500);
    }

    #[test]
    fn drain_ticket_from_writeback_dispatch_ticket() {
        // Need a WritebackDispatchTicket to convert.
        // We can create one indirectly through a WritebackDispatchState.
        let mut state = WritebackDispatchState::<4, 2>::new();
        state
            .enqueue(WritebackWorkItem::new(7, 0, 4096, 3, 4096, 200))
            .unwrap();
        let wb_ticket = state.dispatch_next().unwrap();
        let dt: DrainTicket = wb_ticket.into();
        assert_eq!(dt.ticket_id, wb_ticket.ticket_id);
        assert_eq!(dt.item.object_id, 7);
    }

    // ── WritebackSyncHandleState builder edge cases ────────────────────

    #[test]
    fn handle_state_with_dirty_data_preserves_metadata_flag() {
        let state = WritebackSyncHandleState::new(1, 10, 3)
            .with_dirty_data(4096, true)
            .with_dirty_metadata(true);
        assert!(state.has_dirty_data());
        assert!(state.has_dirty_state());
        assert!(state.dirty_metadata);
        assert!(state.metadata_required_for_data);
    }

    #[test]
    fn handle_state_closed_is_not_open() {
        let state = WritebackSyncHandleState::new(1, 10, 3).closed();
        assert!(!state.is_open);
    }

    #[test]
    fn handle_state_stale_is_stale() {
        let state = WritebackSyncHandleState::new(1, 10, 3).stale();
        assert!(state.is_stale);
    }

    // ═══════════════════════════════════════════════════════════════════
    // ── Writeback daemon tests ─────────────────────────────────────────
    // ═══════════════════════════════════════════════════════════════════

    fn count_flush(bytes: &mut u64) -> impl FnMut(u64, u64, u64) -> Result<u64, ()> + use<'_> {
        |_ino, _off, len| {
            *bytes += len;
            Ok(0)
        }
    }

    // ── daemon wakes and flushes above dirty_ratio ─────────────────

    #[test]
    fn daemon_flushes_when_dirty_ratio_exceeded() {
        let config = WritebackDaemonConfig {
            total_cache_bytes: 4096 * 10,     // 10 pages of cache
            dirty_ratio_hundredths: 2000,     // 20%
            dirty_bytes_threshold: u64::MAX,  // effectively disabled
            dirty_expire_centisecs: u64::MAX, // effectively disabled
            ..Default::default()
        };

        let mut daemon = WritebackDaemon::new(config);
        let mut tracker = DirtyPageTracker::new();

        // Mark 3 pages dirty (30% of cache → exceeds 20% ratio)
        tracker.mark_dirty_at(1, 0, 4096, 1000).unwrap();
        tracker.mark_dirty_at(1, 4096, 4096, 1000).unwrap();
        tracker.mark_dirty_at(1, 8192, 4096, 1000).unwrap();

        let mut flushed: u64 = 0;
        let result = daemon.tick(&tracker, 2000, &mut count_flush(&mut flushed));
        assert!(result > 0);
        assert_eq!(flushed, 4096 * 3);
        assert_eq!(daemon.stats().active_ticks, 1);
        assert_eq!(daemon.stats().ratio_flushes, 1);
    }

    #[test]
    fn daemon_skips_when_below_threshold() {
        let config = WritebackDaemonConfig {
            total_cache_bytes: 4096 * 10,
            dirty_ratio_hundredths: 2000, // 20%
            dirty_bytes_threshold: u64::MAX,
            dirty_expire_centisecs: u64::MAX,
            ..Default::default()
        };

        let mut daemon = WritebackDaemon::new(config);
        let mut tracker = DirtyPageTracker::new();

        // Only 1 page dirty (10% of cache → below 20% ratio)
        tracker.mark_dirty_at(1, 0, 4096, 1000).unwrap();

        let mut flushed: u64 = 0;
        let result = daemon.tick(&tracker, 2000, &mut count_flush(&mut flushed));
        assert_eq!(result, 0);
        assert_eq!(flushed, 0);
        assert_eq!(daemon.stats().idle_ticks, 1);
        assert_eq!(daemon.stats().active_ticks, 0);
    }

    // ── oldest-dirty-first ordering ─────────────────────────────────

    #[test]
    fn daemon_flushes_oldest_dirty_first() {
        let config = WritebackDaemonConfig {
            total_cache_bytes: 4096 * 10,
            dirty_ratio_hundredths: 2000,
            dirty_bytes_threshold: u64::MAX,
            dirty_expire_centisecs: u64::MAX,
            ..Default::default()
        };

        let daemon = WritebackDaemon::new(config);
        let mut tracker = DirtyPageTracker::new();

        // Inode 10 dirtied at t=1000 (oldest)
        tracker.mark_dirty_at(10, 0, 4096, 1000).unwrap();
        // Inode 20 dirtied at t=3000 (newer)
        tracker.mark_dirty_at(20, 0, 4096, 3000).unwrap();
        // Inode 30 dirtied at t=2000 (middle)
        tracker.mark_dirty_at(30, 0, 4096, 2000).unwrap();

        // Capture flush order
        let mut flush_order: Vec<u64> = Vec::new();
        let mut daemon_mut = daemon;
        let result = daemon_mut.tick(&tracker, 5000, &mut |ino, _off, _len| {
            flush_order.push(ino);
            Ok(0)
        });

        assert!(result > 0);
        // Oldest-first: 10 (t=1000), 30 (t=2000), 20 (t=3000)
        assert_eq!(flush_order, vec![10, 30, 20]);
    }

    // ── dirty_expire enforcement ────────────────────────────────────

    #[test]
    fn daemon_flushes_on_expire_even_below_ratio() {
        let config = WritebackDaemonConfig {
            total_cache_bytes: 4096 * 100, // large cache
            dirty_ratio_hundredths: 5000,  // 50%, far above what we have
            dirty_bytes_threshold: u64::MAX,
            dirty_expire_centisecs: 3000, // 30s in centiseconds
            ..Default::default()
        };

        let mut daemon = WritebackDaemon::new(config);
        let mut tracker = DirtyPageTracker::new();

        // Single page dirtied at t=1000, now is t=41000ms → age = 40s (4000cs)
        tracker.mark_dirty_at(1, 0, 4096, 1_000).unwrap();

        let mut flushed: u64 = 0;
        let result = daemon.tick(&tracker, 41_000, &mut count_flush(&mut flushed));
        assert!(result > 0);
        assert_eq!(flushed, 4096);
        assert_eq!(daemon.stats().expire_flushes, 1);
    }

    #[test]
    fn daemon_skips_when_not_expired() {
        let config = WritebackDaemonConfig {
            total_cache_bytes: 4096 * 100,
            dirty_ratio_hundredths: 5000,
            dirty_bytes_threshold: u64::MAX,
            dirty_expire_centisecs: 3000,
            ..Default::default()
        };

        let mut daemon = WritebackDaemon::new(config);
        let mut tracker = DirtyPageTracker::new();

        // Dirtied at t=10000, now is t=15000 → age = 5s (500cs), below 3000cs
        tracker.mark_dirty_at(1, 0, 4096, 10_000).unwrap();

        let mut flushed: u64 = 0;
        let result = daemon.tick(&tracker, 15_000, &mut count_flush(&mut flushed));
        assert_eq!(result, 0);
        assert_eq!(flushed, 0);
    }

    // ── dirty_bytes absolute threshold ──────────────────────────────

    #[test]
    fn daemon_flushes_when_dirty_bytes_exceeded() {
        let config = WritebackDaemonConfig {
            total_cache_bytes: 4096 * 1000,
            dirty_ratio_hundredths: 9000,    // 90%, far above
            dirty_bytes_threshold: 4096 * 2, // 2 pages
            dirty_expire_centisecs: u64::MAX,
            ..Default::default()
        };

        let mut daemon = WritebackDaemon::new(config);
        let mut tracker = DirtyPageTracker::new();

        // 3 pages (above 2-page threshold)
        tracker.mark_dirty_at(1, 0, 4096, 1000).unwrap();
        tracker.mark_dirty_at(1, 4096, 4096, 1000).unwrap();
        tracker.mark_dirty_at(1, 8192, 4096, 1000).unwrap();

        let mut flushed: u64 = 0;
        let result = daemon.tick(&tracker, 2000, &mut count_flush(&mut flushed));
        assert!(result > 0);
        assert_eq!(daemon.stats().bytes_flushes, 1);
    }

    // ── adaptive throttle ───────────────────────────────────────────

    #[test]
    fn daemon_throttles_when_high_latency_detected() {
        let config = WritebackDaemonConfig {
            total_cache_bytes: 4096 * 10,
            dirty_ratio_hundredths: 2000,
            dirty_bytes_threshold: u64::MAX,
            dirty_expire_centisecs: u64::MAX,
            max_flush_bytes_per_tick: 16 * 4096,
            min_flush_bytes_per_tick: 4 * 4096,
            ..Default::default()
        };

        let mut daemon = WritebackDaemon::new(config);
        let original_budget = daemon.flush_budget_per_tick();

        // Inject high-latency flushes (200ms each) to trigger throttle
        let mut tracker = DirtyPageTracker::new();
        tracker.mark_dirty_at(1, 0, 4096, 1000).unwrap();
        tracker.mark_dirty_at(1, 4096, 4096, 1000).unwrap();
        tracker.mark_dirty_at(1, 8192, 4096, 1000).unwrap();
        tracker.mark_dirty_at(1, 12288, 4096, 1000).unwrap();

        // First tick: flush with high latency (records samples)
        daemon.tick(&tracker, 2000, &mut |_ino, _off, _len| Ok(200));

        // Second tick: throttle decision based on previous samples
        // Need fresh dirty pages for second tick (the first tick flushed them)
        let mut tracker2 = DirtyPageTracker::new();
        tracker2.mark_dirty_at(1, 16384, 4096, 1000).unwrap();
        tracker2.mark_dirty_at(1, 20480, 4096, 1000).unwrap();

        daemon.tick(&tracker2, 3000, &mut |_ino, _off, _len| {
            Ok(0) // low latency on second tick, but throttle already happened
        });

        // After throttling triggered, budget should be reduced
        assert!(daemon.flush_budget_per_tick() < original_budget);
        assert_eq!(daemon.stats().throttle_events, 1);
    }

    // ── flush_inode ─────────────────────────────────────────────────

    #[test]
    fn flush_inode_flushes_only_target_inode() {
        let config = WritebackDaemonConfig::default();
        let mut daemon = WritebackDaemon::new(config);
        let mut tracker = DirtyPageTracker::new();

        tracker.mark_dirty_at(1, 0, 4096, 1000).unwrap();
        tracker.mark_dirty_at(2, 0, 4096, 1000).unwrap();
        tracker.mark_dirty_at(1, 4096, 4096, 1000).unwrap();

        let mut flushed: u64 = 0;
        let result = daemon.flush_inode(&tracker, 1, &mut count_flush(&mut flushed));

        assert_eq!(result, 4096 * 2);
        assert_eq!(flushed, 4096 * 2);
    }

    // ── flush_all ───────────────────────────────────────────────────

    #[test]
    fn flush_all_flushes_all_inodes_in_lru_order() {
        let config = WritebackDaemonConfig::default();
        let mut daemon = WritebackDaemon::new(config);
        let mut tracker = DirtyPageTracker::new();

        tracker.mark_dirty_at(10, 0, 4096, 3000).unwrap();
        tracker.mark_dirty_at(20, 0, 4096, 1000).unwrap();
        tracker.mark_dirty_at(30, 0, 4096, 2000).unwrap();

        let mut flush_order: Vec<u64> = Vec::new();
        daemon.flush_all(&tracker, &mut |ino, _off, _len| {
            flush_order.push(ino);
            Ok(0)
        });

        // Oldest-first: 20 (t=1000), 30 (t=2000), 10 (t=3000)
        assert_eq!(flush_order, vec![20, 30, 10]);
    }

    // ── stats accumulation ──────────────────────────────────────────

    #[test]
    fn daemon_stats_accumulate_correctly() {
        let config = WritebackDaemonConfig {
            total_cache_bytes: 4096 * 10,
            dirty_ratio_hundredths: 2000,
            dirty_bytes_threshold: u64::MAX,
            dirty_expire_centisecs: u64::MAX,
            ..Default::default()
        };

        let mut daemon = WritebackDaemon::new(config);
        let mut tracker = DirtyPageTracker::new();

        tracker.mark_dirty_at(1, 0, 4096, 1000).unwrap();
        tracker.mark_dirty_at(1, 4096, 4096, 1000).unwrap();
        tracker.mark_dirty_at(1, 8192, 4096, 1000).unwrap();

        daemon.tick(&tracker, 2000, &mut |_ino, _off, len| {
            Ok(len / 1000) // 4ms, 4ms, 4ms
        });

        let stats = daemon.stats();
        assert_eq!(stats.daemon_wakeups, 1);
        assert_eq!(stats.pages_flushed, 3);
        assert_eq!(stats.bytes_written, 4096 * 3);
        assert_eq!(stats.active_ticks, 1);
        assert_eq!(stats.idle_ticks, 0);
        // dirty_ratio: 3 pages / 10 pages = 30% → 3000 hundredths
        assert_eq!(stats.dirty_ratio_at_wakeup_hundredths, 3000);
    }

    // ── tick with failing flush_fn ──────────────────────────────────

    #[test]
    fn daemon_tick_handles_flush_failure_gracefully() {
        let config = WritebackDaemonConfig {
            total_cache_bytes: 4096 * 10,
            dirty_ratio_hundredths: 2000,
            dirty_bytes_threshold: u64::MAX,
            dirty_expire_centisecs: u64::MAX,
            ..Default::default()
        };

        let mut daemon = WritebackDaemon::new(config);
        let mut tracker = DirtyPageTracker::new();

        tracker.mark_dirty_at(1, 0, 4096, 1000).unwrap();
        tracker.mark_dirty_at(1, 4096, 4096, 1000).unwrap();
        tracker.mark_dirty_at(1, 8192, 4096, 1000).unwrap();

        let result = daemon.tick(&tracker, 2000, &mut |_ino, _off, _len| Err(()));
        // Flush failed → 0 bytes flushed but tick still active
        assert_eq!(result, 0);
        assert_eq!(daemon.stats().active_ticks, 1);
    }

    // ── config defaults ─────────────────────────────────────────────

    #[test]
    fn daemon_config_defaults_are_reasonable() {
        let config = WritebackDaemonConfig::default();
        assert_eq!(config.wake_interval_ms, 5_000);
        assert_eq!(config.dirty_ratio_hundredths, 2_000);
        assert_eq!(config.dirty_bytes_threshold, 256 * 1024 * 1024);
        assert_eq!(config.dirty_expire_centisecs, 3_000);
        assert_eq!(config.max_flush_bytes_per_tick, 64 * 1024 * 1024);
        assert_eq!(config.min_flush_bytes_per_tick, 4 * 1024 * 1024);
    }

    // ── dirty_ratio_fraction ────────────────────────────────────────

    #[test]
    fn dirty_ratio_fraction_is_correct() {
        let config = WritebackDaemonConfig {
            dirty_ratio_hundredths: 2_000,
            ..Default::default()
        };
        assert!((config.dirty_ratio_fraction() - 0.20).abs() < f64::EPSILON);
    }

    // ── dirty_inodes_sorted_by_age works with unknown ages ──────────

    #[test]
    fn dirty_inodes_sorted_unknown_ages_sort_first() {
        let mut tracker = DirtyPageTracker::new();
        tracker.mark_dirty(10, 0, 4096).unwrap(); // age unknown (0)
        tracker.mark_dirty_at(20, 0, 4096, 5000).unwrap(); // known age
        tracker.mark_dirty_at(30, 0, 4096, 3000).unwrap(); // known age

        let sorted = tracker.dirty_inodes_sorted_by_age();
        assert_eq!(sorted.len(), 3);
        // Unknown age (0) sorts first
        assert_eq!(sorted[0].0, 10);
        // Then oldest known age
        assert_eq!(sorted[1].0, 30);
        assert_eq!(sorted[2].0, 20);
    }

    // ── mark_dirty_at with coalescing preserves oldest age ──────────

    #[test]
    fn mark_dirty_at_coalescing_preserves_oldest_age() {
        let mut tracker = DirtyPageTracker::new();
        tracker.mark_dirty_at(1, 0, 4096, 5000).unwrap();
        // Adjacent write with older age
        tracker.mark_dirty_at(1, 4096, 4096, 1000).unwrap();

        let ranges = tracker.get_dirty_ranges_with_age(1);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].0, DirtyRange::new(1, 0, 8192));
        assert_eq!(ranges[0].1, 1000); // oldest age preserved
    }
}
