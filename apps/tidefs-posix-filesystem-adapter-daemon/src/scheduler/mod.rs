// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! P5-02 FUSE scheduler: queue shard creation, worker-pool sizing, backpressure initialization.
//!
//! Part of the P5-02 classified multipool topology for the userspace FUSE runtime.
//! This seam family is one of 10 explicit crate boundaries that separate ingress,
//! scheduling, workers, reply commit, and maintenance so they do not blur
//! into one daemon blob.

use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterBackpressureStateRecord, PosixFilesystemAdapterDirtyExtentWorkItem,
    PosixFilesystemAdapterSessionPhase, PosixFilesystemAdapterSessionRuntimeRecord,
    PosixFilesystemAdapterWorkerPoolSizingRecord, PosixFilesystemAdapterWriteStagingOutcome,
};

/// Re-export all P5-02 request-queue types and runtime functions for this seam family.
pub const SEAM_FAMILY_DOC: &str = concat!("seam.", env!("CARGO_PKG_NAME"), ".    P5-02.v0");

// ── Worker-pool sizing ──────────────────────────────────────────────────────

/// P5-02 §3.3 policy-default sizing constants.
pub mod sizing_defaults {
    /// Minimum reader count.
    pub const MIN_INGRESS_READERS: u32 = 1;
    /// Maximum reader count.
    pub const MAX_INGRESS_READERS: u32 = 4;

    /// Minimum metadata workers.
    pub const MIN_META_WORKERS: u32 = 2;
    /// Maximum metadata workers.
    pub const MAX_META_WORKERS: u32 = 8;

    /// Minimum namespace-mutation workers.
    pub const MIN_NS_MUT_WORKERS: u32 = 2;
    /// Maximum namespace-mutation workers.
    pub const MAX_NS_MUT_WORKERS: u32 = 8;

    /// Minimum directory-stream workers.
    pub const MIN_DIR_STREAM_WORKERS: u32 = 1;
    /// Maximum directory-stream workers.
    pub const MAX_DIR_STREAM_WORKERS: u32 = 4;

    /// Minimum file-read workers.
    pub const MIN_FILE_READ_WORKERS: u32 = 2;
    /// Maximum file-read workers.
    pub const MAX_FILE_READ_WORKERS: u32 = 8;

    /// Minimum file-writeback workers.
    pub const MIN_FILE_WRITEBACK_WORKERS: u32 = 2;
    /// Maximum file-writeback workers.
    pub const MAX_FILE_WRITEBACK_WORKERS: u32 = 8;

    /// Minimum lock-wait workers.
    pub const MIN_LOCK_WAIT_WORKERS: u32 = 1;
    /// Maximum lock-wait workers.
    pub const MAX_LOCK_WAIT_WORKERS: u32 = 4;

    /// Maintenance workers (1 standard, 2 under shadow-pilot).
    pub const MAINTENANCE_WORKERS: u32 = 1;
    pub const MAINTENANCE_WORKERS_SHADOW_PILOT: u32 = 2;

    /// Small-reply committers.
    pub const SMALL_REPLY_COMMITTERS: u32 = 1;

    /// Urgent-control workers.
    pub const URGENT_CONTROL_WORKERS: u32 = 1;
}

/// Clamp a value between min and max.
const fn clamp(value: u32, min: u32, max: u32) -> u32 {
    if value < min {
        min
    } else if value > max {
        max
    } else {
        value
    }
}

/// Compute worker-pool sizing from CPU count according to P5-02 §3.3 policy.
///
/// Sizing rules:
/// - `R` (ingress readers): `clamp(cpu/2, 1, 4)`
/// - `M` (meta workers): `clamp(cpu, 2, 8)`
/// - `N` (namespace-mut workers): `clamp(cpu/2, 2, 8)`
/// - `D` (dir-stream workers): `clamp(cpu/4, 1, 4)`
/// - `W` (file-writeback workers): `clamp(cpu/2, 2, 8)`
/// - `L` (lock-wait workers): `clamp(cpu/4, 1, 4)`
/// - `maintenance`: 1 (2 under shadow-pilot)
/// - `reply.small`: 1
/// - `reply.bulk`: `clamp(cpu/4, 1, 2)`
/// - `urgent_control`: 1
/// - File-read workers follow file-writeback sizing.
#[must_use]
pub const fn default_worker_pool_sizing(
    cpu_count: u32,
    shadow_pilot: bool,
) -> PosixFilesystemAdapterWorkerPoolSizingRecord {
    let cpu = if cpu_count == 0 { 1 } else { cpu_count };

    PosixFilesystemAdapterWorkerPoolSizingRecord {
        ingress_readers: clamp(cpu / 2, 1, 4),
        meta_workers: clamp(cpu, 2, 8),
        namespace_mut_workers: clamp(cpu / 2, 2, 8),
        dir_stream_workers: clamp(cpu / 4, 1, 4),
        file_read_workers: clamp(cpu / 2, 2, 8),
        file_writeback_workers: clamp(cpu / 2, 2, 8),
        lock_wait_workers: clamp(cpu / 4, 1, 4),
        maintenance_workers: if shadow_pilot { 2 } else { 1 },
        small_reply_committers: 1,
        bulk_reply_committers: clamp(cpu / 4, 1, 2),
        urgent_control_workers: 1,
    }
}

// ── Session initialization ──────────────────────────────────────────────────

/// Build a bootstrap-phase session runtime record.
///
/// Maps the sizing record into the runtime topology fields.
#[must_use]
pub fn init_session_bootstrap(
    session_id: u64,
    sizing: &PosixFilesystemAdapterWorkerPoolSizingRecord,
) -> PosixFilesystemAdapterSessionRuntimeRecord {
    PosixFilesystemAdapterSessionRuntimeRecord {
        session_id,
        phase: PosixFilesystemAdapterSessionPhase::Bootstrap.as_u32(),
        ingress_reader_count: sizing.ingress_readers,
        urgent_control_worker_count: sizing.urgent_control_workers,
        meta_worker_count: sizing.meta_workers,
        namespace_mut_worker_count: sizing.namespace_mut_workers,
        dir_stream_worker_count: sizing.dir_stream_workers,
        file_read_worker_count: sizing.file_read_workers,
        file_writeback_worker_count: sizing.file_writeback_workers,
        lock_wait_worker_count: sizing.lock_wait_workers,
        maintenance_worker_count: sizing.maintenance_workers,
        small_reply_committer_count: sizing.small_reply_committers,
        bulk_reply_committer_count: sizing.bulk_reply_committers,
        _reserved: [0_u32; 2],
    }
}

/// Transition a session into steady-state phase.
#[must_use]
pub fn transition_to_steady_state(
    mut session: PosixFilesystemAdapterSessionRuntimeRecord,
) -> PosixFilesystemAdapterSessionRuntimeRecord {
    session.phase = PosixFilesystemAdapterSessionPhase::SteadyState.as_u32();
    session
}

/// Transition a session into draining phase.
#[must_use]
pub fn transition_to_draining(
    mut session: PosixFilesystemAdapterSessionRuntimeRecord,
) -> PosixFilesystemAdapterSessionRuntimeRecord {
    session.phase = PosixFilesystemAdapterSessionPhase::Draining.as_u32();
    session
}

/// Transition a session into terminal phase.
#[must_use]
pub fn transition_to_terminal(
    mut session: PosixFilesystemAdapterSessionRuntimeRecord,
) -> PosixFilesystemAdapterSessionRuntimeRecord {
    session.phase = PosixFilesystemAdapterSessionPhase::Terminal.as_u32();
    session
}

// ── Backpressure initialization ─────────────────────────────────────────────

/// Initialize a fresh backpressure state record (all counters zero).
#[must_use]
pub fn init_backpressure_state() -> PosixFilesystemAdapterBackpressureStateRecord {
    PosixFilesystemAdapterBackpressureStateRecord::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizing_with_4_cpus() {
        let sizing = default_worker_pool_sizing(4, false);
        assert_eq!(sizing.ingress_readers, 2);
        assert_eq!(sizing.meta_workers, 4);
        assert_eq!(sizing.namespace_mut_workers, 2);
        assert_eq!(sizing.dir_stream_workers, 1);
        assert_eq!(sizing.file_read_workers, 2);
        assert_eq!(sizing.file_writeback_workers, 2);
        assert_eq!(sizing.lock_wait_workers, 1);
        assert_eq!(sizing.maintenance_workers, 1);
        assert_eq!(sizing.small_reply_committers, 1);
        assert_eq!(sizing.bulk_reply_committers, 1);
        assert_eq!(sizing.urgent_control_workers, 1);
    }

    #[test]
    fn sizing_with_8_cpus() {
        let sizing = default_worker_pool_sizing(8, false);
        assert_eq!(sizing.ingress_readers, 4);
        assert_eq!(sizing.meta_workers, 8);
        assert_eq!(sizing.namespace_mut_workers, 4);
        assert_eq!(sizing.dir_stream_workers, 2);
        assert_eq!(sizing.file_read_workers, 4);
        assert_eq!(sizing.file_writeback_workers, 4);
        assert_eq!(sizing.lock_wait_workers, 2);
        assert_eq!(sizing.bulk_reply_committers, 2);
    }

    #[test]
    fn sizing_with_shadow_pilot_gives_two_maintenance_workers() {
        let sizing = default_worker_pool_sizing(4, true);
        assert_eq!(sizing.maintenance_workers, 2);
    }

    #[test]
    fn sizing_with_zero_cpus_defaults_to_one() {
        let sizing = default_worker_pool_sizing(0, false);
        assert_eq!(sizing.meta_workers, 2); // clamp(1, 2, 8) = 2
    }

    #[test]
    fn bootstrap_session_has_correct_topology() {
        let sizing = default_worker_pool_sizing(4, false);
        let session = init_session_bootstrap(42, &sizing);
        assert_eq!(session.session_id, 42);
        assert_eq!(
            session.phase,
            PosixFilesystemAdapterSessionPhase::Bootstrap.as_u32()
        );
        assert_eq!(session.meta_worker_count, sizing.meta_workers);
    }

    #[test]
    fn phase_transitions_are_idempotent_for_target() {
        let sizing = default_worker_pool_sizing(4, false);
        let session = init_session_bootstrap(1, &sizing);
        let steady = transition_to_steady_state(session);
        assert_eq!(
            steady.phase,
            PosixFilesystemAdapterSessionPhase::SteadyState.as_u32()
        );
        let terminal = transition_to_terminal(steady);
        assert_eq!(
            terminal.phase,
            PosixFilesystemAdapterSessionPhase::Terminal.as_u32()
        );
    }

    #[test]
    fn backpressure_init_is_zero() {
        let bp = init_backpressure_state();
        assert_eq!(bp.inflight_request_count, 0);
        assert_eq!(bp.inflight_request_bytes, 0);
        assert_eq!(bp.reply_bytes_inflight, 0);
        assert_eq!(bp.dirty_window_bytes, 0);
        assert_eq!(bp.lock_wait_count, 0);
        assert_eq!(bp.maintenance_backlog, 0);
    }
}

// ── Writeback scheduler types ───────────────────────────────────────────────

// ── State machine transition coverage ────────────────────────────

#[test]
fn draining_transition_sets_phase_field() {
    let sizing = default_worker_pool_sizing(4, false);
    let session = init_session_bootstrap(1, &sizing);
    let draining = transition_to_draining(session);
    assert_eq!(
        draining.phase,
        PosixFilesystemAdapterSessionPhase::Draining.as_u32()
    );
}

#[test]
fn transitions_preserve_topology_fields() {
    let sizing = default_worker_pool_sizing(4, false);
    let session = init_session_bootstrap(1, &sizing);
    let steady = transition_to_steady_state(session);
    assert_eq!(steady.meta_worker_count, sizing.meta_workers);
    assert_eq!(
        steady.namespace_mut_worker_count,
        sizing.namespace_mut_workers
    );
    assert_eq!(
        steady.file_writeback_worker_count,
        sizing.file_writeback_workers
    );
    let draining = transition_to_draining(steady);
    assert_eq!(draining.meta_worker_count, sizing.meta_workers);
    assert_eq!(
        draining.file_writeback_worker_count,
        sizing.file_writeback_workers
    );
    let terminal = transition_to_terminal(draining);
    assert_eq!(terminal.meta_worker_count, sizing.meta_workers);
    assert_eq!(
        terminal.file_writeback_worker_count,
        sizing.file_writeback_workers
    );
}

#[test]
fn each_transition_is_idempotent_to_target() {
    let sizing = default_worker_pool_sizing(4, false);
    let session = init_session_bootstrap(1, &sizing);
    let bootstrap_phase = session.phase;
    let again = init_session_bootstrap(1, &sizing);
    assert_eq!(again.phase, bootstrap_phase);

    let steady = transition_to_steady_state(session);
    let steady_phase = steady.phase;
    let steady_twice = transition_to_steady_state(steady);
    assert_eq!(steady_twice.phase, steady_phase);

    let draining = transition_to_draining(session);
    let draining_phase = draining.phase;
    let draining_twice = transition_to_draining(draining);
    assert_eq!(draining_twice.phase, draining_phase);

    let terminal = transition_to_terminal(session);
    let terminal_phase = terminal.phase;
    let terminal_twice = transition_to_terminal(terminal);
    assert_eq!(terminal_twice.phase, terminal_phase);
}

#[test]
fn sequential_bootstrap_steady_draining_terminal_order() {
    let sizing = default_worker_pool_sizing(4, false);
    let session = init_session_bootstrap(1, &sizing);
    assert_eq!(
        session.phase,
        PosixFilesystemAdapterSessionPhase::Bootstrap.as_u32()
    );
    let steady = transition_to_steady_state(session);
    assert_eq!(
        steady.phase,
        PosixFilesystemAdapterSessionPhase::SteadyState.as_u32()
    );
    let draining = transition_to_draining(steady);
    assert_eq!(
        draining.phase,
        PosixFilesystemAdapterSessionPhase::Draining.as_u32()
    );
    let terminal = transition_to_terminal(draining);
    assert_eq!(
        terminal.phase,
        PosixFilesystemAdapterSessionPhase::Terminal.as_u32()
    );
}
/// A unit of writeback work: dirty pages for one object that must be flushed
/// before a transaction group can commit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WritebackWorkItem {
    /// Object identifier in the object store.
    pub object_id: u64,
    /// Start byte offset (inclusive) of the dirty range.
    pub offset_start: u64,
    /// End byte offset (exclusive) of the dirty range.
    pub offset_end: u64,
    /// The transaction group this dirty data belongs to.
    pub commit_group_id: u64,
    /// Number of dirty bytes in this work item.
    pub dirty_byte_count: u64,
    /// Age in milliseconds of the oldest dirty page represented by this item.
    pub oldest_dirty_age_ms: u64,
    /// Monotonic generation counter assigned at enqueue time for tie-breaking.
    pub generation: u64,
}

impl WritebackWorkItem {
    /// Create a writeback work item with generation set to zero.
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

    /// Return this item with an explicit generation.
    #[must_use]
    pub const fn with_generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }

    /// Returns true when `self` has strictly higher writeback priority than `other`.
    ///
    /// Priority order:
    /// 1. Lower `commit_group_id` (older commit_group) goes first.
    /// 2. Within the same commit_group, higher `oldest_dirty_age_ms` goes first.
    /// 3. Within same commit_group and age, higher `dirty_byte_count` goes first.
    /// 4. Within same commit_group, age, and byte count, lower `generation` goes first.
    #[inline]
    fn higher_priority_than(&self, other: &Self) -> bool {
        if self.commit_group_id != other.commit_group_id {
            return self.commit_group_id < other.commit_group_id;
        }
        if self.oldest_dirty_age_ms != other.oldest_dirty_age_ms {
            return self.oldest_dirty_age_ms > other.oldest_dirty_age_ms;
        }
        if self.dirty_byte_count != other.dirty_byte_count {
            return self.dirty_byte_count > other.dirty_byte_count;
        }
        self.generation < other.generation
    }
}

/// Errors returned by front-end dirty-extent scheduler submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirtyExtentSchedulerError {
    Full,
    InvalidRange,
    OutOfWorkItemIds,
}

/// Bounded queue of staged dirty extents waiting for writeback ownership.
pub struct DirtyExtentScheduler<const CAP: usize> {
    items: [PosixFilesystemAdapterDirtyExtentWorkItem; CAP],
    len: usize,
    next_work_item_id: u64,
}

impl<const CAP: usize> DirtyExtentScheduler<CAP> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: [PosixFilesystemAdapterDirtyExtentWorkItem::default(); CAP],
            len: 0,
            next_work_item_id: 1,
        }
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.len == CAP
    }

    #[must_use]
    pub fn as_slice(&self) -> &[PosixFilesystemAdapterDirtyExtentWorkItem] {
        &self.items[..self.len]
    }

    pub fn submit_dirty_extent(
        &mut self,
        outcome: PosixFilesystemAdapterWriteStagingOutcome,
    ) -> Result<u64, DirtyExtentSchedulerError> {
        if self.is_full() {
            return Err(DirtyExtentSchedulerError::Full);
        }
        if outcome.end_offset().is_none() {
            return Err(DirtyExtentSchedulerError::InvalidRange);
        }

        let work_item_id = self.next_work_item_id;
        self.next_work_item_id = self
            .next_work_item_id
            .checked_add(1)
            .ok_or(DirtyExtentSchedulerError::OutOfWorkItemIds)?;

        self.items[self.len] =
            PosixFilesystemAdapterDirtyExtentWorkItem::from_staging_outcome(work_item_id, outcome);
        self.len += 1;
        Ok(work_item_id)
    }
}

impl<const CAP: usize> Default for DirtyExtentScheduler<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors returned by writeback queue operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WritebackQueueError {
    /// The queue is at capacity; push rejected.
    Full,
}

/// Configuration for the writeback scheduler.
#[derive(Clone, Copy, Debug)]
pub struct WritebackSchedulerConfig {
    /// Interval (in milliseconds) between dirty-page scans.
    pub scan_interval_ms: u64,
    /// Maximum number of concurrent in-flight writeback flushes.
    pub max_concurrent_flushes: u32,
    /// Minimum dirty-byte count before a page range is eligible for writeback.
    pub dirty_byte_threshold: u64,
    /// Maximum writeback queue capacity.
    pub queue_capacity: usize,
}

impl Default for WritebackSchedulerConfig {
    fn default() -> Self {
        Self {
            scan_interval_ms: 500,
            max_concurrent_flushes: 4,
            dirty_byte_threshold: 4096,
            queue_capacity: 256,
        }
    }
}

impl WritebackSchedulerConfig {
    /// Create scheduler configuration from explicit tunables.
    #[must_use]
    pub const fn new(
        scan_interval_ms: u64,
        max_concurrent_flushes: u32,
        dirty_byte_threshold: u64,
        queue_capacity: usize,
    ) -> Self {
        Self {
            scan_interval_ms,
            max_concurrent_flushes,
            dirty_byte_threshold,
            queue_capacity,
        }
    }
}

// ── Dirty-page scan input ───────────────────────────────────────────────────

/// Dirty page-range observation produced by a scheduler-local scan pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WritebackDirtyPageRecord {
    /// Object identifier in the object store.
    pub object_id: u64,
    /// Start byte offset (inclusive) of the dirty range.
    pub offset_start: u64,
    /// End byte offset (exclusive) of the dirty range.
    pub offset_end: u64,
    /// Transaction group that owns this dirty range.
    pub commit_group_id: u64,
    /// Number of dirty bytes represented by this range.
    pub dirty_byte_count: u64,
    /// Age in milliseconds of this dirty range.
    pub dirty_age_ms: u64,
}

impl WritebackDirtyPageRecord {
    /// Create a dirty page-range scan record.
    #[must_use]
    pub const fn new(
        object_id: u64,
        offset_start: u64,
        offset_end: u64,
        commit_group_id: u64,
        dirty_byte_count: u64,
        dirty_age_ms: u64,
    ) -> Self {
        Self {
            object_id,
            offset_start,
            offset_end,
            commit_group_id,
            dirty_byte_count,
            dirty_age_ms,
        }
    }

    /// Returns `true` when this record can be merged with the following record.
    #[must_use]
    pub fn is_adjacent_to(&self, next: &Self) -> bool {
        self.object_id == next.object_id
            && self.commit_group_id == next.commit_group_id
            && self.offset_end == next.offset_start
    }

    fn validate(&self) -> Result<(), WritebackDirtyScanError> {
        if self.offset_start >= self.offset_end {
            return Err(WritebackDirtyScanError::InvalidRange);
        }
        if self.dirty_byte_count == 0 {
            return Err(WritebackDirtyScanError::ZeroDirtyBytes);
        }
        Ok(())
    }

    fn into_work_item(self) -> WritebackWorkItem {
        WritebackWorkItem {
            object_id: self.object_id,
            offset_start: self.offset_start,
            offset_end: self.offset_end,
            commit_group_id: self.commit_group_id,
            dirty_byte_count: self.dirty_byte_count,
            oldest_dirty_age_ms: self.dirty_age_ms,
            generation: 0,
        }
    }
}

/// Errors returned by dirty scan batching and enqueue operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WritebackDirtyScanError {
    /// The scan batch has no free record slot.
    BatchFull,
    /// A dirty range had `offset_start >= offset_end`.
    InvalidRange,
    /// A dirty range reported zero dirty bytes.
    ZeroDirtyBytes,
    /// Grouped dirty work could not fit in the writeback queue.
    QueueFull,
}

/// Fixed-size dirty scan batch.
pub struct WritebackDirtyScanBatch<const CAP: usize> {
    records: [WritebackDirtyPageRecord; CAP],
    len: usize,
}

impl<const CAP: usize> WritebackDirtyScanBatch<CAP> {
    /// Create an empty dirty scan batch.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: [WritebackDirtyPageRecord::default(); CAP],
            len: 0,
        }
    }

    /// Number of records in the batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when the batch has no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Maximum number of records this batch can hold.
    #[must_use]
    pub fn capacity(&self) -> usize {
        CAP
    }

    /// Add a dirty page record to the scan batch.
    pub fn push(
        &mut self,
        record: WritebackDirtyPageRecord,
    ) -> Result<(), WritebackDirtyScanError> {
        if self.len == CAP {
            return Err(WritebackDirtyScanError::BatchFull);
        }
        record.validate()?;
        self.records[self.len] = record;
        self.len += 1;
        Ok(())
    }

    /// Access scan records as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[WritebackDirtyPageRecord] {
        &self.records[..self.len]
    }

    /// Group adjacent compatible records into writeback work items.
    #[must_use]
    pub fn group_adjacent(&self) -> WritebackDirtyScanGroups<CAP> {
        let mut groups = WritebackDirtyScanGroups::new();
        let mut cursor = 0;

        while cursor < self.len {
            let mut item = self.records[cursor].into_work_item();
            cursor += 1;

            while cursor < self.len {
                let current_tail = WritebackDirtyPageRecord {
                    object_id: item.object_id,
                    offset_start: item.offset_start,
                    offset_end: item.offset_end,
                    commit_group_id: item.commit_group_id,
                    dirty_byte_count: item.dirty_byte_count,
                    dirty_age_ms: item.oldest_dirty_age_ms,
                };
                let next = self.records[cursor];
                if !current_tail.is_adjacent_to(&next) {
                    break;
                }

                item.offset_end = next.offset_end;
                item.dirty_byte_count = item.dirty_byte_count.saturating_add(next.dirty_byte_count);
                if next.dirty_age_ms > item.oldest_dirty_age_ms {
                    item.oldest_dirty_age_ms = next.dirty_age_ms;
                }
                cursor += 1;
            }

            groups.push_group(item);
        }

        groups
    }

    /// Group and enqueue dirty records, rejecting the whole batch if capacity is insufficient.
    pub fn enqueue_grouped<const QUEUE_CAP: usize, const IN_FLIGHT_CAP: usize>(
        &self,
        state: &mut WritebackDispatchState<QUEUE_CAP, IN_FLIGHT_CAP>,
    ) -> Result<WritebackDirtyScanEnqueueSummary, WritebackDirtyScanError> {
        let groups = self.group_adjacent();
        if groups.len() > state.queue().remaining_capacity() {
            return Err(WritebackDirtyScanError::QueueFull);
        }

        let mut dirty_byte_count = 0_u64;
        for item in groups.as_slice() {
            dirty_byte_count = dirty_byte_count.saturating_add(item.dirty_byte_count);
            state
                .enqueue(*item)
                .map_err(|_| WritebackDirtyScanError::QueueFull)?;
        }

        Ok(WritebackDirtyScanEnqueueSummary {
            scanned_records: self.len,
            grouped_items: groups.len(),
            enqueued_items: groups.len(),
            dirty_byte_count,
        })
    }
}

impl<const CAP: usize> Default for WritebackDirtyScanBatch<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

/// Grouped writeback items produced by a dirty scan batch.
pub struct WritebackDirtyScanGroups<const CAP: usize> {
    items: [WritebackWorkItem; CAP],
    len: usize,
}

impl<const CAP: usize> WritebackDirtyScanGroups<CAP> {
    fn new() -> Self {
        Self {
            items: [WritebackWorkItem::default(); CAP],
            len: 0,
        }
    }

    fn push_group(&mut self, item: WritebackWorkItem) {
        self.items[self.len] = item;
        self.len += 1;
    }

    /// Number of grouped writeback items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when no groups were produced.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Access grouped work items as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[WritebackWorkItem] {
        &self.items[..self.len]
    }
}

/// Summary returned after dirty scan records are grouped and enqueued.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WritebackDirtyScanEnqueueSummary {
    /// Number of dirty records scanned.
    pub scanned_records: usize,
    /// Number of grouped writeback work items.
    pub grouped_items: usize,
    /// Number of writeback work items enqueued.
    pub enqueued_items: usize,
    /// Total dirty bytes represented by enqueued work.
    pub dirty_byte_count: u64,
}

impl WritebackDirtyScanEnqueueSummary {
    /// Create an enqueue summary from explicit counts.
    #[must_use]
    pub const fn new(
        scanned_records: usize,
        grouped_items: usize,
        enqueued_items: usize,
        dirty_byte_count: u64,
    ) -> Self {
        Self {
            scanned_records,
            grouped_items,
            enqueued_items,
            dirty_byte_count,
        }
    }
}

// ── WritebackQueue ──────────────────────────────────────────────────────────

/// A bounded-capacity priority queue for writeback work items.
///
/// Implemented as a binary min-heap over a fixed-size array, supporting
/// `push`, `pop`, `peek`, and capacity queries. When the queue is full,
/// `push` returns `WritebackQueueError::Full` (backpressure signal).
///
/// Heap invariant: the root (index 0) is the item with the *highest* writeback
/// priority according to `WritebackWorkItem::higher_priority_than`.
pub struct WritebackQueue<const CAP: usize> {
    items: [WritebackWorkItem; CAP],
    len: usize,
    generation_counter: u64,
}

impl<const CAP: usize> WritebackQueue<CAP> {
    /// Create an empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: [WritebackWorkItem::default(); CAP],
            len: 0,
            generation_counter: 0,
        }
    }

    /// Number of items currently in the queue.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` when the queue is at capacity.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.len == CAP
    }

    /// Returns `true` when queued work exists for `commit_group_id`.
    #[must_use]
    pub fn contains_commit_group(&self, commit_group_id: u64) -> bool {
        self.items[..self.len]
            .iter()
            .any(|item| item.commit_group_id == commit_group_id)
    }

    /// Maximum capacity of the queue.
    #[must_use]
    pub fn capacity(&self) -> usize {
        CAP
    }

    /// Remaining number of items the queue can accept.
    #[must_use]
    pub fn remaining_capacity(&self) -> usize {
        CAP - self.len
    }

    /// Peek at the highest-priority item without removing it.
    #[must_use]
    pub fn peek(&self) -> Option<&WritebackWorkItem> {
        if self.is_empty() {
            None
        } else {
            Some(&self.items[0])
        }
    }

    /// Push a work item onto the queue.
    ///
    /// Assigns a monotonic `generation` to the item before insertion.
    /// Returns `Err(WritebackQueueError::Full)` when at capacity.
    pub fn push(&mut self, item: WritebackWorkItem) -> Result<(), WritebackQueueError> {
        if self.is_full() {
            return Err(WritebackQueueError::Full);
        }
        let mut item = item;
        item.generation = self.generation_counter;
        self.generation_counter = self.generation_counter.wrapping_add(1);

        let idx = self.len;
        self.items[idx] = item;
        self.len += 1;
        self.bubble_up(idx);
        Ok(())
    }

    /// Remove and return the highest-priority item, or `None` if empty.
    pub fn pop(&mut self) -> Option<WritebackWorkItem> {
        if self.is_empty() {
            return None;
        }
        let result = self.items[0];
        self.len -= 1;
        if self.len > 0 {
            self.items[0] = self.items[self.len];
            self.bubble_down(0);
        }
        Some(result)
    }

    /// Drain all items belonging to `commit_group_id`, returning them in priority order.
    ///
    /// After this call, the queue contains only items whose `commit_group_id` differs
    /// from the requested one. The caller receives all matching items in a
    /// fixed-size array (up to `CAP`).
    pub fn drain_commit_group(&mut self, commit_group_id: u64) -> DrainCommitGroup<CAP> {
        let mut drained = [WritebackWorkItem::default(); CAP];
        let mut drained_count: usize = 0;
        let mut keep = [WritebackWorkItem::default(); CAP];
        let mut keep_count: usize = 0;

        // Pop all items and partition by commit_group_id.
        while let Some(item) = self.pop() {
            if item.commit_group_id == commit_group_id {
                drained[drained_count] = item;
                drained_count += 1;
            } else {
                keep[keep_count] = item;
                keep_count += 1;
            }
        }

        // Re-heapify the kept items.
        for &item in keep[..keep_count].iter() {
            let idx = self.len;
            self.items[idx] = item;
            self.len += 1;
            self.bubble_up(idx);
        }

        DrainCommitGroup {
            items: drained,
            len: drained_count,
        }
    }

    // ── heap helpers ────────────────────────────────────────────────────────

    fn bubble_up(&mut self, mut idx: usize) {
        while idx > 0 {
            let parent = (idx - 1) / 2;
            if self.items[idx].higher_priority_than(&self.items[parent]) {
                self.items.swap(idx, parent);
                idx = parent;
            } else {
                break;
            }
        }
    }

    fn bubble_down(&mut self, mut idx: usize) {
        loop {
            let left = 2 * idx + 1;
            let right = 2 * idx + 2;
            let mut best = idx;

            if left < self.len && self.items[left].higher_priority_than(&self.items[best]) {
                best = left;
            }
            if right < self.len && self.items[right].higher_priority_than(&self.items[best]) {
                best = right;
            }
            if best != idx {
                self.items.swap(idx, best);
                idx = best;
            } else {
                break;
            }
        }
    }
}

impl<const CAP: usize> Default for WritebackQueue<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

/// Collection returned by `WritebackQueue::drain_commit_group`.
pub struct DrainCommitGroup<const CAP: usize> {
    items: [WritebackWorkItem; CAP],
    len: usize,
}

impl<const CAP: usize> DrainCommitGroup<CAP> {
    /// Number of drained items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when no items were drained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Access drained items as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[WritebackWorkItem] {
        &self.items[..self.len]
    }
}

// ── Writeback dispatch / in-flight tracking ────────────────────────────────

/// Errors returned by writeback dispatch-state operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WritebackDispatchError {
    /// No queued writeback work is available for dispatch.
    QueueEmpty,
    /// The in-flight table is at capacity; dispatch must wait for completion.
    InFlightFull,
    /// No in-flight writeback ticket matches the requested ticket id.
    UnknownTicket,
    /// A retry completion could not be requeued because the queue is full.
    RequeueFull,
}

/// A scheduler-local ticket representing work dispatched to the writeback lane.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WritebackDispatchTicket {
    /// Monotonic scheduler-local ticket id.
    pub ticket_id: u64,
    /// The writeback item associated with this ticket.
    pub item: WritebackWorkItem,
}

impl WritebackDispatchTicket {
    /// Create a dispatch ticket for a writeback item.
    #[must_use]
    pub const fn new(ticket_id: u64, item: WritebackWorkItem) -> Self {
        Self { ticket_id, item }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct WritebackInFlightSlot {
    occupied: bool,
    ticket: WritebackDispatchTicket,
}

/// Scheduler-local bridge between a writeback queue and bounded in-flight work.
///
/// This does not call object IO or worker-pool APIs directly. It only models the
/// state transition from queued writeback work to a ticketed in-flight flush, so
/// the later worker integration can preserve ordering and backpressure.
pub struct WritebackDispatchState<const QUEUE_CAP: usize, const IN_FLIGHT_CAP: usize> {
    queue: WritebackQueue<QUEUE_CAP>,
    in_flight: [WritebackInFlightSlot; IN_FLIGHT_CAP],
    in_flight_count: usize,
    next_ticket_id: u64,
}

impl<const QUEUE_CAP: usize, const IN_FLIGHT_CAP: usize>
    WritebackDispatchState<QUEUE_CAP, IN_FLIGHT_CAP>
{
    /// Create an empty dispatch state.
    #[must_use]
    pub fn new() -> Self {
        Self::from_queue(WritebackQueue::new())
    }

    /// Create dispatch state around an existing queue.
    #[must_use]
    pub fn from_queue(queue: WritebackQueue<QUEUE_CAP>) -> Self {
        Self {
            queue,
            in_flight: [WritebackInFlightSlot::default(); IN_FLIGHT_CAP],
            in_flight_count: 0,
            next_ticket_id: 1,
        }
    }

    /// Borrow the queued writeback work.
    #[must_use]
    pub fn queue(&self) -> &WritebackQueue<QUEUE_CAP> {
        &self.queue
    }

    /// Number of queued writeback items.
    #[must_use]
    pub fn queued_len(&self) -> usize {
        self.queue.len()
    }

    /// Number of in-flight writeback items.
    #[must_use]
    pub fn in_flight_len(&self) -> usize {
        self.in_flight_count
    }

    /// Maximum number of concurrent in-flight writeback items.
    #[must_use]
    pub fn in_flight_capacity(&self) -> usize {
        IN_FLIGHT_CAP
    }

    /// Returns `true` when the in-flight table cannot accept another dispatch.
    #[must_use]
    pub fn is_in_flight_full(&self) -> bool {
        self.in_flight_count == IN_FLIGHT_CAP
    }

    /// Enqueue writeback work, preserving `WritebackQueue` backpressure.
    pub fn enqueue(&mut self, item: WritebackWorkItem) -> Result<(), WritebackQueueError> {
        self.queue.push(item)
    }

    /// Dispatch the next queued item into the in-flight table.
    pub fn dispatch_next(&mut self) -> Result<WritebackDispatchTicket, WritebackDispatchError> {
        if self.queue.is_empty() {
            return Err(WritebackDispatchError::QueueEmpty);
        }
        let slot_idx = self
            .first_free_in_flight_slot()
            .ok_or(WritebackDispatchError::InFlightFull)?;
        let item = self.queue.pop().ok_or(WritebackDispatchError::QueueEmpty)?;
        Ok(self.dispatch_item_into_slot(slot_idx, item))
    }

    /// Begin a transaction-group flush barrier by draining queued work for `commit_group_id`.
    #[must_use]
    pub fn begin_commit_group_flush(
        &mut self,
        commit_group_id: u64,
    ) -> WritebackCommitGroupFlushBarrier<QUEUE_CAP> {
        WritebackCommitGroupFlushBarrier::from_drained(
            commit_group_id,
            self.queue.drain_commit_group(commit_group_id),
        )
    }

    /// Dispatch the next item owned by a transaction-group flush barrier.
    pub fn dispatch_commit_group_flush_next(
        &mut self,
        barrier: &mut WritebackCommitGroupFlushBarrier<QUEUE_CAP>,
    ) -> Result<Option<WritebackDispatchTicket>, WritebackDispatchError> {
        let Some(item) = barrier.peek_next_pending() else {
            return Ok(None);
        };

        let ticket = self.dispatch_item(item)?;
        barrier.mark_dispatched();
        Ok(Some(ticket))
    }

    /// Returns `true` when a commit_group flush barrier has no pending or in-flight work.
    #[must_use]
    pub fn is_commit_group_flush_complete(
        &self,
        barrier: &WritebackCommitGroupFlushBarrier<QUEUE_CAP>,
    ) -> bool {
        barrier.is_dispatch_complete() && self.is_commit_group_idle(barrier.commit_group_id())
    }

    /// Complete an in-flight ticket and remove it from in-flight accounting.
    pub fn complete(
        &mut self,
        ticket_id: u64,
    ) -> Result<WritebackWorkItem, WritebackDispatchError> {
        let slot_idx = self
            .find_in_flight_slot(ticket_id)
            .ok_or(WritebackDispatchError::UnknownTicket)?;
        let item = self.in_flight[slot_idx].ticket.item;

        self.in_flight[slot_idx] = WritebackInFlightSlot::default();
        self.in_flight_count -= 1;
        Ok(item)
    }

    /// Complete an in-flight ticket by requeueing its work for retry.
    pub fn retry(&mut self, ticket_id: u64) -> Result<(), WritebackDispatchError> {
        let slot_idx = self
            .find_in_flight_slot(ticket_id)
            .ok_or(WritebackDispatchError::UnknownTicket)?;
        if self.queue.is_full() {
            return Err(WritebackDispatchError::RequeueFull);
        }

        let item = self.in_flight[slot_idx].ticket.item;
        self.in_flight[slot_idx] = WritebackInFlightSlot::default();
        self.in_flight_count -= 1;
        self.queue
            .push(item)
            .map_err(|_| WritebackDispatchError::RequeueFull)
    }

    /// Number of in-flight items for a transaction group.
    #[must_use]
    pub fn in_flight_count_for_commit_group(&self, commit_group_id: u64) -> usize {
        self.in_flight
            .iter()
            .filter(|slot| slot.occupied && slot.ticket.item.commit_group_id == commit_group_id)
            .count()
    }

    /// Returns `true` when a transaction group has no queued or in-flight work.
    #[must_use]
    pub fn is_commit_group_idle(&self, commit_group_id: u64) -> bool {
        !self.queue.contains_commit_group(commit_group_id)
            && self.in_flight_count_for_commit_group(commit_group_id) == 0
    }

    fn first_free_in_flight_slot(&self) -> Option<usize> {
        self.in_flight.iter().position(|slot| !slot.occupied)
    }

    fn find_in_flight_slot(&self, ticket_id: u64) -> Option<usize> {
        self.in_flight
            .iter()
            .position(|slot| slot.occupied && slot.ticket.ticket_id == ticket_id)
    }

    fn dispatch_item(
        &mut self,
        item: WritebackWorkItem,
    ) -> Result<WritebackDispatchTicket, WritebackDispatchError> {
        let slot_idx = self
            .first_free_in_flight_slot()
            .ok_or(WritebackDispatchError::InFlightFull)?;
        Ok(self.dispatch_item_into_slot(slot_idx, item))
    }

    fn dispatch_item_into_slot(
        &mut self,
        slot_idx: usize,
        item: WritebackWorkItem,
    ) -> WritebackDispatchTicket {
        let ticket = WritebackDispatchTicket {
            ticket_id: self.allocate_ticket_id(),
            item,
        };

        self.in_flight[slot_idx] = WritebackInFlightSlot {
            occupied: true,
            ticket,
        };
        self.in_flight_count += 1;
        ticket
    }

    fn allocate_ticket_id(&mut self) -> u64 {
        let ticket_id = self.next_ticket_id;
        self.next_ticket_id = self.next_ticket_id.wrapping_add(1);
        if self.next_ticket_id == 0 {
            self.next_ticket_id = 1;
        }
        ticket_id
    }
}

/// Scheduler-local state for one transaction-group flush barrier.
pub struct WritebackCommitGroupFlushBarrier<const CAP: usize> {
    commit_group_id: u64,
    items: [WritebackWorkItem; CAP],
    len: usize,
    dispatched: usize,
}

impl<const CAP: usize> WritebackCommitGroupFlushBarrier<CAP> {
    fn from_drained(commit_group_id: u64, drained: DrainCommitGroup<CAP>) -> Self {
        Self {
            commit_group_id,
            items: drained.items,
            len: drained.len,
            dispatched: 0,
        }
    }

    /// Transaction group guarded by this flush barrier.
    #[must_use]
    pub fn commit_group_id(&self) -> u64 {
        self.commit_group_id
    }

    /// Number of items drained from the queue when the barrier began.
    #[must_use]
    pub fn drained_len(&self) -> usize {
        self.len
    }

    /// Number of drained items already dispatched.
    #[must_use]
    pub fn dispatched_len(&self) -> usize {
        self.dispatched
    }

    /// Number of drained items still waiting for dispatch.
    #[must_use]
    pub fn pending_dispatch_len(&self) -> usize {
        self.len - self.dispatched
    }

    /// Dirty bytes represented by this flush barrier.
    #[must_use]
    pub fn dirty_byte_count(&self) -> u64 {
        self.items[..self.len]
            .iter()
            .fold(0_u64, |acc, item| acc.saturating_add(item.dirty_byte_count))
    }

    /// Returns `true` when all drained items have been dispatched.
    #[must_use]
    pub fn is_dispatch_complete(&self) -> bool {
        self.dispatched == self.len
    }

    fn peek_next_pending(&self) -> Option<WritebackWorkItem> {
        if self.is_dispatch_complete() {
            None
        } else {
            Some(self.items[self.dispatched])
        }
    }

    fn mark_dispatched(&mut self) {
        self.dispatched += 1;
    }
}

// ── Writeback lifecycle events ──────────────────────────────────────────────

/// Scheduler-local writeback lifecycle event kind.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WritebackLifecycleEventKind {
    /// Dirty scan records were grouped and accepted into the writeback queue.
    DirtyScanEnqueued = 0,
    /// A writeback item was dispatched into the in-flight table.
    DispatchStarted = 1,
    /// An in-flight writeback item was requeued for retry.
    DispatchRetried = 2,
    /// An in-flight writeback item completed.
    DispatchCompleted = 3,
    /// A transaction-group flush barrier started.
    CommitGroupFlushStarted = 4,
    /// A transaction-group flush barrier completed.
    CommitGroupFlushCompleted = 5,
}

impl Default for WritebackLifecycleEventKind {
    fn default() -> Self {
        Self::DirtyScanEnqueued
    }
}

/// Scheduler-local writeback lifecycle status.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WritebackLifecycleStatus {
    /// Work was accepted by the scheduler-local state machine.
    Accepted = 0,
    /// Work is in flight.
    InFlight = 1,
    /// Work was requeued for retry.
    Retried = 2,
    /// Work or a barrier completed.
    Completed = 3,
    /// Work was refused due to local backpressure.
    Backpressured = 4,
}

impl Default for WritebackLifecycleStatus {
    fn default() -> Self {
        Self::Accepted
    }
}

/// Scheduler-local writeback lifecycle event.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WritebackLifecycleEvent {
    /// Monotonic sequence id assigned by `WritebackLifecycleTrace`.
    pub sequence_id: u64,
    /// Event kind.
    pub kind: WritebackLifecycleEventKind,
    /// Event status.
    pub status: WritebackLifecycleStatus,
    /// Transaction group associated with this event, or zero when not singular.
    pub commit_group_id: u64,
    /// Object id associated with this event, or zero when not singular.
    pub object_id: u64,
    /// Dispatch ticket id associated with this event, or zero when not applicable.
    pub ticket_id: u64,
    /// Number of dirty scan records represented by this event.
    pub scanned_records: usize,
    /// Number of writeback work items represented by this event.
    pub work_item_count: usize,
    /// Dirty bytes represented by this event.
    pub dirty_byte_count: u64,
    /// Queue depth observed after the event.
    pub queue_depth: usize,
    /// In-flight count observed after the event.
    pub in_flight_count: usize,
}

/// Draft lifecycle event before sequence assignment.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WritebackLifecycleEventDraft {
    /// Event kind.
    pub kind: WritebackLifecycleEventKind,
    /// Event status.
    pub status: WritebackLifecycleStatus,
    /// Transaction group associated with this event, or zero when not singular.
    pub commit_group_id: u64,
    /// Object id associated with this event, or zero when not singular.
    pub object_id: u64,
    /// Dispatch ticket id associated with this event, or zero when not applicable.
    pub ticket_id: u64,
    /// Number of dirty scan records represented by this event.
    pub scanned_records: usize,
    /// Number of writeback work items represented by this event.
    pub work_item_count: usize,
    /// Dirty bytes represented by this event.
    pub dirty_byte_count: u64,
    /// Queue depth observed after the event.
    pub queue_depth: usize,
    /// In-flight count observed after the event.
    pub in_flight_count: usize,
}

impl WritebackLifecycleEventDraft {
    /// Create an event draft with zero ids and counts.
    #[must_use]
    pub const fn new(kind: WritebackLifecycleEventKind, status: WritebackLifecycleStatus) -> Self {
        Self {
            kind,
            status,
            commit_group_id: 0,
            object_id: 0,
            ticket_id: 0,
            scanned_records: 0,
            work_item_count: 0,
            dirty_byte_count: 0,
            queue_depth: 0,
            in_flight_count: 0,
        }
    }

    /// Return this draft with commit_group and object ids set.
    #[must_use]
    pub const fn with_commit_group_object(mut self, commit_group_id: u64, object_id: u64) -> Self {
        self.commit_group_id = commit_group_id;
        self.object_id = object_id;
        self
    }

    /// Return this draft with a dispatch ticket id set.
    #[must_use]
    pub const fn with_ticket_id(mut self, ticket_id: u64) -> Self {
        self.ticket_id = ticket_id;
        self
    }

    /// Return this draft with scan/work item counts set.
    #[must_use]
    pub const fn with_counts(
        mut self,
        scanned_records: usize,
        work_item_count: usize,
        dirty_byte_count: u64,
    ) -> Self {
        self.scanned_records = scanned_records;
        self.work_item_count = work_item_count;
        self.dirty_byte_count = dirty_byte_count;
        self
    }

    /// Return this draft with queue and in-flight depths set.
    #[must_use]
    pub const fn with_depths(mut self, queue_depth: usize, in_flight_count: usize) -> Self {
        self.queue_depth = queue_depth;
        self.in_flight_count = in_flight_count;
        self
    }
}

/// Errors returned by lifecycle trace operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WritebackLifecycleTraceError {
    /// The trace buffer is full.
    Full,
}

/// Fixed-size scheduler-local lifecycle trace.
pub struct WritebackLifecycleTrace<const CAP: usize> {
    events: [WritebackLifecycleEvent; CAP],
    len: usize,
    next_sequence_id: u64,
}

impl<const CAP: usize> WritebackLifecycleTrace<CAP> {
    /// Create an empty lifecycle trace.
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: [WritebackLifecycleEvent::default(); CAP],
            len: 0,
            next_sequence_id: 1,
        }
    }

    /// Number of events currently retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when the trace has no events.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` when the trace cannot accept another event.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.len == CAP
    }

    /// Access retained lifecycle events.
    #[must_use]
    pub fn as_slice(&self) -> &[WritebackLifecycleEvent] {
        &self.events[..self.len]
    }

    /// Record a lifecycle event draft and assign the next sequence id.
    pub fn record(
        &mut self,
        draft: WritebackLifecycleEventDraft,
    ) -> Result<WritebackLifecycleEvent, WritebackLifecycleTraceError> {
        if self.is_full() {
            return Err(WritebackLifecycleTraceError::Full);
        }

        let event = WritebackLifecycleEvent {
            sequence_id: self.next_sequence_id,
            kind: draft.kind,
            status: draft.status,
            commit_group_id: draft.commit_group_id,
            object_id: draft.object_id,
            ticket_id: draft.ticket_id,
            scanned_records: draft.scanned_records,
            work_item_count: draft.work_item_count,
            dirty_byte_count: draft.dirty_byte_count,
            queue_depth: draft.queue_depth,
            in_flight_count: draft.in_flight_count,
        };
        self.next_sequence_id = self.next_sequence_id.wrapping_add(1);
        if self.next_sequence_id == 0 {
            self.next_sequence_id = 1;
        }
        self.events[self.len] = event;
        self.len += 1;
        Ok(event)
    }

    /// Record a successful dirty scan enqueue.
    pub fn record_scan_enqueue(
        &mut self,
        summary: WritebackDirtyScanEnqueueSummary,
        queue_depth: usize,
    ) -> Result<WritebackLifecycleEvent, WritebackLifecycleTraceError> {
        self.record(WritebackLifecycleEventDraft {
            kind: WritebackLifecycleEventKind::DirtyScanEnqueued,
            status: WritebackLifecycleStatus::Accepted,
            scanned_records: summary.scanned_records,
            work_item_count: summary.enqueued_items,
            dirty_byte_count: summary.dirty_byte_count,
            queue_depth,
            ..WritebackLifecycleEventDraft::default()
        })
    }

    /// Record dispatch into the in-flight table.
    pub fn record_dispatch_started(
        &mut self,
        ticket: WritebackDispatchTicket,
        queue_depth: usize,
        in_flight_count: usize,
    ) -> Result<WritebackLifecycleEvent, WritebackLifecycleTraceError> {
        self.record(WritebackLifecycleEventDraft {
            kind: WritebackLifecycleEventKind::DispatchStarted,
            status: WritebackLifecycleStatus::InFlight,
            commit_group_id: ticket.item.commit_group_id,
            object_id: ticket.item.object_id,
            ticket_id: ticket.ticket_id,
            work_item_count: 1,
            dirty_byte_count: ticket.item.dirty_byte_count,
            queue_depth,
            in_flight_count,
            ..WritebackLifecycleEventDraft::default()
        })
    }

    /// Record a retry requeue.
    pub fn record_dispatch_retried(
        &mut self,
        ticket_id: u64,
        item: WritebackWorkItem,
        queue_depth: usize,
        in_flight_count: usize,
    ) -> Result<WritebackLifecycleEvent, WritebackLifecycleTraceError> {
        self.record(WritebackLifecycleEventDraft {
            kind: WritebackLifecycleEventKind::DispatchRetried,
            status: WritebackLifecycleStatus::Retried,
            commit_group_id: item.commit_group_id,
            object_id: item.object_id,
            ticket_id,
            work_item_count: 1,
            dirty_byte_count: item.dirty_byte_count,
            queue_depth,
            in_flight_count,
            ..WritebackLifecycleEventDraft::default()
        })
    }

    /// Record dispatch completion.
    pub fn record_dispatch_completed(
        &mut self,
        ticket_id: u64,
        item: WritebackWorkItem,
        queue_depth: usize,
        in_flight_count: usize,
    ) -> Result<WritebackLifecycleEvent, WritebackLifecycleTraceError> {
        self.record(WritebackLifecycleEventDraft {
            kind: WritebackLifecycleEventKind::DispatchCompleted,
            status: WritebackLifecycleStatus::Completed,
            commit_group_id: item.commit_group_id,
            object_id: item.object_id,
            ticket_id,
            work_item_count: 1,
            dirty_byte_count: item.dirty_byte_count,
            queue_depth,
            in_flight_count,
            ..WritebackLifecycleEventDraft::default()
        })
    }

    /// Record commit_group flush barrier start.
    pub fn record_commit_group_flush_started<const BARRIER_CAP: usize>(
        &mut self,
        barrier: &WritebackCommitGroupFlushBarrier<BARRIER_CAP>,
        queue_depth: usize,
        in_flight_count: usize,
    ) -> Result<WritebackLifecycleEvent, WritebackLifecycleTraceError> {
        self.record(WritebackLifecycleEventDraft {
            kind: WritebackLifecycleEventKind::CommitGroupFlushStarted,
            status: WritebackLifecycleStatus::Accepted,
            commit_group_id: barrier.commit_group_id(),
            work_item_count: barrier.drained_len(),
            dirty_byte_count: barrier.dirty_byte_count(),
            queue_depth,
            in_flight_count,
            ..WritebackLifecycleEventDraft::default()
        })
    }

    /// Record commit_group flush barrier completion.
    pub fn record_commit_group_flush_completed<const BARRIER_CAP: usize>(
        &mut self,
        barrier: &WritebackCommitGroupFlushBarrier<BARRIER_CAP>,
        queue_depth: usize,
        in_flight_count: usize,
    ) -> Result<WritebackLifecycleEvent, WritebackLifecycleTraceError> {
        self.record(WritebackLifecycleEventDraft {
            kind: WritebackLifecycleEventKind::CommitGroupFlushCompleted,
            status: WritebackLifecycleStatus::Completed,
            commit_group_id: barrier.commit_group_id(),
            work_item_count: barrier.drained_len(),
            dirty_byte_count: barrier.dirty_byte_count(),
            queue_depth,
            in_flight_count,
            ..WritebackLifecycleEventDraft::default()
        })
    }
}

impl<const CAP: usize> Default for WritebackLifecycleTrace<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const QUEUE_CAP: usize, const IN_FLIGHT_CAP: usize> Default
    for WritebackDispatchState<QUEUE_CAP, IN_FLIGHT_CAP>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod writeback_tests {
    use super::*;

    fn item(object_id: u64, commit_group_id: u64, dirty_byte_count: u64) -> WritebackWorkItem {
        WritebackWorkItem {
            object_id,
            offset_start: 0,
            offset_end: dirty_byte_count,
            commit_group_id,
            dirty_byte_count,
            oldest_dirty_age_ms: 0,
            generation: 0,
        }
    }

    fn item_with_age(
        object_id: u64,
        commit_group_id: u64,
        dirty_byte_count: u64,
        oldest_dirty_age_ms: u64,
    ) -> WritebackWorkItem {
        WritebackWorkItem {
            object_id,
            offset_start: 0,
            offset_end: dirty_byte_count,
            commit_group_id,
            dirty_byte_count,
            oldest_dirty_age_ms,
            generation: 0,
        }
    }

    fn dirty(
        object_id: u64,
        offset_start: u64,
        offset_end: u64,
        commit_group_id: u64,
        dirty_byte_count: u64,
        dirty_age_ms: u64,
    ) -> WritebackDirtyPageRecord {
        WritebackDirtyPageRecord {
            object_id,
            offset_start,
            offset_end,
            commit_group_id,
            dirty_byte_count,
            dirty_age_ms,
        }
    }

    fn staging_outcome(
        inode: u64,
        offset: u64,
        length: u32,
    ) -> PosixFilesystemAdapterWriteStagingOutcome {
        PosixFilesystemAdapterWriteStagingOutcome {
            unique: 70,
            inode,
            offset,
            length,
            buffer_handle: 900,
            content_hash64: 0xABCD,
            write_flags: 2,
            _reserved: [0_u32; 1],
        }
    }

    #[test]
    fn dirty_extent_scheduler_submits_staged_write() {
        let mut scheduler = DirtyExtentScheduler::<4>::new();
        let id = scheduler
            .submit_dirty_extent(staging_outcome(42, 4096, 8192))
            .expect("submit dirty extent");

        assert_eq!(id, 1);
        assert_eq!(scheduler.len(), 1);
        let item = scheduler.as_slice()[0];
        assert_eq!(item.work_item_id, 1);
        assert_eq!(item.unique, 70);
        assert_eq!(item.inode, 42);
        assert_eq!(item.offset, 4096);
        assert_eq!(item.length, 8192);
        assert_eq!(item.buffer_handle, 900);
        assert_eq!(item.content_hash64, 0xABCD);
        assert_eq!(item.write_flags, 2);
    }

    #[test]
    fn dirty_extent_scheduler_assigns_monotonic_ids() {
        let mut scheduler = DirtyExtentScheduler::<4>::new();

        assert_eq!(
            scheduler
                .submit_dirty_extent(staging_outcome(1, 0, 4096))
                .unwrap(),
            1
        );
        assert_eq!(
            scheduler
                .submit_dirty_extent(staging_outcome(1, 4096, 4096))
                .unwrap(),
            2
        );
        assert_eq!(scheduler.as_slice()[1].work_item_id, 2);
    }

    #[test]
    fn dirty_extent_scheduler_rejects_full_queue() {
        let mut scheduler = DirtyExtentScheduler::<1>::new();
        scheduler
            .submit_dirty_extent(staging_outcome(1, 0, 4096))
            .unwrap();

        assert_eq!(
            scheduler.submit_dirty_extent(staging_outcome(1, 4096, 4096)),
            Err(DirtyExtentSchedulerError::Full)
        );
        assert_eq!(scheduler.len(), 1);
    }

    #[test]
    fn dirty_extent_scheduler_rejects_overflow_range() {
        let mut scheduler = DirtyExtentScheduler::<4>::new();

        assert_eq!(
            scheduler.submit_dirty_extent(staging_outcome(1, u64::MAX, 1)),
            Err(DirtyExtentSchedulerError::InvalidRange)
        );
        assert!(scheduler.is_empty());
    }

    #[test]
    fn write_dispatch_pipeline_classifies_stages_and_submits_dirty_extent() {
        use crate::ingress::{
            ClassifiedWrite, IngressWriteHandle, IngressWriteHandleTable, RawFuseWriteRequest,
            WriteClassifier, FUSE_WRITE_LOCKOWNER,
        };
        use tidefs_posix_filesystem_adapter_workers_io::{staged_write_hash64, WriteBuffer};

        struct RuntimeHandles;

        impl IngressWriteHandleTable for RuntimeHandles {
            fn lookup_write_handle(&self, fh: u64) -> Option<IngressWriteHandle> {
                (fh == 55).then_some(IngressWriteHandle {
                    inode: 77,
                    writable: true,
                })
            }
        }

        let raw = RawFuseWriteRequest {
            unique: 300,
            inode: 77,
            fh: 55,
            offset: 0,
            size: 4096,
            payload_len: 4096,
            write_flags: FUSE_WRITE_LOCKOWNER,
            lock_owner: 9000,
        };
        let request = match WriteClassifier::new().classify(&RuntimeHandles, raw) {
            ClassifiedWrite::DirtyExtent(request) => request,
            other => panic!("expected dirty extent classification, got {other:?}"),
        };

        let payload = [0x5A_u8; 4096];
        let mut write_buffer = WriteBuffer::new();
        let staged = write_buffer
            .stage(request, &payload)
            .expect("stage classified write");

        let mut scheduler = DirtyExtentScheduler::<2>::new();
        let work_item_id = scheduler
            .submit_dirty_extent(staged.outcome)
            .expect("submit staged write");

        assert_eq!(work_item_id, 1);
        assert_eq!(staged.data.as_slice(), payload.as_slice());
        assert_eq!(scheduler.len(), 1);
        let item = scheduler.as_slice()[0];
        assert_eq!(item.work_item_id, 1);
        assert_eq!(item.unique, 300);
        assert_eq!(item.inode, 77);
        assert_eq!(item.offset, 0);
        assert_eq!(item.length, 4096);
        assert_eq!(item.buffer_handle, 1);
        assert_eq!(item.content_hash64, staged_write_hash64(&payload));
        assert_eq!(item.write_flags, FUSE_WRITE_LOCKOWNER);
    }

    #[test]
    fn new_queue_is_empty() {
        let q = WritebackQueue::<8>::new();
        assert!(q.is_empty());
        assert!(!q.is_full());
        assert_eq!(q.len(), 0);
        assert_eq!(q.capacity(), 8);
        assert_eq!(q.remaining_capacity(), 8);
    }

    #[test]
    fn public_record_constructors_populate_fields() {
        let work = WritebackWorkItem::new(10, 4096, 8192, 7, 4096, 30).with_generation(99);
        assert_eq!(work.object_id, 10);
        assert_eq!(work.offset_start, 4096);
        assert_eq!(work.offset_end, 8192);
        assert_eq!(work.commit_group_id, 7);
        assert_eq!(work.dirty_byte_count, 4096);
        assert_eq!(work.oldest_dirty_age_ms, 30);
        assert_eq!(work.generation, 99);

        let cfg = WritebackSchedulerConfig::new(250, 8, 16384, 512);
        assert_eq!(cfg.scan_interval_ms, 250);
        assert_eq!(cfg.max_concurrent_flushes, 8);
        assert_eq!(cfg.dirty_byte_threshold, 16384);
        assert_eq!(cfg.queue_capacity, 512);

        let record = WritebackDirtyPageRecord::new(11, 0, 4096, 8, 2048, 12);
        assert_eq!(record.object_id, 11);
        assert_eq!(record.commit_group_id, 8);
        assert_eq!(record.dirty_byte_count, 2048);
        assert_eq!(record.dirty_age_ms, 12);

        let summary = WritebackDirtyScanEnqueueSummary::new(3, 2, 2, 8192);
        assert_eq!(summary.scanned_records, 3);
        assert_eq!(summary.grouped_items, 2);
        assert_eq!(summary.enqueued_items, 2);
        assert_eq!(summary.dirty_byte_count, 8192);

        let ticket = WritebackDispatchTicket::new(5, work);
        assert_eq!(ticket.ticket_id, 5);
        assert_eq!(ticket.item, work);

        let draft = WritebackLifecycleEventDraft::new(
            WritebackLifecycleEventKind::DispatchStarted,
            WritebackLifecycleStatus::InFlight,
        )
        .with_commit_group_object(7, 10)
        .with_ticket_id(5)
        .with_counts(0, 1, 4096)
        .with_depths(2, 1);
        assert_eq!(draft.kind, WritebackLifecycleEventKind::DispatchStarted);
        assert_eq!(draft.status, WritebackLifecycleStatus::InFlight);
        assert_eq!(draft.commit_group_id, 7);
        assert_eq!(draft.object_id, 10);
        assert_eq!(draft.ticket_id, 5);
        assert_eq!(draft.work_item_count, 1);
        assert_eq!(draft.queue_depth, 2);
        assert_eq!(draft.in_flight_count, 1);
    }

    #[test]
    fn dirty_scan_batch_rejects_invalid_records() {
        let mut batch = WritebackDirtyScanBatch::<2>::new();
        assert_eq!(
            batch.push(dirty(1, 4096, 4096, 7, 4096, 10)),
            Err(WritebackDirtyScanError::InvalidRange)
        );
        assert_eq!(
            batch.push(dirty(1, 0, 4096, 7, 0, 10)),
            Err(WritebackDirtyScanError::ZeroDirtyBytes)
        );
    }

    #[test]
    fn dirty_scan_batch_reports_full_before_accepting_more_records() {
        let mut batch = WritebackDirtyScanBatch::<1>::new();
        batch.push(dirty(1, 0, 4096, 7, 4096, 10)).unwrap();
        assert_eq!(
            batch.push(dirty(1, 4096, 8192, 7, 4096, 11)),
            Err(WritebackDirtyScanError::BatchFull)
        );
    }

    #[test]
    fn dirty_scan_groups_adjacent_same_object_and_commit_group() {
        let mut batch = WritebackDirtyScanBatch::<4>::new();
        batch.push(dirty(1, 0, 4096, 7, 4096, 10)).unwrap();
        batch.push(dirty(1, 4096, 8192, 7, 4096, 25)).unwrap();
        batch.push(dirty(1, 8192, 12288, 8, 4096, 30)).unwrap();

        let groups = batch.group_adjacent();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups.as_slice()[0].object_id, 1);
        assert_eq!(groups.as_slice()[0].offset_start, 0);
        assert_eq!(groups.as_slice()[0].offset_end, 8192);
        assert_eq!(groups.as_slice()[0].commit_group_id, 7);
        assert_eq!(groups.as_slice()[0].dirty_byte_count, 8192);
        assert_eq!(groups.as_slice()[0].oldest_dirty_age_ms, 25);
        assert_eq!(groups.as_slice()[1].commit_group_id, 8);
    }

    #[test]
    fn dirty_scan_does_not_group_gapped_ranges() {
        let mut batch = WritebackDirtyScanBatch::<4>::new();
        batch.push(dirty(1, 0, 4096, 7, 4096, 10)).unwrap();
        batch.push(dirty(1, 8192, 12288, 7, 4096, 20)).unwrap();

        let groups = batch.group_adjacent();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups.as_slice()[0].offset_end, 4096);
        assert_eq!(groups.as_slice()[1].offset_start, 8192);
    }

    #[test]
    fn dirty_scan_enqueue_grouped_work_items() {
        let mut batch = WritebackDirtyScanBatch::<4>::new();
        let mut state = WritebackDispatchState::<4, 2>::new();
        batch.push(dirty(1, 0, 4096, 7, 4096, 10)).unwrap();
        batch.push(dirty(1, 4096, 8192, 7, 4096, 20)).unwrap();

        let summary = batch.enqueue_grouped(&mut state).unwrap();
        assert_eq!(
            summary,
            WritebackDirtyScanEnqueueSummary {
                scanned_records: 2,
                grouped_items: 1,
                enqueued_items: 1,
                dirty_byte_count: 8192,
            }
        );
        assert_eq!(state.queued_len(), 1);
        assert_eq!(state.queue().peek().unwrap().offset_end, 8192);
        assert_eq!(state.queue().peek().unwrap().oldest_dirty_age_ms, 20);
    }

    #[test]
    fn dirty_scan_enqueue_rejects_when_grouped_items_exceed_queue_capacity() {
        let mut batch = WritebackDirtyScanBatch::<4>::new();
        let mut state = WritebackDispatchState::<1, 2>::new();
        batch.push(dirty(1, 0, 4096, 7, 4096, 10)).unwrap();
        batch.push(dirty(2, 0, 4096, 7, 4096, 20)).unwrap();

        assert_eq!(
            batch.enqueue_grouped(&mut state),
            Err(WritebackDirtyScanError::QueueFull)
        );
        assert_eq!(state.queued_len(), 0);
    }

    #[test]
    fn priority_ordering_same_commit_group_higher_dirty_age_first() {
        let mut q = WritebackQueue::<8>::new();
        q.push(item_with_age(1, 7, 4096, 10)).unwrap();
        q.push(item_with_age(2, 7, 4096, 30)).unwrap();

        assert_eq!(q.pop().unwrap().object_id, 2);
        assert_eq!(q.pop().unwrap().object_id, 1);
    }

    #[test]
    fn push_pop_single_item() {
        let mut q = WritebackQueue::<8>::new();
        let item = WritebackWorkItem {
            object_id: 1,
            offset_start: 0,
            offset_end: 4096,
            commit_group_id: 1,
            dirty_byte_count: 4096,
            oldest_dirty_age_ms: 0,
            generation: 0,
        };
        q.push(item).unwrap();
        assert!(!q.is_empty());
        assert_eq!(q.len(), 1);
        let popped = q.pop().unwrap();
        assert_eq!(popped.object_id, 1);
        assert!(q.is_empty());
    }

    #[test]
    fn pop_from_empty_returns_none() {
        let mut q = WritebackQueue::<8>::new();
        assert!(q.pop().is_none());
    }

    #[test]
    fn push_when_full_returns_error() {
        let mut q = WritebackQueue::<2>::new();
        q.push(WritebackWorkItem {
            object_id: 1,
            offset_start: 0,
            offset_end: 4096,
            commit_group_id: 1,
            dirty_byte_count: 4096,
            oldest_dirty_age_ms: 0,
            generation: 0,
        })
        .unwrap();
        q.push(WritebackWorkItem {
            object_id: 2,
            offset_start: 0,
            offset_end: 4096,
            commit_group_id: 2,
            dirty_byte_count: 4096,
            oldest_dirty_age_ms: 0,
            generation: 0,
        })
        .unwrap();
        assert!(q.is_full());
        let result = q.push(WritebackWorkItem {
            object_id: 3,
            offset_start: 0,
            offset_end: 4096,
            commit_group_id: 3,
            dirty_byte_count: 4096,
            oldest_dirty_age_ms: 0,
            generation: 0,
        });
        assert_eq!(result, Err(WritebackQueueError::Full));
    }

    #[test]
    fn priority_ordering_lower_commit_group_first() {
        let mut q = WritebackQueue::<8>::new();
        // Push in reverse commit_group order.
        q.push(WritebackWorkItem {
            object_id: 3,
            offset_start: 0,
            offset_end: 4096,
            commit_group_id: 3,
            dirty_byte_count: 4096,
            oldest_dirty_age_ms: 0,
            generation: 0,
        })
        .unwrap();
        q.push(WritebackWorkItem {
            object_id: 1,
            offset_start: 0,
            offset_end: 4096,
            commit_group_id: 1,
            dirty_byte_count: 4096,
            oldest_dirty_age_ms: 0,
            generation: 0,
        })
        .unwrap();
        q.push(WritebackWorkItem {
            object_id: 2,
            offset_start: 0,
            offset_end: 4096,
            commit_group_id: 2,
            dirty_byte_count: 4096,
            oldest_dirty_age_ms: 0,
            generation: 0,
        })
        .unwrap();

        // Pop should return commit_group 1, 2, 3.
        assert_eq!(q.pop().unwrap().commit_group_id, 1);
        assert_eq!(q.pop().unwrap().commit_group_id, 2);
        assert_eq!(q.pop().unwrap().commit_group_id, 3);
    }

    #[test]
    fn priority_ordering_same_commit_group_higher_dirty_bytes_first() {
        let mut q = WritebackQueue::<8>::new();
        q.push(WritebackWorkItem {
            object_id: 2,
            offset_start: 0,
            offset_end: 2048,
            commit_group_id: 1,
            dirty_byte_count: 2048,
            oldest_dirty_age_ms: 0,
            generation: 0,
        })
        .unwrap();
        q.push(WritebackWorkItem {
            object_id: 1,
            offset_start: 0,
            offset_end: 8192,
            commit_group_id: 1,
            dirty_byte_count: 8192,
            oldest_dirty_age_ms: 0,
            generation: 0,
        })
        .unwrap();

        // Higher dirty_byte_count should come first.
        assert_eq!(q.pop().unwrap().dirty_byte_count, 8192);
        assert_eq!(q.pop().unwrap().dirty_byte_count, 2048);
    }

    #[test]
    fn priority_ordering_generation_tiebreaker() {
        let mut q = WritebackQueue::<8>::new();
        // Two items with same commit_group and same dirty_byte_count.
        q.push(WritebackWorkItem {
            object_id: 2,
            offset_start: 0,
            offset_end: 4096,
            commit_group_id: 1,
            dirty_byte_count: 4096,
            oldest_dirty_age_ms: 0,
            generation: 0,
        })
        .unwrap();
        q.push(WritebackWorkItem {
            object_id: 1,
            offset_start: 0,
            offset_end: 4096,
            commit_group_id: 1,
            dirty_byte_count: 4096,
            oldest_dirty_age_ms: 0,
            generation: 0,
        })
        .unwrap();

        // First pushed should have lower generation and pop first.
        let first = q.pop().unwrap();
        let second = q.pop().unwrap();
        assert!(first.generation < second.generation);
    }

    #[test]
    fn peek_does_not_remove() {
        let mut q = WritebackQueue::<8>::new();
        q.push(WritebackWorkItem {
            object_id: 1,
            offset_start: 0,
            offset_end: 4096,
            commit_group_id: 1,
            dirty_byte_count: 4096,
            oldest_dirty_age_ms: 0,
            generation: 0,
        })
        .unwrap();
        assert_eq!(q.peek().unwrap().object_id, 1);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn peek_on_empty_returns_none() {
        let q = WritebackQueue::<8>::new();
        assert!(q.peek().is_none());
    }

    #[test]
    fn contains_commit_group_detects_queued_work() {
        let mut q = WritebackQueue::<8>::new();
        assert!(!q.contains_commit_group(7));
        q.push(item(1, 7, 4096)).unwrap();
        assert!(q.contains_commit_group(7));
        assert!(!q.contains_commit_group(8));
    }

    #[test]
    fn drain_commit_group_partitions_correctly() {
        let mut q = WritebackQueue::<8>::new();
        q.push(WritebackWorkItem {
            object_id: 1,
            offset_start: 0,
            offset_end: 4096,
            commit_group_id: 1,
            dirty_byte_count: 4096,
            oldest_dirty_age_ms: 0,
            generation: 0,
        })
        .unwrap();
        q.push(WritebackWorkItem {
            object_id: 2,
            offset_start: 0,
            offset_end: 4096,
            commit_group_id: 1,
            dirty_byte_count: 2048,
            oldest_dirty_age_ms: 0,
            generation: 0,
        })
        .unwrap();
        q.push(WritebackWorkItem {
            object_id: 3,
            offset_start: 0,
            offset_end: 4096,
            commit_group_id: 2,
            dirty_byte_count: 4096,
            oldest_dirty_age_ms: 0,
            generation: 0,
        })
        .unwrap();

        let drained = q.drain_commit_group(1);
        assert_eq!(drained.len(), 2);
        for item in drained.as_slice() {
            assert_eq!(item.commit_group_id, 1);
        }

        // Remaining item should be commit_group 2.
        assert_eq!(q.len(), 1);
        assert_eq!(q.pop().unwrap().commit_group_id, 2);
    }

    #[test]
    fn drain_commit_group_drained_items_in_priority_order() {
        let mut q = WritebackQueue::<8>::new();
        q.push(WritebackWorkItem {
            object_id: 1,
            offset_start: 0,
            offset_end: 2048,
            commit_group_id: 1,
            dirty_byte_count: 2048,
            oldest_dirty_age_ms: 0,
            generation: 0,
        })
        .unwrap();
        q.push(WritebackWorkItem {
            object_id: 2,
            offset_start: 0,
            offset_end: 8192,
            commit_group_id: 1,
            dirty_byte_count: 8192,
            oldest_dirty_age_ms: 0,
            generation: 0,
        })
        .unwrap();

        let drained = q.drain_commit_group(1);
        // Higher dirty_byte_count should be first in drained array.
        assert_eq!(drained.as_slice()[0].dirty_byte_count, 8192);
        assert_eq!(drained.as_slice()[1].dirty_byte_count, 2048);
    }

    #[test]
    fn drain_commit_group_empty_queue_returns_empty() {
        let mut q = WritebackQueue::<8>::new();
        let drained = q.drain_commit_group(1);
        assert!(drained.is_empty());
        assert_eq!(drained.len(), 0);
    }

    #[test]
    fn dispatch_next_moves_queued_item_to_in_flight() {
        let mut state = WritebackDispatchState::<8, 2>::new();
        state.enqueue(item(1, 7, 4096)).unwrap();

        let ticket = state.dispatch_next().unwrap();
        assert_eq!(ticket.ticket_id, 1);
        assert_eq!(ticket.item.object_id, 1);
        assert_eq!(state.queued_len(), 0);
        assert_eq!(state.in_flight_len(), 1);
        assert_eq!(state.in_flight_count_for_commit_group(7), 1);
        assert!(!state.is_commit_group_idle(7));
    }

    #[test]
    fn dispatch_next_empty_queue_returns_error() {
        let mut state = WritebackDispatchState::<8, 2>::new();
        assert_eq!(
            state.dispatch_next(),
            Err(WritebackDispatchError::QueueEmpty)
        );
    }

    #[test]
    fn dispatch_empty_queue_with_zero_in_flight_capacity_returns_queue_empty() {
        let mut state = WritebackDispatchState::<8, 0>::new();
        assert_eq!(
            state.dispatch_next(),
            Err(WritebackDispatchError::QueueEmpty)
        );
    }

    #[test]
    fn dispatch_respects_in_flight_capacity_without_popping() {
        let mut state = WritebackDispatchState::<8, 1>::new();
        state.enqueue(item(1, 7, 4096)).unwrap();
        state.enqueue(item(2, 8, 4096)).unwrap();
        let first = state.dispatch_next().unwrap();

        assert_eq!(first.item.object_id, 1);
        assert!(state.is_in_flight_full());
        assert_eq!(
            state.dispatch_next(),
            Err(WritebackDispatchError::InFlightFull)
        );
        assert_eq!(state.queued_len(), 1);
        assert!(state.queue().contains_commit_group(8));
    }

    #[test]
    fn complete_removes_in_flight_ticket() {
        let mut state = WritebackDispatchState::<8, 2>::new();
        state.enqueue(item(1, 7, 4096)).unwrap();
        let ticket = state.dispatch_next().unwrap();

        let completed = state.complete(ticket.ticket_id).unwrap();
        assert_eq!(completed.object_id, 1);
        assert_eq!(state.in_flight_len(), 0);
        assert!(state.is_commit_group_idle(7));
    }

    #[test]
    fn complete_unknown_ticket_returns_error() {
        let mut state = WritebackDispatchState::<8, 2>::new();
        assert_eq!(
            state.complete(99),
            Err(WritebackDispatchError::UnknownTicket)
        );
    }

    #[test]
    fn retry_unknown_ticket_reports_unknown_before_queue_pressure() {
        let mut state = WritebackDispatchState::<1, 1>::new();
        state.enqueue(item(1, 7, 4096)).unwrap();
        assert_eq!(state.retry(99), Err(WritebackDispatchError::UnknownTicket));
    }

    #[test]
    fn retry_requeues_ticket_and_frees_in_flight_slot() {
        let mut state = WritebackDispatchState::<8, 2>::new();
        state.enqueue(item(1, 7, 4096)).unwrap();
        let ticket = state.dispatch_next().unwrap();

        state.retry(ticket.ticket_id).unwrap();
        assert_eq!(state.in_flight_len(), 0);
        assert_eq!(state.queued_len(), 1);
        let retried = state.dispatch_next().unwrap();
        assert_eq!(retried.item.object_id, 1);
        assert_eq!(retried.item.commit_group_id, 7);
        assert!(retried.item.generation > ticket.item.generation);
    }

    #[test]
    fn retry_full_queue_keeps_ticket_in_flight() {
        let mut state = WritebackDispatchState::<1, 1>::new();
        state.enqueue(item(1, 7, 4096)).unwrap();
        let ticket = state.dispatch_next().unwrap();
        state.enqueue(item(2, 8, 4096)).unwrap();

        assert_eq!(
            state.retry(ticket.ticket_id),
            Err(WritebackDispatchError::RequeueFull)
        );
        assert_eq!(state.in_flight_len(), 1);
        assert_eq!(state.queued_len(), 1);
    }

    #[test]
    fn commit_group_idle_tracks_queued_and_in_flight_work() {
        let mut state = WritebackDispatchState::<8, 2>::new();
        assert!(state.is_commit_group_idle(7));

        state.enqueue(item(1, 7, 4096)).unwrap();
        assert!(!state.is_commit_group_idle(7));

        let ticket = state.dispatch_next().unwrap();
        assert!(!state.is_commit_group_idle(7));

        state.complete(ticket.ticket_id).unwrap();
        assert!(state.is_commit_group_idle(7));
    }

    #[test]
    fn begin_commit_group_flush_drains_only_matching_commit_group() {
        let mut state = WritebackDispatchState::<8, 2>::new();
        state.enqueue(item(1, 7, 4096)).unwrap();
        state.enqueue(item(2, 8, 4096)).unwrap();
        state.enqueue(item(3, 7, 8192)).unwrap();

        let barrier = state.begin_commit_group_flush(7);
        assert_eq!(barrier.commit_group_id(), 7);
        assert_eq!(barrier.drained_len(), 2);
        assert_eq!(barrier.pending_dispatch_len(), 2);
        assert!(!state.queue().contains_commit_group(7));
        assert!(state.queue().contains_commit_group(8));
        assert_eq!(state.queued_len(), 1);
    }

    #[test]
    fn commit_group_flush_dispatches_barrier_items_before_reporting_complete() {
        let mut state = WritebackDispatchState::<8, 2>::new();
        state.enqueue(item(1, 7, 4096)).unwrap();
        state.enqueue(item(2, 7, 8192)).unwrap();
        let mut barrier = state.begin_commit_group_flush(7);

        assert!(!state.is_commit_group_flush_complete(&barrier));
        let first = state
            .dispatch_commit_group_flush_next(&mut barrier)
            .unwrap()
            .unwrap();
        let second = state
            .dispatch_commit_group_flush_next(&mut barrier)
            .unwrap()
            .unwrap();
        assert_eq!(first.item.commit_group_id, 7);
        assert_eq!(second.item.commit_group_id, 7);
        assert!(barrier.is_dispatch_complete());
        assert!(!state.is_commit_group_flush_complete(&barrier));

        state.complete(first.ticket_id).unwrap();
        assert!(!state.is_commit_group_flush_complete(&barrier));
        state.complete(second.ticket_id).unwrap();
        assert!(state.is_commit_group_flush_complete(&barrier));
    }

    #[test]
    fn commit_group_flush_dispatch_next_returns_none_when_barrier_empty() {
        let mut state = WritebackDispatchState::<8, 2>::new();
        let mut barrier = state.begin_commit_group_flush(7);
        assert_eq!(barrier.drained_len(), 0);
        assert!(state
            .dispatch_commit_group_flush_next(&mut barrier)
            .unwrap()
            .is_none());
        assert!(state.is_commit_group_flush_complete(&barrier));
    }

    #[test]
    fn commit_group_flush_dispatch_respects_in_flight_capacity() {
        let mut state = WritebackDispatchState::<8, 1>::new();
        state.enqueue(item(1, 7, 4096)).unwrap();
        state.enqueue(item(2, 7, 8192)).unwrap();
        let mut barrier = state.begin_commit_group_flush(7);

        let first = state
            .dispatch_commit_group_flush_next(&mut barrier)
            .unwrap()
            .unwrap();
        assert_eq!(barrier.pending_dispatch_len(), 1);
        assert_eq!(
            state.dispatch_commit_group_flush_next(&mut barrier),
            Err(WritebackDispatchError::InFlightFull)
        );
        assert_eq!(barrier.pending_dispatch_len(), 1);

        state.complete(first.ticket_id).unwrap();
        let second = state
            .dispatch_commit_group_flush_next(&mut barrier)
            .unwrap()
            .unwrap();
        assert_eq!(second.item.commit_group_id, 7);
        assert!(barrier.is_dispatch_complete());
    }

    #[test]
    fn retry_during_commit_group_flush_keeps_barrier_incomplete_until_reflushed() {
        let mut state = WritebackDispatchState::<8, 2>::new();
        state.enqueue(item(1, 7, 4096)).unwrap();
        let mut barrier = state.begin_commit_group_flush(7);

        let ticket = state
            .dispatch_commit_group_flush_next(&mut barrier)
            .unwrap()
            .unwrap();
        assert!(barrier.is_dispatch_complete());
        state.retry(ticket.ticket_id).unwrap();
        assert!(!state.is_commit_group_flush_complete(&barrier));
        assert!(state.queue().contains_commit_group(7));

        let retried = state.dispatch_next().unwrap();
        state.complete(retried.ticket_id).unwrap();
        assert!(state.is_commit_group_flush_complete(&barrier));
    }

    #[test]
    fn lifecycle_trace_records_scan_dispatch_retry_completion_and_flush_order() {
        let mut batch = WritebackDirtyScanBatch::<4>::new();
        let mut state = WritebackDispatchState::<4, 2>::new();
        let mut trace = WritebackLifecycleTrace::<8>::new();
        batch.push(dirty(1, 0, 4096, 7, 4096, 20)).unwrap();

        let summary = batch.enqueue_grouped(&mut state).unwrap();
        trace
            .record_scan_enqueue(summary, state.queued_len())
            .unwrap();

        let mut barrier = state.begin_commit_group_flush(7);
        trace
            .record_commit_group_flush_started(&barrier, state.queued_len(), state.in_flight_len())
            .unwrap();

        let ticket = state
            .dispatch_commit_group_flush_next(&mut barrier)
            .unwrap()
            .unwrap();
        trace
            .record_dispatch_started(ticket, state.queued_len(), state.in_flight_len())
            .unwrap();

        state.retry(ticket.ticket_id).unwrap();
        trace
            .record_dispatch_retried(
                ticket.ticket_id,
                ticket.item,
                state.queued_len(),
                state.in_flight_len(),
            )
            .unwrap();

        let retried = state.dispatch_next().unwrap();
        trace
            .record_dispatch_started(retried, state.queued_len(), state.in_flight_len())
            .unwrap();

        let completed = state.complete(retried.ticket_id).unwrap();
        trace
            .record_dispatch_completed(
                retried.ticket_id,
                completed,
                state.queued_len(),
                state.in_flight_len(),
            )
            .unwrap();

        assert!(state.is_commit_group_flush_complete(&barrier));
        trace
            .record_commit_group_flush_completed(
                &barrier,
                state.queued_len(),
                state.in_flight_len(),
            )
            .unwrap();

        let events = trace.as_slice();
        assert_eq!(events.len(), 7);
        for (idx, event) in events.iter().enumerate() {
            assert_eq!(event.sequence_id, (idx + 1) as u64);
        }
        let expected_kinds = [
            WritebackLifecycleEventKind::DirtyScanEnqueued,
            WritebackLifecycleEventKind::CommitGroupFlushStarted,
            WritebackLifecycleEventKind::DispatchStarted,
            WritebackLifecycleEventKind::DispatchRetried,
            WritebackLifecycleEventKind::DispatchStarted,
            WritebackLifecycleEventKind::DispatchCompleted,
            WritebackLifecycleEventKind::CommitGroupFlushCompleted,
        ];
        for (event, expected_kind) in events.iter().zip(expected_kinds.iter()) {
            assert_eq!(event.kind, *expected_kind);
        }
        assert_eq!(events[0].scanned_records, 1);
        assert_eq!(events[0].work_item_count, 1);
        assert_eq!(events[0].dirty_byte_count, 4096);
        assert_eq!(events[1].commit_group_id, 7);
        assert_eq!(events[1].dirty_byte_count, 4096);
        assert_eq!(events[3].status, WritebackLifecycleStatus::Retried);
        assert_eq!(events[6].status, WritebackLifecycleStatus::Completed);
        assert_eq!(events[6].queue_depth, 0);
        assert_eq!(events[6].in_flight_count, 0);
    }

    #[test]
    fn lifecycle_trace_full_returns_error_without_advancing() {
        let mut trace = WritebackLifecycleTrace::<1>::new();
        let first = trace
            .record(WritebackLifecycleEventDraft {
                kind: WritebackLifecycleEventKind::DirtyScanEnqueued,
                status: WritebackLifecycleStatus::Accepted,
                scanned_records: 1,
                work_item_count: 1,
                dirty_byte_count: 4096,
                ..WritebackLifecycleEventDraft::default()
            })
            .unwrap();
        assert_eq!(first.sequence_id, 1);
        assert!(trace.is_full());
        assert_eq!(
            trace.record(WritebackLifecycleEventDraft {
                kind: WritebackLifecycleEventKind::DispatchStarted,
                status: WritebackLifecycleStatus::InFlight,
                ..WritebackLifecycleEventDraft::default()
            }),
            Err(WritebackLifecycleTraceError::Full)
        );
        assert_eq!(trace.len(), 1);
        assert_eq!(trace.as_slice()[0].sequence_id, 1);
    }

    #[test]
    fn default_config_has_sane_values() {
        let cfg = WritebackSchedulerConfig::default();
        assert_eq!(cfg.scan_interval_ms, 500);
        assert_eq!(cfg.max_concurrent_flushes, 4);
        assert_eq!(cfg.dirty_byte_threshold, 4096);
        assert_eq!(cfg.queue_capacity, 256);
    }

    #[test]
    fn large_queue_stress_test() {
        let mut q = WritebackQueue::<64>::new();
        // Push 64 items with various commit_group_ids.
        for i in 0..64 {
            q.push(WritebackWorkItem {
                object_id: i,
                offset_start: 0,
                offset_end: (i + 1) * 4096,
                commit_group_id: (63 - i), // reverse commit_group so older commit_groups are pushed later
                dirty_byte_count: (i + 1) * 4096,
                oldest_dirty_age_ms: 0,
                generation: 0,
            })
            .unwrap();
        }
        assert!(q.is_full());

        let mut prev_commit_group = 0u64;
        for _ in 0..64 {
            let item = q.pop().unwrap();
            assert!(item.commit_group_id >= prev_commit_group);
            prev_commit_group = item.commit_group_id;
        }
        assert!(q.is_empty());
    }

    #[test]
    fn work_item_default_is_zeroed() {
        let item = WritebackWorkItem::default();
        assert_eq!(item.object_id, 0);
        assert_eq!(item.offset_start, 0);
        assert_eq!(item.offset_end, 0);
        assert_eq!(item.commit_group_id, 0);
        assert_eq!(item.dirty_byte_count, 0);
        assert_eq!(item.oldest_dirty_age_ms, 0);
        assert_eq!(item.generation, 0);
    }

    // ── WritebackDirtyScanBatch boundaries ──────────────────────────

    #[test]
    fn empty_scan_batch_has_zero_len_is_empty() {
        let batch = WritebackDirtyScanBatch::<4>::new();
        assert_eq!(batch.len(), 0);
        assert!(batch.is_empty());
        assert_eq!(batch.capacity(), 4);
        assert!(batch.as_slice().is_empty());
    }

    #[test]
    fn cap_zero_scan_batch_reporting() {
        let batch = WritebackDirtyScanBatch::<0>::new();
        assert_eq!(batch.capacity(), 0);
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
    }

    #[test]
    fn maximally_discontiguous_records_each_becomes_own_group() {
        let mut batch = WritebackDirtyScanBatch::<4>::new();
        batch.push(dirty(1, 0, 4096, 7, 4096, 10)).unwrap();
        batch.push(dirty(2, 0, 4096, 7, 4096, 10)).unwrap();
        batch.push(dirty(1, 8192, 12288, 7, 4096, 10)).unwrap();
        let groups = batch.group_adjacent();
        assert_eq!(groups.len(), 3);
    }

    #[test]
    fn interleaved_inode_records_maintain_per_inode_ordering() {
        let mut batch = WritebackDirtyScanBatch::<6>::new();
        batch.push(dirty(1, 0, 4096, 7, 4096, 10)).unwrap();
        batch.push(dirty(2, 0, 4096, 8, 4096, 20)).unwrap();
        batch.push(dirty(1, 4096, 8192, 7, 4096, 30)).unwrap();
        let groups = batch.group_adjacent();
        assert_eq!(groups.len(), 3);
        assert_eq!(groups.as_slice()[0].object_id, 1);
        assert_eq!(groups.as_slice()[0].offset_end, 4096);
        assert_eq!(groups.as_slice()[1].object_id, 2);
        assert_eq!(groups.as_slice()[2].object_id, 1);
        assert_eq!(groups.as_slice()[2].offset_end, 8192);
    }

    // ── is_adjacent_to ─────────────────────────────────────────────

    #[test]
    fn is_adjacent_to_exact_boundary_match() {
        let a = WritebackDirtyPageRecord::new(1, 0, 4096, 7, 4096, 10);
        let b = WritebackDirtyPageRecord::new(1, 4096, 8192, 7, 8192, 20);
        assert!(a.is_adjacent_to(&b));
    }

    #[test]
    fn is_adjacent_to_rejects_gap() {
        let a = WritebackDirtyPageRecord::new(1, 0, 4096, 7, 4096, 10);
        let b = WritebackDirtyPageRecord::new(1, 8192, 12288, 7, 8192, 20);
        assert!(!a.is_adjacent_to(&b));
    }

    #[test]
    fn is_adjacent_to_rejects_different_inode() {
        let a = WritebackDirtyPageRecord::new(1, 0, 4096, 7, 4096, 10);
        let b = WritebackDirtyPageRecord::new(2, 4096, 8192, 7, 8192, 20);
        assert!(!a.is_adjacent_to(&b));
    }

    #[test]
    fn is_adjacent_to_rejects_different_commit_group() {
        let a = WritebackDirtyPageRecord::new(1, 0, 4096, 7, 4096, 10);
        let b = WritebackDirtyPageRecord::new(1, 4096, 8192, 8, 8192, 20);
        assert!(!a.is_adjacent_to(&b));
    }

    #[test]
    fn dirty_page_record_default_is_zeroed() {
        let rec = WritebackDirtyPageRecord::default();
        assert_eq!(rec.object_id, 0);
        assert_eq!(rec.offset_start, 0);
        assert_eq!(rec.offset_end, 0);
        assert_eq!(rec.commit_group_id, 0);
        assert_eq!(rec.dirty_byte_count, 0);
        assert_eq!(rec.dirty_age_ms, 0);
    }

    // ── WritebackSchedulerConfig edge cases ─────────────────────────

    #[test]
    fn config_zero_queue_capacity() {
        let cfg = WritebackSchedulerConfig::new(500, 4, 4096, 0);
        assert_eq!(cfg.queue_capacity, 0);
        assert_eq!(cfg.scan_interval_ms, 500);
        assert_eq!(cfg.max_concurrent_flushes, 4);
        assert_eq!(cfg.dirty_byte_threshold, 4096);
    }

    #[test]
    fn config_max_field_values() {
        let cfg = WritebackSchedulerConfig::new(u64::MAX, u32::MAX, u64::MAX, usize::MAX);
        assert_eq!(cfg.scan_interval_ms, u64::MAX);
        assert_eq!(cfg.max_concurrent_flushes, u32::MAX);
        assert_eq!(cfg.dirty_byte_threshold, u64::MAX);
        assert_eq!(cfg.queue_capacity, usize::MAX);
    }

    #[test]
    fn config_default_stability() {
        let cfg1 = WritebackSchedulerConfig::default();
        let cfg2 = WritebackSchedulerConfig::default();
        assert_eq!(cfg1.scan_interval_ms, cfg2.scan_interval_ms);
        assert_eq!(cfg1.max_concurrent_flushes, cfg2.max_concurrent_flushes);
        assert_eq!(cfg1.dirty_byte_threshold, cfg2.dirty_byte_threshold);
        assert_eq!(cfg1.queue_capacity, cfg2.queue_capacity);
    }

    // ── Error enum discriminant / Debug coverage ────────────────────

    #[test]
    fn dirty_extent_scheduler_error_variant_construction() {
        let v = DirtyExtentSchedulerError::Full;
        assert_eq!(v, DirtyExtentSchedulerError::Full);
        assert_ne!(v, DirtyExtentSchedulerError::InvalidRange);
        assert_ne!(v, DirtyExtentSchedulerError::OutOfWorkItemIds);
        let v2 = DirtyExtentSchedulerError::OutOfWorkItemIds;
        assert_eq!(v2, DirtyExtentSchedulerError::OutOfWorkItemIds);
    }

    #[test]
    fn writeback_dirty_scan_error_variant_construction() {
        let v = WritebackDirtyScanError::BatchFull;
        assert_eq!(v, WritebackDirtyScanError::BatchFull);
        assert_ne!(v, WritebackDirtyScanError::InvalidRange);
        assert_ne!(v, WritebackDirtyScanError::ZeroDirtyBytes);
        assert_ne!(v, WritebackDirtyScanError::QueueFull);
    }

    #[test]
    fn writeback_queue_error_clone_eq() {
        let e = WritebackQueueError::Full;
        let e2 = e;
        assert_eq!(e, e2);
        assert_eq!(e, WritebackQueueError::Full);
    }

    #[test]
    fn writeback_dispatch_error_variant_construction() {
        let v = WritebackDispatchError::QueueEmpty;
        assert_eq!(v, WritebackDispatchError::QueueEmpty);
        assert_ne!(v, WritebackDispatchError::InFlightFull);
        assert_ne!(v, WritebackDispatchError::UnknownTicket);
        assert_ne!(v, WritebackDispatchError::RequeueFull);
    }
}
