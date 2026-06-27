// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! ## Authority Classification (per docs/cache-authority-model.md)
//!
//! This readahead module is **Derived**.  It detects sequential access patterns
//! and issues prefetch reads to warm caches, but never holds authoritative
//! data or dirty ownership.  It supplements `tidefs-cache-core::Prefetch`.
//!
//! Sequential-read detection and readahead prefetch for streaming workloads.
//!
//! Tracks per-file read patterns to classify accesses as sequential or random,
//! then issues background prefetch reads to warm caches for sequential streams.
//!
//! # Design
//!
//! - [`StreamDetector`] classifies each read as sequential or random using a
//!   gap-tolerance window (64 KiB). Adjacent reads and reads within the
//!   tolerance window are sequential; far-ahead or backward reads are random.
//! - [`ReadaheadPlanner`] computes prefetch windows with exponential growth
//!   (128 KiB initial, doubling up to 1 MiB max) and clamps at EOF.
//! - [`ReadaheadTracker`] manages per-inode state behind a `RefCell<HashMap>`.
//! - [`issue_readahead`] performs a best-effort background read that populates
//!   the hot-read cache without blocking the current read response.

use std::cell::RefCell;
use std::collections::HashMap;

use tidefs_types_vfs_core::InodeId;

use crate::LocalFileSystem;

// ── Constants ─────────────────────────────────────────────────────────────

/// Minimum readahead window: 128 KiB.
const MIN_READAHEAD_WINDOW: u64 = 128 * 1024;
/// Maximum readahead window: 1 MiB.
const MAX_READAHEAD_WINDOW: u64 = 1024 * 1024;
/// Initial window when sequential access is first detected.
const INITIAL_READAHEAD_WINDOW: u64 = 128 * 1024;
/// Gap tolerance: reads within this many bytes of the expected offset are
/// considered sequential (64 KiB).
const GAP_TOLERANCE: u64 = 64 * 1024;
/// Number of consecutive sequential reads before readahead engages.
const SEQUENTIAL_THRESHOLD: u32 = 2;

// ── ReadaheadState ────────────────────────────────────────────────────────

/// Per-file readahead state tracking sequential access patterns.
#[derive(Clone, Debug)]
pub(crate) struct ReadaheadState {
    /// Expected next read offset (end of last read).
    pub expected_offset: u64,
    /// End offset of the last read (offset + size).
    pub last_end: u64,
    /// Consecutive sequential accesses counter.
    pub sequential_count: u32,
    /// Current readahead window size in bytes.
    pub window_size: u64,
}

impl ReadaheadState {
    pub fn new(_inode_id: InodeId) -> Self {
        Self {
            expected_offset: 0,
            last_end: 0,
            sequential_count: 0,
            window_size: INITIAL_READAHEAD_WINDOW,
        }
    }
}

// ── StreamDetector ────────────────────────────────────────────────────────

/// Result of stream detection: is this access sequential or random?
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamClassification {
    /// Access is sequential (offset at or near expected position).
    Sequential,
    /// Access is random (offset far from expected position).
    Random,
}

/// Classifies read accesses as sequential or random with gap tolerance.
pub(crate) struct StreamDetector;

impl StreamDetector {
    /// Classify a read at `offset` with `size` against the current state.
    pub fn classify(state: &ReadaheadState, offset: u64, size: u32) -> StreamClassification {
        if size == 0 {
            return StreamClassification::Sequential;
        }
        let gap = offset.abs_diff(state.expected_offset);
        if gap <= GAP_TOLERANCE {
            StreamClassification::Sequential
        } else {
            StreamClassification::Random
        }
    }

    /// Update state after a read at `offset` with `size`.
    pub fn record(state: &mut ReadaheadState, offset: u64, size: u32) {
        match Self::classify(state, offset, size) {
            StreamClassification::Sequential => {
                state.sequential_count += 1;
            }
            StreamClassification::Random => {
                state.sequential_count = 0;
            }
        }
        state.last_end = offset + size as u64;
        state.expected_offset = state.last_end;
    }
}

// ── ReadaheadPlanner ──────────────────────────────────────────────────────

/// Plans readahead operations based on sequential access patterns.
pub(crate) struct ReadaheadPlanner;

impl ReadaheadPlanner {
    /// Compute the readahead window for the current state.
    ///
    /// Returns `Some(offset, length)` for the range to prefetch, or `None`
    /// if readahead should not happen (below threshold, at EOF, or zero-length).
    pub fn plan(state: &ReadaheadState, file_size: u64) -> Option<(u64, u64)> {
        if state.sequential_count < SEQUENTIAL_THRESHOLD {
            return None;
        }
        if state.expected_offset >= file_size {
            return None;
        }
        let remaining = file_size - state.expected_offset;
        let window = state.window_size.min(remaining);
        if window == 0 {
            return None;
        }
        Some((state.expected_offset, window))
    }

    /// Grow the window size exponentially (doubling) up to the maximum.
    pub fn grow_window(state: &mut ReadaheadState) {
        let new_size = state.window_size.saturating_mul(2);
        state.window_size = new_size.clamp(MIN_READAHEAD_WINDOW, MAX_READAHEAD_WINDOW);
    }

    /// Shrink window on random access back to the initial size.
    pub fn shrink_window(state: &mut ReadaheadState) {
        state.window_size = INITIAL_READAHEAD_WINDOW;
    }
}

// ── ReadaheadTracker ──────────────────────────────────────────────────────

/// Tracks readahead state for multiple open files.
///
/// Each inode's access pattern is independently tracked.  The tracker
/// classifies each read, updates the per-inode state, and returns a
/// prefetch plan when readahead should be issued.
pub(crate) struct ReadaheadTracker {
    states: RefCell<HashMap<InodeId, ReadaheadState>>,
}

impl ReadaheadTracker {
    pub fn new() -> Self {
        Self {
            states: RefCell::new(HashMap::new()),
        }
    }

    /// Record a read access and return a recommended prefetch window.
    ///
    /// `file_size` is the current inode size used to clamp the readahead
    /// window at EOF.
    pub fn record_read(
        &self,
        inode_id: InodeId,
        offset: u64,
        size: u32,
        file_size: u64,
    ) -> Option<(u64, u64)> {
        let mut states = self.states.borrow_mut();
        let state = states
            .entry(inode_id)
            .or_insert_with(|| ReadaheadState::new(inode_id));

        let class = StreamDetector::classify(state, offset, size);

        match class {
            StreamClassification::Sequential => {
                // Plan based on history before recording this read.
                let plan = ReadaheadPlanner::plan(state, file_size);
                // Record and grow window for next time.
                StreamDetector::record(state, offset, size);
                ReadaheadPlanner::grow_window(state);
                plan
            }
            StreamClassification::Random => {
                StreamDetector::record(state, offset, size);
                ReadaheadPlanner::shrink_window(state);
                None
            }
        }
    }

    /// Remove state when a file handle is released, freeing memory.
    #[allow(dead_code)]
    pub fn remove(&self, inode_id: InodeId) {
        self.states.borrow_mut().remove(&inode_id);
    }
}

// ── issue_readahead ───────────────────────────────────────────────────────

/// Issue a best-effort background read to warm caches for sequential access.
///
/// Returns `Ok(())` on success or if the readahead was a no-op (e.g., EOF).
/// Errors are silently discarded — readahead is an optimisation, not a
/// correctness requirement.
pub(crate) fn issue_readahead(fs: &LocalFileSystem, path: &str, offset: u64, length: u64) {
    let length = usize::try_from(length).unwrap_or(usize::MAX);
    let _ = fs.read_file_range_with_read_serving(
        path,
        offset,
        length,
        tidefs_storage_intent_read_serving::ReadServingDecisionInput::default(),
    );
}

#[allow(dead_code)]
/// Outcome bundle returned by an executor-authorised readahead dispatch.
#[derive(Clone, Debug)]
pub(crate) struct ExecutorReadaheadOutcome {
    /// The executor record produced by evaluate_prefetch_execution.
    pub executor_record: tidefs_storage_intent_prefetch_executor::PrefetchExecutorRecord,
    /// Bytes requested for dispatch when executor permitted the action;
    /// None when the executor refused, blocked, or handed off the action.
    pub bytes_issued: Option<u64>,
}

#[allow(dead_code)]
/// Issue a readahead only after the storage-intent prefetch executor
/// authorises the action family, evidence, budget, and scheduler admission.
///
/// This is the #972 adapter hook that consumes #967 decisions, #913 evidence
/// snapshots, and the #862/#844/#856/#877/#893/#902 boundary refs carried
/// inside `executor_input`.  When the executor returns
/// `PrefetchExecutorOutcome::Started` the call dispatches the readahead
/// through the existing read-serving gate; otherwise it records the refusal,
/// block, or handoff outcome and does not touch cache or storage.
pub(crate) fn issue_readahead_with_executor(
    fs: &LocalFileSystem,
    path: &str,
    offset: u64,
    length: u64,
    executor_input: tidefs_storage_intent_prefetch_executor::PrefetchExecutorInput,
) -> ExecutorReadaheadOutcome {
    let record =
        tidefs_storage_intent_prefetch_executor::evaluate_prefetch_execution(executor_input);

    let bytes_issued = if record.outcome
        == tidefs_storage_intent_prefetch_executor::PrefetchExecutorOutcome::Started
    {
        let len = usize::try_from(length).unwrap_or(usize::MAX);
        let _ = fs.read_file_range_with_read_serving(
            path,
            offset,
            len,
            tidefs_storage_intent_read_serving::ReadServingDecisionInput::default(),
        );
        Some(length)
    } else {
        None
    };

    ExecutorReadaheadOutcome {
        executor_record: record,
        bytes_issued,
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    use crate::DEFAULT_FILE_PERMISSIONS;

    fn set_test_key() {
        std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
    }

    fn temp_dir(label: &str) -> PathBuf {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = env::temp_dir().join(format!("tidefs-ra-{label}-{ts}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn make_inode(id: u64) -> InodeId {
        InodeId::new(id)
    }

    // ── StreamDetector ──────────────────────────────────────────────────

    #[test]
    fn sequential_zero_offset() {
        let state = ReadaheadState::new(make_inode(1));
        assert!(matches!(
            StreamDetector::classify(&state, 0, 4096),
            StreamClassification::Sequential
        ));
    }

    #[test]
    fn sequential_adjacent() {
        let mut state = ReadaheadState::new(make_inode(1));
        StreamDetector::record(&mut state, 0, 4096);
        assert!(matches!(
            StreamDetector::classify(&state, 4096, 4096),
            StreamClassification::Sequential
        ));
    }

    #[test]
    fn sequential_within_gap_tolerance() {
        let mut state = ReadaheadState::new(make_inode(1));
        StreamDetector::record(&mut state, 0, 4096);
        // 32 KiB gap is within 64 KiB tolerance
        assert!(matches!(
            StreamDetector::classify(&state, 4096 + 32 * 1024, 4096),
            StreamClassification::Sequential
        ));
    }

    #[test]
    fn random_far_ahead() {
        let mut state = ReadaheadState::new(make_inode(1));
        StreamDetector::record(&mut state, 0, 4096);
        // 128 KiB gap exceeds 64 KiB tolerance
        assert!(matches!(
            StreamDetector::classify(&state, 128 * 1024, 4096),
            StreamClassification::Random
        ));
    }

    #[test]
    fn random_backwards() {
        let mut state = ReadaheadState::new(make_inode(1));
        StreamDetector::record(&mut state, 64 * 1024, 4096);
        assert!(matches!(
            StreamDetector::classify(&state, 0, 4096),
            StreamClassification::Random
        ));
    }

    #[test]
    fn zero_length_sequential() {
        let state = ReadaheadState::new(make_inode(1));
        assert!(matches!(
            StreamDetector::classify(&state, 100, 0),
            StreamClassification::Sequential
        ));
    }

    #[test]
    fn record_increments_count_on_sequential() {
        let mut state = ReadaheadState::new(make_inode(1));
        assert_eq!(state.sequential_count, 0);
        StreamDetector::record(&mut state, 0, 4096);
        assert_eq!(state.sequential_count, 1);
        StreamDetector::record(&mut state, 4096, 4096);
        assert_eq!(state.sequential_count, 2);
    }

    #[test]
    fn record_resets_count_on_random() {
        let mut state = ReadaheadState::new(make_inode(1));
        StreamDetector::record(&mut state, 0, 4096);
        StreamDetector::record(&mut state, 4096, 4096);
        assert_eq!(state.sequential_count, 2);
        StreamDetector::record(&mut state, 200 * 1024, 4096);
        assert_eq!(state.sequential_count, 0);
    }

    // ── ReadaheadPlanner ─────────────────────────────────────────────────

    #[test]
    fn no_readahead_below_threshold() {
        let state = ReadaheadState::new(make_inode(1));
        // sequential_count = 0, below threshold of 2
        assert_eq!(ReadaheadPlanner::plan(&state, 1024 * 1024), None);
    }

    #[test]
    fn readahead_after_threshold() {
        let mut state = ReadaheadState::new(make_inode(1));
        state.sequential_count = 2;
        state.expected_offset = 0;
        state.window_size = INITIAL_READAHEAD_WINDOW;
        let plan = ReadaheadPlanner::plan(&state, 1024 * 1024);
        assert_eq!(plan, Some((0, INITIAL_READAHEAD_WINDOW)));
    }

    #[test]
    fn readahead_clamped_to_eof() {
        let mut state = ReadaheadState::new(make_inode(1));
        state.sequential_count = 2;
        state.expected_offset = 100 * 1024;
        state.window_size = INITIAL_READAHEAD_WINDOW;
        // File only has 20 KiB remaining beyond expected_offset
        let plan = ReadaheadPlanner::plan(&state, 120 * 1024);
        assert_eq!(plan, Some((100 * 1024, 20 * 1024)));
    }

    #[test]
    fn no_readahead_past_eof() {
        let mut state = ReadaheadState::new(make_inode(1));
        state.sequential_count = 2;
        state.expected_offset = 1024 * 1024;
        state.window_size = INITIAL_READAHEAD_WINDOW;
        assert_eq!(ReadaheadPlanner::plan(&state, 1024 * 1024), None);
    }

    #[test]
    fn window_exponential_growth() {
        let mut state = ReadaheadState::new(make_inode(1));
        assert_eq!(state.window_size, INITIAL_READAHEAD_WINDOW);
        ReadaheadPlanner::grow_window(&mut state);
        assert_eq!(state.window_size, INITIAL_READAHEAD_WINDOW * 2);
        ReadaheadPlanner::grow_window(&mut state);
        assert_eq!(state.window_size, INITIAL_READAHEAD_WINDOW * 4);
        ReadaheadPlanner::grow_window(&mut state);
        // 8x would be 1 MiB which equals MAX_READAHEAD_WINDOW
        assert_eq!(state.window_size, MAX_READAHEAD_WINDOW);
        // Further growth stays at max
        ReadaheadPlanner::grow_window(&mut state);
        assert_eq!(state.window_size, MAX_READAHEAD_WINDOW);
    }

    #[test]
    fn window_shrink_to_initial() {
        let mut state = ReadaheadState::new(make_inode(1));
        state.window_size = MAX_READAHEAD_WINDOW;
        ReadaheadPlanner::shrink_window(&mut state);
        assert_eq!(state.window_size, INITIAL_READAHEAD_WINDOW);
    }

    // ── ReadaheadTracker ─────────────────────────────────────────────────

    #[test]
    fn tracker_sequential_pattern_builds_to_readahead() {
        let tracker = ReadaheadTracker::new();
        let ino = make_inode(10);
        let file_size = 2 * 1024 * 1024;

        // Read 0: seq count 0 -> no readahead
        assert_eq!(tracker.record_read(ino, 0, 4096, file_size), None);
        // Read 1: seq count 1 -> still below threshold
        assert_eq!(tracker.record_read(ino, 4096, 4096, file_size), None);
        // Read 2: threshold met (count=2), readahead triggered.
        // Plan is computed before recording this read, so offset is the
        // expected position (8192) and window reflects two prior growth
        // steps (128 KiB -> 256 KiB -> 512 KiB).
        let plan = tracker.record_read(ino, 8192, 4096, file_size);
        assert!(plan.is_some());
        assert_eq!(plan.unwrap().0, 8192); // expected position
        assert_eq!(plan.unwrap().1, INITIAL_READAHEAD_WINDOW * 4); // 512 KiB
    }

    #[test]
    fn tracker_random_jump_resets_and_no_readahead() {
        let tracker = ReadaheadTracker::new();
        let ino = make_inode(10);
        let file_size = 2 * 1024 * 1024;

        tracker.record_read(ino, 0, 4096, file_size);
        tracker.record_read(ino, 4096, 4096, file_size);
        // Now at seq count 2, next sequential would trigger readahead
        let plan = tracker.record_read(ino, 8192, 4096, file_size);
        assert!(plan.is_some());

        // Random far jump resets
        let plan = tracker.record_read(ino, 500 * 1024, 4096, file_size);
        assert_eq!(plan, None); // count reset, below threshold
    }

    #[test]
    fn tracker_remove_and_fresh_start() {
        let tracker = ReadaheadTracker::new();
        let ino = make_inode(10);
        let file_size = 1024 * 1024;

        tracker.record_read(ino, 0, 4096, file_size);
        tracker.remove(ino);
        // After remove, state is gone — fresh start
        assert_eq!(tracker.record_read(ino, 0, 4096, file_size), None);
    }

    #[test]
    fn tracker_gap_tolerance_unifies_nearby_reads() {
        let tracker = ReadaheadTracker::new();
        let ino = make_inode(10);
        let file_size = 2 * 1024 * 1024;

        tracker.record_read(ino, 0, 4096, file_size);
        // 32 KiB gap (within tolerance)
        tracker.record_read(ino, 4096 + 32 * 1024, 4096, file_size);
        // Third read starts at expected offset of second, sequential
        let end_second = 4096 + 32 * 1024 + 4096;
        let plan = tracker.record_read(ino, end_second, 4096, file_size);
        assert!(plan.is_some());
    }

    #[test]
    fn tracker_multiple_inodes_independent() {
        let tracker = ReadaheadTracker::new();
        let ino1 = make_inode(1);
        let ino2 = make_inode(2);
        let file_size = 4 * 1024 * 1024;

        // Build sequential on ino1
        tracker.record_read(ino1, 0, 4096, file_size);
        tracker.record_read(ino1, 4096, 4096, file_size);
        let plan = tracker.record_read(ino1, 8192, 4096, file_size);
        assert!(plan.is_some());

        // ino2 is independent and starts fresh
        assert_eq!(tracker.record_read(ino2, 0, 4096, file_size), None);
    }

    #[test]
    fn tracker_zero_length_read_does_not_trigger_readahead() {
        let tracker = ReadaheadTracker::new();
        let ino = make_inode(10);
        let file_size = 1024 * 1024;

        // Zero-length reads are sequential but don't advance the offset
        tracker.record_read(ino, 0, 4096, file_size);
        tracker.record_read(ino, 4096, 0, file_size); // zero-length
                                                      // Still only count = 2 (zero-length counted as sequential)
        let plan = tracker.record_read(ino, 4096, 4096, file_size);
        assert!(plan.is_some());
    }

    #[test]
    fn issue_readahead_without_evidence_does_not_warm_hot_read_cache() {
        set_test_key();
        let dir = temp_dir("missing-evidence");
        let payload = vec![0xAB; 256 * 1024];

        let mut fs = LocalFileSystem::open(&dir).expect("open filesystem");
        fs.create_file("/warm.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/warm.bin", 0, &payload).expect("write");
        fs.sync_all().expect("sync");

        issue_readahead(&fs, "/warm.bin", 0, payload.len() as u64);

        let report = fs.hot_read_cache_report();
        assert_eq!(report.insertions, 0, "readahead has no authority evidence");
        assert_eq!(report.resident_entries, 0, "cache remains cold");
    }

    #[test]
    fn executor_refused_readahead_does_not_dispatch() {
        set_test_key();
        let dir = temp_dir("executor-refused");
        let payload = vec![0xEF; 128 * 1024];

        let mut fs = LocalFileSystem::open(&dir).expect("open filesystem");
        fs.create_file("/cold.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/cold.bin", 0, &payload).expect("write");
        fs.sync_all().expect("sync");

        // Default executor input has no decision, evidence, or admission:
        // the executor must refuse.
        let executor_input = Default::default();

        let outcome = issue_readahead_with_executor(
            &fs,
            "/cold.bin",
            0,
            payload.len() as u64,
            executor_input,
        );

        assert_ne!(
            outcome.executor_record.outcome,
            tidefs_storage_intent_prefetch_executor::PrefetchExecutorOutcome::Started,
            "executor must refuse when decision and evidence are absent"
        );
        assert!(
            outcome.bytes_issued.is_none(),
            "no bytes dispatched when executor refuses"
        );
    }

    #[test]
    fn executor_adapter_preserves_executor_record() {
        set_test_key();
        let dir = temp_dir("executor-record");
        let payload = vec![0xAA; 64 * 1024];

        let mut fs = LocalFileSystem::open(&dir).expect("open filesystem");
        fs.create_file("/rec.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/rec.bin", 0, &payload).expect("write");
        fs.sync_all().expect("sync");

        let executor_input = Default::default();

        let outcome =
            issue_readahead_with_executor(&fs, "/rec.bin", 0, payload.len() as u64, executor_input);

        // The outcome carries the full executor record for attribution (#912),
        // retention (#910), and explanation (#849).
        assert!(!outcome.executor_record.can_publish_replacement_receipt());
        assert!(!outcome.executor_record.can_retire_source_receipt());
        assert!(!outcome.executor_record.can_satisfy_durable_sync());
    }
}
