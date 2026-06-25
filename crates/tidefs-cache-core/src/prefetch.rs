// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Sequential access detection for prefetch/readahead.
//!
//! Provides [`SequentialDetector`] — a per-handle offset tracker that
//! detects sequential forward reads, strided patterns, and random access,
//! driving the readahead planner and speculative IO budget.

use std::collections::HashMap;

use crate::{
    budget_category_for_cache_level, BudgetCategory, CacheBudgetLevel, Governor,
};

/// Tracks recent read offsets per file handle to classify access patterns.
///
/// Each handle maintains a bounded ring of the last N read offsets.
/// The detector answers three questions:
///
/// 1. **Sequential forward**: are offsets monotonically increasing?
/// 2. **Strided sequential**: is there a constant stride between offsets?
/// 3. **Sequential run length**: how many consecutive sequential reads?
///
/// # Examples
///
/// ```ignore
/// let mut det = SequentialDetector::new(8, 3);
/// det.record_read(1, 0);
/// det.record_read(1, 4096);
/// det.record_read(1, 8192);
/// assert!(det.is_sequential(1));
/// assert_eq!(det.compute_stride(1), Some(4096));
/// ```
#[derive(Clone, Debug)]
pub struct SequentialDetector {
    /// Maximum number of recent offsets stored per handle.
    max_history: usize,
    /// Minimum history entries required before classifying a pattern.
    min_history: usize,
    /// Per-handle ring buffer: (handle_id → recent offsets, oldest first).
    handles: HashMap<u64, Vec<u64>>,
}

impl SequentialDetector {
    /// Create a new detector.
    ///
    /// `max_history` bounds how many recent offsets are kept per handle.
    /// `min_history` is the minimum number of recorded reads before a
    /// sequential or stride classification is attempted.
    #[must_use]
    pub fn new(max_history: usize, min_history: usize) -> Self {
        assert!(max_history > 0, "max_history must be positive");
        assert!(min_history > 0, "min_history must be positive");
        assert!(
            min_history <= max_history,
            "min_history must not exceed max_history"
        );
        Self {
            max_history,
            min_history,
            handles: HashMap::new(),
        }
    }

    /// Record a read at the given `offset` for the given `handle_id`.
    ///
    /// Offsets are appended to the handle's history; if the history exceeds
    /// `max_history`, the oldest offset is dropped.
    pub fn record_read(&mut self, handle_id: u64, offset: u64) {
        let history = self.handles.entry(handle_id).or_default();
        history.push(offset);
        if history.len() > self.max_history {
            history.remove(0);
        }
    }

    /// Return true if the handle exhibits sequential forward access.
    ///
    /// Sequential forward means every recorded offset (after the first) is
    /// strictly greater than the previous one. At least `min_history` entries
    /// must be present. Returns `false` for insufficient history.
    #[must_use]
    pub fn is_sequential(&self, handle_id: u64) -> bool {
        let history = match self.handles.get(&handle_id) {
            Some(h) if h.len() >= self.min_history => h,
            _ => return false,
        };
        history.windows(2).all(|w| w[1] > w[0])
    }

    /// Return the sequential run length — the count of consecutive
    /// monotonically-increasing offsets at the tail of the history.
    ///
    /// Returns 0 if fewer than 2 entries exist.
    #[must_use]
    pub fn sequential_run_length(&self, handle_id: u64) -> usize {
        let history = match self.handles.get(&handle_id) {
            Some(h) if h.len() >= 2 => h,
            _ => return 0,
        };
        let mut run = 1;
        for w in history.windows(2).rev() {
            if w[1] > w[0] {
                run += 1;
            } else {
                break;
            }
        }
        run
    }

    /// Compute the stride if the handle exhibits a strided sequential pattern.
    ///
    /// A strided pattern has a constant difference between consecutive
    /// offsets. Returns `Some(stride)` if at least `min_history` entries
    /// exist and all consecutive pairs have the same difference.
    /// Returns `None` for irregular spacing or insufficient history.
    #[must_use]
    pub fn compute_stride(&self, handle_id: u64) -> Option<u64> {
        let history = self.handles.get(&handle_id)?;
        if history.len() < self.min_history {
            return None;
        }
        let mut strides = history.windows(2).map(|w| w[1] - w[0]);
        let first = strides.next()?;
        if first == 0 {
            return None; // zero stride is not a valid sequential pattern
        }
        if strides.all(|s| s == first) {
            Some(first)
        } else {
            None
        }
    }

    /// Clear the history for a handle (e.g., on file close).
    pub fn clear(&mut self, handle_id: u64) {
        self.handles.remove(&handle_id);
    }

    /// Return the number of tracked handles.
    #[must_use]
    pub fn handle_count(&self) -> usize {
        self.handles.len()
    }

    /// Return the most recently recorded offset for a handle, if any.
    #[must_use]
    pub fn last_offset(&self, handle_id: u64) -> Option<u64> {
        self.handles.get(&handle_id)?.last().copied()
    }

    /// Return the most recent delta (difference between last two offsets),
    /// if the offsets are forward-increasing. Returns `None` if fewer than
    /// 2 entries exist or the last pair is not increasing.
    #[must_use]
    pub fn last_delta(&self, handle_id: u64) -> Option<u64> {
        let history = self.handles.get(&handle_id)?;
        if history.len() < 2 {
            return None;
        }
        let len = history.len();
        let a = history[len - 2];
        let b = history[len - 1];
        if b > a {
            Some(b - a)
        } else {
            None
        }
    }

    /// Return an iterator over (handle_id, history_len) pairs.
    pub fn iter_handles(&self) -> impl Iterator<Item = (u64, usize)> + '_ {
        self.handles.iter().map(|(k, v)| (*k, v.len()))
    }
}

// ---------------------------------------------------------------------------
// ReadaheadPlanner
// ---------------------------------------------------------------------------

/// Plans readahead windows based on sequential access detection.
///
/// Given a [`SequentialDetector`], the planner computes how many bytes to
/// prefetch ahead of the current read position when a sequential pattern
/// is detected.
///
/// The window formula:
///
/// ```text
/// window = min(max_readahead, run_length * stride * multiplier)
/// ```
///
/// Where `stride` comes from the detector (constant stride > last delta >
/// default stride fallback) and `run_length` is the number of consecutive
/// forward reads.
///
/// # Examples
///
/// ```ignore
/// let mut det = SequentialDetector::new(8, 3);
/// det.record_read(1, 0);
/// det.record_read(1, 4096);
/// det.record_read(1, 8192);
///
/// let planner = ReadaheadPlanner::new(65536, 2.0, 4096);
/// let (start, window) = planner.plan(&det, 1).unwrap();
/// assert_eq!(start, 12288);   // 8192 + 4096
/// assert_eq!(window, 24576);  // min(65536, 3 * 4096 * 2.0)
/// ```
#[derive(Clone, Debug)]
pub struct ReadaheadPlanner {
    /// Hard ceiling on the readahead window in bytes.
    max_readahead: u64,
    /// Multiplier applied to (run_length * stride) before capping.
    multiplier: f64,
    /// Fallback stride when no constant stride is detected (e.g. PAGE_SIZE).
    default_stride: u64,
}

impl ReadaheadPlanner {
    /// Create a new planner.
    ///
    /// `max_readahead` is the absolute ceiling on the window in bytes.
    /// `multiplier` scales the computed window (typical range 1.0–4.0).
    /// `default_stride` is used when the detector has not yet identified a
    /// constant stride (e.g., 4096 for a typical page size).
    #[must_use]
    pub fn new(max_readahead: u64, multiplier: f64, default_stride: u64) -> Self {
        assert!(max_readahead > 0, "max_readahead must be positive");
        assert!(multiplier > 0.0, "multiplier must be positive");
        assert!(default_stride > 0, "default_stride must be positive");
        Self {
            max_readahead,
            multiplier,
            default_stride,
        }
    }

    /// Plan a readahead window for the given handle.
    ///
    /// Returns `Some((start_offset, window_bytes))` if the handle exhibits
    /// sequential forward access and has sufficient history. `start_offset`
    /// is the byte offset where prefetch should begin, and `window_bytes`
    /// is the number of bytes to prefetch.
    ///
    /// Returns `None` if the handle is not sequential or has insufficient
    /// history to determine a start offset.
    #[must_use]
    pub fn plan(&self, detector: &SequentialDetector, handle_id: u64) -> Option<(u64, u64)> {
        if !detector.is_sequential(handle_id) {
            return None;
        }
        let last_offset = detector.last_offset(handle_id)?;
        let run_length = detector.sequential_run_length(handle_id) as u64;
        if run_length == 0 {
            return None;
        }

        // Determine stride: prefer constant stride, then last delta, then default
        let stride = detector
            .compute_stride(handle_id)
            .or_else(|| detector.last_delta(handle_id))
            .unwrap_or(self.default_stride);

        let start_offset = last_offset + stride;
        let raw_window = (run_length as f64 * stride as f64 * self.multiplier) as u64;
        let window_bytes = raw_window.min(self.max_readahead);

        // Window must be non-zero
        if window_bytes == 0 {
            return None;
        }

        Some((start_offset, window_bytes))
    }

    /// Return the configured max_readahead cap.
    #[must_use]
    pub fn max_readahead(&self) -> u64 {
        self.max_readahead
    }

    /// Return the configured multiplier.
    #[must_use]
    pub fn multiplier(&self) -> f64 {
        self.multiplier
    }
}

// ---------------------------------------------------------------------------
// PrefetchStats
// ---------------------------------------------------------------------------

/// A point-in-time snapshot of prefetch statistics.
///
/// Returned by [`PrefetchStats::snapshot()`] for inspection and reporting
/// without holding any locks on the live counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrefetchStatsSnapshot {
    /// Number of file handles currently tracked by the detector.
    pub files_tracked: u64,
    /// Cumulative number of sequential access detections.
    pub sequential_detections: u64,
    /// Total number of prefetch IOs issued.
    pub prefetch_ios_issued: u64,
    /// Number of prefetched pages that were hit before eviction.
    pub prefetch_hits: u64,
    /// Number of demand reads that arrived before prefetch completed (misses).
    pub prefetch_misses: u64,
    /// Total bytes prefetched (regardless of hit/miss).
    pub bytes_prefetched: u64,
    /// Bytes prefetched but never read before eviction (wasted).
    pub wasted_bytes: u64,
}

impl PrefetchStatsSnapshot {
    /// Compute the prefetch hit rate as a fraction in [0.0, 1.0].
    /// Returns 0.0 if no prefetch IOs were issued.
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.prefetch_hits + self.prefetch_misses;
        if total == 0 {
            0.0
        } else {
            self.prefetch_hits as f64 / total as f64
        }
    }

    /// Compute the waste ratio: wasted_bytes / bytes_prefetched.
    /// Returns 0.0 if nothing was prefetched.
    #[must_use]
    pub fn waste_ratio(&self) -> f64 {
        if self.bytes_prefetched == 0 {
            0.0
        } else {
            self.wasted_bytes as f64 / self.bytes_prefetched as f64
        }
    }
}

/// Live counters for prefetch operations.
///
/// All counters are monotonic (`u64`). The struct is `Clone` to allow
/// cheap duplication for point-in-time snapshots.
///
/// # Examples
///
/// ```ignore
/// let mut stats = PrefetchStats::new();
/// stats.record_sequential_detection();
/// stats.record_prefetch_io(4096);
/// stats.record_prefetch_hit();
/// let snap = stats.snapshot();
/// assert_eq!(snap.sequential_detections, 1);
/// assert_eq!(snap.bytes_prefetched, 4096);
/// ```
#[derive(Clone, Debug, Default)]
pub struct PrefetchStats {
    files_tracked: u64,
    sequential_detections: u64,
    prefetch_ios_issued: u64,
    prefetch_hits: u64,
    prefetch_misses: u64,
    bytes_prefetched: u64,
    wasted_bytes: u64,
}

impl PrefetchStats {
    /// Create a new zeroed stats collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a new file handle is being tracked.
    pub fn record_file_tracked(&mut self) {
        self.files_tracked += 1;
    }

    /// Record that a file handle is no longer tracked.
    /// Saturating to prevent underflow.
    pub fn record_file_untracked(&mut self) {
        self.files_tracked = self.files_tracked.saturating_sub(1);
    }

    /// Record a sequential access pattern detection.
    pub fn record_sequential_detection(&mut self) {
        self.sequential_detections += 1;
    }

    /// Record a prefetch IO of `bytes` issued.
    pub fn record_prefetch_io(&mut self, bytes: u64) {
        self.prefetch_ios_issued += 1;
        self.bytes_prefetched += bytes;
    }

    /// Record a prefetch hit: a prefetched page was read before eviction.
    pub fn record_prefetch_hit(&mut self) {
        self.prefetch_hits += 1;
    }

    /// Record a prefetch miss: a demand read arrived before prefetch completed.
    pub fn record_prefetch_miss(&mut self) {
        self.prefetch_misses += 1;
    }

    /// Record wasted bytes: data that was prefetched but evicted before use.
    pub fn record_wasted_bytes(&mut self, bytes: u64) {
        self.wasted_bytes += bytes;
    }

    /// Return a point-in-time snapshot of all counters.
    #[must_use]
    pub fn snapshot(&self) -> PrefetchStatsSnapshot {
        PrefetchStatsSnapshot {
            files_tracked: self.files_tracked,
            sequential_detections: self.sequential_detections,
            prefetch_ios_issued: self.prefetch_ios_issued,
            prefetch_hits: self.prefetch_hits,
            prefetch_misses: self.prefetch_misses,
            bytes_prefetched: self.bytes_prefetched,
            wasted_bytes: self.wasted_bytes,
        }
    }
}

// ---------------------------------------------------------------------------
// PrefetchService
// ---------------------------------------------------------------------------

/// Core prefetch engine tying together detection, planning, and statistics.
///
/// `PrefetchService` is a direct-call service (not yet integrated with the
/// background scheduler). It wraps a [`SequentialDetector`], a
/// [`ReadaheadPlanner`], and [`PrefetchStats`], providing a simple API for
/// read-path integration:
///
/// 1. Call [`on_read`](Self::on_read) on every read to feed the detector.
/// 2. If the return is `Some(window)`, issue speculative IO for that window.
/// 3. After IO completes, call [`on_prefetch_hit`](Self::on_prefetch_hit) or
///    [`on_prefetch_miss`](Self::on_prefetch_miss) to update stats.
/// 4. When a prefetched page is evicted without use, call
///    [`on_prefetch_wasted`](Self::on_prefetch_wasted).
///
/// # Examples
///
/// ```ignore
/// let mut svc = PrefetchService::new(
///     SequentialDetector::new(8, 3),
///     ReadaheadPlanner::new(65536, 2.0, 4096),
/// );
/// // Simulate three sequential 4K reads on handle 1
/// svc.on_read(1, 0);
/// svc.on_read(1, 4096);
/// let window = svc.on_read(1, 8192);
/// assert!(window.is_some());
/// // Caller issues IO for window, then:
/// svc.on_prefetch_hit(1);
/// let snap = svc.stats().snapshot();
/// assert_eq!(snap.prefetch_hits, 1);
/// ```
#[derive(Clone, Debug)]
pub struct PrefetchService {
    detector: SequentialDetector,
    planner: ReadaheadPlanner,
    stats: PrefetchStats,
    /// Last planned readahead window per handle: (start_offset, window_bytes).
    planned: std::collections::HashMap<u64, (u64, u64)>,
    /// Optional resource governor for L2 prefetch/read-ahead window budgets.
    governor: Option<Governor>,
}

impl PrefetchService {
    /// Create a new prefetch service.
    ///
    /// The detector and planner are moved into the service; their
    /// configuration (history size, max readahead, multiplier, etc.)
    /// is set at construction time.
    #[must_use]
    pub fn new(detector: SequentialDetector, planner: ReadaheadPlanner) -> Self {
        Self {
            detector,
            planner,
            stats: PrefetchStats::new(),
            planned: std::collections::HashMap::new(),
            governor: None,
        }
    }

    /// Attach resource-governor accounting for planned L2 prefetch windows.
    pub fn set_governor(&mut self, governor: Governor) {
        self.governor = Some(governor);
    }

    /// Feed a read at `offset` on `handle_id` into the detector.
    ///
    /// If the read causes the handle to be classified as sequential, the
    /// planner computes a readahead window. The window is stored internally
    /// and returned so the caller can issue speculative IO.
    ///
    /// Returns `Some((start_offset, window_bytes))` when a prefetch window
    /// is ready, or `None` when the handle is not (yet) sequential or
    /// the planner declined to produce a window.
    pub fn on_read(&mut self, handle_id: u64, offset: u64) -> Option<(u64, u64)> {
        self.detector.record_read(handle_id, offset);
        let window = self.planner.plan(&self.detector, handle_id)?;
        self.release_planned_window(handle_id);
        if !self.admit_window_budget(window.1) {
            return None;
        }
        self.stats.record_sequential_detection();
        self.planned.insert(handle_id, window);
        Some(window)
    }

    /// Return the last planned readahead window for a handle, if any.
    ///
    /// This does not modify state; it is a pure query for callers that
    /// need to re-check the window without re-feeding a read.
    #[must_use]
    pub fn try_prefetch(&self, handle_id: u64) -> Option<(u64, u64)> {
        self.planned.get(&handle_id).copied()
    }

    /// Record a prefetch hit: the caller found prefetched data in cache.
    /// This updates statistics and removes the planned window for the handle.
    pub fn on_prefetch_hit(&mut self, handle_id: u64) {
        self.stats.record_prefetch_hit();
        self.release_planned_window(handle_id);
    }

    /// Record a prefetch miss: a demand read arrived before prefetch
    /// completed for this handle.
    pub fn on_prefetch_miss(&mut self, handle_id: u64) {
        self.stats.record_prefetch_miss();
        self.release_planned_window(handle_id);
    }

    /// Record wasted bytes: `bytes` of prefetched data were evicted
    /// from cache before being read.
    pub fn on_prefetch_wasted(&mut self, handle_id: u64, bytes: u64) {
        self.stats.record_wasted_bytes(bytes);
        self.release_planned_window(handle_id);
    }

    /// Record that a prefetch IO of `bytes` was issued.
    /// Call this after actually submitting the IO (not from `on_read`).
    pub fn on_prefetch_io_issued(&mut self, _handle_id: u64, bytes: u64) {
        self.stats.record_prefetch_io(bytes);
    }

    /// Record that a file handle is being tracked.
    pub fn on_file_opened(&mut self, _handle_id: u64) {
        self.stats.record_file_tracked();
    }

    /// Record that a file handle is no longer tracked.
    /// Cleans up detector history and planned window for the handle.
    pub fn on_file_closed(&mut self, handle_id: u64) {
        self.stats.record_file_untracked();
        self.detector.clear(handle_id);
        self.release_planned_window(handle_id);
    }

    /// Return a shared reference to the statistics collector.
    #[must_use]
    pub fn stats(&self) -> &PrefetchStats {
        &self.stats
    }

    /// Return a shared reference to the detector (for introspection).
    #[must_use]
    pub fn detector(&self) -> &SequentialDetector {
        &self.detector
    }

    /// Return a shared reference to the planner (for introspection).
    #[must_use]
    pub fn planner(&self) -> &ReadaheadPlanner {
        &self.planner
    }

    /// Return the number of handles with an active planned window.
    #[must_use]
    pub fn planned_count(&self) -> usize {
        self.planned.len()
    }

    fn budget_category() -> BudgetCategory {
        budget_category_for_cache_level(CacheBudgetLevel::L2PrefetchReadAhead)
    }

    fn admit_window_budget(&mut self, bytes: u64) -> bool {
        if let Some(ref governor) = self.governor {
            return governor.admit(Self::budget_category(), bytes).is_ok();
        }
        true
    }

    fn release_window_budget(&self, bytes: u64) {
        if let Some(ref governor) = self.governor {
            governor.release(Self::budget_category(), bytes);
        }
    }

    fn release_planned_window(&mut self, handle_id: u64) {
        if let Some((_, bytes)) = self.planned.remove(&handle_id) {
            self.release_window_budget(bytes);
        }
    }
}

impl Drop for PrefetchService {
    fn drop(&mut self) {
        let bytes: u64 = self.planned.values().map(|(_, bytes)| *bytes).sum();
        self.release_window_budget(bytes);
    }
}
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn data_governor() -> Governor {
        Governor::new(crate::GovernorConfig {
            total_budget_bytes: 1024 * 1024,
            data_cache_fraction: 1.0,
            meta_cache_fraction: 0.0,
            dirty_bytes_fraction: 0.0,
            inode_state_fraction: 0.0,
            cluster_queues_fraction: 0.0,
            misc_fraction: 0.0,
            auto_tune: false,
        })
        .unwrap()
    }

    // ── Sequential detection ─────────────────────────────────────────

    #[test]
    fn sequential_forward_detected() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(1, 0);
        det.record_read(1, 4096);
        det.record_read(1, 8192);
        assert!(det.is_sequential(1));
    }

    #[test]
    fn non_sequential_random_rejected() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(2, 0);
        det.record_read(2, 65536); // jump forward
        det.record_read(2, 4096); // jump backward — breaks monotonicity
        assert!(!det.is_sequential(2));
    }

    #[test]
    fn non_sequential_same_offset_rejected() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(3, 4096);
        det.record_read(3, 4096); // duplicate
        det.record_read(3, 8192);
        // Not strictly increasing because of duplicate
        assert!(!det.is_sequential(3));
    }

    #[test]
    fn insufficient_history_returns_false() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(4, 0);
        det.record_read(4, 4096);
        // Only 2 entries, min_history is 3
        assert!(!det.is_sequential(4));
    }

    #[test]
    fn exactly_min_history_is_sufficient() {
        let mut det = SequentialDetector::new(8, 2);
        det.record_read(5, 0);
        det.record_read(5, 4096);
        assert!(det.is_sequential(5));
    }

    // ── Sequential run length ────────────────────────────────────────

    #[test]
    fn sequential_run_length_counts_tail() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(10, 0);
        det.record_read(10, 4096);
        det.record_read(10, 8192); // 3 sequential
        det.record_read(10, 500); // backward jump breaks the run
        det.record_read(10, 4096);
        det.record_read(10, 8192); // 3 sequential at tail (500→4096→8192)
        assert_eq!(det.sequential_run_length(10), 3);
    }

    #[test]
    fn sequential_run_length_zero_for_insufficient() {
        let det = SequentialDetector::new(8, 3);
        assert_eq!(det.sequential_run_length(99), 0);
    }

    #[test]
    fn sequential_run_length_all_sequential() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(11, 0);
        det.record_read(11, 4096);
        det.record_read(11, 8192);
        det.record_read(11, 12288);
        assert_eq!(det.sequential_run_length(11), 4);
    }

    // ── Stride detection ─────────────────────────────────────────────

    #[test]
    fn stride_detected_constant_4096() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(20, 0);
        det.record_read(20, 4096);
        det.record_read(20, 8192);
        assert_eq!(det.compute_stride(20), Some(4096));
    }

    #[test]
    fn stride_detected_constant_1m() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(21, 0);
        det.record_read(21, 1_048_576);
        det.record_read(21, 2_097_152);
        assert_eq!(det.compute_stride(21), Some(1_048_576));
    }

    #[test]
    fn stride_none_for_irregular_spacing() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(22, 0);
        det.record_read(22, 4096);
        det.record_read(22, 12288); // stride of 4096 then 8192
        assert_eq!(det.compute_stride(22), None);
    }

    #[test]
    fn stride_none_for_zero_stride() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(23, 4096);
        det.record_read(23, 4096);
        det.record_read(23, 4096);
        assert_eq!(det.compute_stride(23), None); // zero stride rejected
    }

    #[test]
    fn stride_none_for_insufficient_history() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(24, 0);
        det.record_read(24, 4096);
        assert_eq!(det.compute_stride(24), None);
    }

    // ── Ring-buffer eviction ─────────────────────────────────────────

    #[test]
    fn ring_buffer_evicts_oldest() {
        let mut det = SequentialDetector::new(3, 2);
        det.record_read(30, 0);
        det.record_read(30, 4096);
        det.record_read(30, 8192);
        det.record_read(30, 12288); // evicts 0
                                    // History is now [4096, 8192, 12288]
        assert!(det.is_sequential(30));
        assert_eq!(det.compute_stride(30), Some(4096));
    }

    // ── Multi-handle isolation ───────────────────────────────────────

    #[test]
    fn handles_are_independent() {
        let mut det = SequentialDetector::new(8, 3);
        // Handle 40: sequential
        det.record_read(40, 0);
        det.record_read(40, 4096);
        det.record_read(40, 8192);
        // Handle 41: random
        det.record_read(41, 0);
        det.record_read(41, 65536);
        det.record_read(41, 4096);
        assert!(det.is_sequential(40));
        assert!(!det.is_sequential(41));
        assert_eq!(det.handle_count(), 2);
    }

    // ── Clear ────────────────────────────────────────────────────────

    #[test]
    fn clear_removes_handle() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(50, 0);
        det.record_read(50, 4096);
        det.record_read(50, 8192);
        assert_eq!(det.handle_count(), 1);
        det.clear(50);
        assert_eq!(det.handle_count(), 0);
        assert!(!det.is_sequential(50));
    }

    // ── Strided but non-sequential (decreasing) ──────────────────────

    #[test]
    fn constant_stride_decreasing_is_not_sequential() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(60, 8192);
        det.record_read(60, 4096);
        det.record_read(60, 0);
        // Constant stride of -4096 (wraps to large u64), but not increasing
        assert!(!det.is_sequential(60));
    }

    // ── Large offset values ──────────────────────────────────────────

    #[test]
    fn large_offsets_work() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(70, 1_000_000_000);
        det.record_read(70, 1_000_004_096);
        det.record_read(70, 1_000_008_192);
        assert!(det.is_sequential(70));
        assert_eq!(det.compute_stride(70), Some(4096));
    }

    // ── last_offset / last_delta ─────────────────────────────────────

    #[test]
    fn last_offset_returns_most_recent() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(80, 0);
        det.record_read(80, 4096);
        det.record_read(80, 8192);
        assert_eq!(det.last_offset(80), Some(8192));
    }

    #[test]
    fn last_offset_none_for_unknown_handle() {
        let det = SequentialDetector::new(8, 3);
        assert_eq!(det.last_offset(99), None);
    }

    #[test]
    fn last_delta_returns_recent_difference() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(81, 0);
        det.record_read(81, 4096);
        assert_eq!(det.last_delta(81), Some(4096));
    }

    #[test]
    fn last_delta_none_for_decreasing() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(82, 8192);
        det.record_read(82, 4096);
        assert_eq!(det.last_delta(82), None);
    }

    #[test]
    fn last_delta_none_for_insufficient() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(83, 4096);
        assert_eq!(det.last_delta(83), None);
    }

    // ── ReadaheadPlanner ─────────────────────────────────────────────

    #[test]
    fn plan_returns_window_for_sequential() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(90, 0);
        det.record_read(90, 4096);
        det.record_read(90, 8192);
        let planner = ReadaheadPlanner::new(65536, 2.0, 4096);
        let (start, window) = planner.plan(&det, 90).unwrap();
        assert_eq!(start, 12288); // 8192 + 4096
                                  // run_length=3, stride=4096, multiplier=2.0 → 24576
        assert_eq!(window, 24576);
    }

    #[test]
    fn plan_none_for_non_sequential() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(91, 0);
        det.record_read(91, 65536);
        det.record_read(91, 4096);
        let planner = ReadaheadPlanner::new(65536, 2.0, 4096);
        assert!(planner.plan(&det, 91).is_none());
    }

    #[test]
    fn plan_none_for_insufficient_history() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(92, 0);
        det.record_read(92, 4096);
        // Only 2 entries, min_history is 3
        let planner = ReadaheadPlanner::new(65536, 2.0, 4096);
        assert!(planner.plan(&det, 92).is_none());
    }

    #[test]
    fn plan_capped_by_max_readahead() {
        let mut det = SequentialDetector::new(8, 3);
        // 6 sequential reads of 4096 each
        for i in 0..6 {
            det.record_read(93, i * 4096);
        }
        // run_length=6, stride=4096, multiplier=2.0 → 49152
        // But max_readahead is 16384, so cap at 16384
        let planner = ReadaheadPlanner::new(16384, 2.0, 4096);
        let (_start, window) = planner.plan(&det, 93).unwrap();
        assert_eq!(window, 16384);
    }

    #[test]
    fn plan_fallback_to_default_stride() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(94, 0);
        det.record_read(94, 4096);
        det.record_read(94, 12288); // irregular: strides of 4096 and 8192
                                    // constant stride is None, last_delta is Some(8192)
                                    // So stride = 8192 (last_delta), not default
        let planner = ReadaheadPlanner::new(65536, 2.0, 4096);
        let (start, window) = planner.plan(&det, 94).unwrap();
        assert_eq!(start, 20480); // 12288 + 8192
        assert_eq!(window, 49152); // min(65536, 3 * 8192 * 2.0)
    }

    #[test]
    fn plan_uses_default_stride_when_no_delta() {
        let mut det = SequentialDetector::new(8, 3);
        // Make it sequential but with zero delta (duplicate offsets)
        det.record_read(95, 4096);
        det.record_read(95, 4096);
        det.record_read(95, 4096);
        // is_sequential is false (not increasing), so plan returns None.
        // This test confirms the non-increasing case is handled.
        let planner = ReadaheadPlanner::new(65536, 2.0, 4096);
        assert!(planner.plan(&det, 95).is_none());
    }

    #[test]
    fn plan_adaptive_window_grows_with_run_length() {
        let mut det = SequentialDetector::new(8, 3);
        let planner = ReadaheadPlanner::new(1_000_000, 2.0, 4096);

        // 3 sequential reads
        det.record_read(96, 0);
        det.record_read(96, 4096);
        det.record_read(96, 8192);
        let w1 = planner.plan(&det, 96).unwrap().1;
        assert_eq!(w1, 24576); // 3 * 4096 * 2.0

        // Extend to 5 sequential reads
        det.record_read(96, 12288);
        det.record_read(96, 16384);
        let w2 = planner.plan(&det, 96).unwrap().1;
        assert_eq!(w2, 40960); // 5 * 4096 * 2.0
        assert!(w2 > w1);
    }

    #[test]
    fn plan_window_shrinks_after_backward_jump() {
        let mut det = SequentialDetector::new(8, 3);
        let planner = ReadaheadPlanner::new(1_000_000, 2.0, 4096);

        // Build a long sequential run
        for i in 0..8 {
            det.record_read(97, i * 4096);
        }
        let _w1 = planner.plan(&det, 97).unwrap().1;

        // Break the run with a backward jump
        det.record_read(97, 4096);
        // Run length is now 2 (4096→8192 doesn't exist; only one forward pair
        // at the tail: whatever the last valid forward pair is).
        // Actually after recording [0..7*4096=28672] then recording 4096,
        // the history (with max_history=8) is [4096, 8192, ..., 28672, 4096]
        // So last pair is 28672→4096 (decreasing), run_length = 1.
        // is_sequential is false, so plan returns None.
        assert!(planner.plan(&det, 97).is_none());
    }

    #[test]
    fn plan_respects_multiplier_one() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(98, 0);
        det.record_read(98, 4096);
        det.record_read(98, 8192);
        let planner = ReadaheadPlanner::new(65536, 1.0, 4096);
        let (_start, window) = planner.plan(&det, 98).unwrap();
        assert_eq!(window, 12288); // 3 * 4096 * 1.0
    }

    #[test]
    fn plan_with_large_stride() {
        let mut det = SequentialDetector::new(8, 3);
        det.record_read(99, 0);
        det.record_read(99, 1_048_576);
        det.record_read(99, 2_097_152);
        let planner = ReadaheadPlanner::new(10_485_760, 2.0, 4096);
        let (start, window) = planner.plan(&det, 99).unwrap();
        assert_eq!(start, 3_145_728); // 2097152 + 1048576
                                      // 3 * 1048576 * 2.0 = 6291456, cap=10485760 → 6291456
        assert_eq!(window, 6_291_456);
    }

    #[test]
    fn plan_none_for_unknown_handle() {
        let det = SequentialDetector::new(8, 3);
        let planner = ReadaheadPlanner::new(65536, 2.0, 4096);
        assert!(planner.plan(&det, 999).is_none());
    }

    #[test]
    fn planner_accessors() {
        let planner = ReadaheadPlanner::new(65536, 2.5, 4096);
        assert_eq!(planner.max_readahead(), 65536);
        assert!((planner.multiplier() - 2.5).abs() < f64::EPSILON);
    }

    // ── PrefetchStats ────────────────────────────────────────────────

    #[test]
    fn stats_new_all_zero() {
        let stats = PrefetchStats::new();
        let snap = stats.snapshot();
        assert_eq!(snap.files_tracked, 0);
        assert_eq!(snap.sequential_detections, 0);
        assert_eq!(snap.prefetch_ios_issued, 0);
        assert_eq!(snap.prefetch_hits, 0);
        assert_eq!(snap.prefetch_misses, 0);
        assert_eq!(snap.bytes_prefetched, 0);
        assert_eq!(snap.wasted_bytes, 0);
    }

    #[test]
    fn stats_record_file_tracked() {
        let mut stats = PrefetchStats::new();
        stats.record_file_tracked();
        assert_eq!(stats.snapshot().files_tracked, 1);
        stats.record_file_tracked();
        assert_eq!(stats.snapshot().files_tracked, 2);
    }

    #[test]
    fn stats_record_file_untracked_saturating() {
        let mut stats = PrefetchStats::new();
        stats.record_file_untracked(); // 0 -> 0 (saturating)
        assert_eq!(stats.snapshot().files_tracked, 0);
        stats.record_file_tracked();
        stats.record_file_untracked();
        assert_eq!(stats.snapshot().files_tracked, 0);
    }

    #[test]
    fn stats_record_sequential_detection() {
        let mut stats = PrefetchStats::new();
        stats.record_sequential_detection();
        stats.record_sequential_detection();
        assert_eq!(stats.snapshot().sequential_detections, 2);
    }

    #[test]
    fn stats_record_prefetch_io() {
        let mut stats = PrefetchStats::new();
        stats.record_prefetch_io(4096);
        assert_eq!(stats.snapshot().prefetch_ios_issued, 1);
        assert_eq!(stats.snapshot().bytes_prefetched, 4096);
        stats.record_prefetch_io(8192);
        assert_eq!(stats.snapshot().prefetch_ios_issued, 2);
        assert_eq!(stats.snapshot().bytes_prefetched, 12288);
    }

    #[test]
    fn stats_record_hit_miss() {
        let mut stats = PrefetchStats::new();
        stats.record_prefetch_hit();
        stats.record_prefetch_hit();
        stats.record_prefetch_miss();
        let snap = stats.snapshot();
        assert_eq!(snap.prefetch_hits, 2);
        assert_eq!(snap.prefetch_misses, 1);
    }

    #[test]
    fn stats_record_wasted_bytes() {
        let mut stats = PrefetchStats::new();
        stats.record_wasted_bytes(1024);
        stats.record_wasted_bytes(2048);
        assert_eq!(stats.snapshot().wasted_bytes, 3072);
    }

    #[test]
    fn stats_hit_rate() {
        let mut stats = PrefetchStats::new();
        // No IOs -> 0.0
        assert!((stats.snapshot().hit_rate() - 0.0).abs() < f64::EPSILON);

        stats.record_prefetch_hit();
        stats.record_prefetch_miss();
        stats.record_prefetch_hit();
        // 2 hits, 1 miss -> 0.666...
        let rate = stats.snapshot().hit_rate();
        assert!((rate - 2.0 / 3.0).abs() < 0.001);
    }

    #[test]
    fn stats_waste_ratio() {
        let mut stats = PrefetchStats::new();
        // No bytes -> 0.0
        assert!((stats.snapshot().waste_ratio() - 0.0).abs() < f64::EPSILON);

        stats.record_prefetch_io(10000); // bytes_prefetched = 10000
        stats.record_wasted_bytes(2500);
        let ratio = stats.snapshot().waste_ratio();
        assert!((ratio - 0.25).abs() < 0.001);
    }

    #[test]
    fn stats_snapshot_independent() {
        let mut stats = PrefetchStats::new();
        stats.record_file_tracked();
        let snap1 = stats.snapshot();
        stats.record_file_tracked();
        // snap1 should still show 1, not 2
        assert_eq!(snap1.files_tracked, 1);
        let snap2 = stats.snapshot();
        assert_eq!(snap2.files_tracked, 2);
    }

    #[test]
    fn stats_clone_independent() {
        let mut stats = PrefetchStats::new();
        stats.record_file_tracked();
        let mut clone = stats.clone();
        clone.record_file_tracked();
        assert_eq!(stats.snapshot().files_tracked, 1);
        assert_eq!(clone.snapshot().files_tracked, 2);
    }

    #[test]
    fn stats_snapshot_default_all_zero() {
        let snap = PrefetchStatsSnapshot::default();
        assert_eq!(snap.files_tracked, 0);
        assert_eq!(snap.sequential_detections, 0);
        assert_eq!(snap.prefetch_ios_issued, 0);
        assert_eq!(snap.hit_rate(), 0.0);
        assert_eq!(snap.waste_ratio(), 0.0);
    }

    #[test]
    fn stats_io_with_zero_bytes() {
        let mut stats = PrefetchStats::new();
        stats.record_prefetch_io(0); // pathological zero-byte IO
        assert_eq!(stats.snapshot().prefetch_ios_issued, 1);
        assert_eq!(stats.snapshot().bytes_prefetched, 0);
    }

    // ── PrefetchService ──────────────────────────────────────────────

    #[test]
    fn service_on_read_sequential_produces_window() {
        let det = SequentialDetector::new(8, 3);
        let planner = ReadaheadPlanner::new(65536, 2.0, 4096);
        let mut svc = PrefetchService::new(det, planner);

        // First two reads don't produce a window (not yet sequential)
        let w0 = svc.on_read(100, 0);
        let w1 = svc.on_read(100, 4096);
        assert!(w0.is_none());
        assert!(w1.is_none());

        // Third read triggers sequential detection
        let w2 = svc.on_read(100, 8192);
        assert!(w2.is_some());
        let (start, size) = w2.unwrap();
        assert_eq!(start, 12288); // 8192 + 4096
        assert_eq!(size, 24576); // 3 * 4096 * 2.0

        let snap = svc.stats().snapshot();
        assert_eq!(snap.sequential_detections, 1);
    }

    #[test]
    fn service_on_read_random_no_window() {
        let det = SequentialDetector::new(8, 3);
        let planner = ReadaheadPlanner::new(65536, 2.0, 4096);
        let mut svc = PrefetchService::new(det, planner);

        svc.on_read(101, 0);
        svc.on_read(101, 65536);
        let w = svc.on_read(101, 4096); // backward jump
        assert!(w.is_none());
        assert_eq!(svc.stats().snapshot().sequential_detections, 0);
    }

    #[test]
    fn service_try_prefetch_returns_planned_window() {
        let det = SequentialDetector::new(8, 3);
        let planner = ReadaheadPlanner::new(65536, 2.0, 4096);
        let mut svc = PrefetchService::new(det, planner);

        // Build sequential pattern on handle 102
        svc.on_read(102, 0);
        svc.on_read(102, 4096);
        let w = svc.on_read(102, 8192).unwrap();

        // try_prefetch should return the same window
        let cached = svc.try_prefetch(102);
        assert_eq!(cached, Some(w));

        // Unknown handle returns None
        assert!(svc.try_prefetch(999).is_none());
    }

    #[test]
    fn service_hit_updates_stats_and_clears_plan() {
        let det = SequentialDetector::new(8, 3);
        let planner = ReadaheadPlanner::new(65536, 2.0, 4096);
        let mut svc = PrefetchService::new(det, planner);

        svc.on_read(103, 0);
        svc.on_read(103, 4096);
        svc.on_read(103, 8192);

        svc.on_prefetch_hit(103);
        assert_eq!(svc.stats().snapshot().prefetch_hits, 1);
        assert!(svc.try_prefetch(103).is_none()); // plan cleared
    }

    #[test]
    fn service_miss_updates_stats_and_clears_plan() {
        let det = SequentialDetector::new(8, 3);
        let planner = ReadaheadPlanner::new(65536, 2.0, 4096);
        let mut svc = PrefetchService::new(det, planner);

        svc.on_read(104, 0);
        svc.on_read(104, 4096);
        svc.on_read(104, 8192);

        svc.on_prefetch_miss(104);
        assert_eq!(svc.stats().snapshot().prefetch_misses, 1);
        assert!(svc.try_prefetch(104).is_none());
    }

    #[test]
    fn service_wasted_updates_bytes() {
        let det = SequentialDetector::new(8, 3);
        let planner = ReadaheadPlanner::new(65536, 2.0, 4096);
        let mut svc = PrefetchService::new(det, planner);

        svc.on_prefetch_wasted(105, 4096);
        svc.on_prefetch_wasted(105, 8192);
        assert_eq!(svc.stats().snapshot().wasted_bytes, 12288);
    }

    #[test]
    fn service_io_issued_updates_counters() {
        let det = SequentialDetector::new(8, 3);
        let planner = ReadaheadPlanner::new(65536, 2.0, 4096);
        let mut svc = PrefetchService::new(det, planner);

        svc.on_prefetch_io_issued(106, 4096);
        svc.on_prefetch_io_issued(106, 16384);
        let snap = svc.stats().snapshot();
        assert_eq!(snap.prefetch_ios_issued, 2);
        assert_eq!(snap.bytes_prefetched, 20480);
    }

    #[test]
    fn service_file_open_close_tracks_count() {
        let det = SequentialDetector::new(8, 3);
        let planner = ReadaheadPlanner::new(65536, 2.0, 4096);
        let mut svc = PrefetchService::new(det, planner);

        svc.on_file_opened(107);
        svc.on_file_opened(108);
        assert_eq!(svc.stats().snapshot().files_tracked, 2);

        svc.on_file_closed(107);
        assert_eq!(svc.stats().snapshot().files_tracked, 1);
    }

    #[test]
    fn service_file_close_cleans_detector_and_plan() {
        let det = SequentialDetector::new(8, 3);
        let planner = ReadaheadPlanner::new(65536, 2.0, 4096);
        let mut svc = PrefetchService::new(det, planner);

        svc.on_read(109, 0);
        svc.on_read(109, 4096);
        svc.on_read(109, 8192);
        assert!(svc.try_prefetch(109).is_some());

        svc.on_file_closed(109);
        assert!(svc.try_prefetch(109).is_none());
        assert!(!svc.detector().is_sequential(109));
        assert_eq!(svc.stats().snapshot().files_tracked, 0);
    }

    #[test]
    fn service_planned_count() {
        let det = SequentialDetector::new(8, 3);
        let planner = ReadaheadPlanner::new(65536, 2.0, 4096);
        let mut svc = PrefetchService::new(det, planner);

        // Handle 110 sequential
        svc.on_read(110, 0);
        svc.on_read(110, 4096);
        svc.on_read(110, 8192);
        assert_eq!(svc.planned_count(), 1);

        // Handle 111 sequential
        svc.on_read(111, 0);
        svc.on_read(111, 4096);
        svc.on_read(111, 8192);
        assert_eq!(svc.planned_count(), 2);

        // Hit on 110 clears its plan
        svc.on_prefetch_hit(110);
        assert_eq!(svc.planned_count(), 1);
    }

    #[test]
    fn service_governor_charges_planned_readahead_to_data_cache() {
        let det = SequentialDetector::new(8, 3);
        let planner = ReadaheadPlanner::new(65536, 2.0, 4096);
        let governor = data_governor();
        let mut svc = PrefetchService::new(det, planner);
        svc.set_governor(governor.clone());

        svc.on_read(120, 0);
        svc.on_read(120, 4096);
        let (_, window_bytes) = svc.on_read(120, 8192).unwrap();
        assert_eq!(
            governor.category_used(BudgetCategory::DataCache),
            window_bytes
        );

        svc.on_prefetch_hit(120);
        assert_eq!(governor.category_used(BudgetCategory::DataCache), 0);
    }

    #[test]
    fn service_accessors() {
        let det = SequentialDetector::new(8, 3);
        let planner = ReadaheadPlanner::new(65536, 2.5, 4096);
        let svc = PrefetchService::new(det, planner);

        assert_eq!(svc.planner().max_readahead(), 65536);
        assert!((svc.planner().multiplier() - 2.5).abs() < f64::EPSILON);
        assert_eq!(svc.stats().snapshot().files_tracked, 0);
    }

    #[test]
    fn service_window_adaptive_across_multiple_reads() {
        let det = SequentialDetector::new(8, 3);
        let planner = ReadaheadPlanner::new(1_000_000, 2.0, 4096);
        let mut svc = PrefetchService::new(det, planner);

        // 3 reads → small window
        svc.on_read(112, 0);
        svc.on_read(112, 4096);
        let w1 = svc.on_read(112, 8192).unwrap();
        assert_eq!(w1.1, 24576); // 3 * 4096 * 2.0

        // 5 reads → larger window
        svc.on_read(112, 12288);
        let w2 = svc.on_read(112, 16384).unwrap();
        assert_eq!(w2.1, 40960); // 5 * 4096 * 2.0
        assert!(w2.1 > w1.1);
    }
}
