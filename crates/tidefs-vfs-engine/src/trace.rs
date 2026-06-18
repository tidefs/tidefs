// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! VFS Engine boundary trace emission — lightweight in-process ring buffer.
//!
//! This module implements the core tracing primitives for VFS Engine
//! observability (issue #3458 / Contract 3 P1). Every VFS operation
//! boundary can be recorded as a [`VfsTrace`] event, buffered in a
//! fixed-capacity [`VfsTracer`] ring, filtered by [`VfsTraceFilter`],
//! and summarised by [`VfsTraceStats`].
//!
//! This is the in-process runtime tracer; the full JSONL cross-
//! implementation format lives in `docs/design/` and the higher-level
//! `TracedVfsEngine` wrapper (P2) will consume these primitives.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use tidefs_types_vfs_core::Errno;

/// A single trace event recorded at a VFS Engine operation boundary.
///
/// Every call to a [`super::VfsEngine`] operation produces exactly one
/// trace step *after* the operation completes (success or error).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VfsTrace {
    /// Operation started (entry). Captures the op name, target inode,
    /// argument hash, and the transaction-group id.
    VfsOpStart {
        /// Wire-stable operation name (e.g. `"lookup"`, `"read"`).
        op: &'static str,
        /// Primary target inode for this operation (0 when not applicable).
        inode: u64,
        /// Dataset identifier for multi-dataset filtering.
        dataset_id: u64,
        /// Hash of the call arguments for correlation with the full trace.
        args_hash: u64,
        /// Transaction-group id at entry time.
        commit_group_id: u64,
    },
    /// Operation completed successfully (exit).
    VfsOpEnd {
        op: &'static str,
        inode: u64,
        dataset_id: u64,
        /// Wall-clock latency in microseconds.
        latency_us: u64,
        commit_group_id: u64,
    },
    /// Operation completed with an error.
    VfsOpError {
        op: &'static str,
        inode: u64,
        dataset_id: u64,
        /// Positive Linux errno (e.g. 2 for ENOENT).
        error: u16,
        latency_us: u64,
        commit_group_id: u64,
    },
}

/// Filter criteria for querying the trace ring buffer.
///
/// All fields are optional; when `None` the criterion is not applied.
/// Filters are ANDed together.
#[derive(Clone, Debug, Default)]
pub struct VfsTraceFilter {
    /// Only return events matching this exact op name.
    pub op: Option<&'static str>,
    /// Only return events for this inode.
    pub inode: Option<u64>,
    /// Only return events for this dataset.
    pub dataset_id: Option<u64>,
    /// Only return events where latency >= this threshold (microseconds).
    pub min_latency_us: Option<u64>,
}

impl VfsTraceFilter {
    /// Create an empty filter (matches everything).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            op: None,
            inode: None,
            dataset_id: None,
            min_latency_us: None,
        }
    }

    /// Set the op filter.
    #[must_use]
    pub const fn with_op(mut self, op: &'static str) -> Self {
        self.op = Some(op);
        self
    }

    /// Set the dataset filter.
    #[must_use]
    pub const fn with_dataset(mut self, dataset_id: u64) -> Self {
        self.dataset_id = Some(dataset_id);
        self
    }

    /// Set the inode filter.
    #[must_use]
    pub const fn with_inode(mut self, inode: u64) -> Self {
        self.inode = Some(inode);
        self
    }

    /// Set the minimum latency filter.
    #[must_use]
    pub const fn with_min_latency(mut self, latency_us: u64) -> Self {
        self.min_latency_us = Some(latency_us);
        self
    }

    /// Returns true when `event` passes all active filter criteria.
    #[must_use]
    pub fn matches(&self, event: &VfsTrace) -> bool {
        let op = event.op();
        let inode = event.inode();
        let latency = event.latency_us();
        if let Some(wanted) = self.op {
            if wanted != op {
                return false;
            }
        }
        if let Some(wanted) = self.inode {
            if wanted != inode {
                return false;
            }
        }
        if let Some(wanted_ds) = self.dataset_id {
            if wanted_ds != event.dataset_id() {
                return false;
            }
        }
        if let Some(threshold) = self.min_latency_us {
            if latency < threshold {
                return false;
            }
        }
        true
    }
}

/// Ring-buffer tracer with configurable capacity.
///
/// When the buffer is full, the oldest event is silently dropped to make
/// room for the new one.
#[derive(Clone, Debug)]
pub struct VfsTracer {
    ring: VecDeque<VfsTrace>,
    capacity: usize,
    /// Counts events that were dropped because the ring was full.
    dropped_events: u64,
    /// Total number of events ever pushed.
    ops_traced: u64,
}

impl VfsTracer {
    /// Create a new tracer with the given ring capacity.
    ///
    /// Capacity is clamped to a minimum of 1.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            ring: VecDeque::with_capacity(cap),
            capacity: cap,
            dropped_events: 0,
            ops_traced: 0,
        }
    }

    /// Push a trace event into the ring buffer.
    ///
    /// If the buffer is at capacity, the oldest event is evicted.
    pub fn push(&mut self, event: VfsTrace) {
        self.ops_traced = self.ops_traced.wrapping_add(1);
        if self.ring.len() >= self.capacity {
            self.ring.pop_front();
            self.dropped_events = self.dropped_events.wrapping_add(1);
        }
        self.ring.push_back(event);
    }

    /// Return all buffered events matching `filter`, newest first.
    ///
    /// When `filter` is `None`, all buffered events are returned.
    #[must_use]
    pub fn query(&self, filter: Option<&VfsTraceFilter>) -> Vec<&VfsTrace> {
        let mut out: Vec<&VfsTrace> = self.ring.iter().collect();
        if let Some(f) = filter {
            out.retain(|e| f.matches(e));
        }
        // Reverse so newest (most recently pushed) comes first.
        out.reverse();
        out
    }

    /// Return the current number of buffered events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ring.len()
    }

    /// Return true when the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    /// Return the configured ring capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Return current tracing statistics.
    #[must_use]
    pub fn stats(&self) -> VfsTraceStats {
        VfsTraceStats {
            ops_traced: self.ops_traced,
            trace_buffer_utilization: self.ring.len(),
            dropped_events: self.dropped_events,
        }
    }

    /// Clear the ring buffer and reset stats to zero.
    pub fn reset(&mut self) {
        self.ring.clear();
        self.dropped_events = 0;
        self.ops_traced = 0;
    }
}

/// Aggregate tracer statistics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VfsTraceStats {
    /// Total events pushed since the last reset.
    pub ops_traced: u64,
    /// Current number of events in the ring buffer.
    pub trace_buffer_utilization: usize,
    /// Events dropped because the ring was full (lifetime counter).
    pub dropped_events: u64,
}

// ── VfsTrace helpers ──────────────────────────────────────────────────────

impl VfsTrace {
    /// Extract the common fields from any variant.
    #[must_use]
    pub fn fields(&self) -> (&'static str, u64, u64) {
        match self {
            Self::VfsOpStart {
                op,
                inode,
                commit_group_id,
                ..
            } => (op, *inode, *commit_group_id),
            Self::VfsOpEnd {
                op,
                inode,
                commit_group_id,
                ..
            } => (op, *inode, *commit_group_id),
            Self::VfsOpError {
                op,
                inode,
                commit_group_id,
                ..
            } => (op, *inode, *commit_group_id),
        }
    }

    /// Operation name for this event.
    #[must_use]
    pub fn op(&self) -> &'static str {
        self.fields().0
    }

    /// Dataset identifier.
    #[must_use]
    pub fn dataset_id(&self) -> u64 {
        match self {
            Self::VfsOpStart { dataset_id, .. }
            | Self::VfsOpEnd { dataset_id, .. }
            | Self::VfsOpError { dataset_id, .. } => *dataset_id,
        }
    }

    /// Primary target inode.
    #[must_use]
    pub fn inode(&self) -> u64 {
        self.fields().1
    }

    /// Transaction-group id.
    #[must_use]
    pub fn commit_group_id(&self) -> u64 {
        self.fields().2
    }

    /// Wall-clock latency in microseconds (0 for VfsOpStart).
    #[must_use]
    pub fn latency_us(&self) -> u64 {
        match self {
            Self::VfsOpStart { .. } => 0,
            Self::VfsOpEnd { latency_us, .. } | Self::VfsOpError { latency_us, .. } => *latency_us,
        }
    }

    /// True when the event represents an operation error.
    #[must_use]
    pub fn is_error(&self) -> bool {
        matches!(self, Self::VfsOpError { .. })
    }

    /// Erno value when this is an error event, None otherwise.
    #[must_use]
    pub fn errno(&self) -> Option<Errno> {
        match self {
            Self::VfsOpError { error, .. } => Some(Errno(*error)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::vec;

    // ── VfsTrace construction helpers ─────────────────────────────────

    fn op_start(op: &'static str, inode: u64, args_hash: u64, commit_group_id: u64) -> VfsTrace {
        VfsTrace::VfsOpStart {
            op,
            inode,
            dataset_id: 0,
            args_hash,
            commit_group_id,
        }
    }

    fn op_end(op: &'static str, inode: u64, latency_us: u64, commit_group_id: u64) -> VfsTrace {
        VfsTrace::VfsOpEnd {
            op,
            inode,
            dataset_id: 0,
            latency_us,
            commit_group_id,
        }
    }

    fn op_error(
        op: &'static str,
        inode: u64,
        error: u16,
        latency_us: u64,
        commit_group_id: u64,
    ) -> VfsTrace {
        VfsTrace::VfsOpError {
            op,
            inode,
            dataset_id: 0,
            error,
            latency_us,
            commit_group_id,
        }
    }

    // ── VfsTrace tests ────────────────────────────────────────────────

    #[test]
    fn start_end_error_round_trip() {
        let s = op_start("read", 5, 0xCAFE, 1);
        let e = op_end("read", 5, 150, 1);
        let err = op_error("write", 5, 28u16, 50, 2); // ENOSPC

        assert_eq!(s.op(), "read");
        assert_eq!(s.inode(), 5);
        assert_eq!(s.commit_group_id(), 1);
        assert_eq!(s.latency_us(), 0);
        assert!(!s.is_error());
        assert!(s.errno().is_none());

        assert_eq!(e.op(), "read");
        assert_eq!(e.latency_us(), 150);
        assert!(!e.is_error());

        assert_eq!(err.op(), "write");
        assert_eq!(err.latency_us(), 50);
        assert!(err.is_error());
        assert_eq!(err.errno(), Some(Errno(28)));
    }

    // ── VfsTracer tests ───────────────────────────────────────────────

    #[test]
    fn tracer_pushes_and_queries() {
        let mut t = VfsTracer::new(8);
        t.push(op_start("read", 1, 0, 0));
        t.push(op_end("read", 1, 100, 0));
        t.push(op_start("write", 2, 0, 0));
        t.push(op_end("write", 2, 200, 0));

        assert_eq!(t.len(), 4);
        assert!(!t.is_empty());

        let all = t.query(None);
        assert_eq!(all.len(), 4);
        // newest first: write end, write start, read end, read start
        assert_eq!(all[0].op(), "write");
        assert_eq!(all[1].op(), "write");
        assert_eq!(all[2].op(), "read");
        assert_eq!(all[3].op(), "read");
    }

    #[test]
    fn tracer_ring_wraparound_drops_oldest() {
        let mut t = VfsTracer::new(4);
        for i in 0u64..8 {
            t.push(op_start("read", i, 0, 0));
        }
        assert_eq!(t.len(), 4);
        let all = t.query(None);
        // Should have the last 4: inodes 7,6,5,4
        let inodes: Vec<u64> = all.iter().map(|e| e.inode()).collect();
        assert_eq!(inodes, vec![7, 6, 5, 4]);

        let stats = t.stats();
        assert_eq!(stats.ops_traced, 8);
        assert_eq!(stats.dropped_events, 4);
    }

    #[test]
    fn tracer_ring_exact_capacity_no_drops() {
        let mut t = VfsTracer::new(4);
        for i in 0u64..4 {
            t.push(op_start("read", i, 0, 0));
        }
        assert_eq!(t.len(), 4);
        let stats = t.stats();
        assert_eq!(stats.ops_traced, 4);
        assert_eq!(stats.dropped_events, 0);
    }

    #[test]
    fn tracer_reset_clears_all() {
        let mut t = VfsTracer::new(8);
        t.push(op_start("read", 1, 0, 0));
        t.push(op_end("read", 1, 100, 0));
        assert_eq!(t.len(), 2);

        t.reset();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);

        let stats = t.stats();
        assert_eq!(stats.ops_traced, 0);
        assert_eq!(stats.dropped_events, 0);
    }

    // ── VfsTraceFilter tests ──────────────────────────────────────────

    #[test]
    fn filter_by_op() {
        let filter = VfsTraceFilter::new().with_op("write");
        assert!(filter.matches(&op_start("write", 1, 0, 0)));
        assert!(!filter.matches(&op_start("read", 1, 0, 0)));
    }

    #[test]
    fn filter_by_inode() {
        let filter = VfsTraceFilter::new().with_inode(42);
        assert!(filter.matches(&op_end("read", 42, 100, 0)));
        assert!(!filter.matches(&op_end("read", 7, 100, 0)));
    }

    #[test]
    fn filter_by_min_latency() {
        let filter = VfsTraceFilter::new().with_min_latency(100);
        assert!(filter.matches(&op_end("read", 1, 150, 0)));
        assert!(!filter.matches(&op_end("read", 1, 50, 0)));
        // VfsOpStart has latency 0 — never passes a positive threshold.
        assert!(!filter.matches(&op_start("read", 1, 0, 0)));
    }

    #[test]
    fn filter_by_dataset() {
        // Create events with different dataset IDs
        let ev1 = VfsTrace::VfsOpEnd {
            op: "read",
            inode: 1,
            dataset_id: 42,
            latency_us: 100,
            commit_group_id: 0,
        };
        let ev2 = VfsTrace::VfsOpEnd {
            op: "read",
            inode: 1,
            dataset_id: 99,
            latency_us: 100,
            commit_group_id: 0,
        };
        let filter = VfsTraceFilter::new().with_dataset(42);
        assert!(filter.matches(&ev1));
        assert!(!filter.matches(&ev2));
    }

    #[test]
    fn filter_combined_criteria() {
        let filter = VfsTraceFilter::new()
            .with_op("read")
            .with_inode(5)
            .with_min_latency(50);

        // matches all three
        assert!(filter.matches(&op_end("read", 5, 75, 0)));
        // wrong inode
        assert!(!filter.matches(&op_end("read", 3, 75, 0)));
        // wrong op
        assert!(!filter.matches(&op_end("write", 5, 75, 0)));
        // below latency threshold
        assert!(!filter.matches(&op_end("read", 5, 25, 0)));
    }

    #[test]
    fn tracer_query_with_filter() {
        let mut t = VfsTracer::new(16);
        t.push(op_start("read", 1, 0, 0));
        t.push(op_end("read", 1, 80, 0));
        t.push(op_start("write", 2, 0, 0));
        t.push(op_end("write", 2, 200, 0));
        t.push(op_error("read", 1, 2u16, 50, 1)); // ENOENT

        // Filter: read ops on inode 1 with latency >= 50
        let filter = VfsTraceFilter::new()
            .with_op("read")
            .with_inode(1)
            .with_min_latency(50);

        let results = t.query(Some(&filter));
        assert_eq!(results.len(), 2);
        // newest first: error, then end
        assert!(results[0].is_error());
        assert!(!results[1].is_error());
    }

    #[test]
    fn tracer_query_empty_filter_returns_all() {
        let mut t = VfsTracer::new(8);
        t.push(op_start("lookup", 1, 0, 0));
        t.push(op_end("lookup", 1, 50, 0));
        assert_eq!(t.query(Some(&VfsTraceFilter::new())).len(), 2);
        assert_eq!(t.query(None).len(), 2);
    }

    // ── Concurrent-style test (single-threaded but simulates interleaving)

    #[test]
    fn tracer_interleaved_ops_from_different_inodes() {
        let mut t = VfsTracer::new(32);
        // Simulate reads on inode 1 and writes on inode 2 interleaved.
        for i in 0u64..10 {
            t.push(op_start("read", 1, i, i));
            t.push(op_end("read", 1, 100, i));
            t.push(op_start("write", 2, i, i));
            t.push(op_end("write", 2, 200, i));
        }

        // Filter for reads on inode 1
        let read_filter = VfsTraceFilter::new().with_op("read").with_inode(1);
        let reads = t.query(Some(&read_filter));
        assert_eq!(reads.len(), 16); // 10 starts + 10 ends, but buffer drops the oldest 2 iterations (4 read events)

        // All read events should be for inode 1
        assert!(reads.iter().all(|e| e.inode() == 1));

        // Filter for writes on inode 2
        let write_filter = VfsTraceFilter::new().with_op("write").with_inode(2);
        let writes = t.query(Some(&write_filter));
        assert_eq!(writes.len(), 16); // 10 starts + 10 ends, but buffer also drops the oldest 2 write iterations (4 write events)
        assert!(writes.iter().all(|e| e.inode() == 2));
    }

    #[test]
    fn stats_accumulate_correctly() {
        let mut t = VfsTracer::new(4);

        // Fill without overflow
        for i in 0u64..4 {
            t.push(op_start("op", i, 0, 0));
        }
        let s = t.stats();
        assert_eq!(s.ops_traced, 4);
        assert_eq!(s.trace_buffer_utilization, 4);
        assert_eq!(s.dropped_events, 0);

        // Push 4 more — all should drop
        for i in 4u64..8 {
            t.push(op_start("op", i, 0, 0));
        }
        let s = t.stats();
        assert_eq!(s.ops_traced, 8);
        assert_eq!(s.trace_buffer_utilization, 4);
        assert_eq!(s.dropped_events, 4);
    }
}

// ── Page cache statistics for kernel/userspace parity ──────────────────────
//
// These types track page-cache hit/miss/populate/prefetch/evict counters
// so that userspace and kernel implementations can compare caching behaviour
// on the same workload (K7-06).

/// Per-workload page-cache statistics for cross-implementation comparison.
///
/// All counters are saturating; they will not wrap on overflow.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VfsPageCacheStats {
    /// Page cache hits (read satisfied from cache).
    pub hit: u64,
    /// Page cache misses (read required backing-store I/O).
    pub miss: u64,
    /// Pages populated into the cache (miss → fill).
    pub populate: u64,
    /// Pages prefetched by readahead.
    pub prefetch: u64,
    /// Pages evicted from the cache.
    pub evict: u64,
}

impl VfsPageCacheStats {
    /// Snapshot the current counters.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            hit: 0,
            miss: 0,
            populate: 0,
            prefetch: 0,
            evict: 0,
        }
    }

    /// Record a cache hit.
    pub fn record_hit(&mut self, count: u64) {
        self.hit = self.hit.saturating_add(count);
    }

    /// Record a cache miss.
    pub fn record_miss(&mut self, count: u64) {
        self.miss = self.miss.saturating_add(count);
    }

    /// Record page population (miss → fill).
    pub fn record_populate(&mut self, count: u64) {
        self.populate = self.populate.saturating_add(count);
    }

    /// Record readahead prefetch pages.
    pub fn record_prefetch(&mut self, count: u64) {
        self.prefetch = self.prefetch.saturating_add(count);
    }

    /// Record page evictions.
    pub fn record_evict(&mut self, count: u64) {
        self.evict = self.evict.saturating_add(count);
    }

    /// Compute the hit ratio as a fraction in parts-per-million.
    ///
    /// Returns 0 when there are no accesses.
    #[must_use]
    pub fn hit_ratio_ppm(&self) -> u64 {
        let total = self.hit.saturating_add(self.miss);
        if total == 0 {
            return 0;
        }
        // hit / total * 1_000_000
        (self.hit as u128)
            .saturating_mul(1_000_000)
            .checked_div(total as u128)
            .map_or(0, |v| v as u64)
    }

    /// Total accesses (hits + misses).
    #[must_use]
    pub fn total_accesses(&self) -> u64 {
        self.hit.saturating_add(self.miss)
    }

    /// Reset all counters to zero.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

/// A mutable page-cache statistics tracker.
///
/// Wraps [`VfsPageCacheStats`] with convenience record methods.
#[derive(Clone, Debug, Default)]
pub struct VfsPageCacheTracker {
    pub stats: VfsPageCacheStats,
}

impl VfsPageCacheTracker {
    /// Create a new tracker with zeroed stats.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stats: VfsPageCacheStats::new(),
        }
    }

    /// Snapshot current stats without resetting.
    #[must_use]
    pub fn snapshot(&self) -> VfsPageCacheStats {
        self.stats
    }

    /// Snapshot and reset.
    pub fn take(&mut self) -> VfsPageCacheStats {
        let s = self.stats;
        self.stats.reset();
        s
    }

    /// Record a cache hit for `count` pages.
    pub fn hit(&mut self, count: u64) {
        self.stats.record_hit(count);
    }

    /// Record a cache miss for `count` pages.
    pub fn miss(&mut self, count: u64) {
        self.stats.record_miss(count);
    }

    /// Record page population for `count` pages.
    pub fn populate(&mut self, count: u64) {
        self.stats.record_populate(count);
    }

    /// Record readahead prefetch for `count` pages.
    pub fn prefetch(&mut self, count: u64) {
        self.stats.record_prefetch(count);
    }

    /// Record page eviction for `count` pages.
    pub fn evict(&mut self, count: u64) {
        self.stats.record_evict(count);
    }
}

#[cfg(test)]
mod page_cache_tests {
    extern crate std;
    use super::*;

    #[test]
    fn stats_initial_zero() {
        let s = VfsPageCacheStats::new();
        assert_eq!(s.hit, 0);
        assert_eq!(s.miss, 0);
        assert_eq!(s.populate, 0);
        assert_eq!(s.prefetch, 0);
        assert_eq!(s.evict, 0);
        assert_eq!(s.total_accesses(), 0);
        assert_eq!(s.hit_ratio_ppm(), 0);
    }

    #[test]
    fn stats_record_and_accumulate() {
        let mut s = VfsPageCacheStats::new();
        s.record_hit(10);
        s.record_miss(2);
        s.record_populate(2);
        s.record_prefetch(8);
        s.record_evict(1);

        assert_eq!(s.hit, 10);
        assert_eq!(s.miss, 2);
        assert_eq!(s.populate, 2);
        assert_eq!(s.prefetch, 8);
        assert_eq!(s.evict, 1);
        assert_eq!(s.total_accesses(), 12);
    }

    #[test]
    fn hit_ratio_all_hits() {
        let mut s = VfsPageCacheStats::new();
        s.record_hit(100);
        assert_eq!(s.hit_ratio_ppm(), 1_000_000);
    }

    #[test]
    fn hit_ratio_all_misses() {
        let mut s = VfsPageCacheStats::new();
        s.record_miss(100);
        assert_eq!(s.hit_ratio_ppm(), 0);
    }

    #[test]
    fn hit_ratio_mixed() {
        let mut s = VfsPageCacheStats::new();
        s.record_hit(75);
        s.record_miss(25);
        // 75/100 = 750,000 ppm
        assert_eq!(s.hit_ratio_ppm(), 750_000);
    }

    #[test]
    fn hit_ratio_ppm_exact() {
        let mut s = VfsPageCacheStats::new();
        s.record_hit(1);
        s.record_miss(3);
        // 1/4 = 250,000 ppm
        assert_eq!(s.hit_ratio_ppm(), 250_000);
    }

    #[test]
    fn stats_reset_clears_all() {
        let mut s = VfsPageCacheStats::new();
        s.record_hit(5);
        s.record_miss(3);
        s.reset();
        assert_eq!(s.total_accesses(), 0);
        assert_eq!(s.hit, 0);
        assert_eq!(s.miss, 0);
    }

    #[test]
    fn stats_clone_is_independent() {
        let mut s = VfsPageCacheStats::new();
        s.record_hit(42);
        let copy = s;
        assert_eq!(copy.hit, 42);
        // Copy semantics — original unchanged after copy.
        assert_eq!(s.hit, 42);
    }

    #[test]
    fn tracker_hit_and_miss() {
        let mut t = VfsPageCacheTracker::new();
        t.hit(10);
        t.miss(5);
        let snap = t.snapshot();
        assert_eq!(snap.hit, 10);
        assert_eq!(snap.miss, 5);
    }

    #[test]
    fn tracker_take_resets() {
        let mut t = VfsPageCacheTracker::new();
        t.hit(10);
        let taken = t.take();
        assert_eq!(taken.hit, 10);
        assert_eq!(t.snapshot().hit, 0);
    }

    #[test]
    fn tracker_prefetch_and_evict() {
        let mut t = VfsPageCacheTracker::new();
        t.prefetch(32);
        t.evict(8);
        let snap = t.snapshot();
        assert_eq!(snap.prefetch, 32);
        assert_eq!(snap.evict, 8);
    }

    #[test]
    fn saturation_does_not_wrap() {
        let mut s = VfsPageCacheStats::new();
        s.record_hit(u64::MAX);
        s.record_hit(1);
        assert_eq!(s.hit, u64::MAX);
    }
}
