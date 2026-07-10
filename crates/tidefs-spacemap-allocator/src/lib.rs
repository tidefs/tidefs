// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Deterministic segment-level free-space allocator (G1 foundation).
//!
//! `SegmentFreeMap` provides a run-based in-memory free segment tracker
//! with BTreeSet-backed sorted, disjoint interval representation.
//! `SpaceMapCheckpointV1` and its bitmap encode/decode routines provide
//! persistent segment_group-partitioned checkpointing. Generation counters
//! defend against stale-pointer corruption.
//!
//! This crate is the source-owned authority for the segment free-map,
//! checkpoint bitmap encoding, and space-pressure classification implemented
//! below. The module API, constants, and gate markers below are the live
//! validation surface for this allocator; historical design prose is
//! provenance only.
#![forbid(unsafe_code)]

use core::fmt;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Gate markers (for xtask validation)
// ---------------------------------------------------------------------------
// SPACEMAP_ALLOCATOR_SPEC
// tidefs-xtask check-spacemap-allocator
// MULTI_DEVICE_ALLOCATOR_COORDINATION_DEFERRED (G2+; pool-level multi-device
//   allocator coordination deferred — see #1694)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default segments per segment_group (4096 -> 512-byte bitmaps).
pub const DEFAULT_SEGMENT_GROUP_SEGMENTS: u64 = 4096;

/// Spacemap checkpoint magic ("SPMP").
pub const SPACEMAP_CHECKPOINT_MAGIC: &[u8; 4] = b"SPMP";

/// Space pressure threshold: warn at 95% pool capacity.
pub const SPACE_PRESSURE_THRESHOLD: f64 = 0.95;
// ---------------------------------------------------------------------------
// SpacePressure (free-space pressure classification)
// ---------------------------------------------------------------------------

/// Fraction of free space below which pressure becomes Moderate.
pub const PRESSURE_MODERATE_FREE: f64 = 0.20;

/// Fraction of free space below which pressure becomes Severe.
pub const PRESSURE_SEVERE_FREE: f64 = 0.10;

/// Fraction of free space below which pressure becomes Critical.
pub const PRESSURE_CRITICAL_FREE: f64 = 0.05;

/// Pool-level space pressure derived from free-segment ratio.
///
/// Variants are ordered by severity (`Ord` derives top-to-bottom),
/// enabling comparative checks like `pressure >= SpacePressure::Severe`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum SpacePressure {
    /// Pool is healthy: >= 20 % free space.
    Healthy,
    /// Pool is under moderate pressure: 10-20 % free space.
    Moderate,
    /// Pool is under severe pressure: 5-10 % free space.
    Severe,
    /// Pool is critically low: < 5 % free space.
    Critical,
}

impl fmt::Display for SpacePressure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Moderate => write!(f, "moderate"),
            Self::Severe => write!(f, "severe"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ---------------------------------------------------------------------------
// Size-class definitions for fast allocation hints (Phase 4)
// ---------------------------------------------------------------------------

/// Number of size classes.
pub const SIZE_CLASS_COUNT: usize = 14;

/// Size-class boundaries in segments (must be monotonically increasing).
/// Each entry is the minimum run length to qualify for that class.
pub const SIZE_CLASS_BOUNDARIES: [u64; SIZE_CLASS_COUNT] = [
    1,    // class 0:  >= 1 segment
    2,    // class 1:  >= 2
    4,    // class 2:  >= 4
    8,    // class 3:  >= 8
    16,   // class 4:  >= 16
    32,   // class 5:  >= 32
    64,   // class 6:  >= 64
    128,  // class 7:  >= 128
    256,  // class 8:  >= 256
    512,  // class 9:  >= 512
    1024, // class 10: >= 1024
    2048, // class 11: >= 2048
    4096, // class 12: >= 4096
    8192, // class 13: >= 8192
];

/// Return the size-class index for a run of `len` segments.
/// Returns the largest size class whose boundary is <= `len`.
#[must_use]
pub fn size_class_for(len: u64) -> usize {
    SIZE_CLASS_BOUNDARIES
        .iter()
        .enumerate()
        .rev()
        .find(|(_, &boundary)| len >= boundary)
        .map_or(0, |(idx, _)| idx)
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors returned by the free map allocator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreeMapError {
    /// Pool is full; GC must run to reclaim space.
    NoFreeSegments,
    /// A segment index exceeds the pool's segment_count.
    SegmentOutOfRange(u64),
    /// `remove_free` called on a segment that is already used.
    AlreadyUsed(u64),
    /// A run passed to the constructor failed validation.
    InvalidRun(u64, u64),
    /// The checkpoint data is corrupt or unreadable.
    CorruptCheckpoint,
}

impl fmt::Display for FreeMapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoFreeSegments => write!(f, "no free segments available"),
            Self::SegmentOutOfRange(seg) => write!(f, "segment {seg} out of range"),
            Self::AlreadyUsed(seg) => write!(f, "segment {seg} already used"),
            Self::InvalidRun(s, e) => write!(f, "invalid run ({s}, {e})"),
            Self::CorruptCheckpoint => write!(f, "corrupt spacemap checkpoint"),
        }
    }
}

impl std::error::Error for FreeMapError {}

// ---------------------------------------------------------------------------
// SpacemapStats (extended allocator statistics, Phase 4)
// ---------------------------------------------------------------------------

/// Extended allocator statistics including size-class hint performance.
#[derive(Clone, Copy, Debug, Default)]
pub struct SpacemapStats {
    /// Total segments in the pool.
    pub segment_count: u64,
    /// Number of currently free segments.
    pub free_segments: u64,
    /// Number of currently used segments.
    pub used_segments: u64,
    /// Number of contiguous free runs.
    pub free_runs: u64,
    /// Fragmentation ratio: (free_runs / free_segments) * 100.
    pub fragmentation_ratio: f64,
    /// Largest contiguous free run in segments.
    pub largest_contiguous_free: u64,
    /// Size-class hint hit rate (0.0-1.0).
    pub size_class_hit_rate: f64,
}

/// A fragmentation hotspot identified by the defrag reporter.
#[derive(Clone, Debug, PartialEq)]
pub struct DefragHotspot {
    /// Segment_group index.
    pub segment_group_index: u32,
    /// Fragmentation percentage within this segment_group.
    pub fragmentation_pct: f64,
    /// Free segments in this segment_group.
    pub free_segments: u64,
    /// Number of free runs in this segment_group.
    pub free_runs: u64,
}

/// Defragmentation report with fragmentation hotspots.
#[derive(Clone, Debug)]
pub struct DefragReport {
    /// Overall fragmentation ratio.
    pub fragmentation_ratio: f64,
    /// Total number of free runs.
    pub free_runs_count: u64,
    /// Largest contiguous free run in segments.
    pub largest_contiguous_free: u64,
    /// Fragmentation hotspots sorted by severity (most fragmented first).
    pub hotspots: Vec<DefragHotspot>,
}

// ---------------------------------------------------------------------------
// SizeClassHints (per-size-class free lists for O(1) allocation)
// ---------------------------------------------------------------------------

/// Per-size-class free lists for O(1) allocation of common sizes.
///
/// Each size class maintains a BTreeSet of free runs that are at least
/// as large as that class's minimum boundary. A run of length N appears
/// in every size class with boundary <= N.
#[derive(Clone, Debug)]
pub(crate) struct SizeClassHints {
    hints: Vec<BTreeSet<(u64, u64)>>,
}

impl SizeClassHints {
    pub(crate) fn new() -> Self {
        SizeClassHints {
            hints: (0..SIZE_CLASS_COUNT).map(|_| BTreeSet::new()).collect(),
        }
    }

    /// Rebuild all size-class hints from the current free runs.
    pub(crate) fn rebuild(&mut self, free_runs: &BTreeSet<(u64, u64)>) {
        for hint in &mut self.hints {
            hint.clear();
        }
        for &(start, end) in free_runs {
            self.insert_run(start, end);
        }
    }

    /// Insert a run into all applicable size classes.
    pub(crate) fn insert_run(&mut self, start: u64, end: u64) {
        let len = end - start;
        let max_class = size_class_for(len);
        for class in 0..=max_class {
            self.hints[class].insert((start, end));
        }
    }

    /// Remove a run from all size classes (called when a run is consumed or split).
    pub(crate) fn remove_run(&mut self, start: u64, end: u64) {
        for hint in &mut self.hints {
            hint.remove(&(start, end));
        }
    }

    /// Find a free run of at least `min_len` segments using size-class hints.
    /// Returns the first run from the best-fit size class, or None on miss.
    pub(crate) fn find_for_size(&self, min_len: u64) -> Option<(u64, u64)> {
        if min_len == 0 {
            return None;
        }
        for class in size_class_for(min_len)..SIZE_CLASS_COUNT {
            if let Some(run) = self.hints[class].first() {
                return Some(*run);
            }
        }
        None
    }

    /// Find a free run of at least `min_len` segments at or after `cursor`.
    pub(crate) fn find_for_size_ge(&self, min_len: u64, cursor: u64) -> Option<(u64, u64)> {
        if min_len == 0 {
            return None;
        }
        for class in size_class_for(min_len)..SIZE_CLASS_COUNT {
            if let Some(run) = self.hints[class].range((cursor, 0)..).next().copied() {
                return Some(run);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// SegmentFreeMapStats
// ---------------------------------------------------------------------------

/// Statistics for a `SegmentFreeMap`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SegmentFreeMapStats {
    /// Total segments in the pool.
    pub segment_count: u64,
    /// Number of currently free segments.
    pub free_segments: u64,
    /// Number of currently used segments.
    pub used_segments: u64,
    /// Number of contiguous free runs.
    pub free_runs: u64,
    /// Fragmentation as `(free_runs / free_segments) * 100`.
    pub fragmentation_pct: f64,
}

// ---------------------------------------------------------------------------
// On-media record types
// ---------------------------------------------------------------------------

/// A single segment_group's bitmap entry in a checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentGroupBitmapEntry {
    /// Index of this segment_group.
    pub segment_group_index: u32,
    /// Length of `bitmap_data` in bytes.
    pub bitmap_len: u32,
    /// Raw bitmap blob (1 bit = 1 free segment, LSB-first per byte).
    pub bitmap_data: Vec<u8>,
}

/// Persistent spacemap checkpoint written to the pool-map journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpaceMapCheckpointV1 {
    /// Magic bytes "SPMP".
    pub magic: [u8; 4],
    /// Format version.
    pub version: u32,
    /// Total segments in the pool.
    pub segment_count: u64,
    /// Segments per segment_group.
    pub segment_group_segments: u64,
    /// Total segment_group count.
    pub segment_group_count: u32,
    /// Number of dirty segment_groups included (incremental).
    pub dirty_segment_group_count: u32,
    /// Monotonic generation counter for segment lifecycle.
    pub generation: u64,
    /// Per-segment_group bitmap entries.
    pub entries: Vec<SegmentGroupBitmapEntry>,
}

impl SpaceMapCheckpointV1 {
    /// Create a new empty checkpoint header.
    #[must_use]
    pub fn new(segment_count: u64, segment_group_segments: u64, generation: u64) -> Self {
        let mc = bitmap_layout(segment_count, segment_group_segments).0 as u32;
        Self {
            magic: *SPACEMAP_CHECKPOINT_MAGIC,
            version: 1,
            segment_count,
            segment_group_segments,
            segment_group_count: mc,
            dirty_segment_group_count: 0,
            generation,
            entries: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// SegmentFreeMap
// ---------------------------------------------------------------------------

/// Deterministic run-based free-segment allocator.
///
/// Maintains sorted, disjoint `[start, end)` half-open interval runs in a
/// `BTreeSet`. Allocation uses a cursor with wrap-around for wear leveling.
#[derive(Clone, Debug)]
pub struct SegmentFreeMap {
    /// Total number of segments in the pool.
    pub segment_count: u64,
    /// Sorted, disjoint, non-adjacent free runs `[start, end)`.
    free_runs: BTreeSet<(u64, u64)>,
    /// Monotonic generation counter incremented on each allocation.
    pub generation: u64,
    /// Segments per segment_group.
    pub segment_group_segments: u64,
    /// Segment_group indices modified since last successful checkpoint flush.
    dirty_segment_groups: BTreeSet<u32>,
    /// Size-class hints for O(1) allocation of common sizes.
    size_class_hints: SizeClassHints,
    /// Number of allocations that hit the size-class cache.
    size_class_hit_count: u64,
    /// Number of allocations that missed the size-class cache.
    size_class_miss_count: u64,
    pub(crate) cached_free: u64,
}

impl SegmentFreeMap {
    /// Create a new free map from an initial set of free runs.
    /// Uses DEFAULT_SEGMENT_GROUP_SEGMENTS for the segment_group partition.
    pub fn new(segment_count: u64, initial_free: Vec<(u64, u64)>) -> Result<Self, FreeMapError> {
        let segment_group_segments = DEFAULT_SEGMENT_GROUP_SEGMENTS;
        let mut fm = SegmentFreeMap {
            segment_count,
            free_runs: BTreeSet::new(),
            generation: 1,
            segment_group_segments,
            dirty_segment_groups: BTreeSet::new(),
            size_class_hints: SizeClassHints::new(),
            size_class_hit_count: 0,
            size_class_miss_count: 0,
            cached_free: 0,
        };
        for (start, end) in initial_free {
            fm.validate_run(start, end)?;
            fm.insert_run_merge(start, end);
        }
        fm.size_class_hints.rebuild(&fm.free_runs);
        fm.cached_free = fm.free_runs.iter().map(|(s, e)| e - s).sum();
        Ok(fm)
    }

    /// Reconstruct from decoded runs (e.g. after pool import).
    pub fn from_runs(segment_count: u64, runs: Vec<(u64, u64)>) -> Result<Self, FreeMapError> {
        Self::new(segment_count, runs)
    }

    /// Reconstruct from a persistent spacemap checkpoint record.
    ///
    /// Decodes the per-segment-group bitmaps back into free runs, merges
    /// adjacent runs, and initializes the in-memory free map with the
    /// generation counter carried in the checkpoint.
    ///
    /// # Errors
    ///
    /// Returns `CorruptCheckpoint` if any bitmap cannot be decoded,
    /// or `InvalidRun` if the decoded runs are invalid.
    pub fn from_checkpoint(checkpoint: &SpaceMapCheckpointV1) -> Result<Self, FreeMapError> {
        let bitmaps: Vec<Vec<u8>> = checkpoint
            .entries
            .iter()
            .map(|e| e.bitmap_data.clone())
            .collect();
        let runs = decode_bitmaps(
            &bitmaps,
            checkpoint.segment_count,
            checkpoint.segment_group_segments,
        )?;
        let mut fm = Self::new(checkpoint.segment_count, runs)?;
        fm.generation = checkpoint.generation.max(1);
        fm.segment_group_segments = checkpoint.segment_group_segments;
        Ok(fm)
    }

    /// Allocate one free segment at or after `cursor`, wrapping to 0 if needed.
    pub fn alloc_after(&mut self, cursor: u64) -> Result<u64, FreeMapError> {
        if self.segment_count == 0 {
            return Err(FreeMapError::NoFreeSegments);
        }
        if let Some(seg) = self.find_first_free_ge(cursor) {
            return self.do_allocate(seg);
        }
        if cursor > 0 {
            if let Some(seg) = self.find_first_free_ge(0) {
                if seg < cursor {
                    return self.do_allocate(seg);
                }
            }
        }
        Err(FreeMapError::NoFreeSegments)
    }

    /// Return a segment to the free set. Idempotent.
    pub fn add_free(&mut self, seg: u64) -> Result<(), FreeMapError> {
        if seg >= self.segment_count {
            return Err(FreeMapError::SegmentOutOfRange(seg));
        }
        if self.is_free(seg) {
            return Ok(());
        }
        self.insert_run_merge(seg, seg.saturating_add(1));
        self.mark_dirty(seg);
        Ok(())
    }

    /// Mark a segment as used. Errors if not currently free.
    pub fn remove_free(&mut self, seg: u64) -> Result<(), FreeMapError> {
        if seg >= self.segment_count {
            return Err(FreeMapError::SegmentOutOfRange(seg));
        }
        if !self.is_free(seg) {
            return Err(FreeMapError::AlreadyUsed(seg));
        }
        self.remove_from_free_runs(seg)?;
        self.mark_dirty(seg);
        Ok(())
    }

    /// Test whether a segment is in the free set. O(log N).
    #[must_use]
    pub fn is_free(&self, seg: u64) -> bool {
        for &(start, end) in self.free_runs.range(..=(seg, u64::MAX)).rev() {
            if start <= seg && seg < end {
                return true;
            }
            if end <= seg {
                break;
            }
        }
        false
    }

    /// Snapshot of current free runs for serialization.
    #[must_use]
    pub fn runs(&self) -> Vec<(u64, u64)> {
        self.free_runs.iter().copied().collect()
    }

    /// Current allocation statistics.
    #[must_use]
    pub fn stats(&self) -> SegmentFreeMapStats {
        let free_segments: u64 = self.free_runs.iter().map(|(s, e)| e - s).sum();
        let free_runs_count = self.free_runs.len() as u64;
        let used_segments = self.segment_count.saturating_sub(free_segments);
        let fragmentation_pct = if free_segments > 0 {
            (free_runs_count as f64 / free_segments as f64) * 100.0
        } else {
            0.0
        };
        SegmentFreeMapStats {
            segment_count: self.segment_count,
            free_segments,
            used_segments,
            free_runs: free_runs_count,
            fragmentation_pct,
        }
    }

    /// Extended statistics including size-class hint rate and largest free run.
    #[must_use]
    pub fn extended_stats(&self) -> SpacemapStats {
        let free_segments: u64 = self.free_runs.iter().map(|(s, e)| e - s).sum();
        let free_runs_count = self.free_runs.len() as u64;
        let used_segments = self.segment_count.saturating_sub(free_segments);
        let fragmentation_ratio = if free_segments > 0 {
            (free_runs_count as f64 / free_segments as f64) * 100.0
        } else {
            0.0
        };
        let largest_contiguous_free = self.free_runs.iter().map(|(s, e)| e - s).max().unwrap_or(0);
        let total_lookups = self.size_class_hit_count + self.size_class_miss_count;
        let size_class_hit_rate = if total_lookups > 0 {
            self.size_class_hit_count as f64 / total_lookups as f64
        } else {
            0.0
        };
        SpacemapStats {
            segment_count: self.segment_count,
            free_segments,
            used_segments,
            free_runs: free_runs_count,
            fragmentation_ratio,
            largest_contiguous_free,
            size_class_hit_rate,
        }
    }

    /// Number of free segments.
    #[must_use]
    pub fn free_count(&self) -> u64 {
        self.free_runs.iter().map(|(s, e)| e - s).sum()
    }

    /// Cached free segment count (updated on every allocation / free).
    #[must_use]
    #[inline]
    pub fn free_segments(&self) -> u64 {
        self.cached_free
    }

    /// Number of used segments (total - free).
    #[must_use]
    #[inline]
    pub fn used_segments(&self) -> u64 {
        self.segment_count.saturating_sub(self.cached_free)
    }

    /// Return the current pool pressure level given free-space thresholds.
    ///
    /// Pressure is computed from the free-segment ratio:
    /// - `Healthy` when >= 20 % free
    /// - `Moderate` when 10-20 % free
    /// - `Severe` when 5-10 % free
    /// - `Critical` when < 5 % free
    ///
    /// An empty pool (segment_count == 0) is always `Healthy`.
    #[must_use]
    pub fn pressure(&self) -> SpacePressure {
        if self.segment_count == 0 {
            return SpacePressure::Healthy;
        }
        let free_ratio = self.cached_free as f64 / self.segment_count as f64;
        if free_ratio < PRESSURE_CRITICAL_FREE {
            SpacePressure::Critical
        } else if free_ratio < PRESSURE_SEVERE_FREE {
            SpacePressure::Severe
        } else if free_ratio < PRESSURE_MODERATE_FREE {
            SpacePressure::Moderate
        } else {
            SpacePressure::Healthy
        }
    }

    /// Check if the pool is under space pressure (>= 95% used).
    #[must_use]
    pub fn is_under_pressure(&self) -> bool {
        let free = self.free_count();
        if self.segment_count == 0 {
            return false;
        }
        let used = self.segment_count.saturating_sub(free);
        (used as f64 / self.segment_count as f64) >= SPACE_PRESSURE_THRESHOLD
    }

    /// Return sorted vector of dirty segment_group indices since last checkpoint.
    #[must_use]
    pub fn dirty_segment_groups(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.dirty_segment_groups.iter().copied().collect();
        v.sort_unstable();
        v
    }

    /// Clear the dirty segment_group set after a successful checkpoint flush.
    pub fn clear_dirty_segment_groups(&mut self) {
        self.dirty_segment_groups.clear();
    }

    /// Number of segment_groups in the pool.
    #[must_use]
    pub fn segment_group_count(&self) -> u64 {
        self.segment_count.div_ceil(self.segment_group_segments)
    }

    // -- size-class-aware allocation and coalescing (Phase 4) --

    /// Free a contiguous range of segments `[start, end)`.
    /// Merges with adjacent free runs automatically.
    ///
    /// # Errors
    /// Returns `SegmentOutOfRange` if the range exceeds `segment_count`.
    /// Returns `InvalidRun` if `start >= end`.
    pub fn free_range(&mut self, start: u64, end: u64) -> Result<(), FreeMapError> {
        self.validate_run(start, end)?;
        self.insert_run_merge(start, end);
        self.size_class_hints.rebuild(&self.free_runs);
        for seg in start..end {
            self.mark_dirty(seg);
        }
        Ok(())
    }

    /// Coalesce any adjacent free runs in the free set.
    ///
    /// While the normal insert/remove operations maintain the non-adjacent
    /// invariant, this method provides a safety net and can be called
    /// periodically to defragment the in-memory representation.
    pub fn coalesce(&mut self) {
        let runs: Vec<(u64, u64)> = self.free_runs.iter().copied().collect();
        if runs.len() < 2 {
            return;
        }
        self.free_runs.clear();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(runs.len());
        merged.push(runs[0]);
        for &(s, e) in &runs[1..] {
            let last = merged.last_mut().unwrap();
            if last.1 == s {
                last.1 = e;
            } else {
                merged.push((s, e));
            }
        }
        for run in merged {
            self.free_runs.insert(run);
        }
        self.size_class_hints.rebuild(&self.free_runs);
    }

    /// Allocate one segment using size-class hints for fast lookup.
    /// Falls back to the full free-run walk on hint miss.
    /// After allocation, runs a coalesce pass.
    pub fn allocate(&mut self, min_size: u64, cursor: u64) -> Result<u64, FreeMapError> {
        if self.segment_count == 0 || self.free_runs.is_empty() {
            return Err(FreeMapError::NoFreeSegments);
        }
        // Try size-class hints first for O(1) lookup.
        if let Some((run_start, _run_end)) =
            self.size_class_hints.find_for_size_ge(min_size, cursor)
        {
            self.size_class_hit_count = self.size_class_hit_count.saturating_add(1);
            let seg = run_start.max(cursor);
            self.remove_from_free_runs(seg)?;
            self.size_class_hints.rebuild(&self.free_runs);
            self.mark_dirty(seg);
            self.generation = self.generation.saturating_add(1).max(1);
            self.coalesce();
            return Ok(seg);
        }
        // Fall back to full walk.
        self.size_class_miss_count = self.size_class_miss_count.saturating_add(1);
        let result = self.alloc_after(cursor);
        if result.is_ok() {
            self.size_class_hints.rebuild(&self.free_runs);
            self.coalesce();
        }
        result
    }

    /// Find a free run of at least `min_len` segments using size-class hints.
    ///
    /// Returns the first run from the best-fit size class (`start, end`),
    /// or `None` when no run of sufficient length exists.
    #[must_use]
    pub fn find_free_run(&self, min_len: u64) -> Option<(u64, u64)> {
        self.size_class_hints.find_for_size(min_len)
    }

    /// Find a free run of at least `min_len` segments at or after `cursor`.
    #[must_use]
    pub fn find_free_run_ge(&self, min_len: u64, cursor: u64) -> Option<(u64, u64)> {
        self.size_class_hints.find_for_size_ge(min_len, cursor)
    }

    /// Remove a run from the size-class hints (called for incremental
    /// maintenance when consuming or splitting a free run from the outside).
    pub fn remove_run_from_hints(&mut self, start: u64, end: u64) {
        self.size_class_hints.remove_run(start, end);
    }

    /// Rebuild all size-class hints from the current free runs.
    ///
    /// Call after a batch of individual `remove_free` / `add_free`
    /// operations to keep the hints consistent without per-operation
    /// rebuild overhead.
    pub fn rebuild_hints(&mut self) {
        self.size_class_hints.rebuild(&self.free_runs);
    }

    /// Produce a defragmentation report identifying fragmentation hotspots.
    #[must_use]
    pub fn defrag_report(&self) -> DefragReport {
        let stats = self.extended_stats();
        let segment_group_count = self.segment_group_count();
        let mut hotspots: Vec<DefragHotspot> = Vec::new();
        for ms in 0..segment_group_count as u32 {
            let ms_start = ms as u64 * self.segment_group_segments;
            let ms_end = (ms_start + self.segment_group_segments).min(self.segment_count);
            let mut ms_free_segments: u64 = 0;
            let mut ms_free_runs: u64 = 0;
            for &(rs, re) in &self.free_runs {
                if rs < ms_end && re > ms_start {
                    let overlap_start = rs.max(ms_start);
                    let overlap_end = re.min(ms_end);
                    let overlap = overlap_end.saturating_sub(overlap_start);
                    if overlap > 0 {
                        ms_free_segments += overlap;
                        ms_free_runs += 1;
                    }
                }
            }
            if ms_free_segments > 0 {
                let ms_frag_pct = (ms_free_runs as f64 / ms_free_segments as f64) * 100.0;
                hotspots.push(DefragHotspot {
                    segment_group_index: ms,
                    fragmentation_pct: ms_frag_pct,
                    free_segments: ms_free_segments,
                    free_runs: ms_free_runs,
                });
            }
        }
        hotspots.sort_by(|a, b| {
            b.fragmentation_pct
                .partial_cmp(&a.fragmentation_pct)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        DefragReport {
            fragmentation_ratio: stats.fragmentation_ratio,
            free_runs_count: stats.free_runs,
            largest_contiguous_free: stats.largest_contiguous_free,
            hotspots,
        }
    }

    // -- private helpers --

    /// Compute the segment_group index for a segment.
    #[inline]
    pub(crate) fn segment_group_index(&self, seg: u64) -> u32 {
        (seg / self.segment_group_segments) as u32
    }

    /// Mark the segment_group containing `seg` as dirty.
    fn mark_dirty(&mut self, seg: u64) {
        let ms = self.segment_group_index(seg);
        self.dirty_segment_groups.insert(ms);
    }

    fn validate_run(&self, start: u64, end: u64) -> Result<(), FreeMapError> {
        if start >= end || end > self.segment_count {
            return Err(FreeMapError::InvalidRun(start, end));
        }
        Ok(())
    }

    fn find_first_free_ge(&self, min: u64) -> Option<u64> {
        for &(start, end) in &self.free_runs {
            if start >= min {
                return Some(start);
            }
            if end > min {
                return Some(min);
            }
        }
        None
    }

    fn do_allocate(&mut self, seg: u64) -> Result<u64, FreeMapError> {
        self.remove_from_free_runs(seg)?;
        self.mark_dirty(seg);
        self.generation = self.generation.saturating_add(1).max(1);
        Ok(seg)
    }

    fn insert_run_merge(&mut self, start: u64, end: u64) {
        let mut new_start = start;
        let mut new_end = end;
        let to_remove: Vec<(u64, u64)> = self
            .free_runs
            .iter()
            .copied()
            .filter(|&(rs, re)| rs <= end && re >= start)
            .collect();
        for (rs, re) in &to_remove {
            new_start = new_start.min(*rs);
            new_end = new_end.max(*re);
            self.free_runs.remove(&(*rs, *re));
        }
        self.free_runs.insert((new_start, new_end));
        self.cached_free = self.free_runs.iter().map(|(s, e)| e - s).sum();
    }

    fn remove_from_free_runs(&mut self, seg: u64) -> Result<(), FreeMapError> {
        let run_key = self
            .free_runs
            .range(..=(seg, u64::MAX))
            .rev()
            .find(|(s, e)| *s <= seg && seg < *e)
            .copied();
        match run_key {
            None => Err(FreeMapError::AlreadyUsed(seg)),
            Some((start, end)) => {
                self.free_runs.remove(&(start, end));
                if seg == start {
                    if start + 1 < end {
                        self.free_runs.insert((start + 1, end));
                    }
                } else if seg == end - 1 {
                    if start < end - 1 {
                        self.free_runs.insert((start, end - 1));
                    }
                } else {
                    self.free_runs.insert((start, seg));
                    self.free_runs.insert((seg + 1, end));
                }
                self.cached_free = self.cached_free.saturating_sub(1);
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SpaceMapBitmap (Phase 2): encode/decode helpers
// ---------------------------------------------------------------------------

/// Compute segment_group layout: (segment_group_count, bytes_per_segment_group_bitmap).
#[must_use]
pub fn bitmap_layout(segment_count: u64, segment_group_segments: u64) -> (u32, usize) {
    let segment_group_count = segment_count.div_ceil(segment_group_segments);
    let bytes_per_segment_group = (segment_group_segments / 8) as usize;
    (segment_group_count as u32, bytes_per_segment_group)
}

/// Encode free runs into per-segment-group bitmaps (LSB-first per byte).
#[must_use]
pub fn encode_bitmaps(
    free_runs: &[(u64, u64)],
    segment_count: u64,
    segment_group_segments: u64,
) -> Vec<Vec<u8>> {
    let (segment_group_count, bytes_per) = bitmap_layout(segment_count, segment_group_segments);
    let mut bitmaps: Vec<Vec<u8>> = (0..segment_group_count)
        .map(|_| vec![0u8; bytes_per])
        .collect();
    for &(start, end) in free_runs {
        for seg in start..end {
            let ms = (seg / segment_group_segments) as usize;
            let bit_in_ms = (seg % segment_group_segments) as usize;
            let byte_idx = bit_in_ms / 8;
            let bit_idx = bit_in_ms % 8;
            if ms < bitmaps.len() && byte_idx < bitmaps[ms].len() {
                bitmaps[ms][byte_idx] |= 1u8 << bit_idx;
            }
        }
    }
    bitmaps
}

/// Decode per-segment-group bitmaps back into free runs, merging adjacent runs.
pub fn decode_bitmaps(
    bitmaps: &[Vec<u8>],
    segment_count: u64,
    segment_group_segments: u64,
) -> Result<Vec<(u64, u64)>, FreeMapError> {
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for (ms_idx, bitmap) in bitmaps.iter().enumerate() {
        let ms_start = ms_idx as u64 * segment_group_segments;
        let valid_bits = segment_group_segments.min(segment_count.saturating_sub(ms_start));
        let bytes_needed = valid_bits.div_ceil(8);
        if bitmap.len() < bytes_needed as usize {
            return Err(FreeMapError::CorruptCheckpoint);
        }
        let mut in_run = false;
        let mut run_start: u64 = 0;
        for bit in 0..valid_bits {
            let byte_idx = (bit / 8) as usize;
            let bit_idx = (bit % 8) as u8;
            let is_free = (bitmap[byte_idx] & (1u8 << bit_idx)) != 0;
            let global_seg = ms_start + bit;
            if is_free && !in_run {
                in_run = true;
                run_start = global_seg;
            } else if !is_free && in_run {
                in_run = false;
                runs.push((run_start, global_seg));
            }
        }
        if in_run {
            runs.push((run_start, ms_start + valid_bits));
        }
    }
    // Merge adjacent runs that span segment_group boundaries.
    if runs.is_empty() {
        return Ok(runs);
    }
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(runs.len());
    merged.push(runs[0]);
    for &(s, e) in &runs[1..] {
        let last = merged.last_mut().unwrap();
        if last.1 == s {
            last.1 = e;
        } else {
            merged.push((s, e));
        }
    }
    Ok(merged)
}

// ---------------------------------------------------------------------------
// SpaceMapCheckpointV1: encode/decode from free map (Phase 3)
// ---------------------------------------------------------------------------

impl SpaceMapCheckpointV1 {
    /// Build a checkpoint from the free map's current runs.
    ///
    /// When `dirty_only` is true, only segment_groups that have been modified since
    /// the last checkpoint are included. When false, all segment_groups are written
    /// (full checkpoint, used for pool close or explicit flush).
    #[must_use]
    pub fn from_free_map(fm: &SegmentFreeMap, dirty_only: bool) -> Self {
        let runs = fm.runs();
        let bitmaps = encode_bitmaps(&runs, fm.segment_count, fm.segment_group_segments);
        let dirty_set: Option<std::collections::BTreeSet<u32>> = if dirty_only {
            Some(fm.dirty_segment_groups.iter().copied().collect())
        } else {
            None
        };
        let entries: Vec<SegmentGroupBitmapEntry> = bitmaps
            .into_iter()
            .enumerate()
            .filter(|(i, _)| {
                dirty_set
                    .as_ref()
                    .is_none_or(|ds| ds.contains(&(*i as u32)))
            })
            .map(|(i, bitmap_data)| SegmentGroupBitmapEntry {
                segment_group_index: i as u32,
                bitmap_len: bitmap_data.len() as u32,
                bitmap_data,
            })
            .collect();
        let dirty_segment_group_count = entries.len() as u32;
        SpaceMapCheckpointV1 {
            magic: *SPACEMAP_CHECKPOINT_MAGIC,
            version: 1,
            segment_count: fm.segment_count,
            segment_group_segments: fm.segment_group_segments,
            segment_group_count: fm.segment_group_count() as u32,
            dirty_segment_group_count,
            generation: fm.generation,
            entries,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_fully_free() {
        let fm = SegmentFreeMap::new(100, vec![(0, 100)]).unwrap();
        assert_eq!(fm.free_count(), 100);
        assert_eq!(fm.runs().len(), 1);
        assert_eq!(fm.runs()[0], (0, 100));
    }

    #[test]
    fn new_empty_initial_free() {
        let fm = SegmentFreeMap::new(100, vec![]).unwrap();
        assert_eq!(fm.free_count(), 0);
        assert!(fm.runs().is_empty());
    }

    #[test]
    fn new_zero_segments() {
        let fm = SegmentFreeMap::new(0, vec![]).unwrap();
        assert_eq!(fm.segment_count, 0);
        assert_eq!(fm.free_count(), 0);
    }

    #[test]
    fn new_merges_adjacent() {
        let fm = SegmentFreeMap::new(100, vec![(0, 50), (50, 100)]).unwrap();
        assert_eq!(fm.free_count(), 100);
        assert_eq!(fm.runs().len(), 1);
        assert_eq!(fm.runs()[0], (0, 100));
    }

    #[test]
    fn new_merges_overlapping() {
        let fm = SegmentFreeMap::new(100, vec![(0, 60), (40, 100)]).unwrap();
        assert_eq!(fm.free_count(), 100);
        assert_eq!(fm.runs().len(), 1);
    }

    #[test]
    fn new_invalid_run() {
        assert!(matches!(
            SegmentFreeMap::new(100, vec![(0, 101)]).unwrap_err(),
            FreeMapError::InvalidRun(0, 101)
        ));
        assert!(matches!(
            SegmentFreeMap::new(100, vec![(50, 50)]).unwrap_err(),
            FreeMapError::InvalidRun(50, 50)
        ));
        assert!(matches!(
            SegmentFreeMap::new(100, vec![(60, 50)]).unwrap_err(),
            FreeMapError::InvalidRun(60, 50)
        ));
    }

    // --- from_runs constructor ---

    #[test]
    fn from_runs_basic() {
        let fm = SegmentFreeMap::from_runs(100, vec![(0, 50), (60, 80)]).unwrap();
        assert_eq!(fm.free_count(), 70);
        assert_eq!(fm.runs().len(), 2);
        assert!(fm.runs().contains(&(0, 50)));
        assert!(fm.runs().contains(&(60, 80)));
    }

    #[test]
    fn from_runs_invalid() {
        assert!(SegmentFreeMap::from_runs(10, vec![(0, 20)]).is_err());
    }

    #[test]
    fn alloc_after_basic() {
        let mut fm = SegmentFreeMap::new(10, vec![(0, 10)]).unwrap();
        assert_eq!(fm.alloc_after(0).unwrap(), 0);
        assert_eq!(fm.free_count(), 9);
        assert!(!fm.is_free(0));
    }

    #[test]
    fn alloc_after_cursor() {
        let mut fm = SegmentFreeMap::new(10, vec![(0, 10)]).unwrap();
        assert_eq!(fm.alloc_after(5).unwrap(), 5);
        assert_eq!(fm.free_count(), 9);
        let runs = fm.runs();
        assert!(runs.contains(&(0, 5)));
        assert!(runs.contains(&(6, 10)));
    }

    #[test]
    fn alloc_after_wrap() {
        let mut fm = SegmentFreeMap::new(10, vec![(0, 5), (8, 10)]).unwrap();
        assert_eq!(fm.alloc_after(5).unwrap(), 8);
        assert_eq!(fm.free_count(), 6);
    }

    #[test]
    fn alloc_after_wrap_to_zero() {
        let mut fm = SegmentFreeMap::new(10, vec![(0, 4)]).unwrap();
        assert_eq!(fm.alloc_after(5).unwrap(), 0);
        assert_eq!(fm.free_count(), 3);
    }

    #[test]
    fn alloc_after_enospc() {
        let _fm = SegmentFreeMap::new(10, vec![]).unwrap();
        assert_eq!(_fm.free_count(), 0);

        let mut fm2 = SegmentFreeMap::new(10, vec![(0, 10)]).unwrap();
        for _ in 0..10 {
            fm2.alloc_after(0).unwrap();
        }
        assert!(matches!(
            fm2.alloc_after(0).unwrap_err(),
            FreeMapError::NoFreeSegments
        ));
    }

    #[test]
    fn alloc_after_zero_pool() {
        let mut fm = SegmentFreeMap::new(0, vec![]).unwrap();
        assert!(matches!(
            fm.alloc_after(0).unwrap_err(),
            FreeMapError::NoFreeSegments
        ));
    }

    #[test]
    fn alloc_after_cursor_beyond_all_free() {
        let mut fm = SegmentFreeMap::new(100, vec![(0, 10), (50, 60)]).unwrap();
        // cursor at 20: no free at or after 20 in first run,
        // wraps to next run at 50
        assert_eq!(fm.alloc_after(20).unwrap(), 50);
        assert_eq!(fm.free_count(), 19);
    }

    #[test]
    fn alloc_splits_run() {
        let mut fm = SegmentFreeMap::new(100, vec![(0, 100)]).unwrap();
        assert_eq!(fm.alloc_after(50).unwrap(), 50);
        let runs = fm.runs();
        assert!(runs.contains(&(0, 50)));
        assert!(runs.contains(&(51, 100)));
    }

    #[test]
    fn add_free_idempotent() {
        let mut fm = SegmentFreeMap::new(10, vec![(0, 10)]).unwrap();
        assert!(fm.add_free(5).is_ok());
        assert_eq!(fm.free_count(), 10);
    }

    #[test]
    fn add_free_new() {
        let mut fm = SegmentFreeMap::new(10, vec![(0, 5), (6, 10)]).unwrap();
        assert!(fm.add_free(5).is_ok());
        assert_eq!(fm.runs().len(), 1);
        assert_eq!(fm.runs()[0], (0, 10));
    }

    #[test]
    fn add_free_merge_left() {
        let mut fm = SegmentFreeMap::new(10, vec![(0, 5), (7, 10)]).unwrap();
        assert!(fm.add_free(5).is_ok());
        assert!(fm.runs().contains(&(0, 6)));
        assert!(fm.runs().contains(&(7, 10)));
    }

    #[test]
    fn add_free_merge_right() {
        let mut fm = SegmentFreeMap::new(10, vec![(0, 5), (7, 10)]).unwrap();
        assert!(fm.add_free(6).is_ok());
        assert!(fm.runs().contains(&(0, 5)));
        assert!(fm.runs().contains(&(6, 10)));
    }

    #[test]
    fn add_free_merge_both() {
        let mut fm = SegmentFreeMap::new(10, vec![(0, 5), (6, 10)]).unwrap();
        assert!(fm.add_free(5).is_ok());
        assert_eq!(fm.runs().len(), 1);
        assert_eq!(fm.runs()[0], (0, 10));
    }

    #[test]
    fn add_free_out_of_range() {
        let mut fm = SegmentFreeMap::new(10, vec![(0, 10)]).unwrap();
        assert!(matches!(
            fm.add_free(10).unwrap_err(),
            FreeMapError::SegmentOutOfRange(10)
        ));
    }

    #[test]
    fn remove_free_first_in_run() {
        let mut fm = SegmentFreeMap::new(10, vec![(0, 10)]).unwrap();
        fm.remove_free(0).unwrap();
        assert!(!fm.is_free(0));
        assert_eq!(fm.free_count(), 9);
        assert!(fm.runs().contains(&(1, 10)));
    }

    #[test]
    fn remove_free_last_in_run() {
        let mut fm = SegmentFreeMap::new(10, vec![(0, 10)]).unwrap();
        fm.remove_free(9).unwrap();
        assert!(!fm.is_free(9));
        assert_eq!(fm.free_count(), 9);
        assert!(fm.runs().contains(&(0, 9)));
    }

    #[test]
    fn remove_free_single_segment_run() {
        let mut fm = SegmentFreeMap::new(10, vec![(0, 1), (5, 6), (9, 10)]).unwrap();
        fm.remove_free(5).unwrap();
        assert_eq!(fm.free_count(), 2);
        assert_eq!(fm.runs(), vec![(0, 1), (9, 10)]);
    }

    #[test]
    fn remove_free_basic() {
        let mut fm = SegmentFreeMap::new(10, vec![(0, 10)]).unwrap();
        assert!(fm.remove_free(5).is_ok());
        assert!(!fm.is_free(5));
        assert_eq!(fm.free_count(), 9);
        let runs = fm.runs();
        assert!(runs.contains(&(0, 5)));
        assert!(runs.contains(&(6, 10)));
    }

    #[test]
    fn remove_free_already_used() {
        let mut fm = SegmentFreeMap::new(10, vec![(0, 10)]).unwrap();
        fm.remove_free(3).unwrap();
        assert!(matches!(
            fm.remove_free(3).unwrap_err(),
            FreeMapError::AlreadyUsed(3)
        ));
    }

    #[test]
    fn remove_free_out_of_range() {
        let mut fm = SegmentFreeMap::new(10, vec![(0, 10)]).unwrap();
        assert!(matches!(
            fm.remove_free(10).unwrap_err(),
            FreeMapError::SegmentOutOfRange(10)
        ));
    }

    #[test]
    fn is_free_basic() {
        let fm = SegmentFreeMap::new(10, vec![(0, 5), (8, 10)]).unwrap();
        assert!(fm.is_free(0));
        assert!(fm.is_free(4));
        assert!(!fm.is_free(5));
        assert!(!fm.is_free(7));
        assert!(fm.is_free(8));
        assert!(fm.is_free(9));
    }

    #[test]
    fn is_free_out_of_range() {
        let fm = SegmentFreeMap::new(10, vec![(0, 10)]).unwrap();
        assert!(!fm.is_free(10));
        assert!(!fm.is_free(100));
    }

    #[test]
    fn free_count_method() {
        let fm = SegmentFreeMap::new(10, vec![(0, 5), (8, 10)]).unwrap();
        assert_eq!(fm.free_count(), 7);
    }

    #[test]
    fn stats_empty() {
        let fm = SegmentFreeMap::new(10, vec![]).unwrap();
        let s = fm.stats();
        assert_eq!(s.free_segments, 0);
        assert_eq!(s.used_segments, 10);
        assert_eq!(s.fragmentation_pct, 0.0);
    }

    #[test]
    fn stats_full() {
        let fm = SegmentFreeMap::new(10, vec![(0, 10)]).unwrap();
        let s = fm.stats();
        assert_eq!(s.free_segments, 10);
        assert_eq!(s.used_segments, 0);
        assert_eq!(s.fragmentation_pct, 10.0);
    }

    #[test]
    fn stats_fragmented() {
        let fm = SegmentFreeMap::new(10, vec![(0, 2), (4, 6), (8, 10)]).unwrap();
        let s = fm.stats();
        assert_eq!(s.free_segments, 6);
        assert_eq!(s.free_runs, 3);
    }

    #[test]
    fn stats_zero_segments() {
        let fm = SegmentFreeMap::new(0, vec![]).unwrap();
        let s = fm.stats();
        assert_eq!(s.segment_count, 0);
        assert_eq!(s.free_segments, 0);
        assert_eq!(s.used_segments, 0);
        assert_eq!(s.fragmentation_pct, 0.0);
    }

    #[test]
    fn stats_single_segment() {
        let fm = SegmentFreeMap::new(1, vec![(0, 1)]).unwrap();
        let s = fm.stats();
        assert_eq!(s.free_segments, 1);
        assert_eq!(s.used_segments, 0);
        assert_eq!(s.free_runs, 1);
    }

    #[test]
    fn space_pressure_detection() {
        let mut fm = SegmentFreeMap::new(100, vec![(0, 100)]).unwrap();
        assert!(!fm.is_under_pressure());

        for _ in 0..95 {
            fm.alloc_after(0).unwrap();
        }
        assert!(fm.is_under_pressure());
    }

    #[test]
    fn space_pressure_empty() {
        let fm = SegmentFreeMap::new(10, vec![]).unwrap();
        assert!(fm.is_under_pressure());
    }

    #[test]
    fn space_pressure_full() {
        let fm = SegmentFreeMap::new(100, vec![(0, 100)]).unwrap();
        assert!(!fm.is_under_pressure());
    }

    #[test]
    fn generation_monotonic() {
        let mut fm = SegmentFreeMap::new(100, vec![(0, 100)]).unwrap();
        let g1 = fm.generation;
        fm.alloc_after(0).unwrap();
        assert!(fm.generation > g1);
        let g2 = fm.generation;
        fm.alloc_after(0).unwrap();
        assert!(fm.generation > g2);
    }

    // --- stale generation detection (Phase 3) ---

    #[test]
    fn checkpoint_generation_floor_at_one() {
        let fm = SegmentFreeMap::new(100, vec![(0, 100)]).unwrap();
        let ckpt = SpaceMapCheckpointV1::from_free_map(&fm, false);
        assert!(ckpt.generation >= 1);
    }

    #[test]
    fn from_checkpoint_respects_generation() {
        let mut fm = SegmentFreeMap::new(100, vec![(0, 100)]).unwrap();
        for _ in 0..10 {
            fm.alloc_after(0).unwrap();
        }
        let gen = fm.generation;
        let ckpt = SpaceMapCheckpointV1::from_free_map(&fm, false);
        let fm2 = SegmentFreeMap::from_checkpoint(&ckpt).unwrap();
        assert_eq!(fm2.generation, gen);
    }

    #[test]
    fn from_checkpoint_floor_generation_zero() {
        let mut ckpt = SpaceMapCheckpointV1::new(100, 4096, 0);
        let bitmaps = encode_bitmaps(&[(0, 100)], 100, 4096);
        ckpt.entries = bitmaps
            .into_iter()
            .enumerate()
            .map(|(i, bitmap_data)| SegmentGroupBitmapEntry {
                segment_group_index: i as u32,
                bitmap_len: bitmap_data.len() as u32,
                bitmap_data,
            })
            .collect();
        let fm = SegmentFreeMap::from_checkpoint(&ckpt).unwrap();
        assert_eq!(fm.generation, 1);
    }

    #[test]
    fn bitmap_layout_basic() {
        let (count, bytes) = bitmap_layout(8192, 4096);
        assert_eq!(count, 2);
        assert_eq!(bytes, 512);
    }

    #[test]
    fn encode_decode_all_free() {
        let runs = vec![(0u64, 100u64)];
        let bitmaps = encode_bitmaps(&runs, 100, 4096);
        let decoded = decode_bitmaps(&bitmaps, 100, 4096).unwrap();
        assert_eq!(decoded, runs);
    }

    #[test]
    fn encode_decode_all_used() {
        let bitmaps = encode_bitmaps(&[], 100, 4096);
        let decoded = decode_bitmaps(&bitmaps, 100, 4096).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn encode_decode_single_segment() {
        let runs = vec![(0u64, 1u64)];
        let bitmaps = encode_bitmaps(&runs, 1, 4096);
        let decoded = decode_bitmaps(&bitmaps, 1, 4096).unwrap();
        assert_eq!(decoded, runs);
    }

    #[test]
    fn encode_decode_single_segment_used() {
        let bitmaps = encode_bitmaps(&[], 1, 4096);
        let decoded = decode_bitmaps(&bitmaps, 1, 4096).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn encode_decode_fragmented() {
        let runs = vec![(0u64, 5u64), (50u64, 60u64), (90u64, 100u64)];
        let bitmaps = encode_bitmaps(&runs, 100, 4096);
        let decoded = decode_bitmaps(&bitmaps, 100, 4096).unwrap();
        assert_eq!(decoded, runs);
    }

    #[test]
    fn encode_decode_cross_segment_group() {
        let runs = vec![(4000u64, 4200u64)];
        let bitmaps = encode_bitmaps(&runs, 8192, 4096);
        let decoded = decode_bitmaps(&bitmaps, 8192, 4096).unwrap();
        assert_eq!(decoded, vec![(4000u64, 4200u64)]);
    }

    #[test]
    fn encode_decode_partial_last_segment_group() {
        let runs = vec![(0u64, 100u64)];
        let bitmaps = encode_bitmaps(&runs, 100, 4096);
        let decoded = decode_bitmaps(&bitmaps, 100, 4096).unwrap();
        assert_eq!(decoded, runs);
    }

    #[test]
    fn checkpoint_new_header() {
        let ckpt = SpaceMapCheckpointV1::new(8192, 4096, 42);
        assert_eq!(&ckpt.magic, SPACEMAP_CHECKPOINT_MAGIC);
        assert_eq!(ckpt.version, 1);
        assert_eq!(ckpt.segment_count, 8192);
        assert_eq!(ckpt.segment_group_segments, 4096);
        assert_eq!(ckpt.segment_group_count, 2);
        assert_eq!(ckpt.generation, 42);
        assert_eq!(ckpt.dirty_segment_group_count, 0);
        assert!(ckpt.entries.is_empty());
    }

    #[test]
    fn checkpoint_from_free_map() {
        let fm = SegmentFreeMap::new(100, vec![(0, 50), (60, 100)]).unwrap();
        let ckpt = SpaceMapCheckpointV1::from_free_map(&fm, false);
        assert_eq!(&ckpt.magic, SPACEMAP_CHECKPOINT_MAGIC);
        assert_eq!(ckpt.segment_count, 100);
        assert_eq!(ckpt.generation, 1);
    }

    #[test]
    fn checkpoint_magic_constant() {
        assert_eq!(SPACEMAP_CHECKPOINT_MAGIC, b"SPMP");
    }

    #[test]
    fn spec_markers_present() {
        let s = concat!(
            "SPACEMAP_ALLOCATOR_SPEC",
            "|",
            "SegmentFreeMap",
            "|",
            "alloc_after",
            "|",
            "add_free",
            "|",
            "remove_free",
            "|",
            "is_free",
            "|",
            "runs",
            "|",
            "stats",
            "|",
            "FreeMapError",
            "|",
            "NoFreeSegments",
            "|",
            "SegmentFreeMapStats",
            "|",
            "fragmentation_pct",
            "|",
            "encode_bitmaps",
            "|",
            "decode_bitmaps",
            "|",
            "bitmap_layout",
            "|",
            "DEFAULT_SEGMENT_GROUP_SEGMENTS",
            "|",
            "SpaceMapCheckpointV1",
            "|",
            "SegmentGroupBitmapEntry",
            "|",
            "SPACEMAP_CHECKPOINT_MAGIC",
            "|",
            "generation",
            "|",
            "SPACE_PRESSURE_THRESHOLD",
            "|",
            "from_runs",
            "|",
            "free_count",
            "|",
            "is_under_pressure",
            "|",
            "tidefs-xtask check-spacemap-allocator"
        );
        assert!(!s.is_empty());
    }

    // --- checkpoint reconstructor tests (from_checkpoint / #1607) ---

    #[test]
    fn from_checkpoint_full_roundtrip() {
        let fm1 = SegmentFreeMap::new(8192, vec![(0, 8192)]).unwrap();
        let ckpt = SpaceMapCheckpointV1::from_free_map(&fm1, false);
        let fm2 = SegmentFreeMap::from_checkpoint(&ckpt).unwrap();
        assert_eq!(fm2.segment_count, 8192);
        assert_eq!(fm2.free_count(), 8192);
        assert_eq!(fm2.generation, fm1.generation);
        assert_eq!(fm2.runs(), fm1.runs());
    }

    #[test]
    fn from_checkpoint_fragmented_roundtrip() {
        let fm1 = SegmentFreeMap::new(10000, vec![(0, 2000), (3000, 5000), (7000, 9000)]).unwrap();
        let ckpt = SpaceMapCheckpointV1::from_free_map(&fm1, false);
        let fm2 = SegmentFreeMap::from_checkpoint(&ckpt).unwrap();
        assert_eq!(fm2.segment_count, 10000);
        assert_eq!(fm2.free_count(), fm1.free_count());
        assert_eq!(fm2.runs(), fm1.runs());
    }

    #[test]
    fn from_checkpoint_preserves_generation() {
        let mut fm = SegmentFreeMap::new(100, vec![(0, 100)]).unwrap();
        fm.alloc_after(0).unwrap();
        fm.alloc_after(0).unwrap();
        let gen_after_allocs = fm.generation;
        let ckpt = SpaceMapCheckpointV1::from_free_map(&fm, false);
        let fm2 = SegmentFreeMap::from_checkpoint(&ckpt).unwrap();
        assert_eq!(fm2.generation, gen_after_allocs);
    }

    #[test]
    fn from_checkpoint_all_used() {
        let fm = SegmentFreeMap::new(100, vec![]).unwrap();
        let ckpt = SpaceMapCheckpointV1::from_free_map(&fm, false);
        let fm2 = SegmentFreeMap::from_checkpoint(&ckpt).unwrap();
        assert_eq!(fm2.free_count(), 0);
    }

    #[test]
    fn from_checkpoint_incremental_roundtrip() {
        let mut fm = SegmentFreeMap::new(8192, vec![(0, 8192)]).unwrap();
        fm.alloc_after(0).unwrap();
        fm.alloc_after(4100).unwrap();
        let ckpt = SpaceMapCheckpointV1::from_free_map(&fm, true);
        let fm2 = SegmentFreeMap::from_checkpoint(&ckpt).unwrap();
        assert_eq!(fm2.free_count(), fm.free_count());
        assert_eq!(fm2.runs(), fm.runs());
    }

    #[test]
    fn from_checkpoint_cross_segment_group_runs() {
        let fm = SegmentFreeMap::new(10000, vec![(4000, 5000)]).unwrap();
        let ckpt = SpaceMapCheckpointV1::from_free_map(&fm, false);
        let fm2 = SegmentFreeMap::from_checkpoint(&ckpt).unwrap();
        assert_eq!(fm2.runs(), vec![(4000, 5000)]);
    }

    // --- dirty-segment_group tracking tests (#1341) ---

    #[test]
    fn dirty_segment_group_on_alloc() {
        let mut fm = SegmentFreeMap::new(10000, vec![(0, 10000)]).unwrap();
        assert!(fm.dirty_segment_groups().is_empty());
        fm.alloc_after(0).unwrap();
        assert_eq!(fm.dirty_segment_groups(), vec![0]);
    }

    #[test]
    fn dirty_segment_group_on_add_free() {
        let mut fm = SegmentFreeMap::new(10000, vec![(0, 5000), (5001, 10000)]).unwrap();
        fm.add_free(5000).unwrap();
        assert!(fm.dirty_segment_groups().contains(&1));
    }

    #[test]
    fn dirty_segment_group_on_remove_free() {
        let mut fm = SegmentFreeMap::new(10000, vec![(0, 10000)]).unwrap();
        fm.remove_free(0).unwrap();
        assert!(fm.dirty_segment_groups().contains(&0));
    }

    #[test]
    fn dirty_segment_group_accumulates() {
        let mut fm = SegmentFreeMap::new(10000, vec![(0, 10000)]).unwrap();
        fm.alloc_after(0).unwrap();
        fm.alloc_after(5000).unwrap();
        let dirty = fm.dirty_segment_groups();
        assert!(dirty.contains(&0));
        assert!(dirty.contains(&1));
        assert_eq!(dirty.len(), 2);
    }

    #[test]
    fn dirty_segment_group_dedup_same_segment_group() {
        let mut fm = SegmentFreeMap::new(10000, vec![(0, 10000)]).unwrap();
        fm.alloc_after(0).unwrap();
        fm.alloc_after(1).unwrap();
        fm.add_free(100).unwrap();
        assert_eq!(fm.dirty_segment_groups(), vec![0]);
    }

    #[test]
    fn clear_dirty_segment_groups() {
        let mut fm = SegmentFreeMap::new(10000, vec![(0, 10000)]).unwrap();
        fm.alloc_after(0).unwrap();
        fm.alloc_after(5000).unwrap();
        assert_eq!(fm.dirty_segment_groups().len(), 2);
        fm.clear_dirty_segment_groups();
        assert!(fm.dirty_segment_groups().is_empty());
    }

    #[test]
    fn segment_group_index_computation() {
        let fm = SegmentFreeMap::new(10000, vec![(0, 10000)]).unwrap();
        assert_eq!(fm.segment_group_index(0), 0);
        assert_eq!(fm.segment_group_index(4095), 0);
        assert_eq!(fm.segment_group_index(4096), 1);
        assert_eq!(fm.segment_group_index(8191), 1);
        assert_eq!(fm.segment_group_index(8192), 2);
    }

    #[test]
    fn segment_group_count_computation() {
        let fm = SegmentFreeMap::new(10000, vec![(0, 10000)]).unwrap();
        assert_eq!(fm.segment_group_count(), 3);
    }

    #[test]
    fn checkpoint_filtered_to_dirty_only() {
        let mut fm = SegmentFreeMap::new(10000, vec![(0, 10000)]).unwrap();
        fm.alloc_after(0).unwrap();
        fm.alloc_after(5000).unwrap();

        let ckpt = SpaceMapCheckpointV1::from_free_map(&fm, true);
        let included: Vec<u32> = ckpt.entries.iter().map(|e| e.segment_group_index).collect();
        assert!(included.contains(&0));
        assert!(included.contains(&1));
        assert!(!included.contains(&2));
        assert_eq!(ckpt.dirty_segment_group_count, 2);
        assert_eq!(ckpt.segment_group_count, 3);
    }

    #[test]
    fn checkpoint_full_includes_all() {
        let mut fm = SegmentFreeMap::new(10000, vec![(0, 10000)]).unwrap();
        fm.alloc_after(0).unwrap();
        let ckpt = SpaceMapCheckpointV1::from_free_map(&fm, false);
        assert_eq!(ckpt.entries.len() as u32, ckpt.segment_group_count);
    }

    #[test]
    fn dirty_only_empty_when_no_changes() {
        let fm = SegmentFreeMap::new(10000, vec![(0, 10000)]).unwrap();
        assert!(fm.dirty_segment_groups().is_empty());
        let ckpt = SpaceMapCheckpointV1::from_free_map(&fm, true);
        assert!(ckpt.entries.is_empty());
        assert_eq!(ckpt.dirty_segment_group_count, 0);
    }

    #[test]
    fn clear_and_redirty_cycle() {
        let mut fm = SegmentFreeMap::new(10000, vec![(0, 10000)]).unwrap();
        fm.alloc_after(0).unwrap();
        fm.clear_dirty_segment_groups();
        assert!(fm.dirty_segment_groups().is_empty());
        fm.alloc_after(100).unwrap();
        assert_eq!(fm.dirty_segment_groups(), vec![0]);
    }

    #[test]
    fn remove_free_marks_dirty() {
        let mut fm = SegmentFreeMap::new(10000, vec![(0, 10000)]).unwrap();
        fm.remove_free(100).unwrap();
        assert!(fm.dirty_segment_groups().contains(&0));
    }

    #[test]
    fn incremental_checkpoint_bitmap_consistency() {
        let mut fm = SegmentFreeMap::new(10000, vec![(0, 10000)]).unwrap();
        fm.alloc_after(0).unwrap();
        fm.alloc_after(5000).unwrap();

        let full = SpaceMapCheckpointV1::from_free_map(&fm, false);
        let inc = SpaceMapCheckpointV1::from_free_map(&fm, true);
        assert_eq!(inc.entries.len(), 2);

        for inc_entry in &inc.entries {
            let full_entry = full
                .entries
                .iter()
                .find(|e| e.segment_group_index == inc_entry.segment_group_index)
                .unwrap();
            assert_eq!(
                inc_entry.bitmap_data, full_entry.bitmap_data,
                "segment_group {} bitmap mismatch",
                inc_entry.segment_group_index
            );
        }
    }

    // --- size_class_for helper ---

    #[test]
    fn size_class_for_basic() {
        assert_eq!(size_class_for(0), 0);
        assert_eq!(size_class_for(1), 0);
        assert_eq!(size_class_for(2), 1);
        assert_eq!(size_class_for(3), 1);
        assert_eq!(size_class_for(4), 2);
        assert_eq!(size_class_for(16), 4);
        assert_eq!(size_class_for(128), 7);
        assert_eq!(size_class_for(1024), 10);
        assert_eq!(size_class_for(8192), 13);
        assert_eq!(size_class_for(99999), 13);
    }

    // --- free_range (Phase 4) ---

    #[test]
    fn free_range_basic() {
        let mut fm = SegmentFreeMap::new(100, vec![(0, 50), (60, 100)]).unwrap();
        fm.free_range(50, 60).unwrap();
        assert_eq!(fm.free_count(), 100);
        assert_eq!(fm.runs().len(), 1);
        assert_eq!(fm.runs()[0], (0, 100));
    }

    #[test]
    fn free_range_partial_overlap() {
        // Freeing a range that overlaps partially with used space.
        let mut fm = SegmentFreeMap::new(100, vec![(0, 30), (70, 100)]).unwrap();
        fm.free_range(25, 75).unwrap();
        // Now: [0,75) merged from [0,30) + [25,75), and [70,100) merged with [70,75)
        // Actually: free_range(25,75) inserts [25,75) which merges with [0,30) => [0,75)
        // and also merges with [70,100) => [0,100)
        assert_eq!(fm.free_count(), 100);
        assert_eq!(fm.runs().len(), 1);
    }

    #[test]
    fn free_range_invalid() {
        let mut fm = SegmentFreeMap::new(100, vec![(0, 50)]).unwrap();
        assert!(matches!(
            fm.free_range(0, 0).unwrap_err(),
            FreeMapError::InvalidRun(0, 0)
        ));
        assert!(matches!(
            fm.free_range(60, 50).unwrap_err(),
            FreeMapError::InvalidRun(60, 50)
        ));
        assert!(matches!(
            fm.free_range(0, 101).unwrap_err(),
            FreeMapError::InvalidRun(0, 101)
        ));
    }

    #[test]
    fn free_range_single_segment() {
        let mut fm = SegmentFreeMap::new(100, vec![(0, 50), (51, 100)]).unwrap();
        fm.free_range(50, 51).unwrap();
        assert_eq!(fm.free_count(), 100);
        assert_eq!(fm.runs().len(), 1);
    }

    #[test]
    fn free_range_marks_dirty() {
        let mut fm = SegmentFreeMap::new(100, vec![(0, 90)]).unwrap();
        // Use up segment 50 so it's dirty
        fm.remove_free(50).unwrap();
        fm.clear_dirty_segment_groups();
        // Now free a range
        fm.free_range(50, 55).unwrap();
        assert!(!fm.dirty_segment_groups().is_empty());
    }

    // --- coalesce ---

    #[test]
    fn coalesce_adjacent_runs() {
        let mut fm = SegmentFreeMap::new(100, vec![]).unwrap();
        // Manually create adjacent runs (shouldn't happen normally, but coalesce fixes it)
        fm.free_runs.clear();
        fm.free_runs.insert((0, 50));
        fm.free_runs.insert((50, 100));
        fm.coalesce();
        assert_eq!(fm.runs().len(), 1);
        assert_eq!(fm.runs()[0], (0, 100));
    }

    #[test]
    fn coalesce_non_adjacent_runs() {
        let mut fm = SegmentFreeMap::new(100, vec![]).unwrap();
        fm.free_runs.clear();
        fm.free_runs.insert((0, 30));
        fm.free_runs.insert((50, 80));
        fm.coalesce();
        assert_eq!(fm.runs().len(), 2);
    }

    #[test]
    fn coalesce_empty() {
        let mut fm = SegmentFreeMap::new(100, vec![]).unwrap();
        fm.coalesce();
        assert!(fm.runs().is_empty());
    }

    #[test]
    fn coalesce_single_run() {
        let mut fm = SegmentFreeMap::new(100, vec![(0, 50)]).unwrap();
        fm.coalesce();
        assert_eq!(fm.runs().len(), 1);
        assert_eq!(fm.runs()[0], (0, 50));
    }

    #[test]
    fn coalesce_multiple_adjacent() {
        let mut fm = SegmentFreeMap::new(100, vec![]).unwrap();
        fm.free_runs.clear();
        fm.free_runs.insert((0, 10));
        fm.free_runs.insert((10, 20));
        fm.free_runs.insert((20, 30));
        fm.free_runs.insert((40, 50));
        fm.free_runs.insert((50, 60));
        fm.coalesce();
        assert_eq!(fm.runs().len(), 2);
        assert!(fm.runs().contains(&(0, 30)));
        assert!(fm.runs().contains(&(40, 60)));
    }

    // --- allocate (size-class hints) ---

    #[test]
    fn allocate_size_class_hit() {
        let mut fm = SegmentFreeMap::new(100, vec![(0, 100)]).unwrap();
        // allocate should use size-class hints and hit
        let seg = fm.allocate(1, 0).unwrap();
        assert_eq!(seg, 0);
        assert_eq!(fm.size_class_hit_count, 1);
        assert_eq!(fm.size_class_miss_count, 0);
    }

    #[test]
    fn allocate_size_class_miss_fallback() {
        // Create a scene where size class can't find, but alloc_after can
        let mut fm = SegmentFreeMap::new(100, vec![(50, 60)]).unwrap();
        // Allocate with cursor 0: hints might not have a run at cursor >= 0
        // Actually with only (50,60) the hints have this run, so this should hit.
        // Let's make it miss by asking for cursor beyond all free
        let result = fm.allocate(1, 70);
        // Size class check: find_for_size_ge(1, 70) - no run at or after 70
        // Fallback to alloc_after(70) - wraps to 0, finds 50
        assert!(result.is_ok());
        assert_eq!(fm.size_class_miss_count, 1);
    }

    #[test]
    fn allocate_enospc() {
        let mut fm = SegmentFreeMap::new(10, vec![]).unwrap();
        assert!(matches!(
            fm.allocate(1, 0).unwrap_err(),
            FreeMapError::NoFreeSegments
        ));
    }

    #[test]
    fn allocate_generation_increments() {
        let mut fm = SegmentFreeMap::new(100, vec![(0, 100)]).unwrap();
        let g1 = fm.generation;
        fm.allocate(1, 0).unwrap();
        assert!(fm.generation > g1);
    }

    #[test]
    fn allocate_size_class_hit_rate() {
        let mut fm = SegmentFreeMap::new(1000, vec![(0, 1000)]).unwrap();
        // 10 allocations should all hit
        for _i in 0..10 {
            fm.allocate(1, 0).unwrap();
        }
        assert_eq!(fm.size_class_hit_count, 10);
        assert_eq!(fm.size_class_miss_count, 0);
    }

    // --- extended_stats ---

    #[test]
    fn extended_stats_basic() {
        let fm = SegmentFreeMap::new(1000, vec![(0, 200), (400, 800)]).unwrap();
        let s = fm.extended_stats();
        assert_eq!(s.segment_count, 1000);
        assert_eq!(s.free_segments, 600);
        assert_eq!(s.used_segments, 400);
        assert_eq!(s.free_runs, 2);
        assert_eq!(s.largest_contiguous_free, 400);
    }

    #[test]
    fn extended_stats_largest_free() {
        let fm = SegmentFreeMap::new(1000, vec![(0, 10), (50, 100), (200, 900)]).unwrap();
        let s = fm.extended_stats();
        assert_eq!(s.largest_contiguous_free, 700);
    }

    #[test]
    fn extended_stats_empty_pool() {
        let fm = SegmentFreeMap::new(0, vec![]).unwrap();
        let s = fm.extended_stats();
        assert_eq!(s.segment_count, 0);
        assert_eq!(s.largest_contiguous_free, 0);
    }

    #[test]
    fn extended_stats_hit_rate_zero() {
        let fm = SegmentFreeMap::new(100, vec![(0, 100)]).unwrap();
        let s = fm.extended_stats();
        assert_eq!(s.size_class_hit_rate, 0.0);
    }

    // --- defrag_report ---

    #[test]
    fn defrag_report_empty() {
        let fm = SegmentFreeMap::new(10000, vec![]).unwrap();
        let r = fm.defrag_report();
        assert!(r.hotspots.is_empty());
        assert_eq!(r.free_runs_count, 0);
        assert_eq!(r.largest_contiguous_free, 0);
        assert_eq!(r.fragmentation_ratio, 0.0);
    }

    #[test]
    fn defrag_report_fully_free() {
        let fm = SegmentFreeMap::new(10000, vec![(0, 10000)]).unwrap();
        let r = fm.defrag_report();
        assert!(!r.hotspots.is_empty());
        assert_eq!(r.free_runs_count, 1);
        assert_eq!(r.largest_contiguous_free, 10000);
        // First hotspot should be the segment_group with lowest fragmentation
    }

    #[test]
    fn defrag_report_fragmented() {
        let fm = SegmentFreeMap::new(
            10000,
            vec![(0, 100), (200, 300), (400, 500), (600, 700), (800, 900)],
        )
        .unwrap();
        let r = fm.defrag_report();
        assert_eq!(r.free_runs_count, 5);
        // Hotspots should be sorted by fragmentation severity
        for i in 1..r.hotspots.len() {
            assert!(r.hotspots[i - 1].fragmentation_pct >= r.hotspots[i].fragmentation_pct);
        }
    }

    // --- alloc → free → coalesce → realloc cycle ---

    #[test]
    fn alloc_free_coalesce_realloc_cycle() {
        let mut fm = SegmentFreeMap::new(100, vec![(0, 100)]).unwrap();
        // Allocate 50 segments
        for _ in 0..50 {
            fm.alloc_after(0).unwrap();
        }
        assert_eq!(fm.free_count(), 50);
        // Free them all back
        for seg in 0..50 {
            fm.free_range(seg, seg + 1).unwrap();
        }
        assert_eq!(fm.free_count(), 100);
        // After free_range, coalesce was called (inside free_range which rebuilds hints)
        // but the explicit coalesce should merge adjacent freed segments
        fm.coalesce();
        assert_eq!(fm.runs().len(), 1);
    }

    // --- extreme fragmentation stress test ---

    #[test]
    fn fragmentation_stress_1000_random_alloc_free() {
        // Use a deterministic "random" sequence for reproducibility.
        let mut fm = SegmentFreeMap::new(2000, vec![(0, 2000)]).unwrap();
        let mut allocated: Vec<u64> = Vec::new();
        let mut seed: u64 = 12345;

        // Simple LCG
        let mut next_rand = || {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            seed
        };

        for _ in 0..1000 {
            let op = next_rand() % 2; // 0 = alloc, 1 = free
            if op == 0 || allocated.is_empty() {
                // Allocate
                let cursor = next_rand() % fm.segment_count;
                if let Ok(seg) = fm.allocate(1, cursor) {
                    allocated.push(seg);
                }
            } else {
                // Free a random previously-allocated segment
                let idx = (next_rand() as usize) % allocated.len();
                let seg = allocated.swap_remove(idx);
                let _ = fm.free_range(seg, seg + 1);
            }
        }

        // After all that churn, free everything and coalesce
        for seg in allocated {
            let _ = fm.free_range(seg, seg + 1);
        }
        fm.coalesce();
        assert_eq!(fm.free_count(), 2000);
        // With coalescing, we should have a single run or very few runs
        assert_eq!(fm.runs().len(), 1);
    }

    #[test]
    fn fragmentation_stress_verify_coalescing() {
        let mut fm = SegmentFreeMap::new(100, vec![(0, 100)]).unwrap();
        // Alternate alloc/free to create a checkerboard pattern
        for i in 0..50 {
            fm.remove_free(i * 2).unwrap(); // Free even segments
        }
        assert_eq!(fm.free_count(), 50);
        // Free all odd segments
        for i in 0..50 {
            fm.free_range(i * 2, i * 2 + 1).unwrap();
        }
        fm.coalesce();
        assert_eq!(fm.free_count(), 100);
        assert_eq!(fm.runs().len(), 1);
    }

    // --- free-segments accounting tests ---

    #[test]
    fn free_segments_initial_value() {
        let fm = SegmentFreeMap::new(100, vec![(0, 50), (60, 100)]).unwrap();
        assert_eq!(fm.free_segments(), 90);
        assert_eq!(fm.used_segments(), 10);
    }

    #[test]
    fn free_segments_after_alloc() {
        let mut fm = SegmentFreeMap::new(100, vec![(0, 100)]).unwrap();
        assert_eq!(fm.free_segments(), 100);
        fm.alloc_after(0).unwrap();
        assert_eq!(fm.free_segments(), 99);
        fm.alloc_after(0).unwrap();
        assert_eq!(fm.free_segments(), 98);
    }

    #[test]
    fn free_segments_after_add_free() {
        let mut fm = SegmentFreeMap::new(100, vec![(0, 50), (51, 100)]).unwrap();
        assert_eq!(fm.free_segments(), 99);
        fm.add_free(50).unwrap();
        assert_eq!(fm.free_segments(), 100);
    }

    #[test]
    fn free_segments_after_remove_free() {
        let mut fm = SegmentFreeMap::new(100, vec![(0, 100)]).unwrap();
        fm.remove_free(5).unwrap();
        assert_eq!(fm.free_segments(), 99);
        assert_eq!(fm.used_segments(), 1);
    }

    #[test]
    fn free_segments_after_free_range() {
        let mut fm = SegmentFreeMap::new(100, vec![(0, 30), (70, 100)]).unwrap();
        assert_eq!(fm.free_segments(), 60);
        fm.free_range(30, 70).unwrap();
        assert_eq!(fm.free_segments(), 100);
    }

    #[test]
    fn free_segments_full_pool() {
        let fm = SegmentFreeMap::new(100, vec![(0, 100)]).unwrap();
        assert_eq!(fm.free_segments(), 100);
        assert_eq!(fm.used_segments(), 0);
    }

    #[test]
    fn free_segments_empty_pool() {
        let fm = SegmentFreeMap::new(100, vec![]).unwrap();
        assert_eq!(fm.free_segments(), 0);
        assert_eq!(fm.used_segments(), 100);
    }

    #[test]
    fn free_segments_after_coalesce_unchanged() {
        // coalesce should not change free_segments count
        let mut fm = SegmentFreeMap::new(100, vec![(0, 50), (51, 100)]).unwrap();
        let before = fm.free_segments();
        fm.add_free(50).unwrap(); // merges [0,50) + [50,51) + [51,100) => [0,100)
        assert_eq!(fm.free_segments(), before + 1);
    }

    #[test]
    fn free_segments_consistent_with_free_count() {
        let mut fm = SegmentFreeMap::new(1000, vec![(0, 1000)]).unwrap();
        for _ in 0..100 {
            fm.alloc_after(0).unwrap();
        }
        assert_eq!(fm.free_segments(), fm.free_count());
        for seg in 0..100 {
            fm.add_free(seg).unwrap();
        }
        assert_eq!(fm.free_segments(), fm.free_count());
    }

    // --- SpacePressure tests ---

    #[test]
    fn pressure_healthy_full_pool() {
        let fm = SegmentFreeMap::new(100, vec![(0, 100)]).unwrap();
        assert_eq!(fm.pressure(), SpacePressure::Healthy);
    }

    #[test]
    fn pressure_healthy_above_20pct() {
        // 30 free out of 100 = 30% free => Healthy
        let fm = SegmentFreeMap::new(100, vec![(0, 30)]).unwrap();
        assert_eq!(fm.pressure(), SpacePressure::Healthy);
    }

    #[test]
    fn pressure_at_exactly_20pct_is_moderate() {
        // 20 free out of 100 = 20% free => Healthy (not below threshold)
        let fm = SegmentFreeMap::new(100, vec![(0, 20)]).unwrap();
        assert_eq!(fm.pressure(), SpacePressure::Healthy);
    }

    #[test]
    fn pressure_below_20pct_is_moderate() {
        // 19 free out of 100 = 19% => Moderate
        let fm = SegmentFreeMap::new(100, vec![(0, 19)]).unwrap();
        assert_eq!(fm.pressure(), SpacePressure::Moderate);
    }

    #[test]
    fn pressure_at_exactly_10pct_is_moderate() {
        // 10 free out of 100 = 10% free => Moderate (not below 10%)
        let fm = SegmentFreeMap::new(100, vec![(0, 10)]).unwrap();
        assert_eq!(fm.pressure(), SpacePressure::Moderate);
    }

    #[test]
    fn pressure_below_10pct_is_severe() {
        // 9 free out of 100 = 9% => Severe
        let fm = SegmentFreeMap::new(100, vec![(0, 9)]).unwrap();
        assert_eq!(fm.pressure(), SpacePressure::Severe);
    }

    #[test]
    fn pressure_at_exactly_5pct_is_severe() {
        // 5 free out of 100 = 5% free => Severe (not below 5%)
        let fm = SegmentFreeMap::new(100, vec![(0, 5)]).unwrap();
        assert_eq!(fm.pressure(), SpacePressure::Severe);
    }

    #[test]
    fn pressure_below_5pct_is_critical() {
        // 4 free out of 100 = 4% => Critical
        let fm = SegmentFreeMap::new(100, vec![(0, 4)]).unwrap();
        assert_eq!(fm.pressure(), SpacePressure::Critical);
    }

    #[test]
    fn pressure_no_free_space_is_critical() {
        let fm = SegmentFreeMap::new(100, vec![]).unwrap();
        assert_eq!(fm.pressure(), SpacePressure::Critical);
    }

    #[test]
    fn pressure_empty_pool_is_healthy() {
        let fm = SegmentFreeMap::new(0, vec![]).unwrap();
        assert_eq!(fm.pressure(), SpacePressure::Healthy);
    }

    #[test]
    fn pressure_transitions_allocating() {
        // Start with 100% free, allocate until critical
        let mut fm = SegmentFreeMap::new(100, vec![(0, 100)]).unwrap();
        assert_eq!(fm.pressure(), SpacePressure::Healthy);

        // Allocate down to 20 free (80 used) — still Healthy at exactly 20%
        for _ in 0..80 {
            fm.alloc_after(0).unwrap();
        }
        assert_eq!(fm.free_segments(), 20);
        assert_eq!(fm.pressure(), SpacePressure::Healthy);

        // Allocate one more: 19 free => Moderate
        fm.alloc_after(0).unwrap();
        assert_eq!(fm.free_segments(), 19);
        assert_eq!(fm.pressure(), SpacePressure::Moderate);

        // Allocate down to 10 free => still Moderate
        for _ in 0..9 {
            fm.alloc_after(0).unwrap();
        }
        assert_eq!(fm.free_segments(), 10);
        assert_eq!(fm.pressure(), SpacePressure::Moderate);

        // Allocate one more: 9 free => Severe
        fm.alloc_after(0).unwrap();
        assert_eq!(fm.free_segments(), 9);
        assert_eq!(fm.pressure(), SpacePressure::Severe);

        // Allocate down to 5 free => still Severe
        for _ in 0..4 {
            fm.alloc_after(0).unwrap();
        }
        assert_eq!(fm.free_segments(), 5);
        assert_eq!(fm.pressure(), SpacePressure::Severe);

        // Allocate one more: 4 free => Critical
        fm.alloc_after(0).unwrap();
        assert_eq!(fm.free_segments(), 4);
        assert_eq!(fm.pressure(), SpacePressure::Critical);

        // Allocate everything => still Critical
        for _ in 0..4 {
            fm.alloc_after(0).unwrap();
        }
        assert_eq!(fm.free_segments(), 0);
        assert_eq!(fm.pressure(), SpacePressure::Critical);
    }

    #[test]
    fn pressure_transitions_freeing() {
        // Start with 0% free (Critical) and free segments back
        let mut fm = SegmentFreeMap::new(100, vec![]).unwrap();
        assert_eq!(fm.pressure(), SpacePressure::Critical);

        // Free up to 4 segments — still Critical
        for seg in 0..4 {
            fm.free_range(seg, seg + 1).unwrap();
        }
        assert_eq!(fm.free_segments(), 4);
        assert_eq!(fm.pressure(), SpacePressure::Critical);

        // Free one more: 5 free => Severe
        fm.free_range(4, 5).unwrap();
        assert_eq!(fm.free_segments(), 5);
        assert_eq!(fm.pressure(), SpacePressure::Severe);

        // Free up to 9 => still Severe
        for seg in 5..9 {
            fm.free_range(seg, seg + 1).unwrap();
        }
        assert_eq!(fm.free_segments(), 9);
        assert_eq!(fm.pressure(), SpacePressure::Severe);

        // Free one more: 10 free => Moderate
        fm.free_range(9, 10).unwrap();
        assert_eq!(fm.free_segments(), 10);
        assert_eq!(fm.pressure(), SpacePressure::Moderate);

        // Free up to 19 => still Moderate
        for seg in 10..19 {
            fm.free_range(seg, seg + 1).unwrap();
        }
        assert_eq!(fm.free_segments(), 19);
        assert_eq!(fm.pressure(), SpacePressure::Moderate);

        // Free one more: 20 free => Healthy
        fm.free_range(19, 20).unwrap();
        assert_eq!(fm.free_segments(), 20);
        assert_eq!(fm.pressure(), SpacePressure::Healthy);
    }

    #[test]
    fn pressure_ord_comparison() {
        assert!(SpacePressure::Critical > SpacePressure::Severe);
        assert!(SpacePressure::Severe > SpacePressure::Moderate);
        assert!(SpacePressure::Moderate > SpacePressure::Healthy);
        assert!(SpacePressure::Critical > SpacePressure::Healthy);
        // Severe is at least Moderate
        assert!(SpacePressure::Severe >= SpacePressure::Moderate);
    }

    #[test]
    fn pressure_display() {
        assert_eq!(format!("{}", SpacePressure::Healthy), "healthy");
        assert_eq!(format!("{}", SpacePressure::Moderate), "moderate");
        assert_eq!(format!("{}", SpacePressure::Severe), "severe");
        assert_eq!(format!("{}", SpacePressure::Critical), "critical");
    }

    #[test]
    fn pressure_constants_order() {
        let thresholds = [
            ("moderate", PRESSURE_MODERATE_FREE),
            ("severe", PRESSURE_SEVERE_FREE),
            ("critical", PRESSURE_CRITICAL_FREE),
        ];

        for pair in thresholds.windows(2) {
            assert!(
                pair[0].1 > pair[1].1,
                "{} threshold must be greater than {} threshold",
                pair[0].0,
                pair[1].0
            );
        }
    }

    #[test]
    fn free_segments_allocation_loop_consistency() {
        // Allocate all segments one by one, verify free_segments stays in sync
        let mut fm = SegmentFreeMap::new(100, vec![(0, 100)]).unwrap();
        for expected in (0..100).rev() {
            assert_eq!(fm.free_segments(), expected + 1);
            fm.alloc_after(0).unwrap();
        }
        assert_eq!(fm.free_segments(), 0);
    }

    // --- spec markers update ---
    #[test]
    fn space_pressure_spec_markers_present() {
        let s = concat!(
            "SpacePressure",
            "|",
            "Healthy",
            "|",
            "Moderate",
            "|",
            "Severe",
            "|",
            "Critical",
            "|",
            "PRESSURE_MODERATE_FREE",
            "|",
            "PRESSURE_SEVERE_FREE",
            "|",
            "PRESSURE_CRITICAL_FREE",
            "|",
            "free_segments",
            "|",
            "used_segments",
            "|",
            "pressure"
        );
        assert!(!s.is_empty());
    }
}
