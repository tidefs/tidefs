//! Dirty-page and dirty-metadata tracker.
//!
//! `DirtyTracker` maintains per-inode dirty byte ranges (coalesced into
//! non-overlapping, sorted intervals) and per-inode dirty-metadata
//! bitflags. It is the authoritative in-memory record of what has been
//! mutated since the last committed transaction group.

use std::collections::BTreeMap;

use crate::types::{DirtyMetaFlags, DirtyRange};

/// Maximum number of dirty intervals per inode before we give up and
/// mark the entire inode dirty from offset 0 to `u64::MAX`.
const MAX_DIRTY_INTERVALS: usize = 256;

/// Per-inode dirty state.
#[derive(Clone, Debug, Default)]
struct InodeDirty {
    /// Non-overlapping, sorted dirty byte intervals.
    /// If `overflow` is true, this vec is ignored and the entire inode
    /// is considered dirty.
    intervals: Vec<DirtyInterval>,
    /// When true, the inode is "fully dirty" (intervals overflowed).
    overflow: bool,
    /// Dirty metadata flags.
    meta_flags: DirtyMetaFlags,
}

/// A single dirty byte interval: `[start, end)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirtyInterval {
    start: u64,
    end: u64,
}

impl DirtyInterval {
    fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    fn overlaps_or_adjacent(&self, other: &Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    fn merge(&mut self, other: &Self) {
        self.start = self.start.min(other.start);
        self.end = self.end.max(other.end);
    }
}

// ---------------------------------------------------------------------------
// DirtyTracker
// ---------------------------------------------------------------------------

/// Tracks dirty pages and dirty metadata for all inodes.
///
/// Thread-compatible (single-threaded by design — commit_group serializes all
/// writes through the accumulator lock).
#[derive(Clone, Debug, Default)]
pub struct DirtyTracker {
    inodes: BTreeMap<u64, InodeDirty>,
}

impl DirtyTracker {
    /// Create an empty dirty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inodes: BTreeMap::new(),
        }
    }

    /// Mark a byte range `[offset, offset+len)` as dirty on `ino`.
    ///
    /// Adjacent and overlapping ranges are coalesced. If the number of
    /// intervals exceeds `MAX_DIRTY_INTERVALS`, the entire inode is
    /// marked dirty (overflow).
    pub fn mark_dirty(&mut self, ino: u64, offset: u64, len: u64) {
        if len == 0 {
            return;
        }
        let new_iv = DirtyInterval::new(offset, offset.saturating_add(len));
        let entry = self.inodes.entry(ino).or_default();

        if entry.overflow {
            return;
        }

        // Insert and coalesce.
        Self::insert_interval(&mut entry.intervals, new_iv);

        if entry.intervals.len() > MAX_DIRTY_INTERVALS {
            entry.intervals.clear();
            entry.overflow = true;
        }
    }

    /// Mark metadata flags as dirty on `ino`.
    pub fn mark_meta_dirty(&mut self, ino: u64, flags: DirtyMetaFlags) {
        self.inodes.entry(ino).or_default().meta_flags.insert(flags);
    }

    /// Clear all dirty state for `ino`.
    pub fn clear_dirty(&mut self, ino: u64) {
        if let Some(entry) = self.inodes.get_mut(&ino) {
            entry.intervals.clear();
            entry.overflow = false;
            entry.meta_flags.clear();
        }
    }

    /// Remove all dirty tracking for `ino` (e.g. after unlink).
    pub fn remove_inode(&mut self, ino: u64) {
        self.inodes.remove(&ino);
    }

    /// Return the set of inode numbers that have any dirty state.
    #[must_use]
    pub fn dirty_inodes(&self) -> Vec<u64> {
        self.inodes
            .iter()
            .filter(|(_, d)| d.overflow || !d.intervals.is_empty() || d.meta_flags.is_dirty())
            .map(|(&ino, _)| ino)
            .collect()
    }

    /// Return the dirty byte ranges for `ino`.
    ///
    /// If the inode overflowed, returns a single range `[0, u64::MAX)`.
    /// If the inode has no dirty data, returns an empty vec.
    #[must_use]
    pub fn dirty_ranges(&self, ino: u64) -> Vec<DirtyRange> {
        match self.inodes.get(&ino) {
            Some(entry) if entry.overflow => {
                vec![DirtyRange::new(ino, 0, u64::MAX)]
            }
            Some(entry) => entry
                .intervals
                .iter()
                .map(|iv| DirtyRange::new(ino, iv.start, iv.end.saturating_sub(iv.start)))
                .collect(),
            None => vec![],
        }
    }

    /// Return the dirty metadata flags for `ino`.
    #[must_use]
    pub fn dirty_meta(&self, ino: u64) -> DirtyMetaFlags {
        self.inodes
            .get(&ino)
            .map(|d| d.meta_flags)
            .unwrap_or(DirtyMetaFlags::NONE)
    }

    /// Returns `true` if `ino` has any dirty data.
    #[must_use]
    pub fn has_dirty_data(&self, ino: u64) -> bool {
        self.inodes
            .get(&ino)
            .is_some_and(|d| d.overflow || !d.intervals.is_empty())
    }

    /// Returns `true` if `ino` has any dirty metadata.
    #[must_use]
    pub fn has_dirty_meta(&self, ino: u64) -> bool {
        self.dirty_meta(ino).is_dirty()
    }

    /// Returns the total number of inodes with dirty state.
    #[must_use]
    pub fn dirty_inode_count(&self) -> usize {
        self.inodes
            .iter()
            .filter(|(_, d)| d.overflow || !d.intervals.is_empty() || d.meta_flags.is_dirty())
            .count()
    }

    /// Returns `true` if there is no dirty state at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.dirty_inode_count() == 0
    }

    // -----------------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------------

    /// Insert an interval into a sorted, non-overlapping interval list,
    /// coalescing as needed.
    fn insert_interval(intervals: &mut Vec<DirtyInterval>, new_iv: DirtyInterval) {
        // Find insertion point.
        let mut i = 0;
        while i < intervals.len() && intervals[i].end < new_iv.start {
            i += 1;
        }

        // i is now the index of the first interval that overlaps or
        // comes after new_iv. Insert and merge rightwards.
        intervals.insert(i, new_iv);

        // Merge forward: while the current interval overlaps or is
        // adjacent to the next, merge them.
        while i + 1 < intervals.len() {
            let cur = intervals[i];
            let nxt = intervals[i + 1];
            if cur.overlaps_or_adjacent(&nxt) {
                intervals[i].merge(&nxt);
                intervals.remove(i + 1);
            } else {
                break;
            }
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
    fn empty_tracker() {
        let dt = DirtyTracker::new();
        assert!(dt.is_empty());
        assert_eq!(dt.dirty_inode_count(), 0);
        assert_eq!(dt.dirty_inodes(), Vec::<u64>::new());
    }

    #[test]
    fn mark_single_range() {
        let mut dt = DirtyTracker::new();
        dt.mark_dirty(1, 0, 4096);
        assert!(dt.has_dirty_data(1));
        assert!(!dt.has_dirty_meta(1));
        assert_eq!(dt.dirty_inodes(), vec![1]);
        let ranges = dt.dirty_ranges(1);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].offset, 0);
        assert_eq!(ranges[0].len, 4096);
    }

    #[test]
    fn mark_zero_len_is_noop() {
        let mut dt = DirtyTracker::new();
        dt.mark_dirty(1, 100, 0);
        assert!(dt.is_empty());
    }

    #[test]
    fn coalesce_adjacent() {
        let mut dt = DirtyTracker::new();
        dt.mark_dirty(1, 0, 4096);
        dt.mark_dirty(1, 4096, 4096);
        let ranges = dt.dirty_ranges(1);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].offset, 0);
        assert_eq!(ranges[0].len, 8192);
    }

    #[test]
    fn coalesce_overlapping() {
        let mut dt = DirtyTracker::new();
        dt.mark_dirty(1, 0, 8192);
        dt.mark_dirty(1, 4096, 8192);
        let ranges = dt.dirty_ranges(1);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].offset, 0);
        assert_eq!(ranges[0].len, 12288);
    }

    #[test]
    fn disjoint_ranges() {
        let mut dt = DirtyTracker::new();
        dt.mark_dirty(1, 0, 4096);
        dt.mark_dirty(1, 16384, 4096);
        let ranges = dt.dirty_ranges(1);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].offset, 0);
        assert_eq!(ranges[0].len, 4096);
        assert_eq!(ranges[1].offset, 16384);
        assert_eq!(ranges[1].len, 4096);
    }

    #[test]
    fn three_way_merge() {
        let mut dt = DirtyTracker::new();
        dt.mark_dirty(1, 0, 4096);
        dt.mark_dirty(1, 12288, 4096);
        // bridge the gap
        dt.mark_dirty(1, 4096, 8192);
        let ranges = dt.dirty_ranges(1);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].offset, 0);
        assert_eq!(ranges[0].len, 16384);
    }

    #[test]
    fn clear_dirty() {
        let mut dt = DirtyTracker::new();
        dt.mark_dirty(1, 0, 4096);
        dt.mark_meta_dirty(1, DirtyMetaFlags::SIZE);
        assert!(!dt.is_empty());
        dt.clear_dirty(1);
        assert!(dt.is_empty());
        assert!(!dt.has_dirty_data(1));
        assert!(!dt.has_dirty_meta(1));
    }

    #[test]
    fn remove_inode() {
        let mut dt = DirtyTracker::new();
        dt.mark_dirty(1, 0, 4096);
        dt.mark_dirty(2, 0, 8192);
        dt.remove_inode(1);
        assert_eq!(dt.dirty_inodes(), vec![2]);
        assert!(dt.dirty_ranges(1).is_empty());
    }

    #[test]
    fn meta_flags_independent() {
        let mut dt = DirtyTracker::new();
        dt.mark_meta_dirty(1, DirtyMetaFlags::SIZE | DirtyMetaFlags::MTIME);
        assert!(dt.has_dirty_meta(1));
        assert!(!dt.has_dirty_data(1));
        assert_eq!(dt.dirty_inodes(), vec![1]);
        let flags = dt.dirty_meta(1);
        assert!(flags.contains(DirtyMetaFlags::SIZE));
        assert!(flags.contains(DirtyMetaFlags::MTIME));
        assert!(!flags.contains(DirtyMetaFlags::CTIME));
    }

    #[test]
    fn overflow_marks_entire_inode_dirty() {
        let mut dt = DirtyTracker::new();
        // Create MAX_DIRTY_INTERVALS + 1 disjoint intervals.
        for i in 0..=MAX_DIRTY_INTERVALS {
            dt.mark_dirty(1, (i as u64) * 8192 * 2, 4096);
        }
        let ranges = dt.dirty_ranges(1);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].offset, 0);
        assert_eq!(ranges[0].len, u64::MAX);
    }

    #[test]
    fn multiple_inodes() {
        let mut dt = DirtyTracker::new();
        dt.mark_dirty(1, 0, 4096);
        dt.mark_dirty(2, 8192, 4096);
        dt.mark_dirty(3, 16384, 4096);
        let mut inodes = dt.dirty_inodes();
        inodes.sort();
        assert_eq!(inodes, vec![1, 2, 3]);
        assert_eq!(dt.dirty_inode_count(), 3);
    }
}
