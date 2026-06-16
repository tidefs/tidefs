//! ## Authority Classification (per docs/cache-authority-model.md)
//!
//! This tracker is **Authoritative** for dirty byte ranges awaiting flush to
//! backing storage.  It maintains the exact byte ranges that the writeback
//! flush path needs.  The parallel DirtyPageTracker in page_cache/mod.rs is a
//! Derived shadow used for per-page tracking and reclaim eligibility.
//!
// dirty_page_tracker.rs — per-inode dirty-page range tracking
//
// Tracks (inode, offset, length) dirty ranges for buffered writes that
// have not yet been flushed.  Coalesces adjacent and overlapping ranges
// so the writeback flush path submits the minimum number of I/Os.
//
// This is complementary to the DirtySet in writeback.rs: DirtySet
// accounts dirty bytes per inode for commit-group durability
// classification; DirtyPageTracker maintains the exact byte ranges
// needed for the flush path.

use std::collections::BTreeMap;
use std::time::Instant;
use tidefs_types_vfs_core::InodeId;

/// A contiguous byte range [offset, offset+length) that is dirty.
#[derive(Clone, Debug)]
pub struct DirtyRange {
    pub offset: u64,
    pub length: u64,
    pub dirty_since: Instant,
}

impl PartialEq for DirtyRange {
    fn eq(&self, other: &Self) -> bool {
        self.offset == other.offset && self.length == other.length
    }
}
impl Eq for DirtyRange {}

impl DirtyRange {
    pub fn new(offset: u64, length: u64) -> Self {
        Self {
            offset,
            length,
            dirty_since: Instant::now(),
        }
    }

    fn end(&self) -> u64 {
        self.offset.saturating_add(self.length)
    }

    #[allow(dead_code)] // INTENT: dirty page tracker types for planned writeback scheduling
    pub fn age(&self) -> std::time::Duration {
        self.dirty_since.elapsed()
    }

    pub fn older_than(&self, threshold: std::time::Duration) -> bool {
        self.dirty_since.elapsed() >= threshold
    }

    fn merge(&self, other: &DirtyRange) -> DirtyRange {
        let start = self.offset.min(other.offset);
        let end = self.end().max(other.end());
        DirtyRange {
            offset: start,
            length: end.saturating_sub(start),
            dirty_since: self.dirty_since.min(other.dirty_since),
        }
    }
}

/// Per-inode dirty-page tracker with range coalescing.
///
/// Each inode maps to a list of non-overlapping, non-adjacent
/// `DirtyRange`s sorted by offset.  `mark_dirty` inserts and
/// coalesces; `flush_inode` removes and returns the dirty set
/// so the writeback path can issue writes.
/// tidefs-queue-root: local_fs.dirty_page_tracker
/// admission: AdmissionPermit  service_curve: ServiceCurve
#[derive(Clone, Debug, Default)]
pub struct DirtyPageTracker {
    ranges: BTreeMap<InodeId, Vec<DirtyRange>>,
}

impl DirtyPageTracker {
    /// Cache authority classification per docs/cache-authority-model.md.
    /// This DirtyPageTracker is Authoritative for dirty byte ranges awaiting flush.
    #[allow(dead_code)]
    pub const CACHE_AUTHORITY_CLASS: &str = "Authoritative";
    /// Return the cache authority classification at runtime.
    #[allow(dead_code)]
    pub fn cache_authority_class(&self) -> &'static str {
        Self::CACHE_AUTHORITY_CLASS
    }

    pub fn new() -> Self {
        Self::default()
    }

    /// Record that bytes [offset, offset+length) are dirty for `inode`.
    ///
    /// Overlapping and adjacent ranges are coalesced so that the flush
    /// path sees the minimum number of contiguous regions.
    pub fn mark_dirty(&mut self, inode: InodeId, offset: u64, length: u64) {
        if length == 0 {
            return;
        }
        let range = DirtyRange::new(offset, length);
        let entry = self.ranges.entry(inode).or_default();
        Self::insert_coalesced(entry, range);
    }

    #[allow(dead_code)] // INTENT: dirty page tracker types for planned writeback scheduling
    /// Flush all dirty ranges for `inode`, returning them in offset order
    /// and removing the inode from the dirty set.  Returns an empty vec
    /// when the inode has no dirty pages.
    pub fn flush_inode(&mut self, inode: InodeId) -> Vec<DirtyRange> {
        self.ranges.remove(&inode).unwrap_or_default()
    }

    /// Capture a snapshot of all dirty ranges for transaction rollback.
    #[must_use]
    pub(crate) fn snapshot_ranges(&self) -> BTreeMap<InodeId, Vec<DirtyRange>> {
        self.ranges.clone()
    }

    /// Restore dirty ranges from a previously captured snapshot.
    pub(crate) fn restore_ranges(&mut self, ranges: BTreeMap<InodeId, Vec<DirtyRange>>) {
        self.ranges = ranges;
    }
    /// Clear dirty tracking for bytes [offset, offset+length) within `inode`.
    /// Ranges that fall entirely outside the cleared span are kept; ranges that
    /// overlap are split or removed so that no dirty byte within
    /// [offset, offset+length) remains tracked.
    /// Returns the number of ranges that were touched (split or removed).
    pub fn clear_range(&mut self, inode: InodeId, offset: u64, length: u64) -> usize {
        if length == 0 {
            return 0;
        }
        let end = offset.saturating_add(length);
        let entry = match self.ranges.get_mut(&inode) {
            Some(v) => v,
            None => return 0,
        };
        let mut touched = 0usize;
        let mut i = 0;
        while i < entry.len() {
            let r_off = entry[i].offset;
            let r_end = entry[i].end();
            if r_end <= offset || r_off >= end {
                // Range is entirely outside the cleared span.
                i += 1;
                continue;
            }
            touched += 1;
            if r_off >= offset && r_end <= end {
                // Range is entirely inside — remove it.
                entry.remove(i);
                continue; // don't advance i; removal shifts remaining left
            }
            if r_off < offset && r_end > end {
                // Range spans the cleared range — split into left + right.
                let right_off = end;
                let right_len = r_end - end;
                entry[i].length = offset - r_off; // left fragment
                entry.insert(i + 1, DirtyRange::new(right_off, right_len));
                i += 2;
                continue;
            }
            if r_off < offset {
                // Left-edge overlap only — truncate right side.
                entry[i].length = offset - r_off;
            } else {
                // Right-edge overlap only — truncate left side.
                entry[i].offset = end;
                entry[i].length = r_end - end;
            }
            i += 1;
        }
        // Prune zero-length ranges that may result from edge cases.
        entry.retain(|r| r.length > 0);
        if entry.is_empty() {
            self.ranges.remove(&inode);
        }
        touched
    }

    #[allow(dead_code)] // INTENT: dirty page tracker types for planned writeback scheduling
    /// Return a snapshot of the dirty ranges for `inode` without clearing.
    pub fn dirty_ranges(&self, inode: InodeId) -> Option<&[DirtyRange]> {
        self.ranges.get(&inode).map(|v| v.as_slice())
    }

    /// Check whether any dirty range for `inode` overlaps
    /// `[offset, offset + length)`.
    pub fn overlaps_range(&self, inode: InodeId, offset: u64, length: u64) -> bool {
        if length == 0 {
            return false;
        }
        let end = offset.saturating_add(length);
        let Some(ranges) = self.ranges.get(&inode) else {
            return false;
        };
        let first_possible = ranges.partition_point(|range| range.end() <= offset);
        ranges
            .get(first_possible)
            .is_some_and(|range| range.offset < end && offset < range.end())
    }

    #[allow(dead_code)] // INTENT: dirty page tracker types for planned writeback scheduling
    /// Check whether `inode` has any dirty pages.
    pub fn is_dirty(&self, inode: InodeId) -> bool {
        self.ranges.get(&inode).is_some_and(|v| !v.is_empty())
    }
    #[allow(dead_code)] // INTENT: dirty page tracker types for planned writeback scheduling
    /// Total number of inodes with at least one dirty page.
    pub fn dirty_inode_count(&self) -> usize {
        self.ranges.len()
    }
    #[allow(dead_code)] // INTENT: dirty page tracker types for planned writeback scheduling
    /// Total number of dirty ranges across all inodes.
    pub fn total_dirty_ranges(&self) -> usize {
        self.ranges.values().map(|v| v.len()).sum()
    }

    pub fn collect_dirty_ranges(&mut self) -> Vec<(InodeId, Vec<DirtyRange>)> {
        let ranges = std::mem::take(&mut self.ranges);
        let mut result: Vec<(InodeId, Vec<DirtyRange>)> = Vec::with_capacity(ranges.len());
        for (inode, ranges) in ranges {
            result.push((inode, ranges));
        }
        result
    }

    // ── private helpers ────────────────────────────────────────────

    /// Insert one range into the sorted non-overlapping set, merging only the
    /// adjacent/overlapping window touched by the new range.
    fn insert_coalesced(ranges: &mut Vec<DirtyRange>, mut range: DirtyRange) {
        let mut start = 0;
        while start < ranges.len() && ranges[start].end() < range.offset {
            start += 1;
        }

        let mut end = start;
        while end < ranges.len() && ranges[end].offset <= range.end() {
            range = range.merge(&ranges[end]);
            end += 1;
        }

        if start == end {
            ranges.insert(start, range);
        } else {
            ranges.splice(start..end, std::iter::once(range));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u64) -> InodeId {
        InodeId::new(n)
    }

    #[test]
    fn single_page_dirty_flush_clean_lifecycle() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(1);

        assert!(!tracker.is_dirty(ino));
        assert_eq!(tracker.dirty_inode_count(), 0);

        tracker.mark_dirty(ino, 0, 4096);

        assert!(tracker.is_dirty(ino));
        assert_eq!(tracker.dirty_inode_count(), 1);
        assert_eq!(
            tracker.dirty_ranges(ino).unwrap(),
            &[DirtyRange::new(0, 4096)]
        );

        let flushed = tracker.flush_inode(ino);
        assert_eq!(flushed, vec![DirtyRange::new(0, 4096)]);
        assert!(!tracker.is_dirty(ino));
        assert_eq!(tracker.dirty_inode_count(), 0);
    }

    #[test]
    fn multi_page_merge_adjacent_ranges() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(2);

        // Two adjacent pages: [0, 4096) + [4096, 4096)
        tracker.mark_dirty(ino, 0, 4096);
        tracker.mark_dirty(ino, 4096, 4096);

        assert_eq!(tracker.total_dirty_ranges(), 1);
        assert_eq!(
            tracker.dirty_ranges(ino).unwrap(),
            &[DirtyRange::new(0, 8192)]
        );
    }

    #[test]
    fn flush_clean_inode_is_noop() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(3);

        let flushed = tracker.flush_inode(ino);
        assert!(flushed.is_empty());
    }

    #[test]
    fn overlapping_write_coalescing_three_writes() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(4);

        // Write 1: [0, 8192)
        tracker.mark_dirty(ino, 0, 8192);
        // Write 2: [4096, 8192) — fully overlaps with write 1
        tracker.mark_dirty(ino, 4096, 8192);
        // Write 3: [12288, 4096) — adjacent to merged [0, 12288)
        tracker.mark_dirty(ino, 12288, 4096);

        assert_eq!(tracker.total_dirty_ranges(), 1);
        assert_eq!(
            tracker.dirty_ranges(ino).unwrap(),
            &[DirtyRange::new(0, 16384)]
        );
    }

    #[test]
    fn flush_ordering_by_offset() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(5);

        // Mark dirty out of offset order
        tracker.mark_dirty(ino, 16384, 4096); // high offset
        tracker.mark_dirty(ino, 0, 4096); // low offset
        tracker.mark_dirty(ino, 8192, 4096); // middle offset

        let flushed = tracker.flush_inode(ino);
        // Should be returned in offset order
        assert_eq!(flushed.len(), 3);
        assert_eq!(flushed[0].offset, 0);
        assert_eq!(flushed[1].offset, 8192);
        assert_eq!(flushed[2].offset, 16384);
    }

    #[test]
    fn multiple_inodes_independent_tracking() {
        let mut tracker = DirtyPageTracker::new();
        let a = id(10);
        let b = id(20);

        tracker.mark_dirty(a, 0, 4096);
        tracker.mark_dirty(b, 0, 8192);

        assert_eq!(tracker.dirty_inode_count(), 2);
        assert!(tracker.is_dirty(a));
        assert!(tracker.is_dirty(b));

        // Flush only a
        let flushed_a = tracker.flush_inode(a);
        assert_eq!(flushed_a.len(), 1);
        assert!(!tracker.is_dirty(a));
        assert!(tracker.is_dirty(b));
        assert_eq!(tracker.dirty_inode_count(), 1);
    }

    #[test]
    fn mark_dirty_then_dirty_again_after_flush() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(6);

        tracker.mark_dirty(ino, 0, 4096);
        let _ = tracker.flush_inode(ino);
        assert!(!tracker.is_dirty(ino));

        tracker.mark_dirty(ino, 0, 4096);
        assert!(tracker.is_dirty(ino));
        assert_eq!(tracker.dirty_ranges(ino).unwrap().len(), 1);
    }

    #[test]
    fn disjoint_ranges_kept_separate() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(7);

        tracker.mark_dirty(ino, 0, 4096);
        tracker.mark_dirty(ino, 8192, 4096); // gap at 4096-8192

        assert_eq!(tracker.total_dirty_ranges(), 2);
        let ranges = tracker.dirty_ranges(ino).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].offset, 0);
        assert_eq!(ranges[1].offset, 8192);
    }

    #[test]
    fn bridging_write_fills_gap() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(8);

        tracker.mark_dirty(ino, 0, 4096);
        tracker.mark_dirty(ino, 8192, 4096);
        assert_eq!(tracker.total_dirty_ranges(), 2);

        // This write bridges the gap at 4096
        tracker.mark_dirty(ino, 4096, 4096);

        assert_eq!(tracker.total_dirty_ranges(), 1);
        assert_eq!(
            tracker.dirty_ranges(ino).unwrap(),
            &[DirtyRange::new(0, 12288)]
        );
    }

    #[test]
    fn zero_length_write_noop() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(9);

        tracker.mark_dirty(ino, 4096, 0);
        assert!(!tracker.is_dirty(ino));
        assert_eq!(tracker.total_dirty_ranges(), 0);
        assert!(tracker.dirty_ranges(ino).is_none());
    }

    #[test]
    fn large_offset_no_overflow() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(11);

        tracker.mark_dirty(ino, u64::MAX - 4096, 4096);
        assert!(tracker.is_dirty(ino));
        assert_eq!(tracker.total_dirty_ranges(), 1);
    }

    #[test]
    fn saturation_at_u64_limit() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(12);

        tracker.mark_dirty(ino, u64::MAX, 1);
        assert!(tracker.is_dirty(ino));
        // end() should saturate, not overflow
        assert_eq!(tracker.dirty_ranges(ino).unwrap()[0].end(), u64::MAX);
    }
    // ── clear_range tests ─────────────────────────────────────────────

    #[test]
    fn clear_range_entirely_within_single_range() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(20);
        // Mark [0, 16384) dirty, then clear [4096, 4096)
        tracker.mark_dirty(ino, 0, 16384);
        assert_eq!(tracker.total_dirty_ranges(), 1);
        let touched = tracker.clear_range(ino, 4096, 4096);
        assert_eq!(touched, 1);
        // Should split into [0, 4096) and [8192, 8192)
        let ranges = tracker.dirty_ranges(ino).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].offset, 0);
        assert_eq!(ranges[0].length, 4096);
        assert_eq!(ranges[1].offset, 8192);
        assert_eq!(ranges[1].length, 8192);
    }

    #[test]
    fn clear_range_removes_entire_entry_when_fully_covered() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(21);
        tracker.mark_dirty(ino, 0, 4096);
        tracker.mark_dirty(ino, 8192, 4096);
        assert_eq!(tracker.total_dirty_ranges(), 2);
        // Clear [0, 12288) which covers everything
        let touched = tracker.clear_range(ino, 0, 12288);
        assert_eq!(touched, 2);
        assert!(!tracker.is_dirty(ino));
        assert_eq!(tracker.dirty_inode_count(), 0);
    }

    #[test]
    fn clear_range_noop_on_clean_inode() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(22);
        let touched = tracker.clear_range(ino, 0, 4096);
        assert_eq!(touched, 0);
        assert!(!tracker.is_dirty(ino));
    }

    #[test]
    fn clear_range_noop_outside_all_ranges() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(23);
        tracker.mark_dirty(ino, 0, 4096);
        // Clear a span entirely after the dirty range
        let touched = tracker.clear_range(ino, 8192, 4096);
        assert_eq!(touched, 0);
        assert_eq!(tracker.total_dirty_ranges(), 1);
        assert_eq!(tracker.dirty_ranges(ino).unwrap()[0].offset, 0);
    }

    #[test]
    fn clear_range_left_edge_overlap() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(24);
        tracker.mark_dirty(ino, 4096, 8192); // [4096, 12288)
                                             // Clear [0, 8192) — overlaps left portion of the dirty range
        let touched = tracker.clear_range(ino, 0, 8192);
        assert_eq!(touched, 1);
        let ranges = tracker.dirty_ranges(ino).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].offset, 8192);
        assert_eq!(ranges[0].length, 4096);
    }

    #[test]
    fn clear_range_right_edge_overlap() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(25);
        tracker.mark_dirty(ino, 4096, 8192); // [4096, 12288)
                                             // Clear [8192, 8192) — overlaps right portion
        let touched = tracker.clear_range(ino, 8192, 8192);
        assert_eq!(touched, 1);
        let ranges = tracker.dirty_ranges(ino).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].offset, 4096);
        assert_eq!(ranges[0].length, 4096);
    }

    #[test]
    fn clear_range_splits_spanning_range() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(26);
        tracker.mark_dirty(ino, 0, 16384); // [0, 16384)
                                           // Clear [4096, 8192) — splits the dirty range into two
        let touched = tracker.clear_range(ino, 4096, 8192);
        assert_eq!(touched, 1);
        let ranges = tracker.dirty_ranges(ino).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].offset, 0);
        assert_eq!(ranges[0].length, 4096);
        assert_eq!(ranges[1].offset, 12288);
        assert_eq!(ranges[1].length, 4096);
    }

    #[test]
    fn clear_range_multiple_disjoint_dirty_ranges() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(27);
        tracker.mark_dirty(ino, 0, 4096);
        tracker.mark_dirty(ino, 8192, 4096);
        tracker.mark_dirty(ino, 16384, 4096);
        // Clear [4096, 8192) which touches the gap but also the start of
        // the second range
        let touched = tracker.clear_range(ino, 4096, 8192);
        assert_eq!(touched, 1); // only the middle range is touched
        let ranges = tracker.dirty_ranges(ino).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].offset, 0);
        assert_eq!(ranges[1].offset, 16384);
    }

    #[test]
    fn clear_range_zero_length_is_noop() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(28);
        tracker.mark_dirty(ino, 0, 4096);
        let touched = tracker.clear_range(ino, 2048, 0);
        assert_eq!(touched, 0);
        assert_eq!(tracker.total_dirty_ranges(), 1);
    }

    #[test]
    fn clear_range_then_remark_dirty() {
        let mut tracker = DirtyPageTracker::new();
        let ino = id(29);
        tracker.mark_dirty(ino, 0, 8192);
        // Clear the middle then remark — should be two disjoint ranges
        tracker.clear_range(ino, 2048, 4096);
        assert_eq!(tracker.total_dirty_ranges(), 2);
        // Remark dirty in the cleared range
        tracker.mark_dirty(ino, 2048, 4096);
        // Should bridge the gap back to one range
        assert_eq!(tracker.total_dirty_ranges(), 1);
        assert_eq!(
            tracker.dirty_ranges(ino).unwrap(),
            &[DirtyRange::new(0, 8192)]
        );
    }

    #[test]
    fn clear_range_fully_removes_inode_from_map() {
        let mut tracker = DirtyPageTracker::new();
        let a = id(30);
        let b = id(31);
        tracker.mark_dirty(a, 0, 4096);
        tracker.mark_dirty(b, 0, 4096);
        assert_eq!(tracker.dirty_inode_count(), 2);

        tracker.clear_range(a, 0, 4096);
        assert_eq!(tracker.dirty_inode_count(), 1);
        assert!(!tracker.is_dirty(a));
        assert!(tracker.is_dirty(b));
        assert!(!tracker.ranges.contains_key(&a));
    }

    #[test]
    fn overlaps_range_reports_target_inode_only() {
        let mut tracker = DirtyPageTracker::new();
        let a = id(40);
        let b = id(41);
        tracker.mark_dirty(a, 4096, 4096);
        tracker.mark_dirty(a, 16384, 4096);
        tracker.mark_dirty(b, 0, 4096);

        assert!(!tracker.overlaps_range(a, 0, 4096));
        assert!(tracker.overlaps_range(a, 4095, 2));
        assert!(tracker.overlaps_range(a, 8191, 2));
        assert!(!tracker.overlaps_range(a, 8192, 4096));
        assert!(tracker.overlaps_range(a, 16384, 1));
        assert!(!tracker.overlaps_range(a, 0, 0));
        assert!(!tracker.overlaps_range(b, 4096, 4096));
        assert!(!tracker.overlaps_range(id(999), 0, 4096));
    }
}
