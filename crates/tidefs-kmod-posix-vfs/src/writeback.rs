//! Writeback tracking for the kernel VFS adapter.
//!
//! Provides [`DirtyFolioTracker`] for the Rust address-space source model.
//! The mounted Linux 7.0 product path does not register this tracker from C:
//! `dirty_folio` uses Linux dirty accounting and `writepages` walks dirty
//! folios through the C `address_space_operations` table. Keep this tracker
//! as a fail-closed/model helper until a direct C-to-Rust writeback bridge is
//! registered and proven.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;
use crate::TideVec as Vec;

use tidefs_kmod_bridge::kernel_types::{Errno, InodeId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirtyRange {
    pub offset: u64,
    pub length: u32,
}

impl DirtyRange {
    pub const fn new(offset: u64, length: u32) -> Self {
        Self { offset, length }
    }
    pub const fn end(self) -> u64 {
        self.offset.saturating_add(self.length as u64)
    }
    fn touches(self, other: DirtyRange) -> bool {
        let se = self.end();
        let oe = other.end();
        self.offset <= oe && other.offset <= se
    }
}

#[derive(Clone, Debug)]
pub struct DirtyFolioTracker {
    entries: Vec<(InodeId, DirtyRange)>,
    max_entries: usize,
}

impl DirtyFolioTracker {
    pub const fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
        }
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn capacity(&self) -> usize {
        self.max_entries
    }

    /// Register a dirty byte range for the given inode.
    ///
    /// Ranges that touch existing tracked ranges are merged.  When the
    /// tracker is at capacity, the entry with the smallest offset for the
    /// same inode (or the globally-smallest (inode, offset) entry) is
    /// evicted to make room. Product-facing paths that must fail closed
    /// instead of evicting dirty state should use [`Self::try_add`].
    pub fn add(&mut self, inode: InodeId, offset: u64, length: u32) {
        let _ = self.insert_range(inode, offset, length, true);
    }

    /// Register a dirty byte range without evicting existing dirty state.
    pub fn try_add(&mut self, inode: InodeId, offset: u64, length: u32) -> Result<(), Errno> {
        self.insert_range(inode, offset, length, false)
    }

    fn insert_range(
        &mut self,
        inode: InodeId,
        offset: u64,
        length: u32,
        allow_evict: bool,
    ) -> Result<(), Errno> {
        if length == 0 {
            return Ok(());
        }
        let mut merged = DirtyRange::new(offset, length);
        let mut indices: Vec<usize> = Vec::new(); // overlapped entry positions
        for (idx, (ino, existing)) in self.entries.iter().enumerate() {
            if *ino == inode && existing.touches(merged) {
                let no = merged.offset.min(existing.offset);
                let ne = merged.end().max(existing.end());
                merged = DirtyRange::new(no, (ne - no) as u32);
                indices.push(idx);
            }
        }

        let merged_len = self.entries.len().saturating_sub(indices.len()) + 1;
        if !allow_evict && merged_len > self.max_entries {
            return Err(Errno::ENOSPC);
        }

        // Remove overlapped entries first (they are being merged).
        indices.sort_unstable();
        for &idx in indices.iter().rev() {
            self.entries.remove(idx);
        }

        // Make room if we are at capacity.
        if allow_evict && self.max_entries == 0 {
            return Ok(());
        }
        while self.entries.len() >= self.max_entries {
            // Prefer evicting an entry for the same inode; fall back to
            // the globally-smallest (inode, offset) entry.
            let evict = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, (ino, _))| *ino == inode)
                .min_by_key(|(_, (_, r))| r.offset)
                .map(|(i, _)| i)
                .unwrap_or(0);
            self.entries.remove(evict);
        }

        // Insert at sorted (inode, offset) position.
        let pos = self
            .entries
            .binary_search_by(|(ino_existing, r)| {
                ino_existing
                    .cmp(&inode)
                    .then_with(|| r.offset.cmp(&merged.offset))
            })
            .err()
            .unwrap_or(self.entries.len());
        self.entries.insert(pos, (inode, merged));
        Ok(())
    }

    pub fn remove(&mut self, inode: InodeId, offset: u64, length: u32) -> bool {
        if let Some(pos) = self
            .entries
            .iter()
            .position(|(ino, r)| *ino == inode && r.offset == offset && r.length == length)
        {
            self.entries.remove(pos);
            true
        } else {
            false
        }
    }

    pub fn drain_inode(&mut self, inode: InodeId) -> Vec<DirtyRange> {
        let mut ranges = Vec::new();
        self.entries.retain(|(ino, r)| {
            if *ino == inode {
                ranges.push(*r);
                false
            } else {
                true
            }
        });
        ranges
    }

    pub fn clear_inode(&mut self, inode: InodeId) -> usize {
        let before = self.entries.len();
        self.entries.retain(|(ino, _)| *ino != inode);
        before - self.entries.len()
    }

    /// Remove any dirty ranges that overlap with the given byte range.
    ///
    /// Entries that are fully contained within the remove range are
    /// deleted.  Entries that partially overlap are trimmed so the
    /// overlapping portion is removed and the non-overlapping portion
    /// is retained as a separate entry.  This is used by
    /// `invalidate_folio` to prevent writeback of pages the kernel
    /// has already discarded.
    ///
    /// Returns the number of entries that were fully or partially
    /// affected.
    pub fn remove_range(&mut self, inode: InodeId, offset: u64, length: u32) -> usize {
        if length == 0 {
            return 0;
        }
        let remove_end = offset.saturating_add(length as u64);
        let mut affected: usize = 0;
        let mut new_entries: Vec<(InodeId, DirtyRange)> = Vec::new();

        self.entries.retain(|(ino, r)| {
            if *ino != inode {
                return true;
            }
            let entry_end = r.end();
            // No overlap: entry is fully before or fully after the remove range
            if entry_end <= offset || r.offset >= remove_end {
                return true;
            }
            affected += 1;
            // Entry is fully contained within the remove range -- discard it
            if r.offset >= offset && entry_end <= remove_end {
                return false;
            }
            // Partial overlap -- retain the non-overlapping portion(s)
            // Keep left portion (before the remove range)
            if r.offset < offset {
                let left_len = (offset - r.offset) as u32;
                if left_len > 0 {
                    new_entries.push((inode, DirtyRange::new(r.offset, left_len)));
                }
            }
            // Keep right portion (after the remove range)
            if entry_end > remove_end {
                let right_len = (entry_end - remove_end) as u32;
                if right_len > 0 {
                    new_entries.push((inode, DirtyRange::new(remove_end, right_len)));
                }
            }
            // Entries that were partially overlapping are replaced with
            // trimmed entries; the original overlap is discarded.
            false
        });

        // Insert any trimmed entries back in sorted order.
        for (ino, range) in new_entries {
            let pos = self
                .entries
                .binary_search_by(|(ino_existing, r)| {
                    ino_existing
                        .cmp(&ino)
                        .then_with(|| r.offset.cmp(&range.offset))
                })
                .err()
                .unwrap_or(self.entries.len());
            self.entries.insert(pos, (ino, range));
        }

        affected
    }

    /// Remove all dirty ranges at or beyond `threshold` for the given inode.
    ///
    /// Entries that straddle the threshold are trimmed so only the portion
    /// before `threshold` is retained.  This is used by the truncate-down
    /// path to discard dirty writeback tracking for pages the kernel has
    /// already freed via setattr(FATTR_SIZE) shrink.
    ///
    /// Returns the number of entries that were fully or partially affected.
    pub fn truncate_down(&mut self, inode: InodeId, threshold: u64) -> usize {
        if threshold == 0 {
            // Truncate to zero: remove everything for this inode.
            return self.clear_inode(inode);
        }
        let mut affected: usize = 0;
        let mut trimmed: Vec<(InodeId, DirtyRange)> = Vec::new();
        self.entries.retain(|(ino, r)| {
            if *ino != inode {
                return true;
            }
            if r.offset >= threshold {
                // Entry starts at or beyond threshold -- discard entirely.
                affected += 1;
                return false;
            }
            if r.end() > threshold {
                // Entry straddles threshold -- trim to keep only the
                // portion before the threshold.
                affected += 1;
                let new_len = (threshold - r.offset) as u32;
                trimmed.push((inode, DirtyRange::new(r.offset, new_len)));
                return false;
            }
            true
        });
        // Re-insert trimmed entries in sorted order.
        for (ino, range) in trimmed {
            let pos = self
                .entries
                .binary_search_by(|(ino_existing, r)| {
                    ino_existing
                        .cmp(&ino)
                        .then_with(|| r.offset.cmp(&range.offset))
                })
                .err()
                .unwrap_or(self.entries.len());
            self.entries.insert(pos, (ino, range));
        }
        affected
    }

    pub fn iter(&self) -> impl Iterator<Item = (InodeId, DirtyRange)> + '_ {
        self.entries.iter().map(|(ino, r)| (*ino, *r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ino(id: u64) -> InodeId {
        InodeId::new(id)
    }

    #[test]
    fn range_end() {
        assert_eq!(DirtyRange::new(0, 4096).end(), 4096);
    }
    #[test]
    fn touches_overlap() {
        assert!(DirtyRange::new(0, 4096).touches(DirtyRange::new(2048, 4096)));
    }
    #[test]
    fn touches_adjacent() {
        assert!(DirtyRange::new(0, 4096).touches(DirtyRange::new(4096, 4096)));
    }
    #[test]
    fn touches_no() {
        assert!(!DirtyRange::new(0, 4096).touches(DirtyRange::new(8192, 4096)));
    }
    #[test]
    fn new_empty() {
        let t = DirtyFolioTracker::new(64);
        assert!(t.is_empty());
        assert_eq!(t.capacity(), 64);
    }
    #[test]
    fn add_single() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 4096);
        assert_eq!(t.len(), 1);
    }
    #[test]
    fn add_merge_overlap() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 4096);
        t.add(ino(1), 2048, 4096);
        assert_eq!(t.len(), 1);
        assert_eq!(t.iter().next().unwrap(), (ino(1), DirtyRange::new(0, 6144)));
    }
    #[test]
    fn add_merge_adjacent() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 4096);
        t.add(ino(1), 4096, 4096);
        assert_eq!(t.len(), 1);
        assert_eq!(t.iter().next().unwrap(), (ino(1), DirtyRange::new(0, 8192)));
    }
    #[test]
    fn add_zero_ignored() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 0);
        assert!(t.is_empty());
    }
    #[test]
    fn add_diff_inodes() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 4096);
        t.add(ino(2), 0, 4096);
        assert_eq!(t.len(), 2);
    }
    #[test]
    fn capacity_evicts_oldest() {
        let mut t = DirtyFolioTracker::new(2);
        t.add(ino(1), 0, 4096);
        t.add(ino(1), 8192, 4096);
        t.add(ino(1), 16384, 4096);
        assert_eq!(t.len(), 2);
    }
    #[test]
    fn merge_at_cap() {
        let mut t = DirtyFolioTracker::new(1);
        t.add(ino(1), 0, 4096);
        t.add(ino(1), 4096, 4096);
        assert_eq!(t.len(), 1);
    }
    #[test]
    fn remove_exact() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 4096);
        assert!(t.remove(ino(1), 0, 4096));
        assert!(t.is_empty());
    }
    #[test]
    fn remove_wrong() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 4096);
        assert!(!t.remove(ino(2), 0, 4096));
    }
    #[test]
    fn drain_works() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 4096);
        t.add(ino(1), 8192, 4096);
        t.add(ino(2), 0, 8192);
        assert_eq!(t.drain_inode(ino(1)).len(), 2);
        assert_eq!(t.len(), 1);
    }
    #[test]
    fn clear_count() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 4096);
        t.add(ino(1), 8192, 4096);
        t.add(ino(2), 0, 4096);
        assert_eq!(t.clear_inode(ino(1)), 2);
    }
    #[test]
    fn iter_sorted() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 8192, 4096);
        t.add(ino(1), 0, 4096);
        t.add(ino(2), 0, 4096);
        let v: Vec<_> = t.iter().collect();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], (ino(1), DirtyRange::new(0, 4096)));
        assert_eq!(v[1], (ino(1), DirtyRange::new(8192, 4096)));
        assert_eq!(v[2], (ino(2), DirtyRange::new(0, 4096)));
    }
    #[test]
    fn merge_three() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 4096);
        t.add(ino(1), 8192, 4096);
        t.add(ino(1), 4096, 4096);
        assert_eq!(t.len(), 1);
        assert_eq!(
            t.iter().next().unwrap(),
            (ino(1), DirtyRange::new(0, 12288))
        );
    }

    // -- remove_range tests --

    #[test]
    fn remove_range_fully_contained_removes_entry() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 4096);
        assert_eq!(t.remove_range(ino(1), 0, 4096), 1);
        assert!(t.is_empty());
    }

    #[test]
    fn remove_range_partial_left_overlap_trims_entry() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 8192);
        assert_eq!(t.remove_range(ino(1), 0, 4096), 1);
        assert_eq!(t.len(), 1);
        let ranges: Vec<_> = t.iter().collect();
        assert_eq!(ranges[0], (ino(1), DirtyRange::new(4096, 4096)));
    }

    #[test]
    fn remove_range_partial_right_overlap_trims_entry() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 8192);
        assert_eq!(t.remove_range(ino(1), 4096, 4096), 1);
        assert_eq!(t.len(), 1);
        let ranges: Vec<_> = t.iter().collect();
        assert_eq!(ranges[0], (ino(1), DirtyRange::new(0, 4096)));
    }

    #[test]
    fn remove_range_middle_splits_entry() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 12288);
        assert_eq!(t.remove_range(ino(1), 4096, 4096), 1);
        assert_eq!(t.len(), 2);
        let ranges: Vec<_> = t.iter().collect();
        assert_eq!(ranges[0], (ino(1), DirtyRange::new(0, 4096)));
        assert_eq!(ranges[1], (ino(1), DirtyRange::new(8192, 4096)));
    }

    #[test]
    fn remove_range_no_overlap_noop() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 4096);
        assert_eq!(t.remove_range(ino(1), 8192, 4096), 0);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn remove_range_zero_length_noop() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 4096);
        assert_eq!(t.remove_range(ino(1), 0, 0), 0);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn remove_range_different_inode_not_affected() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 4096);
        t.add(ino(2), 0, 4096);
        assert_eq!(t.remove_range(ino(1), 0, 4096), 1);
        assert_eq!(t.len(), 1);
        let remaining: Vec<_> = t.iter().collect();
        assert_eq!(remaining[0].0, ino(2));
    }

    #[test]
    fn remove_range_multiple_entries() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 4096);
        t.add(ino(1), 8192, 4096);
        assert_eq!(t.remove_range(ino(1), 0, 16384), 2);
        assert!(t.is_empty());
    }

    #[test]
    fn remove_range_returns_affected_count() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 4096);
        t.add(ino(1), 8192, 4096);
        t.add(ino(1), 16384, 4096);
        assert_eq!(t.remove_range(ino(1), 0, 12288), 2);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn remove_range_preserves_sorted_order() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 4096);
        t.add(ino(1), 8192, 4096);
        t.add(ino(1), 16384, 4096);
        t.add(ino(2), 0, 4096);
        t.remove_range(ino(1), 4096, 4096);
        let ranges: Vec<_> = t.iter().collect();
        assert_eq!(ranges.len(), 4);
        let mut prev: Option<(InodeId, u64)> = None;
        for (ino, r) in &ranges {
            if let Some((pino, poff)) = prev {
                assert!(
                    pino < *ino || (pino == *ino && poff <= r.offset),
                    "entries not sorted"
                );
            }
            prev = Some((*ino, r.offset));
        }
    }

    #[test]
    fn remove_range_then_add_merges_correctly() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 12288);
        t.remove_range(ino(1), 4096, 4096);
        assert_eq!(t.len(), 2);
        t.add(ino(1), 2048, 6144);
        assert_eq!(t.len(), 1);
        let ranges: Vec<_> = t.iter().collect();
        assert_eq!(ranges[0], (ino(1), DirtyRange::new(0, 12288)));
    }

    // -- truncate_down tests --

    #[test]
    fn truncate_down_removes_fully_beyond() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 4096);
        t.add(ino(1), 8192, 4096);
        assert_eq!(t.truncate_down(ino(1), 4096), 1);
        assert_eq!(t.len(), 1);
        let ranges: Vec<_> = t.iter().collect();
        assert_eq!(ranges[0], (ino(1), DirtyRange::new(0, 4096)));
    }

    #[test]
    fn truncate_down_trims_straddling() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 8192);
        assert_eq!(t.truncate_down(ino(1), 4096), 1);
        assert_eq!(t.len(), 1);
        let ranges: Vec<_> = t.iter().collect();
        assert_eq!(ranges[0], (ino(1), DirtyRange::new(0, 4096)));
    }

    #[test]
    fn truncate_down_to_zero_clears_all() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 4096);
        t.add(ino(1), 8192, 4096);
        t.add(ino(2), 0, 4096);
        assert_eq!(t.truncate_down(ino(1), 0), 2);
        assert_eq!(t.len(), 1);
        let remaining: Vec<_> = t.iter().collect();
        assert_eq!(remaining[0].0, ino(2));
    }

    #[test]
    fn truncate_down_no_entries_beyond() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 0, 4096);
        assert_eq!(t.truncate_down(ino(1), 8192), 0);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn truncate_down_other_inode_unaffected() {
        let mut t = DirtyFolioTracker::new(64);
        t.add(ino(1), 8192, 4096);
        t.add(ino(2), 0, 4096);
        assert_eq!(t.truncate_down(ino(1), 4096), 1);
        assert_eq!(t.len(), 1);
        let remaining: Vec<_> = t.iter().collect();
        assert_eq!(remaining[0], (ino(2), DirtyRange::new(0, 4096)));
    }
}
