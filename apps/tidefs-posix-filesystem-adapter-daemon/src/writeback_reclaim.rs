// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Writeback-aware inode cache with reclaim support for the POSIX
//! filesystem adapter daemon.
//!
//! Tracks inode dirty/clean state and provides deterministic reclaim
//! that never evicts dirty or pinned entries before they are flushed.

use std::collections::BTreeMap;

/// Entry in the writeback-aware inode cache.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InodeCacheEntry {
    pub ino: u64,
    /// Total dirty bytes pending flush for this inode.
    pub dirty_bytes: u64,
    /// Whether this entry has no dirty data (clean).
    pub clean: bool,
    /// Pinned entries are in active use and must not be reclaimed.
    pub pinned: bool,
}

// Removed #[allow(dead_code)] — now wired into FUSE dispatch path
impl InodeCacheEntry {
    pub fn new(ino: u64) -> Self {
        Self {
            ino,
            dirty_bytes: 0,
            clean: true,
            pinned: false,
        }
    }

    #[allow(dead_code)]
    pub fn is_dirty(&self) -> bool {
        !self.clean && self.dirty_bytes > 0
    }
}

/// A writeback-aware inode cache that supports reclaim of clean entries
/// while protecting dirty inodes from premature eviction.
#[derive(Clone, Debug)]
// Removed #[allow(dead_code)] — now wired into FUSE dispatch path
pub struct WritebackInodeCache {
    entries: BTreeMap<u64, InodeCacheEntry>,
    max_entries: usize,
    reclaim_attempts: usize,
    reclaim_successes: usize,
}

// Removed #[allow(dead_code)] — now wired into FUSE dispatch path
impl WritebackInodeCache {
    /// Create a new cache with the given maximum entry count.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_entries,
            reclaim_attempts: 0,
            reclaim_successes: 0,
        }
    }

    /// Insert or refresh an inode entry. If already present, resets
    /// pinned state but preserves dirty tracking.
    pub fn insert(&mut self, ino: u64) {
        if let Some(entry) = self.entries.get_mut(&ino) {
            entry.pinned = false;
        } else {
            self.entries.insert(ino, InodeCacheEntry::new(ino));
        }
    }

    /// Remove an inode entry from the cache.
    #[allow(dead_code)]
    pub fn remove(&mut self, ino: u64) -> Option<InodeCacheEntry> {
        self.entries.remove(&ino)
    }

    /// Mark an inode as having dirty data pending flush.
    /// Increments the dirty byte count.
    pub fn mark_dirty(&mut self, ino: u64, byte_count: u64) {
        if let Some(entry) = self.entries.get_mut(&ino) {
            entry.dirty_bytes = entry.dirty_bytes.saturating_add(byte_count);
            entry.clean = false;
        }
    }

    /// Mark an inode as clean (all dirty data flushed).
    pub fn mark_clean(&mut self, ino: u64) {
        if let Some(entry) = self.entries.get_mut(&ino) {
            entry.dirty_bytes = 0;
            entry.clean = true;
        }
    }

    /// Pin an inode (mark as in use, preventing reclaim).
    #[allow(dead_code)]
    pub fn pin(&mut self, ino: u64) {
        if let Some(entry) = self.entries.get_mut(&ino) {
            entry.pinned = true;
        }
    }

    /// Unpin an inode (allow reclaim if clean).
    #[allow(dead_code)]
    pub fn unpin(&mut self, ino: u64) {
        if let Some(entry) = self.entries.get_mut(&ino) {
            entry.pinned = false;
        }
    }

    /// Check whether an inode has dirty data.
    /// Returns `None` if the inode is not in the cache.
    #[allow(dead_code)]
    pub fn is_dirty(&self, ino: u64) -> Option<bool> {
        self.entries.get(&ino).map(|e| e.is_dirty())
    }

    /// Total number of entries in the cache.
    #[allow(dead_code)]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Number of dirty entries.
    #[allow(dead_code)]
    pub fn dirty_count(&self) -> usize {
        self.entries.values().filter(|e| e.is_dirty()).count()
    }

    /// Number of clean entries.
    #[allow(dead_code)]
    pub fn clean_count(&self) -> usize {
        self.entries.values().filter(|e| e.clean).count()
    }

    /// Number of pinned entries.
    #[allow(dead_code)]
    pub fn pinned_count(&self) -> usize {
        self.entries.values().filter(|e| e.pinned).count()
    }

    /// Whether the cache is at capacity.
    #[allow(dead_code)]
    pub fn is_full(&self) -> bool {
        self.entries.len() >= self.max_entries
    }

    /// Check if an inode is present in the cache.
    #[allow(dead_code)]
    pub fn contains(&self, ino: u64) -> bool {
        self.entries.contains_key(&ino)
    }

    /// Forcibly evict a specific inode from the cache. Unlike reclaim,
    /// this ignores dirty and pinned state — intended for write/truncate/
    /// rename-driven eviction where the caller knows the inode is stale.
    pub fn invalidate(&mut self, ino: u64) {
        self.entries.remove(&ino);
    }
    ///
    /// Returns the actual number of entries reclaimed. Dirty entries and
    /// pinned entries are never evicted. Clean entries are reclaimed in
    /// insertion order (lowest inode number first, per BTreeMap ordering).
    #[allow(dead_code)]
    pub fn reclaim_clean(&mut self, target_count: usize) -> usize {
        let to_evict: Vec<u64> = self
            .entries
            .iter()
            .filter(|(_, e)| e.clean && !e.pinned)
            .map(|(ino, _)| *ino)
            .take(target_count)
            .collect();

        let reclaimed = to_evict.len();
        for ino in &to_evict {
            self.entries.remove(ino);
        }

        self.reclaim_attempts += target_count;
        self.reclaim_successes += reclaimed;
        reclaimed
    }

    /// Reclaim all reclaimable entries (clean+unpinned) regardless of count.
    /// Returns the number of entries reclaimed.
    #[allow(dead_code)]
    pub fn reclaim_all_clean(&mut self) -> usize {
        let clean_count = self
            .entries
            .values()
            .filter(|e| e.clean && !e.pinned)
            .count();
        self.reclaim_clean(clean_count)
    }

    /// Returns (attempts, successes) reclaim statistics.
    #[allow(dead_code)]
    pub fn reclaim_stats(&self) -> (usize, usize) {
        (self.reclaim_attempts, self.reclaim_successes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_new_is_clean() {
        let entry = InodeCacheEntry::new(42);
        assert!(entry.clean);
        assert_eq!(entry.dirty_bytes, 0);
        assert!(!entry.is_dirty());
        assert!(!entry.pinned);
    }

    #[test]
    fn entry_dirty_bytes_zero_not_dirty() {
        let entry = InodeCacheEntry {
            ino: 1,
            dirty_bytes: 0,
            clean: false,
            pinned: false,
        };
        assert!(!entry.is_dirty());
    }

    #[test]
    fn entry_dirty_bytes_nonzero_is_dirty() {
        let entry = InodeCacheEntry {
            ino: 1,
            dirty_bytes: 4096,
            clean: false,
            pinned: false,
        };
        assert!(entry.is_dirty());
    }

    #[test]
    fn cache_insert_adds_entry() {
        let mut cache = WritebackInodeCache::new(16);
        cache.insert(1);
        assert!(cache.contains(1));
        assert_eq!(cache.entry_count(), 1);
        assert_eq!(cache.clean_count(), 1);
        assert_eq!(cache.dirty_count(), 0);
    }

    #[test]
    fn cache_insert_duplicate_is_idempotent() {
        let mut cache = WritebackInodeCache::new(16);
        cache.insert(1);
        cache.mark_dirty(1, 4096);
        cache.insert(1);
        assert!(cache.contains(1));
        assert_eq!(cache.entry_count(), 1);
        assert!(cache.is_dirty(1).unwrap());
    }

    #[test]
    fn cache_mark_dirty_tracks_bytes() {
        let mut cache = WritebackInodeCache::new(16);
        cache.insert(1);
        cache.mark_dirty(1, 4096);
        assert!(cache.is_dirty(1).unwrap());
        assert!(!cache.entries.get(&1).unwrap().clean);
        assert_eq!(cache.entries.get(&1).unwrap().dirty_bytes, 4096);
    }

    #[test]
    fn cache_mark_dirty_accumulates() {
        let mut cache = WritebackInodeCache::new(16);
        cache.insert(1);
        cache.mark_dirty(1, 4096);
        cache.mark_dirty(1, 2048);
        assert_eq!(cache.entries.get(&1).unwrap().dirty_bytes, 6144);
    }

    #[test]
    fn cache_mark_clean_resets() {
        let mut cache = WritebackInodeCache::new(16);
        cache.insert(1);
        cache.mark_dirty(1, 4096);
        cache.mark_clean(1);
        assert!(!cache.is_dirty(1).unwrap());
        assert_eq!(cache.entries.get(&1).unwrap().dirty_bytes, 0);
        assert!(cache.entries.get(&1).unwrap().clean);
    }

    #[test]
    fn cache_mark_dirty_unknown_inode_noop() {
        let mut cache = WritebackInodeCache::new(16);
        cache.mark_dirty(99, 4096);
        assert_eq!(cache.entry_count(), 0);
    }

    #[test]
    fn cache_remove_entry() {
        let mut cache = WritebackInodeCache::new(16);
        cache.insert(7);
        let removed = cache.remove(7);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().ino, 7);
        assert!(!cache.contains(7));
    }

    #[test]
    fn cache_pin_unpin() {
        let mut cache = WritebackInodeCache::new(16);
        cache.insert(1);
        cache.pin(1);
        assert!(cache.entries.get(&1).unwrap().pinned);
        assert_eq!(cache.pinned_count(), 1);
        cache.unpin(1);
        assert!(!cache.entries.get(&1).unwrap().pinned);
        assert_eq!(cache.pinned_count(), 0);
    }

    #[test]
    fn cache_is_full() {
        let mut cache = WritebackInodeCache::new(3);
        cache.insert(1);
        cache.insert(2);
        assert!(!cache.is_full());
        cache.insert(3);
        assert!(cache.is_full());
    }

    #[test]
    fn reclaim_clean_removes_clean_entries() {
        let mut cache = WritebackInodeCache::new(16);
        for i in 0..10 {
            cache.insert(i);
        }
        assert_eq!(cache.clean_count(), 10);
        let reclaimed = cache.reclaim_clean(5);
        assert_eq!(reclaimed, 5);
        assert_eq!(cache.entry_count(), 5);
        assert_eq!(cache.clean_count(), 5);
    }

    #[test]
    fn reclaim_clean_target_exceeds_available() {
        let mut cache = WritebackInodeCache::new(16);
        cache.insert(1);
        cache.insert(2);
        let reclaimed = cache.reclaim_clean(10);
        assert_eq!(reclaimed, 2);
        assert_eq!(cache.entry_count(), 0);
    }

    #[test]
    fn reclaim_clean_target_zero_does_nothing() {
        let mut cache = WritebackInodeCache::new(16);
        cache.insert(1);
        cache.insert(2);
        let reclaimed = cache.reclaim_clean(0);
        assert_eq!(reclaimed, 0);
        assert_eq!(cache.entry_count(), 2);
    }

    #[test]
    fn reclaim_all_clean_removes_all_clean() {
        let mut cache = WritebackInodeCache::new(16);
        for i in 0..8 {
            cache.insert(i);
        }
        let reclaimed = cache.reclaim_all_clean();
        assert_eq!(reclaimed, 8);
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn reclaim_refuses_dirty_inodes() {
        let mut cache = WritebackInodeCache::new(16);
        cache.insert(1);
        cache.insert(2);
        cache.insert(3);
        cache.mark_dirty(2, 4096);
        assert_eq!(cache.dirty_count(), 1);
        assert_eq!(cache.clean_count(), 2);
        let reclaimed = cache.reclaim_clean(10);
        assert_eq!(reclaimed, 2);
        assert_eq!(cache.entry_count(), 1);
        assert!(cache.contains(2));
        assert!(cache.is_dirty(2).unwrap());
    }

    #[test]
    fn reclaim_refuses_pinned_clean_inodes() {
        let mut cache = WritebackInodeCache::new(16);
        cache.insert(1);
        cache.insert(2);
        cache.insert(3);
        cache.pin(2);
        let reclaimed = cache.reclaim_clean(10);
        assert_eq!(reclaimed, 2);
        assert!(cache.contains(2));
        assert!(!cache.contains(1));
        assert!(!cache.contains(3));
    }

    #[test]
    fn reclaim_refuses_all_dirty() {
        let mut cache = WritebackInodeCache::new(16);
        for i in 0..5 {
            cache.insert(i);
            cache.mark_dirty(i, 4096);
        }
        let reclaimed = cache.reclaim_clean(10);
        assert_eq!(reclaimed, 0);
        assert_eq!(cache.entry_count(), 5);
    }

    #[test]
    fn flush_then_reclaim_pipeline() {
        let mut cache = WritebackInodeCache::new(16);
        for i in 0..5 {
            cache.insert(i);
        }
        cache.mark_dirty(0, 4096);
        cache.mark_dirty(2, 8192);
        assert_eq!(cache.dirty_count(), 2);
        assert_eq!(cache.clean_count(), 3);
        let pre_flush_reclaimed = cache.reclaim_clean(10);
        assert_eq!(pre_flush_reclaimed, 3);
        assert_eq!(cache.entry_count(), 2);
        assert!(cache.contains(0));
        assert!(cache.contains(2));
        cache.mark_clean(0);
        cache.mark_clean(2);
        assert_eq!(cache.dirty_count(), 0);
        assert_eq!(cache.clean_count(), 2);
        let post_flush_reclaimed = cache.reclaim_all_clean();
        assert_eq!(post_flush_reclaimed, 2);
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn partial_flush_reclaims_only_flushed() {
        let mut cache = WritebackInodeCache::new(16);
        for i in 0..4 {
            cache.insert(i);
            cache.mark_dirty(i, 1024);
        }
        cache.mark_clean(1);
        let reclaimed = cache.reclaim_clean(10);
        assert_eq!(reclaimed, 1);
        assert!(!cache.contains(1));
        assert!(cache.contains(0));
        assert!(cache.contains(2));
        assert!(cache.contains(3));
    }

    #[test]
    fn reclaim_stats_track_attempts_and_successes() {
        let mut cache = WritebackInodeCache::new(16);
        for i in 0..5 {
            cache.insert(i);
        }
        cache.reclaim_clean(3);
        let (attempts, successes) = cache.reclaim_stats();
        assert_eq!(attempts, 3);
        assert_eq!(successes, 3);
        cache.mark_dirty(3, 4096);
        cache.reclaim_clean(5);
        let (attempts2, successes2) = cache.reclaim_stats();
        assert_eq!(attempts2, 8);
        assert_eq!(successes2, 4);
    }

    #[test]
    fn is_dirty_none_for_unknown_inode() {
        let cache = WritebackInodeCache::new(16);
        assert_eq!(cache.is_dirty(999), None);
    }

    #[test]
    fn empty_cache_all_counts_zero() {
        let cache = WritebackInodeCache::new(16);
        assert_eq!(cache.entry_count(), 0);
        assert_eq!(cache.dirty_count(), 0);
        assert_eq!(cache.clean_count(), 0);
        assert_eq!(cache.pinned_count(), 0);
        assert!(!cache.is_full());
    }
}
