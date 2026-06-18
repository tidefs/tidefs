// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Page cache reclaim — LRU eviction of clean pages under memory pressure.
//!
//! PageCacheReclaimer walks the per-inode LRU lists in insertion order
//! (oldest first), skips pages marked dirty in the DirtyPageTracker,
//! and evicts clean pages until the cache resident bytes fall to or
//! below the configured low watermark.
//!
//! Synchronous reclaim is triggered on every insert that pushes the
//! cache above the high watermark. Async background reclaim is deferred
//! to Review debt TFR-008.

use tidefs_types_vfs_core::InodeId;

use super::{DirtyPageTracker, PageCache, PageKey};

/// Tunable watermark configuration for page cache reclaim.
///
/// When resident bytes exceed `high_watermark_bytes`, eviction runs
/// until resident bytes fall to `low_watermark_bytes` or below.
#[derive(Clone, Copy, Debug)]
pub struct ReclaimWatermarks {
    pub high_watermark_bytes: u64,
    pub low_watermark_bytes: u64,
}

impl ReclaimWatermarks {
    pub const fn new(high_bytes: u64, low_bytes: u64) -> Self {
        assert!(low_bytes <= high_bytes);
        Self {
            high_watermark_bytes: high_bytes,
            low_watermark_bytes: low_bytes,
        }
    }

    pub const fn default_for_testing() -> Self {
        Self::new(1024 * 1024, 512 * 1024) // 1 MiB high, 512 KiB low
    }
}

impl Default for ReclaimWatermarks {
    fn default() -> Self {
        Self::new(
            super::DEFAULT_PAGE_CACHE_HIGH_WATERMARK_BYTES,
            super::DEFAULT_PAGE_CACHE_LOW_WATERMARK_BYTES,
        )
    }
}

/// Cumulative statistics for the reclaim path.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReclaimStats {
    /// Total clean pages evicted since start.
    pub pages_evicted: u64,
    /// Pages skipped because they were dirty (waiting for writeback).
    pub pages_skipped_dirty: u64,
    /// Number of times evict_lru was called.
    pub eviction_calls: u64,
    /// Pages evicted by targeted evict_inode calls.
    pub inode_evictions: u64,
    /// Total bytes freed across all evictions.
    pub bytes_freed: u64,
}

impl ReclaimStats {
    pub fn is_idle(&self) -> bool {
        self.pages_evicted == 0
            && self.pages_skipped_dirty == 0
            && self.eviction_calls == 0
            && self.inode_evictions == 0
    }

    /// Merge another ReclaimStats snapshot into this one (accumulate).
    pub fn merge(&mut self, other: Self) {
        self.pages_evicted += other.pages_evicted;
        self.pages_skipped_dirty += other.pages_skipped_dirty;
        self.eviction_calls += other.eviction_calls;
        self.inode_evictions += other.inode_evictions;
        self.bytes_freed += other.bytes_freed;
    }
}

/// Drives LRU eviction of clean pages from the page cache.
///
/// Holds shared references to the page cache and dirty-page tracker.
/// Eviction walks per-inode LRU queues in insertion order, skips
/// dirty pages, and stops when the cache is at or below the low
/// watermark or when no evictable pages remain.
pub struct PageCacheReclaimer<'a> {
    cache: &'a mut PageCache,
    dirty_tracker: &'a DirtyPageTracker,
    watermarks: ReclaimWatermarks,
    pub stats: ReclaimStats,
}

impl<'a> PageCacheReclaimer<'a> {
    pub fn new(
        cache: &'a mut PageCache,
        dirty_tracker: &'a DirtyPageTracker,
        watermarks: ReclaimWatermarks,
    ) -> Self {
        Self {
            cache,
            dirty_tracker,
            watermarks,
            stats: ReclaimStats::default(),
        }
    }

    /// Set new watermarks. Immediately effective for the next eviction call.
    pub fn set_watermarks(&mut self, high_mb: u64, low_mb: u64) {
        let high_bytes = high_mb.saturating_mul(1024 * 1024);
        let low_bytes = low_mb.saturating_mul(1024 * 1024);
        self.watermarks = ReclaimWatermarks::new(high_bytes, low_bytes);
    }

    /// Evict clean pages until the cache is at or below the low watermark,
    /// or until no more evictable pages remain.
    ///
    /// Walks all per-inode LRU queues in insertion order (oldest first).
    /// Pages marked dirty are skipped; clean pages are dropped.
    /// Returns the number of pages evicted.
    pub fn evict_lru(&mut self, n_pages: usize) -> usize {
        self.stats.eviction_calls += 1;
        if n_pages == 0 {
            return 0;
        }

        // Collect inode IDs sorted for deterministic eviction order.
        let inodes: Vec<InodeId> = {
            let mut ids: Vec<InodeId> = self.cache.cached_inodes().collect();
            ids.sort();
            ids
        };

        let mut evicted = 0usize;

        for inode_id in &inodes {
            if evicted >= n_pages {
                break;
            }

            // Collect page keys to evict from this inode's LRU.
            // We need to collect them first to avoid borrow issues.
            let keys_to_evict: Vec<PageKey> = self
                .cache
                .lru_for_inode(*inode_id)
                .filter(|key| {
                    if self.dirty_tracker.is_dirty(key) {
                        self.stats.pages_skipped_dirty += 1;
                        false
                    } else {
                        true
                    }
                })
                .take(n_pages.saturating_sub(evicted))
                .copied()
                .collect();

            for key in &keys_to_evict {
                if let Some(page) = self.cache.remove(key) {
                    self.stats.bytes_freed += page.approximate_memory_bytes();
                    self.stats.pages_evicted += 1;
                    evicted += 1;
                }
                if evicted >= n_pages {
                    break;
                }
            }
        }

        evicted
    }

    /// Evict clean pages until the cache resident bytes are at or below
    /// the low watermark. This is the primary synchronous reclaim entry
    /// point called after insert when the cache exceeds the high watermark.
    ///
    /// Returns the number of pages evicted.
    pub fn evict_to_low_watermark(&mut self) -> usize {
        let mut total_evicted = 0usize;

        while self.cache.resident_bytes() > self.watermarks.low_watermark_bytes {
            // Evict in batches to avoid holding up the caller too long.
            let batch = 64usize;
            let evicted = self.evict_lru(batch);
            if evicted == 0 {
                // No more clean pages to evict — cache is full of dirty pages.
                break;
            }
            total_evicted += evicted;
        }

        total_evicted
    }

    /// Check if the cache is above the high watermark and needs eviction.
    pub fn above_high_watermark(&self) -> bool {
        self.cache.resident_bytes() > self.watermarks.high_watermark_bytes
    }

    /// Evict all clean pages belonging to a specific inode.
    /// Used when an inode is unlinked or evicted from the inode table.
    /// Returns the number of pages evicted.
    pub fn evict_inode(&mut self, inode_id: InodeId) -> usize {
        let keys: Vec<PageKey> = self
            .cache
            .lru_for_inode(inode_id)
            .filter(|key| !self.dirty_tracker.is_dirty(key))
            .copied()
            .collect();

        let mut evicted = 0usize;
        for key in &keys {
            if let Some(page) = self.cache.remove(key) {
                self.stats.bytes_freed += page.approximate_memory_bytes();
                self.stats.inode_evictions += 1;
                self.stats.pages_evicted += 1;
                evicted += 1;
            }
        }
        evicted
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;

    fn key(inode: u64, offset: u64) -> PageKey {
        PageKey::new(InodeId::new(inode), offset, 4096)
    }

    fn data_page(size: usize) -> CachedPage {
        CachedPage::new(vec![0u8; size], size)
    }

    fn setup_cache_with_pages(
        inode: u64,
        count: usize,
        page_size: usize,
    ) -> (PageCache, DirtyPageTracker) {
        let mut cache = PageCache::new(4096);
        let dt = DirtyPageTracker::new();
        for i in 0..count {
            let k = key(inode, i as u64 * 4096);
            cache.insert(k, data_page(page_size));
        }
        (cache, dt)
    }

    #[test]
    fn reclaim_evicts_clean_pages_below_low_watermark() {
        let (mut cache, dt) = setup_cache_with_pages(1, 100, 4096);
        // Set watermarks: high=50 pages, low=30 pages (roughly)
        let wm = ReclaimWatermarks::new(50 * 4096 + 64 * 50, 30 * 4096 + 64 * 30);
        let mut reclaimer = PageCacheReclaimer::new(&mut cache, &dt, wm);

        assert!(reclaimer.above_high_watermark());
        let evicted = reclaimer.evict_to_low_watermark();
        assert!(evicted > 0);
        assert!(!reclaimer.above_high_watermark());
        // Cache should be at or below low watermark.
        assert!(cache.resident_bytes() <= wm.low_watermark_bytes);
    }

    #[test]
    fn reclaim_skips_dirty_pages() {
        let (mut cache, mut dt) = setup_cache_with_pages(1, 10, 8192);
        // Mark pages 0-4 as dirty.
        for i in 0..5 {
            dt.mark_dirty(key(1, i * 4096));
        }
        let wm = ReclaimWatermarks::new(1024, 512); // Tiny watermark to force eviction
        let mut reclaimer = PageCacheReclaimer::new(&mut cache, &dt, wm);

        let evicted = reclaimer.evict_lru(10);
        assert!(evicted > 0);
        assert!(evicted <= 5, "should only evict clean pages (5 of 10)");
        assert_eq!(
            reclaimer.stats.pages_skipped_dirty, 5,
            "should have skipped 5 dirty pages"
        );

        // Dirty pages should still be in cache.
        for i in 0..5 {
            assert!(
                cache.get(&key(1, i * 4096)).is_some(),
                "dirty page {i} should still be cached"
            );
        }
    }

    #[test]
    fn reclaim_evict_inode_drops_all_clean_pages() {
        let (mut cache, mut dt) = setup_cache_with_pages(1, 5, 4096);
        // Add pages for inode 2.
        for i in 0..3 {
            cache.insert(key(2, i * 4096), data_page(4096));
        }
        // Mark one page in inode 1 as dirty.
        dt.mark_dirty(key(1, 0));

        let wm = ReclaimWatermarks::default();
        let mut reclaimer = PageCacheReclaimer::new(&mut cache, &dt, wm);

        let evicted = reclaimer.evict_inode(InodeId::new(1));
        // 5 pages total, 1 dirty => 4 clean evicted.
        assert_eq!(evicted, 4);

        // Dirty page should remain.
        assert!(cache.get(&key(1, 0)).is_some());
    }

    #[test]
    fn reclaim_stats_increment() {
        let (mut cache, dt) = setup_cache_with_pages(1, 20, 4096);
        let wm = ReclaimWatermarks::new(1024, 512); // Force eviction
        let mut reclaimer = PageCacheReclaimer::new(&mut cache, &dt, wm);

        reclaimer.evict_lru(5);
        assert_eq!(reclaimer.stats.eviction_calls, 1);
        assert_eq!(reclaimer.stats.pages_evicted, 5);
        assert!(reclaimer.stats.bytes_freed > 0);

        reclaimer.evict_inode(InodeId::new(1));
        // Remaining 15 clean pages from inode 1.
        assert_eq!(reclaimer.stats.inode_evictions, 15);
        assert_eq!(reclaimer.stats.pages_evicted, 20);
    }

    #[test]
    fn reclaim_noop_below_high_watermark() {
        let (mut cache, dt) = setup_cache_with_pages(1, 5, 4096);
        let wm = ReclaimWatermarks::new(1024 * 1024, 512 * 1024); // Huge watermark
        let mut reclaimer = PageCacheReclaimer::new(&mut cache, &dt, wm);

        assert!(!reclaimer.above_high_watermark());
        let evicted = reclaimer.evict_to_low_watermark();
        assert_eq!(evicted, 0);
        assert_eq!(reclaimer.stats.pages_evicted, 0);
    }

    #[test]
    fn set_watermarks_sets_mb_values() {
        let (mut cache, dt) = setup_cache_with_pages(1, 1, 4096);
        let wm = ReclaimWatermarks::default_for_testing();
        let mut reclaimer = PageCacheReclaimer::new(&mut cache, &dt, wm);

        reclaimer.set_watermarks(10, 5); // 10 MiB high, 5 MiB low
        assert_eq!(reclaimer.watermarks.high_watermark_bytes, 10 * 1024 * 1024);
        assert_eq!(reclaimer.watermarks.low_watermark_bytes, 5 * 1024 * 1024);
    }

    #[test]
    fn evict_lru_limit_respected() {
        let (mut cache, dt) = setup_cache_with_pages(1, 30, 4096);
        let wm = ReclaimWatermarks::new(500, 250); // Tiny watermark
        let mut reclaimer = PageCacheReclaimer::new(&mut cache, &dt, wm);

        // Evict exactly 3 pages.
        let evicted = reclaimer.evict_lru(3);
        assert_eq!(evicted, 3);
        assert_eq!(reclaimer.stats.pages_evicted, 3);
        assert_eq!(cache.page_count(), 27);
    }

    #[test]
    fn evict_to_low_watermark_stops_when_all_dirty() {
        let page_size = 4096usize;
        let (mut cache, mut dt) = setup_cache_with_pages(1, 10, page_size);
        // Mark ALL pages dirty.
        for i in 0..10 {
            dt.mark_dirty(key(1, i as u64 * 4096));
        }
        let wm = ReclaimWatermarks::new(500, 250); // Tiny watermark
        let mut reclaimer = PageCacheReclaimer::new(&mut cache, &dt, wm);

        let evicted = reclaimer.evict_to_low_watermark();
        assert_eq!(evicted, 0);
        assert_eq!(reclaimer.stats.pages_evicted, 0);
        assert_eq!(reclaimer.stats.pages_skipped_dirty, 10);
        // All pages remain.
        assert_eq!(cache.page_count(), 10);
    }
}
