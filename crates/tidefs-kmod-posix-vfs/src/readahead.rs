//! Readahead and page-cache integration for the kernel VFS adapter.
//!
//! Mirrors the userspace VfsPageCacheStats from tidefs-vfs-engine::trace
//! for kernel parity validation (K7-06/#5285).

#[derive(Clone, Copy, Debug, Default)]
pub struct KmodPageCacheStats {
    pub hit: u64,
    pub miss: u64,
    pub populate: u64,
    pub prefetch: u64,
    pub evict: u64,
    pub readahead_count: u64,
}

impl KmodPageCacheStats {
    pub fn hit_ratio_ppm(self) -> u64 {
        let total = self.hit.saturating_add(self.miss);
        if total == 0 {
            return 0;
        }
        // Avoid 128-bit division: __udivti3 is unavailable in the Linux kernel.
        self.hit.saturating_mul(1_000_000) / total
    }
    pub fn record_hit(&mut self) {
        self.hit = self.hit.saturating_add(1);
    }
    pub fn record_miss(&mut self) {
        self.miss = self.miss.saturating_add(1);
    }
    pub fn record_populate(&mut self) {
        self.populate = self.populate.saturating_add(1);
    }
    pub fn record_prefetch(&mut self) {
        self.prefetch = self.prefetch.saturating_add(1);
    }
    pub fn record_evict(&mut self) {
        self.evict = self.evict.saturating_add(1);
    }
    pub fn record_readahead(&mut self) {
        self.readahead_count = self.readahead_count.saturating_add(1);
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ReadaheadWindow {
    pub offset: u64,
    pub length: u32,
}
impl ReadaheadWindow {
    pub const fn new(offset: u64, length: u32) -> Self {
        Self { offset, length }
    }
    pub const fn end(self) -> u64 {
        self.offset.saturating_add(self.length as u64)
    }
}

#[derive(Clone, Debug, Default)]
pub struct KmodPageCacheTracker {
    pub stats: KmodPageCacheStats,
}
impl KmodPageCacheTracker {
    pub const fn new() -> Self {
        Self {
            stats: KmodPageCacheStats {
                hit: 0,
                miss: 0,
                populate: 0,
                prefetch: 0,
                evict: 0,
                readahead_count: 0,
            },
        }
    }
    pub fn snapshot(&self) -> KmodPageCacheStats {
        self.stats
    }
    pub fn take(&mut self) -> KmodPageCacheStats {
        let s = self.stats;
        self.stats = KmodPageCacheStats::default();
        s
    }
    pub fn record_hit(&mut self) {
        self.stats.record_hit();
    }
    pub fn record_miss(&mut self) {
        self.stats.record_miss();
    }
    pub fn record_populate(&mut self) {
        self.stats.record_populate();
    }
    pub fn record_prefetch(&mut self) {
        self.stats.record_prefetch();
    }
    pub fn record_evict(&mut self) {
        self.stats.record_evict();
    }
    pub fn record_readahead(&mut self) {
        self.stats.record_readahead();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_ratio_full_hits() {
        let s = KmodPageCacheStats {
            hit: 100,
            miss: 0,
            ..Default::default()
        };
        assert_eq!(s.hit_ratio_ppm(), 1_000_000);
    }
    #[test]
    fn hit_ratio_full_misses() {
        let s = KmodPageCacheStats {
            hit: 0,
            miss: 100,
            ..Default::default()
        };
        assert_eq!(s.hit_ratio_ppm(), 0);
    }
    #[test]
    fn hit_ratio_mixed() {
        let s = KmodPageCacheStats {
            hit: 75,
            miss: 25,
            ..Default::default()
        };
        assert_eq!(s.hit_ratio_ppm(), 750_000);
    }
    #[test]
    fn hit_ratio_zero() {
        assert_eq!(KmodPageCacheStats::default().hit_ratio_ppm(), 0);
    }
    #[test]
    fn record_all_counters() {
        let mut s = KmodPageCacheStats::default();
        s.record_hit();
        s.record_miss();
        s.record_populate();
        s.record_prefetch();
        s.record_evict();
        s.record_readahead();
        assert_eq!(s.hit, 1);
        assert_eq!(s.miss, 1);
        assert_eq!(s.populate, 1);
        assert_eq!(s.prefetch, 1);
        assert_eq!(s.evict, 1);
        assert_eq!(s.readahead_count, 1);
    }
    #[test]
    fn readahead_window_end() {
        assert_eq!(ReadaheadWindow::new(1024, 4096).end(), 5120);
    }
    #[test]
    fn tracker_snapshot_non_consuming() {
        let mut t = KmodPageCacheTracker::new();
        t.record_hit();
        t.record_hit();
        assert_eq!(t.snapshot().hit, 2);
        assert_eq!(t.snapshot().hit, 2);
    }
    #[test]
    fn tracker_take_consumes() {
        let mut t = KmodPageCacheTracker::new();
        t.record_hit();
        t.record_miss();
        let s = t.take();
        assert_eq!(s.hit, 1);
        assert_eq!(s.miss, 1);
        assert_eq!(t.snapshot().hit, 0);
    }
    #[test]
    fn tracker_new_empty() {
        assert_eq!(KmodPageCacheTracker::new().snapshot().hit, 0);
    }
}
