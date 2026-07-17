// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! ## Authority Classification (per docs/cache-authority-model.md)
//!
//! This cache is **Derived** and **superseded** by `tidefs-cache-core::PageCache`.
//! It is a whole-file LRU read cache that mirrors the authoritative filesystem
//! store for read acceleration.  It must not grow dirty-data ownership, page-level
//! authority, or invalidation primitives that conflict with cache-core.
//!
//! Future work will remove this cache in favor of cache-core::PageCache
//! delegation, consolidating the duplicate whole-file caching that the A16 review
//! register identifies as a split-cache risk.  See also `read_cache.rs` in the
//! local-filesystem for the parallel `HotReadCache` (Derived, same status).
//!
use std::collections::{HashMap, VecDeque};

/// Default byte limit for the FUSE read cache (64 MiB).
///
/// The byte limit bounds total cached data independently of the entry-count
/// limit.  A 256-entry cache of 100 MB files could otherwise retain about
/// 25 GB and risk OOM.
pub const DEFAULT_READ_CACHE_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Bounded non-authoritative LRU read cache keyed by inode ID.
///
/// The cache stores complete file contents for recently read inodes.
/// Writes, truncates, and other content-modifying operations invalidate
/// the corresponding cache entries via `invalidate`.
///
/// The cache enforces a byte-size limit (`max_bytes`) on total cached data,
/// evicting LRU entries when necessary.  An individual entry larger than the
/// byte limit is not cached at all — it would displace all other entries.
///
/// The cache is non-authoritative: the backing filesystem is the source of
/// truth.  Cache entries only accelerate repeated reads.
#[derive(Debug)]
pub struct ReadCache {
    data: HashMap<u64, Vec<u8>>,
    order: VecDeque<u64>,
    bound: usize,
    max_bytes: usize,
    current_bytes: usize,
}

impl ReadCache {
    /// Cache authority classification per docs/cache-authority-model.md.
    /// The daemon ReadCache is Derived and superseded by cache-core::PageCache.
    pub const CACHE_AUTHORITY_CLASS: &str = "Derived";
    /// Return the cache authority classification at runtime.
    pub fn cache_authority_class(&self) -> &'static str {
        Self::CACHE_AUTHORITY_CLASS
    }

    /// Create a new read cache with the given entry-count bound and byte limit.
    pub fn with_byte_limit(bound: usize, max_bytes: usize) -> Self {
        Self {
            data: HashMap::new(),
            order: VecDeque::new(),
            bound,
            max_bytes,
            current_bytes: 0,
        }
    }

    /// Convenience constructor: entry-count bound with the default byte limit.
    pub fn new(bound: usize) -> Self {
        Self::with_byte_limit(bound, DEFAULT_READ_CACHE_MAX_BYTES)
    }

    /// Total bytes currently stored in the cache.
    #[allow(dead_code)]
    pub fn used_bytes(&self) -> usize {
        self.current_bytes
    }

    /// Whether an entry of `len` bytes can be admitted without bypass.
    pub fn can_admit_len(&self, len: usize) -> bool {
        len <= self.max_bytes
    }

    /// Look up cached data for `ino`. Returns `None` on miss.
    /// On hit, promotes the entry to the back of the LRU queue.
    #[allow(dead_code)]
    pub fn get(&mut self, ino: u64) -> Option<&Vec<u8>> {
        if self.data.contains_key(&ino) {
            self.order.retain(|&i| i != ino);
            self.order.push_back(ino);
            self.data.get(&ino)
        } else {
            None
        }
    }

    /// Look up a byte range from the cache. Returns the sub-slice on full
    /// coverage hit; returns `None` on partial coverage or miss.
    ///
    /// This enables page-cache fill-on-miss semantics: the cache stores the
    /// file contents known at the last fill, and `get_range` serves only
    /// when the requested range is fully contained in the cached data.
    pub fn get_range(&self, ino: u64, offset: u64, size: u32) -> Option<Vec<u8>> {
        let data = self.data.get(&ino)?;
        let start = offset as usize;
        let end = start + size as usize;
        if end <= data.len() {
            Some(data[start..end].to_vec())
        } else {
            None
        }
    }

    /// Insert `data` for `ino` into the cache.  Enforces both entry-count
    /// and byte-size limits.
    ///
    /// If the data is larger than `max_bytes`, it is not cached — caching it
    /// would force all other entries out, rendering the cache useless for
    /// normal-sized files.  This matches the HotReadCache admission bypass
    /// for entries exceeding its per-entry limit.
    ///
    /// Otherwise, LRU entries are evicted until both the entry-count bound
    /// and `max_bytes` are satisfied.
    pub fn insert(&mut self, ino: u64, data: Vec<u8>) {
        if !self.data.contains_key(&ino) {
            // Evict for entry-count bound
            while self.data.len() >= self.bound && !self.order.is_empty() {
                if let Some(evicted) = self.order.pop_front() {
                    self.current_bytes -= self.data[&evicted].len();
                    self.data.remove(&evicted);
                } else {
                    break;
                }
            }
        } else {
            self.order.retain(|&i| i != ino);
            // Replace existing entry: free its old bytes
            if let Some(old) = self.data.get(&ino) {
                self.current_bytes = self.current_bytes.saturating_sub(old.len());
            }
        }

        let entry_len = data.len();

        // Admission bypass: entry larger than the entire cache capacity
        if entry_len > self.max_bytes {
            return;
        }

        // Evict LRU entries until there is enough byte headroom
        while self.current_bytes + entry_len > self.max_bytes && !self.order.is_empty() {
            if let Some(evicted) = self.order.pop_front() {
                self.current_bytes = self.current_bytes.saturating_sub(self.data[&evicted].len());
                self.data.remove(&evicted);
            }
        }

        self.data.insert(ino, data);
        self.current_bytes += entry_len;
        self.order.push_back(ino);
    }

    /// Remove a cached entry. Safe to call even if `ino` is not cached.
    pub fn invalidate(&mut self, ino: u64) {
        if let Some(removed) = self.data.remove(&ino) {
            self.current_bytes = self.current_bytes.saturating_sub(removed.len());
        }
        self.order.retain(|&i| i != ino);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get() {
        let mut cache = ReadCache::new(4);
        cache.insert(1, b"hello".to_vec());
        assert_eq!(cache.get(1), Some(&b"hello".to_vec()));
        assert_eq!(cache.used_bytes(), 5);
    }

    #[test]
    fn miss_returns_none() {
        let mut cache = ReadCache::new(4);
        assert_eq!(cache.get(99), None);
    }

    #[test]
    fn evicts_lru_on_entry_capacity() {
        let mut cache = ReadCache::new(2);
        cache.insert(1, b"a".to_vec());
        cache.insert(2, b"b".to_vec());
        cache.get(1);
        cache.insert(3, b"c".to_vec());
        assert_eq!(cache.get(2), None);
        assert_eq!(cache.get(1), Some(&b"a".to_vec()));
        assert_eq!(cache.get(3), Some(&b"c".to_vec()));
    }

    #[test]
    fn invalidate_removes_entry_and_tracks_bytes() {
        let mut cache = ReadCache::new(4);
        cache.insert(1, b"data".to_vec());
        assert_eq!(cache.used_bytes(), 4);
        cache.invalidate(1);
        assert_eq!(cache.get(1), None);
        assert_eq!(cache.used_bytes(), 0);
    }

    #[test]
    fn invalidate_nonexistent_is_noop() {
        let mut cache = ReadCache::new(4);
        cache.invalidate(99);
        assert_eq!(cache.used_bytes(), 0);
    }

    #[test]
    fn update_existing_replaces_value() {
        let mut cache = ReadCache::new(4);
        cache.insert(1, b"old".to_vec());
        cache.insert(1, b"new".to_vec());
        assert_eq!(cache.get(1), Some(&b"new".to_vec()));
        assert_eq!(cache.used_bytes(), 3);
    }

    #[test]
    fn lru_order_respected_under_churn() {
        let mut cache = ReadCache::new(3);
        cache.insert(1, b"1".to_vec());
        cache.insert(2, b"2".to_vec());
        cache.insert(3, b"3".to_vec());
        cache.get(1);
        cache.get(2);
        cache.insert(4, b"4".to_vec());
        assert_eq!(cache.get(3), None);
        assert!(cache.get(1).is_some());
        assert!(cache.get(2).is_some());
        assert!(cache.get(4).is_some());
    }

    #[test]
    fn byte_limit_evicts_lru_entries() {
        let mut cache = ReadCache::with_byte_limit(10, 30);
        cache.insert(1, vec![0u8; 10]);
        cache.insert(2, vec![0u8; 10]);
        cache.insert(3, vec![0u8; 10]);
        assert_eq!(cache.used_bytes(), 30);

        cache.insert(4, vec![0u8; 10]);
        assert_eq!(
            cache.get(1),
            None,
            "LRU entry should be evicted for byte space"
        );
        assert!(cache.get(4).is_some());
        assert_eq!(cache.used_bytes(), 30);
    }

    #[test]
    fn oversized_entry_bypasses_cache() {
        let mut cache = ReadCache::with_byte_limit(10, 10);
        cache.insert(1, vec![0u8; 20]);
        assert_eq!(cache.used_bytes(), 0);
        assert_eq!(cache.get(1), None);

        cache.insert(2, vec![0u8; 5]);
        assert_eq!(cache.used_bytes(), 5);
        assert!(cache.get(2).is_some());
    }

    #[test]
    fn can_admit_len_matches_byte_limit() {
        let cache = ReadCache::with_byte_limit(10, 10);
        assert!(cache.can_admit_len(10));
        assert!(!cache.can_admit_len(11));
    }

    #[test]
    fn byte_eviction_evicts_multiple_for_large_entry() {
        let mut cache = ReadCache::with_byte_limit(10, 20);
        cache.insert(1, vec![0u8; 8]);
        cache.insert(2, vec![0u8; 8]);
        assert_eq!(cache.used_bytes(), 16);

        // 14-byte entry: after evicting one 8-byte entry, 8+14=22>20,
        // so both must go
        cache.insert(3, vec![0u8; 14]);
        assert_eq!(cache.get(1), None);
        assert_eq!(cache.get(2), None);
        assert!(cache.get(3).is_some());
        assert_eq!(cache.used_bytes(), 14);
    }

    #[test]
    fn byte_limit_with_no_entries_is_noop() {
        let mut cache = ReadCache::with_byte_limit(10, 0);
        cache.insert(1, vec![0u8; 1]);
        assert_eq!(cache.used_bytes(), 0);
        assert_eq!(cache.get(1), None);
    }

    #[test]
    fn used_bytes_correct_after_eviction_and_replace() {
        let mut cache = ReadCache::with_byte_limit(10, 50);
        cache.insert(1, vec![0u8; 20]);
        assert_eq!(cache.used_bytes(), 20);
        cache.insert(1, vec![0u8; 30]);
        assert_eq!(cache.used_bytes(), 30);
        cache.invalidate(1);
        assert_eq!(cache.used_bytes(), 0);
    }

    #[test]
    fn get_range_full_hit() {
        let mut cache = ReadCache::new(4);
        cache.insert(1, b"hello world".to_vec());
        assert_eq!(cache.get_range(1, 0, 5), Some(b"hello".to_vec()));
        assert_eq!(cache.get_range(1, 6, 5), Some(b"world".to_vec()));
    }

    #[test]
    fn get_range_partial_coverage_returns_none() {
        let mut cache = ReadCache::new(4);
        cache.insert(1, b"short".to_vec());
        // Request extends beyond cached data
        assert_eq!(cache.get_range(1, 0, 10), None);
    }

    #[test]
    fn get_range_offset_past_length_is_partial() {
        let mut cache = ReadCache::new(4);
        cache.insert(1, b"data".to_vec());
        // Offset 2 + size 4 = 6 > 4
        assert_eq!(cache.get_range(1, 2, 4), None);
    }

    #[test]
    fn get_range_exact_length_hit() {
        let mut cache = ReadCache::new(4);
        cache.insert(1, b"exact".to_vec());
        assert_eq!(cache.get_range(1, 0, 5), Some(b"exact".to_vec()));
    }

    #[test]
    fn get_range_miss_returns_none() {
        let cache = ReadCache::new(4);
        assert_eq!(cache.get_range(99, 0, 5), None);
    }

    #[test]
    fn default_constructor_uses_default_byte_limit() {
        let cache = ReadCache::new(256);
        assert_eq!(cache.max_bytes, DEFAULT_READ_CACHE_MAX_BYTES);
        assert_eq!(cache.used_bytes(), 0);
    }
}
