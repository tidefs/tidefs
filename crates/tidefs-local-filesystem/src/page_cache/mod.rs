// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! ## Authority Classification (per docs/cache-authority-model.md)
//!
//! This page cache is **Derived**.  It mirrors object-store content for read
//! acceleration and must never be cited as the authoritative source for
//! durability or recovery.  Authority lives in the object store and the
//! committed root-slot chain.  The canonical page-level authority is
//! `tidefs-cache-core::PageCache`.
//!
//! Page cache for in-flight file data.
//!
//! Stores dirty and clean pages in memory keyed by (inode_id, page_offset).
//! The DirtyPageTracker records which pages have been modified but not yet
//! written back to the object store. The reclaim sub-module evicts clean
//! pages under memory pressure, coordinating with the writeback layer to
//! never evict in-flight dirty pages.
//!
//! This is an in-memory cache that mirrors object-store content; it is
//! never authoritative for durability or recovery. Authority lives in
//! the object store and the committed root-slot chain.

#[cfg(test)]
mod read_tests;
pub mod reclaim;

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::time::Instant;

use tidefs_types_vfs_core::InodeId;

use crate::constants::DEFAULT_FILESYSTEM_CONTENT_CHUNK_SIZE;

/// Reconciled local lifecycle for a cached page shadow entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageLifecycleState {
    Clean,
    Dirty,
    WritebackPending,
    ErrorPoisoned,
}

/// Default page cache high watermark: 256 MiB.
pub const DEFAULT_PAGE_CACHE_HIGH_WATERMARK_BYTES: u64 = 256 * 1024 * 1024;
/// Default page cache low watermark: 128 MiB.
pub const DEFAULT_PAGE_CACHE_LOW_WATERMARK_BYTES: u64 = 128 * 1024 * 1024;

/// Key for a cached page: inode + byte-offset rounded down to page size.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct PageKey {
    pub inode_id: InodeId,
    pub page_offset: u64,
}

impl PageKey {
    pub fn new(inode_id: InodeId, byte_offset: u64, page_size: u64) -> Self {
        let page_offset = (byte_offset / page_size) * page_size;
        Self {
            inode_id,
            page_offset,
        }
    }
}

/// A cached page with data, dirty flag, and access metadata.
#[derive(Clone, Debug)]
pub struct CachedPage {
    pub data: Vec<u8>,
    pub dirty: bool,
    pub last_access: Instant,
    /// Byte size of the stored data (may differ from page_size for tail pages).
    pub data_len: usize,
}

impl CachedPage {
    pub fn new(data: Vec<u8>, data_len: usize) -> Self {
        Self {
            data,
            dirty: false,
            last_access: Instant::now(),
            data_len,
        }
    }

    pub fn approximate_memory_bytes(&self) -> u64 {
        self.data.capacity() as u64 + 64 // struct overhead estimate
    }
}

/// Tracks which pages are dirty (modified in cache but not yet written back).
///
/// The reclaim path consults this tracker before eviction to avoid dropping
/// pages that are waiting for writeback. The WritebackDaemon removes entries
/// after successful flush.
#[derive(Clone, Debug, Default)]
pub struct DirtyPageTracker {
    dirty_pages: BTreeSet<PageKey>,
    /// Per-inode count of dirty pages for quick queries.
    per_inode_dirty_count: BTreeMap<InodeId, usize>,
    page_lifecycle: BTreeMap<PageKey, PageLifecycleState>,
}

impl DirtyPageTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_dirty(&mut self, key: PageKey) {
        self.set_lifecycle(key, PageLifecycleState::Dirty);
    }

    pub fn mark_writeback_pending(&mut self, key: PageKey) {
        self.set_lifecycle(key, PageLifecycleState::WritebackPending);
    }

    pub fn mark_error_poisoned(&mut self, key: PageKey) {
        self.set_lifecycle(key, PageLifecycleState::ErrorPoisoned);
    }

    pub fn mark_clean(&mut self, key: PageKey) {
        self.set_lifecycle(key, PageLifecycleState::Clean);
    }

    fn set_lifecycle(&mut self, key: PageKey, lifecycle: PageLifecycleState) {
        let was_non_clean = self.dirty_pages.contains(&key);
        let is_non_clean = lifecycle != PageLifecycleState::Clean;
        match (was_non_clean, is_non_clean) {
            (false, true) => {
                self.dirty_pages.insert(key);
                *self.per_inode_dirty_count.entry(key.inode_id).or_insert(0) += 1;
            }
            (true, false) => {
                self.dirty_pages.remove(&key);
                if let Some(count) = self.per_inode_dirty_count.get_mut(&key.inode_id) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.per_inode_dirty_count.remove(&key.inode_id);
                    }
                }
            }
            _ => {}
        }
        if is_non_clean {
            self.page_lifecycle.insert(key, lifecycle);
        } else {
            self.page_lifecycle.remove(&key);
        }
    }

    pub fn is_dirty(&self, key: &PageKey) -> bool {
        self.dirty_pages.contains(key)
    }

    pub fn lifecycle_state(&self, key: &PageKey) -> PageLifecycleState {
        self.page_lifecycle
            .get(key)
            .copied()
            .unwrap_or(PageLifecycleState::Clean)
    }

    pub fn dirty_page_count(&self) -> usize {
        self.dirty_pages.len()
    }

    pub fn dirty_pages_for_inode(&self, inode_id: InodeId) -> impl Iterator<Item = &PageKey> {
        self.dirty_pages
            .range(
                PageKey {
                    inode_id,
                    page_offset: 0,
                }..PageKey {
                    inode_id: InodeId::new(inode_id.get().saturating_add(1)),
                    page_offset: 0,
                },
            )
            .filter(move |k| k.inode_id == inode_id)
    }

    pub fn per_inode_dirty_count(&self, inode_id: InodeId) -> usize {
        self.per_inode_dirty_count
            .get(&inode_id)
            .copied()
            .unwrap_or(0)
    }

    pub fn clear_inode(&mut self, inode_id: InodeId) {
        let keys: Vec<PageKey> = self
            .dirty_pages
            .iter()
            .filter(|k| k.inode_id == inode_id)
            .copied()
            .collect();
        for key in keys {
            self.dirty_pages.remove(&key);
            self.page_lifecycle.remove(&key);
        }
        self.per_inode_dirty_count.remove(&inode_id);
    }
}

/// In-memory page cache with per-inode LRU tracking and dirty-page awareness.
///
/// Capacity is measured in bytes. The LRU is a per-inode insertion-ordered
/// queue. Review debt TFR-008 tracks true LRU promotion on access.
#[derive(Debug)]
pub struct PageCache {
    pages: HashMap<PageKey, CachedPage>,
    /// Per-inode LRU: oldest pages at the front (pop_front for eviction).
    /// tidefs-queue-root: local_fs.page_cache_lru
    /// admission: AdmissionPermit  service_curve: ServiceCurve
    lru: BTreeMap<InodeId, VecDeque<PageKey>>,
    /// Approximate resident memory in bytes.
    resident_bytes: u64,
    /// Page size used for offset alignment.
    page_size: u64,
    /// Statistics.
    pub inserts: u64,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

impl PageCache {
    /// Cache authority classification per docs/cache-authority-model.md.
    /// This PageCache is Derived (mirrors object-store content).
    /// The canonical page-level authority is tidefs-cache-core::PageCache.
    #[allow(dead_code)]
    pub const CACHE_AUTHORITY_CLASS: &str = "Derived";
    /// Return the cache authority classification at runtime.
    #[allow(dead_code)]
    pub fn cache_authority_class(&self) -> &'static str {
        Self::CACHE_AUTHORITY_CLASS
    }

    pub fn new(page_size: u64) -> Self {
        Self {
            pages: HashMap::new(),
            lru: BTreeMap::new(),
            resident_bytes: 0,
            page_size,
            inserts: 0,
            hits: 0,
            misses: 0,
            evictions: 0,
        }
    }

    pub fn with_default_page_size() -> Self {
        Self::new(DEFAULT_FILESYSTEM_CONTENT_CHUNK_SIZE as u64)
    }

    pub fn page_size(&self) -> u64 {
        self.page_size
    }

    pub fn resident_bytes(&self) -> u64 {
        self.resident_bytes
    }

    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    /// Look up a cached page. Returns None on miss.
    pub fn get(&mut self, key: &PageKey) -> Option<&CachedPage> {
        let page = self.pages.get(key)?;
        // Review debt TFR-008: LRU promotion is not wired (insertion-order only).
        self.hits += 1;
        Some(page)
    }

    /// Look up a mutable cached page. Returns None on miss.
    pub fn get_mut(&mut self, key: &PageKey) -> Option<&mut CachedPage> {
        let page = self.pages.get_mut(key)?;
        page.last_access = Instant::now();
        self.hits += 1;
        Some(page)
    }

    /// Insert a page into the cache. If a page with the same key already
    /// exists, replaces it and returns the old page.
    pub fn insert(&mut self, key: PageKey, page: CachedPage) -> Option<CachedPage> {
        let mem = page.approximate_memory_bytes();
        let old = self.pages.insert(key, page);
        if let Some(ref old_page) = old {
            self.resident_bytes = self
                .resident_bytes
                .saturating_sub(old_page.approximate_memory_bytes());
        }
        self.resident_bytes = self.resident_bytes.saturating_add(mem);

        let lru = self.lru.entry(key.inode_id).or_default();
        // Remove existing entry for this key if present, then push to back.
        lru.retain(|k| *k != key);
        lru.push_back(key);

        if old.is_none() {
            self.inserts += 1;
        }
        old
    }

    /// Remove a page from the cache. Returns the removed page if it existed.
    pub fn remove(&mut self, key: &PageKey) -> Option<CachedPage> {
        let page = self.pages.remove(key)?;
        self.resident_bytes = self
            .resident_bytes
            .saturating_sub(page.approximate_memory_bytes());

        if let Some(lru) = self.lru.get_mut(&key.inode_id) {
            lru.retain(|k| *k != *key);
            if lru.is_empty() {
                self.lru.remove(&key.inode_id);
            }
        }
        self.evictions += 1;
        Some(page)
    }

    /// Remove all pages for a given inode. Returns count removed.
    pub fn remove_inode(&mut self, inode_id: InodeId) -> usize {
        let keys: Vec<PageKey> = self
            .pages
            .keys()
            .filter(|k| k.inode_id == inode_id)
            .copied()
            .collect();
        let count = keys.len();
        for key in &keys {
            self.remove(key);
        }
        count
    }

    /// Invalidate (remove) clean, non-dirty pages whose byte range overlaps
    /// with [start_byte, end_byte). Dirty pages are preserved — their data
    /// must be flushed before they become invalidatable.
    ///
    /// This is the primary coherency primitive for mmap lease revocation:
    /// when a conflicting lease is granted to another client, this method
    /// evicts stale clean pages so that subsequent accesses fetch new data.
    ///
    /// Returns the count of pages removed.
    pub fn invalidate_range(&mut self, inode_id: InodeId, start_byte: u64, end_byte: u64) -> usize {
        let keys_to_remove: Vec<PageKey> = self
            .pages
            .iter()
            .filter(|(k, p)| {
                k.inode_id == inode_id
                    && k.page_offset < end_byte
                    && k.page_offset + self.page_size > start_byte
                    && !p.dirty
            })
            .map(|(k, _)| *k)
            .collect();
        let count = keys_to_remove.len();
        for key in &keys_to_remove {
            self.remove(key);
        }
        count
    }

    /// Invalidate clean pages while reconciling against the page-level dirty
    /// lifecycle shadow used by reclaim/writeback scheduling.
    pub fn invalidate_range_reconciled(
        &mut self,
        dirty_tracker: &DirtyPageTracker,
        inode_id: InodeId,
        start_byte: u64,
        end_byte: u64,
    ) -> usize {
        let keys_to_remove: Vec<PageKey> = self
            .pages
            .iter()
            .filter(|(k, p)| {
                k.inode_id == inode_id
                    && k.page_offset < end_byte
                    && k.page_offset + self.page_size > start_byte
                    && !p.dirty
                    && !dirty_tracker.is_dirty(k)
            })
            .map(|(k, _)| *k)
            .collect();
        let count = keys_to_remove.len();
        for key in &keys_to_remove {
            self.remove(key);
        }
        count
    }

    /// Invalidate all clean pages for an inode (entire file).
    /// Convenience wrapper around [`invalidate_range`] with [0, u64::MAX).
    pub fn invalidate_inode(&mut self, inode_id: InodeId) -> usize {
        self.invalidate_range(inode_id, 0, u64::MAX)
    }

    /// Invalidate all clean pages for an inode after reconciling the dirty
    /// lifecycle shadow.
    pub fn invalidate_inode_reconciled(
        &mut self,
        dirty_tracker: &DirtyPageTracker,
        inode_id: InodeId,
    ) -> usize {
        self.invalidate_range_reconciled(dirty_tracker, inode_id, 0, u64::MAX)
    }

    /// Iterate LRU pages for an inode (oldest first) for eviction scanning.
    pub fn lru_for_inode(&self, inode_id: InodeId) -> impl Iterator<Item = &PageKey> {
        self.lru
            .get(&inode_id)
            .into_iter()
            .flat_map(|deque| deque.iter())
    }

    /// All inode IDs that have cached pages.
    pub fn cached_inodes(&self) -> impl Iterator<Item = InodeId> + '_ {
        self.lru.keys().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(inode: u64, offset: u64) -> PageKey {
        PageKey::new(InodeId::new(inode), offset, 4096)
    }

    fn page(data: &[u8]) -> CachedPage {
        CachedPage::new(data.to_vec(), data.len())
    }

    #[test]
    fn insert_and_get_page() {
        let mut cache = PageCache::new(4096);
        let k = key(1, 0);
        cache.insert(k, page(b"hello"));
        assert!(cache.get(&k).is_some());
        assert_eq!(cache.hits, 1);
        assert_eq!(cache.inserts, 1);
    }

    #[test]
    fn get_mut_updates_access_time() {
        let mut cache = PageCache::new(4096);
        let k = key(1, 0);
        cache.insert(k, page(b"hello"));
        let before = cache.pages[&k].last_access;
        std::thread::sleep(std::time::Duration::from_millis(1));
        cache.get_mut(&k).unwrap().data.push(b'!');
        assert!(cache.pages[&k].last_access > before);
    }

    #[test]
    fn remove_page_frees_bytes() {
        let mut cache = PageCache::new(4096);
        let k = key(1, 0);
        let data = vec![0u8; 8192];
        let byte_size = data.capacity() as u64 + 64;
        cache.insert(k, page(&data));
        assert_eq!(cache.resident_bytes, byte_size);
        cache.remove(&k);
        assert_eq!(cache.resident_bytes, 0);
        assert_eq!(cache.page_count(), 0);
    }

    #[test]
    fn remove_inode_drops_all_pages() {
        let mut cache = PageCache::new(4096);
        for i in 0..4u64 {
            cache.insert(key(1, i * 4096), page(b"data"));
        }
        cache.insert(key(2, 0), page(b"other"));
        assert_eq!(cache.page_count(), 5);

        let removed = cache.remove_inode(InodeId::new(1));
        assert_eq!(removed, 4);
        assert_eq!(cache.page_count(), 1);
        assert!(cache.get(&key(2, 0)).is_some());
        assert!(!cache.lru.contains_key(&InodeId::new(1)));
    }

    #[test]
    fn dirty_page_tracker_mark_and_check() {
        let mut dt = DirtyPageTracker::new();
        let k = key(1, 0);
        assert!(!dt.is_dirty(&k));
        assert_eq!(dt.lifecycle_state(&k), PageLifecycleState::Clean);
        dt.mark_dirty(k);
        assert!(dt.is_dirty(&k));
        assert_eq!(dt.lifecycle_state(&k), PageLifecycleState::Dirty);
        assert_eq!(dt.dirty_page_count(), 1);
        assert_eq!(dt.per_inode_dirty_count(InodeId::new(1)), 1);
    }

    #[test]
    fn dirty_page_tracker_mark_clean() {
        let mut dt = DirtyPageTracker::new();
        let k = key(1, 0);
        dt.mark_dirty(k);
        dt.mark_clean(k);
        assert!(!dt.is_dirty(&k));
        assert_eq!(dt.lifecycle_state(&k), PageLifecycleState::Clean);
        assert_eq!(dt.dirty_page_count(), 0);
        assert_eq!(dt.per_inode_dirty_count(InodeId::new(1)), 0);
    }

    #[test]
    fn dirty_page_tracker_counts_pending_and_error_as_non_clean() {
        let mut dt = DirtyPageTracker::new();
        let pending = key(1, 0);
        let poisoned = key(1, 4096);

        dt.mark_writeback_pending(pending);
        dt.mark_error_poisoned(poisoned);

        assert!(dt.is_dirty(&pending));
        assert!(dt.is_dirty(&poisoned));
        assert_eq!(
            dt.lifecycle_state(&pending),
            PageLifecycleState::WritebackPending
        );
        assert_eq!(
            dt.lifecycle_state(&poisoned),
            PageLifecycleState::ErrorPoisoned
        );
        assert_eq!(dt.dirty_page_count(), 2);
        assert_eq!(dt.per_inode_dirty_count(InodeId::new(1)), 2);

        dt.mark_clean(pending);
        assert!(!dt.is_dirty(&pending));
        assert_eq!(dt.per_inode_dirty_count(InodeId::new(1)), 1);
    }

    #[test]
    fn dirty_page_tracker_clear_inode() {
        let mut dt = DirtyPageTracker::new();
        dt.mark_dirty(key(1, 0));
        dt.mark_dirty(key(1, 4096));
        dt.mark_dirty(key(2, 0));
        assert_eq!(dt.dirty_page_count(), 3);

        dt.clear_inode(InodeId::new(1));
        assert_eq!(dt.dirty_page_count(), 1);
        assert!(dt.is_dirty(&key(2, 0)));
        assert_eq!(dt.per_inode_dirty_count(InodeId::new(1)), 0);
    }

    #[test]
    fn dirty_pages_for_inode_iterates_correctly() {
        let mut dt = DirtyPageTracker::new();
        dt.mark_dirty(key(1, 0));
        dt.mark_dirty(key(1, 4096));
        dt.mark_dirty(key(2, 0));

        let inode1_pages: Vec<PageKey> =
            dt.dirty_pages_for_inode(InodeId::new(1)).copied().collect();
        assert_eq!(inode1_pages.len(), 2);
        assert!(inode1_pages.contains(&key(1, 0)));
        assert!(inode1_pages.contains(&key(1, 4096)));
    }

    // ── Test: invalidate_range ─────────────────────────────────────

    #[test]
    fn invalidate_range_removes_clean_pages_in_range() {
        let mut cache = PageCache::new(4096);
        for off in [0u64, 4096, 8192, 12288] {
            cache.insert(key(1, off), page(b"data"));
        }
        let removed = cache.invalidate_range(InodeId::new(1), 4096, 12288);
        assert_eq!(removed, 2, "pages at 4096 and 8192 should be removed");
        assert!(cache.get(&key(1, 0)).is_some(), "page at 0 outside range");
        assert!(cache.get(&key(1, 4096)).is_none(), "page at 4096 in range");
        assert!(cache.get(&key(1, 8192)).is_none(), "page at 8192 in range");
        assert!(
            cache.get(&key(1, 12288)).is_some(),
            "page at 12288 outside range"
        );
    }

    #[test]
    fn invalidate_range_preserves_dirty_pages() {
        let mut cache = PageCache::new(4096);
        cache.insert(key(1, 0), page(b"clean"));
        let mut dirty_page = page(b"dirty");
        dirty_page.dirty = true;
        cache.insert(key(1, 4096), dirty_page);

        let removed = cache.invalidate_range(InodeId::new(1), 0, 8192);
        assert_eq!(removed, 1, "only clean page should be removed");
        assert!(cache.get(&key(1, 0)).is_none(), "clean page removed");
        assert!(cache.get(&key(1, 4096)).is_some(), "dirty page preserved");
    }

    #[test]
    fn reconciled_invalidation_preserves_shadow_pending_and_error_pages() {
        let mut cache = PageCache::new(4096);
        let mut tracker = DirtyPageTracker::new();
        cache.insert(key(1, 0), page(b"clean"));
        cache.insert(key(1, 4096), page(b"pending"));
        cache.insert(key(1, 8192), page(b"poison"));

        tracker.mark_writeback_pending(key(1, 4096));
        tracker.mark_error_poisoned(key(1, 8192));

        let removed = cache.invalidate_range_reconciled(&tracker, InodeId::new(1), 0, 12288);
        assert_eq!(removed, 1, "only the clean page should be removed");
        assert!(cache.get(&key(1, 0)).is_none());
        assert!(cache.get(&key(1, 4096)).is_some());
        assert!(cache.get(&key(1, 8192)).is_some());
    }

    #[test]
    fn invalidate_range_only_matches_given_inode() {
        let mut cache = PageCache::new(4096);
        cache.insert(key(1, 0), page(b"data1"));
        cache.insert(key(2, 0), page(b"data2"));

        let removed = cache.invalidate_range(InodeId::new(1), 0, 4096);
        assert_eq!(removed, 1);
        assert!(
            cache.get(&key(2, 0)).is_some(),
            "inode 2 should be unaffected"
        );
    }

    #[test]
    fn invalidate_range_empty_cache_returns_zero() {
        let mut cache = PageCache::new(4096);
        assert_eq!(cache.invalidate_range(InodeId::new(1), 0, 4096), 0);
    }

    #[test]
    fn invalidate_inode_removes_all_clean_pages() {
        let mut cache = PageCache::new(4096);
        for off in [0u64, 4096, 8192] {
            cache.insert(key(1, off), page(b"data"));
        }
        cache.insert(key(2, 0), page(b"other"));

        let removed = cache.invalidate_inode(InodeId::new(1));
        assert_eq!(removed, 3);
        assert_eq!(cache.page_count(), 1);
        assert!(cache.get(&key(2, 0)).is_some());
    }

    #[test]
    fn invalidate_inode_preserves_dirty_pages() {
        let mut cache = PageCache::new(4096);
        cache.insert(key(1, 0), page(b"clean"));
        let mut dirty_page = page(b"dirty");
        dirty_page.dirty = true;
        cache.insert(key(1, 4096), dirty_page);

        let removed = cache.invalidate_inode(InodeId::new(1));
        assert_eq!(removed, 1);
        assert!(cache.get(&key(1, 4096)).is_some(), "dirty page preserved");
    }
}
