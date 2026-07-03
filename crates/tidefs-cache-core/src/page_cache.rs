// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Page-cache core for TideFS: page insert, lookup, LRU eviction,
//! dirty tracking, and writeback coordination.
//!
//! Provides the buffering layer that FUSE read/write dispatch and
//! the local filesystem depend on. All operations are synchronous;
//! concurrency is handled via an internal [`Mutex`] so the public
//! API is `&self`-friendly.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::sync::Mutex;

use crate::{
    budget_category_for_cache_level, BudgetCategory, BudgetError, CacheBudgetLevel, Governor,
};

// ---------------------------------------------------------------------------
// PageKey: (inode, page-aligned offset)
// ---------------------------------------------------------------------------

/// Identifies a page within a file by its inode number and page-aligned byte
/// offset.  The caller is responsible for ensuring `offset` is page-aligned.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct PageKey {
    pub inode: u64,
    pub offset: u64,
}

impl fmt::Display for PageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ino:{}@{}", self.inode, self.offset)
    }
}

// ---------------------------------------------------------------------------
// Page state flags (bitmask on u8)
// ---------------------------------------------------------------------------

/// Bitmask constants for page state flags.
pub mod page_flags {
    /// Page is clean: no pending writes.
    pub const CLEAN: u8 = 0;
    /// Page has been modified and is not yet written back.
    pub const DIRTY: u8 = 1 << 0;
    /// Page is currently being written back to backing storage.
    pub const WRITEBACK: u8 = 1 << 1;
    /// Page is locked for exclusive access (e.g., during read-fill).
    pub const LOCKED: u8 = 1 << 2;
    /// Page is pinned (cannot be evicted).
    pub const PINNED: u8 = 1 << 3;
    /// Page carries a retained writeback error and must not be reported clean.
    pub const WRITEBACK_ERROR: u8 = 1 << 4;
}

/// Observable local lifecycle state for a cached page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageLifecycleState {
    /// Page has no dirty, writeback-pending, pinned, or retained-error state.
    Clean,
    /// Page is dirty and not currently in writeback.
    Dirty,
    /// Page is sealed into an active writeback batch.
    WritebackPending,
    /// Page retained a writeback error and remains non-clean until retry success.
    ErrorPoisoned,
}

// ---------------------------------------------------------------------------
// Page: a cached page buffer
// ---------------------------------------------------------------------------

/// A cached page holding a data buffer and state flags.
#[derive(Clone)]
pub struct Page {
    /// The key identifying this page.
    pub key: PageKey,
    /// The page data buffer (exactly `page_size` bytes when resident).
    pub data: Vec<u8>,
    /// Bitmask of [`page_flags`] constants.
    pub flags: u8,
}

impl Page {
    /// Create a new page with a zero-filled buffer of `page_size` bytes
    /// and the given key.
    #[must_use]
    pub fn new(key: PageKey, page_size: usize) -> Self {
        Self {
            key,
            data: vec![0u8; page_size],
            flags: page_flags::CLEAN,
        }
    }

    /// Returns `true` if the page is dirty.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.flags & page_flags::DIRTY != 0
    }

    /// Returns `true` if the page is in the writeback state.
    #[must_use]
    pub fn is_writeback(&self) -> bool {
        self.flags & page_flags::WRITEBACK != 0
    }

    /// Returns `true` if the page is locked.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.flags & page_flags::LOCKED != 0
    }

    /// Returns `true` if the page is pinned.
    #[must_use]
    pub fn is_pinned(&self) -> bool {
        self.flags & page_flags::PINNED != 0
    }

    /// Returns `true` if a previous writeback error is retained on this page.
    #[must_use]
    pub fn has_writeback_error(&self) -> bool {
        self.flags & page_flags::WRITEBACK_ERROR != 0
    }

    /// Returns `true` if the page is poisoned by a retained writeback error.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.has_writeback_error()
    }

    /// Returns `true` if the page carries no lifecycle or access flags.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.flags == page_flags::CLEAN
    }

    /// Return the reconciled lifecycle state for this page.
    #[must_use]
    pub fn lifecycle_state(&self) -> PageLifecycleState {
        if self.is_writeback() {
            PageLifecycleState::WritebackPending
        } else if self.has_writeback_error() {
            PageLifecycleState::ErrorPoisoned
        } else if self.is_dirty() {
            PageLifecycleState::Dirty
        } else {
            PageLifecycleState::Clean
        }
    }
}

impl fmt::Debug for Page {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Page")
            .field("key", &self.key)
            .field("len", &self.data.len())
            .field("flags", &self.flags)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Insert error
// ---------------------------------------------------------------------------

/// Reasons an insert may fail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InsertError {
    /// The page already exists in the cache.
    AlreadyExists,
    /// The cache is full and every page is dirty, writeback, or pinned —
    /// no clean page is available for eviction.
    AtCapacityNoCleanPages,
    /// A resource governor rejected the page admission.
    Budget(BudgetError),
}

impl fmt::Display for InsertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InsertError::AlreadyExists => write!(f, "page already exists"),
            InsertError::AtCapacityNoCleanPages => {
                write!(f, "cache full and no clean pages available for eviction")
            }
            InsertError::Budget(e) => write!(f, "page cache budget admission failed: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------

/// Error returned by [`PageCache::flush_dirty_range`] when a page write
/// fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageFlushError {
    /// I/O error during page write.
    IoError,
    /// No space to complete the write (ENOSPC).
    NoSpace,
    /// Operation was interrupted (EINTR).
    Interrupted,
}

impl fmt::Display for PageFlushError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PageFlushError::IoError => write!(f, "I/O error during page flush"),
            PageFlushError::NoSpace => write!(f, "no space during page flush"),
            PageFlushError::Interrupted => write!(f, "page flush interrupted"),
        }
    }
}

impl std::error::Error for PageFlushError {}

// ---------------------------------------------------------------------------
// WritebackToken: active writeback proof
// ---------------------------------------------------------------------------

/// A token proving an active writeback operation on a cached page.
///
/// Created by [`PageCache::start_writeback`].  The holder must consume it
/// via [`PageCache::complete_writeback_with_token`] or
/// [`PageCache::abort_writeback_with_token`].  The token carries the page
/// key so the caller can split writeback dispatch from completion without
/// repeating the inode/offset lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WritebackToken {
    pub key: PageKey,
}

// PageCacheInner — all mutable state behind the Mutex
// ---------------------------------------------------------------------------

struct PageCacheInner {
    pages: HashMap<PageKey, Page>,
    dirty_pages_by_inode: BTreeMap<u64, BTreeSet<u64>>,
    /// Front = LRU (oldest), back = MRU (newest).
    lru_order: VecDeque<PageKey>,
    max_pages: usize,
    page_size: usize,
    hits: u64,
    misses: u64,
    /// Count of pages currently in the writeback state.
    writeback_count: u64,
    evictions: u64,
    inserts: u64,
    governor: Option<Governor>,
}

impl PageCacheInner {
    fn new(max_pages: usize, page_size: usize) -> Self {
        Self {
            pages: HashMap::with_capacity(max_pages.min(1024)),
            dirty_pages_by_inode: BTreeMap::new(),
            lru_order: VecDeque::with_capacity(max_pages.min(1024)),
            max_pages,
            page_size,
            hits: 0,
            misses: 0,
            writeback_count: 0,
            evictions: 0,
            inserts: 0,
            governor: None,
        }
    }

    fn clean_page_category() -> BudgetCategory {
        budget_category_for_cache_level(CacheBudgetLevel::L1HotRead)
    }

    fn dirty_page_category() -> BudgetCategory {
        budget_category_for_cache_level(CacheBudgetLevel::L5DirtyWriteback)
    }

    fn budget_category_for_page(page: &Page) -> BudgetCategory {
        if page.is_dirty() {
            Self::dirty_page_category()
        } else {
            Self::clean_page_category()
        }
    }

    fn release_page_budget(&self, page: &Page) {
        if let Some(ref governor) = self.governor {
            governor.release(Self::budget_category_for_page(page), page.data.len() as u64);
        }
    }

    fn admit_page_budget(&self, page: &Page) -> Result<(), InsertError> {
        if let Some(ref governor) = self.governor {
            governor
                .admit(Self::budget_category_for_page(page), page.data.len() as u64)
                .map(|_| ())
                .map_err(InsertError::Budget)?;
        }
        Ok(())
    }

    fn transfer_page_budget(
        &self,
        from: BudgetCategory,
        to: BudgetCategory,
        size: u64,
    ) -> Result<(), BudgetError> {
        if let Some(ref governor) = self.governor {
            governor.transfer(from, to, size)?;
        }
        Ok(())
    }

    /// Touch the page identified by `key`: move it to the MRU end.
    fn touch_lru(&mut self, key: &PageKey) {
        if let Some(pos) = self.lru_order.iter().position(|k| k == key) {
            self.lru_order.remove(pos);
        }
        self.lru_order.push_back(*key);
    }

    /// Remove a key from the LRU order without touching.
    fn unlink_lru(&mut self, key: &PageKey) {
        if let Some(pos) = self.lru_order.iter().position(|k| k == key) {
            self.lru_order.remove(pos);
        }
    }

    fn dirty_page_count_for_inode(&self, inode: u64) -> usize {
        self.dirty_pages_by_inode
            .get(&inode)
            .map_or(0, |offsets| offsets.len())
    }

    fn record_dirty_page(&mut self, key: PageKey) {
        self.dirty_pages_by_inode
            .entry(key.inode)
            .or_default()
            .insert(key.offset);
    }

    fn forget_dirty_page(&mut self, key: PageKey) {
        let mut remove_entry = false;
        if let Some(offsets) = self.dirty_pages_by_inode.get_mut(&key.inode) {
            offsets.remove(&key.offset);
            if offsets.is_empty() {
                remove_entry = true;
            }
        }
        if remove_entry {
            self.dirty_pages_by_inode.remove(&key.inode);
        }
    }

    fn reconcile_lifecycle_indexes(&mut self) {
        let promote_to_dirty: Vec<u64> = self
            .pages
            .iter()
            .filter_map(|(key, page)| {
                let indexed_dirty = self
                    .dirty_pages_by_inode
                    .get(&key.inode)
                    .is_some_and(|offsets| offsets.contains(&key.offset));
                let must_be_dirty =
                    indexed_dirty || page.is_writeback() || page.has_writeback_error();
                (must_be_dirty && !page.is_dirty()).then_some(page.data.len() as u64)
            })
            .collect();
        for size in promote_to_dirty {
            let _ = self.transfer_page_budget(
                Self::clean_page_category(),
                Self::dirty_page_category(),
                size,
            );
        }

        let mut dirty_pages_by_inode: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        let mut writeback_count = 0u64;
        for (key, page) in &mut self.pages {
            let indexed_dirty = self
                .dirty_pages_by_inode
                .get(&key.inode)
                .is_some_and(|offsets| offsets.contains(&key.offset));
            if indexed_dirty || page.is_writeback() || page.has_writeback_error() {
                page.flags |= page_flags::DIRTY;
            }
            if page.is_writeback() {
                writeback_count = writeback_count.saturating_add(1);
            }
            if page.is_dirty() {
                dirty_pages_by_inode
                    .entry(key.inode)
                    .or_default()
                    .insert(key.offset);
            }
        }
        self.dirty_pages_by_inode = dirty_pages_by_inode;
        self.writeback_count = writeback_count;
    }

    /// Insert a page, evicting one clean page if at capacity.
    /// Returns the evicted page, if any.
    fn insert_page(&mut self, key: PageKey, page: Page) -> Result<Option<Page>, InsertError> {
        if self.pages.contains_key(&key) {
            return Err(InsertError::AlreadyExists);
        }
        // If at capacity, evict the oldest clean, unpinned page.
        let evicted = if self.pages.len() >= self.max_pages {
            match self.evict_one_inner() {
                Some(p) => {
                    self.evictions += 1;
                    Some(p)
                }
                None => return Err(InsertError::AtCapacityNoCleanPages),
            }
        } else {
            None
        };

        self.admit_page_budget(&page)?;
        if page.is_writeback() {
            self.writeback_count += 1;
        }

        self.lru_order.push_back(key);
        self.pages.insert(key, page);
        self.inserts += 1;
        Ok(evicted)
    }
    /// Evict the LRU page that is clean and not pinned.
    /// Walks from LRU tail (front of deque) and selects the first
    /// eligible page.
    ///
    /// Design choice: dirty pages are **skipped** during automatic
    /// capacity eviction.  They must be written back (via the
    /// writeback lifecycle) before they become evictable.  This
    /// prevents silent data loss from automatic eviction.
    fn evict_one_inner(&mut self) -> Option<Page> {
        self.reconcile_lifecycle_indexes();
        // Find the first eligible page from the LRU end.
        let idx = self
            .lru_order
            .iter()
            .position(|key| self.pages.get(key).is_some_and(Page::is_clean))?;

        let key = self.lru_order.remove(idx).unwrap();
        let removed = self.pages.remove(&key);
        if let Some(ref page) = removed {
            if page.is_writeback() {
                self.writeback_count = self.writeback_count.saturating_sub(1);
            }
            self.release_page_budget(page);
        }
        removed
    }

    /// Mark a page dirty by key.  Returns false if the page does not exist.
    fn mark_dirty_inner(&mut self, key: &PageKey) -> bool {
        let Some((became_dirty, size)) = self
            .pages
            .get(key)
            .map(|page| (!page.is_dirty(), page.data.len() as u64))
        else {
            return false;
        };
        if became_dirty
            && self
                .transfer_page_budget(
                    Self::clean_page_category(),
                    Self::dirty_page_category(),
                    size,
                )
                .is_err()
        {
            return false;
        }
        if let Some(page) = self.pages.get_mut(key) {
            page.flags |= page_flags::DIRTY;
        }
        if became_dirty {
            self.record_dirty_page(*key);
        }
        true
    }

    /// Clear the dirty flag on a page.  Returns false if the page does not exist.
    fn clear_dirty_inner(&mut self, key: &PageKey) -> bool {
        let Some((was_dirty, was_writeback, has_writeback_error, size)) =
            self.pages.get(key).map(|page| {
                (
                    page.is_dirty(),
                    page.is_writeback(),
                    page.has_writeback_error(),
                    page.data.len() as u64,
                )
            })
        else {
            return false;
        };
        if was_writeback || has_writeback_error {
            return false;
        }
        if was_dirty
            && self
                .transfer_page_budget(
                    Self::dirty_page_category(),
                    Self::clean_page_category(),
                    size,
                )
                .is_err()
        {
            return false;
        }
        if let Some(page) = self.pages.get_mut(key) {
            page.flags &= !page_flags::DIRTY;
        }
        if was_dirty {
            self.forget_dirty_page(*key);
        }
        true
    }

    /// Start writeback: pin a dirty page and set the writeback flag.
    /// Returns false if the page does not exist, is clean, or is already in writeback.
    fn start_writeback_inner(&mut self, key: &PageKey) -> bool {
        if let Some(page) = self.pages.get_mut(key) {
            if page.flags & page_flags::WRITEBACK != 0 {
                return false; // already in writeback
            }
            if page.flags & page_flags::DIRTY == 0 {
                return false;
            }
            page.flags |= page_flags::WRITEBACK | page_flags::PINNED;
            self.writeback_count += 1;
            true
        } else {
            false
        }
    }

    /// Complete writeback: clear writeback flag; if successful, also clear dirty.
    /// Unpins regardless of success.  Returns false if the page does not exist.
    fn complete_writeback_inner(&mut self, key: &PageKey, success: bool) -> bool {
        let clear_dirty = if let Some(page) = self.pages.get_mut(key) {
            if !page.is_writeback() {
                return false;
            }
            page.flags &= !page_flags::WRITEBACK;
            page.flags &= !page_flags::PINNED;
            self.writeback_count = self.writeback_count.saturating_sub(1);
            if success {
                page.flags &= !page_flags::WRITEBACK_ERROR;
                page.is_dirty()
            } else {
                page.flags |= page_flags::DIRTY | page_flags::WRITEBACK_ERROR;
                true
            }
        } else {
            return false;
        };
        if success && clear_dirty && !self.clear_dirty_inner(key) {
            return false;
        }
        if !success {
            self.record_dirty_page(*key);
        }
        true
    }

    /// Abort writeback: clear writeback flag and unpin, but preserve dirty.
    /// Returns false if the page does not exist.
    fn abort_writeback_inner(&mut self, key: &PageKey) -> bool {
        let preserve_dirty = if let Some(page) = self.pages.get_mut(key) {
            if !page.is_writeback() {
                return false;
            }
            page.flags &= !page_flags::WRITEBACK;
            self.writeback_count = self.writeback_count.saturating_sub(1);
            page.flags &= !page_flags::PINNED;
            page.is_dirty()
        } else {
            return false;
        };
        if preserve_dirty {
            self.record_dirty_page(*key);
        }
        true
    }

    /// Collect keys of all dirty pages.
    fn dirty_page_keys(&mut self) -> Vec<PageKey> {
        self.reconcile_lifecycle_indexes();
        self.dirty_pages_by_inode
            .iter()
            .flat_map(|(inode, offsets)| {
                offsets.iter().filter_map(|offset| {
                    let key = PageKey {
                        inode: *inode,
                        offset: *offset,
                    };
                    self.pages
                        .get(&key)
                        .is_some_and(Page::is_dirty)
                        .then_some(key)
                })
            })
            .collect()
    }

    /// Collect keys of all dirty pages for a given inode.
    fn dirty_page_keys_for_inode(&mut self, inode: u64) -> Vec<PageKey> {
        self.reconcile_lifecycle_indexes();
        if self.dirty_page_count_for_inode(inode) == 0 {
            return Vec::new();
        }
        self.dirty_pages_by_inode
            .get(&inode)
            .into_iter()
            .flat_map(|offsets| offsets.iter())
            .filter_map(|offset| {
                let key = PageKey {
                    inode,
                    offset: *offset,
                };
                self.pages
                    .get(&key)
                    .is_some_and(Page::is_dirty)
                    .then_some(key)
            })
            .collect()
    }

    /// Return true when `inode` has at least one dirty page.
    fn has_dirty_pages_for_inode(&mut self, inode: u64) -> bool {
        self.reconcile_lifecycle_indexes();
        if self.dirty_page_count_for_inode(inode) == 0 {
            return false;
        }
        self.dirty_pages_by_inode
            .get(&inode)
            .into_iter()
            .flat_map(|offsets| offsets.iter())
            .any(|offset| {
                let key = PageKey {
                    inode,
                    offset: *offset,
                };
                self.pages.get(&key).is_some_and(Page::is_dirty)
            })
    }

    /// Collect keys of all dirty pages for a given inode whose byte range
    /// [offset, offset + page_size) overlaps with [start, end).
    fn dirty_page_keys_in_range(&mut self, inode: u64, start: u64, end: u64) -> Vec<PageKey> {
        self.reconcile_lifecycle_indexes();
        if self.dirty_page_count_for_inode(inode) == 0 {
            return Vec::new();
        }
        let page_size = self.page_size as u64;
        let first_possible_offset = start.saturating_sub(page_size.saturating_sub(1));
        self.dirty_pages_by_inode
            .get(&inode)
            .into_iter()
            .flat_map(|offsets| offsets.range(first_possible_offset..end))
            .filter_map(|offset| {
                let key = PageKey {
                    inode,
                    offset: *offset,
                };
                let overlaps = key.offset < end && key.offset.saturating_add(page_size) > start;
                (overlaps && self.pages.get(&key).is_some_and(Page::is_dirty)).then_some(key)
            })
            .collect()
    }

    /// Return true when `inode` has at least one dirty page whose byte range
    /// [offset, offset + page_size) overlaps with [start, end).
    fn has_dirty_pages_in_range(&mut self, inode: u64, start: u64, end: u64) -> bool {
        self.reconcile_lifecycle_indexes();
        if start >= end || self.dirty_page_count_for_inode(inode) == 0 {
            return false;
        }
        let page_size = self.page_size as u64;
        let first_possible_offset = start.saturating_sub(page_size.saturating_sub(1));
        self.dirty_pages_by_inode
            .get(&inode)
            .into_iter()
            .flat_map(|offsets| offsets.range(first_possible_offset..end))
            .any(|offset| {
                let key = PageKey {
                    inode,
                    offset: *offset,
                };
                let overlaps = key.offset < end && key.offset.saturating_add(page_size) > start;
                overlaps && self.pages.get(&key).is_some_and(Page::is_dirty)
            })
    }

    /// Clear dirty flag on all pages for a given inode. Returns count cleared.
    fn clear_dirty_for_inode(&mut self, inode: u64) -> usize {
        self.reconcile_lifecycle_indexes();
        let dirty_count = self.dirty_page_count_for_inode(inode);
        if dirty_count == 0 {
            return 0;
        }
        let offsets: Vec<u64> = self
            .dirty_pages_by_inode
            .get(&inode)
            .into_iter()
            .flat_map(|offsets| offsets.iter().copied())
            .collect();
        let mut cleared = 0usize;
        for offset in offsets {
            let key = PageKey { inode, offset };
            if self.pages.get(&key).is_some_and(Page::is_dirty) && self.clear_dirty_inner(&key) {
                cleared += 1;
            }
        }
        cleared
    }

    /// Invalidate (remove) clean, unpinned, non-writeback pages whose byte
    /// range [offset, offset + page_size) overlaps with [start, end).
    /// Dirty, pinned, and writeback pages are preserved — their data must
    /// be flushed before they become invalidatable.
    ///
    /// Returns the count of pages removed.
    fn invalidate_range_inner(&mut self, inode: u64, start: u64, end: u64) -> usize {
        self.reconcile_lifecycle_indexes();
        let page_size = self.page_size as u64;
        let keys_to_remove: Vec<PageKey> = self
            .pages
            .iter()
            .filter(|(k, p)| {
                k.inode == inode && k.offset < end && k.offset + page_size > start && p.is_clean()
            })
            .map(|(k, _)| *k)
            .collect();
        let count = keys_to_remove.len();
        for key in &keys_to_remove {
            self.unlink_lru(key);
            if let Some(page) = self.pages.remove(key) {
                self.release_page_budget(&page);
            }
        }
        self.evictions += count as u64;
        count
    }

    fn len(&self) -> usize {
        self.pages.len()
    }

    fn is_full(&self) -> bool {
        self.pages.len() >= self.max_pages
    }

    /// Number of pages currently in the writeback state.
    fn writeback_queue_len(&mut self) -> usize {
        self.reconcile_lifecycle_indexes();
        self.writeback_count as usize
    }

    /// Collect keys of all pages currently in the writeback state.
    fn writeback_queue_keys(&mut self) -> Vec<PageKey> {
        self.reconcile_lifecycle_indexes();
        self.pages
            .iter()
            .filter(|(_, p)| p.is_writeback())
            .map(|(k, _)| *k)
            .collect()
    }

    /// Truncate invalidation: remove ALL pages (including dirty) for the
    /// given inode whose offset is at or beyond `new_size`.  Pages that
    /// overlap the truncation boundary are also removed.
    ///
    /// Returns (pages_removed, dirty_pages_removed).
    fn truncate_invalidate_inner(&mut self, inode: u64, new_size: u64) -> (usize, usize) {
        let page_size = self.page_size as u64;
        let keys: Vec<PageKey> = self
            .pages
            .iter()
            .filter(|(k, _)| k.inode == inode && k.offset.saturating_add(page_size) > new_size)
            .map(|(k, _)| *k)
            .collect();

        let mut total = 0usize;
        let mut dirty = 0usize;
        for key in &keys {
            if let Some(page) = self.pages.remove(key) {
                self.unlink_lru(key);
                if page.is_dirty() {
                    dirty += 1;
                }
                if page.is_writeback() {
                    self.writeback_count = self.writeback_count.saturating_sub(1);
                }
                self.forget_dirty_page(*key);
                self.release_page_budget(&page);
                total += 1;
            }
        }
        self.evictions += total as u64;
        (total, dirty)
    }

    /// Unlink invalidation: remove ALL pages for the given inode,
    /// including dirty and writeback pages.  The file no longer exists.
    ///
    /// Returns (pages_removed, dirty_pages_removed).
    fn unlink_invalidate_inner(&mut self, inode: u64) -> (usize, usize) {
        let keys: Vec<PageKey> = self
            .pages
            .iter()
            .filter(|(k, _)| k.inode == inode)
            .map(|(k, _)| *k)
            .collect();

        let mut total = 0usize;
        let mut dirty = 0usize;
        for key in &keys {
            if let Some(page) = self.pages.remove(key) {
                self.unlink_lru(key);
                if page.is_dirty() {
                    dirty += 1;
                }
                if page.is_writeback() {
                    self.writeback_count = self.writeback_count.saturating_sub(1);
                }
                self.forget_dirty_page(*key);
                self.release_page_budget(&page);
                total += 1;
            }
        }
        self.evictions += total as u64;
        (total, dirty)
    }

    /// Invalidate all clean, unpinned, non-writeback pages across the
    /// entire cache.  Returns the count of pages removed.
    fn invalidate_all_clean_inner(&mut self) -> usize {
        self.reconcile_lifecycle_indexes();
        let keys: Vec<PageKey> = self
            .pages
            .iter()
            .filter(|(_, p)| p.is_clean())
            .map(|(k, _)| *k)
            .collect();
        let count = keys.len();
        for key in &keys {
            self.unlink_lru(key);
            if let Some(page) = self.pages.remove(key) {
                self.release_page_budget(&page);
            }
        }
        self.evictions += count as u64;
        count
    }
}

// ---------------------------------------------------------------------------
// PageHandle — locked access to a cached page
// ---------------------------------------------------------------------------

/// A handle to a page in the cache.
///
/// Holds the internal cache lock, guaranteeing exclusive access to the
/// page while the handle is alive.  Drop the handle to release the lock.
///
/// Callers must not call back into `PageCache` methods while holding a
/// `PageHandle`, as that would deadlock on the internal mutex.
pub struct PageHandle<'a> {
    guard: std::sync::MutexGuard<'a, PageCacheInner>,
    key: PageKey,
}

impl<'a> PageHandle<'a> {
    /// The key identifying this page.
    #[must_use]
    pub fn key(&self) -> PageKey {
        self.key
    }

    /// Immutable access to the page data buffer.
    ///
    /// # Panics
    ///
    /// Panics if the page has been removed from the cache (should not happen
    /// while the handle is alive).
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self
            .guard
            .pages
            .get(&self.key)
            .expect("PageHandle: page not found")
            .data
    }

    /// Mutable access to the page data buffer.
    ///
    /// # Panics
    ///
    /// Panics if the page has been removed from the cache (should not happen
    /// while the handle is alive).
    #[must_use]
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self
            .guard
            .pages
            .get_mut(&self.key)
            .expect("PageHandle: page not found")
            .data
    }

    /// Returns `true` if the page is dirty.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.guard
            .pages
            .get(&self.key)
            .is_some_and(|p| p.is_dirty())
    }

    /// Returns `true` if the page is in the writeback state.
    #[must_use]
    pub fn is_writeback(&self) -> bool {
        self.guard
            .pages
            .get(&self.key)
            .is_some_and(|p| p.is_writeback())
    }

    /// Returns `true` if the page is pinned.
    #[must_use]
    pub fn is_pinned(&self) -> bool {
        self.guard
            .pages
            .get(&self.key)
            .is_some_and(|p| p.is_pinned())
    }

    /// Returns `true` if this page carries a retained writeback error.
    #[must_use]
    pub fn has_writeback_error(&self) -> bool {
        self.guard
            .pages
            .get(&self.key)
            .is_some_and(|p| p.has_writeback_error())
    }

    /// Return the reconciled lifecycle state for this page.
    #[must_use]
    pub fn lifecycle_state(&self) -> PageLifecycleState {
        self.guard
            .pages
            .get(&self.key)
            .map_or(PageLifecycleState::Clean, Page::lifecycle_state)
    }

    /// Returns the raw flags byte.
    #[must_use]
    pub fn flags(&self) -> u8 {
        self.guard.pages.get(&self.key).map_or(0, |p| p.flags)
    }

    /// Mark this page dirty.
    pub fn mark_dirty(&mut self) {
        let key = self.key;
        self.guard.mark_dirty_inner(&key);
    }

    /// Clear the dirty flag on this page.
    pub fn clear_dirty(&mut self) {
        let key = self.key;
        self.guard.clear_dirty_inner(&key);
    }

    /// Start writeback on this page: pin and set writeback flag.
    /// Returns `true` if the transition succeeded, `false` if already
    /// in writeback.
    pub fn start_writeback(&mut self) -> bool {
        let key = self.key;
        self.guard.start_writeback_inner(&key)
    }

    /// Complete writeback.  If `success`, the page is marked clean.
    /// The writeback flag and pin are cleared regardless.
    pub fn complete_writeback(&mut self, success: bool) {
        let key = self.key;
        self.guard.complete_writeback_inner(&key, success);
    }

    /// Abort writeback: clear writeback flag and unpin, but leave the
    /// dirty flag intact.
    pub fn abort_writeback(&mut self) {
        let key = self.key;
        self.guard.abort_writeback_inner(&key);
    }
}

// ---------------------------------------------------------------------------
// PageCache — public API
// ---------------------------------------------------------------------------

/// A synchronous page cache with LRU eviction, dirty tracking, and
/// writeback coordination.
///
/// All methods take `&self` — concurrency is handled by the internal
/// [`Mutex`].  The returned [`PageHandle`] holds the lock; drop it
/// promptly and do not call back into `PageCache` while holding a handle.
///
/// # Examples
///
/// ```ignore
/// let cache = PageCache::new(1024, 4096);
/// let handle = cache.insert(1, 0).expect("insert failed");
/// assert_eq!(handle.data().len(), 4096);
/// ```
pub struct PageCache {
    inner: Mutex<PageCacheInner>,
}

impl PageCache {
    /// Create a new page cache.
    ///
    /// `max_pages` is the maximum number of resident pages.  `page_size`
    /// is the size in bytes of each page buffer.
    #[must_use]
    pub fn new(max_pages: usize, page_size: usize) -> Self {
        Self {
            inner: Mutex::new(PageCacheInner::new(max_pages, page_size)),
        }
    }

    /// Create a page cache with resource-governor accounting enabled.
    #[must_use]
    pub fn with_governor(max_pages: usize, page_size: usize, governor: Governor) -> Self {
        let cache = Self::new(max_pages, page_size);
        cache.set_governor(governor);
        cache
    }

    /// Attach a resource governor for clean page and dirty byte accounting.
    ///
    /// Clean resident pages are charged to L1 hot-read [`BudgetCategory::DataCache`].
    /// Dirty and writeback pages transfer to L5 [`BudgetCategory::DirtyBytes`]
    /// until flush/writeback completion makes them clean again.
    pub fn set_governor(&self, governor: Governor) {
        self.inner.lock().unwrap().governor = Some(governor);
    }

    // ── Insert ──────────────────────────────────────────────────────

    /// Insert a new page for the given inode and offset.
    ///
    /// The page buffer is allocated zero-filled.  If the cache is at
    /// capacity, the oldest clean, unpinned page is evicted.  Returns a
    /// [`PageHandle`] on success, or an [`InsertError`] on failure.
    ///
    /// # Errors
    ///
    /// - [`InsertError::AlreadyExists`] if a page already exists at this key.
    /// - [`InsertError::AtCapacityNoCleanPages`] if the cache is full and
    ///   no clean page is evictable.
    pub fn insert(&self, inode: u64, offset: u64) -> Result<PageKey, InsertError> {
        let key = PageKey { inode, offset };
        let mut inner = self.inner.lock().unwrap();
        let page = Page::new(key, inner.page_size);

        match inner.insert_page(key, page) {
            Ok(evicted) => {
                // If a page was evicted, log or handle evicted page.
                let _ = evicted;
                Ok(key)
            }
            Err(e) => Err(e),
        }
    }

    // ── Lookup ──────────────────────────────────────────────────────

    /// Look up a page by inode and offset.
    ///
    /// Returns a [`PageHandle`] on hit, or `None` on miss.  On a hit,
    /// the page is moved to the MRU position.
    pub fn lookup(&self, inode: u64, offset: u64) -> Option<PageHandle<'_>> {
        let key = PageKey { inode, offset };
        let mut guard = self.inner.lock().unwrap();
        if guard.pages.contains_key(&key) {
            guard.touch_lru(&key);
            guard.hits += 1;
        } else {
            guard.misses += 1;
            return None;
        }
        Some(PageHandle { guard, key })
    }

    // ── Remove ──────────────────────────────────────────────────────

    /// Remove a page from the cache, returning it if present.
    pub fn remove(&self, inode: u64, offset: u64) -> Option<Page> {
        let key = PageKey { inode, offset };
        let mut inner = self.inner.lock().unwrap();
        let page = inner.pages.remove(&key)?;
        inner.unlink_lru(&key);
        if page.is_dirty() {
            inner.forget_dirty_page(key);
        }
        if page.is_writeback() {
            inner.writeback_count = inner.writeback_count.saturating_sub(1);
        }
        inner.release_page_budget(&page);
        Some(page)
    }

    /// Remove all pages belonging to `inode` from the cache.
    ///
    /// Returns the number of pages removed.  Used by the FUSE daemon to
    /// invalidate read-cached pages after a write so that subsequent
    /// reads through a different file descriptor see the new data
    /// (close-to-open consistency).
    pub fn remove_pages_for_inode(&self, inode: u64) -> usize {
        let mut inner = self.inner.lock().unwrap();
        let keys: Vec<PageKey> = inner
            .pages
            .keys()
            .filter(|k| k.inode == inode)
            .copied()
            .collect();
        let count = keys.len();
        for key in &keys {
            inner.unlink_lru(key);
            if let Some(page) = inner.pages.remove(key) {
                if page.is_writeback() {
                    inner.writeback_count = inner.writeback_count.saturating_sub(1);
                }
                inner.release_page_budget(&page);
            }
        }
        inner.dirty_pages_by_inode.remove(&inode);
        count
    }

    /// Patch already-resident clean mirrors overlapping `[offset, offset + data.len())`.
    ///
    /// This does not allocate missing pages. It is intended for authoritative
    /// write-through paths that have already reconciled dirty overlap and need
    /// resident mirrors to stay coherent without turning absent sparse pages
    /// into cache entries. Patched pages are left clean.
    #[must_use]
    pub fn patch_resident_clean_range(&self, inode: u64, offset: u64, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }

        let mut inner = self.inner.lock().unwrap();
        let page_size = inner.page_size as u64;
        if page_size == 0 {
            return 0;
        }
        let Ok(data_len) = u64::try_from(data.len()) else {
            return 0;
        };
        let Some(end) = offset.checked_add(data_len) else {
            return 0;
        };

        let mut patched = 0usize;
        let mut cleared_dirty = Vec::new();
        let mut poff = (offset / page_size) * page_size;
        while poff < end {
            let key = PageKey {
                inode,
                offset: poff,
            };
            if inner.pages.contains_key(&key) {
                inner.touch_lru(&key);
                inner.hits = inner.hits.saturating_add(1);

                let copy_start = offset.max(poff);
                let copy_end = end.min(poff.saturating_add(page_size));
                if copy_start < copy_end {
                    let src_start = usize::try_from(copy_start - offset)
                        .expect("source start is bounded by data length");
                    let dst_start = usize::try_from(copy_start - poff)
                        .expect("destination start is bounded by page size");
                    let copy_len = usize::try_from(copy_end - copy_start)
                        .expect("copy length is bounded by page size");
                    if let Some(page) = inner.pages.get_mut(&key) {
                        if src_start < data.len()
                            && dst_start < page.data.len()
                            && copy_len <= data.len().saturating_sub(src_start)
                            && copy_len <= page.data.len().saturating_sub(dst_start)
                        {
                            page.data[dst_start..dst_start + copy_len]
                                .copy_from_slice(&data[src_start..src_start + copy_len]);
                            if page.is_dirty() {
                                cleared_dirty.push(key);
                            }
                            patched = patched.saturating_add(1);
                        }
                    }
                }
            } else {
                inner.misses = inner.misses.saturating_add(1);
            }
            poff = poff.saturating_add(page_size);
        }

        for key in cleared_dirty {
            inner.clear_dirty_inner(&key);
        }
        patched
    }

    // ── Eviction ────────────────────────────────────────────────────

    /// Evict the oldest clean, unpinned page.
    ///
    /// Returns `Some(Page)` if a page was evicted, or `None` if the
    /// cache is empty or all pages are dirty/writeback/pinned.
    ///
    /// This is the same eviction policy used during automatic
    /// capacity-triggered eviction on insert.
    pub fn evict_one(&self) -> Option<Page> {
        let mut inner = self.inner.lock().unwrap();
        let evicted = inner.evict_one_inner();
        if evicted.is_some() {
            inner.evictions += 1;
        }
        evicted
    }

    // ── Dirty tracking (convenience, lock-acquiring) ────────────────

    /// Mark the page at `(inode, offset)` dirty.  Returns `true` if the
    /// page existed.
    ///
    /// Prefer using [`PageHandle::mark_dirty`] directly when you already
    /// hold a handle.
    pub fn mark_dirty(&self, inode: u64, offset: u64) -> bool {
        let key = PageKey { inode, offset };
        self.inner.lock().unwrap().mark_dirty_inner(&key)
    }

    /// Clear the dirty flag on the page at `(inode, offset)`.  Returns
    /// `true` if the page existed.
    pub fn clear_dirty(&self, inode: u64, offset: u64) -> bool {
        let key = PageKey { inode, offset };
        self.inner.lock().unwrap().clear_dirty_inner(&key)
    }

    // ── Writeback coordination (convenience, lock-acquiring) ────────

    /// Start writeback on the page at `(inode, offset)`: pin a dirty page and
    /// set its writeback flag. Returns `true` on success, `false` if the page
    /// does not exist, is clean, or is already in writeback.
    pub fn start_writeback(&self, inode: u64, offset: u64) -> bool {
        let key = PageKey { inode, offset };
        self.inner.lock().unwrap().start_writeback_inner(&key)
    }

    /// Complete writeback: clear writeback flag and unpin.  If
    /// `success`, also clear dirty.  Returns `true` if the page existed.
    pub fn complete_writeback(&self, inode: u64, offset: u64, success: bool) -> bool {
        let key = PageKey { inode, offset };
        self.inner
            .lock()
            .unwrap()
            .complete_writeback_inner(&key, success)
    }

    /// Abort writeback: clear writeback flag and unpin without clearing
    /// dirty.  Returns `true` if the page existed.
    pub fn abort_writeback(&self, inode: u64, offset: u64) -> bool {
        let key = PageKey { inode, offset };
        self.inner.lock().unwrap().abort_writeback_inner(&key)
    }

    // ── Dirty page iteration ────────────────────────────────────────

    /// Return the keys of all dirty pages.
    ///
    /// The caller can then use [`PageCache::lookup`] to obtain handles
    /// to individual pages for writeback.
    #[must_use]
    pub fn dirty_pages(&self) -> Vec<PageKey> {
        self.inner.lock().unwrap().dirty_page_keys()
    }

    /// Return the keys of all dirty pages for a given inode.
    ///
    /// The caller can then use [`PageCache::lookup`] to obtain handles
    /// to individual pages for writeback.
    #[must_use]
    pub fn dirty_pages_for_inode(&self, inode: u64) -> Vec<PageKey> {
        self.inner.lock().unwrap().dirty_page_keys_for_inode(inode)
    }

    /// Return true when the given inode has at least one dirty page.
    #[must_use]
    pub fn has_dirty_pages_for_inode(&self, inode: u64) -> bool {
        self.inner.lock().unwrap().has_dirty_pages_for_inode(inode)
    }

    /// Return the keys of all dirty pages for a given inode whose byte
    /// range overlaps with `[start, end)`.
    ///
    /// A page at offset `P` covers bytes `[P, P + page_size)`.  It
    /// overlaps with `[start, end)` when `P < end` and
    /// `P + page_size > start`.
    ///
    /// The caller can then use [`PageCache::lookup`] to obtain handles
    /// to individual pages for writeback.
    #[must_use]
    pub fn dirty_pages_in_range(&self, inode: u64, start: u64, end: u64) -> Vec<PageKey> {
        self.inner
            .lock()
            .unwrap()
            .dirty_page_keys_in_range(inode, start, end)
    }

    /// Return true when the given inode has at least one dirty page whose
    /// byte range overlaps with `[start, end)`.
    ///
    /// A page at offset `P` covers bytes `[P, P + page_size)`.  It
    /// overlaps with `[start, end)` when `P < end` and
    /// `P + page_size > start`.
    #[must_use]
    pub fn has_dirty_pages_in_range(&self, inode: u64, start: u64, end: u64) -> bool {
        self.inner
            .lock()
            .unwrap()
            .has_dirty_pages_in_range(inode, start, end)
    }

    /// Flush dirty pages in the byte range `[start, end)` for the given
    /// inode, writing each dirty page through `write_page` and marking it
    /// clean on success.
    ///
    /// On failure, dirty pages that were already successfully written
    /// are marked clean; remaining dirty pages are left with their dirty
    /// flag set for the next retry.
    ///
    /// # Errors
    ///
    /// Returns the first error from `write_page` if any write fails.
    pub fn flush_dirty_range<F>(
        &self,
        inode: u64,
        start: u64,
        end: u64,
        mut write_page: F,
    ) -> Result<(), PageFlushError>
    where
        F: FnMut(u64, &[u8]) -> Result<(), PageFlushError>,
    {
        let keys = self.dirty_pages_in_range(inode, start, end);
        if keys.is_empty() {
            return Ok(());
        }

        let mut first_error: Option<PageFlushError> = None;
        for key in &keys {
            if !self.start_writeback(key.inode, key.offset) {
                continue;
            }
            if let Some(page_handle) = self.lookup(key.inode, key.offset) {
                let data = page_handle.data().to_vec();
                drop(page_handle);
                match write_page(key.offset, &data) {
                    Ok(()) => {
                        self.complete_writeback(key.inode, key.offset, true);
                    }
                    Err(e) => {
                        self.complete_writeback(key.inode, key.offset, false);
                        if first_error.is_none() {
                            first_error = Some(e);
                        }
                        break;
                    }
                }
            } else {
                // Page was evicted between dirty_pages_in_range and lookup.
                self.complete_writeback(key.inode, key.offset, false);
            }
        }

        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Clear the dirty flag on all pages for a given inode.
    ///
    /// Returns the number of pages whose dirty flag was cleared.
    /// This is useful after a successful fsync to reset writeback
    /// state without evicting the pages.
    pub fn clear_dirty_for_inode(&self, inode: u64) -> usize {
        self.inner.lock().unwrap().clear_dirty_for_inode(inode)
    }

    /// Invalidate (remove) clean, unpinned, non-writeback pages whose byte
    /// range [offset, offset + page_size) overlaps with [start, end).
    /// Dirty, pinned, and writeback pages are preserved.
    ///
    /// Returns the count of pages removed.
    ///
    /// This is the primary coherency primitive for mmap lease revocation:
    /// when a conflicting lease is granted to another client, this method
    /// evicts the stale clean pages so that subsequent accesses fault and
    /// fetch the new authoritative data.
    pub fn invalidate_range(&self, inode: u64, start: u64, end: u64) -> usize {
        let mut inner = self.inner.lock().unwrap();
        inner.invalidate_range_inner(inode, start, end)
    }

    /// Invalidate all clean pages for an inode (entire file).
    /// Convenience wrapper around [`invalidate_range`] with [0, u64::MAX).
    pub fn invalidate_inode(&self, inode: u64) -> usize {
        self.invalidate_range(inode, 0, u64::MAX)
    }

    // ── Capacity & stats ────────────────────────────────────────────

    /// Number of resident pages.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    /// Returns `true` if the cache has no pages.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Maximum number of resident pages.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.lock().unwrap().max_pages
    }

    /// Page size in bytes.
    #[must_use]
    pub fn page_size(&self) -> usize {
        self.inner.lock().unwrap().page_size
    }

    /// Returns `true` if the cache is at capacity.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.inner.lock().unwrap().is_full()
    }

    /// Total cache hits since creation.
    #[must_use]
    pub fn hit_count(&self) -> u64 {
        self.inner.lock().unwrap().hits
    }

    /// Total cache misses since creation.
    #[must_use]
    pub fn miss_count(&self) -> u64 {
        self.inner.lock().unwrap().misses
    }

    /// Total evictions since creation.
    #[must_use]
    pub fn eviction_count(&self) -> u64 {
        self.inner.lock().unwrap().evictions
    }

    /// Total inserts since creation.
    #[must_use]
    pub fn insert_count(&self) -> u64 {
        self.inner.lock().unwrap().inserts
    }

    // ── WritebackToken lifecycle ─────────────────────────────────

    /// Start writeback on the page at `(inode, offset)` and return a
    /// [`WritebackToken`] that proves the writeback is active.  The
    /// token must be consumed by [`complete_writeback_with_token`] or
    /// [`abort_writeback_with_token`].
    ///
    /// Returns `None` if the page does not exist or is already in
    /// writeback.
    #[must_use]
    pub fn start_writeback_token(&self, inode: u64, offset: u64) -> Option<WritebackToken> {
        let key = PageKey { inode, offset };
        let mut inner = self.inner.lock().unwrap();
        if inner.start_writeback_inner(&key) {
            Some(WritebackToken { key })
        } else {
            None
        }
    }

    /// Complete writeback for the page referenced by `token`.  If
    /// `success`, the page is marked clean.  The writeback flag and pin
    /// are cleared regardless.
    ///
    /// # Panics
    ///
    /// Panics if the page has been evicted (should not happen while the
    /// token is alive).
    pub fn complete_writeback_with_token(&self, token: WritebackToken, success: bool) {
        self.inner
            .lock()
            .unwrap()
            .complete_writeback_inner(&token.key, success);
    }

    /// Abort writeback for the page referenced by `token`.  The
    /// writeback flag and pin are cleared, but the dirty flag is
    /// preserved so the page remains eligible for retry.
    pub fn abort_writeback_with_token(&self, token: WritebackToken) {
        self.inner.lock().unwrap().abort_writeback_inner(&token.key);
    }

    /// Number of pages currently in the writeback state.
    #[must_use]
    pub fn writeback_queue_size(&self) -> usize {
        self.inner.lock().unwrap().writeback_queue_len()
    }

    /// Snapshotted keys of all pages currently in the writeback state.
    #[must_use]
    pub fn writeback_queue_keys(&self) -> Vec<PageKey> {
        self.inner.lock().unwrap().writeback_queue_keys()
    }

    // ── Truncate / unlink invalidation ───────────────────────────

    /// Truncate invalidation: remove ALL pages for `inode` whose offset
    /// is at or beyond `new_size`.  Unlike [`invalidate_range`], this
    /// removes dirty pages too — data beyond EOF after truncate is
    /// meaningless.
    ///
    /// Pages that overlap the truncation boundary (offset < new_size <
    /// offset + page_size) are also removed.
    ///
    /// Returns `(pages_removed, dirty_pages_removed)`.
    pub fn truncate_invalidate(&self, inode: u64, new_size: u64) -> (usize, usize) {
        self.inner
            .lock()
            .unwrap()
            .truncate_invalidate_inner(inode, new_size)
    }

    /// Unlink invalidation: remove ALL pages (including dirty and
    /// writeback) for `inode`.  Called when the inode is deleted.
    ///
    /// Returns `(pages_removed, dirty_pages_removed)`.
    pub fn unlink_invalidate(&self, inode: u64) -> (usize, usize) {
        self.inner.lock().unwrap().unlink_invalidate_inner(inode)
    }

    /// Number of resident pages for a given inode.
    #[must_use]
    pub fn page_count_for_inode(&self, inode: u64) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.pages.iter().filter(|(k, _)| k.inode == inode).count()
    }

    /// Return the keys of all resident pages for a given inode.
    #[must_use]
    pub fn page_keys_for_inode(&self, inode: u64) -> Vec<PageKey> {
        let inner = self.inner.lock().unwrap();
        inner
            .pages
            .iter()
            .filter(|(k, _)| k.inode == inode)
            .map(|(k, _)| *k)
            .collect()
    }

    /// Invalidate all clean, unpinned, non-writeback pages across the
    /// entire cache.  Dirty, pinned, and writeback pages are preserved.
    ///
    /// Returns the count of pages removed.
    pub fn invalidate_all_clean(&self) -> usize {
        self.inner.lock().unwrap().invalidate_all_clean_inner()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ReadCache bridge for workers-io integration
// ---------------------------------------------------------------------------

#[cfg(feature = "adapter-workers-io")]
use tidefs_posix_filesystem_adapter_workers_io::ReadCache;

#[cfg(feature = "adapter-workers-io")]
impl ReadCache for PageCache {
    fn lookup(&self, ino: u64, offset: u64, length: u64) -> Option<Vec<u8>> {
        // Align offset down to page size
        let page_size = self.page_size() as u64;
        let page_offset = (offset / page_size) * page_size;
        let handle = self.lookup(ino, page_offset)?;
        let page_data = handle.data();
        let start_in_page = (offset - page_offset) as usize;
        let end_in_page = start_in_page
            .saturating_add(length as usize)
            .min(page_data.len());
        if start_in_page >= page_data.len() {
            return Some(Vec::new());
        }
        Some(page_data[start_in_page..end_in_page].to_vec())
    }

    fn insert(&mut self, ino: u64, offset: u64, data: &[u8]) {
        let page_size = self.page_size() as u64;
        let page_offset = (offset / page_size) * page_size;
        let start_in_page = (offset - page_offset) as usize;

        // Best-effort insert: if the page already exists we reuse it,
        // otherwise we allocate a new page.
        let _ = PageCache::insert(self, ino, page_offset);

        // Acquire the page handle and copy data in.
        if let Some(mut handle) = self.lookup(ino, page_offset) {
            let dst = handle.data_mut();
            let copy_end = start_in_page.saturating_add(data.len()).min(dst.len());
            if start_in_page < copy_end {
                let copy_len = copy_end - start_in_page;
                dst[start_in_page..start_in_page + copy_len].copy_from_slice(&data[..copy_len]);
            }
            // Page stays clean since we are filling from authoritative storage.
        }
    }
}

// ---------------------------------------------------------------------------
// CacheInvalidationSubscriber impl for PageCache
// ---------------------------------------------------------------------------

impl crate::CacheInvalidationSubscriber for PageCache {
    fn on_invalidate_range(&self, inode: u64, start: u64, end: u64) -> usize {
        self.invalidate_range(inode, start, end)
    }

    fn on_invalidate_inode(&self, inode: u64) -> usize {
        self.invalidate_inode(inode)
    }

    fn on_invalidate_all(&self) -> usize {
        self.invalidate_all_clean()
    }

    fn subscriber_name(&self) -> &'static str {
        "tidefs-cache-core::PageCache"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    const PAGE_SIZE: usize = 4096;

    // ── Helper ──────────────────────────────────────────────────────

    fn new_cache(cap: usize) -> PageCache {
        PageCache::new(cap, PAGE_SIZE)
    }

    fn data_dirty_governor() -> Governor {
        Governor::new(crate::GovernorConfig {
            total_budget_bytes: (PAGE_SIZE as u64) * 8,
            data_cache_fraction: 0.5,
            meta_cache_fraction: 0.0,
            dirty_bytes_fraction: 0.5,
            inode_state_fraction: 0.0,
            cluster_queues_fraction: 0.0,
            misc_fraction: 0.0,
            auto_tune: false,
        })
        .unwrap()
    }

    #[test]
    fn governor_tracks_clean_dirty_and_unlink_release() {
        let governor = data_dirty_governor();
        let cache = PageCache::with_governor(4, PAGE_SIZE, governor.clone());

        cache.insert(1, 0).unwrap();
        assert_eq!(
            governor.category_used(BudgetCategory::DataCache),
            PAGE_SIZE as u64
        );
        assert_eq!(governor.category_used(BudgetCategory::DirtyBytes), 0);

        assert!(cache.mark_dirty(1, 0));
        assert_eq!(governor.category_used(BudgetCategory::DataCache), 0);
        assert_eq!(
            governor.category_used(BudgetCategory::DirtyBytes),
            PAGE_SIZE as u64
        );

        let token = cache.start_writeback_token(1, 0).unwrap();
        cache.complete_writeback_with_token(token, true);
        assert_eq!(
            governor.category_used(BudgetCategory::DataCache),
            PAGE_SIZE as u64
        );
        assert_eq!(governor.category_used(BudgetCategory::DirtyBytes), 0);

        let (removed, dirty_removed) = cache.unlink_invalidate(1);
        assert_eq!((removed, dirty_removed), (1, 0));
        assert_eq!(governor.category_used(BudgetCategory::DataCache), 0);
        assert_eq!(governor.category_used(BudgetCategory::DirtyBytes), 0);
    }

    // ── Test 1: insert + lookup round-trip ───────────────────────────

    #[test]
    fn insert_lookup_round_trip() {
        let cache = new_cache(10);

        cache.insert(42, 0).expect("insert should succeed");
        let handle = cache
            .lookup(42, 0)
            .expect("lookup after insert should succeed");
        assert_eq!(handle.data().len(), PAGE_SIZE);
        assert!(!handle.is_dirty());
        assert!(!handle.is_writeback());
        assert!(!handle.is_pinned());
        drop(handle);

        let found = cache.lookup(42, 0);
        assert!(found.is_some(), "lookup after insert should find page");
        let h = found.unwrap();
        assert_eq!(h.key().inode, 42);
        assert_eq!(h.key().offset, 0);
        assert_eq!(h.data().len(), PAGE_SIZE);
    }

    #[test]
    fn lookup_miss_returns_none() {
        let cache = new_cache(10);
        assert!(cache.lookup(1, 0).is_none());
        assert!(cache.lookup(99, 4096).is_none());
        assert_eq!(cache.miss_count(), 2);
    }

    #[test]
    fn patch_resident_clean_range_skips_missing_pages() {
        let cache = new_cache(10);
        cache.insert(1, 0).expect("insert first page");
        cache.insert(1, 8192).expect("insert third page");

        {
            let mut page = cache.lookup(1, 0).expect("lookup first page");
            page.data_mut().fill(0x11);
        }
        {
            let mut page = cache.lookup(1, 8192).expect("lookup third page");
            page.data_mut().fill(0x33);
            page.mark_dirty();
        }

        let payload = vec![0xAA; 8192];
        assert_eq!(cache.patch_resident_clean_range(1, 1024, &payload), 2);
        assert!(
            cache.lookup(1, 4096).is_none(),
            "missing middle page must not be allocated"
        );

        {
            let page = cache.lookup(1, 0).expect("lookup patched first page");
            assert_eq!(&page.data()[..1024], &[0x11; 1024]);
            assert_eq!(&page.data()[1024..], &[0xAA; PAGE_SIZE - 1024]);
            assert!(!page.is_dirty());
        }
        {
            let page = cache.lookup(1, 8192).expect("lookup patched third page");
            assert_eq!(&page.data()[..1024], &[0xAA; 1024]);
            assert_eq!(&page.data()[1024..], &[0x33; PAGE_SIZE - 1024]);
            assert!(
                !page.is_dirty(),
                "authoritative clean patch clears any dirty resident mirror"
            );
        }
        assert!(cache.dirty_pages_for_inode(1).is_empty());
    }

    // ── Test 2: distinct keys, no cross-talk ────────────────────────

    #[test]
    fn distinct_keys_no_cross_talk() {
        let cache = new_cache(10);

        // Insert pages for inodes 1, 2, 3 all at offset 0
        cache.insert(1, 0).unwrap();
        cache.insert(2, 0).unwrap();
        cache.insert(3, 0).unwrap();

        // Also insert different offsets
        cache.insert(1, 4096).unwrap();
        cache.insert(1, 8192).unwrap();

        // Lookup each and verify correct key
        for (ino, off) in &[(1, 0), (2, 0), (3, 0), (1, 4096), (1, 8192)] {
            let h = cache.lookup(*ino, *off).expect("should find page");
            assert_eq!(h.key().inode, *ino);
            assert_eq!(h.key().offset, *off);
        }

        // Non-existent keys
        assert!(cache.lookup(4, 0).is_none());
        assert!(cache.lookup(1, 12288).is_none());

        assert_eq!(cache.len(), 5);
    }

    // ── Test 3: LRU eviction order ──────────────────────────────────

    #[test]
    fn lru_eviction_oldest_evicted_first() {
        // Capacity = 3
        let cache = new_cache(3);

        // Insert pages (they become MRU on insert)
        cache.insert(1, 0).unwrap(); // MRU: 1
        cache.insert(2, 0).unwrap(); // MRU: 2
        cache.insert(3, 0).unwrap(); // MRU: 3, order: 1->2->3

        // Touch page 1 to move it to MRU: order: 2->3->1
        {
            let _h = cache.lookup(1, 0).unwrap();
        } // drop handle before calling insert

        // Insert page 4: eviction should pick LRU (page 2)
        cache.insert(4, 0).unwrap();

        // Page 2 should be gone
        assert!(
            cache.lookup(2, 0).is_none(),
            "page 2 should be evicted (oldest)"
        );
        // Pages 1, 3, 4 should remain
        assert!(cache.lookup(1, 0).is_some());
        assert!(cache.lookup(3, 0).is_some());
        assert!(cache.lookup(4, 0).is_some());

        assert_eq!(cache.len(), 3);
        assert_eq!(cache.eviction_count(), 1);
    }

    #[test]
    fn lru_strict_order() {
        let cache = new_cache(3);

        cache.insert(1, 0).unwrap();
        cache.insert(2, 0).unwrap();
        cache.insert(3, 0).unwrap();

        // Touch 1 (oldest → MRU).  Then insert 4.  Oldest = 2.
        {
            let _h = cache.lookup(1, 0);
        } // drop handle before calling insert
        cache.insert(4, 0).unwrap();

        assert!(cache.lookup(2, 0).is_none());
        assert!(cache.lookup(1, 0).is_some());
        assert!(cache.lookup(3, 0).is_some());
        assert!(cache.lookup(4, 0).is_some());
    }

    // ── Test 4: dirty eviction ──────────────────────────────────────

    #[test]
    fn dirty_page_not_evicted() {
        let cache = new_cache(2);

        cache.insert(1, 0).unwrap();
        cache.insert(2, 0).unwrap();

        // Mark page 1 dirty
        {
            let mut h = cache.lookup(2, 0).unwrap();
            h.mark_dirty();
        }
        // Mark page 2 dirty
        {
            let mut h = cache.lookup(1, 0).unwrap();
            h.mark_dirty();
        }

        // Now both pages are dirty.  Insert page 3 should fail.
        let result = cache.insert(3, 0);
        assert_eq!(result.err(), Some(InsertError::AtCapacityNoCleanPages));

        // Both original pages still present
        assert!(cache.lookup(1, 0).is_some());
        assert!(cache.lookup(2, 0).is_some());
        assert!(cache.lookup(3, 0).is_none());

        // Evict one also returns none (no clean pages)
        assert!(cache.evict_one().is_none());
    }

    #[test]
    fn dirty_pages_skipped_clean_evicted() {
        let cache = new_cache(3);

        cache.insert(1, 0).unwrap(); // clean
        cache.insert(2, 0).unwrap(); // clean
        cache.insert(3, 0).unwrap(); // clean

        // Mark 1 dirty, touch 2 to make it MRU
        cache.mark_dirty(1, 0);
        {
            let _h = cache.lookup(2, 0);
        } // drop handle before calling evict_one

        // LRU order: 3 is now oldest, 1 in middle, 2 MRU
        // Eviction should evict 3 (oldest clean)
        let result = cache.evict_one();
        assert!(result.is_some());
        let evicted = result.unwrap();
        assert_eq!(evicted.key.inode, 3); // 3 was oldest clean

        // 1 (dirty) and 2 (MRU) remain
        assert!(cache.lookup(1, 0).is_some());
        assert!(cache.lookup(2, 0).is_some());
        assert!(cache.lookup(3, 0).is_none());
    }

    // ── Test 5: writeback lifecycle ─────────────────────────────────

    #[test]
    fn writeback_lifecycle_success() {
        let cache = new_cache(10);

        cache.insert(1, 0).unwrap();

        // Mark dirty
        cache.mark_dirty(1, 0);

        // Start writeback
        assert!(cache.start_writeback(1, 0));
        {
            let h = cache.lookup(1, 0).unwrap();
            assert!(h.is_writeback());
            assert!(h.is_pinned());
            assert!(h.is_dirty()); // dirty persists during writeback
        }

        // Complete writeback with success
        assert!(cache.complete_writeback(1, 0, true));
        {
            let h = cache.lookup(1, 0).unwrap();
            assert!(!h.is_writeback());
            assert!(!h.is_pinned());
            assert!(!h.is_dirty()); // clean after successful writeback
        }
    }

    #[test]
    fn writeback_lifecycle_failure_retains_dirty() {
        let cache = new_cache(10);

        cache.insert(1, 0).unwrap();
        cache.mark_dirty(1, 0);

        cache.start_writeback(1, 0);

        // Complete writeback with failure
        assert!(cache.complete_writeback(1, 0, false));
        {
            let h = cache.lookup(1, 0).unwrap();
            assert!(!h.is_writeback());
            assert!(!h.is_pinned());
            assert!(h.is_dirty()); // dirty retained on failure
        }
    }

    // ── Test 6: writeback abort ─────────────────────────────────────

    #[test]
    fn writeback_abort_preserves_dirty() {
        let cache = new_cache(10);

        cache.insert(1, 0).unwrap();
        cache.mark_dirty(1, 0);

        assert!(cache.start_writeback(1, 0));

        // Abort writeback
        assert!(cache.abort_writeback(1, 0));
        {
            let h = cache.lookup(1, 0).unwrap();
            assert!(!h.is_writeback());
            assert!(!h.is_pinned());
            assert!(h.is_dirty()); // dirty preserved after abort
        }
    }

    #[test]
    fn start_writeback_already_in_writeback_fails() {
        let cache = new_cache(10);

        cache.insert(1, 0).unwrap();
        cache.mark_dirty(1, 0);

        assert!(cache.start_writeback(1, 0));
        // Second start should fail
        assert!(!cache.start_writeback(1, 0));
    }

    #[test]
    fn start_writeback_nonexistent_returns_false() {
        let cache = new_cache(10);
        assert!(!cache.start_writeback(99, 0));
    }

    // ── Test 7: dirty iterator ──────────────────────────────────────

    #[test]
    fn dirty_iterator_yields_only_dirty_pages() {
        let cache = new_cache(10);

        for i in 0..5 {
            cache.insert(i, 0).unwrap();
        }

        // Mark subset dirty: inodes 1, 3
        cache.mark_dirty(1, 0);
        cache.mark_dirty(3, 0);

        let dirty_keys = cache.dirty_pages();
        assert_eq!(dirty_keys.len(), 2);

        let dirty_inodes: Vec<u64> = dirty_keys.iter().map(|k| k.inode).collect();
        assert!(dirty_inodes.contains(&1));
        assert!(dirty_inodes.contains(&3));
    }

    #[test]
    fn dirty_iterator_empty_when_no_dirty_pages() {
        let cache = new_cache(10);

        cache.insert(1, 0).unwrap();
        cache.insert(2, 0).unwrap();

        let dirty_keys = cache.dirty_pages();
        assert!(dirty_keys.is_empty());
    }

    #[test]
    fn dirty_iterator_after_writeback_completion() {
        let cache = new_cache(10);

        cache.insert(1, 0).unwrap();
        cache.insert(2, 0).unwrap();
        cache.mark_dirty(1, 0);
        cache.mark_dirty(2, 0);

        // Start + complete writeback for page 1 (success)
        cache.start_writeback(1, 0);
        cache.complete_writeback(1, 0, true);

        // Only page 2 should remain dirty
        let dirty_keys = cache.dirty_pages();
        assert_eq!(dirty_keys.len(), 1);
        assert_eq!(dirty_keys[0].inode, 2);
    }

    #[test]
    fn dirty_index_does_not_double_count_repeated_marks() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();

        assert!(cache.mark_dirty(1, 0));
        assert!(cache.mark_dirty(1, 0));

        let keys = cache.dirty_pages_for_inode(1);
        assert_eq!(
            keys,
            vec![PageKey {
                inode: 1,
                offset: 0
            }]
        );
    }

    #[test]
    fn dirty_index_tracks_handle_clear_and_writeback_success() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.insert(1, 4096).unwrap();

        {
            let mut page = cache.lookup(1, 0).unwrap();
            page.mark_dirty();
            page.clear_dirty();
        }
        assert!(cache.dirty_pages_for_inode(1).is_empty());

        cache.mark_dirty(1, 0);
        cache.mark_dirty(1, 4096);
        {
            let mut page = cache.lookup(1, 0).unwrap();
            page.start_writeback();
            page.complete_writeback(true);
        }

        assert_eq!(
            cache.dirty_pages_for_inode(1),
            vec![PageKey {
                inode: 1,
                offset: 4096
            }]
        );
    }

    #[test]
    fn dirty_index_updates_when_dirty_pages_are_removed() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.insert(1, 4096).unwrap();
        cache.mark_dirty(1, 0);
        cache.mark_dirty(1, 4096);

        let removed = cache.remove(1, 0).expect("remove dirty page");
        assert!(removed.is_dirty());
        assert_eq!(
            cache.dirty_pages_for_inode(1),
            vec![PageKey {
                inode: 1,
                offset: 4096
            }]
        );

        assert_eq!(cache.remove_pages_for_inode(1), 1);
        assert!(cache.dirty_pages_for_inode(1).is_empty());
        assert!(cache.dirty_pages_in_range(1, 0, 8192).is_empty());
    }

    // ── dirty_pages_in_range ──────────────────────────────────────

    #[test]
    fn dirty_pages_in_range_empty_when_no_dirty_pages() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.insert(1, 4096).unwrap();
        let keys = cache.dirty_pages_in_range(1, 0, 16384);
        assert!(keys.is_empty());
    }

    #[test]
    fn dirty_pages_in_range_filters_by_start_and_end() {
        let cache = new_cache(10);
        // Pages at offsets 0, 4096, 8192, 12288 (each 4 KiB)
        for off in [0u64, 4096, 8192, 12288] {
            cache.insert(1, off).unwrap();
            cache.mark_dirty(1, off);
        }
        // Range [4096, 8192) should only match offset 4096
        let keys = cache.dirty_pages_in_range(1, 4096, 8192);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].offset, 4096);

        // Range [0, 12288) should match offsets 0, 4096, 8192
        let keys2 = cache.dirty_pages_in_range(1, 0, 12288);
        assert_eq!(keys2.len(), 3);
    }

    #[test]
    fn dirty_pages_in_range_overlap_semantics() {
        let cache = new_cache(10);
        cache.insert(1, 4096).unwrap();
        cache.mark_dirty(1, 4096);

        // Range entirely before the page: no overlap
        let keys = cache.dirty_pages_in_range(1, 0, 4096);
        assert!(keys.is_empty(), "range ends at page start: no overlap");

        // Single byte overlap at the end
        let keys = cache.dirty_pages_in_range(1, 4096, 4097);
        assert!(!keys.is_empty(), "byte at 4096 overlaps page [4096,8192)");

        // Range contains the page
        let keys = cache.dirty_pages_in_range(1, 0, 16384);
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn dirty_pages_in_range_only_matches_given_inode() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.mark_dirty(1, 0);
        cache.insert(2, 0).unwrap();
        cache.mark_dirty(2, 0);

        let keys = cache.dirty_pages_in_range(1, 0, 4096);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].inode, 1);
    }

    #[test]
    fn dirty_pages_in_range_ignores_many_unrelated_dirty_inodes() {
        let cache = new_cache(512);
        for inode in 2..258 {
            cache.insert(inode, 0).unwrap();
            cache.mark_dirty(inode, 0);
        }
        for off in [0_u64, 4096, 8192, 12288] {
            cache.insert(1, off).unwrap();
            cache.mark_dirty(1, off);
        }

        let keys = cache.dirty_pages_in_range(1, 4096, 12288);
        assert_eq!(
            keys,
            vec![
                PageKey {
                    inode: 1,
                    offset: 4096
                },
                PageKey {
                    inode: 1,
                    offset: 8192
                }
            ]
        );
    }

    #[test]
    fn dirty_page_boolean_probes_match_inode_and_range_semantics() {
        let cache = new_cache(512);
        for inode in 2..258 {
            cache.insert(inode, 0).unwrap();
            cache.mark_dirty(inode, 0);
        }
        for off in [0_u64, 4096, 8192, 12288] {
            cache.insert(1, off).unwrap();
            cache.mark_dirty(1, off);
        }

        assert!(cache.has_dirty_pages_for_inode(1));
        assert!(cache.has_dirty_pages_for_inode(257));
        assert!(!cache.has_dirty_pages_for_inode(999));
        assert!(!cache.has_dirty_pages_in_range(1, 16384, 16384));
        assert!(!cache.has_dirty_pages_in_range(1, 16384, 20480));
        assert!(!cache.has_dirty_pages_in_range(1, 0, 0));
        assert!(cache.has_dirty_pages_in_range(1, 4096, 12288));
        assert!(cache.has_dirty_pages_in_range(1, 1, 2));
        assert!(!cache.has_dirty_pages_in_range(2, 4096, 12288));

        cache.clear_dirty(1, 4096);
        cache.clear_dirty(1, 8192);
        assert!(!cache.has_dirty_pages_in_range(1, 4096, 12288));
        assert!(cache.has_dirty_pages_for_inode(1));
    }

    // ── flush_dirty_range ───────────────────────────────────────────

    #[test]
    fn flush_dirty_range_cleans_pages_in_range() {
        let cache = new_cache(10);
        for off in [0u64, 4096, 8192] {
            cache.insert(1, off).unwrap();
            cache.mark_dirty(1, off);
        }

        // Flush only the first two pages
        let mut written: Vec<(u64, Vec<u8>)> = Vec::new();
        let result = cache.flush_dirty_range(1, 0, 8192, |offset, data| {
            written.push((offset, data.to_vec()));
            Ok(())
        });
        assert!(result.is_ok());
        assert_eq!(written.len(), 2);
        // HashMap iteration order is not insertion order; sort for assertion
        written.sort_by_key(|(off, _)| *off);
        assert_eq!(written[0].0, 0);
        assert_eq!(written[1].0, 4096);
        assert_eq!(written[1].0, 4096);
        // Pages at 0 and 4096 should be clean; 8192 should remain dirty
        let dirty = cache.dirty_pages_for_inode(1);
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].offset, 8192);
    }

    #[test]
    fn flush_dirty_range_first_error_stops_further_writes() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.mark_dirty(1, 0);
        cache.insert(1, 4096).unwrap();
        cache.mark_dirty(1, 4096);
        cache.insert(1, 8192).unwrap();
        cache.mark_dirty(1, 8192);

        let mut call_count = 0;
        let result = cache.flush_dirty_range(1, 0, 16384, |_offset, _data| {
            call_count += 1;
            if call_count == 2 {
                Err(PageFlushError::NoSpace)
            } else {
                Ok(())
            }
        });
        assert_eq!(result, Err(PageFlushError::NoSpace));
        // First page was written successfully (cleaned), second failed (retains dirty),
        // third was never written.
        assert_eq!(call_count, 2);

        // First page clean, second and third remain dirty
        let dirty = cache.dirty_pages_for_inode(1);
        assert_eq!(dirty.len(), 2);
        assert_eq!(
            cache.writeback_queue_size(),
            0,
            "failed range flush must not leave unattempted pages pending"
        );
    }

    #[test]
    fn flush_dirty_range_empty_range_returns_ok() {
        let cache = new_cache(10);
        let result = cache.flush_dirty_range(1, 0, 4096, |_, _| {
            unreachable!();
            #[allow(unreachable_code)]
            Ok(())
        });
        assert!(result.is_ok());
    }

    #[test]
    fn flush_dirty_range_non_dirty_pages_skipped() {
        let cache = new_cache(10);
        // Insert pages but do not mark dirty
        cache.insert(1, 0).unwrap();
        cache.insert(1, 4096).unwrap();

        let mut called = false;
        let result = cache.flush_dirty_range(1, 0, 16384, |_, _| {
            called = true;
            Ok(())
        });
        assert!(result.is_ok());
        assert!(!called, "write_page should not be called for clean pages");
    }

    // ── Test 8: concurrent insert + lookup ──────────────────────────

    #[test]
    fn concurrent_insert_no_panics_or_lost_pages() {
        let cache = Arc::new(new_cache(100));
        let mut handles = Vec::new();

        // Spawn 4 threads, each inserting 25 pages
        for t in 0..4 {
            let c = Arc::clone(&cache);
            let h = thread::spawn(move || {
                let base = t * 25;
                for i in 0..25 {
                    let inode = base + i;
                    let _ = c.insert(inode as u64, 0);
                }
            });
            handles.push(h);
        }

        for h in handles {
            h.join().unwrap();
        }

        // All 100 pages should be present
        assert_eq!(cache.len(), 100);
        for i in 0..100 {
            assert!(cache.lookup(i, 0).is_some(), "page {i} should exist");
        }
    }

    #[test]
    fn concurrent_lookup_and_insert() {
        let cache = Arc::new(new_cache(200));

        // Pre-populate half
        for i in 0..100 {
            cache.insert(i as u64, 0).unwrap();
        }

        let mut handles = Vec::new();

        // Thread A: lookups
        let ca = Arc::clone(&cache);
        handles.push(thread::spawn(move || {
            for _ in 0..500 {
                let _ = ca.lookup(50, 0);
                let _ = ca.lookup(99, 0);
            }
        }));

        // Thread B: inserts (different inodes)
        let cb = Arc::clone(&cache);
        handles.push(thread::spawn(move || {
            for i in 100..150 {
                let _ = cb.insert(i as u64, 0);
            }
        }));

        for h in handles {
            h.join().unwrap();
        }

        // Original pages still there (not evicted since under capacity)
        for i in 0..100 {
            assert!(cache.lookup(i, 0).is_some(), "page {i} should exist");
        }
    }

    // ── Additional tests ────────────────────────────────────────────

    #[test]
    fn remove_page() {
        let cache = new_cache(10);

        cache.insert(1, 0).unwrap();
        cache.insert(2, 0).unwrap();
        assert_eq!(cache.len(), 2);

        let removed = cache.remove(1, 0);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().key.inode, 1);

        assert_eq!(cache.len(), 1);
        assert!(cache.lookup(1, 0).is_none());
        assert!(cache.lookup(2, 0).is_some());
    }

    #[test]
    fn remove_nonexistent_returns_none() {
        let cache = new_cache(10);
        assert!(cache.remove(99, 0).is_none());
    }

    #[test]
    fn insert_already_exists_fails() {
        let cache = new_cache(10);

        cache.insert(1, 0).unwrap();
        let result = cache.insert(1, 0);
        assert_eq!(result.err(), Some(InsertError::AlreadyExists));
    }

    #[test]
    fn capacity_and_stats() {
        let cache = new_cache(16);
        assert_eq!(cache.capacity(), 16);
        assert_eq!(cache.page_size(), PAGE_SIZE);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        cache.insert(1, 0).unwrap();
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.insert_count(), 1);
        assert!(!cache.is_full());

        // Fill to capacity
        for i in 2..=16 {
            cache.insert(i, 0).unwrap();
        }
        assert!(cache.is_full());
        assert_eq!(cache.len(), 16);
        assert_eq!(cache.insert_count(), 16);
    }

    #[test]
    fn page_handle_data_mut() {
        let cache = new_cache(10);

        cache.insert(1, 0).unwrap();
        {
            let mut h = cache.lookup(1, 0).unwrap();
            let data = h.data_mut();
            data[0] = 0xAB;
            data[1] = 0xCD;
            data[4095] = 0xEF;
        }

        // Verify data persisted
        let h = cache.lookup(1, 0).unwrap();
        assert_eq!(h.data()[0], 0xAB);
        assert_eq!(h.data()[1], 0xCD);
        assert_eq!(h.data()[4095], 0xEF);
    }

    #[test]
    fn page_handle_flags_and_writeback() {
        let cache = new_cache(10);

        cache.insert(1, 0).unwrap();
        {
            let mut h = cache.lookup(1, 0).unwrap();
            assert!(!h.is_dirty());
            assert!(!h.is_writeback());
            assert!(!h.is_pinned());

            h.mark_dirty();
            assert!(h.is_dirty());

            assert!(h.start_writeback());
            assert!(h.is_writeback());
            assert!(h.is_pinned());

            h.complete_writeback(true);
            assert!(!h.is_writeback());
            assert!(!h.is_pinned());
            assert!(!h.is_dirty());
        }
    }

    #[test]
    fn page_handle_abort_writeback() {
        let cache = new_cache(10);

        cache.insert(1, 0).unwrap();
        {
            let mut h = cache.lookup(1, 0).unwrap();
            h.mark_dirty();
            h.start_writeback();
            h.abort_writeback();

            assert!(!h.is_writeback());
            assert!(!h.is_pinned());
            assert!(h.is_dirty()); // dirty preserved
        }
    }

    #[test]
    fn writeback_pinned_page_not_evicted() {
        let cache = new_cache(2);

        cache.insert(1, 0).unwrap();
        cache.insert(2, 0).unwrap();

        // Start writeback on page 1 (pins it)
        cache.mark_dirty(1, 0);
        assert!(cache.start_writeback(1, 0));

        // Insert page 3: page 2 is clean and evictable, page 1 is pinned
        cache.insert(3, 0).unwrap();

        // Page 1 (pinned, writeback) should remain
        assert!(cache.lookup(1, 0).is_some());
        // Page 2 should be evicted
        assert!(cache.lookup(2, 0).is_none());
        // Page 3 should be present
        assert!(cache.lookup(3, 0).is_some());
    }

    #[test]
    fn evict_one_empty_cache_returns_none() {
        let cache = new_cache(10);
        assert!(cache.evict_one().is_none());
    }

    #[test]
    fn insert_at_capacity_with_all_dirty_fails() {
        let cache = new_cache(2);

        cache.insert(1, 0).unwrap();
        cache.insert(2, 0).unwrap();
        cache.mark_dirty(1, 0);
        cache.mark_dirty(2, 0);

        let result = cache.insert(3, 0);
        assert_eq!(result.err(), Some(InsertError::AtCapacityNoCleanPages));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn remove_pages_for_inode_clears_only_target_inode() {
        let cache = new_cache(10);

        // Insert pages for two distinct inodes.
        cache.insert(1, 0).unwrap();
        cache.insert(1, 4096).unwrap();
        cache.insert(1, 8192).unwrap();
        cache.insert(2, 0).unwrap();
        cache.insert(2, 4096).unwrap();
        assert_eq!(cache.len(), 5);

        let removed = cache.remove_pages_for_inode(1);
        assert_eq!(removed, 3, "should remove 3 pages for inode 1");
        assert_eq!(cache.len(), 2, "only inode 2 pages remain");
        assert!(cache.lookup(1, 0).is_none());
        assert!(cache.lookup(1, 4096).is_none());
        assert!(cache.lookup(1, 8192).is_none());
        assert!(cache.lookup(2, 0).is_some());
        assert!(cache.lookup(2, 4096).is_some());

        // Removing a non-existent inode returns 0.
        assert_eq!(cache.remove_pages_for_inode(99), 0);
    }

    // ── Test: invalidate_range ─────────────────────────────────────

    #[test]
    fn invalidate_range_removes_clean_pages_in_range() {
        let cache = new_cache(10);
        for off in [0u64, 4096, 8192, 12288] {
            cache.insert(1, off).unwrap();
        }
        // Invalidate range [4096, 12288): removes pages at 4096 and 8192
        let removed = cache.invalidate_range(1, 4096, 12288);
        assert_eq!(removed, 2);
        assert!(
            cache.lookup(1, 0).is_some(),
            "page at 0 outside range, should stay"
        );
        assert!(
            cache.lookup(1, 4096).is_none(),
            "page at 4096 in range, should be gone"
        );
        assert!(
            cache.lookup(1, 8192).is_none(),
            "page at 8192 in range, should be gone"
        );
        assert!(
            cache.lookup(1, 12288).is_some(),
            "page at 12288 outside range, should stay"
        );
    }

    #[test]
    fn invalidate_range_preserves_dirty_pages() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.insert(1, 4096).unwrap();
        cache.mark_dirty(1, 4096);

        let removed = cache.invalidate_range(1, 0, 8192);
        assert_eq!(removed, 1, "only clean page at offset 0 should be removed");
        assert!(cache.lookup(1, 0).is_none());
        assert!(
            cache.lookup(1, 4096).is_some(),
            "dirty page must survive invalidation"
        );
    }

    #[test]
    fn invalidate_range_preserves_writeback_pages() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.insert(1, 4096).unwrap();
        cache.mark_dirty(1, 4096);
        assert!(cache.start_writeback(1, 4096)); // pins + sets writeback

        let removed = cache.invalidate_range(1, 0, 8192);
        assert_eq!(removed, 1, "only clean page at offset 0 should be removed");
        assert!(
            cache.lookup(1, 4096).is_some(),
            "writeback page must survive invalidation"
        );
    }

    #[test]
    fn invalidate_range_only_matches_given_inode() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.insert(2, 0).unwrap();

        let removed = cache.invalidate_range(1, 0, 4096);
        assert_eq!(removed, 1);
        assert!(
            cache.lookup(2, 0).is_some(),
            "inode 2 page should not be affected"
        );
    }

    #[test]
    fn invalidate_range_empty_cache_returns_zero() {
        let cache = new_cache(10);
        assert_eq!(cache.invalidate_range(1, 0, 4096), 0);
    }

    #[test]
    fn invalidate_inode_removes_all_clean_pages_for_inode() {
        let cache = new_cache(10);
        for off in [0u64, 4096, 8192] {
            cache.insert(1, off).unwrap();
        }
        cache.insert(2, 0).unwrap();

        let removed = cache.invalidate_inode(1);
        assert_eq!(removed, 3);
        assert_eq!(cache.len(), 1, "only inode 2 page should remain");
        assert!(cache.lookup(2, 0).is_some());
    }

    #[test]
    fn invalidate_inode_preserves_dirty_pages() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.insert(1, 4096).unwrap();
        cache.mark_dirty(1, 4096);

        let removed = cache.invalidate_inode(1);
        assert_eq!(removed, 1, "only clean page should be removed");
        assert!(cache.lookup(1, 4096).is_some(), "dirty page must survive");
    }

    // ── WritebackToken lifecycle tests ────────────────────────────

    #[test]
    fn writeback_token_lifecycle_success() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.mark_dirty(1, 0);

        let token = cache.start_writeback_token(1, 0).expect("start writeback");
        assert_eq!(
            token.key,
            PageKey {
                inode: 1,
                offset: 0
            }
        );
        assert_eq!(cache.writeback_queue_size(), 1);

        // Complete with success: page becomes clean
        cache.complete_writeback_with_token(token, true);
        assert_eq!(cache.writeback_queue_size(), 0);
        {
            let h = cache.lookup(1, 0).unwrap();
            assert!(!h.is_dirty());
            assert!(!h.is_writeback());
            assert!(!h.is_pinned());
        }
    }

    #[test]
    fn writeback_token_lifecycle_failure_retains_dirty() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.mark_dirty(1, 0);

        let token = cache.start_writeback_token(1, 0).expect("start writeback");
        cache.complete_writeback_with_token(token, false);

        {
            let h = cache.lookup(1, 0).unwrap();
            assert!(h.is_dirty());
            assert!(!h.is_writeback());
        }
        assert_eq!(cache.writeback_queue_size(), 0);
    }

    #[test]
    fn writeback_token_abort_preserves_dirty() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.mark_dirty(1, 0);

        let token = cache.start_writeback_token(1, 0).expect("start writeback");
        cache.abort_writeback_with_token(token);

        {
            let h = cache.lookup(1, 0).unwrap();
            assert!(h.is_dirty());
            assert!(!h.is_writeback());
            assert!(!h.is_pinned());
        }
        assert_eq!(cache.writeback_queue_size(), 0);
    }

    #[test]
    fn writeback_token_already_in_writeback_returns_none() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.mark_dirty(1, 0);

        let _t1 = cache.start_writeback_token(1, 0).expect("first writeback");
        assert!(cache.start_writeback_token(1, 0).is_none());
    }

    #[test]
    fn writeback_token_nonexistent_returns_none() {
        let cache = new_cache(10);
        assert!(cache.start_writeback_token(99, 0).is_none());
    }

    #[test]
    fn writeback_queue_tracks_active_writebacks() {
        let cache = new_cache(10);
        for i in 0..5 {
            cache.insert(i, 0).unwrap();
            cache.mark_dirty(i, 0);
        }

        assert_eq!(cache.writeback_queue_size(), 0);
        assert!(cache.writeback_queue_keys().is_empty());

        let t0 = cache.start_writeback_token(0, 0).unwrap();
        let t2 = cache.start_writeback_token(2, 0).unwrap();
        assert_eq!(cache.writeback_queue_size(), 2);
        let wb_keys = cache.writeback_queue_keys();
        assert_eq!(wb_keys.len(), 2);

        cache.complete_writeback_with_token(t0, true);
        assert_eq!(cache.writeback_queue_size(), 1);
        cache.abort_writeback_with_token(t2);
        assert_eq!(cache.writeback_queue_size(), 0);
    }

    #[test]
    fn writeback_token_eviction_decrements_queue() {
        let cache = new_cache(2);
        cache.insert(1, 0).unwrap();
        cache.insert(2, 0).unwrap();
        cache.mark_dirty(1, 0);
        let _t = cache.start_writeback_token(1, 0).unwrap();
        assert_eq!(cache.writeback_queue_size(), 1);

        // Evict page 2 (clean); page 1 is writeback+pinned, not evictable
        let evicted = cache.evict_one();
        assert!(evicted.is_some());
        assert_eq!(evicted.unwrap().key.inode, 2);
        assert!(cache.evict_one().is_none(), "writeback page not evictable");
        assert_eq!(cache.writeback_queue_size(), 1);

        // Use unlink to remove writeback page, which decrements queue
        cache.unlink_invalidate(1);
        assert_eq!(cache.writeback_queue_size(), 0);
    }

    // ── Dirty→writeback→clean lifecycle (full contract) ───────────

    #[test]
    fn dirty_to_writeback_to_clean_lifecycle() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();

        // Page starts clean
        let h = cache.lookup(1, 0).unwrap();
        assert!(!h.is_dirty() && !h.is_writeback());
        assert!(!h.is_dirty());
        drop(h);

        // Mark dirty
        cache.mark_dirty(1, 0);
        assert_eq!(cache.dirty_pages().len(), 1);

        // Start writeback
        let token = cache.start_writeback_token(1, 0).unwrap();
        assert_eq!(cache.writeback_queue_size(), 1);
        // Page is still tracked as dirty during writeback
        assert_eq!(cache.dirty_pages().len(), 1);

        // Complete writeback with success
        cache.complete_writeback_with_token(token, true);
        assert_eq!(cache.writeback_queue_size(), 0);
        assert!(cache.dirty_pages().is_empty());
        {
            let h = cache.lookup(1, 0).unwrap();
            assert!(!h.is_dirty());
            assert!(!h.is_writeback());
        }
    }

    #[test]
    fn lifecycle_reconcile_restores_missing_dirty_index() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.mark_dirty(1, 0);
        {
            let mut inner = cache.inner.lock().unwrap();
            inner.dirty_pages_by_inode.clear();
        }

        assert_eq!(
            cache.dirty_pages_for_inode(1),
            vec![PageKey {
                inode: 1,
                offset: 0
            }]
        );
        let h = cache.lookup(1, 0).unwrap();
        assert_eq!(h.lifecycle_state(), PageLifecycleState::Dirty);
    }

    #[test]
    fn lifecycle_reconcile_preserves_stale_dirty_index_before_evict_or_invalidate() {
        let governor = data_dirty_governor();
        let cache = PageCache::with_governor(3, PAGE_SIZE, governor.clone());
        cache.insert(2, 0).unwrap();
        cache.insert(1, 0).unwrap();
        cache.insert(1, 4096).unwrap();
        {
            let mut inner = cache.inner.lock().unwrap();
            inner.dirty_pages_by_inode.entry(1).or_default().insert(0);
            assert!(inner
                .pages
                .get(&PageKey {
                    inode: 1,
                    offset: 0
                })
                .unwrap()
                .is_clean());
        }

        let evicted = cache.evict_one().expect("clean page remains evictable");
        assert_eq!(
            evicted.key,
            PageKey {
                inode: 2,
                offset: 0
            },
            "dirty-index evidence must make the older indexed page non-evictable"
        );
        assert_eq!(
            cache.dirty_pages_for_inode(1),
            vec![PageKey {
                inode: 1,
                offset: 0
            }],
            "reconciliation promotes stale dirty-index evidence to page flags"
        );
        assert_eq!(
            governor.category_used(BudgetCategory::DirtyBytes),
            PAGE_SIZE as u64,
            "reconciliation moves promoted pages into dirty budget"
        );

        let removed = cache.invalidate_range(1, 0, 8192);
        assert_eq!(
            removed, 1,
            "only the truly clean sibling can be invalidated"
        );
        assert!(cache.lookup(1, 0).is_some());
        assert!(cache.lookup(1, 4096).is_none());
    }

    #[test]
    fn dirty_eviction_eligibility() {
        let cache = new_cache(2);
        cache.insert(1, 0).unwrap(); // clean
        cache.insert(2, 0).unwrap(); // clean

        // Mark 1 dirty → not evictable
        cache.mark_dirty(1, 0);
        let evicted = cache.evict_one().unwrap();
        assert_eq!(evicted.key.inode, 2, "clean page 2 must be evicted first");

        // Now only dirty page 1 remains → eviction returns none
        assert!(cache.evict_one().is_none());
    }

    #[test]
    fn clean_page_is_eviction_eligible() {
        let cache = new_cache(1);
        cache.insert(1, 0).unwrap(); // clean
        let evicted = cache.evict_one().unwrap();
        assert_eq!(evicted.key.inode, 1);
        assert!(!evicted.is_dirty() && !evicted.is_writeback());
    }

    #[test]
    fn writeback_page_not_evicted() {
        let cache = new_cache(2);
        cache.insert(1, 0).unwrap();
        cache.insert(2, 0).unwrap();
        cache.mark_dirty(1, 0);
        let _t = cache.start_writeback_token(1, 0).unwrap();

        let evicted = cache.evict_one().unwrap();
        assert_eq!(evicted.key.inode, 2, "writeback page 1 must not be evicted");
        assert!(cache.evict_one().is_none(), "only writeback page left");
    }

    // ── Truncate invalidation ─────────────────────────────────────

    #[test]
    fn truncate_invalidate_removes_pages_beyond_new_size() {
        let cache = new_cache(10);
        // 4 KiB pages: offsets 0, 4096, 8192, 12288
        for off in [0u64, 4096, 8192, 12288] {
            cache.insert(1, off).unwrap();
        }
        assert_eq!(cache.page_count_for_inode(1), 4);

        // Truncate to 5000 bytes: pages at 4096 (overlaps boundary),
        // 8192, and 12288 are beyond or overlap new_size
        let (removed, dirty) = cache.truncate_invalidate(1, 5000);
        assert_eq!(removed, 3);
        assert_eq!(dirty, 0);
        assert_eq!(cache.page_count_for_inode(1), 1);
        assert!(cache.lookup(1, 0).is_some());
        assert!(cache.lookup(1, 4096).is_none());
        assert!(cache.lookup(1, 8192).is_none());
        assert!(cache.lookup(1, 12288).is_none());
    }

    #[test]
    fn truncate_invalidate_removes_dirty_pages_beyond_new_size() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.insert(1, 4096).unwrap();
        cache.insert(1, 8192).unwrap();
        cache.mark_dirty(1, 4096);
        cache.mark_dirty(1, 8192);

        let (removed, dirty) = cache.truncate_invalidate(1, 4096);
        assert_eq!(removed, 2, "pages at 4096 and 8192 removed");
        assert_eq!(dirty, 2, "both pages were dirty");
        assert!(cache.lookup(1, 0).is_some());
        assert!(cache.lookup(1, 4096).is_none());
        assert!(cache.lookup(1, 8192).is_none());
    }

    #[test]
    fn truncate_invalidate_removes_page_overlapping_boundary() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap(); // [0, 4096)
        cache.insert(1, 4096).unwrap(); // [4096, 8192)

        // Truncate to 3000: page at 0 overlaps (0 < 3000 < 4096) → removed
        let (removed, _) = cache.truncate_invalidate(1, 3000);
        assert_eq!(
            removed, 2,
            "both pages removed: one beyond, one overlapping"
        );
        assert_eq!(cache.page_count_for_inode(1), 0);
    }

    #[test]
    fn truncate_invalidate_empty_inode_returns_zero() {
        let cache = new_cache(10);
        let (removed, dirty) = cache.truncate_invalidate(99, 0);
        assert_eq!(removed, 0);
        assert_eq!(dirty, 0);
    }

    #[test]
    fn truncate_invalidate_other_inodes_unaffected() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.insert(1, 4096).unwrap();
        cache.insert(2, 0).unwrap();
        cache.insert(2, 4096).unwrap();

        cache.truncate_invalidate(1, 4096);
        assert_eq!(cache.page_count_for_inode(2), 2);
        assert!(cache.lookup(2, 0).is_some());
        assert!(cache.lookup(2, 4096).is_some());
    }

    // ── Unlink invalidation ───────────────────────────────────────

    #[test]
    fn unlink_invalidate_removes_all_pages_for_inode() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.insert(1, 4096).unwrap();
        cache.insert(1, 8192).unwrap();
        cache.mark_dirty(1, 4096);
        cache.insert(2, 0).unwrap();

        let (removed, dirty) = cache.unlink_invalidate(1);
        assert_eq!(removed, 3);
        assert_eq!(dirty, 1);
        assert_eq!(cache.page_count_for_inode(1), 0);
        assert_eq!(cache.page_count_for_inode(2), 1);
        assert!(cache.lookup(2, 0).is_some());
    }

    #[test]
    fn unlink_invalidate_removes_writeback_pages() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.mark_dirty(1, 0);
        let _t = cache.start_writeback_token(1, 0).unwrap();
        assert_eq!(cache.writeback_queue_size(), 1);

        let (removed, _) = cache.unlink_invalidate(1);
        assert_eq!(removed, 1);
        assert_eq!(cache.writeback_queue_size(), 0);
        assert_eq!(cache.page_count_for_inode(1), 0);
    }

    #[test]
    fn unlink_invalidate_empty_inode_returns_zero() {
        let cache = new_cache(10);
        let (removed, dirty) = cache.unlink_invalidate(99);
        assert_eq!(removed, 0);
        assert_eq!(dirty, 0);
    }

    // ── Rename invalidation (cross-directory) ─────────────────────

    #[test]
    fn rename_invalidation_inodes_unaffected_by_other_inode_ops() {
        // Rename in TideFS is an inode-level operation.  The cache tracks
        // pages by inode number, so a rename that changes the directory
        // entry does not change the inode number.  Pages for the renamed
        // inode remain valid.
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.insert(1, 4096).unwrap();
        cache.mark_dirty(1, 0);

        // "Rename" inode 1 — inode number unchanged, pages stay
        assert_eq!(cache.page_count_for_inode(1), 2);
        assert!(cache.has_dirty_pages_for_inode(1));
        assert!(cache.lookup(1, 0).is_some());
        assert!(cache.lookup(1, 4096).is_some());
    }

    #[test]
    fn rename_source_and_target_inodes_independent() {
        // Rename from inode 5 to inode 6 (overwrite).  Inode 6 pages
        // should be invalidated (unlink of target), inode 5 pages
        // remain valid.
        let cache = new_cache(10);
        cache.insert(5, 0).unwrap(); // source inode
        cache.insert(6, 0).unwrap(); // target inode (to be overwritten)
        cache.mark_dirty(5, 0);
        cache.mark_dirty(6, 0);

        // Unlink target inode 6
        let (removed, dirty) = cache.unlink_invalidate(6);
        assert_eq!(removed, 1);
        assert_eq!(dirty, 1);
        assert_eq!(cache.page_count_for_inode(6), 0);

        // Source inode 5 unchanged
        assert_eq!(cache.page_count_for_inode(5), 1);
        assert!(cache.has_dirty_pages_for_inode(5));
    }

    #[test]
    fn cross_directory_rename_invalidation_is_scoped() {
        // Pages from /dirA/inode are not affected by invalidating /dirB/inode
        let cache = new_cache(10);
        cache.insert(10, 0).unwrap(); // /dirA file
        cache.insert(11, 4096).unwrap(); // /dirB file
        cache.mark_dirty(10, 0);

        // Invalidate /dirB (inode 11) — /dirA (inode 10) unaffected
        let removed = cache.invalidate_inode(11);
        assert_eq!(removed, 1);
        assert_eq!(cache.page_count_for_inode(10), 1);
        assert!(cache.lookup(10, 0).is_some());
    }

    // ── Coherency: bounded invalidation ───────────────────────────

    #[test]
    fn coherency_invalidation_does_not_leave_stale_dirty_pages_reachable() {
        // After truncate, no dirty pages beyond new EOF can be looked up.
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.insert(1, 4096).unwrap();
        cache.insert(1, 8192).unwrap();
        cache.mark_dirty(1, 4096);
        cache.mark_dirty(1, 8192);

        cache.truncate_invalidate(1, 4096);

        assert!(cache.lookup(1, 0).is_some());
        // 4096 and 8192 removed (overlap/beyond boundary)
        assert!(cache.lookup(1, 4096).is_none());
        assert!(cache.lookup(1, 8192).is_none());
        // Dirty tracking for removed pages must be cleared
        assert!(!cache.has_dirty_pages_in_range(1, 4096, 12288));
    }

    #[test]
    fn coherency_after_unlink_no_pages_reachable() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.insert(1, 4096).unwrap();
        cache.mark_dirty(1, 0);
        cache.mark_dirty(1, 4096);

        cache.unlink_invalidate(1);

        assert_eq!(cache.page_count_for_inode(1), 0);
        assert!(cache.lookup(1, 0).is_none());
        assert!(cache.lookup(1, 4096).is_none());
        assert!(!cache.has_dirty_pages_for_inode(1));
    }

    // ── page_count_for_inode / page_keys_for_inode ───────────────

    #[test]
    fn page_count_and_keys_for_inode() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.insert(1, 4096).unwrap();
        cache.insert(2, 0).unwrap();

        assert_eq!(cache.page_count_for_inode(1), 2);
        assert_eq!(cache.page_count_for_inode(2), 1);
        assert_eq!(cache.page_count_for_inode(99), 0);

        let keys = cache.page_keys_for_inode(1);
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&PageKey {
            inode: 1,
            offset: 0
        }));
        assert!(keys.contains(&PageKey {
            inode: 1,
            offset: 4096
        }));
    }

    #[test]
    fn writeback_queue_keys_snapshot() {
        let cache = new_cache(10);
        cache.insert(1, 0).unwrap();
        cache.mark_dirty(1, 0);
        let _t = cache.start_writeback_token(1, 0).unwrap();

        let keys = cache.writeback_queue_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0],
            PageKey {
                inode: 1,
                offset: 0
            }
        );
    }
}
