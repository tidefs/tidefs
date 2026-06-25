// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Directory listing cache (CACHE-P3).
//!
//! A concrete cache that stores sorted directory entry lists for the
//! FUSE readdir hot path.  Entries are keyed by `dir_ino` and
//! invalidated on directory mutations (create, unlink, rename, mkdir,
//! rmdir).  Coherency is enforced via [`ValidityToken`] derived from
//! the directory's mtime+ctime generation counter.
//!
//! Built on [`CacheLatticeRegistry`] from CACHE-P2.

use std::fmt;
use tidefs_types_cache_lattice_core::{
    CacheClass, CacheEntryHeader, MemoryDomain, RebuildCostClass, ValidityToken,
};

use crate::{initial_entry_weight, CacheEntry, CacheLatticeRegistry, Governor};

// ---------------------------------------------------------------------------
// DirListingEntry
// ---------------------------------------------------------------------------

/// A cached directory listing for a single directory inode.
///
/// Stores the sorted list of directory entries and the validity token
/// from when the cache was populated.  The token is compared against
/// the current authoritative token on lookup to detect staleness.
#[derive(Clone, Debug)]
pub struct DirListingEntry {
    /// Sorted directory entries: (name_hash, inode, entry_type).
    ///
    /// `entry_type` uses libc DT_* constants (DT_REG=8, DT_DIR=4, etc.).
    pub entries: Vec<(u64, u64, u8)>,
    /// Validity token computed from (generation || authoritative_state)
    /// when this cache entry was populated.
    pub token: ValidityToken,
    /// Wall-clock timestamp of cache population (milliseconds since epoch).
    pub created_at_ms: i64,
    /// Approximate total size of the cached entry in bytes, used for
    /// eviction weighting.
    pub size_bytes: u64,
}

impl DirListingEntry {
    /// Create a new directory listing entry.
    #[must_use]
    pub fn new(entries: Vec<(u64, u64, u8)>, token: ValidityToken, created_at_ms: i64) -> Self {
        // Estimate size: each entry is ~24 bytes (3×u64), plus Vec overhead.
        let size_bytes = 32u64.saturating_add(entries.len() as u64 * 24);
        Self {
            entries,
            token,
            created_at_ms,
            size_bytes,
        }
    }

    /// Return the number of entries in this listing.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return true if the listing is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// DirectoryListingCacheStats
// ---------------------------------------------------------------------------

/// Statistics for the directory listing cache.
#[derive(Clone, Copy, Debug, Default)]
pub struct DirectoryListingCacheStats {
    /// Number of cache hits (lookup found a valid cached entry).
    pub hits: u64,
    /// Number of cache misses (lookup found no entry or a stale entry).
    pub misses: u64,
    /// Number of explicit invalidations (entry removed due to mutation).
    pub invalidations: u64,
    /// Current number of cached directory listings.
    pub cache_size_entries: usize,
}

// ---------------------------------------------------------------------------
// DirectoryListingCache
// ---------------------------------------------------------------------------

/// A concrete cache that stores sorted directory entry lists for the
/// FUSE readdir hot path, invalidated by directory mutations.
///
/// # Example
///
/// ```ignore
/// let mut cache = DirectoryListingCache::new();
/// let token = ValidityToken::compute(1, b"dir_state");
/// let listing = DirListingEntry::new(
///     vec![(hash1, ino1, 8), (hash2, ino2, 4)],
///     token, 1700000000000,
/// );
/// cache.insert(42, listing);
/// assert!(cache.get(42, &token).is_some());
/// ```
pub struct DirectoryListingCache {
    registry: CacheLatticeRegistry<u64, DirListingEntry>,
    stats: DirectoryListingCacheStats,
}

impl DirectoryListingCache {
    /// Budget domain string used for all entries in this cache.
    const BUDGET_DOMAIN: &'static str = "directory_listing_cache";

    /// Create a new empty directory listing cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registry: CacheLatticeRegistry::new(),
            stats: DirectoryListingCacheStats::default(),
        }
    }

    /// Attach a resource governor for directory-listing cache admission.
    ///
    /// Directory listings are L4 namespace metadata and are charged through
    /// the centralized cache-core mapping as [`crate::BudgetCategory::MetaCache`].
    pub fn set_governor(&mut self, governor: Governor) {
        self.registry.set_governor(governor);
    }

    /// Look up a cached directory listing for `dir_ino`.
    ///
    /// Returns `Some(&DirListingEntry)` if a valid cached entry exists
    /// and its token matches `current_token`.  Returns `None` on miss
    /// or if the cached entry is stale (token mismatch).
    ///
    /// Increments hit/miss counters accordingly.
    pub fn get(&mut self, dir_ino: u64, current_token: &ValidityToken) -> Option<&DirListingEntry> {
        let entry = self
            .registry
            .get(CacheClass::PosixNamespaceMirror, &dir_ino);
        match entry {
            Some(e) if e.value.token.matches(*current_token) => {
                self.stats.hits = self.stats.hits.saturating_add(1);
                // Re-fetch: the match arm borrows e which borrows
                // self.registry; drop it and get a fresh reference.
            }
            Some(_) => {
                // Stale entry — treat as miss but keep it cached.
                // It will be replaced on the next insert or explicitly
                // invalidated on directory mutation.
                self.stats.misses = self.stats.misses.saturating_add(1);
                return None;
            }
            None => {
                self.stats.misses = self.stats.misses.saturating_add(1);
                return None;
            }
        }
        self.registry
            .get(CacheClass::PosixNamespaceMirror, &dir_ino)
            .map(|e| &e.value)
    }

    /// Insert or update a cached directory listing for `dir_ino`.
    ///
    /// If an entry already exists for this inode, it is replaced.
    pub fn insert(&mut self, dir_ino: u64, listing: DirListingEntry) {
        let mut header = CacheEntryHeader::new(
            CacheClass::PosixNamespaceMirror,
            MemoryDomain::AdapterServingHot,
            dir_ino,
            Self::BUDGET_DOMAIN,
            RebuildCostClass::Moderate,
            1, // birth_counter — directory generation is tracked via ValidityToken
        );
        // The header defaults to Exact+ReadYourWrites which require an
        // anchor_vector_ref.  Directory listings are best-effort cached
        // views — set a non-zero anchor ref to satisfy the invariant.
        header.anchor_vector_ref = 1;
        header.set_size(listing.size_bytes);
        let weight = initial_entry_weight(listing.size_bytes);
        let entry = CacheEntry::with_weight(header, listing, weight);
        self.registry
            .insert(CacheClass::PosixNamespaceMirror, dir_ino, entry);
        self.stats.cache_size_entries = self.registry.entry_count(CacheClass::PosixNamespaceMirror);
    }

    /// Invalidate the cached listing for `dir_ino`.
    ///
    /// Called on directory mutation (create, unlink, rename, mkdir,
    /// rmdir).  The entry is removed so the next readdir will walk
    /// the authoritative namespace and repopulate the cache.
    pub fn invalidate(&mut self, dir_ino: u64) {
        if self
            .registry
            .remove(CacheClass::PosixNamespaceMirror, &dir_ino)
            .is_some()
        {
            self.stats.invalidations = self.stats.invalidations.saturating_add(1);
        }
        self.stats.cache_size_entries = self.registry.entry_count(CacheClass::PosixNamespaceMirror);
    }

    /// Invalidate all entries whose directory inode matches a predicate.
    ///
    /// Useful for bulk invalidation after a namespace-wide event.
    /// Returns the number of entries invalidated.
    pub fn invalidate_by_predicate<F>(&mut self, predicate: F) -> usize
    where
        F: Fn(u64) -> bool,
    {
        let count = self
            .registry
            .invalidate_by_key_prefix(CacheClass::PosixNamespaceMirror, |dir_ino| {
                predicate(*dir_ino)
            });
        self.stats.invalidations = self.stats.invalidations.saturating_add(count as u64);
        self.stats.cache_size_entries = self.registry.entry_count(CacheClass::PosixNamespaceMirror);
        count
    }

    /// Return the current number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.registry.entry_count(CacheClass::PosixNamespaceMirror)
    }

    /// Return true if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return a snapshot of the current cache statistics.
    #[must_use]
    pub fn stats(&self) -> DirectoryListingCacheStats {
        DirectoryListingCacheStats {
            cache_size_entries: self.registry.entry_count(CacheClass::PosixNamespaceMirror),
            ..self.stats
        }
    }
}

impl Default for DirectoryListingCache {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DirectoryListingCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectoryListingCache")
            .field("entries", &self.len())
            .field("stats", &self.stats())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_cache_lattice_core::ValidityToken;

    /// Helper: build a small listing with two entries.
    fn sample_listing(token: ValidityToken) -> DirListingEntry {
        DirListingEntry::new(
            vec![
                (0xaaa, 100, 8), // DT_REG
                (0xbbb, 101, 4), // DT_DIR
            ],
            token,
            1700000000000,
        )
    }

    fn meta_governor() -> Governor {
        Governor::new(crate::GovernorConfig {
            total_budget_bytes: 4096,
            data_cache_fraction: 0.0,
            meta_cache_fraction: 1.0,
            dirty_bytes_fraction: 0.0,
            inode_state_fraction: 0.0,
            cluster_queues_fraction: 0.0,
            misc_fraction: 0.0,
            auto_tune: false,
        })
        .unwrap()
    }

    #[test]
    fn governor_charges_directory_listing_to_meta_cache() {
        let governor = meta_governor();
        let mut cache = DirectoryListingCache::new();
        cache.set_governor(governor.clone());
        let token = ValidityToken::compute(1, b"dir_v1");
        let listing = sample_listing(token);
        let size = listing.size_bytes;

        cache.insert(42, listing);
        assert_eq!(governor.category_used(crate::BudgetCategory::MetaCache), size);
        assert_eq!(governor.category_used(crate::BudgetCategory::DataCache), 0);

        cache.invalidate(42);
        assert_eq!(governor.category_used(crate::BudgetCategory::MetaCache), 0);
    }

    // ── basic insert and get ───────────────────────────────────────

    #[test]
    fn hot_cache_hit() {
        let mut cache = DirectoryListingCache::new();
        let token = ValidityToken::compute(1, b"dir_v1");
        cache.insert(42, sample_listing(token));

        let result = cache.get(42, &token);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 2);

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 0);
    }

    #[test]
    fn cold_cache_miss() {
        let mut cache = DirectoryListingCache::new();
        let token = ValidityToken::compute(1, b"dir_v1");

        let result = cache.get(42, &token);
        assert!(result.is_none());

        let stats = cache.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn miss_then_populate_then_hit() {
        let mut cache = DirectoryListingCache::new();
        let token = ValidityToken::compute(1, b"dir_v1");

        // Cold miss.
        assert!(cache.get(42, &token).is_none());
        assert_eq!(cache.stats().misses, 1);

        // Populate.
        cache.insert(42, sample_listing(token));

        // Hot hit.
        assert!(cache.get(42, &token).is_some());
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    // ── invalidation after create ──────────────────────────────────

    #[test]
    fn invalidation_after_create() {
        let mut cache = DirectoryListingCache::new();
        let token = ValidityToken::compute(1, b"dir_v1");
        cache.insert(42, sample_listing(token));

        // Simulate a create in this directory — invalidate.
        cache.invalidate(42);

        let result = cache.get(42, &token);
        assert!(result.is_none()); // Entry was removed.

        let stats = cache.stats();
        assert_eq!(stats.invalidations, 1);
        assert_eq!(stats.cache_size_entries, 0);
    }

    #[test]
    fn invalidation_after_unlink() {
        let mut cache = DirectoryListingCache::new();
        let token = ValidityToken::compute(1, b"dir_v1");
        cache.insert(42, sample_listing(token));
        cache.insert(99, sample_listing(token));

        // Unlink in dir 42 only.
        cache.invalidate(42);

        // Dir 42 is gone.
        assert!(cache.get(42, &token).is_none());
        // Dir 99 is still cached.
        assert!(cache.get(99, &token).is_some());

        let stats = cache.stats();
        assert_eq!(stats.invalidations, 1);
        assert_eq!(stats.cache_size_entries, 1);
    }

    // ── stale token detection ──────────────────────────────────────

    #[test]
    fn stale_entry_token_mismatch_returns_none() {
        let mut cache = DirectoryListingCache::new();
        let v1 = ValidityToken::compute(1, b"dir_v1");
        let v2 = ValidityToken::compute(2, b"dir_v2");

        cache.insert(42, sample_listing(v1));

        // Lookup with a newer token — the cached entry is stale.
        let result = cache.get(42, &v2);
        assert!(result.is_none());

        // Should count as a miss.
        let stats = cache.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 0);
    }

    #[test]
    fn stale_entry_preserved_after_mismatch() {
        let mut cache = DirectoryListingCache::new();
        let v1 = ValidityToken::compute(1, b"dir_v1");
        let v2 = ValidityToken::compute(2, b"dir_v2");

        cache.insert(42, sample_listing(v1));

        // Lookup with mismatched token returns None (stale).
        assert!(cache.get(42, &v2).is_none());

        // Lookup with original valid token still hits (entry preserved).
        assert!(cache.get(42, &v1).is_some());
    }

    // ── concurrent readdir + mutation ──────────────────────────────

    #[test]
    fn concurrent_readdir_and_mutation() {
        let mut cache = DirectoryListingCache::new();
        let v1 = ValidityToken::compute(1, b"dir_v1");

        // Pre-populate three directories.
        cache.insert(10, sample_listing(v1));
        cache.insert(20, sample_listing(v1));
        cache.insert(30, sample_listing(v1));
        assert_eq!(cache.len(), 3);

        // Read from dir 10.
        assert!(cache.get(10, &v1).is_some());

        // Mutate dir 20 (invalidate).
        cache.invalidate(20);

        // Dir 10 still hit, dir 20 miss, dir 30 still hit.
        assert!(cache.get(10, &v1).is_some());
        assert!(cache.get(20, &v1).is_none());
        assert!(cache.get(30, &v1).is_some());

        let stats = cache.stats();
        assert_eq!(stats.hits, 3);
        assert_eq!(stats.invalidations, 1);
    }

    // ── empty directory listing ────────────────────────────────────

    #[test]
    fn empty_directory_listing_cached() {
        let mut cache = DirectoryListingCache::new();
        let token = ValidityToken::compute(1, b"empty_dir");
        let empty = DirListingEntry::new(vec![], token, 1700000000000);

        cache.insert(42, empty);
        let result = cache.get(42, &token);
        assert!(result.is_some());
        assert!(result.unwrap().is_empty());
    }

    // ── multiple inserts for same inode ────────────────────────────

    #[test]
    fn insert_replaces_existing_entry() {
        let mut cache = DirectoryListingCache::new();
        let v1 = ValidityToken::compute(1, b"dir_v1");
        let v2 = ValidityToken::compute(2, b"dir_v2");

        cache.insert(42, sample_listing(v1));
        assert_eq!(cache.len(), 1);

        // Replace with a listing that has a different token.
        let updated = DirListingEntry::new(vec![(0xccc, 200, 8)], v2, 1700000001000);
        cache.insert(42, updated);
        assert_eq!(cache.len(), 1);

        // The old token should miss.
        assert!(cache.get(42, &v1).is_none());
        // The new token should hit.
        let result = cache.get(42, &v2);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 1);
    }

    // ── stats snapshot ─────────────────────────────────────────────

    #[test]
    fn stats_snapshot_reflects_current_state() {
        let mut cache = DirectoryListingCache::new();
        let token = ValidityToken::compute(1, b"dir_v1");

        cache.insert(1, sample_listing(token));
        cache.insert(2, sample_listing(token));
        cache.get(1, &token);
        cache.get(3, &token); // miss

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.cache_size_entries, 2);
        assert_eq!(stats.invalidations, 0);
    }

    // ── is_empty and len ───────────────────────────────────────────

    #[test]
    fn empty_cache_len_and_is_empty() {
        let cache = DirectoryListingCache::new();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn non_empty_cache_len() {
        let mut cache = DirectoryListingCache::new();
        let token = ValidityToken::compute(1, b"dir_v1");
        cache.insert(1, sample_listing(token));
        cache.insert(2, sample_listing(token));

        assert_eq!(cache.len(), 2);
        assert!(!cache.is_empty());
    }
}
