// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Path lookup cache for positive lookup/getattr acceleration and
//! negative (ENOENT) caching.
//!
//! Caches `(parent_ino, name)` → `(ino, generation, value)` for positive
//! hits and `(parent_ino, name)` → expiry for ENOENT (negative) hits.
//! Positive entries use LRU eviction with configurable TTL; negative
//! entries use a simpler TTL-only map with a separate configurable TTL
//! (default 5 seconds).
//!
//! Designed for the FUSE daemon `dispatch_lookup` hot path:
//!  1. check positive cache → hit (return cached attrs)
//!  2. check negative cache → hit (return ENOENT)
//!  3. miss → walk namespace
//!
//! Invalidation hooks (`invalidate_child`, `invalidate_parent`) are
//! called on namespace mutations (create, unlink, rename, rmdir, etc.).

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

// ── PathLookupKey ───────────────────────────────────────────────────────

/// Cache key: (parent_inode, child_name).
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct PathLookupKey {
    /// Parent directory inode number.
    pub parent_ino: u64,
    /// Child name as raw bytes.
    pub name: Vec<u8>,
}

impl PathLookupKey {
    /// Create a new path lookup key.
    #[must_use]
    pub fn new(parent_ino: u64, name: &[u8]) -> Self {
        Self {
            parent_ino,
            name: name.to_vec(),
        }
    }
}

// ── PathLookupEntry ─────────────────────────────────────────────────────

/// A cached positive lookup result.
///
/// `V` is the value type stored alongside the inode identity
/// (e.g., `FuseAttrOut`, `InodeAttr`, or a custom wrapper).
#[derive(Clone, Debug)]
pub struct PathLookupEntry<V: Clone> {
    /// Resolved inode number.
    pub ino: u64,
    /// Inode generation at cache time.
    pub generation: u64,
    /// The cached value (e.g., inode attributes).
    pub value: V,
    /// Absolute expiry time; the entry is stale after this instant.
    expiry: Instant,
}

impl<V: Clone> PathLookupEntry<V> {
    /// Create a new path lookup entry with the given TTL.
    #[must_use]
    pub fn new(ino: u64, generation: u64, value: V, ttl: Duration) -> Self {
        Self {
            ino,
            generation,
            value,
            expiry: Instant::now() + ttl,
        }
    }

    /// Returns `true` if the entry has not expired.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        Instant::now() < self.expiry
    }
}

// ── PathLookupCacheStats ────────────────────────────────────────────────

/// Aggregated statistics for a [`PathLookupCache`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PathLookupCacheStats {
    /// Number of positive cache hits (entry found, non-expired).
    pub positive_hits: u64,
    /// Number of positive cache misses (entry not found or expired).
    pub positive_misses: u64,
    /// Number of negative cache hits (ENOENT served from negative cache).
    pub negative_hits: u64,
    /// Number of negative cache misses (no matching negative entry).
    pub negative_misses: u64,
    /// Number of invalidations performed (child or parent-dir).
    pub invalidations: u64,
}

impl PathLookupCacheStats {
    /// Total lookups (positive hits + misses + negative hits + misses).
    #[must_use]
    pub fn total_lookups(&self) -> u64 {
        self.positive_hits + self.positive_misses + self.negative_hits + self.negative_misses
    }

    /// Positive cache hit rate (0.0–1.0). Returns 0.0 if no lookups.
    #[must_use]
    pub fn positive_hit_rate(&self) -> f64 {
        let total = self.positive_hits + self.positive_misses;
        if total == 0 {
            0.0
        } else {
            self.positive_hits as f64 / total as f64
        }
    }

    /// Negative cache hit rate (0.0–1.0). Returns 0.0 if no lookups.
    #[must_use]
    pub fn negative_hit_rate(&self) -> f64 {
        let total = self.negative_hits + self.negative_misses;
        if total == 0 {
            0.0
        } else {
            self.negative_hits as f64 / total as f64
        }
    }
}

// ── PathLookupCache ─────────────────────────────────────────────────────

/// Combined positive + negative path lookup cache.
///
/// Positive cache: `(parent_ino, name)` → `(ino, generation, value)`
/// with LRU eviction and TTL-based expiry.
///
/// Negative cache: `(parent_ino, name)` → expiry time for ENOENT
/// results.  A separate shorter TTL (default 5 s) limits the window
/// in which a stale negative entry can hide a newly created file.
///
/// The canonical lookup flow via [`lookup`] is:
///  1. Check positive cache → hit (return `Positive`)
///  2. Check negative cache → hit (return `Negative` / ENOENT)
///  3. Return `Miss` — caller must walk the namespace.
pub struct PathLookupCache<V: Clone> {
    /// Positive entries: map from key to cached entry.
    entries: HashMap<PathLookupKey, PathLookupEntry<V>>,
    /// LRU order for positive entries: front = oldest, back = newest.
    lru_order: VecDeque<PathLookupKey>,
    /// Maximum number of cached entries before eviction.
    max_entries: usize,
    /// Default TTL for newly inserted positive entries.
    default_ttl: Duration,
    /// Negative cache: map from key to absolute expiry time.
    negative_entries: HashMap<PathLookupKey, Instant>,
    /// Default TTL for negative entries (default 5 s).
    negative_ttl: Duration,
    /// Aggregated statistics.
    stats: PathLookupCacheStats,
}

impl<V: Clone> PathLookupCache<V> {
    /// Create a new path lookup cache.
    ///
    /// `max_entries` caps the number of resident positive entries; the
    /// LRU entry is evicted when at capacity.
    /// `default_ttl` is the time-to-live for newly inserted positive
    /// entries.  Negative TTL defaults to 5 seconds; use
    /// [`set_negative_ttl`] to configure.
    #[must_use]
    pub fn new(max_entries: usize, default_ttl: Duration) -> Self {
        Self {
            entries: HashMap::with_capacity(max_entries.min(256)),
            lru_order: VecDeque::with_capacity(max_entries.min(256)),
            max_entries: max_entries.max(1),
            default_ttl,
            negative_entries: HashMap::new(),
            negative_ttl: Duration::from_secs(5),
            stats: PathLookupCacheStats::default(),
        }
    }

    /// Set the TTL for negative (ENOENT) cache entries.
    pub fn set_negative_ttl(&mut self, ttl: Duration) {
        self.negative_ttl = ttl;
    }

    /// Return the current negative TTL.
    #[must_use]
    pub fn negative_ttl(&self) -> Duration {
        self.negative_ttl
    }

    // ── Lookup (combined positive + negative) ──────────────────────────

    /// Look up `(parent_ino, name)` in both caches.
    ///
    /// Returns `LookupResult::Positive` on a non-expired positive hit,
    /// `LookupResult::Negative` on a non-expired negative hit (ENOENT),
    /// or `LookupResult::Miss` when the caller must walk the namespace.
    ///
    /// Expired entries in either cache are pruned eagerly.
    pub fn lookup(&mut self, parent_ino: u64, name: &[u8]) -> LookupResult<'_, V> {
        // Check both caches first, update stats, then fetch the entry
        // reference.  This avoids holding a borrow across stats mutation.
        let key = PathLookupKey::new(parent_ino, name);
        let pos_hit = !self.positive_expired_or_absent(&key);
        let neg_hit = !pos_hit && self.check_negative(parent_ino, name);

        if pos_hit {
            self.stats.positive_hits += 1;
        } else {
            self.stats.positive_misses += 1;
        }

        if neg_hit {
            self.stats.negative_hits += 1;
        } else if !pos_hit {
            self.stats.negative_misses += 1;
        }

        // Now fetch and return (no further stats mutations).
        if pos_hit {
            if let Some(entry) = self.get_internal(parent_ino, name) {
                return LookupResult::Positive(entry);
            }
        }
        if neg_hit {
            return LookupResult::Negative;
        }
        LookupResult::Miss
    }

    /// Returns true if the key is absent from the positive cache OR the
    /// entry has expired (and was pruned).  Does NOT update LRU position
    /// or stats.
    fn positive_expired_or_absent(&mut self, key: &PathLookupKey) -> bool {
        // Check expiry without holding a long-lived borrow.
        let expired = self.entries.get(key).is_some_and(|e| !e.is_valid());
        if expired {
            self.entries.remove(key);
            self.unlink_lru(key);
            return true;
        }
        // Not expired: if key is present, it is valid.
        !self.entries.contains_key(key)
    }

    /// Look up `(parent_ino, name)` in the positive cache only.
    ///
    /// Returns a reference to the entry on hit (non-expired), or `None`
    /// on miss or expiry. Expired entries are removed eagerly.
    /// On hit, the entry is moved to the MRU position.
    /// Look up `(parent_ino, name)` in the positive cache only.
    ///
    /// Returns a reference to the entry on hit (non-expired), or `None`
    /// on miss or expiry. Expired entries are removed eagerly.
    /// On hit, the entry is moved to the MRU position.
    pub fn get(&mut self, parent_ino: u64, name: &[u8]) -> Option<&PathLookupEntry<V>> {
        let key = PathLookupKey::new(parent_ino, name);
        let pos_hit = !self.positive_expired_or_absent(&key);

        if pos_hit {
            self.stats.positive_hits += 1;
        } else {
            self.stats.positive_misses += 1;
        }

        // Now fetch (no further stats mutations).
        self.get_internal(parent_ino, name)
    }

    /// Internal positive-cache lookup without stats tracking.
    fn get_internal(&mut self, parent_ino: u64, name: &[u8]) -> Option<&PathLookupEntry<V>> {
        let key = PathLookupKey::new(parent_ino, name);

        let expired = self.entries.get(&key).is_some_and(|e| !e.is_valid());
        if expired {
            self.entries.remove(&key);
            self.unlink_lru(&key);
            return None;
        }

        if self.entries.contains_key(&key) {
            self.touch_lru(&key);
            Some(&self.entries[&key])
        } else {
            None
        }
    }

    /// Check negative cache for `(parent_ino, name)`.
    /// Returns `true` if a non-expired negative entry exists.
    /// Expired negative entries are pruned eagerly.
    pub fn is_negative_cached(&mut self, parent_ino: u64, name: &[u8]) -> bool {
        self.check_negative(parent_ino, name)
    }

    fn check_negative(&mut self, parent_ino: u64, name: &[u8]) -> bool {
        let key = PathLookupKey::new(parent_ino, name);
        match self.negative_entries.get(&key) {
            Some(expiry) if Instant::now() < *expiry => true,
            Some(_) => {
                self.negative_entries.remove(&key);
                false
            }
            None => false,
        }
    }

    /// Check if `(parent_ino, name)` exists in the positive cache and is
    /// non-expired.  Does NOT update LRU position (read-only check).
    #[must_use]
    pub fn contains(&mut self, parent_ino: u64, name: &[u8]) -> bool {
        let key = PathLookupKey::new(parent_ino, name);
        let expired = self.entries.get(&key).is_some_and(|e| !e.is_valid());
        if expired {
            self.entries.remove(&key);
            self.unlink_lru(&key);
            false
        } else {
            self.entries.contains_key(&key)
        }
    }

    // ── Insert ──────────────────────────────────────────────────────────

    /// Insert a positive entry.  If the cache is at capacity, the LRU
    /// entry is evicted.  If the key already exists, the entry is updated
    /// and moved to MRU position.
    ///
    /// Also removes any matching negative entry (the file now exists).
    pub fn insert(&mut self, parent_ino: u64, name: &[u8], ino: u64, generation: u64, value: V) {
        let key = PathLookupKey::new(parent_ino, name);

        // Clear any negative entry for this key — the file now exists.
        self.negative_entries.remove(&key);

        // If key exists in positive cache, update in place + touch LRU.
        if self.entries.contains_key(&key) {
            self.entries.insert(
                key.clone(),
                PathLookupEntry::new(ino, generation, value, self.default_ttl),
            );
            self.touch_lru(&key);
            return;
        }

        // Evict oldest if at capacity.
        if self.entries.len() >= self.max_entries {
            self.evict_one();
        }

        self.entries.insert(
            key.clone(),
            PathLookupEntry::new(ino, generation, value, self.default_ttl),
        );
        self.lru_order.push_back(key);
    }

    /// Insert a negative (ENOENT) entry for `(parent_ino, name)`.
    ///
    /// Uses the configured negative TTL.  Removes any matching positive
    /// entry if one exists.
    pub fn insert_negative(&mut self, parent_ino: u64, name: &[u8]) {
        let key = PathLookupKey::new(parent_ino, name);

        // Remove any stale positive entry for this key.
        self.entries.remove(&key);
        self.unlink_lru(&key);

        self.negative_entries
            .insert(key, Instant::now() + self.negative_ttl);
    }

    /// Remove a negative entry (e.g., after a successful create).
    /// Returns `true` if a negative entry was present.
    pub fn remove_negative(&mut self, parent_ino: u64, name: &[u8]) -> bool {
        let key = PathLookupKey::new(parent_ino, name);
        self.negative_entries.remove(&key).is_some()
    }

    // ── Invalidation ────────────────────────────────────────────────────

    /// Invalidate a specific `(parent_ino, name)` entry in both caches.
    pub fn invalidate_child(&mut self, parent_ino: u64, name: &[u8]) {
        let key = PathLookupKey::new(parent_ino, name);
        let had_positive = self.entries.remove(&key).is_some();
        self.unlink_lru(&key);
        let had_negative = self.negative_entries.remove(&key).is_some();
        if had_positive || had_negative {
            self.stats.invalidations += 1;
        }
    }

    /// Invalidate all entries for a given parent directory in both caches.
    pub fn invalidate_parent_dir(&mut self, parent_ino: u64) {
        let pos_keys: Vec<PathLookupKey> = self
            .entries
            .keys()
            .filter(|k| k.parent_ino == parent_ino)
            .cloned()
            .collect();
        let neg_keys: Vec<PathLookupKey> = self
            .negative_entries
            .keys()
            .filter(|k| k.parent_ino == parent_ino)
            .cloned()
            .collect();

        let count = pos_keys.len() + neg_keys.len();
        if count > 0 {
            self.stats.invalidations += count as u64;
        }

        for key in &pos_keys {
            self.entries.remove(key);
            self.unlink_lru(key);
        }
        for key in &neg_keys {
            self.negative_entries.remove(key);
        }
    }

    /// Remove all positive entries whose cached inode matches `ino`.
    /// Called on setattr to evict stale attribute snapshots.
    pub fn remove_by_ino(&mut self, ino: u64) {
        let keys_to_remove: Vec<PathLookupKey> = self
            .entries
            .iter()
            .filter(|(_, e)| e.ino == ino)
            .map(|(k, _)| k.clone())
            .collect();
        let count = keys_to_remove.len();
        for key in &keys_to_remove {
            self.entries.remove(key);
            self.unlink_lru(key);
        }
        if count > 0 {
            self.stats.invalidations += count as u64;
        }
    }

    /// Remove all entries (positive and negative) from the cache.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.lru_order.clear();
        self.negative_entries.clear();
    }

    // ── Statistics ──────────────────────────────────────────────────────

    /// Return a snapshot of the current statistics.
    #[must_use]
    pub fn stats(&self) -> PathLookupCacheStats {
        self.stats
    }

    /// Reset all statistics counters to zero.
    pub fn reset_stats(&mut self) {
        self.stats = PathLookupCacheStats::default();
    }

    /// Return the current number of positive cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return the number of negative cached entries.
    #[must_use]
    pub fn negative_len(&self) -> usize {
        self.negative_entries.len()
    }

    /// Return `true` if both caches are empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.negative_entries.is_empty()
    }

    /// Return the maximum number of positive entries.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.max_entries
    }

    // ── Internal helpers ────────────────────────────────────────────────

    /// Move `key` to the MRU end of the LRU order.
    fn touch_lru(&mut self, key: &PathLookupKey) {
        if let Some(pos) = self.lru_order.iter().position(|k| k == key) {
            self.lru_order.remove(pos);
        }
        self.lru_order.push_back(key.clone());
    }

    /// Remove `key` from the LRU order if present.
    fn unlink_lru(&mut self, key: &PathLookupKey) {
        if let Some(pos) = self.lru_order.iter().position(|k| k == key) {
            self.lru_order.remove(pos);
        }
    }

    /// Evict the LRU positive entry (front of the deque).
    fn evict_one(&mut self) -> Option<PathLookupEntry<V>> {
        let key = self.lru_order.pop_front()?;
        self.entries.remove(&key)
    }
}

// ── LookupResult ────────────────────────────────────────────────────────

/// Result of a combined [`PathLookupCache::lookup`] call.
#[derive(Debug)]
pub enum LookupResult<'a, V: Clone> {
    /// Positive hit: the entry was found and is non-expired.
    Positive(&'a PathLookupEntry<V>),
    /// Negative hit: a non-expired ENOENT entry exists.
    Negative,
    /// Miss: neither cache had a match; caller must walk the namespace.
    Miss,
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestCache = PathLookupCache<String>;

    fn new_cache(capacity: usize) -> TestCache {
        PathLookupCache::new(capacity, Duration::from_secs(60))
    }

    // ── Positive cache tests (existing) ─────────────────────────────────

    #[test]
    fn insert_and_get() {
        let mut cache = new_cache(10);
        cache.insert(1, b"hello.txt", 100, 1, "attrs_100".into());
        let entry = cache.get(1, b"hello.txt").unwrap();
        assert_eq!(entry.ino, 100);
        assert_eq!(entry.generation, 1);
        assert_eq!(entry.value, "attrs_100");
    }

    #[test]
    fn get_missing_returns_none() {
        let mut cache = new_cache(10);
        assert!(cache.get(1, b"nope").is_none());
    }

    #[test]
    fn get_expired_returns_none() {
        let mut cache: TestCache = PathLookupCache::new(10, Duration::from_millis(1));
        cache.insert(1, b"ephemeral", 100, 1, "gone".into());
        std::thread::sleep(Duration::from_millis(5));
        assert!(cache.get(1, b"ephemeral").is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn insert_updates_existing() {
        let mut cache = new_cache(10);
        cache.insert(1, b"name", 100, 1, "first".into());
        cache.insert(1, b"name", 200, 2, "second".into());
        let entry = cache.get(1, b"name").unwrap();
        assert_eq!(entry.ino, 200);
        assert_eq!(entry.generation, 2);
        assert_eq!(entry.value, "second");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn lru_eviction() {
        let mut cache = new_cache(2);
        cache.insert(1, b"one", 10, 1, "v1".into());
        cache.insert(2, b"two", 20, 1, "v2".into());
        cache.get(1, b"one"); // touch to make MRU
        cache.insert(3, b"three", 30, 1, "v3".into());
        assert!(cache.get(2, b"two").is_none());
        assert!(cache.get(1, b"one").is_some());
        assert!(cache.get(3, b"three").is_some());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn invalidate_child_removes_entry() {
        let mut cache = new_cache(10);
        cache.insert(1, b"a", 10, 1, "va".into());
        cache.insert(1, b"b", 20, 1, "vb".into());
        cache.invalidate_child(1, b"a");
        assert!(cache.get(1, b"a").is_none());
        assert!(cache.get(1, b"b").is_some());
    }

    #[test]
    fn invalidate_parent_dir_removes_all_children() {
        let mut cache = new_cache(10);
        cache.insert(1, b"a", 10, 1, "va".into());
        cache.insert(1, b"b", 20, 1, "vb".into());
        cache.insert(2, b"c", 30, 1, "vc".into());
        cache.invalidate_parent_dir(1);
        assert!(cache.get(1, b"a").is_none());
        assert!(cache.get(1, b"b").is_none());
        assert!(cache.get(2, b"c").is_some());
    }

    #[test]
    fn invalidate_child_nonexistent_is_noop() {
        let mut cache = new_cache(10);
        cache.insert(1, b"a", 10, 1, "v".into());
        cache.invalidate_child(1, b"nonexistent");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn invalidate_parent_dir_nonexistent_is_noop() {
        let mut cache = new_cache(10);
        cache.insert(1, b"a", 10, 1, "v".into());
        cache.invalidate_parent_dir(999);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn clear_removes_all() {
        let mut cache = new_cache(10);
        cache.insert(1, b"a", 10, 1, "v".into());
        cache.insert(2, b"b", 20, 1, "v".into());
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn capacity_respected_under_bulk_insert() {
        let mut cache = new_cache(4);
        for i in 0..8 {
            cache.insert(i, b"entry", 100 + i, 1, format!("v{i}"));
        }
        assert!(cache.len() <= 4);
        for i in 0..4 {
            assert!(cache.get(i, b"entry").is_none());
        }
        for i in 4..8 {
            assert!(cache.get(i, b"entry").is_some());
        }
    }

    #[test]
    fn remove_by_ino_removes_all_matching() {
        let mut cache = new_cache(10);
        cache.insert(1, b"a", 100, 1, "va".into());
        cache.insert(1, b"b", 100, 1, "vb".into());
        cache.insert(2, b"c", 200, 1, "vc".into());
        cache.remove_by_ino(100);
        assert!(cache.get(1, b"a").is_none());
        assert!(cache.get(1, b"b").is_none());
        assert!(cache.get(2, b"c").is_some());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn lru_discipline_across_gets() {
        let mut cache = new_cache(3);
        cache.insert(1, b"a", 10, 1, "v".into());
        cache.insert(2, b"b", 20, 1, "v".into());
        cache.insert(3, b"c", 30, 1, "v".into());
        cache.get(3, b"c");
        cache.get(2, b"b");
        cache.get(1, b"a");
        cache.insert(4, b"d", 40, 1, "v".into());
        assert!(cache.get(3, b"c").is_none());
        assert!(cache.get(1, b"a").is_some());
        assert!(cache.get(2, b"b").is_some());
        assert!(cache.get(4, b"d").is_some());
    }

    // ── Negative cache tests ────────────────────────────────────────────

    #[test]
    fn insert_negative_and_lookup() {
        let mut cache = new_cache(10);
        cache.insert_negative(1, b"nonexistent.txt");

        match cache.lookup(1, b"nonexistent.txt") {
            LookupResult::Negative => {} // expected
            other => panic!("expected Negative, got {other:?}"),
        }
    }

    #[test]
    fn negative_cache_hit_returns_enonent() {
        let mut cache = new_cache(10);
        cache.insert_negative(2, b"ghost");

        assert!(cache.is_negative_cached(2, b"ghost"));
        match cache.lookup(2, b"ghost") {
            LookupResult::Negative => {}
            other => panic!("expected Negative, got {other:?}"),
        }
    }

    #[test]
    fn negative_expiry() {
        let mut cache: TestCache = PathLookupCache::new(10, Duration::from_secs(60));
        cache.set_negative_ttl(Duration::from_millis(1));
        cache.insert_negative(1, b"temp");

        std::thread::sleep(Duration::from_millis(5));

        match cache.lookup(1, b"temp") {
            LookupResult::Miss => {} // expired, should miss
            other => panic!("expected Miss after expiry, got {other:?}"),
        }
    }

    #[test]
    fn insert_negative_clears_matching_positive() {
        let mut cache = new_cache(10);
        cache.insert(1, b"file", 100, 1, "attrs".into());
        assert!(cache.get(1, b"file").is_some());

        cache.insert_negative(1, b"file");
        assert!(cache.get(1, b"file").is_none());
        assert!(cache.is_negative_cached(1, b"file"));
    }

    #[test]
    fn insert_positive_clears_matching_negative() {
        let mut cache = new_cache(10);
        cache.insert_negative(1, b"file");
        assert!(cache.is_negative_cached(1, b"file"));

        cache.insert(1, b"file", 100, 1, "attrs".into());
        assert!(!cache.is_negative_cached(1, b"file"));
        assert!(cache.get(1, b"file").is_some());
    }

    #[test]
    fn invalidate_child_removes_both_caches() {
        let mut cache = new_cache(10);
        cache.insert(1, b"a", 10, 1, "va".into());
        cache.insert_negative(1, b"b");

        cache.invalidate_child(1, b"a");
        cache.invalidate_child(1, b"b");

        assert!(cache.get(1, b"a").is_none());
        assert!(!cache.is_negative_cached(1, b"b"));
    }

    #[test]
    fn invalidate_parent_dir_removes_negative_entries() {
        let mut cache = new_cache(10);
        cache.insert(1, b"real", 10, 1, "v".into());
        cache.insert_negative(1, b"ghost1");
        cache.insert_negative(1, b"ghost2");
        cache.insert_negative(2, b"ghost3");

        cache.invalidate_parent_dir(1);

        assert!(cache.get(1, b"real").is_none());
        assert!(!cache.is_negative_cached(1, b"ghost1"));
        assert!(!cache.is_negative_cached(1, b"ghost2"));
        assert!(cache.is_negative_cached(2, b"ghost3"));
    }

    #[test]
    fn remove_negative_returns_true_only_when_present() {
        let mut cache = new_cache(10);
        assert!(!cache.remove_negative(1, b"nope"));

        cache.insert_negative(1, b"yep");
        assert!(cache.remove_negative(1, b"yep"));
        assert!(!cache.is_negative_cached(1, b"yep"));
    }

    // ── Combined lookup tests ───────────────────────────────────────────

    #[test]
    fn combined_lookup_positive_hit() {
        let mut cache = new_cache(10);
        cache.insert(1, b"file", 100, 1, "attrs".into());

        match cache.lookup(1, b"file") {
            LookupResult::Positive(e) => {
                assert_eq!(e.ino, 100);
                assert_eq!(e.value, "attrs");
            }
            other => panic!("expected Positive, got {other:?}"),
        }
    }

    #[test]
    fn combined_lookup_miss_when_both_empty() {
        let mut cache = new_cache(10);
        match cache.lookup(1, b"nothing") {
            LookupResult::Miss => {}
            other => panic!("expected Miss, got {other:?}"),
        }
    }

    #[test]
    fn combined_lookup_positive_takes_priority_over_negative() {
        let mut cache = new_cache(10);
        cache.insert(1, b"dual", 42, 1, "real".into());
        cache.insert_negative(1, b"dual");

        // When both exist, positive entry must win (file now exists).
        // insert_negative clears positive, so re-insert positive after.
        // Actually the insert order matters: insert_negative clears positive
        // so we need to re-insert the positive after the negative.
        // Let's just re-insert for clarity.
        cache.insert(1, b"dual", 42, 1, "real".into());

        match cache.lookup(1, b"dual") {
            LookupResult::Positive(e) => assert_eq!(e.ino, 42),
            other => panic!("expected Positive, got {other:?}"),
        }
    }

    // ── Stats tests ─────────────────────────────────────────────────────

    #[test]
    fn stats_positive_hits_and_misses() {
        let mut cache = new_cache(10);
        cache.insert(1, b"hit", 100, 1, "v".into());

        cache.get(1, b"hit"); // hit
        cache.get(1, b"miss"); // miss

        let s = cache.stats();
        assert_eq!(s.positive_hits, 1);
        assert_eq!(s.positive_misses, 1);
    }

    #[test]
    fn stats_negative_hits_and_misses() {
        let mut cache = new_cache(10);
        cache.insert_negative(1, b"ghost");

        cache.lookup(1, b"ghost"); // negative hit
        cache.lookup(1, b"other"); // negative miss (+ positive miss)

        let s = cache.stats();
        assert_eq!(s.negative_hits, 1);
        assert_eq!(s.negative_misses, 1);
    }

    #[test]
    fn stats_invalidation_counts() {
        let mut cache = new_cache(10);
        cache.insert(1, b"a", 10, 1, "va".into());
        cache.insert_negative(1, b"b");

        cache.invalidate_child(1, b"a");
        cache.invalidate_child(1, b"b");

        let s = cache.stats();
        assert_eq!(s.invalidations, 2);
    }

    #[test]
    fn stats_invalidation_count_per_dir() {
        let mut cache = new_cache(10);
        cache.insert(1, b"x", 1, 1, "v".into());
        cache.insert(1, b"y", 2, 1, "v".into());
        cache.insert_negative(1, b"z");
        cache.insert(2, b"w", 3, 1, "v".into());

        cache.invalidate_parent_dir(1);

        let s = cache.stats();
        // 3 entries removed from parent 1
        assert_eq!(s.invalidations, 3);
    }

    #[test]
    fn stats_positive_hit_rate() {
        let mut cache = new_cache(10);
        cache.insert(1, b"x", 100, 1, "v".into());

        cache.get(1, b"x"); // hit
        cache.get(1, b"x"); // hit
        cache.get(1, b"y"); // miss

        let s = cache.stats();
        assert!((s.positive_hit_rate() - 2.0 / 3.0).abs() < 0.001);
    }

    #[test]
    fn stats_hit_rate_zero_when_no_lookups() {
        let cache = new_cache(10);
        let s = cache.stats();
        assert_eq!(s.positive_hit_rate(), 0.0);
        assert_eq!(s.negative_hit_rate(), 0.0);
    }

    #[test]
    fn stats_total_lookups() {
        let mut cache = new_cache(10);
        cache.insert(1, b"a", 10, 1, "v".into());
        cache.insert_negative(1, b"ghost");

        cache.lookup(1, b"a"); // positive hit (1)
        cache.lookup(1, b"ghost"); // pos miss (1) + neg hit (1)
        cache.lookup(1, b"nope"); // pos miss (1) + neg miss (1)

        let s = cache.stats();
        // 1 pos hit + 2 pos misses + 1 neg hit + 1 neg miss = 5
        assert_eq!(s.total_lookups(), 5);
    }

    #[test]
    fn reset_stats_clears_all_counters() {
        let mut cache = new_cache(10);
        cache.insert(1, b"x", 100, 1, "v".into());
        cache.get(1, b"x");
        cache.invalidate_child(1, b"x");

        let s = cache.stats();
        assert!(s.positive_hits > 0);
        assert!(s.invalidations > 0);

        cache.reset_stats();
        let s2 = cache.stats();
        assert_eq!(s2.positive_hits, 0);
        assert_eq!(s2.invalidations, 0);
    }

    // ── Negative TTL config ─────────────────────────────────────────────

    #[test]
    fn default_negative_ttl_is_five_seconds() {
        let cache: TestCache = new_cache(10);
        assert_eq!(cache.negative_ttl(), Duration::from_secs(5));
    }

    #[test]
    fn set_negative_ttl_is_honored() {
        let mut cache = new_cache(10);
        cache.set_negative_ttl(Duration::from_secs(1));
        assert_eq!(cache.negative_ttl(), Duration::from_secs(1));
    }

    #[test]
    fn negative_len_reports_count() {
        let mut cache = new_cache(10);
        assert_eq!(cache.negative_len(), 0);

        cache.insert_negative(1, b"a");
        cache.insert_negative(1, b"b");
        assert_eq!(cache.negative_len(), 2);
    }

    #[test]
    fn is_empty_considers_both_caches() {
        let mut cache = new_cache(10);
        assert!(cache.is_empty());

        cache.insert_negative(1, b"ghost");
        assert!(!cache.is_empty());

        cache.remove_negative(1, b"ghost");
        assert!(cache.is_empty());

        cache.insert(1, b"real", 10, 1, "v".into());
        assert!(!cache.is_empty());
    }

    // ── Invalidation after create/rename simulation ─────────────────────

    #[test]
    fn invalidation_after_create() {
        let mut cache = new_cache(10);

        // Simulate: LOOKUP("newfile") returns ENOENT → cache negative
        cache.insert_negative(1, b"newfile");
        assert!(cache.is_negative_cached(1, b"newfile"));

        // Simulate: CREATE("newfile") → invalidate, insert positive
        cache.invalidate_child(1, b"newfile");
        assert!(!cache.is_negative_cached(1, b"newfile"));
        cache.insert(1, b"newfile", 200, 2, "fresh".into());

        match cache.lookup(1, b"newfile") {
            LookupResult::Positive(e) => assert_eq!(e.ino, 200),
            other => panic!("expected Positive after create, got {other:?}"),
        }
    }

    #[test]
    fn invalidation_after_rename() {
        let mut cache = new_cache(10);

        // Old name is cached
        cache.insert(1, b"oldname", 100, 1, "old".into());

        // Rename from oldname to newname
        cache.invalidate_child(1, b"oldname");
        cache.insert(1, b"newname", 100, 1, "renamed".into());

        assert!(cache.get(1, b"oldname").is_none());
        match cache.lookup(1, b"newname") {
            LookupResult::Positive(e) => {
                assert_eq!(e.value, "renamed");
            }
            other => panic!("expected Positive for newname, got {other:?}"),
        }
    }

    #[test]
    fn invalidation_after_unlink() {
        let mut cache = new_cache(10);
        cache.insert(1, b"todelete", 100, 1, "attrs".into());
        cache.invalidate_child(1, b"todelete");

        match cache.lookup(1, b"todelete") {
            LookupResult::Miss => {}
            other => panic!("expected Miss after unlink, got {other:?}"),
        }
    }

    #[test]
    fn invalidation_after_rmdir() {
        let mut cache = new_cache(10);
        cache.insert(1, b"subdir", 100, 1, "dir_attrs".into());
        cache.insert(1, b"file_in_dir", 200, 1, "file_attrs".into());
        cache.insert_negative(1, b"ghost_in_dir");

        cache.invalidate_parent_dir(1);

        assert!(cache.get(1, b"subdir").is_none());
        assert!(cache.get(1, b"file_in_dir").is_none());
        assert!(!cache.is_negative_cached(1, b"ghost_in_dir"));
    }

    // ── Re-validation after negative expiry ─────────────────────────────

    #[test]
    fn revalidate_after_negative_expiry_and_create() {
        let mut cache: TestCache = PathLookupCache::new(10, Duration::from_secs(60));
        cache.set_negative_ttl(Duration::from_millis(1));

        // Step 1: LOOKUP returns ENOENT, negative cache populated
        cache.insert_negative(1, b"late_file");
        assert!(cache.is_negative_cached(1, b"late_file"));

        // Step 2: negative entry expires
        std::thread::sleep(Duration::from_millis(5));

        // Step 3: LOOKUP now misses (negative expired)
        match cache.lookup(1, b"late_file") {
            LookupResult::Miss => {}
            other => panic!("expected Miss after negative expiry, got {other:?}"),
        }

        // Step 4: file is created, inserted into positive cache
        cache.insert(1, b"late_file", 300, 3, "finally".into());

        // Step 5: LOOKUP now hits positive
        match cache.lookup(1, b"late_file") {
            LookupResult::Positive(e) => assert_eq!(e.ino, 300),
            other => panic!("expected Positive after create, got {other:?}"),
        }
    }
}
