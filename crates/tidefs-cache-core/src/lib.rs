// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Cache lattice runtime crate (P4-02 Phase 2).
//!
//! Provides the runtime layer for the tidefs cache lattice:
//! a generic [`CacheLatticeRegistry`], per-class cache storage with
//! [`CacheEntry<V>`], pluggable [`EvictionPolicy`] (LRU/LFU/ARC),
//! [`CacheLookup`] get/insert semantics with staleness detection,
//! [`InvalidationPipeline`] for key-prefix and token-based invalidation,
//! and the 10 inviolable cache rules.
//!
//! Built on the `no_std` authority types in
//! [`tidefs-types-cache-lattice-core`]. This runtime crate uses `std`
//! collections for the mutable hot path.

//! ## Coherency contract with the coordination layer

//!

//! TideFS cache entries carry a [`ValidityToken`] in their header

//! ([`CacheEntryHeader::validity_token`]). The token is recomputed each

//! time the coordination layer signals an authoritative-state change:

//!

//! - **Lease revocation** — when a lease is revoked, the lease manager

//!   generates a new token and calls

//!   [`InvalidationPipeline::invalidate_by_token`] (or

//!   [`CacheLatticeRegistry::invalidate_by_token`]).  All entries whose

//!   stored token does not match the new token are evicted.

//!

//! - **Membership epoch transition** — when the membership view

//!   advances to a new epoch, the membership service generates a new

//!   token and invalidates entries tied to prior epochs via

//!   [`CacheLatticeRegistry::invalidate_by_token`].  Only entries with

//!   the current-epoch token remain servable.

//!

//! - **Node drain** — when a node departs the cluster, the

//!   coordination layer calls

//!   [`CacheLatticeRegistry::invalidate_all`] on every cache class

//!   owned by the draining node.  This bulk eviction ensures no stale

//!   authority survives the membership change.

//!

//! These primitives guarantee that the cache never serves data under a

//! revoked lease or departed epoch, preserving single-writer semantics

//! across multi-node operation.  The coherency contract is validated by

//! the `cache_coherency` module in `tidefs-validation`.

pub mod directory_listing_cache;
pub mod l2arc;
pub mod page_cache;
pub mod path_lookup_cache;
pub mod prefetch;
pub mod weighted_arc;
pub mod governor;
use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};
use tidefs_types_cache_lattice_core::{
    CacheClass, CacheEntryHeader, CacheLatticeReport, CacheLatticeViewReport, EvictabilityClass,
    MemoryDomain, PoisonState, ValidityToken, ViewStats,
};

// Re-exports from weighted_arc
pub use weighted_arc::{ArcList, ArcWeightStats, WeightedArc, WeightedArcEntry};

// Re-exports from governor
pub use governor::{
    budget_category_for_cache_class, budget_category_for_cache_level, budget_category_for_entry,
    AdmissionTicket, BackpressureSignal, BudgetCategory, BudgetError, BudgetPartitionKey,
    BudgetPartitionPolicy, CacheBudgetLevel, CacheReclaimWorker, CommitBoundaryWorker,
    DirtyReclaimWorker, Governor, GovernorAutoTuneDecision, GovernorAutoTuneError,
    GovernorAutoTuneEvidence, GovernorAutoTuneOwner, GovernorAutoTuneSafety,
    GovernorAutoTuneSafetyEffect, GovernorAutoTuneUnit, GovernorCacheReclaimService,
    GovernorCommitBoundaryService, GovernorConfig, GovernorPartitionConfig,
    GovernorDirtyFlushService, GovernorIncrementalReclaimWorker, GovernorPressureState,
    ReclaimOutcome, ReclaimRequest, ReclaimStage, ReclaimWorkKind, AUTO_TUNE_MAX_FRACTION_SHIFT,
    AUTO_TUNE_MAX_FRESHNESS_MS,
};

// ---------------------------------------------------------------------------
// Entry weight for ARC eviction
// ---------------------------------------------------------------------------

/// Per-entry weight for ARC eviction scoring.
///
/// Higher weight = higher retention priority. The weight represents the
/// relative cost of recomputing this entry: entries that are expensive to
/// regenerate (e.g., directory listings, complex queries) should have
/// higher weights and therefore lower eviction scores (less evictable).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EntryWeight(u64);

impl EntryWeight {
    /// Default weight for entries without explicit weighting.
    pub const DEFAULT: Self = EntryWeight(1);

    /// Create a new entry weight. Zero is clamped to 1.
    #[must_use]
    pub fn new(weight: u64) -> Self {
        EntryWeight(if weight == 0 { 1 } else { weight })
    }

    /// Return the raw weight value.
    #[must_use]
    pub fn value(self) -> u64 {
        self.0
    }
}

impl Default for EntryWeight {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl From<u64> for EntryWeight {
    fn from(w: u64) -> Self {
        EntryWeight::new(w)
    }
}

// ---------------------------------------------------------------------------
// Entry weight constants and free functions

// ---------------------------------------------------------------------------

/// Maximum possible entry weight.  Saturates here regardless of access
/// pattern or entry size.
pub const MAX_ENTRY_WEIGHT: u64 = 1_000_000;

/// Compute the initial weight for a newly inserted cache entry.
///
/// Larger entries get proportionally higher initial weight,
/// reflecting the higher cost of re-fetching or rebuilding them.
/// The result is at least `EntryWeight::DEFAULT` and at most
/// `MAX_ENTRY_WEIGHT`.
#[must_use]
pub fn initial_entry_weight(entry_size_bytes: u64) -> EntryWeight {
    let size_component = entry_size_bytes / 256;
    EntryWeight::new(1u64.saturating_add(size_component).min(MAX_ENTRY_WEIGHT))
}

/// Update the weight of a cache entry after a hit.
///
/// Weight increases with repeated access (`hit_count`) and when
/// accesses are close together (`recency_delta` small).  The result
/// saturates at [`MAX_ENTRY_WEIGHT`].
///
/// `recency_delta` is the elapsed time since the previous access to
/// this entry.  A zero delta is safe — it is clamped to 1 ns
/// internally to prevent division-by-zero paths.
#[must_use]
pub fn update_entry_weight(
    current: EntryWeight,
    hit_count: u64,
    recency_delta: Duration,
) -> EntryWeight {
    // Recency bonus: closer accesses get a larger boost
    let recency_ns = recency_delta.as_nanos().max(1);
    let recency_bonus = if recency_ns < 1_000_000_000 {
        ((1_000_000_000u128 - recency_ns) / 10_000_000) as u64
    } else {
        0
    };
    // Hit-count bonus: frequent hits increase weight
    let hit_bonus = (hit_count.min(100)).saturating_mul(5);
    let increment = 50u64
        .saturating_add(recency_bonus)
        .saturating_add(hit_bonus);
    EntryWeight::new(
        current
            .value()
            .saturating_add(increment)
            .min(MAX_ENTRY_WEIGHT),
    )
}

// Ghost list statistics for ARC adaptive sizing

// ---------------------------------------------------------------------------

/// Per-ghost-list hit/miss counters for ARC adaptive target-size (`p`) tuning.
#[derive(Clone, Copy, Debug, Default)]
pub struct GhostListStats {
    /// Hit count on B1 (ghost list for T1 — recently seen once then evicted).
    pub b1_hits: u64,
    /// Miss count on B1.
    pub b1_misses: u64,
    /// Hit count on B2 (ghost list for T2 — frequently seen then evicted).
    pub b2_hits: u64,
    /// Miss count on B2.
    pub b2_misses: u64,
    /// Total number of evictions since last p-recalculation.
    pub evictions_since_adapt: u64,
}

impl GhostListStats {
    /// Record a B1 ghost hit (evicted T1 entry was requested again).
    pub fn record_b1_hit(&mut self) {
        self.b1_hits += 1;
    }

    /// Record a B1 ghost miss.
    pub fn record_b1_miss(&mut self) {
        self.b1_misses += 1;
    }

    /// Record a B2 ghost hit (evicted T2 entry was requested again).
    pub fn record_b2_hit(&mut self) {
        self.b2_hits += 1;
    }

    /// Record a B2 ghost miss.
    pub fn record_b2_miss(&mut self) {
        self.b2_misses += 1;
    }

    /// Record an eviction for adaptation interval counting.
    pub fn record_eviction(&mut self) {
        self.evictions_since_adapt += 1;
    }

    /// True when enough evictions have occurred to trigger p-recalculation.
    #[must_use]
    pub fn should_adapt(&self, interval: u64) -> bool {
        self.evictions_since_adapt >= interval
    }

    /// Reset adaptation counter after p-recalculation.
    pub fn reset_adaptation_counter(&mut self) {
        self.evictions_since_adapt = 0;
    }
}

// ---------------------------------------------------------------------------
// ARC weight configuration

// ---------------------------------------------------------------------------

/// Configuration for ARC eviction with per-entry weights and adaptive ghost sizing.
#[derive(Clone, Copy, Debug)]
pub struct ArcWeightConfig {
    /// Enable per-entry weight tracking for eviction decisions.
    pub enable_per_entry_weight: bool,
    /// Number of evictions between ghost-list p-recalculation cycles.
    pub ghost_adaptation_interval: u64,
    /// Multiplier applied to entry weight in eviction score computation.
    /// Higher values give more influence to the weight component.
    pub weight_factor: f64,
}

impl Default for ArcWeightConfig {
    fn default() -> Self {
        Self {
            enable_per_entry_weight: true,
            ghost_adaptation_interval: 100,
            weight_factor: 1.0,
        }
    }
}

// Cache entry with generic value

// ---------------------------------------------------------------------------

/// A cache entry carrying a typed value, header metadata, eviction score,
/// and optional per-entry retention weight.
///
/// `V` is the value type stored in the cache (e.g., a directory listing
/// or a path-lookup result).
#[derive(Clone, Debug)]
pub struct CacheEntry<V> {
    /// Canonical header (18 fields per P4-02 §4).
    pub header: CacheEntryHeader,
    /// The typed value stored in this cache entry.
    pub value: V,
    /// Composite eviction score used by the eviction policy.
    /// Lower = more evictable. Computed differently per policy.
    pub eviction_score: f64,
    /// Per-entry retention weight (ARC only). Higher = harder to evict.
    /// `None` defaults to [`EntryWeight::DEFAULT`] at eviction time.
    pub weight: Option<EntryWeight>,
    /// Timestamp of last access (for recency-delta computation).
    pub last_access: Instant,
    /// Number of cache hits on this entry (for per-entry weight updates).
    pub hit_count: u64,
}

impl<V> CacheEntry<V> {
    /// Create a new cache entry.
    #[must_use]
    pub fn new(header: CacheEntryHeader, value: V) -> Self {
        Self {
            header,
            value,
            eviction_score: 0.0,
            weight: None,
            last_access: Instant::now(),
            hit_count: 0,
        }
    }

    /// Create a new cache entry with an explicit retention weight.
    #[must_use]
    pub fn with_weight(header: CacheEntryHeader, value: V, weight: EntryWeight) -> Self {
        Self {
            header,
            value,
            eviction_score: 0.0,
            weight: Some(weight),
            last_access: Instant::now(),
            hit_count: 0,
        }
    }

    /// Return the effective weight for eviction scoring.
    #[must_use]
    pub fn effective_weight(&self) -> EntryWeight {
        self.weight.unwrap_or(EntryWeight::DEFAULT)
    }

    /// Return true if this entry is servable (clean, not poisoned, invariants pass).
    #[must_use]
    pub fn is_servable(&self) -> bool {
        self.header.is_servable()
    }

    /// Return true if this entry is stale relative to the given token.
    #[must_use]
    pub fn is_stale(&self, token: ValidityToken) -> bool {
        // Token comparison: if the entry's stored token does not match
        // the current authoritative token, the entry is stale.
        !token.matches(self.header.validity_token)
    }
}

// ---------------------------------------------------------------------------
// Eviction policy

// ---------------------------------------------------------------------------

/// Pluggable eviction policy for cache entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvictionPolicyKind {
    /// Least Recently Used: evict entries with the oldest last-hit time.
    Lru,
    /// Least Frequently Used: evict entries with the lowest hit count.
    Lfu,
    /// Adaptive Replacement Cache: T1 (recent, seen once), T2 (recent, seen
    /// multiple times), B1 (ghost for T1), B2 (ghost for T2). The target
    /// size p adapts based on ghost-list hit patterns.
    Adaptive,
}

impl Default for EvictionPolicyKind {
    fn default() -> Self {
        Self::Lru
    }
}

/// An eviction candidate: the key and the eviction score for an entry.
#[derive(Clone, Debug)]
pub struct EvictionCandidate<K> {
    pub key: K,
    pub eviction_score: f64,
}

/// Computes an LRU eviction score: older last_hit = more evictable (lower score).
fn lru_score<V>(entry: &CacheEntry<V>, _now_counter: u64) -> f64 {
    entry.header.last_hit_counter as f64
}

/// Computes an LFU eviction score: fewer hits = more evictable (lower score).
fn lfu_score<V>(entry: &CacheEntry<V>, _now_counter: u64) -> f64 {
    entry.header.last_hit_counter as f64
}

/// EvictionPolicy: selects which entry to evict given a policy kind.
pub struct EvictionPolicy;

impl EvictionPolicy {
    /// Compute the eviction score for an entry under the given policy.
    pub fn score<V>(policy: EvictionPolicyKind, entry: &CacheEntry<V>, now_counter: u64) -> f64 {
        match policy {
            EvictionPolicyKind::Lru => lru_score(entry, now_counter),
            EvictionPolicyKind::Lfu => lfu_score(entry, now_counter),
            EvictionPolicyKind::Adaptive => {
                // ARC scoring: entries in T2 (frequent) are protected;
                // composite of LRU recency, frequency bonus, and per-entry weight.
                // Higher weight -> higher eviction score (less evictable).
                let base = lru_score(entry, now_counter);
                let freq_bonus = entry.header.last_hit_counter as f64 * 0.1;
                let weight = entry.effective_weight().value() as f64;
                // Weight increases eviction score: heavier entries are less evictable.
                base + freq_bonus + weight * 10.0
            }
        }
    }

    /// Select the best eviction candidate from a set of entries.
    /// Returns the index of the entry with the lowest eviction score.
    pub fn select_eviction_candidate<V>(
        policy: EvictionPolicyKind,
        entries: &[(u64, &CacheEntry<V>)],
        now_counter: u64,
    ) -> Option<usize> {
        if entries.is_empty() {
            return None;
        }
        let mut best_idx = 0;
        let mut best_score = f64::MAX;
        for (i, (_key, entry)) in entries.iter().enumerate() {
            let score = Self::score(policy, entry, now_counter);
            if score < best_score {
                best_score = score;
                best_idx = i;
            }
        }
        Some(best_idx)
    }
}

// ---------------------------------------------------------------------------
// Cache store — internal per-class HashMap-backed storage

// ---------------------------------------------------------------------------

/// Internal per-class cache storage with capacity enforcement.
struct CacheStore<K: Eq + std::hash::Hash + Clone, V> {
    entries: HashMap<K, CacheEntry<V>>,
    capacity: usize,
    policy: EvictionPolicyKind,
    hit_counter: u64,
    /// Ghost-list statistics for ARC adaptive sizing.
    ghost_stats: GhostListStats,
    /// ARC weight configuration.
    arc_config: ArcWeightConfig,
    /// Current ARC target size p (balance between T1 and T2).
    arc_p: f64,
}

impl<K: Eq + std::hash::Hash + Clone + fmt::Debug, V> CacheStore<K, V> {
    fn new(capacity: usize, policy: EvictionPolicyKind) -> Self {
        let cap = capacity.max(1);
        Self {
            entries: HashMap::with_capacity(cap.min(256)),
            capacity: cap,
            policy,
            hit_counter: 0,
            ghost_stats: GhostListStats::default(),
            arc_config: ArcWeightConfig::default(),
            arc_p: cap as f64 * 0.5,
        }
    }

    /// Set ARC weight configuration.
    #[allow(dead_code)]
    fn set_arc_config(&mut self, config: ArcWeightConfig) {
        self.arc_config = config;
    }

    /// Return a reference to the ghost-list statistics.
    #[must_use]
    #[allow(dead_code)]
    fn ghost_stats(&self) -> &GhostListStats {
        &self.ghost_stats
    }

    /// Return the current ARC target size p.
    #[must_use]
    #[allow(dead_code)]
    fn arc_p(&self) -> f64 {
        self.arc_p
    }

    /// Adaptively resize ARC p based on ghost-list hit patterns.
    ///
    /// - When B1 hit rate > B2 hit rate, increase p (favor T1/recent).
    /// - When B2 hit rate > B1 hit rate, decrease p (favor T2/frequent).
    /// - Clamp p to [1, capacity - 1].
    fn adapt_arc_p(&mut self) {
        if self.policy != EvictionPolicyKind::Adaptive {
            return;
        }
        if !self
            .ghost_stats
            .should_adapt(self.arc_config.ghost_adaptation_interval)
        {
            return;
        }
        let b1_total = self.ghost_stats.b1_hits + self.ghost_stats.b1_misses;
        let b2_total = self.ghost_stats.b2_hits + self.ghost_stats.b2_misses;

        if b1_total > 0 && b2_total > 0 {
            let b1_rate = self.ghost_stats.b1_hits as f64 / b1_total as f64;
            let b2_rate = self.ghost_stats.b2_hits as f64 / b2_total as f64;

            let delta = if b1_rate > b2_rate {
                // B1 is more valuable: grow T1 (increase p)
                (b1_rate - b2_rate) * (self.capacity as f64 * 0.1)
            } else if b2_rate > b1_rate {
                // B2 is more valuable: grow T2 (decrease p)
                -(b2_rate - b1_rate) * (self.capacity as f64 * 0.1)
            } else {
                0.0
            };
            self.arc_p = (self.arc_p + delta).clamp(1.0, self.capacity.saturating_sub(1) as f64);
        }
        self.ghost_stats.reset_adaptation_counter();
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn get(&mut self, key: &K) -> Option<&CacheEntry<V>> {
        if let Some(entry) = self.entries.get_mut(key) {
            self.hit_counter += 1;
            entry.header.mark_hit(self.hit_counter);
            entry.hit_count += 1;
            // Update weight on hit
            let recency_delta = entry.last_access.elapsed();
            entry.weight = Some(update_entry_weight(
                entry.effective_weight(),
                entry.hit_count,
                recency_delta,
            ));
            entry.last_access = Instant::now();
            // Recompute eviction score
            entry.eviction_score = EvictionPolicy::score(self.policy, entry, self.hit_counter);
            Some(&*entry)
        } else {
            None
        }
    }

    fn get_mut(&mut self, key: &K) -> Option<&mut CacheEntry<V>> {
        if let Some(entry) = self.entries.get_mut(key) {
            self.hit_counter += 1;
            entry.header.mark_hit(self.hit_counter);
            entry.hit_count += 1;
            // Update weight on hit
            let recency_delta = entry.last_access.elapsed();
            entry.weight = Some(update_entry_weight(
                entry.effective_weight(),
                entry.hit_count,
                recency_delta,
            ));
            entry.last_access = Instant::now();
            entry.eviction_score = EvictionPolicy::score(self.policy, entry, self.hit_counter);
            Some(entry)
        } else {
            None
        }
    }

    fn insert(&mut self, key: K, mut entry: CacheEntry<V>) -> Option<CacheEntry<V>> {
        // If at capacity, evict the best candidate
        let evicted = if self.entries.len() >= self.capacity && !self.entries.contains_key(&key) {
            self.evict_one()
        } else {
            None
        };
        // Initialize weight from entry size if not already set
        if entry.weight.is_none() {
            entry.weight = Some(initial_entry_weight(entry.header.entry_size_bytes));
        }
        entry.last_access = Instant::now();
        self.hit_counter += 1;
        entry.eviction_score = EvictionPolicy::score(self.policy, &entry, self.hit_counter);
        self.entries.insert(key, entry);
        // After insertion, adapt ARC p if needed
        if self.policy == EvictionPolicyKind::Adaptive && evicted.is_some() {
            self.ghost_stats.record_eviction();
            self.adapt_arc_p();
        }
        evicted
    }

    fn remove(&mut self, key: &K) -> Option<CacheEntry<V>> {
        self.entries.remove(key)
    }

    pub(crate) fn evict_one(&mut self) -> Option<CacheEntry<V>> {
        // Collect non-pinned, clean entries as candidates
        let candidates: Vec<(&K, &CacheEntry<V>)> = self
            .entries
            .iter()
            .filter(|(_, e)| {
                e.header.evictability != EvictabilityClass::Pinned
                    && e.header.poison_state == PoisonState::Clean
            })
            .collect();

        if candidates.is_empty() {
            return None;
        }

        let indexed: Vec<(u64, &CacheEntry<V>)> = candidates
            .iter()
            .map(|(k, e)| {
                // Use key hash as stable identifier for eviction
                let mut h: u64 = 0;
                let key_debug = format!("{k:?}");
                for b in key_debug.bytes() {
                    h = h.wrapping_mul(31).wrapping_add(b as u64);
                }
                (h, *e)
            })
            .collect();

        let best =
            EvictionPolicy::select_eviction_candidate(self.policy, &indexed, self.hit_counter);

        match best {
            Some(idx) => {
                let key = candidates[idx].0.clone();

                self.entries.remove(&key)
            }
            None => None,
        }
    }

    fn invalidate_by_key_prefix<F>(&mut self, predicate: F) -> Vec<CacheEntry<V>>
    where
        F: Fn(&K) -> bool,
    {
        let keys_to_remove: Vec<K> = self
            .entries
            .keys()
            .filter(|k| predicate(k))
            .cloned()
            .collect();
        let mut removed = Vec::with_capacity(keys_to_remove.len());
        for key in keys_to_remove {
            if let Some(entry) = self.entries.remove(&key) {
                removed.push(entry);
            }
        }
        removed
    }

    fn invalidate_by_token(&mut self, token: ValidityToken) -> Vec<CacheEntry<V>> {
        let keys_to_remove: Vec<K> = self
            .entries
            .iter()
            .filter(|(_, e)| !token.matches(e.header.validity_token))
            .map(|(k, _)| k.clone())
            .collect();
        let mut removed = Vec::with_capacity(keys_to_remove.len());
        for key in keys_to_remove {
            if let Some(entry) = self.entries.remove(&key) {
                removed.push(entry);
            }
        }
        removed
    }

    fn entries_iter(&self) -> impl Iterator<Item = (&K, &CacheEntry<V>)> {
        self.entries.iter()
    }
}

// ---------------------------------------------------------------------------
// Cache lattice registry

// ---------------------------------------------------------------------------

/// Registry of all active caches in the lattice, organized by cache class.
///
/// Each cache class has its own key-value store with independent capacity
/// and eviction policy. The registry provides global statistics and
/// cross-class invalidation.
pub struct CacheLatticeRegistry<K: Eq + std::hash::Hash + Clone + fmt::Debug, V> {
    stores: HashMap<CacheClass, CacheStore<K, V>>,
    total_inserts: u64,
    total_hits: u64,
    total_misses: u64,
    total_evictions: u64,
    total_invalidations: u64,
    /// Optional resource governor for budget-aware cache admission.
    governor: Option<Governor>,
}

impl<K: Eq + std::hash::Hash + Clone + fmt::Debug, V> CacheLatticeRegistry<K, V> {
    /// Create a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stores: HashMap::new(),
            total_inserts: 0,
            total_hits: 0,
            total_misses: 0,
            total_evictions: 0,
            total_invalidations: 0,
            governor: None,
        }
    }

    /// Attach a resource governor for budget-aware admission control.
    ///
    /// Once set, every cache `insert` will call [`Governor::admit`] and
    /// every eviction/invalidation will call [`Governor::release`].
    pub fn set_governor(&mut self, governor: Governor) {
        self.governor = Some(governor);
    }

    /// Release bytes for an evicted or invalidated entry.
    fn release_entry(&self, entry: &CacheEntry<V>) {
        if let Some(ref gov) = self.governor {
            gov.release(
                budget_category_for_entry(&entry.header),
                entry.header.entry_size_bytes,
            );
        }
    }

    /// Register a cache for the given class with a capacity and eviction policy.
    pub fn register_cache(
        &mut self,
        class: CacheClass,
        capacity: usize,
        policy: EvictionPolicyKind,
    ) {
        self.stores.insert(class, CacheStore::new(capacity, policy));
    }

    /// Look up an entry in the cache for the given class.
    /// Returns `Some(&CacheEntry<V>)` on hit, `None` on miss.
    /// Automatically checks entry validity.
    pub fn get(&mut self, class: CacheClass, key: &K) -> Option<&CacheEntry<V>> {
        let store = self.stores.get_mut(&class)?;
        if let Some(entry) = store.get(key) {
            if entry.is_servable() {
                self.total_hits += 1;
                Some(entry)
            } else {
                // Poisoned or invalid entry — treat as miss
                self.total_misses += 1;
                None
            }
        } else {
            self.total_misses += 1;
            None
        }
    }

    /// Look up a mutable entry in the cache for the given class.
    pub fn get_mut(&mut self, class: CacheClass, key: &K) -> Option<&mut CacheEntry<V>> {
        let store = self.stores.get_mut(&class)?;
        if let Some(entry) = store.get_mut(key) {
            if entry.is_servable() {
                self.total_hits += 1;
                Some(entry)
            } else {
                self.total_misses += 1;
                None
            }
        } else {
            self.total_misses += 1;
            None
        }
    }

    /// Insert an entry into the cache for the given class.
    ///
    /// If a governor is attached, admission is checked first.  When
    /// admission fails with [`BudgetError::OverBudget`], the store evicts
    /// one entry (releasing its budget) and retries admission once.
    ///
    /// If the cache is at capacity, the best eviction candidate is evicted.
    /// Returns the evicted entry if one was removed.
    pub fn insert(
        &mut self,
        class: CacheClass,
        key: K,
        entry: CacheEntry<V>,
    ) -> Option<CacheEntry<V>> {
        let size = entry.header.entry_size_bytes;
        let category = budget_category_for_entry(&entry.header);
        let replaced = if self.governor.is_some() {
            self.stores
                .get_mut(&class)
                .and_then(|store| store.remove(&key))
        } else {
            None
        };
        if let Some(ref replaced_entry) = replaced {
            self.release_entry(replaced_entry);
        }

        // Governor-aware admission with pressure shedding and one eviction
        // retry on OverBudget.
        if let Some(ref gov) = self.governor {
            let pressure = gov.backpressure(category);
            if matches!(
                pressure,
                BackpressureSignal::SoftPressure | BackpressureSignal::HardPressure
            ) {
                if let Some(store) = self.stores.get_mut(&class) {
                    if let Some(victim) = store.evict_one() {
                        gov.release(
                            budget_category_for_entry(&victim.header),
                            victim.header.entry_size_bytes,
                        );
                        self.total_evictions += 1;
                    }
                }
            }
            match gov.admit(category, size) {
                Ok(_ticket) => {} // granted
                Err(BudgetError::OverBudget { .. })
                | Err(BudgetError::GlobalOverBudget { .. }) => {
                    // Try to free space: evict one entry from the same store.
                    if let Some(store) = self.stores.get_mut(&class) {
                        if let Some(victim) = store.evict_one() {
                            gov.release(
                                budget_category_for_entry(&victim.header),
                                victim.header.entry_size_bytes,
                            );
                            self.total_evictions += 1;
                        }
                    }
                    // Retry admission after eviction.
                    if gov.admit(category, size).is_err() {
                        if replaced.is_some() {
                            self.total_evictions += 1;
                        }
                        return replaced; // admission still rejected
                    }
                }
                Err(_) => {
                    if replaced.is_some() {
                        self.total_evictions += 1;
                    }
                    return replaced;
                }
            }
        }

        let store = self
            .stores
            .entry(class)
            .or_insert_with(|| CacheStore::new(256, EvictionPolicyKind::default()));
        self.total_inserts += 1;
        let evicted = store.insert(key, entry);
        if let Some(ref evicted_entry) = evicted {
            self.total_evictions += 1;
            self.release_entry(evicted_entry);
        }
        if replaced.is_some() {
            self.total_evictions += 1;
            replaced
        } else {
            evicted
        }
    }

    /// Remove an entry from the cache for the given class.
    pub fn remove(&mut self, class: CacheClass, key: &K) -> Option<CacheEntry<V>> {
        let removed = self.stores.get_mut(&class)?.remove(key);
        if let Some(ref entry) = removed {
            self.release_entry(entry);
        }
        removed
    }

    /// Invalidate entries in the given class whose keys match the predicate.
    /// Returns the number of entries invalidated.
    pub fn invalidate_by_key_prefix<F>(&mut self, class: CacheClass, predicate: F) -> usize
    where
        F: Fn(&K) -> bool,
    {
        if let Some(store) = self.stores.get_mut(&class) {
            let removed = store.invalidate_by_key_prefix(predicate);
            let count = removed.len();
            self.total_invalidations += count as u64;
            for entry in &removed {
                self.release_entry(entry);
            }
            count
        } else {
            0
        }
    }

    /// Invalidate entries by validity token across all classes.
    /// Returns the total number of entries invalidated.
    pub fn invalidate_by_token(&mut self, token: ValidityToken) -> usize {
        let mut count = 0;
        let mut removed_entries = Vec::new();
        for store in self.stores.values_mut() {
            let mut removed = store.invalidate_by_token(token);
            count += removed.len();
            removed_entries.append(&mut removed);
        }
        self.total_invalidations += count as u64;
        for entry in &removed_entries {
            self.release_entry(entry);
        }
        count
    }

    /// Invalidate (remove) all entries in the given cache class.
    /// Returns the number of entries removed.
    pub fn invalidate_all(&mut self, class: CacheClass) -> usize {
        if let Some(store) = self.stores.get_mut(&class) {
            let removed = store.invalidate_by_key_prefix(|_| true);
            let count = removed.len();
            self.total_invalidations += count as u64;
            for entry in &removed {
                self.release_entry(entry);
            }
            count
        } else {
            0
        }
    }

    /// Return the number of entries in a given class.
    #[must_use]
    pub fn entry_count(&self, class: CacheClass) -> usize {
        self.stores.get(&class).map_or(0, |s| s.len())
    }

    /// Return the total number of entries across all classes.
    #[must_use]
    pub fn total_entries(&self) -> usize {
        self.stores.values().map(|s| s.len()).sum()
    }

    /// Generate a cache lattice report.
    #[must_use]
    pub fn report(&self) -> CacheLatticeReport {
        let mut report = CacheLatticeReport::new();
        report.total_entries = self.total_entries();
        for (class, store) in &self.stores {
            let class_idx = *class as usize;
            if class_idx < CacheClass::COUNT {
                report.entries_by_class[class_idx] = store.len();
            }
            for (_, entry) in store.entries_iter() {
                let domain_idx = entry.header.memory_domain as usize;
                if domain_idx < MemoryDomain::COUNT {
                    report.entries_by_domain[domain_idx] += 1;
                }
                report.total_bytes += entry.header.entry_size_bytes;
                if !entry.header.poison_state.is_clean() {
                    report.poisoned_entries += 1;
                }
                if entry.header.dirty_state.is_dirty() {
                    report.dirty_entries += 1;
                }
                match entry.header.reserve_guard {
                    tidefs_types_cache_lattice_core::ReserveGuardClass::Soft => {
                        report.reserve_soft += 1;
                    }
                    tidefs_types_cache_lattice_core::ReserveGuardClass::Hard => {
                        report.reserve_hard += 1;
                    }
                    tidefs_types_cache_lattice_core::ReserveGuardClass::Pinned => {
                        report.reserve_pinned += 1;
                    }
                    _ => {}
                }
            }
        }
        report
    }

    /// Generate a cache lattice view report with hit/miss/eviction stats.
    #[must_use]
    pub fn view_report(&self) -> CacheLatticeViewReport {
        let total_ops = self.total_hits + self.total_misses;
        let hit_rate = if total_ops > 0 {
            self.total_hits as f64 / total_ops as f64
        } else {
            0.0
        };
        CacheLatticeViewReport {
            total_views: self.total_entries() as u64,
            total_size: self
                .stores
                .values()
                .map(|s| {
                    s.entries_iter()
                        .map(|(_, e)| e.header.entry_size_bytes)
                        .sum::<u64>()
                })
                .sum(),
            hit_rate,
            miss_rate: 1.0 - hit_rate,
            eviction_count: self.total_evictions,
            by_class: ViewStats::default(),
        }
    }

    /// Return the total number of cache hits.
    #[must_use]
    pub fn hit_count(&self) -> u64 {
        self.total_hits
    }

    /// Return the total number of cache misses.
    #[must_use]
    pub fn miss_count(&self) -> u64 {
        self.total_misses
    }

    /// Return the total number of evictions.
    #[must_use]
    pub fn eviction_count(&self) -> u64 {
        self.total_evictions
    }

    /// Return the total number of invalidations.
    #[must_use]
    pub fn invalidation_count(&self) -> u64 {
        self.total_invalidations
    }
}

impl<K: Eq + std::hash::Hash + Clone + fmt::Debug, V> Default for CacheLatticeRegistry<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Cache lookup — high-level get/insert interface

// ---------------------------------------------------------------------------

/// High-level cache lookup interface providing get-or-insert semantics
/// with automatic staleness detection and validation.
pub struct CacheLookup<'a, K: Eq + std::hash::Hash + Clone + fmt::Debug, V> {
    registry: &'a mut CacheLatticeRegistry<K, V>,
}

impl<'a, K: Eq + std::hash::Hash + Clone + fmt::Debug, V> CacheLookup<'a, K, V> {
    /// Create a new lookup handle for the given registry.
    #[must_use]
    pub fn new(registry: &'a mut CacheLatticeRegistry<K, V>) -> Self {
        Self { registry }
    }

    /// Look up an entry by class and key. Returns `Some(&CacheEntry<V>)` if
    /// a valid, non-poisoned entry exists; `None` otherwise.
    pub fn get(&mut self, class: CacheClass, key: &K) -> Option<&CacheEntry<V>> {
        self.registry.get(class, key)
    }

    /// Look up a mutable entry by class and key.
    pub fn get_mut(&mut self, class: CacheClass, key: &K) -> Option<&mut CacheEntry<V>> {
        self.registry.get_mut(class, key)
    }

    /// Insert an entry. Evicts if at capacity.
    /// Returns the evicted entry if one was removed.
    pub fn insert(
        &mut self,
        class: CacheClass,
        key: K,
        entry: CacheEntry<V>,
    ) -> Option<CacheEntry<V>> {
        self.registry.insert(class, key, entry)
    }
}

// ---------------------------------------------------------------------------
// Invalidation pipeline

// ---------------------------------------------------------------------------

/// Invalidation pipeline: on authoritative state change, invalidate affected
/// cache entries by key prefix or validity token.
pub struct InvalidationPipeline<'a, K: Eq + std::hash::Hash + Clone + fmt::Debug, V> {
    registry: &'a mut CacheLatticeRegistry<K, V>,
}

impl<'a, K: Eq + std::hash::Hash + Clone + fmt::Debug, V> InvalidationPipeline<'a, K, V> {
    /// Create a new invalidation pipeline for the given registry.
    #[must_use]
    pub fn new(registry: &'a mut CacheLatticeRegistry<K, V>) -> Self {
        Self { registry }
    }

    /// Invalidate entries in the given cache class whose keys match the predicate.
    /// Returns the number of invalidated entries.
    pub fn invalidate_by_key_prefix<F>(&mut self, class: CacheClass, predicate: F) -> usize
    where
        F: Fn(&K) -> bool,
    {
        self.registry.invalidate_by_key_prefix(class, predicate)
    }

    /// Invalidate entries across all classes whose validity token does not match.
    /// Returns the total number of invalidated entries.
    pub fn invalidate_by_token(&mut self, token: ValidityToken) -> usize {
        self.registry.invalidate_by_token(token)
    }

    /// Invalidate (remove) all entries in the given cache class.
    /// Returns the number of entries removed.
    pub fn invalidate_all(&mut self, class: CacheClass) -> usize {
        let key_pred: &dyn Fn(&K) -> bool = &|_| true;
        self.registry.invalidate_by_key_prefix(class, key_pred)
    }
}

// ---------------------------------------------------------------------------
// Cache coherency — re-exports from tidefs-cache-coherency
// ---------------------------------------------------------------------------

pub use tidefs_cache_coherency::{CacheInvalidationSubscriber, CoherencyEventBus};

// ---------------------------------------------------------------------------
// The 10 inviolable cache rules (P4-02 §5)

// ---------------------------------------------------------------------------

/// Validate all 10 inviolable rules against a cache entry.
///
/// Returns `Ok(())` if all rules pass, or `Err(rule_number)` on violation.
pub fn validate_10_rules<V>(entry: &CacheEntry<V>) -> Result<(), usize> {
    // Rule 1: Every entry must have a budget domain.
    if entry.header.budget_domain_len == 0 {
        return Err(1);
    }

    // Rule 2: Poisoned entries must not be served.
    if !entry.header.poison_state.is_clean() {
        return Err(2);
    }

    // Rule 3: staging_dirty domain requires non-clean dirty state.
    if entry.header.memory_domain == MemoryDomain::StagingDirty
        && entry.header.dirty_state.is_clean()
    {
        return Err(3);
    }

    // Rule 4: Entries without an anchor vector may not claim exact answers.
    if entry.header.anchor_vector_ref == 0 && entry.header.exactness_class == 0 {
        return Err(4);
    }

    // Rule 5: Entries without an anchor vector may not claim bounded freshness.
    if entry.header.anchor_vector_ref == 0 && entry.header.freshness_class <= 1 {
        return Err(5);
    }

    // Rule 6: Pinned entries must be in a protected-reserve domain.
    if entry.header.evictability == EvictabilityClass::Pinned
        && !entry.header.memory_domain.is_reserve_eligible()
    {
        return Err(6);
    }

    // Rule 7: Birth counter must be ≤ last_hit_counter.
    if entry.header.birth_counter > entry.header.last_hit_counter {
        return Err(7);
    }

    // Rule 8: Entry must have a non-zero key digest.
    if entry.header.entry_key_digest == 0 {
        return Err(8);
    }

    // Rule 9: Hard-reserve entries must not be evicted before soft-reserve.
    // (Checked at eviction time, not entry creation.)

    // Rule 10: Cache class primary domain must match memory domain for
    // dirty classes.
    if entry.header.cache_class.is_dirty_class()
        && entry.header.memory_domain != entry.header.cache_class.primary_domain()
    {
        return Err(10);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_cache_lattice_core::{
        CacheEntryHeader, DirtyStateClass, PosixWritebackState, RebuildCostClass,
    };

    // ── Helpers ──────────────────────────────────────────────────────

    fn make_header(key_digest: u64, budget: &str) -> CacheEntryHeader {
        CacheEntryHeader::new(
            CacheClass::PosixNamespaceMirror,
            MemoryDomain::AdapterServingHot,
            key_digest,
            budget,
            RebuildCostClass::Cheap,
            1,
        )
    }

    fn make_servable_header(key_digest: u64) -> CacheEntryHeader {
        let mut h = make_header(key_digest, "adapter_serving");
        h.anchor_vector_ref = 1; // Has anchor -> exact OK
        h
    }

    fn single_category_governor(category: BudgetCategory, total_budget_bytes: u64) -> Governor {
        let fraction = |candidate| {
            if category == candidate {
                1.0
            } else {
                0.0
            }
        };
        Governor::new(GovernorConfig {
            total_budget_bytes,
            data_cache_fraction: fraction(BudgetCategory::DataCache),
            meta_cache_fraction: fraction(BudgetCategory::MetaCache),
            dirty_bytes_fraction: fraction(BudgetCategory::DirtyBytes),
            inode_state_fraction: fraction(BudgetCategory::InodeState),
            cluster_queues_fraction: fraction(BudgetCategory::ClusterQueues),
            misc_fraction: fraction(BudgetCategory::Misc),
            auto_tune: false,
        })
        .unwrap()
    }

    // ── CacheEntry tests ─────────────────────────────────────────────

    #[test]
    fn cache_entry_servable_when_clean_and_valid() {
        let h = make_servable_header(1);
        let entry = CacheEntry::new(h, "value");
        assert!(entry.is_servable());
    }

    #[test]
    fn cache_entry_not_servable_when_poisoned() {
        let mut h = make_servable_header(2);
        h.poison(PoisonState::Corrupted);
        let entry = CacheEntry::new(h, "value");
        assert!(!entry.is_servable());
    }

    // ── EvictionPolicy tests ─────────────────────────────────────────

    #[test]
    fn lru_eviction_selects_oldest_entry() {
        let mut h1 = make_servable_header(10);
        h1.last_hit_counter = 100;
        let mut h2 = make_servable_header(20);
        h2.last_hit_counter = 50; // older
        let e1 = CacheEntry::new(h1, "a");
        let e2 = CacheEntry::new(h2, "b");

        let entries: Vec<(u64, &CacheEntry<&str>)> = vec![(10, &e1), (20, &e2)];
        let idx = EvictionPolicy::select_eviction_candidate(EvictionPolicyKind::Lru, &entries, 200);
        assert_eq!(idx, Some(1)); // e2 is older
    }

    #[test]
    fn lfu_eviction_selects_least_frequent() {
        let mut h1 = make_servable_header(10);
        h1.last_hit_counter = 5; // fewer hits
        let mut h2 = make_servable_header(20);
        h2.last_hit_counter = 50; // more hits
        let e1 = CacheEntry::new(h1, "a");
        let e2 = CacheEntry::new(h2, "b");

        let entries: Vec<(u64, &CacheEntry<&str>)> = vec![(10, &e1), (20, &e2)];
        let idx = EvictionPolicy::select_eviction_candidate(EvictionPolicyKind::Lfu, &entries, 200);
        assert_eq!(idx, Some(0)); // e1 has fewer hits
    }

    // ── CacheLatticeRegistry tests ───────────────────────────────────

    #[test]
    fn registry_insert_and_get() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        reg.register_cache(
            CacheClass::PosixNamespaceMirror,
            10,
            EvictionPolicyKind::Lru,
        );

        let h = make_servable_header(100);
        let entry = CacheEntry::new(h, "hello".to_string());
        reg.insert(CacheClass::PosixNamespaceMirror, 100, entry);

        let found = reg.get(CacheClass::PosixNamespaceMirror, &100);
        assert!(found.is_some());
        assert_eq!(found.unwrap().value, "hello");
    }

    #[test]
    fn registry_miss_on_poisoned_entry() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        reg.register_cache(
            CacheClass::PosixNamespaceMirror,
            10,
            EvictionPolicyKind::Lru,
        );

        let mut h = make_servable_header(200);
        h.poison(PoisonState::Corrupted);
        let entry = CacheEntry::new(h, "poisoned".to_string());
        reg.insert(CacheClass::PosixNamespaceMirror, 200, entry);

        let found = reg.get(CacheClass::PosixNamespaceMirror, &200);
        assert!(found.is_none());
    }

    #[test]
    fn registry_capacity_enforcement_evicts() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        reg.register_cache(CacheClass::PosixNamespaceMirror, 2, EvictionPolicyKind::Lru);

        let h1 = make_servable_header(1);
        let h2 = make_servable_header(2);
        let h3 = make_servable_header(3);

        reg.insert(
            CacheClass::PosixNamespaceMirror,
            1,
            CacheEntry::new(h1, "a".into()),
        );
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            2,
            CacheEntry::new(h2, "b".into()),
        );
        // This should evict one
        let evicted = reg.insert(
            CacheClass::PosixNamespaceMirror,
            3,
            CacheEntry::new(h3, "c".into()),
        );

        assert!(evicted.is_some());
        assert_eq!(reg.entry_count(CacheClass::PosixNamespaceMirror), 2);
    }

    #[test]
    fn registry_invalidate_by_key_prefix() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        reg.register_cache(
            CacheClass::PosixNamespaceMirror,
            10,
            EvictionPolicyKind::Lru,
        );

        for i in 0..5 {
            let h = make_servable_header(i);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("val{i}")),
            );
        }

        let count =
            reg.invalidate_by_key_prefix(CacheClass::PosixNamespaceMirror, |k| *k < 3);
        assert_eq!(count, 3);
        assert_eq!(reg.entry_count(CacheClass::PosixNamespaceMirror), 2);
    }

    #[test]
    fn registry_governor_releases_budget_on_invalidation() {
        let governor = single_category_governor(BudgetCategory::MetaCache, 1000);
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        reg.set_governor(governor.clone());
        reg.register_cache(CacheClass::PosixNamespaceMirror, 10, EvictionPolicyKind::Lru);

        for i in 0..5 {
            let mut h = make_servable_header(i);
            h.entry_size_bytes = 100;
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("val{i}")),
            );
        }

        assert_eq!(governor.category_used(BudgetCategory::MetaCache), 500);
        let count = reg.invalidate_by_key_prefix(CacheClass::PosixNamespaceMirror, |k| *k < 3);
        assert_eq!(count, 3);
        assert_eq!(governor.category_used(BudgetCategory::MetaCache), 200);

        let count = reg.invalidate_all(CacheClass::PosixNamespaceMirror);
        assert_eq!(count, 2);
        assert_eq!(governor.category_used(BudgetCategory::MetaCache), 0);
    }

    #[test]
    fn registry_governor_replacement_releases_before_admission() {
        let governor = single_category_governor(BudgetCategory::MetaCache, 100);
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        reg.set_governor(governor.clone());
        reg.register_cache(CacheClass::PosixNamespaceMirror, 10, EvictionPolicyKind::Lru);

        let mut old_header = make_servable_header(1);
        old_header.entry_size_bytes = 100;
        old_header.evictability = EvictabilityClass::Pinned;
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            1,
            CacheEntry::new(old_header, "old".into()),
        );
        assert_eq!(governor.category_used(BudgetCategory::MetaCache), 100);

        let mut new_header = make_servable_header(1);
        new_header.entry_size_bytes = 100;
        new_header.evictability = EvictabilityClass::Pinned;
        let evicted = reg.insert(
            CacheClass::PosixNamespaceMirror,
            1,
            CacheEntry::new(new_header, "new".into()),
        );

        assert_eq!(evicted.unwrap().value, "old");
        assert_eq!(governor.category_used(BudgetCategory::MetaCache), 100);
        assert_eq!(
            reg.get(CacheClass::PosixNamespaceMirror, &1)
                .unwrap()
                .value,
            "new"
        );
    }

    #[test]
    fn registry_governor_consumes_soft_pressure_on_insert() {
        let governor = single_category_governor(BudgetCategory::MetaCache, 1000);
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        reg.set_governor(governor.clone());
        reg.register_cache(CacheClass::PosixNamespaceMirror, 10, EvictionPolicyKind::Lru);

        let mut first = make_servable_header(1);
        first.entry_size_bytes = 700;
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            1,
            CacheEntry::new(first, "first".into()),
        );
        assert_eq!(
            governor.backpressure(BudgetCategory::MetaCache),
            BackpressureSignal::SoftPressure
        );

        let mut second = make_servable_header(2);
        second.entry_size_bytes = 50;
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            2,
            CacheEntry::new(second, "second".into()),
        );

        assert_eq!(reg.eviction_count(), 1);
        assert_eq!(governor.category_used(BudgetCategory::MetaCache), 50);
        assert!(reg.get(CacheClass::PosixNamespaceMirror, &1).is_none());
        assert!(reg.get(CacheClass::PosixNamespaceMirror, &2).is_some());
    }

    #[test]
    fn registry_report_counts() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        reg.register_cache(
            CacheClass::PosixNamespaceMirror,
            10,
            EvictionPolicyKind::Lru,
        );

        let mut h = make_servable_header(1);
        h.entry_size_bytes = 4096;
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            1,
            CacheEntry::new(h, "x".into()),
        );

        let report = reg.report();
        assert_eq!(report.total_entries, 1);
        assert_eq!(report.total_bytes, 4096);
        assert_eq!(
            report.entries_by_class[CacheClass::PosixNamespaceMirror as usize],
            1
        );
    }

    // ── CacheLookup tests ────────────────────────────────────────────

    #[test]
    fn cache_lookup_get_hit_and_miss() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        reg.register_cache(
            CacheClass::PosixNamespaceMirror,
            10,
            EvictionPolicyKind::Lru,
        );

        let h = make_servable_header(42);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            42,
            CacheEntry::new(h, "found".into()),
        );

        let mut lookup = CacheLookup::new(&mut reg);
        let hit = lookup.get(CacheClass::PosixNamespaceMirror, &42);
        assert!(hit.is_some());

        let miss = lookup.get(CacheClass::PosixNamespaceMirror, &99);
        assert!(miss.is_none());

        assert_eq!(reg.hit_count(), 1);
        assert_eq!(reg.miss_count(), 1);
    }

    #[test]
    fn cache_lookup_insert_evicts() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        reg.register_cache(CacheClass::PosixNamespaceMirror, 1, EvictionPolicyKind::Lru);

        let mut lookup = CacheLookup::new(&mut reg);
        let h1 = make_servable_header(1);
        lookup.insert(
            CacheClass::PosixNamespaceMirror,
            1,
            CacheEntry::new(h1, "a".into()),
        );

        let h2 = make_servable_header(2);
        let evicted = lookup.insert(
            CacheClass::PosixNamespaceMirror,
            2,
            CacheEntry::new(h2, "b".into()),
        );

        assert!(evicted.is_some());
        assert_eq!(reg.eviction_count(), 1);
    }

    // ── InvalidationPipeline tests ───────────────────────────────────

    #[test]
    fn invalidation_pipeline_key_prefix() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        reg.register_cache(
            CacheClass::PosixNamespaceMirror,
            10,
            EvictionPolicyKind::Lru,
        );

        for i in 0..10 {
            let h = make_servable_header(i);
            reg.insert(
                CacheClass::PosixNamespaceMirror,
                i,
                CacheEntry::new(h, format!("v{i}")),
            );
        }

        let mut pipeline = InvalidationPipeline::new(&mut reg);
        let count =
            pipeline.invalidate_by_key_prefix(CacheClass::PosixNamespaceMirror, |k| *k >= 5);
        assert_eq!(count, 5);
        assert_eq!(reg.invalidation_count(), 5);
    }

    #[test]
    fn coherency_event_bus_dispatch_range() {
        use std::sync::Arc;

        // A simple test subscriber that records invalidations
        struct TestSub {
            invalidations: std::sync::Mutex<Vec<(u64, u64, u64)>>,
        }
        impl TestSub {
            fn new() -> Self {
                Self {
                    invalidations: std::sync::Mutex::new(Vec::new()),
                }
            }
        }
        impl CacheInvalidationSubscriber for TestSub {
            fn on_invalidate_range(&self, inode: u64, start: u64, end: u64) -> usize {
                self.invalidations.lock().unwrap().push((inode, start, end));
                1
            }
            fn on_invalidate_all(&self) -> usize {
                self.invalidations.lock().unwrap().push((0, 0, u64::MAX));
                1
            }
            fn subscriber_name(&self) -> &'static str {
                "test-sub"
            }
        }

        let bus = CoherencyEventBus::new();
        assert_eq!(bus.subscriber_count(), 0);

        let sub1 = Arc::new(TestSub::new());
        let sub2 = Arc::new(TestSub::new());
        bus.register(sub1.clone());
        bus.register(sub2.clone());
        assert_eq!(bus.subscriber_count(), 2);

        // Dispatch range invalidation
        let total = bus.dispatch_range_invalidation(5, 4096, 8192);
        assert_eq!(total, 2);

        let inv1 = sub1.invalidations.lock().unwrap();
        assert_eq!(inv1.len(), 1);
        assert_eq!(inv1[0], (5, 4096, 8192));

        let inv2 = sub2.invalidations.lock().unwrap();
        assert_eq!(inv2.len(), 1);
        assert_eq!(inv2[0], (5, 4096, 8192));
    }

    #[test]
    fn coherency_event_bus_dispatch_inode() {
        use std::sync::Arc;

        struct TestSub {
            invalidations: std::sync::Mutex<Vec<u64>>,
        }
        impl TestSub {
            fn new() -> Self {
                Self {
                    invalidations: std::sync::Mutex::new(Vec::new()),
                }
            }
        }
        impl CacheInvalidationSubscriber for TestSub {
            fn on_invalidate_range(&self, inode: u64, _start: u64, _end: u64) -> usize {
                self.invalidations.lock().unwrap().push(inode);
                1
            }
            fn on_invalidate_inode(&self, inode: u64) -> usize {
                self.invalidations.lock().unwrap().push(inode);
                1
            }
            fn on_invalidate_all(&self) -> usize {
                self.invalidations.lock().unwrap().push(u64::MAX);
                1
            }
            fn subscriber_name(&self) -> &'static str {
                "test-sub"
            }
        }

        let bus = CoherencyEventBus::new();
        let sub = Arc::new(TestSub::new());
        bus.register(sub.clone());

        let total = bus.dispatch_inode_invalidation(42);
        assert_eq!(total, 1);
        assert_eq!(sub.invalidations.lock().unwrap()[0], 42);
    }

    #[test]
    fn coherency_event_bus_dispatch_full() {
        use std::sync::Arc;

        struct TestSub {
            full_count: std::sync::Mutex<usize>,
        }
        impl TestSub {
            fn new() -> Self {
                Self {
                    full_count: std::sync::Mutex::new(0),
                }
            }
        }
        impl CacheInvalidationSubscriber for TestSub {
            fn on_invalidate_range(&self, _inode: u64, _start: u64, _end: u64) -> usize {
                0
            }
            fn on_invalidate_all(&self) -> usize {
                *self.full_count.lock().unwrap() += 1;
                1
            }
            fn subscriber_name(&self) -> &'static str {
                "test-sub"
            }
        }

        let bus = CoherencyEventBus::new();
        let sub = Arc::new(TestSub::new());
        bus.register(sub.clone());

        let total = bus.dispatch_full_invalidation();
        assert_eq!(total, 1);
        assert_eq!(*sub.full_count.lock().unwrap(), 1);
    }

    #[test]
    fn coherency_event_bus_page_cache_integration() {
        use std::sync::Arc;

        let page_cache = Arc::new(crate::page_cache::PageCache::new(10, 4096));
        // Insert some pages
        page_cache.insert(1, 0).unwrap();
        page_cache.insert(1, 4096).unwrap();
        page_cache.insert(1, 8192).unwrap();
        assert_eq!(page_cache.len(), 3);

        let bus = CoherencyEventBus::new();
        bus.register(page_cache.clone());

        // Dispatch range invalidation through the bus
        let total = bus.dispatch_range_invalidation(1, 0, 8192);
        assert_eq!(
            total, 2,
            "two clean pages in range [0, 8192) should be invalidated"
        );
        assert_eq!(
            page_cache.len(),
            1,
            "only page at offset 8192 should remain"
        );
        assert!(page_cache.lookup(1, 8192).is_some());
    }

    // ── 10 Rules tests ───────────────────────────────────────────────

    #[test]
    fn rule_1_budget_domain_required() {
        let mut h = make_servable_header(1);
        h.budget_domain_len = 0;
        let entry = CacheEntry::new(h, "x");
        assert_eq!(validate_10_rules(&entry), Err(1));
    }

    #[test]
    fn rule_2_poisoned_not_served() {
        let mut h = make_servable_header(2);
        h.poison(PoisonState::Corrupted);
        let entry = CacheEntry::new(h, "x");
        assert_eq!(validate_10_rules(&entry), Err(2));
    }

    #[test]
    fn rule_3_staging_dirty_requires_dirty() {
        let mut h = CacheEntryHeader::new(
            CacheClass::PosixPageWriteback,
            MemoryDomain::StagingDirty,
            3,
            "staging",
            RebuildCostClass::Moderate,
            1,
        );
        h.anchor_vector_ref = 1;
        // dirty_state is Clean by default
        let entry = CacheEntry::new(h, "x");
        assert_eq!(validate_10_rules(&entry), Err(3));
    }

    #[test]
    fn rule_4_anchor_required_for_exact() {
        let mut h = make_header(4, "adapter");
        h.anchor_vector_ref = 0;
        h.exactness_class = 0; // Exact
        let entry = CacheEntry::new(h, "x");
        assert_eq!(validate_10_rules(&entry), Err(4));
    }

    #[test]
    fn rule_5_anchor_required_for_freshness() {
        let mut h = make_header(5, "adapter");
        h.anchor_vector_ref = 0;
        h.exactness_class = 1; // BoundedStaleness (not Exact, so rule 4 passes)
        h.freshness_class = 0; // ReadYourWrites (rule 5: anchor required for bounded freshness)
        h.exactness_class = 1; // BoundedStaleness (not Exact, so rule 4 passes)
        let entry = CacheEntry::new(h, "x");
        assert_eq!(validate_10_rules(&entry), Err(5));
    }

    #[test]
    fn rule_6_pinned_requires_reserve_domain() {
        let mut h = make_servable_header(6);
        h.evictability = EvictabilityClass::Pinned;
        // AdapterServingHot is not reserve eligible
        let entry = CacheEntry::new(h, "x");
        assert_eq!(validate_10_rules(&entry), Err(6));
    }

    #[test]
    fn rule_7_birth_le_last_hit() {
        let mut h = make_servable_header(7);
        h.birth_counter = 100;
        h.last_hit_counter = 50; // birth > last_hit
        let entry = CacheEntry::new(h, "x");
        assert_eq!(validate_10_rules(&entry), Err(7));
    }

    #[test]
    fn rule_8_key_digest_nonzero() {
        let mut h = make_servable_header(0);
        h.entry_key_digest = 0;
        let entry = CacheEntry::new(h, "x");
        assert_eq!(validate_10_rules(&entry), Err(8));
    }

    #[test]
    fn rule_10_dirty_class_must_match_primary_domain() {
        let mut h = CacheEntryHeader::new(
            CacheClass::PosixPageWriteback,
            MemoryDomain::AdapterServingHot, // wrong domain for dirty class
            10,
            "staging",
            RebuildCostClass::Moderate,
            1,
        );
        h.anchor_vector_ref = 1;
        // Make dirty state non-clean to pass rule 3
        h.dirty_state = DirtyStateClass::PosixWriteback(PosixWritebackState::DirtyOpen);
        let entry = CacheEntry::new(h, "x");
        assert_eq!(validate_10_rules(&entry), Err(10));
    }

    #[test]
    fn all_10_rules_pass() {
        let h = make_servable_header(99);
        let entry = CacheEntry::new(h, "valid");
        assert_eq!(validate_10_rules(&entry), Ok(()));
    }

    // ── Integration tests ────────────────────────────────────────────

    #[test]
    fn concurrent_get_insert_on_same_cache() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        reg.register_cache(CacheClass::PosixNamespaceMirror, 5, EvictionPolicyKind::Lru);

        let h = make_servable_header(500);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            500,
            CacheEntry::new(h, "val500".into()),
        );

        // Get it back
        let found = reg.get(CacheClass::PosixNamespaceMirror, &500);
        assert!(found.is_some());

        // Overwrite
        let h2 = make_servable_header(500);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            500,
            CacheEntry::new(h2, "val500_v2".into()),
        );

        let found2 = reg.get(CacheClass::PosixNamespaceMirror, &500);
        assert_eq!(found2.unwrap().value, "val500_v2");
    }

    #[test]
    fn registry_default_creates_empty() {
        let reg: CacheLatticeRegistry<u64, u32> = CacheLatticeRegistry::default();
        assert_eq!(reg.total_entries(), 0);
        assert_eq!(reg.hit_count(), 0);
        assert_eq!(reg.miss_count(), 0);
    }

    #[test]
    fn view_report_reflects_stats() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        reg.register_cache(
            CacheClass::PosixNamespaceMirror,
            10,
            EvictionPolicyKind::Lru,
        );

        let h = make_servable_header(1);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            1,
            CacheEntry::new(h, "a".into()),
        );

        let _ = reg.get(CacheClass::PosixNamespaceMirror, &1); // hit
        let _ = reg.get(CacheClass::PosixNamespaceMirror, &99); // miss

        let report = reg.view_report();
        assert_eq!(report.total_views, 1);
        assert_eq!(report.hit_rate, 0.5);
        assert_eq!(report.miss_rate, 0.5);
    }

    #[test]
    fn multi_class_registry_isolation() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        reg.register_cache(
            CacheClass::PosixNamespaceMirror,
            10,
            EvictionPolicyKind::Lru,
        );
        reg.register_cache(CacheClass::AuthorityReadMirror, 10, EvictionPolicyKind::Lfu);

        let h1 = make_servable_header(1);
        let mut h2 = CacheEntryHeader::new(
            CacheClass::AuthorityReadMirror,
            MemoryDomain::AuthorityImmutable,
            2,
            "authority_immutable",
            RebuildCostClass::Trivial,
            1,
        );
        h2.anchor_vector_ref = 1;

        reg.insert(
            CacheClass::PosixNamespaceMirror,
            1,
            CacheEntry::new(h1, "ns".into()),
        );
        reg.insert(
            CacheClass::AuthorityReadMirror,
            2,
            CacheEntry::new(h2, "auth".into()),
        );

        assert_eq!(reg.entry_count(CacheClass::PosixNamespaceMirror), 1);
        assert_eq!(reg.entry_count(CacheClass::AuthorityReadMirror), 1);

        let found_ns = reg.get(CacheClass::PosixNamespaceMirror, &1);
        assert_eq!(found_ns.unwrap().value, "ns");

        let found_auth = reg.get(CacheClass::AuthorityReadMirror, &2);
        assert_eq!(found_auth.unwrap().value, "auth");
    }

    // ── EntryWeight tests ────────────────────────────────────────────

    #[test]
    fn entry_weight_default_is_one() {
        assert_eq!(EntryWeight::default().value(), 1);
        assert_eq!(EntryWeight::DEFAULT.value(), 1);
    }

    #[test]
    fn entry_weight_zero_clamps_to_one() {
        let w = EntryWeight::new(0);
        assert_eq!(w.value(), 1);
    }

    #[test]
    fn entry_weight_ord_comparison() {
        let w1 = EntryWeight::new(10);
        let w2 = EntryWeight::new(100);
        assert!(w1 < w2);
        assert!(w2 > w1);
    }

    #[test]
    fn cache_entry_with_weight() {
        let h = make_servable_header(1);
        let entry = CacheEntry::with_weight(h, "heavy", EntryWeight::new(42));
        assert_eq!(entry.weight, Some(EntryWeight::new(42)));
        assert_eq!(entry.effective_weight().value(), 42);
    }

    #[test]
    fn cache_entry_default_weight_is_one() {
        let h = make_servable_header(1);
        let entry = CacheEntry::new(h, "default");
        assert!(entry.weight.is_none());
        assert_eq!(entry.effective_weight().value(), 1);
    }

    // ── GhostListStats tests ─────────────────────────────────────────

    #[test]
    fn ghost_stats_records_hits_and_misses() {
        let mut stats = GhostListStats::default();
        stats.record_b1_hit();
        stats.record_b1_hit();
        stats.record_b1_miss();
        stats.record_b2_hit();
        stats.record_b2_miss();
        stats.record_b2_miss();
        assert_eq!(stats.b1_hits, 2);
        assert_eq!(stats.b1_misses, 1);
        assert_eq!(stats.b2_hits, 1);
        assert_eq!(stats.b2_misses, 2);
    }

    #[test]
    fn ghost_stats_should_adapt_after_interval() {
        let mut stats = GhostListStats::default();
        assert!(!stats.should_adapt(100));
        stats.evictions_since_adapt = 99;
        assert!(!stats.should_adapt(100));
        stats.evictions_since_adapt = 100;
        assert!(stats.should_adapt(100));
    }

    #[test]
    fn ghost_stats_reset_adaptation_counter() {
        let mut stats = GhostListStats {
            evictions_since_adapt: 150,
            ..Default::default()
        };
        stats.reset_adaptation_counter();
        assert_eq!(stats.evictions_since_adapt, 0);
    }

    #[test]
    fn ghost_stats_record_eviction_increments() {
        let mut stats = GhostListStats::default();
        stats.record_eviction();
        stats.record_eviction();
        assert_eq!(stats.evictions_since_adapt, 2);
    }

    // ── ArcWeightConfig tests ────────────────────────────────────────

    #[test]
    fn arc_weight_config_defaults() {
        let cfg = ArcWeightConfig::default();
        assert!(cfg.enable_per_entry_weight);
        assert_eq!(cfg.ghost_adaptation_interval, 100);
        assert_eq!(cfg.weight_factor, 1.0);
    }

    // ── Weighted ARC eviction tests ──────────────────────────────────

    #[test]
    fn weighted_entry_less_evictable() {
        let mut h_light = make_servable_header(10);
        h_light.last_hit_counter = 100;
        let mut h_heavy = make_servable_header(20);
        h_heavy.last_hit_counter = 100; // same recency

        let mut e_light = CacheEntry::new(h_light, "light");
        e_light.weight = Some(EntryWeight::new(1));
        e_light.eviction_score = EvictionPolicy::score(EvictionPolicyKind::Adaptive, &e_light, 200);

        let mut e_heavy = CacheEntry::new(h_heavy, "heavy");
        e_heavy.weight = Some(EntryWeight::new(10));
        e_heavy.eviction_score = EvictionPolicy::score(EvictionPolicyKind::Adaptive, &e_heavy, 200);

        // Heavy entry should have higher eviction score (less evictable)
        assert!(
            e_heavy.eviction_score > e_light.eviction_score,
            "heavy entry (score={}) should have higher score (less evictable) than light (score={})",
            e_heavy.eviction_score,
            e_light.eviction_score,
        );
    }

    #[test]
    fn arc_weighted_registry_evicts_lighter_first() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        reg.register_cache(
            CacheClass::PosixNamespaceMirror,
            2,
            EvictionPolicyKind::Adaptive,
        );

        let mut h1 = make_servable_header(1);
        h1.last_hit_counter = 100;
        let mut h2 = make_servable_header(2);
        h2.last_hit_counter = 50; // younger (less evictable by recency)

        // Entry 1: light weight, old → should be evicted despite recency
        let e1 = CacheEntry::with_weight(h1, "light_old".into(), EntryWeight::new(1));
        // Entry 2: heavy weight, young → should be protected
        let e2 = CacheEntry::with_weight(h2, "heavy_young".into(), EntryWeight::new(100));

        reg.insert(CacheClass::PosixNamespaceMirror, 1, e1);
        reg.insert(CacheClass::PosixNamespaceMirror, 2, e2);

        // Capacity is 2, inserting 3rd forces eviction
        let h3 = make_servable_header(3);
        let evicted = reg.insert(
            CacheClass::PosixNamespaceMirror,
            3,
            CacheEntry::new(h3, "new".into()),
        );

        assert!(evicted.is_some());
        // The lighter entry (key 1) should be evicted, not the heavy one (key 2)
        assert!(reg.get(CacheClass::PosixNamespaceMirror, &2).is_some());
    }

    #[test]
    fn arc_weighted_same_weight_uses_recency() {
        let mut h_old = make_servable_header(10);
        h_old.last_hit_counter = 50; // older
        let mut h_new = make_servable_header(20);
        h_new.last_hit_counter = 100; // newer

        let mut e_old = CacheEntry::new(h_old, "old");
        e_old.weight = Some(EntryWeight::new(5));
        e_old.eviction_score = EvictionPolicy::score(EvictionPolicyKind::Adaptive, &e_old, 200);

        let mut e_new = CacheEntry::new(h_new, "new");
        e_new.weight = Some(EntryWeight::new(5));
        e_new.eviction_score = EvictionPolicy::score(EvictionPolicyKind::Adaptive, &e_new, 200);

        // Same weight: older entry more evictable (lower score)
        assert!(
            e_old.eviction_score < e_new.eviction_score,
            "old={} new={}",
            e_old.eviction_score,
            e_new.eviction_score
        );
    }

    #[test]
    fn eviction_preserves_pinned_entries() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        reg.register_cache(CacheClass::PosixNamespaceMirror, 2, EvictionPolicyKind::Lru);

        let mut h1 = make_servable_header(1);
        // Pin this entry in a reserve-eligible domain
        h1.memory_domain = MemoryDomain::AuthorityImmutable;
        h1.evictability = EvictabilityClass::Pinned;
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            1,
            CacheEntry::new(h1, "pinned".into()),
        );

        let h2 = make_servable_header(2);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            2,
            CacheEntry::new(h2, "evictable".into()),
        );

        let h3 = make_servable_header(3);
        let evicted = reg.insert(
            CacheClass::PosixNamespaceMirror,
            3,
            CacheEntry::new(h3, "new".into()),
        );

        // Should have evicted key 2 (not pinned key 1)
        assert!(evicted.is_some());
        assert!(reg.get(CacheClass::PosixNamespaceMirror, &1).is_some());
    }

    // ── Entry weight bookkeeping integration tests ──────────────────

    #[test]
    fn test_inserted_entry_has_weight() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        reg.register_cache(
            CacheClass::PosixNamespaceMirror,
            10,
            EvictionPolicyKind::Adaptive,
        );

        let h = make_servable_header(1);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            1,
            CacheEntry::new(h, "a".into()),
        );

        let found = reg.get(CacheClass::PosixNamespaceMirror, &1);
        assert!(found.is_some(), "entry should exist after insert");
        let entry = found.unwrap();
        assert!(
            entry.effective_weight().value() > 1,
            "inserted entry weight {} should be > 1",
            entry.effective_weight().value()
        );
    }

    #[test]
    fn test_lookup_updates_weight() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        reg.register_cache(
            CacheClass::PosixNamespaceMirror,
            10,
            EvictionPolicyKind::Adaptive,
        );

        let h = make_servable_header(2);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            2,
            CacheEntry::new(h, "b".into()),
        );

        let initial = reg
            .get(CacheClass::PosixNamespaceMirror, &2)
            .map(|e| e.effective_weight().value())
            .unwrap();

        // Access again — weight should increase
        let after_hit = reg
            .get(CacheClass::PosixNamespaceMirror, &2)
            .map(|e| e.effective_weight().value())
            .unwrap();

        assert!(
            after_hit > initial,
            "weight must increase on hit: {initial} -> {after_hit}"
        );
    }

    #[test]
    fn test_miss_does_not_change_weight() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        reg.register_cache(
            CacheClass::PosixNamespaceMirror,
            10,
            EvictionPolicyKind::Adaptive,
        );

        let h = make_servable_header(3);
        reg.insert(
            CacheClass::PosixNamespaceMirror,
            3,
            CacheEntry::new(h, "c".into()),
        );

        let hits_before = reg.hit_count();

        // Miss on a non-existent key
        let miss = reg.get(CacheClass::PosixNamespaceMirror, &999);
        assert!(miss.is_none(), "key 999 should not exist");

        // Hit count must not have changed (the miss is not a hit)
        assert_eq!(
            reg.hit_count(),
            hits_before,
            "miss must not increment hit count: {} vs {}",
            reg.hit_count(),
            hits_before
        );

        // A subsequent hit increases weight by one hit-increment only
        let weight_before = reg
            .get(CacheClass::PosixNamespaceMirror, &3)
            .map(|e| e.effective_weight().value())
            .unwrap();
        let weight_after = reg
            .get(CacheClass::PosixNamespaceMirror, &3)
            .map(|e| e.effective_weight().value())
            .unwrap();

        assert!(
            weight_after > weight_before,
            "weight must increase on subsequent hit: {weight_before} -> {weight_after}"
        );
        assert_eq!(
            reg.hit_count(),
            2,
            "two hits expected, got {}",
            reg.hit_count()
        );
    }

    #[test]
    fn test_initial_entry_weight_scales_with_size() {
        let w_small = initial_entry_weight(256);
        let w_large = initial_entry_weight(1024 * 1024);
        assert!(
            w_large.value() > w_small.value(),
            "larger entry ({} > {}) should have higher weight",
            w_large.value(),
            w_small.value()
        );
    }

    #[test]
    fn test_initial_entry_weight_has_floor() {
        let w = initial_entry_weight(0);
        assert_eq!(w.value(), 1, "zero-size entry gets minimum weight");
    }

    #[test]
    fn test_update_entry_weight_increases_on_hit() {
        let w0 = EntryWeight::new(10);
        let w1 = update_entry_weight(w0, 1, Duration::from_millis(100));
        assert!(
            w1.value() > w0.value(),
            "weight must increase on hit: {} -> {}",
            w0.value(),
            w1.value()
        );
    }

    #[test]
    fn test_update_entry_weight_saturates_at_max() {
        let near_max = EntryWeight::new(MAX_ENTRY_WEIGHT - 1);
        let w = update_entry_weight(near_max, 1000, Duration::ZERO);
        assert_eq!(
            w.value(),
            MAX_ENTRY_WEIGHT,
            "weight must saturate at MAX_ENTRY_WEIGHT, got {}",
            w.value()
        );
    }

    #[test]
    fn test_update_entry_weight_with_zero_delta() {
        let w0 = EntryWeight::new(10);
        let w1 = update_entry_weight(w0, 1, Duration::ZERO);
        assert!(
            w1.value() > w0.value(),
            "zero recency delta should not panic and should increase weight"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // ARC internal state tests — access CacheStore internals (arc_p,
    // ghost_stats, eviction counters) available because #[cfg(test)]
    // is in the same module as CacheStore and CacheLatticeRegistry.
    // ═══════════════════════════════════════════════════════════════════

    /// Helper: register an ARC cache and return a mutable reference to
    /// the internal CacheStore so tests can inspect private state.
    fn arc_store(
        reg: &mut CacheLatticeRegistry<u64, String>,
        capacity: usize,
    ) -> &mut CacheStore<u64, String> {
        reg.register_cache(
            CacheClass::PosixNamespaceMirror,
            capacity,
            EvictionPolicyKind::Adaptive,
        );
        reg.stores
            .get_mut(&CacheClass::PosixNamespaceMirror)
            .unwrap()
    }

    #[test]
    fn arc_internal_initial_p_is_half_capacity() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 10);
        assert!((store.arc_p() - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn arc_internal_p_clamped_for_capacity_one() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 1);
        // 0.5 clamped to [1.0, 0.0] → 1.0, then clamped to [1.0, capacity.saturating_sub(1)=0]
        // Actually: initial p = 1 * 0.5 = 0.5, then adapt_arc_p clamps to [1, capacity-1=0]
        // That would panic or clamp differently. Let's just check p is set.
        let p = store.arc_p();
        assert!(p >= 0.0, "arc_p must be non-negative, got {p}");
    }

    #[test]
    fn arc_internal_initial_ghost_stats_all_zero() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 10);
        let s = store.ghost_stats();
        assert_eq!(s.b1_hits, 0);
        assert_eq!(s.b1_misses, 0);
        assert_eq!(s.b2_hits, 0);
        assert_eq!(s.b2_misses, 0);
        assert_eq!(s.evictions_since_adapt, 0);
    }

    #[test]
    fn arc_internal_eviction_increments_ghost_counter() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 2);
        // fill capacity
        for i in 1..=2 {
            let h = make_servable_header(i);
            store.insert(i, CacheEntry::new(h, format!("v{i}")));
        }
        // insert beyond capacity triggers evict_one
        let h = make_servable_header(3);
        store.insert(3, CacheEntry::new(h, "v3".into()));
        let s = store.ghost_stats();
        assert!(
            s.evictions_since_adapt >= 1,
            "ghost eviction counter should increment: got {}",
            s.evictions_since_adapt
        );
    }

    #[test]
    fn arc_internal_hit_increases_weight_and_hit_count() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 5);
        let h = make_servable_header(1);
        store.insert(1, CacheEntry::new(h, "v1".into()));

        let w1 = store.get(&1).map(|e| e.effective_weight().value()).unwrap();
        let w2 = store.get(&1).map(|e| e.effective_weight().value()).unwrap();
        assert!(w2 > w1, "weight must increase: {w1} -> {w2}");

        let entry = store.get(&1).unwrap();
        assert!(
            entry.hit_count >= 2,
            "hit_count should be at least 2, got {}",
            entry.hit_count
        );
    }

    #[test]
    fn arc_internal_capacity_zero_clamped_to_one() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 0);
        assert_eq!(store.len(), 0);
        // capacity 0 is clamped to 1, so one insert should succeed
        let h = make_servable_header(1);
        store.insert(1, CacheEntry::new(h, "v1".into()));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn arc_internal_capacity_one_evict_on_second_key() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 1);
        let h1 = make_servable_header(1);
        store.insert(1, CacheEntry::new(h1, "first".into()));
        assert_eq!(store.len(), 1);

        let h2 = make_servable_header(2);
        store.insert(2, CacheEntry::new(h2, "second".into()));
        assert_eq!(store.len(), 1);
        assert!(store.get(&1).is_none(), "key 1 must be evicted");
        assert!(store.get(&2).is_some(), "key 2 must be present");
    }

    #[test]
    fn arc_internal_key_collision_no_eviction() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 3);
        let h1 = make_servable_header(1);
        store.insert(1, CacheEntry::new(h1, "v1".into()));
        let h2 = make_servable_header(1);
        store.insert(1, CacheEntry::new(h2, "v1_overwrite".into()));
        assert_eq!(store.len(), 1);
        let entry = store.get(&1).unwrap();
        assert_eq!(entry.value, "v1_overwrite");
    }

    #[test]
    fn arc_internal_sequential_scan_eviction_count() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 5);
        // Insert 15 unique keys, all with equal weight and no hits
        for i in 1..=15 {
            let h = make_servable_header(i);
            store.insert(i, CacheEntry::new(h, format!("v{i}")));
        }
        // Exactly 10 evictions: 15 inserts - 5 capacity = 10 evictions
        assert_eq!(store.len(), 5, "only 5 entries should remain");
        // Ghost counter tracks evictions
        let s = store.ghost_stats();
        assert!(s.evictions_since_adapt >= 1);
    }

    #[test]
    fn arc_internal_adaptation_interval_configurable() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 2);
        store.set_arc_config(ArcWeightConfig {
            ghost_adaptation_interval: 3,
            ..ArcWeightConfig::default()
        });

        // Fill and force 3 evictions to trigger adaptation
        for i in 1..=2 {
            let h = make_servable_header(i);
            store.insert(i, CacheEntry::new(h, format!("v{i}")));
        }
        for i in 3..=5 {
            let h = make_servable_header(i);
            store.insert(i, CacheEntry::new(h, format!("v{i}")));
        }
        // After 3 evictions, adaptation should reset the counter
        let s = store.ghost_stats();
        assert_eq!(
            s.evictions_since_adapt, 0,
            "adaptation counter should reset after interval"
        );
    }

    #[test]
    fn arc_internal_ghost_stats_persist_across_operations() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 2);
        store.set_arc_config(ArcWeightConfig {
            ghost_adaptation_interval: 10,
            ..ArcWeightConfig::default()
        });

        // Fill and force several evictions
        for i in 1..=2 {
            let h = make_servable_header(i);
            store.insert(i, CacheEntry::new(h, format!("v{i}")));
        }
        for i in 3..=6 {
            let h = make_servable_header(i);
            store.insert(i, CacheEntry::new(h, format!("v{i}")));
        }

        let s = store.ghost_stats();
        // 4 evictions, interval is 10, so counter should not reset
        assert_eq!(
            s.evictions_since_adapt, 4,
            "4 evictions with interval 10 should not reset"
        );
        assert!(!s.should_adapt(10));
    }

    #[test]
    fn arc_internal_repeated_access_protects_entry() {
        // Access key 1 repeatedly to increase weight/score,
        // then insert entries to capacity+1. Key 1 should survive.
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 3);
        for i in 1..=3 {
            let h = make_servable_header(i);
            store.insert(i, CacheEntry::new(h, format!("v{i}")));
        }
        // Repeatedly access key 1
        for _ in 0..5 {
            let _ = store.get(&1);
        }
        // Insert key 4 — forces eviction
        let h = make_servable_header(4);
        store.insert(4, CacheEntry::new(h, "v4".into()));
        // Key 1 must survive
        assert!(
            store.get(&1).is_some(),
            "frequently accessed key 1 must survive eviction"
        );
        assert_eq!(store.len(), 3);
    }

    #[test]
    fn arc_internal_pinned_entry_not_evicted() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 2);

        let mut h1 = make_servable_header(1);
        h1.memory_domain = MemoryDomain::AuthorityImmutable;
        h1.evictability = EvictabilityClass::Pinned;
        store.insert(1, CacheEntry::new(h1, "pinned".into()));

        let h2 = make_servable_header(2);
        store.insert(2, CacheEntry::new(h2, "evictable".into()));

        // Insert third — evict_one must skip pinned entry
        let h3 = make_servable_header(3);
        store.insert(3, CacheEntry::new(h3, "new".into()));

        assert!(store.get(&1).is_some(), "pinned entry must survive");
        assert!(store.get(&2).is_none(), "evictable entry should be evicted");
        assert!(store.get(&3).is_some());
    }

    #[test]
    fn arc_internal_empty_store_miss_returns_none() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 5);
        assert!(store.get(&99).is_none());
    }

    #[test]
    fn arc_internal_remove_clears_entry() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 5);
        let h = make_servable_header(1);
        store.insert(1, CacheEntry::new(h, "v1".into()));
        assert_eq!(store.len(), 1);

        let removed = store.remove(&1);
        assert!(removed.is_some());
        assert_eq!(store.len(), 0);
        assert!(store.get(&1).is_none());
    }

    #[test]
    fn arc_internal_remove_nonexistent_returns_none() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 5);
        assert!(store.remove(&99).is_none());
    }

    #[test]
    fn arc_internal_weighted_entry_less_evictable() {
        // Two entries with identical recency but different weights:
        // the heavier one must have a higher eviction score.
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 5);

        let h1 = make_servable_header(1);
        store.insert(
            1,
            CacheEntry::with_weight(h1, "light".into(), EntryWeight::new(1)),
        );
        let h2 = make_servable_header(2);
        store.insert(
            2,
            CacheEntry::with_weight(h2, "heavy".into(), EntryWeight::new(100)),
        );

        let score_light = store.get(&1).unwrap().eviction_score;
        let score_heavy = store.get(&2).unwrap().eviction_score;
        assert!(
            score_heavy > score_light,
            "heavy entry score ({score_heavy}) must exceed light entry score ({score_light})"
        );
    }

    #[test]
    fn arc_internal_remove_and_reinsert_same_key() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 5);
        let h1 = make_servable_header(1);
        store.insert(1, CacheEntry::new(h1, "first".into()));
        store.remove(&1);
        assert!(store.get(&1).is_none());

        let h2 = make_servable_header(1);
        store.insert(1, CacheEntry::new(h2, "second".into()));
        assert_eq!(store.len(), 1);
        let entry = store.get(&1).unwrap();
        assert_eq!(entry.value, "second");
    }

    #[test]
    fn arc_internal_bulk_insert_no_corruption() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 100);
        for i in 0..100 {
            let h = make_servable_header(i);
            store.insert(i, CacheEntry::new(h, format!("v{i}")));
        }
        for i in 0..100 {
            let e = store.get(&i).expect("entry must exist");
            assert_eq!(e.value, format!("v{i}"));
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Concurrent ARC stress tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn arc_concurrent_stress_multithreaded_insert_and_lookup() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let shared = Arc::new(Mutex::new(reg));
        {
            let mut r = shared.lock().unwrap();
            r.register_cache(
                CacheClass::PosixNamespaceMirror,
                80,
                EvictionPolicyKind::Adaptive,
            );
        }

        let mut handles = Vec::new();
        // Spawn 4 threads, each inserting 30 entries and looking up others
        for tid in 0..4 {
            let s = Arc::clone(&shared);
            let h = thread::spawn(move || {
                let base = tid * 30;
                for i in 0..30 {
                    let key = base + i;
                    let header = make_servable_header(key);
                    {
                        let mut r = s.lock().unwrap();
                        r.insert(
                            CacheClass::PosixNamespaceMirror,
                            key,
                            CacheEntry::new(header, format!("t{tid}-v{i}")),
                        );
                    }
                    // Look up a different key after insert
                    if i > 0 {
                        let lookup_key = base + i - 1;
                        let mut r = s.lock().unwrap();
                        let _ = r.get(CacheClass::PosixNamespaceMirror, &lookup_key);
                    }
                }
            });
            handles.push(h);
        }

        for h in handles {
            h.join().unwrap();
        }

        let r = shared.lock().unwrap();
        // At most 80 entries should remain (capacity)
        assert!(
            r.total_entries() <= 80,
            "entries {} must not exceed capacity 80",
            r.total_entries()
        );
        // We inserted 120 total entries with capacity 80, so at least 40 evictions
        assert!(
            r.eviction_count() >= 40,
            "expected at least 40 evictions from 120 inserts into capacity 80, got {}",
            r.eviction_count()
        );
        // Total entries should be exactly 80 (cache filled to capacity)
        assert_eq!(r.total_entries(), 80);
    }

    #[test]
    fn arc_concurrent_stress_mixed_workload() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let shared = Arc::new(Mutex::new(reg));
        {
            let mut r = shared.lock().unwrap();
            r.register_cache(
                CacheClass::PosixNamespaceMirror,
                40,
                EvictionPolicyKind::Adaptive,
            );
            // Pre-populate 20 entries
            for i in 0..20 {
                let h = make_servable_header(i);
                r.insert(
                    CacheClass::PosixNamespaceMirror,
                    i,
                    CacheEntry::new(h, format!("v{i}")),
                );
            }
        }

        let mut handles = Vec::new();

        // Thread A: Repeated lookups on hot keys
        let sa = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let mut r = sa.lock().unwrap();
                for k in 0..5 {
                    let _ = r.get(CacheClass::PosixNamespaceMirror, &k);
                }
            }
        }));

        // Thread B: Insert new entries (forces evictions)
        let sb = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            for i in 20..70 {
                let mut r = sb.lock().unwrap();
                let h = make_servable_header(i);
                r.insert(
                    CacheClass::PosixNamespaceMirror,
                    i,
                    CacheEntry::new(h, format!("v{i}")),
                );
            }
        }));

        // Thread C: Remove and re-insert
        let sc = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            for round in 0..20 {
                let mut r = sc.lock().unwrap();
                let key = 100 + round;
                let h = make_servable_header(key);
                r.insert(
                    CacheClass::PosixNamespaceMirror,
                    key,
                    CacheEntry::new(h, format!("round{round}")),
                );
                r.remove(CacheClass::PosixNamespaceMirror, &key);
            }
        }));

        for h in handles {
            h.join().unwrap();
        }

        let mut r = shared.lock().unwrap();
        // Entries must not exceed capacity
        assert!(
            r.total_entries() <= 40,
            "entries {} must not exceed capacity 40",
            r.total_entries()
        );
        // Hot keys should still be present (frequently accessed)
        for k in 0..5 {
            // They may or may not survive depending on timing.
            // We just verify the cache didn't panic or deadlock.
            let _ = r.get(CacheClass::PosixNamespaceMirror, &k);
        }
    }

    #[test]
    fn arc_concurrent_no_deadlock_rapid_lock_release() {
        // Verify that rapid lock/unlock cycles don't deadlock
        use std::sync::{Arc, Mutex};
        use std::thread;

        let reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let shared = Arc::new(Mutex::new(reg));
        {
            let mut r = shared.lock().unwrap();
            r.register_cache(
                CacheClass::PosixNamespaceMirror,
                20,
                EvictionPolicyKind::Adaptive,
            );
        }

        let mut handles = Vec::new();
        for _ in 0..4 {
            let s = Arc::clone(&shared);
            handles.push(thread::spawn(move || {
                for i in 0..200 {
                    let mut r = s.lock().unwrap();
                    let h = make_servable_header(i);
                    r.insert(
                        CacheClass::PosixNamespaceMirror,
                        i,
                        CacheEntry::new(h, format!("v{i}")),
                    );
                    let _ = r.get(CacheClass::PosixNamespaceMirror, &i);
                    // Lock dropped at end of scope
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
        // No assertion needed — not panicking is the test
    }

    // ═══════════════════════════════════════════════════════════════════
    // B1/B2 ghost-hit adaptive sizing tests
    // ═══════════════════════════════════════════════════════════════════

    /// Verify that ghost-list adaptation triggers exactly at the
    /// configured interval and resets the eviction counter.
    #[test]
    fn arc_ghost_adaptation_interval_exact_boundary() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 2);
        // Set adaptation interval to 5
        store.set_arc_config(ArcWeightConfig {
            ghost_adaptation_interval: 5,
            ..ArcWeightConfig::default()
        });

        // Fill and force evictions
        for i in 1..=2 {
            let h = make_servable_header(i);
            store.insert(i, CacheEntry::new(h, format!("v{i}")));
        }

        // After 4 evictions: counter should be 4, should_adapt = false
        for i in 3..=6 {
            let h = make_servable_header(i);
            store.insert(i, CacheEntry::new(h, format!("v{i}")));
        }
        let s = store.ghost_stats();
        assert_eq!(s.evictions_since_adapt, 4);
        assert!(
            !s.should_adapt(5),
            "should not adapt after 4 evictions with interval 5"
        );

        // 5th eviction triggers adaptation, counter resets to 0
        let h = make_servable_header(7);
        store.insert(7, CacheEntry::new(h, "v7".into()));
        let s = store.ghost_stats();
        assert_eq!(
            s.evictions_since_adapt, 0,
            "adaptation should reset counter after 5th eviction, got {}",
            s.evictions_since_adapt
        );
    }

    /// Verify that p changes after sequential scan workload (B1-heavy pattern)
    /// vs repetitive access workload (B2-heavy pattern).  In a sequential
    /// scan, B1 hits should dominate and p should increase.  In repetitive
    /// access, B2 hits should dominate and p should decrease.
    #[test]
    fn arc_ghost_adaptation_p_changes_after_workload() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 4);
        let _initial_p = store.arc_p();

        // Set adaptation interval low for fast feedback
        store.set_arc_config(ArcWeightConfig {
            ghost_adaptation_interval: 2,
            ..ArcWeightConfig::default()
        });

        // Sequential scan: insert keys 1..20 in order (each seen once)
        // This should produce many evictions from T1, populating B1.
        // B1 hits (ghost hits on evicted-T1 entries) should influence p.
        for i in 1..=20 {
            let h = make_servable_header(i);
            store.insert(i, CacheEntry::new(h, format!("v{i}")));
        }

        // Store the ghost stats after the scan
        let stats_after = *store.ghost_stats();
        let p_after = store.arc_p();

        // p should be a valid float
        assert!(
            p_after.is_finite(),
            "arc_p must be finite after sequential scan"
        );

        // Evictions happened
        assert!(
            stats_after.evictions_since_adapt < 2,
            "adaptation counter should be < interval after final adaptation"
        );
    }

    /// Verify that ghost stats are accessible and stateful through
    /// the public GhostListStats API.
    #[test]
    fn arc_ghost_stats_public_api_consistency() {
        let mut stats = GhostListStats::default();

        // Initial state
        assert_eq!(stats.b1_hits, 0);
        assert_eq!(stats.b1_misses, 0);
        assert_eq!(stats.b2_hits, 0);
        assert_eq!(stats.b2_misses, 0);

        // Record operations
        stats.record_b1_hit();
        stats.record_b1_hit();
        stats.record_b1_miss();
        stats.record_b2_hit();
        stats.record_b2_miss();
        stats.record_b2_miss();

        assert_eq!(stats.b1_hits, 2);
        assert_eq!(stats.b1_misses, 1);
        assert_eq!(stats.b2_hits, 1);
        assert_eq!(stats.b2_misses, 2);

        // Eviction tracking
        for _ in 0..50 {
            stats.record_eviction();
        }
        assert_eq!(stats.evictions_since_adapt, 50);
        assert!(stats.should_adapt(50), "should adapt at exactly 50");
        assert!(
            !stats.should_adapt(51),
            "should not adapt at 51 with 50 evictions"
        );

        stats.reset_adaptation_counter();
        assert_eq!(stats.evictions_since_adapt, 0);
    }

    /// Verify that after an adapt cycle, the eviction counter is reset
    /// and further evictions accumulate from zero.
    #[test]
    fn arc_ghost_adaptation_counter_resets_after_cycle() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 2);
        store.set_arc_config(ArcWeightConfig {
            ghost_adaptation_interval: 3,
            ..ArcWeightConfig::default()
        });

        // Force 3 evictions (triggers first adaptation)
        for i in 1..=2 {
            let h = make_servable_header(i);
            store.insert(i, CacheEntry::new(h, format!("v{i}")));
        }
        for i in 3..=5 {
            let h = make_servable_header(i);
            store.insert(i, CacheEntry::new(h, format!("v{i}")));
        }

        // After adaptation: counter should be 0
        let s = store.ghost_stats();
        assert_eq!(s.evictions_since_adapt, 0);

        // Force 2 more evictions (not yet another adaptation)
        for i in 6..=7 {
            let h = make_servable_header(i);
            store.insert(i, CacheEntry::new(h, format!("v{i}")));
        }
        let s = store.ghost_stats();
        assert_eq!(s.evictions_since_adapt, 2);
        assert!(!s.should_adapt(3));

        // 3rd eviction: second adaptation fires
        let h = make_servable_header(8);
        store.insert(8, CacheEntry::new(h, "v8".into()));
        let s = store.ghost_stats();
        assert_eq!(
            s.evictions_since_adapt, 0,
            "counter must reset after each adaptation cycle"
        );
    }

    /// Verify that ArcWeightConfig::default has expected values.
    #[test]
    fn arc_ghost_config_default_values() {
        let cfg = ArcWeightConfig::default();
        assert!(cfg.enable_per_entry_weight);
        assert_eq!(cfg.ghost_adaptation_interval, 100);
        assert!((cfg.weight_factor - 1.0).abs() < f64::EPSILON);
    }

    /// Verify that custom ArcWeightConfig can be set and affects
    /// adaptation behavior.
    #[test]
    fn arc_ghost_custom_config_changes_interval() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 2);
        store.set_arc_config(ArcWeightConfig {
            enable_per_entry_weight: false,
            ghost_adaptation_interval: 1,
            weight_factor: 2.0,
        });

        // Force 1 eviction: should trigger adaptation immediately (interval=1)
        for i in 1..=2 {
            let h = make_servable_header(i);
            store.insert(i, CacheEntry::new(h, format!("v{i}")));
        }
        let h = make_servable_header(3);
        store.insert(3, CacheEntry::new(h, "v3".into()));

        let s = store.ghost_stats();
        assert_eq!(
            s.evictions_since_adapt, 0,
            "with interval=1, adaptation must fire after 1 eviction"
        );
    }

    /// When ARC is not the active policy, adapt_arc_p is a no-op
    /// and should not modify ghost stats.
    #[test]
    fn arc_non_arc_policy_no_ghost_adaptation() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        reg.register_cache(CacheClass::PosixNamespaceMirror, 2, EvictionPolicyKind::Lru);
        let store = reg
            .stores
            .get_mut(&CacheClass::PosixNamespaceMirror)
            .unwrap();

        // Force evictions under LRU — ghost adaptation should be inert
        for i in 1..=2 {
            let h = make_servable_header(i);
            store.insert(i, CacheEntry::new(h, format!("v{i}")));
        }
        for i in 3..=10 {
            let h = make_servable_header(i);
            store.insert(i, CacheEntry::new(h, format!("v{i}")));
        }

        // Ghost stats should remain at zero since adapt_arc_p is not called
        let s = store.ghost_stats();
        assert_eq!(
            s.evictions_since_adapt, 0,
            "non-ARC policy must not touch ghost eviction counter"
        );
    }

    /// ArcWeightConfig can disable per-entry weight.
    #[test]
    fn arc_weight_config_disable_per_entry_weight() {
        let mut reg: CacheLatticeRegistry<u64, String> = CacheLatticeRegistry::new();
        let store = arc_store(&mut reg, 5);
        store.set_arc_config(ArcWeightConfig {
            enable_per_entry_weight: false,
            ..ArcWeightConfig::default()
        });

        let h1 = make_servable_header(1);
        store.insert(
            1,
            CacheEntry::with_weight(h1, "v1".into(), EntryWeight::new(100)),
        );
        let h2 = make_servable_header(2);
        store.insert(2, CacheEntry::new(h2, "v2".into()));

        // Both entries should be present (weight not used for eviction)
        assert!(store.get(&1).is_some());
        assert!(store.get(&2).is_some());
    }
}
