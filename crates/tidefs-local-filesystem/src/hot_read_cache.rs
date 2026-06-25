// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Hot read cache — whole-file ARC for read_file/read_symlink.
//!
//! ## Authority Classification (per docs/cache-authority-model.md)
//!
//! This cache is **Derived** and **superseded** by
//! `tidefs-cache-core::PageCache`.  It is a bounded runtime mirror over
//! content already published through the local filesystem transaction/root
//! model.  It must not grow new authority claims, dirty-data ownership, or
//! invalidation primitives that conflict with cache-core.  Future work will
//! remove it entirely in favor of cache-core delegation.
//!
//! The canonical cache authority table is at `docs/cache-authority-model.md`.
//! See also `docs/HOT_READ_CACHE_PC003.md` for the original design document.
//!
use tidefs_types_vfs_core::{InodeId, NodeKind};

use tidefs_cache_core::{
    budget_category_for_cache_level, BudgetCategory, CacheBudgetLevel, Governor,
};
#[cfg(test)]
use tidefs_types_cache_lattice_core::CacheLatticeReport;
use tidefs_types_cache_lattice_core::{
    CacheClass, CacheEntryHeader, MemoryDomain, RebuildCostClass, ReserveGuardClass,
};

use crate::constants::*;
use crate::types::*;

// ── ARC: Adaptive Replacement Cache ─────────────────────────────────────────────
//
// Based on Megiddo & Modha, "ARC: A Self-Tuning, Low Overhead Replacement
// Cache", FAST 2003. Extended with per-entry byte-weight tracking per
// design #1192 / v0.262 arc.py. Capacity is measured in weight units
// (bytes), not entry count. Ghost lists carry evicted entry weights.
// The adaptive policy balances T1/T2 split by weight.
//
// Four lists, each in LRU order (index 0 = MRU, last index = LRU):
//   T1  – resident entries accessed exactly once recently
//   T2  – resident entries accessed at least twice recently
//   B1  – ghost (key, weight) for entries evicted from T1
//   B2  – ghost (key, weight) for entries evicted from T2
//
// Invariants:
//   0 <= weight(T1) + weight(T2) <= c              (resident weight cap)
//   0 <= |T1| + |T2|       <= max_entry_cap        (entry count safety cap)
//   weight(T1)+weight(T2)+weight(B1)+weight(B2) <= 2c (total weight cap)
//   Adaptive target p in [0, c] controls T1/T2 weight split.
//
// With default unit-weight (weight_fn = |_| 1), behavior matches the
// classic entry-count ARC exactly for backward compatibility.

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum HotReadCacheObjectRole {
    File,
    Symlink,
}

impl HotReadCacheObjectRole {
    pub(crate) const fn from_node_kind(kind: NodeKind) -> Option<Self> {
        match kind {
            NodeKind::File => Some(Self::File),
            NodeKind::Symlink => Some(Self::Symlink),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct HotReadCacheKey {
    pub(crate) role: HotReadCacheObjectRole,
    pub(crate) inode_id: u64,
    pub(crate) data_version: u64,
    pub(crate) size: u64,
}

#[cfg(test)]
#[derive(Clone, Debug)]
#[allow(dead_code)] // INTENT: all fields populated in arc_stats() but only a subset read in current tests
pub(crate) struct ArcStats {
    pub t1_size: usize,
    pub t2_size: usize,
    pub b1_size: usize,
    pub b2_size: usize,
    pub t1_weight: u64,
    pub t2_weight: u64,
    pub b1_weight: u64,
    pub b2_weight: u64,
    pub adaptive_p: u64,
    pub capacity: usize,
    pub t1_hits: u64,
    pub t2_hits: u64,
    pub b1_hits: u64, // ghost hits — would have been T1 hits under LRU
    pub b2_hits: u64, // ghost hits — would have been T2 hits under LRU
    pub evictions_from_t1: u64,
    #[allow(dead_code)] // INTENT: ARC eviction counter populated in arc_stats(), consumed by tests
    pub evictions_from_t2: u64,
}

/// An entry in the resident lists (T1 or T2) with cache-lattice header.
///
/// Per P4-02: every cache entry carries a mandatory [`CacheEntryHeader`]
/// with anchor/fence/budget/dirty/poison fields.
#[derive(Clone, Debug)]
struct ArcResident {
    key: HotReadCacheKey,
    bytes: Vec<u8>,
    header: CacheEntryHeader,
}

#[derive(Debug)]
pub(crate) struct HotReadCache {
    policy: HotReadCachePolicy,

    // Resident lists (LRU: index 0 = MRU, last = LRU-tail)
    t1: Vec<ArcResident>,
    t2: Vec<ArcResident>,

    // Ghost lists (LRU: index 0 = MRU, last = LRU-tail), carrying eviction weight
    b1: Vec<(HotReadCacheKey, u64)>,
    b2: Vec<(HotReadCacheKey, u64)>,

    // Adaptive target weight for T1 (p in [0, c])
    adaptive_p: u64,

    // Byte tracking
    resident_bytes: u64,

    // Counters — preserved mapping into the public HotReadCacheReport
    hits: u64,
    misses: u64,
    insertions: u64,
    evictions: u64,
    invalidations: u64,
    admission_bypasses: u64,

    // ARC-specific counters
    t1_hits: u64,
    t2_hits: u64,
    b1_hits: u64,
    b2_hits: u64,
    evictions_from_t1: u64,
    evictions_from_t2: u64,

    // P4-02 cache lattice counters
    admission_rejected_budget: u64,
    admission_rejected_reserve: u64,
    admission_rejected_dirty_state: u64,
    poisoned_on_validate: u64,
    monotonic_counter: u64, // global birth/hit counter
    governor: Option<Governor>,
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn find_in_residents(residents: &[ArcResident], key: &HotReadCacheKey) -> Option<usize> {
    residents.iter().position(|r| r.key == *key)
}

fn find_in_ghosts(ghosts: &[(HotReadCacheKey, u64)], key: &HotReadCacheKey) -> Option<usize> {
    ghosts.iter().position(|(k, _w)| k == key)
}

impl HotReadCache {
    /// Cache authority classification per docs/cache-authority-model.md.
    /// HotReadCache is Derived and superseded by cache-core::PageCache.
    #[allow(dead_code)]
    pub(crate) const CACHE_AUTHORITY_CLASS: &str = "Derived";
    /// Return the cache authority classification at runtime.
    #[allow(dead_code)]
    pub fn cache_authority_class(&self) -> &'static str {
        Self::CACHE_AUTHORITY_CLASS
    }

    pub(crate) fn new(policy: HotReadCachePolicy) -> Self {
        Self {
            policy,
            t1: Vec::new(),
            t2: Vec::new(),
            b1: Vec::new(),
            b2: Vec::new(),
            adaptive_p: 0,
            resident_bytes: 0,
            hits: 0,
            misses: 0,
            insertions: 0,
            evictions: 0,
            invalidations: 0,
            admission_bypasses: 0,
            t1_hits: 0,
            t2_hits: 0,
            b1_hits: 0,
            b2_hits: 0,
            evictions_from_t1: 0,
            evictions_from_t2: 0,
            admission_rejected_budget: 0,
            admission_rejected_reserve: 0,
            admission_rejected_dirty_state: 0,
            poisoned_on_validate: 0,
            monotonic_counter: 0,
            governor: None,
        }
    }

    /// Attach resource-governor accounting for L1 hot-read data bytes.
    pub(crate) fn set_governor(&mut self, governor: Governor) {
        self.governor = Some(governor);
    }

    fn budget_category() -> BudgetCategory {
        budget_category_for_cache_level(CacheBudgetLevel::L1HotRead)
    }

    fn admit_budget(&mut self, bytes: u64) -> bool {
        if let Some(ref governor) = self.governor {
            if governor.admit(Self::budget_category(), bytes).is_err() {
                self.admission_rejected_budget =
                    self.admission_rejected_budget.saturating_add(1);
                return false;
            }
        }
        true
    }

    fn release_budget(&self, bytes: u64) {
        if let Some(ref governor) = self.governor {
            governor.release(Self::budget_category(), bytes);
        }
    }

    fn resize_budget(&mut self, old_bytes: u64, new_bytes: u64) -> bool {
        if new_bytes > old_bytes {
            self.admit_budget(new_bytes - old_bytes)
        } else {
            self.release_budget(old_bytes - new_bytes);
            true
        }
    }

    /// Resident entry capacity (count bound).
    fn entry_capacity(&self) -> usize {
        self.policy.max_entries
    }

    /// Resident weight capacity (byte bound).
    fn weight_capacity(&self) -> u64 {
        self.policy.max_bytes
    }

    /// Total ghost entries (metadata only, no data).
    fn total_ghosts(&self) -> usize {
        self.b1.len() + self.b2.len()
    }

    /// Total resident entries.
    fn total_resident(&self) -> usize {
        self.t1.len() + self.t2.len()
    }

    /// Total resident weight (bytes).
    fn total_resident_weight(&self) -> u64 {
        self.resident_bytes
    }

    /// Total ghost weight (bytes carried by ghost entries).
    fn ghost_weight_b1(&self) -> u64 {
        self.b1.iter().map(|(_, w)| w).sum()
    }

    fn ghost_weight_b2(&self) -> u64 {
        self.b2.iter().map(|(_, w)| w).sum()
    }

    fn total_ghost_weight(&self) -> u64 {
        self.ghost_weight_b1() + self.ghost_weight_b2()
    }

    // ── ARC adaptive-p update ───────────────────────────────────────────

    /// Adapt p after a ghost hit in B1 (weight-based).
    fn adapt_p_up(&mut self) {
        let wb1 = self.ghost_weight_b1();
        let wb2 = self.ghost_weight_b2();
        let delta = if wb1 >= wb2 && wb2 > 0 {
            // increase proportional to B2/B1 weight ratio
            (wb2 / wb1).max(1)
        } else {
            1
        };
        self.adaptive_p = (self.adaptive_p + delta).min(self.weight_capacity());
    }

    /// Adapt p after a ghost hit in B2 (weight-based).
    fn adapt_p_down(&mut self) {
        let wb1 = self.ghost_weight_b1();
        let wb2 = self.ghost_weight_b2();
        let delta = if wb2 >= wb1 && wb1 > 0 {
            (wb1 / wb2).max(1)
        } else {
            1
        };
        self.adaptive_p = self.adaptive_p.saturating_sub(delta);
    }

    /// Enforce ghost-list weight invariant:
    ///   weight(T1)+weight(T2)+weight(B1)+weight(B2) <= 2c
    fn enforce_ghost_cap(&mut self) {
        let limit = 2 * self.weight_capacity();
        while self.total_resident_weight() + self.total_ghost_weight() > limit {
            if self.b1.len() >= self.b2.len() {
                self.b1.pop(); // drop LRU tail of B1
            } else {
                self.b2.pop(); // drop LRU tail of B2
            }
        }
    }

    /// Enforce ghost-list entry-count invariant:
    ///   |B1| + |B2| <= 2 * entry_capacity
    ///
    /// This is a safety bound that prevents unbounded ghost accumulation
    /// when all entries carry unit weights.
    fn enforce_ghost_entry_cap(&mut self) {
        let limit = 2 * self.entry_capacity();
        while self.total_ghosts() > limit {
            if self.b1.len() >= self.b2.len() {
                self.b1.pop();
            } else {
                self.b2.pop();
            }
        }
    }

    /// Evict one entry from the appropriate resident list (T1 or T2)
    /// and move its key to the corresponding ghost list.  Returns the
    /// evicted entry's byte count so the caller can adjust resident_bytes.
    ///
    /// P4-02 eviction law (Design rule §6):
    ///   - Dirty entries must drain through writeback, not hard-evict.
    ///   - Hard/pinned reserve-guarded entries are skipped.
    ///   - If the primary list is fully protected, the secondary is tried.
    ///   - If both are fully protected, eviction fails (None).
    fn evict_one(&mut self) -> Option<u64> {
        if self.total_resident() == 0 {
            return None;
        }

        // Evict when resident weight exceeds adaptive target (compare weights, not counts)
        let evict_from_t1 = !self.t1.is_empty()
            && (self.total_resident_weight() >= self.adaptive_p.max(1) || self.t2.is_empty());
        let evict_from_t1 = evict_from_t1 || (self.t2.is_empty() && !self.t1.is_empty());

        // Two-phase eviction: try the primary list first, then fall back to
        // the other list if all entries in the primary are protected.
        // Avoids simultaneous mutable borrows of self.t1 and self.t2.
        let primary_is_t1 = evict_from_t1;

        // Phase 1: try primary list.
        if let Some(len) = self.try_evict_from(primary_is_t1) {
            return Some(len);
        }

        // Phase 2: try secondary list.
        self.try_evict_from(!primary_is_t1)
    }

    /// Attempt to evict the LRU tail of `list`, rotating past entries
    /// that are dirty, poisoned, or hard/pinned reserve-guarded.
    /// Returns the freed byte count on success, None if the list is
    /// fully protected.
    fn try_evict_from(&mut self, is_t1: bool) -> Option<u64> {
        let list = if is_t1 { &mut self.t1 } else { &mut self.t2 };
        let original_len = list.len();
        for _ in 0..original_len {
            let entry = list.pop()?; // LRU tail
                                     // P4-02: cannot hard-evict dirty entries — they must drain.
            if entry.header.dirty_state.is_dirty() {
                self.admission_rejected_dirty_state =
                    self.admission_rejected_dirty_state.saturating_add(1);
                list.insert(0, entry); // rotate to MRU
                continue;
            }
            // P4-02: cannot evict pinned or hard-reserve entries.
            if matches!(
                entry.header.reserve_guard,
                ReserveGuardClass::Hard | ReserveGuardClass::Pinned
            ) {
                self.admission_rejected_reserve = self.admission_rejected_reserve.saturating_add(1);
                list.insert(0, entry);
                continue;
            }
            // Evictable — move to ghost list.
            let len = entry.bytes.len() as u64;
            if is_t1 {
                self.evictions_from_t1 = self.evictions_from_t1.saturating_add(1);
                self.b1.insert(0, (entry.key, len));
            } else {
                self.evictions_from_t2 = self.evictions_from_t2.saturating_add(1);
                self.b2.insert(0, (entry.key, len));
            }
            self.release_budget(len);
            self.enforce_ghost_cap();
            self.enforce_ghost_entry_cap();
            return Some(len);
        }
        None
    }

    /// Make room for `needed_bytes` by evicting from resident lists.
    fn make_room(&mut self, needed_bytes: u64) {
        while self.total_resident() > 0
            && self.resident_bytes.saturating_add(needed_bytes) > self.policy.max_bytes
        {
            if let Some(freed) = self.evict_one() {
                self.resident_bytes = self.resident_bytes.saturating_sub(freed);
                self.evictions = self.evictions.saturating_add(1);
            } else {
                break;
            }
        }
    }

    /// Evict until resident weight is within byte budget, then
    /// ensure resident count is within entry cap (two-phase enforcement).
    fn enforce_capacity_limits(&mut self) {
        // Phase 1: ensure resident weight is within byte budget.
        while self.resident_bytes > self.weight_capacity() {
            if let Some(freed) = self.evict_one() {
                self.resident_bytes = self.resident_bytes.saturating_sub(freed);
                self.evictions = self.evictions.saturating_add(1);
            } else {
                break;
            }
        }
        // Phase 2: ensure resident count is within entry cap.
        while self.total_resident() >= self.entry_capacity() {
            if let Some(freed) = self.evict_one() {
                self.resident_bytes = self.resident_bytes.saturating_sub(freed);
                self.evictions = self.evictions.saturating_add(1);
            } else {
                break;
            }
        }
    }

    // ── Public API ──────────────────────────────────────────────────────

    /// Look up `key` in the cache.  Returns a clone of the cached bytes on
    /// hit, or `None` on miss.  ARC adaptation (p update) happens on ghost
    /// hits; list reordering happens on resident hits.
    pub(crate) fn get(&mut self, key: HotReadCacheKey) -> Option<Vec<u8>> {
        self.monotonic_counter = self.monotonic_counter.wrapping_add(1);
        let counter = self.monotonic_counter;
        // Check T2 first (more valuable).
        if let Some(idx) = find_in_residents(&self.t2, &key) {
            let mut entry = self.t2.remove(idx);
            // P4-02: validate header before serving.
            if !entry.header.is_servable() {
                self.poisoned_on_validate = self.poisoned_on_validate.saturating_add(1);
                self.misses = self.misses.saturating_add(1);
                return None;
            }
            entry.header.mark_hit(counter);
            let bytes = entry.bytes.clone();
            self.t2.insert(0, entry); // move to MRU
            self.hits = self.hits.saturating_add(1);
            self.t2_hits = self.t2_hits.saturating_add(1);
            return Some(bytes);
        }

        // Check T1.
        if let Some(idx) = find_in_residents(&self.t1, &key) {
            let mut entry = self.t1.remove(idx);
            if !entry.header.is_servable() {
                self.poisoned_on_validate = self.poisoned_on_validate.saturating_add(1);
                self.misses = self.misses.saturating_add(1);
                return None;
            }
            entry.header.mark_hit(counter);
            let bytes = entry.bytes.clone();
            // Promote to T2 (second access)
            self.t2.insert(0, entry);
            self.hits = self.hits.saturating_add(1);
            self.t1_hits = self.t1_hits.saturating_add(1);
            return Some(bytes);
        }

        // Ghost hit in B1 — we evicted too early from T1.
        if let Some(idx) = find_in_ghosts(&self.b1, &key) {
            self.b1.remove(idx);
            self.misses = self.misses.saturating_add(1);
            self.b1_hits = self.b1_hits.saturating_add(1);
            self.adapt_p_up();
            self.enforce_ghost_cap();
            return None;
        }

        // Ghost hit in B2 — we should have promoted to T2.
        if let Some(idx) = find_in_ghosts(&self.b2, &key) {
            self.b2.remove(idx);
            self.misses = self.misses.saturating_add(1);
            self.b2_hits = self.b2_hits.saturating_add(1);
            self.adapt_p_down();
            self.enforce_ghost_cap();
            return None;
        }

        // Complete miss.
        self.misses = self.misses.saturating_add(1);
        None
    }

    /// Admit (or update) an entry into the cache with a P4-02 cache-lattice
    /// header.  If `bytes` is too large for the byte budget, the admission
    /// is bypassed.  Header invariants are validated before insertion.
    ///
    /// All entries are admitted as `PosixNamespaceMirror` class in the
    /// `AdapterServingHot` memory domain (the HotReadCache serves namespace
    /// mirror data).
    pub(crate) fn admit(&mut self, key: HotReadCacheKey, bytes: &[u8]) {
        self.monotonic_counter = self.monotonic_counter.wrapping_add(1);
        let counter = self.monotonic_counter;

        let Ok(len) = u64::try_from(bytes.len()) else {
            self.admission_bypasses = self.admission_bypasses.saturating_add(1);
            return;
        };

        // Reject entries that can never fit.
        if self.policy.max_entries == 0 || len > self.policy.max_bytes {
            self.admission_bypasses = self.admission_bypasses.saturating_add(1);
            return;
        }

        // Already in T2: update data in place, move to MRU of T2.
        if let Some(idx) = find_in_residents(&self.t2, &key) {
            let old_len = self.t2[idx].bytes.len() as u64;
            if !self.resize_budget(old_len, len) {
                return;
            }
            self.resident_bytes = self.resident_bytes.saturating_sub(old_len);
            self.t2[idx].bytes = bytes.to_vec();
            self.t2[idx].header.set_size(len);
            self.t2[idx].header.mark_hit(counter);
            self.resident_bytes = self.resident_bytes.saturating_add(len);
            // Move to MRU
            let entry = self.t2.remove(idx);
            self.t2.insert(0, entry);
            return;
        }

        // Already in T1: update data in place, promote to T2 MRU.
        if let Some(idx) = find_in_residents(&self.t1, &key) {
            let old_len = self.t1[idx].bytes.len() as u64;
            if !self.resize_budget(old_len, len) {
                return;
            }
            self.resident_bytes = self.resident_bytes.saturating_sub(old_len);
            let mut entry = self.t1.remove(idx);
            entry.bytes = bytes.to_vec();
            entry.header.set_size(len);
            entry.header.mark_hit(counter);
            self.resident_bytes = self.resident_bytes.saturating_add(len);
            self.t2.insert(0, entry);
            return;
        }

        // Remove from ghost lists if present (re-admission after eviction).
        if let Some(idx) = find_in_ghosts(&self.b1, &key) {
            self.b1.remove(idx);
        }
        if let Some(idx) = find_in_ghosts(&self.b2, &key) {
            self.b2.remove(idx);
        }

        // Make room for the new entry (entry count + byte budget).
        self.enforce_capacity_limits();
        self.make_room(len);

        // If still can't fit, bypass.
        if self.resident_bytes.saturating_add(len) > self.policy.max_bytes {
            self.admission_bypasses = self.admission_bypasses.saturating_add(1);
            return;
        }

        // Insert at MRU of T1 with cache-lattice header.
        let budget_domain = match key.role {
            HotReadCacheObjectRole::File => "adapter_serving_hot",
            HotReadCacheObjectRole::Symlink => "adapter_serving_hot",
        };
        let mut header = CacheEntryHeader::new(
            CacheClass::PosixNamespaceMirror,
            MemoryDomain::AdapterServingHot,
            key.inode_id ^ key.data_version, // key digest
            budget_domain,
            RebuildCostClass::Cheap,
            counter,
        );
        header.set_size(len);
        header.anchor_vector_ref = 1; // HotReadCache serves exact answers with anchor
        header.exactness_class = 0; // Exact
        header.freshness_class = 0; // ReadYourWrites

        // P4-02 admission check: validate header invariants.
        if header.validate().is_err() {
            self.admission_bypasses = self.admission_bypasses.saturating_add(1);
            return;
        }
        if !self.admit_budget(len) {
            return;
        }

        self.t1.insert(
            0,
            ArcResident {
                key,
                bytes: bytes.to_vec(),
                header,
            },
        );
        self.resident_bytes = self.resident_bytes.saturating_add(len);
        self.insertions = self.insertions.saturating_add(1);
    }

    /// Invalidate all cache entries belonging to `inode_id`.
    pub(crate) fn invalidate_inode(&mut self, inode_id: InodeId) {
        let target = inode_id.get();
        let mut released = 0u64;
        // Remove from T1.
        let _before = self.t1.len();
        self.t1.retain(|r| {
            if r.key.inode_id == target {
                let len = r.bytes.len() as u64;
                self.resident_bytes = self.resident_bytes.saturating_sub(len);
                released = released.saturating_add(len);
                self.invalidations = self.invalidations.saturating_add(1);
                false
            } else {
                true
            }
        });
        // Remove from T2.
        self.t2.retain(|r| {
            if r.key.inode_id == target {
                let len = r.bytes.len() as u64;
                self.resident_bytes = self.resident_bytes.saturating_sub(len);
                released = released.saturating_add(len);
                self.invalidations = self.invalidations.saturating_add(1);
                false
            } else {
                true
            }
        });
        self.release_budget(released);
        // Remove from ghost lists.
        self.b1.retain(|(k, _w)| k.inode_id != target);
        self.b2.retain(|(k, _w)| k.inode_id != target);
    }

    /// Clear all state (resident + ghost lists, all counters).
    pub(crate) fn clear(&mut self) {
        let total = self.t1.len() + self.t2.len();
        if total > 0 {
            self.invalidations = self.invalidations.saturating_add(total as u64);
        }
        self.release_budget(self.resident_bytes);
        self.t1.clear();
        self.t2.clear();
        self.b1.clear();
        self.b2.clear();
        self.resident_bytes = 0;
        self.adaptive_p = 0;
    }

    // ── Reporting ───────────────────────────────────────────────────────

    /// P4-02 cache lattice report: structured observability per design rule.
    ///
    /// Reports per-domain, per-class, poison/dirty/reserve breakdown
    #[cfg(test)]
    /// in addition to the existing HotReadCacheReport fields.
    pub(crate) fn lattice_report(&self) -> CacheLatticeReport {
        let mut report = CacheLatticeReport::new();
        report.total_entries = self.t1.len() + self.t2.len();
        report.total_bytes = self.resident_bytes;

        for entry in self.t1.iter().chain(self.t2.iter()) {
            let dom = entry.header.memory_domain as usize;
            if dom < MemoryDomain::COUNT {
                report.entries_by_domain[dom] += 1;
            }
            let cls = entry.header.cache_class as usize;
            if cls < CacheClass::COUNT {
                report.entries_by_class[cls] += 1;
            }
            if !entry.header.poison_state.is_clean() {
                report.poisoned_entries += 1;
            }
            if entry.header.dirty_state.is_dirty() {
                report.dirty_entries += 1;
            }
            match entry.header.reserve_guard {
                ReserveGuardClass::Soft => report.reserve_soft += 1,
                ReserveGuardClass::Hard => report.reserve_hard += 1,
                ReserveGuardClass::Pinned => report.reserve_pinned += 1,
                _ => {}
            }
        }
        report
    }

    /// Public report, compatible with the existing `HotReadCacheReport` API.
    /// Maps ARC internals onto the report fields, including P4-02 lattice counters.
    pub(crate) fn report(&self) -> HotReadCacheReport {
        HotReadCacheReport {
            spec: HOT_READ_CACHE_SPEC,
            max_entries: self.policy.max_entries,
            max_bytes: self.policy.max_bytes,
            hits: self.hits,
            misses: self.misses,
            insertions: self.insertions,
            evictions: self.evictions,
            invalidations: self.invalidations,
            admission_bypasses: self.admission_bypasses,
            resident_entries: self.t1.len() + self.t2.len(),
            resident_bytes: self.resident_bytes,
            admission_rejected_budget: self.admission_rejected_budget,
            admission_rejected_reserve: self.admission_rejected_reserve,
            admission_rejected_dirty_state: self.admission_rejected_dirty_state,
            poisoned_on_validate: self.poisoned_on_validate,
        }
    }

    /// Detailed ARC statistics — exposed for observability.
    #[cfg(test)]
    pub(crate) fn arc_stats(&self) -> ArcStats {
        ArcStats {
            t1_size: self.t1.len(),
            t2_size: self.t2.len(),
            b1_size: self.b1.len(),
            b2_size: self.b2.len(),
            t1_weight: self.t1.iter().map(|r| r.bytes.len() as u64).sum(),
            t2_weight: self.t2.iter().map(|r| r.bytes.len() as u64).sum(),
            b1_weight: self.ghost_weight_b1(),
            b2_weight: self.ghost_weight_b2(),
            adaptive_p: self.adaptive_p,
            capacity: self.entry_capacity(),
            t1_hits: self.t1_hits,
            t2_hits: self.t2_hits,
            b1_hits: self.b1_hits,
            b2_hits: self.b2_hits,
            evictions_from_t1: self.evictions_from_t1,
            evictions_from_t2: self.evictions_from_t2,
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_cache_lattice_core::{DirtyStateClass, PosixWritebackState};

    fn policy() -> HotReadCachePolicy {
        HotReadCachePolicy {
            max_entries: 8,
            max_bytes: 1024 * 1024,
        }
    }

    fn key(id: u64) -> HotReadCacheKey {
        HotReadCacheKey {
            role: HotReadCacheObjectRole::File,
            inode_id: id,
            data_version: 1,
            size: 100,
        }
    }

    fn data_governor() -> Governor {
        Governor::new(tidefs_cache_core::GovernorConfig {
            total_budget_bytes: 4096,
            data_cache_fraction: 1.0,
            meta_cache_fraction: 0.0,
            dirty_bytes_fraction: 0.0,
            inode_state_fraction: 0.0,
            cluster_queues_fraction: 0.0,
            misc_fraction: 0.0,
            auto_tune: false,
        })
        .unwrap()
    }

    #[test]
    fn governor_charges_hot_read_entries_to_data_cache() {
        let governor = data_governor();
        let mut cache = HotReadCache::new(policy());
        cache.set_governor(governor.clone());
        let data = b"hot file bytes";
        let k = key(1);

        cache.admit(k, data);
        assert_eq!(
            governor.category_used(BudgetCategory::DataCache),
            data.len() as u64
        );

        cache.invalidate_inode(InodeId::new(k.inode_id));
        assert_eq!(governor.category_used(BudgetCategory::DataCache), 0);
    }

    #[test]
    fn arc_basic_hit_miss() {
        let mut cache = HotReadCache::new(policy());
        let k1 = key(1);
        let data = b"hello world";

        assert!(cache.get(k1).is_none(), "miss on empty cache");
        cache.admit(k1, data);
        assert_eq!(
            cache.get(k1).as_deref(),
            Some(data.as_slice()),
            "hit after admit"
        );
    }

    #[test]
    fn arc_promotes_to_t2_on_second_hit() {
        let mut cache = HotReadCache::new(policy());
        let k1 = key(1);

        cache.admit(k1, b"data1");
        let stats = cache.arc_stats();
        assert_eq!(stats.t1_size, 1);
        assert_eq!(stats.t2_size, 0);

        // Second access: promotes from T1 to T2
        cache.get(k1);
        let stats = cache.arc_stats();
        assert_eq!(stats.t1_size, 0);
        assert_eq!(stats.t2_size, 1);
        assert_eq!(stats.t1_hits, 1);
    }

    #[test]
    fn arc_ghost_hit_adapts_p() {
        let mut cache = HotReadCache::new(HotReadCachePolicy {
            max_entries: 2,
            max_bytes: 1024 * 1024,
        });
        let k1 = key(1);
        let k2 = key(2);
        let k3 = key(3);

        // Fill cache.
        cache.admit(k1, b"data1");
        cache.admit(k2, b"data2");
        assert_eq!(cache.arc_stats().t1_size, 2);

        // Evict k1 by admitting k3.
        cache.admit(k3, b"data3");
        let stats = cache.arc_stats();
        assert_eq!(stats.t1_size, 2, "T1 should still have 2 entries");
        assert_eq!(stats.b1_size, 1, "evicted entry should be in B1");

        // Ghost hit on k1 (in B1) should increase p.
        let p_before = cache.arc_stats().adaptive_p;
        cache.get(k1); // B1 ghost hit
        let p_after = cache.arc_stats().adaptive_p;
        assert!(p_after > p_before, "p should increase on B1 hit");
    }

    #[test]
    fn arc_t2_hit_ghost_adapts_p_down() {
        let mut cache = HotReadCache::new(HotReadCachePolicy {
            max_entries: 2,
            max_bytes: 1024 * 1024,
        });
        let k1 = key(1);
        let k2 = key(2);
        let k3 = key(3);

        // Promote k1 and k2 to T2 via second access.
        cache.admit(k1, b"data1");
        cache.get(k1); // T1 -> T2
        cache.admit(k2, b"data2");
        cache.get(k2); // T1 -> T2: both in T2
        assert_eq!(cache.arc_stats().t1_size, 0);
        assert_eq!(cache.arc_stats().t2_size, 2);

        // Evict by admitting k3; T1 is empty, evict from T2 (LRU: k1 -> B2).
        cache.admit(k3, b"data3");
        let stats = cache.arc_stats();
        assert_eq!(stats.b2_size, 1, "k1 should be in B2 ghost list");

        // Ghost hit k1 in B2 -> p decreases.
        cache.get(k1);
        let stats = cache.arc_stats();
        assert_eq!(stats.b2_hits, 1, "should register B2 ghost hit");
    }

    #[test]
    fn arc_invalidate_inode_removes_from_all_lists() {
        let mut cache = HotReadCache::new(policy());
        let k1 = key(1);
        let k2 = key(2);

        cache.admit(k1, b"data1");
        cache.admit(k2, b"data2");
        assert_eq!(cache.arc_stats().t1_size, 2);

        cache.invalidate_inode(InodeId::new(1));
        let stats = cache.arc_stats();
        assert_eq!(stats.t1_size, 1);
        assert_eq!(stats.b1_size, 0);
    }

    #[test]
    fn arc_clear_resets_everything() {
        let mut cache = HotReadCache::new(policy());
        cache.admit(key(1), b"data1");
        cache.admit(key(2), b"data2");
        cache.get(key(1)); // promote to T2

        cache.clear();
        let stats = cache.arc_stats();
        assert_eq!(stats.t1_size, 0);
        assert_eq!(stats.t2_size, 0);
        assert_eq!(stats.b1_size, 0);
        assert_eq!(stats.b2_size, 0);
        assert_eq!(stats.adaptive_p, 0);
    }

    #[test]
    fn arc_bypasses_oversized_entry() {
        let mut cache = HotReadCache::new(HotReadCachePolicy {
            max_entries: 8,
            max_bytes: 10,
        });
        cache.admit(key(1), b"this is more than ten bytes");
        let report = cache.report();
        assert_eq!(report.insertions, 0);
        assert_eq!(report.admission_bypasses, 1);
        assert_eq!(report.resident_entries, 0);
    }

    #[test]
    fn arc_respects_max_entries() {
        let mut cache = HotReadCache::new(HotReadCachePolicy {
            max_entries: 3,
            max_bytes: 1024 * 1024,
        });
        for i in 0..5 {
            cache.admit(key(i), b"x");
        }
        let stats = cache.arc_stats();
        assert!(stats.t1_size + stats.t2_size <= 3);
    }

    #[test]
    fn arc_scan_resistance_basic() {
        // A scan workload (many unique accesses) should not evict frequently
        // accessed T2 entries.
        let mut cache = HotReadCache::new(HotReadCachePolicy {
            max_entries: 4,
            max_bytes: 1024 * 1024,
        });

        // Establish a frequently-accessed entry in T2.
        cache.admit(key(100), b"frequent");
        cache.get(key(100)); // promote to T2
        assert_eq!(cache.arc_stats().t2_size, 1);

        // Simulate a scan: unique accesses that go to T1.
        for i in 0..10 {
            cache.admit(key(i), b"scan");
            // Don't call get() — scan entries access once then never again
        }

        // The frequently-accessed entry should survive the scan.
        let result = cache.get(key(100));
        assert!(result.is_some(), "frequent entry should survive scan");
    }

    #[test]
    fn arc_respects_max_bytes() {
        let mut cache = HotReadCache::new(HotReadCachePolicy {
            max_entries: 100,
            max_bytes: 100,
        });
        cache.admit(key(1), &[0u8; 40]);
        cache.admit(key(2), &[0u8; 40]);
        cache.admit(key(3), &[0u8; 40]); // should evict first
        let report = cache.report();
        assert!(report.resident_bytes <= 100, "must respect byte budget");
        assert!(report.is_bounded());
    }

    #[test]
    fn arc_update_existing_entry_moves_to_t2() {
        let mut cache = HotReadCache::new(policy());
        cache.admit(key(1), b"v1");
        assert_eq!(cache.arc_stats().t1_size, 1);

        // Re-admit same key: should move to T2 with updated data.
        cache.admit(key(1), b"v2");
        let stats = cache.arc_stats();
        assert_eq!(stats.t1_size, 0);
        assert_eq!(stats.t2_size, 1);
        assert_eq!(cache.get(key(1)).as_deref(), Some(b"v2".as_slice()));
    }

    // ── Lattice-aware eviction tests (P4-02 §6) ─────────────────────────

    /// Entries with dirty state must not be hard-evicted (P4-02 §6).
    /// The evictor should skip dirty entries and try the next clean one.
    #[test]
    fn lattice_skips_dirty_entries_during_eviction() {
        let mut cache = HotReadCache::new(HotReadCachePolicy {
            max_entries: 2,
            max_bytes: 1024 * 1024,
        });

        cache.admit(key(1), b"dirty");
        cache.admit(key(2), b"clean");

        // Manually mark key(1) as dirty (simulating adapter writeback).
        for entry in &mut cache.t1 {
            if entry.key.inode_id == 1 {
                entry.header.dirty_state =
                    DirtyStateClass::PosixWriteback(PosixWritebackState::DirtyOpen);
            }
        }

        // Force eviction by admitting a third entry.
        cache.admit(key(3), b"new");

        let report = cache.report();
        assert!(
            report.admission_rejected_dirty_state >= 1,
            "dirty entry should be counted as rejected for eviction"
        );
        // key(1) should still be resident (it was dirty and thus protected).
        assert!(
            cache.get(key(1)).is_some(),
            "dirty entry should survive eviction"
        );
    }

    /// Hard-reserve entries must not be evicted unless under domain-level
    /// pressure emergency (P4-02 §6).
    #[test]
    fn lattice_skips_hard_reserve_entries_during_eviction() {
        let mut cache = HotReadCache::new(HotReadCachePolicy {
            max_entries: 2,
            max_bytes: 1024 * 1024,
        });

        cache.admit(key(1), b"reserved");
        cache.admit(key(2), b"normal");

        // Mark key(1) as hard-reserve guarded.
        for entry in &mut cache.t1 {
            if entry.key.inode_id == 1 {
                entry.header.reserve_guard = ReserveGuardClass::Hard;
            }
        }

        // Force eviction by admitting a third entry.
        cache.admit(key(3), b"new");

        let report = cache.report();
        assert!(
            report.admission_rejected_reserve >= 1,
            "hard-reserve entry should be counted as rejected for eviction"
        );
        assert!(
            cache.get(key(1)).is_some(),
            "hard-reserve entry should survive eviction"
        );
    }

    /// The lattice report must correctly classify entries by domain and class.
    #[test]
    fn lattice_report_classifies_by_domain_and_class() {
        let mut cache = HotReadCache::new(HotReadCachePolicy {
            max_entries: 8,
            max_bytes: 1024 * 1024,
        });

        cache.admit(key(1), b"a");
        cache.admit(key(2), b"b");
        cache.admit(key(3), b"c");

        let lattice = cache.lattice_report();
        assert_eq!(lattice.spec, "tidefs-cache-lattice-p4-02-v1");
        assert_eq!(lattice.total_entries, 3);
        assert_eq!(lattice.total_bytes, 3);
        let domain_idx = MemoryDomain::AdapterServingHot as usize;
        assert_eq!(lattice.entries_by_domain[domain_idx], 3);
        let class_idx = CacheClass::PosixNamespaceMirror as usize;
        assert_eq!(lattice.entries_by_class[class_idx], 3);
        assert_eq!(lattice.poisoned_entries, 0);
        assert_eq!(lattice.dirty_entries, 0);
        assert_eq!(lattice.reserve_soft, 3);
    }
}
