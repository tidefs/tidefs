// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! ## Authority Classification (per docs/cache-authority-model.md)
//!
//! This inode cache is **Authoritative** for inode metadata caching.  It is a
//! specialized ARC cache for inode records and directory content, not a
//! general-purpose data cache.  It does not hold dirty data.  The canonical
//! cache authority table is at `docs/cache-authority-model.md`.
//!
use std::collections::BTreeMap;

use tidefs_types_vfs_core::InodeId;

use tidefs_types_cache_lattice_core::{
    CacheClass, CacheEntryHeader, CacheLatticeReport, DirtyStateClass, EvictabilityClass,
    MemoryDomain, PoisonState, RebuildCostClass, ReserveGuardClass, ValidityToken,
};

use crate::types::*;

// ── ARC: Adaptive Replacement Cache for inode metadata ─────────────────────
//
// Same ARC algorithm as HotReadCache, applied to CachedInode entries keyed
// by InodeId.  Provides lazy on-demand metadata loading: the filesystem
// can avoid eagerly loading all inode records at mount time and instead
// cache them as they are accessed.  Directory content is cached alongside
// the inode record so that path lookups can resolve from cache without
// a second store read.  Weight-aware: capacity measured in bytes, ghost
// lists carry eviction weights, adaptive p balances by weight.
//
// Four lists in LRU order (index 0 = MRU, last = LRU):
//   T1  – resident entries accessed exactly once recently
//   T2  – resident entries accessed at least twice recently
//   B1  – ghost (inode_id, weight) for entries evicted from T1
//   B2  – ghost (inode_id, weight) for entries evicted from T2

/// A cached inode entry: the inode record and optionally its directory listing.
#[derive(Clone, Debug)]
pub(crate) struct CachedInode {
    pub inode: InodeRecord,
    pub directory: Option<BTreeMap<Vec<u8>, NamespaceEntry>>,
}

#[derive(Clone, Debug)]
struct ArcEntry {
    inode_id: InodeId,
    cached: CachedInode,
    header: CacheEntryHeader,
}

#[derive(Debug)]
pub(crate) struct InodeCache {
    policy: InodeCachePolicy,
    t1: Vec<ArcEntry>,
    t2: Vec<ArcEntry>,
    b1: Vec<(InodeId, u64)>,
    b2: Vec<(InodeId, u64)>,
    adaptive_p: u64,
    resident_bytes: u64,
    hits: u64,
    misses: u64,
    insertions: u64,
    evictions: u64,
    invalidations: u64,
    admission_bypasses: u64,
    t1_hits: u64,
    t2_hits: u64,
    b1_hits: u64,
    b2_hits: u64,
    evictions_from_t1: u64,
    evictions_from_t2: u64,
    #[allow(dead_code)] // INTENT: inode cache types for planned hot-inode lookup acceleration
    admission_rejected_budget: u64,
    admission_rejected_reserve: u64,
    admission_rejected_dirty_state: u64,
    poisoned_on_validate: u64,
    monotonic_counter: u64,
}

fn approx_entry_size(cached: &CachedInode) -> u64 {
    let base: u64 = 128;
    let xattr_bytes: u64 = cached
        .inode
        .xattrs
        .iter()
        .map(|(k, v)| (k.len() + v.len()) as u64)
        .sum();
    let dir_bytes: u64 = cached
        .directory
        .as_ref()
        .map(|d| {
            d.iter()
                .map(|(k, v)| (k.len() + v.name.len() + 48) as u64)
                .sum()
        })
        .unwrap_or(0);
    base + xattr_bytes + dir_bytes
}

impl InodeCache {
    /// Cache authority classification per docs/cache-authority-model.md.
    /// This InodeCache is Authoritative for inode metadata caching.
    #[allow(dead_code)]
    pub(crate) const CACHE_AUTHORITY_CLASS: &str = "Authoritative";
    /// Return the cache authority classification at runtime.
    #[allow(dead_code)]
    pub fn cache_authority_class(&self) -> &'static str {
        Self::CACHE_AUTHORITY_CLASS
    }

    pub(crate) fn new(policy: InodeCachePolicy) -> Self {
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
        }
    }

    fn entry_capacity(&self) -> usize {
        self.policy.max_entries
    }
    fn weight_capacity(&self) -> u64 {
        self.policy.max_bytes
    }
    fn total_ghosts(&self) -> usize {
        self.b1.len() + self.b2.len()
    }
    fn total_resident(&self) -> usize {
        self.t1.len() + self.t2.len()
    }

    fn total_resident_weight(&self) -> u64 {
        self.resident_bytes
    }

    fn ghost_weight_b1(&self) -> u64 {
        self.b1.iter().map(|(_, w)| w).sum()
    }

    fn ghost_weight_b2(&self) -> u64 {
        self.b2.iter().map(|(_, w)| w).sum()
    }

    fn total_ghost_weight(&self) -> u64 {
        self.ghost_weight_b1() + self.ghost_weight_b2()
    }

    fn next_counter(&mut self) -> u64 {
        self.monotonic_counter = self.monotonic_counter.wrapping_add(1);
        self.monotonic_counter
    }

    fn header(&mut self, entry_size_bytes: u64) -> CacheEntryHeader {
        let c = self.next_counter();
        CacheEntryHeader {
            cache_class: CacheClass::PosixNamespaceMirror,
            memory_domain: MemoryDomain::AdapterServingHot,
            entry_key_digest: 0,
            anchor_vector_ref: 0,
            freshness_fence_vector_ref: 0,
            policy_revision_ref: 0,
            budget_domain_buf: [0u8; 64],
            budget_domain_len: 0,
            reserve_guard: ReserveGuardClass::Soft,
            dirty_state: DirtyStateClass::Clean,
            entry_size_bytes,
            birth_counter: c,
            last_hit_counter: c,
            rebuild_cost: RebuildCostClass::Trivial,
            evictability: EvictabilityClass::LruTail,
            poison_state: PoisonState::Clean,
            validation_link_ref: 0,
            exactness_class: 0,
            freshness_class: 0,
            validity_token: ValidityToken::default(),
        }
    }

    fn adapt_p_up(&mut self) {
        let wb1 = self.ghost_weight_b1();
        let wb2 = self.ghost_weight_b2();
        let delta = if wb1 >= wb2 && wb2 > 0 {
            (wb2 / wb1).max(1)
        } else {
            1
        };
        self.adaptive_p = (self.adaptive_p + delta).min(self.weight_capacity());
    }

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

    fn enforce_ghost_cap(&mut self) {
        let limit = 2 * self.weight_capacity();
        while self.total_resident_weight() + self.total_ghost_weight() > limit {
            if self.b1.len() >= self.b2.len() {
                self.b1.pop();
            } else {
                self.b2.pop();
            }
        }
    }

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

    fn evict_one(&mut self) -> Option<u64> {
        if self.total_resident() == 0 {
            return None;
        }
        let evict_from_t1 = !self.t1.is_empty()
            && (self.total_resident_weight() >= self.adaptive_p.max(1) || self.t2.is_empty());
        let evict_from_t1 = evict_from_t1 || (self.t2.is_empty() && !self.t1.is_empty());
        let primary_is_t1 = evict_from_t1;
        if let Some(len) = self.try_evict_from(primary_is_t1) {
            return Some(len);
        }
        self.try_evict_from(!primary_is_t1)
    }

    fn try_evict_from(&mut self, is_t1: bool) -> Option<u64> {
        let list = if is_t1 { &mut self.t1 } else { &mut self.t2 };
        let original_len = list.len();
        for _ in 0..original_len {
            let entry = list.pop()?;
            if entry.header.dirty_state.is_dirty() {
                self.admission_rejected_dirty_state =
                    self.admission_rejected_dirty_state.saturating_add(1);
                list.insert(0, entry);
                continue;
            }
            if matches!(
                entry.header.reserve_guard,
                ReserveGuardClass::Hard | ReserveGuardClass::Pinned
            ) {
                self.admission_rejected_reserve = self.admission_rejected_reserve.saturating_add(1);
                list.insert(0, entry);
                continue;
            }
            let len = approx_entry_size(&entry.cached);
            if is_t1 {
                self.evictions_from_t1 = self.evictions_from_t1.saturating_add(1);
                self.b1.insert(0, (entry.inode_id, len));
            } else {
                self.evictions_from_t2 = self.evictions_from_t2.saturating_add(1);
                self.b2.insert(0, (entry.inode_id, len));
            }
            self.resident_bytes = self.resident_bytes.saturating_sub(len);
            self.evictions = self.evictions.saturating_add(1);
            self.enforce_ghost_cap();
            self.enforce_ghost_entry_cap();
            return Some(len);
        }
        None
    }

    // ── Public API ──────────────────────────────────────────────────────
    #[allow(dead_code)] // INTENT: inode cache types for planned hot-inode lookup acceleration
    pub(crate) fn get(&mut self, inode_id: InodeId) -> Option<CachedInode> {
        let now = self.next_counter();

        if let Some(idx) = self.t1.iter().position(|e| e.inode_id == inode_id) {
            let mut entry = self.t1.remove(idx);
            entry.header.last_hit_counter = now;
            self.t1_hits = self.t1_hits.saturating_add(1);
            self.hits = self.hits.saturating_add(1);
            let cached = entry.cached.clone();
            self.t2.insert(0, entry);
            return Some(cached);
        }

        if let Some(idx) = self.t2.iter().position(|e| e.inode_id == inode_id) {
            let mut entry = self.t2.remove(idx);
            entry.header.last_hit_counter = now;
            self.t2_hits = self.t2_hits.saturating_add(1);
            self.hits = self.hits.saturating_add(1);
            let cached = entry.cached.clone();
            self.t2.insert(0, entry);
            return Some(cached);
        }

        if let Some(idx) = self.b1.iter().position(|(k, _w)| *k == inode_id) {
            self.b1.remove(idx);
            self.b1_hits = self.b1_hits.saturating_add(1);
            self.adapt_p_up();
            self.enforce_ghost_cap();
        }
        if let Some(idx) = self.b2.iter().position(|(k, _w)| *k == inode_id) {
            self.b2.remove(idx);
            self.b2_hits = self.b2_hits.saturating_add(1);
            self.adapt_p_down();
            self.enforce_ghost_cap();
        }

        self.misses = self.misses.saturating_add(1);
        None
    }

    pub(crate) fn insert(&mut self, inode_id: InodeId, cached: CachedInode) {
        let entry_size = approx_entry_size(&cached);

        // Check T1 — promote to T2
        if let Some(idx) = self.t1.iter().position(|e| e.inode_id == inode_id) {
            let old_size = approx_entry_size(&self.t1[idx].cached);
            self.resident_bytes = self.resident_bytes.saturating_sub(old_size);
            self.t1.remove(idx);
            let hdr = self.header(entry_size);
            self.resident_bytes = self.resident_bytes.saturating_add(entry_size);
            self.t2.insert(
                0,
                ArcEntry {
                    inode_id,
                    cached,
                    header: hdr,
                },
            );
            return;
        }

        // Check T2 — update in-place
        if let Some(idx) = self.t2.iter().position(|e| e.inode_id == inode_id) {
            let old_size = approx_entry_size(&self.t2[idx].cached);
            self.resident_bytes = self.resident_bytes.saturating_sub(old_size);
            self.t2.remove(idx);
            let hdr = self.header(entry_size);
            self.resident_bytes = self.resident_bytes.saturating_add(entry_size);
            self.t2.insert(
                0,
                ArcEntry {
                    inode_id,
                    cached,
                    header: hdr,
                },
            );
            return;
        }

        if entry_size > self.policy.max_bytes {
            self.admission_bypasses = self.admission_bypasses.saturating_add(1);
            return;
        }

        while self.total_resident() >= self.entry_capacity() {
            if self.evict_one().is_none() {
                break;
            }
        }

        while self.resident_bytes.saturating_add(entry_size) > self.policy.max_bytes {
            if self.evict_one().is_none() {
                self.admission_bypasses = self.admission_bypasses.saturating_add(1);
                return;
            }
        }

        // Admit to T1 — header is constructed first to avoid borrow conflict
        let hdr = self.header(entry_size);
        self.resident_bytes = self.resident_bytes.saturating_add(entry_size);
        self.t1.insert(
            0,
            ArcEntry {
                inode_id,
                cached,
                header: hdr,
            },
        );
        self.insertions = self.insertions.saturating_add(1);
        self.enforce_ghost_cap();
        self.enforce_ghost_entry_cap();
    }

    pub(crate) fn remove(&mut self, inode_id: InodeId) {
        if let Some(idx) = self.t1.iter().position(|e| e.inode_id == inode_id) {
            let s = approx_entry_size(&self.t1[idx].cached);
            self.resident_bytes = self.resident_bytes.saturating_sub(s);
            self.t1.remove(idx);
            return;
        }
        if let Some(idx) = self.t2.iter().position(|e| e.inode_id == inode_id) {
            let s = approx_entry_size(&self.t2[idx].cached);
            self.resident_bytes = self.resident_bytes.saturating_sub(s);
            self.t2.remove(idx);
            return;
        }
        self.b1.retain(|(k, _w)| *k != inode_id);
        self.b2.retain(|(k, _w)| *k != inode_id);
    }

    pub(crate) fn invalidate(&mut self, inode_id: InodeId) {
        self.invalidations = self.invalidations.saturating_add(1);
        self.remove(inode_id);
    }

    pub(crate) fn clear(&mut self) {
        self.t1.clear();
        self.t2.clear();
        self.b1.clear();
        self.b2.clear();
        self.adaptive_p = 0;
        self.resident_bytes = 0;
    }

    #[allow(dead_code)] // INTENT: inode cache types for planned hot-inode lookup acceleration
    pub(crate) fn report(&self) -> InodeCacheReport {
        let r = self.total_resident();
        InodeCacheReport {
            spec: INODE_CACHE_SPEC,
            max_entries: self.policy.max_entries,
            max_bytes: self.policy.max_bytes,
            hits: self.hits,
            misses: self.misses,
            insertions: self.insertions,
            evictions: self.evictions,
            invalidations: self.invalidations,
            admission_bypasses: self.admission_bypasses,
            resident_entries: r,
            resident_bytes: self.resident_bytes,
            admission_rejected_budget: self.admission_rejected_budget,
            admission_rejected_reserve: self.admission_rejected_reserve,
            admission_rejected_dirty_state: self.admission_rejected_dirty_state,
            poisoned_on_validate: self.poisoned_on_validate,
        }
    }

    #[allow(dead_code)] // INTENT: inode cache types for planned hot-inode lookup acceleration
    pub(crate) fn lattice_report(&self) -> CacheLatticeReport {
        let r = self.total_resident();
        CacheLatticeReport {
            spec: INODE_CACHE_SPEC,
            total_entries: r,
            total_bytes: self.resident_bytes,
            entries_by_domain: {
                let mut a = [0usize; MemoryDomain::COUNT];
                a[MemoryDomain::AdapterServingHot as usize] = r;
                a
            },
            entries_by_class: {
                let mut a = [0usize; CacheClass::COUNT];
                a[CacheClass::PosixNamespaceMirror as usize] = r;
                a
            },
            poisoned_entries: 0,
            dirty_entries: 0,
            reserve_soft: r,
            reserve_hard: 0,
            reserve_pinned: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InodeCachePolicy {
    pub max_entries: usize,
    pub max_bytes: u64,
}

impl Default for InodeCachePolicy {
    fn default() -> Self {
        Self {
            max_entries: crate::constants::DEFAULT_INODE_CACHE_MAX_ENTRIES,
            max_bytes: crate::constants::DEFAULT_INODE_CACHE_MAX_BYTES,
        }
    }
}

pub(crate) const INODE_CACHE_SPEC: &str = "publishing checklist item PC-009 inode cache: LocalFileSystem uses a bounded, non-authoritative, inode-id keyed ARC cache that accelerates inode record lookups without becoming publication, recovery, or allocator truth";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InodeCacheReport {
    pub spec: &'static str,
    pub max_entries: usize,
    pub max_bytes: u64,
    pub hits: u64,
    pub misses: u64,
    pub insertions: u64,
    pub evictions: u64,
    pub invalidations: u64,
    pub admission_bypasses: u64,
    pub resident_entries: usize,
    pub resident_bytes: u64,
    pub admission_rejected_budget: u64,
    pub admission_rejected_reserve: u64,
    pub admission_rejected_dirty_state: u64,
    pub poisoned_on_validate: u64,
}

impl InodeCacheReport {
    #[allow(dead_code)] // INTENT: inode cache types for planned hot-inode lookup acceleration
    pub(crate) fn is_bounded(&self) -> bool {
        self.resident_entries <= self.max_entries && self.resident_bytes <= self.max_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_vfs_core::{Generation, NodeKind};

    fn cached(id: u64) -> CachedInode {
        CachedInode {
            inode: InodeRecord {
                rdev: 0,
                inode_id: InodeId::new(id),
                generation: Generation::new(1),
                facets: NodeKind::File.to_facets(),
                mode: 0o644,
                uid: 1000,
                gid: 1000,
                nlink: 1,
                size: 4096,
                data_version: 1,
                metadata_version: 1,
                posix_time: crate::types::PosixTimeRecord::now(),
                xattrs: BTreeMap::new(),
                dir_storage_kind: 0,
                xattr_storage_kind: 0,
                dir_rev: 0,
                subtree_rev: 0,
            },
            directory: None,
        }
    }

    fn policy() -> InodeCachePolicy {
        InodeCachePolicy {
            max_entries: 16,
            max_bytes: 1024 * 1024,
        }
    }

    #[test]
    fn basic_hit_miss() {
        let mut cache = InodeCache::new(policy());
        let id = InodeId::new(1);
        assert!(cache.get(id).is_none());
        cache.insert(id, cached(1));
        assert!(cache.get(id).is_some());
    }

    #[test]
    fn promotes_to_t2() {
        let mut cache = InodeCache::new(policy());
        let id = InodeId::new(1);
        cache.insert(id, cached(1));
        assert_eq!(cache.t1.len(), 1);
        cache.get(id);
        assert_eq!(cache.t1.len(), 0);
        assert_eq!(cache.t2.len(), 1);
    }

    #[test]
    fn respects_max_entries() {
        let mut cache = InodeCache::new(InodeCachePolicy {
            max_entries: 3,
            max_bytes: 1024 * 1024,
        });
        for i in 0..5 {
            cache.insert(InodeId::new(i), cached(i));
        }
        assert!(cache.total_resident() <= 3);
    }

    #[test]
    fn remove_clears() {
        let mut cache = InodeCache::new(policy());
        let id = InodeId::new(1);
        cache.insert(id, cached(1));
        cache.get(id);
        cache.remove(id);
        assert!(cache.get(id).is_none());
    }

    #[test]
    fn invalidate_counter() {
        let mut cache = InodeCache::new(policy());
        cache.insert(InodeId::new(1), cached(1));
        cache.invalidate(InodeId::new(1));
        assert_eq!(cache.report().invalidations, 1);
    }

    #[test]
    fn arc_ghost_hit_adapts_p_by_weight() {
        let mut cache = InodeCache::new(InodeCachePolicy {
            max_entries: 2,
            max_bytes: 1024 * 1024,
        });
        let k1 = InodeId::new(1);
        let k2 = InodeId::new(2);
        let k3 = InodeId::new(3);

        cache.insert(k1, cached(1));
        cache.insert(k2, cached(2));
        assert_eq!(cache.t1.len(), 2);

        // Evict k1 by inserting k3.
        cache.insert(k3, cached(3));
        assert!(
            cache.b1.iter().any(|(k, _w)| *k == k1),
            "k1 should be in B1"
        );

        // Ghost hit on k1 should increase p.
        let p_before = cache.adaptive_p;
        cache.get(k1); // B1 ghost hit
        assert!(cache.adaptive_p > p_before, "p should increase on B1 hit");
    }

    #[test]
    fn weight_capacity_evicts_by_bytes() {
        let mut cache = InodeCache::new(InodeCachePolicy {
            max_entries: 100,
            max_bytes: 200,
        });
        cache.insert(InodeId::new(1), cached(1));
        cache.insert(InodeId::new(2), cached(2));
        cache.insert(InodeId::new(3), cached(3));
        let report = cache.report();
        assert!(report.resident_bytes <= 200, "must respect byte budget");
        assert!(report.is_bounded());
    }
}
