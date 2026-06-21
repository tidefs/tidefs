# Weighted ARC Cache with Per-Entry Weight Tracking — Design Specification

**Issue**: [#1192](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1192)
**Status**: design-spec
**Priority**: P2
**Lane**: storage-core
**Depends on**: #1097 (P4-02 cache taxonomy runtime)
**Related**: #1176 (cache-lattice views), #827 (structural observability), #1111 (memory pressure/reclaim), #1256 (FlashTier/cache device tiering), #1237 (resource governor)

## Abstract

The Adaptive Replacement Cache (ARC) algorithm by Megiddo & Modha balances recency
and frequency as a design answer to plain LRU's recency bias. This is an
algorithmic input, not a TideFS product benchmark claim. The original entry-count
ARC treats every entry identically: a 1 MiB data chunk and a 128-byte inode record
each consume one "slot." This design extends ARC with per-entry weight (byte-count)
tracking so capacity is measured in weight units — typically bytes — not entry
count. Ghost lists carry evicted-entry weights, the adaptive target `p` balances
the T1/T2 split by weight, and P4-02 cache lattice headers provide mandatory
classification and lifecycle law on every resident entry.

The weighted ARC is implemented in two concrete caches within
`tidefs-local-filesystem`:

- **HotReadCache** (`hot_read_cache.rs`): content chunks keyed by
  `(role, inode_id, data_version, size)`; weight is `bytes.len()`.
- **InodeCache** (`inode_cache.rs`): inode records with optional directory
  listings keyed by `InodeId`; weight is an approximate entry size computed
  from inode fields, xattrs, and directory entries.

Both caches share the same ARC algorithm structure but differ in their key
types, weight functions, and admission policies. The P4-02 lattice
integration gives every resident entry a `CacheEntryHeader` with 18
mandatory fields covering memory domain, cache class, dirty state, reserve
guard, poison state, exactness/freshness classification, and rebuild cost.

```
┌──────────────────────────────────────────────────────┐
│                   Weighted ARC                        │
│                                                       │
│  Resident lists (carry data + header)                 │
│   T1: [MRU ... LRU]   exactly 1 hit recently          │
│   T2: [MRU ... LRU]   ≥ 2 hits recently               │
│                                                       │
│  Ghost lists (carry key + eviction weight only)       │
│   B1: [MRU ... LRU]   evicted from T1                 │
│   B2: [MRU ... LRU]   evicted from T2                 │
│                                                       │
│  Invariants:                                          │
│   weight(T1) + weight(T2)          ≤ C (byte budget)  │
│   |T1| + |T2|                      ≤ max_entries       │
│   weight(T1)+weight(T2)+weight(B1)+weight(B2) ≤ 2C    │
│   |B1| + |B2|                      ≤ 2·max_entries    │
│                                                       │
│  Adaptive target p ∈ [0, C]:                         │
│   Ghost hit in B1 → p += ⌈weight(B2)/weight(B1)⌉     │
│   Ghost hit in B2 → p -= ⌈weight(B1)/weight(B2)⌉     │
└──────────────────────────────────────────────────────┘
```

---

## 1. Core Algorithm

### 1.1 Lists and Ordering

The ARC maintains four LRU-ordered lists. Index 0 is the most-recently-used
(MRU) position; the last index is the least-recently-used (LRU) tail:

| List | Contents | Stored weight | Purpose |
|------|----------|---------------|---------|
| T1 | Resident entries: key, value, header | `bytes.len()` per entry | Accessed exactly once recently |
| T2 | Resident entries: key, value, header | `bytes.len()` per entry | Accessed ≥ 2 times recently |
| B1 | Ghost entries: key only | eviction weight | Metadata for entries evicted from T1 |
| B2 | Ghost entries: key only | eviction weight | Metadata for entries evicted from T2 |

### 1.2 Capacity Model

Capacity is dual-bounded:

```rust
struct CachePolicy {
    max_entries: usize,  // entry-count safety cap (prevents tiny-entry flood)
    max_bytes:   u64,    // byte budget (primary capacity measure)
}
```

The byte budget is the authoritative capacity limit. The entry-count cap is a
safety bound that prevents pathological cases where floods of tiny entries
consume all slots (e.g., empty files, small symlinks). Both limits are
enforced simultaneously.

### 1.3 Invariants

1. **Resident weight cap**: `weight(T1) + weight(T2) ≤ max_bytes`
2. **Resident entry cap**: `|T1| + |T2| ≤ max_entries`
3. **Total weight cap**: `weight(T1) + weight(T2) + weight(B1) + weight(B2) ≤ 2·max_bytes`
4. **Total ghost entry cap**: `|B1| + |B2| ≤ 2·max_entries`
5. **Adaptive target**: `0 ≤ p ≤ max_bytes`

Invariants 3 and 4 are enforced after every ghost-list insertion by evicting
the LRU tail of the larger ghost list until within bounds.

### 1.4 Adaptive Target `p`

The adaptive target `p` balances the T1/T2 weight split. It is increased on
B1 ghost hits (recency bias was too weak) and decreased on B2 ghost hits
(frequency bias was too weak). The adjustment is proportional to the weight
ratio of the opposite ghost list:

```python
# B1 ghost hit — increase p (favor T1 / recency)
delta = max(1, weight(B2) / weight(B1))
p = min(C, p + delta)

# B2 ghost hit — decrease p (favor T2 / frequency)
delta = max(1, weight(B1) / weight(B2))
p = max(0, p - delta)
```

With unit weights, this reduces to the classic ARC adaptation formula using
cardinality ratios.

### 1.5 Operations

#### get(key)

```
1. if key in T2:
     move entry to T2 MRU
     return hit (value)
2. if key in T1:
     move entry from T1 → T2 MRU (promotion)
     return hit (value)
3. if key in B1:
     ghost hit → adapt p up; remove from B1
     return miss
4. if key in B2:
     ghost hit → adapt p down; remove from B2
     return miss
5. return complete miss
```

#### admit(key, value)

```
1. if key in T2: update value in place, move to T2 MRU; return
2. if key in T1: update value, promote from T1 → T2 MRU; return
3. if key in B1 or B2: remove from ghost list
4. make room for value.len() bytes:
     enforce_capacity_limits(); make_room(needed_bytes)
5. if resident_bytes + len > max_bytes: admission_bypass; return
7. insert at T1 MRU
```

#### replace (eviction)

When resident weight exceeds the byte budget (or entry count exceeds the
entry cap), the ARC evicts one entry:

```
1. decide which list to evict from:
   if weight(T1) > 0 and (weight(T1) > p or (key in B2 and weight(T1) == p)):
     evict from T1
   else:
     evict from T2
2. scan from LRU tail toward MRU:
   skip dirty entries (P4-02: must drain via writeback)
   skip hard/pinned reserve entries (P4-02)
3. evict first eligible entry:
   move key + eviction weight → ghost list (B1 or B2)
   deduct weight from resident_bytes
   enforce ghost caps
```

The two-phase eviction fallback handles the case where the primary list is
fully protected (all entries dirty or hard-reserved). In that case, the
evictor tries the secondary list. If both lists are fully protected,
eviction halts and admission may be bypassed.

### 1.6 Determinism

The algorithm is fully deterministic:
- No random number generation — all decisions are based on explicit state.
- LRU ordering via `Vec` with index-0 = MRU convention.
- All operations are single-threaded and reproducible.
- Suitable for deterministic simulation and trace replay.

---

## 2. P4-02 Cache Lattice Integration

### 2.1 Entry Header

Every resident entry carries a `CacheEntryHeader` with 18 mandatory fields
defined in `tidefs-types-cache-lattice-core`:

```rust
pub struct CacheEntryHeader {
    pub cache_class:         CacheClass,        // PosixNamespaceMirror, etc.
    pub memory_domain:       MemoryDomain,      // AdapterServingHot, etc.
    pub entry_key_digest:    u64,               // key hash for indexing
    pub anchor_vector_ref:   u64,               // validity token reference
    pub freshness_fence_vector_ref: u64,
    pub policy_revision_ref: u64,
    pub budget_domain_buf:   [u8; 64],          // ASCII budget domain name
    pub budget_domain_len:   u8,
    pub reserve_guard:       ReserveGuardClass, // Soft, Hard, Pinned
    pub dirty_state:         DirtyStateClass,   // Clean, PosixWriteback, etc.
    pub entry_size_bytes:    u64,
    pub birth_counter:       u64,               // monotonic insert time
    pub last_hit_counter:    u64,               // monotonic last access
    pub rebuild_cost:        RebuildCostClass,  // Cheap, Trivial, Expensive, etc.
    pub evictability:        EvictabilityClass, // LruTail, HardReserve, PinnedDma, etc.
    pub poison_state:        PoisonState,       // Clean, Poisoned
    pub exactness_class:     u8,                // 0 = exact
    pub freshness_class:     u8,                // 0 = ReadYourWrites
}
```

### 2.2 Eviction Law (P4-02 §6)

The eviction law protects entries that cannot be safely discarded:

- **Dirty entries**: Must drain through writeback, not hard-evict. The
  evictor skips them and reports `admission_rejected_dirty_state`.
- **Hard/Pinned reserve entries**: Protected from eviction unless domain-level
  pressure emergency. Reported via `admission_rejected_reserve`.
  cache on next eviction pass.



### 2.4 Observability

Each cache exposes:

- **ARCStats** (internal): T1/T2/B1/B2 sizes and weights, adaptive `p`,
  per-list hits/evictions.
- **CacheReport** (public): hits, misses, insertions, evictions,
  rejection counters.
- **CacheLatticeReport** (P4-02): per-domain entry counts, per-class
  entry counts, dirty/poisoned/reserve breakdown.

---

## 3. Concrete Cache Implementations

### 3.1 HotReadCache

**Location**: `crates/tidefs-local-filesystem/src/hot_read_cache.rs`

**Key**: `HotReadCacheKey { role, inode_id, data_version, size }`

The `data_version` component provides staleness safety: when a file is
written, its `data_version` increments, causing old cache entries to
become unreachable. The `size` field co-keys entries so that different
byte ranges of the same file version map to distinct cache slots.

**Weight function**: `bytes.len()` — raw byte count.

**Weight example**: A 64 KiB chunk weighs 65,536; a 128-byte symlink target
weighs 128. The 64 KiB chunk consumes 512× the budget of the symlink.

**Cache class**: `CacheClass::PosixNamespaceMirror`

**Memory domain**: `MemoryDomain::AdapterServingHot`

**Capacity defaults**:
- `DEFAULT_HOT_READ_CACHE_MAX_ENTRIES`: 64
- `DEFAULT_HOT_READ_CACHE_MAX_BYTES`: 256 KiB

**Operations**: `get(key) -> Option<Vec<u8>>`, `admit(key, bytes)`,
`lattice_report()`.

### 3.2 InodeCache

**Location**: `crates/tidefs-local-filesystem/src/inode_cache.rs`

**Key**: `InodeId` — the inode identifier.

**Weight function**: `approx_entry_size(cached)` which sums:
- Base: 128 bytes
- Xattr overhead: sum of `k.len() + v.len()` for each xattr
- Directory overhead: sum of `k.len() + v.name.len() + 48` for each
  directory entry (when directory listing is cached)

**Weight example**: A minimal inode with no xattrs weighs 128; an inode
with 5 xattrs averaging 64 bytes each weighs ~768; an inode with a 1000-entry
directory weighs ~50,000+.

**Cache class**: `CacheClass::PosixNamespaceMirror`

**Memory domain**: `MemoryDomain::AdapterServingHot`

**Capacity defaults**:
- `DEFAULT_INODE_CACHE_MAX_ENTRIES`: 1,024
- `DEFAULT_INODE_CACHE_MAX_BYTES`: 16 MiB

**Operations**: `get(inode_id) -> Option<CachedInode>`,
`clear()`, `report()`, `lattice_report()`.

### 3.3 CachedInode Structure

```rust
pub(crate) struct CachedInode {
    pub inode: InodeRecord,
    pub directory: Option<BTreeMap<Vec<u8>, NamespaceEntry>>,
}
```

Directory listings are cached alongside the inode so path lookups can
resolve from cache without a second store read. When the directory
component is present, the weight function includes directory overhead.

---

## 4. Staleness Discipline

### 4.1 Generation/Root-Insertion Keying

Every cache key includes a version component that changes across reuse
boundaries, preventing stale hits:

| Cache | Key version component | Source |
|-------|----------------------|--------|
| HotReadCache | `data_version` | `InodeRecord.data_version` — increments on write |

For HotReadCache, the `data_version` in the key means old versions are
purging the stale entry from all four lists.

### 4.2 Extended Staleness (Future)

Per the design book's cacheable-objects stack, future caches will include
generation-bearing keys:

- **Record cache**: `(segment_index, segment_generation, record_offset)`
  where segment generation comes from the segment header's `segment_seq`.
- **B+tree node cache**: `(tree_root_ptr, node_ptr)` where `root_ptr` changes
  on any tree structural modification.
- **Extent map cache v2**: `(extent_map_root_ptr, locator_root_ptr)` where
  both roots change on write.

---

## 5. Relationship to P4-02 Cache Lattice Views (#1176)

The weighted ARC provides the eviction substrate for cache-lattice views.
Views (#1176) layer on top of the existing `CacheEntryHeader` infrastructure:

- **View budget enforcement**: A view's byte cost (`ViewBuildCost`) maps to
  the entry's `entry_size_bytes`, flowing through the ARC's weight-aware
  eviction. Expensive-to-rebuild views have higher `RebuildCostClass` values,
  giving them natural eviction protection.
- **View completeness contracts**: The `exactness_class` and `freshness_class`
  fields in `CacheEntryHeader` carry view completeness metadata. Incomplete
  views may be evicted more aggressively.
- **View tombstones**: When a view is evicted, a tombstone record (key +
  weight) enters the ghost list. Ghost hits signal that the evicted view was
  needed again, adapting `p` to retain more entries of that recency/frequency
  class.

---

## 6. Relationship to Memory Pressure (#1111)

The weight-aware ARC is the primary low-level pressure response mechanism:

1. **Byte budget**: The `max_bytes` configuration is the pressure knob.
   When system memory is tight, the resource governor (#1237) can reduce
   `max_bytes` for non-essential caches.
2. **Weight-proportional eviction**: Large entries are preferentially
   evicted because evicting one 1 MiB entry frees as much budget as
   evicting 8,192 128-byte entries.
3. **Two-phase capacity enforcement**: Entry count is enforced after byte
   budget, preventing tiny-entry floods during low-memory scenarios.

---

## 7. Performance Characteristics

### 7.1 Time Complexity

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| `get()` | O(n) | Linear scan of resident and ghost lists |
| `admit()` | O(n + e) | n = list size, e = evictions in `make_room` |
| `evict_one()` | O(n) | Rotates past protected entries |
| `report()` | O(1) | Counter reads only |
| `arc_stats()` | O(n) | Iterates resident lists for weight sums |

### 7.2 Space Overhead

- **Resident entry overhead**: `sizeof(HotReadCacheKey) + sizeof(CacheEntryHeader)` ≈ 120 bytes per entry plus the value bytes.
- **Ghost entry overhead**: `sizeof(key) + sizeof(u64)` ≈ 44 bytes per ghost entry.
- **Total overhead cap**: At most `2·max_entries` ghost entries plus `max_entries` resident entries.

### 7.3 Scan Resistance

ARC's adaptive `p` provides natural scan resistance:
- A sequential scan populates T1 with single-access entries.
- When the scan exceeds `p` weight units, eviction shifts from T1 to T2.
- Frequently-accessed T2 entries survive the scan.
- Ghost hits from evicted scan entries (in B1) increase `p`, making future
  scans more T1-biased — but the adjustment is bounded and self-correcting.

---

## 8. Configuration and Tuning

### 8.1 Policy Knobs

```rust
pub struct HotReadCachePolicy {
    pub max_entries: usize,  // entry-count safety cap
    pub max_bytes: u64,      // byte budget
}

pub struct InodeCachePolicy {
    pub max_entries: usize,
    pub max_bytes: u64,
}
```

### 8.2 Defaults

| Cache | `max_entries` | `max_bytes` | Rationale |
|-------|--------------|-------------|-----------|
| HotReadCache | 64 | 256 KiB | Small working set assumption; most reads are streaming |
| InodeCache | 1,024 | 16 MiB | Inodes are small but numerous; cache hit reduces store reads |

### 8.3 Tuning Guidance

- **Increase `max_bytes`** when the working set fits comfortably in RAM and
  cache hit rates are below 90%. The ARC adapts automatically — larger
  capacity means longer adaptation cycles but better steady-state hit rates.
- **Decrease `max_bytes`** under memory pressure. The two-phase enforcement
  (byte budget first, entry count second) ensures evicted entries are the
  weight-proportional LRU tails.
- **Increase `max_entries`** when the workload includes many tiny entries
  (empty files, small symlinks) that collectively weigh less than the byte
  budget. Without a sufficient entry cap, the ARC may retain few entries
  dominated by a single large one.
- **Balance `max_entries` and `max_bytes`** so that `max_bytes / max_entries`
  approximates the median entry size. For HotReadCache at defaults: 4 KiB
  median (actual chunk size may vary).

### 8.4 Runtime Observability

Cache reports are accessible via the `FileSystemStats` or direct report
access:

```
HotReadCacheReport {
    max_entries: 64, max_bytes: 262144,
    hits: 15234, misses: 891,
    insertions: 1203, evictions: 312,
    resident_entries: 64, resident_bytes: 241664,
    admission_rejected_budget: 0,
    admission_rejected_reserve: 0,
    admission_rejected_dirty_state: 0,
}
```

The `resident_bytes / max_bytes` ratio indicates cache pressure;
`hits / (hits + misses)` is the hit rate.

---

## 9. Future Work

### 9.1 Generic WeightedArcCache<T> Abstraction

Currently, HotReadCache and InodeCache duplicate the ARC algorithm. A future
refactor (#1226) should extract a `WeightedArcCache<K, V, W>` where
`W: Fn(&V) -> u64` is the weight function. This would:

- Eliminate algorithm duplication between the two caches.
- Enable new ARC-based caches (B+tree node cache, extent map cache,
  directory page cache) with minimal code.
- Provide a shared test suite for ARC correctness.

### 9.2 Index-Based LRU for O(1) Operations

The current `Vec`-based implementation uses O(n) linear scans. An
index-based doubly-linked list (using `slab` or `slotmap`) would reduce
`get()` and eviction operations to O(1), enabling larger cache sizes
without linear-scan overhead. The design book's Python reference uses
`OrderedDict` for O(1) operations; Rust can achieve equivalent
performance with index-based links.

### 9.3 Segmented Ghost Lists

Ghost lists currently carry only key + weight. For ghost-hit admission
optimization (#1176 cache-lattice views), ghost entries could also carry

### 9.4 NUMA-Aware Sharding

For multi-socket systems, the ARC could be sharded by key hash into
per-NUMA-node partitions, with independent T1/T2/B1/B2 lists and
adaptive `p` values. This avoids cross-socket contention on cache
operations from parallel FUSE threads.

---

## 10. References

- Megiddo & Modha, "ARC: A Self-Tuning, Low Overhead Replacement Cache",
  FAST 2003.
- tidefs v0.262 Python design: `arc.py` (390 lines), design book §IX
  "Caching and performance modeling".
- tidefs P4-02 cache lattice: `tidefs-types-cache-lattice-core/src/lib.rs`.
- Cache lattice views design: `docs/design/cache-lattice-views.md` (#1176).
- Cache device tiering design: `docs/design/cache-device-tiering-flash_tier-writeback.md` (#1256).
- Memory pressure reclaim: #1111.
- Resource governor design: #1237.

---

## 11. Test Coverage


- **Correctness**: basic hit/miss, promotion from T1→T2, ghost-hit adaptation
- **Eviction**: respects `max_bytes`, respects `max_entries`, boundary
  conditions
- **Lattice protection**: skips dirty entries, skips hard-reserve entries,
  reports rejection counts
- **Lattice reporting**: correctly classifies entries by domain and class
- **Capacity enforcement**: `is_bounded()` returns true after operations
- **ARC behavior**: frequent-entry survives scan, ghost-hit adapts `p`,
  weight-capacity evicts by bytes
