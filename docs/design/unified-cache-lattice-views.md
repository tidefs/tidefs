# Unified Cache-Lattice Views — Architecture Design

**Issue**: [#1977](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1977), [#1939](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1939), [#1909](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1909), [#1819](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1819)
**Coord**: [#1988](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1988), [#1819](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1819)
**Status**: sealed
**Maturity**: **design-sealed** — design spec authenticated as the single authoritative reference for the unified cache-lattice views architecture; Rust implementation deferred to wire-up issues (#1909)
**Lane**: storage-core
**Kind**: design
**Depends on**: P4-02 cache taxonomy (#1097), tidefs-types-cache-lattice-core, tidefs-cache-core
**Builds on**: `docs/design/cache-lattice-views.md` (#1176 — views-as-cached-answers),
  `docs/design/unified-cache-lattice-views.md` (#1691 — earlier iteration, superseded by #1909)

## Coordination Seal (#1988)

This document is the canonical design specification for the Unified
Cache-Lattice Views architecture. It supersedes the earlier iterations
in #1176 (`docs/design/cache-lattice-views.md`) and #1691 (earlier
`docs/design/unified-cache-lattice-views.md`).

**Seal statement**: The three-layer cache-lattice architecture
(`tidefs-types-cache-lattice-core` no_std authority types,
`tidefs-cache-core` shared runtime, and concrete cache implementations
consuming the runtime), the 5 canonical view types (directory listing,
hierarchy manifest, path lookup, missing-path, missing-names) with
`ViewMeta`, `ViewBuildCost`, `ValidityToken`, and per-class refresh logic,
the unified pressure-response pipeline integrating view eviction with
content-cache reclaim under P4-03 pressure stages, the 10 inviolable
rules, and the observability contract (`CacheLatticeReport` per-class
per-domain counters, `CacheLatticeRegistry` system-wide aggregation) are
frozen. No further design changes are permitted. Rust implementation of
individual view types, the runtime view builder, and concrete cache
wire-up is deferred to wire-up issues (#1909), which extend this
specification with implementation details only.

The authority of this document is established by its acceptance as the
single source of truth for cache-lattice views in the TideFS storage
stack. All future implementation issues reference this specification.

## Abstract

The tidefs cache lattice combines two concerns that are currently designed in
separate documents: (1) the **unified architecture** of three cache-lattice
layers — a `no_std` authority type crate, a shared runtime crate, and concrete
cache implementations — and (2) the **view abstraction** that treats cached
answers as precomputed query results with explicit completeness contracts,
build-cost attribution, and a single refresh mechanism.

This document specifies the **merged, authoritative design** for the cache
lattice in tidefs. It covers:

- The single-source-of-truth type system in `tidefs-types-cache-lattice-core`
  (8 memory domains, 9 cache classes, 18-field entry header, 3 dirty-state

- The mandatory runtime layer in `tidefs-cache-core` providing shared admission
  machines, poison management, and observability emitters.

- The **cache-lattice view** abstraction: 5 canonical view types (directory
  listing, hierarchy manifest, path lookup, missing-path, missing-names) with
  `ViewMeta`, `ViewBuildCost`, `ValidityToken`, and per-class refresh logic.

- The unified pressure-response pipeline that integrates view eviction with
  content-cache reclaim under P4-03 pressure stage discipline.

- Concrete cache implementations (`HotReadCache`, `InodeCache`) that consume
  eviction by hand.

- Observability integration: per-class, per-domain counters emitted via
  `CacheLatticeReport` and aggregated by a system-wide `CacheLatticeRegistry`.

---

## 1. Current State Audit

### 1.1 What exists today

```
┌──────────────────────────────────────────────────────────────────┐
│  tidefs-types-cache-lattice-core (no_std)                       │
│  CacheClass (9 variants), MemoryDomain (8 variants),            │
│  CacheEntryHeader (18 fields), DirtyStateClass (3 machines),   │
│  PoisonState, ReserveGuardClass, EvictabilityClass,             │
│  RebuildCostClass, AdmissionResult, CacheLatticeReport,         │
│  PosixWritebackState, BlockFlushState, PublicationPayloadState │
│  USED BY: tidefs-cache-core, hot_read_cache, inode_cache,       │
│          tidefs-types-zero-copy-pin-core                        │
├──────────────────────────────────────────────────────────────────┤
│  tidefs-cache-core (runtime)                                    │
│  classify_memory_domain, admit_cache_entry_under_budget_and_fence│
│  advance_posix_writeback, advance_block_flush,                  │
│  advance_publication_payload, complete_posix_writeback,         │
│  drain_page_loans_and_pins_for_cutover_or_failover,             │
│  CacheObservabilityEmitter, build_report                        │
│  USED BY: (nothing yet — underutilized)                          │
├──────────────────────────────────────────────────────────────────┤
│  tidefs-local-filesystem (concrete caches)                      │
│  hot_read_cache.rs — ARC content cache                          │
│    - imports types from tidefs-types-cache-lattice-core          │
│  inode_cache.rs — ARC inode metadata cache                      │
│    - imports types from tidefs-types-cache-lattice-core          │
└──────────────────────────────────────────────────────────────────┘
```

### 1.2 Changes since #1562

The orphaned duplicate module `crates/tidefs-local-filesystem/src/cache_lattice.rs`
(1150 lines of duplicate type definitions) has been **removed**. Both
`hot_read_cache.rs` and `inode_cache.rs` now import directly from
`tidefs-types-cache-lattice-core`. This resolves the duplicate-type-system
problem identified in the original audit.

### 1.3 Remaining gaps

1. **Underutilized runtime**: `tidefs-cache-core` is fully implemented with
   but `hot_read_cache.rs` and `inode_cache.rs` still implement these concerns
   locally rather than delegating.

2. **No shared pressure response**: each cache runs its own pressure response
   logic without coordination or P4-03 stage discipline.

3. **No views**: the view abstraction from #1176 (5 canonical view types with
   `ViewMeta`, `ViewBuildCost`, `ValidityToken`) is specified but not
   implemented in crate types. The view types are slotted into the existing
   `CacheEntryHeader` fields as described in §5.6 — no schema changes
   needed. The `ViewCache` (§6.3) and view-aware admission path (§5.7)
   remain unimplemented, deferred to wire-up issues under #1909.

4. **No registry**: there is no system-wide `CacheLatticeRegistry` that
   aggregates per-cache counters or coordinates pressure response across all
   caches.

---

## 2. Architecture Overview

### 2.1 Three-layer design

```
┌──────────────────────────────────────────────────────────────────┐
│ LAYER 1: tidefs-types-cache-lattice-core (no_std)               │
│                                                                  │
│ • All cache-lattice types: CacheClass, MemoryDomain,             │
│   CacheEntryHeader, DirtyStateClass, PoisonState, etc.           │
│ • 15 type-level invariants enforced at construction              │
│ • No allocation, no I/O, no runtime dependencies                 │
│ • Single source of truth — no crate or module may define         │
│   parallel or equivalent enums                                   │
├──────────────────────────────────────────────────────────────────┤
│ LAYER 2: tidefs-cache-core (runtime)                            │
│                                                                  │
│ • Admission gates: budget, reserve-floor, dirty-legality,        │
│   anchor/fence-vector checks                                     │
│   freshness-bound comparison                                     │
│ • Eviction/compaction planners: pressure-aware, reclaim-         │
│   priority ordered, dirty-entry aware                            │
│ • Dirty-state machines: POSIX writeback, block flush,            │
│   publication payload — each with legal transition maps          │
│ • Loan/pin drain: cutover and failover helpers                   │
│ • Observability: CacheObservabilityEmitter → CacheLatticeReport  │
│   with per-class, per-domain breakdown                           │
│ • Pressure response: P4-03 stage discipline, ordered eviction    │
│   plans across all registered caches                             │
├──────────────────────────────────────────────────────────────────┤
│ LAYER 3: Concrete cache implementations                         │
│                                                                  │
│ • HotReadCache: ARC-based data content cache                     │
│   - Adds chunk-specific indexing (object_key, offset, length)    │
│ • InodeCache: ARC-based inode metadata cache                     │
│   - Adds inode-specific indexing (inode_id, generation)          │
│ • ViewCache (future): lattice-view cache for 5 view types        │
│   - Consumes Layer 2 for all lifecycle operations                │
│   - Adds ViewMeta, ValidityToken, per-view-class refresh         │
│ • Additional caches (future): block-volume mapping queues,       │
│   authority mirrors, product caches, observe caches              │
└──────────────────────────────────────────────────────────────────┘
```

### 2.2 Design principles

1. **Single type authority**: `tidefs-types-cache-lattice-core` is the only
   source of truth for cache-lattice types. No code outside this crate may
   define equivalent enums or structs.

2. **Mandatory runtime delegation**: every cache implementation MUST delegate
   dirty-state transitions. Caches may not reimplement these.

3. **Explicit contracts**: every cache entry carries an 18-field
   `CacheEntryHeader` that makes its class, domain, exactness, freshness,
   rebuild cost, budget domain, reserve guard, dirty state, evictability,
   and poison state explicit and queryable.

4. **Pressure-aware eviction**: the system never drops dirty entries,
   protected reserve, or pinned DMA pages as an ad-hoc response to memory
   pressure. All reclaim follows P4-03 pressure stage discipline.

5. **Observability by default**: every cache exposes per-class, per-domain
   counters via `CacheLatticeReport`. A system-wide registry aggregates
   these into a single operator-visible report.

---

## 3. Type System: tidefs-types-cache-lattice-core

### 3.1 Memory domains (8)

Each cache entry belongs to exactly one `MemoryDomain`, which determines its
reclaim priority class and reserve-interaction rules.

| # | Domain | Reclaim Priority | Reserve Eligible | Description |
|---|--------|-----------------|------------------|-------------|
| 0 | `AuthorityImmutable` | 10 (last resort) | Yes | Sealed canonical requests, receipts, authority anchors |
| 1 | `AuthorityMutableHot` | 9 | Yes | Head/root mirrors, domain/lease/epoch mirrors |
| 2 | `StagingDirty` | 8 | Yes (to floors) | Dirty windows, writeback staging, publication staging |
| 3 | `AdapterServingHot` | 5 | No | Path/dentry/inode mirrors, handle/dir-stream mirrors |
| 4 | `ProductServing` | 3 | No | Explanation/query caches, answer fragments, summaries |
| 6 | `RebuildRelocationTemp` | 1 | No | Rebuild/relocation temporary scratch buffers |
| 7 | `KernelPinnedDma` | 7 | Yes | Kernel-pinned DMA pages, bio vectors, pinned folios |

Reclaim priority is higher = protect longer. Reserve-eligible domains may
borrow from the protected reserve pool; non-eligible domains may not.

### 3.2 Cache classes (9)

| # | Class | Primary Domain | Dirty? | Description |
|---|-------|---------------|--------|-------------|
| 0 | `AuthorityReadMirror` | AuthorityImmutable | No | Read mirrors of authority state |
| 1 | `PosixNamespaceMirror` | AdapterServingHot | No | Directory entry, inode, path mirrors |
| 2 | `PosixPageWriteback` | StagingDirty | Yes | Dirty page cache awaiting writeback |
| 3 | `BlockVolumeMappingQueue` | StagingDirty | Yes | Block-volume range mapping queues |
| 4 | `ProductRuntime` | ProductServing | No | Product-serving answer caches |
| 5 | `PublicationStaging` | StagingDirty | Yes | Publication payload staging |
| 7 | `RebuildRelocationScratch` | RebuildRelocationTemp | No | Temporary rebuild/relocation buffers |
| 8 | `SessionFence` | AdapterServingHot | No | Session fence and barrier entries |

Dirty classes require `StagingDirty` or `KernelPinnedDma` domain placement
and must pass through a state machine before eviction. Clean classes may be
evicted directly.

### 3.3 CacheEntryHeader (18 mandatory fields)

```rust
pub struct CacheEntryHeader {
    /// Cache class discriminator (9 variants).
    pub cache_class_id: u8,
    /// Memory domain discriminator (8 variants).
    pub memory_domain_id: u8,
    /// Exactness class: 0 = exact (complete, can prove negatives),
    /// 1 = inexact (partial, positives only), 2 = approximate.
    pub exactness_class: u8,
    /// Freshness class: 0 = read-your-writes, 1 = generation-bound,
    /// 2 = best-effort, 3 = stale (must refresh).
    pub freshness_class: u8,
    /// Build cost class: Trivial, Cheap, Moderate, Expensive.
    pub rebuild_cost_class: u8,
    /// Monotonic birth counter (commit_group or generation).
    pub birth_counter: u64,
    /// Monotonic last-hit counter for LRU eviction ordering.
    pub last_hit_counter: u64,
    /// Anchor vector reference (0 = no anchor).
    pub anchor_vector_ref: u64,
    /// Freshness fence vector reference (0 = no fence).
    pub freshness_fence_vector_ref: u64,
    /// Entry size in bytes for budget accounting.
    pub entry_size_bytes: u64,
    /// Budget domain name (e.g., "adapter_serving", "derived_views").
    pub budget_domain: [u8; 32],
    /// Budget domain string length.
    pub budget_domain_len: u8,
    /// Reserve guard class: None, SurplusOnly, HardReserve.
    pub reserve_guard: u8,
    /// Dirty state: Clean or one of 3 dirty-state machines.
    pub dirty_state: DirtyStateClass,
    /// Evictability class: Standard, LastResort, Pinned.
    pub evictability_class: u8,
    /// Poison state: Clean, AnchorMismatch, Corrupted, IOFailure.
    pub poison_state: u8,
    /// Poison epoch for cross-reboot poison persistence.
    pub poison_epoch: u64,
    /// Shard assignment hint for NUMA-aware placement.
    pub shard_hint: u8,
}
```

Every cache entry in the system, regardless of cache implementation or entry
type, MUST populate all 18 fields. The header carries enough metadata for
decisions without knowing the entry's payload type.

### 3.4 Dirty-state machines (3)

Dirty caches must transition through a state machine before eviction. Three
machines are defined:

**POSIX Page Writeback** (for `PosixPageWriteback` cache class):
```
DirtyOpen → DirtySealed → FlushPending → FuaPending → DurableClean → Clean
```

**Block Volume Range Flush** (for `BlockVolumeMappingQueue` cache class):
```
DirtyRange → FlushPending → FuaPending → DurableClean → Clean
```

**Publication Payload** (for `PublicationStaging` cache class):
```
PreparedUnsealed → SealedReady → PublicationInflight → ReceiptIssued → Retired
```

The runtime layer (`tidefs-cache-core`) provides `advance_posix_writeback()`,
`advance_block_flush()`, and `advance_publication_payload()` functions that
enforce legal transitions. Illegal transitions (e.g., DirtyOpen → Clean
without going through Sealed→FlushPending→FuaPending→DurableClean) return
`CacheLatticeError::IllegalDirtyStateTransition`.

`complete_posix_writeback()` is a convenience that runs the full chain
DirtyOpen → Clean and additionally clears poison state.

### 3.5 Type-level invariants


1. **Anchor required for exact**: `exactness_class == 0` requires
   `anchor_vector_ref != 0`.
2. **Dirty domain requires dirty state**: entries in `StagingDirty` or
   `KernelPinnedDma` with a dirty cache class must have a dirty state
   (not `Clean`).
3. **Budget domain required**: `budget_domain_len > 0`.
4. **Poisoned entry not servable**: `poison_state` must be `Clean` for
   a cache entry to be served.
5. **Class-domain consistency**: the entry's `memory_domain_id` must be
   consistent with the cache class's `primary_domain()` or a valid
   override hint.

---

## 4. Runtime Layer: tidefs-cache-core

### 4.1 Domain classification

`classify_memory_domain_for_allocation(class, hint)` resolves the target
memory domain for a new allocation. If a dirty cache class is allocated
into `StagingDirty` or `KernelPinnedDma` via hint, that hint is honored.
Otherwise the class's `primary_domain()` is used.

### 4.2 Admission gate

`admit_cache_entry_under_budget_and_fence(header, budget, max_entry_size)`
runs six checks in order:

1. **Oversized entry**: `entry_size_bytes > max_entry_size_bytes` →
   `AdmissionResult::OversizedEntry`
2. **Dirty-state legality**: dirty state on a non-dirty cache class →
   `AdmissionResult::DirtyStateIllegal`
3. **Budget exhaustion**: `available_entries() == 0` or
   `available_bytes() < entry_size_bytes` → `AdmissionResult::BudgetExhausted`
4. **Reserve breach**: `reserve_guard == None` and
   `available_entries_above_reserve() == 0` → `AdmissionResult::ReserveBreach`
5. **Anchor fence**: `exactness_class == 0` and `anchor_vector_ref == 0` →
   `AdmissionResult::AnchorFenceIncomplete`
6. **Freshness fence**: `freshness_class == 0` and
   `freshness_fence_vector_ref == 0` and `exactness_class > 1` →
   `AdmissionResult::AnchorFenceIncomplete`

Only when all checks pass is `AdmissionResult::Admitted` returned.



1. **Poison check**: if `poison_state != Clean`, the entry is invalid.
2. **Anchor mismatch**: if `anchor_vector_ref != 0` and the referenced
   anchor doesn't match, the entry transitions to `PoisonState::AnchorMismatch`.
3. **Freshness check**: for `freshness_class == 1` (generation-bound),
   if `birth_counter < current_generation`, the entry is stale.
4. **Staleness extension**: for `freshness_class == 3` (stale), the entry
   is always invalid.

### 4.4 Eviction and compaction

`compact_or_evict_cache_class_under_pressure(entries, level, target_bytes)`
builds an ordered eviction plan:

1. Sort entries by reclaim priority (ascending — lowest priority evicted first).
2. Filter out entries with `evictability_class == Pinned` and dirty entries
   (must flush before eviction).
3. Select candidates until `target_bytes` is freed or all eligible entries
   are exhausted.
4. Return an `EvictionPlan` with the list of candidates and total freed bytes.

The function is pressure-level-aware. At `Emergency` level, it drops
`LastResort` evictability entries as well.

### 4.5 Loan/pin drain

`drain_page_loans_and_pins_for_cutover_or_failover(entries, drain_timeout_us)`
iterates all entries in `KernelPinnedDma` and attempts to release their
pins/loans. Returns the number of entries drained and whether all were
drained within the timeout.

### 4.6 Observability emitter

`CacheObservabilityEmitter` tracks:

- Per-domain counters: `current_entries`, `current_bytes`, `total_admits`,
  `total_hits`, `total_misses`, `total_evictions`, `total_dirty_transitions`.
- Per-class counters: same breakdown.
- `CacheLatticeReport` construction via `build_report()` with all 8 domains
  and 9 classes summarized.

### 4.7 Budget domain tracking

`DomainBudget` is a per-domain budget structure with:

```rust
pub struct DomainBudget {
    pub max_entries: usize,
    pub max_bytes: u64,
    pub current_entries: usize,
    pub current_bytes: u64,
    pub reserve_floor_entries: usize,
}
```

Each budget domain (identified by string name stored in
`CacheEntryHeader.budget_domain`) has its own `DomainBudget`. The system
maintains a map from budget domain name to `DomainBudget`.

---

## 5. Cache-Lattice Views

### 5.1 Concept

A **view** is a precomputed, optionally-persistent answer to a query, carrying
explicit metadata about its validity and the cost of its production:

```
View = cached_answer + ViewMeta
```

Views are **derived** (non-authoritative) cache entries. Losing a view cannot
change visible filesystem truth — views are always rebuildable from
authoritative state. This is in contrast to authoritative caches
(`hot_read_cache`, `inode_cache`) which mirror canonical data.

### 5.2 ViewMeta — the completeness contract

```rust
pub struct ViewMeta {
    /// Only a complete view may prove negative answers (e.g., ENOENT).
    /// Incomplete views are valid for positive lookups only.
    pub complete: bool,

    /// Generation of the authoritative data at view build time.
    /// Compared against current generation to detect staleness.
    pub seen_generation: u64,

    /// Cost consumed during build. Drives eviction decisions:
    pub cost: ViewBuildCost,

    /// View class discriminator for typed dispatch.
    pub view_class: ViewClass,

    /// Mismatch with current token → view is invalid.
    pub stored_token: ValidityToken,
}
```

### 5.3 ViewBuildCost

```rust
pub struct ViewBuildCost {
    /// Authoritative reads: btree scans, inode reads, change-stream iteration.
    pub authoritative_reads: u64,
    /// Derived writes: writing view pages to cache.
    pub derived_writes: u64,
    /// Bookkeeping: compaction, tombstone cleanup, index maintenance.
    pub bookkeeping: u64,
}

impl ViewBuildCost {
    pub fn total(&self) -> u64 {
        self.authoritative_reads
            .saturating_add(self.derived_writes)
            .saturating_add(self.bookkeeping)
    }
}
```

`ViewBuildCost.total()` maps to `RebuildCostClass`:
- 0–9 ops → `Trivial`
- 10–99 ops → `Cheap`
- 100–999 ops → `Moderate`
- ≥1000 ops → `Expensive`

### 5.4 ValidityToken

counter scoped to the view's key space.

```rust
pub struct ValidityToken(u64);

impl ValidityToken {
    /// Create a new token at generation 1.
    pub fn new() -> Self { Self(1) }

    pub fn bump(&mut self) { self.0 = self.0.wrapping_add(1); }

    /// Check if a stored token matches.
    pub fn matches(&self, stored: ValidityToken) -> bool {
        self.0 == stored.0
    }
}
```

Each view class has its own token scope:
- Directory listing views: keyed by `(dir_inode_id, dir_rev)` — token bumped
  on any create/unlink/rename within the directory.
- Path lookup views: keyed by `(parent_inode_id, name_bytes)` — token bumped
  on create/unlink/rename of the named entry.
- Missing-path views: keyed by `(parent_inode_id, name_bytes)` — token bumped
  on create of the named entry.
- Missing-names views: keyed by `(dir_inode_id)` — token bumped on any create
  within the directory.
- Hierarchy manifest views: keyed by `(subtree_root_id, subtree_rev)` — token
  bumped on any write within the subtree.

### 5.5 Five canonical view types

| # | View Class | Key | Complete Condition | Use Case |
|---|-----------|-----|-------------------|----------|
| 0 | `DirectoryListing` | `(dir_inode_id, dir_rev)` | All entries enumerated | `readdir` acceleration |
| 1 | `HierarchyManifest` | `(subtree_root_id, subtree_rev)` | Full subtree walked | `statfs`, quota, admin |
| 2 | `PathLookup` | `(parent_inode_id, name_bytes)` | Target inode verified | Path resolution hot path |
| 3 | `MissingPath` | `(parent_inode_id, name_bytes)` | Name confirmed absent | Negative lookup caching |
| 4 | `MissingNames` | `(dir_inode_id)` | All known-missing listed | Bulk negative caching |

### 5.6 View-to-header field mapping

Views slot their metadata into the existing `CacheEntryHeader` without schema
changes:

| Header field | View usage |
|---|---|
| `cache_class_id` | `PosixNamespaceMirror` (class 1) for all views |
| `memory_domain_id` | `AdapterServingHot` (domain 3) |
| `exactness_class` | 0 if `ViewMeta.complete`, 1 otherwise |
| `freshness_class` | 1 (generation-bound) when `seen_generation` matches current; 3 (stale) otherwise |
| `rebuild_cost_class` | Derived from `ViewBuildCost.total()` |
| `birth_counter` | Set to `seen_generation` |
| `last_hit_counter` | Updated on every cache hit; used by LRU eviction |
| `anchor_vector_ref` | Set to `stored_token.0` |
| `entry_size_bytes` | Total serialized view size |
| `budget_domain` | `"derived_views"` |
| `reserve_guard` | `SurplusOnly` (views are evictable) |
| `dirty_state` | `Clean` (views are read-only caches) |
| `evictability_class` | `Standard` for cheap views; `LastResort` for expensive |
| `poison_state` | `Clean`; set to `AnchorMismatch` if token mismatch detected |

### 5.7 View lifecycle

```
DIRTY OPERATION (create, unlink, rename, write)
    │
    ▼
Bump ValidityToken for affected view scopes
    │
    ▼
On next access:
    │
    ├── stored_token matches current → HIT: serve from cache
    │
    └── stored_token mismatches → MISS: rebuild view
                                      │
                                      ▼
                                  Read authoritative state
                                      │
                                      ▼
                                  Build ViewMeta (complete flag, cost)
                                      │
                                      ▼
                                  admit_cache_entry_under_budget_and_fence()
                                      │
                                      ├── Admitted → store in view cache, serve
                                      │
                                      └── Rejected → serve without caching,
                                          mark incomplete, count admission_bypass
```


Directory mutation hooks trigger `ValidityToken` bumps:

- **create(name, dir_inode)**: bump `PathLookup(dir_inode, name)`,
  `MissingPath(dir_inode, name)`, `DirectoryListing(dir_inode, *)`,
  `MissingNames(dir_inode)`, and `HierarchyManifest` for all ancestor dirs.
- **unlink(name, dir_inode)**: bump `PathLookup(dir_inode, name)`,
  `DirectoryListing(dir_inode, *)`, and `HierarchyManifest` for ancestors.
- **rename(old_name, old_dir, new_name, new_dir)**: bump tokens for
  both source and target directories (same scopes as create+unlink).
- **write(inode)**: bump `HierarchyManifest` for all ancestor dirs
  (size/block count changes).

---

## 6. Concrete Cache Implementations

### 6.1 HotReadCache (ARC content cache)

Caches data content chunks keyed by `(object_key_hash, offset, length)`.
design calls for migrating it to delegate to `tidefs-cache-core`.

**Post-migration architecture**:
- `HotReadCache` owns the ARC data structure and chunk-specific indexing.
- On cache miss → read from object store → construct `CacheEntryHeader` →
  call `admit_cache_entry_under_budget_and_fence()`.
- On eviction → call `compact_or_evict_cache_class_under_pressure()`
  with the ARC's ghost-list-ordered candidate list.
- Report via `CacheObservabilityEmitter`.

**Budget domain**: `"hot_read"` under `AdapterServingHot` memory domain.
**Cache class**: `PosixNamespaceMirror` (clean, adapter-serving).

### 6.2 InodeCache (ARC inode metadata cache)

Caches inode metadata keyed by `(inode_id, generation)`. Same migration
pattern as `HotReadCache`.

**Post-migration architecture**:
- `InodeCache` owns the ARC data structure and inode-specific indexing.
- All lifecycle operations delegate to `tidefs-cache-core`.
- Report via `CacheObservabilityEmitter`.

**Budget domain**: `"inode_metadata"` under `AdapterServingHot` memory domain.
**Cache class**: `PosixNamespaceMirror` (clean, adapter-serving).

### 6.3 ViewCache (future)

A new cache implementation dedicated to the 5 view types. Unlike the ARC
caches, the `ViewCache` is always derived (non-authoritative).

**Architecture**:
- Per-view-class hash maps keyed by `(scope_key, ValidityToken)`.
- On access: check `stored_token` against current `ValidityToken` for the
  view's scope. If mismatch → rebuild from authoritative state.
- Budget domain: `"derived_views"` with configurable `derived_bytes_budget_per_pool`.
- Memory domain: `AdapterServingHot`.
- Reclaim priority: between `AdapterServingHot` entries and `ProductServing`.

---

## 7. CacheLatticeRegistry — System-Wide Coordination

### 7.1 Purpose

The `CacheLatticeRegistry` provides:

1. A single registration point for all caches in the system.
2. Aggregated `CacheLatticeReport` across all caches.
3. Coordinated pressure response following P4-03 stage discipline.
4. Per-budget-domain accounting across caches.

### 7.2 Registration

```rust
pub trait CacheLatticeParticipant {
    fn lattice_report(&self) -> CacheLatticeReport;
    fn memory_domains(&self) -> &[MemoryDomain];
    fn apply_pressure_plan(&mut self, plan: &EvictionPlan) -> usize;
}

pub struct CacheLatticeRegistry {
    participants: Vec<Box<dyn CacheLatticeParticipant>>,
    domain_budgets: HashMap<String, DomainBudget>,
    pressure_stage: PressureStage,
}
```

### 7.3 Pressure stages (P4-03)

The registry implements P4-03 pressure stage discipline:

| Stage | Trigger | Response |
|---|---|---|
| `Steady` | Memory < 60% | No eviction |
| `Warm` | Memory 60–75% | Background compaction of `ObserveHot` |
| `ActiveReclaim` | Memory 75–85% | Evict `ProductServing`, compact `AdapterServingHot` |
| `HardThrottle` | Memory 85–92% | Evict `AdapterServingHot` views, throttle admissions |
| `ReserveProtect` | Memory 92–97% | Protect reserve floors, evict all non-reserve |
| `EmergencyFreeze` | Memory > 97% | Drop `LastResort` entries, reject all admissions |

### 7.4 apply_pressure() algorithm

```
apply_pressure():
  1. Sample pressure signals:
     - Total domain bytes across all participants
     - Dirty backlog (entries in StagingDirty)
     - Pin count (entries in KernelPinnedDma)
     - Reserve threat (reserve_floor - current_reserve_headroom)

  2. Classify pressure stage from signals

  3. Build ordered eviction plan:
     For each stage threshold breached:
       For each participant, lowest reclaim priority first:
         compact_or_evict_cache_class_under_pressure(...)
       Stop when target reclaimed or all eligible exhausted

  4. Execute plan against each participant

  5. Emit PressureEscalationReceipt on stage transition
```

### 7.5 Observability aggregation

```rust
pub struct CacheLatticeReport {
    pub total_entries: u64,
    pub total_bytes: u64,
    pub domain_stats: [DomainStat; 8],
    pub class_stats: [ClassStat; 9],
    pub pressure_stage: PressureStage,
    pub view_stats: ViewStats,
}

pub struct ViewStats {
    pub directory_listing_hits: u64,
    pub directory_listing_misses: u64,
    pub path_lookup_hits: u64,
    pub path_lookup_misses: u64,
    pub missing_path_negative_proofs: u64,
    pub hierarchy_manifest_hits: u64,
    pub view_builds_total: u64,
    pub view_evictions_total: u64,
    pub derived_catalog_bytes: u64,
}
```

---

## 8. View Build and Refresh Algorithms

### 8.1 Directory listing view build

```
build_directory_listing_view(dir_inode_id, dir_rev):
  1. Acquire authoritative directory btree read lock
  2. Iterate all entries: collect (name_bytes, inode_id, entry_type)
  3. Sort by name_bytes
  4. Release lock
  5. Construct ViewMeta { complete: true, seen_generation: dir_rev, cost, ... }
  6. Serialize view payload
  7. Admit to ViewCache under "derived_views" budget
  8. Return (entries, ViewMeta)
```

Completeness: a directory listing view is **complete** when the full btree
scan succeeded without interruption. Incomplete views (budget-exhausted
mid-build, or concurrent modification during build) are valid for positive
lookups only — the caller must fall through to authoritative scan for
negative proofs.

### 8.2 Path lookup view build

```
build_path_lookup_view(parent_inode_id, name_bytes):
  1. Look up (name_bytes) in authoritative directory btree
  2. If found:
     a. Construct ViewMeta { complete: true, ... }
     b. Payload = target_inode_id
  3. If not found:
     a. Construct ViewMeta { complete: true, ... }
     b. Payload = None (negative cache)
  4. Admit to ViewCache
  5. Return (target_inode_id, ViewMeta)
```

### 8.3 Hierarchy manifest view build

```
build_hierarchy_manifest_view(subtree_root_id, subtree_rev):
  1. Walk subtree starting at subtree_root_id
  2. Accumulate: total_size, total_blocks, file_count, dir_count,
     oldest_mtime, newest_mtime, deepest_path_len
  3. Construct ViewMeta { complete: true, cost, ... }
  4. Payload = HierarchyManifest { total_size, total_blocks, ... }
  5. Admit to ViewCache
  6. Return (manifest, ViewMeta)
```

### 8.4 Incremental refresh via change streams

For hot directories with high mutation rates, full rebuilds are expensive.
The design supports incremental refresh using directory change streams
(#1173):

```
refresh_directory_listing_view(dir_inode_id, current_rev):
  stored = view_cache.get(DirectoryListing, dir_inode_id)
  if stored is None → full build

  delta_entries = change_stream.query(dir_inode_id,
                                       from_rev=stored.seen_generation,
                                       to_rev=current_rev)

  if delta_entries.count() > threshold → full rebuild (cheaper)

  Apply delta: add creates, remove unlinks, update renames
  Update ViewMeta: seen_generation = current_rev, cost += delta_cost
  Re-admit updated view under budget
```

The threshold for full rebuild vs. incremental refresh is configurable
per pool: `view_incremental_refresh_threshold` (default 64 entries).

---

## 9. Canonical Data Flow: Readdir with Views

```
Client: readdir(dir_inode=42)
    │
    ▼
view_cache.get(DirectoryListing, key=(42, current_dir_rev))
    │
    ├── HIT + complete ──► serve from cache, return entries
    │
    ├── HIT + incomplete ──► serve positives, authoritative scan for negatives
    │                         │
    │                         ▼
    │                     Scan authoritative btree for entries NOT in view
    │                         │
    │                         ▼
    │                     Merge + return
    │
    └── MISS ──► build_directory_listing_view(42, current_dir_rev)
                    │
                    ▼
                admit_cache_entry_under_budget_and_fence(header, budget)
                    │
                    ├── Admitted ──► store in view cache, serve
                    │
                    └── Rejected ──► serve without caching,
                        mark incomplete, count admission_bypass
```

---

## 10. Design Tradeoffs

### 10.1 Unified types vs. per-cache types

**Decision**: Single `no_std` type crate with all cache-lattice types.

**Rationale**: Avoids type drift between caches. The 18-field header is
universal — every cache needs most fields. The overhead of unused fields
(1–2 bytes per entry) is negligible compared to the correctness benefit of
a single schema.

**Tradeoff**: Adding a new field requires updating all caches. Mitigated by
the fact that new fields are rare (3 added since P4-02 inception) and the
compiler enforces exhaustive initialization.

### 10.2 Shared runtime vs. per-cache logic

**Decision**: Mandatory delegation to `tidefs-cache-core` for all lifecycle
operations.

**Rationale**: Prevents drift in admission policy, eviction ordering, and
dirty-state machine enforcement. A cache that reimplements admission could
inadvertently admit poisoned entries or breach reserve floors.

**Tradeoff**: Slightly less flexibility for cache-specific optimizations.
Mitigated by the fact that cache-specific logic (indexing, payload format,
ARC ghost lists) remains in the cache implementation; only the policy
decisions are shared.

### 10.3 Views as disposable vs. persistent

**Decision**: Views are disposable caches, not persistent artifacts.

**Rationale**: Views are derived from authoritative state. Making them
persistent would require crash-consistency guarantees, WAL integration, and
Views are rebuilt on-demand after a crash.

**Tradeoff**: Cold-start performance after a crash is worse until views are
rebuilt. Mitigated by the fact that views are rebuilt lazily and only for
accessed directories/paths.

### 10.4 Per-scope ValidityToken vs. global generation

**Decision**: Fine-grained `ValidityToken` per view scope rather than a
single global generation counter.

defeating the purpose of caching. Per-scope tokens ensure that a `create`

scopes per mutation). Mitigated by the fact that the scope hierarchy is
well-defined (ancestor directories for hierarchy manifests, specific
directories for listing views, specific names for lookup views).

### 10.5 Unified pressure response vs. independent reclaim

**Decision**: System-wide `CacheLatticeRegistry` coordinates pressure response
across all caches.

**Rationale**: Independent per-cache reclaim leads to thrashing — one cache
evicts entries while another has headroom. Coordinated response ensures the
cheapest-to-rebuild entries are evicted first, regardless of which cache
owns them.

**Tradeoff**: Slightly higher latency for pressure response (must aggregate
across caches). Mitigated by the fact that pressure response runs on a
background tick, not in the hot path.

---

## 11. Implementation Phases

### Phase 1: Wire runtime into existing caches

- Add `tidefs-cache-core` as a dependency of `tidefs-local-filesystem`.
- Refactor `HotReadCache` to delegate admission to
  `admit_cache_entry_under_budget_and_fence()`.
- Refactor `HotReadCache` eviction to use
  `compact_or_evict_cache_class_under_pressure()`.
- Refactor `InodeCache` with the same pattern.
- Add `CacheObservabilityEmitter` to both caches.
- Wire `DomainBudget` instances for `"hot_read"` and `"inode_metadata"`.

**Gate**: existing cache tests pass; no behavioral change.

### Phase 2: CacheLatticeRegistry

- Implement `CacheLatticeRegistry` with participant registration.
- Implement `CacheLatticeParticipant` trait on both caches.
- Implement `apply_pressure()` with P4-03 stage discipline.
- Wire registry into `LocalFileSystem` initialization.
- Add `PressureEscalationReceipt` emission.

**Gate**: registry aggregation tests pass; pressure response does not drop
dirty entries or protected reserve.

### Phase 3: View infrastructure

- Implement `ViewMeta`, `ViewBuildCost`, `ValidityToken`, `ViewClass`.
- Add these types to `tidefs-types-cache-lattice-core` or a new
  `tidefs-types-cache-lattice-view-core` crate.
- Implement `ViewCache` with per-view-class hash maps.
- Implement view build algorithms for all 5 view types.
- Implement view refresh (full rebuild and incremental via change streams).
- Wire directory mutation hooks to bump `ValidityToken`.

**Gate**: directory listing view hit rate ≥ 80% under `xfstests generic/001`.

### Phase 4: System-wide observability

- Implement `build_report()` aggregation in `CacheLatticeRegistry`.
- Add `ViewStats` to `CacheLatticeReport`.
- Expose report via observability pipeline (#827).
- Add per-view-class counters.

**Gate**: all counters emit correctly; operator can query per-class hit rates.

---

## 12. Invariants

1. **No duplicate type systems.** `tidefs-types-cache-lattice-core` is the
   only source of `CacheClass`, `MemoryDomain`, `CacheEntryHeader`, and
   related types. No crate or module may define parallel or equivalent enums.

2. **Every cache delegates to the runtime.** `tidefs-cache-core` functions
   dirty-state transitions in production. Caches may not reimplement these.

3. **Every cache entry has a lattice header.** The 18 mandatory fields of
   `CacheEntryHeader` must be populated for every cache entry in the system,
   regardless of cache implementation.

4. **Views are disposable.** Losing a view cannot change visible filesystem
   truth. Views are always rebuildable from authoritative state.

5. **Pressure response is staged.** The system moves through named P4-03
   pressure stages; it never drops dirty entries, protected reserve, or
   pinned DMA pages as an ad-hoc response to memory pressure.

6. **Observability is mandatory.** Every cache exposes per-class, per-domain
   counters via `CacheLatticeReport`. The system-wide registry aggregates
   these into a single operator-visible report.

7. **Admission is atomic.** An entry is either fully admitted (header
   populated, budget charged) or not admitted at all. No partial admission.

8. **Dirty entries flush before eviction.** No cache may evict an entry in
   `StagingDirty` domain with a dirty state without first completing its
   state machine to `Clean`.

9. **ValidityToken bumps are scoped.** Mutating a file in `/a/b/c` bumps
   tokens for `/a/b/c`'s directory listing, path lookups for entries in
   `/a/b/c`, and hierarchy manifests for `/a`, `/a/b`, and `/a/b/c`. It
   does NOT affect tokens for `/x/y/z`.

10. **View completeness is monotonic.** A view that is complete can become
    incomplete (due to incremental refresh or partial rebuild). A view that
    is incomplete can be promoted to complete by a full rebuild. Completeness
    is recorded in the header and visible to operators.

---

## 13. Non-Claims


- **Cross-node view sharing**: views are local to the writer node.

- **Persistent view snapshots**: using derived views to accelerate dataset
  send/receive (#1251) is deferred.

- **View prefetch**: speculative view building based on access patterns is
  covered by the prefetch architecture (#1247).

- **Encrypted/compressed view payloads**: deferred to encryption (#1246)
  and compression (#1245) designs.

- **New CacheClass variants**: views use existing `PosixNamespaceMirror` class
  with the `derived_views` budget domain. No new cache classes are proposed
  in this design.

- **New MemoryDomain variants**: views use existing `AdapterServingHot` domain.
  No new memory domains are proposed in this design.

---

## 14. References

- `crates/tidefs-types-cache-lattice-core/src/lib.rs` — no_std authority types
  (966 lines, 8 MemoryDomain variants, 9 CacheClass variants, 18-field header,
  3 dirty-state machines, 15 type-level tests)
  3 state-machine advance functions, loan/pin drain, observability emitter,
  27 runtime tests)
- `crates/tidefs-local-filesystem/src/hot_read_cache.rs` — ARC content cache
  (imports types from `tidefs-types-cache-lattice-core`; owns local admission/
- `crates/tidefs-local-filesystem/src/inode_cache.rs` — ARC inode cache
  (imports types from `tidefs-types-cache-lattice-core`; owns local admission/
- `docs/design/cache-lattice-views.md` — views-as-cached-answers design (#1176)
- `docs/design/cache-device-tiering-flash_tier-writeback.md` — FlashTier and cache device
  tiering design
- `docs/design/weighted-arc-cache-per-entry-weight-tracking.md` — ARC weight
  tracking
- `docs/CACHE_TAXONOMY_INVARIANTS_P4-02.md` — cache taxonomy design rule (if present)
- `docs/MEMORY_DOMAINS_ARENA_FAMILIES_OWNERSHIP_TOKEN_LAW_P4-01.md` — memory
  domains design rule (if present)
- `docs/MEMORY_PRESSURE_RECLAIM_RESERVE_INTERACTION_P4-03.md` — pressure/
  reclaim/reserve design rule (if present)
- Issue #827 — structural observability
- Issue #1097 — P4-02 cache taxonomy runtime
- Issue #1173 — directory change streams
- Issue #1176 — cache-lattice views (views-as-cached-answers)
- Issue #1636 — earlier unified cache-lattice views design (merged here)
- Issue #1909 — unified cache-lattice views design (this document)
- Issue #1691 — earlier unified cache-lattice views design iteration (superseded by #1909)
- Issue #1239 — universal incremental cursor framework
- Issue #1240 — derived views as first-class architectural pillar
- Issue #1245 — compression architecture
- Issue #1246 — encryption architecture
- Issue #1247 — prefetch architecture
- Issue #1251 — dataset send/receive
