# Derived Views as First-Class Architectural Pillar: ValidityToken Contract, Rebuildability, and Budgeted Incremental Refresh

> **Document authority**: This file is imported/historical design input
> from the pre-GitHub Forgejo-era TideFS repository. It is **not** current
> policy, current specification, implementation-status evidence,
> release-readiness evidence, or worker scheduling authority.
>
> Readers evaluating current TideFS documentation authority should start
> at `docs/INDEX.md` and `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.
>
> **Register classification (2026-06-24)**: `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`
> classifies this file as **historical input** under TFR-019 / GitHub issue
> #1240. The Forgejo-era metadata below (issue #1240, P2 priority,
> DESIGN-M4 milestone, lane/blocking claims, `STATUS.md`/`FEATURE_MATRIX.md`
> references, and DEPENDS-ON links to retired Forgejo issues
> #1173/#1176/#1237/#1239) is preserved only as historical design context.
> Live source has a simpler `ValidityToken` (32-byte BLAKE3 opaque token
> with `matches()`) in `tidefs-types-cache-lattice-core` and stub
> `ViewClass`/`ViewBuildCost` enums without derived-view implementations,
> but no multi-kind token dispatch, no six-view-type runtime, no incremental
> delta refresh, and no budget-governor wiring. The cache-lattice,
> cursor-framework, resource-governor, and WorkBudget architectural claims
> in this document exceed current live-source and claim-registry evidence.
> This file must not be cited as current TideFS implementation status,
> release-readiness evidence, or product authority.
>
> The design material below is preserved for future review; it has not
> been validated against current source behavior or claim-registry evidence.

**Issue**: [#1240](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1240)
**Status**: design-spec
**Priority**: P2
**Lane**: storage-core
**Milestone**: DESIGN-M4: Cluster Infrastructure (Layers 8–11)
**Depends on**: #1173 (directory change streams), #1176 (cache-lattice views), #1237 (unified resource governor), #1239 (cursor framework)

## Abstract

"Derived views" are one of tidefs's key architectural innovations — rebuildable,
budgeted acceleration structures protected by validity predicates. They are
derived (non-authoritative) cached answers to namespace queries that carry
a ValidityToken tying them to the authoritative state they were built from.
When the authoritative state advances beyond the token, the view is stale and
must be refreshed. Refreshing is incremental when possible (applying dir_rev
deltas to a directory listing view) and bounded by WorkBudget limits so demand
IO is never starved.

This design establishes derived views as a first-class architectural pillar
with:

1. A **ValidityToken** contract defining five token kinds and their
2. A **canonical set of six view types** covering the most latency-sensitive
   namespace operations.
3. An **incremental refresh algorithm** driven by directory change streams
   (#1173) and bounded by WorkBudget (#1239).
4. **Budget integration** with the unified resource governor (#1237),
   consuming `meta_cache` memory and bounded construction work.
   for multi-node cache coherency.
6. **Safe eviction** under memory pressure — views are disposable caches that
   can be dropped without correctness impact.

---

## 1. Problem Statement

tidefs currently performs namespace operations (readdir, path lookup, negative
lookup) by consulting authoritative on-disk state on every access. For hot
directories with thousands of entries or deep path traversals, this is
prohibitively slow. The existing cache lattice (#1176) provides the type
scaffolding for cached answers (ViewMeta, ViewClass, ViewBuildCost) but does
not define the ValidityToken contract that governs when a view is stale, the
rebuild mechanics that bring a stale view current, or the budget rules that
keep rebuild under control.

In cluster mode (#1208), follower nodes that hold SHARED dataset leases must
detect that their local derived views are stale when the writer commits
mutations. Without a uniform ValidityToken that both local rebuild and

This design provides:

- **Uniform staleness detection**: one ValidityToken type that every view
  carries, checked on every access.
- **Incremental refresh**: apply only the delta since last build, not a full
  rebuild, when the gap is small.
- **Budgeted work**: every rebuild step is subject to WorkBudget; demand IO
  always wins.

---

## 2. What Is a Derived View?

A **derived view** is a rebuildable acceleration structure that:

| Property | Description |
|---|---|
| **Stored on media** | Persistent hints, not authoritative — stored as cache entries in the cache lattice |
| **Carries a ValidityToken** | Identifies the authoritative state snapshot the view was built from |
| **Rebuildable** | Can be reconstructed from authoritative state at any time |
| **Budgeted** | Subject to memory (meta_cache domain) and construction-time (WorkBudget) limits |
| **Evictable** | Can be dropped under memory pressure without correctness impact |
| **Incrementally updatable** | Small deltas (e.g., one entry added to a directory) are applied without full rebuild |

### 2.1 Relationship to authoritative state

Derived views are NOT authoritative. The authoritative state lives in:

- **Directory B+tree** entries (`DirBtreeLeafEntry` in on-disk B+tree pages)
- **Inode records** (`InodeAttr` with `dir_rev`, `generation`, `subtree_rev`)
- **Directory change streams** (#1173): the persistent, ordered log of
  `(dir_rev, entry_delta)` tuples

A derived view is valid when and only when its ValidityToken matches the
current authoritative state. On mismatch, the view is stale — it may still
return positive hits (cached entries that haven't changed) but MUST NOT
return negative proofs (e.g., "entry X does not exist").

### 2.2 The cache-lattice integration point

Views live in the cache lattice (#1176) as `CacheEntryHeader` records with:

- `cache_class_id` mapped per view type
- `memory_domain_id` = `DerivedViews` (domain 8, reclaim priority 75)
- `exactness_class` = `"complete"` or `"incomplete"` per ViewMeta
- `freshness_class` = `"generation_bound"` or `"generation_stale"` per ValidityToken check
- `budget_domain_ref` = `"derived_views"`
- `reserve_guard_class` = `SurplusOnly` (views are evictable)
- `dirty_state_class` = `Clean` (views are read-only caches)

The existing `CacheEntryHeader` (18 mandatory fields from P4-02) absorbs view
metadata through these field assignments without schema changes.

---

## 3. ValidityToken Contract

### 3.1 Type definition

```rust
/// Identifies the authoritative state against which a derived view is valid.
///
/// Every derived view carries exactly one ValidityToken. When the
/// authoritative state advances beyond the token, the view is stale.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct ValidityToken {
    pub kind: ValidityTokenKind,
    pub value: u64,
}

/// Discriminant for the five canonical token kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum ValidityTokenKind {
    /// Keyed by (dataset_id, dir_inode_id, dir_rev).
    /// View is valid when the directory's dir_rev >= token value.
    DirRev = 0,

    /// Keyed by tree_root_ptr.
    /// View is valid when the current tree root pointer equals token value.
    TreeRoot = 1,

    /// Keyed by (dataset_id, snap_commit_group).
    /// View is valid when no new snapshots exist since snap_commit_group.
    Snapshot = 2,

    /// Keyed by (dataset_id, from_commit_group, to_commit_group).
    /// View is valid when no mutation commit_group falls in [from_commit_group, to_commit_group].
    CommitGroupRange = 3,

    /// Keyed by (namespace: u16, value: u64).
    /// Reserved for future view types that don't map to the canonical four.
    Custom = 4,
}
```


|---|---|---|
| `DirRev` | `inode.dir_rev >= token.value` | Any directory mutation (create, unlink, rename, attribute change) |
| `TreeRoot` | `tree_root_ptr == token.value` | Any namespace mutation (the tree root pointer changes on every commit_group commit that touches the namespace) |
| `Snapshot` | No snapshot with `commit_group > token.value` | `zfs snapshot` or equivalent creates a new snapshot |
| `CommitGroupRange` | No mutation commit_group in `[from, to]` where `from = token.value >> 32`, `to = token.value & 0xFFFFFFFF` | Any write to the covered range |
| `Custom` | Implementation-defined | Use-case specific |


Every view access follows this protocol:

```
    let token = view.validity_token;
    match token.kind {
        DirRev => {
            if current_authoritative_state.dir_rev >= token.value {
                return ViewResult::Valid(view);
            }
        }
        TreeRoot => {
            if current_authoritative_state.tree_root_ptr == token.value {
                return ViewResult::Valid(view);
            }
        }
        Snapshot => {
            if !has_new_snapshot_since(token.value) {
                return ViewResult::Valid(view);
            }
        }
        CommitGroupRange => {
            if !has_mutation_in_range(extract_from(token.value), extract_to(token.value)) {
                return ViewResult::Valid(view);
            }
        }
        Custom => { /* implementation-defined */ }
    }
    ViewResult::Stale(view) // triggers rebuild
}
```

### 3.4 Token serialization

The ValidityToken is stored as 10 bytes in the cache entry header:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `ValidityTokenKind` discriminant (u8) |
| 1 | 1 | Reserved (0x00) |
| 2 | 8 | `value` (u64, little-endian) |

It maps to `CacheEntryHeader.anchor_vector_ref` for persistence and is
hashed (BLAKE3-64) for comparison.

### 3.5 Bridge to `InodeAttr.dir_rev`

The `DirRev` token kind directly consumes `InodeAttr.dir_rev` from
`tidefs_types_vfs_core`. Every directory inode carries a `dir_rev` counter
incremented on every mutation:

```
InodeAttr {
    inode_id: InodeId,
    generation: Generation,
    kind: NodeKind,
    posix: PosixAttrs,
    flags: InodeFlags,
    subtree_rev: u64,
    dir_rev: u64,        // <-- consumed by DirRev tokens
}
```

A directory listing view built at `dir_rev = 42` carries token
`ValidityToken { kind: DirRev, value: 42 }`. When a `create` bumps
`dir_rev` to 43, the view is stale on next access because `43 >= 42`.

### 3.6 Future token kinds

The `Custom` variant reserves namespace `0x0000–0xFFFF` via a u16 prefix.
Namespace 0x0000 is reserved for tidefs core. Extensions (e.g., #1245
compression, #1246 encryption) may register custom namespaces. Custom

---

## 4. Canonical View Types

Six view types form the canonical set. Each type maps to a `ViewClass`
discriminant from #1176 and carries a specific ValidityToken kind.

### 4.1 Directory Listing View

| Property | Value |
|---|---|
| **View class** | `DirectoryListing` (0) |
| **Key** | `(dir_inode_id: u64, dir_rev: u64)` |
| **Content** | Sorted list of `(name_bytes, inode_id, entry_type, cookie)` entries |
| **Token kind** | `DirRev` |
| **Complete?** | Yes — can prove ENOENT (name not in this directory) |
| **Rebuild trigger** | `inode.dir_rev >= token.value` |

**Purpose**: Accelerate `readdir` / `readdirplus`. The most latency-sensitive
view. Without it, every `ls` in a large directory must scan the directory
B+tree from disk.

**Content model**: The view stores the full directory entry list at the time
of build. It is a snapshot — entries added after build are not in the view,
when looked up).

**Incremental refresh**: Applies dir_rev deltas from the directory change
stream (#1173). A view at `dir_rev=42` that receives deltas for `dir_rev=43`
(entry added), `dir_rev=44` (entry renamed), `dir_rev=45` (entry removed)
applies them in order and updates its token to `{ DirRev, 45 }`.

### 4.2 Path Lookup View

| Property | Value |
|---|---|
| **View class** | `PathLookup` (2) |
| **Key** | `(parent_inode_id: u64, name_hash: u64, name_bytes: &[u8])` |
| **Content** | Target `(inode_id, generation, kind)` |
| **Token kind** | `TreeRoot` |
| **Complete?** | When positive hit: yes. When negative: no (must fall through to authoritative lookup for negative proof) |
| **Rebuild trigger** | `tree_root_ptr != token.value` |

**Purpose**: Accelerate single-component name → inode resolution (`lookup`).
Hot paths that repeatedly access the same files (e.g., `stat`, `open`)
benefit from this view. The token is `TreeRoot` rather than `DirRev` because
a path lookup can cross directory boundaries — any namespace mutation

**Content model**: Stores the resolved target inode. A path lookup view
is a positive cache only; it cannot prove that a name does not exist.
Negative proof requires the `MissingPath` view (below).

**Incremental refresh**: Not incrementally refreshable for the `TreeRoot`
the path through the directory index.

### 4.3 Negative Cache (MissingPath) View

| Property | Value |
|---|---|
| **View class** | `MissingPath` (3) |
| **Key** | `(parent_inode_id: u64, name_bytes: &[u8])` |
| **Content** | Empty — the presence of the entry proves absence |
| **Token kind** | `DirRev` (keyed on parent directory's dir_rev) |
| **Complete?** | Yes — can prove ENOENT |
| **Rebuild trigger** | `parent.dir_rev >= token.value` |

**Purpose**: Accelerate negative lookups. Applications that repeatedly check
for lock files, temp files, or configuration files that don't exist benefit
from avoiding repeated authoritative directory scans.

**Content model**: The view entry itself is the proof — its key is the
`(parent, name)` pair and its existence in the cache lattice means "this name
does NOT exist in this directory." When any entry is added to the parent
might now exist.

**Interaction with Directory Listing View**: The directory listing view
(§4.1) is a superset of negative cache information — if a complete directory
listing view is fresh, it can answer both positive and negative lookups.
The `MissingPath` view exists as a lightweight alternative for directories
where building a full listing view is too expensive (very large directories).

### 4.4 Hierarchy Manifest View

| Property | Value |
|---|---|
| **View class** | `HierarchyManifest` (1) |
| **Key** | `(subtree_root_inode_id: u64, subtree_rev: u64)` |
| **Content** | Aggregate statistics: total files, total dirs, total bytes, deepest path, hottest subtree hints |
| **Token kind** | `TreeRoot` |
| **Complete?** | No — aggregate statistics only; must not be used for per-entry correctness |
| **Rebuild trigger** | `tree_root_ptr != token.value` |

**Purpose**: Accelerate `statfs`, quota checks, `du`, and admin tree-walk
operations. Instead of recursively walking a subtree to compute aggregate
statistics, the manifest provides a cached snapshot.

**Content model**:

```rust
pub struct HierarchyManifestContent {
    pub subtree_root_inode_id: u64,
    pub subtree_rev: u64,
    pub total_regular_files: u64,
    pub total_directories: u64,
    pub total_symlinks: u64,
    pub total_special_nodes: u64,
    pub total_logical_bytes: u64,
    pub deepest_path_components: u32,
    pub largest_file_inode_id: u64,
    pub largest_file_bytes: u64,
    pub hottest_subtree_hints: [HotSubtreeHint; 8],
}
```

**Incremental refresh**: Not incrementally refreshable at the TreeRoot level.
Rebuilds by walking the directory index recursively. For large subtrees,
rebuild is deferred to background work with a `WorkBudget`.

### 4.5 Hot-Read Prefetch View

| Property | Value |
|---|---|
| **View class** | `HotReadPrefetch` (5) |
| **Key** | `(inode_id: u64, offset_hint: u64)` |
| **Content** | Next expected read offsets, extent map snippets |
| **Token kind** | `CommitGroupRange` |
| **Complete?** | No — advisory only; never used for correctness |
| **Rebuild trigger** | Writes fall in the tracked commit_group range |

**Purpose**: Accelerate sequential read detection and prefetch (#1247).
Tracks recent read patterns and predicts which extents to prefetch.

### 4.6 Block Export Map View

| Property | Value |
|---|---|
| **View class** | `BlockExportMap` (6) |
| **Key** | `(volume_id: u64, lba_range_start: u64)` |
| **Content** | LBA → extent mapping for block-volume export |
| **Token kind** | `Snapshot` |
| **Complete?** | No — extent maps can change between snapshots |
| **Rebuild trigger** | New snapshot created since last build |

**Purpose**: Accelerate block-volume export (`zfs send` equivalent) by
caching the LBA-to-extent mapping for a snapshot. Rebuilds when a new
snapshot is created.

---

## 5. Construction and Rebuild

### 5.1 Build lifecycle

```
                 ┌──────────────────┐
                 │   View access    │
                 │ (readdir/lookup) │
                 └────────┬─────────┘
                          │
                    ┌─────▼──────┐
                    │ Token valid?│
                    └──┬───────┬──┘
                       │YES    │NO
                  ┌────▼──┐ ┌──▼──────────┐
                  │ Serve │ │ View is      │
                  │ view  │ │ stale        │
                  └───────┘ └──┬───────────┘
                               │
                         ┌─────▼──────────┐
                         │ Can refresh    │
                         │ incrementally? │
                         └──┬──────────┬──┘
                            │YES       │NO
                      ┌─────▼───┐ ┌───▼──────────┐
                      │ Apply   │ │ Full rebuild  │
                      │ deltas  │ │ from auth      │
                      └─────┬───┘ │ state          │
                            │     └───┬────────────┘
                            │         │
                      ┌─────▼─────────▼──┐
                      │ Update token     │
                      │ Persist to       │
                      │ cache lattice    │
                      └──────────────────┘
```

### 5.2 Full rebuild

A full rebuild constructs the view from authoritative state:

1. Acquire a consistent snapshot of authoritative state (the current commit_group
   or a committed checkpoint).
2. Scan the relevant authoritative structure (directory B+tree, inode
   records, etc.).
3. Build the view content in memory, bounded by `WorkBudget`.
4. Compute the ValidityToken from the authoritative state snapshot.
5. Persist the view as a cache entry.

For a directory listing view:
```
fn full_rebuild_dir_listing(dir_inode_id, budget) -> ViewResult {
    let dir = read_dir_inode(dir_inode_id);
    let auth_state = snapshot_authoritative_state();
    let token = ValidityToken { kind: DirRev, value: auth_state.dir_rev };

    let mut entries = Vec::new();
    let mut budget_consumed = WorkBudgetConsumed::default();

    for entry in dir.scan_entries() {
        entries.push(entry);
        budget_consumed.items += 1;
        if budget_consumed.exceeds(budget) {
            return ViewResult::Incomplete { entries, token };
        }
    }

    ViewResult::Complete { entries, token }
}
```

### 5.3 Incremental refresh (DirRev only)

For `DirRev`-token views (directory listing, negative cache), incremental
refresh applies deltas from the directory change stream (#1173):

```
fn incremental_refresh(view, budget) -> ViewResult {
    let current_dir_rev = get_dir_rev(view.dir_inode_id);
    let view_dir_rev = view.token.value;

    if current_dir_rev == view_dir_rev {
        return ViewResult::AlreadyCurrent;
    }

    // Check if gap is small enough for incremental refresh
    let gap = current_dir_rev - view_dir_rev;
    if gap > MAX_INCREMENTAL_GAP || gap == 0 {
        return full_rebuild(view, budget); // fall back
    }

    // Apply deltas from view_dir_rev+1 to current_dir_rev
    let mut entries = view.entries.clone();
    for rev in (view_dir_rev + 1)..=current_dir_rev {
        let delta = read_dir_change_stream(view.dir_inode_id, rev);
        match delta {
            DirDelta::EntryAdded { name, inode_id, entry_type, cookie } => {
                entries.insert_sorted(name, inode_id, entry_type, cookie);
            }
            DirDelta::EntryRemoved { name } => {
                entries.remove_by_name(name);
            }
            DirDelta::EntryRenamed { old_name, new_name, inode_id } => {
                entries.remove_by_name(old_name);
                entries.insert_sorted(new_name, inode_id, ...);
            }
        }
        budget_consumed.items += 1;
        if budget_consumed.exceeds(budget) {
            // Could not finish incremental refresh under budget
            return ViewResult::IncrementalPartial {
                entries,
                applied_up_to_rev: rev - 1,
                token: ValidityToken { kind: DirRev, value: rev - 1 },
            };
        }
    }

    ViewResult::Complete {
        entries,
        token: ValidityToken { kind: DirRev, value: current_dir_rev },
    }
}
```

### 5.4 When to prefer full rebuild over incremental

Incremental refresh is preferred when the gap is small and the change stream
entries are available. Fall back to full rebuild when:

- Gap > `MAX_INCREMENTAL_GAP` (default: 256 deltas)
- Change stream entries are missing (log truncated or compacted)
- The view content is corrupted or inconsistent
- The view token kind does not support incremental refresh (TreeRoot,
  Snapshot, CommitGroupRange)

### 5.5 WorkBudget integration

Every `step()` of view construction/refresh accepts a `WorkBudget`:

| Budget dimension | What it limits |
|---|---|
| `max_items` | Directory entries scanned, deltas applied, inodes resolved |
| `max_bytes` | Bytes read from authoritative structures, bytes written to view cache |
| `max_ms` | Wall-clock time spent in this step (soft limit, yields at next safe point) |

**Construction budget priority**: View rebuilds run at `ServicePriority::Maintenance`
or `ServicePriority::Opportunistic` in the background scheduler (#1241). They never
compete with demand IO at `Critical` or `High` priority.

**Preemption**: A view rebuild that exceeds its budget mid-step must yield and
save an `IncrementalJob` checkpoint. The next tick resumes from the checkpoint.
This uses the same `IncrementalJob` trait that all background work implements
(#1239).

```rust
impl IncrementalJob for DirectoryListingViewRebuildJob {
    fn step(&mut self, budget: WorkBudget) -> Result<StepResult, JobError> {
        // Apply up to budget.max_items deltas
        // Persist checkpoint after each step
        // Return StepResult::in_progress or StepResult::complete
    }

    fn resume(checkpoint: Option<Checkpoint>) -> Result<Self, JobError> {
        // Resume from saved checkpoint after crash or preemption
    }
}
```

### 5.6 Construction triggers

| Trigger | When | Priority |
|---|---|---|
| **On-demand** | First `readdir` or `lookup` hits a cold view | Immediate (on critical path) |
| **Proactive** | Background scheduler picks up stale view rebuild | Maintenance |
| **Prefetch** | Workload signature predicts future access | Opportunistic |

---

## 6. Budget Integration

### 6.1 Memory budget: `meta_cache` domain

Derived views consume memory from the `meta_cache` budget category in the
unified resource governor (#1237). This is distinct from `data_cache` (which
holds content chunks in `hot_read_cache`).

| Budget category | What it holds | View types |
|---|---|---|
| `meta_cache` | Derived views, inode cache, directory index cache | Directory listing, path lookup, negative cache, hierarchy manifest |
| `data_cache` | Content chunk ARC, prefetch L2 | Hot-read prefetch |
| `auth_cache` | Authority mirrors, immutable state | (not views) |

### 6.2 Eviction priority under pressure

When `meta_cache` is under pressure, derived views are evicted in order:

1. **Hot-read prefetch views** — advisory, never correctness-critical
2. **Cold directory listing pages** — LRU-evicted; large directories may be
   partially evicted (drop oldest pages first)
3. **Path lookup views for cold subtrees** — infrequently accessed paths
4. **Negative cache views** — losing these just means more authoritative lookups
5. **Hierarchy manifest views** — expensive to rebuild, protected longer
6. **Hot directory listing views** — protected as long as possible; these are
   the most latency-sensitive

### 6.3 Budget domain string

All derived views use the budget domain string `"derived_views"`. The
pool-level knob `derived_bytes_budget_per_pool` governs this domain.
Default: 128 MiB per pool, tunable via `tidefs pool set derived_bytes_budget=...`.

---


### 7.1 The problem

In cluster mode, a follower node holds a SHARED dataset lease and serves
reads from its local cache. When the writer commits a commit_group that mutates
metadata, the follower's derived views become stale. The follower must detect

### 7.2 How it works

from writer to follower. Each event carries a `(dataset_id, inode_id, new_dir_rev)`
tuple or a `(dataset_id, tree_root_ptr)` tuple.

On the follower:

```
    match event.kind {
            // Mark all DirRev-token views for this directory as stale
                ValidityToken { kind: DirRev, value: /* any token with value < new_dir_rev */ }
            );
        }
            // Mark all TreeRoot-token views as stale
                ValidityToken { kind: TreeRoot, value: /* any token with value != new_tree_root_ptr */ }
            );
        }
            // RESYNC: drop all views for this dataset
            cache_lattice.drop_all_views_for_dataset(event.dataset_id);
        }
    }
}
```


only views keyed on `(dataset_id, inode=42, dir_rev < 101)`. Other
directories' views are unaffected.

### 7.4 Close-to-open freshness barrier

When a follower opens a file, it gates the OPEN response on catching up to
subsequent `readdir` or `lookup` on the follower sees fresh data.

---

## 8. Interaction with the Cache Stack

### 8.1 Where views sit

```
┌────────────────────────────────────┐
│         FUSE daemon / VFS_RPC      │
├────────────────────────────────────┤
│  Cache lattice (entry header law)  │
│  ┌──────────────────────────────┐  │
│  │  Derived Views (this design) │  │
│  │  - Dir listing pages         │  │
│  │  - Path lookup               │  │
│  │  - Negative cache            │  │
│  │  - Hierarchy manifest        │  │
│  │  - Hot-read prefetch         │  │
│  │  - Block export map          │  │
│  ├──────────────────────────────┤  │
│  │  Inode cache (ARC)           │  │
│  │  Hot read cache (ARC)        │  │
│  └──────────────────────────────┘  │
├────────────────────────────────────┤
│  Authoritative on-disk state       │
│  - Directory B+trees               │
│  - Inode records                   │
│  - Directory change streams        │
│  - Extent maps                     │
└────────────────────────────────────┘
```

### 8.2 Views vs. authoritative caches

The existing ARC caches (`hot_read_cache`, `inode_cache`) cache authoritative
data (content chunks, inode metadata). They are NOT views — they are mirrors
of authoritative state with no ValidityToken, no rebuildability, and different
eviction semantics.

Views complement them by caching derived results (directory listings, path
resolutions, subtree aggregates) that are too expensive to recompute on every
access but are not themselves authoritative.

### 8.3 View dependency on inode cache

View rebuilds read authoritative state through the inode cache. If the inode
cache has the relevant inodes hot, view rebuild is fast (no disk IO). If the
inode cache is cold, view rebuild includes the cost of authoritative reads.
The `ViewBuildCost.authoritative_reads` counter captures this.

---

## 9. Memory Domain: DerivedViews

A new memory domain is defined:

```rust
pub enum MemoryDomainId {
    // ... existing 8 domains (0-7) ...
    /// Derived views: precomputed answers to cache-lattice queries.
    /// Rebuildable from authoritative state. Eligible for eviction
    /// under budget pressure. Reclaim priority: 75.
    DerivedViews = 8,
}
```

| Property | Value |
|---|---|
| Reclaim priority | 75 (between `AdapterServingHot` at 100 and `ProductServing` at 50) |
| Protected reserve eligible | No |
| Eviction class | `SurplusOnly` |
| Dirty state | `Clean` (views are read-only) |

---

## 10. Data Structures

### 10.1 View entry on disk

A derived view is stored as a cache lattice entry with:

```
┌────────────────────────────────────┐
│  CacheEntryHeader (18 fields)       │
│  ├── cache_class_id             2B │
│  ├── memory_domain_id           1B │
│  ├── exactness_class            1B │
│  ├── freshness_class            1B │
│  ├── rebuild_cost_class         1B │
│  ├── birth_counter              8B │
│  ├── last_hit_counter           8B │
│  ├── anchor_vector_ref          8B │  ← ValidityToken hash
│  ├── entry_size_bytes           4B │
│  ├── budget_domain_ref          4B │
│  ├── reserve_guard_class        1B │
│  ├── dirty_state_class          1B │
│  ├── evictability_class         1B │
│  ├── poison_state               1B │
│  └── (pad + flags)              6B │
├────────────────────────────────────┤
│  ValidityToken (embedded)      10B │
│  ├── kind (u8)                  1B │
│  ├── reserved (u8)              1B │
│  └── value (u64, LE)            8B │
├────────────────────────────────────┤
│  View payload (variable)           │
│  ├── ViewClass discriminator    1B │
│  ├── content_length             4B │
│  └── content bytes             ... │
└────────────────────────────────────┘
```

### 10.2 View registry

At startup, the local filesystem discovers existing views by scanning cache
lattice entries with `memory_domain_id = DerivedViews` and
authoritative state; stale views are queued for background refresh.

---

## 11. Observability

### 11.1 Per-class counters

| Metric | Description |
|---|---|
| `view_stale_on_access_total{class}` | View was stale when accessed |
| `view_full_rebuilds_total{class}` | Full rebuilds performed |
| `view_incremental_refreshes_total{class}` | Incremental refreshes performed |
| `view_incremental_fallback_total{class}` | Incremental refresh fell back to full rebuild |
| `view_build_budget_exceeded_total{class}` | Build/refresh could not complete within budget |
| `view_evictions_total{class}` | Views evicted under memory pressure |
| `view_hits_total{class}` | Cache hits (view was valid on access) |
| `view_incomplete_negative_fallthrough_total` | Incomplete view positive hit, authoritative fallback for negative proof |
| `derived_views_bytes` | Current total bytes consumed by derived views |

### 11.2 Completeness observability

The `exactness_class` field in `CacheEntryHeader` makes completeness
observable. An `"incomplete"` view means budget exhaustion or a partial
build — the view can serve positive hits but not negative proofs.

---

## 12. Non-Claims

This design does not cover:

- **Cross-node view sharing**: Views are local to each node. Multi-node
  view transfer.
- **View prefetch heuristics**: Workload-signature-driven prefetch of
  views is covered by the prefetch architecture (#1247).
- **Encrypted or compressed view payloads**: Deferred to encryption
  (#1246) and compression (#1245) designs.
- **Persistent view snapshots for send/receive**: Using derived views to
  accelerate dataset send/receive (#1251) is a future optimization.
- **View migration on writer failover**: When the writer lease moves to a
  new node, views must be rebuilt from scratch on the new writer.
  multi-writer view coherence is future work.
- **Production RDMA data path for view transfer**: Transport-level view
  passes.
  coherency design (#1259).

---

## 13. Implementation Plan

### Phase 1: ValidityToken types (no-std authority crate)

1. Add `ValidityToken` and `ValidityTokenKind` to
   `tidefs_types_cache_lattice_core` (or a new
   `tidefs_types_derived_view_core` if preferred).

### Phase 2: View entry persistence in cache lattice

2. Extend `tidefs_local_filesystem/src/cache_lattice.rs` with view entry

### Phase 3: View types implementation

3. Implement `DirectoryListingView` with full rebuild and incremental
   refresh from directory change streams (#1173).
4. Implement `PathLookupView` with TreeRoot token.
5. Implement `MissingPathView` (negative cache) with DirRev token.
6. Implement `HierarchyManifestView` with TreeRoot token.

### Phase 4: Budget and scheduler integration

7. Wire view rebuilds into the background scheduler as
   `IncrementalJobAdapter<ViewRebuildJob>` instances.
8. Add `meta_cache` budget tracking for derived views in the resource
   governor (#1237).

### Phase 5: Cluster integration

10. Implement close-to-open freshness barrier.

---

## 14. References

- `crates/tidefs_types_cache_lattice_core/src/lib.rs` — Cache lattice authority types (8 domains, 9 classes, 18 header fields, dirty-state machines)
- `crates/tidefs_local_filesystem/src/cache_lattice.rs` — Cache lattice runtime scaffolding (P4-02)
- `crates/tidefs_local_filesystem/src/lib.rs` — Local filesystem implementation including `InodeAttr.dir_rev`
- `crates/tidefs_types_vfs_core/src/lib.rs` — `InodeAttr`, `InodeId`, `NodeKind`, `DirEntry`, `Generation`
- `crates/tidefs_types_incremental_job_core/src/lib.rs` — `WorkBudget`, `Checkpoint`, `StepResult`, `CursorState`
- `crates/tidefs_incremental_job_core/src/lib.rs` — `IncrementalJob` trait with step/resume/complete lifecycle
- `crates/tidefs_background_scheduler/src/lib.rs` — Background scheduler with 5-stage priority ordering
- `crates/tidefs_dir_index/src/lib.rs` — Runtime polymorphic directory index (micro-list / B+tree)
- `docs/design/cache-lattice-views.md` — Cache-lattice views design (#1176)
- `docs/design/prefetch-readahead-budgeted-speculative-io.md` — Prefetch/readahead architecture (#1247)
- `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` — Current document authority classification register; this design remains historical input unless classified there
- GitHub issues and pull requests — Current implementation coordination and status surface
- Issue #1173 — Directory change streams (authoritative feed for incremental refresh)
- Issue #1237 — Unified resource governor (budget integration)
- Issue #1239 — Universal incremental cursor framework (rebuild job model)
- Issue #1241 — Background service framework (scheduling)
- Issue #1247 — Prefetch architecture (hot-read prefetch view consumer)
