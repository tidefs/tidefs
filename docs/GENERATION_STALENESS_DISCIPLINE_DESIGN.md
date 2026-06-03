# Generation-Based Staleness Discipline Design (P1 spec-draft)

Maturity: **spec-draft** for the unified fence model that prevents stale
answers across all cache layers, enforces crash-safe update ordering, and

This document closes Forgejo issue #1242.

## 1. Motivation

TideFS uses at least seven distinct cache and acceleration layers, each of
which can serve stale data if not explicitly fenced:

- Record cache: in-memory cache of object-store record payloads
- B-tree node cache: cached B-tree pages across all index types
- Inode cache: cached inode attributes and extent map pointers
- Derived views: materialized results like readdir output, ValidityToken-gated
- Extent map cache: cached byte-range-to-physical mappings
- Hot read cache: LRU content cache for repeated reads
- Daemon-space InodeState: per-inode generation counters in the FUSE daemon

Without a cross-cutting staleness discipline, each cache layer risks
independently inventing (or forgetting) its staleness fence, leading to:

- **Stale-after-reuse bugs:** A cache entry from before a segment recycle
  or pointer rewrite is served as valid after the recycle.
- **Crash-induced staleness:** Fence updated before (not after) the
  protected data is committed, leaving the cache permanently stale
  after restart.
- **Cluster drift:** Fence changes on a writer node are not propagated
  to reader nodes, allowing readers to serve stale cached data.

This design formalizes the staleness discipline as a hard architectural
rule enforced at review time and (eventually) by a lint gate.

### 1.1 ZFS/Ceph anti-patterns addressed

| Anti-pattern | ZFS | Ceph | TideFS response |
|---|---|---|---|
| Ceph OSD cache coherency is lease-based but has no unified staleness model across layers | N/A | Present | Six canonical fence types mapped uniformly across all layers |

## 2. The Staleness Discipline Rule

Every cache or acceleration structure that caches data from authoritative
state MUST define three elements:

1. **A staleness fence:** a monotonic value that, when changed relative to
   the cached entry's recorded fence, proves the cached data is stale.
   to be incremented.

A cache entry is defined as valid only when `entry.fence == current_fence`.
Any mismatch means the entry is stale and must be discarded.

## 3. Canonical Fence Types

Six fence types cover every cache layer in TideFS:

### 3.1 SegmentGeneration

| Property | Value |
|---|---|
| What it protects | Record cache payloads keyed by (segment_index, offset) |
| Monotonic source | Segment header `generation` field, incremented on segment recycle |

Segment reuse is the hardest staleness problem: after a segment is retired
and recycled, a stale cache entry keyed by `(old_segment_index, offset)`
would collide with a new record at the same offset. The `SegmentGeneration`
fence prevents this: the cache key includes the generation, so the old
entry will never match the new generation.

### 3.2 TreeRootPtr

| Property | Value |
|---|---|
| What it protects | B-tree node caches, inode caches, directory block caches |
| Monotonic source | Root pointer (LocatorId) updated at every commit that modifies the tree |

A B-tree root pointer changes whenever the tree's root page is modified
(typically on every structural mutation). This means a cache entry from
cache no longer matches the current root pointer.

For read-only caches (e.g., a B-tree from a snapshot), the root pointer is
stable and cached entries remain valid indefinitely.

### 3.3 InodeGeneration

| Property | Value |
|---|---|
| What it protects | Per-inode cached state: attributes, extent map decode, file size |
| Monotonic source | Per-inode `generation: u64` field incremented on any mutation |

The `InodeGeneration` is stored in the inode record itself and is
incremented as part of any mutating transaction. When the FUSE daemon
caches inode attributes, it stores `(inode_id, inode_generation, attrs)`.
On next access, it compares the cached generation against the inode
record's current generation.

### 3.4 DirRev

| Property | Value |
|---|---|
| What it protects | Directory listing caches, derived readdir views, ValidityToken-gated materializations |
| Monotonic source | Per-directory `dir_rev: u64` field incremented on any entry add/remove/rename |

`DirRev` is stored in the directory inode record. A `ValidityToken`
captures `(dir_inode_id, dir_rev)` at cache-creation time. Before using
a cached directory listing, the token is checked: if `current.dir_rev !=
token.dir_rev`, the listing is regenerated.

### 3.5 CommitGroupSequence

| Property | Value |
|---|---|
| What it protects | Writeback buffers, dirty state assumptions, uncommitted data |
| Monotonic source | Pool-global commit_group counter, incremented at each transaction group boundary |

The `CommitGroupSequence` fence gates writeback caches and dirty-state tracking.
A cached "dirty and uncommitted" flag from commit_group N is invalid if the current
commit_group is > N. This prevents serving dirty-cached data that was lost in a
crash before the commit_group committed.

### 3.6 LeaseEpoch

| Property | Value |
|---|---|
| What it protects | Cluster-side caches on reader nodes |
| Monotonic source | Cluster lease manager: epoch incremented on lease grant/recall |

`LeaseEpoch` is a cluster-wide fence type for distributed cache coherency.
When a writer node takes a lease, the epoch is incremented. Reader nodes
A cached entry with `epoch < current_epoch` is stale.

## 4. Combined Fences

Some caches require multiple fences. The cache entry is valid only if ALL
fences match:

```
ExtentMapCacheEntry {
    extent_map_root_ptr: LocatorId,  // TreeRootPtr fence
    locator_table_root_ptr: LocatorId,  // TreeRootPtr fence for locator table
    inode_id: u64,
    cached_extent: ExtentMapEntryV2,
}
```

If either `extent_map_root_ptr` or `locator_table_root_ptr` differs from
the current authoritative root pointers, the entire cache entry is invalid.

```
fn is_valid(&self, current_map_root: LocatorId, current_locator_root: LocatorId) -> bool {
    self.extent_map_root_ptr == current_map_root
        && self.locator_table_root_ptr == current_locator_root
}
```

### 4.1 Combined fence rules

2. If any fence in the set changes, the entry is discarded — there is no
3. Combined fences are documented in the cache entry type definition with
   both fence types and their monotonic sources.



The staleness fence must be checked BEFORE cached data is consumed, never
after. The check occurs at cache load time:

```
fn cache_get(key: &CacheKey) -> Option<&CachedValue> {
    let entry = self.inner.get(key)?;
    if !entry.is_valid(self.current_fence()) {
        self.inner.remove(key);
        return None;
    }
    Some(&entry.value)
}
```

This prevents TOCTOU races where a fence changes between the cache hit
and the actual use of the cached value.

### 5.2 Eviction on fence mismatch

When a fence check fails, the entry is evicted immediately (not lazily).
This keeps the cache free of dead entries and prevents accumulation of
stale data that could confuse debugging or observability.

### 5.3 Fence propagation ordering (critical for crash safety)

The fence must be updated AFTER the authoritative data it protects is
committed, never before. The canonical ordering is:

1. Write new authoritative data to the transaction.
2. Commit the transaction (data is now durable).
3. Increment the fence value as part of the same transaction or a
   subsequent one that commits atomically.

Incorrect ordering (fence updated before data is committed):

```
// WRONG: crash between fence update and data commit
commit_group.begin();
self.fence = new_fence;           // fence updated
// ... crash here ...
commit_group.write(new_data);              // data never committed
commit_group.commit();
// After restart: fence is new, but data is old. Cache entries with
// the new fence with old data. Catastrophic staleness.
```

Correct ordering:

```
// CORRECT: data committed first, then fence updated
commit_group.begin();
commit_group.write(new_data);              // data written
commit_group.commit();                     // data is durable
// Now increment fence in a subsequent commit_group, or as part of the commit
// record update in the same commit_group (the commit record is the last thing
// written).
self.fence = new_fence;           // fence updated atomically with commit
```

The commit_group commit ordering design (#1267) already specifies a seven-step
pipeline where all data is committed before the commit record. Fence
updates piggyback on the commit record (step 4: APPEND commit record in
the pipeline), ensuring atomicity:

- If the commit_group crashes before the commit record is written, the old fence
- If the commit_group completes, the new fence is visible and cache entries with
  the old fence are correctly evicted.

## 6. Fence Lifecycle

### 6.1 Fence creation

A fence is created alongside its protected resource:
- `SegmentGeneration` is initialized to 0 on segment allocation.
- `TreeRootPtr` is initialized to the root pointer of the initial (empty) tree.
- `InodeGeneration` is initialized to 1 on inode creation.
- `DirRev` is initialized to 1 on directory creation.
- `CommitGroupSequence` is initialized to 1 on pool creation.
- `LeaseEpoch` is initialized to 0; incremented on first lease grant.

### 6.2 Fence persistence

All fences are persistent and survive restarts:
- `SegmentGeneration` is stored in the segment header.
- `TreeRootPtr` is stored in the tree metadata.
- `InodeGeneration` and `DirRev` are stored in the inode record.
- `CommitGroupSequence` is stored in the pool superblock.
- `LeaseEpoch` is stored in the cluster membership state.

### 6.3 Fence monotonicity

All fences are strictly monotonic (only increase). This is enforced by
the fence update path: if a proposed new fence value is not greater than
the current value, the update is rejected. This prevents accidental
fence regression from bugs in the update path.

### 6.4 Fence wrap-around

Fences are 64-bit unsigned integers. At realistic increment rates (one
per mutation per inode, or one per commit_group), wrap-around is not a concern
within the lifetime of a dataset. The design does not include wrap-around
handling because it is not practically reachable.


In cluster mode, fence changes on the writer node are distributed to

|---|---|---|---|
| SegmentGeneration | Not distributed (segment caches are local to the object store) | Local only | N/A |

operation on the affected scope. This is enforced by the coherency
profile: in `strict` and `cluster` profiles, readers must drain the
cached data.

## 8. Relationship to Existing Issues

| Issue | Relationship |
|---|---|
| #1240 (derived views) | ValidityToken uses DirRev as its staleness fence |
| #1206 (lock hierarchy) | Per-resource lock revision counters are staleness fences too |
| #1237 (unified resource governor) | Cache eviction must respect staleness fences; stale entries evicted before live ones |
| #1267 (commit_group commit ordering) | Fence update ordering is critical and dependent on the seven-step commit pipeline |
| #1184 (coherency profiles) | Which fences are distributed vs. local depends on the active profile |
| #1224 (torn-commit recovery) | Fence update ordering is part of the crash-safety contract |
| #1226 (cache architecture) | The unified cache layer uses these fences for all cache types |

## 9. Implementation Plan

This is a **spec-draft**. Implementation is deferred to a continuation issue.

### 9.1 Implementation phases (future)

1. **Phase A — Fence type definitions:** Define `SegmentGeneration`,
   `TreeRootPtr`, `InodeGeneration`, `DirRev`, `CommitGroupSequence`, `LeaseEpoch`
   as newtype wrappers with monotonic increment semantics.
2. **Phase B — Cache key integration:** Extend all cache key types to
   include their fence values. `RecordCacheKey` gets `segment_generation`;
   `BtreeNodeCacheKey` gets `root_ptr`; `InodeCacheKey` gets
   `inode_generation`; etc.
   lookup. Implement `CacheEntry::is_valid()` that compares stored fence
   against current authoritative fence.
4. **Phase D — Fence update ordering:** Wire fence increments into the
   commit_group commit pipeline after data commit, per #1267 ordering contract.
   Add crash tests for fence-before-data bugs.
5. **Phase E — Combined fence support:** Implement combined fence types
   for extent map cache and any other multi-fence caches.
   processing with coherency-profile gating.
7. **Phase G — Lint gate:** Implement a compile-time or review-time check
   that every cache entry type declares its fence types.

### 9.2 Dependencies

- #1267 (commit_group commit ordering) for fence update ordering in the commit pipeline.
- #1226 (cache architecture) for the unified cache layer.


| Gate | Description |
|---|---|
| `segment-generation-prevents-reuse-staleness` | Recycle a segment, verify old cache entries for that segment are evicted |
| `combined-fence-both-required` | Change either fence in a combined set, verify entry is evicted |

## 11. Design Decisions and Rationale

### 11.1 Why per-inode generation and not global epoch

but destroys cache hit rates. Per-inode and per-directory generation

### 11.2 Why combined fences, not cascaded

Combined fences (check both root pointers atomically) are preferred over
cache is empty even though only one fence changed. Combined fences evict
only when necessary and repopulate from the authoritative state.

### 11.3 Why fences are in the cache key, not the value

Embedding the fence in the cache key means a lookup for the same logical
resource with a stale fence will naturally miss (the key doesn't
match). This is more robust than storing the fence in the value and
checking after lookup, because it prevents accidental hits from
key-reuse bugs.


this window: the entry is never returned to the caller if the fence
doesn't match.

## 12. References

- v0.262 Python reference: `tidefs_v0.262/docs/tidefs_design_book.md` section "Cache keys and staleness avoidance"
- CommitGroup commit ordering: `docs/design/canonical-commit-ordering-commit_group-state-machine.md` (#1267)
- Coherency profiles: Forgejo issue #1184
- Derived views design: Forgejo issue #1240
- Unified cache architecture: Forgejo issue #1226
- Unified resource governor: Forgejo issue #1237
