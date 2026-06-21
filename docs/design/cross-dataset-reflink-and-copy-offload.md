# Cross-Dataset Reflink and Copy Offload: Lightweight Clone, Server-Side Copy, and Namespace-Spanning Extent Sharing

**Issue**: [#1276](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1276)
**Status**: design-draft
**Maturity**: spec-draft — defines the pool-wide extent sharing architecture for clone, copy offload, and dedup
**Lane**: storage-core
**Prior-art inputs**: ZFS, CephFS, XFS, and Btrfs behavior inform the design
pressure only. This draft does not claim current TideFS reflink/copy-offload
parity, superiority, or production readiness.

## 1. Problem statement

Existing filesystem behavior that motivates this design:

- **ZFS** limits `clonefile` to the same dataset; cross-dataset requires send/recv (full data copy).
- **CephFS** has no reflink primitive at all.
- **XFS/Btrfs** support cross-reflink within a filesystem but not across subvolumes.

The TideFS design target is **pool-wide extent sharing** where two datasets,
clones, or snapshots can reference the same physical extent bytes through a
pool-wide `ExtentId`, making cross-dataset reflink a metadata operation with
cost proportional to the number of extent records rather than payload size.

## 2. Scope and non-scope

### In scope

- Pool-wide `ExtentId` naming that decouples extent identity from dataset ownership
- Cross-dataset reflink (`clone_file`) as a metadata-only operation committed in a single commit_group
- Server-side copy offload (`copy_file_range`) with boundary-partial read+write
- Atomic commit_group-boundary commit for clone and copy operations
- Integration with pool-wide refcount table (#1180) for shared extent lifecycle
- Snapshot deadlist integration (#1232) for reflinked extent lifecycle
- Post-process dedup backfill path (#1255) that discovers sharing opportunities across datasets
- Bulk-plane fallback for cross-pool copy (#1229)

### Explicitly out of scope

- Reflink across pools (requires BULK send, tracked in #1229)
- Zero-copy network reflink between cluster nodes (deferred to distributed fs layer)
- Directory-level reflink (individual files only in v1)
- Reflink of files with active writable mappings (must quiesce first)
- Reflink of encrypted files across encryption-domain boundaries (deferred to encryption policy layer)

## 3. Architectural foundation: pool-wide ExtentId

### 3.1 Why pool-scoped extent IDs

The V1/V2/V3 extent maps in `tidefs-types-extent-map-core` carry an `ExtentId` field per entry, but the ID is allocated per-dataset — each dataset maintains its own ID namespace. This mirrors ZFS's design constraint: a block pointer references a physical DVA (Data Virtual Address) scoped to the dataset, preventing sharing across dataset boundaries.

The architectural fix is to allocate `ExtentId` from a **single pool-wide counter**. Two datasets can independently reference the same `ExtentId`, each pointing to the same physical `LocatorId` and sharing the same payload bytes.

```
┌─────────────────────────────────────────────────────────┐
│                    POOL                                  │
│  ┌──────────────────┐  ┌──────────────────┐             │
│  │   Dataset A       │  │   Dataset B       │             │
│  │  extent_map:      │  │  extent_map:      │             │
│  │   off=0,len=4096, │  │   off=0,len=4096, │             │
│  │   extent_id=42    │  │   extent_id=42    │  ← shared!  │
│  │   locator_id=7    │  │   locator_id=7    │             │
│  └────────┬──────────┘  └────────┬──────────┘             │
│           │                      │                        │
│           └──────────┬───────────┘                        │
│                      ▼                                    │
│           ┌──────────────────┐                            │
│           │  Locator Table    │                            │
│           │  id=7 → segment 3 │                            │
│           │         offset 1024                           │
│           └──────────────────┘                            │
│                      │                                    │
│           ┌──────────▼──────────┐                         │
│           │ Pool Refcount Table │                         │
│           │ extent_id=42 → 2    │  ← refcount=2          │
│           └─────────────────────┘                         │
└─────────────────────────────────────────────────────────┘
```

### 3.2 Extent lifecycle state machine

Pool-wide extent IDs follow a lifecycle governed by the refcount table, snapshot deadlist, and reclaim queue:

```
                       ┌──────────────────────┐
                       │      ALLOCATE         │
                       │ extent_id ← counter   │
                       │ refcount ← 1          │
                       │ birth_commit_group ← current   │
                       └──────────┬────────────┘
                                  │
                                  ▼
                       ┌──────────────────────┐
                       │       ACTIVE          │
                       │ refcount ≥ 1          │
                       │ referenced by ≥1      │
                       │ dataset or snapshot   │
                       └──────────┬────────────┘
                                  │
                ┌─────────────────┼─────────────────┐
                ▼                 ▼                  ▼
         ┌────────────┐   ┌─────────────┐   ┌──────────────┐
         │  REFLINK    │   │  OVERWRITE   │   │   SNAPSHOT    │
         │ refcount++  │   │  (CoW path)  │   │   CAPTURE     │
         └──────┬──────┘   │ new ext alloc │   │ (pin via      │
                │          │ old refcount--│   │  deadlist)    │
                │          └──────┬───────┘   └──────┬────────┘
                ▼                 │                  │
         ┌──────────────────────┐│                  │
         │ SHARED (refcount>1)  │◄──────────────────┘
         │ referenced by        │
         │ multiple datasets    │
         └──────────┬───────────┘
                    │
          ┌─────────┼──────────┐
          ▼         ▼          ▼
    ┌─────────┐ ┌───────┐ ┌──────────┐
    │ UNLINK  │ │TRUNC  │ │SNAP DEST │
    │ ref--   │ │ ref-- │ │deadlist  │
    └────┬────┘ └───┬───┘ │process   │
         │          │     └────┬─────┘
         ▼          ▼          ▼
    ┌────────────────────────────────┐
    │ refcount == 0 ?                │
    │ YES → death_commit_group ← current      │
    │   → check snap_commit_group_index       │
    │   → pinned? → deadlist         │
    │   → free?   → reclaim queue    │
    │ NO  → remains shared           │
    └────────────────┬───────────────┘
                     │
                     ▼
    ┌────────────────────────────────┐
    │  DEAD → FREED                   │
    │  ReclaimQueue (#1180) processes │
    │  Physical space returns to      │
    │  segment allocator              │
    └────────────────────────────────┘
```

### 3.3 On-media representation

The pool-wide refcount table is the authoritative source for extent sharing state. It is stored as a persistent B+tree rooted in the pool superblock, keyed by `ExtentId`:

```rust
/// Pool-wide refcount entry persisted in the pool superblock's refcount btree.
struct ExtentRefcountEntry {
    extent_id: ExtentId,          // 8 bytes, key
    refcount: u64,                // live reference count (dataset + snapshot)
    birth_commit_group: u64,               // commit_group when first allocated
    death_commit_group: u64,               // commit_group when refcount first hit 0 (0 = live)
    locator_id: LocatorId,        // physical placement
    length: u64,                  // extent payload bytes
    checksum: [u8; 32],           // content digest for dedup discovery
}
```

The table is updated atomically within the commit_group commit ordering (see §7). Batch operations allow cloning a file with 10,000 extents to update 10,000 refcount entries as a single atomic batch within one commit_group.

## 4. Cross-dataset reflink (clone_file)

### 4.1 Algorithm

```
clone_file(src_dataset, src_ino, dst_dataset, dst_parent, dst_name):

  PRECONDITIONS:
    - Both datasets belong to the same pool
    - ORG_TIDEFS_CROSS_DATASET_REFLINK feature flag enabled on both datasets
    - src_ino is a regular file, dst_name does not exist in dst_parent
    - Neither dataset is frozen/read-only

  1. READ SOURCE EXTENT MAP
     src_extents = src_dataset.extent_map.lookup_range(0, src_ino.file_size)
     → Vec<(logical_offset, length, extent_id, locator_id)>

  2. BEGIN COMMIT_GROUP (single atomic transaction)
     a. INCREMENT REFCOUNTS
        for each extent_id in src_extents:
            pool.refcount_table.increment(extent_id)
            // Backfill if extent pre-dates pool-wide tracking

     b. CREATE DESTINATION INODE
        dst_ino = dst_dataset.allocate_inode()
        dst_dataset.write_inode(dst_ino, attrs=src_ino.attrs)

     c. INSERT DIRECTORY ENTRY
        dst_dataset.dir_index.insert(dst_parent, dst_name, dst_ino)

     d. COPY EXTENT MAP
        dst_dataset.extent_map = src_dataset.extent_map.clone()
        // Same extent_ids, same locator_ids, shared refcounts

  3. COMMIT COMMIT_GROUP
     All mutations flushed through the 7-step commit ordering.
     Metadata-only path skips steps 1–2 (no new data payloads).

  Returns: dst_ino, commit_group_id
```

### 4.2 Complexity

| Operation | Time | Journal bytes |
|---|---|---|
| Read source extent map | O(num_extents) | 0 |
| Refcount increment | O(num_extents · log N) | num_extents · ~40 bytes |
| Create dst inode + dir entry | O(log D) | ~200 bytes |
| Copy extent map pages | O(num_extents) | num_extents · entry_size |

Total cost is **O(num_extents)**, proportional to the number of extent map entries, **not** file size. A 1 TiB file with 1 MiB extents has only 1,024 entries — reflink is near-instant.

### 4.3 Error handling

If any step fails before commit, the commit_group rolls back:
- Refcount increments are discarded (in-memory only until commit)
- No dst inode, extent map, or directory entry is persisted
- The pool-wide refcount table remains unchanged

Post-commit, the operation is durable — the commit_group state machine guarantees all-or-nothing semantics.

### 4.4 Write amplification and CoW

After a cross-dataset reflink, writes to either copy trigger CoW **at extent granularity** — not whole-file:

```
write(dataset=A, ino=src_ino, offset=8192, length=4096):
  1. Lookup extent at offset 8192 → extent_id=42, refcount=2
  2. refcount > 1 → must CoW
  3. Allocate new extent_id=99, write 4096 bytes of new data
  4. Decrement refcount for extent_id=42 (now refcount=1)
  5. Replace extent map entry: extent_id=42 → extent_id=99
  6. Commit

Dataset B still references extent_id=42 with refcount=1.
Only the 4 KiB modified extent triggers CoW; the rest of the file shares.
```

## 5. Server-side copy offload (copy_file_range)

### 5.1 Taxonomy

```
                    ┌──────────────────────────────────┐
                    │     copy_file_range(src, dst)     │
                    └──────────────────┬───────────────┘
                                       │
                    ┌──────────────────┼──────────────────┐
                    ▼                  ▼                  ▼
             ┌─────────────┐   ┌─────────────┐   ┌──────────────┐
             │ Same pool,   │   │ Same pool,   │   │  Cross-pool  │
             │ extent-aligned│   │ partial      │   │              │
             │              │   │ boundaries   │   │              │
             └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
                    │                  │                  │
                    ▼                  ▼                  ▼
             ┌─────────────┐   ┌─────────────┐   ┌──────────────┐
             │  REFLINK     │   │  Hybrid:     │   │ BULK plane   │
             │  (metadata)  │   │ reflink mid  │   │ fallback     │
             │              │   │ + read/write │   │ (#1229)      │
             │              │   │ boundaries   │   │              │
             └─────────────┘   └──────────────┘   └──────────────┘
```

### 5.2 Same-pool algorithm

```
copy_file_range(src_fd, off_src, dst_fd, off_dst, len):

  Assert: src_fd and dst_fd are in the same pool

  1. LOOKUP source extents in [off_src, off_src+len)
     src_extents = src_fd.extent_map.lookup_range(off_src, len)

  2. CLASSIFY each extent
     for each ext in src_extents:
         if ext fully within [off_src, off_src+len) AND dst_offset aligned:
             → REFLINK candidate
         else:
             → BOUNDARY: read partial data, write new extent

  3. EXECUTE within single commit_group
     BEGIN ATOMIC
     // Aligned extents: pure metadata
     for each reflink_extent:
         pool.refcount_table.increment(extent_id)
         dst_fd.extent_map.insert(reflink_entry)

     // Boundary extents: read + write (data payload)
     for each boundary_extent:
         data = pool.read_extent_range(extent_id, partial_range)
         new_extent_id = pool.allocate_extent()
         pool.write_extent(new_extent_id, data)
         dst_fd.extent_map.insert(new_entry)

     COMMIT
     END ATOMIC
```

### 5.3 Boundary handling

When the source range does not align to extent boundaries, only the partial boundary bytes are read and rewritten. Mid-range extents are reflinked.

```
Source:   [  Ext A  ][  Ext B  ][  Ext C  ]
          0        4096        8192      12288

copy_file_range(off_src=2048, len=8192):
  → Target range [2048, 10240)

  Ext A [0,4096):     partial head  → read [2048,4096), write to dst
  Ext B [4096,8192):  fully aligned → REFLINK
  Ext C [8192,12288): partial tail  → REFLINK with adjusted logical offset
                                      (dst map: off=8192,dst,len=2048→ext_id_C)

  Data copied: 2048 bytes (partial head from Ext A)
  Metadata ops: 1 new extent + 2 reflinked extents
```

The partial tail extent can still be reflinked because the extent map entry in the destination points to the same extent_id with a tighter logical offset/length. The physical payload is shared; the map entry is just a different view.

### 5.4 Cross-pool fallback

When src and dst are in different pools, extent_ids are not shared. Priority order:

1. **Same-pool reflink** (this design): O(num_extents), metadata-only
2. **BULK plane transfer** (#1229): pool-to-pool data copy via the BULK transport plane
3. **Client-side copy**: read all data, write back — O(file_size) network bandwidth

## 6. Refcount and snapshot integration

### 6.1 Pool-wide refcount table (#1180)

The pool-wide refcount table is a persistent B+tree rooted in the pool superblock. It is the single source of truth for extent sharing:

```
PoolRefcountTable:
  B+tree keyed by ExtentId

  Batch operations (single commit_group):
    batch_increment(extent_ids[]):  atomic multi-increment for clone
    batch_decrement(extent_ids[]):  atomic multi-decrement for unlink/truncate

  The batch operations are critical: cloning a file with 10,000 extents
  must update 10,000 refcount entries atomically, not as 10,000 separate
  transactions.
```

When a dataset writes a new extent, it obtains a pool-wide `ExtentId` and initializes the refcount to 1. Extents allocated before the pool-wide tracking era (upgrade path) are backfilled on first reflink access.

### 6.2 Snapshot deadlist (#1232)

When a reflinked file is deleted, the refcount of its extents drops. If the refcount reaches 0 and a snapshot pins the extent (snap_commit_group in `[birth_commit_group, death_commit_group)`), it moves to the snapshot deadlist instead of immediate reclaim:

```
unlink(dataset=A, ino=reflinked_ino):
  for each extent_id in ino.extent_map:
      entry = pool.refcount_table.decrement(extent_id)
      if entry.refcount == 0:
          entry.death_commit_group = current_commit_group
          snap = snap_commit_group_index.find_first(entry.birth_commit_group, entry.death_commit_group)
          if snap is None:
              reclaim_queue.push(extent_id)   // free immediately
          else:
              snap.deadlist.insert(extent_id)  // pinned by snapshot
```

### 6.3 Post-process dedup (#1255)

Cross-dataset reflink is the **synchronous** path (explicitly created by clone). Post-process dedup is the **asynchronous backfill** — a background scanner discovers extents with identical content checksums across unrelated datasets and merges them:

```
dedup_scanner_tick(budget=N):
  candidates = pool.refcount_table.find_duplicate_checksums(budget)
  for each (ext_a, ext_b) in candidates:
      if byte_compare(ext_a, ext_b) == EQUAL:
          for each ref in pool.find_references(ext_b):
              ref.extent_map.replace(ext_b, ext_a)
          pool.refcount_table[ext_a].refcount += pool.refcount_table[ext_b].refcount
          pool.refcount_table.remove(ext_b)
          reclaim_queue.push(ext_b)
```

Dedup discovers sharing that reflink didn't explicitly create — e.g., two users independently storing the same file in different datasets.

## 7. COMMIT_GROUP commit ordering and atomicity

### 7.1 Clone commit sequence

Cross-dataset reflink integrates with the existing seven-step commit_group state machine (#1267):

```
  Step 1–2: SKIP (no new data payloads for pure clone)

  Step 3: APPEND metadata updates
          - Dataset A: no changes (source is read-only during clone)
          - Dataset B: new inode record, extent map page(s), dir entry
          - Pool: refcount table page(s) with incremented counts

  Step 4: APPEND commit record
          Single METADATA_COMMIT_V1 spanning all three domains

  Step 5: FLUSH metadata journal
  Step 6: UPDATE checkpoint pointer(s)
  Step 7: FLUSH system area
```

Durability class: **MetadataOnly** (steps 3–7 only). The operation completes in one commit_group.

### 7.2 Commit record extension

The commit record identifies which domains were touched in the commit_group:

```rust
struct MetadataCommitV1 {
    commit_group_id: u64,
    datasets_touched: Vec<DatasetId>,
    pool_refcount_touched: bool,   // true when refcount table mutated
    // ... existing fields
}
```


## 8. Feature flag gating

Cross-dataset reflink is gated by a per-pool feature flag:

```
ORG_TIDEFS_CROSS_DATASET_REFLINK   (ro_compat)
```

**ro_compat semantics**: A pool with this flag set can still be mounted read-only by older codex versions that don't understand cross-dataset reflinks. The older codex sees independent datasets with independent extent maps — it cannot create new cross-dataset reflinks, but it can read and write files that already share extents. Writes by older codex will correctly trigger CoW, breaking extent sharing for modified extents.

## 9. API surface

### 9.1 clone_file

```rust
impl LocalFileSystem {
    /// Create a reflink copy of a file, potentially across datasets.
    ///
    /// Metadata-only operation within the same pool: no data is copied,
    /// extent refcounts are atomically incremented, and both files share
    /// the same physical extents. Writes to either copy trigger CoW at
    /// extent granularity.
    ///
    /// # Requirements
    /// - Both datasets in the same pool
    /// - ORG_TIDEFS_CROSS_DATASET_REFLINK feature flag enabled
    /// - Source is a regular file; destination path does not exist
    pub fn clone_file(
        &mut self,
        src_dataset: &str,
        src_path: &str,
        dst_dataset: &str,
        dst_path: &str,
    ) -> Result<CloneFileSummary>;
}

struct CloneFileSummary {
    src_ino: InodeId,
    dst_ino: InodeId,
    extent_count: u64,
    bytes_shared: u64,
    commit_group_id: u64,
}
```

### 9.2 copy_file_range

```rust
impl LocalFileSystem {
    /// Server-side copy offload for byte ranges.
    ///
    /// Within the same pool, extent-aligned ranges are reflinked.
    /// Partial boundary extents are read+written. Cross-pool falls
    /// back to BULK transfer (#1229) or client-side copy.
    pub fn copy_file_range(
        &mut self,
        src_fd: &FileHandle,
        off_src: u64,
        dst_fd: &FileHandle,
        off_dst: u64,
        len: u64,
    ) -> Result<CopyFileRangeSummary>;
}

struct CopyFileRangeSummary {
    bytes_copied: u64,
    bytes_reflinked: u64,
    bytes_boundary_copied: u64,
    commit_group_id: u64,
}
```


### 10.1 Unit tests

- Reflink a file within the same dataset → extent refcount = 2
- Reflink a file across datasets → both see same extent_ids, refcount = 2
- Write to reflinked file → CoW on modified extents only, unmodified extents retain shared refcount
- Delete one reflinked copy → refcount decrements, remaining copy still readable
- Delete both copies → refcount reaches 0, extents enter reclaim queue
- Reflink + snapshot create + delete one copy → deadlist integration verifies pinning
- `copy_file_range` with boundary misalignment → partial read+write + reflink for aligned portion
- Cross-pool `copy_file_range` → BULK fallback triggered

### 10.2 Crash safety

- Kill mid-commit_group during clone → pool and datasets roll back to pre-clone state
- Kill after commit_group commit → clone is durable, both datasets consistent
- Kill during CoW write to reflinked file → commit_group rollback, refcount unchanged
- Recovery verifies `refcount_table` × `extent_map` cross-dataset consistency via commit record

### 10.3 Chaos campaign

- Continuous reflink + write + delete loop under crash injection
- Verify refcount integrity: Σ(dataset references) = pool refcount table sum
- Verify no orphan extents: extents with refcount=0 must be in reclaim queue or deadlist
- Verify no dangling references: extent map entries must not point to freed extent_ids

## 11. Comparison with existing filesystems

This table is a target matrix for the draft design. It does not claim the
listed TideFS capabilities are implemented, validated, or superior to the
incumbents.

| Capability | ZFS prior art | CephFS prior art | XFS/Btrfs prior art | TideFS design target |
|---|---|---|---|---|
| Within-dataset reflink | Yes | No | Yes | Target: yes |
| Cross-dataset reflink | No (send/recv) | No | No (per subvol) | Target: yes |
| Cross-pool reflink | No | No | No | Target: no (BULK) |
| Reflink is metadata-only | Yes | N/A | Yes | Target: yes |
| Post-process dedup across datasets | No | No | No | Planned target (#1255) |
| Snapshot + reflink integration | Clones only | N/A | Per-subvol | Target: pool-wide |
| CoW granularity | Block | N/A | Extent | Target: extent |
| Atomic cross-dataset commit_group | N/A | N/A | N/A | Target: yes |

## 12. Relationship to existing issues

| Issue | Relationship |
|---|---|
| #1191 (extent_id indirection) | Foundation: v2/v3 extent maps with LocatorId indirection |
| #1180 (refcount deltas) | Depends on: pool-wide refcount table for shared extent lifecycle |
| #1232 (deadlist) | Depends on: snapshot-pinned extent tracking for reflinked extents |
| #1255 (dedup) | Enables: dedup discovers cross-dataset sharing opportunities as backfill |
| #1229 (BULK) | Fallback: cross-pool copy offload uses BULK transport plane |
| #1215 (space accounting) | Integrates: shared extent bytes accounted per SpaceDomainId |
| #1267 (commit_group state machine) | Uses: atomic cross-dataset commit_group commit ordering |
| #1223 (feature flags) | Uses: ORG_TIDEFS_CROSS_DATASET_REFLINK feature flag gating |

## 13. Open questions and future work

1. **Directory-level reflink**: Recursive `clone_dir` that reflinks an entire tree. Introduces complexity around multi-file atomicity. Deferred to v2.

2. **Cross-encryption-domain reflink**: Datasets with different encryption keys need key re-wrapping for shared extents. Deferred to the encryption policy layer (`tidefs-encryption`).

3. **Cluster-wide reflink**: Two nodes sharing an extent_id without coordinating every read requires distributed refcount consensus. Deferred to the distributed filesystem layer.

4. **Refcount table performance at scale**: A pool with 10⁹ extents needs careful B+tree batching and write-ahead logging. Benchmarking gated.

5. **Dedup + reflink interaction semantics**: When dedup merges two extents, the resulting relationship is semantically equivalent to a retrospective reflink. Handled in #1255 atop this design's architectural foundation.
