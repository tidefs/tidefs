# Persistent Orphan Index Design (Historical Input)

Maturity: **historical input** - imported persistent-orphan-index target design,
not current reclaim, crash-recovery, space-accounting, or claim-registry
authority.

Authority classification: TFR-019 / `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`
leaves this document as historical input. Use live source, current authority
docs, and `validation/claims.toml` for current orphan-index and reclaim status.

Historical note: this imported document recorded a Forgejo issue #1207
closeout. It does not close any current GitHub persistent-orphan-index,
reclaim, crash-recovery, release-readiness, or production-readiness item.

## Incumbent Comparison Boundary

This imported design document uses ZFS, ext4, and CephFS as historical design
inputs. Its comparison table and "advantage" language are not current TideFS
capability, performance-superiority, cost, durability, or successor claims.
Any future product-facing comparison must route through a #875 claim id and
the comparator evidence required by #928/#930.

## 1. Motivation

POSIX filesystems must reclaim storage for unlinked files whose last file descriptor
closes after unlink (nlink becomes 0 while open). On crash, the inode and its extents
remain on disk but are unreachable from any directory entry. The filesystem must find
and reclaim these orphans on next mount.

The naive approach — scanning the entire inode table — is O(total inodes) and
unacceptable at scale. A petabyte dataset with a billion inodes would incur minutes
to hours of mount-time scanning even if only a handful of files were orphaned.

ZFS handles this with `zfs_unlinked_drain()`: a ZAP (ZFS Attribute Processor) per-dataset
that records unlinked inode IDs. However, ZFS's implementation couples orphan tracking
to the synchronous unlink path (adding latency) and the ZAP limit of ~100K entries
per object forces internal fragmentation for large orphan sets. CephFS has no
persistent orphan index; it relies on recovery scrub.

tidefs requires a dedicated, bounded-memory orphan index that:
- Tracks exactly the set of nlink==0 inodes with dataset-scoped lifetime
- Supports bounded-batch crash recovery (cursor-based, resumable, idempotent)
- Scales with orphan count, not dataset size
- Integrates cleanly with the commit_group state machine (#1267) and deferred cleanup (#1212)

## 2. Relationship to Existing Designs

| Design | Integration point | This design provides |
|---|---|---|
| #1219 (dataset lifecycle) | Destroy job traversal roots | `TraversalRootType::OrphanIndex` is one of the 6 pinned traversal roots |
| #1267 (commit_group state machine) | Transactional unlink/close path | Orphan index insert/delete committed within the same commit_group as the causal event |
| #1212 (deferred cleanup) | Work queue scheduling | Orphan cleanup driven by `CleanupWorkQueue`; index is cursor source |
| #1289 (polymorphic directory index) | Directory entry removal | When last directory entry for an open inode is dropped, orphan index gains it |
| #1250 (three-contract architecture) | On-media format contract | Orphan index defines a new dataset-scoped B+tree root in the on-media format |

## 3. On-Media Format

### 3.1 Orphan index B+tree

A persistent B+tree keyed by inode ID with empty values, stored as a dataset-scoped
root pointer in the dataset metadata record:

```
orphan_index_root: BtreeRootPointer
```

### 3.2 Key format

```
key: inode_id_be_u64  (8 bytes, big-endian)
```

Big-endian encoding ensures natural numerical ordering for cursor-based range scans.

### 3.3 Value format

```
value: empty (0 bytes)
```

The key alone is sufficient; presence in the tree means "this inode is orphaned."
A zero-byte value minimizes B+tree node overhead.

### 3.4 Dataset metadata integration

The orphan index root pointer lives alongside other dataset roots:

```
DatasetMetadataV1 {
    inode_table_root, extent_map_root, directory_index_root,
    xattr_store_root, snapshot_catalog_root, feature_flags_root,
    orphan_index_root,   // <-- this design
    ...
}
```

## 4. State Machine

### 4.1 Transition rules

| Event | nlink before | nlink after | Orphan index action |
|---|---|---|---|
| `unlink()` last link while open | 1 | 0 | Insert inode into orphan index |
| `unlink()` non-last link | >1 | >0 | No action |
| `O_TMPFILE` create | — | 0 | Insert inode into orphan index |
| `linkat()` from orphan state | 0 | 1 | Remove from orphan index |
| `rename()` moving last link | 1→0 at source | 0→1 at target | Source: insert. Target: remove if previously orphaned |
| Last `close()` when nlink==0 | 0 | — (destroyed) | Keep entry; destruction proceeds in same commit_group or via deferred queue |
| Crash before destruction commits | 0 | 0 (persisted) | Index entry survives; recovery on next mount |

### 4.2 Transactional consistency

All orphan index mutations are committed within the same commit_group as the causal event:
- `unlink()` + orphan insert: single commit_group, atomic
- `linkat()` + orphan delete: single commit_group, atomic
- `close()` + destruction: orphan entry removed only after destruction commit_group commits

If the system crashes mid-commit_group, the index state is consistent with nlink state
because either both mutations commit or neither does.

## 5. Bounded Crash Recovery Algorithm

### 5.1 Top-level recovery loop

On mount, the recovery algorithm processes orphans in bounded batches:

```
fn recover_orphans(
    orphan_index, inode_table, budget: WorkBudget, cursor: &mut OrphanCursor,
) -> RecoveryResult {
    let mut reclaimed = 0u64;
    for (inode_id, _) in orphan_index.range(cursor.position..)
                                  .take(budget.ops_remaining()) {
        match inode_table.get(inode_id) {
            None | Some(ref r) if r.nlink != 0 => orphan_index.delete(inode_id),
            Some(rec) => { reclaim_one_orphan(inode_id, rec)?; orphan_index.delete(inode_id); reclaimed += 1; }
        }
        cursor.advance_past(inode_id);
    }
    RecoveryResult { reclaimed, exhausted, cursor: cursor.position }
}
```

### 5.2 Guarantees

1. **Bounded memory**: At most `N` inode records loaded simultaneously; batch size configurable (default 1024).
2. **Idempotency**: `reclaim_one_orphan()` checks whether extents are already freed; deleting an already-deleted entry is a no-op.
3. **Crash safety under partial progress**: Cursor advances per-orphan; crash resumes from last committed position.
4. **No unbounded scan**: Never iterates entire inode table; only visits entries in the orphan index.

### 5.3 Cursor persistence

The recovery cursor is persisted as a dataset metadata field:

```
orphan_recovery_cursor: u64  // last-reclaimed inode_id, or 0 for start
```

On mount, recovery begins at `orphan_recovery_cursor + 1`. Cursor updated after each batch commit_group commit.

### 5.4 Deferred cleanup integration

Orphans created after mount are handled by deferred cleanup work queues (#1212),
not the crash recovery path. Both paths share `reclaim_one_orphan()` but differ
in scheduling: crash recovery runs synchronously during mount, deferred cleanup
runs as a `BackgroundService` (#1179) tick with `Throughput` priority.

## 6. O_TMPFILE Lifecycle

### 6.1 O_TMPFILE semantics

`O_TMPFILE` creates an unnamed file with nlink==0 from birth. Three outcomes:

1. **linkat() into namespace**: Gains a directory entry, nlink becomes 1, orphan entry deleted.
2. **Last close without linkat()**: Destroyed immediately; orphan entry guides cleanup.
3. **Crash before linkat() or close()**: Persisted with nlink==0; found via orphan index.

### 6.2 Index insertion timing

For `O_TMPFILE`, the orphan index entry is inserted at `open()` time (not at first write),
because the inode is already allocated and would leak on crash even without data.

### 6.3 Linkat() integration

When `linkat()` with `AT_EMPTY_PATH` links an `O_TMPFILE` into the namespace:
1. Directory index gains the new entry
2. Orphan index loses the inode entry
Both happen atomically within the same commit_group.

## 7. Integration Points

### 7.1 COMMIT_GROUP commit pipeline

Orphan index mutations participate in the commit_group commit pipeline (#1267):
- **Phase 3 (Quiesce)**: All in-flight orphan index operations are fenced
- **Phase 5 (Flush)**: B+tree pages flushed to object store
- **Phase 6 (Sync)**: Dataset metadata record written; cursor updated if recovery batch completed

### 7.2 Space accounting

When `reclaim_one_orphan()` frees extents, it issues `SpaceDelta` operations via
the space accounting model (#1215). Freed space credited in the reclaiming commit_group.

### 7.3 Snapshot interaction

Snapshotted orphan inodes: extent reclamation gated on deadlist (#1232) clearance.
Orphan index entry deleted immediately after processing; deadlist handles snapshot tracking.

### 7.4 Destroy job interaction

Dataset destroy (#1219): `TraversalRootType::OrphanIndex` walker reclaims all remaining
orphans, skipping snapshot checks since the dataset is being destroyed.

## 8. ZFS and Other Filesystem Design Lessons (Non-Claim)

| Dimension | ZFS (`zfs_unlinked_drain`) | ext4 | CephFS | tidefs orphan index |
|---|---|---|---|---|
| Algorithm | ZAP per-dataset; drain at mount | Scan inode bitmap | MDS journal replay; no persistent index | Persistent B+tree; cursor-based batch recovery |
| Scaling | O(orphans), ZAP capped ~100K | O(total inodes) | O(journal size) | O(orphans), no entry limit |
| Mount-time latency | Bounded if ZAP small; fragments above ~100K | Unbounded | Unbounded | Bounded per batch; configurable WorkBudget |
| O_TMPFILE support | Not native; tmpfs or unlink dance required | Orphan list (ext4 3.11) | N/A | First-class: insert at open, remove at linkat, reclaim on close/crash |
| Crash safety | Sync unlink path adds latency | Journal replay | Journal replay | Same-commit_group insert/delete; idempotent cursor recovery |
| Memory bound | O(orphans) | O(batch) but scan is O(total inodes) | O(journal) | O(batch_size), default 1024 |
| Snapshot safety | `zfs destroy` EBUSY on snapshotted orphans | Current gen only | N/A | Deadlist (#1232) gates extent reclamation |
| Deferred cleanup | Synchronous at mount; no background service | `ext4lazyinit` for inode table only | MDS tick for strays | Deferred cleanup (#1212) for post-mount orphans |

Design lessons recorded by this historical comparison:
1. **No entry count limit**: B+tree vs ZAP ~100K fragmentation
2. **Bounded mount-time processing**: Configurable WorkBudget vs synchronous drain
3. **First-class O_TMPFILE**: Explicit lifecycle with indexed tracking
4. **Cursor-based resumability**: Crash resumes from last cursor; ZFS restarts entirely

## 9. Implementation Plan

### Phase 1: Core types (`crates/tidefs-types-orphan-index-core/`)
- `OrphanIndexEntry`, `OrphanRecoveryCursor`, `OrphanRecoveryBatch`, `OrphanIndexError`
- `reclaim_one_orphan()` function signature
- `no_std` with optional `alloc`
- Gate: `tidefs-xtask check-orphan-index-core`

### Phase 2: Orphan index B+tree operations (`crates/tidefs-orphan-index/`)
- `OrphanIndex` struct with `insert()`, `delete()`, `contains()`, `is_empty()`, `len()`
- `recover_orphans()` bounded-batch algorithm
- Cursor persistence: `load_cursor()` / `save_cursor()`

### Phase 3: COMMIT_GROUP integration
- Wire into commit_group commit pipeline (#1267)
- Atomic unlink+insert, linkat+delete

### Phase 4: O_TMPFILE lifecycle
- Insert at open(), delete at linkat()
- Integration test: crash before linkat, verify recovery

### Phase 5: Snapshot-aware reclamation
- Deadlist (#1232) gating

### Phase 6: Deferred cleanup integration
- Wire into deferred cleanup work queues (#1212)
- BackgroundService tick (#1179)

### Phase 7: Destroy job integration
- `TraversalRootType::OrphanIndex` in destroy walk
- Force-reclaim path (SKIP_ORPHANS flag)

- `tidefs-xtask check-orphan-index` gate


The xtask gate `tidefs-xtask check-orphan-index` verifies:
1. Spec, feature matrix, and status entries present
2. Phase 1 crate compiles with `no_std` + optional `alloc`
3. `recover_orphans()` passes deterministic tests: empty index, single orphan,
   mixed stale/real, budget exhaustion, cursor resume, crash simulation (idempotent)

## 11. Open Questions

1. **Cursor granularity**: Per-batch (current design, trades up to `batch_size - 1`
   reprocessed orphans on crash) or per-orphan (adds 1 B+tree write per orphan)?
2. **Send/receive**: Transfer the orphan index or exclude it (receiver rebuilds from
   inode table)? Option B is simpler.
3. **Compaction**: Should `SegmentCleanerService` (#1179) handle B+tree compaction
   from deleted O_TMPFILE entries, or defer to general B+tree compaction story?
4. **Multi-dataset pools**: Parallel or sequential recovery across datasets?
   Sequential is simpler; parallel requires per-dataset budget allocation.
