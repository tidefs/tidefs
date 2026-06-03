# Persistent Orphan Index — Consolidated Canonical Design

**Issue**: [#1621](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1621)
**Status**: design-spec
**Maturity**: design-spec — Rust implementation deferred to wire-up issues
**Lane**: storage-core
**Supersedes**: #1546, #1589
**Depends on**: #1207 (orphan index design anchor), #1257 (B+tree CoW persistence),
  #1220 (on-media format), #1267 (commit_group state machine), #1219 (dataset lifecycle),
  #1212 (deferred cleanup), #1179 (background scheduler)
**Related**: #1232 (snapshot deadlist), #1215 (space accounting), #1289 (polymorphic directory index),
  #1373 (core types), #1383 (OrphanIndexRoot)

---

## Abstract

The persistent orphan index is a dataset-scoped, key-only B+tree that tracks
`nlink == 0` inodes for bounded-memory, cursor-resumable crash recovery. It
replaces the naive O(total-inodes) mount-time scan with an O(orphans) indexed
approach. The index is rooted in `DatasetMetadataV1.orphan_index_root` with
8-byte big-endian `OrphanKey` entries and zero-byte values. Recovery operates
under a configurable `OrphanRecoveryBudget`, is idempotent across crashes, and
integrates with the commit_group commit pipeline, `BackgroundReclaim`, and deferred
cleanup infrastructure.

Relative to ZFS's `zfs_unlinked_drain()` (ZAP-limited, synchronous, no cursor)
and CephFS (no persistent index; full-dataset scrub), the orphan index provides:
no entry-count ceiling, configurable per-tick budget, and cursor-based crash
resumability.

Phase 1 implementation is complete across three crates:
`tidefs-types-orphan-index-core` (61 tests), `tidefs-orphan-index` (22 tests),
and `tidefs-orphan-recovery-job-core` (26 tests). Wire-up to the commit_group pipeline,

---

## 1. Motivation

### 1.1 Problem

POSIX filesystems must reclaim storage for unlinked files whose last file
descriptor closes after `unlink()` (`nlink` becomes 0 while open). On crash,
the inode and its extents remain on disk but are unreachable from any directory
entry. The filesystem must find and reclaim these "orphans" on next mount.

A naive inode-table scan is O(total inodes) — unacceptable at scale. A petabyte
dataset with a billion inodes would incur minutes to hours of mount-time
scanning even if only a handful of files were orphaned.

### 1.2 Existing approaches and their limits

| Dimension | ZFS | CephFS | ext4 | TideFS |
|---|---:|---:|---:|
| Algorithm | ZAP per-dataset; drain at mount | MDS journal replay | Orphan list in journal superblock | Persistent B+tree; cursor-based batch recovery |
| Scaling | O(orphans), ZAP ~100K cap | O(journal size) | Fixed-size list (~1024) | O(orphans), no entry limit |
| Mount-time latency | Bounded if ZAP small; fragments >100K | Unbounded | Bounded but capacity-limited | Bounded per batch; configurable WorkBudget |
| O_TMPFILE support | Not native | N/A | Partial (3.11+) | First-class: indexed from open to linkat/close |
| Crash safety | Sync unlink path adds latency | Journal replay | Journal replay | Same-commit_group insert/delete; idempotent cursor recovery |
| Memory bound | O(orphans) | O(journal) | O(list) | O(batch_size), default 1024 |
| Snapshot safety | EBUSY on snapshotted orphans | Current gen only | Current gen only | Deadlist (#1232) gates extent reclamation |
| Background recovery | Synchronous at mount | MDS tick for strays | ext4lazyinit (inode table only) | Deferred cleanup (#1212) for post-mount orphans |

### 1.3 Design constraints

1. **Scale with orphan count, not dataset size.** A billion-inode dataset with
   3 orphaned files must recover in O(3) work.
2. **Bounded memory per recovery tick.** Default budget: 1024 orphans, 64 MiB,
   100 ms. Configurable via `OrphanRecoveryBudget`.
3. **Crash-idempotent.** Recovering the same orphan twice must be safe (extent
   freeing is idempotent).
4. **Transactional.** Orphan index insert/delete is committed within the same
   commit_group as the causal event (unlink, linkat, O_TMPFILE create/close).
5. **Snapshot-aware.** Extent reclamation for snapshotted orphans is gated on
   deadlist clearance (#1232).
6. **B+tree-native.** Reuse TideFS's existing B+tree infrastructure (#1257),
   not a bespoke persistent structure.

---

## 2. Architecture

### 2.1 Crate decomposition

```
┌─────────────────────────────────────────────────┐
│  tidefs-types-orphan-index-core  (no_std)       │
│  Authority types: OrphanKey, OrphanCursor,      │
│  OrphanRecoveryBudget, OrphanRecoveryStats,     │
│  OrphanIntegrityError, OrphanIndexRoot          │
├─────────────────────────────────────────────────┤
│  tidefs-orphan-index  (no_std)                  │
│  Runtime: OrphanIndex (BPlusTree<OrphanKey,()>) │
│  insert/delete/contains/len/batch_recover       │
├─────────────────────────────────────────────────┤
│  tidefs-orphan-recovery-job-core  (no_std)      │
│  IncrementalJob wrapper: OrphanRecoveryJob      │
│  Checkpoint serialization, resume, step,        │
│  WorkBudget → OrphanRecoveryBudget conversion   │
└─────────────────────────────────────────────────┘
```

**tidefs-types-orphan-index-core**: Authority types (`no_std`, forbid_unsafe).
Defines the canonical data structures that both the B+tree runtime and the
recovery job consume. No I/O, no allocation beyond `Vec` for error reporting.

**tidefs-orphan-index**: B+tree wrapper (`OrphanIndex` struct). Wraps
`tidefs_btree::BPlusTree<OrphanKey, (), 128, 128>` with domain-specific
semantics: insert at nlink→0, delete after cleanup, cursor-based batch recovery.

**tidefs-orphan-recovery-job-core**: Implements `IncrementalJob` for the
orphan recovery lifecycle. Converts generic `WorkBudget` into domain-specific
`OrphanRecoveryBudget`, serializes/deserializes `OrphanCursor` as
`CursorState`, and produces `StepResult` with checkpoint for the scheduler.

### 2.2 Data flow

```
unlink(fd) / close(last fd)
        │ nlink → 0
        ▼
┌─────────────────┐     commit_group commit
│  OrphanIndex    │ ─────────────────►  on-disk B+tree
│  .insert(inode) │                    (in object store)
└─────────────────┘
        │
        │ crash + remount
        ▼
┌──────────────────────┐
│  OrphanRecoveryJob   │  step() per tick
│  .resume(checkpoint) │  budgeted by WorkBudget
│  .step(budget)       │──► OrphanIndex::batch_recover()
│  .persist_checkpoint()│    returns OrphanRecoveryOutcome
└──────────────────────┘
        │
        │ orphan inode IDs
        ▼
┌──────────────────────┐
│  BackgroundReclaim   │  tick_background_services()
│  (deferred cleanup)  │  stores reclaimed inodes
│  + deadlist gate     │  deletes from OrphanIndex
└──────────────────────┘
```

### 2.3 Integration points

- **Object store**: B+tree pages are persisted via `tidefs-local-object-store`
  through the B+tree CoW persistence layer (#1257).
- **On-media format**: Root pointer stored as `DatasetMetadataV1.orphan_index_root`
  (#1220, #1383).
- **COMMIT_GROUP pipeline**: Insert/delete operations are batched and committed atomically
  within the commit_group lifecycle (#1267). Causal ordering guarantees that the orphan
  index mutation appears in the same commit_group as the unlink/linkat.
- **Background scheduler**: `OrphanRecoveryJob` registers as an `IncrementalJob`
  under the scheduler (#1179, #1549), and `BackgroundReclaim` drains recovered
  orphans into the deferred cleanup pipeline (#1212).
- **Snapshot deadlist**: Extent reclamation is gated by deadlist presence (#1232).
  Orphans captured in a snapshot have their extents pinned until the snapshot is
  destroyed.

---

## 3. Data Structures

### 3.1 OrphanKey

```rust
#[repr(transparent)]
pub struct OrphanKey(pub [u8; 8]);
```

- 8-byte big-endian inode ID.
- Big-endian encoding ensures lexicographic byte comparison equals integer
  comparison, preserving natural numerical order for B+tree range scans.
- Sentinels: `OrphanKey::NONE` (all zeros) for unset; `u64::MAX` saturates.
- Methods: `from_inode_id()`, `to_inode_id()`, `is_none()`, `is_some()`,
  `next()` (saturating +1), `prev()` (saturating -1).

### 3.2 OrphanCursor

```rust
pub struct OrphanCursor {
    pub position: u64,
}
```

- Tracks the last-processed inode ID for resumable recovery.
- `OrphanCursor::START` = 0.
- `advance_past(inode_id)` sets position to `max(position, inode_id)`.
- Serialized as `CursorState` (8 big-endian bytes) for checkpoint persistence.

### 3.3 OrphanRecoveryBudget

```rust
pub struct OrphanRecoveryBudget {
    pub max_orphans_per_tick: usize,   // default: 1024
    pub max_batch_size: usize,         // default: 256
    pub max_bytes_per_tick: u64,       // default: 64 MiB
    pub max_ms_per_tick: u64,          // default: 100 ms
}
```

- Converted from generic `WorkBudget` by `OrphanRecoveryJob::to_orphan_budget()`.
- Zero values disable the corresponding limit (unbounded).
- Additional fields `pressure_threshold` and `pressure_budget_multiplier` support
  space-pressure adaptive throttling.

### 3.4 OrphanRecoveryStats

```rust
pub struct OrphanRecoveryStats {
    pub scanned: usize,      // inodes scanned this tick
    pub stale: usize,        // in index but nlink > 0 (stale entry)
    pub reclaimed: usize,    // successfully freed
    pub skipped: usize,      // skipped (e.g., snapshotted)
    pub errors: usize,       // recovery errors
    pub bytes_reclaimed: u64,
    pub ms_elapsed: u64,
}
```

- Accumulated across ticks with `accumulate()` for per-job totals.
- `stale` entries arise when an inode was re-linked between crash and recovery
  (the index entry is stale; the inode's nlink was restored by journal replay).

### 3.5 OrphanRecoveryOutcome

```rust
pub struct OrphanRecoveryOutcome {
    pub stats: OrphanRecoveryStats,
    pub cursor: OrphanCursor,
    pub exhausted: bool,
    pub inode_ids: Vec<u64>,   // recovered inode IDs for cleanup
}
```

- Returned by `OrphanIndex::batch_recover()`.
- `exhausted` signals that the entire index has been scanned.
- `inode_ids` are the actual orphan inode IDs found in this batch, passed to
  `BackgroundReclaim` for deferred cleanup.

### 3.6 OrphanIndexRoot

```rust
#[repr(transparent)]
pub struct OrphanIndexRoot(pub u64);
```

- Type-safe root pointer stored in `DatasetMetadataV1.orphan_index_root`.
- `OrphanIndexRoot::EMPTY` = `0`.
- Methods: `is_empty()`, `is_present()`.

### 3.7 OrphanIndex (B+tree wrapper)

```rust
pub struct OrphanIndex {
    tree: BPlusTree<OrphanKey, (), MAX_LEAF, MAX_INTERNAL>,
}
```

- `MAX_LEAF = MAX_INTERNAL = 128`.
- Each leaf entry is 8 bytes (key) + B+tree overhead, fitting within a 4 KiB page.
- Key-only: zero-byte values avoid per-entry heap allocation.
- API: `insert(inode_id) -> bool`, `delete(inode_id) -> bool`,
  `contains(inode_id) -> bool`, `len() -> usize`, `is_empty() -> bool`,
  `batch_recover(cursor, budget) -> OrphanRecoveryOutcome`,
  `collect_inode_ids() -> Vec<u64>`.

---

## 4. Algorithms

### 4.1 Unlink-path insert

When an inode's `nlink` reaches 0 (last `unlink()` or last `close()` after
unlink while open):

1. Acquire dataset commit_group write lock.
2. `orphan_index.insert(inode_id)` — returns `true` on first insert.
3. The insert is batched in the current commit_group; B+tree CoW pages are committed
   with the commit_group group commit.
4. The inode's extent tree is marked for deferred reclamation; the extent
   space is not freed until deadlist clearance.

### 4.2 Crash recovery: batch_recover()

```
function batch_recover(cursor, budget):
    stats ← OrphanRecoveryStats::ZERO
    inode_ids ← []
    iter ← tree.range(cursor.position..)

    for each (key, _) in iter:
        if stats.scanned >= budget.max_orphans_per_tick:
            break
        if time_elapsed >= budget.max_ms_per_tick:
            break
        if bytes_processed >= budget.max_bytes_per_tick:
            break

        stats.scanned += 1
        inode_id ← key.to_inode_id()

        // Staleness check is deferred to BackgroundReclaim
        // (requires inode table access, which may not be in memory)
        inode_ids.push(inode_id)
        cursor ← cursor.advance_past(inode_id)

    exhausted ← (stats.scanned < budget.max_orphans_per_tick)

    return OrphanRecoveryOutcome {
        stats, cursor, exhausted, inode_ids
    }
```

Key properties:
- **O(orphans) scan**: Only entries in the B+tree are visited, never the full
  inode table.
- **Cursor advances past every scanned entry**: On crash, up to
  `batch_size - 1` entries may be re-scanned. Reclamation is idempotent, so
  this is safe.
- **Staleness is handled downstream**: `BackgroundReclaim` verifies `nlink == 0`
  against the inode table before performing extent reclamation.

### 4.3 OrphanRecoveryJob lifecycle

```
step(budget):
    if done:
        return StepResult::complete(persist_checkpoint())

    outcome ← index.batch_recover(cursor, to_orphan_budget(budget))
    cursor ← outcome.cursor
    items_processed += outcome.stats.scanned

    if outcome.exhausted:
        done ← true

    return StepResult::in_progress(persist_checkpoint(), outcome.inode_ids)
```

```
resume(checkpoint):
    cursor ← cursor_from_state(checkpoint.cursor_state)
    items_processed ← checkpoint.progress.items_processed
    done ← checkpoint.progress.is_done

    return OrphanRecoveryJob { index, cursor, ... }
```

```
persist_checkpoint():
    return Checkpoint {
        job_id: self.id,
        job_kind: JobKind::OrphanRecovery,
        cursor_state: cursor_to_state(self.cursor),
        progress: JobProgress {
            items_processed: self.items_processed,
            is_done: self.done,
        },
    }
```

### 4.4 Deferred cleanup via BackgroundReclaim

After `batch_recover()` returns orphan inode IDs:

1. `tick_background_services()` records `ReclaimQueueEntry` deltas for each
   orphaned inode into the reclaim queue.
2. `BackgroundReclaim` (Throughput priority, 256-entry batch cap) pops entries
   from the queue in deterministic `ObjectKey` order.
3. For each entry, verifies `nlink == 0` against the inode table (stale guard).
4. If `nlink == 0` and deadlist allows: frees extents, updates space accounting,
   and deletes the inode from `OrphanIndex` and inode table.
5. If the inode is snapshotted (deadlist blocks reclamation): the entry remains
   in the reclaim queue and is retried on the next tick.

This O(1)/O(budget) decoupling separates orphan discovery (O(orphans)) from
extent reclamation (budgeted per tick), unlike ZFS's synchronous drain.

---

## 5. O_TMPFILE Lifecycle

### 5.1 Creation

```
open(O_TMPFILE | O_RDWR, 0)
    → allocate inode (nlink=0 from birth)
    → orphan_index.insert(inode_id)
    → return fd
```

The inode enters the orphan index at creation time, before any directory entry
exists. This is a structural improvement over ZFS, which has no native
O_TMPFILE support.

### 5.2 Linking

```
linkat(AT_FDCWD, "/proc/self/fd/N", AT_FDCWD, "/target/name", AT_SYMLINK_FOLLOW)
    → orphan_index.delete(inode_id)
    → inode.nlink ← 1
    → create directory entry
```

Both the index deletion and the `nlink` increment are committed in the same commit_group.
If a crash occurs between the linkat success and the commit_group commit, journal replay
restores the consistent state.

### 5.3 Close without link

```
close(fd)  // O_TMPFILE never linked
    → orphan_index entry already present
    → extent tree marked for reclamation
    → inode freed at next BackgroundReclaim tick
```

### 5.4 Crash scenarios

| Scenario | State at crash | Recovery behavior |
|---|---|---|
| Crash after open(), before linkat() | Inode in orphan index, nlink=0 | Orphan recovery reclaims inode |
| Crash after linkat(), before commit_group commit | Journal replay restores linkat; inode may be in or out of index depending on commit_group state | Staleness check detects nlink>0; skips |
| Crash after linkat() + commit_group commit | Inode removed from index, nlink>0 | No orphan recovery needed |
| Crash after close() of unlinked inode | Inode in orphan index, nlink=0 | Orphan recovery reclaims inode |

---

## 6. Snapshot Interaction

### 6.1 Deadlist gating

When a snapshot exists, orphaned inodes captured in that snapshot must not have
their extents freed. The deadlist (#1232) tracks which blocks are referenced
by snapshots. `BackgroundReclaim` consults the deadlist before freeing extents:

1. For each orphan inode, build the extent list from the extent tree.
2. For each extent, check deadlist membership.
3. If all extents are deadlist-free: free extents, delete inode from index.
4. If any extent is deadlisted: skip the inode; it remains in the reclaim queue.

### 6.2 Snapshot destroy interaction

When a snapshot is destroyed, extents formerly deadlisted become eligible for
reclamation. The destroy walk (`TraversalRootType::OrphanIndex`) re-queues
affected orphan entries for reclamation, or the next `BackgroundReclaim` tick
naturally retries them.

---

## 7. Tradeoffs and Design Decisions

### 7.1 Key-only tree vs. key-value tree

**Decision**: Key-only (zero-byte values).

**Rationale**: The only information needed is "is this inode orphaned?" — a
boolean. Presence in the tree is that boolean. Zero-byte values minimize disk
and memory overhead (no heap allocation per entry).

### 7.2 Per-batch cursor vs. per-orphan cursor

**Decision**: Per-batch cursor (advances past every scanned entry).

**Tradeoff**: On crash, up to `batch_size - 1` entries may be re-scanned.
Reclamation is idempotent, so this is safe. Per-orphan cursor persistence
would require one B+tree write per orphan, prohibitive for large orphan sets.

### 7.3 Big-endian key encoding

**Decision**: Big-endian byte order for keys.

**Rationale**: The B+tree's `Ord` compares raw bytes lexicographically.
Big-endian encoding means byte comparison equals integer comparison,
preserving natural numerical order for range scans without byte-swapping
during comparison.

### 7.4 Separate crate for authority types

**Decision**: `tidefs-types-orphan-index-core` is `no_std` and free of I/O.

**Rationale**: Authority types are consumed by both the B+tree runtime crate
and the incremental job crate. A shared `no_std` crate prevents dependency
cycles and allows future kernel-side use.

### 7.5 Background reclamation vs. synchronous mount-time drain

**Decision**: Background service with deferred cleanup, not synchronous drain.

**Rationale**: ZFS's synchronous `zfs_unlinked_drain()` blocks mount until all
orphans are reclaimed — minutes for millions of orphans. Background service
allows immediate mount with incremental reclamation interleaved with user I/O.
The tradeoff is that orphaned space is not instantly available, but the
`Critical` service priority ensures prompt reclamation.

### 7.6 Deferred staleness verification

**Decision**: Staleness checks are performed in `BackgroundReclaim`, not in
`batch_recover()`.

**Rationale**: Verifying `nlink == 0` requires inode table access, which may
not be in memory during early mount-phase recovery. Deferring to
`BackgroundReclaim` avoids coupling orphan scanning to inode table availability
and keeps the scan phase purely index-driven.

### 7.7 B+tree node size (128 entries)

**Decision**: `MAX_LEAF = MAX_INTERNAL = 128`.

**Rationale**: Each leaf entry is 8 bytes (key only) + B+tree overhead.
128 entries ≈ 1 KiB of key data per leaf, comfortably within a 4 KiB page.
Provides high fanout (128-way) for both internal nodes and leaves, keeping
tree depth shallow even for millions of orphans.

---

## 8. Implementation Status

### 8.1 Completed (Phase 1)

| Crate | Lines | Tests | Issue |
|---|---|---|---|
| `tidefs-types-orphan-index-core` | 1316 | 61 | #1373, #1383 |
| `tidefs-orphan-index` | 529 | 22 | #1373 |
| `tidefs-orphan-recovery-job-core` | 733 | 26 | #1373 |
| `BackgroundReclaim` | — | 17 | #1546 |

**Crate membership** (workspace `Cargo.toml`):
- `crates/tidefs-types-orphan-index-core`
- `crates/tidefs-orphan-index`
- `crates/tidefs-orphan-recovery-job-core`

**Feature matrix** (`docs/FEATURE_MATRIX.md`):
- Persistent orphan index → `implemented-types` orphan_index

### 8.2 Deferred to wire-up issues

| Work item | Description |
|---|---|
| COMMIT_GROUP integration | Wire insert/delete into commit_group commit pipeline; atomic unlink+insert |
| O_TMPFILE lifecycle | Insert at open(), delete at linkat(); crash-before-linkat test |
| Snapshot-aware reclamation | Deadlist (#1232) gating for snapshotted orphan extents |
| Destroy job integration | `TraversalRootType::OrphanIndex` in destroy walk |
| Send/receive interaction | Exclude orphan index from send stream; receiver rebuilds from inode table |
| Per-dataset recovery job wiring | Create `OrphanRecoveryJob` at mount for each dataset |
| Deferred cleanup service wiring | Wire `OrphanIndex` mutations into `tick_background_services()` |
| B+tree persistence sync | Sync in-memory `OrphanIndex` to object store via commit_group flush pipeline |

---

## 9. Open Questions

1. **Cursor granularity**: Per-batch (current design, trades up to
   `batch_size - 1` reprocessed orphans on crash) vs. per-orphan (adds
   1 B+tree write per orphan)?
2. **Send/receive**: Transfer the orphan index or exclude it (receiver
   rebuilds from inode table)? Option B is simpler.
3. **Compaction**: Should `SegmentCleanerService` (#1179) handle B+tree
   compaction from deleted O_TMPFILE entries, or defer to general B+tree
   compaction story?
4. **Multi-dataset pools**: Parallel or sequential recovery across datasets?
   Sequential is simpler; parallel requires per-dataset budget allocation.
5. **B+tree persistence layer**: How does the in-memory `OrphanIndex` sync
   to the object store? Deferred to #1257 (B+tree CoW persistence) and the
   commit_group flush pipeline.

---


The xtask gate `tidefs-xtask check-orphan-index` will verify:

1. Spec, feature matrix, and status entries present
2. Core crate compiles with `no_std` + optional `alloc`
3. `batch_recover()` passes deterministic tests: empty index, single orphan,
   mixed stale/real, budget exhaustion, cursor resume, crash simulation
4. `OrphanRecoveryJob::step()` and `resume()` round-trip with checkpoint
   serialization
5. `BackgroundReclaim::tick()` populates pending deletions correctly
6. Chaos test: crash injection during recovery; verify idempotent resumption

---

## 11. References

- [#1207](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1207) —
  Original orphan index design anchor
  (`docs/PERSISTENT_ORPHAN_INDEX_DESIGN.md`)
- [#1212](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1212) —
  Deferred cleanup work queues
- [#1215](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1215) —
  Space accounting model
- [#1219](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1219) —
  Dataset lifecycle and destroy job
- [#1220](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1220) —
  On-media format strategy
- [#1232](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1232) —
  Snapshot deadlist and pinning
- [#1257](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1257) —
  B+tree CoW persistence
- [#1267](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1267) —
  Canonical commit_group state machine
- [#1289](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1289) —
  Polymorphic directory index
- [#1373](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1373) —
  Core type implementation
- [#1383](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1383) —
  OrphanIndexRoot type
- [#1546](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1546) —
  Prior design-spec (`docs/design/persistent-orphan-index.md`)
- [#1589](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1589) —
  Prior design-spec (`docs/design/persistent-orphan-index-design.md`)
- [#1549](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1549) —
  Background service framework

---

*This document is the canonical consolidated design-spec for the persistent
orphan index (Issue #1621). It supersedes the earlier design documents at
`docs/design/persistent-orphan-index.md` (#1546) and
`docs/design/persistent-orphan-index-design.md` (#1589). The original
exploration anchor is at `docs/PERSISTENT_ORPHAN_INDEX_DESIGN.md` (#1207).*
