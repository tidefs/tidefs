# Deferred Cleanup Work Queues — Design Specification

**Issue**: [#1776](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1776)
**Canonical spec**: [`docs/design/deferred-cleanup-work-queues.md`](deferred-cleanup-work-queues.md) (#2079)
**Status**: design-spec — Rust implementation deferred to wire-up issues
**Priority**: P2
**Lane**: storage-core
**Depends on**: #1239 (incremental cursor framework), #1180 (refcount delta queues), #1179 (background service framework), #1267 (commit_group state machine)
**Blocks**: Phases 4–7 wire-up issues, ENOSPC pressure response, per-dataset space-pressure handling

## Abstract

POSIX `unlink`, `truncate`, and `rmdir` on large files create a fundamental tension:
the caller expects the syscall to return promptly, but the filesystem must reclaim
the file's storage — potentially millions of extents spanning terabytes. Naive code
builds in-memory lists of every extent and blows RAM. Even a streaming walk adds
unpredictable latency to what the application expects to be fast.

This design specifies a **two-phase deletion** model:

1. **Phase 1 (synchronous, syscall context)**: Commit metadata and enqueue a 128-byte
   work item in O(1) time bounded by directory-entry depth (not file size).
2. **Phase 2 (background, budgeted)**: A `CleanupJob` implementing the `IncrementalJob`
   contract processes work items in bounded batches, iterates extent maps with a
   resumable 64-byte cursor, and enqueues refcount deltas for physical reclamation.

The design requires bounded synchronous latency, bounded memory, eventual
reclamation, crash safety, and consistent space accounting. Those requirements
are not incumbent-comparison claims; any future product-facing statement about
TideFS outperforming or matching another filesystem needs #875 and #928/#930
comparator evidence.

---

## 1. Architecture

### 1.1 Two-phase deletion model

```
                    +-----------------------+
  syscall context   |  PHASE 1: Synchronous |  O(1) latency
  (unlink/truncate) |  metadata commit      |  bounded memory
                    |  work item enqueue    |  immediate st_blocks
                    +-------+---------------+
                            | 128-byte CleanupWorkItemV1
                            v
                    +-----------------------+
  background worker |  PHASE 2: Background   |  bounded per-tick
  (CleanupJob)      |  extent-map iteration  |  resumable cursor
                    |  refcount delta enqueue|  crash-safe checkpoint
                    +-----------------------+
```

**Phase 1 (syscall context)** performs only metadata work bounded by
directory entry depth, not file size, and commits within a single commit_group:

1. **Namespace update**: Remove dentry, update parent directory cookies, update
   mtime/ctime, decrement link count on target inode.
2. **Inode state update**: For truncate, update `size_bytes` to new size; for unlink
   with nlink -> 0, mark inode as orphaned.
3. **Logical space accounting**: Update `DatasetSpaceCountersV1.logical_used_bytes`
   and inode `alloc_bytes` so `st_blocks` is immediately correct.
4. **Work item enqueue**: Persist a 128-byte `CleanupWorkItemV1` into the per-dataset
   cleanup queue B+tree.

**Phase 2 (background worker)** processes enqueued work items in bounded batches:

1. Dequeue `CleanupWorkItemV1` from the per-dataset cleanup queue.
2. Iterate the affected extent map using the stored 64-byte cursor, within `WorkBudget`.
3. For each freed extent, enqueue a refcount delta into the reclaim queue (#1180).
4. Persist the updated cursor in the `Checkpoint`.
5. When all extents for a work item are processed, mark it complete and delete it.

### 1.2 System integration points

| Subsystem | Integration point | Role |
|---|---|---|
| `IncrementalJob` (#1239) | Background worker contract | `CleanupJob` implements `IncrementalJob` with `JobKind::DeferredCleanup` |
| Reclaim queues (#1180) | Reclamation target | Work items produce refcount deltas consumed by `ReclaimQueueEntry` |
| Background service (#1179) | Scheduling and dispatch | Scheduler runs `CleanupJob::step()` per tick with budget enforcement |
| COMMIT_GROUP state machine (#1267) | Commit ordering | Work items committed in same commit_group as namespace update |
| Space accounting (#1215) | Logical/physical tracking | Phase 1 updates logical counters; Phase 2 updates physical counters |
| Extent management (#1191) | Extent-map iteration | Cursor-driven walk of file extent maps |
| Orphan index (#1207) | Inode lifecycle | Orphaned inodes persist until all work items complete |

---

## 2. Data Structures

### 2.1 WorkItemKind — Discriminant enum

```
WorkItemKind (repr u8):
  UnlinkFree       = 0  // unlink with nlink -> 0; orphaned inode
  TruncateFree     = 1  // truncate reducing size; inode stays live
  RmdirFree        = 2  // rmdir on empty directory
  RenameOverwrite  = 3  // rename overwriting an existing inode
  SnapDelete       = 4  // snapshot deletion
  PunchHoleFree    = 5  // fallocate(FALLOC_FL_PUNCH_HOLE)
```

### 2.2 CleanupWorkItemV1 — 128-byte on-media record

| Offset | Size | Field | Description |
|---|---|---|---|
| 0 | 8 | inode_id | Target inode (big-endian u64) |
| 8 | 8 | extent_map_root | B+tree root pointer at enqueue time |
| 16 | 8 | created_commit_group | COMMIT_GROUP number when work item was enqueued |
| 24 | 8 | free_start_block | First logical block to free (for range ops) |
| 32 | 8 | free_end_block | Last logical block to free (inclusive; u64::MAX = to EOF) |
| 40 | 1 | kind | `WorkItemKind` discriminant |
| 41 | 1 | flags | Bitfield: bit 0 = is_complete, bits 1-7 reserved |
| 42 | 8 | extents_processed | Count of extents freed so far (for progress tracking) |
| 50 | 14 | _padding | Reserved for future use (zeroed) |
| 64 | 64 | cursor | Opaque 64-byte extent-map iteration cursor |

Total size: 128 bytes. Fixed size by design — no heap allocations, no variable-length
fields, no pointers. This is critical for O(1) enqueue latency and bounded memory.

**Why 128 bytes?** 64 bytes (a typical cache line) is too small to hold the inode
identity, extent-map root, range parameters, and resumable cursor. 256 bytes
wastes per-item storage for datasets with millions of pending items. 128 bytes
is the smallest power-of-two that fits all required fields with room for cursor
and padding.

### 2.3 Queue key — 9-byte compound key

```
+----------------------+---------+
|  inode_id (BE u64)   | kind u8 |
|      8 bytes         | 1 byte  |
+----------------------+---------+
```

Big-endian `inode_id` ensures natural numeric ordering; the kind byte disambiguates
multiple work items for the same inode (e.g., both a `TruncateFree` and a later
`UnlinkFree`). Key uniqueness guarantees at most one work item per `(inode_id, kind)`
pair. A second truncate on the same inode replaces the first; a truncate followed by
an unlink creates two distinct work items.

### 2.4 Cursor — Opaque 64-byte blob

The 64-byte cursor field is deliberately opaque at the type level to allow
future evolution of the extent-map iteration strategy without on-media format
changes.

| Offset | Size | Field | Description |
|---|---|---|---|
| 0 | 8 | block_index | Logical block offset within the file |
| 8 | 8 | extent_id | Last extent ID processed (B+tree seek key) |
| 16 | 8 | btree_level | Current B+tree depth position |
| 24 | 40 | path_stack | Compressed B+tree path (5 x 8-byte node pointers) |

For very deep extent maps (>5 levels), the path_stack stores a compressed
representation using prefix coding of node pointers. The 64 bytes can represent
B+tree paths up to depth ~64 using 1-byte child-index encoding per level.

---

## 3. Algorithms

### 3.1 Phase 1: Synchronous enqueue (unlink example)

```
enqueue_unlink_work_item(inode):
    assert inode.nlink == 0  // final unlink

    // 1. Allocate work item
    item = CleanupWorkItemV1 {
        inode_id:        inode.id,
        extent_map_root: inode.extent_map_root,
        created_commit_group:     current_commit_group(),
        free_start_block: 0,
        free_end_block:  u64::MAX,  // entire file
        kind:            WorkItemKind::UnlinkFree,
        flags:           0,  // is_complete = false
        extents_processed: 0,
        cursor:          [0u8; 64],  // fresh start
    }


    // 3. Insert into per-dataset B+tree
    key = (item.inode_id.to_be_bytes(), item.kind as u8)
    cleanup_queue.insert(key, item)  // replaces existing if same key

    // 4. Update logical accounting
    dataset.counters.logical_used_bytes -= inode.alloc_bytes

    // 5. Mark inode orphaned
    inode.nlink = 0
    orphan_index.insert(inode.id, inode.birth_commit_group)

    // All O(1) or O(log N) operations; no extent-map iteration
```

The key property: `enqueue_unlink_work_item()` never iterates the extent map.
Its work is bounded by B+tree insertion (O(log N) where N is queue size) and
directory entry depth, never by file size.

### 3.2 Phase 2: Background processing (CleanupJob::step)

```
CleanupJob::step(budget: WorkBudget) -> TickReport:
    report = TickReport::new()
    remaining = budget

    while remaining > 0:
        // 1. Dequeue next pending item
        item = self.queue.dequeue_next(self.cursor)?
        if item.is_none():
            break  // queue empty

        // 2. Stale check -- critical safety gate
        inode = lookup_inode(item.inode_id)
        if inode.birth_commit_group != item.created_commit_group:
            // Inode was recycled; discard stale item
            self.queue.mark_complete_and_delete(item.key)
            continue

        // 3. Process one batch of extents within remaining budget
        (freed_extents, new_cursor, done) =
            self.extent_walker.free_batch(
                item.extent_map_root,
                item.cursor,
                item.free_start_block..=item.free_end_block,
                &mut remaining
            )

        // 4. Enqueue refcount deltas
        for extent in freed_extents:
            reclaim_queue.enqueue(RefcountDelta::decrement(extent))

        // 5. Persist progress
        item.cursor = new_cursor
        item.extents_processed += freed_extents.len()
        if done:
            item.flags.set_complete()
            self.queue.mark_complete_and_delete(item.key)
            // If UnlinkFree, tombstone the inode
        else:
            self.queue.update_cursor(item.key, new_cursor)

        report.add(item.inode_id, freed_extents.len(), done)
        // Budget check at top of loop

    return report
```

### 3.3 Stale detection via birth_commit_group

Inode IDs can be recycled after an inode is fully freed. The `birth_commit_group` field
provides a generation counter that prevents stale work items from freeing extents
belonging to a new incarnation of the same inode ID:

```
Time ----------------------------------------------------->

 inode_id=42 (birth_commit_group=100)
   |
   +- unlink -> enqueue work_item { inode_id=42, created_commit_group=100, ... }
   |
   +- inode tombstoned, id=42 recycled
   |
   +- new inode_id=42 (birth_commit_group=250)
   |   +- new extent_map_root = 0x5678
   |
   +- CleanupJob::step() finds work_item:
        - created_commit_group (100) != birth_commit_group (250) -> STALE, discard
```

### 3.4 Checkpoint and crash recovery

The cleanup queue is a persistent B+tree. Progress is checkpointed by updating
the work item's cursor field in-place after each batch. On crash recovery:

1. Mount scans the per-dataset cleanup queue for non-complete items.
2. For each item, the 64-byte cursor is read — it points to the last processed
   extent-map position.
3. `CleanupJob` resumes iteration from the cursor position.
4. Stale detection (birth_commit_group check) discards items belonging to recycled inodes.

No separate WAL or journal is needed; the B+tree itself is the durable state.

### 3.5 Queue capacity management

The per-dataset queue is capped at 10,000 items. When the cap is hit:

- **Strategy**: Limited inline free on subsequent unlink/truncate syscalls.
  Free at most 64 extents synchronously before enqueuing.
- **Rationale**: Prevents unbounded queue growth during heavy delete workloads
  while keeping the synchronous fallback explicitly capped; the exact latency
  budget requires focused validation.
- **Backpressure**: ENOSPC pressure detection boosts `CleanupJob` to Critical
  scheduling priority, accelerating drain.

---

## 4. Tradeoffs

### 4.1 Two-phase vs. synchronous deletion

This tradeoff table records the design input that foreground extent-free work
can scale with file size. It is not measured TideFS latency evidence and does
not prove superiority over ZFS or any other filesystem.

| Aspect | Two-phase (this design) | Synchronous foreground free path |
|---|---|---|
| unlink latency | Target: O(1) relative to file size | O(extents); can grow with very large files |
| Memory | 128 bytes per pending item | O(extents) heap during syscall |
| Crash safety | Work item is durable in commit_group | Partial free may leave dangling refs |
| Space reclamation | Eventual (background) | Immediate |
| Complexity | Higher (queue, cursor, stale detection) | Lower (single code path) |

**Decision**: Two-phase. Bounded large-file deletion latency is a design
requirement for TideFS. Eventual reclamation is acceptable only when
`st_blocks` is immediately correct and ENOSPC pressure can boost cleanup
priority; current product claims still require implementation and validation
evidence.

### 4.2 B+tree queue vs. flat log

| Aspect | B+tree (this design) | Flat log (append-only) |
|---|---|---|
| Lookup by key | O(log N) | O(N) scan |
| Duplicate suppression | Natural (key uniqueness) | Requires separate index or scan |
| Cursor resume | Ordered iteration | Must scan from head or maintain index |
| Crash recovery | Self-indexing | Must replay entire log |
| Implementation | More complex | Simpler |

**Decision**: B+tree. Duplicate suppression by key (same inode, same kind) is
essential for correctness when a second truncate arrives before the first is
processed. Ordered iteration enables efficient cursor-based resume.

### 4.3 128-byte fixed size vs. variable-length work item

| Aspect | 128-byte fixed (this design) | Variable-length |
|---|---|---|
| Allocation | Stack/arena, no heap | Heap allocation per item |
| B+tree insertion | Single memcpy | Serialize/deserialize |
| Cache behavior | Predictable, fits 4 per cache line pair | Unpredictable |
| Extensibility | Padding for future fields | Can grow unboundedly |

**Decision**: 128-byte fixed. The predictability advantage for B+tree storage
and stack allocation outweighs the inflexibility. The 14-byte padding reserve
provides room for future flags or small fields.

### 4.4 Opaque cursor vs. typed cursor

| Aspect | Opaque 64-byte blob (this design) | Typed struct |
|---|---|---|
| Format evolution | Free: change internals at any time | Requires versioned serde |
| Cross-crate inspection | Not possible without versioning | Natural |
| Type safety | Weaker | Stronger |

**Decision**: Opaque blob. The cursor is only read and written by `CleanupJob`;
no other subsystem needs to interpret it. The ability to evolve the iteration
strategy without on-media format changes is worth the loss of type-level guarantees.

### 4.5 Per-dataset queue vs. global queue

| Aspect | Per-dataset (this design) | Global |
|---|---|---|
| Isolation | Dataset deletion drops queue atomically | Must scan and filter |
| Fairness | Natural per-dataset scheduling | Requires priority-aware dispatch |
| ENOSPC | Dataset-local pressure triggers local cleanup | Global pressure is coarse |
| Storage overhead | One B+tree root per dataset | Single B+tree |

**Decision**: Per-dataset. Dataset lifecycle independence (destroy drops the
queue) and local pressure handling are critical for multi-tenant deployments.

---

## 5. Crate Architecture

### 5.1 Phase 1: `tidefs-types-deferred-cleanup-core`

Defines the authority types:
- `WorkItemKind` — discriminant enum
- `WorkItemFlags` — bitfield wrapper

`#![no_std]` + `#![forbid(unsafe_code)]`. No dependencies beyond `core`.

### 5.2 Phase 2: `tidefs-cleanup-queue-core`

Defines the per-dataset B+tree queue abstraction:
- `CleanupQueueKey` — 9-byte compound key
- `BPlusTreeCleanupQueue` — insert, dequeue_next, mark_complete_and_delete
- `QueueStats` — pending count, completed count, total bytes tracked

### 5.3 Phase 3: `tidefs-cleanup-job-core`

Implements `CleanupJob` as an `IncrementalJob`:
- `step()` — budgeted dequeue + extent walk + refcount delta enqueue
- `CursorState` — opaque 64-byte checkpoint container
- `JobMetrics` — items processed, extents freed, bytes reclaimed

### 5.4 Phases 4-7: Deferred to wire-up issues

| Phase | Scope | Status |
|---|---|---|
| 4 | Extent-map cursor walker integration | Deferred |
| 5 | Refcount delta enqueue plumbing | Deferred |
| 6 | ENOSPC pressure boost + admission control | Deferred |
| 7 | FUSE adapter integration (unlink/truncate/rmdir hooks) | Deferred |

---

## 6. Invariants and Edge Cases

### 6.1 Safety invariants

| # | Invariant | Enforcement |
|---|---|---|
| I3 | Cursor is zeroed at enqueue (fresh start) | Constructor zeroes `[0u8; 64]` |
| I4 | Stale work items are never processed | `created_commit_group != birth_commit_group` check in `step()` |
| I5 | Completed items are deleted, not re-processed | `dequeue_next()` skips completed items |
| I6 | No refcount delta is enqueued twice for the same extent | Cursor advances atomically per extent |
| I7 | Queue insertion is idempotent per `(inode_id, kind)` | Duplicate key replacement |
| I8 | `st_blocks` reflects logical free immediately after unlink/truncate | Phase 1 updates logical counters |

### 6.2 Edge cases

| Scenario | Behavior |
|---|---|
| Unlink then immediate re-create with same inode_id | Stale detection via birth_commit_group; old item discarded |
| Two truncates on same inode before processing | Second truncate replaces first (same key) |
| Truncate followed by unlink before processing | UnlinkFree replaces scope; TruncateFree is separate key |
| Punch hole on inode with pending TruncateFree | PunchHoleFree is a separate key; both are processed |
| Dataset destroyed with pending work items | All items discarded; segments freed en masse |
| Crash mid-queue-processing | Cursor checkpoint resumes from last processed key |
| ENOSPC during cleanup job `step()` | Job stops at budget; no partial extent freeing |
| 10,000-item cap hit | Limited inline free (64 extents) per subsequent syscall |
| Rename overwrite with RENAME_EXCHANGE | Two separate work items (one per overwritten inode) |
| Power loss after Phase 1 but before Phase 2 | Work item persisted in commit_group; recovered on next mount |

---

## 7. Design-input comparison to existing systems

This section preserves incumbent failure modes as design inputs. It is not a
claim that TideFS currently outperforms ZFS or CephFS on unlink latency,
memory boundedness, crash safety, or reclamation cost.

### 7.1 ZFS

ZFS performs `dmu_free_long_range()` synchronously during `zfs_rmdir` and
`zfs_znode_delete`. The design input is that foreground deletion work can scale
with extent count when the implementation iterates and frees every block before
returning to the caller.

**TideFS target**: small durable enqueue, prompt return to caller, and
background reclamation with bounded per-tick work. This remains a target, not
measured comparative evidence.

### 7.2 CephFS

CephFS is useful design input because metadata and placement-group work are not
represented as one fine-grained, per-deletion, scheduler-visible cleanup queue.
The MDS journal and PG removal machinery solve different problems.

**TideFS target**: an `IncrementalJob` contract with resumable cursors and
per-tick budget enforcement, with product comparisons left to #875 and
#928/#930 evidence.

---

## 8. References

- Canonical design spec: [`docs/design/deferred-cleanup-work-queues.md`](deferred-cleanup-work-queues.md)
- Background service scheduling:
  [`docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md`](../BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md)
- Incremental job framework: #1239
- Refcount delta queues: #1180
- Background service framework: #1179
- COMMIT_GROUP state machine: #1267
- Extent management: #1191
- Space accounting: #1215
- Orphan index: #1207
