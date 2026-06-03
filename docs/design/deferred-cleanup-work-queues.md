# Deferred Cleanup Work Queues — Design Specification

**Issue**: [#2079](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2079)
**Supersedes**: [#2015](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2015), [#1933](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1933), [#1929](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1929), [#1881](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1881) (canonical design-spec finalization), [#1749](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1749) (prior iteration), [#1668](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1668) (prior design iteration), [#1619](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1619) (original design), [#1212](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1212) (earlier draft)
**Status**: sealed — canonical design-spec finalized, wire-up deferred. Rust implementation (Phases 4–7) deferred to wire-up issues
**Priority**: P2
**Lane**: storage-core
**Depends on**: #1239 (incremental cursor framework), #1180 (refcount delta queues), #1179 (background service framework), #1267 (commit_group state machine), #1191 (extent management), #1215 (space accounting), #1285 (locator tables), #1207 (orphan index)
**Blocks**: Phases 4–7 wire-up issues (see §10.3), ENOSPC pressure response, per-dataset space-pressure handling
**Implemented crates**: `tidefs-types-deferred-cleanup-core` (Phase 1), `tidefs-cleanup-queue-core` (Phase 2), `tidefs-cleanup-job-core` (Phase 3) — 64 tests, `cargo check --workspace` clean
**Rust implementation**: Phases 4–7 deferred to wire-up issues; see §10.2–10.3

## Abstract

POSIX unlink, truncate, and rmdir on large files create a fundamental tension: the caller
expects the syscall to return promptly, but the filesystem must reclaim the file's storage —
potentially millions of extents spanning terabytes. Naive code builds in-memory lists of
every extent and blows RAM. Even a streaming walk adds unpredictable latency to what the
application expects to be fast.

This design specifies a **two-phase deletion** model: a bounded synchronous phase that
commits metadata and enqueues a 128-byte work item in O(1) time, and a budgeted background
phase that processes work items under the `IncrementalJob` contract to reclaim physical
space. The design guarantees bounded synchronous latency, bounded memory, eventual
reclamation, crash safety, and consistent space accounting.

---

## 1. Architecture

### 1.1 Two-phase deletion model

Every space-freeing namespace operation is split into two phases:

```
                    ┌───────────────────────┐
  syscall context   │  PHASE 1: Synchronous │  O(1) latency
  (unlink/truncate) │  metadata commit      │  bounded memory
                    │  work item enqueue    │  immediate st_blocks
                    └───────┬───────────────┘
                            │ 128-byte CleanupWorkItemV1
                            ▼
                    ┌───────────────────────┐
  background worker │  PHASE 2: Background   │  bounded per-tick
  (CleanupJob)      │  extent-map iteration  │  resumable cursor
                    │  refcount delta enqueue│  crash-safe checkpoint
                    └───────────────────────┘
```

**Phase 1 (syscall context)**: The syscall performs only metadata work bounded by
directory entry depth, not file size, and commits within a single commit_group:

1. **Namespace update**: Remove dentry, update parent directory cookies, update
   mtime/ctime, decrement link count on target inode.
2. **Inode state update**: For truncate, update `size_bytes` to new size; for unlink
   with nlink→0, mark inode as orphaned.
3. **Logical space accounting**: Update `DatasetSpaceCountersV1.logical_used_bytes`
   and inode `alloc_bytes` so `st_blocks` is immediately correct.
4. **Work item enqueue**: Persist a 128-byte `CleanupWorkItemV1` into the per-dataset
   cleanup queue B+tree.

**Phase 2 (background worker)**: A `CleanupJob` implementing `IncrementalJob` (#1239)
processes enqueued work items in bounded batches:

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
| Background scheduler (#1179) | Scheduling | `CleanupJob` runs as a `BackgroundService` at `Throughput` priority |
| CommitGroup state machine (#1267) | Transactional consistency | Work items committed in same commit_group as namespace update |
| Space accounting (#1215) | Logical vs physical counters | Synchronous phase updates logical counters; physical freed by worker |
| Extent management (#1191) | Range-oriented extent ops | Extent-map range delete is a prerequisite for deferred cleanup |
| Locator tables (#1285) | Refcount lifecycle | Deferred cleanup decrements refcounts via locator table operations |
| GC pin set | Liveness gating | Work items pinned until extent-map iteration completes |

---

## 2. Data Structures

### 2.1 `WorkItemKind` — discriminant enum

Defined in `tidefs-types-deferred-cleanup-core`. Stable on-media `u8` encoding:

| Variant | Discriminant | Trigger | Result |
|---|---|---|---|
| `UnlinkFree` | 0 | Unlink of last link (nlink→0) | Free all extents belonging to the inode |
| `TruncateFree` | 1 | Truncate to smaller size | Free extents beyond new EOF |
| `RmdirFree` | 2 | Rmdir of empty directory | Free directory block extents |
| `RenameOverwrite` | 3 | Rename overwriting existing target | Free overwritten target's extents |
| `SnapDelete` | 4 | Snapshot deletion | Free extents unique to deleted snapshot |
| `PunchHoleFree` | 5 | `fallocate(FALLOC_FL_PUNCH_HOLE)` | Free extents within punched range |

Key properties:
- `is_inode_destroying()` returns `true` only for `UnlinkFree`
- `is_namespace_op()` returns `true` for `UnlinkFree`, `TruncateFree`, `RmdirFree`,
  `RenameOverwrite` (namespace ops vs snapshot/hole-punch)
- `COUNT = 6`

### 2.2 `CleanupWorkItemV1` — on-media record (128 bytes)

Defined in `tidefs-types-deferred-cleanup-core`. Fixed-size record persisted in a
per-dataset B+tree:

```
Offset  Size   Field                 Encoding
─────────────────────────────────────────────────
0       8      magic                 b"CLNWITEM" (constant)
8       8      inode_id              u64 BE
16      1      kind                  WorkItemKind as u8
17      8      created_commit_group           u64 BE
25      16     extent_map_root       BtreeRootPointer
41      64     cursor                [u8; 64] (opaque, resumable iteration state)
105     8      bytes_to_free_estimate u64 BE
113     8      extents_processed     u64 BE
121     1      flags                 WorkItemFlags (bit 0 = is_complete, bits 1-7 reserved)
122     6      reserved              [u8; 6] (must be zero)
─────────────────────────────────────────────────
Total:  128 bytes
```

- `is_complete()`: bit 0 of flags set
- `mark_complete()`: sets bit 0 of flags

**Design rationale for 128 bytes**: Fits in two 64-byte cache lines. Large enough for
a 64-byte opaque cursor for resumable extent-map iteration. Small enough that enqueueing
a work item never allocates — it's a single B+tree insertion of a fixed-size value.

### 2.3 `CleanupQueueKey` — B+tree compound key (9 bytes)

Defined in `tidefs-cleanup-queue-core`. Compound key `(inode_id_be_u64, kind_u8)`:

```
Offset  Size   Field
─────────────────────
0       8      inode_id (big-endian u64)
8       1      kind (WorkItemKind as u8)
─────────────────────
Total:  9 bytes
```

Big-endian inode_id ensures natural numeric ordering — items for lower inode IDs appear
first. The kind byte disambiguates multiple work items targeting the same inode (e.g.,
both a truncate and a later unlink).

### 2.4 `CleanupQueueStats` — per-queue observability

| Field | Type | Meaning |
|---|---|---|
| `total_count` | `u64` | Total items in queue (pending + completed) |
| `pending_count` | `u64` | Items not yet marked complete |
| `completed_count` | `u64` | Items marked complete but not yet deleted |
| `pending_bytes_estimate` | `u64` | Sum of `bytes_to_free_estimate` for pending items |

### 2.5 `CleanupQueue` trait

Defined in `tidefs-cleanup-queue-core`. The queue abstraction decoupled from any
specific B+tree implementation:

```rust
pub trait CleanupQueue {
    fn insert(&mut self, item: &CleanupWorkItemV1) -> CleanupQueueKey;
    fn get(&self, key: &CleanupQueueKey) -> Option<&CleanupWorkItemV1>;
    fn dequeue_next(&self, after: Option<&CleanupQueueKey>)
        -> Option<(CleanupQueueKey, &CleanupWorkItemV1)>;
    fn mark_complete(&mut self, key: &CleanupQueueKey) -> Result<(), CleanupQueueError>;
    fn delete(&mut self, key: &CleanupQueueKey) -> Result<(), CleanupQueueError>;
    fn is_empty(&self) -> bool;
    fn len(&self) -> usize;
    fn pending_count(&self) -> usize;
    fn stats(&self) -> CleanupQueueStats;
}
```

The `BPlusTreeCleanupQueue` is the default in-memory implementation backed by
`BTreeMap<CleanupQueueKey, CleanupWorkItemV1>`. The production runtime will use
`BPlusTree` from `tidefs-btree` with the same key/value types for on-disk storage.

---

## 3. Algorithms

### 3.1 Synchronous enqueue (Phase 1)

Called from syscall context (unlink, truncate, rmdir, rename):

```
Algorithm: enqueue_cleanup_work_item(inode, kind, extent_map_root, bytes_to_free)
  1. Assert: in commit_group commit scope
  2. Construct CleanupWorkItemV1:
     - magic = b"CLNWITEM"
     - inode_id = inode.id
     - kind = operation kind
     - created_commit_group = current_commit_group
     - extent_map_root = inode.extent_map.root_pointer
     - cursor = [0u8; 64] (fresh start)
     - bytes_to_free_estimate = estimated bytes
     - extents_processed = 0
     - flags = PENDING (0x00)
     - reserved = [0u8; 6]
  4. Insert into per-dataset cleanup queue B+tree
  5. Commit within current commit_group
  6. Return to caller (O(1) latency)
```

Key properties:
- No extent-map iteration (bounded work)
- No allocation proportional to extent count (bounded memory)
- Work item committed atomically with namespace update (crash safety)
- `st_blocks` already updated in Phase 1 step 3 (immediate logical accounting)

### 3.2 Background processing — `CleanupJob::step()` (Phase 2)

Called by the background scheduler with a `WorkBudget`:

```
Algorithm: CleanupJob::step(budget)
  1. If queue is empty → return StepResult { is_complete: true }
  2. Let items_this_step = 0, bytes_this_step = 0
  3. Loop:
     a. Dequeue next pending item from queue using current cursor
     b. If None → return StepResult { is_complete: true }
     c. Load inode from inode table
     d. Verify inode birth_commit_group == work_item.created_commit_group
        (stale work item detection — inode may have been re-created)
     e. If mismatch → discard stale item, continue
     f. Iterate extent map from cursor position:
        - For each extent beyond cursor (within budget):
          * Check if extent is shared with live snapshot (deadlist check)
          * Enqueue ReclaimQueueEntry for refcount decrement (#1180)
          * Advance cursor
          * Increment extents_processed, items_this_step, bytes_this_step
        - Stop when budget exhausted or extent map fully traversed
     g. If extent map fully traversed:
        - Mark work item complete
        - Delete work item from queue
     h. Else:
        - Persist updated cursor in work item
     i. If items_this_step >= budget.max_items → break
     j. If bytes_this_step >= budget.max_bytes → break
  4. Return StepResult { is_complete: queue is empty }
```

### 3.3 Crash recovery — `CleanupJob::resume()`

```
Algorithm: CleanupJob::resume(checkpoint)
  1. Deserialize cursor from checkpoint.cursor_state
     - Empty cursor → start from beginning of queue
     - Non-empty cursor → seek to position in queue
  2. Load queue from persisted B+tree root pointer in checkpoint
  3. Return CleanupJob positioned at cursor
  4. Background scheduler calls step() with next budget tick
```

Crash safety properties:
- Work items committed in same commit_group as namespace update → no lost work on crash
- Cursor advanced within work item after each extent processed → no duplicate deltas
- Stale work item detection via `created_commit_group` vs inode `birth_commit_group` → safe inode reuse
- `extents_processed > 0` on resume → continues from last processed extent

### 3.4 Stale work item detection

A work item can become stale if the inode is freed and then re-created with the
same inode_id before the work item is processed:

```
Algorithm: is_stale_work_item(work_item, current_inode)
  return work_item.created_commit_group != current_inode.birth_commit_group
```

If stale, the work item is discarded without processing — the new inode's extents
are unrelated to the old work item's extent map.

### 3.5 Priority boosting under ENOSPC pressure

When the dataset approaches ENOSPC, the cleanup job's scheduling priority is boosted:

| Condition | Priority | Budget | Behavior |
|---|---|---|---|
| Normal operation | `Throughput` (priority 2) | `DEFAULT_TICK` (1024 items, 64 MiB, 100 ms) | Steady background reclamation |
| ENOSPC pressure (>90% full) | `LatencySensitive` (priority 1) | `DEFAULT_TICK` | Accelerated reclamation |
| Critical ENOSPC (>98% full) | `Critical` (priority 0) | `MAINTENANCE_TICK` × 4 | Maximum reclamation, preempts other work |

The `bytes_to_free_estimate` field enables size-aware scheduling: under ENOSPC pressure,
the scheduler can prefer work items with larger estimates to maximize immediate space
recovery.

---

## 4. Queue Lifecycle

### 4.1 Per-dataset cleanup queue B+tree

Each dataset owns one cleanup queue B+tree, rooted at a `BtreeRootPointer` stored in
`DatasetMetadataV1`. The B+tree is keyed by `CleanupQueueKey` (inode_id, kind) and stores
`CleanupWorkItemV1` as values.

### 4.2 Queue insertion (syscall context)

```
unlink() → Phase 1 → CleanupWorkItemV1 { kind: UnlinkFree, ... }
                      → B+tree insert(CleanupQueueKey(inode, UnlinkFree), item)
```

Duplicate keys are handled by replacement: if a work item already exists for the same
(inode_id, kind), the new item replaces the old one. This handles edge cases like two
truncates on the same inode before the background worker processes the first.

### 4.3 Queue processing order

Items are dequeued in `(inode_id, kind)` order (natural B+tree key order). This means:
- Lower inode IDs are processed first (FIFO-ish by inode creation order)
- For the same inode, `UnlinkFree` (0) comes before `TruncateFree` (1), which is
  correct: the truncate extent range is a subset of the unlink range

### 4.4 Queue completion and deletion

```
dequeue_next() → process extents within budget → mark_complete() → delete()
```

Items are never deleted until `mark_complete()` has been called. This ensures that a
crash between dequeue and completion does not lose the work item — on resume, the item
is re-dequeued with `extents_processed` indicating where to continue.

---

## 5. Integration with Reclaim Queues

The cleanup job does not free extents directly. Instead, it produces refcount deltas
consumed by the reclaim queue system (#1180):

```
CleanupJob::step()
  ├── extent A freed → ReclaimQueueEntry { object_key, delta: -1, family: Extent }
  ├── extent B freed → ReclaimQueueEntry { object_key, delta: -1, family: Extent }
  └── all extents freed → locator freed → ReclaimQueueEntry { object_key, delta: -1, family: Locator }
```

The four reclaim queue families:

| Family | Trigger | Processing |
|---|---|---|
| `Extent` | Refcount drops to 0 | Free extent payload data |
| `Locator` | Locator entry deleted | Free extent ID; enqueue rebake if parity shards exist |
| `Rebake` | Data shard freed, parity alive | Recompute erasure-coding parity |
| `InodeTombstone` | nlink→0, handles closed | Compact inode from inode table |

The cleanup job only produces `Extent` and `Locator` deltas. `Rebake` and `InodeTombstone`
are triggered as downstream effects by the reclaim queue processor.

---

## 6. Crash Safety and Correctness

### 6.1 Invariants

1. **No lost work**: Work item committed in same commit_group as namespace update. On crash,
   both survive or neither does — no "unlinked but not queued" state.
2. **No duplicate work**: Cursor advances after each extent is processed. On crash
   and resume, the cursor position prevents re-processing already-freed extents.
3. **No stale work**: `created_commit_group` check against inode `birth_commit_group` prevents
   processing work items for re-created inodes.
4. **No in-flight leaks**: `mark_complete()` + `delete()` is atomic from the
   perspective of crash recovery. A partially-processed work item on resume
   continues from the last cursor position.
5. **Physical space not freed until safe**: Refcount deltas go through the
   deadlist check (#1232) — extents shared with live snapshots are not freed.

### 6.2 Crash scenarios

| Scenario | Behavior | Correctness |
|---|---|---|
| Crash before work item committed | Namespace update rolled back; no work item | Correct — nothing to reclaim |
| Crash after work item committed, before processing | On mount, queue contains work item; CleanupJob resumes from empty cursor | Correct — full extent map traversed |
| Crash mid-processing (3 of 10 extents freed) | On resume, cursor at extent 4; remaining 7 processed | Correct — no duplicates, no gaps |
| Inode re-created before work item processed | `birth_commit_group` mismatch detected; work item discarded | Correct — stale work ignored |

### 6.3 Fence and ordering guarantees

- Work item insert is ordered after namespace update within the same commit_group.
- Cursor updates are ordered before mark_complete.
- Reclaim queue delta enqueue is ordered before cursor advance for each extent.
- On crash, the commit_group recovery process replays the namespace update → work item exists.

---

## 7. Concurrency Model

### 7.1 Single-writer queue

The per-dataset cleanup queue has a single writer (syscall context) and a single
reader (CleanupJob worker). This avoids all lock contention on the queue B+tree:

- **Writer (syscall)**: Inserts work items during commit_group commit. Serialized by commit_group commit
  lock. Never reads or modifies existing items.
- **Reader (CleanupJob)**: Dequeues and processes work items. Updates cursor and marks
  complete. Never inserts new items.

### 7.2 Extent-map concurrency

The extent map being iterated by CleanupJob may be concurrently modified by other
operations on the same inode. The concurrency contract:

- Once a work item's `extent_map_root` is captured, the CleanupJob owns the
  right to free extents referenced by that root.
- New writes after the work item was created go to a new extent map root
  (copy-on-write B+tree semantics).
- The stale work item check (`created_commit_group` vs `birth_commit_group`) handles the
  case where the entire inode is replaced.

### 7.3 Dataset-wide concurrency

Multiple datasets may each have an active CleanupJob. These run independently under
the background scheduler's priority and round-robin dispatch. No cross-dataset
coordination is required.

---

## 8. Space Accounting Correctness

### 8.1 Logical vs physical counters

| Counter | Updated by | When |
|---|---|---|
| `logical_used_bytes` | Phase 1 (syscall) | Immediately, within commit_group |
| `st_blocks` | Phase 1 (syscall) | Immediately, within commit_group |
| `physical_used_bytes` | Phase 2 (CleanupJob) | Gradually, as extents freed |
| `phys_reclaimable_bytes` | Phase 1 (syscall) | Immediately, as estimate |
| `df` (statfs) | Phase 1 (syscall) | Immediately, based on logical |

**Key invariant**: `logical_used_bytes` ≤ `physical_used_bytes` at all times.
`phys_reclaimable_bytes = physical_used_bytes - logical_used_bytes` is the amount
of physical space awaiting reclamation.

### 8.2 ENOSPC correctness

After a large unlink, `logical_used_bytes` drops immediately, so `statfs` shows
free space. The application can write to the newly-freed logical space immediately.

Physical space is reclaimed asynchronously. If physical space runs low before
reclamation completes:

1. The background scheduler detects ENOSPC pressure via space accounting.
2. CleanupJob priority is boosted (see §3.5).
3. If still insufficient, the write path blocks with `ENOSPC` — as it should,
   since physical space is genuinely exhausted.

---

## 9. Comparison to ZFS and Ceph

### 9.1 ZFS

| Aspect | ZFS | TideFS |
|---|---|---|
| Unlink of large file | `dmu_free_long_range()` blocks caller for O(extents) time | 128-byte `CleanupWorkItemV1` enqueued in O(1), returns immediately |
| Background reclamation | `bpobj` processed synchronously in `spa_sync` | `CleanupJob` runs as budgeted background task, never blocks application IO |
| Crash safety | `bpobj` is part of commit_group; recovery replays it | Work item committed atomically with namespace update; cursor-based resume |
| Priority model | No priority — `bpobj` competes with application IO in `spa_sync` | `Throughput` priority with ENOSPC boosting to `Critical` |
| Work item limit | Unlimited — `bpobj` can grow to gigabytes | Soft cap of 10,000 items; beyond that, limited inline free |
| Stale work detection | None — `bpobj` entries always processed | `created_commit_group` vs `birth_commit_group` check |

**Key ZFS weakness**: On a 10 TiB file with 128 KiB recordsize (~80M extents), `rm`
can hang for minutes. TideFS enqueues a 128-byte work item and returns immediately.

### 9.2 Ceph

| Aspect | Ceph | TideFS |
|---|---|---|
| Unlink of large file | MDS blocks during unlink | O(1) work item enqueue |
| Deferred work queue | None — MDS journal is closest analogue | Typed, per-dataset B+tree queue |
| Background reclamation | PG removal, per-PG, no global scheduling | Unified `IncrementalJob` contract with budget enforcement |
| Space accounting | Implicit via OSD snap trimming | Explicit logical/physical split with `phys_reclaimable_bytes` |

**Key Ceph weakness**: No deferred work-queue abstraction; space accounting and
reclamation are coupled directly to the metadata operation. TideFS decouples
enqueue (O(log N), 128 bytes) from reclamation (bounded background ticks).

---

## 10. Implementation Status

### 10.1 Implemented crates (Phases 1–3)

Phases 1–3 are implemented and tested. The three crates provide the type system,
queue operations, and incremental-job wrapper that form the foundation for the
deferred cleanup framework.

| Phase | Crate | Status | Content |
|---|---|---|---|
| Phase 2 | `tidefs-cleanup-queue-core` | ✅ Implemented | `CleanupQueueKey` (9-byte compound key: inode_id BE + kind u8), `CleanupQueue` trait, `BPlusTreeCleanupQueue` in-memory impl, `CleanupQueueStats`, `CleanupQueueError`, `dequeue_next()` cursor-based iteration, duplicate-key replacement semantics, 29 unit tests |
| Phase 3 | `tidefs-cleanup-job-core` | ✅ Implemented | `CleanupJob` (implements `IncrementalJob` trait from #1239), `resume()` checkpoint reconstruction, `step()` budget-bounded dequeue/complete/delete loop, `build_checkpoint()` cursor serialization, stale-item detection via `birth_commit_group` vs `created_commit_group`, `complete()`, 14 unit tests |

**Phase 3 scope note**: The current `CleanupJob::step()` processes work items by
dequeuing, marking complete, and deleting from the in-memory `BPlusTreeCleanupQueue`.
Refcount delta enqueue to reclaim queues (#1180) and extent-map iteration are
deferred to Phase 4 and Phase 5 wire-up implementations. The checkpoint cursor
serialization, resume infrastructure, and stale-item detection are fully implemented.

### 10.2 Remaining phases (deferred to wire-up issues)

The following phases are **design-complete** but their Rust implementation is
deferred to separate wire-up issues. Each wire-up issue must reference this
design spec (#1668) as its design authority.

| Phase | Scope | Depends on | Suggested wire-up issue |
|---|---|---|---|
| Phase 4 | Extent-map iteration in `CleanupJob::step()`: bounded walk through the extent map referenced by `extent_map_root`, producing individual extent ranges for refcount delta enqueue. Must respect `WorkBudget` and advance the 64-byte opaque cursor. | #1191 (extent-map range delete), #1239 (cursor framework) | "Wire up Phase 4: extent-map iteration in CleanupJob" |
| Phase 5 | Refcount delta enqueue to reclaim queues: for each freed extent, create `ReclaimQueueEntry` with `delta: -1` and `family: Extent`. When all extents freed, enqueue `Locator` family delta. Integrate with deadlist check for snapshot safety. | #1180 (reclaim queues), #1191, #1232 (deadlist) | "Wire up Phase 5: refcount delta enqueue from CleanupJob" |
| Phase 6 | Per-dataset on-disk cleanup B+tree integration: store cleanup queue root pointer in `DatasetMetadataV1`, implement on-disk B+tree operations backed by the pool allocator, integrate with commit_group commit to ensure work items are committed atomically with namespace updates. | #1207 (orphan index), `DatasetMetadataV1`, pool allocator | "Wire up Phase 6: on-disk cleanup queue B+tree integration" |
| Phase 7 | Background service scheduling and ENOSPC integration: register `CleanupJob` in `BackgroundService` (#1179) at `Throughput` priority, implement priority boosting to `Critical` under ENOSPC pressure, integrate with `phys_reclaimable_bytes` tracking for admission control, wire the 10,000-item soft cap with limited inline free fallback. | #1179 (background service), #1215 (space accounting), space-pressure handling | "Wire up Phase 7: CleanupJob scheduling and ENOSPC integration" |

### 10.3 Wire-up issue charter

Each Phase 4–7 wire-up issue should follow this charter:

1. **Design authority**: Reference this document (#1668) and cite specific sections.
2. **Write set**: The crate(s) to be modified, with explicit file paths.
4. **Dependencies**: All prerequisite issues must be closed before the wire-up
   issue leaves `codex:ready`.
6. **Closeout**: Update `docs/STATUS.md` and `docs/FEATURE_MATRIX.md` when
   capability state changes.


The xtask gate `tidefs-xtask check-deferred-cleanup` verifies:

1. Spec, feature matrix, and status entries present.
2. Phase 1 types compile with `no_std` + optional `alloc`.
3. `CleanupWorkItemV1` round-trip: serialize → deserialize → assert equality.
4. `CleanupQueue` operations: insert → dequeue → verify ordering.
5. Synchronous-phase algorithms: unlink creates work item, truncate creates work
   item, no extent-map iteration in syscall context.
6. `CleanupJob::step()`: respects `WorkBudget`, produces refcount deltas, advances
   cursor, marks complete.
7. Crash simulation: enqueue items → process 3 steps → crash → resume → verify
   no duplicate deltas, no lost work.
8. Space accounting: `st_blocks` after unlink, `df` after unlink, ENOSPC not
   returned after large delete.
9. Stale work item detection: inode re-created → old work item discarded.
10. Budget enforcement: step() never exceeds `max_items`, `max_bytes`.

---

## 12. Tradeoffs and Design Decisions

### 12.1 128-byte fixed-size work item

**Pro**: Bounded memory, no heap allocation during syscall, cache-line-friendly.
**Con**: 64-byte cursor may be insufficient for very complex extent maps (e.g.,
deeply nested B+trees with many levels). Mitigation: cursor is opaque and can store
compressed path information; 64 bytes is sufficient for B+trees up to depth ~8 with
256-byte nodes.

### 12.2 (inode_id, kind) key ordering

**Pro**: Natural clustering by inode, simple implementation, deterministic order.
**Con**: No priority for large items under normal operation. Mitigation: ENOSPC
pressure triggers size-aware scheduling that can override key order.

### 12.3 Soft cap of 10,000 outstanding work items

**Pro**: Bounds worst-case queue memory/disk footprint (~1.28 MB for 10,000 items).
**Con**: Extremely heavy delete workloads (many large files deleted in rapid
succession) could hit the cap. Mitigation: above 10,000 items, the synchronous
phase does limited inline free (up to 64 extents) to reduce backlog.

### 12.4 Work item cancellation via birth_commit_group

**Pro**: Simple, race-free, no cross-subsystem coordination needed.
**Con**: Requires inode table lookup during processing. Mitigation: inode table
lookup is already needed for deadlist checks; marginal additional cost.

### 12.5 Single reader, single writer queue

**Pro**: No lock contention, simple correctness model.
**Con**: Cannot parallelize cleanup across multiple worker threads for a single
dataset. Mitigation: multiple datasets each have independent queues that can be
processed in parallel by different worker threads.

---

## 13. Open Questions

1. **Work item priority ordering**: Should the cleanup queue dequeue in FIFO order
   (oldest work item first) or largest-first (maximize immediate space reclaim)?
   FIFO is simpler and prevents starvation. Largest-first is better for ENOSPC
   pressure. Proposal: FIFO by default, with an admin-triggered "reclaim burst"
   mode that selects by `bytes_to_free_estimate` descending.

2. **Work item limit**: Should there be a per-dataset cap on the number of
   outstanding work items? Proposal: soft cap of 10,000; beyond that, the
   synchronous phase does a limited inline free (up to 64 extents) to reduce
   backlog.

3. **Snapshot interaction**: When a work item's `extent_map_root` references
   extents shared with a live snapshot, the refcount decrement must not free the
   extent's storage — only the deadlist (#1232) gates actual segment freeing.
   The work item's refcount delta goes through the normal deadlist check.

4. **Rename-overwrite**: When `renameat2(RENAME_EXCHANGE)` swaps two files,
   should there be work items for both old targets? Proposal: yes, one item per
   overwritten inode.

5. **Work item cancellation**: If an inode is re-created with the same inode_id
   before the work item is processed, the worker must detect this via `created_commit_group`
   vs `birth_commit_group` comparison. Implemented in CleanupJob::step().

6. **Cluster-aware cleanup**: In a multi-node cluster, should cleanup work items
   be processed by the node that owns the dataset, or distributed? Proposal:
   dataset-owning node processes its own cleanup queue; remote nodes only process
   reclaim deltas that affect shared extents.

---

## 14. Dataset Lifecycle Interactions

### 14.1 Dataset destruction

When a dataset is destroyed:

1. All pending cleanup work items in the dataset's queue are discarded — the
   dataset's storage segments are freed en masse by the dataset destruction
   path, making per-extent refcount deltas unnecessary.
2. The cleanup queue B+tree itself is freed as part of dataset metadata teardown.
3. Any in-progress `CleanupJob` for the dataset is cancelled by the background
   scheduler via `IncrementalJob::cancel()`.

### 14.2 Dataset snapshot

A read-only snapshot of a dataset includes the cleanup queue B+tree in its
state. However:

- Snapshot cleanup items reference extents in the **live** dataset's extent maps.
  When a snapshot exists, extents freed by a work item must be checked against
  the snapshot's deadlist before physical storage is released.
- The deadlist check in `CleanupJob::step()` (step 3f) prevents premature freeing
  of extents shared with live snapshots.
- SnapDelete work items are enqueued when a snapshot is deleted, not when one
  is created.

### 14.3 Dataset send/receive

Cleanup work items are **not** included in send streams:

- The receiving side reconstructs extent maps from the send stream; it does not
  need the sender's cleanup queue state.
- If the send stream includes an inode that was mid-cleanup on the sender, the
  receive side gets a consistent extent map snapshot — the sender's cleanup
  worker processes items independently.
- Receiving a dataset that was destroyed on the sender is handled by the dataset
  destruction path, not by cleanup work items.

### 14.4 Dataset rename

Dataset renames do not affect the cleanup queue. The queue is keyed by inode_id,
which is scoped to the dataset and unchanged by dataset renames.

## 15. Extent Map Root Lifecycle

When a work item is enqueued, the `extent_map_root` field snapshots the inode's
current extent map B+tree root pointer. This snapshot is critical for correctness
under inode reuse:

```text
Time ─────────────────────────────────────────────────────▶

 inode_id=42 (birth_commit_group=100)
   │
   ├─ unlink → enqueue work_item { inode_id=42, created_commit_group=100,
   │              extent_map_root = 0xABCD }
   │
   ├─ inode tombstoned, id=42 recycled
   │
   ├─ new inode_id=42 (birth_commit_group=250)
   │   └─ new extent_map_root = 0x5678
   │
   └─ CleanupJob::step() finds work_item:
        - created_commit_group (100) ≠ birth_commit_group (250) → STALE, discard
        - work_item's extent_map_root (0xABCD) is never traversed
```

The `extent_map_root` value becomes dangling (points to a freed B+tree root) once
the inode is destroyed. This is safe because:

1. The birth_commit_group check gates access: stale items are discarded before any
   `extent_map_root` dereference.
2. If the inode is still live (`birth_commit_group == created_commit_group`), the extent map root
   is guaranteed valid — it belongs to the same inode incarnation.
3. After the work item completes, no further reference to the old root exists.

For `TruncateFree` and `PunchHoleFree`, the extent_map_root remains valid even
after the work item is processed because the inode is still live (only a range
was freed, not the whole inode). Subsequent truncates create new work items
with the inode's current extent_map_root at that time, which may differ from
the root at enqueue time if concurrent writes extended the extent map.

## 16. Cursor Format — Opaque 64-byte Blob

The 64-byte cursor field is deliberately opaque at the type level to allow
future evolution of the extent-map iteration strategy without on-media format
changes. Current design for the cursor contents (deferred to Phase 4 wire-up):

| Offset | Size | Field | Description |
|---|---|---|---|
| 0 | 8 | block_index | Logical block offset within the file (extents processed so far) |
| 8 | 8 | extent_id | Last extent ID processed (for extent-map B+tree seek) |
| 16 | 8 | btree_level | Current B+tree depth position |
| 24 | 40 | path_stack | Compressed B+tree path (5 × 8-byte node pointers for depth ≤ 5) |

For very deep extent maps (>5 levels), the path_stack can store a compressed
representation using prefix coding of node pointers, trading precision for
space. The 64 bytes can represent B+tree paths up to depth ~64 using 1-byte
child-index encoding per level, sufficient for any practical extent map.

**Pro**: Encapsulated format evolution, no on-media format version bump for
cursor changes. **Con**: Opaque blob requires the cleanup job to own the
serialization format; cross-crate cursor inspection is impossible without
versioned deserialization. **Mitigation**: cursor is only read/written by
`CleanupJob`; other subsystems interact through the `CursorState` opaque
container.

## 17. Invariants and Edge Cases

### 17.1 Safety invariants

| # | Invariant | Enforcement |
|---|---|---|
| I3 | Cursor is zeroed at enqueue (fresh start) | Constructor zeroes `[0u8; 64]` |
| I4 | Stale work items are never processed | `created_commit_group ≠ birth_commit_group` check in `step()` |
| I5 | Completed items are deleted, not re-processed | `dequeue_next()` skips completed items |
| I6 | No refcount delta is enqueued twice for the same extent | Cursor advances atomically per extent |
| I7 | Queue insertion is idempotent per (inode_id, kind) | Duplicate key replacement |
| I8 | `st_blocks` reflects logical free immediately after unlink/truncate | Phase 1 updates logical counters |

### 17.2 Edge cases

| Scenario | Behavior |
|---|---|
| Unlink then immediate re-create with same inode_id | Stale detection via birth_commit_group; old item discarded |
| Two truncates on same inode before processing | Second truncate replaces first work item (same key) |
| Truncate followed by unlink before processing | UnlinkFree replaces TruncateFree (different key, same inode); old TruncateFree is superseded |
| Punch hole on inode with pending TruncateFree | PunchHoleFree is a separate key; both are processed |
| Dataset destroyed with pending work items | All items discarded; segments freed en masse |
| Crash mid-queue-processing | Cursor checkpoint resumes from last processed key |
| ENOSPC during cleanup job step() | Job stops at budget; no partial extent freeing |
| 10,000-item cap hit during heavy delete workload | Limited inline free (64 extents) per subsequent unlink |
| Rmdir on non-empty directory (upstream bug) | RmdirFree work item enqueued but directory extents leaked; detection is upstream responsibility |
| Rename overwrite with RENAME_EXCHANGE | Two separate work items: one per overwritten inode (each side of the exchange) |
| Power loss after Phase 1 but before Phase 2 | Work item persisted in commit_group; recovered on next mount |
