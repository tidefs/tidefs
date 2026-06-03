# Deferred Cleanup Work Queues Design (P2)

Maturity: **design-spec** for the bounded-memory work-item framework that decouples
synchronous syscall work (unlink, truncate, rmdir, rename-overwrite) from unbounded
extent-map iteration, ensuring O(1) per-syscall memory while guaranteeing eventual
space reclamation through the background `IncrementalJob` infrastructure.

This document closes Forgejo issue #1212.

## 1. Motivation

POSIX unlink, truncate, and rmdir on large files create a fundamental tension:
the caller expects the syscall to return promptly, but the filesystem must reclaim
the file's storage — potentially millions of extents spanning terabytes. Naive
code builds in-memory lists of every extent and blows RAM. Even a streaming
walk adds unpredictable latency to what the application expects to be fast.

ZFS illustrates the anti-pattern: `zfs_rmdir` and `zfs_znode_delete` perform a
synchronous `dmu_free_long_range` that blocks the caller for O(extents) time.
On a 10 TiB file with 128 KiB recordsize (~80M extents), `rm` can hang for minutes.
CephFS similarly blocks the MDS during unlink of large files.

tidefs must guarantee:

- **Bounded synchronous work**: unlink/truncate syscall latency is O(directory entry
  depth + inode metadata) regardless of file size or extent count
- **Bounded memory**: no allocation proportional to extent count
- **Eventual reclamation**: all freed space is eventually recovered by background
  workers
- **Crash safety**: a crash between syscall return and reclamation completion loses
  no work and duplicates no work
- **Consistent space accounting**: `st_blocks` and `df` reflect freed space
  immediately; physical segment reuse converges in bounded time

## 2. Relationship to Existing Designs

| Design | Integration point | This design provides |
|---|---|---|
| #1239 (incremental cursor framework) | Background worker contract | `CleanupJob` implements `IncrementalJob` with CLEANUP JobKind |
| #1180 (refcount delta queues) | Reclaim target | Work items produce refcount deltas consumed by reclaim queue |
| #1179 (background service) | Scheduling | `CleanupWorker` runs as a bounded-per-tick BackgroundService |
| #1267 (commit_group state machine) | Transactional consistency | Work items committed in same commit_group as namespace update |
| #1215 (space accounting) | Logical vs physical counters | Synchronous phase updates logical counters; physical freed by worker |
| #1191 (extent management) | Range-oriented extent ops | Extent-map range delete is a prerequisite for deferred cleanup |
| #1285 (locator tables) | Refcount lifecycle | Deferred cleanup decrements refcounts via locator table operations |

## 3. Design Principle: Two-Phase Deletion

Every space-freeing namespace operation is split into two phases:

### Phase 1: Synchronous metadata commit (syscall context)

The syscall performs only metadata work — bounded by directory entry depth, not
file size — and commits within a single commit_group:

1. **Namespace update**: Remove dentry, update parent directory cookies,
   update mtime/ctime, decrement link count on target inode
2. **Inode state update**: For truncate, update `size_bytes` to new size;
   for unlink with nlink→0, mark inode as orphaned (#1207)
3. **Logical space accounting**: Update `DatasetSpaceCountersV1.logical_used_bytes`
   and inode `alloc_bytes` so `st_blocks` is immediately correct
4. **Work item enqueue**: Persist a small `CleanupWorkItem` (≤128 bytes) into
   the per-dataset cleanup queue B+tree

This phase must **never** iterate extent-map entries, refcount tables, or
locator records. Its work is O(directory depth + constant).

### Phase 2: Background reclamation (worker context)

A background `CleanupJob` implementing `IncrementalJob` (#1239) processes
enqueued work items in bounded batches:

1. Dequeue `CleanupWorkItem` from the per-dataset cleanup queue
2. Iterate the affected extent map using the stored cursor, within `WorkBudget`
3. For each freed extent, enqueue a refcount delta into the reclaim queue (#1180)
4. Persist the updated cursor in the `Checkpoint`
5. When all extents for a work item are processed, mark it complete and delete it

## 4. On-Media Format

### 4.1 CleanupWorkItem

A persistent record representing a deferred cleanup operation, stored in a
per-dataset B+tree keyed by `(inode_id_be_u64, work_item_kind_be_u8)`:

```rust
/// A deferred cleanup operation persisted at syscall time and processed
/// by the background CleanupJob.
///
/// On-media layout (total: 128 bytes, fixed-size):
///   [0..8)   magic: b"CLNWITEM" (8 bytes)
///   [8..16)  inode_id: u64 BE
///   [16]     kind: WorkItemKind as u8
///   [17..25) created_commit_group: u64 BE
///   [25..41) extent_map_root: BtreeRootPointer (16 bytes)
///   [41..105) cursor: [u8; 64] — opaque cursor state for resumable extent-map iteration
///   [105..113) bytes_to_free_estimate: u64 BE
///   [113..121) extents_processed: u64 BE
///   [121]     flags: u8
///   [122..128) reserved: [u8; 6]
pub struct CleanupWorkItemV1 {
    pub magic: [u8; 8],           // b"CLNWITEM"
    pub inode_id: u64,            // BE
    pub kind: WorkItemKind,
    pub created_commit_group: u64,         // BE — commit_group in which the item was enqueued
    pub extent_map_root: BtreeRootPointer,  // snapshot of the extent-map root at enqueue time
    pub cursor: [u8; 64],         // opaque cursor for resumable extent-map traversal
    pub bytes_to_free_estimate: u64,  // BE — estimated bytes to free (from extent-map subtree sum)
    pub extents_processed: u64,   // BE — running count of extents processed so far
    pub flags: u8,                // bit 0: is_complete, bits 1-7: reserved
}
```

### 4.2 WorkItemKind

```rust
/// The kind of deferred cleanup operation.
///
/// On-media encoding: u8, values below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WorkItemKind {
    /// Unlink of last link to an inode (nlink → 0).
    /// Frees all extents belonging to the inode.
    UnlinkFree = 0,
    /// Truncate to a smaller size.
    /// Frees extents beyond the new EOF.
    TruncateFree = 1,
    /// Rmdir of an empty directory.
    /// Frees directory block extents.
    RmdirFree = 2,
    /// Rename that overwrites an existing target.
    /// Frees the overwritten target's extents.
    RenameOverwrite = 3,
    /// Snapshot deletion.
    /// Frees extents that are unique to the deleted snapshot.
    SnapDelete = 4,
    /// Punch hole (fallocate FALLOC_FL_PUNCH_HOLE).
    /// Frees extents within the punched range.
    PunchHoleFree = 5,
}
```

### 4.3 Per-dataset cleanup queue

A persistent B+tree rooted in the dataset metadata, keyed by `(inode_id_be_u64,
work_item_kind_be_u8)` to enable efficient lookup and delete-on-completion:

```
cleanup_queue_root: BtreeRootPointer  // in DatasetMetadataV1
```

The B+tree maps `(inode_id: u64 BE, kind: u8) → CleanupWorkItemV1`. The composite
key ensures that multiple work items can reference the same inode (e.g., a
`TruncateFree` followed by an `UnlinkFree` on the same inode are distinct entries).

## 5. Synchronous Phase Algorithm

### 5.1 Unlink (nlink → 0 after last directory entry removal)

```text
fn unlink_last_link(inode):
    // Phase 1: Metadata-only synchronous work
    commit_group.begin()

    // 1. Remove dentry, update parent, drop link count
    dir_index.remove(dentry)
    inode.nlink = 0
    inode.update_timestamps()

    // 2. Update space accounting (immediate; st_blocks is correct)
    freed_logical = inode.alloc_bytes
    dataset.counters.logical_used_bytes -= freed_logical
    inode.alloc_bytes = 0
    inode.size_bytes = 0
    inode.extent_map_root = NULL_ROOT

    // 3. Enqueue work item (≤128 bytes, no extent iteration)
    item = CleanupWorkItemV1 {
        magic: b"CLNWITEM",
        inode_id: inode.id,
        kind: UnlinkFree,
        created_commit_group: commit_group.id,
        extent_map_root: old_extent_map_root,  // saved before nulling
        cursor: zeros,
        bytes_to_free_estimate: freed_logical, // from extent-map subtree summary
        extents_processed: 0,
        flags: 0,
    }
    cleanup_queue.insert(item)

    // 4. Insert into orphan index (#1207) so crash recovery can find it
    orphan_index.insert(inode.id)

    commit_group.commit()
    return 0  // success, O(1) work
```

### 5.2 Truncate (size reduction)

```text
fn truncate_shrink(inode, new_size):
    commit_group.begin()

    // 1. Determine freed range
    old_size = inode.size_bytes
    freed_range = (new_size, old_size)

    // 2. Update inode state
    inode.size_bytes = new_size

    // 3. Compute freed bytes from extent-map subtree summary
    freed_bytes = extent_map.subtree_sum(freed_range).total_alloc_bytes
    dataset.counters.logical_used_bytes -= freed_bytes
    inode.alloc_bytes -= freed_bytes

    // 4. Replace extent map root with truncated version
    //    (truncation within extent map is range-delete, O(log N))
    old_root = inode.extent_map_root
    new_root = extent_map.range_delete(freed_range)
    inode.extent_map_root = new_root

    // 5. Enqueue work item for extent reclamation
    item = CleanupWorkItemV1 {
        inode_id: inode.id,
        kind: TruncateFree,
        extent_map_root: old_root,  // frozen snapshot for background iteration
        bytes_to_free_estimate: freed_bytes,
        ...
    }
    cleanup_queue.insert(item)

    commit_group.commit()
    return 0
```

### 5.3 Key invariant: Extent-map subtree summaries

Both algorithms rely on the extent map providing subtree summaries — aggregate
`total_alloc_bytes` per internal node. This enables O(log N) computation of
freed bytes without enumerating individual extents:

```rust
/// Per-node summary stored in extent-map internal pages.
struct ExtentMapSubtreeSummary {
    /// Total allocated bytes (DATA extents) in this subtree.
    total_alloc_bytes: u64,
    /// Total UNWRITTEN bytes (reservations) in this subtree.
    total_unwritten_bytes: u64,
    /// Total extent count in this subtree.
    extent_count: u64,
}
```

The `bytes_to_free_estimate` in the `CleanupWorkItemV1` is populated from
this summary at enqueue time. It drives space accounting decisions (e.g.,
"safety reserve relaxed because 500 GiB of reclaim is in-flight") without
scanning the extent map.

## 6. Background CleanupJob

### 6.1 IncrementalJob implementation

```rust
/// Background worker that processes deferred cleanup work items.
///
/// Implements IncrementalJob from #1239 with JobKind::Cleanup.
pub struct CleanupJob {
    job_id: JobId,
    dataset_id: DatasetId,
    queue: CleanupQueue,          // per-dataset cleanup B+tree
    current_item: Option<CleanupWorkItemV1>,
    extent_map: Arc<ExtentMap>,   // for extent iteration
    reclaim_queue: Arc<ReclaimQueue>,  // #1180 delta queue
    progress: JobProgress,
    epoch: u64,
}

impl IncrementalJob for CleanupJob {
    fn resume(state: Option<Checkpoint>) -> Result<Self, JobError> {
        if let Some(cp) = state {
            // Deserialize cursor: (inode_id, kind, extent_map_position)
            let (inode_id, kind, em_cursor) = CursorState::deserialize(&cp.cursor)?;
            // Reload the work item from queue
            let item = cleanup_queue.get(inode_id, kind)?;
            Ok(Self { current_item: Some(item), ... })
        } else {
            // Fresh start: dequeue the first work item
            Ok(Self { current_item: None, ... })
        }
    }

    fn step(&mut self, budget: WorkBudget) -> Result<StepResult, JobError> {
        let mut items_processed = 0u64;
        let mut bytes_freed = 0u64;

        // Pick up next item if none is active
        if self.current_item.is_none() {
            self.current_item = self.queue.dequeue_next()?;
        }

        while let Some(ref mut item) = self.current_item {
            // Check budget
            if items_processed >= budget.max_items { break; }
            if bytes_freed >= budget.max_bytes { break; }

            // Iterate extents from cursor position, within remaining budget
            let batch_budget = WorkBudget {
                max_items: budget.max_items - items_processed,
                max_bytes: budget.max_bytes - bytes_freed,
                max_ms: 0,
            };

            let (batch, next_cursor, is_done) = self.extent_map
                .iter_extents_from(item.extent_map_root, &item.cursor, batch_budget)?;

            // Enqueue refcount deltas for each freed extent
            for extent in &batch {
                self.reclaim_queue.enqueue_delta(
                    extent.object_key,
                    -1,  // decrement refcount
                )?;
                bytes_freed += extent.alloc_bytes;
                items_processed += 1;
            }

            item.extents_processed += batch.len() as u64;
            item.cursor = next_cursor;

            if is_done {
                // All extents processed: delete work item, move to next
                self.queue.delete(item.inode_id, item.kind)?;
                self.current_item = self.queue.dequeue_next()?;
            }

            self.progress.items_processed += items_processed;
            self.progress.bytes_freed += bytes_freed;
        }

        let is_complete = self.current_item.is_none()
            && self.queue.is_empty()?;

        let cursor = if let Some(ref item) = self.current_item {
            CursorState::serialize(item.inode_id, item.kind, &item.cursor)
        } else {
            CursorState::empty()
        };

        Ok(StepResult {
            checkpoint: Checkpoint {
                job_id: self.job_id,
                job_kind: JobKind::Cleanup,
                epoch: self.epoch,
                cursor,
                progress: self.progress,
            },
            items_this_step: items_processed,
            is_complete,
        })
    }

    fn persist_checkpoint(&self, checkpoint: &Checkpoint) -> Result<(), JobError> {
        // Persist via CheckpointStore in same commit_group as the reclaim deltas
        self.checkpoint_store.save(checkpoint)
    }

    fn complete(self) -> Result<(), JobError> {
        self.checkpoint_store.delete(self.job_id)
    }

    fn job_id(&self) -> JobId { self.job_id }
    fn job_kind(&self) -> JobKind { JobKind::Cleanup }
}
```

### 6.2 Boundedness guarantee

The `CleanupJob` respects `WorkBudget` at two levels:
- **Per-extent**: Each extent-map cursor advance is O(log N) in the B+tree, not
  proportional to total extent count
- **Per-step**: The `iter_extents_from()` method accepts a budget and returns at
  most `max_items` extents, regardless of how many remain

This guarantees the background worker never allocates O(total-extents) memory
and never blocks the commit_group sync for unbounded time.

### 6.3 Crash safety

The cleanup job integrates with the cursor framework's crash safety model (#1239 §5):

- **commit_group atomicity**: Reclaim deltas and cursor advances are committed in the same
  commit_group. Either both persist (progress) or neither does (safe retry).
- **Idempotency**: The refcount delta queue (#1180) applies deltas idempotently —
  a double-decrement on the same object key is detected and skipped.
- **Work item snapshot**: The `extent_map_root` pointer in the work item is a frozen
  snapshot captured at enqueue time. Even if the inode is subsequently modified
  (new writes), the cleanup worker iterates the frozen root, ensuring it only
  frees extents that were live at deletion time.
- **Cursor resumption**: The opaque cursor records the exact B+tree position (page
  ID + index within page). After crash, `resume()` reloads the work item and
  repositions the extent-map iterator at the cursor position.

## 7. Space Accounting Consistency

### 7.1 Logical vs physical counters

The two-phase design introduces a distinction between logical and physical
space accounting:

| Counter | Updated when | Reflects |
|---|---|---|
| `logical_used_bytes` | Synchronous phase (unlink/truncate commit_group) | Application-visible space: `st_blocks`, `df`, quota |
| `logical_avail_bytes` | Synchronous phase | Derived: `total - logical_used - reservations` |
| `phys_alloc_bytes` | Background worker (reclaim commit_group) | Actually allocated segments on devices |
| `phys_reclaimable_bytes` | Synchronous phase (work item enqueue) | Bytes pending reclamation: `sum(work_item.bytes_to_free_estimate)` |

This ensures:
- `df` shows freed space immediately after `rm` returns
- No ENOSPC after large delete: the admission check uses `logical_avail_bytes`
  plus a fraction of `phys_reclaimable_bytes`
- Physical segment reuse converges as the background worker runs

### 7.2 Admission control with in-flight reclaim

When `logical_avail_bytes` is low but `phys_reclaimable_bytes` is high,
the admission gate allows writes up to a configurable fraction of reclaimable
bytes:

```rust
fn admission_check(requested: u64, counters: &DatasetSpaceCountersV1) -> AdmissionResult {
    let available = counters.logical_avail_bytes();
    let reclaim_reserve = counters.phys_reclaimable_bytes * RECLAIM_TRUST_FACTOR; // default: 0.5

    if requested <= available + reclaim_reserve {
        AdmissionResult::Admitted
    } else {
        AdmissionResult::Enospc
    }
}
```

The `RECLAIM_TRUST_FACTOR` (0.5 by default) is a safety margin: we only "spend"
half the promised reclaim because the background worker may lag or the estimate
may be imprecise.

## 8. Integration with Background Service (#1179)

The `CleanupJob` is scheduled by the `BackgroundService` alongside other jobs:

```text
BackgroundService::tick():
    budget = calculate_tick_budget()
    jobs = [
        ScrubService(priority=Normal),
        ResilverService(priority=TimeCritical),
        CleanupJob(priority=High),        // <-- space reclaim is high priority
        SnapDestroyJob(priority=High),
        CompactionJob(priority=Normal),
    ]

    for job in jobs.sorted_by_priority():
        fraction = budget.allocate_proportionally(job.weight())
        result = job.step(fraction)
        job.persist_checkpoint(result.checkpoint)
```

Cleanup is scheduled at **HIGH** priority because it directly enables space
reclamation. If `phys_reclaimable_bytes` exceeds a threshold or ENOSPC is
approaching, cleanup priority is boosted to **TIME_CRITICAL**.

## 9. ZFS, Ceph, and ext4 Comparison

| Dimension | tidefs (this design) | ZFS | Ceph | ext4 |
|---|---|---|---|---|
| **Unlink latency** | O(directory depth), constant per extent. Returns immediately; reclamation is background | O(extents): `dmu_free_long_range` blocks synchronously. 10 TiB file can take minutes | Blocking in MDS; large file unlink stalls namespace operations | O(extents): inode and extent tree blocks freed synchronously |
| **Truncate latency** | O(log N) for range-delete in extent B+tree; work item enqueue only | O(extents freed): synchronous free of all blocks in range | Blocking in MDS for metadata; data objects freed by OSDs asynchronously | O(extents freed): synchronous block bitmap updates |
| **Memory boundedness** | ≤128 bytes per work item; cursor-based iteration; idempotent deltas | Allocates large block-pointer arrays for `dmu_free_long_range` | MDS allocates inode-backpointer structures proportional to file size | Allocates extent-tree buffer heads proportional to freed range |
| **Crash recovery** | Work items persisted in B+tree; resume from cursor. No lost work, no duplicated work | `bpobj` (block_ref object) survives crash but single-threaded and can backlog | OSD recovery replays PG log; MDS replays journal and may re-do namespace ops | Journal replay recovers metadata; extent-tree may leak blocks (fsck required) |
| **Space accounting** | `st_blocks` correct immediately; `df` shows freed space; physical converge is background | `st_blocks` updates synchronously; `df` updates after commit_group commit (within seconds) | `st_blocks` updates synchronously via MDS; physical space freed by OSD scrub | `st_blocks` correct immediately; physical space freed synchronously |
| **ENOSPC after delete** | Prevented: admission check trusts in-flight reclaim with safety margin | ZFS reserves 3.2% (`spa_slop_shift`) to prevent transient ENOSPC; insufficient for large deletes | Ceph may return ENOSPC during rebalancing even with free space available | ext4 reserves 5% by default for root; regular users may hit ENOSPC after large delete |
| **Extent-map dependency** | Requires subtree-summary extent maps (#1191) and range-delete operations | ZFS has block-pointer trees with on-disk summaries (already present) | Ceph uses object maps; no extent tree in MDS | ext4 has extent trees with per-node entry counts (already present) |
| **Worker integration** | `CleanupJob` implements `IncrementalJob` (#1239); scheduled by `BackgroundService` (#1179); feeds `ReclaimQueue` (#1180) | `bpobj` processed by `spa_sync` thread in single-threaded context; no background scheduling | Async data deletion by OSD via `osd_pg_delete`; MDS has no background cleanup worker | No background worker; synchronous freeing only |

### 9.1 ZFS bpobj deep-dive

ZFS's `bpobj` (block_ref object) is the closest analog to tidefs's cleanup work queue:

- **ZFS approach**: When a dataset is destroyed or a large file is truncated,
  ZFS creates a `bpobj` containing all the freed block pointers. The `spa_sync`
  thread then iterates the `bpobj` synchronously during commit_group sync.
- **Key weakness**: `bpobj` processing is single-threaded and competes with
  application IO in the same `spa_sync` context. A large backlog (gigabytes of
  freed blocks) causes multi-second commit_group sync stalls.
- **tidefs improvement**: Cleanup is decoupled from commit_group sync. The synchronous
  phase only enqueues a small work item. The background worker runs in its own
  scheduling context with bounded per-tick budgets, never blocking application IO.
- **Ceph comparison**: Ceph has no equivalent of `bpobj`. Data object deletion is
  handled by the OSD's `pg_removal` process, which is asynchronous but per-PG
  rather than per-deletion-op. Large deletions create PG-level work backlogs
  with no global scheduling.

## 10. Implementation Plan

### Phase 1: Core types
- `CleanupWorkItemV1` and `WorkItemKind` in a new or existing types crate
- Fixed-size (128 bytes) on-media layout with magic `CLNWITEM`
- `no_std` compatible

### Phase 2: Per-dataset cleanup B+tree
- `CleanupQueue` with `insert()`, `dequeue_next()`, `delete()`, `is_empty()`
- Keyed by `(inode_id_be_u64, work_item_kind_be_u8)`
- Root pointer in `DatasetMetadataV1`

### Phase 3: Extent-map subtree summaries (#1191 prerequisite)
- `ExtentMapSubtreeSummary` on internal B+tree pages
- `total_alloc_bytes`, `total_unwritten_bytes`, `extent_count`
- Range-delete operations with O(log N) complexity

### Phase 4: Synchronous-phase algorithm changes
- `unlink_last_link()`: enqueue work item instead of walking extents
- `truncate_shrink()`: range-delete + enqueue
- `rmdir_free()`: enqueue directory block extents
- Logical space accounting updates (immediate)

### Phase 5: CleanupJob (IncrementalJob implementation)
- `CleanupJob` struct implementing `IncrementalJob` from #1239
- `resume()`: load work item from queue, reposition cursor
- `step()`: bounded extent-map iteration, refcount delta enqueue to #1180
- `persist_checkpoint()` and `complete()`

### Phase 6: Background service integration
- Register `CleanupJob` in `BackgroundService` (#1179) at HIGH priority
- ENOSPC pressure → TIME_CRITICAL boosting
- `phys_reclaimable_bytes` tracking and admission control

- `tidefs-xtask check-deferred-cleanup` gate
- Crash injection: unlink large file → kill -9 → restart → verify space reclaimed
- Deterministic test: fixed extent map → enqueue → process → verify all extents
  freed, no duplicates, no leaks
- Chaos test: concurrent unlinks + truncates + crash cycles


The xtask gate `tidefs-xtask check-deferred-cleanup` verifies:

1. Spec, feature matrix, and status entries present
2. Phase 1 types compile with `no_std` + optional `alloc`
3. `CleanupWorkItemV1` round-trip: serialize → deserialize → assert equality
4. `CleanupQueue` operations: insert → dequeue → verify ordering
5. Synchronous-phase algorithms: unlink creates work item, truncate creates work
   item, no extent-map iteration in syscall context
6. `CleanupJob::step()`: respects `WorkBudget`, produces refcount deltas, advances
   cursor, marks complete
7. Crash simulation: enqueue items → process 3 steps → crash → resume → verify
   no duplicate deltas, no lost work
8. Space accounting: `st_blocks` after unlink, `df` after unlink, ENOSPC not
   returned after large delete

## 12. Open Questions

1. **Work item priority ordering**: Should the cleanup queue dequeue in FIFO order
   (oldest work item first) or largest-first (maximize immediate space reclaim)?
   FIFO is simpler and prevents starvation. Largest-first is better for ENOSPC
   pressure. Proposal: FIFO by default, with an admin-triggered "reclaim burst"
   mode that selects by `bytes_to_free_estimate` descending.
2. **Work item limit**: Should there be a per-dataset cap on the number of
   outstanding work items (e.g., max 10,000)? This bounds the cleanup queue size.
   Proposal: soft cap of 10,000; beyond that, the synchronous phase does a
   limited inline free (up to 64 extents) to reduce backlog.
3. **Snapshot interaction**: When a work item's `extent_map_root` references
   extents shared with a live snapshot, the refcount decrement must not free the
   extent's storage — only the deadlist (#1232) gates actual segment freeing.
   The work item's refcount delta goes through the normal deadlist check.
4. **Rename-overwrite**: When `renameat2(RENAME_EXCHANGE)` swaps two files,
   should there be work items for both old targets? Proposal: yes, one item per
   overwritten inode.
5. **Work item cancellation**: If an inode is re-created with the same inode_id
   before the work item is processed (e.g., inode reuse), the worker must
   detect this and discard the stale work item. Proposal: include `created_commit_group`
   in the work item; compare against inode's `birth_commit_group` at processing time.
