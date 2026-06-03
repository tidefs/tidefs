# Refcount Delta-Based Incremental Data Cleanup Queues (P2 spec)

Maturity: **design-spec** for the incremental data reclamation mechanism
based on persistent refcount delta queues, batched processing, and
integration with the locator table lifecycle.

This document closes Forgejo issue #1180.

## 1. Motivation

When files are deleted, truncated, or overwritten in a CoW filesystem, the
extents they reference become dead data — space that is no longer reachable
but still consumes physical storage. The current Rust codebase has:

- `scrub.rs` — block-level integrity verification (reads checksums, reports
  corruption), but performs **no reclamation**.
- `repair.rs` — corruption repair (attempts to fix damaged metadata), but
  performs **no reclamation**.
  shutdown), but performs **no reclamation**.

The extent maps and locator tables design (#1285) specifies the `refcount`
field on `ExtentLocatorValueV1` and the `birth_commit_group`/`death_commit_group` lifecycle
model with explicit refcount tracking. This spec defines the **incremental
reclamation mechanism** that acts on refcount transitions to free dead space
without full-dataset scans.

ZFS solves this with the `dsl_scan`/`dsl_destroy` pipeline and the `bpobj`
(block_ref object) deferred-free subsystem. TideFS must provide an equivalent
that is deterministic, budgeted, and crash-safe.

### 1.1 Why deltas, not full scans

| Approach | Cost per mutation | Recovery after crash | Determinism |
|---|---|---|---|
| Full scan on commit_group boundary | O(dataset size) per commit_group | Re-scan from scratch | Deterministic but slow |
| Delta queue (this spec) | O(1) enqueue, O(budget) per tick | Replay unconsumed deltas | Deterministic, bounded |

Delta queues scale with "what became dead" rather than total dataset size.
A 1 TiB dataset that deletes one 4 KiB file enqueues a single delta entry,
not a full walk of every extent in the dataset.

## 2. Reclaim queue data model

### 2.1 ReclaimQueue

```rust
/// Per-dataset deferred reclamation queue.
///
/// Stored as a persistent B-tree keyed by `ObjectKey` with delta payloads,
/// identical in structure to the per-dataset extent refcount B-tree.
/// This allows the same B-tree code to service both structures.
pub struct ReclaimQueueEntry {
    /// The object key whose refcount changed.
    pub object_key: ObjectKey,
    /// Delta to apply: negative for decrement, positive for increment
    /// (CoW clone adds a reference before the new locator is written).
    pub delta: i64,
}
```

The queue is a persistent B-tree with deterministic key ordering (`ObjectKey`
lexicographic sort). This provides:

- **Stable ordering**: processing produces identical results across runs,
- **Efficient batch extraction**: `scan(start_after=None, max_items=N)` pulls
  the next N entries in key order.
- **Atomic batch commit**: after processing a batch, the consumed entries are
  deleted from the B-tree and a new root is committed.

### 2.2 Per-dataset storage

Each dataset carries a reclaim queue root pointer in its dataset metadata:

```rust
pub struct DatasetMetaV1 {
    // ... existing fields ...
    pub reclaim_queue_root_ptr: u64,
    pub reclaim_queue_device_id: [u8; 16],
}
```

The queue lives on the same device as the extent refcount B-tree (writer device
for slice-0), ensuring atomic commit of both structures within a single commit_group.

## 3. Queue families

The reclaim mechanism spans four queue families, each targeting a different
class of dead data:

### 3.1 Extent reclaim queue

**Trigger**: `locator.refcount` decremented to 0 on truncate, delete, or
overwrite.

**Content**: `(locator_id: ObjectKey, delta: i64)` entries.

**Processing**:
1. Read current refcount from extent refcount B-tree.
2. If `refcount + delta_sum == 0`: the locator is dead.
   - Delete `ExtentLocatorValueV1` from the locator table.
   - The physical space is not immediately freed — it transitions to the
     deadlist for segment-cleaner reclamation (#917).
3. If `refcount + delta_sum > 0`: update refcount, locator remains alive.
   This occurs when a snapshot holds a reference that outlives the delete.
4. If `refcount + delta_sum < 0`: refcount underflow — integrity violation.
   The system must refuse to process and surface a corruption alert.

**Integration point**: `batch_decrement_refcounts()` in
`ExtentLocatorTable` (#1285 §8.7). Each call to this function simultaneously
enqueues the delta into the reclaim queue and decrements the refcount.

### 3.2 Locator reclaim queue

**Trigger**: locator entry deleted from locator table (extent fully dead).

**Content**: `(locator_id: ObjectKey, delta: -1)` entries.

**Processing**:
1. Verify the locator entry is already deleted from the locator table (it
   was removed in the extent reclaim step).
2. If locator entry still exists (racing snapshot creation), skip — it is
   still alive.
3. If locator entry is absent, the physical shard(s) referenced by the
   now-dead locator can be tombstoned.
4. Enqueue the shard object keys into the rebake queue if erasure-coded
   parity shards exist.

### 3.3 Rebake queue

**Trigger**: an erasure-coded data shard is freed while its parity shards
remain alive (other data shards in the stripe are still referenced).

**Content**: `(stripe_id: ObjectKey, flags: u32)` entries indicating which
shard position in the stripe needs parity recomputation.

**Processing** (deferred to erasure-coding implementation):
1. Read surviving data shards from the stripe.
2. Recompute parity shards.
3. Write new parity shard objects.
4. Update the stripe metadata in the locator table.

### 3.4 Inode tombstone queue

**Trigger**: inode `nlink` reaches 0 and all open handles are closed.

**Content**: `(inode_key: ObjectKey, commit_group: u64)` entries.

**Processing**:
1. Verify no open handles reference this inode.
2. Verify all extent maps for this inode have been processed through the
   extent reclaim queue.
3. Compact the inode table: remove the inode entry, reclaim its space in
   the inode B-tree.

## 4. Processing algorithm

### 4.1 ReclaimProcessor

```rust
pub struct ReclaimProcessor {
    /// Maximum number of queue entries to process per tick.
    budget: usize,
}

pub struct ReclaimStats {
    pub processed: usize,
    pub freed: usize,        // locators that reached refcount 0
    pub stale: usize,        // deltas for still-alive locators
    pub commits: usize,      // commit_group commits issued
    pub underflows: usize,   // refcount integrity violations
}
```

### 4.2 Per-tick algorithm

```
fn service_reclaim(dataset, budget):
    stats = ReclaimStats::zero()

    for each dataset in sorted(datasets):
        if stats.processed >= budget: break

        // 1. Open reclaim queue B-tree from dataset metadata
        queue = BTree::open(dataset.reclaim_queue_root_ptr,
                            dataset.reclaim_queue_device_id)
        refcounts = BTree::open(dataset.extent_refcount_root_ptr,
                                dataset.extent_refcount_device_id)

        // 2. Pull next batch (up to budget - processed, max 1024)
        batch = queue.scan(start_after=None,
                           max_items=min(budget - stats.processed, 1024))
        if batch.is_empty(): continue

        // 3. Process each entry
        for entry in batch:
            current_refcount = refcounts.get(entry.object_key)
            if current_refcount is None:
                // Object already deleted — safe to clear delta
                stats.freed += 1
                // Also clean up locator/rebake metadata if extent_id key
            else:
                // Object still alive — delta was for a reference that
                // came back (snapshot, clone)
                stats.stale += 1

            // Delete processed entry from queue
            queue.delete(entry.object_key)
            stats.processed += 1

        // 4. Commit if any entries were processed
        if changed:
            dataset.reclaim_queue_root_ptr = queue.root()
            // Commit dataset metadata with updated queue + refcount roots
            commit_dataset_metadata(dataset)
            stats.commits += 1

    return stats
```

### 4.3 Budget model

The budget (`max_extents` in the Python reference, `budget` here) bounds the
number of queue entries processed per tick. This ensures:

- **No mount-time stalls**: processing is incremental, never a synchronous
  scan of the full queue.
- **Predictable latency**: each tick consumes at most `budget` entries.
- **Background-friendly**: fits within the background service tick model
  (#1177) where each service gets a fixed time or work budget.

Default budget: 256 entries per tick. Configurable per dataset via
`DatasetReclaimPolicy`.

## 5. Integration with extent maps and locator tables (#1285)

### 5.1 Enqueue on refcount decrement

The `ExtentLocatorTable::batch_decrement_refcounts()` function (#1285 §8.7)
is the canonical enqueue point:

```rust
fn batch_decrement_refcounts(&mut self, locator_ids: &[LocatorId])
    -> (Vec<LocatorId>, Vec<(ObjectKey, i64)>)
```

Returns:
- `Vec<LocatorId>`: locators that reached `refcount == 0` (newly dead)
- `Vec<(ObjectKey, i64)>`: delta entries to append to the reclaim queue

The delta entries are *appended to the reclaim queue within the same commit_group*
as the refcount decrement. This is critical for crash safety: if the commit_group
commits, both the decrement and the enqueue are durable; if the commit_group aborts,
neither is.

### 5.2 Enqueue on extent allocation

When a new extent is allocated (CoW write, clone, snapshot hold), the
refcount increment is applied directly — no delta queue entry is needed
because the increment is always valid. The delta queue is only needed for
decrements, which may race with concurrent snapshot creation or clone
operations.

### 5.3 Deadlist interaction

The extent maps design (#1285 §5.4) specifies:

> **DEAD**: All references have been dropped (refcount = 0). The extent is
> added to the deadlist. Space is not immediately freed — the segment
> cleaner reclaims it asynchronously.

The reclaim queue processor is the mechanism that moves locators from
`refcount > 0` to the deadlist. Once on the deadlist, the segment cleaner
(#917) handles physical space reclamation.

```
  [refcount decrement]
        │
        ▼
  [reclaim queue entry]
        │
        ▼
  [reclaim processor] ── refcount == 0 ──► [deadlist]
        │                                       │
        │ (refcount > 0)                        ▼
        ▼                               [segment cleaner]
  [stale — skip]
```

## 6. Crash safety

### 6.1 Persistent queue

The reclaim queue is a persistent B-tree, not an in-memory structure. This
means:

- **Crash during processing**: the queue B-tree still contains all
  unprocessed entries. On next mount, `service_reclaim` resumes from the
  first unprocessed entry.
- **Crash after commit**: processed entries have been deleted from the
  queue B-tree and the new root committed. They are not re-processed.
- **Crash during commit**: the old root (with unprocessed entries) is
  intact; the new root was never made durable. Processing resumes from
  the same batch.

### 6.2 Atomicity with refcount B-tree

The reclaim queue root and the extent refcount root are committed together
in the dataset metadata. A commit_group that processes reclaim entries and updates
refcounts commits both roots atomically. If the commit_group fails (crash), both
roots roll back to their previous state.

### 6.3 Refcount underflow detection

If `refcount + delta_sum < 0`, the system has a refcount integrity bug
(doubled decrement, missing increment). The processor must:

1. Refuse to apply the delta.
2. Surface a `ReclaimIntegrityError::RefcountUnderflow` alert.
3. Leave the offending delta in the queue (not delete it).
4. Increment `stats.underflows`.

This prevents silent data loss from refcount bugs. The online verifier
(#588 integrity chain) can independently cross-check refcounts against
extent map references.

## 7. Background service model

The reclaim processor runs as a `BackgroundService` per #1177. Two
trigger models are supported:

### 7.1 Periodic tick

```
Every commit_group_sync or configurable interval (default: 30s):
  service_reclaim(dataset, budget=N)
```

Suitable for steady-state operation with continuous mutation.

### 7.2 Pressure-driven tick

When the reclaim queue exceeds a threshold (default: 1000 entries), or
when free space drops below a watermark (default: 10%), the tick fires
immediately with an increased budget.

This handles burst-delete workloads (e.g., `rm -rf` of a large directory)
without letting the queue grow unbounded.

## 8. Relationship to existing code

| Module | Relationship |
|---|---|
| `scrub.rs` | Block-level integrity verification. Does not reclaim. Reclaim processor runs independently. |
| `repair.rs` | Corruption repair. Does not reclaim. |
| `recovery.rs` | Crash recovery audit. Does not reclaim. Reclaim queue replay is part of mount recovery. |
| `encoding.rs` | Object encode/decode. Reclaim queue uses B-tree encoding from this module. |
| `lib.rs` (`LocalFileSystem`) | Hosts the `BackgroundService` set including reclaim processor. |

## 9. ZFS comparison

| Property | ZFS | TideFS (this spec) |
|---|---|---|
| Deferred free mechanism | `bpobj` (block_ref object) | Reclaim queue B-tree |
| Processing trigger | `dsl_scan` synchronous pass | Background service, incremental ticks |
| Refcount tracking | Per-block_ref in DDT (dedup table) or indirect via birth commit_group | Per-locator `refcount` field |
| Budget model | Implicit (syncing commit_group) | Explicit `budget` entries per tick |
| Crash safety | ZIL + commit_group atomic commit | Persistent queue + atomic commit with refcount B-tree |

TideFS improves on ZFS by making processing explicitly budgeted (no
unbounded `dsl_scan` pass at mount) and by tying reclaim directly to
the locator table lifecycle rather than an indirect birth_commit_group model.

## 10. Implementation plan

| Phase | Scope | Crate |
|---|---|---|
| 1 | `ReclaimQueueEntry`, `ReclaimStats`, `ReclaimIntegrityError` types | `tidefs-local-filesystem` |
| 2 | Per-dataset reclaim queue B-tree (create, open, scan, delete) | `tidefs-local-filesystem` |
| 3 | Enqueue hook in mutation paths (delete, truncate, overwrite) | `tidefs-local-filesystem` |
| 4 | `ReclaimProcessor` with budgeted batch processing | `tidefs-local-filesystem` |
| 5 | `BackgroundService` integration with periodic + pressure triggers | `tidefs-local-filesystem` |
| 6 | Deadlist handoff to segment cleaner (#917) | `tidefs-local-filesystem` |
| 7 | Crash safety tests: kill -9 during processing, verify queue integrity | integration |
| 8 | Refcount underflow chaos tests | integration |

Phases 1-4 deliver the core mechanism. Phases 5-8 are integration and

## 11. Deferred to other issues

- **Segment cleaner integration (#917)**: physical space reclamation from
  the deadlist is out of scope for this spec. The reclaim processor only
  moves locators to the deadlist.
- **Erasure-coded rebake queue**: parity recomputation on partial stripe
  free is deferred to the erasure-coding implementation issue.
- **Inode tombstone compaction**: inode table compaction is deferred to
  a separate issue covering inode lifecycle management.
- **Cluster-distributed reclaim**: this spec covers single-node local
  filesystem reclamation. Distributed reclaim with replicated locator
  tables requires a separate design.
- **Per-dataset reclaim policy**: `DatasetReclaimPolicy` with tunable
  budget, tick interval, and pressure thresholds is deferred to the
  dataset configuration issue (#1219).
