# Refcount Delta-Based Incremental Data Cleanup Queues (#1689, #1907, #1975, #1817)

Maturity: **design-spec** — authoritative design for refcount delta-based
incremental data cleanup queues. This document supersedes the original P2 spec
(#1180, `docs/REFCOUNT_DELTA_CLEANUP_QUEUES_DESIGN.md`) and the interim design
(#1551, prior revision of this file). It captures the complete implemented-source
state and defers remaining phases to dedicated wire-up issues.

Design-spec issues:
- [#1817](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1817) — current coordinator-generated design-spec maturity gate
  (design sealed; implementation deferred to phased issues).
- [#1975](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1975) — current design-spec maturity gate
  (coordinator-generated; implementation deferred to phased issues).
- [#1907](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1907) — prior design-spec tracking issue.
- [#2128](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2128) — scrub, deep scrub, repair, and resilver orchestration integration update (design sealed; Rust implementation deferred to wire-up issues U1–U10 across `tidefs-scrub-service`, `tidefs-deep-scrub-service`, `tidefs-repair-service`, `tidefs-resilver-service`, `tidefs-suspect-log`, and scheduler modifications).



Canonical design issue: [#1689](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1689)
(authoritative design delivery).

Status: **implemented-source** — all five crates implemented, reclaim queue
wired as `BackgroundService` (#1459), mutation-time delta recording active
(#1463), segment-level `ReclaimScheduler` integrated. Deferred-cleanup-to-reclaim
to phased issues.

Lane: **storage-core**

Depends on:
- [#1285](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1285) (locator table lifecycle + `ExtentLocatorValueV1.refcount`)
- [#1179](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1179) (background service framework)
- [#1239](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1239) (incremental cursor framework / `IncrementalJob` trait)
- [#1267](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1267) (commit_group state machine)
- [#1191](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1191) (extent management)

Blocks:
- [#1544](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1544) (deferred cleanup work queues)
- [#1215](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1215) (space accounting / segment cleaner scheduling)
- [#1459](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1459) (reclaim queue BackgroundService wire-up)
- [#2128](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2128) — scrub, deep scrub, repair, and resilver orchestration integration (blocks U1–U10 wire-up issues)

- `crates/tidefs-types-reclaim-queue-core/` (1000 lines, 30 tests) — authority types: `QueueFamily`, `ReclaimQueueEntry`, `ReclaimStats`, `ReclaimIntegrityError`, `ObjectKey`, `QueueBudget`
- `crates/tidefs-reclaim-queue-core/` (862 lines, 25 tests) — B+tree-backed persistent queue runtime: `BPlusTreeReclaimQueue`
- `crates/tidefs-reclaim-job-core/` (651 lines, 20 tests) — `IncrementalJob` implementor: `ReclaimJob`
- `crates/tidefs-reclaim/` (201 lines) — segment-level `ReclaimScheduler` with pressure-driven compaction
- `crates/tidefs-local-filesystem/src/background_reclaim.rs` (454 lines, 17 tests) — `BackgroundReclaim` service wired as `BackgroundService` on `LocalFileSystem`

---

## 1. Problem Statement

Copy-on-write filesystems accumulate dead data — extents that are no longer
reachable through any inode but still consume physical space. When files are
deleted, truncated, or overwritten, the underlying extents must be reclaimed.

The current Rust codebase has:

- `scrub.rs` — block-level integrity verification (reads checksums, reports
  corruption), but performs **no reclamation**.
- `repair.rs` — corruption repair (attempts to fix damaged metadata), but
  performs **no reclamation**.
  shutdown), but performs **no reclamation**.
- `background_reclaim.rs` — **reclamation engine**: processes refcount-delta
  entries from the reclaim queue under per-tick budget, with deterministic
  `ObjectKey` ordering and cursor-resumable crash safety.
- `crates/tidefs-reclaim/` — **segment-level reclaim**: `ReclaimScheduler`
  monitors space pressure, tracks compaction state, and coordinates batch
  segment rotation via `LocalObjectStore::rotate_segment()`.

The **scrub / deep-scrub / repair / resilver orchestration design**
(`docs/design/scrub-deep-scrub-repair-resilver-orchestration-design.md`) specifies
how scrub findings, deep-scrub shard divergence, repair strategy resolution, and
resilver topology-aware placement integrate with the reclaim pipeline. When reclaim
discovers refcount underflows or stale deltas, findings are emitted through the
unified `IntegrityEventBus` (orchestration design §8). The repair service drains
the `SuspectLog` (orchestration design §3.6) and delegates rebuild execution to the
P8-03 distributed infrastructure. Rust implementation of the four integrity
services is deferred to wire-up issues U1–U10.

Without an incremental reclamation mechanism, every freed extent requires
either a full-dataset scan (O(dataset size)) or an unbounded synchronous
teardown during unlink/truncate (O(file size)). Neither scales.

### 1.1 Design-input comparison: existing filesystems

This comparison classifies incumbent mechanisms as design input only. It is not
evidence that TideFS currently has better reclaim latency, crash safety,
throughput, cost, or durability than ZFS or Ceph. Any future product-facing
comparison must be a #875 claim backed by #928/#930 comparator evidence for the
exact implementation and workload.

| Property | ZFS | Ceph | TideFS (this design) |
|---|---|---|---|
| Deferred free mechanism | `bpobj` (block_ref object) — opaque untyped linked list, unpredictable order | None — PG logs are recovery journals, not reclaim queues; implicit via OSD snap trimming | Sorted, persistent B-tree with deterministic key-order processing |
| Reclamation trigger | `dsl_scan` synchronous pass during commit_group sync | OSD-level snap trimming scans full object indexes | Background service, budgeted incremental ticks |
| Refcount tracking | Per-block_ref in DDT or indirect via `birth_commit_group` | N/A (no per-object refcount) | Per-locator `refcount` field + delta accumulation |
| Budget model | Implicit (bounded by syncing commit_group) | Implicit | Explicit `QueueBudget` with pressure-driven escalation |
| Crash safety | ZIL + commit_group atomic commit | PG log replay | Persistent queue + atomic commit with extent refcount B-tree |

### 1.2 Why deltas, not full scans

| Approach | Cost per mutation | Recovery after crash | Determinism |
|---|---|---|---|
| Full scan on commit_group boundary | O(dataset size) per commit_group | Re-scan from scratch | Deterministic but impractically slow |
| Delta queue (this design) | O(1) enqueue, O(budget) per tick | Replay unconsumed deltas | Deterministic, bounded |

Delta queues scale with "what became dead" rather than total dataset size.
A 1 TiB dataset that deletes one 4 KiB file enqueues a single delta entry,
not a full walk of every extent in the dataset.

---

## 2. Architecture

### 2.1 System integration

```
┌─────────────────────────────────────────────────────────────────┐
│                          syscall context                         │
│  unlink / truncate / overwrite / rmdir / snapshot-destroy        │
│                              │                                   │
│                              ▼                                   │
│   ┌──────────────────────────────────────────────────┐          │
│   │  Mutation path (synchronous)                      │          │
│   │  ├─ Update namespace / inode metadata             │          │
│   │  ├─ Decrement locator refcount                    │          │
│   │  └─ Enqueue ReclaimQueueEntry (O(1))              │          │
│   └──────────────────────┬───────────────────────────┘          │
│                          │ persistent delta                     │
│                          ▼                                      │
│   ┌──────────────────────────────────────────────────┐          │
│   │  Reclaim Queue B+tree (per-dataset, persistent)    │          │
│   │  Key: ObjectKey  │  Value: ReclaimQueueEntry       │          │
│   │  Partitioned by QueueFamily                       │          │
│   └──────────────────────┬───────────────────────────┘          │
└──────────────────────────┼──────────────────────────────────────┘
                           │
┌──────────────────────────┼──────────────────────────────────────┐
│   background worker      │                                       │
│                           ▼                                      │
│   ┌──────────────────────────────────────────────────┐          │
│   │  ReclaimJob (IncrementalJob)                      │          │
│   │  ├─ Dequeue batch (budget: 256 entries/tick)      │          │
│   │  ├─ Apply deltas to extent refcount B-tree         │          │
│   │  ├─ Hand off dead locators to deadlist             │          │
│   │  └─ Persist cursor → resume after crash            │          │
│   └──────────────────────┬───────────────────────────┘          │
│                          │                                      │
│                          ▼                                      │
│   ┌──────────────────────────────────────────────────┐          │
│   │  Deadlist → Segment Cleaner (#1215)               │          │
│   │  Physical space finally freed by segment cleaning │          │
│   └──────────────────────────────────────────────────┘          │
└──────────────────────────────────────────────────────────────────┘
```

### 2.2 Crate dependency graph

```
tidefs-types-reclaim-queue-core     (no_std, zero deps)
  ├── QueueFamily, ReclaimQueueEntry, ObjectKey
  ├── ReclaimStats, ReclaimIntegrityError, QueueBudget
  └──────────────────────┬────────────────────────────
                         │
       ┌─────────────────┼─────────────────┐
       ▼                 ▼                 ▼
tidefs-reclaim-queue-core   tidefs-types-incremental-job-core
  (BPlusTreeReclaimQueue)      (IncrementalJob trait)
       │                        │
       └────────┬───────────────┘
                ▼
    tidefs-reclaim-job-core
      (ReclaimJob: IncrementalJob)
```

The crate split follows the authority-leaf pattern:

- **`tidefs-types-reclaim-queue-core`** is the authority crate — `no_std`,
  `forbid(unsafe_code)`, zero mandatory dependencies. Every crate that
  enqueues or interprets reclaim deltas depends on this crate.
- **`tidefs-reclaim-queue-core`** is the runtime crate — wraps `tidefs-btree`
  to provide a persistent B+tree-backed queue with O(log N) insert/delete
  and deterministic key-order dequeue.
- **`tidefs-reclaim-job-core`** is the integration crate — implements
  `IncrementalJob` to bridge the queue with the background scheduler,
  providing cursor serialization, budgeted stepping, and crash-safe resume.

---

## 3. Data Structures

### 3.1 ObjectKey — B-tree key type

```rust
pub struct ObjectKey(pub [u8; 32]);
```

32-byte fixed-size key, lexicographic ordering. Identical layout to the
`ObjectKey` used by the per-dataset extent refcount B-tree so that the
same B-tree code can service both structures.

- `ObjectKey::NONE` — sentinel (all zeros), used as "start from beginning" cursor.

### 3.2 QueueFamily — four queue families

```rust
pub enum QueueFamily {
    Extent = 0,         // Freed extent payloads (trigger: refcount→0)
    Locator = 1,        // Freed extent IDs (trigger: locator deleted)
    Rebake = 2,         // Pending parity recomputation (trigger: shard freed)
    InodeTombstone = 3, // Deleted inodes awaiting compaction (trigger: nlink→0)
}
```

#### 3.2.1 Extent reclaim queue

Triggered when `locator.refcount` is decremented to 0 on truncate, delete,
or overwrite.

**Content**: `(object_key, delta: i64, family: Extent)` entries.

**Processing**:
1. Read current refcount from extent refcount B-tree.
2. Compute `refcount + delta_sum`.
   - If result == 0: locator is dead → delete from locator table, hand off
     to deadlist for segment-cleaner reclamation (#1215).
   - If result > 0: update refcount (snapshot holds a live reference).
   - If result < 0: **refcount underflow** — integrity violation. Refuse
     to process, surface `ReclaimIntegrityError::RefcountUnderflow`.

#### 3.2.2 Locator reclaim queue

Triggered after the locator table entry is deleted (extent fully dead).

**Content**: `(object_key, delta: -1, family: Locator)` entries.

**Processing**: Verify locator absent, append to deadlist. Enqueue rebake
entries if erasure-coded parity shards exist.

#### 3.2.3 Rebake queue

Triggered when a data shard is freed while parity shards remain alive.

**Content**: `(stripe_key, delta: -1, family: Rebake)` entries.

**Processing**: recompute parity for the affected stripe. Free entire stripe
if all shards are dead.

#### 3.2.4 Inode tombstone queue

Triggered when inode `nlink` reaches 0 and all open file handles are closed.

**Content**: `(inode_key, delta: -1, family: InodeTombstone)` entries.

**Processing**: compact the inode table to remove the tombstone entry,
recovering the inode number for reuse after a grace period.

### 3.3 ReclaimQueueEntry

```rust
pub struct ReclaimQueueEntry {
    pub object_key: ObjectKey,
    pub delta: i64,
    pub family: QueueFamily,
}
```

The entry is the persistent unit of work stored in the reclaim queue B-tree.
`delta` is signed: negative for decrement (freed), positive for increment
(CoW clone adds a reference before the new locator is written).

### 3.4 Per-dataset storage

Each dataset carries a reclaim queue root pointer in its dataset metadata:

```rust
pub struct DatasetMetaV1 {
    // ... existing fields ...
    pub reclaim_queue_root_ptr: u64,
    pub reclaim_queue_device_id: [u8; 16],
}
```

### 3.5 ReclaimStats

```rust
pub struct ReclaimStats {
    pub processed: usize,  // Entries processed this tick
    pub freed: usize,      // Entries that resulted in space freed
    pub stale: usize,      // Stale deltas skipped
    pub commits: usize,    // Separate commit_group commits issued
    pub underflows: usize, // Refcount underflows detected
}
```

### 3.6 ReclaimIntegrityError

```rust
pub enum ReclaimIntegrityError {
    RefcountUnderflow { object_key, current_refcount, delta },
    StaleDeltaResurrection { object_key, expected_refcount, actual_refcount, delta },
    QueueFamilyMismatch { object_key, entry_family, expected_family },
    ObjectKeyNotFound { object_key },
}
```

All errors are non-fatal (`is_fatal()` returns `false`). The processor
skips the offending entry, leaves it in the queue, and reports the error
via `category()` for observability.

### 3.7 QueueBudget

```rust
pub struct QueueBudget {
    pub max_entries_per_tick: usize,       // Default: 256
    pub max_batch_size: usize,             // Default: 1024
    pub pressure_threshold: usize,         // Default: 1000 queue entries
    pub pressure_budget_multiplier: usize, // Default: 2
}
```

When `queue.len() >= pressure_threshold`, `pressure_budget()` returns
`max_entries_per_tick * pressure_budget_multiplier`. This handles burst-delete
workloads without letting the queue grow unbounded.

---

## 4. B+tree Queue Runtime

### 4.1 BPlusTreeReclaimQueue

Defined in `tidefs-reclaim-queue-core`. Wraps `tidefs-btree::BPlusTree`.

Key design properties:

- **Deterministic key ordering**: entries sorted by `ObjectKey` lexicographic
- **O(log N) insert**: each mutation enqueues a single entry.
- **O(log N + B) batch dequeue**: `dequeue_batch(start_after, max)` pulls
  the next N entries in key order.
- **Budgeted per-family queries**: `entries_by_family(family)` and
  `family_count(family)` enable per-pipeline budget allocation.

### 4.2 API surface

| Method | Complexity | Description |
|---|---|---|
| `new()` | O(1) | Create empty queue |
| `insert(entry)` | O(log N) | Enqueue a delta entry |
| `dequeue_next(start_after)` | O(log N + B) | Dequeue next batch from cursor |
| `dequeue_batch(start_after, max)` | O(log N + B) | Dequeue up to `max` entries |
| `len()` | O(1) | Total entry count |
| `is_empty()` | O(1) | Queue emptiness check |
| `stats()` | O(N) | Per-family entry counts |

---

## 5. ReclaimJob: IncrementalJob Integration

### 5.1 ReclaimJob

Defined in `tidefs-reclaim-job-core`. Implements `IncrementalJob` from
`tidefs-types-incremental-job-core`.

```rust
pub struct ReclaimJob {
    queue: BPlusTreeReclaimQueue,
    cursor: ObjectKey,
    id: JobId,
    epoch: u64,
    items_processed: u64,
    bytes_processed: u64,
    done: bool,
}
```

### 5.2 Lifecycle

```
resume(checkpoint) → step(budget) → persist_checkpoint() → …
                                    ↓ (is_complete)
                                 complete()
```

On each `step(WorkBudget)`, the job:
1. Deserializes the cursor (32-byte `ObjectKey`) from `CursorState`.
2. Calls `queue.dequeue_batch(Some(cursor), budget.max_items)`.
4. Advances the cursor to the last processed key + 1.
5. Returns `StepResult` with serialized checkpoint.

### 5.3 Cursor encoding

The cursor is the `ObjectKey` of the next entry to process, serialized as
a 32-byte blob in `CursorState`. An empty cursor (all zeros, `ObjectKey::NONE`)
means "start from the beginning."

Crash-safe resume: the queue B-tree is persistent, so unprocessed entries
survive crashes. The checkpoint cursor ensures no duplicate processing.

### 5.4 IncrementalJob trait compliance

| Trait method | ReclaimJob implementation |
|---|---|
| `job_id()` | Returns `JobId` |
| `job_kind()` | Returns `JobKind::Reclaim` |
| `step(budget)` | Dequeues batch, applies deltas, advances cursor |
| `persist_checkpoint()` | Serializes cursor + stats to `Checkpoint` |
| `resume(checkpoint)` | Deserializes cursor, reconstructs job state |
| `is_complete()` | Returns `done` |
| `complete()` | Idempotent finalization |

---

## 6. Crash Safety

### 6.1 Persistent queue guarantees

The reclaim queue is a persistent B-tree:
- **Crash during processing**: unprocessed entries remain in the queue.
- **Crash after commit**: processed entries already deleted.
- **Crash during commit**: old root intact, new root discarded.

### 6.2 Atomicity with refcount B-tree

The reclaim queue root and extent refcount root are committed together
in dataset metadata. A commit_group that processes reclaim entries commits both
roots atomically.

### 6.3 Refcount underflow detection

If `refcount + delta_sum < 0`, the processor refuses to apply the delta,
surfaces `ReclaimIntegrityError::RefcountUnderflow`, leaves the entry in
the queue, and increments `stats.underflows`. The online verifier (#588
integrity chain) can independently cross-check refcounts against extent
map references.

---

## 7. Background Service Integration

### 7.1 Scheduling

`ReclaimJob` runs at `Throughput` priority in the unified priority dispatcher
(#1179):

```
BackgroundScheduler
├── Critical (40%)
├── LatencySensitive (30%)
├── Throughput (15%)
│   ├── IncrementalJobAdapter<CleanupJob>
│   ├── IncrementalJobAdapter<ReclaimJob>     ← this design
│   └── …
├── BestEffort (10%)
└── Opportunistic (5%)
```

### 7.2 Trigger model

- **Periodic tick**: every commit_group_sync or configurable interval (default: 30s).
- **Pressure-driven tick**: when queue exceeds `QueueBudget.pressure_threshold`
  (default: 1000 entries) or free space drops below 10%, the tick fires
  immediately with `pressure_budget()` (default: 512 entries/tick).

### 7.3 Space accounting handoff

The reclaim processor moves dead locators to the deadlist. Physical space
reclamation is performed by the segment cleaner (#1215).

---

## 8. Relationship to Existing Code

| Module | Relationship |
|---|---|
| `scrub.rs` | Block-level integrity verification. Does not reclaim. See orchestration design §4. |
| `repair.rs` | Corruption repair. Does not reclaim. See orchestration design §6. |
| `recovery.rs` | Crash recovery audit. Reclaim queue replay is mount recovery. |
| `tidefs-locator-table` | Extent reclaim interacts with `ExtentLocatorValueV1.refcount`. |
| `tidefs-space-accounting` | Reclaim updates physical counters on deadlist handoff. |
| `docs/design/scrub-deep-scrub-repair-resilver-orchestration-design.md` | Orchestration design (#2128) for scrub, deep-scrub, repair, and resilver as `BackgroundService` implementations. Reclaim queue integrity errors (refcount underflows, stale delta resurrections) emit `IntegrityEvent` on the unified event bus (orchestration design §8). Repair drains the `SuspectLog` (orchestration design §3.6) and delegates rebuild to P8-03 infrastructure. Rust implementation deferred to wire-up issues U1–U10. |


## 10. Implementation Plan

| Phase | Scope | Status | Crate |
|---|---|---|---|
| 1 | `ReclaimQueueEntry`, `ReclaimStats`, `ReclaimIntegrityError`, `QueueFamily`, `ObjectKey`, `QueueBudget` types | **Done** | `tidefs-types-reclaim-queue-core` |
| 2 | Per-dataset reclaim queue B+tree (create, open, scan, delete, stats) | **Done** | `tidefs-reclaim-queue-core` |
| 3 | `ReclaimJob`: `IncrementalJob` impl with budgeted batch processing, cursor serialization, crash-safe resume | **Done** | `tidefs-reclaim-job-core` |
| 4 | Enqueue hook in mutation paths (delete, truncate, overwrite, snapshot-destroy) | **Done** (#1463) | `tidefs-local-filesystem` |
| 5 | `BackgroundService` integration: `BackgroundReclaim` with periodic + pressure triggers | **Done** (#1459) | `tidefs-local-filesystem/src/background_reclaim.rs` |
| 6 | Segment-level `ReclaimScheduler` with pressure-driven compaction batching | **Done** | `crates/tidefs-reclaim/` |
| 7 | Deferred-cleanup-to-reclaim pipeline: `CleanupJob` → `ReclaimQueue` delta production | **Done** (#1619/#1656) | `tidefs-cleanup-job-core` |
| 8 | Deadlist handoff to segment cleaner (#1215) | Deferred | `tidefs-local-filesystem` |
| 9 | Crash safety tests: kill -9 during step(), verify queue integrity | Deferred | integration |
| 10 | Refcount underflow chaos tests: inject doubled-decrement, verify error surface | Deferred | integration |
| 11 | Production distributed reclaim with replicated locator tables | Deferred | distributed runtime |

---

## 11. Deferred to Other Issues

- **Segment cleaner integration (#1215)**: physical space reclamation from deadlist.
- **Erasure-coded rebake queue (#1249)**: parity recomputation on partial stripe free.
- **Inode tombstone compaction**: inode lifecycle management.
- **Cluster-distributed reclaim**: distributed reclaim with replicated locator tables.
- **Per-dataset reclaim policy (#1219)**: tunable budget, tick interval, pressure thresholds.
- **Reclaim queue BackgroundService wire-up (#1459)**: adapter connection to scheduler.

---

## 12. Design Decisions and Tradeoffs

### 12.1 Single B+tree vs. four separate trees

**Decision**: All four queue families share a single B+tree, partitioned
logically by `QueueFamily`.

**Rationale**: Single atomic commit boundary, simpler space accounting.
Per-family queries provide sufficient isolation.

**Tradeoff**: family-scoped scans filter entries from other families. Acceptable
because dequeue is always key-order sequential and fanout 64 keeps leaf
nodes small.

### 12.2 Delta accumulation vs. immediate processing

**Decision**: Enqueue deltas immediately, process in background.

**Rationale**: O(log N) bounded syscall latency, batch-optimized processing,
delta durable before processing begins.

**Tradeoff**: stale deltas possible. Processor detects via
`StaleDeltaResurrection` and skips gracefully.

### 12.3 `no_std` authority crate

**Decision**: `tidefs-types-reclaim-queue-core` is `#![no_std]` with zero
mandatory dependencies, eliminating circular dependency risk.

### 12.4 Cursor as 32-byte ObjectKey

**Decision**: The `ReclaimJob` cursor is a raw `ObjectKey` serialized directly
to `CursorState`. Simple, zero-allocation, deterministic.

### 12.5 `IncrementalJob` over ad-hoc background loop

**Decision**: `ReclaimJob` implements `IncrementalJob`.

**Rationale**: unified priority dispatch, budget enforcement, observability,
and crash-safe resume — all standard across all background jobs.

---


### 13.1 Unit tests (existing)

- `tidefs-types-reclaim-queue-core`: ~30 tests covering type construction,
  serde roundtrips, error formatting, budget pressure logic, saturation edge cases.
- `tidefs-reclaim-queue-core`: ~25 tests covering insert, dequeue, batch
  family coexistence, sorted order invariant.
- `tidefs-reclaim-job-core`: ~20 tests covering step, resume, cursor
  serialization, checkpoint serde, complete idempotency, mixed family
  processing, already-done step.

### 13.2 Integration gates (pending)

- Crash safety: `kill -9` during `step()`, verify queue integrity on remount.
- Refcount underflow: inject doubled decrement, verify error surface and retention.
- Pressure escalation: fill queue beyond threshold, verify budget doubles.
- Atomic commit: crash during commit_group commit, verify both roots roll back.
- Deterministic replay: process same queue twice, compare `ReclaimStats`.

---

## 14. References

- **Design ancestry**:
  - [#1180](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1180) — original P2 spec (`docs/REFCOUNT_DELTA_CLEANUP_QUEUES_DESIGN.md`)
  - [#1551](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1551) — prior design revision of this document
  - [#1689](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1689) — this design (current revision, canonical)
- **Foundation dependencies**:
  - [#1285](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1285) — locator table lifecycle
  - [#1179](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1179) — background service framework (`docs/design/background-service-framework-design.md`)
  - [#1239](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1239) — incremental cursor framework / `IncrementalJob` trait
  - [#1267](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1267) — commit_group state machine
- **Implemented integration**:
  - [#1459](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1459) — BackgroundReclaim service wire-up
  - [#1463](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1463) — mutation-time delta recording
  - [#1619](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1619) / [#1656](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1656) — deferred cleanup work queues (`docs/design/deferred-cleanup-work-queues.md`)
  - [#1644](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1644) — refcount delta reclaim queues type/queue/job crates
- **Deferred implementation**:
  - [#1544](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1544) — deferred cleanup work queues
  - [#1215](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1215) — space accounting / segment cleaner
  - [#1249](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1249) — erasure coding
- **Orchestration integration**:
  - [#2128](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2128) — scrub, deep scrub, repair, and resilver orchestration integration (`docs/design/scrub-deep-scrub-repair-resilver-orchestration-design.md`)
- **External references**:
  - ZFS: `bpobj` subsystem, `dsl_scan`/`dsl_destroy` pipeline
  - Ceph: PG log recovery, OSD snap trimming
