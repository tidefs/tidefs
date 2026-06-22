# IncrementalJob Core Wire-Up Deferred Design

**Issue**: [#2047](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2047)
**Canonical type design**: [`docs/design/incremental-job-core-types-crate-design.md`](./incremental-job-core-types-crate-design.md) (sealed design spec)
**Seal document**: [`docs/design/incremental-job-core-types-crate-design-sealed.md`](./incremental-job-core-types-crate-design-sealed.md) (formal seal)
**Coord**: [#1930](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1930) (coordination seal)
**Status**: **design-sealed** — wire-up deferred to dedicated subsystem issues
**Maturity**: **design-spec** — wire-up architecture, contracts, and integration templates
**Lane**: storage-core (universal incremental cursor framework, #1239)
**Kind**: design

## Seal Statement

This document formalizes the wire-up deferral architecture for the 14 background
maintenance subsystems that must implement the `IncrementalJob` trait from the
sealed `tidefs-types-incremental-job-core` and `tidefs-incremental-job-core` crates.
The types crate, trait contract, and `CheckpointCodec` binary format are frozen
per #1930. All subsystem wire-up is deferred to dedicated wire-up issues filed
against individual subsystem crates.

No design changes to the sealed types or trait are permitted without a new design
issue. Wire-up issues may define subsystem-specific cursor formats, checkpoint
payloads, and `IncrementalJob` implementations within the constraints of the
sealed contract.

## 1. Architecture Overview

### 1.1 Dependency Graph (Wire-Up View)

```
  ┌─────────────────────────────────────────────────────────┐
  │           tidefs-background-scheduler (#1673)            │
  │  ┌───────────────────────────────────────────────────┐  │
  │  │ TickLoop → dispatch(JobKind, WorkBudget) → step() │  │
  │  └───────────────────────────────────────────────────┘  │
  └────────────┬──────┬──────┬──────┬──────┬──────────────┘
               │      │      │      │      │
               ▼      ▼      ▼      ▼      ▼
  ┌─────────────────────────────────────────────────────────┐
  │     Subsystem crates implement IncrementalJob            │
  │                                                          │
  │  cleanup-job-core      orphan-recovery-job-core          │
  │  reclaim-job-core      scrub-service                    │
  │  deep-scrub-service    resilver-service                 │
  │  gc-mark-service       btree-compaction-service          │
  │  rebake-service        journal-clean-service             │
  │  dataset-destroy-svc   rebalance-service                 │
  │  admin-job-service     (14 subsystems total)             │
  └────────────┬────────────────────────────────────────────┘
               │
               │ depends on (trait impl)
               ▼
  ┌─────────────────────────────────────────────────────────┐
  │   tidefs-incremental-job-core (Phase 2, #1620)           │
  │   IncrementalJob trait, CheckpointCodec trait            │
  └────────────┬────────────────────────────────────────────┘
               │
               │ depends on (types)
               ▼
  ┌─────────────────────────────────────────────────────────┐
  │ tidefs-types-incremental-job-core (Phase 1, #1385)       │
  │ WorkBudget, JobId, JobKind, CursorState, Checkpoint,     │
  │ StepResult, JobProgress, JobError                        │
  └─────────────────────────────────────────────────────────┘
```

### 1.2 Wire-Up Pattern

Every subsystem follows a uniform wire-up pattern with five integration points:

| Integration Point | What the subsystem provides | Constrained by |
|---|---|---|
| 1. `JobKind` variant | Uses its pre-assigned variant (e.g., `JobKind::DeferredCleanup`) | Sealed enum; new variants require design issue |
| 2. Cursor format | Opaque `Vec<u8>` in `CursorState` — subsystem defines internal layout | Must be self-describing for resume; prefer length-delimited framing |
| 3. `IncrementalJob` impl | `resume()`, `step()`, `persist_checkpoint()`, `complete()` | Trait contract (send-safe, idempotent, budget-respecting) |
| 4. Checkpoint persistence | `CheckpointCodec` encode/decode for on-media storage | Binary format with magic `0xC0D0`/`0xC0D1`, versioned, length-delimited |
| 5. Scheduler registration | Registers `JobKind` + factory with background scheduler | Scheduler's `ServiceRegistry` contract |

### 1.3 Implementation Status Matrix

| # | Subsystem | JobKind | Crate | Status | Wire-Up Issue |
|---|---|---|---|---|---|
| 1 | Deferred Cleanup | `DeferredCleanup` | `tidefs-cleanup-job-core` | **implemented** | #1385 |
| 2 | Snapshot Destroy | `SnapshotDestroy` | `tidefs-dataset-lifecycle` | **deferred** | TBD |
| 3 | GC Mark | `GCMark` | `tidefs-cluster-gc` | **deferred** | TBD |
| 4 | B+tree Compaction | `BtreeCompaction` | `tidefs-btree` | **deferred** | TBD |
| 5 | Rebake | `Rebake` | `tidefs-rebuild-planner` | **deferred** | TBD |
| 6 | Journal Cleaning | `JournalCleaning` | `tidefs-local-object-store` | **deferred** | TBD |
| 7 | Dataset Destroy | `DatasetDestroy` | `tidefs-dataset-lifecycle` | **deferred** | TBD |
| 8 | Scrub | `Scrub` | `tidefs-online-verifier` | **deferred** | TBD |
| 9 | Deep Scrub | `DeepScrub` | `tidefs-online-verifier` | **deferred** | TBD |
| 10 | Resilver | `Resilver` | `tidefs-rebuild-planner` | **deferred** | TBD |
| 11 | Rebalance | `Rebalance` | `tidefs-rebalance-planner` | **deferred** | TBD |
| 12 | Admin Jobs | `AdminJob` | `tidefs-control-plane-runtime` | **deferred** | TBD |
| 13 | Reclaim | `Reclaim` | `tidefs-reclaim-job-core` | **deferred** | TBD |
| 14 | Orphan Recovery | `OrphanRecovery` | `tidefs-orphan-recovery-job-core` | **deferred** | TBD |

## 2. Data Structures — Subsystem Cursor and Checkpoint Formats

### 2.1 Cursor Design Principles

Each subsystem defines its own cursor format stored in `CursorState(Vec<u8>)`.
The framework treats cursors as opaque blobs; the subsystem is responsible for:

1. **Self-describing format**: The cursor must carry enough state to resume
   from any valid position without re-scanning.
2. **Forward-only monotonicity**: Once a cursor position is checkpointed and
   persisted, re-executing `step()` from that position must be idempotent.
3. **Compact representation**: Cursor size should be O(log N) for N-element
   datasets, not O(N). Large cursors (> 4 KiB) should use lightweight
   compression (LZ4).
4. **Length-delimited framing**: Multi-field cursors should use a
   length-delimited binary framing (tag-length-value or equivalent) to
   enable forward-compatible field additions.

### 2.2 Per-Subsystem Cursor Schema

#### 2.2.1 Deferred Cleanup (implemented)

```rust
struct CleanupCursor {
    /// Current extent offset in the refcount delta queue
    extent_offset: u64,
    /// Birth transaction group of the last processed entry
    last_birth_commit_group: u64,
    /// Spacemap segment index (for segmented cleanup)
    segment_index: u32,
}
```

Encoded as 20 bytes: `[offset: u64 LE][last_commit_group: u64 LE][segment: u32 LE]`.

#### 2.2.2 Snapshot Destroy (deferred)

```rust
struct SnapshotDestroyCursor {
    /// Dataset ID being destroyed
    dataset_id: u64,
    /// Current B+tree traversal position (object ID)
    current_object_id: u64,
    /// Number of objects freed so far
    objects_freed: u64,
    /// Bytes freed so far (for progress tracking)
    bytes_freed: u64,
}
```

Encoded as 32 bytes: `[dataset: u64 LE][obj: u64 LE][objs_freed: u64 LE][bytes: u64 LE]`.

#### 2.2.3 GC Mark (deferred)

```rust
struct GCMarkCursor {
    /// Current GC generation number
    generation: u64,
    /// Current object ID being traversed
    object_id: u64,
    /// Bitmap of completed root sets (for multi-root GC)
    root_set_mask: u64,
}
```

Encoded as 24 bytes: `[gen: u64 LE][obj: u64 LE][roots: u64 LE]`.

#### 2.2.4 B+tree Compaction (deferred)

```rust
struct BtreeCompactionCursor {
    /// Current leaf page number
    leaf_page: u64,
    /// Offset within the current leaf page
    intra_page_offset: u16,
    /// Source generation (for detecting concurrent splits)
    source_generation: u64,
}
```

Encoded as 18 bytes: `[page: u64 LE][offset: u16 LE][gen: u64 LE]`.

#### 2.2.5 Rebake (deferred)

```rust
struct RebakeCursor {
    /// Ingest journal sequence number being processed
    journal_seq: u64,
    /// Offset within the current journal segment
    segment_offset: u64,
    /// Target base shard ID
    target_shard: u64,
}
```

Encoded as 24 bytes: `[seq: u64 LE][offset: u64 LE][shard: u64 LE]`.

#### 2.2.6 Journal Cleaning (deferred)

```rust
struct JournalCleanCursor {
    /// Oldest transaction group to retain
    min_commit_group: u64,
    /// Current segment being cleaned
    segment_id: u64,
    /// Offset within the current segment
    segment_offset: u64,
}
```

Encoded as 24 bytes: `[min_commit_group: u64 LE][seg: u64 LE][offset: u64 LE]`.

#### 2.2.7 Dataset Destroy (deferred)

```rust
struct DatasetDestroyCursor {
    /// Dataset ID being destroyed
    dataset_id: u64,
    /// Current block being freed (allocation-order traversal)
    current_block: u64,
    /// Total blocks to free
    total_blocks: u64,
}
```

Encoded as 24 bytes: `[ds: u64 LE][block: u64 LE][total: u64 LE]`.

#### 2.2.8 Scrub (deferred)

```rust
struct ScrubCursor {
    /// Current extent ID being verified
    extent_id: u64,
    /// Pool generation for topology consistency
    pool_generation: u64,
    /// Checksum errors detected so far (for progress)
    cksum_errors: u32,
    /// Reserved padding
    _pad: u32,
}
```

Encoded as 24 bytes: `[extent: u64 LE][pool_gen: u64 LE][errors: u32 LE][pad: u32 LE]`.

#### 2.2.9 Deep Scrub (deferred)

```rust
struct DeepScrubCursor {
    /// Current extent ID (same address space as Scrub)
    extent_id: u64,
    /// Current byte offset within the extent
    intra_extent_offset: u64,
    /// Pool generation
    pool_generation: u64,
}
```

Encoded as 24 bytes: `[extent: u64 LE][offset: u64 LE][pool_gen: u64 LE]`.

#### 2.2.10 Resilver (deferred)

```rust
struct ResilverCursor {
    /// Current extent ID being rebuilt
    extent_id: u64,
    /// Target device ID (the replacement device)
    target_device: u64,
    /// Resilver pass number (multi-pass for erasure-coded data)
    pass_number: u8,
    /// Reserved padding
    _pad: [u8; 7],
}
```

Encoded as 24 bytes: `[extent: u64 LE][device: u64 LE][pass: u8][pad: 7u8]`.

#### 2.2.11 Rebalance (deferred)

```rust
struct RebalanceCursor {
    /// Current extent ID being relocated
    extent_id: u64,
    /// Source device ID
    source_device: u64,
    /// Target device ID
    target_device: u64,
}
```

Encoded as 24 bytes: `[extent: u64 LE][src: u64 LE][tgt: u64 LE]`.

#### 2.2.12 Admin Jobs (deferred)

```rust
struct AdminJobCursor {
    /// Admin operation discriminant (sub-kind for JobKind::AdminJob)
    admin_subkind: u8,
    /// Reserved padding
    _pad: [u8; 7],
    /// Operation-specific cursor payload (union-based dispatch by admin_subkind)
    payload: [u8; 64],
}
```

Encoded as 72 bytes: `[subkind: u8][pad: 7u8][payload: 64u8]`.

The 64-byte payload is interpreted differently per `admin_subkind`:
- `0x01` (Pool Import): `[phase: u8][device_index: u16 LE][label_offset: u32 LE][_pad: 57u8]`
- `0x02` (Dataset Send): `[seq: u64 LE][offset: u64 LE][_pad: 48u8]`
- `0x03` (Dataset Receive): `[seq: u64 LE][offset: u64 LE][_pad: 48u8]`
- `0x04` (Snapshot Rollback): `[phase: u8][obj_id: u64 LE][_pad: 55u8]`

#### 2.2.13 Reclaim (deferred)

```rust
struct ReclaimCursor {
    /// Current allocation unit offset
    alloc_unit: u64,
    /// Space accounting generation
    space_gen: u64,
}
```

Encoded as 16 bytes: `[unit: u64 LE][gen: u64 LE]`.

#### 2.2.14 Orphan Recovery (deferred)

```rust
struct OrphanRecoveryCursor {
    /// Current orphan index entry
    orphan_index: u64,
    /// Dataset generation for consistency
    dataset_generation: u64,
}
```

Encoded as 16 bytes: `[index: u64 LE][gen: u64 LE]`.

### 2.3 Checkpoint Binary Format

All subsystems use the binary format defined by `CheckpointCodec`:

```
┌─────────┬─────────┬─────────┬──────────┬──────────┐
│  Magic  │ Version │ Epoch   │ Cursor   │ Reserved │
│  4 B    │  2 B    │  8 B    │  Len B   │  4 B     │
├─────────┼─────────┼─────────┼──────────┼──────────┤
│0xC0D0   │   1     │ u64 LE  │ Len u32  │ 0x000000 │
│(encode) │         │         │ + bytes  │  0000    │
│0xC0D1   │         │         │          │          │
│(decode) │         │         │          │          │
└─────────┴─────────┴─────────┴──────────┴──────────┘
```

Total header: 18 bytes + cursor length. Magic `0xC0D0` for encode (write)
and `0xC0D1` for decode (read) prevents writing a partially-read buffer
back to storage.

The cursor payload within the binary frame is the subsystem-specific
cursor format defined in §2.2. `CheckpointCodec` is agnostic to the
cursor contents — it only frames the opaque bytes.

## 3. Algorithms

### 3.1 Universal Wire-Up Lifecycle

Every subsystem wire-up follows this algorithm:

```
1. SCHEDULER START:
   a. Scheduler selects JobKind based on priority and available budget.
   b. Scheduler reads the persisted checkpoint for this JobKind from stable storage
      via CheckpointCodec::read().
   c. Scheduler calls <SubsystemJob>::resume(checkpoint) to construct the job.

2. TICK LOOP (repeats until Complete or fatal error):
   a. Scheduler allocates a WorkBudget for this tick (DEFAULT_TICK or MAINTENANCE_TICK).
   b. Scheduler calls job.step(budget).
   c. If StepResult::InProgress(cp):
      - Call job.persist_checkpoint(&cp) to flush to stable storage.
      - Continue tick loop (go to 2a).
   d. If StepResult::Complete(cp):
      - Call job.persist_checkpoint(&cp) for final checkpoint.
      - Call job.complete() to finalize.
      - Remove this job from the active set.
   e. If Err(JobError):
      - Log the error.
      - If fatal (Corrupted, Fatal, Storage), remove job and alert operator.
      - If transient (BudgetExceeded, Cancelled, InvalidCursor), retry with backoff.

3. CRASH RECOVERY:
   a. On daemon restart, scheduler scans persisted checkpoints.
   b. For each checkpoint with is_complete() == false:
      - Reconstruct the job via <SubsystemJob>::resume(Some(checkpoint)).
      - The job's resume() method repositions its internal iterator to the
        cursor position stored in the checkpoint.
      - Resume tick loop from step 2.
```

### 3.2 Resume Algorithm (per subsystem)

Every `resume()` implementation follows this pattern:

```
fn resume(state: Option<Checkpoint>) -> Result<Self, JobError> {
    match state {
        None => {
            // Fresh start: initialize cursor to zero position
            Self::new_fresh()
        }
        Some(cp) if cp.is_fresh() => {
            // Empty initial checkpoint: same as fresh start
            Self::new_fresh()
        }
        Some(cp) => {
            // Crash recovery: decode cursor, reposition iterator
            let cursor = Self::decode_cursor(cp.cursor_state())?;
            Self::resume_from_cursor(cursor)
        }
    }
}
```

**Idempotency guarantee**: `resume(Some(cp))` followed by `step()` must
produce the same side effects as if the previous `step()` that produced
`cp` had not crashed. This is achieved by:

1. The checkpoint cursor points to the **last successfully completed**
   position, not the in-progress position.
2. `step()` updates the cursor **after** completing work, not before.
3. Work items processed within a step are idempotent (e.g., freeing an
   already-freed block is a no-op).

### 3.3 Step Algorithm (bounded batch)

```
fn step(&mut self, budget: WorkBudget) -> Result<StepResult, JobError> {
    let mut items = 0u64;
    let mut bytes = 0u64;
    let start = Instant::now();

    loop {
        // Check budget bounds
        if budget.is_paused() {
            return Err(JobError::cancelled(self.job_id()));
        }
        if budget.max_items > 0 && items >= budget.max_items { break; }
        if budget.max_bytes > 0 && bytes >= budget.max_bytes { break; }
        if budget.max_ms > 0 && start.elapsed().as_millis() as u64 >= budget.max_ms { break; }

        // Fetch next work item
        let item = match self.next_work_item() {
            Some(item) => item,
            None => {
                // No more work: job is complete
                let cp = self.final_checkpoint();
                return Ok(StepResult::Complete(cp));
            }
        };

        // Process the work item
        self.process_item(&item)?;
        items += 1;
        bytes += item.byte_cost();

        // Update internal cursor position
        self.advance_cursor(&item);
    }

    // Budget exhausted with work remaining
    let cp = self.current_checkpoint();
    Ok(StepResult::InProgress(cp))
}
```

**Budget enforcement rules**:
- All three dimensions (items, bytes, time) are checked on every iteration.
- A zero limit means "unbounded" for that dimension.
- If all limits are zero (`UNBOUNDED`), the step processes all remaining
  work in a single call — use only for tests and urgent operations.
- Time budget is a soft hint; the implementation checks between items but
  does not preempt mid-item processing.

### 3.4 Persist Checkpoint Algorithm

```
fn persist_checkpoint(&self, checkpoint: &Checkpoint) -> Result<(), JobError> {
    // Encode the checkpoint using CheckpointCodec
    let mut buf = Vec::new();
    self.codec().encode(checkpoint, &mut buf)
        .map_err(|e| JobError::storage(self.job_id(), e))?;

    // Write atomically to stable storage
    // Use write-to-temp + rename for crash safety
    let path = self.checkpoint_path();
    let tmp = format!("{}.tmp", path);
    std::fs::write(&tmp, &buf)
        .map_err(|e| JobError::storage(self.job_id(), e))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| JobError::storage(self.job_id(), e))?;

    // Optional: fsync the directory entry
    // (required for true crash safety; optional for latency-sensitive paths)
    Ok(())
}
```

### 3.5 Complete Algorithm

```
fn complete(self) -> Result<(), JobError> {
    // 1. Flush any in-memory state to stable storage
    self.flush_pending_writes()?;

    // 2. Remove the persisted checkpoint file
    //    (signals to the scheduler that this job is done)
    let path = self.checkpoint_path();
    if std::path::Path::new(&path).exists() {
        std::fs::remove_file(&path)
            .map_err(|e| JobError::storage(self.job_id(), e))?;
    }

    // 3. Log completion for observability
    //    (scheduler records completion in job history)

    // 4. Drop self — no further calls permitted
    Ok(())
}
```

**Post-complete invariants**:
- The checkpoint file must not exist on disk.
- The scheduler must not attempt to resume this job on next daemon start.
- Job history (completed jobs log) records the final progress for admin visibility.

### 3.6 Concurrent Safety Algorithm

When multiple subsystems run concurrently on the same dataset, write-set
conflicts must be avoided:

```
1. SHARED RESOURCE DECLARATION:
   Each JobKind declares its write set in the subsystem crate docs.
   E.g., DeferredCleanup writes to: refcount_delta_queue, spacemap.
         BtreeCompaction writes to: btree_leaf_pages, btree_internal_pages.

2. SCHEDULER CONFLICT DETECTION:
   Before dispatching a step for JobKind A, the scheduler checks:
   a. Is any other active job writing to a resource in A's write set?
   b. If yes, defer A's step until the conflicting job's step completes.

3. COMMIT_GROUP-BASED ORDERING (for block allocator):
   Jobs that modify block allocation (DeferredCleanup, Destroy, Clean,
   Reclaim) must serialize their steps within the same COMMIT_GROUP.
   The scheduler enforces this by grouping allocator-modifying jobs
   into a serial dispatch queue within each COMMIT_GROUP.

4. READ-WRITE CONFLICT (for GC Mark):
   GC Mark reads all live objects. Any job that frees objects
   (DeferredCleanup, Destroy, Clean) must not run concurrently
   with GC Mark. The scheduler defers frees while GC is active.
```

## 4. Error Handling Architecture

### 4.1 Error Classification per Subsystem

| Error variant | When used | Subsystem action |
|---|---|---|
| `JobError::Cancelled` | Operator cancels job via admin interface | Stop at next step boundary, call `complete()` |
| `JobError::BudgetExceeded` | Internal budget check fails (should not happen) | Bug — log and retry with smaller internal batch |
| `JobError::InvalidCursor` | Corrupted checkpoint on resume | Log, discard checkpoint, restart from fresh |
| `JobError::Storage` | IO error during persist_checkpoint or data access | Retry N times with backoff; if persistent, mark job `FATAL` |
| `JobError::Fatal` | Unrecoverable corruption or invariant violation | Stop job, alert operator, preserve checkpoint for debugging |
| `JobError::Other(msg)` | Subsystem-specific error with context | Log with context, retry or escalate based on message content |

### 4.2 Error Recovery State Machine

```
  ┌──────────┐  Cancelled   ┌────────────┐
  │  ACTIVE  │─────────────▶│ CANCELLING  │──▶ complete()
  └────┬─────┘              └────────────┘
       │
       │ Storage error (transient)
       ▼
  ┌──────────┐  retry ok    ┌──────────┐
  │RETRYING  │─────────────▶│  ACTIVE   │
  └────┬─────┘              └──────────┘
       │
       │ Storage error (persistent, N retries exhausted)
       ▼
  ┌──────────┐
  │  FATAL   │──▶ alert operator, preserve state
  └──────────┘
```

### 4.3 Checkpoint Safety During Errors

- **Never checkpoint after an error**: If `step()` returns `Err`, the caller
  must NOT call `persist_checkpoint()`. The cursor position is unchanged.
- **Atomic checkpoint writes**: `persist_checkpoint()` must use write-to-temp
  + rename to prevent partial writes from being read on crash recovery.
- **Checkpoint versioning**: The `CheckpointCodec` version field enables
  forward-compatible format changes. A newer daemon can read an older
  checkpoint format (within the same major version).

## 5. Tradeoffs and Design Decisions

### 5.1 Opaque Cursor vs. Typed Cursor

**Decision**: `CursorState(Vec<u8>)` — opaque blob, each subsystem defines its own format.

**Tradeoff**: Subsystems cannot share cursor inspection tools, and the scheduler
cannot introspect cursor progress (e.g., to compute ETA from cursor position).
However, the alternative — a typed cursor union — would require either:
- A massive enum covering all 14 subsystem cursor types (brittle, high coupling), or
- Dynamic dispatch via `Box<dyn Cursor>` (heap allocation, `no_std` incompatible).

**Mitigation**: The scheduler computes progress from `JobProgress` counters, not
from cursor introspection. Admin tools that need cursor details query the
subsystem directly via admin protocol.

### 5.2 Single Checkpoint per Job vs. Multiple Independent Cursors

**Decision**: Single checkpoint per job, single opaque cursor payload.

**Tradeoff**: Some jobs benefit from multiple independent cursors (e.g.,
journal cleaning with one cursor per segment). These jobs must encode
multiple sub-cursors into the single opaque `Vec<u8>` using their own
framing.

**Mitigation**: The cursor payload is opaque and length-delimited. A
multi-cursor job can use TLV framing internally: `[tag: u8][len: u16 LE][data]...`.

### 5.3 send-safe Trait Bound

**Decision**: `IncrementalJob: Send` (not `Sync`).

**Tradeoff**: Jobs cannot be shared across threads, but the scheduler only
needs to move ownership between the dispatch thread and the tick thread.
Adding `Sync` would restrict subsystem implementations (no `Rc`, no `Cell`)
without providing benefit.

**Rationale**: Each job is owned by exactly one scheduler worker thread for
its entire lifetime. Cross-thread sharing is unnecessary.

### 5.4 complete() Consumes self

**Decision**: `complete(self)` takes ownership.

**Tradeoff**: Prevents accidental reuse of a completed job. The scheduler must
move the job out of its handle before calling `complete()`. This adds a minor
ergonomic cost but eliminates an entire class of bugs (calling `step()` after
`complete()`).

**Alternative**: `&mut self` with a `completed: bool` flag. Rejected because
it pushes the safety burden onto every `step()` implementation.

### 5.5 Binary Format vs. Serde-Only

**Decision**: Provide both `CheckpointCodec` (binary) and optional `serde`
support.

**Tradeoff**: Maintaining two serialization paths adds implementation cost.
The binary format is ~2× more compact than JSON and works without `serde`
matters.

### 5.6 JobKind::Other(u8) vs. Open Enum

**Decision**: `JobKind::Other(u8)` as a forward-compatibility escape hatch.

**Tradeoff**: The scheduler cannot apply specialized scheduling policy to
unknown `JobKind::Other` variants. However, this is acceptable because:
- Only future wire-up issues (not yet designed) need this slot.
- Once a subsystem is wired up with a concrete variant, the `Other` escape
  is no longer used for that subsystem.
- The cost (2 bytes for niche optimization) is minimal.

**Limit**: After 256 - 14 = 242 future subsystems, the `u8` discriminant
is exhausted. This is far beyond the planned 14 subsystems.

### 5.7 Scheduler-Owned Priority vs. Trait-Owned Priority

**Decision**: The scheduler owns the priority table, not the trait.

**Tradeoff**: Jobs cannot override their scheduling priority at runtime.
This is intentional: scheduling policy should be operator-configurable,
not hardcoded in subsystem code. The scheduler maps `JobKind` → priority
from a configuration file or admin protocol command.

### 5.8 no_std Core vs. alloc Default

**Decision**: `no_std` with `alloc` feature enabled by default.

**Tradeoff**: The `alloc` default pulls in `Vec<u8>` and `String`, which
are not available in embedded probe contexts. However, the 99% case (all
tidefs daemons) runs with a heap. Disabling `alloc` produces a ~500-line
core with only `WorkBudget`, `JobId`, `JobKind`, `JobProgress`, and
fixed-message `JobError` variants.

## 6. Wire-Up Issue Template

Each deferred wire-up issue must follow this template:

```
Title: Wire up <SubsystemName> to IncrementalJob trait

## Summary
Implement IncrementalJob for the <SubsystemName> subsystem using
the sealed types from tidefs-types-incremental-job-core and
the trait from tidefs-incremental-job-core.

## Pre-requisites
- [ ] tidefs-types-incremental-job-core (implemented)
- [ ] tidefs-incremental-job-core (implemented)
- [ ] tidefs-background-scheduler (implemented)
- [ ] <Subsystem-specific dependency crates> (TBD)

## Implementation Scope
1. Define subsystem-specific cursor format (§2.2 of wire-up design)
2. Implement IncrementalJob trait:
   - resume(Option<Checkpoint>) -> Result<Self, JobError>
   - step(WorkBudget) -> Result<StepResult, JobError>
   - persist_checkpoint(&Checkpoint) -> Result<(), JobError>
   - complete(self) -> Result<(), JobError>
   - job_id() -> JobId
   - job_kind() -> JobKind
3. Implement CheckpointCodec for on-media persistence
4. Register with background scheduler via ServiceRegistry
5. Add unit tests: resume-fresh, resume-from-checkpoint, step-bounded,
   step-complete, persist-checkpoint, complete, error-recovery

- cargo test -p <subsystem-crate>
- cargo clippy -p <subsystem-crate> -- -D warnings
- cargo check --workspace

## Completion Criteria
- All trait methods implemented and tested
- Checkpoint persistence passes crash-recovery test
- Scheduler correctly dispatches steps for this JobKind
- No unsafe code added
```

## 7. Integration Contract with Background Scheduler

### 7.1 Registration

```rust
/// Each wire-up subsystem registers with the scheduler during daemon bootstrap.
pub trait ServiceRegistry {
    /// Register a job factory for a specific JobKind.
    fn register(
        &mut self,
        kind: JobKind,
        priority: ServicePriority,
        budget_profile: ServiceBudget,
        factory: Box<dyn Fn(Option<Checkpoint>) -> Box<dyn IncrementalJob>>,
    );
}
```

### 7.2 Tick Dispatch Contract

The scheduler guarantees:
1. At most one `step()` call is in-flight per job at any time.
2. `persist_checkpoint()` is called between `step()` calls when
   `StepResult::InProgress` is returned.
3. `complete()` is called exactly once after `StepResult::Complete`.
4. No further calls are made after `complete()` returns.
5. If `step()` or `persist_checkpoint()` returns `Err(JobError::Fatal)`,
   the job is permanently removed from the active set.

The subsystem guarantees:
1. Every `step()` call respects the supplied `WorkBudget`.
2. The cursor in `StepResult` points to the last fully completed position.
3. Replaying from that cursor (via `resume(Some(cp))`) is idempotent.
4. `persist_checkpoint()` is crash-safe (atomic write).

### 7.3 Observability Contract

The scheduler exposes per-job observability via the admin protocol:

| Metric | Source | Update frequency |
|---|---|---|
| `job_kind` | `job.job_kind()` | Static |
| `job_id` | `job.job_id()` | Static |
| `progress` | `StepResult.checkpoint.progress()` | Per step |
| `state` | Scheduler (Active/Retrying/Fatal/Done) | Per state change |
| `last_error` | `JobError` from last failed `step()` | On error |
| `budget_profile` | Scheduler configuration | On config change |
| `tick_count` | Scheduler counter | Per tick |
| `total_items` | Accumulated from `JobProgress` | Per step |
| `total_bytes` | Accumulated from `JobProgress` | Per step |
| `elapsed_wall` | Scheduler timer | Per tick |

## 8. Testing Strategy for Wire-Up

### 8.1 Per-Subsystem Test Suite

Each wire-up implementation must include:

| Test category | Minimum tests | Key invariants |
|---|---|---|
| Fresh resume | 2 | `resume(None)` returns valid job; `job_kind()` matches |
| Crash resume | 3 | `resume(Some(cp))` restores position; idempotent replay |
| Step bounded | 4 | Respects items/bytes/time limits; returns InProgress |
| Step complete | 2 | Returns Complete when work exhausted; final progress matches |
| Persist checkpoint | 2 | Write + read roundtrip; atomic replacement |
| Complete | 2 | Cleans up checkpoint file; post-complete state valid |
| Error recovery | 3 | InvalidCursor → restart; Storage → retry; Fatal → stops |
| Budget edge cases | 4 | UNBOUNDED, PAUSED, zero items, zero bytes |

### 8.2 Integration Test

1. Run the job for N steps, crash at step N/2.
2. Restart, resume from checkpoint, complete.
3. Verify final state is identical to a non-crashed run.


```bash
cargo test -p <subsystem-crate>
cargo clippy -p <subsystem-crate> -- -D warnings
cargo test -p tidefs-types-incremental-job-core
cargo test -p tidefs-incremental-job-core
cargo check --workspace
```

## 9. Migration Path from Deferred to Implemented

For each subsystem currently at `deferred` status:

```
Phase A: Wire-up issue filed
  ↓
Phase B: IncrementalJob implemented, tests pass
  ↓
Phase C: Scheduler registration added
  ↓
Phase D: Crash-recovery integration test passes
  ↓
Phase E: Closeout recorded in the wire-up GitHub issue/PR and, when document authority changes, docs/DOCUMENTATION_AUTHORITY_REGISTER.md
  ↓
Phase F: Wire-up issue closed
```

The first subsystem through this pipeline (DeferredCleanup, already implemented
in #1385) serves as the reference implementation for all subsequent wire-ups.

## 10. References

- **Universal incremental cursor framework**: `docs/UNIVERSAL_INCREMENTAL_CURSOR_FRAMEWORK_DESIGN.md`
- **Canonical type design**: [`docs/design/incremental-job-core-types-crate-design.md`](./incremental-job-core-types-crate-design.md)
- **Formal seal document**: [`docs/design/incremental-job-core-types-crate-design-sealed.md`](./incremental-job-core-types-crate-design-sealed.md)
- **Phase 2 trait + CheckpointCodec**: [`docs/design/incremental-job-core-trait-checkpoint-codec-design.md`](./incremental-job-core-trait-checkpoint-codec-design.md)
- **Background service framework**: [`docs/design/background-service-framework-design.md`](./background-service-framework-design.md)
- **Deferred cleanup wire-up**: #1385 (reference implementation)
- **Types crate**: `crates/tidefs-types-incremental-job-core/src/lib.rs`
- **Core crate**: `crates/tidefs-incremental-job-core/src/lib.rs`
- **Background scheduler**: `crates/tidefs-background-scheduler/src/lib.rs`

## 11. Revision History

| Date | Change | Issue |
|---|---|---|
| 2026-05-02 | Initial crate implementation (1619 + 992 lines) | #1385 |
| 2026-05-04 | Design document formalized | #1588 |
| 2026-05-04 | Coordination seal confirmed; design frozen | #1930 |
| 2026-05-04 | Formal seal document; wire-up deferred | #1985 |
| 2026-05-05 | Wire-up deferred design document; per-subsystem cursor schemas, algorithms, tradeoffs, and wire-up issue template | #2047 |
