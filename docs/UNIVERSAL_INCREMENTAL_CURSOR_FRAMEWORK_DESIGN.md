# Universal Incremental Cursor Framework Design (P2)

Maturity: **design-spec** for the single cross-cutting contract that governs all
bounded, cursor-driven, crash-resumable background work in tidefs: deferred cleanup,
snapshot destroy, metadata GC, B+tree compaction, rebake, journal cleaning, admin
jobs, and scrub — collectively 8+ subsystems.

This document closes Forgejo issue #1239.

## 1. Motivation

A recurring pattern appears across at least eight tidefs subsystems: iterate a
potentially enormous persistent data structure in bounded steps, checkpoint progress
at stable intervals, and resume from the last checkpoint after a crash. Every
subsystem that reinvents this pattern independently must solve the same hard problems:

- **Boundedness**: A single step must not exceed memory, time, or IO budgets regardless
  of dataset size. O(total-elements) passes are unacceptable.
- **Crash safety**: A crash between steps must not lose completed work or corrupt
  persistent state. Idempotent resumption must be guaranteed.
- **Admin visibility**: Operators need a unified view of all active background work —
  progress, ETA, stuck jobs, crash history — without querying N separate subsystems.
- **Scheduling integration**: The background service framework (#1179) needs a uniform
  interface to allocate per-tick budgets across heterogeneous job types.

Without a shared contract, each subsystem:
- Defines its own ad-hoc cursor format (incompatible, non-standard)
- Implements its own checkpoint persistence (inconsistent reliability)
- Exposes its own admin interface (fragmented operator experience)
- Duplicates crash-recovery logic (subtle divergence in edge cases)

ZFS and Ceph provide useful historical design input: their background and
repair paths have multiple progress-tracking mechanisms rather than one shared
TideFS-style cursor contract. This document does not claim current TideFS
parity or superiority over either system; it records the architectural lesson
that TideFS should avoid duplicating cursor, checkpoint, and visibility logic
across subsystems before those paths become entrenched.

## 2. Relationship to Existing Designs

| Design | Integration point | This design provides |
|---|---|---|
| #1179 (background service) | Per-tick scheduling | Uniform `WorkBudget` allocation and `step()` dispatch |
| #1212 (deferred cleanup) | Extent-free iteration | Cursor over refcount/locator extents to free |
| #1232 (snapshot deadlist) | Deadlist B+tree iteration | Cursor over birth_commit_group-ordered deadlist entries |
| #1197 (B+tree compaction) | Sorted key/value rewrite | Cursor over B+tree leaf pages |
| #1222 (rebake) | Ingest-to-base conversion | Cursor over ingest journal records |
| #1217 (admin jobs) | Long-running admin ops | IncrementalJob trait wrapping admin operations |
| #1215 (space accounting) | Space reclaim tracking | Progress counters (bytes_freed, bytes_relocated) |
| #1288 (scrub/repair/resilver) | Integrity verification | Cursor over extent IDs for SCRUB/DEEP_SCRUB/RESILVER |
| #1239 (this design) | Defines the contract | All subsystems implement IncrementalJob |

## 3. Core Contracts

### 3.1 IncrementalJob trait

Every cursor-driven subsystem must implement this trait:

```rust
/// The universal contract for bounded, cursor-driven, crash-resumable background work.
///
/// Every implementation MUST:
/// - Accept and respect a `WorkBudget` on every `step()` call
/// - Return an accurate `StepResult` with the updated `Checkpoint`
/// - Support `resume(None)` for first-run and `resume(Some(cp))` for crash recovery
/// - Guarantee idempotency: `step()` with the same cursor position produces no
///   duplicate side effects
pub trait IncrementalJob: Send {
    /// Resume from a previous checkpoint, or start fresh.
    ///
    /// `state`: `None` for first run; `Some(cp)` after crash or restart.
    /// Implementations load the cursor position from the persisted checkpoint
    /// and reposition their internal iterator accordingly.
    fn resume(state: Option<Checkpoint>) -> Result<Self, JobError>
    where
        Self: Sized;

    /// Execute one bounded batch of work.
    ///
    /// MUST NOT exceed the supplied `budget`. On return, `StepResult.checkpoint`
    /// reflects the exact position after the batch. The caller persists this
    /// checkpoint before the next `step()`.
    ///
    /// If `StepResult.is_complete` is true, the job has finished and the caller
    /// should invoke `complete()`.
    fn step(&mut self, budget: WorkBudget) -> Result<StepResult, JobError>;

    /// Persist the checkpoint to stable storage.
    ///
    /// Called after every `step()` that produced a new checkpoint.
    /// Implementations write to the dataset-scoped checkpoint area.
    /// The write must be atomic within the current commit_group.
    fn persist_checkpoint(&self, checkpoint: &Checkpoint) -> Result<(), JobError>;

    /// Finalize the completed job.
    ///
    /// Cleans up the job's persistent checkpoint, releases resources,
    /// and optionally emits a completion event.
    /// Called exactly once when `StepResult.is_complete` is true.
    fn complete(self) -> Result<(), JobError>;

    /// Unique identifier for this job instance.
    fn job_id(&self) -> JobId;

    /// Human-readable kind for admin display.
    fn job_kind(&self) -> JobKind;
}
```

### 3.2 WorkBudget

The universal bounding contract. Every `step()` invocation receives a `WorkBudget`
and MUST NOT exceed any of its active limits:

```rust
/// Resource budget for a single `IncrementalJob::step()` call.
///
/// A limit of 0 means "no limit" (unbounded in that dimension).
/// At least one limit SHOULD be non-zero to guarantee boundedness.
#[derive(Debug, Clone, Copy)]
pub struct WorkBudget {
    /// Maximum records, entries, or items to process in this step.
    pub max_items: u64,
    /// Maximum bytes to allocate, relocate, or write in this step.
    pub max_bytes: u64,
    /// Maximum wall-clock milliseconds for this step (soft limit).
    pub max_ms: u64,
}

impl WorkBudget {
    /// Default tick quantum used when no explicit budget is configured.
    /// Processes up to 1024 items, 64 MiB of IO, or 100 ms.
    pub const DEFAULT_TICK: Self = Self {
        max_items: 1024,
        max_bytes: 64 * 1024 * 1024,
        max_ms: 100,
    };

    /// Budget for a lightweight maintenance tick (e.g., idle cluster).
    pub const MAINTENANCE_TICK: Self = Self {
        max_items: 256,
        max_bytes: 16 * 1024 * 1024,
        max_ms: 50,
    };
}
```

Budget enforcement is the implementor's responsibility. The framework does not
do not exceed their budget.

### 3.3 Checkpoint structure

```rust
/// A stable checkpoint that allows crash-resumable progress.
///
/// Persisted atomically in the dataset-scoped checkpoint area.
/// The opaque `cursor` blob is interpreted only by the owning `IncrementalJob`.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Stable identifier assigned at job creation.
    pub job_id: JobId,
    /// The kind of job (CLEANUP, SNAP_DESTROY, GC_MARK, etc.).
    pub job_kind: JobKind,
    /// Monotonic epoch counter, incremented on each daemon restart.
    /// Enables the admin to distinguish "fresh run" from "crash recovery".
    pub epoch: u64,
    /// Opaque serialized cursor position. Format is private to the implementation.
    pub cursor: CursorState,
    /// Aggregate progress counters since job start.
    pub progress: JobProgress,
}

/// Opaque cursor blob. Serialized/deserialized by the owning IncrementalJob.
#[derive(Debug, Clone)]
pub struct CursorState(Vec<u8>);

/// Aggregate progress since job creation.
#[derive(Debug, Default, Clone, Copy)]
pub struct JobProgress {
    pub items_processed: u64,
    pub bytes_freed: u64,
    pub bytes_relocated: u64,
    pub bytes_written: u64,
    pub errors_skipped: u64,
}

/// Result of a single `step()` invocation.
pub struct StepResult {
    /// The checkpoint to persist. Represents the exact cursor position
    /// after this batch's work was committed.
    pub checkpoint: Checkpoint,
    /// Items processed in this step (for admin display, not required for correctness).
    pub items_this_step: u64,
    /// True if the job has fully completed. The caller should invoke `complete()`.
    pub is_complete: bool,
}
```

### 3.4 JobKind and JobId

```rust
/// Canonical job kinds for admin visibility and scheduling priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JobKind {
    Cleanup,         // Deferred unlink/truncate extent freeing
    SnapDestroy,     // Snapshot deadlist processing
    GcMark,          // Metadata GC reachability marking
    Compact,         // B+tree compaction / segment defragmentation
    Rebake,          // Ingest journal to base shard conversion
    Clean,           // Data journal segment cleaning
    DsDestroy,       // Admin-initiated dataset destroy
    Scrub,           // Online data integrity verification
    DeepScrub,       // Full read-and-verify scrub
    Resilver,        // Device replacement data rebuild
    Rebalance,       // CRUSH weight change data migration
    AdminJob,        // Generic long-running admin operation
}

/// Unique job identifier assigned at creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JobId(pub u64);
```

## 4. State Machine

Every `IncrementalJob` instance moves through a small set of states:

```
                 +----------+
    create() --> |  IDLE    |
                 +----+-----+
                      |
              resume(None)
                      |
                      v
                 +----+-----+
                 |  RUNNING  |<--------+
                 +----+-----+          |
                      |                |
                  step()                |
                      |                |
              +-------+-------+        |
              |               |        |
        is_complete=false   is_complete=true
              |               |
              v               v
         persist()       complete()
              |               |
              v               v
         RUNNING          COMPLETED
              |
          crash/restart
              |
              v
         resume(Some(cp))
              |
              +----> RUNNING
```

States and transitions:

| State | Meaning | Valid transitions |
|---|---|---|
| `IDLE` | Job created but not yet started | `resume(None)` → RUNNING |
| `RUNNING` | Job actively processing or resumable | `step()` → RUNNING; `complete()` → COMPLETED; crash → resumable via `resume(Some(cp))` |
| `COMPLETED` | Job finished, checkpoint deleted | Terminal state |

A job that crashes in RUNNING state is restarted by calling `resume(Some(last_checkpoint))`.
The implementation repositions its internal cursor and continues from the checkpointed position.
No work is lost (cursor advanced only after work committed). No work is silently duplicated
(idempotency at the application level).

## 5. Crash Safety Guarantees

### 5.1 Checkpoint-after-commit ordering

The checkpoint MUST be persisted only after the batch's work is durably committed.
The invariant is:

```
commit_group_commit(work_batch)  →  persist_checkpoint(cursor_after_batch)  →  next_step()
```

If a crash occurs:
- Before `commit_group_commit`: The batch is lost; cursor was not advanced. On resume, the
  job reprocesses the same range. Idempotency at the application level (e.g.,
  refcounts checked before freeing, deadlist entries checked before moving) prevents
  double-processing from causing harm.
- After `commit_group_commit` but before `persist_checkpoint`: The batch's effects are durable
  but the checkpoint was not written. On resume, the job reprocesses the same range.
  Idempotency handles this case identically.
- After `persist_checkpoint`: The cursor has advanced past the batch. The job
  continues from the next position on resume.

### 5.2 Epoch monotonicity

The `Checkpoint.epoch` counter is incremented by the checkpoint persistence layer on
every daemon restart. This enables:
- Admin detection of crash-recovery cycles (epoch > 1 means "this job crashed at
  least once")
- Epoch-based fencing: if a stale epoch is detected (e.g., from a split-brain
  scenario), the job aborts rather than applying stale checkpoints
- Correlation with crash injection harness (#1230) for deterministic testing

### 5.3 Idempotency contract

Every `step()` implementation MUST be idempotent: calling `step()` twice with the
same cursor position and budget produces no duplicate side effects on persistent state.
This is verified by the crash injection harness.

Idempotency strategies (implementation chooses based on job semantics):
- **Before-write check**: Verify the target extent/entry is still in the expected
  state before modifying it (used by CLEANUP, SNAP_DESTROY, DS_DESTROY)
- **Intent logging**: Write an intent record before the batch, clear it after
  (used by REBAKE, CLEAN, RESILVER, REBALANCE)
- **Tombstone-based**: Mark entries as "processed" with a commit_group stamp; skip
  already-processed entries on resume (used by SCRUB, DEEP_SCRUB)

## 6. Subsystem Catalog

Every subsystem that implements `IncrementalJob` is catalogued here with its
cursor semantics, checkpoint granularity, and idempotency strategy.

| Subsystem | Issue | JobKind | Cursor iterates | Checkpoint granularity | Idempotency |
|---|---|---|---|---|---|
| Deferred cleanup | #1212 | CLEANUP | Extent IDs from refcount/locator tables | Per commit_group commit of batched extent frees | Before-write check |
| Snapshot destroy | #1232 | SNAP_DESTROY | Deadlist B+tree entries in birth_commit_group order | After each batch moved/freed | Before-write check |
| Metadata GC mark | — | GC_MARK | B+tree root set, then reachable internal nodes | After each N segments marked | Before-write check |
| B+tree compaction | #1197 | COMPACT | Key/value pairs in sorted order from victim pages | After each N pairs rewritten to new pages | Intent logging |
| Rebake | #1222 | REBAKE | Ingest records in victim segments | After each N records rebaked to base shards | Intent logging |
| Journal cleaning | — | CLEAN | Live records in victim data journal segments | After each N records relocated | Intent logging |
| Dataset destroy | — | DS_DESTROY | Namespace entries (unlink walk) | After each subtree batch | Before-write check |
| Scrub | #1288 | SCRUB | Extent IDs or namespace entries | After each N records verified | Tombstone-based |
| Deep scrub | #1288 | DEEP_SCRUB | Extent IDs with full readback | After each N records verified | Tombstone-based |
| Resilver | #1288 | RESILVER | Extent IDs on degraded devices | After each N extents rebuilt | Intent logging |
| Rebalance | — | REBALANCE | Extent IDs affected by CRUSH weight change | After each N extents relocated | Intent logging |
| Admin job | #1217 | ADMIN_JOB | Subsystem-specific (wraps other jobs) | Delegates to wrapped job | Delegates |

## 7. Admin Visibility

### 7.1 Unified command

```
tidefsctl jobs list [--dataset <name>] [--kind <kind>] [--state <state>]

  JOB_ID  KIND          STATE       PROGRESS                ETA      EP
  42      GC_MARK       RUNNING     1.2M/3.1M segments      45s      1
  43      SNAP_DESTROY  RUNNING     8.3G/120G freed         12m      1
  44      CLEANUP       RESUMABLE   340K items processed    (paused) 2
  45      COMPACT       COMPLETED   4.2M pairs rewritten    —        1
```

Columns:
- `JOB_ID`: Stable identifier, survives restart
- `KIND`: One of the `JobKind` variants
- `STATE`: RUNNING (actively processing), RESUMABLE (crashed or paused, has a persisted
  checkpoint), COMPLETED, FAILED
- `PROGRESS`: Human-readable progress indicator (kind-specific)
- `ETA`: Estimated time to completion (exponential moving average over recent steps)
- `EP`: Epoch counter (1 = first run, 2+ = has crashed or restarted at least once)

### 7.2 Detailed inspection

```
tidefsctl jobs inspect 42

  Job ID:       42
  Kind:         GC_MARK
  State:        RUNNING
  Epoch:        1
  Created:      2026-05-02T14:30:00Z
  Last step:    2026-05-02T14:35:00Z
  Steps taken:  127
  Progress:
    items_processed:  1,200,000
    target_total:     3,100,000
    percent:          38.7%
  Checkpoint:
    size:            128 bytes
    last_persisted:  2026-05-02T14:34:58Z
  Budget applied:
    max_items:  1024
    max_bytes:  67108864
    max_ms:     100
```

### 7.3 Job lifecycle commands

```
tidefsctl jobs pause <job-id>     -- sets budget to zero (job becomes RESUMABLE)
tidefsctl jobs resume <job-id>    -- restores default budget
tidefsctl jobs cancel <job-id>    -- cancels job, deletes checkpoint, calls abort()
tidefsctl jobs reprioritize <job-id> <priority>  -- adjusts scheduling priority
```

## 8. Integration with Background Service (#1179)

The background service framework owns the scheduling loop:

```rust
// Simplified scheduling loop in BackgroundService::tick()
fn tick(&mut self) -> Result<(), Error> {
    let budget = self.calculate_tick_budget();  // from lane priorities
    let jobs = self.load_resumable_jobs();       // all RESUMABLE + RUNNING jobs

    for job in jobs.by_priority() {
        let job_budget = budget.allocate_fraction(job.weight());
        let result = job.step(job_budget)?;

        if result.is_complete {
            job.complete()?;
            self.delete_checkpoint(job.job_id());
        } else {
            job.persist_checkpoint(&result.checkpoint)?;
            self.update_job_stats(job.job_id(), &result);
        }
    }
    Ok(())
}
```

Scheduling priorities are derived from `JobKind`:
- **TIME_CRITICAL** (highest): REBALANCE, RESILVER (data safety at risk)
- **HIGH**: CLEANUP, SNAP_DESTROY (space reclaim pressure), CLEAN (journal pressure)
- **NORMAL**: GC_MARK, COMPACT, SCRUB
- **LOW**: DEEP_SCRUB, ADMIN_JOB (best-effort)

The scheduler may boost priority when resource pressure is detected (e.g., ENOSPC
boosts CLEANUP and CLEAN to TIME_CRITICAL).

## 9. ZFS, Ceph, and ext4 design-input comparison

The table below is a design-input classification. It is not benchmark evidence,
not a current operational capability claim, and not a successor claim. Any
future statement that TideFS provides better boundedness, crash resumption,
operator visibility, or scheduling than these incumbents must be expressed as a
#875 claim with #928/#930 comparator evidence for the exact implementation and
workload.

| Dimension | tidefs (this design) | ZFS | Ceph | ext4 |
|---|---|---|---|---|
| **Cursor contract** | Single `IncrementalJob` trait, all subsystems | No shared contract: arc_evict, dsl_scan, dsl_destroy, spa_sync each have ad-hoc progress tracking | No shared contract: PG recovery, backfill, scrub, deep-scrub each track progress independently | No background cursor framework; fsck is offline, single-pass |
| **Boundedness guarantee** | `WorkBudget` enforced at every `step()`; per-tick limits for items, bytes, time | ARC eviction is bounded; scrub is unbounded (can consume all IOPS) | PG recovery unbounded per tick; backfill O(placement groups) | fsck O(total-inodes+blocks), single-threaded, unbounded memory |
| **Crash resumption** | `resume(Checkpoint)` with commit_group atomicity; cursor checkpointed after work committed | COMMIT_GROUP sync is crash-safe but scrub/destroy/send must restart from beginning on crash | PG recovery restarts from log on crash; scrub restarts from beginning | fsck restarts from beginning on crash |
| **Admin visibility** | Single `tidefsctl jobs list` command; unified progress, ETA, epoch history | Fragmented: `zpool status` (resilver/scrub), `zfs destroy -nv` (destroy estimate), no unified job view | Fragmented: `ceph status` (recovery), `ceph pg dump` (scrub), per-daemon admin sockets | No background job visibility; `fsck` is foreground only |
| **Scheduling integration** | Priority classes per `JobKind`; budget fraction allocation; pressure-driven boosting | ZFS IO scheduler prioritizes sync writes over scrub; no unified scheduling model | Ceph has op priorities but backfill/recovery scheduling is coarse (osd_max_backfills) | No background scheduling |
| **Epoch fencing** | Epoch counter enables stale checkpoint detection and split-brain prevention | No epoch mechanism; split-brain detection relies on pool import/export | OSDMap epoch is global but not used for per-job fencing | Not applicable |

### 9.1 ZFS design-input analysis

ZFS's background work falls into distinct categories, none sharing a cursor contract:

- **Scrub/resilver**: `dsl_scan` iterates the entire pool's block tree. Progress is
  tracked in the ZAP `scrub_progress` object. On crash, scrub restarts from the
  beginning — no incremental checkpoint. On large pools, this means days of lost
  progress. Resilver is identical but filtered to degraded devices.
- **Dataset destroy**: `dsl_destroy` does a synchronous, single-pass traversal.
  For large datasets, destroy blocks the commit_group sync thread for minutes. No
  boundedness guarantee, no incremental progress, no crash safety.
- **Send/receive**: `zfs send` tracks progress via the "resume token," a base64-encoded
  blob. This is the closest ZFS comes to a cursor concept, but the format is
  send-specific and not reused by other subsystems.
- **ARC eviction**: Bounded by ARC size but uses an LRU/most-recently-used hybrid
  with no cursor or checkpoint concept.

### 9.2 Ceph design-input analysis

- **PG recovery/backfill**: Progress tracked per-PG in memory. On OSD restart,
  recovery restarts from the PG log — efficient for recent changes but O(PG count)
  for full recovery. No per-object incremental cursor; no persistent checkpoint.
- **Scrub/deep-scrub**: Per-PG progress tracked in memory. On OSD restart, scrub
  restarts from the beginning of the PG. No persistent checkpoint.

## 10. Implementation Plan

### Phase 1: Core types and trait (this issue)
- `IncrementalJob` trait in `crates/tidefs-types-incremental-cursor/`
- `WorkBudget`, `Checkpoint`, `CursorState`, `JobProgress`, `StepResult`, `JobKind`, `JobId`
- `no_std` compatible with optional `alloc`
- Unit tests for budget enforcement, checkpoint serialization round-trip
- Gate: `tidefs-xtask check-incremental-cursor`

### Phase 2: Checkpoint persistence layer
- `CheckpointStore` trait: `save()`, `load()`, `delete()`, `list_resumable()`
- Dataset-scoped checkpoint area: a B+tree keyed by `(job_kind_be_u8, job_id_be_u64)`
  with serialized `Checkpoint` values
- Atomic commit_group-commit integration: checkpoints written within the same commit_group as the
  causal batch
- Gate: `tidefs-xtask check-checkpoint-store`

### Phase 3: Background service integration (#1179)
- Scheduling loop: load resumable jobs → allocate tick budget → step each job
- Priority classes and pressure-driven boosting
- Admin socket: `tidefsctl jobs list|inspect|pause|resume|cancel`
- Gate: integration test with mock IncrementalJob implementations

### Phase 4: First subsystem adoption — Deferred cleanup (#1212)
- Implement `IncrementalJob` for `CleanupJob`
- Cursor over refcount/locator extent IDs
- Before-write-check idempotency
- Gate: `tidefs-xtask check-cleanup-cursor`

### Phase 5: Second subsystem — Snapshot destroy (#1232)
- Implement `IncrementalJob` for `SnapDestroyJob`
- Cursor over deadlist B+tree entries
- Before-write-check idempotency
- Gate: `tidefs-xtask check-snap-destroy-cursor`

### Phase 6: Remaining subsystems
- B+tree compaction (#1197), rebake (#1222), journal cleaning, dataset destroy
- Scrub, deep scrub, resilver, rebalance (#1288)
- Each implements `IncrementalJob` with its cursor semantics and idempotency strategy

- Crash injection harness (#1230): deterministic crash at step boundaries, verify
  resumption correctness across all subsystem implementations
- Chaos testing: random kill -9 during active jobs, verify all jobs resume and
  complete cleanly
- Budget enforcement: verify no implementation exceeds its WorkBudget
- Admin command: verify `tidefsctl jobs list|inspect|pause|resume|cancel` output


The xtask gate `tidefs-xtask check-incremental-cursor` verifies:

1. Spec, feature matrix, and status entries present
2. Phase 1 crate compiles with `no_std` + optional `alloc`
3. `WorkBudget` enforcement: mock job that overruns budget → test fails
4. Checkpoint round-trip: serialize → deserialize → assert equality
5. State machine: all valid transitions succeed; invalid transitions reject
6. Crash simulation: create job → step 3 times → simulate crash → resume → verify
   no duplicate work, no lost work
7. Admin command output format: `tidefsctl jobs list` parses correctly

## 12. Open Questions

1. **Checkpoint storage format**: B+tree (per-dataset, co-located with on-media metadata)
   or a separate checkpoint log? B+tree is preferred for consistency with the rest
   of the on-media format. A separate log would simplify crash recovery but create
   a new format surface.
2. **Concurrent job limits**: Should there be a per-dataset cap on active jobs
   (e.g., max 4 concurrent `IncrementalJob` instances)? This prevents scheduler
   thrashing but may starve low-priority jobs. Proposal: soft cap of 8 with
   pressure-driven admission.
3. **Job migration**: If a dataset moves between nodes (future cluster feature),
   should jobs migrate with it? The checkpoint is dataset-scoped, so natural migration
   follows dataset ownership. No special migration protocol needed.
4. **Checkpoint compression**: For large cursors (e.g., B+tree position with deep
   stack), should the opaque `CursorState` blob be compressed? LZ4 adds minimal
   CPU cost and reduces checkpoint storage overhead. Defer to Phase 2 profiling.
5. **ETA calculation**: Exponential moving average over recent steps, or linear
   regression over total progress? EMA is simpler and handles rate changes well;
   linear regression gives better estimates for constant-rate jobs. Proposal: EMA
   with configurable window (default 16 steps).
6. **Abort safety**: Should `IncrementalJob` have an `abort()` method for
   cancellation? `complete()` handles successful completion. An explicit `abort()`
   would clean up partial work (e.g., intent log records from a cancelled REBAKE).
   Add `abort()` as an optional trait method with a default no-op for Phase 1.
