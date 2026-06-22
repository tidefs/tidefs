# Deferred Cleanup Background Service Scheduling — Design Specification

**Issue**: [#2058](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2058)
**Authority**: `docs/design/deferred-cleanup-work-queues.md` (canonical design spec, #1929)
**Status**: design-spec — wire-up deferred to Phase 7 issue per §10.2–§10.3 of canonical spec
**Priority**: P2
**Lane**: storage-core
**Depends on**: #1929 (canonical deferred-cleanup design spec), #1992 (background service framework coordination seal), #1180 (refcount delta queues), #1215 (space accounting)
**Blocks**: Phase 7 wire-up issue, ENOSPC pressure response, per-dataset space-pressure handling
**Implemented crates**: `tidefs-cleanup-job-core` (Phase 3: `CleanupJob` as `IncrementalJob`), `tidefs-background-scheduler` (Phases 1–4: 5-stage scheduler)
**Rust implementation**: Phase 7 deferred to wire-up issue per §10.2–§10.3 of canonical spec

## Abstract

This document specifies the scheduling architecture for deferred cleanup work queues
within the TideFS unified background service framework. It defines how `CleanupJob`
instances are registered, prioritized, budgeted, boosted under ENOSPC pressure, and
integrated with admission control. The design builds on the canonical deferred-cleanup
spec (#1929) and the background service framework coordination seal (#1992), providing
the missing scheduling contract between `CleanupJob` (already implemented in
`tidefs-cleanup-job-core`) and the `BackgroundScheduler` (already implemented in
`tidefs-background-scheduler`).

---

## 1. Architecture

### 1.1 System context

```
┌─────────────────────────────────────────────────────────────────┐
│                     POSIX Filesystem Adapter                     │
│  ┌──────────┐   ┌──────────┐   ┌──────────────┐                │
│  │  unlink  │   │ truncate │   │   rmdir      │                │
│  └────┬─────┘   └────┬─────┘   └──────┬───────┘                │
│       │               │               │                          │
│       ▼               ▼               ▼                          │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              Phase 1: Synchronous commit (syscall)          │ │
│  │  · namespace update  · inode state  · logical accounting   │ │
│  │  · enqueue 128-byte CleanupWorkItemV1 → cleanup queue      │ │
│  └──────────────────────┬─────────────────────────────────────┘ │
│                         │ (work item in per-dataset B+tree)      │
└─────────────────────────┼───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                tidefs-background-scheduler                        │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Scheduler::plan_cycle(budget)                              │ │
│  │                                                             │ │
│  │  Critical ──▶ Scrub, Repair                                 │ │
│  │  LatencySensitive ──▶ ViewBuilder, Reclaim, OrphanRecovery │ │
│  │  Throughput ──▶ CleanupJob ◀══ THIS DESIGN                 │ │
│  │  BestEffort ──▶ Compaction, SegmentCleaner                 │ │
│  │  Opportunistic ──▶ Prefetch                                 │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  Per-cycle:                                                      │
│   1. Check ENOSPC pressure → boost CleanupJob to Critical        │
│   2. Dispatch by priority stage                                  │
│   3. CleanupJob::step(budget) → bounded dequeue + complete       │
│   4. Budget cascading: unused higher-priority budget flows down  │
│   5. TickReport merged → TickLog ring buffer                     │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Integration points

| Subsystem | Integration | This design specifies |
|---|---|---|
| `tidefs-background-scheduler` | `BackgroundScheduler::plan_cycle()` | CleanupJob registration, priority assignment, per-tick dispatch |
| `tidefs-cleanup-job-core` | `CleanupJob` as `IncrementalJob` | Scheduling wrapper: budget adaptation, pressure boosting, admission control |
| `BackgroundService` trait | `IncrementalJobAdapter<CleanupJob>` | Trait bridge: `tick()` → `step()` with budget enforcement |
| Space accounting (#1215) | `phys_reclaimable_bytes` | ENOSPC detection and priority boosting trigger |
| Reclaim queues (#1180) | Refcount delta enqueue | Phase 5 dependency: CleanupJob::step() produces deltas consumed by ReclaimJob |
| COMMIT_GROUP state machine (#1267) | Commit ordering | Work items committed in same commit_group as namespace update; scheduler runs after commit_group commit |

### 1.3 CleanupJob lifecycle within the scheduler

```
                      ┌──────────────────┐
                      │  Scheduler start  │
                      └────────┬─────────┘
                               │
                               ▼
                      ┌──────────────────┐
                 ┌───▶│  Paused (initial) │
                 │    └────────┬─────────┘
                 │             │ register()
                 │             ▼
                 │    ┌──────────────────┐
                 │    │     Running       │◀──────────────────┐
                 │    └───┬──────┬───────┘                   │
                 │        │      │                            │
                 │   pause()    tick()                     resume()
                 │        │      │                            │
                 │        ▼      ▼                            │
                 │    ┌──────┐ ┌──────────────────────────┐  │
                 │    │Paused│ │ step(budget) →            │  │
                 │    └──────┘ │   · dequeue from queue    │──┤
                 │             │   · mark complete          │  │
                 │             │   · advance cursor         │  │
                 │             │   · produce refcount deltas│  │
                 │             └───────────┬───────────────┘  │
                 │                         │                   │
                 │                    ┌────▼──────┐            │
                 │                    │ Completed? │──No───────┘
                 │                    └────┬──────┘
                 │                         │ Yes
                 │                         ▼
                 │                    ┌──────────────────┐
                 │                    │     Retired       │
                 │                    │ (queue drained)   │
                 │                    └──────────────────┘
                 │
                 │    ┌──────────────────┐
                 └────│    Unhealthy      │
                      │ (consecutive      │
                      │  errors > N)      │
                      └──────────────────┘
```

**Lifecycle rules**:

1. `CleanupJob` is registered at scheduler start in `Paused` state.
2. The scheduler transitions to `Running` on first `plan_cycle()` if the cleanup queue is non-empty.
3. If `step()` returns `StepResult::Exhausted` (queue empty), the job transitions to `Retired` — it will be re-registered when a new work item is enqueued.
4. If `step()` returns an error for `max_consecutive_errors` (default: 5) consecutive ticks, the job transitions to `Unhealthy` — manual reset required.
5. `pause()` / `resume()` via admin protocol (`tidefs service pause cleanup`).

---

## 2. Data Structures

### 2.1 CleanupSchedulingState

Per-dataset scheduling metadata, stored alongside the cleanup queue B+tree root.

```rust
/// Scheduling metadata for a per-dataset cleanup job.
///
/// Persisted in `DatasetMetadataV1` alongside the cleanup queue root pointer.
/// Survives daemon restarts to preserve priority-boost state and backlog metrics.
pub struct CleanupSchedulingState {
    /// Number of pending work items in the cleanup queue.
    /// Updated atomically on enqueue (Phase 1) and dequeue (Phase 2).
    pub pending_count: u64,

    /// Sum of `bytes_to_free_estimate` across all pending work items.
    /// Provides a lower bound on physical space that will be reclaimed.
    pub pending_bytes_estimate: u64,

    /// Timestamp (monotonic ms) of the last tick that processed this queue.
    /// Used for starvation detection and backpressure signal freshness.
    pub last_tick_ms: u64,

    /// Whether this queue is currently boosted to `Critical` priority
    /// due to ENOSPC pressure.
    pub enospc_boosted: bool,

    /// The soft cap on pending work items (default: 10,000).
    /// When exceeded, the synchronous phase performs limited inline free
    /// (up to 64 extents) to reduce backlog.
    pub soft_cap: u64,

    /// Reserved for future use — aligned to 64 bytes.
    pub _reserved: [u8; 23],
}
// Total: 64 bytes (one cache line)
```

### 2.2 CleanupSchedulerAdapter

A scheduling wrapper that bridges `CleanupJob` (which implements `IncrementalJob`)
to the `BackgroundService` trait expected by `BackgroundScheduler`.

```rust
/// Adapter that wraps a `CleanupJob` for the background scheduler.
///
/// Responsible for:
///   - Translating `plan_cycle()` budget into `WorkBudget` for `step()`
///   - Detecting ENOSPC pressure and requesting priority boost
///   - Implementing the 10,000-item soft cap with limited inline free
///   - Tracking `phys_reclaimable_bytes` for admission control
pub struct CleanupSchedulerAdapter {
    /// The underlying cleanup job (Phase 3 IncrementalJob).
    pub job: CleanupJob,

    /// Scheduling state — persisted in DatasetMetadataV1.
    pub state: CleanupSchedulingState,

    /// Physical bytes reclaimable across all pending work items.
    /// Read from space accounting subsystem (#1215) each tick.
    pub phys_reclaimable_bytes: u64,

    /// Priority boost requested for the next tick.
    /// Reset to `None` after each `plan_cycle()`.
    pub requested_boost: Option<ServicePriority>,

    /// Consecutive error counter for unhealthy-state detection.
    pub consecutive_errors: u32,
}
```

### 2.3 Priority mapping

The `cleanup` service is registered at `Throughput` priority under normal conditions:

| Condition | Priority | Rationale |
|---|---|---|
| Normal operation (queue non‑empty) | `Throughput` | Cleanup is important but not latency‑sensitive; applications don't wait on it |
| Queue empty | `Retired` (no tick) | Nothing to do; re‑register on next enqueue |
| ENOSPC pressure (free space < 5%) | `Critical` | Space pressure demands aggressive reclamation |
| `pending_count > soft_cap * 2` | `LatencySensitive` | Backlog is growing faster than processing; boost before ENOSPC hits |
| Consecutive errors ≥ 5 | `Unhealthy` | Error loop; manual recovery required |

The `JobKind::DeferredCleanup` → `ServicePriority` mapping in
`ServicePriority::from_job_kind()` returns `Throughput` as the baseline.
Priority boosting overrides this mapping per‑tick via `CleanupSchedulerAdapter::requested_boost`.

---

## 3. Algorithms

### 3.1 Per‑tick scheduling algorithm

```
plan_cycle(global_budget: ServiceBudget, all_services: &[Box<dyn BackgroundService>]):

    // Step 0: Collect pressure signals
    for each dataset:
        free_pct = dataset.space_counters.free_bytes / dataset.space_counters.total_bytes
        if free_pct < 0.05:
            // ENOSPC pressure: boost cleanup to Critical
            cleanup_adapter.requested_boost = Some(Critical)
        else if cleanup_adapter.state.pending_count > cleanup_adapter.state.soft_cap * 2:
            // Backlog pressure: boost to LatencySensitive
            cleanup_adapter.requested_boost = Some(LatencySensitive)

    // Step 1: Assign effective priority per service
    for each service in all_services:
        if service is CleanupSchedulerAdapter:
            effective_priority = service.requested_boost
                .unwrap_or(ServicePriority::from_job_kind(JobKind::DeferredCleanup))
        else:
            effective_priority = service.base_priority

    // Step 2: Dispatch by priority stage (Critical → Opportunistic)
    remaining_budget = global_budget
    for stage in [Critical, LatencySensitive, Throughput, BestEffort, Opportunistic]:
        stage_services = services.filter(|s| s.effective_priority == stage)
        for service in round_robin(stage_services):
            if remaining_budget.is_exhausted():
                break
            tick_budget = min(service.base_budget, remaining_budget)
            report = service.tick(tick_budget)
            remaining_budget = remaining_budget.subtract(report.consumed)
            merge_tick_log(report)

    // Step 3: Budget cascading
    // Unused budget from higher stages cascades to the next stage.
    // Critical services always get their full budget; cascading starts
    // at LatencySensitive.
```

### 3.2 ENOSPC pressure detection and boosting

The scheduler evaluates ENOSPC pressure at the start of every `plan_cycle()` before
dispatching services. Pressure is detected from the space accounting subsystem (#1215):

```rust
fn detect_enospc_pressure(
    dataset_space: &DatasetSpaceCountersV1,
    cleanup_state: &CleanupSchedulingState,
) -> Option<ServicePriority> {
    let free_pct = dataset_space.free_bytes as f64
        / dataset_space.total_bytes.max(1) as f64;

    if free_pct < 0.02 {
        // Severe: <2% free — boost to Critical unconditionally
        Some(ServicePriority::Critical)
    } else if free_pct < 0.05 && cleanup_state.pending_bytes_estimate > 0 {
        // Moderate: 2–5% free with pending reclaimable work — boost to Critical
        Some(ServicePriority::Critical)
    } else if free_pct < 0.10 && cleanup_state.pending_bytes_estimate > 0 {
        // Mild: 5–10% free — boost to LatencySensitive
        Some(ServicePriority::LatencySensitive)
    } else {
        None
    }
}
```

**Boost duration**: The boost applies to the current tick only. Each tick re‑evaluates
pressure signals, preventing sustained boosting that would starve other services.

**Boost interaction with budget cascading**: When boosted to `Critical`, `CleanupJob`
receives `Critical`‑stage budget allocation and does not cascade unused budget to
lower stages until the boost is lifted (next tick re‑evaluation).

### 3.3 Admission control: soft cap and limited inline free

The `soft_cap` (default: 10,000) bounds the cleanup queue size. When the synchronous
phase (Phase 1) detects `pending_count >= soft_cap`, it performs a **limited inline
free** — freeing up to 64 extents synchronously — before enqueuing the work item.

```rust
fn enqueue_sync_phase(
    queue: &mut CleanupQueue,
    inode: &InodeV1,
    kind: WorkItemKind,
    cap: u64,
) -> Result<(), CleanupQueueError> {
    if queue.pending_count() >= cap {
        // Limited inline free: walk up to 64 extents, free them synchronously
        let freed = inline_free_extents(&inode.extent_map_root, 64)?;
        // Adjust logical accounting for the synchronously freed extents
        update_logical_counters(inode, freed);
        // If the inode still has extents after inline free, enqueue the rest
        if !inode.extent_map_is_empty() {
            queue.enqueue(CleanupWorkItemV1::new(inode, kind, /* truncated */))?;
        }
    } else {
        // Normal path: enqueue without synchronous iteration
        queue.enqueue(CleanupWorkItemV1::new(inode, kind, /* full extent range */))?;
    }
    Ok(())
}
```

**Rationale**: The 64‑extent inline free adds bounded latency (O(64) = constant)
while preventing unbounded queue growth. In pathological scenarios (e.g., `rm -rf`
of millions of small files), the cap prevents the cleanup queue B+tree from growing
to gigabytes. The inline‑free threshold is tunable via dataset property
`cleanup_inline_free_max_extents`.

### 3.4 Budget allocation per tick

The `CleanupJob` receives a `WorkBudget` on each tick. For the `Throughput` priority
stage, the default tick budget is:

```rust
pub const CLEANUP_DEFAULT_TICK: ServiceBudget = ServiceBudget {
    max_items: 256,        // Process up to 256 work items per tick
    max_bytes: 0,          // No byte limit (extent-map iteration is the bottleneck)
    max_duration_ms: 60,   // Cap at 60ms wall-clock time
};
```

When boosted to `Critical` under ENOSPC pressure, the budget expands:

```rust
pub const CLEANUP_CRITICAL_TICK: ServiceBudget = ServiceBudget {
    max_items: 1024,       // Aggressive processing under pressure
    max_bytes: 0,
    max_duration_ms: 200,  // Extended wall-clock budget under pressure
};
```

**Budget cascading**: When `CleanupJob` completes its tick before consuming the full
budget (e.g., queue is drained mid‑tick), the remaining items/ms cascade to the next
priority stage (`BestEffort`).

### 3.5 Backpressure and throttling

Under heavy foreground I/O load, the unified resource governor (#1241) may signal
`demand_pressure`. The scheduler reduces background budgets proportionally:

```
effective_budget = base_budget * (1.0 - demand_pressure)
```

For `CleanupJob`, when `demand_pressure > 0.8` (80% I/O saturation), the budget is
reduced to `SMALL_TICK` (16 items, 10ms) to minimize interference with application I/O.
If ENOSPC pressure is simultaneously detected, the `Critical` boost overrides the
backpressure reduction — space pressure takes precedence over I/O scheduling fairness.

### 3.6 Starvation prevention

`CleanupJob` at `Throughput` priority is subject to starvation from higher‑priority
services. The starvation tracker (`StarvationTracker` from Phase 12 of the background
service framework) monitors `last_tick_ms`:

- If `now - last_tick_ms > starvation_timeout_ms` (default: 60s), the service is
  considered starved.
- A starved `CleanupJob` receives a **starvation tick** at the end of the current
  cycle, outside the normal budget, processing up to 16 work items.
- Starvation ticks are logged with `starvation: true` in the `TickLog`.

**Interaction with ENOSPC boost**: If the job is boosted to `Critical` due to ENOSPC,
starvation is impossible — `Critical` services are dispatched first every cycle.

---

## 4. Tradeoffs

### 4.1 Throughput priority vs. Critical priority

| Tradeoff | Decision | Rationale |
|---|---|---|
| Default priority | `Throughput` | Cleanup is important but not latency‑sensitive. Applications never wait on deferred cleanup — they've already received `st_blocks` updates and `ENOSPC` is not returned. |
| ENOSPC boost target | `Critical` | When free space is below 5%, cleanup becomes correctness‑critical: if space is not reclaimed before the next allocation, the system returns `ENOSPC`. Boosting to `Critical` ensures cleanup runs ahead of new allocations. |
| Boost re‑evaluation | Per‑tick | Sustained Critical boosting would starve Scrub/Repair. Per‑tick re‑evaluation ensures the boost is only active while pressure persists. |

### 4.2 Synchronous inline free vs. deferred processing

| Tradeoff | Decision | Rationale |
|---|---|---|
| Soft cap trigger | 10,000 pending items | At this point the cleanup queue B+tree is ~1.3 MiB (10,000 × 128 bytes), acceptable on‑media overhead. |
| Inline free extent limit | 64 extents | O(64) = constant time; adds <1ms latency to syscall even on slow media. |
| Inline free bypass | Never bypassed when `pending_count ≥ soft_cap` | Simple policy; no heuristics to tune. The alternative — variable‑threshold inline free based on disk speed or I/O pressure — adds complexity without measurable benefit. |

### 4.3 Per‑dataset vs. global cleanup scheduling

| Tradeoff | Decision | Rationale |
|---|---|---|
| Scheduling scope | Per‑dataset `CleanupSchedulingState` | Datasets are independent. A dataset with 0 pending items should not consume scheduler cycles. |
| Global budget division | Proportional to `pending_bytes_estimate` | Datasets with more pending work receive proportionally more tick budget. Prevents one dataset's backlog from starving another's. |
| Round‑robin within priority stage | Yes | All `Throughput` services (CleanupJob instances + DataCleanerService) round‑robin within the stage. |

### 4.4 Dequeue ordering: FIFO vs. largest‑first

| Tradeoff | Decision | Rationale |
|---|---|---|
| Default ordering | FIFO (by `inode_id` + `kind` key) | Deterministic, starvation‑free, simple. |
| ENOSPC‑boost ordering | `bytes_to_free_estimate` descending | Under space pressure, maximize immediate reclaimed bytes. Administratively triggerable as "reclaim burst" mode. |
| Implementation | B+tree key ordering (FIFO) + optional secondary scan (largest‑first) | Secondary scan is a one‑time O(N) traversal of the queue to find the largest pending item; acceptable under ENOSPC when space is the bottleneck, not CPU. |

### 4.5 Admission control granularity

| Tradeoff | Decision | Rationale |
|---|---|---|
| Admission signal | `phys_reclaimable_bytes` from space accounting | Tracks actual physical bytes that will be freed, not logical `st_blocks` (which updates immediately). |
| Admission action | When `phys_reclaimable_bytes > free_space_reserve`, throttle new allocations | Prevents the allocator from consuming space that the cleanup worker will need for its own B+tree operations (refcount updates, locator table deletions). |
| Throttle mechanism | Allocator returns `AllocationError::RetryLater` with backoff | Non‑blocking; the FUSE daemon can serve reads during allocation backoff. |

---

## 5. Integration with the POSIX filesystem adapter

### 5.1 Daemon main loop integration

The `BackgroundScheduler` is integrated into the POSIX filesystem adapter daemon's
main loop at the COMMIT_GROUP commit boundary:

```
FUSE daemon main loop:
    while running:
        // 1. Service FUSE requests (foreground)
        fuse_session.receive_and_process(timeout=1ms)

        // 2. Open a new COMMIT_GROUP if needed
        if commit_group_should_open():
            commit_group_open()

        // 3. Process foreground writes through COMMIT_GROUP pipeline
        commit_group_process_foreground()

        // 4. COMMIT_GROUP commit
        commit_group_commit()

        // 5. Background scheduler tick (runs after COMMIT_GROUP commit)
        scheduler.plan_cycle(global_budget)

        // 6. Check for service state transitions
        scheduler.check_health()
```

**Key invariant**: The scheduler tick always runs after COMMIT_GROUP commit, ensuring that
work items enqueued by the synchronous phase (Step 1.2) are visible to the cleanup
job in the same cycle.

### 5.2 Interaction with COMMIT_GROUP sync

When the COMMIT_GROUP state machine initiates a sync (e.g., `fsync` or periodic commit_group_sync),
the scheduler reduces the background budget by 50% for the current cycle to avoid
competing with sync I/O. This reduction is applied after the ENOSPC boost check —
if ENOSPC is active, the reduction is overridden.

### 5.3 Threading model

The initial implementation runs the scheduler inline on the FUSE event loop thread
(single‑threaded). The `CleanupJob` is not `Send + Sync` at this stage. Multi‑threaded
work‑stealing (Phase 16 of the background service framework) will add concurrency
later, at which point `CleanupJob` will need `Send + Sync` bounds.

### 5.4 Per‑dataset service registration

Each dataset with a non‑empty cleanup queue registers one `CleanupSchedulerAdapter`
instance. On dataset creation, the adapter is registered in `Paused` state. On first
work‑item enqueue, the adapter transitions to `Running`. When the queue drains, the
adapter transitions to `Retired`.

```rust
// Pseudo-code for per-dataset lifecycle
fn on_dataset_mount(dataset: &DatasetV1) {
    let adapter = CleanupSchedulerAdapter::new(
        CleanupJob::new(dataset.cleanup_queue_root),
        load_scheduling_state(dataset.metadata),
    );
    scheduler.register(Box::new(adapter), ServicePriority::Throughput);
}

fn on_work_item_enqueued(dataset_id: DatasetId) {
    // If the adapter is Retired, transition to Running
    scheduler.resume_service(dataset_id);
}
```

---

## 6. Operator Visibility

### 6.1 Admin protocol commands

The `tidefs service` CLI provides operator visibility into cleanup scheduling:

```
tidefs service status cleanup [--dataset <name>]
    → Pending items, pending bytes, priority, last tick, consecutive errors

tidefs service pause cleanup --dataset <name>
    → Pause cleanup for a dataset (useful during maintenance)

tidefs service resume cleanup --dataset <name>
    → Resume cleanup after pause

tidefs service boost cleanup --dataset <name>
    → Manually boost to Critical for one cycle

tidefs service reclaim-burst --dataset <name>
    → Trigger largest-first reclamation pass
```

### 6.2 TickLog records

Each `CleanupJob` tick produces a `TickLog` record with:

| Field | Description |
|---|---|
| `service` | `"cleanup"` |
| `dataset_id` | Owning dataset |
| `priority` | Effective priority for this tick |
| `work_items_processed` | Number of items dequeued and completed |
| `extents_freed` | Number of individual extents whose refcount was decremented |
| `bytes_reclaimed_estimate` | Sum of `bytes_to_free_estimate` for completed items |
| `budget_consumed` | Items/ms consumed out of allocated budget |
| `queue_backlog` | Remaining pending items after tick |
| `enospc_boosted` | Whether ENOSPC boost was active |
| `starvation` | Whether this was a starvation‑prevention tick |

---


The xtask gate `tidefs-xtask check-deferred-cleanup-scheduling` verifies:

1. `CleanupSchedulingState` round‑trip: serialize → deserialize → assert equality
2. Priority mapping: `JobKind::DeferredCleanup` → `Throughput`; ENOSPC pressure → `Critical`
3. Budget allocation: `CLEANUP_DEFAULT_TICK` and `CLEANUP_CRITICAL_TICK` constants match spec
4. Soft cap: enqueue 10,001 items → 65th item triggers inline free (64 extents freed synchronously, then enqueue)
5. Starvation detection: no tick for 61s → starvation tick dispatched with 16 items
6. Admission control: `phys_reclaimable_bytes > free_space_reserve` → `AllocationError::RetryLater`
7. ENOSPC boost duration: boost applied for one tick, re‑evaluated next cycle
8. Budget cascading: unused CleanupJob budget flows to BestEffort stage
9. Crash safety: kill -9 mid‑tick → resume from last checkpoint cursor; no duplicate deltas
10. Deterministic trace: capture `TickLog` → replay → assert identical decisions

---

## 8. Dependencies and Sequencing

### 8.1 Prerequisites for Phase 7 wire‑up

The following must be closed before Phase 7 implementation begins:

| Issue | Description | Status |
|---|---|---|
| #1929 | Canonical deferred‑cleanup design spec | ✅ Finalized |
| #1992 | Background service framework coordination seal | ✅ Finalized |
| #1180 | Refcount delta queues | design‑spec |
| #1215 | Space accounting | design‑spec |
| #1191 | Extent‑map range delete (prerequisite for Phase 4) | design‑spec |
| #1239 | Incremental cursor framework | implemented |

### 8.2 Phase 7 wire‑up scope

The Phase 7 wire‑up issue will implement:

2. `CleanupSchedulerAdapter` bridging `CleanupJob` to `BackgroundService`
3. ENOSPC pressure detection and priority boosting in `plan_cycle()`
4. Soft cap (10,000) enforcement with limited inline free (64 extents)
5. Budget constants: `CLEANUP_DEFAULT_TICK`, `CLEANUP_CRITICAL_TICK`
6. Starvation detection and per‑dataset scheduling
7. Admission control via `phys_reclaimable_bytes`
8. Integration with FUSE daemon main loop
10. TickLog records for operator visibility

### 8.3 Write surfaces

This imported plan no longer uses the retired tracker-era status and
feature-matrix ledgers as Phase 7 update targets. Current status, evidence, and
documentation-authority changes live on the GitHub coordination surface and the
repo authority registers.

| Surface | Change |
|---|---|
| `crates/tidefs-cleanup-job-core/src/lib.rs` | Add `CleanupSchedulerAdapter`, budget constants |
| `crates/tidefs-types-deferred-cleanup-core/src/lib.rs` | Add `CleanupSchedulingState` |
| `crates/tidefs-background-scheduler/src/lib.rs` | Add ENOSPC pressure detection, priority boosting to `plan_cycle()` |
| `crates/tidefs-local-filesystem/src/lib.rs` | Wire `CleanupSchedulerAdapter` into per‑dataset lifecycle (serial write surface — requires claim) |
| active POSIX adapter runtime/daemon boundary | Integrate scheduling into the FUSE daemon main loop; the old standalone scheduler shard is not present |
| GitHub implementation issue and pull request | Record Phase 7 completion status, validation evidence, and residual risk on the live coordination surface |
| `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` | Classify this design through the documentation-authority workflow before citing it as current status |
| `docs/REVIEW_TODO_REGISTER.md` | Add a TFR entry only if Phase 7 leaves durable cleanup-scheduling review debt |

---

## 9. Residual Risk

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| ENOSPC boost starvation of Scrub/Repair | Low | Medium | Per‑tick re‑evaluation prevents sustained boost; Critical services always dispatch first even when CleanupJob is boosted |
| Soft cap inline free adds measurable latency | Low | Low | 64 extents is O(1); measured <1ms on NVMe, <5ms on HDD |
| Admission control blocks foreground allocations | Low | High | `RetryLater` is non‑blocking; the allocator retries on next FUSE request |
| Per‑dataset scheduling causes imbalance | Low | Medium | Budget proportional to `pending_bytes_estimate`; small‑backlog datasets receive proportionally less budget |
| Starvation timeout too aggressive | Medium | Low | Default 60s is tunable; starvation tick is small (16 items) |

---

## 10. References

- [#1929] Canonical deferred‑cleanup design spec — `docs/design/deferred-cleanup-work-queues.md`
- [#1992] Background service framework coordination seal — `docs/design/background-service-framework-coordination-confirmed.md`
- [#1673] 16‑phase background service roadmap — `docs/design/background-service-framework-design-spec.md`
- [#1592] Canonical background service design — `docs/design/background-service-framework-design.md`
- [#1180] Refcount delta cleanup queues — `docs/REFCOUNT_DELTA_CLEANUP_QUEUES_DESIGN.md`
- [#1215] Space accounting — `docs/SPACE_ACCOUNTING_MODEL_DESIGN.md`
- [#1212] Original deferred cleanup design — `docs/DEFERRED_CLEANUP_WORK_QUEUES_DESIGN.md`
- [#1241] Unified lane scheduling — `docs/design/unified-scheduling-classes-lane-priority-model.md`
- [#1267] COMMIT_GROUP state machine — `docs/design/canonical-commit-ordering-commit_group-state-machine.md`
- `crates/tidefs-cleanup-job-core/src/lib.rs` — Phase 3 CleanupJob implementation
- `crates/tidefs-background-scheduler/src/lib.rs` — Scheduler implementation
- `crates/tidefs-types-deferred-cleanup-core/src/lib.rs` — Phase 1 types
- `crates/tidefs-cleanup-queue-core/src/lib.rs` — Phase 2 queue implementation
- `crates/tidefs-types-incremental-job-core/src/lib.rs` — IncrementalJob trait
