# Background Service Framework Design (#1592, #1674, #1673, #1877, #1859, #1858, #1980, #1991, #2028, #2001, #2067)

Maturity: **design-spec** for the unified background service framework: tick-driven
scheduler, per-tick budget enforcement, 5-stage priority dispatch, round-robin
fairness, validity-token stale-task prevention, derived catalog lifecycle, incremental
compaction, and service observability.
This document closes Forgejo issues #1592, #1674, #1673, #1858, #1980, #1991, #2028, #2001, and #2067 (coordination seals).
Issue #1877 tracks the deferred Rust implementation wire-up for phases 5–10.

This document formalizes the design specification first developed in #1179
(`docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md`) and refined through implementation
in `crates/tidefs-background-scheduler/` and the `IncrementalJob` trait system
(`crates/tidefs-types-incremental-job-core/`). It serves as the canonical reference
for all background-service wire-up issues.

Claim boundary: this document records background-service design requirements,
implemented-scope status, and incumbent design inputs. It is not evidence that
TideFS currently has lower latency, better throughput isolation, stronger crash
recovery, or better operator visibility than ZFS, Ceph, or other filesystems.
Product-facing incumbent comparisons must be handled through #875 with
#928/#930 comparator evidence for the exact implementation, workload, and
storage class.

## 1. Problem Statement

A storage system running in userspace must perform continuous background maintenance:
scrubbing checksums, reclaiming freed space, compacting B-trees, rebuilding derived
views, cleaning dead segments, and evaluating snapshot retention policies. In the
absence of a unified framework, each subsystem invents its own throttling, progress
tracking, and scheduling — producing inconsistent behavior under load and opaque
operator visibility.

The current codebase (pre-#1179) exhibited exactly this pattern:

| Subsystem | Scheduling mechanism | Throttling |
|-----------|---------------------|------------|
| Block-level scrub | Ad-hoc scan loop | None |
| Repair | Triggered by scrub | None |
| Crash recovery | Mount-time audit | None |
| FUSE daemon background | Inline loops | None |

A unified background service framework is required by at least 12 dependent designs:

| Dependent design | Background service needed |
|-----------------|--------------------------|
| #1176 Cached directory/index views | View builder service |
| #1180 Refcount delta cleanup queues | Data cleaner service |
| #1249 Erasure coding and placement | Scrub + repair services |
| #1222 Rebake architecture | Rebake conversion service |
| #1215 Space accounting and cleaner scheduling | Segment cleaner service |
| Snapshot retention | Retention evaluation service |
| #1241 Unified lane scheduling | Background lane budget integration |
| #1459 Reclaim queue | BackgroundReclaim service |
| #1463 Reclaim delta recording | Delta processing in background tick |
| #1223 Polymorphic extent maps | Extent compaction service |
| Online defrag/compaction | B-tree compaction service |
| Orphan recovery | Orphan recovery service |

## 2. Design Overview

The framework introduces four core abstractions connected by a tick-driven scheduling
loop:

```
┌──────────────────────────────────────────────────────────┐
│                    BackgroundScheduler                    │
│  ┌─────────┐  ┌──────────┐  ┌───────────┐  ┌──────────┐ │
│  │ Critical │→│LatencySen│→│Throughput │→│BestEffort│ │ │
│  │  (40%)   │  │  (30%)   │  │  (15%)    │  │  (10%)   │ │ │
│  └─────────┘  └──────────┘  └───────────┘  └──────────┘ │
│                                        ↓                 │
│                                ┌──────────────┐          │
│                                │Opportunistic │          │
│                                │    (5%)      │          │
│                                └──────────────┘          │
│                                                          │
│  Global Budget: ServiceBudget (reads, writes, ops)       │
│  Round-robin cursor per stage                            │
│  Cascading unused budget                                 │
└──────────────────────────────────────────────────────────┘
```

### 2.1 Core Abstractions

| Abstraction | Responsibility |
|-------------|---------------|
| `BackgroundService` trait | Defines one service: name, priority, tick execution with budget, work-pending query |
| `ServiceBudget` | Per-tick resource limits: max items, max bytes, max milliseconds |
| `TickReport` | Per-tick accounting: processed, skipped, errored, resources consumed, has-more flag |
| `BackgroundScheduler` | Priority-ordered dispatch across services, global budget split, cascading, observability aggregation |

### 2.2 Integration with IncrementalJob

The `BackgroundService` trait is paired with an `IncrementalJobAdapter` that wraps any
`IncrementalJob` implementor (from `tidefs-types-incremental-job-core`). This bridges
the universal incremental cursor contract with the priority-driven background scheduler:

```
BackgroundScheduler
  ├── IncrementalJobAdapter<CleanupJob>        (Throughput)
  ├── IncrementalJobAdapter<ReclaimJob>         (Throughput)
  ├── IncrementalJobAdapter<OrphanRecoveryJob>  (LatencySensitive)
  ├── IncrementalJobAdapter<RebakeJob>          (Throughput → Critical escalation)
  ├── IncrementalJobAdapter<ScrubJob>           (Critical)
  └── …
```

### 2.3 Deterministic Contract

All `BackgroundService` implementations must be deterministic: given the same state and
the same budget, the same tick must produce the same `TickReport`. This enables:
  behavior
- **Deterministic simnet testing**: cluster-wide simulation with identical background
  outcomes per seed
  can inject faults at background service state transitions and verify recovery

## 3. Core Types

### 3.1 ServicePriority

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ServicePriority {
    Critical = 0,          // Authority/consistency: repair, intent-log sync
    LatencySensitive = 1,  // Cache maintenance: directory view building
    Throughput = 2,        // Bulk data work: data cleaning, rebake, reclaim
    BestEffort = 3,        // Compaction/trim: segment compaction, tombstone GC
    Opportunistic = 4,     // Speculative: prefetch, readahead, thermal rebalance
}
```

Priority determines both dispatch order (higher priorities drain first) and budget
allocation weight. Services are dispatched strictly in priority order — no lower-priority
service runs until all higher-priority services with pending work have been offered a tick.

Budget allocation weights per stage:

| Priority | Weight | Rationale |
|----------|--------|-----------|
| Critical | 0.40 | Authority work must make steady progress; capped to leave room for others |
| LatencySensitive | 0.30 | Cache maintenance has high user-visible ROI |
| Throughput | 0.15 | Bulk work is important but deferrable |
| BestEffort | 0.10 | Compaction trims need slow, steady progress |
| Opportunistic | 0.05 | Never starve, but never compete with real work |

Weights are configurable via pool properties. Priority escalation is supported:
for example, `RebakeService` escalates from Throughput to Critical when durability
drops below the warning threshold (durability ladder from #1222).

### 3.2 ServiceBudget

```rust
pub struct ServiceBudget {
    pub max_items: u64,   // Max operations (authoritative reads, derived writes) per tick
    pub max_bytes: u64,   // Max bytes transferred per tick
    pub max_ms: u64,      // Max tick wall-clock duration (soft bound)
}
```

Predefined budgets:

| Constant | Items | Bytes | MS | Use case |
|----------|-------|-------|-----|----------|
| `DEFAULT_TICK` | 1024 | 64 MiB | 100 | Normal background cycle |
| `MAINTENANCE_TICK` | 256 | 16 MiB | 50 | Between demand ops in FUSE loop |
| `SMALL_TICK` | 64 | 4 MiB | 25 | Emergency pressure, low-memory mode |

Budget is enforced strictly — a service must not exceed any dimension. A 1-item grace
period allows finishing an in-progress item when budget hits zero mid-operation.

### 3.3 TickReport

```rust
pub struct TickReport {
    pub processed: u64,       // Items successfully processed this tick
    pub skipped: u64,         // Items skipped (stale token, already done, no-op)
    pub errors: u64,          // Items that produced errors
    pub items_consumed: u64,  // Items consumed from budget
    pub bytes_consumed: u64,  // Bytes consumed from budget
    pub has_more: bool,       // True if service reports more pending work
}
```

The sum `processed + skipped + errors` is bounded by `items_consumed`. The `has_more`
flag determines whether the scheduler will offer this service another tick in the
current cycle (if budget remains and round-robin fairness permits).

### 3.4 CycleReport

```rust
pub struct CycleReport {
    pub services_ran: usize,              // Number of services that ran ≥1 tick
    pub services_skipped: usize,          // Services skipped (idle or no budget)
    pub budget_exhausted: bool,           // Budget fully consumed
    pub remaining_budget: ServiceBudget,  // Unconsumed budget after cycle
    pub total_processed: u64,             // Sum of all service TickReport.processed
    pub total_skipped: u64,               // Sum of all TickReport.skipped
    pub total_errors: u64,                // Sum of all TickReport.errors
    pub wall_ms: u64,                     // Wall-clock duration of the cycle
}
```

## 4. BackgroundService Trait

```rust
pub trait BackgroundService: Send {
    /// Unique name for metrics, scheduling, and operator visibility.
    fn name(&self) -> &'static str;

    /// Priority class determining scheduling order and budget preference.
    fn priority(&self) -> ServicePriority;

    /// Run one tick within the given budget.
    ///
    /// Returns a TickReport with accounting. The service must not exceed
    /// the budget in any dimension. It may use less.
    ///
    /// # Determinism
    /// Given the same state and budget, this must produce the same TickReport.
    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError>;

    /// Whether this service has pending work. Used by the scheduler to
    /// skip idle services without calling tick().
    fn has_work(&self) -> bool;
}
```

### 4.1 IncrementalJobAdapter

The `IncrementalJobAdapter<J: IncrementalJob>` bridges the `BackgroundService` trait
with the cursor-driven `IncrementalJob` contract:

```rust
pub struct IncrementalJobAdapter<J: IncrementalJob> {
    name: &'static str,
    job: J,
    tick_count: u64,
    // … internal tracking
}

impl<J: IncrementalJob> BackgroundService for IncrementalJobAdapter<J> {
    fn name(&self) -> &'static str { self.name }

    fn priority(&self) -> ServicePriority {
        // Maps JobKind to ServicePriority per the 5-stage model:
        // Scrub, DeepScrub             → Critical
        // OrphanRecovery, Reclaim      → LatencySensitive
        // DeferredCleanup, Rebake, …   → Throughput
        // BtreeCompaction, GCMark      → BestEffort
        // AdminJob                     → Throughput (default)
        ServicePriority::for_job_kind(self.job.job_kind())
    }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        let work_budget = WorkBudget::from_service_budget(budget);
        let mut report = TickReport::default();

        while !work_budget.exhausted() && self.job.progress() != JobProgress::Complete {
            match self.job.step(&work_budget) {
                StepResult::Advanced { .. } => report.processed += 1,
                StepResult::Skipped { .. } => report.skipped += 1,
                StepResult::Error(err) => report.errors += 1,
                // …
            }
        }

        report.has_more = self.job.progress() != JobProgress::Complete;
        Ok(report)
    }

    fn has_work(&self) -> bool {
        self.job.progress() != JobProgress::Complete
    }
}
```

## 5. Scheduling Algorithm

### 5.1 Cycle Entry Points

The scheduler is called from two contexts:

1. **Dedicated background cycle** (when demand is idle): runs with `DEFAULT_TICK` budget,
   triggered by a timer (`BACKGROUND_CYCLE_INTERVAL_MS` = 100ms default).

2. **Interstitial tick** (between demand operations): runs with `MAINTENANCE_TICK` budget
   when the FUSE daemon has no pending demand work and the background timer has elapsed.

```
FUSE daemon main loop:
    loop:
        if demand_ops_ready():
            process_one_demand_op()
        else if background_timer_elapsed():
            scheduler.run_cycle(max_budget: MAINTENANCE_TICK)
        else:
            wait_for_events()
```

### 5.2 run_cycle() Algorithm

```
run_cycle(global_budget):
    remaining = global_budget.clone()
    cycle_report = CycleReport::default()

    // COMMIT_GROUP tick: sync if timer expired, bounded single decision
    commit_group.tick()

    for priority in [Critical .. Opportunistic]:
        eligible = services.filter(s.priority() == priority AND s.has_work())
        if eligible.empty(): continue

        budget_per_service = remaining.fraction(1, eligible.len())
        stage_budget = remaining.fraction(stage_weight[priority], 1)

        for service in round_robin(eligible, last_cursor):
            if stage_budget.exhausted(): break

            tick_budget = min(budget_per_service, stage_budget)
            report = service.tick(tick_budget)

            stage_budget.subtract(report)
            remaining.subtract(report)
            cycle_report.merge(report)

            if report.has_more:
                reinsert_for_another_round(service)

        advance_cursor()

    cycle_report.wall_ms = elapsed()
    cycle_report.remaining_budget = remaining
    return cycle_report
```

### 5.3 Key Algorithmic Properties

1. **Strict priority ordering**: All Critical services drain before any LatencySensitive
   service runs. This prevents cache maintenance from delaying integrity repair.

2. **Round-robin fairness**: Services at the same priority level trade off via a rotating
   cursor. If service A processes 50 items and service B has 1000 pending, A gets a tick,
   then B gets a tick, then A, then B — preventing starvation.

3. **Budget cascading**: Unused budget from higher priorities cascades to lower priorities.
   If no Critical service has work, the full budget is available for LatencySensitive and
   below. This maximizes resource utilization.

4. **Budget exhaustion**: When `remaining` hits zero in any dimension, the cycle terminates
   early for all lower-priority services. A cycle that fully consumes budget increments the
   `budget_exhausted` counter for observability.

5. **Stage-level budget caps**: Even with cascading, each stage is capped at its weight
   fraction. A runaway LatencySensitive workload cannot consume 100% of the global budget
   if Critical work appears mid-cycle — it's limited to 30%.

### 5.4 Demand Preemption

Background ticks must never starve demand (foreground) I/O. The scheduler is designed
to be called between demand operations with a small budget:

- `MAINTENANCE_TICK` (256 items, 16 MiB, 50ms) ensures a single background cycle never
  blocks demand for more than a bounded time.
- The FUSE daemon main loop alternates: process one demand op, then one background tick
  (if timer elapsed), then poll for more demand.
- Under sustained demand, background ticks may be deferred indefinitely. This is correct:
  all background work is resumable via cursor state.

## 6. Validity Token Mechanism

### 6.1 Problem

When a background service schedules work (e.g., "build directory view for inode 42"),
the authoritative state may change before the tick executes. Without a validity check,
the service wastes I/O building a view that is immediately stale.

### 6.2 ValidityToken

```rust
/// Opaque token proving a task is still valid at execution time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidityToken(pub u64);
```

Tokens derive from mutation counters on authoritative state (inode mutation counter,
extent map generation number, etc.). At schedule time, the token is captured; at
execution time, the current token is re-derived. If they differ, the task is stale
and skipped.

### 6.3 Skip Semantics

A skipped task is reported in `TickReport.skipped` and does not count against the
- **Idempotency**: scheduling the same work twice (before and after a mutation) results
  in at most one execution.
- **Bounded waste**: maximum wasted work is one tick's budget, not unbounded rework.
- **Determinism**: token derivation from authoritative state is deterministic, enabling

## 7. Derived Catalog Lifecycle

### 7.1 Concept

Views (directory listings, hierarchy manifests, path-lookup maps) are stored in a
**derived catalog** B-tree, separate from the authoritative dataset catalog. The
derived catalog is reachable via a dedicated root pointer in dataset metadata:

```
Dataset metadata:
    authoritative_catalog_ptr  → B-tree of inodes + extents
    derived_catalog_ptr        → B-tree of views + manifests
```

### 7.2 Lifecycle: Build → Serve → Evict → Compact

**Build**: The view builder service constructs a view from authoritative state, encodes
it, and stores it in the derived catalog with a composite key `(view_type: u8, dataset_id: u64, inode_id: u64)`.
The encoded view includes the validity token at build time.

**Serve**: FUSE path resolution checks the derived catalog first. If a view exists and
its token matches the current authoritative state, the view is served from cache. If
token mismatches, the view is evicted and served from authoritative state (with lazy
background rebuild scheduled).

**Evict**: When `derived_bytes_total` exceeds `derived_bytes_budget_per_pool` (default
5% of pool size), the scheduler evicts views by LRU. Eviction writes a tombstone (empty
value) to the derived catalog B-tree.

**Compact**: A compaction pass scans the derived catalog for tombstones and removes them,
copying live entries to a new B-tree root. Compaction is incremental — configurable scan
items per tick, resumable via a `compaction_cursor`. The same B-tree code as the
authoritative catalog is reused, with larger node sizes for write-heavy workloads.

## 8. Service Lifecycle and Error Handling

### 8.1 Service States

```
    ┌──────────┐    register()    ┌──────────┐
    │  Pending  │ ───────────────→│  Active   │
    └──────────┘                  └─────┬─────┘
                                        │
                          ┌─────────────┼─────────────┐
                          ↓             ↓             ↓
                    ┌──────────┐  ┌──────────┐  ┌──────────┐
                    │  Idle    │  │  Error   │  │ Stopped  │
                    │(no work) │  │(unhealthy│  │(shutdown)│
                    └──────────┘  └──────────┘  └──────────┘
```

Services transition between these states:
- **Pending** → **Active**: after `register()` and first `run_cycle()`
- **Active** → **Idle**: `has_work()` returns false; service stays registered but skipped
- **Active** → **Error**: a non-recoverable `ServiceError::Internal` occurs; service
  marked unhealthy, skipped in future cycles, operator alert emitted
- **Active** → **Stopped**: daemon shutdown or drain; all services receive `Stopped` signal

### 8.2 Error Hierarchy

```rust
pub enum ServiceError {
    BudgetExceeded {
        dimension: &'static str,
        limit: u64,
        actual: u64,
    },
    Internal {
        service: &'static str,
        message: String,
    },
    Stopped,
}

pub enum SchedulerError {
    RegistrationFailed {
        service_name: &'static str,
        reason: String,
    },
    ServiceFailed {
        service_name: &'static str,
        error: ServiceError,
    },
    BudgetViolation {
        service_name: &'static str,
        budget: ServiceBudget,
        consumed: TickReport,
    },
}
```

### 8.3 Panic Safety

A panicking service must not crash the daemon. The scheduler catches panics per-tick
(via `std::panic::catch_unwind`), marks the service as unhealthy, emits an observability
event, and continues scheduling other services.

## 9. Existing Services

### 9.1 Implemented Services

| Service | Priority | Crate | Description |
|---------|----------|-------|-------------|
| BackgroundReclaim | Throughput | `tidefs-local-filesystem` | Processes reclaim queue entries in deterministic ObjectKey order, 256-entry batch cap, cursor-resumable |
| CleanupJob | Throughput → Critical (ENOSPC) | `tidefs-cleanup-job-core` | Deferred refcount-delta cleanup, feeds ReclaimQueue entries |
| OrphanRecoveryJob | LatencySensitive | `tidefs-orphan-recovery-job-core` | Recovers orphaned inodes after crash, reconciles nlink counts |
| ReclaimJob | Throughput | `tidefs-reclaim-job-core` | Background reclamation of freed content-object pages |

### 9.2 Design-Spec Services (Wire-Up Pending)

| Service | Priority | Description |
|---------|----------|-------------|
| ViewBuilderService | LatencySensitive | Builds derived catalog views (directory listings, path-lookup maps) |
| DataCleanerService | Throughput | Processes refcount delta queues from #1180 |
| SegmentCleanerService | BestEffort | Reclaims dead segments after rebake completes |
| ScrubService | Critical | Block-level checksum verification |
| RepairService | Critical | Corruption resolution from scrub findings |
| RebakeService | Throughput → Critical | Converts ingest shards to base shards with durability escalation |
| CompactionService | BestEffort | Incremental B-tree compaction (derived catalog, refcount tree) |
| RetentionEvalService | BestEffort | Evaluates snapshot retention policies |

### 9.3 Priority Escalation

Services can escalate priority based on system conditions:

- **ENOSPC pressure**: `CleanupJob` escalates from Throughput to Critical
- **Durability ladder**: `RebakeService` escalates from Throughput to Critical when
  replica count drops below the warning threshold
- **Starvation override**: If any Throughput or BestEffort service has been starved for
  `starvation_timeout_ms` (default 60s), it receives at least one tick before lower
  priorities. This integrates with the unified lane scheduling model (#1241).

## 10. Observability

### 10.1 Per-Service Counters

Each service exposes the following counters, aggregated per-cycle and per-lifetime:

| Counter | Type | Description |
|---------|------|-------------|
| `tick_count` | Monotonic | Total ticks executed |
| `items_processed` | Monotonic | Items successfully processed |
| `items_skipped` | Monotonic | Items skipped (stale token, no-op) |
| `items_errored` | Monotonic | Items that produced errors |
| `budget_items_consumed` | Monotonic | Items consumed from budget |
| `budget_bytes_consumed` | Monotonic | Bytes consumed from budget |
| `cycles_idle` | Monotonic | Cycles where service had no work |
| `panics` | Monotonic | Tick panics caught |

### 10.2 Scheduler-Level Aggregates

| Counter | Type | Description |
|---------|------|-------------|
| `total_cycles` | Monotonic | Full scheduling cycles completed |
| `total_ticks` | Monotonic | Total service ticks across all services |
| `total_processed` | Monotonic | Sum of all service items processed |
| `budget_exhausted_cycles` | Monotonic | Cycles where budget was fully consumed |
| `idle_cycles` | Monotonic | Cycles where no service had work |
| `panicked_services` | Gauge | Count of services currently unhealthy |

### 10.3 Operator Interface

The `tidefsctl background` command exposes:

```
tidefsctl background status     — Per-service and aggregate stats
tidefsctl background pause <S>  — Pause a service (graceful, finish current tick)
tidefsctl background resume <S> — Resume a paused service
tidefsctl background budget     — Show and adjust global budget parameters
```


## 11. Pool Properties and Configuration

All tunable parameters in the background service framework are exposed through
per-pool properties with namespaced keys, following the TideFS property framework
convention. This enables per-pool tuning without recompilation and allows operators
to adjust scheduling behavior at runtime via `tidefsctl pool set`.

### 11.1 Global Scheduler Properties

| Property key | Type | Default | Range | Description |
|-------------|------|---------|-------|-------------|
| `background.tick.max_items` | u64 | 1024 | 64–65536 | Global max items per tick cycle |
| `background.tick.max_bytes` | u64 | 67108864 (64 MiB) | 1 MiB–1 GiB | Global max bytes per tick cycle |
| `background.tick.max_ms` | u64 | 100 | 10–500 | Global max wall-clock ms per cycle (soft) |
| `background.cycle_interval_ms` | u64 | 100 | 10–1000 | Interval between dedicated background cycles |
| `background.maintenance.max_items` | u64 | 256 | 16–16384 | Max items per inter-demand maintenance tick |
| `background.maintenance.max_bytes` | u64 | 16777216 (16 MiB) | 256 KiB–256 MiB | Max bytes per inter-demand maintenance tick |
| `background.maintenance.max_ms` | u64 | 50 | 5–200 | Max ms per inter-demand maintenance tick |

### 11.2 Per-Stage Budget Weights

Weights determine the fraction of the remaining global budget allocated to each
priority stage. Weights sum to 1.0; the scheduler normalizes if the sum differs.

| Property key | Type | Default | Range | Description |
|-------------|------|---------|-------|-------------|
| `background.weight.critical` | f64 | 0.40 | 0.10–0.70 | Budget fraction for Critical stage |
| `background.weight.latency_sensitive` | f64 | 0.30 | 0.10–0.50 | Budget fraction for LatencySensitive stage |
| `background.weight.throughput` | f64 | 0.15 | 0.05–0.40 | Budget fraction for Throughput stage |
| `background.weight.best_effort` | f64 | 0.10 | 0.02–0.30 | Budget fraction for BestEffort stage |
| `background.weight.opportunistic` | f64 | 0.05 | 0.01–0.20 | Budget fraction for Opportunistic stage |

### 11.3 Priority Escalation Triggers

| Property key | Type | Default | Range | Description |
|-------------|------|---------|-------|-------------|
| `background.escalation.enospc` | bool | true | — | Escalate cleanup jobs on ENOSPC pressure |
| `background.escalation.durability_warn_threshold` | u8 | 2 | 1–254 | Replica count below which rebake escalates to Critical |
| `background.starvation.timeout_ms` | u64 | 60000 | 5000–600000 | Time before starved service receives forced tick |

### 11.4 Per-Service Properties

Each registered `BackgroundService` contributes a property namespace under
`background.service.<name>.`. The scheduler forwards these to the service at
registration time. Services may define their own properties:

| Property key | Type | Default | Description |
|-------------|------|---------|-------------|
| `background.service.<name>.enabled` | bool | true | Enable/disable this service |
| `background.service.<name>.batch_size` | u64 | varies | Items per internal batch within a tick |
| `background.service.<name>.priority_override` | string | "" | Override the service's compile-time priority (empty = use default) |

### 11.5 Derived Catalog Properties

| Property key | Type | Default | Range | Description |
|-------------|------|---------|-------|-------------|
| `background.derived.bytes_budget_fraction` | f64 | 0.05 | 0.01–0.25 | Fraction of pool size for derived catalog storage |
| `background.derived.node_size` | u32 | 16384 | 4096–65536 | Derived catalog B-tree node size in bytes |
| `background.derived.compact_items_per_tick` | u64 | 512 | 64–4096 | Tombstone scan items per compaction tick |
| `background.derived.evict_batch` | u64 | 64 | 16–512 | LRU eviction batch size when budget exceeded |
| `background.derived.persist_views` | bool | true | — | Persist derived views across daemon restarts |

### 11.6 Runtime Adjustment

Properties changed via `tidefsctl pool set` take effect at the start of the next
tick cycle. The scheduler reads current property values from the pool property
store at the beginning of each `run_cycle()` call. This ensures:

- **Atomicity**: changes apply between cycles, never mid-tick.
- **Predictability**: the operator can observe the active configuration via
  `tidefsctl pool get` and know exactly which cycle will use which values.
- **No hot-reload races**: property reads are cheap (a few atomic loads) and
  do not require locks.


unit tests, integration tests, deterministic replay, and chaos campaigns.

### 12.1 Unit Tests (in-crate, `#[cfg(test)]`)

| Test category | Scope | Example |
|--------------|-------|---------|
| Type-level invariants | `ServicePriority` ordering, `ServiceBudget` fraction arithmetic | `priority_ordering_is_total()` |
| Budget math | Budget subtraction, exhaustion detection, fraction splitting | `budget_exhausted_when_any_dimension_zero()` |
| TickReport aggregation | Merge semantics, total_attempted = processed + skipped + errors | `merge_preserves_sum_invariant()` |
| Adapter logic | `IncrementalJobAdapter` tick loop termination, has_work delegation | `adapter_stops_when_budget_exhausted()` |
| ValidityToken | Token equality, derivation-from-mutation-counter determinism | `token_unchanged_when_no_mutation()` |

### 12.2 Integration Tests (per-service, `#[cfg(test)]` with harness)

|------|------------------|
| `background_service_determinism` | Same state + same budget = same TickReport |
| `budget_enforcement_strict` | Service never exceeds ServiceBudget in items, bytes, or duration |
| `crash_resume_cursor` | After simulated crash, job resumes from persisted Checkpoint cursor |
| `priority_ordering` | Critical services drain before LatencySensitive; lower priorities starved when budget exhausted |
| `round_robin_fairness` | Two services at same priority each get at least one tick before either gets two |
| `budget_cascading` | Unused Critical budget flows to LatencySensitive; idle stages pass full budget down |
| `starvation_override` | BestEffort service starved for >60s receives at least one tick |
| `priority_escalation_enospc` | CleanupJob priority escalates to Critical under simulated ENOSPC |
| `panic_isolation` | A panicking service is isolated; other services continue in subsequent ticks |
| `validity_token_skip` | Stale-validity-token tasks are skipped and counted in TickReport.skipped |
| `derived_catalog_evict_compact` | Build → evict (tombstone) → compact (removal) lifecycle is crash-consistent |

### 12.3 Deterministic Trace Oracle

uses the deterministic trace oracle to:

1. Record the exact sequence of `tick()` calls, budgets, and `TickReport` values
   from a golden run.
2. Replay the same workload with the same random seed.
3. Assert bitwise-identical `TickReport` sequences.

This catches non-determinism bugs (e.g., HashMap iteration order leaking into
tick scheduling) before they reach production.

### 12.4 Chaos Corruption Campaigns

Chaos tests inject faults at specific points in the scheduling loop:

| Injection point | Expected behavior |
|----------------|------------------|
| Mid-tick crash (kill -9) | Resume from checkpoint, no duplicate processing |
| Disk I/O error during tick | ServiceError::Internal, service marked unhealthy |
| Budget dimension zeros mid-tick | 1-item grace period, then tick terminates |
| Registration during active cycle | New service queued for next cycle, no mid-cycle modification |
| Concurrent property change | Change visible at next cycle start, no torn reads |

### 12.5 Performance Regression Gates

These gates are acceptance targets for scheduler validation. They are not
benchmark evidence and do not support product-facing latency or throughput
claims until backed by recorded validation artifacts for the exact branch,
configuration, workload, and storage class.

| Gate | Threshold | Description |
|------|-----------|-------------|
| `tick_latency_p99_us` | ≤ 5000 µs | P99 wall-clock duration of a single service tick under DEFAULT_TICK |
| `cycle_latency_p99_us` | ≤ 50000 µs | P99 wall-clock duration of a full run_cycle() under DEFAULT_TICK |
| `demand_blocking_max_us` | ≤ 1000 µs | Maximum time a MAINTENANCE_TICK blocks demand processing |
| `memory_overhead_per_service` | ≤ 256 bytes | Per-service scheduler metadata (excl. service-owned state) |


## 13. Design-input comparison: ZFS, Ceph, and TideFS

This table classifies scheduler-shape differences as design input. The TideFS
column describes the design target or implemented-scope abstraction in this
document; it is not a current operational superiority, cost, or bounded-latency
claim.

| Dimension | ZFS | Ceph | TideFS |
|-----------|-----|------|--------|
| **Scheduling model** | Ad-hoc scan tickets + `spa_sync` callbacks | Per-PG state machines | Unified tick-driven scheduler |
| **Budget** | Delay-based throttling (`zfs_scan_idle`, `zfs_resilver_delay`) | Sleep-based (`osd_recovery_sleep`, `osd_max_backfills`) | Per-tick operation-count caps |
| **Priority** | No priority model; scrub/resilver use separate code paths | Per-PG priority, no cluster-wide ordering | 5-stage priority with round-robin fairness |
| **Fairness** | No fairness guarantee; resilver dominates I/O | Per-PG with configurable max_backfills | Round-robin within stage, budget cascading |
| **Stale-task prevention** | N/A (operations are synchronous or idempotent) | N/A (PG state machines track their own state) | ValidityToken from mutation counters |
| **Derived cache** | ARC/FlashTier (data only, no views) | N/A | Persistent derived catalog B-tree with build/serve/evict/compact lifecycle |
| **Compaction** | ZFS metaslab compaction runs in spa_sync path | RocksDB compaction (background, per-OSD) | Incremental B-tree compaction with cursor-resumable scanning |

Key architectural target: TideFS should keep background work behind one budget,
one stale-task prevention model, and one derived-catalog lifecycle instead of
letting each service grow a separate throttling and visibility mechanism. This
is a design lesson, not proof that current TideFS deployments outperform the
disjoint incumbent mechanisms.

## 14. Tradeoffs and Design Decisions

### 14.1 Inline vs. Dedicated Thread

**Decision: Inline scheduling** (called from daemon event loop).

- **Pro**: Simplifies synchronization — no mutexes on shared state, no thread-safety
  concerns for no_std services.
- **Con**: A slow service tick blocks demand processing for the tick duration.
- **Mitigation**: `MAINTENANCE_TICK` caps tick duration at 50ms; services must
  self-limit to stay within budget.

Future: If tail latency measurements show >1ms additional P99 from background ticks,
a dedicated background thread with message-passing can be introduced.

### 14.2 Strict vs. Advisory Budget

**Decision: Strict enforcement with 1-item grace period.**

- **Pro**: Deterministic behavior; prevents runaway services.
- **Pro**: Enables budget exhaustion tracking for operator visibility.
- **Con**: A service may be cut off mid-item, requiring resumption logic in every
  service.
- **Mitigation**: The 1-item grace period allows finishing the current item; services
  use cursor-based state for resumption.

### 14.3 Compile-Time vs. Runtime Plugins

**Decision: Compile-time service registration, with a path to runtime plugins.**

- **Pro**: Simple scheduler — no dynamic dispatch complexity, no plugin ABI.
- **Pro**: Compiler-verified type safety for all service types.
- **Con**: Adding a new service requires recompilation.
- **Future**: Runtime plugins via a plugin registry with versioned ABI, gated behind
  `tidefs_background_plugins` feature flag.

### 14.4 Budget Granularity

**Decision: Three dimensions (items, bytes, milliseconds).**

ZFS and Ceph provide the design input that one or two throttle dimensions can
miss important service-shape differences. TideFS therefore targets three
dimensions: a scrub tick can be byte-heavy but item-light; a reclaim tick can
be item-heavy but byte-light. The `max_ms` dimension is the intended latency
safety net, with any operational claim left to measured validation.

### 14.5 Derived Catalog: Shared vs. Separate B-tree

**Decision: Separate derived catalog B-tree, same B-tree code, different config.**

- The authoritative catalog is read-heavy with smaller nodes (4 KiB).
- The derived catalog is write-heavy (build/evict cycles) and tombstone-heavy
  (compact cycles) with larger nodes (16 KiB).
- Separate B-tree instances prevent derived catalog compaction from creating
  write amplification on the authoritative catalog.
- Same B-tree code reduces maintenance burden.

## 15. Implementation Plan

The implementation is split into 10 phases, with phases 1-4 already complete:

| Phase | Scope | Status | Crate(s) |
|-------|-------|--------|----------|
| **Phase 1: Core types** | `ServicePriority`, `ServiceBudget`, `TickReport`, `CycleReport` | ✅ Done | `tidefs-types-incremental-job-core` |
| **Phase 2: Scheduler** | `BackgroundScheduler`, round-robin dispatch, budget cascading | ✅ Done | `tidefs-background-scheduler` |
| **Phase 3: IncrementalJob bridge** | `IncrementalJobAdapter`, JobKind→Priority mapping | ✅ Done | `tidefs-background-scheduler` |
| **Phase 4: Initial services** | `BackgroundReclaim`, `CleanupJob`, `OrphanRecoveryJob`, `ReclaimJob` | ✅ Done | respective crates |
| **Phase 5: View builder** | `ViewBuilderService`, derived catalog build/serve/evict/compact | 🔲 Pending | `tidefs-derived-catalog` (new) |
| **Phase 6: Data cleaner** | `DataCleanerService` processing refcount delta queues | 🔲 Pending | `tidefs-data-cleaner` (new) |
| **Phase 7: Segment cleaner** | `SegmentCleanerService` reclaiming dead segments | 🔲 Pending | `tidefs-segment-cleaner` (new) |
| **Phase 8: FUSE integration** | Wire scheduler into FUSE daemon main loop with demand preemption | 🔲 Pending | `apps/tidefs-posix-filesystem-adapter-daemon/src/runtime` |
| **Phase 9: Compaction** | `CompactionService` for derived catalog and refcount B-tree | 🔲 Pending | phases 5-6 |

### 15.1 Crate Dependency Graph

```
tidefs-types-incremental-job-core  (no_std, alloc)
    ↑
tidefs-incremental-job-core        (no_std, alloc)
    ↑
tidefs-background-scheduler        (no_std, alloc)
    ↑
    ├── tidefs-local-filesystem     (BackgroundReclaim)
    ├── tidefs-cleanup-job-core     (CleanupJob)
    ├── tidefs-reclaim-job-core     (ReclaimJob)
    └── tidefs-orphan-recovery-…    (OrphanRecoveryJob)
```

## 16. Open Questions

1. **Starvation override threshold**: What is the right `starvation_timeout_ms` for
   BestEffort services? Too short and they compete with latency-sensitive work;
   too long and compaction falls behind. Proposed: 60s, tunable via pool property.

2. **Derived catalog persistence**: Should derived views survive a daemon crash?
   Surviving avoids cold-start latency but requires crash-consistent B-tree writes
   consistency at mount; discard and rebuild if inconsistent.

3. **Multi-pool scheduling**: When multiple pools share one daemon, should the
   scheduler be per-pool or global? Per-pool provides isolation; global provides
   fairness across pools. Proposed: per-pool scheduler instances with a global
   budget divided by pool weight.

4. **Service dependencies**: Some services depend on others (scrub → repair,
   rebake → segment cleaner). Should the scheduler enforce ordering? Proposed:
   no — each service is independent; dependencies are handled by the service
   detecting work via authoritative state (scrub writes findings; repair reads them).

5. **Budget auto-tuning**: Can the scheduler learn optimal budget splits from
   historical cycle data? Machine learning adds complexity and non-determinism.
   Proposed: static weights with operator override; revisit in v1.1.


## 18. Changelog

| Date       | Description | Issue |
|------------|-------------|-------|
| 2026-05-05 | Coordinator issue; design-spec canonical consolidation confirmed as authoritative reference. Crate doc comments in `tidefs-types-incremental-job-core`, `tidefs-incremental-job-core`, and `tidefs-background-scheduler` updated to canonical design doc. Rust implementation of phases 5–10 deferred to wire-up issues (#1877). | #1780 |

## 17. References

- [#1673] This design spec — canonical background service framework design (design-spec)
- [#1674] Canonical consolidation of #1592 and #1673 design specs
- [#1877] Wire-up tracking issue for deferred Rust implementation of phases 5–10
- [#1179] Canonical background service framework design (initial spec)
- [#1459] BackgroundReclaim service implementation
- [#1463] Reclaim delta recording integration
- [#1176] Cached directory/index views
- [#1180] Refcount delta cleanup queues
- [#1249] Erasure coding and placement
- [#1222] Rebake architecture
- [#1215] Space accounting and cleaner scheduling
- [#1241] Unified lane scheduling model
- [#1223] Polymorphic extent maps
- `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md` — initial design spec
- `crates/tidefs-background-scheduler/src/lib.rs` — scheduler implementation (1319 lines)
- `crates/tidefs-types-incremental-job-core/src/lib.rs` — IncrementalJob trait and types
- `docs/design/incremental-job-core-types-crate-design.md` — IncrementalJob type design
- `docs/design/unified-scheduling-classes-lane-priority-model.md` — lane scheduling design
