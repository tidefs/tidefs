# Background Service Framework — Design-Spec (#1803)

Maturity: **design-spec**. Rust implementation deferred to wire-up issues.

This document is the design specification for the TideFS unified background service
framework as tracked in issue #1803. It defines the architecture, core data structures,
scheduling algorithms, and design tradeoffs. The canonical Rust implementation lives in
`crates/tidefs-background-scheduler/` (phases 1–4 complete) with phases 5–10 tracked
under #1877 / #1946.

**Source context:** lane `storage-core`, kind `design`.

**Design lineage:** This document draws from the consolidated canonical design (#1983,
`docs/design/background-service-framework-canonical-consolidation.md`), the scheduler
design (#1592, #1674), the enhanced lifecycle/starvation/backpressure design (#1624),
and the multi-threaded work-stealing design (#1625).

Claim boundary: this document is a design-spec and implementation-status record.
Its ZFS/Ceph comparisons are design inputs only, not product evidence that
TideFS currently provides better latency, throughput isolation, crash
resumption, operator visibility, or cost. Product-facing incumbent comparisons
must be delegated to #875 and backed by #928/#930 comparator evidence for the
exact implementation, workload, and storage class.

---

## 1. Problem Statement

A storage system running in userspace must perform continuous background maintenance:
scrubbing checksums, reclaiming freed space, compacting B-trees, rebuilding derived
views, cleaning dead segments, and evaluating snapshot retention policies. In the
absence of a unified framework, each subsystem invents its own throttling, progress
tracking, and scheduling — producing inconsistent behaviour under load and opaque
operator visibility.

The pre-framework codebase exhibited exactly this pattern:

| Subsystem | Scheduling mechanism | Throttling |
|---|---|---|
| Block-level scrub | Ad-hoc scan loop | None |
| Repair | Triggered by scrub | None |
| Crash recovery | Mount-time audit | None |
| FUSE daemon background | Inline loops | None |

A unified background service framework is required by at least 12 dependent designs:

| Dependent design | Background service needed |
|---|---|
| Cached directory/index views | View builder |
| Refcount delta cleanup queues | Data cleaner |
| Erasure coding and placement | Scrub + repair |
| Rebake architecture | Rebake conversion |
| Space accounting and cleaner scheduling | Segment cleaner |
| Snapshot retention | Retention evaluation |
| Unified lane scheduling | Background lane budget integration |
| BackgroundReclaim service | BackgroundReclaim |
| Reclaim delta recording | Delta processing in background tick |
| Polymorphic extent maps | Extent compaction |
| Online defrag/compaction | B-tree compaction |
| Orphan recovery | Orphan recovery |

---

## 2. Design Principles

The framework applies five design principles:

1. **Unified scheduling** — One scheduler, one cycle, one budget pool. No per-subsystem
   ad-hoc loops.
2. **Priority-ordered fairness** — Higher-priority services always run before
   lower-priority ones; within each priority stage, services round-robin.
3. **Budget enforcement** — Every tick is bounded by items, bytes, and wall-clock
   milliseconds. No unbounded background work.
4. **Observable determinism** — Every scheduling decision is recorded for
5. **Incremental progress** — Every service implements the `IncrementalJob` trait,
   advancing a cursor through a potentially infinite work domain.

### 2.1 ZFS / Ceph design-input comparison

The table below records scheduler-shape lessons. The TideFS row describes the
target framework shape, not a measured current superiority claim.

| System | Background model | Budget | Priority |
|---|---|---|---|
| **ZFS** | Ad-hoc scan tickets + `spa_sync` callbacks | Delay-based throttling (`zfs_scan_idle`) | None |
| **Ceph** | Per-PG state machines | Sleep-based throttling (`osd_recovery_sleep`) | Per-PG |
| **TideFS** | Unified scheduler + `BackgroundService` trait | Per-tick operation-count caps | 5-stage priority |

---

## 3. Architecture

### 3.1 High-Level Structure

```
┌──────────────────────────────────────────────────────────────────────────┐
│                       BackgroundSchedulerPool                             │
│                                                                          │
│  ┌────────────────────────────┐    ┌───────────────────────────────────┐ │
│  │     Planning Thread         │    │          Worker Pool              │ │
│  │     (FUSE event loop)       │    │                                   │ │
│  │                             │    │  Worker 0: tick queue.dequeue     │ │
│  │  plan_cycle(budget)         │    │  Worker 1: tick queue.dequeue     │ │
│  │         │                   │    │  Worker 2: tick queue.dequeue     │ │
│  │  ┌──────▼───────────┐      │    │  Worker 3: tick queue.dequeue     │ │
│  │  │  TickWorkItem    │      │    │                                   │ │
│  │  │  queue           │──────┼───▶│  Steal protocol: when idle,       │ │
│  │  └──────────────────┘      │    │  steal from peer's local queue    │ │
│  └────────────────────────────┘    └───────────────────────────────────┘ │
│                                                                          │
│  collect_reports() ◀────────────────────── Report queue                  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                    Priority Stages                                   │ │
│  │  ┌─────────┐  ┌──────────┐  ┌───────────┐  ┌──────────┐           │ │
│  │  │Critical │→│LatencySen│→│Throughput │→│BestEffort│→Opt        │ │
│  │  │  (40%)  │  │  (30%)   │  │  (15%)    │  │  (10%)   │(5%)       │ │
│  │  └─────────┘  └──────────┘  └───────────┘  └──────────┘           │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  Global Budget: ServiceBudget (items, bytes, ms)                        │
│  Round-robin cursor per stage                                           │
│  Cascading unused budget to next stage                                  │
└──────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Integration with IncrementalJob

The `BackgroundService` trait pairs with an `IncrementalJobAdapter` that wraps any
`IncrementalJob` implementor (from `tidefs-types-incremental-job-core`). This bridges
the universal incremental cursor contract with the priority-driven scheduler:

```
BackgroundScheduler
  ├── IncrementalJobAdapter<CleanupJob>        (Throughput)
  ├── IncrementalJobAdapter<ReclaimJob>         (Throughput)
  ├── IncrementalJobAdapter<OrphanRecoveryJob>  (LatencySensitive)
  ├── IncrementalJobAdapter<RebakeJob>          (Throughput → Critical escalation)
  ├── IncrementalJobAdapter<ScrubJob>           (Critical)
  └── …
```

### 3.3 Service Lifecycle State Machine

Each background service traverses a defined lifecycle:

```
  ┌────────────┐
  │  Stopped   │
  └─────┬──────┘
        │ start()
  ┌─────▼──────┐
  │  Running   │◄──────────────┐
  └──┬──────┬──┘               │
     │      │                  │
     │      │ pause()    resume()
     │      ▼                  │
     │  ┌──────────┐           │
     │  │  Paused  │───────────┘
     │  └──────────┘
     │
     │ consecutive failures > N_CRITICAL (default 10)
     ▼
  ┌──────────────┐
  │   Degraded   │
  └──────┬───────┘
         │ consecutive failures > N_UNHEALTHY (default 50)
         ▼
  ┌──────────────┐      manual reset
  │  Unhealthy   │────────────────────►  Running
  └──────────────┘
```

---

## 4. Core Data Structures

### 4.1 ServicePriority

5-stage priority class for scheduling order and budget allocation.

```rust
pub enum ServicePriority {
    Critical = 0,          // Authority/consistency: repair, intent-log sync
    LatencySensitive = 1,  // Cache maintenance: directory view building
    Throughput = 2,        // Bulk data work: data cleaning, rebake, reclaim
    BestEffort = 3,        // Compaction/trim: segment compaction, tombstone GC
    Opportunistic = 4,     // Speculative: prefetch, readahead, thermal rebalance
}
```

Priority determines both dispatch order and budget allocation weight:

| Priority | Weight | Rationale |
|---|---|---|
| Critical | 0.40 | Authority work must make steady progress; capped to leave room |
| LatencySensitive | 0.30 | Cache maintenance has high user-visible ROI |
| Throughput | 0.15 | Bulk work is important but deferrable |
| BestEffort | 0.10 | Compaction trims need slow, steady progress |
| Opportunistic | 0.05 | Never starve, but never compete with real work |

Weights are configurable via pool properties. Priority escalation is supported:
for example, `RebakeService` escalates from Throughput to Critical when durability
drops below the warning threshold.

### 4.2 ServiceBudget

Per-tick resource limits enforced strictly during each tick.

```rust
pub struct ServiceBudget {
    pub max_items: u64,   // Max operations per tick
    pub max_bytes: u64,   // Max bytes transferred per tick
    pub max_ms: u64,      // Max tick wall-clock duration (soft bound)
}
```

Predefined budgets:

| Constant | Items | Bytes | MS | Use case |
|---|---|---|---|---|
| `DEFAULT_TICK` | 1024 | 64 MiB | 100 | Normal background cycle |
| `MAINTENANCE_TICK` | 256 | 16 MiB | 50 | Between demand ops in FUSE loop |
| `SMALL_TICK` | 64 | 4 MiB | 25 | Emergency pressure, low-memory mode |

Budget is enforced strictly — a service must not exceed any dimension. A 1-item grace
period allows finishing an in-progress item when budget hits zero mid-operation.

### 4.3 TickReport

Per-tick accounting record produced by every `BackgroundService::tick()` call.

```rust
pub struct TickReport {
    pub processed: u64,       // Items successfully processed
    pub skipped: u64,         // Items skipped (stale token, already done, no-op)
    pub errors: u64,          // Items that produced errors
    pub items_consumed: u64,  // Items consumed from budget
    pub bytes_consumed: u64,  // Bytes consumed from budget
    pub has_more: bool,       // True if service reports more pending work
}
```

The sum `processed + skipped + errors` is bounded by `items_consumed`. The `has_more`
flag determines whether the scheduler will offer this service another tick in the
current cycle.

### 4.4 CycleReport

Aggregated per-cycle report summarizing all service activity within one scheduler cycle.

```rust
pub struct CycleReport {
    pub services_ran: usize,
    pub services_skipped: usize,
    pub budget_exhausted: bool,
    pub remaining_budget: ServiceBudget,
    pub total_processed: u64,
    pub total_skipped: u64,
    pub total_errors: u64,
    pub wall_ms: u64,
}
```

### 4.5 BackgroundService Trait

The core trait every background service must implement.

```rust
pub trait BackgroundService: Send {
    /// User-visible service name.
    fn name(&self) -> &str;

    /// Priority class for scheduling.
    fn priority(&self) -> ServicePriority;

    /// Execute one tick within the given budget.
    fn tick(&mut self, budget: &ServiceBudget) -> TickReport;

    /// True if this service has pending work.
    fn has_work(&self) -> bool;

    /// Current lifecycle state.
    fn state(&self) -> ServiceState;

    /// Transition to Running (allowed from Stopped, Paused, Unhealthy).
    fn start(&mut self);

    /// Pause the service (allowed from Running, Degraded).
    fn pause(&mut self);

    /// Resume from Paused (allowed from Paused).
    fn resume(&mut self);

    /// Reset service: clear error counters, return cursor to start.
    fn reset(&mut self);
}
```

### 4.6 ServiceState

```rust
pub enum ServiceState {
    Stopped,
    Running,
    Paused,
    Degraded,   // Consecutive tick errors exceed N_CRITICAL
    Unhealthy,  // Consecutive tick errors exceed N_UNHEALTHY
}
```

### 4.7 BackgroundScheduler

The scheduler maintains a registry of services per priority stage, a round-robin
cursor per stage, and a global budget pool.

```rust
pub struct BackgroundScheduler {
    stages: [Vec<Box<dyn BackgroundService>>; 5],
    cursors: [usize; 5],               // Round-robin indices per stage
    budget: ServiceBudget,
    tick_log: TickLog,                  // In-memory ring buffer
    starvation_tracker: StarvationTracker,
    backpressure: BackpressureController,
}
```

### 4.8 StarvationTracker

Tracks how long each service has been registered without receiving a tick. If a
service exceeds the starvation threshold (default 60s), it is temporarily promoted
to Critical priority for one cycle.

```rust
pub struct StarvationTracker {
    last_tick: HashMap<String, u64>,   // Service name → last tick timestamp
    threshold_ms: u64,                  // Default 60_000
}
```

### 4.9 BackpressureController

Monitors system utilization and adjusts the global budget dynamically. When I/O
pressure is high (e.g., demand FUSE ops saturating), the background budget shrinks
to leave headroom for foreground work.

```rust
pub struct BackpressureController {
    current_budget: ServiceBudget,
    base_budget: ServiceBudget,
    min_budget: ServiceBudget,
    utilization: f64,           // 0.0–1.0 system utilization
    shrink_factor: f64,         // Multiplier when utilization > high_water
    restore_factor: f64,        // Multiplier when utilization < low_water
    high_water: f64,            // 0.85 — shrink above this
    low_water: f64,             // 0.50 — restore below this
}
```

### 4.10 ValidityToken

A monotonic token generated per background service cycle. When a service schedules
work into a future cycle (deferred cleanup, rebake), the token is embedded in the
work item. At execution time, if the token does not match the current cycle's token,
the work item is discarded as stale. This prevents double-processing of work that
has already been handled by a newer cycle.

```rust
pub struct ValidityToken(u64);
```

---

## 5. Algorithms

### 5.1 Main Scheduling Loop

```
procedure run_cycle(scheduler):
    report ← empty CycleReport
    remaining ← scheduler.global_budget
    cycle_token ← next_validity_token()

    for priority in [Critical, LatencySensitive, Throughput, BestEffort, Opportunistic]:
        stage_budget ← allocate_stage_budget(remaining, priority.weight)
        services ← scheduler.stages[priority]

        if services.is_empty() or stage_budget.is_zero():
            cascade remaining to next stage
            continue

        cursor ← scheduler.cursors[priority]
        start_cursor ← cursor
        exhausted ← false

        while not exhausted and remaining > MIN_BUDGET:
            service ← services[cursor]
            if not service.has_work():
                cursor ← (cursor + 1) % len(services)
                if cursor == start_cursor: break    // full rotation, no work
                continue

            tick_budget ← min(stage_budget, remaining)
            tick_report ← service.tick(tick_budget, cycle_token)
            report.merge(tick_report)
            remaining ← remaining - tick_report.consumed()
            stage_budget ← stage_budget - tick_report.consumed()

            if not tick_report.has_more:
                cursor ← (cursor + 1) % len(services)
            // else: give same service another tick in this cycle

            if stage_budget.is_zero() or remaining < MIN_BUDGET:
                exhausted ← true

        scheduler.cursors[priority] ← cursor
        if remaining < MIN_BUDGET: break

    // BestEffort + Opportunistic can consume any remaining budget
    // (cascading from higher-priority unused allocations)
    report.remaining_budget ← remaining
    return report
```

### 5.2 Budget Cascading

Unused budget from higher-priority stages cascades to lower-priority stages. The
allocation is:

1. **Critical** is offered up to 40% of total budget.
2. If Critical consumes less, the remainder is added to LatencySensitive's allocation.
3. This cascading continues through all five stages.
4. At the end of the cycle, any remaining budget is recorded in `CycleReport`.

This ensures that budget is never wasted: if Critical services are idle, their
allocation flows to LatencySensitive, then to Throughput, etc.

### 5.3 Round-Robin Fairness within Stage

Within each priority stage, services are dispatched round-robin:

- A cursor per stage advances each time a service completes a tick (or reports no
  pending work).
- If a service reports `has_more: true`, it gets another tick immediately without
  advancing the cursor — this is "sticky" scheduling that amortizes state
  restoration costs.
- If a full rotation completes with no service having work, the stage is skipped
  and its budget cascades.

### 5.4 Starvation Prevention

The `StarvationTracker` runs before each cycle:

```
procedure check_starvation(scheduler):
    now ← monotonic_time_ms()
    for each service in all stages:
        elapsed ← now - tracker.last_tick[service.name()]
        if elapsed > tracker.threshold_ms and service.priority != Critical:
            promote service to Critical for this cycle
            schedule starvation-prevention tick
            tracker.last_tick[service.name()] ← now
```

After the starvation-prevention tick completes, the service returns to its original
priority. The starvation-prevention tick counts against the service's normal budget
allocation to maintain overall fairness.

### 5.5 Backpressure Auto-Tuning

```
procedure update_backpressure(controller, system_utilization):
    if utilization > controller.high_water:
        controller.current_budget ← max(
            controller.min_budget,
            controller.current_budget * controller.shrink_factor  // e.g., 0.75
        )
    else if utilization < controller.low_water and current < base:
        controller.current_budget ← min(
            controller.base_budget,
            controller.current_budget * controller.restore_factor // e.g., 1.25
        )
```

This ensures background work yields to foreground demand under load and recovers
budget during idle periods.

### 5.6 Health Transitions

After each tick, the scheduler evaluates the service's error rate:

```
procedure evaluate_health(service, consecutive_errors):
    if consecutive_errors == 0 and service.state in [Degraded, Unhealthy]:
        // Auto-recovery: reset error counters
        return

    if consecutive_errors > N_CRITICAL and service.state == Running:
        service.state ← Degraded

    if consecutive_errors > N_UNHEALTHY and service.state == Degraded:
        service.state ← Unhealthy
```

Unhealthy services are skipped in future cycles until manually reset via
`BackgroundService::reset()` or the optional `auto_reset_after_cycles` property.

---

## 6. Registered Background Services

| Service | Priority | Tick profile | State checkpoint key |
|---|---|---|---|
| Scrub | Critical | I/O-heavy, 20–100ms | `(dataset_id, block_offset, checksum_state)` |
| Repair | Critical | Read-modify-write, 5–50ms | `(dataset_id, repair_queue_entry_id)` |
| View builder | LatencySensitive | Metadata scan, 5–30ms | `(dataset_id, object_id)` |
| Reclaim | LatencySensitive | Spacemap walk, 10–40ms | `(dataset_id, sort_key)` |
| Data cleaner | Throughput | Refcount delta, 10–60ms | `(dataset_id, delta_seq)` |
| Rebake | Throughput | Journal→base, 20–100ms | `(dataset_id, journal_offset)` |
| Segment cleaner | BestEffort | Dead segment reclaim, 20–80ms | `(dataset_id, segment_id)` |
| Compaction | BestEffort | B-tree node merge, 10–50ms | `(btree_id, level, node_id)` |
| Prefetch | Opportunistic | Speculative read, 5–20ms | In-memory only |
| Orphan recovery | LatencySensitive | Orphan index walk, 10–30ms | `(dataset_id, orphan_index_entry_id)` |
| Snapshot retention | BestEffort | Policy evaluation, 1–5ms | `(dataset_id, snapshot_id)` |

---

## 7. Implementation Status

### 7.1 Completed (Phases 1–4)

| Phase | Description | Status |
|---|---|---|
| 1 | `ServicePriority`, `ServiceBudget`, `TickReport`, `CycleReport` types | Implemented |
| 2 | `BackgroundService` trait + `BackgroundScheduler` with 5-stage dispatch | Implemented |
| 3 | Round-robin fairness, budget cascading, validity tokens | Implemented |
| 4 | `IncrementalJobAdapter` bridging `IncrementalJob` → `BackgroundService` | Implemented |

### 7.2 Deferred (Phases 5–10, tracked under #1877 / #1946)

| Phase | Description | Status |
|---|---|---|
| 5 | Multi-threaded worker pool with work-stealing | Design-spec complete |
| 6 | Starvation prevention with automatic promotion | Design-spec complete |
| 7 | Backpressure auto-tuning | Design-spec complete |
| 8 | Health state machine (Degraded/Unhealthy transitions) | Design-spec complete |
| 9 | `TickLog` persistence, admin CLI, trace oracle integration | Design-spec complete |
| 10 | Per-service derived catalog lifecycle, crash recovery | Design-spec complete |

### 7.3 Crates

| Crate | Role |
|---|---|
| `tidefs-background-scheduler` | Unified scheduler, dispatch, budget enforcement |
| `tidefs-types-incremental-job-core` | `IncrementalJob` trait + `Checkpoint`, `WorkBudget`, `StepResult` |
| `tidefs-incremental-job-core` | Core incremental job implementations |

---

## 8. Design Tradeoffs

### 8.1 Single-Threaded Planning vs. Dedicated Planner Thread

**Decision**: Planning runs inline on the FUSE event loop (phase 4).

**Rationale**: The planning phase (`plan_cycle`) is intended to stay
O(services x priorities) and small enough for inline execution at the current
service scale. The `< 100us` and `> 500us` figures below are design budgets and
re-evaluation gates, not current benchmark evidence or incumbent-comparison
claims.

**Re-evaluation gate**: If profiling shows `plan_cycle` exceeding 500µs, add a
dedicated planner thread with a lock-free work queue. This is deferred to v1.1.

### 8.2 Per-Service vs. Global Backpressure

**Decision**: Global backpressure with per-stage budget allocation.

**Rationale**: Per-service backpressure creates coupling between unrelated services
and makes the scheduling problem NP-hard (knapsack with dependencies). Global
backpressure with priority-weighted allocation is simpler, predictable, and
sufficient for the current service set.

### 8.3 Sticky Scheduling (has_more) vs. Strict Round-Robin

**Decision**: Sticky scheduling within a cycle, round-robin across cycles.

**Rationale**: Many background operations benefit from amortizing state restoration.
For example, scrub advances through contiguous block ranges — restarting from the
checkpoint on every tick would thrash the block cache. Sticky scheduling allows a
service to consume multiple consecutive ticks when it has pending work, improving
cache locality. The round-robin cursor still advances across cycles, preventing
starvation.

### 8.4 Soft vs. Hard Wall-Clock Budget

**Decision**: Soft wall-clock bound (`max_ms`).

**Rationale**: In userspace, precise wall-clock enforcement would require signal
handlers or cooperative preemption points. The soft bound is a hint: services
should check elapsed time periodically and yield. This is simpler than cooperative
multitasking and sufficient given the tick profiles (1–100ms). A hard bound would
add complexity without proportional benefit.

### 8.5 Validity Tokens vs. Work-Item Versioning

**Decision**: Monotonic per-cycle validity tokens.

**Rationale**: Work-item versioning (embedding a generation number per work unit)
it. Validity tokens are simpler: the scheduler generates a single token per cycle,
and each work item carries the token from its scheduling cycle. At execution time,
mismatched tokens mean the work was superseded and can be discarded. This is
sufficient because background work is cycle-coherent — a newer cycle's token
implies all prior work is obsolete.

### 8.6 Work-Stealing vs. Partitioned Work Queues

**Decision**: Chase-Lev work-stealing deques (phase 5).

**Rationale**: Partitioned queues (one queue per worker, no stealing) are simpler
but suffer from load imbalance: a worker assigned a heavy tick starves while
another is idle. Work-stealing distributes work dynamically with low contention,
following the well-known Chase-Lev algorithm. The tradeoff is implementation
complexity, which is justified by the throughput improvement under non-uniform
work distributions.

### 8.7 Core Pinning

**Decision**: Defer to v1.1.

**Rationale**: The initial implementation uses OS-thread scheduling. Core pinning
can improve cache locality for I/O-heavy workers but adds platform-specific
complexity (sched_setaffinity, cgroups v2). This is deferred until profiling
demonstrates material benefit.

### 8.8 Determinism Contract

**Decision**: All `BackgroundService` implementations must be deterministic.

**Rationale**: Given the same state and the same budget, the same tick must
The cost is that services cannot use wall-clock time or random seeds directly —
these must be injected by the scheduler.

---

## 9. Admin Interface

The admin service exposes background service control via a wire protocol:

```
admin background status [--service <name>]
    → per-service state, tick count, error count, last tick report

admin background pause <service>
    → transition to Paused

admin background resume <service>
    → transition to Running (from Paused)

admin background reset <service>
    → reset error counters, return cursor to checkpoint start

admin background priority <service> <priority>
    → override service priority (operator override)

admin background budget [--items N] [--bytes N] [--ms N]
    → set global budget (override auto-tuning)

admin background ticklog [--tail N]
    → dump recent TickLog entries
```

### 9.1 Observability Integration

The scheduler emits aggregated metrics to the TideFS metrics pipeline:

| Metric | Type | Description |
|---|---|---|
| `bg_cycle_duration_ms` | Histogram | Per-cycle wall-clock time |
| `bg_services_ran` | Gauge | Services that ran in last cycle |
| `bg_items_processed` | Counter | Total items processed across all services |
| `bg_items_skipped` | Counter | Total items skipped (stale/no-op) |
| `bg_items_errors` | Counter | Total items that errored |
| `bg_budget_remaining_pct` | Gauge | Percentage of budget unconsumed |
| `bg_starvation_events` | Counter | Starvation prevention promotions |
| `bg_service_state{name,state}` | Gauge | Per-service current state |

---

## 10. Testing Strategy

### 10.1 Unit Tests (in `tidefs-background-scheduler`)

- Priority dispatch order: verify Critical runs before BestEffort
- Round-robin within stage: verify cursor advancement
- Budget exhaustion: all three dimensions (items, bytes, wall-time)
- Budget cascading: unused Critical budget reaches BestEffort
- Idle service skipping: services with no work are bypassed
- `CycleReport` correctness: totals match individual tick reports
- Validity token stale-work discarding
- `MockBackgroundService` conformance

### 10.2 Integration Tests

- Multi-service cycle: 3+ services at different priorities, verify dispatch
  order and budget consumption
- Starvation prevention: register service, skip ticks for >60s, verify promotion
- Backpressure: simulate high utilization, verify budget shrinkage; simulate
  idle, verify budget restoration
- Health transitions: simulate consecutive errors, verify Degraded → Unhealthy
- Work-stealing (phase 5): register 4 workers, verify distribution

### 10.3 Deterministic Replay Tests

- Capture a cycle trace with known inputs
- Replay with identical inputs; assert identical scheduling decisions
- Replay with different inputs; assert non-deterministic decisions are flagged


```bash
cargo test -p tidefs-background-scheduler -- --test-threads=1
```

For release-candidate or shared-surface changes:

```bash
```

---

## 11. Open Questions

1. **Starvation threshold**: Default 60s; should pool properties expose tuning?
   consistency at mount; discard and rebuild if inconsistent.
3. **Multi-pool scheduling**: Per-pool `BackgroundSchedulerPool` with global
   budget divided by pool weight — v1.1.
4. **Service dependencies**: Not enforced by the scheduler; each service detects
   work via authoritative state queries.
5. **Budget auto-tuning**: Static weights with operator override; ML-based
   tuning revisited in v1.1.
6. **Auto-recovery of Unhealthy services**: Manual reset only by default;
   `auto_reset_after_cycles` property enables hands-off recovery.
7. **TickLog persistence**: In-memory ring buffer; dump on operator request.
8. **Core pinning**: Defer to v1.1.
9. **Dedicated planner thread**: Start inline; add only if profiling shows
   >500µs planning time.
10. **Starvation tick budget accounting**: Starvation-prevention tick counts
    against the service's normal budget to maintain overall fairness.

---

## 12. References

- [#1179] Initial background service framework →
  `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md`
- [#1592] Canonical scheduler design →
  `docs/design/background-service-framework-design.md`
- [#1624] Enhanced design (lifecycle, starvation, backpressure) →
  `docs/design/background-service-framework-design-enhanced.md`
- [#1625] Multi-threaded work-stealing design →
  `docs/design/background-service-framework-multithread-design.md`
- [#1673][#1674] Design-spec →
  `docs/design/background-service-framework-design-spec.md`
- [#1713] 16-phase roadmap
- [#1858][#1859][#1877][#1980] Coordination seal & status tracking
- [#1877][#1946] Phases 5–10 wire-up tracking
- [#1983] Canonical consolidation →
  `docs/design/background-service-framework-canonical-consolidation.md`
- `crates/tidefs-background-scheduler/src/lib.rs` — scheduler (phases 1–4)
- `crates/tidefs-types-incremental-job-core/src/lib.rs` — `IncrementalJob` trait
- `docs/design/incremental-job-core-types-crate-design.md` — type design
- `docs/design/incremental-job-core-wire-up-deferred-design.md` — wire-up
- `docs/design/unified-scheduling-classes-lane-priority-model.md` — lane model
- `docs/design/admin-service-wire-protocol.md` — admin protocol
- `docs/design/deterministic-trace-oracle-system.md` — trace oracle
- `docs/design/deferred-cleanup-background-service-scheduling.md` — cleanup
- `docs/design/deferred-cleanup-work-queues.md` — work queues
- Chase-Lev, "Dynamic Circular Work-Stealing Deque", SPAA 2005
- Blumofe & Leiserson, "Scheduling Multithreaded Computations by Work Stealing", JACM 1999

---

## 13. Change Log

| Date | Change | Author |
|---|---|---|
| 2026-05-05 | Initial design spec for issue #1803 | Codex (worker-s3) |
