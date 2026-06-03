# Background Service Framework Design Spec (#1713)

Maturity: **design-spec**. Rust implementation deferred to wire-up issues.

This document is the definitive design specification for the TideFS unified background
service framework. It consolidates the tick-driven scheduler (#1592, #1674), the
enhanced lifecycle/starvation/backpressure design (#1624), and the multi-threaded
work-stealing design (#1625) into a single authoritative reference. All wire-up
issues for background services MUST reference this spec.

**Source context:** lane `storage-core`, kind `design`.

## 1. Problem Statement

A storage system running in userspace must perform continuous background maintenance:
scrubbing checksums, reclaiming freed space, compacting B-trees, rebuilding derived
views, cleaning dead segments, and evaluating snapshot retention policies. In the
absence of a unified framework, each subsystem invents its own throttling, progress
tracking, and scheduling — producing inconsistent behavior under load and opaque
operator visibility.

The following services run or will run as background work:

| Service | Priority | Tick profile |
|---------|----------|--------------|
| Scrub | Critical | I/O-heavy, 20–100ms |
| Repair | Critical | Read-modify-write, 5–50ms |
| View builder | LatencySensitive | Metadata scan, 5–30ms |
| Reclaim | LatencySensitive | Spacemap walk, 10–40ms |
| Data cleaner | Throughput | Refcount delta processing, 10–60ms |
| Rebake | Throughput | Journal→base conversion, 20–100ms |
| Segment cleaner | BestEffort | Dead segment reclamation, 20–80ms |
| Compaction | BestEffort | B-tree node merge, 10–50ms |
| Prefetch | Opportunistic | Speculative read, 5–20ms |
| Orphan recovery | LatencySensitive | Orphan index walk, 10–30ms |
| Snapshot retention | BestEffort | Policy evaluation, 1–5ms |

At least 12 dependent designs require the framework:

| Dependent design | Background service needed |
|-----------------|--------------------------|
| Cached directory/index views | View builder service |
| Refcount delta cleanup queues | Data cleaner service |
| Erasure coding and placement | Scrub + repair services |
| Rebake architecture | Rebake conversion service |
| Space accounting and cleaner scheduling | Segment cleaner service |
| Snapshot retention | Retention evaluation service |
| Unified lane scheduling | Background lane budget integration |
| BackgroundReclaim service | BackgroundReclaim service |
| Reclaim delta recording | Delta processing in background tick |
| Polymorphic extent maps | Extent compaction service |
| Online defrag/compaction | B-tree compaction service |
| Orphan recovery | Orphan recovery service |

## 2. Design Philosophy

The framework applies five design principles:

1. **Unified scheduling**: One scheduler, one cycle, one budget pool. No per-subsystem
   ad-hoc loops.
2. **Priority-ordered fairness**: Higher-priority services always run before lower-
   priority ones, but within each priority stage, services round-robin.
3. **Budget enforcement**: Every tick is bounded by items, bytes, and wall-clock
   milliseconds. No unbounded background work.
4. **Observable determinism**: Every scheduling decision is recorded in a `TickLog`
5. **Incremental progress**: Every service implements the `IncrementalJob` trait,
   advancing a cursor through a potentially infinite work domain.

## 3. Architecture Overview

```
┌────────────────────────────────────────────────────────────────────────┐
│                        BackgroundSchedulerPool                          │
│                                                                        │
│  ┌───────────────────────────┐    ┌─────────────────────────────────┐ │
│  │     Planning Thread        │    │          Worker Pool            │ │
│  │     (FUSE event loop)      │    │                                 │ │
│  │                            │    │  Worker 0: tick queue.dequeue   │ │
│  │  plan_cycle(budget)       │    │  Worker 1: tick queue.dequeue   │ │
│  │         │                  │    │  Worker 2: tick queue.dequeue   │ │
│  │  ┌──────▼───────────┐     │    │  Worker 3: tick queue.dequeue   │ │
│  │  │  TickWorkItem    │     │    │                                 │ │
│  │  │  queue           │─────┼───▶│  Steal protocol: when idle,     │ │
│  │  └──────────────────┘     │    │  steal from peer's local queue  │ │
│  └───────────────────────────┘    └─────────────────────────────────┘ │
│                                                                        │
│  collect_reports() ◀────────────────────── Report queue                │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │                    Priority Stages                                │ │
│  │  ┌─────────┐  ┌──────────┐  ┌───────────┐  ┌──────────┐         │ │
│  │  │Critical │→│LatencySen│→│Throughput │→│BestEffort│→Opt      │ │
│  │  │  (40%)  │  │  (30%)   │  │  (15%)    │  │  (10%)   │(5%)     │ │
│  │  └─────────┘  └──────────┘  └───────────┘  └──────────┘         │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                        │
│  Global Budget: ServiceBudget (items, bytes, ms)                      │
│  Round-robin cursor per stage                                         │
│  Cascading unused budget to next stage                                │
│  Backpressure: demand pressure shrinks effective budget               │
│  Starvation guard: force-tick starved BestEffort services             │
└────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Single-Threaded Core (Baseline)

The baseline scheduler (`BackgroundScheduler`) runs on a single thread — the FUSE
daemon event loop. It executes all service ticks sequentially within
`run_cycle()`. This is the correct architecture for low-service-count deployments
(≤4 services) and is the foundation that the multi-threaded pool builds upon.

### 3.2 Multi-Threaded Pool (Extension)

`BackgroundSchedulerPool` decouples planning from execution. Planning remains
single-threaded and fast (O(n) in services, <1ms). Execution is distributed across
a fixed-size worker pool with work-stealing. See §10 for the full multi-threaded design.

## 4. Core Abstractions

### 4.1 ServicePriority

Five priority stages, ordered highest to lowest:

```rust
pub enum ServicePriority {
    Critical        = 0,   // 40% of global budget
    LatencySensitive = 1,  // 30% of global budget
    Throughput       = 2,  // 15% of global budget
    BestEffort       = 3,  // 10% of global budget
    Opportunistic    = 4,  //  5% of global budget
}
```

Budget percentages are defaults; operators may override per-pool.

Priority assignment rules:
- `Critical`: Integrity checks (scrub, repair). Must run every cycle.
- `LatencySensitive`: Work that affects user-facing latency (view builder, reclaim).
- `Throughput`: Bulk data movement (data cleaner, rebake).
- `BestEffort`: Compaction, segment cleaning, snapshot evaluation.
- `Opportunistic`: Prefetch, speculative reads. Only runs when nothing else is pending.

### 4.2 ServiceBudget

Per-tick resource limits:

```rust
pub struct ServiceBudget {
    pub max_items: u64,    // Maximum work items to process
    pub max_bytes: u64,    // Maximum bytes to read+write
    pub max_ms: u64,       // Maximum wall-clock milliseconds
}
```

Constants:
- `ServiceBudget::DEFAULT_TICK`: Sensible defaults for a normal cycle.
- `ServiceBudget::MAINTENANCE_TICK`: Reduced budget during maintenance.
- `ServiceBudget::SMALL_TICK`: Minimal budget for quick passes.
- `ServiceBudget::UNBOUNDED`: No limits (used only during mount-time recovery).
- `ServiceBudget::PAUSED`: Zero budget, effectively disabling the service.

Budget exhaustion rules: a tick terminates when ANY dimension is exhausted.

### 4.3 TickReport

Per-tick accounting:

```rust
pub struct TickReport {
    pub service_name: &'static str,
    pub priority: ServicePriority,
    pub items_processed: u64,
    pub items_skipped: u64,
    pub items_errored: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub ms_elapsed: u64,
    pub has_more_work: bool,     // true if the service could have done more
    pub error: Option<ServiceError>,
}
```

### 4.4 CycleReport

Aggregates all `TickReport`s from one scheduler cycle plus scheduler-level statistics:

```rust
pub struct CycleReport {
    pub cycle_number: u64,
    pub ms_cycle_elapsed: u64,
    pub tick_reports: Vec<TickReport>,
    pub budget: ServiceBudget,
    pub effective_budget: ServiceBudget,  // after backpressure shrink
    pub demand_pressure: f64,             // 0.0–1.0
    pub scheduler_stats: SchedulerStats,
}
```

### 4.5 BackgroundService Trait

Every service implements:

```rust
pub trait BackgroundService: Send {
    fn name(&self) -> &'static str;
    fn priority(&self) -> ServicePriority;
    fn tick(&mut self, budget: &ServiceBudget) -> TickReport;
    fn work_pending(&self) -> bool;
    fn state(&self) -> ServiceState;
    fn set_state(&mut self, state: ServiceState);
    fn health(&self) -> HealthTracker;
}
```

### 4.6 IncrementalJobAdapter

Bridges the `IncrementalJob` trait (from `tidefs-types-incremental-job-core`) with
the `BackgroundService` trait:

```rust
pub struct IncrementalJobAdapter<J: IncrementalJob> {
    name: &'static str,
    priority: ServicePriority,
    job: J,
    state: ServiceState,
    health: HealthTracker,
    starvation: StarvationTracker,
}
```

The adapter converts `JobKind` to `ServicePriority`:

| JobKind | ServicePriority |
|---------|----------------|
| Scrub | Critical |
| Repair | Critical |
| Reclaim | LatencySensitive |
| ViewBuild | LatencySensitive |
| OrphanRecovery | LatencySensitive |
| CleanupData | Throughput |
| Rebake | Throughput |
| Compaction | BestEffort |
| SegmentCleanup | BestEffort |
| SnapshotRetention | BestEffort |
| Prefetch | Opportunistic |
| Other | BestEffort |

## 5. Tick Dispatch Algorithm

### 5.1 Single-Threaded Dispatch

```
run_cycle(global_budget):
    cycle_report = CycleReport::new()
    remaining_budget = apply_demand_backpressure(global_budget)

    for priority in [Critical, LatencySensitive, Throughput,
                     BestEffort, Opportunistic]:
        stage_budget = remaining_budget.fraction(stage_weight, 100)
        stage_report = dispatch_stage(priority, stage_budget)
        cycle_report.push_stage(stage_report)
        remaining_budget -= stage_budget.consumed
        // Cascade unused budget to next stage

    // Starvation prevention: force-tick any BestEffort/Opportunistic
    // service that hasn't run in starvation_timeout_ms
    dispatch_starved_services(cycle_report)

    return cycle_report
```

### 5.2 Per-Stage Dispatch

```
dispatch_stage(priority, stage_budget):
    stage_report = StageReport::new()
    services = registered_services.filter(state == Running
              && priority == stage_priority)
    cursor = round_robin_cursor[priority]  // resumes from last position

    for service in services[cursor..] + services[..cursor]:
        if stage_budget.is_exhausted():
            break
        tick_report = service.tick(stage_budget)
        stage_report.push(tick_report)
        stage_budget.subtract(tick_report.consumed)

    round_robin_cursor[priority] = next_position
    return stage_report
```

### 5.3 Budget Cascading

Unused budget from a higher-priority stage cascades to the next-lower stage. Example:

1. Critical stage budget: 40 units. Only 25 used → 15 cascade to LatencySensitive.
2. LatencySensitive: 30 + 15 = 45 units. Only 30 used → 15 cascade to Throughput.
3. Throughput: 15 + 15 = 30 units. Uses all 30.
4. BestEffort: 10 units (no cascade from exhausted Throughput).
5. Opportunistic: 5 units. Only runs if something remains.

### 5.4 COMMIT_GROUP Pre-Cycle

Before dispatching any service, the scheduler calls `commit_group.tick()` on the transaction
group state machine. If `commit_group.tick()` initiates a sync, the global budget's `max_bytes`
dimension is reduced by 50% for that cycle to avoid competing with sync I/O.

## 6. Service Lifecycle State Machine

### 6.1 States

```
                           ┌──────────┐
                     ┌────▶│  Paused  │────┐
                     │     └──────────┘    │
                     │       resume        │
                     │                     │
 ┌──────────┐  register  ┌──────────┐  pause  ┌──────────┐
 │Registered│──────────▶│  Running  │────────▶│  Paused  │
 └──────────┘            └──────────┘         └──────────┘
                              │                     │
                              │ consecutive errors   │
                              │ > error_threshold    │
                              ▼                     │
                         ┌──────────┐               │
                         │Unhealthy │               │
                         └──────────┘               │
                              │                     │
                              │ manual reset        │
                              ▼                     │
                         ┌──────────┐               │
                         │ Running  │◀──────────────┘
                         └──────────┘
                              │
                              │ retire (operator or
                              │ feature gate off)
                              ▼
                         ┌──────────┐
                         │ Retired  │ (terminal)
                         └──────────┘
```

### 6.2 State Enum

```rust
pub enum ServiceState {
    Registered,  // Registered but not yet dispatched
    Running,     // Actively dispatched by the scheduler
    Paused,      // Temporarily suspended; scheduler skips
    Unhealthy,   // Auto-paused after exceeding error threshold
    Retired,     // Permanently removed; terminal
}
```

### 6.3 Transition Rules

1. **Registered → Running**: Automatic on first tick dispatch.
2. **Running → Paused**: Operator command (`tidefs service pause <name>`).
3. **Paused → Running**: Operator command (`tidefs service resume <name>`).
4. **Running → Unhealthy**: Scheduler auto-detects when consecutive `TickReport.error`
   count exceeds `error_threshold` (default: 5 consecutive errors).
5. **Unhealthy → Running**: Operator command (`tidefs service reset <name>`).
   No automatic recovery to prevent flapping.
6. **Any non-terminal → Retired**: Operator command (`tidefs service retire <name>`)
   or feature gate toggled off.

### 6.4 ServiceDescriptor

Each service carries a descriptor for operator introspection:

```rust
pub struct ServiceDescriptor {
    pub name: &'static str,
    pub priority: ServicePriority,
    pub state: ServiceState,
    pub feature_gate: Option<&'static str>,
    pub error_threshold: u32,
    pub starvation_timeout_ms: u64,
    pub last_tick_at: Option<Instant>,
    pub total_cycles_run: u64,
    pub total_items_processed: u64,
    pub total_errors: u64,
}
```

## 7. Starvation Guarantee

### 7.1 Problem

BestEffort and Opportunistic services may be starved indefinitely under sustained
Critical + LatencySensitive load. Without a starvation guard, compaction can fall
behind, B-trees grow, and read latency degrades.

### 7.2 StarvationTracker

```rust
pub struct StarvationTracker {
    pub ms_since_last_tick: u64,
    pub starvation_timeout_ms: u64,
    pub forced_ticks: u64,
}
```

### 7.3 Starvation Prevention Algorithm

After normal dispatch completes:

```
dispatch_starved_services(cycle_report):
    for priority in [BestEffort, Opportunistic]:
        for service in registered_services.filter(state == Running):
            if service.starvation.ms_since_last_tick > starvation_timeout_ms:
                starvation_budget = ServiceBudget {
                    max_items: SERVICE_BUDGET_STARVATION_ITEMS,
                    max_bytes: 0,           // no byte limit during starvation tick
                    max_ms: SERVICE_BUDGET_STARVATION_MS,   // small time slice
                }
                tick_report = service.tick(starvation_budget)
                cycle_report.push(tick_report)
                service.starvation.reset()
```

The starvation tick budget is small (e.g., 100 items, 50ms). This ensures the starved
service makes progress without blowing the cycle budget. The starvation tick counts
against the service's normal budget for the next cycle.

### 7.4 Configurable Parameters

| Parameter | Default | Range | Description |
|-----------|---------|-------|-------------|
| `starvation_timeout_ms` | 60,000 | 5,000–600,000 | Time before forcing a tick |
| `starvation_tick_max_items` | 100 | 10–1,000 | Max items per starvation tick |
| `starvation_tick_max_ms` | 50 | 10–500 | Max ms per starvation tick |

## 8. Backpressure Integration

### 8.1 Demand Pressure Gauge

The FUSE daemon exposes a `demand_pressure` gauge (0.0–1.0) computed from:

```rust
pub fn compute_demand_pressure(
    fuse_queue_depth: u32,
    fuse_queue_capacity: u32,
    io_pending_bytes: u64,
    io_pending_capacity: u64,
) -> f64 {
    let queue_ratio = fuse_queue_depth as f64 / fuse_queue_capacity as f64;
    let io_ratio = io_pending_bytes as f64 / io_pending_capacity as f64;
    (queue_ratio.max(io_ratio) * PRESSURE_SMOOTHING).min(1.0)
}
```

`PRESSURE_SMOOTHING` is an exponential moving average factor (default: 0.3).

### 8.2 Budget Shrink

```
apply_demand_backpressure(global_budget, demand_pressure):
    if demand_pressure < LOW_PRESSURE_THRESHOLD:    // 0.0–0.3
        return global_budget                         // no shrink
    elif demand_pressure < HIGH_PRESSURE_THRESHOLD:  // 0.3–0.7
        shrink = demand_pressure                    // linear shrink
        return global_budget.fraction(shrink * 100, 100)
    else:                                            // >0.7 — critical
        return ServiceBudget::MAINTENANCE_TICK       // minimal background
```

### 8.3 Critical Grace Period

Critical services (scrub, repair) are exempt from budget shrink for
`critical_grace_ms` (default: 5,000ms) after demand pressure exceeds
`HIGH_PRESSURE_THRESHOLD`. After the grace period, Critical services also
receive the shrunk budget.

### 8.4 Pressure-Triggered Cycle Skip

If `demand_pressure > EMERGENCY_THRESHOLD` (default: 0.95), the scheduler
skips the entire cycle. No background service runs. This is the nuclear
option for extreme I/O saturation.

## 9. Health Monitoring and Circuit Breaking

### 9.1 HealthTracker

```rust
pub struct HealthTracker {
    pub consecutive_errors: u32,
    pub error_threshold: u32,
    pub total_errors: u64,
    pub total_ticks: u64,
    pub last_error: Option<ServiceError>,
    pub ms_since_last_success: u64,
}
```

### 9.2 Circuit Breaker

When `consecutive_errors >= error_threshold`, the scheduler transitions the
service from `Running` to `Unhealthy`. The service remains `Unhealthy` until
an operator issues `tidefs service reset <name>`.

### 9.3 Error Categories

```rust
pub enum ServiceError {
    IoError(std::io::ErrorKind),
    CorruptionDetected { block_id: u64, expected: Vec<u8>, actual: Vec<u8> },
    InvariantViolation { invariant: &'static str, detail: String },
    ResourceExhausted { resource: &'static str },
    InternalBug { file: &'static str, line: u32, detail: String },
}
```

Errors are rate-limited: only one `TickReport.error` is emitted per tick,
even if multiple errors occur.

## 10. Multi-Threaded Scheduling

### 10.1 BackgroundSchedulerPool

The pool introduces three phases per cycle:

1. **Plan** (`plan_cycle`): Single-threaded, fast. Determines which services to tick
   and with what budget. Produces `TickWorkItem` entries.
2. **Dispatch** (`dispatch_cycle`): Enqueues `TickWorkItem`s to worker local deques.
3. **Collect** (`collect_cycle`): Waits for workers to finish, aggregates `TickReport`s
   into a `CycleReport`.

```rust
pub struct BackgroundSchedulerPool {
    scheduler: BackgroundScheduler,          // planning state
    workers: Vec<WorkerHandle>,              // worker threads
    tick_queue: ConcurrentDeque<TickWorkItem>,
    report_queue: ConcurrentQueue<TickReport>,
    config: PoolConfig,
}
```

### 10.2 Worker Pool Sizing

| Available CPUs | Worker threads | Rationale |
|---------------|----------------|-----------|
| 1 | 1 | Degraded to inline; no concurrency benefit |
| 2–4 | 2 | Two workers handle I/O parallelism |
| 5–8 | 4 | Typical server deployment |
| 9–16 | min(8, cpus/2) | Leave cores for FUSE demand ops |
| 17+ | 8 | Diminishing returns for background I/O |

Each pool instance is per-pool. A daemon serving multiple pools creates one
`BackgroundSchedulerPool` per pool.

### 10.3 TickWorkItem

```rust
pub struct TickWorkItem {
    pub service_id: ServiceId,
    pub priority: ServicePriority,
    pub budget: ServiceBudget,
    pub starvation_tick: bool,   // true if this is a forced starvation tick
}
```

### 10.4 Work Stealing

When a worker's local deque is empty, it randomly selects a peer worker and
attempts to steal a `TickWorkItem` from the *back* of the peer's deque (Chase-Lev
work-stealing protocol). This minimizes contention: producers push/pop from the
front; stealers pop from the back.

### 10.5 Tick Isolation

Each `TickWorkItem` is self-contained: it carries its own budget and the service
instance (via `Arc<Mutex<dyn BackgroundService>>`). No two workers ever call
`tick()` on the same service simultaneously — the planning phase enforces this
by tracking per-service `tick_in_flight` flags.

### 10.6 FUSE Daemon Integration

```
fuse_event_loop():
    loop:
        // 1. Pre-cycle: COMMIT_GROUP tick + plan
        pool.plan_cycle(compute_global_budget())
        pool.dispatch_cycle()

        // 2. Process demand ops while workers run
        while !cycle_deadline_reached() && !pool.cycle_complete():
            fuse_op = fuse_chan.receive(timeout=remaining_cycle_time())
            handle_fuse_op(fuse_op)

        // 3. Collect results
        report = pool.collect_cycle(timeout=COLLECT_TIMEOUT)
        emit_observability(report)
```

If demand pressure is high, the daemon may skip `dispatch_cycle()` entirely.

## 11. Deterministic Replay Architecture

### 11.1 TickLog

Every scheduling decision is recorded:

```rust
pub struct TickLog {
    pub entries: Vec<TickLogEntry>,
    pub max_entries: usize,   // ring buffer cap (default: 10,000)
}

pub struct TickLogEntry {
    pub cycle_number: u64,
    pub timestamp: u64,       // logical clock tick
    pub service: &'static str,
    pub priority: ServicePriority,
    pub budget: ServiceBudget,
    pub outcome: TickReport,
    pub scheduler_decision: SchedulerDecision,
}
```

### 11.2 Capture Mode

When `BackgroundScheduler.capture_log` is `true`, every `tick()` call is recorded.
The captured `TickLog` can be serialized and replayed deterministically.

### 11.3 Replay Mode

In replay mode, the scheduler does not actually call `service.tick()`. Instead,
the recorded decisions. If a decision diverges, the replay fails with a
`SchedulerDivergence` error.

### 11.4 Trace Oracle Integration

The `TickLog` integrates with `tidefs-trace-oracle` for protocol-level correctness
testing. The trace oracle replays captured logs against a mock I/O layer and
asserts that every scheduling decision is reproducible.

## 12. Operator CLI Surface

### 12.1 Commands

```
tidefs service list                    # List all services with state, health, stats
tidefs service status <name>           # Detailed status for one service
tidefs service pause <name>            # Pause a service
tidefs service resume <name>           # Resume a paused service
tidefs service reset <name>            # Reset an unhealthy service to Running
tidefs service retire <name>           # Permanently retire a service

tidefs scheduler status                # Global scheduler stats + current cycle
tidefs scheduler set-budget <params>   # Override global budget
tidefs scheduler set-priority-weight <stage> <weight>  # Override stage weight
tidefs scheduler dump-log              # Dump TickLog to stdout (JSON)
tidefs scheduler replay-log <file>     # Replay a captured TickLog
```

### 12.2 Admin Protocol Integration

Commands are added to `AdminCommand` in `tidefs-types-admin-service-core`:

```rust
pub enum AdminCommand {
    // ... existing variants ...
    ServiceList,
    ServiceStatus { name: String },
    ServicePause { name: String },
    ServiceResume { name: String },
    ServiceReset { name: String },
    ServiceRetire { name: String },
    SchedulerStatus,
    SchedulerSetBudget { max_items: u64, max_bytes: u64, max_ms: u64 },
    SchedulerSetPriorityWeight { stage: ServicePriority, weight_pct: u8 },
    SchedulerDumpLog,
    SchedulerReplayLog { path: String },
}
```

## 13. Checkpoint Persistence

### 13.1 ServiceCheckpoint

```rust
pub struct ServiceCheckpoint {
    pub job_checkpoint: Checkpoint,        // cursor position
    pub state: ServiceState,               // lifecycle state
    pub health: HealthTracker,             // health snapshot
    pub starvation: StarvationTracker,     // starvation snapshot
}
```

This enables crash-consistent save/restore of the entire scheduler state across
daemon restarts.

### 13.2 Pool Export/Import

When a pool is exported, the scheduler drains all in-flight ticks:

```
pool.prepare_for_export():
    // 1. Pause all services (no new ticks planned)
    for svc in all_services:
        svc.set_state(ServiceState::Paused)

    // 2. Collect all in-flight ticks
    pool.collect_all(timeout=EXPORT_DRAIN_TIMEOUT)

    // 3. Persist all checkpoint state
    pool.persist_all_checkpoints()

    // 4. Shut down worker pool
    pool.shutdown()
```

## 14. Derived Catalog Lifecycle

### 14.1 Overview

Background services that produce derived views (view builder, rebake, compaction)
operate on a **derived catalog** — a separate B-tree instance from the authoritative
catalog.

### 14.2 Separation Rationale

- The authoritative catalog is read-heavy with smaller nodes (4 KiB).
- The derived catalog is write-heavy (build/evict cycles) and tombstone-heavy
  (compact cycles) with larger nodes (16 KiB).
- Separate B-tree instances prevent derived catalog compaction from creating
  write amplification on the authoritative catalog.
- Same B-tree code, different configuration.

### 14.3 Derived Catalog Operations

| Operation | Service | Frequency |
|-----------|---------|-----------|
| Build | View builder | On mount + on authoritative catalog change |
| Serve | View builder | Every FUSE readdir/lookup |
| Evict | View builder | When memory pressure exceeds threshold |
| Compact | Compaction | Every N cycles (tunable) |
| Convert | Rebake | Per ingest journal segment |

## 15. Crate Architecture

### 15.1 Dependency Graph

```
tidefs-types-incremental-job-core    (no_std, alloc)
    ↑
tidefs-incremental-job-core           (no_std, alloc)
    ↑
tidefs-background-scheduler           (no_std, alloc)
    ↑
    ├── tidefs-local-filesystem        (BackgroundReclaim, BackgroundCompaction,
    │                                    BackgroundOrphanReclamation)
    ├── tidefs-cleanup-job-core        (CleanupJob)
    ├── tidefs-reclaim-job-core        (ReclaimJob)
    ├── tidefs-orphan-recovery-job-…   (OrphanRecoveryJob)
    ├── tidefs-derived-catalog         (ViewBuilderService)   [Phase 5, pending]
    ├── tidefs-data-cleaner            (DataCleanerService)   [Phase 6, pending]
    └── tidefs-segment-cleaner         (SegmentCleanerService)[Phase 7, pending]
```

### 15.2 Crate Impact Summary

| Crate | Change for #1713 wire-up |
|-------|--------------------------|
| `tidefs-background-scheduler` | Add `ServiceState`, `StarvationTracker`, `HealthTracker`, `TickLog`, `ServiceDescriptor`, `BackgroundSchedulerPool` |
| `tidefs-types-incremental-job-core` | Add `ServiceCheckpoint`; no breaking changes to existing `IncrementalJob` trait |
| `tidefs-local-filesystem` | Update services to carry `ServiceDescriptor` |
| `apps/tidefs-posix-filesystem-adapter-daemon/src/runtime` | Add `demand_pressure` gauge; wire effective-budget computation |
| `tidefs-trace-oracle` | Add replay integration; connect `TickLog` |
| `tidefs-types-admin-service-core` | Add `AdminCommand::Service{Pause,Resume,Reset,Retire}` variants |

## 16. Implementation Plan

### 16.1 Completed Phases (1–4)

| Phase | Scope | Crate(s) |
|-------|-------|----------|
| **Phase 1: Core types** | `ServicePriority`, `ServiceBudget`, `TickReport`, `CycleReport` | `tidefs-types-incremental-job-core` |
| **Phase 2: Scheduler** | `BackgroundScheduler`, round-robin dispatch, budget cascading | `tidefs-background-scheduler` |
| **Phase 3: IncrementalJob bridge** | `IncrementalJobAdapter`, `JobKind`→Priority mapping | `tidefs-background-scheduler` |
| **Phase 4: Initial services** | `BackgroundReclaim`, `CleanupJob`, `OrphanRecoveryJob`, `ReclaimJob` | respective crates |

### 16.2 Pending Phases (5–16)

| Phase | Scope | Dependencies |
|-------|-------|-------------|
| **Phase 5: View builder** | `ViewBuilderService`, derived catalog build/serve/evict/compact | Phases 1-4 |
| **Phase 6: Data cleaner** | `DataCleanerService` processing refcount delta queues | Phases 1-4 |
| **Phase 7: Segment cleaner** | `SegmentCleanerService` reclaiming dead segments | Phases 1-4 |
| **Phase 8: FUSE integration** | Wire scheduler into FUSE daemon main loop with demand preemption | Phases 1-4 |
| **Phase 9: Compaction** | `CompactionService` for derived catalog and refcount B-tree | Phases 5-6 |
| **Phase 11: Lifecycle** | `ServiceState`, state transitions, `ServiceDescriptor`, feature-gate integration | Phases 1-4 |
| **Phase 12: Starvation** | `StarvationTracker`, starvation-prevention dispatch, configurable timeouts | Phase 11 |
| **Phase 13: Backpressure** | `demand_pressure` gauge, budget shrink, Critical grace period | Phase 11 |
| **Phase 14: Operator CLI** | `tidefs service *` commands, admin-protocol wire-up | Phases 11-12 |
| **Phase 15: Replay** | `TickLog`, capture/replay mode, trace-oracle integration | Phases 11-13 |
| **Phase 16: Multi-thread** | `BackgroundSchedulerPool`, work-stealing, tick isolation | Phases 11-13 |

## 17. Open Questions

1. **Starvation override threshold**: What is the right `starvation_timeout_ms` for
   BestEffort services? Too short and they compete with latency-sensitive work;
   too long and compaction falls behind. Proposed: 60s, tunable via pool property.

2. **Derived catalog persistence**: Should derived views survive a daemon crash?
   Surviving avoids cold-start latency but requires crash-consistent B-tree writes.
   and rebuild if inconsistent.

3. **Multi-pool scheduling**: When multiple pools share one daemon, should the
   scheduler be per-pool or global? Per-pool provides isolation; global provides
   fairness across pools. Proposed: per-pool `BackgroundSchedulerPool` instances
   with a global budget divided by pool weight.

4. **Service dependencies**: Some services depend on others (scrub → repair,
   rebake → segment cleaner). Should the scheduler enforce ordering? Proposed:
   no — each service is independent; dependencies are handled by the service
   detecting work via authoritative state (e.g., scrub writes findings; repair
   reads them).

5. **Budget auto-tuning**: Can the scheduler learn optimal budget splits from
   historical cycle data? Machine learning adds complexity and non-determinism.
   Proposed: static weights with operator override; revisit in v1.1.

6. **Should unhealthy services auto-recover after a cooldown?** Auto-recovery
   risks flapping (unhealthy → running → unhealthy). Proposed: manual reset only,
   with an optional `auto_reset_after_cycles` property (default: 0, meaning off).

7. **Should the TickLog be persisted to disk?** Persisting 10,000 cycles consumes
   ~10 MiB. This is small but adds write amplification to every cycle. Proposed:
   in-memory ring buffer; dump on operator request.

8. **Should workers be pin-able to cores?** Core pinning can improve cache locality.
   Proposed: defer to v1.1; initial implementation uses OS-thread scheduling.

9. **Planning thread vs. FUSE event loop thread**: If planning grows to >500µs
   (unlikely with <20 services), a dedicated planner thread could overlap planning
   with execution. Proposed: start inline on FUSE event loop; profile; add dedicated
   thread only if needed.

10. **Starvation tick budget accounting**: Should the starvation-prevention tick
    count against the service's normal budget? Proposed: yes, to maintain fairness;
    operator can increase global budget if starvation is frequent.

## 18. References

- [#1179] Initial background service framework design
- [#1592] Canonical design specification (Phase 1-4 implementation)
- [#1674] Design specification closure
- [#1624] Enhanced design: lifecycle, starvation, backpressure, CLI, replay
- [#1625] Multi-threaded work-stealing design
- [#1713] This document — definitive consolidated design spec
- [#1459] BackgroundReclaim service implementation
- [#1463] Reclaim delta recording integration
- [#1176] Cached directory/index views
- [#1180] Refcount delta cleanup queues
- [#1249] Erasure coding and placement
- [#1222] Rebake architecture
- [#1215] Space accounting and cleaner scheduling
- [#1241] Unified lane scheduling model
- [#1223] Polymorphic extent maps
- `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md` — #1179 initial spec
- `docs/design/background-service-framework-design.md` — #1592/#1674 canonical design
- `docs/design/background-service-framework-design-enhanced.md` — #1624 enhanced design
- `docs/design/background-service-framework-multithread-design.md` — #1625 multithread design
- `crates/tidefs-background-scheduler/src/lib.rs` — scheduler implementation (1,410 lines)
- `crates/tidefs-types-incremental-job-core/src/lib.rs` — `IncrementalJob` trait and types
- `docs/design/incremental-job-core-types-crate-design.md` — IncrementalJob type design
- `docs/design/unified-scheduling-classes-lane-priority-model.md` — lane scheduling design
- `docs/design/admin-service-wire-protocol.md` — admin protocol for CLI commands
- `docs/design/unified-resource-governor-design.md` — I/O lane allocation
- Chase-Lev, "Dynamic Circular Work-Stealing Deque", SPAA 2005
- Blumofe & Leiserson, "Scheduling Multithreaded Computations by Work Stealing", JACM 1999
