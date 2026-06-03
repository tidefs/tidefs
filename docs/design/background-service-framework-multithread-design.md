# Background Service Framework Multi-Threaded Scheduling Design (#1625)

Maturity: **design-spec** for transitioning the background service scheduler from
single-threaded inline dispatch to a multi-threaded work-stealing pool with tick
isolation, per-service ownership tokens, and deterministic replay readiness.

This document formalises phases 11a–11d deferred from the enhanced design spec
(#1608, `docs/design/background-service-framework-design-enhanced.md` §7). It
builds on the canonical design (#1592) and the scheduler implementation in
`crates/tidefs-background-scheduler/`.

**Source context:** #1179, #1592, #1608. Implementation deferred to wire-up issues.

## 1. Problem Statement

The current `BackgroundScheduler` executes all service ticks on the calling thread
(the FUSE daemon event loop thread). Each tick is synchronous: the scheduler calls
`service.tick(budget)`, waits for completion, collects the `TickReport`, and moves
to the next service. For short ticks (≤10ms), this is acceptable. For longer ticks
(B-tree compaction scanning 500 entries, deep scrub reading 64 MiB), this blocks
the event loop, increasing FUSE operation tail latency.

As TideFS adds more background services per the 10-phase plan (#1592 §15), the
aggregate tick time per cycle will grow. With 8+ services and a 100ms cycle time,
the FUSE daemon risks missing I/O deadlines. Multi-threaded scheduling is required
to decouple background throughput from foreground latency.

The following services are expected to be active simultaneously in a production pool:

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

With 9 services and a 100ms target cycle, serial dispatch cannot meet the budget.
Worse, a single slow tick from a BestEffort service delays a Critical service by
an entire cycle. Multi-threaded work-stealing solves both problems.

## 2. Design Overview

The design introduces a `BackgroundSchedulerPool` that decouples the scheduler's
planning phase (deciding which services to tick and with what budget) from the
execution phase (running ticks). Planning remains single-threaded and fast (O(n)
in registered services, <1ms). Execution is distributed across a fixed-size
worker pool that steals unfinished ticks from a shared concurrent queue.

```
┌─────────────────────────────────────────────────────────────────┐
│                    BackgroundSchedulerPool                       │
│                                                                 │
│  ┌──────────────────────┐    ┌──────────────────────────────┐  │
│  │   Planning Thread     │    │       Worker Pool            │  │
│  │   (FUSE event loop)   │    │                              │  │
│  │                      │    │  Worker 0: tick queue.dequeue│  │
│  │  plan_cycle(budget)  │    │  Worker 1: tick queue.dequeue│  │
│  │         │            │    │  Worker 2: tick queue.dequeue│  │
│  │  ┌──────▼───────┐    │    │  Worker 3: tick queue.dequeue│  │
│  │  │ TickWorkItem │    │    │                              │  │
│  │  │  queue       │────┼───▶│  Steal protocol: when idle,  │  │
│  │  └──────────────┘    │    │  steal from peer's local q   │  │
│  └──────────────────────┘    └──────────────────────────────┘  │
│                                                                 │
│  collect_reports() ◀──────────── Report queue                   │
│                                                                 │
│  Global budget split: per-tick ServiceBudget fragments          │
│  Work stealing: idle workers steal queued ticks                 │
│  Report aggregation: async collection with timeout              │
└─────────────────────────────────────────────────────────────────┘
```

### 2.1 Core Abstractions (New)

| Abstraction | Responsibility |
|-------------|---------------|
| `BackgroundSchedulerPool` | Owns the worker pool, global budget, service registry, and lifecycles |
| `TickWorkItem` | A unit of dispatch: service identifier + `ServiceBudget` fragment |
| `TickCompletion` | Result of one tick: `ServiceName` + `Result<TickReport, SchedulerError>` |
| `WorkerPool` | Fixed-size thread pool with work-stealing deque per worker |
| `TickQueue` | MPMC queue of `TickWorkItem` entries, drained by workers |
| `ReportCollector` | Aggregates `TickCompletion` results into `CycleReport` |

### 2.2 Lifecycle

```
  daemon start
      │
  pool = BackgroundSchedulerPool::new(num_threads, config)
      │
  pool.register(bg_compaction)
  pool.register(bg_reclaim)
  pool.register(bg_orphan_recovery)
  …
      │
  ── event loop ────────────────────────────────────────────
      │
  pool.plan_cycle(global_budget)   ← single-threaded, fast
      │
  pool.dispatch_cycle()            ← enqueues TickWorkItems
      │                              returns immediately
      │
  … handle FUSE demand ops …
      │
  pool.collect_cycle(timeout)      ← waits for workers
      │                              aggregates CycleReport
  ── loop ─────────────────────────────────────────────────
```

## 3. Thread Safety Model

### 3.1 Requirements

The multi-threaded scheduler must satisfy:

1. **No shared mutable state between services.** Each service owns its internal
   state. The scheduler is the sole mutator of `ServiceState` (lifecycle state machine
   from #1608 §2).
2. **Tick isolation.** Each `tick()` call operates on a snapshot of authoritative
   pool state captured at `plan_cycle()` time. Conflicts are resolved by validity
   tokens (§8 of #1592).
3. **Budget enforcement at worker granularity.** The global budget is subdivided
   per-`TickWorkItem` before enqueue. Workers self-limit to their fragment.
4. **Deterministic replay readiness.** All non-determinism must be captured in

### 3.2 Send + Sync Bounds

The `BackgroundService` trait acquires a `Send` bound. All existing service
implementations (`BackgroundReclaim`, `BackgroundCompaction`,
`BackgroundOrphanReclamation`, `BackgroundCleanup`) are already `Send`
because they own their incremental job state exclusively. The trait object
bound is formalised:

```rust
pub trait BackgroundService: Send {
    fn name(&self) -> &'static str;
    fn priority(&self) -> ServicePriority;
    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, SchedulerError>;
    fn has_work(&self) -> bool;
}
```

`Sync` is not required: two workers will never call `tick()` on the same service
simultaneously — the scheduler ensures each service has at most one in-flight tick.

### 3.3 Ownership Model

```
  ┌────────────┐
  │  Scheduler  │──── Arc<Mutex<ServiceState>> ──── (lifecycle tracking)
  └─────┬──────┘
        │ transfers ownership for tick duration
        ▼
  ┌────────────┐
  │  Worker     │──── &mut dyn BackgroundService ──── (tick() executes here)
  └─────┬──────┘
        │ returns ownership
        ▼
  ┌────────────┐
  │  Scheduler  │──── Box<dyn BackgroundService> ──── (service back in registry)
  └────────────┘
```

Before dispatching, the scheduler extracts the service from its `Box<dyn BackgroundService>`
slot in the registry (or, for `Arc<Mutex<>>` models, acquires the lock). The `TickWorkItem`
carries the extracted box. When the worker completes, it returns the box and the report to
the scheduler through the report channel.

**Why Box ownership transfer rather than Arc<Mutex<>>?**

| Approach | Pros | Cons |
|----------|------|------|
| `Arc<Mutex<Box<dyn BackgroundService>>>` | Stateless scheduler, services always accessible | Lock contention, deadlock risk, no exclusive &mut |
| **Box ownership transfer** (chosen) | No locks, exclusive &mut, compile-time safety | Must reconstruct Box after each tick; requires Send bound |

Ownership transfer is preferred because:
- It eliminates the possibility of deadlock (no locks on the hot path).
- It provides exclusive `&mut` access, satisfying Rust's aliasing guarantees without
  runtime checks.
- The overhead of moving a `Box` (one pointer swap) is negligible compared to tick
  execution time (milliseconds).
- The scheduler does not need to inspect service state mid-tick; lifecycle transitions
  (Pause, Unhealthy) are applied between ticks when the scheduler holds ownership.

### 3.4 Service State Lifecycle Under Concurrency

The `ServiceState` field (from #1608 §2) is stored separately from the service box
in an `Arc<Mutex<ServiceState>>` held by the scheduler. Workers never mutate service
state directly. The state transition protocol:

1. **Before tick**: Scheduler checks state. If `Running` or `Starving`, schedules tick.
   If `Paused`, `Unhealthy`, or `Retired`, skips.
2. **During tick**: Worker holds exclusive `&mut` to the service box. Service runs.
3. **After tick**: Worker returns service box + `TickReport` + error count.
   Scheduler receives the box, applies state transition:
   - If `TickReport.errors > 0` and `error_threshold` exceeded → `Unhealthy`
   - If `TickReport.has_more == false` and no more work → stays `Running`
   - If service reports completion → `Running` (next cycle: `has_work() == false`, skipped)

## 4. Work-Stealing Architecture

### 4.1 Worker Pool

The pool uses a fixed number of OS threads (default: `num_cpus::get()`). Each worker
has a local single-producer, multi-consumer (SPMC) deque and participates in the
global MPMC tick queue.

```rust
pub struct WorkerPool {
    /// Worker threads. Created at pool init, joined at pool drop.
    workers: Vec<JoinHandle<()>>,
    /// Per-worker local deques for work stealing.
    local_queues: Vec<Arc<WorkerDeque<TickWorkItem>>>,
    /// Global MPMC queue for initial dispatch.
    global_queue: Arc<CrossbeamQueue<TickWorkItem>>,
    /// Report collector — workers push TickCompletions here.
    report_tx: crossbeam::Sender<TickCompletion>,
    report_rx: crossbeam::Receiver<TickCompletion>,
    /// Shutdown signal.
    shutdown: Arc<AtomicBool>,
}
```

### 4.2 Worker Loop

```
worker_loop(worker_id, local_deque, global_queue, report_tx, shutdown):
    while !shutdown.load(Relaxed):
        item = None

        // 1. Try local deque first (LIFO for cache locality)
        item = local_deque.pop()

        // 2. Try global queue
        if item is None:
            item = global_queue.pop()

        // 3. Steal from sibling (random victim, FIFO for fairness)
        if item is None:
            victim = choose_random_worker()
            item = steal_from(victim.local_deque)

        if item is None:
            park()  // yield or park; woken on new work
            continue

        // Execute tick
        result = item.service.tick(&item.budget)
        report_tx.send(TickCompletion {
            service_name: item.service_name,
            service_box: item.service,
            result,
        })
```

### 4.3 Work-Stealing Protocol

Inspired by the Chase-Lev deque and the Tokio/Rayon work-stealing model:

```
Steal operation (victim):
    // Victim pushes at tail; stealer pops from head.
    // FIFO from stealer perspective = victim's oldest work first.
    return victim.deque.steal()
```

Work-stealing happens only when a worker's local deque and the global queue are both
empty. The stealer picks a random victim to avoid thundering-herd. If steal fails, the
worker parks until new work is enqueued or the shutdown flag is set.

### 4.4 Enqueue Protocol

When the scheduler calls `dispatch_cycle()`, it enqueues all `TickWorkItem`s into the
global queue. Workers are notified via a condition variable. Additionally, items are
evenly distributed across local deques to reduce global queue contention:

```
dispatch_cycle():
    items = plan_cycle()  // ordered by priority, round-robin within stage
    for i, item in enumerate(items):
        // Distribute round-robin across local deques
        local_queues[i % num_workers].push(item)
    wake_all_workers()
```

### 4.5 Priority Ordering Under Concurrency

The scheduler preserves priority ordering even though ticks execute concurrently:

1. **Planning preserves order**: `plan_cycle()` produces an ordered list of
   `TickWorkItem` entries (Critical first, Opportunistic last).
2. **Enqueue order**: Items are distributed round-robin across worker local deques
   in the order produced by `plan_cycle()`. This means worker 0 gets items at indices
   0, W, 2W, …; worker 1 gets 1, W+1, 2W+1, ….
3. **Relaxed execution order**: Workers process their local deques in LIFO order
   (most recently enqueued first), which is fine because:
   - Higher-priority items are enqueued first and will be dequeued (by some worker)
     soon.
   - A Critical tick started slightly after a BestEffort tick will still complete
     and report before the BestEffort tick matters operationally.
   - The scheduler does not depend on exact tick ordering within a cycle — it only
     requires that Critical services are never starved.

If **strict intra-stage ordering** is required (e.g., Scrub before Repair), the
scheduler can enforce it by not enqueuing Repair until Scrub's tick completes.
This is a per-stage configuration option.

## 5. Budget Enforcement

### 5.1 Global Budget Split

The `plan_cycle()` method takes a global `ServiceBudget` and produces per-tick budget
fragments:

```rust
pub fn plan_cycle(&self, global: &ServiceBudget) -> Vec<TickWorkItem> {
    let mut items = Vec::new();
    let mut remaining = *global;

    // For each priority stage (Critical → Opportunistic):
    for stage in ServicePriority::ALL {
        let stage_weight = self.weights.stage_weight(stage);
        let stage_budget = ServiceBudget {
            max_items: (global.max_items as f64 * stage_weight) as u64,
            max_bytes: (global.max_bytes as f64 * stage_weight) as u64,
            max_ms: (global.max_ms as f64 * stage_weight) as u64,
        };

        let active: Vec<_> = self.services_at(stage)
            .filter(|s| s.has_work() && s.state == ServiceState::Running)
            .collect();

        if active.is_empty() {
            continue;
        }

        // Equal split per service in this stage (capped)
        let per_service = ServiceBudget {
            max_items: stage_budget.max_items / active.len() as u64,
            max_bytes: stage_budget.max_bytes / active.len() as u64,
            max_ms: stage_budget.max_ms / active.len() as u64,
        };

        for svc in active {
            items.push(TickWorkItem {
                service_name: svc.name(),
                service_box: /* extract box from registry */,
                budget: per_service,
                priority: stage,
                starvation_tick: false,
            });
        }

        // Unused budget cascades to next stage
        // Track actual consumption in collect_cycle()
    }

    items
}
```

### 5.2 Budget Fragments and Starvation Prevention

Starvation-prevention ticks (from #1608 §5) receive a separate budget allocation
that does not come from the normal per-stage budget:

```rust
pub fn plan_cycle(&self, global: &ServiceBudget) -> Vec<TickWorkItem> {
    let mut items = Vec::new();
    let mut remaining = *global;

    // Before normal budget split, allocate starvation-prevention budget.
    let starved_services: Vec<_> = self.find_starved_services();
    let starvation_budget = ServiceBudget::starvation_fraction(global);

    for svc in starved_services {
        items.push(TickWorkItem {
            service_name: svc.name(),
            service_box: /* ... */,
            budget: starvation_budget,
            priority: svc.priority(),
            starvation_tick: true,
        });
        remaining = remaining.saturating_sub(&starvation_budget);
    }

    // Normal budget split from remaining
    // ...
}
```

### 5.3 Budget Overrun Detection

Workers self-limit to their budget fragment. If a worker detects the service exceeded
its budget (checked by comparing pre-tick counters to post-tick `TickReport.items_consumed`),
it emits a `BudgetViolation` error. The scheduler records the violation and may truncate
the service's next budget as a penalty.

## 6. Checkpoint Persistence Under Concurrency

### 6.1 Write Serialisation

Checkpoint persistence is the only write path in the tick lifecycle that requires
serialisation. The `persist_checkpoint()` call must happen after every tick before
the next tick of the same service begins. Under multi-threaded execution:

- Each service's tick is executed by one worker at a time (guaranteed by ownership
  transfer — the service box is not in the scheduler while a worker holds it).
- The next cycle's `plan_cycle()` will not produce a `TickWorkItem` for a service
  whose box is still held by a worker (the scheduler waits for all completions in
  `collect_cycle()`).
- Checkpoint persistence is therefore naturally serialised per-service.

However, multiple workers may persist checkpoints for *different* services
simultaneously. The checkpoint persistence layer must support concurrent writes.
If the underlying storage is a single-writer resource (e.g., a journal), the
scheduler provides a `CheckpointWriter` with an internal `Mutex`:

```rust
pub struct CheckpointWriter {
    inner: Mutex<Box<dyn CheckpointPersist>>,
}
```

Workers call `checkpoint_writer.persist(&checkpoint)?` which acquires the lock,
writes, and releases. The lock is held for the duration of one disk write (~100µs
with an NVMe device), so contention is negligible with ≤8 workers.

### 6.2 Crash Consistency

Checkpoint writes are crash-atomic: either the old checkpoint or the new checkpoint
is on disk after a crash, never a partial write. The implementation writes to a
staging area, issues `fdatasync`, then atomically renames or swaps the checkpoint
file. This is independent of the thread model.

## 7. Deterministic Replay

### 7.1 The Non-Determinism Problem

Multi-threaded execution introduces non-determinism from the OS scheduler:
tick ordering, thread interleaving, and I/O completion ordering. Deterministic
replay requires capturing the exact order of events that occurred during a run.

### 7.2 TickLog Extension

The `TickLog` from #1608 §6 is extended with interleaving information:

```rust
/// Per-cycle event log for deterministic replay.
pub struct CycleEventLog {
    /// Cycle number.
    pub cycle: u64,
    /// Global budget at start of cycle.
    pub global_budget: ServiceBudget,
    /// Plan: which services were scheduled, in what order, with what budget.
    pub plan: Vec<TickWorkItem>,
    /// Per-tick completions in the order they completed (not were enqueued).
    pub completions: Vec<TickCompletion>,
    /// Worker-to-tick assignment: (worker_id, service_name, start_instant).
    pub assignments: Vec<(u8, &'static str, Instant)>,
}
```

### 7.3 Replay Protocol

For deterministic replay, the `TickLog` from the production run is replayed:

1. **Capture mode**: The scheduler records the full `CycleEventLog` for every cycle.
2. **Replay mode**: The scheduler replays cycles one at a time, using the recorded
   worker assignments and budgets. Workers are simulated (single-threaded, in the
   recorded completion order) with deterministic I/O mocks.
3. **Divergence detection**: After each tick, the replay compares the actual
   `TickReport` against the recorded `TickReport`. Any mismatch is a divergence.

Full deterministic replay across threads (phase 11d) requires the deterministic
simnet (#1249) to control thread scheduling. Until then, replay is single-threaded
with recorded interleaving order — sufficient for protocol correctness testing.

## 8. Integration with Existing Scheduler

### 8.1 Gradual Transition

The `BackgroundSchedulerPool` is introduced alongside the existing single-threaded
`BackgroundScheduler`. The daemon can choose which backend to use:

```rust
pub enum SchedulerBackend {
    /// Single-threaded inline scheduler (current, stable).
    Inline(BackgroundScheduler),
    /// Multi-threaded work-stealing pool (new).
    Pooled(BackgroundSchedulerPool),
}
```

The `BackgroundScheduler` continues to work exactly as before for:
- Development and debugging (single-threaded is easier to reason about).
- Single-pool, low-service-count deployments.

The `BackgroundSchedulerPool` is enabled via a feature flag
(`features.background_thread_pool`) and is the default for production deployments.

### 8.2 Crate Boundaries

```
tidefs-types-incremental-job-core    (no_std, alloc)  — unchanged
    ↑
tidefs-incremental-job-core          (no_std, alloc)  — unchanged
    ↑
tidefs-background-scheduler          (no_std, alloc)  — +Send bound on trait
    ↑
tidefs-background-scheduler-pool     (std)            — new crate
    ↑
apps/tidefs-posix-filesystem-adapter-daemon/src/runtime  — switches to Pooled backend
```

### 8.3 No-Std Compatibility

The existing `tidefs-background-scheduler` crate is `no_std` with `alloc`.
The multi-threaded pool crate (`tidefs-background-scheduler-pool`) requires
`std` for threads, channels, and synchronisation primitives. The `no_std`
crate is unaffected — the `Send` bound addition is compatible with `no_std`.

## 9. Configurable Knobs

| Configuration | Default | Meaning |
|---------------|---------|---------|
| `background_pool.num_threads` | `num_cpus` | Number of worker threads in the pool |
| `background_pool.max_tick_ms` | 200 | Max wall-clock duration of a single tick (soft) |
| `background_pool.collect_timeout_ms` | 500 | Max wait for all workers to finish a cycle |
| `background_pool.steal_attempts` | 3 | Number of steal attempts before parking |
| `background_pool.priority_strict` | false | If true, enforce strict intra-stage ordering (§4.5) |
| `background_pool.checkpoint_writer_threads` | 1 | Number of checkpoint writer threads (0 = inline) |
| `background_pool.replay_capture` | false | Enable `CycleEventLog` capture for deterministic replay |

## 10. Error Handling

### 10.1 Worker Panic Recovery

A panicking tick must not crash the daemon. The `catch_unwind` boundary is placed
at the worker level:

```rust
fn execute_tick(item: TickWorkItem) -> TickCompletion {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        item.service.tick(&item.budget)
    }));

    match result {
        Ok(tick_result) => TickCompletion {
            service_name: item.service_name,
            service_box: item.service,
            result: tick_result,
        },
        Err(panic_payload) => TickCompletion {
            service_name: item.service_name,
            service_box: item.service,
            result: Err(SchedulerError::ServicePanicked {
                service_name: item.service_name,
                panic_info: format!("{:?}", panic_payload),
            }),
        },
    }
}
```

A panicking service is marked `Unhealthy` and removed from future dispatch cycles.
The `ServicePanicked` error variant is added to `SchedulerError`.

### 10.2 Stuck Worker Detection

If a worker does not complete its tick within `max_tick_ms * 2`, the scheduler
considers it stuck. A stuck worker:
1. Has its service marked `Unhealthy`.
2. Logs a `SchedulerAlert::WorkerStuck` event.
3. May be terminated (kill the thread) in a future version with process-level
   recovery. For v1.0, stuck workers are non-recoverable and require a daemon
   restart.

### 10.3 Poisoned Service Recovery

If a service's internal state becomes corrupted (e.g., B-tree invariant violation),
the service returns `SchedulerError::ServiceFailed`. The scheduler's response depends
on `required_for_health`:

- If `required_for_health == true`: Emit `SchedulerAlert::CriticalServiceFailed`.
  The pool is not shut down; other services continue. The operator must decide
  whether to continue or restart.
- If `required_for_health == false`: Mark service `Unhealthy`, continue.

## 11. Observability

### 11.1 New Metrics

Extending the #1608 observability model:

| Metric | Type | Description |
|--------|------|-------------|
| `scheduler.pool.workers_active` | Gauge | Number of workers currently executing ticks |
| `scheduler.pool.workers_parked` | Gauge | Number of workers waiting for work |
| `scheduler.pool.steals_total` | Counter | Total work-steal operations since daemon start |
| `scheduler.pool.steals_successful` | Counter | Successful steal operations |
| `scheduler.pool.tick_queue_depth` | Gauge | Number of ticks in the global queue |
| `scheduler.pool.cycle_plan_us` | Histogram | Microseconds spent in `plan_cycle()` |
| `scheduler.pool.cycle_collect_us` | Histogram | Microseconds spent in `collect_cycle()` |
| `scheduler.pool.worker_stuck` | Counter | Number of times a worker was detected as stuck |
| `scheduler.pool.service_panics` | Counter | Number of service panics caught |

### 11.2 Operator Commands

Extending the operator CLI from #1608 §8:

```
tidefs pool status --background-threads   → Show worker pool state
tidefs pool config set background_pool.num_threads=4
tidefs pool config set background_pool.priority_strict=true
```

## 12. Performance Budgets

| Scenario | Budget | Metric |
|----------|--------|--------|
| Cycle plan (9 services) | <100µs | `cycle_plan_us` p99 |
| Cycle collect (all ticks done) | <50µs | `cycle_collect_us` p99 |
| Tick queue enqueue | <10µs | per `dispatch_cycle()` |
| Worker steal | <5µs | uncontended case |
| Box ownership transfer | <1µs | pointer swap |
| Per-tick checkpoint write | <200µs | NVMe, single writer |

The overhead of the multi-threaded model relative to single-threaded is:
- 100–200µs per cycle for planning, enqueuing, and collecting.
- Zero overhead for services that are idle (skipped in `plan_cycle()`).
- Amortised net gain of 5–10× when ≥3 services have work, because ticks
  execute in parallel.

## 13. Implementation Plan

The implementation is split into four sub-phases, corresponding to 11a–11d
from #1608:

| Phase | Scope | Dependencies | Risk |
|-------|-------|-------------|------|
| **Phase 11a**: Send + Sync bounds | Add `Send` bound to `BackgroundService` trait; verify all implementors are `Send`; add compile-time `assert_send` tests | Phases 1-4 complete | Low |
| **Phase 11b**: Worker pool | `BackgroundSchedulerPool`, `WorkerPool`, `TickQueue`, `TickWorkItem`, `TickCompletion`, `ReportCollector`, work-stealing deques | Phase 11a | Medium |
| **Phase 11c**: Ownership model | Box ownership transfer on dispatch/collect; `ServicePanicked` error; stuck worker detection; concurrent checkpoint persistence | Phase 11b | Medium |
| **Phase 11d**: Deterministic replay | `CycleEventLog`, capture/replay mode, recorded interleaving, divergence detection | Phase 11c + simnet (#1249) | High |

### 13.1 Crate Impact

| Crate | Change |
|-------|--------|
| `tidefs-background-scheduler` | Add `Send` bound to `BackgroundService`; no other changes |
| `tidefs-background-scheduler-pool` | **New crate**: `BackgroundSchedulerPool`, `WorkerPool`, work-stealing |
| `tidefs-types-incremental-job-core` | Add `SchedulerError::ServicePanicked` variant |
| `apps/tidefs-posix-filesystem-adapter-daemon/src/runtime` | Feature-flag switch between Inline and Pooled backends |

## 14. Tradeoffs

### 14.1 Box Ownership Transfer vs. Arc<Mutex<>>

**Decision: Box ownership transfer.**

| Criteria | Box ownership | Arc<Mutex<>> |
|----------|--------------|--------------|
| Deadlock risk | None | Low (two services never depend on each other) |
| Lock contention | None | Moderate (scheduler inspects state between ticks) |
| Memory overhead | 8 bytes (Box) | 16-24 bytes (Arc + Mutex) |
| Multi-tick concurrency of same service | Not supported (by design) | Supported (but would require per-tick queue) |
| Rust safety | Compile-time exclusive &mut | Runtime Mutex guard |

Box ownership transfer is simpler, safer, and sufficient because the framework
explicitly prohibits concurrent ticks on the same service. Multi-tick concurrency
within a single service (phase 11e, deferred to v2.0) would require per-service
internal work queues, which is a fundamentally different model.

### 14.2 Fixed Pool Size vs. Dynamic Scaling

**Decision: Fixed pool size.**

- Fixed pool size eliminates thread creation/destruction overhead.
- The number of background services is bounded: at most ~12 in any deployment.
- A 4–8 worker pool provides ample parallelism without oversubscription.
- Dynamic scaling adds complexity (measuring demand, deciding when to add/remove
  threads) with no clear benefit for this workload.

### 14.3 Crossbeam vs. std::sync

**Decision: Use `crossbeam` for MPMC queues; `std::sync` for atomics and Arc.**

- `crossbeam::queue::ArrayQueue` provides bounded MPMC with no allocation per
  operation — ideal for `TickQueue` and report channels.
- `crossbeam::deque` provides the Chase-Lev work-stealing deque.
- `std::sync::Arc` and `std::sync::atomic` are sufficient for the simple
  synchronisation needs (shutdown flag, service state).
- This avoids pulling in a full async runtime (Tokio) or thread pool (Rayon)
  for a use case that benefits from custom scheduling.

### 14.4 Single Checkpoint Writer vs. Per-Thread Writers

**Decision: Single checkpoint writer thread (phase 1).**

- A single writer eliminates coordination and preserves write ordering.
- Workload: one `persist_checkpoint()` call per tick per service, each ~200µs.
  With 9 services cycling at 100ms, that's 9 writes/100ms = 90 IOPS — trivial.
- If checkpoint write latency becomes a bottleneck (e.g., on rotational media),
  phase 2 could introduce a per-thread staging buffer with batch flush.

## 15. Interaction with Other Subsystems

### 15.1 Unified Resource Governor

The pool queries the unified resource governor's `background_lane_available()`
before each cycle (§13.1 of #1608). Under high demand pressure, the effective
global budget is shrunk proportionally. Each worker enforces its fragment
independently — the governor does not need to be thread-aware.

### 15.2 COMMIT_GROUP State Machine

COMMIT_GROUP ticks remain a pre-cycle, single-threaded operation (§5.4 of #1592). The
scheduler calls `commit_group.tick()` in `plan_cycle()` before producing any
`TickWorkItem`s. If the COMMIT_GROUP initiates a sync, the scheduler reduces
`global_budget.max_bytes` by 50% for that cycle.

### 15.3 FUSE Daemon Integration

The FUSE daemon event loop calls `pool.plan_cycle()` and `pool.dispatch_cycle()`
at the start of each background cycle, then handles FUSE demand ops while
workers execute ticks. At the end of the cycle (or when demand pressure spikes),
it calls `pool.collect_cycle(timeout)`.

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

If demand pressure is high (queue depth > threshold), the daemon may skip
`dispatch_cycle()` entirely, or dispatch with a zero budget
(`ServiceBudget::PAUSED`), deferring all background work.

### 15.4 Pool Export/Import

When a pool is exported, the scheduler must drain all in-flight ticks:

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

## 16. Open Questions

1. **Should the pool be per-pool or global?** If a daemon serves multiple pools,
   should each pool have its own thread pool or share one? Recommendation:
   per-pool `BackgroundSchedulerPool` instances, each with `min(4, num_cpus / num_pools)`
   threads. Shared pool risks one pool's I/O-heavy scrub starving another pool's
   latency-sensitive view builder.

2. **Should the scheduler use a dedicated planning thread?** The current design
   runs `plan_cycle()` on the FUSE event loop thread. If planning grows to
   >500µs (unlikely with <20 services), a dedicated planner thread could overlap
   planning with execution. Recommendation: start inline; profile; add dedicated
   thread only if needed.

3. **How to handle services that become slower under load?** A service that
   normally takes 10ms might take 100ms under heavy I/O load. The pool's
   `max_tick_ms` is a soft limit — workers do not preempt. Recommendation:
   add a `max_tick_ms` budget dimension that the service itself enforces
   (same contract as `WorkBudget.max_ms`). If the service cannot self-limit,
   the scheduler records the overrun and may reduce its budget in future cycles.

4. **Should workers be pin-able to cores?** Core pinning can improve cache
   locality for services that touch large data structures. Recommendation:
   defer to v1.1; the initial implementation uses OS-thread scheduling.

5. **What happens when the number of services exceeds the number of workers?**
   This is the normal case (9+ services, 4 workers). The scheduler plans all
   services in priority order, distributes them across workers, and un-executed
   ticks sit in worker deques until workers become available. This is correct:
   it's a work queue, not a real-time scheduler.

## 17. References

- [#1179] Initial background service framework design
- [#1592] Canonical design specification
- [#1608] Enhanced design: lifecycle, starvation, backpressure, CLI, replay
- [#1249] Deterministic cluster simnet for protocol correctness testing
- `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md` — #1179 design spec
- `docs/design/background-service-framework-design.md` — #1592 canonical design
- `docs/design/background-service-framework-design-enhanced.md` — #1608 enhanced design
- `crates/tidefs-background-scheduler/src/lib.rs` — scheduler implementation (1319 lines)
- `crates/tidefs-types-incremental-job-core/src/lib.rs` — IncrementalJob core types
- `crates/tidefs-incremental-job-core/src/lib.rs` — IncrementalJob trait
- `docs/design/deterministic-trace-oracle-system.md` — trace oracle for replay
- `docs/design/unified-resource-governor-design.md` — I/O lane allocation
- Chase-Lev, "Dynamic Circular Work-Stealing Deque", SPAA 2005
- Blumofe & Leiserson, "Scheduling Multithreaded Computations by Work Stealing", JACM 1999
