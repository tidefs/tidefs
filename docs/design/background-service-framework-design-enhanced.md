# Background Service Framework Design Enhanced (#1624)

Maturity: **design-spec** for the enhanced background service framework: service
lifecycle state machine, starvation guarantees, backpressure integration, deterministic
replay architecture, operator CLI surface, and multi-thread readiness.

This document extends the canonical design in #1592
(`docs/design/background-service-framework-design.md`) and the original #1179 spec
(`docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md`). It formalises the enhancements
required to graduate the framework from single-threaded inline scheduling to a
production-grade background work engine with operator visibility, deterministic

**Source context:** #1592, #1179, implemented phases 1-4 in
`crates/tidefs-background-scheduler/` and `crates/tidefs-local-filesystem/`.

## 1. Enhancement Scope

The #1592 design delivers a working priority-ordered scheduler with budget enforcement,
round-robin fairness, and IncrementalJob integration. Four production services already
run on it: `BackgroundCompaction`, `BackgroundOrphanReclamation`, `BackgroundReclaim`,
and `BackgroundCleanup`. The framework is correct but minimal — it lacks the
production-grade machinery needed for a daemon that may run for months without restart.

This enhancement adds:

| Enhancement | Motivation |
|------------|-----------|
| Service lifecycle state machine | Operators need to pause/resume/retire services without restart |
| Starvation guarantee with configurable timeout | BestEffort services must never be starved indefinitely |
| Backpressure from foreground demand | Heavy FUSE load must shrink background budgets automatically |
| Deterministic replay harness | Protocol-level correctness testing across scheduling decisions |
| Operator CLI surface | `tidefs service pause scrub`, `tidefs service status` etc. |
| Concurrency readiness model | Path from single-threaded inline to multi-threaded work-stealing |
| Health monitoring and circuit breaking | Auto-pause failing services; prevent cascading failures |

## 2. Service Lifecycle State Machine

### 2.1 States

Every `BackgroundService` implementor moves through a defined lifecycle.

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

### 2.2 State Transition Rules

```rust
/// Lifecycle state for a managed background service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceState {
    /// Registered but not yet dispatched. First tick promotes to Running.
    Registered,
    /// Actively dispatched by the scheduler.
    Running,
    /// Temporarily suspended. Scheduler skips. Resumable.
    Paused,
    /// Automatically paused after exceeding error_threshold.
    /// Requires operator intervention to reset to Running.
    Unhealthy,
    /// Permanently removed. Scheduler ignores. Terminal.
    Retired,
}
```

Transition rules:

1. **Registered → Running**: Automatic on first tick dispatch.
2. **Running → Paused**: Operator command (`tidefs service pause <name>`).
3. **Paused → Running**: Operator command (`tidefs service resume <name>`).
4. **Running → Unhealthy**: Scheduler auto-detection after `error_threshold`
   consecutive `TickReport` results where `errors > 0`.
5. **Unhealthy → Running**: Operator command (`tidefs service reset <name>`).
   Manual reset required because the underlying problem (disk failure, corrupt
   metadata) must be diagnosed before re-enabling.
6. **Running → Retired**: Operator command or feature-gate off. Terminal.

### 2.3 Scheduler Integration

The scheduler's `run_cycle` checks `ServiceState` before dispatch:

```
for service in services_by_priority:
    match service.state():
        ServiceState::Running | ServiceState::Registered => dispatch(service)
        ServiceState::Paused | ServiceState::Unhealthy => skip(service)
        ServiceState::Retired => continue
```

Paused and Unhealthy services are counted in `CycleReport.services_skipped` with
a reason tag (`paused` / `unhealthy`), enabling operator dashboards to distinguish
idle from suspended.

## 3. Starvation Guarantee

### 3.1 Problem

The #1592 five-stage priority model drains higher-priority stages completely before
lower stages. If a Critical service (e.g., scrub) generates unbounded work, BestEffort
and Opportunistic services may never run. Compaction and tombstone GC would stall
indefinitely, causing unbounded metadata bloat.

### 3.2 Solution: Starvation Timeout with Priority Inversion

Each service tracks `ticks_since_last_dispatch`. When a lower-priority service exceeds
`starvation_timeout_ticks`, the scheduler temporarily inverts its priority:

```rust
/// Starvation tracking per service.
pub struct StarvationTracker {
    /// Tick counter since last dispatch.
    pub ticks_since_last_dispatch: u64,
    /// Tick at which starvation kicks in.
    pub starvation_timeout_ticks: u64,
    /// Whether this service is currently in starvation-priority-inversion mode.
    pub starved: bool,
}
```

Algorithm (in `run_cycle`):

```
// Phase 1: Normal priority-ordered dispatch (unchanged from #1592)
for priority in [Critical .. Opportunistic]:
    dispatch_services_at(priority)

// Phase 2: Starvation-prevention dispatch
for service in all_services:
    if service.starvation_tracker.starved:
        dispatch_one_tick(service, starvation_budget)
        service.starvation_tracker.starved = false
```

### 3.3 Configurable Timeouts by Stage

| Stage | Default `starvation_timeout_ticks` | Rationale |
|-------|----------------------------------|-----------|
| Critical | N/A (always dispatched first) | Authority work cannot starve |
| LatencySensitive | 100 | Cache staleness degrades user latency |
| Throughput | 300 | Bulk work can tolerate moderate delay |
| BestEffort | 60 | Compaction must run eventually; shorter timeout to prevent metadata bloat |
| Opportunistic | 600 | Prefetch is optional; longest timeout |

The `starvation_budget` for an inverted-priority tick is `ServiceBudget::SMALL_TICK`
(`max_items: 100, max_bytes: 16 MiB, max_ms: 50`). A starved service gets exactly one
small tick per cycle until its starvation flag clears. This prevents a starved-but-heavy
service from monopolising the scheduler.

### 3.4 Interaction with Budget Cascading

Starvation-prevention ticks are charged against `remaining_budget` and reduce the
budget available for normal dispatch in the next cycle. The scheduler records
`starvation_ticks_this_cycle` in `CycleReport` for operator visibility.

## 4. Backpressure from Foreground Demand

### 4.1 Problem

The scheduler's `run_cycle` is called from the FUSE daemon main loop between demand
operations. Under heavy FUSE load, demand ops arrive faster than the scheduler can
complete a full cycle. Running `ServiceBudget::DEFAULT_TICK` when demand ops are
queued would add latency to the request path.

### 4.2 Solution: Demand-Pressure Budget Shrink

The daemon main loop tracks a `demand_pressure` gauge (0.0–1.0) derived from:

- `demand_queue_depth` / `demand_queue_high_watermark`
- Time since last demand op completion (exponential moving average)

Before calling `run_cycle`, the daemon computes an effective budget:

```rust
fn effective_budget(demand_pressure: f64, base: ServiceBudget) -> ServiceBudget {
    if demand_pressure < 0.2 {
        base  // low demand: full budget
    } else if demand_pressure < 0.5 {
        base.scale(0.5)  // moderate demand: halve
    } else if demand_pressure < 0.8 {
        ServiceBudget::SMALL_TICK  // high demand: small tick
    } else {
        // extreme demand: skip cycle entirely
        ServiceBudget::exhausted()
    }
}
```

The scheduler receives this effective budget and distributes it normally. This
ensures background work never adds more than 5-10% latency overhead during
demand saturation.

### 4.3 Grace Period for Critical Services

Even under extreme demand pressure (`demand_pressure >= 0.8`), Critical services
are allowed a single `SMALL_TICK` per `critical_grace_interval_cycles` (default: 10).
This prevents repair/intent-log sync from stalling indefinitely under sustained load.

## 5. Deterministic Replay Architecture

### 5.1 Motivation

Background scheduling is a source of nondeterminism: the order of service ticks
depends on timing (demand pressure, I/O latency, timer granularity). Protocol-level
correctness testing (`tidefs-trace-oracle`) requires deterministic replay of
background work so that golden traces are reproducible.

### 5.2 Design: Tick-Log Capture and Replay

The scheduler is extended with a `TickLog` that records every scheduling decision:

```rust
/// A deterministic record of one scheduling cycle.
pub struct TickLogEntry {
    /// Monotonic cycle counter.
    pub cycle: u64,
    /// Demand pressure at cycle start.
    pub demand_pressure: f64,
    /// Effective budget used for this cycle.
    pub effective_budget: ServiceBudget,
    /// Per-service dispatch order and outcomes.
    pub dispatches: Vec<ServiceDispatchRecord>,
}

pub struct ServiceDispatchRecord {
    pub service_name: &'static str,
    pub budget_given: ServiceBudget,
    pub tick_report: TickReport,
}
```

In **capture mode**, the scheduler appends a `TickLogEntry` to a ring buffer
(bounded: last 10,000 cycles). In **replay mode**, the scheduler reads
`TickLogEntry` records and replays the exact same dispatch order, service
budget splits, and tick outcomes.

Replay mode skips the priority/demand-pressure logic and instead follows the
recorded dispatches verbatim. If a replay tick produces a different `TickReport`
than recorded, the trace oracle flags a divergence.

### 5.3 Service Determinism Contract

For replay to work, every `BackgroundService::tick` must be deterministic:

```
Given:
  - identical service state (checkpoint, cursor)
  - identical ServiceBudget
  - deterministic I/O (or mocked I/O in replay mode)
Then:
  - tick() produces identical TickReport
```

The `IncrementalJobAdapter` already enforces this by forwarding budget to
`IncrementalJob::run_step`, which is bounded by design. Services that use
real I/O in production are given a `MockFileSystem` trait object in replay mode.

## 6. Operator CLI Surface

### 6.1 Commands

```
tidefs service list                     # List all registered services with state
tidefs service status <name>            # Detailed status for one service
tidefs service pause <name>             # Pause a service (Running → Paused)
tidefs service resume <name>            # Resume a paused service (Paused → Running)
tidefs service reset <name>             # Reset unhealthy service (Unhealthy → Running)
tidefs service retire <name>            # Permanently retire (→ Retired)
tidefs service stats [--watch]          # Live scheduler statistics
tidefs scheduler cycle                  # Force one scheduler cycle (operator trigger)
tidefs scheduler budget <items> <bytes> <ms>  # Override global budget
```

### 6.2 Output Format

`tidefs service list`:

```
SERVICE                   STATE       PRIORITY        LAST TICK    HAS WORK
scrub                     Running     Critical        0.3s ago     yes
dirview-builder           Running     LatencySens     2.1s ago     no
data-cleaner              Paused      Throughput      45s ago      yes
segment-compaction        Unhealthy   BestEffort      12m ago      —
prefetch-readahead        Running     Opportunistic   1.2s ago     no
```

`tidefs service status scrub`:

```
Service: scrub
  State:       Running
  Priority:    Critical (stage 1/5)
  Ticks run:   1,247,892
  Last tick:   0.3s ago
  Errors:      0 (consecutive: 0, threshold: 10)
  Starvation:  not starved (last dispatch: 0.3s ago, timeout: N/A)
  Budget used: 847 items, 12.3 MiB, 4.2ms (avg/tick over 1000 ticks)
```

### 6.3 Admin Service Protocol

The scheduler exposes an admin-service wire protocol endpoint (see
`docs/design/admin-service-wire-protocol.md`). Service lifecycle commands
are routed through the existing admin RPC surface, serialised as
`AdminCommand::ServicePause { name }` etc.

## 7. Concurrency Readiness Model

### 7.1 Current State: Single-Threaded Inline

The scheduler runs inline in the FUSE daemon event loop. All `BackgroundService`
implementors share the daemon's thread. This is simple and correct but limits
throughput: a single slow tick (e.g., B-tree compaction scanning 500 entries)
blocks demand ops.

### 7.2 Target: Work-Stealing Thread Pool (Phase 11)

The path to multi-threaded scheduling:

```
                       ┌─────────────────────┐
   FUSE Event Thread   │   Background Pool   │
        │              │                     │
   demand_op()         │  Worker 0: tick()   │
        │              │  Worker 1: tick()   │
   queue_cycle(budget)─│─▶Worker 2: tick()   │
        │              │  Worker 3: tick()   │
   demand_op()         │                     │
        │              │  (steal from        │
   collect_reports()◀──│   completed ticks)  │
        │              └─────────────────────┘
```

Key constraints:

1. **No shared mutable state between services**. Services own their state.
   The scheduler is the only mutator of `ServiceState`.
2. **Tick isolation**: Each tick operates on a snapshot of authoritative state
   captured at tick start. Conflicts are resolved by validity tokens (§8, #1592).
3. **Budget enforcement at thread granularity**: The `ServiceBudget` is split
   across workers before dispatch. Each worker self-limits to its allocation.
4. **Work stealing for load balancing**: If a worker finishes its assigned
   tick early, it can steal the next pending tick from the shared queue.

### 7.3 Transition Plan

| Phase | Change | Risk |
|-------|--------|------|
| 11a | Extract `BackgroundService` to a `Send + Sync` bound | Low: existing services are already `Send` |
| 11b | Introduce `BackgroundSchedulerPool` with `rayon` or custom work-stealing | Medium: thread synchronisation |
| 11c | Per-service `Arc<Mutex<>>` or message-passing for state | Medium: deadlock risk |
| 11d | Deterministic replay across threads (capture thread interleaving) | High: nondeterminism from OS scheduler |

Phases 11a-11c are deferred to a future wire-up issue. Phase 11d requires the
deterministic simnet (#1249) to control thread scheduling.

## 8. Health Monitoring and Circuit Breaking

### 8.1 Per-Service Health Model

Each service maintains a `HealthTracker`:

```rust
pub struct HealthTracker {
    /// Consecutive ticks with errors > 0.
    pub consecutive_errors: u64,
    /// Threshold before auto-pause (Running → Unhealthy).
    pub error_threshold: u64,
    /// Timestamp of last successful tick.
    pub last_ok_tick: Option<Timestamp>,
    /// Moving average of tick duration (ms), for anomaly detection.
    pub avg_tick_duration_ms: f64,
    /// Whether this service is currently tripped.
    pub circuit_open: bool,
}
```

### 8.2 Circuit Breaker Pattern

When `consecutive_errors >= error_threshold`, the scheduler auto-transitions
the service to `Unhealthy`. This is a **circuit breaker**: the service is
removed from the dispatch loop until an operator resets it.

Thresholds by priority:

| Priority | `error_threshold` | Rationale |
|----------|-------------------|-----------|
| Critical | 3 | Authority work errors indicate serious corruption; stop fast |
| LatencySensitive | 10 | Cache rebuild can retry; transient errors acceptable |
| Throughput | 50 | Bulk work errors may be per-item; many retries allowed |
| BestEffort | 100 | Compaction failures are usually transient; high tolerance |
| Opportunistic | 200 | Prefetch errors are noise; highest tolerance |

### 8.3 Cascading Failure Prevention

If >50% of services at a given priority stage are Unhealthy, the scheduler
pauses the entire stage and emits a `SchedulerAlert::StageUnhealthy` event.
This prevents a systemic issue (e.g., disk corruption) from wasting I/O on
doomed work.

## 9. Service Registry Metadata

### 9.1 Registration Descriptor

Services register with a descriptor that carries metadata for operator tooling:

```rust
pub struct ServiceDescriptor {
    /// Unique name. Must match service.name().
    pub name: &'static str,
    /// Human-readable description for operator docs.
    pub description: &'static str,
    /// Priority class.
    pub priority: ServicePriority,
    /// Feature gate name. If the gate is off, service stays Retired.
    pub feature_gate: Option<&'static str>,
    /// Whether this service is required for pool health.
    /// Required services that are Unhealthy trigger a pool-level warning.
    pub required_for_health: bool,
    /// Maximum recommended concurrency (for future thread pool).
    pub max_concurrency: u8,
}
```

### 9.2 Feature Gate Integration

When a feature gate is disabled, the service transitions to `Retired`
and is removed from the dispatch loop. When the gate is re-enabled,
the service re-registers as `Registered` and resumes on the next tick.
This enables phased rollout of background services without daemon restart.

## 10. Budget Auto-Tuning (Future Direction)

### 10.1 Static Budget Limitations

The #1592 static budget weights (Critical 40%, LatencySensitive 30%, etc.) are
simple but suboptimal. Workloads vary: a write-heavy workload needs more
segment cleaning; a read-heavy workload needs more prefetch.

### 10.2 Adaptive Budget Proposal

```rust
pub struct BudgetTuner {
    /// EWMA of has_more=true cycles per stage.
    pub stage_backlog_ewma: [f64; 5],
    /// Window for calculating backlog trend.
    pub window_cycles: u64,
    /// Whether auto-tuning is enabled.
    pub enabled: bool,
}
```

The tuner observes `CycleReport.has_more` per stage over a sliding window.
If Stage N consistently reports `has_more=true` while Stage N+1 reports
`has_more=false`, the tuner shifts budget weight from N+1 to N (bounded
by min/max weight per stage).

This is deferred to v1.1. The static weights are sufficient for v1.0.

## 11. Error Model Refinement

### 11.1 Extended Error Hierarchy

Building on the #1592 `SchedulerError` enum:

```rust
pub enum SchedulerError {
    /// Service registration failed.
    RegistrationFailed { service_name: &'static str, reason: String },
    /// A service tick returned an error.
    ServiceFailed { service_name: &'static str, error: ServiceError },
    /// Scheduler detected a service exceeding its budget.
    BudgetViolation { service_name: &'static str, budget: ServiceBudget, consumed: TickReport },
    /// Starvation-prevention tick exhausted budget mid-cycle.
    StarvationBudgetExhausted { starved_service: &'static str },
    /// A stage was auto-paused because >50% of services are Unhealthy.
    StageUnhealthy { stage: ServicePriority, unhealthy_count: usize, total_count: usize },
    /// Deterministic replay divergence detected.
    ReplayDivergence { cycle: u64, service: &'static str, expected: TickReport, actual: TickReport },
}
```

### 11.2 Error Handling Policy

| Error | Scheduler behaviour | Operator action |
|-------|--------------------|-----------------|
| `ServiceFailed` | Record in health tracker; continue | None if below threshold |
| `BudgetViolation` | Truncate tick; emit warning; continue | Investigate misbehaving service |
| `StarvationBudgetExhausted` | Record; continue with next cycle | Tune starvation timeouts |
| `StageUnhealthy` | Pause entire stage; emit alert | Diagnose systemic issue |
| `ReplayDivergence` | Abort replay; dump trace | File bug against service |

## 12. Observability Additions

### 12.1 New Metrics

Extending the #1592 observability model:

| Metric | Type | Description |
|--------|------|-------------|
| `scheduler.starvation_ticks` | Counter | Number of starvation-prevention ticks this cycle |
| `scheduler.demand_pressure` | Gauge | Current demand pressure (0.0–1.0) |
| `scheduler.effective_budget_items` | Gauge | Items budget after demand-pressure shrink |
| `service.<name>.state` | Gauge | Current lifecycle state (enum as int) |
| `service.<name>.consecutive_errors` | Gauge | Consecutive error count |
| `service.<name>.circuit_open` | Gauge | 1 if circuit breaker tripped, 0 otherwise |
| `stage.<priority>.unhealthy_count` | Gauge | Number of Unhealthy services in stage |

### 12.2 Alerting Rules

| Alert | Condition | Severity |
|-------|-----------|----------|
| `ServiceUnhealthy` | Any service enters Unhealthy state | Warning |
| `StageUnhealthy` | >50% of services in a stage are Unhealthy | Critical |
| `StarvationPersistent` | Any service starved for >5× its timeout | Warning |
| `BudgetExhaustedEveryCycle` | Budget exhausted in 10 consecutive cycles | Info |

## 13. Interaction with Other Subsystems

### 13.1 Unified Resource Governor

The background scheduler consumes I/O resources that compete with foreground
operations. The unified resource governor (`docs/design/unified-resource-governor-design.md`)
assigns a `BackgroundLane` with a fixed fraction of total I/O bandwidth:

```
Total I/O bandwidth (100%)
  ├── DemandLane:  70% (foreground FUSE ops)
  ├── BackgroundLane: 20% (background services)
  └── SystemLane:  10% (metadata flush, COMMIT_GROUP sync)
```

The scheduler's `ServiceBudget` is a logical budget; the resource governor
enforces physical I/O limits. The scheduler queries `governor.background_lane_available()`
before dispatching and reduces `max_bytes` to match.

### 13.2 COMMIT_GROUP State Machine

The `run_cycle` already calls `commit_group.tick()` per the #1592 spec (§5.4). The
enhancement formalises the interaction: the COMMIT_GROUP tick is always a pre-cycle
step and is never counted against the background budget. If the COMMIT_GROUP tick
initiates a sync, the scheduler reduces `effective_budget.max_items` by 50%
for the current cycle to account for the I/O write-out.

### 13.3 Incremental Cursor Framework

All services driven by the scheduler implement `IncrementalJob` from
`tidefs-types-incremental-job-core`. The `IncrementalJobAdapter` bridges
the `BackgroundService` trait to any `IncrementalJob`. The enhancement adds
a `ServiceCheckpoint` wrapper that includes lifecycle state alongside the
cursor checkpoint:

```rust
pub struct ServiceCheckpoint {
    /// The underlying job checkpoint (cursor position).
    pub job_checkpoint: Checkpoint,
    /// Service lifecycle state.
    pub state: ServiceState,
    /// Health tracker snapshot.
    pub health: HealthTracker,
    /// Starvation tracker snapshot.
    pub starvation: StarvationTracker,
}
```

This enables crash-consistent save/restore of the entire scheduler state.

## 14. Implementation Plan

The enhancements are assigned to 5 new sub-phases, built on the #1592 10-phase plan:

| Phase | Scope | Dependencies |
|-------|-------|-------------|
| **Phase 11: Lifecycle** | `ServiceState`, state transitions, `ServiceDescriptor`, feature-gate integration | Phases 1-4 complete |
| **Phase 12: Starvation** | `StarvationTracker`, starvation-prevention dispatch, configurable timeouts | Phase 11 |
| **Phase 13: Backpressure** | `demand_pressure` gauge, budget shrink, Critical grace period | Phase 11 |
| **Phase 14: Operator CLI** | `tidefs service *` commands, admin-protocol wire-up | Phases 11-12 |
| **Phase 15: Replay** | `TickLog`, capture/replay mode, deterministic I/O mock, trace-oracle integration | Phases 11-13 |

Concurrency readiness (Phase 11a-11d in §7.3) is deferred to a separate continuation
issue after the simnet supports deterministic thread scheduling.

## 15. Crate Impact

| Crate | Change |
|-------|--------|
| `tidefs-background-scheduler` | Add `ServiceState`, `StarvationTracker`, `HealthTracker`, `TickLog`, `ServiceDescriptor`; extend `BackgroundScheduler` with lifecycle/starvation/replay methods |
| `tidefs-types-incremental-job-core` | Add `ServiceCheckpoint` type; no breaking changes |
| `tidefs-local-filesystem` | Update `BackgroundCompaction`, `BackgroundReclaim`, `BackgroundOrphanReclamation` to carry `ServiceDescriptor` |
| `apps/tidefs-posix-filesystem-adapter-daemon/src/runtime` | Add `demand_pressure` gauge; wire effective-budget computation |
| `tidefs-trace-oracle` | Add replay integration; connect `TickLog` to deterministic trace |
| `tidefs-types-admin-service-core` | Add `AdminCommand::Service{Pause,Resume,Reset,Retire}` variants |

## 16. Open Questions

1. **Should the starvation-prevention tick count against the service's normal budget?**
   If yes, a starved service gets a smaller normal tick next cycle. If no, it's
   effectively double-budgeted. Recommendation: count against normal budget to
   maintain fairness; operator can increase global budget if starvation is frequent.

2. **Should unhealthy services auto-recover after a cooldown period?**
   Auto-recovery risks flapping (unhealthy → running → unhealthy). Recommendation:
   manual reset only, with an optional `auto_reset_after_cycles` property (default: 0,
   meaning off).

3. **How to handle service re-registration when feature gates toggle?**
   If a feature gate is toggled at runtime, the service must restart its state
   from scratch (new IncrementalJob instance). Recommendation: the scheduler holds
   a `ServiceFactory` closure that creates a fresh service instance on re-registration.

4. **Should the TickLog be persisted to disk?**
   Persisting 10,000 cycles of tick logs consumes ~10 MiB. This is small but
   adds write amplification to every cycle. Recommendation: in-memory ring buffer
   only; dump to disk on operator request (`tidefs scheduler dump-log`).

5. **Interaction with pool export/import?**
   When a pool is exported, background services must drain (finish current tick,
   refuse new work) before the pool is unmounted. Recommendation: add a
   `prepare_for_export()` method that sets all services to Paused and waits for
   in-flight ticks to complete.

## 17. References

- [#1179] Initial background service framework design
- [#1592] Canonical design specification (this document's parent)
- [#1459] BackgroundReclaim service implementation
- [#1463] Reclaim delta recording integration
- [#1249] Deterministic cluster simnet for protocol correctness testing
- [#1241] Unified lane scheduling model
- `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md` — #1179 design spec
- `docs/design/background-service-framework-design.md` — #1592 canonical design
- `crates/tidefs-background-scheduler/src/lib.rs` — scheduler implementation (1319 lines)
- `crates/tidefs-types-incremental-job-core/src/lib.rs` — IncrementalJob core types
- `crates/tidefs-local-filesystem/src/background_compaction.rs` — BackgroundCompaction service
- `crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs` — BackgroundOrphanReclamation service
- `crates/tidefs-local-filesystem/src/background_reclaim.rs` — BackgroundReclaim service
- `docs/design/admin-service-wire-protocol.md` — admin protocol for CLI commands
- `docs/design/unified-resource-governor-design.md` — I/O lane allocation
