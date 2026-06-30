# Background Service Framework Design (#1962)

**Issue**: [#1962](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1962)
**Forgejo**: `codex:claimed`, `kind:design`, `lane:storage-core`, `source:coordinator`
**Status**: design-spec — Rust implementation deferred to wire-up issues tracked in #1877 / #1946
**Maturity**: design-spec
**Authority**: Canonical consolidation at [`docs/design/background-service-framework-canonical-consolidation.md`](background-service-framework-canonical-consolidation.md) (#1983); this document provides a self-contained summary of the architecture, data structures, algorithms, and tradeoffs for issue #1962.

---

## 1. Problem Statement

A userspace storage system must perform continuous background maintenance without
interrupting foreground I/O. Workloads include scrubbing checksums, reclaiming
freed space, compacting B-trees, rebuilding derived views, cleaning dead segments,
and evaluating snapshot retention policies. Without a unified framework, each
subsystem invents ad-hoc scheduling and throttling, producing inconsistent
behaviour under load and opaque operator visibility.

**Twelve dependent designs** require background services: view builder (#1176),
data cleaner (#1180), scrub + repair (#1249), rebake (#1222), segment cleaner
(#1215), snapshot retention, lane budget integration (#1241), BackgroundReclaim
(#1459/#1463), extent compaction (#1223), B-tree compaction, and orphan recovery.

---

## 2. Core Architecture

### 2.1 High-Level Structure

```
┌──────────────────────────────────────────────────────────────────────────┐
│                       BackgroundSchedulerPool                             │
│                                                                          │
│  ┌──────────────────────────┐    ┌─────────────────────────────────────┐│
│  │    Planning Thread        │    │          Worker Pool                ││
│  │    (FUSE event loop)      │    │                                     ││
│  │                           │    │  Worker 0: tick queue.dequeue       ││
│  │  plan_cycle()             │    │  Worker 1: tick queue.dequeue       ││
│  │    ├─ compute budget      │    │  Worker 2: tick queue.dequeue       ││
│  │    ├─ priority dispatch   │    │  Worker 3: tick queue.dequeue       ││
│  │    ├─ starvation check    │    │                                     ││
│  │    ├─ enqueue work items  │    │  work-stealing between workers      ││
│  │    └─ emit TickLog        │    │                                     ││
│  └──────────────────────────┘    └─────────────────────────────────────┘│
│                                                                          │
│  Registered Services (dyn BackgroundService):                            │
│  ┌─────────┐ ┌───────────────┐ ┌──────────┐ ┌────────────┐             │
│  │ Scrub    │ │ ViewBuilder    │ │ Reclaim   │ │ Compaction  │             │
│  │ Repair   │ │ DataCleaner    │ │ SegmentCl │ │ Prefetch    │             │
│  └─────────┘ └───────────────┘ └──────────┘ └────────────┘             │
└──────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Core Abstractions

| Abstraction | Responsibility |
|---|---|
| `BackgroundService` trait | Object-safe trait: name, priority, `tick(budget)`, `has_pending_work()`, state machine |
| `IncrementalJob` trait | Work-domain cursor: `tick()`, `checkpoint()`/`restore()`, `progress()`, `reset()` |
| `IncrementalJobAdapter` | Bridges `IncrementalJob` → `BackgroundService`; maps `JobKind` to `ServicePriority` |
| `ServiceBudget` | 3-dimensional budget: `max_items`, `max_bytes`, `max_milliseconds` |
| `TickReport` | Per-tick accounting: processed, skipped, errored, bytes consumed, `has_more` flag |
| `BackgroundScheduler` | Priority-ordered dispatch, round-robin fairness, budget cascading, observability |
| `ValidityToken` | Derived from inode mutation counters; prevents wasted I/O on stale tasks |

### 2.3 Priority Stages

| Stage | Budget Share | Service Examples | Rationale |
|---|---|---|---|
| **Critical** (40%) | 40% | Scrub, Repair | Correctness-critical; data safety |
| **LatencySensitive** (30%) | 30% | Reclaim, View builder, Orphan recovery | User-visible impact within seconds |
| **Throughput** (15%) | 15% | Data cleaner, Rebake | Bulk work; latency-tolerant |
| **BestEffort** (10%) | 10% | Segment cleaner, Compaction, Snapshot retention | Good-to-have; no user-facing impact |
| **Opportunistic** (5%) | 5% | Prefetch, speculative reads | Only when system is fully idle |

**Budget cascading**: Unused budget from higher stages cascades to lower stages.
A `BestEffort` service can exceed its nominal budget when higher stages are idle,
maximising background throughput without disturbing foreground I/O.

---

## 3. Data Structures

### 3.1 ServiceBudget

```rust
pub struct ServiceBudget {
    pub max_items: usize,       // Maximum work items this tick
    pub max_bytes: u64,         // Maximum bytes read+written this tick
    pub max_milliseconds: u64,  // Maximum wall-clock time this tick
}
```

**Named constants**: `DEFAULT_TICK` (1000 items, 64 MiB, 500ms), `MAINTENANCE_TICK`
(500 items, 32 MiB, 250ms), `SMALL_TICK` (100 items, 8 MiB, 50ms), `UNBOUNDED`.

### 3.2 ServicePriority

```rust
pub enum ServicePriority {
    Critical = 0,
    LatencySensitive = 1,
    Throughput = 2,
    BestEffort = 3,
    Opportunistic = 4,
}
```

Derived from `JobKind` via `ServicePriority::from_job_kind()`.

### 3.3 TickReport

```rust
pub struct TickReport {
    pub service_name: String,
    pub items_processed: usize,
    pub items_skipped: usize,
    pub items_errored: usize,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub microseconds_elapsed: u64,
    pub budget_exhaustion: BudgetExhaustion,
    pub has_more: bool,
}
```

`TickReport` has merge semantics — two reports from the same service can be
combined with `fn merge(&mut self, other: &TickReport)`.

### 3.4 ServiceState

```rust
pub enum ServiceState {
    Running,
    Degraded { consecutive_ticks: u32 },   // ≤N consecutive degraded ticks
    Unhealthy { consecutive_ticks: u32 },  // >N consecutive degraded ticks
    Paused,                                 // Operator-manual pause
    Retired,                                // Permanent retirement
}
```

**State transitions**:
```
Running ──(tick→Ok)──► Running
Running ──(tick→Degraded)──► Degraded(1)
Degraded(n) ──(tick→Ok)──► Running
Degraded(n) ──(tick→Degraded)──► Degraded(n+1)
Degraded(n>threshold) ──► Unhealthy(n)
Unhealthy ──(manual reset)──► Running
Running ──(pause)──► Paused
Paused ──(resume)──► Running
Any ──(retire)──► Retired
```

`DEGRADED_THRESHOLD` defaults to 3 ticks; `UNHEALTHY_THRESHOLD` to 10 ticks.

### 3.5 ValidityToken

```rust
pub struct ValidityToken {
    pub inode: u64,
    pub mutation_counter: u64,
}

impl ValidityToken {
    pub fn is_valid(&self, current_counter: u64) -> bool {
        self.mutation_counter == current_counter
    }
}
```

Provides staleness detection for deferred work items. Before a service processes
a work item, the token is checked against the authoritative inode mutation counter;
stale items are discarded with zero budget cost (1-item grace period).

### 3.6 StarvationTracker

```rust
pub struct StarvationTracker {
    pub last_ticked_cycle: u64,          // Cycle number of last tick
    pub starvation_threshold: Duration,  // Default: 60s
}

impl StarvationTracker {
    pub fn starvation_pressure(&self, current_cycle: u64, cycle_period: Duration) -> f64;
    // Returns 0.0 (not starved) to 1.0 (critically starved).
    // When pressure > 0.8, the service is temporarily promoted one priority stage.
}
```

### 3.7 TickLog (Ring Buffer)

```rust
pub struct TickLog {
    entries: VecDeque<TickLogEntry>,  // Ring buffer, 10,000 entries (~10 MiB)
}

pub struct TickLogEntry {
    pub cycle: u64,
    pub stage: ServicePriority,
    pub service_name: String,
    pub budget_allocated: ServiceBudget,
    pub report: TickReport,
    pub wall_clock_us: u64,
}
```

---

## 4. Algorithms

### 4.1 Scheduler Main Loop (`plan_cycle`)

```
Input:  services[], global_budget, backpressure_multiplier
Output: TickLog entries

1. effective_budget = global_budget * backpressure_multiplier
2. For each stage in priority order (Critical → Opportunistic):
   a. stage_budget = effective_budget * stage_weight
   b. If higher stages left unused budget, cascade to stage_budget
   c. For each service in stage (round-robin, resume from last cursor):
      i.   If service.state ≠ Running, skip
      ii.  Check starvation_tracker → promote if starved
      iii. Check validity_token → discard stale work items
      iv.  Call service.tick(stage_budget) → TickReport
      v.   Debit stage_budget from TickReport consumption
      vi.  If TickReport.has_more and stage_budget > 0, continue next service
      vii. If stage_budget exhausted, advance to next stage
   d. Save round-robin cursor for this stage
3. Emit TickLog entries for all ticked services
4. Advance cycle counter
```

**Complexity**: O(S) per cycle where S = number of registered services. The
per-service `tick()` is bounded by the budget, so total work is bounded.

### 4.2 Starvation Prevention

```
For each service not ticked in this cycle:
  pressure = starvation_tracker.pressure(current_cycle, cycle_period)
  IF pressure > 0.8:
    Temporarily promote service to next-higher priority stage
    Mark service for tick in next cycle at promoted priority
```

The starvation tick counts against the service's normal budget to maintain
fairness. A service starved for >60s automatically receives a priority bump.

### 4.3 Budget Cascading

```
remaining = 0.0
For each stage in priority order:
  stage_budget = effective_budget * stage_weight
  For each service in stage:
    consumed = service.tick(stage_budget)
    stage_budget -= consumed
  remaining += max(0.0, stage_budget)
  Lower_stage_budget = effective_budget * lower_stage_weight + remaining * cascade_factor
  remaining = max(0.0, lower_stage_budget - consumed_by_lower)
```

Default `cascade_factor` is 1.0 (full cascade). Can be reduced per-pool.

### 4.4 Backpressure Integration

The scheduler receives a `backpressure_multiplier` from the unified resource
governor (see `docs/design/unified-resource-governor-design.md`):

```
backpressure_multiplier = clamp(
    1.0 - (io_utilization - 0.7) / (1.0 - 0.7),
    0.1,   // Minimum 10% of budget even under full saturation
    1.0    // Full budget when I/O utilisation ≤ 70%
)
```

This ensures background work shrinks gracefully under foreground I/O pressure.

### 4.5 COMMIT_GROUP Synchronisation

Each background service tick coincides with a COMMIT_GROUP boundary. The scheduler runs
after the COMMIT_GROUP commit step (Phase 6 of the COMMIT_GROUP pipeline) and is never counted
against the background budget. If the COMMIT_GROUP tick initiates a sync, the scheduler
halves `effective_budget.max_items` for the current cycle.

### 4.6 Work-Stealing (Phase 16 — Future)

Workers maintain per-worker deques (Chase-Lev). When a worker exhausts its local
work, it randomly picks a victim and steals from the tail of the victim's deque.
Starvation-threshold escalation triggers global queue push for long-starved work
items.

---

## 5. Tradeoffs

### 5.1 Single-Threaded vs. Multi-Threaded

| Decision | Rationale |
|---|---|
| Design for multi-threaded work-stealing | `Send + Sync` bounds deferred to Phase 16 |
| Add dedicated planner thread only if profiling shows >500µs planning time | Premature optimisation avoided |

### 5.2 Budget Cascading vs. Static Allocation

| Decision | Rationale |
|---|---|
| Unused budget cascades to lower stages | Maximises throughput when foreground is idle |
| Critical stage never donates | Data-safety services always get full allocation |
| Cascade factor tunable per-pool | Operators can restrict cascading for noisy-neighbour isolation |

### 5.3 Service Lifecycle: Auto-Recovery vs. Manual Reset

| Decision | Rationale |
|---|---|
| Unhealthy services require manual reset | Operators need visibility before resuming |
| Optional `auto_reset_after_cycles` for non-critical services | Hands-off recovery for BestEffort/Compaction |
| Paused/Retired require explicit admin command | Safety; no silent state changes |

### 5.4 TickLog Persistence: Memory vs. Disk

| Decision | Rationale |
|---|---|
| In-memory ring buffer (10K cycles) | Avoids write amplification |
| Dump on operator request (`tidefs scheduler dump-log`) | Debug-only; not for crash recovery |
| 10 MiB fixed overhead | Acceptable for observability value |

### 5.5 Service Dependencies: Enforced Ordering vs. Independent

| Decision | Rationale |
|---|---|
| Scheduler does not enforce ordering | Simpler scheduler; fewer coupling bugs |
| Services detect work via authoritative state | Scrub writes findings; Repair reads them independently |
| Dependency tracking deferred to v1.1 | Low risk; current service graph is shallow |

### 5.6 Staleness Detection: ValidityToken vs. Epoch-Based

| Decision | Rationale |
|---|---|
| Per-inode mutation counter | Finer granularity than epoch; no false positives |
| 1-item grace period for token misses | Prevents budget starvation from token race conditions |
| Token checked *after* budget debit | Simpler implementation; 1-item grace absorbs edge case |

---

## 6. Implemented Services (Phases 1–4)

| Service | Priority | Crate | Lines |
|---|---|---|---|
| BackgroundReclaim | LatencySensitive | `tidefs-local-filesystem` | N/A (integrated) |
| BackgroundCompaction | BestEffort | `tidefs-local-filesystem` | N/A (integrated) |
| BackgroundOrphanReclamation | LatencySensitive | `tidefs-local-filesystem` | N/A (integrated) |
| BackgroundCleanup | Throughput | `tidefs-local-filesystem` | N/A (integrated) |
| CleanupJob (IncrementalJob) | Throughput | `tidefs-cleanup-job-core` | ~200 |
| ReclaimJob (IncrementalJob) | LatencySensitive | `tidefs-reclaim-job-core` | ~150 |
| OrphanRecoveryJob (IncrementalJob) | LatencySensitive | `tidefs-orphan-recovery-job-core` | ~180 |

**Scheduler crate**: `tidefs-background-scheduler` (1,410 lines) — `BackgroundScheduler`,
`BackgroundService` trait, `IncrementalJobAdapter`, `ServiceBudget`, `TickReport`,
`ServiceState`, `StarvationTracker`.

**Types crate**: `tidefs-types-incremental-job-core` (1,691 lines) — `IncrementalJob`
trait, `WorkBudget`, `Checkpoint`, `JobProgress`, `CursorState`, `StepResult`,
`JobKind` (33 variants), `JobId`, `JobError`.

---

## 7. Deferred Services (Phases 5–10)

| Phase | Service | Crate | What it does |
|---|---|---|---|
| 5 | ViewBuilderService | `tidefs-derived-catalog` (new) | Build/serve/evict/compact derived catalog B-tree views |
| 6 | DataCleanerService | `tidefs-data-cleaner` (new) | Process refcount delta queues; free confirmed-dead extents |
| 7 | SegmentCleanerService | `tidefs-segment-cleaner` (new) | Reclaim dead segments; coalesce free space |
| 8 | FUSE integration | `apps/tidefs-posix-filesystem-adapter-daemon/src/runtime` | Wire scheduler into daemon main loop; demand preemption |
| 9 | CompactionService | Phases 5–6 crates | Incremental B-tree compaction for derived catalog and refcount B-tree |

---

## 8. Crate Dependency Graph

```
tidefs-types-incremental-job-core  (no_std, alloc, forbid(unsafe_code))
    ↑
tidefs-incremental-job-core        (no_std, alloc)
    ↑
tidefs-background-scheduler        (no_std, alloc)
    ↑
    ├── tidefs-local-filesystem     (BackgroundReclaim, BackgroundCompaction,
    │                                BackgroundOrphanReclamation, BackgroundCleanup)
    ├── tidefs-cleanup-job-core     (CleanupJob)
    ├── tidefs-reclaim-job-core     (ReclaimJob)
    └── tidefs-orphan-recovery-…    (OrphanRecoveryJob)
```

---

## 9. Observability

Every cycle emits a `CycleReport` aggregating per-service `TickReport` values:

| Counter | Description |
|---|---|
| `services_active` | Count of Running services |
| `services_degraded` | Count of Degraded services |
| `services_unhealthy` | Count of Unhealthy services |
| `items_processed_total` | Total work items processed |
| `items_skipped_total` | Stale items skipped (validity token) |
| `items_errored_total` | Items that errored |
| `bytes_read_total` | Total bytes read by background I/O |
| `bytes_written_total` | Total bytes written by background I/O |
| `microseconds_total` | Total wall-clock time consumed |
| `starvation_pressure_max` | Maximum starvation pressure among all services |

These are exposed via the operator CLI (`tidefs scheduler stats`) and the admin
wire protocol (`docs/design/admin-service-wire-protocol.md`).

---

## 10. Testing Strategy

### 10.1 Unit Tests (Phase 1–4: complete)

- `IncrementalJob` trait conformance: `tick()`, `cursor()`, `progress()`, `reset()`,
  `checkpoint()`/`restore()`
- State machine transitions: every `ServiceState` edge
- Budget exhaustion: correct `BudgetExhaustion` variant for items, bytes, wall-time
- Round-robin fairness: per-priority cursor advances correctly
- Validity token: stale tokens cause work-item discard
- StarvationTracker: pressure calculation, record/reset

### 10.2 Integration Tests

- Multi-service cycle: 3+ services at different priorities → verify dispatch order
- Starvation promotion: BestEffort service not ticked >60s → automatically promoted
- Backpressure: high utilisation → budget shrinks; idle → budget restores
- Health transitions: Degraded for N ticks → Unhealthy
- Work-stealing: 4 workers → items distributed and stolen (Phase 16)


```bash
cargo test -p tidefs-background-scheduler -- --test-threads=1
```

---

## 11. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Starvation timeout too aggressive | Medium | BestEffort services starved | Configurable per-stage timeout; operator tunable |
| Budget cascading starves latency-sensitive work | Low | High | Critical services exempt; grace period before cascade |
| Wire-up issues outpace scheduler capacity | Low | Medium | Per-phase issues independently schedulable; no shared write surfaces |

---

## 12. References

- [#1179] Initial background service framework design →
  `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md`
- [#1592] Canonical scheduler design →
  `docs/design/background-service-framework-design.md`
- [#1624] Enhanced design (lifecycle, starvation, backpressure) →
  `docs/design/background-service-framework-design-enhanced.md`
- [#1625] Multi-threaded work-stealing design →
  `docs/design/background-service-framework-multithread-design.md`
- [#1673][#1674] 16-phase roadmap →
  `docs/design/background-service-framework-design-spec.md`
- [#1877] Phases 5–10 wire-up tracking
- [#1946] Phases 5–10 per-phase details →
  `docs/design/background-service-framework-phases-5-10-wire-up-tracking.md`
- [#1983] Canonical consolidation →
  `docs/design/background-service-framework-canonical-consolidation.md`
- [#1992] Retired coordination seal, removed by #1586
- [#1962] This document — self-contained design summary
- `crates/tidefs-background-scheduler/src/lib.rs` — scheduler implementation (1,410 lines)
- `crates/tidefs-types-incremental-job-core/src/lib.rs` — types and traits (1,691 lines)
- `docs/design/incremental-job-core-types-crate-design.md` — IncrementalJob type design
- `docs/design/incremental-job-core-wire-up-deferred-design.md` — wire-up deferred design
- `docs/design/unified-scheduling-classes-lane-priority-model.md` — lane scheduling
- `docs/design/unified-resource-governor-design.md` — I/O lane allocation
- `docs/design/admin-service-wire-protocol.md` — admin protocol
- `docs/design/deterministic-trace-oracle-system.md` — trace oracle
- `docs/design/deferred-cleanup-background-service-scheduling.md` — cleanup scheduling
- `docs/design/deferred-cleanup-work-queues.md` — cleanup work queues
