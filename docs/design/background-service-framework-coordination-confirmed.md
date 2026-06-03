# Background Service Framework Design Enhanced — Coordination Confirmed (#1992)

Maturity: **design-spec**. Rust implementation of phases 5–10 deferred to
wire-up issues tracked in #1877.

This document records the coordination seal on the TideFS unified background
service framework design. All design-spec issues for the background service
framework are sealed; no further design enhancements are planned. Rust
implementation of phases 5–10 is deferred to wire-up issues.

**Source context:** #1592, #1673, #1674, #1858, #1859, #1877, #1980.
Kind: **design**, lane: **coordination**.

## 1. Design Document Lineage

The background service framework design has evolved through multiple issues,
each refining a specific aspect. The canonical reference is
`docs/design/background-service-framework-design.md` (#1592 + #1674).

| Issue | Title | Document | Role |
|-------|-------|----------|------|
| #1179 | Initial background service framework design | `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md` | Original spec (redirects to canonical) |
| #1592 | Design enhanced — §11 Pool Properties, §12 Testing Strategy | `docs/design/background-service-framework-design.md` | Canonical design (860 lines) |
| #1673 | Design enhanced — canonical design-spec | `docs/design/background-service-framework-design-spec.md` | 16-phase roadmap (880 lines) |
| #1674 | Canonical consolidation | (same file as #1592) | Reference update |
| #1858 | Coordination confirmed | — | Coordination seal |
| #1859 | Canonical consolidation: implementation deferred | — | Status update |
| #1877 | Phases 5–10 wire-up tracking | — | Wire-up tracking |
| #1946 | Phases 5–10 wire-up specification | `docs/design/background-service-framework-phases-5-10-wire-up-tracking.md` | Per-phase detail (988 lines) |
| #1980 | Coordination confirmed: implementation deferred | `docs/design/background-service-framework-design-enhanced.md` | Enhanced design (668 lines, 17 sections) |
| **#1992** | **Coordination confirmed: maturity design-spec** | **This document** | **Final coordination seal** |

## 2. Current Implementation State

### 2.1 Implemented (Phases 1–4)

Phases 1–4 are fully implemented in the following crates:

| Crate | Responsibility |
|-------|---------------|
| `tidefs-background-scheduler` | `BackgroundScheduler` with 5-stage priority ordering, round-robin fairness, per-tick budget enforcement, budget cascading (1,410 lines) |
| `tidefs-types-incremental-job-core` | `IncrementalJob` trait, `WorkBudget`, `Checkpoint`, `JobProgress`, `CursorState`, `StepResult`, `JobKind`, `JobId`, `JobError` |
| `tidefs-cleanup-job-core` | `CleanupJob` — deferred cleanup as `IncrementalJob` |
| `tidefs-reclaim-job-core` | `ReclaimJob` — refcount delta reclaim as budgeted `IncrementalJob` |
| `tidefs-orphan-recovery-job-core` | `OrphanRecoveryJob` — orphan index traversal as `IncrementalJob` |
| `tidefs-local-filesystem` | `BackgroundCompaction`, `BackgroundReclaim`, `BackgroundOrphanReclamation`, `BackgroundCleanup` — four production services running on the scheduler |

### 2.2 Core Framework Architecture

The scheduler (`tidefs-background-scheduler`) provides:

- **`BackgroundService` trait** — object-safe trait for schedulable work units
  with deterministic tick contract
- **`IncrementalJobAdapter`** — bridges any `IncrementalJob` to `BackgroundService`
- **`ServicePriority`** — 5-stage enum: Critical, LatencySensitive, Throughput,
  BestEffort, Opportunistic
- **`ServiceBudget`** — 3-dimensional budget (items, bytes, ms) with
  `DEFAULT_TICK`, `MAINTENANCE_TICK`, `SMALL_TICK`, `UNBOUNDED` constants
- **`TickReport`** — per-tick accounting with merge semantics
- **`ServiceError`** / `SchedulerError` — error hierarchy with budget violation
  and internal error variants
- **Job-kind-to-priority mapping** — `ServicePriority::from_job_kind()` maps
  every `JobKind` variant to its correct stage

### 2.3 Sixteen-Phase Roadmap

The canonical design-spec (#1673, `docs/design/background-service-framework-design-spec.md`)
defines 16 phases:

| Phase | Scope | Status |
|-------|-------|--------|
| Phase 1 | `IncrementalJob` trait, `WorkBudget`, `Checkpoint`, core types | **Implemented** |
| Phase 2 | `BackgroundService` trait, `IncrementalJobAdapter` | **Implemented** |
| Phase 3 | `BackgroundScheduler`, 5-stage dispatch, round-robin | **Implemented** |
| Phase 4 | `CleanupJob`, `ReclaimJob`, `OrphanRecoveryJob` | **Implemented** |
| Phase 5 | `ViewBuilderService` — derived catalog views | Deferred to wire-up |
| Phase 6 | `DataCleanerService` — refcount delta processing | Deferred to wire-up |
| Phase 7 | `SegmentCleanerService` — dead segment reclamation | Deferred to wire-up |
| Phase 8 | FUSE integration — scheduler in daemon main loop | Deferred to wire-up |
| Phase 9 | `CompactionService` — derived catalog + refcount B-tree | Deferred to wire-up |
| Phase 11 | Lifecycle state machine — `ServiceState`, transitions | Deferred to wire-up |
| Phase 12 | Starvation guarantee — `StarvationTracker`, timeout dispatch | Deferred to wire-up |
| Phase 13 | Backpressure — `demand_pressure` gauge, budget shrink | Deferred to wire-up |
| Phase 14 | Operator CLI — `tidefs service *` commands | Deferred to wire-up |
| Phase 15 | Deterministic replay — `TickLog`, capture/replay mode | Deferred to wire-up |
| Phase 16 | Concurrency readiness — multi-threaded work-stealing | Deferred to wire-up |

## 3. Design-Spec Maturity Declaration

### 3.1 What "design-spec" Means

The background service framework design has reached **design-spec** maturity.
This means:

- **Architecture**: The 5-stage priority model, budget system, and service trait
  contract are fully specified.
- **Data structures**: All core types (`WorkBudget`, `ServicePriority`,
  `Checkpoint`, `JobProgress`, `CursorState`, `ServiceState`, `TickLog`,
  `StarvationTracker`, `HealthTracker`, `ServiceDescriptor`) are defined with
  Rust type signatures.
- **Algorithms**: Dispatch algorithm (5-stage priority with round-robin within
  stage), budget cascading, starvation prevention (configurable timeout),
  backpressure formula, and replay architecture are specified in pseudocode
  and prose.
- **Tradeoffs**: 5 open questions are documented in #1980 §16, each with a
  recommendation.
  document (#1946).

### 3.2 What design-spec Does NOT Include

- Production Rust implementation of phases 5–16 (deferred to wire-up issues).
- Concrete benchmark numbers (targets defined in `PERFORMANCE_BUDGETS_SLO_REGRESSION_GATES_P10-03.md`).
- Production user documentation (deferred to post-implementation).

## 4. Coordination Seal

### 4.1 What Is Sealed

The following aspects of the background service framework design are now
frozen and must not be changed without a new design issue:

1. **Trait contracts** — `BackgroundService`, `IncrementalJob` trait signatures
   are stable.
2. **Priority model** — 5-stage enum (`Critical` through `Opportunistic`) is
   final. Adding a stage requires a design issue.
3. **Budget model** — 3-dimensional budget (`items`, `bytes`, `ms`) with
   cascading semantics is final.
4. **Checkpoint format** — `Checkpoint` struct layout is stable;
   `ServiceCheckpoint` wrapper is specified.
5. **Service lifecycle** — `ServiceState` enum (Registered, Running, Paused,
   Unhealthy, Retired) is final.
6. **Wire protocol** — Admin commands (`Service{Pause,Resume,Reset,Retire}`)
   are specified in `docs/design/admin-service-wire-protocol.md`.

### 4.2 What Is NOT Sealed

- Internal implementation details of phases 5–16 (wire-up issues own the
  implementation).
- Per-service `IncrementalJob` cursor formats (each job owns its cursor).
- Concrete budget constants (tunable via pool properties).
- Starvation timeout defaults (tunable per deployment).

## 5. Implementation Deferral

### 5.1 Wire-Up Tracking

All Rust implementation work for phases 5–16 is deferred to wire-up issues
tracked in #1877. The canonical wire-up specification is at
`docs/design/background-service-framework-phases-5-10-wire-up-tracking.md`
(#1946, 988 lines), which provides:

- Per-phase architecture diagrams
- Concrete data structure definitions (Rust types)
- Integration algorithms (pseudocode)
- Per-phase tradeoff analysis
- Dependency graphs
- Crate scaffolding templates

### 5.2 Deferred Crate Impact

When wire-up issues are implemented, the following crates will be modified:

| Crate | Phases | Changes |
|-------|--------|--------|
| `tidefs-background-scheduler` | 11–15 | `ServiceState`, `StarvationTracker`, `HealthTracker`, `TickLog`, `ServiceDescriptor`, lifecycle/starvation/replay methods |
| `tidefs-types-incremental-job-core` | 11 | `ServiceCheckpoint` type; no breaking changes |
| `tidefs-local-filesystem` | 5–9, 11 | `ViewBuilderService`, `DataCleanerService`, `SegmentCleanerService`, `CompactionService`, FUSE wire-up; `ServiceDescriptor` on existing services |
| `apps/tidefs-posix-filesystem-adapter-daemon/src/runtime` | 8, 13 | `demand_pressure` gauge; effective-budget computation |
| `tidefs-trace-oracle` | 15 | Replay integration; `TickLog` → deterministic trace connection |
| `tidefs-types-admin-service-core` | 14 | `AdminCommand::Service{Pause,Resume,Reset,Retire}` variants |


| Gate | Phase | Scope |
|------|-------|-------|
| `check-background-service-framework` | 10 | Full integration test: register all services, run N ticks, verify budget enforcement, verify round-robin, verify starvation prevention |
| `check-replay-determinism` | 15 | Golden-trace replay: capture tick log, replay with same seed, assert identical `TickReport` outputs |
| `check-lifecycle-transitions` | 11 | State machine test: exercise all `ServiceState` transitions, verify illegal transitions are rejected |
| `check-backpressure` | 13 | Simulate FUSE load, verify budget shrink, verify Critical grace period |

## 6. Crate Snapshot (Current State)

```
tidefs-background-scheduler/          # 1,410 lines — canonical scheduler
  src/lib.rs                           # BackgroundScheduler, BackgroundService,
                                       # IncrementalJobAdapter, ServicePriority,
                                       # ServiceBudget, TickReport, ServiceError

tidefs-types-incremental-job-core/     # Core types crate
  src/lib.rs                           # IncrementalJob trait, WorkBudget,
                                       # Checkpoint, CursorState, JobProgress,
                                       # StepResult, JobKind, JobId, JobError,
                                       # ServiceCheckpoint, ServiceState

tidefs-cleanup-job-core/              # CleanupJob IncrementalJob
tidefs-reclaim-job-core/              # ReclaimJob IncrementalJob
tidefs-orphan-recovery-job-core/      # OrphanRecoveryJob IncrementalJob
tidefs-local-filesystem/              # 4 production BackgroundService impls
  src/background_compaction.rs
  src/background_reclaim.rs
  src/background_orphan_reclamation.rs
  src/background_cleanup.rs
```

## 7. Integration Contracts

### 7.1 Unified Resource Governor

The background scheduler operates under the `Background` lane of the unified
resource governor (`docs/design/unified-resource-governor-design.md`). When the
governor signals resource pressure (disk I/O saturation, memory pressure),
the background budget is reduced according to the backpressure formula defined
in #1980 §4.2.

### 7.2 COMMIT_GROUP State Machine

Each background service tick coincides with a COMMIT_GROUP boundary. The scheduler runs
after the COMMIT_GROUP commit step (Phase 6 of the COMMIT_GROUP pipeline) and is never counted
against the background budget. If the COMMIT_GROUP tick initiates a sync, the scheduler
reduces `effective_budget.max_items` by 50% for the current cycle.

**Reference**: `docs/design/canonical-commit-ordering-commit_group-state-machine.md`,
`docs/design/commit_group-state-machine-design.md`.

### 7.3 Admin Service Protocol

The operator CLI commands (`tidefs service pause/resume/reset/retire/status`)
are carried over the admin wire protocol defined in
`docs/design/admin-service-wire-protocol.md`. Each command maps to an
`AdminCommand` variant with request/response types.

### 7.4 Deterministic Trace Oracle

The replay architecture (Phase 15) integrates with the deterministic trace
oracle (`docs/design/deterministic-trace-oracle-system.md`). The `TickLog`
captures every scheduling decision (which service ran, budget allocated,
items processed) and replays them deterministically for golden-trace

## 8. Design Tradeoffs (Summary)

### 8.1 Single-Threaded vs. Multi-Threaded

**Decision**: Start single-threaded inline, design for multi-threaded
work-stealing. The `send + sync` bounds on `BackgroundService` are deferred
to Phase 16 (concurrency readiness).

Multi-threading adds scheduler complexity (work stealing, load balancing,
per-core budget accounting) that can be added incrementally.

### 8.2 Budget Cascading vs. Static Allocation

**Decision**: Unused budget from higher-priority stages cascades to lower
stages. A `BestEffort` service can get >100% of its nominal budget if
higher stages are idle.

**Rationale**: Maximizes background throughput when foreground demand is low,
while maintaining strict priority ordering when demand is high.

### 8.3 Service Lifecycle: Auto-Recovery vs. Manual Reset

**Decision**: Unhealthy services require manual reset (operator or admin
protocol). Auto-recovery risks flap loops (unhealthy → running → unhealthy).

**Rationale**: Operators need visibility into why a service became unhealthy
before it resumes. Optional `auto_reset_after_cycles` property is available
for non-critical services.

### 8.4 TickLog Persistence: Memory vs. Disk

**Decision**: TickLog is an in-memory ring buffer (10,000 cycles, ~10 MiB).
Dump to disk on operator request (`tidefs scheduler dump-log`).

**Rationale**: Persisting every cycle adds write amplification. The log is

## 9. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Starvation timeout too aggressive | Medium | BestEffort services starved under load | Configurable per-stage timeout; operator tunable |
| Budget cascading starves latency-sensitive work | Low | High | Critical services exempt from cascading; grace period |
| Wire-up issues outpace scheduler capacity | Low | Medium | Per-phase issues independently schedulable; no shared write surfaces (except `lib.rs`) |

## 10. References

- [#1179] Initial background service framework design
- [#1592] Canonical design specification — `docs/design/background-service-framework-design.md`
- [#1673] Canonical design-spec (16-phase roadmap) — `docs/design/background-service-framework-design-spec.md`
- [#1674] Canonical consolidation
- [#1858] Coordination confirmed
- [#1859] Canonical consolidation: implementation deferred
- [#1877] Phases 5–10 wire-up tracking
- [#1946] Phases 5–10 wire-up specification — `docs/design/background-service-framework-phases-5-10-wire-up-tracking.md`
- [#1980] Enhanced design — `docs/design/background-service-framework-design-enhanced.md`
- [#1992] This document — coordination seal
- `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md` — #1179 original spec (redirects to canonical)
- `docs/design/unified-resource-governor-design.md` — I/O lane allocation
- `docs/design/canonical-commit-ordering-commit_group-state-machine.md` — COMMIT_GROUP pipeline
- `docs/design/admin-service-wire-protocol.md` — admin protocol
- `docs/design/deterministic-trace-oracle-system.md` — trace oracle
- `docs/UNIVERSAL_INCREMENTAL_CURSOR_FRAMEWORK_DESIGN.md` — incremental cursor framework
- `crates/tidefs-background-scheduler/src/lib.rs` — scheduler implementation (1,410 lines)
- `crates/tidefs-types-incremental-job-core/src/lib.rs` — core types
