# Coordination Pipeline Status Update (#1767)

**Issue**: [#1767](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1767)
**Status**: design-spec
**Maturity**: **design-spec** — coordination pipeline status tracking update confirming
that the design phase for cluster-wide services is substantially complete with all major
designs sealed, Rust implementation is deferred to wire-up issues for most cluster
services, and the three active implementation lanes (cleanup/reclaim, spacemap/pool
allocator, P8-03 distributed runtime) continue advancing
**Priority**: P2
**Lane**: storage-core / coordination (Layers 8-11)
**Depends on**: #1738 (coordination pipeline design seal), #1838 (health advancement
strategy), #1753 (roadmap priorities update), #1833 (STATUS.md entry architecture)
**Blocks**: All deferred cluster-service wire-up implementation issues

## Abstract

This document records the coordination pipeline status update anchored at issue
#1767. It confirms that the design phase for cluster-wide services is substantially
complete, with all major designs sealed across the four architectural layers
(Transport, Coordination, Data Flow, Observability). Rust implementation of most
cluster services is deferred to wire-up issues. Three active implementation lanes
remain: cleanup/reclaim queues (implemented-source), spacemap/pool allocator (G1
foundation complete, G2+ deferred), and P8-03 distributed runtime (9/9 canonical
component crates implemented). End-to-end 3-node cluster bootstrapping, cross-node
state machine advancement, and production distributed runtime integration remain
deferred to child GAP issues. The document establishes the canonical status snapshot
for the May 2026 coordination pipeline posture.

---

## 1. Architecture

### 1.1 Four-Layer Decomposition

The coordination pipeline spans four architectural layers, each with sealed designs
and graded implementation maturity:

| Layer | Scope | Services | Status |
|-------|-------|----------|--------|
| **Layer 8: Transport** | Bounded cluster transport, endpoint families, security | Transport session boundedness (#1210), Endpoint families (P8-01), Security/identity (#1659), BULK plane (#1666) | 4/4 designs sealed |
| **Layer 10: Data Flow** | Replication, rebuild, relocation, erasure coding | P8-03 distributed runtime, Rebuild/backfill (OW-305), Erasure-coded layout (OW-306) | Models implemented-source; runtime integration deferred |

### 1.2 Architectural Invariants

The coordination pipeline is governed by five architectural invariants that
must hold across all implementation phases:

1. **Boundedness**: No cluster service may grow state with cluster history.
   Membership state is O(current cluster size), transport state is O(active
   connections), and all operational data paths are independent of epoch history
   (#1283).
2. **Identity-first authorization**: Every service deduplication key and
   authorization decision is scoped by transport-proven peer identity (#1659).
3. **Single serialization point**: Admin mutations serialize through the current
   cluster leader, fenced by (term, epoch). Dataset-mutating operations always
   execute under the writer lease holder (#1698).
4. **Deterministic membership**: Joint-consensus membership changes, not
   gossip-based eventual consistency (#1209).
5. **Unified lane model**: All cluster services use the same `LaneConfig` struct
   and five-class scheduling priority (#1617).

### 1.3 Phase Transition Dependencies

The pipeline progresses through four sequential phases with strict ordering
dependencies:

```
Phase 1: Transport Foundation (Layer 8)
    ├── BULK plane wire protocol (#1666)
    ├── Per-lane transport budgets (#1210)
    └── Security/identity protocol (#1659)
        │
        ▼
Phase 2: Coordination Services (Layer 9)
    ├── MEMBERSHIP protocol → 3-node cluster bootstrap ← CRITICAL PATH
    ├── Distributed lock service → depends on MEMBERSHIP (term, epoch) fencing
    └── Admin proxy model → depends on MEMBERSHIP leader election
        │
        ▼
Phase 3: Data Flow Services (Layer 10)
    ├── P8-03 cross-node state machine advancement
    ├── Rebuild/backfill → depends on P8-03 transport
    └── Erasure-coded layout → depends on BULK plane + P8-03
        │
        ▼
Phase 4: Observability (Layer 11)
    └── Operator truth surfaces, dashboards, traces
```

### 1.4 Active Implementation Lanes

Three implementation lanes carry active work independent of those deferred.
Each lane has its own gate, velocity indicator, and tracked dependencies.

| Lane | Status | Key Work | Gate |
|------|--------|----------|------|
| **Cleanup/Reclaim Queues** | implemented-source | Four persistent B+tree-backed queue families, `ReclaimJob` as `IncrementalJob`, budgeted `step()`, valid-commit_group-gated inline processing, cursor-based crash-safe resume | `cargo check --workspace` + reclaim integration tests |
| **Spacemap/Pool Allocator** | G1 implemented-source, G2+ deferred | Pool-level coordination, `SpacemapV1` allocator, free-space accounting, per-metaslab parallelism deferred to #1278 | `cargo check --workspace` + `tidefs-xtask check-local-storage-allocator` |
| **P8-03 Distributed Runtime** | 9/9 crates implemented-source | Placement → commit → receipt → verify → replicate → relocate → rebuild pipeline, three-phase state machine (idle/active/draining) | 3-node cluster bootstrapping integration test |

### 1.5 Cluster Service Inventory: Design-Sealed vs. Implemented

The 16 canonical cluster service designs and their implementation state:

| # | Service | Layer | Design Maturity | Implementation |
|---|---------|-------|-----------------|----------------|
| 1 | Transport session boundedness | L8 | design-spec | Core crates implemented; per-lane budgets deferred |
| 2 | Endpoint families (P8-01) | L8 | implemented-source | Types/session/pair-graph implemented; multi-family multiplexing deferred |
| 3 | Security/identity model | L8 | design-sealed | Interfaces frozen; Rust implementation deferred |
| 4 | BULK plane protocol | L8 | design-spec | Design complete; implementation deferred |
| 5 | MEMBERSHIP service | L9 | design-spec | Design complete; implementation deferred |
| 6 | Bounded membership state | L9 | design-spec | Design complete; implementation deferred |
| 7 | Distributed lock service | L9 | design-spec | LockTable module exposed (#1832); full Raft state machine deferred |
| 9 | Atomic snapshot coordination | L9 | design-spec | Design complete; implementation deferred |
| 10 | Admin proxy model | L9 | design-spec | Design complete; implementation deferred |
| 11 | Unified scheduling classes | L9 | design-spec | `LaneClass` enum exists; unified `LaneConfig` deferred |
| 12 | P8-03 distributed runtime | L10 | implemented-source | 9/9 crates implemented; cross-node advancement deferred |
| 13 | Rebuild/backfill/rebalance | L10 | implemented-source (model) | Deterministic model; async transfers deferred |
| 14 | Erasure-coded layout | L10 | implemented-source (model) | Single-parity; production Reed-Solomon deferred |
| 15 | Operator truth surfaces | L11 | design-spec | 5 sub-documents; instrumentation deferred |

---

## 2. Data Structures

### 2.1 Pipeline Status Record

The coordination pipeline status is captured in a structured record that encodes
lane state, deferred design inventory, and health signals:

```rust
/// Top-level pipeline status record derived from Forgejo state at snapshot time.
/// This is a design-time concept; the record is materialized in STATUS.md entries.
pub struct CoordinationPipelineStatus {
    /// UTC timestamp of this status snapshot.
    pub snapshot_at: u64,

    /// Monotonically increasing status epoch (matches STATUS.md entry count).
    pub status_epoch: u32,

    /// Overall pipeline phase: DESIGN_PHASE | TRANSITION | IMPLEMENTATION_PHASE
    pub phase: PipelinePhase,

    /// Active implementation lane state.
    pub active_lanes: [LaneStatus; 3],

    /// Deferred design inventory (all 16 services).
    pub deferred_services: Vec<ServiceStatus>,

    /// Aggregate health derived from lane states.
    pub aggregate_health: AggregateHealth,

    /// Open coordination-lane issue metrics.
    pub issue_metrics: IssueMetrics,

    /// Proliferation containment flags.
    pub proliferation: ProliferationState,

    /// TideFS version at snapshot time.
    pub version: (u16, u16, u16),
}

/// Pipeline phase discriminator.
pub enum PipelinePhase {
    /// Design phase: services are being designed, not implemented.
    DesignPhase,
    /// Transition: design sealing complete, wire-up beginning.
    Transition,
    /// Implementation phase: services being implemented from sealed designs.
    ImplementationPhase,
}

/// Per-lane status record.
pub struct LaneStatus {
    /// Lane identifier.
    pub lane: ImplementationLane,

    /// Maturity of this lane's work.
    pub maturity: Maturity,

    /// Crate count contributing to this lane.
    pub crate_count: u32,

    /// Count of implemented-source components.
    pub implemented_components: u32,

    /// Count of deferred components.
    pub deferred_components: u32,

    /// Percent completion (implemented / (implemented + deferred)).
    pub completion_pct: f32,

    /// Issues in flight for this lane.
    pub in_flight_issues: u32,

    /// Blocking dependencies (issue numbers).
    pub blocking: Vec<u32>,
}

/// Implementation lane identifiers.
pub enum ImplementationLane {
    CleanupReclaimQueues = 0,
    SpacemapPoolAllocator = 1,
    P803DistributedRuntime = 2,
}

/// Service design and implementation status.
pub struct ServiceStatus {
    /// Service name.
    pub name: String,

    /// Architectural layer (8-11).
    pub layer: u8,

    /// Design maturity.
    pub design_maturity: Maturity,

    /// Implementation maturity.
    pub implementation_maturity: Maturity,

    /// Design document path.
    pub design_doc: Option<String>,

    /// Reference issue numbers.
    pub issues: Vec<u32>,

    /// Whether implementation is deferred.
    pub deferred: bool,

    /// Reason for deferral when deferred=true.
    pub deferral_reason: Option<String>,
}

/// Maturity levels for designs and implementations.
pub enum Maturity {
    /// Concept only; no formal design document.
    Concept,
    /// Design specification exists but not yet sealed.
    DesignSpec,
    /// Design sealed; no further design changes permitted.
    DesignSealed,
    /// Rust types and interfaces exist.
    TypesImplemented,
    /// Full source implementation complete.
    ImplementedSource,
    ProductionGated,
}

/// Aggregate pipeline health derived from domain maxima.
pub enum AggregateHealth {
    /// All domains healthy; advancement velocity normal.
    Green,
    /// At least one domain degraded; monitor.
    Yellow,
    /// At least one domain blocked or escalated.
    Red,
}

/// Issue metrics from Forgejo labels.
pub struct IssueMetrics {
    pub total_open: u32,
    pub codex_ready: u32,
    pub codex_claimed: u32,
    pub codex_needs_review: u32,
    pub codex_blocked: u32,
    pub codex_done_this_window: u32,
}

/// Proliferation containment state.
pub struct ProliferationState {
    /// Total coordinator-sourced issues open.
    pub total_coordinator_issues: u32,
    /// Whether proliferation threshold has been exceeded.
    pub proliferation_alert: bool,
    /// Recommended action when alert is true.
    pub recommended_action: Option<String>,
}
```

### 2.2 STATUS.md Entry Schema

Each coordination pipeline status update materializes as a STATUS.md entry
following the canonical schema defined in #1833:

```
## YYYY-MM-DD: #<issue> <title>
- **Lane status**: per-lane counts and summaries
- **Coordination pipeline health**: narrative health assessment
- **Recently closed**: issues closed since last entry
- **Roadmap priorities**: ordered priority list
- Closes: #<issue>
```

### 2.3 Dependency Graph Encoding

Cross-service dependencies are encoded as a directed acyclic graph (DAG) to
enable topological ordering of wire-up issues:

```rust
/// A node in the coordination pipeline dependency graph.
pub struct ServiceNode {
    pub name: String,
    pub issue: u32,
    pub layer: u8,
    pub deps: Vec<u32>,        // issue numbers this service depends on
    pub blocks: Vec<u32>,      // issue numbers this service blocks
    pub phase: u8,             // 1-4: transport → coordination → dataflow → observability
    pub critical_path: bool,   // true if on the critical path to 3-node cluster boot
}

/// The full dependency graph for deferred services.
pub struct DependencyGraph {
    pub nodes: Vec<ServiceNode>,
    pub critical_path: Vec<u32>,  // topologically sorted critical-path issue numbers
    pub cycle_detected: bool,
}
```

---

## 3. Algorithms

### 3.1 Status Delta Computation

When generating a new coordination pipeline status update, the delta between
the previous STATUS.md entry and the current Forgejo state is computed:

```
Algorithm: ComputeCoordinationDelta
Input:  prev_entry: STATUS.md header entry (date + issue)
        current_forgejo: Forgejo API issue list for coordination labels
Output: delta: StatusDelta

1. Parse prev_entry for lane counts, closed issues, health narrative.
2. Query Forgejo for all issues with labels: lane:storage-core,
   (codex:ready | codex:claimed | codex:needs-review | codex:blocked | codex:done).
3. Compute lane_status changes:
   a. For each lane L in {cleanup, spacemap, p803}:
      - prev_open = open_count from prev_entry
      - curr_open = count of open issues with lane label matching L
      - delta_open = curr_open - prev_open
      - closed = issues with codex:done set since prev_entry.snapshot_at
      - velocity = closed.count / days_since_prev
   b. If delta_open > 0 → growing_backlog
      If delta_open < 0 → shrinking_backlog
      If delta_open == 0 → steady_state
4. Compute deferred_design_changes:
   a. For each of 16 canonical services:
      - Check Forgejo for design-seal issues referencing that service.
      - If a new seal issue exists since prev_entry → newly_sealed.
      - If a wire-up issue has been claimed → wire_up_started.
   b. Update deferred_services vector with new statuses.
5. Compute aggregate_health:
   a. D1 (active lanes): Healthy if any lane advanced since prev; Degraded if no
      advancement in 14 days; Blocked if no advancement in 30 days.
   b. D2 (deferred designs): Healthy if no seal staleness; AtRisk if any design
      is > 90 days sealed without wire-up.
   c. D3 (dependency graph): Healthy if no cycles; Blocked if cycle detected.
   d. D4 (serial surfaces): Healthy if ≤ 1 active claim per surface; Degraded
      if 2; Blocked if > 2.
   e. Aggregate = max(D1..D4).
6. Compute proliferation_state:
   a. Count coordinator-sourced (source:coordinator) issues open.
   b. If count > threshold → proliferation_alert = true,
      recommended_action = "Audit and deduplicate coordinator-sourced issues."
7. Generate STATUS.md entry from delta.
8. Return delta.
```

### 3.2 Lane Advancement Scoring

Each active implementation lane is scored for advancement velocity using a
trailing-window heuristic:

```
Algorithm: ScoreLaneAdvancement
Input:  lane: ImplementationLane
        since: DateTime (previous STATUS.md entry timestamp)
        forgejo_state: Forgejo issue state
Output: advancement: LaneAdvancement

1. Identify all issues with lane label matching `lane`.
2. closed_since = filter(codex:done AND closed_at > since)
3. claimed_now = filter(codex:claimed)
4. in_review_now = filter(codex:needs-review)
5. blocked_now = filter(codex:blocked)

6. velocity = closed_since.count / days_between(since, now)
7. stall_days = days_since_last_closure(closed_since)

8. if velocity >= target_velocity:
       state = Healthy
   else if velocity > 0 and stall_days < 14:
       state = Degraded
   else if stall_days < 30:
       state = AtRisk
   else:
       state = Blocked

9. Return LaneAdvancement { lane, state, velocity, stall_days,
      closed_count: closed_since.count, in_flight: claimed_now.count + in_review_now.count,
      blocked: blocked_now.count }
```

### 3.3 Wire-Up Deferral Assessment

When assessing whether a sealed design is ready for wire-up, the following
algorithm evaluates dependency readiness and serial-surface availability:

```
Algorithm: AssessWireUpReadiness
Input:  service: ServiceStatus
        dep_graph: DependencyGraph
        serial_surfaces: Set<SerialSurface>
Output: readiness: WireUpReadiness

1. Check design maturity: if service.design_maturity < DesignSealed → NotReady.
2. Check dependency resolution:
   a. For each dep in service.deps:
      - If dep.implementation_maturity < ImplementedSource and dep is NOT itself
        a deferred design → BlockedByDependency(dep).
   b. If all deps are either ImplementedSource or are also deferred (parallel
      wire-up possible) → DependenciesResolved.
3. Check serial surface contention:
   a. If service touches a serial surface in serial_surfaces:
      - active = count of active claims on that surface.
      - If active > 0 and the claim is not for this service → SurfaceContended.
4. If all checks pass → ReadyForWireUp.
5. Return WireUpReadiness { state, blocking_deps: Vec<u32>, contended_surface: Option<String> }.
```

### 3.4 Proliferation Containment

Coordinator-sourced issues can accumulate faster than workers can close them.
The proliferation containment algorithm limits noise:

```
Algorithm: ContainProliferation
Input:  coordinator_issues: Vec<Issue>,
        threshold: u32 = 20
Output: action: ProliferationAction

1. open_count = coordinator_issues.filter(state == open).count()
2. recently_closed = coordinator_issues.filter(closed_at > now - 7_days).count()
3. stale_open = coordinator_issues.filter(updated_at < now - 30_days AND state == open).count()

4. if open_count > threshold:
       if stale_open > 0:
           return AuditAndCloseStale(stale_open)
       else:
           return HoldNewIssues(reason: "All open issues are active; prioritize closing")
   else if open_count > threshold * 0.75:
       return MonitorAndWarn(current: open_count, threshold: threshold)
   else:
       return NoAction
```

---

## 4. Tradeoffs

### 4.1 Design-Sealing vs. Implementation Completeness

**Tradeoff**: Sealing all 16 cluster service designs before implementing any
one of them.

| Approach | Advantages | Disadvantages |
|----------|------------|---------------|
| **Seal all first (chosen)** | Ensures architectural consistency across all services; prevents late-breaking API changes from rippling through implemented services; enables parallel wire-up without cross-service rework. | Delays integration feedback; designs may contain unnoticed gaps that only surface during implementation; creates a large batch of deferred work. |
| **Implement incrementally** | Faster feedback on API ergonomics and correctness; each service's implementation informs the next design. | Risk of cascading API changes when downstream services are designed later; serializes work across all 16 services. |

**Rationale**: The seal-first approach is chosen because the 16 services are
tightly coupled through shared invariants (boundedness, identity-first
authorization, single serialization point). Late-breaking changes to any
invariant would cascade through all downstream implementations.

### 4.2 Deferred Wire-Up vs. Early Rust Implementation

**Tradeoff**: Deferring Rust implementation of most cluster services to
individual wire-up issues vs. implementing them immediately.

| Approach | Advantages | Disadvantages |
|----------|------------|---------------|
| **Defer to wire-up (chosen)** | Parallelizes work across Codex instances without serial-surface contention; allows active lanes (cleanup, spacemap, P8-03) to advance without blocking on cluster service code; keeps implementer batches small and well-bounded. | Accumulates deferred work that must eventually be done; risk of design staleness if wire-up doesn't happen promptly. |
| **Implement immediately** | Reduces deferred backlog; provides early integration testing opportunities. | Serializes all cluster-service work through the single serial surfaces (`tidefs-local-filesystem/src/lib.rs`, `tidefs-local-object-store/src/lib.rs`); blocks active lane progress. |

**Rationale**: The deferral strategy maximizes throughput in the current
implementation phase by allowing the three active lanes to advance in parallel
without serial-surface contention. Wire-up issues inherit sealed designs with
frozen interfaces, minimizing rework risk.

### 4.3 Three Active Lanes vs. Single Sequential Lane

**Tradeoff**: Running three active implementation lanes in parallel vs. focusing
all resources on one lane at a time.

| Approach | Advantages | Disadvantages |
|----------|------------|---------------|
| **Three parallel lanes (chosen)** | Maximizes throughput when lanes touch disjoint write surfaces; allows lane-specific expertise to develop; prevents a single-lane stall from blocking all progress. | Requires coordination to avoid serial-surface collisions; more complex health monitoring; risk of resource dilution if lanes compete for the same Codex instances. |
| **Single sequential lane** | Simpler coordination; no write-surface contention; clear priority ordering. | Any stall blocks all progress; slower overall velocity; lane-specific work cannot be parallelized. |

**Rationale**: The three active lanes touch largely disjoint write surfaces.
Cleanup/reclaim operates on `tidefs-reclaim-*` crates; spacemap operates on
`tidefs-local-object-store` and `tidefs-types-spacemap-*` crates; P8-03 operates
on its 9 component crates. The serial surfaces (`tidefs-local-filesystem`,
`tidefs-local-object-store`) are the only conflict points, and those are managed
by the claim barrier.

### 4.4 Forgejo-Label Coordination vs. Centralized Scheduler

**Tradeoff**: Using Forgejo labels and the `tidefs-claim` barrier as the distributed
coordination mechanism vs. a centralized runtime scheduler.

| Approach | Advantages | Disadvantages |
|----------|------------|---------------|
| **Forgejo labels + claim barrier (chosen)** | Zero runtime dependency; works with any number of Codex instances; Forgejo is already the single source of truth for work items; labels are human-readable and auditable. | No real-time contention resolution; claim races are possible (mitigated by post-claim re-check); requires discipline to maintain label hygiene. |
| **Centralized scheduler** | Real-time contention detection; automatic load balancing; built-in priority enforcement. | Adds a runtime dependency; single point of failure; requires designing, implementing, and operating a scheduler service — which itself would be coordination-layer work. |

**Rationale**: The Forgejo-label approach is sufficient because the work batch
sizes are small (one issue per Codex instance), the claim barrier catches races
deterministically, and the overhead of a centralized scheduler would outweigh
its benefits at the current implementation scale.

### 4.5 Coordinator-Sourced Issue Generation vs. Manual Issue Creation

**Tradeoff**: Auto-generating coordination pipeline status update issues from
STATUS.md vs. manually creating each issue.

| Approach | Advantages | Disadvantages |
|----------|------------|---------------|
| **Auto-generated (chosen)** | Consistent issue formatting; no human error in issue creation; ensures STATUS.md and Forgejo stay synchronized; scales to any issue volume. | Can produce redundant issues if the coordinator runs too frequently; proliferation risk if old status update issues aren't closed promptly. |
| **Manual creation** | Human judgment on whether an update is warranted; avoids proliferation. | Inconsistent formatting; risks STATUS.md/Forgejo drift; doesn't scale. |

**Rationale**: The auto-generation approach is chosen because it ensures
consistency and synchronization between STATUS.md and Forgejo. Proliferation is
controlled by the containment algorithm (§3.4) which audits and closes stale
coordinator-sourced issues.

---

## 5. Residual Risk

### 5.1 Design Staleness

Risk: Sealed designs may become stale if wire-up is delayed beyond the point
where crate APIs have evolved significantly. Mitigation: Each wire-up issue must
include a design-audit step that compares the sealed design against current
crate public APIs before beginning implementation.

### 5.2 Proliferation Drift

Risk: Coordinator-sourced status update issues may accumulate faster than they
are closed, creating noise in the Forgejo project board. Mitigation: The
proliferation containment algorithm flags when coordinator-sourced issue count
exceeds threshold, and each closure includes a deduplication comment.

### 5.3 Single-Surface Bottleneck

Risk: Both the spacemap lane and P8-03 runtime may need to touch
`tidefs-local-object-store/src/lib.rs` simultaneously, creating a claim
contention bottleneck. Mitigation: The claim barrier enforces serial access,
and the lane decomposition was designed to minimize overlap on serial surfaces.

### 5.4 Deferred Backlog Accumulation

Risk: The 13 deferred cluster services represent a significant implementation
backlog that must eventually be addressed. Mitigation: The dependency graph
(§2.3) prioritizes wire-up in topological order, starting with the critical path

---


**Gate**: `cargo check --workspace`

This is a design-spec document only. No Rust source changes are required. The
workspace must continue to compile cleanly.

---

## 7. References

- [#1738](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1738) — Coordination pipeline design seal
- [#1838](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1838) — Coordination pipeline health advancement strategy
- [#1833](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1833) — Coordination pipeline STATUS.md entry architecture
- [#1753](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1753) — Roadmap priorities update
- [#1283](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1283) — Bounded membership state
- [#1617](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1617) — Unified scheduling classes
- `docs/design/coordination-pipeline-cluster-services-design-seal.md`
- `docs/design/coordination-pipeline-health-advancement-strategy.md`
- `docs/design/coordination-pipeline-status-update.md`
- `docs/STATUS.md`
- `docs/FEATURE_MATRIX.md`
