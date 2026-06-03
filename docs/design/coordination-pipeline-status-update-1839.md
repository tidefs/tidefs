# Coordination Pipeline Status Update (#1839)

**Issue**: [#1839](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1839)
**Status**: design-spec
**Maturity**: **design-spec** — coordination pipeline status tracking update covering
the design-phase closure for cluster-wide services, the three remaining active
implementation lanes, deferred wire-up dependencies, and the proliferation
containment strategy for coordinator-sourced issues
**Priority**: P2
**Lane**: storage-core / coordination (Layers 8-11)
**Depends on**: #1738 (design seal), #1838 (health advancement strategy), #1753 (roadmap priorities)
**Blocks**: All deferred cluster-service wire-up implementation issues

## Abstract

This document updates the coordination pipeline status as of the early May 2026
snapshot. It records that the design phase for cluster-wide services is substantially
complete, with all major designs sealed and a 40-issue design-seal wave (#1880–#1981)
confirmed. Three active implementation lanes remain: cleanup/reclaim queues
(implemented-source), spacemap/pool allocator (G1 foundation complete, G2+
deferred), and P8-03 distributed runtime (9/9 canonical component crates
implemented). End-to-end 3-node cluster bootstrapping, cross-node state machine
advancement, and production distributed runtime integration remain deferred to
child GAP issues. The document serves as the authoritative human-readable snapshot
of coordination pipeline health, building on the architecture defined in #1738,
the health monitoring framework defined in #1838, and the roadmap priorities
defined in #1753.

---

## 1. Coordination Pipeline Architecture

### 1.1 Four-Layer Decomposition

The coordination pipeline spans four architectural layers, each with sealed designs
and graded implementation maturity:

| Layer | Scope | Services | Status |
|-------|-------|----------|--------|
| **Layer 8: Transport** | Bounded cluster transport, endpoint families, security | Transport session boundedness (#1210), Endpoint families (P8-01), Security/identity (#1659), BULK plane (#1666) | 4/4 designs sealed; security identity sealed via #1843 |
| **Layer 10: Data Flow** | Replication, rebuild, relocation, erasure coding | P8-03 distributed runtime, Rebuild/backfill, Erasure-coded layout | All models implemented-source; runtime integration deferred |

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

### 1.3 Phase Transitions

The pipeline transitions through four sequential phases:

```
Phase 1: Transport Foundation (Layer 8)
    ├── BULK plane wire protocol
    ├── Per-lane transport budgets
    └── Security/identity protocol (PSK infrastructure)
        │
Phase 2: Coordination Services (Layer 9)
    ├── MEMBERSHIP protocol (3-node cluster bootstrap) ← CRITICAL PATH
    ├── Distributed lock service (depends on MEMBERSHIP fencing)
    └── Admin proxy model (depends on MEMBERSHIP leader election)
        │
Phase 3: Data Flow Services (Layer 10)
    ├── P8-03 cross-node state machine advancement
    ├── Rebuild/backfill (depends on P8-03 transport)
    └── Erasure-coded layout (depends on BULK plane + P8-03)
        │
Phase 4: Observability (Layer 11)
    └── Operator truth surfaces, dashboards, traces
```

---

## 2. Data Structures

### 2.1 Pipeline Health Record

The coordination pipeline health is captured in a structured record derived
from the health monitoring framework (#1838). This is a design-time concept;
no runtime monitoring is required. The health report is generated from Forgejo
state at review intervals.

```rust
/// Top-level health state for the coordination pipeline.
pub struct CoordinationPipelineHealth {
    /// Monotonically increasing health report epoch.
    pub report_epoch: u64,

    /// UTC timestamp of this health assessment.
    pub assessed_at: u64,

    /// Health state per domain (4 domains).
    pub domains: [DomainHealth; 4],

    /// Aggregate pipeline health derived from domain states.
    pub aggregate: AggregateHealth,

    /// Count of open coordination-lane issues by label.
    pub issue_metrics: IssueMetrics,

    /// Active claim inventory.
    pub claims: Vec<ActiveClaim>,
}

/// Health assessment for a single domain.
pub struct DomainHealth {
    /// Domain identifier.
    pub domain: HealthDomain,

    /// Current health state.
    pub state: HealthState,

    /// Consecutive assessment periods in non-Healthy state.
    pub degraded_periods: u32,

    /// Count of issues in this domain that are advancing.
    pub advancing_issues: u32,

    /// Count of issues in this domain that are stalled.
    pub stalled_issues: u32,

    /// Count of dependencies blocking advancement.
    pub blocking_dependencies: u32,

    /// Human-readable health summary.
    pub summary: String,
}

/// The four health domains.
pub enum HealthDomain {
    ActiveImplementationLanes = 0,  // D1
    DeferredDesignToWireUp = 1,     // D2
    DependencyGraph = 2,            // D3
    SerialWriteSurfaces = 3,        // D4
}

/// Health state for a domain.
pub enum HealthState {
    Healthy,
    Degraded,
    AtRisk,
    Blocked,
    Escalated,
}

/// Aggregate pipeline health.
pub enum AggregateHealth {
    Green,
    Yellow,
    Red,
}

/// Issue label counts from the coordination lane.
pub struct IssueMetrics {
    pub total_open: u32,
    pub codex_ready: u32,
    pub codex_claimed: u32,
    pub codex_needs_review: u32,
    pub codex_blocked: u32,
    pub codex_done_this_window: u32,
    pub deferred_no_label: u32,
}

/// An active claim on a serial write surface or implementation lane.
pub struct ActiveClaim {
    pub issue_number: u32,
    pub issue_title: String,
    pub lane: String,
    pub serial_surface: Option<String>,
    pub claimed_at: u64,
    pub last_activity_at: u64,
    pub claim_age_hours: u32,
}
```

### 2.2 Health State Machine

Each domain transitions through a defined health state machine:

```
                         ┌──────────┐
                         │  Healthy │
                         └────┬─────┘
                              │
             ┌────────────────┼────────────────┐
             ▼                ▼                 ▼
      ┌──────────┐    ┌──────────────┐   ┌──────────────┐
      │Degraded  │    │  At-Risk     │   │  Blocked     │
      │(slowdown)│    │ (approaching │   │ (no progress)│
      └────┬─────┘    │  stall)      │   └──────┬───────┘
           │          └──────┬───────┘          │
           │                 │                   │
           └────────┬────────┴───────────────────┘
                    │
                    ▼
             ┌──────────────┐
             │  Escalated   │
             │ (comment on  │
             │  issue)      │
             └──────────────┘
```

### 2.3 Advancement Event Taxonomy

Advancement events are classified by lane and impact:

| Event | Lane | Impact | Detection |
|-------|------|--------|-----------|
| `design_sealed` | D2 | Design phase complete for a service | Forgejo label `kind:design` + close |
| `implementation_started` | D1 | Wire-up coding begins | Forgejo label `codex:claimed` |
| `implementation_complete` | D1 | Crate compiles with types/algos | `codex:needs-review` label |
| `dependency_resolved` | D3 | Blocking issue closed | Forgejo issue closed event |
| `serial_surface_released` | D4 | Claim released | `codex:done` + no active claim |
| `stall_detected` | Any | No progress for N periods | Health assessment cycle |
| `regression_detected` | Any | `cargo check` breakage | CI or manual check |

---

## 3. Algorithms

### 3.1 Health Propagation Algorithm

When a domain's dependency blocks advancement, the blockage propagates through
the pipeline according to the following algorithm:

```
Algorithm: propagate_health(dependency_graph, health_snapshot)

Input:  dependency_graph  — directed graph of issue Depends/Blocks relationships
        health_snapshot   — current DomainHealth for each of {D1, D2, D3, D4}

Output: updated health_snapshot with propagated blockage counts

1. For each domain d in {D1, D2, D3, D4}:
   a. Let B(d) = set of issues in domain d that are currently Blocked
   b. For each blocked issue i in B(d):
      i.   Let dep_issues = dependency_graph.direct_dependencies(i)
      ii.  For each dep in dep_issues:
           A. If dep.status in {Blocked, Escalated}:
              increment domain(d).blocking_dependencies
           B. If dep.domain != d:
              propagate stall to dep.domain with severity = dep.stall_duration

2. For each domain d:
   a. If domain(d).blocking_dependencies > threshold(d):
      domain(d).state = AtRisk
   b. If domain(d).stalled_issues > 0 AND domain(d).blocking_dependencies == 0:
      domain(d).state = Blocked  (self-stall)

3. Compute AggregateHealth:
   a. If any domain is Blocked or Escalated → Red
   b. Else if any domain is AtRisk → Yellow
   c. Else → Green

4. Return updated health_snapshot
```

### 3.2 Stall Detection Algorithm

Stall detection operates over a configurable observation window:

```
Algorithm: detect_stalls(domain, observation_window, stall_threshold)

Input:  domain              — one of {D1, D2, D3, D4}
        observation_window  — number of assessment periods to consider (default: 3)
        stall_threshold     — max periods without advancement before Blocked (default: 2)

Output: updated DomainHealth with stall assessment

1. Let advancing = count of advancement events for domain in observation_window
2. Let total = count of open issues in domain

3. Compute velocity = advancing / observation_window

4. If velocity == 0:
   a. domain.degraded_periods += 1
   b. If domain.degraded_periods >= stall_threshold:
      domain.state = Blocked
      domain.stalled_issues = total
   c. Else:
      domain.state = AtRisk

5. Else if velocity < historical_median(domain):
   a. domain.state = Degraded
   b. domain.degraded_periods += 1

6. Else:
   a. domain.state = Healthy
   b. domain.degraded_periods = 0

7. Return domain
```

### 3.3 Escalation Algorithm

When a domain enters Blocked state, escalation follows a defined protocol:

```
Algorithm: escalate(domain, issue)

Input:  domain  — the blocked health domain
        issue   — the blocking Forgejo issue

Output: escalation comment posted on issue, domain.state = Escalated

1. Compose escalation comment:
   a. "## Coordination Pipeline Escalation"
   b. "Domain: {domain.name} entered Blocked state at {timestamp}"
   c. "Degraded periods: {domain.degraded_periods}"
   d. "Blocking issue: #{issue.number}"
   e. "Impact: {enumerate blocked downstream issues}"

2. Post comment on issue via Forgejo API

3. Set domain.state = Escalated

4. Return

Note: Escalated → Healthy transition requires manual resolution:
      1. Blocking issue is closed OR explicitly waived
      2. Next health assessment observes velocity > 0
      3. Domain transitions Escalated → Healthy
```

### 3.4 Proliferation Containment Algorithm

Coordinator-sourced issues can proliferate beyond the pipeline's implementation
capacity. The containment algorithm throttles issue generation:

```
Algorithm: contain_proliferation(open_issues, capacity, cadence)

Input:  open_issues  — count of open coordination-lane issues
        capacity     — sustainable implementation capacity (default: 5 active)
        cadence      — minimum interval between coordinator issue generations

Output: throttle decision (ALLOW or DEFER)

1. If open_issues > capacity * 3:
   a. Log: "Proliferation alert: {open_issues} open vs capacity {capacity}"
   b. Return DEFER (throttle coordinator generation until open_issues < capacity * 2)

2. If open_issues > capacity * 2:
   a. Apply dedup filter: check if proposed issue duplicates existing open issue
   b. If duplicate: return DEFER
   c. If not duplicate AND last_generation_age > cadence: return ALLOW
   d. Else: return DEFER

3. Else:
   a. Return ALLOW
```

---

## 4. Current Pipeline State

### 4.1 Active Implementation Lanes

| Lane | Status | Key Metrics |
|------|--------|-------------|
| **Cleanup/reclaim queues** | implemented-source | `tidefs-reclaim-queue-core`, `tidefs-reclaim-job-core`, `tidefs-reclaim`, `BackgroundReclaim` live in `tidefs-local-filesystem`. Delta-recording, cursor-resumable, COMMIT_GROUP-gated inline processing. Deferred: erasure coding rebake, inode tombstone compaction, cluster-distributed reclaim. |
| **Spacemap/pool allocator** | G1 implemented-source | `tidefs-spacemap-allocator` (SegmentFreeMap, SpaceMapCheckpointV1, metaslab-partitioned bitmaps, ENOSPC), `tidefs-pool-allocator` (per-metaslab cursors, metaslab selection, ENOSPC propagation). ~60 unit tests. G2+ multi-device coordination deferred to #1694. |
| **P8-03 distributed runtime** | 9/9 crates implemented-source | All canonical component crates implemented: `tidefs-verification-engine`, `tidefs-flow-commit-coordinator`, `tidefs-chunk-shipper`, `tidefs-rebuild-planner`, `tidefs-rebalance-planner`, `tidefs-relocation-planner`, `tidefs-placement-planner`, `tidefs-placement-runtime`, `tidefs-partition-runtime`. End-to-end 3-node bootstrap deferred. |

### 4.2 Design-Sealed Inventory

All 16 canonical cluster-service designs are sealed. The design-seal wave
(#1880–#1981) covers 40 issues across all four layers:

| Layer | Sealed Designs | Representative Issues |
|-------|---------------|----------------------|
| Layer 8 (Transport) | 4 | #1210 (boundedness), P8-01 (endpoint families), #1843 (security), #1666 (BULK plane) |
| Layer 10 (Data Flow) | 3 models | OW-304 (replicated storage), OW-305 (rebuild), OW-306 (erasure coding) |
| Supporting | 2 | #1617 (lane model), #1283 (boundedness) |

### 4.3 Deferred Wire-Up Dependencies

The following implementation is deferred to wire-up issues, each dependent on
specific sealed designs:

| Wire-Up Target | Depends On | Status |
|----------------|-----------|--------|
| MEMBERSHIP protocol wire-up | #1209 design sealed | Deferred; CRITICAL PATH for all L9 services |
| Distributed lock wire-up | #1955 sealed, #1209 MEMBERSHIP runtime | Deferred |
| Admin proxy wire-up | #1698 sealed, MEMBERSHIP leader election | Deferred |
| P8-03 cross-node advancement | 9/9 crates implemented, needs 3-node bootstrap | Deferred |
| BULK plane wire-up | #1666 design sealed, transport infrastructure | Deferred |

### 4.4 Pipeline Health Assessment

| Domain | State | Advancing | Stalled | Blocked By |
|--------|-------|-----------|---------|------------|
| D1: Active Implementation | **Healthy** | 3 lanes advancing | 0 | None; all lanes autonomous |
| D2: Deferred Design→Wire-Up | **Degraded** | 0 wire-ups active | 16 deferred | MEMBERSHIP (#1209) blocking L9 wire-ups |
| D3: Dependency Graph | **Healthy** | No cycles detected | 0 | All deps are linear; no circularity |
| D4: Serial Write Surfaces | **Healthy** | 0 active claims | 0 | Claim barrier (§1.3 AGENTS.md) active |

**Aggregate**: **Yellow** — D2 is Degraded pending MEMBERSHIP wire-up.

---

## 5. Tradeoffs

### 5.1 Deferred Wire-Up vs. Immediate Implementation

| Factor | Deferred Wire-Up (Chosen) | Immediate Implementation |
|--------|--------------------------|-------------------------|
| **Parallelism** | Multiple wire-up issues can proceed in parallel once MEMBERSHIP unblocks | Sequential implementation gated on each dependency |
| **Claim barrier** | Single worker per serial surface; reduced contention | Higher contention risk on `tidefs-local-filesystem` |
| **Velocity** | Slower initial progress; higher confidence in correctness | Faster initial progress; higher rework risk |
| **Coordination overhead** | Each wire-up issue requires explicit dependency resolution | Implicit ordering avoids explicit dependency tracking |

**Decision**: Deferred wire-up is chosen because (a) the design phase is substantially
complete and sealed interfaces provide a stable contract, (b) parallel wire-up
enables multiple workers after MEMBERSHIP unblocks, and (c) explicit dependency
tracking via Forgejo `Depends on`/`Blocks` labels provides visibility.

### 5.2 MEMBERSHIP as Critical Path vs. Parallel Coordination Start

| Factor | MEMBERSHIP-First (Chosen) | Parallel Start |
|--------|--------------------------|---------------|
| **Time-to-production** | Sequential; MEMBERSHIP must complete before any L9 service is production-ready | Potentially faster if MEMBERSHIP work is straightforward |

**Decision**: MEMBERSHIP-first is chosen because every L9 service requires
deterministic epoch fencing for correctness. The joint-consensus model (#1209)
and atomic snapshot consistent cuts. Implementing L9 services without MEMBERSHIP
would require a temporary compatibility layer that would be discarded, increasing
total implementation cost.

### 5.3 Coordinator Proliferation: Generate vs. Throttle

| Factor | Throttle (Chosen) | Unrestricted Generation |
|--------|------------------|------------------------|
| **Issue stockpile** | Bounded; prevents infinite ready-queue growth | Unbounded; stockpile grows with coordinator cadence |
| **Worker starvation** | Workers always have a manageable ready set | Workers may be overwhelmed by choice; priority dilution |
| **Staleness** | Fewer issues, each more current | Many issues may become stale before implementation |

**Decision**: Throttle with dedup filter is chosen. The coordinator operates at
approximately 7.5× generation-to-closure ratio. Without containment, the ready-issue
stockpile grows unboundedly, diluting priority and increasing staleness risk.

### 5.4 Serial Write Surface Contention: Claim Barrier vs. Optimistic Locking

| Factor | Claim Barrier (Chosen) | Optimistic Locking |
|--------|----------------------|-------------------|
| **Correctness** | Pre-claim check prevents overlapping edits | Merge conflicts detected at integration time |
| **Throughput** | Lower parallelism on serial surfaces | Higher parallelism; merge conflict cost |
| **Implementation complexity** | Simple: Forgejo label + claim script | Complex: requires three-way merge and conflict resolution logic |
| **Fit for design phase** | Excellent: design docs don't contend for serial surfaces | Overkill: unnecessary complexity for design-only work |

**Decision**: Claim barrier is chosen. For the current design phase, serial surface
contention is minimal (design docs are independent). As implementation transitions
to code, the claim barrier provides the necessary coordination without the
complexity of optimistic locking and merge conflict resolution.

---

## 6. Roadmap Priorities

### 6.1 Immediate (Design → Implementation Transition)

1. **MEMBERSHIP wire-up (#1209)**: Critical-path blocker for all L9 services.
   and P8-03 cross-node state machine advancement.
2. **Cleanup/reclaim queue wire-up completion**: Integrate remaining deferred
   phases (erasure coding rebake, inode tombstone compaction).
3. **Spacemap G2+**: Multi-device coordination for pool-level space allocation.

### 6.2 Medium-Term (Implementation → Integration)

4. **P8-03 distributed runtime**: 3-node cluster bootstrap with cross-node
   state machine advancement via simnet or QEMU harness.
5. **Transport boundedness**: Per-lane budget enforcement across all cluster
   transport connections.

### 6.3 Long-Term (Integration → Production)

7. **Distributed lock service**: Multi-writer concurrency with Raft-embedded
   fault tolerance.
8. **Cluster-wide atomic snapshots**: Consistent-cut freeze across all nodes.
9. **Erasure coding production**: Reed-Solomon with networked placement.
10. **Full operator observability**: Dashboards, traces, truth surfaces.

---



| Check | Method | Status |
|-------|--------|--------|
| All 16 designs sealed | Forgejo label audit | Complete |
| No architectural invariant violations | Cross-reference design docs against §1.2 invariants | Complete |
| Dependency graph is acyclic | Topological sort of Depends/Blocks graph | Complete (linear DAG) |
| Serial write surface claims non-overlapping | Forgejo claim label audit | Complete |
| `cargo check --workspace` passes | Automated | Gate |


Each wire-up issue must satisfy the gate criteria defined in §4 of #1738:

1. Interface freeze confirmation
2. Write-set declaration respecting serial-surface constraints
4. Dependency resolution
5. `cargo check --workspace` and `cargo test --workspace` pass

---

## 8. Integration Contracts

### 8.1 STATUS.md Update Contract

Every coordination pipeline status update must:

1. Query Forgejo API for current lane state before writing
2. Parse the previous Coordination Status entry from STATUS.md
3. Compute deltas between previous and current state
4. Include: lane status, overall project metrics, pipeline health narrative,
   velocity assessment, proliferation analysis, and roadmap priorities
5. Prepend the new entry at the top of STATUS.md
6. Close the Forgejo issue that triggered the update

### 8.2 FEATURE_MATRIX.md Update Contract

When a capability's maturity changes:

- `design-sealed`: Design finalized, no further design changes expected
- `implemented-source`: Core types and protocols implemented in crates

### 8.3 Cross-Document Consistency Contract

| Document | Consistency Rule |
|----------|-----------------|
| `docs/STATUS.md` | Most recent entry reflects current Forgejo state |
| `docs/FEATURE_MATRIX.md` | Row maturity matches crate implementation state |
| `docs/design/*.md` | Design docs reference correct issue numbers and status |
| Forgejo labels | Issue labels match documented maturity state |

---

## 9. Residual Risk

- **Interface drift**: Sealed interfaces may require adjustment when
  design before coding.
  3-node infrastructure not yet available. Implementation will proceed against
- **Serial-write-surface contention**: As implementation transitions from
  design to code, the serial write surfaces (`tidefs-local-filesystem`,
  `tidefs-local-object-store`) may become bottlenecks. The claim barrier
  (§1.3 of AGENTS.md) mitigates but does not eliminate this risk.
- **Coordinator proliferation**: At 7.5× generation-to-closure ratio, the
  ready-issue stockpile will continue growing unless containment measures
  (cadence throttle, dedup filter, stale auto-close) are applied.
- **MEMBERSHIP bottleneck**: All coordination services are gated on #1209.
  If MEMBERSHIP wire-up encounters unexpected complexity, all downstream
  coordination implementation stalls.

---

## 10. References

- `docs/design/coordination-pipeline-cluster-services-design-seal.md` — #1738 design phase seal
- `docs/design/coordination-pipeline-health-advancement-strategy.md` — #1838 health monitoring framework
- `docs/design/coordination-review-roadmap-priorities-update.md` — #1753 roadmap priorities
- `docs/STATUS.md` — live coordination pipeline status
- `docs/FEATURE_MATRIX.md` — implemented-source capability matrix
- `docs/CURRENT_VS_FUTURE_CAPABILITIES.md` — deferred production gates
- `docs/design/cluster-security-identity-model.md` — sealed security architecture
- `docs/design/cluster-wide-distributed-lock-service-design.md` — lock service architecture
- `docs/design/cluster-bulk-plane-protocol.md` — BULK plane protocol
- `docs/design/cluster-wide-atomic-snapshot-coordination.md` — snapshot coordination
- `docs/design/cluster-admin-proxy-model.md` — admin proxy model
- `docs/design/bounded-cluster-membership-state.md` — anti-OSDMap-explosion design
- `docs/design/unified-scheduling-classes-lane-priority-model.md` — lane model
- `docs/design/deferred-cleanup-work-queues.md` — deferred cleanup design
- `docs/design/refcount-delta-based-incremental-data-cleanup-queues.md` — reclaim queues
- `docs/MEMBERSHIP_SERVICE_DESIGN.md` — membership protocol
- `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md` — P8-03 runtime
- `docs/SPACEMAP_ALLOCATOR_DESIGN.md` — spacemap allocator
- `docs/design/pool-import-export-device-topology-management.md` — pool import/export

---

**Coordination pipeline status update (#1839) complete.** This document
serves as the current authoritative coordination pipeline status snapshot,
building on the design seal (#1738), health monitoring framework (#1838),
and roadmap priorities (#1753). The design phase for cluster-wide services
is substantially complete; active implementation lanes (cleanup/reclaim,
spacemap, P8-03) are advancing; and the deferred wire-up strategy enables
parallel implementation against sealed interface contracts with MEMBERSHIP
(#1209) as the critical-path blocker.

**Gate**: `cargo check --workspace` passes. Design-only document; no code
changes.

**Closes**: #1839
