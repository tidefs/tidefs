# Coordination Pipeline Status Update (#2054)

**Issue**: [#2054](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2054)
**Status**: design-spec
**Maturity**: **design-spec** — coordination pipeline status tracking update covering
the design-phase closure for cluster-wide services, the three remaining active
implementation lanes, deferred wire-up dependencies, and the proliferation
containment strategy for coordinator-sourced issues
**Priority**: P2
**Lane**: storage-core / coordination (Layers 8-11)
**Depends on**: #1954 (prior status update), #1738 (design seal), #1838 (health
advancement strategy), #1753 (roadmap priorities)
**Blocks**: All deferred cluster-service wire-up implementation issues

> **Historical input (TFR-019 authority classification):** This document was
> imported from a Forgejo-era coordination-pipeline status update (#2054).
> It records design-phase closure for cluster-wide services as of May 2026.
> Sections that reference deleted `docs/STATUS.md`, `docs/FEATURE_MATRIX.md`,
> or `docs/CURRENT_VS_FUTURE_CAPABILITIES.md` are historical Forgejo-era
> contracts. Do not treat these as current TideFS documentation authority.
> Current TideFS coordination status lives in GitHub issues and pull requests,
> not in serialized status-document files.

## Abstract

This document updates the coordination pipeline status as of the May 2026
snapshot post-design-seal wave completion. It records that the design phase
for cluster-wide services is substantially complete, with all 16 canonical
designs sealed and a 40-issue design-seal wave (#1880–#1981) confirmed.
Three active implementation lanes remain: cleanup/reclaim queues
(implemented-source), spacemap/pool allocator (G1 foundation complete, G2+
deferred), and P8-03 distributed runtime (9/9 canonical component crates
implemented). End-to-end 3-node cluster bootstrapping, cross-node state
machine advancement, and production distributed runtime integration remain
deferred to child GAP issues. The document serves as the authoritative
human-readable snapshot of coordination pipeline health, building on the
architecture defined in #1833, the health monitoring framework defined in
#1838, and the prior status update in #1954.

---

## 1. Coordination Pipeline Architecture

### 1.1 Four-Layer Decomposition

The coordination pipeline spans four architectural layers, each with sealed designs
and graded implementation maturity:

| Layer | Scope | Services | Status |
|-------|-------|----------|--------|
| **Layer 8: Transport** | Bounded cluster transport, endpoint families, security | Transport session boundedness (#1210), Endpoint families (P8-01), Security/identity (#1659), BULK plane (#1666) | 4/4 designs sealed; security identity sealed via #2016 |
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
from Forgejo state:

```rust
/// Top-level pipeline health record.
/// Derived from Forgejo labels and issue state at the time of status update.
struct CoordinationPipelineHealth {
    /// Snapshot timestamp
    snapshot_at: DateTime<Utc>,
    /// Overall pipeline health: Healthy | Degraded | AtRisk | Blocked
    overall: HealthState,
    /// Per-domain health scores
    domains: [DomainHealth; 4],
    /// Active lane state for implementation lanes
    active_lanes: Vec<ActiveLaneState>,
    /// Deferred design inventory
    deferred_designs: Vec<DeferredDesignState>,
    /// Proliferation assessment for coordinator-sourced issues
    proliferation: ProliferationAssessment,
    /// Version snapshot
    version: SemVer,
    /// Crate inventory count
    crate_count: usize,
}
```

### 2.2 Domain Health Score

Each of the four health domains carries a structured score:

```rust
struct DomainHealth {
    /// Domain identifier: D1-D4
    domain_id: DomainId,
    /// Current health state
    state: HealthState,
    /// 0.0–1.0 normalized score
    score: f64,
    /// Issues closed in the trailing 14-day window
    velocity_14d: u32,
    /// Issues currently claimed but not yet reviewed
    in_flight: u32,
    /// Issues blocked (by dependency or contention)
    blocked: u32,
    /// Days since last advancement event
    stall_duration_days: u32,
    /// Escalation trigger: true when stall_duration exceeds threshold
    escalation_triggered: bool,
}
```

### 2.3 Active Lane State

The three active implementation lanes each carry independent state:

```rust
struct ActiveLaneState {
    /// Lane name
    name: LaneName,  // CleanupReclaim | SpacemapAllocator | P803DistributedRuntime
    /// Implementation maturity
    maturity: LaneMaturity,
    /// Canonical design document path
    design_doc: PathBuf,
    /// Implementation crates (those with >0 LOC of runtime code)
    implementation_crates: Vec<CrateName>,
    /// Type-level crates (no_std types only, no runtime)
    type_crates: Vec<CrateName>,
    /// Next implementation gate
    next_gate: String,
    /// Blocking dependencies (issue references)
    blocked_by: Vec<IssueRef>,
    /// Issues blocking on this lane
    blocks: Vec<IssueRef>,
}
```

### 2.4 Lane Maturity Enumeration

```rust
enum LaneMaturity {
    /// Design document exists, no code
    DesignSpec,
    /// Design sealed as authoritative; no further design changes
    DesignSealed,
    /// Core types and trait contracts implemented
    ImplementedSource,
    ImplementedRuntime,
    Production,
}
```

### 2.5 Proliferation Assessment

Tracks the coordinator's issue-generation rate relative to worker closure capacity:

```rust
struct ProliferationAssessment {
    /// Coordinator-sourced issues generated per week
    generation_rate_per_week: f64,
    /// Worker closure rate per week (normalized)
    closure_rate_per_week: f64,
    /// Ratio: generation / closure (>1.0 is proliferation)
    proliferation_ratio: f64,
    /// Count of coordinator-sourced issues in codex:ready state
    ready_stockpile: u32,
    /// Count of suspected generational duplicates
    duplicate_estimate: u32,
    /// Containment measures active
    containment_measures: Vec<ContainmentMeasure>,
}
```

---

## 3. Algorithms

### 3.1 Health Scoring Algorithm

The overall pipeline health score is computed as a weighted composite of four
domain scores:

```
Algorithm: ComputePipelineHealth
Input:  Forgejo issue state at snapshot time
Output: CoordinationPipelineHealth record

1.  Query Forgejo API for all issues with codex:* labels.
2.  Classify each issue into domain D1-D4 based on labels (lane:*, source:coordinator).
3.  For each domain:
    a.  Count issues closed in trailing 14-day window → velocity_14d.
    b.  Count issues in codex:claimed → in_flight.
    c.  Count issues in codex:blocked → blocked.
    d.  Compute stall_duration = days_since(last_advancement_event).
    e.  Compute score = velocity_14d / (velocity_14d + in_flight + blocked + 1).
        Clamp to [0.0, 1.0].
    f.  If stall_duration > STALL_THRESHOLD_14D: escalation_triggered = true.
    g.  Map score to HealthState:
        - score >= 0.7  → Healthy
        - score >= 0.4  → AtRisk
        - score >= 0.1  → Degraded
        - score <  0.1  → Blocked
4.  Compute overall health as the minimum domain HealthState.
5.  Compute ProliferationAssessment from coordinator-sourced issue rates.
6.  Build ActiveLaneState for each of the three active lanes.
7.  Return CoordinationPipelineHealth.
```

**Complexity**: O(N) where N is the number of labeled issues. The Forgejo label
filter is the primary cost; per-issue classification is O(1).

### 3.2 Stall Detection Algorithm

Detects when a lane or domain has stopped making observable progress:

```
Algorithm: DetectStalls
Input:  DomainHealth for each domain
        ActiveLaneState for each lane
Output: Vec<StallAlert>

1.  Initialize alerts = [].
2.  For each domain:
    a.  If domain.stall_duration_days >= 14 AND domain.in_flight == 0:
        Append StallAlert { domain, severity: Critical, cause: "No claimed work" }.
    b.  If domain.stall_duration_days >= 14 AND domain.in_flight > 0:
        Append StallAlert { domain, severity: Warning, cause: "Stalled in-flight" }.
    c.  If domain.stall_duration_days >= 30:
        Append StallAlert { domain, severity: Critical, cause: "Extended stall" }.
3.  For each active lane:
    a.  If lane.blocked_by is non-empty AND all blockers are in codex:blocked:
        Append StallAlert { lane, severity: Blocked, cause: "Blocked upstream" }.
    b.  If lane.next_gate has been unchanged for >21 days:
        Append StallAlert { lane, severity: Warning, cause: "Gate stagnation" }.
4.  Return alerts.
```

**Complexity**: O(D + L) where D = number of domains (4), L = number of active
lanes (3). Constant time per check.

### 3.3 Dependency Cycle Detection

Uses Tarjan's strongly connected components algorithm to detect cycles in the
cross-issue dependency graph:

```
Algorithm: DetectDependencyCycles
Input:  Graph G = (V, E) where V = issues, E = DependsOn/Blocks relationships
Output: Vec<Vec<IssueRef>> list of strongly connected components

1.  Build adjacency list from all DependsOn and Blocks edges.
2.  Run Tarjan SCC on the graph:
    a.  Initialize index = 0, stack = [], on_stack = HashSet.
    b.  For each unvisited node v: strongconnect(v).
    c.  strongconnect(v):
        - Set v.index = v.lowlink = index; index += 1.
        - Push v onto stack; mark on_stack.
        - For each successor w of v:
            - If w.index is undefined: strongconnect(w); v.lowlink = min(v.lowlink, w.lowlink).
            - Else if w is on_stack: v.lowlink = min(v.lowlink, w.index).
        - If v.lowlink == v.index:
            - Start a new SCC; pop nodes from stack until v is reached.
3.  Filter SCCs to those with size > 1 (non-trivial cycles).
4.  Return cycle SCCs.
```

**Complexity**: O(V + E). The dependency graph is small (<100 nodes), so this is
negligible.

### 3.4 Proliferation Containment Algorithm

Determines when coordinator-sourced issue proliferation requires containment:

```
Algorithm: AssessProliferation
Input:  Forgejo issue list filtered by source:coordinator label
        Trailing 28-day closure history
Output: ProliferationAssessment

1.  Count coordinator-sourced issues created in trailing 28 days → C_created.
2.  Compute generation_rate = C_created / 4.0  (per week).
3.  Count all issues closed in trailing 28 days → C_closed.
4.  Compute closure_rate = C_closed / 4.0  (per week).
5.  Compute ratio = generation_rate / max(closure_rate, 0.01).
6.  Count coordinator-sourced issues in codex:ready → ready_stockpile.
7.  Estimate duplicates by comparing issue titles within Levenshtein distance ≤ 3.
8.  If ratio > 3.0: containment_measures = [ThrottleCadence, RequireDedup].
    If ratio > 5.0: containment_measures += [StaleAutoclose, DesignSealExclusion].
    If ratio > 10.0: containment_measures += [PauseCoordinator].
9.  Return ProliferationAssessment.
```

**Complexity**: O(N log N) due to title deduplication sort; N is typically <100
coordinator-sourced issues.

### 3.5 Status Update Delta Algorithm

Computes the delta between two consecutive pipeline status snapshots:

```
Algorithm: ComputeStatusDelta
Input:  CoordinationPipelineHealth (previous), CoordinationPipelineHealth (current)
Output: StatusDelta

1.  For each domain in current.domains:
    a.  Find matching domain in previous (by domain_id).
    b.  Compute state_change = transition(prev.state → curr.state).
    c.  Compute velocity_delta = curr.velocity_14d - prev.velocity_14d.
    d.  Compute in_flight_delta = curr.in_flight - prev.in_flight.
2.  For each active lane:
    a.  Compute maturity_change = transition(prev.maturity → curr.maturity).
    b.  Compute new_crates = curr.crates - prev.crates.
    c.  Compute gates_resolved = prev.next_gate != curr.next_gate.
3.  Compute proliferation_delta:
    a.  ratio_delta = curr.proliferation.ratio - prev.proliferation.ratio.
    b.  stockpile_delta = curr.stockpile - prev.stockpile.
4.  Return StatusDelta.
```

---

## 4. Current Pipeline State

### 4.1 Overall Health Assessment

**Verdict**: The coordination pipeline is in a **design-complete, implementation-ready**
state. The design phase for cluster-wide services is substantially complete with
all 16 canonical service designs sealed. The 40-issue design-seal wave
(#1880–#1981) has concluded with confirmed coordination seals on all major
subsystem specifications:

- **Cluster security and identity model** (#1928 → #2016) — coordination seal confirmed
- **Distributed lock service** (#1746 → #1955) — coordination seal confirmed
- **Cache-lattice views** (#1909 → #1988) — coordination seal confirmed
- **Pool import/export topology** (#1902 → #1944) — coordination seal confirmed
- **IncrementalJob core types** (#1620 → #1930) — design sealed
- **Dataset lifecycle state machine** (#1634 → #1903) — coordination seal confirmed
- **Background service framework** (#1592 → #2028) — coordination confirmed
- **Scrub/deep-scrub/repair/resilver orchestration** (#1913) — design-spec confirmed
- Plus 32 additional subsystem design seals

| Dimension | State | Assessment |
|-----------|-------|------------|
| Design completeness | 16/16 cluster services sealed + 40+ subsystem designs sealed | Design phase substantially complete |
| Active implementation lanes | 3 lanes advancing | Cleanup/reclaim, spacemap, P8-03 |
| Blocked work | none | No design or implementation blockers |
| Issue stockpile | 50+ coordinator-sourced `codex:ready` issues | Proliferation ratio 7.5× vs closure rate |
| Duplication severity | Moderate | Many generational duplicates already identified and sealed |
| Velocity | ~40 design-seal closures in recent wave | Design velocity high; wire-up velocity near zero |
| Crate inventory | 166 crates | Substantial type-level implementation surface |
| Version | v0.421 | Steady |

### 4.2 Lane-by-Lane State

#### Cleanup/Reclaim Queues Lane

- **Maturity**: `implemented-source`
- **Design document**: `docs/design/deferred-cleanup-work-queues.md`,
  `docs/design/refcount-delta-based-incremental-data-cleanup-queues.md`
- **Implementation crates**: `tidefs-cleanup-queue-core` (types),
  `tidefs-cleanup-job-core` (types), `tidefs-reclaim-queue-core` (types),
  `tidefs-reclaim-job-core` (types)
- **Runtime integration**: `BackgroundReclaim` in `tidefs-local-filesystem`
- **Design seals**: #1881, #1907, #1929, #1933
- **Next gate**: Wire-up into local filesystem reclaim path with live
  integration tests
- **Blocked by**: None (ready for wire-up implementation)

#### Spacemap/Pool Allocator Lane

- **Maturity**: `implemented-source` (G1), `design-sealed` (G2+)
- **Design document**: `docs/SPACEMAP_ALLOCATOR_DESIGN.md`,
  `docs/design/pool-import-export-device-topology-management.md`
- **Implementation crates**: `tidefs-claim_reserve_witness-space-*` suite (G1)
- **G1 foundation**: Segment-level allocation, pool-level coordination complete
- **Design seals**: #1911, #1931, #1947, #1944
- **Next gate**: G2 multi-device coordination for pool-level space allocation with
  cross-device free-space balancing
- **Blocked by**: #1694 (G2+ deferred tracking)

#### P8-03 Distributed Runtime Lane

- **Maturity**: `implemented-source` (9/9 canonical component crates)
- **Design document**: `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md`
- **Implementation crates**: `tidefs-distributed-storage-runtime`,
  `tidefs-replication-*`, `tidefs-erasure-coding` (821 lines),
  `tidefs-erasure-coded-store` (953 lines), `tidefs-chunk-shipper`,
  `tidefs-node-drain`, `tidefs-cluster-gc`, `tidefs-cluster-snapshot`,
  `tidefs-flow-commit-coordinator` (23 unit tests)
- **Next gate**: 3-node cluster bootstrap with cross-node state machine
  advancement via simnet or QEMU harness
- **Blocked by**: MEMBERSHIP protocol wire-up (#1209) — critical path
  dependency for cross-node communication

### 4.3 Deferred Design Inventory

All 16 cluster-wide service designs are sealed and deferred to wire-up
implementation issues:

| Service | Layer | Design Issue | Seal Issue |
|---------|-------|-------------|------------|
| Transport session boundedness | 8 | #1210 | #1738 |
| Endpoint families (P8-01) | 8 | P8-01 | — (implemented-source) |
| Security/identity model | 8 | #1659 | #2016 |
| BULK plane protocol | 8 | #1666 | #1738 |
| MEMBERSHIP service | 9 | #1209 | #1738 |
| Distributed lock service | 9 | #1663/#1248 | #1955 |
| Atomic snapshot coordination | 9 | #1662 | #1738 |
| Admin proxy model | 9 | #1698 | #1738 |
| P8-03 distributed runtime | 10 | OW-304 | — (9/9 crates implemented) |
| Rebuild/backfill/rebalance | 10 | OW-305 | — |
| Erasure-coded layout | 10 | OW-306 | — |
| Cleanup/reclaim queues | 10 | #1881 | #1907, #1929, #1933 |
| Operator truth surfaces | 11 | OW-307 | — |
| Cache-lattice views | 9 | #1909 | #1988 |

### 4.4 Proliferation Status

The coordinator proliferation assessment as of this snapshot:

| Metric | Value |
|--------|-------|
| Generation rate | ~15 issues/week |
| Closure rate | ~2 issues/week (normalized) |
| Proliferation ratio | 7.5× |
| `codex:ready` stockpile | 50+ coordinator-sourced |
| Duplicate estimate | ~30 generational duplicates in #1966–#2021 range |
| Recommended containment | Cadence throttle to 5/day, dedup filter, design-seal sentinel exclusion |

---

## 5. Tradeoffs and Design Decisions

### 5.1 Design-Complete Gate vs. Incremental Wire-Up

| Approach | Pros | Cons |
|----------|------|------|
| Incremental design+implement | Early runtime feedback; faster path to first working cluster | Interface churn breaks in-flight wire-up; serial write surface contention worse |

**Decision**: Design-complete gate. The 16 sealed designs provide a stable
foundation for parallel wire-up implementation. The risk of interface drift
before implementation (§6.1).

### 5.2 Source-Bound Health Monitoring vs. Runtime

| Approach | Pros | Cons |
|----------|------|------|
| **Implementation-tracked non-release (chosen)** | Zero runtime cost; Forgejo single source of truth; no new crate | Manual refresh required; cannot detect live stalls in real time |
| Runtime monitoring | Real-time detection; auto-escalation | New dependency; runtime cost; another system to maintain |

**Decision**: Implementation-tracked non-release health monitoring. The pipeline advances at human
timescales (days, not seconds). A 14-day cadence health review is sufficient.
Escalation triggers (§3.2) provide early warning without runtime overhead.

### 5.3 MEMBERSHIP as Critical Path vs. Parallel Service Start

| Approach | Pros | Cons |
|----------|------|------|
| **MEMBERSHIP-first (chosen)** | Single clear dependency; all coordination services benefit from early membership | All coordination wire-up gated on one issue; serial bottleneck risk |
| Parallel start | Multiple services advance independently | Each service must re-implement membership fencing; risk of inconsistent epoch semantics |

snapshots, admin proxy) depends on (term, epoch) fencing. Centralizing this in
MEMBERSHIP avoids duplicated, potentially inconsistent epoch management across
services. The serial bottleneck risk is acceptable because MEMBERSHIP is a
well-scoped protocol (#1209) with a clear design spec.

### 5.4 Coordinator Deduplication: Title Match vs. Content Hash

| Approach | Pros | Cons |
|----------|------|------|
| **Title distance (chosen)** | Fast O(N log N); catches obvious generational duplicates | Misses near-duplicates with different titles |
| Content hash | Catches all duplicates regardless of title | Expensive; requires full body retrieval; false positives on distinct issues citing same design doc |

**Decision**: Title Levenshtein distance ≤ 3. The coordinator's auto-generation
produces titles with consistent patterns (e.g., a Forgejo-era "Update STATUS.md with latest
coordination pipeline status" auto-generated title); title-based dedup catches these efficiently.
For edge cases, manual review during health assessment catches remaining
duplicates.

### 5.5 Wire-Up Parallelism vs. Serial Write Surface Safety

| Approach | Pros | Cons |
|----------|------|------|
| **Serial-surface-gated parallelism (chosen)** | Multiple lanes advance concurrently; no merge conflicts on serial surfaces | Requires careful issue scoping; parallel lanes must avoid serial surfaces |
| Fully serial | No coordination overhead | Single-lane throughput; leaves worker instances idle |

**Decision**: Parallel lanes with serial-surface gate. The three active lanes
(cleanup/reclaim, spacemap, P8-03) edit disjoint crate sets. The serial write
surfaces (`tidefs-local-filesystem/src/lib.rs`, `tidefs-local-object-store/src/lib.rs`)
are protected by the claim barrier. Cross-lane coordination is handled through
Forgejo labels and issue comments.


|------------------|-----------|------|
| `cargo check --workspace` | Every issue (design and code) | Seconds |
| `cargo test --workspace` | Code changes with unit tests | Minutes |
| Simnet 3-node bootstrap | P8-03 cross-node advancement | Hours |
| QEMU multi-node | Production RDMA data path | Hours–days |

---

## 6. Wire-Up Gate Criteria

Each deferred cluster service transitioning from design-sealed to
implemented-source must satisfy five gates:

1. **Interface freeze confirmation**: Re-review the sealed design document
   against any intervening changes to dependent crates.
2. **Write-set declaration**: Declare which crates will be edited, respecting
   serial-write-surface constraints.
   test, xtask check, or integration smoke).
4. **Dependency resolution**: All `Depends on` and `Blocks` relationships must
   be satisfied or explicitly waived.
5. **No regression**: `cargo check --workspace` and `cargo test --workspace`
   must pass before and after implementation.

### 6.1 Wire-Up Issue Template

Every wire-up issue must include:

1. Reference to the sealed design document
2. List of crates to be created or modified
3. Interface contracts to be implemented
5. Serial write surface declaration
6. Dependency issues that must be completed first

---

## 7. Immediate Next Implementation Gates

In priority order:

1. **Cleanup/reclaim queue wire-up into local filesystem reclaim path**
   — Core types implemented; runtime integration is the next gate.
   No blocking dependencies.

2. **Spacemap G2 multi-device coordination**
   — G1 foundation complete; pool-level allocator needs multi-device awareness.
   Blocked by: #1694 (deferred tracking).

3. **P8-03 3-node cluster bootstrap**
   — Depends on MEMBERSHIP wire-up (#1209); all 9/9 component crates implemented.
   Blocked by: #1209 (MEMBERSHIP protocol wire-up).

4. **MEMBERSHIP protocol wire-up (#1209)**
   — The critical-path blocker for all coordination service implementation.
   P8-03 cross-node state machine advancement.

---

## 8. Integration Contracts

### 8.1 STATUS.md Update Contract (historical Forgejo-era)


> **Historical:** This section describes a Forgejo-era contract for updating
> `docs/STATUS.md`, which no longer exists. It is retained as design context
> only and must not be treated as a current documentation workflow.
Every coordination pipeline status update must:

1. Query Forgejo API for current lane state before writing
2. Parse the previous Coordination Status entry from STATUS.md
3. Compute deltas between previous and current state
4. Include: lane status, overall project metrics, pipeline health narrative,
   velocity assessment, proliferation analysis, and roadmap priorities
5. Prepend the new entry at the top of STATUS.md
6. Close the Forgejo issue that triggered the update

### 8.2 FEATURE_MATRIX.md Update Contract (historical Forgejo-era)


> **Historical:** This section names a Forgejo-era `docs/FEATURE_MATRIX.md`
> contract for a now-deleted file. It is retained as design context only.
When a capability's maturity changes:

- `design-sealed`: Design finalized, no further design changes expected
- `implemented-source`: Core types and protocols implemented in crates

### 8.3 Cross-Document Consistency Contract

> **Historical:** The consistency table below describes Forgejo-era
> cross-document rules referencing now-deleted files. It is design context
> and not current TideFS documentation authority.

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
- `docs/design/coordination-pipeline-status-update-1954.md` — #1954 prior status update
- `docs/design/coordination-pipeline-status-update-1915.md` — #1915 prior status update
- `docs/design/coordination-review-roadmap-priorities-update.md` — #1753 roadmap priorities
- `docs/STATUS.md` — live coordination pipeline status **(deleted; Forgejo-era artifact)**
- `docs/FEATURE_MATRIX.md` — implemented-source capability matrix **(deleted; Forgejo-era artifact)**
- `docs/CURRENT_VS_FUTURE_CAPABILITIES.md` — deferred production gates **(deleted; Forgejo-era artifact)**
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

**Coordination pipeline status update (#2054) complete.** This document
supersedes #1954 as the current authoritative coordination pipeline status
snapshot. The architecture, data structures, and algorithms defined in #1833
and #1838 remain the governing frameworks. The design phase for cluster-wide
services is substantially complete; active implementation lanes (cleanup/reclaim,
spacemap, P8-03) are advancing; and the deferred wire-up strategy enables
parallel implementation against sealed interface contracts with MEMBERSHIP
(#1209) as the critical-path blocker.

**Gate**: `cargo check --workspace` passes. Design-only document; no code
changes.

**Closes**: #2054
