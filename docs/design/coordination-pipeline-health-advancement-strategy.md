# Coordination Pipeline Health: Advancement Strategy and Monitoring Framework

**Documentation authority**: Historical input for TFR-019 / GitHub issue #1164.
This file is not current TideFS policy, current spec, implementation status,
release-readiness evidence, automation policy, or worker scheduling authority.

The body below preserves Forgejo-era health-monitoring vocabulary as historical
design context. Current TideFS coordination authority lives in GitHub issue and
pull-request state plus the repo documentation entry points in `docs/INDEX.md`,
`docs/GITHUB_PR_DEVELOPMENT.md`, and
`docs/DOCUMENTATION_AUTHORITY_REGISTER.md`. References below to Forgejo labels,
`codex:*` issue states, `~/ai/bin/tidefs-claim`, active lanes, dependency
blocking, health scores, dashboards, escalation comments, deleted
`docs/STATUS.md`, or deleted `docs/FEATURE_MATRIX.md` are archival examples only
and must not be recreated, updated, or cited as current TideFS coordination
status.

## Historical Imported Metadata

- Historical Forgejo issue:
  [#1838](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1838)
- Historical status/maturity: design-spec for a coordination pipeline health
  monitoring framework, advancement algorithms, stall-detection data
  structures, and cross-lane dependency health indicators.
- Historical priority/lane: P2; storage-core / coordination (Layers 8-11).
- Historical dependency/blocking claims: depended on #1738 and #1753 and claimed
  to block deferred cluster-service wire-up issues. These are not current
  GitHub issue gates.

## Historical Abstract

This document defines the coordination pipeline health monitoring framework: a
structured approach to tracking the pipeline's advancement velocity, detecting
stalls and regressions, and making principled priority-ordering decisions across
the three active implementation lanes (cleanup/reclaim queues, spacemap/pool
allocator, P8-03 distributed runtime) and sixteen deferred cluster-service designs.
It formalizes the health scoring model, defines the advancement event taxonomy,
specifies the stall-detection and escalation data structures, and documents the
cross-lane dependency health propagation algorithm. Together with the design seal
(#1738) and roadmap priorities (#1753), this document completes the coordination
pipeline governance architecture.

---

## 1. Motivation: Why Formal Pipeline Health Monitoring

The coordination pipeline spans four architectural layers (Transport, Coordination,
Data Flow, Observability), sixteen sealed cluster-service designs, and three active
implementation lanes. The pipeline's advancement is governed by Forgejo labels
(`codex:ready`, `codex:claimed`, `codex:needs-review`, `codex:done`) and guarded
by the `~/ai/bin/tidefs-claim` claim barrier. However, the pipeline currently lacks:

1. **Velocity measurement**: How fast is each lane advancing? Is advancement
   accelerating, steady, or decelerating?
2. **Stall detection**: When has a lane stopped making progress? Is the stall due
   to a dependency, serial-surface contention, or a missing design decision?
3. **Health propagation**: When Lane A is blocked by Lane B's dependency, how is
   that propagated and tracked?
4. **Priority re-evaluation**: When should roadmap priorities be re-assessed
   because a lane has stalled or a dependency has resolved earlier than expected?

This document provides the architectural answer: a monitoring framework that is
lightweight (no runtime dependency, no cron), implementation-tracked non-release (the health report is
derived from Forgejo state), and action-guiding (stall detection triggers
escalation comments on affected issues).

---

## 2. Pipeline Health Architecture

### 2.1 Health Domains

The coordination pipeline is decomposed into four health domains:

| Domain | Scope | Primary Health Indicator |
|--------|-------|-------------------------|
| **D1: Active Implementation Lanes** | Cleanup/reclaim, spacemap G2+, P8-03 runtime | Advancement velocity (issues closed per window) |
| **D2: Deferred Design-to-Wire-Up** | 16 sealed cluster-service designs | Design staleness (time since seal vs. current crate APIs) |
| **D3: Dependency Graph** | Cross-issue `Depends on` / `Blocks` relationships | Blockage count and cycle detection |
| **D4: Serial Write Surfaces** | `tidefs-local-filesystem`, `tidefs-local-object-store` | Contention count (active claim count per surface) |

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

State transition rules are defined per-domain in §4.

### 2.3 Health Data Structures

```rust
/// Top-level health state for the coordination pipeline.
/// This is a design-time concept; no runtime monitoring is required.
/// The health report is generated from Forgejo state at review intervals.
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
    /// Resets to 0 when Healthy is re-entered.
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HealthDomain {
    ActiveImplementationLanes = 0,
    DeferredDesignToWireUp = 1,
    DependencyGraph = 2,
    SerialWriteSurfaces = 3,
}

/// Health state for a domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthState {
    /// Normal advancement velocity; no intervention needed.
    Healthy,
    /// Slower than expected; monitor more frequently.
    Degraded,
    /// Approaching stall threshold; prepare escalation.
    AtRisk,
    /// No progress for >= stall_threshold periods.
    Blocked,
    /// Escalation comment has been posted on the blocking issue.
    Escalated,
}

/// Aggregate pipeline health derived from domain maxima.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregateHealth {
    /// All domains Healthy or Degraded.
    Green,
    /// At least one domain AtRisk; none Blocked or Escalated.
    Yellow,
    /// At least one domain Blocked or Escalated.
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

---

## 3. Health Scoring Algorithm

### 3.1 Per-Domain Scoring

The health scoring algorithm computes a `HealthState` for each domain from
Forgejo issue state. The algorithm is idempotent and implementation-tracked non-release: running it
twice against the same Forgejo state produces the same health scores.

#### Algorithm 1: Active Implementation Lanes Health

```
algorithm score_active_implementation_lanes(forgejo_state):
    input:  forgejo_state with coordination-lane issue inventory
    output: DomainHealth for D1

    lanes = {cleanup_reclaim, spacemap_g2, p8_03_runtime}
    health = DomainHealth { domain: ActiveImplementationLanes, state: Healthy, ... }

    for lane in lanes:
        claims = forgejo_state.claims_for_lane(lane)
        recently_closed = forgejo_state.closed_in_window(lane, window=14d)
        stalled_claims = claims.filter(c => c.age > 30d)

        if stalled_claims.count() > 0:
            health.degraded_periods += 1
            if stalled_claims.count() >= 2:
                health.state = max(health.state, Blocked)
            else if health.degraded_periods >= 3:
                health.state = max(health.state, AtRisk)
            else:
                health.state = max(health.state, Degraded)

        if recently_closed.count() == 0 and claims.count() == 0:
            # Lane has no activity; check if it's intentionally deferred
            if lane.is_deferred_in_status_md():
                # Intentionally deferred — not unhealthy
                pass
            else:
                health.state = max(health.state, AtRisk)

    return health
```

#### Algorithm 2: Deferred Design-to-Wire-Up Health

```
algorithm score_deferred_designs(forgejo_state):
    input:  forgejo_state, current crate API surface
    output: DomainHealth for D2

    sealed_designs = forgejo_state.issues_with_label("kind:design")
        .filter(i => i.is_sealed())

    health = DomainHealth { domain: DeferredDesignToWireUp, state: Healthy, ... }

    for design in sealed_designs:
        days_since_seal = now() - design.sealed_at
        api_drift = check_api_drift(design.referenced_crates)

        if api_drift.major_breaking_changes > 0:
            health.stalled_issues += 1
            health.blocking_dependencies += 1
            health.state = max(health.state, AtRisk)

        if days_since_seal > 90:
            health.state = max(health.state, Degraded)

    return health
```

#### Algorithm 3: Dependency Graph Health

```
algorithm score_dependency_graph(forgejo_state):
    input:  forgejo_state with full issue dependency graph
    output: DomainHealth for D3

    # Build dependency graph from Depends on / Blocks relationships
    graph = build_dependency_graph(forgejo_state)

    health = DomainHealth { domain: DependencyGraph, state: Healthy, ... }

    # Cycle detection
    cycles = graph.detect_cycles()
    if cycles.count() > 0:
        health.state = Blocked
        health.summary = "dependency cycles detected: " + cycles.join(", ")
        return health

    # Blockage counting
    blocked_issues = graph.nodes.filter(n => n.is_blocked_by_another_issue())
    health.stalled_issues = blocked_issues.count()
    health.blocking_dependencies = blocked_issues
        .flat_map(n => n.blocking_issues).unique().count()

    if blocked_issues.count() >= 3:
        health.state = AtRisk
    elif blocked_issues.count() >= 1:
        health.state = Degraded

    return health
```

#### Algorithm 4: Serial Write Surface Health

```
algorithm score_serial_surfaces(forgejo_state):
    input:  forgejo_state with active claims
    output: DomainHealth for D4

    surfaces = {
        "tidefs-local-filesystem",
        "tidefs-local-object-store"
    }

    health = DomainHealth { domain: SerialWriteSurfaces, state: Healthy, ... }

    for surface in surfaces:
        claims = forgejo_state.claims_touching_surface(surface)

        if claims.count() > 1:
            # Multiple claims on the same serial surface
            health.state = Blocked
            health.summary = surface + " has " + claims.count() +
                " active claims (max 1 allowed)"
        elif claims.count() == 1:
            claim = claims.first()
            if claim.age_hours > 48:
                health.state = AtRisk
                health.summary = surface + " held by #" + claim.issue_number +
                    " for " + claim.age_hours + "h"
        # 0 claims is healthy (surface is free)

    return health
```

### 3.2 Aggregate Health Propagation

The aggregate health is the maximum of all domain health states:

```
algorithm compute_aggregate_health(domains):
    input:  [DomainHealth; 4]
    output: AggregateHealth

    state_order = { Healthy: 0, Degraded: 1, AtRisk: 2, Blocked: 3, Escalated: 4 }
    max_state = max(domains.map(d => state_order[d.state]))

    if max_state >= state_order[Blocked]:
        return Red
    elif max_state >= state_order[AtRisk]:
        return Yellow
    else:
        return Green
```

---

## 4. State Transition Rules by Domain

### 4.1 D1: Active Implementation Lanes

| Transition | Trigger | Action |
|-----------|---------|--------|
| Healthy -> Degraded | Any lane has a stalled claim (>30d) or 0 advancement events in 14d | Increase monitoring frequency |
| Degraded -> AtRisk | 3+ consecutive Degraded periods | Prepare escalation comment |
| AtRisk -> Blocked | 2+ lanes stalled simultaneously | Escalate to lane owners |
| Any -> Healthy | All lanes have advancement events in the current window and 0 stalled claims | Reset degraded_periods to 0 |
| Blocked -> Escalated | Manual: health reviewer posts comment on blocking issue | Forgejo comment with health context |

### 4.2 D2: Deferred Design-to-Wire-Up

| Transition | Trigger | Action |
|-----------|---------|--------|
| Healthy -> Degraded | Any sealed design > 90d since seal | Flag for re-review at next cadence |
| AtRisk -> Blocked | API drift + > 120d since seal | Escalate: design may need update before wire-up |
| Any -> Healthy | All sealed designs < 90d and 0 API drift | Reset counter |

### 4.3 D3: Dependency Graph

| Transition | Trigger | Action |
|-----------|---------|--------|
| Healthy -> Degraded | 1+ issues blocked by dependencies | Record blockage in the relevant GitHub issue or PR; use `docs/REVIEW_TODO_REGISTER.md` only for durable review debt |
| Degraded -> AtRisk | 3+ issues blocked | Review for deadlock or re-prioritization |
| AtRisk -> Blocked | Cycle detected OR orphaned dependency (blocker is closed but dependents remain blocked) | Immediate escalation |
| Any -> Healthy | 0 blocked issues | Reset counter |

### 4.4 D4: Serial Write Surfaces

| Transition | Trigger | Action |
|-----------|---------|--------|
| Healthy -> Degraded | Surface held by single claim > 24h | Monitor claim age |
| Degraded -> AtRisk | Surface held by single claim > 48h | Check if claim is stalled |
| AtRisk -> Blocked | Multiple claims on same surface (claim barrier violation) | Immediate escalation |
| Any -> Healthy | 0 active claims on surface | Reset counter |

---

## 5. Advancement Event Taxonomy

Pipeline advancement is tracked through a closed set of advancement event types.
Each event is observable from Forgejo state changes (label transitions, issue
closures, comment activity).

### 5.1 Event Categories

| Category | Events | Observable From |
|----------|--------|-----------------|
| **Design** | `design-sealed`, `design-updated` | `kind:design` label transitions, design doc updates |
| **Implementation** | `codex-claimed`, `codex-needs-review`, `codex-done` | Label transitions on implementation issues |
| **Integration** | `branch-merged-to-master`, `branch-deleted` | Git operations (observable via Forgejo PR/commit) |
| **Review** | `review-comment-posted`, `review-approved` | Comment activity, `codex:needs-review` -> `codex:done` |

### 5.2 Expected Advancement Velocity

Each active implementation lane has an expected advancement cadence:

| Lane | Expected Cadence | Stall Threshold | Advancements This Window |
|------|-----------------|----------------|--------------------------|
| Cleanup/reclaim queues | 1 advancement / 7d | 14d with 0 events | TBD (measured from Forgejo) |
| Spacemap/pool allocator (G2+) | 1 advancement / 14d | 30d with 0 events | TBD |
| P8-03 distributed runtime | 1 advancement / 14d | 30d with 0 events | TBD |

---

## 6. Cross-Lane Dependency Health Propagation

### 6.1 Dependency Classification

Dependencies between coordination-lane issues are classified by severity:

| Class | Symbol | Meaning | Propagation Rule |
|-------|--------|---------|-----------------|
| **Hard block** | `->` | Dependent cannot proceed until dependency completes | Blocked state propagates fully |
| **Soft block** | `~>` | Dependent can make partial progress; full completion requires dependency | AtRisk state propagates |
| **Informational** | `+>` | Dependent benefits from but does not require dependency | No health propagation |

### 6.2 Propagation Algorithm

```
algorithm propagate_dependency_health(graph, health_report):
    input:  dependency graph, current health report
    output: updated health report with propagated states

    # Forward propagation: if issue A blocks issue B and A is unhealthy,
    # downgrade B's health.
    for edge in graph.edges.filter(e => e.class == HardBlock):
        blocker_health = health_report.issue_health(edge.source)
        dependent_health = health_report.issue_health(edge.target)

        if blocker_health.state >= Blocked:
            dependent_health.state = max(dependent_health.state, Blocked)
            dependent_health.summary +=
                " (blocked by unhealthy #" + edge.source + ")"

        if blocker_health.state == AtRisk:
            dependent_health.state = max(dependent_health.state, AtRisk)

    # Reverse propagation: if issue A blocks many issues and all dependents
    # are blocked, escalate A.
    for node in graph.nodes:
        dependents_blocked = node.dependents
            .filter(d => health_report.issue_health(d).state >= Blocked)
            .count()

        if dependents_blocked >= 3 and node.state == Healthy:
            node.state = AtRisk
            node.summary += " (blocking " + dependents_blocked +
                " blocked dependents)"

    return health_report
```

### 6.3 Serial Surface Contention Model

The two serial write surfaces (`tidefs-local-filesystem` and
`tidefs-local-object-store`) require special handling because only one active
issue may edit each at a time. The contention model is:

```
algorithm resolve_serial_surface_contention(surface, claims):
    input:  surface name, list of claims touching that surface
    output: ordering recommendation

    if claims.count() <= 1:
        return NoContention

    # Sort claims by: issue number ascending (oldest first) is the
    # primary ordering -- the first claim to arrive owns the surface.
    ordered = claims.sort_by(c => c.issue_number)

    # The oldest claim is the owner; all others must wait.
    owner = ordered[0]
    waiters = ordered[1..]

    # Waiters should be marked blocked with an explicit dependency
    # on the owner's issue.
    for waiter in waiters:
        if not waiter.has_dependency_on(owner.issue_number):
            recommendation = "Add 'Depends on: #" + owner.issue_number +
                "' to issue #" + waiter.issue_number

    return { owner, waiters }
```

---

## 7. Stall Detection and Escalation

### 7.1 Stall Detection Algorithm

A lane is considered "stalled" when it meets all of:

1. At least one `codex:claimed` issue exists in the lane.
2. The youngest claim in the lane is older than the stall threshold.
3. No `codex:done` or `codex:needs-review` transitions have occurred within
   the stall threshold window.

```
algorithm detect_stalls(lane, forgejo_state):
    input:  lane identifier, forgejo state
    output: Vec<StallRecord>

    claims = forgejo_state.claims_for_lane(lane)
    threshold = lane.stall_threshold
    now = current_time()

    stalls = []

    for claim in claims:
        if now - claim.claimed_at > threshold:
            # Check if any advancement event occurred since claim
            events = forgejo_state.events_for_issue(claim.issue_number)
            last_advancement = events
                .filter(e => e.is_advancement())
                .max_by(e => e.timestamp)

            if last_advancement is None or
               now - last_advancement.timestamp > threshold:
                stalls.push(StallRecord {
                    issue_number: claim.issue_number,
                    claimed_at: claim.claimed_at,
                    last_advancement: last_advancement,
                    stall_duration_hours:
                        (now - (last_advancement?.timestamp ?? claim.claimed_at)),
                    lane: lane,
                })

    return stalls
```

### 7.2 Escalation Levels

| Level | Trigger | Action |
|-------|---------|--------|
| **L0: Monitor** | Stall detected but < 2x threshold | Log in health report; no comment |
| **L1: Comment** | Stall > 2x threshold | Post non-blocking comment on issue: "Health check: no advancement in N hours. Still active?" |
| **L2: Escalate** | Stall > 4x threshold | Post blocking comment + add `codex:blocked` label with rationale comment |
| **L3: Unclaim** | Stall > 8x threshold | Remove `codex:claimed`, add `codex:ready`, comment explaining unclaim |

---

## 8. Coordination Lane Dashboard Model

A conceptual "dashboard" view of the coordination pipeline. Historical drafts
rendered this as a `STATUS.md` section; current TideFS coordination should use
GitHub issue and pull request state, with durable documentation authority
classification in `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` when needed:

```
Coordination Pipeline Health Dashboard
=====================================
Report Epoch: N     Assessed: YYYY-MM-DD HH:MM UTC     Aggregate: Green/Yellow/Red

+------------------------------------------------------------------------------+
| ACTIVE IMPLEMENTATION LANES                     Health: Healthy               |
+---------------+---------------+----------+-------------+---------------------+
| Lane          | Claims        | Stalled  | Advance/14d | Status              |
+---------------+---------------+----------+-------------+---------------------+
| Reclaim       | 1             | 0        | 2           | Active, wire-up     |
| Spacemap G2+  | 0             | 0        | 0           | Deferred (by design)|
| P8-03 RT      | 0             | 0        | 0           | Deferred (by design)|
+---------------+---------------+----------+-------------+---------------------+

+------------------------------------------------------------------------------+
| DEFERRED DESIGNS                               Health: Healthy               |
+------------------------+-----------+-------------+---------------------------+
| Metric                 | Count     | Threshold   | Status                    |
+------------------------+-----------+-------------+---------------------------+
| Sealed designs         | 16        | --          | --                        |
| > 90d since seal       | 0         | > 0 -> flag | All fresh                 |
| API drift detected     | 0         | > 0 -> risk | No breaking changes       |
+------------------------+-----------+-------------+---------------------------+

+------------------------------------------------------------------------------+
| DEPENDENCY GRAPH                               Health: Healthy               |
+------------------------+-----------+-------------+---------------------------+
| Metric                 | Count     | Threshold   | Status                    |
+------------------------+-----------+-------------+---------------------------+
| Blocked issues         | 0         | 1+ -> flag  | No blockages              |
| Dependency cycles      | 0         | 1+ -> block | DAG confirmed             |
+------------------------+-----------+-------------+---------------------------+

+------------------------------------------------------------------------------+
| SERIAL WRITE SURFACES                          Health: Healthy               |
+-----------------------------+-----------+----------+--------------------------+
| Surface                     | Claims    | Age      | Status                   |
+-----------------------------+-----------+----------+--------------------------+
| tidefs-local-filesystem     | 1         | 2h       | In active use            |
| tidefs-local-object-store   | 0         | --       | Free                     |
+-----------------------------+-----------+----------+--------------------------+

| Distribution | ready: N | claimed: N | needs-review: N | done-14d: N |
```

---

## 9. Pipeline Advancement Sequencing Framework

### 9.1 Sequencing Model

The coordination pipeline advances through four phases (defined in #1753 §5).
This document adds the health-gate criteria that must be satisfied before
transitioning between phases:

```
Phase 1: Foundation Complete
  Health gate: AggregateHealth == Green AND
               serial_surface_contention == 0 AND
               blocked_issues == 0
  -> Advances to Phase 2

Phase 2: Networked Services
  Health gate: All Phase 2 designs sealed AND
               transport boundedness implemented-source AND
  -> Advances to Phase 3

Phase 3: Cluster-Wide Features
  Health gate: 3-node bootstrap smoke passes AND
               cross-node state machine advancement demoed AND
               0 API drift in all Phase 3 service designs
  -> Advances to Phase 4

Phase 4: Production Integration
               all deferred production gates tracked in current GitHub issues,
               pull requests, and repo authority docs are resolved
  -> Pipeline complete
```

### 9.2 Phase Transition Health Report

Each phase transition requires a health report (run `#1728` or manual review)
confirming:

1. All gates for the current phase are met.
3. No serial-surface contention would block the next phase's first issue.
4. Relevant GitHub issues, pull requests, and current repo authority docs are
   updated to reflect the transition.

---

## 10. Tradeoffs and Design Decisions

### 10.1 Source-Bound vs. Runtime Monitoring

| Approach | Pros | Cons |
|----------|------|------|
| **Implementation-tracked non-release (chosen)** | Zero runtime cost; no new crate; GitHub issue/PR state and current repo docs remain the coordination authority | Requires manual or issue-driven refresh; cannot detect "live" stalls in real time |
| Runtime monitoring | Real-time stall detection; could auto-escalate | New dependency; runtime cost; another system to maintain |

**Decision**: Implementation-tracked non-release. The coordination pipeline's advancement velocity
is measured in days, not seconds. A scheduled health review (via #1728 or manual
trigger) with 14-day cadence is sufficient. Runtime monitoring would add
complexity without proportional benefit for a pipeline that moves at human
timescales.

### 10.2 Health Report Cadence

| Cadence | Pros | Cons |
|---------|------|------|
| **14-day (chosen)** | Aligns with sprint cadence; enough time for advancement to be visible | May miss fast-moving stalls between checks |
| 7-day | Faster detection | Overhead of more frequent GitHub issue/PR or repo-doc updates |
| 30-day | Lowest overhead | Too slow to catch stalls early |

**Decision**: 14-day cadence with on-demand health checks. Any `codex:claimed`
issue that is stalled beyond threshold triggers an on-demand health review
regardless of cadence.

### 10.3 Escalation Automation vs. Manual Review

| Approach | Pros | Cons |
|----------|------|------|
| **Manual review (chosen)** | Human judgment for false positives; no automated Forgejo spam | Slower response; relies on reviewer availability |
| Automated escalation | Immediate; no human bottleneck | False positives on long-running valid work; could damage contributor trust |

**Decision**: Manual review with automated detection support. The health
scoring algorithm identifies candidates for escalation, but a human reviewer
confirms before posting comments. This prevents false escalations on work that
is legitimately long-running (e.g., a complex wire-up that takes 5+ days).

### 10.4 Dependency Cycle Detection

| Approach | Pros | Cons |
|----------|------|------|
| **Tarjan SCC (chosen)** | O(V+E); exact; identifies all cycles | Requires full graph build |
| DFS with back-edge detection | Simpler implementation | Misses cross-edge cycles |

**Decision**: Tarjan's strongly connected components algorithm. The dependency
graph is small (<100 nodes), so O(V+E) cost is negligible. Exact cycle
detection is required because a dependency cycle in the coordination lane
would deadlock implementation progress.

---



- `cargo check --workspace` passes (no accidental breakage of existing crates).
  state -- a human reviewer computes the domain scores and confirms they match
  expected pipeline health.
- The dependency graph DAG property is verified by enumerating all
  `Depends on` / `Blocks` relationships and confirming no cycles exist.

No additional xtask checks are required because the health monitoring framework
is implementation-tracked non-release (not implemented as a Rust crate).

---

## 12. References

- `docs/design/coordination-pipeline-cluster-services-design-seal.md` -- #1738 design phase seal
- `docs/design/coordination-review-roadmap-priorities-update.md` -- #1753 roadmap priorities
- `docs/GITHUB_PR_DEVELOPMENT.md` -- current GitHub issue/PR coordination policy
- `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` -- current documentation authority classification register
- `docs/INDEX.md` -- documentation entry point and authority caveat
- `docs/design/bounded-cluster-membership-state.md` -- anti-OSDMap-explosion design
- `docs/design/cluster-security-identity-model.md` -- sealed security architecture
- `docs/design/cluster-wide-distributed-lock-service-design.md` -- lock service architecture
- `docs/design/background-service-framework-design-enhanced.md` -- background service framework
- `docs/design/deferred-cleanup-work-queues.md` -- deferred cleanup design
- `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md` -- P8-03 runtime
- `docs/REFCOUNT_DELTA_CLEANUP_QUEUES_DESIGN.md` -- reclaim queues

---

**Historical design draft complete.** The coordination pipeline health monitoring
framework was imported as design context for advancement strategy, health scoring
algorithms, stall detection data structures, and escalation procedures. It is
not current TideFS coordination authority.
