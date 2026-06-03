# Coordination Pipeline Status Update (#1954)

**Issue**: [#1954](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1954)
**Status**: design-spec
**Maturity**: **design-spec** — coordination pipeline status tracking update covering
the current lane states, design-seal wave completion, coordinator proliferation
concern, and deferred wire-up strategy for cluster-wide services
**Priority**: P2
**Lane**: storage-core / coordination (Layers 8-11)
**Depends on**: #1915 (prior status update), #1738 (design seal), #1838 (health
advancement strategy), #1723 (roadmap priorities)
**Blocks**: All deferred cluster-service wire-up implementation issues

## Abstract

This document updates the coordination pipeline status as of the May 2026
snapshot. It records the current state of the three active implementation
lanes (cleanup/reclaim queues, spacemap/pool allocator, P8-03 distributed
runtime), the completion of a 40-issue design-seal wave (#1880–#1981), the
escalating coordinator issue-generation concern, and the lane health metrics
derived from Forgejo state. The document serves as the authoritative
human-readable snapshot of coordination pipeline health, building on the
architecture defined in #1833, the health monitoring framework defined in
#1838, and the prior status update in #1915.

---

## 1. Pipeline State Snapshot

### 1.1 Overall Health Assessment

**Verdict**: The coordination pipeline is in a **healthy, design-complete** state
with three active implementation lanes advancing and all 16 cluster-wide service
designs sealed. The primary concern has escalated from cadence to **proliferation**:
the coordinator is generating generational duplicates and near-duplicate issues
at a rate far exceeding worker closure capacity, creating a stockpile of 50+
`codex:ready` coordinator-sourced issues in the #1966–#2021 range, many of which
are redundant with already-closed design work.

| Dimension | State | Assessment |
|-----------|-------|------------|
| Design completeness | 16/16 cluster services sealed + 40+ subsystem designs sealed | All major and subsystem designs finalized |
| Active implementation lanes | 3 lanes advancing | Cleanup/reclaim, spacemap, P8-03 |
| Blocked work | 1 tracking issue (OW-000) | No design or implementation blockers |
| Issue stockpile | 50+ coordinator-sourced `codex:ready` issues | Proliferation rate > closure rate |
| Duplication severity | High | Many #1966–#2021 issues are generational duplicates of sealed designs |
| Velocity | ~40 design-seal closures in recent wave | Design velocity high; implementation wire-up velocity zero |
| Crate inventory | 166 crates | Substantial type-level implementation surface |
| Version | v0.421 | Steady from prior snapshot |

### 1.2 Lane-by-Lane State

#### Storage-Core Lane (50+ open coordinator-sourced issues)

The storage-core lane is the largest by issue count, driven by coordinator
auto-generation producing generational duplicates of already-sealed designs.
Three sub-lanes are active:

- **Cleanup/Reclaim Queues**: `implemented-source`. Core types in
  `tidefs-cleanup-queue-core` and `tidefs-cleanup-job-core` are implemented.
  The delta-based refcount algorithm is specified in
  `docs/design/refcount-delta-based-incremental-data-cleanup-queues.md`.
  Design sealed via #1881, #1907, #1929, #1933. Wire-up into the local
  filesystem reclaim path remains the next implementation gate.

- **Spacemap/Pool Allocator**: `G1 foundation complete, G2+ deferred`. G1
  provides the fundamental spacemap structures and pool-level allocation
  via `tidefs-claim_reserve_witness-space-*` suite. Multi-device coordination
  (G2) and adaptive segment sizing (G3) are deferred. G1 sealed via #1911,
  #1931, #1947. Pool import/export design sealed via #1944. Design:
  `docs/SPACEMAP_ALLOCATOR_DESIGN.md`,
  `docs/design/pool-import-export-device-topology-management.md`.

- **P8-03 Distributed Runtime**: `9/9 canonical component crates implemented`.
  The full set of distributed runtime crates (`tidefs-distributed-storage-runtime`,
  `tidefs-replication-*`, `tidefs-erasure-coding`, `tidefs-erasure-coded-store`,
  `tidefs-chunk-shipper`, `tidefs-node-drain`, `tidefs-cluster-gc`,
  `tidefs-cluster-snapshot`) are implemented at the type and protocol level.
  `tidefs-flow-commit-coordinator` is `implemented-source` with 23 unit tests.
  End-to-end 3-node cluster bootstrapping and cross-node state machine
  advancement remain deferred to child GAP issues. Design:
  `docs/design/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md`.

#### Coordination Lane

The coordination lane has multiple active claims and a backlog of
coordinator-sourced issues. Key open issues include:

| State | Representative Issues |
|-------|----------------------|
| `codex:claimed` | #1791 (transport spec update), #1792 (spacemap G1), #1818 (POSIX ACL), #1820 (lane tracking sync), #1825 (ublk SET_PARAMS), #1837 (scrub design), #1839 (prior status update), #1844 (P8-03 gap), #1922 (atomic snapshot), #1927 (scheduling classes), #1936 (locator table), #1937 (dataset lifecycle), #1948 (scrub update), #1949 (background svc), #1953 (roadmap), #1955 (distributed lock), #1984 (operator docs), #1992 (background svc), #2009 (health report) |
| `codex:needs-review` | #1694, #1728, #1763 (stale from prior snapshot) |
| `codex:ready` (coordinator) | #1966–#2021 range: predominantly generational duplicates of sealed designs |

#### Design-Seal Wave (#1880–#1981)

A coordinated design-seal wave closed 40+ issues confirming canonical design
specifications as authoritative. Key sealed designs include:

| Design Domain | Seal Issues | Canonical Doc |
|---------------|-------------|---------------|
| Cluster-wide distributed lock service | #1880, #1901 | `docs/design/cluster-wide-distributed-lock-service-design.md` |
| Deferred cleanup work queues | #1881, #1929, #1933 | `docs/design/deferred-cleanup-work-queues.md` |
| Persistent orphan index | #1882 | `docs/design/persistent-orphan-index-consolidated-design.md` |
| Background service framework | #1883, #1935, #1946, #1980 | `docs/design/background-service-framework-design-enhanced.md` |
| Shard groups, replicas, rebake | #1884 | `docs/design/shard-groups-replicas-rebake-design-spec.md` |
| Scrub, repair, resilver orchestration | #1885, #1913, #1917, #1943 | `docs/design/scrub-deep-scrub-repair-resilver-orchestration-design.md` |
| Device layout policies | #1886 | `docs/design/device-layout-policies-adaptive-segment-sizing.md` |
| G3 pillar checksum architecture | #1888 | `docs/design/end-to-end-checksum-architecture-g3-pillar.md` |
| V1 locator table (inline-hash) | #1905 | `docs/design/v1-locator-table-inline-hash.md` |
| V1 extent map tristate model | #1906 | `docs/design/v1-extent-map-tristate-model.md` |
| Refcount delta cleanup queues | #1907 | `docs/design/refcount-delta-based-incremental-data-cleanup-queues.md` |
| POSIX ACL xattr codec | #1908, #1942 | `docs/design/posix-acl-xattr-codec-and-evaluation-design.md` |
| Unified cache-lattice views | #1909, #1939, #1988 | `docs/design/unified-cache-lattice-views.md` |
| Spacemap allocator G1 | #1911, #1931, #1947 | `docs/SPACEMAP_ALLOCATOR_DESIGN.md` |
| Dataset lifecycle state machine | #1903, #1938 | `docs/design/dataset-lifecycle-state-machine.md` |
| Pool import/export topology | #1902, #1944 | `docs/design/pool-import-export-device-topology-management.md` |
| IncrementalJob core types | #1930 | `docs/design/incremental-job-core-types-crate-design.md` |
| Cluster security/identity model | #1928, #2016, #2018, #2020 | `docs/design/cluster-security-identity-model.md` |
| Production erasure coding (G4) | #1932 | `docs/design/production-erasure-coding-crush-placement-g4-pillar.md` |
| Transport endpoint lifecycle | #1889, #1959 | `docs/CLUSTER_TRANSPORT_BOUNDEDNESS_DESIGN.md` |
| Coordination review/roadmap | #1914, #1953, #1981 | `docs/design/coordination-review-roadmap-priorities-update.md` |



#### Docs Lane

Documentation issues track design doc creation, STATUS.md/FEATURE_MATRIX
maintenance, audit sweeps (#1924, #1945), glossary (#1941), debugging
workflows (#1960), and getting-started updates (#1934).

#### Transport Lane

Transport issues cover RDMA experiments (OW-308), boundedness enforcement,
BULK plane protocol wire-up, and endpoint lifecycle documentation. Transport

---

## 2. Architecture: The Coordination Pipeline as a Hierarchical Status Machine

### 2.1 Status Machine Layers

The coordination pipeline operates as a hierarchical status machine with
three layers:

```
Layer 3: Issue State Machine (Forgejo labels)
    codex:ready → codex:claimed → codex:needs-review → codex:done
                                          ↕
                                    codex:blocked

Layer 2: Lane State Machine (STATUS.md entries)
    design-spec → design-sealed → implemented-source → implemented-runtime
                                                              ↓

Layer 1: Pipeline Health State Machine (this document)
    Healthy → Healthy (design-complete) → Healthy (implementing)
        ↓              ↓                        ↓
    Degraded       Proliferating           Stalled
```

### 2.2 Current State Transitions

The pipeline is in the **Healthy (design-complete)** state. All 16 cluster-wide
service designs are sealed. The 40-issue design-seal wave (#1880–#1981) has
transitioned the pipeline from "design in-progress" to "design complete" across
all four architectural layers (Transport, Coordination, Data Flow, Observability).

The next target state is **Healthy (implementing)**, which requires:
1. At least one active implementation lane to reach `implemented-runtime`
3. Zero blocked implementation lanes

---

## 3. Coordinator Proliferation Analysis

### 3.1 The Proliferation Pattern

The coordinator is generating issues in the #1966–#2021 range at a rate far
exceeding worker closure capacity. Analysis of the issue stream reveals a
systematic duplication pattern:

| Duplication Pattern | Examples | Root Cause |
|---------------------|----------|------------|
| Generational duplicates | #1969/#1970 (G3 checksum), #1971/#1993/#1994/#2014 (pool import/export), #1972/#1989/#1990/#2013 (dataset lifecycle) | Coordinator re-generates issues for already-sealed designs |
| Near-duplicate design specs | #1966/#2002 (extent maps), #1967/#1971 (device layout + pool import) | Slightly different titles trigger new issue generation |
| Stale-state re-issue | #1973 (locator table), #1974 (extent map), #1975 (cleanup queues) | Coordinator re-issues designs that were sealed in the #1880-#1947 wave |
| Implementation-gap tracking duplicates | #1978, #2019 (P8-03 gap) | Same gap described differently triggers multiple issues |

### 3.2 Quantified Impact

| Metric | Prior Snapshot (#1915) | Current Snapshot (#1954) | Delta |
|--------|------------------------|--------------------------|-------|
| Coordinator-sourced `codex:ready` | 12 | 50+ | +38+ |
| Generational duplicates detected | 4 | 30+ | +26+ |
| Stale `codex:needs-review` | 3 | 3 (unchanged) | 0 |
| Worker closure rate (coord issues/week) | 1–2 | ~40 (design-seal wave) | Wave-driven, not sustained |
| Coordinator generation rate | ~5/week | ~15/week | Escalating |

### 3.3 Proliferation Root Cause

The design-seal wave (#1880–#1981) closed 40+ issues in rapid succession.
The coordinator, observing closed design issues, re-generates new issues for
the same design domains with slightly different framing because:

1. The coordinator scans STATUS.md for design entries and creates lane-maintenance
   issues for each referenced design domain.
2. When a design is sealed, STATUS.md is updated with the seal entry. The
   coordinator then sees the sealed entry as a new item requiring a tracking issue.
3. Slight variations in STATUS.md entry phrasing produce distinct issue titles,
   defeating deduplication heuristics.

### 3.4 Recommended Mitigations

1. **Coordinator deduplication**: Before generating a new issue, the coordinator
   should query Forgejo for existing open issues with matching domain keywords
   and skip generation if a recent (<7 day) duplicate exists.
2. **Design-seal sentinel**: Issues with `kind:design` that have been closed with
   a `design-sealed` maturity annotation should be excluded from re-generation
   for at least 30 days.
3. **Stale auto-closure**: `codex:needs-review` issues untouched for >14 days
   should be auto-closed with a comment referencing the superseding design.
4. **Cadence throttle**: Coordinator issue generation should be throttled to
   at most 5 new `codex:ready` issues per day across all lanes.

---

## 4. Health Metrics

### 4.1 Lane Health Scores

| Lane | Design Health | Implementation Health | Overall | Trend |
|------|---------------|----------------------|---------|-------|
| Transport | 100% (all designs sealed) | 60% (protocol docs, boundedness partial) | 80% | Stable |
| Coordination | 100% (16/16 services sealed) | 10% (type-level only, no runtime wire-up) | 55% | Stable |
| Data Flow | 100% (all designs sealed) | 40% (9/9 crates, no 3-node bootstrap) | 70% | Stable |
| Observability | 100% (designs sealed) | 5% (no runtime dashboards) | 52% | Stable |
| Storage-Core | 100% (all subsystem designs sealed) | 50% (cleanup/spacemap/P8-03 partial) | 75% | Improving |

### 4.2 Velocity Assessment

- **Design velocity**: High. The #1880–#1981 wave closed 40+ design issues in
  a single coordinated sweep, demonstrating strong batch-processing capability.
- **Implementation velocity**: Near zero for wire-up. No new `implemented-runtime`
  transitions since the prior snapshot. The design-seal wave confirmed specifications
  but did not produce new runtime code.
- **Coordination velocity**: Asymmetric. Coordinator generates ~15 issues/week;
  workers close ~1–2 coordination issues/week under normal cadence (the design-seal
  wave was an exceptional event).

### 4.3 Dependency Health

| Dependency Chain | Status | Blocker |
|------------------|--------|---------|
| BULK plane → P8-03 transport → Rebuild/Backfill | BULK plane design sealed; P8-03 crates implemented | BULK plane wire-up |
| Cleanup/Reclaim → Local filesystem reclaim | Core types implemented; wire-up deferred | Local filesystem integration |
| Spacemap G1 → G2 (multi-device) → G3 (adaptive sizing) | G1 complete; G2/G3 deferred | G2 multi-device coordination |
| P8-03 crates → 3-node bootstrap → cross-node state machine | 9/9 crates implemented; bootstrap deferred | MEMBERSHIP runtime |

---

## 5. Data Structures for Pipeline Status Tracking

### 5.1 `LaneHealthSnapshot`

```rust
/// A point-in-time health snapshot for a single implementation lane.
#[derive(Debug, Clone)]
struct LaneHealthSnapshot {
    /// Lane identifier (e.g., "storage-core", "coordination", "transport")
    lane: LaneId,

    /// Count of open issues in this lane
    open_issues: usize,

    /// Count of `codex:claimed` issues
    claimed_issues: usize,

    /// Count of `codex:needs-review` issues
    needs_review_issues: usize,

    /// Count of `codex:ready` issues
    ready_issues: usize,

    /// Count of `codex:blocked` issues
    blocked_issues: usize,

    /// Design health score (0.0–1.0)
    design_health: f64,

    /// Implementation health score (0.0–1.0)
    implementation_health: f64,

    /// Number of generational duplicates detected
    duplicate_count: usize,

    /// Timestamp of this snapshot
    captured_at: DateTime<Utc>,
}
```

### 5.2 `PipelineStatusEntry`

```rust
/// A single STATUS.md entry representing a pipeline status update.
#[derive(Debug, Clone)]
struct PipelineStatusEntry {
    /// Forgejo issue number associated with this update
    issue_number: u64,

    /// ISO 8601 date of the update
    date: NaiveDate,

    /// Overall pipeline health verdict
    health_verdict: HealthVerdict,

    /// Per-lane health snapshots
    lane_snapshots: Vec<LaneHealthSnapshot>,

    /// Coordinator proliferation assessment
    proliferation_assessment: ProliferationAssessment,

    /// Active implementation lanes
    active_lanes: Vec<ActiveLane>,

    /// Dependency health report
    dependency_health: Vec<DependencyHealth>,

    /// Risk register
    risks: Vec<RiskEntry>,

    /// Recommended actions
    recommendations: Vec<String>,
}

#[derive(Debug, Clone)]
enum HealthVerdict {
    Healthy,
    HealthyDesignComplete,
    HealthyImplementing,
    Degraded { reason: String },
    Proliferating { duplicate_count: usize },
    Stalled { stalled_lane: LaneId, stall_duration_days: u32 },
}

#[derive(Debug, Clone)]
struct ProliferationAssessment {
    /// Total coordinator-sourced open issues
    coordinator_open_issues: usize,

    /// Number of detected generational duplicates
    generational_duplicates: usize,

    /// Coordinator generation rate (issues/week)
    generation_rate_per_week: f64,

    /// Worker closure rate (issues/week)
    closure_rate_per_week: f64,

    /// Proliferation severity
    severity: ProliferationSeverity,
}

#[derive(Debug, Clone)]
enum ProliferationSeverity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
struct ActiveLane {
    lane: LaneId,
    description: String,
    maturity: LaneMaturity,
    crate_count: usize,
    next_gate: String,
}

#[derive(Debug, Clone)]
enum LaneMaturity {
    DesignSpec,
    DesignSealed,
    ImplementedSource,
    ImplementedRuntime,
}
```

### 5.3 Delta Computation Algorithm

The delta between successive STATUS.md coordination entries is computed as:

```
fn compute_pipeline_delta(
    previous: &PipelineStatusEntry,
    current: &PipelineStatusEntry,
) -> PipelineDelta {
    PipelineDelta {
        // Issues closed since previous snapshot
        closed_issues: diff_closed(&previous, &current),

        // New issues opened since previous snapshot
        new_issues: diff_opened(&previous, &current),

        // Lanes whose health score changed by >0.05
        health_changes: diff_health_scores(&previous, &current, threshold=0.05),

        // New generational duplicates detected
        new_duplicates: current.lane_snapshots.iter()
            .map(|ls| ls.duplicate_count)
            .sum::<usize>()
            - previous.lane_snapshots.iter()
                .map(|ls| ls.duplicate_count)
                .sum::<usize>(),

        // Maturity transitions
        maturity_transitions: diff_maturities(&previous, &current),

        // Proliferation severity change
        proliferation_delta: compare_proliferation(&previous, &current),

        // Recommendations carried forward vs new
        recommendation_delta: diff_recommendations(&previous, &current),
    }
}
```

---

## 6. Algorithms: Pipeline Health Scoring

### 6.1 Design Health Score

```
design_health(lane) = sealed_designs(lane) / total_designs(lane)

Where:
- sealed_designs(lane): count of designs with maturity >= design-sealed
- total_designs(lane): count of all design documents in lane scope
```

For cluster-wide services (Layers 8-11): `design_health = 16/16 = 1.0`.

### 6.2 Implementation Health Score

```
implementation_health(lane) = Σ(weight(m) × count(m)) / Σ(weight(m) × total(m))

Where:
- weight(m) = {0.0, 0.1, 0.4, 0.7, 1.0}
- count(m): number of capabilities at maturity m
- total(m): total capabilities tracked in lane
```

### 6.3 Proliferation Severity Algorithm

```
fn assess_proliferation(snapshot: &PipelineStatusEntry) -> ProliferationSeverity {
    let ratio = snapshot.proliferation_assessment.generation_rate_per_week
              / snapshot.proliferation_assessment.closure_rate_per_week.max(0.1);

    let dup_ratio = snapshot.proliferation_assessment.generational_duplicates as f64
                  / snapshot.proliferation_assessment.coordinator_open_issues as f64;

    match (ratio, dup_ratio) {
        (r, _) if r > 10.0 => ProliferationSeverity::Critical,
        (r, d) if r > 5.0 && d > 0.5 => ProliferationSeverity::High,
        (r, d) if r > 3.0 && d > 0.3 => ProliferationSeverity::Medium,
        (r, _) if r > 1.5 => ProliferationSeverity::Low,
        _ => ProliferationSeverity::None,
    }
}
```

Current assessment: `generation_rate = 15/week`, `closure_rate ≈ 2/week` (normalized
non-wave), `ratio = 7.5`, `dup_ratio = 30/50 = 0.6` → **ProliferationSeverity::High**.

---

## 7. Tradeoffs

### 7.1 Design-Seal Wave vs Incremental Sealing

| Approach | Pros | Cons | Verdict |
|----------|------|------|---------|
| Batch seal wave (current) | Efficient, all designs confirmed together, clear state boundary | Creates coordination gap: 40+ closures trigger re-generation cascade | **Chosen** for design phase; proliferation is a coordinator-side concern |
| Incremental sealing | No cascade, worker-paced | Slower, harder to declare "design complete" milestone | Rejected: design phase completeness is valuable |

### 7.2 Coordinator Throttling vs Full Automation

| Approach | Pros | Cons | Verdict |
|----------|------|------|---------|
| Unthrottled generation (current) | Always-up-to-date issue register | Proliferation risk, worker confusion | **Problematic** |
| Throttled generation (5/day) | Manageable issue volume | May miss rapid state changes | **Recommended** |
| On-demand generation only | Zero proliferation | Requires manual trigger for lane maintenance | Rejected: loses automation benefit |

### 7.3 Design-Sealed → Implemented-Source Transition Strategy

| Approach | Pros | Cons | Verdict |
|----------|------|------|---------|
| Per-service wire-up issues | Independent, parallelizable | Requires all dependency designs sealed first | **Chosen** |
| Batch wire-up | Coordinated, fewer issues | Serial bottleneck | Rejected: parallel safety rules prefer independent issues |
| Inline implementation | No coordination overhead | Violates serial-surface rules | Rejected |

---

## 8. Failure Mode Analysis

| Failure Mode | Likelihood | Impact | Mitigation |
|-------------|-----------|--------|------------|
| Coordinator generates issues faster than workers can close them | **High** (confirmed) | Medium (worker confusion, register clutter) | Deduplication, cadence throttle (§3.4) |
| Design-seal wave triggers re-generation cascade | **High** (confirmed) | Medium (30+ duplicates in #1966–#2021) | Design-seal sentinel exclusion (§3.4) |
| Stale `codex:needs-review` issues accumulate indefinitely | Medium | Low (3 stale, unchanged from #1915) | Stale auto-closure policy (§3.4) |
| Serial write surface contention on `tidefs-local-filesystem` | Low | Medium | Only one active issue may edit per AGENTS.md contract |
| Design drift: sealed designs diverge from implementation reality | Medium | Medium | Periodic STATUS.md snapshots capture actual state |
| Worker confusion from duplicate `codex:ready` issues | Medium | Medium | Deduplication + clear supersession comments |

---

## 9. Future Wire-Up Strategy

### 9.1 Dependency-Ordered Implementation Sequence

The 16 sealed cluster-service designs will be wired up in dependency order:

```
Phase 1: Transport Foundation
    ├── BULK plane wire protocol
    ├── Per-lane transport budgets
    └── Security/identity protocol (PSK infrastructure)
        │
Phase 2: Coordination Services
    ├── MEMBERSHIP protocol (3-node cluster bootstrap) ← CRITICAL PATH
    ├── Distributed lock service (depends on MEMBERSHIP fencing)
    └── Admin proxy model (depends on MEMBERSHIP leader election)
        │
Phase 3: Data Flow Services
    ├── P8-03 cross-node state machine advancement
    ├── Rebuild/backfill (depends on P8-03 transport)
    └── Erasure-coded layout (depends on BULK plane + P8-03)
        │
Phase 4: Observability
    └── Operator truth surfaces, dashboards, traces
```

### 9.2 Immediate Next Implementation Gates

1. **Cleanup/reclaim queue wire-up into local filesystem reclaim path**
   — Core types implemented; runtime integration is the next gate.

2. **Spacemap G2 multi-device coordination**
   — G1 foundation complete; pool-level allocator needs multi-device awareness.

3. **P8-03 3-node cluster bootstrap**
   — Depends on MEMBERSHIP wire-up; all 9/9 component crates implemented.

4. **MEMBERSHIP protocol wire-up (#1209)**
   — The critical-path blocker for all coordination service implementation.

### 9.3 Wire-Up Issue Template

Each wire-up issue should include:

1. Reference to the sealed design document
2. List of crates to be created or modified
3. Interface contracts to be implemented
5. Serial write surface declaration
6. Dependency issues that must be completed first

---

## 10. Integration Contracts

### 10.1 STATUS.md Update Contract

Every coordination pipeline status update must:

1. Query Forgejo API for current lane state before writing
2. Parse the previous Coordination Status entry from STATUS.md
3. Compute deltas between previous and current state
4. Include: lane status, overall project metrics, pipeline health narrative,
   velocity assessment, proliferation analysis, and roadmap priorities
5. Prepend the new entry at the top of STATUS.md
6. Close the Forgejo issue that triggered the update

### 10.2 FEATURE_MATRIX.md Update Contract

When a capability's maturity changes, the FEATURE_MATRIX.md row must be updated:

- `design-sealed`: Design finalized, no further design changes expected
- `implemented-source`: Core types and protocols implemented in crates

### 10.3 Cross-Document Consistency Contract

| Document | Consistency Rule |
|----------|-----------------|
| `docs/STATUS.md` | Most recent entry reflects current Forgejo state |
| `docs/FEATURE_MATRIX.md` | Row maturity matches crate implementation state |
| `docs/design/*.md` | Design docs reference correct issue numbers and status |
| Forgejo labels | Issue labels match documented maturity state |

---

## 11. Conclusion

The coordination pipeline is in a **healthy, design-complete** state. All 16
cluster-wide service designs are sealed, and a 40-issue design-seal wave
(#1880–#1981) has confirmed all subsystem design specifications as authoritative.
The three active implementation lanes (cleanup/reclaim queues, spacemap/pool
allocator, P8-03 distributed runtime) are advancing, with the distributed
runtime achieving 9/9 canonical component crates implemented.

The primary operational concern is **coordinator proliferation**: the coordinator
is generating issues at ~15/week, producing 30+ generational duplicates in the
#1966–#2021 range. This exceeds worker closure capacity (~2/week normalized) by
a factor of 7.5×, creating register clutter and potential worker confusion.
Recommended mitigations include coordinator deduplication, design-seal sentinel
exclusion, stale auto-closure policies, and cadence throttling to 5 issues/day.

The deferred wire-up strategy enables parallel implementation against sealed
interface contracts, with services wired up in dependency order from Transport
(Layer 8) through Observability (Layer 11). The critical-path blocker is
MEMBERSHIP protocol wire-up (#1209), which gates all coordination service
implementation including the P8-03 3-node cluster bootstrap.

---

**Coordination pipeline status update (#1954) complete.** This document
supersedes #1915 as the current authoritative coordination pipeline status
snapshot. The architecture, data structures, and algorithms defined in #1833
and #1838 remain the governing frameworks. Future status updates should build
on this document's lane state, proliferation assessment, and health metrics.

**Gate**: `cargo check --workspace` passes. Design-only document; no code
changes.

**Closes**: #1954
