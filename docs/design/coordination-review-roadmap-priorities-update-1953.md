# Coordination Review and Roadmap Priorities Update — 2026-05-05

**Issue**: [#1953](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1953)
**Supersedes**: [#1914](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1914) (previous coordination review)
**Status**: design-spec
**Maturity**: design-spec — coordination pipeline health review, active lane
status, and roadmap priority framework for Q2 2026
**Priority**: P2
**Lane**: storage-core / coordination (Layers 8–11)
**Depends on**: #1914 (prior coordination review), #1738 (coordination pipeline design seal), #1903 (dataset lifecycle design seal)
**Blocks**: All deferred cluster-service wire-up implementation issues
**Authority note**: This imported roadmap is historical input. Current
coordination and documentation-authority status lives in GitHub issues, pull
requests, `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`, and `docs/INDEX.md`,
not in the deleted `docs/STATUS.md` or `docs/FEATURE_MATRIX.md` outputs.

## Abstract

This document performs the third coordination pipeline health review (following
#1753 and #1914). The design phase for cluster-wide services was sealed via #1738
and remains substantially complete. Three active implementation lanes continue to
advance: cleanup/reclaim queues (implemented-source), spacemap/pool allocator
(G1 foundation complete, G2+ deferred), and P8-03 distributed runtime (9/9
canonical component crates implemented). This document formally defines the
architecture of the coordination pipeline, the data structures for pipeline health
tracking and priority ordering, the algorithms for stall detection and scheduling,
and the tradeoffs inherent in the deferred-integration strategy. End-to-end 3-node
cluster bootstrapping, cross-node state machine advancement, and production
distributed runtime integration remain deferred to child GAP issues.

---

## 1. Architecture

### 1.1 Coordination Pipeline Layering

The coordination pipeline spans TideFS Layers 8–11 plus cross-cutting surfaces.
Each layer has a distinct responsibility in the overall coordination architecture:

```
┌──────────────────────────────────────────────────────┐
│ Layer 11: Observability & Health                     │
│   Pipeline health scoring, stall detection,          │
│   shadow-pilot divergence monitoring, trace oracles  │
├──────────────────────────────────────────────────────┤
│ Layer 10: Data Flow & Service Integration            │
│   Replication, rebuild, rebalance, erasure coding,   │
├──────────────────────────────────────────────────────┤
│ Layer 9: Coordination & Consensus                    │
│   Membership epochs, distributed locks, atomic       │
│   snapshots, cluster-admin proxy, security/identity  │
├──────────────────────────────────────────────────────┤
│ Layer 8: Transport                                   │
│   Endpoint families (e0..e3), session management,    │
│   handshake, TCP loopback, RDMA probe (optional)     │
└──────────────────────────────────────────────────────┘
                        │
    ┌───────────────────┼───────────────────┐
    │ Cross-cutting:    │ Cross-cutting:    │
    │ Dataset Lifecycle │ Spacemap/Alloc    │
    │ (design-sealed)   │ (G1 implemented)  │
    └───────────────────┴───────────────────┘
```

### 1.2 Design-Sealed Services

All 16 cluster services plus dataset lifecycle are design-sealed. No new
service designs are required. The sealed designs are listed below with their
canonical design documents:

| # | Service | Document | Maturity |
|---|---------|----------|----------|
| 1 | Membership service | `docs/design/bounded-cluster-membership-state.md` | design-sealed |
| 2 | Distributed lock service | `docs/design/cluster-wide-distributed-lock-service-design.md` | design-sealed |
| 3 | Atomic snapshot coordination | `docs/design/cluster-wide-atomic-snapshot-coordination.md` | design-sealed |
| 4 | Cluster admin proxy | `docs/design/cluster-admin-proxy-model.md` | design-sealed |
| 5 | Security/identity model | `docs/design/cluster-security-identity-model.md` | design-sealed |
| 7 | Bulk plane protocol | `docs/design/cluster-bulk-plane-protocol.md` | design-sealed |
| 8 | Mmap cluster coherency | `docs/design/mmap-cluster-coherency.md` | design-sealed |
| 9 | Node lifecycle management | `docs/design/node-lifecycle-management.md` | design-sealed |
| 10 | Shard groups/replicas/rebake | `docs/design/shard-groups-replicas-rebake-design-spec.md` | design-sealed |
| 11 | Scrub/repair/resilver | `docs/design/scrub-deep-scrub-repair-resilver-orchestration-design.md` | design-sealed |
| 12 | Pool import/export | `docs/design/pool-import-export-device-topology-management.md` | design-sealed |
| 13 | Background service framework | `docs/design/background-service-framework-design.md` | design-sealed |
| 14 | IncrementalJob core types | `docs/design/incremental-job-core-types-crate-design.md` | design-sealed |
| 15 | Unified cache lattice | `docs/design/unified-cache-lattice-views.md` | design-sealed |
| 16 | Deterministic simnet | `docs/design/deterministic-cluster-simnet-protocol-correctness-testing.md` | design-spec |
| 17 | Dataset lifecycle | `docs/design/dataset-lifecycle-state-machine.md` | design-sealed |

### 1.3 Active Implementation Lanes (2026-05-05)

Three lanes have live source that directly advances coordination pipeline
capability. All other cluster services remain deferred to wire-up issues.

#### Lane A: Cleanup/Reclaim Queues (implemented-source)

**Status**: Implemented with background-service integration.

**Crates**:
- `tidefs-types-deferred-cleanup-core` — fix-sized on-media work items
- `tidefs-cleanup-queue-core` — B+tree-backed cleanup queues
- `tidefs-cleanup-job-core` — `IncrementalJob` implementation
- `tidefs-types-reclaim-queue-core` — reclaim entry types
- `tidefs-reclaim-queue-core` — 4-family B+tree reclaim queues
- `tidefs-reclaim-job-core` — reclaim `IncrementalJob`
- `tidefs-reclaim` — `BackgroundReclaim` wired as `BackgroundService`

**Design contract**: Two-phase deletion with O(1) synchronous Phase 1 enqueue
and budgeted background Phase 2 iteration. Delta-aggregation across 4 queue
families (extent reclaim, locator reclaim, rebake, inode tombstone).

**Test coverage**: 64+ unit tests across cleanup/reclaim crates.

**Remaining**: Live refcount delta production, ENOSPC pressure response,
integration test coverage for the reclaim path.

#### Lane B: Spacemap/Pool Allocator (G1 foundation complete)

**Status**: G1 (segment-level allocation) implemented. G2+ (multi-device pool-level
coordination) deferred to wire-up issues tracked in #1694.

**Crates**:
- `tidefs-pool-allocator` — pool-level allocation orchestration
- `tidefs-metaslab-allocator` — per-device metaslab management
- `tidefs-spacemap` — segment-level free/allocated tracking

**Design contract**: G1 covers single-device segment allocation with finite
accounting. G2+ adds multi-device weighted allocation, class-aware placement,
and pressure-driven space rebalancing.

**Test coverage**: 7 sequential implementation issues (#1550/#1568/#1570/#1606/
#1607/#1643/#1693) delivered G1; each with dedicated tests.

**Remaining**: Multi-device coordination (#1694), free-space pressure response,
automatic journal cleaning under space pressure.

#### Lane C: P8-03 Distributed Runtime (9/9 canonical crates)

**Status**: All 9 canonical component crates implemented at the deterministic
model level. Networked runtime and 3-node bootstrapping deferred.

**Crates**:
- `tidefs-membership-epoch` — deterministic OW-302 placement model
- `tidefs-failure-domain-placement` — deterministic OW-303 replica planning
- `tidefs-replicated-object-root-storage` — deterministic OW-304 replicated storage model
- `tidefs-rebuild-backfill-rebalance` — deterministic OW-305 movement planning
- `tidefs-erasure-coded-layout` — deterministic OW-306 single-parity layout
- `tidefs-replication-model` — replication contracts
- `tidefs-replication` — first networked replication transport
- `tidefs-replica-health` — per-chunk health, flap detection
- `tidefs-shadow-pilot-runtime` — h0–h9 hook chain with divergence classification

**Design contract**: The deterministic models exercise correct placement,
planning, and recovery logic without network dependence. The networked
replication transport (#1070) provides quorum-based commit over TCP.

**Test coverage**: Each OW-30x crate is implementation-tracked non-release by a `tidefs-xtask check-*`

**Remaining**: 3-node cluster bootstrapping, cross-node state machine advancement,
production distributed runtime integration (deferred to child GAP issues).

---

## 2. Data Structures

### 2.1 Pipeline Health Record

The `CoordinationPipelineHealth` struct captures the current coordination
pipeline state for health scoring and stall detection.

```
CoordinationPipelineHealth {
    review_sequence: u64,
    assessed_at: DateTime<Utc>,
    design_sealed_count: u8,
    implemented_count: u8,
    deferred_wireup_count: u16,
    active_lanes: Vec<LaneHealth>,
    stale_review_items: Vec<IssueRef>,
    duplicate_issues: Vec<IssueRef>,
    serial_surface_contention: SerialSurfaceState,
    health_score: f64,
}

LaneHealth {
    lane_name: LaneName,
    maturity: LaneMaturity,
    active_claims: u8,
    ready_issues: u8,
    blocked_issues: u8,
    needs_review_issues: u8,
    stale_days_max: u16,
    wire_up_deferred_count: u16,
    health_score: f64,
}

SerialSurfaceState {
    local_filesystem_claim: Option<IssueRef>,
    local_object_store_claim: Option<IssueRef>,
}
```

### 2.2 Priority Ordering Data Structures

The roadmap priority framework uses a 6-phase strict partial order.

```
RoadmapPhase {
    phase: PhaseOrdinal,
    phase_name: PhaseName,
    issue_groups: Vec<IssueGroup>,
    dependency_count: u8,
    estimated_issue_count: u16,
    completed_issue_count: u16,
}

PhaseOrdinal: enum { Maintenance(1), Critical(2), Core(3), Spacemap(4), Distributed(5), Production(6) }

IssueGroup {
    group_name: String,
    issues: Vec<IssueRef>,
    blocking_surface: Option<SerialSurface>,
    estimated_lines: u32,
}
```

### 2.3 Stall Detection Window

A sliding window over coordination pipeline events detects stall conditions.

```
StallWindow {
    window_size: Duration,          // 14-day default
    events: VecDeque<PipelineEvent>,
    min_expected_events: u8,
}

PipelineEvent {
    event_kind: PipelineEventKind,
    occurred_at: DateTime<Utc>,
    issue_ref: Option<IssueRef>,
    lane: Option<LaneName>,
}

PipelineEventKind: enum {
    IssueClaimed, IssueClosed, DesignSealed, WireUpStarted,
    DuplicateCreated, SerialSurfaceContention,
}
```

### 2.4 Deferred Wire-Up Work Queue

Tracks all deferred implementation items with dependency edges forming a DAG.

```
WireUpWorkQueue {
    items: Vec<WireUpItem>,
    dependency_graph: AdjacencyList,
    scheduling_order: Vec<usize>,
}

WireUpItem {
    service_name: String,
    design_document_path: PathBuf,
    estimated_lines: u32,
    dependency_issues: Vec<IssueRef>,
    blocking_issues: Vec<IssueRef>,
    maturity: WireUpMaturity,
}

WireUpMaturity: enum {
}
```

---

## 3. Algorithms

### 3.1 Pipeline Health Scoring

Computes a 0.0–1.0 health score from weighted dimensions: design
completeness (35%), implementation progress (35%), staleness penalty (15%),
and serial contention penalty (15%).

```
fn score_pipeline_health(h: &CoordinationPipelineHealth) -> f64 {
    let design_completeness = h.design_sealed_count as f64 / 17.0;

    let implementation_progress = {
        let lane_scores: Vec<f64> = h.active_lanes.iter()
            .map(|l| l.health_score)
            .collect();
        lane_scores.iter().sum::<f64>() / lane_scores.len().max(1.0) as f64
    };

    let staleness_penalty = {
        let stale_count = h.stale_review_items.len() as f64;
        let dup_count = h.duplicate_issues.len() as f64;
        1.0 - (stale_count * 0.05 + dup_count * 0.03).min(0.4)
    };

    let serial_contention_penalty = {
        if h.serial_surface_contention.has_dual_contention() { 0.95 } else { 1.0 }
    };

    design_completeness * 0.35 + implementation_progress * 0.35
        + staleness_penalty * 0.15 + serial_contention_penalty * 0.15
}
```

### 3.2 Per-Lane Health Scoring

```
fn score_lane_health(lane: &LaneHealth) -> f64 {
    let maturity_score = match lane.maturity {
        LaneMaturity::DesignSpec => 0.2,
        LaneMaturity::ImplementedSource => 0.6,
        LaneMaturity::ImplementedVerified => 1.0,
    };

    let activity_ratio = {
        let total = lane.active_claims + lane.ready_issues + lane.blocked_issues;
        if total == 0 { 0.5 } else { lane.active_claims as f64 / total as f64 }
    };

    let staleness_factor = {
        let days = lane.stale_days_max as f64;
        if days > 30.0 { 0.3 } else if days > 14.0 { 0.6 } else { 1.0 }
    };

    let progress_ratio = {
        let total = lane.wire_up_deferred_count + 1;
        (total - lane.wire_up_deferred_count) as f64 / total as f64
    };

    maturity_score * 0.40 + activity_ratio * 0.25 + staleness_factor * 0.20 + progress_ratio * 0.15
}
```

### 3.3 Stall Detection

A sliding-window algorithm detects stalled lanes. A lane is stalled when
the event count within the window (14-day default) falls below the minimum
threshold (3 events minimum).

```
fn detect_stalls(h: &CoordinationPipelineHealth, window: &StallWindow) -> Vec<StallAlert> {
    let now = Utc::now();
    let cutoff = now - window.window_size;

    let lane_events: HashMap<LaneName, Vec<&PipelineEvent>> = window.events
        .iter()
        .filter(|e| e.occurred_at >= cutoff)
        .filter_map(|e| e.lane.map(|l| (l, e)))
        .fold(HashMap::new(), |mut acc, (lane, event)| {
            acc.entry(lane).or_default().push(event);
            acc
        });

    let active_lanes = [LaneName::CleanupReclaim, LaneName::Spacemap, LaneName::DistributedRuntime];
    let mut alerts = Vec::new();

    for lane in &active_lanes {
        let count = lane_events.get(lane).map(|v| v.len()).unwrap_or(0);
        if count < window.min_expected_events as usize {
            alerts.push(StallAlert {
                lane: *lane,
                events_in_window: count as u8,
                threshold: window.min_expected_events,
                severity: if count == 0 { StallSeverity::Critical } else { StallSeverity::Warning },
                diagnosed_at: now,
            });
        }
    }
    alerts
}
```

### 3.4 Priority Dequeue for Claim Selection

Given roadmap phases in strict order, dequeue the next claimable issue
respecting serial-surface constraints and the dependency DAG.

```
fn next_claimable(
    phases: &[RoadmapPhase],
    active_claims: &HashSet<IssueRef>,
    dependency_graph: &AdjacencyList,
) -> Option<IssueRef> {
    for phase in phases.iter().sorted_by_key(|p| p.phase) {
        for group in &phase.issue_groups {
            if let Some(surface) = &group.blocking_surface {
                if surface_is_contended(surface, active_claims) { continue; }
            }
            for issue in &group.issues {
                if active_claims.contains(issue) { continue; }
                if !deps_satisfied(issue, active_claims, dependency_graph) { continue; }
                return Some(*issue);
            }
        }
    }
    None
}
```

### 3.5 Deduplication Gate

Before creating a new coordination issue, the coordinator must pass a
title-similarity and content-overlap check against all open issues.

```
fn dedup_gate(candidate: &IssueCandidate, open_issues: &[Issue]) -> DedupResult {
    for existing in open_issues {
        let title_dist = normalized_edit_distance(&candidate.title, &existing.title);
        let title_threshold = 0.20 * candidate.title.len().min(existing.title.len()) as f64;
        if title_dist < title_threshold {
            return DedupResult::Duplicate { existing: existing.number, similarity: 1.0 - title_dist / title_threshold };
        }
        let body_similarity = jaccard_similarity(&tokenize(&candidate.body), &tokenize(&existing.body));
        if body_similarity > 0.75 {
            return DedupResult::Superseded { existing: existing.number, similarity: body_similarity };
        }
    }
    DedupResult::Unique
}
```

### 3.6 Auto-Generation Cadence Limiter

The coordinator's issue-generation rate is bounded to at most one
coordination-maintenance issue per 48-hour window (2 issues per 48 hours
allows for urgent creation while preventing unbounded growth).

```
struct CadenceLimiter {
    last_issue_at: Option<DateTime<Utc>>,
    window: Duration,           // 48 hours
}
```

---

## 4. Tradeoffs

### 4.1 Design-Sealed → Deferred-Implementation Strategy

**Tradeoff**: All 17 services are design-sealed but only 3 lanes have
implemented source. This maximizes parallel design completion at the cost of
deferred implementation risk.

| Dimension | Benefit | Cost |
|-----------|---------|------|
| Design velocity | Complete picture of inter-service contracts before implementation begins | Interface drift risk: sealed designs may diverge from evolving crate APIs |
| Coordination clarity | Single source of truth for each service contract | Long tail of deferred wire-up issues (14 services, est. 10k+ lines) |
| Worker parallelism | Multiple lanes advance independently | No end-to-end integration feedback until wire-up produces running code |

current crate APIs before coding begins. This gate catches interface drift
at wire-up time rather than letting it accumulate silently.

### 4.2 Two-Phase Cleanup (O(1) Enqueue, Budgeted Background)

**Tradeoff**: Synchronous operations accept O(1) amortized cost by deferring
actual space reclamation to a background `IncrementalJob`.

**Benefit**: Minimal latency on the hot data path (write, unlink, truncate,
rename). The critical section holds only queue insert.

**Cost**: Space pressure under high churn — the ENOSPC signal can fire even
when reclaimable space exists in deferred queues. A stale window exists
between enqueue and reclamation.

**Mitigation**: Pressure-driven priority boost accelerates Phase 2 processing
when free space falls below threshold (PC-006 `ENOSPC` contract).

### 4.3 Deterministic Models vs. Networked Runtime

**Tradeoff**: P8-03 crates implement deterministic placement/recovery models
that are correct by construction but do not exercise network I/O.

**Benefit**: All placement logic verified in isolation. Reproducible test

**Cost**: The gap between deterministic correctness and networked correctness
is not yet bridged. Cross-node state machine advancement and 3-node
bootstrapping remain untested.

**Mitigation**: The deterministic simnet provides a step toward bridging this
gap by simulating multi-node execution in a deterministic harness.

### 4.4 Serial Surface Contention Model

**Tradeoff**: Two files (`crates/tidefs-local-filesystem/src/lib.rs` and
`crates/tidefs-local-object-store/src/lib.rs`) are designated serial write
surfaces — only one active issue may edit each at a time.

**Benefit**: Eliminates merge conflicts on the two most-edited files. Forces
narrow issue decomposition. The claim barrier (`codex:claimed` label) is
the coordination primitive.

**Cost**: Throughput bottleneck. A 2-line fix waits behind a 200-line refactor.
Issues must be split more finely than natural decomposition warrants.

**Mitigation**: Priority dequeue (3.4) schedules in dependency order.
explicit carve-outs and may proceed without claiming the serial surface.

### 4.5 Historical Coordinator Auto-Generation vs. Manual Triage

**Tradeoff**: The historical pipeline generated issues from `STATUS.md` to keep
then-current roadmap entries synchronized, but that model risked proliferating
near-duplicate issues.

**Benefit**: In that historical model, every `STATUS.md` entry had a
corresponding issue and the design pipeline was mirrored in Forgejo.

**Cost**: Unbounded issue growth. Worker confusion from near-identical issues.
Signal dilution makes genuine `codex:ready` issues harder to find.

**Mitigation**: Cadence limiter (3.6). Deduplication gate (3.5). Superseded
coordination issues are closed immediately upon detection.

---

## 5. Lane Status as of 2026-05-05

| Lane | Maturity | Active claims | Ready | Blocked | Stale | Health |
|------|----------|---------------|-------|---------|-------|--------|
| Cleanup/Reclaim | implemented-source | 0 | 2 | 0 | 0 | 0.74 |
| Spacemap/Pool Allocator | G1 implemented, G2+ deferred | 1 (#1694) | 1 | 0 | 0 | 0.68 |
| P8-03 Distributed Runtime | 9/9 canonical crates | 0 | 3 | 0 | 0 | 0.62 |
| Coordination (docs) | active | 1 (#1953) | 2 | 0 | 3 | 0.60 |
| **Pipeline aggregate** | — | 2 | 8 | 0 | 3 | **0.66** |

---

## 6. Roadmap Priorities (Q2 2026)

### Phase 1: Maintenance (current)
- Close stale `codex:needs-review` items (>30 days)
- Close duplicate coordination issues
- Preserve this review as historical input; use GitHub issues, pull requests,
  `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`, and `docs/INDEX.md` for current
  coordination and doc-authority status.
- Reduce coordinator auto-generation cadence

### Phase 2: Critical
- ENOSPC pressure response for cleanup/reclaim queues
- Live refcount delta production pipeline
- Correctness-blocking bug fixes

### Phase 3: Core
- Spacemap G2+ multi-device coordination
- `BackgroundReclaim` integration test coverage
- Automatic journal cleaning under space pressure

### Phase 4: Spacemap
- Multi-device weighted allocation
- Class-aware device placement
- Pressure-driven space rebalancing

### Phase 5: Distributed
- 3-node cluster bootstrapping
- Cross-node state machine advancement
- Networked replication transport hardening
- Deterministic simnet protocol correctness testing

### Phase 6: Production
- QEMU-based distributed runtime testing
- Performance characterization
- Crash certification for distributed paths

---

## 7. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Serial-surface bottleneck | Medium | High | Narrow issue decomposition; explicit claim barrier |
| Cleanup/reclaim stall under ENOSPC | Medium | High | Pressure-driven priority boost (Phase 2) |
| Coordinator issue proliferation | Medium | Medium | Cadence limiter + dedup gate; close stale items |
| Stale `needs-review` accumulation | Medium | Medium | 30-day auto-escalation or close |
| Dependency DAG deadlock | Low | Medium | DAG is acyclic by construction |

---

## 8. References

- `docs/design/coordination-pipeline-cluster-services-design-seal.md` — #1738 design phase seal
- `docs/design/coordination-review-roadmap-priorities-update.md` — #1914 prior review
- `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` — current authority classification for imported docs; classifies this roadmap as historical input
- `docs/INDEX.md` — current documentation entry points and authority scoping
- `docs/CURRENT_VS_FUTURE_CAPABILITIES.md` — deferred production gates
- `docs/design/dataset-lifecycle-state-machine.md` — #1903 design seal
- `docs/design/shard-groups-replicas-rebake-design-spec.md` — #2030/#1964 shard/replicas/rebake
- `docs/design/scrub-deep-scrub-repair-resilver-orchestration-design.md` — #2055 scrub/repair
- `docs/design/background-service-framework-design.md` — background service framework
- `docs/design/incremental-job-core-types-crate-design.md` — IncrementalJob core types
- `docs/design/unified-cache-lattice-views.md` — #1988 cache lattice
- `docs/design/pool-import-export-device-topology-management.md` — #1944 pool import/export
- `docs/design/deterministic-cluster-simnet-protocol-correctness-testing.md` — simnet design
- `docs/THREE_CONTRACT_ARCHITECTURE.md` — architecture contracts
- `docs/MODULE_OWNERS_INVARIANTS_PC002.md` — module ownership and invariants

---

**Coordination pipeline health review #1953 complete.** Since the #1914 review:

- Shard groups/replicas/rebake reached design-sealed status (#1964)
- Scrub/deep-scrub/repair/resilver orchestration design updated (#2055)
- Pool import/export design sealed (#1944)
- Unified cache lattice views design sealed (#1988)
- Background service framework coordination confirmed (#2028/#2001)
- Dataset lifecycle state machine implementation confirmed — Phases 1,2,6 implemented (#1989/#1937/#1938)
- IncrementalJob core types crate design sealed (#1930)
- The 3 active implementation lanes remain unchanged: cleanup/reclaim, spacemap/pool allocator, and P8-03 distributed runtime
- No new blocked work or design gaps have emerged
- Pipeline health score: 0.66 (stable)
