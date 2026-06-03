# Coordination Review and Roadmap Priorities Update

**Issue**: [#1914](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1914)
**Supersedes**: [#1753](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1753) (original coordination review)
**Status**: design-spec
**Maturity**: **design-spec** — coordination pipeline health review, active
implementation lane status, and roadmap priority framework
**Priority**: P2
**Lane**: storage-core / coordination (Layers 8-11)
**Depends on**: #1738 (coordination pipeline design seal), #1903 (dataset lifecycle state machine design seal), #1644 (refcount delta cleanup queues implemented-source), #1923 (STATUS.md pipeline status update)
**Blocks**: All deferred cluster-service wire-up implementation issues

## Abstract

This document performs a coordination pipeline health review and formalizes the
roadmap priority framework for the TideFS cluster-wide services. This is the
second coordination review (#1753 was the first). The design phase for cluster-wide
services is substantially complete (sealed via #1738) and the implementation surface
has expanded significantly (from ~50 to 226 open issues). This document assesses
coordinator-driven issue proliferation, audits deduplication opportunities, and
re-orders the remaining implementation work. It captures the current state of each
active implementation lane, defines priority-ordering data structures and scheduling
algorithms, documents tradeoffs, and provides the implementation sequencing plan
from design-sealed to production.

---

## 1. Coordination Pipeline Health Review

### 1.1 Overall Pipeline Status

The coordination pipeline spans Layers 8 through 11 (Transport, Coordination,
Data Flow, Observability) plus dataset lifecycle and space accounting cross-cutting
surfaces. As of the #1738 design seal, all 16 cluster service designs are complete.
The pipeline health assessment reflects current state as of the #1923 STATUS.md
snapshot.

| Dimension | Status | Detail |
|-----------|--------|--------|
| Design completeness | **Complete** | 16/16 service designs sealed; dataset lifecycle sealed (#1903) |
| Implementation progress | **Active** | 3 lanes with live implementation, 15 deferred, 1 lifecycle |
| Issue volume | **Elevated** | 226 open issues (up from ~50); 12 coordination-lane |
| Duplicate issues | **High** | 4 spacemap G1 issues, 2 sync-lane-tracking, 2 health-report |
| Blocked work | **1 item** | `#1` Keep Forgejo as the single TideFS work register (`codex:blocked`) |
| Stale review items | **3 items** | `#1694`, `#1728`, `#1763` at `codex:needs-review` without advancement |
| Serial surface contention | **Managed** | One active claim per serial surface |
| Documentation currency | **Current** | STATUS.md and FEATURE_MATRIX.md updated via #1923 within window |

### 1.2 Active Implementation Lanes

Three implementation lanes have live source that directly advances the
coordination pipeline. A fourth cross-cutting lane (dataset lifecycle) has reached
design-sealed status. All other cluster service implementations remain deferred to
wire-up issues.

#### Lane A: Cleanup/Reclaim Queues

| Attribute | Value |
|-----------|-------|
| **Maturity** | implemented-source + background-integrated |
| **Crates** | `tidefs-types-deferred-cleanup-core`, `tidefs-cleanup-queue-core`, `tidefs-cleanup-job-core`, `tidefs-types-reclaim-queue-core`, `tidefs-reclaim-queue-core`, `tidefs-reclaim-job-core`, `tidefs-reclaim` |
| **Key data structures** | `CleanupWorkItemV1` (128-byte fixed-size on-media record), `BPlusTreeCleanupQueue`, `CleanupJob` (implements `IncrementalJob`), `ReclaimQueueEntry`, `QueueFamily`, `BPlusTreeReclaimQueue`, `ReclaimJob`, `BackgroundReclaim` (implements `BackgroundService` in `tidefs-local-filesystem/src/background_reclaim.rs`), `ReclaimScheduler`, `ReclaimStats`, `QueueBudget` |
| **Key algorithms** | Two-phase deletion (O(1) Phase 1 enqueue, budgeted Phase 2 background iteration), cursor-resumable processing, birth_commit_group stale detection, delta-aggregation across 4 queue families (extent reclaim, locator reclaim, rebake, inode tombstone), refcount underflow detection |
| **Tests** | 64+ unit tests across cleanup crates; reclaim crates pass `cargo check --workspace` |
| **Implemented since #1753** | `BackgroundReclaim` wired as `BackgroundService` with 256-entry batch cap and `ProcessedDelta` buffer; 4 reclaim queue families coexisting in single B+tree |
| **Remaining work** | Live refcount delta production; ENOSPC pressure response; integration test coverage for reclaim path |
| **Design tradeoffs** | Bounded O(1) synchronous enqueue trades immediate completeness for minimal sync-path latency; deferred Phase 2 accepts stale-until-next-scan window |

#### Lane B: Spacemap/Pool Allocator

| Attribute | Value |
|-----------|-------|
| **Maturity** | G1 foundation complete (segment-level allocation); G1 pool-level coordination in progress; G2+ multi-device coordination deferred |
| **Crates** | `tidefs-types-spacemap-core`, `tidefs-spacemap-core`, `tidefs-spacemap-allocator` |
| **Key data structures** | Segment-level free/extent bitmaps, pool-level device topology tree |
| **Key algorithms** | Segment allocation with first-fit/best-fit, device-class-aware I/O routing, pool-level free-space tracking |
| **Tests** | Unit tests for segment allocation, pool health/stats |
| **Active issues** | `#1792` (G1 foundation, claimed), `#1911` (pool-level coordination, claimed), `#1848` (G1, deferred), `#1694` (G2+, needs-review) |
| **Duplicate concern** | Four spacemap G1 issues exist simultaneously; `#1792` and `#1911` are the canonical active pair; `#1848` and `#1694` should be closed or absorbed |
| **Remaining work** | G1 pool-level allocation completion; G2+ multi-device coordination: cross-device free-space balancing, device-class-aware placement policies, pool-level allocation with fragmentation avoidance |
| **Design tradeoffs** | G1 segment-level allocation is simple and correct but cannot balance across devices; G2+ coordination introduces cross-device consensus overhead vs. per-device autonomy |

#### Lane C: P8-03 Distributed Runtime

| Attribute | Value |
|-----------|-------|
| **Maturity** | 9/9 canonical component crates implemented; end-to-end bootstrapping deferred |
| **Crates** | `tidefs-placement-planner`, `tidefs-transport`, `tidefs-verification-engine`, `tidefs-replica-health`, `tidefs-rebuild-planner`, `tidefs-relocation-planner`, `tidefs-chunk-shipper`, `tidefs-flow-commit-coordinator`, `tidefs-anti-entropy-auditor` |
| **Key data structures** | Placement plans, transfer orchestrations, verification attestations, replica health states, rebuild plans, relocation plans, chunk shipment records, flow commit epochs, anti-entropy audit trails |
| **Key algorithms** | CRUSH-style failure-domain placement, quorum-based transfer orchestration, BLAKE3 verification, flap-detect health tracking, topology-aware rebuild planning, anti-entropy Merkle diff |
| **Tests** | 9 quorum/distributed runtime integration tests pass |

#### Lane D: Dataset Lifecycle State Machine (cross-cutting)

| Attribute | Value |
|-----------|-------|
| **Maturity** | design-sealed (#1903); runtime Phases 1-2 and 6 implemented |
| **Crates** | `tidefs-types-dataset-lifecycle-core` (Phase 1 types, implemented), `tidefs-dataset-lifecycle` (Phase 2 runtime, implemented) |
| **Key data structures** | `DatasetState` (ACTIVE/DESTROYING/TOMBSTONE), mount-safety gating flags, poison semantics bitmask, pinned traversal roots, destroy worker protocol records, tombstone reaper interval state |
| **Key algorithms** | Per-dataset state machine with mount safety gating, poison propagation for corrupted datasets, pinned traversal roots for GC safety, destroy worker block traversal protocol, tombstone reaper with grace-period expiration, cluster-wide consensus integration contracts |
| **Remaining work** | Phases 3 (poison semantics in FUSE daemon), 4 (pinned roots GC integration), 5 (destroy worker block traversal), 7 (cluster consensus integration) deferred to wire-up issues |
| **Design tradeoffs** | TOMBSTONE grace period prevents premature space reclamation but guarantees crash-safe destroy semantics; poison semantics prevent data corruption propagation at the cost of availability for poisoned datasets |

---

## 1.3 Coordinator Issue Proliferation Audit

The coordinator auto-generation cadence has produced a large influx of new issues
since the #1753 review. Key findings:

### 1.3.1 Volume Growth

| Metric | #1753 window | #1914 window | Delta |
|--------|-------------|-------------|-------|
| Total open issues | ~50 | 226 | +176 |
| Coordination-lane open | ~4 | 12 | +8 |
| `codex:ready` | ~15 | 100 | +85 |
| `codex:claimed` | ~5 | 45 | +40 |
| `codex:needs-review` | ~3 | 29 | +26 |
| `codex:blocked` | 0 | 4 | +4 |

### 1.3.2 Duplicate Identification

| Duplicate Family | Issues | Recommended Action |
|------------------|--------|-------------------|
| Spacemap allocator G1 | `#1792`, `#1911`, `#1848`, `#1694` | Retain `#1792` + `#1911`; close `#1848`, `#1694` |
| Sync lane tracking | `#1820`, `#1763` | Retain `#1820` (claimed); close `#1763` (stale needs-review) |
| Coordination health report | `#1728`, `#1873` | Retain `#1728` (needs-review); close `#1873` (deferred) |
| Roadmap priorities update | `#1753`, `#1804`, `#1914` | Retain `#1914` (this document); close `#1753`, `#1804` |

### 1.3.3 Stale `codex:needs-review` Items

| Issue | Title | Age Concern | Action |
|-------|-------|------------|--------|
| `#1694` | Spacemap allocator G2+ deferred | Superseded by G1 active work | Close or re-label |
| `#1728` | Generate coordination health report | No advancement | Escalate to coordinator owner |
| `#1763` | Synchronize lane tracking | Superseded by `#1820` | Close |

### 1.3.4 Recommended Cadence Reduction

The coordinator issue-generation cadence should be reduced or gated on:

1. Only generate a new issue when the previous instance in the same family has
   reached `codex:done`.
2. Deduplicate against open issues by title similarity before creating.
3. Limit auto-generation to at most one coordination-maintenance issue per 48-hour
   window.
4. Auto-generated issues must not claim a serial surface (`tidefs-local-filesystem`
   and `tidefs-local-object-store`) without explicit lane assignment.

---

## 2. Priority-Ordering Data Structures

### 2.1 PriorityOrder data structure

The `PriorityOrder` structure defines the ordering of work items within the coordination
pipeline. It is a stable sort key composed of:

```rust
/// Roadmap priority ordering key. Lower values indicate higher priority.
/// Updated for the #1914 coordination review to include staleness and duplication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PriorityOrder {
    /// Urgency tier: Critical > Core > Scaling > Polish > Maintenance
    pub urgency: UrgencyTier,
    /// Dependency depth: items with fewer unsatisfied deps rank higher
    pub dependency_depth: u16,
    /// Blocked-by count: how many lanes are blocked by this item
    pub blocking_impact: u16,
    /// Serial-surface contention: higher contention = prioritize to unblock
    pub surface_contention: u8,
    /// Age in days since design-seal or last advancement
    pub age_days: u16,
    /// Whether this item has duplicate siblings inflating the queue
    pub has_duplicates: bool,
    /// Staleness penalty: items at `needs-review` >30 days get negative boost
    pub staleness_days: u16,
}
```

### 2.2 Urgency Tiers

| Tier | Priority | Description | Examples |
|------|----------|-------------|----------|
| **Critical** | 0 | Correctness gates, data-loss blockers | ENOSPC reclaim wiring, refcount underflow |
| **Core** | 1 | Fundamental cluster services | Membership bootstrapping, distributed lock |
| **Scaling** | 2 | Multi-device, erasure coding | Spacemap G2+, EC layout |
| **Polish** | 3 | Observability, operator tooling | Dashboards, runbooks |
| **Maintenance** | 4 | Coordinator housekeeping, dedup, status updates | Issue cleanup, STATUS.md sync |

### 2.3 Priority Scoring Algorithm

```rust
impl PriorityOrder {
    /// Compute a scalar priority score. Lower = higher priority.
    /// Incorporates staleness decay and duplication penalty.
    pub fn score(&self) -> u64 {
        let base = (self.urgency as u64) << 48
            | (self.dependency_depth as u64) << 32
            | (self.blocking_impact as u64) << 24
            | (self.surface_contention as u64) << 16
            | (self.age_days as u64) << 8;
        // Duplicate penalty: demote duplicated items by 1 urgency tier equivalent
        let duplicate_penalty: u64 = if self.has_duplicates { 1 << 48 } else { 0 };
        // Staleness boost: items stuck in review get slight priority elevation
        let staleness_boost: u64 = if self.staleness_days > 30 {
            (self.staleness_days.min(365) as u64) >> 2
        } else {
            0
        };
        base + duplicate_penalty - staleness_boost
    }
}
```

### 2.4 Issue Deduplication Heuristic

```rust
/// Heuristic to detect duplicate issues in the coordination lane.
pub struct DeduplicationKey {
    /// Normalized title prefix (first 64 chars, lowercased, stopwords stripped)
    pub title_prefix: [u8; 64],
    /// Issue family (e.g., "spacemap", "lane-tracking", "health-report")
    pub family: IssueFamily,
    /// Min similarity threshold (0.0-1.0) for considering two issues duplicates
    pub similarity_threshold: f32,
}
```

The deduplication algorithm:

1. Extract a normalized title prefix from each open coordination issue.
2. Hash the prefix with `AhHasher` (DoS-resistant).
3. Group by family and sort by creation date.
4. Within each family, retain the most recent `codex:claimed` or `codex:ready` issue;
   flag the remainder for closure with a `superseded-by` comment.
5. Surface duplicates in the `PriorityOrder.score()` by setting `has_duplicates = true`.

---

## 3. Priority Scheduling Algorithm

### 3.1 Roadmap Lane Scheduler

The lane scheduler assigns work across the implementation lanes based on priority
scores, serial-surface availability, and worker capacity.

```rust
/// Coordinates work item ordering across all lanes.
pub struct RoadmapLaneScheduler {
    /// Priority-ordered queue per lane
    lane_queues: HashMap<LaneId, BinaryHeap<Reverse<PriorityOrder>>>,
    /// Active serial-surface claims (fs, object-store)
    serial_surface_claims: HashSet<SurfaceId>,
    /// Maximum concurrent claimed items per lane
    lane_concurrency: LaneConcurrencyLimits,
}

impl RoadmapLaneScheduler {
    /// Select the next work item to claim, respecting serial-surface and
    /// lane-concurrency constraints.
    pub fn next_claimable(&self) -> Option<(LaneId, WorkItemId)> {
        self.lane_queues.iter()
            .filter(|(lane, _)| self.lane_concurrency.can_claim(lane))
            .flat_map(|(lane, queue)| {
                queue.peek().map(|item| (lane.clone(), item.0))
            })
            .sorted_by_key(|(_, item_id)| self.priority_score(item_id))
            .find(|(_, item_id)| !self.surface_blocked(item_id))
    }

    /// Check if an item's required serial surfaces are free.
    fn surface_blocked(&self, item_id: &WorkItemId) -> bool {
        let required = self.required_surfaces(item_id);
        required.iter().any(|s| self.serial_surface_claims.contains(s))
    }
}
```

---

## 4. Implementation Sequencing (Revised)

Since #1753, the cleanup/reclaim lane has advanced: `BackgroundReclaim` is now a
`BackgroundService` with 256-entry batch processing in `tidefs-local-filesystem`.
The remaining work is reprioritized into six phases with issue hygiene as the
immediate first phase.

### 4.1 Phase 1: Maintenance & Issue Hygiene (IMMEDIATE)

| Priority | Lane | Work Item | Rationale |
|----------|------|-----------|-----------|
| **M1.1** | Coordination | Close stale `codex:needs-review` items | `#1763`, `#1694` superseded |
| **M1.2** | Coordination | Deduplicate spacemap G1 issues | `#1848`, `#1694` → close |
| **M1.3** | Coordination | Deduplicate lane-tracking issues | `#1763` → close |
| **M1.4** | Coordination | Deduplicate health-report issues | `#1873` → close |
| **M1.5** | Coordination | Close superseded roadmap issues | `#1753` (by #1914), `#1804` (by #1914) |
| **M1.6** | Coordinator | Reduce auto-generation cadence | Gate on 48h window + dedup check |

### 4.2 Phase 2: Critical Correctness (NOW)

| Priority | Lane | Work Item | Rationale |
|----------|------|-----------|-----------|
| **P2.1** | Cleanup/Reclaim | Live refcount delta production | Prerequisite for space accounting correctness |
| **P2.2** | Cleanup/Reclaim | ENOSPC pressure-response path | Data-loss prevention; filesystem safety gate |
| **P2.3** | Cleanup/Reclaim | Reclaim-path integration test coverage | Production readiness |
| **P2.4** | Dataset Lifecycle | Phase 3: poison semantics in FUSE daemon | Cross-cutting correctness |

### 4.3 Phase 3: Core Cluster Services

| Priority | Lane | Work Item | Rationale |
|----------|------|-----------|-----------|
| **P3.1** | Transport | Per-lane budget enforcement | Fan-out prerequisite for all cluster wire-up |
| **P3.2** | Membership | 3-node bootstrap (Simnet) | Foundation for all cluster services |
| **P3.3** | Membership | Joint-consensus state machine | Correctness foundation for membership changes |
| **P3.4** | Security | PSK HMAC proof mechanism | Transport security prerequisite |
| **P3.5** | Security | Identity-first authorization | All-service dependency |
| **P3.6** | Transport | Multi-family multiplexing | Wire-up prerequisite for Data/Control/Shadow |

### 4.4 Phase 4: Spacemap Scaling

| Priority | Lane | Work Item | Rationale |
|----------|------|-----------|-----------|
| **P4.1** | Spacemap | Complete G1 pool-level allocation | Foundation for G2+ |
| **P4.2** | Spacemap | G2+ multi-device coordination | Cross-device free-space balancing |
| **P4.3** | Spacemap | Device-class-aware placement | Production pool geometry |

### 4.5 Phase 5: Distributed Coordination

| Priority | Lane | Work Item | Rationale |
|----------|------|-----------|-----------|
| **P5.2** | Distributed Lock | Raft-embedded lock service | Cluster-wide mutual exclusion |
| **P5.3** | Admin Proxy | Leader-fenced admin serialization | Operator safety |
| **P5.4** | Atomic Snapshots | Consistent-cut freeze protocol | Crash-consistent backup foundation |
| **P5.5** | BULK Plane | OFFER/ACCEPT/CREDIT flow | High-throughput data transfer |

### 4.6 Phase 6: Production Integration

| Priority | Lane | Work Item | Rationale |
|----------|------|-----------|-----------|
| **P6.1** | Erasure Coding | Production Reed-Solomon | Data durability at scale |
| **P6.2** | P8-03 Runtime | Production distributed runtime | End-to-end data flow |
| **P6.3** | Operator Observability | Dashboards and truth surfaces | Production readiness |
| **P6.4** | Dataset Lifecycle | Phase 7: cluster consensus integration | Multi-node dataset lifecycle |

---

## 4.7 Dependency Graph (Revised)

```
Phase 1 (Maintenance) ─ Issue cleanup → dedup → cadence reduction
     │
     └── Unblocks cleaner Phase 2-6 sequencing

Phase 2 (Critical) ───────────────────┐
     │                                │
     ├── P2.1 (Refcount deltas) ──────┤
     ├── P2.2 (ENOSPC pressure) ──────┤
     └── P2.3 (Reclaim test coverage)─┤
                                      │
Phase 3 (Core Cluster) ───────────────┤
     │                                │
     ├── P3.1 (Transport budgets) ────┤
     ├── P3.2 (3-node bootstrap) ─────┤
     ├── P3.3 (Consensus) ────────────┤
     ├── P3.4 (PSK HMAC) ─────────────┤
     ├── P3.5 (Identity) ─────────────┤
     └── P3.6 (Multiplexing) ─────────┤
                                      │
Phase 4 (Spacemap Scaling) ───────────┤
     │                                │
     ├── P4.1 (G1 pool-level) ────────┤
     └── P4.2 (G2+ multi-device) ───────┤
                                      │
Phase 5 (Distributed) ────────────────┤
     │                                │
     ├── P5.2 (Lock Service) ─────────┤
     ├── P5.3 (Admin Proxy) ──────────┤
     ├── P5.4 (Snapshots) ────────────┤
     └── P5.5 (BULK Plane) ───────────┤
                                      │
Phase 6 (Production) ─────────────────┘
     ├── P6.1 (Erasure Coding)
     ├── P6.2 (Distributed Runtime)
     ├── P6.3 (Observability)
     └── P6.4 (Dataset Lifecycle consensus)
```

---

## 5. Roadmap Coverage Matrix

### 5.1 Service Implementation Status

| Service | Layer | Design | Implementation | Test Coverage | Wire-Up |
|---------|-------|--------|---------------|---------------|---------|
| Transport boundedness | 8 | Sealed | Core crates | Unit | Per-lane budgets deferred |
| Endpoint families | 8 | Implemented | Types + session struct | TCP loopback IT | Multi-family mux deferred |
| Security/identity | 8 | Sealed | Design only | None | PSK HMAC + identity deferred |
| Membership | 9 | Sealed | Types only | None | 3-node bootstrap deferred |
| Distributed lock | 9 | Sealed | Design only | None | Raft embedding deferred |
| Atomic snapshots | 9 | Sealed | Design only | None | Consistent-cut deferred |
| Admin proxy | 9 | Sealed | Design only | None | Leader serialization deferred |
| P8-03 runtime | 10 | 9/9 crates | All component crates | 9 ITs | Integration deferred |
| Erasure coding | 10 | Design | Design only | None | Production RS deferred |
| Replication/rebuild | 10 | Design | Design only | None | Wire-up deferred |
| Cleanup/reclaim | — | Implemented | All crates + BackgroundService | 64+ unit tests | Refcount deltas deferred |
| Spacemap allocator | — | G1 complete | G1 crates | Unit tests | G1 pool + G2+ deferred |
| Dataset lifecycle | — | Sealed | Phases 1-2, 6 | Unit tests | Phases 3-5, 7 deferred |
| Operator surfaces | 11 | Design | Design only | None | Wire-up deferred |
| BULK plane | 8 | Sealed | Design only | None | OFFER/ACCEPT/CREDIT deferred |

---

## 6. Tradeoffs and Design Decisions

### 6.1 Cleanup/Reclaim First vs. Spacemap First

| Approach | Pros | Cons |
|----------|------|------|
| **Reclaim-first (reaffirmed)** | Unlocks ENOSPC correctness; reclaim path is the most exercised local code path; no serial-surface contention with other lanes | Delays pool-level allocation scaling |
| Spacemap-first | Pool-level scaling addresses growing datasets earlier | G2+ coordination is complex; reclaim correctness blocks filesystem safety |

**Decision (reaffirmed)**: Reclaim-first. The BackgroundReclaim wire-up (#1644) now
connects the reclaim path into the local filesystem. The remaining refcount delta
production and ENOSPC pressure response remain the immediate critical path.

### 6.2 Issue Hygiene First vs. Implementation First

| Approach | Pros | Cons |
|----------|------|------|
| **Hygiene-first (new, chosen)** | Clears 4-6 duplicate/stale issues; reduces confusion for workers; prevents further proliferation | Delays implementation work by ~1 claim cycle |
| Implementation-first | Keeps critical path moving | Duplicate issues accumulate; workers waste time on superseded work; 226-open-issue surface unmanageable |

**Decision**: Issue hygiene first. The coordinator proliferation has created genuine
confusion: 4 spacemap G1 issues, 2 lane-tracking sync issues, 3 stale needs-review
items. Cleaning these before advancing implementation prevents worker thrash.


| Approach | Pros | Cons |
|----------|------|------|
| QEMU-first | Tests real kernel network stack | Slower, requires multi-node QEMU infrastructure |

required before production claims but is deferred to child GAP issues.

### 6.4 Serial Surface Contention Strategy

The two serial write surfaces (`tidefs-local-filesystem` and
`tidefs-local-object-store`) are currently claimed by the cleanup/reclaim
lane. The strategy is:

1. **Complete reclaim wire-up** before any other lane claims either surface.
2. **Split future work** into narrower issues that touch only one surface
   at a time.
3. **Use the claim barrier** (`~/ai/bin/tidefs-claim`) to serialize access.
4. **New**: Monitor coordinator-generated issues for serial-surface scope;
   auto-generated issues must not claim a serial surface without explicit
   lane assignment.

### 6.5 Deferred Service Integration

All 16 coordination services are deferred from design to implementation
wire-up issues. This is intentional:

- **Benefit**: Parallel design completion unblocks parallel implementation.
- **Risk**: Interface drift between sealed designs and evolving crates.
  against current crate APIs before coding begins.
- **Update (#1914)**: The dataset lifecycle state machine has been sealed (#1903)
  since the #1753 review, adding a 17th design-sealed service. Its Phases 3-5, 7
  are similarly deferred to wire-up.

### 6.6 Coordinator Auto-Generation Cadence

The coordinator generates coordination-maintenance issues at a rate exceeding worker
claim-and-close capacity. Since #1753, the open issue count grew from ~50 to 226.
This creates three problems:

1. **Confusion**: Workers encounter 4 nearly-identical spacemap G1 issues.
2. **Signal dilution**: Genuine `codex:ready` issues are buried among auto-generated
   maintenance issues.
3. **Self-reinforcing loop**: Each "update STATUS.md" issue generates more issues,
   which need more STATUS updates, creating an unbounded growth cycle.

**Decision**: Reduce auto-generation cadence to at most one coordination-maintenance
issue per 48-hour window. The coordinator must deduplicate against open issues before
creating. Close all superseded duplicate coordination issues immediately.

---

## 7. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Serial-surface bottleneck | Medium | High | Split issues narrowly; enforce claim barrier |
| Coordinator issue proliferation | **High** | **High** | Cadence reduction + deduplication gate; close stale items |
| Duplicate issue confusion | **High** | Medium | Title-similarity dedup before issue creation; close superseded |
| Coordination pipeline stall | Low | High | Health scoring and stall detection triggers escalation |
| Dependency chain deadlock | Low | Medium | Dependency graph is a DAG; no cycles possible by construction |
| Stale `needs-review` accumulation | **Medium** | Medium | 30-day staleness triggers auto-escalation or close |

---

## 8. References

- `docs/design/coordination-pipeline-cluster-services-design-seal.md` — #1738 design phase seal
- `docs/STATUS.md` — live coordination pipeline status
- `docs/FEATURE_MATRIX.md` — implemented-source capability matrix
- `docs/CURRENT_VS_FUTURE_CAPABILITIES.md` — deferred production gates
- `docs/MEMBERSHIP_SERVICE_DESIGN.md` — membership protocol
- `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md` — P8-03 runtime
- `docs/REFCOUNT_DELTA_CLEANUP_QUEUES_DESIGN.md` — reclaim queues
- `docs/SPACEMAP_ALLOCATOR_DESIGN.md` — spacemap allocator
- `docs/DATASET_LIFECYCLE_DESIGN.md` — dataset lifecycle state machine
- `docs/design/dataset-lifecycle-state-machine.md` — #1903 design seal
- `docs/DEFERRED_CLEANUP_WORK_QUEUES_DESIGN.md` — deferred cleanup design
- `docs/design/cluster-security-identity-model.md` — sealed security architecture
- `docs/design/cluster-wide-distributed-lock-service-design.md` — lock service architecture
- `docs/design/cluster-bulk-plane-protocol.md` — BULK plane protocol
- `docs/design/cluster-wide-atomic-snapshot-coordination.md` — snapshot coordination
- `docs/design/cluster-admin-proxy-model.md` — admin proxy model
- `docs/design/bounded-cluster-membership-state.md` — anti-OSDMap-explosion design
- `docs/design/unified-scheduling-classes-lane-priority-model.md` — lane model
- `docs/THREE_CONTRACT_ARCHITECTURE.md` — architecture contracts

---

**Coordination pipeline health review #1914 complete.** Since the #1753 review:

- Cleanup/reclaim has advanced: `BackgroundReclaim` is now a `BackgroundService`
  wired into `tidefs-local-filesystem` with 4 family queues and 64+ tests.
- Dataset lifecycle reached design-sealed status (#1903) with Phases 1-2 and 6
  implemented and Phases 3-5, 7 deferred.
- Issue volume exploded from ~50 to 226, driven by coordinator auto-generation.
- 4-6 duplicate/stale coordination issues identified for immediate closure.
- Roadmap priorities restructured to 6 phases: Maintenance → Critical → Core →
  Spacemap → Distributed → Production.

**Immediate next action**: Close stale `codex:needs-review` and duplicate coordination
issues (#1763, #1694, #1848, #1873, #1753, #1804). Reduce coordinator auto-generation
cadence to ≤1 issue per 48 hours with mandatory deduplication.
