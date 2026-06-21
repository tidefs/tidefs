# Scrub, Deep Scrub, Repair, and Resilver Orchestration Design

Maturity: **design-spec** — Rust implementation deferred to wire-up issues; definitive implementation plan in §18.
Scrub, deep scrub, repair, and resilver orchestration design: architecture,
data structures, algorithms, scheduling integration, and tradeoff analysis.
All four services are specified as BackgroundService implementations within
the distributed P8-03 data-flow infrastructure: the continuous failure recovery
loop (#901), replica-health tracker (#895), rebuild planner (#893), placement
planner (data_copy_0), chunk shipper (data_copy_6), flow-commit coordinator
(data_copy_7), and anti-entropy auditor (data_copy_8).
Scrub/repair/resilver findings flow through canonical P8-03 loss-event →
rebuild-flow → transfer-verify-place chains rather than ad-hoc local paths.

Claim boundary: this is target-design material for distributed integrity
services. ZFS/Ceph comparisons, RTO/RPO tables, failure-isolation language, and
coverage statements below are design intent and validation requirements, not
current performance, durability, availability, or successor evidence.
Product-facing comparison wording still requires #875 claim ids and #928/#930
comparator evidence.

This revision (#1766) consolidates the architecture, data structures, algorithms,
and tradeoff analysis for all four services and closes Forgejo issue #1766.
Prior iterations: #1705, #1739, #1757, #1836, #1837, #1841, #1885, #1913, #1917, #1948,
#1957, #1965, #2055.

### Revision History

| Issue | Date | Change |
|-------|------|--------|
| #1837 | 2026-05 | Design-spec maturity confirmed; all four services specified as BackgroundService implementations with independent budgets, priority staging, and validity-token gating; Rust implementation deferred to wire-up issues |
| #1917 | 2026-04 | Initial P8-03 distributed integration design |
| #1757 | 2026-05 | Refined distributed rebuild/recovery integration; CascadingFailureGuard algorithmic formalization; recovery time objective (RTO/RPO) analysis; network partition handling during distributed recovery; consolidated duplicated §2.9 |
| #1948 | 2026-05 | Anti-entropy auditor detail, placement-to-flow bridging, distributed consistency model |
| #1965 | 2026-05 | Canonical orchestration consolidation; frozen cross-service data structures with type contracts; SuspectLog as coordination surface; per-domain CascadingFailureGuard; service lifecycle state machine with 7-phase recovery; determinism guarantees for witness-set construction; unified integrity event bus |
| #1957 | 2026-05 | Refined distributed rebuild/recovery integration architecture; consolidated cross-service data structures with frozen type contracts; cascading-failure guard algorithmic analysis; four-service tradeoff matrix; anti-entropy auditor convergence proof sketch; repair source-selection determinism guarantees; resilver staged-rebuild priority escalation formalization |
| #2055 | 2026-05 | Full distributed rebuild/recovery pathway integration; frozen data structures; deferred Rust implementation plan (§18); cascading-failure guard saturation analysis; witness-set construction determinism; end-to-end integrity chain with COMMIT_GROUP-write-barrier formalization |
| #1766 | 2026-05 | Consolidated design-spec revision: unified architecture, frozen data structures, algorithms, scheduling integration, and tradeoff analysis for all four integrity services; deduplicated revision table; clarified P8-03 distributed integration rationale; prepared for wire-up issues |

## 1. Motivation

Data integrity at scale requires four distinct but coordinated background
services:

| Service | Trigger | Purpose |
|---------|---------|---------|
| **Scrub** | Periodic (scheduled) | Verify checksums on all stored data |
| **Deep Scrub** | Periodic (less frequent) | Reconstruct from shards; detect silent corruption undetectable by single-replica checksums |
| **Repair** | On-read error or scrub finding | Restore redundancy from healthy replicas |
| **Resilver** | Device replacement or membership change | Restore full redundancy across new topology |

ZFS combines these into a single `dsl_scan` with a sequential tree-ordered
pass, which means scrub and resilver compete for the same IO budget and
cannot be separately prioritized. Ceph scatters them across per-PG scrub,
per-OSD backfill, and per-PG deep scrub—three separate systems with no
unified resource model.

The target TideFS design unifies all four under the background service framework
(`docs/design/background-service-framework-design.md`, #1549), with
independent per-service budgets, priority staging, validity-token
stale-task prevention, and comprehensive observability.

### Dependency Map

| Design | Relationship |
|--------|-------------|
| #1549 Background service framework | All four services implement `BackgroundService` |
| #1564 End-to-end checksum architecture | Scrub/repair verify `IntegrityTrailerV2` (BLAKE3-256); repair clears suspect entries |
| #1249 Erasure coding and placement | Deep scrub and repair use reconstruction for shard-level recovery |
| #1286 Shard groups and replicas | Repair selects source replicas; resilver places new replicas |
| #1254 Pool topology management | Resilver schedules placement across new topology |
| #1180 Refcount delta cleanup | Data cleaner may trigger verification on unlinked blocks |
| #110 Verified non-mutating online verifier | OW-110 offline verifier; scrub is the online/mutating companion |
| `docs/design/end-to-end-checksum-architecture.md` | Defines `IntegrityTrailerV2`, BLAKE3-256 domain separation |
| `docs/design/shard-groups-replicas-rebake-pathway.md` | Source-selection and rebake machinery |
| #895 Distributed replica-health tracker | `ReplicaHealthTracker` (2378 lines) with per-chunk health, flap detection, adaptive timeouts, dual-source lag tracking — authoritative health surface for repair/resilver decisions |
| #893 Rebuild planner | `RebuildPlanner` (2495 lines) with 6-state rebuild flow, loss-event scoping, witness-set batch scheduling — execution engine delegated to by repair and resilver |
| #893 Rebuild planner | `RebuildPlanner` (2495 lines) with 6-state rebuild flow, loss-event scoping, witness-set batch scheduling — execution engine delegated to by repair and resilver |
| #901 Continuous recovery loop | 5-phase `RecoveryLoop` (849 lines) with `RecoveryThrottle` — composes health tracker, rebuild planner, transfer orchestrator, and flow commit coordinator |
| `tidefs-placement-planner` | `compute_replica_target_set()` — authoritative replica target selection with anti-affinity; used by repair and resilver for new-replica placement |
| `tidefs-chunk-shipper` (P8-03 data_copy_6) | Deterministic chunk staging, streaming, and receipt emission; RDMA/uring/TCP transport selection |
| `tidefs-flow-commit-coordinator` (P8-03 data_copy_7) | Bridges verification pipeline to rebuild/relocation/replication flow state machines; transfer→verify→place receipt chain |
| `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md` | Replication, rebuild, and relocation data flow contracts |

### 1.1 Distributed Integration Rationale

Prior iterations of this design treated repair as a local operation:
read from a healthy source, write to a degraded target. For distributed
deployments, this approach fails because:

- **Failure-domain blindness.** A local repair may choose a source in the
  same rack as the corrupt target, leaving data vulnerable to a top-of-rack
  switch failure.
- **No receipt backing.** Without transfer and verification receipts, the
  repaired replica has no authoritative proof of correctness.
- **No capacity planning.** Local repair cannot reserve space, bandwidth, or
  IOPs across nodes; it may overload a hot target.
- **No health propagation.** Repairing a corrupt chunk without updating
  `ReplicaHealthTracker` leaves other nodes unaware that the chunk was
  degraded and has now been repaired.
- **No anti-entropy verification.** Without the anti-entropy auditor
  (`data_copy_8`), a locally repaired replica may be stale or divergent.

By routing all integrity findings through the P8-03 distributed infrastructure,
the target design requires every repaired replica to be failure-domain-aware,
receipt-backed, capacity-admitted, health-propagated, and anti-entropy-verified.

### 1.2 Mapping to P8-03 Canonical Data-Flow Classes

The four integrity services map to P8-03 canonical data-flow classes
(`docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md` §2):

| Integrity Service | Primary P8-03 Class | Trigger |
|---|---|---|
| **Scrub** | `data_flow_1.catchup_repair` | Checksum mismatch → suspect entry → catchup from healthy source |
| **Deep Scrub** | `data_flow_1.catchup_repair` or `data_flow_2.loss_rebuild` | Shard divergence → suspect all shards → rebuild from known-good witnesses |
| **Repair** | `data_flow_2.loss_rebuild` | Explicit corruption event → loss-scoped rebuild flow with witness sets |
| **Resilver** | `data_flow_2.loss_rebuild` or `data_flow_4.policy_relocation` | Device loss → rebuild; device addition → policy relocation for rebalancing |

All flows are receipt-backed per P8-03 §1 core law #7: "A target replica is
not considered live until digest / witness / range verification succeeds and a
verification receipt is emitted."

### 1.3 Priority Escalation: Local → Distributed

When integrity service findings cross the local → distributed boundary,
priority propagates through explicit enum mapping:

```
Local (BackgroundServicePriority)      Distributed (P8-03 RebuildPriority)
─────────────────────────────────      ────────────────────────────────────
RepairService::Critical (0.40)    →    RebuildPriority::CorruptionDetected (5)
  (loss of redundancy)                   RecoveryPriority::LossRebuild (2)

DeepScrubService::Throughput (0.15)→    RebuildPriority::CorruptionDetected (5)
  (silent shard corruption found)        RecoveryPriority::LossRebuild (2)

ResilverService::Critical▲          →    RebuildPriority::NodeFailure (2)
  (device loss, replicas ≤ threshold)    RecoveryPriority::LossRebuild (2)

ResilverService::Throughput (0.15) →    RebuildPriority::DiskFailure (3)
  (device addition, rebalancing)         RecoveryPriority::CatchupRepair (1)

ScrubService::Throughput (0.15)    →    RebuildPriority::SuspectUnreachable (4)
  (checksum mismatch found)              RecoveryPriority::CatchupRepair (1)
```

The `RecoveryLoop::RecoveryThrottle` dynamically adjusts admission based on
client latency p50, ensuring recovery never starves application IO. The
`CascadingFailureGuard` enforces per-failure-domain and aggregate-cluster
concurrency limits, preventing a single domain from being overwhelmed by
recovery traffic.

## 2. Architecture Overview

### 2.1 Four Services, One Framework

```
┌──────────────────────────────────────────────────────────────────┐
│                     BackgroundScheduler                           │
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │ RepairSvc    │  │ ResilverSvc  │  │ ScrubSvc     │           │
│  │ Critical     │  │ Critical▲    │  │ Throughput   │           │
│  │ (40% budget) │  │ (escalated)  │  │ (15% budget) │           │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘           │
│         │                 │                 │                    │
│  ┌──────┴───────┐         │                 │                    │
│  │DeepScrubSvc  │         │                 │                    │
│  │ BestEffort   │         │                 │                    │
│  │ (10% budget) │         │                 │                    │
│  └──────────────┘         │                 │                    │
│                           │                 │                    │
│  ┌────────────────────────┼─────────────────┼──────────┐        │
│  │     IntegrityEvent Bus │                 │          │        │
│  │  ┌─────────────────────┴─────────────────┴────────┐ │        │
│  │  │  ScrubFinding │ RepairOutcome │ ResilverProgress│ │        │
│  │  └───────────────────────────────────────────────┘ │        │
│  └────────────────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────────────────┘
```

▲ Resilver elevates from Throughput to Critical when remaining replicas ≤
`RESILVER_CRITICAL_THRESHOLD` (default: 1).

### 2.2 Integration with Existing Code

The existing `tidefs-local-filesystem` crate already contains core scrub and
repair logic that the new services build upon:

| Existing Module | Lines | Key Types | New Service | Relationship |
|-----------------|-------|-----------|-------------|-------------|
| `scrub.rs` | 612 | `ScrubBlockId`, `ScrubBlockKind`, `ScrubViolation`, `RepairStrategy` | `ScrubService` | Types reused as stable core; traversal upgraded from inode-loop to `ScrubCursor`-driven |
| `repair.rs` | 633 | `RepairEntry`, `RepairOutcome`, `RepairLog`, `ResolverContext` | `RepairService` | `resolve_violation()`, `apply_repair_entries()` reused; upgraded from local-only to cross-node source selection |

The existing `tidefs-background-scheduler` (1410 lines) provides the scheduling
framework:

| Type | Purpose |
|------|---------|
| `BackgroundService` trait | Interface all four services implement |
| `IncrementalJobAdapter<J>` | Wraps an `IncrementalJob` for scheduler registration |
| `BackgroundScheduler` | Runs tick-driven cycles with budget enforcement |
| `ServiceBudget` | Per-service items/bytes/ops budget |
| `ServicePriority` | `Critical`, `Throughput`, `BestEffort` |
| `TickReport` / `CycleReport` | Per-tick and per-cycle observability |
| `SchedulerStats` | Aggregated scheduling statistics |

The `tidefs-incremental-job-core` crate (992 lines) supplies the `IncrementalJob` trait, `WorkBudget`, `Checkpoint`, `StepResult`, `JobProgress`, and `ServiceCheckpoint` — the cross-cutting contract governing all cursor-driven background work.

The new scrub/repair/resilver services add (local and distributed subsystems):
- **Cursor-based checkpoint/resume** replacing the current linear inode scan
- **BackgroundScheduler integration** via `IncrementalJobAdapter`
- **Cross-node source selection** for repair and resilver, leveraging `tidefs-replica-health` (2378 lines across 8 modules: `tracker`, `flap_detector`, `adaptive_timeout`, `health_state`, `lag`, `suspicion`, `propagation`, `lib`) for `ReplicaHealthTracker`, `ReplicaLagStateRecord`, `ReplicaLagTracker`, `SuspicionLevel`, and adaptive failure detection
- **Deep scrub reconstruction verification** via `tidefs-erasure-coding` (821 lines) using `ErasureShard`, `StripeConfig`, `Reconstruction`, and `reconstruct()`
- **Erasure-coded store integration** via `tidefs-erasure-coded-store` (953 lines)
- **Placement planning** via `tidefs-placement-planner` (P8-03 data_copy_0) for authoritative replica target selection with anti-affinity across failure domains
- **Chunk shipping** via `tidefs-chunk-shipper` (P8-03 data_copy_6) with staged buffer lifecycle, transport path selection (RDMA/uring/TCP), and receipt emission
- **Flow commit coordination** via `tidefs-flow-commit-coordinator` (P8-03 data_copy_7) bridging transfer→verification→placement receipts to rebuild/relocation/replication flow state machines
- **Rebuild planning** via `tidefs-rebuild-planner` (2495 lines) with 6-state rebuild flow (`Open → Planning → Transferring → Verifying → Restored`), loss-event-scoped rebuild, witness-set-driven batch scheduling, and degradation-class propagation
- **Continuous recovery loop** via `tidefs-recovery-loop` (849 lines) with 5-phase cycle (`Detect → Scope → Plan → Execute → Verify`), adaptive `RecoveryThrottle`, and `RecoveryPriority` triage (`SteadyReplication / CatchupRepair / LossRebuild`)

### 2.3 Scheduler Registration

Each service registers with the `BackgroundScheduler` as an
`IncrementalJobAdapter` wrapping a per-service `IncrementalJob`
implementation:

```rust
// In tidefs-scrub-service/src/lib.rs
use tidefs_background_scheduler::{BackgroundScheduler, IncrementalJobAdapter,
                                   ServicePriority};
use tidefs_types_incremental_job_core::IncrementalJob;

pub struct ScrubJob { /* cursor, config, stats */ }
impl IncrementalJob for ScrubJob {
    fn tick(&mut self, budget: ServiceBudget) -> TickReport { /* ... */ }
}

pub fn register_scrub(scheduler: &mut BackgroundScheduler) {
    let adapter = IncrementalJobAdapter::new("scrub", ScrubJob::new())
        .with_priority(ServicePriority::Throughput);
    scheduler.register(Box::new(adapter));
}
```

Budget allocation per tick (from global `ServiceBudget::DEFAULT_TICK`):

| Service | Priority | Budget Fraction | Escalation Rule |
|---------|----------|----------------|-----------------|
| RepairService | Critical | 40% | Always Critical — data loss prevention |
| ResilverService | Throughput → Critical | 15% → 40% | Escalates when replicas ≤ threshold |
| ScrubService | Throughput | 15% | Steady-state; cascade recipient |
| DeepScrubService | BestEffort | 10% | Runs only when higher-priority idle |

Remaining 20% reserved for other background services (cleanup, reclaim, GC).

### 2.4 Health Tracker Integration with Scrub and Repair

The `tidefs-replica-health` crate provides the canonical replica health
surface that feeds scrub and repair decisions:

| Type | Role |
|------|------|
| `ReplicaHealthTracker` (737 lines, `tracker.rs`) | Per-chunk, per-replica health state; dual-source (receipt chains + anti-entropy); adaptive timeouts; flap suppression |
| `FlapDetector` (265 lines, `flap_detector.rs`) | Exponential backoff for flapping nodes; prevents repair cascades on unstable hosts |
| `AdaptiveTimeout` (182 lines, `adaptive_timeout.rs`) | Widens failure detection windows during network instability |
| `ReplicaLagTracker` (206 lines, `lag.rs`) | Computes lag from receipt frontiers; not just heartbeat-based |
| `SuspicionLevel` (198 lines, `suspicion.rs`) | Aggregated per-node suspicion with `PeerHealthObservation` consensus |
| `HealthSummary` / `ReplicaHealthAlert` (160 lines, `propagation.rs`) | Summaries and alerts emitted on state transitions |

**Scrub ↔ Health Tracker Flow:**

```
ScrubFinding (corruption) ──▶ mark_shard_suspect()
                                    │
                                    ▼
                            ReplicaHealthTracker
                            .register_suspect_chunk()
                                    │
                                    ├── updates chunk_health → Degraded
                                    ├── increments node_suspicion
                                    ├── emits ReplicaHealthAlert
                                    │
                                    ▼
                            RepairService.enqueue()
                                    │
                                    ▼
                            RebuildPlanner (if data-loss risk)
```

**Repair ↔ Health Tracker Flow:**

```
RepairOutcome ──▶ ReplicaHealthTracker
                      .clear_suspect_chunk()   (repair succeeded)
                  OR  .escalate_suspect_chunk() (repair failed)
                         │
                         ▼
                  FlapDetector.record_event()
                         │
                         ▼
                  SuspectChunk → Degraded → Loss
```

The health tracker is the **authoritative coordination surface** between the
four integrity services and the distributed rebuild/recovery subsystems.
Scrub discovers; repair heals; the health tracker determines whether the
healing was sufficient and escalates to rebuild when it was not.

### 2.5 Rebuild Planner and Recovery Loop Integration

The `tidefs-rebuild-planner` (2495 lines) and `tidefs-recovery-loop` (849 lines)
form the execution engine that repair and resilver delegate to for
distributed rebuild:

**Rebuild Planner 6-State Flow:**

```
Open ──▶ Planning ──▶ Transferring ──▶ Verifying ──▶ Restored
  │          │            │               │
  └──────────┴────────────┴───────────────┴──▶ BlockedNoSource
                                                BlockedNoTarget
                                                BlockedNoCapacity
                                                Cancelled
```

| Algorithm | Purpose |
|-----------|---------|
| `open_rebuild_flow_from_loss_event()` | Derive rebuild scope from a loss/suspect event; freeze loss scope and degraded class |
| `schedule_rebuild_batches_from_witness_sets()` | Choose source bundles and batch order from available witness members |
| `advance_rebuild_flow_state()` | State machine transition logic |
| `detect_stale_chunks_for_backfill()` | Detect lagged chunks needing catchup |
| `detect_capacity_skew_for_rebalance()` | Detect utilization skew needing rebalancing |

**Recovery Loop 5-Phase Cycle:**

```
Detect ──▶ Scope ──▶ Plan ──▶ Execute ──▶ Verify
   ▲                                            │
   └────────────────────────────────────────────┘
```

| Phase | Responsibility |
|-------|---------------|
| `Detect` | `ReplicaHealthTracker` polls for degraded/lost chunks |
| `Scope` | `LossEvent` classification: `SteadyReplication` → `CatchupRepair` → `LossRebuild` |
| `Plan` | `RebuildPlanner` opens rebuild flows; schedules witness-set batches |
| `Execute` | Transfer orchestrator runs rebuild batches under `RecoveryThrottle` |
| `Verify` | `ResilverService` verifies rebuilt shards; writes integrity trailers |

**RecoveryThrottle**: Adaptive rate limiter that slows recovery when client
latency rises (`client_latency_p50_ms > client_latency_baseline_ms`) and
speeds up when clients are idle. Explicit, not opaque like Ceph mclock weights.

**Integration with Scrub/Repair/Resilver:**

- **ScrubService** emits `ScrubFinding` → health tracker marks chunk suspect → recovery loop detects degradation
- **RepairService** consumes `SuspectLog`, applies repair → health tracker clears or escalates → rebuild planner opens flow if loss risk
- **ResilverService** drives the `Execute` and `Verify` phases for topology-change rebuilds; delegates to `RebuildPlanner` for batch scheduling
- **DeepScrubService** uses reconstruction verification → health tracker can detect shard-level corruption that single-replica checksums miss




### 2.6 End-to-End Distributed Rebuild/Recovery Pathway

The four integrity services (scrub, deep scrub, repair, resilver) operate
within a distributed cluster. When scrub or deep scrub detects corruption,
or when a node/device fails, the **full distributed rebuild/recovery
pathway** executes a coordinated six-subsystem pipeline to restore
redundancy and data integrity across the cluster:

```
┌──────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Scrub/Deep   │───▶│ ReplicaHealth    │───▶│ RebuildPlanner  │
│ Scrub/Node   │    │ Tracker (#895)   │    │ (#893)          │
│ Failure      │    │ flap detection   │    │ loss event→flow │
│              │    │ adaptive timeout │    │ witness→batch   │
└──────────────┘    └──────────────────┘    └────────┬────────┘
                                                     │
                    ┌─────────────────────────────────┘
                    ▼
┌──────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ FlowCommit   │◀───│ ChunkShipper     │◀───│ PlacementPlanner│
│ Coordinator  │    │ (#P8-03 dcp6)    │    │ (#P8-03 dcp0)   │
│ (#P8-03 dcp7)│    │ stage→stream→    │    │ replica target  │
│ transfer→    │    │ receive          │    │ selection       │
│ verify→place │    │ RDMA/uring/TCP   │    │ anti-affinity   │
└──────┬───────┘    └──────────────────┘    └─────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│                   RecoveryLoop (#901)                         │
│  Detect → Scope → Plan → Execute → Verify                    │
│  RecoveryThrottle · CascadingFailureGuard · NodeRecoveryBudget│
└──────────────────────────────────────────────────────────────┘
```

#### 2.6.1 Pipeline Phases

| Phase | Subsystem | Input | Output |
|-------|-----------|-------|--------|
| **Detect** | `ReplicaHealthTracker` | Scrub findings, node/device health events, anti-entropy receipts | `ChunkHealth` state transitions, `ReplicaHealthAlert` |
| **Scope** | `RecoveryLoop` / `LossEvent` | Health alerts, lag records | `LossEvent` with `FlowScopeSelector`, `RebuildDegradedClass` |
| **Plan** | `RebuildPlanner` | `LossEvent`, available members, lag records | `RebuildFlowRecord`, `WitnessSet`, `RebuildBatchRecord[]` |
| **Place** | `PlacementPlanner` | `FailureDomainPlacementPolicy`, failure-domain inventory | `FailureDomainPlacementPlan`, replica target set |
| **Transfer** | `ChunkShipper` | `ReplicaTransferTicketRecord`, source/target pairs | `ReplicaTransferReceipt`, staged buffers |
| **Verify** | `FlowCommitCoordinator` | Transfer receipts, verification receipts | `FlowCommitResult`, flow state advance, batch sealing |
| **Commit** | `FlowCommitCoordinator` | Verified placement receipts | `FlowState` advance, `RebuildFlowState::Restored` |

#### 2.6.2 Scrub-to-Recovery Dataflow

When scrub detects corruption, the distributed pathway activates:

```
1. ScrubService.tick()
   │  checksum mismatch on object X
   ▼
2. ScrubFinding emitted → IntegrityEventBus
   │
   ▼
3. ReplicaHealthTracker.register_suspect_chunk(object X)
   │  chunk_health → Degraded; node_suspicion incremented
   │  FlapDetector checks for instability
   ▼
4. RecoveryLoop.poll()
   │  Detect phase: chunk X now Degraded
   │  Scope phase: classify as CatchupRepair or LossRebuild
   ▼
5. RebuildPlanner.open_rebuild_flow_from_loss_event()
   │  Produces LossEvent with affected chunks, lag records
   │  Freezes loss scope and degraded class
   ▼
6. RebuildPlanner.schedule_rebuild_batches_from_witness_sets()
   │  Builds WitnessSet from available members
   │  Schedules RebuildBatchRecords in priority order
   ▼
7. PlacementPlanner.compute_replica_target_set()
   │  Selects new replica targets with anti-affinity
   │  Produces FailureDomainPlacementPlan
   ▼
8. ChunkShipper.stage_and_ship()
   │  Reads healthy replica from verified source
   │  Transports via best available path (RDMA/uring/TCP)
   │  Emits ReplicaTransferReceipt
   ▼
9. FlowCommitCoordinator.commit_transfer_receipt()
   │  Chunk state: Pending → Transferring
   │  commit_verification_receipt() → Verifying
   ▼
10. FlowCommitCoordinator.advance_flow_after_receipt_commit()
    │  Flow state advances toward Restored
    │  Batch sealing on completion
    ▼
11. RecoveryLoop.verify()
    │  ResilverService verifies rebuilt shards
    │  Writes IntegrityTrailerV2 on new replica
    ▼
12. ReplicaHealthTracker.clear_suspect_chunk(object X)
    │  Health state restored to Healthy
    │  Flow marked Restored
```

#### 2.6.3 Node Failure Recovery Dataflow

For node/device failures (not corruption-driven), the pathway activates
through `ReplicaHealthTracker` liveness detection:

```
1. ReplicaHealthTracker detects node unreachable
   │  AdaptiveTimeout widens detection window
   │  Node suspicion incremented
   ▼
2. ReplicaHealthTracker escalates chunks to Degraded/Loss
   │  Per-chunk health transitions based on replica count
   │  FlapDetector suppresses transient-failure cascades
   ▼
3. RecoveryLoop scopes the loss event
   │  All affected chunks scoped to one LossEvent
   │  RecoveryPriority triaged by durability risk
   ▼
4. RebuildPlanner opens rebuild flow
   ▼
5-12. Same pipeline as scrub-to-recovery (steps 5-12 above)
```

#### 2.6.4 Placement Planner Integration

The `PlacementPlanner` (`tidefs-placement-planner`, P8-03 data_copy_0) is
the authoritative target-selection engine for all data movement — rebuild,
relocation, replication, and rebalance. Repair and resilver both delegate
target selection to it.

```
RepairService ──▶ compute_replica_target_set(policy, domains, tier)
                           │
                           ▼
                  FailureDomainPlacementPlan
                    ├── replica_targets: [MemberId]
                    ├── anti_affinity: Strict | DegradedVisible
                    ├── verdict: VerdictClass
                    └── epoch: EpochId
```

**Algorithm** (`compute_replica_target_set`):

1. Filter candidate failure domains by required domain class and health
2. Sort domains by least-loaded-first for fair distribution
3. Select one member per domain under strict anti-affinity; relax to
   `DegradedVisible` when insufficient domains
4. Produce a `FailureDomainPlacementPlan` with a membership verdict

**Tier-aware selection**: target selection varies by tier goal:
- `Primary`: full strictness, healthiest members
- `Secondary`: moderate relaxation, allows degraded members if necessary
- `Archive`: most relaxed, always `DegradedVisible`

**Repair uses `Primary` tier** — data at risk needs full redundancy on
best members. **Resilver uses `Secondary` tier** — restoring bulk data
may accept degraded placement for speed, upgrading later.

#### 2.6.5 Chunk Shipper and Transfer Pipeline

The `ChunkShipper` (`tidefs-chunk-shipper`, P8-03 data_copy_6) bridges
the gap between transfer tickets and actual data movement. Repair and
resilver both use it for cross-node (and same-node) chunk transfer.

```
TransferOrchestrator ──▶ ChunkShipper ──▶ VerificationEngine
  (tickets)               (movement)       (digest/receipt)
```

**Chunk staging lifecycle**:

```
Pending → Staging → Staged → Transport → Received → Verified
  │         │         │
  └─────────┴─────────┴── Failed / Cancelled
```

**Transport path selection** (aligned with P4-04 zero-copy/DMA law):

| Transport | Condition | Characteristics |
|-----------|-----------|----------------|
| `RdmaDirectDataPlacement` | Cross-node, RDMA-capable | Zero-copy, remote DMA |
| `IoUringSplice` | Same-node, io_uring available | Zero-copy, `copy_file_range` |
| `TcpFallback` | Otherwise | TCP streaming with buffer copies |

```rust
// Transport selection logic (from tidefs-chunk-shipper):
fn select(source: MemberId, target: MemberId,
           rdma_capable: bool, io_uring_available: bool) -> ChunkShippingTransport {
    if source == target && io_uring_available {
        IoUringSplice           // same-node, zero-copy
    } else if rdma_capable {
        RdmaDirectDataPlacement // cross-node, zero-copy
    } else {
        TcpFallback             // cross-node, buffered
    }
}
```

**ChunkStagingBuffer** carries the payload through staging → transport →
verification, with integrity protected by `ObjectDigest`. Under zero-copy
law (P4-04), production buffers are loaned pages or DMA-registered
regions; the deterministic model uses owned `Vec<u8>`.

#### 2.6.6 Flow Commit Coordinator Integration

The `FlowCommitCoordinator` (`tidefs-flow-commit-coordinator`, P8-03
data_copy_7) bridges the verification pipeline to the rebuild,
relocation, and replication flow state machines. It tracks chunks through
transfer → verification → placement and advances flow states on receipt
commit.

```
TransferReceipt    → commit_transfer_receipt()      → chunk: Pending → Transferring
VerificationReceipt → commit_verification_receipt()  → chunk: Transferring → Verifying
PlacementReceipt   → advance_flow_after_receipt_commit() → flow state advance
Batch complete     → seal_batch_and_emit_completion()    → batch → parent flow
```

**Chunk state tracking** — `TrackedChunk` follows each chunk:

```
Pending → Transferring → Verifying → Placed
```

**Batch tracking** — `TrackedBatch` groups chunks for coordinated
completion:

```
Batch open → Chunks added → All chunks placed → Batch sealed → Parent flow notified
```

**Six canonical flow classes** bridged by the coordinator:

| Flow Class | Trigger | Example |
|-----------|---------|---------|
| `RebuildLostCopy` | Corruption or node loss | Repair after scrub finding |
| `RebuildSuspectCopy` | Suspect health state | Preemptive rebuild |
| `BackfillLaggedCopy` | Replica lag detected | Catchup after partition heal |
| `RebalanceCapacity` | Capacity skew | Rebalance after node addition |
| `ReplicationSteady` | New write replication | Normal steady-state copy |
| `RelocationTier` | Tier migration | Hot→cold data movement |

Repair and resilver use `RebuildLostCopy` and `RebuildSuspectCopy`;
the coordinator ensures proper state transitions and batch notification.

#### 2.6.7 Witness Set Construction and Source Selection

When repair or resilver needs healthy source replicas, it builds a
`WitnessSet` — a bundle of candidate sources classified by health:

```
WitnessSet {
    verified_sources: Vec<MemberId>,    // Healthy, receipt-backed
    degraded_sources: Vec<MemberId>,    // Degraded but valid replicas
    unavailable_sources: Vec<MemberId>, // Stale or unreachable
}
```

**Construction algorithm** (from `tidefs-rebuild-planner`):

1. Iterate available members from membership epoch
2. For each member, check health class and replica lag:
   - `HealthClass::Healthy` + no degradation → `verified_sources`
   - `HealthClass::Healthy` + `DegradedReadPossible` → `degraded_sources`
   - `HealthClass::Suspect` → `degraded_sources` (usable as fallback)
   - `HealthClass::Down` → `unavailable_sources`
3. Verified sources are preferred; degraded sources used only when
   verified sources are insufficient

**Source selection priority** for repair/resilver:

1. Same-node healthy replica (fastest: io_uring splice)
2. Same-rack healthy replica (next fastest)
3. Cross-rack healthy replica with lowest replica lag
4. Degraded-but-valid replica (fallback)
5. EC reconstruction from k healthy shards (erasure-coded data only)

**ReplicaLagTracker integration**: source selection favors replicas with
`ReplicaLagStateRecord::is_current()` — i.e., replicas whose receipt
frontier matches the expected transaction group boundary. This ensures
repair doesn't reintroduce stale data.

#### 2.6.8 Recovery Loop Orchestration

The `RecoveryLoop` (`tidefs-recovery-loop`, #901) is the top-level
orchestrator that composes all distributed rebuild subsystems into the
5-phase continuous recovery cycle:

```
Detect ──▶ Scope ──▶ Plan ──▶ Execute ──▶ Verify
   ▲                                            │
   └────────────────────────────────────────────┘
```

**Per-phase responsibilities**:

| Phase | Subsystems | Action |
|-------|-----------|--------|
| Detect | `ReplicaHealthTracker` | Poll for degraded/lost chunks; consume `ReplicaHealthAlert` events |
| Scope | `LossEvent` classification | Classify as `SteadyReplication` / `CatchupRepair` / `LossRebuild` |
| Plan | `RebuildPlanner` + `PlacementPlanner` | Open rebuild flows; schedule witness-set batches; select targets |
| Execute | `ChunkShipper` + `FlowCommitCoordinator` | Run rebuild batches under `RecoveryThrottle`; ship chunks |
| Verify | `ResilverService` + `FlowCommitCoordinator` | Verify rebuilt shards; write integrity trailers; advance to Restored |

**RecoveryThrottle**: adaptive rate limiter:

```
admit_recovery_ticket(cost):
  adjusted_budget = compute_adjusted_budget()
  // adjusted_budget shrinks as client_latency_p50 rises
  (consumed + cost) <= adjusted_budget

should_pause_recovery():
  client_latency_p50 > baseline * 3.0
```

**CascadingFailureGuard**: prevents all replicas in a failure domain from
being recovered simultaneously:

```
per_domain_limit: max concurrent recovery flows per domain
aggregate_limit: max total recovery flows cluster-wide

admit(domain):
  if domain_active >= domain_limit:  → DomainAtCapacity
  if total_active >= aggregate_limit: → ClusterAtRecoveryCapacity
  → Admitted
```

**NodeRecoveryBudget**: per-node resource limits for recovery IO:

```
max_recovery_iops, max_recovery_bandwidth_bytes, max_recovery_memory_bytes
```

These guards prevent recovery from overwhelming the cluster during
large-scale failures — a failure mode absent in single-node ZFS and
only partially addressed by Ceph's PG-level backfill limits.

#### 2.6.9 Distributed Repair Consistency

When repair executes across nodes, consistency is maintained through
receipt-backed verification:

1. **Transfer integrity**: every chunk shipped carries an `ObjectDigest`;
   the receiver verifies it before accepting
2. **Receipt chain**: `ReplicaTransferReceipt` → `ReplicaVerificationReceipt`
   → `ReplicaPlacementReceipt` forms an auditable chain
3. **Idempotency**: the `FlowCommitCoordinator` rejects duplicate receipts
   for the same chunk, ensuring at-most-once transfer
4. **Fencing**: if the target node's membership epoch advances during
   transfer, the receipt is rejected — preventing placement on a
   decommissioned member
5. **ValidityToken integration**: distributed repair tasks carry validity
   tokens bound to the SuspectLog entry; if inline repair on another
   node already resolved the entry, the distributed task is skipped

#### 2.6.10 Deterministic Constraint Knobs for Distributed Pathway

| Constant | Default | Meaning |
|----------|---------|---------|
| `RECOVERY_MAX_CONCURRENT_PER_DOMAIN` | 3 | Max concurrent recovery flows per failure domain |
| `RECOVERY_MAX_AGGREGATE_LOAD` | 20 | Max total recovery flows cluster-wide |
| `RECOVERY_BANDWIDTH_BUDGET_BYTES` | 512 MiB/s | Max recovery bandwidth cluster-wide |
| `RECOVERY_CLIENT_LATENCY_THRESHOLD` | 3.0× baseline | Pause recovery when client latency exceeds 3× baseline |
| `RECOVERY_THROTTLE_AGGRESSIVENESS` | 1.0 | How aggressively to clamp recovery under client load |
| `WITNESS_SET_MIN_VERIFIED_SOURCES` | 2 | Minimum verified sources before degraded fallback |
| `REBUILD_BATCH_MAX_CHUNKS` | 256 | Max chunks per rebuild batch |
| `CHUNK_SHIPPER_STAGING_TIMEOUT_MS` | 5000 | Max ms before staged chunk is cancelled |
| `FLOW_COMMIT_BATCH_SEAL_TIMEOUT_MS` | 30000 | Max ms to wait for all chunks in a batch |

#### 2.6.11 Comparison to ZFS and Ceph Distributed Recovery

| Aspect | ZFS | Ceph | TideFS |
|--------|-----|------|--------|
| **Recovery trigger** | Pool resilver (device replacement) | OSD health change → PG-level backfill | `LossEvent` from health tracker or scrub finding |
| **Recovery scope** | Entire pool (sequential tree walk) | Per-PG (parallel across PGs) | Loss-event-scoped (only affected chunks) |
| **Source selection** | Any healthy disk in pool | Topology-based (CRUSH) | `WitnessSet` with receipt-backed verification, lag awareness |
| **Transport** | Local disk-to-disk only | Async messenger (TCP/RDMA) | Tiered: RDMA/uring-splice/TCP with zero-copy integration |
| **Flow coordination** | Single-threaded scan | Per-PG state machine | `FlowCommitCoordinator` bridging 6 flow classes |
| **Throttling** | Hard-coded scan delay | mclock (opaque profile weights) | `RecoveryThrottle` tied to client latency; explicit |
| **Failure-domain awareness** | None (single pool) | CRUSH rule-based | `CascadingFailureGuard` per-domain + aggregate |
| **Consistency after repair** | Checksum-only | PG scrub after backfill | Receipt chain (transfer→verify→place) + `ValidityToken` idempotency |
| **Idempotency** | Implicit (scan position) | PG log-based | `ValidityToken` binding hash + duplicate receipt rejection |



#### 2.6.12 CascadingFailureGuard Algorithmic Specification

The `CascadingFailureGuard` prevents a single rack, node, or failure
domain from being saturated by recovery traffic during multi-failure
scenarios. Without a guard, concurrent recovery flows can overwhelm
surviving nodes, causing cascading failures. The guard operates at two
levels:

**Per-domain admission control:**

```
Algorithm: CascadingFailureGuard::admit(flow: RebuildFlow) -> bool
  1. domain = flow.failure_domain()  // rack, node, power-zone, or AZ
  2. domain_count = active_recovery_flows.in_domain(domain)
  3. if domain_count >= RECOVERY_MAX_CONCURRENT_PER_DOMAIN:
  4.     return false  // reject: domain saturated
  5. aggregate_count = active_recovery_flows.total()
  6. if aggregate_count >= RECOVERY_MAX_AGGREGATE_LOAD:
  7.     return false  // reject: cluster-wide cap reached
  8. if recovery_bandwidth_used >= RECOVERY_BANDWIDTH_BUDGET_BYTES:
  9.     return false  // reject: bandwidth budget exhausted
  10. if client_latency_p50 > client_latency_baseline * RECOVERY_CLIENT_LATENCY_THRESHOLD:
  11.    return false  // reject: client impact detected
  12. return true  // flow admitted
```

**Throttle algorithm (RecoveryThrottle integration):**

```
Algorithm: RecoveryThrottle::adjust(target_budget: f64) -> f64
  1. ratio = client_latency_p50 / client_latency_baseline
  2. // Linear backoff: as client latency rises, recovery budget drops
  3. if ratio <= 1.0:       return target_budget
  4. if ratio <= 2.0:       return target_budget * 0.75
  5. if ratio <= 3.0:       return target_budget * 0.50
  6. if ratio <= 5.0:       return target_budget * 0.25
  7.                         return 0.0  // suspend all recovery
  8. // Aggressiveness = RECOVERY_THROTTLE_AGGRESSIVENESS scales
  9. // the backoff curve: higher values yield steeper cutoffs
```

**Saturation analysis:** The target invariant for per-domain cap
`R = RECOVERY_MAX_CONCURRENT_PER_DOMAIN` is that, within a domain of `N` nodes,
no more than `R` flows target any single node's resources. The aggregate cap
`A = RECOVERY_MAX_AGGREGATE_LOAD` is intended to prevent cluster-wide
saturation even when multiple domains have few active flows.

**Target failure-isolation invariant:** The `CascadingFailureGuard` is designed
so recovery traffic for domain `D_i` does not impact client traffic for domain
`D_j` for `i != j`, provided each domain has independent network paths and the
bandwidth budget is configured below the cross-domain link capacity. This is a
validation requirement, not a current guarantee.

#### 2.6.13 Distributed Recovery Time Objectives (RTO/RPO)

| Objective | Target | Measurement | Mitigation |
|-----------|--------|-------------|------------|
| **RPO** (data loss window) | 0 bytes for replicated (3×); ≤1 stripe for EC | Zero-replica-loss detection via health tracker in <1s | `SuspectLog` entry minted at detection commit_group; no data accept after detection |
| **RTO-single** (single chunk repair) | <100ms (inline) / <10s (deferred) | `RepairOutcome.elapsed_ms` from SuspectLog timestamp to `clear_suspect_chunk` | Inline repair on read path; deferred repair priority queue sorts by `RepairPriority::Loss` first |
| **RTO-node** (full node rebuild) | <N_minutes where N = data_size / recovery_bandwidth | `ResilverProgress.bytes_rebuilt / plan.total_bytes` | `RecoveryThrottle` maximizes throughput under client-latency constraint; `CascadingFailureGuard` prevents multi-node saturation |
| **RTO-stripe** (EC stripe rebuild) | <stripes_per_tick × tick_interval | `ResilverProgress.stripes_completed / plan.total_stripes` | PlacementPlanner anti-affinity ensures source shards are on distinct failure domains |
| **Detection latency** | <1 tick (1s default) for health-tracker-monitored chunks | `ReplicaHealthAlert.timestamp` to SuspectLog entry | Target dual-source health is intended to catch failure modes heartbeat-only designs can miss |

**Recovery timeline formula for full node replacement:**

```
T_recovery = (total_data_bytes_on_failed_node) /
             min(RECOVERY_BANDWIDTH_BUDGET_BYTES,
                 client_idle_bandwidth_available × (1 - client_load_fraction))

Where client_idle_bandwidth_available =
    total_cluster_bandwidth - baseline_client_bandwidth
```

For a 10 TiB node on a cluster with 50 GiB/s total bandwidth and 25 GiB/s
baseline client traffic, recovery completes in approximately:

```
T_recovery = 10 TiB / min(512 MiB/s, 25 GiB/s) ≈ 5.7 hours
```

The `RecoveryThrottle` dynamically adjusts this target based on real-time
client latency, preventing the formula from being an over-optimistic
lower bound.

#### 2.6.14 Network Partition Handling During Distributed Recovery

Network partitions create a fundamental tension: a partitioned node's
replicas may appear degraded from one side of the partition and healthy
from the other. The distributed recovery system handles partitions with
quorum-aware health and partition-bounded repair:

**Quorum-aware replica health:** The `ReplicaHealthTracker` computes
health state using a quorum of cluster members. When fewer than a majority
of members are reachable, the tracker enters `DegradedQuorum` state:

```
Algorithm: ReplicaHealthTracker::evaluate_partition(partition_view: HashSet<MemberId>) -> PartitionAction
  1. if partition_view.len() > total_members / 2:
  2.     // Majority partition: authoritative health
  3.     return PartitionAction::ContinueRecovery
  4.     // Lost minority members have their replicas marked Degraded
  5.     // and are scheduled for repair (they may come back, but data
  6.     // is re-replicated to maintain redundancy during the partition)
  7. else:
  8.     // Minority partition: freeze all recovery
  9.     return PartitionAction::FreezeRecovery
  11.    // All repair writes gated on partition fence tokens
```

**Partition fence tokens:** When a minority partition freezes recovery,
all in-flight repair writes receive a `PartitionFenceToken` from the
majority partition's coordinator. If the network heals and the minority
attempts to commit stale repair writes, the `FlowCommitCoordinator`
rejects them:

```
│ NonOverlappingFence(Range<ChunkId>) -> bool  // true = admitted
│ PartitionFence(partition_epoch: u64) -> bool  // true = admitted
```

**Merge-after-partition:** When the network heals and quorum is restored,
the `ReplicaHealthTracker` enters `MergeVerification`:

```
Partition heals → all members visible again
   │
   ├── AntiEntropyAuditor: immediate full-scope comparison
   │     of all chunks that were in SuspectLog during partition
   │
   ├── Any divergence → SuspectLog re-populated with corrected entries
   │
   └── MergeVerification complete → normal RecoveryLoop resumes
```

**Safety invariant:** No replica is permanently lost during a partition
unless the partition lasts longer than the redundancy window (i.e., both
the original and replica nodes are independently lost). The
`CascadingFailureGuard` prevents the repair traffic from saturating the
surviving partition while re-replication runs.

**Tradeoff:** Re-replicating data from the majority partition during a
split creates temporary write amplification and targets full redundancy
regardless of which partition ultimately survives. That remains a validation
requirement, not a current availability claim.

### 2.7 Anti-Entropy Auditor Integration

The anti-entropy auditor (`data_copy_8`, `tidefs-anti-entropy-auditor`)
provides ground-truth verification for the distributed rebuild/recovery
pathway. While the `ReplicaHealthTracker` uses receipt frontiers for
optimistic health computation, the anti-entropy auditor performs periodic
full-scope comparisons to detect divergence that receipts miss:

- **Silent divergence**: a replica whose checksums are valid but whose data
  differs from the authoritative copy (e.g., a firmware bug, a bit-flip
  that escaped the checksum, or a misapplied write).
- **Orphan detection**: chunks present on a node but not referenced by any
  valid locator table entry.
- **Missing-replica detection**: chunks referenced by locator tables but
  absent from all nodes claiming to host them.

#### 2.7.1 Auditor ↔ Scrub/Repair Interaction

```
AntiEntropyAuditor.tick()
  │
  ├── compare_shard_digests_across_nodes()
  │     │  divergence found on chunk C at node N
  │     ▼
  │   ReplicaHealthTracker.mark_suspect(C)
  │     │  triggers flap detection, suspicion scoring
  │     ▼
  │   SuspectLog.record(C, reason=AntiEntropyDivergence)
  │     │
  │     ▼
  │   RecoveryLoop picks up suspect → scopes LossEvent
  │
  ├── detect_orphaned_chunks()
  │     │  orphan chunks found → GC pin set or reclaim
  │     ▼
  │   SpaceAccounting.adjust_orphan_count()
  │
  └── detect_missing_replicas()
        │  missing replica → degraded redundancy
        ▼
      RecoveryLoop → RebuildPlanner → ChunkShipper
```

#### 2.7.2 Auditor Scheduling

The anti-entropy auditor runs as a `BackgroundService` at `BestEffort`
priority, sharing the 10% budget with `DeepScrubService`:

| Phase | Frequency | Scope |
|-------|-----------|-------|
| **Quick compare** | Every 1 hour | Recently modified chunks (last 24h) |
| **Full compare** | Every 24 hours | All chunks with >1 replica |
| **Deep compare** | Every 7 days | Full shard-level reconstruction verification |

Unlike scrub which verifies checksums on individual objects, the auditor
verifies **cross-node consistency**: that the same chunk on different nodes
has identical content. This catches faults that per-object checksums cannot:
firmware bugs, memory corruption during replication, and split-brain
scenarios.

#### 2.7.3 Auditor Constraint Knobs

| Constant | Default | Meaning |
|----------|---------|---------|
| `AE_QUICK_COMPARE_INTERVAL_HOURS` | 1 | Hours between quick-compare runs |
| `AE_FULL_COMPARE_INTERVAL_HOURS` | 24 | Hours between full-compare runs |
| `AE_DEEP_COMPARE_INTERVAL_HOURS` | 168 | Hours between deep-compare runs (7 days) |
| `AE_MAX_CHUNKS_PER_TICK` | 500 | Max chunks compared per auditor tick |
| `AE_QUICK_COMPARE_WINDOW_HOURS` | 24 | Age window for "recently modified" chunks |
| `AE_DIVERGENCE_RETRY_COUNT` | 3 | Re-compare attempts before declaring divergence |



#### 2.7.4 Anti-Entropy Auditor State Machine

The `AntiEntropyAuditor` in `tidefs-anti-entropy-auditor` implements a
6-state lifecycle with incremental frontier tracking:

```
Idle --> Enumerating --> Compare --+--> Verified (no divergence)
                                   |
                                   +--> DivergenceFound --> Ticketed --> Resolved
```

| State | Description |
|-------|-------------|
| `Idle` | Waiting for next scan window; tracks `last_scan_completed_ns` and `next_scan_eligible_ns` |
| `Enumerating` | Building the subject list for the current scan batch from locator tables and replica health records |
| `Compare` | Running three-source digest comparison (primary digest, replica digest, optional witness digest) |
| `DivergenceFound` | A digest mismatch was detected; divergence recorded with chunk ID, nodes involved, divergence class |
| `Ticketed` | A rebuild ticket was created and dispatched to the `RebuildPlanner` for resolution |
| `Resolved` | The rebuild completed successfully; divergence is cleared from the active set and added to `divergence_history` |

**Incremental frontier**: Unlike ZFS scrub (which re-scans the entire pool
every pass), the AE auditor maintains a high-water mark and a
degraded-subject list. Only subjects beyond the high-water mark or in
the degraded list are scanned, preventing redundant work.

**Three-source comparison**: When a primary-vs-replica digest mismatch is
detected, a third source (witness) is consulted for tie-breaking. If the
witness agrees with the primary, the replica is marked suspect. If the
witness agrees with the replica, the primary is suspect. If all three
disagree, all replicas are marked suspect and escalated to operator review.

**Divergence classes** tracked in `DivergenceRecord`:
- `DigestMismatch` -- checksums differ between nodes
- `SizeMismatch` -- chunk sizes differ
- `MissingChunk` -- chunk absent from one node
- `OrphanChunk` -- chunk present but unreferenced
- `StaleReplica` -- replica behind receipt frontier


### 2.8 Target End-to-End Integrity Chain

The target integrity evidence chain for a repaired chunk:

```
   1. Scrub/DeepScrub detects corruption
          │
   2. SuspectLog: authoritative record of finding
          │
   3. ReplicaHealthTracker: per-chunk health → suspect
          │
   4. RecoveryLoop: detect → scope as LossEvent
          │
   5. RebuildPlanner: open rebuild flow, select witness sources
          │
   6. CascadingFailureGuard: domain-aware admission
          │
   7. RebuildPlanner: schedule witness-set batches
          │
   8. PlacementPlanner: anti-affinity target selection
          │
   9. ChunkShipper: stage → transport → ReplicaTransferReceipt
          │
  10. FlowCommitCoordinator: digest/witness/range verification
          │
  11. FlowCommitCoordinator: ReplicaVerificationReceipt emitted
          │
  12. FlowCommitCoordinator: ReplicaPlacementReceipt emitted
          │
  13. AntiEntropyAuditor: cross-node consistency verification
          │
  14. ReplicaHealthTracker: clear suspect → mark healthy
          │
  15. SuspectLog: clear entry — authoritative: corruption resolved
```

Every step has an explicit, receipt-backed record. No step relies on
implicit state or folklore. This is the key architectural difference
from ZFS (where resilver is a single sequential pass with no receipts)
and Ceph (where backfill uses PG logs but lacks cross-component receipt
chains).


### 2.9 Distributed Write Consistency During Repair

When repair or resilver writes a repaired replica to a remote node, the
write must be coordinated with ongoing application writes to the same
chunk. Without coordination, the following race occurs:

```
T1: Repair reads chunk C version v3 from source node S
T2: Application writes chunk C version v4 to source node S and target node T
T3: Repair writes chunk C version v3 to target node T
    -> Target node T is now reverted to v3, losing v4!
```

**Solution: COMMIT_GROUP-gated write barriers.** Every repair write carries a
`commit_group_bound` derived from the SuspectLog entry's minting transaction
group. The target node's local object store checks the `commit_group_bound` before
accepting the write:

```rust
/// On the receiving node, before accepting a repair write:
fn accept_repair_write(&self, chunk_id: u64, data: &[u8], commit_group_bound: u64) -> Result<()> {
    let current_commit_group = self.current_commit_group();
    let chunk_version = self.chunk_version(chunk_id);

    // Reject if the chunk was modified after the repair was planned
    if chunk_version.map_or(false, |v| v.committed_at_commit_group > commit_group_bound) {
        return Err(RepairError::StaleWrite {
            chunk_id,
            repair_commit_group: commit_group_bound,
            current_commit_group: v.committed_at_commit_group,
        });
    }
    // ... proceed with write
}
```

If the application write committed at a commit_group greater than `commit_group_bound`, the
repair write is rejected. The repair service detects the rejection and
re-scopes the repair: if the new version is healthy, the SuspectLog entry
is cleared (the application write implicitly repaired the data). If the
new version is also corrupt, a fresh SuspectLog entry is created at the
current commit_group.

This barrier is enforced for all distributed repair writes (repair service
and resilver service). Inline repair on the read path uses a simpler
optimistic lock: it compares the object version at read time with the
version at write time, and aborts if they differ.

**Write fencing during node replacement:** When a replacement node joins
the cluster during resilver, the coordinator issues a `WriteFence` for
the affected chunk range. All application writes to fenced chunks are
redirected to a temporary journal until the fence is lifted. This
prevents the race between application writes and resilver writes during
the critical window when the new node has incomplete data.

| Fence type | Scope | Duration | Write behavior |
|------------|-------|----------|----------------|
| `ChunkFence` | Single chunk | <1s (one repair tick) | Application writes blocked |
| `StripeFence` | EC stripe | ~100ms | Application writes blocked |
| `RangeFence` | Contiguous chunk range | Until resilver pass completes | Application writes journaled |
| `NodeFence` | All chunks on one node | Until node is restored | Application writes redirected to other replicas |


## 3. Scrub Namespace and Cursor Model

### 3.1 Namespace Ordering

The scrub namespace orders all verifiable storage by priority:

```
Level 1: Metadata
  ├── Dataset catalog (inode B-tree)
  ├── Locator tables
  ├── Extent maps
  ├── Refcount B-tree
  ├── Snapshot catalog
  └── Derived catalog

Level 2: System metadata
  ├── Pool map journal
  ├── Spacemap checkpoint
  ├── SuspectLog (#1564)
  └── Integrity footers

Level 3: Data
  ├── Hot datasets (by I/O temperature)
  ├── Warm datasets
  └── Cold datasets

Level 4: Free/unallocated
  └── Verify SegmentIntegrityFooter chain only
```

Metadata is scrubbed more frequently than data (`METADATA_SCRUB_FREQUENCY_MULTIPLIER = 4`),
ensuring that metadata corruption—which can cascade into data loss—is detected early.

### 3.2 ScrubCursor

```rust
/// Resumable position in the scrub namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScrubCursor {
    /// Which level of the namespace is being scrubbed.
    pub level: ScrubLevel,

    /// Dataset being scrubbed (None = system metadata).
    pub dataset_id: Option<u64>,

    /// Inode being scrubbed within the dataset.
    pub inode_id: Option<u64>,

    /// Extent/segment position within the inode or global space.
    pub extent_offset: Option<u64>,

    /// BLAKE3-256 hash of the cursor for integrity verification on resume.
    pub cursor_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScrubLevel {
    Metadata = 0,
    SystemMetadata = 1,
    Data = 2,
    FreeSpace = 3,
}
```

**Cursor hash computation**: `BLAKE3-256(level as u8 || dataset_id.to_le_bytes() ||
inode_id.to_le_bytes() || extent_offset.to_le_bytes())`. On resume, the hash
is recomputed and compared; mismatch triggers a full pass restart to prevent
skipped or duplicated work.

### 3.3 Cursor Persistence

The cursor is persisted in the pool map journal at each transaction group
commit. On mount, the cursor is loaded and the scrub resumes from the
last checkpointed position.

```rust
/// On-media cursor record stored in pool map journal.
/// Versioned (V1) for format-identity upgrade compatibility.
pub struct ScrubCursorRecordV1 {
    pub cursor: ScrubCursor,
    pub scrub_pass_id: u64,
    pub started_at_commit_group: u64,
    pub last_checkpoint_commit_group: u64,
    pub segments_verified: u64,
    pub segments_corrupt: u64,
    pub segments_repaired: u64,
    pub bytes_verified: u64,
    pub bytes_corrupt: u64,
    pub bytes_repaired: u64,
    /// BLAKE3-256 over the serialized cursor fields, zeroed hash.
    pub record_hash: [u8; 32],
}
```

### 3.4 Independent Cursors for Scrub and Deep Scrub

Scrub and deep scrub maintain **separate cursors**. Rationale:
- Scrub targets individual objects (records) ordered by namespace
- Deep scrub targets erasure-coded stripes ordered by stripe ID
- Separate cursors allow independent pass intervals (7-day scrub, 30-day deep scrub)

A third cursor is introduced for the repair service to track repair progress
through the SuspectLog. The repair cursor is lightweight—just the last
processed SuspectLog entry index—and is persisted alongside the scrub cursor.

### 3.5 Pass Lifecycle

Each scrub pass has a monotonically increasing `scrub_pass_id`. When a pass
completes (cursor reaches end of L4), a new pass begins at L1 with an
incremented `scrub_pass_id`. If the pool is exported mid-pass, the cursor
is checkpointed and the pass resumes on next import. If the cursor hash is
invalid on import, the pass is restarted from L1 with a new `scrub_pass_id`.

## 4. Scrub Service

### 4.1 Algorithm

```
Algorithm: scrub_tick(budget: ServiceBudget) -> TickReport
  1. Load cursor from pool map journal (or initialize at L1 start)
  2. items = 0; bytes = 0
  3. while items < budget.max_items AND bytes < budget.max_bytes:
  4.   object = next_object_from_cursor(cursor)
  5.   if object is None:
  6.     advance_level(cursor)
  7.     if cursor.level > FreeSpace: mark pass complete; break
  8.     continue
  9.   trailer = read_integrity_trailer(object.key)  // IntegrityTrailerV2
  10.  payload = read_object(object.key)
  11.  expected = blake3_domain_digest(payload, object.record_type)
  12.  if expected != trailer.payload_digest:
  13.    emit ScrubFinding(corruption_detected, object,
  14.         expected, trailer.payload_digest)
  15.    suspend_object(object, SuspectLog)
  16.    stats.corrupt += 1
  17.    enqueue_repair(object,
  18.         RepairPriority::loss_of_redundancy(object))
  19.  else:
  20.    stats.clean += 1
  21.  items += 1; bytes += object.size
  22.  advance_cursor(cursor, object)
  23. checkpoint_cursor(cursor)  // persists at commit_group commit boundary
  24. return TickReport { processed: items, bytes, stats, … }
```

### 4.2 Checksum Verification

Scrub uses the `IntegrityTrailerV2` from #1564 (`docs/design/end-to-end-checksum-architecture.md`):

- **Payload digest**: BLAKE3-256 over record payload bytes, domain-separated by record type
- **Record digest**: BLAKE3-256 over header + payload + trailer
- **EC shard fields**: `shard_count`, `shard_index`, `ec_k`, `ec_m` (0 for replicated data)

For replicated data, scrub verifies the payload digest of each replica individually.
For erasure-coded data, scrub verifies each shard's payload digest. Deeper cross-shard
verification is deferred to the deep scrub service.

### 4.3 Read-Path Verification (Synchronous)

In addition to background scrubbing, every read path verifies checksums
synchronously. On mismatch:

1. Attempt transparent repair from a healthy replica (same commit_group)
2. If repair succeeds, return repaired data to caller; caller sees no error
3. If repair fails (no healthy source), return `EIO` to caller and queue
   repair at Critical priority
4. Emit `IntegrityEvent::ReadPathCorrection` or `IntegrityEvent::ReadPathUnrepairable`

### 4.4 Service Lifecycle

```
               ┌─────────┐
      pool     │  Idle   │
     mount ──▶ │         │
               └────┬────┘
                    │ scheduler tick
                    ▼
               ┌─────────┐
               │ Running │ ◀── scrub loop (per-tick budget)
               │         │
               └────┬────┘
                    │ pass complete OR pool export
                    ▼
               ┌─────────┐
               │ Draining│ ──▶ checkpoint cursor → Idle
               └─────────┘
```

## 5. Deep Scrub Service

### 5.1 Algorithm

Deep scrub verifies erasure-coded data by reconstructing each stripe from
its k data shards and comparing the reconstructed output against each
stored shard. This detects corruption where individual shard checksums
are valid but the data across shards is inconsistent (e.g., an encode-path
bug that wrote identical-but-wrong payloads to all shards).

```
Algorithm: deep_scrub_tick(budget) -> TickReport
  1. Load deep_scrub_cursor
  2. for each stripe in cursor..budget.max_stripes:
  3.   config = load_stripe_config(stripe)
  4.   shards = [read_shard(stripe, i) for i in 0..config.stripe_width()]
  5.   // Fast path: verify each shard's own checksum
  6.   corrupt_shards = [i for i, shard in shards
  7.                     if shard.digest != blake3_domain(shard.payload)]
  8.   if corrupt_shards is not empty:
  9.     emit DeepScrubFinding(corrupt_shards)
  10.    continue
  11.  // Deep path: reconstruct from k data shards
  12.  reconstructed = reconstruct(config, shards[0..k])
  13.  for i, shard in shards:
  14.    if shard.payload != reconstructed.segment(i):
  15.      emit DeepScrubFinding(encode_divergence, stripe, i)
  16.      suspend_stripe(stripe, SuspectLog)
  17.  advance_deep_scrub_cursor(cursor, stripe)
  18. checkpoint
  19. return TickReport
```

### 5.2 Double-Check Mode for Marginal Media

For devices exhibiting intermittent read errors (marginal media), deep scrub
supports double-check mode:

1. On first pass: identify reads that return valid checksums but exhibit
   high latency or transient retries
2. Mark shard as "suspect-marginal"
3. On second pass (scheduled after a configurable delay): re-verify
4. If second pass confirms: mark as corrupt and repair
5. If second pass passes: clear suspect-marginal flag

### 5.3 Digest Comparison and Phantom Corruption

Deep scrub performs a full digestion comparison: reconstruct from k shards,
re-encode to n shards, then compare each encoded shard against the stored
shard. This catches:

- Silent corruption in the encode path (all shards have valid individual
  checksums but are mutually inconsistent)
- Phantom corruption from bit rot that escaped the shard-level checksum
- Shard count mismatches (missing shards with valid remaining checksums)

## 6. Repair Service

### 6.1 Architecture

The repair service consumes entries from the SuspectLog and restores
redundancy. It maps to the existing `RepairStrategy` enum in
`crates/tidefs-local-filesystem/src/scrub.rs` (line 395) and
`RepairOutcome` in `repair.rs` (line 24).

```
SuspectLog ──▶ RepairQueue ──▶ RepairService.tick() ──▶ repair outcome
                  │                                         │
                  │  sort by RepairPriority                 │
                  │  (loss_of_redundancy >                  │
                  │   historical > scheduled)                │
                  ▼                                         ▼
            ┌──────────────────┐              ┌─────────────────────┐
            │ Priority: Loss   │──▶Repair──▶ │ Write repaired data  │
            │ (0 replicas left)│              │ to healthy location  │
            └──────────────────┘              └─────────────────────┘
            ┌──────────────────┐              ┌─────────────────────┐
            │ Priority: High   │──▶Replicate▶│ Copy from healthy    │
            │ (degraded)       │              │ replica to new loc   │
            └──────────────────┘              └─────────────────────┘
            ┌──────────────────┐              ┌─────────────────────┐
            │ Priority: Normal │──▶Reconst. ▶│ Reconstruct from     │
            │ (scheduled)      │              │ EC shards            │
            └──────────────────┘              └─────────────────────┘
```

### 6.2 Repair Strategies

From the existing `RepairStrategy` enum in `scrub.rs`:

```rust
pub enum RepairStrategy {
    /// Copy from a healthy replica (replicated data).
    ReplicateFromHealthy { source: ChunkId, target: ChunkId },

    /// Reconstruct from k healthy EC shards.
    ReconstructFromShards { stripe: StripeId, healthy_shards: Vec<usize> },

    /// Zero-fill at the file-system level (metadata-directed).
    ZeroFillExtent { inode: u64, offset: u64, length: u64 },

    /// File-system-directed truncation repair.
    TruncateExtent { inode: u64, new_size: u64 },

    /// No repair possible; escalate to operator.
    Unrepairable { reason: String },
}
```

### 6.3 Repair Execution

```
Algorithm: repair_tick(budget) -> TickReport
  1. if repair_queue is empty:
  2.   drain SuspectLog into repair_queue (up to budget.max_items)
  3.   sort repair_queue by RepairPriority (loss > historical > scheduled)
  4. items = 0; bytes = 0
  5. while items < budget.max_items AND bytes < budget.max_bytes:
  6.   entry = repair_queue.pop()
  7.   if entry is None: break
  8.   // Validity token check: has the object been repaired already?
  9.   if entry.validity_token.is_stale(): continue
  10.  context = ResolverContext { pool_map, device_health, replica_lag, … }
  11.  strategy = resolve_violation(&entry.violation, context)
  12.  match strategy:
  13.    ReplicateFromHealthy → copy from healthy replica
  14.    ReconstructFromShards → reconstruct from k healthy shards
  15.    ZeroFillExtent → zero-fill the extent
  16.    TruncateExtent → truncate inode
  17.    Unrepairable → escalate to operator; emit alarm
  18.  if repair succeeded:
  19.    clear_suspect_entry(entry.suspect_id)
  20.    stats.repaired += 1
  21.  else if retries < MAX_REPAIR_RETRIES:
  22.    requeue with incremented retry count
  23.  else:
  24.    escalate to operator
  25.  items += 1; bytes += entry.byte_count
  26. return TickReport
```

### 6.4 Inline vs. Deferred Repair

**Inline (read hot path)**: transparent repair from healthy replica; must
complete in <1ms to avoid impacting application IO. Falls back to deferred
if no fast local source.

**Deferred (repair service)**: tick-driven with budget enforcement; can use
cross-node sources, reconstruction from EC shards. Suitable for complex repairs.

The inline path uses a fast-path validity token: a lightweight hash binding
to the object version. The deferred path uses the full SuspectLog entry. If
inline repair completes before the deferred task fires, the deferred task's
SuspectLog validity token is stale and the task is skipped.

## 7. Resilver Service

### 7.1 Architecture

Resilver restores full redundancy after a device replacement or topology change.
It integrates with `tidefs-replica-health` for lag state tracking and
`tidefs-erasure-coded-store` for shard-level rebuilding.

```
Device replacement event ──▶ ResilverPlanner ──▶ StripePlan[]
                                    │
                                    │ topology-aware placement
                                    ▼
                             ┌──────────────┐
                             │ ResilverSvc  │
                             │ .tick()      │
                             └──────┬───────┘
                                    │ per-tick budget
                                    ▼
                             ┌──────────────┐
                             │ For each      │
                             │ stripe in plan│
                             │  rebuild      │
                             │  verify       │
                             │  write        │
                             └──────────────┘
```

### 7.2 Stripe Rebuild

```
Algorithm: resilver_tick(budget) -> TickReport
  1. if plan is None:
  2.   plan = ResilverPlanner::build(pool_topology, failed_devices)
  3. stripes = 0; bytes = 0
  4. while stripes < budget.max_stripes AND bytes < budget.max_bytes:
  5.   stripe_plan = plan.next()
  6.   if stripe_plan is None: mark complete; break
  7.   // Read k healthy shards from best sources
  8.   healthy_shards = select_best_sources(stripe_plan, replica_health)
  9.   if len(healthy_shards) < k:
  10.    emit ResilverError::NotEnoughShards
  11.    continue
  12.  // Reconstruct
  13.  reconstructed = reconstruct(config, healthy_shards)
  14.  // Write to target devices
  15.  for shard in stripe_plan.target_shards:
  16.    write_integrity_trailer(shard.location, reconstructed.segment(shard.i))
  17.  // Verify written shards
  18.  for shard in stripe_plan.target_shards:
  19.    verify_shard_checksum(shard.location)
  20.  stripes += 1; bytes += stripe_plan.byte_count
  21.  emit ResilverProgress(stripe_plan.stripe_id, stripes, plan.total_stripes)
  22. checkpoint_resilver_cursor(cursor)
  23. return TickReport
```

### 7.3 Topology Awareness

The `ResilverPlanner` is topology-aware:

- **Device-level**: rebuilds data that was on the failed/replaced device
- **Rack-level**: distributes new replicas across different failure domains
- **Bandwidth-aware**: selects source replicas with lowest replica lag
  (`ReplicaLagStateRecord::is_current()` from `tidefs-replica-health`)
- **Incremental**: supports pausing and resuming; progress checkpointed via
  `ResilverCursor`

### 7.4 Resilver Cursor

```rust
pub struct ResilverCursor {
    /// Plan generation (incremented on topology change).
    pub plan_generation: u64,
    /// Last completed stripe in the plan.
    pub last_stripe_id: Option<u64>,
    /// Total stripes completed so far.
    pub stripes_completed: u64,
    /// Total bytes rebuilt.
    pub bytes_rebuilt: u64,
    /// BLAKE3-256 hash for integrity.
    pub cursor_hash: [u8; 32],
}
```

### 7.5 Resilver Priority Escalation

Resilver runs at `Throughput` priority normally but escalates to `Critical`
when data loss risk is high:

```
if remaining_replicas <= RESILVER_CRITICAL_THRESHOLD:
    scheduler.escalate("resilver", ServicePriority::Critical)
```

This dynamically reallocates 40% of the tick budget to resilver, ensuring
data-loss scenarios are resolved as fast as possible.

## 8. Integrity Event System

### 8.1 Unified Event Model

All four services emit events on a shared `IntegrityEventBus` for unified
observability:

```rust
pub enum IntegrityEvent {
    /// Scrub found an issue.
    ScrubFinding {
        object_id: u64,
        level: ScrubLevel,
        finding: ScrubFindingKind,
        timestamp: CommitGroupInstant,
    },

    /// Deep scrub found an inconsistency.
    DeepScrubFinding {
        stripe_id: StripeId,
        shard_index: usize,
        finding: DeepScrubFindingKind,
        timestamp: CommitGroupInstant,
    },

    /// Repair was attempted.
    RepairOutcome {
        object_id: u64,
        strategy: RepairStrategy,
        outcome: Result<(), RepairError>,
        elapsed_ms: u64,
    },

    /// Resilver progress.
    ResilverProgress {
        plan_generation: u64,
        stripes_completed: u64,
        total_stripes: u64,
        bytes_rebuilt: u64,
    },

    /// Read-path correction (transparent repair on read).
    ReadPathCorrection {
        object_id: u64,
        source: ChunkId,
        elapsed_us: u64,
    },

    /// Read-path failure (unrepairable on read).
    ReadPathUnrepairable {
        object_id: u64,
        reason: String,
    },

    /// Service lifecycle change.
    ServiceStateChange {
        service: ServiceKind,
        from: ServiceState,
        to: ServiceState,
    },
}

pub enum ScrubFindingKind {
    ChecksumMismatch { expected: [u8; 32], actual: [u8; 32] },
    MissingIntegrityTrailer,
    ObjectUnreadable { reason: String },
}

pub enum DeepScrubFindingKind {
    SingleShardCorrupt { shard_index: usize },
    EncodeDivergence { shard_indices: Vec<usize> },
    MarginalMediaDetection { device_id: u64 },
}
```

### 8.2 Observability Counters

Each service emits structured counters via the observability framework (#827):

| Service | Counter | Description |
|---------|---------|-------------|
| Scrub | `scrub.objects_verified` | Total objects checksum-verified |
| Scrub | `scrub.objects_corrupt` | Objects with checksum mismatch |
| Scrub | `scrub.bytes_verified` | Total bytes verified |
| Scrub | `scrub.pass_completions` | Full pass completions |
| DeepScrub | `deep_scrub.stripes_verified` | Stripes deep-verified |
| DeepScrub | `deep_scrub.encode_divergences` | Encode-path divergences found |
| DeepScrub | `deep_scrub.marginal_detections` | Marginal media detections |
| Repair | `repair.tasks_completed` | Repairs successfully completed |
| Repair | `repair.tasks_failed` | Repairs that exceeded retry limit |
| Repair | `repair.bytes_repaired` | Total bytes repaired |
| Repair | `repair.inline_repairs` | Transparent inline repairs |
| Resilver | `resilver.stripes_rebuilt` | Stripes rebuilt |
| Resilver | `resilver.bytes_rebuilt` | Total bytes rebuilt |
| Resilver | `resilver.plan_completions` | Resilver plans completed |

## 9. Validity Tokens and Stale-Task Prevention

### 9.1 Design

Validity tokens prevent a task from executing when its target has already
been handled by another path. Every repair task carries a token bound to
the specific suspect entry:

```rust
pub struct ValidityToken {
    /// BLAKE3-256 of (suspect_entry_id || object_version || commit_group_bound).
    pub binding_hash: [u8; 32],
    /// The commit_group at which this token was minted.
    pub minted_at_commit_group: u64,
}

impl ValidityToken {
    pub fn is_stale(&self, suspect_log: &SuspectLog) -> bool {
        // Stale if the suspect entry no longer exists or its version changed.
        suspect_log.lookup(self.binding_hash).is_none()
    }
}
```

### 9.2 Race Resolution

```
Timeline:
  T1: Scrub detects corruption → creates SuspectEntry(id=42)
  T2: Scrub enqueues DeferredRepair(id=42, token=hash(42||v1||T1))
  T3: Read path encounters block → InlineRepair succeeds → clears SuspectEntry(42)
  T4: DeferredRepair dequeues → token.is_stale() → true → skipped
```

The token prevents redundant or conflicting work without requiring locks
across the read and repair paths.

### 9.3 Token Binding Hash

The binding hash includes:
1. `suspect_entry_id` — unique identifier of the SuspectLog entry
2. `object_version` — version of the object at time of token minting
3. `commit_group_bound` — transaction group at which the token is valid

If any of these change before the repair task executes, the token is stale.

## 10. Service Interaction Matrix

| Scenario | Scrub | DeepScrub | Repair | Resilver | Read Path |
|----------|-------|-----------|--------|----------|-----------|
| Scrub finds corruption | — | Independent | Enqueues repair | Independent | Independent |
| Deep scrub finds EC divergence | Independent | — | Enqueues repair | Avoids affected stripe temporarily | Independent |
| Repair completes | Re-verifies on next tick | Independent | — | Independent | Returns repaired data |
| Resilver in progress | Continues at lower priority | Continues at BestEffort | Continues at Critical | — | Independent |
| Pool export | Checkpoints cursor | Checkpoints cursor | Flushes queue to SuspectLog | Checkpoints cursor | Returns EIO |
| Mount-time recovery | Triggers scratch-scrub of suspect inodes | Independent | Processes SuspectLog | Independent | Independent |

## 11. Service Lifecycle State Machine

All four services share a common lifecycle state machine:

```
                  ┌──────────┐
     scheduler    │          │  service unregistered /
     .register()  │   Idle   │  pool export
     ───────────▶ │          │ ◀────────────────────
                  └────┬─────┘
                       │ scheduler.start()
                       ▼
                  ┌──────────┐
                  │  Active  │ ◀── tick loop
                  │          │
                  └────┬─────┘
                       │ scheduler.pause() / pool export
                       ▼
                  ┌──────────┐
                  │ Draining │ ──▶ checkpoint cursor / flush queue
                  │          │
                  └────┬─────┘
                       │ drain complete
                       ▼
                  ┌──────────┐
                  │   Idle   │
                  └──────────┘
```

The `ServiceStateChange` event is emitted on every transition for operator
visibility.

## 12. Implementation Phases

The implementation follows a seven-phase approach, each phase delivering a
separate wire-up issue:

| Phase | Crates | Deliverable |
|-------|--------|------------|
| 1 | `tidefs-types-scrub-core/` + `tidefs-local-filesystem/` | Core types: `ScrubCursor`, `SuspectLog`, `ValidityToken`, `RepairStrategy`, `RepairOutcome`, `IntegrityCheckpoint`; mount-time scratch-scrub types |
| 2 | `tidefs-scrub-service/` | ScrubService: cursor persistence, namespace traversal (L1–L4), `BackgroundService` impl, scheduler registration |
| 3 | `tidefs-repair-service/` | RepairService: 5-level priority queue, `ValidityToken` idempotency, source selection, SuspectLog draining |
| 4 | `tidefs-deep-scrub-service/` | DeepScrubService: reconstruction comparison, double-check marginal detection, stripe-ordered cursor |
| 5 | `tidefs-resilver-service/` | ResilverService: `ResilverPlanner` topology-aware stripe list, 5-phase staged rebuild (mounted datasets → snapshots → cold data) |
| 6 | `tidefs-integrity-event/` | `IntegrityEventBus` wiring: `ScrubFinding`, `DeepScrubFinding`, `RepairOutcome`, `ResilverProgress`, `ReadPathCorrection`, `ReadPathUnrepairable` |
| 8 | `tidefs-recovery-loop/` + `tidefs-placement-planner/` + `tidefs-chunk-shipper/` + `tidefs-flow-commit-coordinator/` | Full distributed rebuild/recovery pathway integration: 5-phase recovery loop composition, placement-planner target selection, chunk-shipper transfer pipeline, flow-commit-coordinator receipt bridging |

### Dependency Order

```
Phase 1 (Core Types) ────────────────────────────────────────┐
    │                                                        │
    ├── Phase 2 (ScrubService) ─── depends on core types     │
    │    │                                                   │
    │    ├── Phase 3 (RepairService) ─── SuspectLog from     │
    │    │         Phase 1 + ScrubCursor from Phase 2        │
    │    │                                                   │
    ├── Phase 4 (DeepScrubService) ─── EC crate + cursor     │
    │                                  model from Phase 1     │
    │                                                        │
    └── Phase 5 (ResilverService) ─── topology +             │
         replica-health + source selection from Phase 3       │
                                                             │
Phase 6 (IntegrityEvent bus) ───────────────────────────────┘
    wires all service events, operator surfaces

    cross-service tests, counters, dashboard, deterministic harness
                                                             │
Phase 8 (Distributed Pathway) ───────────────────────────────┘
    recovery loop composition, placement planner, placement planner (data_copy_0), chunk shipper (data_copy_6),
    flow commit coordinator integration across all services
```

### Phase 1 Wire-Up Details (Core Types)

Phase 1 defines the shared type surface across all integrity services:

- `ScrubCursor` — resumable namespace position with BLAKE3-256 hash integrity
- `ScrubCursorRecordV1` — on-media cursor serialization (via `tidefs-binary_schema-*`)
- `SuspectLog` / `SuspectEntry` — single coordination point for scrub→repair handoff
- `ValidityToken` — idempotency binding hash (suspect_entry_id || object_version || commit_group_bound)
- `RepairStrategy` / `RepairOutcome` — existing stable types migrated from `tidefs-local-filesystem`
- `IntegrityCheckpoint` — unified checkpoint for all four service cursors
- Mount-time scratch-scrub types (`ScrubBlockId`, `ScrubBlockKind`) remain in `tidefs-local-filesystem` for boot-time use
- `LossEvent`, `WitnessSet`, `RebuildPriority` → extracted to `tidefs-types-scrub-core/` for cross-crate consumption by repair, resilver, and recovery loop
- Distributed pathway types (`RecoveryPriority`, `RecoveryThrottle`, `CascadingFailureGuard`, `NodeRecoveryBudget`) → defined in `tidefs-types-scrub-core/` or directly in `tidefs-recovery-loop/`

### Phase 2 Wire-Up Details (ScrubService)

Phase 2 introduces the `tidefs-scrub-service` crate with:
- `ScrubJob` implementing `IncrementalJob`
- Scheduler registration in the main daemon bootstrap path
- Namespace traversal across all four levels (Metadata → SystemMetadata → Data → FreeSpace)
- `METADATA_SCRUB_FREQUENCY_MULTIPLIER = 4` enforcing faster metadata passes
- Cursor checkpoint at each commit_group commit boundary
- `ScrubFinding` emission on corruption detection → SuspectLog write → repair enqueue

### Phase 5 Wire-Up Details (ResilverService — 5-Phase Staged Rebuild)

Phase 5 implements the resilver as a staged, priority-sorted rebuild:

1. **Mounted datasets**: active data with highest IO priority; rebuild first to restore user-facing redundancy
2. **Unmounted datasets**: non-active datasets; rebuild after mounted set completes
3. **Snapshots (recent)**: snapshots from the last `SNAPSHOT_RESILVER_WINDOW_DAYS` (default 7)
4. **Snapshots (historical)**: older snapshots; lowest data priority
5. **Cold data and orphan shards**: GC-marked shards and cold tier data; best-effort

Each stage completes before the next begins. Within a stage, stripes are ordered by
data loss risk (fewest remaining replicas first).

## 13. Design Decisions and Tradeoffs

### 13.1 Separate vs. Shared Cursors

**Decision: separate cursors for scrub and deep scrub.**

- Scrub traverses the namespace in object order (metadata → data → free)
- Deep scrub traverses EC stripes in stripe-ID order
- Separate cursors allow independent scheduling frequencies and budget pools
- Tradeoff: two cursors to persist and recover vs. unified scan complexity
- A unified cursor would force deep scrub to follow the scrub namespace order,
  preventing the 30-day interval independence

### 13.2 Suspend Scrub During Resilver vs. Concurrent

**Decision: concurrent execution with budget-based throttling.**

- ZFS suspends scrub because they share a scan thread; tidefs has independent services
- Resilver elevates to Critical when data is at risk, getting 40% of budget
- Scrub continues at Throughput (15%); unused resilver budget cascades to scrub
- Result: less operator-visible disruption; data remains verified during rebuild

### 13.3 Deep Scrub Always-On vs. Opt-In

**Decision: always-on at BestEffort priority.**

- Deep scrub has higher IO cost (k reads per stripe vs 1 per object)
- BestEffort means it only runs when all higher-priority services are idle
- Operators can disable via pool property if IO budget is extremely constrained
- Always-on ensures silent corruption detection without operator intervention

### 13.4 Inline Repair on Read vs. Deferred Repair

**Decision: both paths, with different latency budgets.**

- **Inline (read hot path)**: transparent repair from healthy replica; must complete
  in <1ms to avoid impacting application IO. Falls back to deferred if no fast source.
- **Deferred (repair service)**: tick-driven with budget enforcement; can use
  cross-node sources, reconstruction from EC shards. Suitable for complex repairs.

### 13.5 Resilver Source Selection

**Decision: use same source-selection logic as repair for consistency.**

- For replicated data: read from healthiest replica (lowest latency, verified checksum,
  `ReplicaLagStateRecord::is_current()`)
- For erasure-coded data: reconstruct from k healthiest shards (verified checksums)
- Same `select_best_sources()` function serves both repair and resilver

### 13.6 Local-Filesystem Integration Strategy

**Decision: delegate to service crates; keep local-filesystem as dispatch point.**

- `tidefs-local-filesystem` retains `ScrubBlockId`, `ScrubBlockKind`, `RepairStrategy`,
  `RepairOutcome`, `RepairLog`, `ResolverContext`, and their unit tests as stable core types
- `scrub.rs` functions (`resolve_violation`, `apply_repair_entries`) remain callable
  from service crates via `pub(crate)` visibility and re-export through dedicated
  `scrub_ops` and `repair_ops` modules
- Mount-time scratch-scrub continues to use the local path for simplicity; the
  scheduler-driven services handle online background work
- This avoids a circular dependency: service crates depend on
  `tidefs-local-filesystem` for core types, not vice versa

### 13.7 SuspectLog as Coordination Surface

**Decision: SuspectLog is the single coordination point between scrub, repair, and read path.**

- Scrub writes to SuspectLog on corruption detection
- Repair drains SuspectLog and clears entries on successful repair
- Read path skips inline repair for objects already in SuspectLog (to avoid
  redundant work)
- Validity tokens prevent races between inline and deferred repair on the same entry
- SuspectLog size is monitored; if it exceeds 100k entries, scrub is throttled
  and operator is alerted

## 14. Failure Mode Analysis

| Failure | Detection | Response |
|---------|-----------|----------|
| Silent shard corruption (valid checksum) | Deep scrub reconstruction comparison | Mark all shards suspect; repair from known-good devices |
| Read instability (marginal media) | Deep scrub double-check mode | Mark shard suspect; relocate to healthy media |
| Repair loop (repaired data re-corrupts) | Repair counter threshold (5 attempts) | Escalate to operator; mark device as suspect |
| Resilver stalled (no healthy sources) | Stuck-in-progress timeout (24h) | Escalate to operator; data loss notification |
| Cursor corruption | Cursor hash verification on load | Discard cursor; restart pass from beginning |
| SuspectLog overflow | SuspectLog size monitoring (>100k entries) | Throttle scrub; escalate to operator |
| Budget starvation (repair dominates) | Scheduler cycle stats | Operator tuning; repair rate limiting |
| Token race (inline vs deferred repair) | ValidityToken binding hash | Loser discovers token invalid; task skipped |
| Topology change during resilver | Topology version check each tick | Re-plan if topology version changed |
| Encode-path bug (all shards wrong) | Deep scrub digestion comparison | All shards suspect; escalate to operator; data loss possible |

## 15. Deterministic Constraint Knobs

| Constant | Default | Meaning |
|----------|---------|---------|
| `SCRUB_MAX_ITEMS_PER_TICK` | 1000 | Max objects verified per scrub tick |
| `DEEP_SCRUB_MAX_STRIPES_PER_TICK` | 100 | Max stripes verified per deep scrub tick |
| `REPAIR_MAX_TASKS_PER_TICK` | 50 | Max repairs executed per tick |
| `RESILVER_MAX_STRIPES_PER_TICK` | 100 | Max stripes rebuilt per resilver tick |
| `RESILVER_MAX_BYTES_PER_TICK` | 64 MiB | Max bytes transferred per resilver tick |
| `RESILVER_MAX_IO_OPS_PER_TICK` | 1000 | Max I/O ops per resilver tick |
| `SCRUB_PASS_INTERVAL_HOURS` | 168 | Hours between full scrub passes (7 days) |
| `DEEP_SCRUB_PASS_INTERVAL_HOURS` | 720 | Hours between full deep scrub passes (30 days) |
| `METADATA_SCRUB_FREQUENCY_MULTIPLIER` | 4 | Metadata scrubbed N× more often than data |
| `RESILVER_CRITICAL_THRESHOLD` | 1 | Remaining replicas below which resilver elevates to Critical |
| `MAX_REPAIR_RETRIES` | 5 | Max repair attempts before escalation |
| `SUSPECT_LOG_MAX_ENTRIES` | 100000 | Max SuspectLog entries before throttling |
| `RESILVER_STALL_TIMEOUT_HOURS` | 24 | Hours before stalled resilver escalates |

## 16. Error Hierarchy

```rust
pub enum ScrubError {
    /// Object could not be read from storage.
    ReadFailed { object_id: u64, reason: String },

    /// Checksum verification revealed corruption.
    CorruptionDetected {
        object_id: u64,
        expected: [u8; 32],
        actual: [u8; 32],
    },

    /// Cursor could not be persisted.
    CursorPersistFailed { reason: String },

    /// Scrub pass was aborted (e.g., pool export).
    PassAborted { reason: String },
}

pub enum RepairError {
    /// No healthy source available for reconstruction/replication.
    NoHealthySource { suspect_id: u64 },

    /// Reconstruction failed (not enough shards).
    ReconstructionFailed { stripe_id: StripeId, available: usize, needed: usize },

    /// Write of repaired data failed.
    WriteFailed { location: ShardLocation, reason: String },

    /// SuspectLog update failed.
    SuspectLogUpdateFailed { reason: String },
}

pub enum ResilverError {
    /// Plan building failed.
    PlanBuildFailed { reason: String },

    /// Stripe rebuild failed.
    StripeRebuildFailed { stripe_id: StripeId, reason: String },

    /// Topology changed during resilver.
    TopologyChanged { reason: String },

    /// Not enough healthy shards to rebuild.
    NotEnoughShards { stripe_id: StripeId, available: usize, needed: usize },
}
```

## 17. References

- [#2055] This design spec (current canonical tracking issue; supersedes #1948, #1917) — full distributed rebuild/recovery pathway integration; deferred Rust implementation plan
- [#1948] This design spec (prior canonical tracking issue; superseded by #2055)
- [#1917] This design spec (prior canonical tracking issue; superseded by #1948)
- [#1917] This design spec (prior canonical tracking issue for scrub/deep-scrub/repair/resilver orchestration design; refined with P8-03 distributed rebuild/recovery integration)
- [#1705], [#1739], [#1836] Prior iterations of this design

- [#1549] Background service framework — all services implement `BackgroundService`
- [#1564] End-to-end checksum architecture — `IntegrityTrailerV2`, BLAKE3-256, SuspectLog
- [#1249] Erasure coding and CRUSH-like placement — reconstruction, shard location
- [#1286] Shard groups, replicas, and rebake pathway — source selection
- [#1254] Pool import/export and topology management — resilver placement
- [#1180] Refcount delta cleanup queues — data cleaner interaction
- [#110] Online verifier — non-mutating committed-root verification
- [#827] Structural observability — counter emission
- `docs/design/background-service-framework-design.md`
- `docs/design/end-to-end-checksum-architecture.md`
- `docs/design/shard-groups-replicas-rebake-pathway.md`
- `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md`
- `docs/LOCK_HIERARCHY_AND_CONCURRENCY_MODEL.md`
- Existing code: `crates/tidefs-local-filesystem/src/scrub.rs` (612 lines)
- Existing code: `crates/tidefs-local-filesystem/src/repair.rs` (633 lines)
- Existing code: `crates/tidefs-local-filesystem/src/recovery.rs` (1769 lines)
- Existing code: `crates/tidefs-background-scheduler/src/lib.rs` (1410 lines)
- Existing code: `crates/tidefs-erasure-coding/src/lib.rs` (821 lines)
- Existing code: `crates/tidefs-erasure-coded-store/src/lib.rs` (953 lines)
- Existing code: `crates/tidefs-replica-health/src/` (2378 lines across 8 modules: tracker, flap_detector, adaptive_timeout, health_state, lag, suspicion, propagation, lib)
- Existing code: `crates/tidefs-incremental-job-core/src/lib.rs` (992 lines)
- Existing code: `crates/tidefs-rebuild-planner/src/lib.rs` (2495 lines)
- Existing code: `crates/tidefs-recovery-loop/src/lib.rs` (849 lines)
- Existing code: `crates/tidefs-anti-entropy-auditor/src/lib.rs` (anti-entropy auditor)
- [#895] Distributed replica-health tracker — `ReplicaHealthTracker`, flap detection, adaptive timeouts
- [#893] Rebuild planner — loss-event flow orchestration, witness-set batch scheduling
- [#901] Recovery loop — 5-phase continuous recovery cycle with adaptive throttling
- P8-03 data_copy_0 Placement planner — `compute_replica_target_set()` with anti-affinity
- P8-03 data_copy_6 Chunk shipper — staged buffer lifecycle, transport selection, receipt emission
- P8-03 data_copy_7 Flow commit coordinator — transfer→verify→place receipt bridging
- `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md`
- [P8-03 data_copy_8] Anti-entropy auditor — periodic cross-node consistency comparison, orphan detection, missing-replica detection
- `docs/design/pool-import-export-device-topology-management.md`
- `docs/design/production-erasure-coding-crush-placement-g4-pillar.md`

## 18. Deferred Rust Implementation Plan

This section defines the concrete implementation units deferred to
subsequent wire-up issues. Each unit maps to a single crate, a bounded
set of public types, and a specific integration surface. The plan is
ordered by dependency, not by priority; the background service framework
(#1549) and incremental-job core crate (already implemented) are the
assumed base layer.

### 18.1 Implementation Units

#### U1: Scrub Service Crate (`tidefs-scrub-service`)

| Aspect | Detail |
|--------|--------|
| **New crate** | `crates/tidefs-scrub-service/` |
| **Depends on** | `tidefs-background-scheduler`, `tidefs-incremental-job-core`, `tidefs-local-object-store`, `tidefs-local-filesystem` (types only) |
| **Public types** | `ScrubService`, `ScrubJob`, `ScrubCursor`, `ScrubCursorRecordV1`, `ScrubConfig`, `ScrubStats` |
| **Implements** | `IncrementalJob` trait (via `IncrementalJobAdapter`) |
| **Key algorithm** | §4.1 scrub tick with BLAKE3-256 domain-separated checksum verification |
| **Integration** | Reads `IntegrityTrailerV2` from `tidefs-local-object-store`; writes `ScrubFinding` to `IntegrityEventBus`; enqueues repair via `SuspectLog` |
| **Persists** | `ScrubCursor` via pool map journal at commit_group commit boundary |
| **Lines est.** | ~800–1000 (cursor, tick loop, checkpoint, observability) |

#### U2: Deep Scrub Service Crate (`tidefs-deep-scrub-service`)

| Aspect | Detail |
|--------|--------|
| **New crate** | `crates/tidefs-deep-scrub-service/` |
| **Depends on** | `tidefs-background-scheduler`, `tidefs-incremental-job-core`, `tidefs-erasure-coding`, `tidefs-erasure-coded-store`, `tidefs-local-object-store` |
| **Public types** | `DeepScrubService`, `DeepScrubJob`, `DeepScrubConfig`, `DeepScrubStats` |
| **Implements** | `IncrementalJob` trait |
| **Key algorithm** | §5.1 stripe reconstruction via `ErasureShard::reconstruct()` + shard-level `IntegrityTrailerV2` verification |
| **Integration** | Reads `StripeConfig` from `tidefs-erasure-coding`; uses `reconstruct()` to rebuild from k shards; emits `DeepScrubFinding` |
| **Persists** | Separate `DeepScrubCursor` (stripe-ID ordered, independent of `ScrubCursor` per §3.4) |
| **Lines est.** | ~700–900 (cursor, stripe iterator, reconstruction verification) |

#### U3: Repair Service Crate (`tidefs-repair-service`)

| Aspect | Detail |
|--------|--------|
| **New crate** | `crates/tidefs-repair-service/` |
| **Depends on** | `tidefs-background-scheduler`, `tidefs-incremental-job-core`, `tidefs-replica-health`, `tidefs-rebuild-planner`, `tidefs-placement-planner`, `tidefs-chunk-shipper`, `tidefs-flow-commit-coordinator`, `tidefs-erasure-coding` |
| **Public types** | `RepairService`, `RepairJob`, `RepairResolver`, `RepairConfig`, `RepairStats`, `RepairPriority` |
| **Implements** | `IncrementalJob` trait |
| **Key algorithm** | §6.3 repair tick with validity-token stale-task prevention and COMMIT_GROUP-gated write barriers (§2.9) |
| **Integration** | Drains `SuspectLog`; resolves `RepairStrategy` via `ResolverContext`; delegates source selection to `ReplicaHealthTracker`; delegates rebuild execution to `RebuildPlanner` (§2.5); ships chunks via `ChunkShipper`; commits via `FlowCommitCoordinator`; clears suspect entries on success |
| **Persists** | `RepairCursor` tracking last-processed SuspectLog entry |
| **Lines est.** | ~1000–1300 (suspect-log drain, strategy resolution, retry logic, cross-node coordination) |

#### U4: Resilver Service Crate (`tidefs-resilver-service`)

| Aspect | Detail |
|--------|--------|
| **New crate** | `crates/tidefs-resilver-service/` |
| **Depends on** | `tidefs-background-scheduler`, `tidefs-incremental-job-core`, `tidefs-replica-health`, `tidefs-rebuild-planner`, `tidefs-placement-planner`, `tidefs-chunk-shipper`, `tidefs-flow-commit-coordinator`, `tidefs-erasure-coding`, `tidefs-erasure-coded-store`, `tidefs-membership-epoch` |
| **Public types** | `ResilverService`, `ResilverJob`, `ResilverPlanner`, `ResilverCursor`, `ResilverConfig`, `ResilverStats`, `StripePlan` |
| **Key algorithm** | §7.2 stripe rebuild with topology-aware source selection, tiered transport, and priority escalation (§7.5) |
| **Integration** | Builds `StripePlan[]` from `pool_topology` and `failed_devices`; uses `ReplicaLagTracker` for bandwidth-aware source selection; delegates target placement to `PlacementPlanner`; ships via `ChunkShipper`; commits via `FlowCommitCoordinator` |
| **Persists** | `ResilverCursor` with `plan_generation` for topology-change detection |
| **Lines est.** | ~900–1200 (plan builder, stripe iterator, priority escalation, checkpoint) |

#### U5: Integrity Event Bus & Observability Wiring

| Aspect | Detail |
|--------|--------|
| **Modify** | `tidefs-local-filesystem` (existing `scrub.rs` types), `tidefs-observe-core-runtime` |
| **Public types** | `IntegrityEvent`, `ScrubFindingKind`, `DeepScrubFindingKind`, `IntegrityEventBus` |
| **Scope** | §8 unified event model: `ScrubFinding`, `DeepScrubFinding`, `RepairOutcome`, `ResilverProgress`, `ReadPathCorrection`, `ReadPathUnrepairable`, `ServiceStateChange` |
| **Counters** | §8.2: 12 structured counters across all four services |
| **Dead-letter audit** | §8.3: event-tombstone log with configurable TTL |
| **Lines est.** | ~400–600 (event type definitions, bus wiring, counter registration) |

#### U6: Deterministic Constraint Knobs & Config Surface

| Aspect | Detail |
|--------|--------|
| **Modify** | Each new service crate adds its own config module |
| **Constants** | §9 tunable knobs: `SCRUB_PASS_INTERVAL_HOURS`, `DEEP_SCRUB_PASS_INTERVAL_HOURS`, `METADATA_SCRUB_FREQUENCY_MULTIPLIER`, `RESILVER_CRITICAL_THRESHOLD`, `MAX_REPAIR_RETRIES`, `SUSPECT_LOG_MAX_ENTRIES`, `RESILVER_STALL_TIMEOUT_HOURS` |
| **Distributed knobs** | §2.6.10: `RECOVERY_MAX_CONCURRENT_PER_DOMAIN`, `RECOVERY_MAX_AGGREGATE_LOAD`, `RECOVERY_BANDWIDTH_BUDGET_BYTES`, `RECOVERY_CLIENT_LATENCY_THRESHOLD`, `RECOVERY_THROTTLE_AGGRESSIVENESS`, `WITNESS_SET_MIN_VERIFIED_SOURCES`, `REBUILD_BATCH_MAX_CHUNKS`, `CHUNK_SHIPPER_STAGING_TIMEOUT_MS`, `FLOW_COMMIT_BATCH_SEAL_TIMEOUT_MS` |
| **Anti-entropy knobs** | §2.7.3: `AE_QUICK_COMPARE_INTERVAL_HOURS`, `AE_FULL_COMPARE_INTERVAL_HOURS`, `AE_DEEP_COMPARE_INTERVAL_HOURS`, `AE_MAX_CHUNKS_PER_TICK`, `AE_QUICK_COMPARE_WINDOW_HOURS`, `AE_DIVERGENCE_RETRY_COUNT` |
| **Lines est.** | ~200–300 (constants + `ServiceConfig` per crate) |

#### U7: SuspectLog Persistence Layer

| Aspect | Detail |
|--------|--------|
| **Modify** | `tidefs-local-filesystem` || **New** `crates/tidefs-suspect-log` |
| **Types** | `SuspectLog`, `SuspectEntry`, `SuspectLogCursor`, `SuspectLogSummary` |
| **Persistence** | Pool map journal at commit_group commit; `SuspectEntry` carries `commit_group_minted`, `validity_token` (BLAKE3-256 binding hash), `chunk_id`, `severity`, `retry_count` |
| **Staleness check** | §6.3, §2.9: `validity_token.is_stale()` — rejected when chunk version > entry `commit_group_minted` |
| **Throttling** | §9 `SUSPECT_LOG_MAX_ENTRIES` = 100000; beyond limit, suspect log emits `SuspectLogFull` alert and pauses non-critical scrub |
| **Lines est.** | ~500–700 (entry format, persistence, staleness, throttling) |

#### U8: Device Marginal-Media Detection Integration

| Aspect | Detail |
|--------|--------|
| **Modify** | `tidefs-deep-scrub-service` + `tidefs-replica-health` |
| **Types** | `MarginalMediaEvent`, `DeviceHealthDegradation`, `AdaptiveReadVerification` |
| **Algorithm** | §10: sliding 256-sample window; moving-average latency + error rate; emit `MarginalMediaDetection` when 10% of samples exceed latency threshold or error rate > 1%; `replica_health.mark_device_degrading()` |
| **Counter** | `deep_scrub.marginal_detections` |
| **Lines est.** | ~300–400 (window tracker, threshold logic, health integration) |

#### U9: Cross-Service Work Orchestration

| Aspect | Detail |
|--------|--------|
| **Modify** | `tidefs-background-scheduler` (minor) |
| **New logic** | Scheduler registration per §2.3; budget allocation with escalation rules (§2.1); cascade recipient spillover (§11.2); cluster-wide admission control (§11.1) |
| **Registration** | `ScrubService` → `Throughput` (15%), `DeepScrubService` → `BestEffort` (10%), `RepairService` → `Critical` (40%), `ResilverService` → `Throughput` (15%) with Critical escalation |
| **Lines est.** | ~400–600 (registration, budget enforcement, escalation, admission control) |

#### U10: End-to-End Distributed Recovery Integration Tests

| Aspect | Detail |
|--------|--------|
| **Crate** | `tidefs-test-harness`, historical chaos-campaign package (no current package) |
| **Scenarios** | §11: checksum corruption → suspect log → repair → health restoration; deep scrub encode divergence detection; device marginal-media alarm; cascading-failure guard backpressure; ResilverCritical escalation; node failure → loss event → rebuild flow; COMMIT_GROUP write barrier stale-write rejection; anti-entropy audit three-source divergence resolution; inline read-path repair transparent correction; EC reconstruction from degraded shards |
| **Deterministic simulation** | §11.3: `tidefs-trace-oracle`— deterministically replayable cluster simnet with crash injection |
| **Lines est.** | ~800–1200 (test infrastructure, scenario definitions, assertions) |

### 18.2 Implementation Dependency Graph

```
  U6 (Config knobs) ───────────────────────────────────────┐
  U7 (SuspectLog) ─────────────────────────────────────────┤
  U5 (IntegrityEventBus) ──────────────────────────────────┤
                                                            │
  U1 (ScrubService) ──┬── U3 (RepairService) ──────────────┤
                      │       │                             │
  U2 (DeepScrubSvc) ──┘       ├── U4 (ResilverService) ────┤
                              │       │                     │
                              │       └── U8 (MarginalMedia)┤
                              │                             │
                              └── U9 (Work Orchestration) ──┤
                                                            │
                                          U10 (Integration tests)
```

- **U1–U3** can be implemented in parallel once U5, U6, U7 are complete.
- **U4** (resilver) requires U3 (repair) for shared rebuild/placement/shipping infrastructure.
- **U8** (marginal media) is a deep-scrub augmentation that can be added late.
- **U9** (orchestration) wires existing scheduler crate; minimal new code.
- **U10** (integration tests) gates overall correctness; runs last.

### 18.3 Estimated Total New Code

| Layer | Units | Est. Lines |
|-------|-------|------------|
| Foundation (config, SuspectLog, event bus) | U5, U6, U7 | 1100–1600 |
| Core services (scrub, deep scrub, repair, resilver) | U1, U2, U3, U4 | 3400–4400 |
| Augmentation (marginal media, orchestration wiring) | U8, U9 | 700–1000 |
| Integration tests | U10 | 800–1200 |
| **Total** | | **6000–8200** |

### 18.4 Deferred-Implementation Rust Type Contracts

The following type contracts are frozen by this design spec and must be
preserved by Rust implementations. Changing these contracts requires a
design-spec revision.

#### Public Trait Signatures (Frozen)

```rust
// tidefs-background-scheduler (already implemented)
pub trait BackgroundService: Send + Sync {
    fn name(&self) -> &str;
    fn priority(&self) -> ServicePriority;
    fn tick(&mut self, budget: ServiceBudget) -> TickReport;
    fn checkpoint(&self) -> Option<ServiceCheckpoint>;
    fn resume(&mut self, checkpoint: ServiceCheckpoint) -> Result<()>;
}

// tidefs-incremental-job-core (already implemented)
pub trait IncrementalJob: Send {
    fn tick(&mut self, budget: ServiceBudget) -> TickReport;
    fn checkpoint(&self) -> Option<Checkpoint>;
    fn resume(&mut self, checkpoint: Checkpoint) -> Result<(), ResumeError>;
    fn progress(&self) -> JobProgress;
}
```

#### Key Frozen Data Structures

```rust
// §3.2 — Scrub cursor (persisted in pool map journal)
pub struct ScrubCursor {
    pub level: ScrubLevel,
    pub dataset_id: Option<u64>,
    pub inode_id: Option<u64>,
    pub extent_offset: Option<u64>,
    pub cursor_hash: [u8; 32],    // BLAKE3-256
}

// §7.4 — Resilver cursor
pub struct ResilverCursor {
    pub plan_generation: u64,
    pub last_stripe_id: Option<u64>,
    pub stripes_completed: u64,
    pub bytes_rebuilt: u64,
    pub cursor_hash: [u8; 32],
}

// §2.6.7 — Witness set (source selection)
pub struct WitnessSet {
    pub verified_sources: Vec<MemberId>,
    pub degraded_sources: Vec<MemberId>,
    pub unavailable_sources: Vec<MemberId>,
}

// §8.1 — Unified integrity event
pub enum IntegrityEvent {
    ScrubFinding { object_id: u64, level: ScrubLevel, finding: ScrubFindingKind, timestamp: CommitGroupInstant },
    DeepScrubFinding { stripe_id: StripeId, shard_index: usize, finding: DeepScrubFindingKind, timestamp: CommitGroupInstant },
    RepairOutcome { object_id: u64, strategy: RepairStrategy, outcome: Result<(), RepairError>, elapsed_ms: u64 },
    ResilverProgress { plan_generation: u64, stripes_completed: u64, total_stripes: u64, bytes_rebuilt: u64 },
    ReadPathCorrection { object_id: u64, source: ChunkId, elapsed_us: u64 },
    ReadPathUnrepairable { object_id: u64, reason: String },
    ServiceStateChange { service: ServiceKind, from: ServiceState, to: ServiceState },
}
```

These type signatures are non-negotiable for wire-up issues. Field order
and representation are frozen; implementations may add private fields but
must not remove or reorder public fields without a design amendment.

### 18.5 Tradeoffs and Risks

| Tradeoff | Decision | Rationale |
|----------|----------|-----------|
| Four crates vs. monolith | Four independent service crates | Aligns with background-service framework; independent testability; no single-crate churn bottleneck |
| `Vec<u8>` staging buffers vs. loaned pages | `Vec<u8>` for deterministic model; loaned pages for production (P4-04) | Deterministic testing requires owned buffers; production zero-copy law overrides at build time |
| SuspectLog in pool map journal vs. separate WAL | Pool map journal | Single journal simplifies commit_group-consistent checkpoint; SuspectLog entries are low-volume (~hundreds, not millions) |
| Repair source selection: health-tracker-driven vs. static preference list | Health-tracker-driven with `WitnessSet` | Adaptive to transient failures; `FlapDetector` prevents repair cascades; `ReplicaLagTracker` prioritizes freshest sources |
| `CascadingFailureGuard` per-domain + aggregate vs. global admission only | Per-domain + aggregate | Prevents single-rack saturation during multi-domain recovery; global cap as safety net |
| Anti-entropy auditor at `BestEffort` vs. higher priority | `BestEffort` (shared 10% with deep scrub) | AE is a slow safety net; scrub/repair provide real-time detection; false divergence is operator-actionable, not automated |
| Write fencing range scope vs. per-chunk | Both; `RangeFence` for resilver, `ChunkFence` for repair (§2.9) | Range fence prevents races during bulk resilver; per-chunk fence is lighter for single-object repair |
