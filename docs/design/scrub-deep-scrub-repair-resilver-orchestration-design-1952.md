# Scrub, Deep Scrub, Repair, and Resilver Orchestration Design

Maturity: **design-spec** — Rust implementation deferred to wire-up issues.
Closes: #1952

Full distributed rebuild/recovery pathway integration across the P8-03
canonical data-flow infrastructure: the continuous failure recovery loop
(#901), replica-health tracker (#895), rebuild planner (#893), placement
planner (data_copy_0), chunk shipper (data_copy_6), flow-commit
coordinator (data_copy_7), and anti-entropy auditor (data_copy_8).
Scrub/repair/resilver findings flow through canonical P8-03 loss-event →
rebuild-flow → transfer-verify-place chains.

Superseded designs: #1705, #1739, #1836, #1841, #1885, #1913, #1917,
#1948, #2055, #1957.

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
per-OSD backfill, and per-PG deep scrub — three separate systems with no
unified resource model.

TideFS unifies all four under the background service framework, with
independent per-service budgets, priority staging, validity-token
stale-task prevention, and comprehensive observability.

### Dependency Map

| Design | Relationship |
|--------|-------------|
| Background service framework (#1549) | All four services implement `BackgroundService` |
| End-to-end checksum architecture (#1564) | Scrub/repair verify `IntegrityTrailerV2` (BLAKE3-256); repair clears suspect entries |
| Erasure coding and placement (#1249) | Deep scrub and repair use reconstruction for shard-level recovery |
| Shard groups and replicas (#1286) | Repair selects source replicas; resilver places new replicas |
| Pool topology management (#1254) | Resilver schedules placement across new topology |
| Refcount delta cleanup (#1180) | Data cleaner may trigger verification on unlinked blocks |
| Anti-entropy auditor (data_copy_8) | Cross-node consistency verification for silent corruption |

## 2. Architecture

### 2.1 Service Taxonomy and Budget Allocation

| Service | Priority | Budget % | Escalation Rule | Concurrency |
|---------|----------|----------|-----------------|-------------|
| ScrubService | Throughput | 15% | Cascade recipient; paused when Repair Critical | Single-pass, single-threaded |
| DeepScrubService | BestEffort | 10% | Paused when Repair or Resilver Critical; shares AE budget | Single-pass, single-threaded |
| RepairService | Critical | 30% | Escalates to 50% when SuspectLog depth > threshold | Multi-worker (domain-scoped) |
| ResilverService | Throughput | 15% | Escalates to 90% when stage == MetadataCritical or DegradedUrgent | Multi-worker (staged) |

Remaining 30% reserved for other background services (cleanup, reclaim,
GC, admin). During Critical resilver stage: scrub is paused (0%), deep
scrub is paused (0%), repair is limited to urgent-only (5%), resilver
gets 90%, admin/liveness gets 5%.

### 2.2 High-Level Data Flow

```
┌──────────────────────────────────────────────────────┐
│                   Replica Health Tracker             │
│        (per-chunk health, lag, flap detection)       │
└──────────────┬───────────────────┬───────────────────┘
               │                   │
    ┌──────────▼──────────┐  ┌─────▼──────────────────┐
    │   Anti-Entropy      │  │    Recovery Loop       │
    │   Auditor           │  │    (5-phase continuous) │
    │   6-state machine   │  │    Detect→Scope→Plan   │
    │   scan scheduler    │  │    →Execute→Verify      │
    │   digest comparator │  │                         │
    └──────────┬──────────┘  └─────────┬───────────────┘
               │                       │
               │ divergences           │ orchestration
               │ (ticketable)          │ (phase gating)
               │                       │
    ┌──────────▼───────────────────────▼──────────────┐
    │              Rebuild Planner (#893)              │
    │  6-state rebuild flow:                          │
    │  Open→Planning→Transferring→Verifying→Restored  │
    │  Loss-event scoping, witness-set scheduling     │
    └──────────┬───────────────────────┬──────────────┘
               │                       │
    ┌──────────▼──────────┐  ┌─────────▼───────────────┐
    │  Placement Planner  │  │  SuspectLog             │
    │  anti-affinity      │  │  authoritative record   │
    │  target selection   │  │  of corruption findings │
    │  tier-aware         │  │  validity-token gating  │
    └──────────┬──────────┘  └─────────────────────────┘
               │
    ┌──────────▼──────────────────────────────────────┐
    │            Chunk Shipper + Flow Commit           │
    │  Staging → Transport → Verification → Placement  │
    │  Receipt-backed transfer chain                   │
    └──────────────────────────────────────────────────┘
```

### 2.3 End-to-End Integrity Guarantee Chain

For a repaired chunk, the full integrity chain is:

1. Scrub/DeepScrub detects corruption
2. SuspectLog: authoritative record of finding with `validity_token`
3. ReplicaHealthTracker: per-chunk health → suspect
4. RecoveryLoop: detect → scope as LossEvent
5. RebuildPlanner: open rebuild flow, select witness sources
6. CascadingFailureGuard: domain-aware admission
7. RebuildPlanner: schedule witness-set batches
8. PlacementPlanner: anti-affinity target selection
9. ChunkShipper: stage → transport → ReplicaTransferReceipt
10. FlowCommitCoordinator: digest/witness/range verification
11. FlowCommitCoordinator: ReplicaVerificationReceipt emitted
12. FlowCommitCoordinator: ReplicaPlacementReceipt emitted
13. AntiEntropyAuditor: cross-node consistency verification
14. ReplicaHealthTracker: clear suspect → mark healthy
15. SuspectLog: clear entry — authoritative: corruption resolved

Every step has an explicit, receipt-backed record.

### 2.4 Distributed Write Consistency (COMMIT_GROUP-Gated Write Barriers)

When repair writes to a remote node, a COMMIT_GROUP-gated write barrier prevents
the classic race:

```
T1: Repair reads chunk C version v3 from source S
T2: Application writes chunk C version v4 to source S and target T
T3: Repair writes chunk C version v3 to target T → STALE REJECTED
```

The repair write carries a `commit_group_bound` derived from the SuspectLog entry's
minting transaction group. The target node rejects writes when
`chunk_version.committed_at_commit_group > commit_group_bound`. If the newer version is
healthy, the SuspectLog entry is cleared (implicit repair). If corrupt,
a fresh entry is created at the current commit_group.

Write fencing levels:

| Fence type | Scope | Duration | Write behavior |
|------------|-------|----------|----------------|
| PerChunk | Single chunk | <1s (one repair tick) | Application writes blocked |
| StripeFence | EC stripe | ~100ms | Application writes blocked |
| RangeFence | Contiguous chunk range | Until resilver pass completes | Application writes journaled |
| NodeFence | All chunks on one node | Until node is restored | Application writes redirected to other replicas |

## 3. Data Structures

### 3.1 LossEvent (Rebuild Trigger)

```rust
pub struct LossEvent {
    pub loss_event_id: u64,               // unique event identifier
    pub loss_class: LossEventClass,       // node failure, disk failure, corruption, etc.
    pub degraded_class: RebuildDegradedClass, // severity of degradation
    pub scope: FlowScopeSelector,         // affected subjects/domains/cohort
    pub lost_members: Vec<MemberId>,      // rebuild targets
    pub detected_epoch: u64,              // epoch when loss was detected
    pub detected_at_ns: u64,              // detection timestamp (ns)
    pub lag_records: Vec<ReplicaLagStateRecord>, // candidate source evaluation
    pub available_members: BTreeMap<MemberId, HealthClass>, // available + health
    pub affected_chunk_count: u64,        // capacity planning
    pub affected_bytes: u64,              // total bytes needing rebuild
}
```

### 3.2 WitnessSet (Source Selection)

```rust
pub struct WitnessSet {
    pub verified_sources: Vec<MemberId>,    // healthy, receipt-backed
    pub degraded_sources: Vec<MemberId>,    // degraded but valid
    pub unavailable_sources: Vec<MemberId>, // stale or unreachable
}
```

Deterministic construction guarantees:

- **G1.** For fixed inputs, output is bit-identical across callers.
- **G2.** `verified_sources` contains only healthy, non-flapping replicas.
- **G3.** `|verified_sources| >= ec_params.k` or `>= 1` for replicated.
- **G4.** `degraded_sources` may be used as fallback.
- **G5.** Selection is stable under health improvements.

Algorithm: sort by `BLAKE3(concat(member_id, plan_gen))`, partition by
health class, select verified sources, promote from degraded if needed.

### 3.3 SuspectLog

```rust
pub struct SuspectEntry {
    pub entry_id: u64,
    pub commit_group_minted: u64,            // transaction group that discovered corruption
    pub validity_token: [u8; 32],   // BLAKE3-256 binding hash
    pub chunk_id: u64,
    pub severity: SuspectSeverity,
    pub retry_count: u32,
    pub finding_kind: SuspectFindingKind, // checksum, size, missing, orphan
}

impl SuspectEntry {
    pub fn is_stale(&self, current_chunk_commit_group: u64) -> bool {
        current_chunk_commit_group > self.commit_group_minted
    }
}
```

Persists to pool map journal at commit_group commit boundary. Maximum
`SUSPECT_LOG_MAX_ENTRIES` = 100,000; beyond limit, emits
`SuspectLogFull` alert and pauses non-critical scrub.

### 3.4 ScrubCursor and ResilverCursor

```rust
pub struct ScrubCursor {
    pub last_object_key: u64,       // resume point in namespace order
    pub pass_id: u64,               // incrementing pass identifier
    pub bytes_verified: u64,        // cumulative bytes
    pub errors_found: u64,          // cumulative error count
    pub started_at_commit_group: u64,        // commit_group at pass start
    pub checkpoint_commit_group: u64,        // commit_group at last checkpoint
}

pub struct ResilverCursor {
    pub current_stripe_id: u64,     // resume point in stripe order
    pub plan_generation: u64,       // topology generation for plan validity
    pub stage: ResilverStage,       // MetadataCritical | DegradedUrgent | UserData(u64) | ArchiveBackground
    pub stripes_restored: u64,      // progress counter
    pub bytes_restored: u64,        // cumulative bytes
}
```

### 3.5 Recovery Priority and Phase

```rust
pub enum RecoveryPriority {
    SteadyReplication = 0,     // normal steady-state replication
    CatchupRepair = 1,         // replica lagging, quorum intact
    LossRebuild = 2,           // durability at risk, quorum may be degraded
}

pub enum RecoveryPhase {
    Detect, Scope, Plan, Execute, Verify,
}
```

### 3.6 Rebuild Flow State Machine (6 states)

```rust
pub enum RebuildFlowState {
    Open,            // flow created from LossEvent
    Planning,        // witness-set and batch planning
    Transferring,    // chunks in flight via ChunkShipper
    Verifying,       // digest/witness verification in FlowCommitCoordinator
    Restored,        // all chunks verified and placed
    // Exception paths:
    BlockedNoSource,   // no healthy source available
    BlockedNoTarget,   // no placement target available
    BlockedNoCapacity, // insufficient space on targets
    Cancelled,         // administrative cancellation
}
```

### 3.7 Anti-Entropy Auditor State Machine (6 states)

```rust
pub enum AntiEntropyState {
    Idle,              // no scan in progress
    Enumerate,         // collecting subjects for this cycle
    Compare,           // comparing digests across replicas
    DivergenceFound,   // differences detected, building DivergenceRecord
    Ticketed,          // divergences ticketed for repair
    Resolved,          // all divergences resolved this cycle
}
```

### 3.8 Cross-Service Type Mapping

| Domain Concept | Source Crate | Key Type |
|---------------|-------------|----------|
| Checksum verification | `tidefs-local-object-store` | `IntegrityTrailerV2` |
| Erasure coding | `tidefs-erasure-coding` | `StripeConfig`, `ErasureShard`, `Reconstruction` |
| Health tracking | `tidefs-replica-health` | `ReplicaHealthTracker`, `FlapDetector`, `ReplicaLagStateRecord` |
| Rebuild planning | `tidefs-rebuild-planner` | `LossEvent`, `WitnessSet`, `RebuildFlowRecord` |
| Recovery loop | `tidefs-recovery-loop` | `RecoveryLoop`, `RecoveryThrottle`, `RecoveryPriority` |
| Placement | `tidefs-placement-planner` | `compute_replica_target_set()`, `FailureDomainPlacementPlan` |
| Transfer | `tidefs-chunk-shipper` | `ChunkShipper`, `ChunkStagingBuffer`, transport selection |
| Commit | `tidefs-flow-commit-coordinator` | `FlowCommitCoordinator`, `TrackedChunk`, `TrackedBatch` |
| Audit | `tidefs-anti-entropy-auditor` | `AntiEntropyAuditor`, `DivergenceRecord` |
| Scheduling | `tidefs-background-scheduler` | `IncrementalJobAdapter`, `ServiceBudget`, `ServicePriority` |

## 4. Algorithms

### 4.1 Scrub Tick

```
Function: scrub_tick(budget) -> TickReport

1. LOAD cursor from pool journal
2. SCAN local object store starting at cursor.last_object_key
3. FOR each object within budget:
     a. VERIFY IntegrityTrailerV2.checksum against BLAKE3-256 re-computation
        (domain-separated: "tidefs-scrub-checksum-v1")
     b. IF mismatch:
          INSERT SuspectEntry into SuspectLog
          EMIT IntegrityEvent::ScrubFinding
          CALL replica_health.mark_shard_suspect(chunk_id)
     c. ADVANCE cursor
4. IF budget exhausted:
     PERSIST cursor at commit_group commit boundary
     RETURN TickReport { objects_verified, errors_found, cursor }
5. IF end of namespace reached:
     INCREMENT cursor.pass_id
     RESET cursor.last_object_key
     RETURN TickReport { complete_pass: true, ... }
```

### 4.2 Deep Scrub Tick

```
Function: deep_scrub_tick(budget) -> TickReport

1. LOAD deep_scrub_cursor from pool journal
2. SCAN EC stripes starting at cursor.current_stripe_id
3. FOR each stripe within budget:
     a. FETCH shards from k healthy replicas (via ReplicaHealthTracker)
     b. CALL ErasureShard::reconstruct() to rebuild full stripe
     c. RECOMPUTE BLAKE3-256 over reconstructed data
        (domain-separated: "tidefs-deep-scrub-checksum-v1")
     d. COMPARE against stored IntegrityTrailerV2 on each shard
     e. IF mismatch:
          CLASSIFY as:
            - SingleShardCorrupt: one shard differs, k others match
            - MultiShardCorrupt: multiple shards differ
            - EncodeDivergence: reconstruction differs from all stored trailers
          INSERT DeepScrubFinding into SuspectLog
          EMIT IntegrityEvent::DeepScrubFinding
     f. TRACK device error rate for marginal-media detection
        (sliding 256-sample window, 10% threshold)
4. PERSIST cursor
5. RETURN TickReport
```

### 4.3 Repair Tick (SuspectLog Drain)

```
Function: repair_tick(budget) -> TickReport

1. DRAIN SuspectLog entries (oldest first, bounded by budget)
2. FOR each SuspectEntry:
     a. IF entry.validity_token.is_stale(current_chunk_commit_group):
          CLEAR entry (already repaired by inline read-path or application write)
          CONTINUE
     b. RESOLVE repair strategy from SuspectFindingKind:
          - ChecksumCorruption → full replica copy from healthy source
          - SingleShardCorrupt → EC reconstruct from k shards
          - MultiShardCorrupt → EC reconstruct + verify against healthiest replicas
          - MissingReplica → placement planner select target, full copy
     c. BUILD WitnessSet from ReplicaHealthTracker
     d. ADMIT through CascadingFailureGuard
     e. SELECT source via WitnessSet (prefer same-node > same-rack > cross-rack)
     f. COMPUTE target via PlacementPlanner::compute_replica_target_set()
     g. SHIP chunk via ChunkShipper with COMMIT_GROUP-gated write barrier
     h. VERIFY via FlowCommitCoordinator
     i. ON success:
          CLEAR SuspectEntry
          MARK chunk healthy in ReplicaHealthTracker
          EMIT IntegrityEvent::RepairComplete
     j. ON failure (stale, no source, partition):
          INCREMENT entry.retry_count
          IF retry_count > MAX_RETRIES:
            ESCALATE to operator with RepairEscalation alert
4. RETURN TickReport
```

### 4.4 Resilver Staged Rebuild

```
Function: resilver_tick(budget) -> TickReport

1. DETERMINE current stage from ResilverCursor:
     MetadataCritical (> k missing)  → service_priority = Critical (90% budget)
     DegradedUrgent (k..k+m missing) → service_priority = High
     UserData(p fractional complete) → service_priority = Elevated/Normal/Background
     ArchiveBackground                → service_priority = Background
2. BUILD StripePlan[] for current stage:
     a. ENUMERATE stripes needing restoration in priority order
     b. SELECT source replicas via ReplicaLagTracker (bandwidth-aware)
     c. COMPUTE target placement via PlacementPlanner (Secondary tier)
     d. GROUP into batches bounded by budget
3. FOR each batch:
     a. ADMIT through CascadingFailureGuard (per-domain + aggregate limits)
     b. SHIP stripes via ChunkShipper
     c. COMMIT via FlowCommitCoordinator
     d. VERIFY integrity on target
     e. ADVANCE cursor
4. IF Critical stage completed:
     RESTORE standard budget allocation (repair 30%, scrub 15%, deep scrub 10%)
5. PERSIST cursor
6. RETURN TickReport
```

### 4.5 Cascading Failure Guard

```
Function: cascading_failure_admit(domain_id) -> AdmissionVerdict

Constants:
  PER_DOMAIN_LIMIT = 3         // max concurrent recovery flows per failure domain
  AGGREGATE_LIMIT = 20         // max total recovery flows cluster-wide

1. IF active_in_domain[domain_id] >= PER_DOMAIN_LIMIT:
     RETURN DomainAtCapacity
2. IF total_active >= AGGREGATE_LIMIT:
     RETURN ClusterAtRecoveryCapacity
3. INCREMENT active_in_domain[domain_id]
4. INCREMENT total_active
5. RETURN Admitted

Function: cascading_failure_release(domain_id):
  DECREMENT active_in_domain[domain_id]
  DECREMENT total_active
```

### 4.6 Recovery Throttle

```
Function: admit_recovery_ticket(cost_bytes) -> bool

1. IF should_pause_recovery():
     RETURN false
2. adjusted = compute_adjusted_budget()
   // shrinks as client_latency_p50 / baseline rises
3. IF (consumed + cost_bytes) <= adjusted:
     RETURN true
4. RETURN false

Function: should_pause_recovery() -> bool
  RETURN client_latency_p50 > client_latency_baseline * 3.0

Function: compute_adjusted_budget() -> u64
  latency_ratio = client_latency_p50 / max(baseline, 0.001)
  scale = 1.0 / max(latency_ratio * throttle_aggressiveness, 1.0)
  RETURN max(bandwidth_budget * scale, 1)
```

### 4.7 Anti-Entropy Audit Cycle

The anti-entropy auditor (data_copy_8) provides an eventually-consistent
safety net for detecting corruption that escapes scrub and deep scrub.

```
Function: ae_audit_cycle() -> TickReport

State machine:
  Idle → Enumerate → Compare → [DivergenceFound → Ticketed] → Resolved → Idle

1. Idle: wait for scheduled interval or targeted-audit trigger
2. Enumerate: collect subjects for this scan cycle
3. Compare: FOR each subject:
     a. FETCH digests from all healthy replicas (via ReplicaHealthTracker)
     b. COMPARE digests pairwise using BLAKE3-256
     c. IF mismatch:
          BUILD DivergenceRecord { subject_id, diverging_replicas, mismatch_type }
          TRANSITION to DivergenceFound
4. DivergenceFound: classify divergences, determine if they need repair
5. Ticketed: create repair tickets (if auto-repair enabled) or operator alerts
6. Resolved: all divergences addressed, transition to Idle

Coverage guarantee: Every persistent corruption is eventually detected
by at least one of {scrub, deep scrub, anti-entropy auditor} within
max(scrub_interval, deep_scrub_interval, ae_scan_interval) of occurrence.
```

### 4.8 Marginal-Media Detection

```
Function: detect_marginal_media(chunk_id, read_latency_us, read_error) -> Option<Alert>

1. INSERT (latency, error) into 256-sample sliding window for device
2. COMPUTE moving average latency and error rate over window
3. IF error_rate > 1% OR p90_latency > threshold:
     EMIT MarginalMediaDetection alert
     CALL replica_health.mark_device_degrading(device_id)
     RETURN Some(alert)
4. RETURN None
```

## 5. Tradeoffs

| Dimension | Scrub | Deep Scrub | Repair | Resilver |
|-----------|-------|------------|--------|----------|
| Trigger | Scheduled | Scheduled (weekly) | On-finding or read-path | Device replacement |
| IO budget | 15% bg | 10% bg (shared w/ AE) | 30% bg (esc to 50%) | 15% bg (esc to 90%) |
| CPU budget | BLAKE3 only | EC reconstruct + BLAKE3 | Replica write + checksum | Full stripe reconstruct |
| Network | None (local) | Shard fetch from peers | Source-target transfer | Full device rebuild |
| Write load | Read-only | Read-only | Write (restore replicas) | Heavy write (rebuild) |
| Fencing required | None | None | Per-chunk fence | Range fence |
| Health tracker role | Consumer | Consumer | Producer + Consumer | Producer + Consumer |
| SuspectLog role | Writer | Writer | Reader/Drainer | Writer (on failure) |
| RebuildPlanner usage | Not used | Not used | Via RecoveryLoop | Via RecoveryLoop |
| Cascade guard subject | No | No | Yes (admission) | Yes (admission) |
| Concurrency model | Single-pass, ST | Single-pass, ST | Multi-worker (domain) | Multi-worker (staged) |
| Checkpoint resume | ScrubCursor | DeepScrubCursor | SuspectLog drain | ResilverCursor |
| Priority escalation | Never | Never | Normal→Elevated→Critical | Normal→Critical |
| Interaction w/ others | Paused in crit resilver | Paused in crit resilver | Concurrent except overlap | May pause scrub/ds/repair |

### Design Decisions

1. **Per-chunk health vs. per-PG health (Ceph).** Per-chunk granularity
   allows precise, loss-event-scoped rebuild. Cost: larger health tracker
   memory footprint. Mitigated by receipt-backed dual-source tracking.

2. **Receipt-backed transfers vs. heartbeat-based.**
   `ReplicaTransferReceipt → ReplicaVerificationReceipt →
   ReplicaPlacementReceipt` chains provide auditable transfer records
   that heartbeat-based systems cannot offer. Cost: per-transfer overhead.
   Mitigated by batch amortization in `FlowCommitCoordinator`.

3. **COMMIT_GROUP-gated write barriers vs. optimistic locking.** COMMIT_GROUP barriers
   prevent stale-write races during repair at the cost of blocking
   concurrent application writes on the same chunk. For per-chunk repair
   (<1s) this is acceptable. For range-fence during resilver, writes are
   journaled rather than blocked.

4. **CascadingFailureGuard vs. unbounded recovery.** Domain-aware
   admission control prevents repair cascades during large-scale failures.
   Cost: slower recovery of large loss events. Tradeoff: safety > speed.

5. **PlacementPlanner anti-affinity vs. random selection.** Deterministic
   anti-affinity across failure domains ensures rebuilt replicas don't
   concentrate in a single domain. Cost: fewer candidate targets during
   topology degradation.

6. **Configurable checkpoint intervals vs. ZFS-style linear scans.**
   Cursor-based resume allows each service to checkpoint independently
   and resume after restart without replaying the entire pass.

## 6. Deferred Rust Implementation Plan

All Rust implementation is deferred to wire-up issues. The implementation
units are:

| Unit | Crate | Est. Lines |
|------|-------|------------|
| U1: ScrubService | `tidefs-scrub-service` (new) | 800–1000 |
| U2: DeepScrubService | `tidefs-deep-scrub-service` (new) | 700–900 |
| U3: RepairService | `tidefs-repair-service` (new) | 1000–1300 |
| U4: ResilverService | `tidefs-resilver-service` (new) | 900–1200 |
| U5: IntegrityEventBus | `tidefs-local-filesystem` (modify) | 300–500 |
| U6: Config knobs | per-crate constants | 200–300 |
| U7: SuspectLog persistence | `tidefs-suspect-log` (new) | 500–700 |
| U8: Marginal-media detection | `tidefs-deep-scrub-service` (modify) | 300–400 |
| U9: Cross-service orchestration | `tidefs-background-scheduler` (modify) | 400–600 |
| U10: Integration tests | `tidefs-test-harness` | 800–1200 |
| **Total** | | **5900–8000** |

### Dependency Graph

```
U5 (IntegrityEventBus) ─┐
U6 (Config knobs) ──────┤
U7 (SuspectLog) ────────┤
                        │
U1 (ScrubService) ──┬── U3 (RepairService)
U2 (DeepScrubSvc) ──┘       │
                            ├── U4 (ResilverService)
                            │       │
                            │       └── U8 (MarginalMedia)
                            │
                            └── U9 (Work Orchestration)
                                    │
                                    └── U10 (Integration tests)
```

U1–U3 can be parallel once U5–U7 are complete. U4 requires U3 for shared
rebuild/placement/shipping infrastructure. U10 gates overall correctness.

## 7. Existing Implemented Crates (Ground Truth)

| Crate | Lines | Role in Design |
|-------|-------|---------------|
| `tidefs-replica-health` | 2378 | `ReplicaHealthTracker`, `FlapDetector`, `AdaptiveTimeout`, `ReplicaLagStateRecord`, `SuspicionLevel` |
| `tidefs-rebuild-planner` | 2495 | `LossEvent`, `WitnessSet`, `RebuildFlowRecord`, 6-state rebuild flow, `RebuildPriority` |
| `tidefs-recovery-loop` | 849 | `RecoveryLoop`, `RecoveryThrottle`, `RecoveryPriority`, `RecoveryPhase` |
| `tidefs-placement-planner` | 544 | `compute_replica_target_set()`, `FailureDomainPlacementPlan` |
| `tidefs-anti-entropy-auditor` | 574 | `AntiEntropyAuditor` 6-state machine, `DigestComparator`, `ScanScheduler` |
| `tidefs-erasure-coding` | 821 | `ErasureShard`, `StripeConfig`, `Reconstruction`, `reconstruct()` |
| `tidefs-erasure-coded-store` | 953 | EC store integration surface |
| `tidefs-chunk-shipper` | — | P8-03 data_copy_6: staged buffer lifecycle, transport selection |
| `tidefs-flow-commit-coordinator` | — | P8-03 data_copy_7: transfer→verify→place receipt bridging |
| `tidefs-types-incremental-job-core` | 1619 | `IncrementalJob` trait, `WorkBudget`, `JobProgress`, `CursorState`, `Checkpoint` |

These crates are already implemented with unit tests and serve as the
foundation for the scrub/deep-scrub/repair/resilver service layer.

## 8. References

- Background service framework: `docs/design/background-service-framework-design.md`
- End-to-end checksum architecture: `docs/design/end-to-end-checksum-architecture-g3-pillar.md`
- Placement planner & AE auditor integration: `docs/design/scrub-deep-scrub-repair-resilver-orchestration-placement-ae-auditor.md`
- Replica health tracker: #895
- Rebuild planner: #893
- Recovery loop: #901
- Shard groups and replicas: `docs/design/shard-groups-replicas-rebake-design-spec.md`
- Pool topology: `docs/design/pool-import-export-device-topology-management.md`
- Incremental job framework: `docs/design/incremental-job-core-trait-checkpoint-codec-design.md`
- P8-03 transport contracts: `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md`
