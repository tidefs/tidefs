# Scrub, Deep Scrub, Repair, and Resilver Orchestration Design: Placement Planner and Anti-Entropy Auditor Integration

Maturity: **design-spec** — Rust wire-up deferred to per-component issue lanes.

This document supersedes the distributed rebuild/recovery integration sections of
`scrub-deep-scrub-repair-resilver-orchestration-design.md` (#1917) for the
placement planner and anti-entropy auditor subsystems. It defines how
`tidefs-placement-planner` and `tidefs-anti-entropy-auditor` feed into repair
and resilver through the canonical P8-03 data-flow infrastructure: the
continuous recovery loop (#901), rebuild planner (#893), flow commit
coordinator, and chunk shipper.

Claim boundary: this is target-design material for placement and anti-entropy
integration. CRUSH analogies, ZFS/Ceph comparisons, degraded-placement
tradeoffs, latency/backfill wording, and verification language below are
design lessons and validation targets, not current placement quality, repair
performance, availability, or successor evidence. Product-facing comparison
wording still requires #875 claim ids and #928/#930 comparator evidence.

Issue: #1943.

## 1. Scope and Relationship to Prior Design

| Document | Covers |
|----------|--------|
| `scrub-deep-scrub-repair-resilver-orchestration-design.md` (#1917) | Full-service lifecycle: scrub passes, suspect logs, deep-scrub reconstruction, repair source selection, resilver topology integration |
| **This document (#1943)** | Placement planner and anti-entropy auditor as canonical decision engines feeding repair and resilver |
| `REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md` | Transport contracts: chunk shipper, flow commit coordinator, transfer/verify/place receipt chains |
| `background-service-framework-design.md` (#1549) | Service lifecycle, budgets, priority staging |
| `end-to-end-checksum-architecture.md` (#1564) | IntegrityTrailerV2, BLAKE3-256 domain separation |

## 2. Architecture Overview

```
                    ┌──────────────────────────────────┐
                    │    Replica Health Tracker (#895) │
                    │    (health, lag, flap detection)  │
                    └──────────────┬───────────────────┘
                                   │
           ┌───────────────────────┼───────────────────────┐
           │                       │                       │
           ▼                       ▼                       ▼
  ┌─────────────────┐   ┌──────────────────┐   ┌──────────────────────┐
  │Anti-Entropy     │   │  Rebuild Planner │   │  Recovery Loop (#901)│
  │Auditor (#1943)  │   │  (#893)          │   │  5-phase continuous  │
  │                 │   │                  │   │  detect→scope→plan   │
  │6-state machine  │   │Loss-event flow   │   │  →execute→verify     │
  │scan scheduler   │   │witness-set batch │   │                      │
  │digest comparator│   │scheduling        │   │  RecoveryThrottle    │
  └────────┬────────┘   └────────┬─────────┘   └──────────┬───────────┘
           │                     │                        │
           │  divergences        │  rebuild plan          │  orchestration
           │  (ticketable)       │  (loss-scoped)         │  (phase gating)
           │                     │                        │
           └─────────────────────┼────────────────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │  Placement Planner (#1943)│
                    │  compute_replica_target_  │
                    │  set()                    │
                    │                           │
                    │  Anti-affinity classes    │
                    │  Tier goals (primary/      │
                    │  secondary/archive)       │
                    │  Failure-domain scoping   │
                    └──────────┬───────────────┘
                               │
                               │  FailureDomainPlacementPlan
                               │  (target members, verdict)
                               │
           ┌───────────────────┼───────────────────┐
           ▼                   ▼                   ▼
  ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐
  │Chunk Shipper │   │Flow Commit   │   │Repair / Resilver │
  │(P8-03 dc_6)  │   │Coordinator   │   │Service Layer     │
  │              │   │(P8-03 dc_7)  │   │                  │
  │staged buffer │   │receipt bridge│   │Places replicas   │
  │transport sel │   │transfer→     │   │at computed       │
  │receipt emit  │   │verify→place  │   │targets           │
  └──────────────┘   └──────────────┘   └──────────────────┘
```

The **placement planner** and **anti-entropy auditor** are the two decision
ingestion points that convert raw signals (health degradation, replica lag,
divergent digests, topology changes) into actionable work items:

- The **anti-entropy auditor** decides *what* needs repair (divergence
  classification → ticketable subjects).
- The **placement planner** decides *where* to place replacement replicas
  (failure-domain-aware target selection with anti-affinity).

The recovery loop composes both with the rebuild planner into a phased,
gated execution cycle.

## 3. Placement Planner (`tidefs-placement-planner`)

### 3.1 Crate Identity

- **Crate**: `tidefs-placement-planner` (P8-03 data_copy_0)
- **Cargo.toml**: `version = "0.421.0"`
- **Dependencies**: `tidefs-membership-epoch`, `tidefs-replication-model`
- **Primary export**: `compute_replica_target_set()`
- **Source**: `crates/tidefs-placement-planner/src/lib.rs` (544 lines)

### 3.2 Algorithm

```rust
pub fn compute_replica_target_set(
    policy: &FailureDomainPlacementPolicy,
    failure_domains: &[FailureDomainRecord],
    tier_goal: TierGoal,
    epoch: EpochId,
) -> Result<FailureDomainPlacementPlan, PlacementError>
```

#### 3.2.1 Phase 1: Domain Filtering

Filter `failure_domains` to those matching:
- `required_failure_domain_class_ref` (e.g., rack, node, device)
- Health at or above the minimum for the `tier_goal`
- Non-empty member list

#### 3.2.2 Phase 2: Candidate Ordering

Sort candidates by `(member_count, domain_id)` — least-loaded first.
This distributes replicas across underutilized domains before filling
hot ones, analogous to CRUSH's straw2 but offline and reproducible.

#### 3.2.3 Phase 3: Anti-Affinity Strictness

```
TierGoal::Primary   → Strict if policy.anti_affinity_class == Strict
TierGoal::Secondary → Strict only if required <= n_domains/2, else DegradedVisible
TierGoal::Archive   → Always DegradedVisible
```

#### 3.2.4 Phase 4: Member Selection

Round-robin across candidate domains. For strict mode, each domain contributes
at most one member. When strict mode exhausts unique domains, the algorithm
falls back to degraded mode (domain reuse). Selection terminates when:
- `required_replica_count` members are selected, or
- All members across all candidate domains are exhausted.

#### 3.2.5 Phase 5: Verdict Construction

Produces a `FailureDomainPlacementPlan` with:
- `selected_members`: the chosen replica targets
- `excluded_members`: all non-selected members across candidate domains
- `verdict_class`: `Admit` (full anti-affinity) or `AdmitDegraded` (reused domains)
- `epoch` and `policy_ref` for auditability

### 3.3 Error Model

```rust
pub enum PlacementError {
    NotEnoughDomains { required: usize, available: usize },
    NotEnoughMembers { required: usize, available: usize },
    NoMatchingDomainClass,
    AllMembersExcluded,
}
```

### 3.4 Repair Integration

When repair needs to place a reconstructed or replicated shard:

1. Repair service queries the **rebuild planner** for a loss-event scope.
2. The rebuild planner calls `compute_replica_target_set()` with:
   - `policy`: the dataset's placement policy (replication factor, failure-domain class)
   - `failure_domains`: current topology inventory from `tidefs-pool-topology`
   - `tier_goal`: `TierGoal::Primary` (repair restores primary-tier redundancy)
3. The resulting `FailureDomainPlacementPlan.selected_members` become the
   target list for the chunk shipper's transfer stage.
4. The flow commit coordinator records the placement verdict in the
   transfer→verify→place receipt chain.

### 3.5 Resilver Integration

Resilver differs from repair in scale: it may need to place hundreds or
thousands of replicas across new topology after device replacement or
pool expansion.

1. Resilver service obtains the new topology inventory post-membership-change.
2. For each stripe needing new replicas, calls `compute_replica_target_set()`
   with `TierGoal::Secondary` initially (the existing primary replicas
   remain in place; new replicas fill secondary slots).
3. Anti-affinity enforcement is relaxed for secondary tier when the
   available domain count is tight — the algorithm naturally degrades.
4. The placement plan is batch-committed through the recovery loop's
   execute phase.

### 3.6 Placement Plan Lifecycle

```
PlacementPolicy + TopologyInventory
        │
        ▼
  compute_replica_target_set()
        │
        ▼
  FailureDomainPlacementPlan
        │
        ├─ selected_members ──► ChunkShipper::stage_transfer()
        ├─ verdict_class    ──► FlowCommitCoordinator::record_verdict()
        └─ excluded_members ──► RebuildPlanner::note_excluded()
                                       │
                                       ▼
                              AntiEntropyAuditor::audit_subject()
                              (post-transfer verification)
```

### 3.7 Placement Cache

The placement planner is stateless and idempotent for a given `(policy,
domains, tier_goal, epoch)` tuple. However, callers may cache results
per loss-event to avoid recomputation during batched stripe rebuilds.
- Epoch advancement (membership change)
- Health-class transitions in any candidate domain
- Operator-initiated policy changes

### 3.8 Tradeoffs

| Decision | Rationale |
|----------|-----------|
| Round-robin over weighted distribution | Simpler to reason about; least-loaded-first ordering approximates weighted balancing without per-member weight fields |
| Fallback to degraded on exhaustion | Target behavior to avoid repair deadlock when topology is too small for strict anti-affinity; degraded placement is an explicit policy choice rather than a quality claim |
| Stateless (no persisted state) | All inputs are externally observable (topology, policy, epoch); no internal state to drift |
| No cross-stripe placement awareness | Each call is independent; batching across stripes is the caller's responsibility (rebuild planner) |

## 4. Anti-Entropy Auditor (`tidefs-anti-entropy-auditor`)

### 4.1 Crate Identity

- **Crate**: `tidefs-anti-entropy-auditor` (P8-03 data_copy_8)
- **Dependencies**: `tidefs-replica-health` (lag records), `tidefs-replication-model`
- **Primary exports**: `AntiEntropyAuditor` struct, `AntiEntropyState`, scan lifecycle API
- **Source**: `crates/tidefs-anti-entropy-auditor/src/` (`lib.rs` 574 lines, `ae_state.rs`, `comparator.rs`, `scan_scheduler.rs`)

### 4.2 Six-State Machine

```
                    ┌──────────────┐
                    │    Idle      │◄──────────────────────────────────────────┐
                    │ last_scan    │                                           │
                    │ next_eligible│                                           │
                    └──────┬───────┘                                           │
                           │ begin_scan()                                      │
                           ▼                                                   │
                    ┌──────────────┐                                           │
                    │ Enumerating  │                                           │
                    │ subject batch│                                           │
                    │ frontier_mark│                                           │
                    └──────┬───────┘                                           │
                           │ begin_compare()                                   │
                           ▼                                                   │
                    ┌──────────────┐     record_comparisons()                  │
                    │   Compare    │────────────────────────────────┐          │
                    │ done / total │                                │          │
                    │ divergences  │                                │          │
                    └──────┬───────┘                                │          │
                           │ classify_divergences()                 │          │
                           ▼                                        │          │
                    ┌──────────────┐                                │          │
                    │ Divergence   │                                │          │
                    │ Found        │                                │          │
                    │ total/class/ │                                │          │
                    │ lag/corrupt/ │                                │          │
                    │ missing      │                                │          │
                    └──────┬───────┘                                │          │
                           │ record_tickets()                       │          │
                           ▼                                        │          │
                    ┌──────────────┐                                │          │
                    │  Ticketed    │                                │          │
                    │ ticket ids   │                                │          │
                    └──────┬───────┘                                │          │
                           │ resolve()                              │          │
                           ▼                                        │          │
                    ┌──────────────┐                                │          │
                    │  Resolved    │                                │          │
                    │ receipt ids  │                                │          │
                    └──────┬───────┘                                │          │
                           │ complete_scan()                        │          │
                           └────────────────────────────────────────┘          │
                                                                               │
          ┌────────────────────────────────────────────────────────────────────┘
          │  (record_comparisons() with no divergences also flows to Idle
          │   via classify → no divergence_found → skip to complete)
```

### 4.3 Scan Scheduler

The `ScanScheduler` and `ScanSchedulePolicy` control *when* and *what* to
scan, using an incremental frontier that prevents re-scanning
already-verified subjects — unlike ZFS scrub which restarts from the
beginning of the pool.

```rust
pub struct ScanSchedulePolicy {
    /// Minimum interval between scan starts (nanoseconds).
    pub min_scan_interval_ns: u64,
    /// Maximum subjects per scan batch.
    pub max_batch_size: usize,
    /// Cluster load threshold above which scans pause.
    /// Range [0.0, 1.0] where 1.0 = fully loaded.
    pub load_threshold: f64,
    /// Multiplier applied to interval when divergences were found
    /// (adaptive backoff).
    pub divergence_backoff_multiplier: f64,
}
```

The frontier tracks:
- `high_water_mark`: highest subject_ref scanned so far
- `degraded_subjects`: priority set inserted at the head of each batch

This means a degraded chunk at subject_ref=5 gets priority even if
high_water_mark is at 50000. After repair confirms the fix, the
subject is cleared from the degraded set.

### 4.4 Digest Comparator

The comparator uses **three-source comparison**:

| Source | Origin |
|--------|--------|
| Primary digest | Transfer receipt chain (BLAKE3-256) |
| Replica digest | Verification receipt chain |
| Witness digest | Witness set, when available (tie-breaker) |

Divergence classification:

```rust
pub enum DivergenceClass {
    /// Replica's digest matches primary but is stale (lag).
    ReplicaLag,
    /// Replica's digest differs from primary (corruption).
    DigestMismatch,
    /// No replica found at all (missing).
    MissingReplica,
    /// Replica node reports unhealthy.
    ReplicaUnhealthy,
}
```

A divergence is **ticketable** (i.e., requires repair action) when:
- `DigestMismatch`: needs reconstruction or re-replication
- `MissingReplica`: needs new replica placement
- `ReplicaUnhealthy`: needs health escalation + possible replacement

`ReplicaLag` alone is *not* ticketable; it feeds back into the replica
health tracker for catchup scheduling.

### 4.5 Integration with Repair and Resilver

#### 4.5.1 Health Signal Ingestion

```rust
// Called by recovery loop when replica health tracker reports stale replicas
let count = auditor.register_degraded_from_health(&lag_records);
```

Only `ReplicaLagStateRecord::is_stale()` entries trigger registration.
These subjects get priority in the next scan batch.

#### 4.5.2 Divergence → Rebuild Flow

```
AntiEntropyAuditor.classify_divergences()
        │
        │  DivergenceFound { total_divergences, classified_corruption, ... }
        ▼
AntiEntropyAuditor.ticketable_divergences()
        │
        │  Vec<&DivergenceRecord>  (DigestMismatch + MissingReplica + ReplicaUnhealthy)
        ▼
RebuildPlanner.create_loss_event()
        │
        │  LossEvent { affected_subjects, witness_set, priority }
        ▼
PlacementPlanner.compute_replica_target_set()
        │
        │  FailureDomainPlacementPlan
        ▼
ChunkShipper + FlowCommitCoordinator
        │
        │  Transfer → Verify → Place receipt chain
        ▼
AntiEntropyAuditor.targeted_audit()
        │
        │  Post-repair verification (bypasses scheduler)
        ▼
AntiEntropyAuditor.resolve()
```

#### 4.5.3 Post-Repair Verification

After repair completes, the auditor runs a **targeted audit** on the
repaired subjects:

```rust
let results = auditor.targeted_audit(&post_repair_inputs, now_ns);
if results.iter().all(|r| !r.diverged) {
    auditor.resolve(now_ns, &receipt_ids);
} else {
    // Re-escalate through recovery loop
}
```

This closes the loop: the same system that discovered the divergence
confirms its resolution.

### 4.6 Backpressure and Throttling

The scan scheduler integrates with the `RecoveryThrottle` from the
recovery loop:

- `should_scan(now_ns, cluster_load_factor)` returns `ScanDecision::Pause`
  when `cluster_load_factor > policy.load_threshold`.
- Divergence-responsive backoff: if the last scan found divergences, the
  next scan interval is multiplied by `divergence_backoff_multiplier`
  (default 2.0) to avoid thrashing on a degraded cluster.
- The scan scheduler does not compete with client IO: it yields to the
  throttle's `should_pause_recovery()` signal.

### 4.7 Observability

The auditor emits:
- `audit_sequence`: monotonic scan cycle counter
- `total_historical_divergences()`: lifetime count for dashboard trending
- Per-cycle counts: `classified_lag`, `classified_corruption`, `classified_missing`
- `tickets_created`: repair tickets generated in current cycle
- `last_error`: for debug/triage

These feed into the structural observability framework
(`docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md`).

### 4.8 Tradeoffs

| Decision | Rationale |
|----------|-----------|
| Per-subject scanning (not full pool) | Enables incremental progress; a pool with 100M objects need not restart from zero |
| Degraded priority queue (not round-robin) | Degraded subjects are urgent; scanning healthy subjects first wastes IO on non-actionable results |
| Three-source comparison (not pair-wise) | Prevents split-brain ambiguity when primary and replica disagree |
| Separate divergence registry (not inline tickets) | Decouples discovery from remediation; allows batching divergences into efficient rebuild plans |
| No Merkle tree (hash-list frontier) | Merkle trees impose O(log N) update cost on every write; hash-list frontier is O(1) per write with lazy comparison |

## 5. Integration: End-to-End Repair Flow

This section traces a complete repair from corruption detection through
verified resolution, showing how each component contributes.

### 5.1 Trigger Paths

Repair can be triggered by three independent paths, all converging on
the recovery loop:

| Trigger | Entry Point |
|---------|-------------|
| **On-read checksum failure** | `scrub.rs` → `SuspectLog` → recovery loop |
| **Scrub pass finding** | Scrub service → `SuspectLog` → recovery loop |
| **Anti-entropy divergence** | `AntiEntropyAuditor.classify_divergences()` → ticketable divergences → recovery loop |

### 5.2 Step-by-Step Flow

```
Step 1: DETECT
  ├─ Scrub/on-read: IntegrityTrailerV2 mismatch → SuspectLog entry
  ├─ Anti-entropy: digest comparison divergence → DivergenceRecord
  └─ Both feed into: recovery loop Detect phase

Step 2: SCOPE
  ├─ RebuildPlanner.create_loss_event(suspect_ids)
  ├─ Determines witness set (healthy replicas that can serve as source)
  ├─ Scopes affected stripes, required shard count
  └─ Assigns RecoveryPriority (SteadyReplication / CatchupRepair / LossRebuild)

Step 3: PLAN
  ├─ PlacementPlanner.compute_replica_target_set(policy, domains, tier_goal, epoch)
  ├─ Produces FailureDomainPlacementPlan with anti-affinity guarantees
  ├─ RecoveryThrottle.admit_recovery_ticket() gates admission
  └─ RebuildPlanner batches stripes into transfer groups

Step 4: EXECUTE
  ├─ ChunkShipper stages transfer: source → target buffer
  ├─ Transport selection: RDMA > io_uring > TCP (auto-negotiated)
  ├─ Receipt emission at each stage (transfer receipt, verification receipt)
  └─ FlowCommitCoordinator bridges transfer→verify→place

Step 5: VERIFY
  ├─ FlowCommitCoordinator confirms placement receipt
  ├─ AntiEntropyAuditor.targeted_audit() verifies repaired subjects
  ├─ On success: AntiEntropyAuditor.resolve() + clear_degraded_subject()
  ├─ On failure: RebuildPlanner re-escalates with reduced witness set
  └─ SuspectLog entry cleared on verified resolution
```

### 5.3 Concurrent Repair Safety

- **Idempotent placement**: `compute_replica_target_set()` is deterministic
  for a given epoch; concurrent repair of the same stripe produces the
  same target set.
- **Epoch gating**: placement plans are scoped to an `EpochId`; if the
  must be recomputed.
- **Witness-set locking**: the rebuild planner acquires a short-lived
  witness-set lock during the Scope phase to prevent source replicas
  from being garbage-collected mid-transfer.
- **SuspectLog deduplication**: multiple detection paths for the same
  corrupt chunk produce a single SuspectLog entry (keyed by object_id +
  shard_index).

## 6. Resilver: Topology-Change Flow

### 6.1 Trigger

- Device replacement (operator or automated via `tidefs-pool-topology`)
- Pool expansion (new devices added)
- Membership change (node join/leave)

### 6.2 Flow

```
Topology change detected
        │
        ▼
PoolTopology::compute_delta(old_inventory, new_inventory)
        │
        │  Delta { added_devices, removed_devices, capacity_change }
        ▼
ResilverService::build_stripe_plan()
        │
        │  For each stripe where replica_count < policy.required_replica_count:
        │    PlacementPlanner::compute_replica_target_set(
        │        policy, new_domains, TierGoal::Secondary, new_epoch)
        │
        ▼
RebuildPlanner::batch_resilver_stripes(placement_plans)
        │
        ▼
RecoveryLoop::execute_plan()  (priority = SteadyReplication)
        │
        ├─ If remaining_replicas < RESILVER_CRITICAL_THRESHOLD:
        │     priority = LossRebuild
        │
        ▼
FlowCommitCoordinator + ChunkShipper
        │
        ▼
AntiEntropyAuditor::targeted_audit()  (post-resilver verification)
```

### 6.3 Resilver-Specific Placement Considerations

- **Capacity-aware ordering**: the placement planner's least-loaded-first
  sort naturally biases new replicas toward underutilized domains.
- **Anti-affinity relaxation**: during large-scale resilver (e.g., replacing
  a full rack), the available domain count may be temporarily below the
  strict anti-affinity threshold. The planner degrades gracefully.
- **Progress tracking**: each resilver batch advances a `ResilverProgress`
  cursor; the target design differs from ZFS's single-tree-order scan by
  recording stripe-granular pause/resume state.
- **Client IO impact**: the recovery throttle dynamically adjusts
  resilver bandwidth based on client latency. This is the intended mitigation
  for backfill-style client impact, not measured current evidence.

## 7. Deep Scrub and Anti-Entropy: Complementary Verification

| Dimension | Deep Scrub | Anti-Entropy Auditor |
|-----------|-----------|---------------------|
| **Trigger** | Scheduled (e.g., every 30 days) | Continuous (adaptive interval) |
| **Scope** | Full pool (all objects) | Incremental frontier + degraded subjects |
| **Method** | Reconstruct from shards, compare checksums | Compare digests across replicas |
| **Detects** | Silent corruption undetectable by single-replica checksum | Replica divergence, lag, missing replicas |
| **Output** | SuspectLog entries | DivergenceRecord → ticketable divergences |
| **Reaction** | Feeds into repair via recovery loop | Feeds into repair via recovery loop |

Deep scrub and anti-entropy auditing are **complementary**, not redundant:
- Deep scrub detects corruption that *all* replicas share (e.g., bit rot in
  the same physical sector across mirrored SSDs).
- Anti-entropy detects *divergence* between replicas (e.g., one replica
  missed writes due to a transient network partition).

Both feed into the same repair machinery.

## 8. Configuration Constants

```rust
// Anti-entropy auditor
pub const AE_MIN_SCAN_INTERVAL_HOURS: u64 = 6;
pub const AE_MAX_BATCH_SIZE: usize = 10000;
pub const AE_LOAD_THRESHOLD: f64 = 0.8;
pub const AE_DIVERGENCE_BACKOFF_MULTIPLIER: f64 = 2.0;

// Placement planner
pub const PLACEMENT_MAX_ROUNDS: usize = 1000;  // safety bound on round-robin

// Resilver
pub const RESILVER_CRITICAL_THRESHOLD: usize = 1;
pub const RESILVER_BATCH_SIZE: usize = 256;
```

## 9. Error Hierarchy (Extension)

These extend the error types in the original scrub/resilver design.

```rust
pub enum PlacementPlanError {
    /// Placement planner returned no viable target set.
    NoViableTargetSet { stripe_id: StripeId, reason: PlacementError },
    /// Topology changed during placement computation.
    EpochStale { expected: EpochId, actual: EpochId },
    /// Anti-affinity constraints too strict for current topology.
    TopologyTooSmall { required: usize, available_domains: usize },
}

pub enum AntiEntropyError {
    /// Scan could not enumerate subjects (catalog unavailable).
    EnumerationFailed { reason: String },
    /// Digest comparison infrastructure unavailable.
    ComparatorUnavailable { reason: String },
    /// Divergences found but no rebuild planner available to ticket them.
    NoRebuildPath { divergence_count: usize },
}
```

## 10. State Diagrams

### 10.1 DivergenceRecord Lifecycle

```
  [ComparisonResult.diverged = true]
          │
          ▼
  ┌──────────────────┐
  │ DivergenceRecord │  classifier: DigestMismatch | MissingReplica | ...
  │   created        │  requires_ticket(): true for all except ReplicaLag
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────┐
  │ DivergenceFound  │  classify_divergences() counts by class
  │   (state)        │
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────┐
  │    Ticketed      │  repair tickets created in replication model
  │   (state)        │
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────┐
  │   Resolved       │  verification receipts confirm fix
  │   (state)        │  DivergenceRecord moved to divergence_history
  └──────────────────┘
```

### 10.2 PlacementPlan Lifecycle

```
  compute_replica_target_set(policy, domains, tier_goal, epoch)
          │
          ▼
  ┌──────────────────────────┐
  │ FailureDomainPlacementPlan│
  │   VerdictClass::Admit    │  ──► Execute immediately
  └──────────────────────────┘

  compute_replica_target_set(policy, domains, tier_goal, epoch)
          │
          ▼
  ┌──────────────────────────────┐
  │ FailureDomainPlacementPlan   │
  │   VerdictClass::AdmitDegraded│  ──► Log warning, execute
  └──────────────────────────────┘

  compute_replica_target_set(policy, domains, tier_goal, epoch)
          │
          ▼
  ┌──────────────────┐
  │   PlacementError │  ──► Escalate to operator
  │ NotEnoughMembers │      (topology expansion needed)
  └──────────────────┘
```

## 11. Concurrency Model

Both the placement planner and anti-entropy auditor operate within the
concurrency model established by the recovery loop:

| Component | Concurrency | Rationale |
|-----------|-------------|-----------|
| `compute_replica_target_set()` | Single-threaded, lock-free | Stateless pure function; multiple callers can compute independently |
| `AntiEntropyAuditor` | Single owner (recovery loop) | State machine transitions are sequential; internal collections are not shared |
| `ScanScheduler::should_scan()` | Read-only query | Safe to call from health tracker thread |
| `DigestComparator::compare_batch()` | Embarrassingly parallel | Each subject-replica pair is independent; may be parallelized in future |

Lock ordering (see `LOCK_HIERARCHY_AND_CONCURRENCY_MODEL.md`):
1. Recovery loop lock (outermost)
2. Replica health tracker lock
3. Anti-entropy auditor (owned by recovery loop, no separate lock)
4. Placement planner (stateless, no lock)

## 12. Testing Strategy

### 12.1 Placement Planner

- **Unit**: Round-robin selection with varying domain counts; degraded
  fallback when domains < required_replicas; edge cases (empty domains,
  all members excluded).
- **Property**: `compute_replica_target_set()` is deterministic for fixed
  inputs; output set size == `required_replica_count` when available
  members suffice.
- **Integration**: Simulated topology from `tidefs-pool-topology`;
  verify anti-affinity across failure domains.

### 12.2 Anti-Entropy Auditor

- **Unit**: Full scan lifecycle (idle→enumerate→compare→divergence_found→
  ticketed→resolved→idle); degraded subject prioritization; targeted
  audit bypasses scheduler.
- **Property**: `drain_divergences()` clears current cycle but preserves
  history; `register_degraded_from_health()` only registers stale entries.
- **Integration**: Feed real `ReplicaLagStateRecord` entries from
  `tidefs-replica-health`; verify ticket creation through
  `tidefs-replication-model`.

Existing tests in `crates/tidefs-anti-entropy-auditor/src/lib.rs`:
- `full_scan_lifecycle_no_divergences`
- `full_scan_lifecycle_with_divergences`
- `degraded_subjects_get_priority`
- `register_degraded_from_health_records`
- `targeted_audit_bypasses_scheduler`
- `drain_divergences_clears_current_cycle`

### 12.3 End-to-End

- **Crash-injection harness** (`deterministic-crash-injection-harness.md`):
  inject corruption, verify that anti-entropy detects, placement planner
  selects targets, and repair completes with verified resolution.
- **Simnet protocol correctness** (`deterministic-cluster-simnet-protocol-correctness-testing.md`):
  multi-node simnet with injected faults.

## 13. Migration Path from Local Repair

Prior iterations of repair performed local source→target replication
without placement planning or anti-entropy verification. The migration
path is:

1. **Phase 1 (current)**: Both subsystems exist as crates with unit tests.
   The recovery loop composes them but the wire-up to the
   scrub/repair/resilver service layer is deferred.
2. **Phase 2 (wire-up)**:
   - `SuspectLog` entries flow through the anti-entropy auditor's
     `register_degraded_subject()` path in addition to direct
     recovery loop entry.
   - Repair service calls `compute_replica_target_set()` instead of
     picking a random healthy source.
   - Post-repair verification uses `AntiEntropyAuditor::targeted_audit()`.
3. **Phase 3 (optimization)**:
   - Placement plan caching for batch resilver.
   - Parallel digest comparison in anti-entropy auditor.
   - Adaptive anti-entropy intervals based on divergence history.

## 14. References

- [#1943] This design spec (placement planner and anti-entropy auditor integration)
- [#1917] Canonical scrub/deep-scrub/repair/resilver orchestration design
- [#895] Replica health tracker — `ReplicaHealthTracker`, flap detection, adaptive timeouts
- [#893] Rebuild planner — loss-event flow, witness-set batch scheduling
- [#901] Continuous recovery loop — 5-phase detect/scope/plan/execute/verify cycle
- [#1549] Background service framework
- [#1564] End-to-end checksum architecture — `IntegrityTrailerV2`, BLAKE3-256
- `crates/tidefs-placement-planner/src/lib.rs` (544 lines) — `compute_replica_target_set()`
- `crates/tidefs-anti-entropy-auditor/src/lib.rs` (574 lines) — `AntiEntropyAuditor` state machine
- `crates/tidefs-recovery-loop/src/lib.rs` (849 lines) — `RecoveryLoop`, `RecoveryThrottle`
- `crates/tidefs-rebuild-planner/src/lib.rs` (2495 lines) — `RebuildPlanner`
- `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md` — Transport contracts
- `docs/design/scrub-deep-scrub-repair-resilver-orchestration-design.md` — Prior design (#1917)
