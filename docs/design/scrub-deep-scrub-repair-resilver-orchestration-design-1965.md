# Scrub, Deep Scrub, Repair, and Resilver Orchestration Design (#1965)

Maturity: **design-spec** — Rust implementation deferred to wire-up issues.
Lane: `storage-core`. Kind: `design`.

This document defines the canonical orchestration design for scrub, deep
scrub, repair, and resilver services within tidefs. It specifies the
architecture, frozen cross-service data structures, algorithms, scheduling
integration, and tradeoff analysis. Rust implementation of individual
service crates (`tidefs-scrub-service`, `tidefs-deep-scrub-service`,
`tidefs-repair-service`, `tidefs-resilver-service`) is deferred to wire-up
issues. This document closes Forgejo issue #1965.

Claim boundary: this is target-design material for distributed integrity
services. Internal "canonical", "guarantee", latency, throughput, and
correctness wording below names intended architecture and validation targets,
not current TideFS product capability, performance evidence, durability
evidence, or successor evidence. Product-facing comparison wording still
requires #875 claim ids and #928/#930 comparator evidence.

Prior canonical revisions: #1609 (unified scheduler integration), #1705
(distributed rebuild/recovery refinement), #1739 (replica-health + throttle),
#1913 (RebuildPlanner + RecoveryLoop), #2055 (full P8-03 data-flow pathway).

## 1. Architecture Overview

Four coordinated background services share the unified scheduler
(`tidefs-background-scheduler`, #1549), the distributed replica-health
tracker (`tidefs-replica-health`, #895), and the P8-03 canonical data-flow
pipeline (rebuild planner → placement planner → chunk shipper → flow commit
coordinator).

```
┌────────────────────────────────────────────────────────────┐
│              Background Scheduler (#1549)                   │
│  5-stage priority: Critical → LatencySensitive →           │
│  Throughput → BestEffort → Opportunistic                   │
│  Per-tick budget enforcement + validity-token gating        │
└────┬───────┬──────────┬──────────┬─────────────────────────┘
     │       │          │          │
     ▼       ▼          ▼          ▼
┌─────────┐ ┌──────────┐ ┌────────┐ ┌──────────────┐
│  Scrub  │ │Deep Scrub│ │ Repair │ │   Resilver   │
│ Service │ │ Service  │ │Service │ │   Service    │
│         │ │          │ │        │ │              │
│periodic │ │periodic  │ │on-read │ │device-replace│
│7-day    │ │30-day    │ │or find │ │or topo-change│
│default  │ │default   │ │trigger │ │trigger       │
└────┬────┘ └────┬─────┘ └───┬────┘ └──────┬───────┘
     │           │            │             │
     └───────────┼────────────┼─────────────┘
                 │            │
                 ▼            ▼
    ┌─────────────────────────────────────┐
    │      SuspectLog (persistent)        │
    │  corruption entries, repair state   │
    └─────────────┬───────────────────────┘
                  │
     ┌────────────┼───────────────┐
     ▼            ▼               ▼
┌──────────┐ ┌──────────┐ ┌──────────────┐
│ Replica  │ │ Rebuild  │ │ Anti-Entropy │
│ Health   │ │ Planner  │ │ Auditor      │
│ Tracker  │ │ (#893)   │ │              │
│ (#895)   │ │          │ │              │
│per-chunk │ │loss-event│ │6-state       │
│health +  │ │witness-  │ │scan scheduler│
│flap det. │ │set batch │ │digest cmp    │
└────┬─────┘ └────┬─────┘ └──────┬───────┘
     │            │              │
     └────────────┼──────────────┘
                  │
     ┌────────────┼───────────────┐
     ▼            ▼               ▼
┌──────────┐ ┌──────────┐ ┌──────────────┐
│Placement │ │  Chunk   │ │Flow Commit   │
│ Planner  │ │ Shipper  │ │Coordinator   │
│          │ │          │ │              │
│anti-aff. │ │staged    │ │transfer→     │
│tier goals│ │transport │ │verify→place  │
└──────────┘ └──────────┘ └──────────────┘
```

### 1.1 Four Services, One Framework

Each service implements `BackgroundService` (from `tidefs-background-scheduler`):

| Service | Trigger | Priority | Cursor |
|---------|---------|----------|--------|
| Scrub | Scheduled (default 7-day interval) | Throughput | `ScrubCursor` — namespace-ordered |
| Deep Scrub | Scheduled (default 30-day interval) | BestEffort | `DeepScrubCursor` — independent from scrub |
| Repair | On-read error or scrub/deep-scrub finding | Critical | None — immediate, small-scope |
| Resilver | Device replacement, topology change | LatencySensitive | `ResilverCursor` — rebuild-progress ordered |

### 1.2 Dependency Hierarchy

```
tidefs-types-incremental-job-core (no_std, leaf)
    ├── tidefs-scrub-service (U1)
    ├── tidefs-deep-scrub-service (U2)
    │   └── tidefs-anti-entropy-auditor (digest comparison)
    ├── tidefs-repair-service (U3)
    │   ├── tidefs-replica-health (health surface)
    │   ├── tidefs-rebuild-planner (loss-event → rebuild)
    │   ├── tidefs-placement-planner (target selection)
    │   └── tidefs-chunk-shipper / tidefs-flow-commit-coordinator
    └── tidefs-resilver-service (U4)
        ├── tidefs-rebuild-planner (staged rebuild plans)
        ├── tidefs-placement-planner (new-topology placement)
        └── tidefs-recovery-loop (5-phase orchestration)

tidefs-background-scheduler (service lifecycle, budget, priority)
    └── All four services register here
```

## 2. Frozen Cross-Service Data Structures

### 2.1 SuspectLogEntry

The persistent coordination surface shared by scrub, deep scrub, repair, and
resilver. Stored as an append-only journal indexed by `(dataset_id, commit_group)`.

```rust
/// An entry in the persistent suspect log.
///
/// Written by scrub/deep-scrub on corruption detection.
/// Consumed by repair to schedule corrective action.
/// Updated by repair on completion.
/// Emitted as IntegrityEvent for observability.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SuspectLogEntry {
    /// Monotonically increasing entry ID within the suspect log.
    pub entry_id: u64,
    /// Dataset that owns the corrupt data.
    pub dataset_id: DatasetId,
    /// Transaction group at time of detection.
    pub commit_group: u64,
    /// Identifies the corrupt block or extent.
    pub block_id: ScrubBlockId,
    /// Object-store key for the corrupt block.
    pub object_key: Vec<u8>,
    /// Expected integrity digest (BLAKE3-256 truncated to 64 bits).
    pub expected_digest: IntegrityDigest64,
    /// Actual digest computed from the stored data.
    pub actual_digest: IntegrityDigest64,
    /// Which service detected the corruption.
    pub detected_by: DetectionSource,
    /// Current repair state.
    pub repair_state: RepairState,
    /// Timestamp of last state transition (seconds since epoch).
    pub last_transition_secs: u64,
    /// Number of repair attempts made.
    pub repair_attempts: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum DetectionSource {
    Scrub,
    DeepScrub,
    ReadPath,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum RepairState {
    /// Detected but not yet addressed.
    Suspect,
    /// Repair is in progress.
    Repairing,
    /// Successfully repaired (reconstructed from healthy replica).
    Repaired,
    /// Repair failed; block is unrecoverable.
    Unrecoverable,
    /// Repair not attempted (no redundancy available).
    SkippedNoRedundancy,
    /// False positive — deep scrub double-check cleared it.
    Cleared,
}
```

### 2.2 ScrubCursor (Resumable Pass State)

Independent cursors per service prevent scrub and deep scrub from sharing
position state. Each is persisted to a checkpoint object for crash-safe
resumption.

```rust
/// Resumable cursor for namespace-ordered scrub passes.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ScrubCursor {
    /// Dataset being scrubbed.
    pub dataset_id: DatasetId,
    /// Pass number (monotonically increasing, starts at 0).
    pub pass_number: u64,
    /// COMMIT_GROUP at which the pass started.
    pub pass_start_commit_group: u64,
    /// Last successfully verified inode_id (0 means pass start).
    pub last_verified_inode: u64,
    /// Within the current inode, last verified data version.
    pub last_verified_version: u64,
    /// Within the current version, last verified chunk index.
    pub last_verified_chunk: u64,
    /// Blocks scanned in this pass so far.
    pub blocks_scanned: u64,
    /// Blocks found corrupt in this pass so far.
    pub blocks_corrupt: u64,
    /// Timestamp of last checkpoint persistence.
    pub last_checkpoint_secs: u64,
}

/// Deep scrub cursor — extends ScrubCursor with reconstruction state.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DeepScrubCursor {
    pub base: ScrubCursor,
    /// Whether this pass includes cross-replica digest comparison.
    pub compare_replicas: bool,
    /// Last divergence found (0 = none).
    pub last_divergence_at_inode: u64,
}
```

### 2.3 RepairPlan

Generated by the repair service from SuspectLog entries. The rebuild planner
converts this into a loss-event and witness-set batch.

```rust
/// Repair plan for one or more corrupt blocks.
#[derive(Clone, Debug)]
pub struct RepairPlan {
    /// SuspectLog entries to repair.
    pub entries: Vec<SuspectLogEntry>,
    /// Selected repair strategy.
    pub strategy: RepairStrategy,
    /// Healthy source replicas for reconstruction.
    pub source_replicas: Vec<ReplicaId>,
    /// Target placement for reconstructed data.
    pub target_placement: FailureDomainPlacementPlan,
    /// Priority: inline (blocking read) or deferred (background).
    pub execution_mode: RepairExecutionMode,
    /// Validity token binding this plan to the current block state.
    pub validity_token: ValidityToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairStrategy {
    /// Reconstruct from healthy replica(s).
    Reconstruct,
    /// Truncate file to last known-good offset.
    Truncate { new_size: u64 },
    /// Mark block corrupt; reads return I/O error.
    MarkCorrupt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairExecutionMode {
    /// Execute immediately (on-read path).
    Inline,
    /// Enqueue for background processing.
    Deferred,
}
```

### 2.4 ResilverStagedRebuildPlan

Generated by the resilver service when a device is replaced or topology
changes. The rebuild planner stages this as a series of loss-event →
witness-set batches with escalating priority.

```rust
/// Staged rebuild plan for resilver.
#[derive(Clone, Debug)]
pub struct ResilverStagedRebuildPlan {
    /// Reason for resilver.
    pub trigger: ResilverTrigger,
    /// Total bytes that must be rebuilt.
    pub total_bytes_to_rebuild: u64,
    /// Bytes rebuilt so far.
    pub bytes_rebuilt: u64,
    /// Stages of increasing priority.
    pub stages: Vec<ResilverStage>,
    /// Cursor for resumption.
    pub cursor: ResilverCursor,
}

#[derive(Clone, Debug)]
pub struct ResilverStage {
    /// Loss-events in this stage.
    pub loss_events: Vec<LossEvent>,
    /// Priority at which this stage runs.
    pub priority: BackgroundServicePriority,
    /// Estimated bytes in this stage.
    pub estimated_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResilverTrigger {
    DeviceReplaced { old_device: DeviceId, new_device: DeviceId },
    TopologyChange { generation: u64 },
    ManualAdmin,
}
```

### 2.5 IntegrityEvent (Observability Bus)

Unified event type emitted to the observability pipeline.

```rust
/// Emitted by all four services for observability.
#[derive(Clone, Debug)]
pub enum IntegrityEvent {
    ScrubPassStarted { dataset_id: DatasetId, pass: u64, commit_group: u64 },
    ScrubPassCompleted { dataset_id: DatasetId, pass: u64, blocks_scanned: u64, blocks_corrupt: u64 },
    ScrubViolationFound { entry: SuspectLogEntry },
    DeepScrubPassStarted { dataset_id: DatasetId, pass: u64 },
    DeepScrubDivergence { dataset_id: DatasetId, inode: u64, digest_a: IntegrityDigest64, digest_b: IntegrityDigest64 },
    RepairStarted { plan: RepairPlan },
    RepairCompleted { entry_id: u64, outcome: RepairOutcome },
    RepairSkipped { entry_id: u64, reason: String },
    ResilverTriggered { plan: ResilverStagedRebuildPlan },
    ResilverStageCompleted { stage_index: usize, bytes_rebuilt: u64 },
    ResilverCompleted { total_bytes_rebuilt: u64 },
}
```

### 2.6 CascadingFailureGuard

Prevents repair cascades: if repair of block A triggers corruption detection
on replica of block B, the guard limits fan-out.

```rust
/// Per-domain + aggregate failure guard to prevent cascading repairs.
#[derive(Clone, Debug, Default)]
pub struct CascadingFailureGuard {
    /// Per failure-domain counter of active repairs.
    pub per_domain: HashMap<FailureDomainId, u32>,
    /// Aggregate counter across all domains.
    pub aggregate_active: u32,
    /// Maximum active repairs per domain before throttling.
    pub max_per_domain: u32,
    /// Maximum aggregate active repairs.
    pub max_aggregate: u32,
}

impl CascadingFailureGuard {
    /// Returns true if a new repair can be admitted.
    pub fn admit(&self, domain: FailureDomainId) -> bool {
        self.aggregate_active < self.max_aggregate
            && self.per_domain.get(&domain).copied().unwrap_or(0) < self.max_per_domain
    }
}
```

## 3. Algorithms

### 3.1 Scrub Pass (Namespace-Ordered Verification)

```
algorithm scrub_pass(cursor: &mut ScrubCursor, store: &LocalObjectStore,
                     checksum: &dyn BlockChecksum, budget: &WorkBudget):
    // Resume from last checkpoint.
    start_inode <- cursor.last_verified_inode
    start_version <- cursor.last_verified_version
    start_chunk <- cursor.last_verified_chunk

    for each inode in namespace_order(starting_from=start_inode):
        layout <- store.read_content_layout(inode)

        for each version in layout.versions(starting_from=start_version):
            for each chunk in version.chunks(starting_from=start_chunk):
                if budget.exhausted():
                    checkpoint(cursor)
                    return PassResult::BudgetExhausted

                data <- store.read(chunk.object_key)
                expected <- chunk.integrity_digest
                actual <- checksum.compute(&data)

                if expected != actual:
                    entry <- SuspectLogEntry::new(
                        block_id=chunk.block_id,
                        expected, actual,
                        detected_by=DetectionSource::Scrub,
                    )
                    suspect_log.append(entry)
                    emit(IntegrityEvent::ScrubViolationFound { entry })
                    cursor.blocks_corrupt += 1

                cursor.blocks_scanned += 1
                cursor.last_verified_chunk = chunk.index

            cursor.last_verified_version = version.number
        cursor.last_verified_inode = inode.id

    // Pass completed.
    emit(IntegrityEvent::ScrubPassCompleted { ... })
    return PassResult::Complete
```

**Checkpoint timing:** Every N blocks (default: 10,000) or every T seconds
(default: 30), whichever comes first. Checkpoints write `ScrubCursor` to a
designated object key `ck.scrub_cursor.{dataset_id}`.

**Budget integration:** `WorkBudget` is supplied by the background scheduler
per tick. The scrub pass yields when the budget is exhausted and resumes on
the next tick from the last checkpoint.

### 3.2 Deep Scrub (Reconstruction + Digest Comparison)

```
algorithm deep_scrub_pass(cursor: &mut DeepScrubCursor,
                          store: &LocalObjectStore,
                          replicas: &[ReplicaHandle],
                          auditor: &AntiEntropyAuditor):
    // Phase 1: Verify local checksums (same as scrub_pass).
    // Phase 2: For each block, reconstruct from shards and compare.

    for each block in namespace_order:
        // Verify local checksum first (cheap).
        outcome <- verify_local(block)

        if outcome == Clean:
            continue

        // Reconstruct from remote replicas and compare digests.
        shards <- fetch_shards_from_replicas(block, replicas)
        reconstructed <- erasure_decode(shards)
        reconstructed_digest <- compute_digest(&reconstructed)
        local_digest <- compute_digest(&store.read(block.key))

        if reconstructed_digest != local_digest:
            // Divergence detected — ticket for repair.
            auditor.record_divergence(block, local_digest, reconstructed_digest)
            suspect_log.append(SuspectLogEntry {
                detected_by: DetectionSource::DeepScrub,
                ...
            })

    return PassResult::Complete
```

**Double-check mode:** For marginal media (devices with increasing
correctable error rates), deep scrub activates double-check mode:
reconstruct a second time from a different shard subset and verify both
reconstructions agree before flagging corruption. This prevents phantom
corruption reports from a single degraded source.

### 3.3 Repair Execution (Inline + Deferred)

```
algorithm repair_entry(entry: &SuspectLogEntry,
                       health_tracker: &ReplicaHealthTracker,
                       rebuild_planner: &RebuildPlanner,
                       placement_planner: &PlacementPlanner,
                       chunk_shipper: &ChunkShipper,
                       flow_coordinator: &FlowCommitCoordinator,
                       failure_guard: &mut CascadingFailureGuard):
    // 1. Check failure guard saturation.
    domain <- resolve_failure_domain(entry.block_id)
    if not failure_guard.admit(domain):
        entry.repair_state <- RepairState::Suspect  // deferred
        return RepairResult::Throttled

    // 2. Select repair strategy.
    redundancy <- health_tracker.available_redundancy(entry.block_id)
    strategy <- if redundancy > 0:
        RepairStrategy::Reconstruct
    else if entry.block_id.kind == ContentChunk:
        RepairStrategy::Truncate { new_size: ... }
    else:
        RepairStrategy::MarkCorrupt

    // 3. Source selection (deterministic).
    sources <- health_tracker.healthy_replicas(entry.block_id)
    ordered_sources <- deterministic_shuffle(sources, seed=entry.block_id)

    // 4. Target placement (anti-affinity).
    target_plan <- placement_planner.compute_replica_target_set(
        block_id=entry.block_id,
        exclude=entry.block_id.location,
        anti_affinity=AntiAffinityClass::Strict,
    )

    // 5. Loss-event -> rebuild.
    loss_event <- LossEvent {
        block_id: entry.block_id,
        degraded_replicas: vec![entry.block_id.location],
        commit_group: entry.commit_group,
    }
    rebuild_plan <- rebuild_planner.build_witness_set(loss_event, ordered_sources)

    // 6. Transfer.
    for each witness in rebuild_plan.witnesses:
        chunk_shipper.stage(witness.source, witness.dest)
        receipt <- chunk_shipper.ship()
        flow_coordinator.verify_and_place(receipt, target_plan)

    // 7. Record outcome.
    entry.repair_state <- RepairState::Repaired
    suspect_log.update(entry)
    emit(IntegrityEvent::RepairCompleted { entry_id: entry.entry_id, ... })

    // 8. Clear health tracker suspicion.
    health_tracker.clear_suspicion(entry.block_id)

    return RepairResult::Success
```

**Inline vs. Deferred decision:**
- **Inline:** Repair is executed synchronously on the read path when the
  reader is a foreground (user-facing) operation. The reader blocks until
  reconstruction completes or a timeout (default: 500ms) elapses, at which
  point the repair is downgraded to deferred and the reader receives an
  `EIO` for that block.
- **Deferred:** Repair is enqueued in the background scheduler at
  `Critical` priority. The suspect block remains in the SuspectLog at
  `Suspect` state until repair completes.

### 3.4 Resilver Staged Rebuild

```
algorithm resilver_staged_rebuild(trigger: ResilverTrigger,
                                  rebuild_planner: &RebuildPlanner,
                                  placement_planner: &PlacementPlanner):
    // 1. Scope: enumerate all blocks on the lost/replaced device.
    lost_blocks <- enumerate_device_blocks(membership, trigger)
    total_bytes <- sum(lost_blocks.map(|b| b.size))

    // 2. Stage 1 (LatencySensitive): critical metadata blocks.
    metadata_blocks <- lost_blocks.filter(|b| b.kind.is_metadata())
    stage1 <- ResilverStage {
        loss_events: metadata_blocks.into_loss_events(),
        priority: BackgroundServicePriority::LatencySensitive,
        estimated_bytes: sum(metadata_blocks.map(|b| b.size)),
    }

    // 3. Stage 2 (Throughput): active data blocks (recent COMMIT_GROUPs).
    recent_data <- lost_blocks
        .filter(|b| b.kind.is_data() && b.last_written_commit_group > staleness_threshold)
    stage2 <- ResilverStage {
        loss_events: recent_data.into_loss_events(),
        priority: BackgroundServicePriority::Throughput,
        estimated_bytes: sum(recent_data.map(|b| b.size)),
    }

    // 4. Stage 3 (BestEffort): cold/archive data blocks.
    cold_data <- lost_blocks
        .filter(|b| b.kind.is_data() && b.last_written_commit_group <= staleness_threshold)
    stage3 <- ResilverStage {
        loss_events: cold_data.into_loss_events(),
        priority: BackgroundServicePriority::BestEffort,
        estimated_bytes: sum(cold_data.map(|b| b.size)),
    }

    plan <- ResilverStagedRebuildPlan {
        trigger, total_bytes_to_rebuild: total_bytes,
        bytes_rebuilt: 0,
        stages: vec![stage1, stage2, stage3],
        cursor: ResilverCursor::default(),
    }

    // Execute stages sequentially, escalating priority at each stage.
    for stage in plan.stages:
        for loss_event in stage.loss_events:
            placement <- placement_planner.compute_replica_target_set(
                exclude=loss_event.failed_device,
            )
            rebuild_planner.process(loss_event, stage.priority, placement)

    emit(IntegrityEvent::ResilverCompleted { ... })
```

**Priority escalation rationale:** Metadata first (fastest path to
operational safety), then active data (user-visible), then cold data
(completeness). Each stage widens the safety window before the next
stage starts.

### 3.5 Anti-Entropy Auditor Convergence

```
algorithm ae_auditor_convergence_pass(auditor: &mut AntiEntropyAuditor,
                                       replicas: &[ReplicaHandle]):
    // 6-state machine: Idle → Scanning → Comparing → Converging → Verifying → Idle.
    // Each state is a stable, checkpointable phase.

    auditor.transition(Idle → Scanning)
    scan_set <- auditor.scan_scheduler.next_batch()
    for each block in scan_set:
        digests <- gather_digests_from_all_replicas(block, replicas)
        auditor.comparator.record(block, digests)

    auditor.transition(Scanning → Comparing)
    divergences <- auditor.comparator.find_divergences()
    if divergences.is_empty():
        auditor.transition(Comparing → Idle)
        return ConvergenceResult::Converged

    auditor.transition(Comparing → Converging)
    for each divergence in divergences:
        // Ticket for deep scrub double-check, then repair if confirmed.
        suspect_log.append_divergence(divergence)

    auditor.transition(Converging → Verifying)
    // Re-scan divergent blocks after repair.
    for each divergence in divergences:
        repaired <- suspect_log.check_state(divergence.block_id)
        if repaired != RepairState::Repaired:
            auditor.record_persistent_divergence(divergence)

    auditor.transition(Verifying → Idle)
    return ConvergenceResult::ConvergedWithDivergences { ... }
```

## 4. Scheduling and Budget Model

### 4.1 Service Registration

Each service registers with the background scheduler via:

```rust
trait BackgroundService {
    fn service_id(&self) -> ServiceId;
    fn default_priority(&self) -> BackgroundServicePriority;
    fn tick(&mut self, budget: WorkBudget) -> TickResult;
    fn checkpoint(&self) -> Checkpoint;
    fn resume(&mut self, checkpoint: Checkpoint);
    fn validity_token(&self) -> ValidityToken;
}
```

| Service | `service_id` | `default_priority` | Tick budget (default) |
|---------|-------------|-------------------|----------------------|
| Scrub | `scrub_0` | Throughput | 8 MiB / tick |
| Deep Scrub | `deep_scrub_0` | BestEffort | 4 MiB / tick |
| Repair | `repair_0` | Critical | Unlimited (small scope) |
| Resilver | `resilver_0` | LatencySensitive → Throughput → BestEffort (staged) | 32 MiB / tick |

### 4.2 Priority Staging

The scheduler dispatches in order: Critical → LatencySensitive → Throughput
→ BestEffort → Opportunistic. Within each stage, round-robin fairness across
registered services. Repair always runs first (Critical); resilver escalates
through stages as rebuild progresses.

### 4.3 Concurrent Execution

Scrub, deep scrub, and resilver may run concurrently with independent
cursors and budgets. The scheduler enforces per-tick IO budget limits:

- **Scrub + Resilver concurrent:** Scrub uses the Throughput lane; resilver
  uses LatencySensitive → Throughput. Both compete for the Throughput budget
  slice with round-robin fairness. Deep scrub runs at BestEffort, taking only
  leftover budget after higher-priority services.
- **Scrub-during-resilver:** Allowed, not suspended. This differs from ZFS
  (`dsl_scan` pause). Rationale: independent cursors mean no shared position
  state to corrupt, and separate budgets prevent starvation.

### 4.4 Validity Tokens

Every tick produces a `ValidityToken` binding the service's work to the
current data state. Before the next tick, the token is checked:

- If the data the service was operating on is still valid (no COMMIT_GROUP write
  since): proceed.
  and re-verify. This prevents repairing data that was already overwritten.

## 5. Integration Points

### 5.1 With Checksum Architecture (#2070)

- BlockChecksum trait: `FastBlockChecksum` (CRC32C-only, for scrub) and
  `ProductionBlockChecksum` (CRC32C header + BLAKE3-256 payload, for deep
  scrub and repair).
- `IntegrityTrailerV2` (112-byte): carries both checksums plus EC shard
  fields for cross-replica reconstruction.
- Domain-separated BLAKE3 contexts per record type prevent hash confusion
  between different data paths.

### 5.2 With Background Service Framework (#2067)

- All four services implement `BackgroundService`.
- Phases 5–10 of the background service framework (View builder, Data
  independent of scrub/repair/resilver. The scrub services are among the
  first consumers of the background service framework.
- Scrub/deep-scrub/repair/resilver are tracked as wire-up issues within
  #1877's deferred implementation plan.

### 5.3 With IncrementalJob Core (#1930)

- All four services use `JobKind::Scrub`, `JobKind::DeepScrub`,
  `JobKind::Repair`, `JobKind::Resilver`.
- Cursor resumption uses `CursorState` and `Checkpoint` from
  `tidefs-types-incremental-job-core`.
- `WorkBudget` governs per-tick IO allocation.

### 5.4 With Orphan Index (#1961)

- Scrub may encounter inode references to blocks that are no longer
  reachable. These are ticketed to the orphan index rather than the
  SuspectLog.
- Repair does not operate on orphaned blocks — the orphan recovery
  job handles those.

### 5.5 With Shard Groups and Rebake (#1964)

- Deep scrub uses shard-group reconstruction to verify data integrity
  across replicas.
- Repair uses shard groups to select healthy source replicas.
- Resilver uses rebake machinery to place new replicas on replacement
  devices.

### 5.6 With Inline Post-Process Deduplication

- Scrub/deep-scrub may discover duplicate blocks. These are emitted as
  `IntegrityEvent`s for the dedup pipeline to consume.
- Repair must not break dedup references: when reconstructing a block
  that is dedup-referenced, all referents must be updated.

## 6. Tradeoffs

### 6.1 Separate vs. Shared Cursors

| Decision | Chosen | Rationale |
|----------|--------|-----------|
| Separate cursors for scrub and deep scrub | ✓ | Independent pass intervals (7-day vs 30-day); preventing deep scrub from blocking scrub progress; avoiding cursor corruption when one service crashes |
| Shared cursor (ZFS approach) | ✗ | Simpler implementation but scrub pauses during deep scrub; single point of cursor corruption |

### 6.2 Suspend Scrub During Resilver vs. Concurrent

| Decision | Chosen | Rationale |
|----------|--------|-----------|
| Concurrent scrub + resilver | ✓ | Independent IO budgets prevent starvation; validity tokens prevent stale-data races; no shared cursor state |
| Suspend scrub during resilver (ZFS) | ✗ | Unnecessary serialization when budgets are enforced; doubles time to data-integrity confidence |

### 6.3 Deep Scrub Always-On vs. Opt-In

| Decision | Chosen | Rationale |
|----------|--------|-----------|
| Always-on at BestEffort priority | ✓ | Silent corruption lurks; BestEffort ensures it never starves foreground IO; 30-day default interval balances cost |
| Opt-in (admin must initiate) | ✗ | Silent corruption can persist for months; admin forgets to run |

### 6.4 Inline vs. Deferred Repair

| Decision | Chosen | Rationale |
|----------|--------|-----------|
| Dual-path: inline + deferred | ✓ | Users expect reads to succeed; inline repair with 500ms timeout gives best-effort; fallback to deferred avoids blocking |
| Inline-only | ✗ | Blocks readers on slow reconstruction; cascading latency |
| Deferred-only | ✗ | Readers see EIO until background repair completes; poor UX |

### 6.5 Resilver Source Selection

| Decision | Chosen | Rationale |
|----------|--------|-----------|
| Centralized: placement planner + rebuild planner | ✓ | Deterministic target selection with anti-affinity; failure-domain awareness; consistent with repair path |
| Per-node independent | ✗ | Risk of conflicting placement decisions; no global failure-domain view |

### 6.6 Local-Filesystem Integration Strategy

| Decision | Chosen | Rationale |
|----------|--------|-----------|
| Separate service crates (`tidefs-scrub-service` etc.) | ✓ | Separation of concerns; testability; independent compilation; follows crate decomposition pattern established by cleanup/reclaim/orphan-recovery |
| Modules within `tidefs-local-filesystem` (current) | ✗ | Too coupled; hard to test independently; bloats local-filesystem crate |

### 6.7 SuspectLog as Coordination Surface

| Decision | Chosen | Rationale |
|----------|--------|-----------|
| Persistent append-only journal | ✓ | Crash-safe coordination; scrub writes, repair consumes, both update; audit trail for compliance |
| In-memory queue | ✗ | Lost on crash; scrub progress wasted; no audit trail |

### 6.8 Cascading Failure Guard: Admission vs. Unlimited

| Decision | Chosen | Rationale |
|----------|--------|-----------|
| Per-domain + aggregate caps | ✓ | Prevents repair cascades (repair of A triggers corruption on B → repair of B triggers C → …); caps at 16/domain, 64 aggregate |
| Unlimited admission | ✗ | Risk of repair storms saturating IO and network bandwidth |

## 7. Error Hierarchy

```rust
#[derive(Debug, thiserror::Error)]
pub enum ScrubError {
    #[error("checksum mismatch at {block_id}: expected {expected}, got {actual}")]
    ChecksumMismatch { block_id: ScrubBlockId, expected: IntegrityDigest64, actual: IntegrityDigest64 },
    #[error("block unreadable: {key} — {reason}")]
    Unreadable { key: String, reason: String },
    #[error("budget exhausted after {blocks_scanned} blocks")]
    BudgetExhausted { blocks_scanned: u64 },
    #[error("cursor corrupted: {reason}")]
    CursorCorrupted { reason: String },
}

#[derive(Debug, thiserror::Error)]
pub enum RepairError {
    #[error("no healthy replicas available for {block_id}")]
    NoHealthyReplicas { block_id: ScrubBlockId },
    #[error("reconstruction failed for {block_id}: {reason}")]
    ReconstructionFailed { block_id: ScrubBlockId, reason: String },
    #[error("throttled by cascading failure guard (domain: {domain:?})")]
    Throttled { domain: FailureDomainId },
    #[error("validity token expired for {block_id}")]
    TokenExpired { block_id: ScrubBlockId },
}

#[derive(Debug, thiserror::Error)]
pub enum ResilverError {
    #[error("device {device:?} not found in topology")]
    DeviceNotFound { device: DeviceId },
    #[error("placement failed: no suitable target with anti-affinity")]
    PlacementFailed,
    #[error("rebuild stage {stage} failed: {reason}")]
    StageFailed { stage: usize, reason: String },
}
```

## 8. Observability

### 8.1 IntegrityEvent Emissions

All four services emit `IntegrityEvent` variants to the observability
pipeline. A dedicated counter registry (`IntegrityCounters`) provides:

| Counter | Emitter | Description |
|---------|---------|-------------|
| `scrub.blocks_scanned` | Scrub | Total blocks verified |
| `scrub.blocks_corrupt` | Scrub | Corruptions detected |
| `deep_scrub.divergences` | Deep Scrub | Cross-replica digest divergences |
| `repair.attempts` | Repair | Total repair attempts |
| `repair.successes` | Repair | Successful reconstructions |
| `repair.failures` | Repair | Failed repairs |
| `repair.skipped` | Repair | Skipped (no redundancy) |
| `repair.throttled` | Repair | Throttled by failure guard |
| `resilver.bytes_rebuilt` | Resilver | Bytes rebuilt |
| `resilver.stage_completed` | Resilver | Stage completions |

### 8.2 SuspectLog Statistics

The SuspectLog itself provides queryable statistics:

- `open_suspect_count` — entries still in `Suspect` state
- `repairing_count` — entries in `Repairing` state
- `unrecoverable_count` — entries in `Unrecoverable` state
- `mean_repair_latency_secs` — average time from detection to repair
- `repair_success_rate` — fraction of attempted repairs that succeed

## 9. Deferred Implementation Plan

### 9.1 Implementation Units

| Unit | Crate | Lines (est.) | Description |
|------|-------|-------------|-------------|
| U1 | `tidefs-scrub-service` | 800–1200 | ScrubService with namespace-ordered pass, ScrubCursor persistence, SuspectLog appends |
| U2 | `tidefs-deep-scrub-service` | 1000–1500 | DeepScrubService with reconstruction-from-shards, double-check mode, anti-entropy auditor integration |
| U3 | `tidefs-repair-service` | 1200–1800 | RepairService with inline/deferred dual path, source selection, failure guard, rebuild-planner delegation |
| U4 | `tidefs-resilver-service` | 1000–1500 | ResilverService with 3-stage priority-escalated rebuild, placement-planner integration |
| U5 | IntegrityEvent wiring | 400–600 | Event emission, counter registration, observability pipeline integration |
| U6 | Config surface | 300–500 | Deterministic constraint knobs, interval config, budget tuning |
| U7 | SuspectLog persistence | 500–800 | Append-only journal, on-disk format, query API, compaction |
| U8 | Marginal-media detection | 400–600 | Correctable error rate tracking, double-check activation threshold |
| U9 | Cross-service orchestration | 600–900 | SuspectLog consumption loop, repair scheduling, validity-token binding |
| U10 | Integration tests | 800–1200 | End-to-end: scrub→detect→repair→verify, resilver staged rebuild, failure guard saturation |

**Total estimated new code:** 7,000–9,500 lines across 4 new crates + wiring.

### 9.2 Dependency Graph

```
Phase 1: U7 (SuspectLog) → U1 (Scrub) → U2 (DeepScrub)
Phase 2: U1, U2 → U3 (Repair), U3 → U4 (Resilver)
Phase 3: U5 (Events), U6 (Config), U8 (Marginal media)
Phase 4: U9 (Orchestration), U10 (Integration tests)
```

### 9.3 Implementation Dependencies

Before U1–U4 can begin, the following must be complete:

- `tidefs-background-scheduler` phases 1–4 (completed)
- `tidefs-types-incremental-job-core` (completed)
- `tidefs-replica-health` (completed, 2378 lines)
- `tidefs-rebuild-planner` (completed, 2495 lines)
- `tidefs-placement-planner` (completed)
- `tidefs-chunk-shipper` (completed)
- `tidefs-flow-commit-coordinator` (completed)
- `tidefs-anti-entropy-auditor` (completed)
- `tidefs-recovery-loop` (completed, 849 lines)

## 10. References

| Document | Subject |
|----------|---------|
| `docs/design/end-to-end-checksum-architecture-g3-pillar.md` | IntegrityTrailerV2, BLAKE3-256 domain separation |
| `docs/design/background-service-framework-design.md` | Unified scheduler, priority staging, validity tokens |
| `docs/design/shard-groups-replicas-rebake-design-spec.md` | Shard groups, replication, rebake pathway |
| `docs/design/incremental-job-core-types-crate-design.md` | JobKind, WorkBudget, Checkpoint, IncrementalJob trait |
| `docs/design/persistent-orphan-index-wire-up-design-1961.md` | Orphan index integration, scrub/orphan boundary |
| `docs/design/scrub-deep-scrub-repair-resilver-orchestration-placement-ae-auditor.md` | Placement planner and AE auditor integration (#1943) |
| `crates/tidefs-local-filesystem/src/scrub.rs` | Existing block-level scrub (612 lines) |
| `crates/tidefs-local-filesystem/src/repair.rs` | Existing block-level repair (633 lines) |
| `crates/tidefs-replica-health/src/lib.rs` | Per-chunk health tracker (public API) |
| `crates/tidefs-rebuild-planner/src/lib.rs` | Loss-event → witness-set rebuild planner |
| `crates/tidefs-anti-entropy-auditor/src/lib.rs` | 6-state AE auditor state machine |
| `crates/tidefs-recovery-loop/src/lib.rs` | 5-phase continuous recovery loop |
