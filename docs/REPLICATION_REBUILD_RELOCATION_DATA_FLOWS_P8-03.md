# replication / rebuild / relocation data flows P8-03 (v0.320)

This document is the source-of-truth for **P8-03** in the production design ledger.

It answers the production question that remained deliberately open after `P2-02`, `P4-02`, `P4-03`, `P4-04`, `P5-02`, `P5-03`, `P6-01`, `P6-02`, and `P7-03`:

**How does tidefs move immutable payloads, restore lost placement, and relocate live extents across devices / nodes / failure domains without hidden authority leaks, fake durability, or folklore around rebuild and anti-entropy?**

The answer must work for:
- Rust userspace `policy_authority` / `authority_publication` / `claim_reserve_witness` / `response_normalizer` services
- userspace `posix_filesystem_adapter` and `block_volume_adapter` charter adapters
- future kernel-assisted `posix_filesystem_adapter` / `block_volume_adapter` paths on Linux 7.0
- local single-node deployments that later scale out
- distributed deployments across multiple failure domains
- normal replication, anti-entropy catch-up, repair rebuild, reclaim relocation, failover recovery, and cutover drains

See also:
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/ALLOCATOR_RECLAIM_FREE_SPACE_SCHEMA_FAMILY_P2-02.md`
- `docs/MEMORY_PRESSURE_RECLAIM_RESERVE_INTERACTION_P4-03.md`
- `docs/ZERO_COPY_DMA_PINNING_PAGE_LOAN_LAW_P4-04.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## Metrics snapshot

| Metric | Count |
|---|---:|
| Canonical data-flow classes | 6 |
| Canonical runtime components | 9 |
| Canonical state machines | 6 |
| New schema families introduced here | 11 |
| New algorithm families introduced here | 11 |
| New distributed protocol families introduced here | 1 |

## 1. Core law

1. **Published truth moves first, replica placement follows by law.**
   Publication receipts define what is authoritative. Replication, rebuild, and relocation make that truth durable and placeable; they do not create publication truth on their own.

2. **Immutable revision payloads are the primary movement unit.**
   Data movement operates on immutable revision payloads, extent groups, and witness-linked chunk families. Mutable heads, projection roots, and policy state move only through successor publication.

3. **Replica placement is receipt-backed, not implied by copying bytes.**
   Copying a chunk to a target does not make it legal placement. The placement becomes legal only after verification and emission of the matching transfer / placement receipts.

4. **Rebuild and relocation are sibling flows, not ad hoc special cases.**
   Rebuild is recovery from missing or suspect placement. Relocation is planned movement for reclaim, rebalancing, tiering, or policy change. They share staging, verification, and commit law.

5. **Authority and product payloads are moved under different obligations.**
   Authority payloads obey protected reserve floors and witness requirements. Product payloads are admitted only from surplus and are dropped/rebuilt before authority reserve is threatened.

6. **Every movement flow is anchor-bound.**
   Replication, rebuild, and relocation tickets are bound to:
   - the relevant authority domain / epoch,
   - the publication / repair / failover receipts they depend on,
   - the reserve/budget domains that pay for them,
   - and the witness sets that justify reconstructability.

7. **Verification is explicit and digest-backed.**
   A target replica is not considered live until digest / witness / range verification succeeds and a verification receipt is emitted.

8. **Partial progress is legal but must be visible.**
   Lagging, degraded, rebuilding, relocating, fenced, or quarantined states are legal states with explicit records. Hidden “some replicas probably exist” folklore is forbidden.

9. **Failover, cutover, and pressure can preempt data movement.**
   Rebuild and relocation must obey freshness fences, failover escrow, reserve protection, and pressure throttles. They may be paused or narrowed before they violate more important obligations.

10. **Userspace and kernel variants share one logical movement graph.**
    Linux 7.0 userspace services may use TCP/QUIC/io_uring and user-memory staging; future kernel paths may use bios, folios, or in-kernel transports. The law of tickets, receipts, witness use, and commit states stays the same.

## 2. Canonical data-flow classes

Tidefs now distinguishes **6 canonical data-flow classes**.

| Class | Purpose |
|---|---|
| `data_flow_0.steady_replication` | normal post-publication replica propagation to satisfy placement targets |
| `data_flow_1.catchup_repair` | anti-entropy or lagged-target catch-up without source loss |
| `data_flow_2.loss_rebuild` | recovery after target / segment / node loss or confirmed unreadability |
| `data_flow_3.reclaim_relocation` | copy-forward drain for reclaim, compaction, or pressure relief |
| `data_flow_4.policy_relocation` | movement for placement/tiering/policy changes without immediate pressure |
| `data_flow_5.cutover_or_failover_drain` | urgent drain/reshaping before failover, cutover, resize, or authority movement |

Rules:
- `data_flow_0` and `data_flow_1` are placement maintenance flows.
- `data_flow_2` is reserve-protected and may preempt product work.
- `data_flow_3` and `data_flow_4` share machinery but differ in admission priority and urgency.
- `data_flow_5` may override ordinary queue ordering when required by failover/cutover law.

## 3. Canonical runtime components

The distributed runtime now distinguishes **9 canonical components**.

| Component | Responsibility |
|---|---|
| `data_copy_0.placement_planner` | compute desired replica targets from policy, failure domains, and tier goals |
| `data_copy_1.transfer_orchestrator` | build chunk/extent transfer tickets and assign them to links/workers |
| `data_copy_3.replica_health_tracker` | lag, suspect, degraded, stale, and verified-placement state |
| `data_copy_4.rebuild_planner` | open rebuild flows after loss/suspect events and choose source witnesses |
| `data_copy_5.relocation_planner` | open relocation flows for reclaim/tiering/policy change |
| `data_copy_6.chunk_shipper` | stage and transport data units, including zero-copy paths when legal |
| `data_copy_7.flow_commit_coordinator` | emit transfer/verification/placement/relocation receipts and advance state |
| `data_copy_8.anti_entropy_auditor` | periodic scan / compare / repair-candidate discovery |

No component is allowed to create hidden authority truth. All legal progress must be receipt-backed.

## 4. Canonical state machines

### 4.1 Replica chunk state

`rcanonical_schema.absent -> rcs1.ticketed -> rcs2.inflight -> rcs3.received -> rcs4.verified -> rcs5.placed`

Side exits:
- `rcsX.suspect`
- `rcsX.quarantined`
- `rcsX.retired`
- `rcsX.stale_but_usable`

### 4.2 Replication flow state

`rfs0.open -> rfs1.planned -> rfs2.transferring -> rfs3.verifying -> rfs4.committed -> rfs5.closed`

Abort / hold exits:
- `rfsX.throttled`
- `rfsX.fenced`
- `rfsX.aborted`

### 4.3 Rebuild flow state

`rebuild_state_0.open -> rebuild_state_1.loss_scoped -> rebuild_state_2.source_selected -> rebuild_state_3.rebuilding -> rebuild_state_4.verified -> rebuild_state_5.republished_if_needed -> rebuild_state_6.closed`

Exceptional exits:
- `rbX.partial_degraded`
- `rbX.quarantine_required`
- `rbX.branch_required`

### 4.4 Relocation flow state

`relocation_state_0.open -> relocation_state_1.copying -> relocation_state_2.verifying -> relocation_state_3.pointer_move_ready -> relocation_state_4.committed -> relocation_state_5.source_retire_ready -> relocation_state_6.closed`

Exceptional exits:
- `rlX.hold_for_pressure`
- `rlX.hold_for_fence`
- `rlX.abort_and_keep_source`

### 4.5 Replica health state

`replica_health_0.healthy -> replica_health_1.lagged -> replica_health_2.suspect -> replica_health_3.degraded -> replica_health_4.rebuilding -> replica_health_5.recovered`

### 4.6 Anti-entropy scan state

`anti_entropy_0.idle -> anti_entropy_1.enumerating -> anti_entropy_2.compare -> anti_entropy_3.divergence_found -> anti_entropy_4.ticketed -> anti_entropy_5.resolved`

## 5. Canonical schema families

The design now introduces **11 canonical schema families**.

| Record | Key fields | Role |
|---|---|---|
| `ReplicaSetRecord` | `replica_set_id`, `subject_ref`, `placement_policy_ref`, `required_count`, `target_failure_domains`, `current_placement_receipt_refs` | authoritative desired/actual replica group state |
| `ReplicaPlacementIntentRecord` | `intent_id`, `flow_class`, `subject_ref`, `source_refs`, `target_refs`, `policy_revision_ref`, `budget_domain_ref`, `reserve_class_ref` | authoritative placement / movement intent |
| `ReplicaChunkStateRecord` | `chunk_id`, `subject_ref`, `source_ref`, `target_ref`, `range_ref`, `digest`, `state`, `transfer_ticket_ref`, `verification_receipt_ref` | authoritative per-chunk placement state |
| `ReplicaTransferTicketRecord` | `ticket_id`, `intent_ref`, `chunk_refs`, `source_anchor_set`, `target_ref`, `pin_budget_ref`, `freshness_fence_ref`, `expiry` | authoritative transfer admission ticket |
| `ReplicaTransferReceipt` | `receipt_id`, `ticket_ref`, `bytes_moved`, `source_anchor_hash`, `target_anchor_hash`, `completion_epoch`, `worker_refs` | canonical receipt of transfer completion |
| `ReplicaVerificationReceipt` | `receipt_id`, `chunk_refs`, `digest_results`, `witness_refs`, `quorum_class`, `verification_epoch`, `status` | canonical verification truth |
| `RebuildFlowRecord` | `rebuild_flow_id`, `loss_event_ref`, `scope_selector`, `source_candidate_refs`, `target_refs`, `state`, `degraded_class` | authoritative rebuild lifecycle |
| `RebuildBatchRecord` | `batch_id`, `rebuild_flow_ref`, `chunk_refs`, `source_bundle_refs`, `target_refs`, `verification_requirements` | authoritative batch planning unit for rebuild |
| `RelocationFlowRecord` | `relocation_flow_id`, `reason_class`, `scope_selector`, `source_refs`, `target_refs`, `state`, `reclaim_debt_ref` | authoritative relocation lifecycle |
| `RelocationBatchRecord` | `batch_id`, `relocation_flow_ref`, `chunk_refs`, `pointer_move_ready`, `source_retire_ready`, `verification_refs` | authoritative relocation batch unit |
| `ReplicaLagStateRecord` | `subject_ref`, `target_ref`, `freshness_fence_frontier`, `lag_class`, `bytes_behind`, `oldest_missing_receipt_ref`, `degraded_visibility_class` | authoritative lag / degraded visibility state |

Rules:
- `ReplicaSetRecord` and `ReplicaPlacementIntentRecord` are authority-side declarations.
- `ReplicaChunkStateRecord` is the fine-grained legal state of movement.
- `ReplicaLagStateRecord` is required so charters can truthfully report degraded / stale-bounded states.

## 6. Canonical algorithms and protocol families

The design now introduces **11 new algorithm / protocol families**.

| Algorithm / protocol | Purpose |
|---|---|
| `compute_replica_target_set()` | choose legal target nodes/devices/failure domains from placement policy |
| `stage_replica_transfer_ticket()` | reserve transfer resources, freeze anchor set, and issue ticket |
| `stream_replica_chunks_under_ticket()` | move chunk payloads under pin/fence/budget law |
| `verify_transferred_chunks_against_digest_and_witness()` | digest/quorum verification before placement becomes legal |
| `commit_replica_transfer_and_placement_receipts()` | emit receipts and advance chunk/set state |
| `open_rebuild_flow_from_loss_event()` | derive rebuild scope from a loss/suspect event |
| `schedule_rebuild_batches_from_witness_sets()` | choose source bundles and batch order for rebuild |
| `open_relocation_flow_from_policy_or_reclaim()` | derive relocation scope from reclaim/tiering/policy triggers |
| `seal_relocation_batch_and_publish_pointer_move()` | commit relocation and retire previous placement safely |
| `advance_replica_health_and_lag_frontiers()` | update lag/degraded states from fences and receipts |
| `replicate_rebuild_relocate_dataflows()` | distributed protocol family coordinating the whole movement graph |

### 6.1 Protocol law

`replicate_rebuild_relocate_dataflows()` obeys these rules:
- transfer tickets are admitted only after reserve/budget checks
- transfer sources and targets are frozen to an anchor/fence set
- verification receipts must precede legal placement confirmation
- pointer-move commits for relocation are atomic with source-retire eligibility
- lag state must be updated whenever a fence frontier or placement receipt advances
- failure, cutover, or reserve-protection events may downgrade or pause flows but may not invent false completion

### 6.2 OW-304 executable replicated object/root storage slice

`crates/tidefs-replication-model` now binds the OW-304 row to source.
It consumes `membership_placement_0` placement policy from `crates/tidefs-membership-epoch` instead of inventing a second replica-placement law.

The executable slice includes:

- `ReplicatedObjectRootRecord` for immutable object payloads and authenticated root payloads;
- `ReplicaCopyRecord` for verified, missing, suspect, unreachable, or rebuilding copies;
- `ReplicatedWritePlan` for exact, degraded, and no-quorum write outcomes;
- `ReplicatedReadPlan` for exact, degraded-but-valid, repair-required, and unavailable read outcomes;
- `RebuildPlan` for restoring required failure-domain spread from verified sources.

It covers degraded read/write, explicit no-quorum refusal, and rebuild restoration tests.
This is a deterministic replicated object/root storage model; networked replication transport, streaming chunk movement, relocation execution, and production distributed runtime remain deferred.

The storage-node pool-backed scrub boundary now exposes `rebuild_admission`,
`rebuild_planner`, and `rebuild_execution_candidates` previews from live
`Pool::placement_receipt_refs()` output. The execution-candidate preview is
intentionally scoped to cross-checking, not completion: it lists candidate
repair work only when rebuild-runtime admission and the strict reconstruction
planner agree on the same receipt, source, target, payload length, and digest.
It proves the storage-node can derive executable receipt-addressed candidates
without synthesizing placement from topology or compatibility listings, while
distributed transfer execution, verification receipts, and repaired placement
publication remain the runtime handoff work.

### 6.3 OW-305 executable rebuild/backfill/rebalance slice

`crates/tidefs-replication-model` now also binds OW-305 movement planning to
source. It extends the OW-304 object/root model with deterministic movement
records instead of treating repair as a hidden side effect.

The executable slice includes:

- `ReplicaMovementIntentRecord` for source placement receipt, source, target,
  digest, byte count, and required verification on each planned transfer;
- `ReplicaCapacityRecord` for capacity and reserved rebuild floor inputs;
- `ReplicaMovementPlan` for explicit rebuild, backfill, and rebalance outcomes;
- `open_rebuild_flow_from_loss_event()` for fault-injection cases where missing,
  suspect, unreachable, or digest-mismatched copies must be restored from
  verified sources;
- `schedule_backfill_batches_from_witness_sets()` for lagged verified copies
  that need freshness-frontier catch-up without replacing fresh sources;
- `plan_rebalance_for_capacity_movement()` for capacity-movement cases where an
  overloaded verified copy moves to a failure-domain-legal target without
  violating reserve floors.

It covers fault-injection, no-source refusal, lagged-copy backfill,
capacity-movement rebalance, and reserve-floor blockage tests. The
transport-backed store also has a narrow receipt-bound repair bridge: it fetches
source bytes by `PlacementReceiptRef`, sends storage-node `RepairObject` to the
target, and accepts completion evidence only from a successful ack with a fresh
repaired placement receipt that passes rebuild-runtime verified-task completion.
This is not yet full replacement-node orchestration, degraded-read policy, or
reclaim publication; those remain part of the broader #18 runtime closeout.

## 7. Steady-state replication flow

1. publication produces immutable payload references and placement obligations
2. `compute_replica_target_set()` derives required placements
3. `stage_replica_transfer_ticket()` freezes anchor set, source set, target, pin budget, and freshness fence
4. `stream_replica_chunks_under_ticket()` transfers payload
5. `verify_transferred_chunks_against_digest_and_witness()` verifies
6. `commit_replica_transfer_and_placement_receipts()` makes placement legal
7. `advance_replica_health_and_lag_frontiers()` updates target health / lag state

## 8. Rebuild flow

1. a loss/suspect event opens `RebuildFlowRecord`
2. `open_rebuild_flow_from_loss_event()` freezes loss scope and degraded class
3. `schedule_rebuild_batches_from_witness_sets()` chooses source bundles and target sets
4. batches are transferred and verified like ordinary replication
5. if source truth is uncertain, repair law may require branch / quarantine / successor publication
6. once target placement is legal, lag and health frontiers are advanced
7. flow closes with receipts or degraded closure if legal placement target cannot yet be met

## 9. Relocation flow

Relocation is used for:
- reclaim/segment drain
- tiering / class movement
- placement-policy changes
- failover / cutover drain

Flow law:
1. `open_relocation_flow_from_policy_or_reclaim()` freezes scope and reason
2. batches are copied and verified
3. `seal_relocation_batch_and_publish_pointer_move()` moves legal placement to target
4. source placement enters retire-eligible state
5. allocator/reclaim law may then reclaim source only after all pending references/fences permit it

Relocation is **copy-forward**, never silent in-place mutation.

## 10. Lag, degraded visibility, and charter consequences

Every charter-facing adapter must consume `ReplicaLagStateRecord`.

### 10.1 Visibility classes
- `exact`
- `bounded_lag`
- `degraded_but_valid`
- `blocked_by_fence`
- `repair_required`

### 10.2 Rules
- posix_filesystem_adapter and block_volume_adapter may serve stale-bounded or degraded-but-valid states only when their charter permits it and the lag record says it is legal
- explanation_query must expose the lag/degraded class explicitly
- control_plane must surface the reserve/budget impact of large rebuild/relocation campaigns

## 11. Reserve, pressure, and failover interaction

Replication and movement are subordinate to the already-settled laws in:
- `P4-03` memory pressure / reserve protection
- `W5-05` freshness fences
- `W5-06` failover / escrow / witness quorum

Therefore:
- ordinary replication yields before protected reserve is violated
- rebuild can preempt product work and low-priority relocation
- failover/cutover drain (`data_flow_5`) can preempt ordinary replication and reclaim relocation
- transfers may be paused under `pressure_stage_4.reserve_protect` and `pressure_stage_5.emergency_freeze`

## 12. Userspace and kernel mapping

### 12.1 Userspace (first implementation target)
- io_uring/TCP/QUIC or equivalent transport
- userspace chunk shipper, verification workers, and receipt committer
- explicit pin budgets and page/buffer loan law from `P4-04`

### 12.2 Future kernel-assisted variants
- folio/bio-assisted movement for selected paths
- kernel completion mirroring
- same ticket/receipt/verification law; no kernel-private movement sovereignty


- steady replication under publication load
- rebuild after target loss with legal degraded visibility
- relocation while reclaim drains a segment class
- relocation interrupted by failover/cutover
- lag/fence reporting correctness under packet loss or slow links
- reserve-protect behavior under simultaneous rebuild and write pressure

These tests belong later in `P10`, but the protocol requirements are fixed here.

## 14. Anti-regression rules

The design is invalid if any implementation later does any of the following:
- treats byte transfer completion as legal placement without verification receipt
- reclaims source placement before pointer-move/retire law is satisfied
- hides degraded or lagged state from charters that are supposed to expose it
- allows relocation to silently rewrite authority truth without receipts
- lets product replication spend protected reserve floors needed for authority rebuild
- creates a kernel/userspace split in what counts as legal placement or verified data
