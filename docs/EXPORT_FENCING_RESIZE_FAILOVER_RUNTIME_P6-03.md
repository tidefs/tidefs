# export fencing / resize / failover runtime P6-03 (v0.322)

This document is the source-of-truth for **P6-03** in the production design ledger.

It answers the production question that remained deliberately open after `P6-01`, `P6-02`, `P7-03`, `P8-03`, and `P2-03`:

**How does tidefs run a real Linux 7.0 `block_volume_adapter` export transition runtime so that resize, failover, revoke, cutover, repair-fence, and queue replay are lawful, receipt-backed events rather than daemon folklore or queue-local heroics?**

The answer must work for:
- Linux 7.0 userspace `block_volume_adapter` over `ublk`
- the already-settled `block_volume_adapter` queue topology and block-cache/barrier law
- distributed authority handoff under reserve-escrow / witness-quorum law
- future Rust-for-Linux `block_volume_adapter` kernel paths
- both local and distributed deployments
- resize, revoke, failover, replay, and cold restart

See also:
- `docs/BLOCK_VOLUME_PROJECTION_CHARTER_BLOCK_VOLUME_ADAPTER.md`
- `docs/UBLK_DAEMON_QUEUE_TOPOLOGY_P6-01.md`
- `docs/BLOCK_CACHE_FLUSH_FUA_DISCARD_LAW_P6-02.md`
- `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md`
- `docs/CANONICAL_BINARY_ENCODE_DECODE_ENDIAN_CHECKSUM_LAW_P2-03.md`
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## Metrics snapshot

| Metric | Count |
|---|---:|
| Canonical transition classes | 6 |
| Runtime components | 10 |
| State machines | 5 |
| Core transition / drain paths | 5 |
| New runtime schema families introduced here | 10 |
| New algorithm families introduced here | 10 |

## 1. Core law

1. **Export-transition runtime state is never authority.**
   Authority still lives in published projection roots, authority domains, lease epochs, receipts, tickets, and fences. Runtime mirrors may only freeze, drain, replay-classify, and resume lawful export service.

2. **Every transition is export-anchor-bound.**
   Resize, failover, revoke, repair-fence, or cold restart recovery must name the export identity, projection root, authority epoch, and queue-set frontier it governs.

3. **Admission must close before authority can move.**
   No export may shrink, hand off, revoke, or rebind authority while new conflicting requests are still being admitted.

4. **Inflight work is classified, never forgotten.**
   Every inflight request ends in one of three legal buckets:
   - committed under the previous export epoch
   - replay-required under the next export epoch
   - aborted / failed with receipt-backed reason

5. **Geometry change is a fenced publication event.**
   Resize is not “change a number and continue.” It is: plan, freeze, drain, commit, publish receipt, and resume.

6. **Failover is reserve-backed and quorum-visible.**
   Authority movement requires reserve escrow, witness-quorum satisfaction, and replay cursor publication before resumed service is legal.

7. **Revoke and stop are explicit runtime transitions.**
   Export stop/revoke may not rely on process death or implicit queue teardown to make the system correct.

8. **Cold restart follows the same transition law.**
   A restarted userspace runtime must reconstruct queue-visible mirrors from receipts, replay cursors, and canonical binary records rather than inferring safety from “empty process state.”

9. **Userspace `ublk` and future kernel block paths share one logical transition graph.**
   The mechanics differ, but admission gates, fence epochs, replay classification, and resume rules must remain semantically aligned.

10. **Copy fallback and replay fallback remain mandatory.**
    Registered buffers, queue locality, and fast completions may accelerate service, but they may never eliminate the ability to drain, replay, or cold-resume lawfully.

## 2. Canonical transition classes

| Class | Meaning |
|---|---|
| `export_transition_0.steady` | ordinary export service, no transition active |
| `export_transition_1.admission_freeze` | stop admitting conflicting requests while preserving inflight classification |
| `export_transition_2.resize_prepare` | geometry-change planning and drain phase |
| `export_transition_3.resize_commit` | committed geometry change with new resume frontier |
| `export_transition_4.failover_handoff` | authority movement to a successor export host/runtime |
| `export_transition_5.revoke_stop` | export stop, revoke, unpublish, or controlled teardown |

### 2.1 Fence classes

| Fence class | Meaning |
|---|---|
| `xfstests_profile_0.soft_gate` | admit only non-conflicting control/observe traffic |
| `xfstests_profile_1.quiesce_gate` | stop conflicting data-plane admission and drain inflight work |
| `xfstests_profile_2.resize_gate` | geometry-change fence over all queue sets of the export |
| `xfstests_profile_3.failover_gate` | authority handoff / replay-classification fence |
| `xfstests_profile_4.revoke_gate` | stop/revoke fence before export removal |
| `xfstests_profile_5.repair_gate` | temporary fence caused by repair successor publication |

## 3. Canonical runtime topology

### 3.1 Runtime components

The transition runtime is decomposed into these canonical components:

1. `BlockVolumeAdapterExportTransitionSupervisor`
2. `BlockVolumeAdapterAdmissionGateCoordinator`
3. `BlockVolumeAdapterFenceEpochCoordinator`
4. `BlockVolumeAdapterInflightClassifier`
5. `BlockVolumeAdapterResizePlanner`
6. `BlockVolumeAdapterReplayCursorWriter`
7. `BlockVolumeAdapterFailoverHandoffCoordinator`
8. `BlockVolumeAdapterRevokeStopCoordinator`
9. `BlockVolumeAdapterQueueDrainCoordinator`
10. `BlockVolumeAdapterTransitionReceiptEmitter`

No component may quietly decide policy, witness quorum truth, or canonical authority state on its own; those remain `policy_authority/authority_publication/claim_reserve_witness/control_plane` matters.

### 3.2 Coordination graph

For one live export, the transition graph is:

- queue admission gate
- fence epoch
- inflight classifier
- queue drain coordinator
- transition planner (`resize` / `failover` / `revoke`)
- replay cursor and transition receipts
- resume or tombstone

The runtime owns **execution order and drain discipline**.
It does **not** own legal truth about whether the export identity, authority epoch, or publication root has already moved.

## 4. Canonical runtime/schema families

| Record | Purpose | Authority class |
|---|---|---|
| `BlockVolumeAdapterExportFenceEpochRecord` | one active or historical fence epoch over an export with class, scope, previous/new authority anchors, and queue frontier refs | runtime mirror / receipt-linked |
| `BlockVolumeAdapterExportAdmissionGateRecord` | current admission state for conflicting/non-conflicting request classes during a transition | runtime mirror |
| `BlockVolumeAdapterExportTransitionIntentRecord` | canonical transition intent for resize/failover/revoke/repair gate with issuer, target state, and linked authority refs | authoritative declaration / runtime-linked |
| `BlockVolumeAdapterExportResizePlanRecord` | frozen preconditions, target geometry, required drains, and continuity checks for one resize event | authoritative declaration / runtime-linked |
| `BlockVolumeAdapterExportFailoverIntentRecord` | handoff target, reserve-escrow refs, witness-quorum refs, replay policy, and successor export target | authoritative declaration |
| `BlockVolumeAdapterInflightDispositionRecord` | per-request or per-batch classification into commit/replay/abort with fence epoch and completion refs | runtime mirror / receipt-linked |
| `BlockVolumeAdapterReplayCursorRecord` | exact replay restart frontier and classification bundle for resumed export service after failover/restart | authoritative declaration / receipt-linked |
| `BlockVolumeAdapterFenceQuiesceReceipt` | durable proof that a fence epoch satisfied its drain conditions and no conflicting inflight work remains unclassified | authoritative receipt |
| `BlockVolumeAdapterResizeCommitReceipt` | durable proof that geometry/size change completed, was published, and resumed under a fresh epoch | authoritative receipt |
| `BlockVolumeAdapterFailoverCutoverReceipt` | durable proof that authority moved, replay cursor became current, and previous runtime lost service rights | authoritative receipt |

## 5. Canonical state machines

### 5.1 Export transition state machine

`steady -> admission_freeze -> draining -> committed | resumed | revoked | failed`

Rules:
- `steady -> admission_freeze` occurs for any transition class except pure observation.
- `admission_freeze -> draining` requires a frozen fence epoch and closed conflicting admission gate.
- `draining -> committed` requires every inflight request classified.
- `committed -> resumed` only after the receipt for the new export epoch/geometry/authority is durable.
- `failed` means the transition itself failed; the export may remain live or become revoked depending on the transition class and receipt law.

### 5.2 Admission gate state machine

`open -> narrowed -> closed -> reopened | retired`

Rules:
- `narrowed` allows control, observe, and non-conflicting maintenance only.
- `closed` forbids new conflicting data-plane requests entirely.
- `reopened` requires a fresh fence epoch and published successor state.

### 5.3 Inflight disposition state machine

`observed -> frozen -> committed | replay_required | aborted`

Rules:
- every request/batch crossing a fence epoch must reach one terminal disposition.
- `replay_required` must reference one canonical `BlockVolumeAdapterReplayCursorRecord`; replay folklore is forbidden.
- `aborted` must name a legal cause (revoke, policy deny, reserve threat, shutdown, etc.).

### 5.4 Resize transition state machine

`planned -> fence_open -> drained -> geometry_commit -> resumed | aborted`

Rules:
- shrink/grow legality is checked before `fence_open`.
- no resize may skip the `drained` state.
- the new geometry is not visible until `geometry_commit` receipt is durable.

### 5.5 Failover/handoff state machine

`intent_open -> escrow_staged -> quorum_met -> fence_open -> drained -> cutover_commit -> resumed | aborted`

Rules:
- reserve escrow must exist before authority movement.
- witness quorum must be satisfied before `cutover_commit`.
- resumed service must reference the fresh replay cursor, not queue luck.

## 6. Core operational paths

### 6.1 Resize grow/shrink under live traffic
1. emit `BlockVolumeAdapterExportTransitionIntentRecord`
2. open `BlockVolumeAdapterExportFenceEpochRecord` with `xfstests_profile_2.resize_gate`
3. narrow/close admission gates for conflicting classes
4. classify inflight requests to commit/replay/abort
5. drain queue sets and dirty/cache state
6. emit `BlockVolumeAdapterResizeCommitReceipt`
7. reopen admission under fresh geometry / epoch

### 6.2 Failover or baton handoff
1. issue `BlockVolumeAdapterExportFailoverIntentRecord`
2. stage reserve escrow + witness quorum satisfaction externally
3. open `xfstests_profile_3.failover_gate`
4. classify inflight requests and emit replay cursor
5. emit `BlockVolumeAdapterFailoverCutoverReceipt`
6. resume only on the successor runtime / epoch

### 6.3 Revoke or controlled stop
1. issue `BlockVolumeAdapterExportTransitionIntentRecord` for revoke/stop
2. close admission gate
3. classify or abort inflight work
4. emit fence quiesce receipt
5. tombstone runtime mirrors and revoke service rights

### 6.4 Cold restart replay
1. reconstruct transition/fence/replay state from receipts and binary_schema records
2. re-open export runtime in fenced mode
3. replay `replay_required` contexts by `BlockVolumeAdapterReplayCursorRecord`
4. emit resumed-service receipt
5. reopen admission gate

### 6.5 Repair-triggered export fence
1. repair successor publication requests `xfstests_profile_5.repair_gate`
2. export runtime freezes conflicting admission
3. inflight work is classified under repair fence epoch
4. new projection root / successor state becomes visible
5. export resumes or remains degraded according to canonical response envelope

## 7. Userspace `ublk` law on Linux 7.0

### 7.1 What userspace owns
In userspace `block_volume_adapter` mode, the daemon owns:
- admission gates,
- queue-visible fence epochs,
- inflight disposition mirrors,
- replay cursors,
- and transition receipt emission.

It does **not** own:
- authority-domain truth,
- reserve escrow truth,
- witness quorum truth,
- or canonical publication state.

### 7.2 Queue drain and resume discipline
A queue set may only resume data-plane service when:
- the relevant fence epoch is terminal and durable,
- cache/dirty/drain obligations are satisfied,
- and the new export epoch / geometry / replay cursor is locally mirrored.

### 7.3 Failure and restart posture
If the daemon crashes mid-transition:
- queue-local memory is discarded,
- receipts and binary_schema records reconstruct legal state,
- unresolved inflight work is replayed/aborted from the canonical cursor,
- and resumed service requires a fresh transition receipt.

## 8. Future kernel parity law

Future kernel block export paths may replace userspace queue-drain mechanics with blk-mq/bio work and in-kernel quiesce paths, but they must preserve the same logical families:
- export fence epochs,
- admission gates,
- inflight dispositions,
- replay cursors,
- resize/failover/revoke receipts.

Kernel fast paths are not allowed to weaken replay classification, gate closure, or failover receipt law.

## 9. Canonical algorithm families introduced here

- `open_block_volume_adapter_export_fence_epoch()`
- `freeze_block_volume_adapter_export_admission_gate()`
- `classify_block_volume_adapter_inflight_request_for_commit_replay_abort()`
- `seal_block_volume_adapter_export_resize_plan()`
- `quiesce_block_volume_adapter_queue_sets_under_export_fence()`
- `commit_block_volume_adapter_resize_and_resume_export()`
- `stage_block_volume_adapter_failover_or_handoff_transition()`
- `emit_block_volume_adapter_replay_cursor_after_transition()`
- `revoke_block_volume_adapter_export_and_tombstone_runtime()`
- `resume_block_volume_adapter_export_after_fence_or_failover()`
