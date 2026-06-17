# ublk daemon / queue topology P6-01 (v0.317)

> TFR-019 authority classification: Historical input. See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

This document is the source-of-truth for **P6-01** in the production design ledger.

It answers the production question that remained deliberately open after `P4-04` and `P5-03`:

**How does tidefs run a real Linux 7.0 `block_volume_adapter` userspace block runtime with explicit queue classes, io_uring/ublk admission, completion, backpressure, flush/FUA, resize/failover quiesce, and future kernel parity, without allowing queue-local state to become hidden authority?**

The answer must work for:
- Linux 7.0 userspace `block_volume_adapter` over `ublk`
- later mixed deployments where `posix_filesystem_adapter` and `block_volume_adapter` coexist on one node
- future Rust-for-Linux `block_volume_adapter` kernel paths
- local single-node and distributed authority placements
- failover, resize, fence, flush/FUA, discard/zero, and export revocation

See also:
- `docs/BLOCK_VOLUME_PROJECTION_CHARTER_BLOCK_VOLUME_ADAPTER.md`
- `docs/ZERO_COPY_DMA_PINNING_PAGE_LOAN_LAW_P4-04.md`
- `docs/PAGE_CACHE_WRITEBACK_MMAP_INTEGRATION_P5-03.md`
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## Metrics snapshot

| Metric | Count |
|---|---:|
| Canonical queue classes | 8 |
| Runtime components | 11 |
| State machines | 5 |
| Core ingress/completion paths | 6 |
| New runtime schema families introduced here | 10 |
| New algorithm families introduced here | 9 |

## 1. Core law

1. **`block_volume_adapter` queue state is never authority.**
   Export truth still lives in published projection roots, authority domains, receipts, and fences. Queue-local mirrors only admit, order, stage, and complete block requests lawfully.

2. **Every request is export-anchor-bound.**
   A read, write, flush, FUA, discard, zero, or resize request must carry enough export / projection-root / fence context to prove which legal truth epoch it belongs to.

3. **Overlapping writes are explicitly ordered.**
   Write serialization is not an emergent property of worker luck. The queue model must pick deterministic write shards and flush epochs so overlapping or conflicting LBA ranges cannot race into hidden local truth.

4. **Flush/FUA are barrier classes, not boolean folklore.**
   A flush/FUA completion must be explainable by a named flush epoch, durability class, and receipt/fence chain.

5. **Resize, failover, export revoke, and cutover are queue-quiesce events.**
   The daemon is not allowed to mutate export geometry or authority while inflight data requests remain unclassified or un-drained.

6. **Control plane and data plane are distinct queue families.**
   Export lifecycle, queue bring-up, and revoke/cutover control may pre-empt data-plane work; ordinary reads/writes may not starve control or fence progress.

7. **Backpressure is reserve-aware.**
   Queue admission consumes reply bytes, registered buffers, pin budget, dirty-window budget, and flush-epoch budget; the runtime must throttle before protected reserve classes are violated.

8. **Userspace `ublk` and future kernel block paths share one logical graph.**
   The mechanics differ (`io_uring` + `ublk` userspace vs kernel request/bio/blk-mq), but the queue classes, flush epochs, fence law, and completion law must stay semantically aligned.

9. **Copy fallback remains mandatory.**
   Registered-buffer, fixed-buffer, or DMA-friendly paths may accelerate `block_volume_adapter`, but the queue law must stay correct when any such optimization is unavailable.

10. **No queue-local caching may quietly redefine `block_volume_adapter`.**
    Read-ahead hints, merge hints, inflight request tables, and completion mirrors are runtime optimization only. They may not become hidden capacity, fence, or durability authority.

## 2. Runtime topology

### 2.1 Session phases

A `block_volume_adapter` export instance moves through:
- `phase.bootstrap`
- `phase.export_admitted`
- `phase.queues_live`
- `phase.quiesce_transition`
- `phase.stopped`

No queue may admit data-plane requests before `phase.queues_live`.
No control-plane mutation may complete while the export is still admitting conflicting requests in `phase.quiesce_transition`.

### 2.2 Canonical runtime components

The runtime is decomposed into these canonical components:

1. `BlockVolumeAdapterExportSupervisor`
2. `BlockVolumeAdapterControlCoordinator`
3. `BlockVolumeAdapterQueueIngress`
4. `BlockVolumeAdapterReadPlanner`
5. `BlockVolumeAdapterWritePlanner`
6. `BlockVolumeAdapterFlushCoordinator`
7. `BlockVolumeAdapterCompletionCommitter`
8. `BlockVolumeAdapterFenceQuiesceCoordinator`
9. `BlockVolumeAdapterResizeCoordinator`
10. `BlockVolumeAdapterRegisteredBufferArena`
11. `BlockVolumeAdapterPinBroker`

No component may silently decide policy, override validity, or authority-domain truth. Those remain `policy_authority/control_plane` matters.

### 2.3 Queue-set graph

Each live export owns one or more **queue sets**.
A queue set is the unit of:
- intake,
- request classification,
- write-order serialization,
- flush epoch tracking,
- completion commit,
- and quiesce/drain.

A queue set contains:
- one ingress lane,
- one or more worker shards by queue class,
- one completion lane,
- one flush-epoch tracker,
- one backpressure mirror,
- and one pin/buffer sub-allocation scope.

Default topology under Linux 7.0 userspace:
- one control uring/ring pair for export lifecycle,
- `N` queue sets for block data plane,
- `N = min(cpu_locality_cap, policy_cap, export_queue_cap)`.

Default policy guidance:
- single export on small node: `N = min(4, cpu_count)`
- larger node / heavy block load: `N = min(16, cpu_count, device_queue_cap)`
- NUMA split: choose queue sets per NUMA locality first, then by queue depth.

These are policy defaults under `control_plane`, not daemon folklore.

## 3. Canonical queue classes

The runtime now distinguishes **8 canonical queue classes**.

| Class | Meaning | Blocking? | Ordering scope |
|---|---|---:|---|
| `ublk_queue_0.control_admin` | create/start/stop/reconfigure/revoke/export-lifecycle commands | no | export |
| `ublk_queue_1.read_fast` | ordinary reads / read-ahead / verify reads | no | LBA stripe |
| `ublk_queue_2.write_ordered` | ordinary writes that mutate logical block state | no | overlapping LBA stripe |
| `ublk_queue_3.flush_fua` | flush/FUA barrier issuance and completion | yes | export + flush epoch |
| `ublk_queue_4.zero_discard` | discard / write-zeroes / deallocate range | no | overlapping LBA stripe |
| `ublk_queue_5.resize_transition` | grow/shrink/geometry transition sequencing | yes | export |
| `ublk_queue_6.fence_failover` | export fencing, quiesce, handoff, failover drain | yes | export + authority domain |
| `ublk_queue_7.maintenance_probe` | health probe, telemetry snapshot, low-priority maintenance | no | queue set |

Key rules:
- `ublk_queue_2`, `ublk_queue_4`, and `ublk_queue_5` may never execute out-of-order over overlapping block ranges.
- `ublk_queue_3` may not complete before all covered writes in the flush epoch are sealed and satisfied.
- `ublk_queue_6` pre-empts all non-control classes for the affected export.

## 4. Canonical shard keys and ordering

Requests are bound to queue shards by canonical keys:

- `key.export_scope`
- `key.queue_id`
- `key.lba_stripe`
- `key.overlap_span`
- `key.flush_epoch`
- `key.fence_scope`
- `key.completion_batch`

### 4.1 Read sharding
Reads normally shard by:
- export
- queue id
- LBA stripe

Read planners may merge contiguous requests into one read plan only if:
- exactness class stays unchanged,
- fence context stays unchanged,

### 4.2 Write sharding
Writes shard by:
- export
- overlap span (derived from LBA stripe and alignment policy)

Any overlapping write, discard, zero, collapse-like transition, or resize-affecting operation must serialize inside the same overlap shard or explicit quiesce scope.

### 4.3 Flush epoch binding
Every admitted write-class request binds to one `FlushEpochRecord`.
A flush/FUA request names a boundary relative to those epochs.
Completion means the covered set has reached the charter’s durability class.

## 5. Canonical runtime/schema families

| Record | Purpose | Authority class |
|---|---|---|
| `BlockVolumeAdapterExportRuntimeRecord` | live export instance, queue-cap policy, authority/fence context, lifecycle state | runtime mirror / governance-linked |
| `BlockVolumeAdapterQueueSetRecord` | one queue set’s ingress/completion lanes, worker pools, pin/buffer scope, and current phase | runtime mirror |
| `BlockVolumeAdapterQueueClassRecord` | declaration of one `ublk_queue_0..ublk_queue_7` class and its ordering/backpressure rules | authoritative declaration |
| `BlockVolumeAdapterQueueShardRecord` | one live shard with key class, inflight set, ordering cursor, and oldest request ref | runtime mirror |
| `BlockVolumeAdapterCompletionCommitMirrorRecord` | completion-side mirror linking request(s), response envelope(s), receipts, byte counts, and final Linux status | runtime mirror / receipt-linked |
| `BlockVolumeAdapterFlushEpochRecord` | grouping of writes/zero/discard requests that must satisfy one flush/FUA boundary | runtime mirror / receipt-linked |
| `BlockVolumeAdapterQueueBackpressureStateRecord` | queue-set and export-wide inflight bytes, reply bytes, registered-buffer debt, dirty debt, and pressure stage | runtime mirror |
| `BlockVolumeAdapterExportFenceMirrorRecord` | queue-visible mirror of export lease/fence/quiesce state for one export | runtime mirror / receipt-linked |
| `BlockVolumeAdapterResizeTransitionRecord` | explicit grow/shrink transition with drain requirements, capacity target, and completion receipts | runtime mirror / receipt-linked |

## 6. Canonical state machines

### 6.1 Export runtime state machine

`bootstrap -> admitted -> live -> quiescing -> fenced -> resumed | stopped`

Rules:
- `live -> quiescing` occurs for resize, failover, revoke, cutover, or severe reserve threat.
- `quiescing -> fenced` requires ingress closed for affected classes and inflight requests either completed or classified for replay/abort.
- `fenced -> resumed` requires a fresh export fence state and queue admission ticket.

### 6.2 Queue-shard state machine

`idle -> accepting -> draining -> fenced -> resumed | retired`

Rules:
- `accepting -> draining` occurs when a flush boundary, resize, revoke, or failover fence needs the shard.
- `draining -> fenced` requires no active unsealed writes in the shard.

### 6.3 Submission-context state machine

`captured -> admitted -> planned -> submitted -> completion_wait -> committed -> retired`

Exceptional exits:
- `planned -> aborted`
- `submitted -> replay_required`
- `completion_wait -> fenced_abort`

### 6.4 Flush-epoch state machine

`open -> sealed -> storage_complete -> durability_wait -> complete | failed`

Rules:
- `storage_complete` is not enough for `FUA` or chartered durable flush completion.
- `durability_wait -> complete` only when the relevant receipt/barrier/token set exists.

### 6.5 Resize/fence transition state machine

`issued -> ingress_closed -> drains_inflight -> publication_or_policy_wait -> committed | aborted`

This same state machine is reused for:
- resize,
- export revoke,
- handoff/failover queue quiesce,
- and explicit charter fence transitions.

## 7. Ingress, planning, submission, and completion graph

### 7.1 Ingress capture
For each incoming block request, the runtime must:
1. freeze export context,
2. freeze authority/fence mirror state,
3. classify queue class,
4. bind the request to a queue shard,
5. build `BlockVolumeAdapterSubmissionContextMirrorRecord`.

### 7.2 Planning
Planning yields one of:
- read plan
- write plan
- zero/discard plan
- flush epoch boundary plan
- resize/fence transition plan

Plans must declare:
- LBA range
- byte count
- exactness class
- durability class
- copy vs registered-buffer path
- reserve/pin budget debit
- required receipts on completion

### 7.3 Submission
Submission to the underlying storage/runtime path is lawful only after:
- backpressure admission,
- registered-buffer / pin admission if needed,
- and flush-epoch association.

### 7.4 Completion commit
Completion rendering must flow through one canonical commit step:
- map result into a canonical response envelope,
- attach receipt refs / fence refs / flush-epoch refs,
- render Linux-facing status / bytes completed,
- retire or replay the submission context.

No fast path may skip the canonical envelope just because Linux only wants `errno` + `nr_bytes`.

## 8. Flush / FUA / discard / zero / resize law

### 8.1 Flush and FUA
- `FUA` write requests bind to a flush epoch but require their own durability class before completion.
- plain writes may complete earlier under their declared charter class.
- explicit flush requests close one or more open flush epochs and wait for completion.

### 8.2 Discard and write-zeroes
`discard` and `write_zeroes` are separate request kinds, not rewritten silently into ordinary write semantics.
They must:
- bind to overlap shards like writes,
- declare whether they preserve allocation or deallocate,
- and emit completion envelopes that can explain charter-visible exactness and durability.

### 8.3 Resize
Resize is never an ambient side effect of ordinary writes.
A resize transition must:
- close affected ingress,
- drain overlapping shards,
- obtain policy/authority permission,
- move the export through `BlockVolumeAdapterResizeTransitionRecord`,
- and only then reopen queue admission under the new geometry.

## 9. Backpressure and reserve law

The runtime now has explicit queue-side caps for:
- inflight requests per queue set,
- inflight data bytes,
- completion bytes not yet committed,
- registered-buffer bytes,
- pin bytes,
- open flush epochs,
- fence/quiesce transitions,
- urgent control reserve.

Backpressure is driven by:
- `BlockVolumeAdapterQueueBackpressureStateRecord`
- `P4-03` pressure stages
- `P4-04` pin/loan reserve classes

When pressure rises:
1. maintenance/probe yields first,
2. read merge depth shrinks,
3. zero/discard batching shrinks,
4. write admission throttles,
5. urgent control/fence work pre-empts,
6. reserve-protect stage may deny new data-plane admission.

## 10. Quiesce / failover / handoff

The queue model is tightly tied to:
- failover / handoff / witness-quorum law (`W5-06`)
- freshness-fence law (`W5-05`)
- zero-copy pin drain law (`P4-04`)

For failover or handoff:
- ingress closes for affected export(s)
- queue sets move to `quiescing`
- inflight contexts are classified into:
  - commit-ok
  - replay-required
  - abort-required
- pins and registered buffers drain under explicit loan-drain intents
- final handoff or failover receipt is not emitted until all affected queue sets are fenced

## 11. Userspace / kernel parity

### 11.1 Userspace `block_volume_adapter` on Linux 7.0 — continuity: Block Volume Adapter (`block_volume_adapter`)
Userspace path owns:
- control-plane ublk coordination
- request capture/classify/plan/commit
- queue mirrors and flush epochs
- registered-buffer arena and pin broker
- rendering Linux block completion status from canonical envelopes

### 11.2 Future kernel `block_volume_adapter` — continuity: Block Volume Adapter (`block_volume_adapter`)
Kernel path must preserve the same logical structure with different mechanics:
- blk-mq / request / bio ingress instead of userspace request capture
- kernel workqueues instead of daemon workers
- kernel pin / DMA structures instead of userspace arenas
- same queue classes
- same flush-epoch law
- same quiesce/fence law
- same receipt/response-envelope discipline

The future kernel path is not permitted to invent a second queue ontology.


1. queue ordering under overlapping writes/discard/zero
2. flush/FUA completion honesty
3. resize while busy and resize under pressure
4. failover/handoff with inflight I/O and pin drain
5. registered-buffer exhaustion and copy fallback correctness
6. mixed read/write/flush storms with backpressure visibility
7. userspace-vs-kernel parity for queue class and flush semantics

That test/harness matrix is completed later by:
- `P6-04` block acceptance / stress harness matrix

## 13. What this closes, and what remains open

This pass closes the structural queue/runtime question for `block_volume_adapter`.
It leaves these adjacent items open:
- `P6-02` block cache / flush / FUA / discard law
- `P6-03` export fencing / resize / failover runtime
- `P6-04` block acceptance / stress harness matrix
- `P7-03` kernel locking / RCU / pinning / workqueue model
- `P2-03` canonical binary encode/decode / endian / checksum law

That is the correct cut: queue topology first, then block cache/durability semantics and kernel concurrency detail.
