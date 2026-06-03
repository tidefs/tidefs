# kernel locking / RCU / pinning / workqueue model P7-03 (v0.319)

This document is the source-of-truth for **P7-03** in the production design ledger.
It is also the implementation-tracked non-release closeout for **OW-205**.

It answers the production question that remained deliberately open after `P4-04`, `P5-03`, `P6-01`, and `P6-02`:

**How does tidefs execute a real Linux 7.0 kernel-space runtime — for future `posix_filesystem_adapter` and `block_volume_adapter` kmods and shared design rule-native helper kernels — without hidden authority in lock order, ad hoc pin lifetimes, or workqueue folklore?**

The answer must work for:
- Linux 7.0 Rust-for-Linux kernels
- future `posix_filesystem_adapter` VFS-facing kmods
- future `block_volume_adapter` block-facing kmods
- shared design rule-native helper kernels (`authority_publication`, `claim_reserve_witness`, `policy_authority`, `response_normalizer`) where parts migrate kernel-side later
- local and distributed deployments

See also:
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/ZERO_COPY_DMA_PINNING_PAGE_LOAN_LAW_P4-04.md`
- `docs/PAGE_CACHE_WRITEBACK_MMAP_INTEGRATION_P5-03.md`
- `docs/UBLK_DAEMON_QUEUE_TOPOLOGY_P6-01.md`
- `docs/BLOCK_CACHE_FLUSH_FUA_DISCARD_LAW_P6-02.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## OW-205 source binding

OW-205 is closed by this document as a specification gate, not as a kernel
implementation gate. The claim is limited to the source-level concurrency law:
lock classes, RCU/read-mostly domains, pin classes, workqueue families,
state-machine transitions, and the race/fault acceptance rows below are now
named and bound to one model.

Future kernel code, Rust-for-Linux bridge code, or block/VFS kernel admission
packets must consume this model. They may not add an untracked lock order,
anonymous pin lifetime, callback sleepability rule, RCU publication shortcut, or
workqueue class as a local implementation detail.

## Metrics snapshot

| Metric | Count |
|---|---:|
| Canonical lock classes | 9 |
| Canonical RCU/read-mostly domains | 6 |
| Canonical pin classes | 6 |
| Canonical workqueue families | 8 |
| Canonical state machines | 6 |
| New schema families introduced here | 11 |
| New algorithm families introduced here | 10 |

## 1. Core law

1. **Kernel-local concurrency state is never authority by itself.**
   Lock state, RCU-visible pointers, folio references, bio completion records, workqueue backlog, and per-CPU mirrors exist to execute charter and kernel law. They may not quietly redefine publication truth, reserve truth, fence truth, or policy truth.

2. **Every mutable kernel object belongs to one authority/fence context.**
   Page-cache windows, block-cache windows, inode mirrors, extent mirrors, queue shards, and pin epochs must each be bound to one domain/epoch/fence anchor set.

3. **RCU is for read-mostly publication of mirrors, not for skipping ordering law.**
   Read-mostly lookup paths may use RCU for performance, but any transition that changes legal visibility must still go through explicit generation/fence law.

4. **Pins are obligations, not conveniences.**
   Folio refs, page pins, bio vector lifetimes, DMA mappings, registered buffer leases, and kernel direct-map loans debit protected reserve classes and must drain under the pin law in `P4-04`.

5. **Workqueues are scheduling classes, not sovereignty classes.**
   A work item may own execution, but not hidden policy, hidden reserve truth, hidden publication truth, or hidden cutover truth.

6. **Locking hierarchy is global and monotonic.**
   No runtime may invent an additional lock order. All `posix_filesystem_adapter`, `block_volume_adapter`, and shared helper kernels must obey one canonical partial order.

7. **Fast path and cutover path are both first-class.**

8. **Userspace and kernel variants share one logical concurrency law.**
   Userspace may use mutexes/queues/arenas; kernel may use spinlocks/RCU/workqueues/folios. The semantics of anchors, dirty epochs, write ordering, pins, drains, and fences must stay aligned.

9. **Sleepability is explicit.**
   Every lock class, callback class, and workqueue family states whether it may sleep, reclaim memory, acquire pins, wait for IO, or call into control-plane helpers.

10. **Kernel helper families must stay seam-native.**
   Future kernelized helpers may accelerate `posix_filesystem_adapter`/`block_volume_adapter`, but they may not absorb adapter-facing nouns into their inner sovereignty model.

## 2. Canonical lock classes

The kernel runtime now distinguishes **9 canonical lock classes**.

| Class | Linux shape | Purpose | Sleepable? |
|---|---|---|---:|
| `kernel_lock_0.seqcount_epoch` | `seqcount_t` / `seqcount_spinlock_t` | publish epoch/fence generation stamps for optimistic readers | no |
| `kernel_lock_1.rcu_anchor` | RCU read section + pointer publish | read-mostly mirror root visibility | no |
| `kernel_lock_2.object_spin` | `spinlock_t` / raw spin in IRQ paths | tiny per-object state transitions, queue/shard cursors | no |
| `kernel_lock_3.range_rwsem` | `rw_semaphore` | object/range mutation exclusion for heavy paths | yes |
| `kernel_lock_4.domain_mutex` | `mutex` | authority-domain state machine, publication/cutover staging | yes |
| `kernel_lock_5.pin_mutex` | `mutex` | pin-broker bookkeeping, loan drain, DMA arena transitions | yes |
| `kernel_lock_6.work_gate` | completion/wait-queue + gate mutex | quiesce/drain/fence transitions | yes |
| `kernel_lock_7.policy_rwsem` | `rw_semaphore` | policy/control-plane mirror visibility in-kernel | yes |
| `kernel_lock_8.emergency_raw` | `raw_spinlock_t` | only for truly hard-IRQ / completion-edge emergency accounting | no |

### 2.1 Canonical lock order

The global order is now explicit:

`kernel_lock_7.policy_rwsem -> kernel_lock_4.domain_mutex -> kernel_lock_3.range_rwsem -> kernel_lock_5.pin_mutex -> kernel_lock_2.object_spin -> kernel_lock_0.seqcount_epoch / kernel_lock_1.rcu_anchor readers`

Special rules:
- `kernel_lock_8.emergency_raw` may only nest with other raw/IRQ-safe emergency accounting and may never wait for ordinary kernel objects.
- `kernel_lock_1.rcu_anchor` readers may not block.
- `kernel_lock_0.seqcount_epoch` is not used to guard heavyweight object mutation; it guards generation publication for optimistic readers.
- `kernel_lock_6.work_gate` is acquired outside data fast paths and may coordinate drains after ordinary mutators stop admitting new work.

### 2.2 Anti-regression rules

- No callback holding `kernel_lock_2.object_spin` may allocate with filesystem reclaim enabled, call into control-plane writers, or wait for IO.
- No path may hold `kernel_lock_3.range_rwsem` and then attempt to acquire `kernel_lock_7.policy_rwsem`.
- No work item may retain `kernel_lock_5.pin_mutex` while waiting for page writeback, fence acknowledgement, or control-plane response.
- No RCU callback may allocate from authority-critical reserve classes without an explicit ticket.

## 3. Canonical RCU/read-mostly domains

The kernel runtime now distinguishes **6 canonical RCU/read-mostly domains**.

| Domain | Purpose |
|---|---|
| `read_domain_0.anchor_roots` | read-mostly publication of projection roots / fence anchors into kernel-visible mirrors |
| `read_domain_1.namespace_read_mirror` | read-mostly namespace/inode mirror pointers for `posix_filesystem_adapter` path lookups |
| `read_domain_2.page_window_roots` | page-cache / block-cache read windows by generation |
| `read_domain_3.queue_runtime_roots` | `block_volume_adapter` queue/shard mirror roots |
| `read_domain_4.policy_mirror_roots` | control-plane policy/override/budget mirrors visible in-kernel |
| `read_domain_5.observe_trace_roots` | low-cost observability/exported stats mirrors |

Rules:
- RCU readers may observe only immutable or generation-stamped mirror pointers.
- Any mutation that changes legality must publish a new generation then retire the previous pointer after grace period.
- RCU mirrors are mirrors; the receipt/fence/authority records remain off the RCU fast path and are referenced by anchor ids.

## 4. Canonical pin classes

The kernel runtime now distinguishes **6 canonical pin classes**.

| Class | Object type | Primary use |
|---|---|---|
| `kernel_pin_0.folio_cache_pin` | folio/page refs | cached read/write windows in `posix_filesystem_adapter` |
| `kernel_pin_1.bio_dma_pin` | bio/vector page refs + DMA map | block IO submit/complete in `block_volume_adapter`/future kmod |
| `kernel_pin_2.direct_map_pin` | direct IO / splice / zero-copy path | uncached direct path |
| `kernel_pin_3.writeback_pin` | dirty folios under writeback | page writeback epochs |
| `kernel_pin_4.relocate_bulk_pin` | rebuild/relocate transfer windows | relocation / rebuild / scrub |
| `kernel_pin_5.cutover_hold_pin` | temporary hold during cutover/failover/fence | drain-safe transitions |

Rules:
- Every pin belongs to a `PinEpochRecord` and reserve class.
- Truncate/hole-punch/collapse/failover may issue `PinFenceRecord` and `LoanDrainIntentRecord` to drain these classes.
- Kernel pins follow the same reserve and drain law already defined for userspace page loans.

## 5. Canonical workqueue families

The kernel runtime now distinguishes **8 canonical workqueue families**.

| Family | Purpose | Concurrency style |
|---|---|---|
| `kernel_workqueue_0.control_serial` | authority/cutover/fence staging hooks | ordered, low parallelism |
| `kernel_workqueue_1.namespace_mut` | heavyweight namespace/object mutation continuation | ordered by object/range key |
| `kernel_workqueue_2.page_writeback` | page dirty-epoch sealing and writeback completion | sharded |
| `kernel_workqueue_3.block_submit_complete` | block submit/completion continuation | sharded / CPU-local |
| `kernel_workqueue_5.reclaim_relocate` | reclaim/relocation / repair assist workers | bounded parallel |
| `kernel_workqueue_6.observe_export` | telemetry/export / trace compaction | low priority |
| `kernel_workqueue_7.emergency_recovery` | reserve-protect / cutover-critical fallbacks | reserved, throttled |

Rules:
- `kernel_workqueue_7` may not be consumed by normal background work.
- `kernel_workqueue_0` and `kernel_workqueue_7` have protected worker slots/reserve so failover/cutover can progress under pressure.
- `kernel_workqueue_2` and `kernel_workqueue_3` may be NUMA-aware and CPU-local, but they still obey domain/fence law.
- `kernel_workqueue_6` yields first under pressure.

## 6. Canonical runtime components

The future kernel-side runtime decomposes into these canonical components:

1. `KernelAnchorMirrorRegistry`
2. `KernelRangeLockBroker`
3. `KernelPinBroker`
4. `KernelPageWindowManager`
5. `KernelBlockSubmissionBroker`
6. `KernelWorkqueueCoordinator`
7. `KernelFenceDrainCoordinator`
8. `KernelPolicyMirrorGate`
9. `KernelEmergencyRecoveryGate`

These components exist for mechanics only. None may decide policy, authority movement, or product governance independently.

## 7. Canonical state machines

### 7.1 Anchor-visible mirror lifecycle
`prepared -> published_rcu -> draining_old_gen -> retired`

### 7.2 Range/object mutation guard lifecycle
`idle -> read_shared | write_exclusive -> quiesce_required -> released`

### 7.3 Pin epoch lifecycle
`open -> sealed -> draining -> fence_satisfied -> released`

### 7.4 Work item lifecycle
`queued -> admitted -> running -> blocked_wait -> resumed -> committed -> retired`

Exceptional exits:
- `queued -> cancelled`
- `running -> emergency_preempted`
- `blocked_wait -> fenced_abort`

### 7.5 Quiesce/fence transition lifecycle
`issued -> ingress_closed -> active_refs_draining -> grace_wait -> resumed | cutover_committed | failover_committed | aborted`

### 7.6 Emergency reserve protection lifecycle
`steady -> warm -> protect -> emergency -> recovered`

This mirrors the pressure law from `P4-03`, but in kernel mechanics.

## 8. Canonical schema families

### 8.1 `KernelLockClassRecord`
Declares one canonical lock class, its Linux primitive family, sleepability, reclaim/IRQ restrictions, allowed nesting predecessors, and audit tag.

### 8.2 `KernelRcuDomainRecord`
Declares one RCU/read-mostly mirror family, the anchor/generation law it obeys, and retirement grace-period class.

### 8.3 `KernelRangeGuardRecord`
Tracks one heavyweight guarded object/range mutation scope with holder(s), generation basis, and associated fence/drain obligations.

### 8.4 `KernelPinStateRecord`
Tracks one pin/loan obligation in-kernel: pin class, object/range, reserve debit, epoch, and drain state.

### 8.5 `KernelPinEpochRecord`
Groups pins into a bounded epoch, with oldest age, reserve totals, and required drain predicates.

### 8.6 `KernelWorkqueueClassRecord`
Declares one workqueue family, concurrency limit, reserve class, NUMA policy, and allowed blocking behavior.

### 8.7 `KernelWorkItemMirrorRecord`
Mirror for one admitted work item, including class, shard key, anchor refs, queue age, and commit/abort receipt refs.

### 8.8 `KernelQuiesceTransitionRecord`
Represents one cutover/fence/failover quiesce transition with ingress-close state, active-ref counts, and completion criteria.

### 8.9 `KernelEmergencyPressureRecord`
Represents entry into protect/emergency pressure stages in kernel runtime terms: queue throttles, drain commands, and reserve threat references.

### 8.10 `KernelGraceRetireRecord`
Tracks old-generation mirror retirement under RCU: publication generation, grace class, and retirement receipt.

### 8.11 `KernelWorkqueueAdmissionTicketRecord`
Admission ticket proving a work item was allowed into a protected or ordinary workqueue under budget/priority law.

## 9. Canonical algorithm families

### 9.1 `classify_kernel_runtime_path_to_lock_and_work_classes()`
Given operation kind, object/range scope, and charter class, determine:
- lock classes required
- RCU domain usage
- pin class (if any)
- workqueue family
- whether the operation is atomic/non-sleepable, sleepable, or fence-gated

### 9.2 `bind_kernel_operation_to_range_guard_and_generation()`
Acquire/freeze the required object/range guard, anchor generation, and seqcount/RCU bases for the operation.

### 9.3 `publish_kernel_rcu_mirror_generation()`
Publish a new mirror generation under seqcount/RCU law and schedule retirement of the previous generation.

### 9.4 `admit_kernel_pin_under_reserve_and_epoch()`
Debit reserve, attach the pin to the correct epoch, and reject/adapt if reserve/fence/policy law forbids the pin.

### 9.5 `seal_kernel_pin_epoch_for_writeback_or_cutover()`
Transition an open pin epoch into a sealed/draining state so writeback, cutover, or failover can reason about completion.

### 9.6 `route_kernel_work_item_to_family_and_shard()`
Route one operation to the proper workqueue family and shard, with protected reserve handling for urgent/control/emergency classes.

### 9.7 `drain_kernel_pins_and_active_guards_for_transition()`
Drive pin drain, active-range-guard drain, and grace waits for cutover/failover/resize/repair.

### 9.8 `enter_kernel_emergency_recovery_mode()`
Escalate queue throttles, reserve protection, workqueue reservations, and low-priority cancellations under pressure or deadlock risk.

### 9.9 `complete_kernel_work_item_and_emit_runtime_receipts()`
Commit/abort a work item with cutover-safe bookkeeping, receipt refs, and mirror retirement if needed.

Static/runtime audit family used to prove that one operation class obeys the canonical lock order and does not sleep in forbidden regions.

## 10. Whole-system operational paths covered here

This pass adds canonical production-depth coverage for:

1. `posix_filesystem_adapter` fast-path read lookup under RCU-visible anchor mirrors
2. `posix_filesystem_adapter` namespace/object mutation under range guards + workqueue continuation
3. `posix_filesystem_adapter` dirty writeback under pin epochs and page-writeback workqueues
4. `block_volume_adapter` block submit/complete under sharded workqueues and pin classes
5. cutover/failover/resize quiesce across kernel mirrors, pins, and work items
6. emergency reserve-protect entry in kernel runtime terms
7. future Rust-for-Linux parity with the userspace queue/pin/fence laws

## 11. Linux 7.0 primitive baseline

The logical law above maps to Linux 7.0 primitive families approximately as follows:

- read-mostly mirrors: `rcu_read_lock()`, `call_rcu()`, generation pointers
- tiny hot-path state: `spinlock_t`, per-CPU stats, `seqcount_t`
- heavy object/range mutation: `rw_semaphore`, `mutex`
- block submit/complete: request/bio callbacks, blk-mq style queue affinity, DMA map/unmap hooks
- background progression: dedicated ordered and sharded workqueues, completions, wait queues

Rust-for-Linux wrappers may vary, but the law in this document is the contract.

## 12. Shared law with userspace variants

The kernel path may differ mechanically from userspace `posix_filesystem_adapter`/`block_volume_adapter`, but it must remain semantically aligned with:

- `docs/FUSE_REQUEST_WORKER_QUEUE_MODEL_P5-02.md`
- `docs/PAGE_CACHE_WRITEBACK_MMAP_INTEGRATION_P5-03.md`
- `docs/ZERO_COPY_DMA_PINNING_PAGE_LOAN_LAW_P4-04.md`
- `docs/UBLK_DAEMON_QUEUE_TOPOLOGY_P6-01.md`
- `docs/BLOCK_CACHE_FLUSH_FUA_DISCARD_LAW_P6-02.md`
- `docs/MEMORY_PRESSURE_RECLAIM_RESERVE_INTERACTION_P4-03.md`

That means:
- queue/work family names may differ mechanically,
- but anchors, fences, dirty epochs, pin epochs, reserve classes, and drain law must stay one logical system.

## 13. OW-205 race and fault acceptance matrix

The OW-205 acceptance surface is a required matrix for later executable kernel
or bridge tests. This closeout fixes the matrix and its pass conditions; it does
not claim that those later runtime campaigns have already passed.

| Acceptance row | Required proof before kernel admission | Blocking failure class |
|---|---|---|
| Lock-order audit | Every operation class declares the ordered subset it may acquire from `kernel_lock_7` down to `kernel_lock_0`/`kernel_lock_1`; no path acquires a later predecessor after a successor. | `kernel_lock_order_inversion` |
| Sleepability audit | Every callback/work item declares whether it may sleep, allocate with reclaim, wait for IO, or call policy/control helpers; non-sleepable classes reject those actions. | `kernel_forbidden_sleep_or_reclaim` |
| RCU generation race | Old-generation mirrors remain immutable and reachable until grace-period retirement; legal visibility changes publish a new generation instead of mutating in place. | `kernel_rcu_hidden_visibility_change` |
| Pin drain and truncate/fence race | Truncate, hole-punch, cutover, failover, and resize paths seal affected `KernelPinEpochRecord` rows and wait for required drain predicates. | `kernel_pin_epoch_leak_or_stale_access` |
| Workqueue starvation and emergency reserve | Ordinary work cannot consume `kernel_workqueue_7.emergency_recovery`; control and emergency families retain progress under pressure. | `kernel_workqueue_reserve_starvation` |
| Cutover/failover quiesce race | Ingress closes before authority/fence movement, active guards and pins drain, grace waits finish, and resumed paths use the new anchor generation. | `kernel_quiesce_incomplete_before_cutover` |
| Block submit/complete race | `block_volume_adapter` submit/complete work binds queue shard, pin epoch, DMA lifetime, and completion receipt before reporting Linux completion. | `kernel_block_completion_without_receipt` |
| Page writeback race | Dirty folios bind to writeback pin epochs and publication/fence anchors before writeback completion can be treated as clean. | `kernel_writeback_hidden_authority` |
| Emergency recovery race | Emergency mode throttles low-priority queues and emits recovery receipts instead of silently dropping, replaying, or promoting local mirrors. | `kernel_emergency_unreceipted_transition` |

Every later executable test, KUnit-style harness, lockdep integration, QEMU
kernel smoke, or fault campaign that claims OW-205 coverage must map failures

## 14. What this closes and what remains

This pass closes the production-depth ambiguity around:
- lock classes
- RCU mirror usage
- pin class law in-kernel
- workqueue families
- cutover/failover drain law in kernel mechanics

It does **not** finish:
- `P7-04` VFS/block integration and kernel UAPI law
- `P8-03` replication / rebuild / relocation data flows
- `P2-03` canonical binary encode/decode / checksum law
- operator/security/stress workstreams

Those remain separate production items in the ledger.
