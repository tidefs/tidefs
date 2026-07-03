# ADR-0008: Failed-Quorum Mutation Evidence Boundary

Date: 2026-06-28
Status: Accepted

## Context

Issue #1282 asked TideFS to decide how failed-quorum mutations in the
transport-backed replicated object store may be used by future durability,
repair, and product-claim surfaces. This is a design/documentation slice only:
it does not implement runtime replication behavior, widen distributed
transaction claims, make RDMA a correctness requirement, or close TFR-017.

The review covered the required evidence:

- `docs/TRANSPORT_CLUSTER_AUTHORITY.md` records the TFR-017 split model:
  transport owns session-local facts, membership and runtime authority own
  epoch, roster, and fence decisions, and transport evidence cannot replace
  those decisions.
- `docs/REVIEW_TODO_REGISTER.md` records that the no-quorum rollback path is
  a narrow improvement only. Sent-but-unacknowledged replicas, replica
  inventory, partition recovery, scrub/repair authority, and distributed
  transaction authority remain open.
- `docs/TRANSPORT_CLUSTER_AUTHORITY.md` keeps transport carrier decisions
  below membership/runtime authority: RDMA is optional acceleration,
  TCP-class transport remains legal, and missing RDMA is a carrier degrade or
  refusal rather than a product correctness failure.
- `docs/design/distributed-snapshot-shipping.md` defers concrete transport
  binding to TFR-017 and separates point-to-point snapshot shipping from the
  live write-replication quorum path.
- `crates/tidefs-replicated-object-store/` currently reports
  `TransportReplicatedPutResult` with ack counts, quorum state, full-commit
  state, and optional placement receipt authority. On no-quorum put/delete it
  restores the local primary from a previous-payload snapshot and sends
  best-effort compensating put/delete messages only to replicas that already
  acknowledged the failed mutation.
- The same crate has degraded read and read self-heal state, but that state is
  not a cross-replica mutation inventory and does not prove transaction
  closure after a partition or lost acknowledgement.
- `apps/tidefs-storage-node/src/authority_spine.rs` exposes daemon-internal
  backend disclosure and replication-factor configuration. It explicitly is
  not final operator UAPI, cluster status, placement/heal exercise authority,
  or repair authority.
- Live adjacent issues #756, #757, #758, #846, #900, #1220, and #1279 are
  closed evidence for scrub comparison, recovery/degradation evidence,
  transport path evidence, QEMU carrier validation, and release-readiness
  boundaries. Open #1278 remains adjacent operator-UAPI work and is
  non-blocking for this slice because this ADR does not edit operator UAPI or
  the review register.
- The live PR file-list snapshot on 2026-06-28 found no open PR touching
  `docs/TRANSPORT_CLUSTER_AUTHORITY.md` or `docs/adr/`. Open draft PRs
  touching `docs/REVIEW_TODO_REGISTER.md` are why this slice treats the
  register as evidence only.

## Decision

TideFS selects a typed unresolved-mutation and replica-inventory ledger as the
next authority boundary for failed-quorum mutation evidence.

The current rollback and compensating-message behavior may remain as a
best-effort mitigation, but it is not a distributed transaction law. A caller,
claim gate, repair path, recovery path, or release-readiness surface must not
interpret local rollback plus best-effort compensation as proof that every
replica converged, that a partition healed safely, or that a multi-node
mutation is closed.

Before any multi-node durability claim consumes failed-quorum mutation
evidence, the replicated-object-store surface needs a durable, typed record
that distinguishes:

- replicas that positively acknowledged the attempted mutation;
- replicas that positively rejected the attempted mutation;
- replicas for which a message was sent but no acknowledgement was observed;
- replicas for which no send was admitted or no session existed;
- the local primary rollback attempt and its result;
- each compensating message attempt, response, timeout, or transport failure;
- the membership epoch, roster, fence, or partition evidence available at the
  time of the attempt, if provided by the membership/partition authority;
- the repair, scrub, or reconciliation action that later resolved or refused
  the unresolved mutation.

Until that ledger and its consumers exist, failed-quorum mutation outcomes stay
visible as unresolved or refused evidence. They do not satisfy distributed
transaction closure, product-grade partition recovery, cross-replica repair
writeback, or release-readiness claims.

## Alternatives Considered

### Keep best-effort rollback and explicit non-claim language

This preserves the current implementation shape: restore the primary after a
no-quorum mutation and send compensating messages to replicas that already
acknowledged. It is simple and useful as damage reduction.

Rejected as the final authority model. It cannot represent replicas that
received a mutation but did not acknowledge, replicas hidden by partitions,
unknown membership/fence state, or later reconciliation. It is acceptable only
as a transient mitigation with explicit unresolved-mutation non-claim language.

### Add a typed unresolved-mutation and replica-inventory ledger

This records the failed-quorum attempt as structured uncertainty instead of
turning uncertainty into success or hiding it behind rollback. It lets later
scrub, repair, recovery, and validation consumers decide whether enough
evidence exists to reconcile replicas, block claims, or fail closed.

Accepted. This is the smallest model that preserves TFR-017 boundaries while
making future implementation and validation work possible. It keeps transport,
membership, storage-node runtime, replicated-object-store, scrub/repair, and
validation harness responsibilities separate.

### Require a stronger transaction or witness protocol now

This would require a consensus-like transaction protocol, external witness
set, or equivalent proof before failed-quorum evidence can be recorded or
consumed.

Rejected for this slice. The current evidence does not show that TideFS must
choose the final witness/transaction protocol before it can preserve
uncertainty. A future issue may add such a protocol if the ledger and
reconciliation model cannot support the durability class being claimed, but
this ADR does not require that stronger protocol as the first step.

## Authority Boundary

| Layer | Owns | Does not own |
|---|---|---|
| Replicated object store | Mutation attempt identity, object key, payload digest or delete intent, local primary previous payload, local rollback result, positive replica acknowledgements, positive rejections, sent-but-unacknowledged outcomes, no-session/no-send outcomes, compensating-message attempts, and unresolved-mutation ledger rows. | Membership epochs, partition-healing decisions, repair source selection, cross-replica writeback, release claims, or RDMA carrier policy. |
| Storage-node runtime authority | Active backend disclosure, derived transport configuration, replication-factor configuration, store-path selection, and diagnostics that surface unresolved state without converting it to operator truth. | Product-grade cluster status, public operator UAPI, partition recovery, repair authority, or release-readiness verdicts. |
| Transport | Session-local send/admission/backpressure/timeout facts and typed connection or send evidence. | Roster authority, epoch advancement, fence decisions, partition healing, quorum law, or transaction closure. |
| Membership and partition authority | Committed roster, membership epoch, peer departure, fences, partition classification, and healing admission. | Per-object mutation rollback, replica inventory reconciliation, or cross-replica repair writeback. |
| Cross-replica scrub and repair | Digest comparison, disagreement classification, repair-source selection, writeback admission, and reconciliation of unresolved mutations once authoritative evidence exists. | Synthesizing transaction closure from transport success, raw ack counts, directory layout, or topology alone. |
| Future validation harnesses | Failure-injection evidence for partial acknowledgements, lost acknowledgements, partition healing, ledger replay, repair consumption, and claim-gate refusal. | Runtime authority decisions or product claims without the matching implementation evidence. |

## Representation Rules

Partial acknowledgements are evidence of the responding replicas only. A
quorum failure with one or more acknowledgements must record those replicas as
participants in an unresolved mutation; it must not assume non-responding
replicas are clean.

Sent-but-unacknowledged replicas are first-class unknowns. A timeout, closed
session, backpressure refusal, or missing response is not proof that the
replica did not apply the mutation.

Local rollback is a local remediation fact. It records that the primary tried
to restore the previous payload or delete the new payload after no quorum; it
does not close remote uncertainty.

Compensating messages are remediation attempts. Their results must be recorded
per target, and a successful compensating ack is still only that target's
evidence. It cannot erase an unresolved-mutation row for other targets.

Partition healing belongs to membership/partition authority and later
scrub/repair/reconciliation consumers. The replicated object store may carry
epoch and fence references supplied by those layers, but it must keep the
mutation unresolved until an owning consumer proves convergence or records a
typed refusal.

RDMA carrier evidence is optional and subordinate to the same rules. RDMA
success, RDMA absence, or TCP fallback may affect carrier diagnostics, but it
does not change transaction or partition semantics.

## Consequences

The immediate implementation mapping is:

- A future replicated-object-store issue should add the unresolved-mutation
  and replica-inventory ledger. Expected write set:
  `crates/tidefs-replicated-object-store/`, plus shared replication-model
  types only if that issue explicitly admits the additional path before source
  edits.
- A later scrub/repair or recovery issue should consume ledger rows only after
  the ledger exists and should stay within its repair/reconciliation write set.
  It must not be folded into the ledger issue unless the live issue body is
  expanded with a non-overlapping source-edit boundary.
- A future validation issue should inject partial acknowledgements,
  sent-but-unacknowledged messages, partition healing, rollback failures, and
  compensating-message failures. Its write set should be a focused harness or
  workflow path, not the replicated-object-store runtime implementation path.

This ADR does not close TFR-017, does not claim product-grade distributed
transactions, does not make TideFS release-ready, does not make RDMA hardware a
requirement, and does not grant cross-replica repair or writeback authority.
