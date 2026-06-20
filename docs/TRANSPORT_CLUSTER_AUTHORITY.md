# Transport / Cluster Authority Boundary

**Status**: Decision record
**Issue**: [#672](https://github.com/tidefs/tidefs/issues/672)
**Date**: 2026-06-21
**TFR link**: TFR-017

## Purpose

When the transport crate, membership layer, and storage-node runtime each
touch the same admission, backpressure, and fencing surfaces, implementation
issues must know which layer owns each decision so they do not duplicate or
bypass authority. This record names the single owner for each runtime gate,
declares which layer enforces but does not originate a decision, and maps
the follow-up implementation issues that close the remaining TFR-017 gaps.

## Evidence reviewed

- `docs/REVIEW_TODO_REGISTER.md` TFR-017 row and current review notes:
  config/runtime fallback, multi-node scrub comparison, repair authority,
  cluster pool CLI/orchestrator disagreement (lines 21, 606, 760–800).
- `crates/tidefs-transport/README.md` — module-level capabilities and
  integration notes for connection admission, peer admission, send
  admission, send backpressure, send scheduling, epoch fence,
  membership guard, send gate, dispatch, and session state.
- Source boundaries:
  `connection_admission.rs`, `peer_admission.rs`, `send_admission.rs`,
  `send_backpressure.rs`, `send_scheduler.rs`, `epoch_fence.rs`,
  `membership_guard.rs`, `epoch_gate.rs`, `epoch_barrier.rs`,
  `epoch_bridge.rs`, `dispatch.rs`, `message_dispatch.rs`,
  `send_gate.rs`, `session/mod.rs`, `transport.rs`.
- Adjacent issue scope:
  #18 (placement receipt/rebuild), #632 (clustered POSIX mount boundary),
  #633 (clustered POSIX lock forwarding), #641 (replica-health admission
  snapshots), #646 (RDMA artifact manifests), #662 (cluster prototype
  vs diagnostic separation).

## Alternatives evaluated

### Alternative A — Transport owns the full runtime gate

Transport would own session admission, peer backpressure, epoch/membership
fencing, and dispatch proofs as a single integrated authority.

**Rejected**. Transport would become a god crate that must understand
membership quorum semantics, cluster leader-election, placement topology,
and write-fence leadership. That duplicates authority already owned by
`tidefs-membership-live`, `tidefs-membership-epoch`, and
`tidefs-cluster`. Transport's job is wire protocols, not distributed
consensus decisions.

### Alternative B — Storage-node/runtime authority owns the gate, transport only enforces typed proofs

The storage-node `RuntimeAuthority` (or a cluster authority crate) would
originate every admission decision. Transport would receive opaque typed
proofs and enforce them mechanically.

**Rejected as the sole model**. While correct for epoch/membership
fencing, this pulls session-local flow decisions (send capacity,
backpressure watermark transitions, lane scheduling) into an authority
layer that has no business managing per-session queue depth. Those
decisions are inherently transport-local and should stay local.

### Alternative C — Split model (selected)

Transport owns session-local admission and backpressure mechanics;
membership/runtime authority owns epoch, fencing, and roster decisions.
Transport enforces authority decisions through narrow typed interfaces
but never originates a roster, epoch, or fencing choice.

**Selected**. This is the model the current source already implements,
and the sections below tighten the boundary descriptions so future
implementation issues do not blur these lines.

## Decision

### Session admission — Transport owns

Session admission is the gate that accepts or rejects an inbound
connection when a peer first opens a transport session. Transport owns
this gate.

- `connection_admission::AdmissionController` validates the connecting
  peer against the current roster, rejects disconnected peers, and
  emits typed admission receipts.
- Transport uses its own simplified roster types (`RosterEntry`,
  `RosterPeerState`) so it does not depend on the full membership
  crate, but the roster it consults is published by the membership
  layer through `CommittedEpochEvidence`.

### Peer backpressure — Transport owns the mechanics; membership owns the roster gate

Backpressure is a two-layer decision:

1. **Mechanics** (transport owns): Per-priority watermarks
   (`send_backpressure::SendCapacitySet`), async capacity
   notification, queue-depth accounting, and weighted-fair-queue
   scheduling (`send_scheduler`). These are local to the transport
   send path and do not require distributed knowledge.

2. **Roster gate** (membership owns, transport enforces): Whether a
   send to a given peer is allowed at all. The membership layer
   provides a `SendGate` implementation that transport calls before
   enqueueing. If the peer is not in the committed roster, transport
   returns `SendPipelineError::PeerNotInRoster`.

The transport crate must not decide on its own that a peer is
authorized; it must consult the `SendGate` (or treat absence of a
gate as permit-all for single-node/test operation).

### Epoch and membership fencing — Membership authority owns; transport enforces

Fencing is a distributed authority decision. No transport module may
originate an epoch number, decide that a peer is evicted, or choose
when to fence.

The membership layer (`tidefs-membership-live`, `tidefs-membership-epoch`)
owns:

- Epoch generation and monotonic advancement.
- Committed roster membership.
- Fencing decisions: which peers are evicted, drained, or failed.

Transport enforces through these narrow, mechanical surfaces:

| Surface | File | Role |
|---|---|---|
| `AdmissionGate` | `peer_admission.rs` | Rejects new connections from non-members; uses `EpochStamp` to catch epoch-advance races. |
| `EpochFence` | `epoch_fence.rs` | Re-evaluates active connections against the new member set after every epoch advance; transitions departed-peer connections to `Draining`. |
| `EpochBarrier` | `epoch_barrier.rs` | Stamps outbound messages with epoch; rejects stale-epoch inbound messages; queues future-epoch messages. |
| `EpochGate` | `epoch_gate.rs` | Per-connection lightweight epoch admission (header-level, not full barrier wire format). |
| `MembershipSessionGuard` | `membership_guard.rs` | Tears down transport sessions to departed peers (drains TCP streams, frees OS resources). |
| `SendGate` | `send_gate.rs` | Trait that blocks outbound sends to non-roster peers. |

The transport crate does not depend on `tidefs-membership-live` directly.
It receives epoch data through narrow channels:

- `TransportEpochSubscriber` trait (via `epoch_bridge`).
- `CommittedEpochEvidence` publish cells.
- `SendGate` trait objects.
- `EpochTransition` broadcast events.

### Dispatch proof consumption — Cluster/runtime authority owns

The message dispatch path (`dispatch.rs`, `message_dispatch.rs`) routes
decoded messages to subsystem handlers. When a message carries a write
fence or requires leadership proof, the dispatch layer consults
`tidefs_cluster::write_fence::WriteFence`. The dispatch layer does not
originate write-fence leadership decisions; it only checks the proof
that the cluster authority provides.

### Failure and claim boundaries

- When transport rejects a connection (admission refusal) or a send
  (roster gate, backpressure, closed session), it records a typed
  `SendAdmissionEvidence` or `AdmissionRejection` receipt. The
  evidence is a transport-local fact about what the send path saw.
- Membership failures (`PeerDeparted`, epoch-advance rejection) are
  surfaced through `CorrelationError::PeerDeparted` so callers can
  retry or route around departed peers.
- Claim gates that consume transport evidence (e.g., "this peer was
  fenced at epoch N") must cite the membership authority, not the
  transport evidence alone. Transport evidence supports but does not
  replace the membership decision.

## Follow-up implementation issues

This decision enables the sibling issues to proceed with clear
boundaries. The following non-overlapping implementation issues close
the remaining TFR-017 gaps named in the register notes.

1. **Cross-replica scrub comparison authority** — owns the digest
   comparison and repair-source selection logic that the register
   notes say is still logged but not compared. Write set:
   `crates/tidefs-storage-scrub/`,
   `crates/tidefs-transport/src/replication.rs`.

2. **Repair authority closure** — owns the recovery closure and
   live TCP/RDMA runtime proof that the register notes remain
   incomplete. Write set:
   `crates/tidefs-storage-repair/`,
   `apps/tidefs-storage-node/src/`.

3. **Distributed transaction authority** — owns the sent-but-
   unacknowledged replica, replica inventory, and partition recovery
   gaps named in the register. Write set:
   `crates/tidefs-replicated-object-store/`.

4. **Cluster pool CLI/orchestrator alignment** — owns reconciling the
   orchestrator source (says live dispatch is not wired) with the
   `tidefsctl cluster pool create` TCP adapter and placement/heal
   exercise status. Adjacent to #662 but narrower. Write set:
   `crates/tidefs-cluster/src/pool_orchestrator.rs`,
   `apps/tidefsctl/src/commands/cluster.rs`.

5. **RDMA hardware validation and partition recovery** — owns the
   remaining carrier-policy evidence gap. Write set:
   `.github/workflows/rdma.yml`, `crates/tidefs-transport/src/rdma/`.

Each of these should be a focused GitHub issue with its own expected
write set, acceptance criteria, and validation tier. None of them
edits this decision record except to update the follow-up list.

## What this decision does not close

- TFR-017 remains open until the follow-up implementation issues
  above are resolved and cross-replica comparison, repair authority,
  and distributed transaction authority are proven end-to-end.
- This decision does not create present-tense product claims.
  It names authority boundaries; product claims require runtime
  validation evidence that does not yet exist for the remaining
  TFR-017 gaps.
