# Distributed Snapshot Shipping Design

Status: current TFR-010 planning pointer for GitHub issue #1250.

This file remains because `docs/REVIEW_TODO_REGISTER.md`,
`docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md`, and ADR-0008 cite it for a narrow
distributed snapshot-shipping boundary. It is not production-readiness,
distributed durability, or transport-performance evidence.

## 1. Protocol Foundation

### 1.1 Decision: VFSSEND2 Is The Protocol Foundation

Distributed snapshot shipping uses VFSSEND2 from `crates/tidefs-send-stream/`
as the protocol foundation. The local VFSSEND1 changed-record export remains a
local-filesystem format and is not extended into a network protocol here.

The current source pointers are:

- `crates/tidefs-send-stream/src/lib.rs` for VFSSEND2 framing;
- `crates/tidefs-send-stream/src/send_stream_adapter.rs` and
  `send_transport_bridge.rs` for transport adapter mechanics;
- `crates/tidefs-receive-stream/` for receive-side base-root and checkpoint
  handling;
- `apps/tidefs-storage-node/src/snapshot_barrier.rs` for the pre-send
  snapshot barrier input.

### 1.3 Transport Binding

This design does not choose TCP, RDMA, loopback, or any other concrete
transport as product authority. TFR-017 and `docs/TRANSPORT_CLUSTER_AUTHORITY.md`
own the transport/membership/runtime split. Snapshot shipping consumes their
admission, roster, epoch, and backpressure decisions when source work exists.

## 4. Deadlist Boundary

Distributed send/receive must not transmit deadlist entries as authority. A
receiver has its own clone set, current root, lifecycle pins, and snapshot
extent pins. Future received snapshot-deletion deltas must trigger the local
released-root derivation API selected by `docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md`
instead of importing sender-side deadlist contents.

## 7.2 Scheduling And Admission

Ordinary snapshot shipping is background bulk work:

- it uses `SessionClass::TransferBulk` and `MessageFamily::StateTransfer`;
- it is resumable and preemptible only at VFSSEND2 chunk/checkpoint boundaries;
- it yields to control, membership, metadata, intent-log durability barriers,
  foreground reads/writes, and policy-protected repair or evacuation work;
- memory pressure throttles or drains snapshot shipping before demand work.

Foreground or demand escalation is allowed only when a storage-intent or
recovery/degradation issue records the evidence that the shipment is required
for durability, RPO/RTO, or repair safety. Issue #862 owns the policy
enforcement vocabulary and source implementation.

Implementations must expose typed defer/refusal reasons before snapshot
shipping becomes operator-facing behavior. Initial classes are:

- `snapshot_not_committed`
- `snapshot_barrier_pending`
- `dataset_slot_in_use`
- `pool_limit_reached`
- `peer_limit_reached`
- `node_limit_reached`
- `membership_peer_unavailable`
- `sender_authority_stale`
- `receiver_missing_base`
- `receiver_rejected_policy`
- `transport_backoff`
- `transport_path_evidence_stale`
- `transport_backpressured`
- `governor_pressure`
- `storage_intent_budget_exhausted`
- `cross_pool_untrusted`
- `resume_checkpoint_invalid`
- `resume_staging_missing`

## Non-Claims

This pointer does not claim product-ready replication, distributed snapshot
availability, WAN/RDMA performance, cross-pool trust policy, automatic snapshot
retention policy, multi-node durability, release readiness, or
successor/comparator standing. Those claims remain gated by source
implementation, focused runtime evidence, `validation/claims.toml`, and
`docs/CLAIMS_GATE_POLICY.md`.
