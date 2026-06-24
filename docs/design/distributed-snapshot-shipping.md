# Distributed Snapshot Shipping Design

> TFR-010 distributed snapshot shipping investigation (issue #1250).
> Design/planning authority, not a production-readiness claim.
> Deadlist integration remains an open design item owned by #1248;
> this document names the integration model and deferred decisions.

## 1. Protocol Foundation

### 1.1 Decision: VFSSEND2 is the protocol foundation

VFSSEND2 (`crates/tidefs-send-stream`) is selected as the canonical
send/receive protocol for distributed snapshot shipping. The alternative
considered—extending the local-filesystem VFSSEND1 `ChangedRecordExport`
format—is rejected.

**Rationale for VFSSEND2:**

- VFSSEND2 already defines stream header versioning, feature negotiation,
  sender authority evidence, record-level checksums, checkpoint cursors, and
  chunk framing with BLAKE3 auth tags. None of these exist in VFSSEND1, and
  retrofitting them would duplicate the send-stream crate.
- The `SendStreamAdapter` and `SendTransportBridge` already bridge VFSSEND2
  framing to transport sessions via `MessageFamily::StateTransfer` /
  `SessionClass::TransferBulk`, providing credit-based flow control and
  authenticated stream-completion footers.
- The deterministic two-node harness (`tidefs-two-node-harness`) already
  validates VFSSEND2 end-to-end through loopback transport, proving the
  chunk-level framing, authenticated shipping, and receive/dispatch pipeline
  are correct.
- VFSSEND2's `SenderAuthority` carries pool UUID, epoch, and membership
  generation as identity evidence that a receiver can validate against cluster
  membership state.

**Why not extend VFSSEND1:**

- VFSSEND1 (`ChangedRecordExport` in `tidefs-local-filesystem`) is a
  single-node format: no transport session model, no feature negotiation, no
  sender identity evidence, and no checkpoint cursor suitable for network
  resumption. Extending it would require building the same session, identity,
  and checkpoint machinery that VFSSEND2 already provides.
- The codebase already treats VFSSEND1 as the current local format and
  VFSSEND2 as the intended multi-node format; introducing a third protocol
  variant would create unnecessary fragmentation.

### 1.2 Protocol layering

```text
  Snapshot lifecycle           (tidefs-local-filesystem, tidefs-dataset-lifecycle)
       |
       v
  VFSSEND2 framing             (tidefs-send-stream: SendBuilder, ChunkFramer)
       |
       v
  Send-stream transport        (send_stream_adapter, send_transport_bridge)
       |
       v
  TIDEfs transport session     (tidefs-transport: MessageFamily::StateTransfer,
       |                        SessionClass::TransferBulk)
       v
  Wire (TCP, RDMA, loopback)
```

### 1.3 Open: transport bindings

This design does not pre-select TCP, RDMA, or any other concrete transport
binding. VFSSEND2's `TransportWriter`/`TransportReader` traits abstract over
the transport, and the `SendStreamAdapter` bridges to the existing
`SendPipelineHandle`. Follow-up implementation issues will wire the concrete
transport selected by the cluster authority decision (TFR-017).

## 2. Session Lifecycle

### 2.1 Session initiation

1. **Sender** (coordinator or designated snapshot-source node) opens a
   transport session to the receiver using existing `tidefs-transport` session
   establishment. The session carries `EndpointFamily::StateTransfer` and
   `SessionClass::TransferBulk`.

2. **Feature negotiation** occurs at the VFSSEND2 level. The
   `FeatureNegotiationRequest`/`FeatureNegotiationReply` exchange validates
   that both peers support the required VFSSEND2 features and agree on
   compression, encryption, and checksum algorithms.

3. **Sender authority validation**: The receiver inspects the
   `SenderAuthority` extension in the stream header (pool UUID, epoch,
   membership generation) and validates it against the receiver's current
   cluster membership view. This is identity evidence, not an authorization
   token; receive authorization is a separate local-filesystem policy gate.

### 2.2 Who drives the send

The **sender** drives the send. The coordinator node (the node that cuts the
snapshot or holds the authoritative snapshot state) enumerates changed objects,
frames them into VFSSEND2 records, and transmits through the transport bridge.
The receiver is passive: it receives, validates, and persists.

This follows the same model as local-filesystem send/receive: the sender
enumerates the delta, and the receiver imports it.

### 2.3 Incremental base negotiation

The sender declares the incremental base root identity in the VFSSEND2 stream
header. The receiver validates it holds that base root via
`BaseRootPinLookup::lookup_base_root` (already implemented in
`tidefs-receive-stream` receive persistence).

- If the receiver holds the base root and its content is intact, the
  incremental receive proceeds (only changed objects are transmitted).
- If the receiver does not hold the base root, it rejects the incremental
  stream. The sender must then initiate a full (non-incremental) send.
- The base root must be a data-retaining snapshot or clone on the receiver,
  protected by the three-part snapshot authority (state map, catalog,
  lifecycle pin).

### 2.4 Checkpoint and resumption

VFSSEND2 `SendCursor` encodes stream position (snapshot index, object index,
record index, payload offset, stream digest). The receiver can:

- Persist a `ReceiveCheckpoint` after processing a configurable number of
  records (controlled by `checkpoint_interval_records` in the stream header).
- On transport failure or node restart, resume from the last checkpoint:
  `ReceiveBuilder::resume_from_checkpoint()` skips already-persisted objects
  and resumes at the next unprocessed record.

The sender may also persist its cursor, but in practice the receiver's
checkpoint is sufficient because the receiver reports the last-safe position
and the sender can re-read and re-transmit from that point.

### 2.5 Across node restarts and partitions

- **Node restart on sender**: The send session is lost. On sender restart,
  a new transport session is established, and the sender resumes from the
  receiver's last-reported checkpoint. The sender re-enumerates the remaining
  objects and continues.
- **Node restart on receiver**: The receive session is lost. On receiver
  restart, it loads the last `ReceiveCheckpoint` from stable storage,
  re-establishes the transport session, and requests the sender resume from
  the checkpoint cursor.
- **Network partition during send**: The transport session fails. Both sides
  retain checkpoint state. When the partition heals, a new session is
  established and the send resumes from the last checkpoint. If the partition
  persists beyond a configured timeout, the send is abandoned and must be
  restarted from scratch or from a fresh snapshot.

### 2.6 Session termination

- **Normal termination**: The sender transmits a `SendStreamEnd` footer
  (or calls `SendTransportBridge::finish()`) containing a BLAKE3 stream
  digest. The receiver verifies the digest against its own accumulated hash
  of all received chunks, confirming complete and ordered delivery.
- **Abort**: Either peer may abort by closing the transport session. The
  receiver retains its last checkpoint for potential resumption.
- After successful termination, the receiver applies the received snapshot
  state atomically, updates its snapshot state map, catalog, and lifecycle
  pins, and the session resources are released.

## 3. Clone Shared-Root Semantics

### 3.1 Clone promotion across nodes

When a clone is promoted on the source node, the promotion changes the
snapshot record's kind from `Clone` to `Snapshot` and clears the `origin`
field. The promoted entry retains the same root and creation generation.

In a distributed context, downstream replicas that received the clone via
snapshot shipping must apply the same promotion:

1. The sender transmits the promotion as a `SnapshotDelta` carrying the
   updated snapshot record (kind=Snapshot, origin=None, same root).
2. The receiver applies the promotion through the existing
   `promote_clone` path in `tidefs-local-filesystem`, which already handles
   the catalog update, flag reconciliation, and authority consistency check.
3. The clone shared-root invariant is preserved: the lifecycle pin for the
   shared root already has a count that includes the clone. Promotion does
   not change the root, so no pin-count adjustment is needed.

### 3.2 Clone deletion across nodes

When a clone is deleted on the source node, the sender transmits a deletion
delta. The receiver calls `delete_clone`, which removes the clone record
and unpins the clone's lifecycle root (decrementing the pin count). The
origin (if still existent) is unaffected.

### 3.3 Clone creation across nodes

A clone created on the source node references the origin snapshot's root.
When shipped to a replica, the receiver must:
1. Verify the origin exists on the receiver (it must have been shipped
   previously).
2. Create the clone record with the same root and origin reference.
3. Pin the shared root and create the catalog entry with `DatasetFlags::CLONE`.

If the origin has not yet been shipped, the receiver must reject the clone
delta and the sender must ensure origin shipment precedes clone shipment.
This is an ordering constraint, not a new semantic.

## 4. Deadlist Integration

### 4.1 Decision: receiver derives deadlist entries locally

When a snapshot deletion is shipped to a replica, the receiver independently
derives deadlist entries from its own GC pin set after applying the deletion.
The sender does not transmit deadlist entries.

**Rationale:**

- The deadlist must respect clone shared-root semantics on the receiver:
  a root unpinned by one snapshot deletion may still be pinned by a clone
  that exists on the receiver but not on the sender. Only the receiver can
  determine which roots are truly unpinned after applying the deletion.
- Deadlist derivation is a local operation: given the set of unpinned
  traversal roots and the object store, the deadlist is the set of block
  keys reachable only from those roots. This is the same operation whether
  the deletion originated locally or was received via snapshot shipping.
- Transmitting deadlist entries from the sender would couple the two nodes'
  GC pin sets, violating the authority model in
  `SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md` section 7.3.

### 4.2 Integration point

The receive path triggers deadlist derivation after processing a
snapshot-deletion delta:

```text
receive delta "delete snapshot X"
       |
       v
delete_snapshot(X)  (local-filesystem: unpin root, remove catalog entry)
       |
       v
derive_deadlist_for_unpinned_roots()  (TBD by #1248)
       |
       v
feed deadlist entries to allocator reclaim pipeline  (TBD by #1248)
```

The deadlist derivation machinery is owned by #1248 (deadlist integration
design). This distributed design defers to #1248 for the derivation algorithm,
persistence format, and allocator integration, and adds only the trigger
point: after receiving a snapshot-deletion delta, the receiver must run
deadlist derivation for the affected root.

### 4.3 What the distributed design requires of #1248

- The deadlist derivation function must accept a set of unpinned traversal
  roots and produce a set of dead block keys.
- The function must be callable from the receive path (not only from the
  local snapshot-deletion path).
- The deadlist must be consultable by the allocator before reusing a block,
  regardless of whether the deadlist entry was triggered by a local or
  received deletion.

## 5. Relationship to Existing Replication Paths

### 5.1 Separate transport sessions

Distributed snapshot shipping uses a **separate transport session** from the
live write-replication path:

| Aspect | Write replication | Snapshot shipping |
|--------|------------------|-------------------|
| Session class | `Replication` (implicit per-write) | `TransferBulk` (long-lived) |
| Message family | `Replication` | `StateTransfer` |
| Priority | Latency-sensitive | Bulk, lower priority |
| Lifecycle | Per-write, short-lived | Per-send, resumable |
| Quorum | Yes (majority/all) | No (point-to-point) |

The `tidefs-transport` outbound scheduler already supports per-session-class
priority differentiation via `session_class_to_send_priority`, so separating
these streams does not require scheduler changes.

### 5.2 Interaction with replicated-object-store

After the receiver persists received snapshot objects into its
`LocalObjectStore`, the normal replication write path applies:

- If the receiver is a primary in a replication group, `LocalObjectStore::put`
  triggers `ReplicationWritePath::submit_write`, which fans the object out to
  replica peers with quorum acknowledgment.
- This means snapshot-received objects automatically reach replication-group
  replicas through the existing write path. Snapshot shipping itself does not
  need to know about replication-group topology.

### 5.3 Interaction with replicated-object-store read path

Snapshot receive does not interact with the read path. Received objects are
written to the local object store; subsequent reads (including degraded reads
from replicas) use the existing `ReplicatedObjectReader` path.

## 6. Error Recovery and Consistency Guarantees

### 6.1 Idempotency

Snapshot shipping is **idempotent by object key**: each object has a stable
key. Re-importing the same key is a no-op after the first successful put.
The receiver's checkpoint tracks which object keys have been persisted;
resumption skips already-persisted keys.

### 6.2 Partial receive handling

On partial receive (transport failure mid-stream):

1. The receiver retains the objects already persisted and the last
   `ReceiveCheckpoint`.
2. The snapshot state (snapshot records, catalog) is **not** updated until
   the full stream is received and verified. The partial-receive state
   lives in the receive staging area.
3. On resumption, the sender re-transmits from the checkpoint. Already-
   persisted objects are skipped.

### 6.3 Consistency guarantees

- **Per-object integrity**: Every VFSSEND2 record carries a BLAKE3 checksum.
  The receiver validates every record before persisting.
- **Stream integrity**: The `SendStreamEnd` footer carries a BLAKE3 stream
  digest over all chunk payloads. The receiver verifies this digest,
  confirming complete and ordered delivery.
- **Atomic application**: Snapshot state updates (snapshot records, catalog
  entries, lifecycle pins) are applied atomically after the full stream is
  received and verified. If the stream fails before completion, the
  receiver's snapshot state is unchanged.
- **No partial-snapshot visibility**: A partially received snapshot is never
  visible to users. The snapshot only becomes visible after the full stream
  is applied.

## 7. Follow-Up Implementation Issue Map

### 7.1 Implementation issues

Each follow-up issue has a single responsibility, a non-overlapping expected
write set, and a validation tier.

Current GitHub mapping: #1252 owns send-path wiring, #1254 owns receive-path
wiring, #1255 owns sender lifecycle, #1256 owns receiver lifecycle, #1257 owns
clone delta propagation, #1259 owns the received-deletion deadlist trigger, and
#1258 owns barrier integration.

| Issue | Responsibility | Expected write set | Validation tier |
|-------|---------------|-------------------|-----------------|
| Wire storage-node daemon to VFSSEND2 send path | Replace VFSSEND1 `ChangedRecordExport` encoding in `tidefs-storage-node` `Frame::Send` handler with VFSSEND2 `SendBuilder` + `SendTransportBridge`. Storage-node daemon only; local-filesystem unchanged. | `apps/tidefs-storage-node/src/`, `Cargo.toml` (add send-stream dep) | Two-node harness + QEMU smoke |
| Wire storage-node daemon to VFSSEND2 receive path | Replace VFSSEND1 `ChangedRecordExport` decoding in `tidefs-storage-node` `Frame::Receive` handler with VFSSEND2 `ReceiveBuilder`. Storage-node daemon only. | `apps/tidefs-storage-node/src/` | Two-node harness + QEMU smoke |
| Distributed snapshot send session lifecycle | Implement session initiation, feature negotiation, sender authority validation, checkpoint persistence, and resumption logic for the sender side. Wires `SendStreamAdapter` to a real transport session. | `crates/tidefs-send-stream/` (session module), `crates/tidefs-transport/` (if needed) | Two-node harness, QEMU carrier (#1220) |
| Distributed snapshot receive session lifecycle | Implement receiver-side session management, checkpoint persistence/load, base-root validation for incremental receives, and atomic snapshot-state application. | `crates/tidefs-receive-stream/`, `crates/tidefs-local-filesystem/src/send_receive.rs` (receive path) | Two-node harness, QEMU carrier (#1220) |
| Clone promotion/deletion propagation | Extend VFSSEND2 `SnapshotDelta` to carry snapshot-record mutations (promotion, deletion) and wire the receive path to apply them through the existing local-filesystem lifecycle. | `crates/tidefs-send-stream/`, `crates/tidefs-local-filesystem/src/snapshot.rs` | Two-node harness, QEMU carrier (#1220) |
| Deadlist derivation trigger on received deletion | Add a trigger point in the receive path that, after processing a snapshot-deletion delta, calls deadlist derivation for the affected root. Depends on #1248 for the derivation function. | `crates/tidefs-local-filesystem/src/send_receive.rs`, integration with deadlist module (TBD by #1248) | Unit tests, two-node harness |
| Snapshot barrier integration with send | Wire the existing `SnapshotBarrier` protocol (in `tidefs-storage-node`) as the pre-send quiesce step: before a distributed snapshot send, the coordinator runs the barrier, then initiates the VFSSEND2 transfer. | `apps/tidefs-storage-node/src/snapshot_barrier.rs`, send-path integration | QEMU carrier (#1220) |

### 7.2 Decision: policy/admission driven event shipping

Distributed snapshot shipping is scheduled by a source-side admission policy,
not by the transport layer and not by a timer that blindly starts sends. The
policy consumes committed snapshot lifecycle events, explicit operator requests,
and recovery/storage-intent signals, then admits a VFSSEND2
`SessionClass::TransferBulk` / `MessageFamily::StateTransfer` shipment only
when dataset, pool, peer, node, lane, membership, and receiver-state gates all
allow it.

This is a pre-alpha safety boundary. The scheduler does not cut snapshots,
does not define retention, does not select a concrete carrier, and does not
prove product replication. It chooses whether a committed snapshot or snapshot
metadata mutation that already exists should be shipped now, resumed, retried,
or refused/deferred with an operator-visible reason.

#### Models considered

1. **Source-coordinator periodic shipping.** A coordinator would scan every
   dataset on a fixed interval and ship any unshipped snapshot.

   This is rejected as the primary model. It is simple, but it hides why work is
   admitted, creates bursty full-send storms after partitions, has no natural
   place to consume storage-intent policy, and would couple snapshot shipping to
   a retention policy this design does not own. Periodic scans remain useful
   only as reconciliation: they may discover missed events and enqueue
   candidates, but each candidate still goes through the admission gates below.

2. **Transport/backpressure driven shipping.** Any source that can open a
   `TransferBulk` session would enqueue stream chunks until transport
   backpressure stops it.

   This is rejected as the policy boundary. Transport owns session-local
   mechanics and evidence, as recorded in `docs/TRANSPORT_CLUSTER_AUTHORITY.md`;
   it does not know dataset lineage, incremental-base availability, retention
   risk, recovery priority, tenant/budget ownership, or operator intent.

3. **Policy/admission driven event shipping.** Snapshot lifecycle events and
   operator or recovery requests create shipment candidates. A source-side
   admission controller chooses full, incremental, resume, retry, or defer
   using lineage state, receiver checkpoints, concurrency slots,
   `SessionClass::TransferBulk` lane state, transport path evidence, and
   storage-intent policy evidence when those surfaces exist.

   This is selected. It preserves VFSSEND2's sender-driven session model, keeps
   policy above transport, and is safe for pre-alpha TideFS because the default
   behavior is conservative: background/bulk shipping yields to foreground
   durability, metadata, control, and read pressure, and unknown evidence
   produces a visible defer/refusal rather than a silent weaker guarantee.

#### Trigger conditions

Only committed, locally visible snapshot state can trigger shipment. A pending
snapshot barrier, uncommitted txg, or partially applied received stream is not a
valid source snapshot for outbound shipping.

Initial full-send triggers are:

- the receiver has no applied snapshot for the `(source pool, dataset, peer)`
  relationship;
- the receiver's advertised base root is missing, corrupt, or not lineage-
  compatible, and policy/operator input allows a re-seed instead of refusing;
- an operator requests a full resynchronization for a dataset/peer pair;
- an incremental send cannot be formed because the base snapshot expired or was
  deleted, but the source still has the target snapshot and the policy permits
  replacing the receiver lineage with a full seed.

Initial incremental-send triggers are:

- a committed snapshot is newer than the receiver's last applied snapshot and
  the receiver holds the declared base root;
- a clone promotion, clone deletion, or snapshot deletion delta follows a
  receiver-visible base snapshot;
- a receiver requests resume or catch-up from a persisted checkpoint whose
  cursor and stream digest still match the source's VFSSEND2 stream.

Periodic reconciliation is allowed only to re-discover candidates that should
already have been enqueued by the event path, such as a source restart, peer
restart, or missed operator request. It must not create snapshots, change
retention, or bypass admission.

#### Admission order and concurrency limits

The admission controller evaluates candidates in this order:

1. Required control, membership, barrier, and foreground durability/read work
   always wins over snapshot shipping.
2. A valid resume attempt for an existing partial receive is admitted before a
   new shipment for the same dataset/peer, because it usually consumes less
   network and receiver staging space.
3. Incremental sends are preferred over full sends when the receiver has a
   verified base root.
4. Full sends are admitted only when no incremental path is valid or an
   operator/policy decision explicitly requests a re-seed.

The initial hard limits are deliberately small:

| Scope | Initial limit | Notes |
|---|---:|---|
| Dataset | 1 outbound shipment and 1 inbound shipment | A resume attempt consumes the same slot as its original shipment. Applying the final receive state is exclusive per dataset. |
| Pool | 2 outbound shipments and 2 inbound shipments | Full sends and incremental sends both count as one pool slot; deployments may lower this under pressure. |
| Peer pair | 1 outbound shipment and 1 inbound shipment | Prevents one slow peer from consuming all `TransferBulk` capacity. |
| Node | 4 active snapshot-shipping sessions total | Includes send, receive, and resume sessions across all pools. |

These are scheduler admission limits, not transport-QoS byte guarantees. Concrete
bandwidth caps, dynamic token shrinkage, and governor-fed window limits remain
owned by #862 and #891. Until those issues provide stronger policy evidence,
snapshot shipping uses these static limits and the existing transport
backpressure/lane state as conservative gates.

#### Retry and backoff

Every failed shipment records a typed retry state keyed by
`(source pool, dataset, peer, target snapshot, stream id)`.

| Failure class | Initial policy |
|---|---|
| Transport failure or timeout | Preserve receiver checkpoint evidence, mark the peer/dataset pair in exponential backoff with jitter, and retry only when membership still admits the peer and the `TransferBulk` lane is not sealed or hard-backpressured. |
| Peer restart or membership epoch advance | Do not reuse stale sender-authority evidence. Refresh membership generation and sender authority, then prefer checkpoint resume if the receiver reports a matching checkpoint. |
| Receiver busy or receiver concurrency limit | Defer using the receiver's hinted retry-after when available; otherwise use the normal backoff floor. This is not a full-send trigger by itself. |
| Receiver rejection for unsupported feature, sender authority mismatch, trust/policy refusal, or cross-pool mismatch | Do not retry until the rejected evidence changes. Surface the refusal to operators with the receiver reason. |
| Missing incremental base | Prefer a full seed only if policy/operator input allows re-seed and the source still has the target snapshot. Otherwise defer/refuse with a base-missing reason and require an operator or policy decision. |
| Transport path evidence stale or contradictory | Defer unless policy explicitly allows conservative background shipping on unknown path evidence. This consumes #846 when available. |
| Governor hard pressure | Refuse or keep deferred while #891 reports hard pressure for cluster queues or bulk transfer tokens. |

The first retry delay is implementation-defined but must be nonzero; each
subsequent retry backs off per failure key and resets only after a successful
stream completion or a materially different failure class. Backoff state is
separate from VFSSEND2 checkpoints: checkpoints identify how to resume data,
while retry state identifies when a resume or replacement send may be admitted.

#### Checkpoint and resume admission

VFSSEND2 checkpoints are the only resume authority. A resume attempt is admitted
only when all of these hold:

- the receiver checkpoint carries a send cursor whose digest matches the source
  stream prefix;
- the source still has the target snapshot and any required base-root objects;
- the sender authority can be refreshed for the current membership epoch;
- no active session already owns the same `(dataset, peer, stream id)` resume;
- the receiver staging state has not been discarded or superseded by a full
  re-seed.

If these checks fail, the scheduler either admits a full seed under the policy
above or refuses/defer with a typed reason. A resume attempt must not silently
fall back to a full send, because doing so can hide retention and operator-cost
decisions.

#### Lane and foreground-pressure treatment

Snapshot shipping uses `SessionClass::TransferBulk` and
`MessageFamily::StateTransfer`. The VFSSEND2 adapter maps that session class to
transport `SendPriority::Bulk`, and `MessageFamily::StateTransfer` may run on
the `Background` lane as its secondary lane. The initial scheduling policy
therefore treats ordinary snapshot shipping as background/bulk work:

- it is resumable and preemptible at VFSSEND2 chunk/checkpoint boundaries;
- it yields to control, membership, metadata, intent-log durability barriers,
  foreground reads/writes, and policy-protected repair/evacuation work;
- memory pressure throttles or drains snapshot shipping before demand work;
- a foreground/demand escalation is allowed only when a storage-intent or
  recovery/degradation issue records the evidence that the shipment is required
  for durability, RPO/RTO, or repair safety. #862 owns that policy enforcement
  vocabulary and source implementation.

#### Operator-visible defer/refusal reasons

Implementations must expose stable refusal/defer classes before shipping becomes
operator-facing behavior. Initial classes are:

| Reason | Meaning |
|---|---|
| `snapshot_not_committed` | The source snapshot or delta is not durably visible. |
| `snapshot_barrier_pending` | The #1258 pre-send barrier has not completed. |
| `dataset_slot_in_use` | The dataset already has an active shipment in that direction. |
| `pool_limit_reached` | The pool's snapshot-shipping slot limit is exhausted. |
| `peer_limit_reached` | The peer pair already has an active shipment in that direction. |
| `node_limit_reached` | The node-level snapshot-shipping session limit is exhausted. |
| `membership_peer_unavailable` | Membership/roster evidence does not admit the peer. |
| `sender_authority_stale` | Sender authority does not match the current membership epoch. |
| `receiver_missing_base` | Incremental base-root validation failed on the receiver. |
| `receiver_rejected_policy` | Receiver policy, trust, or feature negotiation rejected the stream. |
| `transport_backoff` | The failure key is still in retry backoff. |
| `transport_path_evidence_stale` | #846-style path evidence is missing, stale, or contradictory for the requested policy. |
| `transport_backpressured` | Transport lane/backpressure state currently prevents admission. |
| `governor_pressure` | #891-style resource governor pressure prevents bulk transfer admission. |
| `storage_intent_budget_exhausted` | #862-style policy/QoS budget would be exceeded. |
| `cross_pool_untrusted` | Cross-pool trust/policy evidence is absent or rejected. |
| `resume_checkpoint_invalid` | The receiver checkpoint cannot be matched to the source stream. |
| `resume_staging_missing` | Receiver staging state was discarded or superseded. |

#### Implementation map

This design reveals source work but does not assign it to this docs slice:

- Update #1255 or create a same-scope sender scheduler issue before source
  edits to add source-side shipment candidate state, retry/backoff state, and
  resume admission around the VFSSEND2 sender session. Expected write set:
  `crates/tidefs-send-stream/` session/scheduler module only, plus focused
  tests.
- Update #1256 before receiver-side lifecycle work to return typed receiver
  refusal/defer reasons for missing base roots, invalid checkpoints, busy
  staging, stale sender authority, and unsupported features. Expected write set:
  `crates/tidefs-receive-stream/` and the receive integration already named by
  #1256.
- Keep #1258 as the barrier trigger owner. The scheduler consumes a
  barrier-complete or barrier-refused result; it does not redesign
  `SnapshotBarrier`.
- Keep #846, #862, and #891 as non-blocking adjacent owners. Snapshot shipping
  consumes their transport path evidence, intent/QoS budget results, and
  governor pressure state when available, but this design does not move their
  source write sets.
- If implementation requires a standalone scheduler crate instead of extending
  the #1255/#1256 session lifecycle surfaces, create a new GitHub issue before
  source edits with a non-overlapping write set such as a new
  `crates/tidefs-snapshot-shipping-scheduler/` crate and only narrow adapter
  hooks in the sender/receiver lifecycle issues.

#### Non-claims

This scheduling decision does not claim product-ready replication, a WAN or
RDMA performance guarantee, cross-pool trust policy, automatic snapshot
retention policy, or successful QEMU carrier validation. #1220 remains the
carrier-validation surface for runtime follow-up work.

### 7.3 Remaining deferred decisions

The following remain deferred to follow-up design or implementation issues:

- **Concrete transport binding** (TCP, RDMA, etc.): deferred to TFR-017
  cluster authority decision.
- **Concrete QoS byte budgets and bandwidth caps** beyond the initial
  concurrency limits above: deferred to #862 and #891 implementation evidence.
- **Multi-hop routing** (sender → intermediate → receiver): not addressed;
  initial scope is point-to-point.
- **Cross-pool snapshot shipping** (different pool UUIDs): VFSSEND2
  `SenderAuthority` carries pool UUID; cross-pool shipping requires
  pool-trust configuration beyond this design.
- **Deadlist derivation algorithm**: owned by #1248.

## 8. Evidence Reviewed

- `docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md` (closed #1246) — snapshot,
  clone, deadlist, send/receive storage model authority.
- `docs/REVIEW_TODO_REGISTER.md` TFR-010 and TFR-017 notes.
- `docs/design/unified-scheduling-classes-lane-priority-model.md` — canonical
  lane classes, background bulk-transfer treatment, starvation, preemption, and
  memory-pressure rules.
- `docs/TRANSPORT_CLUSTER_AUTHORITY.md` — split authority between
  transport-local admission/backpressure mechanics and membership/runtime
  roster, epoch, and fencing decisions.
- `crates/tidefs-send-stream/src/lib.rs` — VFSSEND2 protocol framing,
  transport feature, current integration status, stale issue references.
- `crates/tidefs-send-stream/src/send_stream_adapter.rs` — transport adapter
  bridging VFSSEND2 to `SendPipelineHandle`.
- `crates/tidefs-send-stream/src/send_transport_bridge.rs` — transport bridge
  with sequenced chunk delivery and BLAKE3 stream digest.
- `crates/tidefs-send-stream/src/transport.rs` — `TransportWriter`/
  `TransportReader` traits, `SendTransport`, `RecvTransport`, loopback pair.
- `crates/tidefs-local-filesystem/src/send_receive.rs` — VFSSEND1
  `ChangedRecordExport`, incremental base-root identity, receive checkpoint.
- `crates/tidefs-local-filesystem/src/snapshot.rs` — snapshot lifecycle,
  hold/release, GC pin management.
- `apps/tidefs-storage-node/src/snapshot_barrier.rs` — multi-node snapshot
  barrier protocol.
- `crates/tidefs-two-node-harness/src/receive_stream.rs` — VFSSEND2
  end-to-end validation through deterministic loopback transport.
- `crates/tidefs-types-transport-session/src/lib.rs`,
  `crates/tidefs-transport/src/outbound_send.rs`,
  `crates/tidefs-transport/src/send_scheduler.rs`, and
  `crates/tidefs-transport/src/send_backpressure.rs` — `TransferBulk`,
  `StateTransfer`, lane class, send-priority, and backpressure source evidence.
- `crates/tidefs-replication/src/write_path.rs` — replication write fan-out
  with quorum semantics.
- `crates/tidefs-replicated-object-store/src/lib.rs` — N-replica store with
  quorum write, degraded read, replica repair.
- Open issue #1248 (deadlist integration design).
- Open issue #1220 (two-node QEMU carrier).
- Live follow-up and adjacent issue bodies: #1252, #1254, #1255, #1256, #1257,
  #1258, #1259, #846, #862, #891, and #1261.
