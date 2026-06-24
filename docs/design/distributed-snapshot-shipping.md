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

| Issue | Responsibility | Expected write set | Validation tier |
|-------|---------------|-------------------|-----------------|
| Wire storage-node daemon to VFSSEND2 send path | Replace VFSSEND1 `ChangedRecordExport` encoding in `tidefs-storage-node` `Frame::Send` handler with VFSSEND2 `SendBuilder` + `SendTransportBridge`. Storage-node daemon only; local-filesystem unchanged. | `apps/tidefs-storage-node/src/`, `Cargo.toml` (add send-stream dep) | Two-node harness + QEMU smoke |
| Wire storage-node daemon to VFSSEND2 receive path | Replace VFSSEND1 `ChangedRecordExport` decoding in `tidefs-storage-node` `Frame::Receive` handler with VFSSEND2 `ReceiveBuilder`. Storage-node daemon only. | `apps/tidefs-storage-node/src/` | Two-node harness + QEMU smoke |
| Distributed snapshot send session lifecycle | Implement session initiation, feature negotiation, sender authority validation, checkpoint persistence, and resumption logic for the sender side. Wires `SendStreamAdapter` to a real transport session. | `crates/tidefs-send-stream/` (session module), `crates/tidefs-transport/` (if needed) | Two-node harness, QEMU carrier (#1220) |
| Distributed snapshot receive session lifecycle | Implement receiver-side session management, checkpoint persistence/load, base-root validation for incremental receives, and atomic snapshot-state application. | `crates/tidefs-receive-stream/`, `crates/tidefs-local-filesystem/src/send_receive.rs` (receive path) | Two-node harness, QEMU carrier (#1220) |
| Clone promotion/deletion propagation | Extend VFSSEND2 `SnapshotDelta` to carry snapshot-record mutations (promotion, deletion) and wire the receive path to apply them through the existing local-filesystem lifecycle. | `crates/tidefs-send-stream/`, `crates/tidefs-local-filesystem/src/snapshot.rs` | Two-node harness, QEMU carrier (#1220) |
| Deadlist derivation trigger on received deletion | Add a trigger point in the receive path that, after processing a snapshot-deletion delta, calls deadlist derivation for the affected root. Depends on #1248 for the derivation function. | `crates/tidefs-local-filesystem/src/send_receive.rs`, integration with deadlist module (TBD by #1248) | Unit tests, two-node harness |
| Snapshot barrier integration with send | Wire the existing `SnapshotBarrier` protocol (in `tidefs-storage-node`) as the pre-send quiesce step: before a distributed snapshot send, the coordinator runs the barrier, then initiates the VFSSEND2 transfer. | `apps/tidefs-storage-node/src/snapshot_barrier.rs`, send-path integration | QEMU carrier (#1220) |

### 7.2 Deferred decisions

The following are deferred to follow-up design or implementation issues:

- **Concrete transport binding** (TCP, RDMA, etc.): deferred to TFR-017
  cluster authority decision.
- **QoS budgets and bandwidth caps** for snapshot shipping sessions: deferred
  to a transport-QoS design issue.
- **Multi-hop routing** (sender → intermediate → receiver): not addressed;
  initial scope is point-to-point.
- **Cross-pool snapshot shipping** (different pool UUIDs): VFSSEND2
  `SenderAuthority` carries pool UUID; cross-pool shipping requires
  pool-trust configuration beyond this design.
- **Snapshot shipping scheduling** (when to ship, retry policy, concurrent
  send limits): deferred to a snapshot-scheduling design issue.
- **Deadlist derivation algorithm**: owned by #1248.

## 8. Evidence Reviewed

- `docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md` (closed #1246) — snapshot,
  clone, deadlist, send/receive storage model authority.
- `docs/REVIEW_TODO_REGISTER.md` TFR-010 and TFR-017 notes.
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
- `crates/tidefs-replication/src/write_path.rs` — replication write fan-out
  with quorum semantics.
- `crates/tidefs-replicated-object-store/src/lib.rs` — N-replica store with
  quorum write, degraded read, replica repair.
- Open issue #1248 (deadlist integration design).
- Open issue #1220 (two-node QEMU carrier).
