# tidefs-cluster

Deterministic cluster membership lease transitions with BLAKE3-verified state
integrity for multi-node validation.

## Membership Lease Transitions

Each cluster member drives a `LeaseStateMachine` to manage its membership
slot lease. The machine is deliberately small and deterministic: every state
transition produces a new BLAKE3-256 digest covering the full machine state,
enabling peer verification without relying on wall-clock trust.

### State diagram

```
                 acquire()
Unleased ─────────────────────> Acquiring
   ▲                                 │
   │                      grant()    │ reject()
   │                                 │
   │ release()             ┌─────────┘
   │                       ▼
   │                     Held ───────────────┐
   │                       │                 │
   │             renew()   │   expire()      │
   │                       ▼                 │
   │                    Renewing ────────────┘
   │                       │
   │           renew_ack() │  renew_nack()
   │                       │
   │                       ▼
   │                     Held
   │                       │
   │            release()  │
   │                       ▼
   └───────────────── Released

                    Expiring ── expire()
                        ▲
Held ──────────────────┘
Renewing ──────────────┘
```

### States

| State | Description |
|---|---|
| `Unleased` | No lease held; ready to begin acquisition |
| `Acquiring` | Lease acquisition in progress (request sent, awaiting grant) |
| `Held` | Lease is held and active |
| `Renewing` | Lease is held but renewal is in progress |
| `Expiring` | Lease TTL is approaching expiry; waiting for renewal response |
| `Released` | Lease has been voluntarily released |

### BLAKE3 integrity

State digests are computed under domain `tidefs-cluster-membership-lease-v1`
and cover: node_id, state discriminant, epoch, transition count, and lease
fields (or zero block when absent). Wire messages carry per-frame BLAKE3-256
digests under domain `tidefs-cluster-membership-lease-protocol-v1`.

## Protocol Messages

Nine message types cover the full lease lifecycle:

| Message | Discriminant | Payload |
|---|---|---|
| `Acquire` | 0x01 | node_id, epoch, slot, lease_term_ms, request_id |
| `AcquireAck` | 0x02 | request_id, lease_id, epoch, slot, lease_term_ms, deadline_ms |
| `AcquireNack` | 0x03 | request_id, reason |
| `Renew` | 0x04 | node_id, lease_id, epoch |
| `RenewAck` | 0x05 | lease_id, new_deadline_ms |
| `RenewNack` | 0x06 | lease_id, reason |
| `Release` | 0x07 | node_id, lease_id, epoch |
| `ReleaseAck` | 0x08 | lease_id |
| `ExpireNotify` | 0x09 | node_id, lease_id, epoch |

### Wire format

```
[1-byte discriminant][bincode payload][32-byte BLAKE3 digest]
```

## Runtime

`ClusterLeaseRuntime` coordinates the state machine with transport-layer
message exchange and epoch transition events. It is designed to be embedded
in a node's main event loop.

### Configuration

| Parameter | Default | Description |
|---|---|---|
| `lease_term_ms` | 30,000 | Duration of each lease term in ms |
| `renewal_threshold_permille` | 750 | Fraction of term (in thousandths) at which to start renewal |
| `max_acquire_retries` | 3 | Maximum acquisition retries |

### API

- `start_acquire(slot, peer)` — begin lease acquisition
- `release_lease(peer)` — voluntarily release the lease
- `tick(now_ms, peer)` — periodic deadline check and automatic renewal
- `handle_incoming(peer, msg)` — process incoming protocol message
- `on_epoch_transition(epoch)` — renegotiate on epoch change
- `status()` — query current lease state and digest
- `on_member_departure(plan, epoch)` — open backfill session and queue batches
- `record_backfill_progress(id, objects, bytes)` — record transfer progress
- `complete_backfill(id)` — finalize a completed backfill
- `abort_backfill(id)` — abort an in-progress backfill
- `backfill_state(id)` — query backfill session state
- `active_backfill_count()` — count of in-flight backfills
- `backfill_pending_objects()` — total objects not yet transferred


## Integration Points

- **tidefs-transport**: Protocol messages are sent/received over established
  transport sessions via `membership_lease_dispatch`. Messages use
  `MessageFamily::LeaseFenceDeadline` (m3).
- **tidefs-membership-live**: Epoch transition events trigger lease
  renegotiation via `ClusterLeaseRuntime::on_epoch_transition()`.

## Validation

```sh
cargo test -p tidefs-cluster
```

Tests cover all state transitions, expiry, duplicate rejection, concurrent
isolation (3 simulated peers), epoch-boundary renegotiation, BLAKE3 digest
determinism, and protocol message encoding/decoding with digest verification.

## Placement Transfer

The placement transfer coordinator bridges placement plans to transport-layer
data movement, moving data ownership between nodes in the deterministic
multi-node harness.

### Transfer lifecycle

```
Idle ──open()──> Planning ──initiate()──> Initiating
                                                │
                                         ┌──────┘
                                         v
                                   Transferring ──complete()──> Confirm
                                        │                          │
                                   abort()                   finalize()
                                        │                          │
                                        v                          v
                                     Aborted                   Complete
```

### States

| State | Description |
|---|---|
| `Idle` | No transfer in progress |
| `Planning` | Transfer plan is being built from placement diffs |
| `Initiating` | Initiate message sent to source; awaiting acknowledgement |
| `Transferring` | Data chunks streaming from source to destination |
| `Confirming` | Transfer complete; final confirmation pending |
| `Complete` | Transfer finished successfully |
| `Failed` | Transfer failed and was rolled back |
| `Aborted` | Transfer was explicitly aborted |

### Core types

- **TransferPlan**: A placement diff identifying source nodes, destination
  nodes, and object ranges to move. Supports construction from placement-runtime
  transfer tickets via `from_entries()` and merging with `merge()`.
- **TransferSession**: Per-transfer state tracking with progress counters,
  retry hooks, and epoch-bound validation.
- **PlacementTransferCoordinator**: Drives the transfer lifecycle, owns
  session state, coordinates message exchange with source and destination
  nodes via the transport transfer control protocol.

### Epoch bounding

Transfers are epoch-bounded: a session is only valid within the epoch it was
opened under. Epoch transitions abort in-flight transfers via
`on_epoch_transition()`. Source nodes must hold an active lease (Held or
Renewing) to serve data during transfer.

### Transport integration

Transfer control messages are exchanged over the transport layer:

| Message | Discriminant | Purpose |
|---|---|---|
| `TransferInitiate` | 0x41 | Start transfer from source to destination |
| `TransferChunkAck` | 0x42 | Acknowledge chunk receipt at destination |
| `TransferComplete` | 0x43 | Signal transfer completed successfully |
| `TransferAbort` | 0x44 | Abort transfer and release resources |
| `TransferChunk` | 0x45 | Data payload chunk from source to destination |

Node-to-node authenticity and integrity are provided by the transport/session
security boundary.


### Validation

```sh
cargo test -p tidefs-cluster -- placement_transfer
```

## Rebuild Backfill

The rebuild backfill initiator bridges rebuild-planner outputs to transport
state-transfer commands, making node/device loss recovery observable in the
userspace cluster harness.

### Backfill lifecycle

```
Idle ──open()──> Planning ──initiate()──> Initiating
                                                │
                                         ┌──────┘
                                         v
                                   Transferring ──complete()──> Verifying
                                        │                          │
                                   abort()                   finalize()
                                        │                          │
                                        v                          v
                                     Aborted                   Complete
```

### States

| State | Description |
|---|---|
| `Idle` | No backfill in progress |
| `Planning` | Rebuild plan is being partitioned into per-target batches |
| `Initiating` | Initiate messages sent to source nodes; awaiting acknowledgement |
| `Transferring` | Data chunks streaming from sources to targets |
| `Verifying` | Transfer complete; integrity verification in progress |
| `Complete` | Backfill finished successfully |
| `Failed` | Backfill failed and was rolled back |
| `Aborted` | Backfill was explicitly aborted |

### Core types

- **RebuildPlan**: An ordered list of `ReconstructionTask` entries describing
  what objects need backfill. Each task names object_id, source_nodes,
  target_nodes, optional data_range, and priority. Mirrors
  `tidefs-rebuild-planner::plan::RebuildPlan` to avoid cyclic dependencies.
- **ReconstructionTask**: A single object needing backfill with source/target
  node sets and priority ordering.
- **BackfillBatch**: Groups `BackfillCommand`s destined for a single target
  member, enabling grouped dispatch and progress tracking.
- **BackfillCommand**: A source→target data movement for a set of object IDs.
  Maps directly to a transport `StateTransferRequest`.
- **BackfillSession**: Per-backfill progress tracking with retry hooks and
  epoch-bound validation.
- **RebuildBackfillInitiator**: Drives the backfill lifecycle, owns session
  state, partitions plans into per-target batches, and coordinates transport
  state-transfer command execution.

### Plan partitioning

The initiator partitions a rebuild plan by target member: for each target node
across all reconstruction tasks, tasks are grouped by source node. One
`BackfillCommand` is created per (source, target) pair carrying the relevant
object IDs. Tasks with no viable sources are silently skipped.

### Epoch bounding

Backfills are epoch-bounded: a session is only valid within the epoch it was
opened under. Epoch transitions (via `on_epoch_transition()`) abort all active
backfills. Source nodes must hold an active lease (Held or Renewing) to serve
backfill data, enforced via `validate_epoch_and_sources()`.

### Transport integration

Each `BackfillCommand` maps to a transport `StateTransferRequest` carrying
`epoch_id`, `requesting_node` (target), `object_ids`, and `max_chunk_bytes`.
The transport layer executes data movement; the initiator tracks progress via
`record_progress()`.

### Validation

```sh
cargo test -p tidefs-cluster -- rebuild_backfill
```
