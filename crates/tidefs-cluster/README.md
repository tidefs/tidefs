# tidefs-cluster

Cluster membership lease and state-transfer crate: deterministic
`LeaseStateMachine`, BLAKE3-verified protocol messages, and
`ClusterLeaseRuntime` coordination for the storage-node daemon.

This is a crate-local API note, not a distributed product claim.
Distributed placement receipt, rebuild, reclaim, RDMA, replacement-node
orchestration, cluster-state convergence, and production readiness
remain blocked behind the authority gates tracked by #18, #1745,
#1795, and `validation/claims.toml`.

## Membership Lease Transitions

`LeaseStateMachine` manages a membership slot lease. Every state transition
produces a BLAKE3-256 digest covering the full machine state, enabling
digest-based integrity verification.

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
message exchange and epoch transition events.

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

## Placement Transfer

The `placement_transfer` module moves object data from source nodes to
destination nodes using the transport transfer control protocol.

### Core types

- **MemberReplicaObjectRange**: A descriptor specifying source and destination
  member IDs plus the object ranges to move. Supports construction from
  placement-runtime transfer tickets via `from_entries()` and merging with
  `merge()`.
- **TransferSession**: Per-transfer state tracking with progress counters,
  retry hooks, and epoch-bound validation.
- **PlacementTransferCoordinator**: Drives the transfer lifecycle, owns
  session state, coordinates message exchange with source and destination
  nodes via the transport transfer control protocol.

### Epoch bounding

Transfers are epoch-bounded: a session is only valid within the epoch it was
opened under. Epoch transitions abort in-flight transfers via
`on_epoch_transition()`.

### Transport integration

Transfer control messages are exchanged over the transport layer:

| Message | Discriminant | Purpose |
|---|---|---|
| `TransferInitiate` | 0x41 | Start transfer from source to destination |
| `TransferChunkAck` | 0x42 | Acknowledge chunk receipt at destination |
| `TransferComplete` | 0x43 | Signal transfer completed successfully |
| `TransferAbort` | 0x44 | Abort transfer and release resources |
| `TransferChunk` | 0x45 | Data payload chunk from source to destination |

### Validation

```sh
cargo test -p tidefs-cluster -- placement_transfer
```

## Rebuild Backfill

The rebuild backfill initiator consumes rebuild-planner outputs and
dispatches transport state-transfer commands for per-object recovery.

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
- **BackfillCommand**: A source-to-target data movement for a set of object
  IDs. Maps directly to a transport `StateTransferRequest`.
- **BackfillSession**: Per-backfill progress tracking with retry hooks and
  epoch-bound validation.
- **RebuildBackfillInitiator**: Drives the backfill lifecycle, owns session
  state, partitions plans into per-target batches, and coordinates transport
  state-transfer command execution.

### Plan partitioning

The initiator partitions a rebuild plan by target member: for each target
node across all reconstruction tasks, tasks are grouped by source node. One
`BackfillCommand` is created per (source, target) pair carrying the relevant
object IDs. Tasks with no viable sources are silently skipped.

### Epoch bounding

Backfills are epoch-bounded: a session is only valid within the epoch it was
opened under. Epoch transitions (via `on_epoch_transition()`) abort all
active backfills.

### Transport integration

Each `BackfillCommand` maps to a transport `StateTransferRequest` carrying
`epoch_id`, `requesting_node` (target), `object_ids`, and `max_chunk_bytes`.
The transport layer executes data movement; the initiator tracks progress via
`record_progress()`.

### Validation

```sh
cargo test -p tidefs-cluster -- rebuild_backfill
```
