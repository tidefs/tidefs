# tidefs-storage-node

Storage node daemon: bridges `tidefs-transport` with
`tidefs-replicated-object-store` and provides a unified runtime
authority spine that discloses the active transport backend to
all subsystems.

This is a daemon-local implementation note, not final distributed
operator UAPI or a distributed product claim. Distributed placement
receipt, rebuild, reclaim, RDMA, replacement-node orchestration,
cluster-state convergence, and production readiness remain blocked
behind the authority gates tracked by #18, #1745, #1795, and
`validation/claims.toml`.

## Runtime Authority Spine

The storage node constructs a `RuntimeAuthority` at startup that
declares one coherent backend choice. Every subsystem (transport,
membership, placement, replication) consults the same spine rather
than maintaining separate deterministic-only and live-only truth
paths. The spine is daemon-internal backend disclosure: it does not
authorize `tidefsctl cluster pool create` beyond its prototype command
class, does not make placement/heal exercises operator status or repair
authority, and does not replace the `cluster status` live-owner path.

## Data Path Selection

At startup, the storage node selects its object store backend based on
`RuntimeAuthority::is_live()`:

- **Live backends**: opens a `TransportReplicatedStore` backed by a local
  `LocalObjectStore` primary plus remote replicas connected via
  per-endpoint-family sessions (Control/Data/Shadow).
  `RuntimeAuthority::replication_factor()` drives `write_quorum` and
  `total_replicas` in the `TransportReplicatedStoreConfig`. Membership
  peers are connected as replicas. When no membership peers are
  configured, a warning is emitted.

- **Non-live backends** (Loopback, DeterministicInMemory, NotRun, or
  no authority): opens a local path-backed `ReplicatedObjectStore` using
  `ReplicatedStoreConfig`. This is the explicit single-node/harness path.

- **Backend disclosure** appears in every `StatsResponse` and
  `HealthCheckResponse`, recording which backend variant is active.

### BackendDisclosure Variants

| Variant | Description | `is_live()` |
|---|---|---|
| `Rdma(addr)` | RDMA transport endpoint | true |
| `Tcp(addr)` | TCP transport bound to socket address | true |
| `Loopback` | In-process loopback for single-node deterministic testing | false |
| `DeterministicInMemory` | Fully deterministic in-memory backend for unit/validation harnesses | false |
| `NotRun` | Authority spine constructed but no transport active (build-only mode) | false |

### Initialization Order

```
disclosure → transport config → membership → placement → replication
```

The authority spine holds the disclosed backend and derived transport
configuration. Membership, placement, and replication subsystems receive
the same backend disclosure and settings during initialization, ensuring
one coherent daemon-internal authority model.

### Replication Factor

The CLI `--replication-factor` flag and JSON `replication_factor` field
default to 1 and set the configured replication factor stored in the
authority spine. This value is available to replication and placement
subsystems at initialization time.

## Modules

- `client`: One-shot client requests to a running storage node.
- `config`: JSON configuration file support (`StorageNodeConfig::from_json_file`).
- `protocol`: Wire protocol framing (request/response frames).
- `server`: Storage node server daemon (accept loop, request dispatch,
  membership service, send/receive, stats).
- `authority_spine`: Runtime authority spine (`RuntimeAuthority`) that
  discloses the active transport backend and wires it through all
  subsystems without defining final cluster operator UAPI.

## Inbound Replication Handler

The storage node's `serve_one()` accept loop handles incoming
`ReplicationMessage` protocol frames from connected
`TransportReplicatedStore` peers. After Frame protocol and
SegmentFetchRequest dispatch, the loop attempts bincode deserialization
of the remaining frame bytes as a `ReplicationMessage`. Recognized
variants include `PutLocal`, `DeleteLocal`, `GetLocal`, and
control-plane messages such as `RepairObject` and
`CheckRepairCompletion`.

### Receipt-Backed Repair

`TransportReplicatedStore` exposes receipt-validating repair entry points
that execute `RepairObject` and record verified-task completion in one
fail-closed path. The bridge treats `RepairObjectAck` as completion
evidence only when `success` is true and the ack carries a non-synthetic
`repaired_placement_receipt_ref` that passes the rebuild-runtime
completion law.

These are storage-node composition boundaries for receipt-backed repair;
replacement-node orchestration, cluster-state convergence, degraded-read
routing, and reclaim completion remain separate #18 work.

### Local-Only Operations (LOCAL-ONLY boundary)

Inbound replication messages from peer storage nodes MUST use local-only
store operations to prevent re-replication loops. These write directly
to the primary store without triggering fan-out to remote replicas.

- `TransportReplicatedStore::put_local()` / `delete_local()` / `get_local()`
  primary-only writes; never produce network replication.
- `ReplicatedObjectStore::put_named()` / `get_named()` / `delete_named()`
  the local path-backed store has no network replicas; these are
  already local-only.

**Guard**: Client-facing Frame ops (`handle_frame_ctx`) use
`*_named()` methods (with fan-out for TransportBacked). Peer
ReplicationMessage ops (`serve_one`) use `*_local()` methods
(no fan-out). These two code paths must not be mixed. The LOCAL-ONLY
boundary is enforced by code structure at
`server.rs` lines 717-810 (ReplicationMessage) and
lines 960-1025 (Frame handler).
