# tidefs-storage-node

Networked storage node daemon: bridges `tidefs-transport` with
`tidefs-replicated-object-store` and provides a unified runtime
authority spine that discloses the active transport backend to
all subsystems. This is storage-node runtime evidence, not final
distributed operator UAPI.

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

- **Live backends** (TCP, RDMA): opens a `TransportReplicatedStore` backed
  by a local `LocalObjectStore` primary plus remote replicas connected via
  per-endpoint-family sessions (Control/Data/Shadow). `RuntimeAuthority`'
  s `replication_factor()` drives `write_quorum` and `total_replicas`
  in the `TransportReplicatedStoreConfig`. Membership peers are connected
  as replicas. When no membership peers are configured, a warning is
  emitted. This proves which backend the daemon selected; it is not a
  distributed operator-maturity claim by itself.

- **Non-live backends** (Loopback, DeterministicInMemory, NotRun, or
  no authority): opens a local path-backed `ReplicatedObjectStore` using
  `ReplicatedStoreConfig`. This is the explicit single-node/harness path
  and is not presented as live multi-node storage validation.

- **Backend disclosure** appears in every `StatsResponse` and
  `HealthCheckResponse`, recording whether the backend is RDMA, TCP,
  loopback, deterministic-in-memory, or not-run.

### Construction Sequence

1. Backend disclosure: the CLI `--rdma` flag plus bind address, or the
   equivalent JSON config fields, produce a `BackendDisclosure` (RDMA, TCP,
   Loopback, DeterministicInMemory, or NotRun).
2. `RuntimeAuthority::build()` validates the disclosure, derives a
   `TransportConfig`, and stores node parameters (member class,
   failure domain, replication factor).
3. The authority spine is logged at startup. Downstream subsystems
   query `authority.backend()`, `authority.transport_config()`,
   and `authority.is_live()` instead of inspecting raw CLI flags.

### BackendDisclosure Variants

| Variant | Description | `is_live()` |
|---|---|---|
| `Rdma(addr)` | RDMA transport with device/address string | true |
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
default to 1 and set the configured replication factor stored in the authority
spine. This value is available to replication and placement subsystems at
initialization time.

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
SegmentFetchRequest dispatch, the loop attempts bincode
deserialization for `tidefs_transport::ReplicationMessage`.

### Handled Variants

| Message | Action |
|---|---|
| `Put { name, payload }` | Writes to local primary store (no fan-out); responds `Ack` |
| `Get { name }` | Reads from local primary store; responds `GetResponse` |
| `Delete { name, generation }` | Deletes from local primary store; responds `DeleteAck` |
| `SyncRequest` | Lists exact object payloads; responds `SyncResponse` entries with `PlacementReceiptRef` authority when the backend exposes pool receipts |
| `ReadPlan { plan_bytes }` | Serves the planned subject locally; pool-backed responses carry a validated `PlacementReceiptRef`, while receiptless backends stay receipt-less |
| `ScrubRequest` | Runs local segment scrub and reports findings plus receipt-inventory disclosure |
| `RepairObject { key, placement_receipt_ref, authoritative_payload }` | Validates the shared placement receipt against the exact 32-byte object key, length, digest, policy, and target width before local repair write; pool-backed repairs respond with a fresh repaired `PlacementReceiptRef` |

Pool-backed scrub reports include `placement_receipt_refs`,
`rebuild_admission`, `rebuild_planner`, and `rebuild_execution_candidates`
previews. All three previews are built from the same real `PlacementReceiptRef`
values: admission runs them through `tidefs-rebuild-runtime`, the planner
preview feeds the live receipt inventory into
`tidefs-rebuild-planner::plan_reconstruction()` with the local node as the
healthy source and configured peers as replacement targets, and execution
candidates are listed only when admission and planner agree on the receipt,
source, target, payload length, and digest. This keeps later distributed
rebuild orchestration tied to receipt-addressed tasks instead of deriving
placement from current topology or receiptless store listings. Local
path-backed and transport-backed receiptless stores report the rebuild
previews as unavailable because they do not expose pool placement receipt
inventory.

Pool-backed `SyncResponse` entries likewise carry the real non-synthetic
`PlacementReceiptRef` for the payload being transferred. Local path-backed and
transport-backed receiptless stores keep sync entries receipt-less rather
than synthesizing placement authority.

Pool-backed `ReadPlanResponse` frames carry the same kind of validated
`PlacementReceiptRef`, and `TransportReplicatedStore::get_planned_with_evidence()`
preserves that ref with the returned payload and source member id. This is
planned-read evidence plumbing only: replacement-node orchestration, repaired
placement publication, broader cluster-state publication, and reclaim
publication remain under the distributed receipt-authority work.
Callers that will use planned-read bytes as repair, rebuild, or reclaim
authority must use
`TransportReplicatedStore::get_planned_with_required_receipt()`, which rejects
receipt-less responses and local-primary hits that do not carry
durable placement receipt evidence.

Receipt-backed repair callers can use
`TransportReplicatedStore::execute_receipt_repair_task_and_record_completion()`
to execute `RepairObject` and record rebuild-runtime verified-task completion
in one fail-closed path. The bridge treats `RepairObjectAck` as completion
evidence only when `success` is true and the ack carries a non-synthetic
`repaired_placement_receipt_ref` that passes the rebuild-runtime completion
law; receipt-less, mismatched, or failed acks do not advance completion or
admission state as success. Receiptless acks without a repaired receipt are
accepted as wire-format responses, but they do not advance receipt-backed
rebuild completion. `RebuildCompletion::verified_receipt_completions()` exposes
the successful source/repaired receipt pairs as a typed publication view for
later consumers; it does not publish broader cluster or reclaim state by
itself. The replicated-store repair bridge returns that same typed record in
`ReceiptRepairCompletionEvidence`, and the flow-commit coordinator can publish
the repaired target `PlacementReceiptRef` as `ReplicaPlacementReceipt` /
`FlowCommitResult` rebuild evidence. Callers that own the coordinator can use
`TransportReplicatedStore::execute_receipt_repair_task_record_completion_and_publish_flow_commit()`
to execute the repair, record verified completion, and publish the repaired
placement in one composed path. That is replicated-store-to-flow-commit
publication plumbing only; replacement-node orchestration, cluster-state
convergence, and reclaim publication remain separate #18 work. When the repair
source was selected through the authoritative planned-read path, callers can
use
`TransportReplicatedStore::execute_receipt_repair_task_from_planned_read_and_record_completion()`
or
`TransportReplicatedStore::execute_receipt_repair_task_from_planned_read_record_completion_and_publish_flow_commit()`.
These variants reuse the same target ack, repaired-receipt, completion, and
flow-commit gates, but first require the planned-read source member,
`PlacementReceiptRef`, payload length, and payload digest to match the
scheduled `BackfillTask`. The planned-read bridge still does not perform
replacement orchestration, cluster-wide convergence, degraded-read routing, or
reclaim completion. The cluster placement map can consume the completed
rebuild `FlowCommitResult` through
`PlacementMap::publish_rebuild_flow_commit_result()` and update local
cluster-runtime repaired-placement state after validating subject, target,
epoch, and receipt authority. `PlacementHealCoordinator` and
`ClusterLeaseRuntime` expose the same local publication path through their
owned placement state. These local placement-publication owner boundaries are
still not degraded-read routing, replacement orchestration, cluster-wide
propagation, or reclaim completion.
Storage-node callers that already have the replicated-store repair publication
can use `publish_repair_flow_commit_into_placement_map()` to cross-check the
repair evidence against the flow-commit result before applying that local
placement-map update. Callers that own `ClusterLeaseRuntime` can use
`publish_repair_flow_commit_into_cluster_runtime()` to perform the same
storage-node cross-check and delegate to runtime-owned placement state. After
those repair publications are accepted, the same owner can use
`finalize_cluster_runtime_heal_from_repair_publications()` to derive the
rebuilt-placement evidence required by the runtime's explicit heal
finalization boundary. These are storage-node composition boundaries only; they
still do not publish cluster-wide convergence, degraded-read routing,
replacement orchestration, or reclaim completion.

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
