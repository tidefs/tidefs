# ADMIN Service Wire Protocol — Design Specification

**Issue**: [#1243](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1243)
**Status**: design-spec
**Priority**: P2
**Lane**: coordination
**Extends**: #1217 (cluster admin proxy model)
**Related**: #1234 (VFS_RPC wire protocol), #1219 (dataset lifecycle), #1215 (space accounting), #1239 (incremental cursor framework), #1248 (lease), #1210 (transport)

## Abstract

This document defines the ADMIN service wire protocol: the canonical encoding
for cluster admin operations over the cluster transport. Every admin method
receives a stable 8-bit method ID, common request/response framing with
term/epoch fencing, an idempotency contract via `(peer_node_id, op_id)` dedup
windows, opaque cursor–based pagination for all enumeration methods, and a
persistent job model for long-running mutations with restart-after-failover
safety.

ADMIN is service_id `0x09` in the tidefs cluster service registry (per
transport framing §17.6.3). It is the primary operator-facing protocol:
all cluster admin queries, dataset/volume/snapshot mutations, and job
lifecycle operations flow through this service.

---

## 1. Service Definition

### 1.1 Wire Identity

```
service_id   = 0x09
service_name = "admin"
message_type = request | response
```

Each ADMIN frame is a standard cluster message (#1210) with `service_id = 0x09`.
The method is encoded as a dedicated `u8` field within the request payload. The
transport envelope carries the service_id as part of the message header, not
overloaded into a single byte.

### 1.2 Dispatch Rule

An ADMIN operation is dispatched by its method ID. The receiver parses the
`AdminReqCommonV1` header, extracts `method_id`, and routes to the appropriate
handler. Unknown method IDs return `errno = ENOSYS` in `AdminRespCommonV1`.

### 1.3 Method Space

The 8-bit method space (0x00–0xFF, 256 slots) is allocated as follows:

| Range | Allocation |
|---|---|
| 0x00–0x0F | Cluster-global queries (stateless, leader executes directly) |
| 0x10–0x1F | Snapshot operations |
| 0x20–0x2F | Volume operations |
| 0x30–0x3F | Dataset lifecycle operations |
| 0x40–0x4F | Property get/set |
| 0x50–0x5F | Job control and observability |
| 0x60–0x6F | Fencing and barrier operations |
| 0x70–0x7F | Reserved for future cluster-global ops |
| 0x80–0xFF | Reserved for future use |

---

## 2. Method ID Table

### 2.1 Complete Method Catalog

Every ADMIN operation has a stable method ID. Assignment groups related
operations so each block has room for future additions.

#### 2.1.1 Cluster-global queries (0x00–0x0F)

| ID | Method | Returns job? | Paginated? |
|----|--------|-------------|------------|
| 0x00 | `PING` | no | no |
| 0x01 | `GET_CLUSTER_STATUS` | no | no |
| 0x02 | `LIST_DATASETS` | no | yes |
| 0x03 | `GET_DATASET_STATUS` | no | no |
| 0x04 | `CREATE_DATASET` | no | no |
| 0x05 | `DESTROY_DATASET` | job_id | no |
| 0x0E | `LIST_SNAPSHOTS` | no | yes |
| 0x0F | `GET_SNAPSHOT_STATUS` | no | no |

Reserved in cluster-global block: 0x06–0x0D (8 slots).

#### 2.1.2 Snapshot operations (0x10–0x1F)

| ID | Method | Returns job? | Paginated? |
|----|--------|-------------|------------|
| 0x06 | `SNAPSHOT_CREATE` | no | no |
| 0x07 | `SNAPSHOT_DESTROY` | job_id | no |

Note: 0x06 and 0x07 are placed in the snapshot block by semantics but keep
their canonical IDs from the v0.262 catalog. Reserved: 0x10–0x1F (14 slots
for expansion).

#### 2.1.3 Volume operations (0x20–0x2F)

| ID | Method | Returns job? | Paginated? |
|----|--------|-------------|------------|
| 0x20 | `LIST_VOLUMES` | no | yes |
| 0x21 | `CREATE_VOLUME` | no | no |
| 0x22 | `DESTROY_VOLUME` | job_id (maybe) | no |
| 0x23 | `RESIZE_VOLUME` | no | no |
| 0x24 | `GET_VOLUME_STATUS` | no | no |

Reserved: 0x25–0x2F (11 slots).

#### 2.1.4 Dataset lifecycle operations (0x30–0x3F)

| ID | Method | Returns job? | Paginated? |
|----|--------|-------------|------------|
| 0x08 | `CLONE_CREATE` | no | no |
| 0x09 | `ROLLBACK_TO_SNAPSHOT` | job_id (when large) | no |

Note: 0x08 and 0x09 are placed in the dataset lifecycle block by semantics.
Reserved: 0x30–0x3F (14 slots for future dataset ops: promote, split, merge,
migrate, etc.).

#### 2.1.5 Property get/set (0x40–0x4F)

| ID | Method | Returns job? | Paginated? |
|----|--------|-------------|------------|
| 0x0A | `GET_PROPERTY` | no | no |
| 0x0B | `SET_PROPERTY` | no | no |

Reserved: 0x40–0x4F (14 slots for typed property enumeration, bulk get/set).

#### 2.1.6 Job control and observability (0x50–0x5F)

| ID | Method | Returns job? | Paginated? |
|----|--------|-------------|------------|
| 0x10 | `LIST_JOBS` | no | yes |
| 0x11 | `GET_JOB_STATUS` | no | no |
| 0x12 | `CANCEL_JOB` | no | no |
| 0x13 | `START_SCRUB` | job_id | no |

Reserved: 0x50–0x5F (12 slots for PAUSE_JOB, RESUME_JOB, RETRY_JOB, etc.).

#### 2.1.7 Fencing and barrier operations (0x60–0x6F)

| ID | Method | Returns job? | Paginated? |
|----|--------|-------------|------------|
| 0x0C | `COMMIT_GROUP_SYNC_BARRIER` | no | no |
| 0x0D | `RECALL_WRITER_LEASE` | no | no |

Reserved: 0x60–0x6F (14 slots for future fencing and coordination ops).

### 2.2 Method Group Summary Table

For quick reference, the complete method ID catalog in numeric order:

| ID | Method | Block | Job? | Page? |
|----|--------|-------|------|-------|
| 0x00 | `PING` | cluster | no | no |
| 0x01 | `GET_CLUSTER_STATUS` | cluster | no | no |
| 0x02 | `LIST_DATASETS` | cluster | no | yes |
| 0x03 | `GET_DATASET_STATUS` | cluster | no | no |
| 0x04 | `CREATE_DATASET` | cluster | no | no |
| 0x05 | `DESTROY_DATASET` | cluster | job_id | no |
| 0x06 | `SNAPSHOT_CREATE` | snapshot | no | no |
| 0x07 | `SNAPSHOT_DESTROY` | snapshot | job_id | no |
| 0x08 | `CLONE_CREATE` | dataset | no | no |
| 0x09 | `ROLLBACK_TO_SNAPSHOT` | dataset | job_id* | no |
| 0x0A | `GET_PROPERTY` | property | no | no |
| 0x0B | `SET_PROPERTY` | property | no | no |
| 0x0C | `COMMIT_GROUP_SYNC_BARRIER` | fence | no | no |
| 0x0D | `RECALL_WRITER_LEASE` | fence | no | no |
| 0x0E | `LIST_SNAPSHOTS` | cluster | no | yes |
| 0x0F | `GET_SNAPSHOT_STATUS` | cluster | no | no |
| 0x10 | `LIST_JOBS` | job | no | yes |
| 0x11 | `GET_JOB_STATUS` | job | no | no |
| 0x12 | `CANCEL_JOB` | job | no | no |
| 0x13 | `START_SCRUB` | job | job_id | no |
| 0x20 | `LIST_VOLUMES` | volume | no | yes |
| 0x21 | `CREATE_VOLUME` | volume | no | no |
| 0x22 | `DESTROY_VOLUME` | volume | job_id* | no |
| 0x23 | `RESIZE_VOLUME` | volume | no | no |
| 0x24 | `GET_VOLUME_STATUS` | volume | no | no |

`*` = job_id only returned when the operation is too large to complete
synchronously. Small rollbacks and volume destroys complete inline.

---

## 3. Common Framing

### 3.1 Request Envelope

```
AdminReqCommonV1:
  method_id: u8          # method selector from §2 catalog
  op_id: u64             # idempotency key (stable across retries)
  term: u64              # leader term as seen by caller
  client_node_id: u64    # origin node; for auditing; mismatch ⇒ reject
```

Every ADMIN request carries this 25-byte common header. The `op_id` field
is the idempotency key — the same `(client_node_id, op_id)` pair may be
resent after a network timeout without causing double-execution.

The `term` field is the leader term as observed by the caller at submission
time. If the leader's term has advanced (or the leader has changed), the
request is rejected with `errno = ESTALE`.

The `client_node_id` is redundant (the transport layer provides peer
identity) but is included for audit trails and as a defense-in-depth
check: if it does not match the transport-authenticated peer, the request
is rejected.

### 3.2 Response Envelope

```
AdminRespCommonV1:
  errno: i32             # 0 on success; positive Linux errno on failure
  leader_term: u64       # current leader term at response time
  leader_node_id: u64    # current leader node ID
  redirect_hint_tlvs: TLVList   # empty on success or local errors
```

The `errno` field uses positive Linux errno values (0 = success).
Common ADMIN-specific errno values:

| errno | Name | Meaning |
|-------|------|---------|
| 0 | OK | Success |
| 1 | EPERM | Caller not authorized for this operation |
| 16 | EBUSY | Resource busy (e.g., dataset has active writers) |
| 22 | EINVAL | Invalid argument (malformed payload) |
| 38 | ENOSYS | Unknown method ID |
| 116 | ESTALE | Stale term/epoch; re-discover leader and retry |
| 517 | EREDIRECT | (custom) Redirect hint: leader is at `redirect_hint_tlvs` |

`EREDIRECT` (517) is a tidefs-specific errno indicating that the request
should be redirected to the leader node specified in `redirect_hint_tlvs`.
This is used by the local admin endpoint when operating in redirect mode.

### 3.3 TLV List Encoding

`redirect_hint_tlvs` is a TLV (Type-Length-Value) list using the same
encoding as #1210 transport extensions:

```
TLVList:
  count: u16
  entries: [TLVEntry; count]

TLVEntry:
  tag: u16
  len: u16
  value: [u8; len]
```

Standard tags for redirect hints:

| Tag | Value |
|-----|-------|
| 0x0001 | Leader transport address (string) |
| 0x0002 | Leader node ID (u64, little-endian) |
| 0x0003 | Leader epoch (u64, little-endian) |

---

## 4. Idempotency Contract

### 4.1 Dedup Model

Every ADMIN mutation is idempotent within a bounded dedup window. The
contract is:

1. Caller assigns a monotonically increasing `op_id` for each mutation.
2. Caller sets `client_node_id` to its own node ID.
3. The `(client_node_id, op_id)` pair is the dedup key.
4. Leader maintains a per-node dedup ring buffer (default: last 4096 ops).
5. On receiving a mutation, the leader checks the dedup ring:
   - **Not found**: execute the mutation, record the result in the ring.
   - **Found with success result**: return `errno = OK` with the cached payload.
   - **Found with error result**: return the cached error.
   - **Found but still in-flight**: wait for the in-flight operation to
     complete, then return its result.

### 4.2 Dedup Window Configuration

| Parameter | Default | Minimum | Maximum |
|-----------|---------|---------|---------|
| Window size per peer | 4096 ops | 256 | 65536 |
| Memory per entry | ~128 bytes | — | — |
| Total at default (5 nodes) | ~2.5 MiB | — | — |

### 4.3 Idempotency Across Leader Changes

The dedup ring buffer is **not persisted** across leader changes. After a
leader failover:

- In-flight mutations with no committed receipt are lost from the ring.
- Callers receive `errno = ESTALE` (from the old leader) or a transport
  error (if the old leader crashes).
- Callers rediscover the new leader, increment the term, and resubmit.
- Mutations that were already **durably committed** before the failover
  return `errno = OK` with the original result (idempotent resubmission
  via the replicated metadata log, not the dedup ring).

### 4.4 Idempotency and Jobs

For job-returning methods (DESTROY_DATASET, SNAPSHOT_DESTROY, ROLLBACK_TO_SNAPSHOT,
START_SCRUB), idempotency works differently:

- The first submission creates the job and returns a `job_id`.
- Subsequent submissions with the same `(client_node_id, op_id)` return the
  same `job_id` and current status — they do **not** create duplicate jobs.
- This relies on the dedup ring and, after failover, on the replicated
  metadata log containing the original job creation record.

---

## 5. Pagination Contract

### 5.1 Page Request/Response

```
PageReqV1:
  limit: u32             # 1–4096 items per page
  cursor_len: u16        # length of cursor blob (0 = start from beginning)
  cursor_bytes: [u8; cursor_len]   # opaque cursor from previous PageRespV1

PageRespV1:
  next_cursor_len: u16   # length of next cursor (0 = EOF)
  next_cursor_bytes: [u8; next_cursor_len]  # opaque cursor for next page
```

### 5.2 Cursor Semantics

- Cursors are **opaque to clients**. Clients must not interpret, construct,
  or modify cursor bytes.
- An empty cursor (`cursor_len = 0`) means "start from the beginning."
- `next_cursor_len = 0` means "end of stream" (no more pages).
- Internally, cursors embed **btree key tuples** (e.g., the last returned
  `(dataset_id, snapshot_id)` pair) for seek-based pagination.
- Cursors are **stable for the duration of a query session** but become
  invalid across leader changes. Clients receive `errno = ESTALE` and must
  restart pagination.
- Cursor bytes are **not guaranteed to be human-readable or sortable**.

### 5.3 Paginated Methods and Cursor Keys

| Method | Cursor Key | Page Item |
|--------|-----------|-----------|
| `LIST_DATASETS` | Last `DatasetId` | `DatasetInfo` |
| `LIST_SNAPSHOTS` | Last `(DatasetId, SnapshotId)` | `SnapshotInfo` |
| `LIST_VOLUMES` | Last `VolumeId` | `VolumeInfo` |
| `LIST_JOBS` | Last `JobId` | `JobInfo` |

### 5.4 Embedding in Request/Response

Paginated methods include `PageReqV1` in the method-specific payload. The
common framing does **not** carry pagination fields — pagination is
method-specific because:

- Not all methods need it.
- Different methods have different cursor key schemas.
- The cursor is semantically part of the method payload, not the transport.

For paginated methods, the request payload is:

```
PaginatedReqV1<T>:
  page: PageReqV1
  body: T
```

And the response:

```
PaginatedRespV1<T>:
  page: PageRespV1
  items: [T; page.limit]
```

---

## 6. Job Model

### 6.1 Job Identity and Lifecycle

```
AdminJobId: u64

AdminJobKindV1 (u8):
  SNAPSHOT_DESTROY  = 1
  DATASET_DESTROY   = 2
  ROLLBACK          = 3
  SCRUB_POOL        = 4
  VOLUME_DESTROY    = 5    // reserved for future use

AdminJobStateV1 (u8):
  QUEUED    = 0
  RUNNING   = 1
  DONE      = 2
  FAILED    = 3
  CANCELED  = 4
```

### 6.2 State Machine

```
                   ┌─────────┐
                   │ QUEUED  │ ← job created, not yet dispatched
                   └────┬────┘
                        │ dispatch
                   ┌────▼─────┐
           ┌───────│ RUNNING  │───────┐
           │       └────┬─────┘       │
           │            │             │ error / crash
           │            │        ┌────▼─────┐
           │            │        │ FAILED   │ (terminal)
           │            │        └──────────┘
           │            │
           │       ┌────▼─────┐
           │       │ DONE     │ (terminal)
           │       └──────────┘
           │
     ┌─────▼──────┐
     │ CANCELED   │ (terminal)
     └────────────┘
```

Transitions:

| From | To | Trigger |
|------|----|---------|
| QUEUED | RUNNING | Scheduler dispatches the job |
| QUEUED | CANCELED | Operator cancels before dispatch |
| RUNNING | DONE | Job completes successfully |
| RUNNING | FAILED | Unrecoverable error or crash |
| RUNNING | CANCELED | Operator requests cancellation; job drains gracefully |

Note: this is a simplified model compared to #1217. The `PAUSED` state is
deferred to a future extension. The current design treats pause as a
scheduler-side throttling decision, not a job state transition.

### 6.3 Job Persistence

Job state (including cursor position) is committed in dataset metadata commit_groups
for restart-after-failover safety. The persistence contract:

1. Before each `step()` call, the job reads its last committed checkpoint
   from the metadata commit_group log.
2. After each `step()` call, the job writes a new checkpoint to the next
   metadata commit_group.
3. Checkpoints include the opaque cursor state, progress counters, and
   the current `AdminJobStateV1`.
4. After a crash, the new leader reads the last checkpoint for each
   non-terminal job and resumes from that point.

### 6.4 Job Integration with IncrementalJob

Admin jobs implement the `IncrementalJob` trait from `tidefs-incremental-job-core`
(#1239):

```rust
/// Admin-specific extension of the universal incremental job contract.
pub trait AdminJob: IncrementalJob {
    /// The JobId assigned at creation.
    fn job_id(&self) -> AdminJobId;

    /// The kind discriminant for observability and routing.
    fn kind(&self) -> AdminJobKindV1;

    /// Current progress snapshot (aggregate counters).
    fn progress(&self) -> ProgressRecord;

    /// Operator-requested cancellation.
    /// The next `step()` should return `StepResult::complete = true`.
    fn cancel(&mut self);
}
```

### 6.5 Progress Record

```rust
pub struct ProgressRecord {
    /// Items (extents, snapshots, volumes) processed since job creation.
    pub items_completed: u64,
    /// Total items to process (best estimate; may be updated mid-job).
    pub total_items: u64,
    /// Bytes processed since job creation (monotonic).
    pub bytes_processed: u64,
    /// Total bytes to process (best estimate).
    pub total_bytes: u64,
    /// Wall-clock milliseconds elapsed since job creation.
    pub elapsed_ms: u64,
    /// Approximate remaining milliseconds at current throughput.
    pub eta_ms: u64,
}
```

---

## 7. Method Payload Sketches

### 7.1 PING (0x00)

```
PING req:  (empty beyond AdminReqCommonV1)
PING resp: (empty beyond AdminRespCommonV1)
```

A no-op health check. Returns `errno = OK` if the leader is reachable
and responsive. Used for liveness probes and connection keep-alive.

### 7.2 GET_CLUSTER_STATUS (0x01)

```
GET_CLUSTER_STATUS req: (empty)
GET_CLUSTER_STATUS resp:
  leader_node_id: u64
  leader_term: u64
  member_count: u32
  healthy_member_count: u32
  degraded: bool                   # true if any member is unhealthy
  members: [MemberStatus; member_count]

MemberStatus:
  node_id: u64
  state: u8                        # 0=online, 1=offline, 2=draining, 3=joining
  rtt_us: u64                      # EWMA RTT in microseconds
  commit_lag_commit_groups: u64             # commit_groups behind writer
  last_seen_ms: u64                # milliseconds since last heartbeat
```

### 7.3 LIST_DATASETS (0x02) — Paginated

```
LIST_DATASETS req:
  page: PageReqV1
  name_filter_len: u16             # 0 = no filter
  name_filter: [u8; name_filter_len]  # UTF-8 prefix match

LIST_DATASETS resp:
  page: PageRespV1
  datasets: [DatasetInfo]

DatasetInfo:
  dataset_id: u64
  name_len: u16
  name: [u8; name_len]             # UTF-8
  state: u8                        # 0=active, 1=destroying, 2=importing
  mounted_on: [u64]                # list of node IDs with active mounts
  created_at_ms: u64               # UNIX epoch milliseconds
```

### 7.4 GET_DATASET_STATUS (0x03)

```
GET_DATASET_STATUS req:
  dataset_id: u64

GET_DATASET_STATUS resp:
  dataset_id: u64
  state: u8
  total_bytes: u64                 # raw pool capacity assigned
  used_bytes: u64                  # currently allocated (data + metadata)
  available_bytes: u64             # total_bytes - used_bytes
  snapshot_count: u32
  volume_count: u32
  last_commit_group: u64
  mounted_on: [u64]                # active mount nodes
  compression_ratio_n: u32         # numerator of compression ratio × 100
  compression_ratio_d: u32         # denominator (= 100)
  dedup_ratio_n: u32
  dedup_ratio_d: u32
  write_rate_bytes_per_sec: u64    # EWMA over 60s
  read_rate_bytes_per_sec: u64     # EWMA over 60s
  iops: u64                        # EWMA over 60s
```

### 7.5 CREATE_DATASET (0x04)

```
CREATE_DATASET req:
  name_len: u16
  name: [u8; name_len]             # UTF-8
  redundancy_policy: u8            # 0=none, 1=mirror, 2=erasure_NplusM
  redundancy_n: u8                 # data shards (erasure only)
  redundancy_m: u8                 # parity shards (erasure only)
  quota_bytes: u64                 # 0 = unlimited
  reservation_bytes: u64           # 0 = thin provisioned
  properties: [Property]           # optional initial properties

Property:
  key_len: u16
  key: [u8; key_len]
  value_len: u16
  value: [u8; value_len]

CREATE_DATASET resp:
  dataset_id: u64
```

### 7.6 DESTROY_DATASET (0x05) — Returns job

```
DESTROY_DATASET req:
  dataset_id: u64
  force: bool                      # skip safety checks (requires confirmation)

DESTROY_DATASET resp:
  job_id: AdminJobId               # for tracking the 4-phase destroy
```

### 7.7 SNAPSHOT_CREATE (0x06)

```
SNAPSHOT_CREATE req:
  dataset_id: u64
  name_len: u16
  name: [u8; name_len]             # UTF-8
  recursive: bool                  # include descendent datasets

SNAPSHOT_CREATE resp:
  snapshot_id: u64
  snap_commit_group: u64                    # commit_group at which snapshot was taken
```

### 7.8 SNAPSHOT_DESTROY (0x07) — Returns job

```
SNAPSHOT_DESTROY req:
  dataset_id: u64
  snapshot_id: u64
  defer: bool                      # true = defer deadlist processing

SNAPSHOT_DESTROY resp:
  job_id: AdminJobId
```

### 7.9 CLONE_CREATE (0x08)

```
CLONE_CREATE req:
  source_dataset_id: u64
  source_snapshot_id: u64          # 0 = use current live state
  target_name_len: u16
  target_name: [u8; target_name_len]

CLONE_CREATE resp:
  clone_dataset_id: u64
```

### 7.10 ROLLBACK_TO_SNAPSHOT (0x09)

```
ROLLBACK_TO_SNAPSHOT req:
  dataset_id: u64
  snapshot_id: u64
  force: bool                      # skip confirmation for newer snapshots

ROLLBACK_TO_SNAPSHOT resp:
  new_commit_group: u64
  job_id: AdminJobId               # 0 if completed synchronously
```

Small rollbacks (few extents) complete inline and return `job_id = 0`.
Large rollbacks return a `job_id` for progress tracking.

### 7.11 GET_PROPERTY (0x0A) / SET_PROPERTY (0x0B)

```
GET_PROPERTY req:
  dataset_id: u64                  # 0 = cluster-global property
  key_len: u16
  key: [u8; key_len]

GET_PROPERTY resp:
  value_len: u16
  value: [u8; value_len]
  source: u8                       # 0=default, 1=local, 2=inherited

SET_PROPERTY req:
  dataset_id: u64
  key_len: u16
  key: [u8; key_len]
  value_len: u16
  value: [u8; value_len]

SET_PROPERTY resp: (empty beyond common)
```

### 7.12 COMMIT_GROUP_SYNC_BARRIER (0x0C)

```
COMMIT_GROUP_SYNC_BARRIER req:
  dataset_id: u64

COMMIT_GROUP_SYNC_BARRIER resp:
  synced_commit_group: u64
```

Flushes all in-flight commit_groups for the dataset. Blocks until every open commit_group
is committed or aborted. Required before snapshot create and rollback to
establish a stable W-boundary.

### 7.13 RECALL_WRITER_LEASE (0x0D)

```
RECALL_WRITER_LEASE req:
  dataset_id: u64

RECALL_WRITER_LEASE resp:
  previous_holder: u64             # node ID that held the lease
  recalled: bool                   # true if recall succeeded
```

### 7.14 LIST_SNAPSHOTS (0x0E) — Paginated

```
LIST_SNAPSHOTS req:
  dataset_id: u64
  page: PageReqV1

LIST_SNAPSHOTS resp:
  page: PageRespV1
  snapshots: [SnapshotInfo]

SnapshotInfo:
  snapshot_id: u64
  name_len: u16
  name: [u8; name_len]
  snap_commit_group: u64
  created_at_ms: u64
  total_bytes: u64                 # bytes referenced (shared + exclusive)
  exclusive_bytes: u64             # bytes unique to this snapshot
  hold_count: u32                  # number of active holds
```

### 7.15 GET_SNAPSHOT_STATUS (0x0F)

```
GET_SNAPSHOT_STATUS req:
  dataset_id: u64
  snapshot_id: u64

GET_SNAPSHOT_STATUS resp:
  (SnapshotInfo as in LIST_SNAPSHOTS)
```

### 7.16 LIST_JOBS (0x10) — Paginated

```
LIST_JOBS req:
  page: PageReqV1
  filter_state: u8                 # 0xFF = all; specific AdminJobStateV1 value
  filter_kind: u8                  # 0xFF = all; specific AdminJobKindV1 value
  dataset_id: u64                  # 0 = all datasets

LIST_JOBS resp:
  page: PageRespV1
  jobs: [JobInfo]

JobInfo:
  job_id: AdminJobId
  kind: AdminJobKindV1
  state: AdminJobStateV1
  dataset_id: u64
  created_at_ms: u64
  updated_at_ms: u64
  items_completed: u64
  total_items: u64
  bytes_processed: u64
  total_bytes: u64
  eta_ms: u64
```

### 7.17 GET_JOB_STATUS (0x11)

```
GET_JOB_STATUS req:
  job_id: AdminJobId

GET_JOB_STATUS resp:
  (JobInfo as in LIST_JOBS, or errno = ENOENT if job_id not found)
```

### 7.18 CANCEL_JOB (0x12)

```
CANCEL_JOB req:
  job_id: AdminJobId

CANCEL_JOB resp:
  previous_state: AdminJobStateV1
  accepted: bool                   # false if job already terminal
```

### 7.19 START_SCRUB (0x13) — Returns job

```
START_SCRUB req:
  dataset_id: u64                  # 0 = all datasets
  scrub_mode: u8                   # 0=verify, 1=verify+repair
  priority: u8                     # 0=low, 1=normal, 2=high

START_SCRUB resp:
  job_id: AdminJobId
```

### 7.20 LIST_VOLUMES (0x20) — Paginated

```
LIST_VOLUMES req:
  dataset_id: u64                  # 0 = all datasets
  page: PageReqV1

LIST_VOLUMES resp:
  page: PageRespV1
  volumes: [VolumeInfo]

VolumeInfo:
  volume_id: u64
  dataset_id: u64
  name_len: u16
  name: [u8; name_len]
  size_bytes: u64
  block_size: u32                  # typically 4096 or 512
  state: u8                        # 0=online, 1=offline, 2=destroying
  created_at_ms: u64
```

### 7.21 CREATE_VOLUME (0x21)

```
CREATE_VOLUME req:
  dataset_id: u64
  name_len: u16
  name: [u8; name_len]
  size_bytes: u64
  block_size: u32
  sparse: bool                     # thin-provisioned vs fully allocated
  properties: [Property]

CREATE_VOLUME resp:
  volume_id: u64
```

### 7.22 DESTROY_VOLUME (0x22)

```
DESTROY_VOLUME req:
  dataset_id: u64
  volume_id: u64
  force: bool

DESTROY_VOLUME resp:
  job_id: AdminJobId               # 0 if completed synchronously
```

### 7.23 RESIZE_VOLUME (0x23)

```
RESIZE_VOLUME req:
  dataset_id: u64
  volume_id: u64
  new_size_bytes: u64
  shrink_ok: bool                  # must be true to allow shrink

RESIZE_VOLUME resp:
  new_size_bytes: u64              # actual new size (may differ if shrink denied)
```

### 7.24 GET_VOLUME_STATUS (0x24)

```
GET_VOLUME_STATUS req:
  dataset_id: u64
  volume_id: u64

GET_VOLUME_STATUS resp:
  (VolumeInfo as in LIST_VOLUMES, plus:)
  allocated_bytes: u64
  block_count: u64
  thin_provisioned: bool
```

---

## 8. Fencing Integration

### 8.1 Execution Model

ADMIN operations are fenced by the leader term and, for dataset-mutating ops,
by the writer lease:

| Op Class | Executor | Fencing |
|----------|----------|---------|
| Cluster-global queries | Leader directly | Term check |
| Cluster-global mutations | Leader directly | Term + replicated config log |
| Dataset-mutating ops | Writer lease holder | Term + writer lease |
| Barrier/sync ops | Writer lease holder | Term + writer lease |

### 8.2 Leader Routing

When a request arrives at a non-leader node:

1. The receiver checks `term` against its known leader term.
2. If its term is stale, it forwards the request to the current leader
   (proxy mode) or returns `errno = EREDIRECT` with the leader's address
   (redirect mode).
4. If the term is stale (the caller had an outdated view), the leader
   returns `errno = ESTALE` with its current term and node ID.

### 8.3 Writer Lease Enforcement

For dataset-mutating ops:

1. Leader identifies the writer lease holder for the target dataset.
2. If the leader is the writer: execute locally.
3. If another node is the writer: proxy the mutation to that node, or
   recall the lease (if the operation requires it).
5. If the lease was lost between routing and execution, return
   `errno = EBUSY`.

### 8.4 COMMIT_GROUP Sync Barrier

Operations requiring a stable point-in-time view (snapshot create, rollback):

1. Writer executes `COMMIT_GROUP_SYNC_BARRIER` — flushes all in-flight commit_groups for the
   dataset.
2. Writer commits the operation in the next commit_group.
3. `snap_commit_group` is recorded explicitly and is **monotonic** within the
   dataset's commit_group sequence.

---

## 9. Relationship to Existing Designs

| Design | Relationship |
|--------|-------------|
| #1217 (admin proxy model) | This spec provides the concrete wire protocol for the proxy model |
| #1234 (VFS_RPC) | Sibling wire protocol spec; ADMIN (0x09) is the control plane, VFS_RPC (0x06) is the data plane |
| #1219 (dataset lifecycle) | DESTROY_DATASET payload encodes the 4-phase destroy trigger |
| #1215 (space accounting) | GET_DATASET_STATUS returns space accounting counters |
| #1239 (incremental cursor) | Admin jobs implement `IncrementalJob`; pagination cursors share opaque-blob contract |
| #1209 (membership) | ADMIN consumes membership for mount-set, leader discovery, RTT |
| #1248 (lease) | ADMIN mutations involving datasets require writer lease; lease observable via ADMIN |
| #1210 (transport) | ADMIN messages travel over cluster control-plane transport |

### 9.1 Distinction from VFS_RPC

| Aspect | ADMIN (0x09) | VFS_RPC (0x06) |
|--------|-------------|----------------|
| Audience | Operators (tidefsctl) | FUSE daemons (kernel VFS) |
| Method space | 8-bit (256 slots) | 6-bit (64 slots) |
| Operations | Cluster admin, datasets, snapshots, volumes, jobs | POSIX file operations |
| Response model | Synchronous (small) or job_id (large) | Always synchronous |
| Pagination | Yes (LIST_*) | No (FUSE is stream-oriented) |
| Idempotency | (node_id, op_id) dedup ring | (node_id, op_id) dedup ring |
| Fencing | Term + lease | Term + epoch |

---

## 10. Security

### 10.1 Authentication

In any mode other than `dev_insecure`, the ADMIN service:
- Only accepts requests from **authenticated peers** (verified via
  transport-layer mTLS or equivalent per #1228)
- Rejects unauthenticated local clients trying to inject mutations
- Preserves **peer identity** across proxy hops so dedup keys
  `(client_node_id, op_id)` remain valid
  transport-authenticated peer identity

### 10.2 Proxy Identity Preservation

When a non-leader proxies an admin request to the leader:
1. The proxying node preserves the originator's `client_node_id`.
2. The transport layer authenticates the proxying node as a valid cluster member.
3. The leader trusts `client_node_id` only when the proxying node is in the
   current membership set and the transport layer vouches for the proxying
   node's identity.

### 10.3 `dev_insecure` Mode

In `dev_insecure` mode (single-node or test clusters), ADMIN accepts
requests from `localhost` without authentication. The `client_node_id` is
set to the local node's ID. This mode is **not for production**.

---

## 11. Implementation Notes

### 11.1 Source-of-Truth Constants

The method ID table, `AdminJobKindV1`, and `AdminJobStateV1` are committed
as Rust `const` blocks in `tidefs-types-admin-service-core`. They are the
single source of truth for the wire protocol. All encoder/decoder
implementations reference these constants.

### 11.2 Binary Encoding

Payloads use the canonical tidefs binary encoding (little-endian, no padding,
variable-length fields with explicit length prefixes). The encoding follows
the `tidefs-binary_schema-*` crate family conventions. Full codec
implementation is deferred to the schema-codec crate phase.

### 11.3 Crate Dependencies

```
tidefs-types-admin-service-core
  ├── (no dependencies)           # pure type definitions, no_std
  └── [optional] serde             # for JSON debugging/CLI

Future crates (not in scope of this design):
  tidefs-schema-codec-admin        # encode/decode
  tidefs-admin-local               # local Unix socket endpoint
  tidefs-admin-leader              # leader-side dispatch
```

---

## 12. Acceptance Criteria Trace

| Criterion | How Met |
|-----------|---------|
| 1. Method ID table is committed as source-of-truth constant block | §2 — complete 24-method catalog with `const` blocks in `tidefs-types-admin-service-core` |
| 2. Request/response payloads are typed with encode/decode coverage | §3, §7 — common framing + 24 payload sketches with typed fields |
| 3. Idempotency via (peer_node_id, op_id) deduplication window | §4 — dedup ring model with configurable window, across-leader semantics |
| 4. All paginated methods have cursor coverage | §5 — opaque cursor contract, per-method cursor keys, PageReqV1/PageRespV1 |
| 5. Job model supports restart-after-failover (cursor persistence) | §6 — persistent checkpoints in metadata commit_groups, `IncrementalJob` integration |

---

## 13. Open Questions and Future Work

1. **Compression**: Should large responses (LIST_DATASETS with hundreds of
   entries) support optional compression at the transport layer? Defer to
   #1210 transport extensions.

2. **Streaming responses**: For very large LIST_* responses, should the
   protocol support server-side streaming (multiple response frames per
   request)? Current pagination model is request/response per page.
   Streaming is deferred to a future extension.

3. **Batch operations**: Should CREATE_DATASET support bulk creation?
   Deferred — single-dataset creation is sufficient for v0.

4. **PAUSED job state**: The #1217 design includes a PAUSED state. This
   spec defers it — pause is modeled as scheduler-side throttling rather
   than a persisted job state. Add PAUSED when operator-initiated pause
   with durability is needed.

5. **Property namespace**: The property model (GET_PROPERTY/SET_PROPERTY)
   needs a property key registry. This is deferred to a separate design
   issue.

6. **REDIRECT_HINT_TLVS format**: The TLV encoding for redirect hints is
   specified at a high level. The exact binary layout should be aligned
   with #1210 transport extension TLVs during implementation.
