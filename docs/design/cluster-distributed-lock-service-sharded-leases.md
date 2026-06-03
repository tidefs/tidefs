# Cluster-Wide Distributed Lock Service — Sharded Leases, Inode-Range Lock Forwarding, Multi-Writer Coherency

**Issue**: [#1248](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1248)
**Status**: design-spec
**Priority**: P2
**Lane**: coordination (Layer 9: Coordination)
**Milestone**: DESIGN-M4: Cluster Infrastructure (Layers 8-11)
**Depends on**: #1228 (cluster security/identity model), #1210 (transport boundedness), #1209 (MEMBERSHIP service)
**Blocks**: multi-writer dataset operations, FUSE lock forwarding, cluster mmap coherency

## Abstract

This document defines the Cluster-Wide Distributed Lock Service for TideFS: a
purpose-built LOCK service (service_id = `0x0A`) that replaces
dataset-scoped exclusive writer leases with a three-tier sharded lease
hierarchy: per-directory subtree leases, per-inode lease tokens, and per-inode
byte-range record locks. The service provides acquire/renew/release/recall/break
semantics, fault-tolerant lock state replication via an embedded Raft consensus
group, FUSE lock operation forwarding (flock, fcntl setlk/getlck) from
non-writer nodes, and lease-epoch fencing integrated with the membership layer.

This is the Phase 2+ scalability milestone from the v0.262 design book S17.5:
without it, a single writer per dataset becomes the bottleneck. The design moves
TideFS from coarse-grained dataset-scoped lease locking to fine-grained,
concurrent, multi-writer operation.

---

## 1. Problem Statement

### 1.1 Current baseline (Phase 1)

The current lease model (`tidefs-lease`) provides **dataset-scoped EXCLUSIVE
writer leases**:

- One node holds the exclusive writer lease for a dataset
- All other nodes serve reads only
- Fencing is bound by `(term, epoch)`

This model is correct but creates a scalability ceiling: a single writer per
dataset serializes all mutation traffic. For workloads with disjoint write sets
(e.g., different subdirectories or non-overlapping file byte ranges), the
dataset-scoped exclusive lease forces unnecessary serialization.

### 1.2 Multi-writer requirements

The v0.262 design book S17.5 maps out the path from single-writer to
multi-writer. The cluster must support:

1. **Concurrent subtree writers**: two nodes mutating different directory
   subtrees within the same dataset must not block each other.
2. **Per-inode concurrent access**: shared readers on a hot file while a
   single writer holds the inode lease.
3. **Byte-range concurrent writers**: two writers on non-overlapping byte
   ranges within the same file (POSIX fcntl record locks).
4. **Cross-node lock forwarding**: POSIX fcntl/flock operations arriving at a
   non-writer node must be forwarded to the lock service and resolved correctly.
5. **Blocking lock support**: `F_SETLKW` (blocking record lock) requires
   callback notification when the lock becomes available.
6. **Crash resilience**: lock state must survive daemon restart and leader
   failover.

### 1.3 Service gap

The existing `tidefs-lease` crate provides only coarse-grained domain leases
(`LeaseDomain::EpochTransition`, `ChunkRange`, `Snapshot`,
`MembershipReconfig`, `Transfer`). There is no concept of:

- Directory subtree leases
- Inode-level lease tokens
- Byte-range record locks
- Lock forwarding from non-owner nodes
- Blocking lock wait queues
- Lock state replication for fault tolerance

This design fills all of these gaps.

---

## 2. Scope and Non-Scope

### In scope

- LOCK service wire protocol (service_id = `0x0A`): acquire, renew, release,
  recall, break, getlk, setlk, setlkw
- Three-tier sharded lease hierarchy: directory subtree → inode → byte range
- Lock service replication via embedded Raft consensus group
- FUSE lock operation forwarding from non-writer nodes
- Blocking lock (F_SETLKW) with callback notification
- Lease-epoch fencing integration with membership layer
- Lock state persistence via transaction model (#1222)
- Interaction contracts with VFS_RPC (#1234) for lock forwarding dispatch
  feed (#1208)
- Lock service integration with lane model (#1241): CONTROL lane for
  lock operations

### Explicitly out of scope

- Kernel-side lock state (kernel forwards locks to userspace daemon)
- Mandatory locking (only advisory POSIX record locks)
- OFD (open file description) locks (only traditional process-associated locks)
- Lock service as a separate daemon process (embedded in tidefsd)
- Cross-pool lock coordination (each pool has its own lock service leader)
- Lock service metrics/alerts (delegated to observability #827)
- Per-lock encryption (delegated to transport TLS)
- Lock service in `dev_insecure` mode (requires authenticated peers per #1228;
  only `tcp_mtls`, `psk_hmac`, or `trusted_fabric`)

---

## 3. Architecture Overview

### 3.1 Service identity

```
service_id   = 0x0A
service_name = "lock"
message_type = request | response | event
```

Each LOCK frame is a standard cluster message (#1210) with `service_id = 0x0A`.
The method is encoded in the low 6 bits of the message-type byte. The high 2
bits distinguish request (0b00), response (0b01), and event (0b10 — for
callbacks and recalls).

### 3.2 Lease hierarchy

```
Pool
  Lock Service Group (Raft-replicated)
    Dataset-level Fencing Context (term, epoch)
      Directory Subtree Lease (SHARED / EXCLUSIVE)
        Inode Lease Token (SHARED / EXCLUSIVE)
          Byte-Range Record Lock (READ / WRITE)
```

Each tier inherits the fencing context of its parent. A directory subtree lease
grant automatically covers all inodes within that subtree, but an inode lease
can be independently granted for finer-grained control. Byte-range locks within
an inode require the inode lease to be held (or a parent subtree lease).

### 3.3 Component model

```
┌─────────────────────────────────────────────────────────┐
│                    tidefsd (each node)                    │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ FUSE daemon   │  │ VFS Engine   │  │ Lock Client   │  │
│  │ lock ops      │  │ lock check   │  │ forward reqs  │  │
│  └──────┬───────┘  └──────┬───────┘  └───────┬───────┘  │
│         │                 │                   │          │
│         └─────────────────┼───────────────────┘          │
│                           │                              │
│                    ┌──────▼──────┐                       │
│                    │  Transport   │                       │
│                    │  (CONTROL)   │                       │
│                    └──────┬──────┘                       │
└───────────────────────────┼──────────────────────────────┘
                            │
                   ┌────────▼────────┐
                   │  Lock Service    │
                   │  (Leader Node)   │
                   │                  │
                   │  ┌─────────────┐ │
                   │  │ Raft Group   │ │
                   │  │ (lock state) │ │
                   │  └─────────────┘ │
                   │  ┌─────────────┐ │
                   │  │ Lock Table   │ │
                   │  │ (in-memory)  │ │
                   │  └─────────────┘ │
                   └─────────────────┘
```

The lock service leader is one node in the cluster, elected via membership.
Lock state is replicated to a Raft group of follower nodes for fault tolerance.
The leader processes all lock acquire/renew/release/break operations and
maintains the authoritative lock table.

### 3.4 Lock service leader election

The lock service leader is the same node as the cluster membership leader
(#1209). The membership layer already provides term/epoch fencing, leader
election, and health tracking. Co-locating the lock service leader with the
membership leader avoids a separate leader-election protocol and ensures lock
state fencing is directly integrated with membership transitions.

On membership leader failover:
1. The new leader reconstructs lock state from the Raft log
2. All existing locks are fenced at the new term
3. A `LOCK_RECALL_ALL` event is broadcast to all nodes
4. Nodes must re-acquire locks under the new term

### 3.5 Lane assignment

All LOCK service messages use `LaneClass::Control` (lane 0, highest priority
per #1241). Lock operations are latency-critical: a delayed lock grant or recall
directly stalls user applications. CONTROL lane provides bounded latency and
starvation prevention.

---

## 4. Three-Tier Sharded Lease Model

### 4.1 Directory subtree leases

A directory subtree lease grants SHARED or EXCLUSIVE authority over all inodes
in a directory and its descendants.

```
SubtreeLease {
    dataset_id: u64,
    dir_ino: u64,               // root inode of the subtree
    class: SubtreeLeaseClass,   // Shared | Exclusive
    holder_id: MemberId,
    lease_id: u64,
    term: u64,
    epoch: EpochId,
    granted_at: u64,
    expires_at: u64,
}
```

**Conflict rules**:
- EXCLUSIVE subtree lease conflicts with any other subtree lease where the
  subtrees overlap (one is an ancestor of the other, or they share any inode).
- SHARED subtree leases are compatible with other SHARED subtree leases on
  overlapping subtrees.
- A subtree lease is sufficient to grant inode leases within that subtree
  without additional directory traversal.

**Grant semantics**:
- When a node requests an EXCLUSIVE subtree lease, the lock service checks for
  conflicting subtree leases (overlapping directories held by other nodes).
- If a conflict exists, the lock service may recall the conflicting lease
  before granting.
- Subtree leases have a configurable TTL with automatic renewal.

### 4.2 Per-inode lease tokens

An inode lease grants SHARED or EXCLUSIVE authority over a single inode.

```
InodeLeaseToken {
    dataset_id: u64,
    ino: u64,
    class: InodeLeaseClass,     // Shared | Exclusive
    holder_id: MemberId,
    parent_lease_id: u64,       // subtree lease that covers this inode
    token_id: u64,
    term: u64,
    epoch: EpochId,
    granted_at: u64,
    expires_at: u64,
    lock_count: u32,            // number of active byte-range locks
}
```

**Conflict rules**:
- EXCLUSIVE inode lease conflicts with any other inode lease on the same inode.
- SHARED inode leases are compatible with other SHARED inode leases.
- Inode lease can only be granted if the holder already has (or requests
  simultaneously) a covering subtree lease.

**Hot file optimization**:
- Frequently accessed files get dedicated inode lease tokens.
- The subtree lease covers the rest of the directory without per-inode
  overhead.
- Inode leases are lazily created: a node holding a subtree EXCLUSIVE lease
  does not need explicit inode leases until another node requests shared access
  to a specific file within that subtree.

### 4.3 Per-inode byte-range record locks

Byte-range record locks implement POSIX fcntl advisory record locking
(F_SETLK, F_SETLKW, F_GETLK) within a single inode.

```
ByteRangeLock {
    dataset_id: u64,
    ino: u64,
    lock_owner: LockOwner,       // (pid, owner_id) for POSIX lock ownership
    lock_type: RangeLockType,    // Read | Write
    start: u64,                  // byte offset (inclusive)
    len: u64,                    // 0 = to end of file
    lock_id: u64,
    granted: bool,               // false for pending blocking locks
    term: u64,
    epoch: EpochId,
    granted_at: u64,
}
```

**Lock ownership model**:
- POSIX record locks are associated with `(pid, file description)`.
- Lock ownership is identified by
  `LockOwner { node_id: MemberId, pid: u32, owner_key: u64 }`.
- Closing any file descriptor associated with the lock owner releases all locks
  from that owner on that file.
- Process termination releases all locks from that pid.
- Node disconnection releases all locks from that node.

**Conflict detection**:
- READ locks are compatible with other READ locks on overlapping ranges.
- WRITE locks conflict with any lock (READ or WRITE) on overlapping ranges.
- The lock service maintains a per-inode interval tree for O(log n) conflict
  detection.

**Blocking lock support (F_SETLKW)**:
- When a WRITE lock request conflicts with existing locks, the lock service
  records a pending lock entry.
- When conflicting locks are released, the lock service evaluates the pending
  queue and sends a `LOCK_GRANT_EVENT` callback.
- Pending locks have a configurable timeout; expired pending locks return
  `EAGAIN` or `EDEADLK`.

---

## 5. Wire Protocol

### 5.1 Method ID table

| Method             | ID   | Direction         | Purpose |
|--------------------|------|-------------------|---------|
| ACQUIRE            | 0x00 | Client → Leader   | Request a new lease or lock grant |
| ACQUIRE_ACK        | 0x01 | Leader → Client   | Grant or deny confirmation |
| RENEW              | 0x02 | Client → Leader   | Extend lease/lock TTL |
| RENEW_ACK          | 0x03 | Leader → Client   | Renewal confirmation |
| RELEASE            | 0x04 | Client → Leader   | Voluntarily release lease/lock |
| RELEASE_ACK        | 0x05 | Leader → Client   | Release confirmation |
| RECALL             | 0x06 | Leader → Client   | Revoke lease/lock (request voluntary release) |
| RECALL_ACK         | 0x07 | Client → Leader   | Acknowledge recall and confirm release |
| BREAK              | 0x08 | Leader → Client   | Forcefully break lease/lock (fence) |
| BREAK_ACK          | 0x09 | Client → Leader   | Acknowledge break |
| GETLK              | 0x0A | Client → Leader   | Query lock status (F_GETLK) |
| GETLK_ACK          | 0x0B | Leader → Client   | Lock status response |
| SETLK              | 0x0C | Client → Leader   | Non-blocking lock request (F_SETLK) |
| SETLKW             | 0x0D | Client → Leader   | Blocking lock request (F_SETLKW) |
| SETLK_ACK          | 0x0E | Leader → Client   | Non-blocking lock result |
| LOCK_GRANT_EVENT   | 0x0F | Leader → Client   | Async grant of previously blocked lock |
| RECALL_ALL         | 0x10 | Leader → All      | Broadcast: all locks fenced on term change |
| RECALL_ALL_ACK     | 0x11 | All → Leader      | Acknowledge full lock release |

Reserved: 0x12–0x3F (46 slots for future lock service extensions).

### 5.2 Common framing

All LOCK messages use the standard transport envelope (#1210) with
`service_id = 0x0A`. The payload for each method follows the patterns below.

### 5.3 ACQUIRE request

```
ACQUIRE Request {
    header:    FrameHeaderV1 { service_id=0x0A, method=0x00, ... }
    op_id:     u64                          // idempotency key (per peer)
    lease_level: LeaseLevel                 // Subtree | Inode | ByteRange
    dataset_id: u64
    // --- subtree fields (when lease_level=Subtree) ---
    dir_ino:    u64                         // root of subtree
    // --- inode fields (when lease_level=Inode) ---
    ino:        u64                         // target inode
    parent_lease_id: u64                    // covering subtree lease (0=none)
    // --- byte-range fields (when lease_level=ByteRange) ---
    lock_owner: LockOwner                   // {node_id, pid, owner_key}
    lock_type:  RangeLockType               // Read | Write
    start:      u64
    len:        u64
    blocking:   bool                        // true for F_SETLKW
    // --- common ---
    class:      LeaseClass                  // Shared | Exclusive
    term_millis: u64                        // requested lease TTL (0=default)
}
```

### 5.4 ACQUIRE_ACK response

```
ACQUIRE_ACK Response {
    header:     FrameHeaderV1 { service_id=0x0A, method=0x01, ... }
    op_id:      u64
    status:     LockStatus                  // Granted | DeniedConflict |
                                            // DeniedFenced | DeniedQuota |
                                            // DeniedNotLeader | Queued
    lease_id:   u64                         // assigned lease_id (0 if denied)
    lease_level: LeaseLevel
    term:       u64
    epoch:      EpochId
    expires_at: u64                         // absolute expiry millis
    conflict_holder: Option<MemberId>       // if DeniedConflict, who holds it
    conflict_lease_id: Option<u64>          // if DeniedConflict, which lease
}
```

### 5.5 RENEW request and ack

```
RENEW Request {
    header:   FrameHeaderV1 { service_id=0x0A, method=0x02, ... }
    op_id:    u64
    lease_id: u64
}

RENEW_ACK Response {
    header:     FrameHeaderV1 { service_id=0x0A, method=0x03, ... }
    op_id:      u64
    status:     LockStatus
    expires_at: u64                         // new absolute expiry millis
}
```

### 5.6 RECALL event (Leader → Client)

```
RECALL Event {
    header:    FrameHeaderV1 { service_id=0x0A, method=0x06, ... }
    lease_id:  u64
    reason:    RecallReason                 // ConflictUpgrade | LeaseExpiry |
                                            // AdminRevoke | MembershipChange
    deadline_millis: u64                    // caller must release by this time
}
```

### 5.7 SETLK request (non-blocking record lock)

```
SETLK Request {
    header:    FrameHeaderV1 { service_id=0x0A, method=0x0C, ... }
    op_id:     u64
    dataset_id: u64
    ino:        u64
    lock_owner: LockOwner
    lock_type:  RangeLockType
    start:      u64
    len:        u64
}
```

### 5.8 SETLK_ACK response

```
SETLK_ACK Response {
    header:    FrameHeaderV1 { service_id=0x0A, method=0x0E, ... }
    op_id:     u64
    status:    SetlkStatus                  // Granted | DeniedConflict |
                                            // DeniedFenced | DeniedNotLeader
    lock_id:   u64                          // 0 if denied
    conflict:  Option<ByteRangeLock>        // conflicting lock info
}
```

### 5.9 LOCK_GRANT_EVENT (async grant for F_SETLKW)

```
LOCK_GRANT_EVENT {
    header:    FrameHeaderV1 { service_id=0x0A, method=0x0F, ... }
    op_id:     u64                          // op_id from original SETLKW
    dataset_id: u64
    lock_id:   u64
    ino:        u64
    lock_owner: LockOwner
    lock_type:  RangeLockType
    start:      u64
    len:        u64
    granted_at: u64
    term:       u64
    epoch:      EpochId
}
```

---

## 6. Lock Service Core Data Structures

### 6.1 `LockServiceLeader`

The leader maintains the authoritative lock table in memory, backed by the
Raft log for persistence.

```rust
pub struct LockServiceLeader {
    /// Raft group for lock state replication
    raft: RaftGroup<LockCommand>,

    /// Per-dataset lock state
    datasets: BTreeMap<u64, DatasetLockState>,

    /// Pending blocking locks waiting for grant
    pending_locks: BTreeMap<u64, PendingLockEntry>,

    /// Leader configuration
    config: LockServiceConfig,

    /// Current membership term/epoch for fencing
    term: u64,
    epoch: EpochId,
}

pub struct DatasetLockState {
    /// Subtree leases keyed by lease_id
    subtree_leases: BTreeMap<u64, SubtreeLease>,

    /// Subtree lease index: dir_ino → set of lease_ids
    subtree_index: BTreeMap<u64, BTreeSet<u64>>,

    /// Inode lease tokens keyed by token_id
    inode_tokens: BTreeMap<u64, InodeLeaseToken>,

    /// Byte-range locks keyed by lock_id
    range_locks: BTreeMap<u64, ByteRangeLock>,

    /// Per-inode interval tree for range lock conflict detection
    range_index: BTreeMap<u64, RangeLockIntervalTree>,

    /// Lock owner → lock_ids mapping (for release-on-close)
    owner_locks: BTreeMap<LockOwner, BTreeSet<u64>>,
}
```

### 6.2 Core type enums

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseLevel {
    Subtree,
    Inode,
    ByteRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubtreeLeaseClass {
    Shared,
    Exclusive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InodeLeaseClass {
    Shared,
    Exclusive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RangeLockType {
    Read,
    Write,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LockOwner {
    pub node_id: MemberId,
    pub pid: u32,
    pub owner_key: u64,  // opaque file-description identifier
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockStatus {
    Granted,
    DeniedConflict,
    DeniedFenced,
    DeniedQuota,
    DeniedNotLeader,
    Queued,              // for blocking locks: queued for async grant
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecallReason {
    ConflictUpgrade,      // higher-priority request requires this lock
    LeaseExpiry,          // lease TTL expired
    AdminRevoke,          // operator-initiated revocation
    MembershipChange,     // leader failover or epoch change
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SetlkStatus {
    Granted,
    DeniedConflict,
    DeniedFenced,
    DeniedNotLeader,
}
```

### 6.3 Lock service configuration

```rust
pub struct LockServiceConfig {
    /// Default lease term in milliseconds
    pub default_lease_term_ms: u64,

    /// Maximum lease term in milliseconds
    pub max_lease_term_ms: u64,

    /// Grace period before lease expiry (fraction of term)
    pub grace_period_ratio: f64,

    /// Maximum number of pending blocking locks per inode
    pub max_pending_locks_per_inode: usize,

    /// Blocking lock timeout (ms); after this, return EAGAIN
    pub blocking_lock_timeout_ms: u64,

    /// Maximum subtree lease nesting depth
    pub max_subtree_depth: u32,

    /// Raft election timeout range (ms)
    pub raft_election_timeout_min_ms: u64,
    pub raft_election_timeout_max_ms: u64,

    /// Raft heartbeat interval (ms)
    pub raft_heartbeat_interval_ms: u64,
}
```

---

## 7. Consensus Replication

### 7.1 Raft-based lock state replication

The lock service uses an embedded Raft consensus group to replicate lock
state for fault tolerance. The group typically has 3 or 5 members (odd number
for quorum).

**Raft log commands**:
```rust
pub enum LockCommand {
    GrantSubtreeLease { grant: SubtreeLease },
    GrantInodeToken { grant: InodeLeaseToken },
    GrantRangeLock { lock: ByteRangeLock },
    ReleaseLease { lease_id: u64, level: LeaseLevel },
    BreakLease { lease_id: u64, level: LeaseLevel, reason: RecallReason },
    FenceAll { term: u64, epoch: EpochId },
}
```

### 7.2 Persistence granularity

Lock state persistence follows a **batched commit** model:

- Every lock grant/release/break is committed to the Raft log synchronously
  before responding to the client.
- Raft log entries are batched: multiple lock operations within a short
  window are committed as a single batch to reduce fsync overhead.
- Batching window: configurable, default 5ms. ACQUIREs wait for the next
  batch commit before receiving ACQUIRE_ACK.
- RENEW operations can be acknowledged optimistically (without waiting for
  Raft commit) when the existing lease's TTL is well within bounds — the
  Raft log entry is still written but the response is sent immediately.

### 7.3 Leader failover

When the membership leader fails and a new leader is elected:

1. New leader replays the Raft log from the last committed index
2. Reconstructs the in-memory lock table
3. Increments the term
5. Broadcasts `RECALL_ALL` to all connected nodes
6. Each node must re-acquire its locks under the new term
7. Locks not re-acquired within the grace period are released

This is safe because:
- No node can mutate without a valid lock
- RECALL_ALL ensures nodes are aware of the failover

### 7.4 Integration with transaction model

Lock state committed to the Raft log is also periodically checkpointed to
the dataset's transaction group (commit_group) metadata (#1222). This provides:

- **Crash recovery**: on full cluster restart, lock state is recovered from
  the latest commit_group checkpoint + Raft log replay.
- **Durability**: lock grants survive individual node failures.
- **Auditability**: lock history is embedded in the commit_group stream for debugging.

Checkpoint frequency: every N Raft log entries (configurable, default 1000)
or every T seconds (configurable, default 30s).

---

## 8. FUSE Lock Operation Forwarding

### 8.1 Forwarding decision

When a FUSE lock operation (flock, fcntl F_SETLK/F_SETLKW/F_GETLK) arrives
at a node:

1. If this node holds the covering write lease (subtree or inode EXCLUSIVE),
   process the lock locally.
2. Otherwise, forward the lock request to the LOCK service via transport.
3. For F_GETLK, the lock service returns the conflicting lock information
   (if any) that the caller must see — this may include locks held by other
   nodes.

### 8.2 Local lock processing shortcut

When the node holds the EXCLUSIVE inode or subtree lease, it can process
POSIX record locks locally:

```
┌───────────────┐
│ FUSE lock op   │
└───────┬───────┘
        │
        ▼
 ┌──────────────┐    Yes    ┌──────────────────┐
 │ Hold covering │─────────▶│ Local lock cache   │
 │ EXCL lease?   │          │ (per-inode)        │
 └──────┬───────┘          └──────────────────┘
        │ No
        ▼
 ┌──────────────┐
 │ Forward to    │
 │ LOCK service  │─────────▶ LOCK service leader
 └──────────────┘
```

This shortcut avoids network round-trips for the common single-writer case
and only introduces lock-service traffic when there are multiple concurrent
writers.

### 8.3 Local lock cache

Each node maintains a local lock cache for inodes where it holds the covering
lease:

```rust
pub struct LocalLockCache {
    /// Per-inode range locks when this node holds the covering lease
    inode_locks: BTreeMap<u64, InodeRangeLockSet>,

    /// Pending blocking locks queued locally
    pending: BTreeMap<u64, PendingLocalLock>,
}

pub struct InodeRangeLockSet {
    pub ino: u64,
    pub covering_lease_id: u64,       // the lease that covers local processing
    pub interval_tree: RangeLockIntervalTree,
    pub owner_locks: BTreeMap<LockOwner, Vec<u64>>,  // for release-on-close
}
```

When the covering lease is recalled, all locally-cached locks for that inode
must be released and any pending blocking locks must be forwarded to the
lock service.

---

## 9. Fencing Integration

### 9.1 Term/epoch fencing

Every lock and lease operation carries `(term, epoch)`. The LOCK service
rejects any request where:

- The term is less than the current term (stale)
- The epoch does not match (membership change in flight)
- The requesting node is not in the current membership view
- The requesting node's health is `Suspected` or `Unreachable`

### 9.2 Fenced node rejection

When a node is fenced (removed from membership, or its health degrades):

1. The lock service leader receives the membership transition notification
2. All locks held by the fenced node are immediately broken
3. `BREAK` notifications are sent to the fenced node (best-effort)
4. Pending locks from the fenced node are cancelled
5. The local lock cache on all remaining nodes is updated

### 9.3 Integration with existing `tidefs-lease`

The lock service extends the existing `LeaseAuthority` model from
`tidefs-lease` by adding new `LeaseDomain` variants:

```rust
pub enum LeaseDomain {
    // ... existing variants ...
    DirectorySubtree {
        dataset_id: u64,
        dir_ino: u64,
    },
    InodeToken {
        dataset_id: u64,
        ino: u64,
        parent_lease_id: u64,
    },
    ByteRange {
        dataset_id: u64,
        ino: u64,
        start: u64,
        len: u64,
    },
}
```

The lock service reuses `LeaseGrant`, `LeaseReceipt`, `LeaseError`,
`LeaseLifecycle` from `tidefs-lease` for consistency. Lock-specific types
are layered on top.

---

## 10. Interaction with Cache Coherency

### 10.1 Lease-gated coherency

The `cluster` coherency profile (#1184) is extended to support multi-writer
lease gating:

- A cached view is valid only within the lease epoch of the covering inode
  or subtree lease.
- When a lease is recalled, all cached views for the covered inodes must be
  to the recalled lease domain.

### 10.2 mmap coherency with range locks

Byte-range locks interact with mmap'd regions:

  nodes that have the same range mmap'd.
  when a WRITE byte-range lock is granted.
  is confirmed.

### 10.3 Close-to-open consistency with locks

The close-to-open freshness barrier (#1242) is extended:

- On `open()`, if byte-range locks exist on the file, the opener must
  receive the current lock state.
- The lock service provides a `GETLK_ALL` method (future extension, reserved
  method ID 0x12) to retrieve all locks on an inode.

---

## 11. Transaction Model Integration

### 11.1 Lock state durability

Lock state is committed through the transaction model (#1222):

- Every lock grant/release/break is a durable transaction record.
- On crash recovery (#1224), the lock state is reconstructed from the commit_group
  commit stream + Raft log replay.
- Intent log (#1252) is NOT used for lock operations; locks require
  consensus-synchronous persistence, not just local intent-log durability.

### 11.2 Lock-state write path

```
lock grant/release
       │
       ▼
┌──────────────┐
│ Raft propose  │  ← quorum commit (synchronous)
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Lock table     │  ← in-memory update
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ CommitGroup checkpoint │  ← periodic batch (every N entries or T seconds)
└──────────────┘
```

### 11.3 Recovery contract

On crash recovery:

1. Replay Raft log from last committed index
2. Reconstruct lock table in memory
3. Replay commit_group checkpoints for any locks committed between Raft snapshots
4. Fence all locks with term increment (new leader) or retain locks with
   same term (same leader restart)
5. Broadcast `RECALL_ALL` if term changed
6. Resume lock service

---

## 12. Design Decisions

### 12.1 Lock service replication: Raft or separate consensus group?

**Decision: Embedded Raft group.**

Rationale:
- The lock service leader is the membership leader, which already has
  consensus machinery.
- Embedding Raft avoids an external dependency.
- The Raft group is small (3–5 members), so overhead is minimal.
- Lock commands are small (hundreds of bytes), so the Raft log is compact.

Alternative considered: External etcd/ZooKeeper. Rejected because it adds
an operational dependency and is overkill for a small, embedded lock table.

### 12.2 Lock persistence granularity: every lock grant committed or batched?

**Decision: Batched commit with synchronous ACK.**

- Every lock grant/release/break is durable before ACK.
- Commits are batched within a short window (5ms default) to amortize fsync.
- RENEW can be acknowledged optimistically.

Rationale:
- Durability is required for correctness: a lock grant that is lost on
  failover causes double-writer corruption.
- Batching avoids the fsync-per-lock latency penalty.
- RENEW is idempotent, so optimistic ack is safe.

### 12.3 Lock service sharding: per-dataset or global?

**Decision: Per-pool global lock table, per-dataset partitioning.**

- One lock service leader per pool.
- Lock state is partitioned by `dataset_id` within the lock table.
- Subtree leases within a dataset are independent of other datasets.

Rationale:
- Per-dataset lock leaders would require N consensus groups, adding
  complexity.
- The lock table is small enough (thousands of entries, not millions)
  for a single leader to handle.
- Future scaling: if lock traffic becomes a bottleneck, the lock service
  can be sharded by dataset group without changing the wire protocol.



  the inode.
  to the requester.

This is the safest approach. Alternatives considered:
- **Optimistic concurrency**: Allow stale reads, detect conflicts later.
  Rejected because POSIX does not allow stale reads for locked ranges.
- **Page-level write-intent logging**: Track writes at page granularity.
  Rejected as too complex for Phase 2.

---

## 13. Migration from Phase 1

### 13.1 Compatibility

The lock service is a new capability. Phase 1 dataset-scoped leases remain
functional and are the default until the lock service is enabled.

The migration path:

1. **Lock service deployed**: The LOCK service leader is elected but no
   nodes request sharded leases.
2. **Opt-in per dataset**: Datasets are individually upgraded to use sharded
   leases via a dataset feature flag.
3. **Graceful fallback**: If the lock service is unavailable, the node falls
   back to dataset-scoped EXCLUSIVE leases.
4. **Rollback**: Datasets can be downgraded to Phase 1 leases if the lock
   service proves unstable.

### 13.2 Feature flag

```rust
pub enum DatasetLockMode {
    /// Phase 1: dataset-scoped exclusive writer lease
    ExclusiveWriter,
    /// Phase 2+: sharded leases via lock service
    Sharded,
}
```

Configured per dataset in the dataset feature flags.

---

## 14. Implementation Phases

### Phase 2a: Lock service core + wire protocol
- LOCK service registration (service_id = 0x0A)
- Wire protocol types and codec
- Lock service leader election (membership leader)
- Basic acquire/renew/release for subtree leases
- Raft group bootstrap (3-node)
- `LockServiceConfig` and `LockServiceLeader` structs

### Phase 2b: Inode leases + byte-range locks
- Per-inode lease tokens
- Byte-range record locks with interval tree
- SETLK/SETLKW/GETLK forwarding from FUSE
- Blocking lock callback (LOCK_GRANT_EVENT)
- Local lock cache for covering lease holders

### Phase 2c: Fault tolerance + fencing
- Raft log replay and lock table reconstruction
- Leader failover with RECALL_ALL
- Term/epoch fencing integration
- CommitGroup checkpointing of lock state
- Crash recovery integration

### Phase 2d: Coherency integration
- mmap range-lock coherency
- Cluster coherency profile extension
- Close-to-open lock state visibility

---

## 15. Residual Risks

1. **Raft group split-brain**: Mitigated by membership leader co-location;
   the membership layer already handles split-brain via epoch fencing.
2. **Lock service leader overload**: If lock traffic exceeds single-node
   capacity, per-dataset lock leader sharding is the escape hatch (see
   §12.3). Not needed for Phase 2.
3. **Blocking lock starvation**: Pending lock queues can grow unboundedly
   if many nodes contend for the same range. Mitigated by `max_pending_locks`
   cap and `blocking_lock_timeout_ms`.
4. **Raft log growth**: Unbounded log growth from high-frequency lock
   operations. Mitigated by periodic snapshotting (Raft snapshot + commit_group
   checkpoint).
5. **Local lock cache staleness on recall**: If a RECALL event is lost
   (network partition), a node may continue to use stale local lock state.
   Mitigated by lease TTL: local locks expire if not renewed, forcing

---

## 16. Acceptance Criteria

1. LOCK service compiles as `service_id = 0x0A` with wire protocol types
   for all 18 methods.
2. `LockServiceLeader` with Raft-backed lock table passes unit tests for:
   acquire, renew, release, recall, break, conflict detection, pending
   lock queue.
3. Subtree lease conflict detection correctly identifies overlapping
   directory hierarchies.
4. Byte-range lock interval tree correctly detects overlapping and
   non-overlapping ranges.
5. Leader failover: lock table reconstructs from Raft log; term increment
   fences all locks.
6. FUSE lock forwarding dispatch (SETLK/SETLKW/GETLK) routes non-owner
   requests to lock service.
7. Local lock cache processes locks locally when covering lease held.
8. `cargo check --workspace` passes with no regressions.

---

## 17. Relationship to Existing Crates

| Crate | Relationship |
|-------|-------------|
| `tidefs-lease` | Extended with `LeaseDomain` variants for Subtree/Inode/ByteRange; reused `LeaseGrant`, `LeaseReceipt`, `LeaseError` |
| `tidefs-membership-epoch` | Used for `MemberId`, `EpochId`, `ClusterMemberRecord` for lock service leader election and fencing |
| `tidefs-types-transport-session` | LOCK frames use standard envelope with `service_id = 0x0A` |
| `tidefs-membership-types` | Lock service leader is the membership leader; lock fencing on membership transitions |
| `tidefs-auth` | Lock service requires authenticated peers (#1228); peer identity bound to `LockOwner.node_id` |
| `tidefs-clock-timing` | Lease TTL and deadline management integrated with `LeaseDeadline` |
| `tidefs-vfs-engine` | VFS operations check lock state before mutating; lock forwarding from FUSE via TFS_RPC (#1234) |
| `tidefs-types-vfs-core` | Inode handles and lock state coordination with VFS layer |

---

*Design derived from v0.262 design book S17.5 "Scaling beyond single-writer:
sharded leases and lock service" + notes S17.4-S17.5. First-class lock
service with consensus replication follows the architecture established by
MEMBERSHIP (#1209) and ADMIN (#1217) services.*
