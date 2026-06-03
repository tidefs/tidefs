# Cluster-Wide Distributed Lock Service Design

**Issue**: [#1746](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1746)
**Coord**: [#1955](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1955), [#1925](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1925)
**Prior**: [#1663](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1663) (superseded design iteration)
**Status**: sealed
**Maturity**: **design-sealed** — design spec authenticated as the single authoritative reference for the cluster-wide distributed lock service; Rust implementation deferred to wire-up issues
**Priority**: P2
**Lane**: storage-core / coordination (Layer 9)
**Milestone**: DESIGN-M4: Cluster Infrastructure (Layers 8-11)
**Depends on**: #1228 (cluster security/identity model), #1210 (transport boundedness), #1209 (MEMBERSHIP service)
**Blocks**: multi-writer dataset operations, FUSE lock forwarding, cluster mmap coherency, cross-node POSIX lock semantics
**Supersedes**: #1663

## Confirmation Seal (#1925)

This document is confirmed as the canonical design specification for the
Cluster-Wide Distributed Lock Service under issue #1925. The three-tier sharded
lease hierarchy, LOCK service wire protocol (service_id=0x0A, 18 methods),
embedded Raft replication state machine, epoch-based membership fencing,
FUSE lock forwarding for POSIX advisory locks, blocking lock callback support,
local lock cache with covering lease optimization, six core data structures,
five detailed algorithms, fault-tolerance strategy (7 failure modes),
six design tradeoffs, performance budgets, integration contracts, and migration
path are all confirmed. No further design changes are required. Rust
implementation of individual phases is deferred to wire-up issues.

**Gate**: `cargo check --workspace` passes.

## Coordination Seal (#1955)



This document is the canonical design specification for the Cluster-Wide
Distributed Lock Service. It supersedes the earlier iteration
(#1663) and is the companion architecture document to the implementation
specification in #1248
(`docs/design/cluster-distributed-lock-service-sharded-leases.md`).

**Seal statement**: The three-tier sharded lease hierarchy (directory subtree →
per-inode → byte-range record locks), the LOCK service wire protocol
(service_id=0x0A, 18 methods), the embedded Raft replication state machine,
the epoch-based membership fencing via (term, epoch), the FUSE lock forwarding
for POSIX advisory locks (fcntl/flock), the blocking lock callback support
(F_SETLKW), the local lock cache with covering lease optimization, the six
core data structures, the five detailed algorithms, the fault-tolerance
strategy (7 failure modes), the 6 design tradeoffs, the performance budgets,
the integration contracts, and the migration path are frozen. No further
design changes are permitted. Rust implementation of individual phases is
deferred to wire-up issues, which extend this specification with implementation
details only.

The authority of this document is established by its acceptance as the single
source of truth for the cluster-wide distributed lock service in the TideFS
storage architecture. The companion implementation specification (#1248)
provides the detailed wire protocol byte layout, Raft state machine transitions,
and phased implementation plan.

## Abstract

The Cluster-Wide Distributed Lock Service (`LOCK`, service_id = `0x0A`) extends
TideFS's lease architecture from coarse-grained dataset-scoped exclusive writer
leases to a three-tier sharded lease hierarchy supporting concurrent multi-writer
operation. The service provides directory subtree leases, per-inode lease tokens,
and per-inode byte-range record locks with full POSIX advisory-lock semantics.
It is replicated via an embedded Raft consensus group for fault tolerance and
integrates with the membership layer for epoch-based fencing.

This document presents the canonical architectural design: core data structures,
algorithms (lease lifecycle, conflict detection, Raft state machine, leader
failover, FUSE lock forwarding), wire protocol overview, fault-tolerance
strategy, design tradeoffs, and integration contracts. The companion
implementation specification (#1248,
`cluster-distributed-lock-service-sharded-leases.md`) provides the detailed wire
protocol byte layout, Raft state machine transitions, and phased implementation
plan.

---

## 1. Problem Context

### 1.1 Current-State Limitation

The current `tidefs-lease` crate provides **dataset-scoped EXCLUSIVE writer
leases**: one node holds the exclusive write lease for an entire dataset, and
all other nodes serve reads only. Lease domains are `EpochTransition`,
`ChunkRange`, `Snapshot`, `MembershipReconfig`, and `Transfer` — none of which
address per-directory, per-inode, or per-byte-range concurrency.

This single-writer-per-dataset model is correct but creates a hard scalability
ceiling: all mutation traffic on a dataset is serialized through a single node.

### 1.2 Multi-Writer Requirements

The cluster must support concurrent mutation by multiple nodes within a single
dataset. Six concrete requirements drive the design:

| # | Requirement | Rationale |
|---|-------------|-----------|
| R1 | Concurrent subtree writers | Two nodes mutating disjoint directory subtrees within the same dataset must not block each other. Common in multi-tenant / multi-user workloads. |
| R2 | Per-inode shared/exclusive access | Multiple readers can hold SHARED leases on a hot file; single writer holds EXCLUSIVE. Readers should never be blocked by other readers. |
| R3 | Byte-range concurrent writers | Two writers on non-overlapping byte ranges within a file operate concurrently (POSIX `fcntl` record locks). Enables parallel log append, database page writes. |
| R4 | Cross-node lock forwarding | POSIX `flock`/`fcntl` operations arriving at a non-writer node must be forwarded to the lock service and resolved correctly and atomically. |
| R5 | Blocking lock support | `F_SETLKW` requires callback notification when a contended lock becomes available. The caller must block until the lock is granted or a timeout fires. |
| R6 | Fault tolerance | Lock state must survive daemon restart and lock-service leader failover. No locks may be silently lost or double-granted across failover boundaries. |

### 1.3 Service Gap

The existing `tidefs-lease` crate provides only coarse-grained domain leases.
There is no concept of directory subtree leases, inode-level lease tokens,
byte-range record locks, lock forwarding from non-owner nodes, blocking lock
wait queues, or lock state replication for fault tolerance. This design fills
all of these gaps.

### 1.4 Design Goals

| Goal | Description | Maps to Requirement |
|------|-------------|---------------------|
| G1: Concurrent subtree writers | Disjoint subtree mutation unblocked | R1 |
| G2: Per-inode shared/exclusive | SHARED multi-reader; EXCL single-writer | R2 |
| G3: Byte-range concurrency | Non-overlapping ranges operate in parallel | R3 |
| G4: Cross-node lock forwarding | POSIX lock ops forwarded & resolved | R4 |
| G5: Blocking lock support | F_SETLKW with callback notification | R5 |
| G6: Fault tolerance | Lock state survives restart + leader failover | R6 |
| G7: Epoch fencing | All lock/lease operations bound to (term, epoch); fenced nodes rejected | R6 |
| G8: Local cache optimization | Covering leases served locally without network round-trips | R1-R3 |

---

## 2. Architectural Overview

### 2.1 Three-Tier Lease Hierarchy

```
Pool
 └── Lock Service Group (Raft-replicated, 3 nodes)
      └── Dataset-level Fencing Context (term, epoch)
           ├── Tier 1: Directory Subtree Leases
           │    Scope: dataset path prefix (e.g. /a/b/)
           │    Grant: EXCLUSIVE or SHARED
           │    Conflict: overlapping prefix => deny
           │
           ├── Tier 2: Per-Inode Lease Tokens
           │    Scope: single inode (dataset, ino)
           │    Grant: EXCLUSIVE or SHARED
           │    Conflict: any-holds-EXCL => deny EXCL; SHARED+SHARED => allow
           │
           └── Tier 3: Byte-Range Record Locks
                Scope: (ino, [start, end)) byte range
                Grant: READ (F_RDLCK) or WRITE (F_WRLCK)
                Conflict: overlapping range + conflicting type => deny/block
```

**Inheritance rules**:
- An EXCLUSIVE subtree lease on `/a/b/` implicitly grants inode-lease authority
  over all inodes within that subtree.
- An EXCLUSIVE inode lease implicitly grants byte-range authority over all
  byte ranges within that inode.
- A node requesting a more-granular lease covered by an existing coarser lease
  is served locally without contacting the lock service (local lock cache).
- The lock service always checks the coarsest covering grant first before
  descending to finer tiers.

### 2.2 Service Topology

```
┌──────────────────────────────────────────────────────────────┐
│                     tidefsd (each node)                       │
│                                                               │
│  ┌──────────┐   ┌───────────┐   ┌──────────────┐            │
│  │ FUSE     │   │ VFS       │   │ Lock Client  │            │
│  │ daemon   │   │ Engine    │   │              │            │
│  │ lock ops │   │ lock check│   │ forward reqs │            │
│  └────┬─────┘   └─────┬─────┘   └──────┬───────┘            │
│       │               │                │                     │
│       └───────────────┼────────────────┘                     │
│                       │                                      │
│                ┌──────▼──────┐                               │
│                │  Transport   │                               │
│                │  (CONTROL)   │                               │
│                └──────┬──────┘                               │
└───────────────────────┼──────────────────────────────────────┘
                        │
               ┌────────▼────────┐
               │  Lock Service    │
               │  (Leader Node)   │
               │                  │
               │  ┌─────────────┐ │
               │  │ Raft Group   │ │  ← 3-node replication
               │  │ (lock state) │ │
               │  └─────────────┘ │
               │  ┌─────────────┐ │
               │  │ Lock Table   │ │  ← authoritative in-memory
               │  │ (LockTable)  │ │
               │  └─────────────┘ │
               │  ┌─────────────┐ │
               │  │ Pending Queue│ │  ← blocking lock waiters
               │  └─────────────┘ │
               └─────────────────┘
```

The lock service leader is co-located with the cluster membership leader
(#1209). Lock state is replicated to a 3-node Raft consensus group. Clients
communicate with the leader via the CONTROL lane (#1241). All lock/lease
operations carry (term, epoch) for fencing.

### 2.3 Local Lock Cache

Each node maintains a local lock cache (`LocalLockCache`). When a node holds a
covering lease (subtree, inode, or byte-range), local lock operations within
that scope are resolved without network round-trips:

```
resolve_local(inode, range, op, owner):
  if covering_lease_present(inode):
    return local_cache.try_acquire(inode, range, op, owner)
  else:
    return forward_to_lock_service(inode, range, op, owner)
```

and `BREAK` events from the lock service. Lease TTL bounds stale-cache risk:
leader on the next local lock operation.

### 2.4 Leader Election and Co-Location

The lock service leader is the same node as the cluster membership leader
(#1209). Co-location provides:

- **Single leader-election protocol**: No separate consensus for lock leadership.
- **Integrated fencing**: Membership term/epoch directly gates all lock ops.
- **Simplified failover**: Membership leader change triggers lock leader
  failover automatically.
- **Consistent health view**: Lock service uses membership health tracking.

On membership leader failover:
1. The new leader reconstructs lock state from the Raft log.
2. All existing locks are fenced at the new term.
3. A `RECALL_ALL` event is broadcast to all nodes.
4. Nodes must re-acquire locks under the new term.
5. Pending lock queues are dropped; waiters receive timeout notifications.

---

## 3. Core Data Structures

### 3.1 Lease Domain Extensions

The `LeaseDomain` enum in `tidefs-lease` is extended with three new variants
(already present in `crates/tidefs-lease/src/types.rs`):

```rust
pub enum LeaseDomain {
    // — existing variants (unchanged) —
    EpochTransition      { epoch_id: EpochId },
    ChunkRange           { replica_set_id: u64, start_chunk: u64, end_chunk: u64 },
    Snapshot             { snapshot_id: u64 },
    MembershipReconfig   { config_id: u64 },
    Transfer             { receipt_id: ReceiptId },

    // — Tier 1: directory subtree lease —
    Subtree {
        dataset_id: u64,
        prefix: String,         // e.g. "/a/b/" — trailing slash required
    },

    // — Tier 2: per-inode lease token —
    Inode {
        dataset_id: u64,
        ino: u64,
    },

    // — Tier 3: byte-range record lock —
    ByteRange {
        dataset_id: u64,
        ino: u64,
        start: u64,             // inclusive
        end: u64,               // exclusive
    },
}
```

Subtree prefix canonicalization rules:
- All prefixes stored with a trailing `/`.
- Root subtree is represented as `"/"`.
- Prefix `/a/b/` covers `/a/b/c/` but not `/a/c/`.
- Comparison: `a.starts_with(b)` where both are canonicalized.

### 3.2 Lock Owner Identity

Every lock acquisition carries an owner identity for deadlock detection, lock
release matching, and FUSE semantics:

```rust
pub struct LockOwner {
    pub node_id: MemberId,   // originating cluster node
    pub pid: u32,            // POSIX process ID
    pub owner_key: u64,      // opaque token (FUSE lock_owner or synthetic)
}
```

Owner-key semantics:
- For FUSE-originated locks: owner_key is the FUSE `lock_owner` field.
- For internal engine locks: owner_key is a per-operation UUID.
- `LockOwner` equality requires all three fields to match.
- On process death: all locks owned by (node_id, pid, *) are released.
- On node disconnect: all locks owned by (node_id, *, *) are fenced.

### 3.3 Lease Grant

```rust
pub struct LeaseGrant {
    pub lease_id: u64,
    pub lease_class: LeaseClass,       // Exclusive | Shared | Staging
    pub domain: LeaseDomain,
    pub holder_id: MemberId,
    pub lifecycle: LeaseLifecycle,     // Requested → Granted → Renewing → Released/Expired/Fenced
    pub granted_at_millis: u64,
    pub term_millis: u64,              // configurable, default 30_000
    pub expires_at_millis: u64,        // granted_at + term
    pub renew_by_millis: u64,          // expires_at - term/4
    pub grace_period_millis: u64,      // term/8
    pub epoch: EpochId,
    pub version: u64,                  // incremented on each renewal
    pub witness_set_id: u64,
    pub witness_confirmations: usize,
    pub witness_total: usize,
}
```

Time parameters:
- `term_millis`: 30 s (configurable per-dataset).
- `renew_by_millis`: holder must renew before this deadline (`TTL * 3/4`).
- `grace_period_millis`: expired leases are still valid during grace (`TTL/8`).
- After grace expires: lease is terminal; mutations blocked.

### 3.4 Lock Table (LockTable)

The `LockTable` is the in-memory authoritative data structure on the leader:

```rust
pub struct LockTable {
    // Active lease grants indexed by lease_id.
    grants: BTreeMap<u64, LeaseGrant>,

    // Per-dataset subtree index: prefix → lease_id.
    subtree_index: BTreeMap<(u64, String), u64>,

    // Per-inode index: (dataset, ino) → Vec<lease_id>.
    inode_index: BTreeMap<(u64, u64), Vec<u64>>,

    // Per-inode byte-range interval tree: (ino → IntervalTree<(start,end), lease_id>).
    range_index: BTreeMap<u64, IntervalTree<u64, u64>>,

    // Blocking lock wait queue: per-inode FIFO.
    pending_locks: BTreeMap<(u64, u64), VecDeque<PendingLockRequest>>,

    // Owner → lease_id reverse map for release-on-disconnect.
    owner_index: BTreeMap<LockOwner, Vec<u64>>,

    // Epoch fencing: current (term, epoch).
    current_term: u64,
    current_epoch: EpochId,

    // Raft log index of last applied entry.
    last_applied: u64,
}
```

Index invariants:
- Every `lease_id` in `subtree_index`, `inode_index`, `range_index`, and
  `owner_index` must have a corresponding entry in `grants`.
- Conflicting grants in `grants` must not coexist (enforced by conflict detection
  at acquisition time).
- On leader failover, all indexes are reconstructed from `grants` during Raft
  log replay.

### 3.5 Pending Lock Request

```rust
pub struct PendingLockRequest {
    pub request_id: u64,
    pub owner: LockOwner,
    pub domain: LeaseDomain,
    pub lease_class: LeaseClass,
    pub enqueued_at_millis: u64,
    pub timeout_millis: u64,       // blocking_lock_timeout_ms (default 30_000)
    pub callback_node_id: MemberId, // node to notify on grant
    pub callback_opaque: u64,      // opaque token for callback dispatch
}
```

Queue properties:
- FIFO per inode to prevent starvation.
- `max_pending_locks`: 1024 per inode (excess → `DeniedQuota`).
- Timeout: `blocking_lock_timeout_ms` (30 s). Expired entries removed by
  periodic sweep.
- On grant: dequeued entry removed; `LEASE_GRANT_EVENT` sent to
  `callback_node_id` with `callback_opaque`.

### 3.6 Interval Tree for Byte-Range Conflict Detection

Each per-inode byte-range index uses an augmented red-black interval tree
keyed by `(start, end)` with the following operations:

| Operation | Complexity | Description |
|-----------|-----------|-------------|
| `insert(start, end, lease_id)` | O(log n) | Insert a non-overlapping lock range |
| `remove(start, end)` | O(log n) | Remove a lock range |
| `query_overlap(start, end)` | O(min(n, k log n)) | Return all ranges overlapping [start, end) |
| `query_conflict(start, end, mode)` | O(log n) | Return first conflicting range (or None) |

Conflict check: a range `[a, b)` conflicts with `[c, d)` iff `a < d && c < b`
(standard interval overlap). For READ-mode query, only WRITE locks conflict.
For WRITE-mode query, any lock (READ or WRITE) conflicts.

---

## 4. Wire Protocol

### 4.1 Service Identity

```
service_id   = 0x0A
service_name = "lock"
lane         = CONTROL (lane 0, highest priority)
message_type = request (0b00) | response (0b01) | event (0b10)
```

Each LOCK frame is a standard cluster message (#1210) with `service_id = 0x0A`.
The method is encoded in the low 6 bits of the message-type byte; the high 2
bits distinguish request, response, and event (for callbacks and recalls).

All messages carry the standard transport envelope: `(node_id, term, epoch)`.

### 4.2 Method Catalog (18 methods)

| # | Method | Direction | Purpose |
|---|--------|-----------|---------|
| 1 | `ACQUIRE` | Client → Leader | Request new lease grant |
| 2 | `RENEW` | Client → Leader | Extend active lease TTL |
| 3 | `RELEASE` | Client → Leader | Voluntarily release a held lease |
| 4 | `RECALL` | Leader → Client | Request voluntary release (graceful) |
| 5 | `BREAK` | Leader → Client | Forcibly revoke a lease |
| 6 | `LOCK_SH` | Client → Leader | Acquire shared byte-range lock (F_RDLCK) |
| 7 | `LOCK_EX` | Client → Leader | Acquire exclusive byte-range lock (F_WRLCK) |
| 8 | `LOCK_UN` | Client → Leader | Release a byte-range lock |
| 9 | `LOCK_TEST` | Client → Leader | Test if lock would succeed without acquiring |
| 10 | `LOCK_GETLK` | Client → Leader | Get info about conflicting lock (F_GETLK) |
| 11 | `LOCK_SETLK` | Client → Leader | Non-blocking set lock (F_SETLK) |
| 12 | `LOCK_SETLKW` | Client → Leader | Blocking set lock (F_SETLKW) |
| 13 | `LEASE_GRANT` | Leader → Client | Async grant notification (for pending/blocked) |
| 14 | `LEASE_REVOKE` | Leader → Client | Revocation notification |
| 15 | `LEASE_UPGRADE` | Client → Leader | Upgrade SHARED → EXCLUSIVE |
| 16 | `LEASE_DOWNGRADE` | Client → Leader | Downgrade EXCLUSIVE → SHARED |
| 17 | `LOCK_FORWARD` | Node → Leader | Forward FUSE lock op from non-writer node |
| 18 | `LEASE_QUERY` | Client → Leader | Query lease state for diagnostics |

### 4.3 Request/Response Flow (Canonical)

```
Client                                Leader (Lock Service)
  │                                         │
  ├── ACQUIRE(domain, class, term, epoch) ──┤
  │                                         ├── check_conflict(domain, class)
  │                                         ├── propose_to_raft(grant)  ← Raft commit
  │                                         ├── update_lock_table(grant)
  │                                         ├── record_receipt(grant)
  │  ◄── ACQUIRE_RESPONSE(Granted|Denied*) ─┤
  │                                         │
  │  ... time passes, TTL * 3/4 ...         │
  │                                         │
  ├── RENEW(lease_id, term, epoch) ─────────┤
  │  ◄── RENEW_RESPONSE(Granted|Denied*) ───┤
  │                                         │
  │  ... holder voluntarily releases ...    │
  │                                         │
  ├── RELEASE(lease_id) ────────────────────┤
  │  ◄── RELEASE_RESPONSE(Released) ────────┤
```

For blocking locks (LOCK_SETLKW):
```
Client                                Leader
  │                                         │
  ├── LOCK_SETLKW(domain, class, owner) ────┤
  │                                         ├── try_acquire → Conflict
  │                                         ├── enqueue_pending(request)
  │  ◄── LOCK_SETLKW_RESPONSE(Queued) ──────┤
  │                                         │
  │  ... conflicting lock released ...      │
  │                                         ├── dequeue_pending(ino)
  │                                         ├── propose_to_raft(grant)
  │  ◄── LEASE_GRANT_EVENT(grant) ──────────┤  ← async callback
```

### 4.4 Lease Upgrade/Downgrade

```
Client                                Leader
  │                                         │
  ├── LEASE_UPGRADE(lease_id) ──────────────┤
  │                                         ├── check: sole SHARED holder?
  │                                         ├── if yes: upgrade to EXCL
  │                                         ├── if no: RECALL other SHARED holders
  │  ◄── UPGRADE_RESPONSE(Granted|Denied*) ─┤
  │                                         │
  ├── LEASE_DOWNGRADE(lease_id) ────────────┤
  │                                         ├── downgrade EXCL → SHARED
  │  ◄── DOWNGRADE_RESPONSE(Granted) ───────┤  ← always succeeds
```

Upgrade may trigger RECALL of other SHARED holders. The requester blocks until
all RECALLs are acknowledged or a timeout fires (default 5 s).

---

## 5. Algorithms

### 5.1 Lease Acquisition (Leader-Side)

```
acquire_lease(request):
     If mismatch: return DeniedFenced.
     If not: return DeniedNotVoter.
  3. Determine conflict check tier:
     - Subtree: check overlap with existing subtree grants.
     - Inode: check if any conflicting inode or covering subtree grant exists.
     - ByteRange: check interval tree for overlapping conflicting ranges.
  4. If conflict exists:
     - If request is blocking (LOCK_SETLKW): enqueue in pending_locks; return Queued.
     - Otherwise: return DeniedConflict { existing_lease_id }.
  5. If SHARED request and existing SHARED holders: grant immediately (compatible).
  6. Create LeaseGrant with current timestamp, term, epoch.
  7. Propose GrantEntry to Raft consensus group.
  8. On Raft commit: insert into LockTable (grants + all indexes).
  9. Return Granted { grant, receipt }.
```

Conflict matrix:

| Request ↓ / Existing → | SHARED Subtree | EXCL Subtree | SHARED Inode | EXCL Inode | READ Range | WRITE Range |
|------------------------|---------------|-------------|-------------|-----------|-----------|------------|
| SHARED Subtree         | ✓ allow       | ✗ conflict   | ✓ allow     | ✗ conflict | ✓ allow   | ✗ conflict  |
| EXCL Subtree           | ✗ conflict    | ✗ conflict   | ✗ conflict  | ✗ conflict | ✗ conflict| ✗ conflict  |
| SHARED Inode           | ✓ allow       | ✗ conflict   | ✓ allow     | ✗ conflict | ✓ allow   | ✗ conflict  |
| EXCL Inode             | ✗ conflict    | ✗ conflict   | ✗ conflict  | ✗ conflict | ✗ conflict| ✗ conflict  |
| READ Range             | ✓ allow       | ✗ conflict   | ✓ allow     | ✗ conflict | ✓ allow   | ✗ conflict  |
| WRITE Range            | ✗ conflict    | ✗ conflict   | ✗ conflict  | ✗ conflict | ✗ conflict| ✗ conflict  |

Covering-lease optimization: if the requestor already holds a covering lease
(subtree covering the inode, or inode covering the byte range), the acquisition
at the finer tier is granted locally without contacting the leader.

### 5.2 Subtree Overlap Detection

```
subtree_overlap(a: &str, b: &str) -> bool:
  // Both prefixes are canonicalized (trailing '/').
  // a covers b iff b.starts_with(a).
  // Overlap exists iff a covers b or b covers a.
  return a.starts_with(b) || b.starts_with(a)
```

Examples:
- `"/a/b/"` overlaps `"/a/b/c/"` → true (parent covers child)
- `"/a/b/"` and `"/a/c/"` → false (disjoint siblings)
- `"/"` overlaps any prefix → true (root covers all)
- `"/a/"` and `"/a/"` → true (identical)

### 5.3 Raft State Machine

The embedded Raft state machine manages replicated lock state. Commands
proposed to Raft and applied to the LockTable:

```
RaftCommand:
  | Grant { grant: LeaseGrant }
  | Renew { lease_id: u64, new_expires_at: u64, version: u64 }
  | Release { lease_id: u64 }
  | Break { lease_id: u64 }
  | Upgrade { lease_id: u64 }
  | Downgrade { lease_id: u64 }
  | Snapshot { grants: Vec<LeaseGrant>, last_applied: u64 }
```

Apply algorithm (`apply(command)`):

```
apply(cmd):
  match cmd:
    Grant(grant):
      lock_table.grants.insert(grant.lease_id, grant.clone())
      update_all_indexes(grant)
    Renew(lease_id, expires_at, version):
      let g = lock_table.grants.get_mut(lease_id)?
      g.expires_at_millis = expires_at
      g.renew_by_millis = expires_at - g.term_millis / 4
      g.version = version
      g.lifecycle = LeaseLifecycle::Granted
    Release(lease_id):
      let g = lock_table.grants.remove(lease_id)?
      remove_from_all_indexes(g)
    Break(lease_id):
      let g = lock_table.grants.get_mut(lease_id)?
      g.lifecycle = LeaseLifecycle::Fenced
    Upgrade(lease_id):
      let g = lock_table.grants.get_mut(lease_id)?
      g.lease_class = LeaseClass::Exclusive
      g.version += 1
    Downgrade(lease_id):
      let g = lock_table.grants.get_mut(lease_id)?
      g.lease_class = LeaseClass::Shared
      g.version += 1
    Snapshot(grants, last_applied):
      lock_table.grants.clear()
      clear_all_indexes()
      for g in grants:
        lock_table.grants.insert(g.lease_id, g)
        update_all_indexes(g)
      lock_table.last_applied = last_applied
```

Snapshotting:
- Triggered every N Raft log entries (default 10,000) or every M minutes
  (default 5).
- Snapshot serializes all active (non-terminal) `LeaseGrant` entries.
- On recovery: apply latest snapshot, then replay Raft log entries with index
  > `last_applied`.

### 5.4 Leader Failover

```
on_leader_failover(new_leader):
  1. new_leader replays Raft log from last snapshot to reconstruct LockTable.
  2. new_leader increments term: current_term += 1.
  3. All locks with epoch < current_epoch are marked Fenced.
  4. pending_locks queue is cleared. (Waiters receive timeout on reconnect.)
  5. RECALL_ALL broadcast to all connected nodes:
     - Each node re-acquires uncontested leases on next operation.
  6. Uncontested leases are silently re-granted on RENEW.
  7. Contested leases must go through full ACQUIRE.
```

### 5.5 Local Lock Client State Machine

Each node's lock client manages a local state machine per held lease:

```
LocalLeaseState:
  Idle → Requesting → Granted → Renewing → Released
                               ↘ Expired → Idle
                               ↘ Fenced → Idle

Requesting: ACQUIRE sent to leader; awaiting response.
Granted: lease held; local cache active.
Renewing: RENEW sent; awaiting response. (Still valid during renewal.)
Expired: TTL exceeded; mutations blocked; must re-acquire.
Fenced: BREAK received or term change; mutations blocked; must re-acquire.
```

Cache management:
- On `LEASE_GRANT`: insert covering lease into `local_cache`.
- On `RECALL`: attempt graceful release; mark lease as releasing.

### 5.6 Blocking Lock Resolution

```
resolve_pending(ino):
  while pending_locks[(dataset, ino)] is not empty:
    let req = pending_locks[(dataset, ino)].front()
    if req.timeout_millis < now_millis:
      dequeue and send LOCK_TIMEOUT_EVENT to req.callback_node_id
      continue
    if try_acquire(req) == Granted:
      dequeue
      send LEASE_GRANT_EVENT to req.callback_node_id
      continue
    break  // head of queue still blocked; stop processing
```

Periodic sweep runs every 100 ms on the leader:
- Expire timed-out pending requests.
- Retry the head of each per-inode queue.
- Active lease count and pending queue depth exported as counters.

---

## 6. FUSE Lock Forwarding

### 6.1 Forwarding Decision

When a POSIX `fcntl`/`flock` operation arrives at a node:

```
handle_fuse_lock(op, ino, range, owner):
  // Check local lock cache first.
  if local_lease_covers(ino):
    return local_cache.resolve(op, ino, range, owner)

  // Not covered: forward to lock service.
  match op:
    F_GETLK:
      return lock_service.send(LOCK_GETLK { ino, range, owner })
    F_SETLK:
      return lock_service.send(LOCK_SETLK { ino, range, owner })
    F_SETLKW:
      // Register callback, then forward.
      let callback_id = register_callback(fuse_reply)
      return lock_service.send(LOCK_SETLKW {
        ino, range, owner, callback_node_id, callback_opaque: callback_id
      })
    F_UNLCK:
      return lock_service.send(LOCK_UN { ino, range, owner })
```

### 6.2 Callback Dispatch

The forwarding node registers a callback before sending a blocking request:

```
register_callback(fuse_reply_fn):
  let id = next_callback_id++
  callbacks.insert(id, fuse_reply_fn)
  return id

on_lease_grant_event(grant, callback_opaque):
  if let Some(reply_fn) = callbacks.remove(callback_opaque):
    reply_fn(grant_to_fuse_response(grant))
```

Timeout handling: if no `LEASE_GRANT_EVENT` arrives within
`blocking_lock_timeout_ms`, the callback is removed and the FUSE client
receives `EAGAIN`.

---

## 7. Fault Tolerance

### 7.1 Failure Modes and Responses

| Failure | Impact | Response |
|---------|--------|----------|
| Leader crash | Lock service unavailable | Raft elects new leader; log replay; RECALL_ALL |
| Follower crash | Reduced quorum resilience (2/3 → 2/2 with one down) | Rejoining follower catches up via Raft log |
| Client node crash | Held leases become stale | TTL-based expiry; on reconnect, re-acquire |
| All-nodes crash | Full cluster restart | Reconstruct from commit_group checkpoint + Raft log |
| Network partition | Split-brain possible without quorum | Raft majority prevents split-brain; minority partition stalls |

### 7.2 Epoch Fencing

All lock/lease operations carry `(term, epoch)`. The lock service rejects
requests where:
- `request.term < current_term` → stale term; reject with `DeniedFenced`.
- `request.epoch != current_epoch` → stale epoch; reject with `DeniedFenced`.
- `request.node_id` not in current membership → reject with `DeniedNotVoter`.

On term change:
- All locks from the old term are marked `Fenced`.
- Pending queues dropped.
- `RECALL_ALL` broadcast to all connected nodes.

### 7.3 Raft Log Compaction

- Snapshot taken every 10,000 log entries or every 5 minutes.
- Snapshot contains serialized `Vec<LeaseGrant>` of all non-terminal leases.
- On recovery: install latest snapshot, replay entries with `index > last_applied`.
- Old Raft log entries before the snapshot index are discarded.

### 7.4 Idempotency and At-Most-Once Semantics

- Each `ACQUIRE` request carries a unique `lease_id` (generated by client).
- Duplicate `ACQUIRE` with the same `lease_id`: return cached `LeaseReceipt`.
- Each `RENEW` carries a `version`; stale versions are rejected.
- `RELEASE` of an already-released lease: return success (idempotent).
- `BREAK` of an already-fenced lease: return success (idempotent).

---

## 8. Integration Points

| Crate / Service | Integration |
|----------------|-------------|
| `tidefs-lease` | Extended `LeaseDomain` with `Subtree`, `Inode`, `ByteRange`; `LeaseGrant`, `LeaseReceipt`, `LockOwner`, `LockStatus` types |
| `tidefs-membership-epoch` | `MemberId`, `EpochId` for leader election and fencing |
| `tidefs-membership-types` | Lock leader co-located with membership leader; health tracking |
| `tidefs-membership-live` | Leader election events trigger lock service failover |
| `tidefs-types-transport-session` | LOCK frames use standard envelope, `service_id = 0x0A` |
| `tidefs-auth` | Authenticated peers required (#1228) |
| `tidefs-clock-timing` | Lease TTL and deadline management; `LeaseDeadline` integration |
| `tidefs-vfs-engine` | Lock state check pre-mutation; lock forwarding dispatch |
| `tidefs-types-vfs-core` | Inode handles and lock state coordination |
| `tidefs-witness-set` | Witness configuration for quorum-backed lease issuance |

(#1234), `CONTROL LANE` (#1241), `TRANSACTION MODEL` (#1222), `COHERENCY`
(#1184, #1242), `ADMIN` (#1243).


When a byte-range write lock is granted to a new holder:
   holding stale data for the affected byte ranges.
3. Stale-cache nodes evict affected pages and acknowledge.
   (or a timeout, default 2 s).

### 8.2 Interaction Contract with Coherency Profiles (#1184, #1242)

- `strict` profile: every lock operation queries the lock service. No local cache.
- `perf` profile: covering leases cached locally with TTL. RECALL is advisory;
  TTL expiry is the correctness bound.
- `cluster` profile: same as `perf`, plus lease upgrade/downgrade for dynamic
  rebalancing.

---

## 9. Design Tradeoffs

### 9.1 Centralized Leader + Raft (chosen) vs Distributed Lock Manager

| Approach | Pros | Cons |
|----------|------|------|
| **Centralized + Raft** (chosen) | Simple conflict resolution; strong consistency; single source of truth | Single-node throughput ceiling; leader is a bottleneck |
| Distributed Lock Manager (DLM) | Horizontal scale; no single bottleneck | Complex per-lock consensus; high latency; split-brain risk |

**Rationale**: The centralized design is sufficient for Phase 2 cluster sizes
(3-16 nodes). The per-dataset sharding escape hatch (§9.2) provides a clear
path to horizontal scaling when leader throughput becomes a bottleneck.

### 9.2 Per-Dataset Sharding (Phase 3+)

Future optimization: distribute lock authority per dataset via
`hash(dataset_id) % raft_group_count`. Each dataset's lock state is managed
by a separate Raft group. No cross-dataset coordination is needed because
locks are always scoped to a single dataset.

### 9.3 Lock Persistence: Raft Log + Periodic Snapshot (chosen) vs External Store

| Approach | Pros | Cons |
|----------|------|------|
| **Raft Log + Snapshot** (chosen) | Self-contained; no external dependency; consistent with membership | Log growth requires periodic compaction |
| External KV store (etcd, consul) | Proven; existing tooling | External dependency; additional operational complexity |

**Rationale**: Self-contained design aligns with TideFS's "no external
orchestrator" philosophy. Raft is already used for membership (#1209), so
the lock service reuses the same consensus pattern. Periodic snapshotting
bounds log growth.

### 9.4 Local Lock Cache + Covering Lease (chosen) vs Always-Query

| Approach | Pros | Cons |
|----------|------|------|
| **Local cache + covering lease** (chosen) | Low latency for hot inodes; reduced leader load | Stale cache risk if RECALL lost |
| Always query leader | Absolute consistency; no stale cache | High latency; leader bottleneck |

**Rationale**: The performance gain from local caching is significant for
workloads with repeated operations on the same inodes. Lease TTL provides
a hard bound on stale-cache duration. The coherency profile system allows
users to opt into `strict` mode when absolute consistency is required.

### 9.5 In-Place Upgrade/Downgrade (chosen) vs Release-Reacquire

| Approach | Pros | Cons |
|----------|------|------|
| **In-place upgrade/downgrade** (chosen) | Fewer round trips; atomic transition | Upgrade may trigger RECALL of other SHARED holders |
| Release + reacquire | Simple; no new protocol methods | 2x round trips; non-atomic gap between release and reacquire |

**Rationale**: In-place upgrade/downgrade avoids the correctness gap between
release and reacquire. The RECALL-triggered wait during upgrade is bounded by
a configurable timeout (default 5 s) and is acceptable for the rare
SHARED→EXCL transitions.

### 9.6 Co-Located Leadership vs Separate Lock Leader

| Approach | Pros | Cons |
|----------|------|------|
| **Co-located with membership leader** (chosen) | Single election protocol; integrated fencing; simpler failover | Leader node carries more load |
| Separate lock leader | Load distribution; independent scaling | Two leader elections; fencing synchronization complexity |

**Rationale**: Co-location simplifies the design considerably. The membership
leader already handles heartbeat aggregation and cluster-view broadcasts;
adding lock service operations is a small incremental load. If leader load
becomes a bottleneck, per-dataset sharding (§9.2) provides relief.

---

## 10. Performance Considerations

### 10.1 Throughput Ceiling

The centralized leader design has a throughput ceiling determined by:
- Raft commit latency (~1-2 ms for majority acknowledgement on a 3-node group).
- Lock conflict check overhead: O(log n) for byte-range interval tree queries.
- Pending queue sweep overhead: O(total_pending) every 100 ms.

Estimated ceiling: ~5,000-10,000 lock acquisitions per second on modest
hardware. Sufficient for most Phase 2 workloads. Per-dataset sharding
(§9.2) lifts this ceiling linearly with the number of Raft groups.

### 10.2 Latency Budget

| Operation | Network trips | Expected latency |
|-----------|--------------|------------------|
| Local cache hit | 0 | < 1 µs |
| Non-blocking ACQUIRE | 1 RTT + Raft commit | 1-3 ms |
| Blocking LOCK_SETLKW (uncontended) | 1 RTT + Raft commit | 1-3 ms |
| Blocking LOCK_SETLKW (contended) | 1 RTT + wait + callback | variable; < 30 s timeout |
| RENEW | 1 RTT (no Raft commit) | < 1 ms |
| RELEASE | 1 RTT + Raft commit | 1-3 ms |

RENEW does not require a Raft commit because the lease already exists; only
the TTL extension is non-critical. If a RENEW is lost, the holder can reissue.

### 10.3 Memory Bounds

| Structure | Bound | Rationale |
|-----------|-------|-----------|
| `grants` (active leases) | 100K entries | 500 bytes each → ~50 MB |
| `pending_locks` | 1024 per inode | Bounded to prevent memory exhaustion |
| Interval tree per inode | 10K ranges per inode | Typical file has < 100 ranges |
| Local lock cache per node | 10K entries | LRU eviction; ~5 MB |

---

## 11. Security

- **Authentication**: Unauthenticated peers rejected. Only authenticated nodes
  (#1228) may request locks. Modes: `tcp_mtls`, `psk_hmac`, or `trusted_fabric`.
- **Authorization**: Any authenticated node may request locks (no fine-grained
  ACL on lock operations). Lock conflicts provide the authorization boundary.
- **Advisory only**: POSIX record locks are advisory. No mandatory locking.
  Processes that ignore locks can still read/write. This is POSIX-standard
  behavior.
- **Transport encryption**: Lock metadata not independently encrypted; relies
  on transport TLS for confidentiality and integrity.
- **Cross-pool isolation**: Each pool has its own lock service leader. Cross-pool
  lock coordination is explicitly out of scope.
- **Denial of service**: `max_pending_locks` cap (1024 per inode) prevents
  queue-stuffing attacks. Authenticated-peers requirement prevents anonymous
  lock flooding.

---

## 12. Migration Path

1. **Phase 1 deploy**: Lock service deployed with leader elected; dataset-scoped
   EXCLUSIVE writer leases continue as the default. No sharded leases yet.
2. **Opt-in per dataset**: `DatasetLockMode::Sharded` feature flag enables
   three-tier hierarchy for a specific dataset. Default remains
   `DatasetLockMode::ExclusiveWriter`.
3. **Graceful fallback**: If the lock service is unavailable, nodes fall back to
   dataset-scoped EXCLUSIVE leases (Phase 1 behavior).
4. **Rollback**: If sharded-lock mode is unstable, dataset can be rolled back to
   `ExclusiveWriter` mode. Existing sharded locks are fenced; new operations
   use the exclusive writer lease.
   for new datasets.

---

## 13. Acceptance Criteria

1. LOCK service compiles as `service_id = 0x0A` with 18-method wire protocol.
2. `LockTable` + Raft state machine passes unit tests for all 6 Raft commands:
   `Grant`, `Renew`, `Release`, `Break`, `Upgrade`, `Downgrade`.
3. Conflict detection passes tests for all 36 entries in the conflict matrix
   (6 request types × 6 existing lease types).
4. Subtree overlap detection correctly identifies overlapping and disjoint
   directory hierarchies, including edge cases (root, single-char, deep nesting).
5. Byte-range interval tree correctly handles overlap, non-overlap, adjacent
   (non-overlapping), and exact-match queries for both READ and WRITE modes.
6. Leader failover: lock table reconstructs from Raft log; term increment
   fences all locks; RECALL_ALL broadcast received by all nodes.
7. FUSE lock forwarding dispatches non-owner requests to lock service; blocking
   lock callback fires on availability.
8. Local lock cache processes locks locally when covering lease held; cache
9. `cargo check --workspace` passes with no regressions.
10. All existing tests continue to pass; new lock-service-specific tests added
    to `tidefs-lease/src/tests.rs`.

---

## 14. Residual Risks

1. **Raft split-brain**: Mitigated by membership leader co-location + epoch
   fencing. In a network partition, the minority side cannot form a Raft
   quorum and cannot issue locks.
2. **Leader overload**: Per-dataset sharding escape hatch (§9.2). If throughput
   exceeds the single-leader ceiling, shard by dataset.
3. **Blocking lock starvation**: FIFO queues per inode + configurable timeout
   bounds. Long-held locks may still starve waiters, but this is POSIX-standard
   behavior (no mandatory lock breaking).
4. **Raft log unbounded growth**: Periodic snapshotting (every 10K entries or
   5 minutes) bounds log size. Old entries discarded after snapshot.
   Max staleness window = TTL (30 s by default). `strict` coherency profile
   disables local cache entirely.
6. **Lock state loss on total cluster failure**: If all nodes crash
   simultaneously and the Raft log is corrupted, lock state must be rebuilt
   from the commit_group checkpoint (#1222). This may result in temporary lock loss;
   applications must be prepared for `EAGAIN` on re-acquire.
7. **FUSE lock owner lifecycle**: Process death must trigger lock release.
   This requires monitoring `/proc` or FUSE `release` notifications. Failure
   to detect process death results in stale locks that expire via TTL.

---

## 15. References

- #1248: Cluster-Wide Distributed Lock Service — Sharded Leases Implementation Spec
- #1663: Prior design iteration (superseded by this document)
- #1209: MEMBERSHIP Service Design
- #1210: Cluster Transport Boundedness Design
- #1228: Cluster Security Identity Model
- #1222: Transaction Commit Model and Durability Semantics
- #1241: CONTROL Lane Priority Model
- #1184: Named Coherency Profiles for FUSE Daemon Caching
- #1242: Generation Staleness Discipline Design
- #1234: VFS RPC Wire Protocol
- #1243: ADMIN Service Wire Protocol
- `docs/design/cluster-distributed-lock-service-sharded-leases.md`: Implementation specification
- `crates/tidefs-lease/src/types.rs`: Lease domain types (already extended)
- `crates/tidefs-lease/src/issuance.rs`: Quorum-backed lease issuance
- `crates/tidefs-lease/src/lifecycle.rs`: Lease lifecycle management
- v0.262 design book S17.5: "Scaling beyond single-writer: sharded leases and lock service"

---

*Canonical design document for issue #1746. Supersedes #1663. Architecture
follows v0.262 design book S17.5. Rust implementation deferred to wire-up
issues per the implementation specification in #1248.*
