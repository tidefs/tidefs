# Dataset Lifecycle State Machine — Design Specification

**Issue**: [#1685](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1685)
**Canonical spec**: `docs/design/dataset-lifecycle-state-machine.md` (#1634 / #1903)
**Lane**: storage-core
**Kind**: design
**Maturity**: design-spec — state machine, transitions, and interfaces are frozen; Rust implementation of remaining destroy-worker and cluster-integration phases deferred to wire-up issues
**Status**: sealed

---

## 1. Architecture Overview

The dataset lifecycle state machine governs the full existence arc of a dataset
from creation through active operation, destruction, and eventual cleanup. It
defines four core states (`ACTIVE`, `DESTROYING`, `TOMBSTONE`, `REAPED`) with
explicit transition rules, mount-safety gating, and cluster-consensus
integration.

```
                    ┌─────────┐
                    │ ACTIVE  │
                    └────┬────┘
                         │ admin: destroy request
                         ▼
               ┌──────────────────┐
               │   DESTROYING     │
               │  (async worker)  │──── abort (admin intervention) ────► ACTIVE
               └────────┬─────────┘
                        │ worker completes block reclamation
                        ▼
               ┌──────────────────┐
               │   TOMBSTONE      │
               │ (cluster visible)│
               └────────┬─────────┘
                        │ reaper: min_age + cluster consensus
                        ▼
               ┌──────────────────┐
               │    REAPED        │
               │ (record removed) │
               └──────────────────┘
```

### 1.1 Architectural Layers

| Layer | Responsibility | Crate |
|---|---|---|
| Type definitions | `DatasetStateV1` enum, wire format, encode/decode | `tidefs-types-dataset-lifecycle-core` |
| Runtime state machine | Transition logic, pre-condition guards, poison notifications | `tidefs-dataset-lifecycle` |
| Mount gate | `DatasetOpenGate::check()` integrates state + feature flags | `tidefs-local-filesystem` |
| Tombstone reaper | Background task: min-age check, cluster consensus, record removal | `tidefs-dataset-lifecycle` (#1461) |

### 1.2 Cross-Cutting Concerns

- **COMMIT_GROUP consistency**: All state transitions commit through a transaction group
  (COMMIT_GROUP), providing atomicity and crash safety.
- **Poison model**: During `DESTROYING`, active FUSE sessions receive poison
  signals with a configurable grace period before forced unmount.
- **GC coordination**: Pinned traversal roots prevent the garbage collector from
  reclaiming metadata blocks still needed by the destroy worker.
- **Cluster consensus**: The `TOMBSTONE` phase holds the dataset record until all
  peers acknowledge, providing cluster-wide observability before physical removal.

---

## 2. Data Structures

### 2.1 DatasetStateV1 Enum

```rust
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum DatasetStateV1 {
    Active = 0,
    Destroying = 1,
    Tombstone = 2,
    // Reaped = 3 is not stored; it means the record no longer exists.
}
```

Stored as a `u8` field in the dataset record header. The `Reaped` state is
transient: once the record is physically removed, the dataset no longer exists
in the catalog.

### 2.2 DestroyJobRecordV1

Created when transitioning `ACTIVE → DESTROYING`. Persisted alongside the
dataset record so the destroy worker can resume after a crash.

```rust
pub struct DestroyJobRecordV1 {
    pub dataset_guid: u64,
    pub started_commit_group: u64,
    pub pinned_roots: Vec<BlockPointer>,
    pub roots_completed: Vec<BlockPointer>,
    pub bytes_total: u64,
    pub bytes_reclaimed: u64,
    pub objects_total: u64,
    pub objects_reclaimed: u64,
}
```

| Field | Purpose |
|---|---|
| `dataset_guid` | Backlink to the owning dataset |
| `started_commit_group` | COMMIT_GROUP at which destroy began; used for crash-recovery ordering |
| `pinned_roots` | GC roots pinned for the duration of the destroy traversal |
| `roots_completed` | Roots whose subtree has been fully reclaimed |
| `bytes_total` / `bytes_reclaimed` | Progress tracking for observability |
| `objects_total` / `objects_reclaimed` | Progress tracking for observability |

### 2.3 PoisonNotification

```rust
pub struct PoisonNotification {
    pub dataset_guid: u64,
    pub grace_period: Duration,  // default: 30s; configurable
    pub force_unmount: bool,     // FORCE_UNMOUNT flag: skip grace, immediate teardown
}
```

### 2.4 DatasetOpenGate

```rust
pub struct DatasetOpenGate;

impl DatasetOpenGate {
    pub fn check(state: DatasetStateV1, features: FeatureFlags) -> Result<(), OpenError> {
        match state {
            DatasetStateV1::Active => Self::check_features(features),
            DatasetStateV1::Destroying => Err(OpenError::DatasetDestroying),
            DatasetStateV1::Tombstone => Err(OpenError::DatasetNotFound),
        }
    }
}
```

---

## 3. Algorithms

### 3.1 ACTIVE → DESTROYING Transition

```
transition_to_destroying(dataset_guid):
  PRE:
    - dataset.state == ACTIVE
    - no clone children exist (EBUSY if clones present)
    - no active lease holders (or lease-drain timeout expired)
  DO:
    1. Set dataset.state = DESTROYING (COMMIT_GROUP-atomic)
    2. Create DestroyJobRecordV1:
       a. Enumerate all root blocks (object tree root, xattr root, ...)
       b. Store in pinned_roots
       c. Register pinned_roots with GC root set
    4. Send PoisonNotification to all active FUSE sessions
    5. Spawn destroy worker task
  POST:
    - dataset.state == DESTROYING
    - DestroyJobRecordV1 persisted
    - All roots pinned against GC
```

### 3.2 Destroy Worker (DESTROYING → TOMBSTONE)

```
destroy_worker(dataset_guid):
  FOR each root in pinned_roots:
    1. Walk the block tree rooted at root
    2. For each data block: reclaim to space allocator
    3. For each metadata block: mark free in metadata allocator
    4. Move root from pinned_roots to roots_completed
    5. Update bytes_reclaimed, objects_reclaimed
    6. Checkpoint DestroyJobRecordV1 (crash-safe progress)
  AFTER all roots complete:
    1. Remove all roots from GC pinned set
    2. Delete DestroyJobRecordV1
    3. Set dataset.state = TOMBSTONE
    4. Record tombstone timestamp
```

**Crash recovery**: On mount/startup, scan for any `DestroyJobRecordV1` with
remaining `pinned_roots`. Resume the worker from the last checkpointed root.

### 3.3 Tombstone Reaper (TOMBSTONE → REAPED)

```
tombstone_reaper():
  PERIODIC (every N commit_groups):
    FOR each dataset with state == TOMBSTONE:
      1. Check age: now - tombstone_timestamp >= min_tombstone_age (default: 100 commit_groups)
      2. Check cluster consensus: all peers in membership acknowledge
      3. If both pass:
         a. Remove dataset record from catalog
         b. Reclaim dataset record metadata blocks
         d. State transitions to REAPED (record no longer exists)
```

### 3.4 DESTROYING → ACTIVE Abort Path

```
abort_destroy(dataset_guid):
  PRE:
    - dataset.state == DESTROYING
    - Admin authorization confirmed
  DO:
    1. Cancel destroy worker task
    2. Remove remaining pinned_roots from GC set
    3. Delete DestroyJobRecordV1
    4. Set dataset.state = ACTIVE
  NOTE:
    - Already-reclaimed blocks are NOT recovered (too complex, low value)
    - Dataset is mountable but may have lost some data
    - Aborted destroy is logged prominently for operator awareness
```

### 3.5 Poison State Machine (FUSE Daemon)

```
fuse_session_on_poison(notification):
  IF notification.force_unmount:
    - Tear down FUSE session
    - Return
  ELSE:
    - Mark session as poisoned
    - Start grace timer (notification.grace_period)
    - New operations: return EIO
    - In-flight operations: drain naturally
    - On timer expiry: force-close remaining handles, tear down session
```

---

## 4. Tradeoffs

### 4.1 Async Destroy vs. Immediate Destroy

| Tradeoff | Decision | Rationale |
|---|---|---|
| Blocking COMMIT_GROUP pipeline | Async design target over immediate prior-art coupling | Large dataset destroys are a latency pressure in ZFS-style commit_group flows; async destroy targets predictable COMMIT_GROUP commit latency under operational destroy |
| Implementation complexity | Higher with async | Accepted for the design target of predictable COMMIT_GROUP commit latency under operational destroy |
| Crash recovery surface | Larger with async | DestroyJobRecordV1 checkpoints make it crash-safe; acceptable cost |

### 4.2 Tombstone Phase Retention

| Tradeoff | Decision | Rationale |
|---|---|---|
| Catalog bloat vs. observability | Retain tombstone record | Cluster-wide visibility of destroy-in-progress prevents stale-peer race conditions |
| Minimum tombstone age | 100 commit_groups (~100s) default, configurable | Long enough for cluster gossip + consensus; adjustable for deployment latency |

### 4.3 Abort Capability

| Tradeoff | Decision | Rationale |
|---|---|---|
| Recover freed blocks on abort | NOT recovered | Too complex (reverse allocator, COMMIT_GROUP ordering issues); low operational value |
| Safety of aborted dataset | Dataset is mountable but may have lost data | Operator is warned; use case is oops-wrong-dataset not recover-all-data |
| Abort permission model | Admin-only, logged | Prevents accidental abort; audit trail for safety review |

### 4.4 Cluster Consensus Integration

| Tradeoff | Decision | Rationale |
|---|---|---|
| Block on all peers vs. majority | All peers (for now) | Membership is small (≤32 nodes); full acknowledgment is stronger |
| Partition tolerance | Tombstone persists until consensus | Split-brain safety: no peer sees REAPED until all acknowledge |

### 4.5 Mount Safety

| Tradeoff | Decision | Rationale |
|---|---|---|
| State check location | DatasetOpenGate::check() in mount path | Single choke point; cannot miss a state transition |
| Atomicity of check+action | Guarded by dataset record lock held across check and mount | Prevents TOCTOU race between state check and FUSE session creation |
| Late-arriving mount during DESTROYING | Refused with ENOENT | No window where a stale client can mount a destroying dataset |

---

## 5. Implementation Status

| Phase | Description | Status | Crate |
|---|---|---|---|
| Phase 1 | DatasetStateV1 types + mount gating | **implemented** | tidefs-types-dataset-lifecycle-core |
| Phase 2 | Runtime state machine (DatasetLifecycle) | **implemented** | tidefs-dataset-lifecycle |
| Phase 3 | Poison semantics (FUSE daemon) | **deferred** | wire-up issue needed |
| Phase 4 | Pinned traversal roots (GC integration) | **deferred** | wire-up issue needed |
| Phase 5 | Destroy worker (block traversal + reclamation) | **deferred** | wire-up issue needed |
| Phase 6 | Tombstone reaper runtime | **implemented** | #1461 |
| Phase 7 | Cluster consensus integration | **deferred** | wire-up issue needed |

---



- `cargo check --workspace`: All existing lifecycle crates compile without errors.
- `tidefs-xtask check-dataset-lifecycle`: Full test suite for implemented phases.
- QEMU smoke test: Create dataset → mount via FUSE → destroy → verify ENOENT on remount.

For deferred phases (3–5, 7), wire-up issues must reference this document as the
authoritative specification and include their own focused test coverage.

---

## 7. References

- Canonical spec: `docs/design/dataset-lifecycle-state-machine.md` (#1634, #1903, #2080)
- Original spec: `docs/DATASET_LIFECYCLE_DESIGN.md` (#1219)
- Interim update: #1560
- Related: #1223 (feature flags), #1267 (COMMIT_GROUP state machine), #1283 (cluster membership),
  #1207 (orphan index), #1254 (pool import/export), #1213 (VFS Engine API)
- Prior confirmation: #2080 (implementation confirmed)

---

**Design-spec sealed**: 2026-05-05. Rust implementation of Phases 3–5 and 7 deferred
to wire-up issues per the implementation plan in the canonical specification.
