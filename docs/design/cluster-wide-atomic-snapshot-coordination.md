# Cluster-Wide Atomic Snapshot Coordination — Design Specification

**Issue**: [#1772](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1772)
**Status**: design-spec (design-only; Rust impl deferred to wire-up issues)
**Priority**: P2
**Lane**: storage-core (coordination)
**Milestone**: DESIGN-M4: Cluster Infrastructure (Layers 8-11)
**Depends on**: #1232 (snapshot deadlist pinning), #1219 (dataset lifecycle), #1243 (ADMIN wire protocol), #1267 (commit_group state machine), #1252 (LOG_DEVICE/intent log), #1209 (MEMBERSHIP service)
**Blocks**: #1251 (cluster snapshot as send/recv unit)
**Related**: #1210 (transport boundedness), #1228 (cluster security), #1248 (distributed lock service), #1283 (cluster membership consensus), #1285 (extent maps/locator tables)
**Implementation crate**: `crates/tidefs-cluster-snapshot`

## Abstract

This document defines cluster-wide atomic snapshot coordination for tidefs:
a coordinated consistent-cut freeze protocol that captures a single
point-in-time across all participating cluster nodes, a cluster-wide snapshot
catalog for cross-node visibility, partial-participation semantics for
unreachable nodes, and integration with the MEMBERSHIP service (#1209), commit_group
state machine (#1267), intent log drain (#1252), publication pipeline, and
snapshot deadlist pinning (#1232).

ZFS snapshots are local-only — a pool can be snapshotted on one node, but
there is no concept of a cluster-wide consistent snapshot. CephFS supports
per-directory snapshots, but multi-MDS snapshot consistency is complex and
unreliable. Neither has true cluster-wide atomic snapshots.

tidefs beats both by designing snapshots that are:
- **Cluster-wide atomic**: a snapshot freezes a consistent point-in-time
  across all nodes
- **Zero-downtime**: snapshot creation doesn't pause IO
- **Cluster-addressable**: the snapshot is visible from any node

---

## 1. Problem Statement

### 1.1 Current baseline

Local snapshots (#1232, OW-108) provide per-node, per-dataset snapshot
capabilities: named references to an authenticated committed-root, rollback
that publishes a new authenticated root, deadlist-based space pinning with
O(log n) create cost, and safe reclamation that preserves snapshot roots.

Local snapshots are correct and implementation-tracked non-release, but they are **single-node**:
a snapshot on node A has no relationship to a snapshot on node B, even if
both nodes hold datasets within the same cluster. There is no way to issue
a single command and obtain a consistent point-in-time image across all
nodes.

### 1.2 Cluster-wide requirements

1. **Cross-node consistency**: when a cluster snapshot is taken, every
   participating dataset must be frozen at the same cluster-wide commit_group
   boundary — no racing writes across nodes can straddle the snapshot
   point.
2. **Zero-downtime**: snapshot creation must not pause reads or require
   unmounting. Writers experience a brief gate on new commit_group formation only.
3. **Partial participation**: if a node is unreachable or unresponsive,
   the snapshot proceeds for the participating subset. The snapshot
   record explicitly lists which nodes participated.
4. **Global visibility**: any node can enumerate cluster snapshots,
   retrieve the cluster-wide snapshot catalog, and map cluster snapshot
   IDs to local snapshot IDs.
5. **Cluster-aware destroy**: destroying a cluster snapshot propagates
   to all participating nodes.
6. **Send/recv integration**: cluster snapshots can be sent (#1251) as
   a unit, preserving the cluster snapshot catalog on the receiver.

### 1.3 Service gap

The ADMIN service (#1243) defines `SNAPSHOT_CREATE` (method 0x06) and
`SNAPSHOT_DESTROY` (method 0x07) as single-node operations. There is no:

- Distributed snapshot barrier protocol
- Cluster-wide snapshot catalog
- Partial-participation handling
- Cross-node snapshot ID mapping
- Quiesce coordination across writers

This design fills all of these gaps.

---

## 2. Architecture Overview

### 2.1 High-level flow

```
  ADMIN client (any node)
       │
       │ SNAPSHOT_CREATE(cluster_wide=true, snap_name)
       ▼
  ┌─────────────────────┐
  │  LEADER node         │
  │  (cluster snapshot   │
  │   coordinator)       │
  └──────┬──────────────┘
         │
         │ Phase 1: SnapshotFreeze broadcast
         │ ─────────────────────────────────────►
         ▼                                         ▼
  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
  │  Writer Node  │  │  Writer Node  │  │  Writer Node  │
  │  (dataset A)  │  │  (dataset B)  │  │  (dataset C)  │
  │               │  │               │  │               │
  │  1. Gate new  │  │  1. Gate new  │  │  1. Gate new  │
  │     commit_group form  │  │     commit_group form  │  │     commit_group form  │
  │  2. Drain      │  │  2. Drain      │  │  2. Drain      │
  │     intent log │  │     intent log │  │     intent log │
  │  3. Freeze     │  │  3. Freeze     │  │  3. Freeze     │
  │     local state│  │     local state│  │     local state│
  │  4. Acknowledge│  │  4. Acknowledge│  │  4. Acknowledge│
  └──────┬────────┘  └──────┬────────┘  └──────┬────────┘
         │                  │                  │
         │ Phase 2: All acks → commit          │
         │ ◄───────────────────────────────────┘
         ▼
  ┌─────────────────────┐
  │  LEADER:             │
  │  1. Build record     │
  │  2. Persist catalog  │
  │  3. Return to caller │
  └─────────────────────┘
```

### 2.2 Protocol phases (as implemented)

| Phase | State | Action |
|-------|-------|--------|
| 0 | Readiness check | Verify drift class, config class, member health, lease health |
| 1 | Propose (Freezing) | Coordinator seals publication pipeline, broadcasts `SnapshotFreeze` |
| 2 | Freeze (Freezing→Frozen) | Each member drains intent log, freezes local state, acknowledges |
| 3 | Commit (Frozen→Committed) | Coordinator persists `ClusterSnapshotRecord` to catalog |
| 4 | Release (Committed→Idle) | Members release snapshot gate, resume commit_group formation |

### 2.3 Coordinator-centric design

The MEMBERSHIP service leader is also the snapshot coordinator. This avoids
distributed consensus: the leader already maintains a durable journal (commit_group
state machine #1267) and a view of all cluster state. Leader-coordinated
snapshots require fewer round trips and integrate naturally with the existing
architecture.

---

## 3. Detailed Protocol Walkthrough

### 3.1 Phase 0: Readiness Check

Before proposing a snapshot, the coordinator evaluates four safety gates:

1. **Drift class safety**: Only `DriftClass` values that allow authority
   movement (`TrustedLocal`, `NominalCluster`, `ElevatedCluster`) are safe.
   `UntrustedTime` is rejected — you cannot take a consistent-cut snapshot
   when clocks are untrusted.

2. **Config class**: Must be `ConfigClass::Normal` (c1). Non-normal config
   classes (degraded, reconfiguring, joint-consensus) are unsafe because
   the membership set is in flux.

3. **Member health**: Every cohort member must be a voter (`can_vote()`) and
   must admit new work (`admits_new_work()`). Unhealthy or non-voter members
   are blocking preconditions.

4. **Lease health**: All leases must be in `Granted` or `Renewing` state.
   Leases in grace, expired, or failover-staged states block the snapshot
   because the writer lease is the coherency enforcement mechanism.

The result is a `SnapshotReadiness` struct:

```rust
pub struct SnapshotReadiness {
    pub ready: bool,
    pub drift_class: DriftClass,
    pub config_class_ok: bool,
    pub all_members_healthy: bool,
    pub all_leases_healthy: bool,
    pub blocking_reasons: Vec<String>,
}
```

### 3.2 Phase 1: Propose (coordinator enters Freezing)

The coordinator constructs a `ClusterSnapshotProposal`:

```rust
pub struct ClusterSnapshotProposal {
    pub snap_id: u64,               // monotonic, assigned by coordinator
    pub epoch: EpochId,              // current membership epoch
    pub publication_cut_ref: u64,    // publication pipeline cut (freeze frontier)
    pub proposed_at_ns: u64,         // monotonic timestamp at proposal
    pub freeze_deadline_ns: u64,     // absolute deadline for freeze phase
    pub drift_class: DriftClass,     // snapshot of drift class at proposal time
    pub members_cohort: Vec<MemberId>,  // cohort members to freeze
    pub parent_snap_id: Option<u64>,    // parent snapshot (for diffs)
}
```

The coordinator seals the publication pipeline at `publication_cut_ref`,
broadcasts the proposal to the cohort, and enters `Freezing` state. Only
voter members in the current epoch are included in the cohort.

**Preconditions:**
- No active snapshot in progress (state must be `Idle`)
- `snap_id` must not already exist in the catalog
- The cohort must be non-empty
- Drift class must be safe

### 3.3 Phase 2: Member Freeze (coordinator waits for acks)

Each cohort member receives the proposal and:

1. **Gates new commit_group formation**: Sets `snapshot_quiesce_pending = true` on
   the commit_group state machine (#1267). Writers can finish the current OPEN commit_group
   but cannot start a new one.

2. **Drains the intent log**: Flushes all pending writes in the log device/intent
   log (#1252) so the frozen state is complete.

3. **Freezes local state**: Captures the local committed root at the
   publication cut frontier.

4. **Creates a `SnapshotFreeze` acknowledgment**:

```rust
pub struct SnapshotFreeze {
    pub snap_id: u64,
    pub member_id: MemberId,
    pub epoch: EpochId,
    pub publication_cut_ref: u64,
    pub local_snap_id: u64,         // local snapshot id on this member
    pub root_commit_id: u64,        // committed root id at freeze point
    pub frozen_at_ns: u64,          // local monotonic timestamp
    pub accepted: bool,             // true = freeze succeeded
    pub refuse_reason: Option<String>,  // set if refused
}
```

The coordinator calls `record_freeze_ack()` for each arriving ack. A variant
`record_freeze_ack_with_deadline()` enforces the freeze deadline, returning
`FreezeDeadlineExceeded` if the deadline has passed.

When all cohort members have acknowledged (and all `accepted == true`), the
coordinator returns a `ClusterSnapshotCommit` value and the active snapshot
transitions to `Frozen`.

**Refusal paths:**
- If any member responds with `accepted == false`, the coordinator aborts
  with `MemberRefused` containing the refusal reason.
- If the freeze deadline is exceeded before all acks arrive, the coordinator
  has two options: abort (clean), or commit degraded (see §3.5).

### 3.4 Phase 3: Commit (coordinator persists to catalog)

The coordinator calls `commit_snapshot()` to finalize:

```rust
pub struct ClusterSnapshotCommit {
    pub snap_id: u64,
    pub epoch: EpochId,
    pub publication_cut_ref: u64,
    pub committed_at_ns: u64,
    pub member_snaps: Vec<MemberSnapshotRef>,
    pub degraded: bool,
    pub degraded_reason: Option<String>,
}

pub struct MemberSnapshotRef {
    pub member_id: MemberId,
    pub local_snap_id: u64,
    pub root_commit_id: u64,
    pub publication_cut_ref: u64,
    pub frozen_at_ns: u64,
}
```

The `ClusterSnapshotRecord` is persisted to the catalog:

```rust
pub struct ClusterSnapshotRecord {
    pub snap_id: u64,
    pub epoch: EpochId,
    pub publication_cut_ref: u64,
    pub member_snaps: Vec<MemberSnapshotRef>,
    pub frozen_at_ns: u64,
    pub committed_at_ns: u64,
    pub freeze_deadline_ns: u64,
    pub degraded: bool,
    pub degraded_reason: Option<String>,
    pub parent_snap_id: Option<u64>,
}
```

**Preconditions for commit:**
- Active snapshot must be in `Frozen` state
- Must have acks from ALL cohort members (for clean commit)
- `snap_id` must not already exist in the catalog

### 3.5 Degraded Snapshots (partial participation)

When not all cohort members respond within the deadline, the coordinator can
call `commit_degraded()` to proceed with the subset that did acknowledge:

```rust
pub fn commit_degraded(
    &mut self,
    snap_id: u64,
    committed_at_ns: u64,
    reason: String,
) -> Result<ClusterSnapshotCommit, ClusterSnapshotError>
```

- The resulting record has `degraded = true` and `degraded_reason` set.
- At least **one** member must acknowledge — zero-ack commits are rejected
  with `InsufficientAcks`.
- Degraded snapshots are valid; they simply document which nodes did and
  did not participate.

### 3.6 Phase 4: Release

After commit, each member releases the snapshot gate (`snapshot_quiesce_pending
= false`) and resumes normal commit_group cycling. The coordinator calls
`release_snapshot()` to transition the snapshot state from `Committed`
through `Releasing` back to `Idle`. In the current implementation, release
is a no-op at the coordinator level — per-member resource release is handled
independently by each node.

### 3.7 Abort Paths

The coordinator can abort an in-progress snapshot under these conditions:

| Condition | Method | Effect |
|-----------|--------|--------|
| Member refusal | `abort_snapshot(snap_id)` | Clears active state; catalog unchanged |
| Deadline exceeded | `abort_snapshot_with_escalation(snap_id, now)` | Clears; returns `DeadlineEscalationReceipt` |
| Epoch change | `handle_epoch_change(snap_id, new_epoch)` | Clears; returns `EpochChanged` error |

The abort path never modifies the catalog. The `snap_id` can be reused for
a subsequent proposal after abort.

---

## 4. Core Data Structures

### 4.1 ClusterSnapshotCatalog

The persistent catalog on the coordinator node indexes all committed cluster
snapshots and their tombstones:

```rust
pub struct ClusterSnapshotCatalog {
    records: BTreeMap<u64, ClusterSnapshotRecord>,    // snap_id → record
    tombstones: BTreeMap<u64, ClusterSnapshotTombstone>, // snap_id → tombstone
}
```

Key operations:
- `insert(record)` — add a committed snapshot
- `get(snap_id)` — look up by id
- `remove(snap_id)` — remove (caller should also record tombstone)
- `len()`, `is_empty()`
- `latest()` — highest snap_id
- `record_tombstone(tombstone)` — immutable audit trail
- `get_tombstone(snap_id)`, `is_tombstoned(snap_id)` — tombstone queries
- `list_tombstones()` — full audit trail

### 4.2 Snapshot ID space

`snap_id` is a `u64`, assigned monotonically by the coordinator. It is:

- Never reused, even after destroy (tombstone prevents zombie snapshots)
- Stable across leader failover (recovered from catalog)
- Used as the cluster-wide identifier visible to all nodes

### 4.3 Cross-node mapping

Each participating node maintains a local mapping:

```
(cluster_snap_id, dataset_id) → local_snap_id
```

This mapping is stored alongside the local snapshot catalog (#1232). It allows
any node to answer "what is the local snapshot id for cluster snapshot X on
dataset Y?"

### 4.4 ClusterSnapshotTombstone

When a cluster snapshot is deleted, an immutable tombstone is recorded:

```rust
pub struct ClusterSnapshotTombstone {
    pub snap_id: u64,
    pub deleted_at_ns: u64,
    pub deleted_by: MemberId,
    pub reason: String,
}
```

Properties:
- `snap_id` is never reused after tombstone is recorded
- `deleted_by` identifies the initiating member for audit
- `deleted_at_ns` provides a monotonic timestamp
- `reason` is a free-form human-readable justification
- Double-delete is rejected with `NotFound`

---

## 5. Epoch Binding (P8-02)

Every snapshot is bound to exactly one membership epoch. The `EpochId` is
carried in the proposal and recorded in the `ClusterSnapshotRecord`.

If the membership epoch changes between proposal and commit (node join/leave,
leader failover, joint-consensus transition), the snapshot is aborted with
`ClusterSnapshotError::EpochChanged`. This prevents:

- Split-brain: a snapshot referencing nodes that are no longer cluster members
- Orphaned records: a snapshot committed under an obsolete epoch

All snapshot participants must be voters in the snapshot epoch. Non-voter
members are rejected at readiness check time with `MemberNotVoter`.

---

## 6. Partial Participation

### 6.1 Policy

Nodes that fail to respond in Phase 2 are excluded from the snapshot.
The snapshot is valid for the participating subset. Unanimous participation
is not required. This is by design: requiring all nodes would make snapshots
unavailable during node maintenance, network partitions, or node failures.

### 6.2 Exclusion reasons

| Reason | Handling |
|---|---|
| Node unreachable (transport timeout) | Excluded; snapshot can be committed degraded or aborted |
| Node responds with refusal (`accepted == false`) | Excluded; reason recorded in error |
| Node responds after deadline | Already committed or aborted; late response is ignored |
| Leader fails during Phase 1 | All PREPARE holders time out and release gate |
| Leader fails during Phase 2 | New leader recovers catalog; incomplete snapshot discarded |

### 6.3 Catch-up for excluded nodes

Excluded nodes' datasets will be at an older commit_group than the snapshot's
`publication_cut_ref`. They can catch up later:
- The cluster snapshot record explicitly lists which nodes participated.
- An excluded node that later becomes reachable can create a local snapshot
  at the cluster `publication_cut_ref` retroactively, provided its commit_group log
  still covers that cut (i.e., the commit_group hasn't been reclaimed).
- If the commit_group has been reclaimed, the node cannot join the snapshot — it
  must use a later snapshot.

### 6.4 Minimum participation

At least one member must acknowledge. Zero-ack commits are rejected with
`InsufficientAcks`. If no nodes respond at all, the snapshot fails.

---

## 7. Snapshot Diff Algorithm

`diff_snapshots(&from, &to)` computes the set difference between two
committed `ClusterSnapshotRecord` values:

```rust
pub struct SnapshotDiff {
    pub added_members: Vec<MemberId>,
    pub removed_members: Vec<MemberId>,
    pub changed_members: Vec<MemberId>,
    pub changed_root_commits: Vec<(MemberId, u64, u64)>, // (member, from_root, to_root)
}
```

Algorithm:
1. Build `BTreeSet<MemberId>` from `from.member_snaps` and `to.member_snaps`
2. `added_members` = in `to` but not `from`
3. `removed_members` = in `from` but not `to`
4. For members in both: compare `root_commit_id`; if different, add to
   `changed_members` and `changed_root_commits`

This is used for:
- Incremental send/receive (only ship changed roots)
- Diagnosing snapshot drift across nodes
- Monitoring snapshot coverage

---

## 8. Snapshot Destroy

### 8.1 Delete protocol

Snapshot destroy removes a committed cluster snapshot from the catalog and
records a tombstone:

2. **Remove from catalog**: `catalog.remove(snap_id)`
3. **Record tombstone**: An immutable `ClusterSnapshotTombstone` is written
   to the catalog for audit trail.
4. **Return tombstone**: The caller receives the tombstone for logging.

### 8.2 Partial destroy

If a node is unreachable during destroy, its local snapshot cleanup is
rejoins, it receives the pending destroy list and cleans up.

### 8.3 Idempotency

Double-delete is rejected with `NotFound`. The tombstone is never removed

---

## 9. Publication Pipeline and Lease Integration

The crate provides integration helpers for the publication pipeline and
distributed lease systems:

```rust
/// The seal trigger class for snapshot freeze.
pub const fn snapshot_seal_trigger() -> PublicationPipelineSealTriggerClass;

/// The lease domain under which the snapshot lease is acquired, scoped per-snapshot.
pub fn snapshot_lease_domain(snap_id: u64) -> LeaseDomain;

/// Resolve a member's snapshot location within a cluster snapshot record.
pub fn resolve_subject_location(
    record: &ClusterSnapshotRecord,
    member_id: MemberId,
) -> Option<&MemberSnapshotRef>;
```

These allow the ADMIN service and transport layer to:
- Seal the publication pipeline at the snapshot freeze frontier
- Acquire per-snapshot leases for distributed coordination
- Map cluster snapshot membership to individual node snapshot locations

---

## 10. Consistency Guarantees

| Guarantee | Mechanism |
|---|---|
| **Filesystem consistency** | Each dataset is fsck-clean at its freeze point. Local snapshots are created from authenticated committed roots, which are always consistent by construction (#1267 invariant). |
| **Cross-node consistency** | All participating nodes freeze at the same `publication_cut_ref`. No write that straddles the cut is included in the snapshot. |
| **Atomicity** | The snapshot either succeeds (all acks, record in catalog) or is aborted (no record, gates released). No partial state. |
| **Durability** | The `ClusterSnapshotRecord` is persisted to the coordinator's catalog before the snapshot is considered committed. |
| **Epoch safety** | Epoch change during the protocol aborts the snapshot. No snapshot can reference a stale epoch. |
| **Tombstone immutability** | Once deleted, a `snap_id` is never reused and the tombstone is permanent. |

### 10.1 What is NOT guaranteed (V1)

- **Zero-RPO across nodes**: The snapshot is crash-consistent, not
  application-consistent. Applications must quiesce at the application level
  for full consistency.
- **Unanimous participation**: Excluded nodes are not in the snapshot. The
  consumer must check `node_membership` and `degraded` fields.
- **Cross-cluster consistency**: Snapshots are per-cluster. Cross-cluster
  consistency requires send/recv (#1251).

---

## 11. Error Model

All errors are enumerated in `ClusterSnapshotError`:

| Error variant | Trigger | Recovery |
|---|---|---|
| `NotFound` | snap_id not in catalog | Check catalog before operating |
| `Duplicate` | snap_id already exists | Use a different snap_id |
| `InvalidState` | Wrong state for operation | Check coordinator state |
| `FreezeDeadlineExceeded` | Deadline passed before all acks | Abort or commit degraded |
| `InsufficientAcks` | Not enough member acks | Wait for more members or abort |
| `MemberRefused` | Member rejected freeze | Investigate refusal reason |
| `EpochChanged` | Membership epoch changed mid-protocol | Retry with new epoch |
| `MemberNotVoter` | Non-voter in cohort | Exclude non-voters from cohort |
| `MemberUnhealthy` | Unhealthy member in cohort | Wait for member recovery |
| `LeaseUnhealthy` | Lease in terminal/grace state | Wait for lease renewal |
| `DriftClassUnsafe` | Untrusted time source | Fix clock synchronization |
| `NoMembersCohorted` | Empty cohort | Add voters to cohort |
| `ConfigClassNotNormal` | Non-normal config class | Wait for normal config |

---

## 12. Testing Strategy

The `tidefs-cluster-snapshot` crate includes a comprehensive test suite
covering the following acceptance criteria:

| Test | Criterion |
|---|---|
| `test_successful_snapshot_create_and_commit` | 3-member clean create + commit |
| `test_duplicate_proposal_rejected` | Duplicate `snap_id` rejected |
| `test_insufficient_acks_rejected` | Commit before all acks rejected |
| `test_freeze_deadline_exceeded` | Deadline enforcement works |
| `test_member_refusal_aborts` | Member refusal with reason |
| `test_state_machine_transitions` | All invalid transitions rejected |
| `test_degraded_commit` | Partial participation with reason |
| `test_abort_and_repropose` | Same `snap_id` reusable after abort |
| `test_epoch_change_during_freeze_aborts` | Epoch binding enforcement |
| `test_snapshot_delete_with_tombstone_audit_trail` | Delete + tombstone + double-delete |
| `test_snapshot_diff` | Diff computation correctness |
| `test_readiness_checks` | Health/drift/config preconditions |
| `test_subject_location_resolution` | Member lookup in record |

---

## 13. ADMIN Service Integration (future)

### 13.1 SNAPSHOT_CREATE extension

The ADMIN `SNAPSHOT_CREATE` method (0x06) is extended with:

- `cluster_wide: bool` flag — when `true`, routes through the cluster
  snapshot coordinator instead of the local snapshot path.
- `freeze_deadline_ms: Option<u32>` — optional override for the freeze
  deadline (default: 500 ms).
- Response includes `cluster_snap_id` and participant list.

### 13.2 SNAPSHOT_DESTROY extension

The ADMIN `SNAPSHOT_DESTROY` method (0x07) accepts:

- `cluster_snap_id: Option<u64>` — when set, destroys the cluster snapshot
  and propagates to all participants.

### 13.3 LIST_SNAPSHOTS extension

`LIST_SNAPSHOTS` (0x0E) gains a `cluster_wide: Option<bool>` filter to
return cluster-wide snapshots, local-only snapshots, or both.

### 13.4 GET_SNAPSHOT_STATUS

A new query `GET_SNAPSHOT_STATUS` (0x0F) accepts a `cluster_snap_id` and
returns detailed participation info:

```
ClusterSnapshotStatusV1:
  cluster_snap_id: u64
  snap_name: Vec<u8>
  creation_time: Timestamp
  publication_cut_ref: u64
  degraded: bool
  participant_count: u32
  participants: Vec<ClusterSnapshotParticipantV1>
```

---

## 14. Observability

### 14.1 Metrics (future)

| Metric | Type | Description |
|---|---|---|
| `tidefs_cluster_snapshot_create_total` | Counter | Successful snapshot creates |
| `tidefs_cluster_snapshot_abort_total` | Counter | Aborted snapshot attempts |
| `tidefs_cluster_snapshot_degraded_total` | Counter | Degraded (partial participation) snapshots |
| `tidefs_cluster_snapshot_destroy_total` | Counter | Successful destroys |
| `tidefs_cluster_snapshot_active_count` | Gauge | Active cluster snapshots |
| `tidefs_cluster_snapshot_freeze_latency_us` | Histogram | Freeze phase duration |

### 14.2 ADMIN queries

- `LIST_SNAPSHOTS` with `cluster_wide=true` returns all cluster snapshots
- `GET_SNAPSHOT_STATUS` with `cluster_snap_id` returns detailed participation

---

## 15. Tradeoffs and Design Decisions

### 15.1 Why leader-coordinated and not peer-to-peer?

A peer-to-peer barrier (e.g., each node independently agrees on a commit_group via
Paxos) would be more complex and slower. The leader already has:
- A view of all cluster state (MEMBERSHIP #1209)
- A journal for durable metadata (commit_group state machine #1267)
- The ADMIN service for operator interaction (#1243)

Leader coordination is simpler, faster (fewer round trips), and integrates
naturally with the existing architecture.

### 15.2 Why gate commit_group formation and not quiesce all IO?

Gating only new commit_group formation (not all IO) means:
- Reads are never paused.
- Writes continue into the current OPEN commit_group.
- The gate duration is bounded by the time to complete the current commit_group
  plus network RTT (< 250 ms).
- If we quiesced all IO (ZFS-style pool freeze), a slow disk could block
  the snapshot indefinitely.

### 15.3 Why max publication cut and not min?

Using the coordinator's `publication_cut_ref` (which is the max across all
nodes at proposal time) as the snapshot frontier means no node is ahead of
the snapshot. Nodes below the frontier will catch up naturally through
normal commit_group cycling. Using `min(all node_commit_group)` would lose writes that
completed on faster nodes before the snapshot.

### 15.4 Why not require unanimous participation?

Requiring all nodes to participate would make the snapshot unavailable during:
- Node maintenance (reboot, upgrade)
- Network partitions
- Node failures

Partial participation makes cluster snapshots robust. The snapshot record
explicitly lists participants and marks the snapshot as `degraded` when
not all members participated.

### 15.5 Why tombstones and not reuse?

Reusing `snap_id` values after destroy would create ambiguity: was snapshot
42 the one from last week or a new one? Tombstones make the ID space
monotonic and auditable. The cost is negligible (a small B-tree entry per
deleted snapshot).

### 15.6 Why readiness gates at proposal time?

Checking drift, config, member health, and lease health before proposing
avoids wasted work: if the cluster isn't ready, the snapshot would be
aborted anyway. Early rejection gives faster feedback to the caller.

---

## 16. ZFS/Ceph Comparison

| Feature | ZFS | CephFS | tidefs |
|---|---|---|---|
| Local snapshots | Yes (per-pool) | Yes (per-directory) | Yes (per-dataset, #1232) |
| Cluster-wide atomic snapshots | No | No (multi-MDS unreliable) | **Yes (this design)** |
| Zero-downtime snapshot | Yes (commit_group-based) | Partial (MDS quiesce) | Yes |
| Partial participation | N/A | N/A | Yes (degraded snapshots) |
| Snapshot barrier | N/A (local only) | MDS quiesce (per-MDS) | Leader-coordinated freeze |
| Cross-node catalog | N/A | N/A | Yes (`ClusterSnapshotCatalog`) |
| Cluster-aware destroy | N/A | N/A | Yes (with tombstones) |
| Snapshot diffs | `zfs diff` | None | `diff_snapshots()` |
| Audit trail | None | None | `ClusterSnapshotTombstone` |

---

## 17. Implementation Phases

### Phase 1: Core types and catalog ✅ (completed)
- `ClusterSnapshotRecord`, `ClusterSnapshotProposal`, `SnapshotFreeze`,
  `ClusterSnapshotCommit`, `ClusterSnapshotTombstone`, `SnapshotReadiness`,
  `SnapshotDiff`, `ClusterSnapshotCatalog`
- Coordinator state machine (`SnapshotState`)
- Full test suite
- Crate: `tidefs-cluster-snapshot`

### Phase 2: ADMIN service wire-up (future)
- Wire `SNAPSHOT_CREATE` and `SNAPSHOT_DESTROY` to the coordinator
- Add `cluster_wide` flag handling
- Add `LIST_SNAPSHOTS` cluster-wide filter
- Add `GET_SNAPSHOT_STATUS` for cluster snapshots

### Phase 3: Distributed barrier protocol (future)
- Implement `SnapshotFreeze` / `SnapshotCommit` message routing over transport (#1210)
- Implement commit_group gate (`gate_next_commit_group_formation`, `release_snapshot_gate`)
- Implement intent log drain integration (#1252)
- Implement deadline-based timeout with escalation

### Phase 4: Snapshot destroy propagation (future)
- Implement `SnapshotDestroyV1` / `SnapshotDestroyedV1` message handling
- Implement partial destroy with pending-destroy list
- Implement DESTROYING state transition

### Phase 5: Leader failover (future)
- Implement catalog recovery from journal on leader change
- Implement in-progress operation resumption
- Implement stale-term message rejection

### Phase 6: Send/recv integration (deferred to #1251)
- Implement cluster snapshot serialization for send/recv
- Implement catalog reconstruction on receive

---

## 18. Implementation Status (v0.421+)

**Completed in `crates/tidefs-cluster-snapshot`:**
- ✅ Core types: all public structs and enums defined and documented
- ✅ State machine: full lifecycle with all transitions and guards
- ✅ Coordinator: `ClusterSnapshotCoordinator` with propose, freeze, commit, abort, release
- ✅ Catalog: `ClusterSnapshotCatalog` with CRUD, tombstones, and queries
- ✅ Readiness gates: drift class, config class, member health, lease health
- ✅ Epoch binding: abort on epoch change
- ✅ Degraded snapshots: `commit_degraded()` with partial participation
- ✅ Snapshot diff: `diff_snapshots()` for incremental operations
- ✅ Tombstone audit trail: immutable delete records
- ✅ Publication pipeline integration: `snapshot_seal_trigger()`
- ✅ Lease domain scoping: `snapshot_lease_domain()`
- ✅ Comprehensive test suite: 13 acceptance criteria covered

**Pending wire-up:**
- ADMIN service integration (#1243)
- Distributed barrier protocol over transport (#1210)
- Intent log drain integration (#1252)
- Leader failover and catalog recovery
- Send/recv integration (#1251)
- Crash injection testing (#1230)

---

## 19. References

- [#1232] Snapshot deadlist pinning design (`docs/SNAPSHOT_DEADLIST_PINNING_DESIGN.md`)
- [#1219] Dataset lifecycle state machine
- [#1243] ADMIN service wire protocol
- [#1267] Canonical commit ordering and commit_group state machine (`docs/COMMIT_GROUP_STATE_MACHINE_DESIGN.md`)
- [#1252] Intent log and LOG_DEVICE design
- [#1209] MEMBERSHIP service design (`docs/MEMBERSHIP_SERVICE_DESIGN.md`)
- [#1251] Send/receive changed-record stream
- [#1210] Transport boundedness design (`docs/CLUSTER_TRANSPORT_BOUNDEDNESS_DESIGN.md`)
- [#1228] Cluster security and identity model
- [#1283] Cluster membership consensus
- [#1285] Extent maps and locator tables
- [OW-108] Local snapshots and rollback (`docs/LOCAL_SNAPSHOTS_OW108.md`)
- [P8-02] Membership placement and failure domain model (`docs/MEMBERSHIP_PLACEMENT_FAILURE_DOMAIN_MODEL_P8-02.md`)
- [P8-03] Replication, rebuild, relocation data flows (`docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md`)
- Implementation: `crates/tidefs-cluster-snapshot/src/lib.rs`

---

*Drafted: 2026-05-03. Updated: 2026-05-04 (issue #1613 — design finalized; crate implementation completed; issue #1662 — design document verified and re-linked). Verified: 2026-05-05 (issue #1772 — design-only gate; cargo check passes).*
