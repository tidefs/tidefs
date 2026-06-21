# MEMBERSHIP Service Design

Maturity: **design-spec** for the cluster membership service (service_id = 0x02)
that provides mount registration, heartbeat-based liveness, leader-aggregated
cluster views, joint-consensus membership changes, and topology-aware coherency
auto-detection.

This document closes Forgejo issue #1209.

## Incumbent Comparison Boundary

This imported design document uses ZFS and Ceph as historical design inputs
for cluster-membership shape. The comparison rows below are design lessons,
not current TideFS capability, distributed-availability, scale, performance,
operator-readiness, or successor claims. Current registry authority records no
validated cluster-membership claim; any future product-facing comparison must
name a #875 claim id and carry the comparator evidence required by #928/#930.

## 1. Motivation

A topology-aware coherency profile (`auto` from #1184) requires every node to
know which nodes currently have a dataset mounted, in what mode, and who holds
the writer lease. Without a cluster membership service, the daemon cannot
automatically select between `strict`, `perf`, or `cluster` caching behavior.

Neither ZFS nor Ceph provides a clean membership primitive:

- **ZFS** has no native cluster membership at all — multi-node ZFS is
  confined to HA failover pairs with external STONITH, not general cluster
  membership with mount registration.
- **Ceph** ties membership to the monitor's OSDMap, which grows without bound
  and embeds per-OSD state rather than per-dataset mount state. The monitor
  must be consulted for every coherency decision, creating a scalability
  bottleneck that tidefs explicitly avoids (#1283).

tidefs needs a purpose-built MEMBERSHIP service that is:
- Advisory for coherency decisions (writer lease remains the enforcement mechanism)
- Lightweight (heartbeat + mount report, not full state replication)
- Deterministic (joint consensus for membership changes, not gossip-based eventual consistency)
- Topology-aware (failure-domain binding from `tidefs-membership-epoch` P8-02 model)

## 2. Design Overview

The MEMBERSHIP service (service_id = 0x02) operates over the cluster transport
(#1229, #1210) and provides three primary functions:

| Function | Mechanism | Frequency |
|----------|-----------|-----------|
| Node liveness + mount registration | `HEARTBEAT` messages from node to leader | Configurable interval (default: 500 ms) |
| Cluster-wide mount view aggregation | Leader aggregates `HEARTBEAT` payloads, broadcasts `CLUSTER_VIEW` | On any membership or mount change |
| Leader discovery + redirect | `JOIN`/`JOIN_ACK` with `LEADER_REDIRECT` hint | On connect, on leader change |

The service does **not**:
- Replicate dataset state (that's the transport layer's job)
- Provide distributed locking (that's #1248)
- Enforce coherency (writer lease is the correctness mechanism)
- Replace the `tidefs-membership-epoch` model (it consumes it)

### 2.1 Relationship to tidefs-membership-epoch

The `tidefs-membership-epoch` crate (P8-02 model) defines the deterministic
member classes, failure-domain bindings, config epochs, cohort populations,
and split-brain hazard laws. The MEMBERSHIP service is the **networked protocol
layer** that makes those types wire-addressable.

```
tidefs-membership-epoch          MEMBERSHIP service (this spec)
  (deterministic model)    <--->   (networked protocol)
  - MemberId, EpochId              - JOIN/JOIN_ACK
  - ClusterMemberRecord            - HEARTBEAT + HeartbeatV1
  - MembershipConfigRecord         - CLUSTER_VIEW + ClusterViewV1
  - MemberFailureDomainBinding     - LEADER_REDIRECT
  - CohortPopulationRecord         - MountReportV1
  - SplitBrainHazardRecord         - Leader election + joint consensus
```

## 3. Wire Protocol

### 3.1 Service Identity

```
ServiceId: 0x02
ServiceName: "membership"
Transport: cluster control plane (authenticated, reliable, ordered)
Default port: pooled with other control-plane services on the cluster transport
```

### 3.2 Method Catalog

| Method ID | Name | Direction | Payload | Response | Description |
|-----------|------|-----------|---------|----------|-------------|
| `0x00` | `JOIN` | Node → presumed leader | `JoinRequestV1` | `JoinResponseV1` or `LeaderRedirectV1` | Request cluster membership; receive peer list + leader term |
| `0x01` | `HEARTBEAT` | Node → leader | `HeartbeatV1` | `HeartbeatAckV1` | Liveness + mount report; leader checks for missed heartbeats |
| `0x02` | `CLUSTER_VIEW` | Leader → all nodes | `ClusterViewV1` | None (push) | Aggregated view of all nodes and mounts; triggers coherency re-evaluation |
| `0x03` | `LEADER_REDIRECT` | Any → requesting node | `LeaderRedirectV1` | None | Redirect to the correct leader; node retries JOIN with correct leader |

### 3.3 JOIN / JOIN_ACK

A node joining the cluster sends a `JoinRequestV1` to the presumed leader.
If the recipient is not the leader (or is unaware of the current leader), it
responds with `LeaderRedirectV1`. Otherwise, it admits the node as a learner
and returns `JoinResponseV1`.

```rust
pub struct JoinRequestV1 {
    /// Node identity (stable across restarts).
    pub node_id: u64,

    /// Node's cluster address (host:port for transport).
    pub cluster_addr: SocketAddr,

    /// Node's failure-domain vector (device→region).
    pub failure_domain: FailureDomainVector,

    /// Node capabilities bitmask.
    pub capabilities: u64,

    /// Highest membership epoch this node has seen (0 for bootstrap).
    pub last_known_epoch: u64,
}

pub struct JoinResponseV1 {
    /// Current leader term.
    pub term: u64,

    /// Leader's node ID.
    pub leader_id: u64,

    /// Current membership epoch.
    pub epoch: EpochId,

    /// Assigned member class (initially Learner).
    pub member_class: MemberClass,

    /// Complete peer list (all current voters + learners).
    pub peers: Vec<NodeDescriptorV1>,

    /// Leader's cluster view at join time (for initial coherency state).
    pub initial_view: ClusterViewV1,
}

pub struct LeaderRedirectV1 {
    /// Current leader's cluster address.
    pub leader_addr: SocketAddr,

    /// Current leader's node ID.
    pub leader_id: u64,

    /// Current term (for the joining node's term tracking).
    pub term: u64,
}
```

### 3.4 HEARTBEAT

Each node periodically sends a `HeartbeatV1` to the leader. The heartbeat
carries both liveness information and the node's current mount state.

```rust
pub struct HeartbeatV1 {
    /// Sending node's ID.
    pub node_id: u64,

    /// Monotonic heartbeat sequence number.
    pub sequence: u64,

    /// Leader term this node believes is current.
    pub term: u64,

    /// Monotonic timestamp (nanoseconds since node boot).
    pub timestamp_ns: u64,

    /// Number of mounted datasets on this node.
    pub mount_count: u16,

    /// Per-dataset mount reports.
    pub mounts: Vec<MountReportV1>,
}

pub struct HeartbeatAckV1 {
    /// Echoed sequence number.
    pub sequence: u64,

    /// Current leader term (may be higher if leadership changed).
    pub term: u64,

    /// Time until next expected heartbeat (ms).
    pub heartbeat_interval_ms: u32,

    /// If set, the leader requests an immediate CLUSTER_VIEW push.
    pub view_pending: bool,
}
```

### 3.5 CLUSTER_VIEW

The leader aggregates heartbeat data from all nodes and periodically pushes
a `ClusterViewV1` to every connected node. The view is pushed on:
- Any membership change (node joined, left, failed, promoted)
- Any mount change (dataset mounted, unmounted, mode changed)
- Periodic refresh (configurable, default: 5 seconds if no changes)

```rust
pub struct NodeDescriptorV1 {
    /// Stable node identity.
    pub node_id: u64,

    /// Cluster address.
    pub cluster_addr: SocketAddr,

    /// Current member class.
    pub member_class: MemberClass,

    /// Failure-domain vector.
    pub failure_domain: FailureDomainVector,

    /// Node capabilities bitmask.
    pub capabilities: u64,

    /// Time since last heartbeat (ms; leader's perspective).
    pub last_heartbeat_ms: u32,

    /// Whether this node is considered alive.
    pub is_alive: bool,
}

pub struct DatasetViewV1 {
    /// Dataset identifier.
    pub dataset_id: [u8; 16],

    /// Node ID of the writer (0 if read-only or no writer).
    pub writer_node_id: u64,

    /// Number of nodes with this dataset mounted.
    pub mounted_count: u16,

    /// Node IDs with this dataset mounted (sorted).
    pub mounted_nodes: Vec<u64>,

    /// The effective coherency profile for this dataset.
    pub coherency_profile: CoherencyProfile,

    /// Writer's last-applied commit_group (for follower freshness).
    pub writer_last_applied_commit_group: u64,

    /// Writer's RTT hint (microseconds, for auto-detection).
    pub writer_rtt_hint_us: u32,
}

pub struct ClusterViewV1 {
    /// Monotonically increasing membership epoch.
    pub epoch: EpochId,

    /// Leader term that produced this view.
    pub term: u64,

    /// Leader's node ID.
    pub leader_id: u64,

    /// Wall-clock timestamp when this view was generated.
    pub generated_at_ns: u64,

    /// Number of nodes in the cluster.
    pub node_count: u16,

    /// All known nodes (alive + dead; dead nodes age out after tombstone period).
    pub nodes: Vec<NodeDescriptorV1>,

    /// Number of mounted datasets.
    pub dataset_count: u16,

    /// Per-dataset aggregated views.
    pub datasets: Vec<DatasetViewV1>,
}
```

## 4. Mount Registration

### 4.1 MountReportV1

Each heartbeat carries a `MountReportV1` per mounted dataset:

```rust
pub struct MountReportV1 {
    /// Dataset identifier.
    pub dataset_id: [u8; 16],

    /// Mount mode on this node.
    pub mode: MountMode,

    /// Effective coherency profile for this mount.
    pub coherency_profile: CoherencyProfile,

    /// RTT hint to writer (microseconds; 0 if writer or unknown).
    /// Used by `auto` profile to decide between strict/perf/cluster.
    pub rtt_hint_us: u32,

    /// This node's last-applied transaction group.
    pub last_applied_commit_group: u64,

    /// Mount time (nanoseconds since node boot).
    pub mounted_at_ns: u64,
}

pub enum MountMode: u8 {
    /// Read-only mount.
    ReadOnly = 0,

    /// Read-write mount; this node holds the writer lease.
    ReadWriteWriter = 1,

    /// Read-write mount; writes forwarded to the writer node.
    ReadWriteForward = 2,
}

pub enum CoherencyProfile: u8 {
    Perf = 0,

    Strict = 1,

    Cluster = 2,

    /// Auto-detect: select profile based on membership view.
    Auto = 3,
}
```

### 4.2 Auto-Detection Algorithm

When a dataset uses the `Auto` coherency profile, the daemon consults the
latest `ClusterViewV1` to determine the effective profile:

```
Algorithm auto_coherency_profile(dataset_id, cluster_view):
    view = cluster_view.datasets[dataset_id]

    if view.mounted_count <= 1:
        return Perf           // single-node: no coherency needed

    if view.writer_rtt_hint_us < RTT_THRESHOLD_STRICT_US:
        return Strict         // low-latency cluster: full coherency feasible

    if view.mounted_count > CLUSTER_PROFILE_THRESHOLD:

```

### 4.3 Mount Lifecycle

| Event | Action | Membership Update |
|-------|--------|-------------------|
| Dataset mounted | Next heartbeat includes new `MountReportV1` | Leader adds to `DatasetViewV1` |
| Dataset unmounted | Next heartbeat omits the dataset | Leader removes from `DatasetViewV1` |
| Mount mode change (RW→RO) | Heartbeat updates `mode` field | Leader updates `writer_node_id` |
| Node fails (heartbeat timeout) | Leader marks node dead, removes its mounts from views | Leader pushes `CLUSTER_VIEW` to all alive nodes |
| Writer node fails | Leader detects timeout, selects new writer from `RW_FORWARD` nodes | New writer election via writer lease (#1248) |
| Dataset destroyed | Node detects tombstone, stops reporting | Leader removes from view after all nodes drop |

## 5. Leader-Elected Cluster View

### 5.1 Leader Responsibilities

The leader is a single elected node that:
1. Receives all `HEARTBEAT` messages
2. Aggregates mount reports into `DatasetViewV1` per dataset
3. Detects node failures via heartbeat timeout
4. Pushes `CLUSTER_VIEW` to all connected nodes
5. Coordinates joint-consensus membership changes
6. Responds to `JOIN` requests (or redirects)

The leader is **not**:
- A state machine replicating dataset contents (that's the DATA plane)
- A distributed lock manager (that's #1248)
- A configuration database (pools/datasets are stored in pool labels)
- A Ceph monitor equivalent (it does not maintain unbounded maps)

### 5.2 Leader Election

Leader election uses a simple Raft-like term-based approach:

1. On startup, a node attempts `JOIN` to its configured bootstrap peer
2. If the bootstrap peer is not the leader, it receives `LEADER_REDIRECT`
3. If no leader is reachable within `LEADER_ELECTION_TIMEOUT_MS`, the node with the lowest `node_id` among reachable peers initiates election
4. Election: candidate increments term, requests votes from all reachable voters
5. If candidate receives votes from a majority of the joint quorum set, it becomes leader
6. The new leader broadcasts `CLUSTER_VIEW` with the new term

Leader election reuses the joint quorum sets from `tidefs-membership-epoch`:
during a joint-consensus transition, both the old and new voter sets must
acknowledge the leader.

### 5.3 Heartbeat Failure Detection

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `HEARTBEAT_INTERVAL_MS` | 500 | Interval between node→leader heartbeats |
| `HEARTBEAT_TIMEOUT_MS` | 2000 | Leader declares node dead after this duration without heartbeat |
| `HEARTBEAT_GRACE_PERIOD_MS` | 5000 | Tombstone period before dead node is removed from views |
| `MAX_MISSED_HEARTBEATS` | 4 | Consecutive missed heartbeats before leader declares failure |

The leader maintains a per-node `last_heartbeat_ns` timestamp. When
`now - last_heartbeat_ns > HEARTBEAT_TIMEOUT_MS`, the node is marked dead.
After `HEARTBEAT_GRACE_PERIOD_MS` of being dead, the node's mounts are
removed from all `DatasetViewV1` entries, and the node is tombstoned.

## 6. Joint Consensus for Membership Changes

### 6.1 Member Classes

The MEMBERSHIP service adopts the member classes from `tidefs-membership-epoch`:

```rust
pub enum MemberClass: u8 {
    /// Full voting member. Participates in leader election and quorum.
    Voter = 0,

    /// Non-voting member catching up to the leader's applied index.
    Learner = 1,

    /// Witness-only: participates in quorum but stores no data.
    Witness = 2,

    /// Data-only: stores replicas but does not vote.
    DataNode = 3,

    Shadow = 4,

    /// Quarantined: excluded from all cohorts until explicitly rehabilitated.
    Quarantined = 5,
}
```

### 6.2 Membership Change Protocol

All membership changes follow a joint-consensus protocol derived from the
Python v0.262 reference (`cluster_membership.py`):

#### Add Learner

```
1. Operator or admin service issues AddLearner(node_id, addr, failure_domain)
2. Leader verifies: node_id not already a member, addr reachable
3. Leader adds node as Learner (non-voting) in current epoch
4. Leader pushes CLUSTER_VIEW with new learner visible
5. Learner receives CLUSTER_VIEW, begins catch-up phase
```

#### Promote Learner to Voter

```
Phase 1: Enter joint consensus
  1. Leader creates MembershipConfigRecord with joint_old_set (current voters)
     and joint_new_set (current voters + learner)
  2. Leader pushes this as a MembershipTransitionRecord
  3. Both old and new voter sets must acknowledge the transition

Phase 2: Commit
  4. Once joint config is acknowledged by both quorum sets, leader promotes
     learner to Voter
  5. Leader increments epoch, pushes CLUSTER_VIEW with new voter set
  6. Old joint config is garbage-collected after acknowledgment from all voters
```

#### Remove Voter

```
Phase 1: Enter joint consensus
  1. Leader creates joint_old_set (current voters) and joint_new_set
     (current voters minus removed node)
  2. Leader pushes MembershipTransitionRecord
  3. Both quorum sets acknowledge

Phase 2: Commit
  4. Leader removes voter, increments epoch
  5. Removed node receives final CLUSTER_VIEW with its removal
  6. Removed node shuts down its membership connection
```

#### Remove Learner

```
1. Single-phase: leader removes learner directly (no quorum needed)
2. Epoch increment not required (learners don't vote)
```

### 6.3 Membership Transition Record

```rust
pub struct MembershipTransitionRecord {
    /// The epoch this transition targets.
    pub epoch: EpochId,

    /// Transition type.
    pub transition: MembershipTransition,

    /// The member being added/removed/promoted.
    pub subject_node_id: u64,

    /// Joint old voter set (for joint-consensus transitions).
    pub joint_old_set: Vec<u64>,

    /// Joint new voter set.
    pub joint_new_set: Vec<u64>,

    /// Timestamp when this transition was proposed.
    pub proposed_at_ns: u64,

    /// Deadline for acknowledgment.
    pub ack_deadline_ns: u64,
}

pub enum MembershipTransition: u8 {
    AddLearner = 0,
    PromoteLearnerToVoter = 1,
    RemoveVoter = 2,
    RemoveLearner = 3,
    ChangeClass = 4,     // e.g. Voter → Witness
    Quarantine = 5,
    Rehabilitate = 6,
}
```

## 7. Integration Contracts

### 7.1 Integration with #1184 (Coherency Profiles)

The `Auto` coherency profile consumes `ClusterViewV1` to determine the
effective profile:

- `Perf` when `mounted_count <= 1` (single-node, no coherency needed)
- `Strict` when `writer_rtt_hint_us < RTT_THRESHOLD_STRICT_US` (low-latency cluster)

When `CLUSTER_VIEW` is pushed with a changed `DatasetViewV1`, nodes with
`Auto` profiles re-evaluate and may transition their caching behavior.

### 7.2 Integration with #1229 (BULK Protocol)

The `cluster_queues` budget category in the resource governor (#1237) gates
cluster transport admission. When the MEMBERSHIP service detects a node
failure, it signals the transport layer to:

1. Cancel inflight `Offer` messages to the dead node
2. Revoke `Credit` tokens held by the dead node
3. Remove the dead node from `BulkAdmissionControl` peer lists
4. Trigger erasure-coding reconstruction for shards on the dead node (#1249)

### 7.3 Integration with #1175 (Cluster Simnet)

The MEMBERSHIP service protocol is tested deterministically via the cluster
harness. Test scenarios include:

- Single-node bootstrap (JOIN with no existing cluster)
- Multi-node join with leader redirect
- Heartbeat failure detection and leader re-election
- Learner catch-up and promotion to voter
- Joint-consensus add/remove voter with simulated partitions
- Mount registration and CLUSTER_VIEW push on mount change

### 7.4 Integration with #1205 (Writer Lease)

The writer lease (#1205) is the correctness mechanism for coherency. The
MEMBERSHIP service provides the topology information that the writer lease
manager uses to:

- Detect writer failure and trigger lease re-election

### 7.5 Integration with #1283 (Bounded Cluster Membership State)

The MEMBERSHIP service explicitly avoids the Ceph OSDMap growth anti-pattern:

- `ClusterViewV1` is **bounded**: at most `MAX_NODES` (default: 256) and
  `MAX_DATASETS` (default: 65536) entries
- Tombstoned nodes are removed after `HEARTBEAT_GRACE_PERIOD_MS`
- Mount reports are push-based (heartbeat), not poll-based
- The leader does not store historical views beyond the current epoch
- Epoch history is bounded by `MAX_EPOCH_HISTORY` (default: 16)

### 7.6 Integration with Resource Governor (#1237)

The MEMBERSHIP service's memory usage falls under the `cluster_queues` budget
category. The leader's view aggregation buffer is bounded:

- `MAX_CLUSTER_VIEW_SIZE_BYTES`: 1 MiB
- `MAX_HEARTBEAT_BUFFER_SIZE_BYTES`: 256 KiB
- `MAX_JOIN_QUEUE_DEPTH`: 16 concurrent JOIN requests

## 8. ZFS and Ceph Design Lessons (Non-Claim)

| Dimension | ZFS | Ceph | tidefs MEMBERSHIP Service |
|-----------|-----|------|---------------------------|
| **Cluster membership model** | No native cluster membership. Multi-node ZFS uses external HA frameworks (Pacemaker, CARP) with STONITH for fencing. No mount registration, no cluster-wide dataset view. | Monitor maintains OSDMap with per-OSD state (up/in, weights, PG mappings). MDS has separate MDSMap. These maps grow without bound (OSDMap can reach hundreds of MB). No per-dataset mount registration. | Purpose-built MEMBERSHIP service with lightweight heartbeat + mount registration. `ClusterViewV1` bounded by `MAX_NODES` (256) and `MAX_DATASETS` (65536). Epoch history bounded by `MAX_EPOCH_HISTORY` (16). |
| **Membership changes** | Manual operator intervention for node add/remove. No joint consensus — failover relies on external fencing to prevent split-brain. | OSD add/remove via `ceph osd crush add/rm`. No joint-consensus protocol for OSD map changes — relies on Paxos through the monitor quorum for map epoch agreement. | Joint-consensus protocol for voter add/remove (2-phase: enter joint config, commit). Single-phase for learner add/remove. Integrated with `tidefs-membership-epoch` deterministic model for split-brain hazard detection. |
| **Mount registration** | No concept of cluster-wide mount registration. Each node mounts ZFS independently. No visibility into which nodes have which datasets mounted. | No mount registration. CephFS clients mount independently; MDS tracks client sessions but not per-dataset mount state. No cluster-wide "who has what mounted" view. | `MountReportV1` per heartbeat carries per-dataset mount mode, coherency profile, RTT hint, and last-applied commit_group. Leader aggregates into `DatasetViewV1` with writer identification and mounted-node list. |
| **Coherency auto-detection** | N/A (single-node or HA pair with manual config). | N/A. CephFS cache coherency is per-capability (caps) with MDS-driven revocation. No topology-aware auto-selection between strict/perf/cluster. | `Auto` coherency profile uses `ClusterViewV1` to select between `Perf` (single-node), `Strict` (low-latency cluster), and `Cluster` (multi-node with RTT hint). Decision is deterministic and re-evaluated on every CLUSTER_VIEW push. |
| **Leader election** | External (Pacemaker). ZFS has no built-in leader election. | Monitor quorum uses Paxos for leader election. OSD and MDS have separate leader concepts. | Raft-like term-based election with joint-consensus quorum support. Candidate requires majority of joint voter set during transitions. Reuses `tidefs-membership-epoch` quorum sets. |
| **Failure detection** | External (Corosync/Pacemaker heartbeat). No built-in membership liveness. | OSD heartbeat to monitor. MDS heartbeat to monitor. Separate mechanisms per daemon type. | Unified `HEARTBEAT` protocol for all nodes. Configurable interval (500 ms) and timeout (2000 ms). Leader detects failures and pushes updated `CLUSTER_VIEW` to all alive nodes. |
| **Scalability** | N/A for clusters. Max 2 nodes in HA pair. | OSDMap grows without bound — hundreds of MB in large clusters. Monitor memory pressure is a known operational issue (#1283 documents this anti-pattern). | Explicitly bounded: max 256 nodes, 65536 datasets per view. Tombstoned nodes removed after grace period. Leader memory bounded by `cluster_queues` budget. No unbounded map growth. |
| **Observability** | No cluster-wide membership observability. Per-node `zpool status` only. | `ceph status`, `ceph osd tree`, `ceph mds stat` — fragmented across daemon types. No single "who has what mounted" view. | Single `ClusterViewV1` provides complete picture: all nodes, all mounts, writer identification, coherency profiles, liveness. Available to every node on every `CLUSTER_VIEW` push. |

### 8.1 Target Design Differences Relative To ZFS

- **Built-in cluster membership**: ZFS requires external HA frameworks with
  manual configuration. tidefs provides a self-contained membership service
  with automatic leader election and failure detection.
- **Mount registration**: ZFS has no concept of cluster-wide mount state.
  tidefs tracks which nodes have which datasets mounted, in what mode,
  enabling automatic coherency profile selection.
- **Joint consensus**: ZFS relies on STONITH for split-brain prevention.
  tidefs uses joint-consensus membership changes with deterministic split-brain
  hazard detection from `tidefs-membership-epoch`.

### 8.2 Target Design Differences Relative To Ceph

- **Bounded state**: Ceph OSDMap grows without bound, causing monitor OOM
  in large clusters. tidefs `ClusterViewV1` is explicitly bounded and
  tombstoned entries are garbage-collected.
- **Purpose-built mount view**: Ceph has no per-dataset mount registration.
  tidefs provides a complete "who has what mounted" view on every node.
- **Joint consensus for membership**: Ceph uses Paxos for map agreement but
  does not have explicit joint-consensus voter transitions. tidefs provides
  2-phase joint consensus for all voting member changes.
- **Coherency auto-detection**: CephFS requires manual cache configuration.
  tidefs `Auto` profile uses membership data to automatically select the
  optimal coherency strategy.

### 8.3 Shared Design Patterns

- **Heartbeat-based liveness**: Both Ceph and tidefs use heartbeat-based
  failure detection with configurable intervals and timeouts.
- **Term-based leadership**: Both Ceph (Paxos) and tidefs (Raft-like term
  election) use monotonically increasing terms for leader election.
- **Leader-aggregated views**: Both Ceph (monitor) and tidefs (MEMBERSHIP
  leader) aggregate cluster state and push to nodes.

## 9. Implementation Plan

### Phase 1: Core Wire Types
Implement `JoinRequestV1`, `JoinResponseV1`, `LeaderRedirectV1`, `HeartbeatV1`,
`HeartbeatAckV1`, `ClusterViewV1`, `NodeDescriptorV1`, `DatasetViewV1`,
`MountReportV1`, `MountMode`, `MembershipTransitionRecord`, `MembershipTransition`,
and their binary encode/decode with CRC32C checksums in
`crates/tidefs-membership-types/` (new crate). Gate: `tidefs-xtask check-membership-types`.

### Phase 2: Leader State Machine
Implement `MembershipLeader`: heartbeat reception, mount aggregation into
`DatasetViewV1`, `ClusterViewV1` generation, failure detection, tombstone GC,
join handling, and leader redirect. Bounded buffers for all state.
Gate: `tidefs-xtask check-membership-leader`.

### Phase 3: Node Client
Implement `MembershipClient`: JOIN on startup, periodic HEARTBEAT with mount
reports, CLUSTER_VIEW reception, leader redirect handling.
Gate: `tidefs-xtask check-membership-client`.

### Phase 4: Leader Election
Implement term-based leader election with joint-consensus quorum support.
Candidate nomination, vote request/response, term increment, leader announcement.
Gate: `tidefs-xtask check-membership-election`.

### Phase 5: Joint Consensus
Implement membership change protocol: AddLearner, PromoteLearnerToVoter
(2-phase joint consensus), RemoveVoter (2-phase), RemoveLearner (1-phase),
ChangeClass, Quarantine, Rehabilitate. Integration with `tidefs-membership-epoch`.
Gate: `tidefs-xtask check-membership-consensus`.

### Phase 6: Coherency Integration
Wire `ClusterViewV1` into the coherency profile system (#1184). Implement
`auto_coherency_profile()` algorithm. Re-evaluate on CLUSTER_VIEW push.
Gate: `tidefs-xtask check-membership-coherency`.

### Phase 7: Transport Integration
Wire MEMBERSHIP service into the cluster transport layer. Integrate with
BULK protocol (#1229) for node-failure cleanup. Register under `cluster_queues`
budget category (#1237).
Gate: `tidefs-xtask check-membership-transport`.

### Phase 8: Writer Lease Integration
Integrate with writer lease (#1205): provide topology data for lease
re-election on writer node failure.
Gate: `tidefs-xtask check-membership-writer-lease`.

Deterministic cluster harness tests: single-node bootstrap, multi-node join
with redirect, heartbeat failure + re-election, learner catch-up + promotion,
joint-consensus add/remove with simulated partitions, mount registration +
Gate: `tidefs-xtask check-membership-simnet`.

### Phase 10: Production Hardening
Observability counters (nodes joined/left/failed, heartbeats sent/received,
views generated/pushed, membership changes), `tidefsctl membership` command,
auto-tuning of heartbeat interval based on cluster size, production deployment
runbook.
Gate: `tidefs-xtask check-membership-production`.

## 10. Deterministic Constraint Knobs

| Constant | Default | Meaning |
|----------|---------|---------|
| `HEARTBEAT_INTERVAL_MS` | 500 | Interval between node→leader heartbeats |
| `HEARTBEAT_TIMEOUT_MS` | 2000 | Leader declares node dead after this duration |
| `HEARTBEAT_GRACE_PERIOD_MS` | 5000 | Tombstone period before dead node removal |
| `MAX_MISSED_HEARTBEATS` | 4 | Consecutive missed beats before failure declaration |
| `LEADER_ELECTION_TIMEOUT_MS` | 5000 | Max wait for leader discovery before initiating election |
| `LEADER_ELECTION_RETRY_MS` | 10000 | Backoff between election attempts |
| `CLUSTER_VIEW_PUSH_INTERVAL_MS` | 5000 | Periodic CLUSTER_VIEW push when no changes occur |
| `CLUSTER_VIEW_PUSH_ON_CHANGE_MS` | 100 | Min interval between change-triggered pushes |
| `MAX_NODES` | 256 | Maximum nodes in a cluster |
| `MAX_DATASETS` | 65536 | Maximum datasets tracked per cluster view |
| `MAX_CLUSTER_VIEW_SIZE_BYTES` | 1 MiB | Maximum serialized CLUSTER_VIEW size |
| `MAX_HEARTBEAT_BUFFER_SIZE_BYTES` | 256 KiB | Maximum leader heartbeat receive buffer |
| `MAX_JOIN_QUEUE_DEPTH` | 16 | Maximum concurrent JOIN requests |
| `RTT_THRESHOLD_STRICT_US` | 500 | RTT below which `Strict` coherency is feasible |
| `CLUSTER_PROFILE_THRESHOLD` | 8 | Mounted count above which `Cluster` profile is preferred |

## 11. Error Hierarchy

```rust
pub enum MembershipError {
    /// JOIN was rejected (node already a member, cluster full, etc.).
    JoinRejected {
        node_id: u64,
        reason: JoinRejectionReason,
    },

    /// Heartbeat was rejected (wrong term, node not in membership).
    HeartbeatRejected {
        node_id: u64,
        reason: HeartbeatRejectionReason,
    },

    /// Leader election failed (no quorum, partition, etc.).
    ElectionFailed {
        term: u64,
        votes_received: u16,
        votes_needed: u16,
    },

    /// Membership transition failed (quorum not reached, deadline, etc.).
    TransitionFailed {
        epoch: EpochId,
        transition: MembershipTransition,
        subject_node_id: u64,
        reason: TransitionFailureReason,
    },

    /// Split-brain hazard detected.
    SplitBrainHazard {
        hazard: SplitBrainHazardRecord,
    },

    /// Leader lost connectivity to too many nodes.
    LeaderIsolated {
        alive_nodes: u16,
        total_voters: u16,
    },

    /// Cluster view update was rejected (stale epoch, wrong term).
    ViewRejected {
        epoch: EpochId,
        term: u64,
        current_term: u64,
    },
}

pub enum JoinRejectionReason {
    AlreadyMember,
    ClusterFull,
    IncompatibleCapabilities,
    InvalidFailureDomain,
    Quarantined,
}

pub enum HeartbeatRejectionReason {
    NotMember,
    StaleTerm,
    UnknownNodeId,
}

pub enum TransitionFailureReason {
    QuorumNotReached,
    DeadlineExceeded,
    SubjectNodeUnreachable,
    InvalidTransition,
}
```

## 12. Open Questions

1. **Should the leader be a dedicated role or rotate among voters?**
   The current design has a single leader handling all heartbeat aggregation
   and view pushes. This creates a scalability limit at `MAX_NODES` (256).
   For clusters beyond 256 nodes, the leader role could be sharded by dataset
   ID range. Recommendation: single leader for v1, sharded leadership deferred
   to a future `MultiLeaderMembership` extension.

2. **Should the MEMBERSHIP service run on a dedicated port?**
   The current design multiplexes MEMBERSHIP traffic over the cluster control
   plane. A dedicated port would simplify firewall rules and load balancing.
   Recommendation: multiplexed for v1 (simpler deployment), dedicated port
   as an operator-configurable option.

3. **How to handle asymmetric network partitions?**
   A node that can heartbeat to the leader but cannot reach peers may be
   marked alive by the leader but unable to participate in data replication.
   Recommendation: the leader's failure detection is authoritative for
   membership; data-plane connectivity is handled separately by the transport
   layer (#1210).

4. **Should the leader persist membership state to stable storage?**
   Persisting epoch history would survive leader crashes but requires a
   write-ahead log. Recommendation: leader state is ephemeral; on leader
   failure, the new leader rebuilds state from the first round of heartbeats
   from all alive nodes. This avoids the complexity of a membership WAL at
   the cost of a brief stale-window after leader failover.

## 13. References

- [#1209] This design spec
- [P8-02] `docs/MEMBERSHIP_PLACEMENT_FAILURE_DOMAIN_MODEL_P8-02.md` — deterministic membership/placement/failure-domain model
- [OW-302B] `docs/MEMBERSHIP_CONFIG_QUORUM_SET_IDENTITY_OW302B.md` — config record hardening
- [#1184] Named coherency profiles — `Auto` profile consumes CLUSTER_VIEW
- [#1229] BULK protocol — transport integration for node-failure cleanup
- [#1210] Cluster transport boundedness — per-connection limits
- [#1205] Writer lease — coherency enforcement (currently being implemented)
- [#1283] Bounded cluster membership state — anti-Ceph-OSDMap-growth design
- [#1175] Cluster simnet — deterministic membership testing
- [#1237] Unified resource governor — cluster_queues budget for membership traffic
- [#1248] Distributed lock service — writer lease integration
- `crates/tidefs-membership-epoch/` — deterministic membership model (2895 lines)
- `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md`
- `docs/ERASURE_CODING_PLACEMENT_DESIGN.md` — failure domain hierarchy reference
- Python v0.262 reference: `cluster_membership.py` (421 lines)
