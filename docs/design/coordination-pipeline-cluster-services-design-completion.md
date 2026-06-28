# Coordination Pipeline: Cluster-Wide Services Design Phase Completion

**Issue**: [#1754](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1754)
**Status**: design-spec
**Maturity**: **design-sealed** — the design phase for all cluster-wide coordination
services is complete; Rust implementation for most services is deferred to wire-up
issues
**Priority**: P2
**Lane**: storage-core / coordination (Layers 8-11)
**Depends on**: #1738 (coordination pipeline design seal), #1838 (health advancement
strategy), #1753 (roadmap priorities), #2054 (prior status update)
**Blocks**: All deferred cluster-service wire-up implementation issues

> **Authority note (TFR-019 / #1293)**: This file is classified as historical
> input, not current TideFS cluster-service, distributed-membership, transport,
> rebuild, placement, or release-readiness authority. The Forgejo #1754
> "design-sealed", "implemented-source", "active implementation lanes",
> "3-node cluster", and deferred wire-up wording below is retained only as
> design-lineage context. Current cluster and transport statements must be
> checked against live source, GitHub issue and pull-request state,
> `docs/TRANSPORT_CLUSTER_AUTHORITY.md`, and the active claim registry.

## Abstract

This document records the completion of the design phase for TideFS cluster-wide
coordination services. It covers the full architectural decomposition across four
layers (Transport, Coordination, Data Flow, Observability), the 16 sealed service
designs with their core data structures and algorithms, the implementation deferral
rationale, the active implementation lanes, and the tradeoff analysis that informed
the design decisions. The design phase closure enables parallel wire-up
implementation issues against sealed interfaces.

---

## 1. Architecture

### 1.1 Layer Decomposition

The coordination pipeline spans four architectural layers, each with sealed designs:

| Layer | Scope | Services | Design Status |
|-------|-------|----------|---------------|
| **Layer 8: Transport** | Bounded cluster transport, endpoint families, security | Transport session boundedness (#1210), Endpoint families (P8-01), Security/identity (#1659), BULK plane (#1666) | Sealed |
| **Layer 10: Data Flow** | Replication, rebuild, relocation, erasure coding | P8-03 distributed runtime, Rebuild/backfill/rebalance (OW-305), Erasure-coded layout (OW-306) | Models implemented; distributed runtime deferred |

### 1.2 Architectural Invariants

1. **Boundedness**: No cluster service may grow state with cluster history (#1283).
   Membership state is O(current cluster size), transport state is O(active connections),
   and all operational data paths are independent of epoch history.
2. **Identity-first authorization**: Every service deduplication key and authorization
   decision is scoped by transport-proven peer identity (#1659).
3. **Single serialization point**: Admin mutations serialize through the current cluster
   leader, fenced by (term, epoch). Dataset-mutating operations always execute under
   the writer lease holder (#1698).
4. **Deterministic membership**: Joint-consensus membership changes, not gossip-based
   eventual consistency (#1209).
5. **Unified lane model**: All cluster services use the same `LaneConfig` struct and
   five-class scheduling priority (#1617).

### 1.3 Service Interconnection Graph

```
Layer 11 (Observability)

Layer 10 (Data Flow)
    --> P8-03 distributed runtime
    |     RecoveryLoop -> RebuildPlanner -> PlacementPlanner -> ChunkShipper
    |     FlowCommitCoordinator -> AntiEntropyAuditor
    --> Rebuild/backfill/rebalance (OW-305)
    --> Erasure-coded layout (OW-306)

Layer 9 (Coordination)
    --> MEMBERSHIP (#1209) <-- HELLO from Layer 8
    --> Distributed Lock (#1663) <-- epoch fencing from MEMBERSHIP
    --> Atomic Snapshots (#1662) <-- epoch barrier from MEMBERSHIP
    --> Admin Proxy (#1698) <-- leader election from MEMBERSHIP

Layer 8 (Transport)
    --> Endpoint families (P8-01)
    --> Security/Identity (#1659) <-- HELLO TLV negotiation
    --> BULK plane (#1666) <-- credit pool from bounded budgets
    --> Transport session boundedness (#1210)
```

---

## 2. Data Structures

### 2.1 Core Coordination Types

#### 2.1.1 EpochToken (MEMBERSHIP #1209)

Monotonically increasing cluster epoch, fenced by term. Fields: `term: u64`
(leader election term), `epoch: u64` (monotonic epoch within this term),
`transition: EpochTransition`. EpochTransition variants: `Heartbeat` (normal
heartbeat-driven advancement), `JointConsensus { old_config, new_config }`
(membership change in progress), `LeaderChange { from, to }` (leader failover).

**Invariants**:
- No two valid (term, epoch) pairs may be equal across different cluster configurations.
- A joint-consensus epoch must complete before any subsequent epoch may begin.

#### 2.1.2 LeaseHandle (Distributed Lock #1663)

A sharded lease for distributed lock operations. Fields: `lease_id: LeaseId`,
`service_id: ServiceId`, `resource: ResourcePath`, `validity: LeaseValidity`,
`acquired_at: EpochToken`. LeaseValidity carries `expires_at: Timestamp`,
`ttl: Duration`, `renewable: bool`. ResourcePath variants: `Subtree { ino }`,
`Inode { ino }`, `ByteRange { ino, start, len }`.

**Algorithms**:
- **Acquisition**: Three-tier check: directory subtree conflict, per-inode
  conflict, byte-range overlap. Any conflict returns `LockConflict` with holder
  identity.
- **Renewal**: Lease holder sends RENEW before `expires_at`. Server extends TTL
- **Release**: Best-effort RELEASE message. Leases expire automatically at
  `expires_at` regardless of RELEASE receipt.


Vec<u64>` (causal predecessor sequence numbers), `timestamp: Timestamp`.
`Global`.

**Algorithm: Causal Delivery**:
1. Producer writes entry with `depends_on` list from local vector clock.
2. Consumers maintain per-producer high-water mark.
3. A consumer may process entry `n` only after all entries in `depends_on` have
   been processed.

#### 2.1.4 ClusterView (MEMBERSHIP #1209)

The authoritative cluster membership view. Fields: `generation: u64`,
`config: ClusterConfig`, `leader: NodeId`, `members: BTreeMap<NodeId, MemberState>`,
`epoch: EpochToken`, `health: BTreeMap<NodeId, MemberHealth>`. ClusterConfig
holds `nodes: Vec<NodeConfig>`, `quorum_size: usize`, `joint_consensus:
Option<JointConsensusState>`. MemberState variants: `Active`, `Joining`,
`Leaving`, `Departed`. MemberHealth tracks `last_heartbeat`, `missed_count`,
`alive`.

**Algorithm: Joint-Consensus Membership Change**:
1. Leader proposes `ClusterConfig` with `joint_consensus = Some(JointConsensusState { old, new })`.
2. During joint consensus, quorum requires majority of *both* old and new configurations.
3. Once joint consensus commits, leader proposes the new configuration alone.
4. New configuration commits with quorum of new nodes only.
5. Removed nodes are transitioned to `Departed` state.

### 2.2 Transport Data Structures

#### 2.2.1 EndpointDescriptor (P8-01)

Identifies a transport endpoint within the cluster. Fields: `node_id: NodeId`,
`family: EndpointFamily`, `discriminator: u32`. EndpointFamily variants:
`LocalEmbed = 0` (process-local), `Control = 1` (control-plane), `Data = 2`
(data-plane), `Shadow = 3` (replication).

**Invariants**:
- At most one Control, Data, or Shadow session per peer pair.
- LocalEmbed is process-local only and does not consume transport resources.
- Data and Shadow endpoints share the same BULK plane credit pool (#1666).

#### 2.2.2 BULK Credit Pool (#1666)

Per-connection credit pool for BULK transfers. Fields: `max_bytes: u64`,
`max_ops: u32`, `allocated: CreditAllocation` (bytes_in_flight, ops_in_flight),
`available: CreditAvailable` (bytes, ops). All counters are atomic for
lock-free credit management.

**Algorithm: OFFER/ACCEPT/CREDIT Flow**:
1. Sender issues OFFER(transfer_id, size, priority).
2. Receiver checks credit availability and issues ACCEPT(transfer_id, credits)
   or DECLINE(transfer_id, reason).
3. Sender transfers data in CREDIT-sized chunks.
4. Receiver issues DONE(transfer_id, checksum) or ABORT(transfer_id, reason).
5. Credits are returned to the pool on DONE/ABORT.

#### 2.2.3 Transport Session Budget (#1210)

Per-lane budget enforcement for transport sessions. Fields: `byte_cap_per_tick`,
`op_cap_per_tick`, `bytes_consumed`, `ops_consumed`, `backpressure_threshold`,
`backpressure_active`. LaneClass variants: `Critical = 0` (system-critical),
`LatencySensitive = 1` (metadata ops), `Throughput = 2` (bulk data),
`BestEffort = 3` (background maintenance), `Opportunistic = 4` (idle-time-only).

---

## 3. Algorithms

### 3.1 Cluster Bootstrap Algorithm

The 3-node cluster bootstrap sequence (deferred to child GAP issues):

```
Phase 1: Discovery
  1. Each node reads its local configuration (node_id, listen_addrs, seed_peers).
  2. Nodes bind to listen addresses and open HELLO connections to seed peers.
  3. HELLO TLV negotiates security mode and protocol version.

Phase 2: Leader Election
  4. Nodes exchange HELLO messages with (node_id, priority, generation).
  5. Highest-priority node with the newest generation becomes the bootstrap leader.
  6. Leader increments epoch to (term=1, epoch=1).

Phase 3: Membership Formation
  7. Leader proposes initial ClusterConfig with all discovered peers.
  8. Peers ACK the configuration.
  9. Leader commits ClusterView with generation=1.

Phase 4: Service Wire-Up
  11. Services register with the local transport multiplexer.
  12. Leader begins heartbeat cadence.
```

State machine: `DISCOVERED -> HELLO_SENT -> HELLO_RECEIVED -> CONFIG_PROPOSED -> CONFIG_COMMITTED -> ACTIVE`, with `CONFIG_PROPOSED -> REJECTED -> DISCOVERED` (retry) fallback.

### 3.2 Cross-Node State Machine Advancement

For any coordinated state machine (membership, lock, snapshot):

```
1. Proposer builds state transition T with (current_epoch, proposed_state, dependencies).
2. Proposer sends PROPOSE(T) to all voting members.
   a. current_epoch matches local epoch.
   b. All dependencies are satisfied.
   c. Proposed state is reachable from current state.
4. Voter sends ACCEPT(T) or REJECT(T, reason).
5. Proposer collects quorum (majority of voting members).
6. On quorum ACCEPT, proposer sends COMMIT(T).
7. On any REJECT or timeout, proposer sends ABORT(T).
8. All members apply COMMIT atomically at the next epoch boundary.
```

### 3.3 Cluster Admin Proxy Serialization (#1698)

```
Client Request
  |
  v
+------------------+
| Admin Proxy      |  <-- Any node can receive admin requests
| (receiving node) |
+--------+---------+
         | Forward to leader if not leader
         v
+------------------+
| Admin Proxy      |  <-- Leader node serializes all mutations
| (leader node)    |
+--------+---------+
         | Acquire writer lease
         v
+------------------+
| Mutation applied |  <-- Within (term, epoch) fence
| under lease      |
+--------+---------+
         | Commit within epoch
         v
+------------------+
| Response to      |
| requesting node  |
+------------------+
```

**Fencing guarantee**: Any mutation that commits in epoch `e` is visible to all
nodes that have advanced to epoch `e` or later. Nodes that lag behind epoch `e`
cannot observe the mutation, which prevents split-brain reads.

### 3.4 Cleanup/Reclaim Queue Algorithm

Active implementation lane — source is implemented, wire-up deferred:

1. **Enqueue**: When a refcount drops to zero or an inode is unlinked, the local
   filesystem enqueues a `ReclaimQueueEntry` into the persistent B+tree-backed
   `BPlusTreeReclaimQueue` with `QueueFamily` (extent reclaim, locator reclaim,
   rebake, inode tombstone).
2. **Batch Dequeue**: `ReclaimJob` (an `IncrementalJob`) is dispatched by the
   background scheduler with a `WorkBudget`. It calls `dequeue_batch(limit=256)`
   to retrieve entries sorted by family priority.
   detection), performs the reclaim (extent deallocation, locator removal, rebake
   staging, or tombstone cleanup), and records the `ProcessedDelta`.
4. **Commit**: Processed deltas are committed atomically within the current COMMIT_GROUP.
   Failed entries are re-enqueued with backoff.
5. **Cursor Resumption**: The job maintains a cursor across ticks for resumable
   processing, ensuring forward progress without starvation.

### 3.5 Spacemap/Pool Allocator (G2+ Deferred)

Active implementation lane — G1 complete, G2+ deferred:

**G1 (complete)**: Per-metaslab spacemap with free-block tracking, weighted
allocation across metaslabs, and basic pool-level coordination. Crates:
`tidefs-pool-allocator`, `tidefs-metaslab-allocator`, `tidefs-spacemap`.

**G2+ (deferred)**: Multi-DEVICE coordination algorithm:
```
Allocate(extent_size, device_class_hint):
  1. Filter metaslabs by device_class.
  2. Score each metaslab: score = free_space / total_space * class_weight.
  3. Select metaslab with highest score that has contiguous free extent.
  4. If no contiguous extent, trigger defrag on best metaslab.
  5. Allocate and update spacemap.
  6. Check pool-level free-space threshold; trigger pressure handling.
```

### 3.6 P8-03 Distributed Runtime (9/9 Crates Implemented, Integration Deferred)

The 9 canonical component crates:

| Crate | Purpose | Lines |
|-------|---------|-------|
| `tidefs-recovery-loop` | Recovery orchestration | 849 |
| `tidefs-rebuild-planner` | Rebuild planning and scheduling | 2495 |
| `tidefs-placement-planner` | Data placement decisions | — |
| `tidefs-chunk-shipper` | Chunk transfer engine | — |
| `tidefs-flow-commit-coordinator` | Distributed commit coordination | — |
| `tidefs-anti-entropy-auditor` | Consistency verification | — |
| `tidefs-erasure-coding` | EC encode/decode | 821 |
| `tidefs-erasure-coded-store` | EC storage management | 953 |
| `tidefs-replica-health-tracker` | Health monitoring | 2378 |

The integration deferred to child GAP issues covers: end-to-end data flow through
the full pipeline, cross-node state machine advancement, and 3-node cluster

---

## 4. Tradeoffs

### 4.1 Design-Seal vs. Implemented-Source

**Decision**: Seal all 16 cluster-wide service designs before implementing any of
them in Rust.

**Rationale**:
- **Pro**: Enables parallel wire-up implementation against frozen interfaces.
  Prevents implementation churn from design evolution. Allows cross-service
- **Con**: Defers end-to-end integration testing. Risk of design-impl mismatch
  discovered late. Requires careful interface contract documentation.

**Mitigation**: Each sealed design includes frozen cross-service data structures
with wire-format stability guarantees. Integration contracts are documented per
service. The P8-03 distributed runtime provides a partial integration test
surface through its 9 implemented component crates.

### 4.2 Boundedness vs. Full History

**Decision**: All cluster services operate with bounded state.

**Rationale**:
- **Pro**: Predictable memory footprint. No unbounded growth in long-running
  clusters. Simpler state management.
- **Con**: Cannot answer historical queries. Requires external audit logging.

**Mitigation**: Layer 11 (Observability) provides operator truth surfaces for
debugging. Audit trails are offloaded to external log aggregation.

### 4.3 Single Leader Serialization vs. Multi-Leader

**Decision**: Admin mutations serialize through a single leader per (term, epoch).

**Rationale**:
- **Pro**: Strong consistency with simple fencing. No distributed consensus for
  individual admin operations.
- **Con**: Leader is a bottleneck for admin throughput. Failover latency affects
  mutation availability.

**Mitigation**: Admin operations are low-frequency by design. Read-only admin
queries can be served by any node. Leader failover uses deterministic
priority-based election.

### 4.4 Joint-Consensus Membership vs. Gossip

**Decision**: Deterministic joint-consensus membership changes (#1209).

**Rationale**:
- **Pro**: Strong consistency guarantees. No split-brain during membership
  transitions. Verifiable configuration history.
- **Con**: Requires quorum during transitions. Slower than gossip for large
  clusters.

**Mitigation**: Membership changes are rare events. The joint-consensus window
is bounded (commits within 2 epochs). For clusters larger than 3-7 nodes,
the protocol can be extended with hierarchical consensus.


**Decision**: Defer end-to-end cluster bootstrapping, cross-node state machine
advancement, and production distributed runtime integration to child GAP issues.

**Rationale**:
- **Pro**: Allows focused implementation of individual service crates against
  sealed interfaces. Reduces coordination overhead during implementation.
- **Con**: Integration risk accumulates. Cross-service bugs may be discovered

**Mitigation**: Each service has a deterministic simulation model. The P8-03
distributed runtime has 9 implemented component crates that exercise the
data-flow pipeline locally. Child GAP issues for integration are pre-filed.

---

## 5. Implementation Lanes

### 5.1 Cleanup/Reclaim Queues (implemented-source)

- **Crates**: `tidefs-types-reclaim-queue-core`, `tidefs-reclaim-queue-core`,
  `tidefs-reclaim-job-core`, `tidefs-local-filesystem/src/background_reclaim.rs`,
  `tidefs-reclaim`
- **Status**: Source implemented. Wire-up into local filesystem reclaim path
  is the next step.
- **Queue families**: extent reclaim, locator reclaim, rebake, inode tombstone.

### 5.2 Spacemap/Pool Allocator (G1 foundation complete, G2+ deferred)

- **Crates**: `tidefs-pool-allocator`, `tidefs-metaslab-allocator`,
  `tidefs-spacemap`
- **Status**: G1 per-metaslab allocation complete. G2+ multi-DEVICE coordination
  deferred.

### 5.3 P8-03 Distributed Runtime (9/9 crates implemented, integration deferred)

- **Crates**: All 9 canonical component crates implemented.
- **Status**: End-to-end integration across full data-flow pipeline deferred to
  child GAP issues.

---

## 6. Design Phase Closure Criteria

The design phase is considered substantially complete when:

1. [x] All 16 cluster-wide service designs are sealed with frozen interfaces.
2. [x] Cross-service data structures are stable and documented.
3. [x] Architectural invariants are formalized and consistent across all services.
4. [x] Layer decomposition (8-11) is complete with clear service boundaries.
5. [x] Implementation deferral rationale is documented per service.
6. [x] Child GAP issues are pre-filed for deferred integration work.
7. [x] Active implementation lanes have clear next-step wire-up issues.

All criteria are met as of this design document.

---

## 7. Residual Risk

   through end-to-end integration. Cross-service interface mismatches may be
   discovered during wire-up.
2. **3-Node Bootstrap**: The full cluster bootstrap path has not been exercised
   in a real networked environment.
3. **Performance Budgets**: Per-service performance budgets (lock acquisition
4. **Fault Tolerance**: Failure mode handling (leader failover, network partition,
   node crash-recovery) is designed but not tested.
5. **Coordinator Cadence**: The coordinator auto-generation cadence produces
   coordination-lane maintenance issues at a rate exceeding worker capacity.
   Periodic deduplication is required.

---

## 8. References

- #1738 — Coordination Pipeline: Cluster-Wide Services Design Phase Seal
- #1838 — Coordination Pipeline Health: Advancement Strategy and Monitoring Framework
- #1753 — Coordination Review and Roadmap Priorities Update
- #2054 — Coordination Pipeline Status Update (#2054)
- #1209 — MEMBERSHIP Service Design
- #1663 — Cluster-Wide Distributed Lock Service Design
- #1662 — Cluster-Wide Atomic Snapshot Coordination Design
- #1698 — Cluster Admin Proxy Model Design
- #1659 — Cluster Security and Identity Model Design
- #1666 — Cluster BULK Plane Protocol Design
- #1210 — Transport Session Boundedness
- #1283 — Bounded Cluster Membership State Design
- #1617 — Unified Scheduling Classes and Lane Priority Model
- #1644 — Refcount Delta-Based Incremental Data Cleanup Queues
