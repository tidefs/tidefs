# Coordination Pipeline: Cluster-Wide Services Design Phase Seal

**Issue**: [#1738](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1738)
**Status**: sealed
**Maturity**: **design-sealed** — the design phase for all cluster-wide coordination
services is complete; Rust implementation for most services is deferred to wire-up
issues
**Priority**: P2
**Lane**: storage-core / coordination (Layers 8-11)
**Depends on**: N/A (this document seals the design phase)
**Blocks**: All cluster-service wire-up implementation issues

## Abstract

This document seals the coordination pipeline design phase for TideFS cluster-wide
services. It records the full inventory of cluster service designs, their maturity
state, the layered architectural decomposition (Layers 8-11), the implementation
deferral rationale, and the gate criteria for transitioning individual services
from design-sealed to implemented-source. All major cluster-wide service designs
are now complete. The design phase closure enables parallel wire-up implementation
issues against sealed interfaces.

---

## 1. Coordination Pipeline Architecture

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

---

## 2. Sealed Design Inventory

### 2.1 Layer 8: Transport

#### Transport Session Boundedness (#1210)
- **Document**: Integrated into the transport crate suite; per-lane budget enforcement
  deferred to wire-up
- **Maturity**: design-spec
- **Key decisions**: Per-connection byte/op budgets, backpressure propagation,
  inline vs. bulk frame thresholds, per-lane inflight caps
- **Implementation state**: Core transport crates implemented; per-lane budgets deferred

#### Endpoint Families (P8-01)
- **Document**: `docs/FEATURE_MATRIX.md` (P8-01 row)
- **Maturity**: implemented-source
- **Key decisions**: Four endpoint families (LocalEmbed e0, Control e1, Data e2,
  Shadow e3), at-most-one Control/Data/Shadow session per peer pair
  loopback integration test implemented. Multi-family multiplexing deferred

#### Cluster Security and Identity Model (#1659)
- **Document**: `docs/design/cluster-security-identity-model.md`
- **Maturity**: design-sealed
- **Key decisions**: Four graduated security modes (dev_insecure, tcp_mtls,
  psk_hmac, trusted_fabric), HELLO TLV negotiation, PSK HMAC proof mechanism,
  identity-first authorization invariant
- **Implementation state**: Interfaces and algorithms frozen; Rust implementation
  deferred to wire-up issues

#### Cluster BULK Plane Protocol (#1666)
- **Document**: `docs/design/cluster-bulk-plane-protocol.md`
- **Maturity**: design-spec
- **Key decisions**: OFFER/ACCEPT/CREDIT/DONE/ABORT state machine, TCP streaming
  and RDMA direct-memory modes, unified credit pool, single failure model
- **Implementation state**: Design complete; implementation deferred

### 2.2 Layer 9: Coordination

#### MEMBERSHIP Service (#1209)
- **Document**: `docs/MEMBERSHIP_SERVICE_DESIGN.md`
- **Maturity**: design-spec
- **Key decisions**: Heartbeat-based liveness, leader-aggregated CLUSTER_VIEW,
  joint-consensus membership changes, mount registration, topology-aware
  coherency auto-detection
- **Implementation state**: `tidefs-membership-epoch` deterministic model
  implemented; networked MEMBERSHIP protocol deferred

#### Bounded Cluster Membership State (#1283)
- **Document**: `docs/design/bounded-cluster-membership-state.md`
- **Maturity**: design-spec
- **Key decisions**: Placement results not placement functions, compaction not
  accumulation, bounded monitor state O(cluster size) not O(cluster history)
- **Implementation state**: Design complete; implementation deferred

#### Cluster Distributed Lock Service (#1663, #1248)
- **Document**: `docs/design/cluster-wide-distributed-lock-service-design.md`
  (architectural), `docs/design/cluster-distributed-lock-service-sharded-leases.md`
  (implementation spec)
- **Maturity**: design-spec
- **Key decisions**: Three-tier sharded lease hierarchy (subtree → inode →
  byte-range), Raft-embedded fault tolerance, epoch fencing, FUSE lock forwarding
- **Implementation state**: Design complete; implementation deferred

- **Maturity**: design-spec
- **Key decisions**: SUBSCRIBE/EVENT/EVENT_ACK/RESYNC methods, per-commit_group batching,
  per-tick processing budgets, RESYNC fast path
- **Implementation state**: Design complete; implementation deferred

#### Cluster-Wide Atomic Snapshot Coordination (#1662)
- **Document**: `docs/design/cluster-wide-atomic-snapshot-coordination.md`
- **Maturity**: design-spec
- **Key decisions**: Consistent-cut freeze protocol, cluster-wide snapshot catalog,
  partial-participation semantics, zero-downtime snapshot creation
- **Implementation state**: Design complete; implementation deferred

#### Cluster Admin Proxy Model (#1698)
- **Document**: `docs/design/cluster-admin-proxy-model.md`
- **Maturity**: design-spec
- **Key decisions**: Local-query fast path, cluster-global proxy/redirect routing,
  leader-side dispatch, lease-aware execution, async job tracking
- **Implementation state**: Design complete; implementation deferred

#### Unified Scheduling Classes (#1617)
- **Document**: `docs/design/unified-scheduling-classes-lane-priority-model.md`
- **Maturity**: design-spec
- **Key decisions**: Five canonical classes (CONTROL, METADATA, DEMAND, SPECULATIVE,
  BACKGROUND), strict priority + starvation prevention + budget caps + preemption
- **Implementation state**: `LaneClass` enum exists in transport types;
  unified `LaneConfig` struct and lane scheduler deferred

### 2.3 Layer 10: Data Flow

#### P8-03 Distributed Runtime
- **Document**: `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md`
- **Maturity**: 9/9 canonical component crates implemented-source
- **Key decisions**: Seven-step pipeline (placement → commit → receipt → verify →
  replicate → relocate → rebuild), three-phase state machine (idle/active/draining),
  auto-sync triggers, back-pressure, recovery contract
- **Implementation state**: All 9 component crates implemented:
  - `tidefs-membership-epoch` — deterministic membership model
  - `tidefs-placement-runtime` / `tidefs-placement-planner` — data placement
  - `tidefs-flow-commit-coordinator` — receipt emission and state advancement
  - `tidefs-replicated-store` — quorum-based commit semantics
  - `tidefs-rebuild-planner` — fault-injection rebuild planning
  - `tidefs-erasure-coded-layout` — single-parity encode/decode
  - Remaining transport/replication runtime crates
  End-to-end 3-node cluster bootstrapping and production distributed runtime
  integration deferred to child GAP issues.

#### Rebuild/Backfill/Rebalance (OW-305)
- **Maturity**: deterministic model implemented-source
- **Key decisions**: Fault-injection rebuild, no-source refusal, lagged-copy
  backfill, capacity-movement rebalance, reserve-floor blockage
- **Implementation state**: Deterministic model implemented; async transfer workers deferred

#### Erasure-Coded Layout (OW-306)
- **Maturity**: deterministic model implemented-source
- **Key decisions**: Single-parity encode/decode, single data-shard rebuild,
  parity rebuild, too-many-missing refusal
- **Implementation state**: Deterministic model implemented; production
  Reed-Solomon and networked erasure-coded runtime deferred

### 2.4 Layer 11: Observability

#### Operator Truth Surfaces (OW-307)
- **Document**: `docs/design/distributed-operator-truth-surfaces-OW307A.md` through
  `OW307E.md` (5 sub-documents)
- **Maturity**: design-spec
- **Key decisions**: Truth-view recall bundles, dashboard schemas, trace
- **Implementation state**: Design complete; implementation deferred

---

## 3. Implementation Deferral Rationale

### 3.1 Why Most Cluster Services Are Deferred

The decision to defer Rust implementation of most cluster-wide services to
individual wire-up issues is deliberate and follows these principles:

| Principle | Rationale |
|-----------|----------|
| **Interface-first development** | Sealed interfaces allow parallel implementation by multiple workers without merge conflicts |
| **Serial write surfaces** | `tidefs-local-filesystem` and `tidefs-local-object-store` are serial write surfaces (one active issue at a time); cluster services that do not touch these surfaces can proceed independently |
| **Priority ordering** | The critical path runs through local filesystem completeness (cleanup/reclaim, spacemap G2+, POSIX coverage) before distributed features |

### 3.2 Services with Active Implementation

Not all coordination services are deferred. The following have active
implementation lanes:

| Service | Status |
|---------|--------|
| Cleanup/reclaim queues | implemented-source; `tidefs-reclaim-queue-core`, `tidefs-reclaim-job-core`, `BackgroundReclaim` live in `tidefs-local-filesystem` |
| Spacemap/pool allocator | G1 foundation complete (segment-level); G2+ multi-device coordination deferred to #1694 |
| P8-03 distributed runtime | 9/9 canonical component crates implemented; end-to-end bootstrapping deferred |
| Background service framework | implemented-source; `BackgroundService` trait and tick scheduler live |

---

## 4. Gate Criteria for Wire-Up Transitions

Each deferred cluster service must satisfy these gates before transitioning from
design-sealed to implemented-source:

1. **Interface freeze confirmation**: The sealed design document must be re-reviewed
   against any intervening changes to dependent crates.
2. **Write-set declaration**: The wire-up issue must declare which crates it will
   edit, respecting serial-write-surface constraints.
   gate (unit test, xtask check, or integration smoke).
4. **Dependency resolution**: All `Depends on` and `Blocks` relationships in the
   design document must be satisfied or explicitly waived.
5. **No regression**: `cargo check --workspace` and `cargo test --workspace` must
   pass before and after implementation.

---

## 5. Design Phase Metrics

| Metric | Count |
|--------|-------|
| Total cluster service designs | 16 |
| Sealed (design-spec or design-sealed) | 11 |
| Implemented-source (models) | 5 |
| Implemented-source (production runtime) | 0 |
| Deferred to wire-up issues | 16 |
| Active implementation lanes | 3 (reclaim, spacemap G1, P8-03 runtime) |

---

## 6. Roadmap from Design to Production

### 6.1 Immediate Priorities (Design → Implementation)

1. **Cleanup/reclaim queue wire-up**: Integrate `BackgroundReclaim` into the
   local filesystem reclaim path with live integration tests.
2. **Spacemap allocator G2+**: Multi-device coordination for pool-level space
   allocation with cross-device free-space balancing.
3. **P8-03 distributed runtime**: 3-node cluster bootstrap with cross-node
   state machine advancement via simnet or QEMU harness.

### 6.2 Medium-Term (Implementation → Integration)

4. **Transport boundedness**: Per-lane budget enforcement across all cluster
   transport connections.
5. **MEMBERSHIP service**: Networked JOIN/HEARTBEAT/CLUSTER_VIEW protocol
   over the bounded transport.

### 6.3 Long-Term (Integration → Production)

7. **Distributed lock service**: Multi-writer concurrency with Raft-embedded
   fault tolerance.
8. **Cluster-wide atomic snapshots**: Consistent-cut freeze across all nodes.
9. **Erasure coding production**: Reed-Solomon with networked placement.
10. **Full operator observability**: Dashboards, traces, truth surfaces.

---

## 7. Residual Risk

- **Interface drift**: Sealed interfaces may require adjustment when implementation
  infrastructure not yet available. Implementation will proceed against simnet
- **Serial-write-surface contention**: As implementation transitions from design
  to code, the serial write surfaces (`tidefs-local-filesystem`,
  `tidefs-local-object-store`) may become bottlenecks.

---

## 8. References

- `docs/FEATURE_MATRIX.md` — current implemented-source capability matrix
- `docs/CURRENT_VS_FUTURE_CAPABILITIES.md` — deferred production gates
- `docs/STATUS.md` — live coordination pipeline status
- `docs/design/cluster-security-identity-model.md` — sealed security architecture
- `docs/design/cluster-wide-distributed-lock-service-design.md` — lock service architecture
- `docs/design/cluster-bulk-plane-protocol.md` — BULK plane protocol
- `docs/design/cluster-wide-atomic-snapshot-coordination.md` — snapshot coordination
- `docs/design/cluster-admin-proxy-model.md` — admin proxy model
- `docs/design/bounded-cluster-membership-state.md` — anti-OSDMap-explosion design
- `docs/design/unified-scheduling-classes-lane-priority-model.md` — lane model
- `docs/MEMBERSHIP_SERVICE_DESIGN.md` — membership protocol
- `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md` — P8-03 runtime
- `docs/REFCOUNT_DELTA_CLEANUP_QUEUES_DESIGN.md` — reclaim queues

---

**Design phase sealed.** No further cluster-wide service architecture documents
are required. Individual wire-up implementation issues may be filed against
each sealed design.
