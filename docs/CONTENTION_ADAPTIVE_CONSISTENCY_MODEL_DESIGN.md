# Contention-Adaptive Distributed Consistency Model

## Status

**design-spec** — design sealed, implementation deferred to milestones in `distributed-consistency-model` phase.

## Problem

In a distributed filesystem, enforcing POSIX semantics across nodes requires
coordination. Static strategies waste resources:

- Always using quorum writes for every operation burns 2-3x write bandwidth even
  when a file has a single writer.
- Always using optimistic concurrency causes high abort rates under contention,
  wasting client CPU and network round-trips.
- Always using leases adds RTT latency to every write, punishing latency-sensitive
  workloads.
- Always using a single serialization point creates a bottleneck and a
  single point of failure.

No single strategy is optimal for all workloads.

## Solution

TideFS dynamically selects a coordination strategy per inode (filesystem) or
per block range (block device) based on observed contention. The system
transitions between five coordination levels with hysteresis to prevent
flapping.

## Coordination Levels

### Level 0: Uncontended (No Coordination)

- **Condition**: Single writer, no concurrent access observed for > N seconds.
- **Strategy**: Local write with async replication. No coordination overhead.
- **POSIX**: close-to-open consistency (NFS-like). Data visible after close()
  on any node within replication lag.
- **Cost**: Zero coordination latency. Replication lag depends on network RTT.

### Level 1: Optimistic (Version Vectors)

- **Condition**: Infrequent concurrent access, conflict rate < threshold.
- **Strategy**: Each write carries a version vector. On conflict, the
  coordinator reconciles (last-writer-wins for data, merge for metadata).
- **POSIX**: write atomicity preserved through version-vector abort/retry.
  close-to-open consistency with eventual visibility.
- **Cost**: Version vector overhead (~64 bytes per write). Retry on conflict
  costs ~RTT.

### Level 2: Lease-Based

- **Condition**: Regular concurrent access, conflict rate > threshold.
- **Strategy**: Writer acquires a distributed lease with configurable TTL
  before modifying. Lease holder has exclusive write access. Readers proceed
  without lease. Lease renewal extends access; expiry auto-releases.
- **POSIX**: Full POSIX write atomicity. Lock ordering (F_SETLK/F_SETLKW)
  preserved through lease priority inheritance. fsync flushes lease-held
  data to quorum before releasing.
- **Cost**: Lease acquisition latency (~RTT for quorum ack). Renewal every
  TTL/2. Grace period on expiry for in-flight ops.

### Level 3: TDMA (Time Division)

- **Condition**: High contention, lease acquisition latency exceeding target
  p99, or lock queues forming.
- **Strategy**: A coordinator assigns time slots to contending nodes in
  round-robin order. Each node gets a predictable write window. Empty slots
  (node has no pending writes) advance early after a configurable dead time.
  Clock drift bounded by CLOCKS_TIMING_FENCES_DRIFT_ASSUMPTIONS (P8-04).
- **POSIX**: Full POSIX with bounded latency. Write ordering determined by
  slot assignment. Lock ordering preserved within each node's slot.
- **Cost**: Slot duration (1-100ms configurable). Unused slots waste bandwidth.
  Requires clock synchronization (NTP/PTP, bounds per P8-04).

### Level 4: Leader-Serialized

- **Condition**: Extreme contention, TDMA slot utilization < 50% (nodes
  cannot produce data fast enough to fill slots), or lock chains exceeding
  depth threshold.
- **Strategy**: All operations for the contended object route through a single
  leader node. The leader serializes writes, resolves lock ordering, and
  replicates to followers. This is the flow-commit coordinator's native mode.
- **POSIX**: Strongest guarantees — all operations linearized at the leader.
- **Cost**: Single-node bottleneck for the contended object. Maximum throughput
  for the contended case (no slot waste, no retry). Leader failover via
  membership epoch transition.

## Transition Rules

Transitions are triggered by the ContentionDetector when a metric crosses
a configurable threshold for a sustained period. Downgrades require a longer
sustained calm period (hysteresis) to prevent flapping.

| From → To | Trigger | Hysteresis |
|---|---|---|
| 0 → 1 | First concurrent writer detected | Immediate |
| 1 → 2 | Conflict rate > 5% for 10s | 30s calm before downgrade |
| 2 → 3 | Lease acquisition p99 > 10ms for 30s | 60s calm |
| 3 → 4 | Slot utilization < 50% for 60s | 120s calm |
| 4 → 3 | Slot utilization > 80% for 60s | — |
| Any → lower | Sustained calm for hysteresis period | Per above |

## Strategy Transition Protocol

Transitions are atomic and safe:

1. **Quiesce**: Stop admitting new operations under the old strategy.
2. **Drain**: Wait for in-flight operations under old strategy to complete
   (or timeout + abort).
3. **Verify**: Version-vector or lease state check confirms no lost writes.
4. **Switch**: Activate new strategy atomically with epoch fencing. Operations
   arriving during transition are queued and replayed under new strategy.
5. **Publish**: New strategy epoch is gossiped through membership view.
   Late-arriving operations with old epoch are rejected (caller retries).

If any step fails, the transition is aborted and the old strategy continues.
No data loss, no consistency violation.

## ContentionDetector

Per-inode (filesystem) or per-block-range (block device) state machine:

- `concurrent_writers: u32` — nodes with active write intents (from membership view)
- `conflict_count: u64` — version-vector rejections in current window
- `total_writes: u64` — total write attempts in current window
- `lease_acquisition_latency_ns: Histogram` — p50/p90/p99 of lease acquisition
- `lock_queue_depth: u32` — waiters for this object's lock
- `slot_utilization: f64` — fraction of TDMA slots that produced writes
- `current_level: CoordinationLevel`
- `stable_since: Instant` — time at current level (for hysteresis)

Configurable thresholds per metric, per level. Sliding windows with
exponential decay.

## Crate Architecture

```
tidefs-contention-detector     — ContentionDetector, ContentionLevel, threshold config
tidefs-lease-manager           — LeaseManager, LeaseState, LeasePriority
tidefs-tdma-scheduler          — TDMAScheduler, SlotAllocation, SlotClock
tidefs-coordination-strategy   — CoordinationStrategy enum, transition protocol, epoch fencing
tidefs-posix-guarantee-verifier — POSIXGuarantee, strategy→guarantee mapping, verification tests
```

All crates are new — no overlap with existing FUSE/dispatch/cluster code.
They integrate with existing:
- `tidefs-membership-live` (for concurrent writer detection, epoch fencing)
- `tidefs-flow-commit-coordinator` (for Level 4 leader serialization)
- `tidefs-replication-model` (for version vectors, quorum writes)
- `tidefs-vfs-engine` (for filesystem operation interception)
- `tidefs-block-volume-adapter-core` (for block device integration)

## Comparison

| Feature | ZFS | Ceph | TideFS (target) |
|---|---|---|---|
| Coordination strategy | N/A (single-node) | Static (primary-copy) | Dynamic (5 levels) |
| Contention detection | N/A | None | Per-inode/per-block |
| Lease mechanism | N/A | OSD capabilities (coarse) | Per-object leases with priority inheritance |
| TDMA | No | No | Yes, for high-contention objects |
| Strategy transitions | N/A | N/A | Atomic with epoch fencing |
| Block device integration | N/A (local only) | librbd (static) | Same coordination layer as filesystem |

This is a novel contribution to distributed filesystem design. No existing
system dynamically selects coordination strategies based on workload patterns.
