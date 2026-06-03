# Shard Groups, Replicas, and Rebake Pathway — Design Specification

**Status: Sealed** — Maturity: **design-spec** for the distributed extent
redundancy model: `ShardGroupV1` encoding with k+m erasure shards, ingest-
replica lifecycle with durability ladder, and budgeted background
`RebakeService` converting ingest extents into base shards.

**Issue:** #2030
**Coord:** #1964
**Prior iterations:** #1884 (prior sealed spec), #1704 (prior sealed spec), #1626 (original), #1675 (refinement), #1593 (prior iteration), #1553 (design-spec refinement), #1286 (original design)
**Lane:** storage-core
**Kind:** design
**Sealed:** 2026-05-04

---

## 0. Seal Notice

This document is the **sealed design specification** for shard groups,
replicas, and rebake pathway. The architecture, data structures,
algorithms, and tradeoffs described here are final. No further design
changes will be accepted without a new design issue.

**Rust implementation is deferred to wire-up issues.** Each phase in
Section 15 (Wire-Up Implementation Plan) will be tracked as an
independent Forgejo issue labeled `codex:ready`. Implementers must
reference this sealed spec in their implementation issues and must not deviate
from the types, state machines, or algorithms defined here without
first opening a new design issue.

The open questions in Section 16 have been resolved with final
recommendations. These are binding decisions for implementers.

---


## 1. Motivation

tidefs writes data in two forms: **ingest extents** (append-only journal,
low-latency, transient) and **base shards** (erasure-coded or replicated,
durable, space-efficient). Without a formal shard-group model and rebake
pathway, three problems arise:

1. **No redundancy during ingest window.** An ingest extent is a single
   copy on a single device. A device failure before rebake means data loss.
2. **No degradation path.** Without explicit replica counts and placement,
   the system cannot distinguish "degraded but safe" from "data at risk."
3. **No ingest bloat management.** Unbaked ingest accumulates CoW fragments
   that hurt read performance and waste space.

ZFS solves (1) and (2) through mirrors or PARITY_RAID at write time, at the
cost of write amplification on every IOP. Ceph solves (1) through
replication at write time, at the cost of multi-hop latency.

tidefs takes a different approach: **fast ingest writes** land on a
single device for minimal latency, then a **budgeted background rebake
service** converts them to base shards with full redundancy. The ingest
window is protected by a **durability ladder** that triggers emergency
rebake if replica counts fall below threshold.

| Concern | ZFS | Ceph | tidefs |
|---------|-----|------|--------|
| Write latency | Pay redundancy cost at write | Pay replication hop at write | Pay single-device latency; redundancy deferred |
| Write amplification | Always k+m writes | Always r writes | 1x at ingest; k+m at rebake |
| Ingest window risk | None (redundant immediately) | None (replicated immediately) | Protected by durability ladder + emergency rebake |
| Space efficiency | Good after write | Good after write | Excellent after rebake; ingest fragments reclaimed |

### Dependency Map

| Design | Relationship |
|--------|-------------|
| #1249 Erasure coding placement | TideCRUSH places shards; `EcProfile` selects (k,m) |
| #1285 Extent maps + locator tables | `locator_id` → `ExtentLocatorValueV1` → shard locations |
| #1179 Background service framework | `RebakeService` implements `BackgroundService` |
| #1287 Checksum architecture | `IntegrityTrailerV2` per-shard digests |
| #1288 Scrub/repair/resilver | Repair selects source from healthy shards |
| #1222 Rebake architecture | Rebake design principles and policy ladder |
| #1215 Space accounting | Rebake frees ingest space; updates physical counters |
| `crates/tidefs-erasure-coding` | GF(2^8) Reed-Solomon encode/decode, `StripeConfig` |
| `crates/tidefs-erasure-coded-store` | `ErasureCodedStore`: data + parity shard storage with repair |
| `crates/tidefs-replication-model` | `ErasureLayoutPolicy`, `ErasureShardClass`, `ErasureDecodeClass` |
| `crates/tidefs-replication` | `ReplicationPolicy`, `ReplicationProtocol` fanout/ack/commit |
| `crates/tidefs-replica-health` | `HealthState`, `SuspicionTracker`, `FlapDetector` |
| `crates/tidefs-types-locator-table-core` | `ExtentLocatorValueV1`, `ReplicaPlacement`, `ShardPlacement` |
| `crates/tidefs-types-extent-map-core` | `ExtentLifecycleState`, `LocatorId`, `ExtentId` |

---

## 2. Design Overview

Three core abstractions:

| Abstraction | Responsibility |
|-------------|---------------|
| `ShardGroupV1` | Encodes k data shards + m parity shards for one extent; on-media format |
| `ReplicaLifecycle` | Tracks ingest replica from write through rebake to trim |
| `RebakeService` | Background service converting ingest to base shards under budget |

The **durability ladder** defines per-dataset redundancy targets:

```
Level 1: None        — single copy (ingest only)
Level 2: Replicated  — r copies on distinct devices (r >= 2)
Level 3: ErasureCoded — k+m shards across (k+m) devices
```

Datasets transition up the ladder as data ages past the ingest window.

---

## 3. Integration with Existing Types

### 3.1 ExtentLocatorValueV1 (already implemented)

The current `ExtentLocatorValueV1` in `crates/tidefs-types-locator-table-core`
already provides the foundation for shard-aware placement:

```rust
// Existing (crates/tidefs-types-locator-table-core/src/lib.rs)
pub struct ExtentLocatorValueV1 {
    pub locator_id: LocatorId,
    pub locator_rev: u64,
    pub flags: u64,           // SHARDED=0x0001, ERASURE_CODED=0x0002, ...
    pub shard_count: u16,
    pub replica_count: u8,
    pub replica_placement: Vec<ReplicaPlacement>,
    pub checksum_profile_id: u8,
    pub compression: u8,
    pub extent_flags: u8,
    pub created_commit_group: u64,
    pub payload_digest: [u8; 32],
    pub payload_bytes: u64,
    pub on_media_bytes: u64,
    pub reserved: [u8; 11],
}

pub struct ReplicaPlacement {
    pub node_id: u64,
    pub device_id: u64,
    pub shard_placements: Vec<ShardPlacement>,
    pub health: ReplicaHealth,
}

pub struct ShardPlacement {
    pub shard_index: u16,
    pub segment_id: u64,
    pub grain_offset: u64,
    pub grain_count: u64,
}
```

For the rebake pathway, when an extent is rebaked:
- `flags` gains `SHARDED | ERASURE_CODED`
- `replica_placement` is populated with one `ReplicaPlacement` per shard target device
- Each `ReplicaPlacement` carries one `ShardPlacement` (single shard per device)
- `shard_count` is set to k+m
- `replica_count` reflects healthy replicas for replicated datasets

### 3.2 ExtentLifecycleState (already implemented)

```rust
// Existing (crates/tidefs-types-extent-map-core/src/lib.rs)
pub enum ExtentLifecycleState {
    Ingest,       // Single-copy append-only journal write
    BaseComplete, // Rebake finished; full shard redundancy
    Dead,         // Extent overwritten; awaiting reclaim
    Freed,        // Terminal; space reclaimed
}
```

The `ReplicaLifecycle` defined in §5 refines `Ingest` with an `EmergencyRebake`
sub-state and adds a `Trimmed` terminal equivalent to `Freed`.

---

## 4. ShardGroupV1 On-Media Format

### 4.1 Structure

`ShardGroupV1` encodes k data shards + m parity shards as a single metadata
blob stored alongside the shard data. It maps 1:1 to a `LocatorId`.

```
Byte layout (little-endian):

Offset  Size   Field
------  ----   -----
0       16     group_id         UUIDv4 identifying this shard group
16      1      ec_k             Data shard count (1..255)
17      1      ec_m             Parity shard count (0..255)
18      1      flags            bit 0=COMPACTED, bit 1=BASE_COMPLETE, bits 2-7 reserved
19      1      replica_count    Replica copies (0 for EC datasets; r for replicated)
20      8      logical_offset   Starting byte offset in the logical extent
28      8      logical_length   Length of the logical extent in bytes
36      32     original_digest  BLAKE3-256 over original (pre-encoding) payload
68      8      stripe_size      Bytes per stripe (data_capacity = k * stripe_size)
76      8      stripe_count     Number of stripes (ceil(logical_length / data_capacity))
84      4      crc32c           CRC32C over bytes 0..83 (pre-shards)
--- repeated per shard (shard_count = k+m) ---
88      2      shard_index      Index 0..(k-1)=data, k..(k+m-1)=parity
90      4      device_id        Physical device ID
94      8      offset           Physical byte offset on device
102     8      length           Padded shard length in bytes
110     32     shard_digest     BLAKE3-256 over this shard's encoded bytes
--- end shard loop (total: 142 + (k+m)*54 bytes) ---
```

Total on-media overhead: `84 + (k+m) * 54` bytes per shard group.

### 4.2 Design Rationale

- **group_id as UUIDv4** instead of `LocatorId(u64)`: Shard groups may be
  created, destroyed, and re-created; a UUID avoids collision with stale
  on-media leftovers. The `ExtentLocatorValueV1.locator_id` maps to
  `ShardGroupV1.group_id` through a locator-table entry.
- **Per-shard digests (BLAKE3-256)** instead of a single group digest:
  Enables single-shard integrity verification without reading all shards.
  A scrub can verify shard 3 without touching shards 0, 1, 2, 4, 5.
- **Separate stripe_size and stripe_count** instead of inferring from
  logical_length: Makes the striping structure explicit. If logical_length
  is not a multiple of `k * stripe_size`, the final stripe has a short
  data block (zero-padded for encoding).
- **Flags byte at fixed offset 18**: Allows scanning for BASE_COMPLETE
  without parsing the full shard descriptor array.

### 4.3 Instance Constraints

| Constraint | Value | Rationale |
|-----------|-------|-----------|
| `ec_k` ≥ 1 | Minimum 1 data shard | Meaningful data stripe |
| `ec_m` ≤ 255 | 8-bit field limit | Practical max m ≈ 4 |
| `ec_k + ec_m` ≤ 255 | 8-bit sum via shard_count(u16) | Addressable via u16 |
| `ec_k + ec_m` ≥ 2 | At least one redundancy shard | Otherwise no point in sharding |
| `replica_count == 0` for `ec_m > 0` | Replicas and EC are exclusive per extent | Design choice: pick one redundancy method |
| `stripe_size ≥ 512` | Minimum shard granularity | Avoids metadata overhead dominating tiny shards |

---

## 5. ReplicaLifecycle State Machine

### 5.1 States

```
                    ┌──────────┐
         write ────▶│  INGEST  │──── timeout/count/capacity ────┐
                    └────┬─────┘                                │
                         │                                      ▼
                         │ device_failure              ┌──────────────────┐
                         ▼                             │ REBAKE_SCHEDULED │
                  ┌───────────────┐                    └────────┬─────────┘
                  │EMERGENCY_REBAKE│                            │
                  └───────┬───────┘          ┌─────────────────┘
                          │                  │
                          └──── rebake_ok ───┤
                                             ▼
                                    ┌──────────────┐
                                    │ BASE_COMPLETE │──── snapshot_destroyed ──▶ ┌─────────┐
                                    └──────────────┘                            │ TRIMMED │
                                                                                └─────────┘
```

| State | Meaning | Duration |
|-------|---------|----------|
| `INGEST` | Single-copy on one device; not durable | Bounded by ingest window (time/count/capacity) |
| `EMERGENCY_REBAKE` | Ingest copy at risk; rebake elevated to critical priority | As fast as budget allows |
| `REBAKE_SCHEDULED` | Normal rebake queued; copy is safe for now | Until rebake tick processes it |
| `BASE_COMPLETE` | k+m shards written; full redundancy achieved | Until all snapshots referencing it are destroyed |
| `TRIMMED` | Space reclaimed from ingest device | Terminal |

### 5.2 Transitions

| From | To | Trigger |
|------|----|---------|
| `INGEST` | `REBAKE_SCHEDULED` | Ingest window limit exceeded (time, count, or capacity) |
| `INGEST` | `EMERGENCY_REBAKE` | Durability level reaches `Critical` or `LossImminent` |
| `EMERGENCY_REBAKE` | `BASE_COMPLETE` | All k+m shards written and verified |
| `REBAKE_SCHEDULED` | `BASE_COMPLETE` | All k+m shards written and verified |
| `REBAKE_SCHEDULED` | `REBAKE_SCHEDULED` | Budget exhausted mid-extent; re-queued for next tick |
| `BASE_COMPLETE` | `TRIMMED` | All snapshots referencing this extent are destroyed |

### 5.3 Relationship to ExtentLifecycleState

```rust
// Mapping: ReplicaLifecycle → ExtentLifecycleState (existing)
fn to_extent_lifecycle(rl: &ReplicaLifecycle) -> ExtentLifecycleState {
    match rl {
        ReplicaLifecycle::Ingest
        | ReplicaLifecycle::EmergencyRebake
        | ReplicaLifecycle::RebakeScheduled => ExtentLifecycleState::Ingest,
        ReplicaLifecycle::BaseComplete => ExtentLifecycleState::BaseComplete,
        ReplicaLifecycle::Trimmed => ExtentLifecycleState::Freed,
    }
}
```

The `ReplicaLifecycle` is a finer-grained view stored in the rebake queue;
the `ExtentLifecycleState` in the extent map is the authoritative state
for read-path decisions.

---

## 6. Durability Ladder

### 6.1 Levels

```
Level 0: Normal      — All replicas/sufficient shards online
Level 1: Warning     — Replicas below target but above Critical threshold
Level 2: Critical    — Replicas at or below `DURABILITY_CRITICAL_THRESHOLD` (default 2)
Level 3: LossImminent — Only 1 replica remaining; data at risk of permanent loss
```

### 6.2 Durability Calculation

For an erasure-coded extent with k+m shards:
```
healthy_shards = count of shards on Online|Degraded devices
min_required = k  // need k-of-(k+m) to reconstruct
if healthy_shards >= k + m   → Normal
if healthy_shards >= k + 1   → Warning
if healthy_shards == k       → Critical
if healthy_shards <  k       → LossImminent
```

For a replicated extent with r copies:
```
healthy_replicas = count of replicas on Online|Degraded devices
if healthy_replicas >= r     → Normal
if healthy_replicas > 2      → Warning
if healthy_replicas == 2     → Critical
if healthy_replicas <  2     → LossImminent
```

### 6.3 Actions per Level

| Level | Action |
|-------|--------|
| `Normal` | No action; rebake at `Throughput` priority |
| `Warning` | Increase rebake priority to `Latency`; log |
| `Critical` | Emergency rebake at `Critical` priority; pump scrub frequency |
| `LossImminent` | Block writes to affected dataset; emergency rebake; alert operator |

### 6.4 Integration with ReplicaHealth

The existing `ReplicaHealth` enum in `crates/tidefs-types-locator-table-core`:

```rust
pub enum ReplicaHealth {
    Online = 0,
    Degraded = 1,
    Offline = 2,
    Retired = 3,
    Corrupt = 4,
}

impl ReplicaHealth {
    pub const fn is_readable(self) -> bool {
        matches!(self, ReplicaHealth::Online | ReplicaHealth::Degraded)
    }
}
```

`Online` and `Degraded` replicas count toward healthy counts.
`Offline` replicas may recover (node rejoins). `Retired` replicas are
permanently removed (device decommissioned). `Corrupt` replicas require
scrub repair before counting as healthy.

---

## 7. RebakeService

### 7.1 Service Budget

`RebakeService` implements the `BackgroundService` trait from #1179.
It operates on a three-dimensional budget per tick:

| Budget Dimension | Default | Purpose |
|-----------------|---------|---------|
| `max_extents_per_tick` | 50 | Limits context switches; prevents starvation of other services |
| `max_read_bytes_per_tick` | 256 MiB | Limits ingest read bandwidth consumption |
| `max_write_bytes_per_tick` | 512 MiB | Limits shard write bandwidth consumption |

Any budget dimension exhausted mid-tick stops further rebake work.
Partially-processed extents are re-queued for the next tick.

### 7.2 Priority Escalation

| Durability Level | Rebake Priority | Behavior |
|-----------------|-----------------|----------|
| `Normal` | `Throughput` | Process extents oldest-first; maximize bytes/tick |
| `Warning` | `Latency` | Process extents closest to ingest window expiry first |
| `Critical` | `Critical` | Bypass budget limits; process all critical extents immediately |
| `LossImminent` | `LossImminent` | Bypass all budgets; block demand writes; only rebake runs |

### 7.3 Rebake Algorithm (per extent)

```
fn rebake_extent(extent: &IngestExtent, policy: &RedundancyPolicy) -> Result<()> {
    // 1. Read ingest data
    let payload = read_ingest(extent.locator_id, extent.physical_offset, extent.physical_length)?;

    // 2. Verify integrity
    if blake3(&payload) != extent.payload_digest {
        return Err(RebakeError::IngestIntegrityFailure);
    }

    // 3. Select target devices via TideCRUSH placement
    let profile = EcProfile { k: policy.k, m: policy.m };
    let targets = tidecrush_place(&profile, extent.logical_offset)?;

    // 4. Encode: split payload into k data stripes, compute m parity stripes
    let config = StripeConfig {
        data_shards: profile.k,
        parity_count: profile.m.into(),
        shard_len: compute_shard_len(payload.len(), profile.k),
    };
    let shard_batches = encode(&payload, &config)?;

    // 5. Write shards to target devices (each shard to one device)
    for (i, (shard, target)) in shard_batches.iter().zip(&targets).enumerate() {
        write_shard(target.device_id, target.offset, &shard)?;
        verify_shard(target.device_id, target.offset, &shard)?;
    }

    // 6. Construct ShardGroupV1 metadata
    let group = ShardGroupV1 { ... };
    write_shard_group_metadata(&group)?;

    // 7. Update locator table: add shard placements, set SHARDED|ERASURE_CODED flags
    update_locator(extent.locator_id, &group)?;

    // 8. Mark extent as BASE_COMPLETE
    set_lifecycle_state(extent.locator_id, ExtentLifecycleState::BaseComplete)?;

    Ok(())
}
```

### 7.4 Atomicity Guarantee

Rebake is atomic per extent: either all k+m shards are written, verified,
and the locator is updated, or the extent is re-queued for the next tick.
No partial state is persisted.

This is enforced by the write order:
1. Write all k+m shard payloads to target devices
2. Verify all shards via checksum
3. Write `ShardGroupV1` metadata block
4. Update `ExtentLocatorValueV1` in the locator table (atomic via COMMIT_GROUP commit)

If the daemon crashes after step 3 but before step 4, the locator still
points to the ingest copy; on recovery, the rebake queue detects the
orphaned shards and re-queues the extent (or reuses the shards if a

---

## 8. RedundancyPolicy

Per-dataset redundancy configuration. Unlike ZFS (pool-wide PARITY_RAID level)
and Ceph (pool-wide replication factor), tidefs allows heterogeneous
redundancy policies within a single pool.

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedundancyPolicy {
    /// No redundancy: single ingest copy only. Data lives and dies with
    /// the ingest device. Suitable for transient/temporary datasets.
    None,

    /// Replicated: r full copies on r distinct devices.
    /// Write path: fanout to r targets via `ReplicationProtocol`.
    /// Read path: any healthy replica; failover on read error.
    Replicated { r: u8 },

    /// Erasure-coded: k data + m parity shards on (k+m) distinct devices.
    /// Write path: write ingest copy; rebake encodes k+m shards.
    /// Read path: read k data shards; reconstruct from parity on failure.
    ErasureCoded { k: u8, m: u8 },
}
```

### 8.1 Policy Immutability

Once set at dataset creation, `RedundancyPolicy` is immutable. Changing
redundancy policy requires dataset migration (send/receive to a new
dataset with the desired policy). This is enforced by the dataset
feature flags system (#1223).

### 8.2 Default Policies

| Dataset Class | Default Policy | Rationale |
|--------------|---------------|-----------|
| `Metadata` | `Replicated { r: 3 }` | Small, critical; low overhead for 3-copy |
| `SmallBlock` (≤ 64 KiB) | `Replicated { r: 2 }` | IOPS-bound; replication avoids EC compute |
| `General` (default) | `ErasureCoded { k: 4, m: 2 }` | Capacity-optimized; 1.5x overhead |
| `Archive` | `ErasureCoded { k: 8, m: 3 }` | Maximum space efficiency; 1.375x overhead |
| `Temporary` | `None` | Transient data; no redundancy needed |

---

## 9. Ingest Window Bounding

The ingest window is bounded by three dimensions. Any limit exceeded
triggers rebake scheduling for the oldest ingest extents.

| Constant | Default | Meaning |
|----------|---------|---------|
| `INGEST_WINDOW_MAX_SECONDS` | 60 | Max seconds an extent stays in INGEST state |
| `INGEST_WINDOW_MAX_EXTENTS` | 10,000 | Max ingest extents before rebake triggers |
| `INGEST_WINDOW_MAX_BYTES` | 1 GiB | Max ingest bytes before rebake triggers |

### 9.1 Design Rationale

- **Time window (60s)**: Worst-case data loss window if the ingest device
  fails. At 60s and 1 GiB/s write rate, up to 60 GiB at risk. Operators
  can tune down to 15s for lower risk or up to 300s for lower rebake
  overhead at the cost of larger loss window.
- **Count window (10,000)**: Prevents metadata bloat. Too many unbaked
  extents degrade locator table scan performance.
- **Capacity window (1 GiB)**: Prevents physical space bloat. Ingest
  fragments cannot be trimmed until rebaked.

The first limit hit wins: if 10,001 extents are written in 30s, rebake
triggers on the count limit, not the time limit.

---

## 10. SegmentCleanerService Integration

After an extent transitions to `BASE_COMPLETE`, the ingest copy on the
original device is eligible for trimming. `SegmentCleanerService`
(#1215) scans for `TRIMMED`-eligible segments and reclaims space.

### 10.1 Safety Gate

An ingest segment must NOT be trimmed until:
1. The corresponding locator entry has `BASE_COMPLETE` lifecycle state,
   OR the locator entry has `SHARDED|ERASURE_CODED` flags set.
2. All shard replicas report `Online` or `Degraded` health.
3. At least `k` shards (for EC) or `r` replicas (for replicated)
   are confirmed readable.

The safety gate prevents trimming the only copy of data before redundancy
is fully established.

---

## 11. ReplicaHealth Service

The existing `crates/tidefs-replica-health` provides:

| Component | Responsibility |
|-----------|---------------|
| `HealthState` | Enum: `Healthy`, `Suspect`, `Unhealthy`, `Unknown` |
| `SuspicionTracker` | Exponential decay suspicion; counts suspect events per replica |
| `FlapDetector` | Detects rapid up/down transitions; suppresses false alerts |
| `LagTracker` | Monitors replication lag for `HealthState::Degraded` |
| `AdaptiveTimeout` | Adjusts health-check intervals based on history |

### 11.1 DurabilityMonitor

A new `DurabilityMonitor` background service extends the replica health
tracking to evaluate durability levels across all extents in a dataset:

```
fn tick() {
    for dataset in all_datasets {
        let level = compute_durability_level(dataset);
        match level {
            Normal => continue,
            Warning => escalate_rebake_priority(dataset, Latency),
            Critical => emergency_rebake(dataset),
            LossImminent => block_dataset_writes(dataset),
        }
    }
}
```

---

## 12. Concurrency and Locking

### 12.1 Write Path During Rebake

An extent being rebaked may still receive reads (from the ingest copy).
Writes to the same logical range during rebake create a new ingest extent;
the old extent continues rebaking and the new extent starts its own
ingest timer. The COMMIT_GROUP commit mechanism ensures no conflicting updates.

### 12.2 Serialization Points

| Resource | Lock | Contention |
|----------|------|-----------|
| `LocatorTable` (per-pool) | `RwLock` | Rebake writes; reads take shared lock |
| `ExtentMap` (per-dataset) | `RwLock` | State transitions |
| `IngestDevice` (per-device) | `Mutex` | Ingest write vs. rebake read |
| `RebakeQueue` | `Mutex` | Enqueue/dequeue |
| `ShardTargetDevice` (per-device) | `Mutex` | Shard write parallelization |

### 12.3 Parallel Rebake

Multiple extents can be rebaked in parallel as long as their target
device sets are disjoint. The `RebakeService` uses a simple greedy
scheduler: sort extents by target device count, then allocate in
non-overlapping batches.

---

## 13. Observability

### 13.1 Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `tidefs.rebake.extents_total` | Counter | Total extents rebaked |
| `tidefs.rebake.bytes_read_total` | Counter | Bytes read from ingest during rebake |
| `tidefs.rebake.bytes_written_total` | Counter | Shard bytes written during rebake |
| `tidefs.rebake.queue_depth` | Gauge | Current rebake queue depth |
| `tidefs.rebake.queue_oldest_seconds` | Gauge | Age of oldest queued extent |
| `tidefs.rebake.budget_exhausted` | Counter | Times budget was exhausted mid-tick |
| `tidefs.durability.level` | Gauge | Current durability level (0-3) per dataset |
| `tidefs.durability.emergency_rebakes` | Counter | Emergency rebake activations |
| `tidefs.ingest.window_utilization_pct` | Gauge | Ingest window capacity utilization |
| `tidefs.shard.healthy_count` | Gauge | Number of healthy shards per dataset |
| `tidefs.replica.suspect_count` | Gauge | Suspect replicas per dataset |

### 13.2 Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| `RebakeQueueBacklogged` | Queue depth > 2x INGEST_WINDOW_MAX_EXTENTS | Warning |
| `DurabilityCritical` | Any dataset reaches `Critical` | Critical |
| `DurabilityLossImminent` | Any dataset reaches `LossImminent` | Critical |
| `RebakeStalled` | No extents rebaked in 2x INGEST_WINDOW_MAX_SECONDS | Critical |

---

## 14. Error Hierarchy

```rust
pub enum ShardGroupError {
    /// TideCRUSH placement returned insufficient targets.
    InsufficientTargets { needed: u8, available: u8 },

    /// Erasure coding encode/decode failed.
    EncodeDecodeFailed { reason: String },

    /// Shard write to target device failed.
    ShardWriteFailed { shard_index: u8, device_id: u32, reason: String },

    /// Locator table update failed.
    LocatorUpdateFailed { locator_id: LocatorId, reason: String },

    /// Integrity trailer mismatch on written shard.
    ShardIntegrityMismatch { shard_index: u8, expected: [u8; 32], actual: [u8; 32] },

    /// ShardGroupV1 metadata block is corrupt or unreadable.
    ShardGroupMetadataCorrupt { group_id: [u8; 16], reason: String },
}

pub enum RebakeError {
    /// Ingest extent is no longer valid (overwritten or truncated).
    ExtentStale { extent_id: u64 },

    /// Ingest extent could not be read.
    IngestReadFailed { extent_id: u64, reason: String },

    /// Ingest data failed integrity check (digest mismatch).
    IngestIntegrityFailure { extent_id: u64, expected: [u8; 32], actual: [u8; 32] },

    /// Rebake budget exhausted mid-extent.
    BudgetExhausted { extent_id: u64, progress: RebakeProgress },

    /// Rebake queue is backed up beyond threshold.
    QueueOverflow { depth: u64, max: u64 },

    /// Shard verification after write failed.
    ShardVerifyFailed { shard_index: u8, device_id: u32, reason: String },
}
```

---

## 15. Wire-Up Implementation Plan

### Phase 1: Core Types
**Crate:** `crates/tidefs-shard-group/` (new)
- `ShardGroupV1` struct with serialize/deserialize
- `ShardDescriptor` struct
- CRC32C integrity over header fields
- Unit tests for size, alignment, round-trip

### Phase 2: ReplicaLifecycle State Machine
**Crate:** `crates/tidefs-shard-group/`
- Ingest window tracking (timestamp, count, byte counters)
- Tests for all valid/invalid transitions

### Phase 3: RebakeService Skeleton
**Crate:** `crates/tidefs-rebake/` (new)
- `BackgroundService` impl with budget enforcement
- Priority queue (oldest-first, emergency-first)
- No-op rebake (log only; no actual EC/shards yet)

### Phase 4: RedundancyPolicy Integration
**Crates:** `tidefs-dataset-lifecycle`, `tidefs-dataset-feature-flags`
- `RedundancyPolicy` enum in dataset properties
- Immutability enforcement at dataset creation
- Per-dataset default policy selection

### Phase 5: TideCRUSH Placement Bindings
**Crates:** `tidefs-erasure-coding`, `tidefs-shard-group`
- Call `tidecrush_place(EcProfile, offset) → Vec<DeviceTarget>`
- Handle insufficient-targets error

### Phase 6: Erasure Coding in Rebake
**Crates:** `tidefs-rebake`, `tidefs-erasure-coding`
- Wire `encode()` and `decode()` into rebake pipeline
- Multi-stripe support for large extents
- Shard write + verify on target devices

### Phase 7: Locator Table Update
**Crates:** `tidefs-locator-table`
- Set `SHARDED|ERASURE_CODED` flags on rebaked locators
- Populate `replica_placement` with per-device `ShardPlacement` entries
- Atomic COMMIT_GROUP-committed locator update after shard writes

### Phase 8: SegmentCleanerService Integration
**Crates:** `tidefs-cleanup-job-core`
- Safety gate: only trim when BASE_COMPLETE and k shards readable
- Trim ingest fragments after locator confirms redundancy

### Phase 9: DurabilityMonitor Service
**Crates:** `tidefs-rebake`, `tidefs-replica-health`
- Periodic durability level computation per dataset
- Emergency rebake escalation at `Critical`/`LossImminent`
- Write blocking at `LossImminent`

**Xtasks:** `tidefs-xtask check-shard-groups-replicas-rebake`
- Deterministic simnet test: write, rebake, corrupt shards, read
- Crash-recovery test: kill daemon mid-rebake, verify recovery
- Budget exhaustion test: verify atomicity (no partial state)
- Durability ladder test: simulate device failures at each level

---

## 16. Resolved Design Decisions

The following questions were resolved during specification sealing
(#1704). These are binding decisions for implementers; do not
reopen without a new design issue.

1. **Should rebake use a dedicated I/O thread pool?**
   Rebake is I/O-heavy (reads ingest, writes k+m shards). A dedicated
   thread could reduce tail latency impact on demand I/O.
   *Recommendation*: start inline with small per-tick budgets; measure
   tail latency; move to dedicated thread only if demand I/O is impacted.

2. **Should partially-rebaked extents be resumable?**
   If rebake is interrupted mid-extent (budget exhaustion, daemon restart),
   partially written shards are orphaned.
   *Recommendation*: make rebake atomic per extent — either all k+m shards
   are written and the locator is updated, or the extent is re-queued for
   the next tick. No partial state.

3. **How to handle rebake during pool export?**
   During export, complete in-flight rebakes, then suspend the rebake queue.
   On next import, the rebake queue is reconstructed from locator entries
   with lifecycle state `Ingest`.
   *Recommendation*: drain in-flight rebakes before completing export;
   resume queue on import.

4. **Should the durability ladder block writes at LossImminent?**
   Blocking writes is the safest option but impacts availability.
   *Recommendation*: block writes at `LossImminent` to prevent silent data
   loss; operator can override via `tidefs.pool.allow_write_during_loss_imminent=1`.

5. **How does rebake interact with snapshots?**
   A snapshot pins the ingest extent's data. If the extent is rebaked after
   the snapshot is taken, the snapshot still references the original locator
   entry. After rebake, the locator entry points to base shards, and the
   snapshot benefits from the improved redundancy.
   *Recommendation*: snapshots reference the locator entry, not the ingest
   location directly; no special handling needed.

6. **What shard size is optimal?**
   Too small: metadata overhead dominates. Too large: repair granularity
   is coarse and read amplification for small IOs increases.
   *Recommendation*: default to 64 KiB shard size, configurable per dataset.
   Use `recordsize`-adaptive sharding for datasets that tune `recordsize`.

---

## 17. References

- [#2030] This sealed design specification
- [#1864] Prior sealed design specification
- [#1884] Prior sealed design specification
- [#1704] Earlier sealed design specification
- [#1249] Erasure coding and CRUSH-like placement — TideCRUSH, EcProfile
- [#1285] Extent maps and locator tables — `ExtentLocatorValueV1`, `LocatorId`
- [#1179] Background service framework — `BackgroundService`, `ServiceBudget`, `ValidityToken`
- [#1287] End-to-end checksum architecture — `IntegrityTrailerV2`, `SuspectLog`
- [#1288] Scrub, repair, and resilver — source selection, repair pipeline
- [#1222] Rebake architecture — rebake design principles, policy ladder
- [#1215] Space accounting — `SegmentCleanerService`, ingest trim
- [#1223] Dataset feature flags — `RedundancyPolicy` immutability
- [#1275] Online pool geometry conversion — `RedundancyPolicy` migration
- `crates/tidefs-erasure-coding/src/lib.rs`
- `crates/tidefs-erasure-coded-store/src/lib.rs`
- `crates/tidefs-replication-model/src/lib.rs`
- `crates/tidefs-replication/src/lib.rs`
- `crates/tidefs-replica-health/src/lib.rs`
- `crates/tidefs-types-locator-table-core/src/lib.rs`
- `crates/tidefs-types-extent-map-core/src/lib.rs`
- `crates/tidefs-locator-table/src/lib.rs`
- `docs/ERASURE_CODING_PLACEMENT_DESIGN.md`
- `docs/EXTENT_MAPS_LOCATOR_TABLES_DESIGN.md`
- `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md`
- `docs/CHECKSUM_ARCHITECTURE_DESIGN.md`
- `docs/SCRUB_REPAIR_RESILVER_DESIGN.md`
- `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md`
