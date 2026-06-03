# Shard Groups, Replicas, and Rebake Pathway — Design Specification

**Status: Design-Spec** — Maturity: **design-spec** for the distributed extent
redundancy model: `ShardGroupV1` encoding with k+m erasure shards, ingest-
replica lifecycle with durability ladder, and budgeted background
`RebakeService` converting ingest extents into base shards.

**Issue:** #1781
**Canonical sealed spec:** #2030 (sealed 2026-05-04), `docs/design/shard-groups-replicas-rebake-design-spec.md`
**Lane:** storage-core
**Kind:** design
**Rust implementation:** Deferred to wire-up issues per Section 15 of canonical spec

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

---

## 2. Architecture Overview

### 2.1 Core Abstractions

| Abstraction | Responsibility |
|-------------|---------------|
| `ShardGroupV1` | On-media format encoding k data shards + m parity shards for one extent |
| `ReplicaLifecycle` | Tracks ingest replica from write through rebake to trim |
| `RebakeService` | Background service converting ingest to base shards under budget |
| `RedundancyPolicy` | Per-dataset redundancy configuration (None/Replicated/ErasureCoded) |
| `DurabilityMonitor` | Evaluates durability levels and escalates emergency rebake |

### 2.2 Durability Ladder

The durability ladder defines per-dataset redundancy targets that data
progresses through as it ages past the ingest window:

```
Level 1: None        — single copy (ingest only)
Level 2: Replicated  — r copies on distinct devices (r >= 2)
Level 3: ErasureCoded — k+m shards across (k+m) devices
```

### 2.3 Data Flow

```
Write Path:
  Client write → Ingest extent (single device, low latency)
       ↓
  DurabilityMonitor checks replica counts
       ↓
  RebakeService (background, budgeted):
    Read ingest → Verify checksum → TideCRUSH placement →
    Encode k+m shards → Write shards → Update locator →
    Mark BASE_COMPLETE → SegmentCleaner trims ingest

Read Path:
  If BASE_COMPLETE: read k data shards, reconstruct from parity on failure
  If INGEST: read from ingest device directly
```

### 2.4 Dependency Map

| Design | Relationship |
|--------|-------------|
| #1249 Erasure coding placement | TideCRUSH places shards; `EcProfile` selects (k,m) |
| #1285 Extent maps + locator tables | `locator_id` → `ExtentLocatorValueV1` → shard locations |
| #1179 Background service framework | `RebakeService` implements `BackgroundService` |
| #1287 Checksum architecture | `IntegrityTrailerV2` per-shard digests |
| #1288 Scrub/repair/resilver | Repair selects source from healthy shards |
| #1222 Rebake architecture | Rebake design principles and policy ladder |
| #1215 Space accounting | Rebake frees ingest space; updates physical counters |

---

## 3. ShardGroupV1 On-Media Format

### 3.1 Structure

`ShardGroupV1` encodes k data shards + m parity shards as a single metadata
blob stored alongside the shard data. It maps 1:1 to a `LocatorId`.

```
Byte layout (little-endian):

Offset  Size   Field
------  ----   -----
0       16     group_id         UUIDv4 identifying this shard group
16      1      ec_k             Data shard count (1..255)
17      1      ec_m             Parity shard count (0..255)
18      1      flags            bit 0=COMPACTED, bit 1=BASE_COMPLETE
19      1      replica_count    Replica copies (0 for EC; r for replicated)
20      8      logical_offset   Starting byte offset in the logical extent
28      8      logical_length   Length of the logical extent in bytes
36      32     original_digest  BLAKE3-256 over original (pre-encoding) payload
68      8      stripe_size      Bytes per stripe (data_capacity = k * stripe_size)
76      8      stripe_count     Number of stripes
84      4      crc32c           CRC32C over bytes 0..83
--- repeated per shard (shard_count = k+m) ---
88      2      shard_index      Index 0..(k-1)=data, k..(k+m-1)=parity
90      4      device_id        Physical device ID
94      8      offset           Physical byte offset on device
102     8      length           Padded shard length in bytes
110     32     shard_digest     BLAKE3-256 over this shard's encoded bytes
--- end shard loop (total: 84 + (k+m)*54 bytes) ---
```

### 3.2 Design Decisions

- **group_id as UUIDv4**: Avoids collision with stale on-media leftovers
  across create/destroy cycles.
- **Per-shard BLAKE3-256 digests**: Enables single-shard integrity
  verification without reading all shards.
- **Separate stripe_size and stripe_count**: Makes the striping structure
  explicit for variable-length final stripes.
- **Flags byte at fixed offset 18**: Allows scanning for BASE_COMPLETE
  without parsing full shard descriptor array.

### 3.3 Instance Constraints

| Constraint | Value | Rationale |
|-----------|-------|-----------|
| `ec_k` ≥ 1 | Minimum 1 data shard | Meaningful data stripe |
| `ec_m` ≤ 255 | 8-bit field limit | Practical max m ≈ 4 |
| `ec_k + ec_m` ≤ 255 | Addressable via u16 | sum fits in shard_count |
| `ec_k + ec_m` ≥ 2 | At least one redundancy shard | Otherwise no point in sharding |
| `replica_count == 0` for `ec_m > 0` | Exclusive redundancy method | EC and replication are orthogonal |
| `stripe_size ≥ 512` | Minimum shard granularity | Avoids metadata overhead dominating tiny shards |

---

## 4. ReplicaLifecycle State Machine

### 4.1 States

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
| `INGEST` | Single-copy on one device; not durable | Bounded by ingest window |
| `EMERGENCY_REBAKE` | Ingest copy at risk; rebake elevated to critical priority | As fast as budget allows |
| `REBAKE_SCHEDULED` | Normal rebake queued; copy is safe | Until rebake tick processes it |
| `BASE_COMPLETE` | k+m shards written; full redundancy achieved | Until all referencing snapshots destroyed |
| `TRIMMED` | Space reclaimed from ingest device | Terminal |

### 4.2 Transitions

| From | To | Trigger |
|------|----|---------|
| `INGEST` | `REBAKE_SCHEDULED` | Ingest window limit exceeded (time, count, or capacity) |
| `INGEST` | `EMERGENCY_REBAKE` | Durability level reaches `Critical` or `LossImminent` |
| `EMERGENCY_REBAKE` | `BASE_COMPLETE` | All k+m shards written and verified |
| `REBAKE_SCHEDULED` | `BASE_COMPLETE` | All k+m shards written and verified |
| `REBAKE_SCHEDULED` | `REBAKE_SCHEDULED` | Budget exhausted mid-extent; re-queued for next tick |
| `BASE_COMPLETE` | `TRIMMED` | All snapshots referencing this extent are destroyed |

### 4.3 Relationship to ExtentLifecycleState

```rust
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

---

## 5. Integration with Existing Types

### 5.1 ExtentLocatorValueV1

```rust
// Existing in crates/tidefs-types-locator-table-core
pub struct ExtentLocatorValueV1 {
    pub locator_id: LocatorId,
    pub locator_rev: u64,
    pub flags: u64,           // SHARDED=0x0001, ERASURE_CODED=0x0002
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

When an extent is rebaked, `flags` gains `SHARDED | ERASURE_CODED`,
`replica_placement` is populated with one entry per shard target device,
and `shard_count` is set to k+m.

### 5.2 ExtentLifecycleState

```rust
// Existing in crates/tidefs-types-extent-map-core
pub enum ExtentLifecycleState {
    Ingest,       // Single-copy append-only journal write
    BaseComplete, // Rebake finished; full shard redundancy
    Dead,         // Extent overwritten; awaiting reclaim
    Freed,        // Terminal; space reclaimed
}
```

---

## 6. RedundancyPolicy

Per-dataset redundancy configuration. tidefs allows heterogeneous
redundancy policies within a single pool, unlike ZFS (pool-wide PARITY_RAID)
and Ceph (pool-wide replication factor).

```rust
pub enum RedundancyPolicy {
    None,                              // Single ingest copy only
    Replicated { r: u8 },              // r full copies on distinct devices
    ErasureCoded { k: u8, m: u8 },     // k data + m parity shards
}
```

### 6.1 Default Policies

| Dataset Class | Default Policy | Rationale |
|--------------|---------------|-----------|
| `Metadata` | `Replicated { r: 3 }` | Small, critical; low overhead |
| `SmallBlock` (≤ 64 KiB) | `Replicated { r: 2 }` | IOPS-bound; avoid EC compute |
| `General` (default) | `ErasureCoded { k: 4, m: 2 }` | Capacity-optimized; 1.5x overhead |
| `Archive` | `ErasureCoded { k: 8, m: 3 }` | Max space efficiency; 1.375x overhead |
| `Temporary` | `None` | Transient data; no redundancy needed |

### 6.2 Immutability

Once set at dataset creation, `RedundancyPolicy` is immutable. Changing
redundancy policy requires dataset migration (send/receive to a new
dataset with the desired policy).

---

## 7. RebakeService

### 7.1 Budget Model

`RebakeService` implements the `BackgroundService` trait and operates on
a three-dimensional budget per tick:

| Budget Dimension | Default | Purpose |
|-----------------|---------|---------|
| `max_extents_per_tick` | 50 | Limits context switches; prevents starvation |
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
fn rebake_extent(extent, policy) -> Result<()> {
    // 1. Read ingest data
    let payload = read_ingest(extent.locator_id, extent.physical_offset,
                              extent.physical_length)?;

    // 2. Verify integrity
    if blake3(&payload) != extent.payload_digest {
        return Err(RebakeError::IngestIntegrityFailure);
    }

    // 3. Select target devices via TideCRUSH placement
    let profile = EcProfile { k: policy.k, m: policy.m };
    let targets = tidecrush_place(&profile, extent.logical_offset)?;

    // 4. Encode: split payload into k data stripes, compute m parity
    let config = StripeConfig {
        data_shards: profile.k,
        parity_count: profile.m.into(),
        shard_len: compute_shard_len(payload.len(), profile.k),
    };
    let shard_batches = encode(&payload, &config)?;

    // 5. Write shards to target devices
    for (i, (shard, target)) in shard_batches.iter().zip(&targets).enumerate() {
        write_shard(target.device_id, target.offset, &shard)?;
        verify_shard(target.device_id, target.offset, &shard)?;
    }

    // 6. Construct ShardGroupV1 metadata and persist
    let group = ShardGroupV1 { ... };
    write_shard_group_metadata(&group)?;

    // 7. Update locator table atomically via COMMIT_GROUP commit
    update_locator(extent.locator_id, &group)?;

    // 8. Mark extent as BASE_COMPLETE
    set_lifecycle_state(extent.locator_id, BaseComplete)?;

    Ok(())
}
```

### 7.4 Atomicity Guarantee

Rebake is atomic per extent: either all k+m shards are written, verified,
and the locator is updated, or the extent is re-queued for the next tick.
No partial state is persisted.

Write order:
1. Write all k+m shard payloads to target devices
2. Verify all shards via checksum
3. Write `ShardGroupV1` metadata block
4. Update `ExtentLocatorValueV1` in the locator table (atomic via COMMIT_GROUP commit)

On crash recovery between steps 3 and 4, the locator still points to the
ingest copy; the rebake queue detects orphaned shards and either reuses
them or re-queues the extent.

---

## 8. Ingest Window Bounding

| Constant | Default | Meaning |
|----------|---------|---------|
| `INGEST_WINDOW_MAX_SECONDS` | 60 | Max seconds an extent stays in INGEST |
| `INGEST_WINDOW_MAX_EXTENTS` | 10,000 | Max ingest extents before rebake triggers |
| `INGEST_WINDOW_MAX_BYTES` | 1 GiB | Max ingest bytes before rebake triggers |

The first limit hit wins. Operators can tune the time window down to 15s
for lower risk or up to 300s for lower rebake overhead.

---

## 9. DurabilityMonitor

A background service that evaluates durability levels across all extents
in a dataset and escalates rebake priority accordingly:

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

At `LossImminent`, writes are blocked to prevent silent data loss.
Operators can override via `tidefs.pool.allow_write_during_loss_imminent=1`.

---

## 10. SegmentCleanerService Integration

After an extent transitions to `BASE_COMPLETE`, the ingest copy is eligible
for trimming by `SegmentCleanerService` (#1215).

### Safety Gate

An ingest segment must NOT be trimmed until:
1. The corresponding locator entry has `BASE_COMPLETE` lifecycle state,
   OR has `SHARDED|ERASURE_CODED` flags set.
2. All shard replicas report `Online` or `Degraded` health.
3. At least `k` shards (for EC) or `r` replicas (for replicated)
   are confirmed readable.

---

## 11. Concurrency and Locking

### 11.1 Write Path During Rebake

An extent being rebaked may still receive reads from the ingest copy.
Writes to the same logical range during rebake create a new ingest extent;
the old extent continues rebaking and the new extent starts its own
ingest timer. The COMMIT_GROUP commit mechanism ensures no conflicting updates.

### 11.2 Serialization Points

| Resource | Lock | Contention |
|----------|------|-----------|
| `LocatorTable` (per-pool) | `RwLock` | Rebake writes; reads take shared lock |
| `ExtentMap` (per-dataset) | `RwLock` | State transitions |
| `IngestDevice` (per-device) | `Mutex` | Ingest write vs. rebake read |
| `RebakeQueue` | `Mutex` | Enqueue/dequeue |
| `ShardTargetDevice` (per-device) | `Mutex` | Shard write parallelization |

### 11.3 Parallel Rebake

Multiple extents can be rebaked in parallel when their target device sets
are disjoint. The scheduler sorts extents by target device count and
allocates in non-overlapping batches using a greedy algorithm.

---

## 12. Snapshots and Rebake Interaction

A snapshot pins the ingest extent's data. When an extent is rebaked after
a snapshot is taken, the snapshot still references the original locator
entry. After rebake, the locator entry points to base shards, and the
snapshot benefits from improved redundancy. No special handling is needed
because snapshots reference the locator entry, not the ingest location.

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
| `tidefs.durability.level` | Gauge | Durability level (0-3) per dataset |
| `tidefs.durability.emergency_rebakes` | Counter | Emergency rebake activations |
| `tidefs.ingest.window_utilization_pct` | Gauge | Ingest window capacity utilization |
| `tidefs.shard.healthy_count` | Gauge | Healthy shards per dataset |
| `tidefs.replica.suspect_count` | Gauge | Suspect replicas per dataset |

### 13.2 Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| `DurabilityDegraded` | Level ≥ Warning for > 60s | Warning |
| `EmergencyRebakeActive` | Durability level == Critical | Critical |
| `WriteBlocked` | Durability level == LossImminent | Critical |
| `RebakeQueueStalled` | Oldest entry > 5× ingest window | Warning |

---

## 14. Tradeoffs and Alternatives

### 14.1 Deferred Redundancy vs. Write-Time Redundancy

| | Deferred (tidefs) | Write-Time (ZFS/Ceph) |
|---|---|---|
| Write latency | Lower (single device) | Higher (k+m or r writes) |
| Write amplification | 1x at ingest, k+m at rebake | Always k+m or r |
| Ingest window risk | Present; mitigated by durability ladder | None |
| Complexity | Higher (rebake service, lifecycle) | Lower |
| Space efficiency | Excellent after rebake | Good after write |

**Rationale:** The latency and amplification advantages outweigh the
added complexity of the rebake pathway, especially for write-heavy
workloads. The durability ladder provides a safety net for the ingest
window.

### 14.2 Erasure Coding vs. Replication

EC trades compute for space. For metadata and small blocks, replication
is preferred because IOPS matter more than space efficiency. For general
and archive data, EC provides 1.5x-1.375x overhead vs. 2x-3x for
replication.

### 14.3 Atomic per-Extent vs. Resumable Rebake

**Choice:** Atomic per-extent rebake (all-or-nothing).

Resumable rebake (saving partial progress) would add significant
complexity to the on-media format and crash recovery for minimal gain.
The per-tick budget model and re-queueing provide equivalent throughput
without the complexity of partial state management.

### 14.4 UUIDv4 vs. LocatorId for group_id

**Choice:** UUIDv4 for `group_id` in `ShardGroupV1`.

Using `LocatorId(u64)` would risk collision with stale on-media
leftovers across create/destroy cycles. UUIDv4 provides globally unique
identifiers without coordination, at the cost of 16 bytes per group.

### 14.5 Inline vs. Dedicated Rebake Thread Pool

**Choice:** Start inline with per-tick budgets; move to dedicated thread
only if demand I/O tail latency is impacted.

Rebake is I/O-heavy. Starting inline keeps the implementation simple.
The budget model ensures rebake doesn't starve demand I/O. If tail
latency becomes an issue, the service can be moved to a dedicated
thread pool without changing the algorithm.

---

## 15. Resolved Design Decisions

1. **Atomic per-extent rebake**: All-or-nothing; no partial state persisted.
2. **UUIDv4 group_id**: Avoids collision with stale on-media leftovers.
3. **Per-shard BLAKE3-256 digests**: Enables single-shard verification.
4. **Exclusive redundancy methods**: EC and replication are mutually exclusive per extent.
5. **Immutable RedundancyPolicy**: Changing policy requires dataset migration.
6. **Write blocking at LossImminent**: Prevents silent data loss; operator overridable.
7. **Snapshot locator reference**: Snapshots reference locator entries, not ingest locations directly.
8. **Three-dimensional ingest window**: Time, count, and capacity bounds; first hit wins.
9. **Safety gate for ingest trimming**: Only trim when BASE_COMPLETE and k/r shards readable.
10. **Pool export drain**: Complete in-flight rebakes before export; resume on import.

---

## 16. Wire-Up Phases (Deferred)

Rust implementation is deferred to wire-up issues tracked independently.
The canonical sealed spec (#2030) defines a 10-phase plan:

| Phase | Scope |
|-------|-------|
| 1 | `ShardGroupV1` encode/decode + tests |
| 2 | `ReplicaLifecycle` state machine + invariants |
| 3 | `RebakeQueue` structure + enqueue/dequeue/requeue |
| 5 | `RebakeService` skeleton implementing `BackgroundService` |
| 6 | EC encode/decode + `tidefs-erasure-coding` integration |
| 7 | Locator table update with `SHARDED|ERASURE_CODED` flags |
| 8 | `SegmentCleanerService` integration + safety gate |
| 9 | `DurabilityMonitor` service + emergency rebake |

---

## 17. Invariants

1. An extent with `ReplicaLifecycle::BaseComplete` MUST have k+m shards written on k+m distinct devices.
2. An extent with `RedundancyPolicy::Replicated { r }` MUST have r full copies on r distinct devices.
3. `replica_count` in `ShardGroupV1` is zero when `ec_m > 0`.
4. An ingest segment MUST NOT be trimmed until the safety gate confirms k (or r) shards are readable.
5. A rebake tick MUST NOT exceed any of the three budget dimensions.
6. `RedundancyPolicy` is immutable after dataset creation.
7. `ShardGroupV1.group_id` is unique; no two groups share the same UUID.
8. Each shard in a `ShardGroupV1` maps to exactly one device.
9. No two shards in the same `ShardGroupV1` share the same device.
10. `ExtentLifecycleState::BaseComplete` implies the locator has `SHARDED|ERASURE_CODED` flags.
11. At `LossImminent`, no new demand writes are accepted without operator override.
12. The `RebakeQueue` never contains an extent in `BASE_COMPLETE` state.
13. The `RebakeQueue` never contains an extent in `TRIMMED` state.
14. TideCRUSH placement respects fault domains: no two shards from the same group on the same failure domain.
15. All shard writes are verified (checksum comparison) before the locator is updated.
16. Extent rebake is idempotent: re-running rebake for an already-rebaked extent is a no-op.
17. The durability level of a dataset degrades monotonically as devices fail.

---

## 18. References

- **Canonical sealed spec**: #2030, `docs/design/shard-groups-replicas-rebake-design-spec.md`
- #1249 Erasure coding and CRUSH-like placement
- #1285 Extent maps and locator tables
- #1179 Background service framework
- #1287 End-to-end checksum architecture
- #1288 Scrub, repair, and resilver
- #1222 Rebake architecture
- #1215 Space accounting
- #1223 Dataset feature flags
- #1275 Online pool geometry conversion
- `crates/tidefs-erasure-coding/src/lib.rs`
- `crates/tidefs-erasure-coded-store/src/lib.rs`
- `crates/tidefs-replication-model/src/lib.rs`
- `crates/tidefs-replication/src/lib.rs`
- `crates/tidefs-replica-health/src/lib.rs`
- `crates/tidefs-types-locator-table-core/src/lib.rs`
- `crates/tidefs-types-extent-map-core/src/lib.rs`
- `crates/tidefs-locator-table/src/lib.rs`
