# Shard Groups, Replicas, and Rebake Pathway — Design Specification

**Maturity: design-spec** — Rust implementation deferred to wire-up issues.

**Issue:** #1963
**Lane:** storage-core
**Kind:** design
**Sealed lineage:** #1286 → #1553 → #1593 → #1626 → #1675 → #1704 → #1884 → #2030 → #1963

---

## 0. Document Purpose

This document defines the architecture, data structures, algorithms, and
tradeoffs for TideFS's distributed extent redundancy model: `ShardGroupV1`
encoding with `k+m` erasure shards, the ingest-replica lifecycle tracked
through a durability ladder, and the budgeted background `RebakeService`
that converts ingest extents into durable base shards.

All type signatures and state-machine transitions described here are binding
on future Rust implementations. No deviations are permitted without a new
design issue.

---

## 1. Motivation

TideFS writes data in two forms:

| Form | Characteristics |
|------|----------------|
| **Ingest extent** | Append-only journal write, single-device, low-latency, transient |
| **Base shard** | Erasure-coded or replicated, multi-device, durable, space-efficient |

Three problems arise without a formal shard-group model and rebake pathway:

1. **No redundancy during the ingest window.** An ingest extent lives on a
   single device. A device failure before rebake means data loss.
2. **No degradation path.** Without explicit replica counts and placement,
   the system cannot distinguish "degraded but safe" from "data at risk."
3. **No ingest bloat management.** Unbaked ingest accumulates CoW fragments
   that degrade read performance and waste space.

### Comparative Approach

| Concern | ZFS | Ceph | TideFS |
|---------|-----|------|--------|
| Write latency | Redundancy cost at write | Replication hop at write | Single-device latency; redundancy deferred |
| Write amplification | Always k+m writes | Always r writes | 1× at ingest; k+m at rebake |
| Ingest window risk | None (redundant immediately) | None (replicated immediately) | Protected by durability ladder + emergency rebake |
| Space efficiency | Good after write | Good after write | Excellent after rebake; ingest fragments reclaimed |

### Dependency Map

| Design / Crate | Relationship |
|---------------|-------------|
| `tidefs-erasure-coding` | GF(2⁸) Reed-Solomon encode/decode, `StripeConfig`, `ParityCount` |
| `tidefs-erasure-coded-store` | `ErasureCodedStore`: data + parity shard storage with repair |
| `tidefs-replication-model` | `ErasureLayoutPolicy`, `ErasureShardClass`, `ErasureDecodeClass` |
| `tidefs-replication` | `ReplicationPolicy`, `ReplicationProtocol` fanout/ack/commit |
| `tidefs-replica-health` | `HealthState`, `SuspicionTracker`, `FlapDetector` |
| `tidefs-types-locator-table-core` | `ExtentLocatorValueV1`, `ReplicaPlacement`, `ReplicaHealth` |
| `tidefs-types-extent-map-core` | `ExtentLifecycleState`, `LocatorId`, `ExtentId` |
| `tidefs-locator-table` | `V1LocatorTable`: inline-hash locator storage |
| #1215 Space accounting | `SegmentCleanerService` frees ingest space after rebake |
| #1249 Erasure coding placement | TideCRUSH places shards; `EcProfile` selects (k,m) |
| #1287 Checksum architecture | `IntegrityTrailerV2` per-shard digests |
| #1288 Scrub/repair/resilver | Repair selects source from healthy shards |

---

## 2. Design Overview

### 2.1 Core Abstractions

| Abstraction | Responsibility |
|-------------|---------------|
| `ShardGroupV1` | Encodes k data shards + m parity shards for one extent; on-media format |
| `ReplicaLifecycle` | Tracks an ingest replica from write through rebake to trim |
| `RebakeService` | Background service converting ingest to base shards under budget |
| `DurabilityLadder` | Per-dataset redundancy target policy and transition triggers |
| `DurabilityMonitor` | Periodic health assessment; emergency rebake escalation |

### 2.2 Durability Ladder

```
Level 1: None          — single copy (ingest only, writes land here)
Level 2: Replicated    — r copies on distinct devices (r ≥ 2)
Level 3: ErasureCoded  — k+m shards across (k+m) devices
```

Datasets transition up the ladder as data ages past the ingest window. The
`RebakeService` drives transitions from `None` → `Replicated` or
`None` → `ErasureCoded` based on the dataset's `RedundancyPolicy`.

### 2.3 Data Flow

```
Write → Ingest Extent (single device) → IngestWindow timer →
  RebakeService reads ingest → erasure-encodes (or replicates) →
  writes k+m shards → updates LocatorTable → trims ingest segment
```

---

## 3. Data Structures

### 3.1 `ShardGroupV1` — On-Media Format

Encodes one extent as k data shards + m parity shards. Total on-media
size: 80 + (k+m) × 48 bytes.

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardGroupV1 {
    /// Unique identifier (maps 1:1 to LocatorId).
    pub group_id: [u8; 16],

    /// Erasure coding profile.
    pub ec_k: u8,
    pub ec_m: u8,

    /// Flags: bit 0 = COMPACTED, bit 1 = BASE_COMPLETE, bits 2–7 reserved.
    pub flags: u8,

    /// Logical byte range covered by this extent.
    pub logical_offset: u64,
    pub logical_length: u64,

    /// BLAKE3-256 over the original logical byte range (pre-encoding).
    pub original_digest: [u8; 32],

    /// Per-shard metadata: physical location, shard digest, shard length.
    pub shards: Vec<ShardDescriptor>,

    /// Number of replicas (zero for erasure-coded datasets).
    pub replica_count: u8,

    /// Reserved for TLV extension.
    pub reserved: [u8; 9],

    /// CRC32C over all preceding fields.
    pub crc32c: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardDescriptor {
    /// Index of this shard (0..k−1 = data, k..k+m−1 = parity).
    pub shard_index: u8,

    /// Device holding this shard.
    pub device_id: u32,

    /// Physical offset on the device.
    pub physical_offset: u64,

    /// Length of the shard payload in bytes.
    pub shard_length: u64,

    /// BLAKE3-256 over this shard's payload.
    pub shard_digest: [u8; 32],

    /// Integrity trailer type (0 = none, 1 = IntegrityTrailerV2).
    pub trailer_type: u8,

    /// Reserved for TLV extension.
    pub reserved: [u8; 3],
}
```

### 3.2 `ReplicaLifecycle` — State Machine

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplicaLifecycleState {
    /// Extent has been written to a single device (no redundancy).
    Ingest,

    /// Extent is being rebaked (reads enqueued, shard writes in progress).
    Rebaking,

    /// Base shards are written; locator entry updated; ingest copy can be trimmed.
    BaseComplete,

    /// Ingest segment has been reclaimed by SegmentCleanerService.
    Trimmed,
}
```

State transitions:

```
Ingest ──[rebake dequeued]──▶ Rebaking ──[all shards written + verified]──▶ BaseComplete
                                                                                    │
                                                                                    ▼
BaseComplete ──[SegmentCleaner frees ingest space]──▶ Trimmed
```

### 3.3 `DurabilityLevel` — Per-Dataset Redundancy State

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DurabilityLevel {
    /// Single copy on one device. Data loss on single device failure.
    None,

    /// r copies on distinct devices. Tolerates r−1 device failures.
    Replicated { replica_count: u8 },

    /// k+m erasure shards. Tolerates any m shard losses.
    ErasureCoded { ec_k: u8, ec_m: u8 },

    /// Fewer than target replicas/shards readable. At risk of data loss.
    Critical { healthy: u8, target: u8 },

    /// Only one replica/set of shards remains. Writes blocked.
    LossImminent,
}
```

### 3.4 `RedundancyPolicy` — Dataset-Level Configuration

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedundancyPolicy {
    /// Target durability level for this dataset.
    pub target_level: DurabilityLevel,

    /// Ingest window: max duration before rebake is triggered.
    pub ingest_window_max_seconds: u64,

    /// Ingest window: max extent count before rebake is triggered.
    pub ingest_window_max_extents: u64,

    /// Ingest window: max bytes before rebake is triggered.
    pub ingest_window_max_bytes: u64,

    /// Minimum replicas for replicated datasets.
    pub replica_min_count: u8,

    /// Whether writes are blocked at LossImminent.
    pub block_writes_at_loss_imminent: bool,
}
```

### 3.5 `RebakeQueueEntry` — Rebake Work Item

```rust
#[derive(Clone, Debug)]
pub struct RebakeQueueEntry {
    /// Locator ID for the extent to rebake.
    pub locator_id: LocatorId,

    /// Extent ID.
    pub extent_id: ExtentId,

    /// Device where the ingest extent resides.
    pub ingest_device_id: u32,

    /// Physical offset of the ingest extent.
    pub ingest_offset: u64,

    /// Logical byte range.
    pub logical_offset: u64,
    pub logical_length: u64,

    /// Target redundancy: erasure profile or replica count.
    pub target_policy: RedundancyPolicy,

    /// Enqueue timestamp (monotonic).
    pub enqueued_at: u64,

    /// Priority (higher = more urgent).
    pub priority: u8,
}
```

### 3.6 `RebakeProgress` — Atomic Progress Tracking

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RebakeProgress {
    /// Not yet started.
    Pending,

    /// Ingest extent read in progress.
    ReadingIngest { bytes_read: u64, total_bytes: u64 },

    /// Erasure encoding (or replication) in progress.
    Encoding { shards_encoded: u8, total_shards: u8 },

    /// Writing shards to target devices.
    WritingShards { shards_written: u8, total_shards: u8 },

    /// Verifying shard integrity (digest check).
    Verifying { shards_verified: u8, total_shards: u8 },

    /// Locator table update pending.
    UpdatingLocator,

    /// Rebake complete.
    Complete,

    /// Rebake failed (reason carried in error).
    Failed(RebakeError),
}
```

---

## 4. Algorithms

### 4.1 Rebake Tick — The Core Scheduling Loop

```
fn rebake_tick(budget: RebakeBudget) -> RebakeTickResult:
    extents = deque from rebake_queue (up to budget.max_extents)
    result = empty RebakeTickResult

    for each extent in extents:
        if budget.bytes_read + extent.logical_length > budget.max_read_bytes:
            break   // budget exhausted

        progress = rebake_one_extent(extent, budget)
        result.extents_processed += 1

        match progress:
            Complete:
                update LocatorTable: set BASE_COMPLETE flag
                enqueue for SegmentCleaner trim
                result.extents_rebaked += 1
            Failed(error):
                re-queue extent (back of queue)
                result.errors.push(error)
            Partial(remaining):
                re-queue extent (front of queue for next tick)
                break  // budget or time exhausted mid-extent
    return result
```

### 4.2 `rebake_one_extent` — Single Extent Conversion

```
fn rebake_one_extent(entry: RebakeQueueEntry, budget: &mut RebakeBudget)
    -> RebakeProgress:

    // Step 1: Read ingest extent
    ingest_data = read_from_device(entry.ingest_device_id, entry.ingest_offset,
                                    entry.logical_length)
    if read fails: return Failed(IngestReadFailed)

    // Step 2: Erasure encode (or replicate)
    match entry.target_policy.target_level:
        ErasureCoded(k, m):
            plan = TideCRUSH.place(k + m, exclude=[entry.ingest_device_id])
            shards = erasure_encode(ingest_data, k, m)
        Replicated(r):
            plan = TideCRUSH.place_replicas(r, exclude=[entry.ingest_device_id])
            shards = replicate(ingest_data, r)

    if placement fails: return Failed(InsufficientTargets)

    // Step 3: Write shards to target devices (atomic: all-or-nothing)
    for each (shard, target) in zip(shards, plan.targets):
        write_shard_to_device(target.device_id, target.offset, shard)
        verify_shard_digest(target.device_id, target.offset, shard.digest)

    if any write or verify fails: return Failed(ShardWriteFailed)

    // Step 4: Create ShardGroupV1 and update locator
    group = ShardGroupV1 { ... from entry + plan ... }
    locator.update(entry.locator_id, group, BASE_COMPLETE)

    return Complete
```

### 4.3 Emergency Rebake — Durability Ladder Escalation

```
fn durability_monitor_tick():
    for each dataset:
        level = compute_durability_level(dataset)

        if level >= Critical:
            enqueue all ingest extents at front of rebake queue
            set rebake priority = MAX

        if level == LossImminent and dataset.policy.block_writes_at_loss_imminent:
            block_new_writes(dataset)
            emit_critical_alert(dataset)
```

### 4.4 Ingest Window Expiry

The `RebakeScheduler` evaluates three thresholds concurrently:

```
fn ingest_window_should_rebake(extent, policy) -> bool:
    return (now - extent.write_time > policy.ingest_window_max_seconds)
        or (ingest_pool.extent_count > policy.ingest_window_max_extents)
        or (ingest_pool.total_bytes > policy.ingest_window_max_bytes)
```

When any threshold is crossed, qualifying extents are enqueued for rebake
with priority proportional to age (oldest first).

### 4.5 Shard Repair from Surviving Shards

```
fn repair_shard(group: ShardGroupV1, missing_index: u8):
    surviving = [s for s in group.shards if s.shard_index != missing_index]
    if surviving.len() < group.ec_k: return Failed(InsufficientShards)

    surviving_data = [read_shard(s) for s in surviving[0..k]]
    reconstructed = erasure_decode(surviving_data, group.ec_k, group.ec_m,
                                    missing_index)
    write_shard(reconstructed, target_for(missing_index))
```

---

## 5. Architecture

### 5.1 Component Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    Dataset Layer                          │
│  RedundancyPolicy  ──  IngestWindowConfig  ──  LocatorId │
└──────────────────────────┬──────────────────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                 ▼
┌─────────────────┐ ┌──────────────┐ ┌──────────────────┐
│  RebakeService   │ │DurabilityMon│ │ SegmentCleaner    │
│  (BackgroundSvc) │ │  itor        │ │ Service           │
│                  │ │              │ │                   │
│  rebake_queue    │ │ per-dataset  │ │ trim_after(       │
│  rebake_tick()   │ │ health scan  │ │   locator.        │
│  atomic_extent() │ │ emergency    │ │   base_complete)  │
│                  │ │ rebake       │ │                   │
└────────┬─────────┘ └──────┬───────┘ └────────┬──────────┘
         │                  │                   │
         ▼                  ▼                   ▼
┌─────────────────────────────────────────────────────────┐
│                   Locator Table                           │
│  ExtentLocatorValueV1  ──  ReplicaPlacement  ──  Flags  │
│  (SHARDED | ERASURE_CODED | BASE_COMPLETE)               │
└──────────────────────────┬──────────────────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                 ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────────┐
│ ErasureCoding│  │  Replication │  │   TideCRUSH       │
│ encode/decode│  │ fanout/ack/  │  │   placement       │
│ GF(2^8) RS   │  │   commit     │  │   target_select   │
└──────────────┘  └──────────────┘  └──────────────────┘
```

### 5.2 Write Path (Ingest)

1. Application writes data → VFS layer → `ExtentMap` allocates extent →
   `LocatorTable` assigns `LocatorId` → data written to single device as
   ingest extent → `ReplicaLifecycle` state = `Ingest`.

### 5.3 Rebake Path

1. `IngestWindow` triggers (time, count, or byte threshold).
2. `RebakeScheduler` dequeues extents, respecting `RebakeBudget`.
3. `RebakeService` reads ingest extent, encodes/encodes via
   `tidefs-erasure-coding` or replicates via `tidefs-replication`.
4. `TideCRUSH` selects target devices (excluding the ingest device).
5. Shards written atomically (all-or-nothing per extent).
6. `LocatorTable` updated: flags set to `SHARDED | ERASURE_CODED | BASE_COMPLETE`;
   `ReplicaPlacement` populated with per-device `ShardPlacement` entries.
7. `SegmentCleanerService` trims ingest segment when `k` shards are readable.

### 5.4 Read Path

1. Application reads data → `LocatorTable` lookup returns `ExtentLocatorValueV1`.
2. If `BASE_COMPLETE`: read from `k` data shards (fast path).
3. If `Ingest`: read from single ingest device (degraded but valid).
4. If missing shards: `ErasureDecode` reconstructs from surviving `k` shards.
5. Health-aware candidate selection via `tidefs-replica-health`.

### 5.5 Repair Path

1. `DurabilityMonitor` detects degraded shards (fewer than `k+m` readable).
2. `ScrubService` or `RebuildPlanner` triggers repair.
3. Source selection from healthy shards (prefer data over parity for
   decode efficiency).
4. `ErasureDecode` reconstructs missing shard.
5. Write reconstructed shard to replacement device.
6. Update `LocatorTable` with new shard placement.

---

## 6. Tradeoffs

### 6.1 Atomic Rebake (Per-Extent All-or-Nothing)

**Decision:** Rebake is atomic per extent. Either all k+m shards are
written and verified, or the extent is re-queued. No partial state.

**Rationale:**
- Simplifies recovery: no orphaned shards to track.
- Avoids complex partial-progress metadata.
- Failure handling is trivial: re-queue and retry.

**Cost:**
- Large extents may exceed a single tick's budget, delaying rebake.
- Mitigated by `REBAKE_MAX_READ_BYTES_PER_TICK` and `REBAKE_MAX_WRITE_BYTES_PER_TICK`
  set large enough for typical extent sizes (64 KiB–1 MiB).

### 6.2 Deferred Redundancy (Ingest Window)

**Decision:** Writes land on a single device; redundancy is added
asynchronously within the ingest window (default 60 s).

**Rationale:**
- Lowest possible write latency (no cross-device coordination at write time).
- Write amplification amortized over the ingest window.

**Cost:**
- Ingest window is a vulnerability window (single device failure = data loss
  for unrebaited extents).
- Mitigated by short ingest window, emergency rebake when `DurabilityLevel`
  drops to `Critical`, and `LossImminent` write-blocking.

### 6.3 Inline vs. Dedicated Rebake Thread

**Decision:** Start inline in the background scheduler; move to a dedicated
I/O thread pool only if demand I/O tail latency is impacted.

**Rationale:**
- Simpler implementation, fewer concurrency bugs.
- Per-tick budgets bound the inline work.
- Tail latency impact can be measured before committing to complexity.

**Tradeoff:**
- If ingest volume outpaces inline rebake throughput, the rebake queue
  grows and the ingest window may expire. The `DurabilityMonitor` will
  detect this and escalate.

### 6.4 Shard Size Selection

**Decision:** Default shard size = 64 KiB, configurable per dataset via
`recordsize`-adaptive sharding.

**Rationale:**
- 64 KiB balances metadata overhead against repair granularity.
- Smaller shards → more metadata, finer repair granularity.
- Larger shards → less metadata, coarser repair (more read amplification
  for small IOs).
- `recordsize`-adaptive sharding ensures datasets with small `recordsize`
  use proportionally smaller shards.

### 6.5 Write Blocking at LossImminent

**Decision:** Block writes when only one replica/shards remains.
Operator can override via `tidefs.pool.allow_write_during_loss_imminent=1`.

**Rationale:**
- Prevents silent data loss when the system is on the brink.
- Availability vs. durability tradeoff: blocking is safe but impacts availability.
- Override gives operators control during maintenance windows where they
  understand the risk.

### 6.6 Snapshot Interaction

**Decision:** Snapshots reference the locator entry (not the ingest location
directly). After rebake, the locator points to base shards, and snapshots
automatically benefit from improved redundancy.

**Rationale:**
- No special snapshot handling needed.
- Ingest segment trimming is gated on all referencing snapshots being
  destroyed (via standard refcount mechanism).
- Snapshot creation and deletion have zero additional complexity in the
  rebake pathway.

---

## 7. Integration Points

### 7.1 With `tidefs-erasure-coding`

The `StripeConfig` type and `encode`/`reconstruct` functions provide the
GF(2⁸) Reed-Solomon engine. `RebakeService` calls `encode()` to produce
`k+m` shards, and repair calls `reconstruct()` to recover missing shards.

### 7.2 With `tidefs-locator-table`

The `V1LocatorTable` stores `ExtentLocatorValueV1` entries. After rebake:

- `lifecycle_state` transitions from `Ingest` to `Rebaking` to `BaseComplete`.
- `replica_placement` is populated with `ShardPlacement` entries.
- `flags` are updated with `SHARDED | ERASURE_CODED`.
- `SegmentCleanerService` queries `lifecycle_state == BaseComplete` to
  identify trimmable ingest segments.

### 7.3 With `tidefs-replica-health`

Per-device health tracking via `HealthState`, `SuspicionTracker`, and
`FlapDetector`. `DurabilityMonitor` queries replica health to compute
per-dataset `DurabilityLevel` and trigger emergency rebake.

### 7.4 With `tidefs-replication`

When the `RedundancyPolicy` specifies `DurabilityLevel::Replicated`,
`RebakeService` uses `ReplicationProtocol` for fanout writes and quorum
ACKs instead of erasure coding. The `ReplicaLifecycle` transitions are
identical; only the encoding step differs.

### 7.5 With Space Accounting

After `BaseComplete`, the ingest segment is reclaimable. `SegmentCleanerService`
trims the segment and updates physical space counters. The rebake pathway
is a net space consumer (k+m writes vs. 1 read), but the reclaimed ingest
space offsets this.

---

## 8. Error Handling

### 8.1 Error Hierarchy

```rust
pub enum ShardGroupError {
    /// TideCRUSH placement returned insufficient targets.
    InsufficientTargets { needed: u8, available: u8 },

    /// Erasure coding encode/decode failed.
    EncodeDecodeFailed { reason: String },

    /// Shard write to target device failed.
    ShardWriteFailed { shard_index: u8, device_id: u32, reason: String },

    /// Locator table update failed.
    LocatorUpdateFailed { locator_id: u64, reason: String },

    /// Integrity trailer mismatch on written shard.
    ShardIntegrityMismatch { shard_index: u8, expected: [u8; 32], actual: [u8; 32] },
}

pub enum RebakeError {
    /// Ingest extent is no longer valid (overwritten or truncated).
    ExtentStale { extent_id: u64 },

    /// Ingest extent could not be read.
    IngestReadFailed { extent_id: u64, reason: String },

    /// Rebake budget exhausted mid-extent.
    BudgetExhausted { extent_id: u64, extent_progress: RebakeProgress },

    /// Rebake queue is backed up beyond threshold.
    QueueOverflow { depth: u64, max: u64 },
}
```

### 8.2 Recovery Strategies

| Failure | Strategy |
|---------|----------|
| Ingest read failed | Re-queue extent; if persistent, mark extent `Corrupt` and alert |
| Encode/decode failed | Re-queue; if persistent, mark extent `Corrupt` and alert |
| Shard write failed | Re-queue entire extent (atomic: all-or-nothing) |
| Partial shard writes (crash) | Shards are orphaned; extent re-queued on restart |
| Budget exhausted mid-extent | Re-queue at front for next tick; no partial state |
| Locator table update failed | Retry with exponential backoff; critical alert on persistent failure |
| Queue overflow | Escalate to emergency rebake; drop lowest-priority entries if critical |

---

## 9. Configuration Constants

| Constant | Default | Meaning |
|----------|---------|---------|
| `INGEST_WINDOW_MAX_SECONDS` | 60 | Max seconds an extent stays in `Ingest` state |
| `INGEST_WINDOW_MAX_EXTENTS` | 10,000 | Max ingest extents before rebake triggers |
| `INGEST_WINDOW_MAX_BYTES` | 1 GiB | Max ingest bytes before rebake triggers |
| `REBAKE_MAX_EXTENTS_PER_TICK` | 50 | Max extents rebaked per tick |
| `REBAKE_MAX_READ_BYTES_PER_TICK` | 256 MiB | Max ingest bytes read per tick |
| `REBAKE_MAX_WRITE_BYTES_PER_TICK` | 512 MiB | Max shard bytes written per tick |
| `REPLICA_MIN_COUNT_DEFAULT` | 2 | Minimum replicas for replicated datasets |
| `DURABILITY_CRITICAL_THRESHOLD` | 2 | Replicas below target triggers emergency rebake |
| `DURABILITY_LOSS_IMMINENT` | 1 | Only 1 replica remaining; block writes |
| `DEFAULT_SHARD_SIZE` | 64 KiB | Default shard paypload size |

---

## 10. Resolved Design Decisions

The following were resolved during the sealed design lineage (#1286 → #2030).
These are binding for implementers.

1. **Atomic rebake per extent.** No partial state. Extents are either fully
   rebaked or re-queued. Orphaned shards from crashes are cleaned up by
   `SegmentCleanerService`.

2. **Start inline, measure, then move to dedicated thread.** The initial
   implementation runs `RebakeService` inline in the background scheduler.
   Only move to a dedicated I/O thread pool if demand I/O tail latency is
   measurably impacted.

3. **Drain rebake queue before pool export.** Complete in-flight rebakes,
   suspend the queue, and resume on import. The rebake queue is reconstructed
   from locator entries with `lifecycle_state == Ingest`.

4. **Block writes at `LossImminent`.** Default is to block. Operator override:
   `tidefs.pool.allow_write_during_loss_imminent=1`.

5. **Snapshots reference locator entries.** After rebake, the locator points
   to base shards, and snapshots benefit from improved redundancy with zero
   additional handling.

6. **Default 64 KiB shard size.** Configurable per dataset. `recordsize`-adaptive
   sharding for datasets that tune `recordsize`.

---

## 11. Wire-Up Implementation Plan (Deferred)

Rust implementation is deferred to wire-up issues. Each phase will be
tracked as an independent Forgejo issue marked `codex:ready`. Implementers
must:

- Reference this design spec (#1963) in their implementation issues.
- Not deviate from the types, state machines, or algorithms defined here.
- Open a new design issue if changes are needed.

| Phase | Scope | Target Crates |
|-------|-------|--------------|
| 1 | `ShardGroupV1` + `ShardDescriptor` types | `tidefs-types-locator-table-core` |
| 2 | `ReplicaLifecycle` state machine | `tidefs-types-extent-map-core` |
| 3 | `RedundancyPolicy` + `DurabilityLevel` types | `tidefs-types-locator-table-core` |
| 4 | `RebakeQueueEntry` + `RebakeProgress` types | `tidefs-rebake` (new) |
| 5 | `RebakeBudget` + `RebakeScheduler` | `tidefs-rebake` (new) |
| 6 | `RebakeService::rebake_tick()` integration | `tidefs-rebake` (new) |
| 7 | Locator table integration (BASE_COMPLETE flag, shard metadata) | `tidefs-locator-table` |
| 8 | `SegmentCleanerService` ingest trim gating | `tidefs-cleanup-job-core` |
| 9 | `DurabilityMonitor` service | `tidefs-rebake` (new) |

---

## 12. References

- [#1286] Original shard groups & rebake design
- [#1704] Sealed design specification
- [#1884] Prior sealed design specification
- [#2030] Prior sealed design specification
- [#1963] This design specification
- `docs/design/shard-groups-replicas-rebake-design-spec.md` — sealed spec (#2030)
- `docs/design/rebake-architecture-ingest-journal-to-base-shard-conversion.md`
- `docs/design/scrub-deep-scrub-repair-resilver-orchestration-design.md`
- `docs/ERASURE_CODING_PLACEMENT_DESIGN.md`
- `docs/EXTENT_MAPS_LOCATOR_TABLES_DESIGN.md`
- `crates/tidefs-erasure-coding/src/lib.rs`
- `crates/tidefs-erasure-coded-store/src/lib.rs`
- `crates/tidefs-replication/src/lib.rs`
- `crates/tidefs-replication-model/src/lib.rs`
- `crates/tidefs-replica-health/src/lib.rs`
- `crates/tidefs-locator-table/src/lib.rs`
- `crates/tidefs-types-locator-table-core/src/lib.rs`
- `crates/tidefs-types-extent-map-core/src/lib.rs`
