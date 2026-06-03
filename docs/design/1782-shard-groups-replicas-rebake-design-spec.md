# Shard Groups, Replicas, and Rebake Pathway — Design Specification

**Status: Sealed** — Maturity: **design-spec** for the distributed extent
redundancy model: `ShardGroupV1` encoding with k+m erasure shards, ingest-
replica lifecycle with durability ladder, and budgeted background
`RebakeService` converting ingest extents into base shards.

**Issue:** #1782
**Prior iterations:** #1286 (original design), #1553 (design-spec refinement), #1593 (prior iteration), #1626 (original), #1675 (refinement), #1704 (prior sealed spec)
**Lane:** storage-core
**Kind:** design
**Sealed:** 2026-05-05

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

The design decisions in Section 16 are binding for implementers.

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
Level 1: None        → single copy, data at risk
Level 2: Replicated  → r full copies distributed across devices
Level 3: ErasureCoded → k+m shards with m-failure tolerance
Level 4: Archive     → multi-site geo-redundancy (out of scope)
```

### 2.1 Lifecycle State Machine

```
                              ┌─────────────────────────┐
                              │   Ingest (fresh write)   │
                              │   replica_count = 1      │
                              │   shard_count = 0        │
                              └────────────┬────────────┘
                                           │
                                 RebakeService picks extent
                                           │
                              ┌────────────▼────────────┐
                              │   Rebaking               │
                              │   k+m shards being       │
                              │   computed and written   │
                              └────────────┬────────────┘
                                           │
                              ┌────────────▼────────────┐
                              │   BaseComplete           │
                              │   k+m shards on disk     │
                              │   locator updated        │
                              └────────────┬────────────┘
                                           │
                              ┌────────────▼────────────┐
                              │   Trimmed                │
                              │   ingest fragment freed  │
                              │   only base shards remain│
                              └─────────────────────────┘
```

---

## 3. Data Structures

### 3.1 ShardGroupV1 — On-Media Format

```rust
/// Encodes one extent as k data shards + m parity shards.
/// Stored as a set of per-device shard blobs, each with an
/// `IntegrityTrailerV2` footer.
pub struct ShardGroupV1 {
    /// Number of data shards (k)
    pub data_count: u8,
    /// Number of parity shards (m)
    pub parity_count: u8,
    /// Uncompressed byte length of the original extent
    pub extent_logical_len: u64,
    /// Compressed byte length of the extent payload before sharding
    pub extent_compressed_len: u64,
    /// Shard size in bytes (uniform across all shards)
    pub shard_size: u32,
    /// GF(2^8) field polynomial identifier
    pub gf_field: u8,
    /// Per-shard ordering index
    pub shard_indices: [u8; MAX_SHARDS],
    /// Locator ID this shard group belongs to
    pub locator_id: LocatorId,
    /// Monotonically increasing rebake generation
    pub rebake_generation: u64,
}

const MAX_SHARDS: usize = 32;
```

**Encoding layout:** The compressed extent payload is zero-padded to a
multiple of `shard_size * data_count`, then split into `data_count`
shards. `parity_count` parity shards are computed via Reed-Solomon over
GF(2^8) using the Vandermonde matrix.

**Per-shard blob format:** `[shard_header(32B) | shard_payload(shard_size) | IntegrityTrailerV2]`

### 3.2 ExtentLocatorValueV1 Extensions

```rust
pub struct ExtentLocatorValueV1 {
    // ... existing fields ...
    pub locator_id: LocatorId,
    pub extent_id: ExtentId,
    pub lifecycle: ExtentLifecycleState,
    /// Shard placements when erasure-coded; empty when Ingest only
    pub shard_placements: Vec<ShardPlacement>,
    /// Replica placements for replicated mode
    pub replica_placements: Vec<ReplicaPlacement>,
    /// Redundancy flags
    pub flags: LocatorFlags,
}

pub struct ShardPlacement {
    pub device_id: DeviceId,
    pub shard_index: u8,
    pub shard_offset: u64,
    pub shard_len: u32,
    pub health: ReplicaHealth,
}

bitflags! {
    pub struct LocatorFlags: u16 {
        const INGEST_ONLY     = 0x0001;
        const REPLICATED      = 0x0002;
        const SHARDED         = 0x0004;
        const ERASURE_CODED   = 0x0008;
        const BASE_COMPLETE   = 0x0010;
        const TRIMMED         = 0x0020;
        const CORRUPT         = 0x0040;
        const NEEDS_REPAIR    = 0x0080;
    }
}
```

### 3.3 ExtentLifecycleState

```rust
pub enum ExtentLifecycleState {
    /// Fresh ingest write; single copy on one device
    Ingest,
    /// Actively being rebaked (k+m shard computation and write in progress)
    Rebaking,
    /// Base shards written; locator entry updated; ingest fragment still present
    BaseComplete,
    /// Ingest fragment freed; only base shards remain
    Trimmed,
}
```

### 3.4 Durability Ladder

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DurabilityLevel {
    /// Data is safe: k healthy shards accessible
    Safe,
    /// One device missing but k shards still accessible
    Degraded,
    /// k-1 shards accessible; one failure from data loss
    Critical,
    /// k-2 or fewer shards accessible; data loss imminent
    LossImminent,
    /// Data unrecoverable
    Lost,
}

#[derive(Debug, Clone)]
pub struct DurabilityState {
    pub dataset_id: DatasetId,
    pub level: DurabilityLevel,
    pub healthy_shards: u8,
    pub total_shards: u8,
    pub min_required: u8,  // k
    pub last_computed: Instant,
    pub extents_at_risk: u64,
}
```

### 3.5 ServiceBudget for RebakeService

```rust
pub struct RebakeBudget {
    /// Maximum bytes to process per tick
    pub max_bytes_per_tick: u64,
    /// Maximum concurrent rebake operations
    pub max_concurrent_ops: u32,
    /// Target tick interval
    pub tick_interval: Duration,
    /// I/O priority class for rebake operations
    pub io_priority: IoPriorityClass,
}
```

---

## 4. Algorithms

### 4.1 RebakeService Main Loop

```
tick():
    1. Acquire service budget token from BackgroundService framework
    2. Query locator table for entries with:
       - lifecycle == Ingest
       - ORDER BY extent_creation_time ASC (oldest first)
    3. For each candidate extent, while budget_remaining > 0:
       a. Read compressed extent payload from ingest device
       c. Lookup EcProfile for dataset → (k, m)
       d. Allocate ShardGroupV1
       e. Call erasure_codec.encode(extent_payload, k, m)
       f. Place k+m shards on target devices via TideCRUSH
          (respecting device failure domains)
       g. Write each shard to target device with IntegrityTrailerV2
       h. Atomically update ExtentLocatorValueV1:
          - Set flags: SHARDED | ERASURE_CODED | BASE_COMPLETE
          - Populate shard_placements
          - Set lifecycle = BaseComplete
          - Increment rebake_generation
       i. Deduct bytes_processed from budget
    4. Release budget token
    5. Schedule next tick at tick_interval
```

### 4.2 Erasure Encode / Decode

```
encode(extent_payload, k, m) → Vec<ShardBlob>:
    1. Pad extent_payload to multiple of shard_size * k
    2. Split into k data shards of shard_size bytes each
    3. Build Vandermonde matrix V of size (k+m) × k over GF(2^8)
    4. For each row j in [k, k+m):
       parity[j-k] = sum over i in [0,k): V[j][i] * data[i] (GF mul)
    5. Return data[0..k] ++ parity[0..m] as ShardBlob vec

decode(available_shards, k, m, shard_indices) → extent_payload:
    1. Build k×k submatrix M from Vandermonde rows at available indices
    2. Invert M over GF(2^8)
    3. Reconstruct data shards = M_inv * available_shards
    4. Strip padding, return extent_payload
```

### 4.3 Shard Placement via TideCRUSH

```
place_shards(k, m, dataset, ec_profile) → Vec<ShardPlacement>:
    1. Query device topology for dataset's pool
    2. Build failure domain tree (rack → host → device)
    3. For each shard i in [0, k+m):
       a. Hash(extent_id, shard_index=i, rebake_generation)
       b. TideCRUSH.select(hash, ec_profile.constraints)
          - Constraint: no two shards on same device
          - Constraint: at most floor(m/2) shards per failure domain
       c. Record (device_id, shard_index, offset, length)
    4. Return placements
```

### 4.4 DurabilityMonitor

```
monitor_tick():
    1. For each dataset with RedundancyPolicy:
       a. Query all locator entries with lifecycle in {BaseComplete, Trimmed}
       b. For each entry, count healthy shards (HealthState == Healthy)
       c. Compute DurabilityLevel:
          - healthy >= k+m         → Safe
          - healthy >= k           → Degraded
          - healthy == k-1         → Critical
          - healthy <= k-2         → LossImminent
          - healthy == 0           → Lost
       d. Update DurabilityState
    2. If any dataset at Critical:
       a. Elevate RebakeService priority to URGENT
       b. Grant extra budget
       c. Log alert
    3. If any dataset at LossImminent:
       a. Block new writes to affected dataset (unless override)
       b. Trigger emergency rebake of all Ingest extents
       c. Page operator

### 4.5 Read Path with Degraded Mode

```
read_extent(extent_id) → extent_payload:
    1. Lookup LocatorId from extent map
    2. Read ExtentLocatorValueV1 from locator table
    3. Match lifecycle:
       - Ingest: read directly from ingest device
       - BaseComplete | Trimmed:
         a. Try reading k data shards
         b. If any shard read fails:
            - Mark shard health as Suspect
            - Read m parity shards
            - Decode: reconstruct missing data shards
            - Log degradation event
         c. Return reconstructed payload
```

### 4.6 Atomicity Guarantee

Rebake is atomic per extent: either all k+m shards are written and the
locator entry is updated, or the extent remains in `Ingest` lifecycle.
No partial state is observable.

Implementation: the locator update is the atomic commit point. Shard
writes are idempotent (same content, same device offset). On crash
recovery, the RebakeService queries for `Ingest` extents and restarts
rebake for each. Partially written shards from a failed rebake are
overwritten by the idempotent re-encode.

---

## 5. Tradeoffs

### 5.1 Latency vs. Durability

| Approach | Write Latency | Durability Window | Space Amp |
|----------|--------------|-------------------|-----------|
| Write redundancy (ZFS, Ceph) | Higher (multi-device I/O) | Zero (immediate) | k+m at write |
| Deferred rebake (tidefs) | Lower (single-device I/O) | Non-zero (until rebake) | 1x initially; k+m after |
| Hybrid (emergency rebake) | Normal until Critical, then spiked | Bounded by rebake rate | 1x → k+m |

**Tradeoff accepted:** tidefs accepts a bounded ingest window risk in
exchange for lower write latency. The durability ladder ensures the
window stays bounded. For workloads needing zero-durability-window,
the operator can set `recordsize` high and use `RedundancyPolicy=Replicated`
(which triggers immediate replication, not deferred rebake).

### 5.2 Shard Size vs. I/O Amplification

| Shard size | Metadata overhead | Small I/O amp | Repair granularity |
|-----------|------------------|---------------|-------------------|
| 4 KiB     | High             | Low           | Fine              |
| 64 KiB    | Medium           | Medium        | Medium            |
| 1 MiB     | Low              | High          | Coarse            |

**Tradeoff accepted:** 64 KiB default, per-dataset override. Read path
can issue sub-shard reads (fetch only needed portion) to reduce
amplification for small random reads.

### 5.3 Budget vs. Ingest Bloat

A tight rebake budget reduces interference with demand I/O but allows
ingest fragments to accumulate. A loose budget clears ingest faster
but may starve demand reads.

**Tradeoff accepted:** Use the BackgroundService framework's adaptive
budget (Section 3.5). At `Normal` durability, use default budget. At
`Critical`, double the budget. At `LossImminent`, use unlimited budget
until durability recovers.

### 5.4 Erasure Coding vs. Replication

| Property | Erasure Coding (k+m) | Replication (r) |
|----------|---------------------|-----------------|
| Storage overhead | m/k | r-1 copies |
| Read latency (healthy) | k reads | 1 read |
| Read latency (degraded) | k+m reads + decode | r reads |
| Repair cost | k reads + encode + 1 write | 1 read + 1 write |
| CPU cost | Reed-Solomon encode/decode | None |

**Tradeoff accepted:** Erasure coding as default for space efficiency.
Replication available as a per-dataset `RedundancyPolicy` option for
latency-sensitive workloads.

---

## 6. Error Handling and Recovery

### 6.1 Crash During Rebake

State before crash: some shards written, locator entry still `Ingest`.
On restart:
1. `RebakeService` queries locator table for `Ingest` extents
2. For each, performs idempotent rebake
3. Pre-written shards from prior attempt are overwritten (idempotent)
4. Locator update commits the new state atomically

### 6.2 Device Failure During Rebake

If a target device fails while writing shards:
1. Write to failed device returns error
2. Mark device health as `Failed` in `ReplicaHealth`
3. Re-run TideCRUSH placement excluding failed device
4. Retry shard write to new device
5. Continue rebake

### 6.3 Checksum Failure

If `IntegrityTrailerV2` detects corruption on read:
1. Mark affected shard as `Suspect`
2. Increment suspicion counter in `SuspicionTracker`
3. If suspicion exceeds threshold, mark as `Corrupt`
4. Trigger repair via `RepairService` (out of scope for this spec)
5. Read path falls through to parity decode

### 6.4 Budget Exhaustion Mid-Rebake

If budget is exhausted before all k+m shards are written:
1. Do NOT commit partial state
2. Do NOT update locator entry
3. Extent remains in `Ingest` lifecycle
4. Re-queued on next tick

---

## 7. Integration Points

### 7.1 Pool Import

On pool import:
1. Scan locator table for entries with `lifecycle = Ingest`
2. Populate `RebakeService` work queue
3. Resume rebake from oldest ingest extent

### 7.2 Pool Export

On pool export:
1. Signal `RebakeService` to drain
2. Complete in-flight rebake operations
3. All `Ingest` extents preserved in locator table
4. On next import, rebake resumes (Section 7.1)

### 7.3 Snapshot Interaction

Snapshots reference locator entries, not ingest locations.
When an `Ingest` extent is rebaked and trimmed:
- The snapshot still references the same `locator_id`
- The locator entry now points to base shards
- The snapshot benefits from improved redundancy
- No special handling required

### 7.4 Dataset Destroy

When a dataset is destroyed:
1. `RebakeService` removes all entries for that dataset from its queue
2. In-flight rebake operations are cancelled
3. Partially written shards are cleaned up via `SegmentCleanerService`

### 7.5 SegmentCleanerService

After rebake transitions an extent to `BaseComplete`:
1. `SegmentCleanerService` detects that ingest fragment is no longer
   the authoritative copy (locator flag `BASE_COMPLETE` is set)
2. Verifies k healthy shards exist
3. Marks ingest segment as reclaimable
4. Cleans and returns space to pool allocator

---

## 8. Performance Model

### 8.1 Rebake Throughput

```
rebake_rate (bytes/sec) = min(
    budget_bytes_per_second,
    ingest_read_bw / (1 + m/k),     # read original + write k+m
    network_bw / (k + m),            # shard distribution
    cpu_encode_bw                      # Reed-Solomon limit
)
```

Typical: 64 KiB shards, k=6, m=2 → 8 shards written per extent.
For a 1 GiB extent: 16,384 shards. With 1 GB/s disk, rebake at
~125 MB/s (1 GB/s / 8x write amp). A 1 TiB ingest queue takes
~2.3 hours to clear.

### 8.2 Durability Window

```
max_ingest_window (seconds) = ingest_queue_bytes / rebake_rate
```

With a 256 GiB ingest queue and 125 MB/s rebake rate: ~35 minutes.
The durability ladder ensures this window is monitored and emergency
rebake is triggered if the queue grows (due to device failures).

### 8.3 Memory Budget

```
peak_rebake_memory = max_concurrent_ops * extent_max_size * (1 + m/k)
```

With 4 concurrent ops, 16 MiB max extent, k=6, m=2: ~85 MiB.
Controlled via `RebakeBudget.max_concurrent_ops`.

---

## 9. Configuration

### 9.1 Dataset-Level

```
# Default: EC 6+2, 64 KiB shards, durability ladder enabled
tidefs.dataset.<name>.redundancy_policy = erasure_coded
tidefs.dataset.<name>.ec_data_shards = 6
tidefs.dataset.<name>.ec_parity_shards = 2
tidefs.dataset.<name>.shard_size = 65536
tidefs.dataset.<name>.rebake_enabled = true

# Alternative: triple replication
tidefs.dataset.<name>.redundancy_policy = replicated
tidefs.dataset.<name>.replica_count = 3
```

### 9.2 Pool-Level

```
tidefs.pool.<name>.rebake_max_bytes_per_second = 268435456  # 256 MiB/s
tidefs.pool.<name>.rebake_max_concurrent_ops = 4
tidefs.pool.<name>.rebake_tick_interval_ms = 1000
tidefs.pool.<name>.durability_monitor_interval_s = 30
tidefs.pool.<name>.allow_write_during_loss_imminent = 0
```

---

## 10. Wire-Up Implementation Plan

Implementation deferred to wire-up issues labeled `codex:ready`.
Each phase is an independent Forgejo issue referencing this spec.

### Phase 1: Core Types
**Crates:** `tidefs-types-extent-map-core`, `tidefs-types-locator-table-core`
- `ShardGroupV1` struct and bitflags
- `ExtentLifecycleState` enum
- `ShardPlacement` struct
- `LocatorFlags` bitflags
- `DurabilityLevel` enum and `DurabilityState` struct

### Phase 2: Locator Table Extensions
**Crates:** `tidefs-locator-table`
- Extend `ExtentLocatorValueV1` with shard/replica placeholders
- `flags` field serialization
- Atomic COMMIT_GROUP-committed locator update

### Phase 3: Erasure Coding Integration
**Crates:** `tidefs-erasure-coding`, `tidefs-replication-model`
- `encode()` / `decode()` API with `ShardGroupV1`
- Multi-stripe support for large extents
- Zero-copy shard buffer management

### Phase 4: Shard Placement
**Crates:** `tidefs-erasure-coded-store`, `tidefs-placement-runtime`
- TideCRUSH integration for shard placement
- Failure domain constraint enforcement
- Device health-aware placement

### Phase 5: RebakeService
**Crates:** `tidefs-rebake` (new or extended crate)
- `BackgroundService` trait implementation
- `RebakeBudget` lifecycle
- Main loop with tick/budget management
- Idempotent rebake with atomic commit

### Phase 6: DurabilityMonitor
**Crates:** `tidefs-replica-health`, `tidefs-rebake`
- Periodic durability level computation
- Emergency rebake escalation
- Write blocking at `LossImminent`
- Alert/log emission

### Phase 7: SegmentCleanerService Integration
**Crates:** `tidefs-cleanup-job-core`
- Safety gate: trim only when `BASE_COMPLETE` and k shards readable
- Ingest fragment cleanup after rebake

### Phase 8: Pool Import/Export
**Crates:** `tidefs-pool-allocator`
- Drain rebake on export
- Rebuild queue on import

### Phase 9: Read Path Integration
**Crates:** `tidefs-vfs-engine`, active POSIX adapter runtime/daemon boundary
- Degraded mode reads with parity decode
- Health state updates on read errors
- Suspicion tracking

- Deterministic simnet: write, rebake, corrupt shards, read
- Crash-recovery: kill daemon mid-rebake, verify recovery
- Budget exhaustion: verify atomicity
- Durability ladder: simulate device failures at each level

---

## 11. Resolved Design Decisions

These are binding decisions for implementers. Do not reopen
without a new design issue.

1. **Should rebake use a dedicated I/O thread pool?**
   Rebake is I/O-heavy (reads ingest, writes k+m shards). A dedicated
   thread could reduce tail latency impact on demand I/O.
   *Decision*: start inline with small per-tick budgets; measure
   tail latency; move to dedicated thread only if demand I/O is impacted.

2. **Should partially-rebaked extents be resumable?**
   If rebake is interrupted mid-extent (budget exhaustion, daemon restart),
   partially written shards are orphaned.
   *Decision*: make rebake atomic per extent — either all k+m shards
   are written and the locator is updated, or the extent is re-queued for
   the next tick. No partial state.

3. **How to handle rebake during pool export?**
   During export, complete in-flight rebakes, then suspend the rebake queue.
   On next import, the rebake queue is reconstructed from locator entries
   with lifecycle state `Ingest`.
   *Decision*: drain in-flight rebakes before completing export;
   resume queue on import.

4. **Should the durability ladder block writes at LossImminent?**
   Blocking writes is the safest option but impacts availability.
   *Decision*: block writes at `LossImminent` to prevent silent data
   loss; operator can override via `tidefs.pool.allow_write_during_loss_imminent=1`.

5. **How does rebake interact with snapshots?**
   A snapshot pins the ingest extent's data. If the extent is rebaked after
   the snapshot is taken, the snapshot still references the original locator
   entry. After rebake, the locator entry points to base shards, and the
   snapshot benefits from the improved redundancy.
   *Decision*: snapshots reference the locator entry, not the ingest
   location directly; no special handling needed.

6. **What shard size is optimal?**
   Too small: metadata overhead dominates. Too large: repair granularity
   is coarse and read amplification for small IOs increases.
   *Decision*: default to 64 KiB shard size, configurable per dataset.
   Use `recordsize`-adaptive sharding for datasets that tune `recordsize`.

---

## 12. References

- [#1782] This sealed design specification
- [#1704] Prior sealed design specification
- [#1626] Earlier iteration
- [#1675] Refinement
- [#1593] Prior iteration
- [#1553] Design-spec refinement
- [#1286] Original design
- [#1249] Erasure coding and CRUSH-like placement — TideCRUSH, EcProfile
- [#1285] Extent maps and locator tables — `ExtentLocatorValueV1`, `LocatorId`
- [#1179] Background service framework — `BackgroundService`, `ServiceBudget`, `ValidityToken`
- [#1287] End-to-end checksum architecture — `IntegrityTrailerV2`, `SuspectLog`
- [#1288] Scrub, repair, and resilver — source selection, repair pipeline
- [#1222] Rebake architecture — rebake design principles, policy ladder
- [#1215] Space accounting — `SegmentCleanerService`, ingest trim
- `crates/tidefs-erasure-coding/src/lib.rs`
- `crates/tidefs-erasure-coded-store/src/lib.rs`
- `crates/tidefs-replication-model/src/lib.rs`
- `crates/tidefs-replication/src/lib.rs`
- `crates/tidefs-replica-health/src/lib.rs`
- `crates/tidefs-types-locator-table-core/src/lib.rs`
- `crates/tidefs-types-extent-map-core/src/lib.rs`
- `crates/tidefs-locator-table/src/lib.rs`
