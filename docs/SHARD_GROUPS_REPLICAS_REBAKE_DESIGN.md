# Shard Groups, Replicas, and Rebake Pathway Design

Maturity: **design-spec** for the distributed extent redundancy model:
`ShardGroupV1` encoding with k+m erasure shards, ingest-replica lifecycle
with durability ladder, and budgeted background rebake service converting
ingest extents into base shards.

This document closes Forgejo issue #1286.

## Incumbent Comparison Boundary

This imported design document uses ZFS and Ceph write-redundancy behavior as
historical design input. The comparison rows below are not current TideFS
durability, write-latency, write-amplification, space-efficiency, cost, or
successor claims. Any future product-facing comparison must name a #875 claim
id and carry the comparator evidence required by #928/#930.

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

The target TideFS design explores a different approach: **fast ingest writes** land on a
single device for minimal latency, then a **budgeted background rebake
service** converts them to base shards with full redundancy. The ingest
window is protected by a **durability ladder** that triggers emergency
rebake if replica counts fall below threshold.

| Concern | ZFS | Ceph | TideFS target design |
|---------|-----|------|--------|
| Write latency | Pay redundancy cost at write | Pay replication hop at write | Pay single-device latency; redundancy deferred |
| Write amplification | Always k+m writes | Always r writes | 1x at ingest; k+m at rebake |
| Ingest window risk | None (redundant immediately) | None (replicated immediately) | Protected by durability ladder + emergency rebake |
| Space efficiency | Good after write | Good after write | Excellent after rebake; ingest fragments reclaimed |

### Dependency Map

| Design | Relationship |
|--------|-------------|
| #1249 Erasure coding placement | TideCRUSH places shards; `EcProfile` selects (k,m) |
| #1285 Extent maps + locator tables | `locator_id` → `LocatorValue` → shard locations |
| #1179 Background service framework | `RebakeService` implements `BackgroundService` |
| #1287 Checksum architecture | `IntegrityTrailerV2` per-shard digests |
| #1288 Scrub/repair/resilver | Repair selects source from healthy shards |
| #1222 Rebake architecture | Rebake design principles and policy ladder |
| #1215 Space accounting | Rebake frees ingest space; updates physical counters |

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

## 3. Shard Group Model

### 3.1 ShardGroupV1 On-Media Format

```rust
/// A shard group encodes one extent as k data shards + m parity shards.
/// Total size on media: 80 + (k+m) * 48 bytes
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardGroupV1 {
    /// Unique identifier for this shard group (maps 1:1 to locator_id).
    pub group_id: [u8; 16],

    /// Erasure coding profile: (k, m).
    pub ec_k: u8,
    pub ec_m: u8,

    /// Flags: bit 0 = COMPACTED, bit 1 = BASE_COMPLETE, bits 2-7 reserved.
    pub flags: u8,

    /// Logical byte range covered by this extent.
    pub logical_offset: u64,
    pub logical_length: u64,

    /// BLAKE3-256 over the original logical byte range (pre-encoding).
    pub original_digest: [u8; 32],

    /// Per-shard metadata: physical location, shard digest, shard length.
    pub shards: Vec<ShardDescriptor>,

    /// Number of replicas of this shard group (for replicated datasets).
    /// Zero for erasure-coded datasets.
    pub replica_count: u8,

    /// Reserved for TLV extension.
    pub reserved: [u8; 9],

    /// CRC32C over all preceding fields.
    pub crc32c: u32,
}

/// Describes one shard within a shard group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardDescriptor {
    /// Index of this shard (0..k-1 = data, k..k+m-1 = parity).
    pub shard_index: u8,

    /// Device holding this shard.
    pub device_id: u32,

    /// Physical offset on the device.
    pub physical_offset: u64,

    /// Length of the shard payload in bytes.
    pub shard_length: u64,

    /// BLAKE3-256 over the shard payload.
    pub shard_digest: [u8; 32],
}
```

### 3.2 Shard Placement via TideCRUSH

Shard placement is deterministic via TideCRUSH from #1249:

```
shard_assignment(group_id, epoch, ec_profile) -> [(node_0, dev_0), ..., (node_{w-1}, dev_{w-1})]
```

where `w = k + m`. The placement function guarantees:
- No two shards of the same group on the same device
- No two shards of the same group in the same failure domain (per profile policy)
- Weight-proportional distribution across devices

### 3.3 Locator Table Integration (#1285)

The `ExtentLocatorTable` maps `locator_id` to physical device + offset:

```rust
/// Value stored in the ExtentLocatorTable for shard-group-based extents.
pub struct ExtentLocatorValueV2 {
    /// Byte range covered by this locator entry.
    pub length: u64,

    /// For shard-group extents: pointer to the ShardGroupV1 record.
    pub shard_group_ptr: Option<ObjectPointer>,

    /// For replicated extents: list of replica locations.
    pub replica_locations: Vec<ReplicaLocation>,

    /// Flags: bit 0 = REBAKE_PENDING, bit 1 = BASE_COMPLETE.
    pub flags: u8,

    /// Birth commit_group of this locator entry.
    pub birth_commit_group: u64,
}

pub struct ReplicaLocation {
    pub device_id: u32,
    pub physical_offset: u64,
    pub shard_digest: [u8; 32],
    pub suspect_count: u32,
}
```

### 3.4 Per-Dataset Shard Policy

Each dataset declares its redundancy policy:

```rust
pub enum RedundancyPolicy {
    /// No redundancy: single copy, ingest-only. Suitable for tmpfs-like datasets.
    None,

    /// Replication: r copies on distinct devices (r >= 2).
    Replicated { replica_count: u8 },

    /// Erasure coding: k data + m parity shards.
    ErasureCoded { ec_k: u8, ec_m: u8 },
}
```

The policy is immutable per dataset (set at creation), enforced by dataset
feature flags (#1223). Changing policy requires dataset migration (#1275).

## 4. Ingest Replica Lifecycle

### 4.1 Lifecycle States

```
 ┌─────────┐     ┌──────────┐     ┌────────────┐     ┌──────────┐
 │ INGEST  │────▶│REBAKE_   │────▶│BASE_       │────▶│TRIMMED   │
 │         │     │SCHEDULED │     │COMPLETE    │     │          │
 └─────────┘     └──────────┘     └────────────┘     └──────────┘
       │               │                                  ▲
       │               │              ┌──────────┐        │
       └───────────────┴─────────────▶│EMERGENCY_│────────┘
                       (durability   │REBAKE    │
                        ladder       └──────────┘
                        trigger)
```

| State | Meaning |
|-------|---------|
| `INGEST` | Extent written to single device; low latency. No redundancy. |
| `REBAKE_SCHEDULED` | Rebake task queued with the `RebakeService`. |
| `BASE_COMPLETE` | Rebake finished; shard group written with full redundancy. Ingest copy still exists. |
| `TRIMMED` | Ingest copy reclaimed; only base shards remain. |
| `EMERGENCY_REBAKE` | Durability ladder triggered; rebake elevated to Critical priority. |

### 4.2 Ingest Window

The ingest window is the time between `INGEST` and `BASE_COMPLETE`. It is
bounded by three mechanisms:

1. **Time-based:** `INGEST_WINDOW_MAX_SECONDS` (default: 60s). Extents older
   than this are automatically scheduled for rebake.
2. **Count-based:** `INGEST_WINDOW_MAX_EXTENTS` (default: 10,000). When the
   ingest extent count exceeds this, rebake is triggered.
3. **Capacity-based:** `INGEST_WINDOW_MAX_BYTES` (default: 1 GiB). When
   ingest bytes exceed this, rebake is triggered.

### 4.3 Durability Ladder

The durability ladder defines minimum acceptable redundancy at each stage:

| Stage | Min replicas / Min (k,m_effective) | Trigger |
|-------|-------------------------------------|---------|
| Normal | Per-dataset policy (e.g., EC-4+2) | Background rebake |
| Warning | 1 replica below target | Rebake elevated to Throughput |
| Critical | 2 replicas below target or m_effective = 0 | Emergency rebake at Critical priority |
| LossImminent | Only 1 replica remaining | All writes to dataset blocked until rebake completes |

The ladder is enforced by the `DurabilityMonitor`, which tracks replica
counts per extent and signals the `RebakeService` when thresholds are crossed.

## 5. Rebake Service

### 5.1 Service as BackgroundService

```rust
impl BackgroundService for RebakeService {
    fn name(&self) -> &'static str { "rebake" }
    fn priority(&self) -> ServicePriority {
        match self.durability_monitor.current_level() {
            DurabilityLevel::Normal => ServicePriority::Throughput,
            DurabilityLevel::Warning => ServicePriority::Throughput,
            DurabilityLevel::Critical => ServicePriority::Critical,
            DurabilityLevel::LossImminent => ServicePriority::Critical,
        }
    }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        let mut report = TickReport::new();

        while let Some(task) = self.rebake_queue.pop() {
            if !task.validity_token.is_valid(&self.current_token_for(task.extent_id)) {
                report.items_skipped += 1;
                continue;
            }

            let outcome = self.rebake_one(task, budget)?;
            report.record_outcome(outcome);

            if budget.is_exhausted() {
                break;
            }
        }

        report.has_more = !self.rebake_queue.is_empty();
        Ok(report)
    }

    fn has_pending_work(&self) -> bool {
        !self.rebake_queue.is_empty()
    }
}
```

### 5.2 Rebake Algorithm

```
rebake_one(task, budget):
    1. Read ingest extent from source device
    2. Verify ingest checksum (BLAKE3-256)
    3. Select redundancy strategy:
       - For Replicated: pick r target devices via TideCRUSH
       - For ErasureCoded: compute k+m shards via RS encode
    4. Compute per-shard BLAKE3-256 digests
    5. Write shards to target devices
    6. Write IntegrityTrailerV2 per shard (CRC32C + BLAKE3-256)
    7. Update ExtentLocatorTable:
       - Set shard_group_ptr to new ShardGroupV1
       - Set replica_locations for replicated extents
       - Set BASE_COMPLETE flag
    8. Emit RebakeReceipt for observability
    9. Schedule ingest trim (via SegmentCleanerService)
```

### 5.3 Encoder Selection

The rebake service selects the appropriate encoder based on redundancy policy:

```rust
pub enum RebakeEncoder {
    /// Copy ingest extent verbatim to r target devices.
    Replicate { replica_count: u8 },

    /// RS encode: split ingest extent into k data shards, compute m parity.
    ErasureCode { ec_k: u8, ec_m: u8 },
}

impl RebakeEncoder {
    pub fn for_policy(policy: &RedundancyPolicy) -> Self {
        match policy {
            RedundancyPolicy::None => {
                // No encoder; extent remains ingest-only
                RebakeEncoder::Replicate { replica_count: 1 }
            }
            RedundancyPolicy::Replicated { replica_count } => {
                RebakeEncoder::Replicate { replica_count }
            }
            RedundancyPolicy::ErasureCoded { ec_k, ec_m } => {
                RebakeEncoder::ErasureCode { ec_k, ec_m }
            }
        }
    }

    pub fn output_shard_count(&self) -> u8 {
        match self {
            RebakeEncoder::Replicate { replica_count } => *replica_count,
            RebakeEncoder::ErasureCode { ec_k, ec_m } => ec_k + ec_m,
        }
    }
}
```

### 5.4 Budget Model

```rust
pub struct RebakeBudget {
    /// Max extents to rebake per tick.
    pub max_extents_per_tick: u32,

    /// Max bytes to read (ingest) per tick.
    pub max_read_bytes_per_tick: u64,

    /// Max bytes to write (shards × devices) per tick.
    pub max_write_bytes_per_tick: u64,

    /// Max I/O operations per tick.
    pub max_io_ops_per_tick: u64,
}

impl Default for RebakeBudget {
    fn default() -> Self {
        Self {
            max_extents_per_tick: 50,
            max_read_bytes_per_tick: 256 * 1024 * 1024,   // 256 MiB
            max_write_bytes_per_tick: 512 * 1024 * 1024,  // 512 MiB (accounts for k+m amplification)
            max_io_ops_per_tick: 2000,
        }
    }
}
```

## 6. Ingest Trimming

After rebake completes (`BASE_COMPLETE` flag set in the locator), the
ingest copy is eligible for trimming. The `SegmentCleanerService` (#1215)
reclaims ingest segments once all their extents have BASE_COMPLETE.

```
Trim eligibility:
  segment is eligible for reclaim when:
    for every extent in segment:
      extent.locator.BASE_COMPLETE == true
      OR extent has been overwritten (newer version exists)
```

The trim is safe because:
- The `ExtentLocatorTable` now points to `ShardGroupV1` (or `replica_locations`),
  not the ingest copy.
- The `SegmentIntegrityFooter` (#1287) ensures the ingest segment hasn't been
  tampered with before reclaim.

## 7. Replica Model Details

### 7.1 Replica Placement

For replicated datasets, the `ShardGroupV1` concept is simplified: instead
of k+m shards, the extent is copied verbatim to `r` devices.

```
ReplicatedShardGroupV1 {
    group_id: [u8; 16],
    replica_count: u8,           // r >= 2
    logical_offset: u64,
    logical_length: u64,
    original_digest: [u8; 32],
    replicas: [ReplicaDescriptor; r],
    // No ec_k/ec_m, no shard encoding
}

ReplicaDescriptor {
    replica_index: u8,           // 0..r-1
    device_id: u32,
    physical_offset: u64,
    payload_length: u64,
    payload_digest: [u8; 32],
}
```

### 7.2 Replica Health Tracking

Each replica location carries a `suspect_count` in the locator table.
The `ReplicaHealthTracker` (from rebuild planner) increments suspect
counts on checksum mismatch and decrements them on successful repair.

```rust
pub struct ReplicaHealth {
    pub device_id: u32,
    pub suspect_count: u32,
    pub last_verified_commit_group: u64,
    pub state: ReplicaState,
}

pub enum ReplicaState {
    Healthy,
    Suspect { since_commit_group: u64 },
    Degraded { missing_since_commit_group: u64 },
    Rebuilding { target_device: u32, started_commit_group: u64 },
}
```

### 7.3 Replica vs Erasure Coding Tradeoff

| Dimension | Replicated (r=3) | ErasureCoded (EC-4+2) |
|-----------|-----------------|----------------------|
| Space overhead | 200% (3x data) | 50% (1.5x data) |
| Read latency (degraded) | Read from any healthy replica | Reconstruct from k shards |
| Write amplification (rebake) | r writes | (k+m) writes |
| Resilience | Tolerates r-1 failures (2) | Tolerates m failures (2) |
| Rebuild cost | Copy 1 full extent | Read k shards, compute parity |
| Best for | Small files, metadata, hot data | Large files, cold data, capacity-constrained |

## 8. Integration Contracts

### 8.1 With Extent Maps (#1285)

```
ExtentMapEntryV2.locator_id → ExtentLocatorTable → ExtentLocatorValueV2
                                                      ├── shard_group_ptr → ShardGroupV1
                                                      └── replica_locations → [ReplicaLocation]
```

When a file read reaches an extent map entry:
1. Look up `locator_id` in `ExtentLocatorTable`
2. If `shard_group_ptr` is set: read ShardGroupV1, select k shards, decode
3. If `replica_locations` is set: read from healthiest replica
4. If neither is set (ingest only): read from ingest location

### 8.2 With Erasure Coding Placement (#1249)

TideCRUSH maps `(group_id, epoch, ec_profile) → [(node, device)]`.
The rebake service calls TideCRUSH to determine target devices for each shard:

```rust
let assignment = crush.assign_shards(group_id, current_epoch, &ec_profile);
for (shard_idx, (node_id, device_id)) in assignment.iter().enumerate() {
    let target = ShardTarget { node_id: *node_id, device_id: *device_id };
    write_shard(shard_idx as u8, &shard_data[shard_idx], target)?;
}
```

### 8.3 With Checksum Architecture (#1287)

Every shard and replica carries `IntegrityTrailerV2`:

```
Shard payload on disk:
  [shard_data (shard_length bytes)]
  [IntegrityTrailerV2 {
      header_crc32c: CRC32C over [payload_length, shard_index, shard_count, ec_k, ec_m, flags, reserved],
      payload_blake3: BLAKE3-256 over shard_data,
      shard_index: this shard's index,
      shard_count: k+m,
      ec_k: k,
      ec_m: m,
      flags: 0,
      reserved: [0; 36],
      trailer_crc32c: CRC32C over all preceding trailer fields,
  }]
```

This enables the scrub service (#1288) to verify each shard independently
and the repair service to identify which specific shard is corrupt.

### 8.4 With Scrub/Repair/Resilver (#1288)

- **Scrub**: walks `ShardGroupV1` entries, verifies each shard's `IntegrityTrailerV2`
- **Repair**: selects k healthiest shards (by `suspect_count`), reconstructs, writes repaired shard
- **Deep scrub**: reads all k+m shards, reconstructs, compares against each stored shard
- **Resilver**: builds priority-sorted list of `ShardGroupV1` entries with shards on degraded devices

## 9. Observability Contract

| Counter | Type | Description |
|---------|------|-------------|
| `rebake_extents_queued_total` | Counter | Extents queued for rebake |
| `rebake_extents_completed_total` | Counter | Extents successfully rebaked |
| `rebake_extents_failed_total` | Counter | Rebake failures |
| `rebake_bytes_read_total` | Counter | Ingest bytes read for rebake |
| `rebake_bytes_written_total` | Counter | Shard bytes written (includes k+m amplification) |
| `rebake_queue_depth` | Gauge | Current rebake queue depth |
| `ingest_window_extent_count` | Gauge | Extents in INGEST state |
| `ingest_window_bytes_total` | Gauge | Bytes in INGEST state |
| `durability_level` | Gauge | Current durability ladder level (0-3) |
| `replicas_degraded_total` | Gauge | Extents below target replica count |
| `locator_base_complete_ratio` | Gauge | Fraction of locator entries with BASE_COMPLETE |

## 10. ZFS and Ceph Design Lessons (Non-Claim)

### 10.1 Redundancy Models

| Dimension | ZFS | Ceph | TideFS target design |
|-----------|-----|------|--------|
| **Redundancy timing** | At write (mirror or PARITY_RAID) | At write (replication or EC pool) | Deferred: fast ingest, background rebake |
| **Write amplification** | Always k+m or r | Always r or k+m | 1x at ingest; k+m or r at rebake |
| **Ingest window risk** | None | None | Protected by durability ladder + emergency rebake |
| **Rebake/compaction** | None (writes are final) | None (writes are final) | `RebakeService` as `BackgroundService` |
| **Shard placement** | Fixed at device level | CRUSH map with rule language | TideCRUSH: deterministic, no DSL, per-stripe placement |
| **Replica policy** | Per-pool (mirror vs PARITY_RAID) | Per-pool (replicated vs EC) | Per-dataset: `RedundancyPolicy` with immutable feature flags |
| **Shard health** | Checksum → self-heal from mirror/parity | Per-PG scrub → repair | Per-shard `suspect_count` in locator; SuspectLog integration |
| **Space efficiency** | Good | Good | Excellent: ingest fragments reclaimed after rebake |

### 10.2 Target Design Differences

1. **Deferred redundancy with bounded risk window.** ZFS and Ceph pay
   redundancy overhead on every write. tidefs writes fast (single device),
   rebakes in background. The durability ladder ensures the risk window
   is bounded and monitored.
2. **Per-dataset policy.** ZFS forces pool-wide mirror vs PARITY_RAID choice.
   Ceph forces pool-wide replicated vs EC. tidefs allows each dataset to
   choose its own `RedundancyPolicy`.
3. **Budgeted background rebake.** Neither ZFS nor Ceph has a concept of
   "background work to improve redundancy." tidefs `RebakeService` runs
   under the unified background service budget, interleaved with demand I/O.
4. **Ingest reclaim.** ZFS and Ceph never reclaim "temporary fast writes"
   because all writes are final. tidefs trims ingest segments after rebake,
   recovering space from the CoW journal.
5. **TideCRUSH simplicity.** Ceph CRUSH uses a rule language DSL with
   separate CRUSH maps per pool. TideCRUSH is a single deterministic
   function with no DSL, no separate map artifacts, and no PG combinatorics.

### 10.3 Where tidefs Matches

1. **Checksum-gated redundancy.** All three systems verify data integrity
   before relying on it for reconstruction.
2. **Deterministic placement.** All three use deterministic functions
   (CRUSH, TideCRUSH) rather than random or round-robin placement.
3. **Durability guarantees.** All three provide configurable redundancy
   levels and rebuild from healthy copies on failure.

## 11. Implementation Strategy

### 11.1 Phases

| Phase | Scope | Dependencies |
|-------|-------|-------------|
| **Phase 1: Core types** | `ShardGroupV1`, `ShardDescriptor`, `ReplicaLifecycle`, `RedundancyPolicy`, `DurabilityLevel`, `RebakeBudget` | #1249 types |
| **Phase 2: TideCRUSH integration** | Wire shard placement into `ShardGroupV1` construction; `assign_shards()` call | Phase 1, #1249 |
| **Phase 3: RebakeService** | `RebakeService` as `BackgroundService`, rebake algorithm, encoder selection | Phase 1-2, #1179 |
| **Phase 4: Locator integration** | `ExtentLocatorValueV2` with `shard_group_ptr` and `replica_locations`; update on rebake | Phase 1, #1285 |
| **Phase 5: Ingest trim** | `SegmentCleanerService` integration; reclaim ingest segments after BASE_COMPLETE | Phase 3, #1215 |
| **Phase 6: Durability monitor** | `DurabilityMonitor` tracking replica counts, emergency rebake trigger | Phase 2-3 |
| **Phase 7: Replica health** | `ReplicaHealth` tracking in locator; SuspectLog integration | Phase 1-4, #1287 |
| **Phase 8: Observability** | All rebake and replica counters | Phase 3-6, #827 |
| **Phase 9: Downstream integration** | Wire shard groups into scrub/repair/resilver (#1288) source selection | Phase 1-4, #1288 |

### 11.2 Crate Boundaries

```
crates/tidefs-shard-group-types/     -- Phase 1: ShardGroupV1, ReplicaLifecycle, RedundancyPolicy
crates/tidefs-rebake-service/        -- Phase 3: RebakeService implementation
crates/tidefs-durability-monitor/    -- Phase 6: DurabilityMonitor
crates/tidefs-replica-health/        -- Phase 7: ReplicaHealth tracking (or extend existing tidefs-replica-health)
```

## 12. Deterministic Constraint Knobs

| Constant | Default | Meaning |
|----------|---------|---------|
| `INGEST_WINDOW_MAX_SECONDS` | 60 | Max seconds an extent stays in INGEST state |
| `INGEST_WINDOW_MAX_EXTENTS` | 10,000 | Max ingest extents before rebake triggers |
| `INGEST_WINDOW_MAX_BYTES` | 1 GiB | Max ingest bytes before rebake triggers |
| `REBAKE_MAX_EXTENTS_PER_TICK` | 50 | Max extents rebaked per tick |
| `REBAKE_MAX_READ_BYTES_PER_TICK` | 256 MiB | Max ingest bytes read per tick |
| `REBAKE_MAX_WRITE_BYTES_PER_TICK` | 512 MiB | Max shard bytes written per tick |
| `REPLICA_MIN_COUNT_DEFAULT` | 2 | Minimum replicas for replicated datasets |
| `DURABILITY_CRITICAL_THRESHOLD` | 2 | Replicas below target that triggers emergency rebake |
| `DURABILITY_LOSS_IMMINENT` | 1 | Only 1 replica remaining; block writes |

## 13. Error Hierarchy

```rust
pub enum ShardGroupError {
    /// TideCRUSH placement returned insufficient targets.
    InsufficientTargets { needed: u8, available: u8 },

    /// Erasure coding encode/decode failed.
    EncodeDecodeFailed { reason: String },

    /// Shard write to target device failed.
    ShardWriteFailed { shard_index: u8, device_id: u32, reason: String },

    /// Locator table update failed.
    LocatorUpdateFailed { locator_id: [u8; 16], reason: String },

    /// Integrity trailer mismatch on written shard.
    ShardIntegrityMismatch { shard_index: u8, expected: [u8; 32], actual: [u8; 32] },
}

pub enum RebakeError {
    /// Ingest extent is no longer valid (overwritten or truncated).
    ExtentStale { extent_id: u64 },

    /// Ingest extent could not be read.
    IngestReadFailed { extent_id: u64, reason: String },

    /// Rebake budget exhausted mid-extent.
    BudgetExhausted { extent_id: u64, progress: RebakeProgress },

    /// Rebake queue is backed up beyond threshold.
    QueueOverflow { depth: u64, max: u64 },
}
```

## 14. Open Questions

1. **Should rebake use a separate thread or the inline scheduler?**
   Rebake is I/O-heavy (reads ingest, writes k+m shards). A dedicated thread
   could reduce tail latency impact on demand I/O. Recommendation: start inline
   with small per-tick budgets, measure tail latency, move to dedicated thread
   only if demand I/O is impacted.

2. **Should partially-rebaked extents be resumable?**
   If rebake is interrupted mid-extent (budget exhaustion, daemon restart), the
   partially written shards are orphaned. Recommendation: make rebake atomic per
   extent — either all k+m shards are written and the locator is updated, or the
   extent is re-queued for the next tick. No partial state.

3. **How to handle rebake during pool export?**
   During export, complete in-flight rebakes, then suspend the rebake queue.
   On next import, the rebake queue is reconstructed from locator entries with
   `BASE_COMPLETE == false`. Recommendation: drain in-flight rebakes before
   completing export; resume queue on import.

4. **Should the durability ladder block writes at LossImminent?**
   Blocking writes is the safest option but impacts availability. Alternative:
   allow writes but log a critical alert. Recommendation: block writes at
   LossImminent to prevent silent data loss; operator can override via
   `tidefs.pool.allow_write_during_loss_imminent=1`.

5. **How does rebake interact with snapshots?**
   A snapshot pins the ingest extent's data. If the extent is rebaked after
   the snapshot is taken, the snapshot still references the ingest copy.
   The ingest segment cannot be trimmed until all snapshots referencing it
   are destroyed. Recommendation: snapshots reference the locator entry,
   not the ingest location directly; after rebake, the locator points to
   base shards, and snapshots also benefit from the improved redundancy.

## 15. References

- [#1286] This design spec
- [#1249] Erasure coding and CRUSH-like placement — TideCRUSH, EcProfile
- [#1285] Extent maps and locator tables — ExtentLocatorValueV2, locator_id
- [#1179] Background service framework — BackgroundService, ServiceBudget, ValidityToken
- [#1287] End-to-end checksum architecture — IntegrityTrailerV2, SuspectLog
- [#1288] Scrub, repair, and resilver — source selection, repair pipeline
- [#1222] Rebake architecture — rebake design principles, policy ladder
- [#1215] Space accounting — SegmentCleanerService, ingest trim
- [#1223] Dataset feature flags — RedundancyPolicy immutability
- [#1275] Online pool geometry conversion — RedundancyPolicy migration
- `docs/ERASURE_CODING_PLACEMENT_DESIGN.md`
- `docs/EXTENT_MAPS_LOCATOR_TABLES_DESIGN.md`
- `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md`
- `docs/CHECKSUM_ARCHITECTURE_DESIGN.md`
- `docs/SCRUB_REPAIR_RESILVER_DESIGN.md`
- `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md`
