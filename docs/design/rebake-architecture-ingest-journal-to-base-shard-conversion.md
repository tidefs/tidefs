# Rebake Architecture: Ingest Journal to Base Shard Conversion with Durability Policy Ladder

Maturity: **design-spec** for the asynchronous rebake service that converts
ingest extents into base shards under a staged durability policy ladder,
with budgeted background execution, crash-safe locator updates, and
attested ingest-segment reclamation.

This document closes Forgejo issue #1222.

## 1. Motivation

In a log-structured filesystem, writes land in an append-only ingest journal
for low latency. But ingest content needs eventual conversion to base shards
for three reasons:

1. **Space efficiency.** Raw ingest accumulates duplicate CoW fragments that
   are not deduplicated or compressed at rest. Rebake consolidates them into
   compact, erasure-coded base shards with one logical copy.
2. **Stronger redundancy.** Ingest replicas are transient and may carry lower
   replication factors than the dataset's declared durability policy. Rebake
   upgrades data from the ingest durability window into the full base-shard
   redundancy target.
3. **Read-path optimization.** Readers that hit unbaked ingest fragments pay
   the cost of scanning the append journal. Base shards are placed by
   TideCRUSH and are directly addressable, improving locality and read
   throughput.

Without a rebake architecture, the system accumulates ingest fragments that
hurt read performance, waste space, and leave data under-protected beyond the
ingest window.

### 1.1 Design Philosophy

tidefs separates the write path from the durability path:

| Concern | ZFS | Ceph | tidefs |
|---------|-----|------|--------|
| Write latency | Pay redundancy cost at write | Pay replication hop at write | Pay single-device latency; redundancy deferred |
| Write amplification | Always k+m writes | Always r writes | 1x at ingest; k+m at rebake |
| Ingest window risk | None (redundant immediately) | None (replicated immediately) | Protected by durability ladder + emergency rebake |
| Space efficiency | Good after write | Good after write | Excellent after rebake; ingest fragments reclaimed |

### 1.2 Dependency Map

| Design | Relationship |
|--------|-------------|
| #1285 Extent maps + locator tables | `ExtentLocatorValueV1` holds locator_id → physical mapping; rebake swaps it |
| #1286 Shard groups / replicas | `ShardGroupV1` is the target format; `ReplicaLifecycle` governs ingest replicas |
| #1249 Erasure coding placement | TideCRUSH places rebaked shards; `EcProfile` selects (k,m) |
| #1179 Background service framework | `RebakeService` implements `BackgroundService` with per-tick budgets |
| #1215 Space accounting | Rebake frees ingest space; updates physical counters via cleaner watermarks |
| #1288 Scrub/repair/resilver | Needs `BASE_COMPLETE` flag for healthy-shard source selection |
| #1267 COMMIT_GROUP state machine | Rebake commits locator updates atomically within a commit_group |

## 2. Design Overview

Rebake is a **five-stage pipeline** executed by a budgeted background service:

```
┌────────────────────────────────────────────────────────────────────┐
│                        REBAKE PIPELINE                             │
│                                                                    │
│  ┌──────────┐    ┌───────────┐    ┌──────────┐    ┌──────────┐   │
│  │ SELECT   │───▶│ RE-ENCODE │───▶│  UPDATE   │───▶│  COMMIT  │   │
│  │ extents  │    │ to shards │    │ locator   │    │ commit_group      │   │
│  └──────────┘    └───────────┘    └──────────┘    └──────────┘   │
│       │                                              │           │
│       └──────────────────────────────────────────────┘           │
│                          ▼                                       │
│                    ┌──────────┐                                   │
│                    │ RECLAIM  │                                   │
│                    │ ingest   │                                   │
│                    └──────────┘                                   │
└────────────────────────────────────────────────────────────────────┘
```

| Stage | Input | Output | Crash-safe? |
|-------|-------|--------|-------------|
| **SELECT** | Locator table entries with `BASE_COMPLETE=false` | Candidate extent list, sorted by coldness | Idempotent (re-derivable) |
| **RE-ENCODE** | Ingest extent payload bytes | `ShardGroupV1` records written to physical devices | Idempotent (overwrites produce same shards for same extent) |
| **UPDATE** | `ExtentLocatorValueV1` entries | Updated locator with `BASE_COMPLETE` flag + shard locations | Ordered after RE-ENCODE commits |
| **COMMIT** | Locator table B-tree state | Durable locator root in next commit_group | Atomic via commit_group |
| **RECLAIM** | Ingest segments no longer referenced | Freed physical segments | Only after COMMIT is durable |

## 3. Selection Algorithm

### 3.1 Candidate Pool

The selection stage scans the locator table for entries where:

1. `ExtentLocatorValueV1.flags & BASE_COMPLETE == 0` — the extent has not been rebaked.
2. `ExtentLocatorValueV1.refcount > 0` — at least one live reference exists.
3. `ExtentLocatorValueV1.birth_commit_group + INGEST_WINDOW_MIN_COMMIT_GROUPS < current_commit_group` — the extent is
   sufficiently cold.

The pool is sorted by `birth_commit_group` ascending: oldest extents are rebaked first.

### 3.2 Coldness Heuristic

An extent is "cold enough" when it has survived at least `INGEST_WINDOW_MIN_COMMIT_GROUPS`
transaction groups without being overwritten. This ensures:

- The extent is not part of an active write burst.
- Its refcount is stable (no racing unlink/truncate).
- The data is likely to benefit from durability upgrade.

The coldness threshold is configurable via the dataset property:

```rust
pub struct RebakePolicy {
    /// Minimum commit_group age before an ingest extent is eligible for rebake.
    pub ingest_window_min_commit_groups: u64,

    /// Maximum ingest extents before emergency rebake triggers (0 = no limit).
    pub ingest_window_max_extents: u64,

    /// Maximum ingest bytes before emergency rebake triggers (0 = no limit).
    pub ingest_window_max_bytes: u64,
}
```

### 3.3 Emergency Rebake Trigger

Under normal operation, Selection runs on a background tick. But if ingest
extent or byte counts exceed their maximums, an **emergency rebake** is
triggered that promotes the RebakeService priority from `Throughput` to
`Critical` until counts fall below threshold.

### 3.4 Selection Batch

Each tick, the selector produces a batch bounded by:

```rust
pub struct SelectionBatch {
    pub extent_locators: Vec<ExtentLocatorValueV1>,
    pub total_ingest_bytes: u64,
    pub estimated_shard_bytes: u64,  // after erasure coding expansion
}
```

Batch limits enforce the per-tick resource budget.

## 4. Re-Encode Pipeline

### 4.1 From Ingest Bytes to Base Shards

For each extent in the selection batch:

1. **Read ingest payload** from the ingest segment at
   `ExtentLocatorValueV1.physical_offset` on
   `ExtentLocatorValueV1.device_id`.

2. **Verify integrity** of the ingest bytes against the stored BLAKE3-256
   digest. Mismatch → log a `SuspectLog` entry, skip the extent, and signal
   the repair subsystem.

3. **Look up durability policy** for the extent's dataset:

   ```rust
   pub enum DurabilityPolicy {
       /// No redundancy — single copy only.
       None,
       /// Replicated across r devices (r >= 2).
       Replicated { replica_count: u8 },
       /// Erasure-coded with (k, m) profile.
       ErasureCoded { ec_profile: EcProfile },
   }
   ```

4. **Apply placement** via TideCRUSH:
   - For `Replicated`: select `replica_count` distinct devices across
     failure domains.
   - For `ErasureCoded`: select `k + m` distinct devices for the shard
     stripe.

5. **Encode data**:
   - For `Replicated`: write the full payload to each replica device.
   - For `ErasureCoded`: split payload into `k` data shards, compute `m`
     parity shards via the GF(2^8) Reed-Solomon engine in
     `tidefs-erasure-coding`.

6. **Write shards** to the assigned physical locations. Each shard is
   written with a BLAKE3-256 integrity trailer (per #1287).

7. **Build `ShardGroupV1`** record containing per-shard descriptors and
   the original digest.

### 4.2 Atomic Per-Extent Rebake

Rebake is atomic per extent: either all `k + m` shards (or all `r` replicas)
are written and verified, or the extent is left in `PENDING_REBAKE` state
for retry. No partial shard group is ever committed.

If budget is exhausted mid-extent, the current extent's partial writes are
left as orphaned on-disk bytes (eventually reclaimed by segment cleaning),
and the extent is re-queued for the next tick.

### 4.3 Re-Encode Budget

```rust
pub struct ReencodeBudget {
    /// Maximum ingest bytes to read this tick.
    pub max_read_bytes: u64,
    /// Maximum shard bytes to write this tick (after encoding).
    pub max_write_bytes: u64,
    /// Maximum extents to process this tick.
    pub max_extents: u64,
}
```

The budget is consumed incrementally. After each extent is processed
(or skipped due to integrity failure), the remaining budget is checked.
When any dimension reaches zero, the tick ends.

## 5. Locator Update

### 5.1 Pointer Swap

After successful re-encoding, the locator entry for the extent is updated:

```
Old ExtentLocatorValueV1:
  locator_id:           <unchanged>
  device_id:            <ingest device>
  physical_offset:      <ingest segment offset>
  physical_length:      <ingest payload length>
  flags:                0 (BASE_COMPLETE = 0)
  locator_kind:         INGEST_EXTENT

New ExtentLocatorValueV1:
  locator_id:           <unchanged>
  device_id:            0 (shard group spans multiple devices)
  physical_offset:      <shard group record offset>
  physical_length:      <ShardGroupV1 size>
  flags:                BASE_COMPLETE = 1, SHARDED = 1
  locator_kind:         BASE_SHARD
  shard_group_id:       <ShardGroupV1.group_id>
```

The `locator_id` remains constant. This is the key invariant: readers that
hold a `locator_id` do not need to know whether the data lives in ingest or
in base shards. The locator table resolves it transparently.

### 5.2 Crash-Safe Update Ordering

The update follows a strict five-step ordering enforced by the commit_group state
machine:

```
1. Read ingest bytes  --- already done (RE-ENCODE stage)
         |
2. Append ShardGroupV1 records to physical media
         |
3. Update ExtentLocatorValueV1 in the locator B-tree
   (set BASE_COMPLETE, SHARDED, shard_group_id)
         |
4. Commit the updated locator root via commit_group
   (steps 3-7 of canonical commit ordering)
         |
5. Mark ingest segments safe to reclaim
   (only after checkpoint pointer is updated)
```

**Why this ordering?** Per #1267, the commit_group commit ordering guarantees that
a pointer is never persisted before what it points to. Step 2 ensures shard
payloads are on durable media before step 4 makes the locator root durable.
The checkpoint pointer in step 4 is only updated after the commit record
is flushed, so a crash at any point leaves either:

- **Crash before step 4 completes:** The old locator still points to ingest.
  On recovery, the extent appears as `BASE_COMPLETE=false`. The orphaned
  shard group writes are harmless -- they'll be cleaned up as unreferenced.
- **Crash after step 4 completes:** The new locator points to base shards.
  On recovery, the extent is `BASE_COMPLETE=true`. The old ingest segment
  is safe to reclaim in step 5.

### 5.3 BASE_COMPLETE Flag Semantics

The `BASE_COMPLETE` flag in `ExtentLocatorValueV1.flags` is a
**one-way transition**: `0 → 1`. Once set, it is never cleared. This flag
is the authoritative gate for:

- **Rebake eligibility:** Only `BASE_COMPLETE == 0` extents are candidates.
- **Scrub source selection (#1288):** Healthy base shards are preferred over
  ingest replicas for reconstruction.
- **Ingest trimming:** Ingest segments referenced only by `BASE_COMPLETE == 1`
  entries are eligible for reclamation.

## 6. Durability Policy Ladder

### 6.1 Ladder Definition

The durability ladder is a per-dataset staged progression from write-time
minimal protection to fully redundant base shards:

```
Level 1: NONE
  -- Single copy on ingest device
  -- ack_level = 1..3 (write acknowledged after local ingest journal flush)

Level 2: INGEST_REPLICATED
  -- r copies on distinct devices (r >= 2)
  -- ack_level = 4 (write acknowledged after all ingest replicas flushed)
  -- Rebake to base shards is deferred

Level 3: BASE_COMPLETE
  -- Erasure-coded or replicated base shards
  -- ack_level = 5 (write acknowledged after base shards durable)
  -- Ingest replicas eligible for trim (DROP_INGEST_AFTER_REBAKE flag)
```

### 6.2 ack_level Semantics

The `ack_level` controls when a write is acknowledged to the caller and
what durability guarantees that acknowledgment carries:

| ack_level | Write completes when... | Data at risk | Use case |
|-----------|------------------------|-------------|----------|
| 1 | Ingest write queued to device | Crash before journal flush | Non-critical temp data |
| 2 | Ingest write in device cache | Device power loss | Best-effort logs |
| 3 | Ingest write FUA'd to media | Single device failure | Default dataset writes |
| 4 | All ingest replicas FUA'd | Multi-device simultaneous failure | Production datasets |
| 5 | Base shards written and BASE_COMPLETE set | Requires catastrophic failure-domain loss | Critical metadata |

Per the issue's design book references (ss29-31), datasets progress through
the ladder as data ages past the ingest window:

- New writes enter at the dataset's configured `write_ack_level` (typically 3 or 4).
- After `INGEST_WINDOW_MIN_COMMIT_GROUPS` commit_groups, eligible extents are rebaked to
  `ack_level=5` (BASE_COMPLETE).
- Emergency rebake can accelerate this transition when durability monitors
  detect degraded replicas.

### 6.3 DROP_INGEST_AFTER_REBAKE Flag

When set on a dataset:

```rust
pub struct DatasetFeatureFlags {
    /// Automatically trim ingest replicas after rebake completes.
    pub drop_ingest_after_rebake: bool,
}
```

This flag controls whether the reclaim stage (stage 5) is triggered
`BASE_COMPLETE` is set, providing extra copies at the cost of space.
Operators may set this `false` during migration or when running with reduced
shard counts, then flip it to `true` once confidence in the base shards
is established.

### 6.4 Dataset Property Binding

The `DurabilityPolicy` and `RebakePolicy` are per-dataset properties set at
creation time via the unified property framework (#1242). They are immutable
after creation except via explicit `tidefsctl dataset set` with operator
confirmation.

```rust
/// Durable configuration for rebake behavior.
pub struct RebakeConfig {
    /// The durability target for base shards.
    pub durability_policy: DurabilityPolicy,

    /// Coldness threshold and emergency triggers.
    pub rebake_policy: RebakePolicy,

    /// Whether to auto-trim ingest after rebake.
    pub drop_ingest_after_rebake: bool,
}
```

## 7. Reclaim

### 7.1 Ingest Segment Retirement

After the commit_group commit makes the locator update durable (step 4 of crash-safe
ordering), the old ingest segments are candidates for reclamation.

The reclaim stage:

1. **Identifies segments** whose every live extent has `BASE_COMPLETE == 1`.
2. **Confirms no snapshots** reference the ingest locations (snapshots
   reference locator IDs, not physical locations -- per #1286 S14.5).
3. **Adds segments to the deadlist** via `SpaceDelta` with
   `pinned_snapshot_delta`. The segment cleaner (#1215) will physically
   reclaim them in a subsequent background tick.
4. **Updates physical counters** to reflect freed space.

### 7.2 Refcount-Based Safety

Reclaim uses the locator table's refcount mechanism:

- Each `locator_id` has a `refcount` tracking how many extent maps point to it.
- After rebake, the old ingest locator entry is no longer referenced by any
  extent map (all maps now point to the `BASE_COMPLETE` locator entry).
- When `refcount == 0` and `BASE_COMPLETE == 1` (meaning the data lives in
  shards), the ingest segment bytes can be freed.

The reclaim stage does not directly free ingest bytes. It transitions refcount-0
entries to the deadlist, and the `SegmentCleanerService` (#1215) performs
the actual physical reclamation.

### 7.3 Interaction with Snapshots

Snapshots pin data at the locator level, not the physical level. When a
snapshot holds a reference to an extent that is later rebaked:

1. The snapshot's extent map references the `locator_id`.
2. After rebake, the `locator_id` resolves to base shards with
   `BASE_COMPLETE == 1`.
3. The snapshot benefits from the improved redundancy of base shards
   without any migration.
4. The ingest segment cannot be trimmed until all snapshots referencing
   the old locator entry are destroyed (tracked via deadlist).

## 8. Budget Model

### 8.1 Background Service Integration

`RebakeService` implements the `BackgroundService` trait (#1179) with
scheduling class `Throughput` (priority 2):

```rust
impl BackgroundService for RebakeService {
    fn name(&self) -> &'static str { "rebake" }

    fn priority(&self) -> ServicePriority {
        if self.emergency_mode {
            ServicePriority::Critical  // Emergency rebake
        } else {
            ServicePriority::Throughput  // Normal background rebake
        }
    }

    fn has_work(&self) -> bool {
        self.pending_extent_count > 0 || self.emergency_mode
    }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        // 1. SELECT -> 2. RE-ENCODE -> 3. UPDATE -> 4. COMMIT -> 5. RECLAIM
        // ...
    }
}
```

### 8.2 Priority Escalation

Under normal conditions, rebake runs at `Throughput` priority. It escalates
to `Critical` when:

1. Ingest extent count exceeds `ingest_window_max_extents`.
2. Ingest byte count exceeds `ingest_window_max_bytes`.
3. Durability monitor reports replicas below `DURABILITY_CRITICAL_THRESHOLD`.

Escalation is automatic and reverts when the condition clears.

### 8.3 Per-Tick Budget

The rebake tick consumes from the `ServiceBudget`:

| Budget field | Maps to | Constraining dimension |
|-------------|---------|----------------------|
| `max_authoritative_reads` | Ingest extent reads | `REBAKE_MAX_READ_BYTES_PER_TICK` |
| `max_derived_writes` | Shard writes (k+m or r) | `REBAKE_MAX_WRITE_BYTES_PER_TICK` |
| `max_bookkeeping_ops` | Locator B-tree updates | `REBAKE_MAX_EXTENTS_PER_TICK` |

The tick returns a `TickReport` with:
- `extents_rebaked`: count successfully converted.
- `extents_skipped`: count skipped (integrity failure, budget exhaustion).
- `ingest_bytes_read`: total ingest bytes consumed.
- `shard_bytes_written`: total shard bytes produced.
- `has_more`: true if work remains for the next tick.

### 8.4 Starvation and Resumability

Rebake is **starvable**: if higher-priority services (Critical, LatencySensitive)
consume all budget, rebake may receive zero ticks. This is acceptable because
ingest extents are durable -- they just haven't been upgraded to base shards yet.

Rebake is **resumable**: when budget becomes available again, it picks up
where it left off. The selection algorithm is deterministic given the same
locator table state, so restart produces the same candidate ordering.

## 9. Data Structures

### 9.1 RebakeQueueEntry

```rust
/// A single entry in the rebake work queue, tracking progress through the pipeline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebakeQueueEntry {
    /// The locator entry to rebake.
    pub locator_id: LocatorId,

    /// Logical byte range of this extent.
    pub logical_offset: u64,
    pub logical_length: u64,

    /// CommitGroup when the extent was created (for coldness ordering).
    pub birth_commit_group: u64,

    /// Current stage in the rebake pipeline.
    pub stage: RebakeStage,

    /// Number of retry attempts (integrity failures, budget exhaustion).
    pub retry_count: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RebakeStage {
    /// Selected, awaiting re-encode.
    Pending,
    /// Shards written, awaiting locator update.
    ShardsWritten,
    /// Locator updated, awaiting commit_group commit.
    LocatorUpdated,
    /// CommitGroup committed, awaiting reclaim.
    Committed,
    /// Reclaim complete; entry can be removed.
    Done,
}
```

### 9.2 RebakeProgress

```rust
/// Progress tracking for an in-flight extent rebake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RebakeProgress {
    /// Bytes of ingest read so far.
    pub bytes_read: u64,
    /// Shards written so far (out of k+m or r).
    pub shards_written: u8,
    /// Total shards to write.
    pub shards_total: u8,
}
```

### 9.3 RebakeSnapshot (pool-level)

```rust
/// Pool-level rebake state persisted across daemon restarts.
#[derive(Clone, Debug)]
pub struct RebakeSnapshot {
    /// Number of extents awaiting rebake.
    pub pending_extents: u64,

    /// Total ingest bytes awaiting rebake.
    pub pending_ingest_bytes: u64,

    /// Whether emergency mode is active.
    pub emergency_mode: bool,

    /// Last completed tick's report (for observability).
    pub last_tick_report: Option<TickReport>,

    /// Monotonically increasing rebake generation.
    pub generation: u64,
}
```

This snapshot is reconstructed on pool import by scanning the locator table
for entries with `BASE_COMPLETE == 0`. No separate persistent queue is needed.

## 10. Crash Safety Analysis

### 10.1 Crash at Each Pipeline Stage

| Crash after | State on recovery | Action |
|------------|-------------------|--------|
| SELECT | RebakeQueueEntry in Pending | Re-derive from locator table scan; deterministic ordering ensures same batch |
| RE-ENCODE (partial) | Orphaned shard writes on disk | Extent re-queued; orphaned bytes cleaned by segment cleaner |
| RE-ENCODE (complete) | Shards durable, locator not updated | Extent re-queued; shard writes are idempotent (same bytes, same placement) |
| UPDATE (pre-commit) | Locator B-tree dirty, not committed | Rolled back by commit_group; extent appears as BASE_COMPLETE=false |
| COMMIT (post-flush) | Locator durable, checkpoint stale | Next commit_group or journal scan picks up the durable locator |
| RECLAIM (partial) | Some ingest segments freed | Retry reclaim; deadlist is idempotent |

### 10.2 Power-Fail During Shard Write

If power fails while writing shards for an extent:

1. Some shard devices may have partial writes.
3. On recovery, the extent has `BASE_COMPLETE == 0` -> remains in ingest.
4. The partial shard writes occupy space but are not referenced by any
   locator. The segment cleaner reclaims them.

No data loss. The ingest copy remains intact.

### 10.3 Torn Locator Update

The locator B-tree update happens inside a commit_group. Per #1267, the commit
ordering ensures:

1. Shard writes (data) are flushed before the commit record (metadata).
2. The commit record is flushed before the checkpoint pointer is updated.
3. The checkpoint pointer update is atomic (a small system-area write).

If the locator B-tree page writes are only partially flushed before crash,
the checkpoint pointer still references the old locator root. On recovery,
the system finds either:

- Valid old checkpoint -> ingest locations still used. No data loss.
- Torn checkpoint -> falls back to journal scan (#1224). The most recent
  durable commit wins. If that commit includes the locator update, the
  shards are live. If not, the ingest is live. Either way, data is safe.

## 11. Integration Points

### 11.1 With Locator Table (#1285)

- `ExtentLocatorValueV1.flags & BASE_COMPLETE` gates rebake eligibility.
- `ExtentLocatorValueV1.locator_kind` distinguishes `INGEST_EXTENT` from
  `BASE_SHARD`.
- The locator's `refcount` field gates reclaim safety.

### 11.2 With Shard Groups (#1286)

- `ShardGroupV1` is the target format for rebaked data.
- `ReplicaLifecycle` governs ingest replicas from write through rebake to trim.
- The rebake produces a `ShardGroupV1` record and stores its `group_id` in
  the locator entry.

### 11.3 With Erasure Coding (#1249)

- TideCRUSH provides deterministic device placement for shards.
- `EcProfile` selects (k,m) parameters for the encoding.
- The GF(2^8) Reed-Solomon engine in `tidefs-erasure-coding` performs
  encode/decode.

### 11.4 With Space Accounting (#1215)

- Rebake frees ingest space: `SpaceDelta` reflects freed segments.
- The segment cleaner (#1215) performs the actual physical reclamation.
- Watermarks trigger cleaner scheduling when free space runs low.

### 11.5 With COMMIT_GROUP State Machine (#1267)

- Locator updates are committed atomically within a commit_group.
- The canonical 7-step commit ordering ensures pointers are never persisted
  before the data they reference.
- Rebake progress is not committed until the commit_group sync completes.

### 11.6 With Scrub/Repair/Resilver (#1288)

- `BASE_COMPLETE` gate: scrub only repairs from healthy base shards.
- Ingest-only extents (pre-rebake) are repaired from ingest replicas.
- Post-rebake extents are reconstructed from surviving base shards.

## 12. Deterministic Constraint Knobs

| Constant | Default | Meaning |
|----------|---------|---------|
| `INGEST_WINDOW_MIN_COMMIT_GROUPS` | 5 | Minimum commit_group age before rebake eligibility |
| `INGEST_WINDOW_MAX_EXTENTS` | 10,000 | Max ingest extents before emergency rebake |
| `INGEST_WINDOW_MAX_BYTES` | 1 GiB | Max ingest bytes before emergency rebake |
| `REBAKE_MAX_EXTENTS_PER_TICK` | 50 | Max extents processed per tick |
| `REBAKE_MAX_READ_BYTES_PER_TICK` | 256 MiB | Max ingest bytes read per tick |
| `REBAKE_MAX_WRITE_BYTES_PER_TICK` | 512 MiB | Max shard bytes written per tick |
| `REBAKE_MAX_RETRIES` | 3 | Max retry attempts per extent before skip and log |
| `REBAKE_QUEUE_DEPTH_WARN` | 50,000 | Pending extent count triggering operator warning |

## 13. Error Hierarchy

```rust
pub enum RebakeError {
    /// Ingest extent is no longer valid (overwritten or truncated).
    ExtentStale { extent_id: u64 },

    /// Ingest extent could not be read from media.
    IngestReadFailed { extent_id: u64, device_id: u32, reason: String },

    /// Ingest data failed integrity verification.
    IngestIntegrityMismatch {
        extent_id: u64,
        expected_digest: [u8; 32],
        actual_digest: [u8; 32],
    },

    /// TideCRUSH placement returned insufficient targets.
    InsufficientPlacementTargets { needed: u8, available: u8 },

    /// Erasure coding encode failed.
    EncodeFailed { locator_id: LocatorId, reason: String },

    /// Shard write to target device failed.
    ShardWriteFailed { shard_index: u8, device_id: u32, reason: String },

    /// Written shard failed integrity verification.
    ShardIntegrityMismatch {
        shard_index: u8,
        expected_digest: [u8; 32],
        actual_digest: [u8; 32],
    },

    /// Locator table update failed.
    LocatorUpdateFailed { locator_id: LocatorId, reason: String },

    /// Budget exhausted mid-extent; extent will be retried.
    BudgetExhausted {
        locator_id: LocatorId,
        progress: RebakeProgress,
    },

    /// Rebake queue depth exceeds warning threshold.
    QueueDepthWarning { depth: u64, warn_threshold: u64 },

    /// Maximum retries exceeded for this extent.
    MaxRetriesExceeded { locator_id: LocatorId, retries: u8 },
}
```

## 14. Observability

### 14.1 Per-Tick Metrics

- `rebake.extents_processed`: counter, total extents rebaked.
- `rebake.ingest_bytes_read`: counter, total bytes consumed from ingest.
- `rebake.shard_bytes_written`: counter, total bytes produced as shards.
- `rebake.space_reclaimed_bytes`: counter, total ingest bytes freed.
- `rebake.ticks_completed`: counter.
- `rebake.ticks_idle`: counter (no work available).
- `rebake.ticks_skipped`: counter (budget starvation).
- `rebake.extents_skipped_integrity`: counter.
- `rebake.extents_skipped_retries_exceeded`: counter.
- `rebake.pending_extents`: gauge, current queue depth.
- `rebake.pending_ingest_bytes`: gauge, current pending bytes.
- `rebake.emergency_mode`: gauge, 0 or 1.

### 14.2 Operator Commands

```
tidefsctl rebake status           # Show pending extents, bytes, last tick stats
tidefsctl rebake trigger          # Trigger immediate rebake tick (forces Throughput->Critical)
tidefsctl rebake pause            # Pause rebake (sets emergency_mode=false, prevents ticks)
tidefsctl rebake resume           # Resume normal rebake scheduling
tidefsctl rebake throttle <N>     # Set max_extents_per_tick override
```

## 15. Implementation Plan

| Phase | Scope | Crate |
|-------|-------|-------|
| **Phase 1: Rebake types** | `RebakeQueueEntry`, `RebakeProgress`, `RebakeError`, `RebakePolicy`, `RebakeConfig` | `tidefs-rebake-types` (new) |
| **Phase 2: Selection engine** | Scan locator table, sort by birth_commit_group, enforce coldness threshold, produce batch | `tidefs-rebake-select` (new) |
| **Phase 3: Re-encode engine** | Read ingest, verify integrity, encode to shards via TideCRUSH + GF(2^8) RS, write ShardGroupV1 | `tidefs-rebake-encode` (new) |
| **Phase 4: Locator update** | Atomic swap of locator entries, BASE_COMPLETE flag, commit_group integration | `tidefs-rebake-update` (new) |
| **Phase 5: Reclaim integration** | Deadlist entry creation, refcount-0 detection, segment cleaner handoff | `tidefs-rebake-reclaim` (new) |
| **Phase 6: RebakeService** | Implement `BackgroundService` trait, budget consumption, emergency escalation | `tidefs-rebake-service` (new) |
| **Phase 7: Pool integration** | Wire into pool daemon: register with scheduler, reconstruction on import | `tidefs-pool` (existing) |
| **Phase 8: Observability** | Per-tick counters, operator commands, emergency-mode signaling | Phases 6-7 |

### 15.1 Crate Boundaries

```
crates/tidefs-rebake-types/     -- Phase 1: types only (no_std compatible)
crates/tidefs-rebake-select/    -- Phase 2: selection engine
crates/tidefs-rebake-encode/    -- Phase 3: re-encode pipeline
crates/tidefs-rebake-update/    -- Phase 4: locator update + commit_group integration
crates/tidefs-rebake-reclaim/   -- Phase 5: reclaim integration
crates/tidefs-rebake-service/   -- Phase 6: BackgroundService impl
```

## 16. Open Questions

1. **Should rebake use a dedicated thread or the inline scheduler?**
   Rebake is I/O-heavy (reads ingest, writes k+m shards). A dedicated thread
   could reduce tail latency impact on demand I/O. Recommendation: start inline
   with small per-tick budgets, measure tail latency, move to dedicated thread
   only if demand I/O is impacted.

2. **Should partially-rebaked extents be resumable?**
   If rebake is interrupted mid-extent (budget exhaustion, daemon restart),
   the partially written shards are orphaned. Recommendation: make rebake
   atomic per extent -- either all k+m shards are written and the locator is
   updated, or the extent is re-queued for the next tick. No partial state.

3. **How to handle rebake during pool export?**
   During export, complete in-flight rebakes, then suspend the rebake queue.
   On next import, the rebake queue is reconstructed from locator entries with
   `BASE_COMPLETE == false`. Recommendation: drain in-flight rebakes before
   completing export; resume queue on import.

4. **Should the durability ladder block writes at severe degradation?**
   Blocking writes is the safest option but impacts availability. Alternative:
   allow writes but log a critical alert. Recommendation: block writes when
   only 1 replica remains (LossImminent) to prevent silent data loss; operator
   can override via `tidefs.pool.allow_write_during_loss_imminent=1`.

5. **How does rebake interact with snapshots?**
   Snapshots reference the `locator_id`, not the physical location. After
   rebake, the locator points to base shards, and snapshots automatically
   benefit from the improved redundancy. The ingest segment cannot be trimmed
   until all snapshots referencing the old extent are destroyed.

6. **Should rebake use different (k,m) for hot vs cold data?**
   V1: single `DurabilityPolicy` per dataset. V2: could support tiered
   policies (e.g., EC-8+2 for cold data, EC-4+2 for warm data) selected
   by age-based heuristics. Deferred to implementation review.

## 17. References

- [#1222] This design spec
- [#1285] Extent maps and locator tables -- `ExtentLocatorValueV1`, locator_id
- [#1286] Shard groups, replicas, and rebake pathway -- `ShardGroupV1`, `ReplicaLifecycle`
- [#1249] Erasure coding and CRUSH-like placement -- TideCRUSH, `EcProfile`
- [#1179] Background service framework -- `BackgroundService`, `ServiceBudget`, `TickReport`
- [#1215] Space accounting model -- `SpaceDelta`, segment cleaner, deadlist
- [#1288] Scrub, repair, and resilver -- source selection from healthy shards
- [#1267] COMMIT_GROUP state machine -- canonical commit ordering
- [#1224] Torn-commit recovery -- journal scan fallback
- [#1242] Per-dataset unified property framework -- dataset property binding
- [#1223] Dataset feature flags -- `DROP_INGEST_AFTER_REBAKE` flag
- `docs/SHARD_GROUPS_REPLICAS_REBAKE_DESIGN.md`
- `docs/ERASURE_CODING_PLACEMENT_DESIGN.md`
- `docs/EXTENT_MAPS_LOCATOR_TABLES_DESIGN.md`
- `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md`
- `docs/SPACE_ACCOUNTING_MODEL_DESIGN.md`
- `docs/COMMIT_GROUP_STATE_MACHINE_DESIGN.md`
- `docs/CHECKSUM_ARCHITECTURE_DESIGN.md`
- `docs/SCRUB_REPAIR_RESILVER_DESIGN.md`
- Python v0.262 design book: SS29-31 (rebake architecture)
