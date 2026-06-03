# Space Pressure Handling: Automatic Journal Cleaning under ENOSPC

**Issue**: [#1181](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1181)
**Status**: design-spec
**Priority**: P2
**Lane**: storage-core
**Maturity**: design-spec — specifies the pressure model, handler trait, cleaning strategies, and integration contract
**Depends on**: #1189 (spacemap allocator), #1179 (background scheduler), #1177 (background services), #1178 (refcount delta cleanup)

## Abstract

This document defines how tidefs detects, signals, and automatically recovers
from near-out-of-space conditions on a journal-by-journal basis. It specifies
the multi-level pressure model, the `SpacePressureHandler` trait, the cleaning
strategies for the three journal classes (pool-map, metadata, data), and the
integration contract with the existing `PoolAllocator`, `ReclaimScheduler`,
`BackgroundScheduler`, and `LocalObjectStore` append path.

This is a **behavioural design** that defines *when* and *what* cleaning
happens, not the implementation details of individual cleaners (those have
their own design documents).

## Relationship to existing docs

| Document | Role |
|---|---|
| `ALLOCATOR_RECLAIM_FREE_SPACE_SCHEMA_FAMILY_P2-02.md` | Allocator family law: segments, extents, reserve, reclaim |
| `BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md` (#1179) | Scheduler hosting the segment cleaner and journal compactors |
| `docs/SPACEMAP_ALLOCATOR_DESIGN.md` (#1189) | `SegmentFreeMap`, `SpaceMapCheckpointV1`, per-metaslab allocation |
| `docs/DATASET_LIFECYCLE_DESIGN.md` | `GcPinSet` — pinned traversal roots as GC barriers |
| crate `tidefs-pool-allocator` | `PoolAllocator`, `SpacePressureEvent`, pressure transitions |
| crate `tidefs-reclaim` | `ReclaimScheduler`, cooldown, waste-threshold compaction |
| crate `tidefs-background-scheduler` | `BackgroundService`, 5-stage priority dispatching |

This document is the **authoritative pressure model**. Individual cleaner
docs remain canonical for their detailed algorithms.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                     SPACE PRESSURE ARCHITECTURE                       │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  append() ──► SpacePressureHandler::ensure_space(bytes_needed)       │
│                         │                                            │
│              ┌──────────┼──────────┐                                 │
│              ▼          ▼          ▼                                 │
│        PoolMap      Metadata     Data                                │
│        Journal      Journal      Journal                             │
│              │          │          │                                  │
│              ▼          ▼          ▼                                 │
│        PoolMapCleaner  SegmentCleaner  DataCleaner                   │
│        (compaction)    (live marking)  (refcount delta)              │
│              │          │          │                                  │
│              └──────────┼──────────┘                                 │
│                         ▼                                            │
│              BackgroundScheduler (5-stage priority)                  │
│                         │                                            │
│                         ▼                                            │
│              PoolAllocator.add_free() → SegmentFreeMap               │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### Crate involvement

| Crate | Role |
|---|---|
| `tidefs-local-object-store` | Hosts per-store `SpacePressureHandler`, journal write path |
| `tidefs-spacemap-allocator` | `SegmentFreeMap`, checkpoint persistence |
| `tidefs-pool-allocator` | `PoolAllocator`, pressure transitions, ENOSPC propagation |
| `tidefs-reclaim` | `ReclaimScheduler`, waste-threshold compaction orchestration |
| `tidefs-background-scheduler` | `BackgroundService` trait, tick dispatch, budget enforcement |
| `tidefs-gc-pin-set` | `GcPinSet` — pinned roots for safe GC marking |

---

## 1. Pressure Model

### 1.1 Three pressure levels

The pressure model uses the pool-wide free-segment ratio evaluated against
the `PoolAllocator`'s 95% threshold (defined in `tidefs-pool-allocator` as
`SPACE_PRESSURE_THRESHOLD`).

| Level | Free ratio | Trigger | Action |
|---|---|---|---|
| **Normal** | free > 20% | — | No cleaning action |
| **Mild pressure** | free ≤ 20% | Falling edge across 20% boundary | Schedule background cleaning; writes proceed normally |
| **High pressure** | free ≤ 5% | Falling edge across 5% boundary | Synchronous cleaning before next write; write latency increases |
| **Emergency** | free == 0 | `PoolAllocator::allocate()` returns `NoFreeSegments` | Block writes; run emergency reclaim synchronously; return ENOSPC if reclaim cannot free space |

detector. This design adds two additional thresholds (20% and 5%) that refine
the *response grading* above that single binary detector.

### 1.2 Threshold configuration

```rust
/// Per-journal pressure thresholds (fraction of total segments).
#[derive(Debug, Clone)]
pub struct PressureThresholds {
    /// Below this fraction, mild pressure activates (background cleaning).
    /// Default: 0.20 (20% free).
    pub mild: f64,
    /// Below this fraction, high pressure activates (synchronous cleaning).
    /// Default: 0.05 (5% free).
    pub high: f64,
    /// At this fraction, the pool is "under pressure" (matches PoolAllocator's
    /// SPACE_PRESSURE_THRESHOLD). Used for the EnterPressure/ExitPressure events.
    /// Default: 0.05 (5% free; same as the PoolAllocator default of 95% used).
    pub pool_pressure: f64,
}

impl Default for PressureThresholds {
    fn default() -> Self {
        Self {
            mild: 0.20,
            high: 0.05,
            pool_pressure: 0.05,
        }
    }
}
```

### 1.3 Pressure state machine

```
                    ┌──────────────────────────────────────────────┐
                    │                                              │
    ┌──────────┐   │   free drops below 20%    ┌──────────────┐   │
    │  NORMAL  │───┼──────────────────────────►│    MILD      │   │
    │          │   │                           │  PRESSURE    │   │
    └──────────┘   │                           └──────────────┘   │
         ▲         │                                  │            │
         │         │   free rises above 20%           │ free drops │
         │         ├──────────────────────────────────┘ below 5%   │
         │         │                                              │
         │         │                           ┌──────────────┐   │
         │         │   free rises above 5%     │    HIGH      │   │
         │         ├───────────────────────────│  PRESSURE    │   │
         │         │                           └──────────────┘   │
         │         │                                  │            │
         │         │                                  │ free == 0  │
         │         │                           ┌──────▼──────┐    │
         │         │   reclaim succeeds        │  EMERGENCY  │    │
         │         ├───────────────────────────│ (ENOSPC)    │    │
         │         │                           └─────────────┘    │
         │         │                                              │
         └─────────┴──────────────────────────────────────────────┘
```

Transitions are edge-triggered (fire once per crossing, not on every query):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureLevel {
    Normal,
    Mild,
    High,
    Emergency,
}

impl PressureLevel {
    pub fn compute(free_ratio: f64, thresholds: &PressureThresholds) -> Self {
        if free_ratio <= 0.0 {
            Self::Emergency
        } else if free_ratio <= thresholds.high {
            Self::High
        } else if free_ratio <= thresholds.mild {
            Self::Mild
        } else {
            Self::Normal
        }
    }
}
```

---

## 2. SpacePressureHandler Trait

### 2.1 Trait definition

The handler is invoked before every append to a journal. Each journal class
(pool-map, metadata, data) gets its own handler instance, allowing
journal-specific cleaning strategies.

```rust
/// Installed before every append to a journal.
///
/// Each implementor owns the cleaning strategy for one journal class.
/// The handler is called with the number of bytes the caller intends to
/// write. It returns `Ok(())` if sufficient space is available or was
/// freed; `Err(StoreError::NoSpace)` if space cannot be made available.
pub trait SpacePressureHandler: Send {
    /// Called before an append of `bytes_needed` bytes.
    ///
    /// # Returns
    /// - `Ok(())` — sufficient free segments exist (naturally or after cleaning).
    /// - `Err(StoreError::NoSpace)` — no free segments and reclaim failed.
    fn ensure_space(&mut self, bytes_needed: u64) -> Result<(), StoreError>;

    /// Current pressure level, for observability and testing.
    fn pressure_level(&self) -> PressureLevel;

    /// Total bytes freed by this handler since mount.
    fn total_freed_bytes(&self) -> u64;

    /// Number of cleaning episodes executed.
    fn cleaning_episodes(&self) -> u64;
}
```

### 2.2 Handler wiring

Each `LocalObjectStore` journal gets one handler:

```rust
pub struct LocalObjectStore {
    // ... existing fields ...
    /// Pool-map journal pressure handler.
    pool_map_handler: Box<dyn SpacePressureHandler>,
    /// Metadata journal pressure handler.
    metadata_handler: Box<dyn SpacePressureHandler>,
    /// Data journal pressure handler.
    data_handler: Box<dyn SpacePressureHandler>,
}
```

The append path calls the appropriate handler before allocating a new segment:

```rust
fn ensure_space_for_append(
    handler: &mut dyn SpacePressureHandler,
    free_map: &mut PoolAllocator,
    reclaim: &mut ReclaimScheduler,
    bytes_needed: u64,
    segment_bytes: u64,
) -> Result<()> {
    match handler.pressure_level() {
        PressureLevel::Normal => {
            // No action. If allocation fails, fall through to emergency.
            if free_map.free_count() > 0 {
                return Ok(());
            }
        }
        PressureLevel::Mild => {
            // Schedule background cleaning; write proceeds immediately.
            // The scheduler will pick this up on its next tick.
        }
        PressureLevel::High => {
            // Synchronous cleaning: run one compaction pass before writing.
            // Wait up to pressure_reclaim_timeout before failing.
        }
        PressureLevel::Emergency => {
            // No free segments. Attempt emergency reclaim synchronously.
            // If reclaim frees no segments, return NoSpace.
        }
    }
    handler.ensure_space(bytes_needed)
}
```

### 2.3 Timeout for synchronous cleaning

High-pressure cleaning is synchronous (blocks the writer), so it must have a
bounded timeout to prevent unbounded write stalls:

```rust
/// Maximum time a synchronous cleaning pass may consume before falling
/// back to ENOSPC. Default: 500ms.
pub const PRESSURE_RECLAIM_TIMEOUT_MS: u64 = 500;
```

---

## 3. Journal Classes and Cleaning Strategies

tidefs maintains three logical journal classes, each with its own cleaning
semantics. The division follows ZFS's intent-log / metadata / data split.

### 3.1 Pool-map journal

The pool-map journal records the persistent free-space map (`SpaceMapCheckpointV1`),
index checkpoints, and segment lifecycle metadata.

**Cleaning strategy** (PoolMapCleaner):

1. Iterate the pool-map journal, identifying obsolete checkpoints.
2. Compose a new pool-map checkpoint containing only the current live state.
3. Mark the old segments as free in the space map.
4. Write the new checkpoint to a fresh segment.
5. If still under pressure, repeat with diminishing returns.

**Notes:**

- Pool-map entries are small and infrequent; the journal grows slowly.
- Cleaning is a straightforward compaction: read all live entries, write
  them to a new segment, free the old ones.
- This is a `BackgroundService` at `ServicePriority::Critical` because it
  directly affects the ability to allocate new segments.

### 3.2 Metadata journal

The metadata journal contains directory entries, inode updates, extent maps,
ACL records, and xattr records.

**Cleaning strategy** (SegmentCleaner):

1. Scan the committed root (the current committed commit_group root pointer).
2. Mark all segments reachable from the root — this is the live set.
3. Any segment not in the live set is a candidate for reclamation.
4. If a segment has *some* live records, attempt **segment compaction**:
   copy all live records to a new segment, then free the old one.
5. If a segment has *no* live records, free it directly.

**Live marking algorithm:**

```
committed_root ──► walk btree / hash chains
                       │
                       ▼
                  reachable_set: BTreeSet<SegmentId>
                       │
                       ▼
                  all_segments - reachable_set = reclaimable
```

**Compaction heuristic** (`should_compact`):

- A segment is compacted when its waste ratio exceeds the configured threshold
  (default 0.3, from `ReclaimConfig::waste_threshold`).
- This is the same heuristic already used by `LocalObjectStore::should_compact`.

**Priority:** `ServicePriority::BestEffort` (compaction and GC marking run when
higher-priority work is idle).

### 3.3 Data journal

The data journal contains object payloads (file data, large xattr values,
indirect block trees).

**Cleaning strategy** (DataCleaner + SegmentCleaner):

1. The **DataCleaner** processes refcount delta queues (#1178) to identify
   extents whose refcount has dropped to zero.
2. Dead extents are accumulated in a "free pending" list.
3. When a data segment has *all* its extents in the free-pending list, the
   **SegmentCleaner** marks the entire segment as free.

**Relationship to refcount deltas (#1178):**

- The refcount delta queue (#1178) is the *input* to data cleaning.
- When an `unlink` or `truncate` decrements a refcount, a delta is queued.
- The DataCleaner drains the queue, reconciles deltas against the extent
  refcount table, and emits "extent X is now dead" events.
- The SegmentCleaner aggregates dead extents by segment and frees segments
  that are fully dead.

**Priority:** `ServicePriority::Throughput` (bulk data work; not latency-sensitive
but expected to make steady progress).

---

## 4. Persistent Free-Space Map

### 4.1 Existing foundation

The free-space map is already implemented in `tidefs-spacemap-allocator`
(`SegmentFreeMap`, `SpaceMapCheckpointV1`). This design specifies the
additional requirements for journal-level pressure awareness.

### 4.2 Checkpoint strategy

| Trigger | Dirty-only or full |
|---|---|
| Normal rotation | Dirty-only (incremental metaslab updates) |
| After reclaim batch | Dirty-only |
| On clean shutdown | Full checkpoint |
| Under mild pressure | Dirty-only at normal frequency |
| Under high pressure | Full checkpoint after each synchronous cleaning pass |

### 4.3 Space map checkpoint layout

```
┌───────────────────────────────────────────────────────────────┐
│ SpaceMapCheckpointV1                                          │
├──────────┬──────────┬─────────────┬──────────────┬────────────┤
│ Header   │ Segment  │ Metaslab    │ Dirty        │ Generation │
│ ("SPMP") │ count    │ segments    │ count        │ counter    │
├──────────┴──────────┴─────────────┴──────────────┴────────────┤
│ MetaslabBitmapEntry[0..N]                                     │
├──────────────┬──────────────┬─────────────────────────────────┤
│ metaslab_idx │ bitmap_len   │ bitmap_data (1 bit per segment) │
│ (u32)        │ (u32)        │ LSB-first per byte              │
└──────────────┴──────────────┴─────────────────────────────────┘
│ Checksum (u64, CRC64 over all preceding bytes)                │
└───────────────────────────────────────────────────────────────┘
```

### 4.4 Crash recovery

On mount, `LocalObjectStore::open_with_mode` loads the most recent space map
checkpoint and replays any subsequent segment allocations/frees from the
segment log to rebuild the allocator state. The generation counter defends
against stale-pointer corruption:

```
recovery algorithm:
  1. Read latest SpaceMapCheckpointV1 from segments_dir
  2. Decode bitmaps, construct SegmentFreeMap
  3. Scan segments written after the checkpoint's generation
  4. Apply alloc/free delta operations from those segments
  5. Reconstruct PoolAllocator with recovered state
```

### 4.5 Deterministic freemap guarantees

- Runs are encoded as `(offset, length)` tuples in the in-memory `BTreeSet`
  representation. The `SpaceMapCheckpointV1` bitmap encoding is a
  deterministic transform: given the same run set, the same bitmaps are
  produced.
- After crash, replay deltas from the last checkpoint to recover allocator
  state. The generation counter ensures that a stale checkpoint referencing
  freed-and-reallocated segments is detected and rejected.
- The checkpoint is written atomically: write to a new segment, fsync, then
  update the pointer. A torn write leaves either the old or the new checkpoint
  intact.

---

## 5. Integration with BackgroundScheduler

### 5.1 Service registration

All cleaners register as `BackgroundService` implementations with the
`BackgroundScheduler`:

| Service | Priority | Journal class |
|---|---|---|
| `PoolMapCleaner` | `Critical` | Pool-map |
| `DataCleaner` | `Throughput` | Data |
| `SegmentCleaner` | `BestEffort` | Metadata + Data |

The scheduler dispatches them in strict priority order with per-tick budgets.
Under normal operation, only the `BestEffort` and `Throughput` cleaners run.
When pressure rises, the scheduler allocates additional budget to the cleaners
for the journals under pressure.

### 5.2 Pressure-aware budget adjustment

When the `PoolAllocator` is under pressure, the scheduler temporarily boosts
the budget for cleaning services:

```
normal budget:  ServiceBudget::DEFAULT_TICK (100 items, 1 MiB, 10ms)
mild pressure:  ServiceBudget::PRESSURE_TICK (500 items, 4 MiB, 50ms)
high pressure:  No budget cap — cleaner runs to completion
```

### 5.3 Interaction with ReclaimScheduler

The `ReclaimScheduler` (in `tidefs-reclaim`) already coordinates compaction
via `rotate_segment()`. The pressure handler layers on top:

- `ReclaimScheduler` controls *when* compaction is safe (cooldown, waste ratio).
- `SpacePressureHandler` controls *whether* cleaning is urgent (pressure level).
- Together they ensure that cleaning is aggressive under pressure and
  conservative under normal conditions.

---

## 6. ENOSPC Fault Injection

### 6.1 Existing mechanism

`FaultInjectionConfig::enospc_after_bytes` causes the store to reject writes
after `enospc_bytes_written` exceeds the limit. This is used in tests to
simulate a full pool.

### 6.2 Extension for pressure testing

Extend the fault injection catalog to support pressure-level injection:

```rust
/// Additional ENOSPC fault injection point for pressure testing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EnospcInjectionPoint {
    /// Inject ENOSPC after the next segment rotation.
    AfterNextRotate,
    /// Inject ENOSPC during ensure_space for the data journal.
    DuringEnsureSpaceData,
    /// Inject ENOSPC during ensure_space for the metadata journal.
    DuringEnsureSpaceMetadata,
}
```

This enables deterministic testing of each pressure level and recovery path.

---

## 7. Integration Test Plan

### 7.1 Test scenarios

| Test | Description |
|---|---|
| `mild_pressure_triggers_background_cleaning` | Allocate until 20% free; verify cleaner is scheduled |
| `high_pressure_triggers_sync_cleaning` | Allocate until 5% free; verify writes block briefly |
| `emergency_reclaim_frees_space` | Exhaust pool; delete objects; verify emergency reclaim succeeds |
| `emergency_reclaim_returns_enospc_when_full` | Exhaust pool with no dead objects; verify ENOSPC returned |
| `pressure_transitions_bidirectional` | Free space after pressure; verify level returns to Normal |
| `crash_during_cleaning_recovers` | Crash while cleaner is active; verify pool recovers on mount |
| `fault_injection_each_level` | Inject ENOSPC at each pressure level; verify correct error path |


- The space pressure integration tests must exercise all four pressure levels
  (Normal → Mild → High → Emergency → recovery → Normal).
- The deterministic crash injection harness (#1230) must cover crashes at
  each pressure-level boundary.

---

## 8. Tradeoffs and Design Decisions

### 8.1 Why per-journal handlers instead of one global handler?

Each journal class has fundamentally different cleaning mechanics:
- Pool-map: simple compaction of small records.
- Metadata: live-set marking against the committed root.
- Data: refcount-delta-driven free-pending accumulation.

A single handler would need to dispatch internally on journal type, making the
interface less clear and harder to test in isolation.

### 8.2 Why synchronous cleaning at high pressure?

At 5% free, every write risks exhausting the pool. Deferring cleaning to a
background thread could result in ENOSPC before the cleaner's next tick. A
bounded synchronous pass (500ms) ensures the writer can proceed without
indefinite stalls.

### 8.3 Why not continuous background cleaning?

Continuous cleaning (always compacting old segments) wastes I/O bandwidth and
increases write amplification. The pressure-threshold model ensures cleaning
only happens when needed, and with intensity proportional to urgency.

### 8.4 Relationship to distributed GC (#917)

This design addresses *local* space pressure — the local node's pool. The
distributed GC in #917 operates at the cluster level (cross-node segment
reachability, distributed refcount reconciliation). The two are complementary:
- Local cleaning frees space on the local node.
- Distributed GC ensures that cluster-wide refcounts are consistent before
  local cleaning can safely free a segment.

### 8.5 Why retain the 95% threshold alongside 5% and 20%?

The 95% threshold (`SPACE_PRESSURE_THRESHOLD`) in `PoolAllocator` is the
existing "under pressure" detector used by `ReclaimScheduler`. The new 20%
(mild) and 5% (high) thresholds refine the response without breaking the
existing compaction path. They coexist: the 95% threshold triggers
`EnterPressure`/`ExitPressure` events, while the wider thresholds gate
additional cleaning strategies.

---

## 9. Implementation Sequence

| Step | Crate(s) | Description |
|---|---|---|
| 1 | `tidefs-local-object-store` | Add `PressureLevel`, `PressureThresholds` types |
| 2 | `tidefs-local-object-store` | Define `SpacePressureHandler` trait |
| 3 | `tidefs-local-object-store` | Wire `ensure_space` calls into append path |
| 4 | `tidefs-local-object-store` | Implement `PoolMapCleaner` (simple compaction) |
| 5 | `tidefs-local-object-store` | Implement `SegmentCleaner` (live-mark + compact) |
| 6 | `tidefs-local-object-store` | Wire cleaners as `BackgroundService` instances |
| 7 | `tidefs-local-object-store` | Extend `FaultInjectionConfig` with pressure injection points |
| 8 | `tidefs-local-object-store` | Add integration tests for all four pressure levels |

---

## 10. Open Questions

1. **Should the 500ms timeout be configurable per journal class?** Data
   cleaning may legitimately take longer than metadata cleaning due to
   larger segment sizes. Consider per-journal timeout overrides.
2. **Should mild-pressure cleaning be triggered by the scheduler's tick
   or by a dedicated wake-up?** The current design relies on the scheduler's
   normal tick cadence. If the tick interval is too long under rapid writes,
   mild pressure could degrade into high pressure before cleaning starts.
3. **Should the generation counter be per-segment or global?** The current
   `SpaceMapCheckpointV1` uses a single global generation counter. Per-segment
   generations would allow finer-grained stale-pointer detection but increase
   checkpoint size.

---

*Generated from issue #1181. v0.1 — design-spec, not implementation.*
