# Prefetch and Readahead Architecture: Budgeted Speculative IO, Metadata Prefetch, Workload Signal Integration

Maturity: **design-spec** for the classical prefetch and readahead system,
bridging sequential-detection, extent-map lookahead, metadata prefetch, and
workload-signature-driven speculative IO into the existing resource governor,
background scheduler, and workload model.

This document closes Forgejo issue #1247.

## 1. Motivation

v0.262 identified prefetch as a design-level feature with a clear architectural
stance: budgeted, never correctness-critical, separated from demand IO. The
current codebase has:

- A workload signature framework (`docs/WORKLOAD_SIGNATURE_MATERIALIZATION_PLANE_LAW.md`)
  that classifies live access patterns but does not drive classical readahead.
- A resource governor (`docs/UNIFIED_RESOURCE_GOVERNOR_DESIGN.md`) with a
  `data_cache` category that partitions L1 (hot) from L2 (prefetch), and an
  `AdmissionPriority::Low` for speculative allocations.
- A background scheduler (`docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md`) with an
  `Opportunistic` priority stage explicitly reserved for prefetch and readahead.
- Extent maps and locator tables (`docs/EXTENT_MAPS_LOCATOR_TABLES_DESIGN.md`,
  `docs/POLYMORPHIC_EXTENT_MAPS_DESIGN.md`) that provide the structural basis
  for layout-aware prefetch.
- A publication pipeline with per-lane queue classes and BULK data-plane
  scheduling (`docs/PUBLICATION_PIPELINE_RUNTIME_DECOMPOSITION_P3-02.md`).

What is missing is a unified design that connects these pieces: a concrete
architecture for sequential-access detection in a FUSE userspace daemon, a
readahead state machine inspired by Linux kernel concepts but adapted for
userspace, metadata prefetch triggered by workload signatures, budget
integration with the governor, and a clear relationship to the RDMA bulk-plane
path.

## 2. Design Principles from v0.262

These principles are non-negotiable and frame every decision in this document:

### 2.1 Prefetch is never correctness-critical

- Prefetch failures are silent; demand reads always fall through.
- No prefetch result may be used to satisfy a correctness requirement.
- A prefetched extent that arrives after the demand read is not an error;
  it is simply discarded.

### 2.2 Demand must win

- Prefetch uses budget tokens from the resource governor (#1237).
- Prefetch work is scheduled in the `Opportunistic` stage of the background
  scheduler (#1241).
- Prefetch must not occupy queue slots needed by demand reads.
- When demand IO is pending, prefetch yields immediately.

### 2.3 Budget model

- Per-dataset prefetch budget in bytes/ops per tick.
- Budget replenishment tied to idle cycles.
- Fractional budgeting for metadata vs data prefetch.
- Prefetch allocations use `AdmissionPriority::Low`; they are the first to be
  evicted under memory pressure.

### 2.4 Concrete prefetch sources

1. **Extent map lookahead for sequential reads**: detect sequential access
   patterns, issue readahead for next extent(s) in the B-tree.
2. **Directory change stream anticipation**: track churn on hot directories,
   pre-warm derived views.
3. **View refresh delta scans as controlled metadata prefetch**: incremental
   derived view updates double as prefetch.

## 3. Sequential Access Detection (FUSE Userspace)

### 3.1 Problem: No kernel page cache visibility

In a kernel-resident filesystem, the kernel's page cache provides a natural
sequential-access detection substrate: the `->readahead()` folio contract
receives the file, offset, and a folio batch that the kernel has already
decided to prefetch. The kernel maintains per-file readahead state (the
`file_ra_state` struct) that tracks the sequential-read window.

In a FUSE userspace daemon, none of this exists. The daemon receives discrete
`FUSE_READ` requests with no hint about whether the access is sequential.
There is no kernel-side readahead state to consult.

### 3.2 Solution: Per-File-Handle Access History

TideFS maintains a lightweight per-open-file-handle access history in the
FUSE daemon. This history lives in daemon memory only (never persisted) and
is keyed by the FUSE file handle (`fuse_ino_t`, `fuse_fh_t`).

```rust
struct AccessHistory {
    file_handle: (u64, u64),     // (ino, fh)
    last_offset: u64,            // offset of the most recent read
    last_length: u32,            // length of the most recent read
    sequential_streak: u8,       // consecutive sequential reads (0-255)
    max_sequential_streak: u8,   // rolling max of sequential_streak
    last_access_tick: u64,       // monotonic tick of last access
    state: AccessState,          // state machine node
}

enum AccessState {
    Idle,                // no recent access history
    Random,              // non-sequential access pattern detected
    SequentialCandidate, // 2+ sequential reads; not yet promoted
    SequentialConfirmed, // >= 4 sequential reads; readahead active
    Streaming,           // long sequential run; aggressive readahead
}
```

### 3.3 State Machine

The access state machine transitions on every `FUSE_READ`:

Transition rules:

1. **Idle → SequentialCandidate**: Two consecutive reads where
   `this.offset == last.offset + last.length`. Streak counter set to 2.
2. **SequentialCandidate → SequentialConfirmed**: Two more sequential reads
   (streak >= 4). Readahead engine is activated.
3. **SequentialConfirmed → Streaming**: Streak >= 16 or file accessed at
   >80% of its extent-map sequential coverage. Aggressive readahead window
   expansion is enabled.
4. **Any → Random**: A read arrives where `this.offset != last.offset + last.length`
   and `this.offset` is not within the already-issued readahead window.
5. **Any → Idle**: No access for `ACCESS_HISTORY_TTL_TICKS` (default: 600 ticks
   ~ 60 seconds at 100ms tick interval). The history entry is evicted.

### 3.4 Handling Overlapping and Out-of-Order Reads

FUSE may reorder reads (especially under `max_readahead` tuning or
`writeback_cache`). The detection algorithm handles this:

- If `this.offset` falls within `[last_offset + last_length, last_offset + last_length + window_slack]`
  where `window_slack` is `last_length * 2`, the read is treated as sequential.
- If `this.offset < last_offset` but within the already-issued readahead window,
  the read is a re-read of prefetched data and does not reset the streak.
- Overlapping reads (offset within `[last_offset, last_offset + last_length)`)
  are benign; they do not advance or reset the streak.

### 3.5 Per-Handle Storage and Cleanup

Access histories are stored in a `HashMap<(u64, u64), AccessHistory>` limited
to `MAX_ACCESS_HISTORIES` entries (default: 4096). When the map is full, the
oldest `last_access_tick` entry is evicted. On `FUSE_RELEASE`, the entry is
removed.

## 4. Readahead Engine

### 4.1 Extent-Map Lookahead

Once sequential access is confirmed, the readahead engine issues speculative
reads for extents beyond the current demand position. The engine uses the
extent map B-tree to discover upcoming extents without reading file data.

```
fn compute_readahead_window(
    extent_map: &ExtentMap,
    current_offset: u64,
    current_length: u32,
    state: &AccessState,
    budget: &PrefetchBudget,
) -> Vec<ReadaheadExtent> {
    // 1. Find the extent(s) covering [current_offset, current_offset + current_length]
    // 2. Walk the B-tree forward to collect upcoming DATA extents
    // 3. Compute window size based on access state:
    //    - SequentialConfirmed: 2x the current read length (capped at 256 KiB)
    //    - Streaming: 8x the current read length (capped at 2 MiB)
    // 4. Apply budget constraint: total readahead bytes <= budget.remaining_data_bytes
    // 5. Return the list of extents to prefetch
}
```

### 4.2 Window Sizing Policy

| State | Multiplier | Max Window | Rationale |
|-------|-----------|------------|-----------|
| `SequentialConfirmed` | 2x | 256 KiB | Conservative; demand may diverge |
| `Streaming` | 8x | 2 MiB | Aggressive; pattern is trusted |
| `Streaming` + low budget | 4x | 512 KiB | Scaled back under pressure |

The window is further constrained by:

- **Extent count cap**: No more than `MAX_READAHEAD_EXTENTS` (default: 64) extents
  per window.
- **Gap limit**: A HOLE of >`READAHEAD_HOLE_SKIP_THRESHOLD` (default: 1 MiB)
  truncates the window (holes are not worth prefetching).
- **File boundary**: The window cannot extend past `file_size`.

### 4.3 Readahead Issuance

Readahead extents are issued as `ReadRequest` objects placed on a dedicated
`PREFETCH_QUEUE`. The queue is drained by the FUSE daemon's main loop only
when no demand reads are pending:

```
FUSE daemon main loop:
    loop:
        if demand_ops_pending():
            process_one_demand_op()
        else if !prefetch_queue.is_empty():
            issue_one_prefetch_read()
        else if background_timer_elapsed():
            scheduler.run_cycle(small_budget)
        else:
            wait_for_events()
```

Each prefetch read is tagged with a `lane = Lane::Speculative` so that the
transport layer never competes with demand traffic.

### 4.4 Completion Handling

When a prefetch read completes:

1. The extent payload is admitted into the **L2 prefetch cache** (under
   `data_cache` budget category, `AdmissionPriority::Low`).
2. If the extent was already demanded (user beat the prefetch), the
   prefetch result is discarded -- the demand read result takes priority.
3. If the L2 cache is under `EVICT_SOFT` pressure, the prefetch result
   may be silently dropped without cache admission.
4. Completed prefetch extents carry a `prefetch_tag` bit in the cache
   entry metadata, distinguishing them from demand-filled L1 entries.

## 5. Prefetch Cache (L2) and Pollution Avoidance

### 5.1 L2 Architecture

The L2 prefetch cache is a sub-partition of the `data_cache` budget category.
It shares the same ARC-based eviction policy but at lower priority:

| Cache level | Priority | Eviction order | Admission priority | Typical size |
|-------------|----------|---------------|-------------------|-------------|
| L1 (hot) | Higher | Evicted last | `Normal` (~3) | ~70% of `data_cache` |
| L2 (prefetch) | Lower | Evicted first | `Low` (~5) | ~30% of `data_cache` |

The governor enforces that L2 is evicted before L1 when `data_cache` hits
`EVICT_SOFT`. L2 entries carry a `prefetch_tag` bit; on a demand hit to an
L2 entry, the entry is promoted to L1 (the bit is cleared) and the demand
is satisfied from the already-cached data.

### 5.2 Prefetch Hit Promotion

When a demand read finds its data in L2 (a prefetch hit):

1. The L2 entry is promoted to L1.
2. The `prefetch_tag` is cleared.
3. The ARC state is updated as if this were an L1 hit.
4. The sequential access streak is reinforced (since the readahead engine
   correctly predicted the next access).

This promotion path means successful prefetch is invisible to the caller:
the data is already in cache, and the promotion is a metadata-only operation.


Prefetched extents carry a `birth_commit_group`. When the extent map is mutated

- On extent-map mutation, the mutation's `(inode, offset_range)` is
- The cache layer compares the feed entry against L1 and L2 entries.
- L2 entries for the affected range are evicted without ceremony
  (no writeback -- prefetch is clean).
- L1 entries for the affected range follow the standard coherency

## 6. Metadata Prefetch

### 6.1 Motivation

Directory traversal and `stat()` patterns dominate cloud workload startup.
The workload signature framework can detect metadata-heavy access patterns
and trigger metadata prefetch -- pre-loading directory entries, inode records,
and xattrs before they are demanded.

### 6.2 Detection

Metadata prefetch is triggered by workload signature classification, not
by sequential-offset patterns. The signature `metadata_hotset.s0` indicates
metadata-dominant name/attr/open/close locality. When this signature is
active for a dataset, the materialization plane considers metadata prefetch
as a candidate materialization.

### 6.3 Metadata Prefetch Actions

| Action | Trigger | Budget category | What is prefetched |
|--------|---------|----------------|-------------------|
| Directory pre-warm | `readdir` on a hot directory | `meta_cache` | Child inode records, directory entry views |
| Path-lookup prefetch | Repeated `lookup` on a prefix tree | `meta_cache` | Intermediate directory B+tree nodes |
| Stat-ahead | Repeated `getattr` on sequential inodes within a directory | `meta_cache` | Inode records for upcoming dirents |
| Xattr pre-load | High `listxattr`/`getxattr` rate on a directory tree | `meta_cache` | Xattr payloads for sibling inodes |

### 6.4 Relationship to Derived View Builders

Derived view builders (#1240) are natural metadata prefetch engines. When
the workload model requests a directory index view or a namespace summary
(product `p0`), the view builder's incremental refresh acts as metadata
prefetch:

1. The view builder scans directory entry tables to detect changes.
2. During the scan, it touches B+tree pages and inode records.
3. Those pages are admitted into `meta_cache` as a natural side effect.
4. Subsequent demand lookups in the same directory tree hit warm cache.

This means metadata prefetch and derived view refresh share the same
budget pool (`meta_cache`) and the same background scheduler stage
(`LatencySensitive` for view building, `Opportunistic` for pure prefetch).

### 6.5 Metadata Prefetch Budget Allocation

The `meta_cache` budget category is split between demand metadata and
prefetch metadata:

| Sub-category | Fraction | Admission | Eviction order |
|-------------|----------|-----------|---------------|
| Demand metadata (L3, L4) | ~80% | `High` | Evicted last |
| Prefetch metadata | ~20% | `Low` | Evicted first |

When `meta_cache` is under pressure, prefetch metadata is evicted before
any demand-loaded metadata.

## 7. Budget Integration

### 7.1 PrefetchBudget Structure

```rust
/// Per-dataset budget for prefetch operations, replenished each governor tick.
pub struct PrefetchBudget {
    /// Maximum data bytes that may be prefetched this tick.
    pub max_data_bytes: u64,

    /// Maximum metadata operations (readdir, getattr, lookup) that may be
    /// speculatively issued this tick.
    pub max_meta_ops: u64,

    /// Remaining data bytes for the current tick.
    pub remaining_data_bytes: u64,

    /// Remaining metadata ops for the current tick.
    pub remaining_meta_ops: u64,

    /// Fraction of the data_cache budget allocated to prefetch (L2).
    /// Default: 0.30 (30% of data_cache for L2 prefetch).
    pub data_cache_prefetch_fraction: f64,

    /// Fraction of the meta_cache budget allocated to prefetch.
    /// Default: 0.20 (20% of meta_cache for speculative metadata).
    pub meta_cache_prefetch_fraction: f64,
}
```

### 7.2 Budget Replenishment

The budget is replenished each governor tick. The replenishment calculation:

```rust
fn replenish_prefetch_budget(dataset, governor_state, workload_signal) {
    // Base budget: fraction of idle cycles
    let idle_fraction = governor_state.idle_cycle_ratio;
    let mut base_data = dataset.data_cache_cap * PREFETCH_FRACTION * idle_fraction;
    let mut base_meta  = dataset.meta_cache_cap * METAPREFETCH_FRACTION * idle_fraction;

    // Workload signal modifier
    if workload_signal.stream_seq_confidence > 0.6 {
        base_data *= 2.0;   // double data prefetch budget for streaming
    }
    if workload_signal.metadata_hotset_confidence > 0.6 {
        base_meta *= 2.0;   // double metadata prefetch budget for metadata-heavy
    }

    // Pressure cap
    if governor_state.backpressure_active {
        base_data = 0;      // no prefetch under global backpressure
        base_meta = 0;
    }

    budget.max_data_bytes = base_data;
    budget.max_meta_ops = base_meta / AVG_METADATA_OP_BYTES;
    budget.remaining_data_bytes = base_data;
    budget.remaining_meta_ops = budget.max_meta_ops;
}
```

### 7.3 Budget Consumption

Each prefetch action consumes budget before issuance:

```rust
fn issue_prefetch_read(extent, budget) -> Result<(), BudgetExhausted> {
    if extent.length > budget.remaining_data_bytes {
        return Err(BudgetExhausted);
    }
    budget.remaining_data_bytes -= extent.length;
    // issue read...
    Ok(())
}

fn issue_metadata_prefetch(action, budget) -> Result<(), BudgetExhausted> {
    if budget.remaining_meta_ops == 0 {
        return Err(BudgetExhausted);
    }
    budget.remaining_meta_ops -= 1;
    // issue metadata op...
    Ok(())
}
```

### 7.4 Interaction with Derived View Refresh Budget

Derived view refresh (#1240) and metadata prefetch share the `meta_cache`
budget category but are distinguished by priority:

- **Derived view refresh** runs at `LatencySensitive` priority in the
  background scheduler. It is correctness-adjacent (stale views degrade
  user-visible performance) and receives a larger budget share.
- **Pure metadata prefetch** runs at `Opportunistic` priority. It is purely
  speculative and receives budget only after derived view work is complete.

The resource governor does not need separate categories for these -- they
both consume `meta_cache` and are differentiated by `AdmissionPriority`.
The background scheduler's priority ordering ensures derived view refresh
completes before prefetch consumes remaining budget.

## 8. Background Scheduler Integration

### 8.1 Prefetch as a BackgroundService

The readahead engine implements the `BackgroundService` trait:

```rust
impl BackgroundService for PrefetchService {
    fn name(&self) -> &'static str { "prefetch" }

    fn priority(&self) -> ServicePriority {
        ServicePriority::Opportunistic
    }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        // 1. Iterate over active file handles with SequentialConfirmed or Streaming state
        // 2. For each handle, compute readahead window (capped by budget.max_authoritative_reads)
        // 3. Issue prefetch reads (capped by budget.max_derived_writes)
        // 4. Return TickReport with accounting
    }

    fn has_work(&self) -> bool {
        self.active_handles.len() > 0 && self.prefetch_budget.has_remaining()
    }
}
```

### 8.2 Scheduling Behavior

The scheduler always drains higher-priority services first. Within
`Opportunistic`, the readahead service competes with thermal rebalance and
other best-effort work via round-robin. Since prefetch uses
`AdmissionPriority::Low` for cache allocation, its allocations are always
evictable.

### 8.3 Demand Preemption

The FUSE main loop checks for demand operations before executing any
background tick. A single prefetch tick processes at most
`budget.max_authoritative_reads` extent-map lookups and issues at most
`budget.max_derived_writes` prefetch reads. This bounds the maximum time
spent in prefetch before returning to demand processing.

## 9. Transport Lane Model

### 9.1 Lane Assignment

Prefetch reads are assigned to the existing `LaneClass::Speculative` transport
lane (defined in `crates/tidefs-transport/src/lane_demux.rs`). This lane
carries the documented semantics of "shadow compare, warmup, advisory mirror,
non-blocking prefetch" -- may be dropped, reordered, or delayed without
correctness impact.

The transport lane model is the 5-lane multiplexer defined in
`tidefs-transport` (P8-01 Section 4):

| Lane | Priority | Used by | Behavior under congestion |
|------|----------|---------|--------------------------|
| `Control` | 0 | Membership, heartbeats, fence | Never throttled |
| `Metadata` | 1 | Log/progress metadata, receipts | Minimal throttling |
| `Demand` | 2 | Foreground demand fetches, FUSE replies | Prioritized |
| `Speculative` | 3 | Prefetch, warmup, shadow compare | Throttled before Demand |
| `Background` | 4 | Chunk shipping, rebuild, scrub | Dropped under congestion |

### 9.2 Speculative Lane Semantics

- Prefetch reads on `LaneClass::Speculative` are subject to backpressure
  via the `LaneBackpressure` high/low watermarks (default 16 MiB / 4 MiB).
  When the lane write queue exceeds `high_watermark`, the lane is paused
  and prefetch writes yield.
- Prefetch reads are never retried on failure. A dropped prefetch read
  consumes no retry budget.
- The transport layer may coalesce multiple prefetch reads into a single
  bulk transfer, but this is transparent to the prefetch engine.

## 10. Integration with RDMA Bulk-Plane Prefetch (#1229)

### 10.1 Separation of Concerns

RDMA bulk-plane prefetch (#1229) operates at the cluster transport layer:
it uses RDMA one-sided reads to pull extent data from remote nodes into
local memory, bypassing the remote CPU. This design document covers local
prefetch: what the daemon decides to read ahead based on access patterns.

These are complementary, not competing:

| Dimension | Local prefetch (this doc) | RDMA bulk-plane (#1229) |
|-----------|--------------------------|------------------------|
| Decision layer | FUSE daemon access history | Cluster placement planner |
| Transport | Speculative lane over any fabric | RDMA one-sided reads |
| Granularity | Per-file-handle sequential detection | Per-shard-group bulk migration |
| Budget | `data_cache` L2 budget | `cluster_queues` + bulk tokens |
| Trigger | Sequential read pattern in FUSE | Replica imbalance, migration planning |

### 10.2 Coordination Point

Both systems consume the same `data_cache` budget category and the same
governor. The coordination point is the `AdmissionPriority`:

- Local prefetch uses `Low` (priority 5).
- RDMA bulk-plane prefetch uses `Low` (priority 5).
- Both are evicted before L1 demand cache.

When both are active, the governor's budget partitioning ensures neither
starves the other: each consumes from `data_cache` with the same priority,
and the first to fill the L2 partition crowds out the other.

### 10.3 Anti-Duplication

A key efficiency concern is duplicate prefetch: the local prefetch engine
might issue a readahead for an extent that the RDMA bulk-plane is already
migrating. To prevent this:

- The extent map's `birth_commit_group` and the locator table's `locator_id` provide
  a stable content identity.
- Before issuing a local prefetch read, the engine checks whether the extent
  is already present in L1 or L2 (cache hit) or whether a bulk-plane
  transfer for that locator is in-flight.
- In-flight tracking is maintained in a short-lived `InFlightMap` keyed by
  `locator_id`, shared between the local prefetch engine and the bulk-plane
  coordinator.

## 11. Relationship to Workload Model

### 11.1 Workload Signatures as Prefetch Triggers

The workload signature framework (`docs/WORKLOAD_SIGNATURE_MATERIALIZATION_PLANE_LAW.md`)
provides the detection signal that activates and tunes prefetch:

| Signature class | Prefetch response |
|----------------|-------------------|
| `stream_seq.s1` | Activate data readahead for files in the detected stream set. Expand readahead window. Increase data prefetch budget multiplier. |
| `metadata_hotset.s0` | Activate directory pre-warm and stat-ahead for hot directories. Increase metadata prefetch budget multiplier. |
| `random_lowlat.s2` | Deactivate data readahead (random access benefits little from prefetch). Shift budget to metadata prefetch if metadata locality is detected. |
| `mixed_unknown.s7` | Conservative prefetch: small window, low budget. Prefer metadata prefetch over data prefetch. |

### 11.2 Prefetch as a Materialization-Plane Candidate

Prefetch actions are materialization-plane candidates with low utility scores
(product `p2.hotset_warmup` and `p5.stream_summary`). The workload model's
scoring function evaluates whether prefetch is worthwhile:

```rust
fn score_prefetch_candidate(signature, budget_state, pressure_state) -> Score {
    if pressure_state.backpressure_active || pressure_state.is_high() {
        return Score::Suppress;   // don't prefetch under pressure
    }

    let mut utility = 0.0;
    if signature.matches(stream_seq) {
        utility += 0.4;   // sequential streams benefit from readahead
    }
    if signature.matches(metadata_hotset) {
        utility += 0.3;   // metadata prefetch benefits hot directories
    }

    let cost = budget_state.prefetch_budget_consumed / budget_state.prefetch_budget_total;
    if cost > 0.8 {
        utility *= 0.5;   // diminishing returns when budget is nearly exhausted
    }

    Score::new(utility, cost)
}
```

When the utility score is below a configurable threshold, the workload model
may suppress prefetch entirely -- even when sequential access is detected.
This prevents prefetch from consuming resources when the predicted benefit
is too low.

### 11.3 Feedback Loop

The workload model's verify stage measures whether prefetch was actually useful:

- **Prefetch hit rate**: fraction of prefetched extents that were subsequently
  demanded.
- **Prefetch waste rate**: fraction of prefetched extents that were evicted
  without ever being demanded.
- **Budget efficiency**: useful prefetch bytes / total prefetch bytes issued.

If the waste rate exceeds `PREFETCH_WASTE_THRESHOLD` (default: 0.50), the
workload model reduces the prefetch budget multiplier for the next tick.
If the hit rate exceeds `PREFETCH_HIT_BOOST_THRESHOLD` (default: 0.70), the
multiplier is increased (up to a configurable ceiling).

## 12. Data Structures Summary

### 12.1 Per-Dataset Structures

```rust
struct DatasetPrefetchState {
    budget: PrefetchBudget,
    active_handles: HashMap<(u64, u64), AccessHistory>,
    stats: PrefetchStats,
}

struct PrefetchStats {
    prefetch_bytes_issued: u64,
    prefetch_hits: u64,        // times a prefetched extent was demanded
    prefetch_waste: u64,       // times a prefetched extent was evicted unused
    prefetch_suppressed: u64,  // times prefetch was suppressed (budget/pressure)
    metadata_prefetch_ops: u64,
    metadata_prefetch_hits: u64,
}
```

### 12.2 Global Structures

```rust
struct GlobalPrefetchState {
    in_flight_map: InFlightMap<LocatorId, PrefetchInFlight>,
    lane_tokens: SpeculativeLaneTokens,
}

struct PrefetchInFlight {
    locator_id: LocatorId,
    issued_tick: u64,
    source: PrefetchSource,
}

enum PrefetchSource {
    LocalReadahead,
    BulkPlane,
    MetadataPrefetch,
}
```

## 13. Adoption of Linux Kernel Readahead State Machine Concepts

### 13.1 Decision: Adopt the state machine, adapt the implementation

The Linux kernel's readahead state machine (`ondemand_readahead()` in
`mm/readahead.c`) provides a well-tested conceptual model:

- **State tracking**: `ra->start`, `ra->size`, `ra->async_size` (the readahead
  window).
- **Window expansion**: exponential growth (2x -> 4x -> 8x) with a cap
  (`ra->ra_pages`).
- **Random-access reset**: any non-sequential access resets the window.
- **Synchronous vs asynchronous**: the first page of a readahead batch is
  synchronous (demand), the rest are asynchronous (prefetch).

TideFS adopts these concepts with adaptations for userspace:

| Kernel concept | TideFS adaptation |
|---------------|-------------------|
| `file_ra_state` (per-struct-file) | `AccessHistory` (per-FUSE-file-handle) |
| `ra_pages` (per-backing-device cap) | `PrefetchBudget.max_data_bytes` (per-dataset, per-tick) |
| `ondemand_readahead()` | `compute_readahead_window()` |
| `page_cache_ra_order()` (folios, large folios) | Extent-aligned readahead (extents are the natural "large folio") |
| `->readahead()` folio contract | FUSE `FUSE_READ` with `Speculative` lane |
| Kernel page cache residency | L2 prefetch cache (ARC-based, separately evictable) |

### 13.2 What TideFS does NOT adopt

- **Kernel page cache integration**: TideFS is userspace; it cannot use the
  kernel's page cache for prefetch state. The L2 cache is the equivalent.
- **Mmap readahead**: The kernel can issue readahead on page faults; TideFS
  sees only `FUSE_READ` requests. Mmap-triggered prefetch requires kernel
  module integration (out of scope for this design).
- **`readahead()` syscall**: The user-facing `readahead(2)` syscall is
  forwarded to the FUSE daemon as a `FUSE_READ` and handled identically to
  any other read -- the access history treats it as a demand read (it does
  not trigger additional prefetch beyond what sequential detection would).

## 14. Configuration and Tuning

### 14.1 Pool-Level Properties

| Property | Default | Range | Description |
|----------|---------|-------|-------------|
| `prefetch.enabled` | `true` | bool | Master enable for all prefetch |
| `prefetch.data_budget_fraction` | `0.30` | 0.0-0.50 | Fraction of `data_cache` for L2 prefetch |
| `prefetch.meta_budget_fraction` | `0.20` | 0.0-0.40 | Fraction of `meta_cache` for metadata prefetch |
| `prefetch.idle_replenish_fraction` | `0.10` | 0.0-0.50 | Fraction of idle cycles that replenish prefetch budget |
| `prefetch.max_window_bytes` | `2 MiB` | 64 KiB-16 MiB | Maximum readahead window for streaming access |
| `prefetch.sequential_streak_threshold` | `4` | 2-16 | Consecutive reads to confirm sequential access |
| `prefetch.streaming_streak_threshold` | `16` | 8-64 | Consecutive reads to enter streaming mode |
| `prefetch.waste_suppress_threshold` | `0.50` | 0.0-1.0 | Waste rate above which prefetch is suppressed |
| `prefetch.history_ttl_ticks` | `600` | 60-3600 | Ticks before an idle access history is evicted |
| `prefetch.max_access_histories` | `4096` | 256-65536 | Maximum per-dataset access history entries |

### 14.2 Dynamic Tuning

All numeric properties are dynamically adjustable via the `control_plane` API
without daemon restart. The operator manual surface
(`docs/OPERATOR_MANUAL_DYNAMIC_TUNING_AND_REALTIME_OBSERVABILITY.md`)
exposes prefetch stats through the shared `truth_view`.

## 15. Observability

### 15.1 Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `prefetch.data_bytes_issued` | Counter | Total data bytes issued as prefetch |
| `prefetch.data_hits` | Counter | Times a prefetched extent was demanded |
| `prefetch.data_waste` | Counter | Times a prefetched extent was evicted unused |
| `prefetch.meta_ops_issued` | Counter | Total metadata prefetch operations issued |
| `prefetch.meta_hits` | Counter | Times a metadata-prefetched record was demanded |
| `prefetch.budget_exhausted` | Counter | Ticks where prefetch budget was fully consumed |
| `prefetch.suppressed_by_pressure` | Counter | Ticks where prefetch was suppressed by backpressure |
| `prefetch.active_handles` | Gauge | Number of file handles in SequentialConfirmed/Streaming state |
| `prefetch.window_bytes_mean` | Histogram | Mean readahead window size across active handles |
| `prefetch.l2_utilization` | Gauge | Current L2 prefetch cache fill ratio |

### 15.2 Traces

Each prefetch tick emits a `PrefetchTickTrace` to the deterministic trace
oracle:

```rust
struct PrefetchTickTrace {
    tick: u64,
    dataset_id: u64,
    handles_scanned: u32,
    extents_issued: u32,
    bytes_issued: u64,
    budget_remaining_data: u64,
    budget_remaining_meta: u64,
    suppressed: bool,
    suppression_reason: Option<SuppressionReason>,
}
```

### 15.3 Truth View Integration

The `truth_view` surface includes a `prefetch_summary` view showing:

- Active sequential streams with file identity, offset, streak count.
- Current budget state (data/meta, remaining/max).
- Rolling hit rate and waste rate.
- L2 cache residency and eviction rate.

## 16. Interaction Summary (Cross-Issue)

| Issue | Interaction with prefetch |
|-------|--------------------------|
| #1237 (resource governor) | Prefetch consumes `data_cache` L2 and `meta_cache` sub-budget. Uses `AdmissionPriority::Low`. |
| #1241 (background lanes) | Prefetch scheduled in `Opportunistic` stage. Never blocks demand. |
| #1240 (derived views) | View refresh doubles as metadata prefetch. Shares `meta_cache` budget. |
| #1229 (RDMA bulk-plane) | Both consume L2 data budget. Anti-duplication via `InFlightMap`. |
| #1179 (background scheduler) | Prefetch implements `BackgroundService` trait. |
| #1285 (extent maps) | Extent-map B-tree walk is the readahead lookahead mechanism. |
| #1225 (tristate extents) | Readahead skips HOLE extents. UNWRITTEN extents not prefetched. |
| workload_model_0 | Workload signatures activate/tune/suppress prefetch. Feedback loop adjusts budget. |
| adaptive_governor_0 | Idle-cycle ratio governs budget replenishment. Backpressure suppresses prefetch. |

## 17. Anti-Regression Rules

1. **No prefetch result may satisfy a correctness requirement.** If a demand
   read finds data only in L2, it must verify the extent's `birth_commit_group` against
   the current extent map before returning. Stale prefetched data causes a
   demand fallthrough, not a silent incorrect read.
2. **No prefetch read may occupy a demand queue slot.** The `Speculative`
   transport lane is a separate queue class.
3. **No metadata prefetch may claim enough budget to starve derived view
   refresh.** The scheduler's priority ordering (`LatencySensitive` > `Opportunistic`)
   enforces this.
4. **No prefetch may proceed under global backpressure.** `prefetch_budget`
   is zeroed when `governor_state.backpressure_active` is true.
5. **Every prefetch allocation must be evictable.** `AdmissionPriority::Low`
   ensures this. No prefetch entry may carry a pin or retention flag.

## 18. Design Decisions (Answered)

### 18.1 How does sequential access detection work across FUSE (no kernel page cache visibility)?

Per-FUSE-file-handle `AccessHistory` with a state machine (`Idle -> SequentialCandidate -> SequentialConfirmed -> Streaming`), using offset-based streak counting with slack for out-of-order reads. No kernel dependency.

### 18.2 Should the Rust implementation adopt Linux kernel readahead state machine concepts?

Yes. The state machine and window-expansion concepts are adopted. The implementation is adapted for userspace (per-handle state, extent-aligned windows, budget-constrained issuance).

### 18.3 How does RDMA bulk-plane prefetch (#1229) interact with local prefetch?

They share the L2 data budget and the same `AdmissionPriority::Low`. Anti-duplication via `InFlightMap` keyed by `locator_id`. The local prefetch engine checks for in-flight bulk-plane transfers before issuing a redundant local prefetch.

### 18.4 Budget interaction: how does prefetch budget relate to derived view refresh budget?

Both consume `meta_cache` budget but at different scheduler priorities (`LatencySensitive` for views, `Opportunistic` for prefetch). The scheduler's priority ordering ensures views are refreshed before prefetch consumes budget. Budget fractions are separately configurable.



1. **Design review**: This document against the v0.262 principles and
   anti-regression rules.
2. **Interface check**: The `BackgroundService` impl, `PrefetchBudget` struct,
   and `AccessHistory` state machine compile against the existing crate APIs.
3. **Integration test target**: A deterministic trace oracle test that replays
   a sequential read workload and asserts:
   - Sequential detection activates within 4 reads.
   - Readahead window size follows the multiplier policy.
   - Budget exhaustion suppresses prefetch correctly.
   - Prefetch hit promotion from L2 to L1 works.
   - Random access resets the state machine.
4. **Pressure test target**: A concurrent workload of demand reads + prefetch
   under memory pressure asserts that demand latency is not degraded by
   prefetch activity.

---

*This document is a design-spec. Implementation work is tracked in separate
Forgejo issues scoped to the crate boundaries identified in the workload
signature materialization plane law and the scheduling contracts in the
background service framework design.*
