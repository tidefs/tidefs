# Background Service Framework Phases 5–10 Wire-Up Tracking (#1946)

> Previously tracked under #1877 / #1935. This document is the canonical
> wire-up tracking specification for phases 5–10 of the TideFS unified
> background service framework.

Maturity: **design-spec**. Rust implementation deferred to wire-up issues.

This document is the wire-up tracking specification for phases 5–10 of the TideFS
unified background service framework. It defines the architecture, data structures,
references the canonical design-spec at
[`docs/design/background-service-framework-design-spec.md`](background-service-framework-design-spec.md)
(#1713) and the canonical scheduler design at
[`docs/design/background-service-framework-design.md`](background-service-framework-design.md)
(#1592, #1674).

**Source context:** lane `coordination`, kind `design`.

## 1. Scope and Relationship to Canonical Spec

The canonical design-spec (#1713) defines the full 16-phase roadmap. Phases 1–4
are implemented in `tidefs-background-scheduler`, `tidefs-types-incremental-job-core`,
`tidefs-cleanup-job-core`, `tidefs-reclaim-job-core`, `tidefs-orphan-recovery-job-core`,
and `tidefs-local-filesystem`. This document tracks the wire-up of phases 5–10:

| Phase | Scope | Dependencies |
|-------|-------|--------------|
| **Phase 5: View builder** | `ViewBuilderService`, derived catalog build/serve/evict/compact | Phases 1–4 |
| **Phase 6: Data cleaner** | `DataCleanerService` processing refcount delta queues | Phases 1–4 |
| **Phase 7: Segment cleaner** | `SegmentCleanerService` reclaiming dead segments | Phases 1–4 |
| **Phase 8: FUSE integration** | Wire scheduler into FUSE daemon main loop with demand preemption | Phases 1–4 |
| **Phase 9: Compaction** | `CompactionService` for derived catalog and refcount B-tree | Phases 5–6 |

Each phase produces one or more wire-up Forgejo issues that implement the Rust code
as specified in the canonical design. This document adds phase-specific details not
covered in the canonical spec: concrete crate scaffolding, per-phase data structures,
integration algorithms, and per-phase tradeoffs.

## 2. Phase 5: View Builder Service

### 2.1 Purpose

The `ViewBuilderService` maintains derived catalog views: cached directory entries,
sorted index views, and polymorphic directory index structures. It wraps an
`IncrementalJob` that walks the authoritative directory B-tree, rebuilds stale
derived views, serves in-memory cached entries, evicts cold entries under memory
pressure, and compacts fragmented index pages.

### 2.2 Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    ViewBuilderService                         │
│  Priority: LatencySensitive                                  │
│                                                              │
│  ┌─────────────────────┐    ┌─────────────────────────────┐ │
│  │   Build Phase        │    │   Maintenance Phase          │ │
│  │   (cold start/       │    │   (incremental, per-tick)   │ │
│  │    cache miss)       │    │                              │ │
│  │                      │    │  ┌───────────────────────┐  │ │
│  │  Walk authoritative  │    │  │ Evict cold entries    │  │ │
│  │  dir B-tree          │───▶│  │ Compact index pages   │  │ │
│  │  Populate view cache │    │  │ Rebuild stale views   │  │ │
│  └─────────────────────┘    │  │ Serve lookup queries   │  │ │
│                              │  └───────────────────────┘  │ │
│                              └─────────────────────────────┘ │
│                                                              │
│  Crate: tidefs-derived-catalog (new)                         │
│  Depends on: tidefs-dir-index, tidefs-btree,                 │
│              tidefs-types-incremental-job-core,              │
│              tidefs-incremental-job-core                     │
└──────────────────────────────────────────────────────────────┘
```

### 2.3 Key Data Structures

```rust
/// A single derived catalog view entry.
///
/// Each entry represents a cached directory listing or index page
/// that can be served without walking the authoritative B-tree.
pub struct ViewEntry {
    /// Parent directory inode.
    pub dir_inode: u64,
    /// Opaque cursor into the authoritative B-tree for this view.
    pub btree_cursor: Vec<u8>,
    /// Sorted list of directory entries in this view page.
    pub entries: Vec<DirEntryProjection>,
    /// Monotonic generation number; incremented when the authoritative
    /// B-tree changes and the view is rebuilt.
    pub generation: u64,
    /// Last-access timestamp for eviction decisions.
    pub last_access_ms: u64,
    /// Whether this view is currently being rebuilt.
    pub rebuilding: bool,
}

/// Projection of a directory entry into a derived view.
pub struct DirEntryProjection {
    pub name_hash: u64,
    pub inode: u64,
    pub entry_type: DirEntryType,
}

/// Statistics for the view builder service.
pub struct ViewBuilderStats {
    /// Number of cached view entries.
    pub cached_views: u64,
    /// Number of views rebuilt this cycle.
    pub views_rebuilt: u64,
    /// Number of views evicted this cycle.
    pub views_evicted: u64,
    /// Number of lookup hits served from cache.
    pub cache_hits: u64,
    /// Number of lookup misses requiring authoritative walk.
    pub cache_misses: u64,
}
```

### 2.4 Tick Algorithm

```
ViewBuilderService::tick(budget):
    1. If cold_start:
       a. Load persisted view cache if available.
       b. If no persisted cache, mark all views as stale.
       c. Set cold_start = false.
    2. Evict phase (up to 25% of budget):
       a. Scan view cache for entries with last_access_ms < eviction_threshold.
       b. Remove up to budget.max_items / 4 entries.
    3. Rebuild phase (remaining budget):
       a. Scan authoritative B-tree for entries with generation mismatch.
       b. For each stale view, re-read directory entries from B-tree.
       c. Update generation and last_access_ms.
       d. Stop when budget exhausted or no more stale views.
    4. Compact phase (if budget remains):
       a. Merge fragmented index pages.
       b. Return TickReport with has_more = (stale views remain || pages fragmented).
```

### 2.5 Tradeoffs

| Decision | Option A | Option B | Chosen | Rationale |
|----------|----------|----------|--------|-----------|
| Eviction policy | LRU with TTL | Fixed-size ring buffer | LRU with TTL | Better cache hit rate under skewed workloads; bounded memory with TTL safety net |
| Rebuild granularity | Per-directory | Per-index-page | Per-index-page | Smaller work units fit within tick budgets; less fragmentation |
| Priority assignment | LatencySensitive | Throughput | LatencySensitive | Cache misses directly increase user-facing lookup latency |

### 2.6 Wire-Up Issue Template

- Crate: `tidefs-derived-catalog` (new)
- Implements: `IncrementalJob` for `ViewBuilderService`
- Registers: `BackgroundScheduler::register(ViewBuilderService)`
- Tests: Unit tests for eviction, rebuild, compaction; deterministic replay test
- Gate: `cargo test -p tidefs-derived-catalog`

## 3. Phase 6: Data Cleaner Service

### 3.1 Purpose

The `DataCleanerService` processes refcount delta queues produced by deferred
cleanup operations. It reads pending deltas from the per-dataset cleanup B+tree,
applies them to the authoritative refcount table, and marks items complete.
This is the Phase 2 of two-phase deletion: Phase 1 enqueues `CleanupWorkItemV1`
entries synchronously; Phase 2 (this service) processes them asynchronously
under a `WorkBudget`.

### 3.2 Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    DataCleanerService                         │
│  Priority: Throughput                                        │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  Tick: process refcount delta queue                      │ │
│  │                                                          │ │
│  │  1. Dequeue N items from cleanup B+tree                  │ │
│  │  2. For each item:                                       │ │
│  │     a. Check birth_commit_group for staleness                     │ │
│  │     b. Iterate extents via extent map                    │ │
│  │     c. Produce refcount deltas into ReclaimQueue         │ │
│  │     d. Mark item complete in cleanup B+tree              │ │
│  │  3. Return TickReport                                    │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  Crate: tidefs-data-cleaner (new)                            │
│  Depends on: tidefs-cleanup-queue-core,                      │
│              tidefs-reclaim-queue-core,                      │
│              tidefs-extent-map,                              │
│              tidefs-types-incremental-job-core,              │
│              tidefs-incremental-job-core                     │
└──────────────────────────────────────────────────────────────┘
```

### 3.3 Key Data Structures

```rust
/// Per-dataset state for the data cleaner.
pub struct DataCleanerState {
    /// Dataset identifier.
    pub dataset_id: u64,
    /// Cursor position in the cleanup B+tree (opaque bytes).
    pub cursor: Vec<u8>,
    /// Items processed since last reset.
    pub items_processed: u64,
    /// Bytes freed since last reset.
    pub bytes_freed: u64,
    /// Errors encountered since last reset.
    pub errors: u64,
}

/// A single refcount delta produced by the cleaner.
pub struct RefcountDelta {
    /// Block identifier.
    pub block_id: u64,
    /// Delta value (negative for freeing, positive for re-referencing).
    pub delta: i64,
    /// Transaction group when this delta was produced.
    pub birth_commit_group: u64,
}

/// Connection to the reclaim queue for downstream processing.
pub struct ReclaimQueueSink {
    /// Pending deltas waiting to be consumed by the reclaim service.
    pub pending: Vec<RefcountDelta>,
    /// Maximum queue depth before backpressure.
    pub max_depth: usize,
}
```

### 3.4 Tick Algorithm

```
DataCleanerService::tick(budget):
    1. Load cursor from checkpoint.
    2. while budget.not_exhausted():
       a. Dequeue next item from cleanup B+tree at cursor.
       b. If no item: break (queue drained).
       c. If item.birth_commit_group < dataset.min_active_commit_group: skip (stale).
       d. Iterate extents for item.inode.
       e. For each extent:
          - Produce RefcountDelta { block_id, delta: -1, birth_commit_group }.
          - Push to ReclaimQueueSink.
          - Increment bytes_freed.
       f. Mark item complete.
       g. Advance cursor.
       h. Update budget counters.
    3. Persist checkpoint (cursor + stats).
    4. Return TickReport.
```

### 3.5 Tradeoffs

| Decision | Option A | Option B | Chosen | Rationale |
|----------|----------|----------|--------|-----------|
| Batch size | Large batches (1024 items) | Small batches (64 items) | Budget-driven (1024 default) | Budget enforcement provides natural batching; tick budget caps resource use |
| Staleness check | Per-item birth_commit_group | Global min_commit_group scan | Per-item | Finer-grained; stale items can be skipped individually without blocking the cursor |
| Delta enqueue | Direct refcount update | Queue to reclaim service | Queue to reclaim service | Decouples cleaner throughput from refcount B-tree write latency |
| Priority assignment | Throughput | LatencySensitive | Throughput | Cleanup is bulk work; latency-insensitive as long as queue doesn't overflow |

### 3.6 Wire-Up Issue Template

- Crate: `tidefs-data-cleaner` (new)
- Implements: `IncrementalJob` for `DataCleanerService`
- Registers: `BackgroundScheduler::register(DataCleanerService)`
- Tests: Unit tests for dequeue, extent iteration, delta production, staleness; integration test with cleanup queue
- Gate: `cargo test -p tidefs-data-cleaner`

## 4. Phase 7: Segment Cleaner Service

### 4.1 Purpose

The `SegmentCleanerService` reclaims dead segments from the on-media format.
When spacemap allocation frees blocks, the segment containing those blocks
accumulates dead space. The cleaner identifies segments with high dead-space
ratios, relocates live data, and returns the segment to the free pool.

### 4.2 Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    SegmentCleanerService                      │
│  Priority: BestEffort                                        │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  Tick: reclaim dead segments                             │ │
│  │                                                          │ │
│  │  1. Scan spacemap for segments above dead threshold      │ │
│  │  2. For each candidate segment:                          │ │
│  │     a. Read segment header and block bitmap              │ │
│  │     b. Identify live blocks                              │ │
│  │     c. Relocate live blocks to new segments              │ │
│  │     d. Update extent maps for relocated blocks           │ │
│  │     e. Mark segment free in spacemap                     │ │
│  │  3. Return TickReport                                    │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  Crate: tidefs-segment-cleaner (new)                         │
│  Depends on: tidefs-spacemap-allocator,                      │
│              tidefs-space-accounting,                        │
│              tidefs-extent-map,                              │
│              tidefs-types-incremental-job-core,              │
│              tidefs-incremental-job-core                     │
└──────────────────────────────────────────────────────────────┘
```

### 4.3 Key Data Structures

```rust
/// Candidate segment for cleaning.
pub struct CleaningCandidate {
    /// Segment identifier.
    pub segment_id: u64,
    /// Total blocks in segment.
    pub total_blocks: u64,
    /// Number of live blocks.
    pub live_blocks: u64,
    /// Dead-space ratio (0.0 = all live, 1.0 = all dead).
    pub dead_ratio: f64,
    /// Estimated cost to relocate (bytes).
    pub relocation_cost: u64,
    /// Estimated benefit (bytes freed).
    pub benefit_bytes: u64,
}

/// Thresholds for triggering segment cleaning.
pub struct CleaningThresholds {
    /// Minimum dead-space ratio to consider a segment (default: 0.20).
    pub min_dead_ratio: f64,
    /// Preferred dead-space ratio target (default: 0.50).
    pub target_dead_ratio: f64,
    /// Maximum segments to clean per tick.
    pub max_segments_per_tick: u64,
    /// Minimum benefit/cost ratio to proceed (default: 2.0).
    pub min_benefit_cost_ratio: f64,
}

/// Statistics for the segment cleaner.
pub struct SegmentCleanerStats {
    pub segments_scanned: u64,
    pub segments_cleaned: u64,
    pub blocks_relocated: u64,
    pub bytes_freed: u64,
    pub write_amplification: f64,
}
```

### 4.4 Tick Algorithm

```
SegmentCleanerService::tick(budget):
    1. Load cursor (last scanned segment_id).
    2. while budget.not_exhausted():
       a. Scan spacemap for next segment_id > cursor.
       b. If no more segments: wrap cursor to 0, set has_more = false, break.
       c. Compute dead_ratio from spacemap counters.
       d. If dead_ratio < thresholds.min_dead_ratio:
          - Advance cursor, continue.
       e. Compute benefit_cost_ratio.
       f. If benefit_cost_ratio < thresholds.min_benefit_cost_ratio:
          - Advance cursor, continue.
       g. Read segment bitmap.
       h. For each live block:
          - Allocate new block from spacemap.
          - Copy data from old block to new block.
          - Update extent map entry.
          - Update budget counters.
       i. Mark old segment free in spacemap.
       j. Increment segments_cleaned.
       k. Advance cursor.
    3. Persist checkpoint.
    4. Return TickReport.
```

### 4.5 Tradeoffs

| Decision | Option A | Option B | Chosen | Rationale |
|----------|----------|----------|--------|-----------|
| Cleaning trigger | Time-based (every N seconds) | Space-based (dead ratio threshold) | Space-based | More efficient; cleans only when beneficial |
| Relocation strategy | Copy all live blocks | Copy only when benefit/cost > 2 | Benefit/cost ratio | Avoids write amplification for barely-dead segments |
| Cursor wrap | Reset to 0 on wrap | Random restart point | Sequential with wrap | Deterministic for replay; predictable scan pattern |
| Priority assignment | BestEffort | Throughput | BestEffort | Cleaning is important but deferrable; starvation prevention ensures progress |

### 4.6 Wire-Up Issue Template

- Crate: `tidefs-segment-cleaner` (new)
- Implements: `IncrementalJob` for `SegmentCleanerService`
- Registers: `BackgroundScheduler::register(SegmentCleanerService)`
- Tests: Unit tests for candidate selection, relocation, spacemap update; integration test with allocator
- Gate: `cargo test -p tidefs-segment-cleaner`

## 5. Phase 8: FUSE Integration

### 5.1 Purpose

Wire the `BackgroundScheduler` into the FUSE daemon main event loop. The scheduler
must run background ticks between FUSE demand operations without starving foreground
traffic. Demand preemption ensures that when a FUSE request arrives, the background
cycle yields within a bounded deadline.

### 5.2 Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     FUSE Daemon Main Loop                         │
│                                                                  │
│  loop:                                                           │
│    ┌──────────────────────────────────────────────────────────┐ │
│    │ 1. Pre-cycle                                             │ │
│    │    budget = compute_background_budget(demand_pressure)   │ │
│    │    BackgroundScheduler::plan_cycle(budget)               │ │
│    │    BackgroundScheduler::dispatch_cycle()                 │ │
│    └──────────────────────────────────────────────────────────┘ │
│                              │                                   │
│                              ▼                                   │
│    ┌──────────────────────────────────────────────────────────┐ │
│    │ 2. Interleaved phase (while workers run)                 │ │
│    │    loop:                                                 │ │
│    │      if FUSE request pending:                            │ │
│    │        handle_fuse_request()                             │ │
│    │      elif cycle_deadline_reached():                      │ │
│    │        break                                             │ │
│    │      else:                                               │ │
│    │        poll with short timeout                           │ │
│    └──────────────────────────────────────────────────────────┘ │
│                              │                                   │
│                              ▼                                   │
│    ┌──────────────────────────────────────────────────────────┐ │
│    │ 3. Collect phase                                         │ │
│    │    report = BackgroundScheduler::collect_cycle()         │ │
│    │    emit_observability(report)                            │ │
│    └──────────────────────────────────────────────────────────┘ │
│                              │                                   │
│                              ▼                                   │
│    ┌──────────────────────────────────────────────────────────┐ │
│    │ 4. Demand-only phase                                     │ │
│    │    if demand_pressure > HIGH_THRESHOLD:                  │ │
│    │        skip next cycle entirely                         │ │
│    │    handle_remaining_fuse_requests()                      │ │
│    └──────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### 5.3 Key Data Structures

```rust
/// Configuration for FUSE integration of the background scheduler.
pub struct FuseBackgroundConfig {
    /// Target cycle interval in milliseconds (default: 100).
    pub cycle_interval_ms: u64,
    /// Maximum cycle duration in milliseconds (default: 50).
    pub cycle_deadline_ms: u64,
    /// FUSE poll timeout when waiting for work (default: 5ms).
    pub poll_timeout_ms: u64,
    /// Demand pressure threshold above which background cycles are skipped.
    pub high_pressure_threshold: f64,
    /// Whether to run background work at all.
    pub enabled: bool,
}

/// Runtime state for the FUSE background integration.
pub struct FuseBackgroundRuntime {
    /// The background scheduler instance.
    pub scheduler: BackgroundScheduler,
    /// Current demand pressure gauge (0.0–1.0).
    pub demand_pressure: f64,
    /// Last cycle start timestamp.
    pub last_cycle_ms: u64,
    /// Cumulative background cycles run.
    pub cycles_run: u64,
    /// Cumulative cycles skipped due to demand pressure.
    pub cycles_skipped: u64,
}
```

### 5.4 Budget Computation Algorithm

```
compute_background_budget(demand_pressure, config):
    base_budget = ServiceBudget::DEFAULT_TICK  // 1024 items, 64 MiB, 100 ms

    // Demand pressure shrinks the effective budget.
    if demand_pressure < 0.3:
        effective = base_budget                    // Plenty of headroom
    elif demand_pressure < 0.6:
        effective = ServiceBudget::MAINTENANCE_TICK // Reduced: 256 items, 16 MiB, 50 ms
    elif demand_pressure < 0.9:
        effective = ServiceBudget::SMALL_TICK       // Minimal: 64 items, 4 MiB, 25 ms
    else:
        effective = ServiceBudget::PAUSED           // Extreme pressure: no background work

    // Critical services always get at least a minimal budget.
    effective.critical_grace = ServiceBudget::SMALL_TICK

    return effective
```

### 5.5 Tradeoffs

| Decision | Option A | Option B | Chosen | Rationale |
|----------|----------|----------|--------|-----------|
| Scheduling model | Dedicated background thread | Inline on FUSE event loop | Inline on FUSE event loop | Simpler; avoids synchronization complexity; dedicated thread deferred to Phase 16 |
| Demand preemption | Interrupt mid-tick | Wait for tick completion | Wait for tick completion | Ticks are bounded (<100ms); mid-tick preemption adds rollback complexity |
| Cycle trigger | Timer-based (every N ms) | Demand-gap-based (run when idle) | Hybrid: timer with demand skip | Ensures background progress even under moderate load; skips under high load |
| Budget scaling | Linear with pressure | Step function | Step function (4 levels) | Simpler to reason about; avoids oscillation |

### 5.6 Wire-Up Issue Template

- Module: `apps/tidefs-posix-filesystem-adapter-daemon/src/runtime` (modify)
- Modifies: FUSE daemon main loop to call `BackgroundScheduler`
- Adds: `FuseBackgroundConfig`, `FuseBackgroundRuntime`, budget computation
- Tests: Integration test with mock FUSE channel; demand-pressure simulation
- Gate: `cargo test -p tidefs-posix-filesystem-adapter-daemon`

## 6. Phase 9: Compaction Service

### 6.1 Purpose

The `CompactionService` merges fragmented B-tree nodes in the derived catalog
B-tree and the refcount B-tree. Over time, insertions and deletions create
partially-filled internal and leaf nodes. Compaction reduces tree depth,
improves scan locality, and reclaims dead space within B-tree pages.

### 6.2 Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    CompactionService                          │
│  Priority: BestEffort                                        │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  Tick: compact B-tree nodes                              │ │
│  │                                                          │ │
│  │  1. Select target B-tree (derived catalog or refcount)   │ │
│  │  2. Scan B-tree for underfilled nodes                    │ │
│  │  3. For each underfilled node:                           │ │
│  │     a. Merge with sibling if combined size fits          │ │
│  │     b. Or redistribute entries from fuller sibling       │ │
│  │     c. Update parent pointers                            │ │
│  │     d. Free emptied nodes                                │ │
│  │  4. Return TickReport                                    │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  Crate: tidefs-compaction (new)                              │
│  Depends on: tidefs-btree, tidefs-derived-catalog (Phase 5), │
│              tidefs-types-incremental-job-core,              │
│              tidefs-incremental-job-core                     │
└──────────────────────────────────────────────────────────────┘
```

### 6.3 Key Data Structures

```rust
/// Target B-tree for compaction.
pub enum CompactionTarget {
    /// Compact the derived catalog directory index B-tree.
    DerivedCatalog,
    /// Compact the refcount B-tree.
    RefcountBTree,
}

/// Statistics for a compaction pass.
pub struct CompactionStats {
    /// Nodes scanned this tick.
    pub nodes_scanned: u64,
    /// Nodes merged this tick.
    pub nodes_merged: u64,
    /// Nodes freed this tick.
    pub nodes_freed: u64,
    /// Bytes reclaimed this tick.
    pub bytes_reclaimed: u64,
    /// Average fill ratio before compaction.
    pub avg_fill_before: f64,
    /// Average fill ratio after compaction.
    pub avg_fill_after: f64,
}

/// Thresholds for triggering compaction.
pub struct CompactionThresholds {
    /// Minimum fill ratio to consider a node underfilled (default: 0.40).
    pub min_fill_ratio: f64,
    /// Target fill ratio after compaction (default: 0.70).
    pub target_fill_ratio: f64,
    /// Minimum number of nodes that must be underfilled to trigger a pass.
    pub min_underfilled_nodes: u64,
}

/// Cursor for interleaved compaction across multiple trees.
pub struct CompactionCursor {
    /// Current target B-tree.
    pub target: CompactionTarget,
    /// Opaque cursor position within the current target.
    pub position: Vec<u8>,
    /// Round-robin counter for fair interleaving.
    pub round: u64,
}
```

### 6.4 Tick Algorithm

```
CompactionService::tick(budget):
    1. Load cursor (target B-tree + position).
    2. if no underfilled nodes exceed thresholds.min_underfilled_nodes:
       a. Return TickReport { has_more: false }.
    3. while budget.not_exhausted():
       a. Scan B-tree from cursor.position.
       b. Find next underfilled node (fill_ratio < thresholds.min_fill_ratio).
       c. If no more underfilled nodes in current target:
          - Switch to next CompactionTarget (round-robin).
          - Reset position.
          - Continue.
       d. If no underfilled nodes in any target: break.
       e. Attempt merge with left sibling.
       f. If merge not possible, attempt merge with right sibling.
       g. If neither merge possible, redistribute from fuller sibling.
       h. Update parent pointers.
       i. Free emptied node if merge emptied it.
       j. Advance cursor.
       k. Update budget counters.
    4. Persist checkpoint.
    5. Return TickReport.
```

### 6.5 Tradeoffs

| Decision | Option A | Option B | Chosen | Rationale |
|----------|----------|----------|--------|-----------|
| Compaction scope | Full tree compaction | Incremental node-at-a-time | Incremental | Fits within tick budget; avoids long stalls |
| Target selection | Always derived catalog first | Round-robin | Round-robin | Fairness; prevents one tree from monopolizing compaction |
| Merge vs redistribute | Always merge when possible | Merge only when >50% space saved | Merge when fill < 0.25, redistribute at 0.25-0.40 | Balances write cost against space savings |
| Priority assignment | BestEffort | Throughput | BestEffort | Compaction is important for long-term performance but latency-insensitive |

### 6.6 Wire-Up Issue Template

- Crate: `tidefs-compaction` (new)
- Implements: `IncrementalJob` for `CompactionService`
- Registers: `BackgroundScheduler::register(CompactionService)`
- Depends on: Phase 5 (derived catalog) and Phase 6 (data cleaner) for B-tree access
- Tests: Unit tests for merge, redistribute, round-robin; integration test with B-tree
- Gate: `cargo test -p tidefs-compaction`


### 7.1 Purpose

the correctness of the entire background service framework across all implemented

1. **Type consistency**: All `ServicePriority`, `ServiceBudget`, `TickReport`,
   `CycleReport` types match the canonical design.
2. **Budget enforcement**: No service exceeds its per-tick budget.
3. **Priority ordering**: Higher-priority services always dispatch before
   lower-priority ones.
4. **Round-robin fairness**: Within each priority stage, services alternate.
5. **Budget cascading**: Unused budget from higher stages cascades to lower stages.
6. **Deterministic replay**: Given identical state and budget, two cycles produce
   identical `CycleReport`s.
7. **Crash consistency**: After a simulated crash at any tick boundary, services
   resume correctly from their last checkpoint.
8. **Starvation prevention**: BestEffort services are force-ticked after
   `starvation_timeout_ms`.

### 7.2 Architecture

```
┌──────────────────────────────────────────────────────────────┐
│           xtask check-background-service-framework            │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  1. Type Consistency Check                               │ │
│  │     - Verify ServicePriority discriminant order          │ │
│  │     - Verify ServiceBudget constants match spec          │ │
│  │     - Verify TickReport fields match spec                │ │
│  │     - Verify CycleReport aggregates correctly            │ │
│  └─────────────────────────────────────────────────────────┘ │
│                              │                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  2. Budget Enforcement Tests                             │ │
│  │     - Single service, DEFAULT_TICK budget                │ │
│  │     - Assert items_consumed <= max_items                 │ │
│  │     - Assert bytes_consumed <= max_bytes                 │ │
│  │     - Assert ms_elapsed <= max_ms (soft bound)           │ │
│  └─────────────────────────────────────────────────────────┘ │
│                              │                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  3. Priority Ordering Tests                              │ │
│  │     - Register services at all five priorities           │ │
│  │     - All services report has_more = true                │ │
│  │     - Assert tick dispatch order is Critical →           │ │
│  │       LatencySensitive → Throughput →                    │ │
│  │       BestEffort → Opportunistic                         │ │
│  └─────────────────────────────────────────────────────────┘ │
│                              │                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  4. Round-Robin Fairness Tests                           │ │
│  │     - Register three Throughput services                 │ │
│  │     - Run multiple cycles                                │ │
│  │     - Assert tick counts differ by at most 1             │ │
│  └─────────────────────────────────────────────────────────┘ │
│                              │                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  5. Budget Cascading Tests                               │ │
│  │     - Register one Critical service (uses 20% budget)    │ │
│  │     - Register one LatencySensitive service              │ │
│  │     - Assert LatencySensitive receives unused 80% of     │ │
│  │       Critical budget as extra allocation                │ │
│  └─────────────────────────────────────────────────────────┘ │
│                              │                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  6. Deterministic Replay Tests                           │ │
│  │     - Run a cycle, capture CycleReport A                 │ │
│  │     - Reset state, run same cycle again                  │ │
│  │     - Assert CycleReport B == CycleReport A              │ │
│  └─────────────────────────────────────────────────────────┘ │
│                              │                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  7. Crash Consistency Tests                              │ │
│  │     - Run tick partial completion                        │ │
│  │     - Simulate crash at tick boundary                    │ │
│  │     - Resume from checkpoint                             │ │
│  │     - Assert no duplicate processing                     │ │
│  │     - Assert no missed items                             │ │
│  └─────────────────────────────────────────────────────────┘ │
│                              │                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  8. Starvation Prevention Tests                          │ │
│  │     - Register BestEffort service                        │ │
│  │     - Run cycles with all higher-priority services       │ │
│  │       reporting has_more = true                          │ │
│  │     - Assert BestEffort is force-ticked after            │ │
│  │       starvation_timeout_ms                              │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

### 7.3 Key Data Structures

```rust
    /// Whether all checks passed.
    pub passed: bool,
    /// Individual check results.
    pub checks: Vec<CheckResult>,
    /// Total checks run.
    pub total_checks: usize,
    /// Checks that failed.
    pub failures: usize,
}

pub struct CheckResult {
    /// Check name (e.g., "budget-enforcement", "priority-ordering").
    pub name: &'static str,
    /// Whether the check passed.
    pub passed: bool,
    /// Failure detail if check failed.
    pub detail: Option<String>,
    /// Wall-clock duration of the check.
    pub duration_ms: u64,
}

///
/// A minimal `IncrementalJob` implementation that simulates
/// work for a configurable number of items with configurable
/// resource consumption, used to exercise all scheduler
/// invariants.
    pub name: &'static str,
    pub priority: ServicePriority,
    pub items_to_process: u64,
    pub bytes_per_item: u64,
    pub ms_per_item: u64,
    pub items_processed: u64,
    pub has_more: bool,
    pub error_on_tick: bool,
}
```


```

    // 1. Type consistency
    report.add(check_type_consistency())

    // 2. Budget enforcement
    report.add(check_budget_enforcement_items())
    report.add(check_budget_enforcement_bytes())
    report.add(check_budget_enforcement_time())

    // 3. Priority ordering
    report.add(check_priority_dispatch_order())

    // 4. Round-robin fairness
    report.add(check_round_robin_fairness())

    // 5. Budget cascading
    report.add(check_budget_cascading())

    // 6. Deterministic replay
    report.add(check_deterministic_replay())

    // 7. Crash consistency
    report.add(check_crash_consistency())

    // 8. Starvation prevention
    report.add(check_starvation_prevention())

    // PHASE-SPECIFIC CHECKS (gated on feature flags)
    if cfg!(feature = "phase5-view-builder"):
        report.add(check_view_builder_service())
    if cfg!(feature = "phase6-data-cleaner"):
        report.add(check_data_cleaner_service())
    if cfg!(feature = "phase7-segment-cleaner"):
        report.add(check_segment_cleaner_service())
    if cfg!(feature = "phase8-fuse-integration"):
        report.add(check_fuse_integration())
    if cfg!(feature = "phase9-compaction"):
        report.add(check_compaction_service())

    report.passed = report.failures == 0
    return report
```

### 7.5 Tradeoffs

| Decision | Option A | Option B | Chosen | Rationale |
|----------|----------|----------|--------|-----------|
| Test framework | Custom test harness | Reuse `#[test]` with common setup | Custom harness with `#[test]` wrappers | xtask provides a single entry point; individual checks can also run as unit tests |
| Mock services | Real services with mock I/O | Pure mock implementations | Pure mock implementations | Deterministic; no filesystem dependency; faster |
| Report format | JSON | Human-readable text | JSON + human-readable summary | Machine-parseable for CI; human-readable for operator inspection |

### 7.6 Wire-Up Issue Template

- Crate: `tidefs-xtask` (new) with `check-background-service-framework` subcommand
- Gate: `cargo xtask check-background-service-framework` (self-test)

## 8. Cross-Phase Dependencies

```
Phase 5 ─────────────────────────────────────────────┐
  ViewBuilderService                                  │
  (tidefs-derived-catalog)                            │
        │                                             │
        │  provides derived catalog B-tree access     │
        ▼                                             │
Phase 9 ─────────────────────────────────────────────┤
  CompactionService                                   │
  (tidefs-compaction)                                 │
        │                                             │
        │  compacts refcount B-tree from Phase 6      │
        ▼                                             │
Phase 6 ─────────────────────────────────────────────┤
  DataCleanerService                                  │
  (tidefs-data-cleaner)                               │
        │                                             │
        │  uses cleanup-queue-core                    │
        │  feeds reclaim-queue-core                   │
        ▼                                             │
Phase 7 ─────────────────────────────────────────────┤
  SegmentCleanerService                               │
  (tidefs-segment-cleaner)                            │
        │                                             │
        │  uses spacemap-allocator                    │
        │  uses extent-map                            │
        ▼                                             │
Phase 8 ─────────────────────────────────────────────┘
  FUSE Integration
  (`apps/tidefs-posix-filesystem-adapter-daemon/src/runtime`)

Phase 10 ─────────────────────────────────────────────
  (tidefs-xtask check-background-service-framework)
  Depends on all phases 1–9
```

### 8.1 Dependency Ordering for Implementation

```
   P5 (View Builder) ──┐
                       ├──▶ P9 (Compaction) ──┐
   P6 (Data Cleaner) ──┤                      │
   P7 (Segment Cleaner)┤                      │
                       │                      │
   P8 (FUSE Integration)──────────────────────┘
```

Phases 5, 6, 7, and 8 are independent and can be implemented in parallel.
Phase 9 depends on Phases 5 and 6 for B-tree access. Phase 10 depends on
all phases 1–9.

## 9. Integration Contracts

### 9.1 Service Registration

Every phase 5–9 service registers with the `BackgroundScheduler` using the
same pattern established in Phases 1–4:

```rust
// Phase 5 example
let view_builder = IncrementalJobAdapter::new(
    ViewBuilderService::resume(checkpoint)?,
    ServicePriority::LatencySensitive,
);
scheduler.register("view-builder", view_builder)?;
```

### 9.2 Checkpoint Persistence

Each service persists its cursor via the `IncrementalJob::persist_checkpoint()`
contract. The checkpoint format follows the `CheckpointCodec` trait from
`tidefs-incremental-job-core`:

```rust
pub trait CheckpointCodec {
    fn encode(&self, checkpoint: &Checkpoint) -> Result<Vec<u8>, JobError>;
    fn decode(&self, data: &[u8]) -> Result<Checkpoint, JobError>;
}
```

### 9.3 Observability Contract

Every service emits `TickReport` per tick and contributes to `CycleReport`.
The FUSE integration (Phase 8) is responsible for surfacing these reports
through the operator CLI and observability pipeline.

### 9.4 Determinism Contract

All services must be deterministic: given the same state and `ServiceBudget`,
`tick()` must produce the same `TickReport`. This enables the deterministic
replay tests in Phase 10.

## 10. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Phase 6 (Data Cleaner) queue overflow | Low | Medium | Backpressure from reclaim queue depth; tick budget ensures steady drain |
| Phase 7 (Segment Cleaner) write amplification | Medium | Medium | Benefit/cost ratio threshold; adaptive cleaning thresholds |
| Phase 8 (FUSE) demand starvation | Medium | High | Demand preemption with bounded deadline; skip cycles under high pressure |
| Phase 9 (Compaction) merge conflicts with foreground B-tree ops | Low | Low | B-tree locking granularity is per-node; compaction locks only siblings |

## 11. References

- [#1713] Definitive consolidated background service framework design spec
- [#1592] Canonical design specification (Phase 1–4 implementation)
- [#1674] Design specification closure
- [#1624] Enhanced design: lifecycle, starvation, backpressure, CLI, replay
- [#1625] Multi-threaded work-stealing design
- [#1673] Background service framework design enhanced — canonical design-spec
- [#1179] Initial background service framework design
- [#1176] Cached directory/index views
- [#1180] Refcount delta cleanup queues
- [#1215] Space accounting and cleaner scheduling
- [#1241] Unified lane scheduling model
- [#1223] Polymorphic extent maps
- [#1617] Unified scheduling classes and lane priority model
- [#1619] Deferred cleanup work queues design
- [#1620] IncrementalJob core trait and CheckpointCodec design
- `docs/design/background-service-framework-design-spec.md` — canonical spec (#1713)
- `docs/design/background-service-framework-design.md` — scheduler design (#1592/#1674)
- `docs/design/background-service-framework-design-enhanced.md` — enhanced design (#1624)
- `docs/design/background-service-framework-multithread-design.md` — multithread design (#1625)
- `docs/design/deferred-cleanup-work-queues.md` — cleanup queue design (#1619)
- `docs/design/incremental-job-core-trait-checkpoint-codec-design.md` — IncrementalJob trait (#1620)
- `docs/design/unified-scheduling-classes-lane-priority-model.md` — lane scheduling (#1617)
- `crates/tidefs-background-scheduler/src/lib.rs` — scheduler implementation (1410 lines)
- `crates/tidefs-types-incremental-job-core/src/lib.rs` — IncrementalJob types
- `crates/tidefs-incremental-job-core/src/lib.rs` — IncrementalJob trait + CheckpointCodec
- `crates/tidefs-cleanup-job-core/src/lib.rs` — CleanupJob implementation
- `crates/tidefs-reclaim-job-core/src/lib.rs` — ReclaimJob implementation
- `crates/tidefs-orphan-recovery-job-core/src/lib.rs` — OrphanRecoveryJob implementation
