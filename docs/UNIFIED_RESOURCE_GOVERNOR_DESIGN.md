# Unified Resource Governor Design

Maturity: **design-spec** for the single budget authority that merges the
6-level cache hierarchy (#1226) with the daemon memory budget model (#1211)
into one resource governor enforcing admission, eviction, and backpressure
across all daemon-side memory categories.

This document closes Forgejo issue #1237 and supersedes/unifies #1226 and #1211.

## Claim Boundary

The ZFS and Ceph material in this document is a design comparison and
architecture target, not a present-tense performance, memory-efficiency, or
operator-cost claim. Product-facing statements that TideFS is better, faster,
more predictable, lower cost, or safer than an incumbent require the #928
comparator-evidence fields, the #850 performance-budget rows, and the #875
claim boundary for the exact workload, cache state, media, and failure mode.

## 1. Motivation

The current design corpus defines cache architecture and memory budgeting as
two separate concerns:

- #1226: 6-level cache hierarchy with budget domains and pressure eviction ladder
- #1211: Daemon memory budget model with categories, eviction ladder, and InodeState lifetime

These describe the same system from different angles. #1226 focuses on what
caches exist and how they interact; #1211 focuses on how to bound and pressure
them. Keeping them separate risks:

- Duplicated budget category definitions diverging over time
- Eviction ladder not matching cache priority levels
- Observability split between "cache stats" and "budget stats"
- Admission paths that bypass budget enforcement

The v0.262 Python reference design explicitly treats these as one system: cache
admission is budget allocation; cache eviction is budget reclaim; backpressure
is the unified overflow valve.

## 2. Design Overview

The unified resource governor is a single authority controlling all daemon-side
memory. Its core invariant:

> Every byte allocated by the daemon is tagged with exactly one budget category.
> Every cache admission is a budget allocation. Every eviction is a budget reclaim.
> Backpressure is the mechanism that prevents unbounded admission when reclaim
> cannot keep up.

The governor exposes two primary interfaces:

| Interface | Direction | Purpose |
|-----------|-----------|---------|
| `Governor::admit(category, size)` | Caller → Governor | Request memory allocation for a cache entry or buffer |
| `Governor::release(category, size)` | Caller → Governor | Return memory to the budget pool after eviction or flush |

Internally, the governor maintains per-category watermarks, a unified eviction
ladder, and backpressure signals that feed into the FUSE admission throttle
and cluster transport admission control.

### 2.1 Relationship to the Background Service Framework (#1179)

The eviction ladder and backpressure machinery execute as budgeted background
service ticks within the `BackgroundScheduler`. The governor itself is not a
service — it is the authority that services consult for admission decisions.
Eviction work triggered by governor pressure is dispatched to the `DataCleaner`
and `SegmentCleaner` services.

## 3. Budget Categories

### 3.1 Unified Budget Namespace

One authority controls all daemon-side memory. The total daemon budget is
partitioned into six categories:

```
budget_total = data_cache + meta_cache + dirty_bytes + inode_state + cluster_queues + misc
```

| Category | Default % | Contains | Eviction Strategy |
|----------|-----------|----------|-------------------|
| `data_cache` | 40% | Hot read cache (L1: extent payloads), prefetch cache (L2: speculative read-ahead) | ARC-based eviction; prefetch evicted before hot |
| `dirty_bytes` | 25% | Write-combining buffers not yet flushed to extent storage (L5) | Never evicted — flushed instead |
| `inode_state` | 8% | Per-inode state: locks, open handles, dirty buffer metadata, extent decode state, validity tokens | LRU eviction of clean state; dirty state flushed first |
| `cluster_queues` | 5% | Inflight cluster RPC frames, dedup windows, bulk transfer tokens (L6) | Backpressure instead of eviction |
| `misc` | 2% | Unallocated safety buffer for internal allocations, FUSE reply buffers, temporary crypto state | Never evicted (bounded by design) |

### 3.2 Cache Level to Budget Category Mapping

Every cache level from #1226 maps to exactly one budget category:

| #1226 Cache Level | Budget Category | Admission Priority | Eviction Order | What Lives Here |
|---|---|---|---|---|
| L1: Hot read cache | `data_cache` | 3 (normal) | Last to evict | Frequently-read extent payloads (ARC hot) |
| L2: Prefetch cache | `data_cache` | 5 (lowest) | First to evict | Speculative read-ahead (ARC warm) |
| L3: Decoded B+tree nodes | `meta_cache` | 2 (high) | High retention | B+tree interior/leaf nodes, inode records |
| L4: Decoded xattrs/dirs | `meta_cache` | 2 (high) | High retention | Xattr payloads, directory entry views, name cache |
| L5: Dirty writeback buffers | `dirty_bytes` | 1 (must-admit) | Never evicted (flushed) | Write-combining buffers, pending commit_group aggregates |
| L6: Cluster inflight buffers | `cluster_queues` | 4 (throttled) | Backpressure | RPC frames, dedup windows, bulk tokens |

### 3.3 Per-Category Watermarks

Each category defines three watermarks, expressed as fractions of the category's
budget cap:

| Watermark | Default | Action |
|-----------|---------|--------|
| `ADMIT_FREELY` | 0.0 – 0.70 | Admit without question |
| `EVICT_SOFT` | 0.70 – 0.85 | Admit but trigger background eviction within the category |
| `EVICT_HARD` | 0.85 – 0.95 | Admit only after synchronous eviction frees space |
| `REJECT` | 0.95+ | Reject admission; escalate to global backpressure |

The `dirty_bytes` category replaces `EVICT_SOFT` and `EVICT_HARD` with flush
thresholds:

| Watermark | Default | Action |
|-----------|---------|--------|
| `FLUSH_BACKGROUND` | 0.50 | Trigger background flush via writeback service |
| `FLUSH_SYNC` | 0.70 | Block admission until flush completes |
| `FORCE_COMMIT_GROUP_SYNC` | 0.85 | Force a transaction group boundary; escalate to backpressure |

### 3.4 Category Configuration

Categories are configured at daemon startup via `ResourceGovernorConfig`:

```rust
pub struct ResourceGovernorConfig {
    /// Total daemon memory budget in bytes.
    /// Default: 60% of host physical RAM, clamped to [256 MiB, 256 GiB].
    pub total_budget_bytes: u64,

    /// Per-category fractions. Must sum to 1.0.
    pub data_cache_fraction: f64,       // default: 0.40
    pub meta_cache_fraction: f64,       // default: 0.20
    pub dirty_bytes_fraction: f64,      // default: 0.25
    pub inode_state_fraction: f64,      // default: 0.08
    pub cluster_queues_fraction: f64,   // default: 0.05
    pub misc_fraction: f64,             // default: 0.02

    /// Whether to auto-tune fractions based on workload signals.
    pub auto_tune: bool,                // default: false (operator opt-in)
}
```

## 4. Admission Control

### 4.1 Admission Algorithm

Every cache entry allocation must pass through `Governor::admit()`:

```rust
impl ResourceGovernor {
    /// Request admission of `size` bytes into `category`.
    ///
    /// Returns `AdmissionResult::Granted` if the allocation is within budget,
    /// or `AdmissionResult::Rejected(reason)` if the budget is exhausted and
    /// eviction cannot free enough space.
    pub fn admit(&self, category: BudgetCategory, size: u64,
                 priority: AdmissionPriority) -> AdmissionResult;
}
```

Algorithm:
1. Compute current utilization ratio for the category: `used / cap`
2. If `util < soft_threshold`: return `Granted` immediately
3. If `util >= soft_threshold` but `< hard_threshold`: return `Granted` but set the category's `eviction_needed` flag (background eviction will run on next tick)
4. If `util >= hard_threshold`: attempt synchronous eviction of `size` bytes within the category; if successful, return `Granted`; otherwise, escalate
5. If eviction cannot free enough and the category is at `REJECT`: return `Rejected` with an `AdmissionReason` that the caller uses to trigger backpressure

### 4.2 Admission Priority

Callers provide an `AdmissionPriority` that controls how the governor treats the
request under pressure:

```rust
pub enum AdmissionPriority {
    /// Must succeed for correctness. Block until admitted (with a configurable
    /// timeout). Used by: dirty buffer admission (L5), FUSE reply buffers.
    /// If blocked for longer than `CRITICAL_ADMIT_TIMEOUT_MS`, the governor
    /// escalates to global backpressure and retries.
    Critical,

    /// Important for latency but can be deferred. Returns AdmissionResult::
    /// Deferred if the category is under pressure; caller retries later.
    /// Used by: B+tree node admission (L3), directory entry views (L4).
    High,

    /// Normal priority. Evictable under soft pressure.
    /// Used by: hot data cache (L1).
    Normal,

    /// Low priority. First to be evicted under any pressure.
    /// Used by: prefetch cache (L2).
    Low,
}
```

### 4.3 Release Path

Every eviction, flush, or explicit drop must call `Governor::release()`:

```rust
impl ResourceGovernor {
    pub fn release(&self, category: BudgetCategory, size: u64);
}
```

The release path is lock-free (atomic counter decrement) to avoid contention
on the hot eviction path. The governor periodically reconciles atomic counters
against actual memory usage via a background reconciliation tick.

## 5. Eviction Ladder

### 5.1 Unified Eviction Ladder

When memory pressure rises, the governor escalates through a unified ladder
that replaces the separate ladders from #1226 and #1211:

| Stage | Trigger | Action | Escalation Condition |
|-------|---------|--------|---------------------|
| 1: Evict cold cache | Any category at `EVICT_SOFT` | Drop L2 prefetch entries; ARC-evict cold L1 and L3/L4 entries up to the soft threshold | Pressure persists for > 1 tick |
| 2: Shrink metadata caches | `meta_cache` still at `EVICT_SOFT` after stage 1 | ARC-evict warm entries from L3/L4; shrink B+tree node cache; evict least-recently-used xattr payloads | Pressure persists for > 2 ticks |
| 3: Flush dirty data | `dirty_bytes` at `FLUSH_BACKGROUND` | Trigger writeback coalescing and extent flush for oldest commit_group buffers | Pressure persists for > 1 tick |
| 4: Force commit_group sync | `dirty_bytes` at `FORCE_COMMIT_GROUP_SYNC` | Force a transaction group commit boundary; drain all dirty buffers to stable storage | N/A — immediate |
| 5: Apply backpressure | Any category at `REJECT` or cumulative pressure > `GLOBAL_BACKPRESSURE_THRESHOLD` | Throttle FUSE request admission; shrink cluster transport windows; block new mutating ops | Backpressure is the terminal state |

### 5.2 Eviction Ladder Execution Model

The ladder is not a single monolithic function. Each stage is dispatched by the
`BackgroundScheduler` (#1179) as a budgeted tick:

- Stage 1-2 eviction: dispatched as `CacheMaintenance` service ticks (priority: `LatencySensitive`)
- Stage 3 flush: dispatched as `WritebackFlush` service ticks (priority: `Throughput`)
- Stage 4 commit_group sync: executed inline by the commit_group commit path (priority: `Critical`)
- Stage 5 backpressure: applied at admission boundary (not a background tick)

This ensures the eviction ladder is observable, budgeted, and cannot starve
foreground I/O.

### 5.3 Stale-State Prevention with Validity Tokens

Per-inode cache state is protected by `ValidityToken` from #1179. When a cache
from authoritative storage. This prevents use-after-eviction bugs without
requiring synchronous coordination between eviction and demand I/O paths.

## 6. Backpressure and Throttling

### 6.1 Backpressure Architecture

Backpressure is the terminal stage of the eviction ladder. It is not an eviction
mechanism — it is an admission gate that prevents new work from entering when
the system cannot keep up with existing work.

The governor maintains a global backpressure counter `backpressure_level`:

| Level | Trigger | Action |
|-------|---------|--------|
| `None` | All categories below hard thresholds | Normal operation |
| `Mild` | One category in `REJECT` state | Throttle FUSE admission: reduce concurrent request cap by 50% |
| `Moderate` | Two categories in `REJECT` or `dirty_bytes` at `FORCE_COMMIT_GROUP_SYNC` | Block all new mutating FUSE ops (`write`, `mkdir`, `unlink`, etc.); reads still admitted |
| `Severe` | Three+ categories in `REJECT` or cumulative utilization > 98% | Block all FUSE admission; flush all inflight work; trigger emergency commit_group sync |

### 6.2 FUSE Admission Throttle

The FUSE daemon's request admission loop consults the governor before accepting
each new kernel request:

```rust
// In the FUSE daemon event loop:
let admission = governor.check_fuse_admission(op_category(&req));
match admission {
    FuseAdmission::Accepted => { /* process normally */ }
    FuseAdmission::Throttled { delay_ms } => {
        fuse_session.receive_with_timeout(delay_ms)?;
    }
    FuseAdmission::Blocked => {
        reply_error(req, libc::ENOMEM)?;
    }
}
```

The `op_category()` classifier maps FUSE operations to budget categories:

| FUSE Op Class | Budget Category | Admission Priority |
|---------------|-----------------|-------------------|
| Read (`FUSE_READ`) | `data_cache` | `Normal` |
| Write (`FUSE_WRITE`) | `dirty_bytes` | `Critical` (must buffer) |
| Metadata read (`LOOKUP`, `GETATTR`, `READDIR`) | `meta_cache` | `High` |
| Metadata mutate (`MKDIR`, `CREATE`, `UNLINK`) | `meta_cache` + `dirty_bytes` | `Critical` |
| Xattr ops | `meta_cache` | `High` |
| Inactive/forget (`FORGET`, `RELEASE`) | `inode_state` | Release path (free) |

### 6.3 Cluster Transport Backpressure

The `cluster_queues` category does not use normal eviction — it uses backpressure
to bound inflight cluster traffic. When `cluster_queues` reaches `REJECT`:

- The transport layer stops accepting new `Offer` messages from peers
- Inflight `Credit` windows are shrunk by 50%
- Bulk transfer tokens are revoked until utilization drops below `EVICT_HARD`

This integrates with the BULK protocol (#1229) by mapping `cluster_queues`
utilization to `BULK_ADMIT_WINDOW` sizing.

## 7. InodeState Lifetime Management

### 7.1 Per-Inode State Budget

The `inode_state` category tracks all per-inode allocations: lock objects,
open handles, dirty buffer metadata, extent decode state, and validity tokens.
It is capped at `8%` of total daemon budget by default.

### 7.2 Reference Counting


- `lookup_refs`: incremented on `LOOKUP` reply; decremented on `FORGET`/`BATCH_FORGET`
- `open_refs`: incremented on `OPEN`/`OPENDIR`; decremented on `RELEASE`/`RELEASEDIR`

State is **evictable** when all are true:
- `lookup_refs == 0`
- `open_refs == 0`
- No active byte-range locks (POSIX or OFD)
- No dirty buffered data pending flush

### 7.3 Eviction Policy

When `inode_state` reaches `EVICT_SOFT`:
1. Scan the LRU for evictable entries (reference counts at zero, no locks, clean)
2. Drop cached extent decode state, negative name caches, access-time metadata
3. Retain lock state and dirty buffer metadata (these are correctness-critical)
4. If still over budget after scanning: apply FUSE_NOTIFY_PRUNE for candidate inodes

### 7.4 FUSE_NOTIFY_PRUNE Integration

The governor may proactively ask the kernel to drop dentry/inode caches via
`FUSE_NOTIFY_PRUNE`, enabling the kernel to emit `FORGET` and freeing InodeState:

- Candidates must satisfy: `open_refs == 0`, no dirty buffers, no active locks
- `lookup_refs` may be nonzero (the prune asks the kernel to drop lookups)
- Best-effort: the kernel may skip inodes with pinned references
- Rate-limited: at most `MAX_PRUNE_CANDIDATES_PER_TICK` (default: 128)
- Never used for correctness — only as a pressure valve

## 8. Observability Unification

### 8.1 Single Observability Surface

The governor exposes a unified observability command, replacing the separate
cache stats and budget stats from the dual-issue model:

```
$ tidefsctl memory
Total daemon budget:  4.0 GiB  (60% of 6.7 GiB host RAM)
  auto-tune:          off

  data_cache:         1.6 GiB / 1.6 GiB (100%)  — 128K admits, 95K evictions
    hot (L1):         1.2 GiB                     42K entries, hit rate 94.2%
    prefetch (L2):    400 MiB                     86K entries, hit rate 12.1%
  meta_cache:         680 MiB / 819 MiB (83%)     — 245K admits, 45K evictions
    btree (L3):       420 MiB                     18K nodes
    xattr/dir (L4):   260 MiB                     31K entries
  dirty_bytes:        512 MiB / 1.0 GiB (50%)      — 42K buffers, 3 commit_groups pending
    oldest commit_group:       commit_group-78412 (1.2s ago)
  inode_state:        180 MiB / 327 MiB (55%)      — 18K inodes, 340 locks
    evictable:        12K (66%)
    prune_candidates: 84 sent, 72 acknowledged
  cluster_queues:     82 MiB / 204 MiB (40%)       — 1.2K frames, 4 bulk tokens
  misc:               52 MiB / 81 MiB  (64%)

Backpressure level:   None
Time in backpressure: 0.0s (last 60s)
Eviction pressure:    0.12 (0.0 = idle, 1.0 = all categories at REJECT)
```

### 8.2 Counter Schema

The governor exposes the following counter hierarchy:

```
tidefs_governor_category_used_bytes{category="data_cache|meta_cache|..."}  gauge
tidefs_governor_category_cap_bytes{category}                               gauge
tidefs_governor_admits_total{category, priority, result}                   counter
tidefs_governor_releases_total{category}                                   counter
tidefs_governor_evictions_total{category, stage}                           counter
tidefs_governor_backpressure_level                                         gauge (0-3)
tidefs_governor_backpressure_duration_seconds_total                        counter
tidefs_governor_inode_state_evictable_count                                gauge
tidefs_governor_prune_candidates_sent_total                                counter
tidefs_governor_prune_candidates_acked_total                               counter
```

## 9. Integration Contracts

### 9.1 Integration with #1176 (Cache-Lattice Views)

Cache-lattice views define *what* each cache level guarantees (completeness
contracts). The resource governor defines *how much* memory each level gets and
*when* entries are evicted. The contract is:

- Each cache level registers its budget category with the governor at startup
- Admission of a view entry calls `governor.admit(category, size, priority)`
- View eviction callbacks are registered: `governor.on_evict(category, callback)`
- The governor never evicts entries that are pinned by an active view contract

### 9.2 Integration with #1179 (Background Services)

The eviction ladder stages are dispatched as background service ticks:

| Ladder Stage | Background Service | Priority |
|---|---|---|
| Evict cold cache (stage 1-2) | `CacheMaintenanceService` | `LatencySensitive` |
| Flush dirty data (stage 3) | `WritebackFlushService` | `Throughput` |
| Force commit_group sync (stage 4) | Inline in commit_group commit path | `Critical` |
| Backpressure (stage 5) | Not a service — admission gate | N/A |

### 9.3 Integration with #1192 (Weighted ARC)

The unified governor does not reimplement eviction algorithms. It delegates to
the weighted ARC cache (#1192) for L1-L4 eviction decisions. The contract is:

- Governor tells ARC: "evict N bytes from data_cache"
- ARC selects victim entries based on its weighted LRU/LFU policy
- ARC calls `governor.release(data_cache, freed_bytes)` after eviction
- Governor monitors whether ARC freed enough; if not, escalates the ladder

### 9.4 Integration with #1229 (BULK Protocol)

The `cluster_queues` budget category directly gates BULK admission:

```rust
impl BulkAdmissionControl {
    fn can_admit(&self, governor: &ResourceGovernor, size: u64) -> bool {
        let util = governor.category_utilization(BudgetCategory::ClusterQueues);
        if util > governor.hard_threshold(BudgetCategory::ClusterQueues) {
            return false; // backpressure: reject bulk offer
        }
        governor.admit(BudgetCategory::ClusterQueues, size, AdmissionPriority::Normal)
            .is_granted()
    }
}
```

### 9.5 Integration with #1215 (Space Accounting)

The governor does not track on-disk space — that is the domain of
`DatasetSpaceCountersV1` and `PoolPhysicalCountersV1`. However, the governor
shares the pressure-coupling interface: when free segment count drops below
the cleaner watermark (#1215), the space accounting layer pushes a pressure
signal into the governor, raising `backpressure_level` to throttle writes
before hitting ENOSPC.

## 10. ZFS and Ceph Design Lessons

| Dimension | ZFS | Ceph | tidefs Unified Governor |
|-----------|-----|------|------------------------|
| **Memory budget model** | `zfs_arc_max` (ARC only). No unified memory budget across ARC, ZIL, dedup table, and object_node cache. Each subsystem manages its own memory independently. | `osd_memory_target` (OSD bluestore cache). Separate caches for OSD map, monitor store, and MDS. No cross-subsystem budget authority. | Single `ResourceGovernor` with 6 categories, unified watermarks, and cross-category eviction ladder. Every byte is tagged and tracked. |
| **Eviction coordination** | ARC shrinker callback (`arc_shrinker_count`/`arc_shrinker_scan`) triggered by kernel MM. ZIL and object_node caches evict independently. | Bluestore cache has onode and buffer caches; no coordinated eviction between OSD memory and MDS memory. Per-daemon silos. | Unified eviction ladder: stage 1→2→3→4→5 escalates across all categories. Eviction is dispatched as budgeted background service ticks, not ad-hoc callbacks. |
| **Backpressure mechanism** | ZFS write throttle (`zfs_write_limit_override`): delays transaction group sync if dirty data exceeds a fraction of available memory. Only throttles writes, not reads or metadata ops. | Ceph OSD backoff (`osd_op_queue_cut_off`): rejects operations when queue depth exceeds threshold. No memory-pressure-aware backpressure. | Multi-level backpressure: Mild→Moderate→Severe with escalating admission restrictions across FUSE reads, FUSE mutations, and cluster transport. Backpressure is proportional to governor pressure level, not queue depth. |
| **Inode/dentry eviction** | Kernel VFS controls dentry/inode eviction via LRU. ZFS does not participate in userspace cache eviction (it's in-kernel). | CephFS MDS maintains its own dentry cache; kernel VFS maintains a separate cache. No coordination between the two. | `FUSE_NOTIFY_PRUNE` integration: governor selects evictable inodes, requests kernel to drop dentries, recovers `InodeState` memory. Bounded LRU per category prevents unbounded growth. |
| **Observability** | `arc_summary`, `arcstat` (ARC only). ZIL stats in `/proc/spl/kstat/zfs/zil`. Dedup stats in separate kstat. No unified memory view. | `ceph daemon osd.N perf dump` (per-daemon). `ceph df` (cluster-level). No unified per-node memory budget view. | Single `tidefsctl memory` command: per-category utilization, hit rates, eviction counts, backpressure level, pressure trend. Prometheus-compatible counter schema. |
| **Admission priority model** | Single class: all ARC inserts compete equally. Demand vs. prefetch is implicit (MRU vs. MFU ghost lists). | OSD op priorities (admin→high→normal→low) affect queue ordering but not memory admission. | Explicit 4-level `AdmissionPriority` (Critical/High/Normal/Low) at every admission point. Critical ops block until admitted; Low ops are deferred or rejected under soft pressure. |
| **Dirty data bounding** | `zfs_dirty_data_max`: hard cap on dirty data; commit_group sync triggered when reached. No proportional backpressure — system stalls until sync completes. | Bluestore `bluestore_cache_size` limits onode/buffer cache. No explicit dirty data cap. | Staged flush thresholds: `FLUSH_BACKGROUND` (50%) starts background writeback, `FLUSH_SYNC` (70%) blocks admission, `FORCE_COMMIT_GROUP_SYNC` (85%) forces commit_group boundary. Proportional backpressure reduces admission rate smoothly rather than hitting a hard cliff. |
| **Auto-tuning** | ARC size can be adjusted dynamically via module parameter. `zfs_arc_max` rewrite takes effect immediately. No workload-signal auto-tuning. | `osd_memory_target` is static per config file. No auto-tuning. | Optional `auto_tune` mode targets category-fraction adjustment from workload signals (read/write ratio, metadata intensity, cluster traffic volume). Operator opt-in, bounded by safety margins. |

### 10.1 Target Design Differences From ZFS

- **Single budget authority**: ZFS has ARC, ZIL, dedup, and object_node caches each
  managing memory independently. tidefs targets one governor for all six
  categories with cross-category pressure escalation.
- **Proportional backpressure**: ZFS write throttling behavior is a design input.
  tidefs targets graduated backpressure (Mild→Severe) with admission-rate
  reduction before a terminal commit-group fence.
- **FUSE-aware eviction**: ZFS (in-kernel) relies on kernel VFS for eviction.
  tidefs targets kernel coordination through `FUSE_NOTIFY_PRUNE` to recover
  userspace `InodeState` memory when the FUSE implementation proves that path.
- **Admission priority classes**: ZFS ARC treats all inserts equally. tidefs
  targets four explicit priority classes that control admission under pressure.

### 10.2 Target Design Differences From Ceph

- **Cross-subsystem budget**: Ceph OSD, MDS, and monitor each manage memory
  independently. tidefs targets a single-node single-governor model.
- **Unified observability**: Ceph requires multiple `ceph daemon ... perf dump`
  invocations to get a partial picture. tidefs targets a `tidefsctl memory`
  view that reports per-node category state from one authority.
- **Eviction as budgeted background work**: Ceph eviction behavior is a design
  input. tidefs targets `BackgroundScheduler` dispatch with per-tick operation
  budgets so foreground starvation remains a gateable outcome rather than an
  asserted property.

### 10.3 Shared Design Inputs

- **ARC-based eviction**: tidefs delegates L1-L4 eviction to the weighted ARC
  from #1192, borrowing the ARC design lesson without claiming incumbent
  parity until workload and comparator evidence exist.
- **Dirty data cap**: Both ZFS and tidefs enforce a hard cap on dirty data
  with commit_group sync as the terminal escape valve. tidefs adds graduated thresholds.
- **Operator-configurable budgets**: Both ZFS (`zfs_arc_max`) and tidefs
  (`ResourceGovernorConfig`) allow operator tuning of memory limits.

## 11. Implementation Plan

### Phase 1: Core Types and Constants
Implement `BudgetCategory`, `AdmissionPriority`, `AdmissionResult`, `AdmissionReason`,
`BackpressureLevel`, `ResourceGovernorConfig`, and all watermark constants in
`crates/tidefs-resource-governor-types/` (new crate). Pure data types, no I/O.

### Phase 2: Governor State Machine
Implement `ResourceGovernor` struct: per-category watermarks, atomic utilization
counters, admission/release paths, category utilization queries. Unit tests for
boundary conditions at each watermark threshold.

### Phase 3: Eviction Ladder
Implement `EvictionLadder` with the 5-stage escalation algorithm. Each stage is
dispatched as a background service tick. Tests for ladder progression and regression.

### Phase 4: Backpressure Propagation
Implement `BackpressureController` with `check_fuse_admission()` and cluster
transport admission gating. Tests for backpressure level transitions.

### Phase 5: FUSE Integration
Wire `governor.check_fuse_admission()` into the FUSE daemon request admission loop.
Implement `op_category()` classifier and `FUSE_NOTIFY_PRUNE` candidate selection.

### Phase 6: Cache Integration
Integrate governor admission calls into L1-L4 cache entry points (ARC insert path,
B+tree node decode, xattr decode, directory view build). Wire release calls into
ARC eviction callback. Register eviction callbacks per cache level.

### Phase 7: Observability
Implement unified counter hierarchy, `tidefsctl memory` command, and Prometheus-
compatible gauge/counter emission.

### Phase 8: InodeState Lifecycle
Implement `InodeState` eviction with LRU, reference-count tracking, and
`FUSE_NOTIFY_PRUNE` integration. Tests for eviction safety.

### Phase 9: Auto-Tuning
Implement workload signal capture and periodic fraction rebalancing. Bounded by
safety margins (±20% of configured fractions).

Full integration test: simulate multi-category memory pressure, verify ladder
progression, backpressure activation, and recovery to idle state.
Gate: `tidefs-xtask check-resource-governor`.

## 12. Deterministic Constraint Knobs

| Constant | Default | Meaning |
|----------|---------|---------|
| `TOTAL_BUDGET_HOST_RAM_FRACTION` | 0.60 | Fraction of host RAM allocated to daemon |
| `TOTAL_BUDGET_MIN_BYTES` | 256 MiB | Minimum daemon memory budget |
| `TOTAL_BUDGET_MAX_BYTES` | 256 GiB | Maximum daemon memory budget |
| `ADMIT_FREELY_THRESHOLD` | 0.70 | Utilization below which admission is always granted |
| `EVICT_SOFT_THRESHOLD` | 0.85 | Utilization triggering background eviction |
| `EVICT_HARD_THRESHOLD` | 0.95 | Utilization requiring synchronous eviction |
| `FLUSH_BACKGROUND_THRESHOLD` | 0.50 | Dirty bytes ratio triggering background flush |
| `FLUSH_SYNC_THRESHOLD` | 0.70 | Dirty bytes ratio requiring synchronous flush |
| `FORCE_COMMIT_GROUP_SYNC_THRESHOLD` | 0.85 | Dirty bytes ratio forcing commit_group boundary |
| `BACKPRESSURE_MILD_UTIL` | 0.95 | Single-category utilization triggering mild backpressure |
| `BACKPRESSURE_MODERATE_UTIL` | 0.98 | Multi-category utilization triggering moderate backpressure |
| `BACKPRESSURE_SEVERE_UTIL` | 0.995 | Cumulative utilization triggering severe backpressure |
| `CRITICAL_ADMIT_TIMEOUT_MS` | 5000 | Max wait for Critical-priority admission |
| `MAX_PRUNE_CANDIDATES_PER_TICK` | 128 | Max FUSE_NOTIFY_PRUNE candidates per tick |
| `EVICTION_LADDER_TICK_INTERVAL_MS` | 100 | Min interval between eviction ladder ticks |
| `RECONCILIATION_INTERVAL_MS` | 5000 | Interval for atomic-counter reconciliation |
| `AUTO_TUNE_INTERVAL_MS` | 30000 | Interval for workload-signal-based auto-tuning |
| `AUTO_TUNE_MAX_FRACTION_SHIFT` | 0.20 | Maximum per-category fraction adjustment |

## 13. Error Hierarchy

```rust
pub enum GovernorError {
    /// Admission was rejected because the category is at REJECT level.
    AdmissionRejected {
        category: BudgetCategory,
        requested_bytes: u64,
        utilization: f64,
        reason: AdmissionReason,
    },

    /// A Critical-priority admission timed out.
    AdmissionTimeout {
        category: BudgetCategory,
        requested_bytes: u64,
        waited_ms: u64,
    },

    InvalidConfiguration {
        reason: String,
    },

    /// An eviction callback failed, leaving the category over budget.
    EvictionFailed {
        category: BudgetCategory,
        target_bytes: u64,
        freed_bytes: u64,
        error: String,
    },
}

pub enum AdmissionReason {
    /// Category is at REJECT level.
    CategoryAtReject { category: BudgetCategory, utilization: f64 },
    /// Global backpressure is active and this priority is blocked.
    GlobalBackpressure { level: BackpressureLevel },
    /// Dirty bytes at FORCE_COMMIT_GROUP_SYNC; commit_group commit in progress.
    CommitGroupSyncInProgress { dirty_bytes: u64, cap: u64 },
}
```

## 14. Performance Correctness Contract Slice

Issue #287 makes local performance a correctness contract before it becomes a
throughput claim. The first implementation authority is
`crates/tidefs-performance-contract`, a `no_std` crate whose core types define:

- `WorkClass` and `ResourceDomain` labels for foreground, background, and
  dirty-debt work;
- `AdmissionPermit` as the must-use token that conserves dirty byte and
  operation debt;
- `BudgetedQueue` as the alloc-backed queue shape that cannot accept dirty
  items without an admission permit;
- `ServiceCurve` as the per-class service envelope used by deterministic
  foreground-read/scrub oracle checks;
- `WriteAdmissionConfig` and `WriteAdmissionState` as the hard local dirty
  byte/op/age admission envelope.

Dynamic tuning may lower or reshape soft limits, but it must not raise the hard
dirty byte, dirty operation, dirty age, permit, or queue-slot caps. The contract
is intentionally conservative: once the oldest dirty permit ages over the cap,
new dirty admissions fail until dirty debt is released.

Queue roots that enter implementation packages must be registered in
`validation/performance/no-hidden-queues.toml` with work class, resource
domains, admission token, service curve, and hard-cap metadata. The checked
guard is:

```text
cargo run -p tidefs-xtask -- check-no-hidden-queues
```

The local claim ids `perf.local.no_unbounded_dirty_debt.v1` and
`perf.local.foreground_read_not_blocked_by_scrub.v1` stay blocked in
`validation/claims.toml` until runtime queue-depth and scrub/read artifacts
cover the actual mounted paths.

## 15. Open Questions

1. **Should the governor run on its own thread or inline?**
   The admission path is hot (called from every cache insert and FUSE request).
   Inline admission with atomic counters avoids contention; a dedicated thread
   would require lock coordination. Recommendation: inline admission with
   atomic counters, background reconciliation tick for accuracy.

2. **Should auto-tuning be opt-in or opt-out?**
   Auto-tuning adjusts category fractions based on workload signals, which
   can cause unexpected behavior during workload transitions. Recommendation:
   opt-in with explicit `--auto-tune` flag, bounded by ±20% safety margins.

3. **Should the governor support per-dataset budget partitioning?**
   Some operators may want to guarantee minimum cache budgets per dataset.
   Recommendation: defer to a future `PoolGovernorPolicy`; the initial
   governor is pool-global.

4. **How to handle FUSE_NOTIFY_PRUNE when the kernel doesn't support it?**
   Older Linux kernels (< 5.8) don't support `FUSE_NOTIFY_PRUNE`. Fallback:
   skip prune and rely on `FORGET`/`BATCH_FORGET` arriving naturally. Prune
   is an optimization, not a correctness requirement.

5. **Should the governor be per-node or cluster-wide?**
   The initial design is per-node. A cluster-wide resource governor would
   require distributed consensus on budget allocation, adding complexity
   without clear benefit in the single-node-first architecture. Recommendation:
   per-node governor; cluster-wide coordination deferred to the distributed
   lock service (#1248) and cluster membership (#1209).

## 16. References

- [#1237] This design spec
- [#1226] Unified cache architecture (superseded/unified by this spec)
- [#1211] Daemon memory budget model (superseded/unified by this spec)
- [#1179] Background service framework — eviction ladder dispatched as service ticks
- [#1192] Weighted ARC cache — delegation target for L1-L4 eviction
- [#1176] Cache-lattice views — completeness contracts governed by budget
- [#1229] BULK protocol — cluster_queues budget enforcement
- [#1215] Space accounting model — cleaner watermark pressure coupling
- [#1248] Distributed lock service — cluster-wide budget coordination (future)
- [#1209] MEMBERSHIP service — per-node budget registration (future)
- [#1111] Memory pressure taxonomy P4-03 — pressure signal definitions
- `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md`
- `docs/SPACE_ACCOUNTING_MODEL_DESIGN.md`
- Python v0.262 reference: `pool_cache.py`, `fuse_budget.py`, design book §§38-42
