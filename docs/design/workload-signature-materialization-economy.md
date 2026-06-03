# Workload-Signature Materialization Economy — Design Specification

**Issue**: [#1268](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1268)
**Status**: design-spec
**Priority**: P2
**Lane**: storage-core
**Milestone**: DESIGN-M2: Filesystem Semantics + Caching (Layers 3-5)
**Depends on**: none (foundational design)
**Feeds**: #1257 (adaptive recordsize), #1226 (cache admission/eviction), #1247 (prefetch/readahead), algorithm-switching (new issue), #1237 (resource governor), #1241 (BACKGROUND lane), #1240 (derived views)
**Related**: `docs/WORKLOAD_SIGNATURE_MATERIALIZATION_PLANE_LAW.md` (production law)

## Abstract

Current DESIGN issues address individual adaptation points — recordsize (#1257), caching (#1226),
prefetch (#1247) — but no issue defines the *shared* workload-signal capture system that feeds all
of them. Without this, each subsystem independently re-implements signal detection, leading to
duplicated counters, inconsistent decisions, and unbounded per-file/per-directory tracking state.

This design introduces a three-level workload-signal taxonomy (global, per-dataset, per-file/directory),
a materialization cost model with budget enforcement, an online epoch-based policy adaptation loop,
and a continuous signal-vector workload classifier that feeds all adaptive subsystems. All per-entity
tracking uses bounded state: fixed-size frequency sketches, capped histograms, and EMA with decay.

tidefs uses a **continuous signal vector** rather than named workload classification (OLTP, analytics, etc.).
Each subsystem defines its own trigger function on this vector. No centralized classifier decides
"is this OLTP?".

---

## 1. Workload Signal Taxonomy

### 1.1 Level 0 — Global Signals (Low Cost, Always-On)

Global signals are cheap to collect and always active. They provide coarse aggregate visibility
and serve as the baseline for higher-level signal derivation.

| Signal | Unit | Method | Range |
|---|---|---|---|
| `iops_read_demand` | ops/s | Exponential moving average (EMA), α=0.2 | [0, ∞) |
| `iops_write_demand` | ops/s | EMA, α=0.2 | [0, ∞) |
| `iops_read_prefetch` | ops/s | EMA, α=0.2 | [0, ∞) |
| `bandwidth_read_bytes` | bytes/s | EMA, α=0.2 | [0, ∞) |
| `bandwidth_write_bytes` | bytes/s | EMA, α=0.2 | [0, ∞) |
| `metadata_op_rate` | ops/s | EMA over lookup/create/unlink/rename, α=0.2 | [0, ∞) |
| `cache_hit_ratio_l1` | ratio [0,1] | Sliding window (last N=256 accesses) | [0, 1] |
| `cache_hit_ratio_l2` | ratio [0,1] | Sliding window (last N=256 accesses) | [0, 1] |
| `free_space_pressure` | ratio [0,1] | (used_bytes / total_bytes), EMA α=0.5 | [0, 1] |

**Cost**: < 1 µs per IO operation. Counters are atomically incremented; rate computation
happens once per epoch (1 s).

### 1.2 Level 1 — Per-Dataset Signals (Enabled by Default)

Per-dataset signals are scoped to a dataset (filesystem, volume, or pool grouping) and
enabled by default. They use bounded histograms and EMA for memory efficiency.

| Signal | Unit | Method | Bounded? |
|---|---|---|---|
| `write_size_distribution` | byte buckets | Exponential-decay histogram, power-of-2 buckets (16 buckets: 512B…16MB) | Yes: 16 u64 counters |
| `read_size_distribution` | byte buckets | Exponential-decay histogram, power-of-2 buckets (16 buckets) | Yes: 16 u64 counters |
| `seq_read_ratio` | ratio [0,1] | EMA-decayed: (sequential_bytes / total_bytes_read), α=0.1 | Yes: 2 f64 fields |
| `seq_write_ratio` | ratio [0,1] | EMA-decayed: (sequential_bytes / total_bytes_written), α=0.1 | Yes: 2 f64 fields |
| `dir_churn_rate` | ops/s per dir | Create+unlink per directory, top-K sketch (K=64) | Yes: 64-entry heap |
| `snapshot_create_rate` | ops/s | EMA, α=0.1 | Yes: 1 f64 |
| `snapshot_destroy_rate` | ops/s | EMA, α=0.1 | Yes: 1 f64 |

**Sequential detection**: Two consecutive IOs are sequential if offsetᵢ₊₁ == offsetᵢ + sizeᵢ
(or offsetᵢ₊₁ == offsetᵢ when reading ahead). The EMA-decayed ratio tracks the proportion
of bytes that arrived sequentially.

**Exponential-decay histogram**: Each bucket count is multiplied by (1 - α) on each epoch tick
(α = 0.05 default), then the new observation is added to the appropriate bucket. This
provides natural recency weighting without storing timestamps.

**Per-dataset state budget**: ~1 KB per dataset (16×8 + 16×8 + 4×8 + 64×(8+8) ≈ 1.3 KB).

### 1.3 Level 2 — Per-File/Directory Signals (Enabled Selectively, Bounded State)

Level 2 signals track per-entity behavior but with strict state caps. No unbounded per-file
state is permitted. Files are promoted to Level 2 tracking only when their access rate
exceeds a threshold (default: 10 ops in a 60 s window).

#### 1.3.1 File Lifecycle State Machine

```
   ┌──────────┐   write ops    ┌──────────┐   60 s no writes   ┌──────────┐
   │   NEW    │ ──────────────→ │  STABLE  │ ─────────────────→ │   COLD   │
   │growing   │                 │infrequent│                    │read-only │
   └──────────┘                 │ writes   │                    └─────┬────┘
                                     │                               │
                                     │ pending unlink                  │ pending unlink
                                     ↓                               ↓
                                ┌──────────┐                   ┌──────────┐
                                │   DEAD   │ ←──────────────── │   DEAD   │
                                │pending   │  60 s no access   │pending   │
                                │ unlink   │                   │ unlink   │
                                └──────────┘                   └──────────┘
```

- **NEW**: File is growing rapidly (> 2 writes in last epoch). May benefit from larger
  recordsize, aggressive prefetch.
- **STABLE**: File receives infrequent writes (< 2 writes per epoch). Standard policies apply.
- **COLD**: No writes for 60 s, only reads. May benefit from compression, lower cache priority.
- **DEAD**: Pending unlink (link count == 0, all handles closed). Skip all adaptive effort.

**State tracking cost per file**: 1 byte (2-bit state + 6-bit epoch counter for hysteresis).

#### 1.3.2 File Access Pattern

| Pattern | Detection | Bits |
|---|---|---|
| `Sequential` | Consecutive reads with monotonic offset, stride ≤ 64KB gap tolerance | 3 |
| `Strided` | Regular offset jumps with consistent stride (detected via 4-entry stride history) | 3 |
| `Random` | No discernible pattern; default state | 3 |
| `AppendOnly` | All writes at EOF, no seeks backward | 3 |

**Detection**: A 4-slot circular buffer stores the last 4 (offset, size) pairs. Stride
detection checks if offset deltas repeat within a 16-byte tolerance. Sequential detection
checks if offsetᵢ₊₁ is within [offsetᵢ + sizeᵢ - 64KB, offsetᵢ + sizeᵢ + 64KB].

**Cost per tracked file**: 5 bytes (4 × (u48 offset hint + u16 size) for buffer + 1 byte pattern state).

#### 1.3.3 Hot Directory Detection

A directory is "hot" when its readdir frequency exceeds a threshold. Uses a Count-Min
Sketch (4 rows × 256 columns = 1024 u32 counters, ~4 KB) shared across all directories
in a dataset. A directory hash maps to 4 counters; the minimum of those 4 is the
estimated frequency. Decay: all counters halved every epoch (approximate aging).

**Cost per dataset**: ~4 KB (shared Count-Min Sketch).

#### 1.3.4 Additional Per-File State

| Signal | Method | Cost |
|---|---|---|
| `link_count` | Atomic counter; tracks hardlink count | 2 bytes |
| `open_handle_count` | Atomic counter; tracks active open fds | 2 bytes |
| `last_access_epoch` | Epoch ID of last read or write | 4 bytes |

**Level 2 total per tracked file**: ~14 bytes. Files are evicted from Level 2 tracking
when their access rate drops below the threshold for 60 consecutive seconds. An LRU
list of 1024 entries limits total tracked files per dataset to ~14 KB.

---

## 2. Workload Signal Vector (Continuous Classification)

Rather than trying to "identify" named workloads (OLTP, analytics, HPC, etc.), tidefs
uses a **continuous signal vector** that feeds ALL adaptive subsystems.

### 2.1 Vector Definition

```rust
/// The canonical workload signal vector. Every adaptive subsystem reads from this.
/// All values are normalized to [0, 1] or represent rates/ratios.
#[derive(Clone, Copy, Debug, Default)]
pub struct WorkloadSignalVector {
    // -- Access pattern --
    /// Ratio of bytes read sequentially vs total bytes read (EMA). Range [0, 1].
    pub seq_read_ratio: f64,
    /// Ratio of bytes written sequentially vs total bytes written (EMA). Range [0, 1].
    pub seq_write_ratio: f64,
    /// Ratio of write ops to total IO ops. Range [0, 1].
    pub write_ratio: f64,

    // -- Size characteristics --
    /// EMA-decayed average write size in bytes.
    pub avg_write_size: f64,
    /// EMA-decayed average read size in bytes.
    pub avg_read_size: f64,
    /// Standard deviation bucket for write sizes (0=uniform, 1=highly variable).
    pub write_size_variance_bucket: u8,
    /// Standard deviation bucket for read sizes (0=uniform, 1=highly variable).
    pub read_size_variance_bucket: u8,

    // -- Rate characteristics --
    /// Metadata operations per second (EMA). Lookup + create + unlink + rename.
    pub metadata_rate: f64,
    /// Directory churn rate per second (EMA).
    pub dir_churn_rate: f64,
    /// Snapshot create+destroy rate per second (EMA).
    pub snapshot_churn_rate: f64,

    // -- Cache characteristics --
    /// L1 cache hit ratio (sliding window). Range [0, 1].
    pub cache_hit_ratio_l1: f64,
    /// L2 cache hit ratio (sliding window). Range [0, 1].
    pub cache_hit_ratio_l2: f64,

    // -- Pressure --
    /// Free space pressure. Range [0, 1] where 1 = full.
    pub free_space_pressure: f64,
    /// IOPS utilization ratio (current / max). Range [0, ∞).
    pub iops_pressure: f64,
    /// Bandwidth utilization ratio (current / max). Range [0, ∞).
    pub bandwidth_pressure: f64,
}
```

### 2.2 Subsystem Trigger Functions

Each adaptive subsystem defines its own **trigger function** on the signal vector.
No centralized classifier makes a single "is this OLTP?" decision.

**Examples**:

| Subsystem | Trigger Function (conceptual) |
|---|---|
| Adaptive recordsize (#1257) | `if avg_write_size > current_recordsize * 0.8 → consider larger recordsize` |
| Cache admission (#1226) | `if seq_read_ratio > 0.7 → enable streaming bypass for L1; if cache_hit_ratio_l1 < 0.3 → increase L1 size` |
| Prefetch (#1247) | `if seq_read_ratio > 0.6 && iops_pressure < 0.5 → aggressive readahead` |
| Compression policy | `if avg_write_size > 64KB && write_ratio > 0.8 → disable compression for throughput` |
| Dir index polymorphism | `if dir_churn_rate > 10.0 && metadata_rate > 1000.0 → switch to hash-based index` |

### 2.3 Confidence and Decay

Each signal carries an implicit **confidence** determined by the observation count since
last reset. A signal with < 10 observations has low confidence and should not trigger
adaptation. Confidence is tracked as `observation_count: u64` (EMA-decayed by α=0.01 per epoch).

```rust
/// Per-signal confidence tracking.
#[derive(Clone, Copy, Debug, Default)]
pub struct SignalConfidence {
    /// EMA-decayed observation count. Below threshold → low confidence.
    pub observation_count: f64,
    /// Age of the signal in epochs since last significant observation.
    pub epochs_since_last_observation: u32,
    /// Whether this signal is reliable enough to drive decisions.
    pub is_confident: bool,
}
```

A signal is "confident" when `observation_count >= 10.0` and `epochs_since_last_observation < 5`.

---

## 3. Materialization Cost Model

Each "materialization decision" (representation switch, defrag, rebake, cache promotion,
index rebuild) has a measurable cost and an estimated benefit.

### 3.1 Cost Formula

```
cost = write_bytes(N_new_pages) * write_cost_per_byte
     + read_bytes(N_old_pages)  * read_cost_per_byte
     + cpu_ms(migration_complexity) * cpu_cost_per_ms
     + latency_penalty_ms        * blocking_factor
```

Where:
- `write_cost_per_byte`: device-class-dependent (NVMe: 0.01, SSD: 0.03, HDD: 0.10)
- `read_cost_per_byte`: same scale
- `cpu_cost_per_ms`: normalized to 1.0
- `blocking_factor`: 0.0 for BACKGROUND lane, 1.0 for blocking METADATA lane

### 3.2 Benefit Formula

```
benefit = latency_reduction_estimate   * latency_weight
        + throughput_improvement_estimate * throughput_weight
        + space_savings                 * space_weight
        - adaptation_risk              * risk_weight
```

Where:
- `latency_reduction_estimate`: expected reduction in p99 latency (µs)
- `throughput_improvement_estimate`: expected increase in ops/s
- `space_savings`: bytes freed or not allocated
- `adaptation_risk`: probability of thrashing (reverting within N epochs)
- Weights are configurable per dataset via `materialization_factor` (see §3.4)

### 3.3 Decision Gate

A materialization decision is only executed if:

```
benefit > cost * materialization_factor
```

If `materialization_factor > 1.0`, the system is conservative (requires higher benefit relative
to cost). If `materialization_factor < 1.0`, the system is aggressive.

### 3.4 Tunable Parameters

```rust
/// Per-dataset materialization tuning.
#[derive(Clone, Copy, Debug)]
pub struct MaterializationPolicy {
    /// Benefit/cost threshold multiplier. >1.0 = conservative, <1.0 = aggressive.
    pub materialization_factor: f64,
    /// Maximum materialization budget per epoch in cost units.
    pub budget_per_epoch: f64,
    /// Maximum number of adaptations per epoch (prevents thrashing storms).
    pub max_adaptations_per_epoch: u32,
    /// Minimum epochs between successive adaptations on same entity.
    pub cooldown_epochs: u32,
    /// Adaptation regret threshold: if more than this fraction of recent adaptations
    /// were reverted, enter cooldown.
    pub regret_threshold: f64,
    /// Whether to allow BACKGROUND-lane materialization (true) or require idle (false).
    pub allow_background_materialization: bool,
}
```

Defaults:

| Parameter | Default | Rationale |
|---|---|---|
| `materialization_factor` | 1.2 | Slightly conservative; prefer to skip marginal adaptations |
| `budget_per_epoch` | 1000.0 | Allows ~1-2 significant materialization ops per second |
| `max_adaptations_per_epoch` | 8 | Prevents adaptation storms under rapid workload shifts |
| `cooldown_epochs` | 10 | 10 seconds between adaptations on the same entity |
| `regret_threshold` | 0.3 | If 30%+ of recent adaptations were reverted, pause |
| `allow_background_materialization` | true | Allow materialization to run in background |

---

## 4. Online Policy Adaptation Loop

### 4.1 Epoch Cycle

The adaptation loop runs once per epoch (default: 1 second, configurable via
`adaptation_epoch_ms: 100..10000`).

```
every epoch (1 s by default, configurable):
  1. COLLECT: Gather Level 0-1 signals from global and per-dataset counters.
     Decay histograms and EMA counters.
  2. CLASSIFY: Build the WorkloadSignalVector for each active dataset.
     Compute confidence for each signal component.
  3. EVALUATE: For each registered adaptive subsystem, call its trigger
     function with the current signal vector.
  4. RANK: For each triggered adaptation, compute the materialization
     cost and benefit. Sort by benefit/cost ratio descending.
  5. SCHEDULE: For each candidate in rank order:
     a. If cost > budget_remaining → skip
     b. If max_adaptations_per_epoch reached → defer to next epoch
     c. If entity in cooldown → skip
     d. If regret_threshold exceeded → skip all further adaptations
     e. Otherwise: schedule adaptation in BACKGROUND lane
  6. DECAY: Reset/decay counters for next epoch. Update regret tracking.
  7. EMIT: Publish adaptation decisions, budget consumption, and signal
     vector to observability surfaces.
```

### 4.2 Adaptation Lifecycle

```
  ┌──────────┐
  │ TRIGGERED│ ← subsystem trigger function fires
  └────┬─────┘
       │ cost computed
       ↓
  ┌──────────┐
  │  RANKED  │ ← sorted by benefit/cost ratio
  └────┬─────┘
       │ budget check + cooldown check
       ↓
  ┌──────────┐     ┌──────────┐
  │SCHEDULED │────→│COMPLETED │ ← materialization finished
  └────┬─────┘     └────┬─────┘
       │                 │
       │ (if reverted    │
       │  within N       │
       │  epochs)        │
       ↓                 │
  ┌──────────┐           │
  │ REVERTED │←──────────┘
  └──────────┘
```

### 4.3 Regret Tracking

"Adaptation regret" measures how many recent adaptations were counterproductive
(reverted within N epochs). A high regret rate triggers cooldown.

```rust
/// Tracks adaptation effectiveness over time.
#[derive(Clone, Debug, Default)]
pub struct AdaptationRegretTracker {
    /// Number of adaptations in the current window.
    pub total_adaptations: u32,
    /// Number of adaptations reverted within cooldown_epochs.
    pub reverted_adaptations: u32,
    /// Fraction of adaptations reverted (reverted / total).
    pub regret_ratio: f64,
    /// Whether the regret threshold is currently exceeded.
    pub in_cooldown: bool,
    /// Epochs remaining in cooldown.
    pub cooldown_remaining: u32,
}
```

The tracker uses a circular buffer of the last 64 adaptation decisions. When a decision
is reverted, it increments `reverted_adaptations`. `total_adaptations` counts all decisions
in the window. When `regret_ratio > regret_threshold`, cooldown is entered for
`cooldown_epochs` epochs, during which no new adaptations are scheduled.

---

## 5. Adaptation Budget Model

### 5.1 Budget Allocation

The materialization budget is integrated with the unified resource governor (#1237).
Each epoch, the governor allocates a fraction of the total background capacity
to materialization work.

```
epoch_budget = min(
    materialization_policy.budget_per_epoch,
    resource_governor.background_capacity * governor_materialization_fraction
)
```

The `governor_materialization_fraction` is a governor-level parameter (default: 0.25)
that caps what fraction of background capacity can be consumed by materialization.

### 5.2 Budget Consumption Tracking

```rust
/// Per-epoch budget state.
#[derive(Clone, Copy, Debug, Default)]
pub struct EpochBudget {
    /// Total budget allocated for this epoch (cost units).
    pub allocated: f64,
    /// Budget consumed so far this epoch.
    pub consumed: f64,
    /// Number of adaptations scheduled this epoch.
    pub adaptations_scheduled: u32,
    /// Number of adaptations deferred due to budget exhaustion.
    pub adaptations_deferred: u32,
}

impl EpochBudget {
    pub fn remaining(&self) -> f64 { self.allocated - self.consumed }
    pub fn is_exhausted(&self) -> bool { self.consumed >= self.allocated }
    pub fn can_schedule(&self, cost: f64) -> bool { self.remaining() >= cost }
}
```

### 5.3 Budget Cascading

Unused budget from one epoch does not roll over (prevents budget hoarding).
High-priority adaptations (those with benefit/cost ratio in the top quartile)
are always scheduled if budget allows; lower-priority adaptations are scheduled
only if budget remains after the top quartile.

---

## 6. Adaptation Scheduling and Concurrency

### 6.1 Scheduling via BACKGROUND Lane

All materialization work is dispatched through the existing BACKGROUND lane (#1241,
`tidefs-background-scheduler`). Materialization is assigned `ServicePriority::Opportunistic`
by default, meaning it runs only when no higher-priority background work (scrub,
reclaim, compaction) is pending.

### 6.2 Concurrency Model

- **Single adaptation per entity at a time**: A file/dataset can only have one active
  materialization in flight.
- **No cross-entity ordering**: Materializations for different files/datasets can run
  concurrently; there is no ordering guarantee between them.
- **Epoch-level serialization**: All trigger evaluation and ranking happens
  synchronously within the epoch tick. Scheduling dispatches work but does not block.

### 6.3 Integration with IncrementalJob

Each materialization is wrapped as an `IncrementalJob` (from
`tidefs-types-incremental-job-core`) and submitted to the `BackgroundScheduler`.
The job can be checkpointed, paused, and resumed across epoch boundaries.

```rust
/// A materialization task wrapped as an IncrementalJob.
pub struct MaterializationJob {
    /// The entity being materialized (dataset ID, file inode, etc.).
    pub entity: MaterializationEntity,
    /// The materialization action to perform.
    pub action: MaterializationAction,
    /// Estimated cost (for budget tracking).
    pub estimated_cost: f64,
    /// The epoch in which this job was scheduled.
    pub scheduled_epoch: u64,
}
```

---

## 7. Materialization Actions Catalog

### 7.1 Supported Actions

| Action | Description | Typical Cost | Typical Benefit |
|---|---|---|---|
| `RecordsizeResize` | Change dataset recordsize (#1257) | Low (metadata update) | Medium (throughput) |
| `CacheTierPromote` | Promote entity to higher cache tier (#1226) | Low (metadata only) | High (latency) |
| `CacheTierDemote` | Demote entity to lower cache tier | Low (metadata only) | Low (space) |
| `PrefetchWindowResize` | Adjust readahead window (#1247) | Zero (parameter change) | High (throughput) |
| `CompressionToggle` | Enable/disable compression for entity | High (re-write data) | Medium (space or throughput) |
| `DirIndexRebuild` | Switch directory index algorithm | Medium (scan dir) | High (lookup latency) |
| `ExtentMapRebuild` | Rebuild extent map (defrag) | High (scan extents) | Medium (throughput) |
| `Rebake` | Convert entity to different on-media format | High (full rewrite) | High (long-term) |
| `PlacementMigrate` | Move entity to different device/tier | High (data copy) | Medium (latency/space) |

### 7.2 Action Classification

Each action is classified by its cost magnitude for scheduling priority:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaterializationCostClass {
    /// Near-zero cost: parameter change, metadata-only update.
    Trivial,
    /// Low cost: scan small structure, update metadata.
    Low,
    /// Medium cost: scan medium structure, partial data rewrite.
    Medium,
    /// High cost: full data rewrite, cross-device migration.
    High,
}
```

---

## 8. Type Definitions and Crate Structure

### 8.1 New Crate: `tidefs-types-workload-model-core`

Following the current shared-types pattern (`tidefs-types-cache-lattice-core`),
a new `no_std` types crate holds the canonical workload-model record types.

```rust
// tidefs-types-workload-model-core/src/lib.rs
#![no_std]
#![forbid(unsafe_code)]

/// Three-level signal taxonomy classification.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkloadSignalLevel {
    Level0 = 0,  // Global, always-on
    Level1 = 1,  // Per-dataset, enabled by default
    Level2 = 2,  // Per-file/directory, selectively enabled
}

/// File lifecycle state (2 bits).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileLifecycle {
    New = 0,
    Stable = 1,
    Cold = 2,
    Dead = 3,
}

/// File access pattern classification.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessPattern {
    Unknown = 0,
    Sequential = 1,
    Strided = 2,
    Random = 3,
    AppendOnly = 4,
}

/// Materialization action classification.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaterializationAction {
    RecordsizeResize = 0,
    CacheTierPromote = 1,
    CacheTierDemote = 2,
    PrefetchWindowResize = 3,
    CompressionToggle = 4,
    DirIndexRebuild = 5,
    ExtentMapRebuild = 6,
    Rebake = 7,
    PlacementMigrate = 8,
}

/// Result of a materialization decision evaluation.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaterializationDecision {
    /// Adaptation was scheduled and will execute.
    Scheduled,
    /// Adaptation was deferred (budget exhausted, cooldown, etc.).
    Deferred,
    /// Adaptation was rejected (cost > benefit, low confidence, etc.).
    Rejected,
    /// Adaptation was completed successfully.
    Completed,
    /// Adaptation was reverted (undo performed).
    Reverted,
}
```

### 8.2 New Crate: `tidefs-workload-model`

The runtime crate implementing the workload-model logic:

```
crates/tidefs-workload-model/
├── Cargo.toml
└── src/
    ├── lib.rs           # Public API, re-exports
    ├── signal_capture.rs # Level 0-2 signal collection
    ├── signal_vector.rs  # WorkloadSignalVector construction
    ├── cost_model.rs     # Materialization cost/benefit computation
    ├── adaptation_loop.rs # Epoch cycle, trigger evaluation, ranking
    ├── budget.rs         # EpochBudget, budget tracking
    ├── regret.rs         # AdaptationRegretTracker
    ├── histograms.rs     # Exponential-decay histogram, Count-Min Sketch
    └── lifecycle.rs      # FileLifecycle state machine
```

### 8.3 WorkloadModelHub

The central hub struct that orchestrates all workload-model concerns:

```rust
/// Central hub for workload-signal capture, classification, and materialization.
pub struct WorkloadModelHub {
    /// Global signal state (Level 0).
    pub global_signals: GlobalSignalState,
    /// Per-dataset signal state (Level 1), keyed by dataset ID.
    pub dataset_signals: HashMap<DatasetId, DatasetSignalState>,
    /// Per-file signal state (Level 2), keyed by inode, bounded.
    pub file_signals: LruCache<InodeId, FileSignalState>,
    /// Materialization policy per dataset.
    pub policies: HashMap<DatasetId, MaterializationPolicy>,
    /// Regret tracker per dataset.
    pub regret_trackers: HashMap<DatasetId, AdaptationRegretTracker>,
    /// Current epoch budget.
    pub budget: EpochBudget,
    /// Registered subsystem triggers.
    pub triggers: Vec<Box<dyn AdaptationTrigger>>,
    /// Pending materialization jobs.
    pub pending_jobs: Vec<MaterializationJob>,
}
```

---

## 9. Subsystem Integration Points

### 9.1 Recordsize Adaptation (#1257)

- **Trigger**: `avg_write_size > current_recordsize * 0.8` for at least 3 confident epochs
- **Action**: `MaterializationAction::RecordsizeResize`
- **Budget impact**: Trivial (metadata update)
- **Cooldown**: 60 s (recordsize changes are disruptive)

### 9.2 Cache Admission/Eviction (#1226)

- **Trigger**: `cache_hit_ratio_l1 < 0.3` → increase L1; `seq_read_ratio > 0.7` → bypass
- **Action**: `MaterializationAction::CacheTierPromote` / `CacheTierDemote`
- **Budget impact**: Low (tag update)
- **Cooldown**: 5 s (cache can adapt quickly)

### 9.3 Prefetch/Readahead (#1247)

- **Trigger**: `seq_read_ratio > 0.6 && iops_pressure < 0.5` → aggressive
- **Action**: `MaterializationAction::PrefetchWindowResize`
- **Budget impact**: Trivial (parameter change)
- **Cooldown**: 1 s (prefetch can adapt fastest)

### 9.4 Algorithm Switching (New Issue)

- **Trigger**: Domain-specific; e.g., `dir_churn_rate > 10.0` → switch dir index
- **Action**: `MaterializationAction::DirIndexRebuild`
- **Budget impact**: Medium
- **Cooldown**: 30 s

### 9.5 Resource Governor (#1237)

The workload model integrates with the resource governor by:
- Consuming `governor_materialization_fraction` of background capacity
- Reporting budget consumption per epoch for governor accounting
- Respecting governor-enforced memory pressure limits (pause all materialization at >90% pressure)

### 9.6 Observability (#1240)

Per-epoch observability emission:
- **Workload signal vector**: current values per dataset (for `truth_view` rendering)
- **Materialization budget consumed**: bytes and CPU-ms per epoch per dataset
- **Adaptation decisions**: per-epoch log of triggered, scheduled, completed, deferred, rejected, reverted
- **Adaptation regret**: current regret ratio and cooldown status

---

## 10. Deterministic Testing Strategy

### 10.1 Synthetic Signal Injection

Tests inject synthetic workload signals and verify that adaptation decisions
match expected outcomes. The `WorkloadModelHub` accepts an `inject_signal()`
method for testing.

```rust
#[test]
fn recordsize_trigger_fires_when_write_size_exceeds_threshold() {
    let mut hub = WorkloadModelHub::new_test();
    let dataset = DatasetId::new(1);

    // Inject signals: large writes, sequential pattern
    hub.inject_signal(dataset, SignalComponent::AvgWriteSize, 128_000.0);
    hub.inject_signal(dataset, SignalComponent::SeqWriteRatio, 0.9);
    hub.inject_confidence(dataset, SignalComponent::AvgWriteSize, 15.0); // confident

    hub.run_epoch();

    let decisions = hub.get_decisions_for(dataset);
    assert!(decisions.iter().any(|d| matches!(d.action, MaterializationAction::RecordsizeResize)));
}

#[test]
fn adaptation_is_deferred_when_budget_exhausted() {
    let mut hub = WorkloadModelHub::new_test();
    hub.set_budget(EpochBudget { allocated: 1.0, ..Default::default() });

    // Trigger many adaptations that would exceed budget
    // Only the highest benefit/cost ones should be scheduled
}

#[test]
fn cooldown_prevents_repeated_adaptation() {
    let mut hub = WorkloadModelHub::new_test();
    // Trigger adaptation, verify it runs
    // Trigger same adaptation immediately, verify it's deferred (cooldown)
}

#[test]
fn regret_threshold_enters_cooldown() {
    let mut hub = WorkloadModelHub::new_test();
    // Schedule and revert adaptations until regret > threshold
    // Verify cooldown is entered and new adaptations are blocked
}
```

### 10.2 Deterministic Epoch Ticking

Epochs are driven by an explicit `tick()` method, not wall-clock time.
Tests call `tick()` to advance time deterministically.

---

## 11. Relationship to Existing Artifacts

### 11.1 Relationship to LAW Document

This design spec is the implementation-level companion to
`docs/WORKLOAD_SIGNATURE_MATERIALIZATION_PLANE_LAW.md`. The LAW document defines
*what* must be true (product plane, execution law, canonical chain, operator
control model). This design spec defines *how* it is implemented (types, algorithms,
scheduling, budget model, crate structure).

### 11.2 Relationship to adaptive_governor_0

`workload_model_0` consumes the shared `adaptive_governor_0` signal substrate
rather than defining a second observation system. Level 0 signals (IOPS, bandwidth,
metadata rate) are captured by `adaptive_governor_0` and consumed by `workload_model_0`.
Level 1-2 signals are workload-model-specific but follow the same observation discipline.

### 11.3 Relationship to Other Design Issues

| Issue | Relationship |
|---|---|
| #1257 (adaptive recordsize) | Consumer of workload signal vector for write-size-driven recordsize selection |
| #1226 (cache admission) | Consumer of signal vector for cache tier promotion/demotion and bypass decisions |
| #1247 (prefetch) | Consumer of sequential-read ratio for readahead window sizing |
| #1237 (resource governor) | Provider of background-work budget; consumer of materialization budget consumption |
| #1241 (BACKGROUND lane) | Materialization work is dispatched as LaneClass::Background jobs |
| #1240 (derived views) | Emits signal vector and adaptation decisions as derived views |
| Algorithm switching (new) | Consumer of signal vector for triggering algorithm transitions |

---

## 12. Migration and Rollout

### 12.1 Implementation Phases

| Phase | Scope | Deliverable |
|---|---|---|
| Phase 1 | Type definitions: `tidefs-types-workload-model-core` crate, enums, records | Compiling types crate |
| Phase 2 | Signal capture: Level 0-1 collection, histograms, EMA machinery | `tidefs-workload-model` with signal capture |
| Phase 3 | Cost model: benefit/cost scoring, budget tracking, regret tracking | Full cost model in runtime crate |
| Phase 4 | Adaptation loop: epoch cycle, trigger evaluation, ranking, scheduling | Complete adaptation loop |
| Phase 5 | Subsystem integration: wire signals into #1257, #1226, #1247 | 3+ subsystems consuming signal vector |
| Phase 6 | Observability: truth_view views, metrics emission | Visible operator surfaces |

### 12.2 Backward Compatibility

- Level 0-1 signals are additive; no existing behavior changes when workload-model
  is initialized with default (no-op) triggers.
- Subsystems that do not register a trigger function continue with their existing
  static/default behavior.
- Materialization budget defaults to 0 when the resource governor is not yet integrated,
  effectively disabling automated materialization.

---

## 13. Failure Modes and Safety

### 13.1 Thrashing Prevention

- **Cooldown periods** between successive adaptations on the same entity
- **Regret tracking** with automatic cooldown when >30% of recent adaptations are reverted
- **Max adaptations per epoch** cap prevents adaptation storms
- **Budget exhaustion** naturally limits adaptation rate

### 13.2 Memory Safety

- All Level 2 per-file tracking uses bounded state (capped LRU, fixed-size sketches)
- Count-Min Sketch for hot-directory detection is fixed-size (1024 counters)
- Exponential-decay histograms are fixed-size (16 buckets)
- No dynamic allocation growth; all structures are pre-sized at initialization

### 13.3 Observability Guardrails

- Every adaptation decision is logged with rationale (trigger signature, cost, benefit)
- Adaptation regret is visible to operators
- Signal confidence levels are visible; low-confidence signals that drive decisions
  are flagged
- A `warn`-level trace is emitted when regret threshold is exceeded

---

## 14. Summary of Key Design Decisions

| Decision | Rationale |
|---|---|
| Continuous signal vector vs named workload classification | Avoids fragile heuristics; each subsystem defines its own trigger |
| Three signal levels with escalating cost | Level 0 always-on, Level 1 per-dataset (default), Level 2 selective |
| Bounded per-entity state only | No unbounded per-file tracking; LRU caps, fixed-size sketches |
| EMA-decayed signals with explicit confidence | Natural recency weighting; prevents low-confidence signals from driving decisions |
| Benefit/cost gating with tunable factor | Operators can bias conservative vs aggressive via a single knob |
| BACKGROUND lane for all materialization | Materialization never blocks foreground IO |
| Integration with resource governor for budget | Single budget authority prevents over-commitment |
| Deterministic epoch ticking | Enables deterministic tests; epoch duration is configurable |
| Adaptation regret tracking | Prevents thrashing by detecting and pausing counterproductive adaptation |
