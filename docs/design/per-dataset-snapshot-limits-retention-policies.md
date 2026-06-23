# Per-Dataset Snapshot Limits and Retention Policies

**Issue**: [#1277](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1277)
**Status**: design-spec
**Priority**: P2
**Lane**: storage-core
**Milestone**: DESIGN-M3: Data Services + Integrity (Layers 6-7)
**Depends on**: #1253 (dataset properties), #1232 (snapshot deadlist), #1215 (space accounting), #1241 (scheduling lanes), #1251 (send/recv), #1258 (cluster snapshots)

## Abstract

tidefs datasets require per-dataset snapshot lifecycle management: hard limits on
snapshot count, age-based automatic expiry, a declarative retention policy for
time-granularity-based preservation, a minimum-snapshot floor to prevent accidental
data loss, reserved space guarantees, and a BACKGROUND-lane auto-pruner that
incrementally destroys excess or expired snapshots without blocking user IO or
stalling the transaction pipeline.

This design integrates with six existing subsystems: local snapshot creation
and catalog (historical #1253), the interval-based deadlist pinning algorithm
(#1232), logical
and physical space accounting including `pinned_snapshot_bytes` (#1215), the
BACKGROUND scheduling lane (#1241), send/recv stream pinning (#1251), and
cluster-wide snapshot coordination (#1258).

## 1. Motivation

### 1.1 Anti-patterns addressed

The comparison rows below are design-pressure notes, not validated superiority
claims. They preserve lifecycle lessons from ZFS, CephFS, and sanoid while
leaving current product-facing retention, performance, durability, and
operational-safety claims blocked behind #875 and #928/#930 comparator
evidence.

| System | Prior-art pressure | TideFS design response target |
|---|---|---|
| ZFS | Snapshot limit and retention workflows often depend on external policy tooling. | Transactional enforcement at create time: `snapshot create` checks `max_snapshots` BEFORE creating. Declarative retention is evaluated by the storage system. |
| CephFS | Snapshot lifecycle policy is a separate operator concern. | Per-dataset retention policies with budgeted BACKGROUND-lane auto-prune. |
| ZFS sanoid | Post-hoc reactive pruning can create then delete to enforce a limit. | Pre-check at create time: if `snapshot_count >= max_snapshots` and no expired snapshot is immediately reclaimable, create fails atomically with `ENOSPC` (snapshot quota). |

### 1.2 Why per-dataset

Snapshot policies are not one-size-fits-all:

- A home-directory dataset may keep 24 hourly + 7 daily snapshots.
- A database dataset may keep 4 weekly + 12 monthly snapshots.
- A scratch dataset may keep 0 snapshots entirely.
- A compliance dataset may keep 5 yearly snapshots with a 7-year minimum retention.

Pool-level policies cannot express these differences without fragmenting datasets
across pools, which defeats the point of a single storage pool.

## 2. Relationship to Existing Designs

| Design | Integration point | This design provides |
|---|---|---|
| #1253 (dataset properties) | Per-dataset property storage | The `SnapshotPolicyV1` struct is stored as a per-dataset property in the dataset record's TLV extension area. Property read/write follows #1253's transactional model. |
| #1232 (snapshot deadlist) | Incremental deadlist destroy | Auto-prune uses the cursor-driven deadlist destroy path from #1232 §4, with per-commit_group bounds. The freeze + move-or-free algorithm is invoked directly. |
| #1215 (space accounting) | `pinned_snapshot_bytes`, reservation | `snapshot_reserve_bytes` feeds into the reservation model. Destroyed snapshot space is credited through `SpaceDelta` accumulators. |
| #1241 (scheduling lanes) | BACKGROUND lane auto-prune | The `SnapshotAutoPruneJob` runs as a BACKGROUND-lane service (#1241 §1.1, priority 4). Budgeted per tick with starvation prevention timeout. |
| #1251 (send/recv) | Stream-pinned snapshots | Snapshots held by an active send/recv stream are pinned; the auto-pruner skips them. The `send_hold_count` field gates destruction. |
| #1219 (dataset lifecycle) | Destroy fencing | When a dataset enters DESTROYING state, the snapshot policy is frozen. No new snapshots are created; the auto-pruner is disabled to prevent interfering with the destroy worker. |
| #1179 (background service) | Service dispatch | The `SnapshotAgeExpiryJob` is registered with the `BackgroundScheduler` at `Throughput` priority. |
| #1254 (pool import) | Pool-level policy defaults | Pool-level snapshot policy defaults are inherited by datasets that don't override them. |
| #1223 (dataset feature flags) | Feature gating | Retention policies are gated by the `org.tidefs:snapshot_retention` feature flag. A dataset without this flag uses pre-v0.418 snapshot semantics (no limits, no auto-prune). |

## 3. Core Data Structures

### 3.1 SnapshotPolicyV1 — per-dataset snapshot policy

```rust
/// Per-dataset snapshot limit and retention policy.
///
/// Stored in the dataset record's TLV extension area as a property
/// per #1253. Updated atomically within a commit_group.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SnapshotPolicyV1 {
    // --- Limit properties ---

    /// Maximum number of snapshots allowed for this dataset.
    /// `snapshot create` checks this BEFORE creating. When `snapshot_count`
    /// reaches this value and no expired snapshot can be pruned first,
    /// create fails with ENOSPC (snapshot quota).
    /// None = no limit (pre-v0.418 behavior).
    pub max_snapshots: Option<u32>,

    /// Maximum age of any snapshot in seconds.
    /// Snapshots older than `now - max_snapshot_age_seconds` are eligible
    /// for auto-destruction, subject to `min_snapshots` floor.
    /// None = no age-based expiry.
    pub max_snapshot_age_seconds: Option<u64>,

    /// Minimum number of snapshots to preserve.
    /// Age-based expiry will never reduce the snapshot count below this
    /// floor, even if all remaining snapshots are older than
    /// `max_snapshot_age_seconds`.
    /// Must be <= max_snapshots when both are set.
    /// None = no floor (age expiry can delete all snapshots).
    pub min_snapshots: Option<u32>,

    /// Guaranteed space reservation for snapshots, in bytes.
    /// The space accounting model treats this as a reservation against
    /// the dataset's quota. New writes cannot consume space below
    /// `snapshot_reserve_bytes` of the quota ceiling.
    /// None = no snapshot space guarantee.
    pub snapshot_reserve_bytes: Option<u64>,

    // --- Declarative retention ---

    /// Retention policy: how many snapshots to keep at each time
    /// granularity. None = no declarative retention (use limit+age only).
    pub retention: Option<SnapshotRetentionV1>,
}
```

### 3.2 SnapshotRetentionV1 — declarative time-granularity retention

```rust
/// Declarative retention policy by time granularity.
///
/// Snapshots are auto-labelled by time granularity at create time.
/// destruction when limits are exceeded.
///
/// Example: `keep_hourly: 24, keep_daily: 7, keep_weekly: 4,
///           keep_monthly: 12, keep_yearly: 5`
///
/// This means: keep the newest 24 hourly snapshots, 7 daily, 4 weekly,
/// 12 monthly, and 5 yearly. Snapshots outside these windows are
/// eligible for pruning.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SnapshotRetentionV1 {
    /// Number of hourly-granularity snapshots to retain.
    /// Hour = snapshot created within the current hour.
    pub keep_hourly: u32,

    /// Number of daily-granularity snapshots to retain.
    /// Day = one snapshot per calendar day (UTC).
    pub keep_daily: u32,

    /// Number of weekly-granularity snapshots to retain.
    /// Week = one snapshot per ISO week (UTC).
    pub keep_weekly: u32,

    /// Number of monthly-granularity snapshots to retain.
    /// Month = one snapshot per calendar month (UTC).
    pub keep_monthly: u32,

    /// Number of yearly-granularity snapshots to retain.
    /// Year = one snapshot per calendar year (UTC).
    pub keep_yearly: u32,
}

impl Default for SnapshotRetentionV1 {
    fn default() -> Self {
        Self {
            keep_hourly: 24,
            keep_daily: 7,
            keep_weekly: 4,
            keep_monthly: 12,
            keep_yearly: 5,
        }
    }
}
```

### 3.3 SnapshotGranularity — time-granularity label

```rust
/// Time granularity label assigned to each snapshot at create time.
///
/// Used by the declarative retention evaluation to determine which
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum SnapshotGranularity {
    Hourly = 0,
    Daily = 1,
    Weekly = 2,
    Monthly = 3,
    Yearly = 4,
}
```

### 3.4 SnapshotMeta extension — per-snapshot retention fields

The existing `SnapshotMeta` from #1232 §2.2 is extended with:

```rust
/// Per-snapshot metadata (extension of #1232 §2.2).
pub struct SnapshotMeta {
    // --- Existing fields from #1232 ---
    pub snapshot_name: Vec<u8>,       // user-visible name bytes
    pub snap_commit_group: u64,                // commit_group at which snapshot was captured
    pub deadlist_root_ptr: LocatorId,
    pub deadlist_count: u64,
    pub deadlist_bytes: u64,
    pub state: u8,                    // 0 = ACTIVE, 1 = DESTROYING
    pub destroy_commit_group: u64,
    pub clone_count: u32,

    // --- New fields for #1277 ---
    /// Timestamp (wall-clock, UTC) when the snapshot was created.
    /// Used for age-based expiry and granularity labelling.
    pub created_at_unix_secs: i64,

    /// Time granularity label for declarative retention.
    pub granularity: SnapshotGranularity,

    /// Number of active send/recv streams referencing this snapshot.
    /// The auto-pruner skips snapshots with hold_count > 0.
    pub send_hold_count: u32,

    /// Whether this snapshot is pinned by user request (manual pin).
    /// Pinned snapshots are never auto-pruned.
    pub user_pinned: bool,

    // --- Aggregate fields maintained on each snapshot ---
    /// Timestamp of the next-younger snapshot, if any.
    /// Used by the auto-pruner to decide which snapshot to destroy first.
    pub next_younger_commit_group: Option<u64>,

    pub flags: u16,                   // reserved
}
```

### 3.5 Retention evaluation result

```rust
/// Result of evaluating retention policy against current snapshots.
#[derive(Clone, Debug, Default)]
pub struct RetentionEvaluation {
    /// Snapshots that are eligible for pruning, ordered oldest-first.
    pub eligible_for_prune: Vec<SnapshotName>,
    /// Reason each prunable snapshot is eligible.
    pub prune_reasons: Vec<PruneReason>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PruneReason {
    /// Snapshot exceeds max_snapshots count limit.
    OverLimit,
    /// Snapshot age exceeds max_snapshot_age_seconds.
    AgeExpired { age_seconds: u64, max_age_seconds: u64 },
    /// Dataset is in DESTROYING state — all snapshots pruned.
    DatasetDestroying,
}
```

### 3.6 SnapshotPolicy property key

```rust
/// Canonical property name for the snapshot policy.
pub const SNAPSHOT_POLICY_PROPERTY: &str = "org.tidefs:snapshot_policy";
```

## 4. Snapshot Policy Enforcement Algorithm

### 4.1 Snapshot create — pre-check

The `create_snapshot` path from the local snapshot design is extended with a
pre-creation check. This runs BEFORE the snapshot catalog entry is written,
making the check atomic with respect to the creation commit_group.

```
fn create_snapshot_pre_check(
    dataset: &DatasetRecord,
    policy: &SnapshotPolicyV1,
    current_snapshots: &[SnapshotMeta],
    now_unix_secs: i64,
) -> Result<PreCheckResult, SnapshotCreateError> {
    // Step 1: Check max_snapshots limit
    if let Some(max) = policy.max_snapshots {
        let current_count = current_snapshots.len() as u32;
        if current_count >= max {
            // Before failing, check if any expired snapshots can be
            // synchronously pruned to make room.
            let prunable = find_prunable_snapshots(
                policy, current_snapshots, now_unix_secs,
            );
            if prunable.is_empty() {
                return Err(SnapshotCreateError::SnapshotLimitReached {
                    current: current_count,
                    max,
                });
            }
            // Prune the oldest prunable snapshot synchronously
            // within this commit_group before proceeding with create.
            // This provides "make room" semantics without a
            // separate pruning commit_group.
            return Ok(PreCheckResult::PruneFirst {
                prune_target: prunable[0].clone(),
            });
        }
    }

    // Step 2: Check snapshot_reserve_bytes against available space
    if let Some(reserve) = policy.snapshot_reserve_bytes {
        let avail = dataset.space_counters.logical_avail_bytes();
        // Snapshot creation itself costs some metadata (deadlist root
        // pointer, snapshot B-tree entries), but the primary space concern
        // is future deadlist growth. The reserve ensures that even if the
        // deadlist grows to consume reserve bytes, writes are still safe.
        if avail < reserve {
            return Err(SnapshotCreateError::InsufficientReserve {
                available: avail,
                required: reserve,
            });
        }
    }

    Ok(PreCheckResult::Proceed)
}

fn find_prunable_snapshots(
    policy: &SnapshotPolicyV1,
    snapshots: &[SnapshotMeta],
    now_unix_secs: i64,
) -> Vec<SnapshotName> {
    let mut prunable = Vec::new();

    for snap in snapshots {
        // Skip pinned snapshots
        if snap.user_pinned || snap.send_hold_count > 0 {
            continue;
        }
        // Skip snapshots in DESTROYING state (already being pruned)
        if snap.state == DESTROYING {
            continue;
        }
        // Age-based: if older than max_age, it's prunable
        if let Some(max_age) = policy.max_snapshot_age_seconds {
            let age = (now_unix_secs - snap.created_at_unix_secs) as u64;
            if age > max_age {
                prunable.push(snap.snapshot_name.clone());
                continue;
            }
        }
        // (Evaluated lazily by the auto-pruner)
    }

    // Sort oldest-first
    prunable.sort_by_key(|_name| /* snap_commit_group */);
    prunable
}
```

### 4.2 Snapshot create — granularity labelling

When a snapshot is created, the system determines its time granularity
by comparing `created_at_unix_secs` against the timestamps of existing
snapshots:

```
fn assign_granularity(
    created_at: i64,
    existing_snapshots: &[SnapshotMeta],
) -> SnapshotGranularity {
    let dt = utc_datetime_from_unix(created_at);

    // Check if this is the first snapshot of the year
    let year_start = start_of_year(dt);
    if !any_snapshot_in_range(existing_snapshots, year_start, created_at) {
        return SnapshotGranularity::Yearly;
    }
    // Check if first of the month
    let month_start = start_of_month(dt);
    if !any_snapshot_in_range(existing_snapshots, month_start, created_at) {
        return SnapshotGranularity::Monthly;
    }
    // Check if first of the ISO week
    let week_start = start_of_iso_week(dt);
    if !any_snapshot_in_range(existing_snapshots, week_start, created_at) {
        return SnapshotGranularity::Weekly;
    }
    // Check if first of the day
    let day_start = start_of_day(dt);
    if !any_snapshot_in_range(existing_snapshots, day_start, created_at) {
        return SnapshotGranularity::Daily;
    }

    SnapshotGranularity::Hourly
}
```

This assignment is recorded in `SnapshotMeta.granularity` at creation time.
The auto-pruner re-evaluates granularity during each retention evaluation
tick to handle the case where an older snapshot is destroyed and a previously
hourly snapshot now becomes the daily/weekly/monthly/yearly representative.

### 4.3 Snapshot create — ordering within commit_group

Per #1267 (canonical commit ordering), snapshot creation within a commit_group
follows the established ordering contract:

1. All refcount transitions for the commit_group are applied.
2. The snapshot root is captured (committed-root summary recorded).
3. The snapshot catalog entry is written with the post-transition root.
4. The commit_group commits.

This ensures that a snapshot created in commit_group N does not observe
half-committed state from concurrent transactions.

## 5. Declarative Retention Evaluation

### 5.1 Algorithm

are eligible for pruning. It runs each tick of the auto-pruner.

```
fn evaluate_retention(
    policy: &SnapshotRetentionV1,
    snapshots: &[SnapshotMeta],
    now_unix_secs: i64,
) -> RetentionEvaluation {
    let mut eligible = Vec::new();
    let mut reasons = Vec::new();

    // Partition snapshots by granularity, sorted newest-first
    let mut hourly: Vec<&SnapshotMeta> = Vec::new();
    let mut daily: Vec<&SnapshotMeta> = Vec::new();
    let mut weekly: Vec<&SnapshotMeta> = Vec::new();
    let mut monthly: Vec<&SnapshotMeta> = Vec::new();
    let mut yearly: Vec<&SnapshotMeta> = Vec::new();

    for snap in snapshots {
        if snap.state != ACTIVE || snap.user_pinned || snap.send_hold_count > 0 {
            continue;
        }
        match snap.granularity {
            Hourly => hourly.push(snap),
            Daily  => daily.push(snap),
            Weekly => weekly.push(snap),
            Monthly => monthly.push(snap),
            Yearly => yearly.push(snap),
        }
    }

    // Sort each bucket newest-first
    for bucket in [&mut hourly, &mut daily, &mut weekly, &mut monthly, &mut yearly] {
        bucket.sort_by(|a, b| b.snap_commit_group.cmp(&a.snap_commit_group));
    }

    // Retain the newest N in each bucket
    for snap in hourly.iter().take(policy.keep_hourly as usize) {
    }
    for snap in daily.iter().take(policy.keep_daily as usize) {
    }
    for snap in weekly.iter().take(policy.keep_weekly as usize) {
    }
    for snap in monthly.iter().take(policy.keep_monthly as usize) {
    }
    for snap in yearly.iter().take(policy.keep_yearly as usize) {
    }

    // Excess snapshots in each bucket are eligible for pruning
    for snap in hourly.iter().skip(policy.keep_hourly as usize) {
        eligible.push(snap.snapshot_name.clone());
    }
    for snap in daily.iter().skip(policy.keep_daily as usize) {
        eligible.push(snap.snapshot_name.clone());
    }
    for snap in weekly.iter().skip(policy.keep_weekly as usize) {
        eligible.push(snap.snapshot_name.clone());
    }
    for snap in monthly.iter().skip(policy.keep_monthly as usize) {
        eligible.push(snap.snapshot_name.clone());
    }
    for snap in yearly.iter().skip(policy.keep_yearly as usize) {
        eligible.push(snap.snapshot_name.clone());
    }

    // Sort eligible oldest-first for destruction order
    eligible.sort_by_key(|name| {
        snapshots.iter()
            .find(|s| &s.snapshot_name == name)
            .map(|s| s.snap_commit_group)
            .unwrap_or(0)
    });

    RetentionEvaluation {
        eligible_for_prune: eligible,
        prune_reasons: reasons,
    }
}
```

### 5.2 Age-based expiry integration

Age-based expiry (`max_snapshot_age_seconds`) is evaluated first, before
declarative retention. Snapshots that exceed the age limit are marked
eligible unless `min_snapshots` would be violated.

```
fn evaluate_age_expiry(
    policy: &SnapshotPolicyV1,
    snapshots: &[SnapshotMeta],
    now_unix_secs: i64,
    evaluation: &mut RetentionEvaluation,
) {
    let max_age = match policy.max_snapshot_age_seconds {
        Some(a) => a,
        None => return,
    };
    let min_count = policy.min_snapshots.unwrap_or(0) as usize;

    let mut candidates: Vec<&SnapshotMeta> = snapshots.iter()
        .filter(|s| s.state == ACTIVE && !s.user_pinned && s.send_hold_count == 0)
        .collect();
    candidates.sort_by_key(|s| s.snap_commit_group);


    for snap in candidates.iter().take(max_deletable) {
        let age = (now_unix_secs - snap.created_at_unix_secs) as u64;
        if age > max_age {
            evaluation.eligible_for_prune.push(snap.snapshot_name.clone());
            evaluation.prune_reasons.push(PruneReason::AgeExpired {
                age_seconds: age,
                max_age_seconds: max_age,
            });
        }
    }
}
```

## 6. Auto-Prune Service

### 6.1 SnapshotAutoPruneJob

The auto-pruner runs as a BACKGROUND-lane service (#1241, priority 4) managed
by the `BackgroundScheduler` (#1179). It is registered at `Throughput` priority
(stage 3) in the background service framework.

```rust
/// BACKGROUND-lane service that incrementally destroys snapshots
pub struct SnapshotAutoPruneJob {
    /// Dataset this job operates on.
    dataset_id: DatasetId,
    /// Cached copy of the current snapshot policy.
    policy: SnapshotPolicyV1,
    /// Cached list of snapshots, refreshed each evaluation cycle.
    snapshots: Vec<SnapshotMeta>,
    /// Current retention evaluation.
    evaluation: Option<RetentionEvaluation>,
    /// Index into evaluation.eligible_for_prune for the current
    /// in-progress destroy.
    cursor: usize,
    /// Per-commit_group deadlist processing budget from #1232 §4.
    deadlist_budget: DeadlistDestroyBudget,
    /// Timestamp of last evaluation (wall clock, UTC).
    last_evaluation_unix_secs: i64,
    /// Whether this job has more work after the current tick.
    has_more: bool,
}
```

### 6.2 Tick execution

```
fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
    let now = current_unix_time();

    // Re-evaluate retention periodically (every 60s or when snapshots change)
    if self.evaluation.is_none()
        || now - self.last_evaluation_unix_secs > 60
        || self.snapshots_changed()
    {
        self.refresh_snapshots()?;
        let mut eval = evaluate_retention(&self.policy.retention, &self.snapshots, now);
        evaluate_age_expiry(&self.policy, &self.snapshots, now, &mut eval);
        self.evaluation = Some(eval);
        self.cursor = 0;
        self.last_evaluation_unix_secs = now;
    }

    let eval = self.evaluation.as_ref().unwrap();

    // Nothing to do
    if eval.eligible_for_prune.is_empty() || self.cursor >= eval.eligible_for_prune.len() {
        self.has_more = false;
        return Ok(TickReport::default());
    }

    // Destroy the next eligible snapshot (incremental, cursor-driven)
    let target_name = &eval.eligible_for_prune[self.cursor];
    let destroy_result = destroy_snapshot_incremental(
        target_name,
        &self.deadlist_budget,
        budget,
    )?;

    let mut report = TickReport::default();
    report.bookkeeping_ops = destroy_result.bookkeeping_ops;

    if destroy_result.complete {
        report.processed = 1;
        self.cursor += 1;
    } else {
        report.skipped = 1; // still in progress, retry next tick
    }

    self.has_more = self.cursor < eval.eligible_for_prune.len();
    report.has_more = self.has_more;

    Ok(report)
}

fn has_work(&self) -> bool {
    self.has_more || {
        self.evaluation.as_ref()
            .map(|e| !e.eligible_for_prune.is_empty())
            .unwrap_or(false)
    }
}
```

### 6.3 Incremental destroy integration

The `destroy_snapshot_incremental` function calls into the deadlist destroy
path from #1232 §4. Key properties:

- **Budgeted**: Each tick processes at most `deadlist_budget.max_ids` deadlist
  entries. If the deadlist has more entries, the destroy continues in the
  next tick.
- **Cursor-driven**: The deadlist destroy cursor (#1232 §4.2) is persisted.
  If the system crashes mid-destroy, the destroy resumes from the cursor on
  next mount.
- **Pinned skip**: Snapshots with `send_hold_count > 0` (#1251) or
  `user_pinned == true` are skipped by the evaluation, so they never reach
  the destroy path.
- **CommitGroup-bounded**: Each destroyed snapshot commits exactly one commit_group with
  bounded deadlist processing. The freeze + move-or-free algorithm (#1232 §4.1)
  ensures that no single commit_group processes an unbounded number of entries.

### 6.4 min_snapshots floor enforcement

The `min_snapshots` floor is enforced at two levels:

1. **Evaluation**: `evaluate_age_expiry` subtracts `min_snapshots` from the
   pruning. Even if all snapshots exceed `max_snapshot_age_seconds`, at
   least `min_snapshots` are preserved.

2. **Manual destroy**: `tidefsctl snapshot destroy` checks that the destroy
   would not reduce the snapshot count below `min_snapshots`. If it would,
   the operation is refused with an explicit error unless `--force` is
   specified (which requires admin capability).

### 6.5 Space reservation interaction

`snapshot_reserve_bytes` integrates with the space accounting model (#1215):

- The reservation is deducted from `logical_avail_bytes` before ENOSPC
  decisions for user writes.
- When a snapshot's deadlist grows (new extents pinned), the `pinned_snapshot_bytes`
  counter (#1215 §3.1) increases. This growth is bounded by `snapshot_reserve_bytes`:
  if `pinned_snapshot_bytes + new_pin > snapshot_reserve_bytes`, the pinning is
  still applied (correctness first), but a space-pressure signal is emitted to
  the cleaner (#1181).
- When snapshots are destroyed, `snapshot_reserve_bytes` is not automatically
  reduced; it remains as a policy setting until the admin changes it.

### 6.6 Dataset destroy interaction

When a dataset enters DESTROYING state (#1219), the snapshot policy is frozen:

- The auto-pruner stops ticking for this dataset.
- No new snapshots can be created.
- The dataset destroy worker (#1219 §3.3) processes all snapshots as part
  of reclamation, independent of retention policy.
- If `SnapshotAutoPruneJob.has_work()` returns true when the dataset
  transitions to DESTROYING, the job is cancelled and its cursor is discarded.
  The dataset destroy worker is responsible for snapshot cleanup from that
  point.

## 7. Observability

### 7.1 Dataset-level metrics

| Metric | Description |
|---|---|
| `tidefs_snapshot_count` | Current number of snapshots for this dataset |
| `tidefs_snapshot_limit` | Configured `max_snapshots` (0 if unset) |
| `tidefs_snapshot_oldest_age_seconds` | Age of the oldest snapshot in seconds |
| `tidefs_snapshot_pinned_bytes` | Total bytes pinned by snapshot deadlists |
| `tidefs_snapshot_reserve_bytes` | Configured `snapshot_reserve_bytes` (0 if unset) |
| `tidefs_snapshot_next_auto_prune_target` | Name of the next snapshot to auto-prune (empty if none) |
| `tidefs_snapshot_prune_eligible_count` | Number of snapshots eligible for auto-pruning |

### 7.2 Auto-pruner metrics

| Metric | Description |
|---|---|
| `tidefs_autoprune_destroyed_total` | Total snapshots destroyed by auto-pruner |
| `tidefs_autoprune_skipped_pinned_total` | Snapshots skipped due to send hold or user pin |
| `tidefs_autoprune_in_progress` | Whether an incremental destroy is in progress (1) or idle (0) |
| `tidefs_autoprune_last_tick_unix_secs` | Timestamp of the last auto-pruner tick |

### 7.3 CLI visibility

```
tidefsctl dataset snapshot-policy show <dataset>
  → displays current policy, snapshot count, oldest age, next prune target

tidefsctl dataset snapshot-policy set <dataset> \
  --max-snapshots 100 \
  --max-age-days 30 \
  --min-snapshots 10 \
  --reserve 10G \
  --retention keep_hourly=24,keep_daily=7,keep_weekly=4,keep_monthly=12,keep_yearly=5

tidefsctl dataset snapshot-policy reset <dataset>
  → clears per-dataset policy, reverts to pool defaults + pre-v0.418 behavior
```

## 8. Implementation Plan

This is a **design-spec**. Implementation is deferred to a continuation issue.

### 8.1 Implementation phases

1. **Phase A — Core types**: Define `SnapshotPolicyV1`, `SnapshotRetentionV1`,
   `SnapshotGranularity`, `RetentionEvaluation`, and `PruneReason` in a new
   crate `tidefs-types-snapshot-policy-core` or within an existing snapshot
   types crate.

2. **Phase B — Property storage**: Wire `SnapshotPolicyV1` into the per-dataset
   property system (#1253). Add encode/decode support. Implement `tidefsctl
   dataset snapshot-policy {show,set,reset}` CLI commands.

3. **Phase C — Snapshot create pre-check**: Extend the `create_snapshot` path
   with the pre-creation check (max_snapshots enforcement, space reserve
   check). Implement granularity labelling at create time.

4. **Phase D — Retention evaluation**: Implement `evaluate_retention` and
   `evaluate_age_expiry` functions. Write unit tests for edge cases
   (empty snapshot set, all snapshots expired, min_snapshots floor).

5. **Phase E — Auto-prune job**: Implement `SnapshotAutoPruneJob` as a
   `BackgroundService` (#1179). Integrate with the deadlist destroy path
   (#1232). Register with the BACKGROUND scheduler.

6. **Phase F — Observability**: Wire metrics into the observe runtime.
   Implement `tidefsctl dataset snapshot-policy show` output.

7. **Phase G — Integration tests**: Test snapshot limit enforcement, age
   expiry with min_snapshots floor, declarative retention correctness,
   auto-prune incremental destroy, send/recv hold skipping, crash recovery
   of prune cursor, and dataset destroy interaction.

### 8.2 Dependencies

- #1253 (dataset properties) must be implemented first for property storage.
- #1232 (snapshot deadlist) must be implemented for incremental destroy.
- #1215 (space accounting) must be implemented for `pinned_snapshot_bytes`
  and reservation integration.
- #1179 (background service) must be implemented for job dispatch.
- #1241 (scheduling lanes) must be implemented for BACKGROUND lane semantics.


| Gate | Description |
|---|---|
| `create-fails-at-limit` | `snapshot create` returns ENOSPC when `snapshot_count >= max_snapshots` and no expired snapshot exists |
| `create-succeeds-with-prune` | `snapshot create` succeeds when `snapshot_count >= max_snapshots` by pruning an expired snapshot first |
| `age-expiry-respects-floor` | Age-based expiry never reduces count below `min_snapshots` |
| `retention-keeps-newest-n` | Declarative retention keeps exactly the newest N snapshots per granularity |
| `retention-reassigns-granularity` | When an older yearly snapshot is destroyed, the next-oldest becomes the yearly representative |
| `autoprune-budgeted-per-tick` | Auto-prune processes `max_ids` deadlist entries per tick, not unlimited |
| `autoprune-resumes-after-crash` | Kill mid-destroy, verify prune resumes from deadlist cursor |
| `send-hold-blocks-prune` | Snapshots with active send/recv streams are never pruned |
| `user-pin-blocks-prune` | User-pinned snapshots are never auto-pruned |
| `space-reserve-blocks-writes` | Writes are refused with ENOSPC when space would dip below `snapshot_reserve_bytes` |
| `dataset-destroy-freezes-policy` | When dataset enters DESTROYING, auto-pruner stops and snapshot policy is frozen |

## 10. Design Decisions and Rationale

### 10.1 Why pre-check at create time, not post-hoc

Reactive external retention tools such as sanoid are the prior-art pressure
for this decision. The create-time pre-check target avoids a create-then-delete
window: if `snapshot_count >=
max_snapshots`, either (a) an expired snapshot is pruned within the same
commit_group to make room, or (b) create fails with ENOSPC. Either outcome is
atomic with respect to the creation commit_group.

### 10.2 Why BACKGROUND lane, not a dedicated thread

Using the BACKGROUND lane (#1241) and `BackgroundScheduler` (#1179) means
the auto-pruner shares resources with other background work (cleaning,
compaction, rebake). The unified budget prevents any single service from
hogging IO. Starvation prevention (#1241 §1.1) ensures the auto-pruner
gets at least one tick within its 60s timeout even under heavy background
load.

### 10.3 Why declarative retention, not cron-like scheduling

Cron-based retention tools are a design-pressure input because their schedule
is outside the storage transaction boundary. Declarative retention is evaluated
within the storage system itself: the auto-pruner runs on every background tick
and the policy target is enforced without relying on an external scheduler.

### 10.4 Why granularity at create time, not evaluation time

Granularity is assigned at create time for two reasons:

1. **Stability**: A snapshot's granularity should not change unexpectedly
   as other snapshots are created or destroyed. If the system labelled
   at evaluation time, a snapshot could flip between Hourly and Daily
   as the daily representative snapshot is destroyed.
2. **Efficiency**: The retention evaluation can bucket snapshots by their
   pre-assigned granularity in O(n) time rather than computing UTC
   calendar boundaries for every snapshot on every tick.

When an older granularity-representative snapshot is destroyed by the
auto-pruner, the next evaluation tick promotes the next-oldest snapshot
in that granularity bucket to the representative position.

### 10.5 Why min_snapshots is a floor, not a separate retention class

`min_snapshots` is designed as a safety floor: "age expiry won't go below
this." It's not a separate retention class because it doesn't specify
*which* snapshots to keep — only how many. The declarative retention policy
specifies which snapshots are valuable (by time granularity). `min_snapshots`
only activates as a backstop when all remaining snapshots are outside the
retention windows.

### 10.6 Why snapshot_reserve_bytes is a soft reservation

The reservation is a *soft* boundary: if `pinned_snapshot_bytes` exceeds
`snapshot_reserve_bytes`, the system does not refuse to pin new extents
(correctness first). Instead, it emits a space-pressure signal (#1181) so
the cleaner can free physical space. A hard reservation would risk
correctness violations if the system cannot pin extents that must be pinned.

## 11. References

- Local snapshots: `docs/LOCAL_SNAPSHOTS_OW108.md`
- Snapshot deadlist pinning: `docs/SNAPSHOT_DEADLIST_PINNING_DESIGN.md` (#1232)
- Space accounting model: `docs/SPACE_ACCOUNTING_MODEL_DESIGN.md` (#1215)
- Unified scheduling lanes: `docs/design/unified-scheduling-classes-lane-priority-model.md` (#1241)
- Background service framework: `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md` (#1179)
- Dataset lifecycle: `docs/DATASET_LIFECYCLE_DESIGN.md` (#1219)
- Dataset feature flags: `docs/DATASET_FEATURE_FLAGS_DESIGN.md` (#1223)
- Send/receive: `docs/SEND_RECEIVE_OW109.md` (#1251)
- COMMIT_GROUP state machine: `docs/design/canonical-commit-ordering-commit_group-state-machine.md` (#1267)
- Canonical property names: `docs/DATASET_FEATURE_FLAGS_DESIGN.md` §4.1
- Space pressure handling: `docs/design/space-pressure-handling-automatic-journal-cleaning.md` (#1181)
- Pool import/export: `docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md` (#1254)


When setting `SnapshotPolicyV1` via `tidefsctl dataset snapshot-policy set`:

1. `min_snapshots` must be `<= max_snapshots` when both are set.
2. `max_snapshot_age_seconds` must be `>= 60` (no sub-minute expiry).
3. `keep_hourly` through `keep_yearly` must each be `<= 65535` (u16 range check).
4. `snapshot_reserve_bytes` must be `>= 1 MiB` when set (minimum meaningful reservation).
5. If `max_snapshots` is set and `min_snapshots` is set, and `max_snapshots < min_snapshots`, the request is rejected with an explanatory error.

## Appendix B: Interaction with Cluster Snapshots (#1258)

In a multi-node cluster:

1. The dataset authority owns the snapshot policy. Policy changes are propagated
2. When the authority's auto-pruner destroys a snapshot, the destroy is
   Peers destroy their local copy of the snapshot asynchronously.
3. A peer that is in the middle of a send/recv stream referencing a snapshot
   that the authority wants to prune will respond with a hold notification.
   The authority's auto-pruner sees `send_hold_count > 0` and skips the
   snapshot. When the stream completes, the hold is released and the snapshot
   becomes eligible for pruning.
