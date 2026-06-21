# Scrub, Deep Scrub, Repair, and Resilver Orchestration Design

Maturity: **design-spec** for the background integrity services: budgeted
scrub scheduler, deep scrub with reconstruction verification, prioritized
repair pipeline, and parallel resilver with topology integration.

Claim boundary: the ZFS/Ceph comparison text in this design is target-design
input only. It does not prove current scrub coverage, repair correctness,
resilver performance, foreground isolation, durability, or OpenZFS/Ceph
successor behavior. Product-facing comparison wording requires #875 claim ids
and #928/#930 comparator evidence.

This document closes Forgejo issue #1288.

## 1. Motivation

Data integrity at scale requires four distinct but coordinated background
services:

| Service | Trigger | Purpose |
|---------|---------|---------|
| **Scrub** | Periodic (scheduled) | Verify checksums on all stored data |
| **Deep Scrub** | Periodic (less frequent) | Reconstruct from shards; detect silent corruption undetectable by single-replica checksums |
| **Repair** | On-read error or scrub finding | Restore redundancy from healthy replicas |
| **Resilver** | Device replacement or membership change | Restore full redundancy across new topology |

ZFS combines these into a single `dsl_scan` with a sequential tree-ordered
pass, which means scrub and resilver compete for the same IO budget and
cannot be separately prioritized. Ceph scatters them across per-PG scrub,
per-OSD backfill, and per-PG deep scrub — three separate systems with no
unified resource model.

The target TideFS design unifies all four under the background service
framework (#1179), with independent per-service budgets, priority staging,
validity-token stale-task prevention, and comprehensive observability.

### Dependency Map

| Design | Relationship |
|--------|-------------|
| #1179 Background service framework | All four services implement `BackgroundService` |
| #1287 Checksum architecture | Scrub/repair verify `IntegrityTrailerV2`; repair clears `SuspectLog` |
| #1249 Erasure coding placement | Deep scrub and repair use `ReconstructPlan` for shard-level recovery |
| #1286 Shard groups and replicas | Repair selects source replicas; resilver places new replicas |
| #1254 Pool topology management | Resilver schedules placement across new topology |
| #1180 Refcount delta cleanup | Data cleaner may trigger scrub verification on unlinked blocks |

### Mounted Transform Identity Authority

GitHub issue #637 is the current design authority for scrub and repair identity
under mounted device transforms. The issue reviewed
`docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md`, this design,
`crates/tidefs-local-filesystem/src/scrub.rs`,
`crates/tidefs-local-filesystem/src/repair.rs`, active stale-generation repair
issue #591, and placement/rebuild issue #18.

Evidence from the current implementation:

- `scrub.rs` reads inline and chunk content through `LocalObjectStore::get`,
  computes `FastBlockChecksum` over encoded chunk bytes, verifies inline
  checksum suffixes, and reports `ScrubBlockId { inode_id, data_version,
  kind }`.
- `repair.rs` consumes those `ScrubBlockId` values, reads the same raw content
  keys for truncation/reconstruction decisions, and can write reconstructed
  bytes through `LocalObjectStore::put`.
- `scrub_repair_integration.rs` maps scrub findings into `SuspectEntry`
  fields and already records missing/stale receipt evidence as blocked
  scheduling state, but the byte identity is still inherited from the raw
  local object path.
- Issue #591 owns stale-generation repair candidate rejection and remains an
  active implementation gate. Issue #18 owns placement receipts, rebuild, and
  repair source selection.

The mounted repair identity is **plaintext content identity**: the logical
mounted file or extent bytes identified by the local filesystem
`ScrubBlockId` and current `data_version`, as produced by a transform-aware
content scrub/read authority. Checksum-layer evidence remains mandatory, but it
is evidence over the exact bytes owned by the checked layer, not the identity
that authorizes mounted repair writeback.

| Candidate identity | Fit for mounted scrub/repair | Decision |
|--------------------|------------------------------|----------|
| Plaintext identity | Matches the user-visible content repair must preserve; stable across compression and encryption implementation details when bound to `ScrubBlockId` and `data_version`. | Chosen mounted product boundary. |
| Compression frame | Useful to diagnose a content-encoding or lower-store compression frame, but frame bytes vary by algorithm, level, and encoder policy and are not the logical content repair must preserve. | Lower-layer evidence only. |
| Encryption frame | Useful to validate authenticated ciphertext at the encryption layer, but nonce/tag/ciphertext identity belongs below mounted content and cannot drive truncation, mark-corrupt, or reconstruction semantics. | Lower-layer evidence only. |
| Checksum-layer identity | Required to prove which layer detected corruption; current chunk checksums are over encoded chunk bytes and inline suffixes cover encoded inline bodies. | Mandatory evidence, not standalone repair identity. |
| Raw media bytes | Useful for media diagnostics and object-store validation, but raw bytes bypass transform ordering and can select whichever raw-store path is convenient. | Not a mounted repair identity. |

The required follow-up implementation mapping is:

| Issue | Slice | Non-overlap boundary |
|-------|-------|----------------------|
| #650 | Add a transform-aware mounted content scrub/read authority. | Content reader/helper types only; no scrub or repair dispatch behavior. |
| #651 | Route local scrub through the #650 authority and report plaintext identity plus checksum-layer evidence. | `scrub.rs` and scrub tests only; no repair writeback or stale-generation behavior. |
| #652 | Gate repair scheduling/dispatch on transform-aware scrub evidence. | Repair integration/writeback consumers only; depends on #591 and must not take #18 placement source selection. |

Mounted device-level compression and encryption remain blocked until those
slices and every other production blocked row in
`docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md` are resolved.

## 2. Design Overview

The framework introduces these new abstractions:

| Abstraction | Responsibility |
|-------------|---------------|
| `ScrubCursor` | Checkpoint/resume position in the scrub namespace |
| `ScrubNamespace` | Ordered traversal space: metadata (dataset/inode) → data (extent/segment) |
| `DeepScrubVerifier` | k-of-n reconstruction verification |
| `RepairPriority` | Per-extent priority: loss-of-redundancy > historical > scheduled |
| `ResilverPlanner` | Topology-aware placement plan for degraded devices |
| `IntegrityEvent` | Unified event type for observability: scrub finding, repair outcome, resilver progress |

All four services register with the `BackgroundScheduler` with distinct priorities:

```
RepairService     → Critical (0.40 weight)
ScrubService      → Throughput (0.15 weight)
DeepScrubService  → BestEffort (0.10 weight)
ResilverService   → Throughput (0.15 weight, elevated to Critical on data-loss risk)
```

## 3. Scrub Namespace and Cursor Model

### 3.1 Namespace Ordering

The scrub namespace orders all verifiable storage by priority:

```
Level 1: Metadata
  ├── Dataset catalog (inode B-tree)
  ├── Locator tables
  ├── Extent maps
  ├── Refcount B-tree
  ├── Snapshot catalog
  └── Derived catalog (#1179)

Level 2: System metadata
  ├── Pool map journal
  ├── Spacemap checkpoint
  ├── SuspectLog (#1287)
  └── Integrity footers

Level 3: Data
  ├── Hot datasets (by I/O temperature)
  ├── Warm datasets
  └── Cold datasets

Level 4: Free/unallocated
  └── Verify SegmentIntegrityFooter chain only
```

### 3.2 ScrubCursor

```rust
/// Resumable position in the scrub namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScrubCursor {
    /// Which level of the namespace is being scrubbed.
    pub level: ScrubLevel,

    /// Dataset being scrubbed (None = system metadata).
    pub dataset_id: Option<u64>,

    /// Inode being scrubbed within the dataset.
    pub inode_id: Option<u64>,

    /// Extent/segment position within the inode or global space.
    pub extent_offset: Option<u64>,

    /// SHA-256 of the cursor for integrity verification on resume.
    pub cursor_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScrubLevel {
    Metadata = 0,
    SystemMetadata = 1,
    Data = 2,
    FreeSpace = 3,
}
```

### 3.3 Cursor Persistence

The cursor is persisted in the pool map journal at each transaction group
commit. On mount, the cursor is loaded and the scrub resumes from the
last checkpointed position.

```rust
/// On-media cursor record stored in pool map journal.
pub struct ScrubCursorRecordV1 {
    pub cursor: ScrubCursor,
    pub scrub_pass_id: u64,
    pub started_at_commit_group: u64,
    pub last_checkpoint_commit_group: u64,
    pub segments_verified: u64,
    pub segments_corrupt: u64,
    pub segments_repaired: u64,
    /// CRC32C of all preceding fields.
    pub crc32c: u32,
}
```

## 4. Scrub Service

### 4.1 Service Registration

```rust
impl BackgroundService for ScrubService {
    fn name(&self) -> &'static str { "scrub" }
    fn priority(&self) -> ServicePriority { ServicePriority::Throughput }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        let mut report = TickReport::new();
        let mut items_processed = 0;

        while budget.auth_reads_remaining() > 0
            && budget.bookkeeping_ops_remaining() > 0
            && items_processed < budget.max_items_per_tick()
        {
            let next = self.next_scrub_target()?;
            let outcome = self.verify_target(&next)?;
            self.advance_cursor(&next);
            self.record_outcome(outcome, &mut report);
            items_processed += 1;
            budget.consume_auth_read(1);
            budget.consume_bookkeeping(1);
        }

        report.items_processed = items_processed;
        report.has_more = self.has_more_work();
        Ok(report)
    }

    fn has_pending_work(&self) -> bool { self.has_more_work() }
}
```

### 4.2 Verification Pipeline

```
For each target:
  1. Read IntegrityTrailerV2 from object
  2. Verify CRC32C header sanity check
  3. Verify BLAKE3-256 payload digest
  4. For shard-group objects: verify shard-level digests
  5. On mismatch: emit ScrubViolation, queue for repair
  6. Update ScrubCursor
  7. Record tick metrics
```

### 4.3 Metadata-First Priority

Metadata is scrubbed more frequently than data because metadata corruption
can render entire datasets inaccessible:

| Metadata objects | Scrub frequency |
|-----------------|----------------|
| Dataset root B-tree | Every scrub pass |
| Locator tables | Every scrub pass |
| Extent maps | Every scrub pass |
| Refcount B-tree | Every scrub pass |
| Data extents | Every N scrub passes (configurable, default N=1) |

### 4.4 Budget Integration

The scrub service operates under a per-tick `ServiceBudget`. A full scrub
pass of a large pool may require millions of ticks. The scheduler ensures:

- No single tick runs for longer than `BACKGROUND_CYCLE_INTERVAL_MS` (100ms)
- Demand I/O is not blocked: the daemon event loop interleaves demand ops
- Progress is observable through per-service counters

## 5. Deep Scrub Service

### 5.1 Problem Statement

Single-replica checksum verification (normal scrub) can detect corruption
when the stored checksum mismatches the stored data. However, it cannot
detect scenarios where both the data and its checksum were corrupted
simultaneously (e.g., bit-rot in a checksum that was computed after the
data was already corrupt, or a firmware bug that writes corrupt data and
a matching checksum).

Deep scrub solves this by reconstructing the data from k of n shards
and comparing against the stored replica:

```
For each stripe:
  1. Read all n shards (or a subset k)
  2. Reconstruct the original data from k shards
  3. Compare reconstructed data against the stored replica
  4. If any shard disagrees with the reconstruction:
     → Mark that shard suspect
     → Attempt repair from healthy shards
```

### 5.2 Service Registration

```rust
impl BackgroundService for DeepScrubService {
    fn name(&self) -> &'static str { "deep_scrub" }
    fn priority(&self) -> ServicePriority { ServicePriority::BestEffort }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        // Deep scrub is more expensive per target: reads k shards + reconstructs
        // Budget: 1 auth read per shard, plus compute cost
        // ...
    }
}
```

### 5.3 Reconstruction Verification

```rust
pub struct DeepScrubVerifier {
    /// Placement model for determining shard locations.
    placement: Arc<TideCRUSH>,

    /// Erasure coding profile for the dataset.
    ec_profile: EcProfile,
}

impl DeepScrubVerifier {
    /// Verify one stripe by reconstructing and comparing.
    pub fn verify_stripe(
        &self,
        stripe_id: StripeId,
        store: &dyn ObjectStore,
    ) -> Result<DeepScrubOutcome, ServiceError> {
        // 1. Determine shard locations for this stripe
        let shard_locations = self.placement.locate_shards(stripe_id, &self.ec_profile);

        // 2. Read k shards (any k suffice for reconstruction)
        let mut shards = Vec::with_capacity(self.ec_profile.k as usize);
        let mut corrupt_shards = Vec::new();

        for (i, location) in shard_locations.iter().enumerate() {
            match store.get_shard(location) {
                Ok(shard) => shards.push((i, shard)),
                Err(_) => corrupt_shards.push(i),
            }
        }

        if shards.len() < self.ec_profile.k as usize {
            return Ok(DeepScrubOutcome::Unverifiable {
                reason: format!("only {} of {} shards readable", shards.len(), self.ec_profile.k),
            });
        }

        // 3. Reconstruct from k shards
        let reconstructed = self.ec_codec.decode(&shards[..self.ec_profile.k as usize])?;

        // 4. Compare all shards against reconstruction
        for (i, shard) in &shards {
            let expected = self.ec_codec.shard_slice(&reconstructed, *i);
            if shard.data != expected {
                corrupt_shards.push(*i);
            }
        }

        if corrupt_shards.is_empty() {
            Ok(DeepScrubOutcome::Clean)
        } else {
            Ok(DeepScrubOutcome::ShardMismatch {
                stripe_id,
                corrupt_shard_indices: corrupt_shards,
                healthy_shard_count: shards.len(),
            })
        }
    }
}
```

### 5.4 Deep Scrub Scheduling

Deep scrub runs less frequently than normal scrub. The scheduler provides
a natural throttling mechanism through BestEffort priority:

- Deep scrub only runs when higher-priority services (scrub, repair, view builder) are idle
- Per-tick budget limits prevent deep scrub from consuming excessive IO
- The deep scrub cursor is separate from the scrub cursor; both can advance independently

## 6. Repair Service

### 6.1 Repair Trigger Classification

Repair is triggered by three event sources:

| Trigger | Priority | Description |
|---------|----------|-------------|
| **On-read corruption** | Critical | Read path detects checksum mismatch; must repair to serve data |
| **Scrub finding** | Throughput | Periodic scrub discovers latent corruption |
| **Deep scrub finding** | BestEffort | Reconstruction reveals silent corruption |
| **Degraded read** | Critical | Read path reconstructs from shards; schedule opportunistic repair |

### 6.2 Repair Priority Model

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RepairPriority {
    /// Data loss imminent: only 1 replica remaining, or (k, m) with m=0 effective.
    LossImminent = 0,

    /// Degraded redundancy: below target replica count or below target m.
    Degraded = 1,

    /// Read-triggered: corruption discovered during demand read.
    ReadTriggered = 2,

    /// Scrub-discovered: corruption found during scheduled scrub.
    ScrubDiscovered = 3,

    /// Opportunistic: preemptive repair when resources are idle.
    Opportunistic = 4,
}
```

### 6.3 Repair Pipeline

```
For each repair task, by priority:

1. Determine repair strategy:
   - Reconstruct: enough healthy shards exist (k of k+m available)
   - Replicate: copy from healthy replica
   - Truncate: corrupt block beyond first content chunk; truncate file
   - MarkCorrupt: no redundancy available; record permanent EIO

2. Select source:
   - For reconstruction: pick k healthiest shards (by SuspectLog status)
   - For replication: pick healthiest replica (lowest suspect count)

3. Execute:
   - Read source data
   - Verify source checksum (trust but verify)
   - Write repaired data to target location
   - Update SuspectLog: clear suspect entry for repaired location
   - Update IntegrityTrailerV2 on repaired object

4. Emit observability event
```

### 6.4 Service Registration

```rust
impl BackgroundService for RepairService {
    fn name(&self) -> &'static str { "repair" }
    fn priority(&self) -> ServicePriority { ServicePriority::Critical }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        let mut report = TickReport::new();

        // Drain the repair queue, highest priority first
        while let Some(task) = self.repair_queue.pop_highest_priority() {
            if !task.expected_token.is_valid(&self.current_token_for(task.subject_id)) {
                report.items_skipped += 1;
                continue; // State changed since task was queued
            }

            let outcome = self.execute_repair(task, budget)?;
            report.record_outcome(outcome);

            if budget.is_exhausted() {
                self.repair_queue.push_front(task); // Re-queue for next tick
                break;
            }
        }

        report.has_more = !self.repair_queue.is_empty();
        Ok(report)
    }

    fn has_pending_work(&self) -> bool { !self.repair_queue.is_empty() }
}
```

### 6.5 Idempotent Repair with Validity Tokens

Repair tasks carry validity tokens derived from the suspect entry's mutation
counter. If the suspect entry is cleared (e.g., by a concurrent repair from

```rust
pub struct RepairTask {
    pub task_id: TaskId,
    pub subject_id: u64,
    pub expected_token: ValidityToken,
    pub priority: RepairPriority,
    pub strategy: RepairStrategy,
    pub source_locations: Vec<ShardLocation>,
    pub target_location: ShardLocation,
    pub queued_at_tick: u64,
}
```

## 7. Resilver Service

### 7.1 What Resilver Is

Resilver restores full data redundancy after a topology change:

| Event | Resilver Action |
|-------|----------------|
| Device failure | Rebuild all stripes that had shards on the failed device |
| Device replacement | Rebuild onto the new device |
| Device addition | Rebalance: relocate shards to the new device for balanced capacity |
| Node removal | Rebuild all stripes with shards on removed node's devices |
| Pool expansion | Rebalance across new devices |

### 7.2 ZFS Comparison

ZFS resilver is sequential and tree-ordered: `dsl_scan` walks the entire
pool's block tree in birth-commit_group order, rebuilding only blocks that reference
the replaced device. This has two problems:

1. **Sequential bottleneck**: a single-threaded scan limits rebuild throughput
   to ~500 MB/s even on NVMe pools
2. **No prioritization**: the root dataset's metadata and a cold snapshot's
   data are rebuilt with equal urgency

tidefs resilver is stripe-parallel and priority-sorted:

1. **Stripe-parallel**: the resilver planner produces a priority-sorted list
   of stripes to rebuild; multiple stripes can be in-flight simultaneously
2. **Priority-sorted**: stripes affecting mounted datasets are rebuilt first;
   cold snapshots last
3. **Budgeted**: the resilver service operates under the background service
   budget, interleaved with demand I/O

### 7.3 Resilver Planner

```rust
pub struct ResilverPlanner {
    /// Topology snapshot at the time the resilver was triggered.
    topology: PoolTopology,

    /// The loss event that triggered the resilver.
    loss_event: LossEvent,

    /// Cached stripe-to-device mapping for efficient lookup.
    stripe_map: StripeDeviceMap,
}

impl ResilverPlanner {
    /// Build the priority-sorted rebuild plan.
    pub fn build_plan(&self) -> Result<ResilverPlan, ServiceError> {
        let mut stripes = Vec::new();

        // 1. Identify affected stripes
        for device in &self.loss_event.affected_devices {
            stripes.extend(self.stripe_map.stripes_on_device(device));
        }

        // 2. Deduplicate (a stripe may span multiple affected devices)
        stripes.sort();
        stripes.dedup();

        // 3. Assign priority
        let mut plan = ResilverPlan::new();
        for stripe_id in &stripes {
            let priority = self.compute_priority(stripe_id);
            plan.add_stripe(*stripe_id, priority);
        }

        // 4. Sort by priority
        plan.sort_by_priority();

        Ok(plan)
    }

    fn compute_priority(&self, stripe_id: &StripeId) -> ResilverPriority {
        // Mounted datasets → Critical
        if self.is_mounted_dataset_stripe(stripe_id) {
            return ResilverPriority::Critical;
        }
        // Hot datasets → Throughput
        if self.is_hot_dataset_stripe(stripe_id) {
            return ResilverPriority::Throughput;
        }
        // Snapshots → BestEffort
        ResilverPriority::BestEffort
    }
}
```

### 7.4 Service Registration

```rust
impl BackgroundService for ResilverService {
    fn name(&self) -> &'static str { "resilver" }
    fn priority(&self) -> ServicePriority {
        if self.has_data_loss_risk() {
            ServicePriority::Critical  // Elevate when redundancy is compromised
        } else {
            ServicePriority::Throughput
        }
    }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        let mut report = TickReport::new();

        while let Some(stripe) = self.plan.next_stripe() {
            // Verify stripe is still degraded (topology may have changed)
            if !self.is_still_degraded(&stripe) {
                report.items_skipped += 1;
                continue;
            }

            let outcome = self.resilver_stripe(&stripe, budget)?;
            report.record_outcome(outcome);

            if budget.is_exhausted() {
                break;
            }
        }

        report.has_more = self.plan.has_remaining();
        Ok(report)
    }

    fn has_pending_work(&self) -> bool { self.plan.has_remaining() }
}
```

### 7.5 Resilver Budget Model

The resilver budget is separate from the global background budget to prevent
resilver from starving scrub:

```rust
pub struct ResilverBudget {
    /// Max stripes to rebuild per tick.
    pub max_stripes_per_tick: u32,

    /// Max bytes to transfer per tick.
    pub max_bytes_per_tick: u64,

    /// Max I/O operations per tick (reads + writes).
    pub max_io_ops_per_tick: u64,
}

impl Default for ResilverBudget {
    fn default() -> Self {
        Self {
            max_stripes_per_tick: 100,
            max_bytes_per_tick: 64 * 1024 * 1024,  // 64 MiB
            max_io_ops_per_tick: 1000,
        }
    }
}
```

## 8. Integration with Checksum Architecture (#1287)

### 8.1 SuspectLog Interaction

The `SuspectLog` from #1287 is the shared state between scrub, repair, and
the read path:

```
Scrub:     discovers mismatch → appends SuspectEntry to SuspectLog
Read path: checks SuspectSet → skips suspect replica, tries next
Repair:    executes repair    → removes SuspectEntry from SuspectLog
Deep scrub: discovers silent mismatch → appends SuspectEntry
```

### 8.2 IntegrityTrailerV2 Fields Used

The scrub service reads these fields from `IntegrityTrailerV2`:

| Field | Used by |
|-------|---------|
| `header_crc32c` | Sanity check before reading payload |
| `payload_blake3` | Primary integrity verification |
| `shard_index` | Identify which shard this is for reconstruction |
| `shard_count` | Know how many shards to expect |
| `ec_k`, `ec_m` | Reconstruction parameters |

## 9. Observability Contract

### 9.1 Scrub Counters

| Counter | Type | Description |
|---------|------|-------------|
| `scrub_objects_verified_total` | Counter | Total objects verified |
| `scrub_bytes_verified_total` | Counter | Total bytes verified |
| `scrub_corruptions_found_total` | Counter | Checksum mismatches discovered |
| `scrub_pass_complete` | Gauge | 1 when a full pass completes |
| `scrub_pass_duration_seconds` | Histogram | Wall time for a full pass |
| `scrub_cursor_level` | Gauge | Current scrub level (0-3) |
| `scrub_pass_id` | Gauge | Monotonically increasing pass ID |

### 9.2 Repair Counters

| Counter | Type | Description |
|---------|------|-------------|
| `repair_tasks_queued_total` | Counter | Repair tasks queued |
| `repair_tasks_completed_total` | Counter | Repairs successfully executed |
| `repair_tasks_failed_total` | Counter | Repairs that could not be completed |
| `repair_bytes_reconstructed_total` | Counter | Bytes reconstructed from shards |
| `repair_bytes_replicated_total` | Counter | Bytes copied from healthy replicas |
| `repair_queue_depth` | Gauge | Current repair queue depth |
| `repair_loss_imminent_count` | Gauge | Stripes with only 1 replica remaining |

### 9.3 Resilver Counters

| Counter | Type | Description |
|---------|------|-------------|
| `resilver_stripes_total` | Counter | Total stripes needing rebuild |
| `resilver_stripes_completed_total` | Counter | Stripes rebuilt |
| `resilver_bytes_transferred_total` | Counter | Bytes transferred |
| `resilver_progress_pct` | Gauge | Percentage complete (0-100) |
| `resilver_active` | Gauge | 1 while resilver is in progress |
| `resilver_eta_seconds` | Gauge | Estimated time to completion |

## 10. ZFS and Ceph Comparison

### 10.1 Integrity Service Models

| Dimension | ZFS | Ceph | tidefs |
|-----------|-----|------|--------|
| **Scrub** | `dsl_scan` — sequential metaslab, single-threaded | `pg_scrub` — per-PG shallow + deep | `ScrubService` — budgeted, cursor-resumable, metadata-first |
| **Deep scrub** | None built-in (relies on checksum verification only) | `pg_deep_scrub` — reads all replicas, compares | `DeepScrubService` — reconstructs from shards, detects silent corruption |
| **Repair** | `zio_checksum_error` → `self_heal` from mirror/redundancy | `pg_repair` — per-PG, PG-local only | `RepairService` — priority-sorted queue, validity-token idempotent |
| **Resilver** | `dsl_scan` resilver mode — sequential, tree-ordered | `pg_backfill` — per-PG, PG-local | `ResilverService` — stripe-parallel, priority-sorted, topology-aware |
| **Scheduling** | Single scanner; scrub and resilver share one thread | Per-PG independent; no global coordination | Unified `BackgroundScheduler` with per-service budgets |
| **Progress** | `zpool status` — single percentage | `ceph status` — PG state counts | Per-service counters + aggregate dashboard |
| **Prioritization** | Birth-commit_group order only | Per-PG priority via OSD config | Metadata-first scrub; dataset-hotness; mounted-first resilver |
| **Idempotency** | None — repeated scans re-verify everything | None — repeated scrubs re-do work | Validity tokens prevent rework on known-good data |

### 10.2 Target Design Differences

These bullets capture design intent and prior-art lessons. They are not current
evidence that TideFS outperforms ZFS or Ceph for scrub, repair, or resilver.

1. **Stripe-parallel resilver**: ZFS sequential resilver is the baseline this
   design reacts to. TideFS targets a priority-sorted stripe list and multiple
   concurrent stripe rebuilds within per-tick budgets.
2. **Deep scrub with reconstruction**: The target design uses k-of-n shard
   reconstruction as an independent reference for deep scrub. This remains a
   planned detection model, not a validated data-integrity guarantee.
3. **Unified observability**: ZFS exposes `zpool status` and Ceph exposes PG
   counters. TideFS targets per-service counters feeding a unified scheduler
   dashboard.
4. **Idempotent repair**: TideFS targets validity tokens so already-repaired
   tasks can be skipped when the token still identifies the same subject.
5. **Budget cascading**: The target scheduler cascades idle repair budget to
   scrub and idle scrub budget to deep scrub, subject to demand-I/O isolation
   evidence before any performance claim is made.

### 10.3 Target Matches and Deferrals

1. **Checksum-gated repair**: ZFS, Ceph, and the TideFS target design verify
   source data before using it for repair.
2. **Cursor-based resumability**: ZFS scan checkpoints and the target TideFS
   `ScrubCursor` are comparable restart/resume design points.
3. **Demand-read repair**: All three designs include a read-path checksum
   mismatch as a repair trigger, but this document does not claim current
   TideFS repair dispatch authority.

## 11. Implementation Strategy

### 11.1 Phases

| Phase | Scope | Dependencies |
|-------|-------|-------------|
| **Phase 1: Core types** | `ScrubCursor`, `ScrubCursorRecordV1`, `ScrubNamespace`, `RepairPriority`, `ResilverPriority`, `ResilverBudget` | #1179 types |
| **Phase 2: ScrubService** | `ScrubService` as `BackgroundService`, cursor advancement, checksum verification loop | Phase 1, #1287 |
| **Phase 3: RepairService** | `RepairService` as `BackgroundService`, priority queue, repair pipeline | Phase 1, #1287, #1249 |
| **Phase 4: DeepScrubService** | `DeepScrubService` as `BackgroundService`, `DeepScrubVerifier`, reconstruction comparison | Phase 1-2, #1249 |
| **Phase 5: ResilverService** | `ResilverService` as `BackgroundService`, `ResilverPlanner`, stripe-parallel rebuild | Phase 1, #1254, #1249 |
| **Phase 6: SuspectLog integration** | Wire scrub/repair/resilver into SuspectLog from #1287 | Phase 2-5, #1287 |
| **Phase 7: Observability** | All per-service counters and scheduler aggregates | Phase 2-5, #827 |
| **Phase 8: Integration** | Register all services with BackgroundScheduler in daemon main loop | Phase 2-5, #1179 |
| **Phase 9: Cursor persistence** | Pool map journal integration for scrub/resilver cursors | Phase 2, #1254 |

### 11.2 Crate Boundaries

```
crates/tidefs-scrub-types/       -- Phase 1: cursor + namespace + priority types
crates/tidefs-scrub-service/     -- Phase 2: ScrubService implementation
crates/tidefs-repair-service/    -- Phase 3: RepairService implementation
crates/tidefs-deep-scrub/        -- Phase 4: DeepScrubService + verifier
crates/tidefs-resilver-service/  -- Phase 5: ResilverService + planner
```

## 12. Deterministic Constraint Knobs

| Constant | Default | Meaning |
|----------|---------|---------|
| `SCRUB_MAX_ITEMS_PER_TICK` | 1000 | Max objects verified per scrub tick |
| `DEEP_SCRUB_MAX_STRIPES_PER_TICK` | 100 | Max stripes verified per deep scrub tick |
| `REPAIR_MAX_TASKS_PER_TICK` | 50 | Max repairs executed per tick |
| `RESILVER_MAX_STRIPES_PER_TICK` | 100 | Max stripes rebuilt per resilver tick |
| `RESILVER_MAX_BYTES_PER_TICK` | 64 MiB | Max bytes transferred per resilver tick |
| `RESILVER_MAX_IO_OPS_PER_TICK` | 1000 | Max I/O ops per resilver tick |
| `SCRUB_PASS_INTERVAL_HOURS` | 168 | Hours between full scrub passes (7 days) |
| `DEEP_SCRUB_PASS_INTERVAL_HOURS` | 720 | Hours between full deep scrub passes (30 days) |
| `METADATA_SCRUB_FREQUENCY_MULTIPLIER` | 4 | Metadata scrubbed N× more often than data |
| `RESILVER_CRITICAL_THRESHOLD` | 1 | Remaining replicas below which resilver elevates to Critical |

## 13. Error Hierarchy

```rust
pub enum ScrubError {
    /// Object could not be read from storage.
    ReadFailed { object_id: u64, reason: String },

    /// Checksum verification revealed corruption.
    CorruptionDetected {
        object_id: u64,
        expected: [u8; 32],
        actual: [u8; 32],
    },

    /// Cursor could not be persisted.
    CursorPersistFailed { reason: String },

    /// Scrub pass was aborted (e.g., pool export).
    PassAborted { reason: String },
}

pub enum RepairError {
    /// No healthy source available for reconstruction/replication.
    NoHealthySource { stripe_id: StripeId },

    /// Reconstruction failed (not enough shards).
    ReconstructionFailed { stripe_id: StripeId, available: usize, needed: usize },

    /// Write of repaired data failed.
    WriteFailed { location: ShardLocation, reason: String },

    /// SuspectLog update failed.
    SuspectLogUpdateFailed { reason: String },
}

pub enum ResilverError {
    /// Plan building failed.
    PlanBuildFailed { reason: String },

    /// Stripe rebuild failed.
    StripeRebuildFailed { stripe_id: StripeId, reason: String },

    /// Topology changed during resilver.
    TopologyChanged { reason: String },
}
```

## 14. Open Questions

1. **Should scrub and deep scrub share a single cursor or maintain separate cursors?**
   Separate cursors allow different scheduling frequencies (metadata-first for
   scrub, stripe-oriented for deep scrub). Recommendation: separate cursors,
   each with its own pass interval.

2. **Should the resilver service suspend scrub during rebuild?**
   ZFS suspends scrub during resilver because they share the same scan thread.
   tidefs has separate services, so scrub can continue at lower priority.
   Recommendation: do not suspend scrub; let the scheduler cascade unused
   budget naturally.

3. **Should deep scrub be opt-in or always-on?**
   Deep scrub has higher IO cost (k reads per stripe vs 1 read per object).
   Recommendation: always-on but at BestEffort priority (only runs when
   higher-priority services are idle). Operator can disable via pool property.

4. **How to handle concurrent scrub and repair on the same object?**
   Both services use validity tokens. If scrub discovers corruption and
   queues a repair, the repair task carries a validity token. If scrub
   reaches the same object again before repair executes, the token will
   still be valid (the suspect entry exists). If repair executes first and
   clears the suspect entry, scrub's token becomes invalid and the object
   is skipped.

5. **Should resilver use the erasure coding or replication path for source reads?**
   For replicated data: read from healthiest replica. For erasure-coded data:
   reconstruct from k healthiest shards. Recommendation: use the same
   source-selection logic as the repair service for consistency.

## 15. References

- [#1288] This design spec
- [#1179] Background service framework — all services implement `BackgroundService`
- [#1287] End-to-end checksum architecture — `IntegrityTrailerV2`, `SuspectLog`
- [#1249] Erasure coding and CRUSH-like placement — reconstruction, shard location
- [#1286] Shard groups, replicas, and rebake pathway — source selection
- [#1254] Pool import/export and topology management — resilver placement
- [#1180] Refcount delta cleanup queues — data cleaner interaction
- [#827] Structural observability — counter emission
- GitHub #637 — mounted transform scrub/repair identity decision
- GitHub #650 — mounted content scrub/read authority implementation slice
- GitHub #651 — local scrub transform-aware identity consumer
- GitHub #652 — repair dispatch transform-aware evidence gate
- GitHub #591 — stale-generation repair candidate rejection
- GitHub #18 — placement receipts, rebuild, and repair source selection
- `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md`
- `docs/CHECKSUM_ARCHITECTURE_DESIGN.md`
- `docs/ERASURE_CODING_PLACEMENT_DESIGN.md`
- Existing code: `crates/tidefs-local-filesystem/src/scrub.rs` (612 lines)
- Existing code: `crates/tidefs-local-filesystem/src/repair.rs` (630 lines)
- Existing code: `crates/tidefs-local-filesystem/src/recovery.rs` (1761 lines)
