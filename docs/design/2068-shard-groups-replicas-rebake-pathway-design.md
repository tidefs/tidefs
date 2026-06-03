# Shard Groups, Replicas, and Rebake Pathway — Design Specification (#2068)

**Status: Design-Spec** — Maturity: **design-spec** for the distributed extent
redundancy model: `ShardGroupV1` erasure-coded shards, ingest-replica lifecycle
with durability ladder, and budgeted background `RebakeService` converting
ingest extents into base shards. Rust implementation deferred to wire-up issues.

**Issue:** #2068
**Sealed spec reference:** #2030 (`docs/design/shard-groups-replicas-rebake-design-spec.md`)
**Lane:** storage-core
**Kind:** design
**Date:** 2026-05-05

---

## 0. Relationship to Sealed Spec #2030

The sealed specification at `docs/design/shard-groups-replicas-rebake-design-spec.md`
(#2030) is the authoritative reference for the shard-group model, replica lifecycle,
and rebake pathway. This document (#2068) provides the canonical architecture summary,
data-structure definitions, algorithmic descriptions, and tradeoff analysis for
implementers. It does not supersede #2030; both documents are consistent. Where this
document is silent, #2030 governs.

---

## 1. Architecture

### 1.1 System Context

```
┌──────────────────────────────────────────────────────────────┐
│                      FUSE / POSIX Adapter                    │
│  write(2) → posix_filesystem_adapter_ingress                │
└──────────────────────┬───────────────────────────────────────┘
                       │ ingest extent (single-device, low latency)
                       ▼
┌──────────────────────────────────────────────────────────────┐
│                  Local Object Store                          │
│  append to ingest journal → ExtentLocatorValueV1 (Ingest)   │
│                      ▲                                       │
│                      │ durability ladder monitors replica    │
│                      │ counts, triggers emergency rebake     │
└──────────────────────┼───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│                   RebakeService                              │
│  BackgroundService: per-tick budget, reads ingest extents,   │
│  encodes k+m shards via ErasureCoding, places via TideCRUSH, │
│  writes shards to target devices, atomically updates locator │
└──────────────────────┬───────────────────────────────────────┘
                       │ base shards (k+m, distributed)
                       ▼
┌──────────────────────────────────────────────────────────────┐
│              ErasureCodedStore / ReplicatedObjectStore       │
│  k data shards + m parity shards across distinct devices    │
│  Read: any k surviving shards → reconstruct original data   │
│  Repair: read k healthy → rebuild missing/corrupt shard      │
└──────────────────────────────────────────────────────────────┘
```

### 1.2 Component Responsibilities

| Component | Crate(s) | Responsibility |
|-----------|----------|---------------|
| `ShardGroupV1` | `tidefs-types-locator-table-core` | On-media encoding of k+m shard layout, shard metadata, integrity trailers |
| `ReplicaLifecycle` | `tidefs-types-extent-map-core` | State machine: Ingest → Rebaking → BaseComplete → Trimming → Done |
| `RebakeService` | `tidefs-rebake` (new) | Background service: select candidates, encode, place, write, update locator |
| `ErasureCoding` | `tidefs-erasure-coding` | GF(2^8) Reed-Solomon encode/decode; `encode(data, k, m) → [shard]` |
| `ErasureCodedStore` | `tidefs-erasure-coded-store` | Store/retrieve/repair data+parity shards |
| `PlacementPlanner` | `tidefs-placement-planner` | TideCRUSH: map shard index → (device, segment, offset) |
| `DurabilityMonitor` | `tidefs-rebake` (new) | Periodic durability-level computation; emergency rebake escalation |
| `IntegrityTrailerV2` | `tidefs-binary_schema-checksum` | Per-shard BLAKE3 digest, COMMIT_GROUP, shard index |

### 1.3 Data Flow

```
1. Write arrives → ingest extent written to single device
2. ExtentLocatorValueV1 created: lifecycle=Ingest, replica_count=1
3. DurabilityMonitor observes Ingest extents, computes durability level
4. RebakeService::tick():
   a. Select candidate extents (lifecycle=Ingest, meets rebake policy)
   b. Read ingest data from source device
   c. ErasureCode::encode(data, k, m) → [k+m shards]
   d. PlacementPlanner::place(shard_index) → (device, segment, offset)
   e. Write each shard to target device with IntegrityTrailerV2
   f. Verify all k+m shards written successfully
   g. Atomically update ExtentLocatorValueV1:
      - lifecycle → BaseComplete
      - replica_placement → [ShardPlacement; k+m]
      - flags → SHARDED | ERASURE_CODED
5. SegmentCleanerService trims ingest fragments (only when BaseComplete confirmed)
6. DurabilityMonitor recomputes dataset durability post-rebake
```

---

## 2. Data Structures

### 2.1 ShardGroupV1 (on-media)

```
ShardGroupV1 {
    magic: [u8; 4] = b"SGRP",
    version: u16 = 1,
    extent_id: ExtentId,
    total_data_bytes: u64,
    shard_count: u8,        // k + m
    data_shards: u8,        // k
    parity_shards: u8,      // m
    shard_size: u32,        // bytes per shard (before padding)
    stripe_width: u32,      // bytes per stripe for multi-stripe extents
    ec_algorithm: EcAlgorithm,
    flags: ShardGroupFlags,
    shard_table: [ShardDescriptor; shard_count],
    commit_group: CommitGroupId,
    checksum: BLAKE3_OUTPUT_LEN,
}
```

| Field | Size | Description |
|-------|------|-------------|
| `shard_index` | u16 | 0..k-1 = data, k..k+m-1 = parity |
| `shard_device` | u64 | Target device GUID |
| `shard_segment` | u64 | Segment ID on target device |
| `shard_offset` | u64 | Byte offset within segment |
| `shard_length` | u64 | Padded shard length (bytes) |
| `shard_digest` | [u8; 32] | BLAKE3-256 of shard content |

### 2.2 ExtentLifecycleState Extensions

```rust
pub enum ExtentLifecycleState {
    Ingest,           // single-device append journal
    Rebaking,         // RebakeService actively encoding/placing
    BaseComplete,     // k+m shards written, verifiable
    Trimming,         // SegmentCleaner reclaiming ingest space
    Done,             // fully rebaked, ingest space freed
    Corrupt,          // unrecoverable (fewer than k shards readable)
}
```

### 2.3 ExtentLocatorValueV1 Extensions

```rust
pub struct ExtentLocatorValueV1 {
    // existing fields
    pub extent_id: ExtentId,
    pub lifecycle: ExtentLifecycleState,
    pub locator_flags: LocatorFlags,
    // NEW: shard-group redundancy
    pub shard_group: Option<ShardGroupDescriptor>,
    pub replica_placement: Vec<ReplicaPlacement>,  // per-device shard placements
}

pub struct ShardGroupDescriptor {
    pub k: u8,
    pub m: u8,
    pub shard_size: u32,
    pub ec_algorithm: EcAlgorithm,
    pub stripe_width: u32,
    pub total_data_bytes: u64,
}
```

### 2.4 ShardPlacement (existing in `tidefs-types-locator-table-core`)

```rust
pub struct ShardPlacement {
    pub shard_index: u16,
    pub segment_id: u64,
    pub grain_offset: u64,
    pub grain_count: u64,
}
```

### 2.5 ReplicaHealth (existing)

```rust
pub enum ReplicaHealth {
    Online,    // device reachable, shard readable
    Degraded,  // device reachable but slow/error-prone
    Offline,   // device unreachable
    Retired,   // device permanently removed
    Corrupt,   // shard digest mismatch
}
```

### 2.6 DurabilityLevel

```rust
pub enum DurabilityLevel {
    Optimal,        // all k+m shards healthy
    Degraded,       // ≥ k shards healthy, some parity missing
    Critical,       // exactly k shards healthy (no parity margin)
    LossImminent,   // < k shards healthy → data at risk
}

impl DurabilityLevel {
    pub fn compute(healthy_data: u8, healthy_parity: u8, k: u8) -> Self {
        let total_healthy = healthy_data + healthy_parity;
        if total_healthy >= k + 1 && healthy_data >= k {
            Self::Optimal
        } else if healthy_data >= k && total_healthy == k {
            Self::Critical
        } else if healthy_data >= k {
            Self::Degraded
        } else {
            Self::LossImminent
        }
    }
}
```

### 2.7 RebakeCandidate

```rust
pub struct RebakeCandidate {
    pub extent_id: ExtentId,
    pub locator_id: LocatorId,
    pub total_bytes: u64,
    pub ingest_age: Duration,        // time since ingest write
    pub dataset_durability: DurabilityLevel,
    pub priority: RebakePriority,
}

pub enum RebakePriority {
    Background = 0,   // normal budgeted rebake
    Expedited = 1,    // durability approaching Critical
    Emergency = 2,    // LossImminent or Critical
}
```

---

## 3. Algorithms

### 3.1 RebakeService::tick()

```
fn tick(budget: ServiceBudget, token: ValidityToken) -> Result<RebakeTickOutcome> {
    let mut remaining = budget;
    let mut rebaked = 0u64;

    // Phase 0: Emergency check
    if durability_monitor.level() <= DurabilityLevel::Critical {
        remaining = remaining.with_priority_boost(EMERGENCY_MULTIPLIER);
    }

    // Phase 1: Select candidates ordered by priority, then ingest age
    let candidates = select_candidates(remaining.bytes());

    for candidate in candidates {
        // Phase 2: Atomically mark Rebaking
        if !locator_table.try_mark_rebaking(candidate.extent_id, token)? {
            continue; // concurrent rebaker claimed it
        }

        // Phase 3: Read ingest data
        let ingest_data = read_ingest_extent(candidate.locator_id)?;

        // Phase 4: Erasure-code encode
        let (k, m) = dataset.erasure_profile();
        let parity = erasure_coding.encode(&ingest_data, k, m)?;
        let shards: Vec<Vec<u8>> = split_data(&ingest_data, k)
            .chain(parity)
            .collect();

        // Phase 5: Place and write shards
        let placements = placement_planner.place_shards(
            candidate.extent_id, k, m, token
        )?;

        let mut write_results = Vec::with_capacity((k + m) as usize);
        for (i, (shard, placement)) in shards.iter().zip(&placements).enumerate() {
            let trailer = IntegrityTrailerV2::new(shard, i as u16, candidate.extent_id, token.commit_group);
            let result = write_shard(placement, shard, &trailer)?;
            write_results.push(result);
        }

        // Phase 6: Verify all writes
        if !write_results.iter().all(|r| r.is_ok()) {
            // Abort: leave lifecycle as Rebaking for retry
            remaining.subtract(shards.len() as u64 * SHARD_IO_COST);
            continue;
        }

        // Phase 7: Atomic locator update (COMMIT_GROUP-committed)
        locator_table.commit_rebake(
            candidate.extent_id,
            ShardGroupDescriptor { k, m, shard_size, ec_algorithm, stripe_width, total_data_bytes },
            placements,
            token,
        )?;

        rebaked += 1;
        remaining.subtract(candidate.total_bytes);

        if remaining.exhausted() {
            break;
        }
    }

    Ok(RebakeTickOutcome { rebaked, remaining_budget: remaining })
}
```

### 3.2 Candidate Selection Policy

```
fn select_candidates(budget_bytes: u64) -> Vec<RebakeCandidate> {
    let mut candidates = Vec::new();
    let mut accumulated = 0u64;

    for extent in locator_table.iter_ingest_extents()
        .filter(|e| e.dataset().rebake_policy().applies(e))
    {
        let durability = durability_monitor.dataset_level(extent.dataset_id);
        let priority = match durability {
            DurabilityLevel::LossImminent => RebakePriority::Emergency,
            DurabilityLevel::Critical => RebakePriority::Emergency,
            DurabilityLevel::Degraded => RebakePriority::Expedited,
            DurabilityLevel::Optimal => RebakePriority::Background,
        };

        candidates.push(RebakeCandidate {
            extent_id: extent.id,
            locator_id: extent.locator_id,
            total_bytes: extent.total_bytes,
            ingest_age: extent.age(),
            dataset_durability: durability,
            priority,
        });

        accumulated += extent.total_bytes;
        if accumulated >= budget_bytes {
            break;
        }
    }

    // Sort: Emergency first, then Expedited, then Background; within tier, oldest first
    candidates.sort_by_key(|c| (c.priority as u8, std::cmp::Reverse(c.ingest_age)));
    candidates
}
```

### 3.3 DurabilityMonitor

```
fn compute_dataset_durability(dataset_id: DatasetId) -> DurabilityLevel {
    let mut total_extents = 0u64;
    let mut at_risk = 0u64;
    let mut critical = 0u64;
    let mut degraded = 0u64;

    for extent in locator_table.iter_dataset_extents(dataset_id) {
        total_extents += 1;
        let healthy = extent.count_healthy_shards();
        let k = extent.shard_group.map(|sg| sg.k).unwrap_or(0);

        if k == 0 {
            // Ingest extent: count as at-risk
            at_risk += 1;
        } else if healthy < k {
            at_risk += 1;
        } else if healthy == k {
            critical += 1;
        } else if healthy < k + extent.shard_group.map(|sg| sg.m).unwrap_or(0) {
            degraded += 1;
        }
    }

    if at_risk > 0 {
        DurabilityLevel::LossImminent
    } else if critical > total_extents / 10 {
        DurabilityLevel::Critical
    } else if degraded > 0 {
        DurabilityLevel::Degraded
    } else {
        DurabilityLevel::Optimal
    }
}
```

### 3.4 Read Path: Shard Assembly

```
fn read_extent(extent_id: ExtentId) -> Result<Vec<u8>> {
    let locator = locator_table.get(extent_id)?;

    match locator.lifecycle {
        ExtentLifecycleState::Ingest | ExtentLifecycleState::Rebaking => {
            // Read from ingest location (single device)
            read_from_ingest_journal(locator)
        }
        ExtentLifecycleState::BaseComplete | ExtentLifecycleState::Trimming
        | ExtentLifecycleState::Done => {
            // Read from base shards
            let sg = locator.shard_group.ok_or(Error::NoShardGroup)?;
            let mut shards = Vec::with_capacity(sg.k as usize);

            for i in 0..sg.k {
                match read_shard(locator, i) {
                    Ok(data) => shards.push(data),
                    Err(_) => {
                        // Try reconstructing from parity
                        let recovered = reconstruct_shard(locator, i, &sg)?;
                        shards.push(recovered);
                    }
                }
                if i >= sg.k as usize {
                    break;
                }
            }

            erasure_coding.decode(&shards, sg.k, sg.m, sg.total_data_bytes)
        }
        ExtentLifecycleState::Corrupt => Err(Error::ExtentCorrupt),
    }
}
```

### 3.5 Crash Safety: Atomic Rebake Commit

The rebake commit is atomic with respect to crashes:

1. Before writing shards: locator lifecycle = `Rebaking` (crash → re-queue for next tick)
2. After all shards written and verified: locator lifecycle = `BaseComplete` in a single COMMIT_GROUP-committed update
3. Orphaned shards (written but never committed) are garbage-collected by `SegmentCleanerService` when no locator entry references them

---

## 4. Durability Ladder

### 4.1 Per-Dataset Redundancy Policy

| Level | Min Replicas | Min Healthy Shards | Write Behavior |
|-------|-------------|-------------------|----------------|
| `none` | 1 | — | No redundancy; no rebake; data-at-risk after any failure |
| `replicated_2` | 2 | 2 | 2-copy replication at ingest |
| `replicated_3` | 3 | 3 | 3-copy replication at ingest |
| `ec_2_1` | — | k=2, m=1 | Erasure-coded: tolerate 1 failure |
| `ec_4_2` | — | k=4, m=2 | Erasure-coded: tolerate 2 failures |
| `ec_8_3` | — | k=8, m=3 | Erasure-coded: tolerate 3 failures |

### 4.2 Durability State Transitions

```
Optimal ──(shard failure)──▶ Degraded ──(shard failure)──▶ Critical ──(shard failure)──▶ LossImminent
    ▲                            │                            │
    │                            │                            │
    └──(repair/rebake)───────────┴──(repair/rebake)──────────┘
```

### 4.3 Emergency Rebake Triggers

| Trigger | Action |
|---------|--------|
| DurabilityLevel::Critical | Boost `RebakeService` budget by 4× |
| DurabilityLevel::LossImminent | Boost budget by 16×; block new writes to affected dataset |
| Device failure with ingest extents | Immediately queue all ingest extents on failed device |
| Pool import after crash | Reconstruct rebake queue from all Ingest lifecycle locators |

---

## 5. Tradeoffs

### 5.1 Write Latency vs. Durability Window

**Tradeoff:** tidefs accepts a durability window (ingest extents are single-copy until rebake
completes) in exchange for minimal write latency and no write amplification at ingest time.

**Mitigation:** The durability ladder monitors the window. If the ingest-to-rebake lag grows
or devices fail, emergency rebake escalates priority. At `LossImminent`, writes are blocked
(operator-overridable).

**Comparison:**
- ZFS: zero durability window but pays k+m write amplification on every write
- Ceph: zero durability window but pays replication hop latency on every write
- tidefs: small durability window (seconds to minutes), zero write amplification at ingest

### 5.2 Shard Size Selection

**Tradeoff:** Smaller shards (16–32 KiB) give finer repair granularity and lower read
amplification for small IOs. Larger shards (256 KiB–1 MiB) reduce metadata overhead
and improve sequential throughput.

**Recommendation:** Default 64 KiB, configurable per dataset. Use recordsize-adaptive
sharding: if `recordsize=1M`, use 256 KiB shards; if `recordsize=4K`, use 16 KiB shards.

### 5.3 Inline vs. Background Rebake

**Tradeoff:** Rebaking inline (during write) eliminates the durability window but
adds encode + multi-device write latency to every write. Background rebake keeps
write latency low but introduces a durability window.

**Decision:** Background rebake with durability ladder. The ladder bridges the gap
between write latency requirements and durability guarantees.

### 5.4 Atomic vs. Resumable Rebake

**Tradeoff:** Atomic rebake (all-or-nothing per extent) is simpler and avoids
partial-state recovery complexity. Resumable rebake would allow progress across
multiple ticks for large extents but requires persisted intermediate state.

**Decision:** Atomic per extent. The per-extent rebake is small (typically one
stripe of k+m shards, each 64 KiB). Multi-stripe extents use stripe-level atomicity.

### 5.5 Dedicated vs. Shared I/O Thread Pool

**Tradeoff:** A dedicated rebake thread pool isolates rebake I/O from demand I/O
but adds thread management overhead and may leave cores idle when rebake is quiescent.

**Decision:** Start with inline execution on the background service thread pool
with small per-tick budgets (default 64 MiB/tick). If demand I/O tail latency
is impacted, move to a dedicated pool of 2–4 threads.

### 5.6 Erasure Coding Algorithm

**Tradeoff:** Reed-Solomon (GF(2^8)) is well-understood, has efficient implementations,
and supports any (k,m) configuration. Alternatives like Cauchy Reed-Solomon or
Liberation codes offer faster encoding but are less mature and less flexible.

**Decision:** Reed-Solomon GF(2^8) as implemented in `tidefs-erasure-coding`.
The crate supports PARITY_RAID1 (m=1), PARITY_RAID2 (m=2), and PARITY_RAID3 (m=3).

---

## 6. On-Media Format

### 6.1 Shard Layout

```
┌────────────────────────────────────────────────────────────┐
│                    ShardGroupV1 Header                      │
│  magic | version | extent_id | k | m | shard_size | ...    │
├────────────────────────────────────────────────────────────┤
│                    ShardDescriptor[0]                       │
│  shard_index=0 | device | segment | offset | length | hash │
├────────────────────────────────────────────────────────────┤
│                    ShardDescriptor[1]                       │
│  ...                                                        │
├────────────────────────────────────────────────────────────┤
│                    ShardDescriptor[k+m-1]                   │
│  ...                                                        │
├────────────────────────────────────────────────────────────┤
│                    Data Shard 0                             │
│  [stripe 0 data | stripe 1 data | ... | padding]           │
│  IntegrityTrailerV2 { digest, commit_group, shard_index }           │
├────────────────────────────────────────────────────────────┤
│                    Data Shard k-1                           │
│  ...                                                        │
├────────────────────────────────────────────────────────────┤
│                    Parity Shard k                           │
│  [stripe 0 parity | stripe 1 parity | ...]                 │
│  IntegrityTrailerV2 { digest, commit_group, shard_index }           │
├────────────────────────────────────────────────────────────┤
│                    Parity Shard k+m-1                       │
│  ...                                                        │
└────────────────────────────────────────────────────────────┘
```

### 6.2 Integrity Trailer

Each shard carries an `IntegrityTrailerV2` with:
- `digest`: BLAKE3-256 of shard payload
- `commit_group`: transaction group at write time
- `shard_index`: position within ShardGroup (0..k+m-1)
- `extent_id`: cross-reference to owning extent

---

## 7. Interaction with Other Subsystems

### 7.1 Scrub / Deep Scrub / Repair / Resilver

- **Scrub** reads all shards and verifies `IntegrityTrailerV2` digests
- **Deep Scrub** reads all k+m shards, reconstructs original data, compares
- **Repair** reads k healthy shards, reconstructs missing/corrupt shard, writes to new location
- **Resilver** bulk-rebuilds all shards on a replacement device

### 7.2 SegmentCleanerService

- Trims ingest fragments only when locator lifecycle is `BaseComplete` or `Done`
- Must verify ≥ k healthy shards before trimming
- Safety gate: `can_trim(extent_id) → bool` checks shard health and lifecycle

### 7.3 Space Accounting

- Ingest space: tracked as `IngestBytes` until rebake completes
- Base shard space: tracked as `BaseShardBytes` after rebake
- `physical_used = IngestBytes + BaseShardBytes + MetadataBytes`
- Rebake temporarily doubles physical usage (ingest + new shards); after trim, ingest space freed

### 7.4 Snapshots

- Snapshots reference the locator entry, not the ingest location directly
- After rebake, the snapshot automatically benefits from improved redundancy
- No special handling needed: the locator update is transparent to snapshot readers

### 7.5 Pool Export/Import

- During export: complete in-flight rebakes, suspend queue
- On import: reconstruct rebake queue from all locator entries with lifecycle `Ingest` or `Rebaking`
- `Rebaking` entries are re-queued (orphaned shards from incomplete rebake are GC'd)

---

## 8. Configuration

### 8.1 Dataset Properties

| Property | Default | Description |
|----------|---------|-------------|
| `redundancy` | `ec_2_1` | Redundancy policy: none, replicated_N, ec_k_m |
| `rebake.age_threshold_secs` | 60 | Min ingest age before rebake eligibility |
| `rebake.bytes_threshold` | `4 MiB` | Min ingest bytes before rebake eligibility |
| `rebake.priority` | `background` | Normal rebake priority |

### 8.2 Pool Properties

| Property | Default | Description |
|----------|---------|-------------|
| `rebake.tick_interval_ms` | 1000 | Interval between RebakeService ticks |
| `rebake.budget_bytes_per_tick` | `64 MiB` | Max bytes processed per tick |
| `rebake.emergency_multiplier` | 16 | Budget multiplier at LossImminent |
| `rebake.max_concurrent_extents` | 256 | Max extents in Rebaking state concurrently |

### 8.3 Tunable Overrides

| Property | Default | Description |
|----------|---------|-------------|
| `tidefs.pool.allow_write_during_loss_imminent` | 0 | Override write block at LossImminent |
| `tidefs.rebake.dedicated_thread_pool` | false | Enable dedicated I/O thread pool |
| `tidefs.rebake.thread_pool_size` | 4 | Dedicated thread pool size |

---


### 9.1 Unit Tests
- Erasure coding round-trip: encode → decode for all (k,m) ∈ {(2,1),(4,2),(8,3)}
- Shard reconstruction: corrupt any single shard, verify reconstruction
- DurabilityLevel computation for all healthy/missing shard combinations
- Candidate selection ordering (Emergency before Expedited before Background)

### 9.2 Integration Tests
- Write → rebake → read: full pipeline with simnet devices
- Crash during rebake: kill daemon mid-encode, verify recovery re-queues extent
- Device failure: mark device offline, verify durability ladder escalates
- Multi-stripe extents: large write (256 KiB+), verify stripe-level encoding
- Pool export/import with in-flight rebake queue

### 9.3 Simnet Deterministic Tests
- Write N extents, rebake all, corrupt m shards per extent, verify reads succeed
- Budget exhaustion: limit budget to 1 extent/tick, verify atomicity (no partial state)
- Durability ladder simulation: fail devices one at a time, verify level transitions

### 9.4 Performance Benchmarks
- Ingest write latency (should be single-device, not multi-hop)
- Rebake throughput (MiB/s) under varying (k,m) configurations
- Read latency for rebaked vs. ingest extents
- Space amplification: physical bytes / logical bytes after rebake + trim

---

## 10. Wire-Up Implementation Plan

Each phase below maps to an independent Forgejo issue labeled `codex:ready`.

| Phase | Scope | Est. Lines |
|-------|-------|-----------|
| 1. Core types | `tidefs-types-locator-table-core`: `ShardGroupV1`, `ShardGroupDescriptor`, `EcAlgorithm`, `ShardGroupFlags` | ~400 |
| 2. Lifecycle states | `tidefs-types-extent-map-core`: `Rebaking`, `BaseComplete`, `Trimming` states | ~200 |
| 3. Erasure coding integration | `tidefs-erasure-coding`: multi-stripe encode/decode, shard split/join | ~600 |
| 4. Shard placement | `tidefs-placement-planner`: TideCRUSH shard placement with anti-affinity | ~800 |
| 5. RebakeService scaffold | `tidefs-rebake`: `BackgroundService` impl, tick loop, budget tracking | ~1200 |
| 6. Rebake core pipeline | `tidefs-rebake`: candidate selection, encode → place → write → commit | ~1500 |
| 7. Locator table updates | `tidefs-locator-table`: atomic rebake commit, shard-group metadata | ~600 |
| 8. Segment cleaner integration | `tidefs-cleanup-job-core`: safety gate for trimming rebaked extents | ~400 |
| 9. DurabilityMonitor | `tidefs-rebake`: periodic durability computation, emergency escalation | ~800 |
| **Total** | | **~7700** |

---

## 11. Invariants

1. **No silent data loss:** An extent is never trimmed from ingest until ≥ k healthy base shards exist and the locator has been atomically updated.
2. **Atomic rebake:** Either all k+m shards are written and the locator is updated, or the extent remains in `Ingest`/`Rebaking` state for retry.
3. **No orphaned shard leaks:** Shards written but never committed are eventually garbage-collected by `SegmentCleanerService`.
4. **Durability ladder monotonicity:** DurabilityLevel only degrades through defined transitions; it improves only through successful rebake or repair.
5. **Write blocking at LossImminent:** New writes to a dataset at LossImminent are blocked (operator-overridable) to prevent compounding data-at-risk.
6. **COMMIT_GROUP ordering:** Locator updates occur in COMMIT_GROUP order; a reader at COMMIT_GROUP T never sees a partially-rebaked extent.
7. **Anti-affinity:** TideCRUSH never places two shards of the same ShardGroup on the same device.
8. **Shard integrity:** Every shard is written with an `IntegrityTrailerV2`; reads verify the digest before returning data.
9. **Snapshot transparency:** Snapshots benefit from rebake automatically; no snapshot migration is required.
10. **Export safety:** Pool export drains in-flight rebakes before completing; import reconstructs the rebake queue.

---

## 12. References

- [#2030] Sealed shard-groups design specification (`docs/design/shard-groups-replicas-rebake-design-spec.md`)
- [#1249] Erasure coding and TideCRUSH placement
- [#1285] Extent maps and locator tables
- [#1179] Background service framework
- [#1287] End-to-end checksum architecture
- [#1288] Scrub, repair, and resilver orchestration
- [#1222] Rebake architecture design
- [#1215] Space accounting and segment cleaning
- `crates/tidefs-erasure-coding/src/lib.rs`
- `crates/tidefs-erasure-coded-store/src/lib.rs`
- `crates/tidefs-replication-model/src/lib.rs`
- `crates/tidefs-replication/src/lib.rs`
- `crates/tidefs-replica-health/src/lib.rs`
- `crates/tidefs-types-locator-table-core/src/lib.rs`
- `crates/tidefs-types-extent-map-core/src/lib.rs`
- `crates/tidefs-locator-table/src/lib.rs`
- `crates/tidefs-placement-planner/src/lib.rs`
