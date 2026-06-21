# Online Pool Geometry Conversion: Mirror-to-Erasure and Erasure-Family Changes Without Data Evacuation

**Issue**: [#1275](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1275)
**Status**: design-spec
**Priority**: P2
**Lane**: storage-core
**Maturity**: design-spec
**Depends on**: #1265 (defrag), #1222 (rebake), #1191 (extent_id indirection), #1253 (dataset properties), #1241/#1239 (scheduling), #1215 (space accounting)

## Abstract

This document defines the online pool geometry conversion mechanism for tidefs.
Geometry conversion changes the durability policy of a pool — switching between
mirroring and erasure-coding, or between erasure-coding families — without
destroying and recreating the pool, without evacuating data to external storage,
and without taking datasets offline.

The design leverages **extent_id indirection** (#1191) to make conversion a
locator-table rewrite: the extent map (file → extent_id) is never touched; only
the locator entry (extent_id → physical shards) changes. Conversion is lazy,
transactional, budgeted, and scoped to individual pools, datasets, or extent
classes.

### Comparison to existing systems

This table records design targets against prior-art pressure. It is not a
current online conversion, cost, availability, or superiority claim.

| System | Mirror↔EC | EC family change | Per-volume scope | Lazy conversion | Budget control |
|--------|-----------|-----------------|------------------|-----------------|-----------------|
| **ZFS** | No (destroy+recreate) | No | N/A | N/A | N/A |
| **Ceph** | Via CRUSH rule change (mass migration) | Via CRUSH rule change (mass migration) | No (pool-wide) | No | Bluestore deferred only |
| **tidefs target** | Target: yes | Target: yes | Target: yes | Target: yes | Target: yes |

---

## 1. Architecture Overview

### 1.1 Core Insight: Extent_id Indirection Enables Conversion

In tidefs, the logical-to-physical mapping uses a stable indirection layer:

```
File extent map                Locator table
┌─────────────────┐          ┌──────────────────────────────────────┐
│ logical_offset  │          │ LocatorId → ExtentLocatorValueV1      │
│ ├─ extent_id(N) │──────────│  flags: ERASURE_CODED | SHARDED …    │
│ ├─ extent_id(M) │    │     │  shard_count: 4                      │
│ └─ extent_id(P) │    │     │  replica_placement[]:                │
└─────────────────┘    │     │    [0] (node, device, segment, …)    │
                       │     │    [1] (node, device, segment, …)    │
                       │     └──────────────────────────────────────┘
                       │
                       │     ┌──────────────────────────────────────┐
                       │     │ LocatorId → ExtentLocatorValueV1      │
                       └─────│  flags: 0 (mirrored)                 │
                             │  replica_placement[]:                │
                             │    [0] (node, device, segment, …)    │
                             │    [1] (node, device, segment, …)    │
                             │    [2] (node, device, segment, …)    │
                             └──────────────────────────────────────┘
```

**Key property**: The extent map is NOT dirtied by geometry conversion.
Only the locator entry for the affected extent_id changes. This is a
single-level design target with no cascading changes to upper layers. It is a
different architecture from ZFS indirect blocks and Ceph CRUSH-rule changes,
not proof of current TideFS online-conversion capability.

### 1.2 What Geometry Conversion Means

Geometry conversion = **durability policy change + lazy rematerialization**.

The pool's `DurabilityPolicy` defines how data is physically laid out:
- **Mirror(N)**: N identical replicas, each on a different failure domain
- **EC(K+M)**: K data shards + M parity shards, any K survivors sufficient

Changing the policy means that new writes use the new layout immediately, while
existing extents are lazily converted from old layout to new layout.

### 1.3 Conversion Scopes

| Scope | Trigger | Effect |
|-------|---------|--------|
| **Pool-wide default** | Pool property change via admin API | New writes use new policy; existing extents lazily converted |
| **Per-dataset** | Dataset property change via #1253 | Only that dataset's extents converted |
| **Per-extent-class** | Extent class selection via #1241 | Hot extents converted first; cold extents deferred |

---

## 2. Durability Policy Model

### 2.1 DurabilityPolicy Enum

```rust
/// Defines how data shards are laid out for durability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurabilityPolicy {
    /// N-way mirroring: N identical replicas on distinct failure domains.
    /// `replica_count >= 1`.
    Mirror { replica_count: u8 },

    /// Erasure coding with K data shards + M parity shards.
    /// Total shards = K + M. Any K survivors are sufficient for reconstruction.
    /// Uses GF(2^8) Reed-Solomon from `tidefs_erasure_coding`.
    ErasureCoded {
        data_shards: u16,
        parity_count: ParityCount,
        shard_len: usize,
    },
}
```

### 2.2 Durability Ladder (Ordering)

Policies are partially ordered by durability strength. The "durability ladder"
defines what conversions are upgrades (more durable), downgrades (less durable),
and lateral (equivalent). The ladder is used to gate conversion requests:

```
                         MORE DURABLE
                             ▲
    EC(8+3) ────────────────┐│
    mirror(4) ──────────────┤│
    EC(4+2) ────────────────┤│
    mirror(3) ──────────────┤│
    EC(2+1) ────────────────┤│
    mirror(2) ──────────────┤│
    mirror(1)               ▼
                         LESS DURABLE
```

- **Upgrade**: Moving to a higher rung (e.g., mirror(2) → EC(4+2)). Always permitted.
- **Lateral**: Different policies at the same rung (e.g., mirror(3) → EC(2+1)). Permitted.
- **Downgrade**: Moving to a lower rung (e.g., mirror(3) → mirror(1)). Requires explicit admin override.

The ladder is defined by a scoring function:

```rust
fn durability_score(policy: &DurabilityPolicy) -> u32 {
    match policy {
        DurabilityPolicy::Mirror { replica_count } => *replica_count as u32 * 100,
        DurabilityPolicy::ErasureCoded { data_shards, parity_count, .. } => {
            let tolerated = parity_count.as_usize() as u32;
            // EC score = data redundancy factor × 50
            // Higher tolerated failures → higher score
            tolerated * 50 + (*data_shards as u32).min(tolerated * 2) * 10
        }
    }
}
```

### 2.3 Policy → Locator Mapping

When a `DurabilityPolicy` is applied to an extent, the locator table entry
(`ExtentLocatorValueV1`) is populated as follows:

| Policy | `flags` | `shard_count` | `replica_count` | `replica_placement` |
|--------|---------|---------------|------------------|---------------------|
| Mirror(N) | 0 | 1 | N | N replicas, each with full payload |
| EC(K+M) | `ERASURE_CODED \| SHARDED` | K+M | 0 | K data shard placements + M parity shard placements |

For EC, the `replica_placement` vector holds `K+M` entries where:
- Entries `[0..K)` are data shards
- Entries `[K..K+M)` are parity shards
- Each entry specifies `node_id`, `device_id`, `segment_id`, `grain_offset`, `grain_count`
- `shard_placements[].shard_index` distinguishes data (0..K-1) from parity (K..K+M-1)

### 2.4 Supported Conversions

```
mirror(N)  ←→  mirror(M)     (any N, M ≥ 1)
mirror(N)  ←→  EC(K+M)       (any valid K, M)
EC(K1+M1)  ←→  EC(K2+M2)     (any valid K1, M1, K2, M2)
```

All conversions are online, transactional, and budgeted.

---

## 3. Conversion Algorithm

### 3.1 Core Algorithm: `convert_extent`

The conversion operation is an extension of the rebake (#1222) and defrag (#1265)
patterns. It re-encodes an extent from its old durability policy to a new one.

```
convert_extent(extent_id, old_policy, new_policy):
  1.  Read all live shards from the current locator entry
      (resolve locator_id from extent map, read physical shards)
  2.  Reassemble the original payload from the old shard layout:
      - Mirror: read any one healthy replica
      - EC: read K out of K+M available shards, reconstruct if needed
  3.  Re-encode the payload with the new policy:
      - Mirror: copy payload to N placement targets
      - EC: compute K data + M parity shards via GF(2^8) Reed-Solomon
  4.  Allocate new shard placements via PlacementPlanner
  5.  Write new shards to physical storage
  6.  In the same commit_group: atomic locator swap —
      update the locator entry to point to new shard placements
  7.  Mark old shards for GC (deadlist)
```

### 3.2 Multi-Stripe Handling for EC

For EC targets where the payload exceeds `data_shards × shard_len`, the conversion
uses multi-stripe encoding identical to `ErasureCodedStore`:

```
reassemble_payload(extent_id) → payload_bytes
if target is EC:
    stripes = ceil(payload_bytes / (data_shards × shard_len))
    for each stripe:
        encode stripe into K data + M parity shards
        each shard → placement target
```

Mirror targets are simpler: the full payload is written to each replica target.

### 3.3 Conversion Context

```rust
/// Persistent cursor tracking conversion progress.
#[derive(Clone, Debug)]
pub struct GeometryConversionCursor {
    /// The scope being converted.
    pub scope: ConversionScope,
    /// Old durability policy (pre-conversion).
    pub old_policy: DurabilityPolicy,
    /// New durability policy (target).
    pub new_policy: DurabilityPolicy,
    /// Extent_id of the last converted extent (or NONE if just started).
    pub last_converted: ExtentId,
    /// Total extents to convert (estimated or exact).
    pub total_extents: u64,
    /// Extents converted so far.
    pub converted_count: u64,
    /// Bytes converted so far.
    pub bytes_converted: u64,
    /// Epoch when conversion started.
    pub started_at_commit_group: u64,
}
```

### 3.4 Job Integration

Geometry conversion is implemented as an `IncrementalJob` (from
`tidefs_types_incremental_job_core`) plugged into the background scheduler
(#1241/#1239) at `ServicePriority::Throughput` — the same priority tier as
rebake and defrag.

```
BackgroundScheduler
  ├── Critical:     scrub, resilver, orphan_recovery
  ├── LatencySensitive: reclaim
  ├── Throughput:   rebake, defrag, geometry_conversion  ← NEW
  ├── BestEffort:   gc_mark, btree_compaction
  └── Opportunistic: prefetch, rebalance
```

During conversion, the pool operates normally:
- **Reads**: Resolved from current locator entry (old shards until swap, then new shards)
- **Writes**: Use the new durability policy for all new allocations
- **Snapshots**: Unaffected; snapshots reference old locator entries until their extents are converted

---

## 4. Transaction Protocol

### 4.1 Locator Swap Protocol

The atomic locator swap is the central safety mechanism. It is identical in
structure to the rebake (#1222) and defrag (#1265) locator swap:

```
┌─────────────────────────────────────────────────────────────┐
│                      COMMIT_GROUP N                                  │
│                                                             │
│  Read old shard set                                         │
│       │                                                     │
│       ▼                                                     │
│  Re-encode with new policy                                  │
│       │                                                     │
│       ▼                                                     │
│  Write new shard set                                        │
│       │                                                     │
│       ▼                                                     │
│  ┌──────────────────────────────────────┐                   │
│  │ COMMIT_GROUP COMMIT: atomic locator swap      │                   │
│  │ - New locator entry goes live        │                   │
│  │ - Old shards move to deadlist        │                   │
│  └──────────────────────────────────────┘                   │
│       │                                                     │
│       ▼                                                     │
│  ┌──────────────────────────────────────┐                   │
│  │ POST COMMIT_GROUP N+1:                        │                   │
│  │ - Old shards eligible for GC         │                   │
│  │ - Space reclaimed by reclaim queue   │                   │
│  └──────────────────────────────────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Locator Table Changes

The locator swap rewrites the `ExtentLocatorValueV1` for the extent:

| Field | Old (Mirror(2)) | New (EC(4+2)) |
|-------|-----------------|---------------|
| `locator_rev` | N | N+1 |
| `flags` | 0 | `ERASURE_CODED \| SHARDED` |
| `shard_count` | 1 | 6 |
| `replica_count` | 2 | 0 |
| `replica_placement` | 2 full replicas | 4 data + 2 parity shards |
| `on_media_bytes` | payload × 2 | payload × 1.5 |

The swap uses the existing `LocatorTableOps::relocate()` trait method, which
atomically replaces the replica placements and increments `locator_rev`.

### 4.3 Space Accounting During Conversion

Conversion temporarily requires space for both old and new shard sets:

```
peak_space = space_old + space_new
```

For mirror-to-EC conversions this is particularly favorable because EC has
lower space overhead:

```
mirror(3) → EC(4+2): 3× → 1.5× (conversion frees 1.5× worth of space after GC)
mirror(2) → mirror(3): 2× → 3× (conversion allocates 1× additional)
```

The conversion engine maintains a space budget and pauses when `free_space <
conversion_headroom × space_new`. The headroom defaults to 1.2× (20% safety
margin) and is configurable.

---

## 5. Safety and Crash Recovery

### 5.1 Invariants

1. **Old shards remain valid until commit_group commit**: Readers see the old locator
   entry until the atomic swap completes. There is never a window where the
   extent is unreachable.
2. **No reduced redundancy window**: At no point during conversion does the
   effective redundancy drop below the old policy's minimum or the new policy's
   minimum (whichever is lower). The old shards are not deleted until after the
   new shards are committed.
3. **Crash at any point is safe**:
   - Crash before new shard writes: old shards remain valid, conversion
     resumes from cursor
   - Crash after new shard writes but before commit_group commit: new shards are
     unreferenced orphans, old shards remain valid, orphans cleaned by GC
   - Crash after commit_group commit but before old shard GC: new shards are live,
     old shards cleaned by reclaim on next tick

### 5.2 Crash Recovery

On mount after a crash during conversion:

1. Load the `GeometryConversionCursor` from the pool superblock
2. If no cursor exists, conversion was not active; proceed normally
3. If a cursor exists, scan the locator table from `last_converted` forward
4. For each extent: check if `locator_rev` matches the expected value
   - If the extent points to new shards: skip (already converted)
   - If the extent points to old shards: resume conversion from this point
5. Re-populate the background scheduler job and continue

### 5.3 Space Threshold Pausing

If free space falls below the configured threshold during conversion:

1. The conversion tick returns `StepResult::Paused`
2. The background scheduler skips conversion in subsequent ticks
3. When free space recovers (via GC reclaim or pool expansion), conversion
   resumes automatically
4. The pause is logged with `explanation_query` observability

---

## 6. Budget and Scheduling

### 6.1 Per-Tick Budget

Each conversion tick operates under a `WorkBudget` from the background scheduler:

```rust
pub struct ConversionWorkBudget {
    /// Maximum extents to convert in this tick.
    pub max_extents: u32,
    /// Maximum bytes to read/write in this tick.
    pub max_bytes: u64,
    /// Maximum IOPS budget for this tick.
    pub max_iops: u32,
    /// Minimum free space fraction (0.0–1.0) required to proceed.
    pub min_free_space_fraction: f32,
}
```

Default values:
- `max_extents`: 256 per tick
- `max_bytes`: 16 MiB per tick
- `max_iops`: 128 per tick
- `min_free_space_fraction`: 0.10 (10% of pool capacity)

### 6.2 Priority Within Throughput Tier

Within the `Throughput` tier, jobs are dispatched round-robin:

```
Throughput tier (round-robin):
  → rebake     (1 tick)
  → defrag     (1 tick)
  → geom_conv  (1 tick)
  → …          (1 tick)
```

If defrag or rebake detects a geometry conversion in progress, it can yield
to the conversion job to accelerate completion.

---

## 7. Observability

### 7.1 Metrics (via `explanation_query`)

| Metric | Description |
|--------|-------------|
| `geom_conv.extents_total` | Total extents to convert |
| `geom_conv.extents_converted` | Extents converted so far |
| `geom_conv.progress_pct` | 0–100% completion |
| `geom_conv.bytes_converted` | Total bytes converted |
| `geom_conv.bytes_remaining` | Estimated bytes remaining |
| `geom_conv.rate_extents_per_sec` | Conversion rate (extents/s) |
| `geom_conv.rate_bytes_per_sec` | Conversion rate (bytes/s) |
| `geom_conv.eta_seconds` | Estimated seconds until completion |
| `geom_conv.space_overhead_bytes` | Current temporary space overhead |
| `geom_conv.is_paused` | Whether paused due to space constraints |
| `geom_conv.error_count` | Cumulative conversion errors |

### 7.2 Progress Reporting

The conversion emits progress via the `explanation_query` runtime:

```
tidefs explain geom-conv pool/datapool
  Status:         ACTIVE (71% complete)
  Old policy:     mirror(2)
  New policy:     EC(4+2)
  Extents done:   71,234 / 100,000
  Rate:           142 extents/s (5.7 MiB/s)
  ETA:            3m 22s
  Space overhead: 8.3 GiB (within budget)
```

---

## 8. Scope Triggering Flow

### 8.1 Pool-Wide Conversion

```
Admin sets pool property: durability_policy → EC(4+2)
  1. Pool superblock updated with new default policy
  2. New writes immediately use EC(4+2)
  3. GeometryConversionCursor created with scope=Pool
  4. Background scheduler picks up conversion job
  5. All extents without a dataset-specific policy are converted
```

### 8.2 Per-Dataset Conversion

```
Admin sets dataset property: durability_policy → mirror(3)
  1. Dataset property updated (via #1253)
  2. GeometryConversionCursor created with scope=Dataset(dataset_id)
  3. Only that dataset's extent_id range is converted
  4. Other datasets and pool default are unaffected
```

### 8.3 Per-Extent-Class Conversion

```
Admin sets extent-class policy: hot_extents → EC(4+2), cold_extents → mirror(2)
  1. Extent class policy updated
  2. Background scheduler picks up two conversion jobs
  3. Hot extents converted first (higher priority)
  4. Cold extents converted opportunistically
```

### 8.4 Cancellation

Conversion can be cancelled at any time:
1. Admin cancels via control plane API
2. Conversion cursor is marked as `cancelled`
3. Already-converted extents remain in the new policy
4. Unconverted extents remain in the old policy
5. Pool operates with mixed policies (all supported, reads resolve correctly)

---

## 9. Extent Map / Snapshots / Clones

### 9.1 Extent Map Stability

The extent map (`ExtentMapEntryV1` / `ExtentMapEntryV2`) is NOT modified by
conversion. The `locator_id` field remains stable; only the locator table entry
it points to is rewritten. This means:

- Extent maps are not dirtied by conversion — no cascading metadata writes
- Files can be read and written normally during conversion
- The extent_id indirection is the sole touchpoint

### 9.2 Snapshot Interaction

Snapshots reference extent maps via their committed commit_group. When a snapshot's
extent is converted:

1. The old locator entry is preserved by the snapshot deadlist (#1232)
2. The new locator entry is live for the current dataset view
3. The snapshot continues to reference the old shards via the deadlist

This means snapshots are transparent to conversion — no snapshot rebuilding
is required.

### 9.3 Clone Interaction

Clones share extent_id → locator mappings with their origin. When a clone's
extent is converted:

1. If the extent is shared (not CoW'd), both origin and clone reference the
   same old shards
2. Conversion of the shared extent benefits both views simultaneously
3. After conversion, both views transparently resolve the new locator entry
4. Subsequent writes to either view trigger CoW as normal

---

## 10. Implementation Plan

### 10.1 New Types

| Crate | Additions |
|-------|-----------|
| `tidefs-types-extent-map-core` | None (uses existing `ExtentId`, `LocatorId`) |
| `tidefs-types-locator-table-core` | `DurabilityPolicy` enum, `ConversionScope` enum |
| `tidefs-erasure-coding` | None (uses existing `encode`/`reconstruct`) |
| `tidefs-erasure-coded-store` | None (reference for multi-stripe encoding) |

### 10.2 New Crate: `tidefs-geometry-conversion`

```
crates/tidefs-geometry-conversion/
  src/
    lib.rs            — GeometryConversionJob, ConversionEngine
    cursor.rs         — GeometryConversionCursor persistence
    convert.rs        — convert_extent core algorithm
    budget.rs         — ConversionWorkBudget space accounting
    metrics.rs        — Observability hooks
  Cargo.toml
```

### 10.3 Integration Points

| Component | Change |
|-----------|--------|
| `tidefs-background-scheduler` | Register `GeometryConversionJob` in Throughput tier |
| `tidefs-local-filesystem` | Pool superblock: store active conversion cursor |
| `tidefs-control-plane-api` | Start/cancel/query conversion commands |
| `tidefs-explanation-query-*` | Export conversion metrics |

### 10.4 Phased Rollout

| Phase | Scope | Gate |
|-------|-------|------|
| **Phase 1** | Types + algorithm + unit tests (this spec) | `cargo test -p tidefs-geometry-conversion` |
| **Phase 2** | Background scheduler integration | Single-node conversion test |
| **Phase 3** | Crash recovery + space pausing | Crash injection harness |
| **Phase 4** | Multi-dataset + extent-class scoping | Multi-scope test |

---

## 11. Tradeoffs and Alternatives Considered

### 11.1 Why Lazy Conversion Instead of Eager?

**Pro lazy**: No downtime, no data evacuation, background work does not block
foreground IO, cancelling leaves a clean mixed-policy state.

**Con lazy**: Mixed policies exist during conversion (reads resolve correctly
but performance may vary). Space overhead of old+new shards during conversion.

**Decision**: Lazy. Eager conversion would require freeze + rewrite, which does
not satisfy the design target for online conversion and resembles a full
external migration workflow.

### 11.2 Why Extent-Level Instead of Object-Level?

Ceph operates at PG/object level (~4 MiB). tidefs operates at extent level
(variable, typically 4 KiB–1 MiB). Extent-level conversion provides:

- Finer-grained progress and lower tail latency per conversion unit
- Better space budget control (smaller temporary space per unit)
- Extent-class segmentation (hot/cold) at fine granularity

The tradeoff is more locator table updates, but the locator table is designed
for this workload (page-level B-tree, batch update support).

### 11.3 Why Not Just Use Rebake Unchanged?

Rebake (#1222) converts ingest → base. Defrag (#1265) rewrites base → base
within the same policy. Geometry conversion adds policy change to the base →
base rewrite:

| Aspect | Rebake | Defrag | Geometry Conversion |
|--------|--------|--------|---------------------|
| Domain | Ingest→Base | Base→Base | Base→Base |
| Policy change | No | No | Target: yes |
| Re-encode | Simple write | Simple write | Target: GF(2^8) Reed-Solomon |
| Locator swap | Yes | Yes | Yes |
| Shard count change | Possible | Possible | Target: expected |

Geometry conversion reuses the locator swap protocol, cursor machinery, and
background scheduling from rebake/defrag. The new logic is in the re-encoding
step: read old policy, re-encode with new policy.

### 11.4 Downgrade Safety

Downgrading (e.g., EC(4+2) → mirror(1)) reduces durability. This is permitted
only with an explicit admin override flag. The design does NOT prevent downgrades
but requires acknowledgment:

```rust
pub struct ConversionRequest {
    pub scope: ConversionScope,
    pub new_policy: DurabilityPolicy,
    pub allow_downgrade: bool,  // Must be true for durability-ladder descents
    pub budget_limit: Option<ConversionWorkBudget>,
}
```

---

## 12. Relationship to Other Issues

| Issue | Relationship |
|-------|-------------|
| #1191 | Provides the extent_id indirection that makes conversion possible |
| #1222 | Rebake provides the locator swap protocol and cursor machinery |
| #1265 | Defrag provides the BPR (base→base rewrite) pattern reused here |
| #1253 | Dataset properties enable per-dataset conversion scoping |
| #1241 | Background scheduler drives conversion as an IncrementalJob |
| #1239 | Bulk plane provides throughput isolation for conversion IO |
| #1215 | Space accounting enforces free-space thresholds |
| #1232 | Snapshot deadlist preserves old shards for unconverted snapshots |

## References

- `crates/tidefs-types-locator-table-core/src/lib.rs` — ExtentLocatorValueV1, LocatorTableOps
- `crates/tidefs-locator-table/src/lib.rs` — V1LocatorTable implementation
- `crates/tidefs-erasure-coding/src/lib.rs` — GF(2^8) Reed-Solomon engine
- `crates/tidefs-erasure-coded-store/src/lib.rs` — Multi-stripe EC store reference
- `crates/tidefs-background-scheduler/src/lib.rs` — 5-stage priority scheduler
- `crates/tidefs-replication-model/src/lib.rs` — Replica placement and movement model
- `docs/ONLINE_DEFRAG_BPR_DESIGN.md` — Defrag design (#1265)
- `docs/design/unified-on-media-format-lifecycle.md` — Format lifecycle framework
