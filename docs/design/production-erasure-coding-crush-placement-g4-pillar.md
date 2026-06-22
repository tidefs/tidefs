# Production Erasure Coding and CRUSH-like Placement Design (G4 Pillar)

Maturity: **design-spec** for the production erasure coding placement engine:
TideCRUSH deterministic placement algorithm, `EcProfile` selection, and
G4 pillar architecture integrating the erasure coding engine, coded store,
placement planner, placement runtime, and locator table into a unified
production data-placement subsystem.

Claim boundary: the Ceph CRUSH comparison text below is design input and
target architecture framing. It does not prove current placement quality,
rebalance behavior, repair performance, cost efficiency, erasure-coded
durability, or OpenZFS/Ceph successor status. Product-facing comparison
wording still requires #875 claim ids and #928/#930 comparator evidence.

This document closes Forgejo issue #1779 (coordinator-generated issue). Supersedes prior issues #1623, #1672, #1857, #1932, and #2027.

Supersedes earlier design sketches at `docs/ERASURE_CODING_PLACEMENT_DESIGN.md`
(#1249) and `docs/ERASURE_CODED_LAYOUT_OW306.md` (#35). This is the canonical
G4 pillar design spec.

## 1. Motivation

tidefs separates the write path from the durability path: writes land as
single-device ingest extents for minimal latency, then a background rebake
service converts them to base shards with full erasure-coded redundancy.
Without a production-grade erasure coding placement engine, three problems
arise:

1. **No deterministic shard placement.** Erasure-coded shards must be placed
   across failure domains deterministically so any node can compute shard
   locations without a centralized allocator. Ceph's CRUSH solves this for
   placement groups; tidefs needs the same property for individual shards.
2. **No profile-driven EC selection.** Different datasets need different
   erasure coding profiles (4+2 archival vs 8+3 durability). Without
   `EcProfile`, every dataset uses the same (k,m), wasting space or
   under-protecting data.
3. **No unified placement engine.** The placement planner computes replica
   targets, and the placement runtime executes them, but neither knows how
   to place erasure-coded shards with CRUSH-style deterministic striping.

Ceph's CRUSH algorithm has proven over two decades that deterministic
pseudo-random placement based on a hierarchical cluster map is the right
abstraction for distributed storage. tidefs adapts this model to its
shard-level granularity rather than PG-level. The intended reduction in PG
state is a target design property, not current measured evidence.

| Concern | Ceph CRUSH | tidefs TideCRUSH |
|---------|------------|------------------|
| Placement granularity | Placement group (PG) | Individual shard |
| Map representation | Bucket hierarchy text/binary | `CrushMapV1` Rust struct |
| Selection function | Straw/straw2/linear | Weighted straw2 with shuffle guard |
| Failure domain | Bucket type hierarchy | `FailureDomainClass` enum |
| Deterministic seeding | PG ID + pool hash | `ShardPlacementSeed` = object_id + stripe + replica |
| Rebalancing on add/remove | Proportional to weight delta | Same, via straw2 |
| Rush-tier separation | Primary/scratch parallelism | `TierGoal` in placement planner |

### Dependency Map

| Design | Relationship |
|--------|-------------|
| #1553 Shard groups / replicas | `ShardGroupV1` carries TideCRUSH-placed shard descriptors |
| #1222 Rebake architecture | Rebake calls TideCRUSH for base-shard placement |
| #1285 Extent maps + locator tables | `ExtentLocatorValueV1` holds shard-to-device mapping |
| #1287 Checksum architecture | `IntegrityTrailerV2` per-shard digests verified post-placement |
| #1288 Scrub/repair/resilver | Repair reconstructs shards at TideCRUSH-computed locations |
| #613 Failure-domain placement | `compute_replica_target_set` feeds member inventory |
| #882 Quorum write + replication runtime | EC placement reuses failure-domain inventory |
| #1179 Background service framework | Rebake uses TideCRUSH placement within budgeted ticks |

## 2. Design Overview

Four core abstractions form the G4 pillar:

| Abstraction | Responsibility |
|-------------|---------------|
| `TideCRUSH` | Deterministic shard placement engine; straw2-based weighted selection |
| `EcProfile` | Erasure coding profile: (k,m) selection, shard sizing, domain constraints |
| `CrushMapV1` | Hierarchical cluster topology: devices → hosts → racks → rows → rooms → datacenters |
| `ShardPlacementSeed` | Deterministic input: object_id + stripe_index + replica_index |

The placement flow:

```
EcProfile { k=4, m=2, domain_class=Host }
        │
        ▼
ShardPlacementSeed { object_id, stripe_index, replica_index }
        │
        ▼
TideCRUSH::place(seed, crush_map, ec_profile) → Vec<CrushPlacement>
        │
        ▼
ShardDescriptor { shard_index, device_id, physical_offset }
        │
        ▼
tidefs-erasure-coded-store writes shards to target LocalObjectStore instances
```

TideCRUSH produces `(k+m)` distinct placements per stripe, one per shard.
Each placement is deterministic — any node in the cluster recomputes the
identical set of target devices given the same seed, map, and profile.

## 3. TideCRUSH: The CRUSH-like Placement Algorithm

### 3.1 Algorithm Overview

TideCRUSH adapts Ceph's CRUSH (Controlled Replication Under Scalable
Hashing) algorithm for tidefs's shard-level placement. The core idea:

1. **Straw2 bucket selection.** Each bucket (rack, host, etc.) is assigned a
   straw length proportional to its weight. The bucket with the longest
   straw wins. When a device is added or removed, only data proportional to
   the weight delta moves — minimal rebalancing.
2. **Shuffle guard.** Before selecting, TideCRUSH shuffles the candidate
   list using a seed-dependent permutation, ensuring that repeated lookups
   with the same seed produce the same deterministic order.
3. **Retry on collision.** If two shards would land on the same device
   (anti-affinity violation), TideCRUSH increments `replica_index` and
   retries, guaranteeing `(k+m)` distinct devices.
4. **Upward failure-domain traversal.** Starting from a root bucket,
   TideCRUSH drills down through the hierarchy, applying straw2 at each
   level, until it reaches a leaf device.

### 3.2 CrushMapV1: Hierarchical Cluster Topology

```rust
/// A CRUSH map encodes the cluster's hierarchical topology.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrushMapV1 {
    /// Monotonically increasing map epoch.
    pub epoch: u64,

    /// All leaf devices in the cluster (OSD-level).
    pub devices: Vec<CrushDevice>,

    /// Topology hierarchy: the root bucket contains all children.
    pub root: CrushBucket,

    /// Reserved for TLV extension.
    pub reserved: [u8; 32],

    /// CRC32C over all preceding fields.
    pub crc32c: u32,
}

/// A leaf device (OSD) in the CRUSH map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrushDevice {
    /// Unique device identifier within the cluster.
    pub device_id: u32,

    /// Weight for straw2 selection (0 = out).
    pub weight: f32,

    /// Device health for placement eligibility.
    pub health: DeviceHealth,

    /// Failure domain identifiers for anti-affinity enforcement.
    pub host_id: u32,
    pub rack_id: u32,
    pub row_id: u32,
    pub room_id: u32,
    pub dc_id: u32,

    /// Reserved.
    pub reserved: [u8; 12],
}

/// A bucket in the CRUSH hierarchy (host, rack, row, room, datacenter).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrushBucket {
    /// Unique bucket identifier.
    pub bucket_id: i32,

    /// Bucket type: 0=device, 1=host, 2=rack, 3=row, 4=room, 5=dc.
    pub bucket_type: u8,

    /// Straw2 selection algorithm (always straw2 in V1).
    pub algorithm: BucketAlgorithm,

    /// Sum of all child weights.
    pub total_weight: f32,

    /// Children: either sub-buckets or leaf device indices.
    pub children: Vec<CrushBucketItem>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BucketAlgorithm {
    /// Straw2: each child gets a straw length; longest wins.
    Straw2 = 0,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrushBucketItem {
    /// Index into `CrushMapV1::devices` for leaf; -1 for sub-bucket.
    pub device_index: i32,

    /// Index into parent's bucket list for sub-bucket; -1 for leaf.
    pub bucket_index: i32,

    /// Weight of this item.
    pub weight: f32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceHealth {
    Healthy = 0,
    Suspect = 1,
    Down = 2,
    Out = 3,
}
```

### 3.3 Straw2 Selection Function

Straw2 is the default and only bucket algorithm. For each child `i` with
weight `w_i`, compute a straw length:

```
straw_i = -log(u_i) / w_i
```

where `u_i` is a pseudo-random value in (0,1] derived from the
`ShardPlacementSeed` and the child's identifier via SipHash-2-4.
The child with the largest straw wins. This is mathematically equivalent
to Ceph's straw2 and has the same optimal rebalancing properties.

### 3.4 ShardPlacementSeed

```rust
/// Deterministic input seed for TideCRUSH placement.
/// Any node that constructs an identical seed gets the same result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ShardPlacementSeed {
    /// Object or extent identifier (e.g., locator_id truncated to 64 bits).
    pub object_id: u64,

    /// Stripe index within the object (0-based).
    pub stripe_index: u32,

    /// Replica/shard index for retry-on-collision (0 = primary attempt).
    pub replica_index: u16,

    /// Reserved.
    pub reserved: u16,
}
```

### 3.5 Core Placement Function

```rust
/// Place `(k+m)` shards for one stripe across the cluster.
///
/// Returns `k+m` `CrushPlacement` results, one per shard index.
/// Requires all returned placements to target distinct devices when the
/// cluster has enough healthy devices.
pub fn place_shards(
    seed: &ShardPlacementSeed,
    crush_map: &CrushMapV1,
    ec_profile: &EcProfile,
) -> Result<Vec<CrushPlacement>, TideCrushError>;

/// A single placement result from TideCRUSH.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrushPlacement {
    /// The shard index (0..k-1 = data, k..k+m-1 = parity).
    pub shard_index: u8,

    /// Target device identifier.
    pub device_id: u32,

    /// Count of retries needed (0 = first attempt succeeded).
    pub retry_count: u16,
}
```

### 3.6 Anti-Affinity Enforcement

TideCRUSH enforces anti-affinity at the failure-domain class specified
by `EcProfile::domain_class`:

| `domain_class` | Guarantee |
|----------------|-----------|
| `Host` (default) | Each shard lands on a different host |
| `Rack` | Each shard lands in a different rack |
| `Row` | Each shard lands in a different row |
| `Room` | Each shard lands in a different room |

The algorithm:
1. For each shard `i` in `0..(k+m)`, construct `ShardPlacementSeed { ...,
   replica_index: 0 }`.
2. Compute candidate device via straw2 traversal.
3. If the device violates anti-affinity (same domain as a previously
   placed shard), increment `replica_index` and retry (up to a configurable
   limit, default 50).
4. If retries are exhausted, return `TideCrushError::InsufficientDevices`.

### 3.7 Rebalancing on Topology Change

When devices are added or removed, TideCRUSH recomputes placement for all
shards. Straw2 ensures minimal data movement:

- **Adding a device:** Only `W_new / W_total` proportion of shards move
  to the new device.
- **Removing a device:** Only shards previously mapped to the removed
  device move; others stay put.
- **Weight change:** Data proportional to the weight delta moves.

The placement runtime handles the actual data movement by comparing
current `ExtentLocatorValueV1` against TideCRUSH-computed targets and
issuing `PlacementGap` tickets for mismatches.

## 4. EcProfile: Erasure Coding Profiles

### 4.1 Profile Structure

```rust
/// An erasure coding profile selects (k,m), shard size, and domain constraints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcProfile {
    /// Unique profile name (e.g., "4+2-64k", "8+3-256k").
    pub name: String,

    /// Number of data shards.
    pub k: u8,

    /// Number of parity shards.
    pub m: u8,

    /// Size of each shard in bytes.
    pub shard_len: u32,

    /// Failure-domain class for anti-affinity.
    pub domain_class: CrushDomainClass,

    /// Whether this profile applies to data or metadata.
    pub profile_class: EcProfileClass,

    /// Minimum number of healthy devices required before degraded mode.
    pub min_healthy_devices: u16,

    /// Reserved.
    pub reserved: [u8; 14],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrushDomainClass {
    Osd = 0,
    Host = 1,
    Rack = 2,
    Row = 3,
    Room = 4,
    Datacenter = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcProfileClass {
    /// Erasure coding for user data.
    Data = 0,
    /// Erasure coding for filesystem metadata.
    Metadata = 1,
    /// Erasure coding for small files (inline EC).
    SmallFile = 2,
}
```

### 4.2 Profile Catalog

tidefs ships with a curated catalog of profiles. Datasets select one
at creation time; the profile is immutable for the dataset's lifetime.

| Profile Name | k | m | shard_len | Overhead | Tolerates | Use Case |
|-------------|---|---|-----------|----------|-----------|----------|
| `2+1-test` | 2 | 1 | 256 B | 1.50x | 1 failure | Unit tests |
| `4+2-64k` | 4 | 2 | 64 KiB | 1.50x | 2 failures | Production data (default) |
| `8+3-64k` | 8 | 3 | 64 KiB | 1.375x | 3 failures | High-durability data |
| `4+2-256k` | 4 | 2 | 256 KiB | 1.50x | 2 failures | Large sequential I/O |
| `8+3-256k` | 8 | 3 | 256 KiB | 1.375x | 3 failures | Archival cold data |
| `16+4-256k` | 16 | 4 | 256 KiB | 1.25x | 4 failures | Wide-stripe archival |
| `2+2-4k` | 2 | 2 | 4 KiB | 2.00x | 2 failures | Metadata mirroring |

### 4.3 Profile-Dataset Binding

An `EcProfile` is bound to a dataset at creation time via
`DatasetFeatureFlags::redundancy_policy`. The binding is immutable:
changing the EC profile requires dataset migration or send/receive.

```rust
pub struct RedundancyPolicy {
    pub policy_class: RedundancyPolicyClass,
    pub ec_profile: Option<String>,  // None for replication-only
    pub replica_count: u8,           // For replicated datasets
    pub domain_class: CrushDomainClass,
}

pub enum RedundancyPolicyClass {
    Replicated,
    ErasureCoded,
}
```

## 5. Integration Architecture

### 5.1 Crate Map

```
┌────────────────────────────────────────────────────────────────┐
│                     G4 Pillar Crate Map                        │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌───────────────────┐    ┌──────────────────────────────┐    │
│  │  tidefs-erasure-  │    │       tidefs-erasure-        │    │
│  │  coding           │───▶│       coded-store            │    │
│  │  (GF(2^8) engine) │    │  (stripe across N stores)    │    │
│  └───────────────────┘    └──────────┬───────────────────┘    │
│                                      │                        │
│  ┌───────────────────┐               │  ┌─────────────────┐   │
│  │  tidefs-crush-    │               │  │ tidefs-locator- │   │
│  │  placement        │◀──────────────┼──│ table           │   │
│  │  (TideCRUSH +     │               │  │ (V1 inline-hash │   │
│  │   CrushMapV1)     │               │  │  locator table) │   │
│  └────────┬──────────┘               │  └─────────────────┘   │
│           │                          │                        │
│  ┌────────┴──────────┐               │  ┌─────────────────┐   │
│  │  tidefs-placement-│               │  │ tidefs-extent-  │   │
│  │  planner          │               └──│ map             │   │
│  │  (compute_replica │                  │ (V1 inline-list │   │
│  │   _target_set)    │                  │  extent map)    │   │
│  └────────┬──────────┘                  └─────────────────┘   │
│           │                                                    │
│  ┌────────┴──────────┐                                        │
│  │  tidefs-placement-│                                        │
│  │  runtime          │                                        │
│  │  (5-phase place-  │                                        │
│  │   ment lifecycle) │                                        │
│  └───────────────────┘                                        │
└────────────────────────────────────────────────────────────────┘
```

The G4 pillar adds one new crate and extends two existing ones:

| Crate | Status | Role |
|-------|--------|------|
| `tidefs-crush-placement` | **New** | TideCRUSH algorithm, `CrushMapV1`, `EcProfile`, `ShardPlacementSeed` |
| `tidefs-erasure-coded-store` | Extended | Accepts `CrushPlacement` targets instead of static path arrays |
| `tidefs-placement-planner` | Extended | Feeds failure-domain inventory to TideCRUSH |

### 5.2 Write Path Integration

During rebake (#1222), the flow is:

```
1. RebakeService selects an ingest extent for rebaking.
2. Reads the extent's logical payload from the ingest journal.
3. Looks up dataset's EcProfile from DatasetFeatureFlags.
4. Constructs ShardPlacementSeed { extent_id, stripe: 0, replica: 0 }.
5. Calls TideCRUSH::place_shards(seed, crush_map, ec_profile).
6. tidefs-erasure-coding::encode() splits payload into k data shards
   + m parity shards.
7. tidefs-erasure-coded-store writes each shard to the device returned
   by TideCRUSH.
8. Updates ExtentLocatorValueV1 with ShardGroupV1 referencing the
   new shard placements.
9. Commits locator update atomically within the current commit_group.
```

### 5.3 Read Path Integration

For clean reads (all k data shards available):

```
1. File system looks up ExtentMapEntryV2 → locator_id.
2. V1LocatorTable::resolve(locator_id) → ExtentLocatorValueV1.
3. ShardGroupV1 contains ShardDescriptor for each shard.
4. Reader issues parallel reads to the first k data-shard devices.
5. Concatenates data shards → original payload.
```

For degraded reads (some data shards unavailable):

```
1. Reader attempts parallel reads of all k+m shard devices.
2. If at least k shards are readable (mix of data and parity):
   a. tidefs-erasure-coding::reconstruct() rebuilds missing data.
   b. Repair is queued for the damaged shards (#1288).
3. If fewer than k shards are readable: return Unavailable.
```

## 6. Data Structures

### 6.1 ShardPlacementPlan

```rust
/// A complete shard placement plan for one extent, computed by TideCRUSH.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardPlacementPlan {
    /// The locator_id this plan corresponds to.
    pub locator_id: u64,

    /// The EC profile used for placement.
    pub ec_profile_name: String,

    /// CrushMapV1 epoch at the time of placement.
    pub crush_map_epoch: u64,

    /// One CrushPlacement per shard (k+m entries).
    pub placements: Vec<CrushPlacement>,

    /// Number of stripes (ceil(payload_bytes / data_capacity)).
    pub stripe_count: u32,

    /// Reserved.
    pub reserved: [u8; 16],
}
```

### 6.2 CrushMapVersion

The CRUSH map is versioned and replicated across the cluster.

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrushMapVersion {
    /// Monotonically increasing map epoch (incremented on any topology change).
    pub epoch: u64,

    /// BLAKE3-256 hash of the serialized `CrushMapV1`.
    pub digest: [u8; 32],

    /// When this map version became active (commit_group number).
    pub activated_at_commit_group: u64,
}
```

### 6.3 EcProfileCatalog

```rust
/// A catalog of available EC profiles, shipped with tidefs and extended
/// by the administrator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcProfileCatalog {
    /// Profiles keyed by name.
    pub profiles: BTreeMap<String, EcProfile>,

    /// Default profile name for new datasets.
    pub default_profile: String,

    /// Catalog version (bumps on profile add/remove).
    pub catalog_version: u64,
}
```

## 7. Error Hierarchy

```rust
/// Errors from the TideCRUSH placement engine.
#[derive(Debug, thiserror::Error)]
pub enum TideCrushError {
    /// Not enough healthy devices to satisfy the EC profile.
    #[error("insufficient healthy devices: need {required}, have {available}")]
    InsufficientDevices { required: u16, available: u16 },

    /// Anti-affinity retries exhausted.
    #[error("anti-affinity retries exhausted after {retries} attempts")]
    RetriesExhausted { retries: u16 },

    /// The CRUSH map has no devices.
    #[error("CRUSH map is empty (no devices)")]
    EmptyMap,

    /// The EC profile requires more devices than exist in the chosen domain class.
    #[error("EC profile {profile} requires {required} devices in domain {domain:?}, only {available} available")]
    DomainTooSmall {
        profile: String,
        required: u16,
        available: u16,
        domain: CrushDomainClass,
    },

    /// Bucket type mismatch in CRUSH map hierarchy.
    #[error("CRUSH map hierarchy violation: expected {expected:?} at level {level}, found {actual:?}")]
    HierarchyViolation {
        level: u8,
        expected: CrushDomainClass,
        actual: CrushDomainClass,
    },

    /// SipHash seed collision (statistically impossible; defensive check).
    #[error("SipHash seed collision detected")]
    SeedCollision,

    /// Profile not found in catalog.
    #[error("EC profile '{name}' not found in catalog")]
    ProfileNotFound { name: String },

    /// Invalid EC profile configuration.
    #[error("invalid EC profile: k={k}, m={m}, reason: {reason}")]
    InvalidProfile { k: u8, m: u8, reason: String },
}
```

## 8. Consistency Guarantees

TideCRUSH provides the following guarantees:

1. **Determinism.** Given identical `(CrushMapV1, ShardPlacementSeed,
   EcProfile)`, all nodes compute identical placement results. No
   centralized allocator or coordinator is needed for placement.
2. **Anti-affinity.** Within the specified `CrushDomainClass`, no two
   shards of the same stripe land in the same failure domain.
3. **Minimal rebalancing.** When the CRUSH map changes, only data
   proportional to the weight change is remapped (straw2 property).
4. **Map epoch binding.** Every `ShardPlacementPlan` records the
   `crush_map_epoch`. If the map changes between plan and execution,
   the placement runtime detects the mismatch and re-plans.
5. **No PG state.** Unlike Ceph, tidefs has no placement groups. Each
   stripe is placed independently. This eliminates PG state combinatorics
   (peering, activation, backfill state machines).

## 9. Implementation Phases

| Phase | Scope | Crate |
|-------|-------|-------|
| Phase 1 | `CrushMapV1` types, `EcProfile` types, `ShardPlacementSeed` | `tidefs-crush-placement` |
| Phase 2 | Straw2 selection function, `place_shards()` algorithm | `tidefs-crush-placement` |
| Phase 3 | Anti-affinity enforcement, retry logic | `tidefs-crush-placement` |
| Phase 5 | `EcProfileCatalog` with curated defaults | `tidefs-crush-placement` |
| Phase 6 | Write-path integration: rebake → TideCRUSH → erasure-coded-store | `tidefs-erasure-coded-store` |
| Phase 7 | Read-path integration: degraded reads via reconstruction | `tidefs-erasure-coded-store` |
| Phase 8 | Integration with placement-runtime for rebalancing | `tidefs-placement-runtime` |
| Phase 9 | `tidefs-xtask check-crush-placement` gate | `tidefs-xtask` |

## 10. Testing Strategy

### 10.1 Unit Tests (Phases 1-5)

- **Straw2 determinism:** Same seed + same map → same device selected
  (verified with 256 random seeds against reference implementation).
- **Minimal rebalancing:** Adding/removing a device moves only the
  straw2-proportional fraction of shards (<1% deviation from ideal).
- **Anti-affinity enforcement:** `k+m` shards always land on distinct
  devices (tested with k+m=12 on a 100-device map, 10,000 seeds).
- **Retry exhaustion:** When fewer devices exist than `k+m`, retries
  eventually exhaust and return `RetriesExhausted`.
- **Domain class filtering:** Placing with `domain_class=Rack` only
  selects from devices in distinct racks.
- **Empty map:** `EmptyMap` error for zero-device maps.
  produce `HierarchyViolation`.

### 10.2 Integration Tests (Phases 6-8)

- **End-to-end encode-place-write-read:** Create a synthetic CRUSH map
  with 12 devices across 4 hosts, encode a 512 KiB payload with 4+2,
  place via TideCRUSH, write to erasure-coded-store, read back, verify.
- **Degraded read:** Delete 2 shard stores, read back via reconstruction,
  verify payload integrity.
- **CRUSH map epoch mismatch:** Change map epoch between plan and execution;
  verify the runtime detects and re-plans.
- **Rebalancing simulation:** Add 2 devices to a 10-device map, verify
  that only straw2-proportional data is flagged for movement.

### 10.3 Property-Based Tests (Phase 10)

- **Determinism across nodes:** Generate random CRUSH maps and seeds,
  compute placement on two independent `TideCRUSH` instances, assert
  identical results.
- **Anti-affinity fuzzing:** Random maps + random `EcProfile` combos;
  never observe two shards on the same device for the same stripe.
- **Rebalancing bound:** `|moved / total| - weight_delta / total_weight| < 0.01`
  for 10,000 randomized topology changes.

## 11. Configuration Knobs

| Constant | Default | Meaning |
|----------|---------|---------|
| `CRUSH_RETRY_LIMIT` | 50 | Max anti-affinity retries before error |
| `CRUSH_DEFAULT_DOMAIN_CLASS` | Host | Default failure domain for anti-affinity |
| `CRUSH_MAP_MAX_DEPTH` | 6 | Max hierarchy depth (device → host → rack → row → room → dc) |
| `CRUSH_MAP_MAX_DEVICES` | 65536 | Max leaf devices per map |
| `EC_PROFILE_DEFAULT` | `4+2-64k` | Default profile for new datasets |
| `EC_MIN_HEALTHY_DEVICES_RATIO` | 1.5 | Min healthy devices = (k+m) * ratio before degraded mode |

## 12. ZFS / Ceph Comparison

| Dimension | ZFS PARITY_RAID | Ceph EC + CRUSH | tidefs TideCRUSH + EC |
|-----------|------------|-----------------|----------------------|
| Placement unit | DEVICE (disk group) | Placement group | Individual shard |
| Placement algorithm | Fixed round-robin within device | CRUSH straw2 on PG | CRUSH straw2 on shard |
| State combinatorics | None (single-node) | PG peering/activation/backfill | Target: no PG indirection |
| Rebalancing cost | Full resilver | Proportional to delta | Target: proportional to placement delta |
| EC profile flexibility | Limited (PARITY_RAID1/Z2/Z3) | Per-pool EC profile | Per-dataset EcProfile |
| Failure domain | None (single node) | Bucket hierarchy | `CrushDomainClass` enum |
| Metadata overhead | None | PG state metadata | `ShardDescriptor` per shard |
| Write amplification | Immediate (1+k+m) | Replication at write or EC at write | Target: 1x at ingest; k+m at rebake |

## 13. Open Questions

1. **Should TideCRUSH support other bucket algorithms besides straw2?**
   Ceph supports uniform, list, tree, and straw buckets. For tidefs V1,
   straw2 is sufficient. Future versions could add `tree` for very large
   hierarchies (>10,000 devices). Recommendation: V1 is straw2-only; add
   tree in V2 if profiling shows hierarchy traversal overhead.

2. **How to handle CRUSH map propagation across the cluster?**
   The CRUSH map must be identical on every node for placement determinism.
   Options: (a) gossip via membership epoch, (b) Raft-commit to a shared
   log, (c) ADMIN service push. Recommendation: embed `CrushMapV1` in the
   membership epoch record (`tidefs-membership-epoch`), piggybacking on
   existing consensus.

3. **Should placement be recomputed on every read?**
   Computing TideCRUSH placement on every read is cheap (SipHash + straw2
   walk) but redundant once `ShardGroupV1` records the placement in the
   locator table. Recommendation: compute once during rebake; store
   `ShardDescriptor` in `ShardGroupV1`; only recompute on repair/rebalance.

4. **How does TideCRUSH interact with pool geometry conversion?**
   When a pool's device topology changes (#1275), the CRUSH map epoch
   increments. Existing data keeps its placement from the old epoch.
   New writes use the new epoch. Recommissioning/rebalancing is handled
   by the placement runtime comparing old vs new placements.

5. **Should small files bypass erasure coding entirely?**
   Files below `data_capacity` (k * shard_len) may not benefit from EC.
   Recommendation: files smaller than `k * shard_len` use replication
   (via `EcProfileClass::SmallFile`); files above use erasure coding.

6. **How to handle multi-stripe placement for large objects?**
   Each stripe gets an independent `ShardPlacementSeed` with incremented
   `stripe_index`. TideCRUSH treats each stripe independently, so a
   10-stripe object gets 10 independent placement computations. This is
   mandatory for correctness: different stripes must not land on the
   same device just because they're from the same object.


## 14. References

- [#1779] This design spec — Production erasure coding and CRUSH-like placement design (G4 pillar); coordinator-generated issue
- [#1623] Prior design spec — Production erasure coding and CRUSH-like placement (G4 pillar) (also closes #1672)
- [#1553] Shard groups, replicas, and rebake pathway — `ShardGroupV1`, `ReplicaLifecycle`
- [#1222] Rebake architecture — rebake pipeline calls TideCRUSH
- [#1285] Extent maps and locator tables — `ExtentLocatorValueV1` holds shard locations
- [#613] Failure-domain placement model — `FailureDomainPlacementPolicy`
- [#882] Quorum write + replication runtime — placement runtime integration
- [#1287] Checksum architecture — `IntegrityTrailerV2` per-shard digests
- [#1288] Scrub/repair/resilver — EC repair from healthy shards
- [#1275] Online pool geometry conversion — topology changes → CRUSH map epoch bump
- [#1215] Space accounting — rebake frees ingest space after EC placement
- Ceph CRUSH paper: Weil, S.A., et al. "CRUSH: Controlled, Scalable, Decentralized Placement of Replicated Data." SC 2006.
- [#1249] Earlier erasure-coding placement design (superseded by this document)
- Erasure-coded layout model OW-306 — single-parity XOR stripe model
- Straw2 algorithm: Sage Weil. "Straw2: Improving Data Distribution in CRUSH." 2014.
- `docs/design/shard-groups-replicas-rebake-pathway.md`
- `docs/design/rebake-architecture-ingest-journal-to-base-shard-conversion.md`
- `crates/tidefs-erasure-coding/` — GF(2^8) Reed-Solomon engine
- `crates/tidefs-erasure-coded-store/` — Object-level EC store
- `crates/tidefs-placement-planner/` — Replica target computation
- `crates/tidefs-placement-runtime/` — 5-phase placement lifecycle
- `crates/tidefs-locator-table/` — V1 inline-hash locator table
- `crates/tidefs-extent-map/` — V1 inline-list extent map
- `crates/tidefs-membership-epoch/` — Failure-domain inventory
- `crates/tidefs-replication-model/` — ERASURE_CODED_LAYOUT_GATE_OW_306
- `docs/STATUS.md` — Current capability maturity tracking
- `docs/FEATURE_MATRIX.md` — Feature surface maturity matrix

## 15. Document History

| Date | Change | Issue |
|------|--------|-------|
| 2026-05-04 | Initial G4 pillar design spec | #1591 |
| 2026-05-04 | Canonical issue reassignment; supersedes #1249; added STATUS/FEATURE_MATRIX references | #1623 |
| 2026-05-04 | Auto-generated coordinator issue; design-spec maturity confirmed | #1672 |
| 2026-05-04 | Coordinator re-issue; updated canonical closing reference to #1857 | #1857 |
| 2026-05-04 | Coordinator re-issue; canonical closing reference updated to #1932 | #1932 |
| 2026-05-04 | Coordinator re-issue; canonical closing reference updated to #2027 | #2027 |
| 2026-05-05 | Coordinator re-issue; canonical closing reference updated to #1779 | #1779 |
