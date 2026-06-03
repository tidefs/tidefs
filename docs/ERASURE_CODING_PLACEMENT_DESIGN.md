# Erasure Coding and CRUSH-like Placement Design (G4 Pillar)

Maturity: **design-spec** for production erasure coding families, CRUSH-like
deterministic placement, automated recovery loop orchestration, and integration
contracts with shard groups, checksums, transport, and rebake.

This document closes Forgejo issue #1249.

## 1. Motivation

TideFS already has executable erasure coding machinery:
- `crates/tidefs-erasure-coding`: GF(2^8) Reed-Solomon encoding with
  PARITY_RAID1/Z2/Z3 parity counts, Vandermonde-matrix reconstruction from any
  k surviving shards (821 lines).
- `crates/tidefs-erasure-coded-store`: object-level erasure-coded store with
  multi-stripe encoding, per-object repair, and configurable (k,m) profiles
  (953 lines).
- `crates/tidefs-membership-epoch`: failure-domain hierarchy
  (Device/Node/Chassis/Rack/Zone/Region) with anti-affinity placement policy
  and `FailureDomainPlacementPolicy` (2895 lines).
- `crates/tidefs-replication-model`: OW-306 single-parity XOR erasure-coded
  layout model for object/root payload bytes (4764 lines).

These are implementation-tracked non-release models. What's missing is the bridge to production:

1. **No placement function maps objects to shard locations.** The membership
   epoch knows failure domains; the erasure-coded store knows how to encode and
   repair. But there is no deterministic function `object_id -> ordered device
   list` that spreads shards across failure domains.
2. **No erasure family catalog.** The code supports arbitrary (k,m), but there
   is no formal analysis of recommended profiles, their space overhead,
   durability characteristics, and failure-correlation assumptions.
3. **No recovery loop orchestration.** `repair_store()` exists as a manual
   call. There is no automatic trigger on degraded read, no background scrub
   scheduler, and no throttling integration with rebuild/relocation.
4. **No integration contracts with sibling pillars.** Erasure coding must
   interact with shard groups (#1286), checksums (#1287), transport (#1229),
   and rebake (#1222), but these interfaces are unspecified.
5. **No ZFS/Ceph positioning.** The design must articulate where tidefs improves
   on ZFS PARITY_RAID (ashift constraints, device-scoped redundancy) and Ceph CRUSH
   (PG combinatorics, per-PG rebuild scope).

## 2. Design Overview

This design introduces four new systems:

| System | Purpose |
|--------|---------|
| `TideCRUSH` | Deterministic placement: `(object_id, epoch, profile) -> ordered [(node, device)]` across failure domains |
| Erasure Family Catalog | Recommended (k,m) profiles with space overhead, durability, I/O amplification analysis |
| Recovery Loop Orchestrator | Degraded-read repair trigger, background scrub, throttling integration with rebuild/relocation |
| Integration Contracts | Interface specifications with checksums, shard groups, transport, rebake |

The existing `tidefs-erasure-coding` crate provides the GF(2^8) RS engine. The
existing `tidefs-erasure-coded-store` provides the object-level multi-stripe
encode/decode/repair. The existing `tidefs-membership-epoch` provides the
failure-domain hierarchy. The new design composes them into a production system
by adding placement, orchestration, and integration contracts.

## 3. TideCRUSH: Deterministic Shard Placement

### 3.1 Core Algorithm

TideCRUSH maps an object identifier and erasure profile to an ordered list of
(shard_index, node_id, device_id) tuples. The mapping is:

```
shard_assignment(object_id, epoch, profile) -> [(node_0, dev_0), ..., (node_{w-1}, dev_{w-1})]
```

where `w = k + m` is the stripe width.

The algorithm proceeds in five stages:

**Stage 1: Hash pool construction.** Combine the object identifier, epoch, and
profile into a single 32-byte hash input:

```
hash_input = BLAKE3(object_id || epoch.to_le_bytes() || profile.to_discriminant())
```

All subsequent draws consume bytes from an extendable-output stream produced by
`BLAKE3::new().update(hash_input).finalize_xof()`.

**Stage 2: Failure-domain selection.** For each shard index `i` in `0..w`,
draw a failure-domain cell from the cluster topology tree:

```
domain = select_domain(hash_stream, topology_root, shard_index, profile.failure_domain_class)
```

`select_domain()` is a recursive straw2-like weighted draw:

```
fn select_domain(xof, node, shard_idx, required_class) -> DomainId:
    if node.class == required_class:
        return node.id
    children = [c for c in node.children if c.is_alive(epoch)]
    weights = [straw2_weight(xof, child.id, shard_idx) for child in children]
    total = sum(weights)
    draw = next_u64(xof) % total
    cumulative = 0
    for (child, w) in zip(children, weights):
        cumulative += w
        if draw < cumulative:
            return select_domain(xof, child, shard_idx, required_class)
    // fallback: last child
    return select_domain(xof, children.last(), shard_idx, required_class)
```

The `straw2_weight()` function (adapted from Ceph's straw2) computes:

```
fn straw2_weight(xof, item_id, shard_idx) -> u64:
    h = BLAKE3(xof.read(32) || item_id.to_le_bytes() || shard_idx.to_le_bytes())
    u = u64_from_bytes(h[0..8])
    ln = -ln(u / 2^64)   // exponential distribution via inversion
    (ln / item.weight).floor() as u64
```

**Stage 3: Anti-affinity enforcement.** After selecting a domain cell, the
algorithm checks whether any previously placed shard falls in the same cell,
a parent cell, or a child cell (depending on the anti-affinity class). For
`AntiAffinityClass::Strict`, the draw is retried (up to a configurable limit,
default 3 retries) with a perturbed hash. If retries are exhausted, the shard
is placed in the first available domain and the verdict is emitted as degraded.

**Stage 4: Device selection within domain.** Once a domain cell is selected,
a device within that cell is chosen via a simple weighted hash:

```
fn select_device(xof, domain, shard_idx) -> DeviceId:
    devices = domain.alive_devices(epoch)
    if devices.is_empty():
        return None  // caller retries domain selection
    i = next_u64(xof) % len(devices)
    devices[i].id
```

**Stage 5: Result assembly.** The algorithm returns:

```
TideCRUSHResult {
    assignments: [(shard_idx, node_id, device_id); w],
    verdict: PlacementVerdict,   // Admitted or AdmittedDegraded
    degradation_reason: Option<DegradationReason>,
}
```

### 3.2 Placement Invariants

1. **Determinism**: same (object_id, epoch, profile, topology) always produces
   the same assignments. No randomness beyond the hash input.
2. **Monotonicity under healthy members**: adding a healthy member to a domain
   may move some assignments but never breaks existing reads (old locations
   remain readable until explicit relocation).
3. **Epoch-gated**: placement is bound to a membership epoch. Epoch changes
   trigger placement recomputation via the relocation planner, not via
   silent migration.
4. **Failure-domain spread**: the `failure_domain_class` parameter controls
   the minimum domain separation. For example, using `FailureDomainClass::Rack`
   ensures no two shards of the same stripe share a rack.
5. **Weight proportionality**: device weights (capacity, IOPS class) influence
   placement proportionally via straw2, preventing hotspot formation.

### 3.3 Failure-Domain Class Semantics

| Domain Class | Use Case | Spread Guarantee |
|-------------|----------|-----------------|
| `Device` | Per-device separation | No two shards on same device |
| `Node` | Host-level failure tolerance | No two shards on same node |
| `Chassis` | Shared PSU/enclosure tolerance | No two shards in same chassis |
| `Rack` | Top-of-rack switch failure tolerance | No two shards in same rack |
| `Zone` | Availability-zone / room failure | No two shards in same zone |
| `Region` | Geographic disaster tolerance | No two shards in same region |

For a (4,2) profile with `RequiredDomainClass::Rack`: all 6 shards are placed
in 6 different racks. Degraded verdict if fewer than 6 racks are available.

### 3.4 Replica-vs-EC Placement Coexistence

Replicated data uses `ReplicaTarget` placement (from P8-02). Erasure-coded data
uses `ErasureCodedTarget` placement. The two coexist in the same cluster:

- Replicated objects: `compute_replica_target_set()` from P8-03.
- EC objects: `tide_crush_assign()` as defined here.

The failure-domain topology is shared. Both placement systems consume the same
`FailureDomainRecord` hierarchy and the same `ClusterMemberRecord` health data.

### 3.5 Comparison with Ceph CRUSH

| Dimension | Ceph CRUSH | TideCRUSH |
|-----------|-----------|-----------|
| Placement unit | PG (placement group), ~100-200 objects | Per-object (stripe) |
| Placement algorithm | Straw2 bucket types, rule-based descent | Straw2-like domain selection, 5-stage pipeline |
| Rebuild scope | Per-PG: all objects in the PG migrate together | Per-stripe: only degraded stripes are rebuilt |
| Rule language | CRUSH map with bucket types, rules | Rust function with typed failure-domain classes |
| Weight model | Device weight in CRUSH map | Device weight from member record |
| Determinism | Input-dependent (CRUSH map version) | Epoch-gated (membership epoch) |
| Upmap/balance | Manual pg-upmap entries needed for balance | Straw2 proportional distribution |
| OSDMap coupling | Tight: CRUSH map embedded in OSDMap epoch | Loose: topology from membership epoch, placement computed independently |

TideCRUSH improves on Ceph CRUSH in two specific dimensions:
- **Per-stripe rebuild**: Ceph must rebuild entire PGs (100-200 objects) when a
  single OSD fails. TideCRUSH rebuilds only the stripes missing shards on the
  failed device.
- **No rule language**: Ceph's CRUSH rule language is a DSL that operators must
  learn. TideCRUSH uses Rust types with compile-time verification.

TideCRUSH intentionally does not provide Ceph's "CRUSH tunables" (chooseleaf
variants, indep vs firstn). The design opts for a single algorithm with
predictable behavior over configurable but fragile tuning knobs.

### 3.6 Comparison with ZFS PARITY_RAID Placement

| Dimension | ZFS PARITY_RAID | TideCRUSH |
|-----------|-----------|-----------|
| Placement unit | Per-device: all stripes on fixed disk set | Per-stripe: any combination within failure-domain constraints |
| Disk set | Fixed at device creation, immutable | Dynamic: devices join/leave via membership epoch |
| Expansion | Add new device (with its own PARITY_RAID), no restriping | Automatic restriping via relocation when topology changes |
| Failure domain | Single chassis (all disks in one device) | Configurable across 6-domain hierarchy |
| Device heterogeneity | All disks in device must be same size | Heterogeneous device weights via straw2 |

Key tidefs advantage: ZFS PARITY_RAID ties redundancy to a fixed device disk set.
Losing a device loses all data on it. TideCRUSH spreads each stripe's shards
across the entire cluster topology, so individual device/node/rack failures
are survivable up to the parity count.

## 4. Erasure Family Catalog

### 4.1 Recommended Profiles

The catalog defines production erasure profiles with explicit space overhead,
durability, and I/O amplification characteristics.

| Profile | k | m | Overhead | Tolerates | Use Case |
|---------|---|---|----------|-----------|----------|
| **EC-2+1** | 2 | 1 | 50% | 1 loss | Warm/cold data, small clusters |
| **EC-4+2** | 4 | 2 | 50% | 2 losses | General-purpose, recommended default |
| **EC-8+2** | 8 | 2 | 25% | 2 losses | Capacity-optimized cold storage |
| **EC-8+3** | 8 | 3 | 37.5% | 3 losses | High-durability cold storage |
| **EC-16+4** | 16 | 4 | 25% | 4 losses | Extreme capacity, archival |

All profiles use GF(2^8) Reed-Solomon with Vandermonde encoding matrices, as
already implemented in `tidefs-erasure-coding`.

### 4.2 Profile Selection Tradeoffs

**Space overhead** = m/k. Lower is better for cost, higher is better for
durability.

| Profile | Space Efficiency | Write Amplification | Reconstruction Cost |
|---------|-----------------|---------------------|---------------------|
| EC-2+1 | 66.7% | 1.5x | 2 reads per lost shard |
| EC-4+2 | 66.7% | 1.5x | 4 reads per lost shard |
| EC-8+2 | 80% | 1.25x | 8 reads per lost shard |
| EC-8+3 | 72.7% | 1.375x | 8 reads per lost shard |
| EC-16+4 | 80% | 1.25x | 16 reads per lost shard |

**Write amplification**: write of 1 byte of user data requires writing all
w=k+m shards. For small writes (< stripe width * shard_len), a read-modify-write
(RMW) cycle is triggered: read surviving shards, recompute parity, write all
shards. This is the classic EC write penalty.

**Reconstruction cost**: rebuilding a single lost shard requires reading k
surviving shards and computing the GF(2^8) matrix inversion. Higher k means
more network I/O and more CPU per reconstruction.

### 4.3 Profile Selection Policy

The profile for a dataset is selected at dataset creation time via the dataset
feature flags system (#1223). The profile is stored as a `DatasetFeatureFlags`
bit and is immutable for the dataset's lifetime (consistent with the format
immutability principle from #1238).

```
Pool::create_dataset(name, profile: ErasureProfile):
    set EC_PROFILE feature flag on dataset
    subsequent writes to this dataset use the profile's (k,m)
```

Dataset migration between profiles requires `send | recv` (#109) or dataset
clone with new profile.

### 4.4 Shard Size Configuration

The `shard_len` parameter controls the byte size of each shard within a stripe.
The current default in `ErasureCodedStoreConfig` is 256 bytes (test) or
variable per profile.

| Profile | Recommended Shard Len | Stripe Data Capacity | Rationale |
|---------|----------------------|---------------------|-----------|
| EC-2+1 | 4 KiB | 8 KiB | Aligns with page/block sizes |
| EC-4+2 | 4 KiB | 16 KiB | Default chunk alignment |
| EC-8+2 | 8 KiB | 64 KiB | Larger stripes for cold data |
| EC-8+3 | 8 KiB | 64 KiB | Same as 8+2 |
| EC-16+4 | 16 KiB | 256 KiB | Archival; large sequential I/O |

The shard length is a power of two and must be >= 512 bytes (minimum sensible
shard for network transport efficiency) and <= 1 MiB (above which per-stripe
reconstruction latency becomes problematic).

### 4.5 Failure-Correlation Awareness

The design acknowledges that failure correlations (shared PSU, shared switch,
shared power grid) make some domain classes more correlated than others. The
erasure profile's parity count (m) must exceed the maximum expected correlated
failure count within the `failure_domain_class`:

```
rule: m > max_correlated_failures(failure_domain_class)
```

| Domain Class | Max Correlated | Minimum m | Example |
|-------------|---------------|-----------|---------|
| Device | 1 (single disk failure) | 1 | EC-2+1 sufficient |
| Node | 1 (node crash) | 1 | EC-2+1 sufficient |
| Chassis | 2 (PSU + backplane) | 2 | EC-4+2 recommended |
| Rack | 3 (ToR switch + PDU) | 2 | EC-4+2 minimum |
| Zone | 5+ (power grid, cooling) | 3 | EC-8+3 recommended |
| Region | 10+ (natural disaster) | N/A (replication) | Use 3x replication for region |

This rule is advisory, not enforced. Operators may choose any profile for any
domain class, but the design documents the risk.

### 4.6 Profile Records

Each erasure profile is recorded as a persistent `ErasureProfileRecord`:

```rust
pub struct ErasureProfileRecord {
    pub profile_id: ErasureProfileId,
    pub data_shards: u8,        // k
    pub parity_count: u8,       // m
    pub shard_len: u32,         // bytes, power of two
    pub required_domain_class: FailureDomainClass,
    pub anti_affinity_class: AntiAffinityClass,
    pub name: &'static str,     // e.g. "EC-4+2"
}
```

## 5. Recovery Loop Orchestration

### 5.1 Recovery Triggers

Recovery is initiated by three trigger types:

**Trigger 1: Degraded Read (synchronous repair).** When a read discovers a
missing, corrupt, or stale shard, the read path reconstructs the data from
surviving shards (already implemented in `reconstruct()`), serves the result
to the caller, and enqueues a background repair job for the missing shard.

```
on_read_degraded(stripe_id, missing_shard_idx, reconstructed_data):
    repair_job = RebuildShardJob {
        stripe_id,
        shard_idx: missing_shard_idx,
        reconstructed_data,  // already computed during read
        priority: RepairPriority::ReadTriggered,
    }
    repair_queue.enqueue(repair_job)
    emit DegradedReadEvent { stripe_id, shard_idx }
```

**Trigger 2: Background Scrub (periodic verification).** A background scrub
worker periodically enumerates all stripes, verifies shard integrity via
checksums, and enqueues repair jobs for any shard that fails verification.

```
scrub_cycle():
    for each dataset with EC profile:
        for each stripe in dataset:
            for each shard in stripe:
                verify_shard_checksum(shard)
                if mismatch:
                    repair_job = RebuildShardJob {
                        stripe_id,
                        shard_idx,
                        reconstructed_data: None,  // will reconstruct from survivors
                        priority: RepairPriority::Scrub,
                    }
                    repair_queue.enqueue(repair_job)
    update_scrub_position()
```

The scrub cycle is designed as a continuous background process:

- One scrub cycle per dataset, configurable interval (default: 7 days)
- Scrubs a configurable number of stripes per commit_group (default: 1000)
- Maintains a persistent scrub cursor to resume after restart
- Emits `ScrubProgressEvent` and `ScrubCompleteEvent` for observability

**Trigger 3: Membership Change (topology-driven repair).** When a device or
node failure is detected via membership epoch change, all stripes with shards
on the failed member are enumerated and repair jobs are created to place
replacement shards on new devices.

```
on_member_failure(failed_member_id):
    stripes = enumerate_stripes_on_member(failed_member_id)
    for (stripe_id, shard_idx) in stripes:
        new_target = tide_crush_reshard(stripe_id, shard_idx, current_epoch, profile)
        repair_job = RebuildShardJob {
            stripe_id,
            shard_idx: new_target.shard_idx,
            target_node: new_target.node_id,
            target_device: new_target.device_id,
            source_stripe_id: stripe_id,
            priority: RepairPriority::LossRecovery,
        }
        repair_queue.enqueue(repair_job)
```

### 5.2 Repair Queue and Scheduling

The repair queue is a priority queue with three priority levels:

| Priority | Queue | Description | Preemption |
|----------|-------|-------------|------------|
| `LossRecovery` (0) | loss_recovery | Shards lost due to device/node failure | May preempt other repair work |
| `ReadTriggered` (1) | read_triggered | Shards missing on read, data already reconstructed | Normal scheduling |
| `Scrub` (2) | scrub | Shards with checksum mismatches found by scrub | Lowest priority, may be paused |

The repair scheduler processes jobs from the queue, respecting these rules:

1. `LossRecovery` jobs always take precedence.
2. At most `N` concurrent repair transfers (default: 4 per node).
3. Repair transfers are throttled to at most `R` bytes/s aggregate (default:
   100 MiB/s, configurable) to avoid starving foreground I/O.
4. When `memory_pressure > reserve_protect` (from P4-03), repair is paused
   entirely — rebuild must yield to preserve reserve space.
5. Repair progress is tracked per-shard and per-stripe in `ReplicaChunkStateRecord`.

### 5.3 Repair Worker Protocol

Each repair job executes as:

```
execute_repair_job(job):
    // 1. Read k surviving shards from their current locations
    surviving = []
    for shard_idx in surviving_shards(job.stripe_id, job.shard_idx):
        shard_data = transport.read(shard_location(shard_idx))
        surviving.push((shard_idx, shard_data))

    // 2. If reconstructed_data is already available (read-triggered), use it
    data = job.reconstructed_data
        .unwrap_or_else(|| reconstruct(surviving, job.stripe_profile))

    // 3. Verify reconstruction against checksum
    expected_checksum = stripe_checksum(job.stripe_id)
    actual_checksum = blake3(&data)
    if actual_checksum != expected_checksum:
        emit RepairChecksumMismatch { job.stripe_id }
        return Err(RepairError::ChecksumMismatch)

    // 4. Write to target location
    transport.write(job.target_location, &data)

    // 5. Verify write
    written = transport.read(job.target_location)
    verify_checksum(written, expected_checksum)

    // 6. Emit placement receipt
    emit ReplicaPlacementReceipt {
        stripe_id: job.stripe_id,
        shard_idx: job.shard_idx,
        location: job.target_location,
        status: Placed,
    }
```

### 5.4 Repair Scope: Per-Stripe vs Per-PG

This is the critical architectural distinction from Ceph:

- **Ceph**: OSD failure -> entire PG enters "degraded" -> all objects in the PG
  (100-200 per PG, ~100 PGs per OSD) are backfilled to new OSDs. Total:
  ~10,000-20,000 objects rebuilt per OSD failure, regardless of how many were
  actually on the failed OSD.
- **TideCRUSH**: Device failure -> enumerate stripes with shards on failed device
  -> rebuild only those shards. A device holding 1M shards means 1M shard
  reconstructions (each reading k surviving shards), not 1M × w stripe
  reconstructions.

In the worst case (uniform distribution), every stripe in the cluster has exactly
one shard on the failed device, so the rebuild cost is `total_stripes × k reads +
total_stripes × 1 write`. This is proportional to the cluster size, not to PG
count × objects-per-PG combinatorics.

### 5.5 Recovery Throttling

Recovery bandwidth is throttled to prevent starvation of foreground I/O:

```
recovery_budget = max(
    MIN_RECOVERY_BANDWIDTH,  // 10 MiB/s — guarantee some recovery progress
    available_bandwidth * recovery_fraction  // default 0.3 (30% of available)
)
```

When foreground I/O saturates the available bandwidth, recovery gets the minimum
budget. When foreground I/O is idle, recovery uses up to `recovery_fraction` of
available bandwidth. The remaining headroom is reserved for latency-sensitive
foreground operations.

This is configurable via pool properties:

```
tidefs pool set recovery-bandwidth-min=10M recovery-bandwidth-fraction=0.3
```

### 5.6 Lost-Stripe Protection

When more than `m` shards are lost (insufficient surviving shards for
reconstruction), the stripe is permanently lost. The system must:

1. Mark the stripe as `StripeState::Unrecoverable` in the extent map.
2. Return `EIO` for reads to the affected byte ranges.
3. Emit a `DataLossEvent` with stripe_id, affected byte range, and reason.
4. Log the event to the operator surface (`truth_view`, dashboard).
5. Never silently return truncated or zero-filled data.

This is consistent with the NO_PRODUCTION_FSCK_FAILURE_MODEL — unrecoverable
stripes are explicit, observable, and do not produce silent corruption.

## 6. Integration Contracts

### 6.1 Shard Groups (#1286)

Shard groups are a logical grouping of shards that share placement constraints
(e.g., "these 6 shards must be in 6 different racks"). TideCRUSH consumes
shard group constraints as input to the anti-affinity enforcement stage:

```
trait ShardGroupConstraint:
    fn required_domain_class(&self) -> FailureDomainClass
    fn anti_affinity_class(&self) -> AntiAffinityClass
    fn stripe_width(&self) -> usize  // w = k + m
```

The `ErasureProfileRecord` implements this trait, making each erasure profile
its own shard group.

### 6.2 Checksums (#1287)

Every shard carries a BLAKE3-256 checksum in the `IntegrityTrailerV2`
(from `CHECKSUM_ARCHITECTURE_DESIGN.md`). The integrity trailer for EC shards
includes additional fields:

```rust
pub struct IntegrityTrailerV2 {
    // ... existing fields from checksum architecture ...
    pub stripe_id: [u8; 32],       // unique stripe identifier
    pub shard_index: u8,            // 0..w-1
    pub stripe_width: u8,           // w = k + m
    pub shard_data_offset: u64,     // byte offset within the logical stripe
    pub shard_crc32c: u32,          // CRC32C over shard data (per header)
    pub payload_blake3: [u8; 32],   // BLAKE3-256 over shard data (per payload)
}
```

This enables:
- **Shard-level integrity**: verify individual shard without fetching siblings.
- **Stripe-level integrity**: verify that all shards belong to the same stripe
  and are in the correct position.
- **Corruption localization**: when a checksum mismatch occurs, the mismatch
  is localized to a specific shard, not the entire stripe. The surviving
  rebuilt from them.

### 6.3 Transport (#1229)

Erasure-coded shard transfers use the same transport session model as
replicated data (P8-01 transport session cohorts):

- Shard reads: `transport.read(ShardLocation)` — reads a single shard from
  its current placement.
- Shard writes: `transport.write(ShardLocation, data)` — writes a single
  shard to its target placement.
- Bulk rebuild: `transport.stream_rebuild(source_locations[], target_location)`
  — streams k surviving shards to the rebuild target, which performs
  reconstruction locally.

The `stream_rebuild` operation is a performance optimization: instead of
fetching k shards to the coordinator and then sending the rebuilt shard to
the target, the coordinator orchestrates a direct peer-to-peer flow where
k sources stream their shards to the target node, which reconstructs and
writes locally. This reduces network traffic from `(k reads + 1 write) ×
shard_len` to `k reads × shard_len` (the write is local to the target).

### 6.4 Rebake (#1222)

Rebake is the process of re-encoding an erasure-coded object when its profile
changes or when parity needs recomputation after partial loss. The rebake
contract defines:

```
trait RebakeSource:
    fn read_stripe(stripe_id) -> Result<Vec<u8>>
    fn write_stripe(stripe_id, profile, data) -> Result<()>
    fn reap_old_shards(stripe_id, old_profile) -> Result<()>
```

Rebake flow:

1. Read full stripe payload from surviving shards (using `reconstruct()` if any
   shards are missing, or direct read if all are present).
2. Re-encode under new profile (new k, m, shard_len).
3. Write new shards to TideCRUSH-assigned locations.
5. Emit placement receipts for new shards.
6. Mark old shards as `retire_eligible`.
7. Old shards are reclaimed by the cleaner only after all references are
   drained.

Rebake is triggered by:
- Dataset profile migration (operator-initiated).
- Stripe-level parity degradation (mismatched checksum on parity shard,
  data shards intact — recompute parity without re-reading full data).
- Topology change requiring restriping (new failure domain constraint).

### 6.5 Extent Map Integration

The extent map must track EC-specific metadata:

```rust
pub struct EcExtentMetadata {
    pub stripe_id: StripeId,
    pub profile_id: ErasureProfileId,
    pub stripe_offset: u64,        // byte offset within the logical object
    pub shard_assignments: [(u8, NodeId, DeviceId); w],  // from TideCRUSH
    pub shard_states: [ErasureShardStateClass; w],
    pub total_stripe_bytes: u64,   // k × shard_len
}
```

This is stored alongside the existing extent map entries for the dataset.

## 7. ZFS and Ceph Comparison

### 7.1 8-Dimension Analysis

| Dimension | ZFS PARITY_RAID | Ceph EC (jerasure/isa) | TideCRUSH + RS |
|-----------|-----------|----------------------|----------------|
| **Redundancy model** | PARITY_RAID1/Z2/Z3 per device, fixed disk set | EC plugin per pool, CRUSH rule per pool | EC profile per dataset, TideCRUSH per stripe |
| **Placement** | Fixed device membership, ashift-constrained | CRUSH map rules, PG-level | Per-stripe straw2 across failure-domain hierarchy |
| **Rebuild scope** | Entire device resilver (all disks in device participate) | Per-PG backfill (100-200 objects per PG) | Per-stripe shard rebuild (only affected stripes) |
| **Space efficiency** | (n-p)/n where p=parity, n=device width | (k)/(k+m), configurable | (k)/(k+m), configurable |
| **Durability model** | Tolerates p disk failures per device | Tolerates m failures per PG's acting set | Tolerates m failures per stripe across failure domains |
| **Failure domain** | Single chassis (all disks in device share PSU/backplane) | Configurable via CRUSH (host/rack/row/room/root) | 6-domain hierarchy: Device/Node/Chassis/Rack/Zone/Region |
| **Write penalty** | Full-stripe writes are optimal; partial writes suffer RMW | Full-stripe writes optimal; partial writes trigger RMW (or WAL/journal) | Full-stripe writes via commit_group batching; partial writes RMW in commit_group commit |
| **Recovery throttling** | `zfs_resilver_delay` and `zfs_scan_idle` | `osd_recovery_sleep`, `osd_max_backfills` | Bandwidth-budget throttling with priority classes |

### 7.2 Where TideCRUSH Improves on ZFS

1. **Dynamic topology**: ZFS PARITY_RAID disk sets are fixed at device creation.
   Adding a disk requires adding a new device. TideCRUSH reassigns shards
   when topology changes via membership epoch.
2. **Cross-chassis resilience**: ZFS PARITY_RAID protects against disk failure
   within a single chassis. TideCRUSH spreads shards across racks/zones,
   tolerating entire rack failures.
3. **Fine-grained rebuild**: ZFS resilver reads and rewrites all data on
   the replacement disk (up to 20 TB). TideCRUSH rebuilds only the shards
   that were on the failed device (proportional to device utilization, not
   device capacity).
4. **Heterogeneous devices**: ZFS cannot mix 1 TB and 16 TB disks in the
   same PARITY_RAID device efficiently (the smaller disk limits capacity).
   TideCRUSH uses weighted straw2 placement, so larger devices naturally
   receive proportionally more shards.
5. **No ashift constraint**: ZFS PARITY_RAID parity computation is tied to ashift
   (512B or 4K). This creates write amplification for small blocks.
   TideCRUSH uses configurable shard_len (power of two, 512B-1MiB),
   independent of device block alignment.

### 7.3 Where TideCRUSH Improves on Ceph

1. **Per-stripe rebuild**: Ceph's PG-level rebuild means losing 1 OSD
   triggers backfill of all PGs that had that OSD in their acting set.
   Each PG contains 100-200 objects. TideCRUSH rebuilds only the
   stripes that lost shards.
2. **No PG combinatorics**: Ceph PG count management (pg_num, pgp_num,
   pg_autoscale) is a frequent source of operator error and performance
   problems. TideCRUSH has no PG indirection — placement is computed
   directly per stripe.
3. **No CRUSH rule language**: Ceph operators must learn the CRUSH rule
   DSL. Incorrect rules cause silent durability violations (e.g., all
   replicas in the same rack). TideCRUSH uses compile-time typed
   failure-domain classes.
4. **No OSDMap epoch coupling**: Ceph's CRUSH map is embedded in the
   OSDMap and changes require map propagation through the monitor quorum.
   TideCRUSH placement is computed from the current membership epoch
   independently.
5. **No pg-upmap drift**: Ceph requires manual `pg-upmap` entries to
   correct placement imbalances. TideCRUSH straw2 weighting produces
   proportional distribution without manual rebalancing.

### 7.4 Where TideCRUSH Matches or Defers

1. **GF(2^8) RS**: tidefs uses the same math as Ceph's jerasure plugin
   and ZFS's PARITY_RAID parity. The encoding is mathematically equivalent.
2. **Write batching**: tidefs commit_group batching provides the same full-stripe
   write optimization that ZFS and Ceph achieve — multiple small writes
   are accumulated into a commit_group and written as full stripes.
3. **Checksum integration**: ZFS has Fletcher/checksum per block; Ceph
   has CRC32C per object; tidefs has BLAKE3-256 per shard with CRC32C
   per header — stronger integrity than both.
4. **Recovery prioritization**: ZFS resilver is single-threaded priority;
   Ceph has `osd_recovery_sleep`/`osd_max_backfills`. TideCRUSH
   bandwidth-budget throttling with three priority queues provides finer
   control.
5. **Caching**: ZFS ARC, Ceph OSD page cache, and tidefs block cache
   are equivalent at this level — all benefit from OS page cache.

## 8. Implementation Strategy

### 8.1 Phases

| Phase | Scope | Dependencies |
|-------|-------|-------------|
| **Phase 1: TideCRUSH algorithm** | Implement straw2-like domain selection, anti-affinity enforcement, device selection. Pure function, no I/O. Unit tests with mock topologies. | `tidefs-membership-epoch` (failure domains) |
| **Phase 3: Recovery Loop Orchestrator** | Repair queue, priority scheduler, bandwidth throttling, degraded-read trigger, background scrub. Integrate with existing `repair_store()`. | Phases 1-2, `tidefs-erasure-coded-store` |
| **Phase 4: Transport EC Integration** | `stream_rebuild()`, shard read/write transport operations. | #1229 (transport), Phase 3 |
| **Phase 5: Checksum EC Integration** | IntegrityTrailerV2 EC fields, shard-level checksum verification, corruption localization. | #1287 (checksums), Phase 1 |
| **Phase 6: Shard Group Integration** | ShardGroupConstraint trait, profile-to-shard-group binding. | #1286 (shard groups), Phase 2 |
| **Phase 7: Rebake Integration** | Rebake flow, profile migration, parity recomputation. | #1222 (rebake), Phase 1-5 |
| **Phase 8: Extent Map EC Integration** | EcExtentMetadata in extent map, stripe location tracking. | Phase 1, extent map V2 (#1311) |
| **Phase 9: Membership-Change Trigger** | on_member_failure enumeration, loss-recovery repair jobs. | Phase 1-3 |

### 8.2 Crate Structure

```
crates/tidefs-erasure-coding/         -- existing: GF(2^8) RS encode/decode
crates/tidefs-erasure-coded-store/    -- existing: object-level EC store + repair
crates/tidefs-erasure-placement/      -- NEW: TideCRUSH algorithm
crates/tidefs-erasure-recovery/       -- NEW: recovery loop orchestrator
crates/tidefs-erasure-profile/        -- NEW: ErasureProfileRecord, catalog
```

The existing crates remain unchanged. New functionality goes into new crates,
composing the existing engine and store as dependencies.

### 8.3 XTask Gate

```
tidefs-xtask check-erasure-coding-placement:
    test tide_crush_assign() with:
        - 3-node, 1-disk-per-node topology, (2,1) profile, Node domain
        - 6-rack × 3-node × 2-disk topology, (4,2) profile, Rack domain
        - anti-affinity strict: verify no two shards share a domain
        - anti-affinity degraded: verify duplicate domains are flagged
        - weight proportionality: 2:1 weighted nodes get ~2:1 shard ratio
        - topology change: add node, verify monotonicity
        - topology change: remove node, verify shards on removed node
          are flagged for relocation
        - edge case: fewer domains than stripe width -> degraded verdict
        - determinism: same inputs always produce same placements
    test recovery loop with:
        - degraded read triggers enqueue
        - loss recovery priority preempts scrub
        - bandwidth throttle pauses recovery under pressure
        - repair checksum mismatch aborts and logs
    test integration contracts:
        - ErasureProfileRecord roundtrip encode/decode
        - IntegrityTrailerV2 EC fields populated correctly
        - ShardGroupConstraint implemented by ErasureProfileRecord
```

## 9. Error Hierarchy

```rust
pub enum TideCRUSHError {
    /// Topology has no alive members at the required domain class.
    NoAliveMembers { domain_class: FailureDomainClass },

    /// Too few domain cells to satisfy anti-affinity requirement.
    InsufficientDomainSpread {
        required: usize,
        available: usize,
        domain_class: FailureDomainClass,
    },

    /// Anti-affinity retries exhausted.
    AntiAffinityRetriesExhausted {
        shard_index: usize,
        retries: usize,
        domain_class: FailureDomainClass,
    },

    /// Invalid erasure profile (k=0, m=0, etc.).
    InvalidProfile { reason: String },

    /// Profile not found in catalog.
    UnknownProfile { profile_id: ErasureProfileId },
}

pub enum RecoveryError {
    /// Insufficient surviving shards for reconstruction.
    InsufficientShards { available: usize, required: usize },

    /// Reconstructed data failed checksum verification.
    ChecksumMismatch { stripe_id: StripeId, expected: [u8; 32], actual: [u8; 32] },

    /// Write to target location failed.
    WriteFailed { location: ShardLocation, reason: String },

    /// Recovery paused due to memory pressure.
    PausedForPressure { pressure_stage: PressureStage },

    /// Recovery throttled to bandwidth limit.
    Throttled { current_budget: u64 },
}
```

## 10. Deterministic Constraint Knobs

All tuning constants are explicit, named, and documented.

| Constant | Default | Meaning |
|----------|---------|---------|
| `ANTI_AFFINITY_MAX_RETRIES` | 3 | Max retries before accepting degraded placement |
| `MIN_RECOVERY_BANDWIDTH_BYTES` | 10 MiB/s | Guaranteed minimum recovery bandwidth |
| `RECOVERY_BANDWIDTH_FRACTION` | 0.30 | Max fraction of available bandwidth for recovery |
| `MAX_CONCURRENT_REPAIR_TRANSFERS` | 4 | Max concurrent repair transfers per node |
| `SCRUB_STRIPES_PER_COMMIT_GROUP` | 1000 | Stripes scrubbed per commit_group commit |
| `SCRUB_CYCLE_INTERVAL_DAYS` | 7 | Days between full scrub cycles |
| `SHARD_LEN_MIN` | 512 | Minimum shard length (bytes, power of two) |
| `SHARD_LEN_MAX` | 1 MiB | Maximum shard length (bytes, power of two) |
| `REPAIR_QUEUE_CAPACITY` | 10000 | Max pending repair jobs before backpressure |

## 11. Open Questions

1. **Should TideCRUSH placement be cached?** Computing placement per read is
   cheap (BLAKE3 + straw2 traversals, ~10 μs), but for high-IOPS workloads
   (1M IOPS), that's 10 seconds of CPU per second. Consider a per-stripe

2. **Should EC-2+1 use PARITY_RAID1 XOR optimization?** The GF(2^8) engine already
   optimizes single parity via XOR. Confirm that `compute_parity()` in
   `tidefs-erasure-coding` correctly dispatches to XOR for `ParityCount::Single`
   (it does — verified in the existing code at line ~240).

3. **Should the recovery loop use cooperative or preemptive scheduling?**
   Current design uses cooperative (repair jobs yield at batch boundaries).
   Preemptive scheduling (interrupt repair mid-transfer for foreground I/O)
   would reduce tail latency but adds complexity. Start with cooperative,
   measure tail latency.

4. **Should the erasure profile catalog be compile-time or runtime?** Runtime
   catalog (stored as pool metadata) allows adding new profiles without
   upgrading tidefs. Compile-time catalog ensures consistency across cluster
   members. Recommendation: compile-time catalog with runtime registration
   for custom profiles (gated behind operator config).

5. **Should TideCRUSH use a dedicated placement service or compute inline?**
   Inline computation (as designed) avoids a placement service as a single
   point of failure/contention. However, the topology must be consistent
   across all nodes computing placement. The membership epoch provides this
   consistency.

## 12. References

- [#1249] This design spec
- [#1222] Rebake: erasure-coded parity recomputation
- [#1286] Shard groups for EC placement
- [#1287] End-to-end checksum architecture (G3 pillar)
- [#1229] Transport session cohort graph
- [#1311] V2 B-tree extent map engine
- `docs/MEMBERSHIP_PLACEMENT_FAILURE_DOMAIN_MODEL_P8-02.md`
- `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md`
- `docs/ERASURE_CODED_LAYOUT_OW306.md`
- `docs/CHECKSUM_ARCHITECTURE_DESIGN.md`
- Ceph CRUSH: "CRUSH: Controlled, Scalable, Decentralized Placement of
  Replicated Data" (Weil et al., SC 2006)
- Ceph straw2: https://docs.ceph.com/en/latest/rados/operations/crush-map/#straw2-buckets
