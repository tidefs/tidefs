# OpenZFS/Ceph Successor Claim (Historical Input)

**Current authority notice:** This imported file is historical design input,
not a current TideFS capability, performance-superiority, cost-effectiveness,
flash-wear, RAM, WAN, durability, or OpenZFS/Ceph successor claim. The claims
gate currently blocks publishing an OpenZFS/Ceph successor claim. Any future
retained product-facing comparison must be expressed through a #875 claim id
and the comparator evidence required by #928/#930.

Historical status: sealed design-spec for the TideFS successor claim to
OpenZFS and Ceph, with an 8-dimension quantitative comparison covering
placement granularity, failure-domain flexibility, topology dynamics, device
heterogeneity, checksum integrity, redundancy model, algorithm simplicity,
and codebase efficiency.

**Issue:** #1786
**Lane:** storage-core
**Kind:** design
**Sealed:** 2026-05-05
**Sealed lineage:** #1279 → #1640 → #1706 → #1871 → #2075 → #1786

---

## 0. Historical Seal Notice

This section records the historical imported seal. It is not current TideFS
claim authority. The 8-dimension comparison, quantified improvements, and
architectural analysis described here may be used as design input only until a
future claim is explicitly registered through #875 and backed by #928/#930
comparator evidence.

**Rust implementation is deferred to wire-up issues.** Each dependency
(TideCRUSH placement, recovery orchestrator, rebake service, checksum
architecture, membership epoch) is tracked by its own sealed design spec
and implementation issues. Implementers must reference this sealed spec
in their implementation issues and must not deviate from the claims, dimensions,
or quantified improvements defined here without first opening a new
design issue.

The design decisions recorded in Sections 2-8 are not binding current
successor-claim authority unless a current issue, current spec, and claim
evidence chain explicitly re-adopts the specific statement.

---

**Issue**: [#1786](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1786)
**Maturity**: design-spec — 8-dimension quantitative comparison with ZFS PARITY_RAID
**Lane**: storage-core
**Kind**: design
**Status**: sealed → design-spec

## 0. Executive Summary

Historically, this document described TideFS as a next-generation successor to
both OpenZFS and Ceph. It recorded 60 alleged design mistakes from those
systems (38 ZFS, 22 Ceph) and a target redundancy model: **per-stripe
erasure-coded placement with deferred redundancy via budgeted rebake**. This
document does not establish a current quantitative claim. It preserves the
historical 8-dimension framing as input for future #875/#928-gated evidence.

The historical claim framing rests on four pillars:

| Pillar | TideFS design | ZFS equivalent | Ceph equivalent |
|--------|--------------|----------------|-----------------|
| **Placement** | TideCRUSH: per-stripe deterministic hash across 6-domain hierarchy | Fixed device disk set; per-device PARITY_RAID | CRUSH straw2: per-PG placement with upmap complexity |
| **Redundancy** | Deferred EC via rebake; durability ladder (None→Replicated→ErasureCoded) | Immediate PARITY_RAID at write time; write amplification on every IO | Immediate replication at write time; multi-hop latency |
| **Integrity** | Mandatory two-tier checksums (CRC32C + BLAKE3-256); per-shard digests | End-to-end 256-bit checksums in block pointers | Optional per-object checksums (crc32c/xxhash64) |
| **Dynamics** | Lazy bounded rebalancing via membership epoch; no frozen PG count/device | Frozen device at creation; no restriping | PG count frozen; catastrophic CRUSH rebalancing |

The 60-mistake coverage matrix provides the negative proof (what we avoid);
this document provides the positive proof (what we achieve).

## 1. Architecture Overview

### 1.1 System Decomposition

```
┌──────────────────────────────────────────────────────────────────────┐
│                    TideFS Storage Stack                                │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────────────┐  │
│  │  TideCRUSH   │  │  Recovery     │  │     Rebake Service       │  │
│  │  Placement   │  │  Orchestrator │  │                          │  │
│  │              │  │               │  │  ingest -> base shards   │  │
│  │ shard->device│  │ trigger/queue │  │  durability ladder       │  │
│  │ straw2 hash  │  │ priority/sched│  │  budgeted background     │  │
│  └──────┬───────┘  └───────┬───────┘  └───────────┬──────────────┘  │
│         │                  │                       │                  │
│         ▼                  ▼                       ▼                  │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │              Membership Epoch (OW-302/OW-303)                   │   │
│  │  Device/Node/Chassis/Rack/Zone/Region failure-domain hierarchy │   │
│  │  Config epoch synthesis, cohort population, placement verdicts  │   │
│  └───────────────────────────────────────────────────────────────┘   │
│         │                  │                       │                  │
│         ▼                  ▼                       ▼                  │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │                    Checksum Architecture (G3)                    │   │
│  │  CRC32C header sanity + BLAKE3-256 payload integrity           │   │
│  │  Domain-separated per-record-type contexts                     │   │
│  │  Per-shard IntegrityTrailerV2, SegmentIntegrityFooter chaining │   │
│  └───────────────────────────────────────────────────────────────┘   │
│         │                  │                       │                  │
│         ▼                  ▼                       ▼                  │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │                    Transport + Pool Management                  │   │
│  │  Shard read/write, pool import/export, device topology mgmt    │   │
│  │  PoolLabelV1 with 2-copy on-device labels, DEGRADED/FAILED FSM │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### 1.2 Write Path: Deferred Redundancy Model

TideFS's central architectural distinction from both ZFS and Ceph is the
**deferred redundancy model**:

```
Write Request
     │
     ▼
[1] Ingest extent: single-device append, minimal latency
     │  - One device, one copy, CRC32C framing + BLAKE3-256 digest
     │  - Durability ladder level: None
     │
     ▼ (after ingest_window expires, configurable, default 60s)
[2] Replication (optional): r copies across anti-affinity devices
     │  - Durability ladder level: Replicated
     │  - Emergency rebake if replica count drops below threshold
     │
     ▼ (background, budgeted, low priority)
[3] Rebake: k+m erasure-coded shards across k+m devices
     │  - TideCRUSH placement with anti-affinity constraints
     │  - Durability ladder level: ErasureCoded
     │  - Original ingest fragments reclaimed for space
     │
     ▼
[4] Base shards: durable, space-efficient, self-healing
     - Per-stripe recovery; read-triggered + scrub + topology-driven repair
```

| Aspect | ZFS | Ceph | TideFS |
|--------|-----|------|--------|
| Write latency | Pay k+m stripe write immediately | Pay r-way replication immediately | Pay single-device latency; redundancy deferred |
| Write amplification | Always 1/(1 - m/k) | Always r* | 1* at ingest; (k+m)/k at rebake |
| Ingest window risk | None (redundant at write) | None (replicated at write) | Protected by durability ladder + emergency rebake |
| Space efficiency | Good (parity overhead) | Good (replica overhead) | Excellent after rebake; ingest fragments reclaimed |

## 2. Core Data Structures

### 2.1 ShardGroupV1 — On-Media Erasure Coding Record

```rust
/// A shard group encodes one extent as k data shards + m parity shards.
pub struct ShardGroupV1 {
    pub group_id: [u8; 16],           // 1:1 with locator_id
    pub ec_k: u8,                      // data shards
    pub ec_m: u8,                      // parity shards
    pub flags: u8,                     // COMPACTED | BASE_COMPLETE
    pub logical_offset: u64,           // byte range start
    pub logical_length: u64,           // byte range length
    pub original_digest: [u8; 32],     // BLAKE3-256 over logical bytes
    pub shards: Vec<ShardDescriptor>,  // (k+m) descriptors
    pub replica_count: u8,             // for replicated datasets
    pub reserved: [u8; 9],
    pub crc32c: u32,                   // over all preceding fields
}

/// One shard within a shard group.
pub struct ShardDescriptor {
    pub shard_index: u8,               // 0..k-1 = data, k..k+m-1 = parity
    pub device_id: u32,                // physical device
    pub shard_digest: [u8; 32],        // BLAKE3-256 over shard payload
    pub shard_length: u32,             // bytes
    pub reserved: [u8; 7],
}
```

### 2.2 IntegrityTrailerV2 — Per-Record Checksum Trailer

```rust
pub struct IntegrityTrailerV2 {
    pub magic: [u8; 8],                // "VLOSINT4"
    pub digest_suite: u16,             // 1 = BLAKE3-256
    pub payload_digest: [u8; 32],      // BLAKE3-256 over payload
    pub record_digest: [u8; 32],       // BLAKE3-256 over header+payload
    pub shard_count: u8,               // for EC shards
    pub shard_index: u8,               // 0-based
    pub ec_k: u8,
    pub ec_m: u8,
    pub reserved: [u8; 28],
}  // 112 bytes
```

Domain-separated BLAKE3 contexts prevent cross-type collision:

| Record type | Domain context |
|---|---|
| `InodeRecord` | `"tidefs.inode.v1"` |
| `ExtentMapEntry` | `"tidefs.extent_map.v1"` |
| `DataShard` | `"tidefs.data_shard.v1"` |
| `IntentLogEntry` | `"tidefs.intent_log.v1"` |

### 2.3 ErasureProfileRecord — Catalog Entry

```rust
pub struct ErasureProfileRecord {
    pub profile_id: ErasureProfileId,
    pub data_shards: u8,               // k
    pub parity_count: u8,              // m
    pub shard_len: u32,                // bytes, power of two
    pub required_domain_class: FailureDomainClass,
    pub anti_affinity_class: AntiAffinityClass,
}
```

### 2.4 Membership Epoch Topology

The 6-domain failure hierarchy is encoded in membership epoch records:

```rust
pub enum FailureDomainClass {
    Device,    // single disk
    Node,      // single server
    Chassis,   // shared PSU + backplane
    Rack,      // shared ToR switch + PDU
    Zone,      // shared power grid + cooling
    Region,    // geographic isolation
}

pub struct FailureDomainPlacementPolicy {
    pub required_class: FailureDomainClass,
    pub anti_affinity_class: AntiAffinityClass,
    pub max_shards_per_domain: Option<u32>,
}
```

### 2.5 Durability Ladder States

```rust
pub enum DurabilityLevel {
    None,            // single copy, ingest only
    Replicated(u8),  // r copies on distinct anti-affinity devices
    ErasureCoded {    // k+m shards across (k+m) devices
        profile: ErasureProfileRecord,
        shard_group: ShardGroupV1,
    },
}
```

## 3. Core Algorithms

### 3.1 TideCRUSH: Deterministic Per-Stripe Placement

TideCRUSH maps `(object_id, epoch, profile) -> [(node, device)]` across
`w = k + m` shards with anti-affinity guarantees.

**Input**: `object_id` (32 bytes), `epoch` (u64), `profile` (ErasureProfileRecord)
**Output**: `Vec<(ShardIndex, NodeId, DeviceId)>` of length `w`

**Stage 1 — Hash pool construction**:
```
hash_input = BLAKE3(object_id || epoch.to_le_bytes() || profile.discriminant())
xof = BLAKE3::new().update(hash_input).finalize_xof()
```

**Stage 2 — Straw2-weighted domain selection** (per shard):
```
for shard_idx in 0..w:
    domain = select_domain(xof, topology_root, shard_idx, required_class)
    // select_domain is recursive straw2: weighted random walk down tree
    // stopping at required_class nodes
```

**Stage 3 — Device selection within domain**:
```
device = select_device(xof, domain, shard_idx)
// uniform random among alive devices weighted by device capacity
```

**Stage 4 — Anti-affinity enforcement**:
```
if already_placed_in_failure_domain(shard_idx, domain.anti_affinity_class):
    retry with next domain draw (max 3 retries; else accept duplicate)
```

**Stage 5 — Assignment output**:
```
return [(0, node_0, dev_0), (1, node_1, dev_1), ..., (w-1, node_{w-1}, dev_{w-1})]
```

**Straw2 weight function** (adapted from Ceph):
```
straw2_weight(hash, item_id, shard_idx) =
    let x = hash_to_f64(hash, item_id || shard_idx)
    device_weight * ln(1.0 / max(x, f64::MIN_POSITIVE))
```

### 3.2 Recovery Loop Orchestration

Three trigger types drive recovery:

| Trigger | Priority | Scope | Mechanism |
|---|---|---|---|
| **Degraded Read** | ReadTriggered (1) | Single missing shard | Synchronous reconstruct from k survivors; enqueue background repair |
| **Background Scrub** | Scrub (2) | All stripes (cyclic) | Verify per-shard BLAKE3; enqueue repair for mismatches |
| **Membership Change** | LossRecovery (0) | All shards on failed member | Enumerate affected stripes; enqueue batch repair to new targets |

**Recovery scheduler rules**:
1. LossRecovery always preempts lower-priority repair.
2. Max N concurrent repair transfers (default N=4 per node).
3. Recovery bandwidth capped at R bytes/s (default 100 MiB/s, configurable).
4. Repair pauses entirely when memory_pressure exceeds reserve threshold.
5. Per-stripe repair reads k surviving shards, reconstructs, writes 1 shard.

**Critical advantage**: Per-stripe rebuild scope. ZFS must resilver an entire
device (potentially TBs) when a single disk fails. Ceph must backfill entire PGs
(10,000–20,000 objects per OSD failure). TideCRUSH rebuilds only the shards
actually placed on the failed device — proportional to cluster size, not PG
combinatorics.

### 3.3 Rebake: Ingest-to-Base Conversion

The rebake service converts ingest extents to erasure-coded base shards under
a background budget:

```
rebake_cycle(dataset):
    for each ingest extent older than ingest_window:
        1. Read extent data from ingest device
        2. Verify BLAKE3-256 digest against IntegrityTrailerV2
        3. Select erasure profile (k,m) from dataset feature flags
        4. Encode: data -> k data shards + m parity shards (GF(2^8) RS)
        5. Compute TideCRUSH placement for (k+m) shards
        6. Write shards to target devices; verify write with read-back + digest
        7. Emit ShardGroupV1 record with placement receipts
        8. Mark ingest extent for deferred cleanup
        9. Emit RebakeProgressEvent to observability pipeline
    update_rebake_cursor()
```

**Budget constraints**:
- Max rebake bandwidth: 50 MiB/s default (configurable per dataset)
- Paused when foreground IO latency exceeds SLO threshold
- Paused when memory pressure exceeds reserve
- Persists rebake cursor for crash recovery

### 3.4 Checksum Verification Pipeline

Every read follows a mandatory verification pipeline:

```
Read path:
1. Read record header from segment
2. Verify CRC32C framing -> StoreError::FramingError on mismatch
3. Read payload + IntegrityTrailerV2
4. Verify BLAKE3-256 payload_digest -> mismatch -> attempt repair from survivors
5. Verify BLAKE3-256 record_digest (header+payload) -> mismatch -> escalate
6. For EC reads: verify per-shard shard_digest -> mismatch -> reconstruct from k survivors
7. Return verified data to caller

On checksum mismatch:
1. Mark record in SuspectLog (persistent corruption tracking)
2. If redundant copy exists: repair from healthy shard
3. If no redundant copy: return IO error with SuspectRecordId
4. Emit ChecksumMismatchEvent to observability pipeline
```

**Segment-level chaining**: Each segment footer carries `previous_segment_digest`,
creating a tamper-evident hash chain across all committed segments.

### 3.5 5-Constraint Placement Pipeline (PC-010.2)

The production placement algorithm filters candidate devices through five
constraints, producing deterministic target assignments:

```
for each placement request (stripe, count):
    candidates = all_alive_devices(epoch)

    // Constraint 1: Anti-affinity — no two shards in same failure domain
    candidates = filter_anti_affinity(candidates, policy, already_placed)

    // Constraint 2: Health — exclude DEGRADED/FAILED/EVACUATING devices
    candidates = filter_health(candidates)

    // Constraint 3: Capacity — exclude devices with < shard_len free
    candidates = filter_capacity(candidates, shard_len)

    // Constraint 4: Pin budget — respect per-device shard count limits
    candidates = filter_pin_budget(candidates, max_shards_per_device)

    // Constraint 5: Load-balancing tiebreaker — straw2-weighted random
    selected = straw2_select(candidates, count)

    return PlacementDecision { selected, refusal_verdicts }
```

## 4. Eight-Dimension Comparison

### Dimension 1: Placement Scope

| System | Scope | Rebuild unit | Impact |
|---|---|---|---|
| ZFS PARITY_RAID | Per-device: all stripes on fixed disk set | Entire device (TBs) | Days to resilver large devices |
| Ceph CRUSH | Per-PG: ~100-200 objects per PG | Entire PG (10K-20K objects per OSD) | Massive data movement on OSD failure |
| **TideCRUSH** | Per-stripe: individual shards | Only shards on failed device | Rebuild proportional to device utilization, not PG/device combinatorics |

**Quantified improvement**: For a 100 TB pool with 20 devices across 4 racks,
a single device failure triggers:
- ZFS: rebuild ~5 TB (entire device)
- Ceph: rebuild ~5 TB * PG amplification (backfill all PGs on failed OSD)
- TideFS: rebuild ~5 TB (only actual shards on the failed device, k reads each)

### Dimension 2: Failure-Domain Flexibility

| System | Hierarchy | Configuration |
|---|---|---|
| ZFS | Single chassis (all disks in one device) | Fixed at device creation |
| Ceph | CRUSH map with bucket types (osd/host/chassis/rack/row/pdu/pod/room/datacenter/region/root) | Arbitrary but complex rule language |
| **TideFS** | 6-domain hierarchy: Device->Node->Chassis->Rack->Zone->Region | Declarative Rust struct, no rule language |

**Advantage**: TideFS's `FailureDomainClass` is a Rust enum with compile-time
verification. Ceph's CRUSH rule language is a DSL that operators must learn
and debug. ZFS has no failure-domain awareness beyond device membership.

### Dimension 3: Topology Dynamics

| System | Device addition | Device removal | Rebalancing |
|---|---|---|---|
| ZFS | Add device (fixed disk set); no restriping | Manual replace or pool DEGRADED | None; new writes only |
| Ceph | Add OSD; CRUSH rebalance triggers massive movement | OSD out -> PG remapping -> backfill | Unbounded lazy rebalancing; catastrophic with small topology changes |
| **TideFS** | Membership epoch update; lazy bounded relocation | Membership epoch update; targeted shard repair | Budgeted relocation; bounded by recovery bandwidth cap |

**Advantage**: TideFS's membership epoch provides a deterministic epoch-gated
topology state. Ceph's OSDMap grows unboundedly with cluster history (monitor
OOM risk). ZFS devices are frozen at creation with no restriping path.

### Dimension 4: Device Heterogeneity

| System | Mixed sizes | Sector alignment | Weight model |
|---|---|---|---|
| ZFS | All disks in device must be same size | ashift baked in at device creation; can't add 4K-native later | None; uniform stripe distribution |
| Ceph | Supported via CRUSH device weight | Per-OSD; flexible | CRUSH weight + pg-upmap entries for balance |
| **TideFS** | Heterogeneous via straw2 device weights | Variable per-device sector alignment | Straw2 proportional distribution; no manual upmap needed |

**Advantage**: ZFS's ashift is a device-level property frozen at creation.
Adding a 4K-native drive to a 512-byte ashift pool wastes space. TideFS
supports per-device sector alignment (#1280) with heterogeneous device
weights ensuring proportional data distribution.

### Dimension 5: Placement Algorithm Simplicity

| System | Algorithm | Configurability | Correctness |
|---|---|---|---|
| ZFS | Fixed device membership (no placement algorithm) | None | Trivial (but inflexible) |
| Ceph | CRUSH straw2 with rule language, tunables, chooseleaf variants, indep/firstn modes | High but fragile | Notoriously hard to reason about; catastrophic misconfiguration possible |
| **TideCRUSH** | Straw2-weighted deterministic hash; single algorithm | Low — profile selection only (k,m) | Predictable behavior; compile-time-verified policy |

**Advantage**: TideCRUSH intentionally omits Ceph's CRUSH tunables (chooseleaf
variants, indep vs firstn, rule language). A single algorithm with predictable
behavior is preferred over configurable but fragile tuning knobs.

### Dimension 6: Checksum Integrity

| System | Header checksum | Payload checksum | Domain separation | Per-shard digest | Corruption tracking |
|---|---|---|---|---|---|
| ZFS | None (checksum in block pointer, not record header) | SHA-256/fletcher4/edonr (configurable per dataset) | None | Implicit (per-block) | No persistent log |
| Ceph | None | Optional crc32c/xxhash64 per-object (per-pool opt-in) | None | None | None |
| **TideFS** | CRC32C (hw-accelerated, ~0.15 cycles/byte) | BLAKE3-256 (mandatory, non-optional) | Per-record-type BLAKE3 key derivation | Per-shard IntegrityTrailerV2 | Persistent SuspectLog |

**Advantage**: ZFS's checksums are configurable but not mandatory (can be set
to `off`). Ceph's checksums are optional per-pool with silent corruption possible
when disabled. TideFS's checksums are mandatory and non-optional — a
checksum-verified read never returns corrupt data silently.

### Dimension 7: Recovery Parallelism

| System | Resilver/repair unit | Parallelism model | Throttling |
|---|---|---|---|
| ZFS | Entire device (sequential tree-ordered resilver) | Single-threaded commit_group sync | None built-in |
| Ceph | Entire PG (backfill) | Per-OSD parallelism; configurable max backfills | osd_max_backfills (default 1) |
| **TideFS** | Per-stripe shard | N concurrent repair transfers per node (default 4) | Bandwidth cap (100 MiB/s default); memory-pressure-aware pause |

**Advantage**: ZFS's sequential tree-ordered resilver is a well-known
bottleneck — days for large pools. Ceph can parallelize but per-PG scope
means massive data movement even for small failures. TideFS combines
per-stripe scope with configurable parallel repair.

### Dimension 8: Write-Path Redundancy Model

| System | Write latency | Write amplification | Ingest window risk | Space after stabilization |
|---|---|---|---|---|
| ZFS | Pay PARITY_RAID stripe write immediately (k+m writes) | Always (k+m)/k | Zero (redundant at write) | Good (parity overhead) |
| Ceph | Pay replication hop immediately (r writes) | Always r* | Zero (replicated at write) | Good (replica overhead) |
| **TideFS** | Single-device latency | 1* at ingest; (k+m)/k at rebake | Protected by durability ladder + emergency rebake | Excellent (erasure-coded; ingest fragments reclaimed) |

**Advantage**: TideFS's deferred redundancy model trades ingest-window risk
for 50-75% lower write amplification on the fast path. The durability ladder
ensures that data aging past the ingest window is automatically promoted to
full redundancy. Emergency rebake provides safety against device failure during
the ingest window.

## 5. Tradeoff Analysis

### 5.1 Deferred Redundancy vs. Immediate Redundancy

**TideFS choice**: Deferred redundancy via rebake.

| Aspect | Pro | Con |
|---|---|---|
| Write latency | Single-device write (no amplification) | Ingest window data at risk |
| Write throughput | No redundancy tax on hot path | Rebake consumes background IO budget |
| Read path | Reads from ingest or base shards transparently | Cold reads may hit ingest fragments (slower) |
| Crash recovery | Lost ingest extents recoverable from intent log | Unbaked extents lost on device failure before rebake |

**Mitigation**: The durability ladder triggers emergency rebake when replica
counts drop below threshold. The ingest window is configurable (default 60s)
and can be set to 0 for datasets requiring immediate redundancy.

### 5.2 Straw2 Simplicity vs. CRUSH Flexibility

**TideFS choice**: Single straw2 algorithm, no rule language.

| Aspect | Pro | Con |
|---|---|---|
| Operator learning curve | Minimal: select profile, configure domain class | Cannot express exotic placement policies |
| Correctness | Deterministic; same input -> same output | No "CRUSH tunables" for fine-tuning |
| Debugging | Placement is reproducible from (object_id, epoch) | Cannot manually override placement |

**Mitigation**: The failure-domain hierarchy (6 classes) covers the vast
majority of real-world topologies. For exotic requirements, the ADMIN
service can provide manual placement overrides at the dataset level.

### 5.3 Per-Stripe vs. Per-Device/Per-PG Granularity

**TideFS choice**: Per-stripe granularity.

| Aspect | Pro | Con |
|---|---|---|
| Rebuild scope | Proportional to actual data on failed device | More placement metadata (ShardGroupV1 per extent) |
| Flexibility | Any device combination per stripe | Slightly higher CPU for placement computation |
| Metadata overhead | ShardGroupV1: 80 + (k+m)*48 bytes per extent | For small extents, metadata overhead is non-trivial |

**Mitigation**: Extent sizes are tuned per profile (4 KiB-256 KiB shard lengths)
to amortize metadata overhead. For datasets with many small extents, replication
(DurabilityLevel::Replicated) is recommended over erasure coding.

### 5.4 Mandatory Checksums vs. Optional

**TideFS choice**: Mandatory, non-optional two-tier checksums.

| Aspect | Pro | Con |
|---|---|---|
| Data integrity | Silent corruption impossible; every read verified | CPU overhead per read (CRC32C + BLAKE3-256) |
| Performance | CRC32C is hw-accelerated (~0.15 cycles/byte); BLAKE3 is ~3 cycles/byte on Zen 4 | ~3% throughput overhead for small reads |
| Simplicity | Single algorithm (BLAKE3-256); no configurable options | No checksum algorithm choice for performance-sensitive workloads |

**Mitigation**: CRC32C framing check catches structural corruption essentially
free. BLAKE3-256 is one of the fastest cryptographic hash functions. The
overhead is well within the noise floor of device IO latency.

### 5.5 Membership Epoch vs. OSDMap vs. Device Labels

**TideFS choice**: Deterministic epoch-gated membership with per-device labels.

| Aspect | Pro | Con |
|---|---|---|
| State size | Bounded; epoch carries only current topology | Requires agreement on epoch transitions |
| History | Device labels carry current pool_guid + commit_group; no epoch history | Cannot reconstruct historical topology without external archive |
| Portability | PoolLabelV1 is self-describing 122-byte binary; cross-system portable | No distributed consensus for topology changes in standalone mode |

**Mitigation**: For cluster mode, the membership epoch is agreed via the
distributed lock service (#1248). For standalone mode, pool import discovers
topology from on-device labels alone.

## 6. Implementation Status

### 6.1 Implemented (Source-Bound)

| Component | Crate/File | Lines | Gate |
|---|---|---|---|
| Membership epoch model | `crates/tidefs-membership-epoch` | 2895 | `tidefs-xtask check-membership-epoch-model` |
| GF(2^8) Reed-Solomon engine | `crates/tidefs-erasure-coding` | 821 | `tidefs-xtask check-erasure-coding` |
| Object-level EC store | `crates/tidefs-erasure-coded-store` | 953 | Unit tests |
| Replication model (OW-306) | `crates/tidefs-replication-model` | 4764 | `tidefs-xtask check-erasure-coded-layout` |
| 5-constraint placement pipeline | `crates/tidefs-placement-runtime` + `tidefs-placement-planner` | — | 30 tests |

### 6.2 Design-Spec (Not Yet Implemented)

| Component | Document | Issue |
|---|---|---|
| TideCRUSH placement engine | `docs/ERASURE_CODING_PLACEMENT_DESIGN.md` | #1249 |
| Recovery loop orchestrator | `docs/ERASURE_CODING_PLACEMENT_DESIGN.md` S5 | #1249 |
| Erasure family catalog | `docs/ERASURE_CODING_PLACEMENT_DESIGN.md` S4 | #1249 |
| Shard groups + rebake | `docs/SHARD_GROUPS_REPLICAS_REBAKE_DESIGN.md` | #1286 |
| End-to-end checksum architecture | `docs/CHECKSUM_ARCHITECTURE_DESIGN.md` + `docs/design/end-to-end-checksum-architecture-g3-pillar.md` | #1287, #1559 |
| Pool import/export + device topology | `docs/design/pool-import-export-device-topology-management.md` | #2084, #2078 |
| Scrub/repair/resilver | `docs/SCRUB_REPAIR_RESILVER_DESIGN.md` | #1221 |

### 6.3 Production Runtime Gaps

The following are designed but not yet implemented as production runtime:

- Networked replication transport and data movers
- Live distributed storage runtime
- Anti-entropy scan scheduling with repair execution
- Production rebuild/backfill/rebalance orchestration
- Capacity-movement execution under overloaded target pressure

These gaps are tracked in the PC-010 blocker map
(`docs/REDUNDANCY_PLACEMENT_RECOVERY_BLOCKER_MAP_PC010A.md`).

## 7. Relationship to 60-Mistake Coverage Matrix

The [ZFS and Ceph Design Mistake Coverage Matrix](../ZFS_CEPH_DESIGN_MISTAKE_COVERAGE_MATRIX.md)
enumerates 60 design mistakes (38 ZFS, 22 Ceph), all COVERED by TideFS
design issues. In current authority, that coverage is historical input only:
it does not prove an implemented-source, runtime, measured, or successor
claim. Each positive statement below needs current issue/spec adoption plus
#875/#928 evidence before it can become product-facing.

| Mistake category | Count | Representative TideFS solution |
|---|---|---|
| Placement inflexibility | 8 | TideCRUSH per-stripe placement (#1249) |
| Recovery bottlenecks | 7 | Per-stripe parallel repair; background scrub (#1221, #1249) |
| Checksum gaps | 5 | Mandatory two-tier checksums with SuspectLog (#1287) |
| Topology/device rigidity | 6 | 6-domain hierarchy; variable sector alignment (#1280, #1254) |
| Metadata scaling | 5 | Polymorphic indexes; metadata engine parallelism (#1278) |
| Write-path fragility | 7 | Intent log; deferred cleanup; torn-commit recovery (#1252, #1190) |
| Cache/resource isolation | 6 | Per-tenant cache domains; unified resource governor (#1237) |
| Snapshot/management gaps | 9 | Per-dataset limits; resumable send/recv (#1277, #1251) |
| State growth | 4 | Bounded epoch state; no OSDMap history (#1283) |
| Other operational gaps | 3 | Online dataset rename; geometry conversion (#1282, #1275) |


Historically, the successor claim was expected to transition from
*aspirational* to *design-spec* when all referenced design documents were
sealed. Under current authority, it transitions to *implemented-source* only
when the four pillars (placement, redundancy, integrity, dynamics) are

**Current gate**: `cargo check --workspace` (no breakage from this document).

**Future gates** (post-implementation):
- `tidefs-xtask check-erasure-coding-placement`
- `tidefs-xtask check-shard-groups-rebake`
- `tidefs-xtask check-checksum-architecture`
- `tidefs-xtask check-recovery-orchestration`
- xfstests-grade recovery truthfulness under failures

## 9. References

- [#1786](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1786) — This issue
- [#1279](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1279) — ZFS/Ceph mistake coverage matrix
- [#1249](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1249) — Erasure coding placement design
- [#1286](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1286) — Shard groups + rebake
- [#1287](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1287) — Checksum architecture
- [#1221](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1221) — Scrub/repair/resilver
- [#2084](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2084) — Pool import/export seal
- [#1283](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1283) — Bounded cluster membership
- [#1237](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1237) — Unified resource governor
- [#1252](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1252) — Intent log + write-intent bitmap
- `docs/ZFS_CEPH_DESIGN_MISTAKE_COVERAGE_MATRIX.md`
- `docs/ERASURE_CODING_PLACEMENT_DESIGN.md`
- `docs/SHARD_GROUPS_REPLICAS_REBAKE_DESIGN.md`
- `docs/CHECKSUM_ARCHITECTURE_DESIGN.md`
- `docs/REDUNDANCY_PLACEMENT_RECOVERY_BLOCKER_MAP_PC010A.md`
- `docs/design/pool-import-export-device-topology-management.md`
- `docs/FEATURE_MATRIX.md`
