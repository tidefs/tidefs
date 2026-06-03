# Device Layout Policies and Adaptive Segment Sizing Design

Maturity: **design-spec** for the device layout policy abstraction, auto-scaling
segment size algorithm, per-region segment sizing with power-of-two alignment,
DeviceLayoutV1 on-media record, and deterministic pool-scaling constraints.

This document closes Forgejo issue #1193. It has been superseded by the refined design specification in docs/design/device-layout-policies-adaptive-segment-sizing.md (closing #1596).

## 1. Motivation

The current codebase allocates segments at a fixed size (`DEFAULT_MAX_SEGMENT_BYTES =
64 MiB` in `tidefs-local-object-store/src/constants.rs`), with fixed journal region
sizes assumed implicitly during pool creation. This works for testing but does not
scale:

- A 1 MiB segment on a 1 PB pool produces ~1e9 segments — the bring-up scan cost
  during pool import (walking all segments to reconstruct the free map) is
  prohibitive. Even a ZFS metaslab scan at ~200 GiB each would be cheaper.
- Fixed journal sizes waste space on large devices (padding unused region capacity)
  or starve on small ones (journal too small for burst writes).
- No explicit layout policy abstraction exists — layout decisions are embedded
  inline in pool open code (`pool.rs`), making per-device-class sizing impossible.
- The Python v0.262 reference implementation had a clean, deterministic layout
  policy system with auto-scaling. The Rust implementation must match or exceed it.

This design defines a `DeviceLayoutPolicy` that computes region boundaries and
segment sizes deterministically from device properties, keeping segment counts
within a reasonable bound regardless of pool scale.

## 2. Design Overview

The layout policy takes `device_size_bytes` and returns a `DeviceLayoutV1` record
with four regions (system area, poolmap journal, metadata journal, data journal),
each with its own segment size. The layout is written into the device header at pool

Three policies are defined:

| Policy | Behaviour |
|--------|-----------|
| `Slice0Small` | Historical tiny layout: 1 MiB segments, fixed small journals. For tests and tiny devices. |
| `Auto` | Auto-scaling: segment size grows with device to keep segment count bounded. Fallback to `Slice0Small` on tiny devices. |
| `Custom { data_segment_size: u64, ... }` | Operator-specified per-region segment sizes. Gate: all sizes must be power-of-two and within bounds. |

The `Auto` policy is the production default. It chooses a power-of-two segment size
that keeps the segment count below a configurable target (default: ~4M segments per
data region), with a floor of 1 MiB and a ceiling of 256 MiB.

## 3. Layout Policy Abstraction

### 3.1 Policy Enum

```rust
/// Layout policy for computing device region partitioning and segment sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceLayoutPolicy {
    /// Historical small layout: 1 MiB segments, fixed small journals.
    /// Always succeeds (deterministic, no scaling logic needed).
    Slice0Small,

    /// Auto-scaling: segment size chosen to keep segment count bounded.
    /// Falls back to Slice0Small on devices too small for the auto layout.
    Auto,

    /// Operator-specified per-region segment sizes.
    /// All sizes must be powers of two within [MIN_SEGMENT_SIZE, MAX_SEGMENT_SIZE].
    Custom {
        system_segment_size: u64,
        poolmap_segment_size: u64,
        metadata_segment_size: u64,
        data_segment_size: u64,
    },
}
```

### 3.2 Builder Function

```rust
pub fn build_device_layout(
    device_size_bytes: u64,
    policy: DeviceLayoutPolicy,
) -> Result<DeviceLayoutV1, LayoutPolicyError>;
```

region boundaries and segment sizes, and returns a deterministic `DeviceLayoutV1`.

## 4. Auto-Scaling Segment Size Algorithm

### 4.1 Algorithm

The `choose_segment_size_bytes()` function picks a power-of-two segment size such
that:

```
segment_count ≈ device_size_bytes / segment_size ≤ TARGET_DATA_SEGMENTS
```

Implementation:

```rust
/// Choose a power-of-two segment size that keeps segment count below target.
///
/// Returns the segment size in bytes, always a power of two.
pub fn choose_segment_size_bytes(
    device_size_bytes: u64,
    target_segments: u64,
    min_seg: u64,
    max_seg: u64,
) -> Option<u64> {
    if device_size_bytes == 0 {
        return None;
    }
    let raw = device_size_bytes / target_segments;
    // Clamp to min/max bounds
    let clamped = raw.clamp(min_seg, max_seg);
    // Round up to next power of two
    Some(clamped.next_power_of_two().clamp(min_seg, max_seg))
}
```

### 4.2 Constants

| Constant | Value | Meaning |
|----------|-------|---------|
| `TARGET_DATA_SEGMENTS` | 4,000,000 | Maximum segment count for data region |
| `MIN_SEGMENT_SIZE_BYTES` | 1 MiB (1,048,576) | Smallest reasonable segment — below this, per-segment overhead dominates |
| `MAX_SEGMENT_SIZE_BYTES` | 256 MiB (268,435,456) | Largest reasonable relocation unit — above this, cleaning granularity hurts |
| `MIN_DEVICE_SIZE_BYTES` | 16 MiB (16,777,216) | Smallest device that can hold a valid pool layout |

### 4.3 Scaling Table

Device sizes and their computed segment sizes under the Auto policy:

| Device Size | Raw seg size | Pwr-of-2 | Segments | Notes |
|-------------|-------------|-----------|----------|-------|
| 100 MiB | 26 B | 1 MiB (floor) | ~100 | Small device, minimal overhead |
| 1 GiB | 269 B | 1 MiB (floor) | ~1024 | Still below floor |
| 4 GiB | 1.07 KiB | 1 MiB (floor) | ~4096 | Hits floor at 1 MiB |
| 10 GiB | 2.68 KiB | 1 MiB (floor) | ~10,240 | |
| 100 GiB | 26.8 KiB | 1 MiB (floor) | ~102,400 | |
| 1 TiB | 275 KiB | 512 KiB? Nein! 1 MiB floor | ~1,048,576 | Approaching target |
| 4 TiB | 1.1 MiB | 2 MiB | ~2,097,152 | Above floor |
| 16 TiB | 4.4 MiB | 8 MiB | ~2,097,152 | |
| 64 TiB | 17.6 MiB | 32 MiB | ~2,097,152 | |
| 256 TiB | 70.4 MiB | 128 MiB | ~2,097,152 | |
| 1 PiB | 281.6 MiB | 256 MiB (ceil) | ~4,194,304 | Hits ceiling |

Key property: segment count stays between ~100 and ~4.2M across a 10^7x device size
range (100 MiB to 1 PiB). Compare to ZFS: metaslab count is fixed at creation time
and changing it requires pool destruction.

### 4.4 Power-of-Two Requirement

Segment sizes are always powers of two. This ensures:

- Region boundaries are naturally aligned — no misaligned writes across segment
  boundaries
- Segment address computation uses shifts, not division
- Free map bit indexing is trivial: `bit_index = offset >> segment_order`
- The allocator's `SpaceMapBitmap` metaslab partitioning (from #1189) aligns
  naturally with power-of-two segment counts per metaslab

## 5. Device Region Partitioning

A device is partitioned into four contiguous regions, each managed by its own
`SegmentStore` with a region-specific segment size:

```
┌─────────────────────────────────────┐
│           System Area               │  1 × system_segment_size
├─────────────────────────────────────┤
│        Poolmap Journal              │  N_pool × poolmap_segment_size
├─────────────────────────────────────┤
│       Metadata Journal              │  N_meta × metadata_segment_size
├─────────────────────────────────────┤
│         Data Journal                │  remainder (≥ 1 segment)
└─────────────────────────────────────┘
```

### 5.1 Region Sizing Rules

**Slice0Small** (historical, for tests and tiny devices):

| Region | Size | Segment Size |
|--------|------|-------------|
| System Area | 1 MiB | 1 MiB |
| Poolmap Journal | 4 MiB | 1 MiB |
| Metadata Journal | 4 MiB | 1 MiB |
| Data Journal | remainder | 1 MiB |

All regions use a uniform 1 MiB segment size.

**Auto** (production default):

| Region | Size | Segment Size |
|--------|------|-------------|
| System Area | max(1 MiB, data_segment_size) | data_segment_size |
| Poolmap Journal | max(4 MiB, 16 × data_segment_size) | data_segment_size |
| Metadata Journal | max(4 MiB, 256 × data_segment_size) | data_segment_size (or smaller, configurable) |
| Data Journal | remainder | data_segment_size |

The `data_segment_size` is computed by `choose_segment_size_bytes()`. Journal
regions scale proportionally with segment size so larger devices get larger journals
(handling more concurrent writeback), while smaller devices keep journals compact.

### 5.2 Minimum Device Check

The layout must fit on the device. The minimum size check is:

```rust
fn layout_min_bytes(layout: &DeviceLayoutV1) -> u64 {
    layout.system_area_bytes
        + layout.poolmap_size
        + layout.metadata_size
        + layout.data_segment_size  // at least 1 data segment
}

    layout_min_bytes(layout) <= device_size_bytes
}
```

If the Auto layout doesn't fit (device too small), it falls back to `Slice0Small`.
If `Slice0Small` also doesn't fit (device < ~10 MiB), `build_device_layout()` returns
`LayoutPolicyError::DeviceTooSmall`.

This fallback is deterministic: Auto → Slice0Small → error. No operator intervention
required.

### 5.3 Region Alignment

All region boundaries are aligned to their respective segment sizes. The system area
starts at offset 0. Each subsequent region starts at the next segment-aligned offset:

```
system_area_end   = system_area_bytes (always segment-aligned since size = segment_size)
poolmap_base      = system_area_end
poolmap_end       = poolmap_base + poolmap_size (poolmap_size % poolmap_segment_size == 0)
metadata_base     = poolmap_end
metadata_end      = metadata_base + metadata_size (metadata_size % metadata_segment_size == 0)
data_base         = metadata_end
data_end          = device_size_bytes
```

## 6. DeviceLayoutV1 Record

### 6.1 On-Media Format

The computed layout is written into the device header as a `DeviceLayoutV1` record.
This record is stored in the system area (first `system_segment_size` bytes of the
device) alongside the pool label and device identity records.

```rust
/// Persistent device layout record (written at pool creation, read on open).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceLayoutV1 {
    /// Layout policy that produced this layout.
    pub policy: DeviceLayoutPolicyDiscriminant,

    // --- System Area ---
    /// Total system area size in bytes (≥ segment_size).
    pub system_area_bytes: u64,

    // --- Poolmap Journal ---
    /// Byte offset of poolmap journal region.
    pub poolmap_base: u64,
    /// Total poolmap journal size in bytes.
    pub poolmap_size: u64,
    /// Segment size for poolmap journal (bytes, power of two).
    pub poolmap_segment_size: u64,

    // --- Metadata Journal ---
    /// Byte offset of metadata journal region.
    pub metadata_base: u64,
    /// Total metadata journal size in bytes.
    pub metadata_size: u64,
    /// Segment size for metadata journal (bytes, power of two).
    pub metadata_segment_size: u64,

    // --- Data Journal ---
    /// Byte offset of data journal region.
    pub data_base: u64,
    /// Total data journal size in bytes.
    pub data_size: u64,
    /// Segment size for data journal (bytes, power of two).
    pub data_segment_size: u64,
}
```

### 6.2 Discriminant

```rust
/// Stored policy discriminant (preserves which policy created the layout).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceLayoutPolicyDiscriminant {
    Slice0Small = 0,
    Auto = 1,
    Custom = 2,
}
```

### 6.3 Encoding

The record uses the standard TideFS binary encoding (little-endian, per the
format law from #1220 and specification in `CANONICAL_BINARY_ENCODE_DECODE_ENDIAN_CHECKSUM_LAW_P2-03.md`):
- All fields are `u64`, little-endian
- Total record size: 10 × 8 + 1 (discriminant) = 81 bytes, padded to align
- CRC32C header checksum (domain: `b"tidefs.layout.device_layout_v1.header"`)
- CRC32C payload checksum (domain: `b"tidefs.layout.device_layout_v1.payload"`)

### 6.4 Invariants


1. `system_area_bytes ≥ data_segment_size`: system area is at least one segment
2. `poolmap_base == system_area_bytes`: poolmap starts immediately after system area
3. `poolmap_size % poolmap_segment_size == 0`: poolmap region is segment-multiple
4. `metadata_base == poolmap_base + poolmap_size`: contiguous regions
5. `metadata_size % metadata_segment_size == 0`: metadata region is segment-multiple
6. `data_base == metadata_base + metadata_size`: contiguous regions
7. `data_segment_size` is a power of two
8. `data_segment_size ∈ [MIN_SEGMENT_SIZE, MAX_SEGMENT_SIZE]`
9. `system_area_bytes + poolmap_size + metadata_size + data_segment_size ≤
    device_size_bytes`: at least one data segment fits

## 7. Per-Region SegmentStore Configuration

Each journal region is managed by its own `SegmentStore` instance, configured with
the region's segment size and base offset. This enables:

- **Different segment sizes per region**: metadata can use smaller segments for lower
  write amplification (metadata writes are small and frequent) while data uses larger
  segments for lower segment count overhead.
- **Independent GC per region**: the data cleaner operates on data segments while
  metadata segments are cleaned separately (if at all — metadata segments may be
  append-only with segment rotation rather than cleaning).
- **Poolmap journal isolation**: the poolmap journal (spacemap checkpoints from #1189)
  is a separate region so checkpoint writes don't contend with data or metadata I/O.

### 7.1 Region Override

The `Auto` policy defaults to using `data_segment_size` for all regions, but the
`build_device_layout` function accepts an optional override for metadata segment size:

```rust
pub fn build_device_layout_with_overrides(
    device_size_bytes: u64,
    policy: DeviceLayoutPolicy,
    metadata_segment_override: Option<u64>,
) -> Result<DeviceLayoutV1, LayoutPolicyError>;
```

This allows metadata to use a quarter or half of the data segment size (while still
`metadata_segment_override` must be a power of two dividing `data_segment_size`.

## 8. Integration with Pool Lifecycle

### 8.1 Pool Creation

```
Pool::create(config, policy)
  ├── for each device:
  │     ├── build_device_layout(device_size, policy)
  │     ├── write DeviceLayoutV1 to system area (offset 0)
  │     ├── open SegmentStore for each region with region-specific segment size
  │     └── initialize empty spacemap bitmap for data region
  ├── write pool label (PoolLabelV1 from #1254)
  └── return Pool
```

### 8.2 Pool Open

```
Pool::open(config)
  ├── for each device:
  │     ├── read DeviceLayoutV1 from system area
  │     ├── if policy == Auto: verify segment_size matches choose_segment_size_bytes()
  │     │   for this device size (prevents pool import with mismatched layout
  │     │   due to config constants changing between code versions)
  │     ├── open SegmentStore for each region with region-specific segment size
  │     └── reconstruct spacemap from poolmap journal checkpoint (#1189)
  └── return Pool
```

### 8.3 Device Add

When adding a device to an existing pool:

```
Pool::add_device(config, policy)
  ├── if policy is Auto: layout is computed fresh from the new device's size
  │   (new devices may have different segment sizes than existing ones)
  ├── build_device_layout(new_device_size, policy)
  ├── write DeviceLayoutV1
  ├── initialize SegmentStores
  └── merge new spacemap bitmap into pool-wide SegmentFreeMap
```

Key property: per-device segment sizes may differ. A 1 TiB NVMe and a 16 TiB HDD in
the same pool will have different data segment sizes (1 MiB vs 8 MiB). The pool-wide
free map tracks segments per device, so different segment sizes per device are naturally
handled. The `SegmentFreeMap` from #1189 already tracks `(device_id, segment_id)` tuples.

### 8.4 Device Remove

Removing a device requires relocating all live data from its segments to other devices
(handled by the relocation planner from #1138, not the layout policy). After
relocation completes, the device's layout is discarded.

## 9. Per-Device Segment Sizing Flexibility

### 9.1 Heterogeneous Device Sizes

A pool may contain devices of dramatically different sizes. The `Auto` policy gives
each device an appropriate segment size for its capacity:

| Device | Size | Auto Segment Size | Segments |
|------|------|-------------------|----------|
| NVMe mirror-0 | 1 TiB | 1 MiB | ~1,048,576 |
| HDD mirror-1 | 16 TiB | 8 MiB | ~2,097,152 |
| HDD mirror-2 | 64 TiB | 32 MiB | ~2,097,152 |

All three devices coexist in one pool. The pool's `SegmentFreeMap` tracks segments
per-device, and allocation picks a device via the deterministic hash from `Pool::put()`.

### 9.2 Device Class Segment Overrides

The `poolmap` and `metadata` journal regions may benefit from smaller segments
regardless of device size. For example, on a 64 TiB HDD with 32 MiB data segments,
the metadata journal could use 4 MiB segments for lower write amplification on
small metadata writes.

The `Custom` policy enables explicit per-region segment sizes for operators who
want to tune for specific workloads.

### 9.3 Segment Size Migration

Changing segment size on an existing device requires full data evacuation (similar
to ZFS's inability to change ashift). The `DeviceLayoutV1` is immutable once
written. Segment size changes happen via:

1. Add replacement device with desired segment size
2. Relocate all data from old device to new device
3. Remove old device

This is consistent with the "no in-place format mutations" principle from #1238
(unified format lifecycle).

## 10. Deterministic Constraint Knobs

All tuning constants are explicit, named, and documented. No magic numbers.

| Constant | Default | Meaning |
|----------|---------|---------|
| `TARGET_DATA_SEGMENTS` | 4,000,000 | Upper bound for data region segment count |
| `MIN_SEGMENT_SIZE_BYTES` | 1,048,576 (1 MiB) | Absolute floor for any segment size |
| `MAX_SEGMENT_SIZE_BYTES` | 268,435,456 (256 MiB) | Absolute ceiling for any segment size |
| `MIN_DEVICE_SIZE_BYTES` | 16,777,216 (16 MiB) | Minimum device that can hold a valid layout |
| `SYSTEM_AREA_SEGMENTS` | 1 | Segments reserved for system area |
| `POOLMAP_JOURNAL_SEGMENTS` | 16 | Poolmap journal size in data-segment multiples |
| `METADATA_JOURNAL_SEGMENTS` | 256 | Metadata journal size in data-segment multiples |

These constants are defined in a `layout` module alongside the policy logic and are
implementation-tracked non-release by `tidefs-xtask check-device-layout-constants`.

### 10.1 Tuning Rationale

- **4M target segments**: keeps bring-up scan at ~50 ms per million segments on
  modern NVMe (assuming 50 μs per segment for spacemap bitmap read). At 4M segments,
  total import scan is ~200 ms — well under the 1-second target for pool import.
- **1 MiB minimum**: below 1 MiB, per-segment overhead (segment header, index entry,
  footer) exceeds 0.1% of segment capacity, making space efficiency unacceptably low.
- **256 MiB maximum**: above 256 MiB, the cleaner must relocate up to 256 MiB to
  reclaim a single segment's dead space, creating latency spikes. A 256 MiB relocation
  at 1 GB/s takes ~250 ms — acceptable as background work.

## 11. ZFS Comparison

| Dimension | ZFS | tidefs |
|-----------|-----|--------|
| **Metaslab/Segment sizing** | Fixed at pool creation (metaslab size defaults to 1/200 of device, min 16 MiB, max 16 GiB). Changing requires pool destruction. | Auto-scaling segment size at creation time per-device, recomputed on device add. Segment count stays bounded across 7 orders of magnitude. |
| **Region partitioning** | No explicit journal regions. ZIL and LOG_DEVICE are separate devices, not region-partitioned. All writes go through the DMU/ZIO pipeline regardless of I/O class. | Four explicit regions per device (system, poolmap, metadata, data), each with independent segment sizing and GC. I/O class routing is the pool's responsibility, but the layout gives each class its own write domain. |
| **Ashift** | Immutable after pool creation. 512B (ashift=9) or 4K (ashift=12) are the only practical options. Change requires pool recreation. | Segment sizes are power-of-two from 1 MiB to 256 MiB, not tied to block alignment. `ashift` (from `PoolProperties`) is a separate concept for device block alignment, independent of segment size. |
| **Pool expansion** | Adding a device forces the new device to use the same ashift as existing devices. Metaslab count on the new device is proportional to its size (fixed ratio). | Adding a device recomputes layout for the new device independently — different segment sizes coexist naturally. |
| **Small device support** | zpool create on a 64 MiB file works but creates a pool with absurdly low space efficiency (metaslab overhead dominates). | Auto policy falls back to Slice0Small for small devices, ensuring usable space even on a 100 MiB device. Explicit error below 16 MiB. |
| **Journal scaling** | ZIL size is fixed at pool creation (typically 1/8 of RAM or a fixed small size). log devices are external. | Journal regions scale proportionally with segment size (poolmap: 16× segment, metadata: 256× segment). Larger devices get larger journals automatically. |
| **Determinism** | Metaslab count = device_size / metaslab_size, rounded up. Variable per device based on exact size. | `choose_segment_size_bytes()` is purely deterministic from device size + constants. Same device always produces same layout. |
| **Migrating segment size** | Not possible without pool destruction. | Not possible without data evacuation (consistent with format immutability principle). But heterogeneous segment sizes across devices means new devices can adopt different sizes without pool-wide migration. |

### 11.1 Where tidefs Improves on ZFS

- **Auto-scaling**: ZFS requires the operator to think about metaslab sizing, or
  accepts the 1/200-of-device default (which produces 16M metaslabs on a 3.2 TB
  device!). tidefs bounds segment count to ~4M regardless of device size.
- **Per-region sizing**: ZFS has one block size for everything (ashift). tidefs
  allows metadata to use smaller segments than data on the same device, reducing
  metadata write amplification.
- **Journal proportionality**: ZFS ZIL sizing doesn't scale with device size —
  a 1 TB pool and a 1 PB pool get the same ZIL size by default. tidefs scales
  journal regions with segment size.
- **Device heterogeneity**: ZFS constrains all devices to the same ashift. tidefs
  allows different segment sizes per device in the same pool.

### 11.2 Where tidefs Matches ZFS

- **Immutability**: like ZFS ashift, segment size is immutable once written.
- **Power-of-two**: both systems use power-of-two sizing for alignment.
- **Device-class awareness**: both route I/O by class (ZFS: special device; tidefs:
  DeviceClass routing in `Pool`).

## 12. Integration Points

### 12.1 Spacemap (#1189)
The `SpaceMapBitmap` metaslab size is derived from `data_segment_size`:
`SEGMENTS_PER_METASLAB = 4096` (fixed), so `metaslab_size = 4096 ×
data_segment_size`. On a 1 MiB segment pool, a metaslab covers 4 GiB. On a 32 MiB
segment pool, a metaslab covers 128 GiB. This keeps `SpaceMapCheckpointV1` records
at a fixed size (512 bytes per metaslab bitmap) regardless of segment size.

### 12.2 Space Accounting (#1215)
The `PoolPhysicalCountersV1` `phys_free_segments` field is a sum across all devices.
Different segment sizes per device mean the physical counters track segments, not bytes.
The `phys_free_bytes` field is derived:
`sum over devices: segments_free[device] × segment_size[device]`.

### 12.3 Pool Import/Export (#1254)
The `PoolLabelV1` record stores the list of device paths and their `DeviceLayoutV1`
and invariants hold.

### 12.4 Cleaner Scheduling (#1215 §9)
The cleaner's segment selection uses `data_segment_size` to compute the cost of
cleaning a segment (IO volume = segment_size) and the benefit (dead bytes within).
Larger segments mean higher per-segment cleaning cost but also larger potential gain.

### 12.5 Allocator Gate
- `choose_segment_size_bytes()` returns correct power-of-two values for edge cases
- `build_device_layout()` invariant checks pass for valid inputs and fail for invalid
- `Slice0Small` produces correct fixed layout
- `Auto` fallback works for tiny devices
- Layout roundtrip: write DeviceLayoutV1 → read → fields match
- Segment counts stay within `TARGET_DATA_SEGMENTS` for device sizes from 100 MiB to 1 PiB (simulated, not real I/O)

## 13. Implementation Plan

### Phase 1: Types and Constants
Implement `DeviceLayoutPolicy`, `DeviceLayoutPolicyDiscriminant`, `DeviceLayoutV1`,
and all constants in `crates/tidefs-local-object-store/src/layout.rs`. Pure data
types, no I/O.

### Phase 2: Auto-Scaling Algorithm
Implement `choose_segment_size_bytes()` and `build_device_layout()`. Unit tests
for all device sizes from 100 MiB to 1 PiB, verifying power-of-two output and
segment count bounds.

### Phase 3: Encode/Decode
Implement binary encode/decode for `DeviceLayoutV1` with CRC32C checksums.
Roundtrip tests with golden vectors.

### Phase 4: Pool Integration
into `Pool::open()`. The pool now stores `DeviceLayoutV1` per device.

### Phase 5: Per-Region SegmentStore
Configure `SegmentStore` instances with region-specific segment sizes and base
offsets. Each device gets 4 SegmentStores (system, poolmap, metadata, data).

Implement `tidefs-xtask check-device-layout-policy` with all tests from §12.5.
No real device I/O — all tests use simulated device sizes.

### Phase 7: Device Add/Remove
Update `add_device()` and `remove_device()` to handle per-device layouts and
heterogeneous segment sizes in the pool-wide `SegmentFreeMap`.

## 14. Error Hierarchy

```rust
#[derive(Debug)]
pub enum LayoutPolicyError {
    /// Device is too small for any valid layout.
    DeviceTooSmall {
        device_size_bytes: u64,
        minimum_required_bytes: u64,
    },

    /// Device size is zero (invalid).
    DeviceSizeZero,

    /// Auto layout didn't fit, and Slice0Small fallback also didn't fit.
    AutoFallbackFailed {
        device_size_bytes: u64,
        auto_min_bytes: u64,
        small_min_bytes: u64,
    },

    /// Custom layout had an invalid segment size.
    InvalidSegmentSize {
        region: &'static str,
        value: u64,
        reason: InvalidSegmentSizeReason,
    },

    /// Custom layout region sizes conflict with device capacity.
    RegionOverflow {
        device_size_bytes: u64,
        required_bytes: u64,
    },
}

#[derive(Debug)]
pub enum InvalidSegmentSizeReason {
    NotPowerOfTwo,
    BelowMinimum { min: u64 },
    AboveMaximum { max: u64 },
    DoesNotDivideDataSegmentSize,
}
```

## 15. Open Questions

1. **Should the system area be larger on big devices?** Currently fixed at
   1 × `system_segment_size`. On a 1 PiB device with 256 MiB segments, the
   system area is 256 MiB — far more than needed for pool label + layout +
   a few metadata records. Consider capping the system area at 16 MiB
   regardless of segment size.

2. **Should metadata journal use a fraction of the data segment size by
   default?** Currently uses `data_segment_size`. A 256 MiB metadata segment
   means a metadata write of 512 bytes wastes 255.999 MiB of segment space.
   Consider defaulting metadata segment size to `max(1 MiB, data_segment_size
   / 4)`.

3. **Poolmap journal sizing**: 16 × data_segment_size may be excessive on
   large devices (4 GiB poolmap journal on a 256 MiB segment device). Consider
   capping poolmap journal at some maximum (e.g., 512 MiB).

These questions should be resolved during Phase 2 implementation based on
concrete numbers from the spacemap design (#1189) and cleaner scheduling
(#1215) — specifically, how much poolmap checkpoint data is written per commit_group.

## 16. References

- [#1189] Spacemap, allocator, and free-space tracking design
- [#1215] Space accounting model design
- [#1254] Pool import/export and device topology design
- [#1238] Unified on-media format lifecycle (meta)
- [#1220] On-media record format strategy
- `CANONICAL_BINARY_ENCODE_DECODE_ENDIAN_CHECKSUM_LAW_P2-03.md`
- Python v0.262 reference: `layout_policy.py` (316 lines)
