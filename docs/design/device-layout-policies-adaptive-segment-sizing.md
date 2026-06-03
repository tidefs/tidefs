# Device Layout Policies and Adaptive Segment Sizing Design

Maturity: **design-spec** for the device layout policy abstraction, auto-scaling
segment size algorithm, per-region segment sizing with power-of-two alignment,
DeviceLayoutV1 on-media record, per-device heterogeneous segment sizes, and
deterministic pool-scaling constraints.

This document formalizes the design scoped in #1193, refined through
#1556, #1596, #1629, and #1679. It is the current authoritative design specification
tracked under #1810. It reflects the current codebase state as of May 2026,
including the existing `SegmentFreeMap`, `PoolAllocator`, `DeviceImpl` trait
hierarchy, and `LocalObjectStore` segment-rotation machinery.

## 1. Motivation

The current codebase writes segments at a fixed maximum size defined by
`DEFAULT_MAX_SEGMENT_BYTES = 64 MiB` in `crates/tidefs-local-object-store/src/constants.rs`.
Segment rotation is governed by struct-level `StoreOptions` fields
(`max_segment_bytes`, `segment_rotation_interval_secs`,
`segment_rotation_write_limit`), all set to flat defaults. Journal region
sizes are assumed implicitly during pool creation rather than being derived
from a layout policy.

This works for single-device testing and small deployments but does not scale:

- A 1 MiB segment on a 1 PiB pool produces ~1e9 segments — the bring-up scan
  cost during pool import (walking all segments to reconstruct the free map)
  is prohibitive.
- Fixed 64 MiB segments on a 4 GiB device waste space: only ~64 data segments
  exist, giving coarse allocation granularity and poor cleaner scheduling.
- Fixed journal sizes waste space on large devices (padding unused region
  capacity) or starve small ones (journal too small for burst writes).
- No explicit layout policy abstraction exists — layout decisions are embedded
  inline in pool open code, making per-device-class sizing impossible.
- Different devices in the same pool (e.g., NVMe metadata + HDD data) currently
  share the same segment size, forcing the smaller/faster device to waste I/O
  on oversized segments or forcing the larger device into too many tiny segments.

This design defines a `DeviceLayoutPolicy` that computes region boundaries and
segment sizes deterministically from device properties, keeping segment counts
within a bounded range (~100–4.2M per region) regardless of pool scale.

## 2. Architecture Overview

```
Pool (tidefs-pool-allocator)
 ├── Device 0 (nvme0n1, 1 TiB)          Device 1 (nvme1n1, 4 TiB)
 │   ├── DeviceLayoutV1              DeviceLayoutV1
 │   │   ├── system_area             (independent layout per device)
 │   │   ├── poolmap_journal
 │   │   ├── metadata_journal
 │   │   └── data_journal
 │   ├── SegmentStore x 4            SegmentStore x 4
 │   │   (each with region-specific   (different segment sizes
 │   │    segment size)               per device)
 │   └── LocalObjectStore             LocalObjectStore
 │
 └── PoolAllocator
      └── SegmentFreeMap (pool-wide, segments counted per device)
           └── Metaslab x N (4096 segments each)
```

The layout policy operates per-device, not pool-wide. Each device gets an
independent `DeviceLayoutV1` record computed from its device size and
the pool's chosen policy. This enables heterogeneous segment sizes:
a 256 GiB NVMe metadata device can use 4 MiB segments while a 16 TiB HDD
data device uses 256 MiB segments, both staying within the target segment
count.

## 3. DeviceLayoutPolicy

### 3.1 Enum Definition

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
    /// All sizes must be powers of two within [MIN, MAX].
    Custom {
        system_segment_size: u64,
        poolmap_segment_size: u64,
        metadata_segment_size: u64,
        data_segment_size: u64,
    },
}
```

### 3.2 Policy Selection Guidance

| Policy | When to use | Tradeoff |
|--------|-------------|----------|
| `Slice0Small` | Tests, tiny devices (<1 GiB), embedded | Predictable, no scaling, wastes space on large devices |
| `Auto` | **Production default**. All general-purpose pools. | Auto-tunes segment size; ~100–4.2M segments across 10^7x device range |
| `Custom` | Operator knows workload better than auto; hybrid pools | Full control, but operator bears correctness burden |

## 4. Auto-Scaling Segment Size Algorithm

### 4.1 Algorithm

The core function `choose_segment_size_bytes()` picks a power-of-two segment
size such that the segment count stays below `TARGET_DATA_SEGMENTS`:

```rust
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
    let clamped = raw.clamp(min_seg, max_seg);
    Some(clamped.next_power_of_two().clamp(min_seg, max_seg))
}
```

### 4.2 Scaling Table

| Device Size | Raw segment size | Power-of-two | Segment count | Overhead |
|-------------|-----------------|--------------|---------------|----------|
| 100 MiB | ~25 B | 1 MiB (floor) | 100 | minimal |
| 4 GiB | ~1 KiB | 1 MiB (floor) | 4,096 | ~1% |
| 256 GiB | 64 KiB | 1 MiB (floor) | 262,144 | negligible |
| 1 TiB | 256 KiB | 1 MiB (floor) | 1,048,576 | negligible |
| 8 TiB | 2 MiB | 2 MiB | 4,194,304 | near target limit |
| 64 TiB | 16 MiB | 16 MiB | 4,194,304 | @ target limit |
| 512 TiB | 128 MiB | 128 MiB | 4,194,304 | @ target limit |
| 1 PiB | 256 MiB | 256 MiB | 4,194,304 | @ target limit |

Segment counts stay in [100, 4,194,304] across a 10^7x device size range.
The power-of-two rounding never doubles the count under target more than 2x,
so the worst case is ~4.2M segments — fully manageable for import scan.

### 4.3 Constants

| Constant | Value | Rationale |
|----------|-------|-----------|
| `TARGET_DATA_SEGMENTS` | 4,000,000 | ~4M segments = ~2 GiB of per-segment metadata at 512 bytes/segment. Import scan at 500 MB/s = ~4 seconds. |
| `MIN_SEGMENT_SIZE_BYTES` | 1 MiB (1,048,576) | Below 1 MiB, per-segment file overhead (inode, directory entry) dominates. Fits ~4,194 segments on a 4 GiB device. |
| `MAX_SEGMENT_SIZE_BYTES` | 256 MiB (268,435,456) | Above 256 MiB, a single segment write stalls all IOPS for too long. Aligned with ZFS `zfs_max_recordsize`. |

The existing `DEFAULT_MAX_SEGMENT_BYTES = 64 MiB` in `constants.rs` becomes the
default when no layout policy is active (single-device, testing mode). With a
layout policy active, each region's segment size overrides this default.

## 5. DeviceLayoutV1 — On-Media Record

### 5.1 Binary Layout (Little-Endian)

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0 | 8 | `magic` | [u8; 8] | `b"VFSDLAY1"` |
| 8 | 2 | `version` | u16 | Format version = 1 |
| 10 | 2 | `policy_discriminant` | u16 | 0=Slice0Small, 1=Auto, 2=Custom |
| 12 | 8 | `device_size_bytes` | u64 | Total device capacity |
| 20 | 8 | `system_area_offset` | u64 | Byte offset of system area |
| 28 | 8 | `system_area_len` | u64 | System area length in bytes |
| 36 | 8 | `poolmap_journal_offset` | u64 | Poolmap journal start |
| 44 | 8 | `poolmap_journal_len` | u64 | Poolmap journal length |
| 52 | 8 | `metadata_journal_offset` | u64 | Metadata journal start |
| 60 | 8 | `metadata_journal_len` | u64 | Metadata journal length |
| 68 | 8 | `data_journal_offset` | u64 | Data journal start |
| 76 | 8 | `data_journal_len` | u64 | Data journal length |
| 84 | 8 | `system_segment_size` | u64 | Segment size for system area |
| 92 | 8 | `poolmap_segment_size` | u64 | Segment size for poolmap journal |
| 100 | 8 | `metadata_segment_size` | u64 | Segment size for metadata journal |
| 108 | 8 | `data_segment_size` | u64 | Segment size for data journal |
| 116 | 4 | `reserved` | u32 | Zero-pad to align CRC |
| 120 | 4 | `crc32c` | u32 | CRC32C of bytes 0..120 |

Total record size: **124 bytes**.

### 5.2 Invariants (Enforced at Encode/Decode)

1. `device_size_bytes` > 0
2. Region offsets are strictly increasing and do not overlap
3. Last region ends at or before `device_size_bytes`
4. All segment sizes are powers of two in [1 MiB, 256 MiB]
5. `system_segment_size == 1 MiB` for `Slice0Small` and `Auto` policies

### 5.3 Storage Location

The `DeviceLayoutV1` record is written as the first object in the system area
of each device, keyed by a well-known object key derived from the device UUID.

## 6. Four-Region Device Partitioning

Each device is divided into four contiguous regions:

```
.______________________________________________________________________.
| System Area | Poolmap Jrnl | Metadata Jrnl |  Data Journal           |
| 1 segment   | 16 segments  | 256 segments  |  remainder              |
.______________________________________________________________________.
```

| Region | Size (segments) | Segment size | Purpose | Write Pattern |
|--------|-----------------|--------------|---------|---------------|
| System area | 1 | `system_segment_size` (1 MiB fixed) | Pool label, layout record, device UUID, root authentication key material | Write-once at pool creation; read-only thereafter |
| Poolmap journal | 16 | `poolmap_segment_size` (= data_segment_size) | `SpaceMapCheckpointV1` records, free/alloc journal | Small writes every commit_group (metaslab-sized) |
| Metadata journal | 256 | `metadata_segment_size` (default: data_segment_size) | Inode records, directory entries, extent maps, xattrs | Many small writes (avg <1 KiB each) |
| Data journal | remainder | `data_segment_size` (auto-scaled) | File content chunks, large objects | Bulk writes (64 KiB chunks, compressed) |

### 6.1 Region Scaling Rationale

The poolmap journal is 16x the data segment size because each commit_group writes at
most a few metaslab bitmaps (dirty-only incremental checkpoints). 16 segments
of journal capacity means 16 commit_groups can accumulate before the oldest segment
must be reclaimed — far more than needed (normal commit_group interval is <1s).

The metadata journal is 256x the data segment size because metadata writes
are many and small: an `mkdir` writes 1 inode + 1 directory entry (~200 bytes
total), but a segment file has `RECORD_HEADER_LEN = 96` + footer + trailer
overhead. 256 segments gives ~256x waste headroom before cleaning pressure
triggers.

The system area is 1 segment because it holds only the pool label, layout
record, and root auth material — all written once. One segment at 1 MiB
holds ~10x the needed content.

### 6.2 Open Question: System Area Cap

On a 1 PiB device with 256 MiB data segments, the system area would be
256 MiB — far more than needed for a ~2 KiB of label data. Consider capping
the system area to 16 MiB regardless of `data_segment_size`. This does not
affect correctness but avoids wasting a large segment on metadata that never
grows.

## 7. Per-Device Segment Sizing (Heterogeneous Pools)

Different devices in the same pool may have different `DeviceLayoutV1` records
with different segment sizes. This is the key design differentiator from ZFS,
where `ashift` is a pool-wide property.

### 7.1 Example: Hybrid NVMe + HDD Pool

```
Pool "tank"
 ├── mirror-0
 │   ├── nvme0n1 (256 GiB, metadata class)
 │   │   .__ DeviceLayoutV1 { data_segment_size: 4 MiB, segments: 65,536 }
 │   .__ nvme1n1 (256 GiB, metadata class)
 │       .__ DeviceLayoutV1 { data_segment_size: 4 MiB, segments: 65,536 }
 .__ mirror-1
     ├── hdd0 (16 TiB, data class)
     │   .__ DeviceLayoutV1 { data_segment_size: 256 MiB, segments: 65,536 }
     .__ hdd1 (16 TiB, data class)
         .__ DeviceLayoutV1 { data_segment_size: 256 MiB, segments: 65,536 }
```

Both mirrors have ~65K data segments despite a 64x device size difference.
The NVMe devices get small segments for low-latency metadata; the HDD devices
get large segments for bulk throughput.

### 7.2 PoolAllocator Integration

The existing `PoolAllocator` (in `crates/tidefs-pool-allocator/`) wraps
`SegmentFreeMap` with per-metaslab cursors. With heterogeneous device segment
sizes, the `SegmentFreeMap` must be extended to track per-device segment-size
metadata. The free map already counts segments, not bytes — so the mapping
from "segment N" to "physical byte range [offset, offset+size)" is the
responsibility of each device's layout. The pool allocator selects a segment
index; the device maps it to physical bytes using its `DeviceLayoutV1`.

```rust
// Proposed extension to SegmentFreeMap
struct SegmentFreeMap {
    // existing fields...
    /// Per-device segment size for physical-to-logical mapping.
    /// Index = device_index. None for uninitialized devices.
    device_segment_sizes: Vec<u64>,
}
```

## 8. Relationship to Existing Code

### 8.1 LocalObjectStore Segment Rotation

The current `LocalObjectStore` (in `crates/tidefs-local-object-store/src/store.rs`)
rotates segments based on `StoreOptions`:

```rust
pub struct StoreOptions {
    pub max_segment_bytes: u64,            // DEFAULT_MAX_SEGMENT_BYTES = 64 MiB
    pub segment_rotation_interval_secs: u64, // DEFAULT_SEGMENT_ROTATION_INTERVAL_SECS = 30
    pub segment_rotation_write_limit: u64,   // DEFAULT_SEGMENT_ROTATION_WRITE_LIMIT = 10_000
    // ...
}
```

When a layout policy is active, `max_segment_bytes` is overridden by the
region-specific segment size from `DeviceLayoutV1`. Rotation intervals and
write limits continue to apply independently per region.

### 8.2 DeviceImpl Trait

The `DeviceImpl` trait (in `crates/tidefs-local-object-store/src/device.rs`)
already abstracts over `SingleDevice` and `MirrorDevice`. Each device wraps one
or more `LocalObjectStore` instances. With the layout policy, each device
will wrap four `LocalObjectStore` instances — one per region — each with
its own `StoreOptions` carrying the region-specific segment size.

### 8.3 SegmentFreeMap and Metaslabs

The `SegmentFreeMap` (in `crates/tidefs-spacemap-allocator/src/lib.rs`)
partitions segments into metaslabs of `DEFAULT_METASLAB_SEGMENTS = 4096`
segments each. With heterogeneous segment sizes, metaslabs remain
segment-indexed, not byte-indexed. The per-device physical mapping is
done by the device layer, not the free map.

When a segment is allocated from the pool-wide `SegmentFreeMap` (which
returns a segment index), the caller must know which device owns that
segment range to determine the physical byte offset. This offset is
`device_start + segment_index x device_segment_size`.

### 8.4 Pool Free/Used Byte Accounting

The `phys_free_bytes` field in pool stats is derived:

```
phys_free_bytes = sum over devices: segments_free[device] x segment_size[device]
```

This requires the `SegmentFreeMap` to track per-device free counts or for
the pool layer to maintain per-device segment-range tables. The per-device
approach is preferred since it aligns with the existing `PoolAllocator`.

## 9. Builder Function: build_device_layout()

```rust
/// Compute the DeviceLayoutV1 for a single device.
///
/// Returns a deterministic layout given device size and policy.
/// The layout is idempotent: same inputs -> same output.
pub fn build_device_layout(
    device_size_bytes: u64,
    policy: DeviceLayoutPolicy,
) -> Result<DeviceLayoutV1, LayoutPolicyError>;
```

### 9.1 Slice0Small Layout (Deterministic)

```
system_area:      1 x 1 MiB = 1 MiB
poolmap_journal:  16 x 1 MiB = 16 MiB
metadata_journal: 256 x 1 MiB = 256 MiB
data_journal:     remainder (device_size - 273 MiB)

Minimum device size: 274 MiB (at least 1 data segment)
```

### 9.2 Auto Layout Computation

```rust
fn build_auto_layout(device_size_bytes: u64) -> Result<DeviceLayoutV1, LayoutPolicyError> {
    let data_seg = choose_segment_size_bytes(
        device_size_bytes,
        TARGET_DATA_SEGMENTS,
        MIN_SEGMENT_SIZE_BYTES,
        MAX_SEGMENT_SIZE_BYTES,
    ).ok_or(LayoutPolicyError::DeviceSizeZero)?;

    let system_seg = 1_048_576; // 1 MiB fixed
    let poolmap_seg = data_seg;
    let metadata_seg = data_seg;

    let system_len = system_seg;
    let poolmap_len = 16 * poolmap_seg;
    let metadata_len = 256 * metadata_seg;
    let header = system_len + poolmap_len + metadata_len;

    if device_size_bytes < header + data_seg {
        // device too small for auto -- fall back to Slice0Small
        return build_slice0small_layout(device_size_bytes);
    }

    let data_len = device_size_bytes - header;

    Ok(DeviceLayoutV1 {
        system_area_offset: 0,
        system_area_len: system_len,
        poolmap_journal_offset: system_len,
        poolmap_journal_len: poolmap_len,
        metadata_journal_offset: system_len + poolmap_len,
        metadata_journal_len: metadata_len,
        data_journal_offset: header,
        data_journal_len: data_len,
        system_segment_size: system_seg,
        poolmap_segment_size: poolmap_seg,
        metadata_segment_size: metadata_seg,
        data_segment_size: data_seg,
        // ... crc32c computed after fields
    })
}
```


Custom layouts must pass these gates before acceptance:
1. All segment sizes are powers of two
2. All segment sizes in [MIN_SEGMENT_SIZE_BYTES, MAX_SEGMENT_SIZE_BYTES]
3. Sum of all four region sizes <= device_size_bytes
4. `poolmap_segment_size` and `metadata_segment_size` divide `data_segment_size`
   (ensures segment alignment for cleaner scheduling)

## 10. Error Hierarchy

```rust
#[derive(Debug)]
pub enum LayoutPolicyError {
    DeviceTooSmall {
        device_size_bytes: u64,
        minimum_required_bytes: u64,
    },
    DeviceSizeZero,
    AutoFallbackFailed {
        device_size_bytes: u64,
        auto_min_bytes: u64,
        small_min_bytes: u64,
    },
    InvalidSegmentSize {
        region: &'static str,
        value: u64,
        reason: InvalidSegmentSizeReason,
    },
    RegionOverflow {
        device_size_bytes: u64,
        required_bytes: u64,
    },
    Crc32cMismatch {
        expected: u32,
        computed: u32,
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

## 11. ZFS Comparison

| Dimension | TideFS | ZFS | Winner |
|-----------|--------|-----|--------|
| Segment size granularity | Per-device, per-region | Pool-wide `ashift` | TideFS |
| Segment count scaling | Auto-scaling keeps count bounded (~100-4.2M) | Manual `zfs_device_metaslab_shift` tuning | TideFS |
| Heterogeneous device segment sizes | Yes -- different sizes per device in same pool | No -- `ashift` is pool-wide | TideFS |
| Region partitioning | 4 explicit regions with independent sizing | Implicit: root_record area + metaslab space | ZFS (simpler) |
| Journal sizing | Scales with segment size (16x, 256x) | Fixed ZIL size, per-pool config | TideFS |
| Operator policy | 3 policies (Slice0Small, Auto, Custom) | Ashift only | TideFS |
| Metadata segregation | Dedicated metadata journal region | Special allocation class (separate devices) | ZFS (more mature) |

## 12. Implementation Plan

### Phase 1: Types and Constants (crates/tidefs-local-object-store/src/layout.rs)
- Define `DeviceLayoutPolicy`, `DeviceLayoutPolicyDiscriminant`, `DeviceLayoutV1`
- Define all constants (`TARGET_DATA_SEGMENTS`, `MIN_SEGMENT_SIZE_BYTES`, etc.)
- Pure data types, no I/O

### Phase 2: Auto-Scaling Algorithm
- Implement `choose_segment_size_bytes()` and `build_device_layout()`
- Unit tests for device sizes 100 MiB -> 1 PiB
- Verify power-of-two output and segment count bounds

### Phase 3: Encode/Decode
- Implement binary encode/decode for `DeviceLayoutV1` with CRC32C
- Roundtrip tests with golden vectors

### Phase 4: Pool Integration
- Integrate `build_device_layout()` into pool creation
- Store `DeviceLayoutV1` per device in pool label

### Phase 5: Per-Region SegmentStore
- Configure `LocalObjectStore` instances with region-specific segment sizes
- Each device gets 4 stores (system, poolmap, metadata, data)

- Implement `tidefs-xtask check-device-layout-policy`

### Phase 7: Device Add/Remove with Heterogeneous Sizing
- Update `add_device()` and `remove_device()` for per-device layouts
- Extend `SegmentFreeMap` with per-device segment size metadata
- Update `PoolAllocator` to handle heterogeneous sizes

## 13. Open Questions

1. **System area cap on large devices**: A 256 MiB system area on a 1 PiB
   device wastes space. Cap at 16 MiB? Requires a `system_segment_size`
   independent of `data_segment_size` for large devices.

2. **Metadata segment size default**: Using `data_segment_size` for metadata
   means a 512-byte inode write wastes a 256 MiB segment on large devices.
   Consider `max(1 MiB, data_segment_size / 4)` as the default metadata
   segment size. Tradeoff: more segments -> costlier metadata replay on import.

3. **Poolmap journal cap**: 16 x 256 MiB = 4 GiB poolmap journal on a 1 PiB
   device. Cap at 512 MiB? Requires understanding per-commit_group checkpoint write
   volume from the spacemap design (#1189).

4. **Segment rotation compatibility**: When `StoreOptions.max_segment_bytes`
   is overridden by `DeviceLayoutV1`, should time-based and write-count-based
   rotation still apply? Proposal: Yes -- rotate when any trigger fires
   (size, time, or write count), but `max_segment_bytes` is authoritative
   for "segment full."

5. **Metadata journal sizing on dedicated metadata devices**: If a device is
   assigned `DeviceClass::Metadata`, should its data journal be zero-sized?
   Proposal: Yes -- build the layout without a data journal on pure-metadata
   devices. The pool routes writes by `IoClass`, so data writes never land
   on a metadata-only device.

## 14. References

- [#1189] Spacemap, allocator, and free-space tracking design
- [#1215] Space accounting model design
- [#1254] Pool import/export and device topology design
- [#1238] Unified on-media format lifecycle (meta)
- [#1220] On-media record format strategy
- `docs/CANONICAL_BINARY_ENCODE_DECODE_ENDIAN_CHECKSUM_LAW_P2-03.md`
- `docs/DEVICE_LAYOUT_POLICIES_DESIGN.md` (original #1193 design)
- `crates/tidefs-local-object-store/src/constants.rs`
- `crates/tidefs-local-object-store/src/store.rs` (segment rotation)
- `crates/tidefs-local-object-store/src/device.rs` (DeviceImpl trait)
- `crates/tidefs-spacemap-allocator/src/lib.rs` (SegmentFreeMap)
- `crates/tidefs-pool-allocator/src/lib.rs` (PoolAllocator)
- Python v0.262 reference: `layout_policy.py`

## 15. Revision History

| Date | Change | Issue |
|------|--------|-------|
| 2026-05-02 | Initial design specification delivered | #1193 |
| 2026-05-04 | Refined design with current codebase integration, updated references, open questions formalized | #1556 |
| 2026-05-04 | Re-issued as #1629: design-spec confirmed as authoritative for wire-up implementation; header updated to mark current tracking; remaining open questions carry forward | #1629 |
| 2026-05-04 | Re-issued as #1679: design-spec reconfirmed as authoritative with updated codebase references including SegmentFreeMap dirty-metaslab tracking (#1341), PoolAllocator metaslab-cursor and space-pressure infrastructure (#1347), and device DeviceClass/IoClass routing; all open questions carry forward to wire-up implementation | #1679 |
| 2026-05-04 | Re-issued as #1886: design-spec reconfirmed as authoritative for wire-up implementation; auto-generated coordinator issue for storage-core lane; all open questions carry forward; Rust implementation deferred to wire-up issues | #1886 |
| 2026-05-05 | Re-issued as #1967: design-spec reconfirmed as authoritative for wire-up implementation; auto-generated coordinator issue for storage-core lane; all open questions carry forward; Rust implementation deferred to wire-up issues | #1967 |
| 2026-05-05 | Re-issued as #1810: design-spec reconfirmed as authoritative for wire-up implementation; auto-generated coordinator issue for storage-core lane; all open questions carry forward; Rust implementation deferred to wire-up issues | #1810 |
