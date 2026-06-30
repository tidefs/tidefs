# Variable Device Sector Alignment Design

**Issue**: [#1280](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1280)
**Status**: design-spec
**Priority**: P2
**Lane**: storage-core
**Maturity**: design-spec
**Depends on**: #1285 (extent maps & locator tables), #1193 (device layout policies), #1275 (online pool geometry conversion), #1254 (pool import/export and online device topology)

## Abstract

ZFS `ashift`, Ceph BlueStore allocation sizing, and btrfs sector sizing are
prior-art inputs for this design. They do not prove a current TideFS capacity,
flash-wear, throughput, or better-than-incumbent claim. A pool-wide alignment
choice can make later mixed-sector media inefficient through padding or
read-modify-write behavior; this design records how TideFS intends to avoid that
lock-in.

tidefs avoids this by tying alignment to the **extent locator** rather than the pool
or device. Every `ExtentLocatorValueV1` carries alignment flags that tell the I/O path
which sector size the extent's physical data respects. The pool declares *supported*
alignments (not a single enforced alignment) in its on-media metadata. New devices
with larger native sectors can join a live pool as long as they support at least one
pool-supported alignment. Extents written to a 4K-native device automatically use 4K
alignment; extents on 512B devices stay at 512B. No forced conversion, no wasted
space.

### Comparison to existing systems

| System | Pool-wide alignment | Add 4K drive to 512B pool | Per-extent alignment | No-read-modify-write for mixed sectors |
|--------|--------------------|--------------------------|---------------------|--------------------------------------|
| **ZFS** | Yes (ashift) | No — can waste space or amplify writes | No | No |
| **Ceph BlueStore** | per-OSD (min_alloc_size) | No — requires OSD recreation | No | No |
| **btrfs** | per-device (sectorsize) | Yes, but per-device not per-extent | No | Partial (per-device) |
| **tidefs target** | Pool declares *supported* set | Target: new writes auto-adapt | Target: yes | Target: yes |

---

## 1. Architecture Overview

### 1.1 Core Insight: Extent_id Indirection Decouples Logical from Physical

tidefs's extent_id indirection layer (#1285) is the architectural enabler.
In ZFS, block pointers embed physical locations directly in the indirect-block
tree — changing the physical alignment of a block requires rewriting every
parent pointer in the tree. In tidefs:

```
File extent map                Locator table                   Device geometry
┌─────────────────┐          ┌──────────────────────────────┐  ┌──────────────┐
│ logical_offset  │          │ LocatorId → LocatorValue     │  │ Device A     │
│ ├─ extent_id(N) │──────────│  flags: ALIGNMENT_4K …       │──│ 512B native  │
│ ├─ extent_id(M) │    │     │  device_ptr → dev A, off X   │  │              │
│ └─ extent_id(P) │    │     └──────────────────────────────┘  └──────────────┘
└─────────────────┘    │
                       │     ┌──────────────────────────────┐  ┌──────────────┐
                       │     │ LocatorId → LocatorValue     │  │ Device B     │
                       └─────│  flags: ALIGNMENT_512B …     │──│ 4K native    │
                             │  device_ptr → dev B, off Y   │  │              │
                             └──────────────────────────────┘  └──────────────┘
```

**Key property**: The extent map (file → extent_id) is never dirtied by alignment
changes. Alignment is a property of the locator entry — one indirection level down.
This means extents N and P can live on different devices with different native sector
sizes, each using its optimal alignment, without any cascading changes upward.

### 1.2 Alignment as a Per-Extent Property

Rather than a single pool-wide `ashift`, each `ExtentLocatorValueV1` carries:

- **Alignment flags** in the existing `flags: u64` bitfield indicating which sector
  boundary the extent's on-media data respects.
- **Device pointer(s)** that route I/O to the specific device/device.
- **Physical offset** that is guaranteed to be a multiple of the extent's alignment.

The I/O path reads these flags and configures the block layer, DMA engine, and
allocator admission accordingly — all from the locator, never from a global pool
property.

### 1.3 Pool-Level Alignment Policy

The pool declares which alignments it supports in its on-media `PoolMeta` record:

```rust
/// Alignment modes this pool supports (bitfield).
/// Each bit corresponds to a sector size: bit 0 = 512B, bit 1 = 1K,
/// bit 2 = 2K, bit 3 = 4K, bit 4 = 8K, bits 5-15 reserved.
pub supported_alignments: u16,
```

| Bit | Alignment | `ashift` equivalent | Typical device |
|-----|-----------|---------------------|---------------|
| 0 | 512 B | 9 | 512n HDD, 512e HDD (emulated) |
| 1 | 1 KiB | 10 | Rare; some embedded flash |
| 2 | 2 KiB | 11 | Rare; some SAS SSDs |
| 3 | 4 KiB | 12 | 4K-native NVMe, 512e SSDs (native) |
| 4 | 8 KiB | 13 | Some enterprise NVMe, QLC NAND |
| 5-15 | reserved | — | Future expansion |

sector size appears in `supported_alignments`. If the device's sector size is not in
the supported set, the add is rejected (operator must adjust the pool policy first).

The policy is **additive by default**: pools created with 512B-only devices have
`supported_alignments = 0x0001`. When a 4K-native device is added, the policy can be
extended to `0x0009` (512B + 4K). Shrinking the set (e.g., removing 512B support)
requires all 512B-aligned extents to be relocated first — a pool-wide operation gated
by operator intent.

---

## 2. Data Structures

### 2.1 ExtentLocatorValueV1 Alignment Flags

New flags are added to the `locator_flags` module in
`crates/tidefs-types-locator-table-core/src/lib.rs`:

```rust
pub mod locator_flags {
    // … existing flags (SHARDED, ERASURE_CODED, COMPRESSED, etc.) …
    pub const SHARDED: u64 = 0x0001;
    pub const ERASURE_CODED: u64 = 0x0002;
    pub const COMPRESSED: u64 = 0x0004;
    pub const ENCRYPTED: u64 = 0x0008;
    pub const DEDUP_ELIGIBLE: u64 = 0x0010;
    pub const CLONE_TARGET: u64 = 0x0020;
    pub const DEADLIST: u64 = 0x0040;
    pub const INLINE_PAYLOAD: u64 = 0x0080;

    // Alignment flags: exactly one must be set for any DATA extent.
    // Bits 8-11 form a 4-bit alignment selector (shift = 8).
    pub const ALIGNMENT_SHIFT: u64 = 8;
    pub const ALIGNMENT_MASK: u64 = 0x0F00;

    pub const ALIGNMENT_512B: u64 = 0x0100;  // ashift 9
    pub const ALIGNMENT_1K:   u64 = 0x0200;  // ashift 10
    pub const ALIGNMENT_2K:   u64 = 0x0400;  // ashift 11
    pub const ALIGNMENT_4K:   u64 = 0x0800;  // ashift 12
    pub const ALIGNMENT_8K:   u64 = 0x1000;  // ashift 13
    // bits 12-15 reserved for future larger alignments (16K, 32K, 64K, 128K)
}
```

Alignment flags use a 4-bit field (bits 8-11) selecting one of 16 possible
alignment values. The mapping is:

| Flag value | Alignment | ashift | Minimum I/O unit |
|---|---|---|---|
| `0x0100` | 512 B | 9 | 512 B |
| `0x0200` | 1 KiB | 10 | 1 KiB |
| `0x0400` | 2 KiB | 11 | 2 KiB |
| `0x0800` | 4 KiB | 12 | 4 KiB |
| `0x1000` | 8 KiB | 13 | 8 KiB |

**Invariant**: For any DATA extent (`extent_kind = DATA`), exactly one alignment
bit in `ALIGNMENT_MASK` is set. For UNWRITTEN extents, the alignment field is
zero. For HOLE extents (not stored), alignment is not applicable.

Helper functions on `ExtentLocatorValueV1`:

```rust
impl ExtentLocatorValueV1 {
    /// Return the extent's alignment in bytes, or None if not a DATA extent.
    pub fn alignment_bytes(&self) -> Option<u64> {
        let raw = (self.flags & locator_flags::ALIGNMENT_MASK) >> locator_flags::ALIGNMENT_SHIFT;
        match raw {
            0 => None, // UNWRITTEN or no alignment set (legacy)
            1 => Some(512),
            2 => Some(1024),
            3 => Some(2048),
            4 => Some(4096),
            5 => Some(8192),
            _ => None, // reserved
        }
    }

    pub fn offset_is_aligned(&self, physical_offset: u64) -> bool {
        match self.alignment_bytes() {
            Some(align) => physical_offset % align == 0,
            None => true,
        }
    }
}
```

### 2.2 PoolMeta Extensions

The pool on-media metadata record gains a `supported_alignments` field:

```rust
/// Pool metadata — persisted in the pool's system area.
struct PoolMetaV1 {
    // … existing fields (name, uuid, created_commit_group, …) …
    // … device topology, device class assignments, … …

    /// Bitfield of alignment modes this pool supports (see locator_flags::ALIGNMENT_*).
    /// Each bit position maps to the ashift-equivalent:
    ///   bit 0 = 512B (ashift 9)
    ///   bit 1 = 1KiB (ashift 10)
    ///   …
    ///   bit 4 = 8KiB (ashift 13)
    /// At least one bit must always be set.
    pub supported_alignments: u16,

    /// When set, the pool allows mixed-alignment extents.
    /// When cleared (default for single-device pools), all extents use the
    /// lowest-common alignment.
    pub mixed_alignment_enabled: bool,
}
```

**On-disk format** (V1 unified record family, per #1220):

| Field | Offset | Size | Description |
|---|---:|---:|---|
| `supported_alignments` | TBD | 2 | Bitfield of supported alignment modes |
| `mixed_alignment_enabled` | TBD | 1 | 0/1 flag for mixed-alignment operation |
| `alignment_padding` | TBD | 5 | Reserved, zero |

### 2.3 Device-Side Sector Size Discovery

Each device exposes its native physical sector size through the `Device` trait:

```rust
/// Information about a device's physical sector geometry.
#[derive(Clone, Copy, Debug)]
pub struct DeviceSectorInfo {
    /// Logical sector size reported by the device (may be emulated, e.g., 512B on 512e).
    pub logical_sector_size: u32,
    /// Physical sector size — the device's native I/O unit.
    pub physical_sector_size: u32,
    /// Optimal I/O size for throughput (usually stripe width or erase block).
    pub optimal_io_size: u64,
}

pub trait DeviceImpl {
    // … existing methods …
    fn sector_info(&self) -> DeviceSectorInfo;
}
```

On Linux block devices, these are read from
`/sys/block/<dev>/queue/{logical_block_size,physical_block_size,optimal_io_size}`.
For regular-file development devices, the sector info is derived from the
underlying filesystem's `statvfs.f_bsize` and the kernel's `io_opt` from
`statx`.

### 2.4 Device-to-Alignment Mapping Table

A runtime table maps each device to its preferred alignment for new extent allocation:

```rust
/// Maps each active device to the alignment new extents should use when
/// placed on that device.
struct DeviceAlignmentMap {
    /// Per-device preferred alignment (derived from physical_sector_size).
    /// Indexed by pool-internal device index.
    alignments: Vec<u64>,
}
```

This table is rebuilt on pool import from per-device `DeviceSectorInfo` and the pool's
`supported_alignments` policy. For a 4K-native device in a pool that supports both
512B and 4K, the map entry is 4096. For a 512B-native device, it is 512.

---

## 3. Write-Path Algorithm

### 3.1 Extent Creation

When a write creates a new DATA extent, the allocator selects a target device based
on the pool's device-class routing. Before allocating space, the write path:

1. Looks up the target device's preferred alignment from `DeviceAlignmentMap`.
2. Rounds the extent's payload size up to the alignment boundary.
3. Passes `minimum_alignment_bytes` to the space allocator's admission check.
4. On allocation success, sets the alignment flag in the new
   `ExtentLocatorValueV1.flags`.

```
┌──────────────────────────────────────────────────────────────────┐
│                      NEW EXTENT WRITE PATH                       │
├──────────────────────────────────────────────────────────────────┤
│ 1. Write request: (file, offset, 17 KiB payload)                │
│ 2. Device router: → device 3 (4K-native NVMe)                     │
│ 3. DeviceAlignmentMap[device3] → 4096                               │
│ 4. Rounded payload: 20 KiB (5 × 4096)                            │
│ 5. Allocator admission: alignment_bytes=4096, size=20480         │
│ 6. Allocator returns: (segment=X, grain_offset=Y)                │
│ 7. on_media_bytes = 20480                                        │
│ 8. ExtentLocatorValueV1.flags |= ALIGNMENT_4K                    │
│ 9. Write payload to device; checksum; commit                     │
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 Read Path

On read, the block layer reads the `ExtentLocatorValueV1`, extracts
`alignment_bytes()`, and uses it to configure the I/O submission:

- For direct I/O: `O_DIRECT` buffer must be aligned to `alignment_bytes`.
- For ublk block device I/O: `discard_alignment` and `alignment_offset` in the
  ublk parameters are set from the extent's alignment.
- For kernel bypass (future RDMA): the DMA memory region is allocated with
  the extent's alignment constraint.

No pool-wide flag is consulted — every extent carries its own alignment, and the
I/O path obeys it exactly.

### 3.3 Space Allocation with Variable Alignment

The space allocator (ticket-based, `tidefs-claim_reserve_witness-space-alloc`)
already accepts `alignment_bytes` in its `AdmissionRequest` and `AllocationTicket`
types. The variable-alignment design extends this:

- **Admission**: The `minimum_alignment_bytes` in `AdmissionRequest` is set from
  the target device's preferred alignment, not a global constant.
- **Free-run selection**: `free_run_select` already accepts an `alignment_grains`
  parameter. This is set to `alignment_bytes / GRAIN_BYTES`.
- **Space accounting**: The `on_media_bytes` field in `ExtentLocatorValueV1` is
  rounded up to the alignment boundary. Space accounting tracks the rounded size,
  not the logical payload size.

### 3.4 Checksum and Integrity

Checksums (BLAKE3-256) are computed over the logical payload bytes, not the
padded on-media bytes. The padding region (alignment slop between `payload_bytes`
and `on_media_bytes`) is zero-filled on write and ignored on checksum verification.
This means alignment padding introduces no checksum fragility.

---

## 4. Migration and Compatibility

### 4.1 Existing Extents (Pre-Variable-Alignment)

Extents created before this design (no alignment flag set) are treated as
`ALIGNMENT_512B` — the most conservative alignment. This is safe because:

- 512B alignment is always a subset of any larger alignment.
- All existing devices in the current codebase use 512B or 4K native sectors
  (the pool's `ashift=12` default effectively provides 4K alignment everywhere).
- Reading a 4K-aligned extent as 512B-aligned is always correct (512B is a
  divisor of 4K).

When a pre-existing extent is first modified (rewritten), it is allocated on
the target device with that device's preferred alignment, and the alignment flag
is set in the new locator entry.

### 4.2 Adding a 4K-Native Device to a 512B-Only Pool

```
┌──────────────────────────────────────────────────────────────────┐
│                   DEVICE ADDITION WORKFLOW                       │
├──────────────────────────────────────────────────────────────────┤
│ 1. Operator: tidefs pool add /dev/nvme0n1 pool0                  │
│ 2. Probe device: physical_sector_size = 4096                      │
│ 3. PoolMeta.supported_alignments = 0x0001 (512B only)            │
│ 4. Check: 4096 → ashift 12 → bit 3 in supported_alignments?     │
│    → bit 3 = 0 → REJECT                                         │
│ 5. Operator: tidefs pool set supported_alignments +4k pool0       │
│    → supported_alignments |= 0x0008 (now 0x0009)                 │
│ 6. Retry add: bit 3 is now set → ACCEPT                         │
│ 7. New device online; new extents on this device use 4K alignment│
│ 8. Existing extents on 512B devices unchanged                    │
└──────────────────────────────────────────────────────────────────┘
```

### 4.3 Removing a Device Class (Shrinking the Alignment Set)

If the operator wants to remove 512B-aligned devices from the pool (e.g.,
migrating all data to 4K-native devices and retiring the old 512B drives):

1. Operator sets a pool property `target_alignment = 4096`.
2. Background relocation (via #1275 online geometry conversion infrastructure)
   rewrites all 512B-aligned extents to 4K-aligned devices.
3. When `count(512B-aligned extents) == 0`, the operator can remove 512B from
   `supported_alignments`.
4. Remaining 512B-only devices are detached.

This is a **lazy, budgeted background operation** — no downtime, no forced
evacuation, no pool destruction.

### 4.4 Background Relocation for Alignment Homogenization

The background relocation service (built on #1265 defrag infrastructure and
#1222 rebake) can be configured with an alignment homogenization policy:

- **Policy**: "Migrate all extents with alignment X to devices with alignment Y."
- **Budget**: configurable I/O bandwidth cap (e.g., 10 MiB/s).
- **Progress**: tracked per-extent; restartable across reboots.
- **Transparent**: file extent maps are never touched (extent_id indirection).

---

## 5. Anti-Pattern Avoidance

### 5.1 ZFS ashift Immutability Pressure

**Prior-art pressure**: `zpool create -o ashift=9 pool ...` with 512B drives. Later add a
4K-native NVMe. ZFS writes every 4K sector as 8 × 512B logical blocks, but on a
4K-native device, a 512B write triggers a read-modify-write of the entire 4K
physical sector. This can amplify I/O and reduce effective throughput.

**TideFS design target**: Extents placed on the 4K-native device use `ALIGNMENT_4K`.
The allocator rounds to 4K boundaries. The block layer issues 4K-aligned I/O.
The target is to avoid read-modify-write on mixed-sector pools where the device
and extent policy permit it.

### 5.2 Ceph bluestore_min_alloc_size Immutability

**Prior-art pressure**: `bluestore_min_alloc_size` is set per-OSD at creation time. To
change it, the OSD must be destroyed and recreated — losing all data on that OSD.

**TideFS design target**: `supported_alignments` is a pool-level policy that can be
widened at any time (additive). Individual extents carry their own alignment.
No OSD/device recreation is needed.

### 5.3 btrfs Mixed Sector Sizes

**btrfs**: Each device has a fixed `sectorsize`, and the filesystem uses the
maximum of all device sectorsizes for metadata. This avoids the read-modify-write
problem for metadata but doesn't optimize data placement per-device — data
blocks are always at least the size of the largest device's sector.

**tidefs improvement**: Per-extent alignment means data on 512B devices can
use 512B-aligned writes (lower overhead for small files), while data on 4K
devices uses 4K alignment. No global maximum is forced.

---

## 6. Integration Points

### 6.1 With Extent Maps and Locator Tables (#1285)

The alignment flags are added to the `ExtentLocatorValueV1` flags bitfield
(bits 8-11). The fixed-size record (`LOCATOR_VALUE_V1_FIXED_SIZE = 122` bytes)
does not change — alignment uses existing reserved flag bits, not new fields.

The `locator_flags` module is the single authority for alignment flag values.

### 6.2 With Device Layout Policies (#1193)

The `DeviceLayoutPolicy::build_device_layout()` function does not change.
The layout policy computes region boundaries and segment sizes independently
of sector alignment. Alignment is a per-extent property applied at allocation
time, not a layout constraint.

However, segment sizes must remain multiples of the largest supported alignment
to avoid fragmentation. The `Auto` policy already produces power-of-two segment
sizes (minimum 1 MiB), which is a multiple of every alignment in the supported
set.

### 6.3 With Online Pool Geometry Conversion (#1275)

Geometry conversion (mirror↔EC) is a locator-level operation. Since alignment
flags live in the locator entry, conversion automatically preserves the source
extent's alignment. A mirrored extent at `ALIGNMENT_4K` converted to EC(K+M)
retains `ALIGNMENT_4K` — each shard is allocated with 4K alignment on its
target device(s).

### 6.4 With Pool Import/Export (#1254)

On pool import, the `supported_alignments` field is read from `PoolMeta` and
in the supported set triggers a warning and is held in `DeviceState::Offline`
until the operator resolves the policy mismatch.

### 6.5 With Space Allocator

The space allocator already supports per-allocation alignment via
`AdmissionRequest.minimum_alignment_bytes` and `AllocationTicket.alignment_bytes`.
The variable-alignment design feeds the target device's preferred alignment into
these fields at extent allocation time.

### 6.6 With Block Volume Adapter

For ublk-backed block devices, the `ublk_params` struct already carries
`discard_alignment` and `alignment` fields. The variable-alignment design
populates these from the extent's alignment at I/O submission time rather
than from a static pool property.

---

## 7. Performance Properties

### 7.1 No Read-Modify-Write on Mixed-Sector Pools

| Write scenario | ZFS prior-art example (ashift=9, 4K drive) | TideFS design target (per-extent alignment) |
|---|---|---|
| 4 KiB write to 4K NVMe | RMW: read 4K, merge 512B×8, write 4K | Target: direct 4K write, no RMW |
| 512 B write to 512B HDD | Direct 512B write | Direct 512B write |
| 4 KiB write to 512e HDD | 8 × 512B (no RMW, emulated at drive) | 8 × 512B or aligned 4K if drive supports |

### 7.2 Space Overhead

Alignment padding creates internal fragmentation within each extent:

| Alignment | Max padding | Worst-case overhead for 1-byte write |
|---|---|---|
| 512 B | 511 B | 511× (51100%) |
| 4 KiB | 4095 B | 4095× (409500%) |
| 8 KiB | 8191 B | 8191× |

In practice, tidefs aggregates small writes in the intent log before extent
creation, and the `recordsize` policy (#1257) sets a minimum extent size
(default 4 KiB). The worst-case overhead for a 4 KiB write at 8 KiB alignment
is 100% — only 4 KiB of 8 KiB is used. However, this is identical to ZFS
ashift overhead and is a well-known property of sector-aligned storage.

### 7.3 Memory and CPU Cost

- **Locator lookup**: +1 bitmask operation (`flags & ALIGNMENT_MASK`) per
  extent read/write — negligible.
- **DeviceAlignmentMap**: one `Vec<u64>` with one entry per device — ~8 bytes/device.
- **PoolMeta**: +3 bytes on-media (2 for supported_alignments, 1 for mixed flag).

---

## 8. Edge Cases and Safety

### 8.1 Legacy Extents Without Alignment Flags

- Extents with no alignment bit set (`flags & ALIGNMENT_MASK == 0`) are treated
  as `ALIGNMENT_512B` — the most conservative safe default.
- The `alignment_bytes()` method returns `None` for UNWRITTEN extents and legacy
  extents, and callers fall back to 512B alignment.

### 8.2 Device Sector Size Change Across Reboot

A device's reported physical sector size can theoretically change across reboots
(e.g., NVMe format with different LBAF). On pool import:

1. `DeviceSectorInfo` is re-probed.
2. If `physical_sector_size` changed and is not in `supported_alignments`, the
   device is held OFFLINE with a descriptive error.
3. The operator must either update `supported_alignments` or reformat the device.

### 8.3 Alignment and Compression Interaction

Compressed extents: `payload_bytes` (logical) < `on_media_bytes` (physical).
The alignment applies to `on_media_bytes` — the physical allocation on disk
must be aligned, even if the compressed payload is smaller. The compression
layer already handles this (compressed data is written to a physical allocation
that may be larger than the compressed size).

### 8.4 Alignment and Encryption Interaction

Encryption (ChaCha20-Poly1305) operates on logical payload bytes before
alignment padding. The padding region is zero-filled after encryption.
No interaction — encryption and alignment are orthogonal.

### 8.5 Alignment and Erasure Coding

For erasure-coded extents, each shard carries its own alignment based on the
device it lands on. A single EC(4+2) extent may have:
- 4 data shards on 4K-native NVMe → `ALIGNMENT_4K`
- 2 parity shards on 512B HDD → `ALIGNMENT_512B`

This is valid as long as each shard's device supports its alignment. The shard
assembly logic is alignment-agnostic — it reads each shard at its native
alignment and reassembles the logical payload.

---

## 9. Non-Goals (Explicit Boundaries)

- **Automatic 512e→4Kn conversion at the device level**: tidefs does not
  reformat devices. It adapts to whatever sector size the device reports.
- **Sub-512B alignment**: The minimum I/O unit is 512 bytes. Sector sizes
  below 512B are not supported (no real device uses them).
- **Per-file alignment policies**: Alignment is a per-extent property tied
  to the target device. Per-file or per-dataset alignment preferences are
  deferred to the `recordsize` policy design (#1257).
- **Alignment-aware defrag that re-aligns extents**: Defrag (#1265) may
  optionally align extents to their target device during relocation, but
  this is an optimization, not a requirement. The design here specifies
  only the data structures and write-path behavior.

---



```
tidefs-xtask check-variable-sector-alignment
```

This gate verifies:
1. This document exists at `docs/design/variable-device-sector-alignment.md`
   and contains all required sections.
2. The `locator_flags` module defines `ALIGNMENT_MASK`, `ALIGNMENT_SHIFT`,
   and the five alignment constants (`ALIGNMENT_512B` through `ALIGNMENT_8K`).
3. `ExtentLocatorValueV1::alignment_bytes()` returns correct values for
   each flag and `None` for zero flags.
4. The `supported_alignments` field is documented as a `u16` bitfield in
   the pool metadata on-media layout.
5. `DeviceSectorInfo` or equivalent device probing interface is defined.
6. The write-path algorithm includes alignment rounding and flag setting.
7. Legacy extent handling (no alignment flag = 512B) is documented.
8. No `u64` flag collisions with existing flags (SHARDED=0x0001 through
   INLINE_PAYLOAD=0x0080 vs ALIGNMENT_MASK=0x0F00).

---

## 11. Implementation Sequence

| Step | Dependency | Deliverable |
|---|---|---|
| 1. Add alignment flags to `locator_flags` | None | `locator_flags` module update |
| 2. Add `alignment_bytes()` to `ExtentLocatorValueV1` | Step 1 | Helper method |
| 3. Define `DeviceSectorInfo` and `DeviceAlignmentMap` | None | Types |
| 4. Implement device sector probing | Step 3 | `SingleDevice` file-backed probe |
| 5. Add `supported_alignments` to pool metadata | #1220 (format strategy) | `PoolMetaV1` update |
| 6. Wire alignment into write path | Steps 1-5 | Extent creation sets alignment flag |
| 7. Wire alignment into read path (ublk, direct I/O) | Step 1 | I/O submission alignment |
| 9. Migration infrastructure (legacy extent handling) | Step 1 | Compatibility read path |
| 10. Background alignment homogenization | #1265, #1222 | Relocation policy |

Steps 1-5 are the core data-structure work (this design). Steps 6-9 are
implementation successors. Step 10 is deferred.

---

## 12. References

- ZFS ashift documentation: `zpoolprops(7)` — "ashift" property
- Ceph BlueStore min_alloc_size: `ceph-osd(8)` — `bluestore_min_alloc_size`
- #1285: Extent Maps and Locator Tables Design (`docs/EXTENT_MAPS_LOCATOR_TABLES_DESIGN.md`)
- #1193: Device Layout Policies Design (`docs/DEVICE_LAYOUT_POLICIES_DESIGN.md`)
- #1275: Online Pool Geometry Conversion (`docs/design/online-pool-geometry-conversion.md`)
- #1254: Pool Import/Export and Online Device Topology (`docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md`)
- #1220: On-Media Format Strategy (`docs/design/on-media-format-strategy.md`)
- #1265: Online Defrag/BPR Design (`docs/ONLINE_DEFRAG_BPR_DESIGN.md`)
- #1222: Shard Groups, Replicas, Rebake Design (deleted historical lineage;
  use `docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md` for current receipt
  authority)
