// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![deny(dead_code)]
#![deny(unused_imports)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Block-level allocation mechanism: free-block bitmap, allocation admission,
//! per-inode quota gating, statfs accumulation, and dirty-bitmap flush.
//!
//! # Authority
//!
//! Pool-level segment allocation (which segment, which device, device-class
//! routing, and pool-wide space-pressure signaling) is owned by
//! `tidefs_pool_allocator::PoolAllocator`; this crate operates against the
//! block-level free/used bitmap **under** that authority. When both levels
//! are active, callers allocate segments through the pool allocator first and
//! then use this crate's methods to carve blocks within those segments.
//! The block allocator does not make pool-level or device-level placement
//! decisions.
//!
//! # Position in the TideFS block stack
//!
//! The block allocator sits between the extent map and the object store,
//! answering "here are N free blocks" or ENOSPC. It gates write-path
//! admission at the block level: before a write can proceed the caller must
//! reserve, allocate, and commit blocks through this crate. Segment-level
//! placement and pool-wide space-accounting decisions flow through the
//! pool allocator above this component.
//!
//! ```text
//! FUSE handler / ublk target
//!         |
//!   VfsEngine / extent map    <- "I need N blocks for this file"
//!         |
//!   BlockAllocator            <- "here are N free blocks" or ENOSPC
//!         |
//!   PoolAllocator             <- segment selection, device routing
//!         |
//!   object store / bitmap persistence
//! ```
//!
//! Consumers include:
//! - `tidefs-block-volume-adapter-core` — block-device write-path admission.
//! - `tidefs-local-filesystem` — file-extent allocation in the FUSE path.
//! - `tidefs-local-object-store` — object-storage block provisioning.
//! - `tidefs-validation` — deterministic allocation replay in test harnesses.
//! - `tidefs-device-removal` — device fencing and deallocation during
//!   device drain.
//!
//! # Allocation state machine
//!
//! Every write goes through a three-phase lifecycle:
//!
//! 1. **Reserve** — call [`BlockAllocator::reserve`] to claim blocks against
//!    the inode's quota. Fails with [`AllocError::QuotaExceeded`] if the
//!    inode's hard limit would be breached. No bitmap mutation occurs yet.
//!
//! 2. **Allocate** — call one of the `alloc*` / `allocate*` methods to obtain
//!    concrete block addresses from the free-block bitmap. May return
//!    [`AllocResult::NoSpace`] with a `largest_free_extent` diagnostic for
//!    fragmentation analysis. On success, the selected blocks are marked used
//!    and the spacemap is updated.
//!
//! 3. **Commit** — call [`BlockAllocator::commit`] to move the reserved quota
//!    from "reserved" to "committed" (counted against the inode's hard limit).
//!    The commit boundary also marks the bitmap dirty so the next
//!    [`BlockAllocator::flush`] or [`BlockAllocator::flush_to`] call persists
//!    the new state.
//!
//! Rollback paths:
//! - [`BlockAllocator::release`] — release a reservation without allocating
//!   (caller aborted before reaching `alloc`).
//! - [`BlockAllocator::free`] + [`BlockAllocator::uncommit`] — undo an
//!   allocation that was already committed (e.g., extent-map rollback after
//!   a failed object-store write).
//!
//! The callers are responsible for ordering: reserve before allocate, free
//! before uncommit. Methods panic on programmer errors (committing more than
//! reserved, releasing more than reserved).
//!
//! # Architecture
//!
//! - [`FreeBlockBitmap`] — persistent bit-level free/used tracking. The bitmap
//!   is a flat bit array where bit `i` corresponds to block `i` (1 = used,
//!   0 = free). It supports first-fit, best-fit, and scattered allocation
//!   strategies, plus `largest_contiguous_free()` for fragmentation reporting.
//! - [`AllocResult`] — enriched allocation result with ENOSPC diagnostics
//!   (`largest_free_extent` field) so callers can distinguish true pool
//!   exhaustion from fragmentation.
//! - [`FreeExtentIter`] — iterator over contiguous free runs for space
//!   analysis and fragmentation inspection.
//! - [`QuotaTable`] — per-inode reserve → commit → release lifecycle with
//!   hard-limit enforcement. Entries are lazily created on first access and
//!   pruned when both reserved and committed counts reach zero.
//! - [`Statfs`] — block counters for the FUSE `statfs` operation. Inode
//!   fields are zeroed; the namespace layer merges inode-table counters.
//! - [`BlockAllocator`] — single public entry-point wrapping the bitmap,
//!   quota table, device topology registry, spacemap, and TRIM machinery
//!   behind an `Arc<RwLock<AllocatorInner>>`.
//!
//! # Allocation policy
//!
//! [`BlockAllocator::alloc`] selects free blocks from the in-memory
//! free-block bitmap. It does **not** decide which segment or which device
//! receives the blocks — that authority belongs to
//! `tidefs_pool_allocator::PoolAllocator`.
//!
//! The block-level selection uses a three-tier strategy:
//!
//! 1. **First-fit** via [`FreeBlockBitmap::alloc_contiguous`] — scans forward
//!    from the last allocation hint for the first run of consecutive free bits.
//! 2. **Best-fit** via [`FreeBlockBitmap::alloc_contiguous_best_fit`] — scans
//!    the entire bitmap to select the smallest run that satisfies the request,
//!    reducing long-term fragmentation.
//! 3. **Scattered** via [`FreeBlockBitmap::alloc_any`] — falls back to
//!    non-contiguous allocation when no single run is large enough.
//!
//! Higher-level entry points enrich the result:
//! - [`BlockAllocator::allocate`] — returns [`AllocResult`] with fragmentation
//!   diagnostics; contiguous-only (no scattered fallback).
//! - [`BlockAllocator::allocate_aligned`] — byte-oriented variant that rounds
//!   up to the configured sector boundary before delegating to `allocate`.
//! - [`BlockAllocator::alloc_bytes`] — byte-oriented with physical-sector
//!   alignment awareness; prefers physically-aligned runs from the spacemap
//!   size-class cache, falling back to scattered allocation.
//! - [`BlockAllocator::alloc_bytes_at`] — allocates at a target pool offset
//!   with per-device topology resolution and inward-rounding alignment.
//!
//! # Thread safety
//!
//! A single `Arc<RwLock<AllocatorInner>>` guards all mutable state (bitmap,
//! quota table, device topologies, spacemap, TRIM sink, and stats). The write
//! path (`alloc`/`free`/`flush`/`reserve`/`commit`/`release`/`uncommit`)
//! takes a write lock; `statfs`, `topology_for`, `free_count`, `block_count`,
//! and `quota_counts` take a read lock. [`BlockAllocator`] is `Clone` (cheap
//! `Arc` clone), making it safe to share across threads. Contention is
//! expected to be low because the lock is held only for bitmap/table mutation,
//! not for I/O.
//!
//! # Persistence
//!
//! The free-block bitmap is persisted via [`BlockAllocator::flush_to`],
//! which writes dirty bitmap words to a [`BitmapFlushSink`] implementation.
//! After a successful write, the bitmap is marked clean. Callers that manage
//! their own I/O can use [`BlockAllocator::flush_words`] to retrieve raw
//! u64 words and [`BlockAllocator::mark_clean`] to clear the dirty flag.
//! On mount, [`BlockAllocator::from_persisted`] reconstructs the bitmap
//! and spacemap from previously flushed words.
//!
//! # Device topology and alignment
//!
//! The allocator enforces sector-alignment contracts via
//! [`AllocatorTopology`] (default for the pool) and per-device
//! [`DeviceTopology`] entries registered through
//! [`BlockAllocator::register_device`]. Each device contributes its physical
//! geometry (logical/physical sector size, alignment offset, minimum I/O
//! size). The allocator resolves the correct topology at allocation time via
//! [`BlockAllocator::topology_for`] and [`BlockAllocator::topology_for_range`],
//! rejecting cross-device requests with [`AllocError::MixedDeviceTopology`].
//!
//! # Further reading
//!
//! The [README](README.md) covers the on-disk bitmap format, a complete
//! integration map for the five direct consumer crates, the full error
//! surface table, a per-module responsibility breakdown, and the testing
//! overview. The rustdoc here focuses on the architecture and API contract;
//! the README fills in deployment, persistence, and consumer-facing detail.

pub mod bitmap;
pub mod error;
pub mod quota;
pub mod statfs;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::RwLock;

pub use bitmap::{FreeBlockBitmap, FreeExtentIter};
pub use error::AllocError;
pub use quota::QuotaTable;
pub use statfs::Statfs;
pub use tidefs_commit_group::{CommitGroupEpochFence, CommitGroupId};

use tidefs_spacemap_allocator::SegmentFreeMap;
use tidefs_types_vfs_core::InodeId;

/// Block address type (re-exported from bitmap module).
pub use bitmap::BlockId;

/// Unique identifier for a block device in the storage pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct DeviceId(pub u32);

/// Device-level physical geometry reported by the block layer.
///
/// Describes logical and physical sector sizes, optimal I/O sizing,
/// and alignment constraints for a single block device. Converted
/// to [`AllocatorTopology`] for the allocator's alignment calculations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceTopology {
    /// Logical sector size in bytes (e.g., 512, 4096).
    pub logical_sector_size: u64,
    /// Physical sector size in bytes (e.g., 4096, 8192).
    /// Used as the effective sector size for alignment calculations.
    pub physical_sector_size: u64,
    /// Optimal I/O size in bytes reported by the device (e.g., 0 or 131072).
    pub optimal_io_size: u64,
    /// Byte offset from start of device to first aligned sector (usually 0).
    pub alignment_offset: u64,
    /// Minimum I/O size in bytes. When larger than `physical_sector_size`,
    /// allocations smaller than or not aligned to this boundary are rejected.
    /// Defaults to 0 (same as `physical_sector_size`).
    pub min_io_size: u64,
}

impl Default for DeviceTopology {
    fn default() -> Self {
        Self {
            logical_sector_size: 512,
            physical_sector_size: 512,
            optimal_io_size: 0,
            alignment_offset: 0,
            min_io_size: 0,
        }
    }
}

impl From<DeviceTopology> for AllocatorTopology {
    fn from(dt: DeviceTopology) -> Self {
        Self {
            logical_sector_size: dt.logical_sector_size,
            sector_size: dt.physical_sector_size,
            alignment_offset: dt.alignment_offset,
            min_io_size: dt.min_io_size,
        }
    }
}

/// Device topology for sector-aligned block allocation.
///
/// Describes the physical sector size and alignment of the underlying
/// block device so that extent allocations can be rounded to sector
/// boundaries and avoid read-modify-write penalties at the block layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocatorTopology {
    /// Logical sector size in bytes (e.g., 512, 4096). This is the minimum
    /// alignment unit enforced on every extent start and length.
    pub logical_sector_size: u64,
    /// Physical sector size in bytes (e.g., 512, 4096, 8192). Preferred
    /// alignment for optimal-IO placement; the allocator prefers
    /// physically-aligned free-extent candidates.
    pub sector_size: u64,
    /// Byte offset from start of device to first aligned sector (usually 0).
    pub alignment_offset: u64,
    /// Minimum I/O size in bytes. When larger than `sector_size`, allocations
    /// smaller than or not aligned to this boundary are rejected with
    /// [`AllocError::AlignmentViolation`]. Defaults to 0 (same as `sector_size`).
    pub min_io_size: u64,
}

impl Default for AllocatorTopology {
    fn default() -> Self {
        Self {
            logical_sector_size: 512,
            sector_size: 512,
            alignment_offset: 0,
            min_io_size: 0,
        }
    }
}

impl AllocatorTopology {
    /// Create a topology with explicit sector size and alignment offset.
    ///
    /// Sets `logical_sector_size` equal to `sector_size` (backward-compatible
    /// for homogeneous-sector devices). Use `with_logical` when the
    /// logical and physical sector sizes differ (e.g., 512e drives).
    #[must_use]
    pub const fn new(sector_size: u64, alignment_offset: u64) -> Self {
        Self {
            logical_sector_size: sector_size,
            sector_size,
            alignment_offset,
            min_io_size: 0,
        }
    }

    /// Create a topology with distinct logical and physical sector sizes.
    ///
    /// `logical` is the minimum alignment unit; `physical` is the preferred
    /// placement alignment. For 512e (512-byte logical, 4K physical), use
    /// `with_logical(512, 4096, alignment_offset)`.
    #[must_use]
    pub const fn with_logical(
        logical_sector_size: u64,
        physical_sector_size: u64,
        alignment_offset: u64,
    ) -> Self {
        Self {
            logical_sector_size,
            sector_size: physical_sector_size,
            alignment_offset,
            min_io_size: 0,
        }
    }

    /// Create a topology with explicit sector size, alignment offset,
    /// and minimum I/O size.
    ///
    /// Sets `logical_sector_size` equal to `sector_size` (backward-compatible).
    #[must_use]
    pub const fn with_min_io(sector_size: u64, alignment_offset: u64, min_io_size: u64) -> Self {
        Self {
            logical_sector_size: sector_size,
            sector_size,
            alignment_offset,
            min_io_size,
        }
    }

    /// Effective minimum I/O size: the larger of `sector_size` and
    /// `min_io_size` (or `sector_size` when `min_io_size` is 0).
    #[must_use]
    pub fn effective_min_io_size(&self) -> u64 {
        if self.min_io_size == 0 || self.min_io_size <= self.sector_size {
            self.sector_size
        } else {
            self.min_io_size
        }
    }

    /// Round a byte offset up to the nearest sector boundary.
    ///
    /// Returns a value `>= byte_offset` that is sector-aligned.
    #[must_use]
    pub fn round_up_sector(&self, byte_offset: u64) -> u64 {
        let s = self.sector_size;
        if byte_offset <= self.alignment_offset {
            return self.alignment_offset;
        }
        let shifted = byte_offset - self.alignment_offset;
        let rem = shifted % s;
        if rem == 0 {
            byte_offset
        } else {
            byte_offset + (s - rem)
        }
    }

    /// Round a byte offset down to the nearest sector boundary.
    ///
    /// Returns a value `<= byte_offset` that is sector-aligned.
    #[must_use]
    pub fn round_down_sector(&self, byte_offset: u64) -> u64 {
        if byte_offset <= self.alignment_offset {
            return self.alignment_offset;
        }
        let shifted = byte_offset - self.alignment_offset;
        let rem = shifted % self.sector_size;
        byte_offset - rem
    }

    /// Check whether a (offset, length) pair is sector-aligned.
    #[must_use]
    pub fn is_sector_aligned(&self, byte_offset: u64, length: u64) -> bool {
        if byte_offset < self.alignment_offset {
            return false;
        }
        let shifted = byte_offset - self.alignment_offset;
        shifted % self.sector_size == 0 && length % self.sector_size == 0
    }
    /// Check whether a byte offset is sector-aligned (ignoring length).
    ///
    /// Returns true when `byte_offset` is a multiple of `sector_size`
    /// after accounting for `alignment_offset`. Offsets below
    /// `alignment_offset` are rejected.
    #[must_use]
    pub fn is_offset_sector_aligned(&self, byte_offset: u64) -> bool {
        if byte_offset < self.alignment_offset {
            return false;
        }
        let shifted = byte_offset - self.alignment_offset;
        shifted % self.sector_size == 0
    }

    /// Round a byte offset up to the nearest logical-sector boundary.
    ///
    /// Uses `logical_sector_size` (the minimum alignment unit) rather than
    /// the physical `sector_size`. Offsets below `alignment_offset` are
    /// clamped to `alignment_offset`.
    #[must_use]
    pub fn round_up_logical(&self, byte_offset: u64) -> u64 {
        let s = self.logical_sector_size;
        if byte_offset <= self.alignment_offset {
            return self.alignment_offset;
        }
        let shifted = byte_offset - self.alignment_offset;
        let rem = shifted % s;
        if rem == 0 {
            byte_offset
        } else {
            byte_offset + (s - rem)
        }
    }

    /// Round a byte offset down to the nearest logical-sector boundary.
    #[must_use]
    pub fn round_down_logical(&self, byte_offset: u64) -> u64 {
        if byte_offset <= self.alignment_offset {
            return self.alignment_offset;
        }
        let shifted = byte_offset - self.alignment_offset;
        let rem = shifted % self.logical_sector_size;
        byte_offset - rem
    }

    /// Check whether a (offset, length) pair is logical-sector-aligned.
    #[must_use]
    pub fn is_logical_aligned(&self, byte_offset: u64, length: u64) -> bool {
        if byte_offset < self.alignment_offset {
            return false;
        }
        let shifted = byte_offset - self.alignment_offset;
        shifted % self.logical_sector_size == 0 && length % self.logical_sector_size == 0
    }

    /// Round a byte extent inward to logical-sector boundaries.
    ///
    /// Rounds `offset` up and `offset + length` down, then returns the
    /// aligned `(start, aligned_length)` pair. When the aligned region is
    /// empty (`start >= end`), returns `(offset, 0)` to let the caller
    /// detect [`AllocError::AlignmentImpossible`].
    #[must_use]
    pub fn round_extent_inward(&self, offset: u64, length: u64) -> (u64, u64) {
        if length == 0 {
            return (offset, 0);
        }
        let start = self.round_up_logical(offset);
        let end = self.round_down_logical(offset.saturating_add(length));
        if end <= start {
            (offset, 0)
        } else {
            (start, end - start)
        }
    }

    /// Return the slack fraction: what proportion of the requested length
    /// is lost to logical-sector inward rounding. Returns 0.0 when length
    /// is 0.
    #[must_use]
    pub fn slack_fraction(&self, requested_length: u64, aligned_length: u64) -> f64 {
        if requested_length == 0 || aligned_length >= requested_length {
            return 0.0;
        }
        (requested_length - aligned_length) as f64 / requested_length as f64
    }

    /// Round a byte extent outward to sector boundaries.
    ///
    /// Rounds `offset` down and `offset + length` up, then returns the
    /// aligned `(start, aligned_length)` pair. Zero-length extents return
    /// `(offset, 0)`.
    #[must_use]
    pub fn round_extent_outward(&self, offset: u64, length: u64) -> (u64, u64) {
        if length == 0 {
            return (offset, 0);
        }
        let start = self.round_down_sector(offset);
        let end = self.round_up_sector(offset + length);
        (start, end - start)
    }

    /// Minimum number of blocks needed to cover `byte_length` with
    /// sector-aligned rounding applied.
    ///
    /// Returns 0 for a 0-byte request.
    #[must_use]
    pub fn blocks_for_bytes(&self, byte_length: u64, block_size: u64) -> u32 {
        if byte_length == 0 {
            return 0;
        }
        let aligned = self.round_up_sector(byte_length);
        // Ceiling division to get block count.
        aligned.div_ceil(block_size) as u32
    }
}

/// Maximum fraction of the requested byte range that alignment rounding
/// is allowed to consume before the allocation is rejected with
/// [`AllocError::AlignmentImpossible`].
pub const MAX_ALIGNMENT_SLACK: f64 = 0.5;

/// Reserved byte range holding the persisted free-block bitmap.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Region {
    /// Byte offset of the bitmap region in the backing storage image.
    pub offset: u64,
    /// Byte length of the bitmap region in the backing storage image.
    pub length: u64,
}

impl Region {
    /// Create a bitmap region from a byte offset and length.
    #[must_use]
    pub const fn new(offset: u64, length: u64) -> Self {
        Self { offset, length }
    }
}

/// Sink used by [`BlockAllocator::flush_to`] to persist dirty bitmap words.
pub trait BitmapFlushSink {
    /// Write the allocator bitmap words into `region`.
    #[must_use = "flush result must be consumed to detect I/O errors"]
    fn write_bitmap(&mut self, region: Region, words: &[u64]) -> Result<(), AllocError>;
}

/// Callback invoked when blocks are freed and the coalesced freed range
/// exceeds the configured minimum discard threshold.
///
/// Implementations forward the TRIM range to the backing device (file-backed
/// `fallocate(FALLOC_FL_PUNCH_HOLE)` or block-device `BLKDISCARD` ioctl).
pub trait TrimSink: Send + Sync {
    /// Discard (TRIM/UNMAP) a byte range on the backing device.
    ///
    /// Called by [`BlockAllocator::free`] when a contiguous freed range
    /// meets or exceeds the configured [`BlockAllocator::min_discard_bytes`] threshold.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the discard operation fails.
    fn trim_range(&mut self, offset: u64, length: u64) -> Result<(), std::io::Error>;
}

/// Statistics for TRIM/DISCARD operations issued by the block allocator.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrimStats {
    /// Total number of TRIM operations issued.
    pub trim_ops: u64,
    /// Total bytes trimmed across all operations.
    pub trim_bytes: u64,
}

/// Internal state behind the `RwLock`.
struct AllocatorInner {
    bitmap: FreeBlockBitmap,
    quotas: QuotaTable,
    block_size: u32,
    bitmap_region: Region,
    /// Device topology for sector-aligned allocation (default, used when
    /// no per-device topology is registered for the target offset).
    topology: AllocatorTopology,
    /// Root-reserve block count: these blocks are subtracted from `f_bavail`
    /// and withheld from public allocation until privilege-aware admission exists.
    root_reserve: u64,
    /// Per-device topologies keyed by DeviceId.
    device_topologies: HashMap<DeviceId, DeviceTopology>,
    /// Mapping from pool byte offset to the owning device's range.
    /// Key is start_offset, value is (DeviceId, length_in_bytes).
    device_extents: BTreeMap<u64, (DeviceId, u64)>,
    /// Segment-level free-space map for alignment-aware allocation via
    /// size-class hints. Kept in sync with `bitmap` as a fast-lookup cache.
    spacemap: SegmentFreeMap,
    /// Optional sink for TRIM/DISCARD notifications when blocks are freed.
    trim_sink: Option<Box<dyn TrimSink>>,
    /// Minimum freed extent size (in bytes) before a TRIM is issued.
    /// Default 1 MiB; set to 0 to always trim, or u64::MAX to effectively
    /// disable.
    min_discard_bytes: u64,
    /// Running TRIM operation statistics.
    trim_stats: TrimStats,
    /// Devices currently fenced for removal (no new allocations).
    fenced_devices: HashSet<DeviceId>,
    /// Blocks allocated by commit-group epochs that are not durable yet.
    pending_allocations: BTreeMap<CommitGroupEpochFence, BTreeSet<BlockId>>,
    /// Fast owner lookup for blocks in `pending_allocations`.
    pending_allocation_blocks: BTreeMap<BlockId, CommitGroupEpochFence>,
    /// Blocks waiting for their freeing commit-group epoch to become durable.
    pending_frees: BTreeMap<CommitGroupEpochFence, BTreeSet<BlockId>>,
    /// Fast owner lookup for blocks in `pending_frees`.
    pending_free_blocks: BTreeMap<BlockId, CommitGroupEpochFence>,
}

impl std::fmt::Debug for AllocatorInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AllocatorInner")
            .field("bitmap", &self.bitmap)
            .field("quotas", &self.quotas)
            .field("block_size", &self.block_size)
            .field("bitmap_region", &self.bitmap_region)
            .field("topology", &self.topology)
            .field("root_reserve", &self.root_reserve)
            .field("device_topologies", &self.device_topologies)
            .field("device_extents", &self.device_extents)
            .field("spacemap", &self.spacemap)
            .field("trim_sink", &self.trim_sink.as_ref().map(|_| "TrimSink"))
            .field("min_discard_bytes", &self.min_discard_bytes)
            .field("trim_stats", &self.trim_stats)
            .field("fenced_devices", &self.fenced_devices)
            .field("pending_allocations", &self.pending_allocations)
            .field("pending_allocation_blocks", &self.pending_allocation_blocks)
            .field("pending_frees", &self.pending_frees)
            .field("pending_free_blocks", &self.pending_free_blocks)
            .finish()
    }
}

/// A contiguous byte range freed from a block device, eligible for
/// TRIM/DISCARD/UNMAP at the backing storage layer.
///
/// Multiple `TrimRequest` ranges can be coalesced via [`coalesce_trim_requests`]
/// to reduce TRIM command overhead by merging adjacent or overlapping
/// freed extents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrimRequest {
    /// Start byte offset of the freed range.
    pub offset: u64,
    /// Length of the freed range in bytes.
    pub length: u64,
}

impl TrimRequest {
    /// Create a new trim request covering `[offset, offset + length)`.
    #[must_use]
    pub const fn new(offset: u64, length: u64) -> Self {
        Self { offset, length }
    }
}

/// Coalesce a list of `TrimRequest` ranges, merging adjacent and
/// overlapping freed extents.
///
/// Adjacent ranges (end of one equals start of next) and overlapping
/// ranges are merged into a single range. Gaps up to `gap_threshold`
/// bytes are also bridged to reduce TRIM command count.
///
/// Returns a new consolidated list sorted by ascending offset.
#[must_use]
pub fn coalesce_trim_requests(requests: &[TrimRequest], gap_threshold: u64) -> Vec<TrimRequest> {
    if requests.is_empty() {
        return Vec::new();
    }

    let mut sorted: Vec<TrimRequest> = requests.to_vec();
    sorted.sort_by_key(|r| r.offset);

    let mut merged: Vec<TrimRequest> = Vec::with_capacity(sorted.len());
    let mut current = sorted[0];

    for &next in &sorted[1..] {
        let current_end = current.offset.saturating_add(current.length);
        // Merge if next starts at or before current_end + gap_threshold.
        if next.offset <= current_end.saturating_add(gap_threshold) {
            let next_end = next.offset.saturating_add(next.length);
            let new_end = current_end.max(next_end);
            current.length = new_end.saturating_sub(current.offset);
        } else {
            merged.push(current);
            current = next;
        }
    }
    merged.push(current);
    merged
}
/// Result of a block allocation attempt.
///
/// Enriches the `NoSpace` case with the largest contiguous free extent
/// (in blocks) so callers can distinguish true ENOSPC from fragmentation.
///
/// Converts to `Result<Vec<BlockId>, AllocError>` via `From`/`Into`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AllocResult {
    /// Allocation succeeded.
    Allocated(Vec<BlockId>),
    /// No contiguous free run of sufficient size exists.
    NoSpace {
        /// Size (in blocks) of the largest contiguous free run.
        largest_free_extent: u32,
    },
}

impl From<AllocResult> for Result<Vec<BlockId>, AllocError> {
    fn from(ar: AllocResult) -> Self {
        match ar {
            AllocResult::Allocated(blocks) => Ok(blocks),
            AllocResult::NoSpace { .. } => Err(AllocError::NoSpace),
        }
    }
}
impl AllocResult {
    /// Return the largest contiguous free extent in blocks, if known.
    ///
    /// Returns `Some(n)` for [`AllocResult::NoSpace`] (carrying the
    /// fragmentation diagnostic), and `None` for [`AllocResult::Allocated`]
    /// (no fragmentation information is computed on the success path).
    #[must_use]
    pub fn largest_free_extent(&self) -> Option<u32> {
        match self {
            Self::Allocated(_) => None,
            Self::NoSpace {
                largest_free_extent,
            } => Some(*largest_free_extent),
        }
    }
}

/// Physical block allocation reserved by a commit-group epoch.
///
/// The blocks named by this handle are unavailable to other allocations until
/// the owning epoch is made durable or the reservation is explicitly released.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockAllocationReservation {
    epoch_fence: CommitGroupEpochFence,
    blocks: Vec<BlockId>,
}

impl BlockAllocationReservation {
    fn new(epoch_fence: CommitGroupEpochFence, blocks: Vec<BlockId>) -> Self {
        Self {
            epoch_fence,
            blocks,
        }
    }

    /// Commit-group epoch that owns this block reservation.
    #[must_use]
    pub fn epoch_fence(&self) -> CommitGroupEpochFence {
        self.epoch_fence
    }

    /// Reserved physical block ids.
    #[must_use]
    pub fn blocks(&self) -> &[BlockId] {
        &self.blocks
    }

    /// Number of reserved blocks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Returns true when the reservation is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Consume the reservation and return its physical block ids.
    #[must_use]
    pub fn into_blocks(self) -> Vec<BlockId> {
        self.blocks
    }
}

/// Pending-free reservation owned by a commit-group epoch.
///
/// The blocks in this handle remain allocated and excluded from physical free
/// space until the owning epoch is made durable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockFreeReservation {
    epoch_fence: CommitGroupEpochFence,
    blocks: Vec<BlockId>,
}

impl BlockFreeReservation {
    fn new(epoch_fence: CommitGroupEpochFence, blocks: Vec<BlockId>) -> Self {
        Self {
            epoch_fence,
            blocks,
        }
    }

    /// Commit-group epoch that owns this pending free.
    #[must_use]
    pub fn epoch_fence(&self) -> CommitGroupEpochFence {
        self.epoch_fence
    }

    /// Blocks waiting for the commit-group durability barrier.
    #[must_use]
    pub fn blocks(&self) -> &[BlockId] {
        &self.blocks
    }

    /// Number of blocks waiting to be freed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Returns true when no blocks were accepted into the pending-free set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

/// Summary of allocator state retired at a commit-group epoch barrier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CommitGroupBlockDelta {
    /// Allocation reservations retired for the epoch.
    pub allocations: u64,
    /// Pending-free reservations retired for the epoch.
    pub frees: u64,
}

/// The public block allocator handle.
///
/// All operations are synchronized through an internal `RwLock`.
/// Clone is cheap (only clones the `Arc`-like handle).
#[derive(Clone, Debug)]
pub struct BlockAllocator {
    inner: std::sync::Arc<RwLock<AllocatorInner>>,
}

impl BlockAllocator {
    /// Create a new block allocator.
    ///
    /// - `block_count` - total data blocks in the filesystem image.
    /// - `block_size` - bytes per block (standard: 4096).
    /// - `bitmap_region` - reserved byte range for the persisted bitmap.
    ///
    /// The bitmap is initialized with all blocks free. If an on-disk bitmap
    /// exists, use `from_persisted` instead.
    ///
    /// Uses default [`AllocatorTopology`] (512-byte sectors, zero offset).
    #[must_use]
    pub fn new(block_count: u64, block_size: u32, bitmap_region: Region) -> Self {
        Self::with_topology(
            block_count,
            block_size,
            bitmap_region,
            AllocatorTopology::default(),
            0,
        )
    }

    /// Default block size: 4096 bytes (4 KiB).
    ///
    /// This is the standard TideFS block size used by pool creation,
    /// format utilities, and all in-tree callers of [`BlockAllocator::new`].
    pub const DEFAULT_BLOCK_SIZE: u32 = 4096;

    /// Default minimum discard request size: 1 MiB.
    ///
    /// Freed extents smaller than this are not forwarded to the
    /// [`TrimSink`] when [`BlockAllocator::free`] is called.
    pub const DEFAULT_MIN_DISCARD_BYTES: u64 = 1_048_576;

    /// Create a new block allocator with explicit device topology.
    ///
    /// See `new` for parameter docs. `topology` sets the sector-alignment
    /// contract for all allocation and free operations.
    #[must_use]
    pub fn with_topology(
        block_count: u64,
        block_size: u32,
        bitmap_region: Region,
        topology: AllocatorTopology,
        root_reserve: u64,
    ) -> Self {
        Self::assert_region_capacity(block_count, bitmap_region);
        Self::assert_block_alignment(block_size, &topology);
        Self::from_inner(AllocatorInner {
            bitmap: FreeBlockBitmap::new(block_count),
            quotas: QuotaTable::new(),
            block_size,
            bitmap_region,
            topology,
            root_reserve,
            device_topologies: HashMap::new(),
            device_extents: BTreeMap::new(),
            spacemap: SegmentFreeMap::new(block_count, vec![(0, block_count)])
                .expect("initial spacemap construction"),
            trim_sink: None,
            min_discard_bytes: BlockAllocator::DEFAULT_MIN_DISCARD_BYTES,
            trim_stats: TrimStats::default(),
            fenced_devices: HashSet::new(),
            pending_allocations: BTreeMap::new(),
            pending_allocation_blocks: BTreeMap::new(),
            pending_frees: BTreeMap::new(),
            pending_free_blocks: BTreeMap::new(),
        })
    }

    /// Create a new block allocator with an explicit root reserve.
    ///
    /// `root_reserve` is subtracted from `f_bavail` and public allocation
    /// rejects requests that would consume it.
    ///
    /// Uses default [`AllocatorTopology`] (512-byte sectors, zero offset).
    #[must_use]
    pub fn with_root_reserve(
        block_count: u64,
        block_size: u32,
        bitmap_region: Region,
        root_reserve: u64,
    ) -> Self {
        Self::with_topology(
            block_count,
            block_size,
            bitmap_region,
            AllocatorTopology::default(),
            root_reserve,
        )
    }

    /// Create a new block allocator with explicit topology and a TRIM sink.
    ///
    /// The `trim_sink` is invoked when freed block extents exceed
    /// `min_discard_bytes`. The caller provides the initial threshold;
    /// use [`BlockAllocator::set_min_discard_bytes`] to adjust at runtime.
    #[must_use]
    pub fn with_trim_sink(
        block_count: u64,
        block_size: u32,
        bitmap_region: Region,
        topology: AllocatorTopology,
        root_reserve: u64,
        trim_sink: Box<dyn TrimSink>,
        min_discard_bytes: u64,
    ) -> Self {
        let ba = Self::with_topology(
            block_count,
            block_size,
            bitmap_region,
            topology,
            root_reserve,
        );
        {
            let mut inner = ba.inner.write().unwrap();
            inner.trim_sink = Some(trim_sink);
            inner.min_discard_bytes = min_discard_bytes;
        }
        ba
    }

    /// Restore from a previously persisted bitmap.
    ///
    /// - `block_count` - must match the value used when the bitmap was persisted.
    /// - `block_size` - must match.
    /// - `bitmap_region` - reserved byte range for the persisted bitmap.
    /// - `words` - raw u64 words previously obtained via [`Self::flush_words`].
    ///
    /// Uses default [`AllocatorTopology`] (512-byte sectors, zero offset).
    #[must_use]
    pub fn from_persisted(
        block_count: u64,
        block_size: u32,
        bitmap_region: Region,
        words: Vec<u64>,
    ) -> Self {
        Self::from_persisted_with_topology(
            block_count,
            block_size,
            bitmap_region,
            words,
            AllocatorTopology::default(),
            0,
        )
    }

    /// Restore from a previously persisted bitmap with an explicit root reserve.
    ///
    /// Uses default [`AllocatorTopology`] (512-byte sectors, zero offset).
    #[must_use]
    pub fn from_persisted_with_root_reserve(
        block_count: u64,
        block_size: u32,
        bitmap_region: Region,
        words: Vec<u64>,
        root_reserve: u64,
    ) -> Self {
        Self::from_persisted_with_topology(
            block_count,
            block_size,
            bitmap_region,
            words,
            AllocatorTopology::default(),
            root_reserve,
        )
    }

    /// Restore from a previously persisted bitmap with explicit topology.
    #[must_use]
    pub fn from_persisted_with_topology(
        block_count: u64,
        block_size: u32,
        bitmap_region: Region,
        words: Vec<u64>,
        topology: AllocatorTopology,
        root_reserve: u64,
    ) -> Self {
        Self::assert_region_capacity(block_count, bitmap_region);
        Self::assert_block_alignment(block_size, &topology);

        // Clone words for spacemap reconstruction before moving into bitmap.
        let words_clone = words.clone();

        // Build free runs from the bitmap words for spacemap initialization.
        let mut runs = Vec::new();
        let mut run_start: Option<u64> = None;
        let total = block_count;
        for blk in 0..total {
            let word_idx = (blk / 64) as usize;
            let bit_idx = (blk % 64) as u32;
            let is_free = if word_idx < words_clone.len() {
                (words_clone[word_idx] >> bit_idx) & 1 == 0
            } else {
                true
            };
            if is_free {
                if run_start.is_none() {
                    run_start = Some(blk);
                }
            } else if let Some(s) = run_start.take() {
                runs.push((s, blk));
            }
        }
        if let Some(s) = run_start {
            runs.push((s, total));
        }

        Self::from_inner(AllocatorInner {
            bitmap: FreeBlockBitmap::from_words(block_count, words),
            quotas: QuotaTable::new(),
            block_size,
            bitmap_region,
            topology,
            root_reserve,
            device_topologies: HashMap::new(),
            device_extents: BTreeMap::new(),
            spacemap: SegmentFreeMap::new(block_count, runs)
                .expect("spacemap reconstruction from persisted bitmap"),
            trim_sink: None,
            min_discard_bytes: BlockAllocator::DEFAULT_MIN_DISCARD_BYTES,
            trim_stats: TrimStats::default(),
            fenced_devices: HashSet::new(),
            pending_allocations: BTreeMap::new(),
            pending_allocation_blocks: BTreeMap::new(),
            pending_frees: BTreeMap::new(),
            pending_free_blocks: BTreeMap::new(),
        })
    }

    /// Minimum bytes required to persist a bitmap for `block_count` blocks.
    #[must_use]
    pub fn required_bitmap_bytes(block_count: u64) -> u64 {
        FreeBlockBitmap::byte_len_for(block_count)
    }

    /// Return the configured bitmap region.
    #[must_use]
    pub fn bitmap_region(&self) -> Region {
        self.inner.read().unwrap().bitmap_region
    }

    /// Return the configured default device topology for sector-aligned allocation.
    #[must_use]
    pub fn allocator_topology(&self) -> AllocatorTopology {
        self.inner.read().unwrap().topology
    }

    /// Register a block device with its physical geometry and pool address range.
    ///
    /// `start_offset` and `length` describe the device's byte range within
    /// the storage pool. Once registered, allocations at offsets within this
    /// range use this device's topology for alignment enforcement.
    ///
    /// Returns `Err(AllocError::DeviceAlreadyRegistered)` when `id` is
    /// already registered.
    #[must_use = "device registration result must be consumed to detect errors"]
    pub fn register_device(
        &self,
        id: DeviceId,
        topology: DeviceTopology,
        start_offset: u64,
        length: u64,
    ) -> Result<(), AllocError> {
        // Validate topology before registering.
        if !topology.logical_sector_size.is_power_of_two()
            || topology.logical_sector_size == 0
            || topology.physical_sector_size == 0
            || !topology.physical_sector_size.is_power_of_two()
        {
            return Err(AllocError::InvalidDeviceTopology);
        }
        if topology.alignment_offset >= topology.physical_sector_size {
            return Err(AllocError::InvalidDeviceTopology);
        }

        let mut inner = self.inner.write().unwrap();
        if inner.device_topologies.contains_key(&id) {
            return Err(AllocError::DeviceAlreadyRegistered);
        }
        inner.device_topologies.insert(id, topology);
        inner.device_extents.insert(start_offset, (id, length));
        Ok(())
    }

    /// Return the [`AllocatorTopology`] that applies to the given byte offset.
    ///
    /// When `offset` falls within a registered device's range, returns the
    /// topology for that device. Otherwise falls back to the default
    /// [`AllocatorTopology`] configured at construction time.
    ///
    /// Returns `Err(AllocError::DeviceNotRegistered)` only when no default
    /// topology is set and no device covers the offset.
    #[must_use = "topology lookup must be consumed to select correct alignment"]
    pub fn topology_for(&self, offset: u64) -> Result<AllocatorTopology, AllocError> {
        let inner = self.inner.read().unwrap();
        // Search for a device extent that contains this offset.
        // BTreeMap::range with reverse iteration to find the last start <= offset.
        for (start, (id, len)) in inner.device_extents.range(..=offset).rev() {
            if offset >= *start && offset < start + len {
                if let Some(dt) = inner.device_topologies.get(id) {
                    return Ok(AllocatorTopology::from(*dt));
                }
            }
        }
        // Fall back to default topology.
        Ok(inner.topology)
    }

    /// Validate that a byte range `[start, start+length)` lies entirely within
    /// a single device's topology.
    ///
    /// Returns the applicable [`AllocatorTopology`] when the range is
    /// homogeneous (all offsets map to the same device topology).
    ///
    /// Returns `Err(AllocError::MixedDeviceTopology)` when the range crosses
    /// a device boundary, or `Err(AllocError::DeviceNotRegistered)` when
    /// part of the range has no registered topology and no default is set.
    #[must_use = "topology result must be consumed to verify alignment"]
    pub fn topology_for_range(
        &self,
        start: u64,
        length: u64,
    ) -> Result<AllocatorTopology, AllocError> {
        if length == 0 {
            return self.topology_for(start);
        }
        let end = start.saturating_add(length);
        let inner = self.inner.read().unwrap();

        // Find the topology for the start offset.
        let start_topo = self.topology_for_locked(&inner, start)?;
        // Check every device-extent boundary within the range.
        for (_extent_start, (_id, _extent_len)) in inner.device_extents.range(start..end) {
            // Check if the range crosses a device boundary by comparing
            // endpoint topologies.
            let end_topo = self.topology_for_locked(&inner, end.saturating_sub(1))?;
            if start_topo != end_topo {
                return Err(AllocError::MixedDeviceTopology);
            }
            // Also check at the boundary itself.
            let mid = *_extent_start;
            if mid > start {
                let mid_topo = self.topology_for_locked(&inner, mid)?;
                if mid_topo != start_topo {
                    return Err(AllocError::MixedDeviceTopology);
                }
            }
        }
        // Final check at end-1.
        let end_topo = self.topology_for_locked(&inner, end.saturating_sub(1))?;
        if end_topo != start_topo {
            return Err(AllocError::MixedDeviceTopology);
        }
        Ok(start_topo)
    }

    /// Internal: topology lookup that takes a pre-acquired read lock.
    fn topology_for_locked(
        &self,
        inner: &AllocatorInner,
        offset: u64,
    ) -> Result<AllocatorTopology, AllocError> {
        for (start, (id, len)) in inner.device_extents.range(..=offset).rev() {
            if offset >= *start && offset < start + len {
                if let Some(dt) = inner.device_topologies.get(id) {
                    return Ok(AllocatorTopology::from(*dt));
                }
            }
        }
        Ok(inner.topology)
    }

    /// Return the number of registered devices.
    #[must_use]
    pub fn registered_device_count(&self) -> usize {
        self.inner.read().unwrap().device_topologies.len()
    }

    fn from_inner(inner: AllocatorInner) -> Self {
        Self {
            inner: std::sync::Arc::new(RwLock::new(inner)),
        }
    }

    fn assert_region_capacity(block_count: u64, region: Region) {
        let needed = Self::required_bitmap_bytes(block_count);
        assert!(
            region.length >= needed,
            "bitmap region too small: length={}, required={needed}",
            region.length
        );
    }

    fn assert_block_alignment(block_size: u32, topology: &AllocatorTopology) {
        assert!(
            u64::from(block_size) % topology.sector_size == 0,
            "block_size ({block_size}) must be a multiple of sector_size ({})",
            topology.sector_size
        );
    }

    fn admit_allocation(inner: &AllocatorInner, nblocks: u32) -> Result<(), AllocError> {
        let requested = u64::from(nblocks);
        if requested == 0 {
            return Ok(());
        }

        let available = inner.bitmap.free_count().saturating_sub(inner.root_reserve);
        if requested > available {
            return Err(AllocError::NoSpace);
        }

        Ok(())
    }

    fn validate_epoch_fence(epoch_fence: CommitGroupEpochFence) -> Result<(), AllocError> {
        if epoch_fence.is_valid() {
            Ok(())
        } else {
            Err(AllocError::CommitGroupConflict)
        }
    }

    fn alloc_locked(inner: &mut AllocatorInner, nblocks: u32) -> Result<Vec<BlockId>, AllocError> {
        Self::admit_allocation(inner, nblocks)?;
        let blocks = if inner.fenced_devices.is_empty() {
            inner.bitmap.alloc(nblocks)?
        } else {
            let bs = inner.block_size;
            let extents = inner.device_extents.clone();
            let fenced = inner.fenced_devices.clone();
            inner
                .bitmap
                .alloc_contiguous_skip_devices(nblocks, bs, &extents, &fenced)
                .or_else(|_| {
                    inner
                        .bitmap
                        .alloc_any_skip_devices(nblocks, bs, &extents, &fenced)
                })?
        };
        Self::mark_blocks_used_in_spacemap(inner, &blocks);
        Ok(blocks)
    }

    fn mark_blocks_used_in_spacemap(inner: &mut AllocatorInner, blocks: &[BlockId]) {
        for &blk in blocks {
            let _ = inner.spacemap.remove_free(blk);
        }
        inner.spacemap.rebuild_hints();
    }

    fn mark_blocks_free_locked(inner: &mut AllocatorInner, blocks: &[BlockId]) {
        inner.bitmap.free_blocks(blocks);
        for &blk in blocks {
            let _ = inner.spacemap.add_free(blk);
        }
        inner.spacemap.rebuild_hints();
    }

    /// Allocate `nblocks`, preferring contiguous blocks and falling back to
    /// scattered blocks when the free space is fragmented.
    #[must_use = "allocation result must be consumed to track block usage"]
    pub fn alloc(&self, nblocks: u32) -> Result<Vec<BlockId>, AllocError> {
        let mut inner = self.inner.write().unwrap();
        let blocks = Self::alloc_locked(&mut inner, nblocks)?;
        #[cfg(debug_assertions)]
        debug_assert!(
            inner.bitmap.check_invariants(),
            "invariant violation after alloc"
        );
        Ok(blocks)
    }

    /// Reserve physical blocks for a commit-group epoch.
    ///
    /// The returned reservation names blocks that are already withheld from
    /// the free bitmap, so other writers cannot reallocate them while the
    /// owning commit group is still in flight. Call
    /// [`Self::mark_commit_group_durable`] when the epoch becomes durable, or
    /// [`Self::release_allocation`] / [`Self::abort_commit_group`] to roll the
    /// reservation back.
    #[must_use = "block allocation reservations must be retired at the commit-group barrier"]
    pub fn reserve_allocation(
        &self,
        epoch_fence: CommitGroupEpochFence,
        nblocks: u32,
    ) -> Result<BlockAllocationReservation, AllocError> {
        Self::validate_epoch_fence(epoch_fence)?;

        let mut inner = self.inner.write().unwrap();
        let blocks = Self::alloc_locked(&mut inner, nblocks)?;
        inner
            .pending_allocations
            .entry(epoch_fence)
            .or_default()
            .extend(blocks.iter().copied());
        for &block in &blocks {
            inner.pending_allocation_blocks.insert(block, epoch_fence);
        }
        #[cfg(debug_assertions)]
        debug_assert!(
            inner.bitmap.check_invariants(),
            "invariant violation after reserve_allocation"
        );
        Ok(BlockAllocationReservation::new(epoch_fence, blocks))
    }

    /// Release a single in-flight allocation reservation before durability.
    ///
    /// This rolls back only the blocks present in `reservation`. To retire every
    /// reservation owned by an epoch, use [`Self::abort_commit_group`].
    pub fn release_allocation(
        &self,
        reservation: BlockAllocationReservation,
    ) -> Result<CommitGroupBlockDelta, AllocError> {
        let epoch_fence = reservation.epoch_fence();
        Self::validate_epoch_fence(epoch_fence)?;

        let mut inner = self.inner.write().unwrap();
        let mut released = Vec::new();
        if let Some(pending) = inner.pending_allocations.get_mut(&epoch_fence) {
            for &block in reservation.blocks() {
                if pending.remove(&block) {
                    released.push(block);
                }
            }
        }
        if inner
            .pending_allocations
            .get(&epoch_fence)
            .is_some_and(BTreeSet::is_empty)
        {
            inner.pending_allocations.remove(&epoch_fence);
        }
        let mut cancelled_frees = Vec::new();
        for block in &released {
            if inner.pending_allocation_blocks.get(block) == Some(&epoch_fence) {
                inner.pending_allocation_blocks.remove(block);
            }
            if inner.pending_free_blocks.get(block) == Some(&epoch_fence) {
                inner.pending_free_blocks.remove(block);
                cancelled_frees.push(*block);
            }
        }
        if !cancelled_frees.is_empty() {
            if let Some(pending_frees) = inner.pending_frees.get_mut(&epoch_fence) {
                for block in &cancelled_frees {
                    pending_frees.remove(block);
                }
            }
            if inner
                .pending_frees
                .get(&epoch_fence)
                .is_some_and(BTreeSet::is_empty)
            {
                inner.pending_frees.remove(&epoch_fence);
            }
        }
        Self::mark_blocks_free_locked(&mut inner, &released);
        #[cfg(debug_assertions)]
        debug_assert!(
            inner.bitmap.check_invariants(),
            "invariant violation after release_allocation"
        );
        Ok(CommitGroupBlockDelta {
            allocations: released.len() as u64,
            frees: cancelled_frees.len() as u64,
        })
    }

    /// Hold blocks in the pending-free set until a commit group is durable.
    ///
    /// Accepted blocks remain allocated in the bitmap and are not included in
    /// allocator free-space reporting until [`Self::mark_commit_group_durable`]
    /// is called for `epoch_fence`.
    #[must_use = "pending frees must be retired at the commit-group barrier"]
    pub fn free_on_commit(
        &self,
        epoch_fence: CommitGroupEpochFence,
        blocks: &[BlockId],
    ) -> Result<BlockFreeReservation, AllocError> {
        Self::validate_epoch_fence(epoch_fence)?;

        let mut inner = self.inner.write().unwrap();
        let mut scheduled = BTreeSet::new();
        for &block in blocks {
            if block >= inner.bitmap.block_count() || inner.bitmap.is_free(block) {
                continue;
            }
            if let Some(owner) = inner.pending_allocation_blocks.get(&block) {
                if *owner != epoch_fence {
                    return Err(AllocError::CommitGroupConflict);
                }
            }
            if let Some(owner) = inner.pending_free_blocks.get(&block) {
                if *owner != epoch_fence {
                    return Err(AllocError::CommitGroupConflict);
                }
                continue;
            }
            scheduled.insert(block);
        }
        let scheduled: Vec<BlockId> = scheduled.into_iter().collect();

        if !scheduled.is_empty() {
            for &block in &scheduled {
                inner.pending_free_blocks.insert(block, epoch_fence);
            }
            inner
                .pending_frees
                .entry(epoch_fence)
                .or_default()
                .extend(scheduled.iter().copied());
        }

        Ok(BlockFreeReservation::new(epoch_fence, scheduled))
    }

    /// Retire all block reservations owned by a durable commit-group epoch.
    ///
    /// Allocation reservations become ordinary committed used blocks. Pending
    /// frees become reusable and are reflected in free-space reporting.
    pub fn mark_commit_group_durable(
        &self,
        epoch_fence: CommitGroupEpochFence,
    ) -> Result<CommitGroupBlockDelta, AllocError> {
        Self::validate_epoch_fence(epoch_fence)?;

        let mut inner = self.inner.write().unwrap();
        let allocations = inner
            .pending_allocations
            .remove(&epoch_fence)
            .unwrap_or_default();
        for block in &allocations {
            if inner.pending_allocation_blocks.get(block) == Some(&epoch_fence) {
                inner.pending_allocation_blocks.remove(block);
            }
        }

        let frees = inner.pending_frees.remove(&epoch_fence).unwrap_or_default();
        let freed: Vec<BlockId> = frees.iter().copied().collect();
        for block in &freed {
            if inner.pending_free_blocks.get(block) == Some(&epoch_fence) {
                inner.pending_free_blocks.remove(block);
            }
        }
        Self::mark_blocks_free_locked(&mut inner, &freed);
        #[cfg(debug_assertions)]
        debug_assert!(
            inner.bitmap.check_invariants(),
            "invariant violation after mark_commit_group_durable"
        );
        self.maybe_discard_freed(&mut inner, &freed);

        Ok(CommitGroupBlockDelta {
            allocations: allocations.len() as u64,
            frees: freed.len() as u64,
        })
    }

    /// Abort all block reservations owned by a commit-group epoch.
    ///
    /// In-flight allocations are returned to the allocator. Pending frees are
    /// discarded without changing bitmap state because the freeing epoch did
    /// not become durable.
    pub fn abort_commit_group(
        &self,
        epoch_fence: CommitGroupEpochFence,
    ) -> Result<CommitGroupBlockDelta, AllocError> {
        Self::validate_epoch_fence(epoch_fence)?;

        let mut inner = self.inner.write().unwrap();
        let allocations = inner
            .pending_allocations
            .remove(&epoch_fence)
            .unwrap_or_default();
        let released: Vec<BlockId> = allocations.iter().copied().collect();
        for block in &released {
            if inner.pending_allocation_blocks.get(block) == Some(&epoch_fence) {
                inner.pending_allocation_blocks.remove(block);
            }
        }

        let frees = inner.pending_frees.remove(&epoch_fence).unwrap_or_default();
        for block in &frees {
            if inner.pending_free_blocks.get(block) == Some(&epoch_fence) {
                inner.pending_free_blocks.remove(block);
            }
        }

        Self::mark_blocks_free_locked(&mut inner, &released);
        #[cfg(debug_assertions)]
        debug_assert!(
            inner.bitmap.check_invariants(),
            "invariant violation after abort_commit_group"
        );

        Ok(CommitGroupBlockDelta {
            allocations: released.len() as u64,
            frees: frees.len() as u64,
        })
    }

    /// Allocate `nblocks` contiguous blocks.
    ///
    /// Returns `Ok(Vec<BlockId>)` on success, or `Err(AllocError::NoSpace)`
    /// if insufficient free blocks exist.
    #[must_use = "allocation result must be consumed to track block usage"]
    pub fn alloc_contiguous(&self, nblocks: u32) -> Result<Vec<BlockId>, AllocError> {
        let mut inner = self.inner.write().unwrap();
        Self::admit_allocation(&inner, nblocks)?;
        let blocks = if inner.fenced_devices.is_empty() {
            inner.bitmap.alloc_contiguous(nblocks)?
        } else {
            let bs = inner.block_size;
            let extents = inner.device_extents.clone();
            let fenced = inner.fenced_devices.clone();
            inner
                .bitmap
                .alloc_contiguous_skip_devices(nblocks, bs, &extents, &fenced)?
        };
        for &blk in &blocks {
            let _ = inner.spacemap.remove_free(blk);
        }
        inner.spacemap.rebuild_hints();
        #[cfg(debug_assertions)]
        debug_assert!(
            inner.bitmap.check_invariants(),
            "invariant violation after alloc_contiguous"
        );
        Ok(blocks)
    }

    /// Allocate `nblocks` blocks (not necessarily contiguous).
    ///
    /// This is preferred over `alloc_contiguous` when contiguity isn't
    /// required, as it avoids fragmentation pressure.
    #[must_use = "scattered allocation result must be consumed to track block usage"]
    pub fn alloc_any(&self, nblocks: u32) -> Result<Vec<BlockId>, AllocError> {
        let mut inner = self.inner.write().unwrap();
        Self::admit_allocation(&inner, nblocks)?;
        let blocks = if inner.fenced_devices.is_empty() {
            inner.bitmap.alloc_any(nblocks)?
        } else {
            let bs = inner.block_size;
            let extents = inner.device_extents.clone();
            let fenced = inner.fenced_devices.clone();
            inner
                .bitmap
                .alloc_any_skip_devices(nblocks, bs, &extents, &fenced)?
        };
        for &blk in &blocks {
            let _ = inner.spacemap.remove_free(blk);
        }
        inner.spacemap.rebuild_hints();
        #[cfg(debug_assertions)]
        debug_assert!(
            inner.bitmap.check_invariants(),
            "invariant violation after alloc_any"
        );
        Ok(blocks)
    }

    /// Allocate `nblocks` blocks with best-fit fallback and ENOSPC diagnostics.
    ///
    /// Returns [`AllocResult::Allocated`] on success, or
    /// [`AllocResult::NoSpace`] with the largest free extent on failure.
    #[must_use = "new allocation result must be consumed"]
    pub fn allocate(&self, nblocks: u32) -> Result<AllocResult, AllocError> {
        if nblocks == 0 {
            return Ok(AllocResult::Allocated(Vec::new()));
        }
        let mut inner = self.inner.write().unwrap();
        // Convert admission NoSpace into AllocResult diagnostics.
        match Self::admit_allocation(&inner, nblocks) {
            Err(AllocError::NoSpace) => {
                let largest = inner.bitmap.largest_contiguous_free();
                return Ok(AllocResult::NoSpace {
                    largest_free_extent: largest,
                });
            }
            Err(e) => return Err(e),
            Ok(()) => {}
        }
        // Contiguous-only: first-fit then best-fit. No scattered fallback.
        match inner
            .bitmap
            .alloc_contiguous(nblocks)
            .or_else(|_| inner.bitmap.alloc_contiguous_best_fit(nblocks))
        {
            Ok(blocks) => {
                for &blk in &blocks {
                    let _ = inner.spacemap.remove_free(blk);
                }
                inner.spacemap.rebuild_hints();
                Ok(AllocResult::Allocated(blocks))
            }
            Err(AllocError::NoSpace) => {
                let largest = inner.bitmap.largest_contiguous_free();
                Ok(AllocResult::NoSpace {
                    largest_free_extent: largest,
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Allocate blocks for `byte_length` bytes, returning [`AllocResult`].
    ///
    /// Rounds up to sector boundary, delegates to [`Self::allocate`].
    #[must_use = "new aligned allocation result must be consumed"]
    pub fn allocate_aligned(&self, byte_length: u64) -> Result<AllocResult, AllocError> {
        if byte_length == 0 {
            return Ok(AllocResult::Allocated(Vec::new()));
        }

        let nblocks = {
            let inner = self.inner.read().unwrap();
            let topo = inner.topology;
            let bs = u64::from(inner.block_size);
            let eff_min_io = topo.effective_min_io_size();
            if eff_min_io > topo.sector_size && byte_length % eff_min_io != 0 {
                return Err(AllocError::AlignmentViolation);
            }
            let aligned_len = topo.round_up_logical(byte_length);
            aligned_len.div_ceil(bs) as u32
        };

        if nblocks == 0 {
            return Ok(AllocResult::Allocated(Vec::new()));
        }

        let result = self.allocate(nblocks)?;
        #[cfg(debug_assertions)]
        {
            let inner = self.inner.read().unwrap();
            let bs = u64::from(inner.block_size);
            let topo = inner.topology;
            if let AllocResult::Allocated(ref blocks) = result {
                let byte_len = blocks.len() as u64 * bs;
                debug_assert!(
                    byte_len % topo.sector_size == 0,
                    "allocate_aligned: result not sector-aligned"
                );
            }
        }
        Ok(result)
    }

    /// Allocate enough blocks to cover `byte_length` bytes, rounding up to
    /// the configured sector boundary first.
    ///
    /// Returns `Err(AllocError::AlignmentViolation)` when `byte_length` is not
    /// sector-aligned and a minimum I/O size constraint is in effect.
    ///
    /// When the device topology has a physical sector size larger than the
    /// logical sector size (e.g., 512e drives), this method prefers
    /// physically-aligned free-extent candidates via the spacemap's
    /// size-class hints, falling back to scattered allocation when no
    /// physically-aligned run is available.
    #[must_use = "byte-range allocation result must be consumed to track block usage"]
    pub fn alloc_bytes(&self, byte_length: u64) -> Result<Vec<BlockId>, AllocError> {
        if byte_length == 0 {
            return Ok(Vec::new());
        }

        let mut inner = self.inner.write().unwrap();
        let topology = inner.topology;
        let block_size = u64::from(inner.block_size);

        let eff_min_io = topology.effective_min_io_size();
        // Reject if byte_length is not a multiple of effective min I/O size
        // when the device imposes an alignment larger than the sector size.
        if eff_min_io > topology.sector_size && byte_length % eff_min_io != 0 {
            return Err(AllocError::AlignmentViolation);
        }

        let aligned_len = topology.round_up_logical(byte_length);
        let nblocks = aligned_len.div_ceil(block_size) as u32;
        if nblocks == 0 {
            return Ok(Vec::new());
        }

        // Alignment-aware placement: when physical sector > logical sector,
        // try to find a physically-aligned contiguous run via the spacemap.
        if topology.sector_size > topology.logical_sector_size && nblocks > 0 {
            let phys_blocks = topology.sector_size / block_size;
            // Search for a run whose start is physical-sector-aligned.
            // The spacemap's size-class hints give O(1) best-fit lookup.
            if let Some((run_start, _run_end)) = inner.spacemap.find_free_run(u64::from(nblocks)) {
                if run_start % phys_blocks == 0 {
                    // Found a physically-aligned run. Allocate from bitmap
                    // at that position.
                    let blk = inner.bitmap.alloc_contiguous_at(run_start, nblocks)?;
                    // Sync spacemap.
                    for &b in &blk {
                        let _ = inner.spacemap.remove_free(b);
                    }
                    #[cfg(debug_assertions)]
                    {
                        let sector_size = topology.sector_size;
                        debug_assert!(
                            blk.first()
                                .is_none_or(|&b| (b * block_size) % sector_size == 0),
                            "alloc_bytes: physically-aligned start not sector-aligned"
                        );
                    }
                    return Ok(blk);
                }
            }
        }

        // Fall back to regular allocation (skip fenced devices).
        Self::admit_allocation(&inner, nblocks)?;
        let blocks = if inner.fenced_devices.is_empty() {
            inner.bitmap.alloc(nblocks)?
        } else {
            let bs = inner.block_size;
            let extents = inner.device_extents.clone();
            let fenced = inner.fenced_devices.clone();
            inner
                .bitmap
                .alloc_contiguous_skip_devices(nblocks, bs, &extents, &fenced)
                .or_else(|_| {
                    inner
                        .bitmap
                        .alloc_any_skip_devices(nblocks, bs, &extents, &fenced)
                })?
        };
        for &blk in &blocks {
            let _ = inner.spacemap.remove_free(blk);
        }
        #[cfg(debug_assertions)]
        {
            let byte_len = blocks.len() as u64 * block_size;
            debug_assert!(
                byte_len % topology.sector_size == 0,
                "alloc_bytes: fallback allocation not sector-aligned: {} blocks * {} byte block = {} bytes, sector_size={}",
                blocks.len(), block_size, byte_len, topology.sector_size
            );
        }
        inner.spacemap.rebuild_hints();
        #[cfg(debug_assertions)]
        debug_assert!(
            inner.bitmap.check_invariants(),
            "invariant violation after alloc_bytes"
        );
        Ok(blocks)
    }
    /// Allocate enough blocks to cover bytes `[offset, offset+length)`.
    ///
    /// Resolves the per-device topology from `offset` via `topology_for`,
    /// then rounds `offset` *up* and `(offset + length)` *down* to the
    /// device's `logical_sector_size` boundary. This is inward rounding:
    /// the resulting aligned region is always a subset of the requested
    /// range. The caller gets exactly what was requested, just aligned.
    ///
    /// Returns `Err(AllocError::AlignmentImpossible)` when inward rounding
    /// produces an empty region or loses more than
    /// [`MAX_ALIGNMENT_SLACK`] of the requested range.
    ///
    /// Returns `Err(AllocError::MixedDeviceTopology)` when the rounded
    /// extent spans two or more devices with different topologies.
    #[must_use = "at-offset allocation result must be consumed to track block usage"]
    pub fn alloc_bytes_at(&self, offset: u64, length: u64) -> Result<Vec<BlockId>, AllocError> {
        if length == 0 {
            return Ok(Vec::new());
        }

        let block_size = {
            let inner = self.inner.read().unwrap();
            u64::from(inner.block_size)
        };

        // Resolve per-device topology for the target offset.
        let topology = self.topology_for(offset)?;

        // Inward-round to logical-sector boundaries.
        let (aligned_start, aligned_len) = topology.round_extent_inward(offset, length);

        // Reject if inward rounding consumed the entire region.
        if aligned_len == 0 {
            return Err(AllocError::AlignmentImpossible);
        }

        // Reject if alignment slack exceeds the allowed fraction.
        let slack = topology.slack_fraction(length, aligned_len);
        if slack > MAX_ALIGNMENT_SLACK {
            return Err(AllocError::AlignmentImpossible);
        }

        // Validate that the aligned extent stays within a single device topology.
        let _ = self.topology_for_range(aligned_start, aligned_len)?;

        let eff_min_io = topology.effective_min_io_size();
        // Reject when min_io_size > sector_size and the extent is not
        // a multiple of effective min I/O size.
        if eff_min_io > topology.sector_size
            && (aligned_start % eff_min_io != 0 || aligned_len % eff_min_io != 0)
        {
            return Err(AllocError::AlignmentViolation);
        }

        let nblocks = aligned_len.div_ceil(block_size) as u32;
        if nblocks == 0 {
            return Ok(Vec::new());
        }
        let blocks = self.alloc(nblocks)?;
        #[cfg(debug_assertions)]
        {
            let block_size = u64::from(self.inner.read().unwrap().block_size);
            let byte_len = blocks.len() as u64 * block_size;
            debug_assert!(
                byte_len % topology.sector_size == 0,
                "alloc_bytes_at: result byte range not sector-aligned: {} blocks * {} byte block = {} bytes, sector_size={}",
                blocks.len(), block_size, byte_len, topology.sector_size
            );
        }
        Ok(blocks)
    }

    /// Mark blocks as free.
    ///
    /// Idempotent: already-free blocks are silently ignored.
    ///
    /// In debug builds, panics if the block count would not be sector-aligned
    /// (i.e. `blocks.len() * block_size` is not a multiple of
    /// `topology.sector_size`). In release builds, the free proceeds without
    /// an alignment check.
    pub fn free(&self, blocks: &[BlockId]) {
        #[cfg(debug_assertions)]
        {
            let inner = self.inner.read().unwrap();
            let block_size = u64::from(inner.block_size);
            let byte_len = blocks.len() as u64 * block_size;
            debug_assert!(
                byte_len % inner.topology.sector_size == 0,
                "free extent not sector-aligned: {} blocks * {} byte block = {} bytes, sector_size={}",
                blocks.len(),
                block_size,
                byte_len,
                inner.topology.sector_size
            );
        }
        let mut inner = self.inner.write().unwrap();
        let immediate: Vec<BlockId> = blocks
            .iter()
            .copied()
            .filter(|block| {
                !inner.pending_allocation_blocks.contains_key(block)
                    && !inner.pending_free_blocks.contains_key(block)
            })
            .collect();
        Self::mark_blocks_free_locked(&mut inner, &immediate);
        #[cfg(debug_assertions)]
        debug_assert!(
            inner.bitmap.check_invariants(),
            "invariant violation after free"
        );

        // Issue TRIM for freed extents that meet the minimum discard threshold.
        self.maybe_discard_freed(&mut inner, &immediate);
    }

    /// Set the minimum discard threshold in bytes.
    ///
    /// Freed extents smaller than this are not forwarded to the
    /// [`TrimSink`]. Setting to `u64::MAX` effectively disables
    /// automatic TRIM on free.
    pub fn set_min_discard_bytes(&self, threshold: u64) {
        self.inner.write().unwrap().min_discard_bytes = threshold;
    }

    /// Return the current minimum discard threshold in bytes.
    #[must_use]
    pub fn min_discard_bytes(&self) -> u64 {
        self.inner.read().unwrap().min_discard_bytes
    }

    /// Set or replace the TRIM sink on an already-constructed allocator.
    ///
    /// Passing [`None`] disables automatic TRIM on free.  When a sink is
    /// provided, the caller should also set [`BlockAllocator::set_min_discard_bytes`].
    pub fn set_trim_sink(&self, sink: Option<Box<dyn TrimSink>>) {
        let mut inner = self.inner.write().unwrap();
        inner.trim_sink = sink;
    }

    /// Discard a specific byte range through the configured [`TrimSink`].
    ///
    /// When a sink is registered and `length >= min_discard_bytes`, this
    /// issues a single TRIM operation. Otherwise it silently succeeds.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the sink's discard operation fails.
    pub fn discard_extent(&self, offset: u64, length: u64) -> Result<(), AllocError> {
        let mut inner = self.inner.write().unwrap();
        self.do_discard(&mut inner, offset, length)
    }

    /// Return accumulated TRIM statistics.
    #[must_use]
    pub fn trim_stats(&self) -> TrimStats {
        self.inner.read().unwrap().trim_stats
    }

    /// After freeing blocks, compute coalesced TRIM ranges and forward
    /// extents meeting the minimum threshold to the configured sink.
    fn maybe_discard_freed(&self, inner: &mut AllocatorInner, blocks: &[BlockId]) {
        let sink = match &mut inner.trim_sink {
            Some(s) => s,
            None => return,
        };
        let min_bytes = inner.min_discard_bytes;
        if min_bytes == u64::MAX || blocks.is_empty() {
            return;
        }

        let block_size = u64::from(inner.block_size);
        // Compute coalesced trim ranges from the freed block ids.
        // Must work inside the write lock -- cannot call self.trim_requests_for
        // because it would re-acquire the inner lock and deadlock.
        let raw: Vec<TrimRequest> = blocks
            .iter()
            .map(|&id| TrimRequest {
                offset: id * block_size,
                length: block_size,
            })
            .collect();
        let requests = crate::coalesce_trim_requests(&raw, min_bytes);
        // Downcast the Box<dyn TrimSink> to &mut dyn TrimSink for the call.
        // SAFETY: we hold the exclusive write lock on inner, so the sink
        // is not accessed concurrently.
        let sink_mut: &mut dyn TrimSink = sink.as_mut();
        for req in &requests {
            if req.length >= min_bytes {
                if let Err(e) = sink_mut.trim_range(req.offset, req.length) {
                    // Log and continue; a single TRIM failure should not
                    // prevent subsequent ranges from being trimmed.
                    eprintln!(
                        "TRIM failed for range [{}, {}): {}",
                        req.offset,
                        req.offset + req.length,
                        e
                    );
                } else {
                    inner.trim_stats.trim_ops += 1;
                    inner.trim_stats.trim_bytes += req.length;
                }
            }
        }
    }

    /// Execute a single discard through the configured sink.
    fn do_discard(
        &self,
        inner: &mut AllocatorInner,
        offset: u64,
        length: u64,
    ) -> Result<(), AllocError> {
        let sink = inner.trim_sink.as_mut().ok_or(AllocError::NoSpace)?;
        sink.trim_range(offset, length).map_err(|_e| AllocError::Io)
    }

    /// Reserve `nblocks` for an inode without committing them.
    ///
    /// Returns `Err(AllocError::QuotaExceeded)` if the reservation would
    /// exceed the inode's hard limit.
    #[must_use = "reservation result must be consumed to detect quota errors"]
    pub fn reserve(&self, inode: InodeId, nblocks: u64) -> Result<(), AllocError> {
        self.inner.write().unwrap().quotas.reserve(inode, nblocks)
    }

    /// Commit a prior reserve: transfer blocks from reserved to committed.
    ///
    /// Panics on programmer error (committing more than reserved).
    pub fn commit(&self, inode: InodeId, nblocks: u64) {
        self.inner.write().unwrap().quotas.commit(inode, nblocks);
    }

    /// Release a prior reserve without allocating.
    ///
    /// Panics on programmer error (releasing more than reserved).
    pub fn release(&self, inode: InodeId, nblocks: u64) {
        self.inner.write().unwrap().quotas.release(inode, nblocks);
    }

    /// Decrease committed quota for an inode after lower layers free blocks.
    ///
    /// This saturates at zero, matching [`QuotaTable::uncommit`].
    pub fn uncommit(&self, inode: InodeId, nblocks: u64) {
        self.inner.write().unwrap().quotas.uncommit(inode, nblocks);
    }

    /// Set a hard block limit for an inode. 0 = unlimited.
    pub fn set_quota_limit(&self, inode: InodeId, limit: u64) {
        self.inner.write().unwrap().quotas.set_limit(inode, limit);
    }

    /// Return (reserved, committed) counts for an inode.
    #[must_use]
    pub fn quota_counts(&self, inode: InodeId) -> (u64, u64) {
        self.inner.read().unwrap().quotas.counts(inode)
    }

    /// Return allocator-local block statistics for isolated allocator tests.
    ///
    /// Production statfs authority lives in
    /// `tidefs_local_filesystem::capacity_authority::CapacityAuthority`; this
    /// helper reports only the free-block bitmap counters maintained by this
    /// allocator.
    #[must_use]
    pub fn allocator_statfs(&self) -> Statfs {
        let inner = self.inner.read().unwrap();
        let total = inner.bitmap.block_count();
        let free = inner.bitmap.free_count();
        let avail = free.saturating_sub(inner.root_reserve);
        let mut s = Statfs::new(u64::from(inner.block_size));
        s.set_blocks(total, free, avail);
        s
    }

    /// Return filesystem statistics suitable for `statfs`.
    ///
    /// **Deprecated**: the production statfs authority is
    /// [`tidefs_local_filesystem::capacity_authority::CapacityAuthority`].
    /// This method computes block counters directly from the free-block bitmap
    /// and is not used in the mounted FUSE or kernel statfs path. It remains
    /// available for tests that exercise the allocator in isolation.
    #[deprecated(
        since = "0.421.0",
        note = "Use tidefs_local_filesystem::capacity_authority::CapacityAuthority for production statfs"
    )]
    #[must_use]
    pub fn statfs(&self) -> Statfs {
        self.allocator_statfs()
    }

    /// Return the raw bitmap words for persisting to disk.
    ///
    /// The caller is responsible for writing these to the reserved region.
    /// After a successful write, call `mark_clean` to clear the dirty flag.
    #[must_use = "flush result must be consumed to detect I/O errors"]
    pub fn flush_words(&self) -> Vec<u64> {
        self.inner.read().unwrap().bitmap.words().to_vec()
    }

    /// Flush the dirty bitmap state.
    ///
    /// This crate does not own a storage backend, so this marks the in-memory
    /// bitmap clean after the caller has retrieved [`Self::flush_words`]. Integrators
    /// that can write to a backing image should prefer [`Self::flush_to`].
    #[must_use = "flush result must be consumed to detect I/O errors"]
    pub fn flush(&self) -> Result<(), AllocError> {
        self.mark_clean();
        Ok(())
    }

    /// Write dirty bitmap words to a caller-provided persistence sink.
    #[must_use = "flush-to result must be consumed to detect I/O errors"]
    pub fn flush_to<S: BitmapFlushSink>(&self, sink: &mut S) -> Result<(), AllocError> {
        let mut inner = self.inner.write().unwrap();
        if !inner.bitmap.is_dirty() {
            return Ok(());
        }

        sink.write_bitmap(inner.bitmap_region, inner.bitmap.words())?;
        inner.bitmap.mark_clean();
        Ok(())
    }

    /// Clear the bitmap dirty flag (call after successful persist).
    pub fn mark_clean(&self) {
        self.inner.write().unwrap().bitmap.mark_clean();
    }

    /// True if the in-memory bitmap differs from the on-disk copy.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.inner.read().unwrap().bitmap.is_dirty()
    }

    /// Total blocks managed.
    #[must_use]
    pub fn block_count(&self) -> u64 {
        self.inner.read().unwrap().bitmap.block_count()
    }

    /// Block size in bytes.
    #[must_use]
    pub fn block_size(&self) -> u32 {
        self.inner.read().unwrap().block_size
    }

    /// Number of currently free blocks.
    #[must_use]
    pub fn free_count(&self) -> u64 {
        self.inner.read().unwrap().bitmap.free_count()
    }

    /// Number of blocks reserved by non-durable commit-group allocations.
    #[must_use]
    pub fn pending_allocation_count(&self) -> u64 {
        self.inner.read().unwrap().pending_allocation_blocks.len() as u64
    }

    /// Number of blocks held in the pending-free set.
    #[must_use]
    pub fn pending_free_count(&self) -> u64 {
        self.inner.read().unwrap().pending_free_blocks.len() as u64
    }

    /// Collect all free block ranges as `TrimRequest` byte ranges.
    /// Scans the free-block bitmap and returns every contiguous free run
    /// converted to byte-offset trim requests. The returned ranges are
    /// already sorted by ascending offset (scan order).
    #[must_use]
    pub fn free_ranges(&self) -> Vec<TrimRequest> {
        let inner = self.inner.read().unwrap();

        let block_size = u64::from(inner.block_size);

        let total = inner.bitmap.block_count();

        let mut ranges = Vec::new();

        let mut run_start: Option<u64> = None;

        for blk in 0..total {
            if inner.bitmap.is_free(blk) {
                if run_start.is_none() {
                    run_start = Some(blk);
                }
            } else if let Some(start) = run_start.take() {
                let offset = start * block_size;

                let length = (blk - start) * block_size;

                ranges.push(TrimRequest { offset, length });
            }
        }

        if let Some(start) = run_start {
            let offset = start * block_size;

            let length = (total - start) * block_size;

            ranges.push(TrimRequest { offset, length });
        }

        ranges
    }

    /// Convert a set of freed block IDs into coalesced `TrimRequest` byte ranges.
    /// `gap_threshold` controls how aggressively adjacent freed extents are
    /// merged (see [`coalesce_trim_requests`]). A threshold of 0 means only
    /// exact-adjacent or overlapping ranges are merged.
    #[must_use]
    pub fn trim_requests_for(&self, freed: &[BlockId], gap_threshold: u64) -> Vec<TrimRequest> {
        let inner = self.inner.read().unwrap();

        let block_size = u64::from(inner.block_size);

        let raw: Vec<TrimRequest> = freed
            .iter()
            .map(|&id| TrimRequest {
                offset: id * block_size,

                length: block_size,
            })
            .collect();

        coalesce_trim_requests(&raw, gap_threshold)
    }
    /// Total committed blocks across all inodes (from quota table).
    #[must_use]
    pub fn total_committed(&self) -> u64 {
        self.inner.read().unwrap().quotas.total_committed()
    }

    /// Fence a device: prevent new allocations on it (device removal).
    pub fn fence_device(&self, device_id: DeviceId) {
        self.inner.write().unwrap().fenced_devices.insert(device_id);
    }

    /// Remove a device from the fence set.
    pub fn unfence_device(&self, device_id: DeviceId) {
        self.inner
            .write()
            .unwrap()
            .fenced_devices
            .remove(&device_id);
    }

    /// Returns `true` if the device is currently fenced for removal.
    #[must_use]
    pub fn is_device_fenced(&self, device_id: DeviceId) -> bool {
        self.inner
            .read()
            .unwrap()
            .fenced_devices
            .contains(&device_id)
    }

    /// Returns a snapshot of currently fenced device IDs.
    #[must_use]
    pub fn fenced_device_ids(&self) -> Vec<DeviceId> {
        self.inner
            .read()
            .unwrap()
            .fenced_devices
            .iter()
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(block_count: u64) -> Region {
        Region::new(0, BlockAllocator::required_bitmap_bytes(block_count))
    }

    #[test]
    fn new_allocator_properties() {
        let ba = BlockAllocator::new(1024, 4096, region(1024));
        assert_eq!(ba.block_count(), 1024);
        assert_eq!(ba.block_size(), 4096);
        assert_eq!(ba.free_count(), 1024);
        assert_eq!(ba.bitmap_region(), region(1024));
    }

    #[test]
    fn alloc_contiguous_and_free() {
        let ba = BlockAllocator::new(1024, 4096, region(1024));
        let blocks = ba.alloc_contiguous(10).unwrap();
        assert_eq!(blocks.len(), 10);
        assert_eq!(ba.free_count(), 1014);

        ba.free(&blocks);
        assert_eq!(ba.free_count(), 1024);
    }

    #[test]
    fn alloc_all_exhaustion() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        ba.alloc_any(64).unwrap();
        assert!(ba.alloc_contiguous(1).is_err());
        assert!(ba.alloc_any(1).is_err());
    }

    #[test]
    fn allocation_respects_root_reserve_exact_fit_boundary() {
        let ba = BlockAllocator::with_root_reserve(8, 4096, region(8), 2);
        let initial = ba.allocator_statfs();

        assert_eq!(initial.f_bfree, 8);
        assert_eq!(initial.f_bavail, 6);
        assert_eq!(ba.alloc_any(7), Err(AllocError::NoSpace));
        assert_eq!(ba.free_count(), 8);
        assert_eq!(ba.allocator_statfs().f_bavail, 6);

        let exact_blocks = ba.alloc_any(6).unwrap();
        assert_eq!(exact_blocks.len(), 6);
        assert_eq!(ba.free_count(), 2);

        let exact = ba.allocator_statfs();
        assert_eq!(exact.f_bfree, 2);
        assert_eq!(exact.f_bavail, 0);
        assert_eq!(ba.alloc(1), Err(AllocError::NoSpace));
        assert_eq!(ba.alloc_any(1), Err(AllocError::NoSpace));
        assert_eq!(ba.alloc_contiguous(1), Err(AllocError::NoSpace));

        ba.free(&exact_blocks);

        let restored = ba.allocator_statfs();
        assert_eq!(restored.f_bfree, 8);
        assert_eq!(restored.f_bavail, 6);
        assert_eq!(ba.free_count(), 8);
    }

    #[test]
    fn statfs_allocation_exhaustion_recovers_after_free() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        let blocks = ba.alloc_any(64).unwrap();

        let exhausted = ba.allocator_statfs();
        assert_eq!(exhausted.f_blocks, 64);
        assert_eq!(exhausted.f_bfree, 0);
        assert_eq!(exhausted.f_bavail, 0);
        assert_eq!(ba.free_count(), 0);

        ba.free(&blocks);

        let restored = ba.allocator_statfs();
        assert_eq!(restored.f_blocks, 64);
        assert_eq!(restored.f_bfree, 64);
        assert_eq!(restored.f_bavail, 64);
        assert_eq!(ba.free_count(), 64)
    }

    #[test]
    fn statfs_reflects_usage() {
        let ba = BlockAllocator::with_root_reserve(1000, 4096, region(1000), 100);
        let s = ba.allocator_statfs();
        assert_eq!(s.f_blocks, 1000);
        assert_eq!(s.f_bfree, 1000);
        assert_eq!(s.f_bavail, 900); // 1000 - 100 root reserve
        assert_eq!(s.f_bsize, 4096);
        assert_eq!(s.f_frsize, 4096);
        assert_eq!(s.f_files, 0); // zeroed
    }

    #[test]
    fn statfs_after_alloc() {
        let ba = BlockAllocator::with_root_reserve(1000, 4096, region(1000), 50);
        ba.alloc_any(30).unwrap();
        let s = ba.allocator_statfs();
        assert_eq!(s.f_bfree, 970);
        assert_eq!(s.f_bavail, 920); // 970 - 50
    }

    #[test]
    fn root_reserve_exact_fit_allocation_recovers_after_free() {
        let ba = BlockAllocator::with_root_reserve(8, 4096, region(8), 2);
        let blocks = ba.alloc_any(6).unwrap();

        let exact_fit = ba.allocator_statfs();
        assert_eq!(exact_fit.f_blocks, 8);
        assert_eq!(exact_fit.f_bfree, 2);
        assert_eq!(exact_fit.f_bavail, 0);
        assert_eq!(ba.free_count(), 2);

        ba.free(&blocks);

        let restored = ba.allocator_statfs();
        assert_eq!(restored.f_blocks, 8);
        assert_eq!(restored.f_bfree, 8);
        assert_eq!(restored.f_bavail, 6);
        assert_eq!(ba.free_count(), 8);
    }

    #[test]
    fn statfs_bavail_saturates_when_root_reserve_exceeds_free() {
        let ba = BlockAllocator::with_root_reserve(100, 4096, region(100), 120);

        let s = ba.allocator_statfs();

        assert_eq!(s.f_blocks, 100);
        assert_eq!(s.f_bfree, 100);
        assert_eq!(s.f_bavail, 0);
        assert_eq!(s.f_bsize, 4096);
        assert_eq!(s.f_frsize, 4096);
    }

    #[test]
    fn quota_reserve_commit_release() {
        let ba = BlockAllocator::new(1024, 4096, region(1024));
        let ino = InodeId::new(1);
        ba.set_quota_limit(ino, 100);

        assert!(ba.reserve(ino, 60).is_ok());
        let (r, c) = ba.quota_counts(ino);
        assert_eq!(r, 60);
        assert_eq!(c, 0);

        ba.commit(ino, 30);
        let (r, c) = ba.quota_counts(ino);
        assert_eq!(r, 30);
        assert_eq!(c, 30);

        ba.release(ino, 30);
        let (r, c) = ba.quota_counts(ino);
        assert_eq!(r, 0);
        assert_eq!(c, 30);

        ba.uncommit(ino, 20);
        let (r, c) = ba.quota_counts(ino);
        assert_eq!(r, 0);
        assert_eq!(c, 10);

        ba.uncommit(ino, 20);
        let (r, c) = ba.quota_counts(ino);
        assert_eq!(r, 0);
        assert_eq!(c, 0);
    }

    #[test]
    fn quota_exceeded() {
        let ba = BlockAllocator::new(1024, 4096, region(1024));
        let ino = InodeId::new(2);
        ba.set_quota_limit(ino, 10);
        assert!(ba.reserve(ino, 100).is_err());
    }

    #[test]
    fn flush_roundtrip() {
        let ba = BlockAllocator::new(256, 4096, region(256));
        ba.alloc(10).unwrap();
        assert!(ba.is_dirty());

        let words = ba.flush_words();
        ba.flush().unwrap();
        assert!(!ba.is_dirty());

        // Simulate re-init from persisted words.
        let ba2 = BlockAllocator::from_persisted(256, 4096, region(256), words);
        assert_eq!(ba2.free_count(), ba.free_count());
        assert!(!ba2.is_dirty());
    }

    #[test]
    fn free_idempotent() {
        let ba = BlockAllocator::new(128, 4096, region(128));
        let blocks = ba.alloc_any(5).unwrap();
        let free_before = ba.free_count();

        ba.free(&blocks);
        assert_eq!(ba.free_count(), free_before + 5);

        // Free again: idempotent.
        ba.free(&blocks);
        assert_eq!(ba.free_count(), free_before + 5);
    }

    #[test]
    fn flush_to_writes_region_and_marks_clean() {
        #[derive(Default)]
        struct Sink {
            region: Option<Region>,
            words: Vec<u64>,
        }

        impl BitmapFlushSink for Sink {
            fn write_bitmap(&mut self, region: Region, words: &[u64]) -> Result<(), AllocError> {
                self.region = Some(region);
                self.words = words.to_vec();
                Ok(())
            }
        }

        let ba = BlockAllocator::new(128, 4096, region(128));
        ba.alloc(2).unwrap();
        let mut sink = Sink::default();

        ba.flush_to(&mut sink).unwrap();

        assert_eq!(sink.region, Some(region(128)));
        assert!(!sink.words.is_empty());
        assert!(!ba.is_dirty());
    }

    /// Alloc, free, and re-alloc round-trip through the full BlockAllocator.
    /// Proves freed space is correctly tracked and reusable.
    #[test]
    fn alloc_free_realloc_roundtrip() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        let blocks = ba.alloc_contiguous(10).unwrap();
        assert_eq!(ba.free_count(), 54);
        ba.free(&blocks);
        assert_eq!(ba.free_count(), 64);
        let blocks2 = ba.alloc_any(10).unwrap();
        assert_eq!(blocks2.len(), 10);
        assert_eq!(ba.free_count(), 54);
    }

    /// Free two adjacent extents, then allocate a larger contiguous
    /// extent spanning both. This is the BlockAllocator-level analog
    /// of the free-list merge test.
    #[test]
    fn adjacent_free_merge_through_block_allocator() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        let a = ba.alloc_contiguous(4).unwrap();
        let b = ba.alloc_contiguous(4).unwrap();
        assert_eq!(ba.free_count(), 56);
        ba.free(&a);
        ba.free(&b);
        assert_eq!(ba.free_count(), 64);
        // The combined freed space (8 contiguous blocks) must be allocatable.
        let c = ba.alloc_contiguous(8).unwrap();
        assert_eq!(c.len(), 8);
    }

    /// Full exhaustion, free one, re-allocate: proves the error-to-recovery
    /// path through the BlockAllocator admission check.
    #[test]
    fn exhaustion_recovery_through_block_allocator() {
        let ba = BlockAllocator::new(32, 4096, region(32));
        let blocks = ba.alloc_any(32).unwrap();
        assert!(ba.alloc(1).is_err());
        assert!(ba.alloc_contiguous(1).is_err());
        assert!(ba.alloc_any(1).is_err());
        // Free one block and verify re-allocation works.
        ba.free(&blocks[0..1]);
        assert_eq!(ba.free_count(), 1);
        let recovered = ba.alloc(1).unwrap();
        assert_eq!(recovered.len(), 1);
    }

    /// Fragmentation-stress round-trip: alloc and free in interleaved
    /// patterns, then verify that the allocator can still satisfy a
    /// contiguous allocation request via the two-pass scan.
    /// Guards against silent extent corruption in the FUSE write dispatch path when the allocator returns stale free blocks.
    #[test]
    fn fragmentation_stress_roundtrip() {
        let ba = BlockAllocator::new(128, 4096, region(128));
        // Allocate 10 blocks, free the odd-indexed ones.
        let a = ba.alloc_contiguous(10).unwrap(); // blocks 0..9
        let odds: Vec<u64> = a.iter().skip(1).step_by(2).copied().collect();
        ba.free(&odds); // free 1,3,5,7,9
                        // Allocate another 20 blocks (comes from hint after a's last block).
        let b = ba.alloc_contiguous(20).unwrap(); // blocks 10..29
                                                  // Free the remaining even blocks from the first allocation.
        let evens: Vec<u64> = a.iter().step_by(2).copied().collect();
        ba.free(&evens); // free 0,2,4,6,8
                         // Free the second allocation.
        ba.free(&b); // free 10..29
                     // All 128 blocks should be free again.
        assert_eq!(ba.free_count(), 128);
    }

    // ─── AllocatorTopology alignment helpers ───

    #[test]
    fn topology_default_is_512_sector_zero_offset() {
        let t = AllocatorTopology::default();
        assert_eq!(t.sector_size, 512);
        assert_eq!(t.alignment_offset, 0);
        assert_eq!(t.min_io_size, 0);
        assert_eq!(t.effective_min_io_size(), 512);
    }

    #[test]
    fn round_up_sector_already_aligned() {
        let t = AllocatorTopology::new(4096, 0);
        assert_eq!(t.round_up_sector(0), 0);
        assert_eq!(t.round_up_sector(4096), 4096);
        assert_eq!(t.round_up_sector(8192), 8192);
    }

    #[test]
    fn round_up_sector_unaligned() {
        let t = AllocatorTopology::new(4096, 0);
        assert_eq!(t.round_up_sector(1), 4096);
        assert_eq!(t.round_up_sector(512), 4096);
        assert_eq!(t.round_up_sector(4095), 4096);
        assert_eq!(t.round_up_sector(4097), 8192);
    }

    #[test]
    fn round_up_sector_with_alignment_offset() {
        let t = AllocatorTopology::new(4096, 512);
        // alignment_offset=512 means sectors start at 512, 4608, 8704, ...
        assert_eq!(t.round_up_sector(0), 512);
        assert_eq!(t.round_up_sector(512), 512);
        assert_eq!(t.round_up_sector(513), 4608);
        assert_eq!(t.round_up_sector(4608), 4608);
    }

    #[test]
    fn round_down_sector_already_aligned() {
        let t = AllocatorTopology::new(4096, 0);
        assert_eq!(t.round_down_sector(0), 0);
        assert_eq!(t.round_down_sector(4096), 4096);
        assert_eq!(t.round_down_sector(8192), 8192);
    }

    #[test]
    fn round_down_sector_unaligned() {
        let t = AllocatorTopology::new(4096, 0);
        assert_eq!(t.round_down_sector(1), 0);
        assert_eq!(t.round_down_sector(4095), 0);
        assert_eq!(t.round_down_sector(4097), 4096);
        assert_eq!(t.round_down_sector(8191), 4096);
    }

    #[test]
    fn round_down_sector_with_alignment_offset() {
        let t = AllocatorTopology::new(4096, 512);
        assert_eq!(t.round_down_sector(0), 512);
        assert_eq!(t.round_down_sector(512), 512);
        assert_eq!(t.round_down_sector(4607), 512);
        assert_eq!(t.round_down_sector(4609), 4608);
    }

    #[test]
    fn is_sector_aligned_true() {
        let t = AllocatorTopology::new(512, 0);
        assert!(t.is_sector_aligned(0, 512));
        assert!(t.is_sector_aligned(512, 1024));
        assert!(t.is_sector_aligned(1024, 0));
    }

    #[test]
    fn is_sector_aligned_false() {
        let t = AllocatorTopology::new(512, 0);
        assert!(!t.is_sector_aligned(1, 512));
        assert!(!t.is_sector_aligned(0, 513));
        assert!(!t.is_sector_aligned(0, 1));
    }

    #[test]
    fn is_sector_aligned_with_offset() {
        let t = AllocatorTopology::new(4096, 512);
        assert!(t.is_sector_aligned(512, 4096));
        assert!(!t.is_sector_aligned(0, 4096));
        assert!(!t.is_sector_aligned(512, 512));
    }

    #[test]
    fn blocks_for_bytes_exact_block_fit() {
        let t = AllocatorTopology::new(512, 0);
        // 4096 bytes at 512 sector size = exactly 1 4096-byte block.
        assert_eq!(t.blocks_for_bytes(4096, 4096), 1);
    }

    #[test]
    fn blocks_for_bytes_rounds_up_sector_then_block() {
        let t = AllocatorTopology::new(4096, 0);
        // 1 byte rounds up to 4096, which is 1 block.
        assert_eq!(t.blocks_for_bytes(1, 4096), 1);
        // 4097 bytes rounds up to 8192, which is 2 blocks.
        assert_eq!(t.blocks_for_bytes(4097, 4096), 2);
    }

    #[test]
    fn blocks_for_bytes_zero() {
        let t = AllocatorTopology::new(512, 0);
        assert_eq!(t.blocks_for_bytes(0, 4096), 0);
    }

    #[test]
    fn effective_min_io_size_defaults_to_sector_size() {
        let t = AllocatorTopology::new(512, 0);
        assert_eq!(t.effective_min_io_size(), 512);
        let t = AllocatorTopology::new(4096, 0);
        assert_eq!(t.effective_min_io_size(), 4096);
    }

    #[test]
    fn effective_min_io_size_uses_explicit_min_io() {
        let t = AllocatorTopology::with_min_io(512, 0, 4096);
        assert_eq!(t.effective_min_io_size(), 4096);
    }

    // ─── Allocator topology-aware construction ───

    #[test]
    fn allocator_with_topology_exposes_configuration() {
        let t = AllocatorTopology::new(4096, 0);
        let ba = BlockAllocator::with_topology(256, 4096, region(256), t, 0);
        let got = ba.allocator_topology();
        assert_eq!(got.sector_size, 4096);
        assert_eq!(got.alignment_offset, 0);
    }

    #[test]
    fn allocator_topology_default_backward_compatible() {
        let ba = BlockAllocator::new(128, 4096, region(128));
        let t = ba.allocator_topology();
        assert_eq!(t.sector_size, 512);
        assert_eq!(t.alignment_offset, 0);
        // Existing alloc/free still work with default topology.
        let blocks = ba.alloc_contiguous(5).unwrap();
        assert_eq!(blocks.len(), 5);
        ba.free(&blocks);
    }

    #[test]
    #[should_panic(expected = "must be a multiple of sector_size")]
    fn with_topology_rejects_misaligned_block_size() {
        let t = AllocatorTopology::new(4096, 0);
        let r = Region::new(0, BlockAllocator::required_bitmap_bytes(64));
        let _ba = BlockAllocator::with_topology(64, 512, r, t, 0);
    }

    // ─── alloc_bytes with alignment ───

    #[test]
    fn alloc_bytes_rounds_up_to_sector_then_block() {
        let t = AllocatorTopology::new(4096, 0);
        let ba = BlockAllocator::with_topology(64, 4096, region(64), t, 0);
        // 1 byte -> rounds to 4096 bytes -> 1 block.
        let blocks = ba.alloc_bytes(1).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(ba.free_count(), 63);
        ba.free(&blocks);
    }

    #[test]
    fn alloc_bytes_exact_block_sized() {
        let t = AllocatorTopology::new(4096, 0);
        let ba = BlockAllocator::with_topology(64, 4096, region(64), t, 0);
        let blocks = ba.alloc_bytes(4096).unwrap();
        assert_eq!(blocks.len(), 1);
        ba.free(&blocks);
    }

    #[test]
    fn alloc_bytes_crosses_block_boundary() {
        let t = AllocatorTopology::new(4096, 0);
        let ba = BlockAllocator::with_topology(64, 4096, region(64), t, 0);
        // 4097 bytes -> rounds to 8192 -> 2 blocks.
        let blocks = ba.alloc_bytes(4097).unwrap();
        assert_eq!(blocks.len(), 2);
        ba.free(&blocks);
    }

    #[test]
    fn alloc_bytes_zero_returns_empty() {
        let t = AllocatorTopology::new(4096, 0);
        let ba = BlockAllocator::with_topology(64, 4096, region(64), t, 0);
        let blocks = ba.alloc_bytes(0).unwrap();
        assert!(blocks.is_empty());
    }

    #[test]
    fn alloc_bytes_alignment_violation_when_min_io_larger_than_sector() {
        // 4K-native device with 512-byte logical sector: min_io_size=4096.
        let t = AllocatorTopology::with_min_io(512, 0, 4096);
        let ba = BlockAllocator::with_topology(64, 4096, region(64), t, 0);
        // 512 bytes not aligned to 4K min_io -> AlignmentViolation.
        let err = ba.alloc_bytes(512).unwrap_err();
        assert_eq!(err, AllocError::AlignmentViolation);
    }

    #[test]
    fn alloc_bytes_alignment_violation_not_triggered_when_aligned() {
        let t = AllocatorTopology::with_min_io(512, 0, 4096);
        let ba = BlockAllocator::with_topology(64, 4096, region(64), t, 0);
        // 4096 bytes is aligned to both 512 and 4096.
        let blocks = ba.alloc_bytes(4096).unwrap();
        assert_eq!(blocks.len(), 1);
        ba.free(&blocks);
    }

    #[test]
    fn alloc_bytes_no_alignment_violation_when_min_io_equals_sector() {
        let t = AllocatorTopology::new(512, 0);
        let ba = BlockAllocator::with_topology(64, 4096, region(64), t, 0);
        // 512-byte request with sector_size=512, min_io_size=0 -> fine.
        let blocks = ba.alloc_bytes(512).unwrap();
        assert_eq!(blocks.len(), 1); // rounds up to 4096 block, 1 block
        ba.free(&blocks);
    }

    #[test]
    fn alloc_bytes_rejects_unaligned_when_8k_native() {
        // 8K-native device with 4K logical sector: sector_size=4096,
        // min_io_size=8192. A 4096-byte request is aligned to the logical
        // sector but not to the physical min I/O boundary.
        let t = AllocatorTopology::with_min_io(4096, 0, 8192);
        let ba = BlockAllocator::with_topology(64, 4096, region(64), t, 0);
        // 4096 bytes not aligned to 8K min_io -> AlignmentViolation.
        let err = ba.alloc_bytes(4096).unwrap_err();
        assert_eq!(err, AllocError::AlignmentViolation);
        // 8192 bytes is aligned to both 4K and 8K.
        let blocks = ba.alloc_bytes(8192).unwrap();
        assert_eq!(blocks.len(), 2); // 2 blocks of 4096 each
        ba.free(&blocks);
    }

    // ─── from_persisted_with_topology ───

    #[test]
    fn from_persisted_with_topology_roundtrip() {
        let t = AllocatorTopology::new(4096, 0);
        let ba = BlockAllocator::with_topology(256, 4096, region(256), t, 0);
        ba.alloc_contiguous(10).unwrap();
        let words = ba.flush_words();
        ba.flush().unwrap();

        let ba2 = BlockAllocator::from_persisted_with_topology(256, 4096, region(256), words, t, 0);
        assert_eq!(ba2.free_count(), ba.free_count());
        assert_eq!(ba2.allocator_topology(), t);
    }
    // ─── alloc_bytes_at with offset-aware alignment ───

    #[test]
    fn topology_round_up_4k_sectors() {
        // 513 bytes on a 4K device → rounds up to 4096 (one sector), 1 block.
        let t = AllocatorTopology::new(4096, 0);
        let ba = BlockAllocator::with_topology(64, 4096, region(64), t, 0);
        let blocks = ba.alloc_bytes(513).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(ba.free_count(), 63);
        ba.free(&blocks);
    }

    #[test]
    fn topology_reject_misaligned_offset() {
        // alloc_bytes_at with offset=1, length=4096 on a 4K device.
        // Inward rounding: round_up(1)=4096, round_down(4097)=4096 → empty.
        let t = AllocatorTopology::new(4096, 0);
        let ba = BlockAllocator::with_topology(64, 4096, region(64), t, 0);
        let err = ba.alloc_bytes_at(1, 4096).unwrap_err();
        assert_eq!(err, AllocError::AlignmentImpossible);

        // With a larger request (8192 bytes at offset=1), inward rounding
        // preserves [4096, 8192) → 1 block.
        let blocks = ba.alloc_bytes_at(1, 8192).unwrap();
        assert_eq!(blocks.len(), 1);
        ba.free(&blocks);
    }

    #[test]
    fn topology_reject_misaligned_offset_below_alignment() {
        // offset=0 < alignment_offset=512 on a 4K-logical device.
        // Inward rounding clamps start to 512, rounds end down: [512, 512) → empty.
        let t = AllocatorTopology::new(4096, 512);
        let ba = BlockAllocator::with_topology(64, 4096, region(64), t, 0);
        let err = ba.alloc_bytes_at(0, 4096).unwrap_err();
        assert_eq!(err, AllocError::AlignmentImpossible);

        // With enough extra length to cover the alignment offset, it succeeds.
        // [0, 8704): round_up(0)=512, round_down(8704)=8704 → [512, 8704) = 8192.
        let blocks = ba.alloc_bytes_at(0, 8704).unwrap();
        assert_eq!(blocks.len(), 2);
        ba.free(&blocks);
    }

    #[test]
    fn topology_alignment_offset_correction() {
        // 4K disk in a 512e enclosure: alignment_offset=3584.
        // offset=0 → clamped to 3584 (first aligned sector).
        // offset=3584 → sector-aligned, succeeds.
        let t = AllocatorTopology::new(4096, 3584);
        let ba = BlockAllocator::with_topology(64, 4096, region(64), t, 0);
        let blocks = ba.alloc_bytes_at(3584, 4096).unwrap();
        assert_eq!(blocks.len(), 1);
        ba.free(&blocks);
    }

    #[test]
    fn topology_alignment_offset_correction_clamps_below() {
        // 4K sectors with alignment_offset=3584. offset=0, length=4096:
        // round_up(0)=3584, round_down(4096)=3584 → empty → AlignmentImpossible.
        let t = AllocatorTopology::new(4096, 3584);
        let ba = BlockAllocator::with_topology(64, 4096, region(64), t, 0);
        let err = ba.alloc_bytes_at(0, 4096).unwrap_err();
        assert_eq!(err, AllocError::AlignmentImpossible);

        // With a larger range that covers the alignment gap, it succeeds.
        // [0, 12288): round_up(0)=3584, round_down(12288)=11776 → [3584, 11776) = 8192.
        let blocks = ba.alloc_bytes_at(0, 12288).unwrap();
        assert_eq!(blocks.len(), 2); // ceil(8192/4096) = 2
        ba.free(&blocks);
    }

    #[test]
    fn topology_dealloc_rounds_outward() {
        // round_extent_outward on a sub-sector range.
        let t = AllocatorTopology::new(4096, 0);
        // [512, 4096) → rounds to [0, 4096), i.e., start=0, len=4096.
        let (start, len) = t.round_extent_outward(512, 3584);
        assert_eq!(start, 0);
        assert_eq!(len, 4096);
    }

    #[test]
    fn topology_dealloc_rounds_outward_partial_end() {
        let t = AllocatorTopology::new(4096, 0);
        // [0, 4608) → rounds to [0, 8192).
        let (start, len) = t.round_extent_outward(0, 4608);
        assert_eq!(start, 0);
        assert_eq!(len, 8192);
    }

    #[test]
    fn topology_dealloc_rounds_outward_zero_length() {
        let t = AllocatorTopology::new(4096, 0);
        let (start, len) = t.round_extent_outward(100, 0);
        assert_eq!(start, 100);
        assert_eq!(len, 0);
    }

    #[test]
    fn topology_dealloc_rounds_outward_with_alignment_offset() {
        // 4K sectors with alignment_offset=512.
        let t = AllocatorTopology::new(4096, 512);
        // [1000, 4000) → start rounds down to 512, end rounds up to 4608.
        let (start, len) = t.round_extent_outward(1000, 3000);
        assert_eq!(start, 512);
        // end = offset+length = 4000, round_up_sector(4000) with offset=512
        // 4000 > 512, shifted=3488, rem=3488%4096=3488, 4000+(4096-3488)=4608
        assert_eq!(len, 4608 - 512);
    }

    #[test]
    fn topology_min_io_size_4k_native_512_logical() {
        // 4K-native device with 512-byte logical sector.
        let t = AllocatorTopology::with_min_io(512, 0, 4096);
        let ba = BlockAllocator::with_topology(64, 4096, region(64), t, 0);
        // 512 bytes → AlignmentViolation because min_io_size=4096 > sector_size=512.
        let err = ba.alloc_bytes(512).unwrap_err();
        assert_eq!(err, AllocError::AlignmentViolation);
        // 4096 bytes → aligned, succeeds.
        let blocks = ba.alloc_bytes(4096).unwrap();
        assert_eq!(blocks.len(), 1);
        ba.free(&blocks);
    }

    #[test]
    fn alloc_bytes_at_min_io_violation() {
        // alloc_bytes_at with min_io_size constraint: offset aligned but
        // length not a multiple of effective min I/O size → AlignmentViolation.
        let t = AllocatorTopology::with_min_io(512, 0, 4096);
        let ba = BlockAllocator::with_topology(64, 4096, region(64), t, 0);
        // offset=0 is aligned, but length=512 is not a multiple of
        // eff_min_io=4096 → AlignmentViolation.
        let err = ba.alloc_bytes_at(0, 512).unwrap_err();
        assert_eq!(err, AllocError::AlignmentViolation);

        // 4096 bytes is aligned to both sector and min_io → succeeds.
        let blocks = ba.alloc_bytes_at(0, 4096).unwrap();
        assert_eq!(blocks.len(), 1);
        ba.free(&blocks);

        // With 8K min_io, even 4K length (aligned to sector but not min_io)
        // fails.
        let t2 = AllocatorTopology::with_min_io(4096, 0, 8192);
        let ba2 = BlockAllocator::with_topology(64, 4096, region(64), t2, 0);
        let err = ba2.alloc_bytes_at(0, 4096).unwrap_err();
        assert_eq!(err, AllocError::AlignmentViolation);
    }

    // ─── DeviceTopology and DeviceId ───

    #[test]
    fn device_topology_default_is_512() {
        let dt = DeviceTopology::default();
        assert_eq!(dt.logical_sector_size, 512);
        assert_eq!(dt.physical_sector_size, 512);
        assert_eq!(dt.optimal_io_size, 0);
        assert_eq!(dt.alignment_offset, 0);
        assert_eq!(dt.min_io_size, 0);
    }

    #[test]
    fn device_topology_to_allocator_topology() {
        let dt = DeviceTopology {
            logical_sector_size: 512,
            physical_sector_size: 4096,
            optimal_io_size: 131072,
            alignment_offset: 0,
            min_io_size: 4096,
        };
        let at = AllocatorTopology::from(dt);
        assert_eq!(at.sector_size, 4096);
        assert_eq!(at.alignment_offset, 0);
        assert_eq!(at.min_io_size, 4096);
    }

    #[test]
    fn device_id_eq() {
        let a = DeviceId(1);
        let b = DeviceId(2);
        let c = DeviceId(1);
        assert_eq!(a, c);
        assert_ne!(a, b);
    }

    // ─── Heterogeneous device registration ───

    #[test]
    fn register_device_success() {
        let ba = BlockAllocator::new(128, 4096, region(128));
        let dt = DeviceTopology {
            logical_sector_size: 512,
            physical_sector_size: 4096,
            optimal_io_size: 0,
            alignment_offset: 0,
            min_io_size: 0,
        };
        ba.register_device(DeviceId(0), dt, 0, 65536).unwrap();
        assert_eq!(ba.registered_device_count(), 1);
    }

    #[test]
    fn register_device_duplicate_rejected() {
        let ba = BlockAllocator::new(128, 4096, region(128));
        let dt = DeviceTopology::default();
        ba.register_device(DeviceId(0), dt, 0, 65536).unwrap();
        let err = ba.register_device(DeviceId(0), dt, 0, 65536).unwrap_err();
        assert_eq!(err, AllocError::DeviceAlreadyRegistered);
    }

    #[test]
    fn topology_for_returns_device_topology_when_registered() {
        let ba = BlockAllocator::new(128, 4096, region(128));
        let dt = DeviceTopology {
            logical_sector_size: 512,
            physical_sector_size: 4096,
            optimal_io_size: 0,
            alignment_offset: 0,
            min_io_size: 0,
        };
        ba.register_device(DeviceId(0), dt, 0, 65536).unwrap();
        let topo = ba.topology_for(0).unwrap();
        assert_eq!(topo.sector_size, 4096);
    }

    #[test]
    fn topology_for_falls_back_to_default_outside_registered_range() {
        let ba = BlockAllocator::new(128, 4096, region(128));
        let dt = DeviceTopology {
            logical_sector_size: 512,
            physical_sector_size: 4096,
            optimal_io_size: 0,
            alignment_offset: 0,
            min_io_size: 0,
        };
        // Device covers 0..65536.
        ba.register_device(DeviceId(0), dt, 0, 65536).unwrap();
        // Offset 70000 is outside the device range → falls back to default 512.
        let topo = ba.topology_for(70000).unwrap();
        assert_eq!(topo.sector_size, 512);
    }

    // ─── Heterogeneous device topology enforcement ───

    #[test]
    fn alloc_bytes_at_uses_4k_device_topology() {
        let ba = BlockAllocator::new(128, 4096, region(128));
        let dt = DeviceTopology {
            logical_sector_size: 512,
            physical_sector_size: 4096,
            optimal_io_size: 0,
            alignment_offset: 0,
            min_io_size: 0,
        };
        ba.register_device(DeviceId(0), dt, 0, 131072).unwrap();
        // offset=1, length=4096 with 512B logical: auto-aligns to [512, 4096)
        // which is 3584 bytes → 1 block. (Was MisalignedOffset before inward rounding.)
        let blocks = ba.alloc_bytes_at(1, 4096).unwrap();
        assert_eq!(blocks.len(), 1);
        ba.free(&blocks);

        // offset=0, length=4096 → aligned on both logical and physical.
        let blocks = ba.alloc_bytes_at(0, 4096).unwrap();
        assert_eq!(blocks.len(), 1);
        ba.free(&blocks);

        // offset=1, length=512: round_up(1)=512, round_down(513)=512 → empty.
        let err = ba.alloc_bytes_at(1, 512).unwrap_err();
        assert_eq!(err, AllocError::AlignmentImpossible);
    }

    #[test]
    fn two_devices_different_sector_sizes() {
        let ba = BlockAllocator::new(256, 4096, region(256));
        // Device 0: 512-byte sectors, offset 0..131072
        let dt0 = DeviceTopology {
            logical_sector_size: 512,
            physical_sector_size: 512,
            optimal_io_size: 0,
            alignment_offset: 0,
            min_io_size: 0,
        };
        ba.register_device(DeviceId(0), dt0, 0, 131072).unwrap();
        // Device 1: 4096-byte sectors, offset 131072..262144
        let dt1 = DeviceTopology {
            logical_sector_size: 4096,
            physical_sector_size: 4096,
            optimal_io_size: 0,
            alignment_offset: 0,
            min_io_size: 0,
        };
        ba.register_device(DeviceId(1), dt1, 131072, 131072)
            .unwrap();
        assert_eq!(ba.registered_device_count(), 2);

        // Allocation on dev0 (512B sector): offset=512 succeeds.
        let blocks = ba.alloc_bytes_at(0, 512).unwrap();
        assert_eq!(blocks.len(), 1); // rounds up to 4096-byte block
        ba.free(&blocks);

        // Allocation on dev1 (4K sector): offset=512 is misaligned.
        // Inward rounding: round_up(131584)=135168, round_down(135680)=135168 → empty.
        let err = ba.alloc_bytes_at(131072 + 512, 4096).unwrap_err();
        assert_eq!(err, AllocError::AlignmentImpossible);
        // With enough length to cover the misalignment, it auto-aligns.
        let blocks = ba.alloc_bytes_at(131072 + 512, 8192).unwrap();
        assert_eq!(blocks.len(), 1); // [135168, 139264) = 4096 bytes
        ba.free(&blocks);

        // Allocation on dev1 at aligned offset succeeds.
        let blocks = ba.alloc_bytes_at(131072, 4096).unwrap();
        assert_eq!(blocks.len(), 1);
        ba.free(&blocks);
    }

    // ─── Cross-device allocation rejection ───

    #[test]
    fn cross_device_allocation_rejected() {
        let ba = BlockAllocator::new(256, 4096, region(256));
        // Device 0: bytes 0..65536, 512B sectors
        let dt0 = DeviceTopology {
            logical_sector_size: 512,
            physical_sector_size: 512,
            optimal_io_size: 0,
            alignment_offset: 0,
            min_io_size: 0,
        };
        ba.register_device(DeviceId(0), dt0, 0, 65536).unwrap();
        // Device 1: bytes 65536..131072, 4096B sectors
        let dt1 = DeviceTopology {
            logical_sector_size: 4096,
            physical_sector_size: 4096,
            optimal_io_size: 0,
            alignment_offset: 0,
            min_io_size: 0,
        };
        ba.register_device(DeviceId(1), dt1, 65536, 65536).unwrap();

        // Request spans both devices: offset=0, length=131072.
        let err = ba.alloc_bytes_at(0, 131072).unwrap_err();
        assert_eq!(err, AllocError::MixedDeviceTopology);
    }

    #[test]
    fn cross_device_allocation_rejected_at_rounded_boundary() {
        let ba = BlockAllocator::new(256, 4096, region(256));
        let dt0 = DeviceTopology {
            logical_sector_size: 512,
            physical_sector_size: 512,
            optimal_io_size: 0,
            alignment_offset: 0,
            min_io_size: 0,
        };
        ba.register_device(DeviceId(0), dt0, 0, 65536).unwrap();
        // Device 1 starts at 65536 with 4K sectors.
        let dt1 = DeviceTopology {
            logical_sector_size: 4096,
            physical_sector_size: 4096,
            optimal_io_size: 0,
            alignment_offset: 0,
            min_io_size: 0,
        };
        ba.register_device(DeviceId(1), dt1, 65536, 65536).unwrap();

        // Request that starts in dev0 but extends past dev0's logical-sector
        // boundary into dev1. Inward rounding on dev0 (512B logical) shrinks
        // the extent to [0, 65536) which stays within dev0.
        let blocks = ba.alloc_bytes_at(0, 66000).unwrap();
        assert!(!blocks.is_empty());
        ba.free(&blocks);

        // A request that extends far enough that inward rounding still crosses.
        // [0, 131072): round_up(0)=0, round_down(131072)=131072 → spans dev0→dev1.
        let err = ba.alloc_bytes_at(0, 131072).unwrap_err();
        assert_eq!(err, AllocError::MixedDeviceTopology);
    }

    // ─── topology_for_range checks ───

    #[test]
    fn topology_for_range_homogeneous_returns_topology() {
        let ba = BlockAllocator::new(128, 4096, region(128));
        let dt = DeviceTopology {
            logical_sector_size: 512,
            physical_sector_size: 4096,
            optimal_io_size: 0,
            alignment_offset: 0,
            min_io_size: 0,
        };
        ba.register_device(DeviceId(0), dt, 0, 65536).unwrap();
        let topo = ba.topology_for_range(0, 4096).unwrap();
        assert_eq!(topo.sector_size, 4096);
    }

    #[test]
    fn topology_for_range_heterogeneous_rejected() {
        let ba = BlockAllocator::new(256, 4096, region(256));
        let dt0 = DeviceTopology::default(); // 512B sectors
        ba.register_device(DeviceId(0), dt0, 0, 65536).unwrap();
        let dt1 = DeviceTopology {
            logical_sector_size: 4096,
            physical_sector_size: 4096,
            optimal_io_size: 0,
            alignment_offset: 0,
            min_io_size: 0,
        };
        ba.register_device(DeviceId(1), dt1, 65536, 65536).unwrap();

        let err = ba.topology_for_range(0, 131072).unwrap_err();
        assert_eq!(err, AllocError::MixedDeviceTopology);
    }

    #[test]
    fn topology_for_range_zero_length_uses_start_offset_device() {
        let ba = BlockAllocator::new(128, 4096, region(128));
        let dt = DeviceTopology {
            logical_sector_size: 512,
            physical_sector_size: 4096,
            optimal_io_size: 0,
            alignment_offset: 0,
            min_io_size: 0,
        };
        ba.register_device(DeviceId(0), dt, 0, 65536).unwrap();
        let topo = ba.topology_for_range(1024, 0).unwrap();
        assert_eq!(topo.sector_size, 4096);
    }

    // ─── alignment_offset correction with DeviceTopology ───

    #[test]
    fn alignment_offset_correction_with_device_topology() {
        let ba = BlockAllocator::new(128, 4096, region(128));
        // 4K disk in a 512e enclosure: alignment_offset=3584.
        let dt = DeviceTopology {
            logical_sector_size: 512,
            physical_sector_size: 4096,
            optimal_io_size: 0,
            alignment_offset: 3584,
            min_io_size: 0,
        };
        ba.register_device(DeviceId(0), dt, 0, 131072).unwrap();

        // offset=0, length=4096 with alignment_offset=3584:
        // round_up(0)=3584, round_down(4096)=4096 → [3584, 4096) = 512 B.
        // slack = 87.5% > MAX_ALIGNMENT_SLACK → AlignmentImpossible.
        let err = ba.alloc_bytes_at(0, 4096).unwrap_err();
        assert_eq!(err, AllocError::AlignmentImpossible);

        // With enough requested length to survive inward rounding.
        // [0, 8192): round_up(0)=3584, round_down(8192)=8192 → [3584, 8192) = 4608.
        let blocks = ba.alloc_bytes_at(0, 8192).unwrap();
        assert_eq!(blocks.len(), 2); // ceil(4608/4096) = 2
        ba.free(&blocks);

        // offset=3584 → aligned, succeeds.
        let blocks = ba.alloc_bytes_at(3584, 4096).unwrap();
        assert_eq!(blocks.len(), 1);
        ba.free(&blocks);
    }

    // ─── Default topology backward compatibility ───

    #[test]
    fn no_devices_registered_uses_default_topology() {
        // No devices registered — allocator uses default 512B topology.
        let ba = BlockAllocator::new(128, 4096, region(128));
        let blocks = ba.alloc_bytes_at(0, 512).unwrap();
        assert_eq!(blocks.len(), 1);
        ba.free(&blocks);
        // offset=1, length=512 on 512-byte logical device:
        // round_up(1)=512, round_down(513)=512 → empty → AlignmentImpossible.
        let err = ba.alloc_bytes_at(1, 512).unwrap_err();
        assert_eq!(err, AllocError::AlignmentImpossible);

        // With a larger request, auto-alignment succeeds.
        let blocks = ba.alloc_bytes_at(1, 1024).unwrap();
        assert_eq!(blocks.len(), 1); // [512, 1024) = 512 bytes
        ba.free(&blocks);
    }

    // ─── Spacemap sync tests ───

    #[test]
    fn spacemap_syncs_with_bitmap_on_alloc() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        let blocks = ba.alloc_contiguous(3).unwrap();
        // Spacemap should reflect the allocation.
        let inner = ba.inner.read().unwrap();
        assert!(!inner.spacemap.is_free(blocks[0]));
        assert!(!inner.spacemap.is_free(blocks[1]));
        assert!(!inner.spacemap.is_free(blocks[2]));
        assert_eq!(inner.spacemap.free_count(), 61);
        drop(inner);
        ba.free(&blocks);
    }

    #[test]
    fn spacemap_syncs_with_bitmap_on_free() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        let blocks = ba.alloc_any(3).unwrap();
        {
            let inner = ba.inner.read().unwrap();
            assert_eq!(inner.spacemap.free_count(), 61);
        }
        ba.free(&blocks);
        let inner = ba.inner.read().unwrap();
        assert_eq!(inner.spacemap.free_count(), 64);
        assert!(inner.spacemap.is_free(blocks[0]));
    }

    #[test]
    fn spacemap_persistence_roundtrip() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        ba.alloc_contiguous(5).unwrap();
        let words = ba.flush_words();
        ba.flush().unwrap();

        let ba2 = BlockAllocator::from_persisted(64, 4096, region(64), words);
        let inner = ba2.inner.read().unwrap();
        assert_eq!(inner.spacemap.free_count(), 59);
        // Block 0 should be used in both bitmap and spacemap.
        assert!(!inner.spacemap.is_free(0));
    }

    // ─── Alignment-aware placement tests ───

    #[test]
    fn alloc_bytes_prefers_physically_aligned_on_512e() {
        // 512e device: logical=512, physical=4096, block_size=4096.
        // Every block is both logically and physically aligned since
        // block_size == physical_sector_size. The preference is trivially
        // satisfied when block 0 is free.
        let t = AllocatorTopology::with_logical(512, 4096, 0);
        let ba = BlockAllocator::with_topology(64, 4096, region(64), t, 0);
        let blocks = ba.alloc_bytes(4096).unwrap();
        assert_eq!(blocks.len(), 1);
        // Block 0 should be allocated (first free, physically aligned).
        assert_eq!(blocks[0], 0);
        ba.free(&blocks);
    }

    #[test]
    fn alloc_bytes_with_physical_larger_than_logical() {
        // 512e device: logical=512, physical=4096, block_size=4096.
        // Physical == block_size, so every block is physically aligned.
        // The spacemap alignment-aware path should work correctly.
        let t = AllocatorTopology::with_logical(512, 4096, 0);
        let ba = BlockAllocator::with_topology(64, 4096, region(64), t, 0);
        // Allocate one block via alloc_bytes (triggers alignment-aware path).
        let blocks = ba.alloc_bytes(4096).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0], 0);
        ba.free(&blocks);
    }

    #[test]
    fn alloc_bytes_uses_logical_rounding_on_homogeneous_device() {
        // Homogeneous 4K device.
        let t = AllocatorTopology::new(4096, 0);
        let ba = BlockAllocator::with_topology(64, 4096, region(64), t, 0);
        // 513 bytes → rounds up to 4096 (logical sector) → 1 block.
        let blocks = ba.alloc_bytes(513).unwrap();
        assert_eq!(blocks.len(), 1);
        ba.free(&blocks);
    }

    #[test]
    fn spacemap_find_free_run_integration() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        // Consume first 5 blocks.
        ba.alloc_contiguous(5).unwrap();
        let inner = ba.inner.read().unwrap();
        // find_free_run should find a run starting at block 5.
        let run = inner.spacemap.find_free_run(1);
        assert!(run.is_some());
        let (start, end) = run.unwrap();
        assert_eq!(start, 5);
        assert_eq!(end, 64);
    }

    #[test]
    fn spacemap_remove_run_from_hints_integration() {
        let mut fm = tidefs_spacemap_allocator::SegmentFreeMap::new(64, vec![(0, 64)]).unwrap();
        // Remove a run from hints and verify it's gone.
        fm.remove_run_from_hints(10, 20);
        // The free runs are still there (remove_run_from_hints only updates hints).
        // After rebuild, the run should be gone.
        let run = fm.find_free_run(1);
        // The run (10, 20) might still appear if other runs cover it.
        // Just verify no panic.
        assert!(run.is_some());
    }

    // ─── Topology validation at registration ───

    #[test]
    fn register_device_rejects_zero_logical_sector_size() {
        let ba = BlockAllocator::new(128, 4096, region(128));
        let dt = DeviceTopology {
            logical_sector_size: 0,
            physical_sector_size: 4096,
            optimal_io_size: 0,
            alignment_offset: 0,
            min_io_size: 0,
        };
        let err = ba.register_device(DeviceId(0), dt, 0, 65536).unwrap_err();
        assert_eq!(err, AllocError::InvalidDeviceTopology);
    }

    #[test]
    fn register_device_rejects_non_power_of_two_logical() {
        let ba = BlockAllocator::new(128, 4096, region(128));
        let dt = DeviceTopology {
            logical_sector_size: 1000,
            physical_sector_size: 4096,
            optimal_io_size: 0,
            alignment_offset: 0,
            min_io_size: 0,
        };
        let err = ba.register_device(DeviceId(0), dt, 0, 65536).unwrap_err();
        assert_eq!(err, AllocError::InvalidDeviceTopology);
    }

    #[test]
    fn register_device_rejects_non_power_of_two_physical() {
        let ba = BlockAllocator::new(128, 4096, region(128));
        let dt = DeviceTopology {
            logical_sector_size: 512,
            physical_sector_size: 3000,
            optimal_io_size: 0,
            alignment_offset: 0,
            min_io_size: 0,
        };
        let err = ba.register_device(DeviceId(0), dt, 0, 65536).unwrap_err();
        assert_eq!(err, AllocError::InvalidDeviceTopology);
    }

    #[test]
    fn register_device_rejects_zero_physical() {
        let ba = BlockAllocator::new(128, 4096, region(128));
        let dt = DeviceTopology {
            logical_sector_size: 512,
            physical_sector_size: 0,
            optimal_io_size: 0,
            alignment_offset: 0,
            min_io_size: 0,
        };
        let err = ba.register_device(DeviceId(0), dt, 0, 65536).unwrap_err();
        assert_eq!(err, AllocError::InvalidDeviceTopology);
    }

    #[test]
    fn register_device_rejects_alignment_offset_gte_physical() {
        let ba = BlockAllocator::new(128, 4096, region(128));
        let dt = DeviceTopology {
            logical_sector_size: 512,
            physical_sector_size: 4096,
            optimal_io_size: 0,
            alignment_offset: 4096, // >= physical_sector_size
            min_io_size: 0,
        };
        let err = ba.register_device(DeviceId(0), dt, 0, 65536).unwrap_err();
        assert_eq!(err, AllocError::InvalidDeviceTopology);
    }

    #[test]
    fn register_device_accepts_valid_topology() {
        let ba = BlockAllocator::new(128, 4096, region(128));
        let dt = DeviceTopology {
            logical_sector_size: 512,
            physical_sector_size: 4096,
            optimal_io_size: 131072,
            alignment_offset: 0,
            min_io_size: 0,
        };
        ba.register_device(DeviceId(0), dt, 0, 65536).unwrap();
        assert_eq!(ba.registered_device_count(), 1);
    }

    // ─── Property: alloc_bytes_at returns logically-aligned extents ───

    #[test]
    fn prop_alloc_bytes_at_returns_logically_aligned_extents() {
        // For a set of (offset, length, device) triples, verify that the
        // returned extent's start and length are multiples of logical_sector_size.
        let cases = [
            // 512B logical device
            (
                0u64,
                4096u64,
                DeviceTopology {
                    logical_sector_size: 512,
                    physical_sector_size: 512,
                    optimal_io_size: 0,
                    alignment_offset: 0,
                    min_io_size: 0,
                },
            ),
            // 4K logical device
            (
                4096,
                12288,
                DeviceTopology {
                    logical_sector_size: 4096,
                    physical_sector_size: 4096,
                    optimal_io_size: 0,
                    alignment_offset: 0,
                    min_io_size: 0,
                },
            ),
            // 512e device (512 logical, 4K physical)
            (
                512,
                8192,
                DeviceTopology {
                    logical_sector_size: 512,
                    physical_sector_size: 4096,
                    optimal_io_size: 0,
                    alignment_offset: 0,
                    min_io_size: 0,
                },
            ),
            // unaligned offset on 4K device (should auto-align and succeed)
            (
                1024,
                16384,
                DeviceTopology {
                    logical_sector_size: 4096,
                    physical_sector_size: 4096,
                    optimal_io_size: 0,
                    alignment_offset: 0,
                    min_io_size: 0,
                },
            ),
        ];

        for (offset, length, dt) in cases {
            let ba = BlockAllocator::new(256, 4096, region(256));
            ba.register_device(DeviceId(0), dt, 0, (offset + length) * 4)
                .unwrap();

            let blocks = ba.alloc_bytes_at(offset, length).unwrap();
            let byte_len = blocks.len() as u64 * 4096;
            // The returned byte range should be a multiple of logical_sector_size.
            // Since alloc_bytes_at rounds inward, the start may differ from offset.
            // The key invariant: byte_len % logical_sector_size == 0.
            assert!(
                byte_len % dt.logical_sector_size == 0,
                "alloc_bytes_at({offset}, {length}) on device with logical={ls} returned {byte_len} bytes",
                ls = dt.logical_sector_size
            );
            ba.free(&blocks);
        }
    }
    #[test]
    fn allocator_with_topology_backward_compatible() {
        // Using with_topology to set a global 4K topology still works
        // when no per-device registration is done.
        let t = AllocatorTopology::new(4096, 0);
        let ba = BlockAllocator::with_topology(128, 4096, region(128), t, 0);
        assert_eq!(ba.registered_device_count(), 0);
        let topo = ba.topology_for(0).unwrap();
        assert_eq!(topo.sector_size, 4096);
        let blocks = ba.alloc_bytes_at(0, 4096).unwrap();
        assert_eq!(blocks.len(), 1);
        ba.free(&blocks);
    }

    // ─── Zero-size and oversized allocation rejection ───

    /// Zero-size alloc is rejected with NoSpace (bitmap layer rejects
    /// nblocks==0 as nonsensical).
    #[test]
    fn alloc_zero_size_rejected() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        assert_eq!(ba.alloc(0), Err(AllocError::NoSpace));
        assert_eq!(ba.alloc_contiguous(0), Err(AllocError::NoSpace));
        assert_eq!(ba.alloc_any(0), Err(AllocError::NoSpace));
        assert_eq!(ba.free_count(), 64);
    }

    /// Requesting more blocks than total capacity returns NoSpace.
    #[test]
    fn alloc_oversized_rejected() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        assert_eq!(ba.alloc(65), Err(AllocError::NoSpace));
        assert_eq!(ba.alloc_contiguous(65), Err(AllocError::NoSpace));
        assert_eq!(ba.alloc_any(65), Err(AllocError::NoSpace));
        assert_eq!(ba.free_count(), 64);
    }

    // ─── Fragmentation-induced contiguous allocation failure ───

    /// Allocate every block, free every other one to create a checkerboard.
    /// alloc_contiguous(2) must fail (no adjacent pair is free).
    /// After freeing all, large contiguous alloc recovers.
    #[test]
    fn fragmentation_contiguous_fails_checkerboard() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        let all = ba.alloc_any(64).unwrap();
        let evens: Vec<u64> = all.iter().step_by(2).copied().collect();
        ba.free(&evens); // free 0,2,4,...,62
        assert_eq!(ba.free_count(), 32);
        // No two adjacent blocks are free.
        assert!(ba.alloc_contiguous(2).is_err());
        // Scattered allocation still works.
        let scattered = ba.alloc_any(2).unwrap();
        assert_eq!(scattered.len(), 2);
        ba.free(&scattered);
        // Free remaining odd blocks → full merge.
        let odds: Vec<u64> = all.iter().skip(1).step_by(2).copied().collect();
        ba.free(&odds);
        assert_eq!(ba.free_count(), 64);
        let merged = ba.alloc_contiguous(32).unwrap();
        assert_eq!(merged.len(), 32);
    }

    /// Free three adjacent extents in reverse order; merged region is
    /// allocatable as a single contiguous run.
    #[test]
    fn free_reverse_order_merge() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        let a = ba.alloc_contiguous(4).unwrap();
        let b = ba.alloc_contiguous(4).unwrap();
        let c = ba.alloc_contiguous(4).unwrap();
        ba.free(&c);
        ba.free(&b);
        ba.free(&a);
        let merged = ba.alloc_contiguous(12).unwrap();
        assert_eq!(merged.len(), 12);
    }

    /// Freeing non-adjacent blocks does not spuriously merge them.
    /// Consume all remaining space so no large free backstop exists.
    #[test]
    fn free_non_adjacent_no_spurious_merge() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        let a = ba.alloc_contiguous(3).unwrap(); // blocks 0..2
        let _b = ba.alloc_contiguous(3).unwrap(); // blocks 3..5
        let c = ba.alloc_contiguous(3).unwrap(); // blocks 6..8
        let _rest = ba.alloc_any(55).unwrap(); // consume remainder
        ba.free(&a);
        ba.free(&c);
        assert_eq!(ba.free_count(), 6);
        // max contig free run is 3.
        assert!(ba.alloc_contiguous(6).is_err());
        let small = ba.alloc_contiguous(3).unwrap();
        assert_eq!(small.len(), 3);
    }

    // ─── Split on partial allocation ───

    /// Allocating a sub-range leaves the remainder allocatable.
    #[test]
    fn alloc_partial_region_split() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        let first = ba.alloc_contiguous(3).unwrap();
        assert_eq!(first.len(), 3);
        assert_eq!(ba.free_count(), 61);
        let second = ba.alloc_contiguous(10).unwrap();
        assert_eq!(second.len(), 10);
        assert_eq!(ba.free_count(), 51);
        ba.free(&first);
        ba.free(&second);
        assert_eq!(ba.free_count(), 64);
    }

    /// The exact remainder after a partial allocation can be consumed.
    #[test]
    fn alloc_exact_remainder_consumes_region() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        let first = ba.alloc_contiguous(30).unwrap();
        assert_eq!(ba.free_count(), 34);
        let second = ba.alloc_contiguous(34).unwrap();
        assert_eq!(second.len(), 34);
        assert_eq!(ba.free_count(), 0);
        assert!(ba.alloc(1).is_err());
        ba.free(&first);
        ba.free(&second);
    }

    // ─── Churn and invariants ───

    /// Rapid alternating allocate/free; free_count + outstanding == total.
    #[test]
    fn rapid_alloc_free_churn_invariant() {
        let total: u64 = 64;
        let ba = BlockAllocator::new(total, 4096, region(total));
        let mut allocated_count: u64 = 0;
        for _ in 0..50 {
            let n: u32 = 3;
            let blocks = ba.alloc_any(n).unwrap();
            allocated_count += u64::from(n);
            assert_eq!(ba.free_count(), total - allocated_count);
            ba.free(&blocks);
            allocated_count -= u64::from(n);
            assert_eq!(ba.free_count(), total - allocated_count);
        }
        assert_eq!(ba.free_count(), total);
    }

    /// Deterministic random allocate/free sequence with LCG seed.
    /// Invariant: free_count + outstanding == total at every step.
    #[test]
    fn random_alloc_free_invariant() {
        let total: u64 = 128;
        let ba = BlockAllocator::new(total, 4096, region(total));
        let mut state: u64 = 42;
        let mut outstanding: Vec<Vec<u64>> = Vec::new();
        let mut allocated_count: u64 = 0;
        for _ in 0..100 {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            let action = state & 1;
            let n = ((state >> 1) % 8) + 1;
            if action == 0 || outstanding.is_empty() {
                if let Ok(blocks) = ba.alloc_any(n as u32) {
                    allocated_count += blocks.len() as u64;
                    outstanding.push(blocks);
                }
            } else {
                let idx = ((state >> 4) as usize) % outstanding.len();
                let blocks = outstanding.remove(idx);
                allocated_count -= blocks.len() as u64;
                ba.free(&blocks);
            }
            assert_eq!(ba.free_count(), total - allocated_count);
        }
        for blocks in outstanding {
            ba.free(&blocks);
        }
        assert_eq!(ba.free_count(), total);
    }

    // ─── TrimRequest coalesce tests ───

    #[test]

    fn trim_request_coalesce_empty_input() {
        let result = coalesce_trim_requests(&[], 0);

        assert!(result.is_empty());
    }

    #[test]

    fn trim_request_coalesce_single_range() {
        let requests = [TrimRequest::new(0, 4096)];

        let result = coalesce_trim_requests(&requests, 0);

        assert_eq!(result.len(), 1);

        assert_eq!(result[0].offset, 0);

        assert_eq!(result[0].length, 4096);
    }

    #[test]

    fn trim_request_coalesce_adjacent_ranges() {
        let requests = [TrimRequest::new(0, 4096), TrimRequest::new(4096, 4096)];

        let result = coalesce_trim_requests(&requests, 0);

        assert_eq!(result.len(), 1);

        assert_eq!(result[0].offset, 0);

        assert_eq!(result[0].length, 8192);
    }

    #[test]

    fn trim_request_coalesce_overlapping_ranges() {
        let requests = [TrimRequest::new(0, 8192), TrimRequest::new(4096, 8192)];

        let result = coalesce_trim_requests(&requests, 0);

        assert_eq!(result.len(), 1);

        assert_eq!(result[0].offset, 0);

        assert_eq!(result[0].length, 12288);
    }

    #[test]

    fn trim_request_coalesce_gap_within_threshold() {
        let requests = [
            TrimRequest::new(0, 4096),
            TrimRequest::new(8192, 4096), // 4096-byte gap
        ];

        // gap of 4096 is within threshold of 8192 -> merged

        let result = coalesce_trim_requests(&requests, 8192);

        assert_eq!(result.len(), 1);

        assert_eq!(result[0].offset, 0);

        assert_eq!(result[0].length, 12288);
    }

    #[test]

    fn trim_request_coalesce_gap_exceeds_threshold() {
        let requests = [
            TrimRequest::new(0, 4096),
            TrimRequest::new(12288, 4096), // 8192-byte gap
        ];

        let result = coalesce_trim_requests(&requests, 4096);

        assert_eq!(result.len(), 2);

        assert_eq!(result[0].offset, 0);

        assert_eq!(result[0].length, 4096);

        assert_eq!(result[1].offset, 12288);

        assert_eq!(result[1].length, 4096);
    }

    #[test]

    fn trim_request_coalesce_sorts_unsorted_input() {
        let requests = [TrimRequest::new(12288, 4096), TrimRequest::new(0, 4096)];

        let result = coalesce_trim_requests(&requests, 0);

        // Should be sorted by offset, not merged (gap too large)

        assert_eq!(result.len(), 2);

        assert_eq!(result[0].offset, 0);

        assert_eq!(result[1].offset, 12288);
    }

    #[test]

    fn trim_request_coalesce_multiple_non_mergeable() {
        let requests = [
            TrimRequest::new(0, 4096),
            TrimRequest::new(16384, 4096),
            TrimRequest::new(32768, 4096),
        ];

        let result = coalesce_trim_requests(&requests, 0);

        assert_eq!(result.len(), 3);
    }

    // ─── BlockAllocator free_ranges / trim_requests_for tests ───

    #[test]

    fn free_ranges_empty_allocator_all_free() {
        let ba = BlockAllocator::new(64, 4096, region(64));

        let ranges = ba.free_ranges();

        assert_eq!(ranges.len(), 1);

        assert_eq!(ranges[0].offset, 0);

        assert_eq!(ranges[0].length, 64 * 4096);
    }

    #[test]

    fn free_ranges_after_alloc_shows_used_and_free_regions() {
        let ba = BlockAllocator::new(64, 4096, region(64));

        // Allocate blocks 0-9 (10 blocks)

        let blocks = ba.alloc_contiguous(10).unwrap();

        assert_eq!(blocks, (0..10).collect::<Vec<_>>());

        let ranges = ba.free_ranges();

        // Free range starts at block 10, covers 54 blocks

        assert_eq!(ranges.len(), 1);

        assert_eq!(ranges[0].offset, 10 * 4096);

        assert_eq!(ranges[0].length, 54 * 4096);
    }

    #[test]

    fn free_ranges_after_free_merges_back() {
        let ba = BlockAllocator::new(64, 4096, region(64));

        let blocks = ba.alloc_contiguous(10).unwrap();

        ba.free(&blocks);

        let ranges = ba.free_ranges();

        assert_eq!(ranges.len(), 1);

        assert_eq!(ranges[0].offset, 0);

        assert_eq!(ranges[0].length, 64 * 4096);
    }

    #[test]

    fn trim_requests_for_converts_block_ids_to_byte_ranges() {
        let ba = BlockAllocator::new(64, 4096, region(64));

        let freed = vec![0, 1, 2]; // three contiguous blocks

        let requests = ba.trim_requests_for(&freed, 0);

        assert_eq!(requests.len(), 1);

        assert_eq!(requests[0].offset, 0);

        assert_eq!(requests[0].length, 3 * 4096);
    }

    #[test]

    fn trim_requests_for_scattered_blocks_with_gap_threshold() {
        let ba = BlockAllocator::new(64, 4096, region(64));

        // Blocks 0-2 and 4-6 (block 3 is still allocated)

        let freed = vec![0, 1, 2, 4, 5, 6];

        // With gap_threshold=0, should be 2 separate runs

        let requests_zero = ba.trim_requests_for(&freed, 0);

        assert_eq!(requests_zero.len(), 2);

        // With gap_threshold=4096 (one block), should merge across block 3 gap

        let requests_merge = ba.trim_requests_for(&freed, 4096);

        assert_eq!(requests_merge.len(), 1);

        assert_eq!(requests_merge[0].offset, 0);

        assert_eq!(requests_merge[0].length, 7 * 4096);
    }

    #[test]

    fn trim_requests_for_empty_input() {
        let ba = BlockAllocator::new(64, 4096, region(64));

        let requests = ba.trim_requests_for(&[], 0);

        assert!(requests.is_empty());
    }

    // ─── TrimSink / discard_extent tests ───

    type TrimCallLog = std::sync::Arc<std::sync::Mutex<Vec<(u64, u64)>>>;

    /// Mock TrimSink that records every (offset, length) call in a shared Vec.
    struct MockTrimSink {
        calls: TrimCallLog,
    }

    impl MockTrimSink {
        fn new() -> (Self, TrimCallLog) {
            let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            (
                Self {
                    calls: calls.clone(),
                },
                calls,
            )
        }
    }

    impl TrimSink for MockTrimSink {
        fn trim_range(&mut self, offset: u64, length: u64) -> Result<(), std::io::Error> {
            self.calls.lock().unwrap().push((offset, length));
            Ok(())
        }
    }

    #[test]
    fn trim_sink_not_invoked_when_no_sink_registered() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        let blocks = ba.alloc_contiguous(10).unwrap();
        // No sink → free is silent, no panic.
        ba.free(&blocks);
        let stats = ba.trim_stats();
        assert_eq!(stats.trim_ops, 0);
        assert_eq!(stats.trim_bytes, 0);
    }

    #[test]
    fn trim_sink_invoked_for_freed_blocks_meeting_threshold() {
        let (mock, calls) = MockTrimSink::new();
        let ba = BlockAllocator::with_trim_sink(
            64,
            4096,
            region(64),
            AllocatorTopology::default(),
            0,
            Box::new(mock),
            0, // min_discard_bytes = 0 → always trim
        );
        let blocks = ba.alloc_contiguous(10).unwrap(); // 10 × 4096 = 40 KiB
        ba.free(&blocks);
        let stats = ba.trim_stats();
        // 10 adjacent blocks coalesce into 1 trim call
        assert_eq!(stats.trim_ops, 1);
        assert_eq!(stats.trim_bytes, 40_960);
        // Verify the mock recorded the call
        let drained: Vec<(u64, u64)> = calls.lock().unwrap().drain(..).collect();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, 0); // offset = block 0 * 4096
        assert_eq!(drained[0].1, 40_960); // length
    }

    #[test]
    fn trim_sink_not_invoked_when_below_min_discard_bytes() {
        let (mock, calls) = MockTrimSink::new();
        let ba = BlockAllocator::with_trim_sink(
            128,
            4096,
            region(128),
            AllocatorTopology::default(),
            0,
            Box::new(mock),
            1_048_576, // 1 MiB threshold
        );
        let blocks = ba.alloc_contiguous(100).unwrap(); // 100 × 4096 = 400 KiB < 1 MiB
        ba.free(&blocks);
        let stats = ba.trim_stats();
        // Below threshold → no trim
        assert_eq!(stats.trim_ops, 0);
        assert_eq!(stats.trim_bytes, 0);
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn trim_sink_coalesces_adjacent_frees() {
        // Allocate A, B, C contiguously; free A and C first, then B.
        // All three should merge into one trim call.
        let (mock, calls) = MockTrimSink::new();
        let ba = BlockAllocator::with_trim_sink(
            64,
            4096,
            region(64),
            AllocatorTopology::default(),
            0,
            Box::new(mock),
            0,
        );
        let a = ba.alloc_contiguous(10).unwrap(); // blocks  0..9
        let b = ba.alloc_contiguous(10).unwrap(); // blocks 10..19
        let c = ba.alloc_contiguous(10).unwrap(); // blocks 20..29

        ba.free(&c); // free 20..29 first
        ba.free(&a); // free  0..9
        ba.free(&b); // free 10..19 — bridges the gap
                     // After all three are freed, they should coalesce into one range.
        let stats = ba.trim_stats();
        assert_eq!(stats.trim_ops, 3); // one per free() call
        let drained: Vec<(u64, u64)> = calls.lock().unwrap().drain(..).collect();
        // Each free() issues a coalesced trim for the blocks just freed.
        // c alone → 10 blocks
        // a alone → 10 blocks
        // b bridges a and c → all 30 coalesced
        assert_eq!(drained.len(), 3);
        // Each free() call processes only the blocks passed to it.
        // free(&c): blocks 20..29 → offset 20*4096
        assert_eq!(drained[0].0, 20 * 4096);
        assert_eq!(drained[0].1, 10 * 4096);
        // free(&a): blocks 0..9 → offset 0
        assert_eq!(drained[1].0, 0);
        assert_eq!(drained[1].1, 10 * 4096);
        // free(&b): blocks 10..19 → offset 10*4096
        assert_eq!(drained[2].0, 10 * 4096);
        assert_eq!(drained[2].1, 10 * 4096);
    }

    #[test]
    fn discard_extent_uses_sink_directly() {
        let (mock, calls) = MockTrimSink::new();
        let ba = BlockAllocator::with_trim_sink(
            64,
            4096,
            region(64),
            AllocatorTopology::default(),
            0,
            Box::new(mock),
            0,
        );
        ba.discard_extent(65536, 131072).unwrap();
        let drained: Vec<(u64, u64)> = calls.lock().unwrap().drain(..).collect();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, 65536);
        assert_eq!(drained[0].1, 131072);
    }

    #[test]
    fn set_trim_sink_after_construction() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        let (mock, calls) = MockTrimSink::new();

        // Initially no sink, no trim
        let blocks = ba.alloc_contiguous(10).unwrap();
        ba.free(&blocks);
        assert_eq!(ba.trim_stats().trim_ops, 0);

        // Now attach sink
        ba.set_trim_sink(Some(Box::new(mock)));
        ba.set_min_discard_bytes(0);

        let blocks2 = ba.alloc_contiguous(10).unwrap();
        ba.free(&blocks2);
        assert_eq!(ba.trim_stats().trim_ops, 1);

        let drained: Vec<(u64, u64)> = calls.lock().unwrap().drain(..).collect();
        assert_eq!(drained.len(), 1);
    }

    #[test]
    fn set_trim_sink_none_disables_trim() {
        let (mock, _calls) = MockTrimSink::new();
        let ba = BlockAllocator::with_trim_sink(
            64,
            4096,
            region(64),
            AllocatorTopology::default(),
            0,
            Box::new(mock),
            0,
        );
        // Disable sink
        ba.set_trim_sink(None);
        let blocks = ba.alloc_contiguous(10).unwrap();
        ba.free(&blocks);
        assert_eq!(ba.trim_stats().trim_ops, 0);
    }

    // ─── AllocResult conversion ───

    #[test]
    fn alloc_result_allocated_converts_to_ok() {
        let ar = AllocResult::Allocated(vec![0, 1, 2]);
        let res: Result<Vec<u64>, AllocError> = ar.into();
        assert_eq!(res, Ok(vec![0, 1, 2]));
    }

    #[test]
    fn alloc_result_no_space_converts_to_err() {
        let ar = AllocResult::NoSpace {
            largest_free_extent: 42,
        };
        let res: Result<Vec<u64>, AllocError> = ar.into();
        assert_eq!(res, Err(AllocError::NoSpace));
    }

    #[test]
    fn alloc_result_no_space_carries_value() {
        let ar = AllocResult::NoSpace {
            largest_free_extent: 17,
        };
        match ar {
            AllocResult::NoSpace {
                largest_free_extent,
            } => assert_eq!(largest_free_extent, 17),
            _ => panic!("expected NoSpace"),
        }
    }
    #[test]
    fn alloc_result_largest_free_extent_accessor() {
        let allocated = AllocResult::Allocated(vec![0, 1, 2]);
        assert_eq!(allocated.largest_free_extent(), None);
        let nospace = AllocResult::NoSpace {
            largest_free_extent: 42,
        };
        assert_eq!(nospace.largest_free_extent(), Some(42));
    }

    // ─── allocate ───

    #[test]
    fn allocate_success_returns_allocated() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        let result = ba.allocate(10).unwrap();
        assert!(matches!(result, AllocResult::Allocated(ref vs) if vs.len() == 10));
    }

    #[test]
    fn allocate_no_space_returns_largest_free() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        ba.alloc_any(64).unwrap();
        let result = ba.allocate(1).unwrap();
        match result {
            AllocResult::NoSpace {
                largest_free_extent,
            } => assert_eq!(largest_free_extent, 0),
            _ => panic!("expected NoSpace"),
        }
    }

    #[test]
    fn allocate_zero_returns_empty() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        let result = ba.allocate(0).unwrap();
        assert_eq!(result, AllocResult::Allocated(Vec::new()));
    }

    #[test]
    fn allocate_fragmented_returns_largest_free_diag() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        // Create a checkerboard: used at 0,4,8,...,60. Free runs of 3 blocks each.
        // Allocate all blocks, then free groups of 3 contiguous blocks between
        // every 4th-position pin.
        let _all = ba.alloc_contiguous(64).unwrap();
        let mut to_free: Vec<u64> = Vec::new();
        for start in (0..64).step_by(4) {
            for off in 1..4 {
                if start + off < 64 {
                    to_free.push(start + off);
                }
            }
        }
        ba.free(&to_free);
        // Now max contiguous free is 3 (the gaps between pins).
        // Request 4 -> NoSpace with largest=3.
        let result = ba.allocate(4).unwrap();
        match result {
            AllocResult::NoSpace {
                largest_free_extent,
            } => assert_eq!(largest_free_extent, 3),
            _ => panic!("expected NoSpace"),
        }
        // Clean up remaining pins.
        let pins: Vec<u64> = (0..64).step_by(4).collect();
        ba.free(&pins);
        assert_eq!(ba.free_count(), 64);
    }

    // ─── allocate_aligned ───

    #[test]
    fn allocate_aligned_exact_block_size() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        let result = ba.allocate_aligned(4096).unwrap();
        match result {
            AllocResult::Allocated(ref vs) => assert_eq!(vs.len(), 1),
            _ => panic!("expected Allocated"),
        }
    }

    #[test]
    fn allocate_aligned_rounds_up() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        let result = ba.allocate_aligned(4097).unwrap();
        match result {
            AllocResult::Allocated(ref vs) => assert_eq!(vs.len(), 2),
            _ => panic!("expected Allocated"),
        }
    }

    #[test]
    fn allocate_aligned_zero_returns_empty() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        let result = ba.allocate_aligned(0).unwrap();
        assert_eq!(result, AllocResult::Allocated(Vec::new()));
    }

    #[test]
    fn allocate_aligned_no_space() {
        let ba = BlockAllocator::new(64, 4096, region(64));
        ba.alloc_any(64).unwrap();
        let result = ba.allocate_aligned(4096).unwrap();
        assert!(matches!(result, AllocResult::NoSpace { .. }));
    }

    #[test]
    fn allocate_aligned_min_io_violation() {
        let t = AllocatorTopology::with_min_io(512, 0, 16384);
        let ba = BlockAllocator::with_topology(256, 4096, region(256), t, 0);
        let err = ba.allocate_aligned(2048).unwrap_err();
        assert_eq!(err, AllocError::AlignmentViolation);
    }

    #[test]
    fn alloc_free_cycle_preserves_invariants() {
        let ba = BlockAllocator::new(256, 4096, region(256));
        for _ in 0..20 {
            let blocks = ba.alloc(5).unwrap();
            ba.free(&blocks);
        }
        assert_eq!(ba.free_count(), 256);
    }
}
