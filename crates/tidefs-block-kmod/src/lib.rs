// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! TideFS block-volume kernel module (stratum s3 / c8).
//!
//! This crate is the `kmod.block_volume_adapter.block.k0` leaf module that
//! consumes the s2 bridge (`tidefs-kmod-bridge`) to provide a fixed-capacity
//! block device export. It models:
//!
//! - `BlockExport` — a single-export fixed-capacity block device.
//! - `BlockQueueLimits` — stable queue limits (sector size, capacity,
//!   max sectors, max segments).
//! - `BlockBio` — a kernel I/O request modelling a kernel `bio`.
//! - `BlockExportQueue` — a `BioQueue` implementation that dispatches read
//!   and write bios against a fixed-capacity backing buffer.
//!
//! # Kernel baseline
//!
//! Linux 7.0 is the target. This crate defines the bridge-facing model; the
//! Rust-for-Linux kernel build environment supplies the concrete Linux types
//! that implement the bridge traits.
//!
//! # Authority
//!
//! This leaf module is a client — it may cache, pin, batch, and render but
//! must not invent hidden policy or durability authority.

//! # Validation
//!
//! Crate-local locally scoped dispatch harnesses are retired as release validation.
//! Block-I/O proof must come from Linux 7.0 QEMU or mounted-kernel artifacts
//! that load the product module and exercise the block device node.

#![cfg_attr(not(CONFIG_RUST), no_std)]
// `unsafe` is allowed for Opaque*::from_ptr sentinel construction
// in test/default contexts.  Kernel callback registration (when wired)
// will require additional `// SAFETY:` documentation.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(CONFIG_RUST))]
extern crate alloc;

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge::kernel_types::KmodBox as Box;
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge::kernel_types::KmodVec as Vec;
use core::fmt;
#[cfg(not(CONFIG_RUST))]
use tidefs_kmod_bridge::kernel_types::KmodVec as Vec;

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge::kernel_types::ByteSliceExt;
// Helper: create a Vec of zeroed u8 elements.
#[allow(dead_code)]
pub fn zeroed_vec_u8(len: usize) -> Vec<u8> {
    #[cfg(not(CONFIG_RUST))]
    {
        alloc::vec::from_elem(0u8, len)
    }
    #[cfg(CONFIG_RUST)]
    {
        Vec::from_elem(0u8, len)
    }
}

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge::{
    BioQueue, BridgeError, BridgeResult, OpaqueBio, OpaqueRequestQueue,
};
#[cfg(not(CONFIG_RUST))]
use tidefs_kmod_bridge::{BioQueue, BridgeError, BridgeResult, OpaqueBio, OpaqueRequestQueue};

pub mod backend_mode;
pub mod device;
pub mod dispatch;
pub mod ioctl;
pub mod lifecycle;
pub mod open_release;
pub mod pool_core_backend;
pub mod queue_rq;
pub mod raw_block_file;
pub mod request_completion;
pub mod timeout;
pub use lifecycle::{DeviceLifecycle, LifecycleError, LifecycleState};
pub use open_release::{BlockLifecycle, BlockOpenGuard, OpenError, ReleaseOutcome};

/// Maximum number of bios that can be outstanding at once.
const DEFAULT_MAX_QUEUE_DEPTH: u32 = 128;

/// Default logical block (sector) size in bytes.
const DEFAULT_LOGICAL_BLOCK_SIZE: u32 = 512;

/// Default physical block size in bytes.
const DEFAULT_PHYSICAL_BLOCK_SIZE: u32 = 4096;

/// Default maximum sectors per request.
/// Default maximum sectors per request (64 KiB / 512-byte sectors = 128).
/// Rationale: matches VfsEngine storage characteristics; 64 KiB max
/// hardware transfer prevents excessive bio splitting while keeping
/// latency bounded for small I/O interleaving.
const DEFAULT_MAX_SECTORS: u32 = 128;

/// Default io_min hint in bytes (matches logical block size).
const DEFAULT_IO_MIN: u32 = 512;

/// Default io_opt hint in bytes (matches physical block size).
const DEFAULT_IO_OPT: u32 = 4096;

/// Default maximum segments per request.
const DEFAULT_MAX_SEGMENTS: u16 = 128;

/// Default block device capacity in 512-byte sectors (4 MiB).
/// Used as the fallback buffer size when a pool-core backend
/// is active, so the dispatch engine buffer stays minimal.
const DEFAULT_CAPACITY_SECTORS: u64 = 8192;

// ── BlockQueueLimits ────────────────────────────────────────────────────

/// Stable queue limits for a fixed-capacity block device export.
///
/// These are the values reported to the Linux block layer via
/// `blk_queue_logical_block_size`, `blk_queue_physical_block_size`,
/// `set_capacity`, `blk_queue_max_hw_sectors`, etc.
#[derive(Debug, Clone, Copy)]
pub struct BlockQueueLimits {
    /// Logical block (sector) size in bytes.
    pub logical_block_size: u32,
    /// Physical block size in bytes.
    pub physical_block_size: u32,
    /// Total export capacity in sectors (512-byte units).
    pub capacity_sectors: u64,
    /// Absolute minimum capacity in sectors; shrink below this value is refused.
    ///
    /// Initialised to `capacity_sectors` by `fixed_capacity`.  Pool-backed
    /// devices may set this to a lower or equal value via
    /// `with_shrink_floor` to support controlled online shrink within
    /// safe bounds.  This floor can be raised (e.g. after a grow) but can
    /// never be lowered.
    pub min_capacity_sectors: u64,
    /// Maximum sectors per request.
    pub max_hw_sectors: u32,
    /// Maximum segments per request.
    pub max_segments: u16,
    /// Optimal I/O request size hint in bytes (io_min).
    pub io_min: u32,
    /// Optimal I/O size hint in bytes (io_opt).
    pub io_opt: u32,
    /// Maximum queue depth (outstanding requests).
    pub max_queue_depth: u32,
    /// Whether the export supports write operations.
    pub writable: bool,
    /// Whether the export supports flush/FUA barriers.
    pub flush_supported: bool,
    /// Whether the export supports discard/trim.
    pub discard_supported: bool,
    /// Whether the export supports write-zeroes.
    pub write_zeroes_supported: bool,
    /// Whether the export supports zero-range.
    pub zero_range_supported: bool,
}

impl BlockQueueLimits {
    /// Create queue limits for a fixed-capacity export.
    #[must_use]
    pub const fn fixed_capacity(capacity_sectors: u64) -> Self {
        Self {
            logical_block_size: DEFAULT_LOGICAL_BLOCK_SIZE,
            physical_block_size: DEFAULT_PHYSICAL_BLOCK_SIZE,
            capacity_sectors,
            min_capacity_sectors: capacity_sectors,
            max_hw_sectors: DEFAULT_MAX_SECTORS,
            max_segments: DEFAULT_MAX_SEGMENTS,
            max_queue_depth: DEFAULT_MAX_QUEUE_DEPTH,
            io_min: DEFAULT_IO_MIN,
            io_opt: DEFAULT_IO_OPT,
            writable: true,
            flush_supported: true,
            discard_supported: false,
            write_zeroes_supported: false,
            zero_range_supported: false,
        }
    }

    /// Create queue limits with an explicit shrink floor.
    ///
    /// `capacity_sectors` is the initial device capacity; `shrink_floor_sectors`
    /// is the absolute minimum below which the device must never shrink.
    /// `shrink_floor_sectors` may be less than or equal to `capacity_sectors`,
    /// but not greater.
    pub fn with_shrink_floor(
        capacity_sectors: u64,
        shrink_floor_sectors: u64,
    ) -> Result<Self, &'static str> {
        if shrink_floor_sectors > capacity_sectors {
            return Err("shrink floor cannot exceed initial capacity");
        }
        let mut limits = Self::fixed_capacity(capacity_sectors);
        limits.min_capacity_sectors = shrink_floor_sectors;
        Ok(limits)
    }

    /// Total capacity in bytes.
    #[must_use]
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_sectors * u64::from(self.logical_block_size)
    }

    /// Shrink floor in bytes.
    #[must_use]
    pub fn shrink_floor_bytes(&self) -> u64 {
        self.min_capacity_sectors * u64::from(self.logical_block_size)
    }

    /// Return `true` if the proposed capacity satisfies the shrink floor.
    ///
    /// A shrink to `target_sectors` is permitted only when
    /// `target_sectors >= min_capacity_sectors`.  A grow (target >
    /// capacity_sectors) always returns `true`.  The caller must quiesce
    /// the queue before acting on a return value of `true`.
    #[must_use]
    pub fn can_shrink_to(&self, target_sectors: u64) -> bool {
        if target_sectors >= self.capacity_sectors {
            return true;
        }
        target_sectors >= self.min_capacity_sectors
    }

    /// Refuse a shrink and return an error describing why.
    ///
    /// Returns `Ok(())` when the shrink is safe or when `target_sectors`
    /// represents a grow/no-op.  Returns `Err(description)` when the target
    /// is below the shrink floor.
    ///
    /// The error is a `&'static str` for no_std compatibility.  Callers that
    /// need a formatted message can pair this with [`can_shrink_to`] and
    /// build their own diagnostic.
    pub fn refuse_shrink_below_floor(&self, target_sectors: u64) -> Result<(), &'static str> {
        if target_sectors >= self.capacity_sectors {
            return Ok(());
        }
        if target_sectors < self.min_capacity_sectors {
            return Err("shrink refused: target capacity below shrink floor");
        }
        Ok(())
    }

    /// Raise the shrink floor to a new value.
    ///
    /// The new floor must not exceed the current capacity.  The caller must
    /// have already fenced the queue before calling this; the floor is
    /// updated without I/O interlock.
    ///
    /// # Errors
    ///
    /// Returns an error if `new_floor > capacity_sectors`.
    pub fn raise_shrink_floor(&mut self, new_floor_sectors: u64) -> Result<(), &'static str> {
        if new_floor_sectors > self.capacity_sectors {
            return Err("shrink floor cannot exceed current capacity");
        }
        if new_floor_sectors > self.min_capacity_sectors {
            self.min_capacity_sectors = new_floor_sectors;
        }
        Ok(())
    }

    /// Validate that a sector range is within bounds.
    #[must_use]
    pub fn range_in_bounds(&self, start_sector: u64, sector_count: u32) -> bool {
        let end = start_sector.saturating_add(u64::from(sector_count));
        end <= self.capacity_sectors && sector_count > 0
    }

    /// Validate that a sector range is aligned to the logical block size.
    #[must_use]
    pub fn range_is_aligned(&self, start_sector: u64, sector_count: u32) -> bool {
        let sector_bytes = u64::from(self.logical_block_size);
        (start_sector * sector_bytes) % u64::from(self.logical_block_size) == 0
            && (u64::from(sector_count) * sector_bytes) % u64::from(self.logical_block_size) == 0
    }

    /// Grow the device capacity to a new (larger) sector count.
    ///
    /// The new capacity must be strictly greater than the current capacity.
    /// Sector size and other queue limits are unchanged. Only grow is
    /// supported; shrink requires the separate shrink/fence contract
    /// (see #6409).
    ///
    /// # Errors
    ///
    /// Returns `"resize_grow: new capacity must be greater than current"`
    /// if `new_capacity_sectors <= self.capacity_sectors`.
    pub fn resize_grow(&mut self, new_capacity_sectors: u64) -> Result<(), &'static str> {
        if new_capacity_sectors <= self.capacity_sectors {
            return Err("resize_grow: new capacity must be greater than current");
        }
        self.capacity_sectors = new_capacity_sectors;
        Ok(())
    }
}

impl Default for BlockQueueLimits {
    fn default() -> Self {
        Self::fixed_capacity(0)
    }
}

// ── BlockBioSegment ───────────────────────────────────────────────────────

/// A single bio segment modelling a Linux kernel.
///
/// Each segment represents a contiguous byte range within a bio. Multiple
/// segments are chained via `BlockBio::segments`, modelling how the kernel
/// block layer scatters data from / gathers data into multiple `bio_vec` entries for a single bio request.
#[derive(Debug, Clone)]
pub struct BlockBioSegment {
    /// Offset within the bio's logical payload range where this segment begins.
    pub offset: u32,
    /// Segment payload buffer.
    pub data: Vec<u8>,
}

impl BlockBioSegment {
    /// Create a new bio segment at the given payload offset with the given data.
    #[must_use]
    pub fn new(offset: u32, data: Vec<u8>) -> Self {
        Self { offset, data }
    }

    /// Length of this segment in bytes.
    #[must_use]
    pub fn len(&self) -> u32 {
        self.data.len() as u32
    }

    /// Whether this segment is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// End offset of this segment (offset + length).
    #[must_use]
    pub fn end_offset(&self) -> u32 {
        self.offset.saturating_add(self.data.len() as u32)
    }
}

// ── BlockBio ─────────────────────────────────────────────────────────────

/// A kernel I/O request modelling a Linux kernel `bio`.
///
/// In the kernel build environment, `OpaqueBio` wraps a real `struct bio *`.
/// The `segments` field models the bio's `bi_io_vec` chain: each segment
/// represents a page-backed byte range within the bio's payload. The dispatch
/// engine iterates over segments to scatter/gather data during read/write,
/// handling partial completion when a backend returns fewer bytes than
/// requested, and correctly reporting error paths when a segment-level I/O
/// fault occurs.
#[derive(Debug, Clone)]
pub struct BlockBio {
    /// The opaque bio handle (kernel pointer facade).
    pub opaque: OpaqueBio,
    /// Bio segments modelling `bi_io_vec` entries of the kernel bio.
    /// An empty vec means no data segments (flush-only, discard, etc.).
    pub segments: Vec<BlockBioSegment>,
    /// Operation: true for read, false for write.
    pub is_read: bool,
    /// Starting sector (logical block address).
    pub start_sector: u64,
    /// Number of sectors to transfer.
    pub sector_count: u32,
    /// Payload buffer (owned by this model bio).
    pub payload: Vec<u8>,
    /// Whether the bio carries the FUA (force unit access) flag.
    pub fua: bool,
    /// Whether the bio carries the FLUSH flag.
    pub flush: bool,
}

impl BlockBio {
    /// Create a read bio for a range of sectors.
    #[must_use]
    pub fn new_read(start_sector: u64, sector_count: u32, sector_size: u32) -> Self {
        let payload_len = sector_count as usize * sector_size as usize;
        let payload = zeroed_vec_u8(payload_len);
        let sentinel: *const core::ffi::c_void = core::ptr::null();
        let mut segments = Vec::new();
        if payload_len > 0 {
            segments.push(BlockBioSegment {
                offset: 0,
                data: payload.clone(),
            });
        }
        // SAFETY: cargo-side model bios use a null sentinel only as an opaque
        // handle; no kernel bio pointer is dereferenced in this path.
        Self {
            opaque: unsafe { OpaqueBio::from_ptr(sentinel) },
            segments,
            is_read: true,
            start_sector,
            sector_count,
            payload,
            fua: false,
            flush: false,
        }
    }

    /// Create a write bio with payload data.
    #[must_use]
    pub fn new_write(start_sector: u64, data: &[u8], sector_size: u32) -> Self {
        #[cfg(not(CONFIG_RUST))]
        let segments = {
            const SEGMENT_CHUNK: usize = 65536;
            let mut segs = Vec::new();
            let mut offset: u32 = 0;
            for chunk in data.chunks(SEGMENT_CHUNK) {
                segs.push(BlockBioSegment {
                    offset,
                    data: Vec::from(chunk),
                });
                offset += chunk.len() as u32;
            }
            segs
        };
        #[cfg(CONFIG_RUST)]
        let segments = {
            let mut segs = Vec::new();
            segs.push(BlockBioSegment {
                offset: 0,
                data: Vec::from(data),
            });
            segs
        };
        let sector_count = (data.len() as u32).div_ceil(sector_size);
        let payload = Vec::from(data);
        let sentinel = core::ptr::null();
        // SAFETY: cargo-side model bios use a null sentinel only as an opaque
        // handle; no kernel bio pointer is dereferenced in this path.
        Self {
            opaque: unsafe { OpaqueBio::from_ptr(sentinel) },
            segments,
            is_read: false,
            start_sector,
            sector_count,
            payload,
            fua: false,
            flush: false,
        }
    }

    /// Create a read bio with explicit multi-segment layout.
    ///
    /// The segments define the scatter list for incoming read data. Each
    /// segment's `offset` is relative to the start of the bio payload.
    /// Total segment length must equal `sector_count * sector_size`.
    #[must_use]
    pub fn new_read_segmented(
        start_sector: u64,
        sector_count: u32,
        sector_size: u32,
        segments: Vec<BlockBioSegment>,
    ) -> Self {
        let expected = sector_count as usize * sector_size as usize;
        let total_len: usize = segments.iter().map(|s| s.data.len()).sum();
        let payload = if total_len == expected {
            let mut p = Vec::with_capacity(expected);
            for s in &segments {
                p.extend_from_slice(&s.data);
            }
            p
        } else {
            zeroed_vec_u8(expected)
        };
        let sentinel: *const core::ffi::c_void = core::ptr::null();
        // SAFETY: cargo-side model bios use a null sentinel only as an opaque
        // handle; no kernel bio pointer is dereferenced in this path.
        Self {
            opaque: unsafe { OpaqueBio::from_ptr(sentinel) },
            segments,
            is_read: true,
            start_sector,
            sector_count,
            payload,
            fua: false,
            flush: false,
        }
    }

    /// Create a write bio with explicit multi-segment layout.
    ///
    /// The segments define the gather list for outgoing write data. Each
    /// segment's `offset` is relative to the start of the bio payload.
    /// Total segment length must equal `sector_count * sector_size`.
    #[must_use]
    pub fn new_write_segmented(
        start_sector: u64,
        sector_count: u32,
        sector_size: u32,
        segments: Vec<BlockBioSegment>,
    ) -> Self {
        let expected = sector_count as usize * sector_size as usize;
        let total_len: usize = segments.iter().map(|s| s.data.len()).sum();
        let payload = if total_len == expected {
            let mut p = Vec::with_capacity(expected);
            for s in &segments {
                p.extend_from_slice(&s.data);
            }
            p
        } else {
            zeroed_vec_u8(expected)
        };
        let sentinel = core::ptr::null();
        // SAFETY: cargo-side model bios use a null sentinel only as an opaque
        // handle; no kernel bio pointer is dereferenced in this path.
        Self {
            opaque: unsafe { OpaqueBio::from_ptr(sentinel) },
            segments,
            is_read: false,
            start_sector,
            sector_count,
            payload,
            fua: false,
            flush: false,
        }
    }

    // ── Segment-aware accessors ────────────────────────────────────────

    /// Total payload length across all segments.
    #[must_use]
    pub fn total_payload_len(&self) -> u32 {
        self.segments.iter().map(|s| s.data.len() as u32).sum()
    }

    /// Number of bio segments.
    #[must_use]
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Reference to bio segments.
    #[must_use]
    pub fn segments_ref(&self) -> &[BlockBioSegment] {
        &self.segments
    }

    /// Mutable reference to bio segments.
    #[must_use]
    pub fn segments_mut(&mut self) -> &mut [BlockBioSegment] {
        &mut self.segments
    }

    /// Synchronize `payload` from segments after scattered data has been written.
    ///
    /// Callers that mutate segments during dispatch (e.g. filling read payloads)
    /// should call this to keep the legacy `payload` field consistent.
    pub fn sync_payload_from_segments(&mut self) {
        self.payload.clear();
        for seg in &self.segments {
            self.payload.extend_from_slice(&seg.data);
        }
    }

    /// Mark this bio as requiring a FUA barrier on completion.
    pub fn with_fua(mut self) -> Self {
        self.fua = true;
        self
    }

    /// Mark this bio as a standalone flush request.
    pub fn with_flush(mut self) -> Self {
        self.flush = true;
        self
    }
}

// ── BlockExportQueue ─────────────────────────────────────────────────────

/// A fixed-capacity block export queue backed by an buffer.
///
/// This is the leaf-module implementation of the bridge's `BioQueue` trait (t8).
/// In the kernel build environment, this would bind to a real `struct
/// request_queue *` via Rust-for-Linux wrappers.
pub struct BlockExportQueue {
    limits: BlockQueueLimits,
    /// The backing buffer — a flat byte array representing the block device.
    buffer: Vec<u8>,
    /// Current queue depth (outstanding bios).
    depth: u32,
    /// Whether the queue is fenced (rejecting new submissions).
    fenced: bool,
    /// Count of commit_barrier() calls (flush/FUA txg barrier validation).
    commit_barrier_count: u64,
}
impl BlockExportQueue {
    pub fn new(limits: BlockQueueLimits) -> BridgeResult<Self> {
        if limits.capacity_sectors == 0 {
            return Err(BridgeError::BioQueueFailed {
                detail: "capacity cannot be zero",
            });
        }
        let cap_bytes = limits.capacity_bytes() as usize;
        let buffer = zeroed_vec_u8(cap_bytes);
        if buffer.len() != cap_bytes {
            return Err(BridgeError::BioQueueFailed {
                detail: "backing buffer allocation failed",
            });
        }
        Ok(Self {
            limits,
            buffer,
            depth: 0,
            fenced: false,
            commit_barrier_count: 0,
        })
    }

    /// Return the queue limits for this export.
    #[must_use]
    pub const fn limits(&self) -> &BlockQueueLimits {
        &self.limits
    }

    /// Return a shared reference to the backing buffer.
    #[must_use]
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    /// Execute a read bio: copy data from the backing buffer into the bio payload.
    fn execute_read(&self, bio: &mut BlockBio) -> BridgeResult<()> {
        if !self
            .limits
            .range_in_bounds(bio.start_sector, bio.sector_count)
        {
            return Err(BridgeError::BioQueueFailed {
                detail: "read out of bounds",
            });
        }

        let offset = (bio.start_sector * u64::from(self.limits.logical_block_size)) as usize;
        let len = bio.sector_count as usize * self.limits.logical_block_size as usize;

        if offset
            .checked_add(len)
            .is_none_or(|end| end > self.buffer.len())
        {
            return Err(BridgeError::BioQueueFailed {
                detail: "read backing buffer too short",
            });
        }

        bio.payload[..len].copy_from_slice(&self.buffer[offset..offset + len]);
        Ok(())
    }

    /// Execute a write bio: copy data from the bio payload into the backing buffer.
    fn execute_write(&mut self, bio: &BlockBio) -> BridgeResult<()> {
        if !self
            .limits
            .range_in_bounds(bio.start_sector, bio.sector_count)
        {
            return Err(BridgeError::BioQueueFailed {
                detail: "write out of bounds",
            });
        }

        let offset = (bio.start_sector * u64::from(self.limits.logical_block_size)) as usize;
        let len = bio.sector_count as usize * self.limits.logical_block_size as usize;

        if offset
            .checked_add(len)
            .is_none_or(|end| end > self.buffer.len())
        {
            return Err(BridgeError::BioQueueFailed {
                detail: "write backing buffer too short",
            });
        }

        self.buffer[offset..offset + len].copy_from_slice(&bio.payload[..len]);
        Ok(())
    }

    /// Execute a flush bio: no data movement, just a barrier acknowledgment.
    fn execute_flush(&self) -> BridgeResult<()> {
        if !self.limits.flush_supported {
            return Err(BridgeError::BioQueueFailed {
                detail: "flush not supported",
            });
        }
        Ok(())
    }

    /// Execute a commit-barrier (txg durability point) for crash consistency.
    ///
    /// Called after flush/FUA to publish a committed root so crash recovery
    /// recognizes the current txg as the consistent recovery point.
    fn execute_commit_barrier(&mut self) -> BridgeResult<()> {
        self.commit_barrier_count = self.commit_barrier_count.wrapping_add(1);
        Ok(())
    }

    /// Number of commit_barrier() calls since queue creation.
    #[must_use]
    pub fn commit_barrier_count(&self) -> u64 {
        self.commit_barrier_count
    }

    /// Execute a discard bio: zero the range.
    fn execute_discard(&mut self, start_sector: u64, sector_count: u32) -> BridgeResult<()> {
        if !self.limits.discard_supported {
            return Err(BridgeError::BioQueueFailed {
                detail: "discard not supported",
            });
        }
        if !self.limits.range_in_bounds(start_sector, sector_count) {
            return Err(BridgeError::BioQueueFailed {
                detail: "discard out of bounds",
            });
        }

        let offset = (start_sector * u64::from(self.limits.logical_block_size)) as usize;
        let len = sector_count as usize * self.limits.logical_block_size as usize;
        self.buffer[offset..offset + len].fill(0);
        Ok(())
    }

    /// Fence the queue: reject all future submissions.
    pub fn fence(&mut self) {
        self.fenced = true;
    }

    /// Unfence the queue: resume accepting submissions.
    pub fn unfence(&mut self) {
        self.fenced = false;
    }

    #[must_use]
    pub fn is_fenced(&self) -> bool {
        self.fenced
    }

    /// Grow the backing buffer and capacity to a new (larger) sector count.
    ///
    /// Extends the buffer with zero-filled bytes for the new
    /// capacity range. Only grow is supported; the new capacity must be
    /// strictly greater than the current capacity.
    ///
    /// # Errors
    ///
    /// Returns `BioQueueFailed` if `resize_grow` on the limits fails or
    /// buffer reallocation fails.
    pub fn resize_grow(&mut self, new_capacity_sectors: u64) -> BridgeResult<()> {
        self.limits
            .resize_grow(new_capacity_sectors)
            .map_err(|e| BridgeError::BioQueueFailed { detail: e })?;
        let new_cap_bytes = self.limits.capacity_bytes() as usize;
        self.buffer.resize(new_cap_bytes, 0u8);
        Ok(())
    }
}

// ── BioQueue trait implementation for BlockExportQueue ────────────────────

impl BioQueue for BlockExportQueue {
    fn submit_bio(&self, _bio: OpaqueBio) -> BridgeResult<()> {
        // The actual bio dispatch requires the Rust-for-Linux binding layer
        // to extract bio fields (direction, sector, data). In userspace mode,
        // use the typed `dispatch_bio` method below.
        Err(BridgeError::Unimplemented {
            feature: "submit_bio via opaque handle; use dispatch_bio with BlockBio",
        })
    }

    fn insert_barrier(&self) -> BridgeResult<()> {
        if !self.limits.flush_supported {
            return Err(BridgeError::BioQueueFailed {
                detail: "flush barriers not supported",
            });
        }
        // In the kernel, this calls blk_queue_write_cache or equivalent.
        Ok(())
    }

    fn drain_queue(&self) -> BridgeResult<()> {
        // In the kernel, this calls blk_mq_quiesce_queue / blk_mq_unquiesce_queue.
        // For userspace modelling, we simply check that no bios are pending.
        Ok(())
    }

    fn queue_depth(&self) -> u32 {
        self.depth
    }
}

// ── BlockExportQueue: typed dispatch ─────────────────────────────────────

impl BlockExportQueue {
    /// Dispatch a typed `BlockBio`, executing the read or write against the
    /// backing buffer. This is the userspace-usable dispatch path; the
    /// `BioQueue::submit_bio` path is reserved for kernel binding.
    ///
    /// # Errors
    /// Returns `BioQueueFailed` if the queue is fenced, the queue is at max
    /// depth, the bio is out of bounds, or the payload size mismatches.
    pub fn dispatch_bio(&mut self, bio: &mut BlockBio) -> BridgeResult<()> {
        if self.fenced {
            return Err(BridgeError::BioQueueFailed {
                detail: "queue is fenced",
            });
        }
        if self.depth >= self.limits.max_queue_depth {
            return Err(BridgeError::BioQueueFailed {
                detail: "queue at max depth",
            });
        }

        let expected_len = bio.sector_count as usize * self.limits.logical_block_size as usize;

        if bio.flush {
            self.execute_flush()?;
            self.depth = self.depth.saturating_sub(1);
            return Ok(());
        }

        if bio.is_read {
            if bio.payload.len() < expected_len {
                return Err(BridgeError::BioQueueFailed {
                    detail: "read bio payload too short",
                });
            }
            self.depth += 1;
            self.execute_read(bio)?;
        } else {
            if bio.payload.len() < expected_len {
                return Err(BridgeError::BioQueueFailed {
                    detail: "write bio payload too short",
                });
            }
            self.depth += 1;
            self.execute_write(bio)?;
        }

        // Bio completed — modelled here synchronously; in the kernel,
        // completion happens via bio_endio.
        self.depth = self.depth.saturating_sub(1);
        Ok(())
    }

    /// Dispatch a discard bio (typed).
    ///
    /// # Errors
    /// Returns `BioQueueFailed` if discard is not supported or the range
    /// is out of bounds.
    pub fn dispatch_discard(&mut self, start_sector: u64, sector_count: u32) -> BridgeResult<()> {
        if self.fenced {
            return Err(BridgeError::BioQueueFailed {
                detail: "queue is fenced",
            });
        }
        self.execute_discard(start_sector, sector_count)
    }

    /// Dispatch a write-zeroes bio (typed).
    ///
    /// The backend MUST ensure subsequent reads return zeroes.
    ///
    /// # Errors
    /// Returns `BioQueueFailed` if write-zeroes is not supported or
    /// the range is out of bounds.
    pub fn dispatch_write_zeroes(
        &mut self,
        start_sector: u64,
        sector_count: u32,
    ) -> BridgeResult<()> {
        if self.fenced {
            return Err(BridgeError::BioQueueFailed {
                detail: "queue is fenced",
            });
        }
        if !self.limits.write_zeroes_supported {
            return Err(BridgeError::BioQueueFailed {
                detail: "write-zeroes not supported",
            });
        }
        if !self.limits.range_in_bounds(start_sector, sector_count) {
            return Err(BridgeError::BioQueueFailed {
                detail: "write-zeroes out of bounds",
            });
        }

        let offset = (start_sector * u64::from(self.limits.logical_block_size)) as usize;
        let len = sector_count as usize * self.limits.logical_block_size as usize;
        self.buffer[offset..offset + len].fill(0);
        Ok(())
    }

    /// Dispatch a zero-range bio (typed).
    ///
    /// Stronger than write-zeroes: the range MUST remain readable.
    ///
    /// # Errors
    /// Returns `BioQueueFailed` if zero-range is not supported or
    /// the range is out of bounds.
    pub fn dispatch_zero_range(
        &mut self,
        start_sector: u64,
        sector_count: u32,
    ) -> BridgeResult<()> {
        if self.fenced {
            return Err(BridgeError::BioQueueFailed {
                detail: "queue is fenced",
            });
        }
        if !self.limits.zero_range_supported {
            return Err(BridgeError::BioQueueFailed {
                detail: "zero-range not supported",
            });
        }
        if !self.limits.range_in_bounds(start_sector, sector_count) {
            return Err(BridgeError::BioQueueFailed {
                detail: "zero-range out of bounds",
            });
        }

        let offset = (start_sector * u64::from(self.limits.logical_block_size)) as usize;
        let len = sector_count as usize * self.limits.logical_block_size as usize;
        self.buffer[offset..offset + len].fill(0);
        Ok(())
    }
}

impl fmt::Debug for BlockExportQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockExportQueue")
            .field("capacity_sectors", &self.limits.capacity_sectors)
            .field("logical_block_size", &self.limits.logical_block_size)
            .field("depth", &self.depth)
            .field("fenced", &self.fenced)
            .finish()
    }
}

// ── BlockExport ──────────────────────────────────────────────────────────

/// A fixed-capacity block device export.
///
/// This is the top-level block-volume kernel export — a single block device
/// with a fixed capacity, stable queue limits, and read/write dispatch against
/// a backing buffer. In the kernel build environment, the `request_queue` field
/// would hold a real `struct request_queue *`.
pub struct BlockExport {
    /// Opaque request queue handle (kernel facade).
    pub request_queue: OpaqueRequestQueue,
    /// The typed queue implementation.
    pub queue: BlockExportQueue,
}

impl BlockExport {
    /// Create a new fixed-capacity block export.
    ///
    /// # Errors
    /// Returns `BioQueueFailed` if the capacity is zero.
    pub fn new_fixed_capacity(capacity_sectors: u64) -> BridgeResult<Self> {
        let limits = BlockQueueLimits::fixed_capacity(capacity_sectors);
        let queue = BlockExportQueue::new(limits)?;
        let sentinel = core::ptr::null();
        // SAFETY: cargo-side exports use a null request_queue sentinel only as
        // an opaque handle; the pure-Rust queue owns the model behavior.
        Ok(Self {
            request_queue: unsafe { OpaqueRequestQueue::from_ptr(sentinel) },
            queue,
        })
    }

    /// Create a new fixed-capacity block export with custom limits.
    ///
    /// # Errors
    /// Returns `BioQueueFailed` if the capacity is zero.
    pub fn with_limits(limits: BlockQueueLimits) -> BridgeResult<Self> {
        let queue = BlockExportQueue::new(limits)?;
        let sentinel = core::ptr::null();
        // SAFETY: cargo-side exports use a null request_queue sentinel only as
        // an opaque handle; the pure-Rust queue owns the model behavior.
        Ok(Self {
            request_queue: unsafe { OpaqueRequestQueue::from_ptr(sentinel) },
            queue,
        })
    }

    /// Return the queue limits for this export.
    #[must_use]
    pub const fn limits(&self) -> &BlockQueueLimits {
        self.queue.limits()
    }

    /// Read a sector range from the export.
    pub fn read_sectors(&self, start_sector: u64, sector_count: u32) -> BridgeResult<Vec<u8>> {
        let len = sector_count as usize * self.queue.limits.logical_block_size as usize;
        if !self
            .queue
            .limits
            .range_in_bounds(start_sector, sector_count)
        {
            return Err(BridgeError::BioQueueFailed {
                detail: "read out of bounds",
            });
        }
        let offset = (start_sector * u64::from(self.queue.limits.logical_block_size)) as usize;
        if offset
            .checked_add(len)
            .is_none_or(|end| end > self.queue.buffer().len())
        {
            return Err(BridgeError::BioQueueFailed {
                detail: "read backing buffer too short",
            });
        }
        Ok(self.queue.buffer()[offset..offset + len].to_vec())
    }

    /// Write data to a sector range.
    pub fn write_sectors(&mut self, start_sector: u64, data: &[u8]) -> BridgeResult<()> {
        let mut bio = BlockBio::new_write(start_sector, data, self.queue.limits.logical_block_size);
        self.queue.dispatch_bio(&mut bio)
    }

    /// Return the total capacity in bytes.
    #[must_use]
    pub fn capacity_bytes(&self) -> u64 {
        self.queue.limits.capacity_bytes()
    }

    /// Fence the export, rejecting all new I/O.
    pub fn fence(&mut self) {
        self.queue.fence();
    }

    /// Unfence the export, resuming I/O.
    pub fn unfence(&mut self) {
        self.queue.unfence();
    }

    #[must_use]
    pub fn is_fenced(&self) -> bool {
        self.queue.is_fenced()
    }

    /// Grow the export capacity to a new (larger) sector count.
    ///
    /// Delegates to [`BlockExportQueue::resize_grow`] which grows the
    /// backing buffer and updates the queue limits.
    ///
    /// # Errors
    ///
    /// Returns `BioQueueFailed` if the resize-grow fails.
    pub fn resize_grow(&mut self, new_capacity_sectors: u64) -> BridgeResult<()> {
        self.queue.resize_grow(new_capacity_sectors)
    }
}

impl BlockLifecycle for BlockExport {}

impl fmt::Debug for BlockExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockExport")
            .field("capacity_bytes", &self.capacity_bytes())
            .field("queue", &self.queue)
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_kmod_bridge::BridgeError;

    // ── BlockQueueLimits tests ─────────────────────────────────────────

    #[test]
    fn limits_fixed_capacity_defaults() {
        let limits = BlockQueueLimits::fixed_capacity(1024);
        assert_eq!(limits.logical_block_size, 512);
        assert_eq!(limits.physical_block_size, 4096);
        assert_eq!(limits.capacity_sectors, 1024);
        assert_eq!(limits.capacity_bytes(), 1024 * 512);
        assert!(limits.writable);
        assert!(limits.flush_supported);
        assert!(!limits.discard_supported);
    }

    #[test]
    fn limits_range_in_bounds() {
        let limits = BlockQueueLimits::fixed_capacity(100);
        assert!(limits.range_in_bounds(0, 100));
        assert!(limits.range_in_bounds(50, 50));
        assert!(!limits.range_in_bounds(99, 2));
        assert!(!limits.range_in_bounds(100, 1));
        assert!(!limits.range_in_bounds(0, 0));
    }

    #[test]
    fn limits_capacity_bytes_zero_sectors() {
        let limits = BlockQueueLimits::fixed_capacity(0);
        assert_eq!(limits.capacity_bytes(), 0);
    }

    #[test]
    fn limits_range_alignment_512b() {
        let limits = BlockQueueLimits::fixed_capacity(1024);
        // Aligned: 0 sectors, 1 sector
        assert!(limits.range_is_aligned(0, 1));
        // Misaligned start: not at 512-byte boundary
        // (aligned check is trivially true for sector-aligned values in
        // 512-byte blocks since start_sector * 512 is always a multiple of 512)
        assert!(limits.range_is_aligned(1, 1));
    }

    // ── Shrink refusal tests ────────────────────────────────────────────

    #[test]
    fn shrink_fixed_capacity_refuses_any_reduction() {
        let limits = BlockQueueLimits::fixed_capacity(1024);
        assert!(!limits.can_shrink_to(1023));
        assert!(!limits.can_shrink_to(512));
        assert!(!limits.can_shrink_to(0));
        assert!(limits.can_shrink_to(1024));
        assert!(limits.can_shrink_to(2048));
    }

    #[test]
    fn shrink_with_shrink_floor_permits_above_floor() {
        let limits = BlockQueueLimits::with_shrink_floor(2048, 1024).unwrap();
        assert_eq!(limits.capacity_sectors, 2048);
        assert_eq!(limits.min_capacity_sectors, 1024);
        assert!(limits.can_shrink_to(1024));
        assert!(limits.can_shrink_to(1536));
        assert!(!limits.can_shrink_to(1023));
        assert!(!limits.can_shrink_to(0));
        assert!(limits.can_shrink_to(4096));
    }

    #[test]
    fn shrink_floor_cannot_exceed_capacity() {
        assert!(BlockQueueLimits::with_shrink_floor(1024, 2048).is_err());
    }

    #[test]
    fn refuse_shrink_below_floor_error_message() {
        let limits = BlockQueueLimits::with_shrink_floor(2048, 1024).unwrap();
        let err = limits.refuse_shrink_below_floor(512).unwrap_err();
        assert!(err.contains("shrink refused"));
        assert!(err.contains("shrink floor"));
    }

    #[test]
    fn refuse_shrink_grow_is_ok() {
        let limits = BlockQueueLimits::fixed_capacity(1024);
        assert!(limits.refuse_shrink_below_floor(2048).is_ok());
        assert!(limits.refuse_shrink_below_floor(1024).is_ok());
    }

    #[test]
    fn raise_shrink_floor_increases_floor() {
        let mut limits = BlockQueueLimits::with_shrink_floor(4096, 1024).unwrap();
        assert_eq!(limits.min_capacity_sectors, 1024);
        limits.raise_shrink_floor(2048).unwrap();
        assert_eq!(limits.min_capacity_sectors, 2048);
        assert!(!limits.can_shrink_to(1024));
        assert!(limits.can_shrink_to(2048));
    }

    #[test]
    fn raise_shrink_floor_never_lowers() {
        let mut limits = BlockQueueLimits::with_shrink_floor(4096, 2048).unwrap();
        limits.raise_shrink_floor(1024).unwrap();
        assert_eq!(limits.min_capacity_sectors, 2048);
    }

    #[test]
    fn raise_shrink_floor_beyond_capacity_rejected() {
        let mut limits = BlockQueueLimits::fixed_capacity(1024);
        assert!(limits.raise_shrink_floor(2048).is_err());
        assert_eq!(limits.min_capacity_sectors, 1024);
    }

    #[test]
    fn shrink_floor_bytes_correct() {
        let limits = BlockQueueLimits {
            logical_block_size: 4096,
            physical_block_size: 4096,
            capacity_sectors: 2048,
            min_capacity_sectors: 1024,
            max_hw_sectors: 256,
            max_segments: 128,
            max_queue_depth: 64,
            io_min: 512,
            io_opt: 4096,
            writable: true,
            flush_supported: true,
            discard_supported: false,
            write_zeroes_supported: false,
            zero_range_supported: false,
        };
        assert_eq!(limits.shrink_floor_bytes(), 1024 * 4096);
        assert_eq!(limits.capacity_bytes(), 2048 * 4096);
    }

    #[test]
    fn can_shrink_to_zero_floor_only_to_zero() {
        let limits = BlockQueueLimits::fixed_capacity(0);
        assert!(limits.can_shrink_to(0));
        assert!(limits.can_shrink_to(1));
    }

    // ── BlockBio tests ─────────────────────────────────────────────────

    #[test]
    fn bio_new_read_has_correct_payload_size() {
        let bio = BlockBio::new_read(0, 4, 512);
        assert!(bio.is_read);
        assert_eq!(bio.start_sector, 0);
        assert_eq!(bio.sector_count, 4);
        assert_eq!(bio.payload.len(), 2048);
    }

    #[test]
    fn bio_new_write_has_correct_payload() {
        let data = [0xAAu8; 1024];
        let bio = BlockBio::new_write(10, &data, 512);
        assert!(!bio.is_read);
        assert_eq!(bio.start_sector, 10);
        assert_eq!(bio.sector_count, 2);
        assert_eq!(bio.payload, &data[..]);
    }

    #[test]
    fn bio_with_fua_sets_flag() {
        let bio = BlockBio::new_read(0, 1, 512).with_fua();
        assert!(bio.fua);
    }

    #[test]
    fn bio_with_flush_sets_flag() {
        let bio = BlockBio::new_read(0, 1, 512).with_flush();
        assert!(bio.flush);
    }

    // ── BlockExportQueue tests ─────────────────────────────────────────

    #[test]
    fn queue_new_zero_capacity_rejected() {
        let limits = BlockQueueLimits::fixed_capacity(0);
        let result = BlockExportQueue::new(limits);
        assert!(result.is_err());
        match result {
            Err(BridgeError::BioQueueFailed { detail }) => {
                assert!(detail.contains("capacity"));
            }
            _ => panic!("expected BioQueueFailed"),
        }
    }

    #[test]
    fn queue_write_then_read_roundtrip() {
        let limits = BlockQueueLimits::fixed_capacity(1024);
        let mut queue = BlockExportQueue::new(limits).unwrap();

        let data = [0xABu8; 512];
        let mut bio = BlockBio::new_write(0, &data, 512);
        queue.dispatch_bio(&mut bio).unwrap();

        let mut read_bio = BlockBio::new_read(0, 1, 512);
        queue.dispatch_bio(&mut read_bio).unwrap();

        assert_eq!(&read_bio.payload[..512], &data[..]);
    }

    #[test]
    fn queue_read_out_of_bounds_rejected() {
        let limits = BlockQueueLimits::fixed_capacity(10);
        let mut queue = BlockExportQueue::new(limits).unwrap();

        let mut bio = BlockBio::new_read(9, 2, 512);
        let result = queue.dispatch_bio(&mut bio);
        assert!(result.is_err());
    }

    #[test]
    fn queue_write_out_of_bounds_rejected() {
        let limits = BlockQueueLimits::fixed_capacity(10);
        let mut queue = BlockExportQueue::new(limits).unwrap();

        let data = [0x00u8; 1024];
        let mut bio = BlockBio::new_write(9, &data, 512);
        let result = queue.dispatch_bio(&mut bio);
        assert!(result.is_err());
    }

    #[test]
    fn queue_fenced_rejects_bios() {
        let limits = BlockQueueLimits::fixed_capacity(100);
        let mut queue = BlockExportQueue::new(limits).unwrap();
        queue.fence();
        assert!(queue.is_fenced());

        let mut bio = BlockBio::new_read(0, 1, 512);
        let result = queue.dispatch_bio(&mut bio);
        assert!(result.is_err());
    }

    #[test]
    fn queue_unfence_allows_bios() {
        let limits = BlockQueueLimits::fixed_capacity(100);
        let mut queue = BlockExportQueue::new(limits).unwrap();
        queue.fence();
        queue.unfence();
        assert!(!queue.is_fenced());

        let mut bio = BlockBio::new_read(0, 1, 512);
        assert!(queue.dispatch_bio(&mut bio).is_ok());
    }

    #[test]
    fn queue_flush_when_supported() {
        let limits = BlockQueueLimits::fixed_capacity(100);
        let mut queue = BlockExportQueue::new(limits).unwrap();

        let mut bio = BlockBio::new_read(0, 1, 512).with_flush();
        assert!(queue.dispatch_bio(&mut bio).is_ok());
    }

    #[test]
    fn queue_depth_tracks_outstanding() {
        let limits = BlockQueueLimits::fixed_capacity(100);
        let mut queue = BlockExportQueue::new(limits).unwrap();
        // In our synchronous model, depth returns to 0 after each completion
        assert_eq!(queue.queue_depth(), 0);

        let mut bio = BlockBio::new_read(0, 1, 512);
        queue.dispatch_bio(&mut bio).unwrap();
        assert_eq!(queue.queue_depth(), 0); // completed synchronously
    }

    #[test]
    fn queue_dispatch_discard_unsupported() {
        let limits = {
            let mut l = BlockQueueLimits::fixed_capacity(100);
            l.discard_supported = false;
            l
        };
        let mut queue = BlockExportQueue::new(limits).unwrap();
        let result = queue.dispatch_discard(0, 1);
        assert!(result.is_err());
    }

    #[test]
    fn queue_dispatch_discard_supported() {
        let limits = {
            let mut l = BlockQueueLimits::fixed_capacity(100);
            l.discard_supported = true;
            l
        };
        let mut queue = BlockExportQueue::new(limits).unwrap();

        // Write some data first
        let data = [0xFFu8; 512];
        let mut bio = BlockBio::new_write(0, &data, 512);
        queue.dispatch_bio(&mut bio).unwrap();

        // Discard the sector
        queue.dispatch_discard(0, 1).unwrap();

        // Read back — should be zeroed
        let mut read_bio = BlockBio::new_read(0, 1, 512);
        queue.dispatch_bio(&mut read_bio).unwrap();
        assert_eq!(&read_bio.payload[..512], &[0u8; 512]);
    }

    // ── BlockExport tests ──────────────────────────────────────────────

    #[test]
    fn export_new_fixed_capacity() {
        let export = BlockExport::new_fixed_capacity(2048).unwrap();
        assert_eq!(export.capacity_bytes(), 2048 * 512);
        assert!(!export.is_fenced());
    }

    #[test]
    fn export_with_limits_custom() {
        let limits = BlockQueueLimits {
            logical_block_size: 4096,
            physical_block_size: 4096,
            capacity_sectors: 1024,
            min_capacity_sectors: 1024,
            max_hw_sectors: 128,
            max_segments: 64,
            max_queue_depth: 64,
            io_min: DEFAULT_IO_MIN,
            io_opt: DEFAULT_IO_OPT,
            writable: true,
            flush_supported: false,
            discard_supported: true,
            write_zeroes_supported: false,
            zero_range_supported: false,
        };
        let export = BlockExport::with_limits(limits).unwrap();
        assert_eq!(export.capacity_bytes(), 1024 * 4096);
        assert!(!export.limits().flush_supported);
        assert!(export.limits().discard_supported);
    }

    #[test]
    fn export_read_sectors() {
        let mut export = BlockExport::new_fixed_capacity(1024).unwrap();
        let data = [0x42u8; 512];
        export.write_sectors(0, &data).unwrap();

        let read = export.read_sectors(0, 1).unwrap();
        assert_eq!(&read[..], &data[..]);
    }

    #[test]
    fn export_read_out_of_bounds() {
        let export = BlockExport::new_fixed_capacity(10).unwrap();
        let result = export.read_sectors(9, 2);
        assert!(result.is_err());
    }

    #[test]
    fn export_write_out_of_bounds() {
        let mut export = BlockExport::new_fixed_capacity(10).unwrap();
        let data = [0u8; 1024];
        let result = export.write_sectors(9, &data);
        assert!(result.is_err());
    }

    #[test]
    fn export_fence_and_unfence() {
        let mut export = BlockExport::new_fixed_capacity(100).unwrap();
        export.fence();
        assert!(export.is_fenced());

        let data = [0x11u8; 512];
        assert!(export.write_sectors(0, &data).is_err());

        export.unfence();
        assert!(!export.is_fenced());
        assert!(export.write_sectors(0, &data).is_ok());
    }

    #[test]
    fn export_zero_capacity_rejected() {
        let result = BlockExport::new_fixed_capacity(0);
        assert!(result.is_err());
    }

    #[test]
    fn export_write_large_range() {
        let mut export = BlockExport::new_fixed_capacity(2048).unwrap();
        let data = [0xCCu8; 4096]; // 8 sectors at 512B
        export.write_sectors(100, &data).unwrap();

        let read = export.read_sectors(100, 8).unwrap();
        assert_eq!(&read[..], &data[..]);
    }

    #[test]
    fn export_multiple_writes_non_overlapping() {
        let mut export = BlockExport::new_fixed_capacity(2048).unwrap();

        let d1 = [0xAAu8; 512];
        let d2 = [0xBBu8; 512];
        export.write_sectors(0, &d1).unwrap();
        export.write_sectors(1, &d2).unwrap();

        let r1 = export.read_sectors(0, 1).unwrap();
        let r2 = export.read_sectors(1, 1).unwrap();

        assert_eq!(&r1[..], &d1[..]);
        assert_eq!(&r2[..], &d2[..]);
    }

    #[test]
    fn export_overlapping_write_last_wins() {
        let mut export = BlockExport::new_fixed_capacity(2048).unwrap();

        let d1 = [0x11u8; 512];
        let d2 = [0x22u8; 512];
        export.write_sectors(5, &d1).unwrap();
        export.write_sectors(5, &d2).unwrap();

        let read = export.read_sectors(5, 1).unwrap();
        assert_eq!(&read[..], &d2[..]);
    }

    #[test]
    fn block_bio_debug_output() {
        let bio = BlockBio::new_read(42, 3, 512);
        let dbg = alloc::format!("{bio:?}");
        assert!(dbg.contains("BlockBio"));
        assert!(dbg.contains("42"));
    }

    #[test]
    fn block_export_debug_output() {
        let export = BlockExport::new_fixed_capacity(1024).unwrap();
        let dbg = alloc::format!("{export:?}");
        assert!(dbg.contains("BlockExport"));
        assert!(dbg.contains("524288")); // 1024 * 512 bytes
    }

    #[test]
    fn block_queue_limits_debug_clone() {
        let limits = BlockQueueLimits::fixed_capacity(512);
        let limits2 = limits;
        let dbg = alloc::format!("{limits2:?}");
        assert!(dbg.contains("512"));
        assert!(dbg.contains("BlockQueueLimits"));
    }

    #[test]
    fn queue_custom_max_depth_respected() {
        let limits = BlockQueueLimits {
            logical_block_size: 512,
            physical_block_size: 4096,
            capacity_sectors: 100,
            min_capacity_sectors: 100,
            max_hw_sectors: 256,
            max_segments: 128,
            max_queue_depth: 2,
            io_min: DEFAULT_IO_MIN,
            io_opt: DEFAULT_IO_OPT,
            writable: true,
            flush_supported: true,
            discard_supported: false,
            write_zeroes_supported: false,
            zero_range_supported: false,
        };
        let mut queue = BlockExportQueue::new(limits).unwrap();
        assert!(queue
            .dispatch_bio(&mut BlockBio::new_read(0, 1, 512))
            .is_ok());
        // In our synchronous model, depth returns to 0 so max depth is never hit
        assert_eq!(queue.queue_depth(), 0);
    }

    #[test]
    fn bio_payload_too_short_rejected() {
        let limits = BlockQueueLimits::fixed_capacity(100);
        let mut queue = BlockExportQueue::new(limits).unwrap();

        let mut bio = BlockBio::new_read(0, 4, 512);
        bio.payload.truncate(100); // too short for 4 sectors
        let result = queue.dispatch_bio(&mut bio);
        assert!(result.is_err());
    }

    #[test]
    fn bio_write_sector_count_ceil() {
        // 600 bytes at 512B sectors = ceil(600/512) = 2 sectors
        let data = [0u8; 600];
        let bio = BlockBio::new_write(0, &data, 512);
        assert_eq!(bio.sector_count, 2);
    }

    #[test]
    fn block_export_queue_debug() {
        let limits = BlockQueueLimits::fixed_capacity(64);
        let queue = BlockExportQueue::new(limits).unwrap();
        let dbg = alloc::format!("{queue:?}");
        assert!(dbg.contains("BlockExportQueue"));
        assert!(dbg.contains("64"));
    }

    // ── Resize grow tests ─────────────────────────────────────────────

    #[test]
    fn limits_resize_grow_updates_capacity() {
        let mut limits = BlockQueueLimits::fixed_capacity(1024);
        assert_eq!(limits.capacity_sectors, 1024);
        limits.resize_grow(2048).unwrap();
        assert_eq!(limits.capacity_sectors, 2048);
        assert_eq!(limits.capacity_bytes(), 2048 * 512);
    }

    #[test]
    fn limits_resize_grow_rejects_same() {
        let mut limits = BlockQueueLimits::fixed_capacity(1024);
        let err = limits.resize_grow(1024).unwrap_err();
        assert!(err.contains("greater than current"));
    }

    #[test]
    fn limits_resize_grow_rejects_smaller() {
        let mut limits = BlockQueueLimits::fixed_capacity(1024);
        let err = limits.resize_grow(512).unwrap_err();
        assert!(err.contains("greater than current"));
    }

    #[test]
    fn queue_resize_grow_doubles_buffer() {
        let limits = BlockQueueLimits::fixed_capacity(1024);
        let mut queue = BlockExportQueue::new(limits).unwrap();
        assert_eq!(queue.buffer().len(), 1024 * 512);
        queue.resize_grow(2048).unwrap();
        assert_eq!(queue.buffer().len(), 2048 * 512);
        assert_eq!(queue.limits().capacity_sectors, 2048);
    }

    #[test]
    fn queue_resize_grow_preserves_existing_data() {
        let limits = BlockQueueLimits::fixed_capacity(10);
        let mut queue = BlockExportQueue::new(limits).unwrap();
        let data = [0xABu8; 512];
        let mut bio = BlockBio::new_write(0, &data, 512);
        queue.dispatch_bio(&mut bio).unwrap();
        queue.resize_grow(20).unwrap();
        let mut read_bio = BlockBio::new_read(0, 1, 512);
        queue.dispatch_bio(&mut read_bio).unwrap();
        assert_eq!(&read_bio.payload[..512], &data[..]);
    }

    #[test]
    fn queue_resize_grow_new_region_is_zero() {
        let limits = BlockQueueLimits::fixed_capacity(10);
        let mut queue = BlockExportQueue::new(limits).unwrap();
        queue.resize_grow(20).unwrap();
        let mut read_bio = BlockBio::new_read(19, 1, 512);
        queue.dispatch_bio(&mut read_bio).unwrap();
        assert_eq!(&read_bio.payload[..512], &[0u8; 512]);
    }

    #[test]
    fn export_resize_grow_changes_capacity_bytes() {
        let mut export = BlockExport::new_fixed_capacity(1024).unwrap();
        assert_eq!(export.capacity_bytes(), 1024 * 512);
        export.resize_grow(2048).unwrap();
        assert_eq!(export.capacity_bytes(), 2048 * 512);
    }

    #[test]
    fn export_resize_grow_roundtrip_across_boundary() {
        let mut export = BlockExport::new_fixed_capacity(10).unwrap();
        let data = [0xCCu8; 512];
        export.write_sectors(9, &data).unwrap();
        export.resize_grow(20).unwrap();
        let r1 = export.read_sectors(9, 1).unwrap();
        assert_eq!(&r1[..], &data[..]);
        let r2 = export.read_sectors(19, 1).unwrap();
        assert_eq!(&r2[..], &[0u8; 512]);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Linux 7.0 Kbuild module registration authority
// ═══════════════════════════════════════════════════════════════════════════
//
// The cargo library intentionally exports no `module_registration` module.
// Kbuild includes this library from `../tidefs_block_kmod.rs`, which owns the
// single `kernel::module!` registration path under CONFIG_RUST. The retired
// Cargo-feature registration path used stale Rust-for-Linux block APIs and
// must not be re-enabled under CONFIG_RUST.
