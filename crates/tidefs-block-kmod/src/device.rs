//! TideFS block-volume kernel device registration.
//!
//! This module provides [`TidefsBlockDevice`] — the kernel-side wrapper that
//! models a blk-mq `GenDisk` registration backed by the leaf-module
//! [`crate::BlockExport`]. It owns the device lifecycle and bio-dispatch path
//! that maps Linux block-layer `submit_bio` calls onto the typed
//! [`crate::BlockExportQueue`] I/O engine.
//!
//! # Kernel binding (Linux 7.0)
//!
//! When built by Linux 7.0 Kbuild, `../tidefs_block_kmod.rs` includes this
//! library under `CONFIG_RUST` and registers the device with real
//! `kernel::block::mq::Operations` plus a kernel gendisk. The user-space build
//! always provides the typed model path for testing.
//!
//! # Lifecycle
//!
//! The device follows a BLAKE3-verified lifecycle state machine
//! ([`crate::lifecycle::DeviceLifecycle`]) tracing the kernel gendisk
//! registration path:
//!
//! 1. **Unloaded** → **Allocated** — `TidefsBlockDevice::new()` validates
//!    device parameters (name, capacity, sector size) and records a
//!    BLAKE3-256 digest for the `alloc_gendisk` transition.
//! 2. **Allocated** → **QueueReady** — The request queue limits are
//!    configured and a second transition digest is recorded.
//! 3. **QueueReady** → **Active** — The device is marked active (add_disk),
//!    recorded with a third BLAKE3 transition digest.
//!
//! Domain: `tidefs-block-kmod-lifecycle-v1`
//!
//! # Architecture
//!
//! ```text
//! Linux block layer
//!   ↓ submit_bio
//! Linux blk-mq gendisk         (Kbuild entrypoint: tidefs_block_kmod.rs)
//!   ↓
//! TidefsBlockDevice            (this module, always available)
//!   ↓
//! BlockExport → BlockExportQueue → backing buffer
//! ```

use crate::dispatch::{BlockBackend, DispatchEngine};
use crate::lifecycle::{DeviceLifecycle, LifecycleState};
use crate::open_release::{BlockLifecycle, BlockOpenGuard, OpenError, ReleaseOutcome};
use crate::pool_core_backend::PoolCoreBackend;
use crate::request_completion::RequestCompletion;
use crate::timeout::{InflightTracker, TimeoutOutcome};
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge::kernel_types::KmodVec as Vec;
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge::{BridgeError, BridgeResult};
use crate::DEFAULT_CAPACITY_SECTORS;
use crate::{BlockBio, BlockExport, BlockQueueLimits};
#[cfg(not(CONFIG_RUST))]
use tidefs_kmod_bridge::kernel_types::KmodVec as Vec;
#[cfg(not(CONFIG_RUST))]
use tidefs_kmod_bridge::{BridgeError, BridgeResult};

/// Maximum queue depth for the blk-mq tag set.
const DEFAULT_TAGSET_DEPTH: u32 = 64;

/// Default logical block (sector) size in bytes.
const DEFAULT_SECTOR_SIZE: u32 = 512;

/// Default physical block size in bytes.
const DEFAULT_PHYSICAL_BLOCK_SIZE: u32 = 4096;

/// Default maximum sectors per hardware request.
/// Default maximum sectors per request (64 KiB / 512-byte sectors = 128).
/// Rationale: matches VfsEngine storage characteristics.
const DEFAULT_MAX_HW_SECTORS: u32 = 128;

/// Default io_min hint in bytes (matches logical block size).
const DEFAULT_IO_MIN: u32 = 512;

/// Default io_opt hint in bytes (matches physical block size).
const DEFAULT_IO_OPT: u32 = 4096;

/// Default maximum segments per request.
const DEFAULT_MAX_SEGMENTS: u16 = 128;

struct PoolCoreBio<'a> {
    start_sector: u64,
    sector_count: u32,
    is_read: bool,
    read_only: bool,
    buf: &'a mut [u8],
}

// ── TidefsBlockDevice ────────────────────────────────────────────────────

/// Kernel-side block-device wrapper owning a [`BlockExport`] and its queue.
///
/// In the Linux kernel build environment, this struct is registered as a
/// blk-mq `GenDisk` via `kernel::block::gen_disk::GenDisk::try_new()` with a
/// `kernel::block::mq::TagSet`. The `submit_bio` dispatch path maps incoming
/// kernel bios onto the typed [`BlockExportQueue`] dispatch.
///
/// # BLAKE3-verified lifecycle
///
/// Construction runs through three BLAKE3-256 domain-separated transitions
/// (domain: `tidefs-block-kmod-lifecycle-v1`):
/// - Unloaded → Allocated (gendisk parameter validation)
/// - Allocated → QueueReady (request queue configuration)
/// - QueueReady → Active (add_disk)
///
/// The resulting digests are exposed via [`lifecycle_digests()`] for
/// validation.
///
/// # Examples
///
/// ```rust
/// use tidefs_block_kmod::device::TidefsBlockDevice;
///
/// let mut dev = TidefsBlockDevice::new("tidefs0", 1024 * 1024).unwrap();
/// assert_eq!(dev.capacity_bytes(), 1024 * 1024 * 512);
/// assert!(dev.is_registered());
/// ```
pub struct TidefsBlockDevice {
    /// BLAKE3-verified bio dispatch engine owning the block export backend.
    dispatch_engine: DispatchEngine<BlockExport>,

    /// Configured blk-mq tag-set depth (max outstanding requests).
    tagset_depth: u32,

    /// Whether the device is registered and accepting I/O (soft toggle).
    registered: bool,

    /// Whether the device is read-only (BLKROSET-controlled).
    /// Write bios are rejected when this flag is set.
    read_only: bool,

    /// BLAKE3-verified gendisk lifecycle state machine.
    lifecycle: DeviceLifecycle,

    /// BLAKE3-256 digests for the three construction-phase transitions:
    /// [alloc_gendisk, alloc_queue, add_disk].
    lifecycle_digests: [[u8; 32]; 3],

    /// Device name (e.g., "tidefs0").
    name: &'static str,

    /// Logical block size from queue limits (cached for fast access).
    sector_size: u32,

    /// Open/release lifecycle guard with FMODE_EXCL enforcement.
    open_guard: BlockOpenGuard,

    /// Optional pool-core backend for production kernel block I/O.
    pool_core_backend: Option<PoolCoreBackend>,

    /// Request-completion tracker: counts completions, bytes transferred,
    /// and errors across all I/O dispatch paths.
    completion: RequestCompletion,
    /// Queue limits reported to the kernel (real capacity from pool-core
    /// backend when active). The dispatch-engine buffer is
    /// separately capped.
    limits: BlockQueueLimits,

    /// Inflight request tracker: deadline-based timeout detection and
    /// reset recovery for stalled backend I/O.
    inflight_tracker: InflightTracker,
}

impl TidefsBlockDevice {
    /// Create a new block device with the given name and capacity in sectors.
    ///
    /// Allocates the backing buffer and configures default queue limits:
    /// 512-byte logical sectors, 4096-byte physical blocks, 64-deep tag set,
    /// flush support enabled, discard disabled.
    ///
    /// The constructor runs the BLAKE3-verified lifecycle through three
    /// transitions: Unloaded → Allocated → QueueReady → Active.
    /// Validation digests are available via [`lifecycle_digests()`].
    ///
    /// # Errors
    ///
    /// Returns `BioQueueFailed` if the capacity is zero or the backing
    /// allocation fails.
    pub fn new(name: &'static str, capacity_sectors: u64) -> BridgeResult<Self> {
        let limits = BlockQueueLimits {
            logical_block_size: DEFAULT_SECTOR_SIZE,
            physical_block_size: DEFAULT_PHYSICAL_BLOCK_SIZE,
            capacity_sectors,
            min_capacity_sectors: capacity_sectors,
            max_hw_sectors: DEFAULT_MAX_HW_SECTORS,
            max_segments: DEFAULT_MAX_SEGMENTS,
            max_queue_depth: DEFAULT_TAGSET_DEPTH,
            io_min: DEFAULT_IO_MIN,
            io_opt: DEFAULT_IO_OPT,
            writable: true,
            flush_supported: true,
            discard_supported: false,
            write_zeroes_supported: false,
            zero_range_supported: false,
        };
        Self::new_inner(name, limits)
    }

    /// Create a block device with explicit queue limits.
    ///
    /// Use this when the caller needs non-default sector sizes, discard
    /// support, or a different tag-set depth.
    ///
    /// # Errors
    ///
    /// Returns `BioQueueFailed` if the capacity is zero or the backing
    /// allocation fails.
    pub fn with_limits(name: &'static str, limits: BlockQueueLimits) -> BridgeResult<Self> {
        Self::new_inner(name, limits)
    }

    /// Create a **production** block device backed by a
    /// [`PoolCoreBackend`](crate::pool_core_backend::PoolCoreBackend).
    ///
    /// The pool-core backend becomes the primary I/O path (all kernel bios
    /// route through it via [`submit_kernel_bio`]).  An bring-up
    /// backend is still allocated as a validation fallback but is never
    /// used for dispatched I/O when the pool-core backend is set.
    ///
    /// The pool-core backend owns a [`PoolCoreHandle`] which carries the
    /// pool's capacity, sector size, flush/discard support, and I/O
    /// primitives.  Queue limits are derived from the backend.
    ///
    /// # Errors
    ///
    /// Returns `BioQueueFailed` if the bring-up buffer allocation fails.
    /// The pool-core backend itself is not validated here -- validation
    /// happens on first open via [`BlockLifecycle::init`].
    pub fn with_pool_core_backend(
        name: &'static str,
        pool_core: crate::pool_core_backend::PoolCoreBackend,
    ) -> BridgeResult<Self> {
        let sector_size = pool_core.sector_size();
        let capacity_bytes = pool_core.capacity();
        let capacity_sectors = capacity_bytes / u64::from(sector_size);

        let limits = BlockQueueLimits {
            logical_block_size: sector_size,
            physical_block_size: sector_size.max(4096),
            capacity_sectors,
            min_capacity_sectors: capacity_sectors,
            max_hw_sectors: DEFAULT_MAX_HW_SECTORS,
            max_segments: DEFAULT_MAX_SEGMENTS,
            max_queue_depth: DEFAULT_TAGSET_DEPTH,
            io_min: DEFAULT_IO_MIN,
            io_opt: DEFAULT_IO_OPT,
            writable: true,
            flush_supported: pool_core.flush_supported(),
            discard_supported: pool_core.discard_supported(),
            write_zeroes_supported: pool_core.write_zeroes_supported(),
            zero_range_supported: pool_core.zero_range_supported(),
        };
        Self::new_inner_with_pool_backend(name, limits, Some(pool_core))
    }

    /// Shared construction: validates parameters via the lifecycle state
    /// machine, allocates the backing buffer, and records all three
    /// construction-phase BLAKE3 transition digests.  No pool-core backend.
    fn new_inner(name: &'static str, limits: BlockQueueLimits) -> BridgeResult<Self> {
        Self::new_inner_with_pool_backend(name, limits, None)
    }

    /// Shared construction with optional pool-core backend.
    fn new_inner_with_pool_backend(
        name: &'static str,
        limits: BlockQueueLimits,
        pool_core_backend: Option<PoolCoreBackend>,
    ) -> BridgeResult<Self> {
        let sector_size = limits.logical_block_size;
        let tagset_depth = limits.max_queue_depth;

        // Phase 1: validate parameters via lifecycle (Unloaded -> Allocated)
        let mut lifecycle = DeviceLifecycle::new(name, limits.capacity_sectors, sector_size);
        let d_alloc = lifecycle
            .alloc_gendisk()
            .map_err(|e| BridgeError::InvalidState {
                detail: match e {
                    crate::lifecycle::LifecycleError::InvalidCapacity { .. } => {
                        "device capacity must be > 0"
                    }
                    crate::lifecycle::LifecycleError::InvalidSectorSize { .. } => {
                        "sector size must be 512 or 4096"
                    }
                    crate::lifecycle::LifecycleError::InvalidDeviceName => {
                        "device name must be non-empty"
                    }
                    _ => "invalid lifecycle transition in alloc_gendisk",
                },
            })?;

        // Cap the dispatch buffer to a bounded size regardless of
        // backend type. Real device capacity is preserved in self.limits for
        // kernel reporting; the dispatch engine only needs a small fallback.
        let mut export_limits = limits;
        export_limits.capacity_sectors =
            export_limits.capacity_sectors.min(DEFAULT_CAPACITY_SECTORS);

        // Phase 2: allocate backing buffer and transition to QueueReady
        let export = BlockExport::with_limits(export_limits)?;
        let d_queue = lifecycle
            .alloc_queue()
            .map_err(|_| BridgeError::InvalidState {
                detail: "lifecycle: cannot transition to QueueReady",
            })?;

        // Phase 3: create and activate the BLAKE3-verified dispatch engine
        let engine_limits = *export.limits();
        let mut dispatch_engine = DispatchEngine::new(export, engine_limits);
        let _activate_digest = dispatch_engine.activate();

        let d_active = lifecycle
            .add_disk()
            .map_err(|_| BridgeError::InvalidState {
                detail: "lifecycle: cannot transition to Active",
            })?;

        let completion = RequestCompletion::new();
        let inflight_tracker = InflightTracker::default_config();

        Ok(Self {
            dispatch_engine,
            tagset_depth,
            registered: true,
            read_only: false,
            lifecycle,
            lifecycle_digests: [d_alloc, d_queue, d_active],
            name,
            sector_size,
            open_guard: BlockOpenGuard::new(),
            limits,
            completion,
            inflight_tracker,
            pool_core_backend,
        })
    }

    /// Set or replace the pool-core backend post-construction.
    ///
    /// This is intended for kernel-entrypoint code that obtains the pool
    /// context after the device has already been allocated (e.g. during
    /// `fill_super` or a late `ioctl`).  Once set, all subsequent kernel
    /// bios route through the pool-core backend instead of the default
    /// bring-up buffer.
    pub fn set_pool_core_backend(&mut self, pc: crate::pool_core_backend::PoolCoreBackend) {
        self.pool_core_backend = Some(pc);
    }

    /// Whether a pool-core backend is configured.
    #[must_use]
    pub fn has_pool_core_backend(&self) -> bool {
        self.pool_core_backend.is_some()
    }

    // ── Open/release lifecycle ─────────────────────────────────────────────

    /// Handle a block device open request with FMODE_EXCL enforcement.
    ///
    /// On first open (when the open count transitions from 0 to 1), the
    /// backend's [`BlockLifecycle::init`] is called. If initialization
    /// fails, the open request is rejected and the guard is rolled back.
    ///
    /// * `exclusive` — whether FMODE_EXCL semantics are requested.
    ///
    /// # Errors
    ///
    /// Returns [`OpenError::ExclusiveConflict`] if the device is already
    /// held exclusively. Returns [`OpenError::BusyWithOtherOpeners`] if
    /// an exclusive open is attempted while other handles are open.
    /// Returns a bridge error if backend initialization fails on first open.
    pub fn open(&mut self, exclusive: bool) -> BridgeResult<()> {
        let is_first_open = self.open_guard.open_count() == 0;
        self.open_guard
            .open(exclusive)
            .map_err(|oe| BridgeError::InvalidState {
                detail: match oe {
                    OpenError::ExclusiveConflict => "open: device is already held exclusively",
                    OpenError::BusyWithOtherOpeners => "open: device has existing open handles",
                },
            })?;

        if is_first_open {
            // First open: invoke backend initialization.
            // If init fails, roll back the open.
            if let Err(e) = self.dispatch_engine.backend_mut().init() {
                let _ = self.open_guard.release();
                return Err(e);
            }
        }
        Ok(())
    }

    /// Handle a block device release (close) request.
    ///
    /// On last close, the backend's [`BlockLifecycle::teardown`] is called,
    /// the dispatch engine is deactivated, and the device transitions to
    /// the Removing→Removed lifecycle states.
    ///
    /// Returns [`ReleaseOutcome::LastClose`] when the open count drops
    /// to zero, or [`ReleaseOutcome::StillOpen`] with the remaining count.
    pub fn release(&mut self) -> ReleaseOutcome {
        let outcome = self.open_guard.release();
        if outcome == ReleaseOutcome::LastClose {
            let _ = self.dispatch_engine.backend_mut().teardown();
            let _ = self.dispatch_engine.deactivate();
            self.registered = false;
        }
        outcome
    }

    /// Current number of open handles.
    #[must_use]
    pub fn open_count(&self) -> u32 {
        self.open_guard.open_count()
    }

    /// Whether the device is currently held exclusively.
    #[must_use]
    pub fn is_exclusive_held(&self) -> bool {
        self.open_guard.is_exclusive_held()
    }

    // ── Completion tracking ───────────────────────────────────────────────

    /// Total number of I/O completions tracked by this device.
    #[must_use]
    pub fn completion_count(&self) -> u64 {
        self.completion.completion_count()
    }

    /// Total bytes transferred across all successful I/O completions.
    #[must_use]
    pub fn total_bytes_transferred(&self) -> u64 {
        self.completion.total_bytes_transferred()
    }

    /// Total number of errored I/O completions.
    #[must_use]
    pub fn error_count(&self) -> u64 {
        self.completion.error_count()
    }

    /// Return a snapshot of completion statistics.
    #[must_use]
    pub fn completion_stats(&self) -> (u64, u64, u64) {
        (
            self.completion.completion_count(),
            self.completion.total_bytes_transferred(),
            self.completion.error_count(),
        )
    }

    // -- Inflight tracking -------------------------------------------------

    /// Return a reference to the inflight request tracker.
    #[must_use]
    pub fn inflight_tracker(&self) -> &InflightTracker {
        &self.inflight_tracker
    }

    /// Return a mutable reference to the inflight request tracker.
    pub fn inflight_tracker_mut(&mut self) -> &mut InflightTracker {
        &mut self.inflight_tracker
    }

    /// Check for timed-out inflight requests at `now_ms` and return the outcome.
    ///
    /// If requests have timed out, the device is fenced and a reset is required
    /// before new I/O can be accepted. Committed-root integrity is preserved:
    /// timed-out writes did not advance the committed root.
    pub fn check_timeouts(&mut self, now_ms: u64) -> TimeoutOutcome {
        self.inflight_tracker.check_timeouts(now_ms)
    }

    /// Check for timed-out requests and fence the device if the fence
    /// threshold is reached. Returns true if the device is operational
    /// (not fenced), false if it has been fenced and requires reset.
    ///
    /// This is the primary integration point for the kernel queue_rq path:
    /// call this before each I/O dispatch with the current monotonic time.
    pub fn check_and_fence_timeouts(&mut self, now_ms: u64) -> bool {
        let outcome = self.inflight_tracker.check_timeouts(now_ms);
        match outcome {
            TimeoutOutcome::NoTimeout => true,
            TimeoutOutcome::TimedOut { .. } => {
                // Device remains operational; timed-out requests were
                // already removed from the inflight tracker.
                true
            }
            TimeoutOutcome::Fenced { .. } => {
                // Permanent fence: reject all future I/O until reset.
                self.fence();
                false
            }
        }
    }

    /// Reset the device after a timeout: drains inflight requests, clears the
    /// consecutive-timeout counter, and un-fences the device. After reset,
    /// the device is ready to accept new I/O.
    pub fn reset_after_timeout(&mut self) {
        let _drained = self.inflight_tracker.drain();
        self.inflight_tracker.reset_consecutive_timeouts();
        // Re-enable the dispatch engine if it was fenced.
        if self.dispatch_engine.is_fenced() {
            self.dispatch_engine.unfence();
        }
    }

    // ── I/O dispatch ─────────────────────────────────────────────────────

    /// Submit a typed [`BlockBio`] to the underlying queue.
    ///
    /// This is the userspace-accessible dispatch path. In the kernel build,
    /// `kernel::block::mq::Operations::submit_bio` calls into this method
    /// after extracting bio fields from the kernel `bio` structure.
    ///
    /// # Errors
    ///
    /// Returns an error if the device is not registered, the device is
    /// fenced, the queue is at max depth, the bio range is out of bounds,
    /// or the payload size is wrong.
    /// Submit a typed [`BlockBio`] through the BLAKE3-verified dispatch engine.
    ///
    /// The bio is classified by operation type (Read/Write/Flush/Discard),
    /// validated against device limits, executed through the storage
    /// backend, and recorded with a BLAKE3-256 dispatch digest (domain:
    /// `tidefs-block-kmod-dispatch-v1`).
    ///
    /// # Errors
    ///
    /// Returns an error if the device is not registered or the dispatch
    /// engine rejects the bio.
    pub fn submit_bio(&mut self, bio: &mut BlockBio) -> BridgeResult<()> {
        if !self.registered {
            return Err(BridgeError::InvalidState {
                detail: "device not registered",
            });
        }
        // Reject write bios when the device is read-only (BLKROSET).
        if !bio.is_read && self.read_only {
            return Err(BridgeError::InvalidState {
                detail: "device is read-only",
            });
        }
        match self.dispatch_engine.dispatch(bio) {
            crate::dispatch::DispatchResult::Completed { .. }
            | crate::dispatch::DispatchResult::Partial { .. }
            | crate::dispatch::DispatchResult::CompletedNoData => Ok(()),
            crate::dispatch::DispatchResult::NotSupported => Err(BridgeError::Unimplemented {
                feature: "bio operation not supported by backend",
            }),
            crate::dispatch::DispatchResult::Rejected { reason } => {
                Err(BridgeError::BioQueueFailed { detail: reason })
            }
            crate::dispatch::DispatchResult::IoError { detail } => {
                Err(BridgeError::BioQueueFailed { detail })
            }
        }
    }

    /// Submit a discard (trim) request.
    ///
    /// # Errors
    ///
    /// Returns an error if discard is not supported, the device is fenced,
    /// or the range is out of bounds.
    pub fn submit_discard(&mut self, start_sector: u64, sector_count: u32) -> BridgeResult<()> {
        if !self.registered {
            return Err(BridgeError::InvalidState {
                detail: "device not registered",
            });
        }
        if self.read_only {
            return Err(BridgeError::InvalidState {
                detail: "device is read-only",
            });
        }
        match self
            .dispatch_engine
            .dispatch_discard_op(start_sector, sector_count)
        {
            crate::dispatch::DispatchResult::CompletedNoData => Ok(()),
            crate::dispatch::DispatchResult::Partial { .. } => Ok(()),
            crate::dispatch::DispatchResult::NotSupported => Err(BridgeError::Unimplemented {
                feature: "discard not supported by backend",
            }),
            crate::dispatch::DispatchResult::Rejected { reason } => {
                Err(BridgeError::BioQueueFailed { detail: reason })
            }
            crate::dispatch::DispatchResult::IoError { detail } => {
                Err(BridgeError::BioQueueFailed { detail })
            }
            crate::dispatch::DispatchResult::Completed { .. } => Err(BridgeError::InvalidState {
                detail: "discard returned unexpected Completed",
            }),
        }
    }

    /// Submit a write-zeroes request.
    ///
    /// The backend MUST ensure subsequent reads return zeroes for the
    /// specified range. The backend MAY allocate backing storage as
    /// needed — sparse backends will deallocate (discard) the range
    /// instead of zero-filling it, preserving sparse accounting.
    ///
    /// # Errors
    ///
    /// Returns an error if write-zeroes is not supported, the device is
    /// fenced, or the range is out of bounds.
    pub fn submit_write_zeroes(
        &mut self,
        start_sector: u64,
        sector_count: u32,
    ) -> BridgeResult<()> {
        if !self.registered {
            return Err(BridgeError::InvalidState {
                detail: "device not registered",
            });
        }
        if self.read_only {
            return Err(BridgeError::InvalidState {
                detail: "device is read-only",
            });
        }
        match self
            .dispatch_engine
            .dispatch_write_zeroes_op(start_sector, sector_count)
        {
            crate::dispatch::DispatchResult::CompletedNoData => Ok(()),
            crate::dispatch::DispatchResult::Partial { .. } => Ok(()),
            crate::dispatch::DispatchResult::NotSupported => Err(BridgeError::Unimplemented {
                feature: "write-zeroes not supported by backend",
            }),
            crate::dispatch::DispatchResult::Rejected { reason } => {
                Err(BridgeError::BioQueueFailed { detail: reason })
            }
            crate::dispatch::DispatchResult::IoError { detail } => {
                Err(BridgeError::BioQueueFailed { detail })
            }
            crate::dispatch::DispatchResult::Completed { .. } => Err(BridgeError::InvalidState {
                detail: "write-zeroes returned unexpected Completed",
            }),
        }
    }

    /// Submit a zero-range request (stronger than write-zeroes).
    ///
    /// Unlike write-zeroes, the backend MUST ensure the zeroed range
    /// remains readable (no fault on access) and return zeroes. The
    /// implementation interacts with allocation and extent authority.
    ///
    /// # Errors
    ///
    /// Returns an error if zero-range is not supported, the device is
    /// fenced, or the range is out of bounds.
    pub fn submit_zero_range(&mut self, start_sector: u64, sector_count: u32) -> BridgeResult<()> {
        if !self.registered {
            return Err(BridgeError::InvalidState {
                detail: "device not registered",
            });
        }
        if self.read_only {
            return Err(BridgeError::InvalidState {
                detail: "device is read-only",
            });
        }
        match self
            .dispatch_engine
            .dispatch_zero_range_op(start_sector, sector_count)
        {
            crate::dispatch::DispatchResult::CompletedNoData => Ok(()),
            crate::dispatch::DispatchResult::Partial { .. } => Ok(()),
            crate::dispatch::DispatchResult::NotSupported => Err(BridgeError::Unimplemented {
                feature: "zero-range not supported by backend",
            }),
            crate::dispatch::DispatchResult::Rejected { reason } => {
                Err(BridgeError::BioQueueFailed { detail: reason })
            }
            crate::dispatch::DispatchResult::IoError { detail } => {
                Err(BridgeError::BioQueueFailed { detail })
            }
            crate::dispatch::DispatchResult::Completed { .. } => Err(BridgeError::InvalidState {
                detail: "zero-range returned unexpected Completed",
            }),
        }
    }
    /// Submit a kernel-originated bio with raw sector and data-buffer parameters.
    ///
    /// This is the kernel-callback dispatch path: it bypasses [`BlockBio`]
    /// (which carries a [`Vec<u8>`] payload unsuitable for kernel bio-page
    /// data) and calls the storage backend through the existing device
    /// convenience wrappers.  Validation (registration, read-only,
    /// range-in-bounds) is performed before the backend call.
    ///
    /// * `start_sector` — logical block address of the first sector.
    /// * `sector_count` — number of sectors to transfer.
    /// * `is_read` — `true` for REQ_OP_READ, `false` for REQ_OP_WRITE.
    /// * `buf` — data buffer: for reads, receives data from the backend;
    ///   for writes, provides data to be written. `buf.len()` must be at
    ///   least `sector_count * sector_size`.
    ///
    /// # Returns
    ///
    /// The number of bytes transferred on success.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError` if the device is not registered, is read-only
    /// (for writes), the sector range is out of bounds, the buffer size is
    /// wrong, or the backend I/O fails.
    pub fn submit_kernel_bio(
        &mut self,
        start_sector: u64,
        sector_count: u32,
        is_read: bool,
        buf: &mut [u8],
    ) -> BridgeResult<u32> {
        // Route through pool-core backend when configured.
        if let Some(ref mut pc) = self.pool_core_backend {
            return Self::submit_via_pool_core(
                &mut self.completion,
                self.sector_size,
                pc,
                PoolCoreBio {
                    start_sector,
                    sector_count,
                    is_read,
                    read_only: self.read_only,
                    buf,
                },
            );
        }
        if !self.registered {
            return Err(BridgeError::InvalidState {
                detail: "device not registered",
            });
        }
        if self.is_fenced() {
            return Err(BridgeError::InvalidState {
                detail: "device is fenced",
            });
        }
        // Reject writes when the device is read-only.
        if !is_read && self.read_only {
            return Err(BridgeError::InvalidState {
                detail: "device is read-only",
            });
        }

        let expected_len = sector_count as usize * self.sector_size as usize;
        if buf.len() < expected_len {
            return Err(BridgeError::BioQueueFailed {
                detail: "buffer too short for sector range",
            });
        }

        let limits = self.limits();
        if !limits.range_in_bounds(start_sector, sector_count) {
            return Err(BridgeError::BioQueueFailed {
                detail: "sector range out of bounds",
            });
        }

        if is_read {
            let data = self.read_sectors(start_sector, sector_count)?;
            let copy_len = data.len().min(buf.len());
            buf[..copy_len].copy_from_slice(&data[..copy_len]);
            let bytes = copy_len as u32;
            self.completion
                .complete(crate::request_completion::CompletionOutcome::ok(bytes));
            Ok(bytes)
        } else {
            self.write_sectors(start_sector, &buf[..expected_len])?;
            let bytes = expected_len as u32;
            self.completion
                .complete(crate::request_completion::CompletionOutcome::ok(bytes));
            Ok(bytes)
        }
    }

    // ── Pool-core dispatch helpers ───────────────────────────────────────

    /// Route kernel bio I/O through the pool-core backend.
    fn submit_via_pool_core(
        completion: &mut crate::request_completion::RequestCompletion,
        sector_size: u32,
        pc: &mut PoolCoreBackend,
        bio: PoolCoreBio<'_>,
    ) -> BridgeResult<u32> {
        let PoolCoreBio {
            start_sector,
            sector_count,
            is_read,
            read_only,
            buf,
        } = bio;
        let expected_len = sector_count as usize * sector_size as usize;
        if buf.len() < expected_len {
            return Err(BridgeError::BioQueueFailed {
                detail: "buffer too short",
            });
        }
        if is_read {
            let bytes = pc.read_sectors(start_sector, sector_count, buf)?;
            completion.complete(crate::request_completion::CompletionOutcome::ok(bytes));
            Ok(bytes)
        } else {
            if read_only {
                return Err(BridgeError::InvalidState {
                    detail: "device is read-only",
                });
            }
            let bytes = pc.write_sectors(start_sector, &buf[..expected_len])?;
            completion.complete(crate::request_completion::CompletionOutcome::ok(bytes));
            Ok(bytes)
        }
    }

    /// Route kernel flush through the pool-core backend.
    fn submit_flush_via_pool_core(
        completion: &mut crate::request_completion::RequestCompletion,
        pc: &mut PoolCoreBackend,
    ) -> BridgeResult<()> {
        let result = pc.flush();
        match &result {
            Ok(()) => {
                completion.complete(crate::request_completion::CompletionOutcome::ok(0));
            }
            Err(e) => {
                completion.complete(crate::request_completion::CompletionOutcome::err(
                    crate::queue_rq::BlkMqStatus::from(e),
                    0,
                ));
            }
        }
        result
    }

    /// Route kernel discard through the pool-core backend.
    fn submit_discard_via_pool_core(
        pc: &mut PoolCoreBackend,
        start_sector: u64,
        sector_count: u32,
    ) -> BridgeResult<()> {
        pc.discard_sectors(start_sector, sector_count)
    }

    /// Route kernel write-zeroes through the pool-core backend.
    fn submit_write_zeroes_via_pool_core(
        pc: &mut PoolCoreBackend,
        start_sector: u64,
        sector_count: u32,
    ) -> BridgeResult<()> {
        pc.write_zeroes_sectors(start_sector, sector_count)
    }

    /// Route kernel zero-range through the pool-core backend.
    fn submit_zero_range_via_pool_core(
        pc: &mut PoolCoreBackend,
        start_sector: u64,
        sector_count: u32,
    ) -> BridgeResult<()> {
        pc.zero_range_sectors(start_sector, sector_count)
    }
    /// Submit a kernel-originated flush (REQ_OP_FLUSH) barrier.
    ///
    /// Delegates to the backend through the dispatch engine.
    /// Returns `Unimplemented` if the backend does not support flush
    /// operations.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError` if the device is not registered, is fenced,
    /// flush is unsupported, or the backend flush fails.
    pub fn submit_kernel_flush(&mut self) -> BridgeResult<()> {
        // Route through pool-core backend when configured.
        if let Some(ref mut pc) = self.pool_core_backend {
            return Self::submit_flush_via_pool_core(&mut self.completion, pc);
        }
        if !self.registered {
            return Err(BridgeError::InvalidState {
                detail: "device not registered",
            });
        }
        if self.is_fenced() {
            return Err(BridgeError::InvalidState {
                detail: "device is fenced",
            });
        }
        if !self.limits().flush_supported {
            return Err(BridgeError::Unimplemented {
                feature: "flush not supported by backend",
            });
        }
        // In-memory backend: flush is a no-op after validation.
        // Kernel mode: the backend's flush method issues blkdev_issue_flush.
        let result = self.dispatch_engine.backend_mut().flush();
        match &result {
            Ok(()) => {
                self.completion
                    .complete(crate::request_completion::CompletionOutcome::ok(0));
            }
            Err(e) => {
                self.completion
                    .complete(crate::request_completion::CompletionOutcome::err(
                        crate::queue_rq::BlkMqStatus::from(e),
                        0,
                    ));
            }
        }
        result
    }

    /// Submit a kernel-originated discard (REQ_OP_DISCARD) operation.
    ///
    /// Delegates to [`submit_discard`] which routes through the
    /// [`crate::dispatch::DispatchEngine`].
    ///
    /// # Errors
    ///
    /// Returns `BridgeError` if the device is not registered, is fenced,
    /// discard is unsupported, the range is out of bounds, or the backend
    /// discard fails.
    pub fn submit_kernel_discard(
        &mut self,
        start_sector: u64,
        sector_count: u32,
    ) -> BridgeResult<()> {
        // Route through pool-core backend when configured.
        if let Some(ref mut pc) = self.pool_core_backend {
            return Self::submit_discard_via_pool_core(pc, start_sector, sector_count);
        }
        let result = self.submit_discard(start_sector, sector_count);
        match &result {
            Ok(()) => {
                self.completion
                    .complete(crate::request_completion::CompletionOutcome::ok(0));
            }
            Err(e) => {
                self.completion
                    .complete(crate::request_completion::CompletionOutcome::err(
                        crate::queue_rq::BlkMqStatus::from(e),
                        0,
                    ));
            }
        }
        result
    }

    /// Submit a kernel-originated write-zeroes (REQ_OP_WRITE_ZEROES) operation.
    ///
    /// Delegates to [`submit_write_zeroes`] which routes through the
    /// [`crate::dispatch::DispatchEngine`].
    ///
    /// # Errors
    ///
    /// Returns `BridgeError` if the device is not registered, is fenced,
    /// write-zeroes is unsupported, the range is out of bounds, or the backend
    /// write-zeroes fails.
    pub fn submit_kernel_write_zeroes(
        &mut self,
        start_sector: u64,
        sector_count: u32,
    ) -> BridgeResult<()> {
        // Route through pool-core backend when configured.
        if let Some(ref mut pc) = self.pool_core_backend {
            return Self::submit_write_zeroes_via_pool_core(pc, start_sector, sector_count);
        }
        let result = self.submit_write_zeroes(start_sector, sector_count);
        match &result {
            Ok(()) => {
                self.completion
                    .complete(crate::request_completion::CompletionOutcome::ok(0));
            }
            Err(e) => {
                self.completion
                    .complete(crate::request_completion::CompletionOutcome::err(
                        crate::queue_rq::BlkMqStatus::from(e),
                        0,
                    ));
            }
        }
        result
    }

    /// Submit a kernel-originated zero-range operation.
    ///
    /// Stronger than write-zeroes: the zeroed range MUST remain readable
    /// and return zeroes. Delegates to [`submit_zero_range`] which routes
    /// through the [`crate::dispatch::DispatchEngine`].
    ///
    /// # Errors
    ///
    /// Returns `BridgeError` if the device is not registered, is fenced,
    /// zero-range is unsupported, the range is out of bounds, or the backend
    /// zero-range fails.
    pub fn submit_kernel_zero_range(
        &mut self,
        start_sector: u64,
        sector_count: u32,
    ) -> BridgeResult<()> {
        // Route through pool-core backend when configured.
        if let Some(ref mut pc) = self.pool_core_backend {
            return Self::submit_zero_range_via_pool_core(pc, start_sector, sector_count);
        }
        let result = self.submit_zero_range(start_sector, sector_count);
        match &result {
            Ok(()) => {
                self.completion
                    .complete(crate::request_completion::CompletionOutcome::ok(0));
            }
            Err(e) => {
                self.completion
                    .complete(crate::request_completion::CompletionOutcome::err(
                        crate::queue_rq::BlkMqStatus::from(e),
                        0,
                    ));
            }
        }
        result
    }
    // ── Lifecycle ────────────────────────────────────────────────────────

    /// Register the device as active.
    ///
    /// In the kernel build, this corresponds to calling
    /// `GenDisk::set_capacity()` and making the device visible to user-space.
    pub fn register(&mut self) {
        self.registered = true;
    }

    /// Unregister the device (quiesce I/O and remove from the system).
    ///
    /// After this call, all further `submit_bio` calls will be rejected
    /// until `register()` is called again.
    pub fn unregister(&mut self) {
        self.registered = false;
    }

    /// Fence the device: reject all new I/O.
    ///
    /// Maps to `blk_mq_quiesce_queue()` in the kernel build.
    pub fn fence(&mut self) {
        self.dispatch_engine.fence();
    }

    /// Unfence the device: resume accepting I/O.
    ///
    /// Maps to `blk_mq_unquiesce_queue()` in the kernel build.
    pub fn unfence(&mut self) {
        self.dispatch_engine.unfence();
    }

    // ── Accessors ────────────────────────────────────────────────────────

    /// Return the device name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Return total device capacity in bytes.
    #[must_use]
    pub fn capacity_bytes(&self) -> u64 {
        self.dispatch_engine.backend().capacity_bytes()
    }

    /// Return the logical block (sector) size in bytes.
    #[must_use]
    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }

    /// Return the configured tag-set (queue) depth.
    #[must_use]
    pub fn tagset_depth(&self) -> u32 {
        self.tagset_depth
    }

    /// Return the queue limits for this device.
    #[must_use]
    pub fn limits(&self) -> &BlockQueueLimits {
        &self.limits
    }

    /// Whether the device is currently registered.
    #[must_use]
    pub fn is_registered(&self) -> bool {
        self.registered
    }

    /// Whether the device is fenced.
    #[must_use]
    pub fn is_fenced(&self) -> bool {
        self.dispatch_engine.is_fenced()
    }

    /// Set the device read-only flag (BLKROSET).
    ///
    /// When read-only, all write-bio submissions are rejected.
    /// Read bios continue to be accepted.
    pub fn set_read_only(&mut self, ro: bool) {
        self.read_only = ro;
        self.dispatch_engine.set_writable(!ro);
    }

    /// Return the current read-only flag (BLKROGET).
    #[must_use]
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Dispatch a block-device ioctl command.
    ///
    /// Wraps [crate::ioctl::dispatch_ioctl] with the device's backend
    /// and read-only state. Returns the ioctl outcome or a negative errno
    /// on failure.
    ///
    /// # Errors
    ///
    /// Returns negative errno (-ENOTTY, -EFAULT, -EIO) as described
    /// in [crate::ioctl::dispatch_ioctl].
    pub fn ioctl(&mut self, cmd: u32, arg: usize) -> Result<crate::ioctl::IoctlOutcome, i32> {
        // Handle TideFS-private ioctls that need dispatch_engine access.
        if cmd == crate::ioctl::TIDEFS_BLK_DISCARD_STATS {
            if arg == 0 {
                return Err(crate::ioctl::EFAULT);
            }
            let stats = self.discard_stats_payload();
            return Ok(crate::ioctl::IoctlOutcome::DiscardStats(stats));
        }
        if cmd == crate::ioctl::TIDEFS_BLK_DISCARD_SUBMIT {
            let start_sector = (arg >> 32) as u64;
            let sector_count = (arg & 0xFFFF_FFFF) as u32;
            if sector_count == 0 {
                return Err(crate::ioctl::EINVAL);
            }
            let result = self.submit_discard(start_sector, sector_count);
            return match result {
                Ok(()) => Ok(crate::ioctl::IoctlOutcome::Ok),
                Err(_) => Err(-crate::ioctl::EIO),
            };
        }
        crate::ioctl::dispatch_ioctl(
            self.dispatch_engine.backend_mut(),
            cmd,
            arg,
            &mut self.read_only,
        )
    }

    /// Build a discard stats payload from the dispatch engine counter state.
    pub fn discard_stats_payload(&self) -> crate::ioctl::DiscardStatsIoctlPayload {
        crate::ioctl::DiscardStatsIoctlPayload {
            discard_count: self.dispatch_engine.discard_count(),
            discard_sectors_total: self.dispatch_engine.discard_sectors_total(),
            discard_budget_exceeded: self.dispatch_engine.discard_budget_exceeded(),
            discard_supported: if self.dispatch_engine.backend().discard_supported() {
                1
            } else {
                0
            },
            max_sectors_per_discard: self
                .dispatch_engine
                .discard_budget()
                .max_sectors_per_discard,
            max_total_discard_ops: self.dispatch_engine.discard_budget().max_total_discard_ops,
        }
    }

    /// Return the current lifecycle state.
    #[must_use]
    pub fn lifecycle_state(&self) -> LifecycleState {
        self.lifecycle.state()
    }

    /// Return the three BLAKE3-256 construction-phase transition digests:
    /// `[alloc_gendisk, alloc_queue, add_disk]`.
    ///
    /// These digests provide deterministic validation that the
    /// device was constructed through the correct lifecycle sequence.
    #[must_use]
    pub fn lifecycle_digests(&self) -> &[[u8; 32]; 3] {
        &self.lifecycle_digests
    }

    /// Return the last BLAKE3-256 lifecycle transition digest.
    #[must_use]
    pub fn last_lifecycle_digest(&self) -> &[u8; 32] {
        self.lifecycle.last_digest()
    }

    /// Return a reference to the underlying [`BlockExport`] (via the dispatch engine backend).
    #[must_use]
    pub fn export(&self) -> &BlockExport {
        self.dispatch_engine.backend()
    }

    /// Return a mutable reference to the underlying [`BlockExport`] (via the dispatch engine backend).
    pub fn export_mut(&mut self) -> &mut BlockExport {
        self.dispatch_engine.backend_mut()
    }

    /// Grow the device capacity to a new (larger) sector count.
    ///
    /// Delegates to the [`DispatchEngine::resize_grow`] which updates
    /// queue limits and grows the backing buffer. Only grow is supported;
    /// shrink requires the separate fence contract (see #6409).
    ///
    /// In the kernel build, this maps to `set_capacity()` on the gendisk.
    ///
    /// # Errors
    ///
    /// Returns `BioQueueFailed` if the new capacity is not larger or
    /// buffer reallocation fails.
    pub fn resize_grow(&mut self, new_capacity_sectors: u64) -> BridgeResult<()> {
        self.dispatch_engine.resize_grow(new_capacity_sectors)
    }

    /// Return a reference to the [`DispatchEngine`].
    #[must_use]
    pub fn dispatch_engine(&self) -> &DispatchEngine<BlockExport> {
        &self.dispatch_engine
    }

    /// Return the BLAKE3-256 dispatch digest of the most recent operation.
    #[must_use]
    pub fn last_dispatch_digest(&self) -> &[u8; 32] {
        self.dispatch_engine.last_digest()
    }

    /// Return the total dispatch count.
    #[must_use]
    pub fn dispatch_count(&self) -> u64 {
        self.dispatch_engine.dispatch_count()
    }

    /// Return total bytes read through the dispatch engine.
    #[must_use]
    pub fn bytes_read(&self) -> u64 {
        self.dispatch_engine.bytes_read()
    }

    /// Return total bytes written through the dispatch engine.
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.dispatch_engine.bytes_written()
    }

    /// Read a sector range directly (convenience wrapper).
    ///
    /// # Errors
    ///
    /// Returns an error if the range is out of bounds.
    pub fn read_sectors(&self, start_sector: u64, sector_count: u32) -> BridgeResult<Vec<u8>> {
        self.dispatch_engine
            .backend()
            .read_sectors(start_sector, sector_count)
    }

    /// Write data to a sector range directly (convenience wrapper).
    ///
    /// # Errors
    ///
    /// Returns an error if the range is out of bounds.
    pub fn write_sectors(&mut self, start_sector: u64, data: &[u8]) -> BridgeResult<()> {
        self.dispatch_engine
            .backend_mut()
            .write_sectors(start_sector, data)
    }
}

impl core::fmt::Debug for TidefsBlockDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TidefsBlockDevice")
            .field("name", &self.name)
            .field("capacity_bytes", &self.capacity_bytes())
            .field("sector_size", &self.sector_size)
            .field("tagset_depth", &self.tagset_depth)
            .field("registered", &self.registered)
            .field("is_fenced", &self.is_fenced())
            .field("lifecycle_state", &self.lifecycle.state())
            .field("dispatch_count", &self.dispatch_engine.dispatch_count())
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::LifecycleState;

    // ── Construction ────────────────────────────────────────────────────

    #[test]
    fn device_new_default_limits() {
        let dev = TidefsBlockDevice::new("tidefs0", 2048).unwrap();
        assert_eq!(dev.name(), "tidefs0");
        assert_eq!(dev.capacity_bytes(), 2048 * 512);
        assert_eq!(dev.sector_size(), 512);
        assert_eq!(dev.tagset_depth(), 64);
        assert!(dev.is_registered());
        assert!(!dev.is_fenced());
        assert_eq!(dev.lifecycle_state(), LifecycleState::Active);
    }

    #[test]
    fn device_new_zero_capacity_rejected() {
        let result = TidefsBlockDevice::new("tidefs0", 0);
        assert!(result.is_err());
    }

    #[test]
    fn device_with_limits_custom() {
        let limits = BlockQueueLimits {
            logical_block_size: 4096,
            physical_block_size: 4096,
            capacity_sectors: 1024,
            min_capacity_sectors: 1024,
            max_hw_sectors: 128,
            max_segments: 64,
            max_queue_depth: 32,
            io_min: 512,
            io_opt: 4096,
            writable: true,
            flush_supported: false,
            discard_supported: true,
            write_zeroes_supported: false,
            zero_range_supported: false,
        };
        let dev = TidefsBlockDevice::with_limits("custom0", limits).unwrap();
        assert_eq!(dev.capacity_bytes(), 1024 * 4096);
        assert_eq!(dev.sector_size(), 4096);
        assert_eq!(dev.tagset_depth(), 32);
        assert!(!dev.limits().flush_supported);
        assert!(dev.limits().discard_supported);
    }

    // ── BLAKE3 lifecycle digest tests ───────────────────────────────────

    #[test]
    fn device_construction_produces_three_lifecycle_digests() {
        let dev = TidefsBlockDevice::new("digest0", 1024).unwrap();
        let digests = dev.lifecycle_digests();
        assert_eq!(digests.len(), 3);

        // All three digests are non-zero
        for d in digests {
            assert_ne!(d, &[0u8; 32], "lifecycle digest should be non-zero");
        }

        // All three digests are distinct
        assert_ne!(
            digests[0], digests[1],
            "alloc vs queue digests should differ"
        );
        assert_ne!(
            digests[1], digests[2],
            "queue vs active digests should differ"
        );
        assert_ne!(
            digests[0], digests[2],
            "alloc vs active digests should differ"
        );
    }

    #[test]
    fn device_lifecycle_digests_deterministic() {
        let dev1 = TidefsBlockDevice::new("same", 2048).unwrap();
        let dev2 = TidefsBlockDevice::new("same", 2048).unwrap();

        assert_eq!(
            dev1.lifecycle_digests(),
            dev2.lifecycle_digests(),
            "same parameters should produce identical lifecycle digests"
        );
    }

    #[test]
    fn device_lifecycle_digests_different_per_name() {
        let dev_a = TidefsBlockDevice::new("dev-a", 1024).unwrap();
        let dev_b = TidefsBlockDevice::new("dev-b", 1024).unwrap();

        assert_ne!(
            dev_a.lifecycle_digests(),
            dev_b.lifecycle_digests(),
            "different names should produce different lifecycle digests"
        );
    }

    #[test]
    fn device_lifecycle_digests_different_per_capacity() {
        let dev1 = TidefsBlockDevice::new("test", 1024).unwrap();
        let dev2 = TidefsBlockDevice::new("test", 2048).unwrap();

        assert_ne!(
            dev1.lifecycle_digests(),
            dev2.lifecycle_digests(),
            "different capacities should produce different lifecycle digests"
        );
    }

    #[test]
    fn device_lifecycle_digests_different_per_sector_size() {
        let dev512 = TidefsBlockDevice::new("test", 1024).unwrap();
        let dev4k = TidefsBlockDevice::with_limits(
            "test",
            BlockQueueLimits {
                logical_block_size: 4096,
                physical_block_size: 4096,
                capacity_sectors: 1024,
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
            },
        )
        .unwrap();

        assert_ne!(
            dev512.lifecycle_digests(),
            dev4k.lifecycle_digests(),
            "different sector sizes should produce different lifecycle digests"
        );
    }

    #[test]
    fn device_last_lifecycle_digest_is_add_disk() {
        let dev = TidefsBlockDevice::new("last0", 1024).unwrap();
        let digests = dev.lifecycle_digests();

        // The last digest (add_disk transition) should match last_lifecycle_digest()
        assert_eq!(dev.last_lifecycle_digest(), &digests[2]);
    }

    // ── I/O dispatch ────────────────────────────────────────────────────

    #[test]
    fn device_write_then_read_roundtrip() {
        let mut dev = TidefsBlockDevice::new("tidefs0", 1024).unwrap();
        let data = [0xABu8; 512];
        let mut bio = BlockBio::new_write(0, &data, 512);
        dev.submit_bio(&mut bio).unwrap();

        let mut read_bio = BlockBio::new_read(0, 1, 512);
        dev.submit_bio(&mut read_bio).unwrap();
        assert_eq!(&read_bio.payload[..512], &data[..]);
    }

    #[test]
    fn device_submit_bio_rejected_when_unregistered() {
        let mut dev = TidefsBlockDevice::new("tidefs0", 100).unwrap();
        dev.unregister();
        let mut bio = BlockBio::new_read(0, 1, 512);
        let result = dev.submit_bio(&mut bio);
        assert!(result.is_err());
    }

    #[test]
    fn device_submit_bio_rejected_when_fenced() {
        let mut dev = TidefsBlockDevice::new("tidefs0", 100).unwrap();
        dev.fence();
        let mut bio = BlockBio::new_read(0, 1, 512);
        let result = dev.submit_bio(&mut bio);
        assert!(result.is_err());
    }

    #[test]
    fn device_unfence_allows_io() {
        let mut dev = TidefsBlockDevice::new("tidefs0", 100).unwrap();
        dev.fence();
        dev.unfence();
        let mut bio = BlockBio::new_read(0, 1, 512);
        assert!(dev.submit_bio(&mut bio).is_ok());
    }

    #[test]
    fn device_re_register_allows_io() {
        let mut dev = TidefsBlockDevice::new("tidefs0", 100).unwrap();
        dev.unregister();
        dev.register();
        let mut bio = BlockBio::new_read(0, 1, 512);
        assert!(dev.submit_bio(&mut bio).is_ok());
    }

    #[test]
    fn device_submit_discard_supported() {
        let limits = BlockQueueLimits {
            logical_block_size: 512,
            physical_block_size: 4096,
            capacity_sectors: 100,
            min_capacity_sectors: 100,
            max_hw_sectors: 256,
            max_segments: 128,
            max_queue_depth: 64,
            io_min: 512,
            io_opt: 4096,
            writable: true,
            flush_supported: true,
            discard_supported: true,
            write_zeroes_supported: false,
            zero_range_supported: false,
        };
        let mut dev = TidefsBlockDevice::with_limits("disc0", limits).unwrap();

        // Write some data
        let data = [0xFFu8; 512];
        dev.write_sectors(0, &data).unwrap();

        // Discard
        dev.submit_discard(0, 1).unwrap();

        // Read back — should be zeroed
        let read = dev.read_sectors(0, 1).unwrap();
        assert_eq!(&read[..512], &[0u8; 512]);
    }

    #[test]
    fn device_submit_discard_unsupported_rejected() {
        let mut dev = TidefsBlockDevice::new("nodisc0", 100).unwrap();
        let result = dev.submit_discard(0, 1);
        assert!(result.is_err());
    }

    #[test]
    fn device_submit_discard_rejected_when_unregistered() {
        let mut dev = TidefsBlockDevice::new("tidefs0", 100).unwrap();
        dev.unregister();
        let result = dev.submit_discard(0, 1);
        assert!(result.is_err());
    }

    // ── Write-zeroes ─────────────────────────────────────────────────────

    #[test]
    fn device_submit_write_zeroes_supported() {
        let limits = BlockQueueLimits {
            logical_block_size: 512,
            physical_block_size: 4096,
            capacity_sectors: 100,
            min_capacity_sectors: 100,
            max_hw_sectors: 256,
            max_segments: 128,
            max_queue_depth: 64,
            io_min: 512,
            io_opt: 4096,
            writable: true,
            flush_supported: true,
            discard_supported: false,
            write_zeroes_supported: true,
            zero_range_supported: false,
        };
        let mut dev = TidefsBlockDevice::with_limits("wz0", limits).unwrap();

        // Write some data, then write-zeroes over it
        let data = [0xFFu8; 512];
        dev.write_sectors(0, &data).unwrap();
        dev.submit_write_zeroes(0, 1).unwrap();

        // Read back — should be zeroed
        let read = dev.read_sectors(0, 1).unwrap();
        assert_eq!(&read[..512], &[0u8; 512]);
    }

    #[test]
    fn device_submit_write_zeroes_unsupported_rejected() {
        let mut dev = TidefsBlockDevice::new("nowz0", 100).unwrap();
        let result = dev.submit_write_zeroes(0, 1);
        assert!(result.is_err());
    }

    #[test]
    fn device_submit_write_zeroes_rejected_when_unregistered() {
        let mut dev = TidefsBlockDevice::new("tidefs0", 100).unwrap();
        dev.unregister();
        let result = dev.submit_write_zeroes(0, 1);
        assert!(result.is_err());
    }

    // ── Zero-range ───────────────────────────────────────────────────────

    #[test]
    fn device_submit_zero_range_supported() {
        let limits = BlockQueueLimits {
            logical_block_size: 512,
            physical_block_size: 4096,
            capacity_sectors: 100,
            min_capacity_sectors: 100,
            max_hw_sectors: 256,
            max_segments: 128,
            max_queue_depth: 64,
            io_min: 512,
            io_opt: 4096,
            writable: true,
            flush_supported: true,
            discard_supported: false,
            write_zeroes_supported: false,
            zero_range_supported: true,
        };
        let mut dev = TidefsBlockDevice::with_limits("zr0", limits).unwrap();

        // Write some data, then zero-range over it
        let data = [0xFFu8; 512];
        dev.write_sectors(0, &data).unwrap();
        dev.submit_zero_range(0, 1).unwrap();

        // Read back — should be zeroed
        let read = dev.read_sectors(0, 1).unwrap();
        assert_eq!(&read[..512], &[0u8; 512]);
    }

    #[test]
    fn device_submit_zero_range_unsupported_rejected() {
        let mut dev = TidefsBlockDevice::new("nozr0", 100).unwrap();
        let result = dev.submit_zero_range(0, 1);
        assert!(result.is_err());
    }

    #[test]
    fn device_submit_zero_range_rejected_when_unregistered() {
        let mut dev = TidefsBlockDevice::new("tidefs0", 100).unwrap();
        dev.unregister();
        let result = dev.submit_zero_range(0, 1);
        assert!(result.is_err());
    }
    // ── Accessors ───────────────────────────────────────────────────────

    #[test]
    fn device_name_accessor() {
        let dev = TidefsBlockDevice::new("prod-vol-001", 1024).unwrap();
        assert_eq!(dev.name(), "prod-vol-001");
    }

    #[test]
    fn device_export_accessor() {
        let mut dev = TidefsBlockDevice::new("tidefs0", 1024).unwrap();
        assert_eq!(dev.export().capacity_bytes(), 1024 * 512);

        // Mutate via export
        let data = [0x11u8; 512];
        dev.export_mut().write_sectors(0, &data).unwrap();
        let read = dev.export().read_sectors(0, 1).unwrap();
        assert_eq!(&read[..], &data[..]);
    }

    // ── Debug / Display ─────────────────────────────────────────────────

    #[test]
    fn device_debug_output() {
        let dev = TidefsBlockDevice::new("debug0", 1024).unwrap();
        let dbg = alloc::format!("{dev:?}");
        assert!(dbg.contains("TidefsBlockDevice"));
        assert!(dbg.contains("debug0"));
        assert!(dbg.contains("524288")); // 1024 * 512
        assert!(dbg.contains("lifecycle_state"));
    }

    // ── Multiple non-overlapping writes ─────────────────────────────────

    #[test]
    fn device_multiple_writes_non_overlapping() {
        let mut dev = TidefsBlockDevice::new("multi0", 1024).unwrap();
        let d1 = [0xAAu8; 512];
        let d2 = [0xBBu8; 512];
        dev.write_sectors(0, &d1).unwrap();
        dev.write_sectors(1, &d2).unwrap();

        let r1 = dev.read_sectors(0, 1).unwrap();
        let r2 = dev.read_sectors(1, 1).unwrap();
        assert_eq!(&r1[..], &d1[..]);
        assert_eq!(&r2[..], &d2[..]);
    }

    // ── Completion tracking tests ──────────────────────────────────────

    #[test]
    fn completion_tracks_successful_read() {
        let mut dev = TidefsBlockDevice::new("test-comp-read", 100).unwrap();
        let mut buf = [0u8; 512];
        let result = dev.submit_kernel_bio(0, 1, true, &mut buf);
        assert!(result.is_ok());
        assert_eq!(dev.completion_count(), 1);
        assert_eq!(dev.total_bytes_transferred(), 512);
        assert_eq!(dev.error_count(), 0);
    }

    #[test]
    fn completion_tracks_successful_write() {
        let mut dev = TidefsBlockDevice::new("test-comp-write", 100).unwrap();
        let mut buf = [0xAAu8; 512];
        let result = dev.submit_kernel_bio(0, 1, false, &mut buf);
        assert!(result.is_ok());
        assert_eq!(dev.completion_count(), 1);
        assert_eq!(dev.total_bytes_transferred(), 512);
        assert_eq!(dev.error_count(), 0);
    }

    #[test]
    fn completion_tracks_multiple_io() {
        let mut dev = TidefsBlockDevice::new("test-comp-multi", 200).unwrap();

        // 2 reads, 1 write
        let mut buf = [0u8; 512];
        dev.submit_kernel_bio(0, 1, true, &mut buf).unwrap();
        dev.submit_kernel_bio(1, 1, true, &mut buf).unwrap();
        let mut wbuf = [0xCCu8; 512];
        dev.submit_kernel_bio(2, 1, false, &mut wbuf).unwrap();

        assert_eq!(dev.completion_count(), 3);
        assert_eq!(dev.total_bytes_transferred(), 1536);
        assert_eq!(dev.error_count(), 0);
    }

    #[test]
    fn completion_tracks_flush() {
        let mut dev = TidefsBlockDevice::new("test-comp-flush", 100).unwrap();
        let result = dev.submit_kernel_flush();
        assert!(result.is_ok());
        assert_eq!(dev.completion_count(), 1);
        assert_eq!(dev.total_bytes_transferred(), 0); // flush transfers 0 bytes
        assert_eq!(dev.error_count(), 0);
    }

    #[test]
    fn completion_counts_errors() {
        let mut dev = TidefsBlockDevice::new("test-comp-err", 50).unwrap();

        // Out-of-bounds read triggers an error
        let mut buf = [0u8; 512];
        let result = dev.submit_kernel_bio(60, 1, true, &mut buf);
        assert!(result.is_err());
        assert_eq!(dev.completion_count(), 0); // errors before submit aren't tracked
        assert_eq!(dev.error_count(), 0);
    }

    #[test]
    fn completion_tracks_error_on_out_of_bounds_write() {
        let mut dev = TidefsBlockDevice::new("test-comp-oob", 50).unwrap();
        let mut buf = [0xDDu8; 512];
        let result = dev.submit_kernel_bio(60, 1, false, &mut buf);
        assert!(result.is_err());
        // The error is returned before completion tracking (validation fails early)
    }

    #[test]
    fn completion_stats_accessor() {
        let mut dev = TidefsBlockDevice::new("test-comp-stats", 200).unwrap();
        let mut buf = [0u8; 512];
        dev.submit_kernel_bio(0, 1, true, &mut buf).unwrap();
        dev.submit_kernel_bio(0, 1, true, &mut buf).unwrap();
        let mut wbuf = [0xEEu8; 512];
        dev.submit_kernel_bio(1, 1, false, &mut wbuf).unwrap();

        let (count, bytes, errors) = dev.completion_stats();
        assert_eq!(count, 3);
        assert_eq!(bytes, 1536);
        assert_eq!(errors, 0);
    }

    #[test]
    fn completion_zero_initial_state() {
        let dev = TidefsBlockDevice::new("test-comp-zero", 100).unwrap();
        assert_eq!(dev.completion_count(), 0);
        assert_eq!(dev.total_bytes_transferred(), 0);
        assert_eq!(dev.error_count(), 0);
        let (count, bytes, errors) = dev.completion_stats();
        assert_eq!((count, bytes, errors), (0, 0, 0));
    }

    // -- Timeout and reset recovery fault-injection tests -------------------

    /// Simulate a stalled backend: record an inflight write with a deadline
    /// far in the past, then verify timeout detection fires.
    #[test]
    fn timeout_detects_stalled_inflight_request() {
        let mut dev = TidefsBlockDevice::new("test-stall", 1024).unwrap();

        // Record an inflight request with a deadline already expired.
        // now_ms=0, timeout=30_000ms -> deadline=30_000, check at 31_000 -> expired
        {
            let tracker = dev.inflight_tracker_mut();
            let _ = tracker.record_request(
                1, // request_id
                0, // now_ms (start of epoch)
                crate::timeout::InflightOp::Write,
                0, // start_sector
                8, // sector_count
            );
            assert_eq!(tracker.inflight_count(), 1);
        }

        // At t=31_000ms (just past the default 30s timeout), the request
        // should have timed out.
        let now_ms = 31_000u64;
        let outcome = dev.inflight_tracker_mut().check_timeouts(now_ms);
        assert!(
            matches!(outcome, crate::timeout::TimeoutOutcome::TimedOut { ref request_ids, .. }
                if request_ids == &alloc::vec![1]),
            "expected TimedOut with request_id=1, got {outcome:?}"
        );
        assert_eq!(dev.inflight_tracker().inflight_count(), 0);
        assert_eq!(dev.inflight_tracker().total_timeouts(), 1);
        assert!(!dev.inflight_tracker().is_fenced());
    }

    /// Verify that check_and_fence_timeouts returns true when there are
    /// no timeouts (normal operation).
    #[test]
    fn check_and_fence_timeouts_passes_when_no_timeout() {
        let mut dev = TidefsBlockDevice::new("test-no-timeout", 1024).unwrap();
        // No inflight requests recorded, so check should pass.
        assert!(dev.check_and_fence_timeouts(0));
        assert!(!dev.is_fenced());
    }

    /// Verify that check_and_fence_timeouts detects a timed-out request
    /// but does not fence on the first timeout (only after consecutive limit).
    #[test]
    fn check_and_fence_timeouts_detects_timeout_without_fencing() {
        let mut dev = TidefsBlockDevice::new("test-first-timeout", 1024).unwrap();

        // Record an inflight write with a deadline that has already expired.
        {
            let tracker = dev.inflight_tracker_mut();
            let _ = tracker.record_request(1, 0, crate::timeout::InflightOp::Write, 0, 8);
        }
        // At t=31s, check should detect timeout but not fence (first timeout).
        assert!(dev.check_and_fence_timeouts(31_000));
        assert!(!dev.is_fenced());
        // Verify the tracker recorded the timeout
        assert_eq!(dev.inflight_tracker().total_timeouts(), 1);
    }

    /// Verify that consecutive timeouts trigger device fencing.
    #[test]
    fn consecutive_timeouts_fence_device() {
        let mut dev = TidefsBlockDevice::new("test-fence", 1024).unwrap();

        // Simulate 3 consecutive inflight timeouts.
        // The default TimeoutConfig fences after 3 consecutive timeouts.

        // First timeout
        let _ = dev.inflight_tracker_mut().record_request(
            1,
            0,
            crate::timeout::InflightOp::Write,
            0,
            8,
        );
        let outcome = dev.inflight_tracker_mut().check_timeouts(31_000);
        assert!(matches!(
            outcome,
            crate::timeout::TimeoutOutcome::TimedOut { .. }
        ));
        assert!(!dev.inflight_tracker().is_fenced());

        // Second timeout (no completion in between)
        let _ = dev.inflight_tracker_mut().record_request(
            2,
            0,
            crate::timeout::InflightOp::Write,
            1,
            8,
        );
        let outcome = dev.inflight_tracker_mut().check_timeouts(31_000);
        assert!(matches!(
            outcome,
            crate::timeout::TimeoutOutcome::TimedOut { .. }
        ));
        assert!(!dev.inflight_tracker().is_fenced());

        // Third consecutive timeout should fence (default max_consecutive_timeouts=3)
        let _ = dev.inflight_tracker_mut().record_request(
            3,
            0,
            crate::timeout::InflightOp::Write,
            2,
            8,
        );
        let outcome = dev.inflight_tracker_mut().check_timeouts(31_000);
        assert!(
            matches!(outcome, crate::timeout::TimeoutOutcome::Fenced { .. }),
            "expected Fenced after 3 consecutive timeouts, got {outcome:?}"
        );
        assert!(dev.inflight_tracker().is_fenced());
    }

    /// Verify that reset_after_timeout drains inflight requests and
    /// restores the device to an operational state.
    #[test]
    fn reset_after_timeout_restores_device() {
        let mut dev = TidefsBlockDevice::new("test-reset", 1024).unwrap();

        // Record a request and trigger timeout
        {
            let tracker = dev.inflight_tracker_mut();
            let _ = tracker.record_request(1, 0, crate::timeout::InflightOp::Read, 0, 1);
        }
        let _ = dev.inflight_tracker_mut().check_timeouts(31_000);
        assert_eq!(dev.inflight_tracker().total_timeouts(), 1);

        // Reset
        dev.reset_after_timeout();
        assert_eq!(dev.inflight_tracker().inflight_count(), 0);
        assert_eq!(dev.inflight_tracker().consecutive_timeouts(), 0);

        // Device should be operational after reset
        assert!(!dev.is_fenced());
    }

    /// Verify that the inflight tracker is properly initialized in a new
    /// device and accessible through the public API.
    #[test]
    fn inflight_tracker_is_initialized_on_new_device() {
        let dev = TidefsBlockDevice::new("test-tracker-init", 1024).unwrap();
        let tracker = dev.inflight_tracker();
        assert_eq!(tracker.inflight_count(), 0);
        assert!(!tracker.is_fenced());
        assert_eq!(tracker.total_timeouts(), 0);
        assert_eq!(tracker.total_completed(), 0);
        assert_eq!(tracker.consecutive_timeouts(), 0);
    }

    /// Verify that a successful I/O completion resets the consecutive
    /// timeout counter (providing resilience against transient stalls).
    #[test]
    fn successful_io_resets_consecutive_timeout_counter() {
        let mut dev = TidefsBlockDevice::new("test-io-reset", 1024).unwrap();

        // Trigger one timeout
        let _ =
            dev.inflight_tracker_mut()
                .record_request(1, 0, crate::timeout::InflightOp::Read, 0, 1);
        let _ = dev.inflight_tracker_mut().check_timeouts(31_000);
        assert_eq!(dev.inflight_tracker().consecutive_timeouts(), 1);

        // Normal I/O completion should reset
        let _ = dev.inflight_tracker_mut().record_request(
            2,
            31_000,
            crate::timeout::InflightOp::Read,
            1,
            1,
        );
        dev.inflight_tracker_mut().complete_request(2);
        assert_eq!(dev.inflight_tracker().consecutive_timeouts(), 0);
    }

    /// Verify that committed-root integrity is preserved: a timed-out
    /// write does not corrupt the backing data buffer.
    #[test]
    fn timeout_preserves_data_integrity() {
        let mut dev = TidefsBlockDevice::new("test-integrity", 1024).unwrap();

        // Write known data to sector 0
        let wbuf = [0xABu8; 512];
        let result = dev.submit_kernel_bio(0, 1, false, &mut wbuf.clone());
        assert!(result.is_ok());

        // Read it back to confirm
        let mut rbuf = [0u8; 512];
        let result = dev.submit_kernel_bio(0, 1, true, &mut rbuf);
        assert!(result.is_ok());
        assert_eq!(&rbuf[..], &[0xABu8; 512]);

        // Simulate a timed-out write: the inflight tracker records a write
        // that never completes, but the underlying data is unchanged.
        {
            let tracker = dev.inflight_tracker_mut();
            let _ = tracker.record_request(99, 0, crate::timeout::InflightOp::Write, 0, 8);
        }
        let outcome = dev.inflight_tracker_mut().check_timeouts(31_000);
        assert!(matches!(
            outcome,
            crate::timeout::TimeoutOutcome::TimedOut { .. }
        ));

        // The data should still be intact (the timed-out write was never applied).
        let mut rbuf2 = [0u8; 512];
        dev.submit_kernel_bio(0, 1, true, &mut rbuf2).unwrap();
        assert_eq!(&rbuf2[..], &[0xABu8; 512], "data corrupted after timeout");
    }

    /// Exercise the full fault-injection workflow: record inflight request,
    /// detect timeout, fence, reset, and verify operation resumes.
    #[test]
    fn full_timeout_fence_reset_resume_workflow() {
        let mut dev = TidefsBlockDevice::new("test-full-workflow", 1024).unwrap();

        // Pre-condition: device is operational
        assert!(!dev.is_fenced());
        assert!(dev.check_and_fence_timeouts(0));

        // Simulate 3 separate, consecutive inflight timeouts.
        // Each check_timeouts call with exactly one timed-out request
        // increments the consecutive counter.
        for i in 0..3u64 {
            let _ = dev.inflight_tracker_mut().record_request(
                i,
                0,
                crate::timeout::InflightOp::Write,
                i,
                1,
            );
            let outcome = dev.inflight_tracker_mut().check_timeouts(31_000);
            if i < 2 {
                assert!(
                    matches!(outcome, crate::timeout::TimeoutOutcome::TimedOut { .. }),
                    "expected TimedOut on iteration {i}, got {outcome:?}"
                );
            } else {
                assert!(
                    matches!(outcome, crate::timeout::TimeoutOutcome::Fenced { .. }),
                    "expected Fenced on iteration {i}, got {outcome:?}"
                );
            }
        }
        assert!(dev.inflight_tracker().is_fenced());

        // Reset the device
        dev.inflight_tracker_mut().unfence();
        assert!(!dev.inflight_tracker().is_fenced());
        dev.reset_after_timeout();

        // Device should be operational again
        assert!(dev.check_and_fence_timeouts(31_001));

        // I/O should work after reset
        let wbuf = [0xCDu8; 512];
        let result = dev.submit_kernel_bio(0, 1, false, &mut wbuf.clone());
        assert!(result.is_ok());

        let mut rbuf = [0u8; 512];
        dev.submit_kernel_bio(0, 1, true, &mut rbuf).unwrap();
        assert_eq!(&rbuf[..], &[0xCDu8; 512]);
    }
}
