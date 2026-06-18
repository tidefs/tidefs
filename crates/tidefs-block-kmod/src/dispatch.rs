// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Bio request dispatch bridging Linux block layer to VfsEngine storage.
//!
//! This module implements the blk_mq Operations/GenDisk request-processing
//! callback that translates Linux `bio` requests into storage-backend
//! read/write/flush/discard calls. The dispatch path is BLAKE3-256
//! domain-separated (domain: `tidefs-block-kmod-dispatch-v1`) for
//! deterministic operational validation.
//!
//! # Architecture
//!
//! ```text
//! Linux block layer (submit_bio)
//!   ↓
//! DispatchEngine::dispatch(bio)
//!   ├─ classify: BioOp::Read/Write/Flush/Discard
//!   ├─ validate: sector range, device state, queue depth
//!   ├─ execute: BlockBackend::read/write/flush/discard
//!   └─ record: BLAKE3 dispatch digest
//! ```
//!
//! # Backend abstraction
//!
//! The [`BlockBackend`] trait decouples dispatch logic from storage
//! implementation. In production, the backend is VfsEngine; in tests,
//! it is an in-memory buffer. This separation allows the dispatch
//! engine to be validated without a running kernel or VfsEngine.
//!
//! Domain: `tidefs-block-kmod-dispatch-v1`

use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge::kernel_types::ByteSliceExt;
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge::{BridgeError, BridgeResult};
use crate::{BlockBio, BlockQueueLimits};
#[cfg(not(CONFIG_RUST))]
use tidefs_kmod_bridge::{BridgeError, BridgeResult};

/// Domain separator for BLAKE3-256 dispatch-path integrity hashing.
const DOMAIN: &str = "tidefs-block-kmod-dispatch-v1";

// ── BioOp: request-type discriminator ───────────────────────────────────

/// Block I/O operation type corresponding to Linux `REQ_OP_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BioOp {
    /// REQ_OP_READ (0): read sectors from the device.
    Read,
    /// REQ_OP_WRITE (1): write sectors to the device.
    Write,
    /// REQ_OP_FLUSH (4): flush volatile write caches.
    Flush,
    /// REQ_OP_DISCARD (3): discard (trim/unmap) sector range.
    Discard,
    /// REQ_OP_WRITE_ZEROES (9): write zeroes to sector range.
    WriteZeroes,
    /// REQ_OP_ZONE_RESET mapped: zero-range through allocation authority.
    ZeroRange,
}

impl BioOp {
    /// Classify a [`BlockBio`] into its operation type.
    ///
    /// Priority order matches Linux semantics: FLUSH is inspected first
    /// (a bio can carry both FLUSH and data), then the read/write direction.
    #[must_use]
    pub fn classify(bio: &BlockBio) -> Self {
        if bio.flush {
            BioOp::Flush
        } else if bio.is_read {
            BioOp::Read
        } else {
            BioOp::Write
        }
    }

    /// Classify a discard request explicitly.
    #[must_use]
    pub const fn discard() -> Self {
        BioOp::Discard
    }

    /// Classify a write-zeroes request explicitly.
    #[must_use]
    pub const fn write_zeroes() -> Self {
        BioOp::WriteZeroes
    }

    /// Classify a zero-range request explicitly.
    #[must_use]
    pub const fn zero_range() -> Self {
        BioOp::ZeroRange
    }
}

impl core::fmt::Display for BioOp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Read => write!(f, "READ"),
            Self::Write => write!(f, "WRITE"),
            Self::Flush => write!(f, "FLUSH"),
            Self::Discard => write!(f, "DISCARD"),
            Self::WriteZeroes => write!(f, "WRITE_ZEROES"),
            Self::ZeroRange => write!(f, "ZERO_RANGE"),
        }
    }
}

// ── DispatchResult ──────────────────────────────────────────────────────

/// Outcome of a single bio dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchResult {
    /// I/O completed successfully with the number of bytes transferred.
    Completed { bytes_transferred: u32 },
    /// Partial completion: `bytes_transferred` bytes were transferred,
    /// but fewer than the requested `bytes_requested`. The block layer
    /// uses `blk_update_request` to advance the residual.
    Partial {
        bytes_transferred: u32,
        bytes_requested: u32,
    },
    /// Operation completed with no data transferred (flush, discard).
    CompletedNoData,
    /// The operation is not supported by the backend or device.
    NotSupported,
    /// The bio was rejected due to invalid parameters or device state.
    Rejected { reason: &'static str },
    /// An I/O error occurred during backend execution.
    IoError { detail: &'static str },
}

impl DispatchResult {
    /// Whether the dispatch was successful (including partial completion).
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(
            self,
            Self::Completed { .. } | Self::Partial { .. } | Self::CompletedNoData
        )
    }

    /// Bytes transferred, or 0 for no-data operations and errors.
    #[must_use]
    pub fn bytes_transferred(&self) -> u32 {
        match self {
            Self::Completed { bytes_transferred } => *bytes_transferred,
            Self::Partial {
                bytes_transferred, ..
            } => *bytes_transferred,
            _ => 0,
        }
    }
}
// ── DiscardAmplificationBudget ─────────────────────────────────────────

/// Budget that limits discard amplification in the kernel block path.
///
/// Discard amplification is the ratio of backend discard operations to
/// logical discard requests. Each discard (REQ_OP_DISCARD) bio generates
/// at least one backend `discard_sectors` call. An unbounded discard
/// workload can overwhelm the storage backend with per-block deallocation
/// metadata churn.
///
/// The budget enforces two constraints:
///
/// 1. **Per-operation sector cap** (`max_sectors_per_discard`): a single
///    discard bio exceeding this cap is rejected. This prevents a
///    single huge TRIM from monopolising the backend.
/// 2. **Lifetime operation cap** (`max_total_discard_ops`): after this
///    many successful discards, further discards are rejected. This
///    bounds the total discard amplification over the device lifetime.
///
/// When either constraint is exceeded the dispatch engine records a
/// budget-exceeded rejection and the discard is not forwarded to the
/// backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscardAmplificationBudget {
    /// Maximum sectors a single discard bio may request.
    /// Default: 0 (no per-operation cap — only lifetime cap applies).
    pub max_sectors_per_discard: u64,
    /// Maximum total successful discard operations allowed.
    /// Default: 0 (unlimited).
    pub max_total_discard_ops: u64,
}

impl DiscardAmplificationBudget {
    /// Create a budget with no per-operation cap and unlimited lifetime ops.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_sectors_per_discard: 0,
            max_total_discard_ops: 0,
        }
    }

    /// Create a budget with only a lifetime operation cap.
    #[must_use]
    pub const fn with_lifetime_cap(max_total_discard_ops: u64) -> Self {
        Self {
            max_sectors_per_discard: 0,
            max_total_discard_ops,
        }
    }
}

// ── BlockBackend trait ──────────────────────────────────────────────────

/// Storage backend abstraction for block I/O dispatch.
///
/// Implementations provide the actual data movement for read, write,
/// flush, and discard operations. The dispatch engine validates bios
/// and then delegates to the backend for execution.
///
/// # Backend classification
///
/// ## Bring-up / test backend (current default)
///
/// [`crate::BlockExport`] + [`crate::BlockExportQueue`] provide a
/// **fixed-capacity in-memory buffer**.  This is the bring-up and test
/// backend. It is useful for narrow unit checks but does **not** provide
/// release validation, persistent storage, power-fail atomicity, or
/// crash-consistency across host reboots.
///
/// ## Production backend
///
/// In production, the backend bridges to `VfsEngine` through the
/// kernel-UAPI surface.  The `read` and `write` methods translate
/// sector-relative offsets into VfsEngine file offsets on the backing
/// block file, providing durable persistence and crash-consistency.
pub trait BlockBackend {
    /// Read sectors from the backend into `buf`.
    ///
    /// `buf.len()` must equal `sector_count * sector_size`.
    ///
    /// # Errors
    ///
    /// Returns an error if the range is out of bounds or a storage
    /// failure occurs.
    fn read_sectors(
        &self,
        start_sector: u64,
        sector_count: u32,
        buf: &mut [u8],
    ) -> BridgeResult<u32>;

    /// Write `data` to the backend starting at `start_sector`.
    ///
    /// `data.len()` must be a multiple of the sector size.
    ///
    /// # Errors
    ///
    /// Returns an error if the range is out of bounds or a storage
    /// failure occurs.
    fn write_sectors(&mut self, start_sector: u64, data: &[u8]) -> BridgeResult<u32>;

    /// Flush any volatile write caches to stable storage.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend does not support flushing
    /// or the flush operation fails.
    fn flush(&mut self) -> BridgeResult<()>;

    /// Return the total device capacity in bytes.
    fn capacity(&self) -> u64;

    /// Discard (trim/unmap) a range of sectors.
    ///
    /// After a successful discard, reads from the discarded range
    /// may return any data (typically zeroes).
    ///
    /// # Errors
    ///
    /// Returns an error if discard is not supported or the range
    /// is out of bounds.
    fn discard_sectors(&mut self, start_sector: u64, sector_count: u32) -> BridgeResult<()>;

    /// Whether flush/FUA operations are supported.
    fn flush_supported(&self) -> bool;

    /// Whether discard/trim operations are supported.
    fn discard_supported(&self) -> bool;

    /// Write zeroes to a range of sectors.
    ///
    /// Unlike discard, subsequent reads MUST return zeroes. The backend
    /// MAY allocate backing storage as needed.
    ///
    /// # Errors
    ///
    /// Returns an error if write-zeroes is not supported or the range
    /// is out of bounds.
    fn write_zeroes_sectors(&mut self, start_sector: u64, sector_count: u32) -> BridgeResult<()>;

    /// Zero a range of sectors through the allocation layer.
    ///
    /// Stronger than both discard and write-zeroes: the range MUST be
    /// readable (no fault on access) and MUST return zeroes.
    ///
    /// # Errors
    ///
    /// Returns an error if zero-range is not supported or the range
    /// is out of bounds.
    fn zero_range_sectors(&mut self, start_sector: u64, sector_count: u32) -> BridgeResult<()>;

    /// Whether write-zeroes operations are supported.
    fn write_zeroes_supported(&self) -> bool;

    /// Whether zero-range operations are supported.
    fn zero_range_supported(&self) -> bool;

    /// Commit a transaction-group barrier for durability.
    ///
    /// After a successful flush, the backend must publish a committed
    /// root so that crash recovery recognizes the current txg as the
    /// consistent recovery point.  The default implementation is a no-op;
    /// production backends (PoolCoreBackend) override this to call
    /// through to the pool-core txg commit barrier.
    ///
    /// # Errors
    ///
    /// Returns an error if the txg commit-barrier fails.
    fn commit_barrier(&mut self) -> BridgeResult<()> {
        Ok(())
    }

    /// The logical block (sector) size in bytes.
    fn sector_size(&self) -> u32;

    /// Grow the backend capacity to a new (larger) sector count.
    ///
    /// The default implementation is a no-op. Backends that maintain
    /// their own capacity tracking (e.g., in-memory buffer backends)
    /// should override this to resize their backing storage.
    ///
    /// # Errors
    ///
    /// Returns an error if the resize-grow fails.
    fn resize_grow(&mut self, _new_capacity_sectors: u64) -> BridgeResult<()> {
        Ok(())
    }
}

// ── DispatchEngine ──────────────────────────────────────────────────────

/// BLAKE3-verified bio dispatch engine.
///
/// Accepts [`BlockBio`] requests, classifies them by operation type
/// ([`BioOp`]), validates sector ranges and device state, dispatches
/// to the [`BlockBackend`], and records BLAKE3-256 domain-separated
/// dispatch validation for every operation.
///
/// # Lifecycle integration
///
/// The engine is registered during the QueueReady→Active lifecycle
/// transition. Before registration, all bios are rejected. After
/// the device transitions to Removing, bios are rejected again.
///
/// # BLAKE3 validation
///
/// Every dispatch produces a deterministic BLAKE3-256 digest (domain:
/// `tidefs-block-kmod-dispatch-v1`) that covers the operation type,
/// sector range, payload hash, and dispatch sequence number. Two
/// identical dispatch sequences produce identical digest chains.
pub struct DispatchEngine<B: BlockBackend> {
    /// The storage backend.
    backend: B,
    /// Device queue limits (capacity, sector size, etc.).
    limits: BlockQueueLimits,
    /// Whether the dispatch engine is active (accepting bios).
    active: bool,
    /// Whether the device is fenced (rejecting all bios).
    fenced: bool,
    /// Monotonically increasing dispatch sequence number.
    dispatch_count: u64,
    /// BLAKE3-256 digest of the most recent dispatch.
    last_digest: [u8; 32],
    /// Total bytes read since engine creation.
    bytes_read: u64,
    /// Total bytes written since engine creation.
    bytes_written: u64,
    /// Current inflight I/O count (atomic for concurrent dispatch safety).
    inflight: AtomicU32,
    /// Number of bios rejected due to queue-depth saturation.
    saturation_rejections: u64,
    /// Total read operations successfully dispatched.
    read_count: u64,
    /// Total write operations successfully dispatched.
    write_count: u64,
    /// Total flush operations successfully dispatched.
    flush_count: u64,
    /// Total discard operations successfully dispatched.
    discard_count: u64,
    /// Total logical sectors discarded (cumulative).
    discard_sectors_total: u64,
    /// Number of discard bios rejected because the amplification budget
    /// was exceeded (per-operation sector cap or lifetime op cap).
    discard_budget_exceeded: u64,
    /// The active discard amplification budget. Defaults to
    /// [`DiscardAmplificationBudget::unlimited`] so that a missing
    /// budget is not a release blocker.
    discard_budget: DiscardAmplificationBudget,
}

impl<B: BlockBackend> DispatchEngine<B> {
    /// Create a new dispatch engine wrapping a backend.
    ///
    /// The engine starts inactive; it must be activated via
    /// [`activate`](Self::activate) before accepting bios.
    #[must_use]
    pub fn new(backend: B, limits: BlockQueueLimits) -> Self {
        Self {
            backend,
            limits,
            active: false,
            fenced: false,
            dispatch_count: 0,
            last_digest: [0u8; 32],
            bytes_read: 0,
            bytes_written: 0,
            inflight: AtomicU32::new(0),
            saturation_rejections: 0,
            read_count: 0,
            write_count: 0,
            flush_count: 0,
            discard_count: 0,
            discard_sectors_total: 0,
            discard_budget_exceeded: 0,
            discard_budget: DiscardAmplificationBudget::unlimited(),
        }
    }

    // ── Lifecycle ──────────────────────────────────────────────────────

    /// Activate the dispatch engine so it accepts bios.
    ///
    /// Called during the QueueReady→Active lifecycle transition.
    /// Returns the BLAKE3-256 activation digest.
    pub fn activate(&mut self) -> [u8; 32] {
        self.active = true;
        self.compute_lifecycle_digest("activate")
    }

    /// Deactivate the dispatch engine so it rejects bios.
    ///
    /// Called during the Active→Removing lifecycle transition.
    /// Returns the BLAKE3-256 deactivation digest.
    pub fn deactivate(&mut self) -> [u8; 32] {
        self.active = false;
        self.compute_lifecycle_digest("deactivate")
    }

    /// Fence the device: reject all new I/O.
    pub fn fence(&mut self) {
        self.fenced = true;
    }

    /// Unfence the device: resume accepting I/O.
    pub fn unfence(&mut self) {
        self.fenced = false;
    }

    // ── Accessors ──────────────────────────────────────────────────────

    /// Whether the engine is currently active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Whether the engine is currently fenced.
    #[must_use]
    pub fn is_fenced(&self) -> bool {
        self.fenced
    }

    /// The dispatch sequence number (count of bios processed).
    #[must_use]
    pub fn dispatch_count(&self) -> u64 {
        self.dispatch_count
    }

    /// The BLAKE3-256 digest of the most recent dispatch.
    #[must_use]
    pub fn last_digest(&self) -> &[u8; 32] {
        &self.last_digest
    }

    /// Total bytes read since engine creation.
    #[must_use]
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Total bytes written since engine creation.
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Current inflight I/O count.
    #[must_use]
    pub fn inflight(&self) -> u32 {
        self.inflight.load(Ordering::Acquire)
    }

    /// Number of bios rejected due to queue-depth saturation.
    #[must_use]
    pub fn saturation_rejections(&self) -> u64 {
        self.saturation_rejections
    }

    /// Total read operations successfully dispatched.
    #[must_use]
    pub fn read_count(&self) -> u64 {
        self.read_count
    }

    /// Total write operations successfully dispatched.
    #[must_use]
    pub fn write_count(&self) -> u64 {
        self.write_count
    }

    /// Total flush operations successfully dispatched.
    #[must_use]
    pub fn flush_count(&self) -> u64 {
        self.flush_count
    }

    /// Total discard operations successfully dispatched.
    #[must_use]
    pub fn discard_count(&self) -> u64 {
        self.discard_count
    }

    /// Total logical sectors discarded.
    #[must_use]
    pub fn discard_sectors_total(&self) -> u64 {
        self.discard_sectors_total
    }

    /// Number of discards rejected because the amplification budget was exceeded.
    #[must_use]
    pub fn discard_budget_exceeded(&self) -> u64 {
        self.discard_budget_exceeded
    }

    /// The current discard amplification budget.
    #[must_use]
    pub fn discard_budget(&self) -> &DiscardAmplificationBudget {
        &self.discard_budget
    }

    /// Set a new discard amplification budget.
    ///
    /// Changing the budget does not reset existing counters.
    pub fn set_discard_budget(&mut self, budget: DiscardAmplificationBudget) {
        self.discard_budget = budget;
    }

    /// The queue limits for this engine.
    #[must_use]
    pub fn limits(&self) -> &BlockQueueLimits {
        &self.limits
    }

    /// Return a reference to the backend.
    #[must_use]
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Return a mutable reference to the backend.
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Grow the engine capacity to a new (larger) sector count.
    ///
    /// Updates the internal queue limits and delegates to the backend
    /// to grow its backing storage. Only grow is supported; the new
    /// capacity must be strictly greater than the current capacity.
    ///
    /// # Errors
    ///
    /// Returns `BioQueueFailed` if the resize-grow fails.
    pub fn resize_grow(&mut self, new_capacity_sectors: u64) -> BridgeResult<()> {
        self.limits
            .resize_grow(new_capacity_sectors)
            .map_err(|e| BridgeError::BioQueueFailed { detail: e })?;
        self.backend.resize_grow(new_capacity_sectors)
    }

    // ── Dispatch ───────────────────────────────────────────────────────

    /// Dispatch a single [`BlockBio`] through the engine.
    ///
    /// Classifies the bio operation, validates the request, executes
    /// it against the backend, and records BLAKE3 dispatch validation.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchResult::Rejected`] if the engine is inactive,
    /// fenced, or the bio fails validation. Returns
    /// [`DispatchResult::IoError`] if the backend operation fails.
    pub fn dispatch(&mut self, bio: &mut BlockBio) -> DispatchResult {
        // Pre-dispatch validation
        if !self.active {
            return DispatchResult::Rejected {
                reason: "dispatch engine not active",
            };
        }
        if self.fenced {
            return DispatchResult::Rejected {
                reason: "device is fenced",
            };
        }

        // Queue-depth saturation gate: reject when inflight count is at
        // or beyond the configured max_queue_depth.  This signals
        // BLK_STS_RESOURCE to the block layer so it can apply
        // backpressure rather than overwhelming the backend.
        let max_depth = self.limits.max_queue_depth;
        let prev = self.inflight.fetch_add(1, Ordering::AcqRel);
        if prev >= max_depth {
            // Saturated: undo the increment and reject.
            self.inflight.fetch_sub(1, Ordering::Release);
            self.saturation_rejections += 1;
            return DispatchResult::Rejected {
                reason: "queue depth saturated",
            };
        }

        let op = BioOp::classify(bio);

        // Validate sector range for data operations
        if (op == BioOp::Read || op == BioOp::Write)
            && !self
                .limits
                .range_in_bounds(bio.start_sector, bio.sector_count)
        {
            // Undo inflight increment on validation failure.
            self.inflight.fetch_sub(1, Ordering::Release);
            return DispatchResult::Rejected {
                reason: "sector range out of bounds",
            };
        }

        // Execute the operation
        let result = match op {
            BioOp::Read => self.dispatch_read(bio),
            BioOp::Write => self.dispatch_write(bio),
            BioOp::Flush => self.dispatch_flush(),
            BioOp::Discard => self.dispatch_discard(bio),
            BioOp::WriteZeroes | BioOp::ZeroRange => {
                // WriteZeroes/ZeroRange dispatched via explicit dispatch_write_zeroes_op/
                // dispatch_zero_range_op at the kernel entrypoint, not through BlockBio flags
                self.inflight.fetch_sub(1, Ordering::Release);
                return DispatchResult::NotSupported;
            }
        };

        // Decrement inflight now that execution is complete.
        self.inflight.fetch_sub(1, Ordering::Release);

        // Track per-operation fairness counters.
        match op {
            BioOp::Read => self.read_count += 1,
            BioOp::Write => self.write_count += 1,
            BioOp::Flush => self.flush_count += 1,
            _ => {}
        }

        // Record BLAKE3 dispatch validation
        self.dispatch_count += 1;
        self.last_digest = self.compute_dispatch_digest(op, bio, &result);

        result
    }

    /// Dispatch an explicit discard operation (not carried by BlockBio flags).
    pub fn dispatch_discard_op(&mut self, start_sector: u64, sector_count: u32) -> DispatchResult {
        if !self.active {
            return DispatchResult::Rejected {
                reason: "dispatch engine not active",
            };
        }
        if self.fenced {
            return DispatchResult::Rejected {
                reason: "device is fenced",
            };
        }
        if !self.limits.writable {
            return DispatchResult::Rejected {
                reason: "device is read-only",
            };
        }
        if !self.backend.discard_supported() {
            return DispatchResult::NotSupported;
        }
        // ── discard amplification budget check ─────────────────────────
        if !self.limits.range_in_bounds(start_sector, sector_count) {
            return DispatchResult::Rejected {
                reason: "discard sector range out of bounds",
            };
        }
        if !self.check_discard_budget(start_sector, sector_count) {
            self.discard_budget_exceeded += 1;
            return DispatchResult::Rejected {
                reason: "discard amplification budget exceeded",
            };
        }

        let result = match self.backend.discard_sectors(start_sector, sector_count) {
            Ok(()) => DispatchResult::CompletedNoData,
            Err(e) => DispatchResult::IoError {
                detail: match e {
                    BridgeError::BioQueueFailed { detail } => detail,
                    _ => "discard backend error",
                },
            },
        };

        // Track discard statistics for amplification budget
        if result.is_ok() {
            self.discard_count += 1;
            let sc = u64::from(sector_count);
            self.discard_sectors_total = self.discard_sectors_total.saturating_add(sc);
        }

        // Record BLAKE3 dispatch validation for discard
        self.dispatch_count += 1;
        let mut dummy_bio =
            BlockBio::new_read(start_sector, sector_count, self.limits.logical_block_size);
        dummy_bio.flush = false;
        self.last_digest = self.compute_dispatch_digest(BioOp::Discard, &dummy_bio, &result);

        result
    }

    /// Dispatch a write-zeroes operation on the backend.
    ///
    /// The backend MUST ensure subsequent reads return zeroes for the
    /// specified range. The backend MAY allocate backing storage.
    pub fn dispatch_write_zeroes_op(
        &mut self,
        start_sector: u64,
        sector_count: u32,
    ) -> DispatchResult {
        if !self.active {
            return DispatchResult::Rejected {
                reason: "dispatch engine not active",
            };
        }
        if self.fenced {
            return DispatchResult::Rejected {
                reason: "dispatch engine fenced",
            };
        }
        if !self.limits.writable {
            return DispatchResult::Rejected {
                reason: "device is read-only",
            };
        }
        if !self.backend.write_zeroes_supported() {
            return DispatchResult::NotSupported;
        }

        let capacity = self.limits.capacity_sectors;
        let end = start_sector.saturating_add(u64::from(sector_count));
        if sector_count == 0 || end > capacity {
            return DispatchResult::Rejected {
                reason: "write-zeroes range out of bounds",
            };
        }

        let result = match self
            .backend
            .write_zeroes_sectors(start_sector, sector_count)
        {
            Ok(()) => DispatchResult::CompletedNoData,
            Err(_) => DispatchResult::IoError {
                detail: "write-zeroes backend error",
            },
        };

        self.dispatch_count += 1;
        let dummy_bio =
            BlockBio::new_read(start_sector, sector_count, self.limits.logical_block_size);
        self.last_digest = self.compute_dispatch_digest(BioOp::WriteZeroes, &dummy_bio, &result);

        result
    }

    /// Dispatch a zero-range operation on the backend.
    ///
    /// Stronger than write-zeroes: the range MUST remain readable and
    /// return zeroes. The implementation should interact with allocation
    /// and extent authority.
    pub fn dispatch_zero_range_op(
        &mut self,
        start_sector: u64,
        sector_count: u32,
    ) -> DispatchResult {
        if !self.active {
            return DispatchResult::Rejected {
                reason: "dispatch engine not active",
            };
        }
        if self.fenced {
            return DispatchResult::Rejected {
                reason: "dispatch engine fenced",
            };
        }
        if !self.limits.writable {
            return DispatchResult::Rejected {
                reason: "device is read-only",
            };
        }
        if !self.backend.zero_range_supported() {
            return DispatchResult::NotSupported;
        }

        let capacity = self.limits.capacity_sectors;
        let end = start_sector.saturating_add(u64::from(sector_count));
        if sector_count == 0 || end > capacity {
            return DispatchResult::Rejected {
                reason: "zero-range out of bounds",
            };
        }

        let result = match self.backend.zero_range_sectors(start_sector, sector_count) {
            Ok(()) => DispatchResult::CompletedNoData,
            Err(_) => DispatchResult::IoError {
                detail: "zero-range backend error",
            },
        };

        self.dispatch_count += 1;
        let dummy_bio =
            BlockBio::new_read(start_sector, sector_count, self.limits.logical_block_size);
        self.last_digest = self.compute_dispatch_digest(BioOp::ZeroRange, &dummy_bio, &result);

        result
    }

    /// Set the writable flag on the engine's limits.
    ///
    /// When `false`, all write, discard, write-zeroes, and zero-range
    /// operations are rejected at the dispatch layer.  This is the
    /// central enforcement point for BLKROSET and snapshot-anchored
    /// read-only exports.
    pub fn set_writable(&mut self, writable: bool) {
        self.limits.writable = writable;
    }

    // ── Private dispatch helpers ───────────────────────────────────────

    fn dispatch_read(&mut self, bio: &mut BlockBio) -> DispatchResult {
        let expected_len = bio.sector_count as usize * self.limits.logical_block_size as usize;
        // Under cargo: if the bio has multiple segments, use segment-aware scatter dispatch.
        // Under CONFIG_RUST: real segment iteration happens in copy_request_payload.
        #[cfg(not(CONFIG_RUST))]
        if bio.segment_count() > 1 {
            return self.dispatch_read_segmented(bio, expected_len);
        }
        if bio.payload.len() < expected_len {
            return DispatchResult::Rejected {
                reason: "read payload buffer too short",
            };
        }

        match self.backend.read_sectors(
            bio.start_sector,
            bio.sector_count,
            &mut bio.payload[..expected_len],
        ) {
            Ok(bytes) => {
                self.bytes_read += u64::from(bytes);
                let bytes_u32 = bytes;
                if bytes_u32 < expected_len as u32 {
                    DispatchResult::Partial {
                        bytes_transferred: bytes_u32,
                        bytes_requested: expected_len as u32,
                    }
                } else {
                    DispatchResult::Completed {
                        bytes_transferred: bytes_u32,
                    }
                }
            }
            Err(e) => DispatchResult::IoError {
                detail: match e {
                    BridgeError::BioQueueFailed { detail } => detail,
                    _ => "read backend error",
                },
            },
        }
    }

    /// Segment-aware read dispatch: scatters backend data across bio segments.
    ///
    /// Reads the full sector range from the backend into a temporary buffer,
    /// then scatters the data across individual segments. If the backend
    /// returns fewer bytes than requested, partial completion is reported
    /// with the actual byte count.
    ///
    /// Cargo-only: under CONFIG_RUST, real bio segment iteration is handled
    /// by `copy_request_payload` in `tidefs_block_kmod.rs`.
    #[cfg(not(CONFIG_RUST))]
    fn dispatch_read_segmented(
        &mut self,
        bio: &mut BlockBio,
        expected_len: usize,
    ) -> DispatchResult {
        let mut flat = alloc::vec![0u8; expected_len];
        match self
            .backend
            .read_sectors(bio.start_sector, bio.sector_count, &mut flat)
        {
            Ok(bytes) => {
                let bytes_usize = bytes as usize;
                let copy_len = bytes_usize.min(expected_len);
                // Scatter into segments
                let mut remaining = copy_len;
                for seg in bio.segments_mut() {
                    if remaining == 0 {
                        break;
                    }
                    let seg_len = seg.data.len();
                    let n = seg_len.min(remaining);
                    seg.data[..n]
                        .copy_from_slice(&flat[copy_len - remaining..copy_len - remaining + n]);
                    remaining -= n;
                }
                bio.sync_payload_from_segments();
                self.bytes_read += u64::from(bytes);
                let bytes_u32 = bytes;
                if bytes_u32 < expected_len as u32 {
                    DispatchResult::Partial {
                        bytes_transferred: bytes_u32,
                        bytes_requested: expected_len as u32,
                    }
                } else {
                    DispatchResult::Completed {
                        bytes_transferred: bytes_u32,
                    }
                }
            }
            Err(e) => DispatchResult::IoError {
                detail: match e {
                    BridgeError::BioQueueFailed { detail } => detail,
                    _ => "read backend error",
                },
            },
        }
    }

    fn dispatch_write(&mut self, bio: &mut BlockBio) -> DispatchResult {
        if !self.limits.writable {
            return DispatchResult::Rejected {
                reason: "device is read-only",
            };
        }
        let expected_len = bio.sector_count as usize * self.limits.logical_block_size as usize;
        // Under cargo: if the bio has multiple segments, use segment-aware gather dispatch.
        // Under CONFIG_RUST: real segment iteration happens in copy_request_payload.
        #[cfg(not(CONFIG_RUST))]
        if bio.segment_count() > 1 {
            return self.dispatch_write_segmented(bio, expected_len);
        }
        let write_data = if bio.payload.len() >= expected_len {
            &bio.payload[..expected_len]
        } else {
            return DispatchResult::Rejected {
                reason: "write payload too short",
            };
        };

        match self.backend.write_sectors(bio.start_sector, write_data) {
            Ok(bytes) => {
                self.bytes_written += u64::from(bytes);
                let bytes_u32 = bytes;
                if bytes_u32 < expected_len as u32 {
                    DispatchResult::Partial {
                        bytes_transferred: bytes_u32,
                        bytes_requested: expected_len as u32,
                    }
                } else {
                    DispatchResult::Completed {
                        bytes_transferred: bytes_u32,
                    }
                }
            }
            Err(e) => DispatchResult::IoError {
                detail: match e {
                    BridgeError::BioQueueFailed { detail } => detail,
                    _ => "write backend error",
                },
            },
        }
    }

    /// Segment-aware write dispatch: gathers data from bio segments.
    ///
    /// Concatenates segment data into a flat buffer for the backend, then
    /// dispatches the write. If the backend writes fewer bytes than
    /// requested, partial completion is reported. An error mid-transfer
    /// is reported as IoError.
    ///
    /// Cargo-only: under CONFIG_RUST, real bio segment iteration is handled
    /// by `copy_request_payload` in `tidefs_block_kmod.rs`.
    #[cfg(not(CONFIG_RUST))]
    fn dispatch_write_segmented(&mut self, bio: &BlockBio, expected_len: usize) -> DispatchResult {
        // Gather segment data into a flat buffer
        let mut flat = alloc::vec![0u8; expected_len];
        let mut offset: usize = 0;
        for seg in bio.segments_ref() {
            let seg_len = seg.data.len();
            let n = seg_len.min(expected_len.saturating_sub(offset));
            if n == 0 {
                break;
            }
            flat[offset..offset + n].copy_from_slice(&seg.data[..n]);
            offset += n;
        }
        match self
            .backend
            .write_sectors(bio.start_sector, &flat[..offset])
        {
            Ok(bytes) => {
                self.bytes_written += u64::from(bytes);
                let bytes_u32 = bytes;
                if bytes_u32 < expected_len as u32 {
                    DispatchResult::Partial {
                        bytes_transferred: bytes_u32,
                        bytes_requested: expected_len as u32,
                    }
                } else {
                    DispatchResult::Completed {
                        bytes_transferred: bytes_u32,
                    }
                }
            }
            Err(e) => DispatchResult::IoError {
                detail: match e {
                    BridgeError::BioQueueFailed { detail } => detail,
                    _ => "write backend error",
                },
            },
        }
    }

    fn dispatch_flush(&mut self) -> DispatchResult {
        if !self.backend.flush_supported() {
            return DispatchResult::NotSupported;
        }
        if let Err(e) = self.backend.flush() {
            return DispatchResult::IoError {
                detail: match e {
                    BridgeError::BioQueueFailed { detail } => detail,
                    _ => "flush backend error",
                },
            };
        }
        // Commit a txg barrier so crash recovery recognizes this durability point.
        if let Err(e) = self.backend.commit_barrier() {
            return DispatchResult::IoError {
                detail: match e {
                    BridgeError::BioQueueFailed { detail } => detail,
                    _ => "txg commit-barrier error",
                },
            };
        }
        DispatchResult::CompletedNoData
    }

    fn dispatch_discard(&mut self, bio: &BlockBio) -> DispatchResult {
        if !self.limits.writable {
            return DispatchResult::Rejected {
                reason: "device is read-only",
            };
        }
        if !self.backend.discard_supported() {
            return DispatchResult::NotSupported;
        }
        if !self
            .limits
            .range_in_bounds(bio.start_sector, bio.sector_count)
        {
            return DispatchResult::Rejected {
                reason: "discard sector range out of bounds",
            };
        }
        if !self.check_discard_budget(bio.start_sector, bio.sector_count) {
            self.discard_budget_exceeded += 1;
            return DispatchResult::Rejected {
                reason: "discard amplification budget exceeded",
            };
        }
        let result = match self
            .backend
            .discard_sectors(bio.start_sector, bio.sector_count)
        {
            Ok(()) => DispatchResult::CompletedNoData,
            Err(e) => DispatchResult::IoError {
                detail: match e {
                    BridgeError::BioQueueFailed { detail } => detail,
                    _ => "discard backend error",
                },
            },
        };
        if result.is_ok() {
            self.discard_count += 1;
            let sc = u64::from(bio.sector_count);
            self.discard_sectors_total = self.discard_sectors_total.saturating_add(sc);
        }
        result
    }

    /// Check whether a discard request fits within the amplification budget.
    fn check_discard_budget(&self, start_sector: u64, sector_count: u32) -> bool {
        let _ = start_sector;
        let budget = &self.discard_budget;
        // Per-operation sector cap (0 = no cap).
        if budget.max_sectors_per_discard > 0
            && u64::from(sector_count) > budget.max_sectors_per_discard
        {
            return false;
        }
        // Lifetime operation cap (0 = unlimited).
        if budget.max_total_discard_ops > 0 && self.discard_count >= budget.max_total_discard_ops {
            return false;
        }
        true
    }

    // ── BLAKE3 digest computation ──────────────────────────────────────

    /// Compute a BLAKE3-256 domain-separated digest for a lifecycle event.
    #[cfg(not(CONFIG_RUST))]
    fn compute_lifecycle_digest(&self, event: &str) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(DOMAIN);
        hasher.update(b"lifecycle:");
        hasher.update(event.as_bytes());
        hasher.update(&self.dispatch_count.to_le_bytes());
        hasher.update(&self.bytes_read.to_le_bytes());
        hasher.update(&self.bytes_written.to_le_bytes());
        hasher.finalize().into()
    }

    /// Compute a BLAKE3-256 domain-separated digest for a lifecycle event (Kbuild stub).
    #[cfg(CONFIG_RUST)]
    fn compute_lifecycle_digest(&self, _event: &str) -> [u8; 32] {
        [0u8; 32]
    }
    /// Compute a BLAKE3-256 domain-separated digest for a bio dispatch.
    #[cfg(not(CONFIG_RUST))]
    fn compute_dispatch_digest(
        &self,
        op: BioOp,
        bio: &BlockBio,
        result: &DispatchResult,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(DOMAIN);
        // Operation type
        hasher.update(&(op as u8).to_le_bytes());
        // Sequence number
        hasher.update(&self.dispatch_count.to_le_bytes());
        // Sector range
        hasher.update(&bio.start_sector.to_le_bytes());
        hasher.update(&bio.sector_count.to_le_bytes());
        // Payload hash (for data integrity verification)
        if op == BioOp::Read || op == BioOp::Write {
            let payload_hash = blake3::hash(&bio.payload);
            hasher.update(payload_hash.as_bytes());
        }
        // Result status
        let result_byte: u8 = if result.is_ok() { 1 } else { 0 };
        hasher.update(&[result_byte]);
        // Cumulative counters
        hasher.update(&self.bytes_read.to_le_bytes());
        hasher.update(&self.bytes_written.to_le_bytes());
        hasher.finalize().into()
    }

    /// Compute a BLAKE3-256 domain-separated dispatch digest (Kbuild stub).
    #[cfg(CONFIG_RUST)]
    fn compute_dispatch_digest(
        &self,
        _op: BioOp,
        _bio: &BlockBio,
        _result: &DispatchResult,
    ) -> [u8; 32] {
        [0u8; 32]
    }
}

impl<B: BlockBackend> core::fmt::Debug for DispatchEngine<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DispatchEngine")
            .field("active", &self.active)
            .field("fenced", &self.fenced)
            .field("dispatch_count", &self.dispatch_count)
            .field("bytes_read", &self.bytes_read)
            .field("bytes_written", &self.bytes_written)
            .field("last_digest", &hex_digest(&self.last_digest))
            .field("discard_count", &self.discard_count)
            .field("discard_sectors_total", &self.discard_sectors_total)
            .field("discard_budget_exceeded", &self.discard_budget_exceeded)
            .finish()
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Format a 32-byte digest as a hex string (first 16 bytes for debug).
#[cfg(not(CONFIG_RUST))]
fn hex_digest(digest: &[u8; 32]) -> alloc::string::String {
    use core::fmt::Write;
    let mut s = alloc::string::String::with_capacity(32);
    for byte in &digest[..16] {
        write!(&mut s, "{byte:02x}").ok();
    }
    s
}

#[cfg(CONFIG_RUST)]
fn hex_digest(digest: &[u8; 32]) -> crate::tidefs_kmod_bridge::kernel_types::KmodString {
    use core::fmt::Write;
    let mut s = crate::tidefs_kmod_bridge::kernel_types::KmodString::new();
    for byte in &digest[..16] {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

// ── BlockBackend impl for BlockExport ──────────────────────────────────

impl BlockBackend for crate::BlockExport {
    fn read_sectors(
        &self,
        start_sector: u64,
        sector_count: u32,
        buf: &mut [u8],
    ) -> BridgeResult<u32> {
        let data = crate::BlockExport::read_sectors(self, start_sector, sector_count)?;
        let copy_len = data.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&data[..copy_len]);
        Ok(copy_len as u32)
    }

    fn write_sectors(&mut self, start_sector: u64, data: &[u8]) -> BridgeResult<u32> {
        crate::BlockExport::write_sectors(self, start_sector, data)?;
        Ok(data.len() as u32)
    }

    fn flush(&mut self) -> BridgeResult<()> {
        // In-memory flush is a no-op; kernel mode issues blkdev_issue_flush.
        Ok(())
    }

    fn commit_barrier(&mut self) -> BridgeResult<()> {
        self.queue.execute_commit_barrier()
    }

    fn capacity(&self) -> u64 {
        self.capacity_bytes()
    }

    fn discard_sectors(&mut self, start_sector: u64, sector_count: u32) -> BridgeResult<()> {
        self.queue.dispatch_discard(start_sector, sector_count)
    }

    fn write_zeroes_sectors(&mut self, start_sector: u64, sector_count: u32) -> BridgeResult<()> {
        self.queue.dispatch_write_zeroes(start_sector, sector_count)
    }

    fn zero_range_sectors(&mut self, start_sector: u64, sector_count: u32) -> BridgeResult<()> {
        self.queue.dispatch_zero_range(start_sector, sector_count)
    }

    fn flush_supported(&self) -> bool {
        self.limits().flush_supported
    }

    fn resize_grow(&mut self, new_capacity_sectors: u64) -> BridgeResult<()> {
        crate::BlockExport::resize_grow(self, new_capacity_sectors)
    }
    fn discard_supported(&self) -> bool {
        self.limits().discard_supported
    }
    fn write_zeroes_supported(&self) -> bool {
        self.limits().write_zeroes_supported
    }
    fn zero_range_supported(&self) -> bool {
        self.limits().zero_range_supported
    }
    fn sector_size(&self) -> u32 {
        self.limits().logical_block_size
    }
}
// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue_rq::BlkMqStatus;
    use crate::{BlockBio, BlockBioSegment, BlockQueueLimits};

    // -- In-memory backend adapter for testing --------------------------

    /// Wraps a [] to implement [].
    struct QueueBackend {
        export: crate::BlockExport,
    }

    impl QueueBackend {
        fn new(limits: BlockQueueLimits) -> BridgeResult<Self> {
            Ok(Self {
                export: crate::BlockExport::with_limits(limits)?,
            })
        }
    }

    impl BlockBackend for QueueBackend {
        fn read_sectors(
            &self,
            start_sector: u64,
            sector_count: u32,
            buf: &mut [u8],
        ) -> BridgeResult<u32> {
            let data = self.export.read_sectors(start_sector, sector_count)?;
            let copy_len = data.len().min(buf.len());
            buf[..copy_len].copy_from_slice(&data[..copy_len]);
            Ok(copy_len as u32)
        }

        fn write_sectors(&mut self, start_sector: u64, data: &[u8]) -> BridgeResult<u32> {
            self.export.write_sectors(start_sector, data)?;
            Ok(data.len() as u32)
        }

        fn flush(&mut self) -> BridgeResult<()> {
            // In-memory backend: flush is a no-op
            Ok(())
        }

        fn commit_barrier(&mut self) -> BridgeResult<()> {
            self.export.queue.execute_commit_barrier()
        }

        fn capacity(&self) -> u64 {
            self.export.capacity_bytes()
        }
        fn discard_sectors(&mut self, start_sector: u64, sector_count: u32) -> BridgeResult<()> {
            let sector_size = self.sector_size() as usize;
            let len = sector_count as usize * sector_size;
            let zeroes = alloc::vec![0u8; len];
            self.export.write_sectors(start_sector, &zeroes)?;
            Ok(())
        }

        fn write_zeroes_sectors(
            &mut self,
            start_sector: u64,
            sector_count: u32,
        ) -> BridgeResult<()> {
            self.export
                .queue
                .dispatch_write_zeroes(start_sector, sector_count)
        }

        fn zero_range_sectors(&mut self, start_sector: u64, sector_count: u32) -> BridgeResult<()> {
            self.export
                .queue
                .dispatch_zero_range(start_sector, sector_count)
        }

        fn write_zeroes_supported(&self) -> bool {
            self.export.limits().write_zeroes_supported
        }

        fn zero_range_supported(&self) -> bool {
            self.export.limits().zero_range_supported
        }

        fn flush_supported(&self) -> bool {
            self.export.limits().flush_supported
        }

        fn discard_supported(&self) -> bool {
            self.export.limits().discard_supported
        }

        fn resize_grow(&mut self, new_capacity_sectors: u64) -> BridgeResult<()> {
            self.export.resize_grow(new_capacity_sectors)
        }

        fn sector_size(&self) -> u32 {
            self.export.limits().logical_block_size
        }
    }

    // ── Test helpers ───────────────────────────────────────────────────

    fn test_limits(capacity_sectors: u64) -> BlockQueueLimits {
        BlockQueueLimits::fixed_capacity(capacity_sectors)
    }

    fn test_limits_with_discard(capacity_sectors: u64) -> BlockQueueLimits {
        BlockQueueLimits {
            logical_block_size: 512,
            physical_block_size: 4096,
            capacity_sectors,
            min_capacity_sectors: capacity_sectors,
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
        }
    }

    fn make_engine(capacity_sectors: u64) -> DispatchEngine<QueueBackend> {
        let limits = test_limits(capacity_sectors);
        let backend = QueueBackend::new(limits).unwrap();
        DispatchEngine::new(backend, limits)
    }

    fn make_engine_with_discard(capacity_sectors: u64) -> DispatchEngine<QueueBackend> {
        let limits = test_limits_with_discard(capacity_sectors);
        let backend = QueueBackend::new(limits).unwrap();
        DispatchEngine::new(backend, limits)
    }

    // ── BioOp classification tests ────────────────────────────────────

    #[test]
    fn bio_op_classify_read() {
        let bio = BlockBio::new_read(0, 1, 512);
        assert_eq!(BioOp::classify(&bio), BioOp::Read);
    }

    #[test]
    fn bio_op_classify_write() {
        let bio = BlockBio::new_write(0, &[0u8; 512], 512);
        assert_eq!(BioOp::classify(&bio), BioOp::Write);
    }

    #[test]
    fn bio_op_classify_flush_takes_priority() {
        let mut bio = BlockBio::new_write(0, &[0u8; 512], 512);
        bio.flush = true;
        assert_eq!(BioOp::classify(&bio), BioOp::Flush);
    }

    #[test]
    fn bio_op_display() {
        assert_eq!(alloc::format!("{}", BioOp::Read), "READ");
        assert_eq!(alloc::format!("{}", BioOp::Write), "WRITE");
        assert_eq!(alloc::format!("{}", BioOp::Flush), "FLUSH");
        assert_eq!(alloc::format!("{}", BioOp::Discard), "DISCARD");
    }

    #[test]
    fn bio_op_discriminants_distinct() {
        let ops = [BioOp::Read, BioOp::Write, BioOp::Flush, BioOp::Discard];
        for i in 0..ops.len() {
            for j in (i + 1)..ops.len() {
                assert_ne!(ops[i], ops[j]);
            }
        }
    }

    // ── DispatchResult tests ──────────────────────────────────────────

    #[test]
    fn dispatch_result_is_ok() {
        assert!(DispatchResult::Completed {
            bytes_transferred: 512
        }
        .is_ok());
        assert!(DispatchResult::CompletedNoData.is_ok());
        assert!(!DispatchResult::NotSupported.is_ok());
        assert!(!DispatchResult::Rejected { reason: "test" }.is_ok());
        assert!(!DispatchResult::IoError { detail: "test" }.is_ok());
    }

    #[test]
    fn dispatch_result_bytes_transferred() {
        assert_eq!(
            DispatchResult::Completed {
                bytes_transferred: 1024
            }
            .bytes_transferred(),
            1024
        );
        assert_eq!(DispatchResult::CompletedNoData.bytes_transferred(), 0);
        assert_eq!(DispatchResult::NotSupported.bytes_transferred(), 0);
    }

    // ── DispatchEngine lifecycle tests ────────────────────────────────

    #[test]
    fn engine_starts_inactive() {
        let engine = make_engine(100);
        assert!(!engine.is_active());
        assert!(!engine.is_fenced());
        assert_eq!(engine.dispatch_count(), 0);
    }

    #[test]
    fn engine_activate_produces_digest() {
        let mut engine = make_engine(100);
        let digest = engine.activate();
        assert!(engine.is_active());
        assert_ne!(digest, [0u8; 32]);
    }

    #[test]
    fn engine_deactivate_produces_digest() {
        let mut engine = make_engine(100);
        engine.activate();
        let digest = engine.deactivate();
        assert!(!engine.is_active());
        assert_ne!(digest, [0u8; 32]);
    }

    #[test]
    fn engine_rejects_bio_when_inactive() {
        let mut engine = make_engine(100);
        let mut bio = BlockBio::new_read(0, 1, 512);
        let result = engine.dispatch(&mut bio);
        assert!(matches!(result, DispatchResult::Rejected { .. }));
    }

    #[test]
    fn engine_rejects_bio_when_fenced() {
        let mut engine = make_engine(100);
        engine.activate();
        engine.fence();
        let mut bio = BlockBio::new_read(0, 1, 512);
        let result = engine.dispatch(&mut bio);
        assert!(matches!(result, DispatchResult::Rejected { .. }));
    }

    #[test]
    fn engine_accepts_bio_after_unfence() {
        let mut engine = make_engine(100);
        engine.activate();
        engine.fence();
        engine.unfence();
        let mut bio = BlockBio::new_read(0, 1, 512);
        let result = engine.dispatch(&mut bio);
        assert!(result.is_ok());
    }

    // ── Dispatch: single-sector read ──────────────────────────────────

    #[test]
    fn single_sector_read_returns_zeroes_initially() {
        let mut engine = make_engine(100);
        engine.activate();
        let mut bio = BlockBio::new_read(0, 1, 512);
        let result = engine.dispatch(&mut bio);
        assert!(result.is_ok());
        assert_eq!(&bio.payload[..512], &[0u8; 512]);
    }

    #[test]
    fn single_sector_read_increments_counters() {
        let mut engine = make_engine(100);
        engine.activate();
        let mut bio = BlockBio::new_read(0, 1, 512);
        engine.dispatch(&mut bio);
        assert_eq!(engine.dispatch_count(), 1);
        assert_eq!(engine.bytes_read(), 512);
        assert_eq!(engine.bytes_written(), 0);
    }

    // ── Dispatch: single-sector write ─────────────────────────────────

    #[test]
    fn single_sector_write_then_read() {
        let mut engine = make_engine(100);
        engine.activate();

        let data = [0xABu8; 512];
        let mut wbio = BlockBio::new_write(5, &data, 512);
        let result = engine.dispatch(&mut wbio);
        assert!(result.is_ok());

        let mut rbio = BlockBio::new_read(5, 1, 512);
        engine.dispatch(&mut rbio);
        assert_eq!(&rbio.payload[..512], &data[..]);
    }

    // ── Dispatch: multi-sector spanning extents ────────────────────────

    #[test]
    fn multi_sector_write_read_spanning() {
        let mut engine = make_engine(200);
        engine.activate();

        let data = alloc::vec![0xCCu8; 8 * 512];
        let mut wbio = BlockBio::new_write(10, &data, 512);
        engine.dispatch(&mut wbio);

        // Read back across the same range
        let mut rbio = BlockBio::new_read(10, 8, 512);
        engine.dispatch(&mut rbio);
        assert_eq!(&rbio.payload[..], &data[..]);
    }

    #[test]
    fn multi_sector_partial_span_read() {
        let mut engine = make_engine(200);
        engine.activate();

        // Write 8 sectors
        let data = alloc::vec![0xDDu8; 8 * 512];
        let mut wbio = BlockBio::new_write(20, &data, 512);
        engine.dispatch(&mut wbio);

        // Read middle 4 sectors
        let mut rbio = BlockBio::new_read(22, 4, 512);
        engine.dispatch(&mut rbio);
        assert_eq!(&rbio.payload[..4 * 512], &data[2 * 512..6 * 512]);
    }

    // ── Dispatch: BLAKE3 verification ─────────────────────────────────

    #[test]
    fn dispatch_produces_non_zero_digest() {
        let mut engine = make_engine(100);
        engine.activate();
        let mut bio = BlockBio::new_read(0, 1, 512);
        engine.dispatch(&mut bio);
        assert_ne!(engine.last_digest(), &[0u8; 32]);
    }

    #[test]
    fn dispatch_digest_changes_per_operation() {
        let mut engine = make_engine(100);
        engine.activate();

        let mut rbio = BlockBio::new_read(0, 1, 512);
        engine.dispatch(&mut rbio);
        let d1 = *engine.last_digest();

        let mut rbio2 = BlockBio::new_read(1, 1, 512);
        engine.dispatch(&mut rbio2);
        let d2 = *engine.last_digest();

        assert_ne!(d1, d2, "digests should differ per dispatch");
    }

    #[test]
    fn dispatch_digest_deterministic() {
        let mut engine1 = make_engine(100);
        engine1.activate();
        let data = b"deterministic payload test v1".to_vec();
        let mut wbio1 = BlockBio::new_write(0, &data, 512);
        engine1.dispatch(&mut wbio1);
        let d1 = *engine1.last_digest();

        let mut engine2 = make_engine(100);
        engine2.activate();
        let mut wbio2 = BlockBio::new_write(0, &data, 512);
        engine2.dispatch(&mut wbio2);
        let d2 = *engine2.last_digest();

        assert_eq!(
            d1, d2,
            "identical dispatch sequences should produce identical digests"
        );
    }

    // ── Dispatch: flush passthrough ───────────────────────────────────

    #[test]
    fn flush_passthrough_ok() {
        let mut engine = make_engine(100);
        engine.activate();

        let mut bio = BlockBio::new_read(0, 1, 512);
        bio.flush = true;
        let result = engine.dispatch(&mut bio);
        assert_eq!(result, DispatchResult::CompletedNoData);
    }

    // ── Dispatch: flush + commit_barrier chain ────────────────────────

    #[test]
    fn flush_increments_commit_barrier_count() {
        let mut engine = make_engine(100);
        engine.activate();

        assert_eq!(engine.backend().export.queue.commit_barrier_count(), 0);

        let mut bio = BlockBio::new_read(0, 1, 512);
        bio.flush = true;
        let result = engine.dispatch(&mut bio);
        assert_eq!(result, DispatchResult::CompletedNoData);
        assert_eq!(engine.backend().export.queue.commit_barrier_count(), 1);

        // Second flush: counter increments again
        let mut bio2 = BlockBio::new_read(0, 1, 512);
        bio2.flush = true;
        engine.dispatch(&mut bio2);
        assert_eq!(engine.backend().export.queue.commit_barrier_count(), 2);
    }

    #[test]
    fn write_flush_barrier_data_visible() {
        let mut engine = make_engine(100);
        engine.activate();

        // Write data, flush (which also commits a barrier), verify data survives
        let data = [0x42u8; 512];
        let mut wbio = BlockBio::new_write(0, &data, 512);
        let wr = engine.dispatch(&mut wbio);
        assert!(wr.is_ok());

        // Flush with barrier
        let mut flush_bio = BlockBio::new_read(0, 1, 512);
        flush_bio.flush = true;
        let fr = engine.dispatch(&mut flush_bio);
        assert_eq!(fr, DispatchResult::CompletedNoData);
        assert_eq!(engine.backend().export.queue.commit_barrier_count(), 1);

        // Data still readable after flush+barrier
        let mut rbio = BlockBio::new_read(0, 1, 512);
        engine.dispatch(&mut rbio);
        assert_eq!(&rbio.payload[..512], &data[..]);
    }

    #[test]
    fn multiple_flush_barrier_chain() {
        let mut engine = make_engine(100);
        engine.activate();

        // Write data to sector 0 and 5
        let data0 = [0xAAu8; 512];
        let data5 = [0xBBu8; 512];
        let mut w0 = BlockBio::new_write(0, &data0, 512);
        let mut w5 = BlockBio::new_write(5, &data5, 512);
        engine.dispatch(&mut w0);
        engine.dispatch(&mut w5);

        // Flush + barrier after writes
        let mut fb = BlockBio::new_read(0, 1, 512);
        fb.flush = true;
        engine.dispatch(&mut fb);
        assert_eq!(engine.backend().export.queue.commit_barrier_count(), 1);

        // Both sectors readable
        let mut r0 = BlockBio::new_read(0, 1, 512);
        let mut r5 = BlockBio::new_read(5, 1, 512);
        engine.dispatch(&mut r0);
        engine.dispatch(&mut r5);
        assert_eq!(&r0.payload[..], &data0[..]);
        assert_eq!(&r5.payload[..], &data5[..]);

        // More writes, another flush+barrier
        let data10 = [0xCCu8; 512];
        let mut w10 = BlockBio::new_write(10, &data10, 512);
        engine.dispatch(&mut w10);
        let mut fb2 = BlockBio::new_read(0, 1, 512);
        fb2.flush = true;
        engine.dispatch(&mut fb2);
        assert_eq!(engine.backend().export.queue.commit_barrier_count(), 2);

        // All three sectors readable
        let mut r10 = BlockBio::new_read(10, 1, 512);
        engine.dispatch(&mut r10);
        assert_eq!(&r10.payload[..], &data10[..]);
    }

    #[test]
    fn write_without_flush_barrier_data_still_visible_same_boot() {
        let mut engine = make_engine(100);
        engine.activate();

        let data = [0x77u8; 512];
        let mut wbio = BlockBio::new_write(3, &data, 512);
        engine.dispatch(&mut wbio);

        // No flush: data still readable (same boot, in-memory)
        let mut rbio = BlockBio::new_read(3, 1, 512);
        engine.dispatch(&mut rbio);
        assert_eq!(&rbio.payload[..], &data[..]);
        // No commit_barrier called
        assert_eq!(engine.backend().export.queue.commit_barrier_count(), 0);
    }

    #[test]
    fn deactivate_then_activate_resets_barrier_count() {
        let mut engine = make_engine(100);
        engine.activate();

        let mut bio = BlockBio::new_read(0, 1, 512);
        bio.flush = true;
        engine.dispatch(&mut bio);
        assert_eq!(engine.backend().export.queue.commit_barrier_count(), 1);

        // Deactivate/reactivate: same queue, counter persists (backend not reset)
        engine.deactivate();
        engine.activate();
        let mut bio2 = BlockBio::new_read(0, 1, 512);
        bio2.flush = true;
        engine.dispatch(&mut bio2);
        // Counter continues from prior state (same BlockExportQueue)
        assert_eq!(engine.backend().export.queue.commit_barrier_count(), 2);
    }

    // ── Dispatch: discard passthrough ─────────────────────────────────

    #[test]
    fn discard_passthrough_zeroes_data() {
        let mut engine = make_engine_with_discard(200);
        engine.activate();

        // Write data first
        let data = [0xFFu8; 512];
        let mut wbio = BlockBio::new_write(5, &data, 512);
        engine.dispatch(&mut wbio);

        // Discard that sector
        let result = engine.dispatch_discard_op(5, 1);
        assert!(result.is_ok());

        // Read back - should be zeroed
        let mut rbio = BlockBio::new_read(5, 1, 512);
        engine.dispatch(&mut rbio);
        assert_eq!(&rbio.payload[..512], &[0u8; 512]);
    }

    #[test]
    fn discard_unsupported_rejected() {
        let mut engine = make_engine(100); // discard_supported = false
        engine.activate();
        let result = engine.dispatch_discard_op(0, 1);
        assert_eq!(result, DispatchResult::NotSupported);
    }

    // ── Dispatch: out-of-bounds rejection ─────────────────────────────

    #[test]
    fn read_beyond_capacity_rejected() {
        let mut engine = make_engine(50);
        engine.activate();
        let mut bio = BlockBio::new_read(60, 1, 512);
        let result = engine.dispatch(&mut bio);
        assert!(matches!(result, DispatchResult::Rejected { .. }));
    }

    #[test]
    fn write_beyond_capacity_rejected() {
        let mut engine = make_engine(50);
        engine.activate();
        let data = [0u8; 512];
        let mut bio = BlockBio::new_write(60, &data, 512);
        let result = engine.dispatch(&mut bio);
        assert!(matches!(result, DispatchResult::Rejected { .. }));
    }

    #[test]
    fn discard_beyond_capacity_rejected() {
        let mut engine = make_engine_with_discard(50);
        engine.activate();
        let result = engine.dispatch_discard_op(60, 1);
        assert!(matches!(result, DispatchResult::Rejected { .. }));
    }

    // ── Dispatch: concurrent / backpressure ───────────────────────────

    #[test]
    fn concurrent_multi_sector_isolation() {
        let mut engine = make_engine(200);
        engine.activate();

        // Write non-overlapping sectors concurrently
        let d1 = [0x11u8; 512];
        let d2 = [0x22u8; 512];
        let d3 = [0x33u8; 512];

        let mut w1 = BlockBio::new_write(0, &d1, 512);
        let mut w2 = BlockBio::new_write(10, &d2, 512);
        let mut w3 = BlockBio::new_write(20, &d3, 512);

        engine.dispatch(&mut w1);
        engine.dispatch(&mut w2);
        engine.dispatch(&mut w3);

        // Verify isolation
        let mut r1 = BlockBio::new_read(0, 1, 512);
        let mut r2 = BlockBio::new_read(10, 1, 512);
        let mut r3 = BlockBio::new_read(20, 1, 512);

        engine.dispatch(&mut r1);
        engine.dispatch(&mut r2);
        engine.dispatch(&mut r3);

        assert_eq!(&r1.payload[..512], &d1[..]);
        assert_eq!(&r2.payload[..512], &d2[..]);
        assert_eq!(&r3.payload[..512], &d3[..]);
    }

    #[test]
    fn backpressure_dispatch_count_monotonic() {
        let mut engine = make_engine(200);
        engine.activate();

        for i in 0u64..128 {
            let data = alloc::vec![i as u8; 512];
            let mut wbio = BlockBio::new_write(i % 100, &data, 512);
            engine.dispatch(&mut wbio);
        }

        assert_eq!(engine.dispatch_count(), 128);
        assert!(engine.bytes_written() > 0);
    }

    // ── Remount persistence ────────────────────────────────────────────

    #[test]
    fn remount_persistence_data_survives() {
        let mut engine = make_engine(200);
        engine.activate();

        // Write data (padded to full sector for block-aligned write)
        let mut data = b"persistent across remount".to_vec();
        data.resize(512, 0xCC);
        let mut wbio = BlockBio::new_write(0, &data, 512);
        let result = engine.dispatch(&mut wbio);
        assert!(result.is_ok(), "write should succeed: {result:?}");

        // Simulate remount: deactivate then reactivate
        engine.deactivate();
        engine.activate();

        // Data should still be there (backend is the same)
        let mut rbio = BlockBio::new_read(0, 1, 512);
        engine.dispatch(&mut rbio);
        assert_eq!(&rbio.payload[..], &data[..]);
    }

    #[test]
    fn remount_dispatch_count_resumes() {
        let mut engine = make_engine(200);
        engine.activate();

        let mut bio = BlockBio::new_read(0, 1, 512);
        engine.dispatch(&mut bio);
        assert_eq!(engine.dispatch_count(), 1);

        // Deactivate: bios are now rejected
        engine.deactivate();
        let mut bio2 = BlockBio::new_read(0, 1, 512);
        let result = engine.dispatch(&mut bio2);
        assert!(!result.is_ok(), "bio should be rejected when inactive");
        assert_eq!(engine.dispatch_count(), 1); // unchanged (rejected bios don't count)

        // Reactivate: new bios are accepted, count resumes
        engine.activate();
        let mut bio3 = BlockBio::new_read(0, 1, 512);
        engine.dispatch(&mut bio3);
        assert_eq!(engine.dispatch_count(), 2);
        assert!(engine.is_active());
    }

    // ── Accessor tests ────────────────────────────────────────────────

    #[test]
    fn engine_limits_accessor() {
        let engine = make_engine(1024);
        assert_eq!(engine.limits().capacity_sectors, 1024);
    }

    #[test]
    fn engine_backend_accessor() {
        let engine = make_engine(100);
        assert_eq!(engine.backend().sector_size(), 512);
        assert!(engine.backend().flush_supported());
    }

    // ── Debug output tests ────────────────────────────────────────────

    #[test]
    fn dispatch_engine_debug() {
        let engine = make_engine(100);
        let dbg = alloc::format!("{engine:?}");
        assert!(dbg.contains("DispatchEngine"));
        assert!(dbg.contains("active"));
    }

    #[test]
    fn dispatch_result_debug() {
        let r = DispatchResult::Completed {
            bytes_transferred: 512,
        };
        assert!(alloc::format!("{r:?}").contains("Completed"));
    }

    // ── Multi-segment bio dispatch tests ──────────────────────────────

    #[test]
    fn multi_segment_write_then_read_roundtrip() {
        let mut engine = make_engine(200);
        engine.activate();

        // Create a 4-sector write split across 2 segments:
        // seg1: sectors 0-1 (offset 0, len 1024) = 0xAA
        // seg2: sectors 2-3 (offset 1024, len 1024) = 0xBB
        let seg1 = BlockBioSegment::new(0, alloc::vec![0xAAu8; 1024]);
        let seg2 = BlockBioSegment::new(1024, alloc::vec![0xBBu8; 1024]);
        let segments = alloc::vec![seg1, seg2];
        let mut wbio = BlockBio::new_write_segmented(10, 4, 512, segments);
        let result = engine.dispatch(&mut wbio);
        assert!(result.is_ok(), "multi-segment write failed: {result:?}");

        // Read back sector 10 (2 sectors): both from seg1 = all 0xAA
        let mut rbio = BlockBio::new_read(10, 2, 512);
        engine.dispatch(&mut rbio);
        assert_eq!(&rbio.payload[..], &[0xAAu8; 1024]);

        // Read back sector 12 (2 sectors): both from seg2 = all 0xBB
        let mut rbio2 = BlockBio::new_read(12, 2, 512);
        engine.dispatch(&mut rbio2);
        assert_eq!(&rbio2.payload[..], &[0xBBu8; 1024]);
    }

    #[test]
    fn multi_segment_read_scatters_data() {
        let mut engine = make_engine(200);
        engine.activate();

        // Write flat data first
        let data = alloc::vec![0xCCu8; 2048];
        let mut wbio = BlockBio::new_write(0, &data, 512);
        engine.dispatch(&mut wbio);

        // Read back with 3 segments
        let seg1 = BlockBioSegment::new(0, alloc::vec![0u8; 512]);
        let seg2 = BlockBioSegment::new(512, alloc::vec![0u8; 1024]);
        let seg3 = BlockBioSegment::new(1536, alloc::vec![0u8; 512]);
        let segments = alloc::vec![seg1, seg2, seg3];
        let mut rbio = BlockBio::new_read_segmented(0, 4, 512, segments);

        let result = engine.dispatch(&mut rbio);
        assert!(result.is_ok(), "multi-seg read failed: {result:?}");

        // Verify segments were filled
        assert_eq!(&rbio.segments_ref()[0].data[..], &data[..512]);
        assert_eq!(&rbio.segments_ref()[1].data[..], &data[512..1536]);
        assert_eq!(&rbio.segments_ref()[2].data[..], &data[1536..]);
    }

    #[test]
    fn multi_segment_write_gathers_data() {
        let mut engine = make_engine(200);
        engine.activate();

        // Write with 3 segments
        let seg1 = BlockBioSegment::new(0, alloc::vec![0x11u8; 512]);
        let seg2 = BlockBioSegment::new(512, alloc::vec![0x22u8; 1024]);
        let seg3 = BlockBioSegment::new(1536, alloc::vec![0x33u8; 512]);
        let segments = alloc::vec![seg1, seg2, seg3];
        let mut wbio = BlockBio::new_write_segmented(5, 4, 512, segments);
        let result = engine.dispatch(&mut wbio);
        assert!(result.is_ok(), "multi-seg write failed: {result:?}");

        // Read back flat
        let mut rbio = BlockBio::new_read(5, 4, 512);
        engine.dispatch(&mut rbio);
        assert_eq!(&rbio.payload[..512], &[0x11u8; 512]);
        assert_eq!(&rbio.payload[512..1536], &[0x22u8; 1024]);
        assert_eq!(&rbio.payload[1536..], &[0x33u8; 512]);
    }

    #[test]
    fn partial_completion_short_read() {
        let mut engine = make_engine(200);
        engine.activate();

        // Write 4 sectors of data
        let data = alloc::vec![0xDDu8; 2048];
        let mut wbio = BlockBio::new_write(0, &data, 512);
        engine.dispatch(&mut wbio);

        // Read with 6 segments requesting 6 sectors
        let s0 = BlockBioSegment::new(0, alloc::vec![0u8; 512]);
        let s1 = BlockBioSegment::new(512, alloc::vec![0u8; 512]);
        let s2 = BlockBioSegment::new(1024, alloc::vec![0u8; 512]);
        let s3 = BlockBioSegment::new(1536, alloc::vec![0u8; 512]);
        let s4 = BlockBioSegment::new(2048, alloc::vec![0u8; 512]);
        let s5 = BlockBioSegment::new(2560, alloc::vec![0u8; 512]);
        let segments = alloc::vec![s0, s1, s2, s3, s4, s5];
        let mut rbio = BlockBio::new_read_segmented(0, 6, 512, segments);
        // Pre-condition: read within capacity range (6 sectors at sector 0)
        let result = engine.dispatch(&mut rbio);
        // Should be completed (all 6 sectors within 200-sector capacity)
        assert!(result.is_ok());
    }

    #[test]
    fn segment_count_preserved_in_constructor() {
        let seg1 = BlockBioSegment::new(0, alloc::vec![0u8; 512]);
        let seg2 = BlockBioSegment::new(512, alloc::vec![0u8; 512]);
        let segments = alloc::vec![seg1, seg2];
        let bio = BlockBio::new_read_segmented(0, 2, 512, segments);
        assert_eq!(bio.segment_count(), 2);
        assert_eq!(bio.total_payload_len(), 1024);
    }

    #[test]
    fn segment_count_one_for_single_buffer() {
        let bio = BlockBio::new_read(0, 4, 512);
        // Single payload → single segment
        assert_eq!(bio.segment_count(), 1);
        assert_eq!(bio.total_payload_len(), 2048);
    }

    #[test]
    fn sync_payload_from_segments_after_read() {
        let mut engine = make_engine(200);
        engine.activate();

        let data = alloc::vec![0xEEu8; 1024];
        let mut wbio = BlockBio::new_write(0, &data, 512);
        engine.dispatch(&mut wbio);

        let segments = alloc::vec![
            BlockBioSegment::new(0, alloc::vec![0u8; 512]),
            BlockBioSegment::new(512, alloc::vec![0u8; 512]),
        ];
        let mut rbio = BlockBio::new_read_segmented(0, 2, 512, segments);
        engine.dispatch(&mut rbio);
        rbio.sync_payload_from_segments();
        assert_eq!(&rbio.payload[..], &data[..]);
    }

    #[test]
    fn dispatch_partial_variant_coverage() {
        // Verify the Partial variant is reachable through the match arms
        let partial = DispatchResult::Partial {
            bytes_transferred: 256,
            bytes_requested: 512,
        };
        assert!(partial.is_ok());
        assert_eq!(partial.bytes_transferred(), 256);
        assert!(!matches!(partial, DispatchResult::Completed { .. }));
    }

    #[test]
    fn partial_bytes_transferred_correct() {
        let partial = DispatchResult::Partial {
            bytes_transferred: 128,
            bytes_requested: 512,
        };
        assert_eq!(partial.bytes_transferred(), 128);
    }

    #[test]
    fn completion_outcome_from_partial_result() {
        use crate::request_completion::CompletionOutcome;
        let partial = DispatchResult::Partial {
            bytes_transferred: 256,
            bytes_requested: 512,
        };
        let outcome = CompletionOutcome::from(&partial);
        assert_eq!(outcome.status, BlkMqStatus::Ok);
        assert_eq!(outcome.bytes_transferred, 256);
        assert_eq!(outcome.bytes_requested, 512);
    }

    #[test]
    fn dispatch_result_debug_partial() {
        let r = DispatchResult::Partial {
            bytes_transferred: 128,
            bytes_requested: 512,
        };
        let s = alloc::format!("{r:?}");
        assert!(s.contains("Partial"));
    }
    // ── Queue-depth saturation tests ─────────────────────────────────

    #[test]
    fn saturation_rejects_when_inflight_equals_max_queue_depth() {
        let mut engine = make_engine(100);
        engine.activate();
        // Set inflight artificially to max_queue_depth limit
        engine
            .inflight
            .store(engine.limits.max_queue_depth, Ordering::Release);
        let mut bio = BlockBio::new_read(0, 1, 512);
        let result = engine.dispatch(&mut bio);
        assert!(
            matches!(result, DispatchResult::Rejected { reason } if reason.contains("saturated"))
        );
        assert_eq!(engine.saturation_rejections(), 1);
    }

    #[test]
    fn saturation_rejects_when_inflight_exceeds_max_queue_depth() {
        let mut engine = make_engine(100);
        engine.activate();
        engine
            .inflight
            .store(engine.limits.max_queue_depth + 5, Ordering::Release);
        let mut bio = BlockBio::new_read(0, 1, 512);
        let result = engine.dispatch(&mut bio);
        assert!(
            matches!(result, DispatchResult::Rejected { reason } if reason.contains("saturated"))
        );
    }

    #[test]
    fn saturation_undoes_inflight_increment_on_rejection() {
        let mut engine = make_engine(100);
        engine.activate();
        let max_depth = engine.limits.max_queue_depth;
        engine.inflight.store(max_depth, Ordering::Release);
        let mut bio = BlockBio::new_read(0, 1, 512);
        let _ = engine.dispatch(&mut bio);
        // After rejection, inflight must still be max_depth (increment was undone)
        assert_eq!(engine.inflight(), max_depth);
    }

    #[test]
    fn saturation_rejection_count_increments() {
        let mut engine = make_engine(100);
        engine.activate();
        engine
            .inflight
            .store(engine.limits.max_queue_depth, Ordering::Release);
        let mut bio1 = BlockBio::new_read(0, 1, 512);
        let mut bio2 = BlockBio::new_read(5, 1, 512);
        engine.dispatch(&mut bio1);
        engine.dispatch(&mut bio2);
        assert_eq!(engine.saturation_rejections(), 2);
    }

    #[test]
    fn saturation_does_not_block_valid_dispatch_at_max() {
        let mut engine = make_engine(100);
        engine.activate();
        let max_depth = engine.limits.max_queue_depth;
        // Set inflight to max_depth - 1: one slot available
        engine.inflight.store(max_depth - 1, Ordering::Release);
        let mut bio = BlockBio::new_read(0, 1, 512);
        let result = engine.dispatch(&mut bio);
        assert!(
            result.is_ok(),
            "dispatch should succeed when below max: {result:?}"
        );
        // Inflight should return to max_depth - 1 after successful dispatch
        assert_eq!(engine.inflight(), max_depth - 1);
    }

    #[test]
    fn saturation_with_max_queue_depth_1_allows_one() {
        let limits = {
            let mut l = BlockQueueLimits::fixed_capacity(100);
            l.max_queue_depth = 1;
            l
        };
        let backend = QueueBackend::new(limits).unwrap();
        let mut engine = DispatchEngine::new(backend, limits);
        engine.activate();

        // First dispatch succeeds
        let mut bio = BlockBio::new_read(0, 1, 512);
        let result = engine.dispatch(&mut bio);
        assert!(result.is_ok(), "first dispatch failed: {result:?}");

        // Artificially inflate inflight to 1: next dispatch should saturate
        engine.inflight.store(1, Ordering::Release);
        let mut bio2 = BlockBio::new_read(5, 1, 512);
        let result2 = engine.dispatch(&mut bio2);
        assert!(
            matches!(result2, DispatchResult::Rejected { reason } if reason.contains("saturated"))
        );
    }

    // ── Fairness counter tests ────────────────────────────────────────

    #[test]
    fn read_count_tracks_reads() {
        let mut engine = make_engine(100);
        engine.activate();
        assert_eq!(engine.read_count(), 0);
        for i in 0..10 {
            let mut bio = BlockBio::new_read(i % 20, 1, 512);
            engine.dispatch(&mut bio);
        }
        assert_eq!(engine.read_count(), 10);
    }

    #[test]
    fn write_count_tracks_writes() {
        let mut engine = make_engine(100);
        engine.activate();
        assert_eq!(engine.write_count(), 0);
        for i in 0..10 {
            let data = [(i as u8); 512];
            let mut bio = BlockBio::new_write(i % 20, &data, 512);
            engine.dispatch(&mut bio);
        }
        assert_eq!(engine.write_count(), 10);
    }

    #[test]
    fn flush_count_tracks_flushes() {
        let mut engine = make_engine(100);
        engine.activate();
        assert_eq!(engine.flush_count(), 0);
        for _ in 0..5 {
            let mut bio = BlockBio::new_read(0, 1, 512);
            bio.flush = true;
            engine.dispatch(&mut bio);
        }
        assert_eq!(engine.flush_count(), 5);
    }

    #[test]
    fn read_write_counts_independent() {
        let mut engine = make_engine(100);
        engine.activate();
        // 3 reads, 5 writes
        for _ in 0..3 {
            let mut bio = BlockBio::new_read(0, 1, 512);
            engine.dispatch(&mut bio);
        }
        for i in 0..5 {
            let data = [(i as u8); 512];
            let mut bio = BlockBio::new_write(i % 20, &data, 512);
            engine.dispatch(&mut bio);
        }
        assert_eq!(engine.read_count(), 3);
        assert_eq!(engine.write_count(), 5);
        assert_eq!(engine.flush_count(), 0);
    }

    #[test]
    fn mixed_read_write_flush_fairness() {
        let mut engine = make_engine(200);
        engine.activate();
        // Mixed workload: reads, writes, and flushes
        let data = [0xAAu8; 512];
        for i in 0..20 {
            let mut bio = if i % 3 == 0 {
                let mut b = BlockBio::new_read(i, 1, 512);
                b.flush = i % 6 == 0;
                b
            } else {
                BlockBio::new_write(i, &data, 512)
            };
            engine.dispatch(&mut bio);
        }
        // Verifies counts are plausible (total 20 dispatches, all successful)
        let total = engine.read_count() + engine.write_count() + engine.flush_count();
        assert_eq!(
            total,
            20,
            "total dispatch count mismatch: r={} w={} f={}",
            engine.read_count(),
            engine.write_count(),
            engine.flush_count()
        );
    }

    // ── Inflight integrity tests ──────────────────────────────────────

    #[test]
    fn inflight_always_returns_to_zero_after_synchronous_dispatch() {
        let mut engine = make_engine(100);
        engine.activate();
        for i in 0..50 {
            let mut bio = BlockBio::new_read(i % 20, 1, 512);
            let result = engine.dispatch(&mut bio);
            assert!(result.is_ok(), "dispatch {i} failed: {result:?}");
            assert_eq!(engine.inflight(), 0, "inflight not zero after dispatch {i}");
        }
    }

    #[test]
    fn inflight_correct_on_validation_failure() {
        let mut engine = make_engine(50);
        engine.activate();
        // dispatch out-of-bounds: should undo inflight increment
        let mut bio = BlockBio::new_read(60, 1, 512);
        let result = engine.dispatch(&mut bio);
        assert!(!result.is_ok());
        assert_eq!(
            engine.inflight(),
            0,
            "inflight not zero after validation rejection"
        );
    }

    #[test]
    fn inflight_correct_when_inactive() {
        let mut engine = make_engine(100);
        // Engine not activated: dispatch should reject without touching inflight
        let mut bio = BlockBio::new_read(0, 1, 512);
        let result = engine.dispatch(&mut bio);
        assert!(
            matches!(result, DispatchResult::Rejected { reason } if reason.contains("not active"))
        );
        assert_eq!(engine.inflight(), 0);
    }

    #[test]
    fn inflight_correct_when_fenced() {
        let mut engine = make_engine(100);
        engine.activate();
        engine.fence();
        let mut bio = BlockBio::new_read(0, 1, 512);
        let result = engine.dispatch(&mut bio);
        assert!(matches!(result, DispatchResult::Rejected { reason } if reason.contains("fenced")));
        assert_eq!(engine.inflight(), 0);
    }

    // ── Combined saturation + fairness stress ─────────────────────────

    #[test]
    fn saturation_and_fairness_stress() {
        let mut limits = BlockQueueLimits::fixed_capacity(500);
        limits.max_queue_depth = 16;
        let backend = QueueBackend::new(limits).unwrap();
        let mut engine = DispatchEngine::new(backend, limits);
        engine.activate();

        // Simulate a saturated workload: set inflight to max_depth frequently
        // to force rejections, then validate fairness counters still track correctly
        let data = [0xCCu8; 512];
        let mut ok_dispatches = 0u64;
        for i in 0..200u64 {
            if i % 20 == 0 {
                // Saturate the queue
                engine
                    .inflight
                    .store(engine.limits.max_queue_depth, Ordering::Release);
            }
            let mut bio = if i % 2 == 0 {
                BlockBio::new_read(i % 100, 1, 512)
            } else {
                BlockBio::new_write(i % 100, &data, 512)
            };
            if engine.dispatch(&mut bio).is_ok() {
                ok_dispatches += 1;
            }
        }
        // Fairness counters should only count successful dispatches
        let total_counted = engine.read_count() + engine.write_count() + engine.flush_count();
        assert_eq!(
            total_counted, ok_dispatches,
            "counted dispatches ({total_counted}) != ok_dispatches ({ok_dispatches})"
        );
        assert!(
            engine.saturation_rejections() > 0,
            "should have some saturation rejections"
        );
    }

    // ── Accessor coverage ─────────────────────────────────────────────

    #[test]
    fn saturation_rejections_starts_at_zero() {
        let engine = make_engine(100);
        assert_eq!(engine.saturation_rejections(), 0);
        assert_eq!(engine.inflight(), 0);
        assert_eq!(engine.read_count(), 0);
        assert_eq!(engine.write_count(), 0);
        assert_eq!(engine.flush_count(), 0);
        assert_eq!(engine.discard_count(), 0);
        assert_eq!(engine.discard_sectors_total(), 0);
        assert_eq!(engine.discard_budget_exceeded(), 0);
    }

    // ── Discard amplification budget tests ────────────────────────────

    #[test]
    fn discard_budget_unlimited_by_default() {
        let mut engine = make_engine_with_discard(200);
        engine.activate();
        // Unlimited budget: all discards succeed
        for _ in 0..100 {
            let result = engine.dispatch_discard_op(0, 1);
            assert!(
                result.is_ok(),
                "discard should succeed with unlimited budget"
            );
        }
        assert_eq!(engine.discard_count(), 100);
        assert_eq!(engine.discard_sectors_total(), 100);
        assert_eq!(engine.discard_budget_exceeded(), 0);
    }

    #[test]
    fn discard_budget_lifetime_cap_rejects_after_limit() {
        let mut engine = make_engine_with_discard(200);
        engine.activate();
        engine.set_discard_budget(DiscardAmplificationBudget::with_lifetime_cap(5));
        // First 5 succeed
        for _ in 0..5 {
            assert!(engine.dispatch_discard_op(0, 1).is_ok());
        }
        assert_eq!(engine.discard_count(), 5);
        assert_eq!(engine.discard_budget_exceeded(), 0);
        // 6th and beyond rejected
        for _ in 0..3 {
            let result = engine.dispatch_discard_op(0, 1);
            assert!(
                matches!(result, DispatchResult::Rejected { reason } if reason.contains("amplification budget"))
            );
        }
        assert_eq!(engine.discard_count(), 5); // unchanged
        assert_eq!(engine.discard_budget_exceeded(), 3);
    }

    #[test]
    fn discard_budget_per_op_sector_cap_rejects_large_discard() {
        let mut engine = make_engine_with_discard(200);
        engine.activate();
        let mut budget = DiscardAmplificationBudget::unlimited();
        budget.max_sectors_per_discard = 10;
        engine.set_discard_budget(budget);
        // Small discard (1 sector) succeeds
        assert!(engine.dispatch_discard_op(0, 1).is_ok());
        assert_eq!(engine.discard_count(), 1);
        // Large discard (11 sectors) rejected
        let result = engine.dispatch_discard_op(0, 11);
        assert!(
            matches!(result, DispatchResult::Rejected { reason } if reason.contains("amplification budget"))
        );
        assert_eq!(engine.discard_budget_exceeded(), 1);
    }

    #[test]
    fn discard_budget_per_op_sector_cap_zero_means_no_cap() {
        let mut engine = make_engine_with_discard(200);
        engine.activate();
        // budget.max_sectors_per_discard = 0 means unlimited per-op
        engine.set_discard_budget(DiscardAmplificationBudget::unlimited());
        assert!(engine.dispatch_discard_op(0, 200).is_ok());
        assert_eq!(engine.discard_count(), 1);
        assert_eq!(engine.discard_budget_exceeded(), 0);
    }

    #[test]
    fn discard_budget_both_caps_can_be_active() {
        let mut engine = make_engine_with_discard(200);
        engine.activate();
        let budget = DiscardAmplificationBudget {
            max_sectors_per_discard: 5,
            max_total_discard_ops: 3,
        };
        engine.set_discard_budget(budget);
        // First 3 small discards succeed
        for _ in 0..3 {
            assert!(engine.dispatch_discard_op(0, 3).is_ok());
        }
        assert_eq!(engine.discard_count(), 3);
        // 4th rejected by lifetime cap
        let result = engine.dispatch_discard_op(0, 3);
        assert!(
            matches!(result, DispatchResult::Rejected { reason } if reason.contains("amplification budget"))
        );
        assert_eq!(engine.discard_budget_exceeded(), 1);
        // Large discard also rejected by per-op cap (even if lifetime wasn't hit)
        engine.set_discard_budget(DiscardAmplificationBudget {
            max_sectors_per_discard: 5,
            max_total_discard_ops: 0,
        });
        let result2 = engine.dispatch_discard_op(0, 10);
        assert!(
            matches!(result2, DispatchResult::Rejected { reason } if reason.contains("amplification budget"))
        );
    }

    #[test]
    fn discard_budget_via_dispatch_bio_path() {
        let mut engine = make_engine_with_discard(200);
        engine.activate();
        engine.set_discard_budget(DiscardAmplificationBudget::with_lifetime_cap(2));
        // dispatch_discard is called via the BlockBio path (classified as Discard)
        // In the current implementation, Discard is not classified by BlockBio::classify(),
        // so we test dispatch_discard_op directly. The bio dispatch path for discard
        // also works through dispatch_discard_op.
        assert!(engine.dispatch_discard_op(0, 1).is_ok());
        assert!(engine.dispatch_discard_op(1, 1).is_ok());
        let result = engine.dispatch_discard_op(2, 1);
        assert!(
            matches!(result, DispatchResult::Rejected { reason } if reason.contains("amplification budget"))
        );
    }

    #[test]
    fn discard_budget_exceeded_starts_at_zero() {
        let engine = make_engine_with_discard(100);
        assert_eq!(engine.discard_budget_exceeded(), 0);
        assert_eq!(engine.discard_count(), 0);
        assert_eq!(engine.discard_sectors_total(), 0);
    }

    #[test]
    fn discard_sectors_total_accumulates_correctly() {
        let mut engine = make_engine_with_discard(200);
        engine.activate();
        assert!(engine.dispatch_discard_op(0, 3).is_ok());
        assert!(engine.dispatch_discard_op(10, 7).is_ok());
        assert!(engine.dispatch_discard_op(50, 1).is_ok());
        assert_eq!(engine.discard_sectors_total(), 11);
        assert_eq!(engine.discard_count(), 3);
    }

    #[test]
    fn set_discard_budget_does_not_reset_counters() {
        let mut engine = make_engine_with_discard(200);
        engine.activate();
        assert!(engine.dispatch_discard_op(0, 1).is_ok());
        assert_eq!(engine.discard_count(), 1);
        // Change budget - counters persist
        engine.set_discard_budget(DiscardAmplificationBudget::with_lifetime_cap(10));
        assert_eq!(engine.discard_count(), 1);
        assert_eq!(engine.discard_sectors_total(), 1);
    }

    // ── Read-only export enforcement tests ────────────────────────────

    #[test]
    fn read_only_rejects_write_bio() {
        let mut engine = make_engine(100);
        engine.activate();
        engine.set_writable(false);
        let data = [0xAAu8; 512];
        let mut bio = BlockBio::new_write(0, &data, 512);
        let result = engine.dispatch(&mut bio);
        assert!(
            matches!(result, DispatchResult::Rejected { reason } if reason.contains("read-only"))
        );
    }

    #[test]
    fn read_only_allows_read_bio() {
        let mut engine = make_engine(100);
        engine.activate();
        engine.set_writable(false);
        let mut bio = BlockBio::new_read(0, 1, 512);
        let result = engine.dispatch(&mut bio);
        assert!(result.is_ok());
    }

    #[test]
    fn read_only_rejects_discard() {
        let limits = test_limits_with_discard(100);
        let backend = QueueBackend::new(limits).unwrap();
        let mut engine = DispatchEngine::new(backend, limits);
        engine.activate();
        engine.set_writable(false);
        let result = engine.dispatch_discard_op(0, 10);
        assert!(
            matches!(result, DispatchResult::Rejected { reason } if reason.contains("read-only"))
        );
    }

    #[test]
    fn read_only_rejects_write_zeroes() {
        let mut limits = test_limits(100);
        limits.write_zeroes_supported = true;
        let backend = QueueBackend::new(limits).unwrap();
        let mut engine = DispatchEngine::new(backend, limits);
        engine.activate();
        engine.set_writable(false);
        let result = engine.dispatch_write_zeroes_op(0, 10);
        assert!(
            matches!(result, DispatchResult::Rejected { reason } if reason.contains("read-only"))
        );
    }

    #[test]
    fn read_only_rejects_zero_range() {
        let mut limits = test_limits(100);
        limits.zero_range_supported = true;
        let backend = QueueBackend::new(limits).unwrap();
        let mut engine = DispatchEngine::new(backend, limits);
        engine.activate();
        engine.set_writable(false);
        let result = engine.dispatch_zero_range_op(0, 10);
        assert!(
            matches!(result, DispatchResult::Rejected { reason } if reason.contains("read-only"))
        );
    }

    #[test]
    fn read_only_set_writable_reenables_writes() {
        let mut engine = make_engine(100);
        engine.activate();
        engine.set_writable(false);
        let data = [0xAAu8; 512];
        let mut bio = BlockBio::new_write(0, &data, 512);
        let result = engine.dispatch(&mut bio);
        assert!(
            matches!(result, DispatchResult::Rejected { reason } if reason.contains("read-only"))
        );

        engine.set_writable(true);
        let mut bio2 = BlockBio::new_write(0, &data, 512);
        let result2 = engine.dispatch(&mut bio2);
        assert!(result2.is_ok());
    }

    #[test]
    fn read_only_flush_still_accepted() {
        // Flush is not a mutating storage operation; it drains volatile
        // caches. Read-only devices should still accept flush barriers.
        let mut engine = make_engine(100);
        engine.activate();
        engine.set_writable(false);
        let mut bio = BlockBio::new_read(0, 1, 512).with_flush();
        let result = engine.dispatch(&mut bio);
        assert!(result.is_ok());
    }
}
