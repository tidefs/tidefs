//! blk-mq request completion dispatch bridging VfsEngine I/O outcomes
//! to Linux block-layer `blk_mq_end_request`.
//!
//! This module converts VfsEngine block I/O outcomes into Linux
//! `blk_status_t` values and provides the completion dispatch that
//! calls `blk_mq_end_request` with the appropriate status and byte
//! count, closing the dispatch-to-completion loop after `queue_rq`
//! dispatches work to VfsEngine.
//!
//! # Data-path contract
//!
//! ```text
//! queue_rq dispatch
//!   → VfsEngine::block_read / block_write / block_flush / block_discard
//!   → CompletionOutcome (status + bytes_transferred)
//!   → RequestCompletion::complete()
//!     → blk_mq_end_request(status, bytes)
//! ```
//!
//! # blk_status_t error taxonomy
//!
//! VfsEngine errors map to Linux `blk_status_t` values through
//! [`BlkMqStatus`]:
//!
//! | VfsEngine Errno | BlkMqStatus  | blk_status_t    | Retry?  |
//! |-----------------|--------------|-----------------|---------|
//! | Success         | `Ok`         | `BLK_STS_OK`    | —       |
//! | `ENOSPC`        | `NoSpace`    | `BLK_STS_NOSPC` | No      |
//! | `EIO`           | `IoError`    | `BLK_STS_IOERR` | No      |
//! | `ENXIO`     | `Medium`     | `BLK_STS_MEDIUM`| No      |
//! | `ENOSYS`        | `IoError`    | `BLK_STS_IOERR` | No      |
//! | other           | `IoError`    | `BLK_STS_IOERR` | No      |
//!
//! # Partial completions
//!
//! Short reads and writes (where `bytes_transferred < requested`) are
//! signalled with `BlkMqStatus::Ok` and the actual byte count. The
//! block layer uses `blk_update_request` to advance the residual
//! before the final `blk_mq_end_request`.
//!
//! # Userspace vs kernel mode
//!
//! Cargo builds use a typed model that records the completion outcome for test
//! verification. The Kbuild entrypoint translates completed requests to
//! `blk_mq_end_request` in `../tidefs_block_kmod.rs`.

use crate::dispatch::DispatchResult;
use crate::queue_rq::{BlkMqStatus, QueueRqOutcome};
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge::kernel_types::Errno;
#[cfg(not(CONFIG_RUST))]
use tidefs_vfs_engine::Errno;

// ── CompletionOutcome ───────────────────────────────────────────────────

/// Completion outcome carrying the blk-mq status and bytes-transferred
/// count for a single `blk_mq_end_request` call.
///
/// This is the final product of the dispatch-to-completion pipeline:
/// `queue_rq` dispatches to VfsEngine, VfsEngine returns a result,
/// and the result is mapped into a `CompletionOutcome` that feeds
/// `blk_mq_end_request`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompletionOutcome {
    /// blk-mq status code for `blk_mq_end_request`.
    pub status: BlkMqStatus,
    /// Number of bytes transferred.
    pub bytes_transferred: u32,
    /// Number of bytes requested (for partial-completion diagnosis).
    pub bytes_requested: u32,
}

impl CompletionOutcome {
    /// Full success: all requested bytes transferred.
    #[must_use]
    pub const fn ok(bytes: u32) -> Self {
        Self {
            status: BlkMqStatus::Ok,
            bytes_transferred: bytes,
            bytes_requested: bytes,
        }
    }

    /// Partial success: fewer bytes transferred than requested.
    ///
    /// The block layer uses `blk_update_request` to advance the
    /// residual before the final `blk_mq_end_request`.
    #[must_use]
    pub const fn partial(bytes_transferred: u32, bytes_requested: u32) -> Self {
        Self {
            status: BlkMqStatus::Ok,
            bytes_transferred,
            bytes_requested,
        }
    }

    /// Error outcome: no bytes transferred.
    #[must_use]
    pub const fn err(status: BlkMqStatus, bytes_requested: u32) -> Self {
        Self {
            status,
            bytes_transferred: 0,
            bytes_requested,
        }
    }

    /// Whether the completion carries a success status.
    #[must_use]
    pub fn is_ok(self) -> bool {
        self.status.is_ok()
    }

    /// Whether this is a partial completion (transferred < requested).
    #[must_use]
    pub fn is_partial(self) -> bool {
        self.status.is_ok() && self.bytes_transferred < self.bytes_requested
    }

    /// Number of bytes not transferred (residual for
    /// `blk_update_request`).
    #[must_use]
    pub fn residual(self) -> u32 {
        self.bytes_requested.saturating_sub(self.bytes_transferred)
    }
}

// ── From conversions ─────────────────────────────────────────────────────

impl From<QueueRqOutcome> for CompletionOutcome {
    /// Convert a `queue_rq` dispatch outcome into a `blk_mq_end_request`
    /// completion.
    ///
    /// The `QueueRqOutcome` carries the status and bytes transferred;
    /// the requested byte count is set to the transferred count for
    /// full-success outcomes (the dispatch path does not track the
    /// original request size separately).
    fn from(outcome: QueueRqOutcome) -> Self {
        Self {
            status: outcome.status,
            bytes_transferred: outcome.bytes_transferred,
            bytes_requested: outcome.bytes_transferred,
        }
    }
}

impl From<Result<u32, Errno>> for CompletionOutcome {
    /// Convert a VfsEngine block-operation result into a completion.
    ///
    /// The returned byte count becomes both `bytes_transferred` and
    /// `bytes_requested`. For partial-completion detection with an
    /// explicit request size, use [`completion_from_result`].
    fn from(result: Result<u32, Errno>) -> Self {
        match result {
            Ok(bytes) => Self::ok(bytes),
            Err(e) => Self::err(BlkMqStatus::from(e), 0),
        }
    }
}

/// Build a [`CompletionOutcome`] from a VfsEngine result with an
/// explicit `bytes_requested` for partial-completion detection.
#[must_use]
pub fn completion_from_result(
    result: Result<u32, Errno>,
    bytes_requested: u32,
) -> CompletionOutcome {
    match result {
        Ok(bytes) if bytes >= bytes_requested => CompletionOutcome::ok(bytes),
        Ok(bytes) => CompletionOutcome::partial(bytes, bytes_requested),
        Err(e) => CompletionOutcome::err(BlkMqStatus::from(e), bytes_requested),
    }
}

// ── From<DispatchResult> ───────────────────────────────────────────────────

impl From<&DispatchResult> for CompletionOutcome {
    /// Convert a `DispatchResult` from the dispatch engine into a
    /// `CompletionOutcome` for `blk_mq_end_request`.
    ///
    /// # Mapping
    ///
    /// | DispatchResult | CompletionOutcome |
    /// |---|---|
    /// | `Completed { bytes }` | `ok(bytes)` |
    /// | `CompletedNoData` | `ok(0)` |
    /// | `NotSupported` | `err(IoError, 0)` (ENOSYS semantics) |
    /// | `Rejected { .. }` | `err(IoError, 0)` |
    /// | `IoError { .. }` | `err(IoError, 0)` |
    fn from(result: &DispatchResult) -> Self {
        match result {
            DispatchResult::Completed { bytes_transferred } => Self::ok(*bytes_transferred),
            DispatchResult::Partial {
                bytes_transferred,
                bytes_requested,
            } => Self::partial(*bytes_transferred, *bytes_requested),
            DispatchResult::CompletedNoData => Self::ok(0),
            DispatchResult::NotSupported
            | DispatchResult::Rejected { .. }
            | DispatchResult::IoError { .. } => Self::err(BlkMqStatus::IoError, 0),
        }
    }
}

impl From<DispatchResult> for CompletionOutcome {
    /// Convert an owned `DispatchResult` into a `CompletionOutcome`.
    #[inline]
    fn from(result: DispatchResult) -> Self {
        Self::from(&result)
    }
}

// ── RequestCompletion ────────────────────────────────────────────────────

/// Request completion dispatcher that bridges VfsEngine outcomes to
/// Linux `blk_mq_end_request`.
///
/// In cargo builds, this records completion outcomes for test verification.
/// The Kbuild entrypoint owns the real `blk_mq_end_request` call.
///
/// # Lifecycle
///
/// The dispatcher is created once per block device. Each I/O completion
/// passes through `complete()` which records the outcome and (in kernel
/// mode) signals the block layer.
pub struct RequestCompletion {
    /// Total bytes transferred across all completions.
    total_bytes: u64,
    /// Total completions processed.
    completions: u64,
    /// Total errors encountered.
    errors: u64,
}

impl RequestCompletion {
    /// Create a new request completion dispatcher.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            total_bytes: 0,
            completions: 0,
            errors: 0,
        }
    }

    /// Complete a block I/O request with the given outcome.
    ///
    /// In the cargo model, this records the completion for verification.
    ///
    /// # Returns
    ///
    /// The recorded outcome for caller verification.
    pub fn complete(&mut self, outcome: CompletionOutcome) -> CompletionOutcome {
        self.completions = self.completions.wrapping_add(1);
        if outcome.status.is_ok() {
            self.total_bytes = self
                .total_bytes
                .wrapping_add(u64::from(outcome.bytes_transferred));
        } else {
            self.errors = self.errors.wrapping_add(1);
        }
        outcome
    }

    /// Total bytes transferred across all completions.
    #[must_use]
    pub fn total_bytes_transferred(&self) -> u64 {
        self.total_bytes
    }

    /// Total number of completions processed.
    #[must_use]
    pub fn completion_count(&self) -> u64 {
        self.completions
    }

    /// Total number of errored completions.
    #[must_use]
    pub fn error_count(&self) -> u64 {
        self.errors
    }

    /// Reset counters (useful for per-cycle measurement).
    pub fn reset_counters(&mut self) {
        self.total_bytes = 0;
        self.completions = 0;
        self.errors = 0;
    }
}

impl Default for RequestCompletion {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for RequestCompletion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RequestCompletion")
            .field("total_bytes", &self.total_bytes)
            .field("completions", &self.completions)
            .field("errors", &self.errors)
            .finish()
    }
}

// ── complete_block_request ─────────────────────────────────────────────────

/// Complete a block I/O request by translating a VfsEngine result into a
/// [`CompletionOutcome`], recording it through [`RequestCompletion`], and
/// (in kernel mode) calling `blk_mq_end_request`.
///
/// This is the canonical completion entry-point for the full dispatch-to-
/// completion pipeline: it takes a raw VfsEngine block-operation result,
/// builds a [`CompletionOutcome`] that carries the correct `blk_status_t`
/// and byte-transfer count, feeds it through the [`RequestCompletion`]
/// tracker, and returns the outcome for caller verification.
///
/// # Arguments
///
/// * `rc` — the request-completion tracker (mutable borrow).
/// * `result` — the VfsEngine block operation result (`Ok(bytes)` or
///   `Err(errno)`).
/// * `bytes_requested` — the number of bytes originally requested, used
///   for partial-completion detection.
///
/// # Returns
///
/// The [`CompletionOutcome`] that was recorded.
#[must_use]
pub fn complete_block_request(
    rc: &mut RequestCompletion,
    result: Result<u32, Errno>,
    bytes_requested: u32,
) -> CompletionOutcome {
    let outcome = completion_from_result(result, bytes_requested);
    rc.complete(outcome)
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── CompletionOutcome tests ───────────────────────────────────────

    #[test]
    fn completion_outcome_ok() {
        let c = CompletionOutcome::ok(4096);
        assert!(c.is_ok());
        assert!(!c.is_partial());
        assert_eq!(c.bytes_transferred, 4096);
        assert_eq!(c.bytes_requested, 4096);
        assert_eq!(c.residual(), 0);
    }

    #[test]
    fn completion_outcome_partial() {
        let c = CompletionOutcome::partial(2048, 4096);
        assert!(c.is_ok());
        assert!(c.is_partial());
        assert_eq!(c.bytes_transferred, 2048);
        assert_eq!(c.bytes_requested, 4096);
        assert_eq!(c.residual(), 2048);
    }

    #[test]
    fn completion_outcome_error() {
        let c = CompletionOutcome::err(BlkMqStatus::IoError, 4096);
        assert!(!c.is_ok());
        assert_eq!(c.bytes_transferred, 0);
        assert_eq!(c.bytes_requested, 4096);
        assert_eq!(c.residual(), 4096);
        assert_eq!(c.status, BlkMqStatus::IoError);
    }

    #[test]
    fn completion_outcome_nospace() {
        let c = CompletionOutcome::err(BlkMqStatus::NoSpace, 8192);
        assert_eq!(c.status, BlkMqStatus::NoSpace);
        assert_eq!(c.status.to_kernel_code(), 4);
    }

    #[test]
    fn completion_outcome_medium() {
        let c = CompletionOutcome::err(BlkMqStatus::Medium, 512);
        assert_eq!(c.status, BlkMqStatus::Medium);
        assert_eq!(c.status.to_kernel_code(), 5);
    }

    #[test]
    fn residual_saturates_at_zero() {
        let c = CompletionOutcome::partial(5000, 4096);
        assert_eq!(c.residual(), 0);
    }

    // ── From<QueueRqOutcome> tests ────────────────────────────────────

    #[test]
    fn from_queue_rq_outcome_ok() {
        let qo = QueueRqOutcome::ok(1024);
        let co = CompletionOutcome::from(qo);
        assert!(co.is_ok());
        assert_eq!(co.bytes_transferred, 1024);
        assert_eq!(co.bytes_requested, 1024);
    }

    #[test]
    fn from_queue_rq_outcome_err() {
        let qo = QueueRqOutcome::err(BlkMqStatus::NoSpace);
        let co = CompletionOutcome::from(qo);
        assert!(!co.is_ok());
        assert_eq!(co.status, BlkMqStatus::NoSpace);
        assert_eq!(co.bytes_transferred, 0);
        assert_eq!(co.bytes_requested, 0);
    }

    // ── From<Result<u32, Errno>> tests ────────────────────────────────

    #[test]
    fn from_result_ok() {
        let co = CompletionOutcome::from(Ok(4096u32));
        assert!(co.is_ok());
        assert_eq!(co.bytes_transferred, 4096);
    }

    #[test]
    fn from_result_enospc_maps_to_nospace() {
        let co = CompletionOutcome::from(Err(Errno::ENOSPC));
        assert!(!co.is_ok());
        assert_eq!(co.status, BlkMqStatus::NoSpace);
    }

    #[test]
    fn from_result_eio_maps_to_ioerror() {
        let co = CompletionOutcome::from(Err(Errno::EIO));
        assert_eq!(co.status, BlkMqStatus::IoError);
    }

    #[test]
    fn from_result_enomedium_maps_to_medium() {
        let co = CompletionOutcome::from(Err(Errno::ENXIO));
        assert_eq!(co.status, BlkMqStatus::Medium);
    }

    #[test]
    fn from_result_enosys_maps_to_ioerror() {
        let co = CompletionOutcome::from(Err(Errno::ENOSYS));
        assert_eq!(co.status, BlkMqStatus::IoError);
    }

    #[test]
    fn from_result_einval_maps_to_ioerror() {
        let co = CompletionOutcome::from(Err(Errno::EINVAL));
        assert_eq!(co.status, BlkMqStatus::IoError);
    }

    // ── completion_from_result tests ──────────────────────────────────

    #[test]
    fn completion_from_result_full_success() {
        let co = completion_from_result(Ok(4096), 4096);
        assert!(co.is_ok());
        assert!(!co.is_partial());
        assert_eq!(co.bytes_transferred, 4096);
    }

    #[test]
    fn completion_from_result_partial_read() {
        let co = completion_from_result(Ok(2048), 4096);
        assert!(co.is_ok());
        assert!(co.is_partial());
        assert_eq!(co.bytes_transferred, 2048);
        assert_eq!(co.residual(), 2048);
    }

    #[test]
    fn completion_from_result_more_than_requested() {
        let co = completion_from_result(Ok(8192), 4096);
        assert!(co.is_ok());
        assert!(!co.is_partial());
    }

    #[test]
    fn completion_from_result_error_with_requested() {
        let co = completion_from_result(Err(Errno::EIO), 4096);
        assert!(!co.is_ok());
        assert_eq!(co.bytes_requested, 4096);
        assert_eq!(co.bytes_transferred, 0);
        assert_eq!(co.residual(), 4096);
    }

    // ── RequestCompletion tests ───────────────────────────────────────

    #[test]
    fn request_completion_tracks_counts() {
        let mut rc = RequestCompletion::new();

        rc.complete(CompletionOutcome::ok(4096));
        rc.complete(CompletionOutcome::ok(2048));
        rc.complete(CompletionOutcome::err(BlkMqStatus::IoError, 1024));

        assert_eq!(rc.completion_count(), 3);
        assert_eq!(rc.total_bytes_transferred(), 6144);
        assert_eq!(rc.error_count(), 1);
    }

    #[test]
    fn request_completion_reset() {
        let mut rc = RequestCompletion::new();
        rc.complete(CompletionOutcome::ok(4096));
        rc.complete(CompletionOutcome::ok(4096));
        rc.complete(CompletionOutcome::err(BlkMqStatus::NoSpace, 8192));

        rc.reset_counters();
        assert_eq!(rc.completion_count(), 0);
        assert_eq!(rc.total_bytes_transferred(), 0);
        assert_eq!(rc.error_count(), 0);
    }

    #[test]
    fn request_completion_mixed_statuses() {
        let mut rc = RequestCompletion::new();

        rc.complete(CompletionOutcome::ok(512));
        rc.complete(CompletionOutcome::err(BlkMqStatus::NoSpace, 1024));
        rc.complete(CompletionOutcome::err(BlkMqStatus::Medium, 2048));
        rc.complete(CompletionOutcome::err(BlkMqStatus::IoError, 4096));
        rc.complete(CompletionOutcome::err(BlkMqStatus::Resource, 8192));

        assert_eq!(rc.completion_count(), 5);
        assert_eq!(rc.total_bytes_transferred(), 512);
        assert_eq!(rc.error_count(), 4);
    }

    #[test]
    fn request_completion_debug_output() {
        let mut rc = RequestCompletion::new();
        rc.complete(CompletionOutcome::ok(1024));
        let dbg = alloc::format!("{rc:?}");
        assert!(dbg.contains("RequestCompletion"));
        assert!(dbg.contains("1024"));
        assert!(dbg.contains("completions"));
    }

    #[test]
    fn request_completion_default_is_blank() {
        let rc = RequestCompletion::default();
        assert_eq!(rc.completion_count(), 0);
        assert_eq!(rc.total_bytes_transferred(), 0);
        assert_eq!(rc.error_count(), 0);
    }

    // ── BlkMqStatus completeness ──────────────────────────────────────

    #[test]
    fn blkmq_status_all_variants_have_kernel_codes() {
        for (status, expected) in [
            (BlkMqStatus::Ok, 0),
            (BlkMqStatus::IoError, 1),
            (BlkMqStatus::Resource, 2),
            (BlkMqStatus::NoSpace, 4),
            (BlkMqStatus::Medium, 5),
        ] {
            assert_eq!(status.to_kernel_code(), expected);
        }
    }

    #[test]
    fn errno_to_blkmqstatus_complete_mapping() {
        assert_eq!(BlkMqStatus::from(Errno::ENOSPC), BlkMqStatus::NoSpace);
        assert_eq!(BlkMqStatus::from(Errno::EIO), BlkMqStatus::IoError);
        assert_eq!(BlkMqStatus::from(Errno::ENXIO), BlkMqStatus::Medium);
        assert_eq!(BlkMqStatus::from(Errno::ENOSYS), BlkMqStatus::IoError);
        assert_eq!(BlkMqStatus::from(Errno::EINVAL), BlkMqStatus::IoError);
        assert_eq!(BlkMqStatus::from(Errno::EPERM), BlkMqStatus::IoError);
    }

    // ── Partial completion workflow test ──────────────────────────────

    #[test]
    fn partial_completion_residual_tracking() {
        let co = completion_from_result(Ok(1024), 1536);
        assert!(co.is_ok());
        assert!(co.is_partial());
        assert_eq!(co.bytes_transferred, 1024);
        assert_eq!(co.residual(), 512);

        let mut rc = RequestCompletion::new();
        rc.complete(co);

        assert_eq!(rc.total_bytes_transferred(), 1024);
        assert_eq!(rc.error_count(), 0);
    }

    #[test]
    fn completion_outcome_debug_and_clone() {
        let c = CompletionOutcome::ok(512);
        let c2 = c;
        assert_eq!(c, c2);
        let dbg = alloc::format!("{c:?}");
        assert!(dbg.contains("CompletionOutcome"));
        assert!(dbg.contains("512"));
    }

    // ── From<DispatchResult> tests ─────────────────────────────────────

    #[test]
    fn from_dispatch_result_completed_ok() {
        use crate::dispatch::DispatchResult;
        let dr = DispatchResult::Completed {
            bytes_transferred: 4096,
        };
        let co = CompletionOutcome::from(dr);
        assert!(co.is_ok());
        assert_eq!(co.bytes_transferred, 4096);
        assert_eq!(co.bytes_requested, 4096);
    }

    #[test]
    fn from_dispatch_result_completed_no_data() {
        use crate::dispatch::DispatchResult;
        let dr = DispatchResult::CompletedNoData;
        let co = CompletionOutcome::from(dr);
        assert!(co.is_ok());
        assert_eq!(co.bytes_transferred, 0);
    }

    #[test]
    fn from_dispatch_result_not_supported() {
        use crate::dispatch::DispatchResult;
        let dr = DispatchResult::NotSupported;
        let co = CompletionOutcome::from(dr);
        assert!(!co.is_ok());
        assert_eq!(co.status, BlkMqStatus::IoError);
        assert_eq!(co.bytes_transferred, 0);
    }

    #[test]
    fn from_dispatch_result_rejected() {
        use crate::dispatch::DispatchResult;
        let dr = DispatchResult::Rejected { reason: "fenced" };
        let co = CompletionOutcome::from(dr);
        assert!(!co.is_ok());
        assert_eq!(co.status, BlkMqStatus::IoError);
        assert_eq!(co.bytes_transferred, 0);
    }

    #[test]
    fn from_dispatch_result_ioerror() {
        use crate::dispatch::DispatchResult;
        let dr = DispatchResult::IoError {
            detail: "backend failure",
        };
        let co = CompletionOutcome::from(dr);
        assert!(!co.is_ok());
        assert_eq!(co.status, BlkMqStatus::IoError);
        assert_eq!(co.bytes_transferred, 0);
    }

    #[test]
    fn from_dispatch_result_ref() {
        use crate::dispatch::DispatchResult;
        let dr = DispatchResult::Completed {
            bytes_transferred: 1024,
        };
        let co = CompletionOutcome::from(&dr);
        assert!(co.is_ok());
        assert_eq!(co.bytes_transferred, 1024);
        // dr is still usable because we took &ref
        assert_eq!(dr.bytes_transferred(), 1024);
    }

    // ── Dispatch-to-completion pipeline test ───────────────────────────

    #[test]
    fn pipeline_dispatch_result_through_completion() {
        use crate::dispatch::DispatchResult;
        let mut rc = RequestCompletion::new();

        // Simulate three dispatches: read, write, error
        let outcomes = [
            DispatchResult::Completed {
                bytes_transferred: 4096,
            },
            DispatchResult::Completed {
                bytes_transferred: 2048,
            },
            DispatchResult::IoError {
                detail: "disk failure",
            },
        ];

        for dr in &outcomes {
            let co = CompletionOutcome::from(dr);
            rc.complete(co);
        }

        assert_eq!(rc.completion_count(), 3);
        assert_eq!(rc.total_bytes_transferred(), 6144);
        assert_eq!(rc.error_count(), 1);
    }

    #[test]
    fn pipeline_partial_success_tracking() {
        use crate::dispatch::DispatchResult;
        let mut rc = RequestCompletion::new();

        // Partial read: only 2048 of 4096 transferred
        let dr = DispatchResult::Completed {
            bytes_transferred: 2048,
        };
        let co = CompletionOutcome::from(dr);
        assert!(co.is_ok());
        // Note: DispatchResult doesn't carry bytes_requested,
        // so is_partial() won't detect partials from this path alone.
        // Use completion_from_result for partial-detection.
        rc.complete(co);

        assert_eq!(rc.completion_count(), 1);
        assert_eq!(rc.error_count(), 0);
    }

    // ── complete_block_request tests ───────────────────────────────────

    #[test]
    fn complete_block_request_success_tracks_bytes() {
        let mut rc = RequestCompletion::new();
        let outcome = complete_block_request(&mut rc, Ok(4096), 4096);
        assert!(outcome.is_ok());
        assert_eq!(outcome.bytes_transferred, 4096);
        assert_eq!(rc.completion_count(), 1);
        assert_eq!(rc.total_bytes_transferred(), 4096);
        assert_eq!(rc.error_count(), 0);
    }

    #[test]
    fn complete_block_request_partial_write() {
        let mut rc = RequestCompletion::new();
        // VfsEngine wrote fewer bytes than requested
        let outcome = complete_block_request(&mut rc, Ok(2048), 4096);
        assert!(outcome.is_ok());
        assert!(outcome.is_partial());
        assert_eq!(outcome.bytes_transferred, 2048);
        assert_eq!(outcome.bytes_requested, 4096);
        assert_eq!(outcome.residual(), 2048);
        assert_eq!(rc.completion_count(), 1);
        assert_eq!(rc.error_count(), 0);
    }

    #[test]
    fn complete_block_request_io_error() {
        let mut rc = RequestCompletion::new();
        let outcome = complete_block_request(&mut rc, Err(Errno::EIO), 4096);
        assert!(!outcome.is_ok());
        assert_eq!(outcome.status, BlkMqStatus::IoError);
        assert_eq!(outcome.bytes_transferred, 0);
        assert_eq!(rc.completion_count(), 1);
        assert_eq!(rc.error_count(), 1);
        assert_eq!(rc.total_bytes_transferred(), 0);
    }

    #[test]
    fn complete_block_request_nospace() {
        let mut rc = RequestCompletion::new();
        let outcome = complete_block_request(&mut rc, Err(Errno::ENOSPC), 8192);
        assert!(!outcome.is_ok());
        assert_eq!(outcome.status, BlkMqStatus::NoSpace);
        assert_eq!(outcome.status.to_kernel_code(), 4);
        assert_eq!(rc.error_count(), 1);
    }

    #[test]
    fn complete_block_request_medium_error() {
        let mut rc = RequestCompletion::new();
        let outcome = complete_block_request(&mut rc, Err(Errno::ENXIO), 512);
        assert!(!outcome.is_ok());
        assert_eq!(outcome.status, BlkMqStatus::Medium);
        assert_eq!(outcome.status.to_kernel_code(), 5);
    }

    #[test]
    fn complete_block_request_enosys_is_ioerror() {
        let mut rc = RequestCompletion::new();
        // ENOSYS (unsupported operation) maps to IoError (not a separate NotSupp)
        let outcome = complete_block_request(&mut rc, Err(Errno::ENOSYS), 1024);
        assert!(!outcome.is_ok());
        assert_eq!(outcome.status, BlkMqStatus::IoError);
    }

    // ── Full pipeline: QueueRqOutcome → Completion → RequestCompletion ──

    #[test]
    fn pipeline_queue_rq_outcome_through_request_completion() {
        let mut rc = RequestCompletion::new();

        // Simulate three queue_rq dispatches: read, write, error
        let outcomes = [
            QueueRqOutcome::ok(4096),
            QueueRqOutcome::ok(2048),
            QueueRqOutcome::err(BlkMqStatus::NoSpace),
        ];

        for qo in &outcomes {
            let co = CompletionOutcome::from(qo.clone());
            rc.complete(co);
        }

        assert_eq!(rc.completion_count(), 3);
        assert_eq!(rc.total_bytes_transferred(), 6144);
        assert_eq!(rc.error_count(), 1);
    }

    #[test]
    fn pipeline_result_errno_through_completion() {
        let mut rc = RequestCompletion::new();

        // Mix of success and error VfsEngine results
        let results: &[Result<u32, Errno>] = &[
            Ok(512),
            Ok(1024),
            Err(Errno::EIO),
            Ok(2048),
            Err(Errno::ENOSPC),
        ];

        for (i, r) in results.iter().enumerate() {
            let co = CompletionOutcome::from(*r);
            assert_eq!(co.is_ok(), r.is_ok(), "mismatch at index {i}");
            rc.complete(co);
        }

        assert_eq!(rc.completion_count(), 5);
        assert_eq!(rc.total_bytes_transferred(), 3584); // 512 + 1024 + 2048
        assert_eq!(rc.error_count(), 2); // EIO + ENOSPC
    }

    #[test]
    fn pipeline_mixed_payloads_all_status_types() {
        let mut rc = RequestCompletion::new();

        // Exercise all BlkMqStatus variants through CompletionOutcome
        let outcomes = [
            CompletionOutcome::ok(4096),
            CompletionOutcome::partial(1024, 4096),
            CompletionOutcome::err(BlkMqStatus::IoError, 512),
            CompletionOutcome::err(BlkMqStatus::Resource, 0),
            CompletionOutcome::err(BlkMqStatus::NoSpace, 8192),
            CompletionOutcome::err(BlkMqStatus::Medium, 256),
        ];

        for co in &outcomes {
            rc.complete(*co);
        }

        assert_eq!(rc.completion_count(), 6);
        assert_eq!(rc.total_bytes_transferred(), 5120); // 4096 + 1024
        assert_eq!(rc.error_count(), 4); // IoError + Resource + NoSpace + Medium
    }

    #[test]
    fn complete_block_request_reset_between_cycles() {
        let mut rc = RequestCompletion::new();

        // Cycle 1
        let _ = complete_block_request(&mut rc, Ok(1024), 1024);
        let _ = complete_block_request(&mut rc, Err(Errno::EIO), 512);
        assert_eq!(rc.completion_count(), 2);
        assert_eq!(rc.error_count(), 1);

        // Reset
        rc.reset_counters();
        assert_eq!(rc.completion_count(), 0);
        assert_eq!(rc.error_count(), 0);

        // Cycle 2
        let _ = complete_block_request(&mut rc, Ok(2048), 2048);
        let _ = complete_block_request(&mut rc, Ok(512), 512);
        assert_eq!(rc.completion_count(), 2);
        assert_eq!(rc.total_bytes_transferred(), 2560);
        assert_eq!(rc.error_count(), 0);
    }
}
