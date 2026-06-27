// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Write-path latency histograms and structured error attribution for
//! the posix-filesystem-adapter-daemon tracing layer.
//!
//! # LatencyHistogram
//!
//! Lock-free exponential-bucket latency recorder backed by [`AtomicU64`]
//! counters. Buckets span from 10 us through 10 s with an overflow
//! bucket for operations exceeding 10 s.
//!
//! # FuseErrorCode
//!
//! Structured error-code enum that maps every errno the daemon returns
//! on the write path into typed `tracing` fields (`error.kind`,
//! `error.operation`, `error.inode`), replacing ad-hoc `tracing::error!`
//! calls with machine-readable diagnostics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;
use std::time::Duration;

// ---------------------------------------------------------------------------
// LatencyHistogram
// ---------------------------------------------------------------------------

/// Bucket boundaries in nanoseconds, building exponential decades:
/// 10 us, 100 us, 1 ms, 10 ms, 100 ms, 1 s, 10 s.
const BUCKET_BOUNDS_NS: [u64; 7] = [
    10_000,         // 10 us
    100_000,        // 100 us
    1_000_000,      // 1 ms
    10_000_000,     // 10 ms
    100_000_000,    // 100 ms
    1_000_000_000,  // 1 s
    10_000_000_000, // 10 s
];

/// Lock-free latency histogram with exponential-decade buckets.
///
/// Each bucket is an independent [`AtomicU64`]; recording requires
/// no locking and is safe for concurrent use from multiple tokio tasks.
///
/// # Bucket layout
///
/// | Index | Range            |
/// |-------|------------------|
/// | 0     | <= 10 us         |
/// | 1     | <= 100 us        |
/// | 2     | <= 1 ms          |
/// | 3     | <= 10 ms         |
/// | 4     | <= 100 ms        |
/// | 5     | <= 1 s           |
/// | 6     | <= 10 s          |
/// | 7     | > 10 s (overflow)|
pub struct LatencyHistogram {
    buckets: [AtomicU64; 8],
    count: AtomicU64,
    sum_ns: AtomicU64,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}

impl LatencyHistogram {
    /// Create a new, zero-initialized histogram.
    pub const fn new() -> Self {
        Self {
            buckets: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            count: AtomicU64::new(0),
            sum_ns: AtomicU64::new(0),
        }
    }

    /// Record a latency observation.
    ///
    /// Atomically increments the appropriate bucket counter, total
    /// observation count, and cumulative nanosecond sum.
    pub fn record(&self, elapsed: Duration) {
        let ns = elapsed.as_nanos() as u64;
        self.sum_ns.fetch_add(ns, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        let idx = BUCKET_BOUNDS_NS
            .iter()
            .position(|&bound| ns <= bound)
            .unwrap_or(7); // overflow bucket

        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// Produce an atomic snapshot of the histogram counters.
    pub fn snapshot(&self) -> HistogramSnapshot {
        let count = self.count.load(Ordering::Relaxed);
        let sum_ns = self.sum_ns.load(Ordering::Relaxed);
        let mut buckets = [0u64; 8];
        for (i, b) in buckets.iter_mut().enumerate() {
            *b = self.buckets[i].load(Ordering::Relaxed);
        }
        HistogramSnapshot {
            count,
            sum_ns,
            buckets,
        }
    }

    /// Emit a `tracing::info!` summary line for this histogram.
    ///
    /// `name` is the operation name used as the log prefix (e.g.
    /// `"fuse_write"`, `"fuse_fsync"`).
    pub fn emit_summary(&self, name: &str) {
        let snap = self.snapshot();
        if snap.count == 0 {
            tracing::info!(
                target: "tidefs.latency",
                op = name,
                count = 0,
                "latency histogram empty (no observations)"
            );
            return;
        }

        let avg_us = if snap.count > 0 {
            snap.sum_ns / snap.count / 1_000
        } else {
            0
        };

        tracing::info!(
            target: "tidefs.latency",
            op = name,
            count = snap.count,
            avg_us = avg_us,
            p10us = snap.buckets[0],
            p100us = snap.buckets[1],
            p1ms = snap.buckets[2],
            p10ms = snap.buckets[3],
            p100ms = snap.buckets[4],
            p1s = snap.buckets[5],
            p10s = snap.buckets[6],
            overflow = snap.buckets[7],
            "latency histogram summary",
        );
    }
}

// ---------------------------------------------------------------------------
// Global histogram singletons for the five write-path operations
// ---------------------------------------------------------------------------

/// Write (FUSE opcode 16) latency histogram.
pub static HIST_WRITE: LazyLock<LatencyHistogram> = LazyLock::new(LatencyHistogram::new);

/// Fsync (FUSE opcode 26, datasync=false) latency histogram.
pub static HIST_FSYNC: LazyLock<LatencyHistogram> = LazyLock::new(LatencyHistogram::new);

/// Fdatasync (FUSE opcode 26, datasync=true) latency histogram.
pub static HIST_FDATASYNC: LazyLock<LatencyHistogram> = LazyLock::new(LatencyHistogram::new);

/// Fsync/fdatasync storage-sync phase latency histogram.
/// Records time spent inside engine.fsync() (store.sync_all() and related
/// I/O), separate from page-cache writeback and FUSE protocol overhead.
pub static HIST_FSYNC_STORAGE: LazyLock<LatencyHistogram> = LazyLock::new(LatencyHistogram::new);

/// Flush (FUSE opcode 25) latency histogram.
pub static HIST_FLUSH: LazyLock<LatencyHistogram> = LazyLock::new(LatencyHistogram::new);

/// Syncfs (FUSE opcode 50) latency histogram.
pub static HIST_SYNCFS: LazyLock<LatencyHistogram> = LazyLock::new(LatencyHistogram::new);

/// Create (FUSE opcode 18) latency histogram.
pub static HIST_CREATE: LazyLock<LatencyHistogram> = LazyLock::new(LatencyHistogram::new);
/// Read (FUSE opcode 15) latency histogram.
pub static HIST_READ: LazyLock<LatencyHistogram> = LazyLock::new(LatencyHistogram::new);

/// Metadata operations (lookup, getattr, setattr, readdir, opendir, statfs)
/// aggregate latency histogram.
pub static HIST_METADATA: LazyLock<LatencyHistogram> = LazyLock::new(LatencyHistogram::new);
/// Scheduler cycle (background work dispatch) latency histogram.
pub static HIST_BG_SCHEDULER: LazyLock<LatencyHistogram> = LazyLock::new(LatencyHistogram::new);

/// Reason class recorded by the FUSE governor-admission boundary.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FuseAdmissionReason {
    /// The request was admitted at the FUSE boundary.
    Accepted,
    /// Soft pressure deferred a non-critical request.
    SoftDeferred,
    /// Hard pressure refused a mutating request.
    HardRefusedMutating,
    /// Hard pressure refused a request under the all-request policy.
    HardRefusedAll,
}

static FUSE_ADMISSION_ACCEPTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static FUSE_ADMISSION_SOFT_DEFERRED_TOTAL: AtomicU64 = AtomicU64::new(0);
static FUSE_ADMISSION_HARD_REFUSED_MUTATING_TOTAL: AtomicU64 = AtomicU64::new(0);
static FUSE_ADMISSION_HARD_REFUSED_ALL_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Point-in-time snapshot of FUSE governor admission reason counters.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct FuseAdmissionReasonSnapshot {
    pub accepted: u64,
    pub soft_deferred: u64,
    pub hard_refused_mutating: u64,
    pub hard_refused_all: u64,
}

/// Record one FUSE governor-admission decision reason.
pub fn record_fuse_admission_reason(reason: FuseAdmissionReason) {
    match reason {
        FuseAdmissionReason::Accepted => {
            FUSE_ADMISSION_ACCEPTED_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        FuseAdmissionReason::SoftDeferred => {
            FUSE_ADMISSION_SOFT_DEFERRED_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        FuseAdmissionReason::HardRefusedMutating => {
            FUSE_ADMISSION_HARD_REFUSED_MUTATING_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        FuseAdmissionReason::HardRefusedAll => {
            FUSE_ADMISSION_HARD_REFUSED_ALL_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Return the current FUSE governor-admission reason counters.
#[must_use]
pub fn fuse_admission_reason_snapshot() -> FuseAdmissionReasonSnapshot {
    FuseAdmissionReasonSnapshot {
        accepted: FUSE_ADMISSION_ACCEPTED_TOTAL.load(Ordering::Relaxed),
        soft_deferred: FUSE_ADMISSION_SOFT_DEFERRED_TOTAL.load(Ordering::Relaxed),
        hard_refused_mutating: FUSE_ADMISSION_HARD_REFUSED_MUTATING_TOTAL.load(Ordering::Relaxed),
        hard_refused_all: FUSE_ADMISSION_HARD_REFUSED_ALL_TOTAL.load(Ordering::Relaxed),
    }
}

/// Reason class recorded when the FUSE prune-notify boundary cannot emit.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FusePruneNotificationUnavailableReason {
    /// The active fuser boundary has no `FUSE_NOTIFY_PRUNE`/equivalent sender.
    FuserNotifyPruneUnsupported,
    /// The boundary exists, but the kernel/user send failed for this candidate.
    NotifySendFailed,
}

static FUSE_PRUNE_NOTIFICATION_SENT_TOTAL: AtomicU64 = AtomicU64::new(0);
static FUSE_PRUNE_NOTIFICATION_ACKNOWLEDGED_TOTAL: AtomicU64 = AtomicU64::new(0);
static FUSE_PRUNE_NOTIFICATION_UNAVAILABLE_TOTAL: AtomicU64 = AtomicU64::new(0);
static FUSE_PRUNE_NOTIFICATION_UNSUPPORTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static FUSE_PRUNE_NOTIFICATION_SEND_FAILED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Point-in-time snapshot of governor-driven FUSE prune notification counters.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct FusePruneNotificationSnapshot {
    pub sent: u64,
    pub acknowledged: u64,
    pub unavailable: u64,
    pub unavailable_unsupported: u64,
    pub unavailable_send_failed: u64,
}

/// Record one prune notification handed to the active FUSE boundary.
pub fn record_fuse_prune_notification_sent() {
    FUSE_PRUNE_NOTIFICATION_SENT_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record one prune notification accepted by the active FUSE boundary.
pub fn record_fuse_prune_notification_acknowledged() {
    FUSE_PRUNE_NOTIFICATION_ACKNOWLEDGED_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record one unavailable prune notification boundary or send result.
pub fn record_fuse_prune_notification_unavailable(
    reason: FusePruneNotificationUnavailableReason,
) {
    FUSE_PRUNE_NOTIFICATION_UNAVAILABLE_TOTAL.fetch_add(1, Ordering::Relaxed);
    match reason {
        FusePruneNotificationUnavailableReason::FuserNotifyPruneUnsupported => {
            FUSE_PRUNE_NOTIFICATION_UNSUPPORTED_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        FusePruneNotificationUnavailableReason::NotifySendFailed => {
            FUSE_PRUNE_NOTIFICATION_SEND_FAILED_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Return the current governor-driven FUSE prune notification counters.
#[must_use]
pub fn fuse_prune_notification_snapshot() -> FusePruneNotificationSnapshot {
    FusePruneNotificationSnapshot {
        sent: FUSE_PRUNE_NOTIFICATION_SENT_TOTAL.load(Ordering::Relaxed),
        acknowledged: FUSE_PRUNE_NOTIFICATION_ACKNOWLEDGED_TOTAL.load(Ordering::Relaxed),
        unavailable: FUSE_PRUNE_NOTIFICATION_UNAVAILABLE_TOTAL.load(Ordering::Relaxed),
        unavailable_unsupported: FUSE_PRUNE_NOTIFICATION_UNSUPPORTED_TOTAL.load(Ordering::Relaxed),
        unavailable_send_failed: FUSE_PRUNE_NOTIFICATION_SEND_FAILED_TOTAL.load(Ordering::Relaxed),
    }
}

// ---------------------------------------------------------------------------
// Shutdown summary emission
// ---------------------------------------------------------------------------

/// Emit histogram summaries for all five write-path operations.
///
/// Call this during daemon shutdown (unmount / SIGTERM) to produce a
/// latency profile log line for every instrumented operation.
#[allow(dead_code)]
pub fn emit_all_summaries() {
    HIST_WRITE.emit_summary("fuse_write");
    HIST_FSYNC.emit_summary("fuse_fsync");
    HIST_FDATASYNC.emit_summary("fuse_fdatasync");
    HIST_FSYNC_STORAGE.emit_summary("fuse_fsync_storage");
    HIST_FLUSH.emit_summary("fuse_flush");
    HIST_SYNCFS.emit_summary("fuse_syncfs");
    HIST_CREATE.emit_summary("fuse_create");
    HIST_READ.emit_summary("fuse_read");
    HIST_METADATA.emit_summary("fuse_metadata");
    HIST_BG_SCHEDULER.emit_summary("bg_scheduler_cycle");
    crate::observability::emit_commit_group_summary();
}

/// A point-in-time snapshot of a [`LatencyHistogram`].
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct HistogramSnapshot {
    pub count: u64,
    pub sum_ns: u64,
    pub buckets: [u64; 8],
}

impl HistogramSnapshot {
    /// Average latency in microseconds, or 0 when count is 0.
    #[must_use]
    #[allow(dead_code)]
    pub fn avg_us(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            self.sum_ns / self.count / 1_000
        }
    }
}

// ---------------------------------------------------------------------------
// BackgroundSchedulerSnapshot — scheduler observability
// ---------------------------------------------------------------------------

/// A point-in-time snapshot of background scheduler statistics.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
#[derive(Default)]
pub struct BgSchedulerSnapshot {
    /// Number of registered background services.
    pub service_count: usize,
    /// Number of cycles executed since daemon start.
    pub cycles_executed: u64,
    /// Number of cycles that completed without budget exhaustion.
    pub cycles_completed: u64,
    /// Number of cycles preempted by demand signal.
    pub cycles_preempted: u64,
    /// Number of ticks that found no work (idle).
    pub idle_ticks: u64,
    /// Total items processed by background services.
    pub total_processed: u64,
    /// Total errors encountered by background services.
    pub total_errors: u64,
    /// Wall-clock milliseconds spent in background cycles.
    pub cumulative_wall_ms: u64,
}

// ---------------------------------------------------------------------------
// FuseErrorCode -- structured FUSE error attribution
// ---------------------------------------------------------------------------

/// Structured error code for FUSE write-path operations.
///
/// Each variant carries the logical operation name and the affected inode
/// (when available), producing machine-readable `tracing` fields instead
/// of ad-hoc free-text error messages.
#[derive(Debug, Clone, Copy)]
pub enum FuseErrorCode {
    /// EBADF -- bad file descriptor (unknown handle, closed handle,
    /// or handle not opened for the attempted operation).
    BadFileDescriptor { operation: &'static str, inode: u64 },
    /// EIO -- input/output error (engine write failure, cache corruption,
    /// extent-map I/O failure).
    Io { operation: &'static str, inode: u64 },
    /// ENOSPC -- no space left on device (extent map full, block allocator
    /// exhausted, capacity reservation denied).
    NoSpace { operation: &'static str, inode: u64 },
    /// EINVAL -- invalid argument (negative offset, zero-length write
    /// with invalid flags, unsupported write_flags).
    InvalidArgument { operation: &'static str, inode: u64 },
    /// ENOENT -- no such file or directory (parent inode not found,
    /// name resolution failure).
    NoEntry { operation: &'static str, inode: u64 },
    /// ENOTDIR -- not a directory (parent exists but is not a directory).
    NotDirectory { operation: &'static str, inode: u64 },
    /// EACCES -- permission denied.
    PermissionDenied { operation: &'static str, inode: u64 },
    /// EROFS -- read-only filesystem.
    ReadOnlyFilesystem { operation: &'static str, inode: u64 },
    /// EINTR -- operation interrupted.
    Interrupted { operation: &'static str, inode: u64 },
    /// EFBIG -- file too big.
    FileTooBig { operation: &'static str, inode: u64 },
    /// EEXIST -- file already exists.
    AlreadyExists { operation: &'static str, inode: u64 },
    /// ENOSYS -- function not implemented (engine does not support
    /// the requested operation).
    NotSupported { operation: &'static str, inode: u64 },
    /// ENODATA -- no data available (xattr not found).
    NoData { operation: &'static str, inode: u64 },
    /// EXDEV -- cross-device link.
    CrossDevice { operation: &'static str, inode: u64 },
    /// ENAMETOOLONG -- name too long.
    NameTooLong { operation: &'static str, inode: u64 },
    /// ENOTEMPTY -- directory not empty.
    NotEmpty { operation: &'static str, inode: u64 },
}

impl FuseErrorCode {
    /// Map an `Errno` value and operation context to a structured
    /// [`FuseErrorCode`].
    ///
    /// Unknown errno values fall back to `Io`.
    #[must_use]
    pub fn from_errno(
        errno: tidefs_types_vfs_core::Errno,
        operation: &'static str,
        inode: u64,
    ) -> Self {
        // Match on the raw libc errno value.
        match errno.0 {
            val if val == libc::EBADF as u16 => Self::BadFileDescriptor { operation, inode },
            val if val == libc::EIO as u16 => Self::Io { operation, inode },
            val if val == libc::ENOSPC as u16 => Self::NoSpace { operation, inode },
            val if val == libc::EINVAL as u16 => Self::InvalidArgument { operation, inode },
            val if val == libc::ENOENT as u16 => Self::NoEntry { operation, inode },
            val if val == libc::ENOTDIR as u16 => Self::NotDirectory { operation, inode },
            val if val == libc::EACCES as u16 => Self::PermissionDenied { operation, inode },
            val if val == libc::EROFS as u16 => Self::ReadOnlyFilesystem { operation, inode },
            val if val == libc::EINTR as u16 => Self::Interrupted { operation, inode },
            val if val == libc::EFBIG as u16 => Self::FileTooBig { operation, inode },
            val if val == libc::EEXIST as u16 => Self::AlreadyExists { operation, inode },
            val if val == libc::ENOSYS as u16 => Self::NotSupported { operation, inode },
            val if val == libc::ENODATA as u16 => Self::NoData { operation, inode },
            val if val == libc::EXDEV as u16 => Self::CrossDevice { operation, inode },
            val if val == libc::ENAMETOOLONG as u16 => Self::NameTooLong { operation, inode },
            val if val == libc::ENOTEMPTY as u16 => Self::NotEmpty { operation, inode },
            _ => Self::Io { operation, inode },
        }
    }

    /// Emit this error as a structured `tracing::error!` event.
    ///
    /// Produces fields `error.kind`, `error.operation`, and
    /// `error.inode` for automated diagnostics.
    pub fn emit(&self) {
        let (kind, operation, inode) = match *self {
            Self::BadFileDescriptor { operation, inode } => ("EBADF", operation, inode),
            Self::Io { operation, inode } => ("EIO", operation, inode),
            Self::NoSpace { operation, inode } => ("ENOSPC", operation, inode),
            Self::InvalidArgument { operation, inode } => ("EINVAL", operation, inode),
            Self::NoEntry { operation, inode } => ("ENOENT", operation, inode),
            Self::NotDirectory { operation, inode } => ("ENOTDIR", operation, inode),
            Self::PermissionDenied { operation, inode } => ("EACCES", operation, inode),
            Self::ReadOnlyFilesystem { operation, inode } => ("EROFS", operation, inode),
            Self::Interrupted { operation, inode } => ("EINTR", operation, inode),
            Self::FileTooBig { operation, inode } => ("EFBIG", operation, inode),
            Self::AlreadyExists { operation, inode } => ("EEXIST", operation, inode),
            Self::NotSupported { operation, inode } => ("ENOSYS", operation, inode),
            Self::NoData { operation, inode } => ("ENODATA", operation, inode),
            Self::CrossDevice { operation, inode } => ("EXDEV", operation, inode),
            Self::NameTooLong { operation, inode } => ("ENAMETOOLONG", operation, inode),
            Self::NotEmpty { operation, inode } => ("ENOTEMPTY", operation, inode),
        };

        tracing::error!(
            target: "tidefs.error",
            error_kind = kind,
            error_operation = operation,
            error_inode = inode,
            "FUSE write-path error: {} on {} (inode {})",
            kind, operation, inode
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── LatencyHistogram tests ─────────────────────────────────────────

    #[test]
    fn histogram_bucket_boundaries() {
        let h = LatencyHistogram::new();

        // 5 us -> bucket 0 (<=10us)
        h.record(Duration::from_nanos(5_000));
        // 50 us -> bucket 1 (<=100us)
        h.record(Duration::from_nanos(50_000));
        // 500 us -> bucket 2 (<=1ms)
        h.record(Duration::from_nanos(500_000));
        // 5 ms -> bucket 3 (<=10ms)
        h.record(Duration::from_micros(5_000));
        // 50 ms -> bucket 4 (<=100ms)
        h.record(Duration::from_millis(50));
        // 500 ms -> bucket 5 (<=1s)
        h.record(Duration::from_millis(500));
        // 5 s -> bucket 6 (<=10s)
        h.record(Duration::from_secs(5));
        // 15 s -> bucket 7 (>10s overflow)
        h.record(Duration::from_secs(15));

        let snap = h.snapshot();
        assert_eq!(snap.count, 8);
        assert_eq!(snap.buckets[0], 1, "bucket 0 (<=10us)");
        assert_eq!(snap.buckets[1], 1, "bucket 1 (<=100us)");
        assert_eq!(snap.buckets[2], 1, "bucket 2 (<=1ms)");
        assert_eq!(snap.buckets[3], 1, "bucket 3 (<=10ms)");
        assert_eq!(snap.buckets[4], 1, "bucket 4 (<=100ms)");
        assert_eq!(snap.buckets[5], 1, "bucket 5 (<=1s)");
        assert_eq!(snap.buckets[6], 1, "bucket 6 (<=10s)");
        assert_eq!(snap.buckets[7], 1, "bucket 7 (>10s overflow)");
    }

    #[test]
    fn empty_histogram_snapshot_and_summary_do_not_panic() {
        let h = LatencyHistogram::new();
        let snap = h.snapshot();
        assert_eq!(snap.count, 0);
        assert_eq!(snap.avg_us(), 0);
        for b in &snap.buckets {
            assert_eq!(*b, 0);
        }
        // emit_summary must not panic on empty histogram.
        h.emit_summary("test_empty");
    }

    #[test]
    fn error_code_mapping_covers_all_current_errno_return_sites() {
        // Verify that every errno value the daemon returns on the write
        // path maps to a distinct, non-panic FuseErrorCode.
        let test_errnos: &[(u16, &str)] = &[
            (libc::EBADF as u16, "EBADF"),
            (libc::EIO as u16, "EIO"),
            (libc::ENOSPC as u16, "ENOSPC"),
            (libc::EINVAL as u16, "EINVAL"),
            (libc::ENOENT as u16, "ENOENT"),
            (libc::ENOTDIR as u16, "ENOTDIR"),
            (libc::EACCES as u16, "EACCES"),
            (libc::EROFS as u16, "EROFS"),
            (libc::EINTR as u16, "EINTR"),
            (libc::EFBIG as u16, "EFBIG"),
            (libc::EEXIST as u16, "EEXIST"),
            (libc::ENOSYS as u16, "ENOSYS"),
            (libc::ENODATA as u16, "ENODATA"),
            (libc::EXDEV as u16, "EXDEV"),
            (libc::ENAMETOOLONG as u16, "ENAMETOOLONG"),
            (libc::ENOTEMPTY as u16, "ENOTEMPTY"),
        ];

        for &(raw, label) in test_errnos {
            let code = FuseErrorCode::from_errno(tidefs_types_vfs_core::Errno(raw), "test_op", 42);
            // Every code must emit without panic.
            code.emit();

            // Verify the variant matches the expected errno kind.
            let emitted_kind = match code {
                FuseErrorCode::BadFileDescriptor { .. } => "EBADF",
                FuseErrorCode::Io { .. } => "EIO",
                FuseErrorCode::NoSpace { .. } => "ENOSPC",
                FuseErrorCode::InvalidArgument { .. } => "EINVAL",
                FuseErrorCode::NoEntry { .. } => "ENOENT",
                FuseErrorCode::NotDirectory { .. } => "ENOTDIR",
                FuseErrorCode::PermissionDenied { .. } => "EACCES",
                FuseErrorCode::ReadOnlyFilesystem { .. } => "EROFS",
                FuseErrorCode::Interrupted { .. } => "EINTR",
                FuseErrorCode::FileTooBig { .. } => "EFBIG",
                FuseErrorCode::AlreadyExists { .. } => "EEXIST",
                FuseErrorCode::NotSupported { .. } => "ENOSYS",
                FuseErrorCode::NoData { .. } => "ENODATA",
                FuseErrorCode::CrossDevice { .. } => "EXDEV",
                FuseErrorCode::NameTooLong { .. } => "ENAMETOOLONG",
                FuseErrorCode::NotEmpty { .. } => "ENOTEMPTY",
            };
            assert_eq!(
                emitted_kind, label,
                "errno {raw} mapped to wrong FuseErrorCode variant"
            );
        }
    }

    #[test]
    fn concurrent_histogram_recording_is_panic_free() {
        use std::sync::Arc;
        use std::thread;

        let h = Arc::new(LatencyHistogram::new());
        let mut handles = Vec::new();

        for t in 0..8 {
            let h = Arc::clone(&h);
            handles.push(thread::spawn(move || {
                for i in 0..10_000 {
                    // Vary the duration per thread to exercise different buckets.
                    let ns = (t * 1000 + i % 1000) as u64 * 1_000;
                    h.record(Duration::from_nanos(ns));
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        let snap = h.snapshot();
        assert_eq!(snap.count, 80_000, "all 8 threads x 10k records counted");

        // Sum of bucket counts must equal total count.
        let bucket_sum: u64 = snap.buckets.iter().sum();
        assert_eq!(bucket_sum, snap.count, "bucket sum matches total count");
    }

    // ── HistogramSnapshot tests ──────────────────────────────────────

    #[test]
    fn snapshot_avg_us_computes_correctly() {
        let h = LatencyHistogram::new();
        // Record two observations: 100 us and 200 us = avg 150 us.
        h.record(Duration::from_micros(100));
        h.record(Duration::from_micros(200));

        let snap = h.snapshot();
        assert_eq!(snap.count, 2);
        // 300_000 ns / 2 / 1000 = 150 us
        assert_eq!(snap.avg_us(), 150);
    }
}

// ---------------------------------------------------------------------------
// LatencyTimer -- drop-guard for recording handler latency
// ---------------------------------------------------------------------------

/// RAII guard that records elapsed time into a [`LatencyHistogram`]
/// on drop.  Use at the top of a dispatch handler to automatically
/// capture end-to-end latency regardless of early returns.
pub struct LatencyTimer<'a> {
    start: std::time::Instant,
    histogram: &'a LatencyHistogram,
}

impl<'a> LatencyTimer<'a> {
    pub fn new(histogram: &'a LatencyHistogram) -> Self {
        Self {
            start: std::time::Instant::now(),
            histogram,
        }
    }
}

impl<'a> Drop for LatencyTimer<'a> {
    fn drop(&mut self) {
        self.histogram.record(self.start.elapsed());
    }
}

// ---------------------------------------------------------------------------
// CommitGroupMetrics -- transaction group observability
// ---------------------------------------------------------------------------

/// Global commit_group metrics, updated after each periodic commit.
pub static COMMIT_GROUP_CURRENT_ID: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
pub static TXG_COMMITTED_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static TXG_DURABLE_HIGH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Snapshot of commit_group observability counters.
#[derive(Debug, Clone, Copy)]
pub struct CommitGroupSnapshot {
    pub current_commit_group_id: u64,
    pub committed_count: u64,
    pub durable_high: u64,
}

impl CommitGroupSnapshot {
    /// Capture the current commit_group observability state.
    pub fn now() -> Self {
        Self {
            current_commit_group_id: COMMIT_GROUP_CURRENT_ID
                .load(std::sync::atomic::Ordering::Relaxed),
            committed_count: TXG_COMMITTED_COUNT.load(std::sync::atomic::Ordering::Relaxed),
            durable_high: TXG_DURABLE_HIGH.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

/// Emit a human-readable commit_group summary to stderr.
pub fn emit_commit_group_summary() {
    let snap = CommitGroupSnapshot::now();
    eprintln!(
        "txg_observability current_id={} committed={} durable_high={}",
        snap.current_commit_group_id, snap.committed_count, snap.durable_high,
    );
}
