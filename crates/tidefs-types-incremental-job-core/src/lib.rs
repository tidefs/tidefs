// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Authority type definitions for the universal incremental cursor framework.
//!
//! Implements Phase 1 of the background service framework.
//! Canonical design spec:
//! [`docs/design/background-service-framework-design.md`]
//! (issues #1592, #1673, #1674, #1780). Wire-up tracking: #1877.
//! with seven core types:
//!
//! - [`WorkBudget`] — three-dimensional resource bound (items, bytes, time)
//!   with `DEFAULT_TICK` and `MAINTENANCE_TICK` constants
//! - [`JobProgress`] — aggregate progress counters since job creation
//! - [`JobId`] — unique job identifier (newtype `u64`)
//! - [`JobKind`] — discriminant enum covering all background maintenance and
//!   admin operations
//! - [`JobError`] — error type for checkpoint corruption, budget violations,
//!   and I/O failures
//!
//! Types gated on the `alloc` feature (enabled by default):
//!
//! - [`CursorState`] — opaque serialized cursor blob (requires `Vec<u8>`)
//! - [`Checkpoint`] — persisted progress marker with cursor state
//! - [`StepResult`] — outcome of one `step()` call with checkpoint
//!
//! # The IncrementalJob trait
//!
//! The [`IncrementalJob`] trait is the universal contract that every
//! long-running background maintenance and admin operation implements.
//! It defines a standard control plane for the scheduler, checkpoint
//! persistence layer, and admin tooling, alongside the data-plane types
//! in this crate.
//!
//! # Comparison to ZFS / Ceph
//!
//! - **ZFS**: Background operations (scrub, resilver, dataset destroy) use
//!   ad-hoc scan tickets and `spa_sync` pass callbacks without a unified
//!   budget or checkpoint contract. Scrub progress is tracked via
//!   `dsl_scan_phys_t` but is not resumable across imports without a full
//!   pool re-scan. Resilver uses `device_rebuild` with internal bitmaps;
//!   checkpoint granularity is coarse and not exposed to other subsystems.
//!   This design provides a universal budget envelope and fine-grained
//!   crash-resumable checkpoints for every maintenance operation.
//!
//! - **Ceph**: PGs self-repair via `pg_scrub` and `pg_deep_scrub` with
//!   per-PG state machines, but there is no cluster-wide work budget or
//!   unified checkpoint format. Backfill/recovery (analogous to resilver)
//!   uses per-PG `RecoveryOp` queues with peer-to-peer push/pull, not a
//!   cursor-based step contract. This design provides a single job model
//!   with consistent budget enforcement across all background work.
//!
//! [`IncrementalJob`]:
//!     ../../tidefs-incremental-job-core/trait.IncrementalJob.html
//! [`docs/design/background-service-framework-design.md`]:
//!     docs/design/background-service-framework-design.md

use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "alloc")]
extern crate alloc;

// ---------------------------------------------------------------------------
// WorkBudget — three-dimensional resource bound
// ---------------------------------------------------------------------------

/// Resource budget for a single `IncrementalJob::step()` call.
///
/// Every `step()` invocation receives a `WorkBudget` and **MUST NOT** exceed
/// any of its active limits. A limit of `0` means "unbounded" in that
/// dimension. At least one limit **SHOULD** be non-zero to guarantee
/// forward-progress boundedness.
///
/// # Budget enforcement
///
/// Budget enforcement is the implementor's responsibility. The framework
/// does not preempt; it trusts the implementation. The validation gate
/// tests that implementations do not exceed their budget.
///
/// # Constants
///
/// | Constant | Items | Bytes | Time |
/// |---|---|---|---|
/// | [`DEFAULT_TICK`](WorkBudget::DEFAULT_TICK) | 1024 | 64 MiB | 100 ms |
/// | [`MAINTENANCE_TICK`](WorkBudget::MAINTENANCE_TICK) | 256 | 16 MiB | 50 ms |
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WorkBudget {
    /// Maximum records, entries, or items to process in this step.
    /// `0` = unbounded.
    pub max_items: u64,
    /// Maximum bytes to allocate, relocate, or write in this step.
    /// `0` = unbounded.
    pub max_bytes: u64,
    /// Maximum wall-clock milliseconds for this step (soft limit).
    /// `0` = unbounded.
    pub max_ms: u64,
}

impl WorkBudget {
    /// Default tick quantum used when no explicit budget is configured.
    ///
    /// Processes up to 1024 items, 64 MiB of I/O, or 100 ms —
    /// whichever limit is hit first.
    pub const DEFAULT_TICK: Self = Self {
        max_items: 1024,
        max_bytes: 64 * 1024 * 1024,
        max_ms: 100,
    };

    /// Budget for a lightweight maintenance tick (e.g., idle cluster).
    ///
    /// Processes up to 256 items, 16 MiB of I/O, or 50 ms.
    pub const MAINTENANCE_TICK: Self = Self {
        max_items: 256,
        max_bytes: 16 * 1024 * 1024,
        max_ms: 50,
    };

    /// Fully unbounded budget — no limits in any dimension.
    ///
    /// Use for admin-initiated tasks that should run to completion
    /// without being throttled by the scheduler.
    pub const UNBOUNDED: Self = Self {
        max_items: 0,
        max_bytes: 0,
        max_ms: 0,
    };

    /// Paused budget — zero active limits signal the scheduler to
    /// skip this job tick.  Equivalent to  in value but
    /// carries distinct scheduling semantics ("do no work" vs
    /// "do unlimited work").
    pub const PAUSED: Self = Self {
        max_items: 0,
        max_bytes: 0,
        max_ms: 0,
    };

    /// Returns `true` if at least one limit is non-zero (the budget
    /// provides boundedness).
    #[must_use]
    pub const fn is_bounded(self) -> bool {
        self.max_items > 0 || self.max_bytes > 0 || self.max_ms > 0
    }

    /// Returns `true` if all three limits are zero (fully unbounded).
    #[must_use]
    pub const fn is_unbounded(self) -> bool {
        self.max_items == 0 && self.max_bytes == 0 && self.max_ms == 0
    }

    /// Returns `true` if `items` does not exceed `max_items`
    /// (or `max_items == 0`, meaning unbounded).
    #[must_use]
    pub const fn items_within_budget(self, items: u64) -> bool {
        self.max_items == 0 || items <= self.max_items
    }

    /// Returns `true` if `bytes` does not exceed `max_bytes`
    /// (or `max_bytes == 0`, meaning unbounded).
    #[must_use]
    pub const fn bytes_within_budget(self, bytes: u64) -> bool {
        self.max_bytes == 0 || bytes <= self.max_bytes
    }
}

impl Default for WorkBudget {
    fn default() -> Self {
        Self::DEFAULT_TICK
    }
}

impl fmt::Display for WorkBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WorkBudget(items={}, bytes={}, ms={})",
            self.max_items, self.max_bytes, self.max_ms,
        )
    }
}

// ---------------------------------------------------------------------------
// CursorState — opaque cursor blob (requires alloc feature)
// ---------------------------------------------------------------------------

/// Opaque serialized cursor blob private to each `IncrementalJob`
/// implementation.
///
/// The format and interpretation of the inner bytes are entirely the
/// responsibility of the owning job. The framework treats this as an
/// opaque payload for persistence and crash recovery.
///
/// Requires the `alloc` feature (enabled by default).
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CursorState(pub alloc::vec::Vec<u8>);

#[cfg(feature = "alloc")]
impl CursorState {
    /// Create an empty cursor (used for fresh job starts).
    #[must_use]
    pub fn empty() -> Self {
        CursorState(alloc::vec::Vec::new())
    }

    /// Returns `true` if the cursor is empty (no state has been saved).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of bytes in the cursor blob.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns a byte slice view of the cursor data.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(feature = "alloc")]
impl From<alloc::vec::Vec<u8>> for CursorState {
    fn from(v: alloc::vec::Vec<u8>) -> Self {
        CursorState(v)
    }
}

#[cfg(feature = "alloc")]
impl From<CursorState> for alloc::vec::Vec<u8> {
    fn from(c: CursorState) -> Self {
        c.0
    }
}

// ---------------------------------------------------------------------------
// JobProgress — aggregate progress counters
// ---------------------------------------------------------------------------

/// Aggregate progress since job creation.
///
/// Updated by the job implementation after each committed batch.
/// Provides admin-facing observability without requiring the job to
/// expose internal cursor details.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct JobProgress {
    /// Total items (records, entries, extents) processed since job start.
    pub items_processed: u64,
    /// Estimated total items to process. `0` means "unknown" (e.g.,
    /// dynamic work sets like GC marking).
    pub items_total_estimate: u64,
    /// Total bytes processed since job start.
    pub bytes_processed: u64,
    /// Estimated total bytes to process. `0` means "unknown".
    pub bytes_total_estimate: u64,
    /// Wall-clock elapsed milliseconds since job creation.
    pub elapsed_ms: u64,
}

impl JobProgress {
    /// Returns the completion ratio as thousandths (0–1000).
    ///
    /// Uses `items_total_estimate` if non-zero; falls back to
    /// `bytes_total_estimate`. Returns `0` if neither estimate is
    /// available.
    #[must_use]
    pub fn completion_permille(&self) -> u16 {
        if self.items_total_estimate > 0 && self.items_processed <= self.items_total_estimate {
            ((self.items_processed as u128 * 1000) / self.items_total_estimate as u128) as u16
        } else if self.bytes_total_estimate > 0 && self.bytes_processed <= self.bytes_total_estimate
        {
            ((self.bytes_processed as u128 * 1000) / self.bytes_total_estimate as u128) as u16
        } else {
            0
        }
    }

    /// Accumulate another progress snapshot into this one (addition).
    /// Estimates are not additive; the caller's estimate is kept.
    pub fn accumulate(&mut self, other: JobProgress) {
        self.items_processed = self.items_processed.saturating_add(other.items_processed);
        self.bytes_processed = self.bytes_processed.saturating_add(other.bytes_processed);
        self.elapsed_ms = self.elapsed_ms.saturating_add(other.elapsed_ms);
    }
}

impl fmt::Display for JobProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "items={}/{} bytes={}/{} elapsed={}ms",
            self.items_processed,
            self.items_total_estimate,
            self.bytes_processed,
            self.bytes_total_estimate,
            self.elapsed_ms,
        )
    }
}

// ---------------------------------------------------------------------------
// Checkpoint — persisted progress marker (requires alloc feature)
// ---------------------------------------------------------------------------

/// A stable checkpoint that allows crash-resumable progress.
///
/// Persisted atomically in the dataset-scoped checkpoint area.
/// The opaque [`cursor_state`](Checkpoint::cursor_state) is interpreted
/// only by the owning [`IncrementalJob`] implementation.
///
/// # Epoch counter
///
/// The [`epoch`](Checkpoint::epoch) field is incremented by the checkpoint
/// persistence layer on each daemon restart. This enables the admin to
/// distinguish "fresh run after restart" from "continuing a running job."
///
/// Requires the `alloc` feature (enabled by default).
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Checkpoint {
    /// Stable identifier assigned at job creation.
    pub job_id: JobId,
    /// The kind of job (DeferredCleanup, SnapshotDestroy, GCMark, etc.).
    pub job_kind: JobKind,
    /// Monotonic epoch counter, incremented on each daemon restart.
    pub epoch: u64,
    /// Opaque serialized cursor position.
    pub cursor_state: CursorState,
    /// Aggregate progress counters since job start.
    pub progress: JobProgress,
}

#[cfg(feature = "alloc")]
impl Checkpoint {
    /// Create a checkpoint for a brand-new job (epoch 1, empty cursor,
    /// zero progress).
    #[must_use]
    pub fn new_initial(job_id: JobId, job_kind: JobKind) -> Self {
        Checkpoint {
            job_id,
            job_kind,
            epoch: 1,
            cursor_state: CursorState::empty(),
            progress: JobProgress::default(),
        }
    }

    /// Returns `true` if this is an initial (fresh-start) checkpoint
    /// with an empty cursor.
    #[must_use]
    pub fn is_fresh(&self) -> bool {
        self.cursor_state.is_empty()
    }
}

// ---------------------------------------------------------------------------
// StepResult — outcome of one step() (requires alloc feature)
// ---------------------------------------------------------------------------

/// Result of a single `IncrementalJob::step()` invocation.
///
/// Contains the updated checkpoint reflecting work completed in this
/// batch and a completion flag.
///
/// Requires the `alloc` feature (enabled by default).
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct StepResult {
    /// The checkpoint to persist. Represents the exact cursor position
    /// after this batch's work was committed.
    pub checkpoint: Checkpoint,
    /// `true` if the job has fully completed. The caller should invoke
    /// `complete()` and not call `step()` again.
    pub is_complete: bool,
}

#[cfg(feature = "alloc")]
impl StepResult {
    /// Create a step result indicating the batch was processed but the
    /// job is not yet complete.
    #[must_use]
    pub fn in_progress(checkpoint: Checkpoint) -> Self {
        StepResult {
            checkpoint,
            is_complete: false,
        }
    }

    /// Create a step result indicating the job is fully complete.
    #[must_use]
    pub fn complete(checkpoint: Checkpoint) -> Self {
        StepResult {
            checkpoint,
            is_complete: true,
        }
    }
}

// ---------------------------------------------------------------------------
// JobId — unique job identifier
// ---------------------------------------------------------------------------

/// Unique job identifier assigned at creation.
///
/// This is a monotonically increasing counter scoped to the pool.
/// Zero is reserved as a sentinel ("no job").
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct JobId(pub u64);

impl JobId {
    /// Sentinel value for "no job."
    pub const NONE: Self = JobId(0);

    /// Returns `true` if this is the `NONE` sentinel.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if this is a real job id (non-zero).
    #[must_use]
    pub const fn is_some(self) -> bool {
        self.0 != 0
    }
}

impl Default for JobId {
    fn default() -> Self {
        Self::NONE
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "job:{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// JobKind — discriminant enum for background / admin operations
// ---------------------------------------------------------------------------

/// Canonical job kinds for admin visibility and scheduling priority.
///
/// Each variant corresponds to a specific background maintenance or admin
/// operation. The `Other(u8)` variant supports forward compatibility with
/// job kinds added in future releases.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum JobKind {
    /// Deferred unlink/truncate extent freeing.
    DeferredCleanup,
    /// Snapshot deadlist processing and pinned-extent reclamation.
    SnapshotDestroy,
    /// Metadata GC reachability marking pass.
    GCMark,
    /// B+tree compaction / segment defragmentation.
    BtreeCompaction,
    /// Ingest journal to base shard conversion.
    Rebake,
    /// Data journal segment cleaning.
    JournalCleaning,
    /// Admin-initiated dataset destroy.
    DatasetDestroy,
    /// Online data integrity verification (metadata-only or sampled).
    Scrub,
    /// Full read-and-verify scrub (all data blocks).
    DeepScrub,
    /// Device replacement data rebuild.
    Resilver,
    /// Continuous failure recovery loop orchestration.
    Recovery,
    /// Generic long-running admin operation.
    /// Reclaim: refcount-delta-based deferred extent/locator reclamation.
    Reclaim,
    /// Mount-time orphan recovery: reclaim extents for nlink==0 inodes.
    OrphanRecovery,
    /// Derived catalog view building: directory B-tree walk, view cache population.
    DerivedCatalog,
    DataCleaner,
    /// Online extent map defragmentation: merges adjacent extents and
    /// compacts fragmented extent maps into contiguous form.
    Defrag,
    /// Dead segment reclamation: compact and free segments with high dead ratios.
    SegmentCleaner,
    SnapshotPruner,
    Dedup,
    /// Online pool geometry conversion: rewrite locator table entries for durability policy change.
    GeometryConvert,
    /// Restore lost or suspect replica copies via rebuild planner.
    Rebuild,
    /// Catch up lagged replica copies via backfill planner.
    Backfill,
    /// Move replicas for capacity optimization via rebalance planner.
    Rebalance,
    /// Restore lost or suspect replica copies via rebuild planner.
    AdminJob,
    /// Forward-compatibility variant for future job kinds.
    Other(u8),
}

impl JobKind {
    /// Returns a human-readable label for the job kind.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            JobKind::DeferredCleanup => "deferred_cleanup",
            JobKind::SnapshotDestroy => "snapshot_destroy",
            JobKind::GCMark => "gc_mark",
            JobKind::BtreeCompaction => "btree_compaction",
            JobKind::Rebake => "rebake",
            JobKind::JournalCleaning => "journal_cleaning",
            JobKind::DatasetDestroy => "dataset_destroy",
            JobKind::Scrub => "scrub",
            JobKind::DeepScrub => "deep_scrub",
            JobKind::Resilver => "resilver",
            JobKind::Recovery => "recovery",
            JobKind::AdminJob => "admin_job",
            JobKind::Reclaim => "reclaim",
            JobKind::OrphanRecovery => "orphan_recovery",
            JobKind::DerivedCatalog => "derived_catalog",
            JobKind::DataCleaner => "data_cleaner",
            JobKind::Defrag => "defrag",
            JobKind::SegmentCleaner => "segment_cleaner",
            JobKind::SnapshotPruner => "snapshot_pruner",
            JobKind::Dedup => "dedup",
            JobKind::GeometryConvert => "geometry_convert",
            JobKind::Rebuild => "rebuild",
            JobKind::Backfill => "backfill",
            JobKind::Rebalance => "rebalance",
            JobKind::Other(_) => "other",
        }
    }

    /// Returns `true` if this job kind involves data integrity checking.
    #[must_use]
    pub const fn is_integrity_check(self) -> bool {
        matches!(self, JobKind::Scrub | JobKind::DeepScrub)
    }

    /// Returns `true` if this job kind is latency-sensitive and should
    /// not be starved by lower-priority work.
    #[must_use]
    pub const fn is_latency_sensitive(self) -> bool {
        matches!(
            self,
            JobKind::Resilver
                | JobKind::Recovery
                | JobKind::JournalCleaning
                | JobKind::OrphanRecovery
                | JobKind::Reclaim
                | JobKind::DerivedCatalog
        )
    }
}

impl fmt::Display for JobKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JobKind::Other(n) => write!(f, "other({n})"),
            _ => f.write_str(self.label()),
        }
    }
}

// ---------------------------------------------------------------------------
// JobError — error type
// ---------------------------------------------------------------------------

/// Errors produced by `IncrementalJob` operations.
///
/// The `Other` variant (with a heap-allocated `String` payload) requires the
/// `alloc` feature (enabled by default). Without `alloc`, only fixed-message
/// variants are available.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JobError {
    /// The persisted checkpoint is corrupt or unreadable.
    CheckpointCorrupt { job_id: JobId, reason: &'static str },
    /// The opaque cursor state could not be deserialized or is invalid
    /// for the current job implementation.
    CursorStateInvalid { job_id: JobId, reason: &'static str },
    /// The implementation exceeded one or more budget limits during
    /// a `step()` call.
    BudgetExceeded {
        job_id: JobId,
        budget: WorkBudget,
        actual_items: u64,
        actual_bytes: u64,
    },
    /// `step()` was called on a job that has already reported
    /// `is_complete = true`.
    JobAlreadyComplete { job_id: JobId },
    /// An I/O error occurred during checkpoint persistence or data
    /// access.
    IoError {
        job_id: JobId,
        message: &'static str,
    },
    /// A catch-all for errors that don't fit the above categories.
    /// Requires the `alloc` feature.
    #[cfg(feature = "alloc")]
    Other(alloc::string::String),
}

impl JobError {
    /// Returns the [`JobId`] associated with this error, if any.
    #[must_use]
    pub fn job_id(&self) -> Option<JobId> {
        match self {
            JobError::CheckpointCorrupt { job_id, .. }
            | JobError::CursorStateInvalid { job_id, .. }
            | JobError::BudgetExceeded { job_id, .. }
            | JobError::JobAlreadyComplete { job_id }
            | JobError::IoError { job_id, .. } => Some(*job_id),
            #[cfg(feature = "alloc")]
            JobError::Other(_) => None,
        }
    }
}

impl fmt::Display for JobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JobError::CheckpointCorrupt { job_id, reason } => {
                write!(f, "checkpoint corrupt for {job_id}: {reason}")
            }
            JobError::CursorStateInvalid { job_id, reason } => {
                write!(f, "cursor state invalid for {job_id}: {reason}")
            }
            JobError::BudgetExceeded {
                job_id,
                budget,
                actual_items,
                actual_bytes,
            } => {
                write!(
                    f,
                    "budget exceeded for {job_id}: budget={budget}, actual_items={actual_items}, actual_bytes={actual_bytes}"
                )
            }
            JobError::JobAlreadyComplete { job_id } => {
                write!(f, "job {job_id} already complete")
            }
            JobError::IoError { job_id, message } => {
                write!(f, "I/O error for {job_id}: {message}")
            }
            #[cfg(feature = "alloc")]
            JobError::Other(msg) => {
                write!(f, "job error: {msg}")
            }
        }
    }
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// IncrementalJob trait — universal control-plane contract (requires alloc)
// ---------------------------------------------------------------------------

/// Universal contract for every long-running background maintenance and
/// admin operation.
///
/// Every subsystem that performs incremental work (scrub, resilver, GC
/// mark, btree compaction, rebake, deferred cleanup, etc.) implements
/// this trait. The scheduler drives progress via repeated `step()` calls,
/// the checkpoint persistence layer calls `persist_checkpoint()` for
/// crash recovery, and admin tooling inspects `job_id()` / `job_kind()`
/// for observability.
///
/// # Lifecycle
///
/// 1. **Creation**: A fresh job is created via
///    `resume(Checkpoint::new_initial(id, kind))`.
/// 2. **Stepping**: The scheduler calls `step(budget)` repeatedly. Each
///    call receives a [`WorkBudget`] and **MUST NOT** exceed any active
///    limit. The returned [`StepResult`] indicates progress and whether
///    the job is complete.
/// 3. **Checkpointing**: After every committed batch, the scheduler calls
///    `persist_checkpoint()` to obtain the latest checkpoint and persists
///    it atomically.
/// 4. **Crash recovery**: On daemon restart, the scheduler loads the last
///    persisted [`Checkpoint`] and calls `resume(checkpoint)` to recreate
///    the job at its last committed position.
/// 5. **Completion**: When `step()` returns `StepResult { is_complete:
///    true, .. }`, the scheduler calls `complete()` for final cleanup and
///    does not call `step()` again.
///
/// # Budget contract
///
/// Implementors **MUST** self-enforce the [`WorkBudget`] passed to
/// `step()`. The framework does not preempt; it trusts the
/// implementation. Violations are a correctness bug.
///
/// # Object safety
///
/// This trait is **not** object-safe (`resume` uses `where Self: Sized`).
/// Jobs are dispatched through generics, not trait objects, enabling
/// zero-cost monomorphization in hot `step()` paths.
///
/// Requires the `alloc` feature (enabled by default).
#[cfg(feature = "alloc")]
pub trait IncrementalJob {
    /// Reconstruct a job from a persisted [`Checkpoint`].
    ///
    /// Called at job creation (with a fresh `Checkpoint`) and after crash
    /// recovery (with the last persisted checkpoint). The implementation
    /// must validate the cursor state and return
    /// [`JobError::CursorStateInvalid`] if the opaque blob is unreadable.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::CursorStateInvalid`] if the cursor cannot be
    /// deserialized or is otherwise invalid for this job implementation.
    fn resume(checkpoint: Checkpoint) -> Result<Self, JobError>
    where
        Self: Sized;

    /// Execute one quantum of work under the given [`WorkBudget`].
    ///
    /// The implementation chooses what constitutes a quantum: scanning N
    /// extents, compacting one segment, freeing a batch of deadlist
    /// entries, etc. It **MUST NOT** exceed any active budget limit.
    ///
    /// Returns a [`StepResult`] containing the updated checkpoint and a
    /// completion flag. When `is_complete` is `true`, the caller must not
    /// call `step()` again.
    fn step(&mut self, budget: WorkBudget) -> StepResult;

    /// Return the current checkpoint for atomic persistence.
    ///
    /// Called after every successful `step()` batch. The returned
    /// [`Checkpoint`] must reflect all work committed in the last
    /// `step()` call, including the updated cursor position and progress
    /// counters.
    fn persist_checkpoint(&self) -> Checkpoint;

    /// Finalize the job after completion.
    ///
    /// Called exactly once when `step()` returns `is_complete: true`.
    /// The implementation releases any resources held by the job and
    /// performs final cleanup.
    fn complete(self);

    /// Return the stable job identifier.
    fn job_id(&self) -> JobId;

    /// Return the discriminant for admin visibility and scheduling.
    fn job_kind(&self) -> JobKind;
}
// ---------------------------------------------------------------------------
// ServiceCheckpoint — scheduler crash-consistent save/restore point
// ---------------------------------------------------------------------------

/// Crash-consistent checkpoint for a background service's full state.
///
/// Wraps the job-level [`Checkpoint`] with scheduler-managed lifecycle
/// and tracking state, enabling atomic save/restore of the entire
/// scheduler state.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServiceCheckpoint {
    /// The underlying job checkpoint (cursor position).
    pub job_checkpoint: Checkpoint,
    /// Service lifecycle state.
    pub service_state: ServiceState,
    /// Health tracker — consecutive error count.
    pub health_consecutive_errors: u32,
    /// Starvation tracker — cycles since last dispatch.
    pub starvation_cycles_since_last_run: u64,
}

/// Service lifecycle state for a managed background service.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ServiceState {
    /// Registered but not yet dispatched. First tick promotes to Running.
    Registered,
    /// Actively dispatched by the scheduler.
    Running,
    /// Temporarily suspended. Scheduler skips. Resumable.
    Paused,
    /// Automatically paused after exceeding error_threshold.
    /// Requires operator intervention to reset to Running.
    Unhealthy,
    /// Permanently removed. Scheduler ignores. Terminal.
    Retired,
}

impl ServiceState {
    /// Whether the service may be dispatched in this state.
    #[must_use]
    pub fn is_dispatchable(self) -> bool {
        matches!(self, ServiceState::Running)
    }

    /// Whether this is a terminal state.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, ServiceState::Retired)
    }
}

impl core::fmt::Display for ServiceState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ServiceState::Registered => write!(f, "registered"),
            ServiceState::Running => write!(f, "running"),
            ServiceState::Paused => write!(f, "paused"),
            ServiceState::Unhealthy => write!(f, "unhealthy"),
            ServiceState::Retired => write!(f, "retired"),
        }
    }
}
// ---------------------------------------------------------------------------
// SchedulerEpoch — monotonic generation counter for dispatch ordering
// ---------------------------------------------------------------------------

/// Monotonic epoch counter that advances on each scheduler restart.
///
/// Used to detect and reject stale dispatch records from a previous
/// scheduler lifetime. Every dispatch record carries the epoch in which
/// it was created; the scheduler rejects dispatch for a record whose
/// epoch differs from the current epoch unless the record is being
/// replayed after a crash within the same epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SchedulerEpoch(pub u64);

impl SchedulerEpoch {
    /// The initial epoch value at pool creation or first scheduler start.
    pub const INITIAL: Self = SchedulerEpoch(0);

    /// Advance to the next epoch.
    #[must_use]
    pub fn next(self) -> Self {
        SchedulerEpoch(self.0 + 1)
    }

    /// Returns true if this epoch is reached from `prev` by advancing.
    #[must_use]
    pub fn is_successor_of(self, prev: SchedulerEpoch) -> bool {
        self.0 == prev.0 + 1
    }
}

impl core::fmt::Display for SchedulerEpoch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "epoch-{}", self.0)
    }
}

impl Default for SchedulerEpoch {
    fn default() -> Self {
        Self::INITIAL
    }
}

// ---------------------------------------------------------------------------
// DispatchRecordId — unique identity for a single dispatch event
// ---------------------------------------------------------------------------

/// Unique identifier for a dispatch record.
///
/// Used to prevent duplicate dispatch: the scheduler stores this id
/// and rejects any attempt to dispatch the same id within the same epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DispatchRecordId(pub u64);

impl core::fmt::Display for DispatchRecordId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "dispatch-{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// DispatchState — lifecycle state of a dispatch record
// ---------------------------------------------------------------------------

/// State of a dispatched job tracked by the scheduler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DispatchState {
    /// Record persisted, job not yet started.
    Pending,
    /// Job is actively executing.
    InProgress,
    /// Job completed successfully; completion marker persisted.
    Completed,
    /// Job was cancelled before completion.
    Cancelled,
}

impl DispatchState {
    /// True if this state represents a terminal condition.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, DispatchState::Completed | DispatchState::Cancelled)
    }

    /// True if the job may be resumed or re-queued.
    #[must_use]
    pub fn is_resumable(self) -> bool {
        matches!(self, DispatchState::Pending | DispatchState::InProgress)
    }
}

impl core::fmt::Display for DispatchState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DispatchState::Pending => write!(f, "pending"),
            DispatchState::InProgress => write!(f, "in_progress"),
            DispatchState::Completed => write!(f, "completed"),
            DispatchState::Cancelled => write!(f, "cancelled"),
        }
    }
}

// ---------------------------------------------------------------------------
// DispatchRecord — durable dispatch event for a scheduled job
// ---------------------------------------------------------------------------

/// Persistent record of a job dispatch event.
///
/// Written before a job begins execution and updated on completion,
/// cancellation, or checkpoint advancement. On daemon restart, the
/// scheduler replays pending and in-progress records to resume work.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DispatchRecord {
    /// The job identity.
    pub job_id: JobId,
    /// The kind of job.
    pub job_kind: JobKind,
    /// Scheduler epoch when this record was created.
    pub epoch: SchedulerEpoch,
    /// Unique dispatch identity within this epoch.
    pub dispatch_id: DispatchRecordId,
    /// Current lifecycle state.
    pub state: DispatchState,
    /// Wall-clock timestamp when the record was created (ms since pool epoch).
    pub created_at_ms: u64,
    /// Last known checkpoint, if any step completed.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub last_checkpoint: Option<Checkpoint>,
}

#[cfg(feature = "alloc")]
impl DispatchRecord {
    /// Create a new dispatch record in `Pending` state.
    #[must_use]
    pub fn new(
        job_id: JobId,
        job_kind: JobKind,
        epoch: SchedulerEpoch,
        dispatch_id: DispatchRecordId,
        now_ms: u64,
    ) -> Self {
        Self {
            job_id,
            job_kind,
            epoch,
            dispatch_id,
            state: DispatchState::Pending,
            created_at_ms: now_ms,
            last_checkpoint: None,
        }
    }

    /// Transition to `InProgress`.
    pub fn mark_in_progress(&mut self) {
        self.state = DispatchState::InProgress;
    }

    /// Transition to `Completed`.
    pub fn mark_completed(&mut self) {
        self.state = DispatchState::Completed;
    }

    /// Transition to `Cancelled`.
    pub fn mark_cancelled(&mut self) {
        self.state = DispatchState::Cancelled;
    }

    /// Update the last checkpoint after a step.
    pub fn update_checkpoint(&mut self, cp: Checkpoint) {
        self.last_checkpoint = Some(cp);
    }

    /// True if this record can be re-dispatched after restart.
    #[must_use]
    pub fn can_resume(&self) -> bool {
        self.state.is_resumable()
    }
}

#[cfg(feature = "alloc")]
impl core::fmt::Display for DispatchRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "DispatchRecord({} {} epoch={} state={})",
            self.job_id, self.job_kind, self.epoch, self.state
        )
    }
}
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── WorkBudget ─────────────────────────────────────────────────────

    #[test]
    fn default_tick_values() {
        let b = WorkBudget::DEFAULT_TICK;
        assert_eq!(b.max_items, 1024);
        assert_eq!(b.max_bytes, 64 * 1024 * 1024);
        assert_eq!(b.max_ms, 100);
    }

    #[test]
    fn maintenance_tick_values() {
        let b = WorkBudget::MAINTENANCE_TICK;
        assert_eq!(b.max_items, 256);
        assert_eq!(b.max_bytes, 16 * 1024 * 1024);
        assert_eq!(b.max_ms, 50);
    }

    #[test]
    fn is_bounded_when_any_limit_set() {
        assert!(WorkBudget::DEFAULT_TICK.is_bounded());
        assert!(WorkBudget {
            max_items: 1,
            ..WorkBudget::default()
        }
        .is_bounded());
        assert!(WorkBudget {
            max_ms: 1,
            ..WorkBudget::default()
        }
        .is_bounded());
    }

    #[test]
    fn is_unbounded_when_all_zero() {
        let b = WorkBudget {
            max_items: 0,
            max_bytes: 0,
            max_ms: 0,
        };
        assert!(b.is_unbounded());
        assert!(!b.is_bounded());
    }

    #[test]
    fn items_within_budget_unbounded() {
        let b = WorkBudget {
            max_items: 0,
            ..WorkBudget::default()
        };
        assert!(b.items_within_budget(1_000_000));
    }

    #[test]
    fn items_within_budget_bounded() {
        let b = WorkBudget {
            max_items: 1024,
            ..WorkBudget::default()
        };
        assert!(b.items_within_budget(1024));
        assert!(!b.items_within_budget(1025));
    }

    #[test]
    fn bytes_within_budget() {
        let b = WorkBudget {
            max_bytes: 1024,
            ..WorkBudget::default()
        };
        assert!(b.bytes_within_budget(1024));
        assert!(!b.bytes_within_budget(1025));
    }

    #[test]
    fn bytes_within_budget_unbounded() {
        let b = WorkBudget {
            max_bytes: 0,
            ..WorkBudget::default()
        };
        assert!(b.bytes_within_budget(u64::MAX));
    }

    #[test]
    fn default_is_default_tick() {
        assert_eq!(WorkBudget::default(), WorkBudget::DEFAULT_TICK);
    }

    #[test]
    fn work_budget_display() {
        let s = format!("{}", WorkBudget::DEFAULT_TICK);
        assert!(s.contains("1024"));
        assert!(s.contains("67108864"));
        assert!(s.contains("100"));
    }

    // ── CursorState ────────────────────────────────────────────────────

    #[test]
    fn empty_cursor() {
        let c = CursorState::empty();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
        assert_eq!(c.as_bytes(), b"");
    }

    #[test]
    fn cursor_from_vec() {
        let data = vec![1, 2, 3, 4];
        let c = CursorState::from(data.clone());
        assert!(!c.is_empty());
        assert_eq!(c.len(), 4);
        assert_eq!(c.as_bytes(), &[1, 2, 3, 4]);
        let back: Vec<u8> = c.into();
        assert_eq!(back, data);
    }

    #[test]
    fn cursor_default_is_empty() {
        assert!(CursorState::default().is_empty());
    }

    #[test]
    fn cursor_clone_eq() {
        let c1 = CursorState(vec![0xDE, 0xAD]);
        let c2 = c1.clone();
        assert_eq!(c1, c2);
    }

    // ── JobProgress ────────────────────────────────────────────────────

    #[test]
    fn progress_default_zero() {
        let p = JobProgress::default();
        assert_eq!(p.items_processed, 0);
        assert_eq!(p.items_total_estimate, 0);
        assert_eq!(p.bytes_processed, 0);
        assert_eq!(p.bytes_total_estimate, 0);
        assert_eq!(p.elapsed_ms, 0);
    }

    #[test]
    fn completion_permille_items() {
        let p = JobProgress {
            items_processed: 500,
            items_total_estimate: 1000,
            ..Default::default()
        };
        assert_eq!(p.completion_permille(), 500);
    }

    #[test]
    fn completion_permille_bytes_fallback() {
        let p = JobProgress {
            bytes_processed: 750,
            bytes_total_estimate: 1000,
            ..Default::default()
        };
        assert_eq!(p.completion_permille(), 750);
    }

    #[test]
    fn completion_permille_no_estimate() {
        let p = JobProgress::default();
        assert_eq!(p.completion_permille(), 0);
    }

    #[test]
    fn completion_permille_items_preferred_over_bytes() {
        let p = JobProgress {
            items_processed: 200,
            items_total_estimate: 1000,
            bytes_processed: 800,
            bytes_total_estimate: 1000,
            ..Default::default()
        };
        assert_eq!(p.completion_permille(), 200);
    }

    #[test]
    fn completion_permille_full() {
        let p = JobProgress {
            items_processed: 1000,
            items_total_estimate: 1000,
            ..Default::default()
        };
        assert_eq!(p.completion_permille(), 1000);
    }

    #[test]
    fn accumulate_progress() {
        let mut a = JobProgress {
            items_processed: 100,
            bytes_processed: 4096,
            elapsed_ms: 50,
            ..Default::default()
        };
        let b = JobProgress {
            items_processed: 50,
            bytes_processed: 2048,
            elapsed_ms: 25,
            ..Default::default()
        };
        a.accumulate(b);
        assert_eq!(a.items_processed, 150);
        assert_eq!(a.bytes_processed, 6144);
        assert_eq!(a.elapsed_ms, 75);
    }

    #[test]
    fn accumulate_saturating() {
        let mut a = JobProgress {
            items_processed: u64::MAX,
            ..Default::default()
        };
        let b = JobProgress {
            items_processed: 1,
            ..Default::default()
        };
        a.accumulate(b);
        assert_eq!(a.items_processed, u64::MAX);
    }

    #[test]
    fn progress_display() {
        let p = JobProgress {
            items_processed: 100,
            items_total_estimate: 1000,
            bytes_processed: 5000,
            bytes_total_estimate: 10000,
            elapsed_ms: 300,
        };
        let s = format!("{p}");
        assert!(s.contains("100"));
        assert!(s.contains("1000"));
        assert!(s.contains("5000"));
        assert!(s.contains("10000"));
        assert!(s.contains("300"));
    }

    // ── Checkpoint ─────────────────────────────────────────────────────

    #[test]
    fn new_initial_checkpoint() {
        let job_id = JobId(42);
        let ck = Checkpoint::new_initial(job_id, JobKind::Scrub);
        assert_eq!(ck.job_id, job_id);
        assert_eq!(ck.job_kind, JobKind::Scrub);
        assert_eq!(ck.epoch, 1);
        assert!(ck.cursor_state.is_empty());
        assert_eq!(ck.progress, JobProgress::default());
        assert!(ck.is_fresh());
    }

    #[test]
    fn checkpoint_is_fresh_with_non_empty_cursor() {
        let ck = Checkpoint {
            job_id: JobId(1),
            job_kind: JobKind::GCMark,
            epoch: 3,
            cursor_state: CursorState(vec![1, 2, 3]),
            progress: JobProgress::default(),
        };
        assert!(!ck.is_fresh());
    }

    #[test]
    fn checkpoint_clone_eq() {
        let ck1 = Checkpoint::new_initial(JobId(7), JobKind::Resilver);
        let ck2 = ck1.clone();
        assert_eq!(ck1, ck2);
    }

    // ── StepResult ─────────────────────────────────────────────────────

    #[test]
    fn step_result_in_progress() {
        let ck = Checkpoint::new_initial(JobId(1), JobKind::BtreeCompaction);
        let sr = StepResult::in_progress(ck.clone());
        assert!(!sr.is_complete);
        assert_eq!(sr.checkpoint, ck);
    }

    #[test]
    fn step_result_complete() {
        let ck = Checkpoint::new_initial(JobId(1), JobKind::DeferredCleanup);
        let sr = StepResult::complete(ck.clone());
        assert!(sr.is_complete);
        assert_eq!(sr.checkpoint, ck);
    }

    // ── JobId ──────────────────────────────────────────────────────────

    #[test]
    fn job_id_none_sentinel() {
        assert!(JobId::NONE.is_none());
        assert!(!JobId::NONE.is_some());
        assert_eq!(JobId::default(), JobId::NONE);
    }

    #[test]
    fn job_id_some() {
        let id = JobId(99);
        assert!(id.is_some());
        assert!(!id.is_none());
    }

    #[test]
    fn job_id_ordering() {
        assert!(JobId(1) < JobId(2));
        assert!(JobId(100) > JobId(99));
    }

    #[test]
    fn job_id_display() {
        assert_eq!(format!("{}", JobId(42)), "job:42");
    }

    // ── JobKind ────────────────────────────────────────────────────────

    #[test]
    fn job_kind_labels() {
        assert_eq!(JobKind::DeferredCleanup.label(), "deferred_cleanup");
        assert_eq!(JobKind::SnapshotDestroy.label(), "snapshot_destroy");
        assert_eq!(JobKind::GCMark.label(), "gc_mark");
        assert_eq!(JobKind::BtreeCompaction.label(), "btree_compaction");
        assert_eq!(JobKind::Rebake.label(), "rebake");
        assert_eq!(JobKind::JournalCleaning.label(), "journal_cleaning");
        assert_eq!(JobKind::DatasetDestroy.label(), "dataset_destroy");
        assert_eq!(JobKind::Scrub.label(), "scrub");
        assert_eq!(JobKind::DeepScrub.label(), "deep_scrub");
        assert_eq!(JobKind::Resilver.label(), "resilver");
        assert_eq!(JobKind::AdminJob.label(), "admin_job");
        assert_eq!(JobKind::Other(42).label(), "other");
    }

    #[test]
    fn job_kind_is_integrity_check() {
        assert!(JobKind::Scrub.is_integrity_check());
        assert!(JobKind::DeepScrub.is_integrity_check());
        assert!(!JobKind::Resilver.is_integrity_check());
        assert!(!JobKind::DeferredCleanup.is_integrity_check());
    }

    #[test]
    fn job_kind_is_latency_sensitive() {
        assert!(JobKind::Resilver.is_latency_sensitive());
        assert!(JobKind::JournalCleaning.is_latency_sensitive());
        assert!(!JobKind::Scrub.is_latency_sensitive());
        assert!(JobKind::DerivedCatalog.is_latency_sensitive());
        assert!(!JobKind::AdminJob.is_latency_sensitive());
    }

    #[test]
    fn job_kind_display() {
        assert_eq!(format!("{}", JobKind::Scrub), "scrub");
        assert_eq!(format!("{}", JobKind::Other(99)), "other(99)");
    }

    // ── JobError ───────────────────────────────────────────────────────

    #[test]
    fn error_checkpoint_corrupt() {
        let e = JobError::CheckpointCorrupt {
            job_id: JobId(1),
            reason: "bad magic",
        };
        assert_eq!(e.job_id(), Some(JobId(1)));
        let s = format!("{e}");
        assert!(s.contains("checkpoint corrupt"));
        assert!(s.contains("bad magic"));
    }

    #[test]
    fn error_cursor_state_invalid() {
        let e = JobError::CursorStateInvalid {
            job_id: JobId(2),
            reason: "version mismatch",
        };
        assert_eq!(e.job_id(), Some(JobId(2)));
    }

    #[test]
    fn error_budget_exceeded() {
        let e = JobError::BudgetExceeded {
            job_id: JobId(3),
            budget: WorkBudget::DEFAULT_TICK,
            actual_items: 2048,
            actual_bytes: 0,
        };
        assert_eq!(e.job_id(), Some(JobId(3)));
        let s = format!("{e}");
        assert!(s.contains("budget exceeded"));
        assert!(s.contains("2048"));
    }

    #[test]
    fn error_job_already_complete() {
        let e = JobError::JobAlreadyComplete { job_id: JobId(4) };
        assert_eq!(e.job_id(), Some(JobId(4)));
        assert!(format!("{e}").contains("already complete"));
    }

    #[test]
    fn error_io_error() {
        let e = JobError::IoError {
            job_id: JobId(5),
            message: "disk full",
        };
        assert_eq!(e.job_id(), Some(JobId(5)));
        assert!(format!("{e}").contains("I/O error"));
        assert!(format!("{e}").contains("disk full"));
    }

    #[test]
    fn error_other() {
        let e = JobError::Other("custom error".into());
        assert_eq!(e.job_id(), None);
        assert!(format!("{e}").contains("custom error"));
    }

    #[test]
    fn error_display_all_variants_nonempty() {
        let errors: &[JobError] = &[
            JobError::CheckpointCorrupt {
                job_id: JobId(1),
                reason: "test",
            },
            JobError::CursorStateInvalid {
                job_id: JobId(2),
                reason: "test",
            },
            JobError::BudgetExceeded {
                job_id: JobId(3),
                budget: WorkBudget::DEFAULT_TICK,
                actual_items: 1,
                actual_bytes: 1,
            },
            JobError::JobAlreadyComplete { job_id: JobId(4) },
            JobError::IoError {
                job_id: JobId(5),
                message: "test",
            },
            JobError::Other("test".into()),
        ];
        for e in errors {
            let s = format!("{e}");
            assert!(!s.is_empty(), "empty display for {e:?}");
        }
    }

    // ── Integration tests ──────────────────────────────────────────────

    #[test]
    fn full_job_lifecycle_types() {
        let job_id = JobId(42);
        let kind = JobKind::BtreeCompaction;

        let ck = Checkpoint::new_initial(job_id, kind);
        assert!(ck.is_fresh());
        assert_eq!(ck.epoch, 1);

        let progress = JobProgress {
            items_processed: 256,
            items_total_estimate: 10240,
            bytes_processed: 4 * 1024 * 1024,
            elapsed_ms: 45,
            ..Default::default()
        };
        assert_eq!(progress.completion_permille(), 25);

        let step_ck = Checkpoint {
            job_id,
            job_kind: kind,
            epoch: 1,
            cursor_state: CursorState(vec![0xBE, 0xEF]),
            progress,
        };

        let result = StepResult::in_progress(step_ck.clone());
        assert!(!result.is_complete);
        assert_eq!(result.checkpoint.cursor_state.as_bytes(), &[0xBE, 0xEF]);

        let final_result = StepResult::complete(step_ck);
        assert!(final_result.is_complete);
    }

    #[test]
    fn budget_enforcement_scenario() {
        let budget = WorkBudget::DEFAULT_TICK;
        assert!(budget.items_within_budget(512));
        assert!(budget.bytes_within_budget(32 * 1024 * 1024));
        assert!(!budget.items_within_budget(2048));
    }

    #[test]
    fn all_job_kinds_have_labels() {
        let kinds = [
            JobKind::DeferredCleanup,
            JobKind::SnapshotDestroy,
            JobKind::GCMark,
            JobKind::BtreeCompaction,
            JobKind::Rebake,
            JobKind::JournalCleaning,
            JobKind::DatasetDestroy,
            JobKind::Scrub,
            JobKind::DeepScrub,
            JobKind::DerivedCatalog,
            JobKind::DataCleaner,
            JobKind::Defrag,
            JobKind::Resilver,
            JobKind::AdminJob,
            JobKind::Other(0),
        ];
        for k in &kinds {
            assert!(!k.label().is_empty(), "empty label for {k:?}");
        }
    }

    #[test]
    fn cursor_state_large_blob() {
        let big = vec![0u8; 1_000_000];
        let c = CursorState(big.clone());
        assert_eq!(c.len(), 1_000_000);
        let back: Vec<u8> = c.into();
        assert_eq!(back.len(), 1_000_000);
    }

    // ── IncrementalJob trait ──────────────────────────────────────────

    #[derive(Debug)]
    struct TestJob {
        id: JobId,
        kind: JobKind,
        epoch: u64,
        current: u64,
        remaining: u64,
        progress: JobProgress,
        complete_flag: bool,
    }

    impl IncrementalJob for TestJob {
        fn resume(checkpoint: Checkpoint) -> Result<Self, JobError> {
            let cursor: u64 = if checkpoint.is_fresh() {
                0
            } else if checkpoint.cursor_state.len() == 8 {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(checkpoint.cursor_state.as_bytes());
                u64::from_le_bytes(buf)
            } else {
                return Err(JobError::CursorStateInvalid {
                    job_id: checkpoint.job_id,
                    reason: "cursor must be 8 bytes",
                });
            };
            let remaining = 100u64.saturating_sub(cursor);
            Ok(TestJob {
                id: checkpoint.job_id,
                kind: checkpoint.job_kind,
                epoch: checkpoint.epoch,
                current: cursor,
                remaining,
                progress: checkpoint.progress,
                complete_flag: false,
            })
        }
        fn step(&mut self, budget: WorkBudget) -> StepResult {
            assert!(!self.complete_flag);
            let max = if budget.max_items == 0 {
                self.remaining
            } else {
                budget.max_items
            };
            let items = core::cmp::min(max, self.remaining);
            assert!(budget.items_within_budget(items));
            self.current += items;
            self.remaining -= items;
            self.progress.items_processed = self.progress.items_processed.saturating_add(items);
            self.progress.items_total_estimate = 100;
            let ck = self.persist_checkpoint();
            if self.remaining == 0 {
                self.complete_flag = true;
                StepResult::complete(ck)
            } else {
                StepResult::in_progress(ck)
            }
        }
        fn persist_checkpoint(&self) -> Checkpoint {
            Checkpoint {
                job_id: self.id,
                job_kind: self.kind,
                epoch: self.epoch,
                cursor_state: CursorState(self.current.to_le_bytes().to_vec()),
                progress: self.progress,
            }
        }
        fn complete(self) {
            assert!(self.complete_flag);
        }
        fn job_id(&self) -> JobId {
            self.id
        }
        fn job_kind(&self) -> JobKind {
            self.kind
        }
    }

    #[test]
    fn incremental_job_full_lifecycle() {
        let job_id = JobId(42);
        let mut job =
            TestJob::resume(Checkpoint::new_initial(job_id, JobKind::Scrub)).expect("resume");
        assert_eq!(job.job_id(), job_id);
        assert_eq!(job.job_kind(), JobKind::Scrub);
        let budget = WorkBudget {
            max_items: 10,
            max_bytes: 0,
            max_ms: 0,
        };
        let mut steps = 0u32;
        loop {
            let r = job.step(budget);
            steps += 1;
            if r.is_complete {
                assert_eq!(job.progress.items_processed, 100);
                job.complete();
                break;
            }
        }
        assert_eq!(steps, 10);
    }

    #[test]
    fn incremental_job_resume_from_checkpoint() {
        let ck = Checkpoint {
            job_id: JobId(99),
            job_kind: JobKind::GCMark,
            epoch: 1,
            cursor_state: CursorState(70u64.to_le_bytes().to_vec()),
            progress: JobProgress {
                items_processed: 70,
                items_total_estimate: 100,
                ..Default::default()
            },
        };
        let mut job = TestJob::resume(ck).expect("resume");
        assert_eq!(job.current, 70);
        assert_eq!(job.remaining, 30);
        let mut steps = 0u32;
        loop {
            let r = job.step(WorkBudget {
                max_items: 5,
                max_bytes: 0,
                max_ms: 0,
            });
            steps += 1;
            if r.is_complete {
                job.complete();
                break;
            }
        }
        assert_eq!(steps, 6);
    }

    #[test]
    fn incremental_job_invalid_cursor_error() {
        let ck = Checkpoint {
            job_id: JobId(1),
            job_kind: JobKind::BtreeCompaction,
            epoch: 1,
            cursor_state: CursorState(vec![0xAB]),
            progress: JobProgress::default(),
        };
        let err = TestJob::resume(ck).unwrap_err();
        assert!(matches!(err, JobError::CursorStateInvalid { .. }));
    }

    #[test]
    fn incremental_job_persist_checkpoint_roundtrip() {
        let mut job =
            TestJob::resume(Checkpoint::new_initial(JobId(7), JobKind::Resilver)).expect("resume");
        let r = job.step(WorkBudget {
            max_items: 42,
            max_bytes: 0,
            max_ms: 0,
        });
        assert!(!r.is_complete);
        let job2 = TestJob::resume(job.persist_checkpoint()).expect("resume");
        assert_eq!(job2.current, 42);
    }

    #[test]
    fn incremental_job_unbounded_budget() {
        let mut job = TestJob::resume(Checkpoint::new_initial(JobId(1), JobKind::DeferredCleanup))
            .expect("resume");
        let r = job.step(WorkBudget {
            max_items: 0,
            max_bytes: 0,
            max_ms: 0,
        });
        assert!(r.is_complete);
    }

    #[test]
    fn incremental_job_epoch_preserved() {
        let ck = Checkpoint {
            job_id: JobId(5),
            job_kind: JobKind::AdminJob,
            epoch: 7,
            cursor_state: CursorState::empty(),
            progress: JobProgress::default(),
        };
        let job = TestJob::resume(ck).expect("resume");
        assert_eq!(job.epoch, 7);
        assert_eq!(job.persist_checkpoint().epoch, 7);
    }
    // ── Serde roundtrip tests ─────────────────────────────────────────

    #[cfg(feature = "serde")]
    #[test]
    fn workbudget_serde_roundtrip() {
        let b = WorkBudget::DEFAULT_TICK;
        let json = serde_json::to_string(&b).unwrap();
        let b2: WorkBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(b, b2);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn jobprogress_serde_roundtrip() {
        let p = JobProgress {
            items_processed: 1024,
            items_total_estimate: 2048,
            bytes_processed: 4 * 1024 * 1024,
            bytes_total_estimate: 0,
            elapsed_ms: 50,
        };
        let json = serde_json::to_string(&p).unwrap();
        let p2: JobProgress = serde_json::from_str(&json).unwrap();
        assert_eq!(p, p2);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn jobid_serde_roundtrip() {
        let id = JobId(42);
        let json = serde_json::to_string(&id).unwrap();
        let id2: JobId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, id2);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn jobkind_serde_roundtrip() {
        let k = JobKind::BtreeCompaction;
        let json = serde_json::to_string(&k).unwrap();
        let k2: JobKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, k2);
    }

    #[cfg(all(feature = "serde", feature = "alloc"))]
    #[test]
    fn cursorstate_serde_roundtrip() {
        let c = CursorState(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let json = serde_json::to_string(&c).unwrap();
        let c2: CursorState = serde_json::from_str(&json).unwrap();
        assert_eq!(c, c2);
    }

    #[cfg(all(feature = "serde", feature = "alloc"))]
    #[test]
    fn checkpoint_serde_roundtrip() {
        let ck = Checkpoint::new_initial(JobId(7), JobKind::Scrub);
        let json = serde_json::to_string(&ck).unwrap();
        let ck2: Checkpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(ck, ck2);
    }

    #[cfg(all(feature = "serde", feature = "alloc"))]
    #[test]
    fn stepresult_serde_roundtrip() {
        let ck = Checkpoint::new_initial(JobId(7), JobKind::Scrub);
        let sr = StepResult::in_progress(ck);
        let json = serde_json::to_string(&sr).unwrap();
        let sr2: StepResult = serde_json::from_str(&json).unwrap();
        assert_eq!(sr, sr2);
    }

    // ── IncrementalJob mock implementation ─────────────────────────────

    /// Minimal IncrementalJob implementation for testing the trait contract.
    #[derive(Debug)]
    struct MockScanJob {
        id: JobId,
        kind: JobKind,
        total_items: u64,
        processed: u64,
        cursor_bytes: Vec<u8>,
    }

    impl MockScanJob {
        fn encode_cursor(processed: u64) -> Vec<u8> {
            processed.to_le_bytes().to_vec()
        }

        fn decode_cursor(bytes: &[u8]) -> Option<u64> {
            if bytes.len() != 8 {
                return None;
            }
            let mut arr = [0u8; 8];
            arr.copy_from_slice(bytes);
            Some(u64::from_le_bytes(arr))
        }
    }

    impl IncrementalJob for MockScanJob {
        fn resume(checkpoint: Checkpoint) -> Result<Self, JobError> {
            if checkpoint.cursor_state.is_empty() {
                return Ok(MockScanJob {
                    id: checkpoint.job_id,
                    kind: checkpoint.job_kind,
                    total_items: 1000,
                    processed: 0,
                    cursor_bytes: Vec::new(),
                });
            }
            let processed = Self::decode_cursor(checkpoint.cursor_state.as_bytes()).ok_or(
                JobError::CursorStateInvalid {
                    job_id: checkpoint.job_id,
                    reason: "invalid cursor length",
                },
            )?;
            Ok(MockScanJob {
                id: checkpoint.job_id,
                kind: checkpoint.job_kind,
                total_items: 1000,
                processed,
                cursor_bytes: checkpoint.cursor_state.into(),
            })
        }

        fn step(&mut self, budget: WorkBudget) -> StepResult {
            let remaining = self.total_items - self.processed;
            let max_items = if budget.max_items == 0 {
                remaining
            } else {
                budget.max_items.min(remaining)
            };
            let batch = max_items.min(100);
            self.processed += batch;
            self.cursor_bytes = Self::encode_cursor(self.processed);

            let progress = JobProgress {
                items_processed: batch,
                items_total_estimate: self.total_items,
                bytes_processed: batch * 4096,
                bytes_total_estimate: self.total_items * 4096,
                elapsed_ms: 10,
            };
            let ck = Checkpoint {
                job_id: self.id,
                job_kind: self.kind,
                epoch: 1,
                cursor_state: CursorState(self.cursor_bytes.clone()),
                progress,
            };
            if self.processed >= self.total_items {
                StepResult::complete(ck)
            } else {
                StepResult::in_progress(ck)
            }
        }

        fn persist_checkpoint(&self) -> Checkpoint {
            Checkpoint {
                job_id: self.id,
                job_kind: self.kind,
                epoch: 1,
                cursor_state: CursorState(self.cursor_bytes.clone()),
                progress: JobProgress {
                    items_processed: self.processed,
                    items_total_estimate: self.total_items,
                    bytes_processed: self.processed * 4096,
                    bytes_total_estimate: self.total_items * 4096,
                    elapsed_ms: self.processed * 10 / 100,
                },
            }
        }

        fn complete(self) {
            // no-op for mock
        }

        fn job_id(&self) -> JobId {
            self.id
        }

        fn job_kind(&self) -> JobKind {
            self.kind
        }
    }

    // ── IncrementalJob lifecycle tests ─────────────────────────────────

    #[test]
    fn trait_fresh_start_creates_job() {
        let ck = Checkpoint::new_initial(JobId(1), JobKind::Scrub);
        let job = MockScanJob::resume(ck).unwrap();
        assert_eq!(job.job_id(), JobId(1));
        assert_eq!(job.job_kind(), JobKind::Scrub);
        assert_eq!(job.processed, 0);
    }

    #[test]
    fn trait_step_makes_progress() {
        let ck = Checkpoint::new_initial(JobId(2), JobKind::GCMark);
        let mut job = MockScanJob::resume(ck).unwrap();
        let result = job.step(WorkBudget::DEFAULT_TICK);
        assert!(!result.is_complete);
        assert_eq!(result.checkpoint.progress.items_processed, 100);
    }

    #[test]
    fn trait_step_respects_budget() {
        let ck = Checkpoint::new_initial(JobId(3), JobKind::BtreeCompaction);
        let mut job = MockScanJob::resume(ck).unwrap();
        let budget = WorkBudget {
            max_items: 1,
            ..WorkBudget::default()
        };
        let result = job.step(budget);
        assert!(!result.is_complete);
        assert_eq!(result.checkpoint.progress.items_processed, 1);
    }

    #[test]
    fn trait_completes_after_full_scan() {
        let ck = Checkpoint::new_initial(JobId(4), JobKind::DeepScrub);
        let mut job = MockScanJob::resume(ck).unwrap();
        for _ in 0..20 {
            let result = job.step(WorkBudget::UNBOUNDED);
            if result.is_complete {
                return;
            }
        }
        panic!("job did not complete within expected steps");
    }

    #[test]
    fn trait_resume_from_checkpoint() {
        let ck = Checkpoint::new_initial(JobId(5), JobKind::DeferredCleanup);
        let mut job = MockScanJob::resume(ck).unwrap();
        let _ = job.step(WorkBudget::DEFAULT_TICK);
        let _ = job.step(WorkBudget::DEFAULT_TICK);
        let _ = job.step(WorkBudget::DEFAULT_TICK);
        let saved = job.persist_checkpoint();
        assert_eq!(saved.progress.items_processed, 300);

        let mut job2 = MockScanJob::resume(saved).unwrap();
        assert_eq!(job2.processed, 300);
        assert_eq!(job2.job_id(), JobId(5));

        let result = job2.step(WorkBudget::DEFAULT_TICK);
        assert_eq!(result.checkpoint.progress.items_processed, 100);
    }

    #[test]
    fn trait_resume_invalid_cursor_errors() {
        let ck = Checkpoint {
            job_id: JobId(6),
            job_kind: JobKind::Scrub,
            epoch: 1,
            cursor_state: CursorState(vec![0xBA, 0xD]),
            progress: JobProgress::default(),
        };
        let err = MockScanJob::resume(ck).unwrap_err();
        assert!(matches!(err, JobError::CursorStateInvalid { .. }));
    }

    #[test]
    fn trait_unbounded_budget_runs_freely() {
        let ck = Checkpoint::new_initial(JobId(7), JobKind::Resilver);
        let mut job = MockScanJob::resume(ck).unwrap();
        let result = job.step(WorkBudget::UNBOUNDED);
        assert_eq!(result.checkpoint.progress.items_processed, 100);
    }

    #[test]
    fn trait_paused_budget_is_recognized() {
        let ck = Checkpoint::new_initial(JobId(8), JobKind::AdminJob);
        let mut job = MockScanJob::resume(ck).unwrap();
        let result = job.step(WorkBudget::PAUSED);
        assert!(!result.is_complete);
    }

    #[test]
    fn trait_persist_checkpoint_reflects_state() {
        let ck = Checkpoint::new_initial(JobId(9), JobKind::JournalCleaning);
        let mut job = MockScanJob::resume(ck).unwrap();
        let step1 = job.step(WorkBudget::DEFAULT_TICK);
        let persisted = job.persist_checkpoint();
        assert_eq!(persisted.progress.items_processed, 100);
        assert_eq!(step1.checkpoint.progress.items_processed, 100);
    }

    #[test]
    fn trait_job_id_consistent() {
        let ck = Checkpoint::new_initial(JobId(99), JobKind::SnapshotDestroy);
        let job = MockScanJob::resume(ck).unwrap();
        assert_eq!(job.job_id(), JobId(99));
    }

    #[test]
    fn trait_job_kind_consistent() {
        let ck = Checkpoint::new_initial(JobId(10), JobKind::DatasetDestroy);
        let job = MockScanJob::resume(ck).unwrap();
        assert_eq!(job.job_kind(), JobKind::DatasetDestroy);
    }

    #[test]
    fn trait_complete_is_idempotent_safe() {
        let ck = Checkpoint::new_initial(JobId(11), JobKind::Rebake);
        let job = MockScanJob::resume(ck).unwrap();
        job.complete();
    }

    // ── Dispatch record types ─────────────────────────────────────────

    #[test]
    fn scheduler_epoch_advances_monotonically() {
        let e0 = SchedulerEpoch::INITIAL;
        assert_eq!(e0.0, 0);
        let e1 = e0.next();
        assert_eq!(e1.0, 1);
        assert!(e1.is_successor_of(e0));
        assert!(!e0.is_successor_of(e1));
    }

    #[test]
    fn scheduler_epoch_default_is_initial() {
        let e: SchedulerEpoch = Default::default();
        assert_eq!(e, SchedulerEpoch::INITIAL);
    }

    #[test]
    fn dispatch_record_id_equality() {
        let a = DispatchRecordId(1);
        let b = DispatchRecordId(1);
        let c = DispatchRecordId(2);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn dispatch_state_terminal_and_resumable() {
        assert!(!DispatchState::Pending.is_terminal());
        assert!(DispatchState::Pending.is_resumable());
        assert!(!DispatchState::InProgress.is_terminal());
        assert!(DispatchState::InProgress.is_resumable());
        assert!(DispatchState::Completed.is_terminal());
        assert!(!DispatchState::Completed.is_resumable());
        assert!(DispatchState::Cancelled.is_terminal());
        assert!(!DispatchState::Cancelled.is_resumable());
    }

    #[test]
    fn dispatch_record_new_is_pending() {
        let rec = DispatchRecord::new(
            JobId(42),
            JobKind::Scrub,
            SchedulerEpoch(1),
            DispatchRecordId(100),
            12345,
        );
        assert_eq!(rec.job_id, JobId(42));
        assert_eq!(rec.job_kind, JobKind::Scrub);
        assert_eq!(rec.epoch, SchedulerEpoch(1));
        assert_eq!(rec.dispatch_id, DispatchRecordId(100));
        assert_eq!(rec.state, DispatchState::Pending);
        assert_eq!(rec.created_at_ms, 12345);
        assert!(rec.last_checkpoint.is_none());
        assert!(rec.can_resume());
    }

    #[test]
    fn dispatch_record_lifecycle_transitions() {
        let mut rec = DispatchRecord::new(
            JobId(1),
            JobKind::DeferredCleanup,
            SchedulerEpoch(0),
            DispatchRecordId(1),
            0,
        );
        assert_eq!(rec.state, DispatchState::Pending);
        rec.mark_in_progress();
        assert_eq!(rec.state, DispatchState::InProgress);
        assert!(rec.can_resume());
        rec.mark_completed();
        assert_eq!(rec.state, DispatchState::Completed);
        assert!(!rec.can_resume());
    }

    #[test]
    fn dispatch_record_cancellation() {
        let mut rec = DispatchRecord::new(
            JobId(2),
            JobKind::GCMark,
            SchedulerEpoch(3),
            DispatchRecordId(7),
            0,
        );
        rec.mark_in_progress();
        rec.mark_cancelled();
        assert_eq!(rec.state, DispatchState::Cancelled);
        assert!(rec.state.is_terminal());
        assert!(!rec.can_resume());
    }

    #[test]
    fn dispatch_record_checkpoint_update() {
        let mut rec = DispatchRecord::new(
            JobId(3),
            JobKind::BtreeCompaction,
            SchedulerEpoch(1),
            DispatchRecordId(5),
            0,
        );
        let cp = Checkpoint::new_initial(JobId(3), JobKind::BtreeCompaction);
        rec.update_checkpoint(cp.clone());
        assert_eq!(rec.last_checkpoint, Some(cp));
    }

    #[test]
    fn dispatch_record_display_nonempty() {
        let rec = DispatchRecord::new(
            JobId(1),
            JobKind::Scrub,
            SchedulerEpoch(0),
            DispatchRecordId(1),
            0,
        );
        assert!(!format!("{rec}").is_empty());
    }

    #[test]
    fn dispatch_state_display_nonempty() {
        for state in &[
            DispatchState::Pending,
            DispatchState::InProgress,
            DispatchState::Completed,
            DispatchState::Cancelled,
        ] {
            assert!(!format!("{state}").is_empty());
        }
    }

    #[test]
    fn dispatch_record_id_display_nonempty() {
        assert!(!format!("{}", DispatchRecordId(0)).is_empty());
    }

    #[test]
    fn scheduler_epoch_display_nonempty() {
        assert!(!format!("{}", SchedulerEpoch::INITIAL).is_empty());
    }
}
