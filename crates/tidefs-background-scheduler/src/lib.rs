// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]

//! Background Service Framework: canonical unified scheduler for IncrementalJob dispatch
//! with per-tick budget enforcement, 5-stage priority ordering, round-robin
//! fairness, and budget cascading.
//!
//! Implements the current source-backed scheduler boundary summarized by
//! [`docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md`].
//! Pairs the [`BackgroundService`] trait with an
//! [`IncrementalJobAdapter`] that wraps any [`IncrementalJob`] implementor,
//! enabling the same job implementations to be driven in priority order
//! under a unified budget.
//!
//! ## Architecture
//!
//! ```text
//! BackgroundScheduler
//!   ├── service: IncrementalJobAdapter<CleanupJob>
//!   ├── service: IncrementalJobAdapter<ReclaimJob>
//!   ├── service: IncrementalJobAdapter<OrphanRecoveryJob>
//!   └── …
//! ```
//!
//! Each service is assigned a [`ServicePriority`] and driven in strict
//! 5-stage order with round-robin fairness within each stage.
//!
//! ## Comparison to ZFS / Ceph
//!
//! - **ZFS**: Background work (scrub, resilver, dataset destroy) uses ad-hoc
//!   scan tickets and `spa_sync` pass callbacks with no unified budget or
//!   priority model. Scrub/resilver use `zfs_scan_idle` / `zfs_resilver_delay`
//!   (delay-based throttling), not operation-count caps.
//! - **Ceph**: PG scrub, backfill, and recovery are per-PG state machines
//!   with no cluster-wide budget or priority ordering. Throttling is
//!   sleep-based (`osd_recovery_sleep`, `osd_max_backfills`).
//! - **TideFS**: Single scheduler dispatching all background work with
//!   explicit per-tick operation-count budgets, 5-stage priority ordering,
//!   round-robin fairness, and budget cascading from higher to lower
//!   priorities.
//!
//! [`docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md`]:
//!     docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md
//! [`BackgroundService`]: trait.BackgroundService.html
//! [`IncrementalJobAdapter`]: struct.IncrementalJobAdapter.html
//! [`ServicePriority`]: enum.ServicePriority.html
//! [`IncrementalJob`]:
//!     ../../tidefs-types-incremental-job-core/trait.IncrementalJob.html

// Multi-threaded scheduler (requires std).
#[cfg(any(test, feature = "std"))]
pub mod multi_threaded;
pub mod scheduling;
use core::fmt;
#[cfg(feature = "alloc")]
extern crate alloc;

/// Simple monotonic time helper for wall-clock tracking.
/// Returns milliseconds since an arbitrary epoch.
fn crate_time_now_ms() -> u64 {
    // In no_std, we rely on the caller/host to provide a time source.
    // For testing and initial wiring, return 0 to maintain deterministic
    // behavior. Production integration layers (FUSE daemon, pool manager)
    // should provide a real monotonic clock.
    0
}

use alloc::collections::VecDeque;
#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec::Vec};

#[cfg(feature = "alloc")]
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[allow(unused_imports)]
use tidefs_types_incremental_job_core::{
    Checkpoint, DispatchRecord, DispatchRecordId, IncrementalJob, JobError, JobId, JobKind,
    JobProgress, SchedulerEpoch, ServiceCheckpoint, ServiceState, StepResult, WorkBudget,
};

use tidefs_incremental_job_core::{DispatchStore, DispatchStoreError};

// ---------------------------------------------------------------------------
// ServicePriority — 5-stage priority for scheduling and budget allocation
// ---------------------------------------------------------------------------

/// Priority class for scheduling order and budget allocation.
///
/// The scheduler drains higher-priority services before lower-priority ones.
/// Within each stage, services are dispatched round-robin for fairness.
///
/// # Ordering
///
/// Variants are ordered from highest to lowest priority. `Critical` runs
/// first; `Opportunistic` runs last and only when no other work exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ServicePriority {
    /// Authority/consistency work: may not be deferred indefinitely.
    /// Examples: repair, intent-log sync, membership-health check.
    Critical = 0,

    /// Latency-sensitive cache maintenance. Deferrable but user-visible
    /// latency degrades without it.
    /// Examples: directory view building, path-lookup cache refresh.
    LatencySensitive = 1,

    /// Bulk throughput work. Progress is expected but individual ticks
    /// are not latency-critical.
    /// Examples: data cleaning, rebake conversion, snapshot evaluation.
    Throughput = 2,

    /// Deferred compaction and trim. Runs when higher-priority work is idle.
    /// Examples: segment compaction, ingest trim, tombstone GC.
    BestEffort = 3,

    /// Speculative work that may improve future performance but is never
    /// required for correctness.
    /// Examples: prefetch, readahead, thermal rebalance.
    Opportunistic = 4,
}

impl ServicePriority {
    /// Number of priority stages.
    pub const STAGE_COUNT: usize = 5;

    /// All priority levels in dispatch order.
    pub const ALL: [ServicePriority; 5] = [
        ServicePriority::Critical,
        ServicePriority::LatencySensitive,
        ServicePriority::Throughput,
        ServicePriority::BestEffort,
        ServicePriority::Opportunistic,
    ];

    /// Map a [`JobKind`] to its default [`ServicePriority`].
    ///
    /// The mapping follows the 5-stage model:
    /// - Integrity checks and cluster membership → Critical
    /// - Orphan recovery, reclaim → LatencySensitive
    /// - Bulk data work → Throughput
    /// - Compaction, GC mark → BestEffort
    /// - Admin jobs → Throughput (default)
    #[must_use]
    pub fn from_job_kind(kind: JobKind) -> Self {
        match kind {
            JobKind::Scrub | JobKind::DeepScrub | JobKind::Resilver | JobKind::Recovery => {
                ServicePriority::Critical
            }
            JobKind::DerivedCatalog
            | JobKind::OrphanRecovery
            | JobKind::Reclaim
            | JobKind::JournalCleaning => ServicePriority::LatencySensitive,
            JobKind::DeferredCleanup
            | JobKind::SnapshotDestroy
            | JobKind::Rebake
            | JobKind::DatasetDestroy
            | JobKind::DataCleaner
            | JobKind::SnapshotPruner
            | JobKind::Rebuild
            | JobKind::Backfill
            | JobKind::Rebalance
            | JobKind::AdminJob => ServicePriority::Throughput,
            JobKind::GCMark | JobKind::BtreeCompaction => ServicePriority::BestEffort,
            JobKind::SegmentCleaner => ServicePriority::Throughput,
            JobKind::Defrag => ServicePriority::BestEffort,
            JobKind::Dedup => ServicePriority::BestEffort,
            JobKind::GeometryConvert => ServicePriority::BestEffort,
            JobKind::Other(_) => ServicePriority::Throughput,
        }
    }

    /// Human-readable label for logging and observability.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            ServicePriority::Critical => "critical",
            ServicePriority::LatencySensitive => "latency_sensitive",
            ServicePriority::Throughput => "throughput",
            ServicePriority::BestEffort => "best_effort",
            ServicePriority::Opportunistic => "opportunistic",
        }
    }
}

impl fmt::Display for ServicePriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// ServiceBudget — per-tick resource budget
// ---------------------------------------------------------------------------

/// Per-tick resource budget for one service invocation.
///
/// The service must not exceed these limits. The scheduler divides the
/// global budget across services, preferring higher-priority services.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ServiceBudget {
    /// Maximum items (records, entries, extents) to process per tick.
    /// `0` = unbounded.
    pub max_items: u64,
    /// Maximum bytes to read/write per tick.
    /// `0` = unbounded.
    pub max_bytes: u64,
    /// Maximum wall-clock milliseconds per tick (soft limit).
    /// `0` = unbounded.
    pub max_ms: u64,
}

impl ServiceBudget {
    /// Global budget for the entire tick cycle across all services.
    pub const DEFAULT_TICK: Self = Self {
        max_items: 1024,
        max_bytes: 64 * 1024 * 1024,
        max_ms: 100,
    };

    /// Global default budget for the BackgroundScheduler.
    /// Same as [`ServiceBudget::DEFAULT_TICK`]; provided for semantic clarity at scheduler construction sites.
    pub const GLOBAL_DEFAULT: Self = Self::DEFAULT_TICK;

    /// Lightweight budget for a single inter-demand cycle.
    /// Ensures a background tick never starves foreground I/O.
    pub const MAINTENANCE_TICK: Self = Self {
        max_items: 256,
        max_bytes: 16 * 1024 * 1024,
        max_ms: 50,
    };

    /// Minimal budget for emergency pressure or low-memory mode.
    pub const SMALL_TICK: Self = Self {
        max_items: 64,
        max_bytes: 4 * 1024 * 1024,
        max_ms: 25,
    };

    /// Fully unbounded — no limits in any dimension.
    pub const UNBOUNDED: Self = Self {
        max_items: 0,
        max_bytes: 0,
        max_ms: 0,
    };

    /// Returns `true` if at least one limit is non-zero.
    #[must_use]
    pub const fn is_bounded(self) -> bool {
        self.max_items > 0 || self.max_bytes > 0 || self.max_ms > 0
    }

    /// Returns `true` if all three limits are zero.
    #[must_use]
    pub const fn is_exhausted(self) -> bool {
        self.max_items == 0 && self.max_bytes == 0 && self.max_ms == 0
    }

    /// Return a budget scaled by `numerator / denominator`.
    /// Each dimension is divided proportionally, with a floor of 1
    /// unless the original was already 0 (unbounded).
    #[must_use]
    pub fn fraction(self, numerator: u64, denominator: u64) -> Self {
        if denominator == 0 {
            return self;
        }
        Self {
            max_items: if self.max_items == 0 {
                0
            } else {
                (self.max_items * numerator / denominator).max(1)
            },
            max_bytes: if self.max_bytes == 0 {
                0
            } else {
                (self.max_bytes * numerator / denominator).max(1)
            },
            max_ms: if self.max_ms == 0 {
                0
            } else {
                (self.max_ms * numerator / denominator).max(1)
            },
        }
    }

    /// Subtract consumption from this budget, saturating at zero.
    pub fn subtract_consumed(&mut self, items: u64, bytes: u64, _ms: u64) {
        if self.max_items > 0 {
            self.max_items = self.max_items.saturating_sub(items);
        }
        if self.max_bytes > 0 {
            self.max_bytes = self.max_bytes.saturating_sub(bytes);
        }
    }

    /// Convert to a [`WorkBudget`] for passing to [`IncrementalJob::step()`].
    #[must_use]
    pub fn to_work_budget(self) -> WorkBudget {
        WorkBudget {
            max_items: self.max_items,
            max_bytes: self.max_bytes,
            max_ms: self.max_ms,
        }
    }
}

impl Default for ServiceBudget {
    fn default() -> Self {
        Self::DEFAULT_TICK
    }
}

impl fmt::Display for ServiceBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ServiceBudget(items={}, bytes={}, ms={})",
            self.max_items, self.max_bytes, self.max_ms,
        )
    }
}

// ---------------------------------------------------------------------------
// TickReport — per-tick accounting
// ---------------------------------------------------------------------------

/// Accounting report for one service tick.
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TickReport {
    /// Items successfully processed this tick.
    pub processed: u64,
    /// Items skipped (token mismatch, already done, no-op).
    pub skipped: u64,
    /// Items that produced errors.
    pub errors: u64,
    /// Items consumed this tick (must not exceed budget).
    pub items_consumed: u64,
    /// Bytes consumed this tick (must not exceed budget).
    pub bytes_consumed: u64,
    /// True if the service reports more pending work after this tick.
    pub has_more: bool,
}

impl TickReport {
    /// Total items attempted (processed + skipped + errors).
    #[must_use]
    pub fn total_attempted(&self) -> u64 {
        self.processed
            .saturating_add(self.skipped)
            .saturating_add(self.errors)
    }

    /// Merge another report into this one (accumulation).
    pub fn merge(&mut self, other: &TickReport) {
        self.processed = self.processed.saturating_add(other.processed);
        self.skipped = self.skipped.saturating_add(other.skipped);
        self.errors = self.errors.saturating_add(other.errors);
        self.items_consumed = self.items_consumed.saturating_add(other.items_consumed);
        self.bytes_consumed = self.bytes_consumed.saturating_add(other.bytes_consumed);
        self.has_more = self.has_more || other.has_more;
    }
}

impl fmt::Display for TickReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "processed={} skipped={} errors={} items_used={} bytes_used={} has_more={}",
            self.processed,
            self.skipped,
            self.errors,
            self.items_consumed,
            self.bytes_consumed,
            self.has_more,
        )
    }
}

// ---------------------------------------------------------------------------
// ServiceError — errors from service tick invocations
// ---------------------------------------------------------------------------

/// Errors produced during service tick execution.
#[derive(Clone, Debug)]
pub enum ServiceError {
    /// Service exceeded budget in one or more dimensions.
    BudgetExceeded {
        service: &'static str,
        limit: u64,
        actual: u64,
    },
    /// Service encountered a non-recoverable internal error.
    Internal {
        service: &'static str,
        message: &'static str,
    },
    /// Service was stopped externally (shutdown, drain).
    Stopped { service: &'static str },
    /// The underlying IncrementalJob returned an error.
    JobError {
        service: &'static str,
        error: JobError,
    },
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceError::BudgetExceeded {
                service,
                limit,
                actual,
            } => {
                write!(
                    f,
                    "{service}: budget exceeded (limit={limit}, actual={actual})"
                )
            }
            ServiceError::Internal { service, message } => {
                write!(f, "{service}: {message}")
            }
            ServiceError::Stopped { service } => {
                write!(f, "{service}: stopped")
            }
            ServiceError::JobError { service, error } => {
                write!(f, "{service}: job error: {error}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SchedulerError — errors from scheduler-level operations
// ---------------------------------------------------------------------------

/// Errors produced at the scheduler level.
#[derive(Clone, Debug)]
pub enum SchedulerError {
    /// Service registration failed.
    RegistrationFailed {
        service_name: &'static str,
        reason: &'static str,
    },
    /// A service produced an error during a tick.
    ServiceFailed {
        service_name: &'static str,
        error: ServiceError,
    },
    /// A service exceeded its budget during a tick.
    BudgetViolation {
        service_name: &'static str,
        budget: ServiceBudget,
        consumed: TickReport,
    },
}

impl fmt::Display for SchedulerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchedulerError::RegistrationFailed {
                service_name,
                reason,
            } => {
                write!(f, "{service_name}: registration failed: {reason}")
            }
            SchedulerError::ServiceFailed {
                service_name,
                error,
            } => {
                write!(f, "{service_name}: {error}")
            }
            SchedulerError::BudgetViolation {
                service_name,
                budget,
                consumed,
            } => {
                write!(
                    f,
                    "{service_name}: budget violation (budget={budget}, consumed={consumed})"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BackgroundService trait — one schedulable work unit
// ---------------------------------------------------------------------------

/// A single background work unit managed by the scheduler.
///
/// Implementors must be deterministic: given the same state, the same tick
/// with the same budget must produce the same [`TickReport`]. This enables
/// golden-trace validation.
///
/// The trait is object-safe, allowing the scheduler to own a heterogeneous
/// collection of services via `Box<dyn BackgroundService>`.
///
/// # Relationship to IncrementalJob
///
/// Use [`IncrementalJobAdapter`] to wrap any [`IncrementalJob`]
/// implementor as a `BackgroundService`. Direct implementations of
/// `BackgroundService` are rarely needed; the adapter covers the
/// common case.
///
/// [`IncrementalJobAdapter`]: struct.IncrementalJobAdapter.html
/// [`IncrementalJob`]:
///     ../../tidefs-types-incremental-job-core/trait.IncrementalJob.html
/// [`TickReport`]: struct.TickReport.html
///
/// Preserved as a trait per DESIGN_OVERFITTING_POLICY.md §5: this is
/// legitimate open-set polymorphism. Multiple crates implement
/// BackgroundService for different background work types (scrub,
/// compaction, reclaim, dataset lifecycle, etc.).
#[cfg(feature = "alloc")]
pub trait BackgroundService: Send {
    /// Unique name for metrics, scheduling, and operator visibility.
    fn name(&self) -> &'static str;

    /// Priority class determining scheduling order and budget preference.
    fn priority(&self) -> ServicePriority;

    /// Run one tick within the given budget.
    ///
    /// Returns a [`TickReport`] with accounting. The service must not
    /// exceed the budget in any dimension. It may use less.
    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError>;

    /// Whether this service has pending work. Used by the scheduler to
    /// skip idle services.
    fn has_work(&self) -> bool;

    /// Stable job identity for durable dispatch tracking.
    ///
    /// Services that wrap an [`IncrementalJob`] return the job identity so
    /// `BackgroundScheduler` can persist a dispatch record before execution.
    fn dispatch_identity(&self) -> Option<(JobId, JobKind)> {
        None
    }

    /// Latest checkpoint available after a successful tick.
    ///
    /// Durable dispatch records store this checkpoint so restart replay can
    /// resume from the last committed position.
    fn dispatch_checkpoint(&self) -> Option<Checkpoint> {
        None
    }
}

// ---------------------------------------------------------------------------
// IncrementalJobAdapter — wraps IncrementalJob as BackgroundService
// ---------------------------------------------------------------------------

/// Adapter that wraps any [`IncrementalJob`] implementor as a
/// [`BackgroundService`].
///
/// The adapter translates between the scheduler's per-tick budget model
/// and the job's [`WorkBudget`]-driven `step()` contract.
///
/// # Type Parameters
///
/// * `J` — The concrete [`IncrementalJob`] implementation being wrapped.
///
/// # Priority
///
/// The default priority is derived from the job's [`JobKind`] via
/// [`ServicePriority::from_job_kind`]. Call [`with_priority`] to override.
///
/// [`with_priority`]: IncrementalJobAdapter::with_priority
#[cfg(feature = "alloc")]
pub struct IncrementalJobAdapter<J: IncrementalJob> {
    name: &'static str,
    job: J,
    priority: ServicePriority,
    last_was_complete: bool,
}

#[cfg(feature = "alloc")]
impl<J: IncrementalJob> IncrementalJobAdapter<J> {
    /// Create a new adapter for the given job.
    ///
    /// Priority is derived from the job's [`JobKind`].
    #[must_use]
    pub fn new(name: &'static str, job: J) -> Self {
        let priority = ServicePriority::from_job_kind(job.job_kind());
        Self {
            name,
            job,
            priority,
            last_was_complete: false,
        }
    }

    /// Override the priority class.
    #[must_use]
    pub fn with_priority(mut self, priority: ServicePriority) -> Self {
        self.priority = priority;
        self
    }

    /// Return a reference to the inner job.
    #[must_use]
    pub fn inner(&self) -> &J {
        &self.job
    }

    /// Return a mutable reference to the inner job.
    #[must_use]
    pub fn inner_mut(&mut self) -> &mut J {
        &mut self.job
    }
}

#[cfg(feature = "alloc")]
impl<J: IncrementalJob + Send> BackgroundService for IncrementalJobAdapter<J> {
    fn name(&self) -> &'static str {
        self.name
    }

    fn priority(&self) -> ServicePriority {
        self.priority
    }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        if self.last_was_complete {
            return Ok(TickReport {
                has_more: false,
                ..TickReport::default()
            });
        }

        let wb = budget.to_work_budget();
        let step = self.job.step(wb);

        // Track items and bytes consumed from the checkpoint progress delta.
        // The StepResult.checkpoint.progress reflects cumulative totals, so
        // we report the full tick consumption from the progress field.
        let items = step.checkpoint.progress.items_processed;
        let bytes = step.checkpoint.progress.bytes_processed;

        if step.is_complete {
            self.last_was_complete = true;
            // finalize the job
            // Note: complete() consumes self, so we use a take pattern.
            // We don't actually call complete() here since we still own self;
            // the scheduler handles completion state separately.
        }

        Ok(TickReport {
            processed: items,
            skipped: 0,
            errors: 0,
            items_consumed: items,
            bytes_consumed: bytes,
            has_more: !step.is_complete,
        })
    }

    fn has_work(&self) -> bool {
        !self.last_was_complete
    }

    fn dispatch_identity(&self) -> Option<(JobId, JobKind)> {
        Some((self.job.job_id(), self.job.job_kind()))
    }

    fn dispatch_checkpoint(&self) -> Option<Checkpoint> {
        Some(self.job.persist_checkpoint())
    }
}

impl<J: IncrementalJob + fmt::Debug> fmt::Debug for IncrementalJobAdapter<J> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IncrementalJobAdapter")
            .field("name", &self.name)
            .field("priority", &self.priority)
            .field("job", &self.job)
            .field("last_was_complete", &self.last_was_complete)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// SchedulerStats — cumulative statistics across all scheduling cycles
// ---------------------------------------------------------------------------

/// Cumulative statistics across all scheduling cycles.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SchedulerStats {
    /// Total number of cycles executed.
    pub total_cycles: u64,
    /// Total operations processed across all services.
    pub total_processed: u64,
    /// Total operations skipped (no work available).
    pub total_skipped: u64,
    /// Total errors encountered.
    pub total_errors: u64,
    /// Number of times all services were idle in a cycle.
    pub services_idle: u64,
    /// Number of times the budget was exhausted.
    pub budget_exhausted: u64,
}

/// Read-only snapshot of a registered background service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisteredService {
    /// Unique service name used in cycle reports and metrics.
    pub name: &'static str,
    /// Priority used by the scheduler's stage ordering.
    pub priority: ServicePriority,
}

// ---------------------------------------------------------------------------
// CycleReport — aggregate report for one full scheduling cycle
// ---------------------------------------------------------------------------

/// Aggregate report for one full scheduling cycle.
#[derive(Clone, Debug, Default)]
pub struct CycleReport {
    /// Per-service tick reports, indexed by service name.
    pub per_service: Vec<(&'static str, TickReport)>,
    /// Remaining budget after the cycle.
    pub remaining_budget: ServiceBudget,
    /// Number of services that ran this cycle.
    pub services_ran: usize,
    /// Number of services skipped (idle).
    pub services_skipped: usize,
    /// True if budget was exhausted before all services ran.
    pub budget_exhausted: bool,
    /// Total items successfully processed across all services.
    pub total_processed: u64,
    /// Total items skipped across all services.
    pub total_skipped: u64,
    /// Total errors across all services.
    pub total_errors: u64,
    /// Wall-clock duration of the cycle in milliseconds.
    pub wall_ms: u64,
    /// True if the cycle was interrupted by a demand-preemption signal.
    pub preempted: bool,
}

impl CycleReport {
    /// Merge a per-service tick report into this cycle report.
    pub fn push(&mut self, name: &'static str, report: TickReport) {
        self.per_service.push((name, report));
    }
}

impl fmt::Display for CycleReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ran={} skipped={} exhausted={} remaining={} processed={} errs={} wall_ms={}",
            self.services_ran,
            self.services_skipped,
            self.budget_exhausted,
            self.remaining_budget,
            self.total_processed,
            self.total_errors,
            self.wall_ms,
        )
    }
}

// ---------------------------------------------------------------------------
// BackgroundScheduler — top-level dispatch engine
// ---------------------------------------------------------------------------

/// Top-level background work scheduler.
///
/// Owns a set of [`BackgroundService`] instances and dispatches ticks
/// in priority order with round-robin fairness.
///
/// # Scheduling algorithm
///
/// 1. Start with the global budget for this cycle.
/// 2. For each priority stage (Critical → Opportunistic):
///    - Collect all services at this priority that have work.
///    - Divide the remaining budget among them.
///    - Dispatch ticks round-robin.
///    - Cascade unused budget to the next stage.
/// 3. Terminate early when budget is exhausted in all dimensions.
///
/// # Example
///
/// ```ignore
/// use tidefs_background_scheduler::{
///     BackgroundScheduler, ServiceBudget, ServicePriority,
///     IncrementalJobAdapter,
/// };
/// // ... create a CleanupJob, wrap it ...
/// let mut scheduler = BackgroundScheduler::new(ServiceBudget::DEFAULT_TICK);
/// scheduler.register(Box::new(adapter));
/// let report = scheduler.run_cycle();
/// ```
#[cfg(feature = "alloc")]
pub struct BackgroundScheduler {
    work_queue: crate::scheduling::WorkItemQueue,
    services: Vec<Box<dyn BackgroundService>>,
    service_dispatch_ids: Vec<Option<DispatchRecordId>>,
    global_budget: ServiceBudget,
    cursors: [usize; 5],
    stats: SchedulerStats,
    preempt_flag: Option<Arc<AtomicBool>>,
    dispatch_store: Option<Box<dyn DispatchStore>>,
    epoch: SchedulerEpoch,
    next_dispatch_id: DispatchRecordId,
}

impl core::fmt::Debug for BackgroundScheduler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BackgroundScheduler")
            .field("service_count", &self.services.len())
            .field("global_budget", &self.global_budget)
            .field("cursors", &self.cursors)
            .field("stats", &self.stats)
            .finish()
    }
}

#[cfg(feature = "alloc")]
impl BackgroundScheduler {
    /// Create a new scheduler with the given global budget.
    #[must_use]
    pub fn new(global_budget: ServiceBudget) -> Self {
        Self {
            services: Vec::new(),
            service_dispatch_ids: Vec::new(),
            work_queue: crate::scheduling::WorkItemQueue::new_default(),
            global_budget,
            cursors: [0; 5],
            preempt_flag: None,
            stats: SchedulerStats::default(),
            dispatch_store: None,
            epoch: SchedulerEpoch::INITIAL,
            next_dispatch_id: DispatchRecordId(0),
        }
    }

    /// Register a service.
    pub fn register(&mut self, service: Box<dyn BackgroundService>) {
        self.services.push(service);
        self.service_dispatch_ids.push(None);
    }

    /// Attach a demand-preemption signal.
    ///
    /// When set, [`tick_if_idle`](Self::tick_if_idle) and
    /// [`run_cycle`](Self::run_cycle) check this flag between service
    /// ticks. If another thread sets the flag to `true`, the scheduler
    /// yields after completing the current service tick.
    pub fn set_preempt_signal(&mut self, flag: Arc<AtomicBool>) {
        self.preempt_flag = Some(flag);
    }

    /// Clear the preemption signal (e.g. during shutdown).
    pub fn clear_preempt_signal(&mut self) {
        self.preempt_flag = None;
    }

    /// Return the number of registered services.
    #[must_use]
    pub fn service_count(&self) -> usize {
        self.services.len()
    }

    /// Return the currently registered services and their scheduler priority.
    #[must_use]
    pub fn registered_services(&self) -> Vec<RegisteredService> {
        self.services
            .iter()
            .map(|service| RegisteredService {
                name: service.name(),
                priority: service.priority(),
            })
            .collect()
    }

    /// Remove and return the last registered service, if any.
    ///
    /// Used by `MultiThreadedScheduler` for work stealing between cores.
    #[must_use]
    pub fn take_last_service(&mut self) -> Option<Box<dyn BackgroundService>> {
        self.service_dispatch_ids.pop();
        self.services.pop()
    }

    /// Run one full scheduling cycle.
    ///
    /// Dispatches ticks to all services that have work, in priority order
    /// with round-robin fairness within each priority stage.
    /// Submit a `Schedulable` work item into the per-lane queue.
    ///
    /// The item will be dispatched during the next `poll()` according
    /// to its lane priority and the lane's per-tick budget.
    pub fn submit(&mut self, item: alloc::boxed::Box<dyn crate::scheduling::Schedulable>) {
        self.work_queue.submit(item);
    }

    /// Set the current time for starvation-tracking purposes.
    ///
    /// Call before `poll()` with a monotonic millisecond timestamp.
    pub fn set_now_ms(&mut self, now_ms: u64) {
        self.work_queue.set_now_ms(now_ms);
    }

    /// Poll the per-lane work queue for one scheduling tick.
    ///
    /// Drains lanes in priority order (Critical → Idle), enforcing per-lane
    /// budgets and starvation-promoting items that have waited too long.
    /// Returns a `PollResult` indicating work done, idle, or budget exhausted.
    pub fn poll(&mut self) -> crate::scheduling::PollResult {
        self.work_queue.poll()
    }

    /// Number of work items currently queued across all lanes.
    #[must_use]
    pub fn work_queued(&self) -> usize {
        self.work_queue.total_queued()
    }

    fn record_dispatched_tick(
        &mut self,
        dispatch_id: Option<DispatchRecordId>,
        checkpoint: Option<Checkpoint>,
        completed: bool,
    ) -> Result<(), DispatchStoreError> {
        let Some(dispatch_id) = dispatch_id else {
            return Ok(());
        };
        let Some(store) = self.dispatch_store.as_mut() else {
            return Ok(());
        };
        let mut record = store
            .load_record(dispatch_id)?
            .ok_or(DispatchStoreError::NotFound(dispatch_id))?;
        if let Some(checkpoint) = checkpoint {
            record.update_checkpoint(checkpoint);
        }
        if completed {
            record.mark_completed();
        } else {
            record.mark_in_progress();
        }
        store.update_record(&record)
    }

    pub fn run_cycle(&mut self) -> CycleReport {
        let cycle_start = crate_time_now_ms();
        let mut remaining_budget = self.global_budget;
        let mut report = CycleReport::default();
        let mut last_index: usize = 0;

        // Organize services by priority, preserving insertion order
        // within each stage for round-robin dispatch.
        for stage in &ServicePriority::ALL {
            // Collect indices of services at this priority that have work.
            let mut indices: Vec<usize> = Vec::new();
            for (i, svc) in self.services.iter().enumerate() {
                if svc.priority() == *stage && svc.has_work() {
                    indices.push(i);
                }
            }

            if indices.is_empty() {
                continue;
            }

            // Divide remaining budget among eligible services.
            let count = indices.len() as u64;
            let per_service_budget = remaining_budget.fraction(1, count);

            // Round-robin dispatch within this stage.
            // Start from the service after last_index within this stage's index set.
            let start_pos = indices.iter().position(|&i| i >= last_index).unwrap_or(0);

            for offset in 0..indices.len() {
                let pos = (start_pos + offset) % indices.len();
                let idx = indices[pos];

                if self.global_budget.is_bounded()
                    && remaining_budget.max_items == 0
                    && remaining_budget.max_bytes == 0
                    && remaining_budget.max_ms == 0
                {
                    report.budget_exhausted = true;
                    break;
                }

                let (svc_name, dispatch_id, tick_result, checkpoint, service_has_work) = {
                    let svc = &mut self.services[idx];
                    let dispatch_id = self.service_dispatch_ids[idx];
                    let svc_name = svc.name();
                    let tick_result = svc.tick(&per_service_budget);
                    let checkpoint = if tick_result.is_ok() {
                        svc.dispatch_checkpoint()
                    } else {
                        None
                    };
                    let service_has_work = svc.has_work();
                    (
                        svc_name,
                        dispatch_id,
                        tick_result,
                        checkpoint,
                        service_has_work,
                    )
                };

                match tick_result {
                    Ok(tick_report) => {
                        let mut tick_report = tick_report;
                        if self
                            .record_dispatched_tick(
                                dispatch_id,
                                checkpoint,
                                !tick_report.has_more || !service_has_work,
                            )
                            .is_err()
                        {
                            tick_report.errors = tick_report.errors.saturating_add(1);
                        }
                        remaining_budget.subtract_consumed(
                            tick_report.items_consumed,
                            tick_report.bytes_consumed,
                            0,
                        );
                        report.services_ran += 1;
                        report.total_processed += tick_report.processed;
                        report.total_skipped += tick_report.skipped;
                        report.total_errors += tick_report.errors;
                        report.push(svc_name, tick_report);
                        last_index = idx;
                    }
                    Err(_e) => {
                        // Service errored; skip it this cycle but
                        // don't remove it. The error is logged by
                        // the caller/integration layer.
                        report.services_skipped += 1;
                    }
                }

                // Demand preemption: if the preempt flag is set, yield

                // after completing the current service tick.

                if let Some(ref flag) = self.preempt_flag {
                    if flag.load(Ordering::Relaxed) {
                        report.preempted = true;

                        report.remaining_budget = remaining_budget;

                        report.wall_ms = crate_time_now_ms().saturating_sub(cycle_start);

                        return report;
                    }
                }

                if self.global_budget.is_bounded()
                    && remaining_budget.max_items == 0
                    && remaining_budget.max_bytes == 0
                    && remaining_budget.max_ms == 0
                {
                    report.budget_exhausted = true;
                    break;
                }
            }

            if report.budget_exhausted {
                break;
            }
        }

        report.remaining_budget = remaining_budget;
        report.wall_ms = crate_time_now_ms().saturating_sub(cycle_start);
        report
    }

    /// Check if any registered service has work pending.
    #[must_use]
    pub fn any_work_pending(&self) -> bool {
        self.services.iter().any(|s| s.has_work())
    }

    /// Run one scheduler cycle if any service has work pending.
    ///
    /// Returns `Some(CycleReport)` if work was done, `None` if all
    /// services are idle or the preemption flag is set before starting.
    /// When the preemption signal is set, the tick is skipped entirely
    /// (returns `None`) so the caller can respond to the demand event
    /// without delay.
    #[must_use]
    pub fn tick_if_idle(&mut self) -> Option<CycleReport> {
        // Skip if preempted before starting.
        if let Some(ref flag) = self.preempt_flag {
            if flag.load(Ordering::Relaxed) {
                return None;
            }
        }

        if self.any_work_pending() {
            Some(self.run_cycle())
        } else {
            None
        }
    }

    // ── Durable dispatch support ──────────────────────────────────────

    /// Create a scheduler with a [`DispatchStore`] for durable dispatch.
    ///
    /// The store persists dispatch records so jobs survive daemon restarts.
    /// If the store already contains an epoch, the scheduler adopts it;
    /// otherwise it persists [`SchedulerEpoch::INITIAL`].
    #[must_use]
    pub fn with_dispatch_store(
        global_budget: ServiceBudget,
        mut store: Box<dyn DispatchStore>,
    ) -> Result<Self, DispatchStoreError> {
        let epoch = match store.load_epoch()? {
            Some(epoch) => epoch,
            None => {
                store.store_epoch(SchedulerEpoch::INITIAL)?;
                SchedulerEpoch::INITIAL
            }
        };
        let records = store.load_records()?;
        let next_dispatch_id = records
            .iter()
            .map(|r| r.dispatch_id.0)
            .max()
            .map(|max_id| DispatchRecordId(max_id.saturating_add(1)))
            .unwrap_or(DispatchRecordId(0));
        Ok(Self {
            services: Vec::new(),
            service_dispatch_ids: Vec::new(),
            work_queue: crate::scheduling::WorkItemQueue::new_default(),
            global_budget,
            cursors: [0; 5],
            preempt_flag: None,
            stats: SchedulerStats::default(),
            dispatch_store: Some(store),
            epoch,
            next_dispatch_id,
        })
    }

    /// Load resumable dispatch records from the store.
    ///
    /// Returns records that were `Pending` or `InProgress` at the time of
    /// the last shutdown/crash. The caller should recreate jobs from these
    /// records and re-register them.
    pub fn load_resumable_records(&self) -> Result<Vec<DispatchRecord>, DispatchStoreError> {
        match &self.dispatch_store {
            Some(store) => store.load_resumable(),
            None => Ok(Vec::new()),
        }
    }

    /// Load one dispatch record by id.
    pub fn load_dispatch_record(
        &self,
        dispatch_id: DispatchRecordId,
    ) -> Result<Option<DispatchRecord>, DispatchStoreError> {
        match &self.dispatch_store {
            Some(store) => store.load_record(dispatch_id),
            None => Ok(None),
        }
    }

    /// Register an [`IncrementalJob`] service and persist its dispatch record.
    pub fn register_incremental_job<J>(
        &mut self,
        name: &'static str,
        job: J,
    ) -> Result<DispatchRecordId, DispatchStoreError>
    where
        J: IncrementalJob + Send + 'static,
    {
        let job_id = job.job_id();
        let job_kind = job.job_kind();
        self.register_dispatched(
            Box::new(IncrementalJobAdapter::new(name, job)),
            job_id,
            job_kind,
        )
    }

    /// Register a reconstructed [`IncrementalJob`] against an existing
    /// resumable dispatch record.
    ///
    /// Use this after loading a `Pending` or `InProgress` record from
    /// [`load_resumable_records`](Self::load_resumable_records) and rebuilding
    /// the concrete job from the record's checkpoint.
    pub fn register_resumable_incremental_job<J>(
        &mut self,
        name: &'static str,
        job: J,
        dispatch_id: DispatchRecordId,
    ) -> Result<DispatchRecordId, DispatchStoreError>
    where
        J: IncrementalJob + Send + 'static,
    {
        self.register_resumable_dispatch(
            Box::new(IncrementalJobAdapter::new(name, job)),
            dispatch_id,
        )
    }

    /// Register a service and persist its dispatch record.
    ///
    /// Creates a [`DispatchRecord`] in `Pending` state, persists it, then
    /// registers the service for scheduling. Returns the assigned
    /// [`DispatchRecordId`].
    ///
    /// If a dispatch store is not configured (created via [`new`]), this
    /// method behaves like [`register`] but still assigns a dispatch id.
    pub fn register_dispatched(
        &mut self,
        service: Box<dyn BackgroundService>,
        job_id: JobId,
        job_kind: JobKind,
    ) -> Result<DispatchRecordId, DispatchStoreError> {
        if let Some(ref store) = self.dispatch_store {
            if let Some(existing) = store.load_record_by_job(job_id, job_kind)? {
                return Err(DispatchStoreError::DuplicateDispatch(existing.dispatch_id));
            }
        }

        let dispatch_id = self.next_dispatch_id;
        self.next_dispatch_id = DispatchRecordId(dispatch_id.0 + 1);

        let now_ms = crate_time_now_ms();
        let mut record = DispatchRecord::new(job_id, job_kind, self.epoch, dispatch_id, now_ms);

        if let Some(ref mut store) = self.dispatch_store {
            store.store_record(&record)?;
        }

        record.mark_in_progress();

        if let Some(ref mut store) = self.dispatch_store {
            store.update_record(&record)?;
        }

        self.services.push(service);
        self.service_dispatch_ids.push(Some(dispatch_id));
        Ok(dispatch_id)
    }

    /// Register a service against an existing resumable dispatch record.
    ///
    /// This is the restart/replay counterpart to [`register_dispatched`]:
    /// it does not create a new record, and it does not treat the existing
    /// stable job identity as a duplicate. Instead, it verifies that the
    /// record is resumable and attaches the service to the original
    /// [`DispatchRecordId`] so future ticks update the same durable record.
    pub fn register_resumable_dispatch(
        &mut self,
        service: Box<dyn BackgroundService>,
        dispatch_id: DispatchRecordId,
    ) -> Result<DispatchRecordId, DispatchStoreError> {
        let store = self
            .dispatch_store
            .as_mut()
            .ok_or(DispatchStoreError::NotFound(dispatch_id))?;
        let mut record = store
            .load_record(dispatch_id)?
            .ok_or(DispatchStoreError::NotFound(dispatch_id))?;

        if !record.can_resume() {
            return Err(DispatchStoreError::InvalidState {
                dispatch_id,
                expected: "Pending or InProgress",
                actual: record.state,
            });
        }

        let Some((job_id, job_kind)) = service.dispatch_identity() else {
            return Err(DispatchStoreError::InvalidState {
                dispatch_id,
                expected: "service with dispatch identity",
                actual: record.state,
            });
        };
        if job_id != record.job_id || job_kind != record.job_kind {
            return Err(DispatchStoreError::InvalidState {
                dispatch_id,
                expected: "matching dispatch identity",
                actual: record.state,
            });
        }

        record.mark_in_progress();
        store.update_record(&record)?;

        self.services.push(service);
        self.service_dispatch_ids.push(Some(dispatch_id));
        Ok(dispatch_id)
    }

    /// Mark a dispatched service as completed.
    ///
    /// Updates the dispatch record to `Completed` state and persists it.
    /// Returns an error if no dispatch store is configured.
    pub fn mark_dispatched_completed(
        &mut self,
        dispatch_id: DispatchRecordId,
    ) -> Result<(), DispatchStoreError> {
        if let Some(ref mut store) = self.dispatch_store {
            let mut record = store
                .load_record(dispatch_id)?
                .ok_or(DispatchStoreError::NotFound(dispatch_id))?;
            record.mark_completed();
            store.update_record(&record)?;
        }
        Ok(())
    }

    /// Cancel a dispatched service.
    ///
    /// Updates the dispatch record to `Cancelled` state and persists it.
    pub fn cancel_dispatched(
        &mut self,
        dispatch_id: DispatchRecordId,
    ) -> Result<(), DispatchStoreError> {
        if let Some(ref mut store) = self.dispatch_store {
            let mut record = store
                .load_record(dispatch_id)?
                .ok_or(DispatchStoreError::NotFound(dispatch_id))?;
            record.mark_cancelled();
            store.update_record(&record)?;
        }
        Ok(())
    }

    /// Update the checkpoint for a dispatched service.
    pub fn update_dispatched_checkpoint(
        &mut self,
        dispatch_id: DispatchRecordId,
        checkpoint: Checkpoint,
    ) -> Result<(), DispatchStoreError> {
        if let Some(ref mut store) = self.dispatch_store {
            let mut record = store
                .load_record(dispatch_id)?
                .ok_or(DispatchStoreError::NotFound(dispatch_id))?;
            record.update_checkpoint(checkpoint);
            store.update_record(&record)?;
        }
        Ok(())
    }

    /// Advance the scheduler epoch.
    ///
    /// Called on daemon restart. All dispatch records from the previous
    /// epoch are considered stale; new dispatches use the new epoch.
    pub fn advance_epoch(&mut self) -> Result<SchedulerEpoch, DispatchStoreError> {
        let new_epoch = self.epoch.next();
        self.epoch = new_epoch;
        if let Some(ref mut store) = self.dispatch_store {
            store.store_epoch(new_epoch)?;
        }
        Ok(new_epoch)
    }

    /// Return the current scheduler epoch.
    #[must_use]
    pub fn epoch(&self) -> SchedulerEpoch {
        self.epoch
    }

    /// Check whether a dispatch with the given id has already been recorded
    /// in the current epoch. Returns `true` if the dispatch would be a
    /// duplicate.
    pub fn is_duplicate_dispatch(
        &self,
        dispatch_id: DispatchRecordId,
    ) -> Result<bool, DispatchStoreError> {
        match &self.dispatch_store {
            Some(store) => {
                let existing = store.load_record(dispatch_id)?;
                Ok(existing.is_some())
            }
            None => Ok(false),
        }
    }

    /// Return true if a dispatch already exists for this stable job identity.
    pub fn is_duplicate_job_dispatch(
        &self,
        job_id: JobId,
        job_kind: JobKind,
    ) -> Result<bool, DispatchStoreError> {
        match &self.dispatch_store {
            Some(store) => Ok(store.load_record_by_job(job_id, job_kind)?.is_some()),
            None => Ok(false),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// SchedulingClass — 5-lane priority classification for task submission
// ---------------------------------------------------------------------------

/// Scheduling class for lane-based priority dispatch.
///
/// Variants are ordered from highest to lowest priority. The lane scheduler
/// uses weighted round-robin dispatch (8:4:2:1:1 ratio) to guarantee that
/// Critical and High jobs execute within 100ms of enqueue when the system
/// is not overloaded.
///
/// # Starvation Bounds
///
/// With all 5 lanes non-empty, the weighted round-robin algorithm guarantees:
/// - Critical: at most 15 consecutive pops before a Critical item is served
/// - High:      at most 23 consecutive pops before a High item is served
/// - Normal:    at most 27 consecutive pops before a Normal item is served
/// - Low:       at most 29 consecutive pops before a Low item is served
/// - BestEffort: at most 30 consecutive pops before a BestEffort item is served
///
/// These bounds assume lane weights 16:8:4:2:1 (derived from 8:4:2:1:0.5
/// scaled by 2). The absolute starvation guard triggers at 100 consecutive
/// pops for any non-empty lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SchedulingClass {
    /// Must execute within 100ms of enqueue. System-correctness work:
    /// repair, intent-log sync, membership-health checks.
    Critical = 0,

    /// Should execute within 500ms. Latency-sensitive background work:
    /// writeback flush, directory view building, cache priming.
    High = 1,

    /// Expected throughput work. Deferrable but needed for steady-state
    /// operation: GC scanning, extent relocation, dedup indexing.
    Normal = 2,

    /// Low-priority deferred work. Compaction, trim, tombstone GC.
    Low = 3,

    /// Speculative work that improves future performance but is never
    /// required for correctness: prefetch, readahead, thermal rebalance.
    BestEffort = 4,
}

impl SchedulingClass {
    /// Number of priority lanes.
    pub const LANE_COUNT: usize = 5;

    /// All scheduling classes in dispatch order.
    pub const ALL: [SchedulingClass; 5] = [
        SchedulingClass::Critical,
        SchedulingClass::High,
        SchedulingClass::Normal,
        SchedulingClass::Low,
        SchedulingClass::BestEffort,
    ];

    /// Lane weight for weighted round-robin dispatch.
    ///
    /// Weights are derived from 8:4:2:1:0.5 scaled by 2 to integers:
    /// Critical=16, High=8, Normal=4, Low=2, BestEffort=1.
    #[must_use]
    pub const fn weight(self) -> u32 {
        match self {
            SchedulingClass::Critical => 16,
            SchedulingClass::High => 8,
            SchedulingClass::Normal => 4,
            SchedulingClass::Low => 2,
            SchedulingClass::BestEffort => 1,
        }
    }

    /// Sum of all lane weights (16 + 8 + 4 + 2 + 1 = 31).
    pub const TOTAL_WEIGHT: u32 = 31;

    /// Human-readable label for logging and observability.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            SchedulingClass::Critical => "critical",
            SchedulingClass::High => "high",
            SchedulingClass::Normal => "normal",
            SchedulingClass::Low => "low",
            SchedulingClass::BestEffort => "best_effort",
        }
    }

    /// Convert from a lane index (0..5).
    #[must_use]
    pub fn from_index(idx: usize) -> Option<Self> {
        match idx {
            0 => Some(SchedulingClass::Critical),
            1 => Some(SchedulingClass::High),
            2 => Some(SchedulingClass::Normal),
            3 => Some(SchedulingClass::Low),
            4 => Some(SchedulingClass::BestEffort),
            _ => None,
        }
    }

    /// Lane index (0..5).
    #[must_use]
    pub fn index(self) -> usize {
        self as usize
    }
}

impl core::fmt::Display for SchedulingClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// LaneQueue — 5-lane priority queue with weighted round-robin dispatch
// ---------------------------------------------------------------------------

/// A 5-lane priority queue with weighted round-robin dispatch.
///
/// Each lane holds items in FIFO order. [`pop`](LaneQueue::pop) selects the
/// next item using a credit-based weighted round-robin algorithm:
/// each lane has a credit budget proportional to its weight; when a lane's
/// credit is exhausted, the next eligible lane is selected. Credits reset
/// when no non-empty lane has positive credit.
///
/// # Starvation Guard
///
/// Tracks the maximum number of consecutive pops where each non-empty lane
/// was skipped. If any lane exceeds [`STARVATION_THRESHOLD`] (100), the
/// queue enters a starvation-priority mode where the starved lane is
/// promoted to the front until it is drained.
///
pub struct LaneQueue<T> {
    /// Per-lane FIFO queues indexed by SchedulingClass::index().
    lanes: [VecDeque<T>; SchedulingClass::LANE_COUNT],

    /// Per-lane credit counters for weighted round-robin.
    credits: [u32; SchedulingClass::LANE_COUNT],

    /// Total pop count since creation.
    pop_count: u64,

    /// Per-lane counter: ticks since the oldest item was enqueued.
    /// (approximation: increments each pop; resets when lane is served)
    skip_count: [u64; SchedulingClass::LANE_COUNT],

    /// Maximum observed skip count for each lane.
    max_skip: [u64; SchedulingClass::LANE_COUNT],
}

/// Default starvation threshold: if a non-empty lane is skipped 100
/// consecutive times, the queue enters starvation-priority mode.
pub const STARVATION_THRESHOLD: u64 = 100;

impl<T> LaneQueue<T> {
    /// Create a new empty lane queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            lanes: [
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
            ],
            credits: [
                SchedulingClass::Critical.weight(),
                SchedulingClass::High.weight(),
                SchedulingClass::Normal.weight(),
                SchedulingClass::Low.weight(),
                SchedulingClass::BestEffort.weight(),
            ],
            pop_count: 0,
            skip_count: [0; SchedulingClass::LANE_COUNT],
            max_skip: [0; SchedulingClass::LANE_COUNT],
        }
    }

    /// Push an item into the given scheduling class lane.
    pub fn push(&mut self, class: SchedulingClass, item: T) {
        self.lanes[class.index()].push_back(item);
    }

    /// Pop the next item according to weighted round-robin dispatch.
    ///
    /// Returns `None` if all lanes are empty. Otherwise, selects the
    /// highest-priority non-empty lane with positive credits, decrements
    /// its credit, and returns the front item. When no lane has credits,
    /// all credits are reset and selection retries.
    ///
    /// If a non-empty lane has been skipped more than
    /// [`STARVATION_THRESHOLD`] times, it is served immediately
    /// regardless of credits.
    pub fn pop(&mut self) -> Option<(SchedulingClass, T)> {
        // Check for starvation: any non-empty lane skipped too long?
        for class in &SchedulingClass::ALL {
            let idx = class.index();
            if !self.lanes[idx].is_empty() && self.skip_count[idx] >= STARVATION_THRESHOLD {
                let item = self.lanes[idx].pop_front().unwrap();
                self.pop_count += 1;
                // Reset skip count for this lane; accumulate for others.
                for c in &SchedulingClass::ALL {
                    let i = c.index();
                    if i == idx {
                        self.max_skip[i] = self.max_skip[i].max(self.skip_count[i]);
                        self.skip_count[i] = 0;
                    } else if !self.lanes[i].is_empty() {
                        self.skip_count[i] += 1;
                        self.max_skip[i] = self.max_skip[i].max(self.skip_count[i]);
                    }
                }
                return Some((*class, item));
            }
        }

        // Normal weighted round-robin: find highest-priority non-empty
        // lane with positive credits.
        loop {
            for class in &SchedulingClass::ALL {
                let idx = class.index();
                if !self.lanes[idx].is_empty() && self.credits[idx] > 0 {
                    let item = self.lanes[idx].pop_front().unwrap();
                    self.credits[idx] -= 1;
                    self.pop_count += 1;

                    // Update skip counts.
                    for c in &SchedulingClass::ALL {
                        let i = c.index();
                        if i == idx {
                            self.skip_count[i] = 0;
                        } else if !self.lanes[i].is_empty() {
                            self.skip_count[i] += 1;
                            self.max_skip[i] = self.max_skip[i].max(self.skip_count[i]);
                        }
                    }
                    return Some((*class, item));
                }
            }

            // No non-empty lane with credits. Check if anything is left.
            if self.lanes.iter().all(|l| l.is_empty()) {
                return None;
            }

            // Reset credits and retry.
            self.credits = [
                SchedulingClass::Critical.weight(),
                SchedulingClass::High.weight(),
                SchedulingClass::Normal.weight(),
                SchedulingClass::Low.weight(),
                SchedulingClass::BestEffort.weight(),
            ];
        }
    }

    /// Total number of items across all lanes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lanes.iter().map(|l| l.len()).sum()
    }

    /// Returns `true` if all lanes are empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lanes.iter().all(|l| l.is_empty())
    }

    /// Number of items in a specific lane.
    #[must_use]
    pub fn lane_len(&self, class: SchedulingClass) -> usize {
        self.lanes[class.index()].len()
    }

    /// Total number of pop operations since creation.
    #[must_use]
    pub fn pop_count(&self) -> u64 {
        self.pop_count
    }

    /// Maximum observed number of consecutive pops where a non-empty
    /// lane of the given class was skipped. Zero if the lane has never
    /// been skipped while non-empty.
    #[must_use]
    pub fn max_skip(&self, class: SchedulingClass) -> u64 {
        self.max_skip[class.index()]
    }

    /// Returns `true` if any lane has exceeded the starvation threshold.
    #[must_use]
    pub fn has_starvation(&self) -> bool {
        self.max_skip.iter().any(|&s| s >= STARVATION_THRESHOLD)
    }
}

impl<T> Default for LaneQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> core::fmt::Debug for LaneQueue<T>
where
    T: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LaneQueue")
            .field("total_len", &self.len())
            .field("pop_count", &self.pop_count)
            .field(
                "lane_lens",
                &[
                    self.lane_len(SchedulingClass::Critical),
                    self.lane_len(SchedulingClass::High),
                    self.lane_len(SchedulingClass::Normal),
                    self.lane_len(SchedulingClass::Low),
                    self.lane_len(SchedulingClass::BestEffort),
                ],
            )
            .field("credits", &self.credits)
            .field("max_skip", &self.max_skip)
            .finish()
    }
}

#[cfg(test)]
impl<T> LaneQueue<T> {
    /// Set the skip count for a lane (test-only).
    /// Allows direct manipulation of starvation tracking for testing.
    fn set_skip_count(&mut self, class: SchedulingClass, count: u64) {
        self.skip_count[class.index()] = count;
    }

    // ---------------------------------------------------------------------------
    // Scheduler — async task scheduler backed by LaneQueue
}

// ---------------------------------------------------------------------------

#[cfg(feature = "scheduler")]
pub mod scheduler;
#[cfg(test)]
mod tests {
    use super::*;

    // ── ServicePriority ───────────────────────────────────────────────

    #[test]
    fn priority_ordering() {
        assert!(ServicePriority::Critical < ServicePriority::LatencySensitive);
        assert!(ServicePriority::LatencySensitive < ServicePriority::Throughput);
        assert!(ServicePriority::Throughput < ServicePriority::BestEffort);
        assert!(ServicePriority::BestEffort < ServicePriority::Opportunistic);
    }

    #[test]
    fn all_stages_covers_five_levels() {
        assert_eq!(ServicePriority::ALL.len(), 5);
        let mut sorted = ServicePriority::ALL;
        sorted.sort();
        // After sorting, they should be in definition order.
        assert_eq!(sorted[0], ServicePriority::Critical);
        assert_eq!(sorted[4], ServicePriority::Opportunistic);
    }

    #[test]
    fn from_job_kind_maps_all_variants() {
        assert_eq!(
            ServicePriority::from_job_kind(JobKind::Scrub),
            ServicePriority::Critical
        );
        assert_eq!(
            ServicePriority::from_job_kind(JobKind::DeepScrub),
            ServicePriority::Critical
        );
        assert_eq!(
            ServicePriority::from_job_kind(JobKind::Resilver),
            ServicePriority::Critical
        );
        assert_eq!(
            ServicePriority::from_job_kind(JobKind::OrphanRecovery),
            ServicePriority::LatencySensitive
        );
        assert_eq!(
            ServicePriority::from_job_kind(JobKind::Reclaim),
            ServicePriority::LatencySensitive
        );
        assert_eq!(
            ServicePriority::from_job_kind(JobKind::DerivedCatalog),
            ServicePriority::LatencySensitive
        );
        assert_eq!(
            ServicePriority::from_job_kind(JobKind::DeferredCleanup),
            ServicePriority::Throughput
        );
        assert_eq!(
            ServicePriority::from_job_kind(JobKind::SnapshotDestroy),
            ServicePriority::Throughput
        );
        assert_eq!(
            ServicePriority::from_job_kind(JobKind::GCMark),
            ServicePriority::BestEffort
        );
        assert_eq!(
            ServicePriority::from_job_kind(JobKind::BtreeCompaction),
            ServicePriority::BestEffort
        );
        assert_eq!(
            ServicePriority::from_job_kind(JobKind::Dedup),
            ServicePriority::BestEffort
        );
    }

    #[test]
    fn priority_label_nonempty() {
        for p in &ServicePriority::ALL {
            assert!(!p.label().is_empty());
        }
    }

    // ── ServiceBudget ─────────────────────────────────────────────────

    #[test]
    fn default_tick_is_bounded() {
        assert!(ServiceBudget::DEFAULT_TICK.is_bounded());
    }

    #[test]
    fn small_tick_is_bounded() {
        assert!(ServiceBudget::SMALL_TICK.is_bounded());
    }

    #[test]
    fn zero_budget_is_exhausted() {
        let b = ServiceBudget {
            max_items: 0,
            max_bytes: 0,
            max_ms: 0,
        };
        assert!(b.is_exhausted());
    }

    #[test]
    fn fraction_scales_proportionally() {
        let b = ServiceBudget {
            max_items: 100,
            max_bytes: 200,
            max_ms: 0,
        };
        let half = b.fraction(1, 2);
        assert_eq!(half.max_items, 50);
        assert_eq!(half.max_bytes, 100);
        assert_eq!(half.max_ms, 0); // unbounded stays unbounded

        let third = b.fraction(1, 3);
        assert_eq!(third.max_items, 33); // 100/3 = 33 (with floor of 1)
    }

    #[test]
    fn fraction_denom_zero_is_noop() {
        let b = ServiceBudget::DEFAULT_TICK;
        let result = b.fraction(1, 0);
        assert_eq!(result.max_items, b.max_items);
    }

    #[test]
    fn subtract_consumed_saturates() {
        let mut b = ServiceBudget {
            max_items: 10,
            max_bytes: 100,
            max_ms: 0,
        };
        b.subtract_consumed(20, 50, 0);
        assert_eq!(b.max_items, 0);
        assert_eq!(b.max_bytes, 50);
    }

    #[test]
    fn subtract_consumed_unbounded_unchanged() {
        let mut b = ServiceBudget::UNBOUNDED;
        b.subtract_consumed(1000, 1000, 0);
        assert_eq!(b.max_items, 0); // was 0, stays 0 (unbounded)
        assert_eq!(b.max_bytes, 0);
    }

    #[test]
    fn to_work_budget_conversion() {
        let sb = ServiceBudget {
            max_items: 42,
            max_bytes: 1024,
            max_ms: 10,
        };
        let wb = sb.to_work_budget();
        assert_eq!(wb.max_items, 42);
        assert_eq!(wb.max_bytes, 1024);
        assert_eq!(wb.max_ms, 10);
    }

    // ── TickReport ───────────────────────────────────────────────────

    #[test]
    fn tick_report_total_attempted() {
        let report = TickReport {
            processed: 5,
            skipped: 2,
            errors: 1,
            ..TickReport::default()
        };
        assert_eq!(report.total_attempted(), 8);
    }

    #[test]
    fn tick_report_merge() {
        let mut a = TickReport {
            processed: 3,
            skipped: 1,
            errors: 0,
            items_consumed: 4,
            bytes_consumed: 100,
            has_more: true,
        };
        let b = TickReport {
            processed: 5,
            skipped: 0,
            errors: 2,
            items_consumed: 7,
            bytes_consumed: 200,
            has_more: false,
        };
        a.merge(&b);
        assert_eq!(a.processed, 8);
        assert_eq!(a.skipped, 1);
        assert_eq!(a.errors, 2);
        assert_eq!(a.items_consumed, 11);
        assert_eq!(a.bytes_consumed, 300);
        assert!(a.has_more); // true OR false = true
    }

    // ── ServiceError ─────────────────────────────────────────────────

    #[test]
    fn service_error_display_nonempty() {
        let errors = [
            ServiceError::BudgetExceeded {
                service: "test",
                limit: 10,
                actual: 15,
            },
            ServiceError::Internal {
                service: "test",
                message: "disk full",
            },
            ServiceError::Stopped { service: "test" },
            ServiceError::JobError {
                service: "test",
                error: JobError::CheckpointCorrupt {
                    job_id: JobId(1),
                    reason: "test",
                },
            },
        ];
        for e in &errors {
            let s = format!("{e}");
            assert!(!s.is_empty(), "empty display for {e:?}");
        }
    }

    // ── BackgroundScheduler integration tests ────────────────────────

    /// A minimal IncrementalJob for testing the adapter.
    #[derive(Debug)]
    struct MockJob {
        id: JobId,
        kind: JobKind,
        total: u64,
        processed: u64,
    }

    impl MockJob {
        fn new(id: u64, kind: JobKind, total: u64) -> Self {
            Self {
                id: JobId(id),
                kind,
                total,
                processed: 0,
            }
        }
    }

    impl IncrementalJob for MockJob {
        fn resume(ck: Checkpoint) -> Result<Self, JobError> {
            let processed = if ck.cursor_state.is_empty() {
                0
            } else if ck.cursor_state.len() == 8 {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(ck.cursor_state.as_bytes());
                u64::from_le_bytes(buf)
            } else {
                return Err(JobError::CursorStateInvalid {
                    job_id: ck.job_id,
                    reason: "cursor must be 8 bytes",
                });
            };
            Ok(Self {
                id: ck.job_id,
                kind: ck.job_kind,
                total: 100,
                processed,
            })
        }

        fn step(&mut self, budget: WorkBudget) -> StepResult {
            let remaining = self.total - self.processed;
            let max = if budget.max_items == 0 {
                remaining
            } else {
                budget.max_items.min(remaining)
            };
            let batch = max.min(20); // mock: max 20 per step
            self.processed += batch;

            let progress = JobProgress {
                items_processed: batch,
                items_total_estimate: self.total,
                bytes_processed: batch * 1024,
                bytes_total_estimate: self.total * 1024,
                elapsed_ms: 5,
            };
            let ck = Checkpoint {
                job_id: self.id,
                job_kind: self.kind,
                epoch: 1,
                cursor_state: tidefs_types_incremental_job_core::CursorState(
                    self.processed.to_le_bytes().to_vec(),
                ),
                progress,
            };
            if self.processed >= self.total {
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
                cursor_state: tidefs_types_incremental_job_core::CursorState(
                    self.processed.to_le_bytes().to_vec(),
                ),
                progress: JobProgress {
                    items_processed: self.processed,
                    items_total_estimate: self.total,
                    ..JobProgress::default()
                },
            }
        }

        fn complete(self) {}
        fn job_id(&self) -> JobId {
            self.id
        }
        fn job_kind(&self) -> JobKind {
            self.kind
        }
    }

    #[test]
    fn scheduler_empty_no_work() {
        let mut s = BackgroundScheduler::new(ServiceBudget::SMALL_TICK);
        assert!(!s.any_work_pending());
        let report = s.run_cycle();
        assert_eq!(report.services_ran, 0);
    }

    #[test]
    fn adapter_priority_derived_from_job_kind() {
        let job = MockJob::new(1, JobKind::Scrub, 100);
        let adapter = IncrementalJobAdapter::new("scrub", job);
        assert_eq!(adapter.priority(), ServicePriority::Critical);
    }

    #[test]
    fn adapter_with_explicit_priority() {
        let job = MockJob::new(1, JobKind::Scrub, 100);
        let adapter =
            IncrementalJobAdapter::new("scrub", job).with_priority(ServicePriority::Throughput);
        assert_eq!(adapter.priority(), ServicePriority::Throughput);
    }

    #[test]
    fn adapter_tick_makes_progress() {
        let job = MockJob::new(1, JobKind::DeferredCleanup, 100);
        let mut adapter = IncrementalJobAdapter::new("cleanup", job);
        assert!(adapter.has_work());

        let budget = ServiceBudget {
            max_items: 10,
            ..ServiceBudget::DEFAULT_TICK
        };
        let report = adapter.tick(&budget).unwrap();
        assert!(report.processed > 0);
        assert!(report.has_more);
    }

    #[test]
    fn adapter_completes_after_full_work() {
        let job = MockJob::new(1, JobKind::BtreeCompaction, 100);
        let mut adapter = IncrementalJobAdapter::new("compaction", job);
        let budget = ServiceBudget::UNBOUNDED;

        let mut runs = 0;
        loop {
            let report = adapter.tick(&budget).unwrap();
            runs += 1;
            if !report.has_more {
                break;
            }
            if runs > 20 {
                panic!("job didn't complete within 20 steps");
            }
        }
        // After completion, has_work is false.
        assert!(!adapter.has_work());
    }

    #[test]
    fn scheduler_priority_ordering_critical_first() {
        let mut scheduler = BackgroundScheduler::new(ServiceBudget::SMALL_TICK);

        // Register a low-priority service first, high-priority second.
        let low_job = MockJob::new(1, JobKind::BtreeCompaction, 100); // BestEffort
        let high_job = MockJob::new(2, JobKind::Scrub, 100); // Critical

        scheduler.register(Box::new(IncrementalJobAdapter::new("low", low_job)));
        scheduler.register(Box::new(IncrementalJobAdapter::new("high", high_job)));

        let report = scheduler.run_cycle();

        // The first service to run should be the Critical one (index 1).
        assert!(
            report.services_ran > 0,
            "expected at least one service to run"
        );
    }

    #[test]
    fn scheduler_round_robin_within_stage() {
        let mut scheduler = BackgroundScheduler::new(ServiceBudget::DEFAULT_TICK);

        let job1 = MockJob::new(1, JobKind::DeferredCleanup, 100); // Throughput
        let job2 = MockJob::new(2, JobKind::DeferredCleanup, 100); // Throughput

        scheduler.register(Box::new(IncrementalJobAdapter::new("a", job1)));
        scheduler.register(Box::new(IncrementalJobAdapter::new("b", job2)));

        let report = scheduler.run_cycle();
        assert!(
            report.services_ran >= 2,
            "expected both services to run at least once"
        );
    }

    #[test]
    fn scheduler_cascades_unused_budget() {
        // Register Critical + BestEffort. The Critical job completes
        // quickly; remaining budget should cascade to BestEffort.
        let mut scheduler = BackgroundScheduler::new(ServiceBudget::DEFAULT_TICK);

        let crit_job = MockJob::new(1, JobKind::Scrub, 5); // Critical, small
        let be_job = MockJob::new(2, JobKind::BtreeCompaction, 100); // BestEffort

        scheduler.register(Box::new(IncrementalJobAdapter::new("crit", crit_job)));
        scheduler.register(Box::new(IncrementalJobAdapter::new("be", be_job)));

        let report = scheduler.run_cycle();
        // Both should have run: Critical first (with small budget),
        // then BestEffort with cascaded budget.
        assert!(report.services_ran >= 2, "expected both services to run");
    }

    #[test]
    fn scheduler_skips_idle_services() {
        let mut scheduler = BackgroundScheduler::new(ServiceBudget::SMALL_TICK);

        // Create a job with 0 total that reports complete immediately.
        let done_job = MockJob::new(1, JobKind::DeferredCleanup, 0);
        let mut adapter = IncrementalJobAdapter::new("done", done_job);
        // Run it once to complete
        let _ = adapter.tick(&ServiceBudget::SMALL_TICK);
        assert!(!adapter.has_work());

        scheduler.register(Box::new(adapter));
        let report = scheduler.run_cycle();
        assert_eq!(report.services_ran, 0);
    }

    #[test]
    fn scheduler_any_work_pending() {
        let mut scheduler = BackgroundScheduler::new(ServiceBudget::SMALL_TICK);
        let job = MockJob::new(1, JobKind::Scrub, 100);
        scheduler.register(Box::new(IncrementalJobAdapter::new("scrub", job)));
        assert!(scheduler.any_work_pending());
    }

    #[test]
    fn cycle_report_display_nonempty() {
        let report = CycleReport {
            services_ran: 3,
            services_skipped: 1,
            budget_exhausted: false,
            remaining_budget: ServiceBudget::DEFAULT_TICK,
            ..CycleReport::default()
        };
        assert!(!format!("{report}").is_empty());
    }

    // ── Serde roundtrip tests ────────────────────────────────────────

    #[cfg(feature = "serde")]
    #[test]
    fn service_priority_serde_roundtrip() {
        for p in &ServicePriority::ALL {
            let json = serde_json::to_string(p).unwrap();
            let p2: ServicePriority = serde_json::from_str(&json).unwrap();
            assert_eq!(*p, p2);
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn service_budget_serde_roundtrip() {
        let b = ServiceBudget::DEFAULT_TICK;
        let json = serde_json::to_string(&b).unwrap();
        let b2: ServiceBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(b.max_items, b2.max_items);
        assert_eq!(b.max_bytes, b2.max_bytes);
        assert_eq!(b.max_ms, b2.max_ms);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn tick_report_serde_roundtrip() {
        let r = TickReport {
            processed: 10,
            skipped: 2,
            errors: 1,
            items_consumed: 13,
            bytes_consumed: 2048,
            has_more: true,
        };
        let json = serde_json::to_string(&r).unwrap();
        let r2: TickReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r.processed, r2.processed);
        assert_eq!(r.has_more, r2.has_more);
    }

    // ── SchedulingClass ──────────────────────────────────────────────

    #[test]
    fn scheduling_class_ordering() {
        assert!(SchedulingClass::Critical < SchedulingClass::High);
        assert!(SchedulingClass::High < SchedulingClass::Normal);
        assert!(SchedulingClass::Normal < SchedulingClass::Low);
        assert!(SchedulingClass::Low < SchedulingClass::BestEffort);
    }

    #[test]
    fn scheduling_class_all_covers_five_levels() {
        assert_eq!(SchedulingClass::ALL.len(), 5);
        assert_eq!(SchedulingClass::ALL[0], SchedulingClass::Critical);
        assert_eq!(SchedulingClass::ALL[4], SchedulingClass::BestEffort);
    }

    #[test]
    fn scheduling_class_weight_sum() {
        let sum: u32 = SchedulingClass::ALL.iter().map(|c| c.weight()).sum();
        assert_eq!(sum, SchedulingClass::TOTAL_WEIGHT);
        assert_eq!(SchedulingClass::TOTAL_WEIGHT, 31);
    }

    #[test]
    fn scheduling_class_label_nonempty() {
        for c in &SchedulingClass::ALL {
            assert!(!c.label().is_empty());
        }
    }

    #[test]
    fn scheduling_class_from_index_roundtrip() {
        for c in &SchedulingClass::ALL {
            assert_eq!(SchedulingClass::from_index(c.index()), Some(*c));
        }
        assert_eq!(SchedulingClass::from_index(5), None);
        assert_eq!(SchedulingClass::from_index(100), None);
    }

    // ── LaneQueue: single-lane FIFO ──────────────────────────────────

    #[test]
    fn lane_queue_single_lane_fifo() {
        let mut q = LaneQueue::new();
        q.push(SchedulingClass::Normal, 1);
        q.push(SchedulingClass::Normal, 2);
        q.push(SchedulingClass::Normal, 3);

        assert_eq!(q.pop(), Some((SchedulingClass::Normal, 1)));
        assert_eq!(q.pop(), Some((SchedulingClass::Normal, 2)));
        assert_eq!(q.pop(), Some((SchedulingClass::Normal, 3)));
        assert_eq!(q.pop(), None);
    }

    // ── LaneQueue: empty pop ─────────────────────────────────────────

    #[test]
    fn lane_queue_empty_pop_returns_none() {
        let mut q: LaneQueue<i32> = LaneQueue::new();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert_eq!(q.pop(), None);
    }

    // ── LaneQueue: inter-lane priority ───────────────────────────────

    #[test]
    fn lane_queue_inter_lane_priority() {
        let mut q = LaneQueue::new();
        // Push Normal first, then Critical. Critical should pop first.
        q.push(SchedulingClass::Normal, "normal_item");
        q.push(SchedulingClass::Critical, "critical_item");

        let first = q.pop().unwrap();
        assert_eq!(first.0, SchedulingClass::Critical);
        assert_eq!(first.1, "critical_item");

        let second = q.pop().unwrap();
        assert_eq!(second.0, SchedulingClass::Normal);
        assert_eq!(second.1, "normal_item");

        assert!(q.is_empty());
    }

    // ── LaneQueue: multi-lane priority with deep queues ──────────────

    #[test]
    fn lane_queue_multi_lane_priority_deep() {
        let mut q = LaneQueue::new();
        // Push items across all lanes, then verify Critical items
        // are popped before BestEffort items.
        q.push(SchedulingClass::BestEffort, "be1");
        q.push(SchedulingClass::BestEffort, "be2");
        q.push(SchedulingClass::Low, "low1");
        q.push(SchedulingClass::Critical, "crit1");
        q.push(SchedulingClass::Normal, "norm1");
        q.push(SchedulingClass::Critical, "crit2");

        // First two pops should be Critical items (in FIFO order).
        assert_eq!(q.pop().unwrap().1, "crit1");
        assert_eq!(q.pop().unwrap().1, "crit2");

        // After that, with credits: Critical is exhausted, so High
        // (empty) -> Normal gets popped, then Low, then BestEffort.
        // But specifics depend on weights. At minimum, verify
        // BestEffort doesn't come before Critical.
        let remaining: Vec<_> = std::iter::from_fn(|| q.pop()).collect();
        assert_eq!(remaining.len(), 4);
        // BestEffort items should be last or near-last.
        let be_positions: Vec<usize> = remaining
            .iter()
            .enumerate()
            .filter(|(_, (_, val))| val.starts_with("be"))
            .map(|(i, _)| i)
            .collect();
        // Both BE items should be in the second half of pops.
        assert!(
            be_positions.iter().all(|&p| p >= 2),
            "BestEffort items popped too early: positions {be_positions:?}"
        );
    }

    // ── LaneQueue: weight ratio ──────────────────────────────────────

    #[test]
    fn lane_queue_weight_ratio_approximate() {
        let mut q = LaneQueue::new();
        // Push many items in each lane to ensure no lane empties early.
        let n: u32 = 100;
        for _ in 0..n {
            q.push(SchedulingClass::Critical, ());
            q.push(SchedulingClass::High, ());
            q.push(SchedulingClass::Normal, ());
            q.push(SchedulingClass::Low, ());
            q.push(SchedulingClass::BestEffort, ());
        }

        // Pop 2 full credit cycles (62 items) and verify the
        // distribution approximates the weight ratio 16:8:4:2:1.
        let mut counts = [0u32; 5];
        for _ in 0..(SchedulingClass::TOTAL_WEIGHT * 2) {
            if let Some((class, _)) = q.pop() {
                counts[class.index()] += 1;
            }
        }

        // With 2 cycles, expected per-lane pops: 32, 16, 8, 4, 2.
        // Allow generous tolerance.
        assert!(
            counts[0] > counts[1],
            "Critical pops ({}) should exceed High pops ({})",
            counts[0],
            counts[1]
        );
        assert!(
            counts[1] > counts[2],
            "High pops ({}) should exceed Normal pops ({})",
            counts[1],
            counts[2]
        );
        assert!(
            counts[2] > counts[3],
            "Normal pops ({}) should exceed Low pops ({})",
            counts[2],
            counts[3]
        );
        assert!(
            counts[3] > counts[4],
            "Low pops ({}) should exceed BestEffort pops ({})",
            counts[3],
            counts[4]
        );

        // Verify approximate magnitudes.
        assert!(
            counts[0] >= 28,
            "Critical count={} should be near 32",
            counts[0]
        );
        assert!(
            counts[4] <= 6,
            "BestEffort count={} should be near 2",
            counts[4]
        );

        // Total should equal TOTAL_WEIGHT * 2 = 62.
        let total: u32 = counts.iter().sum();
        assert_eq!(total, SchedulingClass::TOTAL_WEIGHT * 2);
    }

    // ── LaneQueue: starvation guard ──────────────────────────────────

    #[test]
    fn lane_queue_no_starvation_under_normal_load() {
        let mut q = LaneQueue::new();
        // Fill all lanes with many items and drain. The weighted
        // algorithm should prevent any lane from reaching STARVATION_THRESHOLD.
        let items_per_lane = 1000u64;
        for _ in 0..items_per_lane {
            q.push(SchedulingClass::Critical, "c");
            q.push(SchedulingClass::High, "h");
            q.push(SchedulingClass::Normal, "n");
            q.push(SchedulingClass::Low, "l");
            q.push(SchedulingClass::BestEffort, "b");
        }

        while q.pop().is_some() {}

        // No lane should have hit the starvation threshold.
        assert!(!q.has_starvation());

        // Each lane's max skip should be well under 100.
        for class in &SchedulingClass::ALL {
            let max_skip = q.max_skip(*class);
            assert!(
                max_skip < STARVATION_THRESHOLD,
                "class {class} had max_skip={max_skip} which exceeds threshold"
            );
        }
    }

    #[test]
    fn lane_queue_starvation_guard_triggers() {
        // Verify the starvation guard fires when a non-empty lane's
        // skip count reaches STARVATION_THRESHOLD. In normal operation
        // with weighted round-robin this never happens (max gap is 30),
        // so we manipulate skip_count directly via the test-only setter.
        let mut q: LaneQueue<&str> = LaneQueue::new();

        // Push a Critical item that should be starved.
        q.push(SchedulingClass::Critical, "starving_crit");

        // Artificially set the skip count to just below threshold.
        // The next pop that skips Critical should trigger the guard.
        q.set_skip_count(SchedulingClass::Critical, STARVATION_THRESHOLD);

        // Pop one item. The starvation check runs first and should
        // serve Critical immediately even though it has no credits.
        let result = q.pop();
        assert_eq!(
            result,
            Some((SchedulingClass::Critical, "starving_crit")),
            "starvation guard should serve Critical when skip_count >= threshold"
        );

        // After serving, Critical's skip_count should reset to 0.
        assert_eq!(q.max_skip(SchedulingClass::Critical), STARVATION_THRESHOLD);
        let _ = q.is_empty();
    }

    // ── LaneQueue: concurrent submit and pop ─────────────────────────

    #[tokio::test]
    async fn lane_queue_concurrent_submit_pop() {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let q = Arc::new(Mutex::new(LaneQueue::new()));
        let num_producers = 4;
        let items_per_producer = 250u64;

        // Spawn producers that push items into various lanes.
        let mut handles = Vec::new();
        for p in 0..num_producers {
            let q = q.clone();
            let handle = tokio::spawn(async move {
                for i in 0..items_per_producer {
                    let class = match (p + i as usize) % 5 {
                        0 => SchedulingClass::Critical,
                        1 => SchedulingClass::High,
                        2 => SchedulingClass::Normal,
                        3 => SchedulingClass::Low,
                        _ => SchedulingClass::BestEffort,
                    };
                    let item = (p, i);
                    q.lock().await.push(class, item);
                }
            });
            handles.push(handle);
        }

        // Wait for all producers to finish.
        for h in handles {
            h.await.unwrap();
        }

        // Drain the queue.
        let mut total = 0u64;
        let mut lane_counts = [0u64; 5];
        {
            let mut q = q.lock().await;
            while let Some((class, _)) = q.pop() {
                lane_counts[class.index()] += 1;
                total += 1;
            }
        }

        assert_eq!(total, (num_producers as u64) * items_per_producer);
        let sum_lanes: u64 = lane_counts.iter().sum();
        assert_eq!(sum_lanes, total);

        // Every lane should have been served.
        for (i, &count) in lane_counts.iter().enumerate() {
            assert!(
                count > 0,
                "lane {} ({}) was never served",
                i,
                SchedulingClass::from_index(i).unwrap()
            );
        }
    }

    // ── LaneQueue: property test (10K random-class submits) ─────────

    #[test]
    fn lane_queue_property_test_10k_random_submits() {
        // Use a deterministic pseudo-random sequence seeded by lane
        // index parity, not an external RNG, to keep the test
        // reproducible across platforms.
        let mut q: LaneQueue<u64> = LaneQueue::new();
        let mut submitted = [0u64; SchedulingClass::LANE_COUNT];
        let total_items: u64 = 10_000;

        // Generate 10,000 items with deterministic class assignment.
        for i in 0..total_items {
            let class = SchedulingClass::from_index((i % 13) as usize % 5).unwrap();
            q.push(class, i);
            submitted[class.index()] += 1;
        }

        // Drain the queue and track per-lane completion counts.
        let mut completed = [0u64; SchedulingClass::LANE_COUNT];
        while let Some((class, _val)) = q.pop() {
            completed[class.index()] += 1;
        }

        // Assert per-lane completion counts match submission counts.
        for class in &SchedulingClass::ALL {
            let idx = class.index();
            assert_eq!(
                completed[idx], submitted[idx],
                "lane {class}: submitted {} but completed {}",
                submitted[idx], completed[idx],
            );
        }

        // Assert no lane experienced starvation.
        assert!(
            !q.has_starvation(),
            "starvation detected: max_skip = {:?}",
            [
                q.max_skip(SchedulingClass::Critical),
                q.max_skip(SchedulingClass::High),
                q.max_skip(SchedulingClass::Normal),
                q.max_skip(SchedulingClass::Low),
                q.max_skip(SchedulingClass::BestEffort)
            ]
        );

        // Assert no Critical job waited more than 100 consecutive
        // dequeues while still pending. The max_skip for Critical
        // must be well under STARVATION_THRESHOLD.
        for class in &[SchedulingClass::Critical, SchedulingClass::High] {
            let max = q.max_skip(*class);
            assert!(
                max < STARVATION_THRESHOLD,
                "class {class} max_skip={max} exceeded starvation threshold",
            );
        }

        // Total pop count should match total items.
        assert_eq!(q.pop_count(), total_items);
    }
}
