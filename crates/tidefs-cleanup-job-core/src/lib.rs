// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! CleanupJob: IncrementalJob for deferred cleanup work items.
//!
//! Implements the background processing of [`CleanupWorkItemV1`] records
//! enqueued by synchronous namespace operations (unlink, truncate, rmdir,
//! rename-overwrite, snap-delete, punch-hole). Each tick processes a bounded
//! batch of work items within a [`WorkBudget`], advancing a cursor across the
//! cleanup queue.
//!
//! ## Budget respect
//!
//! The `step()` implementation respects `WorkBudget::max_items` by
//! limiting the number of work items processed per call.
//!
//! ## Relationship to BackgroundScheduler
//!
//! `CleanupJob` implements [`IncrementalJob`] and can be wrapped in
//! [`IncrementalJobAdapter`] to become a [`BackgroundService`] in the
//! unified scheduler at `Throughput` priority (`JobKind::DeferredCleanup`).
//!
//! ## Cleanup job receipts
//!
//! [`CleanupJobReceipt`] records provide deterministic source evidence for
//! cleanup job admission, skip, retry, failure, and completion decisions. They
//! are intentionally lower-tier evidence until paired with cleanup queue replay
//! receipts and mounted runtime artifacts; by themselves they do not claim
//! crash recovery or mounted cleanup correctness.

use serde::{Deserialize, Serialize};
use std::fmt;
use tidefs_types_deferred_cleanup_core::CleanupWorkItemV1;
use tidefs_types_incremental_job_core::{
    Checkpoint, IncrementalJob, JobError, JobId, JobKind, JobProgress as IncrJobProgress,
    StepResult, WorkBudget,
};

// ---------------------------------------------------------------------------
// CleanupJobStats — observability
// ---------------------------------------------------------------------------

/// Accumulated statistics for CleanupJob.
///
/// Exposed through the background scheduler's per-service stats
/// so operators can monitor deferred cleanup progress.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CleanupJobStats {
    /// Total work items processed since job start.
    pub items_processed: u64,
    /// Items marked complete (all extents freed).
    pub items_completed: u64,
    /// Items still in progress (cursor mid-iteration).
    pub items_in_progress: u64,
    /// Items that encountered errors.
    pub items_errored: u64,
    /// Estimated bytes freed so far.
    pub bytes_freed_estimate: u64,
}

impl CleanupJobStats {
    /// Zero-valued stats.
    pub const ZERO: Self = Self {
        items_processed: 0,
        items_completed: 0,
        items_in_progress: 0,
        items_errored: 0,
        bytes_freed_estimate: 0,
    };
}

// ---------------------------------------------------------------------------
// Cursor encoding helpers
// ---------------------------------------------------------------------------

/// Encode a cursor index into cursor state bytes.
/// Format: 8 bytes of u64 LE, or empty for start.
fn encode_cursor(index: u64) -> Vec<u8> {
    index.to_le_bytes().to_vec()
}

/// Decode cursor state bytes back into an index.
fn decode_cursor(bytes: &[u8]) -> u64 {
    if bytes.len() < 8 {
        return 0;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(buf)
}

// ---------------------------------------------------------------------------
// CleanupJob
// ---------------------------------------------------------------------------

/// IncrementalJob that processes deferred cleanup work items, freeing
/// extents within a per-tick [`WorkBudget`].
///
/// # Lifecycle
///
/// 1. `resume(Checkpoint)`: creates a fresh job from a checkpoint.
/// 2. `step(budget)`: processes up to `budget.max_items` work items,
///    advancing an internal cursor.
/// 3. `persist_checkpoint()`: returns current checkpoint.
/// 4. `complete()`: no-op.
pub struct CleanupJob {
    job_id: JobId,
    work_items: Vec<CleanupWorkItemV1>,
    cursor: u64,
    stats: CleanupJobStats,
    default_item_bytes: u64,
}

impl CleanupJob {
    /// Create a fresh CleanupJob with the given work items.
    #[must_use]
    pub fn new(work_items: Vec<CleanupWorkItemV1>) -> Self {
        Self {
            job_id: JobId::NONE,
            work_items,
            cursor: 0,
            stats: CleanupJobStats::ZERO,
            default_item_bytes: 4096,
        }
    }

    /// Assign a specific [`JobId`].
    #[must_use]
    pub fn with_job_id(mut self, job_id: JobId) -> Self {
        self.job_id = job_id;
        self
    }

    /// Set the default bytes estimate for items whose
    /// `bytes_to_free_estimate` is zero.
    pub fn set_default_item_bytes(&mut self, bytes: u64) {
        self.default_item_bytes = bytes;
    }

    /// Current statistics.
    #[must_use]
    pub fn stats(&self) -> CleanupJobStats {
        self.stats
    }

    /// Source evidence that the job has only model/progress reclaim state.
    ///
    /// The estimate is useful operator progress, but it is not committed
    /// physical reclaim evidence and must not feed mounted availability.
    #[must_use]
    pub fn reclaim_progress_refusal(
        &self,
        validation_tier: CleanupReceiptValidationTier,
    ) -> ReclaimEvidenceRefusal {
        ReclaimEvidenceRefusal::new(
            ReclaimEvidenceProducer::CleanupJob,
            self.job_id,
            CleanupWorkItemId::NONE,
            ReclaimEvidenceRefusalReason::CleanupProgressOnly,
            self.stats.bytes_freed_estimate,
            self.stats.items_completed,
            validation_tier,
        )
    }

    /// Number of pending work items (not yet processed).
    #[must_use]
    pub fn pending_count(&self) -> u64 {
        self.work_items.len() as u64
    }

    /// Returns `true` if all items have been processed.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.cursor as usize >= self.work_items.len()
    }

    /// Process one work item to completion (mark it complete, account bytes).
    fn process_one_item(&mut self, idx: usize) {
        let item = &mut self.work_items[idx];
        if item.is_complete() {
            return;
        }
        let estimated = if item.bytes_to_free_estimate > 0 {
            item.bytes_to_free_estimate
        } else {
            self.default_item_bytes
        };
        item.mark_complete();
        item.extents_processed = 1;
        self.stats.items_completed += 1;
        self.stats.bytes_freed_estimate += estimated;
    }

    /// Build a checkpoint from current state.
    fn build_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            job_id: self.job_id,
            job_kind: JobKind::DeferredCleanup,
            epoch: 1,
            cursor_state: tidefs_types_incremental_job_core::CursorState(encode_cursor(
                self.cursor,
            )),
            progress: IncrJobProgress {
                items_processed: self.stats.items_processed,
                items_total_estimate: self.work_items.len() as u64,
                bytes_processed: self.stats.bytes_freed_estimate,
                bytes_total_estimate: 0,
                elapsed_ms: 0,
            },
        }
    }
}

impl IncrementalJob for CleanupJob {
    fn resume(checkpoint: Checkpoint) -> Result<Self, JobError>
    where
        Self: Sized,
    {
        let cursor = decode_cursor(checkpoint.cursor_state.as_bytes());
        let items_processed = checkpoint.progress.items_processed;
        let bytes_freed = checkpoint.progress.bytes_processed;
        Ok(CleanupJob {
            job_id: checkpoint.job_id,
            work_items: Vec::new(), // caller re-populates via new()
            cursor,
            stats: CleanupJobStats {
                items_processed,
                items_completed: items_processed,
                items_in_progress: 0,
                items_errored: 0,
                bytes_freed_estimate: bytes_freed,
            },
            default_item_bytes: 4096,
        })
    }

    fn step(&mut self, budget: WorkBudget) -> StepResult {
        if self.is_exhausted() {
            return StepResult::complete(self.build_checkpoint());
        }

        let limit = if budget.max_items > 0 {
            (budget.max_items as usize).min(self.work_items.len())
        } else {
            self.work_items.len()
        };

        let start = self.cursor as usize;
        let end = (start + limit).min(self.work_items.len());
        let mut processed_this_tick = 0u64;

        for idx in start..end {
            self.process_one_item(idx);
            processed_this_tick += 1;
        }

        self.cursor = end as u64;
        self.stats.items_processed += processed_this_tick;

        let checkpoint = self.build_checkpoint();
        if self.is_exhausted() {
            StepResult::complete(checkpoint)
        } else {
            StepResult::in_progress(checkpoint)
        }
    }

    fn persist_checkpoint(&self) -> Checkpoint {
        self.build_checkpoint()
    }

    fn complete(self) {}

    fn job_id(&self) -> JobId {
        self.job_id
    }

    fn job_kind(&self) -> JobKind {
        JobKind::DeferredCleanup
    }
}

// ---------------------------------------------------------------------------
// CleanupTask trait and job-execution framework
// ---------------------------------------------------------------------------

use std::collections::{BinaryHeap, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// CleanupJobReceipt -- deterministic cleanup job source evidence
// ---------------------------------------------------------------------------

/// Stable identity for one cleanup work item covered by a receipt.
///
/// The zero value is a sentinel and is rejected for completed receipts because
/// completed evidence must identify the covered work.
#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize,
)]
pub struct CleanupWorkItemId(pub u64);

impl CleanupWorkItemId {
    /// Sentinel value for an absent work item identity.
    pub const NONE: Self = CleanupWorkItemId(0);

    /// Returns `true` when this is the absent work item sentinel.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` when this is a concrete work item identity.
    #[must_use]
    pub const fn is_some(self) -> bool {
        self.0 != 0
    }
}

impl fmt::Display for CleanupWorkItemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "work-item:{}", self.0)
    }
}

/// Validation tier associated with the evidence that produced a receipt.
///
/// Labels match the repository validation schema without making this core
/// cleanup crate depend on validation runtime infrastructure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CleanupReceiptValidationTier {
    /// Tier 0: source/model/schema evidence only.
    SourceModel,
    /// Tier 1: focused cargo or unit-test evidence.
    CargoUnit,
    /// Tier 2: harness evidence without a mounted/live product path.
    HarnessOnly,
    /// Tier 3: mounted userspace runtime evidence.
    MountedUserspace,
    /// Tier 3: QEMU guest runtime evidence.
    QemuGuest,
    /// Tier 4: kernel build evidence.
    Kbuild,
    /// Tier 4: QEMU module-load evidence.
    QemuModuleLoad,
    /// Tier 5: mounted kernel VFS evidence.
    MountedKernelVfs,
    /// Tier 5: kernel block I/O evidence.
    KernelBlockIo,
    /// Tier 6: full-kernel no-daemon evidence.
    FullKernelNoDaemon,
    /// Tier 7: multi-process distributed evidence.
    MultiProcessDistributed,
}

impl CleanupReceiptValidationTier {
    /// Human-readable label used for JSON serialization.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            CleanupReceiptValidationTier::SourceModel => "source-model",
            CleanupReceiptValidationTier::CargoUnit => "cargo-unit",
            CleanupReceiptValidationTier::HarnessOnly => "harness-only",
            CleanupReceiptValidationTier::MountedUserspace => "mounted-userspace",
            CleanupReceiptValidationTier::QemuGuest => "qemu-guest",
            CleanupReceiptValidationTier::Kbuild => "kbuild",
            CleanupReceiptValidationTier::QemuModuleLoad => "qemu-module-load",
            CleanupReceiptValidationTier::MountedKernelVfs => "mounted-kernel-vfs",
            CleanupReceiptValidationTier::KernelBlockIo => "kernel-block-io",
            CleanupReceiptValidationTier::FullKernelNoDaemon => "full-kernel-no-daemon",
            CleanupReceiptValidationTier::MultiProcessDistributed => "multi-process-distributed",
        }
    }

    /// Numeric validation tier level.
    #[must_use]
    pub const fn tier_level(self) -> u8 {
        match self {
            CleanupReceiptValidationTier::SourceModel => 0,
            CleanupReceiptValidationTier::CargoUnit => 1,
            CleanupReceiptValidationTier::HarnessOnly => 2,
            CleanupReceiptValidationTier::MountedUserspace
            | CleanupReceiptValidationTier::QemuGuest => 3,
            CleanupReceiptValidationTier::Kbuild | CleanupReceiptValidationTier::QemuModuleLoad => {
                4
            }
            CleanupReceiptValidationTier::MountedKernelVfs
            | CleanupReceiptValidationTier::KernelBlockIo => 5,
            CleanupReceiptValidationTier::FullKernelNoDaemon => 6,
            CleanupReceiptValidationTier::MultiProcessDistributed => 7,
        }
    }
}

impl Default for CleanupReceiptValidationTier {
    fn default() -> Self {
        Self::SourceModel
    }
}

impl fmt::Display for CleanupReceiptValidationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Optional digest for a validation artifact that produced or checked a receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CleanupReceiptArtifactDigest {
    /// Digest algorithm name, for example `blake3`.
    pub algorithm: String,
    /// Lowercase hex digest bytes.
    pub hex: String,
}

impl CleanupReceiptArtifactDigest {
    /// Construct an artifact digest record.
    #[must_use]
    pub fn new(algorithm: impl Into<String>, hex: impl Into<String>) -> Self {
        Self {
            algorithm: algorithm.into(),
            hex: hex.into(),
        }
    }

    fn is_empty(&self) -> bool {
        self.algorithm.trim().is_empty() || self.hex.trim().is_empty()
    }
}

/// Producer that reported committed physical reclaim evidence or a refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReclaimEvidenceProducer {
    /// `tidefs-cleanup-engine` block reclaimer.
    CleanupEngine,
    /// `tidefs-data-cleaner` liveness/deadlist handoff producer.
    DataCleaner,
    /// `tidefs-cleanup-job-core` cleanup job progress model.
    CleanupJob,
}

impl ReclaimEvidenceProducer {
    /// Human-readable label used for JSON serialization.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CleanupEngine => "cleanup-engine",
            Self::DataCleaner => "data-cleaner",
            Self::CleanupJob => "cleanup-job",
        }
    }
}

impl fmt::Display for ReclaimEvidenceProducer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Typed committed physical reclaim progress.
///
/// These records mean a producer observed a successful physical release at a
/// commit boundary. Later capacity-accounting consumers may translate this
/// evidence into authority-owned deltas; the producer record itself does not
/// mutate mounted `statfs`, ENOSPC, or quota availability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommittedReclaimEvidence {
    /// Producer crate that observed the committed release.
    pub producer: ReclaimEvidenceProducer,
    /// Stable cleanup job identity that owned the release.
    pub job_id: JobId,
    /// Stable cleanup work item identity covered by the release.
    pub work_item_id: CleanupWorkItemId,
    /// Monotonic commit/TXG generation that made the release durable.
    pub commit_generation: u64,
    /// Physical units released, such as allocator blocks.
    pub units_reclaimed: u64,
    /// Physical bytes released.
    pub bytes_reclaimed: u64,
    /// Validation tier backing this evidence.
    pub validation_tier: CleanupReceiptValidationTier,
}

impl CommittedReclaimEvidence {
    /// Build committed physical reclaim evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ReclaimEvidenceError`] when the record lacks stable identity,
    /// a non-zero commit generation, or a non-zero physical release.
    pub fn physical_release(
        producer: ReclaimEvidenceProducer,
        job_id: JobId,
        work_item_id: CleanupWorkItemId,
        commit_generation: u64,
        units_reclaimed: u64,
        bytes_reclaimed: u64,
        validation_tier: CleanupReceiptValidationTier,
    ) -> Result<Self, ReclaimEvidenceError> {
        validate_committed_reclaim_context(
            job_id,
            work_item_id,
            commit_generation,
            units_reclaimed,
            bytes_reclaimed,
        )?;
        Ok(Self {
            producer,
            job_id,
            work_item_id,
            commit_generation,
            units_reclaimed,
            bytes_reclaimed,
            validation_tier,
        })
    }

    /// Returns `true` because this is committed physical reclaim evidence.
    #[must_use]
    pub const fn is_committed_physical_reclaim(&self) -> bool {
        true
    }

    /// Serialize this evidence as deterministic compact JSON.
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Reason a producer refused to publish committed reclaim evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReclaimEvidenceRefusalReason {
    /// The producer has only an estimate.
    EstimatedOnly,
    /// Reclaim is queued or staged but not physically released.
    QueuedOnly,
    /// The producer has cleanup progress counters, not a committed release.
    CleanupProgressOnly,
    /// The producer drained model/liveness state without releasing blocks.
    ModelOnlyDrain,
    /// A physical-release path completed without reporting released bytes.
    NoCommittedPhysicalRelease,
}

/// Typed refusal that explains why a producer cannot increase availability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReclaimEvidenceRefusal {
    /// Producer that refused to publish committed evidence.
    pub producer: ReclaimEvidenceProducer,
    /// Job identity available to the refusing producer.
    pub job_id: JobId,
    /// Work-item identity available to the refusing producer, or `NONE`.
    pub work_item_id: CleanupWorkItemId,
    /// Why this is not committed physical reclaim evidence.
    pub reason: ReclaimEvidenceRefusalReason,
    /// Producer-local estimated bytes, when available.
    pub estimated_bytes: u64,
    /// Queued, staged, or progress units covered by this refusal.
    pub units: u64,
    /// Validation tier backing this refusal.
    pub validation_tier: CleanupReceiptValidationTier,
}

impl ReclaimEvidenceRefusal {
    /// Build a reclaim evidence refusal.
    #[must_use]
    pub const fn new(
        producer: ReclaimEvidenceProducer,
        job_id: JobId,
        work_item_id: CleanupWorkItemId,
        reason: ReclaimEvidenceRefusalReason,
        estimated_bytes: u64,
        units: u64,
        validation_tier: CleanupReceiptValidationTier,
    ) -> Self {
        Self {
            producer,
            job_id,
            work_item_id,
            reason,
            estimated_bytes,
            units,
            validation_tier,
        }
    }

    /// Returns `false` because refusals never authorize mounted availability.
    #[must_use]
    pub const fn is_committed_physical_reclaim(&self) -> bool {
        false
    }

    /// Serialize this refusal as deterministic compact JSON.
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Error returned when committed reclaim evidence is malformed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReclaimEvidenceError {
    /// Committed evidence must name a real job.
    MissingJobId,
    /// Committed evidence must name covered work.
    MissingWorkItemId,
    /// Commit generation must be non-zero.
    MissingCommitGeneration,
    /// Physical release unit count must be non-zero.
    ZeroUnitsReclaimed,
    /// Physical released bytes must be non-zero.
    ZeroBytesReclaimed,
}

impl fmt::Display for ReclaimEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingJobId => f.write_str("committed reclaim evidence is missing a job id"),
            Self::MissingWorkItemId => {
                f.write_str("committed reclaim evidence is missing a work item id")
            }
            Self::MissingCommitGeneration => {
                f.write_str("committed reclaim evidence is missing a commit generation")
            }
            Self::ZeroUnitsReclaimed => {
                f.write_str("committed reclaim evidence has zero reclaimed units")
            }
            Self::ZeroBytesReclaimed => {
                f.write_str("committed reclaim evidence has zero reclaimed bytes")
            }
        }
    }
}

impl std::error::Error for ReclaimEvidenceError {}

fn validate_committed_reclaim_context(
    job_id: JobId,
    work_item_id: CleanupWorkItemId,
    commit_generation: u64,
    units_reclaimed: u64,
    bytes_reclaimed: u64,
) -> Result<(), ReclaimEvidenceError> {
    if job_id.is_none() {
        return Err(ReclaimEvidenceError::MissingJobId);
    }
    if work_item_id.is_none() {
        return Err(ReclaimEvidenceError::MissingWorkItemId);
    }
    if commit_generation == 0 {
        return Err(ReclaimEvidenceError::MissingCommitGeneration);
    }
    if units_reclaimed == 0 {
        return Err(ReclaimEvidenceError::ZeroUnitsReclaimed);
    }
    if bytes_reclaimed == 0 {
        return Err(ReclaimEvidenceError::ZeroBytesReclaimed);
    }
    Ok(())
}

/// Cleanup job receipt state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupJobReceiptState {
    /// A cleanup job attempt was admitted for execution.
    Admitted,
    /// A cleanup job attempt was skipped before doing work.
    Skipped,
    /// A cleanup job attempt will be retried in a later generation.
    Retried,
    /// A cleanup job attempt failed terminally.
    Failed,
    /// A cleanup job attempt completed its covered work.
    Completed,
}

impl CleanupJobReceiptState {
    fn requires_reason(self) -> bool {
        matches!(self, Self::Skipped | Self::Failed)
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Skipped | Self::Failed | Self::Completed)
    }

    fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Admitted => {
                matches!(
                    next,
                    Self::Skipped | Self::Retried | Self::Failed | Self::Completed
                )
            }
            Self::Retried => matches!(next, Self::Admitted),
            Self::Skipped | Self::Failed | Self::Completed => false,
        }
    }
}

/// Deterministic source receipt for a cleanup job state decision.
///
/// The `work_item_id` field is also the covered work identity for completed
/// receipts. These records are source evidence only; higher tiers must attach
/// cleanup queue replay and runtime artifacts before claiming mounted cleanup
/// correctness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CleanupJobReceipt {
    /// Stable cleanup job identifier.
    pub job_id: JobId,
    /// Stable cleanup work item identifier.
    pub work_item_id: CleanupWorkItemId,
    /// Receipt state being recorded.
    pub state: CleanupJobReceiptState,
    /// Human-readable reason for the decision.
    pub reason: String,
    /// Monotonic attempt generation for this job/work item pair.
    pub attempt_generation: u64,
    /// Validation tier backing this receipt.
    pub validation_tier: CleanupReceiptValidationTier,
    /// Optional digest for the artifact that produced or checked the receipt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_digest: Option<CleanupReceiptArtifactDigest>,
}

impl CleanupJobReceipt {
    /// Build a cleanup job receipt.
    #[must_use]
    pub fn new(
        state: CleanupJobReceiptState,
        job_id: JobId,
        work_item_id: CleanupWorkItemId,
        reason: impl Into<String>,
        attempt_generation: u64,
        validation_tier: CleanupReceiptValidationTier,
    ) -> Self {
        Self {
            job_id,
            work_item_id,
            state,
            reason: reason.into(),
            attempt_generation,
            validation_tier,
            artifact_digest: None,
        }
    }

    /// Build an admitted receipt.
    #[must_use]
    pub fn admitted(
        job_id: JobId,
        work_item_id: CleanupWorkItemId,
        reason: impl Into<String>,
        attempt_generation: u64,
        validation_tier: CleanupReceiptValidationTier,
    ) -> Self {
        Self::new(
            CleanupJobReceiptState::Admitted,
            job_id,
            work_item_id,
            reason,
            attempt_generation,
            validation_tier,
        )
    }

    /// Build a skipped receipt.
    #[must_use]
    pub fn skipped(
        job_id: JobId,
        work_item_id: CleanupWorkItemId,
        reason: impl Into<String>,
        attempt_generation: u64,
        validation_tier: CleanupReceiptValidationTier,
    ) -> Self {
        Self::new(
            CleanupJobReceiptState::Skipped,
            job_id,
            work_item_id,
            reason,
            attempt_generation,
            validation_tier,
        )
    }

    /// Build a retried receipt.
    #[must_use]
    pub fn retried(
        job_id: JobId,
        work_item_id: CleanupWorkItemId,
        reason: impl Into<String>,
        attempt_generation: u64,
        validation_tier: CleanupReceiptValidationTier,
    ) -> Self {
        Self::new(
            CleanupJobReceiptState::Retried,
            job_id,
            work_item_id,
            reason,
            attempt_generation,
            validation_tier,
        )
    }

    /// Build a failed receipt.
    #[must_use]
    pub fn failed(
        job_id: JobId,
        work_item_id: CleanupWorkItemId,
        reason: impl Into<String>,
        attempt_generation: u64,
        validation_tier: CleanupReceiptValidationTier,
    ) -> Self {
        Self::new(
            CleanupJobReceiptState::Failed,
            job_id,
            work_item_id,
            reason,
            attempt_generation,
            validation_tier,
        )
    }

    /// Build a completed receipt.
    #[must_use]
    pub fn completed(
        job_id: JobId,
        work_item_id: CleanupWorkItemId,
        reason: impl Into<String>,
        attempt_generation: u64,
        validation_tier: CleanupReceiptValidationTier,
    ) -> Self {
        Self::new(
            CleanupJobReceiptState::Completed,
            job_id,
            work_item_id,
            reason,
            attempt_generation,
            validation_tier,
        )
    }

    /// Attach an artifact digest to this receipt.
    #[must_use]
    pub fn with_artifact_digest(mut self, artifact_digest: CleanupReceiptArtifactDigest) -> Self {
        self.artifact_digest = Some(artifact_digest);
        self
    }

    /// Validate this receipt independent of any prior receipt chain.
    pub fn validate(&self) -> Result<(), CleanupJobReceiptValidationError> {
        validate_receipt_at_index(self, 0)
    }

    /// Serialize this receipt as deterministic compact JSON.
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize a receipt from JSON bytes.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

/// Error returned by cleanup job receipt validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CleanupJobReceiptValidationError {
    /// Receipt is missing a concrete job id.
    MissingJobId { index: usize },
    /// Receipt is missing a concrete work item id.
    MissingWorkItemId { index: usize },
    /// Skipped or failed receipts must include non-empty reason text.
    MissingReasonText {
        index: usize,
        state: CleanupJobReceiptState,
    },
    /// Completed receipts must identify the covered work.
    MissingCoveredWorkIdentity { index: usize },
    /// Receipt artifact digest was present but incomplete.
    EmptyArtifactDigest { index: usize },
    /// A chain mixed receipts for different job/work item identities.
    ReceiptIdentityMismatch {
        index: usize,
        expected_job_id: JobId,
        actual_job_id: JobId,
        expected_work_item_id: CleanupWorkItemId,
        actual_work_item_id: CleanupWorkItemId,
    },
    /// Attempt generation moved backward or failed to advance after retry.
    StaleAttemptGeneration {
        index: usize,
        previous: u64,
        current: u64,
    },
    /// The adjacent receipt states are not part of the known state machine.
    UnknownStateTransition {
        index: usize,
        from: CleanupJobReceiptState,
        to: CleanupJobReceiptState,
    },
}

impl fmt::Display for CleanupJobReceiptValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingJobId { index } => {
                write!(f, "cleanup receipt {index} is missing a job id")
            }
            Self::MissingWorkItemId { index } => {
                write!(f, "cleanup receipt {index} is missing a work item id")
            }
            Self::MissingReasonText { index, state } => {
                write!(
                    f,
                    "cleanup receipt {index} in state {state:?} is missing reason text"
                )
            }
            Self::MissingCoveredWorkIdentity { index } => {
                write!(
                    f,
                    "completed cleanup receipt {index} is missing covered work identity"
                )
            }
            Self::EmptyArtifactDigest { index } => {
                write!(f, "cleanup receipt {index} has an empty artifact digest")
            }
            Self::ReceiptIdentityMismatch {
                index,
                expected_job_id,
                actual_job_id,
                expected_work_item_id,
                actual_work_item_id,
            } => {
                write!(
                    f,
                    "cleanup receipt {index} identity changed from {expected_job_id}/{expected_work_item_id} to {actual_job_id}/{actual_work_item_id}"
                )
            }
            Self::StaleAttemptGeneration {
                index,
                previous,
                current,
            } => {
                write!(
                    f,
                    "cleanup receipt {index} has stale attempt generation {current}; previous was {previous}"
                )
            }
            Self::UnknownStateTransition { index, from, to } => {
                write!(
                    f,
                    "cleanup receipt {index} has unknown transition {from:?} -> {to:?}"
                )
            }
        }
    }
}

impl std::error::Error for CleanupJobReceiptValidationError {}

/// Validate a receipt chain for one job/work item identity.
///
/// The validator rejects invalid single-record fields, mixed identities, stale
/// attempt generations, and state transitions outside the cleanup receipt state
/// machine.
pub fn validate_cleanup_job_receipts(
    receipts: &[CleanupJobReceipt],
) -> Result<(), CleanupJobReceiptValidationError> {
    let Some(first) = receipts.first() else {
        return Ok(());
    };
    validate_receipt_at_index(first, 0)?;

    for (index, pair) in receipts.windows(2).enumerate() {
        let previous = &pair[0];
        let current = &pair[1];
        let current_index = index + 1;
        validate_receipt_at_index(current, current_index)?;

        if previous.job_id != current.job_id || previous.work_item_id != current.work_item_id {
            return Err(CleanupJobReceiptValidationError::ReceiptIdentityMismatch {
                index: current_index,
                expected_job_id: previous.job_id,
                actual_job_id: current.job_id,
                expected_work_item_id: previous.work_item_id,
                actual_work_item_id: current.work_item_id,
            });
        }

        if current.attempt_generation < previous.attempt_generation
            || (previous.state == CleanupJobReceiptState::Retried
                && current.state == CleanupJobReceiptState::Admitted
                && current.attempt_generation <= previous.attempt_generation)
        {
            return Err(CleanupJobReceiptValidationError::StaleAttemptGeneration {
                index: current_index,
                previous: previous.attempt_generation,
                current: current.attempt_generation,
            });
        }

        if previous.state.is_terminal() || !previous.state.can_transition_to(current.state) {
            return Err(CleanupJobReceiptValidationError::UnknownStateTransition {
                index: current_index,
                from: previous.state,
                to: current.state,
            });
        }
    }

    Ok(())
}

fn validate_receipt_at_index(
    receipt: &CleanupJobReceipt,
    index: usize,
) -> Result<(), CleanupJobReceiptValidationError> {
    if receipt.job_id.is_none() {
        return Err(CleanupJobReceiptValidationError::MissingJobId { index });
    }
    if receipt.state == CleanupJobReceiptState::Completed && receipt.work_item_id.is_none() {
        return Err(CleanupJobReceiptValidationError::MissingCoveredWorkIdentity { index });
    }
    if receipt.work_item_id.is_none() {
        return Err(CleanupJobReceiptValidationError::MissingWorkItemId { index });
    }
    if receipt.state.requires_reason() && receipt.reason.trim().is_empty() {
        return Err(CleanupJobReceiptValidationError::MissingReasonText {
            index,
            state: receipt.state,
        });
    }
    if receipt
        .artifact_digest
        .as_ref()
        .is_some_and(CleanupReceiptArtifactDigest::is_empty)
    {
        return Err(CleanupJobReceiptValidationError::EmptyArtifactDigest { index });
    }
    Ok(())
}

/// Result of executing a single cleanup task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobResult {
    /// Task completed successfully.
    Ok(()),
    /// Task failed but may succeed on retry, with an error description.
    Retryable(String),
    /// Task failed irrecoverably, with an error description.
    Fatal(String),
}

/// Lifecycle state machine for a cleanup task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobState {
    /// Not yet started.
    Pending,
    /// Currently executing.
    Running,
    /// Completed successfully.
    Completed,
    /// Failed irrecoverably after `attempt` tries.
    Failed { attempt: u32 },
    /// Eligible for retry after a transient failure.
    Retryable,
}

/// Configuration for retry with exponential backoff and jitter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of execution attempts (including the first).
    pub max_attempts: u32,
    /// Base backoff delay in milliseconds.
    pub base_delay_ms: u64,
    /// Maximum backoff delay in milliseconds.
    pub max_delay_ms: u64,
}

impl RetryConfig {
    /// Default: 3 attempts, 100 ms base, 5 s max.
    pub const DEFAULT: Self = Self {
        max_attempts: 3,
        base_delay_ms: 100,
        max_delay_ms: 5_000,
    };

    /// Compute next backoff delay for attempt `n` (1-indexed).
    ///
    /// Exponential backoff: `base * 2^(n-1)` capped at `max_delay_ms`,
    /// with deterministic jitter derived from attempt parity.
    pub fn next_delay(&self, attempt: u32) -> u64 {
        if attempt == 0 {
            return 0;
        }
        let exp = (attempt - 1).min(20);
        let raw = self.base_delay_ms.saturating_mul(1u64 << exp);
        // Apply deterministic jitter before capping
        let jitter = raw / 8;
        let with_jitter = if attempt % 2 == 0 {
            raw.saturating_sub(jitter)
        } else {
            raw.saturating_add(jitter)
        };
        with_jitter.min(self.max_delay_ms)
    }

    /// True when no more retries are allowed.
    pub fn is_exhausted(&self, attempt: u32) -> bool {
        attempt >= self.max_attempts
    }
}

/// Trait for typed cleanup work units.
///
/// Each implementation performs a single cleanup operation (segment
/// compaction, dead-object reclamation, snapshot pruning).  The scheduler
/// calls `execute` and uses `JobResult` to drive retry / failure.
pub trait CleanupTask: std::fmt::Debug {
    /// Execute the work.  Return `JobResult::Ok(())` on success,
    /// `JobResult::Retryable(...)` for transient failures, or
    /// `JobResult::Fatal(...)` for unrecoverable errors.
    fn execute(&mut self) -> JobResult;

    /// Undo partial side-effects after a fatal failure.  Called at most
    /// once, after `execute` returns `Fatal`.
    fn rollback(&mut self);

    /// Human-readable description for logging and observability.
    fn describe(&self) -> &str;
}

/// Progress checkpoint for crash-safe resume (JSON-serializable).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobProgress {
    /// Opaque job identifier.
    pub job_id: String,
    /// Execution attempts so far.
    pub attempt: u32,
    /// Most recent error message, if any.
    pub last_error: Option<String>,
    /// Seconds since UNIX epoch when this checkpoint was written.
    pub timestamp_secs: u64,
}

impl JobProgress {
    /// Create a new progress record at the current wall-clock time.
    pub fn new(job_id: String) -> Self {
        let timestamp_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            job_id,
            attempt: 0,
            last_error: None,
            timestamp_secs,
        }
    }

    /// Serialise to a JSON byte vector.
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialise from a JSON byte slice.
    pub fn from_json(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

// ---------------------------------------------------------------------------
// Priority type for scheduler ordering (lower = higher urgency)
// ---------------------------------------------------------------------------

/// Cleanup priority level.  Lower numeric value means higher urgency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Priority {
    /// Critical — run immediately (e.g. space exhaustion recovery).
    Critical = 0,
    /// High — run before normal work.
    High = 1,
    /// Normal — standard background cleanup.
    Normal = 2,
    /// Low — best-effort, only when idle.
    Low = 3,
}

// ---------------------------------------------------------------------------
// CleanupEntry -- metadata for the priority queue
// ---------------------------------------------------------------------------

/// Entry in the scheduler's priority queue.  `Ord` is reversed: lower
/// priority value equals higher urgency, so `BinaryHeap` (max-heap) pops
/// the most-urgent entry first.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CleanupEntry {
    pub priority: Priority,
    pub job_id: String,
    pub state: JobState,
    pub retry_config: RetryConfig,
    pub attempt: u32,
}

impl CleanupEntry {
    pub fn new(job_id: String, priority: Priority, retry_config: RetryConfig) -> Self {
        Self {
            priority,
            job_id,
            state: JobState::Pending,
            retry_config,
            attempt: 0,
        }
    }
}

impl Ord for CleanupEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .priority
            .cmp(&self.priority)
            .then_with(|| self.job_id.cmp(&other.job_id))
    }
}

impl PartialOrd for CleanupEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// ---------------------------------------------------------------------------
// CleanupScheduler -- priority-ordered dispatcher with retry
// ---------------------------------------------------------------------------

/// Priority-ordered scheduler for `CleanupTask` implementations.
///
/// Maintains a bounded-capacity priority queue with an associated job store.
/// `drain()` processes all ready jobs; `drain_one()` processes the single
/// highest-priority job.  Lifecycle is tracked per-entry and progress can
/// be serialised via `JobProgress`.
pub struct CleanupScheduler {
    queue: BinaryHeap<CleanupEntry>,
    jobs: HashMap<String, Box<dyn CleanupTask>>,
    capacity: usize,
}

impl CleanupScheduler {
    /// Create a new scheduler with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: BinaryHeap::new(),
            jobs: HashMap::new(),
            capacity,
        }
    }

    /// Number of jobs in the queue.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// True when the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Maximum queue capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Submit a job.  Returns `Ok(())` or `Err(job)` when at capacity.
    pub fn submit(
        &mut self,
        job: Box<dyn CleanupTask>,
        priority: Priority,
        retry_config: RetryConfig,
    ) -> Result<(), Box<dyn CleanupTask>> {
        if self.queue.len() >= self.capacity {
            return Err(job);
        }
        let job_id = job.describe().to_string();
        let entry = CleanupEntry::new(job_id.clone(), priority, retry_config);
        self.queue.push(entry);
        self.jobs.insert(job_id, job);
        Ok(())
    }

    /// Drain all jobs in priority order.  Returns progress checkpoints for
    /// every job processed.  Retryable jobs are re-enqueued.
    pub fn drain(&mut self) -> Vec<JobProgress> {
        let mut results = Vec::new();
        let mut retries: Vec<CleanupEntry> = Vec::new();

        while let Some(mut entry) = self.queue.pop() {
            let progress = self.execute_entry(&mut entry);
            if entry.state == JobState::Retryable {
                retries.push(entry);
            }
            results.push(progress);
        }

        for entry in retries {
            self.queue.push(entry);
        }

        results
    }

    /// Process the single highest-priority job.  Returns `None` when empty.
    pub fn drain_one(&mut self) -> Option<JobProgress> {
        let mut entry = self.queue.pop()?;
        let progress = self.execute_entry(&mut entry);
        if entry.state == JobState::Retryable {
            self.queue.push(entry);
        }
        Some(progress)
    }

    fn execute_entry(&mut self, entry: &mut CleanupEntry) -> JobProgress {
        entry.state = JobState::Running;
        entry.attempt += 1;

        let job = match self.jobs.get_mut(&entry.job_id) {
            Some(j) => j,
            None => {
                entry.state = JobState::Failed {
                    attempt: entry.attempt,
                };
                let mut progress = JobProgress::new(entry.job_id.clone());
                progress.attempt = entry.attempt;
                progress.last_error = Some("job not found in scheduler".into());
                return progress;
            }
        };

        let result = job.execute();

        let mut progress = JobProgress::new(entry.job_id.clone());
        progress.attempt = entry.attempt;

        match result {
            JobResult::Ok(()) => {
                entry.state = JobState::Completed;
            }
            JobResult::Retryable(err) => {
                progress.last_error = Some(err.clone());
                if entry.retry_config.is_exhausted(entry.attempt) {
                    entry.state = JobState::Failed {
                        attempt: entry.attempt,
                    };
                } else {
                    entry.state = JobState::Retryable;
                }
            }
            JobResult::Fatal(err) => {
                progress.last_error = Some(err.clone());
                entry.state = JobState::Failed {
                    attempt: entry.attempt,
                };
                job.rollback();
            }
        }

        progress
    }

    /// Serialise progress for all known jobs as JSON.
    pub fn persist_all(&self) -> Vec<u8> {
        let records: Vec<JobProgress> = self
            .queue
            .iter()
            .map(|e| {
                let mut p = JobProgress::new(e.job_id.clone());
                p.attempt = e.attempt;
                p
            })
            .collect();
        serde_json::to_vec(&records).unwrap_or_default()
    }
}
// ---------------------------------------------------------------------------
// CleanupContext — context for deferred cleanup job execution
// ---------------------------------------------------------------------------

/// Execution context passed to [`DeferredCleanupJob::execute`].
///
/// Contains the commit_group epoch identifier so jobs can adjust their behaviour
/// (e.g. skip work already done in the current epoch).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupContext {
    /// Transaction-group identifier that triggered this dispatch.
    pub txg_id: u64,
    /// Monotonic epoch counter.
    pub epoch: u64,
    /// Wall-clock seconds since UNIX epoch at dispatch time.
    pub timestamp_secs: u64,
}

impl CleanupContext {
    /// Create a new context for the given commit_group and epoch.
    #[must_use]
    pub fn new(txg_id: u64, epoch: u64) -> Self {
        let timestamp_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            txg_id,
            epoch,
            timestamp_secs,
        }
    }

    /// Returns `true` if this context is newer than `other` by epoch.
    #[must_use]
    pub fn is_newer_than(&self, other: &Self) -> bool {
        self.epoch > other.epoch
    }
}

// ---------------------------------------------------------------------------
// CleanupError
// ---------------------------------------------------------------------------

/// Error returned by [`DeferredCleanupJob::execute`] on failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupError {
    /// Human-readable description.
    pub message: String,
    /// Phase in which the error occurred.
    pub phase: CleanupPhase,
    /// True if the job should be retried in the next epoch.
    pub retryable: bool,
}

impl CleanupError {
    /// Create a retryable error.
    #[must_use]
    pub fn retryable(message: impl Into<String>, phase: CleanupPhase) -> Self {
        Self {
            message: message.into(),
            phase,
            retryable: true,
        }
    }

    /// Create a fatal (non-retryable) error.
    #[must_use]
    pub fn fatal(message: impl Into<String>, phase: CleanupPhase) -> Self {
        Self {
            message: message.into(),
            phase,
            retryable: false,
        }
    }
}

impl fmt::Display for CleanupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CleanupError in phase {:?}: {} [retryable={}]",
            self.phase, self.message, self.retryable
        )
    }
}

impl std::error::Error for CleanupError {}

// ---------------------------------------------------------------------------
// JobOutcome
// ---------------------------------------------------------------------------

/// Result of executing a single [`DeferredCleanupJob`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JobOutcome {
    /// Job completed successfully. All side-effects are durable.
    Completed,
    /// Job made partial progress but is not yet finished.
    /// The scheduler will re-invoke it in the next epoch.
    Incomplete,
    /// Job encountered a transient failure and should be retried.
    Retryable(CleanupError),
    /// Job encountered an irrecoverable failure and must be removed.
    Fatal(CleanupError),
}

impl JobOutcome {
    /// Returns `true` if this outcome means the job should not be retried.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, JobOutcome::Completed | JobOutcome::Fatal(_))
    }

    /// Returns `true` if the job completed successfully.
    #[must_use]
    pub fn is_completed(&self) -> bool {
        matches!(self, JobOutcome::Completed)
    }
}

// ---------------------------------------------------------------------------
// CleanupPhase — ordered dispatch phases within a commit_group epoch
// ---------------------------------------------------------------------------

/// Ordered phases for deferred cleanup dispatch within a single commit_group epoch.
///
/// Phases are dispatched sequentially: all `ExtentFree` jobs complete before
/// any `SpacemapUpdate` jobs start, and so on. This ordering guarantees that
/// space-accounting updates see the up-to-date free state.
///
/// The numeric discriminants encode the dispatch order (ascending).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum CleanupPhase {
    /// Free extents belonging to deleted or truncated objects.
    ExtentFree = 0,
    /// Update spacemap accounting after extent frees.
    SpacemapUpdate = 1,
    /// Register dead objects for later reclamation by the segment cleaner.
    DeadObjectRegister = 2,
    /// Reap orphaned metadata (inode tombstones, empty directory blocks).
    OrphanReap = 3,
}

impl CleanupPhase {
    /// Number of defined phases.
    pub const COUNT: usize = 4;

    /// All phases in dispatch order.
    pub const ALL: [CleanupPhase; 4] = [
        CleanupPhase::ExtentFree,
        CleanupPhase::SpacemapUpdate,
        CleanupPhase::DeadObjectRegister,
        CleanupPhase::OrphanReap,
    ];

    /// Returns the next phase, or `None` if this is the last.
    #[must_use]
    pub const fn next(self) -> Option<CleanupPhase> {
        match self {
            CleanupPhase::ExtentFree => Some(CleanupPhase::SpacemapUpdate),
            CleanupPhase::SpacemapUpdate => Some(CleanupPhase::DeadObjectRegister),
            CleanupPhase::DeadObjectRegister => Some(CleanupPhase::OrphanReap),
            CleanupPhase::OrphanReap => None,
        }
    }

    /// Returns the first phase in dispatch order.
    #[must_use]
    pub const fn first() -> CleanupPhase {
        CleanupPhase::ExtentFree
    }

    /// Returns the last phase in dispatch order.
    #[must_use]
    pub const fn last() -> CleanupPhase {
        CleanupPhase::OrphanReap
    }
}

// ---------------------------------------------------------------------------
// DeferredCleanupJob trait
// ---------------------------------------------------------------------------

/// A single deferred cleanup operation executed after a commit_group commit.
///
/// Implementations must be idempotent: calling `execute` twice with the same
/// [`CleanupContext`] must produce an equivalent outcome. The scheduler may
/// re-invoke a job after a crash or retry.
///
/// # Idempotency contract
///
/// - If the job has already completed its work for `ctx.txg_id`, it should
///   return `JobOutcome::Completed` immediately.
/// - If the job fails transiently, it should return
///   `JobOutcome::Retryable`. The scheduler will re-invoke in the next
///   epoch (up to the configured retry limit).
/// - If the job encounters an irrecoverable error, it should return
///   `JobOutcome::Fatal`. The scheduler removes it permanently.
pub trait DeferredCleanupJob: fmt::Debug {
    /// Execute this job in the given commit_group context.
    ///
    /// Returns the outcome of execution. The scheduler uses the outcome to
    /// decide whether to retain, retry, or remove the job.
    fn execute(&mut self, ctx: &CleanupContext) -> JobOutcome;

    /// The dispatch phase this job belongs to.
    fn phase(&self) -> CleanupPhase;

    /// Unique identifier for logging and observability.
    fn job_id(&self) -> &str;

    /// Priority within the phase (lower value = higher priority).
    /// Default: 0 (normal priority).
    fn priority(&self) -> u32 {
        0
    }
}

// ---------------------------------------------------------------------------
// TxgCommitObserver — trait-based integration with CommitGroupCoordinator
// ---------------------------------------------------------------------------

/// Observer notified when a commit_group commits.
///
/// The [`CommitGroupCoordinator`] (or its wrapper) calls [`on_commit`] after
/// successfully anchoring a commit group. Implementations — including
/// [`JobScheduler`] — use this signal to dispatch registered deferred
/// cleanup jobs.
///
/// [`CommitGroupCoordinator`]: tidefs_flow_commit_coordinator
/// [`on_commit`]: TxgCommitObserver::on_commit
pub trait TxgCommitObserver: fmt::Debug {
    /// Called after a transaction group commits successfully.
    ///
    /// `txg_id` is the global transaction-group identifier.
    /// `epoch` is the monotonic epoch counter for the committing dataset/pool.
    fn on_commit(&mut self, txg_id: u64, epoch: u64);

    /// Human-readable name for logging.
    fn name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// JobScheduler — phase-ordered deferred cleanup dispatcher
// ---------------------------------------------------------------------------

/// Phase-ordered scheduler for [`DeferredCleanupJob`] implementations.
///
/// Registered jobs are grouped by [`CleanupPhase`]. When a commit_group commit signal
/// arrives via [`TxgCommitObserver::on_commit`], the scheduler dispatches
/// all non-terminal jobs phase by phase: `ExtentFree` first, then
/// `SpacemapUpdate`, `DeadObjectRegister`, and `OrphanReap`.
///
/// # Lifecycle
///
/// 1. Call [`register`](Self::register) to add jobs.
/// 2. Wire the scheduler as a [`TxgCommitObserver`].
/// 3. When `on_commit` fires, all registered jobs are dispatched in phase
///    order.
/// 4. Completed and fatal jobs are automatically removed.
/// 5. Retryable and incomplete jobs remain registered for the next epoch.
///
/// # Retry
///
/// Jobs that return `Retryable` are retried up to `max_retries` times
/// (default: 3). Exhausted retries are treated as fatal and removed.
pub struct JobScheduler {
    /// Jobs organised by phase.
    phases: [Vec<ScheduledJob>; CleanupPhase::COUNT],
    /// Maximum retry attempts per job (including the initial attempt).
    max_retries: u32,
    /// Most recent commit_group context (updated on commit).
    last_context: Option<CleanupContext>,
    /// Total jobs dispatched (cumulative).
    total_dispatched: u64,
    /// Total jobs completed (cumulative).
    total_completed: u64,
    /// Total jobs failed fatally (cumulative).
    total_fatal: u64,
}

/// Internal wrapper: a registered job plus its retry state.
struct ScheduledJob {
    job: Box<dyn DeferredCleanupJob>,
    attempts: u32,
    last_outcome: Option<JobOutcome>,
}

impl ScheduledJob {
    fn new(job: Box<dyn DeferredCleanupJob>) -> Self {
        Self {
            job,
            attempts: 0,
            last_outcome: None,
        }
    }

    fn is_terminal(&self) -> bool {
        self.last_outcome
            .as_ref()
            .is_some_and(JobOutcome::is_terminal)
    }
}

impl JobScheduler {
    /// Create a new scheduler with the default retry limit (3).
    #[must_use]
    pub fn new() -> Self {
        Self {
            phases: [
                Vec::new(), // ExtentFree
                Vec::new(), // SpacemapUpdate
                Vec::new(), // DeadObjectRegister
                Vec::new(), // OrphanReap
            ],
            max_retries: 3,
            last_context: None,
            total_dispatched: 0,
            total_completed: 0,
            total_fatal: 0,
        }
    }

    /// Set the maximum retry attempts per job.
    pub fn set_max_retries(&mut self, max: u32) {
        self.max_retries = max;
    }

    /// Number of registered (non-terminal) jobs.
    #[must_use]
    pub fn job_count(&self) -> usize {
        self.phases
            .iter()
            .map(|p| p.iter().filter(|j| !j.is_terminal()).count())
            .sum()
    }

    /// Returns `true` if no non-terminal jobs are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.job_count() == 0
    }

    /// Register a deferred cleanup job.
    ///
    /// The job is placed in the bucket for its declared [`DeferredCleanupJob::phase`].
    pub fn register(&mut self, job: Box<dyn DeferredCleanupJob>) {
        let phase_idx = job.phase() as usize;
        self.phases[phase_idx].push(ScheduledJob::new(job));
    }

    /// Most recent context, if any commit has been observed.
    #[must_use]
    pub fn last_context(&self) -> Option<&CleanupContext> {
        self.last_context.as_ref()
    }

    /// Cumulative dispatch count.
    #[must_use]
    pub fn total_dispatched(&self) -> u64 {
        self.total_dispatched
    }

    /// Cumulative completed count.
    #[must_use]
    pub fn total_completed(&self) -> u64 {
        self.total_completed
    }

    /// Cumulative fatal-failure count.
    #[must_use]
    pub fn total_fatal(&self) -> u64 {
        self.total_fatal
    }

    /// Dispatch all non-terminal jobs for a single phase.
    ///
    /// Returns the outcomes keyed by job_id. Terminal jobs are removed;
    /// retryable/incomplete jobs remain for the next epoch.
    fn dispatch_phase(&mut self, ctx: &CleanupContext, phase: CleanupPhase) {
        let phase_idx = phase as usize;
        let mut phase_jobs = std::mem::take(&mut self.phases[phase_idx]);
        let mut retained: Vec<ScheduledJob> = Vec::new();

        // Sort by priority (lower = higher priority)
        phase_jobs.sort_by_key(|j| (j.job.priority(), j.job.job_id().to_string()));

        for mut entry in phase_jobs {
            if entry.is_terminal() {
                continue; // already done or fatal, skip
            }

            entry.attempts += 1;
            self.total_dispatched += 1;

            let outcome = entry.job.execute(ctx);
            entry.last_outcome = Some(outcome.clone());

            match &outcome {
                JobOutcome::Completed => {
                    self.total_completed += 1;
                    // Terminal: drop the job
                }
                JobOutcome::Incomplete => {
                    // Retain for next epoch (no retry counter consumed)
                    retained.push(entry);
                }
                JobOutcome::Retryable(_) => {
                    if entry.attempts >= self.max_retries {
                        self.total_fatal += 1;
                        // Exhausted retries: drop
                    } else {
                        retained.push(entry);
                    }
                }
                JobOutcome::Fatal(_) => {
                    self.total_fatal += 1;
                    // Terminal: drop
                }
            }
        }

        self.phases[phase_idx] = retained;
    }

    /// Collect diagnostics for all currently registered jobs.
    ///
    /// Returns tuples of (job_id, phase, attempts, last_outcome).
    #[must_use]
    pub fn diagnostics(&self) -> Vec<(String, CleanupPhase, u32, Option<JobOutcome>)> {
        let mut out = Vec::new();
        for (phase_idx, jobs) in self.phases.iter().enumerate() {
            for entry in jobs {
                let phase = match phase_idx {
                    0 => CleanupPhase::ExtentFree,
                    1 => CleanupPhase::SpacemapUpdate,
                    2 => CleanupPhase::DeadObjectRegister,
                    3 => CleanupPhase::OrphanReap,
                    _ => unreachable!(),
                };
                out.push((
                    entry.job.job_id().to_string(),
                    phase,
                    entry.attempts,
                    entry.last_outcome.clone(),
                ));
            }
        }
        out
    }
}

impl Default for JobScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for JobScheduler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JobScheduler")
            .field("job_count", &self.job_count())
            .field("max_retries", &self.max_retries)
            .field("last_context", &self.last_context)
            .field("total_dispatched", &self.total_dispatched)
            .field("total_completed", &self.total_completed)
            .field("total_fatal", &self.total_fatal)
            .finish()
    }
}

impl TxgCommitObserver for JobScheduler {
    fn on_commit(&mut self, txg_id: u64, epoch: u64) {
        let ctx = CleanupContext::new(txg_id, epoch);
        self.last_context = Some(ctx.clone());

        // Dispatch jobs phase by phase
        for phase in CleanupPhase::ALL {
            self.dispatch_phase(&ctx, phase);
        }
    }

    fn name(&self) -> &str {
        "JobScheduler"
    }
}

// ---------------------------------------------------------------------------
// BtreeCleanupDeferredJob — deferred B+tree node maintenance
// ---------------------------------------------------------------------------

use tidefs_cleanup_queue_core::{BtreeCleanupEntry, BtreeCleanupQueue};

/// A [`DeferredCleanupJob`] that processes pending entries from a
/// [`BtreeCleanupQueue`] on each commit group boundary.
///
/// On `execute()`, the job dequeues up to `batch_size` pending entries,
/// marks them as processed, and returns the outcome. When the queue is
/// exhausted, it returns `Completed`.
///
/// # Idempotency
///
/// Entries already marked as processed are skipped. Calling `execute()`
/// with an empty queue returns `Completed` immediately.
///
/// # Lifecycle
///
/// 1. Create the job with a populated [`BtreeCleanupQueue`].
/// 2. Register with [`JobScheduler::register`].
/// 3. On each commit, the scheduler calls `execute()`.
/// 4. When all entries are processed, the job is removed.
#[derive(Debug)]
pub struct BtreeCleanupDeferredJob {
    /// The persistent cleanup queue backing this job.
    pub queue: BtreeCleanupQueue,
    /// How many entries to process per `execute()` call.
    batch_size: usize,
    /// Unique identifier for this job instance.
    id: String,
}

impl BtreeCleanupDeferredJob {
    /// Create a new job wrapping a [`BtreeCleanupQueue`].
    #[must_use]
    pub fn new(queue: BtreeCleanupQueue, batch_size: usize) -> Self {
        let id = format!("btree-cleanup-{}", queue.next_entry_id());
        Self {
            queue,
            batch_size,
            id,
        }
    }

    /// Create with a custom identifier string.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    /// Access the underlying queue.
    #[must_use]
    pub fn queue(&self) -> &BtreeCleanupQueue {
        &self.queue
    }

    /// Mutable access to the underlying queue.
    pub fn queue_mut(&mut self) -> &mut BtreeCleanupQueue {
        &mut self.queue
    }

    /// Dequeue a pending batch and call `f` on each entry.
    ///
    /// Entries are not marked as processed — call [`execute`](Self::execute)
    /// after successful processing, or use [`process_and_ack`](Self::process_and_ack)
    /// to process and mark in one step.
    ///
    /// Returns the number of entries in the batch.
    pub fn process_batch_with<F: FnMut(&BtreeCleanupEntry)>(&mut self, mut f: F) -> usize {
        let batch = self.queue.dequeue_batch(self.batch_size);
        let count = batch.len();
        for (_id, entry) in &batch {
            f(entry);
        }
        count
    }

    /// Dequeue a pending batch, call `f` on each entry, and mark all as
    /// processed.
    ///
    /// Returns the number of entries processed.
    pub fn process_and_ack<F: FnMut(&BtreeCleanupEntry)>(&mut self, mut f: F) -> usize {
        let batch = self.queue.dequeue_batch(self.batch_size);
        let count = batch.len();
        for (_id, entry) in &batch {
            f(entry);
        }
        let ids: Vec<u64> = batch.iter().map(|(id, _)| *id).collect();
        self.queue.ack_processed(&ids);
        count
    }
}

impl DeferredCleanupJob for BtreeCleanupDeferredJob {
    fn execute(&mut self, _ctx: &CleanupContext) -> JobOutcome {
        if self.queue.is_empty() {
            return JobOutcome::Completed;
        }

        let pending = self.queue.pending_count();
        if pending == 0 {
            // All entries are processed but not yet purged
            return JobOutcome::Completed;
        }

        let batch = self.queue.dequeue_batch(self.batch_size);
        if batch.is_empty() {
            return JobOutcome::Completed;
        }

        let ids: Vec<u64> = batch.iter().map(|(id, _)| *id).collect();
        let marked = self.queue.ack_processed(&ids);

        if marked == 0 {
            // Nothing changed
            return JobOutcome::Completed;
        }

        // Return Incomplete if more entries remain; Completed if done
        if self.queue.pending_count() == 0 {
            JobOutcome::Completed
        } else {
            JobOutcome::Incomplete
        }
    }

    fn phase(&self) -> CleanupPhase {
        // B+tree structural maintenance runs after extent-freeing,
        // before spacemap updates.
        CleanupPhase::SpacemapUpdate
    }

    fn job_id(&self) -> &str {
        &self.id
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_deferred_cleanup_core::{UnresolvedExtentMapRoot, WorkItemKind};

    fn make_item(inode_id: u64, kind: WorkItemKind, bytes: u64) -> CleanupWorkItemV1 {
        CleanupWorkItemV1::new(inode_id, kind, 1, UnresolvedExtentMapRoot::EMPTY, bytes)
    }

    fn make_items(count: u64) -> Vec<CleanupWorkItemV1> {
        (0..count)
            .map(|i| make_item(i, WorkItemKind::UnlinkFree, 4096 * (i + 1)))
            .collect()
    }

    fn receipt_for(state: CleanupJobReceiptState, attempt_generation: u64) -> CleanupJobReceipt {
        CleanupJobReceipt::new(
            state,
            JobId(7),
            CleanupWorkItemId(99),
            "unit evidence",
            attempt_generation,
            CleanupReceiptValidationTier::CargoUnit,
        )
    }

    // -- CleanupJobReceipt tests --

    #[test]
    fn cleanup_job_receipt_json_is_deterministic() {
        let receipt = CleanupJobReceipt::completed(
            JobId(7),
            CleanupWorkItemId(99),
            "processed cleanup work item",
            2,
            CleanupReceiptValidationTier::CargoUnit,
        )
        .with_artifact_digest(CleanupReceiptArtifactDigest::new(
            "blake3",
            "0123456789abcdef",
        ));

        let json = receipt.to_json_string().unwrap();
        assert_eq!(
            json,
            r#"{"job_id":7,"work_item_id":99,"state":"completed","reason":"processed cleanup work item","attempt_generation":2,"validation_tier":"cargo-unit","artifact_digest":{"algorithm":"blake3","hex":"0123456789abcdef"}}"#
        );

        let decoded = CleanupJobReceipt::from_json_slice(json.as_bytes()).unwrap();
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn committed_reclaim_evidence_json_is_deterministic() {
        let evidence = CommittedReclaimEvidence::physical_release(
            ReclaimEvidenceProducer::CleanupEngine,
            JobId(7),
            CleanupWorkItemId(99),
            4,
            3,
            12_288,
            CleanupReceiptValidationTier::CargoUnit,
        )
        .unwrap();

        assert!(evidence.is_committed_physical_reclaim());
        assert_eq!(
            evidence.to_json_string().unwrap(),
            r#"{"producer":"cleanup-engine","job_id":7,"work_item_id":99,"commit_generation":4,"units_reclaimed":3,"bytes_reclaimed":12288,"validation_tier":"cargo-unit"}"#
        );
    }

    #[test]
    fn committed_reclaim_evidence_rejects_non_committed_release() {
        let err = CommittedReclaimEvidence::physical_release(
            ReclaimEvidenceProducer::CleanupEngine,
            JobId(7),
            CleanupWorkItemId(99),
            4,
            3,
            0,
            CleanupReceiptValidationTier::CargoUnit,
        )
        .unwrap_err();

        assert_eq!(err, ReclaimEvidenceError::ZeroBytesReclaimed);
    }

    #[test]
    fn cleanup_job_receipt_sequence_accepts_retry_then_completion() {
        let receipts = vec![
            CleanupJobReceipt::admitted(
                JobId(7),
                CleanupWorkItemId(99),
                "scheduler admitted work item",
                1,
                CleanupReceiptValidationTier::SourceModel,
            ),
            CleanupJobReceipt::retried(
                JobId(7),
                CleanupWorkItemId(99),
                "transient extent map read conflict",
                1,
                CleanupReceiptValidationTier::SourceModel,
            ),
            CleanupJobReceipt::admitted(
                JobId(7),
                CleanupWorkItemId(99),
                "retry generation admitted",
                2,
                CleanupReceiptValidationTier::SourceModel,
            ),
            CleanupJobReceipt::completed(
                JobId(7),
                CleanupWorkItemId(99),
                "cleanup source path completed",
                2,
                CleanupReceiptValidationTier::CargoUnit,
            ),
        ];

        validate_cleanup_job_receipts(&receipts).unwrap();
    }

    #[test]
    fn cleanup_job_receipt_validation_rejects_unknown_transition() {
        let receipts = vec![
            receipt_for(CleanupJobReceiptState::Admitted, 1),
            receipt_for(CleanupJobReceiptState::Completed, 1),
            receipt_for(CleanupJobReceiptState::Retried, 2),
        ];

        let err = validate_cleanup_job_receipts(&receipts).unwrap_err();
        assert_eq!(
            err,
            CleanupJobReceiptValidationError::UnknownStateTransition {
                index: 2,
                from: CleanupJobReceiptState::Completed,
                to: CleanupJobReceiptState::Retried,
            }
        );
    }

    #[test]
    fn cleanup_job_receipt_validation_rejects_stale_attempt_generation() {
        let receipts = vec![
            CleanupJobReceipt::admitted(
                JobId(7),
                CleanupWorkItemId(99),
                "retry admitted",
                2,
                CleanupReceiptValidationTier::SourceModel,
            ),
            CleanupJobReceipt::retried(
                JobId(7),
                CleanupWorkItemId(99),
                "older retry receipt arrived late",
                1,
                CleanupReceiptValidationTier::SourceModel,
            ),
        ];

        let err = validate_cleanup_job_receipts(&receipts).unwrap_err();
        assert_eq!(
            err,
            CleanupJobReceiptValidationError::StaleAttemptGeneration {
                index: 1,
                previous: 2,
                current: 1,
            }
        );
    }

    #[test]
    fn cleanup_job_receipt_validation_rejects_retry_without_new_generation() {
        let receipts = vec![
            CleanupJobReceipt::admitted(
                JobId(7),
                CleanupWorkItemId(99),
                "first attempt admitted",
                1,
                CleanupReceiptValidationTier::SourceModel,
            ),
            CleanupJobReceipt::retried(
                JobId(7),
                CleanupWorkItemId(99),
                "will retry",
                1,
                CleanupReceiptValidationTier::SourceModel,
            ),
            CleanupJobReceipt::admitted(
                JobId(7),
                CleanupWorkItemId(99),
                "stale retry admission",
                1,
                CleanupReceiptValidationTier::SourceModel,
            ),
        ];

        let err = validate_cleanup_job_receipts(&receipts).unwrap_err();
        assert_eq!(
            err,
            CleanupJobReceiptValidationError::StaleAttemptGeneration {
                index: 2,
                previous: 1,
                current: 1,
            }
        );
    }

    #[test]
    fn cleanup_job_receipt_validation_rejects_missing_skip_or_fail_reason() {
        let skipped = CleanupJobReceipt::skipped(
            JobId(7),
            CleanupWorkItemId(99),
            " ",
            1,
            CleanupReceiptValidationTier::SourceModel,
        );
        assert_eq!(
            skipped.validate().unwrap_err(),
            CleanupJobReceiptValidationError::MissingReasonText {
                index: 0,
                state: CleanupJobReceiptState::Skipped,
            }
        );

        let failed = CleanupJobReceipt::failed(
            JobId(7),
            CleanupWorkItemId(99),
            "",
            1,
            CleanupReceiptValidationTier::SourceModel,
        );
        assert_eq!(
            failed.validate().unwrap_err(),
            CleanupJobReceiptValidationError::MissingReasonText {
                index: 0,
                state: CleanupJobReceiptState::Failed,
            }
        );
    }

    #[test]
    fn cleanup_job_receipt_validation_rejects_completed_without_work_identity() {
        let receipt = CleanupJobReceipt::completed(
            JobId(7),
            CleanupWorkItemId::NONE,
            "complete but missing covered work",
            1,
            CleanupReceiptValidationTier::SourceModel,
        );

        assert_eq!(
            receipt.validate().unwrap_err(),
            CleanupJobReceiptValidationError::MissingCoveredWorkIdentity { index: 0 }
        );
    }

    #[test]
    fn cleanup_job_receipt_validation_rejects_missing_base_identity() {
        let missing_job = CleanupJobReceipt::admitted(
            JobId::NONE,
            CleanupWorkItemId(99),
            "missing job identity",
            1,
            CleanupReceiptValidationTier::SourceModel,
        );
        assert_eq!(
            missing_job.validate().unwrap_err(),
            CleanupJobReceiptValidationError::MissingJobId { index: 0 }
        );

        let missing_work = CleanupJobReceipt::admitted(
            JobId(7),
            CleanupWorkItemId::NONE,
            "missing work identity",
            1,
            CleanupReceiptValidationTier::SourceModel,
        );
        assert_eq!(
            missing_work.validate().unwrap_err(),
            CleanupJobReceiptValidationError::MissingWorkItemId { index: 0 }
        );
    }

    #[test]
    fn cleanup_job_receipt_validation_rejects_mixed_identity_chain() {
        let receipts = vec![
            CleanupJobReceipt::admitted(
                JobId(7),
                CleanupWorkItemId(99),
                "scheduler admitted work item",
                1,
                CleanupReceiptValidationTier::SourceModel,
            ),
            CleanupJobReceipt::completed(
                JobId(8),
                CleanupWorkItemId(100),
                "completed different work item",
                1,
                CleanupReceiptValidationTier::CargoUnit,
            ),
        ];

        let err = validate_cleanup_job_receipts(&receipts).unwrap_err();
        assert_eq!(
            err,
            CleanupJobReceiptValidationError::ReceiptIdentityMismatch {
                index: 1,
                expected_job_id: JobId(7),
                actual_job_id: JobId(8),
                expected_work_item_id: CleanupWorkItemId(99),
                actual_work_item_id: CleanupWorkItemId(100),
            }
        );
    }

    #[test]
    fn cleanup_job_receipt_validation_rejects_incomplete_artifact_digest() {
        let empty_algorithm = CleanupJobReceipt::completed(
            JobId(7),
            CleanupWorkItemId(99),
            "completed with incomplete artifact digest",
            1,
            CleanupReceiptValidationTier::CargoUnit,
        )
        .with_artifact_digest(CleanupReceiptArtifactDigest::new("", "0123456789abcdef"));
        assert_eq!(
            empty_algorithm.validate().unwrap_err(),
            CleanupJobReceiptValidationError::EmptyArtifactDigest { index: 0 }
        );

        let empty_hex = CleanupJobReceipt::completed(
            JobId(7),
            CleanupWorkItemId(99),
            "completed with incomplete artifact digest",
            1,
            CleanupReceiptValidationTier::CargoUnit,
        )
        .with_artifact_digest(CleanupReceiptArtifactDigest::new("blake3", " "));
        assert_eq!(
            empty_hex.validate().unwrap_err(),
            CleanupJobReceiptValidationError::EmptyArtifactDigest { index: 0 }
        );
    }

    // -- Existing CleanupJob / IncrementalJob tests --

    #[test]
    fn new_job_empty() {
        let job = CleanupJob::new(Vec::new());
        assert_eq!(job.job_id(), JobId::NONE);
        assert_eq!(job.job_kind(), JobKind::DeferredCleanup);
        assert_eq!(job.stats(), CleanupJobStats::ZERO);
        assert!(job.is_exhausted());
    }

    #[test]
    fn new_job_with_items() {
        let items = make_items(10);
        let job = CleanupJob::new(items);
        assert!(!job.is_exhausted());
        assert_eq!(job.pending_count(), 10);
    }

    #[test]
    fn with_job_id_sets_id() {
        let job = CleanupJob::new(Vec::new()).with_job_id(JobId(42));
        assert_eq!(job.job_id(), JobId(42));
    }

    #[test]
    fn step_processes_items_within_budget() {
        let items = make_items(20);
        let mut job = CleanupJob::new(items);
        let budget = WorkBudget {
            max_items: 5,
            ..WorkBudget::default()
        };
        let result = job.step(budget);
        assert!(!result.is_complete);
        assert_eq!(job.stats().items_processed, 5);
        assert_eq!(job.stats().items_completed, 5);
        let decoded = decode_cursor(result.checkpoint.cursor_state.as_bytes());
        assert_eq!(decoded, 5);
    }

    #[test]
    fn step_completes_when_exhausted() {
        let items = make_items(3);
        let mut job = CleanupJob::new(items);
        let result = job.step(WorkBudget {
            max_items: 10,
            ..WorkBudget::default()
        });
        assert!(result.is_complete);
        assert_eq!(job.stats().items_processed, 3);
        assert!(job.is_exhausted());
    }

    #[test]
    fn step_empty_job_completes() {
        let mut job = CleanupJob::new(Vec::new());
        let result = job.step(WorkBudget::DEFAULT_TICK);
        assert!(result.is_complete);
    }

    #[test]
    fn step_respects_max_items() {
        let items = make_items(100);
        let mut job = CleanupJob::new(items);
        let result = job.step(WorkBudget {
            max_items: 7,
            ..WorkBudget::default()
        });
        assert_eq!(job.stats().items_processed, 7);
        let decoded = decode_cursor(result.checkpoint.cursor_state.as_bytes());
        assert_eq!(decoded, 7);
    }

    #[test]
    fn step_unbounded_processes_all() {
        let items = make_items(50);
        let mut job = CleanupJob::new(items);
        let result = job.step(WorkBudget::UNBOUNDED);
        assert!(result.is_complete);
        assert_eq!(job.stats().items_processed, 50);
    }

    #[test]
    fn cursor_advances_across_steps() {
        let items = make_items(20);
        let mut job = CleanupJob::new(items);
        job.step(WorkBudget {
            max_items: 8,
            ..WorkBudget::default()
        });
        assert_eq!(job.stats().items_processed, 8);
        job.step(WorkBudget {
            max_items: 8,
            ..WorkBudget::default()
        });
        assert_eq!(job.stats().items_processed, 16);
        let result = job.step(WorkBudget {
            max_items: 10,
            ..WorkBudget::default()
        });
        assert!(result.is_complete);
        assert_eq!(job.stats().items_processed, 20);
    }

    #[test]
    fn resume_from_checkpoint_restores_cursor() {
        let items = make_items(30);
        let mut job = CleanupJob::new(items);
        let result = job.step(WorkBudget {
            max_items: 10,
            ..WorkBudget::default()
        });
        let saved_cp = result.checkpoint.clone();
        let resumed = CleanupJob::resume(saved_cp).unwrap();
        assert_eq!(resumed.stats.items_processed, 10);
        assert_eq!(resumed.cursor, 10);
    }

    #[test]
    fn stats_tracks_bytes_freed() {
        let items: Vec<CleanupWorkItemV1> = vec![
            make_item(1, WorkItemKind::UnlinkFree, 4096),
            make_item(2, WorkItemKind::TruncateFree, 8192),
            make_item(3, WorkItemKind::RmdirFree, 16384),
        ];
        let mut job = CleanupJob::new(items);
        job.step(WorkBudget::UNBOUNDED);
        assert_eq!(job.stats().items_completed, 3);
        assert_eq!(job.stats().bytes_freed_estimate, 4096 + 8192 + 16384);
    }

    #[test]
    fn cleanup_job_progress_refuses_committed_reclaim_evidence() {
        let items: Vec<CleanupWorkItemV1> = vec![make_item(1, WorkItemKind::UnlinkFree, 4096)];
        let mut job = CleanupJob::new(items).with_job_id(JobId(11));
        job.step(WorkBudget::UNBOUNDED);

        let refusal = job.reclaim_progress_refusal(CleanupReceiptValidationTier::CargoUnit);
        assert_eq!(refusal.producer, ReclaimEvidenceProducer::CleanupJob);
        assert_eq!(refusal.job_id, JobId(11));
        assert_eq!(
            refusal.reason,
            ReclaimEvidenceRefusalReason::CleanupProgressOnly
        );
        assert_eq!(refusal.estimated_bytes, 4096);
        assert_eq!(refusal.units, 1);
        assert!(!refusal.is_committed_physical_reclaim());
    }

    #[test]
    fn stats_zero_item_bytes_uses_default() {
        let items: Vec<CleanupWorkItemV1> = vec![make_item(1, WorkItemKind::PunchHoleFree, 0)];
        let mut job = CleanupJob::new(items);
        job.set_default_item_bytes(8192);
        job.step(WorkBudget::UNBOUNDED);
        assert_eq!(job.stats().bytes_freed_estimate, 8192);
    }

    #[test]
    fn all_work_item_kinds_processed() {
        let kinds = [
            WorkItemKind::UnlinkFree,
            WorkItemKind::TruncateFree,
            WorkItemKind::RmdirFree,
            WorkItemKind::RenameOverwrite,
            WorkItemKind::SnapDelete,
            WorkItemKind::PunchHoleFree,
        ];
        let items: Vec<CleanupWorkItemV1> = kinds
            .iter()
            .enumerate()
            .map(|(i, &kind)| make_item(i as u64, kind, 4096))
            .collect();
        let mut job = CleanupJob::new(items);
        let result = job.step(WorkBudget::UNBOUNDED);
        assert!(result.is_complete);
        assert_eq!(job.stats().items_completed, 6);
    }

    #[test]
    fn persist_checkpoint_matches_step_checkpoint() {
        let items = make_items(5);
        let mut job = CleanupJob::new(items);
        let step_result = job.step(WorkBudget {
            max_items: 3,
            ..WorkBudget::default()
        });
        let persisted = job.persist_checkpoint();
        assert_eq!(
            step_result.checkpoint.cursor_state.as_bytes(),
            persisted.cursor_state.as_bytes()
        );
    }

    #[test]
    fn step_after_exhaustion_returns_complete() {
        let items = make_items(5);
        let mut job = CleanupJob::new(items);
        let result1 = job.step(WorkBudget::UNBOUNDED);
        assert!(result1.is_complete);
        let result2 = job.step(WorkBudget::DEFAULT_TICK);
        assert!(result2.is_complete);
    }

    #[test]
    fn checkpoint_has_correct_job_kind() {
        let items = make_items(3);
        let mut job = CleanupJob::new(items);
        let result = job.step(WorkBudget::DEFAULT_TICK);
        assert_eq!(result.checkpoint.job_kind, JobKind::DeferredCleanup);
    }

    #[test]
    fn checkpoint_progress_reflects_stats() {
        let items = make_items(10);
        let mut job = CleanupJob::new(items);
        let result = job.step(WorkBudget {
            max_items: 3,
            ..WorkBudget::default()
        });
        assert_eq!(result.checkpoint.progress.items_processed, 3);
        assert_eq!(result.checkpoint.progress.items_total_estimate, 10);
        assert!(result.checkpoint.progress.bytes_processed > 0);
    }

    // -----------------------------------------------------------------------
    // Mock CleanupTask for scheduler tests
    // -----------------------------------------------------------------------

    /// A mock job that succeeds, fails retryably, or fatally based on
    /// pre-programmed behaviour.
    #[derive(Debug)]
    struct MockCleanupTask {
        name: String,
        outcomes: Vec<JobResult>,
        call_count: usize,
        rollback_called: bool,
    }

    impl MockCleanupTask {
        fn new_success(name: &str) -> Self {
            Self {
                name: name.into(),
                outcomes: vec![JobResult::Ok(())],
                call_count: 0,
                rollback_called: false,
            }
        }

        fn new_retry_then_succeed(name: &str, retries: usize) -> Self {
            let mut outcomes: Vec<JobResult> = (0..retries)
                .map(|i| JobResult::Retryable(format!("attempt {}", i + 1)))
                .collect();
            outcomes.push(JobResult::Ok(()));
            Self {
                name: name.into(),
                outcomes,
                call_count: 0,
                rollback_called: false,
            }
        }

        fn new_fatal(name: &str) -> Self {
            Self {
                name: name.into(),
                outcomes: vec![JobResult::Fatal("fatal error".into())],
                call_count: 0,
                rollback_called: false,
            }
        }
    }

    impl CleanupTask for MockCleanupTask {
        fn execute(&mut self) -> JobResult {
            let outcome = self.outcomes[self.call_count].clone();
            self.call_count += 1;
            outcome
        }

        fn rollback(&mut self) {
            self.rollback_called = true;
        }

        fn describe(&self) -> &str {
            &self.name
        }
    }

    // -----------------------------------------------------------------------
    // RetryConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn retry_config_default_values() {
        let cfg = RetryConfig::DEFAULT;
        assert_eq!(cfg.max_attempts, 3);
        assert_eq!(cfg.base_delay_ms, 100);
        assert_eq!(cfg.max_delay_ms, 5_000);
    }

    #[test]
    fn retry_config_next_delay_attempt_zero() {
        let cfg = RetryConfig::DEFAULT;
        assert_eq!(cfg.next_delay(0), 0);
    }

    #[test]
    fn retry_config_next_delay_attempt_one() {
        let cfg = RetryConfig::DEFAULT;
        // base * 2^0 = 100, jitter +12.5% = 112
        assert_eq!(cfg.next_delay(1), 112);
    }

    #[test]
    fn retry_config_next_delay_attempt_two() {
        let cfg = RetryConfig::DEFAULT;
        // base * 2^1 = 200, jitter -12.5% = 175
        assert_eq!(cfg.next_delay(2), 175);
    }

    #[test]
    fn retry_config_next_delay_capped_at_max() {
        let cfg = RetryConfig {
            max_attempts: 5,
            base_delay_ms: 100,
            max_delay_ms: 500,
        };
        // attempt 4: base * 2^3 = 800, capped to 500, +12.5% capped = 500
        assert_eq!(cfg.next_delay(4), 500);
    }

    #[test]
    fn retry_config_is_exhausted() {
        let cfg = RetryConfig::DEFAULT;
        assert!(!cfg.is_exhausted(0));
        assert!(!cfg.is_exhausted(1));
        assert!(!cfg.is_exhausted(2));
        assert!(cfg.is_exhausted(3));
        assert!(cfg.is_exhausted(4));
    }

    #[test]
    fn retry_config_exponential_growth() {
        let cfg = RetryConfig {
            max_attempts: 10,
            base_delay_ms: 10,
            max_delay_ms: 100_000,
        };
        let d1 = cfg.next_delay(1); // 10 + jitter
        let d4 = cfg.next_delay(4); // 80 + jitter
        let d7 = cfg.next_delay(7); // 640 + jitter
        assert!(d1 < d4);
        assert!(d4 < d7);
    }

    // -----------------------------------------------------------------------
    // JobState tests
    // -----------------------------------------------------------------------

    #[test]
    fn job_state_default_pending() {
        let state = JobState::Pending;
        assert_eq!(state, JobState::Pending);
    }

    #[test]
    fn job_state_failed_holds_attempt() {
        let state = JobState::Failed { attempt: 3 };
        match state {
            JobState::Failed { attempt } => assert_eq!(attempt, 3),
            _ => panic!("expected Failed"),
        }
    }

    // -----------------------------------------------------------------------
    // JobResult tests
    // -----------------------------------------------------------------------

    #[test]
    fn job_result_equality() {
        assert_eq!(JobResult::Ok(()), JobResult::Ok(()));
        assert_eq!(
            JobResult::Retryable("err".into()),
            JobResult::Retryable("err".into())
        );
        assert_ne!(
            JobResult::Retryable("err".into()),
            JobResult::Retryable("different".into())
        );
        assert_eq!(
            JobResult::Fatal("fatal".into()),
            JobResult::Fatal("fatal".into())
        );
    }

    // -----------------------------------------------------------------------
    // JobProgress tests
    // -----------------------------------------------------------------------

    #[test]
    fn job_progress_new_sets_timestamp() {
        let progress = JobProgress::new("job-1".into());
        assert_eq!(progress.job_id, "job-1");
        assert_eq!(progress.attempt, 0);
        assert!(progress.last_error.is_none());
        assert!(progress.timestamp_secs > 0);
    }

    #[test]
    fn job_progress_json_round_trip() {
        let mut progress = JobProgress::new("test-job".into());
        progress.attempt = 2;
        progress.last_error = Some("transient".into());
        let json = progress.to_json();
        let restored = JobProgress::from_json(&json).unwrap();
        assert_eq!(progress, restored);
    }

    #[test]
    fn job_progress_from_json_invalid() {
        assert!(JobProgress::from_json(b"not json").is_none());
    }

    // -----------------------------------------------------------------------
    // Priority ordering tests
    // -----------------------------------------------------------------------

    #[test]
    fn priority_ordering_critical_before_normal() {
        assert!(Priority::Critical < Priority::Normal);
        assert!(Priority::High < Priority::Normal);
        assert!(Priority::Normal < Priority::Low);
    }

    // -----------------------------------------------------------------------
    // CleanupEntry ordering tests
    // -----------------------------------------------------------------------

    #[test]
    fn cleanup_entry_ordering_by_priority() {
        let low = CleanupEntry::new("low".into(), Priority::Low, RetryConfig::DEFAULT);
        let critical =
            CleanupEntry::new("critical".into(), Priority::Critical, RetryConfig::DEFAULT);
        // critical has lower Priority value, so it should be "greater" in the
        // reversed Ord (i.e. popped first from BinaryHeap)
        assert!(critical > low);
    }

    #[test]
    fn cleanup_entry_tie_break_on_job_id() {
        let a = CleanupEntry::new("a".into(), Priority::Normal, RetryConfig::DEFAULT);
        let b = CleanupEntry::new("b".into(), Priority::Normal, RetryConfig::DEFAULT);
        assert!(a < b); // "a" < "b"
    }

    // -----------------------------------------------------------------------
    // CleanupScheduler tests
    // -----------------------------------------------------------------------

    #[test]
    fn scheduler_new_empty() {
        let s = CleanupScheduler::new(10);
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.capacity(), 10);
    }

    #[test]
    fn scheduler_submit_and_drain_one_success() {
        let mut s = CleanupScheduler::new(5);
        let job = Box::new(MockCleanupTask::new_success("test-job"));
        assert!(s
            .submit(job, Priority::Normal, RetryConfig::DEFAULT)
            .is_ok());
        assert_eq!(s.len(), 1);
        let progress = s.drain_one().unwrap();
        assert_eq!(progress.job_id, "test-job");
        assert_eq!(progress.attempt, 1);
        assert!(progress.last_error.is_none());
        assert!(s.is_empty());
    }

    #[test]
    fn scheduler_drain_one_empty_returns_none() {
        let mut s = CleanupScheduler::new(5);
        assert!(s.drain_one().is_none());
    }

    #[test]
    fn scheduler_capacity_rejection() {
        let mut s = CleanupScheduler::new(2);
        s.submit(
            Box::new(MockCleanupTask::new_success("a")),
            Priority::Normal,
            RetryConfig::DEFAULT,
        )
        .unwrap();
        s.submit(
            Box::new(MockCleanupTask::new_success("b")),
            Priority::Normal,
            RetryConfig::DEFAULT,
        )
        .unwrap();
        let job = Box::new(MockCleanupTask::new_success("c"));
        let err = s
            .submit(job, Priority::Normal, RetryConfig::DEFAULT)
            .unwrap_err();
        assert_eq!(err.describe(), "c");
    }

    #[test]
    fn scheduler_priority_ordering() {
        let mut s = CleanupScheduler::new(10);
        s.submit(
            Box::new(MockCleanupTask::new_success("low")),
            Priority::Low,
            RetryConfig::DEFAULT,
        )
        .unwrap();
        s.submit(
            Box::new(MockCleanupTask::new_success("critical")),
            Priority::Critical,
            RetryConfig::DEFAULT,
        )
        .unwrap();
        s.submit(
            Box::new(MockCleanupTask::new_success("normal")),
            Priority::Normal,
            RetryConfig::DEFAULT,
        )
        .unwrap();
        s.submit(
            Box::new(MockCleanupTask::new_success("high")),
            Priority::High,
            RetryConfig::DEFAULT,
        )
        .unwrap();

        // drain_one should pop highest priority first
        let p1 = s.drain_one().unwrap();
        assert_eq!(p1.job_id, "critical");
        let p2 = s.drain_one().unwrap();
        assert_eq!(p2.job_id, "high");
        let p3 = s.drain_one().unwrap();
        assert_eq!(p3.job_id, "normal");
        let p4 = s.drain_one().unwrap();
        assert_eq!(p4.job_id, "low");
        assert!(s.is_empty());
    }

    #[test]
    fn scheduler_retryable_job_re_enqueued() {
        let mut s = CleanupScheduler::new(5);
        let job = Box::new(MockCleanupTask::new_retry_then_succeed("retry-job", 1));
        let cfg = RetryConfig {
            max_attempts: 3,
            base_delay_ms: 10,
            max_delay_ms: 1000,
        };
        s.submit(job, Priority::Normal, cfg).unwrap();

        // First drain_one: returns Retryable, re-enqueued
        let p1 = s.drain_one().unwrap();
        assert_eq!(p1.attempt, 1);
        assert!(p1.last_error.is_some());
        assert_eq!(s.len(), 1); // re-enqueued

        // Second drain_one: should succeed
        let p2 = s.drain_one().unwrap();
        assert_eq!(p2.attempt, 2);
        assert!(p2.last_error.is_none());
        assert!(s.is_empty());
    }

    #[test]
    fn scheduler_retry_exhaustion() {
        let mut s = CleanupScheduler::new(5);
        // Job that always returns Retryable
        #[derive(Debug)]
        struct AlwaysRetry;
        impl CleanupTask for AlwaysRetry {
            fn execute(&mut self) -> JobResult {
                JobResult::Retryable("again".into())
            }
            fn rollback(&mut self) {}
            fn describe(&self) -> &str {
                "always-retry"
            }
        }
        let cfg = RetryConfig {
            max_attempts: 2,
            base_delay_ms: 10,
            max_delay_ms: 1000,
        };
        s.submit(Box::new(AlwaysRetry), Priority::Normal, cfg)
            .unwrap();

        // First attempt
        let p1 = s.drain_one().unwrap();
        assert_eq!(p1.attempt, 1);
        assert_eq!(s.len(), 1); // re-enqueued (attempt 1 < max 2)

        // Second attempt
        let p2 = s.drain_one().unwrap();
        assert_eq!(p2.attempt, 2);
        assert!(s.is_empty()); // exhausted, not re-enqueued
    }

    #[test]
    fn scheduler_fatal_triggers_rollback() {
        let mut s = CleanupScheduler::new(5);
        let job = Box::new(MockCleanupTask::new_fatal("fatal-job"));
        s.submit(job, Priority::Normal, RetryConfig::DEFAULT)
            .unwrap();

        let progress = s.drain_one().unwrap();
        assert_eq!(progress.job_id, "fatal-job");
        assert!(progress.last_error.is_some());
        assert!(s.is_empty()); // fatal = not re-enqueued
    }

    #[test]
    fn scheduler_drain_all() {
        let mut s = CleanupScheduler::new(10);
        s.submit(
            Box::new(MockCleanupTask::new_success("a")),
            Priority::Normal,
            RetryConfig::DEFAULT,
        )
        .unwrap();
        s.submit(
            Box::new(MockCleanupTask::new_success("b")),
            Priority::Normal,
            RetryConfig::DEFAULT,
        )
        .unwrap();
        s.submit(
            Box::new(MockCleanupTask::new_success("c")),
            Priority::Normal,
            RetryConfig::DEFAULT,
        )
        .unwrap();

        let results = s.drain();
        assert_eq!(results.len(), 3);
        assert!(s.is_empty());
    }

    #[test]
    fn scheduler_drain_with_retries() {
        let mut s = CleanupScheduler::new(10);
        let cfg = RetryConfig {
            max_attempts: 3,
            base_delay_ms: 10,
            max_delay_ms: 1000,
        };
        s.submit(
            Box::new(MockCleanupTask::new_retry_then_succeed("r", 2)),
            Priority::Normal,
            cfg,
        )
        .unwrap();
        s.submit(
            Box::new(MockCleanupTask::new_success("ok")),
            Priority::Normal,
            RetryConfig::DEFAULT,
        )
        .unwrap();

        let results = s.drain();
        // First drain: "ok" succeeds, "r" fails -> re-enqueued
        // Then the retry loop inside drain processes "r" again
        // Actually drain processes all in one go, then re-enqueues retries
        // So we get all initial results plus re-processed ones
        assert!(results.len() >= 2);
        // After drain, the retryable jobs are back in the queue
        assert_eq!(s.len(), 1); // "r" needs more retries
    }

    #[test]
    fn scheduler_persist_all() {
        let mut s = CleanupScheduler::new(10);
        s.submit(
            Box::new(MockCleanupTask::new_success("a")),
            Priority::Normal,
            RetryConfig::DEFAULT,
        )
        .unwrap();
        s.submit(
            Box::new(MockCleanupTask::new_success("b")),
            Priority::High,
            RetryConfig::DEFAULT,
        )
        .unwrap();

        let json = s.persist_all();
        let records: Vec<JobProgress> = serde_json::from_slice(&json).unwrap();
        assert_eq!(records.len(), 2);
        let ids: Vec<&str> = records.iter().map(|r| r.job_id.as_str()).collect();
        assert!(ids.contains(&"a"));
        assert!(ids.contains(&"b"));
    }

    // -----------------------------------------------------------------------
    // doc-test: CleanupTask can be implemented by a mock segment-cleaner job
    // -----------------------------------------------------------------------

    /// ```rust
    /// use tidefs_cleanup_job_core::{CleanupTask, JobResult};
    ///
    /// #[derive(Debug)]
    /// struct SegmentCleanerJob { segment_id: u64 }
    ///
    /// impl CleanupTask for SegmentCleanerJob {
    ///     fn execute(&mut self) -> JobResult {
    ///         // In real code: scan segment, relocate live blocks, free dead ones
    ///         JobResult::Ok(())
    ///     }
    ///     fn rollback(&mut self) {}
    ///     fn describe(&self) -> &str { "segment-cleaner" }
    /// }
    /// ```
    #[allow(dead_code)]
    fn _doctest_cleanup_task_impl() {}
    // -----------------------------------------------------------------------
    // DeferredCleanupJob / JobScheduler / CleanupPhase / TxgCommitObserver tests
    // -----------------------------------------------------------------------

    /// Mock DeferredCleanupJob for testing.
    #[derive(Debug)]
    struct MockDeferredJob {
        id: String,
        phase: CleanupPhase,
        prio: u32,
        outcomes: Vec<JobOutcome>,
        call_count: usize,
    }

    impl MockDeferredJob {
        fn new_success(id: &str, phase: CleanupPhase) -> Self {
            Self {
                id: id.into(),
                phase,
                prio: 0,
                outcomes: vec![JobOutcome::Completed],
                call_count: 0,
            }
        }

        fn new_incomplete(id: &str, phase: CleanupPhase) -> Self {
            Self {
                id: id.into(),
                phase,
                prio: 0,
                outcomes: vec![
                    JobOutcome::Incomplete,
                    JobOutcome::Incomplete,
                    JobOutcome::Completed,
                ],
                call_count: 0,
            }
        }

        fn new_retryable(id: &str, phase: CleanupPhase, retries: usize) -> Self {
            let mut outcomes: Vec<JobOutcome> = (0..retries)
                .map(|i| {
                    JobOutcome::Retryable(CleanupError::retryable(
                        format!("attempt {}", i + 1),
                        phase,
                    ))
                })
                .collect();
            outcomes.push(JobOutcome::Completed);
            Self {
                id: id.into(),
                phase,
                prio: 0,
                outcomes,
                call_count: 0,
            }
        }

        fn new_fatal(id: &str, phase: CleanupPhase) -> Self {
            Self {
                id: id.into(),
                phase,
                prio: 0,
                outcomes: vec![JobOutcome::Fatal(CleanupError::fatal("fatal", phase))],
                call_count: 0,
            }
        }
    }

    impl DeferredCleanupJob for MockDeferredJob {
        fn execute(&mut self, _ctx: &CleanupContext) -> JobOutcome {
            let outcome = self.outcomes[self.call_count].clone();
            self.call_count += 1;
            outcome
        }

        fn phase(&self) -> CleanupPhase {
            self.phase
        }
        fn job_id(&self) -> &str {
            &self.id
        }
        fn priority(&self) -> u32 {
            self.prio
        }
    }

    // ── CleanupContext ────────────────────────────────────────────────

    #[test]
    fn context_new_sets_txg_and_epoch() {
        let ctx = CleanupContext::new(42, 3);
        assert_eq!(ctx.txg_id, 42);
        assert_eq!(ctx.epoch, 3);
        assert!(ctx.timestamp_secs > 0);
    }

    #[test]
    fn context_is_newer_than_by_epoch() {
        let old = CleanupContext {
            txg_id: 1,
            epoch: 1,
            timestamp_secs: 0,
        };
        let new = CleanupContext {
            txg_id: 2,
            epoch: 2,
            timestamp_secs: 0,
        };
        assert!(new.is_newer_than(&old));
        assert!(!old.is_newer_than(&new));
        assert!(!new.is_newer_than(&new));
    }

    // ── CleanupPhase ─────────────────────────────────────────────────

    #[test]
    fn phase_count_is_four() {
        assert_eq!(CleanupPhase::COUNT, 4);
    }

    #[test]
    fn phase_all_in_order() {
        assert_eq!(CleanupPhase::ALL[0], CleanupPhase::ExtentFree);
        assert_eq!(CleanupPhase::ALL[1], CleanupPhase::SpacemapUpdate);
        assert_eq!(CleanupPhase::ALL[2], CleanupPhase::DeadObjectRegister);
        assert_eq!(CleanupPhase::ALL[3], CleanupPhase::OrphanReap);
    }

    #[test]
    fn phase_next_transitions() {
        assert_eq!(
            CleanupPhase::ExtentFree.next(),
            Some(CleanupPhase::SpacemapUpdate)
        );
        assert_eq!(
            CleanupPhase::SpacemapUpdate.next(),
            Some(CleanupPhase::DeadObjectRegister)
        );
        assert_eq!(
            CleanupPhase::DeadObjectRegister.next(),
            Some(CleanupPhase::OrphanReap)
        );
        assert_eq!(CleanupPhase::OrphanReap.next(), None);
    }

    #[test]
    fn phase_first_and_last() {
        assert_eq!(CleanupPhase::first(), CleanupPhase::ExtentFree);
        assert_eq!(CleanupPhase::last(), CleanupPhase::OrphanReap);
    }

    #[test]
    fn phase_ordering_is_correct() {
        assert!(CleanupPhase::ExtentFree < CleanupPhase::SpacemapUpdate);
        assert!(CleanupPhase::SpacemapUpdate < CleanupPhase::DeadObjectRegister);
        assert!(CleanupPhase::DeadObjectRegister < CleanupPhase::OrphanReap);
    }

    // ── CleanupError ─────────────────────────────────────────────────

    #[test]
    fn cleanup_error_retryable() {
        let err = CleanupError::retryable("transient", CleanupPhase::SpacemapUpdate);
        assert!(err.retryable);
        assert_eq!(err.phase, CleanupPhase::SpacemapUpdate);
        assert!(err.message.contains("transient"));
    }

    #[test]
    fn cleanup_error_fatal() {
        let err = CleanupError::fatal("disk failed", CleanupPhase::ExtentFree);
        assert!(!err.retryable);
    }

    #[test]
    fn cleanup_error_display() {
        let err = CleanupError::retryable("boom", CleanupPhase::OrphanReap);
        let s = format!("{err}");
        assert!(s.contains("boom"));
        assert!(s.contains("OrphanReap"));
        assert!(s.contains("retryable=true"));
    }

    // ── JobOutcome ───────────────────────────────────────────────────

    #[test]
    fn job_outcome_terminal() {
        assert!(JobOutcome::Completed.is_terminal());
        assert!(!JobOutcome::Incomplete.is_terminal());
        assert!(
            !JobOutcome::Retryable(CleanupError::retryable("e", CleanupPhase::ExtentFree))
                .is_terminal()
        );
        assert!(
            JobOutcome::Fatal(CleanupError::fatal("e", CleanupPhase::ExtentFree)).is_terminal()
        );
    }

    #[test]
    fn job_outcome_is_completed() {
        assert!(JobOutcome::Completed.is_completed());
        assert!(!JobOutcome::Incomplete.is_completed());
        assert!(
            !JobOutcome::Retryable(CleanupError::retryable("e", CleanupPhase::ExtentFree))
                .is_completed()
        );
        assert!(
            !JobOutcome::Fatal(CleanupError::fatal("e", CleanupPhase::ExtentFree)).is_completed()
        );
    }

    // ── JobScheduler ─────────────────────────────────────────────────

    #[test]
    fn scheduler_new_is_empty() {
        let s = JobScheduler::new();
        assert!(s.is_empty());
        assert_eq!(s.job_count(), 0);
        assert_eq!(s.total_dispatched(), 0);
        assert_eq!(s.total_completed(), 0);
        assert_eq!(s.total_fatal(), 0);
        assert!(s.last_context().is_none());
    }

    #[test]
    fn scheduler_register_job() {
        let mut s = JobScheduler::new();
        s.register(Box::new(MockDeferredJob::new_success(
            "a",
            CleanupPhase::ExtentFree,
        )));
        assert!(!s.is_empty());
        assert_eq!(s.job_count(), 1);
    }

    #[test]
    fn scheduler_register_multiple_phases() {
        let mut s = JobScheduler::new();
        s.register(Box::new(MockDeferredJob::new_success(
            "a",
            CleanupPhase::ExtentFree,
        )));
        s.register(Box::new(MockDeferredJob::new_success(
            "b",
            CleanupPhase::SpacemapUpdate,
        )));
        s.register(Box::new(MockDeferredJob::new_success(
            "c",
            CleanupPhase::DeadObjectRegister,
        )));
        s.register(Box::new(MockDeferredJob::new_success(
            "d",
            CleanupPhase::OrphanReap,
        )));
        assert_eq!(s.job_count(), 4);
    }

    #[test]
    fn scheduler_dispatch_single_job_success() {
        let mut s = JobScheduler::new();
        s.register(Box::new(MockDeferredJob::new_success(
            "a",
            CleanupPhase::ExtentFree,
        )));
        s.on_commit(1, 1);
        assert!(s.is_empty());
        assert_eq!(s.total_dispatched(), 1);
        assert_eq!(s.total_completed(), 1);
        assert_eq!(s.total_fatal(), 0);
        assert_eq!(s.last_context().unwrap().txg_id, 1);
    }

    #[test]
    fn scheduler_dispatch_phase_ordering() {
        // Jobs in different phases; verify dispatch order via a shared log.
        use std::cell::RefCell;
        use std::rc::Rc;

        #[derive(Debug)]
        struct OrderingJob {
            id: String,
            phase: CleanupPhase,
            log: Rc<RefCell<Vec<String>>>,
        }
        impl DeferredCleanupJob for OrderingJob {
            fn execute(&mut self, _ctx: &CleanupContext) -> JobOutcome {
                self.log.borrow_mut().push(self.id.clone());
                JobOutcome::Completed
            }
            fn phase(&self) -> CleanupPhase {
                self.phase
            }
            fn job_id(&self) -> &str {
                &self.id
            }
        }

        let log = Rc::new(RefCell::new(Vec::new()));
        let mut s = JobScheduler::new();

        s.register(Box::new(OrderingJob {
            id: "orphan".into(),
            phase: CleanupPhase::OrphanReap,
            log: log.clone(),
        }));
        s.register(Box::new(OrderingJob {
            id: "dead".into(),
            phase: CleanupPhase::DeadObjectRegister,
            log: log.clone(),
        }));
        s.register(Box::new(OrderingJob {
            id: "sm".into(),
            phase: CleanupPhase::SpacemapUpdate,
            log: log.clone(),
        }));
        s.register(Box::new(OrderingJob {
            id: "extent".into(),
            phase: CleanupPhase::ExtentFree,
            log: log.clone(),
        }));

        s.on_commit(1, 1);

        let order = log.borrow();
        // Jobs registered in arbitrary order; dispatch must be phase-ordered
        assert_eq!(order[0], "extent");
        assert_eq!(order[1], "sm");
        assert_eq!(order[2], "dead");
        assert_eq!(order[3], "orphan");
    }

    #[test]
    fn scheduler_priority_ordering_within_phase() {
        use std::cell::RefCell;
        use std::rc::Rc;

        #[derive(Debug)]
        struct PrioJob {
            id: String,
            prio: u32,
            log: Rc<RefCell<Vec<String>>>,
        }
        impl DeferredCleanupJob for PrioJob {
            fn execute(&mut self, _ctx: &CleanupContext) -> JobOutcome {
                self.log.borrow_mut().push(self.id.clone());
                JobOutcome::Completed
            }
            fn phase(&self) -> CleanupPhase {
                CleanupPhase::ExtentFree
            }
            fn job_id(&self) -> &str {
                &self.id
            }
            fn priority(&self) -> u32 {
                self.prio
            }
        }

        let log = Rc::new(RefCell::new(Vec::new()));
        let mut s = JobScheduler::new();

        // Lower priority value = higher urgency = dispatched first
        s.register(Box::new(PrioJob {
            id: "c".into(),
            prio: 3,
            log: log.clone(),
        }));
        s.register(Box::new(PrioJob {
            id: "a".into(),
            prio: 1,
            log: log.clone(),
        }));
        s.register(Box::new(PrioJob {
            id: "b".into(),
            prio: 2,
            log: log.clone(),
        }));

        s.on_commit(1, 1);
        let order = log.borrow();
        assert_eq!(order[0], "a"); // prio 1 first
        assert_eq!(order[1], "b"); // prio 2 second
        assert_eq!(order[2], "c"); // prio 3 last
    }

    #[test]
    fn scheduler_incomplete_job_retained() {
        let mut s = JobScheduler::new();
        s.register(Box::new(MockDeferredJob::new_incomplete(
            "inc",
            CleanupPhase::ExtentFree,
        )));

        // First commit: incomplete -> retained
        s.on_commit(1, 1);
        assert!(!s.is_empty());
        assert_eq!(s.job_count(), 1);
        assert_eq!(s.total_completed(), 0);

        // Second commit: incomplete -> retained
        s.on_commit(2, 1);
        assert!(!s.is_empty());
        assert_eq!(s.job_count(), 1);

        // Third commit: completes
        s.on_commit(3, 1);
        assert!(s.is_empty());
        assert_eq!(s.total_completed(), 1);
        assert_eq!(s.total_dispatched(), 3);
    }

    #[test]
    fn scheduler_retryable_job_reattempted() {
        let mut s = JobScheduler::new();
        s.register(Box::new(MockDeferredJob::new_retryable(
            "r",
            CleanupPhase::ExtentFree,
            2,
        )));

        // Attempt 1: Retryable
        s.on_commit(1, 1);
        assert!(!s.is_empty());
        assert_eq!(s.total_completed(), 0);

        // Attempt 2: Retryable
        s.on_commit(2, 1);
        assert!(!s.is_empty());

        // Attempt 3: Completes
        s.on_commit(3, 1);
        assert!(s.is_empty());
        assert_eq!(s.total_completed(), 1);
        assert_eq!(s.total_dispatched(), 3);
    }

    #[test]
    fn job_scheduler_retry_limit_exhausted() {
        let mut s = JobScheduler::new();
        s.set_max_retries(2);

        #[derive(Debug)]
        struct AlwaysRetry {
            phase: CleanupPhase,
            id: String,
        }
        impl DeferredCleanupJob for AlwaysRetry {
            fn execute(&mut self, _ctx: &CleanupContext) -> JobOutcome {
                JobOutcome::Retryable(CleanupError::retryable("again", self.phase))
            }
            fn phase(&self) -> CleanupPhase {
                self.phase
            }
            fn job_id(&self) -> &str {
                &self.id
            }
        }

        s.register(Box::new(AlwaysRetry {
            phase: CleanupPhase::ExtentFree,
            id: "ar".into(),
        }));

        // Attempt 1
        s.on_commit(1, 1);
        assert!(!s.is_empty());

        // Attempt 2 (max retries hit) -> exhausted, removed
        s.on_commit(2, 1);
        assert!(s.is_empty());
        assert_eq!(s.total_fatal(), 1);
    }

    #[test]
    fn scheduler_fatal_job_removed() {
        let mut s = JobScheduler::new();
        s.register(Box::new(MockDeferredJob::new_fatal(
            "f",
            CleanupPhase::SpacemapUpdate,
        )));

        s.on_commit(1, 1);
        assert!(s.is_empty());
        assert_eq!(s.total_fatal(), 1);
        assert_eq!(s.total_dispatched(), 1);
    }

    #[test]
    fn scheduler_diagnostics() {
        let mut s = JobScheduler::new();
        s.register(Box::new(MockDeferredJob::new_success(
            "a",
            CleanupPhase::ExtentFree,
        )));
        s.register(Box::new(MockDeferredJob::new_success(
            "b",
            CleanupPhase::DeadObjectRegister,
        )));

        let diag = s.diagnostics();
        assert_eq!(diag.len(), 2);
        let ids: Vec<&str> = diag.iter().map(|(id, _, _, _)| id.as_str()).collect();
        assert!(ids.contains(&"a"));
        assert!(ids.contains(&"b"));

        // All attempts should be 0 before dispatch
        for (_, _, attempts, _) in &diag {
            assert_eq!(*attempts, 0);
        }
    }

    #[test]
    fn scheduler_diagnostics_after_dispatch() {
        let mut s = JobScheduler::new();
        s.register(Box::new(MockDeferredJob::new_success(
            "x",
            CleanupPhase::ExtentFree,
        )));
        s.register(Box::new(MockDeferredJob::new_fatal(
            "y",
            CleanupPhase::OrphanReap,
        )));

        s.on_commit(1, 1);

        // After dispatch, both are terminal -> diagnostics should be empty
        let diag = s.diagnostics();
        assert_eq!(diag.len(), 0);
    }

    #[test]
    fn scheduler_multiple_commits() {
        let mut s = JobScheduler::new();
        s.register(Box::new(MockDeferredJob::new_success(
            "a",
            CleanupPhase::ExtentFree,
        )));
        s.register(Box::new(MockDeferredJob::new_success(
            "b",
            CleanupPhase::ExtentFree,
        )));

        // First commit dispatches both
        s.on_commit(1, 1);
        assert!(s.is_empty());

        // Second commit: nothing to do
        s.on_commit(2, 2);
        assert!(s.is_empty());
        assert_eq!(s.total_dispatched(), 2);
        assert_eq!(s.total_completed(), 2);
        assert_eq!(s.last_context().unwrap().epoch, 2);
    }

    #[test]
    fn scheduler_mixed_outcomes() {
        let mut s = JobScheduler::new();
        s.register(Box::new(MockDeferredJob::new_success(
            "ok",
            CleanupPhase::ExtentFree,
        )));
        s.register(Box::new(MockDeferredJob::new_fatal(
            "bad",
            CleanupPhase::ExtentFree,
        )));
        s.register(Box::new(MockDeferredJob::new_incomplete(
            "pend",
            CleanupPhase::ExtentFree,
        )));

        s.on_commit(1, 1);

        // ok: completed, bad: fatal, pend: incomplete -> retained
        assert_eq!(s.job_count(), 1);
        assert_eq!(s.total_completed(), 1);
        assert_eq!(s.total_fatal(), 1);

        let diag = s.diagnostics();
        assert_eq!(diag.len(), 1);
        assert_eq!(diag[0].0, "pend");
    }

    #[test]
    fn scheduler_default_constructor() {
        let s = JobScheduler::default();
        assert!(s.is_empty());
    }

    #[test]
    fn scheduler_debug_format() {
        let mut s = JobScheduler::new();
        s.register(Box::new(MockDeferredJob::new_success(
            "a",
            CleanupPhase::ExtentFree,
        )));
        let dbg = format!("{s:?}");
        assert!(dbg.contains("JobScheduler"));
        assert!(dbg.contains("job_count"));
    }

    #[test]
    fn txg_commit_observer_name() {
        let s = JobScheduler::new();
        assert_eq!(s.name(), "JobScheduler");
    }

    #[test]
    fn idempotent_execute_completed_job_returns_completed() {
        // A job that knows it's done for txg_id 1 should return Completed on
        // second invocation.
        #[derive(Debug)]
        struct IdempotentJob {
            already_done: bool,
        }
        impl DeferredCleanupJob for IdempotentJob {
            fn execute(&mut self, _ctx: &CleanupContext) -> JobOutcome {
                if self.already_done {
                    JobOutcome::Completed
                } else {
                    self.already_done = true;
                    JobOutcome::Incomplete
                }
            }
            fn phase(&self) -> CleanupPhase {
                CleanupPhase::ExtentFree
            }
            fn job_id(&self) -> &str {
                "idem"
            }
        }

        let mut s = JobScheduler::new();
        s.register(Box::new(IdempotentJob {
            already_done: false,
        }));

        s.on_commit(1, 1);
        assert_eq!(s.total_dispatched(), 1);
        assert_eq!(s.total_completed(), 0);
        assert!(!s.is_empty());

        // Second dispatch: job returns Completed
        s.on_commit(2, 2);
        assert_eq!(s.total_dispatched(), 2);
        assert_eq!(s.total_completed(), 1);
        assert!(s.is_empty());
    }
    // ── BtreeCleanupDeferredJob ──────────────────────────────────────

    #[test]
    fn btree_deferred_job_empty_queue_completes() {
        let queue = tidefs_cleanup_queue_core::BtreeCleanupQueue::new();
        let mut job = BtreeCleanupDeferredJob::new(queue, 10);
        let ctx = CleanupContext::new(1, 1);
        let outcome = job.execute(&ctx);
        assert!(outcome.is_completed());
    }

    #[test]
    fn btree_deferred_job_processes_batch() {
        let mut queue = tidefs_cleanup_queue_core::BtreeCleanupQueue::new();
        queue.enqueue(tidefs_cleanup_queue_core::BtreeCleanupEntry::new(
            1,
            10,
            tidefs_cleanup_queue_core::BtreeCleanupOp::MergeLeft,
            1,
        ));
        queue.enqueue(tidefs_cleanup_queue_core::BtreeCleanupEntry::new(
            1,
            20,
            tidefs_cleanup_queue_core::BtreeCleanupOp::MergeRight,
            1,
        ));
        assert_eq!(queue.pending_count(), 2);

        let mut job = BtreeCleanupDeferredJob::new(queue, 1);
        let ctx = CleanupContext::new(1, 1);

        // First execute: process 1 entry
        let outcome = job.execute(&ctx);
        assert!(!outcome.is_completed()); // one still pending
        assert_eq!(job.queue().pending_count(), 1);

        // Second execute: process remaining
        let outcome2 = job.execute(&ctx);
        assert!(outcome2.is_completed());
        assert_eq!(job.queue().pending_count(), 0);
    }

    #[test]
    fn btree_deferred_job_idempotent() {
        let mut queue = tidefs_cleanup_queue_core::BtreeCleanupQueue::new();
        queue.enqueue(tidefs_cleanup_queue_core::BtreeCleanupEntry::new(
            1,
            10,
            tidefs_cleanup_queue_core::BtreeCleanupOp::MergeLeft,
            1,
        ));

        let mut job = BtreeCleanupDeferredJob::new(queue, 10);
        let ctx = CleanupContext::new(1, 1);

        // First call processes the entry
        let outcome = job.execute(&ctx);
        assert!(outcome.is_completed());

        // Second call with same context: already done, should return Completed
        let outcome2 = job.execute(&ctx);
        assert!(outcome2.is_completed());
    }

    #[test]
    fn btree_deferred_job_job_id() {
        let queue = tidefs_cleanup_queue_core::BtreeCleanupQueue::new();
        let job = BtreeCleanupDeferredJob::new(queue, 10);
        assert!(job.job_id().starts_with("btree-cleanup-"));
    }

    #[test]
    fn btree_deferred_job_custom_id() {
        let queue = tidefs_cleanup_queue_core::BtreeCleanupQueue::new();
        let job = BtreeCleanupDeferredJob::new(queue, 10).with_id("my-cleanup");
        assert_eq!(job.job_id(), "my-cleanup");
    }

    #[test]
    fn btree_deferred_job_phase() {
        let queue = tidefs_cleanup_queue_core::BtreeCleanupQueue::new();
        let job = BtreeCleanupDeferredJob::new(queue, 10);
        assert_eq!(job.phase(), CleanupPhase::SpacemapUpdate);
    }

    #[test]
    fn btree_deferred_job_scheduler_integration() {
        let mut queue = tidefs_cleanup_queue_core::BtreeCleanupQueue::new();
        queue.enqueue(tidefs_cleanup_queue_core::BtreeCleanupEntry::new(
            1,
            42,
            tidefs_cleanup_queue_core::BtreeCleanupOp::Redistribute,
            1,
        ));

        let job = BtreeCleanupDeferredJob::new(queue, 10);
        let mut scheduler = JobScheduler::new();
        scheduler.register(Box::new(job));

        assert!(!scheduler.is_empty());
        scheduler.on_commit(1, 1);

        // After dispatch, the single entry should be processed
        // and the job removed (completed)
        assert!(scheduler.is_empty());
        assert_eq!(scheduler.total_completed(), 1);
    }

    #[test]
    fn btree_deferred_job_scheduler_multi_epoch() {
        let mut queue = tidefs_cleanup_queue_core::BtreeCleanupQueue::new();
        queue.enqueue(tidefs_cleanup_queue_core::BtreeCleanupEntry::new(
            1,
            1,
            tidefs_cleanup_queue_core::BtreeCleanupOp::MergeLeft,
            1,
        ));
        queue.enqueue(tidefs_cleanup_queue_core::BtreeCleanupEntry::new(
            1,
            2,
            tidefs_cleanup_queue_core::BtreeCleanupOp::MergeRight,
            1,
        ));

        let job = BtreeCleanupDeferredJob::new(queue, 1); // process 1 per tick
        let mut scheduler = JobScheduler::new();
        scheduler.register(Box::new(job));

        // Epoch 1: process first entry
        scheduler.on_commit(1, 1);
        assert!(!scheduler.is_empty()); // job still has 1 pending
        assert_eq!(scheduler.total_completed(), 0);

        // Epoch 2: process second entry
        scheduler.on_commit(2, 2);
        assert!(scheduler.is_empty());
        assert_eq!(scheduler.total_completed(), 1);
    }

    // ── process_batch_with / process_and_ack ────────────────────────

    #[test]
    fn process_batch_with_callback() {
        let mut queue = tidefs_cleanup_queue_core::BtreeCleanupQueue::new();
        queue.enqueue(tidefs_cleanup_queue_core::BtreeCleanupEntry::new(
            1,
            10,
            tidefs_cleanup_queue_core::BtreeCleanupOp::MergeLeft,
            1,
        ));
        queue.enqueue(tidefs_cleanup_queue_core::BtreeCleanupEntry::new(
            1,
            20,
            tidefs_cleanup_queue_core::BtreeCleanupOp::MergeRight,
            1,
        ));

        let mut job = BtreeCleanupDeferredJob::new(queue, 10);
        let mut seen = Vec::new();
        let count = job.process_batch_with(|entry| {
            seen.push(entry.node_id);
        });
        assert_eq!(count, 2);
        assert_eq!(seen, vec![10, 20]);
        // Entries NOT marked as processed
        assert_eq!(job.queue().pending_count(), 2);
    }

    #[test]
    fn process_and_ack_marks_entries() {
        let mut queue = tidefs_cleanup_queue_core::BtreeCleanupQueue::new();
        queue.enqueue(tidefs_cleanup_queue_core::BtreeCleanupEntry::new(
            1,
            42,
            tidefs_cleanup_queue_core::BtreeCleanupOp::Redistribute,
            1,
        ));

        let mut job = BtreeCleanupDeferredJob::new(queue, 10);
        let mut opts_seen = Vec::new();
        let count = job.process_and_ack(|entry| {
            opts_seen.push(entry.op);
        });
        assert_eq!(count, 1);
        assert!(opts_seen.contains(&tidefs_cleanup_queue_core::BtreeCleanupOp::Redistribute));
        // Entry marked as processed
        assert_eq!(job.queue().pending_count(), 0);
        assert_eq!(job.queue().processed_count(), 1);
    }

    #[test]
    fn process_and_ack_empty_queue() {
        let queue = tidefs_cleanup_queue_core::BtreeCleanupQueue::new();
        let mut job = BtreeCleanupDeferredJob::new(queue, 10);
        let count = job.process_and_ack(|_entry| {
            panic!("should not be called");
        });
        assert_eq!(count, 0);
    }
}
