// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Background-scheduler runtime handoff for admitted relocation decisions.
//!
//! The governor owns admission. This module owns the bounded runtime handoff:
//! an admitted decision becomes a stable, idempotent job that is driven by the
//! canonical background-service scheduler and may retire source receipts only
//! after the #911 action-execution predicates allow it.
//!
//! Concrete local defrag, rebuild/repair, evacuation, geo catch-up, and rebake
//! movers remain separate product components. They plug in through
//! [`RelocationDataMover`] and must return receipt-addressed action evidence;
//! this service refuses or blocks rather than fabricating mover, verification,
//! publication, or source-retirement evidence.

use crate::admission::{AdmissionRecord, AdmissionVerdict};
use crate::governor::{RelocationCompletionError, RelocationCompletionRecord, RelocationGovernor};
use crate::reasons::GovernorRelocationReason;
use tidefs_background_scheduler::{
    BackgroundService, ServiceBudget, ServiceError, ServicePriority, TickReport,
};
use tidefs_storage_intent_core::{
    action_execution_allows_source_retirement, action_execution_satisfies_completion,
    evidence_ref_is_kind, StorageIntentActionEvidenceState, StorageIntentActionExecutionEvidence,
    StorageIntentActionExecutionRefusalReason, StorageIntentActionTargetVerificationState,
    StorageIntentEvidenceId, StorageIntentEvidenceKind, StorageIntentEvidenceRef,
    StorageIntentObjectScope, StorageIntentPolicyId, StorageIntentPolicyRevision,
};
use tidefs_types_incremental_job_core::{JobId, JobKind};

/// Background service adaptor for the relocation governor and runtime queue.
///
/// The service implements the canonical [`BackgroundService`] trait directly
/// because it must coordinate a governor admission queue, mover output, #911
/// evidence predicates, and governor completion bookkeeping.
pub struct RelocationGovernorService {
    /// The underlying governor.
    pub governor: RelocationGovernor,

    /// Current time source (ms since epoch).
    now_ms: u64,

    /// Policy revision considered current by the runtime scheduler.
    current_policy_revision: Option<StorageIntentPolicyRevision>,

    /// Receipt-addressed mover selected by the integration layer.
    mover: Box<dyn RelocationDataMover>,

    /// Durable runtime jobs derived from admitted governor records.
    jobs: Vec<RelocationRuntimeJob>,
}

impl RelocationGovernorService {
    /// Create a new relocation governor service.
    ///
    /// The default mover refuses all execution. Integrations that can actually
    /// move bytes must install a concrete mover with [`Self::with_data_mover`].
    #[must_use]
    pub fn new(governor: RelocationGovernor) -> Self {
        RelocationGovernorService {
            governor,
            now_ms: 0,
            current_policy_revision: None,
            mover: Box::new(NoopRelocationDataMover),
            jobs: Vec::new(),
        }
    }

    /// Install the receipt-addressed mover selected by source inspection.
    #[must_use]
    pub fn with_data_mover(mut self, mover: Box<dyn RelocationDataMover>) -> Self {
        self.mover = mover;
        self
    }

    /// Advance the service clock.
    pub fn advance_time(&mut self, delta_ms: u64) {
        self.now_ms = self.now_ms.saturating_add(delta_ms);
    }

    /// Set the current time.
    pub fn set_time(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
    }

    /// Current time.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }

    /// Set the currently active policy revision for stale-decision checks.
    pub fn set_current_policy_revision(&mut self, revision: StorageIntentPolicyRevision) {
        self.current_policy_revision = Some(revision);
    }

    /// Enqueue a runtime job derived from an admitted governor record.
    pub fn enqueue_job(
        &mut self,
        job: RelocationRuntimeJob,
    ) -> Result<(), RelocationRuntimeEnqueueError> {
        if job.admission.verdict != AdmissionVerdict::Admitted {
            return Err(RelocationRuntimeEnqueueError::AdmissionNotExecutable);
        }
        if self
            .jobs
            .iter()
            .any(|existing| existing.job_id == job.job_id || existing.action_id == job.action_id)
        {
            return Err(RelocationRuntimeEnqueueError::DuplicateRuntimeJob);
        }
        self.jobs.push(job);
        Ok(())
    }

    /// Runtime jobs owned by the service.
    #[must_use]
    pub fn jobs(&self) -> &[RelocationRuntimeJob] {
        &self.jobs
    }

    /// Mutable runtime job lookup by stable job id.
    #[must_use]
    pub fn job_mut(&mut self, job_id: JobId) -> Option<&mut RelocationRuntimeJob> {
        self.jobs.iter_mut().find(|job| job.job_id == job_id)
    }

    /// Poll the governor and runtime queue.
    #[must_use]
    pub fn poll(&mut self) -> GovernorPollResult {
        self.governor.expire_cooldowns(self.now_ms);

        GovernorPollResult {
            admitted_count: self.governor.admitted_count(),
            bytes_in_flight: self.governor.bytes_in_flight(),
            can_admit: self.governor.can_admit(),
            runtime_jobs: self.jobs.iter().filter(|job| job.has_work()).count(),
        }
    }

    fn first_work_job(&self) -> Option<&RelocationRuntimeJob> {
        self.jobs.iter().find(|job| job.has_work())
    }
}

impl BackgroundService for RelocationGovernorService {
    fn name(&self) -> &'static str {
        "relocation-governor"
    }

    fn priority(&self) -> ServicePriority {
        self.first_work_job()
            .map(RelocationRuntimeJob::scheduler_priority)
            .unwrap_or(ServicePriority::BestEffort)
    }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        self.governor.expire_cooldowns(self.now_ms);

        let mut remaining = *budget;
        let mut report = TickReport::default();
        let max_jobs = if budget.max_items == 0 {
            self.jobs.len()
        } else {
            budget.max_items as usize
        };
        let mut completions = Vec::new();

        for _ in 0..max_jobs {
            let Some(index) = self.jobs.iter().position(RelocationRuntimeJob::has_work) else {
                break;
            };
            if service_budget_exhausted(*budget, remaining) {
                break;
            }

            let per_job_budget = ServiceBudget {
                max_items: if remaining.max_items == 0 { 0 } else { 1 },
                max_bytes: remaining.max_bytes,
                max_ms: remaining.max_ms,
            };
            let drive = drive_relocation_job(
                &mut self.jobs[index],
                self.mover.as_mut(),
                self.current_policy_revision,
                self.now_ms,
                per_job_budget,
            );
            remaining.subtract_consumed(
                drive.report.items_consumed,
                drive.report.bytes_consumed,
                0,
            );
            report.merge(&drive.report);
            if let Some(completion) = drive.completion {
                completions.push((index, completion));
            }
        }

        for (index, completion) in completions {
            if let Err(error) = self.governor.record_relocation_completed(completion) {
                if let Some(job) = self.jobs.get_mut(index) {
                    job.block(RelocationRuntimeRefusal::GovernorCompletionRejected);
                }
                return Err(ServiceError::Internal {
                    service: "relocation-governor",
                    message: completion_error_message(error),
                });
            }
        }

        report.has_more = self.jobs.iter().any(RelocationRuntimeJob::has_work);
        Ok(report)
    }

    fn has_work(&self) -> bool {
        self.jobs.iter().any(RelocationRuntimeJob::has_work)
    }

    fn dispatch_identity(&self) -> Option<(JobId, JobKind)> {
        self.first_work_job()
            .map(|job| (job.job_id, job.job_kind()))
    }
}

/// Result of polling the governor service.
#[derive(Clone, Copy, Debug)]
pub struct GovernorPollResult {
    /// Number of currently admitted relocations.
    pub admitted_count: usize,

    /// Total bytes in flight.
    pub bytes_in_flight: u64,

    /// Whether the governor can admit more relocations.
    pub can_admit: bool,

    /// Number of runtime jobs that still have schedulable work.
    pub runtime_jobs: usize,
}

/// Error returned when a job cannot enter the runtime queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationRuntimeEnqueueError {
    /// The governor did not admit this action for authority-changing runtime.
    AdmissionNotExecutable,
    /// A job with the same stable action or job id is already queued.
    DuplicateRuntimeJob,
}

/// Runtime reason for selecting the concrete mover family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationMoverKind {
    /// Local extent-map/object defragmentation or compaction mover.
    LocalMaintenance,
    /// Local receipt-publishing placement movement.
    LocalReceiptMovement,
    /// Distributed rebuild/repair mover.
    DistributedRepair,
    /// Device/member evacuation mover.
    Evacuation,
    /// Geo catch-up mover.
    GeoCatchup,
    /// Rebake/data-shape mover.
    Rebake,
}

impl RelocationMoverKind {
    /// Select the mover family from the governor reason.
    #[must_use]
    pub const fn from_reason(reason: GovernorRelocationReason) -> Self {
        match reason {
            GovernorRelocationReason::HddDefrag | GovernorRelocationReason::SsdCompaction => {
                Self::LocalMaintenance
            }
            GovernorRelocationReason::PolicySatisfaction
            | GovernorRelocationReason::Promotion
            | GovernorRelocationReason::Demotion
            | GovernorRelocationReason::WearRebalance => Self::LocalReceiptMovement,
            GovernorRelocationReason::Repair => Self::DistributedRepair,
            GovernorRelocationReason::Evacuation => Self::Evacuation,
            GovernorRelocationReason::GeoCatchup => Self::GeoCatchup,
            GovernorRelocationReason::Rebake => Self::Rebake,
        }
    }
}

/// Budget and evidence refs that must be present before a runtime move starts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelocationRuntimeBudgetRefs {
    pub capacity_ref: StorageIntentEvidenceRef,
    pub tenant_isolation_ref: StorageIntentEvidenceRef,
    pub media_capability_ref: StorageIntentEvidenceRef,
    pub service_objective_ref: StorageIntentEvidenceRef,
    pub wear_cost_ref: StorageIntentEvidenceRef,
    pub non_wear_cost_ref: StorageIntentEvidenceRef,
    pub retention_ref: StorageIntentEvidenceRef,
    pub result_refusal_ref: StorageIntentEvidenceRef,
}

impl RelocationRuntimeBudgetRefs {
    /// Returns true when the runtime has the budget/evidence refs required to
    /// avoid treating unknown cost, wear, capacity, or result state as success.
    #[must_use]
    pub const fn has_required_refs(self) -> bool {
        evidence_ref_is_kind(
            self.capacity_ref,
            StorageIntentEvidenceKind::CapacityAdmissionEvidence,
        ) && evidence_ref_is_kind(
            self.tenant_isolation_ref,
            StorageIntentEvidenceKind::TenantIsolationEvidence,
        ) && evidence_ref_is_kind(
            self.media_capability_ref,
            StorageIntentEvidenceKind::MediaCapabilityEvidence,
        ) && evidence_ref_is_kind(
            self.service_objective_ref,
            StorageIntentEvidenceKind::ServiceObjectiveEvidence,
        ) && evidence_ref_is_kind(
            self.wear_cost_ref,
            StorageIntentEvidenceKind::MediaCostWearLedger,
        ) && evidence_ref_is_kind(
            self.non_wear_cost_ref,
            StorageIntentEvidenceKind::MediaCostWearLedger,
        ) && evidence_ref_is_kind(
            self.retention_ref,
            StorageIntentEvidenceKind::EvidenceRetentionEvidence,
        ) && evidence_ref_is_kind(
            self.result_refusal_ref,
            StorageIntentEvidenceKind::ResultRefusalEvidence,
        )
    }
}

/// Durable runtime state for an admitted relocation action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelocationRuntimeJob {
    pub job_id: JobId,
    pub admission: AdmissionRecord,
    pub subject_id: u64,
    pub action_id: StorageIntentEvidenceId,
    pub subject_scope: StorageIntentObjectScope,
    pub source_receipt_ref: StorageIntentEvidenceRef,
    pub target_placement_ref: StorageIntentEvidenceRef,
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub retry_generation: u32,
    pub budget_refs: RelocationRuntimeBudgetRefs,
    pub mover_kind: RelocationMoverKind,
    pub total_bytes: u64,
    pub bytes_moved: u64,
    pub action_evidence: StorageIntentActionExecutionEvidence,
    pub state: RelocationRuntimeState,
    pub last_refusal: Option<RelocationRuntimeRefusal>,
}

impl RelocationRuntimeJob {
    /// Create a runtime job from an admitted governor record.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        job_id: JobId,
        admission: AdmissionRecord,
        subject_id: u64,
        action_id: StorageIntentEvidenceId,
        subject_scope: StorageIntentObjectScope,
        source_receipt_ref: StorageIntentEvidenceRef,
        target_placement_ref: StorageIntentEvidenceRef,
        policy_id: StorageIntentPolicyId,
        policy_revision: StorageIntentPolicyRevision,
        retry_generation: u32,
        budget_refs: RelocationRuntimeBudgetRefs,
        total_bytes: u64,
        action_evidence: StorageIntentActionExecutionEvidence,
    ) -> Self {
        let mover_kind = RelocationMoverKind::from_reason(admission.reason);
        Self {
            job_id,
            admission,
            subject_id,
            action_id,
            subject_scope,
            source_receipt_ref,
            target_placement_ref,
            policy_id,
            policy_revision,
            retry_generation,
            budget_refs,
            mover_kind,
            total_bytes,
            bytes_moved: 0,
            action_evidence,
            state: RelocationRuntimeState::Pending,
            last_refusal: None,
        }
    }

    /// Returns true when this job still needs scheduler attention.
    #[must_use]
    pub const fn has_work(&self) -> bool {
        !self.state.is_terminal()
    }

    /// Canonical job kind used for dispatch tracking.
    #[must_use]
    pub const fn job_kind(&self) -> JobKind {
        match self.admission.reason {
            GovernorRelocationReason::Repair => JobKind::Rebuild,
            GovernorRelocationReason::GeoCatchup => JobKind::Backfill,
            GovernorRelocationReason::PolicySatisfaction
            | GovernorRelocationReason::Promotion
            | GovernorRelocationReason::Demotion
            | GovernorRelocationReason::WearRebalance => JobKind::Rebalance,
            GovernorRelocationReason::Evacuation => JobKind::AdminJob,
            GovernorRelocationReason::HddDefrag | GovernorRelocationReason::SsdCompaction => {
                JobKind::Defrag
            }
            GovernorRelocationReason::Rebake => JobKind::Rebake,
        }
    }

    /// Scheduler priority chosen from source-inspected mover family.
    #[must_use]
    pub const fn scheduler_priority(&self) -> ServicePriority {
        match self.admission.reason {
            GovernorRelocationReason::Repair | GovernorRelocationReason::Evacuation => {
                ServicePriority::Critical
            }
            GovernorRelocationReason::GeoCatchup | GovernorRelocationReason::Rebake => {
                ServicePriority::Throughput
            }
            GovernorRelocationReason::PolicySatisfaction => ServicePriority::BestEffort,
            GovernorRelocationReason::HddDefrag
            | GovernorRelocationReason::SsdCompaction
            | GovernorRelocationReason::Promotion
            | GovernorRelocationReason::Demotion
            | GovernorRelocationReason::WearRebalance => ServicePriority::Opportunistic,
        }
    }

    fn preflight_refusal(
        &self,
        current_policy_revision: Option<StorageIntentPolicyRevision>,
    ) -> Option<RelocationRuntimeRefusal> {
        if self.job_id.is_none()
            || self.action_id == StorageIntentEvidenceId::ZERO
            || self.subject_scope.dataset_id.is_zero()
        {
            return Some(RelocationRuntimeRefusal::MissingActionIdentity);
        }
        if self.admission.verdict != AdmissionVerdict::Admitted {
            return Some(RelocationRuntimeRefusal::AdmissionNotExecutable);
        }
        if !self.source_receipt_ref.is_bound() {
            return Some(RelocationRuntimeRefusal::MissingSourceReceipt);
        }
        if !self.target_placement_ref.is_bound() {
            return Some(RelocationRuntimeRefusal::MissingTargetPlacement);
        }
        if self.policy_id.is_zero() || self.policy_revision.0 == 0 {
            return Some(RelocationRuntimeRefusal::MissingPolicyEvidence);
        }
        if current_policy_revision.is_some_and(|revision| revision != self.policy_revision)
            || self.action_evidence.policy_revision != self.policy_revision
            || self.action_evidence.action_id != self.action_id
            || self.action_evidence.replay.retry_generation != self.retry_generation
        {
            return Some(RelocationRuntimeRefusal::StalePolicyRevision);
        }
        if !self.budget_refs.has_required_refs() {
            return Some(RelocationRuntimeRefusal::MissingRuntimeBudgetEvidence);
        }
        if self.action_evidence.evidence_state != StorageIntentActionEvidenceState::Fresh {
            return Some(RelocationRuntimeRefusal::StaleActionEvidence);
        }

        preflight_action_refusal(self.action_evidence.action_refusal())
    }

    fn block(&mut self, refusal: RelocationRuntimeRefusal) {
        self.state = RelocationRuntimeState::Blocked;
        self.last_refusal = Some(refusal);
    }

    fn refuse(&mut self, refusal: RelocationRuntimeRefusal) {
        self.state = RelocationRuntimeState::Refused;
        self.last_refusal = Some(refusal);
    }

    fn completion_record(&self, now_ms: u64) -> RelocationCompletionRecord {
        RelocationCompletionRecord {
            admission_id: self.admission.admission_id,
            subject_id: self.subject_id,
            source_receipt_id: self.admission.source_receipt_id,
            reason: self.admission.reason,
            bytes: self.bytes_moved,
            completed_at_ms: now_ms,
            replacement_receipt_ref: self.action_evidence.publication.replacement_receipt_ref,
            source_retirement_ref: self.action_evidence.evidence_ref,
            action_completion_ref: self.action_evidence.action_completion_ref,
            result_refusal_ref: self.budget_refs.result_refusal_ref,
        }
    }
}

/// Runtime state machine for an admitted relocation job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationRuntimeState {
    Pending,
    Copying,
    Verifying,
    Publishing,
    RetiringSource,
    Complete,
    Blocked,
    Refused,
    Aborted,
    RolledBack,
}

impl RelocationRuntimeState {
    /// Returns true when the scheduler should not continue this job without
    /// fresh external evidence or a new admission.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Complete | Self::Blocked | Self::Refused | Self::Aborted | Self::RolledBack
        )
    }
}

/// Runtime refusal or blocker recorded on a relocation job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationRuntimeRefusal {
    AdmissionNotExecutable,
    MissingActionIdentity,
    MissingSourceReceipt,
    MissingTargetPlacement,
    MissingPolicyEvidence,
    StalePolicyRevision,
    StaleActionEvidence,
    MissingRuntimeBudgetEvidence,
    DataMoverUnavailable,
    DataMoverRefused,
    DuplicateDeliverySuppressed,
    TargetVerificationFailed,
    MissingTargetVerification,
    MissingPublicationEvidence,
    MissingActionCompletionEvidence,
    SourceRetirementForbidden,
    GovernorCompletionRejected,
    ActionEvidenceRefused(StorageIntentActionExecutionRefusalReason),
}

/// Result from one bounded mover invocation.
#[derive(Clone, Debug)]
pub struct RelocationMoveOutcome {
    pub status: RelocationMoveStatus,
    pub bytes_moved: u64,
    pub action_evidence: StorageIntentActionExecutionEvidence,
}

impl RelocationMoveOutcome {
    /// Mover made progress and may need another tick.
    #[must_use]
    pub const fn progress(
        bytes_moved: u64,
        action_evidence: StorageIntentActionExecutionEvidence,
    ) -> Self {
        Self {
            status: RelocationMoveStatus::Progress,
            bytes_moved,
            action_evidence,
        }
    }

    /// Mover finished the data-copy phase and returned completion evidence.
    #[must_use]
    pub const fn complete(
        bytes_moved: u64,
        action_evidence: StorageIntentActionExecutionEvidence,
    ) -> Self {
        Self {
            status: RelocationMoveStatus::Complete,
            bytes_moved,
            action_evidence,
        }
    }

    /// Mover could not run yet but did not weaken authority.
    #[must_use]
    pub const fn deferred(action_evidence: StorageIntentActionExecutionEvidence) -> Self {
        Self {
            status: RelocationMoveStatus::Deferred,
            bytes_moved: 0,
            action_evidence,
        }
    }

    /// Mover refused execution.
    #[must_use]
    pub const fn refused(
        refusal: RelocationRuntimeRefusal,
        action_evidence: StorageIntentActionExecutionEvidence,
    ) -> Self {
        Self {
            status: RelocationMoveStatus::Refused(refusal),
            bytes_moved: 0,
            action_evidence,
        }
    }
}

/// Mover status for one runtime tick.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationMoveStatus {
    Progress,
    Complete,
    Deferred,
    Refused(RelocationRuntimeRefusal),
}

/// Receipt-addressed relocation mover selected by the integration layer.
pub trait RelocationDataMover: Send {
    /// Execute one bounded data-movement step and return updated #911 evidence.
    fn move_step(
        &mut self,
        job: &RelocationRuntimeJob,
        budget: ServiceBudget,
    ) -> RelocationMoveOutcome;
}

#[derive(Debug)]
struct NoopRelocationDataMover;

impl RelocationDataMover for NoopRelocationDataMover {
    fn move_step(
        &mut self,
        job: &RelocationRuntimeJob,
        _budget: ServiceBudget,
    ) -> RelocationMoveOutcome {
        RelocationMoveOutcome::refused(
            RelocationRuntimeRefusal::DataMoverUnavailable,
            job.action_evidence,
        )
    }
}

struct RelocationRuntimeDriveResult {
    report: TickReport,
    completion: Option<RelocationCompletionRecord>,
}

fn drive_relocation_job(
    job: &mut RelocationRuntimeJob,
    mover: &mut dyn RelocationDataMover,
    current_policy_revision: Option<StorageIntentPolicyRevision>,
    now_ms: u64,
    budget: ServiceBudget,
) -> RelocationRuntimeDriveResult {
    let mut report = TickReport {
        items_consumed: 1,
        ..TickReport::default()
    };

    if let Some(refusal) = job.preflight_refusal(current_policy_revision) {
        job.refuse(refusal);
        report.errors = 1;
        return RelocationRuntimeDriveResult {
            report,
            completion: None,
        };
    }

    if job.state == RelocationRuntimeState::Pending {
        job.state = RelocationRuntimeState::Copying;
    }

    if job.state == RelocationRuntimeState::Copying {
        let outcome = mover.move_step(job, budget);
        job.action_evidence = outcome.action_evidence;
        job.bytes_moved = job.bytes_moved.saturating_add(outcome.bytes_moved);
        report.bytes_consumed = outcome.bytes_moved;

        match outcome.status {
            RelocationMoveStatus::Deferred => {
                report.skipped = 1;
                report.has_more = true;
                return RelocationRuntimeDriveResult {
                    report,
                    completion: None,
                };
            }
            RelocationMoveStatus::Refused(refusal) => {
                job.refuse(refusal);
                report.errors = 1;
                return RelocationRuntimeDriveResult {
                    report,
                    completion: None,
                };
            }
            RelocationMoveStatus::Progress => {
                report.processed = 1;
                if job.bytes_moved < job.total_bytes {
                    report.has_more = true;
                    return RelocationRuntimeDriveResult {
                        report,
                        completion: None,
                    };
                }
            }
            RelocationMoveStatus::Complete => {
                report.processed = 1;
            }
        }
        job.state = RelocationRuntimeState::Verifying;
    }

    if job.state == RelocationRuntimeState::Verifying {
        if matches!(
            job.action_evidence.target_verification.state,
            StorageIntentActionTargetVerificationState::DigestMismatch
                | StorageIntentActionTargetVerificationState::PartialWrite
                | StorageIntentActionTargetVerificationState::DegradedPartial
                | StorageIntentActionTargetVerificationState::Refused
        ) {
            job.state = RelocationRuntimeState::RolledBack;
            job.last_refusal = Some(RelocationRuntimeRefusal::TargetVerificationFailed);
            report.errors = 1;
            return RelocationRuntimeDriveResult {
                report,
                completion: None,
            };
        }

        if !job.action_evidence.target_verification.is_complete() {
            job.block(RelocationRuntimeRefusal::MissingTargetVerification);
            report.errors = 1;
            return RelocationRuntimeDriveResult {
                report,
                completion: None,
            };
        }
        job.state = RelocationRuntimeState::Publishing;
    }

    if job.state == RelocationRuntimeState::Publishing {
        if !job.action_evidence.publication.is_complete() {
            job.block(RelocationRuntimeRefusal::MissingPublicationEvidence);
            report.errors = 1;
            return RelocationRuntimeDriveResult {
                report,
                completion: None,
            };
        }
        job.state = RelocationRuntimeState::RetiringSource;
    }

    if job.state == RelocationRuntimeState::RetiringSource {
        if !action_execution_satisfies_completion(job.action_evidence).satisfied {
            job.block(RelocationRuntimeRefusal::MissingActionCompletionEvidence);
            report.errors = 1;
            return RelocationRuntimeDriveResult {
                report,
                completion: None,
            };
        }
        if !action_execution_allows_source_retirement(job.action_evidence).satisfied {
            job.block(RelocationRuntimeRefusal::SourceRetirementForbidden);
            report.errors = 1;
            return RelocationRuntimeDriveResult {
                report,
                completion: None,
            };
        }

        job.state = RelocationRuntimeState::Complete;
        let completion = job.completion_record(now_ms);
        return RelocationRuntimeDriveResult {
            report,
            completion: Some(completion),
        };
    }

    RelocationRuntimeDriveResult {
        report,
        completion: None,
    }
}

const fn service_budget_exhausted(initial: ServiceBudget, remaining: ServiceBudget) -> bool {
    (initial.max_items > 0 && remaining.max_items == 0)
        || (initial.max_bytes > 0 && remaining.max_bytes == 0)
        || (initial.max_ms > 0 && remaining.max_ms == 0)
}

const fn preflight_action_refusal(
    refusal: StorageIntentActionExecutionRefusalReason,
) -> Option<RelocationRuntimeRefusal> {
    match refusal {
        StorageIntentActionExecutionRefusalReason::None
        | StorageIntentActionExecutionRefusalReason::MissingTargetVerification
        | StorageIntentActionExecutionRefusalReason::PartialTargetWrite
        | StorageIntentActionExecutionRefusalReason::TargetWriteIsNotCompletion
        | StorageIntentActionExecutionRefusalReason::MissingPublicationEvidence
        | StorageIntentActionExecutionRefusalReason::MissingOrderingEvidence
        | StorageIntentActionExecutionRefusalReason::MissingRecoveryDegradationEvidence
        | StorageIntentActionExecutionRefusalReason::MissingActionCompletionEvidence
        | StorageIntentActionExecutionRefusalReason::SourceRetirementForbidden => None,
        StorageIntentActionExecutionRefusalReason::DuplicateActionDelivery => {
            Some(RelocationRuntimeRefusal::DuplicateDeliverySuppressed)
        }
        other => Some(RelocationRuntimeRefusal::ActionEvidenceRefused(other)),
    }
}

const fn completion_error_message(error: RelocationCompletionError) -> &'static str {
    match error {
        RelocationCompletionError::NotAdmitted => "runtime completion has no admitted subject",
        RelocationCompletionError::SubjectMismatch => "runtime completion subject mismatch",
        RelocationCompletionError::SourceReceiptMismatch => {
            "runtime completion source receipt mismatch"
        }
        RelocationCompletionError::ReasonMismatch => "runtime completion reason mismatch",
        RelocationCompletionError::MissingReplacementReceipt => {
            "runtime completion missing replacement receipt"
        }
        RelocationCompletionError::MissingSourceRetirementEvidence => {
            "runtime completion missing source-retirement evidence"
        }
        RelocationCompletionError::MissingActionCompletionEvidence => {
            "runtime completion missing action-completion evidence"
        }
        RelocationCompletionError::MissingResultRefusalEvidence => {
            "runtime completion missing result/refusal evidence"
        }
    }
}

/// Relocation governor job kind for the incremental-job model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationJobKind {
    /// HDD defrag job.
    HddDefrag,

    /// SSD compaction job.
    SsdCompaction,

    /// Wear rebalance job.
    WearRebalance,

    /// Geo catch-up job.
    GeoCatchup,

    /// Rebake (data-shape transform) job.
    Rebake,

    /// Promotion job.
    Promotion,

    /// Demotion job.
    Demotion,

    /// Policy satisfaction job.
    PolicySatisfaction,

    /// Repair/rebuild job.
    Repair,

    /// Evacuation/drain job.
    Evacuation,
}

impl RelocationJobKind {
    /// Map from governor relocation reason.
    #[must_use]
    pub const fn from_reason(reason: GovernorRelocationReason) -> Self {
        match reason {
            GovernorRelocationReason::PolicySatisfaction => RelocationJobKind::PolicySatisfaction,
            GovernorRelocationReason::Repair => RelocationJobKind::Repair,
            GovernorRelocationReason::Evacuation => RelocationJobKind::Evacuation,
            GovernorRelocationReason::HddDefrag => RelocationJobKind::HddDefrag,
            GovernorRelocationReason::SsdCompaction => RelocationJobKind::SsdCompaction,
            GovernorRelocationReason::Rebake => RelocationJobKind::Rebake,
            GovernorRelocationReason::Promotion => RelocationJobKind::Promotion,
            GovernorRelocationReason::Demotion => RelocationJobKind::Demotion,
            GovernorRelocationReason::GeoCatchup => RelocationJobKind::GeoCatchup,
            GovernorRelocationReason::WearRebalance => RelocationJobKind::WearRebalance,
        }
    }

    /// Stable diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RelocationJobKind::HddDefrag => "hdd-defrag",
            RelocationJobKind::SsdCompaction => "ssd-compaction",
            RelocationJobKind::WearRebalance => "wear-rebalance",
            RelocationJobKind::GeoCatchup => "geo-catchup",
            RelocationJobKind::Rebake => "rebake",
            RelocationJobKind::Promotion => "promotion",
            RelocationJobKind::Demotion => "demotion",
            RelocationJobKind::PolicySatisfaction => "policy-satisfaction",
            RelocationJobKind::Repair => "repair",
            RelocationJobKind::Evacuation => "evacuation",
        }
    }
}

impl core::fmt::Display for RelocationJobKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governor::RelocationGovernorConfig;
    use crate::hard_gates::HardGateEvidence;
    use crate::heuristics::{HeuristicInput, RelocationActionClass};
    use std::collections::VecDeque;
    use tidefs_background_scheduler::BackgroundScheduler;
    use tidefs_storage_intent_core::{
        StorageIntentActionAbortRollbackRecord, StorageIntentActionBudgetOutcomeRecord,
        StorageIntentActionClass,
        StorageIntentActionExecutionAdmissionRefs, StorageIntentActionExecutionFlags,
        StorageIntentActionExecutionReplayRecord, StorageIntentActionExecutionStepState,
        StorageIntentActionPublicationBoundaryRecord, StorageIntentActionPublicationState,
        StorageIntentActionReplayState, StorageIntentActionSourceProtectionRecord,
        StorageIntentActionTargetVerificationRecord, StorageIntentDomainId,
        StorageIntentReplayIdempotencyKey, StorageIntentSourceRetirementState,
    };

    #[derive(Clone)]
    struct ScriptedMover {
        outcomes: VecDeque<RelocationMoveOutcome>,
    }

    impl ScriptedMover {
        fn new(outcomes: Vec<RelocationMoveOutcome>) -> Self {
            Self {
                outcomes: outcomes.into(),
            }
        }
    }

    impl RelocationDataMover for ScriptedMover {
        fn move_step(
            &mut self,
            job: &RelocationRuntimeJob,
            _budget: ServiceBudget,
        ) -> RelocationMoveOutcome {
            match self.outcomes.pop_front() {
                Some(outcome) => outcome,
                None => RelocationMoveOutcome::deferred(job.action_evidence),
            }
        }
    }

    fn clean_evidence() -> HardGateEvidence {
        HardGateEvidence {
            source_receipt_authoritative: Some(true),
            target_satisfies_policy: Some(true),
            foreground_budget_available: Some(100),
            dirty_memory_budget_available: Some(1024 * 1024),
            transport_budget_available: Some(1024 * 1024),
            capacity_budget_available: Some(1024 * 1024),
            media_wear_budget_available: Some(1000),
            prediction_confidence: Some(3),
            action_class: Some(RelocationActionClass::AuthorityMovement),
            rollback_proof_available: Some(true),
            replacement_receipt_published: Some(true),
            media_capability_fresh: Some(true),
            target_media_eligible: Some(true),
            evidence_is_fresh: Some(true),
            evidence_is_consistent: Some(true),
        }
    }

    fn defrag_input() -> HeuristicInput {
        HeuristicInput {
            hdd_seek_distance: Some(1000),
            hdd_expected_seek_distance: Some(400),
            hdd_fragmentation_ratio: Some(0.6),
            hdd_expected_fragmentation_ratio: Some(0.2),
            relocation_bytes: Some(1024),
            ..HeuristicInput::default()
        }
    }

    fn admitted_record(reason: GovernorRelocationReason) -> (RelocationGovernor, AdmissionRecord) {
        let mut gov = RelocationGovernor::new(RelocationGovernorConfig {
            max_concurrent_relocations: 8,
            ..RelocationGovernorConfig::default()
        });
        let input = if reason == GovernorRelocationReason::HddDefrag {
            defrag_input()
        } else {
            HeuristicInput {
                relocation_bytes: Some(1024),
                ..HeuristicInput::default()
            }
        };
        let decision = gov.evaluate_proposal(
            42,
            reason,
            &input,
            &clean_evidence(),
            10,
            [1u8; 16],
            [2u8; 16],
        );
        assert_eq!(decision.verdict, AdmissionVerdict::Admitted);
        let record = gov.latest_admission_record().unwrap().clone();
        (gov, record)
    }

    fn runtime_job(
        admission: AdmissionRecord,
        evidence: StorageIntentActionExecutionEvidence,
    ) -> RelocationRuntimeJob {
        RelocationRuntimeJob::new(
            JobId(7),
            admission,
            42,
            evidence.action_id,
            subject_scope(),
            eref(StorageIntentEvidenceKind::PlacementReceipt, 90),
            eref(StorageIntentEvidenceKind::DecisionFrontierEvidence, 91),
            StorageIntentPolicyId([7u8; 16]),
            StorageIntentPolicyRevision(7),
            evidence.replay.retry_generation,
            budget_refs(),
            1024,
            evidence,
        )
    }

    fn subject_scope() -> StorageIntentObjectScope {
        StorageIntentObjectScope {
            dataset_id: StorageIntentDomainId([3u8; 16]),
            object_id: StorageIntentEvidenceId([4u8; 32]),
            range_start: 0,
            range_len: 1024,
            generation: 1,
        }
    }

    fn budget_refs() -> RelocationRuntimeBudgetRefs {
        RelocationRuntimeBudgetRefs {
            capacity_ref: eref(StorageIntentEvidenceKind::CapacityAdmissionEvidence, 10),
            tenant_isolation_ref: eref(StorageIntentEvidenceKind::TenantIsolationEvidence, 11),
            media_capability_ref: eref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 12),
            service_objective_ref: eref(StorageIntentEvidenceKind::ServiceObjectiveEvidence, 13),
            wear_cost_ref: eref(StorageIntentEvidenceKind::MediaCostWearLedger, 14),
            non_wear_cost_ref: eref(StorageIntentEvidenceKind::MediaCostWearLedger, 15),
            retention_ref: eref(StorageIntentEvidenceKind::EvidenceRetentionEvidence, 16),
            result_refusal_ref: eref(StorageIntentEvidenceKind::ResultRefusalEvidence, 17),
        }
    }

    fn action_evidence(
        step_state: StorageIntentActionExecutionStepState,
        target_state: StorageIntentActionTargetVerificationState,
        publication_state: StorageIntentActionPublicationState,
        retirement_state: StorageIntentSourceRetirementState,
        replay_state: StorageIntentActionReplayState,
    ) -> StorageIntentActionExecutionEvidence {
        action_evidence_with_identity(
            8,
            step_state,
            target_state,
            publication_state,
            retirement_state,
            replay_state,
        )
    }

    fn action_evidence_with_identity(
        identity_seed: u8,
        step_state: StorageIntentActionExecutionStepState,
        target_state: StorageIntentActionTargetVerificationState,
        publication_state: StorageIntentActionPublicationState,
        retirement_state: StorageIntentSourceRetirementState,
        replay_state: StorageIntentActionReplayState,
    ) -> StorageIntentActionExecutionEvidence {
        let action_id = StorageIntentEvidenceId([identity_seed; 32]);
        let flags = StorageIntentActionExecutionFlags::ACTION_IDENTITY
            .union(StorageIntentActionExecutionFlags::DECISION_FRONTIER_REF)
            .union(StorageIntentActionExecutionFlags::HARD_GATE_REF)
            .union(StorageIntentActionExecutionFlags::SELECTED_CANDIDATE_REF)
            .union(StorageIntentActionExecutionFlags::COUNTERFACTUAL_PAYBACK_REF)
            .union(StorageIntentActionExecutionFlags::RESERVE_ADMISSION_REF)
            .union(StorageIntentActionExecutionFlags::ISOLATION_REF)
            .union(StorageIntentActionExecutionFlags::MEDIA_CAPABILITY_REF)
            .union(StorageIntentActionExecutionFlags::RETENTION_REF)
            .union(StorageIntentActionExecutionFlags::IDEMPOTENCY_KEY)
            .union(StorageIntentActionExecutionFlags::STEP_SEQUENCE)
            .union(StorageIntentActionExecutionFlags::CRASH_RECOVERY_MARKER)
            .union(StorageIntentActionExecutionFlags::DUPLICATE_SUPPRESSION)
            .union(StorageIntentActionExecutionFlags::SOURCE_RECEIPTS)
            .union(StorageIntentActionExecutionFlags::ROLLBACK_SOURCES_RETAINED)
            .union(StorageIntentActionExecutionFlags::READ_SERVING_ELIGIBILITY)
            .union(StorageIntentActionExecutionFlags::FORBID_SOURCE_RETIREMENT_UNTIL_COMPLETE)
            .union(StorageIntentActionExecutionFlags::TARGET_RECEIPT_CANDIDATE)
            .union(StorageIntentActionExecutionFlags::TARGET_DIGEST_INTEGRITY)
            .union(StorageIntentActionExecutionFlags::MEDIA_FLUSH_BARRIER)
            .union(StorageIntentActionExecutionFlags::RECONSTRUCTION_WIDTH)
            .union(StorageIntentActionExecutionFlags::REPLACEMENT_PUBLICATION)
            .union(StorageIntentActionExecutionFlags::PUBLICATION_ORDERING)
            .union(StorageIntentActionExecutionFlags::RECOVERY_DEGRADATION_REF)
            .union(StorageIntentActionExecutionFlags::POLICY_ROLLOUT_REF)
            .union(StorageIntentActionExecutionFlags::VISIBLE_CONVERGING_STATE)
            .union(StorageIntentActionExecutionFlags::BUDGET_ACCOUNTING)
            .union(StorageIntentActionExecutionFlags::PAYBACK_ATTACHMENT)
            .union(StorageIntentActionExecutionFlags::COOLDOWN_DEPENDENCY)
            .union(StorageIntentActionExecutionFlags::ACTION_COMPLETION_PROOF);

        StorageIntentActionExecutionEvidence {
            evidence_ref: eref(StorageIntentEvidenceKind::ActionExecutionEvidence, 1),
            action_id,
            subject_scope: subject_scope(),
            action_class: StorageIntentActionClass::DurablePlacementMovement,
            producer_component_ref: eref(
                StorageIntentEvidenceKind::OperatorExplanationProjection,
                2,
            ),
            producer_version: 1,
            policy_id: StorageIntentPolicyId([7u8; 16]),
            policy_revision: StorageIntentPolicyRevision(7),
            execution_epoch: 1,
            temporal_ref: eref(StorageIntentEvidenceKind::TemporalEvidence, 3),
            integrity_ref: eref(StorageIntentEvidenceKind::ValidationArtifact, 4),
            evidence_query_snapshot_ref: eref(StorageIntentEvidenceKind::EvidenceQuerySnapshot, 5),
            admission_refs: StorageIntentActionExecutionAdmissionRefs {
                decision_frontier_ref: eref(StorageIntentEvidenceKind::DecisionFrontierEvidence, 6),
                hard_gate_result_ref: eref(StorageIntentEvidenceKind::ValidationArtifact, 7),
                selected_candidate_ref: eref(
                    StorageIntentEvidenceKind::DecisionFrontierEvidence,
                    8,
                ),
                counterfactual_payback_ref: eref(
                    StorageIntentEvidenceKind::PreflightSimulationEvidence,
                    9,
                ),
                reserve_admission_ref: eref(
                    StorageIntentEvidenceKind::CapacityAdmissionEvidence,
                    10,
                ),
                scheduler_admission_ref: eref(
                    StorageIntentEvidenceKind::SchedulerAdmissionRecord,
                    11,
                ),
                tenant_isolation_ref: eref(StorageIntentEvidenceKind::TenantIsolationEvidence, 12),
                media_capability_ref: eref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 13),
                evidence_retention_ref: eref(
                    StorageIntentEvidenceKind::EvidenceRetentionEvidence,
                    14,
                ),
            },
            step_state,
            replay: StorageIntentActionExecutionReplayRecord {
                idempotency_key: StorageIntentReplayIdempotencyKey([identity_seed; 16]),
                step_sequence: 1,
                retry_generation: 0,
                state: replay_state,
                crash_recovery_marker_ref: eref(
                    StorageIntentEvidenceKind::ActionExecutionEvidence,
                    18,
                ),
                duplicate_suppression_ref: eref(
                    StorageIntentEvidenceKind::ActionExecutionEvidence,
                    19,
                ),
                replay_refusal_ref: eref(StorageIntentEvidenceKind::ResultRefusalEvidence, 20),
            },
            source_protection: StorageIntentActionSourceProtectionRecord {
                source_receipts_ref: eref(StorageIntentEvidenceKind::PlacementReceipt, 21),
                old_placement_ref: eref(StorageIntentEvidenceKind::PlacementReceipt, 22),
                old_placement_generation: 1,
                retained_rollback_sources_ref: eref(
                    StorageIntentEvidenceKind::PlacementReceipt,
                    23,
                ),
                retained_rollback_source_count: 1,
                read_serving_eligibility_ref: eref(
                    StorageIntentEvidenceKind::ReadFreshnessEvidence,
                    24,
                ),
                read_serving_eligible: true,
                retirement_state,
            },
            target_verification: StorageIntentActionTargetVerificationRecord {
                state: target_state,
                target_receipt_candidate_ref: eref(StorageIntentEvidenceKind::PlacementReceipt, 25),
                digest_integrity_ref: eref(StorageIntentEvidenceKind::ValidationArtifact, 26),
                media_flush_barrier_ref: eref(
                    StorageIntentEvidenceKind::MediaCapabilityEvidence,
                    27,
                ),
                reconstruction_width: 2,
                required_reconstruction_width: 2,
                target_bytes: 1024,
                verified_bytes: if target_state
                    == StorageIntentActionTargetVerificationState::Verified
                {
                    1024
                } else {
                    512
                },
            },
            publication: StorageIntentActionPublicationBoundaryRecord {
                state: publication_state,
                replacement_receipt_ref: eref(StorageIntentEvidenceKind::PlacementReceipt, 28),
                ordering_evidence_ref: eref(StorageIntentEvidenceKind::OrderingEvidence, 29),
                recovery_degradation_ref: eref(
                    StorageIntentEvidenceKind::RecoveryDegradationEvidence,
                    30,
                ),
                policy_rollout_ref: eref(StorageIntentEvidenceKind::PolicyRolloutEvidence, 31),
                visible_state_ref: eref(
                    StorageIntentEvidenceKind::OperatorExplanationProjection,
                    32,
                ),
                operator_explanation_ref: eref(
                    StorageIntentEvidenceKind::OperatorExplanationProjection,
                    33,
                ),
                publication_sequence: 1,
            },
            abort_rollback: StorageIntentActionAbortRollbackRecord::default(),
            budget: StorageIntentActionBudgetOutcomeRecord {
                work_bytes: 1024,
                foreground_disruption_us: 10,
                media_write_bytes: 1024,
                network_egress_bytes: 0,
                reserve_consumed_bytes: 1024,
                reserve_budget_bytes: 4096,
                reserve_generation: 1,
                outcome_attachment_ref: eref(StorageIntentEvidenceKind::ResultRefusalEvidence, 34),
                payback_ref: eref(StorageIntentEvidenceKind::MediaCostWearLedger, 35),
                cooldown_dependency_ref: eref(
                    StorageIntentEvidenceKind::SchedulerAdmissionRecord,
                    36,
                ),
            },
            action_completion_ref: eref(StorageIntentEvidenceKind::ActionExecutionEvidence, 37),
            evidence_state: StorageIntentActionEvidenceState::Fresh,
            flags,
            refusal: StorageIntentActionExecutionRefusalReason::None,
        }
    }

    fn eref(kind: StorageIntentEvidenceKind, seed: u8) -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef::new(kind, StorageIntentEvidenceId([seed; 32]), 1, 1)
    }

    #[test]
    fn scheduler_tick_completes_after_publication_and_source_retirement() {
        let (gov, admission) = admitted_record(GovernorRelocationReason::HddDefrag);
        let evidence = action_evidence(
            StorageIntentActionExecutionStepState::Complete,
            StorageIntentActionTargetVerificationState::Verified,
            StorageIntentActionPublicationState::SourceRetirementPublished,
            StorageIntentSourceRetirementState::Ready,
            StorageIntentActionReplayState::FirstAttempt,
        );
        let job = runtime_job(admission, evidence);
        let mover = ScriptedMover::new(vec![RelocationMoveOutcome::complete(1024, evidence)]);
        let mut service = RelocationGovernorService::new(gov).with_data_mover(Box::new(mover));
        service.set_time(500);
        service.set_current_policy_revision(StorageIntentPolicyRevision(7));
        service.enqueue_job(job).unwrap();

        let report = service.tick(&ServiceBudget::MAINTENANCE_TICK).unwrap();
        assert_eq!(report.processed, 1);
        assert_eq!(service.governor.admitted_count(), 0);
        assert_eq!(service.jobs()[0].state, RelocationRuntimeState::Complete);
    }

    #[test]
    fn target_write_without_verification_does_not_retire_source() {
        let (gov, admission) = admitted_record(GovernorRelocationReason::HddDefrag);
        let mut evidence = action_evidence(
            StorageIntentActionExecutionStepState::Copying,
            StorageIntentActionTargetVerificationState::NotStarted,
            StorageIntentActionPublicationState::NotPublished,
            StorageIntentSourceRetirementState::PendingCompletion,
            StorageIntentActionReplayState::FirstAttempt,
        );
        evidence.target_verification.target_receipt_candidate_ref =
            StorageIntentEvidenceRef::default();
        let job = runtime_job(admission, evidence);
        let mover = ScriptedMover::new(vec![RelocationMoveOutcome::complete(1024, evidence)]);
        let mut service = RelocationGovernorService::new(gov).with_data_mover(Box::new(mover));
        service.set_current_policy_revision(StorageIntentPolicyRevision(7));
        service.enqueue_job(job).unwrap();

        let report = service.tick(&ServiceBudget::MAINTENANCE_TICK).unwrap();
        assert_eq!(report.errors, 1);
        assert_eq!(service.governor.admitted_count(), 1);
        assert_eq!(
            service.jobs()[0].last_refusal,
            Some(RelocationRuntimeRefusal::MissingTargetVerification)
        );
    }

    #[test]
    fn failed_verification_rolls_back_without_source_retirement() {
        let (gov, admission) = admitted_record(GovernorRelocationReason::HddDefrag);
        let evidence = action_evidence(
            StorageIntentActionExecutionStepState::Verifying,
            StorageIntentActionTargetVerificationState::DigestMismatch,
            StorageIntentActionPublicationState::NotPublished,
            StorageIntentSourceRetirementState::PendingCompletion,
            StorageIntentActionReplayState::FirstAttempt,
        );
        let job = runtime_job(admission, evidence);
        let mover = ScriptedMover::new(vec![RelocationMoveOutcome::complete(1024, evidence)]);
        let mut service = RelocationGovernorService::new(gov).with_data_mover(Box::new(mover));
        service.set_current_policy_revision(StorageIntentPolicyRevision(7));
        service.enqueue_job(job).unwrap();

        service.tick(&ServiceBudget::MAINTENANCE_TICK).unwrap();
        assert_eq!(service.jobs()[0].state, RelocationRuntimeState::RolledBack);
        assert_eq!(service.governor.admitted_count(), 1);
    }

    #[test]
    fn stale_policy_revalidation_blocks_runtime_job() {
        let (gov, admission) = admitted_record(GovernorRelocationReason::HddDefrag);
        let evidence = action_evidence(
            StorageIntentActionExecutionStepState::Complete,
            StorageIntentActionTargetVerificationState::Verified,
            StorageIntentActionPublicationState::SourceRetirementPublished,
            StorageIntentSourceRetirementState::Ready,
            StorageIntentActionReplayState::FirstAttempt,
        );
        let job = runtime_job(admission, evidence);
        let mover = ScriptedMover::new(vec![RelocationMoveOutcome::complete(1024, evidence)]);
        let mut service = RelocationGovernorService::new(gov).with_data_mover(Box::new(mover));
        service.set_current_policy_revision(StorageIntentPolicyRevision(8));
        service.enqueue_job(job).unwrap();

        let report = service.tick(&ServiceBudget::MAINTENANCE_TICK).unwrap();
        assert_eq!(report.errors, 1);
        assert_eq!(
            service.jobs()[0].last_refusal,
            Some(RelocationRuntimeRefusal::StalePolicyRevision)
        );
        assert_eq!(service.governor.admitted_count(), 1);
    }

    #[test]
    fn duplicate_delivery_is_suppressed_without_double_retirement() {
        let (gov, admission) = admitted_record(GovernorRelocationReason::HddDefrag);
        let evidence = action_evidence(
            StorageIntentActionExecutionStepState::Complete,
            StorageIntentActionTargetVerificationState::Verified,
            StorageIntentActionPublicationState::SourceRetirementPublished,
            StorageIntentSourceRetirementState::Ready,
            StorageIntentActionReplayState::DuplicateSuppressed,
        );
        let job = runtime_job(admission, evidence);
        let mover = ScriptedMover::new(vec![RelocationMoveOutcome::complete(1024, evidence)]);
        let mut service = RelocationGovernorService::new(gov).with_data_mover(Box::new(mover));
        service.set_current_policy_revision(StorageIntentPolicyRevision(7));
        service.enqueue_job(job).unwrap();

        let report = service.tick(&ServiceBudget::MAINTENANCE_TICK).unwrap();
        assert_eq!(report.errors, 1);
        assert_eq!(
            service.jobs()[0].last_refusal,
            Some(RelocationRuntimeRefusal::DuplicateDeliverySuppressed)
        );
        assert_eq!(service.governor.admitted_count(), 1);
    }

    #[test]
    fn scheduler_budget_processes_one_job_per_bounded_tick() {
        let (mut gov, first_admission) = admitted_record(GovernorRelocationReason::HddDefrag);
        let _ = gov.evaluate_proposal(
            43,
            GovernorRelocationReason::HddDefrag,
            &defrag_input(),
            &clean_evidence(),
            11,
            [3u8; 16],
            [4u8; 16],
        );
        let second_admission = gov.latest_admission_record().unwrap().clone();
        let first_evidence = action_evidence(
            StorageIntentActionExecutionStepState::Complete,
            StorageIntentActionTargetVerificationState::Verified,
            StorageIntentActionPublicationState::SourceRetirementPublished,
            StorageIntentSourceRetirementState::Ready,
            StorageIntentActionReplayState::FirstAttempt,
        );
        let second_evidence = action_evidence_with_identity(
            9,
            StorageIntentActionExecutionStepState::Complete,
            StorageIntentActionTargetVerificationState::Verified,
            StorageIntentActionPublicationState::SourceRetirementPublished,
            StorageIntentSourceRetirementState::Ready,
            StorageIntentActionReplayState::FirstAttempt,
        );
        let mut first = runtime_job(first_admission, first_evidence);
        first.job_id = JobId(70);
        let mut second = runtime_job(second_admission, second_evidence);
        second.job_id = JobId(71);
        second.subject_id = 43;
        let mover = ScriptedMover::new(vec![
            RelocationMoveOutcome::complete(1024, first_evidence),
            RelocationMoveOutcome::complete(1024, second_evidence),
        ]);
        let mut service = RelocationGovernorService::new(gov).with_data_mover(Box::new(mover));
        service.set_current_policy_revision(StorageIntentPolicyRevision(7));
        service.enqueue_job(first).unwrap();
        service.enqueue_job(second).unwrap();

        let report = service
            .tick(&ServiceBudget {
                max_items: 1,
                max_bytes: 4096,
                max_ms: 50,
            })
            .unwrap();
        assert_eq!(report.items_consumed, 1);
        assert_eq!(service.jobs()[0].state, RelocationRuntimeState::Complete);
        assert_eq!(service.jobs()[1].state, RelocationRuntimeState::Pending);
        assert_eq!(service.governor.admitted_count(), 1);
    }

    #[test]
    fn scheduler_byte_budget_preempts_follow_on_job() {
        let (mut gov, first_admission) = admitted_record(GovernorRelocationReason::HddDefrag);
        let _ = gov.evaluate_proposal(
            43,
            GovernorRelocationReason::HddDefrag,
            &defrag_input(),
            &clean_evidence(),
            11,
            [3u8; 16],
            [4u8; 16],
        );
        let second_admission = gov.latest_admission_record().unwrap().clone();
        let first_evidence = action_evidence(
            StorageIntentActionExecutionStepState::Complete,
            StorageIntentActionTargetVerificationState::Verified,
            StorageIntentActionPublicationState::SourceRetirementPublished,
            StorageIntentSourceRetirementState::Ready,
            StorageIntentActionReplayState::FirstAttempt,
        );
        let second_evidence = action_evidence_with_identity(
            9,
            StorageIntentActionExecutionStepState::Complete,
            StorageIntentActionTargetVerificationState::Verified,
            StorageIntentActionPublicationState::SourceRetirementPublished,
            StorageIntentSourceRetirementState::Ready,
            StorageIntentActionReplayState::FirstAttempt,
        );
        let mut first = runtime_job(first_admission, first_evidence);
        first.job_id = JobId(80);
        let mut second = runtime_job(second_admission, second_evidence);
        second.job_id = JobId(81);
        second.subject_id = 43;
        let mover = ScriptedMover::new(vec![
            RelocationMoveOutcome::complete(1024, first_evidence),
            RelocationMoveOutcome::complete(1024, second_evidence),
        ]);
        let mut service = RelocationGovernorService::new(gov).with_data_mover(Box::new(mover));
        service.set_current_policy_revision(StorageIntentPolicyRevision(7));
        service.enqueue_job(first).unwrap();
        service.enqueue_job(second).unwrap();

        let report = service
            .tick(&ServiceBudget {
                max_items: 0,
                max_bytes: 1024,
                max_ms: 50,
            })
            .unwrap();
        assert_eq!(report.bytes_consumed, 1024);
        assert_eq!(service.jobs()[0].state, RelocationRuntimeState::Complete);
        assert_eq!(service.jobs()[1].state, RelocationRuntimeState::Pending);
        assert_eq!(service.governor.admitted_count(), 1);
    }

    #[test]
    fn service_registers_with_background_scheduler() {
        let gov = RelocationGovernor::default();
        let service = RelocationGovernorService::new(gov);
        let mut scheduler = BackgroundScheduler::new(ServiceBudget::MAINTENANCE_TICK);
        scheduler.register(Box::new(service));
        assert_eq!(
            scheduler.registered_services()[0].name,
            "relocation-governor"
        );
    }

    #[test]
    fn job_kind_from_all_reasons() {
        for reason in &GovernorRelocationReason::ALL {
            let kind = RelocationJobKind::from_reason(*reason);
            assert!(!kind.to_string().is_empty());
        }
    }
}
