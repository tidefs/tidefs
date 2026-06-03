//! RebuildAdmission: bridges membership loss detection to rebuild/backfill
//! flow initiation.
//!
//! When a node departs or a device is lost, the admission controller:
//! 1. Records the loss event
//! 2. Identifies affected subjects that need replica recovery
//! 3. Generates DegradedReplicaReports for the BackfillScheduler
//! 4. Builds ReplicaMovementIntentRecords for the RebuildRuntime
//! 5. Tracks which members are under active rebuild
//!
//! Admission is idempotent: re-admitting an already-rebuilding member
//! returns the existing flow state rather than creating a duplicate.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::MemberId;
use tidefs_replication_model::{
    ObjectDigest, ReplicaMovementClass, ReplicaMovementIntentRecord, ReplicatedReceiptId,
    ReplicatedSubjectId,
};

use crate::scheduler::{BackfillScheduler, DegradedReplicaReport};
use crate::RebuildRuntimeBuilder;

// ─ RebuildAdmissionStatus ────────────────────────────────────────

/// Per-member rebuild admission status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RebuildAdmissionStatus {
    /// No rebuild is active for this member.
    Idle,
    /// Rebuild has been admitted and is in progress.
    Rebuilding,
    /// Rebuild completed successfully.
    Completed,
    /// Rebuild was refused (no healthy sources, insufficient capacity, etc.).
    Refused,
}

impl RebuildAdmissionStatus {
    #[must_use]
    pub fn is_active(self) -> bool {
        matches!(self, Self::Rebuilding)
    }

    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Refused)
    }
}

// ─ LossRecord ─────────────────────────────────────────────────────

/// A simplified loss record describing what was lost and what needs rebuilding.
///
/// This is the rebuild-runtime's own loss representation, decoupled from the
/// rebuild-planner's LossEvent so the runtime does not depend on the planner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LossRecord {
    /// Members that were lost and need their replicas rebuilt elsewhere.
    pub lost_members: Vec<MemberId>,
    /// Members that are still healthy and can serve as rebuild sources.
    pub healthy_sources: Vec<MemberId>,
    /// Subjects that were placed on the lost members and need new replicas.
    pub affected_subjects: Vec<AffectedSubject>,
    /// Epoch when the loss was detected.
    pub detected_epoch: u64,
    /// Timestamp when the loss was detected (nanoseconds).
    pub detected_at_ns: u64,
}

/// A subject that lost one or more replicas due to a node/device loss.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AffectedSubject {
    /// The subject that lost replica(s).
    pub subject_ref: ReplicatedSubjectId,
    /// Expected payload digest.
    pub payload_digest: ObjectDigest,
    /// Expected payload length.
    pub payload_len: u64,
    /// Movement class: Rebuild for lost copies, Backfill for lagged copies.
    pub movement_class: ReplicaMovementClass,
    /// Which of the lost members held this subject.
    pub lost_on: Vec<MemberId>,
}

// ─ AdmissionOutcome ───────────────────────────────────────────────

/// Result of attempting to admit a rebuild for a set of lost members.
#[derive(Clone, Debug)]
pub struct AdmissionOutcome {
    /// The members for which rebuild was admitted.
    pub admitted: Vec<MemberId>,
    /// The members for which rebuild was refused (already rebuilding, no sources, etc.).
    pub refused: Vec<(MemberId, AdmissionRefusalReason)>,
    /// The number of DegradedReplicaReports generated.
    pub report_count: usize,
    /// The number of ReplicaMovementIntentRecords generated.
    pub intent_count: usize,
}

/// Why a rebuild admission was refused for a specific member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionRefusalReason {
    /// Rebuild is already in progress for this member.
    AlreadyActive,
    /// No healthy source members are available.
    NoHealthySources,
    /// No affected subjects were found for this member.
    NoAffectedSubjects,
    /// Rebuild has already completed for this member.
    AlreadyCompleted,
}

// ─ RebuildAdmission ───────────────────────────────────────────────

/// Controls admission of rebuild/backfill flows after node/device loss.
///
/// Maintains per-member admission state, generates scheduler reports and
/// movement intents from loss records, and prevents duplicate rebuild flows.
#[derive(Clone, Debug, Default)]
pub struct RebuildAdmission {
    /// Per-member rebuild status.
    pub(crate) member_status: BTreeMap<MemberId, RebuildAdmissionStatus>,
    /// The next receipt ID for generated intents.
    next_receipt_id: u64,
    /// Epoch of the most recent loss event.
    current_epoch: u64,
}

impl RebuildAdmission {
    /// Create a new admission controller.
    #[must_use]
    pub fn new() -> Self {
        Self {
            member_status: BTreeMap::new(),
            next_receipt_id: 1,
            current_epoch: 0,
        }
    }

    /// Create with a known epoch.
    #[must_use]
    pub fn with_epoch(epoch: u64) -> Self {
        Self {
            member_status: BTreeMap::new(),
            next_receipt_id: 1,
            current_epoch: epoch,
        }
    }

    /// Advance to a new epoch, clearing completed status for members that
    /// may need re-rebuild after an epoch change.
    pub fn advance_epoch(&mut self, new_epoch: u64) {
        self.current_epoch = new_epoch;
        for status in self.member_status.values_mut() {
            if status.is_terminal() {
                *status = RebuildAdmissionStatus::Idle;
            }
        }
    }

    /// Attempt to admit rebuild for the lost members described in `loss`.
    ///
    /// For each lost member:
    /// - If already rebuilding, refuse with AlreadyActive.
    /// - If already completed in this epoch, refuse with AlreadyCompleted.
    /// - If no healthy sources exist, refuse with NoHealthySources.
    /// - If no affected subjects, refuse with NoAffectedSubjects.
    /// - Otherwise, admit the rebuild and generate reports + intents.
    #[must_use]
    pub fn admit(
        &mut self,
        loss: &LossRecord,
        scheduler: &mut BackfillScheduler,
    ) -> AdmissionOutcome {
        let mut admitted = Vec::new();
        let mut refused = Vec::new();
        let mut reports = Vec::new();

        for &lost_member in &loss.lost_members {
            let current = self
                .member_status
                .get(&lost_member)
                .copied()
                .unwrap_or(RebuildAdmissionStatus::Idle);

            match current {
                RebuildAdmissionStatus::Rebuilding => {
                    refused.push((lost_member, AdmissionRefusalReason::AlreadyActive));
                    continue;
                }
                RebuildAdmissionStatus::Completed => {
                    refused.push((lost_member, AdmissionRefusalReason::AlreadyCompleted));
                    continue;
                }
                RebuildAdmissionStatus::Idle | RebuildAdmissionStatus::Refused => {}
            }

            if loss.healthy_sources.is_empty() {
                refused.push((lost_member, AdmissionRefusalReason::NoHealthySources));
                self.member_status
                    .insert(lost_member, RebuildAdmissionStatus::Refused);
                continue;
            }

            let member_subjects: Vec<&AffectedSubject> = loss
                .affected_subjects
                .iter()
                .filter(|s| s.lost_on.contains(&lost_member))
                .collect();

            if member_subjects.is_empty() {
                refused.push((lost_member, AdmissionRefusalReason::NoAffectedSubjects));
                continue;
            }

            for subject in &member_subjects {
                let report = DegradedReplicaReport {
                    subject_ref: subject.subject_ref,
                    healthy_sources: loss.healthy_sources.clone(),
                    missing_targets: vec![lost_member],
                    movement_class: subject.movement_class,
                    payload_digest: subject.payload_digest,
                    payload_len: subject.payload_len,
                    now_ns: loss.detected_at_ns,
                    deadline_offset_ns: 3_600_000_000_000,
                };
                reports.push(report);
            }

            self.member_status
                .insert(lost_member, RebuildAdmissionStatus::Rebuilding);
            admitted.push(lost_member);
        }

        let report_count = reports.len();
        scheduler.ingest(&reports);

        AdmissionOutcome {
            admitted,
            refused,
            report_count,
            intent_count: report_count,
        }
    }

    /// Generate ReplicaMovementIntentRecords from the admitted loss record.
    #[must_use]
    pub fn generate_intents(&mut self, loss: &LossRecord) -> Vec<ReplicaMovementIntentRecord> {
        let mut intents = Vec::new();

        for subject in &loss.affected_subjects {
            if loss.healthy_sources.is_empty() {
                continue;
            }

            let source = loss.healthy_sources[0];

            for &target in &subject.lost_on {
                if self.member_status.get(&target) != Some(&RebuildAdmissionStatus::Rebuilding) {
                    continue;
                }

                let intent = ReplicaMovementIntentRecord {
                    intent_id: ReplicatedReceiptId(self.next_receipt_id),
                    movement_class: subject.movement_class,
                    subject_ref: subject.subject_ref,
                    source_member_ref: source,
                    target_member_ref: target,
                    payload_digest: subject.payload_digest,
                    payload_len: subject.payload_len,
                    verification_required: false,
                };

                self.next_receipt_id += 1;
                intents.push(intent);
            }
        }

        intents
    }

    /// Build a RebuildRuntime from the admitted loss record.
    #[must_use]
    pub fn build_runtime(
        &mut self,
        job_id: u64,
        loss: &LossRecord,
    ) -> Option<crate::RebuildRuntime> {
        let intents = self.generate_intents(loss);
        if intents.is_empty() {
            return None;
        }

        let mut builder = RebuildRuntimeBuilder::new(
            tidefs_types_incremental_job_core::JobId(job_id),
            tidefs_types_incremental_job_core::JobKind::Other(200),
        );
        builder.add_intents(intents);
        Some(builder.build())
    }

    /// Mark rebuild as completed for a member.
    pub fn mark_completed(&mut self, member: MemberId) -> bool {
        match self.member_status.get(&member) {
            Some(RebuildAdmissionStatus::Rebuilding) => {
                self.member_status
                    .insert(member, RebuildAdmissionStatus::Completed);
                true
            }
            _ => false,
        }
    }

    /// Mark rebuild as refused/failed for a member.
    pub fn mark_refused(&mut self, member: MemberId) {
        self.member_status
            .insert(member, RebuildAdmissionStatus::Refused);
    }

    /// Query the admission status for a member.
    #[must_use]
    pub fn status(&self, member: MemberId) -> RebuildAdmissionStatus {
        self.member_status
            .get(&member)
            .copied()
            .unwrap_or(RebuildAdmissionStatus::Idle)
    }

    /// Check if any members are currently rebuilding.
    #[must_use]
    pub fn has_active_rebuilds(&self) -> bool {
        self.member_status.values().any(|s| s.is_active())
    }

    /// List members that are currently rebuilding.
    #[must_use]
    pub fn active_rebuilds(&self) -> Vec<MemberId> {
        self.member_status
            .iter()
            .filter(|(_, s)| s.is_active())
            .map(|(m, _)| *m)
            .collect()
    }

    /// List members that have completed rebuild.
    #[must_use]
    pub fn completed_rebuilds(&self) -> Vec<MemberId> {
        self.member_status
            .iter()
            .filter(|(_, s)| **s == RebuildAdmissionStatus::Completed)
            .map(|(m, _)| *m)
            .collect()
    }

    /// Reset all state.
    pub fn reset(&mut self) {
        self.member_status.clear();
        self.next_receipt_id = 1;
    }

    /// Current epoch.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }
}

// ─ Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::BackfillScheduler;

    fn make_subject(id: u64, class: ReplicaMovementClass, lost_on: Vec<u64>) -> AffectedSubject {
        AffectedSubject {
            subject_ref: ReplicatedSubjectId::new(id),
            payload_digest: ObjectDigest::new(id * 100),
            payload_len: 4096,
            movement_class: class,
            lost_on: lost_on.into_iter().map(MemberId::new).collect(),
        }
    }

    fn make_loss(lost: &[u64], sources: &[u64], subjects: Vec<AffectedSubject>) -> LossRecord {
        LossRecord {
            lost_members: lost.iter().map(|&m| MemberId::new(m)).collect(),
            healthy_sources: sources.iter().map(|&m| MemberId::new(m)).collect(),
            affected_subjects: subjects,
            detected_epoch: 1,
            detected_at_ns: 1000,
        }
    }

    #[test]
    fn admits_initial_rebuild() {
        let mut admission = RebuildAdmission::with_epoch(1);
        let mut scheduler = BackfillScheduler::new();

        let loss = make_loss(
            &[10],
            &[20, 30],
            vec![make_subject(
                1,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                vec![10],
            )],
        );

        let outcome = admission.admit(&loss, &mut scheduler);
        assert_eq!(outcome.admitted, vec![MemberId::new(10)]);
        assert!(outcome.refused.is_empty());
        assert_eq!(outcome.report_count, 1);
        assert!(admission.has_active_rebuilds());
        assert_eq!(
            admission.status(MemberId::new(10)),
            RebuildAdmissionStatus::Rebuilding
        );
    }

    #[test]
    fn refuses_duplicate_admission() {
        let mut admission = RebuildAdmission::with_epoch(1);
        let mut scheduler = BackfillScheduler::new();

        let loss = make_loss(
            &[10],
            &[20],
            vec![make_subject(
                1,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                vec![10],
            )],
        );

        let outcome1 = admission.admit(&loss, &mut scheduler);
        assert_eq!(outcome1.admitted.len(), 1);

        let outcome2 = admission.admit(&loss, &mut scheduler);
        assert!(outcome2.admitted.is_empty());
        assert_eq!(outcome2.refused.len(), 1);
        assert_eq!(outcome2.refused[0].1, AdmissionRefusalReason::AlreadyActive);
    }

    #[test]
    fn refuses_when_no_healthy_sources() {
        let mut admission = RebuildAdmission::with_epoch(1);
        let mut scheduler = BackfillScheduler::new();

        let loss = make_loss(
            &[10],
            &[],
            vec![make_subject(
                1,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                vec![10],
            )],
        );

        let outcome = admission.admit(&loss, &mut scheduler);
        assert!(outcome.admitted.is_empty());
        assert_eq!(outcome.refused.len(), 1);
        assert_eq!(
            outcome.refused[0].1,
            AdmissionRefusalReason::NoHealthySources
        );
        assert_eq!(
            admission.status(MemberId::new(10)),
            RebuildAdmissionStatus::Refused
        );
    }

    #[test]
    fn refuses_when_no_affected_subjects() {
        let mut admission = RebuildAdmission::with_epoch(1);
        let mut scheduler = BackfillScheduler::new();

        let loss = make_loss(&[10], &[20], vec![]);

        let outcome = admission.admit(&loss, &mut scheduler);
        assert!(outcome.admitted.is_empty());
        assert_eq!(outcome.refused.len(), 1);
        assert_eq!(
            outcome.refused[0].1,
            AdmissionRefusalReason::NoAffectedSubjects
        );
    }

    #[test]
    fn marks_completed() {
        let mut admission = RebuildAdmission::with_epoch(1);
        let mut scheduler = BackfillScheduler::new();

        let loss = make_loss(
            &[10],
            &[20],
            vec![make_subject(
                1,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                vec![10],
            )],
        );

        let _ = admission.admit(&loss, &mut scheduler);
        assert!(admission.mark_completed(MemberId::new(10)));
        assert_eq!(
            admission.status(MemberId::new(10)),
            RebuildAdmissionStatus::Completed
        );
        assert!(!admission.has_active_rebuilds());
    }

    #[test]
    fn generates_intents() {
        let mut admission = RebuildAdmission::with_epoch(1);
        let mut scheduler = BackfillScheduler::new();

        let loss = make_loss(
            &[10],
            &[20],
            vec![make_subject(
                1,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                vec![10],
            )],
        );

        let _ = admission.admit(&loss, &mut scheduler);
        let intents = admission.generate_intents(&loss);
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].subject_ref, ReplicatedSubjectId::new(1));
        assert_eq!(intents[0].source_member_ref, MemberId::new(20));
        assert_eq!(intents[0].target_member_ref, MemberId::new(10));
        assert_eq!(
            intents[0].movement_class,
            ReplicaMovementClass::RebuildLostOrSuspectCopy
        );
    }

    #[test]
    fn build_runtime_creates_valid_job() {
        let mut admission = RebuildAdmission::with_epoch(1);
        let mut scheduler = BackfillScheduler::new();

        let loss = make_loss(
            &[10],
            &[20],
            vec![
                make_subject(1, ReplicaMovementClass::RebuildLostOrSuspectCopy, vec![10]),
                make_subject(2, ReplicaMovementClass::RebuildLostOrSuspectCopy, vec![10]),
            ],
        );

        let _ = admission.admit(&loss, &mut scheduler);
        let rt = admission.build_runtime(42, &loss).unwrap();
        assert!(!rt.is_finished());
        assert_eq!(rt.stats().objects_pending, 2);
    }

    #[test]
    fn build_runtime_returns_none_when_no_intents() {
        let mut admission = RebuildAdmission::with_epoch(1);
        let mut scheduler = BackfillScheduler::new();

        let loss = make_loss(&[10], &[20], vec![]);
        let _ = admission.admit(&loss, &mut scheduler);
        assert!(admission.build_runtime(42, &loss).is_none());
    }

    #[test]
    fn epoch_advance_resets_completed() {
        let mut admission = RebuildAdmission::with_epoch(1);
        let mut scheduler = BackfillScheduler::new();

        let loss = make_loss(
            &[10],
            &[20],
            vec![make_subject(
                1,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                vec![10],
            )],
        );

        let _ = admission.admit(&loss, &mut scheduler);
        admission.mark_completed(MemberId::new(10));
        assert_eq!(
            admission.status(MemberId::new(10)),
            RebuildAdmissionStatus::Completed
        );

        admission.advance_epoch(2);
        assert_eq!(
            admission.status(MemberId::new(10)),
            RebuildAdmissionStatus::Idle
        );
        assert_eq!(admission.current_epoch(), 2);
    }

    #[test]
    fn active_and_completed_lists() {
        let mut admission = RebuildAdmission::with_epoch(1);
        let mut scheduler = BackfillScheduler::new();

        let loss1 = make_loss(
            &[10],
            &[20],
            vec![make_subject(
                1,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                vec![10],
            )],
        );
        let loss2 = make_loss(
            &[11],
            &[20],
            vec![make_subject(
                2,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                vec![11],
            )],
        );

        let _ = admission.admit(&loss1, &mut scheduler);
        let _ = admission.admit(&loss2, &mut scheduler);
        assert_eq!(admission.active_rebuilds().len(), 2);

        admission.mark_completed(MemberId::new(10));
        assert_eq!(admission.active_rebuilds(), vec![MemberId::new(11)]);
        assert_eq!(admission.completed_rebuilds(), vec![MemberId::new(10)]);
    }

    #[test]
    fn reset_clears_all() {
        let mut admission = RebuildAdmission::with_epoch(1);
        let mut scheduler = BackfillScheduler::new();

        let loss = make_loss(
            &[10],
            &[20],
            vec![make_subject(
                1,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                vec![10],
            )],
        );

        let _ = admission.admit(&loss, &mut scheduler);
        admission.reset();
        assert!(!admission.has_active_rebuilds());
        assert_eq!(
            admission.status(MemberId::new(10)),
            RebuildAdmissionStatus::Idle
        );
    }

    #[test]
    fn multiple_lost_members() {
        let mut admission = RebuildAdmission::with_epoch(1);
        let mut scheduler = BackfillScheduler::new();

        let loss = make_loss(
            &[10, 11],
            &[20, 30],
            vec![
                make_subject(
                    1,
                    ReplicaMovementClass::RebuildLostOrSuspectCopy,
                    vec![10, 11],
                ),
                make_subject(2, ReplicaMovementClass::RebuildLostOrSuspectCopy, vec![10]),
            ],
        );

        let outcome = admission.admit(&loss, &mut scheduler);
        assert_eq!(outcome.admitted.len(), 2);
        assert!(outcome.refused.is_empty());
        assert_eq!(outcome.report_count, 3);
    }
}
