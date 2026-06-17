//! RebuildCompletion: tracks rebuild flow completion and emits
//! signals when missing data has been fully recovered after
//! node/device loss.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::MemberId;
use tidefs_replication_model::{
    ObjectDigest, PlacementReceiptRef, ReplicaMovementIntentRecord, ReplicatedSubjectId,
};

use crate::admission::RebuildAdmission;
use crate::task::BackfillTask;

type IntentCompletionKey = (MemberId, ReplicatedSubjectId);
type ReceiptIntentCompletionKey = (MemberId, ReplicatedSubjectId, PlacementReceiptRef);
type ReceiptCompletionKey = (MemberId, ReplicatedSubjectId, PlacementReceiptRef);
type VerifiedReceiptCompletionKey = (
    MemberId,
    ReplicatedSubjectId,
    PlacementReceiptRef,
    PlacementReceiptRef,
);

fn receipt_digest_to_object_digest(payload_digest: [u8; 32]) -> ObjectDigest {
    ObjectDigest::new(u64::from_le_bytes(
        payload_digest[..8]
            .try_into()
            .expect("digest prefix has 8 bytes"),
    ))
}

/// Per-member rebuild completion tracking.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompletionStatus {
    pub member: MemberId,
    pub total_subjects: u64,
    pub subjects_completed: u64,
    pub subjects_failed: u64,
    pub is_complete: bool,
}

impl CompletionStatus {
    #[must_use]
    pub fn new(member: MemberId, total_subjects: u64) -> Self {
        Self {
            member,
            total_subjects,
            subjects_completed: 0,
            subjects_failed: 0,
            is_complete: false,
        }
    }

    pub fn record_completed(&mut self) {
        self.subjects_completed += 1;
        self.check_complete();
    }

    pub fn record_failed(&mut self) {
        self.subjects_failed += 1;
        self.check_complete();
    }

    fn check_complete(&mut self) {
        if self.subjects_completed + self.subjects_failed >= self.total_subjects {
            self.is_complete = true;
        }
    }

    #[must_use]
    pub fn fraction(&self) -> f64 {
        if self.total_subjects == 0 {
            return 1.0;
        }
        self.subjects_completed as f64 / self.total_subjects as f64
    }

    #[must_use]
    pub fn all_succeeded(&self) -> bool {
        self.is_complete && self.subjects_failed == 0
    }
}

/// Signal emitted when all rebuild intents for a member finish.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebuildCompleted {
    pub member: MemberId,
    pub total: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub fully_successful: bool,
}

/// Receipt evidence for a verified rebuild task that completed successfully.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifiedReceiptCompletionRecord {
    pub target_member: MemberId,
    pub subject_ref: ReplicatedSubjectId,
    pub source_placement_receipt_ref: PlacementReceiptRef,
    pub repaired_placement_receipt_ref: PlacementReceiptRef,
}

/// Error returned when a repaired target receipt cannot prove task completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptCompletionError {
    /// The caller supplied a synthetic placeholder instead of a durable
    /// repaired target placement receipt.
    SyntheticReceiptRef { object_id: u64 },
    /// The repaired receipt carries a redundancy policy that cannot describe
    /// legal placement.
    MalformedReceiptPolicy { object_id: u64 },
    /// The repaired receipt records fewer physical targets than its redundancy
    /// policy requires.
    InsufficientReceiptTargets {
        object_id: u64,
        required: u16,
        actual: u16,
    },
    /// The repaired receipt is for a different logical subject.
    ObjectIdMismatch {
        task_object_id: u64,
        repaired_object_id: u64,
    },
    /// The repaired receipt is for a different object key.
    ObjectKeyMismatch { object_id: u64 },
    /// The repaired receipt is for a different payload length.
    PayloadLengthMismatch {
        object_id: u64,
        task_len: u64,
        repaired_len: u64,
    },
    /// The repaired receipt is for a different payload digest.
    PayloadDigestMismatch { object_id: u64 },
}

/// Tracks rebuild completion across multiple members.
#[derive(Clone, Debug, Default)]
pub struct RebuildCompletion {
    members: BTreeMap<MemberId, CompletionStatus>,
    completed_intent_subjects: BTreeSet<IntentCompletionKey>,
    completed_receipt_intents: BTreeSet<ReceiptIntentCompletionKey>,
    completed_receipt_tasks: BTreeSet<ReceiptCompletionKey>,
    completed_verified_receipt_tasks: BTreeSet<VerifiedReceiptCompletionKey>,
    pending_events: Vec<RebuildCompleted>,
}

impl RebuildCompletion {
    #[must_use]
    pub fn new() -> Self {
        Self {
            members: BTreeMap::new(),
            completed_intent_subjects: BTreeSet::new(),
            completed_receipt_intents: BTreeSet::new(),
            completed_receipt_tasks: BTreeSet::new(),
            completed_verified_receipt_tasks: BTreeSet::new(),
            pending_events: Vec::new(),
        }
    }

    pub fn register(&mut self, member: MemberId, total_subjects: u64) {
        self.members
            .entry(member)
            .or_insert_with(|| CompletionStatus::new(member, total_subjects));
    }

    pub fn record_intent_completion(
        &mut self,
        member: MemberId,
        subject: ReplicatedSubjectId,
        success: bool,
        admission: &mut RebuildAdmission,
    ) -> Option<RebuildCompleted> {
        let dedup_key = (member, subject);
        if self.completed_intent_subjects.contains(&dedup_key) {
            return None;
        }
        self.completed_intent_subjects.insert(dedup_key);

        self.record_completion_unit(member, success, admission)
    }

    pub fn record_receipt_intent_completion(
        &mut self,
        intent: &ReplicaMovementIntentRecord,
        success: bool,
        admission: &mut RebuildAdmission,
    ) -> Option<RebuildCompleted> {
        let dedup_key = (
            intent.target_member_ref,
            intent.subject_ref,
            intent.placement_receipt_ref,
        );
        if self.completed_receipt_intents.contains(&dedup_key) {
            return None;
        }
        self.completed_receipt_intents.insert(dedup_key);

        self.record_completion_unit(intent.target_member_ref, success, admission)
    }

    pub fn record_task_completion(
        &mut self,
        task: &BackfillTask,
        success: bool,
        admission: &mut RebuildAdmission,
    ) -> Option<RebuildCompleted> {
        let dedup_key = (
            task.target_member,
            task.subject_ref,
            task.placement_receipt_ref,
        );
        if self.completed_receipt_tasks.contains(&dedup_key) {
            return None;
        }
        self.completed_receipt_tasks.insert(dedup_key);

        self.record_completion_unit(task.target_member, success, admission)
    }

    /// Complete a receipt-bound task only after the repaired target receipt
    /// proves the same logical object, object key, payload size, digest, and
    /// redundancy width as the scheduled movement.
    pub fn record_receipt_verified_task_completion(
        &mut self,
        task: &BackfillTask,
        repaired_receipt_ref: PlacementReceiptRef,
        admission: &mut RebuildAdmission,
    ) -> Result<Option<RebuildCompleted>, ReceiptCompletionError> {
        Self::validate_repaired_receipt_ref(task, repaired_receipt_ref)?;

        let dedup_key = (
            task.target_member,
            task.subject_ref,
            task.placement_receipt_ref,
            repaired_receipt_ref,
        );
        if !self.completed_verified_receipt_tasks.insert(dedup_key) {
            return Ok(None);
        }

        Ok(self.record_completion_unit(task.target_member, true, admission))
    }

    /// Validate a repaired target receipt against the scheduled receipt-bound
    /// task without mutating completion state.
    pub fn validate_repaired_receipt_for_task(
        task: &BackfillTask,
        repaired_receipt_ref: PlacementReceiptRef,
    ) -> Result<(), ReceiptCompletionError> {
        Self::validate_repaired_receipt_ref(task, repaired_receipt_ref)
    }

    fn validate_repaired_receipt_ref(
        task: &BackfillTask,
        repaired_receipt_ref: PlacementReceiptRef,
    ) -> Result<(), ReceiptCompletionError> {
        if repaired_receipt_ref.is_synthetic() {
            return Err(ReceiptCompletionError::SyntheticReceiptRef {
                object_id: repaired_receipt_ref.object_id,
            });
        }
        if !repaired_receipt_ref.redundancy_policy.is_well_formed() {
            return Err(ReceiptCompletionError::MalformedReceiptPolicy {
                object_id: repaired_receipt_ref.object_id,
            });
        }
        let required = repaired_receipt_ref.redundancy_policy.target_width();
        if repaired_receipt_ref.target_count < required {
            return Err(ReceiptCompletionError::InsufficientReceiptTargets {
                object_id: repaired_receipt_ref.object_id,
                required,
                actual: repaired_receipt_ref.target_count,
            });
        }

        let task_object_id = task.subject_ref.0;
        if repaired_receipt_ref.object_id != task_object_id {
            return Err(ReceiptCompletionError::ObjectIdMismatch {
                task_object_id,
                repaired_object_id: repaired_receipt_ref.object_id,
            });
        }
        if repaired_receipt_ref.object_key != task.placement_receipt_ref.object_key {
            return Err(ReceiptCompletionError::ObjectKeyMismatch {
                object_id: repaired_receipt_ref.object_id,
            });
        }
        if repaired_receipt_ref.payload_len != task.payload_len {
            return Err(ReceiptCompletionError::PayloadLengthMismatch {
                object_id: repaired_receipt_ref.object_id,
                task_len: task.payload_len,
                repaired_len: repaired_receipt_ref.payload_len,
            });
        }
        if repaired_receipt_ref.payload_digest != task.placement_receipt_ref.payload_digest
            || receipt_digest_to_object_digest(repaired_receipt_ref.payload_digest)
                != task.payload_digest
        {
            return Err(ReceiptCompletionError::PayloadDigestMismatch {
                object_id: repaired_receipt_ref.object_id,
            });
        }

        Ok(())
    }

    fn record_completion_unit(
        &mut self,
        member: MemberId,
        success: bool,
        admission: &mut RebuildAdmission,
    ) -> Option<RebuildCompleted> {
        let status = self
            .members
            .entry(member)
            .or_insert_with(|| CompletionStatus::new(member, 0));
        let was_complete = status.is_complete;
        if success {
            status.record_completed();
        } else {
            status.record_failed();
        }

        if !was_complete && status.is_complete {
            let event = RebuildCompleted {
                member,
                total: status.total_subjects,
                succeeded: status.subjects_completed,
                failed: status.subjects_failed,
                fully_successful: status.all_succeeded(),
            };
            if event.fully_successful {
                admission.mark_completed(member);
            } else {
                admission.mark_refused(member);
            }
            self.pending_events.push(event.clone());
            return Some(event);
        }
        None
    }

    pub fn record_batch_completion(
        &mut self,
        completed_intents: &[ReplicaMovementIntentRecord],
        admission: &mut RebuildAdmission,
    ) -> Vec<RebuildCompleted> {
        let mut events = Vec::new();
        for intent in completed_intents {
            if let Some(event) = self.record_receipt_intent_completion(intent, true, admission) {
                events.push(event);
            }
        }
        events
    }

    pub fn record_task_batch_completion(
        &mut self,
        completed_tasks: &[BackfillTask],
        admission: &mut RebuildAdmission,
    ) -> Vec<RebuildCompleted> {
        let mut events = Vec::new();
        for task in completed_tasks {
            if let Some(event) = self.record_task_completion(task, true, admission) {
                events.push(event);
            }
        }
        events
    }

    #[must_use]
    pub fn drain_events(&mut self) -> Vec<RebuildCompleted> {
        std::mem::take(&mut self.pending_events)
    }

    #[must_use]
    pub fn status(&self, member: MemberId) -> Option<&CompletionStatus> {
        self.members.get(&member)
    }

    #[must_use]
    pub fn is_member_complete(&self, member: MemberId) -> bool {
        self.members
            .get(&member)
            .map(|s| s.is_complete)
            .unwrap_or(false)
    }

    #[must_use]
    pub fn all_complete(&self) -> bool {
        !self.members.is_empty() && self.members.values().all(|s| s.is_complete)
    }

    #[must_use]
    pub fn in_progress_count(&self) -> usize {
        self.members.values().filter(|s| !s.is_complete).count()
    }

    #[must_use]
    pub fn total_completed_subjects(&self) -> u64 {
        (self.completed_intent_subjects.len()
            + self.completed_receipt_intents.len()
            + self.completed_receipt_tasks.len()
            + self.completed_verified_receipt_tasks.len()) as u64
    }

    #[must_use]
    pub fn verified_receipt_completions(&self) -> Vec<VerifiedReceiptCompletionRecord> {
        self.completed_verified_receipt_tasks
            .iter()
            .map(
                |(
                    target_member,
                    subject_ref,
                    source_placement_receipt_ref,
                    repaired_placement_receipt_ref,
                )| VerifiedReceiptCompletionRecord {
                    target_member: *target_member,
                    subject_ref: *subject_ref,
                    source_placement_receipt_ref: *source_placement_receipt_ref,
                    repaired_placement_receipt_ref: *repaired_placement_receipt_ref,
                },
            )
            .collect()
    }

    pub fn reset(&mut self) {
        self.members.clear();
        self.completed_intent_subjects.clear();
        self.completed_receipt_intents.clear();
        self.completed_receipt_tasks.clear();
        self.completed_verified_receipt_tasks.clear();
        self.pending_events.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::{BackfillTask, BackfillTaskInit};
    use tidefs_membership_epoch::MemberId;
    use tidefs_replication_model::{
        PlacementReceiptRef, ReceiptRedundancyPolicy, ReplicaMovementClass, ReplicatedReceiptId,
        ReplicatedSubjectId,
    };

    fn make_intent(id: u64, member: u64, subject: u64) -> ReplicaMovementIntentRecord {
        let placement_receipt_ref = receipt_ref(subject, id);
        ReplicaMovementIntentRecord {
            intent_id: ReplicatedReceiptId(id),
            movement_class: ReplicaMovementClass::RebuildLostOrSuspectCopy,
            subject_ref: ReplicatedSubjectId::new(subject),
            placement_receipt_ref,
            source_member_ref: MemberId::new(1),
            target_member_ref: MemberId::new(member),
            payload_digest: receipt_digest_to_object_digest(placement_receipt_ref.payload_digest),
            payload_len: placement_receipt_ref.payload_len,
            verification_required: true,
        }
    }

    fn receipt_ref(subject: u64, generation: u64) -> PlacementReceiptRef {
        let mut object_key = [0xA5; 32];
        object_key[..8].copy_from_slice(&subject.to_le_bytes());
        let mut digest = [0x5A; 32];
        digest[..8].copy_from_slice(&subject.to_le_bytes());
        digest[8..16].copy_from_slice(&generation.to_le_bytes());
        PlacementReceiptRef::replicated(
            subject,
            object_key,
            tidefs_membership_epoch::EpochId::new(7),
            generation,
            2,
            4096,
            digest,
        )
    }

    fn make_task(subject: u64, member: u64, generation: u64) -> BackfillTask {
        let placement_receipt_ref = receipt_ref(subject, generation);
        BackfillTask::new(BackfillTaskInit {
            subject_ref: ReplicatedSubjectId::new(subject),
            placement_receipt_ref,
            source_member: MemberId::new(1),
            target_member: MemberId::new(member),
            movement_class: ReplicaMovementClass::RebuildLostOrSuspectCopy,
            payload_digest: receipt_digest_to_object_digest(placement_receipt_ref.payload_digest),
            payload_len: placement_receipt_ref.payload_len,
            created_at_ns: 0,
            deadline_ns: 10_000,
        })
    }

    fn repaired_receipt_for_task(task: &BackfillTask, generation: u64) -> PlacementReceiptRef {
        let mut repaired = task.placement_receipt_ref;
        repaired.receipt_generation = generation;
        repaired
    }

    fn rebuilding_member(
        completion: &mut RebuildCompletion,
        admission: &mut RebuildAdmission,
        member: MemberId,
        total_subjects: u64,
    ) {
        completion.register(member, total_subjects);
        admission
            .member_status
            .insert(member, crate::admission::RebuildAdmissionStatus::Rebuilding);
    }

    fn assert_refusal_preserves_rebuild_state(
        completion: &mut RebuildCompletion,
        admission: &RebuildAdmission,
        member: MemberId,
    ) {
        assert_eq!(
            admission.status(member),
            crate::admission::RebuildAdmissionStatus::Rebuilding
        );
        assert_eq!(completion.status(member).unwrap().subjects_completed, 0);
        assert_eq!(completion.total_completed_subjects(), 0);
        assert_eq!(completion.drain_events().len(), 0);
    }

    #[test]
    fn tracks_single_member_completion() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        completion.register(member, 2);
        admission
            .member_status
            .insert(member, crate::admission::RebuildAdmissionStatus::Rebuilding);

        let e1 = completion.record_intent_completion(
            member,
            ReplicatedSubjectId::new(1),
            true,
            &mut admission,
        );
        assert!(e1.is_none());
        let e2 = completion.record_intent_completion(
            member,
            ReplicatedSubjectId::new(2),
            true,
            &mut admission,
        );
        assert!(e2.is_some());
        let event = e2.unwrap();
        assert!(event.fully_successful);
        assert!(completion.is_member_complete(member));
        assert_eq!(
            admission.status(member),
            crate::admission::RebuildAdmissionStatus::Completed
        );
    }

    #[test]
    fn deduplicates_repeated_intents() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        let subject = ReplicatedSubjectId::new(1);
        completion.register(member, 1);
        admission
            .member_status
            .insert(member, crate::admission::RebuildAdmissionStatus::Rebuilding);

        assert!(completion
            .record_intent_completion(member, subject, true, &mut admission)
            .is_some());
        assert!(completion
            .record_intent_completion(member, subject, true, &mut admission)
            .is_none());
    }

    #[test]
    fn tracks_failed_completion() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        completion.register(member, 1);
        admission
            .member_status
            .insert(member, crate::admission::RebuildAdmissionStatus::Rebuilding);

        let event = completion
            .record_intent_completion(member, ReplicatedSubjectId::new(1), false, &mut admission)
            .unwrap();
        assert!(!event.fully_successful);
        assert_eq!(event.failed, 1);
        assert_eq!(
            admission.status(member),
            crate::admission::RebuildAdmissionStatus::Refused
        );
    }

    #[test]
    fn batch_completion() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        completion.register(member, 3);
        admission
            .member_status
            .insert(member, crate::admission::RebuildAdmissionStatus::Rebuilding);

        let intents = vec![
            make_intent(1, 10, 1),
            make_intent(2, 10, 2),
            make_intent(3, 10, 3),
        ];
        let events = completion.record_batch_completion(&intents, &mut admission);
        assert_eq!(events.len(), 1);
        assert!(events[0].fully_successful);
        assert!(completion.is_member_complete(member));
    }

    #[test]
    fn batch_completion_keeps_intent_receipt_generations_distinct() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        completion.register(member, 2);
        admission
            .member_status
            .insert(member, crate::admission::RebuildAdmissionStatus::Rebuilding);

        let intents = vec![make_intent(1, 10, 7), make_intent(2, 10, 7)];
        assert_ne!(
            intents[0].placement_receipt_ref,
            intents[1].placement_receipt_ref
        );

        let events = completion.record_batch_completion(&intents, &mut admission);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].succeeded, 2);
        assert!(events[0].fully_successful);
        assert_eq!(completion.total_completed_subjects(), 2);
    }

    #[test]
    fn task_completion_keeps_receipt_generations_distinct() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        completion.register(member, 2);
        admission
            .member_status
            .insert(member, crate::admission::RebuildAdmissionStatus::Rebuilding);

        let first = make_task(42, 10, 1);
        let second = make_task(42, 10, 2);

        assert!(completion
            .record_task_completion(&first, true, &mut admission)
            .is_none());
        let event = completion
            .record_task_completion(&second, true, &mut admission)
            .expect("second receipt generation completes the member");

        assert_eq!(event.succeeded, 2);
        assert!(event.fully_successful);
        assert_eq!(completion.total_completed_subjects(), 2);
        assert_eq!(completion.status(member).unwrap().subjects_completed, 2);
        assert_eq!(
            admission.status(member),
            crate::admission::RebuildAdmissionStatus::Completed
        );
    }

    #[test]
    fn task_completion_deduplicates_exact_receipt_task() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        completion.register(member, 1);
        admission
            .member_status
            .insert(member, crate::admission::RebuildAdmissionStatus::Rebuilding);

        let task = make_task(42, 10, 1);

        assert!(completion
            .record_task_completion(&task, true, &mut admission)
            .is_some());
        assert!(completion
            .record_task_completion(&task, true, &mut admission)
            .is_none());
        assert_eq!(completion.total_completed_subjects(), 1);
        assert_eq!(completion.status(member).unwrap().subjects_completed, 1);
        assert_eq!(completion.drain_events().len(), 1);
        assert_eq!(completion.drain_events().len(), 0);
    }

    #[test]
    fn receipt_verified_task_completion_requires_repaired_receipt() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        rebuilding_member(&mut completion, &mut admission, member, 1);
        let task = make_task(42, 10, 1);
        let repaired = repaired_receipt_for_task(&task, 2);

        let event = completion
            .record_receipt_verified_task_completion(&task, repaired, &mut admission)
            .expect("receipt should verify")
            .expect("first verified receipt completes the member");

        assert_eq!(event.succeeded, 1);
        assert!(event.fully_successful);
        assert_eq!(completion.total_completed_subjects(), 1);
        assert_eq!(completion.status(member).unwrap().subjects_completed, 1);
        assert_eq!(
            admission.status(member),
            crate::admission::RebuildAdmissionStatus::Completed
        );
        assert_eq!(
            completion.verified_receipt_completions(),
            vec![VerifiedReceiptCompletionRecord {
                target_member: member,
                subject_ref: task.subject_ref,
                source_placement_receipt_ref: task.placement_receipt_ref,
                repaired_placement_receipt_ref: repaired,
            }]
        );
    }

    #[test]
    fn receipt_verified_task_completion_deduplicates_exact_repaired_receipt() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        rebuilding_member(&mut completion, &mut admission, member, 1);
        let task = make_task(42, 10, 1);
        let repaired = repaired_receipt_for_task(&task, 2);

        assert!(completion
            .record_receipt_verified_task_completion(&task, repaired, &mut admission)
            .expect("receipt should verify")
            .is_some());
        assert!(completion
            .record_receipt_verified_task_completion(&task, repaired, &mut admission)
            .expect("duplicate receipt should still verify")
            .is_none());

        assert_eq!(completion.total_completed_subjects(), 1);
        assert_eq!(completion.status(member).unwrap().subjects_completed, 1);
        assert_eq!(completion.verified_receipt_completions().len(), 1);
        assert_eq!(completion.drain_events().len(), 1);
        assert_eq!(completion.drain_events().len(), 0);
    }

    #[test]
    fn receipt_verified_completions_are_ordered_and_reset() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        rebuilding_member(&mut completion, &mut admission, member, 2);
        let later = make_task(43, 10, 1);
        let earlier = make_task(42, 10, 1);
        let later_repaired = repaired_receipt_for_task(&later, 3);
        let earlier_repaired = repaired_receipt_for_task(&earlier, 2);

        assert!(completion
            .record_receipt_verified_task_completion(&later, later_repaired, &mut admission)
            .expect("later receipt should verify")
            .is_none());
        assert!(completion
            .record_receipt_verified_task_completion(&earlier, earlier_repaired, &mut admission)
            .expect("earlier receipt should verify")
            .is_some());

        assert_eq!(
            completion.verified_receipt_completions(),
            vec![
                VerifiedReceiptCompletionRecord {
                    target_member: member,
                    subject_ref: earlier.subject_ref,
                    source_placement_receipt_ref: earlier.placement_receipt_ref,
                    repaired_placement_receipt_ref: earlier_repaired,
                },
                VerifiedReceiptCompletionRecord {
                    target_member: member,
                    subject_ref: later.subject_ref,
                    source_placement_receipt_ref: later.placement_receipt_ref,
                    repaired_placement_receipt_ref: later_repaired,
                },
            ]
        );

        completion.reset();
        assert!(completion.verified_receipt_completions().is_empty());
    }

    #[test]
    fn receipt_verified_task_completion_rejects_synthetic_repaired_receipt() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        rebuilding_member(&mut completion, &mut admission, member, 1);
        let task = make_task(42, 10, 1);
        let repaired = PlacementReceiptRef::synthetic_for_subject(task.subject_ref);

        let err = completion
            .record_receipt_verified_task_completion(&task, repaired, &mut admission)
            .expect_err("synthetic receipt must not complete");

        assert_eq!(
            err,
            ReceiptCompletionError::SyntheticReceiptRef { object_id: 42 }
        );
        assert_refusal_preserves_rebuild_state(&mut completion, &admission, member);
    }

    #[test]
    fn receipt_verified_task_completion_rejects_malformed_repaired_policy() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        rebuilding_member(&mut completion, &mut admission, member, 1);
        let task = make_task(42, 10, 1);
        let mut repaired = repaired_receipt_for_task(&task, 2);
        repaired.redundancy_policy = ReceiptRedundancyPolicy::Replicated { copies: 0 };

        let err = completion
            .record_receipt_verified_task_completion(&task, repaired, &mut admission)
            .expect_err("malformed policy must not complete");

        assert_eq!(
            err,
            ReceiptCompletionError::MalformedReceiptPolicy { object_id: 42 }
        );
        assert_refusal_preserves_rebuild_state(&mut completion, &admission, member);
    }

    #[test]
    fn receipt_verified_task_completion_rejects_under_width_repaired_receipt() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        rebuilding_member(&mut completion, &mut admission, member, 1);
        let task = make_task(42, 10, 1);
        let mut repaired = repaired_receipt_for_task(&task, 2);
        repaired.redundancy_policy = ReceiptRedundancyPolicy::Erasure {
            data_shards: 2,
            parity_shards: 1,
        };
        repaired.target_count = 2;

        let err = completion
            .record_receipt_verified_task_completion(&task, repaired, &mut admission)
            .expect_err("under-width receipt must not complete");

        assert_eq!(
            err,
            ReceiptCompletionError::InsufficientReceiptTargets {
                object_id: 42,
                required: 3,
                actual: 2,
            }
        );
        assert_refusal_preserves_rebuild_state(&mut completion, &admission, member);
    }

    #[test]
    fn receipt_verified_task_completion_rejects_object_id_mismatch() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        rebuilding_member(&mut completion, &mut admission, member, 1);
        let task = make_task(42, 10, 1);
        let mut repaired = repaired_receipt_for_task(&task, 2);
        repaired.object_id = 43;

        let err = completion
            .record_receipt_verified_task_completion(&task, repaired, &mut admission)
            .expect_err("object id mismatch must not complete");

        assert_eq!(
            err,
            ReceiptCompletionError::ObjectIdMismatch {
                task_object_id: 42,
                repaired_object_id: 43,
            }
        );
        assert_refusal_preserves_rebuild_state(&mut completion, &admission, member);
    }

    #[test]
    fn receipt_verified_task_completion_rejects_object_key_mismatch() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        rebuilding_member(&mut completion, &mut admission, member, 1);
        let task = make_task(42, 10, 1);
        let mut repaired = repaired_receipt_for_task(&task, 2);
        repaired.object_key[31] ^= 0xFF;

        let err = completion
            .record_receipt_verified_task_completion(&task, repaired, &mut admission)
            .expect_err("object key mismatch must not complete");

        assert_eq!(
            err,
            ReceiptCompletionError::ObjectKeyMismatch { object_id: 42 }
        );
        assert_refusal_preserves_rebuild_state(&mut completion, &admission, member);
    }

    #[test]
    fn receipt_verified_task_completion_rejects_payload_len_mismatch() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        rebuilding_member(&mut completion, &mut admission, member, 1);
        let task = make_task(42, 10, 1);
        let mut repaired = repaired_receipt_for_task(&task, 2);
        repaired.payload_len += 1;

        let err = completion
            .record_receipt_verified_task_completion(&task, repaired, &mut admission)
            .expect_err("payload length mismatch must not complete");

        assert_eq!(
            err,
            ReceiptCompletionError::PayloadLengthMismatch {
                object_id: 42,
                task_len: 4096,
                repaired_len: 4097,
            }
        );
        assert_refusal_preserves_rebuild_state(&mut completion, &admission, member);
    }

    #[test]
    fn receipt_verified_task_completion_rejects_payload_digest_mismatch() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        rebuilding_member(&mut completion, &mut admission, member, 1);
        let task = make_task(42, 10, 1);
        let mut repaired = repaired_receipt_for_task(&task, 2);
        repaired.payload_digest[0] ^= 0xFF;

        let err = completion
            .record_receipt_verified_task_completion(&task, repaired, &mut admission)
            .expect_err("payload digest mismatch must not complete");

        assert_eq!(
            err,
            ReceiptCompletionError::PayloadDigestMismatch { object_id: 42 }
        );
        assert_refusal_preserves_rebuild_state(&mut completion, &admission, member);
    }

    #[test]
    fn drain_events_clears_pending() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        completion.register(member, 1);
        admission
            .member_status
            .insert(member, crate::admission::RebuildAdmissionStatus::Rebuilding);
        completion.record_intent_completion(
            member,
            ReplicatedSubjectId::new(1),
            true,
            &mut admission,
        );
        assert_eq!(completion.drain_events().len(), 1);
        assert_eq!(completion.drain_events().len(), 0);
    }

    #[test]
    fn multiple_members() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let m10 = MemberId::new(10);
        let m11 = MemberId::new(11);
        completion.register(m10, 1);
        completion.register(m11, 1);
        admission
            .member_status
            .insert(m10, crate::admission::RebuildAdmissionStatus::Rebuilding);
        admission
            .member_status
            .insert(m11, crate::admission::RebuildAdmissionStatus::Rebuilding);

        assert!(!completion.all_complete());
        assert_eq!(completion.in_progress_count(), 2);
        completion.record_intent_completion(m10, ReplicatedSubjectId::new(1), true, &mut admission);
        assert!(!completion.all_complete());
        assert_eq!(completion.in_progress_count(), 1);
        completion.record_intent_completion(m11, ReplicatedSubjectId::new(2), true, &mut admission);
        assert!(completion.all_complete());
        assert_eq!(completion.in_progress_count(), 0);
    }

    #[test]
    fn empty_completion_not_all_complete() {
        assert!(!RebuildCompletion::new().all_complete());
    }

    #[test]
    fn unknown_member_status() {
        assert!(RebuildCompletion::new().status(MemberId::new(99)).is_none());
    }

    #[test]
    fn fraction_computation() {
        let s = CompletionStatus::new(MemberId::new(10), 10);
        assert!((s.fraction() - 0.0).abs() < f64::EPSILON);

        let mut s2 = CompletionStatus::new(MemberId::new(10), 10);
        s2.subjects_completed = 5;
        assert!((s2.fraction() - 0.5).abs() < f64::EPSILON);

        let s3 = CompletionStatus::new(MemberId::new(10), 0);
        assert!((s3.fraction() - 1.0).abs() < f64::EPSILON);
    }

    // ── erasure-coded receipt tests for #346 ──────────────────────────

    fn erasure_receipt_ref(
        subject: u64,
        generation: u64,
        data_shards: u8,
        parity_shards: u8,
    ) -> PlacementReceiptRef {
        let mut object_key = [0xA5; 32];
        object_key[..8].copy_from_slice(&subject.to_le_bytes());
        let mut digest = [0x5A; 32];
        digest[..8].copy_from_slice(&subject.to_le_bytes());
        digest[8..16].copy_from_slice(&generation.to_le_bytes());
        PlacementReceiptRef::erasure(
            subject,
            object_key,
            tidefs_membership_epoch::EpochId::new(7),
            generation,
            data_shards,
            parity_shards,
            4096,
            digest,
        )
    }

    fn make_erasure_task(
        subject: u64,
        member: u64,
        generation: u64,
        data_shards: u8,
        parity_shards: u8,
    ) -> BackfillTask {
        let placement_receipt_ref =
            erasure_receipt_ref(subject, generation, data_shards, parity_shards);
        BackfillTask::new(BackfillTaskInit {
            subject_ref: ReplicatedSubjectId::new(subject),
            placement_receipt_ref,
            source_member: MemberId::new(1),
            target_member: MemberId::new(member),
            movement_class: ReplicaMovementClass::RebuildLostOrSuspectCopy,
            payload_digest: receipt_digest_to_object_digest(placement_receipt_ref.payload_digest),
            payload_len: placement_receipt_ref.payload_len,
            created_at_ns: 0,
            deadline_ns: 10_000,
        })
    }

    #[test]
    fn erasure_receipt_verification_passes() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        rebuilding_member(&mut completion, &mut admission, member, 1);

        let task = make_erasure_task(42, 10, 1, 4, 2);
        let mut repaired = erasure_receipt_ref(42, 1, 4, 2);
        repaired.receipt_generation = 2;

        let event = completion
            .record_receipt_verified_task_completion(&task, repaired, &mut admission)
            .expect("erasure receipt should verify")
            .expect("first verified receipt completes member");

        assert_eq!(event.succeeded, 1);
        assert!(event.fully_successful);
        assert_eq!(completion.total_completed_subjects(), 1);
    }

    #[test]
    fn erasure_receipt_rejects_under_width_targets() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        rebuilding_member(&mut completion, &mut admission, member, 1);

        let task = make_erasure_task(42, 10, 1, 4, 2);
        // Repaired receipt claims only 5 targets, but 4+2=6 required
        let mut repaired = erasure_receipt_ref(42, 1, 4, 2);
        repaired.receipt_generation = 2;
        repaired.target_count = 5;

        let err = completion
            .record_receipt_verified_task_completion(&task, repaired, &mut admission)
            .expect_err("under-width erasure receipt must not complete");

        assert_eq!(
            err,
            ReceiptCompletionError::InsufficientReceiptTargets {
                object_id: 42,
                required: 6,
                actual: 5,
            }
        );
        assert_refusal_preserves_rebuild_state(&mut completion, &admission, member);
    }


    #[test]
    fn erasure_receipt_rejects_malformed_zero_data_shards() {
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        rebuilding_member(&mut completion, &mut admission, member, 1);

        let task = make_erasure_task(42, 10, 1, 0, 2);
        let mut repaired = erasure_receipt_ref(42, 1, 0, 2);
        repaired.receipt_generation = 2;
        repaired.redundancy_policy = tidefs_replication_model::ReceiptRedundancyPolicy::Erasure {
            data_shards: 0,
            parity_shards: 2,
        };

        let err = completion
            .record_receipt_verified_task_completion(&task, repaired, &mut admission)
            .expect_err("malformed erasure policy must not complete");

        assert_eq!(
            err,
            ReceiptCompletionError::MalformedReceiptPolicy { object_id: 42 }
        );
        assert_refusal_preserves_rebuild_state(&mut completion, &admission, member);
    }
    #[test]
    fn rebuild_after_replacement_receipt_completes() {
        // Simulates rebuild after a device replacement: the replacement
        // receipt has a higher generation than the original source receipt.
        let mut completion = RebuildCompletion::new();
        let mut admission = RebuildAdmission::with_epoch(1);
        let member = MemberId::new(10);
        rebuilding_member(&mut completion, &mut admission, member, 1);

        let task = make_erasure_task(42, 10, 1, 4, 2);
        // Replacement receipt has generation 5 (much higher than original gen 1)
        let mut replacement_receipt = erasure_receipt_ref(42, 1, 4, 2);
        replacement_receipt.receipt_generation = 5;

        let event = completion
            .record_receipt_verified_task_completion(&task, replacement_receipt, &mut admission)
            .expect("replacement receipt should verify")
            .expect("completes rebuild after replacement");

        assert_eq!(event.succeeded, 1);
        assert!(event.fully_successful);

        let records = completion.verified_receipt_completions();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].source_placement_receipt_ref.receipt_generation,
            1
        );
        assert_eq!(
            records[0].repaired_placement_receipt_ref.receipt_generation,
            5
        );
    }
}
