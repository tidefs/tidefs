//! RebuildCompletion: tracks rebuild flow completion and emits
//! signals when missing data has been fully recovered after
//! node/device loss.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::MemberId;
use tidefs_replication_model::{ReplicaMovementIntentRecord, ReplicatedSubjectId};

use crate::admission::RebuildAdmission;

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

/// Tracks rebuild completion across multiple members.
#[derive(Clone, Debug, Default)]
pub struct RebuildCompletion {
    members: BTreeMap<MemberId, CompletionStatus>,
    completed_subjects: BTreeSet<(MemberId, ReplicatedSubjectId)>,
    pending_events: Vec<RebuildCompleted>,
}

impl RebuildCompletion {
    #[must_use]
    pub fn new() -> Self {
        Self {
            members: BTreeMap::new(),
            completed_subjects: BTreeSet::new(),
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
        if self.completed_subjects.contains(&dedup_key) {
            return None;
        }
        self.completed_subjects.insert(dedup_key);

        let status = self
            .members
            .entry(member)
            .or_insert_with(|| CompletionStatus::new(member, 0));
        if success {
            status.record_completed();
        } else {
            status.record_failed();
        }

        if status.is_complete {
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
            if let Some(event) = self.record_intent_completion(
                intent.target_member_ref,
                intent.subject_ref,
                true,
                admission,
            ) {
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
        self.completed_subjects.len() as u64
    }

    pub fn reset(&mut self) {
        self.members.clear();
        self.completed_subjects.clear();
        self.pending_events.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::MemberId;
    use tidefs_replication_model::{
        ObjectDigest, ReplicaMovementClass, ReplicatedReceiptId, ReplicatedSubjectId,
    };

    fn make_intent(id: u64, member: u64, subject: u64) -> ReplicaMovementIntentRecord {
        ReplicaMovementIntentRecord {
            intent_id: ReplicatedReceiptId(id),
            movement_class: ReplicaMovementClass::RebuildLostOrSuspectCopy,
            subject_ref: ReplicatedSubjectId::new(subject),
            source_member_ref: MemberId::new(1),
            target_member_ref: MemberId::new(member),
            payload_digest: ObjectDigest::new(id * 100),
            payload_len: 4096,
            verification_required: false,
        }
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
}
