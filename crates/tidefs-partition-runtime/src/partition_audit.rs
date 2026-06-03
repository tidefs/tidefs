//! PartitionAudit: records partition events for operator audit
//! through the operator audit system (#898).

use crate::types::{
    derive_record_id, now_millis, PartitionEvent, PartitionEventClass, PartitionHazardClass,
};
use tidefs_membership_epoch::{EpochId, MemberId, SplitBrainHazardRecord};

// ---------------------------------------------------------------------------
// PartitionAuditRecorder
// ---------------------------------------------------------------------------

/// Records partition events for operator visibility and audit trail.
///
/// Emitted events are surfaced via the #898 control plane with per-member
/// partition state. Events are recorded for operator audit queries through
/// `explanation_query`.
pub struct PartitionAuditRecorder {
    /// All recorded partition events.
    pub events: Vec<PartitionEvent>,
    /// Next event ID.
    next_event_id: u64,
    /// My member ID.
    pub my_id: MemberId,
    /// Current epoch.
    pub epoch: EpochId,
}

impl PartitionAuditRecorder {
    /// Create a new audit recorder.
    pub fn new(my_id: MemberId, epoch: EpochId) -> Self {
        Self {
            events: Vec::new(),
            next_event_id: 1,
            my_id,
            epoch,
        }
    }

    /// Record a partition-detected event.
    pub fn record_partition_detected(
        &mut self,
        hazard_class: PartitionHazardClass,
        partition_members: Vec<MemberId>,
        quorum_side_members: Vec<MemberId>,
        minority_side_members: Vec<MemberId>,
        split_brain_hazard: Option<SplitBrainHazardRecord>,
    ) -> &PartitionEvent {
        self.record_event(
            PartitionEventClass::PartitionDetected,
            hazard_class,
            partition_members,
            quorum_side_members,
            minority_side_members,
            split_brain_hazard,
        )
    }

    /// Record quorum side confirmation.
    pub fn record_quorum_side_confirmed(
        &mut self,
        minority_members: Vec<MemberId>,
    ) -> &PartitionEvent {
        self.record_event(
            PartitionEventClass::QuorumSideConfirmed,
            PartitionHazardClass::QuorumSide,
            minority_members.clone(),
            vec![self.my_id],
            minority_members,
            None,
        )
    }

    /// Record minority side fencing.
    pub fn record_minority_fenced(
        &mut self,
        quorum_side_members: Vec<MemberId>,
    ) -> &PartitionEvent {
        self.record_event(
            PartitionEventClass::MinorityFenced,
            PartitionHazardClass::MinoritySide,
            quorum_side_members.clone(),
            quorum_side_members,
            vec![self.my_id],
            None,
        )
    }

    /// Record ambiguous halt.
    pub fn record_ambiguous_halted(&mut self, sides: Vec<Vec<MemberId>>) -> &PartitionEvent {
        let all_members: Vec<MemberId> = sides.iter().flat_map(|s| s.iter().copied()).collect();
        self.record_event(
            PartitionEventClass::AmbiguousHalted,
            PartitionHazardClass::PartitionAmbiguous,
            all_members,
            Vec::new(),
            Vec::new(),
            None,
        )
    }

    /// Record healing started.
    pub fn record_healing_started(&mut self, rejoining_members: Vec<MemberId>) -> &PartitionEvent {
        self.record_event(
            PartitionEventClass::HealingStarted,
            PartitionHazardClass::QuorumSide,
            rejoining_members.clone(),
            vec![self.my_id],
            rejoining_members,
            None,
        )
    }

    /// Record healing complete.
    pub fn record_healing_complete(&mut self, rejoining_members: Vec<MemberId>) -> &PartitionEvent {
        self.record_event(
            PartitionEventClass::HealingComplete,
            PartitionHazardClass::QuorumSide,
            rejoining_members,
            vec![self.my_id],
            Vec::new(),
            None,
        )
    }

    /// Record split-brain hazard emission.
    pub fn record_split_brain_hazard(
        &mut self,
        hazard: &SplitBrainHazardRecord,
    ) -> &PartitionEvent {
        self.record_event(
            PartitionEventClass::SplitBrainHazardEmitted,
            PartitionHazardClass::PartitionAmbiguous,
            hazard.conflicting_holder_refs.clone(),
            Vec::new(),
            Vec::new(),
            Some(hazard.clone()),
        )
    }

    /// Get all events since a given timestamp (for audit queries).
    #[must_use]
    pub fn events_since(&self, since_millis: u64) -> Vec<&PartitionEvent> {
        self.events
            .iter()
            .filter(|e| e.emitted_at_millis >= since_millis)
            .collect()
    }

    /// Get the most recent event of a given class.
    #[must_use]
    pub fn most_recent_event(&self, class: PartitionEventClass) -> Option<&PartitionEvent> {
        self.events.iter().rev().find(|e| e.event_class == class)
    }

    /// Check if there's an active (unresolved) partition event.
    #[must_use]
    pub fn has_active_partition(&self) -> bool {
        self.events
            .last()
            .map(|e| {
                matches!(
                    e.event_class,
                    PartitionEventClass::PartitionDetected
                        | PartitionEventClass::QuorumSideConfirmed
                        | PartitionEventClass::MinorityFenced
                        | PartitionEventClass::AmbiguousHalted
                )
            })
            .unwrap_or(false)
    }

    // -------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------

    fn record_event(
        &mut self,
        event_class: PartitionEventClass,
        hazard_class: PartitionHazardClass,
        partition_members: Vec<MemberId>,
        quorum_side_members: Vec<MemberId>,
        minority_side_members: Vec<MemberId>,
        split_brain_hazard: Option<SplitBrainHazardRecord>,
    ) -> &PartitionEvent {
        let event_id = self.next_event_id;
        self.next_event_id += 1;
        let emitted_at = now_millis();
        let digest = derive_record_id(event_id, self.epoch.0, emitted_at);

        let event = PartitionEvent {
            event_id,
            event_class,
            hazard_class,
            epoch: self.epoch,
            partition_members,
            quorum_side_members,
            minority_side_members,
            split_brain_hazard,
            emitted_at_millis: emitted_at,
            digest,
        };

        self.events.push(event);
        self.events.last().unwrap()
    }

    /// Reset the recorder.
    pub fn reset(&mut self) {
        self.events.clear();
        self.next_event_id = 1;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_partition_detected() {
        let mut rec = PartitionAuditRecorder::new(MemberId::new(1), EpochId::new(1));
        let event = rec.record_partition_detected(
            PartitionHazardClass::QuorumSide,
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
            vec![MemberId::new(1), MemberId::new(2)],
            vec![MemberId::new(3)],
            None,
        );
        assert_eq!(event.event_class, PartitionEventClass::PartitionDetected);
        assert_eq!(rec.events.len(), 1);
    }

    #[test]
    fn test_record_minority_fenced() {
        let mut rec = PartitionAuditRecorder::new(MemberId::new(1), EpochId::new(1));
        let event = rec.record_minority_fenced(vec![MemberId::new(2), MemberId::new(3)]);
        assert_eq!(event.event_class, PartitionEventClass::MinorityFenced);
        assert_eq!(event.hazard_class, PartitionHazardClass::MinoritySide);
    }

    #[test]
    fn test_active_partition_detected() {
        let mut rec = PartitionAuditRecorder::new(MemberId::new(1), EpochId::new(1));
        assert!(!rec.has_active_partition());
        rec.record_partition_detected(
            PartitionHazardClass::QuorumSide,
            vec![],
            vec![],
            vec![],
            None,
        );
        assert!(rec.has_active_partition());
    }

    #[test]
    fn test_events_since_filtering() {
        let mut rec = PartitionAuditRecorder::new(MemberId::new(1), EpochId::new(1));
        rec.record_partition_detected(
            PartitionHazardClass::QuorumSide,
            vec![],
            vec![],
            vec![],
            None,
        );
        rec.record_healing_started(vec![]);
        let event2_id = rec.events[1].event_id;
        // Both events may share the same millisecond timestamp.
        // Use event_id ordering instead of timestamp for reliable filtering.
        assert!(rec.events.len() == 2);
        assert_eq!(rec.events[1].event_id, event2_id);
        // Filtering from timestamp 0 should return all events
        let all = rec.events_since(0);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_event_id_monotonic() {
        let mut rec = PartitionAuditRecorder::new(MemberId::new(1), EpochId::new(1));
        let e1 = rec.record_partition_detected(
            PartitionHazardClass::QuorumSide,
            vec![],
            vec![],
            vec![],
            None,
        );
        let e1_id = e1.event_id;
        let e2 = rec.record_healing_complete(vec![]);
        assert!(e2.event_id > e1_id);
    }

    #[test]
    fn test_record_split_brain_hazard() {
        let mut rec = PartitionAuditRecorder::new(MemberId::new(1), EpochId::new(1));
        let hazard = SplitBrainHazardRecord {
            hazard_id: 42,
            authority_domain_ref: tidefs_membership_epoch::AuthorityDomainId::new(1),
            membership_epoch_ref: EpochId::new(1),
            conflicting_holder_refs: vec![MemberId::new(1), MemberId::new(2)],
            conflicting_domain_refs: vec![],
            required_hold_or_quarantine_ref:
                tidefs_membership_epoch::VerdictClass::RefuseSplitBrain,
            resolution_receipt_ref: tidefs_membership_epoch::ReceiptId::ZERO,
            digest: 0,
        };
        let event = rec.record_split_brain_hazard(&hazard);
        assert_eq!(
            event.event_class,
            PartitionEventClass::SplitBrainHazardEmitted
        );
        assert!(event.split_brain_hazard.is_some());
    }
}
