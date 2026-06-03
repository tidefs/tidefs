#![forbid(unsafe_code)]

//! Graceful peer departure coordination.
//!
//! A [`LeaveCoordinator`] validates a leave request against the current roster,
//! computes the successor epoch, removes the departing peer from the member
//! set, and produces a [`LeaveNotificationPayload`] for broadcast to remaining
//! peers.
//!
//! ## Lifecycle
//!
//! ```text
//! validate_leave(member_id, reason)
//!   |
//!   +-- transition in flight? → Rejected (conflicting proposal)
//!   +-- member not in roster?  → Rejected
//!   +-- last member?           → Rejected (cluster would be empty)
//!   +-- success → Accepted
//!         |
//!         +-- compute successor epoch = current + 1
//!         +-- remove departing member from roster
//!         +-- produce LeaveNotificationPayload for broadcast
//! ```
//!
//! ## Epoch-advancement conflict detection
//!
//! When multiple configuration changes (join, leave, drain) are in flight,
//! the coordinator detects conflicting concurrent proposals by tracking
//! the `transition_in_flight` flag and refusing leave requests when another
//! epoch transition is already pending.

use serde::{Deserialize, Serialize};

use crate::coordinator_promotion::{CoordinatorChanged, CoordinatorPromotion};
use crate::{EpochId, LeaveOutcome, LeaveReason, MemberId};

// ---------------------------------------------------------------------------
// LeaveCoordinator
// ---------------------------------------------------------------------------

/// Coordinates graceful peer departure from the cluster.
///
/// Validates that the departing peer is a current roster member, that
/// it has not already departed, and that the cluster is not left with
/// zero members. On success, computes the successor epoch and produces
/// a [`LeaveNotificationPayload`] for broadcast.
#[derive(Clone, Debug)]
pub struct LeaveCoordinator {
    /// Current committed epoch.
    pub current_epoch: EpochId,
    /// Sorted, deduplicated member set.
    pub member_set: Vec<MemberId>,
    /// Whether another epoch transition is in flight (prevents conflict).
    pub transition_in_flight: bool,
    /// The current coordinator, used to compute promotion on departure.
    pub current_coordinator: Option<MemberId>,
}

impl LeaveCoordinator {
    /// Create a new leave coordinator.
    #[must_use]
    pub fn new(current_epoch: EpochId, member_set: Vec<MemberId>) -> Self {
        let coordinator = CoordinatorPromotion::current_coordinator(&member_set);
        Self {
            current_epoch,
            member_set,
            transition_in_flight: false,
            current_coordinator: coordinator,
        }
    }

    /// Create a coordinator with transition-in-flight awareness.
    #[must_use]
    pub fn with_transition_flag(
        current_epoch: EpochId,
        member_set: Vec<MemberId>,
        transition_in_flight: bool,
    ) -> Self {
        let coordinator = CoordinatorPromotion::current_coordinator(&member_set);
        Self {
            current_epoch,
            member_set,
            transition_in_flight,
            current_coordinator: coordinator,
        }
    }

    /// Validate and process a leave request.
    ///
    /// Returns a [`LeaveResult`] with the outcome, the successor epoch,
    /// the updated member set (without the departing member), and
    /// a [`LeaveNotificationPayload`] ready for broadcast.
    ///
    /// # Outcomes
    ///
    /// - `Accepted`: the peer was in the roster and removal succeeded.
    /// - `Rejected`: the peer is not in the roster, is the last member,
    ///   or a conflicting transition is in flight.
    /// - `AlreadyDeparted`: returned when the peer was already removed.
    #[must_use]
    pub fn validate_leave(&self, departing_member: MemberId, reason: LeaveReason) -> LeaveResult {
        // Reject when another transition is in flight.
        if self.transition_in_flight {
            return LeaveResult {
                outcome: LeaveOutcome::Rejected,
                successor_epoch: self.current_epoch,
                coordinator_changed: None,
                successor_member_set: self.member_set.clone(),
                notification: None,
                rejected_reason: Some("conflicting epoch transition in flight".into()),
            };
        }

        // Reject if the departing member is not in the current member set.
        if !self.member_set.contains(&departing_member) {
            return LeaveResult {
                outcome: LeaveOutcome::Rejected,
                successor_epoch: self.current_epoch,
                coordinator_changed: None,
                successor_member_set: self.member_set.clone(),
                notification: None,
                rejected_reason: Some(format!(
                    "member {departing_member:?} is not in the current roster"
                )),
            };
        }

        // Reject if this is the last member — cluster would be empty.
        if self.member_set.len() <= 1 {
            return LeaveResult {
                outcome: LeaveOutcome::Rejected,
                successor_epoch: self.current_epoch,
                coordinator_changed: None,
                successor_member_set: self.member_set.clone(),
                notification: None,
                rejected_reason: Some("last member cannot leave; cluster would be empty".into()),
            };
        }

        // Compute successor set and epoch.
        let successor_epoch = self.current_epoch.next();
        let successor_member_set: Vec<MemberId> = self
            .member_set
            .iter()
            .copied()
            .filter(|m| *m != departing_member)
            .collect();

        let notification = LeaveNotificationPayload {
            departing_member,
            departure_epoch: self.current_epoch,
            successor_epoch,
            reason,
        };

        // Compute coordinator promotion when the departing member is the
        // current coordinator.
        let coordinator_changed = self.current_coordinator.and_then(|coord| {
            if departing_member == coord {
                CoordinatorPromotion::promote_on_departure(&self.member_set, departing_member)
            } else {
                None
            }
        });

        LeaveResult {
            outcome: LeaveOutcome::Accepted,
            successor_epoch,
            successor_member_set,
            coordinator_changed,
            notification: Some(notification),
            rejected_reason: None,
        }
    }
}

// ---------------------------------------------------------------------------
// LeaveResult
// ---------------------------------------------------------------------------

/// Result of a leave validation and coordination.
#[derive(Clone, Debug)]
pub struct LeaveResult {
    /// Whether the leave was accepted, rejected, or already processed.
    pub outcome: LeaveOutcome,
    /// The successor epoch (unchanged if rejected).
    pub successor_epoch: EpochId,
    /// The coordinator promotion payload when the departing member was the coordinator.
    pub coordinator_changed: Option<CoordinatorChanged>,
    /// The member set after departure.
    pub successor_member_set: Vec<MemberId>,
    /// The notification payload for broadcast, when accepted.
    pub notification: Option<LeaveNotificationPayload>,
    /// Rejection reason when outcome is `Rejected`.
    pub rejected_reason: Option<String>,
}

impl LeaveResult {
    /// Whether the leave was accepted.
    #[must_use]
    pub fn is_accepted(&self) -> bool {
        matches!(self.outcome, LeaveOutcome::Accepted)
    }
}

// ---------------------------------------------------------------------------
// LeaveNotificationPayload
// ---------------------------------------------------------------------------

/// Payload for a leave notification broadcast to remaining cluster members.
///
/// Carries the departing member identity, departure epoch, successor epoch,
/// and the reason for departure. This is the payload that gets embedded into
/// `MembershipOutboundMessage::LeaveNotification` for transport dispatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaveNotificationPayload {
    /// The departing member.
    pub departing_member: MemberId,
    /// The current epoch at departure.
    pub departure_epoch: EpochId,
    /// The epoch after departure (successor).
    pub successor_epoch: EpochId,
    /// Reason for departure.
    pub reason: LeaveReason,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn member(id: u64) -> MemberId {
        MemberId::new(id)
    }

    fn epoch(id: u64) -> EpochId {
        EpochId::new(id)
    }

    fn coordinator(members: &[u64]) -> LeaveCoordinator {
        LeaveCoordinator::new(
            EpochId::new(5),
            members.iter().map(|&id| MemberId::new(id)).collect(),
        )
    }

    // ── Basic leave coordination ─────────────────────────────────────

    #[test]
    fn validate_leave_accepts_valid_member() {
        let coord = coordinator(&[1, 2, 3]);
        let result = coord.validate_leave(member(2), LeaveReason::Voluntary);

        assert_eq!(result.outcome, LeaveOutcome::Accepted);
        assert!(result.is_accepted());
        assert_eq!(result.successor_epoch, epoch(6));
        assert_eq!(result.successor_member_set, vec![member(1), member(3)]);

        let notif = result.notification.unwrap();
        assert_eq!(notif.departing_member, member(2));
        assert_eq!(notif.departure_epoch, epoch(5));
        assert_eq!(notif.successor_epoch, epoch(6));
        assert_eq!(notif.reason, LeaveReason::Voluntary);
        assert!(result.rejected_reason.is_none());
    }

    #[test]
    fn validate_leave_rejects_non_member() {
        let coord = coordinator(&[1, 2]);
        let result = coord.validate_leave(member(99), LeaveReason::Voluntary);

        assert_eq!(result.outcome, LeaveOutcome::Rejected);
        assert!(!result.is_accepted());
        assert_eq!(result.successor_epoch, epoch(5));
        assert_eq!(result.successor_member_set, vec![member(1), member(2)]);
        assert!(result.notification.is_none());
        assert!(result
            .rejected_reason
            .unwrap()
            .contains("not in the current roster"));
    }

    #[test]
    fn validate_leave_rejects_last_member() {
        let coord = coordinator(&[1]);
        let result = coord.validate_leave(member(1), LeaveReason::Maintenance);

        assert_eq!(result.outcome, LeaveOutcome::Rejected);
        assert!(result.rejected_reason.unwrap().contains("last member"));
        assert!(result.notification.is_none());
    }

    #[test]
    fn validate_leave_rejects_when_transition_in_flight() {
        let coord = LeaveCoordinator::with_transition_flag(
            EpochId::new(5),
            vec![member(1), member(2), member(3)],
            true,
        );
        let result = coord.validate_leave(member(2), LeaveReason::Draining);

        assert_eq!(result.outcome, LeaveOutcome::Rejected);
        assert!(result.rejected_reason.unwrap().contains("in flight"));
        assert!(result.notification.is_none());
    }

    #[test]
    fn validate_leave_rejects_already_removed_member() {
        let coord = coordinator(&[1, 3]); // member 2 already removed
        let result = coord.validate_leave(member(2), LeaveReason::Voluntary);

        assert_eq!(result.outcome, LeaveOutcome::Rejected);
        assert!(result
            .rejected_reason
            .unwrap()
            .contains("not in the current roster"));
    }

    #[test]
    fn validate_leave_all_reasons_accepted() {
        let coord = coordinator(&[1, 2, 3, 4]);
        for reason in [
            LeaveReason::Voluntary,
            LeaveReason::Maintenance,
            LeaveReason::Draining,
        ] {
            let result = coord.validate_leave(member(3), reason);
            assert!(result.is_accepted(), "reason={reason:?} should be accepted");
            assert_eq!(result.notification.unwrap().reason, reason);
        }
    }

    #[test]
    fn successor_epoch_advances_correctly() {
        for epoch_num in [0, 1, 5, 99] {
            let coord = LeaveCoordinator::new(
                EpochId::new(epoch_num),
                vec![member(1), member(2), member(3)],
            );
            let result = coord.validate_leave(member(2), LeaveReason::Voluntary);
            assert_eq!(result.successor_epoch, EpochId::new(epoch_num + 1));
        }
    }

    #[test]
    fn leave_notification_payload_bincode_roundtrip() {
        let payload = LeaveNotificationPayload {
            departing_member: MemberId::new(42),
            departure_epoch: EpochId::new(7),
            successor_epoch: EpochId::new(8),
            reason: LeaveReason::Maintenance,
        };

        let encoded = bincode::serialize(&payload).unwrap();
        let decoded: LeaveNotificationPayload = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn leave_notification_payload_equality() {
        let a = LeaveNotificationPayload {
            departing_member: member(1),
            departure_epoch: epoch(5),
            successor_epoch: epoch(6),
            reason: LeaveReason::Voluntary,
        };
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(a.reason, LeaveReason::Maintenance);
    }

    #[test]
    fn validate_leave_empty_member_set_rejected() {
        let coord = LeaveCoordinator::new(EpochId::new(0), vec![]);
        let result = coord.validate_leave(member(1), LeaveReason::Voluntary);
        assert_eq!(result.outcome, LeaveOutcome::Rejected);
    }

    // ── Coordinator promotion on departure ─────────────────────────────

    #[test]
    fn coordinator_promotion_on_accepted_leave() {
        let coord = coordinator(&[1, 2, 3]); // coordinator = 1 (lowest)
        let result = coord.validate_leave(member(1), LeaveReason::Voluntary);

        assert_eq!(result.outcome, LeaveOutcome::Accepted);
        assert!(result.coordinator_changed.is_some());
        let cc = result.coordinator_changed.unwrap();
        assert_eq!(cc.old, member(1));
        assert_eq!(cc.new, member(2)); // next lowest after 1
    }

    #[test]
    fn no_coordinator_promotion_when_non_coordinator_leaves() {
        let coord = coordinator(&[1, 5, 10]); // coordinator = 1
        let result = coord.validate_leave(member(5), LeaveReason::Voluntary);

        assert_eq!(result.outcome, LeaveOutcome::Accepted);
        assert!(result.coordinator_changed.is_none());
    }

    #[test]
    fn coordinator_promotion_preserves_leave_payload() {
        let coord = coordinator(&[10, 20, 30]); // coordinator = 10
        let result = coord.validate_leave(member(10), LeaveReason::Maintenance);

        assert_eq!(result.outcome, LeaveOutcome::Accepted);
        assert!(result.coordinator_changed.is_some());
        let cc = result.coordinator_changed.unwrap();
        assert_eq!(cc.old, member(10));
        assert_eq!(cc.new, member(20));

        // Leave notification payload is still correct.
        let notif = result.notification.unwrap();
        assert_eq!(notif.departing_member, member(10));
        assert_eq!(notif.successor_epoch, epoch(6));
        assert_eq!(notif.reason, LeaveReason::Maintenance);
    }

    #[test]
    fn rejection_never_includes_coordinator_changed() {
        // Non-member
        let coord = coordinator(&[1, 2]);
        let result = coord.validate_leave(member(99), LeaveReason::Voluntary);
        assert_eq!(result.outcome, LeaveOutcome::Rejected);
        assert!(result.coordinator_changed.is_none());

        // Last member
        let coord = coordinator(&[1]);
        let result = coord.validate_leave(member(1), LeaveReason::Maintenance);
        assert_eq!(result.outcome, LeaveOutcome::Rejected);
        assert!(result.coordinator_changed.is_none());

        // Transition in flight
        let coord = LeaveCoordinator::with_transition_flag(
            EpochId::new(5),
            vec![member(1), member(2), member(3)],
            true,
        );
        let result = coord.validate_leave(member(1), LeaveReason::Draining);
        assert_eq!(result.outcome, LeaveOutcome::Rejected);
        assert!(result.coordinator_changed.is_none());
    }

    #[test]
    fn coordinator_promotion_with_large_gap() {
        let coord = coordinator(&[3, 100, 200]); // coordinator = 3
        let result = coord.validate_leave(member(3), LeaveReason::Draining);

        assert!(result.is_accepted());
        let cc = result.coordinator_changed.unwrap();
        assert_eq!(cc.old, member(3));
        assert_eq!(cc.new, member(100));
    }
}
