#![forbid(unsafe_code)]

//! Incarnation-based stale-command rejection for inbound membership messages.
//!
//! Every coordinator transition increments the incarnation counter. Before
//! dispatching an inbound membership message, the validator checks whether
//! the message carries a coordinator-scoped incarnation that is >= the
//! local tracker. Messages with a lower incarnation are rejected as stale.
//!
//! ## Security model
//!
//! This closes the split-brain window where a partitioned former coordinator
//! could issue stale epoch-advance or departure commands that peers could
//! not reliably reject before. No BLAKE3, MAC, or auth-token layers are
//! added — incarnation is a plain monotonic counter riding in existing
//! membership message fields.
//!
//! ## Validated message types
//!
//! - `JoinResponse` — carries coordinator incarnation at join time
//! - `LeaveNotification` — carries coordinator incarnation at departure
//! - `EpochProposal` — carries coordinator incarnation at proposal time
//!
//! All other message types pass through without incarnation validation.

use tidefs_membership_epoch::incarnation::IncarnationTracker;
use tidefs_membership_epoch::Incarnation;

use crate::dispatch_router::{MembershipDispatchError, MembershipMessage};

/// Validates that an inbound membership message's incarnation is not stale.
///
/// Wraps an [`IncarnationTracker`] and provides a `validate()` method that
/// extracts the incarnation from relevant message variants and checks it
/// against the current value.
pub struct IncarnationValidator;

impl IncarnationValidator {
    /// Validate the incarnation carried by an inbound membership message.
    ///
    /// Returns `Ok(())` if:
    /// - The message type does not carry incarnation (pass-through)
    /// - The message carries incarnation >= `tracker.current()`
    ///
    /// # Errors
    ///
    /// Returns [`MembershipDispatchError::HandlerError`] wrapping a
    /// [`StaleIncarnation`] when the message carries an incarnation
    /// lower than the tracker's current value.
    pub fn validate(
        tracker: &IncarnationTracker,
        msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        let msg_incarnation: Option<Incarnation> = match msg {
            MembershipMessage::JoinResponse { incarnation, .. } => Some(*incarnation),
            MembershipMessage::LeaveNotification { incarnation, .. } => Some(*incarnation),
            MembershipMessage::EpochProposal { incarnation, .. } => Some(*incarnation),
            _ => None,
        };

        if let Some(inc) = msg_incarnation {
            tracker.validate(inc).map_err(|stale| {
                MembershipDispatchError::HandlerError(format!(
                    "stale incarnation rejected: msg={} current={}",
                    stale.msg_incarnation, stale.current_incarnation
                ))
            })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::{EpochId, LeaveReason, MemberId};

    fn tracker_at(v: u64) -> IncarnationTracker {
        IncarnationTracker::new(Incarnation(v))
    }

    fn join_response(incarnation: u64) -> MembershipMessage {
        MembershipMessage::JoinResponse {
            request_member_id: MemberId::ZERO,
            accepted: true,
            assigned_epoch: Some(EpochId::ZERO),
            reject_reason: None,
            responded_at_millis: 0,
            incarnation: Incarnation(incarnation),
        }
    }

    fn leave_notification(incarnation: u64) -> MembershipMessage {
        MembershipMessage::LeaveNotification {
            member_id: MemberId::ZERO,
            departure_epoch: EpochId::ZERO,
            announced_at_millis: 0,
            leave_reason: LeaveReason::Voluntary,
            incarnation: Incarnation(incarnation),
        }
    }

    fn epoch_proposal(incarnation: u64) -> MembershipMessage {
        MembershipMessage::EpochProposal {
            proposer: MemberId::ZERO,
            proposed_epoch: EpochId::ZERO,
            proposed_member_set: vec![],
            proposal_nonce: 0,
            proposed_at_millis: 0,
            incarnation: Incarnation(incarnation),
        }
    }

    #[test]
    fn join_response_equal_accepted() {
        let tracker = tracker_at(5);
        assert!(IncarnationValidator::validate(&tracker, &join_response(5)).is_ok());
    }

    #[test]
    fn join_response_greater_accepted() {
        let tracker = tracker_at(5);
        assert!(IncarnationValidator::validate(&tracker, &join_response(10)).is_ok());
    }

    #[test]
    fn join_response_lower_rejected() {
        let tracker = tracker_at(5);
        let result = IncarnationValidator::validate(&tracker, &join_response(3));
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("stale"));
    }

    #[test]
    fn leave_notification_equal_accepted() {
        let tracker = tracker_at(5);
        assert!(IncarnationValidator::validate(&tracker, &leave_notification(5)).is_ok());
    }

    #[test]
    fn leave_notification_lower_rejected() {
        let tracker = tracker_at(7);
        assert!(IncarnationValidator::validate(&tracker, &leave_notification(3)).is_err());
    }

    #[test]
    fn epoch_proposal_equal_accepted() {
        let tracker = tracker_at(5);
        assert!(IncarnationValidator::validate(&tracker, &epoch_proposal(5)).is_ok());
    }

    #[test]
    fn epoch_proposal_lower_rejected() {
        let tracker = tracker_at(5);
        assert!(IncarnationValidator::validate(&tracker, &epoch_proposal(4)).is_err());
    }

    #[test]
    fn non_validated_types_pass_through() {
        let tracker = tracker_at(100);
        let msg = MembershipMessage::HealthReport {
            member_id: MemberId::ZERO,
            epoch: EpochId::ZERO,
            health_class: 0,
            reported_at_millis: 0,
        };
        assert!(IncarnationValidator::validate(&tracker, &msg).is_ok());
    }

    #[test]
    fn genesis_tracker_accepts_all() {
        let tracker = IncarnationTracker::genesis();
        assert!(IncarnationValidator::validate(&tracker, &join_response(0)).is_ok());
        assert!(IncarnationValidator::validate(&tracker, &join_response(100)).is_ok());
        assert!(IncarnationValidator::validate(&tracker, &leave_notification(u64::MAX)).is_ok());
    }
}
