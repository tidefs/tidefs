// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Coordinator-side join-request handler with roster-constraint validation,
//! coordinator-authority checks, incarnation-verified stale-message rejection,
//! and idempotency-key-wrapped proposal submission.
//!
//! ## Protocol role
//!
//! When a joining peer sends a `JoinRequest` over transport, the coordinator
//! (this peer) runs [`JoinHandler::handle_join_request`] to validate the
//! request and produce an outcome. The handler:
//!
//! 1. Verifies self is the current coordinator.
//! 2. Checks the joining peer is not already in the roster.
//! 3. Runs `validate_add_peer` from the roster-constraints module (#6214).
//! 4. Verifies incarnation match against the `IncarnationTracker` (#6208).
//! 5. On passing all gates: produces a `JoinProposal` containing the
//!    roster-addition payload and an idempotency key for safe coordinator
//!    retransmission after failover (#6239).
//! 6. On any failure: returns a rejection with a human-readable reason.
//!
//! This module is pure logic with no transport, storage, or runtime wiring.
//! The caller (typically `MembershipRuntime`) feeds the result into the
//! proposal commit path and the join-response dispatcher.
//!
//! ## Integration
//!
//! - Coordinates with `JoinInitiator` (joining peer side, #6184).
//! - Complements `JoinRequestHandler` (admission lifecycle tracking) with
//!   coordinator-specific authority and constraint validation.
//! - The returned `JoinProposal` is handed to the epoch proposal path;
//!   the returned `JoinIdempotencyKey` prevents duplicate proposals on
//!   retransmission.

use tidefs_membership_epoch::incarnation::IncarnationTracker;
use tidefs_membership_epoch::roster_constraints::{
    validate_add_peer, ConstraintValidationError, RosterConstraints,
};
use tidefs_membership_epoch::{EpochId, Incarnation, MemberId};

// ---------------------------------------------------------------------------
// JoinIdempotencyKey -- prevents duplicate proposals on retransmission
// ---------------------------------------------------------------------------

/// A key derived from the join request that uniquely identifies a proposal
/// for idempotency deduplication.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct JoinIdempotencyKey(pub u64);

impl JoinIdempotencyKey {
    /// Derive a deterministic idempotency key from the joining peer's
    /// identity and the target epoch.
    #[must_use]
    pub fn derive(joining_peer: MemberId, epoch: EpochId) -> Self {
        let mixed = (joining_peer.0.wrapping_mul(0x9E37_79B9_7F4A_7C15))
            ^ (epoch.0.wrapping_mul(0xBF58_476D_1CE4_E5B9));
        Self(mixed)
    }
}

impl std::fmt::Display for JoinIdempotencyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JoinIdempotencyKey({})", self.0)
    }
}

// ---------------------------------------------------------------------------
// JoinProposal -- roster-addition payload produced on successful validation
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinProposal {
    pub joining_peer: MemberId,
    pub join_epoch: EpochId,
    pub idempotency_key: JoinIdempotencyKey,
}

// ---------------------------------------------------------------------------
// JoinRejectionReason -- structured rejection reasons
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JoinRejectionReason {
    NotCoordinator,
    AlreadyMember,
    JoinInProgress,
    ConstraintViolation(ConstraintValidationError),
    StaleIncarnation {
        msg_incarnation: Incarnation,
        current_incarnation: Incarnation,
    },
    InvalidMemberId,
    /// The pool-scan evidence for the joining member is not committed.
    UncommittedPoolScan,
    /// The label agreement for the joining member has not been committed.
    LabelAgreementNotCommitted,
    /// The pool-scan does not include the joining member's identity.
    MemberNotInPoolScan,
}

impl std::fmt::Display for JoinRejectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotCoordinator => write!(f, "not the current coordinator"),
            Self::AlreadyMember => write!(f, "peer is already a cluster member"),
            Self::JoinInProgress => write!(f, "join request already in progress for this peer"),
            Self::ConstraintViolation(e) => write!(f, "roster constraint violation: {e}"),
            Self::StaleIncarnation {
                msg_incarnation,
                current_incarnation,
            } => write!(
                f,
                "stale incarnation: msg={msg_incarnation} current={current_incarnation}"
            ),
            Self::InvalidMemberId => write!(f, "invalid member id"),
            Self::UncommittedPoolScan => {
                write!(f, "pool-scan evidence not committed")
            }
            Self::LabelAgreementNotCommitted => {
                write!(f, "label agreement not committed")
            }
            Self::MemberNotInPoolScan => {
                write!(f, "member identity not found in committed pool scan")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// JoinHandlerResult -- outcome of handling a join request
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JoinHandlerResult {
    Accepted(JoinProposal),
    Rejected(JoinRejectionReason),
}

impl JoinHandlerResult {
    #[must_use]
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted(_))
    }

    #[must_use]
    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected(_))
    }
}

// ---------------------------------------------------------------------------
// JoinHandler -- coordinator-side join-request validator
// ---------------------------------------------------------------------------

pub struct JoinHandler {
    self_id: MemberId,
    is_coordinator: bool,
    roster: Vec<MemberId>,
    constraints: RosterConstraints,
    incarnation_tracker: IncarnationTracker,
    pending_joins: Vec<MemberId>,
}

impl JoinHandler {
    #[must_use]
    pub fn new(
        self_id: MemberId,
        is_coordinator: bool,
        roster: Vec<MemberId>,
        constraints: RosterConstraints,
        incarnation_tracker: IncarnationTracker,
    ) -> Self {
        Self {
            self_id,
            is_coordinator,
            roster,
            constraints,
            incarnation_tracker,
            pending_joins: Vec::new(),
        }
    }

    // -- Accessors --

    #[must_use]
    pub fn self_id(&self) -> MemberId {
        self.self_id
    }

    #[must_use]
    pub fn is_coordinator(&self) -> bool {
        self.is_coordinator
    }

    #[must_use]
    pub fn roster(&self) -> &[MemberId] {
        &self.roster
    }

    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending_joins.len()
    }

    #[must_use]
    pub fn current_incarnation(&self) -> Incarnation {
        self.incarnation_tracker.current()
    }

    // -- Mutable helpers --

    pub fn set_coordinator(&mut self, is_coordinator: bool) {
        self.is_coordinator = is_coordinator;
    }

    pub fn set_roster(&mut self, roster: Vec<MemberId>) {
        self.roster = roster;
    }

    pub fn set_incarnation_tracker(&mut self, tracker: IncarnationTracker) {
        self.incarnation_tracker = tracker;
    }

    pub fn complete_join(&mut self, peer: MemberId) {
        self.pending_joins.retain(|p| *p != peer);
    }

    pub fn clear_pending(&mut self) {
        self.pending_joins.clear();
    }

    // -- Core validation --

    pub fn handle_join_request(
        &mut self,
        joining_peer: MemberId,
        msg_incarnation: Incarnation,
        join_epoch: EpochId,
    ) -> JoinHandlerResult {
        if joining_peer == MemberId::ZERO {
            return JoinHandlerResult::Rejected(JoinRejectionReason::InvalidMemberId);
        }
        if !self.is_coordinator {
            return JoinHandlerResult::Rejected(JoinRejectionReason::NotCoordinator);
        }
        if let Err(stale) = self.incarnation_tracker.validate(msg_incarnation) {
            return JoinHandlerResult::Rejected(JoinRejectionReason::StaleIncarnation {
                msg_incarnation: stale.msg_incarnation,
                current_incarnation: stale.current_incarnation,
            });
        }
        if self.roster.contains(&joining_peer) {
            return JoinHandlerResult::Rejected(JoinRejectionReason::AlreadyMember);
        }
        if self.pending_joins.contains(&joining_peer) {
            return JoinHandlerResult::Rejected(JoinRejectionReason::JoinInProgress);
        }
        if let Err(e) = validate_add_peer(&self.roster, joining_peer, &self.constraints) {
            return JoinHandlerResult::Rejected(JoinRejectionReason::ConstraintViolation(e));
        }
        self.pending_joins.push(joining_peer);
        let idempotency_key = JoinIdempotencyKey::derive(joining_peer, join_epoch);
        let proposal = JoinProposal {
            joining_peer,
            join_epoch,
            idempotency_key,
        };
        JoinHandlerResult::Accepted(proposal)
    }

    pub fn handle_join_request_idempotent(
        &mut self,
        joining_peer: MemberId,
        msg_incarnation: Incarnation,
        join_epoch: EpochId,
    ) -> JoinHandlerResult {
        if self.pending_joins.contains(&joining_peer) {
            let idempotency_key = JoinIdempotencyKey::derive(joining_peer, join_epoch);
            return JoinHandlerResult::Accepted(JoinProposal {
                joining_peer,
                join_epoch,
                idempotency_key,
            });
        }
        self.handle_join_request(joining_peer, msg_incarnation, join_epoch)
    }
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

    fn default_constraints() -> RosterConstraints {
        RosterConstraints::default()
    }

    fn coordinator_handler() -> JoinHandler {
        JoinHandler::new(
            member(1),
            true,
            vec![member(1), member(2)],
            default_constraints(),
            IncarnationTracker::genesis(),
        )
    }

    fn non_coordinator_handler() -> JoinHandler {
        JoinHandler::new(
            member(3),
            false,
            vec![member(1), member(2), member(3)],
            default_constraints(),
            IncarnationTracker::genesis(),
        )
    }

    // -- JoinIdempotencyKey --

    #[test]
    fn idempotency_key_different_members() {
        let k1 = JoinIdempotencyKey::derive(member(1), EpochId::new(5));
        let k2 = JoinIdempotencyKey::derive(member(2), EpochId::new(5));
        assert_ne!(k1, k2);
    }

    #[test]
    fn idempotency_key_different_epochs() {
        let k1 = JoinIdempotencyKey::derive(member(1), EpochId::new(5));
        let k2 = JoinIdempotencyKey::derive(member(1), EpochId::new(6));
        assert_ne!(k1, k2);
    }

    #[test]
    fn idempotency_key_same_inputs() {
        let k1 = JoinIdempotencyKey::derive(member(42), EpochId::new(10));
        let k2 = JoinIdempotencyKey::derive(member(42), EpochId::new(10));
        assert_eq!(k1, k2);
    }

    // -- Valid join accepted --

    #[test]
    fn valid_join_accepted() {
        let mut handler = coordinator_handler();
        let result = handler.handle_join_request(member(3), Incarnation::ZERO, EpochId::new(0));
        match &result {
            JoinHandlerResult::Accepted(proposal) => {
                assert_eq!(proposal.joining_peer, member(3));
                assert_eq!(proposal.join_epoch, EpochId::new(0));
            }
            other => panic!("expected Accepted, got {other:?}"),
        }
        assert!(result.is_accepted());
        assert_eq!(handler.pending_count(), 1);
    }

    #[test]
    fn valid_join_with_higher_incarnation() {
        let mut handler = JoinHandler::new(
            member(1),
            true,
            vec![member(1)],
            default_constraints(),
            IncarnationTracker::new(Incarnation(5)),
        );
        let result = handler.handle_join_request(member(2), Incarnation(5), EpochId::new(1));
        assert!(result.is_accepted());
    }

    #[test]
    fn valid_join_with_greater_incarnation() {
        let mut handler = JoinHandler::new(
            member(1),
            true,
            vec![member(1)],
            default_constraints(),
            IncarnationTracker::new(Incarnation(3)),
        );
        let result = handler.handle_join_request(member(2), Incarnation(7), EpochId::new(0));
        assert!(result.is_accepted());
    }

    // -- Rejection: not coordinator --

    #[test]
    fn non_coordinator_rejected() {
        let mut handler = non_coordinator_handler();
        let result = handler.handle_join_request(member(4), Incarnation::ZERO, EpochId::new(0));
        match &result {
            JoinHandlerResult::Rejected(JoinRejectionReason::NotCoordinator) => {}
            other => panic!("expected NotCoordinator, got {other:?}"),
        }
        assert!(result.is_rejected());
    }

    // -- Rejection: invalid member id --

    #[test]
    fn zero_member_id_rejected() {
        let mut handler = coordinator_handler();
        let result =
            handler.handle_join_request(MemberId::ZERO, Incarnation::ZERO, EpochId::new(0));
        match &result {
            JoinHandlerResult::Rejected(JoinRejectionReason::InvalidMemberId) => {}
            other => panic!("expected InvalidMemberId, got {other:?}"),
        }
    }

    // -- Rejection: already member --

    #[test]
    fn already_member_rejected() {
        let mut handler = coordinator_handler();
        let result = handler.handle_join_request(member(1), Incarnation::ZERO, EpochId::new(0));
        match &result {
            JoinHandlerResult::Rejected(JoinRejectionReason::AlreadyMember) => {}
            other => panic!("expected AlreadyMember, got {other:?}"),
        }
    }

    #[test]
    fn already_member_different_epoch() {
        let mut handler = coordinator_handler();
        let result = handler.handle_join_request(member(2), Incarnation::ZERO, EpochId::new(99));
        match &result {
            JoinHandlerResult::Rejected(JoinRejectionReason::AlreadyMember) => {}
            other => panic!("expected AlreadyMember, got {other:?}"),
        }
    }

    // -- Rejection: stale incarnation --

    #[test]
    fn stale_incarnation_rejected() {
        let mut handler = JoinHandler::new(
            member(1),
            true,
            vec![member(1)],
            default_constraints(),
            IncarnationTracker::new(Incarnation(5)),
        );
        let result = handler.handle_join_request(member(2), Incarnation(3), EpochId::new(0));
        match &result {
            JoinHandlerResult::Rejected(JoinRejectionReason::StaleIncarnation {
                msg_incarnation,
                current_incarnation,
            }) => {
                assert_eq!(*msg_incarnation, Incarnation(3));
                assert_eq!(*current_incarnation, Incarnation(5));
            }
            other => panic!("expected StaleIncarnation, got {other:?}"),
        }
    }

    // -- Rejection: roster constraint violation --

    #[test]
    fn roster_full_rejected() {
        let constraints = RosterConstraints::new(2, 1);
        let mut handler = JoinHandler::new(
            member(1),
            true,
            vec![member(1), member(2)],
            constraints,
            IncarnationTracker::genesis(),
        );
        let result = handler.handle_join_request(member(3), Incarnation::ZERO, EpochId::new(0));
        assert!(matches!(
            result,
            JoinHandlerResult::Rejected(JoinRejectionReason::ConstraintViolation(
                ConstraintValidationError::TooManyPeers,
            ))
        ));
    }

    // -- Duplicate-in-flight detection --

    #[test]
    fn duplicate_in_flight_rejected() {
        let mut handler = coordinator_handler();
        let r1 = handler.handle_join_request(member(3), Incarnation::ZERO, EpochId::new(0));
        assert!(r1.is_accepted());
        assert_eq!(handler.pending_count(), 1);
        let r2 = handler.handle_join_request(member(3), Incarnation::ZERO, EpochId::new(0));
        assert!(matches!(
            r2,
            JoinHandlerResult::Rejected(JoinRejectionReason::JoinInProgress)
        ));
    }

    #[test]
    fn completed_join_frees_slot() {
        let mut handler = coordinator_handler();
        let _ = handler.handle_join_request(member(3), Incarnation::ZERO, EpochId::new(0));
        assert_eq!(handler.pending_count(), 1);
        handler.complete_join(member(3));
        assert_eq!(handler.pending_count(), 0);
        let r = handler.handle_join_request(member(3), Incarnation::ZERO, EpochId::new(1));
        assert!(r.is_accepted());
        assert_eq!(handler.pending_count(), 1);
    }

    // -- Idempotent resubmission --

    #[test]
    fn idempotent_resubmission_returns_same_proposal() {
        let mut handler = coordinator_handler();
        let r1 =
            handler.handle_join_request_idempotent(member(3), Incarnation::ZERO, EpochId::new(5));
        let p1 = match r1 {
            JoinHandlerResult::Accepted(p) => p.clone(),
            other => panic!("expected Accepted, got {other:?}"),
        };
        let r2 =
            handler.handle_join_request_idempotent(member(3), Incarnation::ZERO, EpochId::new(5));
        match r2 {
            JoinHandlerResult::Accepted(p) => {
                assert_eq!(p, p1);
                assert_eq!(p.idempotency_key, p1.idempotency_key);
            }
            other => panic!("expected idempotent Accepted, got {other:?}"),
        }
        assert_eq!(handler.pending_count(), 1);
    }

    #[test]
    fn idempotent_does_not_bypass_validation_for_new_peer() {
        let mut handler = coordinator_handler();
        let _ = handler.handle_join_request(member(3), Incarnation::ZERO, EpochId::new(0));
        let r =
            handler.handle_join_request_idempotent(member(4), Incarnation::ZERO, EpochId::new(1));
        assert!(r.is_accepted());
        assert_eq!(handler.pending_count(), 2);
    }

    // -- Accessor tests --

    #[test]
    fn accessor_self_id() {
        let handler = coordinator_handler();
        assert_eq!(handler.self_id(), member(1));
    }

    #[test]
    fn accessor_is_coordinator() {
        let h1 = coordinator_handler();
        let h2 = non_coordinator_handler();
        assert!(h1.is_coordinator());
        assert!(!h2.is_coordinator());
    }

    #[test]
    fn accessor_roster() {
        let handler = coordinator_handler();
        assert_eq!(handler.roster(), &[member(1), member(2)]);
    }

    #[test]
    fn accessor_current_incarnation() {
        let handler = coordinator_handler();
        assert_eq!(handler.current_incarnation(), Incarnation::ZERO);
    }

    // -- Mutator tests --

    #[test]
    fn set_coordinator_toggle() {
        let mut handler = non_coordinator_handler();
        assert!(!handler.is_coordinator());
        handler.set_coordinator(true);
        assert!(handler.is_coordinator());
        handler.set_coordinator(false);
        assert!(!handler.is_coordinator());
    }

    #[test]
    fn set_roster_updates_list() {
        let mut handler = coordinator_handler();
        handler.set_roster(vec![member(1), member(2), member(3)]);
        assert_eq!(handler.roster(), &[member(1), member(2), member(3)]);
    }

    #[test]
    fn set_incarnation_tracker_updates() {
        let mut handler = coordinator_handler();
        assert_eq!(handler.current_incarnation(), Incarnation::ZERO);
        let new_tracker = IncarnationTracker::new(Incarnation(42));
        handler.set_incarnation_tracker(new_tracker);
        assert_eq!(handler.current_incarnation(), Incarnation(42));
    }

    #[test]
    fn clear_pending_empties() {
        let mut handler = coordinator_handler();
        let _ = handler.handle_join_request(member(3), Incarnation::ZERO, EpochId::new(0));
        let _ = handler.handle_join_request(member(4), Incarnation::ZERO, EpochId::new(0));
        assert_eq!(handler.pending_count(), 2);
        handler.clear_pending();
        assert_eq!(handler.pending_count(), 0);
    }

    // -- Rejection reason display --

    #[test]
    fn rejection_reason_display_is_human_readable() {
        let reasons = [
            (
                JoinRejectionReason::NotCoordinator,
                "not the current coordinator",
            ),
            (
                JoinRejectionReason::AlreadyMember,
                "already a cluster member",
            ),
            (JoinRejectionReason::JoinInProgress, "already in progress"),
            (
                JoinRejectionReason::ConstraintViolation(ConstraintValidationError::TooManyPeers),
                "would exceed max peers",
            ),
            (
                JoinRejectionReason::StaleIncarnation {
                    msg_incarnation: Incarnation(2),
                    current_incarnation: Incarnation(5),
                },
                "stale incarnation",
            ),
            (JoinRejectionReason::InvalidMemberId, "invalid member id"),
        ];
        for (reason, expected_substr) in &reasons {
            let msg = reason.to_string();
            assert!(
                msg.contains(expected_substr),
                "expected '{expected_substr}' in '{msg}' for {reason:?}"
            );
        }
    }

    #[test]
    fn join_proposal_clone_and_debug() {
        let proposal = JoinProposal {
            joining_peer: member(42),
            join_epoch: EpochId::new(7),
            idempotency_key: JoinIdempotencyKey::derive(member(42), EpochId::new(7)),
        };
        let cloned = proposal.clone();
        assert_eq!(proposal, cloned);
        let s = format!("{proposal:?}");
        assert!(s.contains("42"));
        assert!(s.contains("7"));
    }

    #[test]
    fn incarnation_increment_rejects_old_messages() {
        let mut tracker = IncarnationTracker::genesis();
        tracker.increment();
        let mut handler = JoinHandler::new(
            member(1),
            true,
            vec![member(1)],
            default_constraints(),
            tracker,
        );
        let result = handler.handle_join_request(member(2), Incarnation::ZERO, EpochId::new(0));
        assert!(matches!(
            result,
            JoinHandlerResult::Rejected(JoinRejectionReason::StaleIncarnation { .. })
        ));
        let result = handler.handle_join_request(member(2), Incarnation(1), EpochId::new(0));
        assert!(result.is_accepted());
    }
}
