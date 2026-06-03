//! Integration test: coordinator-side JoinHandler + joining-side JoinInitiator
//! two-node join handshake.

#![forbid(unsafe_code)]

use tidefs_membership_epoch::incarnation::IncarnationTracker;
use tidefs_membership_epoch::roster_constraints::RosterConstraints;
use tidefs_membership_epoch::{EpochId, Incarnation, MemberId};
use tidefs_membership_live::join_handler::{
    JoinHandler, JoinHandlerResult, JoinIdempotencyKey, JoinRejectionReason,
};
use tidefs_membership_live::join_initiator::{
    JoinInitiator, JoinInitiatorConfig, JoinInitiatorState, JoinResult,
};
use tidefs_membership_live::join_response::JoinOutcome;
use tidefs_membership_live::roster::MembershipRoster;

fn member(id: u64) -> MemberId {
    MemberId::new(id)
}

fn coordinator_handler(roster: Vec<MemberId>) -> JoinHandler {
    JoinHandler::new(
        member(1),
        true,
        roster,
        RosterConstraints::default(),
        IncarnationTracker::genesis(),
    )
}

fn accept_outcome(member_id: MemberId, epoch: EpochId, roster: Vec<MemberId>) -> JoinOutcome {
    JoinOutcome::Accepted {
        member_id,
        epoch,
        roster,
        incarnation: Incarnation::ZERO,
    }
}

#[test]
fn full_two_node_join_handshake_success() {
    let mut coordinator = coordinator_handler(vec![member(1)]);
    let mut joiner = JoinInitiator::new(JoinInitiatorConfig {
        coordinator_member_id: member(1),
        request_timeout_ms: 15_000,
        max_retries: 3,
        backoff_base_ms: 1_000,
    });
    joiner.initiate().unwrap();
    joiner.on_connected().unwrap();
    let result = coordinator.handle_join_request(member(2), Incarnation::ZERO, EpochId::new(0));
    assert!(result.is_accepted());
    assert_eq!(coordinator.pending_count(), 1);
    let outcome = accept_outcome(member(2), EpochId::new(1), vec![member(1), member(2)]);
    let r = joiner.on_response(&outcome).unwrap();
    assert!(matches!(r, JoinResult::Accepted { .. }));
    let mut roster = MembershipRoster::new();
    joiner.install_roster(&mut roster).unwrap();
    assert_eq!(roster.snapshot().len(), 2);
}

#[test]
fn non_coordinator_rejects_join() {
    let mut handler = JoinHandler::new(
        member(3),
        false,
        vec![member(1), member(2), member(3)],
        RosterConstraints::default(),
        IncarnationTracker::genesis(),
    );
    let r = handler.handle_join_request(member(4), Incarnation::ZERO, EpochId::new(0));
    assert!(matches!(
        r,
        JoinHandlerResult::Rejected(JoinRejectionReason::NotCoordinator)
    ));
}

#[test]
fn stale_incarnation_rejects_join() {
    let mut handler = JoinHandler::new(
        member(1),
        true,
        vec![member(1)],
        RosterConstraints::default(),
        IncarnationTracker::new(Incarnation(5)),
    );
    let r = handler.handle_join_request(member(2), Incarnation(2), EpochId::new(0));
    assert!(matches!(
        r,
        JoinHandlerResult::Rejected(JoinRejectionReason::StaleIncarnation { .. })
    ));
}

#[test]
fn already_member_rejects_join() {
    let mut handler = coordinator_handler(vec![member(1), member(2)]);
    let r = handler.handle_join_request(member(2), Incarnation::ZERO, EpochId::new(0));
    assert!(matches!(
        r,
        JoinHandlerResult::Rejected(JoinRejectionReason::AlreadyMember)
    ));
}

#[test]
fn roster_full_rejects_join() {
    let mut handler = JoinHandler::new(
        member(1),
        true,
        vec![member(1), member(2)],
        RosterConstraints::new(2, 1),
        IncarnationTracker::genesis(),
    );
    let r = handler.handle_join_request(member(3), Incarnation::ZERO, EpochId::new(0));
    assert!(matches!(
        r,
        JoinHandlerResult::Rejected(JoinRejectionReason::ConstraintViolation(_))
    ));
}

#[test]
fn idempotent_resubmission_returns_same_proposal() {
    let mut handler = coordinator_handler(vec![member(1)]);
    let r1 = handler.handle_join_request_idempotent(member(2), Incarnation::ZERO, EpochId::new(5));
    let p1 = match r1 {
        JoinHandlerResult::Accepted(p) => p,
        other => panic!("expected Accepted, got {other:?}"),
    };
    let r2 = handler.handle_join_request_idempotent(member(2), Incarnation::ZERO, EpochId::new(5));
    match r2 {
        JoinHandlerResult::Accepted(p) => {
            assert_eq!(p.joining_peer, p1.joining_peer);
            assert_eq!(p.idempotency_key, p1.idempotency_key);
        }
        other => panic!("expected idempotent Accepted, got {other:?}"),
    }
    assert_eq!(handler.pending_count(), 1);
}

#[test]
fn zero_member_id_rejected() {
    let mut handler = coordinator_handler(vec![member(1)]);
    let r = handler.handle_join_request(MemberId::ZERO, Incarnation::ZERO, EpochId::new(0));
    assert!(matches!(
        r,
        JoinHandlerResult::Rejected(JoinRejectionReason::InvalidMemberId)
    ));
}

#[test]
fn joiner_retries_after_rejection_then_succeeds() {
    let mut coordinator = JoinHandler::new(
        member(1),
        true,
        vec![member(1)],
        RosterConstraints::new(2, 1),
        IncarnationTracker::genesis(),
    );
    let mut joiner = JoinInitiator::new(JoinInitiatorConfig {
        coordinator_member_id: member(1),
        request_timeout_ms: 30_000,
        max_retries: 3,
        backoff_base_ms: 100,
    });
    joiner.initiate().unwrap();
    joiner.on_connected().unwrap();
    let r1 = coordinator.handle_join_request(member(2), Incarnation::ZERO, EpochId::new(0));
    assert!(r1.is_accepted());
    let reject = JoinOutcome::Rejected {
        reason: "quorum lost".into(),
    };
    joiner.on_response(&reject).unwrap();
    assert_eq!(joiner.state(), JoinInitiatorState::Idle);
    coordinator.complete_join(member(2));
    joiner.initiate().unwrap();
    joiner.on_connected().unwrap();
    let r2 = coordinator.handle_join_request(member(2), Incarnation::ZERO, EpochId::new(1));
    assert!(r2.is_accepted());
    let outcome = accept_outcome(member(2), EpochId::new(2), vec![member(1), member(2)]);
    joiner.on_response(&outcome).unwrap();
    let mut roster = MembershipRoster::new();
    joiner.install_roster(&mut roster).unwrap();
    assert_eq!(roster.snapshot().len(), 2);
}

#[test]
fn coordinator_toggle_affects_join_handler() {
    let mut handler = JoinHandler::new(
        member(1),
        false,
        vec![member(1), member(2)],
        RosterConstraints::default(),
        IncarnationTracker::genesis(),
    );
    assert!(matches!(
        handler.handle_join_request(member(3), Incarnation::ZERO, EpochId::new(0)),
        JoinHandlerResult::Rejected(JoinRejectionReason::NotCoordinator)
    ));
    handler.set_coordinator(true);
    assert!(handler
        .handle_join_request(member(3), Incarnation::ZERO, EpochId::new(0))
        .is_accepted());
}

#[test]
fn incarnation_update_rejects_stale_after_promotion() {
    let mut handler = JoinHandler::new(
        member(1),
        true,
        vec![member(1)],
        RosterConstraints::default(),
        IncarnationTracker::genesis(),
    );
    assert!(handler
        .handle_join_request(member(2), Incarnation::ZERO, EpochId::new(0))
        .is_accepted());
    handler.complete_join(member(2));
    let mut tracker = IncarnationTracker::genesis();
    tracker.increment();
    handler.set_incarnation_tracker(tracker);
    assert!(matches!(
        handler.handle_join_request(member(3), Incarnation::ZERO, EpochId::new(0)),
        JoinHandlerResult::Rejected(JoinRejectionReason::StaleIncarnation { .. })
    ));
    assert!(handler
        .handle_join_request(member(3), Incarnation(1), EpochId::new(0))
        .is_accepted());
}

#[test]
fn idempotency_key_deterministic_across_handler_instances() {
    let k1 = JoinIdempotencyKey::derive(member(42), EpochId::new(7));
    let mut handler = coordinator_handler(vec![member(1)]);
    let r = handler.handle_join_request(member(42), Incarnation::ZERO, EpochId::new(7));
    let p = match r {
        JoinHandlerResult::Accepted(p) => p,
        other => panic!("expected Accepted, got {other:?}"),
    };
    assert_eq!(p.idempotency_key, k1);
}
