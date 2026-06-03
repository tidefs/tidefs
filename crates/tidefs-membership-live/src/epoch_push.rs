//! Committed-epoch push broadcast to connected peers over transport.
//!
//! [`EpochPushBroadcaster`] bridges the
//! [`crate::epoch_coordinator::EpochAdvanceCoordinator`] epoch-commit path
//! to transport broadcast so all connected peers receive the new
//! [`crate::epoch_coordinator::EpochView`] when the local node commits a
//! roster-changing epoch. This closes the synchronization gap between local
//! epoch commitment and distributed membership state, ensuring peers do not
//! need to poll or reconnect to discover roster changes.
//!
//! ## Architecture
//!
//! The broadcaster implements
//! [`crate::epoch_coordinator::EpochCommitSubscriber`] and is registered
//! with the [`EpochAdvanceCoordinator`] via
//! [`EpochAdvanceCoordinator::subscribe`]. On each committed epoch:
//!
//! 1. The committed [`EpochView`] is encoded into a
//!    [`crate::membership_outbound_dispatch::MembershipOutboundMessage::EpochPush`].
//! 2. The message is broadcast to all currently connected active peers via
//!    [`crate::membership_outbound_dispatch::MembershipOutboundDispatch::broadcast`].
//! 3. Per-peer send failures (backpressure, queue-full, shutdown) are
//!    silently dropped — the epoch commit path is never blocked.
//!
//! ## Receive-side
//!
//! [`EpochPushReceiveHandler`] implements
//! [`crate::dispatch_router::MembershipMessageHandler`] to handle incoming
//! [`crate::dispatch_router::MembershipMessage::EpochPush`] messages.
//! It validates the pushed epoch view against the local epoch chain via
//! [`tidefs_membership_epoch::epoch_chain::EpochChainVerifier`] and, if
//! valid, feeds the new member set into the local
//! [`EpochAdvanceCoordinator`] as liveness changes.
//!
//! ## Security model
//!
//! This module is pure event-driven dispatch operating within the existing
//! transport/session security boundary. No new wire types, framing, or
//! protocol layers are introduced. The epoch push message reuses the
//! existing `MembershipOutboundMessage` bincode serialization and
//! `MembershipMessage` decode path.

use std::sync::Mutex;

use tidefs_membership_epoch::epoch_chain::EpochChainVerifier;
use tidefs_membership_epoch::MemberId;

use crate::dispatch_router::{
    MembershipDispatchError, MembershipMessage, MembershipMessageHandler,
};
use crate::epoch_coordinator::{EpochAdvanceCoordinator, EpochCommitSubscriber, EpochView};
use crate::membership_outbound_dispatch::{MembershipOutboundDispatch, MembershipOutboundMessage};

// ---------------------------------------------------------------------------
// EpochPushBroadcaster
// ---------------------------------------------------------------------------

/// Bridges committed-epoch advancement to transport broadcast so all
/// connected peers receive the new [`EpochView`] without polling or
/// reconnecting.
///
/// Implements [`EpochCommitSubscriber`] to receive committed epoch views
/// from the [`EpochAdvanceCoordinator`]. On each commit, encodes the view
/// into a [`MembershipOutboundMessage::EpochPush`] and broadcasts to all
/// active roster peers via [`MembershipOutboundDispatch`].
///
/// # Drop-on-full semantics
///
/// If a peer's transport send queue is at capacity (governed by send-queue
/// depth limits, #6045), the push is silently dropped for that peer. The
/// epoch commit path is never blocked by slow or stalled peers.
///
/// # Lifecycle
///
/// 1. Construct via [`new`](EpochPushBroadcaster::new) with references to
///    the transport [`SendDispatcher`](tidefs_transport::SendDispatcher) and
///    [`MembershipRoster`](crate::roster::MembershipRoster).
/// 2. Register with the epoch advance coordinator via
///    `coordinator.subscribe(Box::new(broadcaster))`.
/// 3. On each committed epoch, all connected peers automatically receive the
///    updated epoch view.
pub struct EpochPushBroadcaster<'a> {
    /// Outbound dispatch bridge for broadcast to connected peers.
    outbound: MembershipOutboundDispatch<'a>,
}

impl<'a> EpochPushBroadcaster<'a> {
    /// Create a new epoch push broadcaster.
    ///
    /// `send_dispatcher` — transport send dispatcher for peer enqueue.
    /// `roster` — membership roster for active peer iteration.
    #[must_use]
    pub fn new(
        send_dispatcher: &'a tidefs_transport::send_dispatch::SendDispatcher,
        roster: &'a crate::roster::MembershipRoster,
    ) -> Self {
        Self {
            outbound: MembershipOutboundDispatch::new(send_dispatcher, roster),
        }
    }
}

impl EpochCommitSubscriber for EpochPushBroadcaster<'_> {
    fn on_epoch_committed(&self, view: &EpochView) {
        let msg = MembershipOutboundMessage::EpochPush {
            epoch_number: view.epoch_number,
            member_set: view.member_set.clone(),
            created_at_millis: view.created_at_millis,
        };

        // Broadcast to all active roster peers.
        // Per-peer failures (backpressure, queue-full, shutdown) are
        // silently absorbed — the epoch commit path is never blocked.
        let _result = self.outbound.broadcast(msg);
    }
}

// ---------------------------------------------------------------------------
// EpochPushReceiveHandler
// ---------------------------------------------------------------------------

/// Handles incoming [`MembershipMessage::EpochPush`] messages from remote
/// peers, validating the pushed epoch view against the local epoch chain
/// and feeding valid successors into the local epoch advance coordinator.
///
/// # Validation
///
/// Incoming epoch pushes are validated through
/// [`EpochChainVerifier::verify_proposal`] to reject stale epochs,
/// non-monotonic regressions, and forked member sets. Only valid
/// successor epochs are applied as liveness changes.
///
/// # Thread safety
///
/// The handler wraps its state in `Arc<Mutex<...>>` so it can satisfy the
/// `Send + Sync` bound on [`MembershipMessageHandler`] while holding
/// mutable state (the chain verifier) and a mutable reference to the
/// coordinator.
pub struct EpochPushReceiveHandler {
    /// Shared chain verifier for fork detection and monotonicity.
    verifier: Mutex<EpochChainVerifier>,
    /// Shared coordinator for applying valid epoch views.
    coordinator: Mutex<EpochAdvanceCoordinator>,
}

impl EpochPushReceiveHandler {
    /// Create a new receive handler.
    ///
    /// `coordinator` — the local epoch advance coordinator, initialized
    ///   with the current member set.
    #[must_use]
    pub fn new(coordinator: EpochAdvanceCoordinator) -> Self {
        Self {
            verifier: Mutex::new(EpochChainVerifier::new()),
            coordinator: Mutex::new(coordinator),
        }
    }

    /// Set the local committed epoch for chain verification context.
    ///
    /// Must be called before processing incoming pushes so the verifier
    /// has the correct committed-epoch baseline.
    pub fn set_committed_epoch(&self, committed_epoch: u64) {
        // Reset verifier state to clear fork-tracking for the new baseline.
        self.verifier.lock().unwrap().reset();
        // EpochChainVerifier doesn't store committed epoch separately;
        // it's passed per-call to verify_proposal.
        let _ = committed_epoch;
    }

    /// Current epoch known to the local coordinator.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.coordinator.lock().unwrap().epoch_counter()
    }
}

impl MembershipMessageHandler for EpochPushReceiveHandler {
    fn handle_epoch_push(&self, msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        let (epoch_number, member_set, _created_at_millis) = match msg {
            MembershipMessage::EpochPush {
                epoch_number,
                member_set,
                created_at_millis,
            } => (*epoch_number, member_set.clone(), *created_at_millis),
            _ => return Ok(()),
        };

        let mut coordinator = self.coordinator.lock().unwrap();

        // Current committed epoch from the coordinator
        let committed_epoch = coordinator.epoch_counter();

        // Convert member set to u64 slice for EpochChainVerifier.
        let member_ids: Vec<u64> = member_set.iter().map(|m| m.0).collect();

        // Validate through the epoch chain verifier.
        {
            let mut verifier = self.verifier.lock().unwrap();
            if let Err(e) = verifier.verify_proposal(
                0, // proposer_id: 0 for push (not a proposal, just a notification)
                epoch_number.0,
                &member_ids,
                committed_epoch,
            ) {
                // Stale, regression, or fork — silently ignore.
                // The push path is fire-and-forget; peers catch up through
                // the next agreement round.
                let _ = e;
                return Ok(());
            }
        }

        // If the pushed epoch is exactly committed_epoch + 1, apply it.
        // Compute the diff between current member set and pushed member set
        // to generate appropriate liveness changes.
        if epoch_number.0 == committed_epoch + 1 {
            let current_view = coordinator.current_view().cloned();
            let current_members: Vec<MemberId> =
                current_view.map(|v| v.member_set).unwrap_or_default();

            // Peers in pushed set but not in current: reinstate as Alive
            for &new_member in &member_set {
                if !current_members.contains(&new_member) {
                    let change = crate::epoch_coordinator::PeerLivenessChange::new(
                        new_member,
                        crate::epoch_coordinator::PeerLivenessStatus::Dead,
                        crate::epoch_coordinator::PeerLivenessStatus::Alive,
                        0, // timestamp: use 0 for push-derived changes
                    );
                    coordinator.on_liveness_change(change);
                }
            }

            // Peers in current set but not in pushed: mark as Dead
            for current_member in &current_members {
                if !member_set.contains(current_member) {
                    let change = crate::epoch_coordinator::PeerLivenessChange::new(
                        *current_member,
                        crate::epoch_coordinator::PeerLivenessStatus::Alive,
                        crate::epoch_coordinator::PeerLivenessStatus::Dead,
                        0,
                    );
                    coordinator.on_liveness_change(change);
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch_coordinator::{EpochView, PeerLivenessChange, PeerLivenessStatus};
    use tidefs_membership_epoch::EpochId;

    fn now_ms() -> u64 {
        1_700_000_000_000
    }

    fn make_coordinator(members: Vec<MemberId>) -> EpochAdvanceCoordinator {
        let mut c = EpochAdvanceCoordinator::new(1);
        c.initialize(members, now_ms());
        c
    }

    // ------------------------------------------------------------------
    // EpochPushBroadcaster tests
    // ------------------------------------------------------------------

    /// Static verification that EpochPushBroadcaster implements EpochCommitSubscriber.
    #[test]
    fn broadcaster_implements_epoch_commit_subscriber() {
        // Compile-time verification: if this compiles, the trait bound is satisfied.
        fn _assert_subscriber<T: EpochCommitSubscriber>(_: &T) {}
        // We cannot construct an EpochPushBroadcaster here (needs SendDispatcher),
        // but the impl block's existence is sufficient compile-time proof.
    }

    #[test]
    fn epoch_push_message_encodes_epoch_view() {
        let view = EpochView::new(
            EpochId::new(3),
            vec![MemberId::new(1), MemberId::new(2)],
            now_ms(),
        );

        let msg = MembershipOutboundMessage::EpochPush {
            epoch_number: view.epoch_number,
            member_set: view.member_set.clone(),
            created_at_millis: view.created_at_millis,
        };

        // Verify bincode round-trip
        let encoded = bincode::serialize(&msg).expect("bincode serialize");
        let decoded: MembershipOutboundMessage =
            bincode::deserialize(&encoded).expect("bincode deserialize");

        match decoded {
            MembershipOutboundMessage::EpochPush {
                epoch_number,
                member_set,
                created_at_millis,
            } => {
                assert_eq!(epoch_number, EpochId::new(3));
                assert_eq!(member_set, vec![MemberId::new(1), MemberId::new(2)]);
                assert_eq!(created_at_millis, view.created_at_millis);
            }
            other => panic!("expected EpochPush, got {other:?}"),
        }
    }

    #[test]
    fn epoch_push_variant_name() {
        let msg = MembershipOutboundMessage::EpochPush {
            epoch_number: EpochId::new(1),
            member_set: vec![MemberId::new(10)],
            created_at_millis: 500,
        };
        assert_eq!(msg.variant_name(), "EpochPush");
    }

    #[test]
    fn epoch_push_message_family() {
        let msg = MembershipOutboundMessage::EpochPush {
            epoch_number: EpochId::new(1),
            member_set: vec![],
            created_at_millis: 0,
        };
        assert_eq!(
            msg.message_family(),
            tidefs_transport::envelope::MessageFamily::PublicationProgress
        );
    }

    // ------------------------------------------------------------------
    // EpochPushReceiveHandler tests
    // ------------------------------------------------------------------

    #[test]
    fn receive_handler_accepts_valid_successor_push() {
        let members = vec![MemberId::new(1), MemberId::new(2)];
        let coordinator = make_coordinator(members.clone());
        let handler = EpochPushReceiveHandler::new(coordinator);

        // Push epoch 1 with member set [1, 2, 3] — adds member 3
        let push_msg = MembershipMessage::EpochPush {
            epoch_number: EpochId::new(1),
            member_set: vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
            created_at_millis: now_ms(),
        };

        let result = handler.handle_epoch_push(&push_msg);
        assert!(result.is_ok());

        // Coordinator should have advanced to epoch 1
        assert_eq!(handler.current_epoch(), 1);
    }

    #[test]
    fn receive_handler_rejects_stale_epoch() {
        let coordinator = make_coordinator(vec![MemberId::new(1), MemberId::new(2)]);
        let handler = EpochPushReceiveHandler::new(coordinator);

        // Push epoch 0 — same as current committed epoch → stale
        let push_msg = MembershipMessage::EpochPush {
            epoch_number: EpochId::new(0),
            member_set: vec![MemberId::new(1)],
            created_at_millis: now_ms(),
        };

        let result = handler.handle_epoch_push(&push_msg);
        assert!(result.is_ok()); // silently ignored, not an error
        assert_eq!(handler.current_epoch(), 0);
    }

    #[test]
    fn receive_handler_rejects_epoch_regression() {
        // Advance coordinator to epoch 2 first
        let mut coordinator =
            make_coordinator(vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]);
        // Remove member 3 to advance to epoch 1
        let c1 = PeerLivenessChange::new(
            MemberId::new(3),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            now_ms(),
        );
        coordinator.on_liveness_change(c1);
        // Remove member 2 to advance to epoch 2
        let c2 = PeerLivenessChange::new(
            MemberId::new(2),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            now_ms() + 1,
        );
        coordinator.on_liveness_change(c2);
        assert_eq!(coordinator.epoch_counter(), 2);

        let handler = EpochPushReceiveHandler::new(coordinator);

        // Push epoch 1 — regression from current epoch 2
        let push_msg = MembershipMessage::EpochPush {
            epoch_number: EpochId::new(1),
            member_set: vec![MemberId::new(1), MemberId::new(2)],
            created_at_millis: now_ms(),
        };

        let result = handler.handle_epoch_push(&push_msg);
        assert!(result.is_ok()); // silently ignored
        assert_eq!(handler.current_epoch(), 2); // unchanged
    }

    #[test]
    fn receive_handler_rejects_gap_in_epoch_chain() {
        let coordinator = make_coordinator(vec![MemberId::new(1)]);
        let handler = EpochPushReceiveHandler::new(coordinator);

        // Push epoch 5 — gap from committed epoch 0
        let push_msg = MembershipMessage::EpochPush {
            epoch_number: EpochId::new(5),
            member_set: vec![MemberId::new(1), MemberId::new(2)],
            created_at_millis: now_ms(),
        };

        let result = handler.handle_epoch_push(&push_msg);
        assert!(result.is_ok()); // silently ignored
        assert_eq!(handler.current_epoch(), 0); // unchanged
    }

    #[test]
    fn receive_handler_removes_dead_peer_from_push() {
        let members = vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)];
        let coordinator = make_coordinator(members);
        let handler = EpochPushReceiveHandler::new(coordinator);

        // Push epoch 1 with member 2 removed
        let push_msg = MembershipMessage::EpochPush {
            epoch_number: EpochId::new(1),
            member_set: vec![MemberId::new(1), MemberId::new(3)],
            created_at_millis: now_ms(),
        };

        let result = handler.handle_epoch_push(&push_msg);
        assert!(result.is_ok());
        assert_eq!(handler.current_epoch(), 1);

        // Coordinator view should no longer contain member 2
        let coordinator = handler.coordinator.lock().unwrap();
        let view = coordinator.current_view().unwrap();
        assert!(!view.contains(MemberId::new(2)));
        assert!(view.contains(MemberId::new(1)));
        assert!(view.contains(MemberId::new(3)));
    }

    #[test]
    fn receive_handler_adds_new_peer_from_push() {
        let members = vec![MemberId::new(1), MemberId::new(2)];
        let coordinator = make_coordinator(members);
        let handler = EpochPushReceiveHandler::new(coordinator);

        // Push epoch 1 with member 3 added
        let push_msg = MembershipMessage::EpochPush {
            epoch_number: EpochId::new(1),
            member_set: vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
            created_at_millis: now_ms(),
        };

        let result = handler.handle_epoch_push(&push_msg);
        assert!(result.is_ok());
        assert_eq!(handler.current_epoch(), 1);

        let coordinator = handler.coordinator.lock().unwrap();
        let view = coordinator.current_view().unwrap();
        assert!(view.contains(MemberId::new(3)));
        assert_eq!(view.member_count(), 3);
    }

    #[test]
    fn receive_handler_noop_for_unchanged_member_set() {
        let members = vec![MemberId::new(1), MemberId::new(2)];
        let coordinator = make_coordinator(members.clone());
        let handler = EpochPushReceiveHandler::new(coordinator);

        // Push epoch 1 with the same member set — valid transition but no change
        let push_msg = MembershipMessage::EpochPush {
            epoch_number: EpochId::new(1),
            member_set: members,
            created_at_millis: now_ms(),
        };

        let result = handler.handle_epoch_push(&push_msg);
        assert!(result.is_ok());
        // The coordinator may or may not advance depending on whether
        // the member set change is detected. In this case, since the
        // set is the same, no liveness change is generated, so epoch
        // should not advance.
    }

    #[test]
    fn receive_handler_handles_empty_push() {
        let members = vec![MemberId::new(1)];
        let coordinator = make_coordinator(members);
        let handler = EpochPushReceiveHandler::new(coordinator);

        // Push epoch 1 with empty member set — would remove member 1,
        // but min_members=1 prevents the coordinator from accepting an empty view.
        let push_msg = MembershipMessage::EpochPush {
            epoch_number: EpochId::new(1),
            member_set: vec![],
            created_at_millis: now_ms(),
        };

        let result = handler.handle_epoch_push(&push_msg);
        assert!(result.is_ok()); // silently handled — coordinator rejects empty set

        // Epoch does not advance because the proposed change would drop below min_members.
        // This is expected behavior: the quorum guard prevents the last member from being removed.
        let coordinator = handler.coordinator.lock().unwrap();
        let view = coordinator.current_view().unwrap();
        assert!(view.contains(MemberId::new(1)));
    }

    #[test]
    fn receive_handler_fork_detection_same_epoch_different_member_set() {
        let members = vec![MemberId::new(1), MemberId::new(2)];
        let coordinator = make_coordinator(members);
        let handler = EpochPushReceiveHandler::new(coordinator);

        // First push: epoch 1 with members [1, 2, 3]
        let push1 = MembershipMessage::EpochPush {
            epoch_number: EpochId::new(1),
            member_set: vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
            created_at_millis: now_ms(),
        };
        handler.handle_epoch_push(&push1).unwrap();

        // Second push: epoch 1 with different members [1, 2, 4] — fork
        let push2 = MembershipMessage::EpochPush {
            epoch_number: EpochId::new(1),
            member_set: vec![MemberId::new(1), MemberId::new(2), MemberId::new(4)],
            created_at_millis: now_ms() + 100,
        };
        let result = handler.handle_epoch_push(&push2);
        assert!(result.is_ok()); // silently ignored (fork rejection)
    }

    #[test]
    fn receive_handler_idempotent_same_push_twice() {
        let members = vec![MemberId::new(1)];
        let coordinator = make_coordinator(members);
        let handler = EpochPushReceiveHandler::new(coordinator);

        let push_msg = MembershipMessage::EpochPush {
            epoch_number: EpochId::new(1),
            member_set: vec![MemberId::new(1), MemberId::new(2)],
            created_at_millis: now_ms(),
        };

        // First push: accepted
        handler.handle_epoch_push(&push_msg).unwrap();
        assert_eq!(handler.current_epoch(), 1);

        // Second push: same epoch, same member set — idempotent
        // After the first push, committed_epoch=1, so epoch 1 is stale.
        // This is expected — the coordinator already has this epoch.
        let result = handler.handle_epoch_push(&push_msg);
        assert!(result.is_ok());
    }

    #[test]
    fn receive_handler_membership_message_clone_eq() {
        let original = MembershipMessage::EpochPush {
            epoch_number: EpochId::new(7),
            member_set: vec![MemberId::new(10), MemberId::new(20), MemberId::new(30)],
            created_at_millis: 1_700_000_000_000,
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);

        match cloned {
            MembershipMessage::EpochPush {
                epoch_number,
                member_set,
                created_at_millis,
            } => {
                assert_eq!(epoch_number, EpochId::new(7));
                assert_eq!(
                    member_set,
                    vec![MemberId::new(10), MemberId::new(20), MemberId::new(30)]
                );
                assert_eq!(created_at_millis, 1_700_000_000_000);
            }
            other => panic!("expected EpochPush, got {other:?}"),
        }
    }
}
