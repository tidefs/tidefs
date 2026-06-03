//! Roster-change notification broadcast to connected peers.
//!
//! When a new peer completes the join handshake and is added to the roster,
//! [`RosterNotifier::notify_peer_joined`] broadcasts a
//! [`MembershipOutboundMessage::PeerJoined`] notification to all
//! currently-connected cluster members via their transport sessions.
//!
//! ## Architecture
//!
//! ```text
//! PeerJoinHandshake completes
//!        |
//!        v
//! RosterNotifier::notify_peer_joined(peer_id, roster_epoch)
//!        |
//!        +-- snapshot roster of active peers
//!        +-- construct MembershipOutboundMessage::PeerJoined { peer_id, roster_epoch }
//!        +-- for each active peer except the joining peer:
//!        |     +-- call OutboundDispatch::send_to_peer(peer, msg.clone())
//!        |     +-- log errors, continue on failure (partial-failure tolerant)
//!        +-- return NotifyResult { success_count, error_count }
//! ```
//!
//! ## Integration
//!
//! The membership runtime creates a [`RosterNotifier`] during initialization
//! with a reference to the [`MembershipOutboundDispatch`] and the
//! [`MembershipRoster`]. After the [`PeerJoinHandshake`] accepts a new peer,
//! the runtime calls `notify_peer_joined` to inform existing members.
//!
//! ## Failure tolerance
//!
//! An unreachable peer does not block broadcast to remaining peers.
//! Individual send failures are logged and the broadcast continues.
//! The caller receives a [`NotifyResult`] with counts for success and
//! error, enabling monitoring without aborting the join flow.
//!
//! ## Stale-notification avoidance
//!
//! Notifications carry an optional send deadline via the
//! [`tidefs_transport::send_deadline`] infrastructure (#6115).
//! When the deadline is configured, stale notifications that cannot
//! be delivered within the deadline window are cancelled at the
//! transport layer.

use std::fmt;

use tidefs_membership_epoch::{EpochId, MemberId};

use crate::membership_outbound_dispatch::{
    MembershipOutboundDispatch, MembershipOutboundMessage, OutboundDispatchError,
};
use crate::roster::{MembershipRoster, RosterState};

// ---------------------------------------------------------------------------
// RosterNotifier — broadcast peer-joined notifications
// ---------------------------------------------------------------------------

/// Broadcasts peer-join notifications to all connected cluster members.
///
/// Created during membership runtime initialization with a reference to the
/// outbound dispatch bridge. Called after a peer completes the join handshake
/// to inform existing members about the new peer without polling.
pub struct RosterNotifier<'a> {
    dispatch: &'a MembershipOutboundDispatch<'a>,
    roster: &'a MembershipRoster,
}

impl<'a> RosterNotifier<'a> {
    /// Create a new roster notifier.
    pub fn new(dispatch: &'a MembershipOutboundDispatch<'a>, roster: &'a MembershipRoster) -> Self {
        Self { dispatch, roster }
    }

    /// Broadcast a peer-joined notification to all active connected peers.
    ///
    /// Constructs a [`MembershipOutboundMessage::PeerJoined`] message and
    /// fans it out to every active roster member except `joining_peer_id`.
    /// Uses [`MembershipOutboundDispatch::send_to_peer`] to reuse existing
    /// transport sessions rather than opening new connections.
    ///
    /// # Partial-failure tolerance
    ///
    /// If an individual peer is unreachable (e.g. its transport session has
    /// been torn down), the send failure is recorded and the broadcast
    /// continues to remaining peers. This prevents one unreachable member
    /// from blocking notification delivery to all others.
    ///
    /// # Returns
    ///
    /// A [`NotifyResult`] with success and error counts. The caller can
    /// inspect the result to log or alert on widespread delivery failures.
    pub fn notify_peer_joined(
        &self,
        joining_peer_id: MemberId,
        roster_epoch: EpochId,
    ) -> NotifyResult {
        let snapshot = self.roster.snapshot();
        let message = MembershipOutboundMessage::PeerJoined {
            member_id: joining_peer_id,
            roster_epoch,
        };

        let mut success_count = 0usize;
        let mut errors = Vec::new();

        for (member_id, state) in snapshot.iter() {
            // Skip the joining peer — they already know they joined.
            if *member_id == joining_peer_id {
                continue;
            }
            // Only notify active peers.
            if *state != RosterState::Active {
                continue;
            }

            match self.dispatch.send_to_peer(*member_id, message.clone()) {
                Ok(()) => success_count += 1,
                Err(e) => errors.push((*member_id, e)),
            }
        }

        NotifyResult::new(success_count, errors)
    }
}

// ---------------------------------------------------------------------------
// NotifyResult
// ---------------------------------------------------------------------------

/// Outcome of a roster notification broadcast.
///
/// A partially successful broadcast delivers to some peers and records
/// per-peer errors for the rest.
#[derive(Debug, Clone)]
pub struct NotifyResult {
    /// Number of peers that received the notification.
    pub success_count: usize,
    /// Per-peer errors for peers that did not receive the notification.
    pub errors: Vec<(MemberId, OutboundDispatchError)>,
}

impl NotifyResult {
    /// Create a new notify result.
    pub fn new(success_count: usize, errors: Vec<(MemberId, OutboundDispatchError)>) -> Self {
        Self {
            success_count,
            errors,
        }
    }

    /// Whether every active peer (excluding the joining peer) received
    /// the notification.
    pub fn all_succeeded(&self) -> bool {
        self.errors.is_empty()
    }

    /// Whether no peer received the notification.
    pub fn all_failed(&self) -> bool {
        self.success_count == 0 && !self.errors.is_empty()
    }
}

impl fmt::Display for NotifyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "peer-joined notify: {} succeeded, {} errors",
            self.success_count,
            self.errors.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::membership_outbound_dispatch::MembershipOutboundMessage;
    use crate::roster::{MembershipRoster, RosterState};
    use tidefs_membership_epoch::{EpochId, MemberId};
    use tidefs_transport::envelope::MessageFamily;

    // ------------------------------------------------------------------
    // Test helpers
    // ------------------------------------------------------------------

    // We test RosterNotifier logic in isolation by verifying the
    // roster-iteration, exclusion, and state-filtering behaviour
    // against real MembershipRoster objects. Integration through
    // MembershipOutboundDispatch is validated by the existing
    // outbound dispatch test suite.

    // ------------------------------------------------------------------
    // NotifyResult tests
    // ------------------------------------------------------------------

    #[test]
    fn notify_result_all_succeeded_when_no_errors() {
        let result = NotifyResult::new(3, vec![]);
        assert!(result.all_succeeded());
        assert!(!result.all_failed());
    }

    #[test]
    fn notify_result_partial_success() {
        let result = NotifyResult::new(
            2,
            vec![(
                MemberId::new(3),
                OutboundDispatchError::NoTransportQueue {
                    member_id: MemberId::new(3),
                    peer_id: 3,
                },
            )],
        );
        assert!(!result.all_succeeded());
        assert!(!result.all_failed());
    }

    #[test]
    fn notify_result_all_failed() {
        let result = NotifyResult::new(
            0,
            vec![(
                MemberId::new(2),
                OutboundDispatchError::NoTransportQueue {
                    member_id: MemberId::new(2),
                    peer_id: 2,
                },
            )],
        );
        assert!(result.all_failed());
        assert!(!result.all_succeeded());
    }

    #[test]
    fn notify_result_display() {
        let result = NotifyResult::new(3, vec![]);
        let s = format!("{result}");
        assert!(s.contains("3 succeeded"));
        assert!(s.contains("0 errors"));
    }

    // ------------------------------------------------------------------
    // RosterNotifier tests (integration with real roster)
    // ------------------------------------------------------------------

    /// Build a roster with the given members all in Active state.
    fn build_roster(member_ids: &[u64]) -> MembershipRoster {
        let mut roster = MembershipRoster::new();
        for &id in member_ids {
            roster.add_member(MemberId::new(id));
        }
        roster
    }

    /// Build a roster with mixed states.
    fn build_mixed_roster() -> MembershipRoster {
        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(1)); // Active
        roster.add_member(MemberId::new(2)); // Active
        roster.add_member(MemberId::new(3)); // Active -> make Suspected
        roster.add_member(MemberId::new(4)); // Active -> Suspected -> Failed
        roster.add_member(MemberId::new(5)); // Active -> make Left
        let _ = roster.transition_state(MemberId::new(3), RosterState::Suspected);
        // Active -> Failed is illegal; go Active -> Suspected -> Failed
        let _ = roster.transition_state(MemberId::new(4), RosterState::Suspected);
        let _ = roster.transition_state(MemberId::new(4), RosterState::Failed);
        let _ = roster.transition_state(MemberId::new(5), RosterState::Left);
        roster
    }

    #[test]
    fn notifier_excludes_joining_peer() {
        // The notifier logic iterates the roster and skips the joining peer.
        // We verify this by constructing a roster and checking the skip
        // is implemented — tested via the integration test below.
        //
        // This test validates that the exclusion check (`*member_id == joining_peer_id`)
        // compiles and the type comparison works.
        let roster = build_roster(&[10, 20, 30]);
        let joining = MemberId::new(10);
        let snapshot = roster.snapshot();
        let mut would_notify: Vec<MemberId> = Vec::new();
        for (mid, state) in snapshot.iter() {
            if *mid == joining || *state != RosterState::Active {
                continue;
            }
            would_notify.push(*mid);
        }
        // Should only notify peers 20, 30 — not 10
        assert_eq!(would_notify.len(), 2);
        assert!(!would_notify.contains(&MemberId::new(10)));
        assert!(would_notify.contains(&MemberId::new(20)));
        assert!(would_notify.contains(&MemberId::new(30)));
    }

    #[test]
    fn notifier_skips_non_active_peers() {
        let roster = build_mixed_roster();
        let joining = MemberId::new(99); // not in roster
        let snapshot = roster.snapshot();
        let mut would_notify: Vec<MemberId> = Vec::new();
        for (mid, state) in snapshot.iter() {
            if *mid == joining || *state != RosterState::Active {
                continue;
            }
            would_notify.push(*mid);
        }
        // Only peers 1 and 2 are Active; 3=Suspected, 4=Failed, 5=Left
        assert_eq!(would_notify.len(), 2);
        assert!(would_notify.contains(&MemberId::new(1)));
        assert!(would_notify.contains(&MemberId::new(2)));
    }

    #[test]
    fn notifier_empty_roster() {
        let roster = MembershipRoster::new();
        let joining = MemberId::new(1);
        let snapshot = roster.snapshot();
        let mut would_notify = 0usize;
        for (mid, state) in snapshot.iter() {
            if *mid == joining || *state != RosterState::Active {
                continue;
            }
            would_notify += 1;
        }
        assert_eq!(would_notify, 0);
    }

    #[test]
    fn notifier_joiner_is_only_active_member() {
        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(1));
        let joining = MemberId::new(1);
        let snapshot = roster.snapshot();
        let mut would_notify = 0usize;
        for (mid, state) in snapshot.iter() {
            if *mid == joining || *state != RosterState::Active {
                continue;
            }
            would_notify += 1;
        }
        assert_eq!(
            would_notify, 0,
            "no peers to notify when joiner is the only member"
        );
    }

    #[test]
    fn notifier_constructs_correct_peer_joined_message() {
        let joining_id = MemberId::new(42);
        let epoch = EpochId::new(7);
        let msg = MembershipOutboundMessage::PeerJoined {
            member_id: joining_id,
            roster_epoch: epoch,
        };
        assert_eq!(msg.variant_name(), "PeerJoined");
        assert_eq!(msg.message_family(), MessageFamily::PublicationProgress);

        // Verify clone and Eq
        let msg2 = msg.clone();
        assert_eq!(msg, msg2);
    }

    // ------------------------------------------------------------------
    // Integration tests with real SendDispatcher
    // ------------------------------------------------------------------

    use tidefs_transport::send_dispatch::{SendDispatcher, SendQueueConfig};
    use tidefs_transport::ErrorClassifier;

    /// Full integration: notify_peer_joined fans out PeerJoined messages
    /// to all active peers except the joining peer through a real
    /// SendDispatcher transport pipeline.
    #[test]
    fn notify_peer_joined_fans_out_to_active_peers() {
        let config = SendQueueConfig::new(256, 1_048_576).unwrap();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier, None);

        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(1));
        roster.add_member(MemberId::new(2));
        roster.add_member(MemberId::new(3));

        let dispatch = MembershipOutboundDispatch::new(&dispatcher, &roster);
        let notifier = RosterNotifier::new(&dispatch, &roster);

        let joining_id = MemberId::new(3);
        let epoch = EpochId::new(7);
        let result = notifier.notify_peer_joined(joining_id, epoch);

        // Should notify peers 1 and 2, skip peer 3 (the joiner).
        assert_eq!(result.success_count, 2);
        assert!(result.all_succeeded());
        assert!(!result.all_failed());

        // Peer 1 received the message.
        let q1 = dispatcher.queue(1).expect("queue for peer 1 should exist");
        assert_eq!(q1.depth(), 1);
        let drained = q1.dequeue().expect("peer 1 should have message");
        let msg1: MembershipOutboundMessage = bincode::deserialize(&drained.payload).unwrap();
        assert_eq!(
            msg1,
            MembershipOutboundMessage::PeerJoined {
                member_id: joining_id,
                roster_epoch: epoch,
            }
        );

        // Peer 2 received the message.
        let q2 = dispatcher.queue(2).expect("queue for peer 2 should exist");
        assert_eq!(q2.depth(), 1);
        let msg2: MembershipOutboundMessage =
            bincode::deserialize(&q2.dequeue().unwrap().payload).unwrap();
        assert_eq!(msg2, msg1);

        // Peer 3 (joining) should NOT have a queue.
        assert!(dispatcher.queue(3).is_none());
    }

    /// When the roster has only the joining peer, no notifications are sent
    /// and the result reflects that.
    #[test]
    fn notify_peer_joined_single_member_no_peers_to_notify() {
        let config = SendQueueConfig::new(256, 1_048_576).unwrap();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier, None);

        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(1));

        let dispatch = MembershipOutboundDispatch::new(&dispatcher, &roster);
        let notifier = RosterNotifier::new(&dispatch, &roster);

        let result = notifier.notify_peer_joined(MemberId::new(1), EpochId::new(1));
        assert_eq!(result.success_count, 0);
        assert!(result.errors.is_empty());
    }

    /// When the roster has multiple peers but some are in non-Active states,
    /// only the Active peers receive the notification.
    #[test]
    fn notify_peer_joined_skips_non_active_peers_in_dispatcher() {
        let config = SendQueueConfig::new(256, 1_048_576).unwrap();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier, None);

        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(1)); // Active
        roster.add_member(MemberId::new(2)); // Active -> Suspected
        roster.add_member(MemberId::new(3)); // Active
        roster.add_member(MemberId::new(4)); // Active -> Left
        let _ = roster.transition_state(MemberId::new(2), RosterState::Suspected);
        let _ = roster.transition_state(MemberId::new(4), RosterState::Left);

        let dispatch = MembershipOutboundDispatch::new(&dispatcher, &roster);
        let notifier = RosterNotifier::new(&dispatch, &roster);

        let joining_id = MemberId::new(5); // not in roster — unrelated
        let result = notifier.notify_peer_joined(joining_id, EpochId::new(1));

        // Only peers 1 and 3 are Active — they should get the message.
        assert_eq!(result.success_count, 2);
        assert!(result.all_succeeded());

        assert_eq!(dispatcher.queue(1).unwrap().depth(), 1);
        assert_eq!(dispatcher.queue(3).unwrap().depth(), 1);

        // Peer 2 (Suspected) and Peer 4 (Left) should NOT have queues.
        assert!(dispatcher.queue(2).is_none());
        assert!(dispatcher.queue(4).is_none());
    }
}
