// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Roster leave-notification broadcast to connected peers.
//!
//! When a peer departs the cluster gracefully, [`RosterLeaveNotifier::notify_peer_left`]
//! broadcasts a [`MembershipOutboundMessage::LeaveNotification`] to all
//! currently-connected cluster members except the departing peer.
//!
//! ## Architecture
//!
//! ```text
//! LeaveCoordinator accepts departure
//!        |
//!        v
//! RosterLeaveNotifier::notify_peer_left(peer_id, departure_epoch, reason, incarnation)
//!        |
//!        +-- snapshot roster of active peers
//!        +-- construct MembershipOutboundMessage::LeaveNotification { peer_id, ... }
//!        +-- for each active peer except the departing peer:
//!        |     +-- call OutboundDispatch::send_to_peer(peer, msg.clone())
//!        |     +-- log errors, continue on failure (partial-failure tolerant)
//!        +-- return NotifyResult { success_count, error_count }
//! ```
//!
//! ## Integration
//!
//! After a [`LeaveCoordinator`] accepts a leave request, the caller uses
//! `RosterLeaveNotifier` to broadcast the leave notification to remaining
//! peers. The membership runtime can bridge leave events to transport
//! session teardown via the existing [`RosterSessionHandle`].
//!
//! ## Failure tolerance
//!
//! Same partial-failure model as [`super::roster_notify::RosterNotifier`]:
//! unreachable peers do not block broadcast to remaining peers.
//! Individual send failures are logged.

use std::fmt;

use std::sync::{Arc, Mutex};
use tidefs_membership_epoch::transition_journal::{
    current_time_millis, MembershipTransitionJournal, TransitionKind,
};
use tidefs_membership_epoch::{EpochId, Incarnation, LeaveReason, MemberId};

use crate::membership_outbound_dispatch::{
    MembershipOutboundDispatch, MembershipOutboundMessage, OutboundDispatchError,
};
use crate::roster::{MembershipRoster, RosterState};

// ---------------------------------------------------------------------------
// RosterLeaveNotifier
// ---------------------------------------------------------------------------

/// Broadcasts peer leave notifications to all connected cluster members.
///
/// Created during membership runtime initialization with a reference to the
/// outbound dispatch bridge. Called after a leave request is accepted by
/// the [`tidefs_membership_epoch::leave_coordinator::LeaveCoordinator`] to
/// inform remaining members about the departing peer.
pub struct RosterLeaveNotifier<'a> {
    dispatch: &'a MembershipOutboundDispatch<'a>,
    roster: &'a MembershipRoster,
    /// Optional transition journal for coordinator crash-recovery replay.
    journal: Option<&'a Arc<Mutex<MembershipTransitionJournal>>>,
}

impl<'a> RosterLeaveNotifier<'a> {
    /// Create a new leave notifier.
    pub fn new(dispatch: &'a MembershipOutboundDispatch<'a>, roster: &'a MembershipRoster) -> Self {
        Self {
            dispatch,
            roster,
            journal: None,
        }
    }

    /// Attach a transition journal for crash-recovery recording.
    pub fn with_journal(
        dispatch: &'a MembershipOutboundDispatch<'a>,
        roster: &'a MembershipRoster,
        journal: &'a Arc<Mutex<MembershipTransitionJournal>>,
    ) -> Self {
        Self {
            dispatch,
            roster,
            journal: Some(journal),
        }
    }

    /// Broadcast a leave notification to all active connected peers.
    ///
    /// Constructs a [`MembershipOutboundMessage::LeaveNotification`] message and
    /// fans it out to every active roster member except `departing_peer_id`.
    ///
    /// # Partial-failure tolerance
    ///
    /// If an individual peer is unreachable, the send failure is recorded
    /// and the broadcast continues to remaining peers.
    ///
    /// # Returns
    ///
    /// A [`LeaveNotifyResult`] with success and error counts.
    pub fn notify_peer_left(
        &self,
        departing_peer_id: MemberId,
        departure_epoch: EpochId,
        reason: LeaveReason,
        incarnation: Incarnation,
    ) -> LeaveNotifyResult {
        let now_millis = current_time_millis();

        // Journal prepare: record leave intent before fan-out.
        let journal_id = self.journal.map(|j| {
            j.lock().expect("journal lock poisoned").record_prepare(
                TransitionKind::Leave {
                    peer_id: departing_peer_id,
                    epoch: departure_epoch,
                    reason,
                },
                now_millis,
            )
        });

        let snapshot = self.roster.snapshot();
        let message = MembershipOutboundMessage::LeaveNotification {
            member_id: departing_peer_id,
            departure_epoch,
            announced_at_millis: 0, // filled by transport layer
            leave_reason: reason,
            incarnation,
        };

        let mut success_count = 0usize;
        let mut errors = Vec::new();

        for (member_id, state) in snapshot.iter() {
            // Skip the departing peer.
            if *member_id == departing_peer_id {
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

        // Journal commit: mark the leave as completed after fan-out.
        if let Some(id) = journal_id {
            if let Some(j) = self.journal {
                let mut guard = j.lock().expect("journal lock poisoned");
                guard.record_commit(id, now_millis);
            }
        }

        LeaveNotifyResult::new(success_count, errors)
    }
}

// ---------------------------------------------------------------------------
// LeaveNotifyResult
// ---------------------------------------------------------------------------

/// Outcome of a leave notification broadcast.
#[derive(Debug, Clone)]
pub struct LeaveNotifyResult {
    /// Number of peers that received the notification.
    pub success_count: usize,
    /// Per-peer errors for peers that did not receive the notification.
    pub errors: Vec<(MemberId, OutboundDispatchError)>,
}

impl LeaveNotifyResult {
    /// Create a new leave notify result.
    pub fn new(success_count: usize, errors: Vec<(MemberId, OutboundDispatchError)>) -> Self {
        Self {
            success_count,
            errors,
        }
    }

    /// Whether every active peer (excluding the departing peer) received
    /// the notification.
    pub fn all_succeeded(&self) -> bool {
        self.errors.is_empty()
    }
}

impl fmt::Display for LeaveNotifyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "peer-left notify: {} succeeded, {} errors",
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
    use crate::roster::MembershipRoster;
    use tidefs_membership_epoch::{EpochId, Incarnation, LeaveReason, MemberId};
    use tidefs_transport::send_dispatch::{SendDispatcher, SendQueueConfig};
    use tidefs_transport::ErrorClassifier;

    // ------------------------------------------------------------------
    // LeaveNotifyResult tests
    // ------------------------------------------------------------------

    #[test]
    fn leave_notify_result_all_succeeded() {
        let result = LeaveNotifyResult::new(3, vec![]);
        assert!(result.all_succeeded());
    }

    #[test]
    fn leave_notify_result_partial_failure() {
        let result = LeaveNotifyResult::new(
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
    }

    #[test]
    fn leave_notify_result_display() {
        let result = LeaveNotifyResult::new(2, vec![]);
        let s = format!("{result}");
        assert!(s.contains("2 succeeded"));
        assert!(s.contains("0 errors"));
    }

    // ------------------------------------------------------------------
    // RosterLeaveNotifier integration tests
    // ------------------------------------------------------------------

    #[test]
    fn notify_peer_left_fans_out_to_active_peers() {
        let config = SendQueueConfig::new(256, 1_048_576).unwrap();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier, None);

        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(1));
        roster.add_member(MemberId::new(2));
        roster.add_member(MemberId::new(3));

        let dispatch = MembershipOutboundDispatch::new(&dispatcher, &roster);
        let notifier = RosterLeaveNotifier::new(&dispatch, &roster);

        let departing_id = MemberId::new(3);
        let result = notifier.notify_peer_left(
            departing_id,
            EpochId::new(5),
            LeaveReason::Voluntary,
            Incarnation::ZERO,
        );

        // Should notify peers 1 and 2, skip peer 3 (the departing one).
        assert_eq!(result.success_count, 2);
        assert!(result.all_succeeded());

        // Peer 1 received the message.
        let q1 = dispatcher.queue(1).expect("queue for peer 1 should exist");
        assert_eq!(q1.depth(), 1);
        let drained = q1.dequeue().expect("peer 1 should have message");
        let msg1: MembershipOutboundMessage = bincode::deserialize(&drained.payload).unwrap();
        assert_eq!(
            msg1,
            MembershipOutboundMessage::LeaveNotification {
                member_id: departing_id,
                departure_epoch: EpochId::new(5),
                announced_at_millis: 0,
                leave_reason: LeaveReason::Voluntary,
                incarnation: Incarnation::ZERO,
            }
        );

        // Peer 2 received the message.
        let q2 = dispatcher.queue(2).expect("queue for peer 2 should exist");
        assert_eq!(q2.depth(), 1);
        let msg2: MembershipOutboundMessage =
            bincode::deserialize(&q2.dequeue().unwrap().payload).unwrap();
        assert_eq!(msg2, msg1);

        // Peer 3 (departing) should NOT have a queue.
        assert!(dispatcher.queue(3).is_none());
    }

    #[test]
    fn notify_peer_left_single_member_no_peers_to_notify() {
        let config = SendQueueConfig::new(256, 1_048_576).unwrap();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier, None);

        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(1));

        let dispatch = MembershipOutboundDispatch::new(&dispatcher, &roster);
        let notifier = RosterLeaveNotifier::new(&dispatch, &roster);

        let result = notifier.notify_peer_left(
            MemberId::new(1),
            EpochId::new(1),
            LeaveReason::Maintenance,
            Incarnation::ZERO,
        );
        assert_eq!(result.success_count, 0);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn notify_peer_left_skips_non_active_peers() {
        let config = SendQueueConfig::new(256, 1_048_576).unwrap();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier, None);

        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(1)); // Active
        roster.add_member(MemberId::new(2)); // Active -> Suspected
        roster.add_member(MemberId::new(3)); // Active
        let _ = roster.transition_state(MemberId::new(2), RosterState::Suspected);

        let dispatch = MembershipOutboundDispatch::new(&dispatcher, &roster);
        let notifier = RosterLeaveNotifier::new(&dispatch, &roster);

        let result = notifier.notify_peer_left(
            MemberId::new(99), // not in roster
            EpochId::new(1),
            LeaveReason::Draining,
            Incarnation::ZERO,
        );

        // Only peers 1 and 3 are Active — they should get the message.
        assert_eq!(result.success_count, 2);
        assert!(result.all_succeeded());

        assert_eq!(dispatcher.queue(1).unwrap().depth(), 1);
        assert_eq!(dispatcher.queue(3).unwrap().depth(), 1);
        assert!(dispatcher.queue(2).is_none());
    }

    #[test]
    fn notify_peer_left_all_reasons() {
        let config = SendQueueConfig::new(256, 1_048_576).unwrap();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier, None);

        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(1));
        roster.add_member(MemberId::new(2));

        let dispatch = MembershipOutboundDispatch::new(&dispatcher, &roster);
        let notifier = RosterLeaveNotifier::new(&dispatch, &roster);

        for reason in [
            LeaveReason::Voluntary,
            LeaveReason::Maintenance,
            LeaveReason::Draining,
        ] {
            let result = notifier.notify_peer_left(
                MemberId::new(2),
                EpochId::new(3),
                reason,
                Incarnation::ZERO,
            );
            assert_eq!(result.success_count, 1);

            let msg: MembershipOutboundMessage =
                bincode::deserialize(&dispatcher.queue(1).unwrap().dequeue().unwrap().payload)
                    .unwrap();
            if let MembershipOutboundMessage::LeaveNotification { leave_reason, .. } = msg {
                assert_eq!(leave_reason, reason);
            } else {
                panic!("expected LeaveNotification, got {:?}", msg.variant_name());
            }
        }
    }
}
