// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Coordinator-side departure handler for quorum-confirmed peer removal.
//!
//! [`DepartureCoordinator`] receives a [`DepartureRequest`] from a peer
//! (or an eviction trigger from the operator), validates it against the
//! current roster via [`super::leave_coordinator::LeaveCoordinator`],
//! proposes the roster removal through
//! [`super::membership_quorum_tracker::MembershipQuorumTracker`],
//! commits the transition through
//! [`super::transition_journal::MembershipTransitionJournal`],
//! and advances the epoch.
//!
//! ## Lifecycle
//!
//! ```text
//! handle_departure_request(peer_id, reason)
//!   |
//!   +-- validate through LeaveCoordinator
//!   |     +-- rejected → return DepartureOutcome::Rejected
//!   |
//!   +-- prepare transition journal entry (Leave)
//!   +-- create MembershipQuorumTracker with roster change proposal
//!   +-- broadcast proposal to peers
//!   |
//!   +-- on quorum committed:
//!   |     +-- commit transition journal entry
//!   |     +-- advance epoch (remove peer from roster)
//!   |     +-- trigger session teardown for departed peer
//!   |
//!   +-- on quorum rejected / timeout:
//!         +-- abort transition journal entry
//!         +-- return DepartureOutcome::Rejected
//! ```
//!
//! ## Eviction path
//!
//! Eviction is coordinator-initiated without a peer-side state machine:
//! the coordinator calls `initiate_eviction(peer_id, reason)` directly.
//! The coordinator validates via the same `LeaveCoordinator` path and
//! proposes the removal through the quorum tracker.

use std::collections::HashMap;

use crate::coordinator_promotion::CoordinatorChanged;
use crate::leave_coordinator::{LeaveCoordinator, LeaveNotificationPayload};
use crate::membership_quorum_tracker::{
    MembershipQuorumTracker, QuorumOutcome, QuorumTrackerError,
};
use crate::transition_journal::{MembershipTransitionJournal, TransitionId, TransitionKind};
use crate::{EpochId, LeaveOutcome, LeaveReason, MemberId};
use tidefs_membership_types::departure::DepartureResponse;
use tidefs_membership_types::RosterChangeProposal;

// ---------------------------------------------------------------------------
// DepartureCoordinator
// ---------------------------------------------------------------------------

/// Coordinates quorum-confirmed peer departure on the coordinator side.
///
/// Wraps the existing [`LeaveCoordinator`], [`MembershipQuorumTracker`],
/// and [`MembershipTransitionJournal`] to provide a unified departure
/// protocol with quorum voting and crash-recovery journaling.
#[derive(Debug, Clone)]
pub struct DepartureCoordinator {
    /// The internal leave coordinator for validation and successor computation.
    pub leave_coordinator: LeaveCoordinator,
    /// Transition journal for crash-recovery durability.
    pub journal: MembershipTransitionJournal,
    /// Map of active quorum trackers by proposal id.
    active_proposals: HashMap<u64, PendingDeparture>,
    /// Next proposal id.
    next_proposal_id: u64,
}

/// An in-flight departure tracked through the coordinator.
#[derive(Debug, Clone)]
struct PendingDeparture {
    /// The quorum tracker for this departure proposal.
    pub tracker: MembershipQuorumTracker,
    /// The transition journal entry id for crash recovery.
    pub journal_entry_id: TransitionId,
    /// Whether the journal entry has been committed.
    pub journal_committed: bool,
    /// The notification payload for broadcast on commit.
    pub notification: LeaveNotificationPayload,
    /// Successor member set (excluding departing peer).
    pub successor_member_set: Vec<u64>,
    /// Coordinator promotion info if the departing peer was coordinator.
    pub coordinator_changed: Option<CoordinatorChanged>,
}

impl DepartureCoordinator {
    /// Create a new departure coordinator.
    #[must_use]
    pub fn new(leave_coordinator: LeaveCoordinator) -> Self {
        Self {
            leave_coordinator,
            journal: MembershipTransitionJournal::new(),
            active_proposals: HashMap::new(),
            next_proposal_id: 1,
        }
    }

    /// Create with an existing journal (e.g. after crash recovery).
    #[must_use]
    pub fn with_journal(
        leave_coordinator: LeaveCoordinator,
        journal: MembershipTransitionJournal,
    ) -> Self {
        Self {
            leave_coordinator,
            journal,
            active_proposals: HashMap::new(),
            next_proposal_id: 1,
        }
    }

    /// Handle a voluntary departure request from a peer.
    ///
    /// Validates the request through the `LeaveCoordinator`, journals the
    /// transition, creates a quorum tracker, and returns the proposal id
    /// and response to send back to the peer.
    ///
    /// Returns `None` if validation fails (the reason is in the response).
    #[must_use]
    pub fn handle_departure_request(
        &mut self,
        peer_id: u64,
        reason: LeaveReason,
        now_millis: u64,
    ) -> (DepartureResponse, Option<u64>) {
        let member_id = MemberId::new(peer_id);
        let result = self.leave_coordinator.validate_leave(member_id, reason);

        match result.outcome {
            LeaveOutcome::Accepted => {
                let notification = result.notification.clone().unwrap();
                let successor_member_set: Vec<u64> =
                    result.successor_member_set.iter().map(|m| m.0).collect();

                // Journal the transition.
                let journal_entry_id = self.journal.record_prepare(
                    TransitionKind::Leave {
                        peer_id: member_id,
                        epoch: self.leave_coordinator.current_epoch,
                        reason,
                    },
                    now_millis,
                );

                // Create the quorum tracker with a roster-change proposal.
                let proposal = RosterChangeProposal {
                    proposal_id: self.next_proposal_id,
                    coordinator_id: self
                        .leave_coordinator
                        .current_coordinator
                        .map(|m| m.0)
                        .unwrap_or(0),
                    current_epoch: self.leave_coordinator.current_epoch.0,
                    added: vec![],
                    removed: vec![peer_id],
                    created_at_millis: now_millis,
                };

                let mut tracker = MembershipQuorumTracker::new(
                    proposal.clone(),
                    successor_member_set.clone(),
                    30_000, // 30s quorum timeout
                );
                tracker.set_created_at(now_millis);

                let proposal_id = self.next_proposal_id;
                self.next_proposal_id += 1;

                self.active_proposals.insert(
                    proposal_id,
                    PendingDeparture {
                        tracker,
                        journal_entry_id,
                        journal_committed: false,
                        notification,
                        successor_member_set,
                        coordinator_changed: result.coordinator_changed,
                    },
                );

                let response = DepartureResponse {
                    peer_id,
                    accepted: true,
                    successor_epoch: result.successor_epoch.0,
                    reject_reason: None,
                };
                (response, Some(proposal_id))
            }
            LeaveOutcome::Rejected | LeaveOutcome::AlreadyDeparted => {
                let response = DepartureResponse {
                    peer_id,
                    accepted: false,
                    successor_epoch: result.successor_epoch.0,
                    reject_reason: result.rejected_reason.clone(),
                };
                (response, None)
            }
        }
    }

    /// Receive a quorum vote for a pending departure proposal.
    ///
    /// When quorum is reached, the transition journal entry is committed
    /// and the proposal is ready for epoch advancement.
    pub fn receive_vote(
        &mut self,
        proposal_id: u64,
        voter_id: u64,
        accepted: bool,
        now_millis: u64,
    ) -> Result<QuorumOutcome, QuorumTrackerError> {
        use tidefs_membership_types::RosterChangeVote;

        let pending = self.active_proposals.get_mut(&proposal_id).ok_or(
            QuorumTrackerError::ProposalIdMismatch {
                expected: 0,
                received: proposal_id,
            },
        )?;

        let vote = RosterChangeVote {
            proposal_id,
            voter_id,
            accepted,
            reject_reason: None,
            voted_at_millis: now_millis,
        };

        let outcome = pending.tracker.receive_vote(&vote)?;

        if let QuorumOutcome::Committed { .. } = &outcome {
            // Commit the journal entry.
            self.journal
                .record_commit(pending.journal_entry_id, now_millis);
            pending.journal_committed = true;
        }

        Ok(outcome)
    }

    /// Check for timeout on all pending proposals.
    ///
    /// Returns a list of (proposal_id, QuorumOutcome) for any proposals
    /// that reached a terminal state due to timeout.
    #[must_use]
    pub fn check_timeouts(&mut self, now_millis: u64) -> Vec<(u64, QuorumOutcome)> {
        let mut terminal: Vec<(u64, QuorumOutcome)> = Vec::new();
        for (id, pending) in &mut self.active_proposals {
            let outcome = pending.tracker.check_timeout(now_millis);
            match &outcome {
                QuorumOutcome::Rejected { .. } | QuorumOutcome::Committed { .. } => {
                    if matches!(&outcome, QuorumOutcome::Rejected { .. }) {
                        self.journal
                            .record_abort(pending.journal_entry_id, now_millis);
                    }
                    terminal.push((*id, outcome));
                }
                QuorumOutcome::Pending => {}
            }
        }
        terminal
    }

    /// Get the successor member set for a committed departure.
    ///
    /// Returns `None` if the proposal is not committed.
    #[must_use]
    pub fn successor_member_set(&self, proposal_id: u64) -> Option<&[u64]> {
        self.active_proposals
            .get(&proposal_id)
            .filter(|p| p.tracker.committed)
            .map(|p| p.successor_member_set.as_slice())
    }

    /// Get the leave notification payload for a committed departure.
    #[must_use]
    pub fn leave_notification(&self, proposal_id: u64) -> Option<&LeaveNotificationPayload> {
        self.active_proposals
            .get(&proposal_id)
            .filter(|p| p.tracker.committed)
            .map(|p| &p.notification)
    }

    /// Get the coordinator promotion info for a committed departure.
    #[must_use]
    pub fn coordinator_changed(&self, proposal_id: u64) -> Option<&CoordinatorChanged> {
        self.active_proposals
            .get(&proposal_id)
            .filter(|p| p.tracker.committed)
            .and_then(|p| p.coordinator_changed.as_ref())
    }

    /// Remove a terminal proposal from the active set.
    pub fn remove_proposal(&mut self, proposal_id: u64) -> bool {
        self.active_proposals.remove(&proposal_id).is_some()
    }

    /// Whether a proposal is still pending.
    #[must_use]
    pub fn is_pending(&self, proposal_id: u64) -> bool {
        self.active_proposals
            .get(&proposal_id)
            .is_some_and(|p| !p.tracker.committed && !p.tracker.aborted)
    }

    /// Initiate an eviction (coordinator-triggered departure).
    ///
    /// This is the same as `handle_departure_request` but uses
    /// `DepartureReason::Evicted`. The peer does not request this;
    /// the coordinator initiates it.
    #[must_use]
    pub fn initiate_eviction(
        &mut self,
        peer_id: u64,
        reason: LeaveReason,
        now_millis: u64,
    ) -> (DepartureResponse, Option<u64>) {
        // Eviction uses the same leave-coordinator path as voluntary departure.
        // The response is delivered to the evicted peer via epoch push.
        self.handle_departure_request(peer_id, reason, now_millis)
    }

    /// Return the current epoch.
    #[must_use]
    pub fn current_epoch(&self) -> EpochId {
        self.leave_coordinator.current_epoch
    }

    /// Finalize a committed departure by updating the LeaveCoordinator's
    /// internal state (member set, epoch, coordinator).
    ///
    /// Must be called after quorum reaches `Committed` and the journal
    /// entry has been committed. After finalization, the departed peer
    /// is removed from the roster and the epoch is advanced.
    ///
    /// Returns `true` if the proposal was found and finalized, `false`
    /// if the proposal is unknown or already removed.
    pub fn finalize_departure(&mut self, proposal_id: u64) -> bool {
        let pending = match self.active_proposals.get(&proposal_id) {
            Some(p) if p.tracker.committed && p.journal_committed => p,
            _ => return false,
        };

        let successor_ids: Vec<MemberId> = pending
            .successor_member_set
            .iter()
            .map(|&id| MemberId::new(id))
            .collect();

        self.leave_coordinator.member_set = successor_ids;
        self.leave_coordinator.current_epoch = self.leave_coordinator.current_epoch.next();
        self.leave_coordinator.current_coordinator =
            crate::coordinator_promotion::CoordinatorPromotion::current_coordinator(
                &self.leave_coordinator.member_set,
            );
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_coordinator(members: &[u64], epoch: u64) -> DepartureCoordinator {
        let member_ids: Vec<MemberId> = members.iter().map(|&id| MemberId::new(id)).collect();
        let lc = LeaveCoordinator::new(EpochId::new(epoch), member_ids);
        DepartureCoordinator::new(lc)
    }

    fn now() -> u64 {
        1_000_000
    }

    // ── Voluntary departure request ─────────────────────────────────

    #[test]
    fn handle_departure_request_accepts_valid_peer() {
        let mut coord = make_coordinator(&[1, 2, 3], 5);
        let (resp, proposal_id) = coord.handle_departure_request(2, LeaveReason::Voluntary, now());

        assert!(resp.accepted);
        assert_eq!(resp.peer_id, 2);
        assert_eq!(resp.successor_epoch, 6);
        assert!(resp.reject_reason.is_none());
        assert!(proposal_id.is_some());
    }

    #[test]
    fn handle_departure_request_rejects_non_member() {
        let mut coord = make_coordinator(&[1, 2], 5);
        let (resp, proposal_id) = coord.handle_departure_request(99, LeaveReason::Voluntary, now());

        assert!(!resp.accepted);
        assert!(resp
            .reject_reason
            .as_deref()
            .unwrap()
            .contains("not in the current roster"));
        assert!(proposal_id.is_none());
    }

    #[test]
    fn handle_departure_request_rejects_last_member() {
        let mut coord = make_coordinator(&[1], 5);
        let (resp, proposal_id) = coord.handle_departure_request(1, LeaveReason::Voluntary, now());

        assert!(!resp.accepted);
        assert!(resp
            .reject_reason
            .as_deref()
            .unwrap()
            .contains("last member"));
        assert!(proposal_id.is_none());
    }

    #[test]
    fn handle_departure_request_with_draining_reason() {
        let mut coord = make_coordinator(&[1, 2, 3, 4], 5);
        let (resp, proposal_id) = coord.handle_departure_request(3, LeaveReason::Draining, now());

        assert!(resp.accepted);
        assert!(proposal_id.is_some());
    }

    // ── Quorum voting ───────────────────────────────────────────────

    #[test]
    fn receive_vote_reaches_quorum() {
        let mut coord = make_coordinator(&[1, 2, 3], 5);
        let (_, proposal_id) = coord.handle_departure_request(2, LeaveReason::Voluntary, now());
        let pid = proposal_id.unwrap();

        // 3 members, threshold = 2. Node 1 (coordinator) and node 3 must accept.
        let outcome = coord.receive_vote(pid, 1, true, now()).unwrap();
        assert!(matches!(outcome, QuorumOutcome::Pending));

        let outcome = coord.receive_vote(pid, 3, true, now()).unwrap();
        assert!(matches!(outcome, QuorumOutcome::Committed { .. }));

        // Verify journal entry was committed.
        assert!(coord.active_proposals[&pid].journal_committed);
    }

    #[test]
    fn receive_vote_split_no_quorum() {
        let mut coord = make_coordinator(&[1, 2, 3], 5);
        let (_, proposal_id) = coord.handle_departure_request(2, LeaveReason::Voluntary, now());
        let pid = proposal_id.unwrap();

        // Only 1 accept, 1 reject; threshold=2 not met.
        coord.receive_vote(pid, 1, true, now()).unwrap();
        coord.receive_vote(pid, 3, false, now()).unwrap();
        assert!(!coord.active_proposals[&pid].tracker.committed);
        assert!(!coord.active_proposals[&pid].journal_committed);
    }

    #[test]
    fn receive_vote_wrong_proposal_id_errors() {
        let mut coord = make_coordinator(&[1, 2, 3], 5);
        let _ = coord.handle_departure_request(2, LeaveReason::Voluntary, now());
        let err = coord.receive_vote(999, 1, true, now()).unwrap_err();
        assert!(matches!(err, QuorumTrackerError::ProposalIdMismatch { .. }));
    }

    // ── Successor member set ────────────────────────────────────────

    #[test]
    fn successor_member_set_after_committed_departure() {
        let mut coord = make_coordinator(&[1, 2, 3], 5);
        let (_, proposal_id) = coord.handle_departure_request(2, LeaveReason::Voluntary, now());
        let pid = proposal_id.unwrap();

        coord.receive_vote(pid, 1, true, now()).unwrap();
        coord.receive_vote(pid, 3, true, now()).unwrap();

        let successor = coord.successor_member_set(pid).unwrap();
        assert_eq!(successor, &[1u64, 3]);
    }

    #[test]
    fn successor_member_set_none_when_not_committed() {
        let mut coord = make_coordinator(&[1, 2, 3], 5);
        let (_, proposal_id) = coord.handle_departure_request(2, LeaveReason::Voluntary, now());
        let pid = proposal_id.unwrap();

        assert!(coord.successor_member_set(pid).is_none());
    }

    // ── Leave notification ──────────────────────────────────────────

    #[test]
    fn leave_notification_after_commit() {
        let mut coord = make_coordinator(&[1, 2, 3], 5);
        let (_, proposal_id) = coord.handle_departure_request(2, LeaveReason::Voluntary, now());
        let pid = proposal_id.unwrap();

        coord.receive_vote(pid, 1, true, now()).unwrap();
        coord.receive_vote(pid, 3, true, now()).unwrap();

        let notif = coord.leave_notification(pid).unwrap();
        assert_eq!(notif.departing_member, MemberId::new(2));
        assert_eq!(notif.successor_epoch, EpochId::new(6));
        assert_eq!(notif.reason, LeaveReason::Voluntary);
    }

    // ── Eviction ────────────────────────────────────────────────────

    #[test]
    fn initiate_eviction_accepts_valid_peer() {
        let mut coord = make_coordinator(&[1, 2, 3], 5);
        let (resp, proposal_id) = coord.initiate_eviction(2, LeaveReason::Draining, now());

        assert!(resp.accepted);
        assert!(proposal_id.is_some());
    }

    #[test]
    fn initiate_eviction_rejects_non_member() {
        let mut coord = make_coordinator(&[1, 2], 5);
        let (resp, proposal_id) = coord.initiate_eviction(99, LeaveReason::Draining, now());

        assert!(!resp.accepted);
        assert!(proposal_id.is_none());
    }

    // ── Timeout ─────────────────────────────────────────────────────

    #[test]
    fn check_timeouts_aborts_stale_proposal() {
        let mut coord = make_coordinator(&[1, 2, 3], 5);
        let (_, proposal_id) = coord.handle_departure_request(2, LeaveReason::Voluntary, now());
        let pid = proposal_id.unwrap();

        // Receive 1 reject vote — with 3 members and threshold 2, we need
        // to push past timeout with rejections to make quorum unreachable.
        coord.receive_vote(pid, 1, false, now()).unwrap();
        coord.receive_vote(pid, 3, false, now()).unwrap();

        let terminal = coord.check_timeouts(now() + 50_000);
        assert!(!terminal.is_empty());
        let (id, outcome) = &terminal[0];
        assert_eq!(*id, pid);
        assert!(matches!(outcome, QuorumOutcome::Rejected { .. }));
    }

    // ── Remove proposal ─────────────────────────────────────────────

    #[test]
    fn remove_proposal_cleans_up() {
        let mut coord = make_coordinator(&[1, 2, 3], 5);
        let (_, proposal_id) = coord.handle_departure_request(2, LeaveReason::Voluntary, now());
        let pid = proposal_id.unwrap();

        assert!(coord.remove_proposal(pid));
        assert!(!coord.is_pending(pid));
        assert!(coord.successor_member_set(pid).is_none());
    }

    #[test]
    fn remove_nonexistent_proposal_returns_false() {
        let mut coord = make_coordinator(&[1, 2, 3], 5);
        assert!(!coord.remove_proposal(999));
    }

    // ── Current epoch ───────────────────────────────────────────────

    #[test]
    fn current_epoch_returns_coordinator_epoch() {
        let coord = make_coordinator(&[1, 2, 3], 42);
        assert_eq!(coord.current_epoch(), EpochId::new(42));
    }

    // ── Coordinator promotion on departure ──────────────────────────

    #[test]
    fn coordinator_promotion_when_coordinator_departs() {
        let mut coord = make_coordinator(&[1, 2, 3], 5);
        // Coordinator is node 1 (lowest id).
        let (resp, proposal_id) = coord.handle_departure_request(1, LeaveReason::Voluntary, now());

        assert!(resp.accepted);
        let pid = proposal_id.unwrap();

        coord.receive_vote(pid, 2, true, now()).unwrap();
        coord.receive_vote(pid, 3, true, now()).unwrap();

        let cc = coord.coordinator_changed(pid).unwrap();
        assert_eq!(cc.old, MemberId::new(1));
        assert_eq!(cc.new, MemberId::new(2));
    }

    #[test]
    fn no_coordinator_promotion_when_non_coordinator_departs() {
        let mut coord = make_coordinator(&[1, 2, 3], 5);
        let (resp, proposal_id) = coord.handle_departure_request(3, LeaveReason::Voluntary, now());

        assert!(resp.accepted);
        let pid = proposal_id.unwrap();

        coord.receive_vote(pid, 1, true, now()).unwrap();
        coord.receive_vote(pid, 2, true, now()).unwrap();

        assert!(coord.coordinator_changed(pid).is_none());
    }

    // ── Finalize departure ──────────────────────────────────────────

    #[test]
    fn finalize_departure_updates_leave_coordinator_state() {
        let mut coord = make_coordinator(&[1, 2, 3], 5);
        let (_, proposal_id) = coord.handle_departure_request(2, LeaveReason::Voluntary, now());
        let pid = proposal_id.unwrap();

        coord.receive_vote(pid, 1, true, now()).unwrap();
        coord.receive_vote(pid, 3, true, now()).unwrap();

        let old_epoch = coord.current_epoch();
        assert!(coord.finalize_departure(pid));

        // Epoch should be advanced.
        assert_eq!(coord.current_epoch(), EpochId::new(old_epoch.0 + 1));
        // Member 2 should be removed.
        let member_ids: Vec<u64> = coord
            .leave_coordinator
            .member_set
            .iter()
            .map(|m| m.0)
            .collect();
        assert_eq!(member_ids, vec![1, 3]);
    }

    #[test]
    fn finalize_departure_returns_false_for_unknown_proposal() {
        let mut coord = make_coordinator(&[1, 2, 3], 5);
        assert!(!coord.finalize_departure(999));
    }

    #[test]
    fn finalize_departure_returns_false_when_not_committed() {
        let mut coord = make_coordinator(&[1, 2, 3], 5);
        let (_, proposal_id) = coord.handle_departure_request(2, LeaveReason::Voluntary, now());
        let pid = proposal_id.unwrap();
        // Not voted yet — not committed.
        assert!(!coord.finalize_departure(pid));
    }
}
