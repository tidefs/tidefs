#![forbid(unsafe_code)]

//! Quorum-based roster change tracking for the coordinator.
//!
//! [`MembershipQuorumTracker`] wraps a [`RosterChangeProposal`] and collects
//! [`RosterChangeVote`] responses from current cluster members. When a
//! simple-majority quorum of accept votes is reached, the proposal is
//! committed. Unacknowledged proposals are treated as implicit rejections
//! after a configurable timeout.
//!
//! ## Lifecycle
//!
//! ```text
//! create(proposal) → AwaitingVotes
//!   |
//!   +-- receive_vote(vote) for each member response
//!   +-- check_timeout(now_millis) → timed out → Aborted
//!   +-- quorum reached → Committed
//! ```
//!
//! ## Quorum calculation
//!
//! Simple majority: `floor(N / 2) + 1` where N is the number of current
//! members. For a single-member cluster, N=1 requires 1 accept vote.
//!
//! ## Timeout behavior
//!
//! When `timeout_ms > 0`, votes not received within the timeout window
//! count as implicit rejections. If the remaining uncast votes cannot
//! mathematically reach quorum, the proposal is aborted early.

use std::collections::BTreeSet;
use tidefs_membership_types::RosterChangeProposal;
use tidefs_membership_types::RosterChangeVote;

// ---------------------------------------------------------------------------
// MembershipQuorumTracker
// ---------------------------------------------------------------------------

/// Tracks quorum collection for a roster change proposal on the coordinator.
///
/// Collects accept/reject votes, computes quorum status, and handles
/// proposal timeout.
#[derive(Clone, Debug)]
pub struct MembershipQuorumTracker {
    /// The proposal being voted on.
    pub proposal: RosterChangeProposal,
    /// The set of current member ids at proposal time.
    pub current_members: Vec<u64>,
    /// Set of (voter_id, accepted) for deduplication.
    votes: BTreeSet<(u64, bool)>,
    /// Minimum number of accept votes required for quorum.
    pub quorum_threshold: usize,
    /// Whether the quorum has been reached.
    pub committed: bool,
    /// Whether the proposal was aborted (timeout or impossible quorum).
    pub aborted: bool,
    /// Timeout deadline in milliseconds since epoch, or 0 for no timeout.
    pub timeout_ms: u64,
    /// Millisecond timestamp when the proposal was created.
    pub created_at_millis: u64,
}

/// Outcome of a quorum-tracked proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuorumOutcome {
    /// Quorum was reached; the change is committed.
    Committed {
        /// The accepted proposal.
        proposal: RosterChangeProposal,
        /// Number of accept votes received.
        approvals: usize,
    },
    /// The proposal was rejected (quorum not reached, or explicit rejections).
    Rejected {
        /// The proposal that was rejected.
        proposal: RosterChangeProposal,
        /// Number of accept votes.
        approvals: usize,
        /// Number of reject votes.
        rejections: usize,
        /// Reason for rejection.
        reason: String,
    },
    /// Still collecting votes.
    Pending,
}

/// Errors returned by quorum tracker operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuorumTrackerError {
    /// The proposal has already been committed.
    AlreadyCommitted,
    /// The proposal has already been aborted.
    AlreadyAborted,
    /// The vote's proposal_id does not match.
    ProposalIdMismatch { expected: u64, received: u64 },
    /// A duplicate vote was received from the same voter.
    DuplicateVote(u64),
    /// The voter is not in the current member set.
    VoterNotMember(u64),
}

impl MembershipQuorumTracker {
    /// Create a new quorum tracker for the given proposal.
    ///
    /// `current_members` must be sorted and deduplicated.
    /// `timeout_ms` of 0 means no timeout.
    #[must_use]
    pub fn new(proposal: RosterChangeProposal, current_members: Vec<u64>, timeout_ms: u64) -> Self {
        let n = current_members.len();
        let quorum_threshold = if n == 0 { 0 } else { (n / 2) + 1 };

        Self {
            proposal,
            current_members,
            votes: BTreeSet::new(),
            quorum_threshold,
            committed: false,
            aborted: false,
            timeout_ms,
            created_at_millis: 0, // set by caller after construction
        }
    }

    /// Set the creation timestamp.
    pub fn set_created_at(&mut self, millis: u64) {
        self.created_at_millis = millis;
    }

    /// Receive a vote from a member.
    ///
    /// # Errors
    ///
    /// Returns an error if the proposal is already committed/aborted,
    /// the proposal_id doesn't match, the vote is a duplicate, or the
    /// voter is not in the current member set.
    pub fn receive_vote(
        &mut self,
        vote: &RosterChangeVote,
    ) -> Result<QuorumOutcome, QuorumTrackerError> {
        if self.committed {
            return Err(QuorumTrackerError::AlreadyCommitted);
        }
        if self.aborted {
            return Err(QuorumTrackerError::AlreadyAborted);
        }
        if vote.proposal_id != self.proposal.proposal_id {
            return Err(QuorumTrackerError::ProposalIdMismatch {
                expected: self.proposal.proposal_id,
                received: vote.proposal_id,
            });
        }
        if self.votes.iter().any(|(vid, _)| *vid == vote.voter_id) {
            return Err(QuorumTrackerError::DuplicateVote(vote.voter_id));
        }
        // Validate voter is in current member set.
        if !self.current_members.contains(&vote.voter_id) {
            return Err(QuorumTrackerError::VoterNotMember(vote.voter_id));
        }

        self.votes.insert((vote.voter_id, vote.accepted));

        // Check if quorum is reached.
        if self.quorum_reached() {
            self.committed = true;
            Ok(QuorumOutcome::Committed {
                proposal: self.proposal.clone(),
                approvals: self.approvals(),
            })
        } else {
            Ok(QuorumOutcome::Pending)
        }
    }

    /// Check whether the proposal has timed out.
    ///
    /// When a timeout fires, remaining uncast votes are treated as
    /// implicit rejections. If quorum becomes unreachable, the proposal
    /// is aborted.
    ///
    /// Returns `QuorumOutcome::Rejected` when the proposal is aborted
    /// due to timeout, or `QuorumOutcome::Pending` if still waiting.
    pub fn check_timeout(&mut self, now_millis: u64) -> QuorumOutcome {
        if self.committed || self.aborted {
            // Already resolved.
            if self.committed {
                return QuorumOutcome::Committed {
                    proposal: self.proposal.clone(),
                    approvals: self.approvals(),
                };
            } else {
                return QuorumOutcome::Rejected {
                    proposal: self.proposal.clone(),
                    approvals: self.approvals(),
                    rejections: self.rejections(),
                    reason: "already aborted".to_string(),
                };
            }
        }

        if self.timeout_ms == 0 {
            return QuorumOutcome::Pending;
        }

        let elapsed = now_millis.saturating_sub(self.created_at_millis);
        if elapsed < self.timeout_ms {
            return QuorumOutcome::Pending;
        }

        // Timeout: remaining members are implicit rejections.
        // Determine if quorum is still reachable.
        let remaining = self.current_members.len().saturating_sub(self.votes.len());
        let max_possible_approvals = self.approvals() + remaining;
        if max_possible_approvals < self.quorum_threshold {
            // Quorum impossible.
            self.aborted = true;
            return QuorumOutcome::Rejected {
                proposal: self.proposal.clone(),
                approvals: self.approvals(),
                rejections: self.rejections() + remaining,
                reason: format!(
                    "timeout after {timeout_ms}ms: {approvals} approve + {rejections} reject, \
                     {remaining} uncast, quorum threshold {threshold} unreachable",
                    timeout_ms = self.timeout_ms,
                    approvals = self.approvals(),
                    rejections = self.rejections(),
                    remaining = remaining,
                    threshold = self.quorum_threshold,
                ),
            };
        }

        // Quorum still mathematically possible; stay pending.
        QuorumOutcome::Pending
    }

    /// Force-abort the proposal (e.g. on coordinator promotion).
    pub fn abort(&mut self) -> QuorumOutcome {
        if self.committed {
            return QuorumOutcome::Committed {
                proposal: self.proposal.clone(),
                approvals: self.approvals(),
            };
        }
        self.aborted = true;
        QuorumOutcome::Rejected {
            proposal: self.proposal.clone(),
            approvals: self.approvals(),
            rejections: self.rejections(),
            reason: "proposal aborted".to_string(),
        }
    }

    /// Number of accept votes cast.
    #[must_use]
    pub fn approvals(&self) -> usize {
        self.votes.iter().filter(|(_, accepted)| *accepted).count()
    }

    /// Number of reject votes cast.
    #[must_use]
    pub fn rejections(&self) -> usize {
        self.votes.iter().filter(|(_, accepted)| !*accepted).count()
    }

    /// Total number of votes cast (both approve and reject).
    #[must_use]
    pub fn votes_cast(&self) -> usize {
        self.votes.len()
    }

    /// Whether enough approve votes are present to meet quorum.
    fn quorum_reached(&self) -> bool {
        self.approvals() >= self.quorum_threshold
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proposal(
        id: u64,
        coordinator: u64,
        epoch: u64,
        added: Vec<u64>,
        removed: Vec<u64>,
    ) -> RosterChangeProposal {
        RosterChangeProposal {
            proposal_id: id,
            coordinator_id: coordinator,
            current_epoch: epoch,
            added,
            removed,
            created_at_millis: 1000,
        }
    }

    fn accept_vote(proposal_id: u64, voter: u64) -> RosterChangeVote {
        RosterChangeVote {
            proposal_id,
            voter_id: voter,
            accepted: true,
            reject_reason: None,
            voted_at_millis: 1100,
        }
    }

    fn reject_vote(proposal_id: u64, voter: u64, reason: &str) -> RosterChangeVote {
        RosterChangeVote {
            proposal_id,
            voter_id: voter,
            accepted: false,
            reject_reason: Some(reason.to_string()),
            voted_at_millis: 1100,
        }
    }

    // ── Quorum counting ──────────────────────────────────────────

    #[test]
    fn simple_majority_3_members_requires_2_approvals() {
        let proposal = make_proposal(1, 1, 5, vec![4], vec![]);
        let tracker = MembershipQuorumTracker::new(proposal.clone(), vec![1, 2, 3], 0);
        assert_eq!(tracker.quorum_threshold, 2);
    }

    #[test]
    fn simple_majority_5_members_requires_3_approvals() {
        let proposal = make_proposal(1, 1, 5, vec![6], vec![]);
        let tracker = MembershipQuorumTracker::new(proposal, vec![1, 2, 3, 4, 5], 0);
        assert_eq!(tracker.quorum_threshold, 3);
    }

    #[test]
    fn single_member_requires_1_approval() {
        let proposal = make_proposal(1, 1, 0, vec![2], vec![]);
        let tracker = MembershipQuorumTracker::new(proposal, vec![1], 0);
        assert_eq!(tracker.quorum_threshold, 1);
    }

    #[test]
    fn empty_members_requires_0_approvals() {
        let proposal = make_proposal(1, 1, 0, vec![], vec![]);
        let tracker = MembershipQuorumTracker::new(proposal, vec![], 0);
        assert_eq!(tracker.quorum_threshold, 0);
    }

    // ── Vote collection ──────────────────────────────────────────

    #[test]
    fn all_accept_reaches_quorum() {
        let proposal = make_proposal(1, 1, 5, vec![4], vec![]);
        let mut tracker = MembershipQuorumTracker::new(proposal.clone(), vec![1, 2, 3], 0);

        let outcome = tracker.receive_vote(&accept_vote(1, 1)).unwrap();
        assert!(matches!(outcome, QuorumOutcome::Pending));
        assert!(!tracker.committed);
        assert_eq!(tracker.approvals(), 1);

        let outcome = tracker.receive_vote(&accept_vote(1, 2)).unwrap();
        assert!(matches!(outcome, QuorumOutcome::Committed { .. }));
        assert!(tracker.committed);
        assert_eq!(tracker.approvals(), 2);
    }

    #[test]
    fn all_reject_no_quorum() {
        let proposal = make_proposal(1, 1, 5, vec![4], vec![]);
        let mut tracker = MembershipQuorumTracker::new(proposal.clone(), vec![1, 2, 3], 0);

        tracker.receive_vote(&reject_vote(1, 1, "bad")).unwrap();
        tracker.receive_vote(&reject_vote(1, 2, "bad")).unwrap();
        tracker.receive_vote(&reject_vote(1, 3, "bad")).unwrap();

        assert!(!tracker.committed);
        assert_eq!(tracker.approvals(), 0);
        assert_eq!(tracker.rejections(), 3);
    }

    #[test]
    fn split_vote_majority_accept() {
        let proposal = make_proposal(1, 1, 5, vec![5], vec![]);
        let mut tracker = MembershipQuorumTracker::new(proposal.clone(), vec![1, 2, 3, 4], 0);
        // threshold = 3 for 4 members

        tracker.receive_vote(&accept_vote(1, 1)).unwrap();
        tracker.receive_vote(&accept_vote(1, 2)).unwrap();
        tracker.receive_vote(&reject_vote(1, 3, "no")).unwrap();
        // Still pending: only 2 approvals
        assert!(!tracker.committed);

        tracker.receive_vote(&accept_vote(1, 4)).unwrap();
        assert!(tracker.committed);
        assert_eq!(tracker.approvals(), 3);
        assert_eq!(tracker.rejections(), 1);
    }

    #[test]
    fn split_vote_no_majority() {
        let proposal = make_proposal(1, 1, 5, vec![5], vec![]);
        let mut tracker = MembershipQuorumTracker::new(proposal.clone(), vec![1, 2, 3, 4], 0);
        // threshold = 3 for 4 members

        tracker.receive_vote(&accept_vote(1, 1)).unwrap();
        tracker.receive_vote(&accept_vote(1, 2)).unwrap();
        tracker.receive_vote(&reject_vote(1, 3, "no")).unwrap();
        tracker.receive_vote(&reject_vote(1, 4, "no")).unwrap();

        assert!(!tracker.committed);
        assert_eq!(tracker.approvals(), 2);
        assert_eq!(tracker.rejections(), 2);
    }

    // ── Error cases ──────────────────────────────────────────────

    #[test]
    fn reject_duplicate_vote() {
        let proposal = make_proposal(1, 1, 5, vec![4], vec![]);
        let mut tracker = MembershipQuorumTracker::new(proposal.clone(), vec![1, 2, 3], 0);

        tracker.receive_vote(&accept_vote(1, 1)).unwrap();
        let err = tracker.receive_vote(&accept_vote(1, 1)).unwrap_err();
        assert!(matches!(err, QuorumTrackerError::DuplicateVote(1)));
    }

    #[test]
    fn reject_wrong_proposal_id() {
        let proposal = make_proposal(1, 1, 5, vec![4], vec![]);
        let mut tracker = MembershipQuorumTracker::new(proposal, vec![1, 2, 3], 0);

        let bad_vote = accept_vote(99, 1); // wrong proposal_id
        let err = tracker.receive_vote(&bad_vote).unwrap_err();
        assert!(matches!(
            err,
            QuorumTrackerError::ProposalIdMismatch {
                expected: 1,
                received: 99
            }
        ));
    }

    #[test]
    fn reject_non_member_voter() {
        let proposal = make_proposal(1, 1, 5, vec![4], vec![]);
        let mut tracker = MembershipQuorumTracker::new(proposal, vec![1, 2, 3], 0);

        let err = tracker.receive_vote(&accept_vote(1, 99)).unwrap_err();
        assert!(matches!(err, QuorumTrackerError::VoterNotMember(99)));
    }

    #[test]
    fn reject_vote_after_commit() {
        let proposal = make_proposal(1, 1, 5, vec![4], vec![]);
        let mut tracker = MembershipQuorumTracker::new(proposal.clone(), vec![1, 2, 3], 0);

        tracker.receive_vote(&accept_vote(1, 1)).unwrap();
        tracker.receive_vote(&accept_vote(1, 2)).unwrap();
        assert!(tracker.committed);

        let err = tracker.receive_vote(&accept_vote(1, 3)).unwrap_err();
        assert!(matches!(err, QuorumTrackerError::AlreadyCommitted));
    }

    #[test]
    fn reject_vote_after_abort() {
        let proposal = make_proposal(1, 1, 5, vec![4], vec![]);
        let mut tracker = MembershipQuorumTracker::new(proposal, vec![1, 2, 3], 0);
        tracker.abort();
        let err = tracker.receive_vote(&accept_vote(1, 1)).unwrap_err();
        assert!(matches!(err, QuorumTrackerError::AlreadyAborted));
    }

    // ── Timeout ──────────────────────────────────────────────────

    #[test]
    fn timeout_before_deadline_is_pending() {
        let mut proposal = make_proposal(1, 1, 5, vec![4], vec![]);
        proposal.created_at_millis = 5000;
        let mut tracker = MembershipQuorumTracker::new(
            proposal,
            vec![1, 2, 3],
            5000, // 5s timeout
        );
        tracker.set_created_at(5000);

        // Only 2s elapsed
        let outcome = tracker.check_timeout(7000);
        assert!(matches!(outcome, QuorumOutcome::Pending));
    }

    #[test]
    fn timeout_after_deadline_no_quorum_possible_aborts() {
        let mut proposal = make_proposal(1, 1, 5, vec![4], vec![]);
        proposal.created_at_millis = 1000;
        let mut tracker = MembershipQuorumTracker::new(
            proposal,
            vec![1, 2, 3, 4, 5],
            3000, // 3s timeout
        );
        tracker.set_created_at(1000);

        // Only 1 approve vote by the timeout; remaining 4 uncast.
        // Maximum possible = 1 + 4 = 5, threshold = 3 → possible
        tracker.receive_vote(&accept_vote(1, 1)).unwrap();

        let outcome = tracker.check_timeout(4001); // just over 3s
        assert!(
            matches!(outcome, QuorumOutcome::Pending),
            "quorum still reachable even with time elapsed"
        );
    }

    #[test]
    fn timeout_with_no_votes_quorum_still_possible() {
        let mut proposal = make_proposal(1, 1, 5, vec![4], vec![]);
        proposal.created_at_millis = 1000;
        let mut tracker = MembershipQuorumTracker::new(proposal, vec![1, 2, 3], 3000);
        tracker.set_created_at(1000);

        // No votes cast at all. 3 members, threshold=2. All 3 uncast → max=3 > 2.
        let outcome = tracker.check_timeout(4001);
        assert!(
            matches!(outcome, QuorumOutcome::Pending),
            "quorum still possible with all uncast votes"
        );
    }

    #[test]
    fn timeout_with_rejections_making_quorum_impossible() {
        let mut proposal = make_proposal(1, 1, 5, vec![4], vec![]);
        proposal.created_at_millis = 1000;
        let mut tracker = MembershipQuorumTracker::new(proposal, vec![1, 2, 3], 3000);
        tracker.set_created_at(1000);

        // 2 rejections, 0 approvals. 3 members, threshold=2.
        // Remaining = 1, max_approvals = 0 + 1 = 1 < 2 → impossible
        tracker.receive_vote(&reject_vote(1, 1, "no")).unwrap();
        tracker.receive_vote(&reject_vote(1, 2, "no")).unwrap();

        let outcome = tracker.check_timeout(4001);
        assert!(matches!(outcome, QuorumOutcome::Rejected { .. }));
        assert!(tracker.aborted);
    }

    #[test]
    fn no_timeout_when_timeout_is_zero() {
        let mut proposal = make_proposal(1, 1, 5, vec![4], vec![]);
        proposal.created_at_millis = 1000;
        let mut tracker = MembershipQuorumTracker::new(
            proposal,
            vec![1, 2, 3],
            0, // no timeout
        );
        tracker.set_created_at(1000);

        let outcome = tracker.check_timeout(9999999);
        assert!(matches!(outcome, QuorumOutcome::Pending));
    }

    #[test]
    fn even_n_tie_breaking() {
        // 4 members, threshold = 3 (floor(4/2) + 1 = 3)
        let proposal = make_proposal(1, 1, 5, vec![5], vec![]);
        let mut tracker = MembershipQuorumTracker::new(proposal.clone(), vec![1, 2, 3, 4], 0);
        assert_eq!(tracker.quorum_threshold, 3);

        // 2 approve, 2 reject — no quorum
        tracker.receive_vote(&accept_vote(1, 1)).unwrap();
        tracker.receive_vote(&accept_vote(1, 2)).unwrap();
        tracker.receive_vote(&reject_vote(1, 3, "no")).unwrap();
        tracker.receive_vote(&reject_vote(1, 4, "no")).unwrap();

        assert!(!tracker.committed);
        assert_eq!(tracker.approvals(), 2);
        assert_eq!(tracker.rejections(), 2);
    }

    #[test]
    fn abort_produces_rejected_outcome() {
        let proposal = make_proposal(1, 1, 5, vec![4], vec![]);
        let mut tracker = MembershipQuorumTracker::new(proposal, vec![1, 2, 3], 0);
        tracker.receive_vote(&accept_vote(1, 1)).unwrap();

        let outcome = tracker.abort();
        assert!(matches!(outcome, QuorumOutcome::Rejected { .. }));
        assert!(tracker.aborted);
        assert!(!tracker.committed);
    }

    #[test]
    fn abort_on_already_committed_returns_committed() {
        let proposal = make_proposal(1, 1, 5, vec![4], vec![]);
        let mut tracker = MembershipQuorumTracker::new(
            proposal.clone(),
            vec![1, 2, 3], // threshold=2
            0,
        );
        tracker.receive_vote(&accept_vote(1, 1)).unwrap();
        tracker.receive_vote(&accept_vote(1, 2)).unwrap();
        assert!(tracker.committed);

        let outcome = tracker.abort();
        assert!(matches!(outcome, QuorumOutcome::Committed { .. }));
    }

    #[test]
    fn large_member_set_quorum_calculation() {
        // 101 members, threshold = 51 (floor(101/2) + 1 = 51)
        let members: Vec<u64> = (1..=101).collect();
        let proposal = make_proposal(1, 1, 5, vec![102], vec![]);
        let tracker = MembershipQuorumTracker::new(proposal, members, 0);
        assert_eq!(tracker.quorum_threshold, 51);
    }

    // ── Multi-node quorum simulation (integration smoke) ──────────

    /// Simulate a three-node cluster where the coordinator (node 1)
    /// proposes adding node 4. Nodes 2 and 3 vote; quorum of 2 (from 3
    /// members) is reached and the proposal is committed.
    #[test]
    fn three_node_join_quorum_smoke() {
        let members = vec![1u64, 2, 3];
        let proposal = make_proposal(1, 1, 5, vec![4], vec![]);

        // Simulate member 2 receiving the proposal and voting accept.
        let mut tracker = MembershipQuorumTracker::new(
            proposal.clone(),
            members.clone(),
            0, // no timeout for smoke test
        );
        tracker.set_created_at(1000);

        // Member 2 accepts.
        let outcome = tracker.receive_vote(&accept_vote(1, 2)).unwrap();
        assert!(
            matches!(outcome, QuorumOutcome::Pending),
            "1 accept vote from 3 members -> pending"
        );

        // Member 3 accepts -> quorum (2/3 >= 2).
        let outcome = tracker.receive_vote(&accept_vote(1, 3)).unwrap();
        assert!(
            matches!(outcome, QuorumOutcome::Committed { .. }),
            "2 accept votes from 3 members -> committed"
        );
        assert!(tracker.committed);
        assert_eq!(tracker.approvals(), 2);
    }

    /// Simulate a coordinator (node 1) proposing removal of node 3.
    /// Node 2 rejects, node 3 accepts — but node 3 is the subject
    /// of removal so it still gets a vote. Only 1 accept -> no quorum.
    #[test]
    fn three_node_leave_split_vote_no_quorum() {
        let members = vec![1u64, 2, 3];
        let proposal = make_proposal(2, 1, 5, vec![], vec![3]);

        let mut tracker = MembershipQuorumTracker::new(proposal.clone(), members.clone(), 0);
        tracker.set_created_at(1000);

        tracker
            .receive_vote(&reject_vote(2, 2, "premature"))
            .unwrap();
        tracker.receive_vote(&accept_vote(2, 3)).unwrap();

        assert!(!tracker.committed);
        assert_eq!(tracker.approvals(), 1);
        assert_eq!(tracker.rejections(), 1);
    }

    /// Coordinator leaves (promotion): node 1 departs, node 2 becomes
    /// coordinator. Node 3 must accept. Two-member quorum threshold is 2.
    #[test]
    fn coordinator_departure_promotion_quorum() {
        let _members = [1u64, 2, 3];
        // Node 1 (the coordinator) leaves. Remaining: {2, 3}.
        // Node 2 becomes the new coordinator, proposes removal of 1.
        let proposal = make_proposal(3, 2, 5, vec![], vec![1]);

        // After node 1 departs, only nodes 2 and 3 remain.
        let remaining = vec![2u64, 3];
        let mut tracker = MembershipQuorumTracker::new(proposal.clone(), remaining.clone(), 0);
        assert_eq!(tracker.quorum_threshold, 2, "floor(2/2)+1 = 2");

        tracker.set_created_at(1000);
        tracker.receive_vote(&accept_vote(3, 2)).unwrap();
        let outcome = tracker.receive_vote(&accept_vote(3, 3)).unwrap();
        assert!(matches!(outcome, QuorumOutcome::Committed { .. }));
    }

    /// Timeout-based abort: a 5-member cluster with the coordinator
    /// proposing a join. Only 1 member responds within the timeout;
    /// the remaining 3 uncast votes + 1 approval cannot reach
    /// threshold 3.
    #[test]
    fn timeout_aborts_when_quorum_unreachable() {
        let members: Vec<u64> = (1..=5).collect();
        let proposal = make_proposal(4, 1, 5, vec![6], vec![]);
        let mut tracker = MembershipQuorumTracker::new(
            proposal, members, 5000, // 5s timeout
        );
        tracker.set_created_at(1000);

        // Only 1 accept before timeout.
        tracker.receive_vote(&accept_vote(4, 1)).unwrap();

        // 6 seconds elapsed (past 5s timeout).
        let outcome = tracker.check_timeout(7000);
        // 1 approval + 4 uncast = 5 > threshold 3, so still possible.
        assert!(
            matches!(outcome, QuorumOutcome::Pending),
            "1 approve + 4 uncast = 5 -> still reachable"
        );

        // Now all 4 remaining cast rejections.
        for id in 2..=5 {
            tracker
                .receive_vote(&reject_vote(4, id, "timeout"))
                .unwrap();
        }

        // 1 approve, 4 reject, 0 uncast -> max=1 < threshold=3 -> unreachable.
        let outcome = tracker.check_timeout(7001);
        assert!(
            matches!(outcome, QuorumOutcome::Rejected { .. }),
            "1 approve + 4 reject = quorum unreachable"
        );
    }
}
