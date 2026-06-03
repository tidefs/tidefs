#![forbid(unsafe_code)]

//! Deterministic coordinator election triggered by lease expiry.
//!
//! When the coordinator lease expires via quorum-loss stepdown (see
//! `CoordinatorLease` in `tidefs-membership-live`), remaining peers use
//! [`CoordinatorElection`] to deterministically select and self-promote
//! a new coordinator.
//!
//! ## Election protocol
//!
//! 1. Check [`CoordinatorElection::election_needed`] with the lease-expiry signal.
//! 2. Compute [`CoordinatorElection::election_ranking`] (lowest `MemberId` wins).
//! 3. Call [`CoordinatorElection::should_self_promote`]; if `true`, call
//!    [`CoordinatorElection::promote`].
//! 4. The caller installs the returned [`CoordinatorElectionOutcome`] into the
//!    runtime and advances the incarnation counter.
//!
//! This module is pure logic with no runtime wiring. It complements
//! [`crate::coordinator_promotion::CoordinatorPromotion`] (which handles
//! explicit coordinator departure) by covering the lease-expiry case.

use crate::MemberId;
use tidefs_membership_types::{CoordinatorElectionOutcome, ElectionTrigger};

// ---------------------------------------------------------------------------
// CoordinatorElection
// ---------------------------------------------------------------------------

/// Pure-logic coordinator election state for lease-expiry scenarios.
///
/// Holds the current peer roster and the caller's own identity.
/// All methods are stateless predicates or fallible constructors;
/// the caller is responsible for invoking [`promote`](Self::promote) only
/// when [`should_self_promote`](Self::should_self_promote) returns `true`.
#[derive(Clone, Debug)]
pub struct CoordinatorElection {
    /// This peer's identity.
    self_id: MemberId,
    /// All currently active members from the committed roster.
    roster: Vec<MemberId>,
}

impl CoordinatorElection {
    /// Create a new election context.
    ///
    /// `roster` should be the active, healthy member set from the
    /// committed epoch roster. Dead or departed members should be
    /// excluded by the caller before constructing this struct.
    #[must_use]
    pub fn new(self_id: MemberId, roster: Vec<MemberId>) -> Self {
        Self { self_id, roster }
    }

    /// Returns `true` when an election is needed.
    ///
    /// An election is needed when the coordinator lease has expired
    /// *and* at least one other eligible candidate exists in the roster.
    /// A single-member cluster whose lease expires has nobody to elect
    /// and returns `false`.
    #[must_use]
    pub fn election_needed(&self, lease_expired: bool) -> bool {
        lease_expired && self.roster.len() > 1
    }

    /// Deterministic ranking of all roster members.
    ///
    /// Sorted by `MemberId` (ascending, per `Ord`). The first entry
    /// is the highest-priority candidate. Tie-breaking is inherent
    /// in `MemberId`'s `Ord` impl (u64 comparison).
    #[must_use]
    pub fn election_ranking(&self) -> Vec<MemberId> {
        let mut sorted = self.roster.clone();
        sorted.sort_unstable();
        sorted
    }

    /// Returns `true` when `self` is the highest-ranked eligible candidate.
    ///
    /// Returns `false` when `self` is not in the roster (defensive:
    /// should not happen in normal operation).
    #[must_use]
    pub fn should_self_promote(&self) -> bool {
        self.election_ranking()
            .first()
            .is_some_and(|first| *first == self.self_id)
    }

    /// Produce an election outcome with an incremented incarnation counter.
    ///
    /// Returns `Some(CoordinatorElectionOutcome)` when this peer is the
    /// top-ranked candidate. Returns `None` when this peer should not
    /// self-promote (not top-ranked, or not in roster).
    ///
    /// The new incarnation is always `current_incarnation + 1`.
    #[must_use]
    pub fn promote(
        &self,
        current_incarnation: u64,
        election_epoch: u64,
        _trigger: ElectionTrigger,
    ) -> Option<CoordinatorElectionOutcome> {
        if !self.should_self_promote() {
            return None;
        }
        Some(CoordinatorElectionOutcome {
            new_coordinator: self.self_id.0,
            new_incarnation: current_incarnation.saturating_add(1),
            election_epoch,
        })
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

    // ── election_needed ──────────────────────────────────────────────

    #[test]
    fn election_not_needed_when_lease_valid() {
        let election = CoordinatorElection::new(member(3), vec![member(1), member(3), member(5)]);
        assert!(!election.election_needed(false));
    }

    #[test]
    fn election_needed_when_lease_expired_and_peers_exist() {
        let election = CoordinatorElection::new(member(3), vec![member(1), member(3), member(5)]);
        assert!(election.election_needed(true));
    }

    #[test]
    fn election_not_needed_single_member() {
        let election = CoordinatorElection::new(member(1), vec![member(1)]);
        assert!(!election.election_needed(true));
    }

    #[test]
    fn election_needed_two_members() {
        let election = CoordinatorElection::new(member(2), vec![member(1), member(2)]);
        assert!(election.election_needed(true));
    }

    // ── election_ranking ─────────────────────────────────────────────

    #[test]
    fn ranking_sorted_lowest_first() {
        let election =
            CoordinatorElection::new(member(99), vec![member(50), member(10), member(30)]);
        let ranking = election.election_ranking();
        assert_eq!(ranking, vec![member(10), member(30), member(50)]);
    }

    #[test]
    fn ranking_deterministic_same_input() {
        let roster = vec![member(5), member(1), member(9), member(3)];
        let election1 = CoordinatorElection::new(member(1), roster.clone());
        let election2 = CoordinatorElection::new(member(1), roster);
        assert_eq!(election1.election_ranking(), election2.election_ranking());
    }

    #[test]
    fn ranking_lowest_id_wins() {
        let election =
            CoordinatorElection::new(member(100), vec![member(100), member(1), member(50)]);
        let ranking = election.election_ranking();
        assert_eq!(ranking[0], member(1));
    }

    // ── should_self_promote ──────────────────────────────────────────

    #[test]
    fn self_promote_when_top_ranked() {
        let election = CoordinatorElection::new(member(1), vec![member(1), member(3), member(5)]);
        assert!(election.should_self_promote());
    }

    #[test]
    fn self_not_promote_when_not_top_ranked() {
        let election = CoordinatorElection::new(member(5), vec![member(1), member(3), member(5)]);
        assert!(!election.should_self_promote());
    }

    #[test]
    fn self_not_promote_when_not_in_roster() {
        let election = CoordinatorElection::new(member(99), vec![member(1), member(2), member(3)]);
        assert!(!election.should_self_promote());
    }

    // ── promote ──────────────────────────────────────────────────────

    #[test]
    fn promote_produces_outcome() {
        let election = CoordinatorElection::new(member(2), vec![member(2), member(5), member(7)]);
        let outcome = election
            .promote(3, 10, ElectionTrigger::LeaseExpired)
            .expect("top-ranked peer should promote");
        assert_eq!(outcome.new_coordinator, 2);
        assert_eq!(outcome.new_incarnation, 4);
        assert_eq!(outcome.election_epoch, 10);
    }

    #[test]
    fn promote_returns_none_when_not_top_ranked() {
        let election = CoordinatorElection::new(member(7), vec![member(2), member(5), member(7)]);
        let result = election.promote(0, 0, ElectionTrigger::LeaseExpired);
        assert!(result.is_none());
    }

    #[test]
    fn promote_returns_none_when_not_in_roster() {
        let election = CoordinatorElection::new(member(99), vec![member(1), member(2)]);
        let result = election.promote(0, 0, ElectionTrigger::LeaseExpired);
        assert!(result.is_none());
    }

    #[test]
    fn incarnation_increments_by_exactly_one() {
        let election = CoordinatorElection::new(member(1), vec![member(1), member(2)]);
        let outcome = election
            .promote(7, 5, ElectionTrigger::LeaseExpired)
            .unwrap();
        assert_eq!(outcome.new_incarnation, 8);
    }

    #[test]
    fn bootstrap_election_zero_to_one() {
        let election = CoordinatorElection::new(member(1), vec![member(1), member(2)]);
        let outcome = election.promote(0, 0, ElectionTrigger::Bootstrap).unwrap();
        assert_eq!(outcome.new_incarnation, 1);
        assert_eq!(outcome.new_coordinator, 1);
        assert_eq!(outcome.election_epoch, 0);
    }

    #[test]
    fn incarnation_saturating_at_u64_max() {
        let election = CoordinatorElection::new(member(1), vec![member(1), member(2)]);
        let outcome = election
            .promote(u64::MAX, 0, ElectionTrigger::LeaseExpired)
            .unwrap();
        assert_eq!(outcome.new_incarnation, u64::MAX);
    }

    #[test]
    fn coordinator_departed_trigger() {
        let election = CoordinatorElection::new(member(3), vec![member(3), member(7)]);
        let outcome = election
            .promote(5, 2, ElectionTrigger::CoordinatorDeparted)
            .unwrap();
        assert_eq!(outcome.new_coordinator, 3);
        assert_eq!(outcome.new_incarnation, 6);
    }
}
