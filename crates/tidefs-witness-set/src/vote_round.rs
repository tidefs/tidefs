// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// VoteRound: round-id generation, vote collection with duplicate detection,
// and outcome determination (passed/failed/pending/deadlocked) for
// quorum-based consensus.
//
// Each VoteRound binds a set of voters to a single operation. Votes are
// boolean (approve/reject). The round resolves to Passed when the approval
// count satisfies the quorum threshold, Failed when rejections make quorum
// impossible, Deadlocked when all votes are cast without quorum, or remains
// Pending while ballots remain outstanding.

use crate::witness_set::QuorumThreshold;
use std::collections::BTreeMap;

/// Terminal or intermediate result of a vote round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteOutcome {
    Pending,
    Passed,
    Failed,
    Deadlocked,
}

/// A single quorum vote round for a particular operation.
#[derive(Clone, Debug)]
pub struct VoteRound {
    round_id: u64,
    operation_id: u64,
    voters: BTreeMap<u64, Option<bool>>,
    threshold: QuorumThreshold,
    tally: (usize, usize),
    outcome: VoteOutcome,
}

impl VoteRound {
    pub fn new(
        round_id: u64,
        operation_id: u64,
        voter_ids: &[u64],
        threshold: QuorumThreshold,
    ) -> Self {
        let voters: BTreeMap<u64, Option<bool>> = voter_ids.iter().map(|&id| (id, None)).collect();
        let outcome = if voter_ids.is_empty() {
            VoteOutcome::Deadlocked
        } else {
            VoteOutcome::Pending
        };
        Self {
            round_id,
            operation_id,
            voters,
            threshold,
            tally: (0, 0),
            outcome,
        }
    }

    pub fn round_id(&self) -> u64 {
        self.round_id
    }
    pub fn operation_id(&self) -> u64 {
        self.operation_id
    }
    pub fn voter_count(&self) -> usize {
        self.voters.len()
    }
    pub fn votes_cast(&self) -> usize {
        self.tally.0 + self.tally.1
    }
    pub fn tally(&self) -> (usize, usize) {
        self.tally
    }
    pub fn outcome(&self) -> VoteOutcome {
        self.outcome
    }
    pub fn threshold(&self) -> QuorumThreshold {
        self.threshold
    }

    pub fn cast_vote(&mut self, voter_id: u64, approve: bool) -> bool {
        if self.outcome != VoteOutcome::Pending {
            return false;
        }
        let entry = match self.voters.get_mut(&voter_id) {
            Some(e) if e.is_none() => e,
            _ => return false,
        };
        *entry = Some(approve);
        if approve {
            self.tally.0 += 1;
        } else {
            self.tally.1 += 1;
        }
        self.reevaluate();
        true
    }

    pub fn has_voted(&self, voter_id: u64) -> bool {
        self.voters
            .get(&voter_id)
            .map(|v| v.is_some())
            .unwrap_or(false)
    }

    pub fn pending_voters(&self) -> Vec<u64> {
        self.voters
            .iter()
            .filter(|(_, v)| v.is_none())
            .map(|(&id, _)| id)
            .collect()
    }

    fn reevaluate(&mut self) {
        let total = self.voters.len();
        if total == 0 {
            self.outcome = VoteOutcome::Deadlocked;
            return;
        }
        let approved = self.tally.0;
        let rejected = self.tally.1;
        let cast = approved + rejected;
        let remaining = total - cast;
        if self.threshold.is_satisfied(approved, total) {
            self.outcome = VoteOutcome::Passed;
            return;
        }
        // All votes cast without quorum.
        if remaining == 0 {
            // Nobody approved → definitely Failed.
            if approved == 0 {
                self.outcome = VoteOutcome::Failed;
            } else {
                self.outcome = VoteOutcome::Deadlocked;
            }
            return;
        }
        if !self.threshold.is_satisfied(approved + remaining, total) {
            self.outcome = VoteOutcome::Failed;
            return;
        }
        self.outcome = VoteOutcome::Pending;
    }
}

/// Monotonically increasing round-id generator.
#[derive(Clone, Debug)]
pub struct RoundIdGenerator {
    next_id: u64,
}

impl RoundIdGenerator {
    pub fn new() -> Self {
        Self { next_id: 1 }
    }
    pub fn starting_at(first_id: u64) -> Self {
        Self { next_id: first_id }
    }
    pub fn next_round_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
    pub fn peek(&self) -> u64 {
        self.next_id
    }
}

impl Default for RoundIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- RoundIdGenerator --
    #[test]
    fn test_gen_default() {
        let mut gen = RoundIdGenerator::new();
        assert_eq!(gen.next_round_id(), 1);
        assert_eq!(gen.next_round_id(), 2);
    }

    #[test]
    fn test_gen_starting_at() {
        let mut gen = RoundIdGenerator::starting_at(100);
        assert_eq!(gen.next_round_id(), 100);
    }

    #[test]
    fn test_gen_peek() {
        let mut gen = RoundIdGenerator::new();
        assert_eq!(gen.peek(), 1);
        gen.next_round_id();
        assert_eq!(gen.peek(), 2);
    }

    // -- Construction --
    #[test]
    fn test_new_vote_round() {
        let vr = VoteRound::new(1, 100, &[1, 2, 3], QuorumThreshold::StrictMajority);
        assert_eq!(vr.round_id(), 1);
        assert_eq!(vr.operation_id(), 100);
        assert_eq!(vr.voter_count(), 3);
        assert_eq!(vr.votes_cast(), 0);
        assert_eq!(vr.outcome(), VoteOutcome::Pending);
    }

    #[test]
    fn test_empty_voters_deadlocked() {
        let vr = VoteRound::new(0, 0, &[], QuorumThreshold::StrictMajority);
        assert_eq!(vr.outcome(), VoteOutcome::Deadlocked);
    }

    // -- Single-node --
    #[test]
    fn test_single_approve_passes() {
        let mut vr = VoteRound::new(1, 42, &[1], QuorumThreshold::StrictMajority);
        assert!(vr.cast_vote(1, true));
        assert_eq!(vr.outcome(), VoteOutcome::Passed);
    }

    #[test]
    fn test_single_reject_fails() {
        let mut vr = VoteRound::new(1, 42, &[1], QuorumThreshold::StrictMajority);
        assert!(vr.cast_vote(1, false));
        assert_eq!(vr.outcome(), VoteOutcome::Failed);
    }

    // -- Three-node majority --
    #[test]
    fn test_three_node_majority_passes() {
        let mut vr = VoteRound::new(1, 200, &[1, 2, 3], QuorumThreshold::StrictMajority);
        assert!(vr.cast_vote(1, true));
        assert_eq!(vr.outcome(), VoteOutcome::Pending);
        assert!(vr.cast_vote(2, true));
        assert_eq!(vr.outcome(), VoteOutcome::Passed);
    }

    #[test]
    fn test_three_node_two_reject_fails() {
        let mut vr = VoteRound::new(1, 200, &[1, 2, 3], QuorumThreshold::StrictMajority);
        vr.cast_vote(1, false);
        vr.cast_vote(2, false);
        assert_eq!(vr.outcome(), VoteOutcome::Failed);
    }

    // -- Five-node majority --
    #[test]
    fn test_five_node_majority_exactly_three() {
        let mut vr = VoteRound::new(1, 500, &[1, 2, 3, 4, 5], QuorumThreshold::StrictMajority);
        vr.cast_vote(1, true);
        vr.cast_vote(2, true);
        vr.cast_vote(3, true);
        assert_eq!(vr.outcome(), VoteOutcome::Passed);
    }

    #[test]
    fn test_five_node_fails_when_too_many_reject() {
        let mut vr = VoteRound::new(1, 500, &[1, 2, 3, 4, 5], QuorumThreshold::StrictMajority);
        vr.cast_vote(1, false);
        vr.cast_vote(2, false);
        vr.cast_vote(3, false);
        assert_eq!(vr.outcome(), VoteOutcome::Failed);
    }

    // -- Super-majority --
    #[test]
    fn test_super_majority_passes() {
        let mut vr = VoteRound::new(1, 600, &[1, 2, 3, 4, 5], QuorumThreshold::SuperMajority);
        vr.cast_vote(1, true);
        vr.cast_vote(2, true);
        vr.cast_vote(3, true);
        assert_eq!(vr.outcome(), VoteOutcome::Pending);
        vr.cast_vote(4, true);
        assert_eq!(vr.outcome(), VoteOutcome::Passed);
    }

    #[test]
    fn test_super_majority_fails() {
        let mut vr = VoteRound::new(1, 600, &[1, 2, 3, 4, 5], QuorumThreshold::SuperMajority);
        vr.cast_vote(1, false);
        vr.cast_vote(2, false);
        assert_eq!(vr.outcome(), VoteOutcome::Failed);
    }

    // -- Exact --
    #[test]
    fn test_exact_threshold_passes() {
        let mut vr = VoteRound::new(1, 700, &[1, 2, 3, 4], QuorumThreshold::Exact(3));
        vr.cast_vote(1, true);
        vr.cast_vote(2, true);
        vr.cast_vote(3, true);
        assert_eq!(vr.outcome(), VoteOutcome::Passed);
    }

    #[test]
    fn test_exact_threshold_fails() {
        let mut vr = VoteRound::new(1, 700, &[1, 2, 3, 4], QuorumThreshold::Exact(3));
        vr.cast_vote(1, false);
        vr.cast_vote(2, false);
        assert_eq!(vr.outcome(), VoteOutcome::Failed);
    }

    // -- Duplicate rejection --
    #[test]
    fn test_duplicate_vote_rejected() {
        let mut vr = VoteRound::new(1, 100, &[1, 2, 3], QuorumThreshold::StrictMajority);
        assert!(vr.cast_vote(1, true));
        assert!(!vr.cast_vote(1, true));
        assert_eq!(vr.tally(), (1, 0));
    }

    #[test]
    fn test_non_voter_rejected() {
        let mut vr = VoteRound::new(1, 100, &[1, 2, 3], QuorumThreshold::StrictMajority);
        assert!(!vr.cast_vote(99, true));
    }

    #[test]
    fn test_vote_after_terminal_rejected() {
        let mut vr = VoteRound::new(1, 100, &[1, 2, 3], QuorumThreshold::StrictMajority);
        vr.cast_vote(1, true);
        vr.cast_vote(2, true);
        assert!(!vr.cast_vote(3, true));
    }

    // -- has_voted / pending_voters --
    #[test]
    fn test_has_voted() {
        let mut vr = VoteRound::new(1, 100, &[1, 2, 3], QuorumThreshold::StrictMajority);
        assert!(!vr.has_voted(1));
        vr.cast_vote(1, true);
        assert!(vr.has_voted(1));
    }

    #[test]
    fn test_pending_voters() {
        let mut vr = VoteRound::new(1, 100, &[1, 2, 3], QuorumThreshold::StrictMajority);
        assert_eq!(vr.pending_voters(), vec![1, 2, 3]);
        vr.cast_vote(2, true);
        assert_eq!(vr.pending_voters(), vec![1, 3]);
    }

    // -- Deadlock --
    #[test]
    fn test_deadlock_all_voted_no_quorum() {
        let mut vr = VoteRound::new(1, 100, &[1, 2, 3, 4], QuorumThreshold::StrictMajority);
        vr.cast_vote(1, true);
        vr.cast_vote(2, true);
        vr.cast_vote(3, false);
        vr.cast_vote(4, false);
        assert_eq!(vr.outcome(), VoteOutcome::Deadlocked);
    }

    // -- Edge --
    #[test]
    fn test_two_node_majority() {
        let mut vr = VoteRound::new(1, 100, &[1, 2], QuorumThreshold::StrictMajority);
        vr.cast_vote(1, true);
        vr.cast_vote(2, true);
        assert_eq!(vr.outcome(), VoteOutcome::Passed);
    }

    #[test]
    fn test_two_node_one_reject_fails() {
        let mut vr = VoteRound::new(1, 100, &[1, 2], QuorumThreshold::StrictMajority);
        vr.cast_vote(1, false);
        assert_eq!(vr.outcome(), VoteOutcome::Failed);
    }

    #[test]
    fn test_round_isolation() {
        let mut vr1 = VoteRound::new(1, 100, &[1, 2, 3], QuorumThreshold::StrictMajority);
        let mut vr2 = VoteRound::new(2, 200, &[4, 5, 6], QuorumThreshold::Exact(2));
        vr1.cast_vote(1, true);
        vr1.cast_vote(2, true);
        vr2.cast_vote(4, true);
        assert_eq!(vr1.outcome(), VoteOutcome::Passed);
        assert_eq!(vr2.outcome(), VoteOutcome::Pending);
    }
}
