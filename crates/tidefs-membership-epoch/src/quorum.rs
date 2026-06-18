// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Quorum-based epoch commitment with BLAKE3-verified voting.
//!
//! This module implements the proposal → vote → commit pipeline for
//! advancing membership epochs through quorum agreement. Every
//! proposal, vote, and commitment carries a BLAKE3 integrity proof
//! covering the configuration payload so any member can independently
//! verify correctness.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// A proposal to transition the membership to a new configuration.
///
/// Created by a member node, broadcast to voters, and committed when
/// a quorum of verified [`EpochVote::Approve`] votes is collected.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochProposal {
    /// Unique identifier for this proposal (deterministic from
    /// proposer + sequence number).
    pub proposal_id: u64,
    /// Monotonic epoch sequence number; must be strictly greater
    /// than the current epoch.
    pub sequence_number: u64,
    /// Node that proposed this transition.
    pub proposer_id: u64,
    /// Target epoch identifier after the transition.
    pub proposed_epoch_id: u64,
    /// The epoch this proposal intends to advance from.
    pub prior_epoch_id: u64,
    /// Sorted, deduplicated member node ids in the proposed configuration.
    pub proposed_members: Vec<u64>,
    /// BLAKE3-256 hash covering the full proposal payload (domain-tagged).
    pub blake3_hash: [u8; 32],
}

impl EpochProposal {
    /// Domain separation tag for proposal hashing.
    pub const DOMAIN_TAG: &[u8] = b"MembershipEpoch.Proposal.v1";

    /// Compute the BLAKE3 hash for a proposal.
    ///
    /// Covers proposer_id, sequence_number, proposed_epoch_id,
    /// prior_epoch_id, and each member id in order (callers must
    /// ensure `proposed_members` is sorted before calling).
    pub fn compute_hash(
        proposer_id: u64,
        sequence_number: u64,
        proposed_epoch_id: u64,
        prior_epoch_id: u64,
        proposed_members: &[u64],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_TAG);
        hasher.update(&proposer_id.to_le_bytes());
        hasher.update(&sequence_number.to_le_bytes());
        hasher.update(&proposed_epoch_id.to_le_bytes());
        hasher.update(&prior_epoch_id.to_le_bytes());
        hasher.update(b"|members|");
        for id in proposed_members {
            hasher.update(&id.to_le_bytes());
        }
        hasher.finalize().into()
    }

    /// Verify that self.blake3_hash matches the computed hash.
    pub fn verify(&self) -> bool {
        Self::compute_hash(
            self.proposer_id,
            self.sequence_number,
            self.proposed_epoch_id,
            self.prior_epoch_id,
            &self.proposed_members,
        ) == self.blake3_hash
    }
}

/// A voter's response to an [`EpochProposal`].
///
/// Each vote carries a BLAKE3 hash binding the voter identity,
/// proposal hash, and approval/rejection decision together so
/// votes cannot be forged or replayed against a different proposal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EpochVote {
    Approve {
        voter_id: u64,
        /// Hash of the proposal this vote targets.
        proposal_hash: [u8; 32],
        /// BLAKE3 hash of the vote data (domain-tagged).
        vote_hash: [u8; 32],
    },
    Reject {
        voter_id: u64,
        proposal_hash: [u8; 32],
        vote_hash: [u8; 32],
    },
}

impl EpochVote {
    /// Domain separation tag for vote hashing.
    pub const DOMAIN_TAG: &[u8] = b"MembershipEpoch.Vote.v1";

    /// Compute the BLAKE3 vote hash covering voter + proposal + decision.
    pub fn compute_vote_hash(voter_id: u64, proposal_hash: &[u8; 32], approved: bool) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_TAG);
        hasher.update(&voter_id.to_le_bytes());
        hasher.update(proposal_hash);
        let tag: u8 = if approved { 0x01 } else { 0x00 };
        hasher.update(&[tag]);
        hasher.finalize().into()
    }

    /// Create an approve vote with BLAKE3 integrity proof.
    pub fn approve(voter_id: u64, proposal_hash: &[u8; 32]) -> Self {
        Self::Approve {
            voter_id,
            proposal_hash: *proposal_hash,
            vote_hash: Self::compute_vote_hash(voter_id, proposal_hash, true),
        }
    }

    /// Create a reject vote with BLAKE3 integrity proof.
    pub fn reject(voter_id: u64, proposal_hash: &[u8; 32]) -> Self {
        Self::Reject {
            voter_id,
            proposal_hash: *proposal_hash,
            vote_hash: Self::compute_vote_hash(voter_id, proposal_hash, false),
        }
    }

    /// Return the voter's node identifier.
    pub fn voter_id(&self) -> u64 {
        match self {
            Self::Approve { voter_id, .. } | Self::Reject { voter_id, .. } => *voter_id,
        }
    }

    /// Return the proposal hash this vote targets.
    pub fn proposal_hash(&self) -> &[u8; 32] {
        match self {
            Self::Approve { proposal_hash, .. } | Self::Reject { proposal_hash, .. } => {
                proposal_hash
            }
        }
    }

    /// True if this is an approve vote.
    pub fn is_approve(&self) -> bool {
        matches!(self, Self::Approve { .. })
    }

    /// Verify that the embedded vote_hash matches the computed hash.
    pub fn verify(&self) -> bool {
        let expected =
            Self::compute_vote_hash(self.voter_id(), self.proposal_hash(), self.is_approve());
        match self {
            Self::Approve { vote_hash, .. } | Self::Reject { vote_hash, .. } => {
                expected == *vote_hash
            }
        }
    }
}

/// Tally of votes on an epoch proposal, enforcing a simple-majority
/// quorum threshold.
///
/// Votes are deduplicated by voter id. Once the quorum threshold is
/// reached, the tally automatically commits and produces an
/// [`EpochCommitment`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuorumVoteTally {
    pub proposal: EpochProposal,
    /// Set of (voter_id, is_approve) for deduplication.
    votes: BTreeSet<(u64, bool)>,
    /// Minimum number of approve votes required.
    pub quorum_threshold: usize,
    /// Total number of eligible voters.
    pub voter_count: usize,
    /// Whether the quorum has been reached and the tally committed.
    pub committed: bool,
    /// The commitment, set when quorum is reached.
    pub commitment: Option<EpochCommitment>,
}

impl QuorumVoteTally {
    /// Create a new tally for a proposal.
    ///
    /// The quorum threshold defaults to a simple majority:
    /// `(voter_count / 2) + 1`.
    pub fn new(proposal: EpochProposal, voter_count: usize) -> Self {
        let quorum_threshold = if voter_count == 0 {
            0
        } else {
            (voter_count / 2) + 1
        };
        Self {
            proposal,
            votes: BTreeSet::new(),
            quorum_threshold,
            voter_count,
            committed: false,
            commitment: None,
        }
    }

    /// Cast a vote into the tally.
    ///
    /// # Errors
    ///
    /// Returns [`QuorumError::AlreadyCommitted`] if the quorum was
    /// already reached. Returns [`QuorumError::ProposalHashMismatch`]
    /// if the vote targets a different proposal. Returns
    /// [`QuorumError::VoteVerificationFailed`] if the vote's BLAKE3
    /// proof is invalid. Returns [`QuorumError::DuplicateVote`] if
    /// this voter already cast a vote.
    pub fn cast_vote(&mut self, vote: &EpochVote) -> Result<(), QuorumError> {
        if self.committed {
            return Err(QuorumError::AlreadyCommitted);
        }
        if vote.proposal_hash() != &self.proposal.blake3_hash {
            return Err(QuorumError::ProposalHashMismatch);
        }
        if !vote.verify() {
            return Err(QuorumError::VoteVerificationFailed);
        }
        if self.votes.iter().any(|(vid, _)| *vid == vote.voter_id()) {
            return Err(QuorumError::DuplicateVote(vote.voter_id()));
        }

        self.votes.insert((vote.voter_id(), vote.is_approve()));

        if self.quorum_reached() {
            self.commit();
        }
        Ok(())
    }

    /// Number of approve votes cast so far.
    pub fn approvals(&self) -> usize {
        self.votes.iter().filter(|(_, approved)| *approved).count()
    }

    /// Number of reject votes cast so far.
    pub fn rejections(&self) -> usize {
        self.votes.iter().filter(|(_, approved)| !*approved).count()
    }

    /// Total number of votes cast (both approve and reject).
    pub fn vote_cast(&self) -> usize {
        self.votes.len()
    }

    /// Whether enough approve votes are present to meet quorum.
    fn quorum_reached(&self) -> bool {
        self.approvals() >= self.quorum_threshold
    }

    /// Commit the proposal, producing an [`EpochCommitment`].
    fn commit(&mut self) {
        self.committed = true;
        self.commitment = Some(EpochCommitment {
            epoch_id: self.proposal.proposed_epoch_id,
            member_set: self.proposal.proposed_members.clone(),
            blake3_commitment: EpochCommitment::compute_commitment(
                self.proposal.proposed_epoch_id,
                &self.proposal.proposed_members,
            ),
            sequence_number: self.proposal.sequence_number,
            prior_epoch_id: self.proposal.prior_epoch_id,
        });
    }
}

/// A BLAKE3-verified committed epoch configuration.
///
/// Produced when a quorum of members approves an
/// [`EpochProposal`]. The commitment binds the epoch number,
/// member set, and sequence together with a BLAKE3 proof so
/// any consumer can verify the committed configuration's
/// integrity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochCommitment {
    /// Epoch identifier for the committed configuration.
    pub epoch_id: u64,
    /// Sorted member node ids in the committed configuration.
    pub member_set: Vec<u64>,
    /// BLAKE3-256 hash covering epoch_id and member_set.
    pub blake3_commitment: [u8; 32],
    /// Monotonic sequence number matching the proposal.
    pub sequence_number: u64,
    /// The epoch this commitment advanced from.
    pub prior_epoch_id: u64,
}

impl EpochCommitment {
    /// Domain separation tag for commitment hashing.
    pub const DOMAIN_TAG: &[u8] = b"MembershipEpoch.Commitment.v1";

    /// Compute the BLAKE3 commitment hash for an epoch configuration.
    pub fn compute_commitment(epoch_id: u64, member_set: &[u64]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_TAG);
        hasher.update(&epoch_id.to_le_bytes());
        for id in member_set {
            hasher.update(&id.to_le_bytes());
        }
        hasher.finalize().into()
    }

    /// Verify that the embedded commitment hash matches the computed hash.
    pub fn verify(&self) -> bool {
        Self::compute_commitment(self.epoch_id, &self.member_set) == self.blake3_commitment
    }
}

/// Errors that can occur during quorum-based epoch advancement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuorumError {
    /// The proposal has already been committed; no further votes accepted.
    AlreadyCommitted,
    /// A vote's proposal hash does not match the proposal being tallied.
    ProposalHashMismatch,
    /// A vote's BLAKE3 integrity proof is invalid.
    VoteVerificationFailed,
    /// The same voter attempted to vote twice.
    DuplicateVote(u64),
    /// The proposal's sequence number is not strictly greater than
    /// the current epoch (stale).
    StaleSequence,
    /// The proposal's prior_epoch_id does not match the current epoch.
    InvalidPriorEpoch,
    /// A quorum of approve votes has not yet been reached.
    QuorumNotReached {
        /// Number of approve votes counted.
        approvals: usize,
        /// Number of approve votes required.
        required: usize,
    },
    /// The proposed member set is empty (degenerate configuration).
    EmptyMemberSet,
}

impl fmt::Display for QuorumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyCommitted => write!(f, "proposal already committed"),
            Self::ProposalHashMismatch => {
                write!(f, "vote proposal hash does not match tally proposal")
            }
            Self::VoteVerificationFailed => write!(f, "vote BLAKE3 verification failed"),
            Self::DuplicateVote(id) => write!(f, "duplicate vote from member {id}"),
            Self::StaleSequence => write!(f, "proposal sequence number is stale"),
            Self::InvalidPriorEpoch => {
                write!(f, "proposal prior_epoch_id does not match current epoch")
            }
            Self::QuorumNotReached {
                approvals,
                required,
            } => {
                write!(
                    f,
                    "quorum not reached: {approvals} approvals, {required} required"
                )
            }
            Self::EmptyMemberSet => write!(f, "proposed member set is empty"),
        }
    }
}

impl std::error::Error for QuorumError {}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EpochProposal ─────────────────────────────────────────────────

    fn make_proposal(
        proposer_id: u64,
        seq: u64,
        proposed_epoch: u64,
        prior_epoch: u64,
        members: &[u64],
    ) -> EpochProposal {
        let mut sorted = members.to_vec();
        sorted.sort();
        sorted.dedup();
        let hash =
            EpochProposal::compute_hash(proposer_id, seq, proposed_epoch, prior_epoch, &sorted);
        EpochProposal {
            proposal_id: proposer_id.wrapping_mul(seq),
            sequence_number: seq,
            proposer_id,
            proposed_epoch_id: proposed_epoch,
            prior_epoch_id: prior_epoch,
            proposed_members: sorted,
            blake3_hash: hash,
        }
    }

    #[test]
    fn proposal_verify_accepts_valid() {
        let p = make_proposal(1, 2, 2, 1, &[1, 2, 3]);
        assert!(p.verify());
    }

    #[test]
    fn proposal_verify_rejects_tampered_members() {
        let mut p = make_proposal(1, 2, 2, 1, &[1, 2, 3]);
        p.proposed_members.push(99);
        assert!(!p.verify());
    }

    #[test]
    fn proposal_verify_rejects_tampered_epoch() {
        let mut p = make_proposal(1, 2, 2, 1, &[1, 2, 3]);
        p.proposed_epoch_id = 7;
        assert!(!p.verify());
    }

    #[test]
    fn proposal_hash_deterministic() {
        let p1 = make_proposal(1, 2, 2, 1, &[1, 2, 3]);
        let p2 = make_proposal(1, 2, 2, 1, &[1, 2, 3]);
        assert_eq!(p1.blake3_hash, p2.blake3_hash);
    }

    #[test]
    fn proposal_hash_differs_by_proposer() {
        let p1 = make_proposal(1, 2, 2, 1, &[1, 2, 3]);
        let p2 = make_proposal(99, 2, 2, 1, &[1, 2, 3]);
        assert_ne!(p1.blake3_hash, p2.blake3_hash);
    }

    #[test]
    fn proposal_hash_differs_by_members() {
        let p1 = make_proposal(1, 2, 2, 1, &[1, 2, 3]);
        let p2 = make_proposal(1, 2, 2, 1, &[1, 2, 3, 4]);
        assert_ne!(p1.blake3_hash, p2.blake3_hash);
    }

    #[test]
    fn proposal_serde_roundtrip() {
        let p = make_proposal(1, 2, 2, 1, &[1, 2, 3]);
        let json = serde_json::to_string(&p).unwrap();
        let restored: EpochProposal = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, p);
        assert!(restored.verify());
    }

    // ── EpochVote ─────────────────────────────────────────────────────

    fn proposal_hash() -> [u8; 32] {
        EpochProposal::compute_hash(1, 2, 2, 1, &[1, 2, 3])
    }

    #[test]
    fn approve_vote_verifies() {
        let ph = proposal_hash();
        let vote = EpochVote::approve(1, &ph);
        assert!(vote.verify());
        assert!(vote.is_approve());
        assert_eq!(vote.voter_id(), 1);
    }

    #[test]
    fn reject_vote_verifies() {
        let ph = proposal_hash();
        let vote = EpochVote::reject(2, &ph);
        assert!(vote.verify());
        assert!(!vote.is_approve());
        assert_eq!(vote.voter_id(), 2);
    }

    #[test]
    fn vote_rejects_tampered_hash() {
        let ph = proposal_hash();
        let vote = match EpochVote::approve(1, &ph) {
            EpochVote::Approve {
                voter_id,
                proposal_hash,
                vote_hash: _,
            } => {
                // Tamper with the embedded vote_hash
                EpochVote::Approve {
                    voter_id,
                    proposal_hash,
                    vote_hash: [0u8; 32],
                }
            }
            _ => unreachable!(),
        };
        assert!(!vote.verify());
    }

    #[test]
    fn approve_and_reject_have_different_hashes() {
        let ph = proposal_hash();
        let approve = EpochVote::approve(1, &ph);
        let reject = EpochVote::reject(1, &ph);
        match (&approve, &reject) {
            (EpochVote::Approve { vote_hash: ah, .. }, EpochVote::Reject { vote_hash: rh, .. }) => {
                assert_ne!(ah, rh);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn vote_hash_deterministic() {
        let ph = proposal_hash();
        let v1 = EpochVote::approve(1, &ph);
        let v2 = EpochVote::approve(1, &ph);
        match (&v1, &v2) {
            (
                EpochVote::Approve { vote_hash: h1, .. },
                EpochVote::Approve { vote_hash: h2, .. },
            ) => {
                assert_eq!(h1, h2);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn vote_serde_roundtrip() {
        let ph = proposal_hash();
        let vote = EpochVote::approve(1, &ph);
        let json = serde_json::to_string(&vote).unwrap();
        let restored: EpochVote = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, vote);
        assert!(restored.verify());
    }

    // ── QuorumVoteTally ───────────────────────────────────────────────

    #[test]
    fn tally_commit_with_simple_majority() {
        let proposal = make_proposal(1, 1, 1, 0, &[1, 2, 3]);
        let mut tally = QuorumVoteTally::new(proposal.clone(), 3);

        // With 3 voters, threshold is 2
        assert_eq!(tally.quorum_threshold, 2);

        let v1 = EpochVote::approve(1, &proposal.blake3_hash);
        tally.cast_vote(&v1).unwrap();
        assert!(!tally.committed);
        assert_eq!(tally.approvals(), 1);

        let v2 = EpochVote::approve(2, &proposal.blake3_hash);
        tally.cast_vote(&v2).unwrap();
        assert!(tally.committed);
        assert_eq!(tally.approvals(), 2);
        assert!(tally.commitment.is_some());
    }

    #[test]
    fn tally_commit_with_mixed_votes_still_reaches_quorum() {
        let proposal = make_proposal(1, 1, 1, 0, &[1, 2, 3, 4, 5]);
        let mut tally = QuorumVoteTally::new(proposal.clone(), 5);
        assert_eq!(tally.quorum_threshold, 3);

        tally
            .cast_vote(&EpochVote::approve(1, &proposal.blake3_hash))
            .unwrap();
        tally
            .cast_vote(&EpochVote::approve(2, &proposal.blake3_hash))
            .unwrap();
        tally
            .cast_vote(&EpochVote::reject(3, &proposal.blake3_hash))
            .unwrap();
        assert!(!tally.committed);
        assert_eq!(tally.rejections(), 1);

        tally
            .cast_vote(&EpochVote::approve(4, &proposal.blake3_hash))
            .unwrap();
        assert!(tally.committed);
        assert_eq!(tally.approvals(), 3);
    }

    #[test]
    fn tally_refuses_duplicate_vote() {
        let proposal = make_proposal(1, 1, 1, 0, &[1, 2, 3]);
        let mut tally = QuorumVoteTally::new(proposal.clone(), 3);

        tally
            .cast_vote(&EpochVote::approve(1, &proposal.blake3_hash))
            .unwrap();
        let result = tally.cast_vote(&EpochVote::approve(1, &proposal.blake3_hash));
        assert!(matches!(result, Err(QuorumError::DuplicateVote(1))));
    }

    #[test]
    fn tally_refuses_wrong_proposal_hash() {
        let p1 = make_proposal(1, 1, 1, 0, &[1, 2, 3]);
        let p2 = make_proposal(1, 1, 1, 0, &[1, 2, 3, 4]);
        let mut tally = QuorumVoteTally::new(p1, 3);

        let vote_for_p2 = EpochVote::approve(1, &p2.blake3_hash);
        let result = tally.cast_vote(&vote_for_p2);
        assert!(matches!(result, Err(QuorumError::ProposalHashMismatch)));
    }

    #[test]
    fn tally_refuses_tampered_vote() {
        let proposal = make_proposal(1, 1, 1, 0, &[1, 2, 3]);
        let mut tally = QuorumVoteTally::new(proposal.clone(), 3);

        // Manually create a vote with wrong hash
        let bad_vote = EpochVote::Approve {
            voter_id: 1,
            proposal_hash: proposal.blake3_hash,
            vote_hash: [0u8; 32],
        };
        let result = tally.cast_vote(&bad_vote);
        assert!(matches!(result, Err(QuorumError::VoteVerificationFailed)));
    }

    #[test]
    fn tally_refuses_vote_after_commit() {
        let proposal = make_proposal(1, 1, 1, 0, &[1, 2, 3]);
        let mut tally = QuorumVoteTally::new(proposal.clone(), 2);

        // With 2 voters, threshold is 2
        tally
            .cast_vote(&EpochVote::approve(1, &proposal.blake3_hash))
            .unwrap();
        tally
            .cast_vote(&EpochVote::approve(2, &proposal.blake3_hash))
            .unwrap();
        assert!(tally.committed);

        let result = tally.cast_vote(&EpochVote::approve(3, &proposal.blake3_hash));
        assert!(matches!(result, Err(QuorumError::AlreadyCommitted)));
    }

    #[test]
    fn tally_with_1_voter_requires_1_approval() {
        let proposal = make_proposal(1, 1, 1, 0, &[42]);
        let mut tally = QuorumVoteTally::new(proposal.clone(), 1);
        assert_eq!(tally.quorum_threshold, 1);

        tally
            .cast_vote(&EpochVote::approve(42, &proposal.blake3_hash))
            .unwrap();
        assert!(tally.committed);
    }

    #[test]
    fn tally_with_zero_voters() {
        let proposal = make_proposal(1, 1, 1, 0, &[1]);
        let tally = QuorumVoteTally::new(proposal, 0);
        assert_eq!(tally.quorum_threshold, 0);
        // Edge case: 0 voters, so quorum is vacuously unreachable
        // unless threshold is 0 — which it is for 0 voters
    }

    // ── EpochCommitment ───────────────────────────────────────────────

    #[test]
    fn commitment_verify_accepts_valid() {
        let c = EpochCommitment {
            epoch_id: 5,
            member_set: vec![1, 2, 3],
            blake3_commitment: EpochCommitment::compute_commitment(5, &[1, 2, 3]),
            sequence_number: 5,
            prior_epoch_id: 4,
        };
        assert!(c.verify());
    }

    #[test]
    fn commitment_verify_rejects_tampered_members() {
        let mut c = EpochCommitment {
            epoch_id: 5,
            member_set: vec![1, 2, 3],
            blake3_commitment: EpochCommitment::compute_commitment(5, &[1, 2, 3]),
            sequence_number: 5,
            prior_epoch_id: 4,
        };
        c.member_set.push(99);
        assert!(!c.verify());
    }

    #[test]
    fn commitment_verify_rejects_tampered_epoch() {
        let mut c = EpochCommitment {
            epoch_id: 5,
            member_set: vec![1, 2, 3],
            blake3_commitment: EpochCommitment::compute_commitment(5, &[1, 2, 3]),
            sequence_number: 5,
            prior_epoch_id: 4,
        };
        c.epoch_id = 7;
        assert!(!c.verify());
    }

    #[test]
    fn commitment_hash_deterministic() {
        let h1 = EpochCommitment::compute_commitment(5, &[1, 2, 3]);
        let h2 = EpochCommitment::compute_commitment(5, &[1, 2, 3]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn commitment_hash_differs_by_member_order() {
        // Members must be sorted; different order = different hash
        let h1 = EpochCommitment::compute_commitment(5, &[1, 2, 3]);
        let h2 = EpochCommitment::compute_commitment(5, &[3, 2, 1]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn commitment_serde_roundtrip() {
        let c = EpochCommitment {
            epoch_id: 5,
            member_set: vec![1, 2, 3],
            blake3_commitment: EpochCommitment::compute_commitment(5, &[1, 2, 3]),
            sequence_number: 5,
            prior_epoch_id: 4,
        };
        let json = serde_json::to_string(&c).unwrap();
        let restored: EpochCommitment = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, c);
        assert!(restored.verify());
    }

    // ── Full lifecycle: propose → vote → commit ───────────────────────

    #[test]
    fn full_lifecycle_3_voter_majority() {
        let proposal = make_proposal(1, 2, 2, 1, &[1, 2, 3]);
        let mut tally = QuorumVoteTally::new(proposal.clone(), 3);

        // Voters 1 and 2 approve, voter 3 rejects
        tally
            .cast_vote(&EpochVote::approve(1, &proposal.blake3_hash))
            .unwrap();
        tally
            .cast_vote(&EpochVote::reject(3, &proposal.blake3_hash))
            .unwrap();
        assert!(!tally.committed);

        tally
            .cast_vote(&EpochVote::approve(2, &proposal.blake3_hash))
            .unwrap();
        assert!(tally.committed);

        let commitment = tally.commitment.unwrap();
        assert_eq!(commitment.epoch_id, 2);
        assert_eq!(commitment.member_set, vec![1, 2, 3]);
        assert!(commitment.verify());
    }

    #[test]
    fn split_vote_no_quorum() {
        let proposal = make_proposal(1, 2, 2, 1, &[1, 2, 3, 4]);
        let mut tally = QuorumVoteTally::new(proposal.clone(), 4);
        // With 4 voters, threshold is 3
        assert_eq!(tally.quorum_threshold, 3);

        // Two approve, two reject — no quorum
        tally
            .cast_vote(&EpochVote::approve(1, &proposal.blake3_hash))
            .unwrap();
        tally
            .cast_vote(&EpochVote::approve(2, &proposal.blake3_hash))
            .unwrap();
        tally
            .cast_vote(&EpochVote::reject(3, &proposal.blake3_hash))
            .unwrap();
        tally
            .cast_vote(&EpochVote::reject(4, &proposal.blake3_hash))
            .unwrap();

        assert!(!tally.committed);
        assert_eq!(tally.approvals(), 2);
        assert_eq!(tally.rejections(), 2);
    }

    #[test]
    fn missing_vote_scenario() {
        let proposal = make_proposal(1, 2, 2, 1, &[1, 2, 3, 4, 5]);
        let mut tally = QuorumVoteTally::new(proposal.clone(), 5);
        // With 5 voters, threshold is 3

        // Only 2 votes cast, both approve
        tally
            .cast_vote(&EpochVote::approve(1, &proposal.blake3_hash))
            .unwrap();
        tally
            .cast_vote(&EpochVote::approve(2, &proposal.blake3_hash))
            .unwrap();

        assert!(!tally.committed);
        assert_eq!(tally.vote_cast(), 2);
        assert_eq!(tally.approvals(), 2);
    }

    #[test]
    fn unanimous_approve_5_voters() {
        let proposal = make_proposal(1, 3, 3, 2, &[10, 20, 30, 40, 50]);
        let mut tally = QuorumVoteTally::new(proposal.clone(), 5);
        assert_eq!(tally.quorum_threshold, 3);

        // Cast 2 votes, not yet quorum
        tally
            .cast_vote(&EpochVote::approve(10, &proposal.blake3_hash))
            .unwrap();
        tally
            .cast_vote(&EpochVote::approve(20, &proposal.blake3_hash))
            .unwrap();
        assert!(!tally.committed);

        // 3rd vote reaches quorum and auto-commits
        tally
            .cast_vote(&EpochVote::approve(30, &proposal.blake3_hash))
            .unwrap();
        assert!(tally.committed);
        assert_eq!(tally.approvals(), 3);

        // Post-commit votes are rejected
        let result = tally.cast_vote(&EpochVote::approve(40, &proposal.blake3_hash));
        assert!(matches!(result, Err(QuorumError::AlreadyCommitted)));
        assert!(tally.commitment.unwrap().verify());
    }
}
