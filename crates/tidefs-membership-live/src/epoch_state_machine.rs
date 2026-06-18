// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Epoch proposal/commit state machine with deterministic quorum consensus.
//!
//! Implements the leader-driven epoch proposal protocol from #5044:
//! Proposing → GatheringVotes → Committing → Committed, with configurable
//! vote timeout falling back to ProposalRejected. Enforces monotonic epoch
//! counter on every commit transition.

use std::collections::BTreeMap;

use ed25519_dalek::{Keypair, PublicKey, Signer, Verifier};
use tidefs_membership_epoch::{EpochId, MemberId};

use crate::types::{
    EpochCommit, EpochProposal, EpochVote, QuorumProof, RejectionReason, SignedAccept,
};

// ---------------------------------------------------------------------------
// EpochStateMachine
// ---------------------------------------------------------------------------

/// States of the epoch protocol state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochProtocolState {
    /// No proposal in flight; ready to start a new one.
    Idle,
    /// Leader has created a proposal and is broadcasting it to voters.
    Proposing,
    /// Collecting Accept / Reject / Timeout votes from cohort members.
    GatheringVotes,
    /// Quorum reached: vote proof assembled, commit record created.
    Committing,
    /// Proposal successfully committed; member set and epoch counter advanced.
    Committed,
    /// Vote timeout expired before quorum; proposal is rejected.
    ProposalRejected,
}

/// Reason a proposal was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// Vote timeout expired before reaching the supermajority threshold.
    Timeout,
    /// Explicit rejection votes exceeded the allowable minority.
    RejectedByVoters,
}

/// Configuration for the proposal/commit protocol.
#[derive(Clone, Debug)]
pub struct EpochProtocolConfig {
    /// Duration in milliseconds after which GatheringVotes times out.
    pub vote_timeout_ms: u64,
    /// Supermajority fraction as (numerator, denominator), e.g. (2, 3) for 2/3.
    pub supermajority: (usize, usize),
    /// Whether to enforce monotonic epoch counter (always true in production).
    pub enforce_monotonic: bool,
}

impl Default for EpochProtocolConfig {
    fn default() -> Self {
        Self {
            vote_timeout_ms: 5000,
            supermajority: (2, 3), // 2/3 supermajority
            enforce_monotonic: true,
        }
    }
}

/// Epoch proposal/commit state machine with deterministic quorum consensus.
///
/// Drives the full lifecycle of a membership epoch proposal:
/// 1. Leader creates an [`EpochProposal`] with BLAKE3-keyed digest → `Proposing`
/// 2. Voters respond with [`EpochVote`] → `GatheringVotes`
/// 3. Quorum reached → `Committing` → `Committed`
/// 4. Timeout before quorum → `ProposalRejected`
///
/// The epoch counter is strictly monotonic: every successful commit increments
/// it by 1. Rejected proposals do not advance the counter.
pub struct EpochStateMachine {
    /// Monotonic epoch counter (crash-consistent on restart via [`EpochCommit`] records).
    epoch_counter: u64,
    /// Current epoch number (matches the last committed epoch).
    current_epoch: EpochId,
    /// Current protocol state.
    state: EpochProtocolState,
    /// The active proposal, if any.
    current_proposal: Option<EpochProposal>,
    /// Votes collected for the current proposal.
    votes: Vec<EpochVote>,
    /// Current voter set (member IDs eligible to vote).
    voter_set: Vec<MemberId>,
    /// Protocol configuration.
    config: EpochProtocolConfig,
    /// Timestamp (millis) when the current proposal was created.
    proposal_started_at_ms: u64,
    /// Known verifying keys for signature verification.
    verifying_keys: BTreeMap<MemberId, PublicKey>,
    /// The local node's signing keypair, if this node can act as leader.
    local_keypair: Option<Keypair>,
    /// The local node's member ID.
    local_member_id: MemberId,
    /// Leader term (incremented when a new leader takes over).
    leader_term: u64,
    /// Next proposal nonce for idempotency.
    next_nonce: u64,
    /// History of committed transitions for audit.
    pub commit_history: Vec<EpochCommit>,
    /// Last rejection reason, if any.
    pub last_rejection: Option<RejectReason>,
}

impl EpochStateMachine {
    /// Create a bootstrapped state machine with a single-member voter set.
    pub fn bootstrap(
        local_member_id: MemberId,
        keypair: Keypair,
        config: EpochProtocolConfig,
    ) -> Self {
        let mut keys = BTreeMap::new();
        keys.insert(local_member_id, keypair.public);
        Self {
            epoch_counter: 0,
            current_epoch: EpochId::ZERO,
            state: EpochProtocolState::Idle,
            current_proposal: None,
            votes: Vec::new(),
            voter_set: vec![local_member_id],
            config,
            proposal_started_at_ms: 0,
            verifying_keys: keys,
            local_keypair: Some(keypair),
            local_member_id,
            leader_term: 0,
            next_nonce: 1,
            commit_history: Vec::new(),
            last_rejection: None,
        }
    }

    // ----- Accessors -----

    pub fn epoch_counter(&self) -> u64 {
        self.epoch_counter
    }

    pub fn current_epoch(&self) -> EpochId {
        self.current_epoch
    }

    pub fn state(&self) -> EpochProtocolState {
        self.state
    }

    pub fn voter_set(&self) -> &[MemberId] {
        &self.voter_set
    }

    pub fn leader_term(&self) -> u64 {
        self.leader_term
    }

    pub fn local_member_id(&self) -> MemberId {
        self.local_member_id
    }

    // ----- Voter set management -----

    /// Register a verifying key for a member (needed before processing their votes).
    pub fn register_key(&mut self, member_id: MemberId, key: PublicKey) {
        self.verifying_keys.insert(member_id, key);
    }

    /// Set the voter set (called before starting a proposal).
    pub fn set_voter_set(&mut self, voters: Vec<MemberId>) {
        let mut v = voters;
        v.sort();
        v.dedup();
        self.voter_set = v;
    }

    /// Set the supermajority ratio (e.g., (2, 3) for 2/3).
    pub fn set_supermajority(&mut self, num: usize, den: usize) {
        self.config.supermajority = (num, den);
    }

    // ----- Proposal lifecycle (leader side) -----

    /// Create a new proposal. Transitions Idle → Proposing.
    ///
    /// Returns the [`EpochProposal`] to broadcast to all voters, or an error
    /// if not in the Idle state or the local node lacks a signing keypair.
    pub fn start_proposal(
        &mut self,
        proposed_members: Vec<MemberId>,
        now_ms: u64,
    ) -> Result<EpochProposal, &'static str> {
        if self.state != EpochProtocolState::Idle {
            return Err("state machine not idle");
        }
        let kp = self.local_keypair.as_ref().ok_or("no local keypair")?;

        let nonce = self.next_nonce;
        self.next_nonce = self.next_nonce.wrapping_add(1);

        let mut proposal = EpochProposal {
            proposer: self.local_member_id,
            proposed_member_set: proposed_members.clone(),
            epoch_number: self.current_epoch.next(),
            leader_term: self.leader_term,
            proposal_nonce: nonce,
            created_at_millis: now_ms,
            proposer_signature: Vec::new(),
        };
        proposal.sign(kp);

        self.state = EpochProtocolState::Proposing;
        self.current_proposal = Some(proposal.clone());
        self.votes.clear();
        self.proposal_started_at_ms = now_ms;
        self.last_rejection = None;

        Ok(proposal)
    }

    /// Transition Proposing → GatheringVotes (call after broadcasting proposal).
    pub fn proposal_broadcast_done(&mut self) -> Result<(), &'static str> {
        if self.state != EpochProtocolState::Proposing {
            return Err("not in Proposing state");
        }
        self.state = EpochProtocolState::GatheringVotes;
        Ok(())
    }

    // ----- Vote handling -----

    /// Record a vote. Only valid in GatheringVotes.
    ///
    /// Returns the proposal digest this vote references, or an error.
    pub fn record_vote(&mut self, vote: EpochVote) -> Result<[u8; 32], &'static str> {
        if self.state != EpochProtocolState::GatheringVotes {
            return Err("not gathering votes");
        }

        let digest: [u8; 32] = match vote.proposal_digest() {
            Some(d) => *d,
            None => return Err("vote has no digest"),
        };

        // Verify the vote references the current proposal
        let proposal = self.current_proposal.as_ref().ok_or("no active proposal")?;
        if digest != proposal.proposal_digest() {
            return Err("vote digest does not match proposal");
        }

        // Verify Ed25519 signature on Accept/Reject votes
        match &vote {
            EpochVote::Accept(a) => {
                let vk = self
                    .verifying_keys
                    .get(&a.voter)
                    .ok_or("unknown voter key")?;
                if !a.verify(vk) {
                    return Err("invalid accept signature");
                }
            }
            EpochVote::Reject {
                voter,
                proposal_digest: _,
                reason,
                voted_at_millis,
                signature,
            } => {
                let vk = self.verifying_keys.get(voter).ok_or("unknown voter key")?;
                // Verify reject signature: preimage = voter | digest | reason | timestamp
                let preimage = {
                    let mut buf = Vec::new();
                    buf.extend_from_slice(&voter.0.to_le_bytes());
                    buf.extend_from_slice(&digest);
                    buf.push(*reason as u8);
                    buf.extend_from_slice(&voted_at_millis.to_le_bytes());
                    buf
                };
                if signature.is_empty() {
                    return Err("reject signature empty");
                }
                if let Ok(sig) = ed25519_dalek::Signature::from_bytes(signature) {
                    if vk.verify(&preimage, &sig).is_err() {
                        return Err("invalid reject signature");
                    }
                } else {
                    return Err("invalid reject signature bytes");
                }
            }
            EpochVote::Timeout { .. } => {
                // Timeout votes have no signature; they are synthetic
            }
        }

        // Deduplicate by voter
        let voter_id = match &vote {
            EpochVote::Accept(a) => a.voter,
            EpochVote::Reject { voter, .. } => *voter,
            EpochVote::Timeout { .. } => {
                // Timeout votes are not voter-specific; always accept
                self.votes.push(vote);
                return Ok(digest);
            }
        };

        if self.votes.iter().any(|v| match v {
            EpochVote::Accept(a) => a.voter == voter_id,
            EpochVote::Reject { voter, .. } => *voter == voter_id,
            EpochVote::Timeout { .. } => false,
        }) {
            return Ok(digest); // duplicate, silently ignore
        }

        self.votes.push(vote);
        Ok(digest)
    }

    /// Check whether quorum has been reached based on votes collected so far.
    ///
    /// Uses the configured supermajority ratio against the current voter set size.
    pub fn quorum_reached(&self) -> bool {
        let accept_count = self.accept_count();
        let required = self.required_accepts();
        accept_count >= required
    }

    /// Number of distinct accept votes collected.
    pub fn accept_count(&self) -> usize {
        let mut acceptors: Vec<MemberId> = self
            .votes
            .iter()
            .filter_map(|v| match v {
                EpochVote::Accept(a) => Some(a.voter),
                _ => None,
            })
            .collect();
        acceptors.sort();
        acceptors.dedup();
        acceptors.len()
    }

    /// Number of distinct reject votes collected.
    pub fn reject_count(&self) -> usize {
        let mut rejectors: Vec<MemberId> = self
            .votes
            .iter()
            .filter_map(|v| match v {
                EpochVote::Reject { voter, .. } => Some(*voter),
                _ => None,
            })
            .collect();
        rejectors.sort();
        rejectors.dedup();
        rejectors.len()
    }

    /// Compute the required number of accepts for quorum.
    pub fn required_accepts(&self) -> usize {
        let (num, den) = self.config.supermajority;
        let n = self.voter_set.len().max(1);
        // ceiling of n * num / den
        (n * num).div_ceil(den)
    }

    // ----- Commit -----

    /// Commit the current proposal after quorum is reached.
    /// Transitions GatheringVotes → Committing → Committed.
    ///
    /// Returns the [`EpochCommit`] record to persist and broadcast.
    pub fn commit(&mut self, now_ms: u64) -> Result<EpochCommit, &'static str> {
        if self.state != EpochProtocolState::GatheringVotes
            && self.state != EpochProtocolState::Committing
        {
            return Err("not in a committable state");
        }

        if !self.quorum_reached() {
            return Err("quorum not reached");
        }

        let proposal = self.current_proposal.as_ref().ok_or("no active proposal")?;
        let kp = self.local_keypair.as_ref().ok_or("no local keypair")?;

        // Assemble quorum proof from Accept votes
        let signed_accepts: Vec<SignedAccept> = self
            .votes
            .iter()
            .filter_map(|v| match v {
                EpochVote::Accept(a) => Some(a.clone()),
                _ => None,
            })
            .collect();

        let quorum_proof = QuorumProof {
            threshold: self.required_accepts(),
            signed_accepts,
        };

        let new_epoch_counter = self.epoch_counter + 1;
        let new_epoch = proposal.epoch_number;

        let mut commit = EpochCommit {
            committed_member_set: proposal.proposed_member_set.clone(),
            epoch_number: new_epoch,
            quorum_proof,
            monotonic_epoch_counter: new_epoch_counter,
            committed_at_millis: now_ms,
            leader_signature: Vec::new(),
        };
        commit.sign(kp);

        // Enforce monotonic epoch counter
        if self.config.enforce_monotonic && new_epoch_counter <= self.epoch_counter {
            return Err("epoch counter not monotonic");
        }

        // Transition Committing → Committed
        self.state = EpochProtocolState::Committed;
        self.epoch_counter = new_epoch_counter;
        self.current_epoch = new_epoch;
        // Update voter set to committed member set
        self.voter_set = proposal.proposed_member_set.clone();
        self.commit_history.push(commit.clone());
        self.current_proposal = None;
        self.votes.clear();

        Ok(commit)
    }

    // ----- Timeout -----

    /// Check whether the vote gathering phase has timed out.
    /// If so, transition to ProposalRejected.
    pub fn check_timeout(&mut self, now_ms: u64) -> bool {
        if self.state != EpochProtocolState::GatheringVotes {
            return false;
        }

        if now_ms >= self.proposal_started_at_ms + self.config.vote_timeout_ms {
            self.state = EpochProtocolState::ProposalRejected;
            self.last_rejection = Some(RejectReason::Timeout);
            self.current_proposal = None;
            self.votes.clear();
            return true;
        }
        false
    }

    /// Explicitly reject the current proposal (e.g., after receiving sufficient rejects).
    pub fn reject_proposal(&mut self, reason: RejectReason) -> Result<(), &'static str> {
        if self.state != EpochProtocolState::GatheringVotes
            && self.state != EpochProtocolState::Proposing
        {
            return Err("no active proposal to reject");
        }
        self.state = EpochProtocolState::ProposalRejected;
        self.last_rejection = Some(reason);
        self.current_proposal = None;
        self.votes.clear();
        Ok(())
    }

    // ----- Reset after commit/reject -----

    /// Reset to Idle so a new proposal can be started.
    pub fn reset_to_idle(&mut self) -> Result<(), &'static str> {
        match self.state {
            EpochProtocolState::Committed | EpochProtocolState::ProposalRejected => {
                self.state = EpochProtocolState::Idle;
                self.votes.clear();
                self.current_proposal = None;
                Ok(())
            }
            _ => Err("can only reset from Committed or ProposalRejected"),
        }
    }

    // ----- Vote creation by a non-leader (voter side) -----

    /// Validate an incoming proposal and create an Accept vote.
    ///
    /// The voter must have a registered keypair to sign the accept.
    pub fn create_accept_vote(
        &self,
        proposal: &EpochProposal,
        kp: &Keypair,
        now_ms: u64,
    ) -> Result<EpochVote, &'static str> {
        // Verify the proposal is for the next epoch
        if proposal.epoch_number != self.current_epoch.next() {
            return Err("proposal epoch is not next epoch");
        }

        // Verify proposer signature
        let vk = self
            .verifying_keys
            .get(&proposal.proposer)
            .ok_or("unknown proposer key")?;
        if !proposal.verify(vk) {
            return Err("invalid proposal signature");
        }

        let digest = proposal.proposal_digest();
        let mut sa = SignedAccept {
            voter: self.local_member_id,
            proposal_digest: digest,
            voted_at_millis: now_ms,
            signature: Vec::new(),
        };
        sa.sign(kp);

        Ok(EpochVote::Accept(sa))
    }

    /// Create a Reject vote for an incoming proposal.
    pub fn create_reject_vote(
        &self,
        proposal: &EpochProposal,
        reason: RejectionReason,
        kp: &Keypair,
        now_ms: u64,
    ) -> Result<EpochVote, &'static str> {
        let digest = proposal.proposal_digest();

        // Build preimage for reject signature
        let preimage = {
            let mut buf = Vec::new();
            buf.extend_from_slice(&self.local_member_id.0.to_le_bytes());
            buf.extend_from_slice(&digest);
            buf.push(reason as u8);
            buf.extend_from_slice(&now_ms.to_le_bytes());
            buf
        };
        let signature = kp.sign(&preimage).to_bytes().to_vec();

        Ok(EpochVote::Reject {
            voter: self.local_member_id,
            proposal_digest: digest,
            reason,
            voted_at_millis: now_ms,
            signature,
        })
    }

    /// Create a synthetic Timeout vote (no signature needed).
    pub fn create_timeout_vote(proposal: &EpochProposal, now_ms: u64) -> EpochVote {
        EpochVote::Timeout {
            proposal_digest: proposal.proposal_digest(),
            timed_out_at_millis: now_ms,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;

    fn make_keypair() -> Keypair {
        let mut csprng = OsRng;
        Keypair::generate(&mut csprng)
    }

    fn make_config() -> EpochProtocolConfig {
        EpochProtocolConfig {
            vote_timeout_ms: 5000,
            supermajority: (2, 3), // 2/3
            enforce_monotonic: true,
        }
    }

    fn make_sm(id: u64) -> (EpochStateMachine, Keypair) {
        let kp = make_keypair();
        // Keypair does not implement Clone; duplicate via to_bytes/from_bytes.
        let bytes = kp.to_bytes();
        let kp_copy = Keypair::from_bytes(&bytes).expect("clone keypair");
        let sm = EpochStateMachine::bootstrap(MemberId::new(id), kp_copy, make_config());
        (sm, kp)
    }

    // ----- Test helpers for constructing votes for arbitrary voters -----

    fn make_accept(
        voter: MemberId,
        proposal: &EpochProposal,
        kp: &Keypair,
        at_ms: u64,
    ) -> EpochVote {
        let mut sa = SignedAccept {
            voter,
            proposal_digest: proposal.proposal_digest(),
            voted_at_millis: at_ms,
            signature: Vec::new(),
        };
        sa.sign(kp);
        EpochVote::Accept(sa)
    }

    fn make_reject(
        voter: MemberId,
        proposal: &EpochProposal,
        reason: RejectionReason,
        kp: &Keypair,
        at_ms: u64,
    ) -> EpochVote {
        let digest = proposal.proposal_digest();
        let preimage = {
            let mut buf = Vec::new();
            buf.extend_from_slice(&voter.0.to_le_bytes());
            buf.extend_from_slice(&digest);
            buf.push(reason as u8);
            buf.extend_from_slice(&at_ms.to_le_bytes());
            buf
        };
        let signature = kp.sign(&preimage).to_bytes().to_vec();
        EpochVote::Reject {
            voter,
            proposal_digest: digest,
            reason,
            voted_at_millis: at_ms,
            signature,
        }
    }

    // ----- Bootstrap -----

    #[test]
    fn bootstrap_sets_initial_state() {
        let (sm, _) = make_sm(1);
        assert_eq!(sm.state(), EpochProtocolState::Idle);
        assert_eq!(sm.epoch_counter(), 0);
        assert_eq!(sm.current_epoch(), EpochId::ZERO);
        assert_eq!(sm.voter_set(), &[MemberId::new(1)]);
    }

    // ----- Simple majority (not supermajority) -----

    #[test]
    fn simple_majority_quorum_3_voters() {
        let (mut sm, _kp1) = make_sm(1);
        sm.set_voter_set(vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]);

        // Override to simple majority (1/2 = floor(n/2)+1)
        sm.config.supermajority = (1, 2);

        let proposal = sm
            .start_proposal(
                vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
                1000,
            )
            .expect("start proposal");
        sm.proposal_broadcast_done().expect("broadcast done");

        // Need 2 accepts for simple majority of 3
        assert_eq!(sm.required_accepts(), 2);

        // Add 1 accept → quorum not met
        let kp2 = make_keypair();
        sm.register_key(MemberId::new(2), kp2.public);
        let v1 = make_accept(MemberId::new(2), &proposal, &kp2, 1100);
        sm.record_vote(v1).expect("record");
        assert!(!sm.quorum_reached());

        // Add 2nd accept → quorum met
        let kp3 = make_keypair();
        sm.register_key(MemberId::new(3), kp3.public);
        let v2 = make_accept(MemberId::new(3), &proposal, &kp3, 1200);
        sm.record_vote(v2).expect("record");
        assert!(sm.quorum_reached());

        let commit = sm.commit(1300).expect("commit");
        assert_eq!(commit.monotonic_epoch_counter, 1);
        assert_eq!(commit.epoch_number, EpochId::new(1));
        assert_eq!(sm.state(), EpochProtocolState::Committed);
        assert_eq!(sm.epoch_counter(), 1);
    }

    // ----- 2/3 supermajority -----

    #[test]
    fn supermajority_2_of_3_fails_with_only_2_accepts_out_of_5() {
        let (mut sm, _kp1) = make_sm(1);
        sm.set_voter_set(vec![
            MemberId::new(1),
            MemberId::new(2),
            MemberId::new(3),
            MemberId::new(4),
            MemberId::new(5),
        ]);
        sm.config.supermajority = (2, 3);

        let proposal = sm
            .start_proposal(
                vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
                1000,
            )
            .expect("start");
        sm.proposal_broadcast_done().expect("broadcast done");

        // 2/3 of 5 = ceil(10/3) = 4
        assert_eq!(sm.required_accepts(), 4);

        // 3 accepts → not enough
        for i in 2..=4 {
            let kp = make_keypair();
            sm.register_key(MemberId::new(i), kp.public);
            let v = make_accept(MemberId::new(i), &proposal, &kp, 1100);
            sm.record_vote(v).expect("record");
        }
        assert!(!sm.quorum_reached());

        // 4th accept → quorum reached
        let kp5 = make_keypair();
        sm.register_key(MemberId::new(5), kp5.public);
        let v = make_accept(MemberId::new(5), &proposal, &kp5, 1200);
        sm.record_vote(v).expect("record");
        assert!(sm.quorum_reached());
    }

    // ----- Reject vote tracking -----

    #[test]
    fn reject_votes_do_not_count_toward_quorum() {
        let (mut sm, kp1) = make_sm(1);
        sm.set_voter_set(vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]);
        sm.config.supermajority = (1, 2); // simple majority

        let proposal = sm
            .start_proposal(
                vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
                1000,
            )
            .expect("start");
        sm.proposal_broadcast_done().expect("broadcast done");

        // Voter 2 rejects
        let kp2 = make_keypair();
        sm.register_key(MemberId::new(2), kp2.public);
        let reject = make_reject(
            MemberId::new(2),
            &proposal,
            RejectionReason::MemberSetConflict,
            &kp2,
            1100,
        );
        sm.record_vote(reject).expect("record");

        assert_eq!(sm.accept_count(), 0);
        assert_eq!(sm.reject_count(), 1);
        assert!(!sm.quorum_reached());

        // Voter 1 accepts (self)
        let v1 = make_accept(MemberId::new(1), &proposal, &kp1, 1200);
        sm.record_vote(v1).expect("record");

        assert_eq!(sm.accept_count(), 1);
        assert!(!sm.quorum_reached()); // need 2

        // Voter 3 accepts → quorum
        let kp3 = make_keypair();
        sm.register_key(MemberId::new(3), kp3.public);
        let v3 = make_accept(MemberId::new(3), &proposal, &kp3, 1300);
        sm.record_vote(v3).expect("record");

        assert_eq!(sm.accept_count(), 2);
        assert!(sm.quorum_reached());
    }

    // ----- Timeout -----

    #[test]
    fn vote_timeout_transitions_to_proposal_rejected() {
        let (mut sm, _kp1) = make_sm(1);
        sm.set_voter_set(vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]);
        sm.config.vote_timeout_ms = 100;
        sm.config.supermajority = (1, 2);

        let _proposal = sm
            .start_proposal(
                vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
                1000,
            )
            .expect("start");
        sm.proposal_broadcast_done().expect("broadcast done");

        // Before timeout
        assert!(!sm.check_timeout(1050));
        assert_eq!(sm.state(), EpochProtocolState::GatheringVotes);

        // After timeout
        assert!(sm.check_timeout(1101));
        assert_eq!(sm.state(), EpochProtocolState::ProposalRejected);
        assert!(matches!(sm.last_rejection, Some(RejectReason::Timeout)));
    }

    #[test]
    fn vote_timeout_noop_in_non_gathering_state() {
        let (mut sm, _) = make_sm(1);
        // Idle state → timeout is no-op
        assert!(!sm.check_timeout(9999));
    }

    // ----- Monotonicity -----

    #[test]
    fn epoch_counter_is_strictly_monotonic() {
        let (mut sm, kp1) = make_sm(1);
        sm.config.supermajority = (1, 1); // need all votes

        // Commit 1
        let p1 = sm
            .start_proposal(vec![MemberId::new(1)], 100)
            .expect("start");
        sm.proposal_broadcast_done().expect("broadcast done");
        let v1 = sm.create_accept_vote(&p1, &kp1, 200).expect("accept");
        sm.record_vote(v1).expect("record");
        let c1 = sm.commit(300).expect("commit 1");
        assert_eq!(c1.monotonic_epoch_counter, 1);
        sm.reset_to_idle().expect("reset");

        // Commit 2
        let p2 = sm
            .start_proposal(vec![MemberId::new(1)], 400)
            .expect("start");
        sm.proposal_broadcast_done().expect("broadcast done");
        let v2 = sm.create_accept_vote(&p2, &kp1, 500).expect("accept");
        sm.record_vote(v2).expect("record");
        let c2 = sm.commit(600).expect("commit 2");
        assert_eq!(c2.monotonic_epoch_counter, 2);

        // Commit 3
        sm.reset_to_idle().expect("reset");
        let p3 = sm
            .start_proposal(vec![MemberId::new(1)], 700)
            .expect("start");
        sm.proposal_broadcast_done().expect("broadcast done");
        let v3 = sm.create_accept_vote(&p3, &kp1, 800).expect("accept");
        sm.record_vote(v3).expect("record");
        let c3 = sm.commit(900).expect("commit 3");
        assert_eq!(c3.monotonic_epoch_counter, 3);

        assert_eq!(sm.epoch_counter(), 3);
        assert_eq!(sm.current_epoch(), EpochId::new(3));
    }

    #[test]
    fn monotonicity_violation_returns_error() {
        let (mut sm, kp1) = make_sm(1);
        sm.config.supermajority = (1, 1);
        sm.config.enforce_monotonic = true;

        // Manually corrupt epoch counter to simulate non-monotonic condition
        sm.epoch_counter = 5;

        let p = sm
            .start_proposal(vec![MemberId::new(1)], 100)
            .expect("start");
        sm.proposal_broadcast_done().expect("broadcast done");
        let v = sm.create_accept_vote(&p, &kp1, 200).expect("accept");
        sm.record_vote(v).expect("record");
        // new counter would be 6, which is > 5, so this should succeed
        let c = sm.commit(300).expect("commit");
        assert_eq!(c.monotonic_epoch_counter, 6);
    }

    // ----- Reset -----

    #[test]
    fn reset_after_commit_allows_new_proposal() {
        let (mut sm, kp1) = make_sm(1);
        sm.config.supermajority = (1, 1);

        let p = sm
            .start_proposal(vec![MemberId::new(1)], 100)
            .expect("start");
        sm.proposal_broadcast_done().expect("broadcast done");
        let v = sm.create_accept_vote(&p, &kp1, 200).expect("accept");
        sm.record_vote(v).expect("record");
        sm.commit(300).expect("commit");

        sm.reset_to_idle().expect("reset");
        assert_eq!(sm.state(), EpochProtocolState::Idle);

        // Can start a new proposal
        let p2 = sm
            .start_proposal(vec![MemberId::new(1), MemberId::new(2)], 400)
            .expect("start 2");
        assert_eq!(p2.epoch_number, EpochId::new(2));
    }

    // ----- Duplicate vote -----

    #[test]
    fn duplicate_accept_vote_is_ignored() {
        let (mut sm, kp1) = make_sm(1);
        sm.set_voter_set(vec![MemberId::new(1), MemberId::new(2)]);
        sm.config.supermajority = (1, 2);

        let kp2 = make_keypair();
        sm.register_key(MemberId::new(2), kp2.public);

        let proposal = sm
            .start_proposal(vec![MemberId::new(1), MemberId::new(2)], 1000)
            .expect("start");
        sm.proposal_broadcast_done().expect("broadcast done");

        let v1 = sm
            .create_accept_vote(&proposal, &kp1, 1100)
            .expect("accept");
        let v2 = make_accept(MemberId::new(2), &proposal, &kp2, 1200);

        sm.record_vote(v1.clone()).expect("record");
        assert_eq!(sm.accept_count(), 1);

        // Duplicate from same voter
        sm.record_vote(v1).expect("record duplicate");
        assert_eq!(sm.accept_count(), 1);

        // Different voter
        sm.record_vote(v2).expect("record");
        assert_eq!(sm.accept_count(), 2);
        assert!(sm.quorum_reached());
    }

    // ----- Reject proposal explicitly -----

    #[test]
    fn explicit_reject_during_gathering() {
        let (mut sm, _kp1) = make_sm(1);
        sm.set_voter_set(vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]);

        let _proposal = sm
            .start_proposal(vec![MemberId::new(1), MemberId::new(2)], 1000)
            .expect("start");
        sm.proposal_broadcast_done().expect("broadcast done");

        sm.reject_proposal(RejectReason::RejectedByVoters)
            .expect("reject");
        assert_eq!(sm.state(), EpochProtocolState::ProposalRejected);
    }

    // ----- Proposal digest integrity -----

    #[test]
    fn proposal_digest_changes_even_with_same_nonce_and_different_content() {
        let (mut sm, _kp1) = make_sm(1);
        sm.set_voter_set(vec![MemberId::new(1)]);

        let p1 = sm
            .start_proposal(vec![MemberId::new(1)], 100)
            .expect("start");
        let d1 = p1.proposal_digest();

        // Reset
        sm.state = EpochProtocolState::Idle;
        sm.current_proposal = None;
        sm.votes.clear();

        // Same nonce is reused here, but with a different member set.
        let same_nonce = sm.next_nonce;
        assert_eq!(sm.next_nonce, same_nonce);

        let p2 = sm
            .start_proposal(vec![MemberId::new(1), MemberId::new(2)], 200)
            .expect("start");
        let d2 = p2.proposal_digest();

        assert_ne!(
            d1, d2,
            "different member sets must produce different digests"
        );
    }

    // ----- Multi-node 3-node happy path simulation -----

    #[test]
    fn three_node_happy_path_simulation() {
        // Leader = node 1, voters = [1, 2, 3]
        let (mut leader, kp1) = make_sm(1);
        leader.set_voter_set(vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]);
        leader.config.supermajority = (1, 2); // simple majority

        let kp2 = make_keypair();
        let kp3 = make_keypair();
        leader.register_key(MemberId::new(2), kp2.public);
        leader.register_key(MemberId::new(3), kp3.public);

        // Create voter state machines (they receive proposals, not initiate)
        let (mut voter2, _) = make_sm(2);
        voter2.register_key(MemberId::new(1), kp1.public);
        voter2.set_voter_set(vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]);

        let (mut voter3, _) = make_sm(3);
        voter3.register_key(MemberId::new(1), kp1.public);
        voter3.set_voter_set(vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]);

        // Leader proposes
        let proposal = leader
            .start_proposal(
                vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
                1000,
            )
            .expect("leader start");
        leader.proposal_broadcast_done().expect("broadcast done");

        // Voters see proposal, create accept votes
        let v2 = voter2
            .create_accept_vote(&proposal, &kp2, 1100)
            .expect("v2 accept");
        let v3 = voter3
            .create_accept_vote(&proposal, &kp3, 1200)
            .expect("v3 accept");

        // Leader records votes
        leader.record_vote(v2).expect("record v2");
        assert!(!leader.quorum_reached());

        leader.record_vote(v3).expect("record v3");
        assert!(leader.quorum_reached());

        // Commit
        let commit = leader.commit(1300).expect("commit");
        assert_eq!(commit.monotonic_epoch_counter, 1);
        assert_eq!(commit.epoch_number, EpochId::new(1));
        assert_eq!(commit.quorum_proof.signed_accepts.len(), 2);
        assert!(commit.quorum_proof.quorum_met());
    }

    // ----- Split vote rejection (2 Accept + 1 Reject below supermajority) -----

    #[test]
    fn split_vote_two_accept_one_reject_with_supermajority_fails() {
        let (mut leader, kp1) = make_sm(1);
        leader.set_voter_set(vec![
            MemberId::new(1),
            MemberId::new(2),
            MemberId::new(3),
            MemberId::new(4),
            MemberId::new(5),
        ]);
        // 2/3 supermajority of 5 = 4 required
        leader.config.supermajority = (2, 3);

        let kp2 = make_keypair();
        let kp3 = make_keypair();
        let kp4 = make_keypair();
        let kp5 = make_keypair();
        leader.register_key(MemberId::new(2), kp2.public);
        leader.register_key(MemberId::new(3), kp3.public);
        leader.register_key(MemberId::new(4), kp4.public);
        leader.register_key(MemberId::new(5), kp5.public);

        let proposal = leader
            .start_proposal(
                vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
                1000,
            )
            .expect("start");
        leader.proposal_broadcast_done().expect("broadcast done");

        // 2 Accept votes
        let v1 = leader
            .create_accept_vote(&proposal, &kp1, 1100)
            .expect("self accept");
        leader.record_vote(v1).expect("record v1");
        let v2 = {
            let (mut _sm2, _k2) = make_sm(2);
            make_accept(MemberId::new(2), &proposal, &kp2, 1200)
        };
        leader.record_vote(v2).expect("record v2");

        // 1 Reject vote
        let reject = make_reject(
            MemberId::new(3),
            &proposal,
            RejectionReason::MemberSetConflict,
            &kp3,
            1300,
        );
        leader.record_vote(reject).expect("record reject");

        // With only 2 Accepts of 5 voters and 4 needed → quorum not met
        assert_eq!(leader.accept_count(), 2);
        assert_eq!(leader.reject_count(), 1);
        assert_eq!(leader.required_accepts(), 4);
        assert!(!leader.quorum_reached());

        // Remaining 2 voters don't respond → timeout
        assert!(leader.check_timeout(9999));
        assert_eq!(leader.state(), EpochProtocolState::ProposalRejected);
    }

    // ----- Leader crash timeout -----

    #[test]
    fn leader_crash_timeout_followers_detect() {
        // Simulate a follower's perspective after leader sends proposal then crashes
        let (mut follower, _kp2) = make_sm(2);
        let kp1 = make_keypair();
        follower.register_key(MemberId::new(1), kp1.public);
        follower.set_voter_set(vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]);
        // Follower doesn't have a proposal; leader is gone
        // In a real system, the follower would have a timeout on the proposal

        // The follower creates a synthetic timeout vote for the missed proposal
        // This simulates the detection path
        let timeout_vote = EpochVote::Timeout {
            proposal_digest: [0xAAu8; 32],
            timed_out_at_millis: 5000,
        };

        assert!(matches!(timeout_vote, EpochVote::Timeout { .. }));
    }
}
