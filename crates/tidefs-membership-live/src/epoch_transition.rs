// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use crate::epoch_fence::MembershipEpochFence;
use crate::failure_detector::*;
use crate::types::*;
use ed25519_dalek::{Keypair, PublicKey};
use std::collections::BTreeMap;
use tidefs_membership_epoch::{ConfigClass, EpochId, MemberId};
use tidefs_node_drain::FenceToken;

// ---------------------------------------------------------------------------
// 3-phase epoch transition protocol
// ---------------------------------------------------------------------------

/// The epoch transition engine executes the 3-phase protocol:
/// Propose → Accept → Commit.
///
/// Phase 1 (Propose): Any node detecting a membership event creates a proposal.
/// Phase 2 (Accept): Each cohort member validates and returns an accept (or rejects).
/// Phase 3 (Commit): When proposer collects quorum accepts, broadcasts commit.
pub struct EpochTransitionEngine {
    current_epoch: EpochId,
    config_class: ConfigClass,
    /// Active proposals: proposal_id → proposal state
    active_proposals: BTreeMap<u64, ProposalState>,
    next_proposal_id: u64,
    /// Number of voters used for quorum computation
    voter_count: usize,
    /// Completed transitions for audit
    pub transition_history: Vec<CompletedTransition>,
    /// Accepts this node has sent (for duplicate detection)
    my_accepts: BTreeMap<u64, EpochTransitionAccept>,
    /// Commits this node has received and applied
    applied_commits: BTreeMap<EpochId, EpochTransitionCommit>,
}

#[derive(Clone, Debug)]
struct ProposalState {
    pub proposal: EpochTransitionProposal,
    pub accepts: Vec<EpochTransitionAccept>,
    pub committed: bool,
}

#[derive(Clone, Debug)]
pub struct CompletedTransition {
    pub from_epoch: EpochId,
    pub to_epoch: EpochId,
    pub reason: TransitionReason,
    pub members_added: Vec<MemberId>,
    pub members_removed: Vec<MemberId>,
    pub acceptance_count: usize,
    pub committed_at_millis: u64,
}

pub struct EpochTransitionProposalRequest<'a> {
    pub proposer: MemberId,
    pub members_added: Vec<MemberId>,
    pub members_removed: Vec<MemberId>,
    pub reason: TransitionReason,
    pub validation: Vec<SuspicionRecord>,
    pub fence_token: Option<FenceToken>,
    pub signing_key: &'a Keypair,
}

impl<'a> EpochTransitionProposalRequest<'a> {
    pub fn new(
        proposer: MemberId,
        members_added: Vec<MemberId>,
        members_removed: Vec<MemberId>,
        reason: TransitionReason,
        validation: Vec<SuspicionRecord>,
        fence_token: Option<FenceToken>,
        signing_key: &'a Keypair,
    ) -> Self {
        Self {
            proposer,
            members_added,
            members_removed,
            reason,
            validation,
            fence_token,
            signing_key,
        }
    }
}

impl EpochTransitionEngine {
    pub fn new(current_epoch: EpochId) -> Self {
        Self {
            current_epoch,
            config_class: ConfigClass::Normal,
            active_proposals: BTreeMap::new(),
            next_proposal_id: 1,
            voter_count: 3,
            transition_history: Vec::new(),
            my_accepts: BTreeMap::new(),
            applied_commits: BTreeMap::new(),
        }
    }

    /// Get the current epoch.
    pub fn current_epoch(&self) -> EpochId {
        self.current_epoch
    }

    /// Get the current config class.
    pub fn config_class(&self) -> ConfigClass {
        self.config_class
    }

    /// Create a new proposal (Phase 1).
    pub fn propose(
        &mut self,
        request: EpochTransitionProposalRequest<'_>,
    ) -> EpochTransitionProposal {
        let proposal_id = self.next_proposal_id;
        self.next_proposal_id += 1;

        let to_epoch = self.current_epoch.next();
        let mut proposal = EpochTransitionProposal {
            proposal_id,
            proposer: request.proposer,
            from_epoch: self.current_epoch,
            to_epoch,
            members_added: request.members_added,
            members_removed: request.members_removed,
            reason: request.reason,
            validation: request.validation,
            proposed_at_millis: now_millis(),
            fence_token: request.fence_token,
            proposer_signature: Vec::new(),
        };
        proposal.sign(request.signing_key);

        self.active_proposals.insert(
            proposal_id,
            ProposalState {
                proposal: proposal.clone(),
                accepts: Vec::new(),
                committed: false,
            },
        );

        proposal
    }

    /// Validate a proposal received from another node.
    pub fn validate_proposal(
        &self,
        proposal: &EpochTransitionProposal,
        verifying_keys: &BTreeMap<MemberId, PublicKey>,
        alive_members: &[MemberId],
        detector: &FailureDetector,
    ) -> Result<(), TransitionError> {
        // Must be for our current epoch → next epoch
        if proposal.from_epoch != self.current_epoch {
            return Err(TransitionError::EpochMismatch {
                expected: self.current_epoch,
                got: proposal.from_epoch,
            });
        }

        // Verify signature
        let vk = verifying_keys
            .get(&proposal.proposer)
            .ok_or(TransitionError::UnknownProposer(proposal.proposer))?;
        if !proposal.verify(vk) {
            return Err(TransitionError::InvalidSignature);
        }

        // Proposer must be alive
        if !alive_members.contains(&proposal.proposer) {
            return Err(TransitionError::ProposerNotAlive(proposal.proposer));
        }

        // Proposer must be a voter
        if let Some(peer) = detector.get_peer(proposal.proposer) {
            if !peer.is_voter() {
                return Err(TransitionError::ProposerNotVoter(proposal.proposer));
            }
        } else {
            return Err(TransitionError::UnknownProposer(proposal.proposer));
        }

        // For failure-based transitions, require K suspicion records
        if matches!(proposal.reason, TransitionReason::FailureDetected) {
            if proposal.validation.is_empty() {
                return Err(TransitionError::InsufficientValidation);
            }
            // Each suspicion must be from a distinct reporter
            let reporters: std::collections::BTreeSet<MemberId> =
                proposal.validation.iter().map(|s| s.reported_by).collect();
            if reporters.len() < 2 {
                return Err(TransitionError::InsufficientValidation);
            }
        }

        Ok(())
    }

    /// Validate a proposal against the membership epoch fence.
    ///
    /// In addition to the base validation performed by
    /// [`validate_proposal`], this method checks:
    ///
    /// 1. The proposer is not in the fence's exclusion list (fenced or
    ///    removed from the roster). Returns [`TransitionError::ProposerFenced`]
    ///    when the proposer has been evicted.
    /// 2. The proposal's `from_epoch` is not stale relative to the fence
    ///    epoch. Returns [`TransitionError::StaleEpoch`] when the proposal
    ///    epoch is below the current fence.
    ///
    /// This is the recommended entry point for inbound proposal dispatch
    /// when an epoch fence is wired into the receive path. Without the
    /// fence, use [`validate_proposal`] directly.
    ///
    /// # Errors
    ///
    /// Same as [`validate_proposal`], plus:
    /// - [`TransitionError::ProposerFenced`] when the proposer is fenced.
    /// - [`TransitionError::StaleEpoch`] when the proposal epoch is stale.
    pub fn validate_proposal_against_fence(
        &self,
        proposal: &EpochTransitionProposal,
        verifying_keys: &BTreeMap<MemberId, PublicKey>,
        alive_members: &[MemberId],
        detector: &FailureDetector,
        fence: &MembershipEpochFence,
    ) -> Result<(), TransitionError> {
        // Base validation first.
        self.validate_proposal(proposal, verifying_keys, alive_members, detector)?;

        // Fence check: the proposer must not be fenced or removed.
        if !fence.contains(proposal.proposer) {
            return Err(TransitionError::ProposerFenced(proposal.proposer));
        }

        // Epoch freshness: the proposal must not carry a stale epoch.
        let fence_epoch = fence.current_epoch();
        if proposal.from_epoch.0 < fence_epoch.0 {
            return Err(TransitionError::StaleEpoch {
                proposal_epoch: proposal.from_epoch,
                fence_epoch,
            });
        }

        Ok(())
    }

    /// Create an accept for a proposal (Phase 2).
    pub fn accept(
        &mut self,
        proposal: &EpochTransitionProposal,
        acceptor: MemberId,
        alive_voters: &[MemberId],
        signing_key: &Keypair,
    ) -> Result<EpochTransitionAccept, TransitionError> {
        // Don't accept our own proposal twice
        if self.my_accepts.contains_key(&proposal.proposal_id) {
            return Err(TransitionError::AlreadyAccepted(proposal.proposal_id));
        }

        // Compute the resulting voter set after the transition
        let mut resulting: Vec<MemberId> = alive_voters.to_vec();
        resulting.retain(|v| !proposal.members_removed.contains(v));
        for m in &proposal.members_added {
            if !resulting.contains(m) {
                resulting.push(*m);
            }
        }
        resulting.sort();

        let mut accept = EpochTransitionAccept {
            proposal_id: proposal.proposal_id,
            acceptor,
            accepted_at_millis: now_millis(),
            resulting_voter_set: resulting,
            signature: Vec::new(),
        };
        accept.sign(signing_key);

        // Record locally
        if let Some(state) = self.active_proposals.get_mut(&proposal.proposal_id) {
            state.accepts.push(accept.clone());
        }
        self.my_accepts.insert(proposal.proposal_id, accept.clone());

        Ok(accept)
    }

    /// Record an accept from another node.
    pub fn record_accept(
        &mut self,
        accept: EpochTransitionAccept,
        verifying_keys: &BTreeMap<MemberId, PublicKey>,
    ) -> Result<AcceptanceStatus, TransitionError> {
        let vk = verifying_keys
            .get(&accept.acceptor)
            .ok_or(TransitionError::UnknownProposer(accept.acceptor))?;
        if !accept.verify(vk) {
            return Err(TransitionError::InvalidSignature);
        }

        let total_voters = self.current_voter_count();
        let required = (total_voters / 2) + 1;

        let state = self
            .active_proposals
            .get_mut(&accept.proposal_id)
            .ok_or(TransitionError::UnknownProposal(accept.proposal_id))?;

        // Don't double-count
        if state.accepts.iter().any(|a| a.acceptor == accept.acceptor) {
            return Ok(AcceptanceStatus::Duplicate);
        }

        state.accepts.push(accept);

        if state.accepts.len() >= required {
            Ok(AcceptanceStatus::QuorumReached {
                accepts_count: state.accepts.len(),
                required,
            })
        } else {
            Ok(AcceptanceStatus::Pending {
                accepts_count: state.accepts.len(),
                required,
            })
        }
    }

    /// Create a commit after quorum is reached (Phase 3).
    pub fn commit(
        &mut self,
        proposal_id: u64,
        signing_key: &Keypair,
    ) -> Result<EpochTransitionCommit, TransitionError> {
        let (_accepts_count, proposal, accept_receipts) = {
            let state = self
                .active_proposals
                .get(&proposal_id)
                .ok_or(TransitionError::UnknownProposal(proposal_id))?;

            let total_voters = self.current_voter_count();
            let required = (total_voters / 2) + 1;
            if state.accepts.len() < required {
                return Err(TransitionError::InsufficientAccepts {
                    got: state.accepts.len(),
                    required,
                });
            }

            let receipts: Vec<u64> = state
                .accepts
                .iter()
                .map(|a| a.acceptor.0.wrapping_mul(a.accepted_at_millis))
                .collect();

            (state.accepts.len(), state.proposal.clone(), receipts)
        };

        let new_epoch = proposal.to_epoch;

        let mut commit = EpochTransitionCommit {
            proposal_id,
            new_epoch,
            accept_receipts,
            committed_at_millis: now_millis(),
            proposer_signature: Vec::new(),
        };
        commit.sign(signing_key);

        // Apply the commit locally
        self.apply_commit_local(&commit, &proposal);

        Ok(commit)
    }

    /// Process a commit received from another node.
    pub fn receive_commit(
        &mut self,
        commit: &EpochTransitionCommit,
        verifying_keys: &BTreeMap<MemberId, PublicKey>,
        detector: &mut FailureDetector,
    ) -> Result<AppliedTransition, TransitionError> {
        // Don't re-apply
        if self.applied_commits.contains_key(&commit.new_epoch) {
            return Err(TransitionError::EpochAlreadyApplied(commit.new_epoch));
        }

        // Find the proposal
        let proposal = self
            .active_proposals
            .get(&commit.proposal_id)
            .map(|s| s.proposal.clone())
            .ok_or(TransitionError::UnknownProposal(commit.proposal_id))?;

        // Verify signature
        let vk = verifying_keys
            .get(&proposal.proposer)
            .ok_or(TransitionError::UnknownProposer(proposal.proposer))?;
        if !commit.verify(vk) {
            return Err(TransitionError::InvalidSignature);
        }

        // Apply the epoch transition
        self.apply_commit_local(commit, &proposal);

        // Update failure detector: remove departed members, update classes
        for member_id in &proposal.members_removed {
            detector.remove_peer(*member_id);
        }

        let applied = AppliedTransition {
            from_epoch: proposal.from_epoch,
            to_epoch: commit.new_epoch,
            reason: proposal.reason,
            members_added: proposal.members_added.clone(),
            members_removed: proposal.members_removed.clone(),
            committed_at_millis: commit.committed_at_millis,
        };

        Ok(applied)
    }

    fn apply_commit_local(
        &mut self,
        commit: &EpochTransitionCommit,
        proposal: &EpochTransitionProposal,
    ) {
        self.applied_commits
            .insert(commit.new_epoch, commit.clone());

        let state = self.active_proposals.get(&proposal.proposal_id);
        let acceptance_count = state.map(|s| s.accepts.len()).unwrap_or(0);

        self.transition_history.push(CompletedTransition {
            from_epoch: proposal.from_epoch,
            to_epoch: commit.new_epoch,
            reason: proposal.reason,
            members_added: proposal.members_added.clone(),
            members_removed: proposal.members_removed.clone(),
            acceptance_count,
            committed_at_millis: commit.committed_at_millis,
        });

        self.current_epoch = commit.new_epoch;

        // Set config class based on transition
        self.config_class = match proposal.reason {
            TransitionReason::JoinRequested | TransitionReason::PromotedToVoter => {
                ConfigClass::Joint
            }
            TransitionReason::FailureDetected | TransitionReason::DemotedFromVoter => {
                ConfigClass::Normal
            }
            TransitionReason::GracefulLeave => ConfigClass::Normal,
        };

        // Mark proposal as committed and clean up old proposals
        if let Some(state) = self.active_proposals.get_mut(&proposal.proposal_id) {
            state.committed = true;
        }
        self.active_proposals
            .retain(|_, s| s.proposal.from_epoch >= self.current_epoch);
    }

    /// Get the current voter count from the engine's perspective.
    fn current_voter_count(&self) -> usize {
        self.voter_count
    }

    /// Set the voter count for quorum computation.
    pub fn set_voter_count(&mut self, count: usize) {
        self.voter_count = count;
    }

    /// Check if the given proposal_id is known.
    pub fn has_proposal(&self, proposal_id: u64) -> bool {
        self.active_proposals.contains_key(&proposal_id)
    }

    /// Get accepts count for a proposal.
    pub fn accepts_count(&self, proposal_id: u64) -> usize {
        self.active_proposals
            .get(&proposal_id)
            .map(|s| s.accepts.len())
            .unwrap_or(0)
    }

    /// Cancel a specific proposal by ID.
    ///
    /// Removes the proposal from the active set and any locally recorded
    /// accept for it. Returns `true` if the proposal was found and cancelled.
    ///
    /// A cancelled proposal cannot be committed or receive further votes.
    /// This is used when the proposer has been fenced or the proposal
    /// itself is determined to be stale.
    pub fn cancel_proposal(&mut self, proposal_id: u64) -> bool {
        self.my_accepts.remove(&proposal_id);
        self.active_proposals.remove(&proposal_id).is_some()
    }

    /// Cancel all active (non-committed) proposals from a fenced peer.
    ///
    /// When the fencing watchdog determines a peer is unresponsive and
    /// fences it, any in-flight epoch transition proposals from that peer
    /// must be cancelled so they cannot reach quorum. This method scans the
    /// active proposals for any where the proposer matches `fenced_peer`
    /// and cancels them.
    ///
    /// Returns the number of proposals that were cancelled.
    ///
    /// Already-committed proposals are not affected (they have already
    /// been applied and are retained for audit history only).
    pub fn cancel_proposals_from_fenced_peer(&mut self, fenced_peer: MemberId) -> usize {
        let to_cancel: Vec<u64> = self
            .active_proposals
            .iter()
            .filter(|(_, state)| state.proposal.proposer == fenced_peer && !state.committed)
            .map(|(id, _)| *id)
            .collect();

        let count = to_cancel.len();
        for id in to_cancel {
            self.cancel_proposal(id);
        }
        count
    }

    /// Return the active proposal ID for a given proposer, if any.
    ///
    /// Useful for checking whether a proposer has an in-flight proposal
    /// before creating a new one or before fencing.
    #[must_use]
    pub fn active_proposal_from(&self, proposer: MemberId) -> Option<u64> {
        self.active_proposals
            .iter()
            .find(|(_, state)| state.proposal.proposer == proposer && !state.committed)
            .map(|(id, _)| *id)
    }
}

#[derive(Debug, Clone)]
pub struct AppliedTransition {
    pub from_epoch: EpochId,
    pub to_epoch: EpochId,
    pub reason: TransitionReason,
    pub members_added: Vec<MemberId>,
    pub members_removed: Vec<MemberId>,
    pub committed_at_millis: u64,
}

#[derive(Debug)]
pub enum AcceptanceStatus {
    Pending {
        accepts_count: usize,
        required: usize,
    },
    QuorumReached {
        accepts_count: usize,
        required: usize,
    },
    Duplicate,
}

#[derive(Debug, thiserror::Error)]
pub enum TransitionError {
    #[error("epoch mismatch: expected {expected:?}, got {got:?}")]
    EpochMismatch { expected: EpochId, got: EpochId },
    #[error("unknown proposer {0:?}")]
    UnknownProposer(MemberId),
    #[error("proposer is not alive: {0:?}")]
    ProposerNotAlive(MemberId),
    #[error("proposer is not a voter: {0:?}")]
    ProposerNotVoter(MemberId),
    /// Proposer has been fenced or removed from the roster.
    #[error("proposer has been fenced: {0:?}")]
    ProposerFenced(MemberId),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("insufficient validation for failure-based transition")]
    InsufficientValidation,
    #[error("already accepted proposal {0}")]
    AlreadyAccepted(u64),
    #[error("unknown proposal {0}")]
    UnknownProposal(u64),
    #[error("insufficient accepts: got {got}, required {required}")]
    InsufficientAccepts { got: usize, required: usize },
    #[error("epoch already applied: {0:?}")]
    EpochAlreadyApplied(EpochId),
    /// The proposal carries a stale epoch relative to the membership fence.
    #[error("stale proposal epoch {proposal_epoch:?} below fence epoch {fence_epoch:?}")]
    StaleEpoch {
        proposal_epoch: EpochId,
        fence_epoch: EpochId,
    },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;
    use tidefs_membership_epoch::{EpochId, MemberClass, MemberId};

    fn make_keypair() -> Keypair {
        let mut csprng = OsRng;
        Keypair::generate(&mut csprng)
    }

    macro_rules! propose {
        (
            $engine:expr,
            $proposer:expr,
            $members_added:expr,
            $members_removed:expr,
            $reason:expr,
            $validation:expr,
            $fence_token:expr,
            $signing_key:expr $(,)?
        ) => {
            $engine.propose(EpochTransitionProposalRequest::new(
                $proposer,
                $members_added,
                $members_removed,
                $reason,
                $validation,
                $fence_token,
                $signing_key,
            ))
        };
    }

    #[test]
    fn test_propose_accept_commit_cycle() {
        let kp = make_keypair();
        let verifying_key = kp.public;
        let mut keys = BTreeMap::new();
        keys.insert(MemberId::new(1), verifying_key);

        let mut engine = EpochTransitionEngine::new(EpochId::new(1));
        engine.set_voter_count(1);

        // Phase 1: Propose
        let proposal = propose!(
            engine,
            MemberId::new(1),
            vec![],
            vec![],
            TransitionReason::GracefulLeave,
            vec![],
            None,
            &kp,
        );
        assert_eq!(proposal.from_epoch, EpochId::new(1));
        assert_eq!(proposal.to_epoch, EpochId::new(2));

        // Phase 2: Accept
        let alive_voters = vec![MemberId::new(1)];
        let accept = engine
            .accept(&proposal, MemberId::new(1), &alive_voters, &kp)
            .expect("accept");
        assert_eq!(accept.proposal_id, proposal.proposal_id);

        // Phase 3: Commit
        let commit = engine.commit(proposal.proposal_id, &kp).expect("commit");
        assert_eq!(commit.new_epoch, EpochId::new(2));
        assert_eq!(engine.current_epoch(), EpochId::new(2));
    }

    #[test]
    fn test_epoch_advances_on_transition() {
        let kp = make_keypair();
        let verifying_key = kp.public;
        let mut keys = BTreeMap::new();
        keys.insert(MemberId::new(1), verifying_key);

        let mut engine = EpochTransitionEngine::new(EpochId::new(10));
        engine.set_voter_count(1);

        let proposal = propose!(
            engine,
            MemberId::new(1),
            vec![],
            vec![],
            TransitionReason::GracefulLeave,
            vec![],
            None,
            &kp,
        );
        let alive = vec![MemberId::new(1)];
        engine.accept(&proposal, MemberId::new(1), &alive, &kp).ok();
        engine.commit(proposal.proposal_id, &kp).ok();

        assert_eq!(engine.current_epoch(), EpochId::new(11));
        assert_eq!(engine.transition_history.len(), 1);
    }

    #[test]
    fn test_failure_transition_requires_validation() {
        let kp = make_keypair();
        let verifying_key = kp.public;
        let mut keys = BTreeMap::new();
        keys.insert(MemberId::new(1), verifying_key);

        let mut engine = EpochTransitionEngine::new(EpochId::new(1));
        engine.set_voter_count(1);

        let proposal = propose!(
            engine,
            MemberId::new(1),
            vec![],
            vec![MemberId::new(3)],
            TransitionReason::FailureDetected,
            vec![], // no validation
            None,
            &kp,
        );

        let mut detector = FailureDetector::new(MembershipConfig::default(), make_keypair());
        detector.register_peer(MemberId::new(1), MemberClass::Voter, 1, EpochId::new(1));

        let result = engine.validate_proposal(&proposal, &keys, &[MemberId::new(1)], &detector);
        assert!(result.is_err());
    }

    #[test]
    fn test_cannot_accept_twice() {
        let kp = make_keypair();
        let mut engine = EpochTransitionEngine::new(EpochId::new(1));
        engine.set_voter_count(1);

        let proposal = propose!(
            engine,
            MemberId::new(1),
            vec![],
            vec![],
            TransitionReason::GracefulLeave,
            vec![],
            None,
            &kp,
        );
        let alive = vec![MemberId::new(1)];
        engine.accept(&proposal, MemberId::new(1), &alive, &kp).ok();
        let result = engine.accept(&proposal, MemberId::new(1), &alive, &kp);
        assert!(result.is_err());
    }

    #[test]
    fn test_quorum_requires_majority() {
        let kp1 = make_keypair();
        let kp2 = make_keypair();
        let kp3 = make_keypair();

        let mut keys = BTreeMap::new();
        keys.insert(MemberId::new(1), kp1.public);
        keys.insert(MemberId::new(2), kp2.public);
        keys.insert(MemberId::new(3), kp3.public);

        let mut engine = EpochTransitionEngine::new(EpochId::new(1));
        engine.set_voter_count(3);

        let proposal = propose!(
            engine,
            MemberId::new(1),
            vec![],
            vec![],
            TransitionReason::GracefulLeave,
            vec![],
            None,
            &kp1,
        );
        let alive = vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)];

        // 1 accept is not enough (need 2 for 3 voters)
        let accept2 = EpochTransitionAccept {
            proposal_id: proposal.proposal_id,
            acceptor: MemberId::new(2),
            accepted_at_millis: now_millis(),
            resulting_voter_set: alive.clone(),
            signature: Vec::new(),
        };
        let mut a2 = accept2.clone();
        a2.sign(&kp2);

        let status = engine.record_accept(a2, &keys).expect("record accept");
        assert!(matches!(status, AcceptanceStatus::Pending { .. }));

        // 2nd accept reaches quorum
        let mut a3 = accept2.clone();
        a3.acceptor = MemberId::new(3);
        a3.sign(&kp3);

        let status = engine.record_accept(a3, &keys).expect("record accept");
        assert!(matches!(status, AcceptanceStatus::QuorumReached { .. }));

        // Now can commit
        assert!(engine.commit(proposal.proposal_id, &kp1).is_ok());
    }

    // ── Fence-aware proposal validation tests ───────────────────────

    #[test]
    fn test_validate_against_fence_rejects_fenced_proposer() {
        let kp = make_keypair();
        let verifying_key = kp.public;
        let mut keys = BTreeMap::new();
        keys.insert(MemberId::new(1), verifying_key);

        let mut engine = EpochTransitionEngine::new(EpochId::new(5));

        // Create a fence where member 1 is NOT in the roster.
        let fence = MembershipEpochFence::new();
        let view = crate::epoch_coordinator::EpochView::new(
            EpochId::new(5),
            vec![MemberId::new(2), MemberId::new(3)], // proposer (1) is fenced/removed
            1000,
        );
        fence.update_from_view(&view);

        let mut detector = FailureDetector::new(MembershipConfig::default(), make_keypair());
        detector.register_peer(MemberId::new(1), MemberClass::Voter, 1, EpochId::new(5));

        let proposal = propose!(
            engine,
            MemberId::new(1),
            vec![],
            vec![],
            TransitionReason::GracefulLeave,
            vec![],
            None,
            &kp,
        );

        let result = engine.validate_proposal_against_fence(
            &proposal,
            &keys,
            &[MemberId::new(1)],
            &detector,
            &fence,
        );
        match result {
            Err(TransitionError::ProposerFenced(id)) => {
                assert_eq!(id, MemberId::new(1));
            }
            other => panic!("expected ProposerFenced, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_against_fence_rejects_stale_epoch() {
        let kp = make_keypair();
        let verifying_key = kp.public;
        let mut keys = BTreeMap::new();
        keys.insert(MemberId::new(1), verifying_key);

        let mut engine = EpochTransitionEngine::new(EpochId::new(3));

        // Fence is at epoch 7 — proposal from epoch 3 is stale.
        let fence = MembershipEpochFence::new();
        let view = crate::epoch_coordinator::EpochView::new(
            EpochId::new(7),
            vec![MemberId::new(1), MemberId::new(2)],
            1000,
        );
        fence.update_from_view(&view);

        let mut detector = FailureDetector::new(MembershipConfig::default(), make_keypair());
        detector.register_peer(MemberId::new(1), MemberClass::Voter, 1, EpochId::new(5));

        let proposal = propose!(
            engine,
            MemberId::new(1),
            vec![],
            vec![],
            TransitionReason::GracefulLeave,
            vec![],
            None,
            &kp,
        );

        let result = engine.validate_proposal_against_fence(
            &proposal,
            &keys,
            &[MemberId::new(1)],
            &detector,
            &fence,
        );
        match result {
            Err(TransitionError::StaleEpoch {
                proposal_epoch,
                fence_epoch,
            }) => {
                assert_eq!(proposal_epoch, EpochId::new(3));
                assert_eq!(fence_epoch, EpochId::new(7));
            }
            other => panic!("expected StaleEpoch, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_against_fence_accepts_valid_proposal() {
        let kp = make_keypair();
        let verifying_key = kp.public;
        let mut keys = BTreeMap::new();
        keys.insert(MemberId::new(1), verifying_key);

        let mut engine = EpochTransitionEngine::new(EpochId::new(5));

        // Fence at epoch 5 with proposer (1) in the roster.
        let fence = MembershipEpochFence::new();
        let view = crate::epoch_coordinator::EpochView::new(
            EpochId::new(5),
            vec![MemberId::new(1), MemberId::new(2)],
            1000,
        );
        fence.update_from_view(&view);

        let mut detector = FailureDetector::new(MembershipConfig::default(), make_keypair());
        detector.register_peer(MemberId::new(1), MemberClass::Voter, 1, EpochId::new(5));

        let proposal = propose!(
            engine,
            MemberId::new(1),
            vec![],
            vec![],
            TransitionReason::GracefulLeave,
            vec![],
            None,
            &kp,
        );

        let result = engine.validate_proposal_against_fence(
            &proposal,
            &keys,
            &[MemberId::new(1)],
            &detector,
            &fence,
        );
        assert!(
            result.is_ok(),
            "valid proposal should be accepted, got {result:?}"
        );
    }

    #[test]
    fn test_validate_against_fence_rejects_even_if_base_validation_passes() {
        // Demonstrates that fence rejection takes priority after base
        // validation passes. Even when the proposer is alive, a voter,
        // and the signature verifies, a fenced proposer is rejected.
        let kp = make_keypair();
        let verifying_key = kp.public;
        let mut keys = BTreeMap::new();
        keys.insert(MemberId::new(1), verifying_key);

        let mut engine = EpochTransitionEngine::new(EpochId::new(5));

        // Fence does not include proposer 1.
        let fence = MembershipEpochFence::new();
        let view = crate::epoch_coordinator::EpochView::new(
            EpochId::new(5),
            vec![MemberId::new(2), MemberId::new(3)],
            1000,
        );
        fence.update_from_view(&view);

        // Proposer is alive, a voter, epoch matches — base validation passes.
        let mut detector = FailureDetector::new(MembershipConfig::default(), make_keypair());
        detector.register_peer(MemberId::new(1), MemberClass::Voter, 1, EpochId::new(5));

        let proposal = propose!(
            engine,
            MemberId::new(1),
            vec![],
            vec![],
            TransitionReason::GracefulLeave,
            vec![],
            None,
            &kp,
        );

        // Base validation alone would pass.
        assert!(engine
            .validate_proposal(&proposal, &keys, &[MemberId::new(1)], &detector)
            .is_ok());

        // But fence-aware validation rejects.
        let result = engine.validate_proposal_against_fence(
            &proposal,
            &keys,
            &[MemberId::new(1)],
            &detector,
            &fence,
        );
        assert!(matches!(result, Err(TransitionError::ProposerFenced(_))));
    }

    #[test]
    fn test_validate_against_fence_empty_fence_rejects_all() {
        // An empty fence (no members) rejects all proposals.
        let kp = make_keypair();
        let verifying_key = kp.public;
        let mut keys = BTreeMap::new();
        keys.insert(MemberId::new(1), verifying_key);

        let mut engine = EpochTransitionEngine::new(EpochId::new(0));

        let fence = MembershipEpochFence::new(); // empty — no members

        let mut detector = FailureDetector::new(MembershipConfig::default(), make_keypair());
        detector.register_peer(MemberId::new(1), MemberClass::Voter, 1, EpochId::new(0));

        let proposal = propose!(
            engine,
            MemberId::new(1),
            vec![],
            vec![],
            TransitionReason::GracefulLeave,
            vec![],
            None,
            &kp,
        );

        let result = engine.validate_proposal_against_fence(
            &proposal,
            &keys,
            &[MemberId::new(1)],
            &detector,
            &fence,
        );
        assert!(matches!(result, Err(TransitionError::ProposerFenced(_))));
    }

    // ── Proposal cancellation on peer fencing tests ─────────────────

    #[test]
    fn test_cancel_proposal_removes_active_proposal() {
        let kp = make_keypair();
        let mut engine = EpochTransitionEngine::new(EpochId::new(1));
        engine.set_voter_count(1);

        let proposal = propose!(
            engine,
            MemberId::new(1),
            vec![],
            vec![],
            TransitionReason::GracefulLeave,
            vec![],
            None,
            &kp,
        );
        let pid = proposal.proposal_id;

        assert!(engine.has_proposal(pid));
        assert!(engine.cancel_proposal(pid));
        assert!(!engine.has_proposal(pid));
    }

    #[test]
    fn test_cancel_proposal_returns_false_for_unknown() {
        let mut engine = EpochTransitionEngine::new(EpochId::new(1));
        assert!(!engine.cancel_proposal(999));
    }

    #[test]
    fn test_cancel_proposal_removes_local_accept() {
        let kp = make_keypair();
        let mut engine = EpochTransitionEngine::new(EpochId::new(1));
        engine.set_voter_count(1);

        let proposal = propose!(
            engine,
            MemberId::new(1),
            vec![],
            vec![],
            TransitionReason::GracefulLeave,
            vec![],
            None,
            &kp,
        );
        let alive = vec![MemberId::new(1)];
        engine
            .accept(&proposal, MemberId::new(1), &alive, &kp)
            .unwrap();

        assert!(engine.cancel_proposal(proposal.proposal_id));
        // After cancellation, re-accepting should work (no longer already accepted)
        let proposal2 = propose!(
            engine,
            MemberId::new(1),
            vec![],
            vec![],
            TransitionReason::GracefulLeave,
            vec![],
            None,
            &kp,
        );
        let result = engine.accept(&proposal2, MemberId::new(1), &alive, &kp);
        assert!(
            result.is_ok(),
            "should be able to accept new proposal after cancel"
        );
    }

    #[test]
    fn test_cancel_proposals_from_fenced_peer_removes_all() {
        let kp = make_keypair();
        let mut engine = EpochTransitionEngine::new(EpochId::new(1));
        engine.set_voter_count(1);

        // Peer 1 creates two proposals
        let p1 = propose!(
            engine,
            MemberId::new(1),
            vec![],
            vec![],
            TransitionReason::GracefulLeave,
            vec![],
            None,
            &kp,
        );
        let p2 = propose!(
            engine,
            MemberId::new(1),
            vec![MemberId::new(99)],
            vec![],
            TransitionReason::JoinRequested,
            vec![],
            None,
            &kp,
        );

        assert!(engine.has_proposal(p1.proposal_id));
        assert!(engine.has_proposal(p2.proposal_id));

        let cancelled = engine.cancel_proposals_from_fenced_peer(MemberId::new(1));
        assert_eq!(cancelled, 2);
        assert!(!engine.has_proposal(p1.proposal_id));
        assert!(!engine.has_proposal(p2.proposal_id));
    }

    #[test]
    fn test_cancel_proposals_from_fenced_peer_leaves_other_proposers() {
        let kp1 = make_keypair();
        let kp2 = make_keypair();
        let mut engine = EpochTransitionEngine::new(EpochId::new(1));
        engine.set_voter_count(1);

        // Peer 1 proposal
        let p1 = propose!(
            engine,
            MemberId::new(1),
            vec![],
            vec![],
            TransitionReason::GracefulLeave,
            vec![],
            None,
            &kp1,
        );
        // Peer 2 proposal
        let p2 = propose!(
            engine,
            MemberId::new(2),
            vec![],
            vec![],
            TransitionReason::GracefulLeave,
            vec![],
            None,
            &kp2,
        );

        // Cancel peer 1 only
        let cancelled = engine.cancel_proposals_from_fenced_peer(MemberId::new(1));
        assert_eq!(cancelled, 1);
        assert!(!engine.has_proposal(p1.proposal_id));
        assert!(
            engine.has_proposal(p2.proposal_id),
            "peer 2's proposal should survive"
        );
    }

    #[test]
    fn test_cancel_proposals_no_match_returns_zero() {
        let kp = make_keypair();
        let mut engine = EpochTransitionEngine::new(EpochId::new(1));
        engine.set_voter_count(1);

        propose!(
            engine,
            MemberId::new(1),
            vec![],
            vec![],
            TransitionReason::GracefulLeave,
            vec![],
            None,
            &kp,
        );

        let cancelled = engine.cancel_proposals_from_fenced_peer(MemberId::new(99));
        assert_eq!(cancelled, 0);
    }

    #[test]
    fn test_cancel_does_not_affect_committed_proposal() {
        let kp = make_keypair();
        let mut engine = EpochTransitionEngine::new(EpochId::new(1));
        engine.set_voter_count(1);

        let proposal = propose!(
            engine,
            MemberId::new(1),
            vec![],
            vec![],
            TransitionReason::GracefulLeave,
            vec![],
            None,
            &kp,
        );
        let alive = vec![MemberId::new(1)];
        engine
            .accept(&proposal, MemberId::new(1), &alive, &kp)
            .unwrap();
        engine.commit(proposal.proposal_id, &kp).unwrap();

        // After commit, the proposal is in transition_history, not active_proposals.
        // Cancellation should return 0 because there are no active proposals from peer 1.
        let cancelled = engine.cancel_proposals_from_fenced_peer(MemberId::new(1));
        assert_eq!(cancelled, 0);
        // Transition history still records the committed transition.
        assert_eq!(engine.transition_history.len(), 1);
    }

    #[test]
    fn test_active_proposal_from_returns_correct_id() {
        let kp1 = make_keypair();
        let mut engine = EpochTransitionEngine::new(EpochId::new(1));
        engine.set_voter_count(1);

        let p = propose!(
            engine,
            MemberId::new(1),
            vec![],
            vec![],
            TransitionReason::GracefulLeave,
            vec![],
            None,
            &kp1,
        );

        assert_eq!(
            engine.active_proposal_from(MemberId::new(1)),
            Some(p.proposal_id)
        );
        assert_eq!(engine.active_proposal_from(MemberId::new(2)), None);
    }

    #[test]
    fn test_active_proposal_from_none_after_commit() {
        let kp = make_keypair();
        let mut engine = EpochTransitionEngine::new(EpochId::new(1));
        engine.set_voter_count(1);

        let proposal = propose!(
            engine,
            MemberId::new(1),
            vec![],
            vec![],
            TransitionReason::GracefulLeave,
            vec![],
            None,
            &kp,
        );
        let alive = vec![MemberId::new(1)];
        engine
            .accept(&proposal, MemberId::new(1), &alive, &kp)
            .unwrap();
        engine.commit(proposal.proposal_id, &kp).unwrap();

        assert_eq!(engine.active_proposal_from(MemberId::new(1)), None);
    }
}
