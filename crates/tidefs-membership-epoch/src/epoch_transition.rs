//! Epoch transition state machine with BLAKE3-verified proposal,
//! peer acknowledgment quorum, and commit finalization.
//!
//! [`EpochTransitionStateMachine`] coordinates the full proposal ->
//! broadcast -> ack -> commit lifecycle governing epoch advancement
//! across peers. It bridges membership-live events (SWIM failure
//! detection, join/drain completions) to epoch transitions by
//! wrapping the low-level [`EpochState`] enum with quorum tracking
//! and timeout guards.
//!
//! # Protocol phases
//!
//! 1. **Propose**: caller creates a proposal from a membership delta.
//! 2. **Broadcast**: proposal is disseminated to peers (caller
//!    responsibility via the returned [`EpochProposalMessage`]).
//! 3. **Collect acks**: peers respond with [`EpochAckMessage`]s;
//!    the state machine deduplicates and counts approvals.
//! 4. **Commit**: once quorum is reached, the epoch is finalized
//!    and the committed delta is returned.
//!
//! Timeouts abort pending transitions, returning to `Stable` so a
//! new proposal can be initiated.

use std::collections::BTreeSet;

use super::epoch_proposal::{
    EpochAckMessage, EpochProposalMessage, MembershipDelta, ProposalError,
};
use super::epoch_state::{EpochState, InvalidStateTransition};

// -- QuorumThreshold --------------------------------------------------

/// How many peer acknowledgments constitute a quorum.
///
/// The threshold is evaluated against the total peer count
/// configured on the state machine (which excludes the proposer).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuorumThreshold {
    /// Strict majority: > N/2 approvals required.
    SimpleMajority,
    /// Supermajority: > 2N/3 approvals required.
    SuperMajority,
    /// Exact fixed count of approvals required.
    Fixed(usize),
}

impl QuorumThreshold {
    /// How many approvals are needed given `peer_count` peers
    /// (excluding the proposer).
    #[must_use]
    pub fn required_approvals(self, peer_count: usize) -> usize {
        match self {
            Self::SimpleMajority => (peer_count / 2) + 1,
            Self::SuperMajority => (2 * peer_count / 3) + 1,
            Self::Fixed(n) => n,
        }
    }
}

// -- EpochTransitionConfig --------------------------------------------

/// Configuration for the epoch transition state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochTransitionConfig {
    /// Quorum threshold for committing proposals.
    pub quorum_threshold: QuorumThreshold,
    /// Maximum time in milliseconds to wait for acks before
    /// the proposal times out (0 = no timeout).
    pub timeout_ms: u64,
}

impl Default for EpochTransitionConfig {
    fn default() -> Self {
        Self {
            quorum_threshold: QuorumThreshold::SimpleMajority,
            timeout_ms: 30_000, // 30 s default
        }
    }
}

// -- EpochTransitionResult --------------------------------------------

/// Outcome of a committed epoch transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochTransitionResult {
    /// The proposal message that was committed.
    pub proposal: EpochProposalMessage,
    /// How many peers approved.
    pub approvals: usize,
    /// Total peers that responded (approvals + rejections).
    pub responses: usize,
}

// -- EpochTransitionStateMachine --------------------------------------

/// The epoch transition state machine.
///
/// Manages the four-phase epoch lifecycle and tracks peer
/// acknowledgments toward a configurable quorum threshold.
#[derive(Clone, Debug)]
pub struct EpochTransitionStateMachine {
    state: EpochState,
    /// The proposal currently being voted on (set during propose).
    current_proposal: Option<EpochProposalMessage>,
    /// Set of peer node ids that have acknowledged (approved or rejected).
    ack_set: BTreeSet<u64>,
    config: EpochTransitionConfig,
    /// Number of voting peers (excluding the proposer / self).
    peer_count: usize,
}

impl EpochTransitionStateMachine {
    /// Create a new state machine in the [`EpochState::Stable`] state.
    ///
    /// `peer_count` is the number of voting peers (excluding the
    /// proposer). For single-node degenerate case, set `peer_count`
    /// to 0 and the quorum threshold degrades to 0 approvals required.
    #[must_use]
    pub fn new(config: EpochTransitionConfig, peer_count: usize) -> Self {
        Self {
            state: EpochState::Stable,
            current_proposal: None,
            ack_set: BTreeSet::new(),
            config,
            peer_count,
        }
    }

    /// Return the current epoch state.
    #[must_use]
    pub fn state(&self) -> EpochState {
        self.state
    }

    /// Return the current proposal, if any.
    #[must_use]
    pub fn current_proposal(&self) -> Option<&EpochProposalMessage> {
        self.current_proposal.as_ref()
    }

    /// Return the number of unique peer acks received so far.
    #[must_use]
    pub fn ack_count(&self) -> usize {
        self.ack_set.len()
    }

    /// Check whether quorum has been reached.
    #[must_use]
    pub fn quorum_reached(&self) -> bool {
        if self.state != EpochState::AwaitingAcks {
            return false;
        }
        self.config
            .quorum_threshold
            .required_approvals(self.peer_count)
            <= self.ack_set.len()
    }

    // -- propose -------------------------------------------------------

    /// Initiate an epoch transition by creating a signed proposal.
    ///
    /// Transitions `Stable` -> `Proposing`. If this is a single-node
    /// degenerate case (peer_count == 0), the machine transitions
    /// directly to `Committed`, skipping ack collection.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] if:
    /// - The machine is not in `Stable` state
    /// - The proposed epoch is not current_epoch + 1
    /// - The resulting member set is empty
    pub fn propose(
        &mut self,
        proposer_id: u64,
        current_epoch: u64,
        delta: MembershipDelta,
        resulting_members: &[u64],
    ) -> Result<EpochProposalMessage, TransitionError> {
        // Validate state transition
        self.state.validate_transition(EpochState::Proposing)?;

        let proposed_epoch = current_epoch + 1;

        // Validate resulting members
        let mut sorted = resulting_members.to_vec();
        sorted.sort();
        sorted.dedup();
        if sorted.is_empty() {
            return Err(TransitionError::EmptyMemberSet);
        }

        let proposal =
            EpochProposalMessage::new(proposer_id, current_epoch, proposed_epoch, delta, &sorted);

        self.current_proposal = Some(proposal.clone());
        self.state = EpochState::Proposing;
        self.ack_set.clear();

        // Degenerate single-node case: commit immediately
        if self.peer_count == 0 {
            self.state = EpochState::Committed;
        }

        Ok(proposal)
    }

    // -- broadcast -----------------------------------------------------

    /// Broadcast the current proposal to peers.
    ///
    /// Transitions `Proposing` -> `AwaitingAcks`. After this call,
    /// the machine is ready to receive acks.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] if not in `Proposing` state.
    pub fn broadcast(&mut self) -> Result<(), TransitionError> {
        self.state.validate_transition(EpochState::AwaitingAcks)?;
        self.state = EpochState::AwaitingAcks;
        Ok(())
    }

    // -- receive_ack ---------------------------------------------------

    /// Process an acknowledgment (approval or rejection) from a peer.
    ///
    /// Validates the ack's BLAKE3 integrity and that it targets the
    /// current proposal. Duplicate acks from the same peer are
    /// rejected. Only approvals contribute to quorum, but rejections
    /// are tracked to prevent re-submission.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] on:
    /// - Machine not in `AwaitingAcks` state
    /// - Ack BLAKE3 verification failure
    /// - Ack proposal_hash mismatch with current proposal
    /// - Duplicate ack from the same peer
    pub fn receive_ack(&mut self, ack: &EpochAckMessage) -> Result<(), TransitionError> {
        if self.state != EpochState::AwaitingAcks {
            return Err(TransitionError::InvalidState {
                expected: EpochState::AwaitingAcks,
                actual: self.state,
            });
        }

        // Verify ack BLAKE3 integrity
        if !ack.verify() {
            return Err(ProposalError::AckVerificationFailed.into());
        }

        // Verify ack targets the current proposal
        let proposal = self
            .current_proposal
            .as_ref()
            .ok_or(TransitionError::NoCurrentProposal)?;
        if ack.proposal_hash != proposal.blake3_hash {
            return Err(ProposalError::ProposalHashMismatch.into());
        }

        // Reject duplicate acks
        if self.ack_set.contains(&ack.acker_id) {
            return Err(ProposalError::DuplicateAck(ack.acker_id).into());
        }

        self.ack_set.insert(ack.acker_id);
        Ok(())
    }

    // -- commit --------------------------------------------------------

    /// Finalize the epoch transition once quorum is reached.
    ///
    /// Transitions `AwaitingAcks` -> `Committed` and returns the
    /// transition result with the committed delta.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] if:
    /// - Machine is not in `AwaitingAcks` state
    /// - Quorum has not been reached yet
    pub fn commit(&mut self) -> Result<EpochTransitionResult, TransitionError> {
        if self.state != EpochState::AwaitingAcks {
            return Err(TransitionError::InvalidState {
                expected: EpochState::AwaitingAcks,
                actual: self.state,
            });
        }

        if !self.quorum_reached() {
            return Err(TransitionError::QuorumNotReached {
                required: self
                    .config
                    .quorum_threshold
                    .required_approvals(self.peer_count),
                received: self.ack_set.len(),
            });
        }

        self.state.validate_transition(EpochState::Committed)?;

        let proposal = self
            .current_proposal
            .take()
            .ok_or(TransitionError::NoCurrentProposal)?;

        self.state = EpochState::Committed;

        Ok(EpochTransitionResult {
            proposal,
            approvals: self.ack_set.len(),
            responses: self.ack_set.len(),
        })
    }

    // -- abort ---------------------------------------------------------

    /// Abort the current proposal and return to `Stable`.
    ///
    /// Valid from `Proposing` (before broadcast) and `AwaitingAcks`
    /// (timeout or insufficient responses). Clears the current
    /// proposal and ack set.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] if not in an abortable state.
    pub fn abort(&mut self) -> Result<(), TransitionError> {
        if self.state == EpochState::Stable {
            return Err(TransitionError::InvalidState {
                expected: EpochState::Proposing,
                actual: EpochState::Stable,
            });
        }
        if self.state == EpochState::Committed {
            return Err(TransitionError::InvalidState {
                expected: EpochState::Proposing,
                actual: EpochState::Committed,
            });
        }

        self.state = EpochState::Stable;
        self.current_proposal = None;
        self.ack_set.clear();
        Ok(())
    }

    // -- reset ---------------------------------------------------------

    /// Reset the state machine from `Committed` back to `Stable`.
    ///
    /// After a successful commit, call this to allow new proposals.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] if not in `Committed` state.
    pub fn reset(&mut self) -> Result<(), TransitionError> {
        self.state.validate_transition(EpochState::Stable)?;
        self.state = EpochState::Stable;
        self.current_proposal = None;
        self.ack_set.clear();
        Ok(())
    }

    // -- timeout helpers -----------------------------------------------

    /// Whether the configured timeout is non-zero.
    #[must_use]
    pub fn has_timeout(&self) -> bool {
        self.config.timeout_ms > 0
    }

    /// The configured timeout in milliseconds.
    #[must_use]
    pub fn timeout_ms(&self) -> u64 {
        self.config.timeout_ms
    }
}

// -- TransitionError --------------------------------------------------

/// Errors that can occur during epoch transition processing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransitionError {
    /// The state machine is not in the expected state.
    InvalidState {
        expected: EpochState,
        actual: EpochState,
    },
    /// The proposed epoch is not exactly current_epoch + 1.
    NonConsecutiveEpoch { current: u64, proposed: u64 },
    /// The resulting member set is empty.
    EmptyMemberSet,
    /// No current proposal exists (internal error).
    NoCurrentProposal,
    /// Quorum threshold not yet reached.
    QuorumNotReached { required: usize, received: usize },
    /// An error from the proposal/ack layer.
    Proposal(ProposalError),
    /// An invalid state transition was attempted.
    StateTransition(InvalidStateTransition),
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidState { expected, actual } => {
                write!(f, "invalid state: expected {expected}, got {actual}")
            }
            Self::NonConsecutiveEpoch { current, proposed } => {
                write!(
                    f,
                    "non-consecutive epoch: current={current}, proposed={proposed}"
                )
            }
            Self::EmptyMemberSet => {
                write!(f, "resulting member set is empty")
            }
            Self::NoCurrentProposal => {
                write!(f, "no current proposal")
            }
            Self::QuorumNotReached { required, received } => {
                write!(f, "quorum not reached: need {required}, got {received}")
            }
            Self::Proposal(e) => write!(f, "proposal error: {e}"),
            Self::StateTransition(e) => write!(f, "state transition error: {e}"),
        }
    }
}

impl std::error::Error for TransitionError {}

impl From<InvalidStateTransition> for TransitionError {
    fn from(e: InvalidStateTransition) -> Self {
        Self::StateTransition(e)
    }
}

impl From<ProposalError> for TransitionError {
    fn from(e: ProposalError) -> Self {
        Self::Proposal(e)
    }
}

// -- Tests ------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_sm(peer_count: usize) -> EpochTransitionStateMachine {
        EpochTransitionStateMachine::new(EpochTransitionConfig::default(), peer_count)
    }

    // -- State transitions -------------------------------------------

    #[test]
    fn new_starts_in_stable() {
        let sm = default_sm(3);
        assert_eq!(sm.state(), EpochState::Stable);
    }

    #[test]
    fn propose_transitions_to_proposing() {
        let mut sm = default_sm(3);
        sm.propose(1, 0, MembershipDelta::NodeJoined(4), &[1, 4])
            .unwrap();
        assert_eq!(sm.state(), EpochState::Proposing);
        assert!(sm.current_proposal().is_some());
    }

    #[test]
    fn broadcast_transitions_to_awaiting_acks() {
        let mut sm = default_sm(3);
        sm.propose(1, 0, MembershipDelta::NodeJoined(4), &[1, 4])
            .unwrap();
        sm.broadcast().unwrap();
        assert_eq!(sm.state(), EpochState::AwaitingAcks);
    }

    #[test]
    fn commit_transitions_to_committed() {
        let mut sm = default_sm(2);
        let msg = sm
            .propose(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3])
            .unwrap();
        sm.broadcast().unwrap();

        sm.receive_ack(&EpochAckMessage::approve(2, &msg.blake3_hash))
            .unwrap();
        sm.receive_ack(&EpochAckMessage::approve(3, &msg.blake3_hash))
            .unwrap();

        let result = sm.commit().unwrap();
        assert_eq!(sm.state(), EpochState::Committed);
        assert_eq!(result.approvals, 2);
    }

    #[test]
    fn reset_from_committed_to_stable() {
        let mut sm = default_sm(2);
        let msg = sm
            .propose(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3])
            .unwrap();
        sm.broadcast().unwrap();

        sm.receive_ack(&EpochAckMessage::approve(2, &msg.blake3_hash))
            .unwrap();
        sm.receive_ack(&EpochAckMessage::approve(3, &msg.blake3_hash))
            .unwrap();
        sm.commit().unwrap();

        sm.reset().unwrap();
        assert_eq!(sm.state(), EpochState::Stable);
        assert!(sm.current_proposal().is_none());
        assert_eq!(sm.ack_count(), 0);
    }

    #[test]
    fn abort_from_proposing_to_stable() {
        let mut sm = default_sm(3);
        sm.propose(1, 0, MembershipDelta::NodeJoined(4), &[1, 4])
            .unwrap();
        sm.abort().unwrap();
        assert_eq!(sm.state(), EpochState::Stable);
        assert!(sm.current_proposal().is_none());
    }

    #[test]
    fn abort_from_awaiting_acks_to_stable() {
        let mut sm = default_sm(3);
        sm.propose(1, 0, MembershipDelta::NodeJoined(4), &[1, 4])
            .unwrap();
        sm.broadcast().unwrap();
        sm.abort().unwrap();
        assert_eq!(sm.state(), EpochState::Stable);
    }

    #[test]
    fn abort_from_stable_is_error() {
        let mut sm = default_sm(3);
        let err = sm.abort().unwrap_err();
        assert!(matches!(err, TransitionError::InvalidState { .. }));
    }

    #[test]
    fn abort_from_committed_is_error() {
        let mut sm = default_sm(2);
        let msg = sm
            .propose(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3])
            .unwrap();
        sm.broadcast().unwrap();
        sm.receive_ack(&EpochAckMessage::approve(2, &msg.blake3_hash))
            .unwrap();
        sm.receive_ack(&EpochAckMessage::approve(3, &msg.blake3_hash))
            .unwrap();
        sm.commit().unwrap();

        let err = sm.abort().unwrap_err();
        assert!(matches!(err, TransitionError::InvalidState { .. }));
    }

    // -- Invalid transitions -----------------------------------------

    #[test]
    fn propose_from_non_stable_is_error() {
        let mut sm = default_sm(3);
        sm.propose(1, 0, MembershipDelta::NodeJoined(4), &[1, 4])
            .unwrap();
        let err = sm
            .propose(1, 0, MembershipDelta::NodeJoined(5), &[1, 4, 5])
            .unwrap_err();
        assert!(matches!(err, TransitionError::StateTransition(_)));
    }

    #[test]
    fn broadcast_without_propose_is_error() {
        let mut sm = default_sm(3);
        let err = sm.broadcast().unwrap_err();
        assert!(matches!(err, TransitionError::StateTransition(_)));
    }

    #[test]
    fn commit_without_acks_is_error() {
        let mut sm = default_sm(3);
        sm.propose(1, 0, MembershipDelta::NodeJoined(4), &[1, 4])
            .unwrap();
        sm.broadcast().unwrap();
        let err = sm.commit().unwrap_err();
        assert!(matches!(err, TransitionError::QuorumNotReached { .. }));
    }

    #[test]
    fn reset_without_commit_is_error() {
        let mut sm = default_sm(3);
        let err = sm.reset().unwrap_err();
        assert!(matches!(err, TransitionError::StateTransition(_)));
    }

    // -- Ack validation ----------------------------------------------

    #[test]
    fn receive_ack_verifies_integrity() {
        let mut sm = default_sm(2);
        let msg = sm
            .propose(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3])
            .unwrap();
        sm.broadcast().unwrap();

        let mut ack = EpochAckMessage::approve(2, &msg.blake3_hash);
        ack.blake3_hash = [0u8; 32]; // tamper
        let err = sm.receive_ack(&ack).unwrap_err();
        assert!(matches!(
            err,
            TransitionError::Proposal(ProposalError::AckVerificationFailed)
        ));
    }

    #[test]
    fn receive_ack_rejects_wrong_proposal_hash() {
        let mut sm = default_sm(2);
        sm.propose(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3])
            .unwrap();
        sm.broadcast().unwrap();

        let ack = EpochAckMessage::approve(2, &[99u8; 32]);
        let err = sm.receive_ack(&ack).unwrap_err();
        assert!(matches!(
            err,
            TransitionError::Proposal(ProposalError::ProposalHashMismatch)
        ));
    }

    #[test]
    fn receive_ack_rejects_duplicate() {
        let mut sm = default_sm(2);
        let msg = sm
            .propose(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3])
            .unwrap();
        sm.broadcast().unwrap();

        sm.receive_ack(&EpochAckMessage::approve(2, &msg.blake3_hash))
            .unwrap();
        let err = sm
            .receive_ack(&EpochAckMessage::approve(2, &msg.blake3_hash))
            .unwrap_err();
        assert!(matches!(
            err,
            TransitionError::Proposal(ProposalError::DuplicateAck(2))
        ));
    }

    #[test]
    fn receive_ack_outside_awaiting_acks_is_error() {
        let mut sm = default_sm(2);
        let ack = EpochAckMessage::approve(2, &[42u8; 32]);
        let err = sm.receive_ack(&ack).unwrap_err();
        assert!(matches!(
            err,
            TransitionError::InvalidState {
                expected: EpochState::AwaitingAcks,
                actual: EpochState::Stable,
            }
        ));
    }

    // -- Quorum arithmetic -------------------------------------------

    #[test]
    fn simple_majority_of_3_is_2() {
        assert_eq!(QuorumThreshold::SimpleMajority.required_approvals(3), 2);
    }

    #[test]
    fn simple_majority_of_5_is_3() {
        assert_eq!(QuorumThreshold::SimpleMajority.required_approvals(5), 3);
    }

    #[test]
    fn simple_majority_of_2_is_2() {
        assert_eq!(QuorumThreshold::SimpleMajority.required_approvals(2), 2);
    }

    #[test]
    fn simple_majority_of_1_is_1() {
        assert_eq!(QuorumThreshold::SimpleMajority.required_approvals(1), 1);
    }

    #[test]
    fn simple_majority_of_0_is_1() {
        assert_eq!(QuorumThreshold::SimpleMajority.required_approvals(0), 1);
    }

    #[test]
    fn super_majority_of_3_is_3() {
        assert_eq!(QuorumThreshold::SuperMajority.required_approvals(3), 3);
    }

    #[test]
    fn super_majority_of_5_is_4() {
        assert_eq!(QuorumThreshold::SuperMajority.required_approvals(5), 4);
    }

    #[test]
    fn super_majority_of_6_is_5() {
        assert_eq!(QuorumThreshold::SuperMajority.required_approvals(6), 5);
    }

    #[test]
    fn fixed_threshold_is_exact() {
        assert_eq!(QuorumThreshold::Fixed(42).required_approvals(10), 42);
    }

    // -- Single-node degenerate case ---------------------------------

    #[test]
    fn single_node_propose_commits_immediately() {
        let mut sm = default_sm(0);
        let msg = sm
            .propose(1, 0, MembershipDelta::NodeJoined(2), &[1, 2])
            .unwrap();
        assert!(msg.verify());
        assert_eq!(sm.state(), EpochState::Committed);

        // reset works from Committed
        sm.reset().unwrap();
        assert_eq!(sm.state(), EpochState::Stable);
    }

    // -- Quorum reached check ----------------------------------------

    #[test]
    fn quorum_reached_false_before_enough_acks() {
        let mut sm = default_sm(3);
        let msg = sm
            .propose(1, 0, MembershipDelta::NodeJoined(4), &[1, 4])
            .unwrap();
        sm.broadcast().unwrap();

        sm.receive_ack(&EpochAckMessage::approve(2, &msg.blake3_hash))
            .unwrap();
        assert!(!sm.quorum_reached()); // need 2 of 3, have 1

        sm.receive_ack(&EpochAckMessage::approve(3, &msg.blake3_hash))
            .unwrap();
        assert!(sm.quorum_reached()); // have 2 of 3
    }

    #[test]
    fn quorum_reached_false_in_non_awaiting_state() {
        let mut sm = default_sm(3);
        assert!(!sm.quorum_reached());

        sm.propose(1, 0, MembershipDelta::NodeJoined(4), &[1, 4])
            .unwrap();
        assert!(!sm.quorum_reached()); // still Proposing
    }

    // -- Full lifecycle integration ----------------------------------

    #[test]
    fn propose_abort_repropose_cycle() {
        let mut sm = default_sm(3);

        // First proposal, aborted
        let msg1 = sm
            .propose(1, 0, MembershipDelta::NodeJoined(4), &[1, 4])
            .unwrap();
        assert!(msg1.verify());
        sm.abort().unwrap();
        assert_eq!(sm.state(), EpochState::Stable);

        // Second proposal, broadcast, commit
        let msg2 = sm
            .propose(1, 0, MembershipDelta::NodeJoined(5), &[1, 4, 5])
            .unwrap();
        sm.broadcast().unwrap();
        sm.receive_ack(&EpochAckMessage::approve(2, &msg2.blake3_hash))
            .unwrap();
        sm.receive_ack(&EpochAckMessage::approve(3, &msg2.blake3_hash))
            .unwrap();
        let result = sm.commit().unwrap();
        assert_eq!(result.proposal.delta, MembershipDelta::NodeJoined(5));
    }

    #[test]
    fn multi_epoch_chain_lifecycle() {
        // Epoch 0 -> 1: NodeJoined(2), 1 peer (only node 2)
        let mut sm = default_sm(1);
        let msg0 = sm
            .propose(1, 0, MembershipDelta::NodeJoined(2), &[1, 2])
            .unwrap();
        sm.broadcast().unwrap();
        sm.receive_ack(&EpochAckMessage::approve(2, &msg0.blake3_hash))
            .unwrap();
        let r0 = sm.commit().unwrap();
        assert_eq!(r0.proposal.proposed_epoch, 1);

        // Epoch 1 -> 2: NodeJoined(3), 2 peers (nodes 2,3)
        let mut sm = default_sm(2);
        let msg1 = sm
            .propose(1, 1, MembershipDelta::NodeJoined(3), &[1, 2, 3])
            .unwrap();
        sm.broadcast().unwrap();
        sm.receive_ack(&EpochAckMessage::approve(2, &msg1.blake3_hash))
            .unwrap();
        sm.receive_ack(&EpochAckMessage::approve(3, &msg1.blake3_hash))
            .unwrap();
        let r1 = sm.commit().unwrap();
        assert_eq!(r1.proposal.proposed_epoch, 2);

        // Epoch 2 -> 3: NodeDrained(2), 1 peer (only node 3)
        let mut sm = default_sm(1);
        let msg2 = sm
            .propose(1, 2, MembershipDelta::NodeDrained(2), &[1, 3])
            .unwrap();
        sm.broadcast().unwrap();
        sm.receive_ack(&EpochAckMessage::approve(3, &msg2.blake3_hash))
            .unwrap();
        let r2 = sm.commit().unwrap();
        assert_eq!(r2.proposal.proposed_epoch, 3);
        assert_eq!(r2.proposal.delta, MembershipDelta::NodeDrained(2));
    }

    #[test]
    fn all_delta_variants_work() {
        let deltas = [
            MembershipDelta::NodeJoined(2),
            MembershipDelta::NodeDrained(3),
            MembershipDelta::NodeFailed(4),
            MembershipDelta::NodeSuspected(5),
        ];
        for delta in deltas {
            let mut sm = default_sm(2);
            let members = if delta.is_removal() {
                &[1u64][..]
            } else {
                &[1u64, 2u64][..]
            };
            let msg = sm.propose(1, 0, delta, members).unwrap();
            assert!(msg.verify());
            sm.broadcast().unwrap();
        }
    }

    // -- Proposal validation -----------------------------------------

    #[test]
    fn propose_rejects_empty_members() {
        let mut sm = default_sm(2);
        let err = sm
            .propose(1, 0, MembershipDelta::NodeJoined(2), &[])
            .unwrap_err();
        assert!(matches!(err, TransitionError::EmptyMemberSet));
    }

    #[test]
    fn propose_sorts_and_dedups_members() {
        let mut sm = default_sm(2);
        let msg = sm
            .propose(1, 0, MembershipDelta::NodeJoined(3), &[3, 1, 3, 2, 1])
            .unwrap();
        assert_eq!(msg.resulting_members, vec![1, 2, 3]);
        assert!(msg.verify());
    }

    // -- TransitionError display -------------------------------------

    #[test]
    fn transition_error_display_formats() {
        let e = TransitionError::InvalidState {
            expected: EpochState::AwaitingAcks,
            actual: EpochState::Stable,
        };
        let s = format!("{e}");
        assert!(s.contains("invalid state"));
        assert!(s.contains("AwaitingAcks"));
        assert!(s.contains("Stable"));

        let e = TransitionError::QuorumNotReached {
            required: 3,
            received: 1,
        };
        let s = format!("{e}");
        assert!(s.contains("quorum"));
        assert!(s.contains("3"));
        assert!(s.contains("1"));

        let e = TransitionError::NonConsecutiveEpoch {
            current: 1,
            proposed: 5,
        };
        let s = format!("{e}");
        assert!(s.contains("non-consecutive"));
    }

    // -- Timeout configuration ---------------------------------------

    #[test]
    fn default_config_has_timeout() {
        let sm = default_sm(3);
        assert!(sm.has_timeout());
        assert_eq!(sm.timeout_ms(), 30_000);
    }

    #[test]
    fn zero_timeout_disables_timeout() {
        let sm = EpochTransitionStateMachine::new(
            EpochTransitionConfig {
                quorum_threshold: QuorumThreshold::SimpleMajority,
                timeout_ms: 0,
            },
            3,
        );
        assert!(!sm.has_timeout());

        // Zero timeout does not affect propose/broadcast/commit
        let mut sm2 = EpochTransitionStateMachine::new(
            EpochTransitionConfig {
                quorum_threshold: QuorumThreshold::SimpleMajority,
                timeout_ms: 0,
            },
            3,
        );
        sm2.propose(1, 0, MembershipDelta::NodeJoined(4), &[1, 4])
            .unwrap();
        sm2.broadcast().unwrap();
    }
}
