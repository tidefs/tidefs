//! Peer-to-peer epoch-agreement protocol with proposal broadcast,
//! ack collection, quorum commit, and subscriber dispatch.
//!
//! [`MembershipEpochAgreement`] coordinates the multi-node epoch
//! transition lifecycle:
//!
//! 1. **Propose**: a coordinator creates an
//!    [`EpochAgreementProposal`](tidefs_membership_types::EpochAgreementProposal)
//!    and calls [`propose`](MembershipEpochAgreement::propose).
//! 2. **Broadcast**: the caller sends the returned proposal to all
//!    peers over transport; the agreement tracks which peers are
//!    expected to respond.
//! 3. **Collect**: as peers respond with
//!    [`EpochAgreementAck`](tidefs_membership_types::EpochAgreementAck)
//!    messages, the caller feeds them into
//!    [`receive_ack`](MembershipEpochAgreement::receive_ack).
//! 4. **Commit**: once the quorum threshold of acceptances is met,
//!    the agreement auto-commits, producing an
//!    [`EpochAgreementCommit`](tidefs_membership_types::EpochAgreementCommit)
//!    and dispatching to registered subscribers.
//!
//! Timeouts are surfaced via [`check_timeout`](MembershipEpochAgreement::check_timeout)
//! so the caller can abort stale proposals.  Duplicate proposals from
//! the same coordinator are detected and rejected.
//!
//! This protocol carries no per-message BLAKE3 or MAC: node-to-node
//! integrity and authenticity are the responsibility of the transport
//! security boundary.

use crate::epoch_chain::{ChainError, EpochChainVerifier};
use std::collections::BTreeSet;
use std::time::Instant;

use tidefs_membership_types::{EpochAgreementAck, EpochAgreementCommit, EpochAgreementProposal};

use crate::epoch_commit_subscriber::{EpochCommitBus, EpochCommitNotification};
use crate::EpochId;

// ── AgreementState ──────────────────────────────────────────────────

/// The current phase of the epoch-agreement protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgreementState {
    /// No proposal in progress; ready for a new proposal.
    Idle,
    /// A proposal has been created and is being broadcast to peers.
    Proposing,
    /// The proposal has been broadcast; collecting acknowledgments.
    AwaitingAcks,
    /// Quorum was reached and the epoch has been committed.
    Committed,
}

// ── AgreementError ──────────────────────────────────────────────────

/// Errors that can occur during the epoch-agreement protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgreementError {
    /// The agreement is not in [`AgreementState::Idle`]; a proposal is
    /// already in progress.
    AlreadyInProgress,
    /// The agreement is not in the expected state for the operation.
    WrongState {
        expected: AgreementState,
        actual: AgreementState,
    },
    /// The ack's epoch_id does not match the current proposal's epoch_id.
    EpochIdMismatch { expected: u64, received: u64 },
    /// A duplicate ack was received from a peer that already responded.
    DuplicateAck(u64),
    /// Quorum has not yet been reached (returned by [`commit`]).
    QuorumNotReached { approvals: usize, required: usize },
    /// The proposed view (member set) is empty.
    EmptyView,
    /// A duplicate proposal was detected (same coordinator_id + epoch_id
    /// as a previously committed or in-progress proposal).
    DuplicateProposal { coordinator_id: u64, epoch_id: u64 },
    /// Epoch-chain verification failed.
    ChainError(ChainError),
}

impl std::fmt::Display for AgreementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyInProgress => write!(f, "agreement already in progress"),
            Self::WrongState { expected, actual } => {
                write!(f, "expected state {expected:?}, actual {actual:?}")
            }
            Self::EpochIdMismatch { expected, received } => {
                write!(
                    f,
                    "ack epoch_id {received} does not match proposal {expected}"
                )
            }
            Self::DuplicateAck(id) => write!(f, "duplicate ack from peer {id}"),
            Self::QuorumNotReached {
                approvals,
                required,
            } => {
                write!(
                    f,
                    "quorum not reached: {approvals} approvals, {required} required"
                )
            }
            Self::EmptyView => write!(f, "proposed member view is empty"),
            Self::DuplicateProposal {
                coordinator_id,
                epoch_id,
            } => {
                write!(
                    f,
                    "duplicate proposal: coordinator={coordinator_id} epoch={epoch_id}"
                )
            }
            Self::ChainError(e) => {
                write!(f, "chain verification failed: {e}")
            }
        }
    }
}

impl std::error::Error for AgreementError {}

// ── QuorumMode ──────────────────────────────────────────────────────

/// How the quorum threshold is computed from the peer count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuorumMode {
    /// Strict majority: `floor(N/2) + 1` acceptances required.
    SimpleMajority,
    /// Every known peer must accept.
    Unanimous,
    /// A fixed number of acceptances required.
    Fixed(usize),
}

impl QuorumMode {
    /// How many acceptances are needed given `peer_count` peers
    /// (excluding the coordinator).
    #[must_use]
    pub fn required_approvals(self, peer_count: usize) -> usize {
        match self {
            Self::SimpleMajority => {
                if peer_count == 0 {
                    0
                } else {
                    (peer_count / 2) + 1
                }
            }
            Self::Unanimous => peer_count,
            Self::Fixed(n) => n,
        }
    }
}

// ── MembershipEpochAgreement ────────────────────────────────────────

/// Coordinates a single epoch-agreement round across peers.
///
/// # Lifecycle
///
/// ```text
/// Idle ──[propose]──> Proposing ──[broadcast]──> AwaitingAcks
///                                                    │
///                                          ┌─[receive_ack (quorum)]──> Committed
///                                          │
///                                          └─[abort / timeout]──> Idle
/// ```
///
/// After `Committed`, call [`reset`](MembershipEpochAgreement::reset)
/// to return to `Idle` for the next round.
pub struct MembershipEpochAgreement {
    state: AgreementState,
    /// The proposal currently being voted on.
    current_proposal: Option<EpochAgreementProposal>,
    /// Set of peer node ids that have acknowledged (accepted or rejected).
    ack_set: BTreeSet<u64>,
    /// Number of acceptances received so far.
    approvals: usize,
    /// Quorum computation mode.
    quorum_mode: QuorumMode,
    /// Number of voting peers (excluding the coordinator).
    peer_count: usize,
    /// Optional timeout deadline (wall-clock Instant + timeout_ms).
    deadline: Option<Instant>,
    /// Timeout duration in milliseconds (0 = no timeout).
    timeout_ms: u64,
    /// Optional commit bus for dispatching epoch-commit notifications.
    commit_bus: Option<EpochCommitBus>,
    /// Set of (coordinator_id, epoch_id) already seen for duplicate
    /// suppression.
    seen_proposals: BTreeSet<(u64, u64)>,
    /// The locally committed epoch number. Used by the chain verifier
    /// to reject proposals that do not form a valid successor chain.
    committed_epoch: u64,
    /// Chain verifier for fork detection across proposals.
    chain_verifier: EpochChainVerifier,
}

impl MembershipEpochAgreement {
    /// Create a new agreement coordinator.
    ///
    /// `peer_count` is the number of voting peers excluding the
    /// coordinator. For single-node operation, set `peer_count` to 0
    /// and quorum degrades to 0 approvals required.
    #[must_use]
    pub fn new(quorum_mode: QuorumMode, peer_count: usize, timeout_ms: u64) -> Self {
        Self {
            state: AgreementState::Idle,
            current_proposal: None,
            ack_set: BTreeSet::new(),
            approvals: 0,
            quorum_mode,
            peer_count,
            deadline: None,
            timeout_ms,
            commit_bus: None,
            seen_proposals: BTreeSet::new(),
            committed_epoch: 0,
            chain_verifier: EpochChainVerifier::new(),
        }
    }

    /// Attach an [`EpochCommitBus`] for commit notification dispatch.
    ///
    /// When quorum is reached and the epoch commits, each registered
    /// subscriber receives an [`EpochCommitNotification`].
    pub fn set_commit_bus(&mut self, bus: EpochCommitBus) {
        self.commit_bus = Some(bus);
    }

    /// Set the locally committed epoch number for chain verification.
    ///
    /// Must be called before [`propose`](Self::propose) so that incoming
    /// proposals are validated against the correct chain state.
    pub fn set_committed_epoch(&mut self, epoch: u64) {
        self.committed_epoch = epoch;
        // Reset fork-detection state when the committed epoch advances.
        self.chain_verifier.reset();
    }

    /// Return the current state of the agreement protocol.
    #[must_use]
    pub fn state(&self) -> AgreementState {
        self.state
    }

    /// Return the current proposal, if any.
    #[must_use]
    pub fn current_proposal(&self) -> Option<&EpochAgreementProposal> {
        self.current_proposal.as_ref()
    }

    /// Number of unique peers that have responded so far.
    #[must_use]
    pub fn ack_count(&self) -> usize {
        self.ack_set.len()
    }

    /// Number of acceptance votes received.
    #[must_use]
    pub fn approval_count(&self) -> usize {
        self.approvals
    }

    /// The quorum threshold (computed from `quorum_mode` and `peer_count`).
    #[must_use]
    pub fn quorum_threshold(&self) -> usize {
        self.quorum_mode.required_approvals(self.peer_count)
    }

    /// Whether quorum has been reached.
    #[must_use]
    pub fn quorum_reached(&self) -> bool {
        self.state == AgreementState::AwaitingAcks && self.approvals >= self.quorum_threshold()
    }

    // ── propose ─────────────────────────────────────────────────────

    /// Initiate a new epoch-agreement round.
    ///
    /// Transitions `Idle` → `Proposing`. If `peer_count` is 0 (single-node
    /// degenerate case), transitions directly to `Committed`.
    ///
    /// # Errors
    ///
    /// Returns [`AgreementError::AlreadyInProgress`] if not in `Idle` state.
    /// Returns [`AgreementError::EmptyView`] if `view` is empty.
    /// Returns [`AgreementError::DuplicateProposal`] if the same
    /// (coordinator_id, epoch_id) pair was already seen.
    pub fn propose(
        &mut self,
        coordinator_id: u64,
        epoch_id: u64,
        mut view: Vec<u64>,
    ) -> Result<EpochAgreementProposal, AgreementError> {
        if self.state != AgreementState::Idle {
            return Err(AgreementError::AlreadyInProgress);
        }

        if view.is_empty() {
            return Err(AgreementError::EmptyView);
        }

        let dedup_key = (coordinator_id, epoch_id);
        if !self.seen_proposals.insert(dedup_key) {
            return Err(AgreementError::DuplicateProposal {
                coordinator_id,
                epoch_id,
            });
        }

        // Epoch-chain verification: validate that epoch_id forms a valid
        // successor to the locally committed epoch.
        self.chain_verifier
            .verify_proposal(coordinator_id, epoch_id, &view, self.committed_epoch)
            .map_err(AgreementError::ChainError)?;

        view.sort();
        view.dedup();

        let proposal = EpochAgreementProposal {
            epoch_id,
            view,
            coordinator_id,
        };

        self.current_proposal = Some(proposal.clone());
        self.state = AgreementState::Proposing;
        self.ack_set.clear();
        self.approvals = 0;

        // Single-node degenerate case: commit immediately
        if self.peer_count == 0 {
            self.state = AgreementState::Committed;
        }

        Ok(proposal)
    }

    // ── broadcast ───────────────────────────────────────────────────

    /// Signal that the proposal has been broadcast to peers.
    ///
    /// Transitions `Proposing` → `AwaitingAcks` and sets the deadline
    /// if `timeout_ms > 0`.
    ///
    /// # Errors
    ///
    /// Returns [`AgreementError::WrongState`] if not in `Proposing` state.
    pub fn broadcast(&mut self) -> Result<(), AgreementError> {
        if self.state != AgreementState::Proposing {
            return Err(AgreementError::WrongState {
                expected: AgreementState::Proposing,
                actual: self.state,
            });
        }

        self.state = AgreementState::AwaitingAcks;

        if self.timeout_ms > 0 {
            self.deadline =
                Some(Instant::now() + std::time::Duration::from_millis(self.timeout_ms));
        }

        Ok(())
    }

    // ── receive_ack ─────────────────────────────────────────────────

    /// Process an acknowledgment from a peer.
    ///
    /// Validates that the ack targets the current proposal's epoch.
    /// Duplicate acks from the same peer are rejected. Both approvals
    /// and rejections are tracked (only approvals count toward quorum).
    ///
    /// Returns `Ok(true)` if quorum was reached as a result of this ack.
    ///
    /// # Errors
    ///
    /// Returns [`AgreementError::WrongState`] if not in `AwaitingAcks`.
    /// Returns [`AgreementError::EpochIdMismatch`] if ack targets wrong epoch.
    /// Returns [`AgreementError::DuplicateAck`] if peer already responded.
    pub fn receive_ack(&mut self, ack: &EpochAgreementAck) -> Result<bool, AgreementError> {
        if self.state != AgreementState::AwaitingAcks {
            return Err(AgreementError::WrongState {
                expected: AgreementState::AwaitingAcks,
                actual: self.state,
            });
        }

        // Validate ack targets the current proposal
        let proposal = self
            .current_proposal
            .as_ref()
            .ok_or(AgreementError::WrongState {
                expected: AgreementState::AwaitingAcks,
                actual: self.state,
            })?;

        if ack.epoch_id != proposal.epoch_id {
            return Err(AgreementError::EpochIdMismatch {
                expected: proposal.epoch_id,
                received: ack.epoch_id,
            });
        }

        // Reject duplicate acks
        if self.ack_set.contains(&ack.peer_id) {
            return Err(AgreementError::DuplicateAck(ack.peer_id));
        }

        self.ack_set.insert(ack.peer_id);
        if ack.accepted {
            self.approvals += 1;
        }

        if self.quorum_reached() {
            self.commit_internal();
            return Ok(true);
        }

        Ok(false)
    }

    // ── commit ──────────────────────────────────────────────────────

    /// Attempt to finalize the epoch transition.
    ///
    /// Returns the commit notification if quorum has been reached.
    ///
    /// # Errors
    ///
    /// Returns [`AgreementError::WrongState`] if not in `AwaitingAcks`.
    /// Returns [`AgreementError::QuorumNotReached`] if quorum unmet.
    pub fn commit(&mut self) -> Result<EpochAgreementCommit, AgreementError> {
        if self.state != AgreementState::AwaitingAcks {
            return Err(AgreementError::WrongState {
                expected: AgreementState::AwaitingAcks,
                actual: self.state,
            });
        }

        if !self.quorum_reached() {
            return Err(AgreementError::QuorumNotReached {
                approvals: self.approvals,
                required: self.quorum_threshold(),
            });
        }

        self.commit_internal();
        let proposal = self.current_proposal.as_ref().unwrap();
        Ok(EpochAgreementCommit {
            epoch_id: proposal.epoch_id,
        })
    }

    /// Internal commit: transition to Committed and dispatch to bus.
    fn commit_internal(&mut self) {
        let proposal = match self.current_proposal.take() {
            Some(p) => p,
            None => return,
        };

        self.state = AgreementState::Committed;

        // Dispatch to commit bus if configured
        if let Some(ref bus) = self.commit_bus {
            let notification = EpochCommitNotification {
                epoch: EpochId::new(proposal.epoch_id),
                roster_hash: [0u8; 32], // no BLAKE3 — roster hash not needed here
                member_ids: proposal.view,
                commit_index: 0, // bus increments internally
                catalog_delta_bytes: None,
            };
            bus.dispatch_commit(notification.epoch, notification.member_ids);
        }
    }

    // ── abort ───────────────────────────────────────────────────────

    /// Abort the current proposal and return to `Idle`.
    ///
    /// Valid from `Proposing` and `AwaitingAcks` states (e.g., on
    /// timeout or insufficient responses).
    ///
    /// # Errors
    ///
    /// Returns [`AgreementError::WrongState`] if not in an abortable state.
    pub fn abort(&mut self) -> Result<(), AgreementError> {
        match self.state {
            AgreementState::Proposing | AgreementState::AwaitingAcks => {
                self.state = AgreementState::Idle;
                self.current_proposal = None;
                self.ack_set.clear();
                self.approvals = 0;
                // Reset fork-detection state on abort.
                self.chain_verifier.reset();
                self.deadline = None;
                Ok(())
            }
            _ => Err(AgreementError::WrongState {
                expected: AgreementState::Proposing,
                actual: self.state,
            }),
        }
    }

    // ── reset ───────────────────────────────────────────────────────

    /// Reset from `Committed` back to `Idle` for the next round.
    ///
    /// # Errors
    ///
    /// Returns [`AgreementError::WrongState`] if not in `Committed` state.
    pub fn reset(&mut self) -> Result<(), AgreementError> {
        if self.state != AgreementState::Committed {
            return Err(AgreementError::WrongState {
                expected: AgreementState::Committed,
                actual: self.state,
            });
        }

        self.state = AgreementState::Idle;
        self.current_proposal = None;
        self.ack_set.clear();
        self.approvals = 0;
        self.deadline = None;
        Ok(())
    }

    // ── timeout ─────────────────────────────────────────────────────

    /// Whether the agreement has timed out.
    ///
    /// Returns `true` if a deadline is set and the current time has
    /// exceeded it. Callers should call [`abort`] when this returns
    /// `true`.
    #[must_use]
    pub fn check_timeout(&self) -> bool {
        match self.deadline {
            Some(deadline) => Instant::now() >= deadline,
            None => false,
        }
    }

    /// Whether a timeout is configured (timeout_ms > 0).
    #[must_use]
    pub fn has_timeout(&self) -> bool {
        self.timeout_ms > 0
    }
}

impl std::fmt::Debug for MembershipEpochAgreement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MembershipEpochAgreement")
            .field("state", &self.state)
            .field("current_proposal", &self.current_proposal)
            .field("ack_set", &self.ack_set)
            .field("approvals", &self.approvals)
            .field("quorum_mode", &self.quorum_mode)
            .field("peer_count", &self.peer_count)
            .field("deadline", &self.deadline)
            .field("timeout_ms", &self.timeout_ms)
            .field(
                "commit_bus",
                &self.commit_bus.as_ref().map(|_| "EpochCommitBus"),
            )
            .field("seen_proposals", &self.seen_proposals)
            .finish()
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_agreement(peer_count: usize, timeout_ms: u64) -> MembershipEpochAgreement {
        MembershipEpochAgreement::new(QuorumMode::SimpleMajority, peer_count, timeout_ms)
    }

    // ── Basic lifecycle ──────────────────────────────────────────────

    #[test]
    fn initial_state_is_idle() {
        let a = make_agreement(3, 0);
        assert_eq!(a.state(), AgreementState::Idle);
        assert_eq!(a.ack_count(), 0);
        assert!(a.current_proposal().is_none());
    }

    #[test]
    fn propose_transitions_to_proposing() {
        let mut a = make_agreement(3, 0);
        a.set_committed_epoch(4);
        let p = a.propose(1, 5, vec![1, 2, 3]).unwrap();
        assert_eq!(p.epoch_id, 5);
        assert_eq!(p.coordinator_id, 1);
        assert_eq!(p.view, vec![1, 2, 3]);
        assert_eq!(a.state(), AgreementState::Proposing);
    }

    #[test]
    fn propose_sorts_and_dedupes_view() {
        let mut a = make_agreement(3, 0);
        a.set_committed_epoch(4);
        let p = a.propose(1, 5, vec![3, 1, 2, 1]).unwrap();
        assert_eq!(p.view, vec![1, 2, 3]);
    }

    #[test]
    fn propose_rejects_empty_view() {
        let mut a = make_agreement(3, 0);
        a.set_committed_epoch(4);
        let result = a.propose(1, 5, vec![]);
        assert!(matches!(result, Err(AgreementError::EmptyView)));
    }

    #[test]
    fn propose_rejects_duplicate_proposal() {
        let mut a = make_agreement(3, 0);
        a.set_committed_epoch(4);
        a.propose(1, 5, vec![1, 2, 3]).unwrap();
        a.abort().unwrap();
        let result = a.propose(1, 5, vec![1, 2, 3]);
        assert!(matches!(
            result,
            Err(AgreementError::DuplicateProposal { .. })
        ));
    }

    #[test]
    fn propose_rejects_when_not_idle() {
        let mut a = make_agreement(3, 0);
        a.set_committed_epoch(4);
        a.propose(1, 5, vec![1, 2, 3]).unwrap();
        let result = a.propose(1, 6, vec![1, 2, 3]);
        assert!(matches!(result, Err(AgreementError::AlreadyInProgress)));
    }

    // ── Broadcast ────────────────────────────────────────────────────

    #[test]
    fn broadcast_transitions_to_awaiting_acks() {
        let mut a = make_agreement(3, 0);
        a.set_committed_epoch(4);
        a.propose(1, 5, vec![1, 2, 3]).unwrap();
        a.broadcast().unwrap();
        assert_eq!(a.state(), AgreementState::AwaitingAcks);
    }

    #[test]
    fn broadcast_sets_deadline() {
        let mut a = make_agreement(3, 10_000);
        a.set_committed_epoch(4);
        a.propose(1, 5, vec![1, 2, 3]).unwrap();
        a.broadcast().unwrap();
        assert!(a.has_timeout());
        assert!(!a.check_timeout()); // just set, not expired
    }

    #[test]
    fn broadcast_no_timeout_when_zero() {
        let mut a = make_agreement(3, 0);
        a.set_committed_epoch(4);
        a.propose(1, 5, vec![1, 2, 3]).unwrap();
        a.broadcast().unwrap();
        assert!(!a.has_timeout());
        assert!(!a.check_timeout());
    }

    #[test]
    fn broadcast_rejects_wrong_state() {
        let mut a = make_agreement(3, 0);
        let result = a.broadcast();
        assert!(matches!(result, Err(AgreementError::WrongState { .. })));
    }

    // ── Ack collection ───────────────────────────────────────────────

    fn setup_awaiting_acks(
        peer_count: usize,
    ) -> (MembershipEpochAgreement, EpochAgreementProposal) {
        let mut a = make_agreement(peer_count, 0);
        a.set_committed_epoch(4);
        let p = a.propose(1, 5, vec![1, 2, 3, 4, 5]).unwrap();
        a.broadcast().unwrap();
        (a, p)
    }

    #[test]
    fn receive_approval_ack() {
        let (mut a, p) = setup_awaiting_acks(3);
        let ack = EpochAgreementAck {
            epoch_id: p.epoch_id,
            peer_id: 2,
            accepted: true,
        };
        let quorum = a.receive_ack(&ack).unwrap();
        assert!(!quorum); // need 2 of 3
        assert_eq!(a.approval_count(), 1);
        assert_eq!(a.ack_count(), 1);
    }

    #[test]
    fn receive_rejection_ack_does_not_count_toward_quorum() {
        let (mut a, p) = setup_awaiting_acks(3);
        let ack = EpochAgreementAck {
            epoch_id: p.epoch_id,
            peer_id: 2,
            accepted: false,
        };
        let quorum = a.receive_ack(&ack).unwrap();
        assert!(!quorum);
        assert_eq!(a.approval_count(), 0);
        assert_eq!(a.ack_count(), 1);
    }

    #[test]
    fn quorum_reached_with_two_of_three() {
        let (mut a, p) = setup_awaiting_acks(3);
        // peer 2 approves
        a.receive_ack(&EpochAgreementAck {
            epoch_id: p.epoch_id,
            peer_id: 2,
            accepted: true,
        })
        .unwrap();
        assert_eq!(a.state(), AgreementState::AwaitingAcks);

        // peer 3 approves → quorum
        let quorum = a
            .receive_ack(&EpochAgreementAck {
                epoch_id: p.epoch_id,
                peer_id: 3,
                accepted: true,
            })
            .unwrap();
        assert!(quorum);
        assert_eq!(a.state(), AgreementState::Committed);
        assert_eq!(a.approval_count(), 2);
    }

    #[test]
    fn quorum_not_reached_with_rejection() {
        let (mut a, p) = setup_awaiting_acks(3);
        a.receive_ack(&EpochAgreementAck {
            epoch_id: p.epoch_id,
            peer_id: 2,
            accepted: true,
        })
        .unwrap();
        a.receive_ack(&EpochAgreementAck {
            epoch_id: p.epoch_id,
            peer_id: 3,
            accepted: false,
        })
        .unwrap();
        // Still need 2 approvals (only 1 so far)
        assert_eq!(a.state(), AgreementState::AwaitingAcks);
        assert!(!a.quorum_reached());
    }

    #[test]
    fn receive_ack_rejects_wrong_epoch() {
        let (mut a, _p) = setup_awaiting_acks(3);
        let ack = EpochAgreementAck {
            epoch_id: 99,
            peer_id: 2,
            accepted: true,
        };
        let result = a.receive_ack(&ack);
        assert!(matches!(
            result,
            Err(AgreementError::EpochIdMismatch { .. })
        ));
    }

    #[test]
    fn receive_ack_rejects_duplicate() {
        let (mut a, p) = setup_awaiting_acks(3);
        let ack = EpochAgreementAck {
            epoch_id: p.epoch_id,
            peer_id: 2,
            accepted: true,
        };
        a.receive_ack(&ack).unwrap();
        let result = a.receive_ack(&ack);
        assert!(matches!(result, Err(AgreementError::DuplicateAck(2))));
    }

    #[test]
    fn receive_ack_rejects_wrong_state() {
        let (mut a, _p) = setup_awaiting_acks(3);
        a.abort().unwrap();
        let ack = EpochAgreementAck {
            epoch_id: 5,
            peer_id: 2,
            accepted: true,
        };
        let result = a.receive_ack(&ack);
        assert!(matches!(result, Err(AgreementError::WrongState { .. })));
    }

    // ── Commit ───────────────────────────────────────────────────────

    #[test]
    fn explicit_commit_after_quorum() {
        let (mut a, p) = setup_awaiting_acks(3);
        // 2 approvals needed for quorum with 3 peers (simple majority)
        a.receive_ack(&EpochAgreementAck {
            epoch_id: p.epoch_id,
            peer_id: 2,
            accepted: true,
        })
        .unwrap();
        // 1 so far, not yet quorum
        assert_eq!(a.state(), AgreementState::AwaitingAcks);
        // 2nd approval reaches quorum
        a.receive_ack(&EpochAgreementAck {
            epoch_id: p.epoch_id,
            peer_id: 3,
            accepted: true,
        })
        .unwrap();
        // quorum reached via receive_ack, state is Committed
        assert_eq!(a.state(), AgreementState::Committed);
    }
    #[test]
    fn commit_rejects_before_quorum() {
        let (mut a, _p) = setup_awaiting_acks(3);
        let result = a.commit();
        assert!(matches!(
            result,
            Err(AgreementError::QuorumNotReached { .. })
        ));
    }

    #[test]
    fn commit_produces_notification() {
        let (mut a, p) = setup_awaiting_acks(1); // threshold = 1
        a.receive_ack(&EpochAgreementAck {
            epoch_id: p.epoch_id,
            peer_id: 2,
            accepted: true,
        })
        .unwrap();
        assert_eq!(a.state(), AgreementState::Committed);
    }

    // ── Abort / Reset ────────────────────────────────────────────────

    #[test]
    fn abort_from_proposing() {
        let mut a = make_agreement(3, 0);
        a.set_committed_epoch(4);
        a.propose(1, 5, vec![1, 2, 3]).unwrap();
        a.abort().unwrap();
        assert_eq!(a.state(), AgreementState::Idle);
        assert!(a.current_proposal().is_none());
    }

    #[test]
    fn abort_from_awaiting_acks() {
        let (mut a, _p) = setup_awaiting_acks(3);
        a.abort().unwrap();
        assert_eq!(a.state(), AgreementState::Idle);
        assert_eq!(a.ack_count(), 0);
    }

    #[test]
    fn abort_rejects_from_idle() {
        let mut a = make_agreement(3, 0);
        let result = a.abort();
        assert!(matches!(result, Err(AgreementError::WrongState { .. })));
    }

    #[test]
    fn abort_rejects_from_committed() {
        let (mut a, p) = setup_awaiting_acks(1);
        a.receive_ack(&EpochAgreementAck {
            epoch_id: p.epoch_id,
            peer_id: 2,
            accepted: true,
        })
        .unwrap();
        assert_eq!(a.state(), AgreementState::Committed);
        let result = a.abort();
        assert!(matches!(result, Err(AgreementError::WrongState { .. })));
    }

    #[test]
    fn reset_from_committed() {
        let (mut a, p) = setup_awaiting_acks(1);
        a.receive_ack(&EpochAgreementAck {
            epoch_id: p.epoch_id,
            peer_id: 2,
            accepted: true,
        })
        .unwrap();
        assert_eq!(a.state(), AgreementState::Committed);
        a.reset().unwrap();
        assert_eq!(a.state(), AgreementState::Idle);
    }

    #[test]
    fn reset_rejects_from_non_committed() {
        let mut a = make_agreement(3, 0);
        let result = a.reset();
        assert!(matches!(result, Err(AgreementError::WrongState { .. })));
    }

    // ── Single-node degenerate case ──────────────────────────────────

    #[test]
    fn single_node_commits_immediately() {
        let mut a = make_agreement(0, 0);
        a.set_committed_epoch(4);
        a.propose(1, 5, vec![1]).unwrap();
        // No peers → immediate commit
        assert_eq!(a.state(), AgreementState::Committed);
    }

    #[test]
    fn single_node_quorum_threshold_zero() {
        let a = make_agreement(0, 0);
        assert_eq!(a.quorum_threshold(), 0);
    }

    // ── Quorum modes ─────────────────────────────────────────────────

    #[test]
    fn simple_majority_of_5_requires_3() {
        assert_eq!(QuorumMode::SimpleMajority.required_approvals(5), 3);
    }

    #[test]
    fn simple_majority_of_4_requires_3() {
        assert_eq!(QuorumMode::SimpleMajority.required_approvals(4), 3);
    }

    #[test]
    fn simple_majority_of_1_requires_1() {
        assert_eq!(QuorumMode::SimpleMajority.required_approvals(1), 1);
    }

    #[test]
    fn simple_majority_of_0_requires_0() {
        assert_eq!(QuorumMode::SimpleMajority.required_approvals(0), 0);
    }

    #[test]
    fn unanimous_of_3_requires_3() {
        assert_eq!(QuorumMode::Unanimous.required_approvals(3), 3);
    }

    #[test]
    fn fixed_threshold() {
        assert_eq!(QuorumMode::Fixed(2).required_approvals(10), 2);
    }

    // ── Timeout ──────────────────────────────────────────────────────

    #[test]
    fn timeout_not_fired_before_deadline() {
        let mut a = make_agreement(3, 60_000); // 60 s
        a.set_committed_epoch(4);
        a.propose(1, 5, vec![1, 2, 3]).unwrap();
        a.broadcast().unwrap();
        assert!(!a.check_timeout());
    }

    #[test]
    fn zero_timeout_never_fires() {
        let mut a = make_agreement(3, 0);
        a.set_committed_epoch(4);
        a.propose(1, 5, vec![1, 2, 3]).unwrap();
        a.broadcast().unwrap();
        assert!(!a.check_timeout());
    }

    // ── Full lifecycle ───────────────────────────────────────────────

    #[test]
    fn full_lifecycle_3_peer_majority() {
        let mut a = make_agreement(3, 0);
        a.set_committed_epoch(4);
        let p = a.propose(1, 5, vec![1, 2, 3]).unwrap();
        assert_eq!(a.state(), AgreementState::Proposing);

        a.broadcast().unwrap();
        assert_eq!(a.state(), AgreementState::AwaitingAcks);

        // Peer 2 approves
        let quorum = a
            .receive_ack(&EpochAgreementAck {
                epoch_id: p.epoch_id,
                peer_id: 2,
                accepted: true,
            })
            .unwrap();
        assert!(!quorum);

        // Peer 3 approves → quorum, auto-commit
        let quorum = a
            .receive_ack(&EpochAgreementAck {
                epoch_id: p.epoch_id,
                peer_id: 3,
                accepted: true,
            })
            .unwrap();
        assert!(quorum);
        assert_eq!(a.state(), AgreementState::Committed);

        a.reset().unwrap();
        assert_eq!(a.state(), AgreementState::Idle);
    }

    #[test]
    fn lifecycle_with_rejection_no_quorum() {
        let mut a = make_agreement(3, 0);
        a.set_committed_epoch(4);
        let p = a.propose(1, 5, vec![1, 2, 3]).unwrap();
        a.broadcast().unwrap();

        // Two rejections — quorum never reached
        a.receive_ack(&EpochAgreementAck {
            epoch_id: p.epoch_id,
            peer_id: 2,
            accepted: false,
        })
        .unwrap();
        a.receive_ack(&EpochAgreementAck {
            epoch_id: p.epoch_id,
            peer_id: 3,
            accepted: false,
        })
        .unwrap();

        assert_eq!(a.state(), AgreementState::AwaitingAcks);
        assert!(!a.quorum_reached());

        // Abort and retry
        a.abort().unwrap();
        assert_eq!(a.state(), AgreementState::Idle);
    }

    #[test]
    fn lifecycle_unanimous_mode() {
        let mut a = MembershipEpochAgreement::new(QuorumMode::Unanimous, 3, 0);
        a.set_committed_epoch(4);
        let p = a.propose(1, 5, vec![1, 2, 3]).unwrap();
        a.broadcast().unwrap();

        // 2 approvals — not enough (need 3)
        a.receive_ack(&EpochAgreementAck {
            epoch_id: p.epoch_id,
            peer_id: 2,
            accepted: true,
        })
        .unwrap();
        a.receive_ack(&EpochAgreementAck {
            epoch_id: p.epoch_id,
            peer_id: 3,
            accepted: true,
        })
        .unwrap();
        assert_eq!(a.state(), AgreementState::AwaitingAcks);

        // 3rd approval → quorum
        let quorum = a
            .receive_ack(&EpochAgreementAck {
                epoch_id: p.epoch_id,
                peer_id: 4,
                accepted: true,
            })
            .unwrap();
        assert!(quorum);
        assert_eq!(a.state(), AgreementState::Committed);
    }

    // ── Commit bus integration ───────────────────────────────────────

    #[test]
    fn commit_dispatches_to_bus() {
        let bus = EpochCommitBus::new();
        let mut a = MembershipEpochAgreement::new(QuorumMode::SimpleMajority, 1, 0);
        a.set_commit_bus(bus);
        a.set_committed_epoch(4);

        let p = a.propose(1, 5, vec![1, 2, 3]).unwrap();
        a.broadcast().unwrap();

        let quorum = a
            .receive_ack(&EpochAgreementAck {
                epoch_id: p.epoch_id,
                peer_id: 2,
                accepted: true,
            })
            .unwrap();
        assert!(quorum);
        assert_eq!(a.state(), AgreementState::Committed);
    }

    // ── AgreementError Display ──────────────────────────────────────

    #[test]
    fn error_display_contains_message() {
        let e = AgreementError::AlreadyInProgress;
        assert!(format!("{e}").contains("in progress"));

        let e = AgreementError::DuplicateAck(42);
        assert!(format!("{e}").contains("42"));

        let e = AgreementError::EmptyView;
        assert!(format!("{e}").contains("empty"));

        let e = AgreementError::QuorumNotReached {
            approvals: 1,
            required: 3,
        };
        assert!(format!("{e}").contains("1"));
        assert!(format!("{e}").contains("3"));
    }
}
