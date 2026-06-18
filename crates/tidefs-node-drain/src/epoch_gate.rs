// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Epoch-bound transition gate for node drain.
//!
//! The [`EpochGate`] coordinates the membership epoch transition that excludes
//! a draining node. It uses the [`EpochGateOps`] trait to abstract the 3-phase
//! epoch protocol (propose, accept-collect, commit) so the production wiring
//! lives in `tidefs-membership-live` without creating a circular dependency.

use std::fmt;
use tidefs_membership_epoch::MemberId;

// ---------------------------------------------------------------------------
// EpochGateState
// ---------------------------------------------------------------------------

/// Phases of the epoch-bound drain transition.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EpochGateState {
    /// Gate is idle; no epoch transition has been initiated.
    Idle,
    /// Quorum count set; proposal prepared but not yet sent.
    ProposalPending,
    /// Proposal broadcast; collecting accepts from cohort members.
    CollectingAccepts {
        /// Number of accepts received so far.
        accepts_received: usize,
        /// Quorum threshold required for commit.
        quorum_threshold: usize,
    },
    /// Quorum reached; commit broadcast.
    Committing,
    /// Transition committed; drain can proceed past the epoch gate.
    Committed,
    /// Gate timed out waiting for quorum.
    TimedOut,
    /// Gate failed due to proposal rejection or transport error.
    Failed { reason: String },
}

impl EpochGateState {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::ProposalPending => "proposal_pending",
            Self::CollectingAccepts { .. } => "collecting_accepts",
            Self::Committing => "committing",
            Self::Committed => "committed",
            Self::TimedOut => "timed_out",
            Self::Failed { .. } => "failed",
        }
    }

    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Committed | Self::TimedOut | Self::Failed { .. })
    }

    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Committed)
    }
}

impl Default for EpochGateState {
    fn default() -> Self {
        Self::Idle
    }
}

// ---------------------------------------------------------------------------
// EpochGateError
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EpochGateError {
    InvalidState {
        node_id: MemberId,
        expected: String,
        actual: EpochGateState,
    },
    ProposalRejected {
        node_id: MemberId,
        rejected_by: MemberId,
        reason: String,
    },
    QuorumTimeout {
        node_id: MemberId,
        accepts_received: usize,
        quorum_threshold: usize,
    },
    CommitFailed {
        node_id: MemberId,
        reason: String,
    },
    Cancelled {
        node_id: MemberId,
    },
}

impl fmt::Display for EpochGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState {
                node_id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "node {} epoch gate: expected {}, but state is {:?}",
                    node_id.0, expected, actual
                )
            }
            Self::ProposalRejected {
                node_id,
                rejected_by,
                reason,
            } => {
                write!(
                    f,
                    "node {} epoch proposal rejected by {}: {}",
                    node_id.0, rejected_by.0, reason
                )
            }
            Self::QuorumTimeout {
                node_id,
                accepts_received,
                quorum_threshold,
            } => {
                write!(
                    f,
                    "node {} epoch gate quorum timeout: {}/{} accepts",
                    node_id.0, accepts_received, quorum_threshold
                )
            }
            Self::CommitFailed { node_id, reason } => {
                write!(f, "node {} epoch commit failed: {}", node_id.0, reason)
            }
            Self::Cancelled { node_id } => {
                write!(f, "node {} epoch gate cancelled", node_id.0)
            }
        }
    }
}

impl std::error::Error for EpochGateError {}

// ---------------------------------------------------------------------------
// EpochGateConfig
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochGateConfig {
    pub quorum_timeout_ms: u64,
    pub cohort_size: usize,
}

impl Default for EpochGateConfig {
    fn default() -> Self {
        Self {
            quorum_timeout_ms: 30_000,
            cohort_size: 3,
        }
    }
}

impl EpochGateConfig {
    #[must_use]
    pub fn quorum_threshold(&self) -> usize {
        (self.cohort_size / 2) + 1
    }
}

// ---------------------------------------------------------------------------
// EpochGateOps trait
// ---------------------------------------------------------------------------

pub trait EpochGateOps {
    fn propose_exclusion(
        &mut self,
        node_to_remove: MemberId,
        proposer: MemberId,
        reason: &str,
    ) -> Result<u64, String>;

    fn collect_accepts(
        &mut self,
        proposal_id: u64,
        voter_members: &[MemberId],
    ) -> Result<usize, String>;

    fn quorum_reached(&self, proposal_id: u64, threshold: usize) -> bool;

    fn commit_transition(&mut self, proposal_id: u64) -> Result<(), String>;

    fn cancel_proposal(&mut self, proposal_id: u64) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// EpochGate
// ---------------------------------------------------------------------------

pub struct EpochGate {
    node_id: MemberId,
    state: EpochGateState,
    config: EpochGateConfig,
    proposal_id: Option<u64>,
    elapsed_ms: u64,
}

impl EpochGate {
    #[must_use]
    pub fn new(node_id: MemberId, config: EpochGateConfig) -> Self {
        Self {
            node_id,
            state: EpochGateState::Idle,
            config,
            proposal_id: None,
            elapsed_ms: 0,
        }
    }

    #[must_use]
    pub fn with_defaults(node_id: MemberId) -> Self {
        Self::new(node_id, EpochGateConfig::default())
    }

    #[must_use]
    pub fn node_id(&self) -> MemberId {
        self.node_id
    }

    #[must_use]
    pub fn state(&self) -> EpochGateState {
        self.state.clone()
    }

    #[must_use]
    pub fn config(&self) -> EpochGateConfig {
        self.config
    }

    #[must_use]
    pub fn proposal_id(&self) -> Option<u64> {
        self.proposal_id
    }

    #[must_use]
    pub fn elapsed_ms(&self) -> u64 {
        self.elapsed_ms
    }

    #[must_use]
    pub fn is_committed(&self) -> bool {
        self.state.is_success()
    }

    #[must_use]
    pub fn quorum_threshold(&self) -> usize {
        self.config.quorum_threshold()
    }

    pub fn initiate(
        &mut self,
        ops: &mut dyn EpochGateOps,
        proposer: MemberId,
        reason: &str,
    ) -> Result<EpochGateState, EpochGateError> {
        if self.state != EpochGateState::Idle {
            return Err(EpochGateError::InvalidState {
                node_id: self.node_id,
                expected: "Idle".to_string(),
                actual: self.state.clone(),
            });
        }

        self.state = EpochGateState::ProposalPending;

        let proposal_id = ops
            .propose_exclusion(self.node_id, proposer, reason)
            .map_err(|e| EpochGateError::ProposalRejected {
                node_id: self.node_id,
                rejected_by: proposer,
                reason: e,
            })?;

        self.proposal_id = Some(proposal_id);
        self.state = EpochGateState::CollectingAccepts {
            accepts_received: 0,
            quorum_threshold: self.quorum_threshold(),
        };

        Ok(self.state.clone())
    }

    pub fn drive(
        &mut self,
        ops: &mut dyn EpochGateOps,
        voter_members: &[MemberId],
        delta_ms: u64,
    ) -> Result<EpochGateState, EpochGateError> {
        self.elapsed_ms = self.elapsed_ms.saturating_add(delta_ms);

        // Check timeout
        if self.elapsed_ms >= self.config.quorum_timeout_ms {
            if let EpochGateState::CollectingAccepts {
                accepts_received,
                quorum_threshold,
            } = self.state
            {
                self.state = EpochGateState::TimedOut;
                return Err(EpochGateError::QuorumTimeout {
                    node_id: self.node_id,
                    accepts_received,
                    quorum_threshold,
                });
            }
        }

        match &mut self.state {
            EpochGateState::CollectingAccepts {
                accepts_received,
                quorum_threshold,
            } => {
                let threshold = *quorum_threshold;
                let pid = self
                    .proposal_id
                    .ok_or_else(|| EpochGateError::InvalidState {
                        node_id: self.node_id,
                        expected: "has proposal".to_string(),
                        actual: EpochGateState::CollectingAccepts {
                            accepts_received: *accepts_received,
                            quorum_threshold: threshold,
                        },
                    })?;

                let count = ops.collect_accepts(pid, voter_members).map_err(|e| {
                    EpochGateError::ProposalRejected {
                        node_id: self.node_id,
                        rejected_by: MemberId::ZERO,
                        reason: e,
                    }
                })?;

                *accepts_received = count;

                if ops.quorum_reached(pid, threshold) {
                    self.state = EpochGateState::Committing;
                } else {
                    return Ok(self.state.clone());
                }
            }
            EpochGateState::Committing => {
                let pid = self.proposal_id.ok_or(EpochGateError::InvalidState {
                    node_id: self.node_id,
                    expected: "has proposal".to_string(),
                    actual: EpochGateState::Committing,
                })?;

                ops.commit_transition(pid)
                    .map_err(|e| EpochGateError::CommitFailed {
                        node_id: self.node_id,
                        reason: e,
                    })?;

                self.state = EpochGateState::Committed;
            }
            EpochGateState::Committed
            | EpochGateState::TimedOut
            | EpochGateState::Failed { .. } => {}
            EpochGateState::Idle | EpochGateState::ProposalPending => {
                return Err(EpochGateError::InvalidState {
                    node_id: self.node_id,
                    expected: "CollectingAccepts".to_string(),
                    actual: self.state.clone(),
                });
            }
        }

        Ok(self.state.clone())
    }

    pub fn execute(
        &mut self,
        ops: &mut dyn EpochGateOps,
        proposer: MemberId,
        voter_members: &[MemberId],
        reason: &str,
    ) -> Result<EpochGateState, EpochGateError> {
        self.initiate(ops, proposer, reason)?;
        loop {
            let state = self.drive(ops, voter_members, 0)?;
            if state.is_terminal() {
                return Ok(state);
            }
        }
    }

    pub fn cancel(&mut self, ops: &mut dyn EpochGateOps) -> Result<(), EpochGateError> {
        if self.state.is_terminal() {
            return Ok(());
        }
        if let Some(pid) = self.proposal_id {
            let _ = ops.cancel_proposal(pid);
        }
        self.state = EpochGateState::Idle;
        self.proposal_id = None;
        self.elapsed_ms = 0;
        Ok(())
    }

    pub fn mark_failed(&mut self, reason: String) {
        self.state = EpochGateState::Failed { reason };
    }
}

// ---------------------------------------------------------------------------
// EpochGateResult
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochGateResult {
    pub node_id: MemberId,
    pub success: bool,
    pub final_state: EpochGateState,
    pub proposal_id: Option<u64>,
    pub elapsed_ms: u64,
    pub accepts_collected: usize,
    pub quorum_threshold: usize,
}

impl EpochGateResult {
    #[must_use]
    pub fn from_gate(gate: &EpochGate) -> Self {
        let (accepts_collected, quorum_threshold) = match &gate.state {
            EpochGateState::CollectingAccepts {
                accepts_received,
                quorum_threshold,
            } => (*accepts_received, *quorum_threshold),
            _ => (0, gate.quorum_threshold()),
        };
        Self {
            node_id: gate.node_id,
            success: gate.state.is_success(),
            final_state: gate.state.clone(),
            proposal_id: gate.proposal_id,
            elapsed_ms: gate.elapsed_ms,
            accepts_collected,
            quorum_threshold,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn nid(id: u64) -> MemberId {
        MemberId::new(id)
    }

    struct MockEpochGateOps {
        proposals: BTreeMap<u64, (MemberId, Vec<MemberId>)>,
        next_pid: u64,
        staged_accepts: usize,
        commit_succeeds: bool,
        proposal_fails: bool,
        committed_pids: Vec<u64>,
    }

    impl MockEpochGateOps {
        fn new() -> Self {
            Self {
                proposals: BTreeMap::new(),
                next_pid: 100,
                staged_accepts: 0,
                commit_succeeds: true,
                proposal_fails: false,
                committed_pids: Vec::new(),
            }
        }

        fn with_accepts(mut self, count: usize) -> Self {
            self.staged_accepts = count;
            self
        }

        fn with_commit_failure(mut self) -> Self {
            self.commit_succeeds = false;
            self
        }

        fn with_proposal_failure(mut self) -> Self {
            self.proposal_fails = true;
            self
        }
    }

    impl EpochGateOps for MockEpochGateOps {
        fn propose_exclusion(
            &mut self,
            node_to_remove: MemberId,
            _proposer: MemberId,
            _reason: &str,
        ) -> Result<u64, String> {
            if self.proposal_fails {
                return Err("proposal rejected by cohort".to_string());
            }
            let pid = self.next_pid;
            self.next_pid += 1;
            self.proposals.insert(pid, (node_to_remove, Vec::new()));
            Ok(pid)
        }

        fn collect_accepts(
            &mut self,
            proposal_id: u64,
            voter_members: &[MemberId],
        ) -> Result<usize, String> {
            if !self.proposals.contains_key(&proposal_id) {
                return Err("unknown proposal".to_string());
            }
            let entry = self.proposals.get_mut(&proposal_id).unwrap();
            for v in voter_members {
                if !entry.1.contains(v) {
                    entry.1.push(*v);
                    self.staged_accepts += 1;
                }
            }
            Ok(self.staged_accepts)
        }

        fn quorum_reached(&self, _proposal_id: u64, threshold: usize) -> bool {
            self.staged_accepts >= threshold
        }

        fn commit_transition(&mut self, proposal_id: u64) -> Result<(), String> {
            if !self.commit_succeeds {
                return Err("commit rejected".to_string());
            }
            self.committed_pids.push(proposal_id);
            Ok(())
        }

        fn cancel_proposal(&mut self, proposal_id: u64) -> Result<(), String> {
            self.proposals.remove(&proposal_id);
            Ok(())
        }
    }

    // -------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------

    #[test]
    fn epoch_gate_full_lifecycle() {
        let mut ops = MockEpochGateOps::new().with_accepts(0);
        let mut gate = EpochGate::with_defaults(nid(1));
        assert_eq!(gate.quorum_threshold(), 2);

        let voters = vec![nid(1), nid(2), nid(3)];
        gate.initiate(&mut ops, nid(1), "graceful_drain").unwrap();
        gate.drive(&mut ops, &voters, 0).unwrap();

        ops.staged_accepts = 3;
        let state = gate.drive(&mut ops, &voters, 0).unwrap();
        assert_eq!(state, EpochGateState::Committed);
        assert_eq!(ops.committed_pids.len(), 1);
    }

    #[test]
    fn epoch_gate_quorum_timeout() {
        let mut ops = MockEpochGateOps::new().with_accepts(0);
        let mut gate = EpochGate::new(
            nid(2),
            EpochGateConfig {
                quorum_timeout_ms: 100,
                cohort_size: 3,
            },
        );

        let voters = vec![nid(2), nid(3), nid(4)];
        gate.initiate(&mut ops, nid(2), "drain").unwrap();

        let err = gate.drive(&mut ops, &voters, 150).unwrap_err();
        assert!(matches!(err, EpochGateError::QuorumTimeout { .. }));
        assert_eq!(gate.state(), EpochGateState::TimedOut);
    }

    #[test]
    fn epoch_gate_proposal_rejected() {
        let mut ops = MockEpochGateOps::new().with_proposal_failure();
        let mut gate = EpochGate::with_defaults(nid(3));

        let err = gate.initiate(&mut ops, nid(3), "drain").unwrap_err();
        assert!(matches!(err, EpochGateError::ProposalRejected { .. }));
    }

    #[test]
    fn epoch_gate_commit_failure() {
        let mut ops = MockEpochGateOps::new()
            .with_accepts(3)
            .with_commit_failure();
        let mut gate = EpochGate::with_defaults(nid(4));

        let voters = vec![nid(4), nid(5), nid(6)];
        gate.initiate(&mut ops, nid(4), "drain").unwrap();

        let state = gate.drive(&mut ops, &voters, 0).unwrap();
        assert_eq!(state, EpochGateState::Committing);

        let err = gate.drive(&mut ops, &voters, 0).unwrap_err();
        assert!(matches!(err, EpochGateError::CommitFailed { .. }));
    }

    #[test]
    fn epoch_gate_cancel_mid_collection() {
        let mut ops = MockEpochGateOps::new().with_accepts(0);
        // Use cohort_size=5 so quorum=3; 2 voters won't reach it
        let mut gate = EpochGate::new(
            nid(5),
            EpochGateConfig {
                quorum_timeout_ms: 30_000,
                cohort_size: 5,
            },
        );

        let voters = vec![nid(5), nid(6)];
        gate.initiate(&mut ops, nid(5), "drain").unwrap();
        gate.drive(&mut ops, &voters, 0).unwrap();

        assert!(matches!(
            gate.state(),
            EpochGateState::CollectingAccepts { .. }
        ));

        gate.cancel(&mut ops).unwrap();
        assert_eq!(gate.state(), EpochGateState::Idle);
        assert_eq!(gate.proposal_id(), None);
    }

    #[test]
    fn epoch_gate_cannot_initiate_twice() {
        let mut ops = MockEpochGateOps::new().with_accepts(0);
        let mut gate = EpochGate::with_defaults(nid(6));

        gate.initiate(&mut ops, nid(6), "first").unwrap();
        let err = gate.initiate(&mut ops, nid(6), "second").unwrap_err();
        assert!(matches!(err, EpochGateError::InvalidState { .. }));
    }

    #[test]
    fn epoch_gate_execute_convenience() {
        let mut ops = MockEpochGateOps::new().with_accepts(3);
        let mut gate = EpochGate::with_defaults(nid(7));

        let voters = vec![nid(7), nid(8), nid(9)];
        let result = gate.execute(&mut ops, nid(7), &voters, "drain").unwrap();
        assert_eq!(result, EpochGateState::Committed);
        assert!(gate.is_committed());
    }

    #[test]
    fn epoch_gate_result_summary() {
        let mut ops = MockEpochGateOps::new().with_accepts(3);
        let mut gate = EpochGate::with_defaults(nid(8));

        let voters = vec![nid(8), nid(9), nid(10)];
        gate.execute(&mut ops, nid(8), &voters, "drain").unwrap();

        let result = EpochGateResult::from_gate(&gate);
        assert!(result.success);
        assert_eq!(result.node_id, nid(8));
        assert!(result.proposal_id.is_some());
    }

    #[test]
    fn epoch_gate_mark_failed() {
        let mut gate = EpochGate::with_defaults(nid(9));
        gate.mark_failed("transport lost".to_string());
        assert!(matches!(gate.state(), EpochGateState::Failed { .. }));
        assert!(gate.state().is_terminal());
    }

    #[test]
    fn epoch_gate_default_config() {
        let config = EpochGateConfig::default();
        assert_eq!(config.quorum_timeout_ms, 30_000);
        assert_eq!(config.cohort_size, 3);
        assert_eq!(config.quorum_threshold(), 2);
    }

    #[test]
    fn epoch_gate_config_quorum_five_nodes() {
        let config = EpochGateConfig {
            quorum_timeout_ms: 60_000,
            cohort_size: 5,
        };
        assert_eq!(config.quorum_threshold(), 3);
    }

    #[test]
    fn epoch_gate_drive_noop_on_terminal() {
        let mut ops = MockEpochGateOps::new().with_accepts(3);
        let mut gate = EpochGate::with_defaults(nid(10));

        let voters = vec![nid(10), nid(11), nid(12)];
        gate.execute(&mut ops, nid(10), &voters, "drain").unwrap();
        assert_eq!(gate.state(), EpochGateState::Committed);

        let state = gate.drive(&mut ops, &voters, 0).unwrap();
        assert_eq!(state, EpochGateState::Committed);
    }
}
