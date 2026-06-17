//! High-level node join lifecycle state machine.
//!
//! Tracks the progression of a new node through the five join phases:
//! Idle → JoinRequested → Bootstrapping → CatchingUp → Joining → Joined.
//!
//! This module implements the `NodeJoin` orchestrator, `JoinToken` for
//! one-time join authorization, and `JoinStats` for tracking join metrics.

use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::{EpochId, MemberId};

use super::JoinError;

// ── NodeJoinState ────────────────────────────────────────────────────

/// High-level join lifecycle state.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum NodeJoinState {
    /// Node has not started joining.
    Idle = 0,
    /// New node contacts bootstrap peer to request a join token.
    JoinRequested = 1,
    /// Downloading membership view, feature flags, and cluster config
    /// from the bootstrap peer via state transfer.
    Bootstrapping = 2,
    /// Requesting missed TXGs from peers and applying them incrementally.
    CatchingUp = 3,
    /// Proposing a membership epoch transition to include this node.
    Joining = 4,
    /// Node is a full member — can receive data placements.
    Joined = 5,
    /// Join failed and will not retry without explicit re-initiation.
    Failed = 6,
}

impl NodeJoinState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "join.idle",
            Self::JoinRequested => "join.requested",
            Self::Bootstrapping => "join.bootstrapping",
            Self::CatchingUp => "join.catching_up",
            Self::Joining => "join.joining",
            Self::Joined => "join.joined",
            Self::Failed => "join.failed",
        }
    }

    /// Whether the node has reached a terminal state (Joined or Failed).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Joined | Self::Failed)
    }

    /// Whether the node can currently receive data placements.
    #[must_use]
    pub const fn can_receive_placements(self) -> bool {
        matches!(self, Self::Joined)
    }
}

// ── JoinToken ────────────────────────────────────────────────────────

/// A one-time token issued by a bootstrap peer to authorize a join attempt.
///
/// The token is valid for a single join attempt and expires after a
/// configurable window. Once used (consumed by a successful Bootstrap
/// transition), the token is cleared.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct JoinToken {
    /// Unique nonce that identifies this token.
    pub nonce: u64,
    /// The MemberId of the node this token was issued to.
    pub issued_to: MemberId,
    /// The bootstrap peer that issued this token.
    pub bootstrap_peer: MemberId,
    /// When the token was issued (nanoseconds since some epoch).
    pub issued_at_ns: u64,
    /// When the token expires (nanoseconds since some epoch).
    pub expires_at_ns: u64,
    /// The membership epoch this token authorizes the join under.
    /// `None` for legacy tokens that predate epoch binding.
    pub epoch: Option<EpochId>,
}

impl JoinToken {
    /// Create a new join token.
    #[must_use]
    pub fn new(
        nonce: u64,
        issued_to: MemberId,
        bootstrap_peer: MemberId,
        issued_at_ns: u64,
        ttl_ns: u64,
    ) -> Self {
        Self {
            nonce,
            issued_to,
            bootstrap_peer,
            issued_at_ns,
            expires_at_ns: issued_at_ns.saturating_add(ttl_ns),
            epoch: None,
        }
    }

    /// Attach an epoch binding to this token.
    #[must_use]
    pub fn with_epoch(mut self, epoch: EpochId) -> Self {
        self.epoch = Some(epoch);
        self
    }

    /// Whether the token has expired at the given time.
    #[must_use]
    pub fn is_expired_at(&self, now_ns: u64) -> bool {
        now_ns >= self.expires_at_ns
    }

    /// Whether the token is valid for the given member at the given time.
    #[must_use]
    pub fn is_valid_for(&self, member_id: MemberId, now_ns: u64) -> bool {
        self.issued_to == member_id && !self.is_expired_at(now_ns)
    }
}

// ── JoinStats ────────────────────────────────────────────────────────

/// Statistics tracked during a node join.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct JoinStats {
    /// Total wall-clock time of the join in milliseconds.
    pub join_time_ms: u64,
    /// Total bytes downloaded during the bootstrap phase.
    pub bootstrap_bytes_downloaded: u64,
    /// Number of TXGs caught up during the catch-up phase.
    pub txgs_caught_up: u64,
    /// Whether the join completed successfully.
    pub join_success: bool,
}

// ── NodeJoin orchestrator ────────────────────────────────────────────

/// Orchestrates the 5-phase join lifecycle for a new node.
///
/// The join progresses through:
/// Idle → JoinRequested → Bootstrapping → CatchingUp → Joining → Joined.
///
/// At each phase the caller provides external inputs (token validation,
/// bootstrap data, TXG catch-up completion, epoch proposal acceptance)
/// to advance the machine.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeJoin {
    /// The joining member.
    pub member_id: MemberId,
    /// Current join state.
    pub state: NodeJoinState,
    /// The join token (set during JoinRequested, consumed on successful bootstrap).
    pub token: Option<JoinToken>,
    /// Accumulated join statistics.
    pub stats: JoinStats,
    /// When the join started (nanoseconds since some epoch).
    pub started_at_ns: u64,
    /// When the most recent state transition occurred.
    pub state_entered_at_ns: u64,
    /// The current membership epoch known to the joining node.
    pub current_epoch: EpochId,
    /// The bootstrap peer being used for this join.
    pub bootstrap_peer: Option<MemberId>,
    /// The join session epoch binding that authorizes this join.
    /// Set when the token is accepted or the join commit is validated.
    pub session_epoch: Option<crate::JoinSessionEpoch>,
}

impl NodeJoin {
    /// Create a new join in the Idle state.
    #[must_use]
    pub fn new(member_id: MemberId, epoch: EpochId, started_at_ns: u64) -> Self {
        Self {
            member_id,
            state: NodeJoinState::Idle,
            token: None,
            stats: JoinStats::default(),
            started_at_ns,
            state_entered_at_ns: started_at_ns,
            current_epoch: epoch,
            bootstrap_peer: None,
            session_epoch: None,
        }
    }

    /// Transition from Idle to JoinRequested.
    ///
    /// The caller supplies the bootstrap peer that will validate the join.
    /// Returns an error if the node is not idle.
    pub fn request_join(&mut self, bootstrap_peer: MemberId, at_ns: u64) -> Result<(), JoinError> {
        if self.state != NodeJoinState::Idle {
            return Err(JoinError::PreflightDenied(format!(
                "cannot request join in state {:?}",
                self.state
            )));
        }
        self.state = NodeJoinState::JoinRequested;
        self.state_entered_at_ns = at_ns;
        self.bootstrap_peer = Some(bootstrap_peer);
        Ok(())
    }

    /// Accept a join token and transition to Bootstrapping.
    ///
    /// Validates that the token is for this member, not expired, and was
    /// issued by the expected bootstrap peer.
    pub fn accept_token(&mut self, token: JoinToken, at_ns: u64) -> Result<(), JoinError> {
        if self.state != NodeJoinState::JoinRequested {
            return Err(JoinError::PreflightDenied(format!(
                "cannot accept token in state {:?}",
                self.state
            )));
        }
        let expected_peer = self
            .bootstrap_peer
            .ok_or_else(|| JoinError::PreflightDenied("no bootstrap peer set".into()))?;
        if token.bootstrap_peer != expected_peer {
            return Err(JoinError::PreflightDenied(format!(
                "token issued by peer {} but expected {}",
                token.bootstrap_peer.0, expected_peer.0
            )));
        }
        if !token.is_valid_for(self.member_id, at_ns) {
            return Err(JoinError::PreflightDenied(
                "token invalid: expired or wrong member".into(),
            ));
        }

        // Record the session epoch binding from the token.
        let join_epoch = token.epoch.unwrap_or(self.current_epoch);
        self.session_epoch = Some(crate::JoinSessionEpoch::new(
            join_epoch,
            self.member_id,
            token.nonce,
        ));
        self.current_epoch = join_epoch;

        self.token = Some(token);
        self.state = NodeJoinState::Bootstrapping;
        self.state_entered_at_ns = at_ns;
        Ok(())
    }

    /// Complete the bootstrap phase.
    ///
    /// Records the number of bytes downloaded and transitions to CatchingUp.
    pub fn bootstrap_complete(
        &mut self,
        bytes_downloaded: u64,
        at_ns: u64,
    ) -> Result<(), JoinError> {
        if self.state != NodeJoinState::Bootstrapping {
            return Err(JoinError::PreflightDenied(format!(
                "cannot complete bootstrap in state {:?}",
                self.state
            )));
        }
        self.stats.bootstrap_bytes_downloaded = bytes_downloaded;
        self.state = NodeJoinState::CatchingUp;
        self.state_entered_at_ns = at_ns;
        // Token is consumed — clear it.
        self.token = None;
        Ok(())
    }

    /// Record TXGs caught up and transition to Joining when catch-up is complete.
    ///
    /// The caller reports how many TXGs were caught up in this batch.
    /// When `caught_up_complete` is true, transitions to Joining.
    pub fn catch_up_progress(
        &mut self,
        txgs_applied: u64,
        caught_up_complete: bool,
        at_ns: u64,
    ) -> Result<(), JoinError> {
        if self.state != NodeJoinState::CatchingUp {
            return Err(JoinError::PreflightDenied(format!(
                "cannot report catch-up progress in state {:?}",
                self.state
            )));
        }
        self.stats.txgs_caught_up = self.stats.txgs_caught_up.saturating_add(txgs_applied);
        if caught_up_complete {
            self.state = NodeJoinState::Joining;
            self.state_entered_at_ns = at_ns;
        }
        Ok(())
    }

    /// Complete the join — transition to Joined.
    ///
    /// Called after the epoch transition proposal has been accepted and
    /// committed, making this node a full member.
    pub fn join_complete(&mut self, at_ns: u64) -> Result<(), JoinError> {
        if self.state != NodeJoinState::Joining {
            return Err(JoinError::PreflightDenied(format!(
                "cannot complete join in state {:?}",
                self.state
            )));
        }
        self.state = NodeJoinState::Joined;
        self.state_entered_at_ns = at_ns;
        self.stats.join_success = true;
        let elapsed_ns = at_ns.saturating_sub(self.started_at_ns);
        self.stats.join_time_ms = elapsed_ns / 1_000_000;
        Ok(())
    }

    /// Mark the join as failed.
    pub fn fail(&mut self, at_ns: u64) {
        self.state = NodeJoinState::Failed;
        self.state_entered_at_ns = at_ns;
        self.stats.join_success = false;
        let elapsed_ns = at_ns.saturating_sub(self.started_at_ns);
        self.stats.join_time_ms = elapsed_ns / 1_000_000;
    }

    /// Whether the join is in a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Whether the node can currently receive data placements.
    #[must_use]
    pub fn can_receive_placements(&self) -> bool {
        self.state.can_receive_placements()
    }

    /// Operator-visible join status for this node.
    ///
    /// Distinguishes between waiting-for-quorum, stale-epoch,
    /// identity-mismatch, transfer-ready, and terminal outcomes.
    #[must_use]
    pub fn join_status(&self) -> crate::JoinStatus {
        if self.state == NodeJoinState::Failed {
            return crate::JoinStatus::Failed("join lifecycle failed".into());
        }
        if self.state == NodeJoinState::Joined {
            return crate::JoinStatus::TransferComplete;
        }

        let session = match &self.session_epoch {
            Some(s) => s,
            None => {
                if self.state >= NodeJoinState::Bootstrapping {
                    return crate::JoinStatus::MissingEpochEvidence;
                }
                return crate::JoinStatus::WaitingForQuorum;
            }
        };

        match session.is_valid_for(self.member_id, self.current_epoch) {
            Ok(()) => {
                if self.state >= NodeJoinState::CatchingUp {
                    crate::JoinStatus::TransferInProgress
                } else {
                    crate::JoinStatus::TransferReady
                }
            }
            Err(status) => status,
        }
    }
}

// ── Catch-up plan and progress ────────────────────────────────────────

/// A plan for the catch-up phase: which segments the new node needs
/// to pull from the bootstrap peer during state transfer.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CatchUpPlan {
    /// Segment IDs to request from the bootstrap peer.
    pub segment_ids: Vec<u64>,
    /// The bootstrap peer that will serve the segments.
    pub bootstrap_peer: MemberId,
    /// The committed root the segments must be consistent with.
    pub committed_root: u64,
    /// Total estimated bytes to transfer.
    pub estimated_bytes: u64,
}

/// Tracks progress through the catch-up phase.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CatchUpProgress {
    /// How many segments have been fully received and verified.
    pub segments_received: u64,
    /// How many segments are in the plan total.
    pub segments_total: u64,
    /// How many bytes have been received and verified.
    pub bytes_received: u64,
    /// Whether the catch-up is complete.
    pub is_complete: bool,
    /// The latest committed root verified.
    pub verified_committed_root: Option<u64>,
}

impl CatchUpProgress {
    /// Create a new progress tracker for the given plan.
    #[must_use]
    pub fn new(plan: &CatchUpPlan) -> Self {
        Self {
            segments_received: 0,
            segments_total: plan.segment_ids.len() as u64,
            bytes_received: 0,
            is_complete: plan.segment_ids.is_empty(),
            verified_committed_root: None,
        }
    }

    /// Record a successfully received segment.
    pub fn record_segment(&mut self, bytes: u64) {
        self.segments_received = self.segments_received.saturating_add(1);
        self.bytes_received = self.bytes_received.saturating_add(bytes);
        if self.segments_received >= self.segments_total {
            self.is_complete = true;
        }
    }

    /// Whether catch-up is complete (all segments received).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.is_complete
    }
}

impl NodeJoin {
    /// Start the join lifecycle from a validated join commit result.
    ///
    /// Transitions directly from Idle to Bootstrapping using the
    /// membership config and committed root received during join.
    /// This skips the JoinRequested state since mutual attestation
    /// already verified the bootstrap peer.
    pub fn start_from_join_commit(
        &mut self,
        commit: &crate::JoinCommitResult,
        bootstrap_peer: MemberId,
        at_ns: u64,
    ) -> Result<(), JoinError> {
        if self.state != NodeJoinState::Idle {
            return Err(JoinError::PreflightDenied(format!(
                "cannot start from join commit in state {:?}",
                self.state
            )));
        }

        // Record the session epoch binding from the join commit.
        self.session_epoch = Some(crate::JoinSessionEpoch::new(
            commit.epoch,
            self.member_id,
            at_ns,
        ));

        self.state = NodeJoinState::Bootstrapping;
        self.state_entered_at_ns = at_ns;
        self.bootstrap_peer = Some(bootstrap_peer);
        self.current_epoch = commit.epoch;
        Ok(())
    }

    /// Transition from Bootstrapping to CatchingUp with a catch-up plan.
    ///
    /// Records bootstrap metrics and creates the catch-up plan for the
    /// state transfer phase.
    pub fn begin_catch_up(
        &mut self,
        plan: &CatchUpPlan,
        bootstrap_bytes: u64,
        at_ns: u64,
    ) -> Result<CatchUpProgress, JoinError> {
        if self.state != NodeJoinState::Bootstrapping {
            return Err(JoinError::PreflightDenied(format!(
                "cannot begin catch-up in state {:?}",
                self.state
            )));
        }

        self.stats.bootstrap_bytes_downloaded = bootstrap_bytes;
        self.state = NodeJoinState::CatchingUp;
        self.state_entered_at_ns = at_ns;
        self.token = None; // Token consumed on bootstrap complete

        Ok(CatchUpProgress::new(plan))
    }

    /// Complete the catch-up phase and transition to Joining.
    ///
    /// The caller reports the progress of segment transfers.
    /// When `progress.is_complete()` is true, transitions to Joining.
    pub fn complete_catch_up(
        &mut self,
        progress: &CatchUpProgress,
        at_ns: u64,
    ) -> Result<(), JoinError> {
        if self.state != NodeJoinState::CatchingUp {
            return Err(JoinError::PreflightDenied(format!(
                "cannot complete catch-up in state {:?}",
                self.state
            )));
        }

        self.stats.txgs_caught_up = progress.segments_received;

        if progress.is_complete() {
            self.state = NodeJoinState::Joining;
            self.state_entered_at_ns = at_ns;
        }

        Ok(())
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_lifecycle_idle_to_joined() {
        let mut join = NodeJoin::new(MemberId::new(42), EpochId::new(1), 1_000_000);
        assert_eq!(join.state, NodeJoinState::Idle);
        assert!(!join.is_terminal());

        // Idle → JoinRequested
        join.request_join(MemberId::new(1), 2_000_000).unwrap();
        assert_eq!(join.state, NodeJoinState::JoinRequested);
        assert_eq!(join.bootstrap_peer, Some(MemberId::new(1)));

        // Accept token → Bootstrapping
        let token = JoinToken::new(
            12345,
            MemberId::new(42),
            MemberId::new(1),
            1_500_000,
            10_000_000_000,
        );
        join.accept_token(token, 2_000_000).unwrap();
        assert_eq!(join.state, NodeJoinState::Bootstrapping);

        // Bootstrap complete → CatchingUp
        join.bootstrap_complete(1048576, 3_000_000).unwrap();
        assert_eq!(join.state, NodeJoinState::CatchingUp);
        assert_eq!(join.stats.bootstrap_bytes_downloaded, 1048576);
        assert!(join.token.is_none()); // Token consumed

        // Catch up some TXGs (not yet complete)
        join.catch_up_progress(5, false, 4_000_000).unwrap();
        assert_eq!(join.state, NodeJoinState::CatchingUp);
        assert_eq!(join.stats.txgs_caught_up, 5);

        // Catch up remaining TXGs → complete → Joining
        join.catch_up_progress(3, true, 5_000_000).unwrap();
        assert_eq!(join.state, NodeJoinState::Joining);
        assert_eq!(join.stats.txgs_caught_up, 8);

        // Join complete → Joined
        join.join_complete(6_000_000).unwrap();
        assert_eq!(join.state, NodeJoinState::Joined);
        assert!(join.is_terminal());
        assert!(join.can_receive_placements());
        assert!(join.stats.join_success);
        assert_eq!(join.stats.join_time_ms, 5); // 5_000_000 ns = 5 ms
    }

    #[test]
    fn join_with_bootstrap_peer() {
        let mut join = NodeJoin::new(MemberId::new(10), EpochId::new(3), 0);
        join.request_join(MemberId::new(99), 1000).unwrap();
        assert_eq!(join.bootstrap_peer, Some(MemberId::new(99)));
        assert_eq!(join.state, NodeJoinState::JoinRequested);

        let token = JoinToken::new(1, MemberId::new(10), MemberId::new(99), 500, 60_000_000_000);
        join.accept_token(token, 1000).unwrap();
        assert_eq!(join.state, NodeJoinState::Bootstrapping);

        join.bootstrap_complete(65536, 2000).unwrap();
        assert_eq!(join.state, NodeJoinState::CatchingUp);
    }

    #[test]
    fn catch_up_zero_missed_txgs() {
        let mut join = NodeJoin::new(MemberId::new(10), EpochId::new(1), 0);
        join.request_join(MemberId::new(1), 1000).unwrap();
        let token = JoinToken::new(1, MemberId::new(10), MemberId::new(1), 500, 60_000_000_000);
        join.accept_token(token, 1000).unwrap();
        join.bootstrap_complete(0, 2000).unwrap();

        // Zero missed TXGs — catch-up completes immediately
        join.catch_up_progress(0, true, 3000).unwrap();
        assert_eq!(join.state, NodeJoinState::Joining);
        assert_eq!(join.stats.txgs_caught_up, 0);
    }

    #[test]
    fn catch_up_n_missed_txgs() {
        let mut join = NodeJoin::new(MemberId::new(10), EpochId::new(1), 0);
        join.request_join(MemberId::new(1), 1000).unwrap();
        let token = JoinToken::new(1, MemberId::new(10), MemberId::new(1), 500, 60_000_000_000);
        join.accept_token(token, 1000).unwrap();
        join.bootstrap_complete(0, 2000).unwrap();

        // First batch: 7 TXGs
        join.catch_up_progress(7, false, 3000).unwrap();
        assert_eq!(join.state, NodeJoinState::CatchingUp);
        assert_eq!(join.stats.txgs_caught_up, 7);

        // Second batch: 5 TXGs, complete
        join.catch_up_progress(5, true, 4000).unwrap();
        assert_eq!(join.state, NodeJoinState::Joining);
        assert_eq!(join.stats.txgs_caught_up, 12);
    }

    #[test]
    fn join_rejected_wrong_token() {
        let mut join = NodeJoin::new(MemberId::new(10), EpochId::new(1), 0);
        join.request_join(MemberId::new(1), 1000).unwrap();

        // Token issued for wrong member
        let bad_token = JoinToken::new(1, MemberId::new(99), MemberId::new(1), 500, 60_000_000_000);
        let err = join.accept_token(bad_token, 1000).unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(..)));
        assert_eq!(join.state, NodeJoinState::JoinRequested); // Unchanged

        // Token issued by wrong bootstrap peer
        let bad_token2 =
            JoinToken::new(1, MemberId::new(10), MemberId::new(7), 500, 60_000_000_000);
        let err = join.accept_token(bad_token2, 1000).unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(..)));

        // Expired token
        let expired_token = JoinToken::new(1, MemberId::new(10), MemberId::new(1), 0, 1000);
        let err = join.accept_token(expired_token, 5000).unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(..)));
    }

    #[test]
    fn join_during_partition_refused() {
        // Simulate that the join has progressed to CatchingUp, but
        // the bootstrap peer becomes unreachable. The join cannot
        // complete without epoch proposal acceptance, so we test
        // that the state machine correctly stays in CatchingUp
        // and then fails when the partition persists.
        let mut join = NodeJoin::new(MemberId::new(10), EpochId::new(1), 0);
        join.request_join(MemberId::new(1), 1000).unwrap();
        let token = JoinToken::new(1, MemberId::new(10), MemberId::new(1), 500, 60_000_000_000);
        join.accept_token(token, 1000).unwrap();
        join.bootstrap_complete(4096, 2000).unwrap();
        join.catch_up_progress(3, true, 3000).unwrap();
        assert_eq!(join.state, NodeJoinState::Joining);

        // In Joining state, the epoch proposal must be accepted by a
        // quorum. If the partition means no quorum can be reached,
        // the join fails.
        join.fail(5000);
        assert_eq!(join.state, NodeJoinState::Failed);
        assert!(!join.stats.join_success);
        assert_eq!(join.stats.join_time_ms, 0); // 5000 ns = 0 ms
    }

    #[test]
    fn cannot_request_join_twice() {
        let mut join = NodeJoin::new(MemberId::new(10), EpochId::new(1), 0);
        join.request_join(MemberId::new(1), 1000).unwrap();
        let err = join.request_join(MemberId::new(2), 2000).unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(..)));
    }

    #[test]
    fn cannot_skip_phases() {
        let mut join = NodeJoin::new(MemberId::new(10), EpochId::new(1), 0);

        // Try to accept token before requesting join
        let token = JoinToken::new(1, MemberId::new(10), MemberId::new(1), 0, 60_000_000_000);
        assert!(join.accept_token(token.clone(), 1000).is_err());

        // Try to complete bootstrap before accepting token
        join.request_join(MemberId::new(1), 1000).unwrap();
        assert!(join.bootstrap_complete(0, 2000).is_err());

        // Try to catch up before bootstrap complete
        join.accept_token(token, 1500).unwrap();
        assert!(join.catch_up_progress(1, true, 2000).is_err());

        // Try to complete join before catch-up
        join.bootstrap_complete(0, 2000).unwrap();
        assert!(join.join_complete(3000).is_err());

        // Catch up then complete
        join.catch_up_progress(0, true, 3000).unwrap();
        join.join_complete(4000).unwrap();
        assert_eq!(join.state, NodeJoinState::Joined);
    }

    #[test]
    fn join_token_expiration() {
        let token = JoinToken::new(42, MemberId::new(10), MemberId::new(1), 1000, 5000);
        assert!(!token.is_expired_at(1000));
        assert!(!token.is_expired_at(5999));
        assert!(token.is_expired_at(6000));
        assert!(token.is_expired_at(10000));
        assert!(token.is_valid_for(MemberId::new(10), 3000));
        assert!(!token.is_valid_for(MemberId::new(99), 3000));
        assert!(!token.is_valid_for(MemberId::new(10), 7000)); // Expired
    }

    #[test]
    fn join_stats_accumulate_correctly() {
        let mut join = NodeJoin::new(MemberId::new(10), EpochId::new(1), 0);
        assert_eq!(join.stats.bootstrap_bytes_downloaded, 0);
        assert_eq!(join.stats.txgs_caught_up, 0);
        assert!(!join.stats.join_success);
        assert_eq!(join.stats.join_time_ms, 0);

        join.request_join(MemberId::new(1), 1_000_000).unwrap();
        let token = JoinToken::new(
            1,
            MemberId::new(10),
            MemberId::new(1),
            500_000,
            60_000_000_000,
        );
        join.accept_token(token, 1_500_000).unwrap();
        join.bootstrap_complete(2_097_152, 2_000_000).unwrap();
        join.catch_up_progress(3, true, 3_000_000).unwrap();
        join.join_complete(4_000_000).unwrap();

        assert_eq!(join.stats.bootstrap_bytes_downloaded, 2_097_152);
        assert_eq!(join.stats.txgs_caught_up, 3);
        assert!(join.stats.join_success);
        assert_eq!(join.stats.join_time_ms, 4); // 4_000_000 ns = 4 ms
    }

    // ── Catch-up phase tests ──────────────────────────────────────

    #[test]
    fn catch_up_plan_default() {
        let plan = CatchUpPlan::default();
        assert!(plan.segment_ids.is_empty());
        assert_eq!(plan.committed_root, 0);
        assert_eq!(plan.estimated_bytes, 0);
    }

    #[test]
    fn catch_up_progress_tracks_segments() {
        let plan = CatchUpPlan {
            segment_ids: vec![1, 2, 3],
            bootstrap_peer: MemberId::new(1),
            committed_root: 0xABCD,
            estimated_bytes: 300,
        };

        let mut progress = CatchUpProgress::new(&plan);
        assert_eq!(progress.segments_total, 3);
        assert_eq!(progress.segments_received, 0);
        assert!(!progress.is_complete());

        progress.record_segment(100);
        assert_eq!(progress.segments_received, 1);
        assert_eq!(progress.bytes_received, 100);
        assert!(!progress.is_complete());

        progress.record_segment(100);
        progress.record_segment(100);
        assert!(progress.is_complete());
        assert_eq!(progress.segments_received, 3);
        assert_eq!(progress.bytes_received, 300);
    }

    #[test]
    fn catch_up_progress_empty_plan_immediate_complete() {
        let plan = CatchUpPlan {
            segment_ids: vec![],
            bootstrap_peer: MemberId::new(1),
            committed_root: 0,
            estimated_bytes: 0,
        };
        let progress = CatchUpProgress::new(&plan);
        assert!(progress.is_complete());
    }

    #[test]
    fn node_join_start_from_join_commit() {
        let mut join = NodeJoin::new(MemberId::new(42), EpochId::new(1), 1_000_000);
        assert_eq!(join.state, NodeJoinState::Idle);

        let commit = crate::JoinCommitResult {
            member_id: MemberId::new(42),
            membership_config: tidefs_membership_epoch::MembershipConfigRecord {
                membership_epoch_id: EpochId::new(5),
                config_class: tidefs_membership_epoch::ConfigClass::Normal,
                version_index: 0,
                voter_set_refs: vec![],
                learner_set_refs: vec![MemberId::new(42)],
                observer_set_refs: vec![],
                joint_old_set_refs: vec![],
                joint_new_set_refs: vec![],
                issuance_receipt_ref: tidefs_membership_epoch::ReceiptId(0),
                digest: 0,
            },
            committed_root: 0xDEAD,
            epoch: EpochId::new(5),
            pool_id: 7,
        };

        join.start_from_join_commit(&commit, MemberId::new(1), 2_000_000)
            .unwrap();
        assert_eq!(join.state, NodeJoinState::Bootstrapping);
        assert_eq!(join.bootstrap_peer, Some(MemberId::new(1)));
        assert_eq!(join.current_epoch, EpochId::new(5));
    }

    #[test]
    fn node_join_begin_catch_up() {
        let mut join = NodeJoin::new(MemberId::new(42), EpochId::new(1), 1_000_000);
        let commit = crate::JoinCommitResult {
            member_id: MemberId::new(42),
            membership_config: tidefs_membership_epoch::MembershipConfigRecord {
                membership_epoch_id: EpochId::new(5),
                config_class: tidefs_membership_epoch::ConfigClass::Normal,
                version_index: 0,
                voter_set_refs: vec![],
                learner_set_refs: vec![MemberId::new(42)],
                observer_set_refs: vec![],
                joint_old_set_refs: vec![],
                joint_new_set_refs: vec![],
                issuance_receipt_ref: tidefs_membership_epoch::ReceiptId(0),
                digest: 0,
            },
            committed_root: 0xBEEF,
            epoch: EpochId::new(5),
            pool_id: 7,
        };

        join.start_from_join_commit(&commit, MemberId::new(1), 2_000_000)
            .unwrap();
        assert_eq!(join.state, NodeJoinState::Bootstrapping);

        let plan = CatchUpPlan {
            segment_ids: vec![10, 20, 30],
            bootstrap_peer: MemberId::new(1),
            committed_root: 0xBEEF,
            estimated_bytes: 96000,
        };

        let progress = join.begin_catch_up(&plan, 65536, 3_000_000).unwrap();
        assert_eq!(join.state, NodeJoinState::CatchingUp);
        assert_eq!(join.stats.bootstrap_bytes_downloaded, 65536);
        assert_eq!(progress.segments_total, 3);
        assert!(!progress.is_complete());
    }

    #[test]
    fn node_join_complete_catch_up() {
        let mut join = NodeJoin::new(MemberId::new(42), EpochId::new(1), 1_000_000);
        let commit = crate::JoinCommitResult {
            member_id: MemberId::new(42),
            membership_config: tidefs_membership_epoch::MembershipConfigRecord {
                membership_epoch_id: EpochId::new(5),
                config_class: tidefs_membership_epoch::ConfigClass::Normal,
                version_index: 0,
                voter_set_refs: vec![],
                learner_set_refs: vec![MemberId::new(42)],
                observer_set_refs: vec![],
                joint_old_set_refs: vec![],
                joint_new_set_refs: vec![],
                issuance_receipt_ref: tidefs_membership_epoch::ReceiptId(0),
                digest: 0,
            },
            committed_root: 0xBEEF,
            epoch: EpochId::new(5),
            pool_id: 7,
        };

        join.start_from_join_commit(&commit, MemberId::new(1), 2_000_000)
            .unwrap();

        let plan = CatchUpPlan {
            segment_ids: vec![10, 20],
            bootstrap_peer: MemberId::new(1),
            committed_root: 0xBEEF,
            estimated_bytes: 64000,
        };

        let mut progress = join.begin_catch_up(&plan, 0, 3_000_000).unwrap();
        assert_eq!(join.state, NodeJoinState::CatchingUp);

        // Not yet complete
        progress.record_segment(32000);
        join.complete_catch_up(&progress, 4_000_000).unwrap();
        assert_eq!(join.state, NodeJoinState::CatchingUp); // Still catching up

        // Complete
        progress.record_segment(32000);
        join.complete_catch_up(&progress, 5_000_000).unwrap();
        assert_eq!(join.state, NodeJoinState::Joining);
        assert_eq!(join.stats.txgs_caught_up, 2);

        // Finalize
        join.join_complete(6_000_000).unwrap();
        assert_eq!(join.state, NodeJoinState::Joined);
        assert!(join.can_receive_placements());
    }

    #[test]
    fn node_join_cannot_start_from_commit_twice() {
        let mut join = NodeJoin::new(MemberId::new(42), EpochId::new(1), 1_000_000);
        let commit = crate::JoinCommitResult {
            member_id: MemberId::new(42),
            membership_config: tidefs_membership_epoch::MembershipConfigRecord {
                membership_epoch_id: EpochId::new(5),
                config_class: tidefs_membership_epoch::ConfigClass::Normal,
                version_index: 0,
                voter_set_refs: vec![],
                learner_set_refs: vec![MemberId::new(42)],
                observer_set_refs: vec![],
                joint_old_set_refs: vec![],
                joint_new_set_refs: vec![],
                issuance_receipt_ref: tidefs_membership_epoch::ReceiptId(0),
                digest: 0,
            },
            committed_root: 0xBEEF,
            epoch: EpochId::new(5),
            pool_id: 7,
        };

        join.start_from_join_commit(&commit, MemberId::new(1), 2_000_000)
            .unwrap();
        let err = join
            .start_from_join_commit(&commit, MemberId::new(1), 3_000_000)
            .unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(..)));
    }

    #[test]
    fn node_join_begin_catch_up_only_from_bootstrapping() {
        let mut join = NodeJoin::new(MemberId::new(42), EpochId::new(1), 1_000_000);
        // Still in Idle
        let plan = CatchUpPlan::default();
        let err = join.begin_catch_up(&plan, 0, 2_000_000).unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(..)));
    }
}
