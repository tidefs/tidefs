// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Node join handshake protocol: epoch-verified join request/response
//! with structured rejection reasons.
//!
//! Wraps the wire-level [`JoinHandshake`] from [`discovery`] with
//! higher-level epoch verification against the current membership
//! epoch. Provides a typed rejection model so callers can distinguish
//! transient failures (stale epoch) from permanent ones (pool full).
//!
//! # Protocol flow
//!
//! ```text
//! Joiner                          Pool Member
//!   |                                |
//!   |── DiscoveryProbe ────────────>|
//!   |<── DiscoveryResponse ─────────|
//!   |── JoinHandshakeRequest ──────>|
//!   |                                |── verify_epoch()
//!   |                                |── decide_accept()
//!   |<── JoinHandshakeResponse ──────|
//!   |── verify_acceptance() ────────>|
//!   |<══════ active session ═══════>|
//! ```

use crate::discovery::{JoinHandshake, JoinHandshakeConfig, JoinHandshakeResponse};

use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::{EpochId, MemberId, MembershipConfigRecord};

// ── Rejection reason ─────────────────────────────────────────────────

/// Structured rejection reason for join handshake refusal.
///
/// Each variant carries the context needed for the caller to decide
/// whether to retry (stale epoch), reconfigure, or give up.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RejectionReason {
    /// Epoch mismatch: the joining node's epoch does not match the pool.
    EpochMismatch { expected: EpochId, got: EpochId },
    /// Epoch is stale: the joining node is behind and must catch up.
    EpochStale { expected: EpochId, got: EpochId },
    /// Pool has reached its configured member limit.
    PoolFull { current: usize, max: usize },
    /// A member with this identity already exists.
    MemberAlreadyExists { member_id: MemberId },
    /// Joining node's capabilities are insufficient.
    InsufficientCapabilities { required: u64, provided: u64 },
    /// Protocol version mismatch between joiner and pool.
    ProtocolVersionMismatch { expected: u32, got: u32 },
    /// A custom, human-readable reason.
    Custom(String),
}

impl RejectionReason {
    #[must_use]
    pub fn as_str(&self) -> String {
        match self {
            Self::EpochMismatch { expected, got } => {
                format!("epoch mismatch: expected {expected:?}, got {got:?}")
            }
            Self::EpochStale { expected, got } => {
                format!("epoch stale: expected {expected:?}, got {got:?} (node must catch up)")
            }
            Self::PoolFull { current, max } => {
                format!("pool full: {current}/{max} members")
            }
            Self::MemberAlreadyExists { member_id } => {
                format!("member already exists: {member_id:?}")
            }
            Self::InsufficientCapabilities { required, provided } => {
                format!("insufficient capabilities: required {required:#x}, provided {provided:#x}")
            }
            Self::ProtocolVersionMismatch { expected, got } => {
                format!("protocol version mismatch: expected {expected}, got {got}")
            }
            Self::Custom(reason) => reason.clone(),
        }
    }

    /// Whether this rejection reason is retryable (the caller can
    /// attempt again after correcting the issue).
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::EpochStale { .. })
    }

    /// Whether this rejection reason is permanent (the caller should
    /// not retry without manual intervention).
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        !self.is_retryable()
    }
}

impl std::fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ── Epoch verifier trait ─────────────────────────────────────────────

/// Trait for verifying epoch compatibility during a join handshake.
///
/// Implementations query the local membership view to determine whether
/// the joining node's epoch is acceptable. This trait boundary avoids
/// a direct dependency on `tidefs-membership-live`.
pub trait EpochVerifier {
    /// Verify that a joining node with the given epoch is acceptable.
    ///
    /// Returns `Ok(())` if the epoch is valid, or a [`RejectionReason`]
    /// explaining why the join should be rejected.
    fn verify_join_epoch(
        &self,
        joiner_epoch: EpochId,
        current_epoch: EpochId,
    ) -> Result<(), RejectionReason>;

    /// Return the current pool epoch as known to this verifier.
    fn current_epoch(&self) -> EpochId;

    /// Check whether the pool can accept another member.
    ///
    /// Returns `Ok(())` if there is room, or a [`RejectionReason`].
    fn check_pool_capacity(
        &self,
        current_count: usize,
        max_members: usize,
    ) -> Result<(), RejectionReason> {
        if current_count >= max_members {
            Err(RejectionReason::PoolFull {
                current: current_count,
                max: max_members,
            })
        } else {
            Ok(())
        }
    }
}

// ── Node join handshake orchestrator ─────────────────────────────────

/// Higher-level orchestrator that wraps the wire-level [`JoinHandshake`]
/// with epoch verification and structured rejection.
///
/// Manages the full join handshake flow:
///
/// 1. Discovery: locate pool members via broadcast probes
/// 2. Epoch verification: check that the joining node's epoch is current
/// 3. Join decision: accept or reject with structured reason
/// 4. Activation: transition to active and register the node
///
/// # Example
///
/// ```ignore
/// use tidefs_node_join::handshake::{NodeJoinHandshake, EpochVerifier};
/// use tidefs_node_join::discovery::JoinHandshakeConfig;
///
/// let mut hs = NodeJoinHandshake::new(
///     node_identity,
///     JoinHandshakeConfig::default(),
///     EpochId::new(1),
///     0,
/// );
///
/// // After discovery + join request, verify epoch:
/// match hs.verify_epoch(&verifier, pool_epoch) {
///     Ok(()) => { /* proceed */ }
///     Err(reason) => { /* reject with reason */ }
/// }
/// ```
#[derive(Clone, Debug)]
pub struct NodeJoinHandshake {
    /// The wire-level handshake.
    pub inner: JoinHandshake,
    /// Whether epoch verification has passed.
    pub epoch_verified: bool,
    /// The rejection reason if the join was refused.
    pub rejection: Option<RejectionReason>,
    /// The epoch the joining node proposes.
    pub target_epoch: EpochId,
    /// The join session epoch binding recorded on successful join.
    /// Set by `record_session_epoch` after the handshake is active.
    pub session_epoch: Option<crate::JoinSessionEpoch>,
}

impl NodeJoinHandshake {
    /// Create a new node join handshake orchestrator.
    #[must_use]
    pub fn new(
        node_identity: tidefs_membership_epoch::NodeIdentity,
        config: JoinHandshakeConfig,
        target_epoch: EpochId,
        now_ns: u64,
    ) -> Self {
        Self {
            inner: JoinHandshake::new(node_identity, config, now_ns),
            epoch_verified: false,
            rejection: None,
            target_epoch,
            session_epoch: None,
        }
    }

    /// Verify the joining node's epoch against the pool's current epoch
    /// using the given [`EpochVerifier`].
    ///
    /// On success, sets `epoch_verified = true`. On failure, sets
    /// `rejection` and returns the error.
    pub fn verify_epoch(
        &mut self,
        verifier: &dyn EpochVerifier,
        pool_epoch: EpochId,
    ) -> Result<(), RejectionReason> {
        match verifier.verify_join_epoch(self.target_epoch, pool_epoch) {
            Ok(()) => {
                self.epoch_verified = true;
                self.rejection = None;
                Ok(())
            }
            Err(reason) => {
                self.reject(reason.clone());
                Err(reason)
            }
        }
    }

    /// Decide whether to accept the join based on the current handshake
    /// state and epoch verification.
    ///
    /// Returns `Ok(())` if all conditions are met. Returns `Err` with a
    /// structured rejection reason otherwise.
    ///
    /// Checks:
    /// - Handshake is in Syncing state (discovery completed)
    /// - Epoch has been verified
    /// - No prior rejection exists
    pub fn decide_accept(&self) -> Result<(), RejectionReason> {
        if let Some(ref rejection) = self.rejection {
            return Err(rejection.clone());
        }

        if !self.epoch_verified {
            return Err(RejectionReason::Custom("epoch not yet verified".into()));
        }

        if self.inner.state != crate::discovery::HandshakeState::Syncing {
            return Err(RejectionReason::Custom(format!(
                "handshake not in syncing state: {:?}",
                self.inner.state
            )));
        }

        Ok(())
    }

    /// Build an accept response for the joining node.
    ///
    /// Call after `decide_accept()` returns `Ok(())`.
    /// Includes the membership config and committed root so the joiner
    /// can begin phase promotion.
    #[must_use]
    pub fn build_accept_response(
        &self,
        assigned_member_id: MemberId,
        config: MembershipConfigRecord,
        committed_root: u64,
    ) -> JoinHandshakeResponse {
        JoinHandshakeResponse::accept_with_config(
            assigned_member_id,
            self.target_epoch,
            config,
            committed_root,
        )
    }

    /// Build a reject response with the given reason.
    #[must_use]
    pub fn build_reject_response(&self, reason: &RejectionReason) -> JoinHandshakeResponse {
        JoinHandshakeResponse::reject(reason.as_str())
    }

    /// Mark the handshake as rejected locally (no wire message sent).
    pub fn reject(&mut self, reason: RejectionReason) {
        self.rejection = Some(reason);
        self.epoch_verified = false;
    }

    /// Whether the handshake completed successfully (inner Active and
    /// epoch verified).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.inner.is_active() && self.epoch_verified
    }

    /// Whether the join was rejected.
    #[must_use]
    pub fn is_rejected(&self) -> bool {
        self.rejection.is_some()
    }

    /// Whether the join is ready for activation (handshake active,
    /// epoch verified, no rejection).
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.is_active() && !self.is_rejected()
    }

    /// Record the join session epoch binding after a successful handshake.
    ///
    /// Stores the membership epoch, quorum evidence, and joining member
    /// identity for use by state transfer and promotion gates.
    /// Must only be called when the handshake is active and epoch-verified.
    pub fn record_session_epoch(
        &mut self,
        joining_member_id: tidefs_membership_epoch::MemberId,
        quorum_evidence: Option<crate::QuorumEvidence>,
    ) -> Result<(), crate::JoinError> {
        if !self.is_active() {
            return Err(crate::JoinError::PreflightDenied(
                "cannot record session epoch: handshake not active".into(),
            ));
        }

        let session = crate::JoinSessionEpoch::new(
            self.target_epoch,
            joining_member_id,
            0, // nonce assigned by caller or generated externally
        );

        let session = if let Some(qe) = quorum_evidence {
            session.with_quorum(qe)
        } else {
            session
        };

        self.session_epoch = Some(session);
        Ok(())
    }

    /// The operator-visible join status for this handshake.
    #[must_use]
    pub fn join_status(&self, current_epoch: EpochId) -> crate::JoinStatus {
        if self.is_rejected() {
            return crate::JoinStatus::Failed(
                self.rejection
                    .as_ref()
                    .map_or_else(|| "rejected".into(), |r| r.to_string()),
            );
        }

        if !self.is_active() {
            return crate::JoinStatus::WaitingForQuorum;
        }

        let session = match &self.session_epoch {
            Some(s) => s,
            None => return crate::JoinStatus::MissingEpochEvidence,
        };

        let assigned_id = match self.inner.assigned_member_id {
            Some(id) => id,
            None => return crate::JoinStatus::MissingEpochEvidence,
        };

        match session.is_valid_for(assigned_id, current_epoch) {
            Ok(()) => crate::JoinStatus::TransferReady,
            Err(status) => status,
        }
    }
}

// ── Default epoch verifier ───────────────────────────────────────────

/// A simple epoch verifier that requires exact epoch match.
///
/// Used when the pool does not support catching up stale joiners.
/// For production use, a membership-live-backed verifier should
/// be implemented that handles epoch transitions gracefully.
#[derive(Clone, Debug)]
pub struct StrictEpochVerifier {
    /// Current pool epoch.
    epoch: EpochId,
    /// Maximum pool members.
    #[allow(dead_code)]
    max_members: usize,
    /// Current member count.
    current_member_count: usize,
}

impl StrictEpochVerifier {
    /// Create a new strict epoch verifier.
    #[must_use]
    pub fn new(epoch: EpochId, max_members: usize, current_member_count: usize) -> Self {
        Self {
            epoch,
            max_members,
            current_member_count,
        }
    }

    /// Update the current member count (e.g., after a node joins or leaves).
    pub fn set_member_count(&mut self, count: usize) {
        self.current_member_count = count;
    }

    /// Update the pool epoch (e.g., after an epoch transition).
    pub fn set_epoch(&mut self, epoch: EpochId) {
        self.epoch = epoch;
    }
}

impl EpochVerifier for StrictEpochVerifier {
    fn verify_join_epoch(
        &self,
        joiner_epoch: EpochId,
        current_epoch: EpochId,
    ) -> Result<(), RejectionReason> {
        if joiner_epoch < current_epoch {
            Err(RejectionReason::EpochStale {
                expected: current_epoch,
                got: joiner_epoch,
            })
        } else if joiner_epoch != current_epoch {
            Err(RejectionReason::EpochMismatch {
                expected: current_epoch,
                got: joiner_epoch,
            })
        } else {
            Ok(())
        }
    }

    fn current_epoch(&self) -> EpochId {
        self.epoch
    }

    fn check_pool_capacity(
        &self,
        current_count: usize,
        max_members: usize,
    ) -> Result<(), RejectionReason> {
        if current_count >= max_members {
            Err(RejectionReason::PoolFull {
                current: current_count,
                max: max_members,
            })
        } else {
            Ok(())
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::JoinHandshakeConfig;
    use tidefs_membership_epoch::NodeIdentity;

    fn test_identity(id: u64) -> NodeIdentity {
        NodeIdentity::new(id)
    }

    // ── RejectionReason tests ──────────────────────────────────────

    #[test]
    fn rejection_reason_display() {
        let r = RejectionReason::EpochMismatch {
            expected: EpochId::new(10),
            got: EpochId::new(5),
        };
        assert!(r.as_str().contains("epoch mismatch"));
        assert!(r.as_str().contains("10"));
        assert!(r.as_str().contains("5"));

        let r = RejectionReason::PoolFull { current: 7, max: 7 };
        assert!(r.as_str().contains("pool full"));
        assert!(r.as_str().contains("7/7"));
    }

    #[test]
    fn rejection_reason_retryability() {
        assert!(RejectionReason::EpochStale {
            expected: EpochId::new(10),
            got: EpochId::new(5),
        }
        .is_retryable());

        assert!(RejectionReason::EpochMismatch {
            expected: EpochId::new(10),
            got: EpochId::new(5),
        }
        .is_permanent());

        assert!(RejectionReason::PoolFull { current: 7, max: 7 }.is_permanent());

        assert!(RejectionReason::MemberAlreadyExists {
            member_id: MemberId::new(42),
        }
        .is_permanent());
    }

    #[test]
    fn rejection_reason_serialization() {
        let reason = RejectionReason::EpochMismatch {
            expected: EpochId::new(10),
            got: EpochId::new(5),
        };
        let json = bincode::serialize(&reason).unwrap();
        let back: RejectionReason = bincode::deserialize(&json).unwrap();
        assert_eq!(back, reason);
    }

    // ── StrictEpochVerifier tests ──────────────────────────────────

    #[test]
    fn strict_verifier_accepts_matching_epoch() {
        let verifier = StrictEpochVerifier::new(EpochId::new(10), 8, 3);
        assert!(verifier
            .verify_join_epoch(EpochId::new(10), EpochId::new(10))
            .is_ok());
        assert_eq!(verifier.current_epoch(), EpochId::new(10));
    }

    #[test]
    fn strict_verifier_rejects_mismatched_epoch() {
        let verifier = StrictEpochVerifier::new(EpochId::new(10), 8, 3);
        let err = verifier
            .verify_join_epoch(EpochId::new(15), EpochId::new(10))
            .unwrap_err();
        assert!(matches!(err, RejectionReason::EpochMismatch { .. }));
    }

    #[test]
    fn strict_verifier_rejects_stale_epoch() {
        let verifier = StrictEpochVerifier::new(EpochId::new(10), 8, 3);
        let err = verifier
            .verify_join_epoch(EpochId::new(5), EpochId::new(10))
            .unwrap_err();
        assert!(matches!(err, RejectionReason::EpochStale { .. }));
    }

    #[test]
    fn strict_verifier_pool_capacity() {
        let verifier = StrictEpochVerifier::new(EpochId::new(1), 8, 7);
        // Room for one more
        assert!(verifier.check_pool_capacity(7, 8).is_ok());
        // Pool full
        let err = verifier.check_pool_capacity(8, 8).unwrap_err();
        assert!(matches!(err, RejectionReason::PoolFull { .. }));
    }

    // ── NodeJoinHandshake tests ────────────────────────────────────

    #[test]
    fn node_join_handshake_creation() {
        let hs = NodeJoinHandshake::new(
            test_identity(1),
            JoinHandshakeConfig::default(),
            EpochId::new(10),
            1000,
        );
        assert!(!hs.epoch_verified);
        assert!(hs.rejection.is_none());
        assert_eq!(hs.target_epoch, EpochId::new(10));
        assert_eq!(hs.inner.state, crate::discovery::HandshakeState::Candidate);
    }

    #[test]
    fn epoch_verification_success() {
        let mut hs = NodeJoinHandshake::new(
            test_identity(1),
            JoinHandshakeConfig::default(),
            EpochId::new(10),
            1000,
        );
        let verifier = StrictEpochVerifier::new(EpochId::new(10), 8, 3);

        hs.verify_epoch(&verifier, EpochId::new(10)).unwrap();
        assert!(hs.epoch_verified);
        assert!(hs.rejection.is_none());
    }

    #[test]
    fn epoch_verification_failure() {
        let mut hs = NodeJoinHandshake::new(
            test_identity(1),
            JoinHandshakeConfig::default(),
            EpochId::new(5),
            1000,
        );
        let verifier = StrictEpochVerifier::new(EpochId::new(10), 8, 3);

        let err = hs.verify_epoch(&verifier, EpochId::new(10)).unwrap_err();
        assert!(!hs.epoch_verified);
        assert!(matches!(err, RejectionReason::EpochStale { .. }));
        assert_eq!(hs.rejection, Some(err));
    }

    #[test]
    fn decide_accept_requires_verified_epoch() {
        let verifier = StrictEpochVerifier::new(EpochId::new(10), 8, 3);

        let mut hs = NodeJoinHandshake::new(
            test_identity(1),
            JoinHandshakeConfig::default(),
            EpochId::new(10),
            1000,
        );

        // Not yet verified
        let err = hs.decide_accept().unwrap_err();
        assert!(matches!(err, RejectionReason::Custom(_)));
        assert!(err.as_str().contains("epoch not yet verified"));

        // Verify then decide
        hs.verify_epoch(&verifier, EpochId::new(10)).unwrap();

        // Still not in Syncing state (need discovery first)
        let err = hs.decide_accept().unwrap_err();
        assert!(matches!(err, RejectionReason::Custom(_)));
        assert!(err.as_str().contains("not in syncing state"));
    }

    #[test]
    fn decide_accept_rejects_when_rejection_already_set() {
        let mut hs = NodeJoinHandshake::new(
            test_identity(1),
            JoinHandshakeConfig::default(),
            EpochId::new(10),
            1000,
        );
        hs.reject(RejectionReason::PoolFull { current: 8, max: 8 });

        let err = hs.decide_accept().unwrap_err();
        assert!(matches!(err, RejectionReason::PoolFull { .. }));
    }

    #[test]
    fn build_accept_response() {
        let verifier = StrictEpochVerifier::new(EpochId::new(10), 8, 3);
        let mut hs = NodeJoinHandshake::new(
            test_identity(1),
            JoinHandshakeConfig::default(),
            EpochId::new(10),
            1000,
        );
        hs.verify_epoch(&verifier, EpochId::new(10)).unwrap();

        // Manually advance to Syncing (simulating discovery completion)
        hs.inner.probe_sent(2000).unwrap();
        hs.inner
            .on_discovery_response(
                &crate::discovery::DiscoveryResponse::new(
                    EpochId::new(10),
                    true,
                    MemberId::new(2),
                    42,
                ),
                3000,
            )
            .unwrap();
        assert_eq!(hs.inner.state, crate::discovery::HandshakeState::Syncing);

        assert!(hs.decide_accept().is_ok());

        let config = tidefs_membership_epoch::MembershipConfigRecord {
            membership_epoch_id: EpochId::new(10),
            config_class: tidefs_membership_epoch::ConfigClass::Normal,
            version_index: 0,
            voter_set_refs: vec![MemberId::new(2)],
            learner_set_refs: vec![MemberId::new(1)],
            observer_set_refs: vec![],
            joint_old_set_refs: vec![],
            joint_new_set_refs: vec![],
            issuance_receipt_ref: tidefs_membership_epoch::ReceiptId(0),
            digest: 0,
        };

        let resp = hs.build_accept_response(MemberId::new(1), config, 0xBEEF);
        assert!(resp.accepted);
        assert_eq!(resp.assigned_member_id, MemberId::new(1));
        assert_eq!(resp.current_epoch, EpochId::new(10));
        assert_eq!(resp.committed_root, 0xBEEF);
    }

    #[test]
    fn build_reject_response() {
        let hs = NodeJoinHandshake::new(
            test_identity(1),
            JoinHandshakeConfig::default(),
            EpochId::new(5),
            1000,
        );
        let reason = RejectionReason::EpochMismatch {
            expected: EpochId::new(10),
            got: EpochId::new(5),
        };
        let resp = hs.build_reject_response(&reason);
        assert!(!resp.accepted);
        assert_eq!(resp.rejection_reason, Some(reason.as_str()));
    }

    #[test]
    fn reject_method_sets_rejection() {
        let mut hs = NodeJoinHandshake::new(
            test_identity(1),
            JoinHandshakeConfig::default(),
            EpochId::new(10),
            1000,
        );
        assert!(!hs.is_rejected());

        hs.reject(RejectionReason::MemberAlreadyExists {
            member_id: MemberId::new(42),
        });
        assert!(hs.is_rejected());
        assert!(!hs.is_ready());
        assert!(!hs.is_active());
    }

    #[test]
    fn is_ready_requires_active_handshake() {
        let verifier = StrictEpochVerifier::new(EpochId::new(10), 8, 3);
        let mut hs = NodeJoinHandshake::new(
            test_identity(1),
            JoinHandshakeConfig::default(),
            EpochId::new(10),
            1000,
        );
        hs.verify_epoch(&verifier, EpochId::new(10)).unwrap();

        // Inner handshake is still Candidate — not ready
        assert!(!hs.is_ready());
        assert!(!hs.is_active());
    }

    // ── Integration: full handshake flow with epoch verification ──

    #[test]
    fn full_handshake_with_epoch_verification() {
        let mut hs = NodeJoinHandshake::new(
            test_identity(1),
            JoinHandshakeConfig::default(),
            EpochId::new(10),
            1000,
        );

        // Discovery → Syncing
        hs.inner.probe_sent(2000).unwrap();
        hs.inner
            .on_discovery_response(
                &crate::discovery::DiscoveryResponse::new(
                    EpochId::new(10),
                    true,
                    MemberId::new(2),
                    42,
                ),
                3000,
            )
            .unwrap();
        assert_eq!(hs.inner.state, crate::discovery::HandshakeState::Syncing);

        // Epoch verification
        let verifier = StrictEpochVerifier::new(EpochId::new(10), 8, 3);
        hs.verify_epoch(&verifier, EpochId::new(10)).unwrap();

        // Decide accept
        assert!(hs.decide_accept().is_ok());

        // Receive join acceptance
        let config = tidefs_membership_epoch::MembershipConfigRecord {
            membership_epoch_id: EpochId::new(10),
            config_class: tidefs_membership_epoch::ConfigClass::Normal,
            version_index: 0,
            voter_set_refs: vec![MemberId::new(2)],
            learner_set_refs: vec![MemberId::new(1)],
            observer_set_refs: vec![],
            joint_old_set_refs: vec![],
            joint_new_set_refs: vec![],
            issuance_receipt_ref: tidefs_membership_epoch::ReceiptId(0),
            digest: 0,
        };
        let resp = hs.build_accept_response(MemberId::new(1), config, 0xCAFE);
        hs.inner.on_join_response(&resp, 4000).unwrap();
        assert_eq!(hs.inner.state, crate::discovery::HandshakeState::Active);
        assert!(hs.is_active());
        assert!(hs.is_ready());
    }

    #[test]
    fn full_handshake_with_epoch_rejection() {
        let mut hs = NodeJoinHandshake::new(
            test_identity(1),
            JoinHandshakeConfig::default(),
            EpochId::new(5),
            1000,
        );

        // Discovery → Syncing
        hs.inner.probe_sent(2000).unwrap();
        hs.inner
            .on_discovery_response(
                &crate::discovery::DiscoveryResponse::new(
                    EpochId::new(10),
                    true,
                    MemberId::new(2),
                    42,
                ),
                3000,
            )
            .unwrap();

        // Epoch verification fails
        let verifier = StrictEpochVerifier::new(EpochId::new(10), 8, 3);
        let err = hs.verify_epoch(&verifier, EpochId::new(10)).unwrap_err();
        assert!(matches!(err, RejectionReason::EpochStale { .. }));
        assert_eq!(hs.rejection, Some(err.clone()));

        // Build rejection response
        let resp = hs.build_reject_response(&err);
        hs.inner.on_join_response(&resp, 4000).unwrap();
        assert_eq!(hs.inner.state, crate::discovery::HandshakeState::Rejected);
        assert!(hs.inner.rejection_reason.is_some());
    }

    // ── Two-node handshake with epoch verification over transport ──

    #[test]
    fn two_node_handshake_with_epoch_verification_over_transport() {
        use std::cell::RefCell;
        use std::rc::Rc;
        use tidefs_transport::harness::{DeterministicMessageScheduler, SchedulerConfig};

        let sched = Rc::new(RefCell::new(DeterministicMessageScheduler::new(
            SchedulerConfig::deterministic(42),
        )));

        let n_joiner = NodeIdentity::new(1);
        let n_member = NodeIdentity::new(2);

        sched.borrow_mut().register_node(n_joiner);
        sched.borrow_mut().register_node(n_member);

        // --- Joiner: discovery ---
        let mut hs = NodeJoinHandshake::new(
            n_joiner,
            JoinHandshakeConfig::default(),
            EpochId::new(10),
            0,
        );
        hs.inner.probe_sent(1000).unwrap();
        let probe = hs.inner.build_discovery_probe(0);
        sched
            .borrow_mut()
            .send(n_joiner, n_member, 0, probe.encode().unwrap(), 0);
        sched.borrow_mut().tick_n(2);

        // Pool member responds with discovery
        {
            let mut s = sched.borrow_mut();
            let mut responses: Vec<(NodeIdentity, Vec<u8>, u64)> = Vec::new();
            while let Some(_msg) = s.recv(n_member) {
                let resp = crate::discovery::DiscoveryResponse::new(
                    EpochId::new(10),
                    true,
                    MemberId::new(2),
                    42,
                );
                responses.push((n_joiner, resp.encode().unwrap(), 1));
            }
            for (to, payload, seq) in responses {
                s.send(n_member, to, 0, payload, seq);
            }
        }
        sched.borrow_mut().tick_n(1);

        while let Some(msg) = sched.borrow_mut().recv(n_joiner) {
            hs.inner
                .on_discovery_response(
                    &crate::discovery::DiscoveryResponse::decode(&msg.payload).unwrap(),
                    2000,
                )
                .unwrap();
        }
        assert_eq!(hs.inner.state, crate::discovery::HandshakeState::Syncing);

        // Epoch verification on pool member side
        let verifier = StrictEpochVerifier::new(EpochId::new(10), 8, 3);
        hs.verify_epoch(&verifier, EpochId::new(10)).unwrap();
        assert!(hs.decide_accept().is_ok());

        // Joiner sends join request
        let join_req = hs
            .inner
            .build_join_request(tidefs_membership_epoch::MemberClass::Learner, 999)
            .unwrap();
        sched
            .borrow_mut()
            .send(n_joiner, n_member, 0, join_req.encode().unwrap(), 2);
        sched.borrow_mut().tick_n(2);

        // Pool member: verify epoch, accept join
        {
            let mut s = sched.borrow_mut();
            let mut responses: Vec<(NodeIdentity, Vec<u8>, u64)> = Vec::new();
            while let Some(_msg) = s.recv(n_member) {
                // On the pool member side, verify epoch
                let pool_verifier = StrictEpochVerifier::new(EpochId::new(10), 8, 3);
                let mut pool_hs = NodeJoinHandshake::new(
                    n_member,
                    JoinHandshakeConfig::default(),
                    EpochId::new(10),
                    0,
                );
                pool_hs.inner.probe_sent(1000).unwrap();
                pool_hs
                    .inner
                    .on_discovery_response(
                        &crate::discovery::DiscoveryResponse::new(
                            EpochId::new(10),
                            true,
                            MemberId::new(1),
                            42,
                        ),
                        2000,
                    )
                    .unwrap();
                pool_hs
                    .verify_epoch(&pool_verifier, EpochId::new(10))
                    .unwrap();
                assert!(pool_hs.decide_accept().is_ok());

                let config = tidefs_membership_epoch::MembershipConfigRecord {
                    membership_epoch_id: EpochId::new(10),
                    config_class: tidefs_membership_epoch::ConfigClass::Normal,
                    version_index: 0,
                    voter_set_refs: vec![MemberId::new(2)],
                    learner_set_refs: vec![MemberId::new(1)],
                    observer_set_refs: vec![],
                    joint_old_set_refs: vec![],
                    joint_new_set_refs: vec![],
                    issuance_receipt_ref: tidefs_membership_epoch::ReceiptId(0),
                    digest: 0,
                };
                let resp = pool_hs.build_accept_response(MemberId::new(1), config, 0xFEED);
                responses.push((n_joiner, resp.encode().unwrap(), 3));
            }
            for (to, payload, seq) in responses {
                s.send(n_member, to, 0, payload, seq);
            }
        }
        sched.borrow_mut().tick_n(1);

        // Joiner receives acceptance
        while let Some(msg) = sched.borrow_mut().recv(n_joiner) {
            hs.inner
                .on_join_response(
                    &crate::discovery::JoinHandshakeResponse::decode(&msg.payload).unwrap(),
                    3000,
                )
                .unwrap();
        }
        assert_eq!(hs.inner.state, crate::discovery::HandshakeState::Active);
        assert!(hs.is_active());
        assert!(hs.is_ready());
    }

    #[test]
    fn two_node_handshake_epoch_mismatch_rejection_over_transport() {
        use std::cell::RefCell;
        use std::rc::Rc;
        use tidefs_transport::harness::{DeterministicMessageScheduler, SchedulerConfig};

        let sched = Rc::new(RefCell::new(DeterministicMessageScheduler::new(
            SchedulerConfig::deterministic(789),
        )));

        let n_joiner = NodeIdentity::new(1);
        let n_member = NodeIdentity::new(2);

        sched.borrow_mut().register_node(n_joiner);
        sched.borrow_mut().register_node(n_member);

        // Joiner has epoch 5, pool has epoch 10
        let mut hs =
            NodeJoinHandshake::new(n_joiner, JoinHandshakeConfig::default(), EpochId::new(5), 0);
        hs.inner.probe_sent(1000).unwrap();
        sched.borrow_mut().send(
            n_joiner,
            n_member,
            0,
            hs.inner.build_discovery_probe(0).encode().unwrap(),
            0,
        );
        sched.borrow_mut().tick_n(2);

        {
            let mut s = sched.borrow_mut();
            let mut responses: Vec<(NodeIdentity, Vec<u8>, u64)> = Vec::new();
            while let Some(_msg) = s.recv(n_member) {
                let resp = crate::discovery::DiscoveryResponse::new(
                    EpochId::new(10),
                    true,
                    MemberId::new(2),
                    42,
                );
                responses.push((n_joiner, resp.encode().unwrap(), 1));
            }
            for (to, payload, seq) in responses {
                s.send(n_member, to, 0, payload, seq);
            }
        }
        sched.borrow_mut().tick_n(1);

        while let Some(msg) = sched.borrow_mut().recv(n_joiner) {
            hs.inner
                .on_discovery_response(
                    &crate::discovery::DiscoveryResponse::decode(&msg.payload).unwrap(),
                    2000,
                )
                .unwrap();
        }

        // Epoch verification fails: joiner has epoch 5, pool has 10
        let verifier = StrictEpochVerifier::new(EpochId::new(10), 8, 3);
        let err = hs.verify_epoch(&verifier, EpochId::new(10)).unwrap_err();
        assert!(matches!(err, RejectionReason::EpochStale { .. }));

        // Pool member sends rejection
        let join_req = hs
            .inner
            .build_join_request(tidefs_membership_epoch::MemberClass::Learner, 1)
            .unwrap();
        sched
            .borrow_mut()
            .send(n_joiner, n_member, 0, join_req.encode().unwrap(), 2);
        sched.borrow_mut().tick_n(1);

        {
            let mut s = sched.borrow_mut();
            let mut responses: Vec<(NodeIdentity, Vec<u8>, u64)> = Vec::new();
            while let Some(_msg) = s.recv(n_member) {
                let resp = hs.build_reject_response(&err);
                responses.push((n_joiner, resp.encode().unwrap(), 3));
            }
            for (to, payload, seq) in responses {
                s.send(n_member, to, 0, payload, seq);
            }
        }
        sched.borrow_mut().tick_n(1);

        while let Some(msg) = sched.borrow_mut().recv(n_joiner) {
            hs.inner
                .on_join_response(
                    &crate::discovery::JoinHandshakeResponse::decode(&msg.payload).unwrap(),
                    3000,
                )
                .unwrap();
        }
        assert_eq!(hs.inner.state, crate::discovery::HandshakeState::Rejected);
        assert!(hs.inner.rejection_reason.is_some());
        assert!(!hs.is_ready());
    }

    #[test]
    fn rejection_reason_roundtrip_via_bincode() {
        let reason = RejectionReason::EpochStale {
            expected: EpochId::new(15),
            got: EpochId::new(8),
        };
        let encoded = bincode::serialize(&reason).unwrap();
        let decoded: RejectionReason = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, reason);

        let reason2 = RejectionReason::Custom("testing 1 2 3".into());
        let encoded2 = bincode::serialize(&reason2).unwrap();
        let decoded2: RejectionReason = bincode::deserialize(&encoded2).unwrap();
        assert_eq!(decoded2, reason2);
    }
}
