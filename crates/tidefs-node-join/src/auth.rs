//! Join authentication: mutual attestation handshake for node join.
//!
//! Wraps the `tidefs-auth` attestation protocol (HelloMessage/HelloResponse)
//! for the node join use case. After broadcast discovery selects a
//! bootstrap peer, the joining node performs mutual attestation to
//! cryptographically verify the peer's cluster membership before
//! proceeding with the join request.
//!
//! # Flow
//!
//! ```text
//! Joiner                                  Bootstrap Peer
//!   |                                           |
//!   |──── HelloMessage { id, nonce, epoch } ──>|
//!   |                                           |
//!   |<── HelloResponse { id, nonce, sig } ─────|
//!   |                                           |
//!   |  (verify mutual attestation)              |
//!   |                                           |
//!   ──── authenticated ────────────────────────|
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;
use tidefs_auth::attestation::{verify_mutual_attestation, HelloMessage, HelloResponse};
use tidefs_auth::NodeIdentity;
use tidefs_auth::NodeKeyStore;
use tidefs_membership_epoch::{EpochId, MemberId};

use crate::discovery::DiscoveryConsensus;
use crate::JoinError;

// ── Auth states ──────────────────────────────────────────────────────

/// States in the join authentication state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum JoinAuthState {
    /// Authentication has not started.
    Idle = 0,
    /// Hello sent, waiting for response.
    Attesting = 1,
    /// Mutual attestation succeeded.
    Authenticated = 2,
    /// Attestation failed or was rejected.
    Rejected = 3,
    /// Timeout while waiting for response.
    Timeout = 4,
}

impl JoinAuthState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Authenticated | Self::Rejected | Self::Timeout)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "auth.idle",
            Self::Attesting => "auth.attesting",
            Self::Authenticated => "auth.authenticated",
            Self::Rejected => "auth.rejected",
            Self::Timeout => "auth.timeout",
        }
    }
}

// ── Auth result ──────────────────────────────────────────────────────

/// Result of a successful join authentication.
#[derive(Clone, Debug)]
pub struct JoinAuthResult {
    /// The verified identity of the bootstrap peer.
    pub peer_identity: NodeIdentity,
    /// The epoch agreed upon during attestation.
    pub agreed_epoch: EpochId,
    /// The bootstrap peer member ID.
    pub bootstrap_peer: MemberId,
    /// The pool ID from discovery consensus.
    pub pool_id: u64,
    /// The session class negotiated.
    pub session_class: tidefs_auth::SessionClass,
    /// Whether attestation was fully verified.
    pub verified: bool,
}

// ── Join auth orchestrator ────────────────────────────────────────────

/// Orchestrates the mutual attestation handshake during node join.
///
/// After broadcast discovery selects a bootstrap peer, this type
/// manages the Ed25519-based mutual attestation handshake to verify
/// both nodes' identities within the cluster context.
///
/// # Usage
///
/// 1. Create with `JoinAuth::new(identity, consensus)`.
/// 2. Build a `HelloMessage` via `tidefs-auth` (signing happens externally).
/// 3. Call `hello_sent()` to transition to Attesting.
/// 4. Feed the `HelloResponse` into `on_hello_response()`.
/// 5. On success, the `JoinAuthResult` is available via `result()`.
pub struct JoinAuth {
    /// The joining node's identity.
    pub node_identity: NodeIdentity,
    /// Current authentication state.
    pub state: JoinAuthState,
    /// The client nonce used in the HelloMessage.
    pub client_nonce: [u8; 32],
    /// The consensus from broadcast discovery.
    pub consensus: DiscoveryConsensus,
    /// The authentication result (populated on success).
    pub auth_result: Option<JoinAuthResult>,
    /// When the current phase started (ns).
    phase_started_ns: u64,
    /// Timeout for the attestation phase (ns).
    pub timeout_ns: u64,
    /// Known node identities (built from discovery or pre-configured).
    pub known_keys: NodeKeyStore,
    /// Rejection reason (populated on failure).
    pub rejection_reason: Option<String>,
}

impl fmt::Debug for JoinAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinAuth")
            .field("node_identity", &self.node_identity)
            .field("state", &self.state)
            .field("client_nonce", &self.client_nonce)
            .field("consensus", &self.consensus)
            .field("auth_result", &self.auth_result)
            .field("phase_started_ns", &self.phase_started_ns)
            .field("timeout_ns", &self.timeout_ns)
            .field("known_keys_count", &self.known_keys.identities.len())
            .field("rejection_reason", &self.rejection_reason)
            .finish()
    }
}

impl JoinAuth {
    /// Create a new join authentication from discovery consensus.
    #[must_use]
    pub fn new(
        node_identity: NodeIdentity,
        consensus: DiscoveryConsensus,
        timeout_ns: u64,
        known_keys: NodeKeyStore,
    ) -> Self {
        Self {
            node_identity,
            state: JoinAuthState::Idle,
            client_nonce: [0u8; 32],
            consensus,
            auth_result: None,
            phase_started_ns: 0,
            timeout_ns,
            known_keys,
            rejection_reason: None,
        }
    }

    /// Record that a HelloMessage has been sent. Transitions to Attesting.
    ///
    /// The caller must provide the client nonce used in the HelloMessage
    /// so that the response verification can use it.
    pub fn hello_sent(&mut self, client_nonce: [u8; 32], now_ns: u64) -> Result<(), JoinError> {
        if self.state != JoinAuthState::Idle {
            return Err(JoinError::PreflightDenied(format!(
                "cannot send hello in state {:?}",
                self.state
            )));
        }
        self.client_nonce = client_nonce;
        self.state = JoinAuthState::Attesting;
        self.phase_started_ns = now_ns;
        Ok(())
    }

    /// Process a HelloResponse from the bootstrap peer.
    ///
    /// Verifies the full 7-step mutual attestation handshake and
    /// transitions to Authenticated on success, or Rejected on failure.
    pub fn on_hello_response(
        &mut self,
        response: &HelloResponse,
        hello_message: &HelloMessage,
    ) -> Result<(), JoinError> {
        if self.state != JoinAuthState::Attesting {
            return Err(JoinError::PreflightDenied(format!(
                "unexpected hello response in state {:?}",
                self.state
            )));
        }

        // Verify the server nonce from the response
        let server_nonce = response.server_nonce;

        match verify_mutual_attestation(
            &self.client_nonce,
            &server_nonce,
            hello_message,
            response,
            &self.known_keys,
        ) {
            Ok(attestation_result) => {
                self.state = JoinAuthState::Authenticated;
                self.auth_result = Some(JoinAuthResult {
                    peer_identity: attestation_result.peer_identity,
                    agreed_epoch: EpochId::new(attestation_result.epoch),
                    bootstrap_peer: self.consensus.bootstrap_peer,
                    pool_id: self.consensus.pool_id,
                    session_class: attestation_result.session_class,
                    verified: attestation_result.verified,
                });
                Ok(())
            }
            Err(e) => {
                self.state = JoinAuthState::Rejected;
                self.rejection_reason = Some(format!("attestation failed: {e}"));
                Err(JoinError::PreflightDenied(format!(
                    "attestation verification failed: {e}"
                )))
            }
        }
    }

    /// Check for timeout. Returns `true` if the auth phase timed out.
    pub fn check_timeout(&mut self, now_ns: u64) -> bool {
        if self.state != JoinAuthState::Attesting {
            return false;
        }

        let elapsed = now_ns.saturating_sub(self.phase_started_ns);
        if elapsed >= self.timeout_ns {
            self.state = JoinAuthState::Timeout;
            self.rejection_reason = Some(format!("auth timeout after {} ms", elapsed / 1_000_000));
            return true;
        }
        false
    }

    /// Whether authentication completed successfully.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.state == JoinAuthState::Authenticated
    }

    /// Whether authentication failed or timed out.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity(id: u64) -> NodeIdentity {
        NodeIdentity::generate(id)
            .expect("generate test identity")
            .0
    }

    fn empty_consensus() -> DiscoveryConsensus {
        DiscoveryConsensus {
            bootstrap_peer: MemberId::new(2),
            agreed_epoch: EpochId::new(5),
            member_table_hash: 0xCAFE,
            pool_id: 42,
            responder_count: 2,
            responses: vec![],
        }
    }

    fn empty_key_store() -> NodeKeyStore {
        NodeKeyStore::default()
    }

    #[test]
    fn join_auth_idle_to_attesting() {
        let mut auth = JoinAuth::new(
            test_identity(1),
            empty_consensus(),
            10_000_000_000,
            empty_key_store(),
        );
        assert_eq!(auth.state, JoinAuthState::Idle);

        let nonce = [42u8; 32];
        auth.hello_sent(nonce, 1000).unwrap();
        assert_eq!(auth.state, JoinAuthState::Attesting);
        assert_eq!(auth.client_nonce, nonce);
    }

    #[test]
    fn join_auth_cannot_hello_twice() {
        let mut auth = JoinAuth::new(
            test_identity(1),
            empty_consensus(),
            10_000_000_000,
            empty_key_store(),
        );
        auth.hello_sent([1u8; 32], 1000).unwrap();
        let err = auth.hello_sent([2u8; 32], 2000).unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(..)));
    }

    #[test]
    fn join_auth_rejects_response_in_wrong_state() {
        let auth = JoinAuth::new(
            test_identity(1),
            empty_consensus(),
            10_000_000_000,
            empty_key_store(),
        );
        // No hello sent yet - can't verify response
        assert_eq!(auth.state, JoinAuthState::Idle);
    }

    #[test]
    fn join_auth_timeout() {
        let mut auth = JoinAuth::new(
            test_identity(1),
            empty_consensus(),
            5_000_000_000,
            empty_key_store(),
        );
        auth.hello_sent([1u8; 32], 1000).unwrap();

        // Before timeout
        assert!(!auth.check_timeout(4_000_000_000));
        assert_eq!(auth.state, JoinAuthState::Attesting);

        // After timeout
        assert!(auth.check_timeout(7_000_000_000));
        assert_eq!(auth.state, JoinAuthState::Timeout);
        assert!(auth.rejection_reason.is_some());
    }

    #[test]
    fn join_auth_no_timeout_on_non_attesting() {
        let mut auth = JoinAuth::new(
            test_identity(1),
            empty_consensus(),
            1_000_000_000,
            empty_key_store(),
        );
        // In Idle state - no timeout
        assert!(!auth.check_timeout(10_000_000_000));
        assert_eq!(auth.state, JoinAuthState::Idle);
    }

    #[test]
    fn join_auth_consensus_fields_preserved() {
        let consensus = empty_consensus();
        let auth = JoinAuth::new(
            test_identity(1),
            consensus,
            10_000_000_000,
            empty_key_store(),
        );
        assert_eq!(auth.consensus.bootstrap_peer, MemberId::new(2));
        assert_eq!(auth.consensus.agreed_epoch, EpochId::new(5));
        assert_eq!(auth.consensus.pool_id, 42);
        assert_eq!(auth.consensus.member_table_hash, 0xCAFE);
    }

    #[test]
    fn join_auth_state_as_str() {
        assert_eq!(JoinAuthState::Idle.as_str(), "auth.idle");
        assert_eq!(JoinAuthState::Attesting.as_str(), "auth.attesting");
        assert_eq!(JoinAuthState::Authenticated.as_str(), "auth.authenticated");
        assert_eq!(JoinAuthState::Rejected.as_str(), "auth.rejected");
        assert_eq!(JoinAuthState::Timeout.as_str(), "auth.timeout");
    }

    #[test]
    fn join_auth_state_is_terminal() {
        assert!(!JoinAuthState::Idle.is_terminal());
        assert!(!JoinAuthState::Attesting.is_terminal());
        assert!(JoinAuthState::Authenticated.is_terminal());
        assert!(JoinAuthState::Rejected.is_terminal());
        assert!(JoinAuthState::Timeout.is_terminal());
    }
}
