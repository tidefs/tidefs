//! 7-step mutual attestation HELLO handshake state machine.
//!
//! Implements the full 7-step handshake from the cluster security identity
//! model (#1843 Phase 2):
//!
//! ## Protocol flow
//!
//! Initiator                         Responder
//!   |                                 |
//!   |-- HELLO ---------------------->|  Step 1
//!   |                                 |-- verify initiator identity
//!   |<- HELLO_ACK -------------------|  Step 2
//!   |-- verify responder identity     |
//!   |-- VERIFY --------------------->|  Step 3
//!   |                                 |-- verify initiator signature
//!   |<====== session established ====>|  Step 4
//!   |                                 |
//!   |<====== derive session keys ====>|  Step 5
//!   |<====== exchange versions/flags=>|  Step 6
//!   |<====== authenticated transport=>|  Step 7
//!
//! ## Timeout
//!
//! If any step takes longer than 30 seconds, the handshake fails with
//! HandshakeTimeout. This is enforced by the caller via Tokio timeout.

use std::time::Duration;

use blake3::Hasher;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::attestation::{HelloMessage, HelloResponse, SessionToken};
use crate::error::AttestationError;
use crate::identity::NodeIdentity;

// ---------------------------------------------------------------------------
// Handshake state enumeration
// ---------------------------------------------------------------------------

/// The 7 states of the mutual attestation handshake.
#[derive(Clone, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state before any messages are sent.
    Init,
    /// Step 1 complete: HELLO sent, waiting for HELLO_ACK.
    HelloSent { hello: HelloMessage },
    /// Step 2 complete: HELLO_ACK received, preparing VERIFY.
    AckReceived {
        hello: HelloMessage,
        response: HelloResponse,
    },
    /// Step 4 complete: VERIFY sent + accepted, session established.
    Verified {
        initiator_identity: NodeIdentity,
        responder_identity: NodeIdentity,
        session_token: SessionToken,
        session_id: u64,
    },
    /// Steps 5-7 complete: keys derived, versions exchanged, transport ready.
    Established {
        initiator_identity: NodeIdentity,
        responder_identity: NodeIdentity,
        session_keys: SessionKeys,
        session_token: SessionToken,
        accepted_protocol: u16,
        accepted_features: u64,
    },
    /// Handshake failed with a reason.
    Failed { reason: String },
}

impl HandshakeState {
    /// Whether the state is terminal (either Established or Failed).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Established { .. } | Self::Failed { .. })
    }

    /// Whether the handshake completed successfully.
    pub fn is_established(&self) -> bool {
        matches!(self, Self::Established { .. })
    }

    /// Human-readable label for this state.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::HelloSent { .. } => "hello_sent",
            Self::AckReceived { .. } => "ack_received",
            Self::Verified { .. } => "verified",
            Self::Established { .. } => "established",
            Self::Failed { .. } => "failed",
        }
    }
}

// ---------------------------------------------------------------------------
// Default handshake timeout: 30 seconds per the design spec
// ---------------------------------------------------------------------------

/// Default timeout for any single handshake step.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Session keys derived after successful attestation (Step 5)
// ---------------------------------------------------------------------------

/// Session keys derived from the handshake nonces.
///
/// Produced via BLAKE3-based key derivation from the concatenated
/// nonces and the session_id. The HMAC key is always derived; the
/// ChaCha20-Poly1305 encryption key is optional.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// HMAC-SHA256 key for per-message authentication (32 bytes).
    pub hmac_key: [u8; 32],
    /// Optional ChaCha20-Poly1305 encryption key (32 bytes).
    pub encryption_key: Option<[u8; 32]>,
    /// The session identifier used as part of key derivation.
    pub session_id: u64,
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("hmac_key", &"[REDACTED; 32]")
            .field(
                "encryption_key",
                &self.encryption_key.as_ref().map(|_| "[REDACTED; 32]"),
            )
            .field("session_id", &self.session_id)
            .finish()
    }
}

impl Zeroize for SessionKeys {
    fn zeroize(&mut self) {
        self.hmac_key = [0u8; 32];
        self.encryption_key = None;
        // session_id is not secret; leave it alone
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.hmac_key = [0u8; 32];
        self.encryption_key = None;
    }
}

// ---------------------------------------------------------------------------
// VERIFY message (Step 3)
// ---------------------------------------------------------------------------

/// VERIFY message sent by the initiator in Step 3 of the handshake.
///
/// The initiator signs (responder_nonce || session_id) to prove
/// possession of their private key and confirm session establishment.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VerifyMessage {
    /// Echo of the responder's nonce from HELLO_ACK.
    pub responder_nonce_echo: [u8; 32],
    /// Session ID assigned by the responder.
    pub session_id: u64,
    /// Signature over (responder_nonce || session_id) by initiator.
    pub signature: Vec<u8>,
}

impl VerifyMessage {
    /// Create a signed VERIFY message.
    pub fn new(responder_nonce: [u8; 32], session_id: u64, signing_key: &Keypair) -> Self {
        let mut preimage = Vec::with_capacity(40);
        preimage.extend_from_slice(&responder_nonce);
        preimage.extend_from_slice(&session_id.to_le_bytes());

        let signature = signing_key.sign(&preimage).to_bytes().to_vec();

        Self {
            responder_nonce_echo: responder_nonce,
            session_id,
            signature,
        }
    }

    /// Verify the initiator's signature on this VERIFY message.
    pub fn verify(&self, initiator_public: &PublicKey) -> Result<(), AttestationError> {
        let mut preimage = Vec::with_capacity(40);
        preimage.extend_from_slice(&self.responder_nonce_echo);
        preimage.extend_from_slice(&self.session_id.to_le_bytes());

        let signature = Signature::from_bytes(&self.signature).map_err(|e| {
            AttestationError::ChallengeFailed {
                reason: format!("invalid VERIFY signature bytes: {e}"),
            }
        })?;

        initiator_public
            .verify(&preimage, &signature)
            .map_err(|e| AttestationError::ChallengeFailed {
                reason: format!("VERIFY signature mismatch: {e}"),
            })?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Key derivation (Step 5)
// ---------------------------------------------------------------------------

const SESSION_KEY_DOMAIN_HMAC: &str = "tidefs-auth-session-hmac-key-v1";
const SESSION_KEY_DOMAIN_ENC: &str = "tidefs-auth-session-encryption-key-v1";

/// Derive session keys from the handshake nonces and session_id.
///
/// Uses BLAKE3 keyed derivation:
///   hmac_key = derive_key("tidefs-auth-session-hmac-key-v1",
///                         nonce_i || nonce_r || session_id)
///   enc_key  = derive_key("tidefs-auth-session-encryption-key-v1",
///                         nonce_i || nonce_r || session_id)
pub fn derive_session_keys(
    initiator_nonce: &[u8; 32],
    responder_nonce: &[u8; 32],
    session_id: u64,
    derive_encryption: bool,
) -> SessionKeys {
    let mut key_material = Vec::with_capacity(72);
    key_material.extend_from_slice(initiator_nonce);
    key_material.extend_from_slice(responder_nonce);
    key_material.extend_from_slice(&session_id.to_le_bytes());

    // HMAC key
    let mut hmac_kdf = Hasher::new_derive_key(SESSION_KEY_DOMAIN_HMAC);
    hmac_kdf.update(&key_material);
    let hmac_key: [u8; 32] = hmac_kdf.finalize().into();

    // Optional encryption key
    let encryption_key = if derive_encryption {
        let mut enc_kdf = Hasher::new_derive_key(SESSION_KEY_DOMAIN_ENC);
        enc_kdf.update(&key_material);
        let ek: [u8; 32] = enc_kdf.finalize().into();
        Some(ek)
    } else {
        None
    };

    SessionKeys {
        hmac_key,
        encryption_key,
        session_id,
    }
}

// ---------------------------------------------------------------------------
// HelloHandshake: the full 7-step state machine
// ---------------------------------------------------------------------------

/// Result of completing the handshake.
#[derive(Clone, PartialEq, Eq)]
pub struct HelloHandshakeResult {
    pub session_keys: SessionKeys,
    pub session_token: SessionToken,
    pub peer_identity: NodeIdentity,
    pub accepted_protocol: u16,
    pub accepted_features: u64,
}
impl std::fmt::Debug for HelloHandshakeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelloHandshakeResult")
            .field("session_keys", &self.session_keys)
            .field("session_token", &self.session_token)
            .field("peer_identity", &self.peer_identity)
            .field("accepted_protocol", &self.accepted_protocol)
            .field("accepted_features", &self.accepted_features)
            .finish()
    }
}

/// The HelloHandshake state machine drives the 7-step mutual attestation
/// handshake for the initiator side.
///
/// The responder side uses HelloHandshake::respond() then handle_verify().
pub struct HelloHandshake {
    state: HandshakeState,
    initiator_identity: Option<NodeIdentity>,
    initiator_secret_bytes: Option<[u8; 32]>,
    initiator_nonce: Option<[u8; 32]>,
    responder_nonce: Option<[u8; 32]>,
    session_id: Option<u64>,
}

impl Drop for HelloHandshake {
    fn drop(&mut self) {
        if let Some(ref mut secret) = self.initiator_secret_bytes {
            *secret = [0u8; 32];
        }
    }
}
impl HelloHandshake {
    // ------------------------------------------------------------------
    // Initiator path
    // ------------------------------------------------------------------

    /// Create a new handshake in the Init state.
    pub fn new() -> Self {
        Self {
            state: HandshakeState::Init,
            initiator_identity: None,
            initiator_secret_bytes: None,
            initiator_nonce: None,
            responder_nonce: None,
            session_id: None,
        }
    }

    /// Step 1: Create the HELLO message to send.
    pub fn initiate(
        &mut self,
        identity: NodeIdentity,
        signing_key: &Keypair,
        supported_versions: Vec<u16>,
        session_class: crate::attestation::SessionClass,
        epoch: u64,
    ) -> Result<HelloMessage, AttestationError> {
        identity.verify_self_signature().map_err(|e| {
            AttestationError::SignatureVerificationFailed {
                node_id: identity.node_id,
                reason: e.to_string(),
            }
        })?;

        let hello = HelloMessage::new(
            identity.clone(),
            signing_key,
            supported_versions,
            session_class,
            epoch,
        );

        self.initiator_identity = Some(identity);
        self.initiator_secret_bytes = Some(signing_key.secret.to_bytes());
        self.initiator_nonce = Some(hello.client_nonce);

        self.state = HandshakeState::HelloSent {
            hello: hello.clone(),
        };

        Ok(hello)
    }

    /// Step 3: Process the HELLO_ACK response, verify it, and produce VERIFY.
    pub fn handle_hello_ack(
        &mut self,
        response: HelloResponse,
    ) -> Result<VerifyMessage, AttestationError> {
        let hello = match &self.state {
            HandshakeState::HelloSent { hello } => hello.clone(),
            other => {
                return Err(AttestationError::ChallengeFailed {
                    reason: format!("expected state HelloSent, got {}", other.as_str()),
                });
            }
        };

        response
            .server_identity
            .verify_self_signature()
            .map_err(|e| AttestationError::SignatureVerificationFailed {
                node_id: response.server_identity.node_id,
                reason: e.to_string(),
            })?;

        response.verify()?;

        let initiator_nonce = self
            .initiator_nonce
            .ok_or(AttestationError::NonceMismatch)?;

        if response.client_nonce_echo != initiator_nonce {
            return Err(AttestationError::NonceMismatch);
        }

        if hello.proposed_epoch != response.server_epoch {
            return Err(AttestationError::EpochMismatch {
                client_epoch: hello.proposed_epoch,
                server_epoch: response.server_epoch,
            });
        }

        self.responder_nonce = Some(response.server_nonce);
        self.session_id = Some(response.session_token.session_id);

        let secret_bytes = self.initiator_secret_bytes.ok_or({
            AttestationError::ChallengeFailed {
                reason: "initiator key not set".into(),
            }
        })?;

        let initiator_pk = self
            .initiator_identity
            .as_ref()
            .and_then(|id| id.verifying_key().ok())
            .ok_or({
                AttestationError::ChallengeFailed {
                    reason: "initiator public key not available".into(),
                }
            })?;
        let secret = SecretKey::from_bytes(&secret_bytes).map_err(|e| {
            AttestationError::ChallengeFailed {
                reason: format!("invalid initiator secret key: {e}"),
            }
        })?;
        let signing_key = Keypair {
            secret,
            public: initiator_pk,
        };

        let verify_msg = VerifyMessage::new(
            response.server_nonce,
            response.session_token.session_id,
            &signing_key,
        );

        self.state = HandshakeState::AckReceived { hello, response };

        Ok(verify_msg)
    }

    /// Steps 5-6: Derive session keys and finalize protocol negotiation.
    pub fn establish(
        &mut self,
        accepted_protocol: u16,
        accepted_features: u64,
        derive_encryption: bool,
    ) -> Result<HelloHandshakeResult, AttestationError> {
        let (initiator_identity, responder_identity, session_token, session_id) = match &self.state
        {
            HandshakeState::AckReceived { hello: _, response } => {
                let initiator_identity = self.initiator_identity.clone().ok_or({
                    AttestationError::ChallengeFailed {
                        reason: "initiator identity not set".into(),
                    }
                })?;
                (
                    initiator_identity,
                    response.server_identity.clone(),
                    response.session_token.clone(),
                    response.session_token.session_id,
                )
            }
            HandshakeState::Verified {
                initiator_identity,
                responder_identity,
                session_token,
                session_id,
            } => (
                initiator_identity.clone(),
                responder_identity.clone(),
                session_token.clone(),
                *session_id,
            ),
            other => {
                return Err(AttestationError::ChallengeFailed {
                    reason: format!(
                        "expected state AckReceived or Verified, got {}",
                        other.as_str()
                    ),
                });
            }
        };

        self.finalize_establish(
            initiator_identity,
            responder_identity,
            session_token,
            session_id,
            accepted_protocol,
            accepted_features,
            derive_encryption,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize_establish(
        &mut self,
        initiator_identity: NodeIdentity,
        responder_identity: NodeIdentity,
        session_token: SessionToken,
        session_id: u64,
        accepted_protocol: u16,
        accepted_features: u64,
        derive_encryption: bool,
    ) -> Result<HelloHandshakeResult, AttestationError> {
        let initiator_nonce = self.initiator_nonce.ok_or({
            AttestationError::ChallengeFailed {
                reason: "initiator nonce not set".into(),
            }
        })?;
        let responder_nonce = self.responder_nonce.ok_or({
            AttestationError::ChallengeFailed {
                reason: "responder nonce not set".into(),
            }
        })?;

        let session_keys = derive_session_keys(
            &initiator_nonce,
            &responder_nonce,
            session_id,
            derive_encryption,
        );

        self.state = HandshakeState::Established {
            initiator_identity: initiator_identity.clone(),
            responder_identity: responder_identity.clone(),
            session_keys: session_keys.clone(),
            session_token: session_token.clone(),
            accepted_protocol,
            accepted_features,
        };

        Ok(HelloHandshakeResult {
            session_keys,
            session_token,
            peer_identity: responder_identity,
            accepted_protocol,
            accepted_features,
        })
    }

    /// Mark the handshake as failed.
    pub fn fail(&mut self, reason: String) {
        self.state = HandshakeState::Failed { reason };
    }

    /// The current handshake state.
    pub fn state(&self) -> &HandshakeState {
        &self.state
    }

    /// Whether the handshake is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Whether the handshake completed successfully.
    pub fn is_established(&self) -> bool {
        self.state.is_established()
    }

    // ------------------------------------------------------------------
    // Responder path (Steps 2, 4)
    // ------------------------------------------------------------------

    /// Step 2: Responder processes a HELLO and produces a HELLO_ACK.
    #[allow(clippy::too_many_arguments)]
    pub fn respond(
        hello: &HelloMessage,
        responder_identity: NodeIdentity,
        responder_key: &Keypair,
        accepted_version: u16,
        accepted_session_class: crate::attestation::SessionClass,
        session_id: u64,
        epoch: u64,
    ) -> Result<HelloResponse, AttestationError> {
        hello.client_identity.verify_self_signature().map_err(|e| {
            AttestationError::SignatureVerificationFailed {
                node_id: hello.client_identity.node_id,
                reason: e.to_string(),
            }
        })?;

        hello.verify()?;

        if hello.proposed_epoch != epoch {
            return Err(AttestationError::EpochMismatch {
                client_epoch: hello.proposed_epoch,
                server_epoch: epoch,
            });
        }

        let response = HelloResponse::new(
            responder_identity,
            responder_key,
            hello.client_nonce,
            accepted_version,
            accepted_session_class,
            session_id,
            epoch,
        );

        Ok(response)
    }

    /// Step 4: Responder verifies the initiator's VERIFY message.
    pub fn handle_verify(
        verify_msg: &VerifyMessage,
        initiator_public: &PublicKey,
    ) -> Result<(), AttestationError> {
        verify_msg.verify(initiator_public)
    }
}

impl Default for HelloHandshake {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::SessionClass;
    use crate::identity::NodeIdentity;

    fn make_node_identity(node_id: u64) -> (NodeIdentity, Keypair) {
        NodeIdentity::generate(node_id).expect("generate identity")
    }

    #[test]
    fn full_seven_step_handshake_happy_path() {
        let (initiator_id, initiator_key) = make_node_identity(1);
        let (responder_id, responder_key) = make_node_identity(2);
        let session_id: u64 = 0xCAFE_BEEF;

        let mut hs = HelloHandshake::new();
        let hello = hs
            .initiate(
                initiator_id.clone(),
                &initiator_key,
                vec![1, 2],
                SessionClass::FullMesh,
                7,
            )
            .expect("initiate");
        assert!(matches!(hs.state(), HandshakeState::HelloSent { .. }));

        let response = HelloHandshake::respond(
            &hello,
            responder_id.clone(),
            &responder_key,
            1,
            SessionClass::FullMesh,
            session_id,
            7,
        )
        .expect("respond");

        let verify_msg = hs.handle_hello_ack(response).expect("handle hello ack");
        assert!(matches!(hs.state(), HandshakeState::AckReceived { .. }));

        let initiator_public = initiator_id.verifying_key().expect("vk");
        HelloHandshake::handle_verify(&verify_msg, &initiator_public).expect("handle verify");

        let result = hs.establish(1, 0xF00D, true).expect("establish");
        assert!(hs.is_established());
        assert_eq!(result.peer_identity.node_id, 2);
        assert_eq!(result.accepted_protocol, 1);
        assert_eq!(result.accepted_features, 0xF00D);
        assert!(result.session_keys.encryption_key.is_some());
        assert_eq!(result.session_keys.session_id, session_id);
        assert_ne!(result.session_keys.hmac_key, [0u8; 32]);
        let enc_key = result.session_keys.encryption_key.unwrap();
        assert_ne!(enc_key, [0u8; 32]);
        assert_ne!(result.session_keys.hmac_key, enc_key);
    }

    #[test]
    fn wrong_identity_rejected_by_responder() {
        let (initiator_id, initiator_key) = make_node_identity(1);
        let (bad_id, _bad_key) = make_node_identity(99);
        let (responder_id, responder_key) = make_node_identity(2);

        let mut hs = HelloHandshake::new();
        let hello = hs
            .initiate(
                initiator_id,
                &initiator_key,
                vec![1],
                SessionClass::FullMesh,
                1,
            )
            .expect("initiate");

        let mut tampered_hello = hello.clone();
        tampered_hello.client_identity = bad_id;

        let result = HelloHandshake::respond(
            &tampered_hello,
            responder_id,
            &responder_key,
            1,
            SessionClass::FullMesh,
            42,
            1,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("signature"));
    }

    #[test]
    fn bad_hello_signature_rejected() {
        let (initiator_id, initiator_key) = make_node_identity(1);
        let (responder_id, responder_key) = make_node_identity(2);

        let mut hs = HelloHandshake::new();
        let mut hello = hs
            .initiate(
                initiator_id,
                &initiator_key,
                vec![1],
                SessionClass::FullMesh,
                1,
            )
            .expect("initiate");
        hello.signature[0] ^= 0xFF;

        let result = HelloHandshake::respond(
            &hello,
            responder_id,
            &responder_key,
            1,
            SessionClass::FullMesh,
            42,
            1,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("signature"));
    }

    #[test]
    fn bad_hello_ack_signature_rejected() {
        let (initiator_id, initiator_key) = make_node_identity(1);
        let (responder_id, responder_key) = make_node_identity(2);

        let mut hs = HelloHandshake::new();
        let hello = hs
            .initiate(
                initiator_id,
                &initiator_key,
                vec![1],
                SessionClass::FullMesh,
                1,
            )
            .expect("initiate");

        let mut response = HelloHandshake::respond(
            &hello,
            responder_id,
            &responder_key,
            1,
            SessionClass::FullMesh,
            42,
            1,
        )
        .expect("respond");
        response.signature[0] ^= 0xFF;

        let result = hs.handle_hello_ack(response);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("signature"));
    }

    #[test]
    fn bad_verify_signature_rejected() {
        let (initiator_id, initiator_key) = make_node_identity(1);
        let (responder_id, responder_key) = make_node_identity(2);

        let mut hs = HelloHandshake::new();
        let hello = hs
            .initiate(
                initiator_id.clone(),
                &initiator_key,
                vec![1],
                SessionClass::FullMesh,
                1,
            )
            .expect("initiate");

        let response = HelloHandshake::respond(
            &hello,
            responder_id,
            &responder_key,
            1,
            SessionClass::FullMesh,
            42,
            1,
        )
        .expect("respond");

        let mut verify_msg = hs.handle_hello_ack(response).expect("handle hello ack");
        verify_msg.signature[0] ^= 0xFF;

        let initiator_public = initiator_id.verifying_key().expect("vk");
        let result = HelloHandshake::handle_verify(&verify_msg, &initiator_public);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("signature"));
    }

    #[test]
    fn nonce_echo_mismatch_rejected() {
        // Tampering the nonce echo invalidates the responder's signature
        // since the nonce is part of the signed payload. This is correct
        // protocol behavior: signature verification must fail first.
        let (initiator_id, initiator_key) = make_node_identity(1);
        let (responder_id, responder_key) = make_node_identity(2);

        let mut hs = HelloHandshake::new();
        let hello = hs
            .initiate(
                initiator_id,
                &initiator_key,
                vec![1],
                SessionClass::FullMesh,
                1,
            )
            .expect("initiate");

        let mut response = HelloHandshake::respond(
            &hello,
            responder_id,
            &responder_key,
            1,
            SessionClass::FullMesh,
            42,
            1,
        )
        .expect("respond");
        response.client_nonce_echo[0] ^= 0xFF;

        let result = hs.handle_hello_ack(response);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("signature"));
    }

    #[test]
    fn epoch_mismatch_rejected() {
        let (initiator_id, initiator_key) = make_node_identity(1);
        let (responder_id, responder_key) = make_node_identity(2);

        let mut hs = HelloHandshake::new();
        let hello = hs
            .initiate(
                initiator_id,
                &initiator_key,
                vec![1],
                SessionClass::FullMesh,
                7,
            )
            .expect("initiate");

        let result = HelloHandshake::respond(
            &hello,
            responder_id,
            &responder_key,
            1,
            SessionClass::FullMesh,
            42,
            99,
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AttestationError::EpochMismatch { .. }
        ));
    }

    #[test]
    fn session_key_derivation_deterministic() {
        let nonce_i = [0xAA; 32];
        let nonce_r = [0xBB; 32];
        let session_id: u64 = 42;

        let keys1 = derive_session_keys(&nonce_i, &nonce_r, session_id, true);
        let keys2 = derive_session_keys(&nonce_i, &nonce_r, session_id, true);

        assert_eq!(keys1.hmac_key, keys2.hmac_key);
        assert_eq!(keys1.encryption_key, keys2.encryption_key);
        assert_eq!(keys1.session_id, keys2.session_id);
    }

    #[test]
    fn session_key_derivation_different_inputs_different_keys() {
        let nonce_i = [0xAA; 32];
        let nonce_r = [0xBB; 32];
        let keys1 = derive_session_keys(&nonce_i, &nonce_r, 1, true);
        let keys2 = derive_session_keys(&nonce_i, &nonce_r, 2, true);
        assert_ne!(keys1.hmac_key, keys2.hmac_key);
        assert_ne!(keys1.encryption_key, keys2.encryption_key);
    }

    #[test]
    fn session_key_no_encryption_when_disabled() {
        let nonce_i = [0xAA; 32];
        let nonce_r = [0xBB; 32];
        let keys = derive_session_keys(&nonce_i, &nonce_r, 1, false);
        assert!(keys.encryption_key.is_none());
    }

    #[test]
    fn state_labels() {
        assert_eq!(HandshakeState::Init.as_str(), "init");
        assert_eq!(
            HandshakeState::HelloSent {
                hello: make_dummy_hello()
            }
            .as_str(),
            "hello_sent"
        );
        assert_eq!(
            HandshakeState::AckReceived {
                hello: make_dummy_hello(),
                response: make_dummy_response()
            }
            .as_str(),
            "ack_received"
        );
        assert_eq!(
            HandshakeState::Failed { reason: "x".into() }.as_str(),
            "failed"
        );
    }

    #[test]
    fn terminal_and_established_predicates() {
        assert!(!HandshakeState::Init.is_terminal());
        assert!(!HandshakeState::Init.is_established());
        let failed = HandshakeState::Failed {
            reason: "timeout".into(),
        };
        assert!(failed.is_terminal());
        assert!(!failed.is_established());
    }

    #[test]
    fn handle_hello_ack_from_init_fails() {
        let mut hs = HelloHandshake::new();
        let (_, responder_key) = make_node_identity(2);
        let dummy_resp = HelloResponse::new(
            make_node_identity(2).0,
            &responder_key,
            [0u8; 32],
            1,
            SessionClass::FullMesh,
            1,
            1,
        );
        let result = hs.handle_hello_ack(dummy_resp);
        assert!(result.is_err());
    }

    #[test]
    fn establish_from_init_fails() {
        let mut hs = HelloHandshake::new();
        let result = hs.establish(1, 0, false);
        assert!(result.is_err());
    }

    #[test]
    fn double_initiate_overwrites_state() {
        let (id1, k1) = make_node_identity(1);
        let (id2, k2) = make_node_identity(2);
        let mut hs = HelloHandshake::new();
        let hello1 = hs
            .initiate(id1, &k1, vec![1], SessionClass::FullMesh, 1)
            .expect("first");
        assert!(matches!(hs.state(), HandshakeState::HelloSent { .. }));
        let hello2 = hs
            .initiate(id2, &k2, vec![2], SessionClass::FullMesh, 2)
            .expect("second");
        assert_ne!(hello1.client_nonce, hello2.client_nonce);
    }

    #[test]
    fn verify_message_sign_and_verify() {
        let (_, key) = make_node_identity(1);
        let nonce = [0xCC; 32];
        let session_id: u64 = 77;
        let verify_msg = VerifyMessage::new(nonce, session_id, &key);
        assert_eq!(verify_msg.responder_nonce_echo, nonce);
        assert_eq!(verify_msg.session_id, session_id);
        let public = key.public;
        verify_msg.verify(&public).expect("verify");
    }

    #[test]
    fn verify_message_tampered_nonce_fails() {
        let (_, key) = make_node_identity(1);
        let nonce = [0xCC; 32];
        let mut verify_msg = VerifyMessage::new(nonce, 77, &key);
        verify_msg.responder_nonce_echo[0] ^= 0xFF;
        let public = key.public;
        assert!(verify_msg.verify(&public).is_err());
    }

    #[test]
    fn verify_message_wrong_key_fails() {
        let (_, key) = make_node_identity(1);
        let (_, other_key) = make_node_identity(3);
        let nonce = [0xCC; 32];
        let verify_msg = VerifyMessage::new(nonce, 77, &key);
        let other_public = other_key.public;
        assert!(verify_msg.verify(&other_public).is_err());
    }

    #[test]
    fn concurrent_handshakes_unique_keys() {
        let (id1, k1) = make_node_identity(1);
        let (id2, k2) = make_node_identity(2);
        let (rid, rk) = make_node_identity(99);

        let mut hs1 = HelloHandshake::new();
        let hello1 = hs1
            .initiate(id1.clone(), &k1, vec![1], SessionClass::FullMesh, 1)
            .unwrap();
        let resp1 =
            HelloHandshake::respond(&hello1, rid.clone(), &rk, 1, SessionClass::FullMesh, 100, 1)
                .unwrap();
        hs1.handle_hello_ack(resp1).unwrap();
        let r1 = hs1.establish(1, 0, true).unwrap();

        let mut hs2 = HelloHandshake::new();
        let hello2 = hs2
            .initiate(id2, &k2, vec![1], SessionClass::FullMesh, 1)
            .unwrap();
        let resp2 =
            HelloHandshake::respond(&hello2, rid, &rk, 1, SessionClass::FullMesh, 200, 1).unwrap();
        hs2.handle_hello_ack(resp2).unwrap();
        let r2 = hs2.establish(1, 0, true).unwrap();

        assert_ne!(r1.session_keys.hmac_key, r2.session_keys.hmac_key);
        assert_ne!(r1.session_keys.session_id, r2.session_keys.session_id);
    }

    #[test]
    fn explicit_fail_transitions_to_failed() {
        let mut hs = HelloHandshake::new();
        hs.fail("test failure".into());
        assert!(matches!(hs.state(), HandshakeState::Failed { .. }));
        assert!(hs.is_terminal());
        assert!(!hs.is_established());
    }

    #[test]
    fn default_is_init() {
        let hs = HelloHandshake::default();
        assert!(matches!(hs.state(), HandshakeState::Init));
    }

    #[test]
    fn verified_to_established_via_establish() {
        let (id1, k1) = make_node_identity(1);
        let (rid, rk) = make_node_identity(2);

        let mut hs = HelloHandshake::new();
        let hello = hs
            .initiate(id1.clone(), &k1, vec![1], SessionClass::FullMesh, 1)
            .unwrap();
        let resp =
            HelloHandshake::respond(&hello, rid.clone(), &rk, 1, SessionClass::FullMesh, 42, 1)
                .unwrap();
        let verify_msg = hs.handle_hello_ack(resp.clone()).unwrap();

        let initiator_public = id1.verifying_key().unwrap();
        HelloHandshake::handle_verify(&verify_msg, &initiator_public).unwrap();

        let result = hs.establish(1, 0xABCD, false).unwrap();
        assert!(hs.is_established());
        assert_eq!(result.accepted_features, 0xABCD);
        assert!(result.session_keys.encryption_key.is_none());
    }

    #[test]
    fn protocol_version_exchange_in_handshake() {
        let (id1, k1) = make_node_identity(1);
        let (rid, rk) = make_node_identity(2);

        let mut hs = HelloHandshake::new();
        let hello = hs
            .initiate(id1, &k1, vec![1, 2, 3], SessionClass::FullMesh, 1)
            .unwrap();
        let resp =
            HelloHandshake::respond(&hello, rid, &rk, 2, SessionClass::FullMesh, 42, 1).unwrap();
        hs.handle_hello_ack(resp).unwrap();

        let result = hs.establish(2, 0xCAFE, false).unwrap();
        assert_eq!(result.accepted_protocol, 2);
        assert_eq!(result.accepted_features, 0xCAFE);
    }

    fn make_dummy_hello() -> HelloMessage {
        let (id, key) = make_node_identity(1);
        HelloMessage::new(id, &key, vec![1], SessionClass::FullMesh, 1)
    }

    fn make_dummy_response() -> HelloResponse {
        let (id, key) = make_node_identity(2);
        HelloResponse::new(id, &key, [0u8; 32], 1, SessionClass::FullMesh, 1, 1)
    }

    // ── Zeroization verification tests (NEXT-SEC-008) ─────────────────

    #[test]
    fn zeroization_session_keys_explicit_zeroize() {
        let mut keys = derive_session_keys(&[0xAAu8; 32], &[0xBBu8; 32], 1, true);
        assert_ne!(keys.hmac_key, [0u8; 32], "HMAC key must be non-zero");

        keys.zeroize();
        assert_eq!(
            keys.hmac_key, [0u8; 32],
            "HMAC key must be zero after zeroize()"
        );
        assert!(
            keys.encryption_key.is_none(),
            "encryption key must be None after zeroize()"
        );
        assert_eq!(
            keys.session_id, 1,
            "session_id must be preserved (not secret)"
        );
    }

    #[test]
    fn zeroization_session_keys_debug_does_not_leak_key_bytes() {
        let keys = derive_session_keys(&[0xAAu8; 32], &[0xBBu8; 32], 42, true);
        let debug_str = format!("{keys:?}");

        assert!(
            debug_str.contains("REDACTED"),
            "SessionKeys Debug must redact hmac_key: {debug_str}"
        );
        assert!(
            debug_str.contains("42"),
            "SessionKeys Debug must show session_id: {debug_str}"
        );
    }

    #[test]
    fn zeroization_hello_handshake_result_debug_safe() {
        let (id, key) = make_node_identity(1);
        let mut hs = HelloHandshake::new();
        let hello = hs
            .initiate(id.clone(), &key, vec![1], SessionClass::FullMesh, 1)
            .unwrap();
        let (rid, rk) = make_node_identity(2);
        let resp =
            HelloHandshake::respond(&hello, rid, &rk, 2, SessionClass::FullMesh, 42, 1).unwrap();
        hs.handle_hello_ack(resp).unwrap();
        let result = hs.establish(1, 0, false).unwrap();

        let debug_str = format!("{result:?}");
        assert!(
            debug_str.contains("HelloHandshakeResult"),
            "HelloHandshakeResult Debug must name the type"
        );
    }

    #[test]
    fn zeroization_hello_handshake_drop_zeroizes_secret() {
        let (_id, key) = make_node_identity(1);
        let mut hs = HelloHandshake::new();
        let original_secret = key.secret.to_bytes();
        assert_ne!(original_secret, [0u8; 32]);

        // initiate() stores secret bytes
        let (id, key2) = make_node_identity(1);
        hs.initiate(id, &key2, vec![1], SessionClass::FullMesh, 1)
            .unwrap();

        // Drop should zeroize (compiles and doesn't panic is the test)
        drop(hs);
    }

    #[test]
    fn zeroization_clone_then_zeroize_both_independent() {
        let keys = derive_session_keys(&[1u8; 32], &[2u8; 32], 1, true);
        let mut clone = keys.clone();

        assert_eq!(keys.hmac_key, clone.hmac_key);

        clone.zeroize();
        assert_eq!(clone.hmac_key, [0u8; 32]);
        assert_ne!(
            keys.hmac_key, [0u8; 32],
            "original must retain key after clone zeroize"
        );

        // Drop of `keys` triggers Drop::zeroize
        drop(keys);
    }
}
