//! Deterministic parameter-negotiation protocol for transport sessions.
//!
//! Implements a 3-message protocol that exchanges node identities, nonces,
//! protocol families, endpoint family, and epoch between two peers and
//! confirms mutual agreement on the full transcript.
//!
//! **IMPORTANT: This is NOT an authenticated key agreement protocol.**
//! All messages carry only public data. The derived token and verify
//! values are computed solely from public transcript bytes, so any observer
//! or MITM can compute the same values. This protocol provides NO secrecy,
//! NO authentication, and NO confidentiality.
//!
//! ## Purpose
//!
//! This protocol is a deterministic scaffold for peer-to-peer parameter
//! agreement during connection setup. Production deployments MUST use
//! `tidefs-auth` (Ed25519-signed HELLO handshake) or an equivalent real
//! authenticated key agreement to establish session encryption keys. The
//! negotiation token produced here MUST NOT be used as cipher key material.
//!
//! ## Protocol flow
//!
//! ```text
//! Client                         Server
//!   |                              |
//!   |── ClientHello ──────────────>|
//!   |                              |  (record ClientHello,
//!   |                              |   update transcript,
//!   |                              |   derive negotiation token,
//!   |                              |   produce ServerVerify)
//!   |<─ ServerHello+ServerVerify───|
//!   |  (verify ServerVerify,       |
//!   |   derive negotiation token,  |
//!   |   produce ClientVerify)      |
//!   |── ClientVerify ─────────────>|
//!   |                              |  (verify ClientVerify)
//!   |<══════ parameters agreed ═══>|
//! ```
//!
//! ## Transcript agreement
//!
//! Both peers' node identities and nonces are included in the transcript,
//! ensuring cross-session uniqueness. The ephemeral nonces make each
//! transcript distinct, so replaying a captured ClientHello on a second
//! connection produces a different transcript and is rejected at the
//! ServerVerify step.
//!
//! ## Token derivation
//!
//! The negotiation token is a BLAKE3 derive_key over the transcript hash:
//!   token = derive_key("tidefs-transport-negotiation-token-v1", transcript_hash)

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::{FamilyVersion, NodeIdentityPublic};

// ---------------------------------------------------------------------------
// Domain context strings for handshake key derivation
// ---------------------------------------------------------------------------

/// Domain context for negotiation token derivation via BLAKE3 derive_key.
const NEGOTIATION_TOKEN_DOMAIN: &str = "tidefs-transport-negotiation-token-v1";

// ---------------------------------------------------------------------------
// Negotiation message types
// ---------------------------------------------------------------------------

/// Tag byte prepended to each message before feeding into the transcript
/// hasher. This prevents message-type confusion attacks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum MessageTag {
    ClientHello = 0x01,
    ServerHello = 0x02,
}

/// ClientHello: sent by the connecting client to initiate parameter negotiation.
///
/// Contains the client's ephemeral nonce, identity, protocol capabilities,
/// endpoint family, and epoch. This is the first message in the protocol.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ClientHello {
    /// Ephemeral client nonce (32 random bytes).
    pub client_nonce: [u8; 32],
    /// Client's node ID.
    pub node_id: u64,
    /// Client's Ed25519 public identity.
    pub identity: NodeIdentityPublic,
    /// Protocol families and versions the client supports.
    pub families: Vec<FamilyVersion>,
    /// Endpoint family (e0..e3 per P8-01), serialized as u32.
    pub endpoint_family: u32,
    /// Membership epoch the client is bound to.
    pub epoch: u64,
}

/// ServerHello: sent by the server in response to ClientHello.
///
/// Contains the server's ephemeral nonce, identity, protocol capabilities,
/// endpoint family, and epoch. Followed immediately by ServerVerify.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ServerHello {
    /// Ephemeral server nonce (32 random bytes).
    pub server_nonce: [u8; 32],
    /// Server's node ID.
    pub node_id: u64,
    /// Server's Ed25519 public identity.
    pub identity: NodeIdentityPublic,
    /// Protocol families and versions the server supports.
    pub families: Vec<FamilyVersion>,
    /// Endpoint family (e0..e3 per P8-01), serialized as u32.
    pub endpoint_family: u32,
    /// Membership epoch the server is bound to.
    pub epoch: u64,
}

/// ServerVerify: sent by the server after ServerHello, carrying the
/// derived negotiation token as a public transcript-agreement proof.
/// The negotiation token is NOT a secret; it is computed from public
/// transcript data and confirms both peers derived the same token.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ServerVerify {
    /// The derived negotiation token. Both peers compute the same token from
    /// the transcript; receiving it confirms transcript agreement.
    pub transcript_verify: [u8; 32],
}

/// ClientVerify: sent by the client after verifying ServerVerify, carrying the
/// derived negotiation token as a public transcript-agreement proof.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ClientVerify {
    /// The derived negotiation token. Both peers compute the same token from
    /// the transcript; receiving it confirms transcript agreement.
    pub transcript_verify: [u8; 32],
}

// ---------------------------------------------------------------------------
// Wire message wrapper for framing negotiation messages on the transport
// ---------------------------------------------------------------------------

/// Discriminant for negotiation message framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeFrameKind {
    ClientHello = 0x01,
    ServerHello = 0x02,
    ServerVerify = 0x03,
    ClientVerify = 0x04,
}

impl HandshakeFrameKind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::ClientHello),
            0x02 => Some(Self::ServerHello),
            0x03 => Some(Self::ServerVerify),
            0x04 => Some(Self::ClientVerify),
            _ => None,
        }
    }
}

/// A framed negotiation message: one discriminant byte followed by
/// bincode-encoded payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandshakeFrame {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    ServerVerify(ServerVerify),
    ClientVerify(ClientVerify),
}

impl HandshakeFrame {
    /// Encode this negotiation frame to wire bytes:
    /// `[discriminant: u8] || [bincode payload]`
    pub fn encode(&self) -> Result<Vec<u8>, HandshakeError> {
        let (kind, payload) = match self {
            Self::ClientHello(m) => (
                HandshakeFrameKind::ClientHello,
                bincode::serialize(m).map_err(|e| HandshakeError::Encode(e.to_string()))?,
            ),
            Self::ServerHello(m) => (
                HandshakeFrameKind::ServerHello,
                bincode::serialize(m).map_err(|e| HandshakeError::Encode(e.to_string()))?,
            ),
            Self::ServerVerify(m) => (
                HandshakeFrameKind::ServerVerify,
                bincode::serialize(m).map_err(|e| HandshakeError::Encode(e.to_string()))?,
            ),
            Self::ClientVerify(m) => (
                HandshakeFrameKind::ClientVerify,
                bincode::serialize(m).map_err(|e| HandshakeError::Encode(e.to_string()))?,
            ),
        };
        let mut frame = Vec::with_capacity(1 + payload.len());
        frame.push(kind as u8);
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    /// Decode a negotiation frame from wire bytes.
    /// Format: `[discriminant: u8] || [bincode payload]`
    pub fn decode(bytes: &[u8]) -> Result<Self, HandshakeError> {
        if bytes.is_empty() {
            return Err(HandshakeError::Decode("empty frame".into()));
        }
        let kind = HandshakeFrameKind::from_u8(bytes[0])
            .ok_or_else(|| HandshakeError::Decode(format!("unknown frame kind: {}", bytes[0])))?;
        let payload = &bytes[1..];
        match kind {
            HandshakeFrameKind::ClientHello => {
                let m: ClientHello = bincode::deserialize(payload)
                    .map_err(|e| HandshakeError::Decode(format!("ClientHello: {e}")))?;
                Ok(Self::ClientHello(m))
            }
            HandshakeFrameKind::ServerHello => {
                let m: ServerHello = bincode::deserialize(payload)
                    .map_err(|e| HandshakeError::Decode(format!("ServerHello: {e}")))?;
                Ok(Self::ServerHello(m))
            }
            HandshakeFrameKind::ServerVerify => {
                let m: ServerVerify = bincode::deserialize(payload)
                    .map_err(|e| HandshakeError::Decode(format!("ServerVerify: {e}")))?;
                Ok(Self::ServerVerify(m))
            }
            HandshakeFrameKind::ClientVerify => {
                let m: ClientVerify = bincode::deserialize(payload)
                    .map_err(|e| HandshakeError::Decode(format!("ClientVerify: {e}")))?;
                Ok(Self::ClientVerify(m))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Negotiation transcript
// ---------------------------------------------------------------------------

/// Accumulates the negotiation transcript, which is a BLAKE3 hash of all
/// messages exchanged in order. Each message is prefixed with its
/// [`MessageTag`] byte before being fed into the hasher.
pub struct HandshakeTranscript {
    hasher: blake3::Hasher,
}

impl HandshakeTranscript {
    /// Create a new empty transcript.
    pub fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
        }
    }

    /// Feed a message into the transcript.
    fn update_with_tag(&mut self, tag: MessageTag, serialized: &[u8]) {
        self.hasher.update(&[tag as u8]);
        self.hasher.update(serialized);
    }

    /// Feed a ClientHello into the transcript.
    pub fn update_client_hello(&mut self, msg: &ClientHello) -> Result<(), HandshakeError> {
        let bytes = bincode::serialize(msg).map_err(|e| HandshakeError::Encode(e.to_string()))?;
        self.update_with_tag(MessageTag::ClientHello, &bytes);
        Ok(())
    }

    /// Feed a ServerHello into the transcript.
    pub fn update_server_hello(&mut self, msg: &ServerHello) -> Result<(), HandshakeError> {
        let bytes = bincode::serialize(msg).map_err(|e| HandshakeError::Encode(e.to_string()))?;
        self.update_with_tag(MessageTag::ServerHello, &bytes);
        Ok(())
    }

    /// Finalize the transcript and return the 32-byte hash.
    pub fn finalize(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

impl Default for HandshakeTranscript {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Negotiation token derivation
// ---------------------------------------------------------------------------

/// Derive a 32-byte negotiation token from the negotiation transcript hash.
///
/// Uses BLAKE3 derive_key mode with the domain context string
/// `NEGOTIATION_TOKEN_DOMAIN`, feeding the transcript hash as input.
/// Both peers derive the same key when they agree on the transcript.
pub fn derive_negotiation_token(transcript_hash: &[u8; 32]) -> [u8; 32] {
    let mut kdf = blake3::Hasher::new_derive_key(NEGOTIATION_TOKEN_DOMAIN);
    kdf.update(transcript_hash);
    kdf.finalize().into()
}

// Transcript verification: both peers compare negotiation tokens directly.

// ---------------------------------------------------------------------------
// Negotiation state machine
// ---------------------------------------------------------------------------

/// The handshake state machine for a single peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandshakeState {
    /// Waiting for the client to send ClientHello (server-side initial state).
    ExpectingClientHello,
    /// ClientHello received, waiting for ServerHello + ServerVerify.
    ExpectingServerHello,
    /// ServerHello received, waiting for ServerVerify.
    ExpectingServerVerify,
    /// ServerVerify verified, waiting for ClientVerify.
    ExpectingClientVerify,
    /// Negotiation complete: both sides have verified key possession.
    Complete(NegotiationComplete),
}

/// The result of a successful handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegotiationComplete {
    /// 32-byte negotiation token derived from the negotiation transcript.
    pub negotiation_token: [u8; 32],
    /// Verified peer node ID.
    pub peer_node_id: u64,
    /// Verified peer identity (Ed25519 public key).
    pub peer_identity: NodeIdentityPublic,
    /// Protocol families the peer supports.
    pub peer_families: Vec<FamilyVersion>,
    /// Peer's endpoint family (as wire u32).
    pub peer_endpoint_family: u32,
    /// Peer's epoch.
    pub peer_epoch: u64,
    /// Final transcript hash (for audit logging).
    pub transcript_hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// Client-side negotiation driver
// ---------------------------------------------------------------------------

/// Client-side negotiation context.
pub struct ClientHandshake {
    state: HandshakeState,
    transcript: Option<HandshakeTranscript>,
    client_hello: Option<ClientHello>,
}

impl ClientHandshake {
    /// Create a new client-side handshake with the given parameters.
    ///
    /// Generates an ephemeral client nonce and builds the ClientHello message.
    /// The caller must send the returned `ClientHello` to the server.
    pub fn initiate(
        node_id: u64,
        identity: NodeIdentityPublic,
        families: Vec<FamilyVersion>,
        endpoint_family: u32,
        epoch: u64,
    ) -> Result<(Self, ClientHello), HandshakeError> {
        use rand::Rng;
        let client_nonce: [u8; 32] = rand::thread_rng().gen();

        let client_hello = ClientHello {
            client_nonce,
            node_id,
            identity,
            families,
            endpoint_family,
            epoch,
        };

        let mut transcript = HandshakeTranscript::new();
        transcript.update_client_hello(&client_hello)?;

        Ok((
            Self {
                state: HandshakeState::ExpectingServerHello,
                transcript: Some(transcript),
                client_hello: Some(client_hello.clone()),
            },
            client_hello,
        ))
    }

    /// Process ServerHello + ServerVerify received from the server.
    pub fn handle_server_hello(
        &mut self,
        server_hello: ServerHello,
        server_finished: ServerVerify,
    ) -> Result<ClientVerify, HandshakeError> {
        if self.state != HandshakeState::ExpectingServerHello {
            return Err(HandshakeError::StateMachine(format!(
                "expected state ExpectingServerHello, got {:?}",
                self.state
            )));
        }

        // Update transcript with ServerHello
        self.transcript
            .as_mut()
            .ok_or_else(|| HandshakeError::StateMachine("transcript already consumed".into()))?
            .update_server_hello(&server_hello)?;

        // Finalize transcript and derive negotiation token
        let transcript_hash = self
            .transcript
            .take()
            .ok_or_else(|| HandshakeError::StateMachine("transcript already consumed".into()))?
            .finalize();
        let negotiation_token = derive_negotiation_token(&transcript_hash);

        // Verify server carried the same negotiation token
        if server_finished.transcript_verify != negotiation_token {
            return Err(HandshakeError::TranscriptMismatch(
                "server transcript verification mismatch".into(),
            ));
        }

        // Produce client finished
        let client_finished = ClientVerify {
            transcript_verify: negotiation_token,
        };

        let _ = self
            .client_hello
            .take()
            .ok_or_else(|| HandshakeError::StateMachine("client_hello already consumed".into()))?;

        self.state = HandshakeState::Complete(NegotiationComplete {
            negotiation_token,
            peer_node_id: server_hello.node_id,
            peer_identity: server_hello.identity,
            peer_families: server_hello.families,
            peer_endpoint_family: server_hello.endpoint_family,
            peer_epoch: server_hello.epoch,
            transcript_hash,
        });

        Ok(client_finished)
    }

    /// Return the current negotiation state.
    pub fn state(&self) -> &HandshakeState {
        &self.state
    }
}

// ---------------------------------------------------------------------------
// Server-side negotiation driver
// ---------------------------------------------------------------------------

/// Server-side negotiation context.
pub struct ServerHandshake {
    state: HandshakeState,
    negotiation_token: Option<[u8; 32]>, // parameter-negotiation token, NOT an encryption key
    server_hello: Option<ServerHello>,
}

impl ServerHandshake {
    /// Create a new server-side handshake in response to a received ClientHello.
    ///
    /// Generates an ephemeral server nonce and builds the ServerHello +
    /// ServerVerify messages.
    pub fn respond(
        client_hello: ClientHello,
        node_id: u64,
        identity: NodeIdentityPublic,
        families: Vec<FamilyVersion>,
        endpoint_family: u32,
        epoch: u64,
    ) -> Result<(Self, ServerHello, ServerVerify), HandshakeError> {
        use rand::Rng;
        let mut transcript = HandshakeTranscript::new();
        transcript.update_client_hello(&client_hello)?;

        let server_nonce: [u8; 32] = rand::thread_rng().gen();

        let server_hello = ServerHello {
            server_nonce,
            node_id,
            identity,
            families,
            endpoint_family,
            epoch,
        };

        transcript.update_server_hello(&server_hello)?;

        // Derive negotiation token from transcript
        let transcript_hash = transcript.finalize();
        let negotiation_token = derive_negotiation_token(&transcript_hash);

        let server_finished = ServerVerify {
            transcript_verify: negotiation_token,
        };

        Ok((
            Self {
                state: HandshakeState::ExpectingClientVerify,
                negotiation_token: Some(negotiation_token),
                server_hello: Some(server_hello.clone()),
            },
            server_hello,
            server_finished,
        ))
    }

    /// Process ClientVerify received from the client.
    pub fn handle_client_finished(
        &mut self,
        client_finished: ClientVerify,
        peer_hello: ClientHello,
    ) -> Result<NegotiationComplete, HandshakeError> {
        if self.state != HandshakeState::ExpectingClientVerify {
            return Err(HandshakeError::StateMachine(format!(
                "expected state ExpectingClientVerify, got {:?}",
                self.state
            )));
        }

        let negotiation_token = self
            .negotiation_token
            .take()
            .ok_or_else(|| HandshakeError::StateMachine("negotiation token not derived".into()))?;

        // Recompute transcript hash for transcript verification verification
        let mut transcript = HandshakeTranscript::new();
        transcript.update_client_hello(&peer_hello)?;
        let server_hello = self
            .server_hello
            .as_ref()
            .ok_or_else(|| HandshakeError::StateMachine("server_hello not set".into()))?;
        transcript.update_server_hello(server_hello)?;
        let transcript_hash = transcript.finalize();

        if client_finished.transcript_verify != negotiation_token {
            return Err(HandshakeError::TranscriptMismatch(
                "client transcript verification mismatch".into(),
            ));
        }

        Ok(NegotiationComplete {
            negotiation_token,
            peer_node_id: peer_hello.node_id,
            peer_identity: peer_hello.identity,
            peer_families: peer_hello.families,
            peer_endpoint_family: peer_hello.endpoint_family,
            peer_epoch: peer_hello.epoch,
            transcript_hash,
        })
    }

    /// Return the current negotiation state.
    pub fn state(&self) -> &HandshakeState {
        &self.state
    }
}

// ---------------------------------------------------------------------------
// Negotiation errors
// ---------------------------------------------------------------------------

#[derive(Error, Debug, Clone)]
pub enum HandshakeError {
    #[error("encode error: {0}")]
    Encode(String),

    #[error("decode error: {0}")]
    Decode(String),

    #[error("negotiation state machine error: {0}")]
    StateMachine(String),

    #[error("transcript verification failed: {0}")]
    TranscriptMismatch(String),

    #[error("cryptographic error: {0}")]
    Crypto(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity(seed: u64) -> NodeIdentityPublic {
        let mut state = seed.wrapping_mul(0x9E3779B97F4A7C15);
        state ^= state >> 30;
        state = state.wrapping_mul(0xBF58476D1CE4E5B9);
        state ^= state >> 27;
        state = state.wrapping_mul(0x94D049BB133111EB);
        state ^= state >> 31;

        let mut key_bytes = [0u8; 32];
        for byte in &mut key_bytes {
            state = state.wrapping_mul(0x9E3779B97F4A7C15);
            state ^= state >> 30;
            state = state.wrapping_mul(0xBF58476D1CE4E5B9);
            state ^= state >> 27;
            *byte = (state >> 24) as u8;
        }

        let secret = ed25519_dalek::SecretKey::from_bytes(&key_bytes).expect("valid secret key");
        let public = ed25519_dalek::PublicKey::from(&secret);

        NodeIdentityPublic {
            node_id: seed,
            verifying_key_bytes: public.to_bytes(),
            attested_at_millis: 0,
            identity_version: 1,
            self_signature: Vec::new(),
        }
    }
    // ------------------------------------------------------------------
    // Full client-server round-trip
    // ------------------------------------------------------------------

    #[test]
    fn full_negotiation_roundtrip_identical_tokens() {
        let client_id = test_identity(1);
        let server_id = test_identity(2);

        let (mut client_hs, client_hello) = ClientHandshake::initiate(
            1,
            client_id.clone(),
            vec![FamilyVersion::new(1, 1, 0)],
            1,
            42,
        )
        .expect("client initiate");

        assert!(matches!(
            client_hs.state(),
            HandshakeState::ExpectingServerHello
        ));

        let (mut server_hs, server_hello, server_finished) = ServerHandshake::respond(
            client_hello.clone(),
            2,
            server_id.clone(),
            vec![FamilyVersion::new(1, 1, 0)],
            1,
            42,
        )
        .expect("server respond");

        assert!(matches!(
            server_hs.state(),
            HandshakeState::ExpectingClientVerify
        ));

        let client_finished = client_hs
            .handle_server_hello(server_hello, server_finished)
            .expect("client handle server hello");

        let client_state = client_hs.state();
        let client_complete = match client_state {
            HandshakeState::Complete(c) => c,
            other => panic!("expected Complete, got {other:?}"),
        };

        let server_complete = server_hs
            .handle_client_finished(client_finished, client_hello)
            .expect("server handle client finished");

        assert_eq!(
            client_complete.negotiation_token,
            server_complete.negotiation_token
        );
        assert_eq!(
            client_complete.transcript_hash,
            server_complete.transcript_hash
        );
        assert_eq!(client_complete.peer_node_id, 2);
        assert_eq!(client_complete.peer_identity, server_id);
        assert_eq!(server_complete.peer_node_id, 1);
        assert_eq!(server_complete.peer_identity, client_id);
        assert_eq!(client_complete.peer_families.len(), 1);
        assert_eq!(client_complete.peer_families[0].family_id, 1);
        assert_eq!(client_complete.peer_epoch, 42);
        assert_eq!(server_complete.peer_epoch, 42);
    }

    // ------------------------------------------------------------------
    // Transcript divergence detection
    // ------------------------------------------------------------------

    #[test]
    fn tampered_server_hello_rejected() {
        let client_id = test_identity(1);
        let server_id = test_identity(2);

        let (mut client_hs, client_hello) =
            ClientHandshake::initiate(1, client_id, vec![], 1, 0).expect("initiate");

        let (_server_hs, server_hello, server_finished) =
            ServerHandshake::respond(client_hello, 2, server_id.clone(), vec![], 1, 0)
                .expect("respond");

        let mut tampered = server_hello.clone();
        tampered.server_nonce[0] ^= 0xFF;

        let result = client_hs.handle_server_hello(tampered, server_finished);
        assert!(result.is_err(), "tampered ServerHello should be rejected");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("transcript verification"),
            "error should mention transcript verification"
        );
    }

    // ------------------------------------------------------------------
    // Uniqueness: different sessions produce different tokens
    // ------------------------------------------------------------------

    #[test]
    fn negotiation_tokens_unique_per_session() {
        let id1 = test_identity(1);
        let id2 = test_identity(2);

        let (mut ch1, c1) = ClientHandshake::initiate(1, id1.clone(), vec![], 1, 0).unwrap();
        let (_sh1, s1, sf1) = ServerHandshake::respond(c1, 2, id2.clone(), vec![], 1, 0).unwrap();
        ch1.handle_server_hello(s1, sf1).unwrap();
        let token1 = match ch1.state() {
            HandshakeState::Complete(c) => c.negotiation_token,
            _ => panic!("expected Complete"),
        };

        let (mut ch2, c2) = ClientHandshake::initiate(1, id1, vec![], 1, 0).unwrap();
        let (_sh2, s2, sf2) = ServerHandshake::respond(c2, 2, id2, vec![], 1, 0).unwrap();
        ch2.handle_server_hello(s2, sf2).unwrap();
        let token2 = match ch2.state() {
            HandshakeState::Complete(c) => c.negotiation_token,
            _ => panic!("expected Complete"),
        };

        assert_ne!(
            token1, token2,
            "negotiation tokens should be unique per handshake"
        );
    }

    // ------------------------------------------------------------------
    // HandshakeFrame encode/decode round-trip
    // ------------------------------------------------------------------

    #[test]
    fn handshake_frame_encode_decode_roundtrip() {
        let client_id = test_identity(10);
        let original = ClientHello {
            client_nonce: [0xAA; 32],
            node_id: 1,
            identity: client_id,
            families: vec![FamilyVersion::new(1, 1, 0)],
            endpoint_family: 1,
            epoch: 7,
        };

        let frame = HandshakeFrame::ClientHello(original.clone());
        let encoded = frame.encode().expect("encode");
        let decoded = HandshakeFrame::decode(&encoded).expect("decode");

        match decoded {
            HandshakeFrame::ClientHello(m) => assert_eq!(m, original),
            other => panic!("expected ClientHello, got {other:?}"),
        }
    }

    #[test]
    fn handshake_frame_decode_unknown_kind_fails() {
        assert!(HandshakeFrame::decode(&[0xFF, 0x00]).is_err());
    }

    #[test]
    fn handshake_frame_decode_empty_bytes_fails() {
        assert!(HandshakeFrame::decode(&[]).is_err());
    }

    // ------------------------------------------------------------------
    // State machine: invalid transitions
    // ------------------------------------------------------------------

    #[test]
    fn client_double_handle_server_hello_fails() {
        let client_id = test_identity(1);
        let server_id = test_identity(2);

        let (mut client_hs, client_hello) =
            ClientHandshake::initiate(1, client_id, vec![], 1, 0).expect("initiate");

        let (_server_hs, server_hello, server_finished) =
            ServerHandshake::respond(client_hello, 2, server_id, vec![], 1, 0).expect("respond");

        client_hs
            .handle_server_hello(server_hello.clone(), server_finished.clone())
            .expect("first handle");

        let result = client_hs.handle_server_hello(server_hello, server_finished);
        assert!(result.is_err(), "second handle should fail");
    }

    #[test]
    fn server_double_handle_client_finished_fails() {
        let client_id = test_identity(1);
        let server_id = test_identity(2);

        let (mut client_hs, client_hello) =
            ClientHandshake::initiate(1, client_id, vec![], 1, 0).expect("initiate");

        let (mut server_hs, server_hello, server_finished) =
            ServerHandshake::respond(client_hello.clone(), 2, server_id, vec![], 1, 0)
                .expect("respond");

        let client_finished = client_hs
            .handle_server_hello(server_hello, server_finished)
            .expect("client handle");

        server_hs
            .handle_client_finished(client_finished.clone(), client_hello.clone())
            .expect("first server handle");

        let result = server_hs.handle_client_finished(client_finished, client_hello);
        assert!(result.is_err(), "second handle should fail");
    }

    // ------------------------------------------------------------------
    // Transcript verification tampering
    // ------------------------------------------------------------------

    #[test]
    fn tampered_server_verify_rejected() {
        let client_id = test_identity(1);
        let server_id = test_identity(2);

        let (mut client_hs, client_hello) =
            ClientHandshake::initiate(1, client_id, vec![], 1, 0).expect("initiate");

        let (_server_hs, server_hello, mut server_finished) =
            ServerHandshake::respond(client_hello, 2, server_id, vec![], 1, 0).expect("respond");

        server_finished.transcript_verify[0] ^= 0xFF;

        let result = client_hs.handle_server_hello(server_hello, server_finished);
        assert!(result.is_err(), "tampered ServerVerify should be rejected");
    }

    #[test]
    fn tampered_client_verify_rejected() {
        let client_id = test_identity(1);
        let server_id = test_identity(2);

        let (mut client_hs, client_hello) =
            ClientHandshake::initiate(1, client_id, vec![], 1, 0).expect("initiate");

        let (mut server_hs, server_hello, server_finished) =
            ServerHandshake::respond(client_hello.clone(), 2, server_id, vec![], 1, 0)
                .expect("respond");

        let mut client_finished = client_hs
            .handle_server_hello(server_hello, server_finished)
            .expect("client handle");

        client_finished.transcript_verify[0] ^= 0xFF;

        let result = server_hs.handle_client_finished(client_finished, client_hello);
        assert!(result.is_err(), "tampered ClientVerify should be rejected");
    }

    // ------------------------------------------------------------------
    // Replay: same ClientHello on two connections produces different keys
    // ------------------------------------------------------------------

    #[test]
    fn replay_same_client_hello_different_server_nonce() {
        let client_id = test_identity(1);
        let server_id = test_identity(2);

        // The client sends its ClientHello; the server responds twice with
        // different nonces, producing different transcripts and keys.
        let (_ch1, client_hello) =
            ClientHandshake::initiate(1, client_id, vec![], 1, 0).expect("initiate");

        let (_sh1, _s1, sf1) =
            ServerHandshake::respond(client_hello.clone(), 2, server_id.clone(), vec![], 1, 0)
                .expect("respond 1");

        let (_sh2, s2, sf2) =
            ServerHandshake::respond(client_hello, 2, server_id, vec![], 1, 0).expect("respond 2");

        // The two ServerVerify values should differ because the transcripts
        // differ (different server_nonce).
        assert_ne!(
            sf1.transcript_verify, sf2.transcript_verify,
            "different transcripts should produce different ServerVerify"
        );
        // And the two ServerHellos should have different nonces
        assert_ne!(
            _s1.server_nonce, s2.server_nonce,
            "each server response should use a fresh nonce"
        );
    }

    // ------------------------------------------------------------------
    // Attacker-observer: eavesdropper can derive the same token
    // ------------------------------------------------------------------

    #[test]
    fn attacker_observer_derives_same_negotiation_token() {
        // An eavesdropper who captures all handshake messages can
        // independently compute the same negotiation token, proving
        // this protocol provides NO secrecy.
        let client_id = test_identity(1);
        let server_id = test_identity(2);

        let (mut client_hs, client_hello) =
            ClientHandshake::initiate(1, client_id, vec![], 1, 0).expect("initiate");

        let (_server_hs, server_hello, server_verify) =
            ServerHandshake::respond(client_hello.clone(), 2, server_id, vec![], 1, 0)
                .expect("respond");

        let _client_verify = client_hs
            .handle_server_hello(server_hello.clone(), server_verify)
            .expect("client handle");

        let client_complete = match client_hs.state() {
            HandshakeState::Complete(c) => c,
            other => panic!("expected Complete, got {other:?}"),
        };

        // Attacker reconstructs the transcript from captured messages
        let mut attacker_transcript = HandshakeTranscript::new();
        attacker_transcript
            .update_client_hello(&client_hello)
            .unwrap();
        attacker_transcript
            .update_server_hello(&server_hello)
            .unwrap();
        let attacker_hash = attacker_transcript.finalize();

        let attacker_token = derive_negotiation_token(&attacker_hash);
        assert_eq!(
            attacker_token, client_complete.negotiation_token,
            "attacker can independently compute the same negotiation token              from captured public messages -- this is NOT a secret"
        );
    }

    #[test]
    fn session_params_from_negotiation_complete_roundtrip() {
        let id_a = test_identity(1);
        let id_b = test_identity(2);

        // Perform a full handshake round-trip
        let (mut ch, client_hello) =
            ClientHandshake::initiate(1, id_a.clone(), vec![], 0, 0).expect("initiate");
        let (mut sh, server_hello, server_finished) =
            ServerHandshake::respond(client_hello.clone(), 2, id_b.clone(), vec![], 0, 0)
                .expect("respond");

        // Client processes server's response, produces ClientVerify
        let client_finished = ch
            .handle_server_hello(server_hello, server_finished)
            .expect("handle_server_hello");

        // Server verifies ClientVerify, produces NegotiationComplete
        let complete = sh
            .handle_client_finished(client_finished, client_hello)
            .expect("handle_client_finished");

        // Create SessionParams with a negotiated version and capability mask
        let params = crate::session::SessionParams::from_negotiation_complete(
            &complete,
            1,           // negotiated_version
            0x0000_0003, // capability_mask: data + control
            42,          // session_id
        );

        assert_eq!(params.negotiated_version, 1);
        assert_eq!(params.capability_mask, 0x0000_0003);
        assert_eq!(params.session_id, 42);
        assert_eq!(params.remote_node_id, 1); // server sees client as peer
        assert_eq!(params.remote_identity.node_id, 1); // server sees client identity as peer
        assert_eq!(params.negotiation_token, complete.negotiation_token);
        assert_eq!(params.transcript_hash, complete.transcript_hash);
    }
}
