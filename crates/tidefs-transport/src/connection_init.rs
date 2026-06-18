// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Connection initialization handshake: protocol version negotiation and peer
//! identity exchange that runs after TCP accept/connect and before message
//! dispatch.
//!
//! ## Purpose
//!
//! After a raw TCP connection is established (#5828 accept, #5837 connect) but
//! before framed messages flow (codec, channels, keepalive, dispatch), peers
//! must negotiate protocol compatibility and exchange identity. This module
//! provides a two-message Hello/HelloAck handshake that bridges raw I/O to the
//! transport message pipeline.
//!
//! ## Exchange
//!
//! ```text
//! Initiator (connect side)          Responder (accept side)
//!      │                                    │
//!      │──── Hello(v=1, my_node_id) ──────▶ │
//!      │                                    │ validate version, record peer
//!      │ ◀── HelloAck(v=1, peer_node_id,    │
//!      │           accepted=true) ───────── │
//!      │                                    │
//!      ▼                                    ▼
//!    Active                               Active
//! ```
//!
//! ## Wire format
//!
//! Handshake messages are serialized with bincode and wrapped in the
//! existing [`crate::codec::MessageCodec`] wire format using
//! [`crate::envelope::MessageFamily::HelloClose`] as the family
//! discriminant. Total overhead per handshake message:
//! 5 bytes codec header + bincode payload.

use serde::{Deserialize, Serialize};

use crate::codec::{CodecError, MessageCodec};
use crate::envelope::MessageFamily;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Current protocol version for the connection initialization handshake.
pub const HANDSHAKE_PROTOCOL_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// HandshakeMessage
// ---------------------------------------------------------------------------

/// A two-message handshake frame exchanged after TCP connect/accept and
/// before the full message dispatch pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakeMessage {
    /// Sent by the connecting (initiator) side after TCP connect.
    Hello {
        /// Protocol version the initiator supports.
        protocol_version: u32,
        /// The initiator's node identity.
        node_id: u64,
    },
    /// Sent by the listening (responder) side in reply to a Hello.
    HelloAck {
        /// Protocol version the responder selected (must match Hello's version).
        protocol_version: u32,
        /// The responder's node identity.
        node_id: u64,
        /// Whether the handshake is accepted.  `false` means the initiator
        /// should close the connection.
        accepted: bool,
    },
}

impl HandshakeMessage {
    /// Serialize this message through the given [`MessageCodec`].
    ///
    /// Uses bincode for the inner payload, then wraps in a codec frame
    /// with [`MessageFamily::HelloClose`].
    pub fn encode(&self, codec: &MessageCodec) -> Result<Vec<u8>, ConnectionInitError> {
        let payload = bincode::serialize(self)
            .map_err(|e| ConnectionInitError::Serialization(e.to_string()))?;
        codec
            .encode(MessageFamily::HelloClose, &payload)
            .map_err(ConnectionInitError::Codec)
    }

    /// Deserialize a handshake message from a codec frame's payload bytes.
    pub fn decode(payload: &[u8]) -> Result<Self, ConnectionInitError> {
        bincode::deserialize(payload).map_err(|e| ConnectionInitError::Serialization(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// ConnectionInitState
// ---------------------------------------------------------------------------

/// Per-connection initialization lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionInitState {
    /// Connection established but handshake not yet started.
    Pending,
    /// Hello sent or received; waiting for the other side.
    Handshaking,
    /// Handshake completed successfully; the connection is ready for
    /// message dispatch.
    Active,
    /// Handshake failed; the connection should be closed.
    Failed,
}

impl ConnectionInitState {
    /// Returns `true` if the connection is ready for message dispatch.
    #[must_use]
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Returns `true` if the connection should be dropped.
    #[must_use]
    pub fn is_failed(self) -> bool {
        matches!(self, Self::Failed)
    }
}

// ---------------------------------------------------------------------------
// ConnectionInitError
// ---------------------------------------------------------------------------

/// Errors that can occur during connection initialization.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionInitError {
    /// The peer's protocol version does not match the local version.
    #[error("protocol version mismatch: local {local}, peer {peer}")]
    VersionMismatch {
        /// The protocol version supported by the local side.
        local: u32,
        /// The protocol version advertised by the peer.
        peer: u32,
    },

    /// The peer explicitly rejected the handshake.
    #[error("handshake rejected by peer (node_id={node_id})")]
    PeerRejection { node_id: u64 },

    /// The handshake did not complete within the configured timeout.
    #[error("handshake timed out")]
    Timeout,

    /// An error from the wire codec layer.
    #[error("codec error: {0}")]
    Codec(#[from] CodecError),

    /// Payload serialization or deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// The handshake was already completed or has already failed;
    /// cannot be re-run on the same connection.
    #[error("handshake already completed or failed")]
    AlreadyComplete,

    /// The peer's identity conflicts with an existing connection to a
    /// different node on the same address.
    #[error("peer identity conflict: existing node_id={existing}, received node_id={received}")]
    IdentityConflict {
        /// The node_id of the already-known peer.
        existing: u64,
        /// The node_id claimed by the new connection.
        received: u64,
    },
}

// ---------------------------------------------------------------------------
// HandshakeInitiator
// ---------------------------------------------------------------------------

/// State machine for the connecting (initiator) side of the handshake.
///
/// After `TcpStream::connect()` succeeds, the initiator sends a [`Hello`],
/// waits for a [`HelloAck`], and validates the response.
///
/// [`Hello`]: HandshakeMessage::Hello
/// [`HelloAck`]: HandshakeMessage::HelloAck
#[derive(Debug)]
pub struct HandshakeInitiator {
    /// The local node's identity.
    local_node_id: u64,
    /// Current initialization state.
    state: ConnectionInitState,
    /// The peer's node identity, set after a successful handshake.
    peer_node_id: Option<u64>,
}

impl HandshakeInitiator {
    /// Create a new initiator for the given local node identity.
    #[must_use]
    pub fn new(local_node_id: u64) -> Self {
        Self {
            local_node_id,
            state: ConnectionInitState::Pending,
            peer_node_id: None,
        }
    }

    /// Return the current connection initialization state.
    #[must_use]
    pub fn state(&self) -> ConnectionInitState {
        self.state
    }

    /// Return the peer's node identity after a successful handshake.
    #[must_use]
    pub fn peer_node_id(&self) -> Option<u64> {
        self.peer_node_id
    }

    /// Build the [`Hello`] message the initiator should send.
    ///
    /// Transitions state from `Pending` to `Handshaking`.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionInitError::AlreadyComplete`] if the handshake has
    /// already been initiated or completed.
    pub fn build_hello(&mut self) -> Result<HandshakeMessage, ConnectionInitError> {
        if self.state != ConnectionInitState::Pending {
            return Err(ConnectionInitError::AlreadyComplete);
        }
        self.state = ConnectionInitState::Handshaking;
        Ok(HandshakeMessage::Hello {
            protocol_version: HANDSHAKE_PROTOCOL_VERSION,
            node_id: self.local_node_id,
        })
    }

    /// Process a [`HelloAck`] received from the responder.
    ///
    /// Validates protocol version compatibility and the `accepted` flag.
    /// On success, transitions state to `Active` and records the peer's
    /// identity.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionInitError::AlreadyComplete`] if not in `Handshaking`
    /// state.  Returns [`ConnectionInitError::VersionMismatch`] if the peer's
    /// version differs.  Returns [`ConnectionInitError::PeerRejection`] if
    /// `accepted` is `false`.
    pub fn handle_hello_ack(&mut self, ack: &HandshakeMessage) -> Result<(), ConnectionInitError> {
        if self.state != ConnectionInitState::Handshaking {
            return Err(ConnectionInitError::AlreadyComplete);
        }

        let (peer_version, peer_node_id, accepted) = match ack {
            HandshakeMessage::HelloAck {
                protocol_version,
                node_id,
                accepted,
            } => (*protocol_version, *node_id, *accepted),
            _ => {
                return Err(ConnectionInitError::Serialization(
                    "expected HelloAck, got Hello".into(),
                ));
            }
        };

        if !accepted {
            self.state = ConnectionInitState::Failed;
            return Err(ConnectionInitError::PeerRejection {
                node_id: peer_node_id,
            });
        }

        if peer_version != HANDSHAKE_PROTOCOL_VERSION {
            self.state = ConnectionInitState::Failed;
            return Err(ConnectionInitError::VersionMismatch {
                local: HANDSHAKE_PROTOCOL_VERSION,
                peer: peer_version,
            });
        }

        self.peer_node_id = Some(peer_node_id);
        self.state = ConnectionInitState::Active;
        Ok(())
    }

    /// Force the initiator into `Failed` state (e.g., on timeout).
    pub fn fail(&mut self) {
        self.state = ConnectionInitState::Failed;
    }
}

// ---------------------------------------------------------------------------
// HandshakeResponder
// ---------------------------------------------------------------------------

/// State machine for the listening (responder) side of the handshake.
///
/// After `TcpListener::accept()` yields a connection, the responder waits
/// for a [`Hello`], validates it, and replies with a [`HelloAck`].
///
/// [`Hello`]: HandshakeMessage::Hello
/// [`HelloAck`]: HandshakeMessage::HelloAck
#[derive(Debug)]
pub struct HandshakeResponder {
    /// The local node's identity.
    local_node_id: u64,
    /// Current initialization state.
    state: ConnectionInitState,
    /// The peer's node identity, set after a successful handshake.
    peer_node_id: Option<u64>,
}

impl HandshakeResponder {
    /// Create a new responder for the given local node identity.
    #[must_use]
    pub fn new(local_node_id: u64) -> Self {
        Self {
            local_node_id,
            state: ConnectionInitState::Pending,
            peer_node_id: None,
        }
    }

    /// Return the current connection initialization state.
    #[must_use]
    pub fn state(&self) -> ConnectionInitState {
        self.state
    }

    /// Return the peer's node identity after a successful handshake.
    #[must_use]
    pub fn peer_node_id(&self) -> Option<u64> {
        self.peer_node_id
    }

    /// Process a [`Hello`] message received from the initiator and build
    /// the corresponding [`HelloAck`] response.
    ///
    /// Validates the initiator's protocol version.  Transitions state
    /// from `Pending` through `Handshaking` to either `Active` (on
    /// acceptance) or `Failed` (on version mismatch).
    ///
    /// Returns an `Ok(HelloAck)` with `accepted: false` when the
    /// initiator's version is unsupported.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionInitError::AlreadyComplete`] if the handshake has
    /// already been processed.
    pub fn handle_hello(
        &mut self,
        hello: &HandshakeMessage,
    ) -> Result<HandshakeMessage, ConnectionInitError> {
        if self.state != ConnectionInitState::Pending {
            return Err(ConnectionInitError::AlreadyComplete);
        }
        self.state = ConnectionInitState::Handshaking;

        let (peer_version, peer_node_id) = match hello {
            HandshakeMessage::Hello {
                protocol_version,
                node_id,
            } => (*protocol_version, *node_id),
            _ => {
                self.state = ConnectionInitState::Failed;
                return Err(ConnectionInitError::Serialization(
                    "expected Hello, got HelloAck".into(),
                ));
            }
        };

        if peer_version != HANDSHAKE_PROTOCOL_VERSION {
            self.state = ConnectionInitState::Failed;
            return Ok(HandshakeMessage::HelloAck {
                protocol_version: HANDSHAKE_PROTOCOL_VERSION,
                node_id: self.local_node_id,
                accepted: false,
            });
        }

        self.peer_node_id = Some(peer_node_id);
        self.state = ConnectionInitState::Active;
        Ok(HandshakeMessage::HelloAck {
            protocol_version: HANDSHAKE_PROTOCOL_VERSION,
            node_id: self.local_node_id,
            accepted: true,
        })
    }

    /// Force the responder into `Failed` state (e.g., on timeout or
    /// truncated message).
    pub fn fail(&mut self) {
        self.state = ConnectionInitState::Failed;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn codec() -> MessageCodec {
        MessageCodec::default()
    }

    // ---- HandshakeMessage encode/decode round-trip ----

    #[test]
    fn hello_encode_decode_roundtrip() {
        let c = codec();
        let msg = HandshakeMessage::Hello {
            protocol_version: 1,
            node_id: 42,
        };
        let frame = msg.encode(&c).unwrap();

        // Decode through the codec first, then bincode.
        let (family, payload) = c.decode(&frame).unwrap();
        assert_eq!(family, MessageFamily::HelloClose);
        let decoded = HandshakeMessage::decode(&payload).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn hello_ack_encode_decode_roundtrip() {
        let c = codec();
        let msg = HandshakeMessage::HelloAck {
            protocol_version: 1,
            node_id: 99,
            accepted: true,
        };
        let frame = msg.encode(&c).unwrap();
        let (_family, payload) = c.decode(&frame).unwrap();
        let decoded = HandshakeMessage::decode(&payload).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn hello_ack_rejected_encode_decode_roundtrip() {
        let c = codec();
        let msg = HandshakeMessage::HelloAck {
            protocol_version: 1,
            node_id: 7,
            accepted: false,
        };
        let frame = msg.encode(&c).unwrap();
        let (_, payload) = c.decode(&frame).unwrap();
        let decoded = HandshakeMessage::decode(&payload).unwrap();
        assert_eq!(decoded, msg);
    }

    // ---- decode with garbage payload ----

    #[test]
    fn decode_garbage_payload() {
        let result = HandshakeMessage::decode(b"not a valid bincode message");
        assert!(result.is_err());
    }

    // ---- ConnectionInitState transitions ----

    #[test]
    fn connection_init_state_is_pending_by_default() {
        let init = HandshakeInitiator::new(1);
        assert_eq!(init.state(), ConnectionInitState::Pending);
    }

    #[test]
    fn connection_init_state_active_after_handshake() {
        let mut init = HandshakeInitiator::new(1);
        let _hello = init.build_hello().unwrap();
        assert_eq!(init.state(), ConnectionInitState::Handshaking);

        let ack = HandshakeMessage::HelloAck {
            protocol_version: HANDSHAKE_PROTOCOL_VERSION,
            node_id: 2,
            accepted: true,
        };
        init.handle_hello_ack(&ack).unwrap();
        assert_eq!(init.state(), ConnectionInitState::Active);
        assert_eq!(init.peer_node_id(), Some(2));
    }

    // ---- HandshakeInitiator: happy path ----

    #[test]
    fn initiator_happy_path() {
        let mut init = HandshakeInitiator::new(10);

        let hello = init.build_hello().unwrap();
        assert_eq!(
            hello,
            HandshakeMessage::Hello {
                protocol_version: HANDSHAKE_PROTOCOL_VERSION,
                node_id: 10,
            }
        );
        assert_eq!(init.state(), ConnectionInitState::Handshaking);

        let ack = HandshakeMessage::HelloAck {
            protocol_version: HANDSHAKE_PROTOCOL_VERSION,
            node_id: 20,
            accepted: true,
        };
        init.handle_hello_ack(&ack).unwrap();
        assert_eq!(init.state(), ConnectionInitState::Active);
        assert_eq!(init.peer_node_id(), Some(20));
    }

    // ---- HandshakeInitiator: rejects version mismatch ----

    #[test]
    fn initiator_rejects_version_mismatch() {
        let mut init = HandshakeInitiator::new(1);
        init.build_hello().unwrap();

        let ack = HandshakeMessage::HelloAck {
            protocol_version: 99,
            node_id: 2,
            accepted: true,
        };
        let err = init.handle_hello_ack(&ack).unwrap_err();
        match err {
            ConnectionInitError::VersionMismatch { local, peer } => {
                assert_eq!(local, HANDSHAKE_PROTOCOL_VERSION);
                assert_eq!(peer, 99);
            }
            _ => panic!("expected VersionMismatch, got {err:?}"),
        }
        assert!(init.state().is_failed());
    }

    // ---- HandshakeInitiator: rejects peer rejection ----

    #[test]
    fn initiator_rejects_peer_rejection() {
        let mut init = HandshakeInitiator::new(1);
        init.build_hello().unwrap();

        let ack = HandshakeMessage::HelloAck {
            protocol_version: HANDSHAKE_PROTOCOL_VERSION,
            node_id: 2,
            accepted: false,
        };
        let err = init.handle_hello_ack(&ack).unwrap_err();
        match err {
            ConnectionInitError::PeerRejection { node_id } => {
                assert_eq!(node_id, 2);
            }
            _ => panic!("expected PeerRejection, got {err:?}"),
        }
        assert!(init.state().is_failed());
    }

    // ---- HandshakeInitiator: rejects wrong message type ----

    #[test]
    fn initiator_rejects_hello_as_ack() {
        let mut init = HandshakeInitiator::new(1);
        init.build_hello().unwrap();

        // Feed a Hello instead of HelloAck.
        let wrong = HandshakeMessage::Hello {
            protocol_version: 1,
            node_id: 2,
        };
        let err = init.handle_hello_ack(&wrong).unwrap_err();
        assert!(matches!(err, ConnectionInitError::Serialization(_)));
    }

    // ---- HandshakeInitiator: rejects double-build ----

    #[test]
    fn initiator_rejects_double_build() {
        let mut init = HandshakeInitiator::new(1);
        init.build_hello().unwrap();
        let err = init.build_hello().unwrap_err();
        assert!(matches!(err, ConnectionInitError::AlreadyComplete));
    }

    // ---- HandshakeInitiator: rejects ack when not handshaking ----

    #[test]
    fn initiator_rejects_ack_when_not_handshaking() {
        let mut init = HandshakeInitiator::new(1);
        let ack = HandshakeMessage::HelloAck {
            protocol_version: HANDSHAKE_PROTOCOL_VERSION,
            node_id: 2,
            accepted: true,
        };
        let err = init.handle_hello_ack(&ack).unwrap_err();
        assert!(matches!(err, ConnectionInitError::AlreadyComplete));
    }

    // ---- HandshakeInitiator: fail state ----

    #[test]
    fn initiator_fail_transitions_to_failed() {
        let mut init = HandshakeInitiator::new(1);
        init.fail();
        assert!(init.state().is_failed());
    }

    // ---- HandshakeResponder: happy path ----

    #[test]
    fn responder_happy_path() {
        let mut resp = HandshakeResponder::new(20);

        let hello = HandshakeMessage::Hello {
            protocol_version: HANDSHAKE_PROTOCOL_VERSION,
            node_id: 10,
        };
        let ack = resp.handle_hello(&hello).unwrap();
        assert_eq!(
            ack,
            HandshakeMessage::HelloAck {
                protocol_version: HANDSHAKE_PROTOCOL_VERSION,
                node_id: 20,
                accepted: true,
            }
        );
        assert_eq!(resp.state(), ConnectionInitState::Active);
        assert_eq!(resp.peer_node_id(), Some(10));
    }

    // ---- HandshakeResponder: rejects unsupported version ----

    #[test]
    fn responder_rejects_version_mismatch_with_accepted_false() {
        let mut resp = HandshakeResponder::new(20);

        let hello = HandshakeMessage::Hello {
            protocol_version: 99,
            node_id: 10,
        };
        let ack = resp.handle_hello(&hello).unwrap();
        assert_eq!(
            ack,
            HandshakeMessage::HelloAck {
                protocol_version: HANDSHAKE_PROTOCOL_VERSION,
                node_id: 20,
                accepted: false,
            }
        );
        assert!(resp.state().is_failed());
        // peer_node_id is NOT set on version mismatch.
        assert_eq!(resp.peer_node_id(), None);
    }

    // ---- HandshakeResponder: rejects wrong message type ----

    #[test]
    fn responder_rejects_ack_as_hello() {
        let mut resp = HandshakeResponder::new(1);

        let wrong = HandshakeMessage::HelloAck {
            protocol_version: 1,
            node_id: 2,
            accepted: true,
        };
        let err = resp.handle_hello(&wrong).unwrap_err();
        assert!(matches!(err, ConnectionInitError::Serialization(_)));
        assert!(resp.state().is_failed());
    }

    // ---- HandshakeResponder: rejects double handle ----

    #[test]
    fn responder_rejects_double_handle() {
        let mut resp = HandshakeResponder::new(1);
        let hello = HandshakeMessage::Hello {
            protocol_version: HANDSHAKE_PROTOCOL_VERSION,
            node_id: 10,
        };
        resp.handle_hello(&hello).unwrap();
        let err = resp.handle_hello(&hello).unwrap_err();
        assert!(matches!(err, ConnectionInitError::AlreadyComplete));
    }

    // ---- HandshakeResponder: fail state ----

    #[test]
    fn responder_fail_transitions_to_failed() {
        let mut resp = HandshakeResponder::new(1);
        resp.fail();
        assert!(resp.state().is_failed());
    }

    // ---- End-to-end initiator <-> responder simulation ----

    #[test]
    fn end_to_end_successful_handshake() {
        let mut init = HandshakeInitiator::new(100);
        let mut resp = HandshakeResponder::new(200);

        // Initiator builds Hello.
        let hello = init.build_hello().unwrap();

        // Responder receives and processes Hello.
        let ack = resp.handle_hello(&hello).unwrap();
        assert!(resp.state().is_active());
        assert_eq!(resp.peer_node_id(), Some(100));

        // Initiator receives and processes HelloAck.
        init.handle_hello_ack(&ack).unwrap();
        assert!(init.state().is_active());
        assert_eq!(init.peer_node_id(), Some(200));
    }

    // ---- End-to-end: version mismatch ----

    #[test]
    fn end_to_end_version_mismatch() {
        let mut init = HandshakeInitiator::new(100);

        // Responder receives a Hello with a version it doesn't support.
        let hello = HandshakeMessage::Hello {
            protocol_version: 99,
            node_id: 100,
        };

        let mut resp = HandshakeResponder::new(200);
        let ack = resp.handle_hello(&hello).unwrap();
        // ack should have accepted=false.
        assert_eq!(
            ack,
            HandshakeMessage::HelloAck {
                protocol_version: HANDSHAKE_PROTOCOL_VERSION,
                node_id: 200,
                accepted: false,
            }
        );
        assert!(resp.state().is_failed());

        // Initiator gets rejected.
        let _ = init.build_hello().unwrap();
        let err = init.handle_hello_ack(&ack).unwrap_err();
        assert!(matches!(
            err,
            ConnectionInitError::PeerRejection { node_id: 200 }
        ));
    }

    // ---- End-to-end: initiator sees version mismatch in HelloAck ----

    #[test]
    fn end_to_end_initiator_sees_version_mismatch_in_ack() {
        let mut init = HandshakeInitiator::new(100);
        init.build_hello().unwrap();

        // Simulate an ack from a newer peer with incompatible version.
        let ack = HandshakeMessage::HelloAck {
            protocol_version: 2,
            node_id: 200,
            accepted: true,
        };
        let err = init.handle_hello_ack(&ack).unwrap_err();
        assert!(matches!(
            err,
            ConnectionInitError::VersionMismatch { local: 1, peer: 2 }
        ));
    }
}
