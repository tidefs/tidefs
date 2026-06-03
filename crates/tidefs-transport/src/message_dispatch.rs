//! Transport message dispatch: type-discriminated routing to subsystem handlers.
//!
//! ## Purpose
//!
//! The transport layer receives framed messages over sessions, but after
//! decoding the transport envelope ([`crate::envelope::TransportEnvelope`]),
//! the payload must be routed to the correct subsystem handler (membership,
//! chunk-transfer, lease, flow-control, etc.). This module provides that
//! type-to-handler routing through a unified dispatch path.
//!
//! ## Architecture
//!
//! ```text
//! TransportEnvelope (decoded)
//!   |
//!   v
//! MessageDispatcher::dispatch(session_id, payload)
//!   |
//!   +-- decode MessageEnvelope (type_tag + payload + CRC32C)
//!   +-- lookup MessageType -> Arc<dyn MessageHandler>
//!   +-- handler.handle(session_id, payload)
//! ```
//!
//! ## MessageType registry
//!
//! [`MessageType`] variants carry a deterministic non-cryptographic discriminant
//! (deterministic non-cryptographic discriminant per message type)
//! used as the wire type tag. Unknown discriminants decode to
//! `MessageType::Custom(discriminant)`, enabling forward-compatible
//! extension without version negotiation.
//!
//! ## CRC32C-verified envelope format
//!
//! ```text
//! [0..4)   type_tag       u32 LE (deterministic discriminant)
//! [4..8)   payload_len    u32 LE
//! [8..]    payload        payload_len bytes
//! [...]    integrity      4 bytes CRC32C checksum
//! ```
//!
//! Integrity mechanism: CRC32C checksum over (type_tag || payload_len || payload)
//!
//! ## MessageHandler trait contract
//!
//! Handlers receive the session ID and decoded payload. They must be
//! `Send + Sync` for concurrent registration. The `handle` method is
//! synchronous and should return quickly; long-running work should be
//! spawned onto a task.
//!
//! ## Integration with transport session receive path
//!
//! The session receive loop calls [`MessageDispatcher::dispatch()`] after
//! decoding the transport envelope. The dispatcher decodes the message
//! envelope, verifies CRC32C, looks up the handler, and
//! dispatches. Errors are returned as [`DispatchError`] variants for the
//! session to log or surface.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use crate::types::SessionId;

// ---------------------------------------------------------------------------
// Domain-separation constants for message envelope integrity
// ---------------------------------------------------------------------------

/// Minimum envelope size: type_tag (4) + payload_len (4) + CRC32C (4).
const MIN_ENVELOPE_SIZE: usize = 12;

// ---------------------------------------------------------------------------
// MessageType — subsystem message type identifiers
// ---------------------------------------------------------------------------

/// Identifies the subsystem a transport message targets.
///
/// Each known variant carries a deterministic non-cryptographic discriminant
/// used as the 4-byte wire type tag. Unknown discriminants are preserved as
/// [`MessageType::Custom`], enabling forward-compatible extension.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MessageType {
    /// Membership subsystem messages (membership-live, epoch transitions).
    Membership,
    /// Chunk-transfer subsystem messages (state transfer, object shipping).
    ChunkTransfer,
    /// Lease subsystem messages (lease renew/recall/fence).
    Lease,
    /// Flow-control subsystem messages (credit grants, window updates).
    FlowControl,
    /// Committed-roster push messages (passive-peer epoch synchronization).
    RosterPush,
    /// Custom/unknown message type carrying the raw wire discriminant.
    Custom(u32),
}

impl MessageType {
    /// Number of well-known message types.
    pub const KNOWN_COUNT: usize = 5;

    /// Return the list of all well-known message types.
    pub const fn all_known() -> [MessageType; 5] {
        [
            Self::Membership,
            Self::ChunkTransfer,
            Self::Lease,
            Self::FlowControl,
            Self::RosterPush,
        ]
    }

    /// Compute the wire discriminant for this message type.
    ///
    /// Returns a deterministic u32 discriminant.
    #[must_use]
    pub fn discriminant(self) -> u32 {
        let label: &[u8] = match self {
            Self::Membership => b"membership",
            Self::ChunkTransfer => b"chunk-transfer",
            Self::Lease => b"lease",
            Self::FlowControl => b"flow-control",
            Self::RosterPush => b"roster-push",
            Self::Custom(d) => return d,
        };
        compute_msgtype_discriminant(label)
    }

    /// Look up a [`MessageType`] from its wire discriminant.
    ///
    /// Well-known discriminants return their corresponding variant;
    /// unrecognized discriminants return `MessageType::Custom(d)`.
    #[must_use]
    pub fn from_discriminant(d: u32) -> Self {
        for known in Self::all_known() {
            if known.discriminant() == d {
                return known;
            }
        }
        Self::Custom(d)
    }

    /// Human-readable label for this message type.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Membership => "membership",
            Self::ChunkTransfer => "chunk-transfer",
            Self::Lease => "lease",
            Self::FlowControl => "flow-control",
            Self::RosterPush => "roster-push",
            Self::Custom(_) => "custom",
        }
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(d) => write!(f, "custom(0x{d:08x})"),
            other => write!(f, "{}", other.label()),
        }
    }
}

/// Well-known discriminants are assigned as simple const values.
/// Custom discriminants store their value directly.
fn compute_msgtype_discriminant(label: &[u8]) -> u32 {
    match label {
        b"membership" => 1,
        b"chunk-transfer" => 2,
        b"lease" => 3,
        b"flow-control" => 4,
        b"roster-push" => 5,
        _ => {
            // Unknown labels: fall back to a simple non-cryptographic hash
            // so the discriminant is deterministic per label.
            let mut h: u32 = 0x811c9dc5;
            for &b in label {
                h ^= b as u32;
                h = h.wrapping_mul(0x01000193);
            }
            h | 0x8000_0000 // Ensure no collision with well-known values
        }
    }
}

// ---------------------------------------------------------------------------
// DispatchError
// ---------------------------------------------------------------------------

/// Errors that can occur during message dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchError {
    /// The message envelope is too short to contain a valid frame.
    EnvelopeTooShort {
        /// Number of bytes received.
        got: usize,
    },
    /// The CRC32C checksum does not match the payload.
    PayloadVerificationFailed,
    /// The message type discriminant is not recognized.
    UnknownMessageType {
        /// The unrecognized discriminant value.
        discriminant: u32,
    },
    /// The message type is known but no handler is registered for it.
    HandlerNotFound {
        /// The message type that has no handler.
        message_type: MessageType,
    },
    /// The registered handler rejected the message.
    HandlerRejected {
        /// The message type.
        message_type: MessageType,
        /// Optional reason string from the handler.
        reason: String,
    },
}

impl fmt::Display for DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvelopeTooShort { got } => {
                write!(f, "message envelope too short: {got} bytes")
            }
            Self::PayloadVerificationFailed => {
                write!(f, "CRC32C payload verification failed")
            }
            Self::UnknownMessageType { discriminant } => {
                write!(f, "unknown message type discriminant: 0x{discriminant:08x}")
            }
            Self::HandlerNotFound { message_type } => {
                write!(f, "no handler registered for message type: {message_type}")
            }
            Self::HandlerRejected {
                message_type,
                reason,
            } => {
                write!(f, "handler rejected message type {message_type}: {reason}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MessageHandler trait
// ---------------------------------------------------------------------------

/// Trait for handling decoded transport messages within a session context.
///
/// Implementors receive the session ID and decoded payload bytes.
/// Implementations must be `Send + Sync` for concurrent registration.
/// Handlers should return quickly; long-running work must be spawned
/// onto a task.
pub trait MessageHandler: Send + Sync {
    /// Handle an incoming message received on the identified session.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError::HandlerRejected`] if the handler cannot
    /// process the message (malformed payload, wrong state, etc.).
    fn handle(&self, session_id: SessionId, payload: &[u8]) -> Result<(), DispatchError>;
}

// ---------------------------------------------------------------------------
// MessageDispatcher
// ---------------------------------------------------------------------------

/// Registry-based dispatcher that routes incoming transport messages
/// to registered subsystem handlers based on message type discrimination.
///
/// Handlers are stored in a [`HashMap`] keyed by [`MessageType`].
/// Registration requires `&mut self`; dispatch uses `&self`.
pub struct MessageDispatcher {
    handlers: HashMap<MessageType, Arc<dyn MessageHandler>>,
}

impl MessageDispatcher {
    /// Create a new empty message dispatcher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a handler for a given message type.
    ///
    /// If a handler is already registered for this type, it is replaced.
    pub fn register(&mut self, message_type: MessageType, handler: Arc<dyn MessageHandler>) {
        self.handlers.insert(message_type, handler);
    }

    /// Remove a handler for a given message type.
    ///
    /// Returns the removed handler, if any.
    pub fn unregister(&mut self, message_type: MessageType) -> Option<Arc<dyn MessageHandler>> {
        self.handlers.remove(&message_type)
    }

    /// Return the number of registered handlers.
    #[must_use]
    pub fn handler_count(&self) -> usize {
        self.handlers.len()
    }

    /// Return true if a handler is registered for the given message type.
    #[must_use]
    pub fn has_handler(&self, message_type: MessageType) -> bool {
        self.handlers.contains_key(&message_type)
    }

    /// Dispatch an incoming transport message to the appropriate handler.
    ///
    /// The raw transport payload is expected to be a
    /// [`MessageEnvelope`]-encoded frame. This method:
    ///
    /// 1. Decodes the envelope and verifies CRC32C.
    /// 2. Looks up the handler for the decoded message type.
    /// 3. Calls [`MessageHandler::handle`] with the session ID and payload.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError`] on envelope decode failure, unknown message
    /// type, missing handler, or handler rejection.
    pub fn dispatch(&self, session_id: SessionId, raw_payload: &[u8]) -> Result<(), DispatchError> {
        let envelope = MessageEnvelope::decode(raw_payload)?;
        let message_type = MessageType::from_discriminant(envelope.type_tag);

        let handler = self
            .handlers
            .get(&message_type)
            .ok_or(DispatchError::HandlerNotFound { message_type })?;

        handler.handle(session_id, &envelope.payload)
    }
}

impl Default for MessageDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MessageEnvelope — CRC32C-verified wire format
// ---------------------------------------------------------------------------

/// A decoded CRC32C-verified message envelope.
///
/// Carries the message type discriminant, payload bytes, and the
/// CRC32C checksum verified during decode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageEnvelope {
    /// The message type discriminant (u32 LE on wire).
    pub type_tag: u32,
    /// The decoded payload bytes.
    pub payload: Vec<u8>,
    /// The CRC32C checksum (verified on decode).
    pub crc32c: u32,
}

impl MessageEnvelope {
    /// Encode a message type and payload into a CRC32C-verified envelope.
    ///
    /// Returns the wire-format bytes: type_tag (u32 LE) + payload_len (u32 LE)
    /// + payload + CRC32C checksum.
    #[must_use]
    pub fn encode(message_type: MessageType, payload: &[u8]) -> Vec<u8> {
        let type_tag = message_type.discriminant();
        let payload_len = payload.len() as u32;

        let mut buf = Vec::with_capacity(8 + payload.len() + 4);
        buf.extend_from_slice(&type_tag.to_le_bytes());
        buf.extend_from_slice(&payload_len.to_le_bytes());
        buf.extend_from_slice(payload);

        let crc = crc32c::crc32c(&buf);
        buf.extend_from_slice(&crc.to_le_bytes());

        buf
    }

    /// Decode and verify a CRC32C-verified message envelope.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError::EnvelopeTooShort`] if the buffer is too small.
    /// Returns [`DispatchError::PayloadVerificationFailed`] if the CRC32C
    /// checksum does not match.
    pub fn decode(data: &[u8]) -> Result<Self, DispatchError> {
        if data.len() < MIN_ENVELOPE_SIZE {
            return Err(DispatchError::EnvelopeTooShort { got: data.len() });
        }

        let payload_end = data.len() - 4;
        let framed = &data[..payload_end];
        let stored_crc = u32::from_le_bytes(data[payload_end..].try_into().unwrap());

        let expected = crc32c::crc32c(framed);
        if stored_crc != expected {
            return Err(DispatchError::PayloadVerificationFailed);
        }

        if framed.len() < 8 {
            return Err(DispatchError::EnvelopeTooShort { got: data.len() });
        }

        let type_tag = u32::from_le_bytes([framed[0], framed[1], framed[2], framed[3]]);
        let payload_len = u32::from_le_bytes([framed[4], framed[5], framed[6], framed[7]]) as usize;

        if framed.len() < 8 + payload_len {
            return Err(DispatchError::EnvelopeTooShort { got: data.len() });
        }

        let payload = framed[8..8 + payload_len].to_vec();

        Ok(Self {
            type_tag,
            payload,
            crc32c: stored_crc,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // -----------------------------------------------------------------------
    // MessageType discriminant tests
    // -----------------------------------------------------------------------

    #[test]
    fn msgtype_discriminant_deterministic() {
        let d1 = MessageType::Membership.discriminant();
        let d2 = MessageType::Membership.discriminant();
        assert_eq!(d1, d2, "discriminant must be deterministic");
    }

    #[test]
    fn msgtype_discriminant_distinct() {
        let mut seen = Vec::new();
        for known in MessageType::all_known() {
            let d = known.discriminant();
            assert!(
                !seen.contains(&d),
                "discriminant collision for {known:?}: 0x{d:08x}"
            );
            seen.push(d);
        }
    }

    #[test]
    fn msgtype_discriminant_nonzero() {
        for known in MessageType::all_known() {
            assert_ne!(
                known.discriminant(),
                0,
                "discriminant for {known:?} must be non-zero"
            );
        }
    }

    #[test]
    fn msgtype_from_discriminant_round_trip() {
        for known in MessageType::all_known() {
            let d = known.discriminant();
            let recovered = MessageType::from_discriminant(d);
            assert_eq!(recovered, known, "round-trip failed for {known:?}");
        }
    }

    #[test]
    fn msgtype_unknown_discriminant_becomes_custom() {
        // Use a discriminant that shouldn't collide with well-known types
        let unknown = 0xDEAD_BEEF_u32;
        // Make sure it doesn't collide
        for known in MessageType::all_known() {
            assert_ne!(known.discriminant(), unknown);
        }
        let result = MessageType::from_discriminant(unknown);
        assert_eq!(result, MessageType::Custom(unknown));
    }

    #[test]
    fn msgtype_display_known() {
        assert_eq!(format!("{}", MessageType::Membership), "membership");
        assert_eq!(format!("{}", MessageType::ChunkTransfer), "chunk-transfer");
        assert_eq!(format!("{}", MessageType::Lease), "lease");
        assert_eq!(format!("{}", MessageType::FlowControl), "flow-control");
    }

    #[test]
    fn msgtype_display_custom() {
        let custom = MessageType::Custom(0xABCD1234);
        let s = format!("{custom}");
        assert!(s.contains("custom"), "display should include 'custom': {s}");
        assert!(s.contains("abcd1234"), "display should include hex: {s}");
    }

    // -----------------------------------------------------------------------
    // MessageEnvelope encode/decode tests
    // -----------------------------------------------------------------------

    #[test]
    fn envelope_round_trip_membership() {
        let payload = b"membership-epoch-transition-v1";
        let encoded = MessageEnvelope::encode(MessageType::Membership, payload);
        let decoded = MessageEnvelope::decode(&encoded).unwrap();

        assert_eq!(decoded.type_tag, MessageType::Membership.discriminant());
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn envelope_round_trip_empty_payload() {
        let encoded = MessageEnvelope::encode(MessageType::Lease, b"");
        let decoded = MessageEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded.type_tag, MessageType::Lease.discriminant());
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn envelope_round_trip_large_payload() {
        let payload = vec![0xAA_u8; 65536];
        let encoded = MessageEnvelope::encode(MessageType::ChunkTransfer, &payload);
        let decoded = MessageEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded.type_tag, MessageType::ChunkTransfer.discriminant());
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn envelope_round_trip_custom_type() {
        let custom = MessageType::Custom(0x12345678);
        let payload = b"custom-payload";
        let encoded = MessageEnvelope::encode(custom, payload);
        let decoded = MessageEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded.type_tag, 0x12345678);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn envelope_tampered_payload_fails_verification() {
        let payload = b"important-data";
        let mut encoded = MessageEnvelope::encode(MessageType::Membership, payload);

        // Flip a bit in the payload
        let payload_offset = 8; // after type_tag(4) + payload_len(4)
        encoded[payload_offset] ^= 0x01;

        let result = MessageEnvelope::decode(&encoded);
        assert!(
            matches!(result, Err(DispatchError::PayloadVerificationFailed)),
            "tampered payload must fail verification, got: {result:?}"
        );
    }

    #[test]
    fn envelope_tampered_type_tag_fails_verification() {
        let payload = b"important-data";
        let mut encoded = MessageEnvelope::encode(MessageType::Membership, payload);

        // Flip a bit in the type tag
        encoded[0] ^= 0x01;

        let result = MessageEnvelope::decode(&encoded);
        assert!(
            matches!(result, Err(DispatchError::PayloadVerificationFailed)),
            "tampered type tag must fail verification, got: {result:?}"
        );
    }

    #[test]
    fn envelope_tampered_crc32c_fails_verification() {
        let payload = b"important-data";
        let mut encoded = MessageEnvelope::encode(MessageType::Membership, payload);

        // Flip a bit in the CRC32C at the end
        let last = encoded.len() - 1;
        encoded[last] ^= 0x01;

        let result = MessageEnvelope::decode(&encoded);
        assert!(
            matches!(result, Err(DispatchError::PayloadVerificationFailed)),
            "tampered CRC32C must fail verification, got: {result:?}"
        );
    }

    #[test]
    fn envelope_too_short_rejected() {
        let result = MessageEnvelope::decode(&[0u8; 10]);
        assert!(
            matches!(result, Err(DispatchError::EnvelopeTooShort { .. })),
            "short buffer must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn envelope_deterministic_encoding() {
        let payload = b"deterministic-test";
        let enc1 = MessageEnvelope::encode(MessageType::Membership, payload);
        let enc2 = MessageEnvelope::encode(MessageType::Membership, payload);
        assert_eq!(enc1, enc2);
    }

    #[test]
    fn envelope_different_types_produce_different_frames() {
        let payload = b"same-payload";
        let enc1 = MessageEnvelope::encode(MessageType::Membership, payload);
        let enc2 = MessageEnvelope::encode(MessageType::Lease, payload);
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn envelope_different_payloads_produce_different_frames() {
        let enc1 = MessageEnvelope::encode(MessageType::Membership, b"payload-a");
        let enc2 = MessageEnvelope::encode(MessageType::Membership, b"payload-b");
        assert_ne!(enc1, enc2);
    }

    // -----------------------------------------------------------------------
    // MessageDispatcher tests
    // -----------------------------------------------------------------------

    /// A simple test handler that records invocations.
    struct RecordingHandler {
        calls: Mutex<Vec<(SessionId, Vec<u8>)>>,
        reject: Mutex<bool>,
    }

    impl RecordingHandler {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                reject: Mutex::new(false),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }

        fn last_call(&self) -> Option<(SessionId, Vec<u8>)> {
            self.calls.lock().unwrap().last().cloned()
        }

        fn set_reject(&self, reject: bool) {
            *self.reject.lock().unwrap() = reject;
        }
    }

    impl MessageHandler for RecordingHandler {
        fn handle(&self, session_id: SessionId, payload: &[u8]) -> Result<(), DispatchError> {
            if *self.reject.lock().unwrap() {
                return Err(DispatchError::HandlerRejected {
                    message_type: MessageType::Membership,
                    reason: "test rejection".into(),
                });
            }
            self.calls
                .lock()
                .unwrap()
                .push((session_id, payload.to_vec()));
            Ok(())
        }
    }

    #[test]
    fn dispatcher_new_is_empty() {
        let d = MessageDispatcher::new();
        assert_eq!(d.handler_count(), 0);
    }

    #[test]
    fn dispatcher_register_and_dispatch() {
        let mut d = MessageDispatcher::new();
        let handler = Arc::new(RecordingHandler::new());

        d.register(MessageType::Membership, handler.clone());

        assert_eq!(d.handler_count(), 1);
        assert!(d.has_handler(MessageType::Membership));

        let payload = b"test-membership-msg";
        let encoded = MessageEnvelope::encode(MessageType::Membership, payload);
        let sid = SessionId::new(42);

        d.dispatch(sid, &encoded).unwrap();

        assert_eq!(handler.call_count(), 1);
        let (recv_sid, recv_payload) = handler.last_call().unwrap();
        assert_eq!(recv_sid, sid);
        assert_eq!(recv_payload, payload);
    }

    #[test]
    fn dispatcher_handler_not_found() {
        let d = MessageDispatcher::new();
        let encoded = MessageEnvelope::encode(MessageType::Lease, b"lease-msg");
        let result = d.dispatch(SessionId::new(1), &encoded);

        assert!(
            matches!(
                result,
                Err(DispatchError::HandlerNotFound {
                    message_type: MessageType::Lease
                })
            ),
            "expected HandlerNotFound, got: {result:?}"
        );
    }

    #[test]
    fn dispatcher_payload_verification_failed() {
        let mut d = MessageDispatcher::new();
        let handler = Arc::new(RecordingHandler::new());
        d.register(MessageType::Membership, handler);

        let mut encoded = MessageEnvelope::encode(MessageType::Membership, b"data");
        encoded[8] ^= 0xFF; // tamper with payload
        let result = d.dispatch(SessionId::new(1), &encoded);

        assert!(
            matches!(result, Err(DispatchError::PayloadVerificationFailed)),
            "expected PayloadVerificationFailed, got: {result:?}"
        );
    }

    #[test]
    fn dispatcher_handler_rejected() {
        let mut d = MessageDispatcher::new();
        let handler = Arc::new(RecordingHandler::new());
        handler.set_reject(true);
        d.register(MessageType::Membership, handler);

        let encoded = MessageEnvelope::encode(MessageType::Membership, b"data");
        let result = d.dispatch(SessionId::new(1), &encoded);

        assert!(
            matches!(result, Err(DispatchError::HandlerRejected { .. })),
            "expected HandlerRejected, got: {result:?}"
        );
    }

    #[test]
    fn dispatcher_multiple_handlers() {
        let mut d = MessageDispatcher::new();
        let mem_handler = Arc::new(RecordingHandler::new());
        let lease_handler = Arc::new(RecordingHandler::new());
        let chunk_handler = Arc::new(RecordingHandler::new());

        d.register(MessageType::Membership, mem_handler.clone());
        d.register(MessageType::Lease, lease_handler.clone());
        d.register(MessageType::ChunkTransfer, chunk_handler.clone());

        assert_eq!(d.handler_count(), 3);

        // Dispatch to each and verify correct routing
        d.dispatch(
            SessionId::new(1),
            &MessageEnvelope::encode(MessageType::Membership, b"m1"),
        )
        .unwrap();
        d.dispatch(
            SessionId::new(2),
            &MessageEnvelope::encode(MessageType::Lease, b"l1"),
        )
        .unwrap();
        d.dispatch(
            SessionId::new(3),
            &MessageEnvelope::encode(MessageType::ChunkTransfer, b"c1"),
        )
        .unwrap();

        assert_eq!(mem_handler.call_count(), 1);
        assert_eq!(lease_handler.call_count(), 1);
        assert_eq!(chunk_handler.call_count(), 1);

        assert_eq!(mem_handler.last_call().unwrap().1, b"m1".to_vec());
        assert_eq!(lease_handler.last_call().unwrap().1, b"l1".to_vec());
        assert_eq!(chunk_handler.last_call().unwrap().1, b"c1".to_vec());
    }

    #[test]
    fn dispatcher_unregister() {
        let mut d = MessageDispatcher::new();
        let handler = Arc::new(RecordingHandler::new());
        d.register(MessageType::Membership, handler);

        assert_eq!(d.handler_count(), 1);

        let removed = d.unregister(MessageType::Membership);
        assert!(removed.is_some());
        assert_eq!(d.handler_count(), 0);
        assert!(!d.has_handler(MessageType::Membership));

        // Dispatch after unregister should fail
        let encoded = MessageEnvelope::encode(MessageType::Membership, b"data");
        let result = d.dispatch(SessionId::new(1), &encoded);
        assert!(matches!(result, Err(DispatchError::HandlerNotFound { .. })));
    }

    #[test]
    fn dispatcher_unregister_nonexistent() {
        let mut d = MessageDispatcher::new();
        let removed = d.unregister(MessageType::Lease);
        assert!(removed.is_none());
    }

    #[test]
    fn dispatcher_replace_handler() {
        let mut d = MessageDispatcher::new();
        let h1 = Arc::new(RecordingHandler::new());
        let h2 = Arc::new(RecordingHandler::new());

        d.register(MessageType::Membership, h1.clone());
        d.register(MessageType::Membership, h2.clone());

        // h1 should have been replaced; dispatching goes to h2
        let encoded = MessageEnvelope::encode(MessageType::Membership, b"data");
        d.dispatch(SessionId::new(1), &encoded).unwrap();

        assert_eq!(
            h1.call_count(),
            0,
            "replaced handler should not receive calls"
        );
        assert_eq!(h2.call_count(), 1);
    }

    #[test]
    fn dispatcher_default_constructs_empty() {
        let d = MessageDispatcher::default();
        assert_eq!(d.handler_count(), 0);
    }

    // -----------------------------------------------------------------------
    // DispatchError Display tests
    // -----------------------------------------------------------------------

    #[test]
    fn dispatch_error_display_envelope_too_short() {
        let e = DispatchError::EnvelopeTooShort { got: 10 };
        let s = format!("{e}");
        assert!(s.contains("too short"));
        assert!(s.contains("10"));
    }

    #[test]
    fn dispatch_error_display_payload_verification_failed() {
        let e = DispatchError::PayloadVerificationFailed;
        let s = format!("{e}");
        assert!(s.contains("verification"));
    }

    #[test]
    fn dispatch_error_display_unknown_message_type() {
        let e = DispatchError::UnknownMessageType {
            discriminant: 0xDEAD,
        };
        let s = format!("{e}");
        assert!(s.contains("unknown"));
        assert!(s.contains("dead"));
    }

    #[test]
    fn dispatch_error_display_handler_not_found() {
        let e = DispatchError::HandlerNotFound {
            message_type: MessageType::Lease,
        };
        let s = format!("{e}");
        assert!(s.contains("no handler"));
        assert!(s.contains("lease"));
    }

    #[test]
    fn dispatch_error_display_handler_rejected() {
        let e = DispatchError::HandlerRejected {
            message_type: MessageType::Membership,
            reason: "bad state".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("rejected"));
        assert!(s.contains("membership"));
        assert!(s.contains("bad state"));
    }
}
