// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Membership lease message dispatch for the transport session handler.
//!
//! Routes encoded [`tidefs_cluster::MembershipLeaseMessage`] values through
//! the transport envelope layer using `MessageFamily::LeaseFenceDeadline` (m3)
//! so that incoming membership lease messages can be decoded and routed to
//! the cluster lease runtime, and responses sent back on the same session.
//!
//! ## Integration with transport envelopes
//!
//! Membership lease messages produced by
//! [`tidefs_cluster::MembershipLeaseMessage::encode`] are self-framed with
//! a 1-byte discriminant, bincode payload, and trailing 32-byte BLAKE3
//! digest. The transport layer treats these bytes as opaque payloads
//! carried inside transport envelopes tagged with
//! `MessageFamily::LeaseFenceDeadline`.
//!
//! ## Dispatch flow
//!
//! ```text
//! MembershipLeaseMessage
//!   → encode()              → framed payload bytes
//!   → Transport envelope (m3)   → on-wire frame
//!   → Transport envelope decode → framed payload bytes
//!   → decode()              → MembershipLeaseMessage
//! ```

use crate::envelope::MessageFamily;
use crate::session::Session;
use tidefs_cluster::MembershipLeaseMessage;

// ── Encode/decode ──────────────────────────────────────────────────

/// Encode a [`MembershipLeaseMessage`] into transport-ready payload bytes.
///
/// The returned bytes are the self-framed membership lease message
/// (discriminant + bincode payload + BLAKE3 digest) suitable for wrapping
/// in a transport envelope with `MessageFamily::LeaseFenceDeadline`.
///
/// # Errors
///
/// Returns [`tidefs_cluster::ProtocolError`] if encoding fails.
pub fn encode_membership_lease_message(
    msg: &MembershipLeaseMessage,
) -> Result<Vec<u8>, tidefs_cluster::ProtocolError> {
    msg.encode()
}

/// Decode a transport payload into a [`MembershipLeaseMessage`].
///
/// The payload must be a framed membership lease message as produced by
/// [`encode_membership_lease_message`].
///
/// # Errors
///
/// Returns [`tidefs_cluster::ProtocolError`] if the payload is invalid:
/// bad framing, digest mismatch, or deserialization failure.
pub fn decode_membership_lease_message(
    payload: &[u8],
) -> Result<MembershipLeaseMessage, tidefs_cluster::ProtocolError> {
    MembershipLeaseMessage::decode(payload)
}

/// The [`MessageFamily`] for membership lease messages.
pub const MEMBERSHIP_LEASE_MESSAGE_FAMILY: MessageFamily = MessageFamily::LeaseFenceDeadline;

// ── Session dispatch helpers ───────────────────────────────────────

/// Trait for handling decoded membership lease messages within a
/// transport session context. Implementors (typically the cluster
/// lease runtime) receive decoded messages along with the session
/// they arrived on, enabling responses to be sent back on the same
/// session.
pub trait MembershipLeaseMessageHandler: Send + Sync {
    /// Handle an incoming membership lease message received on the
    /// given session.
    ///
    /// The handler should process the message and may use `session` to
    /// send a response. Implementations must be non-blocking; long-running
    /// work should be spawned onto a task.
    fn handle_membership_lease_message(
        &self,
        session: &mut Session,
        msg: MembershipLeaseMessage,
    ) -> Result<(), tidefs_cluster::ProtocolError>;
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::TransportBackendKind;
    use crate::types::SessionId;
    use crate::TransportAddr;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tidefs_cluster::protocol::{AcquireAck, AcquireRequest, ReleaseRequest, RenewRequest};
    use tidefs_membership_epoch::EpochId;
    use tidefs_types_transport_session::EndpointFamily;

    fn make_session() -> Session {
        Session::new(
            SessionId::new(1),
            10,
            20,
            TransportAddr::Tcp(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                8000,
            )),
            EndpointFamily::LocalEmbed,
            TransportBackendKind::Tcp,
        )
    }

    // ── encode/decode round-trip ───────────────────────────────────

    #[test]
    fn roundtrip_acquire() {
        let msg = MembershipLeaseMessage::Acquire(AcquireRequest {
            node_id: 1,
            epoch: EpochId(5),
            slot: 0,
            lease_term_ms: 30_000,
            request_id: 42,
        });
        let encoded = encode_membership_lease_message(&msg).unwrap();
        let decoded = decode_membership_lease_message(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_acquire_ack() {
        let msg = MembershipLeaseMessage::AcquireAck(AcquireAck {
            request_id: 42,
            lease_id: 100,
            epoch: EpochId(5),
            slot: 0,
            lease_term_ms: 30_000,
            deadline_ms: 30_000,
        });
        let encoded = encode_membership_lease_message(&msg).unwrap();
        let decoded = decode_membership_lease_message(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_renew() {
        let msg = MembershipLeaseMessage::Renew(RenewRequest {
            node_id: 1,
            lease_id: 100,
            epoch: EpochId(5),
        });
        let encoded = encode_membership_lease_message(&msg).unwrap();
        let decoded = decode_membership_lease_message(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_release() {
        let msg = MembershipLeaseMessage::Release(ReleaseRequest {
            node_id: 1,
            lease_id: 100,
            epoch: EpochId(5),
        });
        let encoded = encode_membership_lease_message(&msg).unwrap();
        let decoded = decode_membership_lease_message(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    // ── decode rejects garbage ──────────────────────────────────────

    #[test]
    fn decode_rejects_garbage() {
        let garbage = vec![0xFFu8; 100];
        assert!(decode_membership_lease_message(&garbage).is_err());
    }

    #[test]
    fn decode_rejects_empty() {
        assert!(decode_membership_lease_message(&[]).is_err());
    }

    // ── message family is correct ──────────────────────────────────

    #[test]
    fn membership_lease_message_family_is_m3() {
        assert_eq!(
            MEMBERSHIP_LEASE_MESSAGE_FAMILY,
            MessageFamily::LeaseFenceDeadline
        );
    }

    // ── handler dispatch integration test ─────────────────────────

    struct TestHandler {
        pub received: std::sync::Mutex<Vec<MembershipLeaseMessage>>,
    }

    impl TestHandler {
        fn new() -> Self {
            Self {
                received: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl MembershipLeaseMessageHandler for TestHandler {
        fn handle_membership_lease_message(
            &self,
            _session: &mut Session,
            msg: MembershipLeaseMessage,
        ) -> Result<(), tidefs_cluster::ProtocolError> {
            self.received.lock().unwrap().push(msg);
            Ok(())
        }
    }

    #[test]
    fn handler_receives_decoded_message() {
        let handler = TestHandler::new();
        let mut session = make_session();

        let msg = MembershipLeaseMessage::Renew(RenewRequest {
            node_id: 1,
            lease_id: 100,
            epoch: EpochId(3),
        });

        handler
            .handle_membership_lease_message(&mut session, msg.clone())
            .unwrap();

        let received = handler.received.lock().unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0], msg);
    }
}
