//! Membership roster-gated session establishment with epoch-version exchange.
//!
//! [`SessionEstablishment`] sits at the transport ingress edge after the
//! Hello/HelloAck handshake ([`crate::connection_init`]) completes but before
//! the connection enters normal message dispatch. It performs two checks:
//!
//! 1. **Roster verification**: queries the membership roster via a
//!    [`tidefs_membership_epoch::roster_verifier::MembershipRosterVerifier`]
//!    to confirm the connecting peer is a current member.
//! 2. **Epoch-version exchange**: after verification, both sides exchange
//!    their current committed epoch numbers via
//!    [`tidefs_membership_epoch::epoch_version_exchange::EpochVersionMessage`]
//!    and compare to detect divergence.
//!
//! # Flow
//!
//! ```text
//! Responder (accept side, after Hello received)
//!      │
//!      │ peer_id = hello.node_id
//!      │
//!      ├── verifier.is_member(peer_id)? ──► reject if not member
//!      │
//!      ├── send EpochVersionMessage(local_epoch) ──► initiator
//!      │
//!      ├── recv EpochVersionMessage(remote_epoch) ◄── initiator
//!      │
//!      ├── outcome = EpochVersionExchangeOutcome::evaluate(remote, local)
//!      │
//!      ▼
//!   proceed or flag catch-up
//! ```
//!
//! The initiator performs the symmetric exchange after receiving HelloAck.
//!
//! # Wire format
//!
//! Epoch-version messages are serialized with bincode and wrapped in the
//! existing [`crate::codec::MessageCodec`] wire format using
//! [`crate::envelope::MessageFamily::HelloClose`] as the family discriminant
//! (same family as the connection handshake).

use std::sync::Arc;

use crate::addr::TransportAddr;
use crate::codec::MessageCodec;
use crate::envelope::MessageFamily;
use crate::peer_address_registry::PeerAddressRegistry;
use tidefs_membership_epoch::epoch_version_exchange::{
    EpochVersionExchangeOutcome, EpochVersionMessage,
};
use tidefs_membership_epoch::roster_verifier::MembershipRosterVerifier;
use tidefs_membership_epoch::MemberId;

// ---------------------------------------------------------------------------
// SessionEstablishmentError
// ---------------------------------------------------------------------------

/// Errors that can occur during session establishment.
#[derive(Debug, thiserror::Error)]
pub enum SessionEstablishmentError {
    /// The connecting peer is not a member of the current roster.
    #[error("peer {peer_id} is not a member of the current roster")]
    NotAMember { peer_id: u64 },

    /// Failed to serialize the epoch-version message.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Failed to read or write a frame on the connection.
    #[error("I/O error: {0}")]
    Io(String),

    /// Failed to deserialize the remote peer's epoch-version message.
    #[error("deserialization error: {0}")]
    Deserialization(String),
}

// ---------------------------------------------------------------------------
// SessionEstablishmentOutcome
// ---------------------------------------------------------------------------

/// The result of a successful session establishment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionEstablishmentOutcome {
    /// The admitted peer's node identifier.
    pub peer_id: u64,
    /// The local node's current committed epoch at establishment time.
    pub local_epoch: u64,
    /// The remote peer's current committed epoch (received during exchange).
    pub remote_epoch: u64,
    /// The result of comparing local and remote epochs.
    pub epoch_outcome: EpochVersionExchangeOutcome,
}

impl SessionEstablishmentOutcome {
    /// Returns `true` if both peers are at the same epoch.
    #[must_use]
    pub fn is_in_sync(&self) -> bool {
        self.epoch_outcome.is_in_sync()
    }

    /// Returns `true` if the local node is behind and needs catch-up.
    #[must_use]
    pub fn local_needs_catchup(&self) -> bool {
        self.epoch_outcome.local_needs_catchup()
    }

    /// Returns `true` if the remote peer is behind and should be flagged.
    #[must_use]
    pub fn remote_needs_catchup(&self) -> bool {
        self.epoch_outcome.remote_needs_catchup()
    }
}

// ---------------------------------------------------------------------------
// SessionEstablishment
// ---------------------------------------------------------------------------

/// Membership roster-gated session establishment hook.
///
/// Holds a roster verifier and a message codec. The
/// [`establish_responder`](Self::establish_responder) method is called on the
/// accept side after the Hello/HelloAck handshake produces a peer identity.
/// The [`establish_initiator`](Self::establish_initiator) method is called on
/// the connect side after receiving the HelloAck.
pub struct SessionEstablishment {
    verifier: Box<dyn MembershipRosterVerifier>,
    codec: MessageCodec,
    /// Optional peer address registry for outbound connection address
    /// resolution. When present, callers can use
    /// [`resolve_peer_address`](Self::resolve_peer_address) to look up
    /// a peer's endpoint addresses before initiating a connection.
    address_registry: Option<Arc<PeerAddressRegistry>>,
}

impl SessionEstablishment {
    /// Create a new session establishment hook.
    #[must_use]
    pub fn new(verifier: Box<dyn MembershipRosterVerifier>, codec: MessageCodec) -> Self {
        Self {
            verifier,
            codec,
            address_registry: None,
        }
    }

    /// Attach a peer address registry for outbound connection address
    /// resolution.
    ///
    /// When set, [`resolve_peer_address`](Self::resolve_peer_address)
    /// can look up a peer's transport endpoint addresses before
    /// initiating an outbound connection. The registry is typically
    /// shared with [`MembershipTransportBridge`] so both components
    /// operate on the same address set.
    #[must_use]
    pub fn with_address_registry(mut self, registry: Arc<PeerAddressRegistry>) -> Self {
        self.address_registry = Some(registry);
        self
    }

    /// Resolve a peer's node identity to its registered transport
    /// endpoint addresses.
    ///
    /// Returns [`None`] if no address registry is attached or if the
    /// peer has no registered addresses. An empty [`Vec`] means the
    /// peer is registered but no addresses are known yet.
    #[must_use]
    pub fn resolve_peer_address(&self, peer_id: MemberId) -> Option<Vec<TransportAddr>> {
        self.address_registry.as_ref()?.lookup(peer_id)
    }

    /// Return the current local epoch from the roster verifier.
    #[must_use]
    pub fn local_epoch(&self) -> u64 {
        self.verifier.current_epoch()
    }

    /// Perform roster verification and epoch-version exchange on the
    /// responder (accept) side.
    ///
    /// Called after the handshake has produced the peer's node identity.
    ///
    /// # Arguments
    ///
    /// * `peer_id` — The connecting peer's node identity from the handshake.
    /// * `write_frame` — Function to write a framed message to the connection.
    /// * `read_frame` — Function to read a framed message from the connection.
    ///
    /// # Errors
    ///
    /// Returns [`SessionEstablishmentError::NotAMember`] if the peer is not
    /// in the roster.
    pub fn establish_responder(
        &self,
        peer_id: u64,
        write_frame: &mut dyn FnMut(&[u8]) -> Result<(), String>,
        read_frame: &mut dyn FnMut() -> Result<Vec<u8>, String>,
    ) -> Result<SessionEstablishmentOutcome, SessionEstablishmentError> {
        let member_id = MemberId::new(peer_id);
        if !self.verifier.is_member(member_id) {
            return Err(SessionEstablishmentError::NotAMember { peer_id });
        }

        let local_epoch = self.verifier.current_epoch();
        self.send_epoch_version(local_epoch, write_frame)?;
        let remote_epoch = self.receive_epoch_version(read_frame)?;
        let epoch_outcome = EpochVersionExchangeOutcome::evaluate(remote_epoch, local_epoch);

        Ok(SessionEstablishmentOutcome {
            peer_id,
            local_epoch,
            remote_epoch,
            epoch_outcome,
        })
    }

    /// Perform roster verification and epoch-version exchange on the
    /// initiator (connect) side.
    ///
    /// Called after receiving the HelloAck. The initiator reads the
    /// responder's epoch first, then sends its own.
    pub fn establish_initiator(
        &self,
        peer_id: u64,
        write_frame: &mut dyn FnMut(&[u8]) -> Result<(), String>,
        read_frame: &mut dyn FnMut() -> Result<Vec<u8>, String>,
    ) -> Result<SessionEstablishmentOutcome, SessionEstablishmentError> {
        let member_id = MemberId::new(peer_id);
        if !self.verifier.is_member(member_id) {
            return Err(SessionEstablishmentError::NotAMember { peer_id });
        }

        let local_epoch = self.verifier.current_epoch();
        let remote_epoch = self.receive_epoch_version(read_frame)?;
        self.send_epoch_version(local_epoch, write_frame)?;
        let epoch_outcome = EpochVersionExchangeOutcome::evaluate(remote_epoch, local_epoch);

        Ok(SessionEstablishmentOutcome {
            peer_id,
            local_epoch,
            remote_epoch,
            epoch_outcome,
        })
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    fn send_epoch_version(
        &self,
        epoch: u64,
        write_frame: &mut dyn FnMut(&[u8]) -> Result<(), String>,
    ) -> Result<(), SessionEstablishmentError> {
        let msg = EpochVersionMessage::new(epoch);
        let payload = bincode::serialize(&msg)
            .map_err(|e| SessionEstablishmentError::Serialization(e.to_string()))?;
        let frame = self
            .codec
            .encode(MessageFamily::HelloClose, &payload)
            .map_err(|e| SessionEstablishmentError::Serialization(e.to_string()))?;
        write_frame(&frame).map_err(SessionEstablishmentError::Io)
    }

    fn receive_epoch_version(
        &self,
        read_frame: &mut dyn FnMut() -> Result<Vec<u8>, String>,
    ) -> Result<u64, SessionEstablishmentError> {
        let frame = read_frame().map_err(SessionEstablishmentError::Io)?;
        let (_family, payload) = self
            .codec
            .decode(&frame)
            .map_err(|e| SessionEstablishmentError::Deserialization(e.to_string()))?;
        let msg: EpochVersionMessage = bincode::deserialize(&payload)
            .map_err(|e| SessionEstablishmentError::Deserialization(e.to_string()))?;
        Ok(msg.epoch_number)
    }
}

impl std::fmt::Debug for SessionEstablishment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionEstablishment")
            .field("local_epoch", &self.verifier.current_epoch())
            .field("has_address_registry", &self.address_registry.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashSet;

    // ---- Mock verifier ----

    struct MockVerifier {
        members: HashSet<u64>,
        epoch: u64,
    }

    impl MockVerifier {
        fn new(members: &[u64], epoch: u64) -> Self {
            Self {
                members: members.iter().copied().collect(),
                epoch,
            }
        }
    }

    impl MembershipRosterVerifier for MockVerifier {
        fn is_member(&self, peer_id: MemberId) -> bool {
            self.members.contains(&peer_id.0)
        }

        fn current_epoch(&self) -> u64 {
            self.epoch
        }
    }

    fn make_establishment(members: &[u64], epoch: u64) -> SessionEstablishment {
        SessionEstablishment::new(
            Box::new(MockVerifier::new(members, epoch)),
            MessageCodec::default(),
        )
    }

    // ---- InMemoryChannel with RefCell for shared mutable access ----

    struct InMemoryChannel {
        buffer: RefCell<Vec<u8>>,
    }

    impl InMemoryChannel {
        fn new() -> Self {
            Self {
                buffer: RefCell::new(Vec::new()),
            }
        }

        fn write_frame(&self, data: &[u8]) -> Result<(), String> {
            let len = (data.len() as u32).to_be_bytes();
            self.buffer.borrow_mut().extend_from_slice(&len);
            self.buffer.borrow_mut().extend_from_slice(data);
            Ok(())
        }

        fn read_frame(&self) -> Result<Vec<u8>, String> {
            let mut buf = self.buffer.borrow_mut();
            if buf.len() < 4 {
                return Err("buffer empty".to_string());
            }
            let mut len_bytes = [0u8; 4];
            len_bytes.copy_from_slice(&buf[..4]);
            let len = u32::from_be_bytes(len_bytes) as usize;
            if buf.len() < 4 + len {
                return Err("buffer too short".to_string());
            }
            let payload = buf[4..4 + len].to_vec();
            buf.drain(..4 + len);
            Ok(payload)
        }
    }

    type WriteFn<'a> = Box<dyn FnMut(&[u8]) -> Result<(), String> + 'a>;
    type ReadFn<'a> = Box<dyn FnMut() -> Result<Vec<u8>, String> + 'a>;

    fn make_write_read(channel: &InMemoryChannel) -> (WriteFn<'_>, ReadFn<'_>) {
        let write_fn = Box::new(|data: &[u8]| channel.write_frame(data));
        let read_fn = Box::new(|| channel.read_frame());
        (write_fn, read_fn)
    }

    // ---- Roster verification ----

    #[test]
    fn responder_accepts_member_peer() {
        let est = make_establishment(&[1, 2, 3], 5);
        let channel = InMemoryChannel::new();

        let remote_msg = EpochVersionMessage::new(5);
        let remote_payload = bincode::serialize(&remote_msg).unwrap();
        let remote_frame = est
            .codec
            .encode(MessageFamily::HelloClose, &remote_payload)
            .unwrap();
        channel.write_frame(&remote_frame).unwrap();

        let (mut write_fn, mut read_fn) = make_write_read(&channel);
        let outcome = est
            .establish_responder(2, &mut write_fn, &mut read_fn)
            .unwrap();
        assert_eq!(outcome.peer_id, 2);
        assert_eq!(outcome.local_epoch, 5);
        assert_eq!(outcome.remote_epoch, 5);
        assert!(outcome.is_in_sync());
    }

    #[test]
    fn responder_rejects_non_member() {
        let est = make_establishment(&[1, 2], 5);
        let channel = InMemoryChannel::new();
        let (mut write_fn, mut read_fn) = make_write_read(&channel);

        let err = est
            .establish_responder(99, &mut write_fn, &mut read_fn)
            .unwrap_err();
        match err {
            SessionEstablishmentError::NotAMember { peer_id } => assert_eq!(peer_id, 99),
            _ => panic!("expected NotAMember, got {err:?}"),
        }
    }

    #[test]
    fn responder_empty_roster_rejects_all() {
        let est = make_establishment(&[], 0);
        let channel = InMemoryChannel::new();
        let (mut write_fn, mut read_fn) = make_write_read(&channel);

        let err = est
            .establish_responder(1, &mut write_fn, &mut read_fn)
            .unwrap_err();
        assert!(matches!(err, SessionEstablishmentError::NotAMember { .. }));
    }

    // ---- Epoch-version exchange ----

    #[test]
    fn responder_detects_remote_behind() {
        let est = make_establishment(&[1, 2], 7);
        let channel = InMemoryChannel::new();

        let remote_msg = EpochVersionMessage::new(3);
        let remote_payload = bincode::serialize(&remote_msg).unwrap();
        let remote_frame = est
            .codec
            .encode(MessageFamily::HelloClose, &remote_payload)
            .unwrap();
        channel.write_frame(&remote_frame).unwrap();

        let (mut write_fn, mut read_fn) = make_write_read(&channel);
        let outcome = est
            .establish_responder(2, &mut write_fn, &mut read_fn)
            .unwrap();
        assert_eq!(outcome.remote_epoch, 3);
        assert_eq!(outcome.local_epoch, 7);
        assert!(outcome.remote_needs_catchup());
        assert!(!outcome.local_needs_catchup());
    }

    #[test]
    fn responder_detects_local_behind() {
        let est = make_establishment(&[1, 2], 2);
        let channel = InMemoryChannel::new();

        let remote_msg = EpochVersionMessage::new(9);
        let remote_payload = bincode::serialize(&remote_msg).unwrap();
        let remote_frame = est
            .codec
            .encode(MessageFamily::HelloClose, &remote_payload)
            .unwrap();
        channel.write_frame(&remote_frame).unwrap();

        let (mut write_fn, mut read_fn) = make_write_read(&channel);
        let outcome = est
            .establish_responder(1, &mut write_fn, &mut read_fn)
            .unwrap();
        assert_eq!(outcome.remote_epoch, 9);
        assert_eq!(outcome.local_epoch, 2);
        assert!(outcome.local_needs_catchup());
        assert!(!outcome.remote_needs_catchup());
    }

    // ---- Initiator-side ----

    #[test]
    fn initiator_accepts_member() {
        let est = make_establishment(&[10, 20, 30], 4);
        let channel = InMemoryChannel::new();

        let remote_msg = EpochVersionMessage::new(4);
        let remote_payload = bincode::serialize(&remote_msg).unwrap();
        let remote_frame = est
            .codec
            .encode(MessageFamily::HelloClose, &remote_payload)
            .unwrap();
        channel.write_frame(&remote_frame).unwrap();

        let (mut write_fn, mut read_fn) = make_write_read(&channel);
        let outcome = est
            .establish_initiator(20, &mut write_fn, &mut read_fn)
            .unwrap();
        assert_eq!(outcome.peer_id, 20);
        assert_eq!(outcome.local_epoch, 4);
        assert_eq!(outcome.remote_epoch, 4);
        assert!(outcome.is_in_sync());
    }

    #[test]
    fn initiator_rejects_non_member() {
        let est = make_establishment(&[1], 5);
        let channel = InMemoryChannel::new();
        let (mut write_fn, mut read_fn) = make_write_read(&channel);

        let err = est
            .establish_initiator(999, &mut write_fn, &mut read_fn)
            .unwrap_err();
        assert!(matches!(
            err,
            SessionEstablishmentError::NotAMember { peer_id: 999 }
        ));
    }

    #[test]
    fn initiator_detects_epoch_divergence() {
        let est = make_establishment(&[1, 2, 3], 10);
        let channel = InMemoryChannel::new();

        let remote_msg = EpochVersionMessage::new(5);
        let remote_payload = bincode::serialize(&remote_msg).unwrap();
        let remote_frame = est
            .codec
            .encode(MessageFamily::HelloClose, &remote_payload)
            .unwrap();
        channel.write_frame(&remote_frame).unwrap();

        let (mut write_fn, mut read_fn) = make_write_read(&channel);
        let outcome = est
            .establish_initiator(3, &mut write_fn, &mut read_fn)
            .unwrap();
        assert!(outcome.remote_needs_catchup());
    }

    // ---- Debug output ----

    #[test]
    fn debug_output_includes_epoch() {
        let est = make_establishment(&[1], 42);
        let s = format!("{est:?}");
        assert!(s.contains("SessionEstablishment"));
    }

    // ---- Outcome helpers ----

    #[test]
    fn outcome_is_in_sync() {
        let outcome = SessionEstablishmentOutcome {
            peer_id: 1,
            local_epoch: 5,
            remote_epoch: 5,
            epoch_outcome: EpochVersionExchangeOutcome::InSync,
        };
        assert!(outcome.is_in_sync());
        assert!(!outcome.local_needs_catchup());
        assert!(!outcome.remote_needs_catchup());
    }

    #[test]
    fn outcome_local_behind() {
        let outcome = SessionEstablishmentOutcome {
            peer_id: 1,
            local_epoch: 3,
            remote_epoch: 7,
            epoch_outcome: EpochVersionExchangeOutcome::LocalBehind {
                remote_epoch: 7,
                local_epoch: 3,
            },
        };
        assert!(!outcome.is_in_sync());
        assert!(outcome.local_needs_catchup());
        assert!(!outcome.remote_needs_catchup());
    }

    #[test]
    fn outcome_remote_behind() {
        let outcome = SessionEstablishmentOutcome {
            peer_id: 1,
            local_epoch: 7,
            remote_epoch: 3,
            epoch_outcome: EpochVersionExchangeOutcome::RemoteBehind {
                remote_epoch: 3,
                local_epoch: 7,
            },
        };
        assert!(outcome.remote_needs_catchup());
        assert!(!outcome.local_needs_catchup());
    }

    // ---- local_epoch accessor ----

    #[test]
    fn local_epoch_matches_verifier() {
        let est = make_establishment(&[1], 99);
        assert_eq!(est.local_epoch(), 99);
    }

    // ---- Epoch version message round-trip in frame ----

    #[test]
    fn epoch_version_frame_round_trip() {
        let est = make_establishment(&[1, 2], 8);
        let responder_channel = InMemoryChannel::new();
        let initiator_channel = InMemoryChannel::new();

        let init_msg = EpochVersionMessage::new(6);
        let init_payload = bincode::serialize(&init_msg).unwrap();
        let init_frame = est
            .codec
            .encode(MessageFamily::HelloClose, &init_payload)
            .unwrap();
        responder_channel.write_frame(&init_frame).unwrap();

        let mut responder_write = |data: &[u8]| initiator_channel.write_frame(data);
        let mut responder_read = || responder_channel.read_frame();

        let resp_outcome = est
            .establish_responder(2, &mut responder_write, &mut responder_read)
            .unwrap();
        assert_eq!(resp_outcome.local_epoch, 8);
        assert_eq!(resp_outcome.remote_epoch, 6);
        assert!(resp_outcome.remote_needs_catchup());

        let resp_frame = initiator_channel.read_frame().unwrap();
        let (_family, payload) = est.codec.decode(&resp_frame).unwrap();
        let resp_msg: EpochVersionMessage = bincode::deserialize(&payload).unwrap();
        assert_eq!(resp_msg.epoch_number, 8);
    }
}
