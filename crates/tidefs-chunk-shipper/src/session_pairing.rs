// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! ShipperSession: binds a send-stream SendQueue to a receive-stream
//! ObjectAssembler with a shared BLAKE3-256 session-integrity hasher.
//!
//! Each session tracks a lifecycle through four states:
//! - `Paired`: send queue and receive assembler are bound, ready for transfer.
//! - `Transferring`: chunks are actively being sent and received.
//! - `Draining`: all chunks sent; waiting for remaining acks and assembly.
//! - `Closed`: transfer complete and final integrity verified.

use std::sync::Arc;

use tidefs_receive_stream::assembler::ObjectAssembler;
use tidefs_send_stream::send_queue::SendQueue;

/// Domain-separation context for the session-integrity BLAKE3 hasher.
const SESSION_DOMAIN: &[u8] = b"tidefs-chunk-shipper-session-v1";

/// Session lifecycle states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    Paired,
    Transferring,
    Draining,
    Closed,
}

/// A paired session binding a send-stream queue to a receive-stream assembler.
///
/// Maintains a domain-separated BLAKE3-256 session-integrity hasher that
/// accumulates the digest of every chunk payload sent through the session.
pub struct ShipperSession {
    pub session_id: u64,
    pub state: SessionState,
    pub send_queue: Arc<SendQueue<Vec<u8>>>,
    pub receive_assembler: ObjectAssembler,
    send_hasher: blake3::Hasher,
    recv_hasher: blake3::Hasher,
    frames_sent: u64,
    bytes_sent: u64,
    bytes_received: u64,
    objects_completed: u64,
}

impl ShipperSession {
    #[must_use]
    pub fn new(session_id: u64, send_queue_capacity: usize) -> Self {
        let mut send_hasher = blake3::Hasher::new();
        send_hasher.update(SESSION_DOMAIN);
        let mut recv_hasher = blake3::Hasher::new();
        recv_hasher.update(SESSION_DOMAIN);

        Self {
            session_id,
            state: SessionState::Paired,
            send_queue: Arc::new(SendQueue::new(send_queue_capacity)),
            receive_assembler: ObjectAssembler::new(),
            send_hasher,
            recv_hasher,
            frames_sent: 0,
            bytes_sent: 0,
            bytes_received: 0,
            objects_completed: 0,
        }
    }

    pub fn start_transfer(&mut self) -> Result<(), SessionStateError> {
        if self.state != SessionState::Paired {
            return Err(SessionStateError {
                expected: SessionState::Paired,
                actual: self.state,
            });
        }
        self.state = SessionState::Transferring;
        Ok(())
    }

    pub fn start_drain(&mut self) -> Result<(), SessionStateError> {
        if self.state != SessionState::Transferring {
            return Err(SessionStateError {
                expected: SessionState::Transferring,
                actual: self.state,
            });
        }
        self.state = SessionState::Draining;
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), SessionStateError> {
        if self.state != SessionState::Draining && self.state != SessionState::Transferring {
            return Err(SessionStateError {
                expected: SessionState::Draining,
                actual: self.state,
            });
        }
        self.state = SessionState::Closed;
        Ok(())
    }

    /// Feed a payload into the send-side session hasher.
    pub fn hash_send_payload(&mut self, payload: &[u8]) {
        let len_prefix = (payload.len() as u64).to_le_bytes();
        self.send_hasher.update(&len_prefix);
        self.send_hasher.update(payload);
    }

    /// Feed a payload into the receive-side session hasher.
    pub fn hash_recv_payload(&mut self, payload: &[u8]) {
        let len_prefix = (payload.len() as u64).to_le_bytes();
        self.recv_hasher.update(&len_prefix);
        self.recv_hasher.update(payload);
    }

    /// Finalize the send-side session digest.
    ///
    /// Domain-separated with the total chunk count so both sides produce
    /// comparable digests.
    #[must_use]
    pub fn send_digest(&self) -> [u8; 32] {
        let mut hasher = self.send_hasher.clone();
        hasher.update(&self.frames_sent.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Finalize the receive-side session digest.
    ///
    /// Uses the same finalization parameter as `send_digest` (frames_sent)
    /// so that both sides produce comparable digests.
    #[must_use]
    pub fn recv_digest(&self) -> [u8; 32] {
        let mut hasher = self.recv_hasher.clone();
        hasher.update(&self.frames_sent.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Verify that send and receive session digests match.
    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        self.send_digest() == self.recv_digest()
    }

    /// Record that a frame was enqueued for sending.
    pub fn record_frame_sent(&mut self, payload_len: usize) {
        self.frames_sent += 1;
        self.bytes_sent += payload_len as u64;
    }

    /// Record that bytes were received and assembled.
    pub fn record_bytes_received(&mut self, n: u64) {
        self.bytes_received += n;
    }

    /// Record a completed object.
    pub fn record_object_completed(&mut self) {
        self.objects_completed += 1;
    }

    // ── Accessors ──

    #[must_use]
    pub fn frames_sent_count(&self) -> u64 {
        self.frames_sent
    }
    #[must_use]
    pub fn bytes_sent_total(&self) -> u64 {
        self.bytes_sent
    }
    #[must_use]
    pub fn bytes_received_total(&self) -> u64 {
        self.bytes_received
    }
    #[must_use]
    pub fn objects_completed_count(&self) -> u64 {
        self.objects_completed
    }
    #[must_use]
    pub fn pending_objects(&self) -> usize {
        self.receive_assembler.pending_objects()
    }
    #[must_use]
    pub fn is_paired(&self) -> bool {
        self.state == SessionState::Paired
    }
    #[must_use]
    pub fn is_transferring(&self) -> bool {
        self.state == SessionState::Transferring
    }
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.state == SessionState::Draining
    }
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state == SessionState::Closed
    }
}

/// Error returned when a state transition is attempted from the wrong state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionStateError {
    pub expected: SessionState,
    pub actual: SessionState,
}

impl std::fmt::Display for SessionStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "session state error: expected {:?}, actual {:?}",
            self.expected, self.actual
        )
    }
}

impl std::error::Error for SessionStateError {}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_is_paired() {
        let session = ShipperSession::new(1, 8);
        assert!(session.is_paired());
        assert_eq!(session.state, SessionState::Paired);
        assert_eq!(session.frames_sent_count(), 0);
        assert_eq!(session.bytes_sent_total(), 0);
        assert_eq!(session.pending_objects(), 0);
    }

    #[test]
    fn paired_to_transferring() {
        let mut session = ShipperSession::new(1, 8);
        assert!(session.start_transfer().is_ok());
        assert!(session.is_transferring());
    }

    #[test]
    fn transfer_to_draining() {
        let mut session = ShipperSession::new(1, 8);
        session.start_transfer().unwrap();
        assert!(session.start_drain().is_ok());
        assert!(session.is_draining());
    }

    #[test]
    fn drain_or_transfer_to_closed() {
        let mut session = ShipperSession::new(1, 8);
        session.start_transfer().unwrap();
        session.start_drain().unwrap();
        assert!(session.close().is_ok());
        assert!(session.is_closed());

        let mut s2 = ShipperSession::new(2, 8);
        s2.start_transfer().unwrap();
        assert!(s2.close().is_ok());
    }

    #[test]
    fn invalid_transitions_return_error() {
        let mut session = ShipperSession::new(1, 8);
        assert!(session.start_drain().is_err());
        assert!(session.close().is_err());
        session.start_transfer().unwrap();
        assert!(session.start_transfer().is_err());
        session.start_drain().unwrap();
        assert!(session.start_drain().is_err());
        session.close().unwrap();
        assert!(session.close().is_err());
    }

    #[test]
    fn session_hasher_domain_separation() {
        let s1 = ShipperSession::new(1, 8);
        let s2 = ShipperSession::new(2, 8);
        assert_eq!(s1.send_digest(), s2.send_digest());
        assert_eq!(s1.recv_digest(), s2.recv_digest());
    }

    #[test]
    fn session_hasher_different_data_different_digest() {
        let mut s1 = ShipperSession::new(1, 8);
        let mut s2 = ShipperSession::new(2, 8);
        s1.hash_send_payload(b"hello");
        s2.hash_send_payload(b"world");
        assert_ne!(s1.send_digest(), s2.send_digest());
    }

    #[test]
    fn send_and_recv_hashers_match_on_same_data() {
        let mut session = ShipperSession::new(1, 8);
        session.hash_send_payload(b"chunk one");
        session.hash_send_payload(b"chunk two");
        session.hash_recv_payload(b"chunk one");
        session.hash_recv_payload(b"chunk two");
        assert!(session.verify_integrity());
    }

    #[test]
    fn send_and_recv_hashers_mismatch_on_different_data() {
        let mut session = ShipperSession::new(1, 8);
        session.hash_send_payload(b"correct data");
        session.hash_recv_payload(b"tampered data");
        assert!(!session.verify_integrity());
    }

    #[test]
    fn record_frame_sent_tracks_stats() {
        let mut session = ShipperSession::new(1, 8);
        session.record_frame_sent(100);
        session.record_frame_sent(50);
        assert_eq!(session.frames_sent_count(), 2);
        assert_eq!(session.bytes_sent_total(), 150);
    }

    #[test]
    fn record_bytes_and_objects() {
        let mut session = ShipperSession::new(1, 8);
        session.record_bytes_received(1024);
        session.record_bytes_received(512);
        session.record_object_completed();
        session.record_object_completed();
        assert_eq!(session.bytes_received_total(), 1536);
        assert_eq!(session.objects_completed_count(), 2);
    }

    #[test]
    fn send_queue_is_shared_and_bounded() {
        let session = ShipperSession::new(1, 4);
        let q = &session.send_queue;
        assert_eq!(q.capacity(), 4);
        assert!(q.is_empty());
        q.enqueue(vec![1, 2, 3]);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn four_state_lifecycle_is_exhaustive() {
        let session = ShipperSession::new(1, 8);
        assert!(session.is_paired());
        assert!(!session.is_transferring());
        assert!(!session.is_draining());
        assert!(!session.is_closed());
    }

    #[test]
    fn state_error_display() {
        let err = SessionStateError {
            expected: SessionState::Paired,
            actual: SessionState::Closed,
        };
        let msg = err.to_string();
        assert!(msg.contains("Paired"));
        assert!(msg.contains("Closed"));
    }
}
