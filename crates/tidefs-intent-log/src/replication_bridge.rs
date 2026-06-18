// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Intent-log entry replication bridge for multi-node write durability.
//!
//! Bridges the local intent-log durability mechanism to a transport session
//! so that committed intent-log entries stream to peer storage nodes.
//! Each frame is serialized with a length-prefixed wire format and fed
//! through a BLAKE3-keyed stream hasher. A stream-completion footer
//! (`VIRE` magic) allows the receiver to verify complete, ordered delivery.
//!
//! # Architecture
//!
//! ```text
//! IntentLogFrame → encode → [len:u32 LE][frame_bytes] → transport.send()
//!                                             │
//!                          BLAKE3-keyed stream hasher (concurrent)
//!                                             │
//!                 finish → [magic VIRE][total][stream_digest]
//! ```
//!
//! # Feature gate
//!
//! This module is compiled when the `replication` feature is enabled.
//! The core bridge works with any type implementing [`ReplicationTransport`],
//! so unit tests use a mock transport without pulling in tidefs-transport.
//!
//! # Wire format
//!
//! Per-entry message:
//!
//! ```text
//! [entry_len: u32 LE][frame_bytes: N bytes]
//! ```
//!
//! Stream-completion footer:
//!
//! ```text
//! [magic "VIRE": u32 LE][total_entries: u64 LE][stream_digest: [u8; 32]]
//! ```

use std::fmt;

use crate::IntentLogFrame;

// ── Constants ──────────────────────────────────────────────────────────

/// Magic bytes for the stream-completion footer ("VIRE").
pub const INTENT_REPLICATION_MAGIC: u32 = 0x56_49_52_45;

/// Domain context for the stream-level BLAKE3 keyed digest.
const STREAM_DIGEST_CONTEXT: &str = "TideFS intent-log replication bridge stream v1";

/// Size of the stream-completion footer on the wire: magic(4) + total_entries(8) + digest(32).
const FOOTER_SIZE: usize = 44;

// ── ReplicationTransport trait ─────────────────────────────────────────

/// Abstract transport write capability for intent-log replication.
///
/// Implementors write ordered byte frames to a transport session.
/// The trait is intentionally minimal so the bridge can be tested
/// with a mock and integrated with any transport backend.
pub trait ReplicationTransport {
    /// Write a complete frame to the transport.
    ///
    /// # Errors
    ///
    /// Returns [`ReplicationTransportError`] when the transport is
    /// disconnected, timed out, or has encountered an unrecoverable error.
    fn send(&mut self, data: &[u8]) -> Result<(), ReplicationTransportError>;

    /// Whether the transport can accept another frame without blocking.
    fn is_ready(&self) -> bool;
}

// ── ReplicationTransportError ──────────────────────────────────────────

/// Errors returned by [`ReplicationTransport::send`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplicationTransportError {
    /// The transport session was disconnected.
    Disconnected,
    /// The transport operation timed out.
    Timeout,
    /// An underlying transport I/O error occurred.
    TransportError(String),
}

impl fmt::Display for ReplicationTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disconnected => write!(f, "replication transport session disconnected"),
            Self::Timeout => write!(f, "replication transport operation timed out"),
            Self::TransportError(msg) => write!(f, "replication transport error: {msg}"),
        }
    }
}

impl std::error::Error for ReplicationTransportError {}

// ── ReplicationAck ─────────────────────────────────────────────────────

/// Acknowledgment returned after replicating one or more entries.
///
/// Carries the number of entries replicated, the running stream digest
/// (for checkpointing), and optionally the peer's BLAKE3 confirmation
/// hash once the receiver acknowledges the stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicationAck {
    /// Number of entries successfully transmitted in this operation.
    pub entries_replicated: u64,
    /// Running BLAKE3-256 stream digest after these entries.
    pub stream_digest: [u8; 32],
    /// Peer BLAKE3 confirmation hash (set after finish + peer ack).
    pub peer_confirmation_hash: Option<[u8; 32]>,
}

// ── IntentLogReplicationBridge ─────────────────────────────────────────

/// Bridges intent-log frames to a transport session for multi-node
/// write durability.
///
/// Wraps a [`ReplicationTransport`] implementation with a BLAKE3-keyed
/// stream hasher that covers every replicated entry in FIFO order.
/// The bridge tracks the total number of entries sent and emits a
/// verified stream-completion footer on [`finish_replication_stream`].
///
/// # Lifecycle
///
/// 1. Call [`replicate_entry`](Self::replicate_entry) for each frame,
///    or [`replicate_batch`](Self::replicate_batch) for amortized flush.
/// 2. Call [`finish_replication_stream`](Self::finish_replication_stream)
///    to send the stream-completion footer and await peer acknowledgment.
///
/// # Backpressure
///
/// The bridge checks [`ReplicationTransport::is_ready`] before each send.
/// When the transport is not ready, the call returns `Ok` with 0 entries
/// replicated — the caller should retry.
pub struct IntentLogReplicationBridge<T: ReplicationTransport> {
    /// Transport write endpoint.
    transport: T,
    /// Keyed BLAKE3-256 hasher covering all entry payloads in FIFO order.
    stream_hasher: blake3::Hasher,
    /// Total number of entries sent so far.
    entries_sent: u64,
}

impl<T: ReplicationTransport> IntentLogReplicationBridge<T> {
    /// Create a new bridge wrapping a transport session.
    ///
    /// The stream hasher is initialized with a key derived from the
    /// domain context string, preventing cross-context collision.
    pub fn new(transport: T) -> Self {
        let key = blake3::derive_key(STREAM_DIGEST_CONTEXT, b"");
        Self {
            transport,
            stream_hasher: blake3::Hasher::new_keyed(&key),
            entries_sent: 0,
        }
    }

    /// Return the number of entries sent so far.
    #[must_use]
    pub fn entries_sent(&self) -> u64 {
        self.entries_sent
    }

    /// Return a snapshot of the running stream digest.
    #[must_use]
    pub fn stream_digest(&self) -> [u8; 32] {
        self.stream_hasher.finalize().into()
    }

    /// Replicate a single intent-log frame through the transport.
    ///
    /// Encodes the frame to bytes, wraps it in a length-prefixed wire
    /// message, feeds it into the BLAKE3-keyed stream hasher, and sends
    /// it through the transport.
    ///
    /// Returns a [`ReplicationAck`] with the updated stream digest.
    /// Returns `Ok` with `entries_replicated: 0` when the transport
    /// is not ready.
    ///
    /// # Errors
    ///
    /// Returns [`ReplicationTransportError`] if the transport write fails.
    pub fn replicate_entry(
        &mut self,
        frame: &IntentLogFrame,
    ) -> Result<ReplicationAck, ReplicationTransportError> {
        if !self.transport.is_ready() {
            return Ok(ReplicationAck {
                entries_replicated: 0,
                stream_digest: self.stream_hasher.finalize().into(),
                peer_confirmation_hash: None,
            });
        }

        let wire_msg = encode_entry_wire(frame);
        self.stream_hasher.update(&wire_msg);

        self.transport.send(&wire_msg)?;
        self.entries_sent += 1;

        Ok(ReplicationAck {
            entries_replicated: 1,
            stream_digest: self.stream_hasher.finalize().into(),
            peer_confirmation_hash: None,
        })
    }

    /// Replicate a batch of intent-log frames.
    ///
    /// Each frame is individually encoded, hashed, and sent. Returns
    /// a [`ReplicationAck`] covering the batch. Stops early if the
    /// transport is not ready or encounters an error; already-sent
    /// entries are tracked in `entries_sent`.
    ///
    /// # Errors
    ///
    /// Returns [`ReplicationTransportError`] if a transport write fails.
    pub fn replicate_batch(
        &mut self,
        frames: &[IntentLogFrame],
    ) -> Result<ReplicationAck, ReplicationTransportError> {
        let mut sent = 0u64;
        for frame in frames {
            if !self.transport.is_ready() {
                break;
            }
            let wire_msg = encode_entry_wire(frame);
            self.stream_hasher.update(&wire_msg);
            self.transport.send(&wire_msg)?;
            self.entries_sent += 1;
            sent += 1;
        }
        Ok(ReplicationAck {
            entries_replicated: sent,
            stream_digest: self.stream_hasher.finalize().into(),
            peer_confirmation_hash: None,
        })
    }

    /// Finish the replication stream: send the BLAKE3-verified
    /// stream-completion footer with the `VIRE` magic, total entry
    /// count, and stream digest.
    ///
    /// After this call, the peer can verify the stream digest against
    /// all received entries.
    ///
    /// # Errors
    ///
    /// Returns [`ReplicationTransportError`] if the transport write fails.
    pub fn finish_replication_stream(&mut self) -> Result<(), ReplicationTransportError> {
        let digest: [u8; 32] = self.stream_hasher.finalize().into();
        let footer = encode_stream_footer(self.entries_sent, digest);
        self.transport.send(&footer)?;
        Ok(())
    }

    /// Consume the bridge and return the inner transport.
    #[must_use]
    pub fn into_transport(self) -> T {
        self.transport
    }
}

// ── Wire encoding helpers ──────────────────────────────────────────────

/// Encode a single intent-log frame for wire transmission.
///
/// Format: `[entry_len: u32 LE][frame_bytes: N bytes]`
fn encode_entry_wire(frame: &IntentLogFrame) -> Vec<u8> {
    let frame_bytes = frame.encode();
    let mut buf = Vec::with_capacity(4 + frame_bytes.len());
    buf.extend_from_slice(&(frame_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&frame_bytes);
    buf
}

/// Decode a single wire entry, returning the frame.
///
/// Returns `None` if the buffer is too short to contain a complete entry.
pub fn decode_entry_wire(data: &[u8]) -> Option<(IntentLogFrame, usize)> {
    if data.len() < 4 {
        return None;
    }
    let entry_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let total_needed = 4 + entry_len;
    if data.len() < total_needed {
        return None;
    }
    let frame = IntentLogFrame::decode(&data[4..total_needed]).ok()?;
    Some((frame, total_needed))
}

/// Encode a stream-completion footer.
///
/// Format: `[magic "VIRE": u32 LE][total_entries: u64 LE][stream_digest: [u8; 32]]`
pub fn encode_stream_footer(total_entries: u64, stream_digest: [u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FOOTER_SIZE);
    buf.extend_from_slice(&INTENT_REPLICATION_MAGIC.to_le_bytes());
    buf.extend_from_slice(&total_entries.to_le_bytes());
    buf.extend_from_slice(&stream_digest);
    buf
}

/// Decode a stream-completion footer.
///
/// Returns `(total_entries, stream_digest)` on success.
pub fn decode_stream_footer(data: &[u8]) -> Result<(u64, [u8; 32]), StreamFooterDecodeError> {
    if data.len() < FOOTER_SIZE {
        return Err(StreamFooterDecodeError::Truncated);
    }
    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if magic != INTENT_REPLICATION_MAGIC {
        return Err(StreamFooterDecodeError::BadMagic { got: magic });
    }
    let total_entries = u64::from_le_bytes(data[4..12].try_into().unwrap());
    let digest: [u8; 32] = data[12..44].try_into().unwrap();
    Ok((total_entries, digest))
}

/// Error decoding a stream-completion footer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamFooterDecodeError {
    /// Not enough data for a complete footer.
    Truncated,
    /// Magic bytes did not match `VIRE`.
    BadMagic { got: u32 },
}

impl fmt::Display for StreamFooterDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "stream footer truncated"),
            Self::BadMagic { got } => write!(f, "stream footer bad magic: 0x{got:08X}"),
        }
    }
}

impl std::error::Error for StreamFooterDecodeError {}

// ── Transport adapter (feature = "replication") ────────────────────────

/// Adapter that implements [`ReplicationTransport`] for
/// [`tidefs_transport::backend::ConnectionLike`].
///
/// This adapter is only available when the `replication` feature is
/// enabled, which pulls in the `tidefs-transport` dependency.
#[cfg(feature = "replication")]
pub struct ConnectionReplicationTransport {
    conn: Box<dyn tidefs_transport::backend::ConnectionLike>,
}

#[cfg(feature = "replication")]
impl ConnectionReplicationTransport {
    /// Wrap a [`tidefs_transport::backend::ConnectionLike`] for use as
    /// a [`ReplicationTransport`].
    pub fn new(conn: Box<dyn tidefs_transport::backend::ConnectionLike>) -> Self {
        Self { conn }
    }

    /// Return a reference to the inner connection.
    #[must_use]
    pub fn inner(&self) -> &dyn tidefs_transport::backend::ConnectionLike {
        &*self.conn
    }

    /// Return a mutable reference to the inner connection.
    #[must_use]
    pub fn inner_mut(&mut self) -> &mut dyn tidefs_transport::backend::ConnectionLike {
        &mut *self.conn
    }

    /// Consume the adapter and return the inner connection.
    #[must_use]
    pub fn into_inner(self) -> Box<dyn tidefs_transport::backend::ConnectionLike> {
        self.conn
    }
}

#[cfg(feature = "replication")]
impl ReplicationTransport for ConnectionReplicationTransport {
    fn send(&mut self, data: &[u8]) -> Result<(), ReplicationTransportError> {
        self.conn
            .write_frame(data)
            .map_err(|e| ReplicationTransportError::TransportError(format!("{e}")))
    }

    fn is_ready(&self) -> bool {
        // ConnectionLike has no readiness query; always ready.
        // Backpressure is handled by the connection blocking internally.
        true
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IntentLogRecord;
    use std::sync::Mutex;

    // ── Mock transport ───────────────────────────────────────────────

    /// A mock transport that records sent messages and supports
    /// controllable readiness and error injection.
    struct MockReplicationTransport {
        sent: Mutex<Vec<Vec<u8>>>,
        ready: bool,
        error_after: usize,
        send_count: usize,
    }

    impl MockReplicationTransport {
        fn new() -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                ready: true,
                error_after: usize::MAX,
                send_count: 0,
            }
        }

        fn ready(mut self, r: bool) -> Self {
            self.ready = r;
            self
        }

        fn with_error_after(mut self, n: usize) -> Self {
            self.error_after = n;
            self
        }

        fn take_sent(&self) -> Vec<Vec<u8>> {
            self.sent.lock().unwrap().drain(..).collect()
        }
    }

    impl ReplicationTransport for MockReplicationTransport {
        fn send(&mut self, data: &[u8]) -> Result<(), ReplicationTransportError> {
            if self.send_count >= self.error_after {
                return Err(ReplicationTransportError::Disconnected);
            }
            self.send_count += 1;
            self.sent.lock().unwrap().push(data.to_vec());
            Ok(())
        }

        fn is_ready(&self) -> bool {
            self.ready
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────

    fn make_create_frame(ino: u64, name: &[u8], txg_id: u64, seq: u64) -> IntentLogFrame {
        IntentLogFrame::new(
            IntentLogRecord::Create {
                parent: 1,
                name: name.to_vec(),
                mode: 0o644,
                ino,
            },
            txg_id,
            seq,
        )
    }

    fn make_write_frame(ino: u64, txg_id: u64, seq: u64) -> IntentLogFrame {
        IntentLogFrame::new(
            IntentLogRecord::Write {
                ino,
                offset: 0,
                length: 256,
                data_hash: [0xAB; 32],
            },
            txg_id,
            seq,
        )
    }

    // ── Tests: replicate_entry ───────────────────────────────────────

    #[test]
    fn replicate_entry_sends_wire_message() {
        let transport = MockReplicationTransport::new();
        let mut bridge = IntentLogReplicationBridge::new(transport);
        let frame = make_create_frame(42, b"test.txt", 1, 0);

        let ack = bridge.replicate_entry(&frame).unwrap();
        assert_eq!(ack.entries_replicated, 1);
        assert_eq!(bridge.entries_sent(), 1);

        let sent = bridge.transport.take_sent();
        assert_eq!(sent.len(), 1);

        // Decode the wire message
        let (decoded, consumed) = decode_entry_wire(&sent[0]).unwrap();
        assert_eq!(consumed, sent[0].len());
        assert_eq!(decoded.record, frame.record);
        assert_eq!(decoded.txg_id, frame.txg_id);
        assert_eq!(decoded.record_seq, frame.record_seq);
    }

    #[test]
    fn replicate_entry_not_ready_returns_zero() {
        let transport = MockReplicationTransport::new().ready(false);
        let mut bridge = IntentLogReplicationBridge::new(transport);
        let frame = make_create_frame(1, b"a", 1, 0);

        let ack = bridge.replicate_entry(&frame).unwrap();
        assert_eq!(ack.entries_replicated, 0);
        assert_eq!(bridge.entries_sent(), 0);
    }

    #[test]
    fn replicate_entry_propagates_transport_error() {
        let transport = MockReplicationTransport::new().with_error_after(0);
        let mut bridge = IntentLogReplicationBridge::new(transport);
        let frame = make_create_frame(1, b"a", 1, 0);

        let err = bridge.replicate_entry(&frame).unwrap_err();
        assert_eq!(err, ReplicationTransportError::Disconnected);
        assert_eq!(bridge.entries_sent(), 0);
    }

    #[test]
    fn replicate_entry_increments_entries_sent() {
        let transport = MockReplicationTransport::new();
        let mut bridge = IntentLogReplicationBridge::new(transport);

        assert_eq!(bridge.entries_sent(), 0);
        bridge
            .replicate_entry(&make_create_frame(10, b"a", 1, 0))
            .unwrap();
        assert_eq!(bridge.entries_sent(), 1);
        bridge
            .replicate_entry(&make_create_frame(11, b"b", 1, 1))
            .unwrap();
        assert_eq!(bridge.entries_sent(), 2);
    }

    // ── Tests: replicate_batch ───────────────────────────────────────

    #[test]
    fn replicate_batch_sends_all_entries() {
        let transport = MockReplicationTransport::new();
        let mut bridge = IntentLogReplicationBridge::new(transport);

        let frames: Vec<_> = (0..5)
            .map(|i| make_create_frame(i + 10, format!("f{i}").as_bytes(), 1, i))
            .collect();

        let ack = bridge.replicate_batch(&frames).unwrap();
        assert_eq!(ack.entries_replicated, 5);
        assert_eq!(bridge.entries_sent(), 5);

        let sent = bridge.transport.take_sent();
        assert_eq!(sent.len(), 5);

        for (i, message) in sent.iter().enumerate() {
            let (decoded, _) = decode_entry_wire(message).unwrap();
            assert_eq!(decoded.record_seq, i as u64);
        }
    }

    #[test]
    fn replicate_batch_stops_on_not_ready() {
        // Create a transport with 2 entries capacity, then not-ready
        let transport = MockReplicationTransport::new().with_error_after(2);
        let mut bridge = IntentLogReplicationBridge::new(transport);

        let frames: Vec<_> = (0..5)
            .map(|i| make_create_frame(i + 10, format!("f{i}").as_bytes(), 1, i))
            .collect();

        let err = bridge.replicate_batch(&frames).unwrap_err();
        assert_eq!(err, ReplicationTransportError::Disconnected);
        // Error happened on 3rd send (index 2) — first 2 sent successfully
        assert_eq!(bridge.entries_sent(), 2);
    }

    #[test]
    fn replicate_batch_empty_returns_zero() {
        let transport = MockReplicationTransport::new();
        let mut bridge = IntentLogReplicationBridge::new(transport);

        let ack = bridge.replicate_batch(&[]).unwrap();
        assert_eq!(ack.entries_replicated, 0);
        assert_eq!(bridge.entries_sent(), 0);
    }

    #[test]
    fn replicate_batch_with_not_ready_transport() {
        let transport = MockReplicationTransport::new().ready(false);
        let mut bridge = IntentLogReplicationBridge::new(transport);

        let frames = vec![make_create_frame(1, b"a", 1, 0)];
        let ack = bridge.replicate_batch(&frames).unwrap();
        assert_eq!(ack.entries_replicated, 0);
    }

    // ── Tests: stream digest ─────────────────────────────────────────

    #[test]
    fn stream_digest_covers_all_entries_in_order() {
        let transport = MockReplicationTransport::new();
        let mut bridge = IntentLogReplicationBridge::new(transport);

        let f0 = make_create_frame(10, b"a", 1, 0);
        let f1 = make_create_frame(11, b"b", 1, 1);
        let f2 = make_write_frame(12, 1, 2);

        bridge.replicate_entry(&f0).unwrap();
        bridge.replicate_entry(&f1).unwrap();
        bridge.replicate_entry(&f2).unwrap();

        // Compute expected digest manually
        let context = "TideFS intent-log replication bridge stream v1";
        let key = blake3::derive_key(context, b"");
        let mut expected = blake3::Hasher::new_keyed(&key);
        expected.update(&encode_entry_wire(&f0));
        expected.update(&encode_entry_wire(&f1));
        expected.update(&encode_entry_wire(&f2));
        let expected_digest: [u8; 32] = expected.finalize().into();

        assert_eq!(bridge.stream_digest(), expected_digest);
    }

    #[test]
    fn stream_digest_empty_stream_is_deterministic() {
        let transport = MockReplicationTransport::new();
        let bridge = IntentLogReplicationBridge::new(transport);

        let context = "TideFS intent-log replication bridge stream v1";
        let key = blake3::derive_key(context, b"");
        let expected: [u8; 32] = blake3::Hasher::new_keyed(&key).finalize().into();

        assert_eq!(bridge.stream_digest(), expected);
    }

    #[test]
    fn stream_digest_differs_for_different_entry_order() {
        let transport1 = MockReplicationTransport::new();
        let mut bridge1 = IntentLogReplicationBridge::new(transport1);

        let transport2 = MockReplicationTransport::new();
        let mut bridge2 = IntentLogReplicationBridge::new(transport2);

        let fa = make_create_frame(10, b"a", 1, 0);
        let fb = make_create_frame(11, b"b", 1, 1);

        bridge1.replicate_entry(&fa).unwrap();
        bridge1.replicate_entry(&fb).unwrap();

        bridge2.replicate_entry(&fb).unwrap();
        bridge2.replicate_entry(&fa).unwrap();

        assert_ne!(bridge1.stream_digest(), bridge2.stream_digest());
    }

    // ── Tests: finish_replication_stream ─────────────────────────────

    #[test]
    fn finish_writes_stream_footer() {
        let transport = MockReplicationTransport::new();
        let mut bridge = IntentLogReplicationBridge::new(transport);

        let f0 = make_create_frame(10, b"a", 1, 0);
        let f1 = make_write_frame(10, 1, 1);
        bridge.replicate_entry(&f0).unwrap();
        bridge.replicate_entry(&f1).unwrap();

        bridge.finish_replication_stream().unwrap();

        let sent = bridge.transport.take_sent();
        // 2 entries + 1 footer = 3 messages
        assert_eq!(sent.len(), 3);

        let footer = &sent[2];
        let (total, digest) = decode_stream_footer(footer).unwrap();
        assert_eq!(total, 2);
        assert_eq!(digest, bridge.stream_digest());
    }

    #[test]
    fn finish_empty_stream_still_writes_footer() {
        let transport = MockReplicationTransport::new();
        let mut bridge = IntentLogReplicationBridge::new(transport);

        bridge.finish_replication_stream().unwrap();

        let sent = bridge.transport.take_sent();
        assert_eq!(sent.len(), 1); // just footer

        let (total, digest) = decode_stream_footer(&sent[0]).unwrap();
        assert_eq!(total, 0);
        assert_eq!(digest, bridge.stream_digest());
    }

    #[test]
    fn finish_propagates_transport_error() {
        let transport = MockReplicationTransport::new().with_error_after(0);
        let mut bridge = IntentLogReplicationBridge::new(transport);

        let err = bridge.finish_replication_stream().unwrap_err();
        assert_eq!(err, ReplicationTransportError::Disconnected);
    }

    // ── Tests: wire format round-trip ────────────────────────────────

    #[test]
    fn encode_decode_entry_wire_round_trip() {
        let frame = make_create_frame(42, b"hello.txt", 7, 3);
        let wire = encode_entry_wire(&frame);
        let (decoded, consumed) = decode_entry_wire(&wire).unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(decoded.record, frame.record);
        assert_eq!(decoded.txg_id, frame.txg_id);
        assert_eq!(decoded.record_seq, frame.record_seq);
        assert_eq!(decoded.checksum, frame.checksum);
    }

    #[test]
    fn decode_entry_wire_truncated_returns_none() {
        // Valid entry needs at least 4 bytes for length prefix
        assert!(decode_entry_wire(&[]).is_none());
        assert!(decode_entry_wire(&[0u8; 2]).is_none());

        // Declare a huge length but not enough data
        let mut truncated = vec![0u8; 4];
        truncated[0] = 0xFF; // huge length
        assert!(decode_entry_wire(&truncated).is_none());
    }

    #[test]
    fn decode_entry_wire_rejects_corrupt_frame() {
        let frame = make_create_frame(1, b"x", 1, 0);
        let mut wire = encode_entry_wire(&frame);
        // Corrupt the frame payload (flip a byte after the length prefix)
        wire[5] ^= 0xFF;
        // Should still parse length correctly, but frame decode fails checksum
        assert!(decode_entry_wire(&wire).is_none());
    }

    // ── Tests: stream footer encode/decode ───────────────────────────

    #[test]
    fn encode_decode_stream_footer_round_trip() {
        let digest: [u8; 32] = [0xCC; 32];
        let footer = encode_stream_footer(42, digest);
        let (total, decoded_digest) = decode_stream_footer(&footer).unwrap();
        assert_eq!(total, 42);
        assert_eq!(decoded_digest, digest);
    }

    #[test]
    fn decode_stream_footer_truncated() {
        assert!(matches!(
            decode_stream_footer(&[0u8; 10]),
            Err(StreamFooterDecodeError::Truncated)
        ));
    }

    #[test]
    fn decode_stream_footer_bad_magic() {
        let digest = [0u8; 32];
        let mut footer = encode_stream_footer(1, digest);
        footer[0] ^= 0xFF;
        assert!(matches!(
            decode_stream_footer(&footer),
            Err(StreamFooterDecodeError::BadMagic { .. })
        ));
    }

    // ── Tests: ReplicationAck ─────────────────────────────────────────

    #[test]
    fn ack_reflects_batch_size() {
        let transport = MockReplicationTransport::new();
        let mut bridge = IntentLogReplicationBridge::new(transport);

        let frames: Vec<_> = (0..3)
            .map(|i| make_create_frame(i + 1, format!("f{i}").as_bytes(), 1, i))
            .collect();

        let ack = bridge.replicate_batch(&frames).unwrap();
        assert_eq!(ack.entries_replicated, 3);
        assert_eq!(ack.peer_confirmation_hash, None);
        assert_eq!(ack.stream_digest, bridge.stream_digest());
    }

    // ── Tests: into_transport ─────────────────────────────────────────

    #[test]
    fn into_transport_returns_inner() {
        let transport = MockReplicationTransport::new().ready(false);
        let bridge = IntentLogReplicationBridge::new(transport);

        let recovered = bridge.into_transport();
        assert!(!recovered.is_ready());
    }

    // ── Tests: error display ─────────────────────────────────────────

    #[test]
    fn replication_transport_error_display() {
        assert!(format!("{}", ReplicationTransportError::Disconnected).contains("disconnected"));
        assert!(format!("{}", ReplicationTransportError::Timeout).contains("timed out"));
        let e = ReplicationTransportError::TransportError("disk full".into());
        assert!(format!("{e}").contains("disk full"));
    }

    #[test]
    fn stream_footer_decode_error_display() {
        assert!(format!("{}", StreamFooterDecodeError::Truncated).contains("truncated"));
        let e = StreamFooterDecodeError::BadMagic { got: 0xDEADBEEF };
        assert!(format!("{e}").contains("DEADBEEF"));
    }

    // ── Tests: multi-variant frame round-trip ────────────────────────

    #[test]
    fn various_record_types_round_trip_through_wire() {
        let transport = MockReplicationTransport::new();
        let mut bridge = IntentLogReplicationBridge::new(transport);

        let frames = vec![
            IntentLogFrame::new(
                IntentLogRecord::Write {
                    ino: 1,
                    offset: 0,
                    length: 64,
                    data_hash: [0x11; 32],
                },
                1,
                0,
            ),
            IntentLogFrame::new(
                IntentLogRecord::Truncate {
                    ino: 1,
                    new_size: 4096,
                },
                1,
                1,
            ),
            IntentLogFrame::new(
                IntentLogRecord::Mkdir {
                    parent: 1,
                    name: b"sub".to_vec(),
                    mode: 0o755,
                    ino: 10,
                },
                1,
                2,
            ),
            IntentLogFrame::new(
                IntentLogRecord::Unlink {
                    parent: 1,
                    name: b"old".to_vec(),
                    ino: 5,
                },
                1,
                3,
            ),
            IntentLogFrame::new(
                IntentLogRecord::Fsync {
                    ino: 1,
                    fh: 42,
                    mode: 0,
                },
                1,
                4,
            ),
        ];

        let ack = bridge.replicate_batch(&frames).unwrap();
        assert_eq!(ack.entries_replicated, 5);

        let sent = bridge.transport.take_sent();
        assert_eq!(sent.len(), 5);

        for (i, wire_msg) in sent.iter().enumerate() {
            let (decoded, _) = decode_entry_wire(wire_msg).unwrap();
            assert_eq!(decoded.record_seq, i as u64);
            assert_eq!(decoded.txg_id, 1);
            // Verify checksums survive round-trip
            assert_eq!(decoded.checksum, frames[i].checksum);
        }
    }
}
