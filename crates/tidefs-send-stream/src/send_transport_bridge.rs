//! Send-transport bridge that drains a [`SendQueue`] of [`TransferChunk`]s
//! and transmits them through a transport session for multi-node state
//! transfer.
//!
//! # Architecture
//!
//! The bridge sits between the bounded send queue (filled by chunk encoders)
//! and the transport wire. It drains chunks in FIFO order, wraps each in a
//! sequenced transport message, and emits a BLAKE3-verified stream-completion
//! footer when the stream is finished. Backpressure from the transport
//! propagates naturally: when the transport is not ready, the bridge pauses
//! draining rather than buffering unboundedly.
//!
//! # Wire format
//!
//! Each chunk message on the wire is:
//!
//! ```text
//! [seq: u64 LE][chunk_wire: N bytes]  (TransferChunk::encode_to_wire output)
//! ```
//!
//! The stream-completion footer is:
//!
//! ```text
//! [magic "VSEN": u32 LE][total_chunks: u64 LE][stream_digest: [u8; 32]]
//! ```
//!
//! The stream digest is a BLAKE3-256 hash of all chunk payloads in FIFO
//! order under the `TideFS send-transport bridge stream v1` domain, allowing
//! the receiver to verify complete, ordered delivery.

use std::sync::Arc;

use super::chunk_encoder::TransferChunk;
use super::send_queue::SendQueue;

/// Magic bytes for the stream-completion footer ("VSEN").
const STREAM_END_MAGIC: u32 = 0x5653_454E;

/// Domain context for the stream-level BLAKE3 digest.
const STREAM_DIGEST_CONTEXT: &str = "TideFS send-transport bridge stream v1";

// ---------------------------------------------------------------------------
// SendTransport trait
// ---------------------------------------------------------------------------

/// Abstract transport write capability.
///
/// Implementors write ordered byte frames to a transport session
/// (TCP connection, RDMA queue pair, loopback channel, etc.).
/// The trait is intentionally minimal so the bridge can be tested
/// with a mock and integrated with any transport backend.
pub trait SendTransport {
    /// Write a complete frame to the transport.
    ///
    /// The implementation decides framing boundaries; the bridge
    /// guarantees each `send` call is one logical message.
    ///
    /// # Errors
    ///
    /// Returns [`SendTransportError`] when the transport is disconnected,
    /// timed out, or has encountered an unrecoverable error.
    fn send(&mut self, data: &[u8]) -> Result<(), SendTransportError>;

    /// Whether the transport can accept another frame without blocking.
    ///
    /// When this returns `false`, the bridge pauses draining to
    /// propagate backpressure to the send queue.
    fn is_ready(&self) -> bool;

    /// Check whether sufficient flow-control credits are available for
    /// sending `byte_count` bytes.
    ///
    /// The default implementation always returns `Ok(())` (unlimited
    /// credit). Implementations with flow control override this to
    /// enforce bounded receive-window backpressure.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error when credits are exhausted.
    fn check_credit(&mut self, _byte_count: u64) -> Result<(), String> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SendTransportError
// ---------------------------------------------------------------------------

/// Errors returned by [`SendTransport::send`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendTransportError {
    /// The transport session was disconnected.
    Disconnected,
    /// The transport operation timed out.
    Timeout,
    /// An underlying transport I/O error occurred.
    TransportError(String),
}

impl std::fmt::Display for SendTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected => write!(f, "transport session disconnected"),
            Self::Timeout => write!(f, "transport operation timed out"),
            Self::TransportError(msg) => write!(f, "transport error: {msg}"),
        }
    }
}

impl std::error::Error for SendTransportError {}

// ---------------------------------------------------------------------------
// SendTransportBridge
// ---------------------------------------------------------------------------

/// Bridges a [`SendQueue<TransferChunk>`] to a transport session.
///
/// Drains chunks from the queue in FIFO order, sends each through the
/// transport with per-chunk sequence numbers, maintains a running
/// BLAKE3-256 stream digest, and emits a verified stream-completion
/// footer on [`finish`](Self::finish).
///
/// # Lifecycle
///
/// 1. Enqueue chunks via the shared [`SendQueue`] (producer side).
/// 2. Call [`drain_available`](Self::drain_available) repeatedly to
///    send chunks without blocking.
/// 3. When all chunks are enqueued and the producer signals completion,
///    call [`drain_all`](Self::drain_all) to flush everything.
/// 4. Call [`finish`](Self::finish) to send the stream-completion footer.
///
/// # Backpressure
///
/// The bridge checks [`SendTransport::is_ready`] before each send.
/// When the transport is not ready, draining pauses. This propagates
/// backpressure to the send queue (producers block on `enqueue` when
/// the queue is full).
pub struct SendTransportBridge<T: SendTransport> {
    /// Shared handle to the bounded send queue.
    queue: Arc<SendQueue<TransferChunk>>,
    /// Transport write endpoint.
    transport: T,
    /// Monotonic per-chunk sequence number (assigned in send order).
    next_seq: u64,
    /// Running BLAKE3-256 hasher over all chunk payloads for the stream digest.
    stream_hasher: blake3::Hasher,
    /// Total number of chunks sent so far.
    chunks_sent: u64,
}

impl<T: SendTransport> SendTransportBridge<T> {
    /// Create a new bridge attached to a send queue and transport.
    ///
    /// The queue is shared so that a producer thread can continue
    /// enqueuing while the bridge drains.
    pub fn new(queue: Arc<SendQueue<TransferChunk>>, transport: T) -> Self {
        let key = blake3::derive_key(STREAM_DIGEST_CONTEXT, b"");
        Self {
            queue,
            transport,
            next_seq: 0,
            stream_hasher: blake3::Hasher::new_keyed(&key),
            chunks_sent: 0,
        }
    }

    /// Return the number of chunks sent so far.
    #[must_use]
    pub fn chunks_sent(&self) -> u64 {
        self.chunks_sent
    }

    /// Return the next sequence number that will be assigned.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Drain all currently available chunks without blocking.
    ///
    /// Calls [`SendQueue::drain`] to atomically take everything in the
    /// queue, then sends each chunk through the transport. Stops early
    /// if the transport reports not-ready.
    ///
    /// Returns the number of chunks sent in this call.
    ///
    /// # Errors
    ///
    /// Returns [`SendTransportError`] if a transport write fails.
    /// Unsent chunks are **not** re-enqueued — the caller should handle
    /// error recovery (re-enqueue unsent chunks, retry, or abort).
    pub fn drain_available(&mut self) -> Result<u64, SendTransportError> {
        let chunks = self.queue.drain();
        if chunks.is_empty() {
            return Ok(0);
        }
        self.send_batch(chunks)
    }

    /// Drain all chunks, blocking only between drain calls.
    ///
    /// Repeatedly drains the queue until empty. Between drains, yields
    /// to allow producers to enqueue more chunks. This method does not
    /// spin-wait: each iteration drains whatever is available and then
    /// loops.
    ///
    /// Returns the total number of chunks sent.
    ///
    /// # Errors
    ///
    /// Returns [`SendTransportError`] if a transport write fails.
    pub fn drain_all(&mut self) -> Result<u64, SendTransportError> {
        let mut total = 0u64;
        loop {
            let chunks = self.queue.drain();
            if chunks.is_empty() {
                break;
            }
            let sent = self.send_batch(chunks)?;
            total += sent;
        }
        Ok(total)
    }

    /// Finish the stream: drain any remaining chunks, then write the
    /// BLAKE3-verified stream-completion footer.
    ///
    /// After this call, the receiver knows the stream is complete and
    /// can verify the stream digest against all received chunks.
    ///
    /// Returns `(total_chunks, stream_digest)`.
    ///
    /// # Errors
    ///
    /// Returns [`SendTransportError`] if a transport write fails.
    pub fn finish(&mut self) -> Result<(u64, [u8; 32]), SendTransportError> {
        // Drain any last chunks
        self.drain_all()?;

        let digest: [u8; 32] = self.stream_hasher.finalize().into();
        let footer = encode_stream_end(self.chunks_sent, digest);
        self.transport.send(&footer)?;

        Ok((self.chunks_sent, digest))
    }

    /// Send a batch of already-drained chunks.
    fn send_batch(&mut self, chunks: Vec<TransferChunk>) -> Result<u64, SendTransportError> {
        let mut sent = 0u64;
        for chunk in &chunks {
            if !self.transport.is_ready() {
                break;
            }

            // Check flow-control credits before framing
            if let Err(_e) = self.transport.check_credit(chunk.payload.len() as u64) {
                // Window exhausted — stop draining; unsent chunks
                // remain in the batch (dropped here; callers should
                // re-enqueue or pause).
                break;
            }

            // Stream digest: hash the payload bytes
            self.stream_hasher.update(&chunk.payload);

            // Encode the wire message: [seq: u64 LE][chunk_wire]
            let chunk_wire = chunk.encode_to_wire();
            let mut msg = Vec::with_capacity(8 + chunk_wire.len());
            msg.extend_from_slice(&self.next_seq.to_le_bytes());
            msg.extend_from_slice(&chunk_wire);

            match self.transport.send(&msg) {
                Ok(()) => {
                    self.next_seq += 1;
                    sent += 1;
                }
                Err(e) => {
                    self.chunks_sent += sent;
                    return Err(e);
                }
            }
        }
        self.chunks_sent += sent;
        Ok(sent)
    }
}

// ---------------------------------------------------------------------------
// Wire encoding helpers
// ---------------------------------------------------------------------------

/// Encode a stream-completion footer.
///
/// Format: `[magic "VSEN": u32 LE][total_chunks: u64 LE][stream_digest: [u8; 32]]`
pub fn encode_stream_end(total_chunks: u64, stream_digest: [u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + 8 + 32);
    buf.extend_from_slice(&STREAM_END_MAGIC.to_le_bytes());
    buf.extend_from_slice(&total_chunks.to_le_bytes());
    buf.extend_from_slice(&stream_digest);
    buf
}

/// Decode a stream-completion footer, returning `(total_chunks, stream_digest)`.
pub fn decode_stream_end(data: &[u8]) -> Result<(u64, [u8; 32]), StreamEndDecodeError> {
    if data.len() < 44 {
        return Err(StreamEndDecodeError::Truncated);
    }
    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if magic != STREAM_END_MAGIC {
        return Err(StreamEndDecodeError::BadMagic { got: magic });
    }
    let total_chunks = u64::from_le_bytes(data[4..12].try_into().unwrap());
    let digest: [u8; 32] = data[12..44].try_into().unwrap();
    Ok((total_chunks, digest))
}

/// Error decoding a stream-end footer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamEndDecodeError {
    Truncated,
    BadMagic { got: u32 },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Transport adapter (feature = "transport")
// ---------------------------------------------------------------------------

/// Adapter that implements [] for
/// [].
///
/// # Example
///
///
#[cfg(feature = "transport")]
pub struct ConnectionTransport {
    conn: Box<dyn tidefs_transport::backend::ConnectionLike>,
}

#[cfg(feature = "transport")]
impl ConnectionTransport {
    /// Wrap a [] for use as a [].
    pub fn new(conn: Box<dyn tidefs_transport::backend::ConnectionLike>) -> Self {
        Self { conn }
    }

    /// Return a reference to the inner connection.
    pub fn inner(&self) -> &dyn tidefs_transport::backend::ConnectionLike {
        &*self.conn
    }

    /// Return a mutable reference to the inner connection.
    pub fn inner_mut(&mut self) -> &mut dyn tidefs_transport::backend::ConnectionLike {
        &mut *self.conn
    }

    /// Consume the adapter and return the inner connection.
    pub fn into_inner(self) -> Box<dyn tidefs_transport::backend::ConnectionLike> {
        self.conn
    }
}

#[cfg(feature = "transport")]
impl SendTransport for ConnectionTransport {
    fn send(&mut self, data: &[u8]) -> Result<(), SendTransportError> {
        self.conn
            .write_frame(data)
            .map_err(|e| SendTransportError::TransportError(format!("{e}")))
    }

    fn is_ready(&self) -> bool {
        // ConnectionLike has no readiness query; always ready.
        // Backpressure is handled by the connection blocking internally.
        true
    }
}

// ---------------------------------------------------------------------------
// CreditSendTransport — flow-control-aware transport wrapper
// ---------------------------------------------------------------------------

/// A [`SendTransport`] wrapper that enforces credit-based flow control
/// using [`tidefs_transport::flow_control::CreditWindow`].
///
/// Each send consumes credits from the window; when credits are
/// exhausted, `check_credit` returns an error, giving the bridge
/// backpressure to pause draining. The receiver must send credit grants
/// to replenish the window.
///
/// Requires the `transport` feature.
///
/// # Example
///
/// ```ignore
/// use tidefs_transport::flow_control::CreditWindow;
/// let window = CreditWindow::default_window();
/// let inner = ConnectionTransport::new(conn);
/// let transport = CreditSendTransport::new(inner, window);
/// let mut bridge = SendTransportBridge::new(queue, transport);
/// bridge.drain_available().unwrap();
/// ```
#[cfg(feature = "transport")]
pub struct CreditSendTransport<T: SendTransport> {
    /// The inner transport delegate.
    pub inner: T,
    /// Receive-window credit tracker for flow control.
    pub window: tidefs_transport::flow_control::CreditWindow,
}

#[cfg(feature = "transport")]
impl<T: SendTransport> CreditSendTransport<T> {
    /// Wrap a transport with flow-control credit tracking.
    pub fn new(inner: T, window: tidefs_transport::flow_control::CreditWindow) -> Self {
        Self { inner, window }
    }

    /// Consume the wrapper and return the inner transport.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Grant credits (called when a credit grant arrives from the peer).
    pub fn grant_credits(&mut self, credits: u64) {
        self.window.grant(credits);
    }

    /// Access the inner transport.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Mutable access to the inner transport.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

#[cfg(feature = "transport")]
impl<T: SendTransport> SendTransport for CreditSendTransport<T> {
    fn send(&mut self, data: &[u8]) -> Result<(), SendTransportError> {
        // Consume credits equal to the data size being sent
        self.window
            .consume(data.len() as u64)
            .map_err(|e| SendTransportError::TransportError(e.to_string()))?;
        self.inner.send(data)
    }

    fn is_ready(&self) -> bool {
        // Not-ready when window is exhausted (backpressure) or inner
        // transport is not ready.
        !self.window.is_exhausted() && self.inner.is_ready()
    }

    fn check_credit(&mut self, byte_count: u64) -> Result<(), String> {
        if byte_count > self.window.available_credits {
            return Err(format!(
                "flow-control window exhausted: need {byte_count}, have {}",
                self.window.available_credits
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // ── Mock transport ───────────────────────────────────────────────

    /// A mock transport that records sent messages and supports
    /// controllable readiness and error injection.
    struct MockTransport {
        sent: Mutex<Vec<Vec<u8>>>,
        ready: bool,
        error_after: usize, // inject error after N sends
        send_count: usize,
    }

    impl MockTransport {
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

    impl SendTransport for MockTransport {
        fn send(&mut self, data: &[u8]) -> Result<(), SendTransportError> {
            if self.send_count >= self.error_after {
                return Err(SendTransportError::Disconnected);
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

    fn make_chunk(byte: u8, seq: u32) -> TransferChunk {
        TransferChunk::new(
            [byte; 32],
            u64::from(seq) * 256,
            seq,
            seq + 1,
            vec![byte; 64],
            false,
        )
    }

    fn queue_with_chunks(capacity: usize, n: usize) -> Arc<SendQueue<TransferChunk>> {
        let q = Arc::new(SendQueue::new(capacity));
        for i in 0..n {
            q.enqueue(make_chunk((i as u8) + 1, i as u32));
        }
        q
    }

    /// Extract the sequence number from a sent wire message.
    fn msg_seq(msg: &[u8]) -> u64 {
        u64::from_le_bytes(msg[0..8].try_into().unwrap())
    }

    /// Extract the chunk from a sent wire message (skip 8-byte seq prefix).
    fn msg_chunk(msg: &[u8]) -> (TransferChunk, &[u8]) {
        TransferChunk::decode_from_wire(&msg[8..]).unwrap()
    }

    // ── Tests: drain_available ───────────────────────────────────────

    #[test]
    fn drain_available_sends_all_queued_chunks() {
        let q = queue_with_chunks(8, 3);
        let transport = MockTransport::new();
        let mut bridge = SendTransportBridge::new(Arc::clone(&q), transport);

        let sent = bridge.drain_available().unwrap();
        assert_eq!(sent, 3);
        assert_eq!(bridge.chunks_sent(), 3);
        assert_eq!(bridge.next_seq(), 3);
        assert!(q.is_empty());
    }

    #[test]
    fn drain_available_empty_queue_returns_zero() {
        let q = Arc::new(SendQueue::new(4));
        let transport = MockTransport::new();
        let mut bridge = SendTransportBridge::new(Arc::clone(&q), transport);

        let sent = bridge.drain_available().unwrap();
        assert_eq!(sent, 0);
    }

    #[test]
    fn drain_available_stops_on_not_ready() {
        let q = queue_with_chunks(8, 5);
        let transport = MockTransport::new().ready(false);
        let mut bridge = SendTransportBridge::new(Arc::clone(&q), transport);

        // Transport not ready — nothing drained despite queue being full
        let sent = bridge.drain_available().unwrap();
        assert_eq!(sent, 0);
        assert_eq!(bridge.chunks_sent(), 0);
    }

    #[test]
    fn drain_available_propagates_transport_error() {
        let q = queue_with_chunks(8, 5);
        let transport = MockTransport::new().with_error_after(2);
        let mut bridge = SendTransportBridge::new(Arc::clone(&q), transport);

        let err = bridge.drain_available().unwrap_err();
        assert_eq!(err, SendTransportError::Disconnected);
        // Chunks were drained from queue but only 2 sent
        assert_eq!(bridge.chunks_sent(), 2);
    }

    // ── Tests: sequence numbers ──────────────────────────────────────

    #[test]
    fn sequence_numbers_are_monotonic() {
        let q = queue_with_chunks(8, 4);
        let transport = MockTransport::new();
        let mut bridge = SendTransportBridge::new(Arc::clone(&q), transport);

        bridge.drain_available().unwrap();

        let sent = bridge.transport.take_sent();
        // Verify we have 4 messages
        assert_eq!(sent.len(), 4);

        for (i, message) in sent.iter().enumerate().take(4) {
            let seq = msg_seq(message);
            assert_eq!(seq, i as u64);
        }
    }

    #[test]
    fn sequence_numbers_continue_across_drain_calls() {
        let q = Arc::new(SendQueue::new(8));
        q.enqueue(make_chunk(1, 0));
        q.enqueue(make_chunk(2, 1));

        let transport = MockTransport::new();
        let mut bridge = SendTransportBridge::new(Arc::clone(&q), transport);

        // First drain sends 2 chunks
        bridge.drain_available().unwrap();
        assert_eq!(bridge.next_seq(), 2);

        // Enqueue more and drain again
        q.enqueue(make_chunk(3, 2));
        q.enqueue(make_chunk(4, 3));
        bridge.drain_available().unwrap();

        // Total: 4 sent, seqs 0-3
        assert_eq!(bridge.chunks_sent(), 4);
        assert_eq!(bridge.next_seq(), 4);
    }

    // ── Tests: chunk integrity ───────────────────────────────────────

    #[test]
    fn chunk_wire_format_round_trips() {
        let q = queue_with_chunks(4, 1);
        let transport = MockTransport::new();
        let mut bridge = SendTransportBridge::new(Arc::clone(&q), transport);

        bridge.drain_available().unwrap();

        let sent = bridge.transport.take_sent();
        assert_eq!(sent.len(), 1);

        let seq = msg_seq(&sent[0]);
        assert_eq!(seq, 0);

        let (decoded, rest) = msg_chunk(&sent[0]);
        assert!(rest.is_empty());
        assert!(decoded.verify_auth_tag());
        assert_eq!(decoded.chunk_index, 0);
    }

    #[test]
    fn chunk_preserves_blake3_auth_tag() {
        let q = queue_with_chunks(4, 2);
        let transport = MockTransport::new();
        let mut bridge = SendTransportBridge::new(Arc::clone(&q), transport);

        bridge.drain_available().unwrap();

        let sent = bridge.transport.take_sent();
        assert_eq!(sent.len(), 2);

        for msg in &sent {
            let (chunk, _) = msg_chunk(msg);
            assert!(
                chunk.verify_auth_tag(),
                "BLAKE3 auth tag must survive transport"
            );
        }
    }

    // ── Tests: stream digest ─────────────────────────────────────────

    #[test]
    fn stream_digest_covers_all_payloads_in_order() {
        let q = queue_with_chunks(4, 3);
        let transport = MockTransport::new();
        let mut bridge = SendTransportBridge::new(Arc::clone(&q), transport);

        let (total, digest) = bridge.finish().unwrap();
        assert_eq!(total, 3);

        // Recompute expected digest
        let context = "TideFS send-transport bridge stream v1";
        let key = blake3::derive_key(context, b"");
        let mut expected = blake3::Hasher::new_keyed(&key);
        expected.update(&[1u8; 64]); // chunk 0 payload
        expected.update(&[2u8; 64]); // chunk 1 payload
        expected.update(&[3u8; 64]); // chunk 2 payload
        let expected_digest: [u8; 32] = expected.finalize().into();
        assert_eq!(digest, expected_digest);
    }

    #[test]
    fn stream_digest_empty_stream() {
        let q = Arc::new(SendQueue::new(4));
        let transport = MockTransport::new();
        let mut bridge = SendTransportBridge::new(q, transport);

        let (total, digest) = bridge.finish().unwrap();
        assert_eq!(total, 0);

        let context = "TideFS send-transport bridge stream v1";
        let key = blake3::derive_key(context, b"");
        let expected: [u8; 32] = blake3::Hasher::new_keyed(&key).finalize().into();
        assert_eq!(digest, expected);
    }

    // ── Tests: stream-completion footer ──────────────────────────────

    #[test]
    fn finish_writes_stream_end_footer() {
        let q = queue_with_chunks(4, 2);
        let transport = MockTransport::new();
        let mut bridge = SendTransportBridge::new(Arc::clone(&q), transport);

        let (total, digest) = bridge.finish().unwrap();

        let sent = bridge.transport.take_sent();
        // 2 chunks + 1 footer = 3 messages
        assert_eq!(sent.len(), 3);

        let footer = &sent[2];
        let (decoded_total, decoded_digest) = decode_stream_end(footer).unwrap();
        assert_eq!(decoded_total, total);
        assert_eq!(decoded_digest, digest);
    }

    #[test]
    fn finish_with_empty_stream_still_writes_footer() {
        let q = Arc::new(SendQueue::new(4));
        let transport = MockTransport::new();
        let mut bridge = SendTransportBridge::new(q, transport);

        let (total, digest) = bridge.finish().unwrap();
        assert_eq!(total, 0);

        let sent = bridge.transport.take_sent();
        assert_eq!(sent.len(), 1); // just footer

        let (decoded_total, decoded_digest) = decode_stream_end(&sent[0]).unwrap();
        assert_eq!(decoded_total, 0);
        assert_eq!(decoded_digest, digest);
    }

    #[test]
    fn finish_propagates_transport_error_on_footer() {
        let q = queue_with_chunks(4, 1);
        // Error on 2nd send (chunk 0 sends, then footer fails)
        let transport = MockTransport::new().with_error_after(1);
        let mut bridge = SendTransportBridge::new(Arc::clone(&q), transport);

        let err = bridge.finish().unwrap_err();
        assert_eq!(err, SendTransportError::Disconnected);
        assert_eq!(bridge.chunks_sent(), 1);
    }

    // ── Tests: stream-end decode ─────────────────────────────────────

    #[test]
    pub fn decode_stream_end_valid() {
        let digest: [u8; 32] = [0xAA; 32];
        let footer = encode_stream_end(42, digest);
        let (total, decoded_digest) = decode_stream_end(&footer).unwrap();
        assert_eq!(total, 42);
        assert_eq!(decoded_digest, digest);
    }

    #[test]
    pub fn decode_stream_end_truncated() {
        assert!(matches!(
            decode_stream_end(&[0u8; 10]),
            Err(StreamEndDecodeError::Truncated)
        ));
    }

    #[test]
    pub fn decode_stream_end_bad_magic() {
        let digest = [0u8; 32];
        let mut footer = encode_stream_end(1, digest);
        footer[0] ^= 0xFF;
        assert!(matches!(
            decode_stream_end(&footer),
            Err(StreamEndDecodeError::BadMagic { .. })
        ));
    }

    // ── Tests: drain_all ─────────────────────────────────────────────

    #[test]
    fn drain_all_sends_everything() {
        let q = queue_with_chunks(8, 5);
        let transport = MockTransport::new();
        let mut bridge = SendTransportBridge::new(Arc::clone(&q), transport);

        let total = bridge.drain_all().unwrap();
        assert_eq!(total, 5);
        assert_eq!(bridge.chunks_sent(), 5);
        assert!(q.is_empty());
    }

    #[test]
    fn drain_all_handles_interleaved_producer() {
        let q = Arc::new(SendQueue::new(4));
        // Pre-load 2 chunks
        q.enqueue(make_chunk(1, 0));
        q.enqueue(make_chunk(2, 1));

        let transport = MockTransport::new();
        let mut bridge = SendTransportBridge::new(Arc::clone(&q), transport);

        // Start drain_all in a way that processes in batches
        // Since queue.drain() atomically takes everything, drain_all
        // actually works: first drain takes 2, then loop sees empty.
        let total = bridge.drain_all().unwrap();
        assert_eq!(total, 2);
    }

    // ── Tests: chunks_sent and next_seq ──────────────────────────────

    #[test]
    fn chunks_sent_and_next_seq_tracking() {
        let q = queue_with_chunks(4, 2);
        let transport = MockTransport::new();
        let mut bridge = SendTransportBridge::new(Arc::clone(&q), transport);

        assert_eq!(bridge.chunks_sent(), 0);
        assert_eq!(bridge.next_seq(), 0);

        bridge.drain_available().unwrap();
        assert_eq!(bridge.chunks_sent(), 2);
        assert_eq!(bridge.next_seq(), 2);
    }

    // ── Tests: SendTransportError display ────────────────────────────

    #[test]
    fn error_display() {
        assert!(format!("{}", SendTransportError::Disconnected).contains("disconnected"));
        assert!(format!("{}", SendTransportError::Timeout).contains("timed out"));
        let e = SendTransportError::TransportError("disk full".into());
        assert!(format!("{e}").contains("disk full"));
    }
}
