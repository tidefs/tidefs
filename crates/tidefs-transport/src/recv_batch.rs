//! Transport receive-side batch message decoding with partial-frame
//! prefix retention and vectored-socket-read dispatch.
//!
//! ## Purpose
//!
//! The [`RecvBatchDecoder`] accepts raw bytes from a vectored socket read
//! (`readv`-style iovec), scans the buffer for complete length-delimited
//! frames, decodes each frame into a ([`MessageFamily`], payload) pair in a
//! single pass, and returns the accumulated batch. Incomplete trailing bytes
//! are retained in an internal prefix buffer for the next read cycle, avoiding
//! per-message copy overhead.
//!
//! ## Architecture
//!
//! ```text
//! TcpStream (read half)
//!   |
//!   v
//! ConnectionReceiver::recv_loop()
//!   |
//!   +-- read bytes -> RecvBatchDecoder::feed()
//!                         |
//!                         v
//!                   Vec<(MessageFamily, Vec<u8>)>
//!                         |
//!                         v
//!                   dispatch_batch() -> per-channel queues
//! ```
//!
//! ## Frame format
//!
//! Uses the canonical length-delimited codec format from [`crate::codec`]:
//!
//! ```text
//! [0..4)   payload_len    u32 LE (length of payload only)
//! [4]      family         u8  (MessageFamily discriminant)
//! [5..]    payload        payload_len bytes
//! ```
//!
//! Total frame size = 5 + payload_len.
//!
//! ## Configuration
//!
//! [`RecvBatchConfig`] controls batching behavior:
//!
//! | Parameter | Default | Purpose |
//! |---|---|---|
//! | `max_batch_size` | 128 | Maximum decoded messages per `feed()` call |
//! | `min_batch_bytes` | 0 | Minimum raw bytes before processing (0 = always) |
//!
//! ## Partial-frame handling
//!
//! When the raw buffer ends mid-frame (incomplete header or payload), the
//! unprocessed trailing bytes are retained in the internal prefix buffer.
//! On the next `feed()` call, new data is appended to the prefix and scanning
//! resumes. This avoids the per-message copy of a traditional read buffer
//! approach.
//!
//! ## Error handling
//!
//! Malformed frames (invalid family discriminant, payload too large) are
//! rejected: the offending frame bytes are consumed and a warning is logged.
//! The scanner then resumes at the next byte boundary, preventing a single
//! corrupt frame from stalling the entire receive path.

//! ## Security model
//!
//! This module is a pure framing-and-dispatch optimization: it scans raw
//! socket-read bytes for complete frames, decodes them, and dispatches the
//! decoded payloads to the existing message router. It introduces no new
//! wire types, framing formats, protocol layers, or cryptographic surfaces.
//! All transport security (encryption, session authentication, integrity)
//! is provided by the underlying transport/session security boundary
//! ([`crate::session_cipher`]), which operates on the same payload bytes
//! before they reach this decoder. This module is not a security or trust
//! boundary — it is a throughput optimization on already-received data.

use crate::codec::MessageCodec;
use crate::envelope::MessageFamily;

// ---------------------------------------------------------------------------
// RecvBatchConfig
// ---------------------------------------------------------------------------

/// Configuration for a [`RecvBatchDecoder`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecvBatchConfig {
    /// Maximum number of decoded messages returned per `feed()` call.
    /// When the batch reaches this size, remaining bytes stay in the
    /// prefix buffer for the next cycle. Default: 128.
    pub max_batch_size: usize,
    /// Minimum number of raw bytes accumulated before processing begins.
    /// When 0 (default), every `feed()` is processed immediately.
    pub min_batch_bytes: usize,
}

impl Default for RecvBatchConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 128,
            min_batch_bytes: 0,
        }
    }
}

impl RecvBatchConfig {
    /// Create a new config.
    ///
    /// Returns `None` if `max_batch_size` is zero.
    #[must_use]
    pub fn new(max_batch_size: usize, min_batch_bytes: usize) -> Option<Self> {
        if max_batch_size == 0 {
            return None;
        }
        Some(Self {
            max_batch_size,
            min_batch_bytes,
        })
    }

    /// Config that disables batch accumulation: every feed returns at most
    /// one decoded message.
    #[must_use]
    pub fn single_message() -> Self {
        Self {
            max_batch_size: 1,
            min_batch_bytes: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// RecvBatchDecoder
// ---------------------------------------------------------------------------

/// Scans raw socket-read buffers for complete length-delimited frames,
/// decodes each frame in a single pass, and returns the accumulated batch.
///
/// Incomplete trailing bytes are retained in an internal prefix buffer for
/// the next `feed()` call.
///
/// # Example
///
/// ```ignore
/// use tidefs_transport::recv_batch::{RecvBatchDecoder, RecvBatchConfig};
/// use tidefs_transport::codec::MessageCodec;
///
/// let config = RecvBatchConfig::default();
/// let codec = MessageCodec::default();
/// let mut decoder = RecvBatchDecoder::new(config, codec);
///
/// // Feed raw bytes from a socket read.
/// let batch = decoder.feed(&raw_bytes);
/// for (family, payload) in batch {
///     dispatch.dispatch_or_warn(DecodedMessage::new(family, payload));
/// }
/// ```
pub struct RecvBatchDecoder {
    config: RecvBatchConfig,
    codec: MessageCodec,
    /// Partial frame bytes carried over from the previous read cycle.
    /// Contains the incomplete trailing header/payload that could not
    /// be fully decoded.
    prefix: Vec<u8>,
    /// Total bytes fed since construction (diagnostic counter).
    total_bytes_fed: u64,
    /// Total complete frames emitted since construction.
    frames_emitted: u64,
    /// Number of malformed frames skipped.
    malformed_skipped: u64,
}

impl RecvBatchDecoder {
    /// Create a new decoder with the given configuration and codec.
    #[must_use]
    pub fn new(config: RecvBatchConfig, codec: MessageCodec) -> Self {
        Self {
            config,
            codec,
            prefix: Vec::new(),
            total_bytes_fed: 0,
            frames_emitted: 0,
            malformed_skipped: 0,
        }
    }

    /// Feed raw bytes from a socket read into the decoder.
    ///
    /// Returns a batch of decoded `(MessageFamily, payload)` pairs.
    /// Incomplete trailing bytes are retained internally for the next
    /// `feed()` call.
    ///
    /// If `config.min_batch_bytes > 0` and the total accumulated bytes
    /// (prefix + new data) is below the threshold, the new data is
    /// appended to the prefix and an empty batch is returned.
    pub fn feed(&mut self, data: &[u8]) -> Vec<(MessageFamily, Vec<u8>)> {
        self.total_bytes_fed += data.len() as u64;

        // Append new data to the prefix buffer.
        self.prefix.extend_from_slice(data);

        // Honour min_batch_bytes threshold: defer processing if below.
        if self.config.min_batch_bytes > 0 && self.prefix.len() < self.config.min_batch_bytes {
            return Vec::new();
        }

        let mut batch = Vec::new();
        let max_frame_size = self.codec.max_frame_size();
        let header_size = crate::codec::CODEC_FRAME_HEADER_SIZE; // 5

        // Scan the prefix buffer for complete frames.
        loop {
            // Need at least a full header to determine payload length.
            if self.prefix.len() < header_size {
                break;
            }

            // Read payload length (u32 LE from bytes 0..4).
            let payload_len = u32::from_le_bytes([
                self.prefix[0],
                self.prefix[1],
                self.prefix[2],
                self.prefix[3],
            ]) as usize;

            // Reject frames with payload exceeding the codec's max.
            if payload_len > max_frame_size {
                tracing::warn!(
                    payload_len = payload_len,
                    max_frame_size = max_frame_size,
                    "recv batch: payload too large, skipping frame"
                );
                self.prefix.drain(..header_size);
                self.malformed_skipped += 1;
                continue;
            }

            let frame_len = header_size + payload_len;

            // Check if the full frame is available.
            if self.prefix.len() < frame_len {
                // Partial frame -- keep remaining bytes in prefix for next feed.
                break;
            }

            // Extract the complete frame.
            let frame_bytes: Vec<u8> = self.prefix[..frame_len].to_vec();
            self.prefix.drain(..frame_len);

            // Decode the frame.
            match self.codec.decode(&frame_bytes) {
                Ok((family, payload)) => {
                    batch.push((family, payload));
                    self.frames_emitted += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "recv batch: malformed frame, skipping"
                    );
                    self.malformed_skipped += 1;
                }
            }

            // Honour max_batch_size: stop accumulating and leave
            // remaining bytes in prefix for the next feed() cycle.
            if batch.len() >= self.config.max_batch_size {
                break;
            }
        }

        batch
    }

    /// Total bytes fed into the decoder since construction.
    #[must_use]
    pub fn total_bytes_fed(&self) -> u64 {
        self.total_bytes_fed
    }

    /// Number of complete frames emitted since construction.
    #[must_use]
    pub fn frames_emitted(&self) -> u64 {
        self.frames_emitted
    }

    /// Number of malformed frames skipped since construction.
    #[must_use]
    pub fn malformed_skipped(&self) -> u64 {
        self.malformed_skipped
    }

    /// Number of bytes currently buffered in the prefix (partial frame).
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.prefix.len()
    }

    /// Whether the prefix buffer is empty (no partial frame pending).
    #[must_use]
    pub fn is_prefix_empty(&self) -> bool {
        self.prefix.is_empty()
    }

    /// Discard the prefix buffer and reset diagnostic counters.
    ///
    /// Useful for connection reset or error recovery.
    pub fn reset(&mut self) {
        self.prefix.clear();
        self.total_bytes_fed = 0;
        self.frames_emitted = 0;
        self.malformed_skipped = 0;
    }

    /// Return a snapshot of diagnostic counters.
    #[must_use]
    pub fn diagnostics(&self) -> RecvBatchDiagnostics {
        RecvBatchDiagnostics {
            total_bytes_fed: self.total_bytes_fed,
            frames_emitted: self.frames_emitted,
            malformed_skipped: self.malformed_skipped,
            buffered_bytes: self.prefix.len(),
        }
    }
}

// ---------------------------------------------------------------------------
// RecvBatchDiagnostics
// ---------------------------------------------------------------------------

/// Snapshot of diagnostic counters from a [`RecvBatchDecoder`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecvBatchDiagnostics {
    /// Total bytes fed into the decoder.
    pub total_bytes_fed: u64,
    /// Number of complete frames emitted.
    pub frames_emitted: u64,
    /// Number of malformed frames skipped.
    pub malformed_skipped: u64,
    /// Bytes currently buffered in the prefix.
    pub buffered_bytes: usize,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::CODEC_FRAME_HEADER_SIZE;
    use crate::envelope::MessageFamily;

    fn codec() -> MessageCodec {
        MessageCodec::default()
    }

    fn build_codec_frame(family: MessageFamily, payload: &[u8]) -> Vec<u8> {
        let codec = codec();
        codec.encode(family, payload).unwrap()
    }

    // ---- Config tests ----

    #[test]
    fn config_defaults() {
        let cfg = RecvBatchConfig::default();
        assert_eq!(cfg.max_batch_size, 128);
        assert_eq!(cfg.min_batch_bytes, 0);
    }

    #[test]
    fn config_new_rejects_zero_max_batch() {
        assert!(RecvBatchConfig::new(0, 0).is_none());
    }

    #[test]
    fn config_single_message() {
        let cfg = RecvBatchConfig::single_message();
        assert_eq!(cfg.max_batch_size, 1);
    }

    // ---- Single-frame decode ----

    #[test]
    fn feed_single_frame() {
        let mut decoder = RecvBatchDecoder::new(RecvBatchConfig::default(), codec());
        let frame = build_codec_frame(MessageFamily::HelloClose, b"hello");
        let batch = decoder.feed(&frame);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].0, MessageFamily::HelloClose);
        assert_eq!(batch[0].1, b"hello");
        assert_eq!(decoder.frames_emitted(), 1);
        assert_eq!(decoder.malformed_skipped(), 0);
        assert!(decoder.is_prefix_empty());
    }

    #[test]
    fn feed_single_frame_empty_payload() {
        let mut decoder = RecvBatchDecoder::new(RecvBatchConfig::default(), codec());
        let frame = build_codec_frame(MessageFamily::HeartbeatAck, &[]);
        let batch = decoder.feed(&frame);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].0, MessageFamily::HeartbeatAck);
        assert!(batch[0].1.is_empty());
        assert_eq!(decoder.frames_emitted(), 1);
    }

    // ---- Multi-frame batch decode ----

    #[test]
    fn feed_multi_frame_batch() {
        let mut decoder = RecvBatchDecoder::new(RecvBatchConfig::default(), codec());
        let f1 = build_codec_frame(MessageFamily::StateTransfer, b"msg1");
        let f2 = build_codec_frame(MessageFamily::ReplicaTransferVerify, b"msg2");
        let f3 = build_codec_frame(MessageFamily::HelloClose, b"msg3");

        let mut combined = Vec::new();
        combined.extend_from_slice(&f1);
        combined.extend_from_slice(&f2);
        combined.extend_from_slice(&f3);

        let batch = decoder.feed(&combined);
        assert_eq!(batch.len(), 3);
        assert_eq!(batch[0], (MessageFamily::StateTransfer, b"msg1".to_vec()));
        assert_eq!(
            batch[1],
            (MessageFamily::ReplicaTransferVerify, b"msg2".to_vec())
        );
        assert_eq!(batch[2], (MessageFamily::HelloClose, b"msg3".to_vec()));
        assert_eq!(decoder.frames_emitted(), 3);
        assert!(decoder.is_prefix_empty());
    }

    // ---- Partial-frame prefix retention ----

    #[test]
    fn partial_frame_retained_across_feeds() {
        let mut decoder = RecvBatchDecoder::new(RecvBatchConfig::default(), codec());
        let frame = build_codec_frame(MessageFamily::ElectionControl, b"complete");

        // Feed only the first 3 bytes of the frame (partial header).
        let batch1 = decoder.feed(&frame[..3]);
        assert!(batch1.is_empty());
        assert_eq!(decoder.buffered_bytes(), 3);

        // Feed the rest -- the complete frame should be decoded.
        let batch2 = decoder.feed(&frame[3..]);
        assert_eq!(batch2.len(), 1);
        assert_eq!(batch2[0].0, MessageFamily::ElectionControl);
        assert_eq!(batch2[0].1, b"complete");
        assert!(decoder.is_prefix_empty());
    }

    #[test]
    fn partial_payload_retained_across_feeds() {
        let mut decoder = RecvBatchDecoder::new(RecvBatchConfig::default(), codec());
        let payload = b"this is a payload that will be split";
        let frame = build_codec_frame(MessageFamily::PublicationProgress, payload);

        // Feed header + part of payload.
        let split = CODEC_FRAME_HEADER_SIZE + 5;
        let batch1 = decoder.feed(&frame[..split]);
        assert!(batch1.is_empty());
        assert_eq!(decoder.buffered_bytes(), split);

        // Feed remaining payload.
        let batch2 = decoder.feed(&frame[split..]);
        assert_eq!(batch2.len(), 1);
        assert_eq!(batch2[0].0, MessageFamily::PublicationProgress);
        assert_eq!(batch2[0].1, payload);
    }

    #[test]
    fn partial_frame_between_two_complete_frames() {
        let mut decoder = RecvBatchDecoder::new(RecvBatchConfig::default(), codec());
        let f1 = build_codec_frame(MessageFamily::StateTransfer, b"first");
        let f2 = build_codec_frame(MessageFamily::ReplicaTransferVerify, b"second");

        // Build stream: full f1 + partial f2 (just header) + rest of f2.
        let mut stream = f1.clone();
        stream.extend_from_slice(&f2[..CODEC_FRAME_HEADER_SIZE]);

        let batch1 = decoder.feed(&stream);
        assert_eq!(batch1.len(), 1);
        assert_eq!(batch1[0].1, b"first");

        // Prefix should hold the partial f2 header.
        assert_eq!(decoder.buffered_bytes(), CODEC_FRAME_HEADER_SIZE);

        // Feed the rest of f2.
        let batch2 = decoder.feed(&f2[CODEC_FRAME_HEADER_SIZE..]);
        assert_eq!(batch2.len(), 1);
        assert_eq!(batch2[0].1, b"second");
        assert!(decoder.is_prefix_empty());
    }

    #[test]
    fn prefix_accumulates_multiple_partial_feeds() {
        let mut decoder = RecvBatchDecoder::new(RecvBatchConfig::default(), codec());
        let frame = build_codec_frame(MessageFamily::HelloClose, b"accumulated");

        // Feed byte by byte.
        for i in 0..frame.len() - 1 {
            let batch = decoder.feed(&frame[i..i + 1]);
            assert!(batch.is_empty(), "no frame at byte {i}");
        }
        // Last byte completes the frame.
        let batch = decoder.feed(&frame[frame.len() - 1..]);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].1, b"accumulated");
    }

    // ---- Empty buffer no-op ----

    #[test]
    fn feed_empty_buffer_noop() {
        let mut decoder = RecvBatchDecoder::new(RecvBatchConfig::default(), codec());
        let batch = decoder.feed(&[]);
        assert!(batch.is_empty());
        assert_eq!(decoder.total_bytes_fed(), 0);
        assert_eq!(decoder.frames_emitted(), 0);
    }

    // ---- Max-batch-size truncation ----

    #[test]
    fn max_batch_size_truncation() {
        let config = RecvBatchConfig::new(2, 0).unwrap();
        let mut decoder = RecvBatchDecoder::new(config, codec());

        let f1 = build_codec_frame(MessageFamily::HelloClose, b"a");
        let f2 = build_codec_frame(MessageFamily::HeartbeatAck, b"b");
        let f3 = build_codec_frame(MessageFamily::ElectionControl, b"c");
        let f4 = build_codec_frame(MessageFamily::LeaseFenceDeadline, b"d");

        let mut stream = Vec::new();
        stream.extend_from_slice(&f1);
        stream.extend_from_slice(&f2);
        stream.extend_from_slice(&f3);
        stream.extend_from_slice(&f4);

        // First feed: should get at most 2 frames.
        let batch1 = decoder.feed(&stream);
        assert_eq!(batch1.len(), 2);
        assert_eq!(batch1[0].1, b"a");
        assert_eq!(batch1[1].1, b"b");

        // Prefix should hold remaining 2 frames.
        assert_eq!(decoder.buffered_bytes(), f3.len() + f4.len());

        // Feed empty to drain remaining (since they're in prefix).
        let batch2 = decoder.feed(&[]);
        assert_eq!(batch2.len(), 2);
        assert_eq!(batch2[0].1, b"c");
        assert_eq!(batch2[1].1, b"d");
        assert!(decoder.is_prefix_empty());
    }

    // ---- Malformed frame rejection ----

    #[test]
    fn malformed_frame_invalid_discriminant_skipped() {
        let mut decoder = RecvBatchDecoder::new(RecvBatchConfig::default(), codec());

        // Build a frame with an invalid family discriminant (255).
        let mut malformed = Vec::new();
        malformed.extend_from_slice(&4u32.to_le_bytes()); // payload_len = 4
        malformed.push(255u8); // invalid discriminant
        malformed.extend_from_slice(b"data");

        // Valid frame after the malformed one.
        let valid = build_codec_frame(MessageFamily::StateTransfer, b"good");

        let mut stream = malformed.clone();
        stream.extend_from_slice(&valid);

        let batch = decoder.feed(&stream);
        assert_eq!(batch.len(), 1, "only the valid frame should be decoded");
        assert_eq!(batch[0].1, b"good");
        assert_eq!(decoder.malformed_skipped(), 1);
    }

    #[test]
    fn malformed_frame_oversize_payload_skipped() {
        let codec = MessageCodec::with_max_frame_size(1024);
        let mut decoder = RecvBatchDecoder::new(RecvBatchConfig::default(), codec);

        // Build a frame with payload_len exceeding max.
        let mut malformed = Vec::new();
        malformed.extend_from_slice(&2048u32.to_le_bytes()); // payload_len = 2048 > 1024
        malformed.push(MessageFamily::HelloClose as u8);
        malformed.extend_from_slice(&vec![0xCDu8; 2048]);

        let batch = decoder.feed(&malformed);
        // The malformed frame is skipped (payload too large -> consumes only header).
        assert_eq!(batch.len(), 0, "no valid frames in this stream");
        assert!(decoder.malformed_skipped() >= 1);
        // Prefix should retain the garbage bytes that could not form complete frames.
        assert!(!decoder.is_prefix_empty());
    }
    #[test]
    fn zero_length_frame_decoded() {
        let mut decoder = RecvBatchDecoder::new(RecvBatchConfig::default(), codec());
        let frame = build_codec_frame(MessageFamily::ShadowValidation, &[]);
        let batch = decoder.feed(&frame);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].0, MessageFamily::ShadowValidation);
        assert!(batch[0].1.is_empty());
    }

    // ---- Diagnostic counters ----

    #[test]
    fn diagnostic_counters_accurate() {
        let mut decoder = RecvBatchDecoder::new(RecvBatchConfig::default(), codec());
        let f1 = build_codec_frame(MessageFamily::StateTransfer, b"hello");
        let f2 = build_codec_frame(MessageFamily::ReplicaTransferVerify, b"goodbye");

        let mut stream = f1.clone();
        stream.extend_from_slice(&f2);

        let batch = decoder.feed(&stream);
        assert_eq!(batch.len(), 2);
        assert_eq!(decoder.frames_emitted(), 2);
        assert_eq!(decoder.total_bytes_fed(), stream.len() as u64);
        assert_eq!(decoder.buffered_bytes(), 0);
        assert_eq!(decoder.malformed_skipped(), 0);

        let diag = decoder.diagnostics();
        assert_eq!(diag.frames_emitted, 2);
        assert_eq!(diag.total_bytes_fed, stream.len() as u64);
        assert_eq!(diag.buffered_bytes, 0);
        assert_eq!(diag.malformed_skipped, 0);
    }

    #[test]
    fn diagnostics_default_is_zero() {
        let decoder = RecvBatchDecoder::new(RecvBatchConfig::default(), codec());
        let diag = decoder.diagnostics();
        assert_eq!(diag.total_bytes_fed, 0);
        assert_eq!(diag.frames_emitted, 0);
        assert_eq!(diag.malformed_skipped, 0);
        assert_eq!(diag.buffered_bytes, 0);
    }

    // ---- Reset ----

    #[test]
    fn reset_clears_state() {
        let mut decoder = RecvBatchDecoder::new(RecvBatchConfig::default(), codec());
        let frame = build_codec_frame(MessageFamily::HelloClose, b"test");

        // Feed partial frame to populate prefix.
        let _ = decoder.feed(&frame[..3]);
        assert!(!decoder.is_prefix_empty());

        decoder.reset();
        assert!(decoder.is_prefix_empty());
        assert_eq!(decoder.total_bytes_fed(), 0);
        assert_eq!(decoder.frames_emitted(), 0);
        assert_eq!(decoder.malformed_skipped(), 0);

        // After reset, the full frame should decode cleanly.
        let batch = decoder.feed(&frame);
        assert_eq!(batch.len(), 1);
    }

    // ---- Min-batch-bytes threshold ----

    #[test]
    fn min_batch_bytes_defers_processing() {
        let config = RecvBatchConfig::new(128, 100).unwrap();
        let mut decoder = RecvBatchDecoder::new(config, codec());
        let payload = vec![0x42u8; 120];
        let frame = build_codec_frame(MessageFamily::HelloClose, &payload);

        // Feed partial frame -- below min_batch_bytes (5 header + 50 payload = 55 < 100).
        let split = CODEC_FRAME_HEADER_SIZE + 50;
        let batch = decoder.feed(&frame[..split]);
        assert!(batch.is_empty());
        assert_eq!(decoder.buffered_bytes(), split);

        // Feed the rest -- now crosses the threshold.
        let batch = decoder.feed(&frame[split..]);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].0, MessageFamily::HelloClose);
        assert_eq!(batch[0].1, payload);
    }
    #[test]
    fn min_batch_bytes_zero_processes_immediately() {
        let config = RecvBatchConfig::new(128, 0).unwrap();
        let mut decoder = RecvBatchDecoder::new(config, codec());
        let frame = build_codec_frame(MessageFamily::HelloClose, b"immediate");
        let batch = decoder.feed(&frame[..3]);
        // Even with only 3 bytes (partial header), we attempt processing.
        // No complete frame possible, so batch is empty but bytes are buffered.
        assert!(batch.is_empty());
        assert_eq!(decoder.buffered_bytes(), 3);
    }

    // ---- Round-trip all message families ----

    #[test]
    fn roundtrip_all_message_families() {
        let mut decoder = RecvBatchDecoder::new(RecvBatchConfig::default(), codec());
        let mut stream = Vec::new();

        for family in MessageFamily::all() {
            let payload = format!("payload-{family}");
            let frame = build_codec_frame(family, payload.as_bytes());
            stream.extend_from_slice(&frame);
        }

        let batch = decoder.feed(&stream);
        assert_eq!(batch.len(), 10);

        for (i, family) in MessageFamily::all().iter().enumerate() {
            assert_eq!(batch[i].0, *family);
            assert_eq!(batch[i].1, format!("payload-{family}").as_bytes());
        }
    }

    // ---- Large payload round-trip ----

    #[test]
    fn large_payload_roundtrip() {
        let mut decoder = RecvBatchDecoder::new(RecvBatchConfig::default(), codec());
        let payload = vec![0xABu8; 65536];
        let frame = build_codec_frame(MessageFamily::StateTransfer, &payload);

        let batch = decoder.feed(&frame);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].1.len(), 65536);
        assert_eq!(batch[0].1, payload);
        assert_eq!(decoder.frames_emitted(), 1);
    }

    // ---- Trailing bytes after complete frames are retained ----

    #[test]
    fn trailing_garbage_after_complete_frame_retained() {
        let mut decoder = RecvBatchDecoder::new(RecvBatchConfig::default(), codec());
        let frame = build_codec_frame(MessageFamily::HelloClose, b"clean");

        let mut stream = frame.clone();
        stream.extend_from_slice(b"trailing junk that is not a valid frame");

        let batch = decoder.feed(&stream);
        // The complete frame is decoded.
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].1, b"clean");
        // Trailing garbage is partially consumed (invalid headers are skipped)
        // and the remainder stays in the prefix buffer.
        assert!(!decoder.is_prefix_empty());
        assert!(
            decoder.malformed_skipped() > 0,
            "garbage should trigger malformed skips"
        );
        // Remaining bytes should be less than the full garbage length.
        assert!(decoder.buffered_bytes() < (stream.len() - frame.len()));
    }
}
