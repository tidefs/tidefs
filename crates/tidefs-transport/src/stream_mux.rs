// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport stream multiplexer with per-stream sequencing and backpressure
//! signaling.
//!
//! The stream multiplexer enables multiple independent logical streams
//! (membership, control-plane, data transfer) to share a single transport
//! connection. Each stream has its own monotonic sequence number space,
//! lifecycle state machine, and backpressure propagation.
//!
//! ## Frame layout
//!
//! ```text
//! [magic:4][stream_id:2 LE][sequence:8 LE][flags:1][payload_length:4 LE]
//! [payload:variable]
//! ```
//!
//! The mux frame carries routing and ordering metadata only. Authenticity and
//! integrity are provided by the surrounding transport/session envelope.
//!
//! ## Flag semantics
//!
//! | Flag | Bit   | Meaning |
//! |------|-------|---------|
//! | SYN  | 0x01  | Open a new stream |
//! | FIN  | 0x02  | Graceful close of stream |
//! | DATA | 0x04  | Frame carries payload data |
//! | RST  | 0x08  | Force-reset stream immediately |
//! | ACK  | 0x10  | Acknowledgment (combined with SYN or FIN) |
//!
//! ## Stream lifecycle state machine
//!
//! ```text
//! Opening --[SYN+ACK]--> Active
//!                           |
//!                           +--[FIN]--> Closing --[FIN+ACK]--> Closed
//!                           |
//!                           +--[RST]--> Closed
//! ```

use bytes::Bytes;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Magic bytes for stream-mux frames: "VSMX".
pub const STREAM_MUX_MAGIC: [u8; 4] = [b'V', b'S', b'M', b'X'];

/// Fixed header size: magic(4) + stream_id(2) + seq(8) + flags(1) + payload_len(4).
pub const STREAM_MUX_HEADER_SIZE: usize = 19;

/// Maximum concurrent streams.
pub const MAX_STREAMS: u16 = 256;

/// Default max payload per DATA frame.
pub const DEFAULT_MAX_PAYLOAD: u32 = 65536;

pub const FLAG_SYN: u8 = 0x01;
pub const FLAG_FIN: u8 = 0x02;
pub const FLAG_DATA: u8 = 0x04;
pub const FLAG_RST: u8 = 0x08;
pub const FLAG_ACK: u8 = 0x10;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamMuxError {
    FrameTooShort {
        len: usize,
    },
    FrameLengthMismatch {
        len: usize,
        expected: usize,
    },
    InvalidMagic,
    StreamNotFound {
        stream_id: u16,
    },
    StreamLimitExceeded,
    WrongState {
        stream_id: u16,
        expected: StreamState,
        actual: StreamState,
    },
    SequenceGap {
        stream_id: u16,
        expected: u64,
        received: u64,
    },
    PayloadTooLarge {
        len: u32,
        max: u32,
    },
    StreamReset {
        stream_id: u16,
    },
    StreamClosed {
        stream_id: u16,
    },
}

impl std::fmt::Display for StreamMuxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FrameTooShort { len } => write!(f, "frame too short: {len} bytes"),
            Self::FrameLengthMismatch { len, expected } => {
                write!(
                    f,
                    "frame length mismatch: got {len} bytes, expected {expected}"
                )
            }
            Self::InvalidMagic => write!(f, "invalid magic bytes"),
            Self::StreamNotFound { stream_id } => write!(f, "stream {stream_id} not found"),
            Self::StreamLimitExceeded => write!(f, "max streams ({MAX_STREAMS}) exceeded"),
            Self::WrongState {
                stream_id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "stream {stream_id}: expected {expected:?}, actual {actual:?}"
                )
            }
            Self::SequenceGap {
                stream_id,
                expected,
                received,
            } => {
                write!(
                    f,
                    "stream {stream_id}: seq gap expected {expected} got {received}"
                )
            }
            Self::PayloadTooLarge { len, max } => write!(f, "payload {len} > max {max}"),
            Self::StreamReset { stream_id } => write!(f, "stream {stream_id} reset"),
            Self::StreamClosed { stream_id } => write!(f, "stream {stream_id} closed"),
        }
    }
}

impl std::error::Error for StreamMuxError {}

// ---------------------------------------------------------------------------
// StreamState
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamState {
    Opening,
    Active,
    Closing,
    Closed,
}

// ---------------------------------------------------------------------------
// StreamMuxFrame
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamMuxFrame {
    pub stream_id: u16,
    pub sequence: u64,
    pub flags: u8,
    pub payload: Bytes,
}

impl StreamMuxFrame {
    pub fn syn(stream_id: u16, sequence: u64) -> Self {
        Self {
            stream_id,
            sequence,
            flags: FLAG_SYN,
            payload: Bytes::new(),
        }
    }
    pub fn syn_ack(stream_id: u16, sequence: u64) -> Self {
        Self {
            stream_id,
            sequence,
            flags: FLAG_SYN | FLAG_ACK,
            payload: Bytes::new(),
        }
    }
    pub fn data(stream_id: u16, sequence: u64, payload: Bytes) -> Self {
        Self {
            stream_id,
            sequence,
            flags: FLAG_DATA,
            payload,
        }
    }
    pub fn fin(stream_id: u16, sequence: u64) -> Self {
        Self {
            stream_id,
            sequence,
            flags: FLAG_FIN,
            payload: Bytes::new(),
        }
    }
    pub fn fin_ack(stream_id: u16, sequence: u64) -> Self {
        Self {
            stream_id,
            sequence,
            flags: FLAG_FIN | FLAG_ACK,
            payload: Bytes::new(),
        }
    }
    pub fn rst(stream_id: u16, sequence: u64) -> Self {
        Self {
            stream_id,
            sequence,
            flags: FLAG_RST,
            payload: Bytes::new(),
        }
    }

    pub fn is_syn(&self) -> bool {
        self.flags & FLAG_SYN != 0
    }
    pub fn is_fin(&self) -> bool {
        self.flags & FLAG_FIN != 0
    }
    pub fn is_data(&self) -> bool {
        self.flags & FLAG_DATA != 0
    }
    pub fn is_rst(&self) -> bool {
        self.flags & FLAG_RST != 0
    }
    pub fn is_ack(&self) -> bool {
        self.flags & FLAG_ACK != 0
    }

    /// Encode this frame into `[header:19][payload:N]`.
    pub fn encode(&self) -> Vec<u8> {
        let payload_len = self.payload.len() as u32;
        let mut buf = Vec::with_capacity(STREAM_MUX_HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&STREAM_MUX_MAGIC);
        buf.extend_from_slice(&self.stream_id.to_le_bytes());
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        buf.push(self.flags);
        buf.extend_from_slice(&payload_len.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode a raw mux frame. Payload integrity belongs to the outer
    /// transport/session envelope, not to this per-stream framing layer.
    pub fn decode(raw: &[u8]) -> Result<Self, StreamMuxError> {
        if raw.len() < STREAM_MUX_HEADER_SIZE {
            return Err(StreamMuxError::FrameTooShort { len: raw.len() });
        }
        if raw[0..4] != STREAM_MUX_MAGIC {
            return Err(StreamMuxError::InvalidMagic);
        }

        let stream_id = u16::from_le_bytes(
            raw[4..6]
                .try_into()
                .map_err(|_| StreamMuxError::InvalidMagic)?,
        );
        let sequence = u64::from_le_bytes(
            raw[6..14]
                .try_into()
                .map_err(|_| StreamMuxError::InvalidMagic)?,
        );
        let flags = raw[14];
        let payload_length = u32::from_le_bytes(
            raw[15..19]
                .try_into()
                .map_err(|_| StreamMuxError::InvalidMagic)?,
        );

        let payload_end = STREAM_MUX_HEADER_SIZE + payload_length as usize;
        if payload_end > raw.len() {
            return Err(StreamMuxError::FrameTooShort { len: raw.len() });
        }
        if payload_end != raw.len() {
            return Err(StreamMuxError::FrameLengthMismatch {
                len: raw.len(),
                expected: payload_end,
            });
        }
        let payload = Bytes::copy_from_slice(&raw[STREAM_MUX_HEADER_SIZE..payload_end]);

        Ok(Self {
            stream_id,
            sequence,
            flags,
            payload,
        })
    }
}

// ---------------------------------------------------------------------------
// StreamMuxConfig
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct StreamMuxConfig {
    pub max_streams: u16,
    pub max_payload: u32,
}

impl Default for StreamMuxConfig {
    fn default() -> Self {
        Self {
            max_streams: MAX_STREAMS,
            max_payload: DEFAULT_MAX_PAYLOAD,
        }
    }
}

// ---------------------------------------------------------------------------
// MuxStream (internal)
// ---------------------------------------------------------------------------

struct MuxStream {
    state: StreamState,
    outbound_seq: u64,
    inbound_seq: u64,
    send_queue: VecDeque<Bytes>,
}

impl MuxStream {
    fn new() -> Self {
        Self {
            state: StreamState::Opening,
            outbound_seq: 1,
            inbound_seq: 1,
            send_queue: VecDeque::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// StreamMuxer
// ---------------------------------------------------------------------------

pub struct StreamMuxer {
    config: StreamMuxConfig,
    streams: BTreeMap<u16, MuxStream>,
    next_stream_id: u16,
    backpressure: Arc<AtomicBool>,
    recv_tx: BTreeMap<u16, tokio::sync::mpsc::UnboundedSender<Result<Bytes, StreamMuxError>>>,
}

impl StreamMuxer {
    pub fn new(config: StreamMuxConfig) -> Self {
        Self {
            config,
            streams: BTreeMap::new(),
            next_stream_id: 1,
            backpressure: Arc::new(AtomicBool::new(false)),
            recv_tx: BTreeMap::new(),
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(StreamMuxConfig::default())
    }

    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    pub fn backpressure_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.backpressure)
    }

    pub fn set_backpressure(&self, on: bool) {
        self.backpressure.store(on, Ordering::SeqCst);
    }

    pub fn is_backpressure(&self) -> bool {
        self.backpressure.load(Ordering::SeqCst)
    }

    // ----------------------------------------------------------------
    // Stream lifecycle
    // ----------------------------------------------------------------

    pub fn open_stream(&mut self) -> Result<StreamHandle, StreamMuxError> {
        let stream_id = self.allocate_stream_id()?;

        let (recv_tx, recv_rx) = tokio::sync::mpsc::unbounded_channel();
        self.streams.insert(stream_id, MuxStream::new());
        self.recv_tx.insert(stream_id, recv_tx);

        Ok(StreamHandle {
            stream_id,
            recv_rx: Some(recv_rx),
            backpressure: Arc::clone(&self.backpressure),
        })
    }

    pub fn accept_stream(&mut self, stream_id: u16) -> Result<StreamHandle, StreamMuxError> {
        if self.streams.contains_key(&stream_id) {
            return Err(StreamMuxError::WrongState {
                stream_id,
                expected: StreamState::Closed,
                actual: self.streams[&stream_id].state,
            });
        }
        if self.streams.len() >= self.config.max_streams as usize {
            return Err(StreamMuxError::StreamLimitExceeded);
        }

        let (recv_tx, recv_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut stream = MuxStream::new();
        stream.state = StreamState::Active;
        self.streams.insert(stream_id, stream);
        self.recv_tx.insert(stream_id, recv_tx);

        Ok(StreamHandle {
            stream_id,
            recv_rx: Some(recv_rx),
            backpressure: Arc::clone(&self.backpressure),
        })
    }

    // ----------------------------------------------------------------
    // Queue data (for synchronous send into muxer)
    // ----------------------------------------------------------------

    pub fn queue_send(&mut self, stream_id: u16, data: Bytes) -> Result<(), StreamMuxError> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(StreamMuxError::StreamNotFound { stream_id })?;
        if stream.state != StreamState::Active {
            return Err(StreamMuxError::WrongState {
                stream_id,
                expected: StreamState::Active,
                actual: stream.state,
            });
        }
        stream.send_queue.push_back(data);
        Ok(())
    }

    // ----------------------------------------------------------------
    // Polling
    // ----------------------------------------------------------------

    pub fn poll_send(&mut self) -> Vec<StreamMuxFrame> {
        let mut frames = Vec::new();

        if self.backpressure.load(Ordering::SeqCst) {
            return frames;
        }

        let ids: Vec<u16> = self.streams.keys().copied().collect();
        for stream_id in ids {
            let stream = match self.streams.get_mut(&stream_id) {
                Some(s) => s,
                None => continue,
            };

            if stream.state != StreamState::Active {
                continue;
            }

            while let Some(payload) = stream.send_queue.pop_front() {
                let chunk = if payload.len() > self.config.max_payload as usize {
                    let rest = payload.slice(self.config.max_payload as usize..);
                    stream.send_queue.push_front(rest);
                    payload.slice(..self.config.max_payload as usize)
                } else {
                    payload
                };

                let seq = stream.outbound_seq;
                stream.outbound_seq = stream.outbound_seq.wrapping_add(1);
                frames.push(StreamMuxFrame::data(stream_id, seq, chunk));

                if frames.len() >= 64 {
                    return frames;
                }
            }
        }

        frames
    }

    // ----------------------------------------------------------------
    // Process inbound frame
    // ----------------------------------------------------------------

    pub fn process_inbound(
        &mut self,
        frame: &StreamMuxFrame,
    ) -> Result<Vec<StreamMuxFrame>, StreamMuxError> {
        let mut responses = Vec::new();

        // Handle SYN
        if frame.is_syn() {
            if self.streams.contains_key(&frame.stream_id) {
                // SYN+ACK on an existing stream: fall through to state machine
                if frame.is_ack() {
                    // handled below via stream state machine
                } else {
                    return Err(StreamMuxError::WrongState {
                        stream_id: frame.stream_id,
                        expected: StreamState::Closed,
                        actual: self.streams[&frame.stream_id].state,
                    });
                }
            } else {
                if self.streams.len() >= self.config.max_streams as usize {
                    return Err(StreamMuxError::StreamLimitExceeded);
                }

                let mut stream = MuxStream::new();
                stream.state = StreamState::Active;
                stream.inbound_seq = frame.sequence.wrapping_add(1);
                self.streams.insert(frame.stream_id, stream);

                if !frame.is_ack() {
                    responses.push(StreamMuxFrame::syn_ack(frame.stream_id, 0));
                }
                return Ok(responses);
            }
        }

        let stream =
            self.streams
                .get_mut(&frame.stream_id)
                .ok_or(StreamMuxError::StreamNotFound {
                    stream_id: frame.stream_id,
                })?;

        // RST handling
        if frame.is_rst() {
            stream.state = StreamState::Closed;
            self.deliver_recv_error(
                frame.stream_id,
                StreamMuxError::StreamReset {
                    stream_id: frame.stream_id,
                },
            );
            return Ok(responses);
        }

        // Collect delivery actions during match, apply after borrow released
        #[derive(Clone, Debug)]
        enum DeliveryAction {
            Data(u16, Bytes),
            Error(u16, StreamMuxError),
        }
        let mut deliveries: Vec<DeliveryAction> = Vec::new();

        match stream.state {
            StreamState::Opening => {
                if frame.is_syn() && frame.is_ack() {
                    stream.state = StreamState::Active;
                    stream.inbound_seq = frame.sequence.wrapping_add(1);
                } else {
                    return Err(StreamMuxError::WrongState {
                        stream_id: frame.stream_id,
                        expected: StreamState::Active,
                        actual: stream.state,
                    });
                }
            }
            StreamState::Active => {
                if frame.is_fin() {
                    stream.state = if frame.is_ack() {
                        StreamState::Closed
                    } else {
                        StreamState::Closing
                    };
                    if !frame.is_ack() {
                        responses.push(StreamMuxFrame::fin_ack(frame.stream_id, 0));
                    }
                    deliveries.push(DeliveryAction::Error(
                        frame.stream_id,
                        StreamMuxError::StreamClosed {
                            stream_id: frame.stream_id,
                        },
                    ));
                } else if frame.is_data() {
                    let expected = stream.inbound_seq;
                    if frame.sequence != expected {
                        return Err(StreamMuxError::SequenceGap {
                            stream_id: frame.stream_id,
                            expected,
                            received: frame.sequence,
                        });
                    }
                    stream.inbound_seq = stream.inbound_seq.wrapping_add(1);
                    deliveries.push(DeliveryAction::Data(frame.stream_id, frame.payload.clone()));
                }
            }
            StreamState::Closing => {
                if frame.is_fin() && frame.is_ack() {
                    stream.state = StreamState::Closed;
                    deliveries.push(DeliveryAction::Error(
                        frame.stream_id,
                        StreamMuxError::StreamClosed {
                            stream_id: frame.stream_id,
                        },
                    ));
                }
                if frame.is_data() {
                    let expected = stream.inbound_seq;
                    if frame.sequence != expected {
                        return Err(StreamMuxError::SequenceGap {
                            stream_id: frame.stream_id,
                            expected,
                            received: frame.sequence,
                        });
                    }
                    stream.inbound_seq = stream.inbound_seq.wrapping_add(1);
                    deliveries.push(DeliveryAction::Data(frame.stream_id, frame.payload.clone()));
                }
            }
            StreamState::Closed => {
                return Err(StreamMuxError::StreamClosed {
                    stream_id: frame.stream_id,
                });
            }
        }
        // Release borrow on streams before delivery
        let _ = stream;

        for action in deliveries {
            match action {
                DeliveryAction::Data(sid, data) => self.deliver_recv_data(sid, data),
                DeliveryAction::Error(sid, err) => self.deliver_recv_error(sid, err),
            }
        }

        Ok(responses)
    }

    // ----------------------------------------------------------------
    // Close / reset
    // ----------------------------------------------------------------

    pub fn close_stream(&mut self, stream_id: u16) -> Result<StreamMuxFrame, StreamMuxError> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(StreamMuxError::StreamNotFound { stream_id })?;

        match stream.state {
            StreamState::Active => {
                let seq = stream.outbound_seq;
                stream.outbound_seq = stream.outbound_seq.wrapping_add(1);
                stream.state = StreamState::Closing;
                Ok(StreamMuxFrame::fin(stream_id, seq))
            }
            StreamState::Opening => {
                stream.state = StreamState::Closed;
                Ok(StreamMuxFrame::rst(stream_id, 0))
            }
            _ => Err(StreamMuxError::StreamClosed { stream_id }),
        }
    }

    pub fn reset_stream(&mut self, stream_id: u16) -> Result<StreamMuxFrame, StreamMuxError> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(StreamMuxError::StreamNotFound { stream_id })?;
        stream.state = StreamState::Closed;
        self.deliver_recv_error(stream_id, StreamMuxError::StreamReset { stream_id });
        Ok(StreamMuxFrame::rst(stream_id, 0))
    }

    pub fn shutdown_all(&mut self) -> Vec<StreamMuxFrame> {
        let ids: Vec<u16> = self.streams.keys().copied().collect();
        let mut frames = Vec::new();
        for id in ids {
            if let Some(stream) = self.streams.get_mut(&id) {
                stream.state = StreamState::Closed;
                self.deliver_recv_error(id, StreamMuxError::StreamReset { stream_id: id });
                frames.push(StreamMuxFrame::rst(id, 0));
            }
        }
        frames
    }

    pub fn stream_state(&self, stream_id: u16) -> Option<StreamState> {
        self.streams.get(&stream_id).map(|s| s.state)
    }

    // ----------------------------------------------------------------
    // Internal
    // ----------------------------------------------------------------

    fn allocate_stream_id(&mut self) -> Result<u16, StreamMuxError> {
        if self.streams.len() >= self.config.max_streams as usize {
            return Err(StreamMuxError::StreamLimitExceeded);
        }
        let start = self.next_stream_id;
        loop {
            if !self.streams.contains_key(&self.next_stream_id) {
                let id = self.next_stream_id;
                self.next_stream_id = self.next_stream_id.wrapping_add(1);
                if self.next_stream_id == 0 {
                    self.next_stream_id = 1;
                }
                return Ok(id);
            }
            self.next_stream_id = self.next_stream_id.wrapping_add(1);
            if self.next_stream_id == 0 {
                self.next_stream_id = 1;
            }
            if self.next_stream_id == start {
                return Err(StreamMuxError::StreamLimitExceeded);
            }
        }
    }

    fn deliver_recv_data(&mut self, stream_id: u16, data: Bytes) {
        if let Some(tx) = self.recv_tx.get(&stream_id) {
            let _ = tx.send(Ok(data));
        }
    }

    fn deliver_recv_error(&mut self, stream_id: u16, err: StreamMuxError) {
        if let Some(tx) = self.recv_tx.remove(&stream_id) {
            let _ = tx.send(Err(err));
        }
    }
}

// ---------------------------------------------------------------------------
// StreamHandle
// ---------------------------------------------------------------------------

pub struct StreamHandle {
    pub stream_id: u16,
    recv_rx: Option<tokio::sync::mpsc::UnboundedReceiver<Result<Bytes, StreamMuxError>>>,
    backpressure: Arc<AtomicBool>,
}

impl StreamHandle {
    pub async fn recv(&mut self) -> Option<Result<Bytes, StreamMuxError>> {
        match &mut self.recv_rx {
            Some(rx) => rx.recv().await,
            None => None,
        }
    }

    pub fn is_backpressure(&self) -> bool {
        self.backpressure.load(Ordering::SeqCst)
    }

    pub fn close(mut self) {
        self.recv_rx.take();
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------------------------------------------------------
    // StreamMuxFrame encode/decode round-trip
    // ----------------------------------------------------------------

    #[test]
    fn frame_encode_decode_data() {
        let payload = Bytes::copy_from_slice(b"hello multiplexer");
        let frame = StreamMuxFrame::data(42, 7, payload.clone());
        let encoded = frame.encode();
        let decoded = StreamMuxFrame::decode(&encoded).unwrap();

        assert_eq!(decoded.stream_id, 42);
        assert_eq!(decoded.sequence, 7);
        assert!(decoded.is_data());
        assert!(!decoded.is_syn());
        assert!(!decoded.is_fin());
        assert!(!decoded.is_rst());
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn frame_encode_decode_syn() {
        let frame = StreamMuxFrame::syn(1, 0);
        let encoded = frame.encode();
        let decoded = StreamMuxFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.stream_id, 1);
        assert!(decoded.is_syn());
        assert!(!decoded.is_ack());
    }

    #[test]
    fn frame_encode_decode_syn_ack() {
        let frame = StreamMuxFrame::syn_ack(1, 0);
        let encoded = frame.encode();
        let decoded = StreamMuxFrame::decode(&encoded).unwrap();
        assert!(decoded.is_syn());
        assert!(decoded.is_ack());
    }

    #[test]
    fn frame_encode_decode_fin() {
        let frame = StreamMuxFrame::fin(5, 42);
        let encoded = frame.encode();
        let decoded = StreamMuxFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.stream_id, 5);
        assert_eq!(decoded.sequence, 42);
        assert!(decoded.is_fin());
        assert!(!decoded.is_data());
    }

    #[test]
    fn frame_encode_decode_fin_ack() {
        let frame = StreamMuxFrame::fin_ack(5, 0);
        let encoded = frame.encode();
        let decoded = StreamMuxFrame::decode(&encoded).unwrap();
        assert!(decoded.is_fin());
        assert!(decoded.is_ack());
    }

    #[test]
    fn frame_encode_decode_rst() {
        let frame = StreamMuxFrame::rst(3, 0);
        let encoded = frame.encode();
        let decoded = StreamMuxFrame::decode(&encoded).unwrap();
        assert!(decoded.is_rst());
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn frame_empty_payload() {
        let frame = StreamMuxFrame::data(0, 0, Bytes::new());
        let encoded = frame.encode();
        let decoded = StreamMuxFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.payload.len(), 0);
    }

    // ----------------------------------------------------------------
    // Frame mutation and framing errors
    // ----------------------------------------------------------------

    #[test]
    fn payload_bytes_are_decoded_without_inner_integrity_layer() {
        let frame = StreamMuxFrame::data(1, 1, Bytes::copy_from_slice(b"data"));
        let mut encoded = frame.encode();

        encoded[STREAM_MUX_HEADER_SIZE + 1] ^= 0xFF;

        let decoded = StreamMuxFrame::decode(&encoded).unwrap();
        assert_ne!(decoded.payload, frame.payload);
    }

    #[test]
    fn invalid_magic_detection() {
        let frame = StreamMuxFrame::data(1, 1, Bytes::copy_from_slice(b"data"));
        let mut encoded = frame.encode();

        encoded[0] = 0xFF;

        let result = StreamMuxFrame::decode(&encoded);
        assert!(matches!(result, Err(StreamMuxError::InvalidMagic)));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let frame = StreamMuxFrame::data(1, 1, Bytes::copy_from_slice(b"data"));
        let mut encoded = frame.encode();
        encoded.push(0);

        let result = StreamMuxFrame::decode(&encoded);
        assert!(matches!(
            result,
            Err(StreamMuxError::FrameLengthMismatch { .. })
        ));
    }

    #[test]
    fn too_short_frame() {
        let result = StreamMuxFrame::decode(&[0u8; 10]);
        assert!(matches!(result, Err(StreamMuxError::FrameTooShort { .. })));
    }

    #[test]
    fn empty_frame() {
        let result = StreamMuxFrame::decode(&[]);
        assert!(matches!(result, Err(StreamMuxError::FrameTooShort { .. })));
    }

    // ----------------------------------------------------------------
    // StreamMuxer: open, queue, poll
    // ----------------------------------------------------------------

    #[test]
    fn muxer_open_stream() {
        let mut muxer = StreamMuxer::with_default_config();
        let handle = muxer.open_stream().unwrap();
        assert_eq!(handle.stream_id, 1);
        assert_eq!(muxer.stream_count(), 1);
    }

    #[test]
    fn muxer_queue_send_and_poll() {
        let mut muxer = StreamMuxer::with_default_config();

        // Open a stream and accept it (so it's Active)
        let syn = StreamMuxFrame::syn(1, 0);
        let _ = muxer.process_inbound(&syn).unwrap();
        assert_eq!(muxer.stream_state(1), Some(StreamState::Active));

        // Queue data
        muxer
            .queue_send(1, Bytes::copy_from_slice(b"hello"))
            .unwrap();
        muxer
            .queue_send(1, Bytes::copy_from_slice(b"world"))
            .unwrap();

        // Poll should produce DATA frames
        let frames = muxer.poll_send();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].stream_id, 1);
        assert_eq!(frames[0].sequence, 1);
        assert_eq!(&frames[0].payload[..], b"hello");
        assert_eq!(frames[1].stream_id, 1);
        assert_eq!(frames[1].sequence, 2);
        assert_eq!(&frames[1].payload[..], b"world");
    }

    #[test]
    fn muxer_accept_stream() {
        let mut muxer = StreamMuxer::with_default_config();
        let handle = muxer.accept_stream(7).unwrap();
        assert_eq!(handle.stream_id, 7);
        assert_eq!(muxer.stream_state(7), Some(StreamState::Active));
    }

    // ----------------------------------------------------------------
    // Stream lifecycle: SYN -> SYN+ACK -> Active -> FIN -> FIN+ACK -> Closed
    // ----------------------------------------------------------------

    #[test]
    fn stream_lifecycle_graceful_close() {
        let mut muxer = StreamMuxer::with_default_config();

        // Peer sends SYN
        let syn = StreamMuxFrame::syn(1, 0);
        let responses = muxer.process_inbound(&syn).unwrap();
        assert_eq!(responses.len(), 1);
        assert!(responses[0].is_syn() && responses[0].is_ack());
        assert_eq!(muxer.stream_state(1), Some(StreamState::Active));

        // Queue data on active stream
        muxer
            .queue_send(1, Bytes::copy_from_slice(b"data"))
            .unwrap();
        let frames = muxer.poll_send();
        assert_eq!(frames.len(), 1);
        assert!(frames[0].is_data());

        // Peer sends FIN
        let fin = StreamMuxFrame::fin(1, 1);
        let responses = muxer.process_inbound(&fin).unwrap();
        assert_eq!(responses.len(), 1);
        assert!(responses[0].is_fin() && responses[0].is_ack());

        // Peer sends FIN+ACK
        let fin_ack = StreamMuxFrame::fin_ack(1, 1);
        let responses = muxer.process_inbound(&fin_ack).unwrap();
        assert!(responses.is_empty());
        assert_eq!(muxer.stream_state(1), Some(StreamState::Closed));
    }

    #[test]
    fn stream_reset_via_rst() {
        let mut muxer = StreamMuxer::with_default_config();

        // Open and accept
        muxer.accept_stream(1).unwrap();

        // RST arrives
        let rst = StreamMuxFrame::rst(1, 0);
        let responses = muxer.process_inbound(&rst).unwrap();
        assert!(responses.is_empty());
        assert_eq!(muxer.stream_state(1), Some(StreamState::Closed));
    }

    // ----------------------------------------------------------------
    // Data delivery via recv
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn stream_recv_data() {
        let mut muxer = StreamMuxer::with_default_config();

        // Accept stream
        let mut handle = muxer.accept_stream(1).unwrap();

        // Send a DATA frame on that stream
        let data_frame = StreamMuxFrame::data(1, 1, Bytes::copy_from_slice(b"recv test"));
        let _ = muxer.process_inbound(&data_frame).unwrap();

        // Handle should receive the data
        let result = handle.recv().await;
        assert!(result.is_some());
        let payload = result.unwrap().unwrap();
        assert_eq!(&payload[..], b"recv test");
    }

    #[tokio::test]
    async fn stream_recv_error_on_close() {
        let mut muxer = StreamMuxer::with_default_config();

        // Accept stream
        let mut handle = muxer.accept_stream(1).unwrap();

        // Close stream (FIN -> FIN+ACK)
        let fin = StreamMuxFrame::fin(1, 1);
        let _ = muxer.process_inbound(&fin).unwrap();
        let fin_ack = StreamMuxFrame::fin_ack(1, 1);
        let _ = muxer.process_inbound(&fin_ack).unwrap();

        // recv should return error
        let result = handle.recv().await;
        assert!(result.is_some());
        assert!(result.unwrap().is_err());
    }

    #[tokio::test]
    async fn stream_recv_error_on_rst() {
        let mut muxer = StreamMuxer::with_default_config();
        let mut handle = muxer.accept_stream(1).unwrap();

        let rst = StreamMuxFrame::rst(1, 0);
        let _ = muxer.process_inbound(&rst).unwrap();

        let result = handle.recv().await;
        assert!(result.is_some());
        assert!(result.unwrap().is_err());
    }

    // ----------------------------------------------------------------
    // Backpressure
    // ----------------------------------------------------------------

    #[test]
    fn backpressure_halt_poll_send() {
        let mut muxer = StreamMuxer::with_default_config();

        // Accept stream
        muxer.accept_stream(1).unwrap();
        muxer
            .queue_send(1, Bytes::copy_from_slice(b"data"))
            .unwrap();

        // Without backpressure: poll produces frames
        let frames = muxer.poll_send();
        assert_eq!(frames.len(), 1);

        // No more data
        let frames = muxer.poll_send();
        assert!(frames.is_empty());

        // Queue more data, then enable backpressure
        muxer
            .queue_send(1, Bytes::copy_from_slice(b"more"))
            .unwrap();
        muxer.set_backpressure(true);

        let frames = muxer.poll_send();
        assert!(frames.is_empty());

        // Release backpressure: frames flow again
        muxer.set_backpressure(false);
        let frames = muxer.poll_send();
        assert_eq!(frames.len(), 1);
        assert_eq!(&frames[0].payload[..], b"more");
    }

    #[test]
    fn backpressure_flag_shared() {
        let mut muxer = StreamMuxer::with_default_config();
        muxer.accept_stream(1).unwrap();

        let flag = muxer.backpressure_flag();
        assert!(!flag.load(Ordering::SeqCst));

        muxer.set_backpressure(true);
        assert!(flag.load(Ordering::SeqCst));

        muxer.set_backpressure(false);
        assert!(!flag.load(Ordering::SeqCst));
    }

    // ----------------------------------------------------------------
    // Multiplexed interleaving
    // ----------------------------------------------------------------

    #[test]
    fn multiplexed_four_streams() {
        let mut muxer = StreamMuxer::with_default_config();

        // Accept 4 streams
        for id in 1..=4 {
            muxer.accept_stream(id).unwrap();
        }

        // Queue data on all streams
        muxer.queue_send(1, Bytes::copy_from_slice(b"A1")).unwrap();
        muxer.queue_send(2, Bytes::copy_from_slice(b"B1")).unwrap();
        muxer.queue_send(3, Bytes::copy_from_slice(b"C1")).unwrap();
        muxer.queue_send(4, Bytes::copy_from_slice(b"D1")).unwrap();
        muxer.queue_send(1, Bytes::copy_from_slice(b"A2")).unwrap();
        muxer.queue_send(2, Bytes::copy_from_slice(b"B2")).unwrap();

        let frames = muxer.poll_send();
        // Should produce frames from all streams with correct per-stream sequences
        let mut per_stream: BTreeMap<u16, Vec<(u64, Bytes)>> = BTreeMap::new();
        for f in &frames {
            per_stream
                .entry(f.stream_id)
                .or_default()
                .push((f.sequence, f.payload.clone()));
        }

        assert_eq!(per_stream[&1].len(), 2);
        assert_eq!(per_stream[&2].len(), 2);
        assert_eq!(per_stream[&3].len(), 1);
        assert_eq!(per_stream[&4].len(), 1);

        // Per-stream sequences should be monotonic
        for (sid, items) in &per_stream {
            let mut prev: Option<u64> = None;
            for (seq, _) in items {
                if let Some(p) = prev {
                    assert!(seq > &p, "stream {sid}: seq {seq} not > {p}");
                }
                prev = Some(*seq);
            }
        }
    }

    #[test]
    fn multiplexed_data_delivery_per_stream() {
        let mut muxer = StreamMuxer::with_default_config();

        // Accept 3 streams
        muxer.accept_stream(1).unwrap();
        muxer.accept_stream(2).unwrap();
        muxer.accept_stream(3).unwrap();

        // Deliver data on each stream in interleaved order
        muxer
            .process_inbound(&StreamMuxFrame::data(1, 1, Bytes::copy_from_slice(b"s1-a")))
            .unwrap();
        muxer
            .process_inbound(&StreamMuxFrame::data(2, 1, Bytes::copy_from_slice(b"s2-a")))
            .unwrap();
        muxer
            .process_inbound(&StreamMuxFrame::data(1, 2, Bytes::copy_from_slice(b"s1-b")))
            .unwrap();
        muxer
            .process_inbound(&StreamMuxFrame::data(3, 1, Bytes::copy_from_slice(b"s3-a")))
            .unwrap();
        muxer
            .process_inbound(&StreamMuxFrame::data(2, 2, Bytes::copy_from_slice(b"s2-b")))
            .unwrap();

        // Each stream's inbound_seq advanced independently
        assert_eq!(muxer.stream_state(1), Some(StreamState::Active));
        assert_eq!(muxer.stream_state(2), Some(StreamState::Active));
        assert_eq!(muxer.stream_state(3), Some(StreamState::Active));
    }

    // ----------------------------------------------------------------
    // Sequence gap detection
    // ----------------------------------------------------------------

    #[test]
    fn sequence_gap_rejected() {
        let mut muxer = StreamMuxer::with_default_config();
        muxer.accept_stream(1).unwrap();

        // First frame seq=1
        muxer
            .process_inbound(&StreamMuxFrame::data(1, 1, Bytes::copy_from_slice(b"ok")))
            .unwrap();

        // Skip to seq=5
        let result =
            muxer.process_inbound(&StreamMuxFrame::data(1, 5, Bytes::copy_from_slice(b"gap")));
        assert!(matches!(result, Err(StreamMuxError::SequenceGap { .. })));
    }

    // ----------------------------------------------------------------
    // Max stream exhaustion
    // ----------------------------------------------------------------

    #[test]
    fn max_stream_limit() {
        let config = StreamMuxConfig {
            max_streams: 4,
            max_payload: DEFAULT_MAX_PAYLOAD,
        };
        let mut muxer = StreamMuxer::new(config);

        // Open 4 streams
        for _ in 0..4 {
            muxer.open_stream().unwrap();
        }

        // 5th should fail
        let result = muxer.open_stream();
        assert!(matches!(result, Err(StreamMuxError::StreamLimitExceeded)));
    }

    // ----------------------------------------------------------------
    // Wrong state errors
    // ----------------------------------------------------------------

    #[test]
    fn wrong_state_queue_on_closed() {
        let mut muxer = StreamMuxer::with_default_config();
        muxer.open_stream().unwrap(); // stream_id=1

        // Mark stream 1 as Active by receiving SYN+ACK
        let syn_ack = StreamMuxFrame::syn_ack(1, 0);
        muxer.process_inbound(&syn_ack).unwrap();
        assert_eq!(muxer.stream_state(1), Some(StreamState::Active));

        // Close via RST
        muxer.process_inbound(&StreamMuxFrame::rst(1, 0)).unwrap();
        assert_eq!(muxer.stream_state(1), Some(StreamState::Closed));

        // Queue should fail
        let result = muxer.queue_send(1, Bytes::copy_from_slice(b"nope"));
        assert!(result.is_err());
    }

    #[test]
    fn wrong_state_close_twice() {
        let mut muxer = StreamMuxer::with_default_config();
        muxer.accept_stream(1).unwrap();

        // First close
        let fin = muxer.close_stream(1).unwrap();
        assert!(fin.is_fin());

        // Second close on Closing state should fail
        let result = muxer.close_stream(1);
        assert!(result.is_err());
    }

    // ----------------------------------------------------------------
    // Shutdown all
    // ----------------------------------------------------------------

    #[test]
    fn shutdown_all_streams() {
        let mut muxer = StreamMuxer::with_default_config();

        // Accept 3 streams
        muxer.accept_stream(1).unwrap();
        muxer.accept_stream(2).unwrap();
        muxer.accept_stream(3).unwrap();

        let frames = muxer.shutdown_all();
        assert_eq!(frames.len(), 3);
        for f in &frames {
            assert!(f.is_rst());
        }
        assert_eq!(muxer.stream_state(1), Some(StreamState::Closed));
        assert_eq!(muxer.stream_state(2), Some(StreamState::Closed));
        assert_eq!(muxer.stream_state(3), Some(StreamState::Closed));
    }

    // ----------------------------------------------------------------
    // Round-trip: encode poll_send output and decode as process_inbound
    // ----------------------------------------------------------------

    #[test]
    fn round_trip_poll_to_process() {
        let mut muxer = StreamMuxer::with_default_config();

        // Create stream and queue data
        muxer.accept_stream(1).unwrap();
        muxer
            .queue_send(1, Bytes::copy_from_slice(b"round-trip data"))
            .unwrap();

        // Poll send to get encoded frames
        let frames = muxer.poll_send();
        assert_eq!(frames.len(), 1);

        // Encode and decode
        let raw = frames[0].encode();
        let decoded = StreamMuxFrame::decode(&raw).unwrap();
        assert_eq!(decoded.stream_id, 1);
        assert_eq!(decoded.sequence, 1);
        assert!(decoded.is_data());
        assert_eq!(&decoded.payload[..], b"round-trip data");
    }

    // ----------------------------------------------------------------
    // StreamHandle close
    // ----------------------------------------------------------------

    #[test]
    fn handle_close_consumes_channels() {
        let mut muxer = StreamMuxer::with_default_config();
        let handle = muxer.accept_stream(1).unwrap();
        handle.close();
        // Handle consumed; no assertion needed beyond drop
    }

    // ----------------------------------------------------------------
    // Multiple SYNs (duplicate stream)
    // ----------------------------------------------------------------

    #[test]
    fn duplicate_syn_rejected() {
        let mut muxer = StreamMuxer::with_default_config();

        // First SYN
        let syn1 = StreamMuxFrame::syn(1, 0);
        let resp = muxer.process_inbound(&syn1).unwrap();
        assert_eq!(resp.len(), 1);

        // Second SYN for same stream_id should be rejected
        let syn2 = StreamMuxFrame::syn(1, 0);
        let result = muxer.process_inbound(&syn2);
        assert!(result.is_err());
    }

    // ----------------------------------------------------------------
    // StreamNotFound error
    // ----------------------------------------------------------------

    #[test]
    fn data_on_unknown_stream_rejected() {
        let mut muxer = StreamMuxer::with_default_config();

        let data = StreamMuxFrame::data(999, 1, Bytes::copy_from_slice(b"ghost"));
        let result = muxer.process_inbound(&data);
        assert!(matches!(
            result,
            Err(StreamMuxError::StreamNotFound { stream_id: 999 })
        ));
    }

    // ----------------------------------------------------------------
    // Deterministic frame encoding
    // ----------------------------------------------------------------

    #[test]
    fn frame_encoding_is_deterministic() {
        let frame = StreamMuxFrame::data(1, 1, Bytes::copy_from_slice(b"deterministic"));
        let encoded1 = frame.encode();
        let encoded2 = frame.encode();
        assert_eq!(encoded1, encoded2);
        let decoded1 = StreamMuxFrame::decode(&encoded1).unwrap();
        let decoded2 = StreamMuxFrame::decode(&encoded2).unwrap();
        assert_eq!(decoded1.payload, decoded2.payload);
    }

    // ----------------------------------------------------------------
    // Large payload (near max)
    // ----------------------------------------------------------------

    #[test]
    fn large_payload_round_trip() {
        let payload = Bytes::from(vec![0xAB; 65535]);
        let frame = StreamMuxFrame::data(1, 1, payload.clone());
        let encoded = frame.encode();
        let decoded = StreamMuxFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.payload, payload);
    }

    // ----------------------------------------------------------------
    // Poll limit (64 frames per call)
    // ----------------------------------------------------------------

    #[test]
    fn poll_send_limit_64_frames() {
        let mut muxer = StreamMuxer::with_default_config();
        muxer.accept_stream(1).unwrap();

        // Queue 100 small payloads
        for i in 0..100 {
            muxer.queue_send(1, Bytes::from(vec![i as u8])).unwrap();
        }

        // First poll should produce at most 64
        let frames = muxer.poll_send();
        assert_eq!(frames.len(), 64);

        // Second poll should produce remaining 36
        let frames2 = muxer.poll_send();
        assert_eq!(frames2.len(), 36);
    }
}
