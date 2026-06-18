// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Chunk encoder: splits objects into fixed-size chunks, computes BLAKE3-256
//! per-chunk hashes, and emits length-delimited wire-format frames.
//!
//! This module provides the high-level encoding engine that bridges the
//! low-level VFSSEND2 stream types with transport-agnostic chunk delivery
//! via `tidefs_chunk_shipper`.

use crate::{Bytes32, LineageManifest, SendStreamError};
use std::fmt;

// ---------------------------------------------------------------------------
// Frame header constants
// ---------------------------------------------------------------------------

/// Magic bytes for chunk frame identification: `VCHNK\0\0\0`.
const FRAME_MAGIC: [u8; 8] = *b"VCHNK\0\0\0";

/// Current frame wire version.
const FRAME_VERSION: u16 = 1;

/// Fixed frame header size: magic(8) + version(2) + frame_len(4) = 14.
const FRAME_HEADER_SIZE: usize = 14;

/// Magic bytes for send-lineage manifest frames: `VMANF\0\0\0`.
const MANIFEST_FRAME_MAGIC: [u8; 8] = *b"VMANF\0\0\0";

/// Current send-lineage manifest frame wire version.
const MANIFEST_FRAME_VERSION: u16 = 1;

/// Fixed manifest frame header size: magic(8) + version(2) + frame_len(4) = 14.
const MANIFEST_FRAME_HEADER_SIZE: usize = 14;

// ---------------------------------------------------------------------------
// ChunkFrame
// ---------------------------------------------------------------------------

/// A single chunk frame in the wire format.
///
/// Each frame is self-describing: a fixed header followed by the
/// variable-length body. The body contains the object id, chunk sequence
/// number, byte offset, payload length, BLAKE3-256 hash, and payload data.
#[derive(Clone, Debug, PartialEq)]
pub struct ChunkFrame {
    /// Object identifier (stable 256-bit id).
    pub object_id: Bytes32,
    /// Zero-based chunk sequence number within the object.
    pub chunk_seq: u32,
    /// Byte offset of this chunk within the object.
    pub offset: u64,
    /// BLAKE3-256 hash of the payload.
    pub blake3_hash: Bytes32,
    /// Raw payload bytes for this chunk.
    pub payload: Vec<u8>,
}

impl ChunkFrame {
    /// Create a new chunk frame, computing the BLAKE3 hash.
    pub fn new(object_id: Bytes32, chunk_seq: u32, offset: u64, payload: Vec<u8>) -> Self {
        let blake3_hash = crate::blake3_digest(&payload);
        Self {
            object_id,
            chunk_seq,
            offset,
            blake3_hash,
            payload,
        }
    }

    /// Encode this chunk frame to wire format.
    ///
    /// Returns the complete frame bytes: `[header | body]`.
    pub fn encode(&self) -> Vec<u8> {
        let body = self.encode_body();
        let frame_len = body.len() as u32;
        let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + body.len());
        frame.extend_from_slice(&FRAME_MAGIC);
        frame.extend_from_slice(&FRAME_VERSION.to_be_bytes());
        frame.extend_from_slice(&frame_len.to_be_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    /// Encode the frame body (object_id + chunk_seq + offset + payload_len + hash + payload).
    fn encode_body(&self) -> Vec<u8> {
        let payload_len = self.payload.len() as u32;
        let mut body = Vec::with_capacity(32 + 4 + 8 + 4 + 32 + self.payload.len());
        body.extend_from_slice(&self.object_id);
        body.extend_from_slice(&self.chunk_seq.to_be_bytes());
        body.extend_from_slice(&self.offset.to_be_bytes());
        body.extend_from_slice(&payload_len.to_be_bytes());
        body.extend_from_slice(&self.blake3_hash);
        body.extend_from_slice(&self.payload);
        body
    }

    /// Decode a chunk frame from wire format bytes.
    ///
    /// Returns `None` if the frame is malformed (wrong magic, version, or
    /// truncation).
    pub fn decode(mut bytes: &[u8]) -> Option<Self> {
        if bytes.len() < FRAME_HEADER_SIZE {
            return None;
        }
        // Read and verify magic
        let magic: [u8; 8] = bytes[..8].try_into().ok()?;
        if magic != FRAME_MAGIC {
            return None;
        }
        bytes = &bytes[8..];

        // Read and verify version
        let version = u16::from_be_bytes(bytes[..2].try_into().ok()?);
        if version != FRAME_VERSION {
            return None;
        }
        bytes = &bytes[2..];

        // Read frame length
        let frame_len = u32::from_be_bytes(bytes[..4].try_into().ok()?) as usize;
        bytes = &bytes[4..];

        if bytes.len() < frame_len {
            return None;
        }
        bytes = &bytes[..frame_len];

        // Read body fields
        if bytes.len() < 32 + 4 + 8 + 4 + 32 {
            return None;
        }
        let object_id: Bytes32 = bytes[..32].try_into().ok()?;
        bytes = &bytes[32..];

        let chunk_seq = u32::from_be_bytes(bytes[..4].try_into().ok()?);
        bytes = &bytes[4..];

        let offset = u64::from_be_bytes(bytes[..8].try_into().ok()?);
        bytes = &bytes[8..];

        let payload_len = u32::from_be_bytes(bytes[..4].try_into().ok()?) as usize;
        bytes = &bytes[4..];

        let blake3_hash: Bytes32 = bytes[..32].try_into().ok()?;
        bytes = &bytes[32..];

        if bytes.len() < payload_len {
            return None;
        }
        let payload = bytes[..payload_len].to_vec();

        // Verify hash
        let computed = crate::blake3_digest(&payload);
        if computed != blake3_hash {
            return None;
        }

        Some(Self {
            object_id,
            chunk_seq,
            offset,
            blake3_hash,
            payload,
        })
    }

    /// Verify that this frame's BLAKE3 hash matches its payload.
    pub fn verify(&self) -> bool {
        crate::blake3_digest(&self.payload) == self.blake3_hash
    }
}

/// A length-delimited send-lineage manifest frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineageManifestFrame {
    /// Canonical lineage manifest payload.
    pub manifest: LineageManifest,
    /// BLAKE3 digest of the canonical manifest payload.
    pub manifest_digest: Bytes32,
}

impl LineageManifestFrame {
    /// Create a new manifest frame.
    #[must_use]
    pub fn new(manifest: LineageManifest) -> Self {
        let manifest_digest = manifest.digest();
        Self {
            manifest,
            manifest_digest,
        }
    }

    /// Encode this manifest frame as `[header | manifest_digest | manifest_payload]`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let body = self.encode_body();
        let frame_len = body.len() as u32;
        let mut frame = Vec::with_capacity(MANIFEST_FRAME_HEADER_SIZE + body.len());
        frame.extend_from_slice(&MANIFEST_FRAME_MAGIC);
        frame.extend_from_slice(&MANIFEST_FRAME_VERSION.to_be_bytes());
        frame.extend_from_slice(&frame_len.to_be_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    fn encode_body(&self) -> Vec<u8> {
        let manifest_payload = self.manifest.encode();
        let mut body = Vec::with_capacity(32 + manifest_payload.len());
        body.extend_from_slice(&self.manifest_digest);
        body.extend_from_slice(&manifest_payload);
        body
    }

    /// Decode a manifest frame from wire bytes.
    pub fn decode(mut bytes: &[u8]) -> Result<Self, SendStreamError> {
        if bytes.len() < MANIFEST_FRAME_HEADER_SIZE {
            return Err(SendStreamError::UnexpectedEof);
        }
        let magic: [u8; 8] = bytes[..8]
            .try_into()
            .map_err(|_| SendStreamError::UnexpectedEof)?;
        if magic != MANIFEST_FRAME_MAGIC {
            return Err(SendStreamError::BadMagic);
        }
        bytes = &bytes[8..];

        let version = u16::from_be_bytes(
            bytes[..2]
                .try_into()
                .map_err(|_| SendStreamError::UnexpectedEof)?,
        );
        if version != MANIFEST_FRAME_VERSION {
            return Err(SendStreamError::UnsupportedVersion(version));
        }
        bytes = &bytes[2..];

        let frame_len = u32::from_be_bytes(
            bytes[..4]
                .try_into()
                .map_err(|_| SendStreamError::UnexpectedEof)?,
        ) as usize;
        bytes = &bytes[4..];
        if bytes.len() != frame_len || frame_len < 32 {
            return Err(SendStreamError::UnexpectedEof);
        }

        let manifest_digest: Bytes32 = bytes[..32]
            .try_into()
            .map_err(|_| SendStreamError::UnexpectedEof)?;
        let manifest = LineageManifest::decode_payload(&bytes[32..])?;
        if manifest.digest() != manifest_digest {
            return Err(SendStreamError::RecordChecksumMismatch);
        }
        Ok(Self {
            manifest,
            manifest_digest,
        })
    }

    /// Verify that the stored digest still matches the manifest payload.
    #[must_use]
    pub fn verify(&self) -> bool {
        self.manifest.digest() == self.manifest_digest
    }
}

// ---------------------------------------------------------------------------
// ChunkEncoder
// ---------------------------------------------------------------------------

/// Configurable encoder that splits object data into fixed-size chunks,
/// computes per-chunk BLAKE3-256 hashes, and emits self-describing
/// [`ChunkFrame`]s.
///
/// # Example
///
/// ```rust
/// use tidefs_send_stream::encoder::{ChunkEncoder, ChunkEncoderConfig};
///
/// let config = ChunkEncoderConfig { chunk_size: 1024 };
/// let encoder = ChunkEncoder::new(config);
///
/// let data = vec![0x42u8; 3000];
/// let object_id = [1u8; 32];
/// let frames = encoder.encode_object(object_id, &data);
///
/// assert_eq!(frames.len(), 3); // 1024 + 1024 + 952
/// for f in &frames {
///     assert!(f.verify());
/// }
/// ```
#[derive(Clone, Debug)]
pub struct ChunkEncoder {
    config: ChunkEncoderConfig,
}

/// Configuration for [`ChunkEncoder`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ChunkEncoderConfig {
    /// Maximum payload bytes per chunk.
    ///
    /// Must be at least 1. Default: 65536 (64 KiB).
    pub chunk_size: u32,
}

impl Default for ChunkEncoderConfig {
    fn default() -> Self {
        Self { chunk_size: 65536 }
    }
}

impl ChunkEncoder {
    /// Create a new encoder with the given configuration.
    pub fn new(config: ChunkEncoderConfig) -> Self {
        Self { config }
    }

    /// Returns a copy of the current configuration.
    pub fn config(&self) -> ChunkEncoderConfig {
        self.config
    }

    /// Split an object into chunks, computing BLAKE3-256 per chunk and
    /// emitting self-describing [`ChunkFrame`]s.
    ///
    /// An empty object produces a single frame with an empty payload.
    pub fn encode_object(&self, object_id: Bytes32, data: &[u8]) -> Vec<ChunkFrame> {
        let chunk_size = self.config.chunk_size.max(1) as usize;
        if data.is_empty() {
            return vec![ChunkFrame::new(object_id, 0, 0, Vec::new())];
        }

        let num_chunks = data.len().div_ceil(chunk_size);
        let mut frames = Vec::with_capacity(num_chunks);

        for (i, chunk_bytes) in data.chunks(chunk_size).enumerate() {
            let offset = (i * chunk_size) as u64;
            let frame = ChunkFrame::new(object_id, i as u32, offset, chunk_bytes.to_vec());
            frames.push(frame);
        }

        frames
    }

    /// Compute the number of chunks an object of `data_len` bytes will
    /// produce without actually encoding.
    pub fn chunk_count(&self, data_len: usize) -> usize {
        if data_len == 0 {
            return 1;
        }
        data_len.div_ceil(self.config.chunk_size.max(1) as usize)
    }
}

// ---------------------------------------------------------------------------
// ChunkDecoder
// ---------------------------------------------------------------------------

/// Decodes a stream of raw bytes (e.g., from a transport receive buffer)
/// into individual [`ChunkFrame`]s.
///
/// Frames are extracted by scanning for the magic header. Any bytes before
/// the first valid frame are skipped (which accommodates transport headers
/// or stale partial data). Truncated frames at the end of the buffer are
/// left unconsumed.
pub struct ChunkDecoder;

impl ChunkDecoder {
    /// Decode all complete frames from a byte buffer.
    ///
    /// Returns decoded frames and the number of bytes consumed.
    /// Remaining bytes (if any) are a truncated partial frame.
    pub fn decode_all(mut bytes: &[u8]) -> (Vec<ChunkFrame>, usize) {
        let consumed_start = bytes.len();
        let mut frames = Vec::new();

        while let Some(pos) = bytes
            .windows(FRAME_MAGIC.len())
            .position(|w| w == FRAME_MAGIC)
        {
            // Scan for magic
            bytes = &bytes[pos..];

            if let Some(frame) = ChunkFrame::decode(bytes) {
                let frame_total_len = FRAME_HEADER_SIZE + frame.encode_body().len();
                bytes = &bytes[frame_total_len.min(bytes.len())..];
                frames.push(frame);
            } else {
                // Broken frame. If too short for a complete header, leave
                // unconsumed for the next call (partial frame). Otherwise
                // skip the magic bytes and continue scanning.
                if bytes.len() < FRAME_HEADER_SIZE {
                    break;
                }
                bytes = &bytes[FRAME_MAGIC.len()..];
            }
        }

        let consumed = consumed_start - bytes.len();
        (frames, consumed)
    }
}

// ---------------------------------------------------------------------------
// ChunkEncoderError
// ---------------------------------------------------------------------------

/// Errors that can occur during chunk encoding.
#[derive(Clone, Debug, PartialEq)]
pub enum ChunkEncoderError {
    /// The chunk size is zero (must be at least 1).
    ZeroChunkSize,
    /// A chunk payload exceeds the configured maximum.
    ChunkTooLarge { actual: usize, max: u32 },
}

impl fmt::Display for ChunkEncoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroChunkSize => write!(f, "chunk size must be at least 1"),
            Self::ChunkTooLarge { actual, max } => {
                write!(f, "chunk payload {actual} bytes exceeds max {max}")
            }
        }
    }
}

impl std::error::Error for ChunkEncoderError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn obj_id(b: u8) -> Bytes32 {
        [b; 32]
    }

    fn manifest() -> LineageManifest {
        let header = crate::SendStreamHeader::new([1; 16], [2; 16], [3; 16]);
        LineageManifest::full(&header, [4; 32])
    }

    // -- ChunkFrame encode/decode --

    #[test]
    fn frame_encode_decode_round_trip() {
        let payload = b"hello chunk world".to_vec();
        let frame = ChunkFrame::new(obj_id(1), 0, 0, payload.clone());
        let encoded = frame.encode();
        let decoded = ChunkFrame::decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded.object_id, obj_id(1));
        assert_eq!(decoded.chunk_seq, 0);
        assert_eq!(decoded.offset, 0);
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.blake3_hash, frame.blake3_hash);
    }

    #[test]
    fn frame_decode_rejects_wrong_magic() {
        let payload = b"data".to_vec();
        let frame = ChunkFrame::new(obj_id(1), 0, 0, payload);
        let mut encoded = frame.encode();
        encoded[0] ^= 0xFF;
        assert!(ChunkFrame::decode(&encoded).is_none());
    }

    #[test]
    fn frame_decode_rejects_wrong_version() {
        let payload = b"data".to_vec();
        let frame = ChunkFrame::new(obj_id(1), 0, 0, payload);
        let mut encoded = frame.encode();
        encoded[8] = 99;
        assert!(ChunkFrame::decode(&encoded).is_none());
    }

    #[test]
    fn frame_decode_rejects_truncated_header() {
        let header = &FRAME_MAGIC[..4];
        assert!(ChunkFrame::decode(header).is_none());
    }

    #[test]
    fn frame_decode_rejects_hash_mismatch() {
        let payload = b"original".to_vec();
        let frame = ChunkFrame::new(obj_id(1), 0, 0, payload);
        let mut encoded = frame.encode();
        let hash_start = FRAME_HEADER_SIZE + 32 + 4 + 8 + 4;
        encoded[hash_start] ^= 0xFF;
        assert!(ChunkFrame::decode(&encoded).is_none());
    }

    #[test]
    fn frame_decode_rejects_truncated_body() {
        let frame = ChunkFrame::new(obj_id(1), 0, 0, b"test".to_vec());
        let full = frame.encode();
        let truncated = &full[..full.len() - 2];
        assert!(ChunkFrame::decode(truncated).is_none());
    }

    #[test]
    fn frame_verify_passes() {
        let frame = ChunkFrame::new(obj_id(1), 5, 4096, b"verify me".to_vec());
        assert!(frame.verify());
    }

    #[test]
    fn frame_verify_fails_on_corruption() {
        let mut frame = ChunkFrame::new(obj_id(1), 0, 0, b"data".to_vec());
        frame.payload[0] ^= 0xFF;
        assert!(!frame.verify());
    }

    #[test]
    fn manifest_frame_round_trips_before_data_frames() {
        let frame = LineageManifestFrame::new(manifest());
        let encoded = frame.encode();
        let decoded = LineageManifestFrame::decode(&encoded).unwrap();

        assert_eq!(decoded, frame);
        assert!(decoded.verify());
    }

    // -- ChunkEncoder --

    #[test]
    fn encoder_single_chunk_object() {
        let encoder = ChunkEncoder::new(ChunkEncoderConfig { chunk_size: 1024 });
        let data = vec![0xAAu8; 512];
        let frames = encoder.encode_object(obj_id(1), &data);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].chunk_seq, 0);
        assert_eq!(frames[0].offset, 0);
        assert_eq!(frames[0].payload, data);
        assert!(frames[0].verify());
    }

    #[test]
    fn encoder_multi_chunk_object() {
        let encoder = ChunkEncoder::new(ChunkEncoderConfig { chunk_size: 100 });
        let data = vec![0xBBu8; 250];
        let frames = encoder.encode_object(obj_id(2), &data);
        assert_eq!(frames.len(), 3); // 100 + 100 + 50
        assert_eq!(frames[0].chunk_seq, 0);
        assert_eq!(frames[0].offset, 0);
        assert_eq!(frames[1].chunk_seq, 1);
        assert_eq!(frames[1].offset, 100);
        assert_eq!(frames[2].chunk_seq, 2);
        assert_eq!(frames[2].offset, 200);

        for f in &frames {
            assert!(f.verify());
        }

        let mut reassembled = Vec::new();
        for f in &frames {
            reassembled.extend_from_slice(&f.payload);
        }
        assert_eq!(reassembled, data);
    }

    #[test]
    fn encoder_empty_object() {
        let encoder = ChunkEncoder::new(ChunkEncoderConfig::default());
        let frames = encoder.encode_object(obj_id(3), &[]);
        assert_eq!(frames.len(), 1, "empty object produces one empty frame");
        assert_eq!(frames[0].payload.len(), 0);
        assert!(frames[0].verify());
    }

    #[test]
    fn encoder_exact_chunk_boundary() {
        let encoder = ChunkEncoder::new(ChunkEncoderConfig { chunk_size: 256 });
        let data = vec![0xCCu8; 512];
        let frames = encoder.encode_object(obj_id(4), &data);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].payload.len(), 256);
        assert_eq!(frames[1].payload.len(), 256);
    }

    #[test]
    fn encoder_chunk_count() {
        let encoder = ChunkEncoder::new(ChunkEncoderConfig { chunk_size: 100 });
        assert_eq!(encoder.chunk_count(0), 1);
        assert_eq!(encoder.chunk_count(1), 1);
        assert_eq!(encoder.chunk_count(100), 1);
        assert_eq!(encoder.chunk_count(101), 2);
        assert_eq!(encoder.chunk_count(250), 3);
    }

    #[test]
    fn encoder_config_defaults() {
        let config = ChunkEncoderConfig::default();
        assert_eq!(config.chunk_size, 65536);
    }

    #[test]
    fn encoder_large_chunk_size() {
        let encoder = ChunkEncoder::new(ChunkEncoderConfig {
            chunk_size: 1_000_000,
        });
        let data = vec![0xDDu8; 500_000];
        let frames = encoder.encode_object(obj_id(5), &data);
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn encoder_minimum_chunk_size() {
        let encoder = ChunkEncoder::new(ChunkEncoderConfig { chunk_size: 1 });
        let data = vec![0xEEu8; 5];
        let frames = encoder.encode_object(obj_id(6), &data);
        assert_eq!(frames.len(), 5);
        for (i, f) in frames.iter().enumerate() {
            assert_eq!(f.chunk_seq, i as u32);
            assert_eq!(f.offset, i as u64);
            assert_eq!(f.payload.len(), 1);
        }
    }

    // -- ChunkDecoder --

    #[test]
    fn decoder_single_frame() {
        let encoder = ChunkEncoder::new(ChunkEncoderConfig { chunk_size: 1024 });
        let data = b"decode-test-data".to_vec();
        let frames = encoder.encode_object(obj_id(7), &data);
        let mut buffer = Vec::new();
        for f in &frames {
            buffer.extend_from_slice(&f.encode());
        }

        let (decoded, consumed) = ChunkDecoder::decode_all(&buffer);
        assert_eq!(consumed, buffer.len());
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].payload, data);
    }

    #[test]
    fn decoder_multiple_frames() {
        let encoder = ChunkEncoder::new(ChunkEncoderConfig { chunk_size: 64 });
        let data = vec![0xFFu8; 200];
        let frames = encoder.encode_object(obj_id(8), &data);
        assert!(frames.len() >= 3);

        let mut buffer = Vec::new();
        for f in &frames {
            buffer.extend_from_slice(&f.encode());
        }

        let (decoded, consumed) = ChunkDecoder::decode_all(&buffer);
        assert_eq!(consumed, buffer.len());
        assert_eq!(decoded.len(), frames.len());

        let mut reassembled = Vec::new();
        for f in &decoded {
            reassembled.extend_from_slice(&f.payload);
        }
        assert_eq!(reassembled, data);
    }

    #[test]
    fn decoder_skip_garbage_prefix() {
        let encoder = ChunkEncoder::new(ChunkEncoderConfig { chunk_size: 1024 });
        let frame = encoder.encode_object(obj_id(9), b"valid")[0].encode();

        let mut buffer = b"JUNK_PREFIX_BYTES".to_vec();
        buffer.extend_from_slice(&frame);

        let (decoded, _consumed) = ChunkDecoder::decode_all(&buffer);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].payload, b"valid");
    }

    #[test]
    fn decoder_partial_frame_at_end() {
        let encoder = ChunkEncoder::new(ChunkEncoderConfig { chunk_size: 1024 });
        let frame = encoder.encode_object(obj_id(10), b"complete")[0].encode();

        let mut buffer = frame.clone();
        buffer.extend_from_slice(&FRAME_MAGIC);

        let (decoded, consumed) = ChunkDecoder::decode_all(&buffer);
        assert_eq!(decoded.len(), 1, "only the complete frame is decoded");
        assert!(consumed < buffer.len());
    }

    #[test]
    fn decoder_empty_buffer() {
        let (frames, consumed) = ChunkDecoder::decode_all(&[]);
        assert!(frames.is_empty());
        assert_eq!(consumed, 0);
    }

    #[test]
    fn decoder_only_garbage() {
        let (frames, consumed) = ChunkDecoder::decode_all(b"no magic here");
        assert!(frames.is_empty());
        assert_eq!(consumed, 0);
    }

    // -- Integration: encode -> wire -> decode -> verify --

    #[test]
    fn integration_full_pipeline() {
        let config = ChunkEncoderConfig { chunk_size: 50 };
        let encoder = ChunkEncoder::new(config);
        let data = b"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"; // 52 bytes
        let oid = [0xAB; 32];

        let frames = encoder.encode_object(oid, data);
        assert!(frames.len() >= 2);

        let mut wire = Vec::new();
        for f in &frames {
            wire.extend_from_slice(&f.encode());
        }

        let (decoded, consumed) = ChunkDecoder::decode_all(&wire);
        assert_eq!(consumed, wire.len());
        assert_eq!(decoded.len(), frames.len());

        for f in &decoded {
            assert!(f.verify());
        }

        let mut reassembled = Vec::new();
        for f in &decoded {
            reassembled.extend_from_slice(&f.payload);
        }
        assert_eq!(reassembled, data);
        assert_eq!(
            crate::blake3_digest(data),
            crate::blake3_digest(&reassembled)
        );
    }

    #[test]
    fn integration_two_objects_interleaved() {
        let encoder = ChunkEncoder::new(ChunkEncoderConfig { chunk_size: 256 });
        let oid1 = [1u8; 32];
        let oid2 = [2u8; 32];
        let data1 = vec![0x11u8; 400];
        let data2 = vec![0x22u8; 300];

        let frames1 = encoder.encode_object(oid1, &data1);
        let frames2 = encoder.encode_object(oid2, &data2);

        let mut buffer = Vec::new();
        for f in &frames1 {
            buffer.extend_from_slice(&f.encode());
        }
        for f in &frames2 {
            buffer.extend_from_slice(&f.encode());
        }

        let (decoded, consumed) = ChunkDecoder::decode_all(&buffer);
        assert_eq!(consumed, buffer.len());

        let obj1_frames: Vec<_> = decoded.iter().filter(|f| f.object_id == oid1).collect();
        let obj2_frames: Vec<_> = decoded.iter().filter(|f| f.object_id == oid2).collect();

        assert_eq!(obj1_frames.len(), frames1.len());
        assert_eq!(obj2_frames.len(), frames2.len());

        let mut r1 = Vec::new();
        for f in &obj1_frames {
            r1.extend_from_slice(&f.payload);
        }
        assert_eq!(r1, data1);

        let mut r2 = Vec::new();
        for f in &obj2_frames {
            r2.extend_from_slice(&f.payload);
        }
        assert_eq!(r2, data2);
    }
}
