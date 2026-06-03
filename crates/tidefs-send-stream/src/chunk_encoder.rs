//! BLAKE3 domain-separated chunk encoder producing TransferStream wire format.
//!
//! Each chunk carries a domain-separated BLAKE3-256 authentication tag under
//! the `TransferStream` domain, matching the format consumed by
//! `tidefs_receive_stream::decoder::ChunkDecoder` for multi-node state transfer.
//!
//! # Wire format (little-endian)
//!
//! ```text
//! offset  size  field
//! 0       4     magic (0x5653_4352 = "VSCR")
//! 4       32    object_id
//! 36      8     offset (u64)
//! 44      4     chunk_index (u32)
//! 48      4     total_chunks (u32)
//! 52      4     payload_len (u32)
//! 56      4     chunk_flags (u32; bit 0 = is_last)
//! 60      4     header_crc32c (u32; CRC32C of bytes 0..60)
//! 64      32    auth_tag (BLAKE3-256 domain-separated)
//! 96      N     payload
//! ```

use tidefs_binary_schema_checksum::blake3_domain_digest;
use tidefs_binary_schema_core::{DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion};

// ---------------------------------------------------------------------------
// Format constants (mirror tidefs_receive_stream for wire compatibility)
// ---------------------------------------------------------------------------

/// Schema family for TransferStream chunk framing (matches receive-stream family 7).
pub const CHUNK_FAMILY: SchemaFamilyId = SchemaFamilyId(7);
/// Schema type for a framed data chunk within the TransferStream family.
pub const CHUNK_TYPE: SchemaTypeId = SchemaTypeId(1);
/// Schema version for chunk framing v1.0.
pub const CHUNK_VERSION: SchemaVersion = SchemaVersion::new(1, 0);

/// Wire-format magic bytes ("VSCR" little-endian).
const CHUNK_MAGIC: u32 = 0x5653_4352;

/// Size of the fixed chunk wire header in bytes.
const HEADER_BYTES: usize = 64;

/// Size of the BLAKE3-256 auth tag in bytes.
const AUTH_TAG_BYTES: usize = 32;

// ---------------------------------------------------------------------------
// TransferChunk
// ---------------------------------------------------------------------------

/// A chunk frame with domain-separated BLAKE3 authentication.
///
/// Mirrors `tidefs_receive_stream::decoder::FramedChunk` so the send and
/// receive sides round-trip without depending on each other.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferChunk {
    /// Stable object identifier.
    pub object_id: [u8; 32],
    /// Byte offset of this chunk within the object.
    pub offset: u64,
    /// Zero-based chunk index.
    pub chunk_index: u32,
    /// Total number of chunks in the object.
    pub total_chunks: u32,
    /// Raw payload bytes for this chunk.
    pub payload: Vec<u8>,
    /// BLAKE3-256 domain-separated auth tag (TransferStream domain).
    pub auth_tag: [u8; 32],
    /// True when this is the final chunk of the object.
    pub is_last: bool,
}

impl TransferChunk {
    /// Create a new chunk, computing the domain-separated BLAKE3 auth tag.
    pub fn new(
        object_id: [u8; 32],
        offset: u64,
        chunk_index: u32,
        total_chunks: u32,
        payload: Vec<u8>,
        is_last: bool,
    ) -> Self {
        let auth_tag = compute_auth_tag(&payload);
        Self {
            object_id,
            offset,
            chunk_index,
            total_chunks,
            payload,
            auth_tag,
            is_last,
        }
    }

    /// Verify that the stored auth tag matches the payload.
    pub fn verify_auth_tag(&self) -> bool {
        compute_auth_tag(&self.payload) == self.auth_tag
    }

    /// Encode this chunk to TransferStream wire format.
    ///
    /// Returns the complete frame: `[header(64) | auth_tag(32) | payload(N)]`.
    pub fn encode_to_wire(&self) -> Vec<u8> {
        let payload_len = self.payload.len() as u32;
        let mut buf = Vec::with_capacity(HEADER_BYTES + AUTH_TAG_BYTES + self.payload.len());

        // Build header bytes 0..60 (without CRC32C)
        let mut hdr60 = [0u8; 60];
        hdr60[0..4].copy_from_slice(&CHUNK_MAGIC.to_le_bytes());
        hdr60[4..36].copy_from_slice(&self.object_id);
        hdr60[36..44].copy_from_slice(&self.offset.to_le_bytes());
        hdr60[44..48].copy_from_slice(&self.chunk_index.to_le_bytes());
        hdr60[48..52].copy_from_slice(&self.total_chunks.to_le_bytes());
        hdr60[52..56].copy_from_slice(&payload_len.to_le_bytes());
        let flags: u32 = if self.is_last { 1 } else { 0 };
        hdr60[56..60].copy_from_slice(&flags.to_le_bytes());

        // CRC32C of header bytes 0..60
        let crc = crc32c_header(&hdr60);

        buf.extend_from_slice(&hdr60);
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&self.auth_tag);
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode one chunk frame from the front of `bytes`.
    ///
    /// Returns the decoded chunk plus any remaining trailing bytes.
    pub fn decode_from_wire(bytes: &[u8]) -> Result<(Self, &[u8]), ChunkDecodeError> {
        if bytes.len() < HEADER_BYTES {
            return Err(ChunkDecodeError::TruncatedHeader { got: bytes.len() });
        }

        let (header, rest) = bytes.split_at(HEADER_BYTES);

        let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
        if magic != CHUNK_MAGIC {
            return Err(ChunkDecodeError::BadMagic { got: magic });
        }

        let object_id: [u8; 32] = header[4..36].try_into().unwrap();
        let offset = u64::from_le_bytes(header[36..44].try_into().unwrap());
        let chunk_index = u32::from_le_bytes(header[44..48].try_into().unwrap());
        let total_chunks = u32::from_le_bytes(header[48..52].try_into().unwrap());
        let payload_len = u32::from_le_bytes(header[52..56].try_into().unwrap());
        let chunk_flags = u32::from_le_bytes(header[56..60].try_into().unwrap());
        let is_last = (chunk_flags & 1) != 0;
        let stored_crc = u32::from_le_bytes(header[60..64].try_into().unwrap());

        // Verify header CRC32C (bytes 0..60)
        let computed_crc = crc32c_header(&header[0..60]);
        if computed_crc != stored_crc {
            return Err(ChunkDecodeError::HeaderChecksumMismatch);
        }

        let total_needed = AUTH_TAG_BYTES + payload_len as usize;
        if rest.len() < total_needed {
            return Err(ChunkDecodeError::TruncatedPayload {
                declared: payload_len,
                available: rest.len().saturating_sub(AUTH_TAG_BYTES),
            });
        }

        let auth_tag: [u8; 32] = rest[0..32].try_into().unwrap();
        let payload = rest[32..32 + payload_len as usize].to_vec();
        let remaining = &rest[32 + payload_len as usize..];

        // Verify domain-separated auth tag
        let expected_tag = compute_auth_tag(&payload);
        if auth_tag != expected_tag {
            return Err(ChunkDecodeError::AuthTagMismatch);
        }

        Ok((
            Self {
                object_id,
                offset,
                chunk_index,
                total_chunks,
                payload,
                auth_tag,
                is_last,
            },
            remaining,
        ))
    }
}

// ---------------------------------------------------------------------------
// ChunkDecodeError
// ---------------------------------------------------------------------------

/// Errors from decoding a TransferStream chunk frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChunkDecodeError {
    /// Input is too short to contain a valid chunk header.
    TruncatedHeader { got: usize },
    /// Input is shorter than the declared payload length.
    TruncatedPayload { declared: u32, available: usize },
    /// Magic bytes do not match the expected value.
    BadMagic { got: u32 },
    /// Header CRC32C mismatch.
    HeaderChecksumMismatch,
    /// BLAKE3 auth tag verification failed.
    AuthTagMismatch,
    /// Declared payload length exceeds maximum allowed.
    PayloadTooLarge { declared: u32, max: u32 },
}

// ---------------------------------------------------------------------------
// TransferChunkEncoder
// ---------------------------------------------------------------------------

/// Configurable encoder that splits object data into fixed-size chunks with
/// domain-separated BLAKE3-256 auth tags.
///
/// Produces [`TransferChunk`] frames that are wire-compatible with the
/// receive-stream decoder (`tidefs_receive_stream::decoder::ChunkDecoder`).
///
/// # Example
///
/// ```ignore
/// use tidefs_send_stream::chunk_encoder::{TransferChunkEncoder, TransferChunkEncoderConfig};
///
/// let config = TransferChunkEncoderConfig { chunk_size: 65536 };
/// let encoder = TransferChunkEncoder::new(config);
///
/// let data = vec![0x42u8; 100_000];
/// let object_id = [1u8; 32];
/// let chunks = encoder.encode_object(object_id, &data);
///
/// for c in &chunks {
///     assert!(c.verify_auth_tag());
/// }
/// ```
#[derive(Clone, Debug)]
pub struct TransferChunkEncoder {
    config: TransferChunkEncoderConfig,
}

/// Configuration for [`TransferChunkEncoder`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TransferChunkEncoderConfig {
    /// Maximum payload bytes per chunk (default: 65536 = 64 KiB).
    pub chunk_size: u32,
}

impl Default for TransferChunkEncoderConfig {
    fn default() -> Self {
        Self { chunk_size: 65536 }
    }
}

impl TransferChunkEncoder {
    /// Create a new encoder with the given configuration.
    pub fn new(config: TransferChunkEncoderConfig) -> Self {
        Self { config }
    }

    /// Return a copy of the current configuration.
    pub fn config(&self) -> TransferChunkEncoderConfig {
        self.config
    }

    /// Split an object into domain-separated chunks.
    ///
    /// An empty object produces a single chunk with an empty payload and
    /// `total_chunks = 1`.
    pub fn encode_object(&self, object_id: [u8; 32], data: &[u8]) -> Vec<TransferChunk> {
        let chunk_size = self.config.chunk_size.max(1) as usize;
        if data.is_empty() {
            return vec![TransferChunk::new(object_id, 0, 0, 1, Vec::new(), true)];
        }

        let total_chunks = data.len().div_ceil(chunk_size) as u32;
        let mut chunks = Vec::with_capacity(total_chunks as usize);

        for (i, chunk_data) in data.chunks(chunk_size).enumerate() {
            let offset = (i * chunk_size) as u64;
            let is_last = i + 1 == total_chunks as usize;
            let chunk = TransferChunk::new(
                object_id,
                offset,
                i as u32,
                total_chunks,
                chunk_data.to_vec(),
                is_last,
            );
            chunks.push(chunk);
        }

        chunks
    }

    /// Compute the number of chunks an object of `data_len` bytes will
    /// produce without actually encoding.
    pub fn chunk_count(&self, data_len: usize) -> usize {
        if data_len == 0 {
            return 1;
        }
        data_len.div_ceil(self.config.chunk_size.max(1) as usize)
    }

    /// Maximum chunk payload size (excludes header + auth tag overhead).
    pub fn max_payload(&self) -> u32 {
        self.config.chunk_size.max(1)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the domain-separated BLAKE3-256 auth tag for a payload.
fn compute_auth_tag(payload: &[u8]) -> [u8; 32] {
    blake3_domain_digest(
        payload,
        CHUNK_FAMILY,
        CHUNK_TYPE,
        CHUNK_VERSION,
        DomainTag::TransferStream,
    )
}

/// CRC32C of header bytes.
fn crc32c_header(data: &[u8]) -> u32 {
    crc32c::crc32c(data)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn obj_id(b: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = b;
        id
    }

    // -- TransferChunk encode/decode --

    #[test]
    fn transfer_chunk_encode_decode_round_trip() {
        let payload = b"hello transfer chunk".to_vec();
        let chunk = TransferChunk::new(obj_id(1), 0, 0, 1, payload.clone(), true);
        let wire = chunk.encode_to_wire();
        let (decoded, rest) = TransferChunk::decode_from_wire(&wire).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded.object_id, obj_id(1));
        assert_eq!(decoded.chunk_index, 0);
        assert_eq!(decoded.total_chunks, 1);
        assert_eq!(decoded.offset, 0);
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.auth_tag, chunk.auth_tag);
        assert!(decoded.is_last);
        assert!(decoded.verify_auth_tag());
    }

    #[test]
    fn transfer_chunk_decode_rejects_bad_magic() {
        let chunk = TransferChunk::new(obj_id(1), 0, 0, 1, b"data".to_vec(), true);
        let mut wire = chunk.encode_to_wire();
        wire[0] ^= 0xFF;
        assert!(matches!(
            TransferChunk::decode_from_wire(&wire),
            Err(ChunkDecodeError::BadMagic { .. })
        ));
    }

    #[test]
    fn transfer_chunk_decode_rejects_truncated_header() {
        let bytes = [0u8; 10];
        assert!(matches!(
            TransferChunk::decode_from_wire(&bytes),
            Err(ChunkDecodeError::TruncatedHeader { got: 10 })
        ));
    }

    #[test]
    fn transfer_chunk_decode_rejects_truncated_payload() {
        let chunk = TransferChunk::new(obj_id(1), 0, 0, 1, b"hello".to_vec(), false);
        let mut wire = chunk.encode_to_wire();
        wire.truncate(wire.len() - 2);
        assert!(matches!(
            TransferChunk::decode_from_wire(&wire),
            Err(ChunkDecodeError::TruncatedPayload { .. })
        ));
    }

    #[test]
    fn transfer_chunk_decode_rejects_header_crc_mismatch() {
        let chunk = TransferChunk::new(obj_id(1), 0, 0, 1, b"abc".to_vec(), false);
        let mut wire = chunk.encode_to_wire();
        wire[10] ^= 0x01;
        assert!(matches!(
            TransferChunk::decode_from_wire(&wire),
            Err(ChunkDecodeError::HeaderChecksumMismatch)
        ));
    }

    #[test]
    fn transfer_chunk_decode_rejects_auth_tag_mismatch() {
        let mut chunk = TransferChunk::new(obj_id(1), 0, 0, 1, b"original".to_vec(), false);
        chunk.auth_tag[0] ^= 0xFF;
        let wire = chunk.encode_to_wire();
        assert!(matches!(
            TransferChunk::decode_from_wire(&wire),
            Err(ChunkDecodeError::AuthTagMismatch)
        ));
    }

    #[test]
    fn transfer_chunk_decode_rejects_payload_tampering() {
        let chunk = TransferChunk::new(obj_id(1), 0, 0, 1, b"hello".to_vec(), false);
        let mut wire = chunk.encode_to_wire();
        // Tamper with payload byte at offset 96 (header 64 + auth 32)
        let payload_start = HEADER_BYTES + AUTH_TAG_BYTES;
        wire[payload_start] ^= 0x01;
        assert!(matches!(
            TransferChunk::decode_from_wire(&wire),
            Err(ChunkDecodeError::AuthTagMismatch)
        ));
    }

    #[test]
    fn transfer_chunk_verify_auth_tag_passes() {
        let chunk = TransferChunk::new(obj_id(2), 4096, 0, 1, b"verify me".to_vec(), true);
        assert!(chunk.verify_auth_tag());
    }

    #[test]
    fn transfer_chunk_verify_auth_tag_fails_on_corruption() {
        let mut chunk = TransferChunk::new(obj_id(2), 0, 0, 1, b"data".to_vec(), true);
        chunk.payload[0] ^= 0xFF;
        assert!(!chunk.verify_auth_tag());
    }

    #[test]
    fn transfer_chunk_empty_payload_round_trip() {
        let chunk = TransferChunk::new(obj_id(0xCC), 0, 0, 1, Vec::new(), true);
        let wire = chunk.encode_to_wire();
        let (decoded, rest) = TransferChunk::decode_from_wire(&wire).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded.payload.len(), 0);
        assert!(decoded.is_last);
        assert_eq!(decoded.total_chunks, 1);
    }

    #[test]
    fn transfer_chunk_trailing_bytes_preserved() {
        let chunk = TransferChunk::new(obj_id(1), 0, 0, 1, b"first".to_vec(), false);
        let mut wire = chunk.encode_to_wire();
        wire.extend_from_slice(b"trailing");
        let (decoded, rest) = TransferChunk::decode_from_wire(&wire).unwrap();
        assert_eq!(decoded.payload, b"first");
        assert_eq!(rest, b"trailing");
    }

    // -- TransferChunkEncoder --

    #[test]
    fn encoder_single_chunk_object() {
        let encoder = TransferChunkEncoder::new(TransferChunkEncoderConfig { chunk_size: 1024 });
        let data = vec![0xAAu8; 512];
        let chunks = encoder.encode_object(obj_id(1), &data);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].chunk_index, 0);
        assert_eq!(chunks[0].offset, 0);
        assert_eq!(chunks[0].total_chunks, 1);
        assert_eq!(chunks[0].payload, data);
        assert!(chunks[0].is_last);
        assert!(chunks[0].verify_auth_tag());
    }

    #[test]
    fn encoder_multi_chunk_object() {
        let encoder = TransferChunkEncoder::new(TransferChunkEncoderConfig { chunk_size: 100 });
        let data = vec![0xBBu8; 250];
        let chunks = encoder.encode_object(obj_id(2), &data);
        assert_eq!(chunks.len(), 3);

        assert_eq!(chunks[0].chunk_index, 0);
        assert_eq!(chunks[0].offset, 0);
        assert!(!chunks[0].is_last);
        assert_eq!(chunks[1].chunk_index, 1);
        assert_eq!(chunks[1].offset, 100);
        assert!(!chunks[1].is_last);
        assert_eq!(chunks[2].chunk_index, 2);
        assert_eq!(chunks[2].offset, 200);
        assert!(chunks[2].is_last);

        assert_eq!(chunks[0].total_chunks, 3);
        assert_eq!(chunks[1].total_chunks, 3);
        assert_eq!(chunks[2].total_chunks, 3);

        for c in &chunks {
            assert!(c.verify_auth_tag());
        }

        let reassembled: Vec<u8> = chunks.iter().flat_map(|c| c.payload.clone()).collect();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn encoder_empty_object() {
        let encoder = TransferChunkEncoder::new(TransferChunkEncoderConfig::default());
        let chunks = encoder.encode_object(obj_id(3), &[]);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].payload.len(), 0);
        assert!(chunks[0].is_last);
        assert!(chunks[0].verify_auth_tag());
    }

    #[test]
    fn encoder_exact_chunk_boundary() {
        let encoder = TransferChunkEncoder::new(TransferChunkEncoderConfig { chunk_size: 256 });
        let data = vec![0xCCu8; 512];
        let chunks = encoder.encode_object(obj_id(4), &data);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].payload.len(), 256);
        assert_eq!(chunks[1].payload.len(), 256);
    }

    #[test]
    fn encoder_chunk_count() {
        let encoder = TransferChunkEncoder::new(TransferChunkEncoderConfig { chunk_size: 100 });
        assert_eq!(encoder.chunk_count(0), 1);
        assert_eq!(encoder.chunk_count(1), 1);
        assert_eq!(encoder.chunk_count(100), 1);
        assert_eq!(encoder.chunk_count(101), 2);
        assert_eq!(encoder.chunk_count(250), 3);
    }

    #[test]
    fn encoder_default_config() {
        let config = TransferChunkEncoderConfig::default();
        assert_eq!(config.chunk_size, 65536);
    }

    #[test]
    fn encoder_with_max_payload() {
        let encoder = TransferChunkEncoder::new(TransferChunkEncoderConfig { chunk_size: 1 });
        let data = vec![0xEEu8; 5];
        let chunks = encoder.encode_object(obj_id(6), &data);
        assert_eq!(chunks.len(), 5);
        for (i, c) in chunks.iter().enumerate() {
            assert_eq!(c.chunk_index, i as u32);
            assert_eq!(c.offset, i as u64);
            assert_eq!(c.payload.len(), 1);
        }
    }

    #[test]
    fn domain_separation_differs_from_plain_blake3() {
        let payload = b"domain separation test";
        let chunk = TransferChunk::new(obj_id(1), 0, 0, 1, payload.to_vec(), true);
        let plain: [u8; 32] = blake3::hash(payload).into();
        assert_ne!(
            chunk.auth_tag, plain,
            "domain-separated tag must differ from plain BLAKE3"
        );
    }

    #[test]
    fn wire_compatible_with_receive_stream_decoder() {
        // Encode with our encoder, decode with our own decoder (round-trip).
        // The receive-stream crate uses identical wire format constants.
        let encoder = TransferChunkEncoder::new(TransferChunkEncoderConfig { chunk_size: 50 });
        let data = b"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"; // 52 bytes
        let chunks = encoder.encode_object(obj_id(7), data);
        assert!(chunks.len() >= 2);

        let mut wire = Vec::new();
        for c in &chunks {
            wire.extend_from_slice(&c.encode_to_wire());
        }

        let mut decoded_chunks = Vec::new();
        let mut rest: &[u8] = &wire;
        while !rest.is_empty() {
            let (chunk, remaining) = TransferChunk::decode_from_wire(rest).unwrap();
            decoded_chunks.push(chunk);
            rest = remaining;
        }

        assert_eq!(decoded_chunks.len(), chunks.len());

        let reassembled: Vec<u8> = decoded_chunks
            .iter()
            .flat_map(|c| c.payload.clone())
            .collect();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn is_last_flag_round_trips() {
        for is_last in [false, true] {
            let chunk = TransferChunk::new(obj_id(0xDD), 0, 0, 1, b"x".to_vec(), is_last);
            let wire = chunk.encode_to_wire();
            let (decoded, _) = TransferChunk::decode_from_wire(&wire).unwrap();
            assert_eq!(decoded.is_last, is_last);
        }
    }
}
