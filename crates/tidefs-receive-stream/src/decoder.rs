// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Chunk decoder: parse wire-format chunk frames and verify BLAKE3
//! domain-separated authentication tags.
//!
//! Wire format (little-endian):
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

use crate::{AUTH_TAG_BYTES, CHUNK_HEADER_BYTES, CHUNK_MAGIC};

/// A decoded and verified chunk frame from the wire.
///
/// Mirrors the layout of `tidefs_send_stream::framer::FramedChunk`
/// so the two crates can round-trip without depending on each other.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FramedChunk {
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
    /// BLAKE3-256 domain-separated digest of the payload (TransferStream domain).
    pub auth_tag: [u8; 32],
    /// True when this is the final chunk of the object.
    pub is_last: bool,
}

impl FramedChunk {
    /// Compute and verify the domain-separated BLAKE3 authentication tag
    /// for the stored payload. Returns `true` when the tag matches.
    #[must_use]
    pub fn verify_auth_tag(&self) -> bool {
        let recomputed = blake3_domain_digest(
            &self.payload,
            SchemaFamilyId(7),
            SchemaTypeId(1),
            SchemaVersion::new(1, 0),
            DomainTag::TransferStream,
        );
        recomputed == self.auth_tag
    }
}

/// Chunk-level decoding errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChunkDecodeError {
    /// Input is too short to contain a valid chunk header.
    TruncatedHeader { got: usize, expected: usize },
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

impl core::fmt::Display for ChunkDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TruncatedHeader { got, expected } => {
                write!(
                    f,
                    "truncated chunk header: got {got} bytes, need {expected}"
                )
            }
            Self::TruncatedPayload {
                declared,
                available,
            } => {
                write!(
                    f,
                    "truncated chunk payload: declared {declared} bytes, only {available} available"
                )
            }
            Self::BadMagic { got } => {
                write!(
                    f,
                    "bad chunk magic: 0x{got:08X}, expected 0x{CHUNK_MAGIC:08X}"
                )
            }
            Self::HeaderChecksumMismatch => {
                write!(f, "chunk header CRC32C mismatch")
            }
            Self::AuthTagMismatch => {
                write!(f, "BLAKE3 auth tag verification failed")
            }
            Self::PayloadTooLarge { declared, max } => {
                write!(
                    f,
                    "declared payload length {declared} exceeds maximum {max}"
                )
            }
        }
    }
}

impl std::error::Error for ChunkDecodeError {}

/// Decodes wire-format chunk frames and verifies BLAKE3 authentication tags.
///
/// Each call to [`decode_chunk`] consumes one complete chunk frame from the
/// front of `bytes` and returns the decoded [`FramedChunk`] along with the
/// remaining unprocessed bytes.
///
/// # Wire format
///
/// The 64-byte header is followed by a 32-byte BLAKE3 auth tag and then the
/// variable-length payload. The header includes a CRC32C of its first 60
/// bytes for fast corruption detection.
pub struct ChunkDecoder {
    /// Maximum payload bytes per chunk (0 = unlimited).
    max_payload: u32,
}

impl Default for ChunkDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkDecoder {
    /// Create a new decoder with no payload size limit.
    #[must_use]
    pub fn new() -> Self {
        Self { max_payload: 0 }
    }

    /// Create a decoder that rejects chunks with payloads larger than `max`.
    #[must_use]
    pub fn with_max_payload(max: u32) -> Self {
        Self { max_payload: max }
    }

    /// Decode one chunk frame from the front of `bytes`.
    ///
    /// Returns the decoded and verified [`FramedChunk`] plus any remaining
    /// trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ChunkDecodeError`] if the header is truncated, the magic
    /// is wrong, the header CRC32C is bad, the declared payload length is
    /// unreachable or exceeds the configured maximum, or the BLAKE3 auth
    /// tag does not match the payload.
    pub fn decode_chunk<'a>(
        &self,
        bytes: &'a [u8],
    ) -> Result<(FramedChunk, &'a [u8]), ChunkDecodeError> {
        if bytes.len() < CHUNK_HEADER_BYTES {
            return Err(ChunkDecodeError::TruncatedHeader {
                got: bytes.len(),
                expected: CHUNK_HEADER_BYTES,
            });
        }

        let (header, rest) = bytes.split_at(CHUNK_HEADER_BYTES);

        // Parse header fields
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
        let _header_crc32c_stored = u32::from_le_bytes(header[60..64].try_into().unwrap());

        // Verify header CRC32C (bytes 0..60)
        let computed_crc = crc32c_header(&header[0..60]);
        if computed_crc != _header_crc32c_stored {
            return Err(ChunkDecodeError::HeaderChecksumMismatch);
        }

        // Payload size validation
        if self.max_payload > 0 && payload_len > self.max_payload {
            return Err(ChunkDecodeError::PayloadTooLarge {
                declared: payload_len,
                max: self.max_payload,
            });
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

        // Verify BLAKE3 domain-separated auth tag
        let expected_tag = blake3_domain_digest(
            &payload,
            SchemaFamilyId(7),
            SchemaTypeId(1),
            SchemaVersion::new(1, 0),
            DomainTag::TransferStream,
        );
        if auth_tag != expected_tag {
            return Err(ChunkDecodeError::AuthTagMismatch);
        }

        Ok((
            FramedChunk {
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

/// Encode a [`FramedChunk`] to wire format bytes.
///
/// This is the companion to [`ChunkDecoder::decode_chunk`] and is used
/// primarily for testing and round-trip validation.
pub fn encode_chunk_to_wire(chunk: &FramedChunk) -> Vec<u8> {
    let payload_len = chunk.payload.len() as u32;
    let mut buf = Vec::with_capacity(CHUNK_HEADER_BYTES + AUTH_TAG_BYTES + chunk.payload.len());

    // Build header bytes 0..60 (without CRC32C)
    let mut header60 = [0u8; 60];
    header60[0..4].copy_from_slice(&CHUNK_MAGIC.to_le_bytes());
    header60[4..36].copy_from_slice(&chunk.object_id);
    header60[36..44].copy_from_slice(&chunk.offset.to_le_bytes());
    header60[44..48].copy_from_slice(&chunk.chunk_index.to_le_bytes());
    header60[48..52].copy_from_slice(&chunk.total_chunks.to_le_bytes());
    header60[52..56].copy_from_slice(&payload_len.to_le_bytes());
    let flags: u32 = if chunk.is_last { 1 } else { 0 };
    header60[56..60].copy_from_slice(&flags.to_le_bytes());

    // Compute and append CRC32C
    let crc = crc32c_header(&header60);
    buf.extend_from_slice(&header60);
    buf.extend_from_slice(&crc.to_le_bytes());

    // Auth tag
    buf.extend_from_slice(&chunk.auth_tag);

    // Payload
    buf.extend_from_slice(&chunk.payload);

    buf
}

/// CRC32C of header bytes 0..60.
fn crc32c_header(data: &[u8]) -> u32 {
    crc32c::crc32c(data)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_binary_schema_checksum::blake3_domain_digest;

    fn test_obj_id(byte: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    fn make_chunk(
        object_id: [u8; 32],
        offset: u64,
        chunk_index: u32,
        total_chunks: u32,
        payload: &[u8],
        is_last: bool,
    ) -> FramedChunk {
        let auth_tag = blake3_domain_digest(
            payload,
            SchemaFamilyId(7),
            SchemaTypeId(1),
            SchemaVersion::new(1, 0),
            DomainTag::TransferStream,
        );
        FramedChunk {
            object_id,
            offset,
            chunk_index,
            total_chunks,
            payload: payload.to_vec(),
            auth_tag,
            is_last,
        }
    }

    #[test]
    fn single_chunk_round_trip() {
        let chunk = make_chunk(test_obj_id(0xAB), 0, 0, 1, b"hello world", true);
        let wire = encode_chunk_to_wire(&chunk);
        let decoder = ChunkDecoder::new();
        let (decoded, rest) = decoder.decode_chunk(&wire).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded.object_id, chunk.object_id);
        assert_eq!(decoded.offset, chunk.offset);
        assert_eq!(decoded.chunk_index, chunk.chunk_index);
        assert_eq!(decoded.total_chunks, chunk.total_chunks);
        assert_eq!(decoded.payload, chunk.payload);
        assert_eq!(decoded.auth_tag, chunk.auth_tag);
        assert_eq!(decoded.is_last, chunk.is_last);
        assert!(decoded.verify_auth_tag());
    }

    #[test]
    fn multi_chunk_round_trip() {
        let _data = b"0123456789";
        let c0 = make_chunk(test_obj_id(0x01), 0, 0, 3, b"0123", false);
        let c1 = make_chunk(test_obj_id(0x01), 4, 1, 3, b"4567", false);
        let c2 = make_chunk(test_obj_id(0x01), 8, 2, 3, b"89", true);

        let mut wire = Vec::new();
        wire.extend_from_slice(&encode_chunk_to_wire(&c0));
        wire.extend_from_slice(&encode_chunk_to_wire(&c1));
        wire.extend_from_slice(&encode_chunk_to_wire(&c2));

        let decoder = ChunkDecoder::new();
        let (d0, rest) = decoder.decode_chunk(&wire).unwrap();
        assert_eq!(d0.payload, c0.payload);
        assert_eq!(d0.chunk_index, 0);
        assert!(!d0.is_last);

        let (d1, rest) = decoder.decode_chunk(rest).unwrap();
        assert_eq!(d1.payload, c1.payload);
        assert_eq!(d1.chunk_index, 1);
        assert!(!d1.is_last);

        let (d2, rest) = decoder.decode_chunk(rest).unwrap();
        assert_eq!(d2.payload, c2.payload);
        assert_eq!(d2.chunk_index, 2);
        assert!(d2.is_last);

        assert!(rest.is_empty());
    }

    #[test]
    fn empty_payload_chunk() {
        let chunk = make_chunk(test_obj_id(0xCC), 0, 0, 1, b"", true);
        let wire = encode_chunk_to_wire(&chunk);
        let decoder = ChunkDecoder::new();
        let (decoded, rest) = decoder.decode_chunk(&wire).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded.payload, b"");
        assert!(decoded.is_last);
        assert_eq!(decoded.total_chunks, 1);
    }

    #[test]
    fn truncated_header_rejected() {
        let bytes = [0u8; 10];
        let decoder = ChunkDecoder::new();
        let err = decoder.decode_chunk(&bytes).unwrap_err();
        assert!(matches!(
            err,
            ChunkDecodeError::TruncatedHeader {
                got: 10,
                expected: 64
            }
        ));
    }

    #[test]
    fn truncated_payload_rejected() {
        let chunk = make_chunk(test_obj_id(0x01), 0, 0, 1, b"hello", false);
        let mut wire = encode_chunk_to_wire(&chunk);
        // Truncate the last 2 bytes of payload
        wire.truncate(wire.len() - 2);
        let decoder = ChunkDecoder::new();
        let err = decoder.decode_chunk(&wire).unwrap_err();
        assert!(matches!(err, ChunkDecodeError::TruncatedPayload { .. }));
    }

    #[test]
    fn bad_magic_rejected() {
        let chunk = make_chunk(test_obj_id(0x01), 0, 0, 1, b"abc", false);
        let mut wire = encode_chunk_to_wire(&chunk);
        wire[0] ^= 0xFF;
        let decoder = ChunkDecoder::new();
        let err = decoder.decode_chunk(&wire).unwrap_err();
        assert!(matches!(err, ChunkDecodeError::BadMagic { .. }));
    }

    #[test]
    fn auth_tag_mismatch_rejected() {
        let mut chunk = make_chunk(test_obj_id(0x01), 0, 0, 1, b"original", false);
        // Corrupt the auth tag
        chunk.auth_tag[0] ^= 0xFF;
        let wire = encode_chunk_to_wire(&chunk);
        let decoder = ChunkDecoder::new();
        let err = decoder.decode_chunk(&wire).unwrap_err();
        assert!(matches!(err, ChunkDecodeError::AuthTagMismatch));
    }

    #[test]
    fn payload_tampered_auth_tag_mismatch() {
        let chunk = make_chunk(test_obj_id(0x01), 0, 0, 1, b"hello", false);
        let mut wire = encode_chunk_to_wire(&chunk);
        // Tamper with payload byte (at offset 96 = header 64 + auth 32)
        let payload_start = CHUNK_HEADER_BYTES + AUTH_TAG_BYTES;
        wire[payload_start] ^= 0x01;
        let decoder = ChunkDecoder::new();
        let err = decoder.decode_chunk(&wire).unwrap_err();
        assert!(matches!(err, ChunkDecodeError::AuthTagMismatch));
    }

    #[test]
    fn header_checksum_mismatch_rejected() {
        let chunk = make_chunk(test_obj_id(0x01), 0, 0, 1, b"abc", false);
        let mut wire = encode_chunk_to_wire(&chunk);
        // Corrupt a header byte (not crc32c field itself)
        wire[10] ^= 0x01;
        let decoder = ChunkDecoder::new();
        let err = decoder.decode_chunk(&wire).unwrap_err();
        assert!(matches!(err, ChunkDecodeError::HeaderChecksumMismatch));
    }

    #[test]
    fn max_payload_enforcement() {
        let chunk = make_chunk(test_obj_id(0x01), 0, 0, 1, b"abcdefgh", false);
        let wire = encode_chunk_to_wire(&chunk);
        let decoder = ChunkDecoder::with_max_payload(4);
        let err = decoder.decode_chunk(&wire).unwrap_err();
        assert!(matches!(
            err,
            ChunkDecodeError::PayloadTooLarge {
                declared: 8,
                max: 4
            }
        ));
    }

    #[test]
    fn domain_separated_auth_tag_differs_from_plain_blake3() {
        let payload = b"domain separation test";
        let domain_tag = blake3_domain_digest(
            payload,
            SchemaFamilyId(7),
            SchemaTypeId(1),
            SchemaVersion::new(1, 0),
            DomainTag::TransferStream,
        );
        let plain: [u8; 32] = blake3::hash(payload).into();
        assert_ne!(domain_tag, plain);
    }

    #[test]
    fn different_domain_tag_produces_different_digest() {
        let payload = b"cross-domain test";
        let transfer_tag = blake3_domain_digest(
            payload,
            SchemaFamilyId(7),
            SchemaTypeId(1),
            SchemaVersion::new(1, 0),
            DomainTag::TransferStream,
        );
        let object_tag = blake3_domain_digest(
            payload,
            SchemaFamilyId(7),
            SchemaTypeId(1),
            SchemaVersion::new(1, 0),
            DomainTag::ObjectPayloadChunk,
        );
        assert_ne!(transfer_tag, object_tag);
    }

    #[test]
    fn is_last_flag_round_trips() {
        for is_last in [false, true] {
            let chunk = make_chunk(test_obj_id(0xDD), 0, 0, 1, b"x", is_last);
            let wire = encode_chunk_to_wire(&chunk);
            let decoder = ChunkDecoder::new();
            let (decoded, _) = decoder.decode_chunk(&wire).unwrap();
            assert_eq!(decoded.is_last, is_last, "is_last={is_last} mismatch");
        }
    }

    #[test]
    fn large_object_id_preserved() {
        let mut id = [0xFFu8; 32];
        id[16] = 0x42;
        let chunk = make_chunk(id, 1024, 5, 10, b"large-id test", false);
        let wire = encode_chunk_to_wire(&chunk);
        let decoder = ChunkDecoder::new();
        let (decoded, _) = decoder.decode_chunk(&wire).unwrap();
        assert_eq!(decoded.object_id, id);
    }

    #[test]
    fn trailing_bytes_preserved() {
        let chunk = make_chunk(test_obj_id(0x01), 0, 0, 1, b"first", false);
        let mut wire = encode_chunk_to_wire(&chunk);
        wire.extend_from_slice(b"trailing garbage");
        let decoder = ChunkDecoder::new();
        let (decoded, rest) = decoder.decode_chunk(&wire).unwrap();
        assert_eq!(decoded.payload, b"first");
        assert_eq!(rest, b"trailing garbage");
    }

    #[test]
    fn zero_length_stream() {
        let bytes = [];
        let decoder = ChunkDecoder::new();
        assert!(decoder.decode_chunk(&bytes).is_err());
    }
}
