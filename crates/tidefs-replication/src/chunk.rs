// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Replica chunk wire format for BLAKE3-verified object-data push.
//!
//! Defines `ReplicaChunk` (the wire frame carrying payload data with
//! integrity framing) and `ReplicaChunkAck` (the per-target response).
//! Both types support deterministic encode/decode for transport over
//! raw byte channels.

use std::fmt;

// ── Magic constants ─────────────────────────────────────────────────

/// 16-byte magic for `ReplicaChunk` frames: `VREPLICA_PUSH_CHK`.
pub const REPLICA_CHUNK_MAGIC: &[u8; 16] = b"VREPLICA_PUSH_CH";
/// 4-byte magic for `ReplicaChunkAck` frames: `VRPA`.
pub const REPLICA_CHUNK_ACK_MAGIC: &[u8; 4] = b"VRPA";

/// Current wire format version.
pub const CHUNK_FORMAT_VERSION: u32 = 1;

/// Fixed header size of a `ReplicaChunk` (magic + version + seq + epoch
/// + object_id + offset + length + checksum + payload_len).
pub const CHUNK_HEADER_SIZE: usize = 16 + 4 + 8 + 8 + 32 + 8 + 8 + 32 + 4;

/// Fixed frame size of a `ReplicaChunkAck`.
pub const CHUNK_ACK_FRAME_SIZE: usize = 4 + 8 + 8 + 32 + 1;

// ── ReplicaChunk ────────────────────────────────────────────────────

/// A BLAKE3-framed chunk carrying object data to a replica target.
///
/// Wire layout (little-endian unless noted):
///
/// | Offset | Size | Field            |
/// |--------|------|------------------|
/// | 0      | 16   | magic (`VREPL...`)|
/// | 16     | 4    | version (u32)    |
/// | 20     | 8    | sequence (u64)   |
/// | 28     | 8    | epoch (u64)      |
/// | 36     | 32   | object_id        |
/// | 68     | 8    | offset (u64)     |
/// | 76     | 8    | length (u64)     |
/// | 84     | 32   | payload_checksum |
/// | 116    | 4    | payload_len (u32)|
/// | 120    | N    | payload          |
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaChunk {
    /// Monotonic sequence number for ordering and dedup.
    pub sequence: u64,
    /// Membership epoch this chunk belongs to.
    pub epoch: u64,
    /// BLAKE3-256 content hash of the object being replicated (32 bytes).
    pub object_id: [u8; 32],
    /// Byte offset within the object.
    pub offset: u64,
    /// Byte length of the payload in this chunk.
    pub length: u64,
    /// BLAKE3-256 checksum of the payload alone.
    pub payload_checksum: [u8; 32],
    /// The payload bytes carried in this chunk.
    pub payload: Vec<u8>,
}

impl ReplicaChunk {
    /// Create a new chunk, computing the payload checksum automatically.
    #[must_use]
    pub fn new(
        sequence: u64,
        epoch: u64,
        object_id: [u8; 32],
        offset: u64,
        payload: Vec<u8>,
    ) -> Self {
        let length = payload.len() as u64;
        let payload_checksum = blake3::hash(&payload).into();
        Self {
            sequence,
            epoch,
            object_id,
            offset,
            length,
            payload_checksum,
            payload,
        }
    }

    /// Encode this chunk into a wire-format byte vector.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let payload_len_u32 = self.payload.len() as u32;
        let mut buf = Vec::with_capacity(CHUNK_HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(REPLICA_CHUNK_MAGIC);
        buf.extend_from_slice(&CHUNK_FORMAT_VERSION.to_le_bytes());
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        buf.extend_from_slice(&self.object_id);
        buf.extend_from_slice(&self.offset.to_le_bytes());
        buf.extend_from_slice(&self.length.to_le_bytes());
        buf.extend_from_slice(&self.payload_checksum);
        buf.extend_from_slice(&payload_len_u32.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode a `ReplicaChunk` from wire-format bytes.
    ///
    /// # Errors
    ///
    /// Returns `DecodeError` if the magic, version, or framing is invalid,
    /// or if the payload checksum does not match.
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        if data.len() < CHUNK_HEADER_SIZE {
            return Err(DecodeError::TooShort {
                needed: CHUNK_HEADER_SIZE,
                got: data.len(),
            });
        }
        if &data[0..16] != REPLICA_CHUNK_MAGIC.as_slice() {
            return Err(DecodeError::BadMagic);
        }
        let version = u32::from_le_bytes(data[16..20].try_into().unwrap());
        if version != CHUNK_FORMAT_VERSION {
            return Err(DecodeError::UnknownVersion { version });
        }
        let sequence = u64::from_le_bytes(data[20..28].try_into().unwrap());
        let epoch = u64::from_le_bytes(data[28..36].try_into().unwrap());
        let mut object_id = [0u8; 32];
        object_id.copy_from_slice(&data[36..68]);
        let offset = u64::from_le_bytes(data[68..76].try_into().unwrap());
        let length = u64::from_le_bytes(data[76..84].try_into().unwrap());
        let mut payload_checksum = [0u8; 32];
        payload_checksum.copy_from_slice(&data[84..116]);
        let payload_len = u32::from_le_bytes(data[116..120].try_into().unwrap()) as usize;

        if data.len() < CHUNK_HEADER_SIZE + payload_len {
            return Err(DecodeError::PayloadTruncated {
                expected: payload_len,
                got: data.len() - CHUNK_HEADER_SIZE,
            });
        }

        let payload = data[CHUNK_HEADER_SIZE..CHUNK_HEADER_SIZE + payload_len].to_vec();

        // Verify payload checksum
        let computed: [u8; 32] = blake3::hash(&payload).into();
        if computed != payload_checksum {
            return Err(DecodeError::ChecksumMismatch);
        }

        // Verify length field matches actual payload
        if payload.len() as u64 != length {
            return Err(DecodeError::LengthMismatch {
                declared: length,
                actual: payload.len() as u64,
            });
        }

        Ok(Self {
            sequence,
            epoch,
            object_id,
            offset,
            length,
            payload_checksum,
            payload,
        })
    }

    /// Verify the payload checksum without re-decoding.
    #[must_use]
    pub fn verify_checksum(&self) -> bool {
        let computed: [u8; 32] = blake3::hash(&self.payload).into();
        computed == self.payload_checksum
    }
}

// ── ReplicaChunkAck ─────────────────────────────────────────────────

/// Per-target acknowledgment of a received `ReplicaChunk`.
///
/// Wire layout (little-endian):
///
/// | Offset | Size | Field               |
/// |--------|------|---------------------|
/// | 0      | 4    | magic (`VRPA`)      |
/// | 4      | 8    | sequence (u64)      |
/// | 12     | 8    | epoch (u64)         |
/// | 20     | 32   | verification_hash   |
/// | 52     | 1    | success (u8)        |
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaChunkAck {
    /// Echoed sequence number from the chunk being acknowledged.
    pub sequence: u64,
    /// Echoed epoch from the chunk being acknowledged.
    pub epoch: u64,
    /// BLAKE3-256 hash of the received + verified payload.
    pub verification_hash: [u8; 32],
    /// Whether the chunk was accepted and stored.
    pub success: bool,
}

impl ReplicaChunkAck {
    /// Create a successful acknowledgment.
    #[must_use]
    pub fn success(sequence: u64, epoch: u64, verification_hash: [u8; 32]) -> Self {
        Self {
            sequence,
            epoch,
            verification_hash,
            success: true,
        }
    }

    /// Create a failure acknowledgment.
    #[must_use]
    pub fn failure(sequence: u64, epoch: u64, verification_hash: [u8; 32]) -> Self {
        Self {
            sequence,
            epoch,
            verification_hash,
            success: false,
        }
    }

    /// Encode this ack into wire-format bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(CHUNK_ACK_FRAME_SIZE);
        buf.extend_from_slice(REPLICA_CHUNK_ACK_MAGIC);
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        buf.extend_from_slice(&self.verification_hash);
        buf.push(u8::from(self.success));
        buf
    }

    /// Decode a `ReplicaChunkAck` from wire-format bytes.
    ///
    /// # Errors
    ///
    /// Returns `DecodeError` if the magic or framing is invalid.
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        if data.len() < CHUNK_ACK_FRAME_SIZE {
            return Err(DecodeError::TooShort {
                needed: CHUNK_ACK_FRAME_SIZE,
                got: data.len(),
            });
        }
        if &data[0..4] != REPLICA_CHUNK_ACK_MAGIC.as_slice() {
            return Err(DecodeError::BadMagic);
        }
        let sequence = u64::from_le_bytes(data[4..12].try_into().unwrap());
        let epoch = u64::from_le_bytes(data[12..20].try_into().unwrap());
        let mut verification_hash = [0u8; 32];
        verification_hash.copy_from_slice(&data[20..52]);
        let success = data[52] != 0;
        Ok(Self {
            sequence,
            epoch,
            verification_hash,
            success,
        })
    }
}

// ── DecodeError ──────────────────────────────────────────────────────

/// Errors that can occur during chunk/ack decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Input buffer is too short to contain a valid frame.
    TooShort { needed: usize, got: usize },
    /// Magic bytes do not match the expected value.
    BadMagic,
    /// The wire format version is not supported.
    UnknownVersion { version: u32 },
    /// The payload section was truncated relative to its declared length.
    PayloadTruncated { expected: usize, got: usize },
    /// The payload BLAKE3 checksum does not match the computed value.
    ChecksumMismatch,
    /// The declared length field disagrees with the actual payload length.
    LengthMismatch { declared: u64, actual: u64 },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { needed, got } => {
                write!(f, "buffer too short: need {needed} bytes, got {got}")
            }
            Self::BadMagic => write!(f, "bad magic bytes"),
            Self::UnknownVersion { version } => {
                write!(f, "unknown chunk format version: {version}")
            }
            Self::PayloadTruncated { expected, got } => {
                write!(f, "payload truncated: expected {expected} bytes, got {got}")
            }
            Self::ChecksumMismatch => write!(f, "payload BLAKE3 checksum mismatch"),
            Self::LengthMismatch { declared, actual } => {
                write!(
                    f,
                    "length field {declared} disagrees with actual payload length {actual}"
                )
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_object_id() -> [u8; 32] {
        *blake3::hash(b"test-object").as_bytes()
    }

    // ── ReplicaChunk encode/decode round-trip ─────────────────────

    #[test]
    fn encode_decode_roundtrip_empty_payload() {
        let chunk = ReplicaChunk::new(1, 42, test_object_id(), 0, vec![]);
        let encoded = chunk.encode();
        let decoded = ReplicaChunk::decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded, chunk);
        assert!(decoded.verify_checksum());
    }

    #[test]
    fn encode_decode_roundtrip_with_payload() {
        let payload = b"hello replica world".to_vec();
        let chunk = ReplicaChunk::new(7, 100, test_object_id(), 4096, payload);
        let encoded = chunk.encode();
        let decoded = ReplicaChunk::decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded, chunk);
        assert!(decoded.verify_checksum());
    }

    #[test]
    fn encode_decode_large_payload() {
        let payload = vec![0xABu8; 65536];
        let chunk = ReplicaChunk::new(3, 5, test_object_id(), 0, payload);
        let encoded = chunk.encode();
        let decoded = ReplicaChunk::decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded, chunk);
    }

    #[test]
    fn decode_too_short() {
        let result = ReplicaChunk::decode(b"short");
        assert!(matches!(result, Err(DecodeError::TooShort { .. })));
    }

    #[test]
    fn decode_bad_magic() {
        let mut buf = vec![0u8; CHUNK_HEADER_SIZE + 4];
        buf[0..16].copy_from_slice(b"BAD_MAGIC_XXXXXX");
        buf[16..20].copy_from_slice(&1u32.to_le_bytes());
        buf[116..120].copy_from_slice(&0u32.to_le_bytes());
        let result = ReplicaChunk::decode(&buf);
        assert!(matches!(result, Err(DecodeError::BadMagic)));
    }

    #[test]
    fn decode_unknown_version() {
        let mut buf = vec![0u8; CHUNK_HEADER_SIZE + 4];
        buf[0..16].copy_from_slice(REPLICA_CHUNK_MAGIC);
        buf[16..20].copy_from_slice(&99u32.to_le_bytes());
        buf[116..120].copy_from_slice(&0u32.to_le_bytes());
        let result = ReplicaChunk::decode(&buf);
        assert!(matches!(
            result,
            Err(DecodeError::UnknownVersion { version: 99 })
        ));
    }

    #[test]
    fn decode_checksum_mismatch() {
        let payload = b"correct payload".to_vec();
        let mut chunk = ReplicaChunk::new(1, 1, test_object_id(), 0, payload);
        // Corrupt the checksum
        chunk.payload_checksum[0] ^= 0xFF;
        let encoded = chunk.encode();
        let result = ReplicaChunk::decode(&encoded);
        assert!(matches!(result, Err(DecodeError::ChecksumMismatch)));
    }

    #[test]
    fn decode_payload_truncated() {
        let chunk = ReplicaChunk::new(1, 1, test_object_id(), 0, b"hello".to_vec());
        let mut encoded = chunk.encode();
        // Remove last byte of payload
        encoded.pop();
        let result = ReplicaChunk::decode(&encoded);
        assert!(matches!(result, Err(DecodeError::PayloadTruncated { .. })));
    }

    #[test]
    fn verify_checksum_correct() {
        let chunk = ReplicaChunk::new(1, 1, test_object_id(), 0, b"data".to_vec());
        assert!(chunk.verify_checksum());
    }

    #[test]
    fn verify_checksum_incorrect() {
        let mut chunk = ReplicaChunk::new(1, 1, test_object_id(), 0, b"data".to_vec());
        chunk.payload = b"tampered".to_vec();
        assert!(!chunk.verify_checksum());
    }

    // ── ReplicaChunkAck encode/decode round-trip ──────────────────

    #[test]
    fn ack_encode_decode_success() {
        let hash = *blake3::hash(b"verified").as_bytes();
        let ack = ReplicaChunkAck::success(42, 7, hash);
        let encoded = ack.encode();
        let decoded = ReplicaChunkAck::decode(&encoded).expect("ack decode should succeed");
        assert_eq!(decoded, ack);
        assert!(decoded.success);
    }

    #[test]
    fn ack_encode_decode_failure() {
        let hash = *blake3::hash(b"bad").as_bytes();
        let ack = ReplicaChunkAck::failure(1, 3, hash);
        let encoded = ack.encode();
        let decoded = ReplicaChunkAck::decode(&encoded).expect("ack decode should succeed");
        assert_eq!(decoded, ack);
        assert!(!decoded.success);
    }

    #[test]
    fn ack_decode_too_short() {
        let result = ReplicaChunkAck::decode(b"x");
        assert!(matches!(result, Err(DecodeError::TooShort { .. })));
    }

    #[test]
    fn ack_decode_bad_magic() {
        let mut buf = vec![0u8; CHUNK_ACK_FRAME_SIZE];
        buf[0..4].copy_from_slice(b"XXXX");
        let result = ReplicaChunkAck::decode(&buf);
        assert!(matches!(result, Err(DecodeError::BadMagic)));
    }

    #[test]
    fn ack_decode_valid_invalid_checksum_cases() {
        // Valid success ack
        let hash = *blake3::hash(b"data1").as_bytes();
        let ack = ReplicaChunkAck::success(10, 5, hash);
        let encoded = ack.encode();
        let decoded = ReplicaChunkAck::decode(&encoded).expect("valid ack");
        assert_eq!(decoded.verification_hash, hash);
        assert!(decoded.success);

        // Valid failure ack
        let hash2 = *blake3::hash(b"data2").as_bytes();
        let ack2 = ReplicaChunkAck::failure(11, 6, hash2);
        let encoded2 = ack2.encode();
        let decoded2 = ReplicaChunkAck::decode(&encoded2).expect("valid ack");
        assert_eq!(decoded2.verification_hash, hash2);
        assert!(!decoded2.success);
    }

    #[test]
    fn chunk_header_size_constant_correct() {
        // Verify header size matches our wire layout calculation
        assert_eq!(CHUNK_HEADER_SIZE, 16 + 4 + 8 + 8 + 32 + 8 + 8 + 32 + 4);
        assert_eq!(CHUNK_ACK_FRAME_SIZE, 4 + 8 + 8 + 32 + 1);
    }
}
