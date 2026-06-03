//! State transfer message types for deterministic node catch-up.
//!
//! These types carry object identifiers and payload data with BLAKE3
//! integrity verification via tidefs-binary_schema-checksum primitives.
//!
//! ## Wire format
//!
//! Both `StateTransferRequest` and `StateTransferChunk` use `bincode` for
//! binary encode/decode. Payload integrity is protected by a domain-separated
//! BLAKE3 digest embedded in each chunk.

use serde::{Deserialize, Serialize};
use tidefs_binary_schema_checksum::{blake3_domain_digest, blake3_domain_verify};
use tidefs_binary_schema_core::{
    BinarySchemaError, DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion,
};

// ---------------------------------------------------------------------------
// Domain constants for state transfer payload integrity.
// ---------------------------------------------------------------------------

/// Schema family for state transfer messages.
const ST_FAMILY: SchemaFamilyId = SchemaFamilyId(8);

/// Schema type for state transfer payloads.
const ST_TYPE: SchemaTypeId = SchemaTypeId(1);

/// Schema version for state transfer v1.0.
const ST_VERSION: SchemaVersion = SchemaVersion::new(1, 0);

/// Domain tag: TransferStream (P2-03 §4, tag 8).
const ST_DOMAIN_TAG: DomainTag = DomainTag::TransferStream;

// ---------------------------------------------------------------------------
// StateTransferRequest
// ---------------------------------------------------------------------------

/// Request from a joining node asking an existing node for specific objects.
///
/// Sent after epoch admission to trigger catch-up of missing object data.
/// The receiver should respond with zero or more [`StateTransferChunk`]
/// messages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateTransferRequest {
    /// The epoch in which this request is made.
    pub epoch_id: u64,
    /// The node requesting the objects.
    pub requesting_node: u64,
    /// Object IDs being requested.
    pub object_ids: Vec<u64>,
    /// Maximum chunk size the requester can accept, in bytes.
    pub max_chunk_bytes: u64,
}

impl StateTransferRequest {
    /// Create a new state transfer request.
    pub fn new(
        epoch_id: u64,
        requesting_node: u64,
        object_ids: Vec<u64>,
        max_chunk_bytes: u64,
    ) -> Self {
        Self {
            epoch_id,
            requesting_node,
            object_ids,
            max_chunk_bytes,
        }
    }

    /// Encode to binary via bincode.
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Decode from binary via bincode.
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

// ---------------------------------------------------------------------------
// StateTransferChunk
// ---------------------------------------------------------------------------

/// A chunk of state transfer data for a single object.
///
/// Carries a slice of object payload with a domain-separated BLAKE3 digest
/// for integrity verification. The receiver must verify the digest before
/// accepting the chunk data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateTransferChunk {
    /// The epoch this chunk belongs to.
    pub epoch_id: u64,
    /// The object this chunk belongs to.
    pub object_id: u64,
    /// Byte offset within the object.
    pub offset: u64,
    /// Total object size (same for all chunks of this object).
    pub total_size: u64,
    /// Payload data.
    pub payload: Vec<u8>,
    /// Domain-separated BLAKE3 digest of the payload (32 bytes).
    pub payload_digest: [u8; 32],
    /// Whether this is the last chunk for this object.
    pub is_last: bool,
}

impl StateTransferChunk {
    /// Create a new chunk, computing the BLAKE3 payload digest automatically.
    pub fn new(
        epoch_id: u64,
        object_id: u64,
        offset: u64,
        total_size: u64,
        payload: Vec<u8>,
        is_last: bool,
    ) -> Self {
        let payload_digest =
            blake3_domain_digest(&payload, ST_FAMILY, ST_TYPE, ST_VERSION, ST_DOMAIN_TAG);
        Self {
            epoch_id,
            object_id,
            offset,
            total_size,
            payload,
            payload_digest,
            is_last,
        }
    }

    /// Verify the payload against the embedded BLAKE3 digest.
    ///
    /// Returns `Ok(())` if the payload matches its digest, or
    /// `BinarySchemaError::DigestMismatch` if it does not.
    pub fn verify_payload(&self) -> Result<(), BinarySchemaError> {
        blake3_domain_verify(
            &self.payload,
            &self.payload_digest,
            ST_FAMILY,
            ST_TYPE,
            ST_VERSION,
            ST_DOMAIN_TAG,
        )
    }

    /// Encode to binary via bincode.
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Decode from binary via bincode.
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── StateTransferRequest round-trip ───────────────────────────────

    #[test]
    fn request_roundtrip_bincode() {
        let req = StateTransferRequest::new(1, 2, vec![10, 20, 30], 65536);
        let encoded = req.encode().unwrap();
        let decoded = StateTransferRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_roundtrip_empty_object_ids() {
        let req = StateTransferRequest::new(3, 4, vec![], 4096);
        let encoded = req.encode().unwrap();
        let decoded = StateTransferRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_roundtrip_single_object() {
        let req = StateTransferRequest::new(5, 6, vec![7], 1024);
        let encoded = req.encode().unwrap();
        let decoded = StateTransferRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_encode_produces_non_empty_bytes() {
        let req = StateTransferRequest::new(1, 2, vec![42], 8192);
        let encoded = req.encode().unwrap();
        assert!(!encoded.is_empty());
    }

    // ── StateTransferChunk round-trip ─────────────────────────────────

    #[test]
    fn chunk_roundtrip_bincode() {
        let payload = b"state transfer test payload".to_vec();
        let chunk = StateTransferChunk::new(1, 42, 0, payload.len() as u64, payload.clone(), true);

        let encoded = chunk.encode().unwrap();
        let decoded = StateTransferChunk::decode(&encoded).unwrap();
        assert_eq!(decoded, chunk);
    }

    #[test]
    fn chunk_roundtrip_empty_payload() {
        let chunk = StateTransferChunk::new(1, 99, 0, 0, vec![], true);

        let encoded = chunk.encode().unwrap();
        let decoded = StateTransferChunk::decode(&encoded).unwrap();
        assert_eq!(decoded, chunk);
    }

    #[test]
    fn chunk_roundtrip_large_payload() {
        let payload = vec![0xABu8; 65536];
        let chunk = StateTransferChunk::new(2, 7, 4096, 131072, payload.clone(), false);

        let encoded = chunk.encode().unwrap();
        let decoded = StateTransferChunk::decode(&encoded).unwrap();
        assert_eq!(decoded, chunk);
    }

    #[test]
    fn chunk_roundtrip_nonzero_offset() {
        let payload = b"middle chunk data".to_vec();
        let chunk = StateTransferChunk::new(3, 10, 4096, 16384, payload.clone(), false);

        let encoded = chunk.encode().unwrap();
        let decoded = StateTransferChunk::decode(&encoded).unwrap();
        assert_eq!(decoded, chunk);
    }

    // ── Digest determinism and uniqueness ─────────────────────────────

    #[test]
    fn chunk_payload_digest_is_deterministic() {
        let payload = b"deterministic payload".to_vec();
        let c1 = StateTransferChunk::new(1, 1, 0, payload.len() as u64, payload.clone(), false);
        let c2 = StateTransferChunk::new(1, 1, 0, payload.len() as u64, payload, false);
        assert_eq!(c1.payload_digest, c2.payload_digest);
    }

    #[test]
    fn chunk_digest_differs_by_payload() {
        let c1 = StateTransferChunk::new(1, 1, 0, 5, b"hello".to_vec(), false);
        let c2 = StateTransferChunk::new(1, 1, 0, 5, b"world".to_vec(), false);
        assert_ne!(c1.payload_digest, c2.payload_digest);
    }

    #[test]
    fn chunk_digest_is_content_based_not_metadata_based() {
        // Same payload, different offset/object → same digest (content-addressed).
        let payload = b"content-addressed".to_vec();
        let c1 = StateTransferChunk::new(1, 1, 0, payload.len() as u64, payload.clone(), false);
        let c2 = StateTransferChunk::new(2, 2, 4096, payload.len() as u64, payload, false);
        assert_eq!(c1.payload_digest, c2.payload_digest);
    }

    // ── Payload verification ──────────────────────────────────────────

    #[test]
    fn verify_payload_succeeds_for_valid_chunk() {
        let chunk = StateTransferChunk::new(1, 42, 0, 10, b"valid data".to_vec(), true);
        assert!(chunk.verify_payload().is_ok());
    }

    #[test]
    fn verify_payload_fails_for_tampered_payload() {
        let mut chunk = StateTransferChunk::new(1, 42, 0, 10, b"valid data".to_vec(), true);

        // Tamper with the payload without updating the digest
        chunk.payload = b"BAD DATA!!".to_vec();

        let result = chunk.verify_payload();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BinarySchemaError::DigestMismatch
        ));
    }

    #[test]
    fn verify_payload_fails_for_tampered_digest() {
        let mut chunk = StateTransferChunk::new(1, 42, 0, 10, b"valid data".to_vec(), true);

        // Tamper with the digest without changing the payload
        chunk.payload_digest[0] ^= 0xFF;

        let result = chunk.verify_payload();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BinarySchemaError::DigestMismatch
        ));
    }

    #[test]
    fn verify_payload_empty_chunk() {
        let chunk = StateTransferChunk::new(1, 99, 0, 0, vec![], true);
        assert!(chunk.verify_payload().is_ok());
    }

    // ── Last-chunk flag ───────────────────────────────────────────────

    #[test]
    fn last_chunk_flag_is_preserved() {
        let chunk = StateTransferChunk::new(1, 42, 0, 10, b"last one".to_vec(), true);
        assert!(chunk.is_last);

        let chunk = StateTransferChunk::new(1, 42, 0, 10, b"more coming".to_vec(), false);
        assert!(!chunk.is_last);
    }
}
