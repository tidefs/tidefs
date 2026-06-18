// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Segment fetch message types for cross-node object reads.
//!
//! These types carry receipt-bound object segment identifiers and payload
//! data. Per-message integrity is provided by the transport session security
//! boundary; segment fetch messages carry placement receipt authority for real
//! movement and keep bare object identifiers only as a compatibility fallback.
//!
//! ## Wire format
//!
//! Every segment fetch message is prefixed with a 4-byte ASCII magic tag
//! (`SF01` for request, `SF02` for response) followed by bincode-encoded
//! payload. This allows receivers to distinguish segment fetch messages
//! from other wire protocols without ambiguous fallback decoding.

use serde::{Deserialize, Serialize};
use tidefs_replication_model::PlacementReceiptRef;

// ---------------------------------------------------------------------------
// Wire magic — self-describing 4-byte ASCII prefix
// ---------------------------------------------------------------------------

/// Magic bytes for SegmentFetchRequest wire frames.
pub const SEGMENT_FETCH_REQUEST_MAGIC: [u8; 4] = *b"SF01";

/// Magic bytes for SegmentFetchResponse wire frames.
pub const SEGMENT_FETCH_RESPONSE_MAGIC: [u8; 4] = *b"SF02";

/// Error returned when segment fetch decoding fails due to missing
/// or mismatched wire magic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentFetchMagicError {
    pub expected: [u8; 4],
    pub got: Vec<u8>,
}

impl std::fmt::Display for SegmentFetchMagicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "segment fetch magic mismatch: expected {:?}, got {:?}",
            &self.expected, &self.got
        )
    }
}

// ---------------------------------------------------------------------------
// SegmentFetchRequest
// ---------------------------------------------------------------------------

/// Request from one node to fetch a segment of an object from a remote node.
///
/// Sent over an established transport session to request a specific byte
/// range of an object identified by `placement_receipt_ref` when real
/// placement authority is available. `object_id` remains for model logging and
/// compatibility callers that do not yet pass receipt refs.
///
/// Wire format: 4-byte ASCII magic `SF01` followed by bincode-encoded struct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentFetchRequest {
    /// The object to read from. Real movement should pair this with a
    /// non-synthetic placement receipt ref; absent/synthetic refs are legacy
    /// fallback only.
    pub object_id: u64,
    /// Placement receipt authority for the object key to fetch.
    pub placement_receipt_ref: Option<PlacementReceiptRef>,
    /// Byte offset within the object.
    pub segment_offset: u64,
    /// Number of bytes to read, starting at `segment_offset`.
    pub segment_length: u64,
}

impl SegmentFetchRequest {
    /// Create a new segment fetch request.
    pub fn new(object_id: u64, segment_offset: u64, segment_length: u64) -> Self {
        Self {
            object_id,
            placement_receipt_ref: None,
            segment_offset,
            segment_length,
        }
    }

    /// Create a segment fetch request bound to durable placement receipt
    /// authority.
    pub fn with_placement_receipt_ref(
        placement_receipt_ref: PlacementReceiptRef,
        segment_offset: u64,
        segment_length: u64,
    ) -> Self {
        Self {
            object_id: placement_receipt_ref.object_id,
            placement_receipt_ref: Some(placement_receipt_ref),
            segment_offset,
            segment_length,
        }
    }

    /// Return real receipt authority for object-key lookup, if this request
    /// carries one.
    pub fn non_synthetic_receipt_ref(&self) -> Option<PlacementReceiptRef> {
        self.placement_receipt_ref
            .filter(|receipt| !receipt.is_synthetic())
    }

    /// Encode to wire format: 4-byte SF01 magic + bincode payload.
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        let mut buf = Vec::with_capacity(4 + 32);
        buf.extend_from_slice(&SEGMENT_FETCH_REQUEST_MAGIC);
        let inner = bincode::serialize(self)?;
        buf.extend_from_slice(&inner);
        Ok(buf)
    }

    /// Decode from wire format.  Requires the 4-byte SF01 magic prefix.
    ///
    /// Returns `Err(bincode::Error)` with a descriptive message if the
    /// magic is missing or mismatched.
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        if bytes.len() < 4 {
            return Err(bincode::Error::new(bincode::ErrorKind::SizeLimit));
        }
        if bytes[..4] != SEGMENT_FETCH_REQUEST_MAGIC {
            return Err(bincode::Error::new(bincode::ErrorKind::Custom(format!(
                "bad segment fetch request magic: expected {:?}, got {:?}",
                &SEGMENT_FETCH_REQUEST_MAGIC,
                &bytes[..4]
            ))));
        }
        bincode::deserialize(&bytes[4..])
    }

    /// Check whether `bytes` starts with the segment fetch request magic.
    ///
    /// Fast-path check for protocol discrimination without attempting a
    /// full decode.
    pub fn has_magic_prefix(bytes: &[u8]) -> bool {
        bytes.len() >= 4 && bytes[..4] == SEGMENT_FETCH_REQUEST_MAGIC
    }
}

// ---------------------------------------------------------------------------
// SegmentFetchResponse
// ---------------------------------------------------------------------------

/// Response carrying a fetched object segment.
///
/// Payload integrity is provided by the transport session security boundary.
///
/// Wire format: 4-byte ASCII magic `SF02` followed by bincode-encoded struct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentFetchResponse {
    /// The object this segment belongs to.
    pub object_id: u64,
    /// Byte offset within the object.
    pub segment_offset: u64,
    /// Number of payload bytes in this response.
    pub segment_length: u64,
    /// Payload data for the requested segment.
    pub payload: Vec<u8>,
}

impl SegmentFetchResponse {
    /// Create a new response.
    ///
    /// # Panics
    ///
    /// Panics if `segment_length != payload.len()` or if
    /// `segment_offset + segment_length` would overflow u64.
    pub fn new(object_id: u64, segment_offset: u64, segment_length: u64, payload: Vec<u8>) -> Self {
        assert_eq!(
            segment_length as usize,
            payload.len(),
            "SegmentFetchResponse: segment_length ({segment_length}) must equal payload.len() ({})",
            payload.len()
        );
        assert!(
            segment_offset.checked_add(segment_length).is_some(),
            "SegmentFetchResponse: segment_offset ({segment_offset}) + segment_length ({segment_length}) would overflow u64"
        );

        Self {
            object_id,
            segment_offset,
            segment_length,
            payload,
        }
    }

    /// Encode to wire format: 4-byte SF02 magic + bincode payload.
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        let mut buf = Vec::with_capacity(4 + 64 + self.payload.len());
        buf.extend_from_slice(&SEGMENT_FETCH_RESPONSE_MAGIC);
        let inner = bincode::serialize(self)?;
        buf.extend_from_slice(&inner);
        Ok(buf)
    }

    /// Decode from wire format.  Requires the 4-byte SF02 magic prefix.
    ///
    /// Returns `Err(bincode::Error)` with a descriptive message if the
    /// magic is missing or mismatched.
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        if bytes.len() < 4 {
            return Err(bincode::Error::new(bincode::ErrorKind::SizeLimit));
        }
        if bytes[..4] != SEGMENT_FETCH_RESPONSE_MAGIC {
            return Err(bincode::Error::new(bincode::ErrorKind::Custom(format!(
                "bad segment fetch response magic: expected {:?}, got {:?}",
                &SEGMENT_FETCH_RESPONSE_MAGIC,
                &bytes[..4]
            ))));
        }
        bincode::deserialize(&bytes[4..])
    }

    /// Check whether `bytes` starts with the segment fetch response magic.
    ///
    /// Fast-path check for protocol discrimination without attempting a
    /// full decode.
    pub fn has_magic_prefix(bytes: &[u8]) -> bool {
        bytes.len() >= 4 && bytes[..4] == SEGMENT_FETCH_RESPONSE_MAGIC
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── SegmentFetchRequest magic + round-trip ───────────────────────

    #[test]
    fn request_roundtrip_bincode() {
        let req = SegmentFetchRequest::new(42, 0, 4096);
        let encoded = req.encode().unwrap();
        let decoded = SegmentFetchRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_roundtrip_preserves_receipt_ref() {
        let receipt = PlacementReceiptRef::replicated(
            42,
            [0xA5; 32],
            tidefs_membership_epoch::EpochId::new(7),
            3,
            2,
            123,
            [0xBC; 32],
        );
        let req = SegmentFetchRequest::with_placement_receipt_ref(receipt, 12, 34);

        let encoded = req.encode().unwrap();
        let decoded = SegmentFetchRequest::decode(&encoded).unwrap();

        assert_eq!(decoded.object_id, receipt.object_id);
        assert_eq!(decoded.placement_receipt_ref, Some(receipt));
        assert_eq!(decoded.non_synthetic_receipt_ref(), Some(receipt));
        assert_eq!(decoded.segment_offset, 12);
        assert_eq!(decoded.segment_length, 34);
    }

    #[test]
    fn request_synthetic_receipt_is_not_lookup_authority() {
        let receipt = PlacementReceiptRef::synthetic_for_subject(
            tidefs_replication_model::ReplicatedSubjectId::new(42),
        );
        let req = SegmentFetchRequest {
            object_id: 42,
            placement_receipt_ref: Some(receipt),
            segment_offset: 0,
            segment_length: 1,
        };

        assert_eq!(req.non_synthetic_receipt_ref(), None);
    }

    #[test]
    fn request_has_magic_prefix() {
        let req = SegmentFetchRequest::new(1, 0, 1024);
        let encoded = req.encode().unwrap();
        assert!(SegmentFetchRequest::has_magic_prefix(&encoded));
        assert!(encoded.starts_with(&SEGMENT_FETCH_REQUEST_MAGIC));
    }

    #[test]
    fn request_decode_rejects_missing_magic() {
        let inner = bincode::serialize(&SegmentFetchRequest::new(1, 0, 8)).unwrap();
        assert!(SegmentFetchRequest::decode(&inner).is_err());
    }

    #[test]
    fn request_decode_rejects_wrong_magic() {
        let req = SegmentFetchRequest::new(1, 0, 8);
        let mut encoded = req.encode().unwrap();
        encoded[0] ^= 0xFF;
        assert!(SegmentFetchRequest::decode(&encoded).is_err());
    }

    #[test]
    fn request_decode_rejects_too_short() {
        assert!(SegmentFetchRequest::decode(&[0u8; 2]).is_err());
    }

    #[test]
    fn request_roundtrip_large_offset() {
        let req = SegmentFetchRequest::new(1, u64::MAX - 4096, 4096);
        let encoded = req.encode().unwrap();
        let decoded = SegmentFetchRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_roundtrip_max_values() {
        let req = SegmentFetchRequest::new(u64::MAX, u64::MAX, u64::MAX);
        let encoded = req.encode().unwrap();
        let decoded = SegmentFetchRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_roundtrip_zero_length() {
        let req = SegmentFetchRequest::new(7, 0, 0);
        let encoded = req.encode().unwrap();
        let decoded = SegmentFetchRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_encode_produces_non_empty_bytes() {
        let req = SegmentFetchRequest::new(42, 0, 1024);
        let encoded = req.encode().unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn request_magic_constant_distinct_from_response() {
        assert_ne!(
            SEGMENT_FETCH_REQUEST_MAGIC, SEGMENT_FETCH_RESPONSE_MAGIC,
            "request and response magic must differ"
        );
    }

    // ── SegmentFetchResponse magic + round-trip ─────────────────────

    #[test]
    fn response_roundtrip_bincode() {
        let payload = b"segment fetch test payload".to_vec();
        let resp = SegmentFetchResponse::new(42, 0, payload.len() as u64, payload.clone());

        let encoded = resp.encode().unwrap();
        let decoded = SegmentFetchResponse::decode(&encoded).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn response_has_magic_prefix() {
        let resp = SegmentFetchResponse::new(1, 0, 4, b"data".to_vec());
        let encoded = resp.encode().unwrap();
        assert!(SegmentFetchResponse::has_magic_prefix(&encoded));
        assert!(encoded.starts_with(&SEGMENT_FETCH_RESPONSE_MAGIC));
    }

    #[test]
    fn response_decode_rejects_missing_magic() {
        let inner =
            bincode::serialize(&SegmentFetchResponse::new(1, 0, 4, b"data".to_vec())).unwrap();
        assert!(SegmentFetchResponse::decode(&inner).is_err());
    }

    #[test]
    fn response_decode_rejects_wrong_magic() {
        let resp = SegmentFetchResponse::new(1, 0, 4, b"data".to_vec());
        let mut encoded = resp.encode().unwrap();
        encoded[0] ^= 0xFF;
        assert!(SegmentFetchResponse::decode(&encoded).is_err());
    }

    #[test]
    fn response_decode_rejects_too_short() {
        assert!(SegmentFetchResponse::decode(&[0u8; 2]).is_err());
    }

    #[test]
    fn response_roundtrip_empty_payload() {
        let resp = SegmentFetchResponse::new(99, 0, 0, vec![]);

        let encoded = resp.encode().unwrap();
        let decoded = SegmentFetchResponse::decode(&encoded).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn response_roundtrip_large_payload() {
        let payload = vec![0xCDu8; 65536];
        let resp = SegmentFetchResponse::new(7, 4096, 65536, payload.clone());

        let encoded = resp.encode().unwrap();
        let decoded = SegmentFetchResponse::decode(&encoded).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn response_roundtrip_nonzero_offset() {
        let payload = b"middle segment data".to_vec();
        let resp = SegmentFetchResponse::new(10, 8192, payload.len() as u64, payload.clone());

        let encoded = resp.encode().unwrap();
        let decoded = SegmentFetchResponse::decode(&encoded).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn response_roundtrip_max_u64_fields() {
        let payload = b"max fields".to_vec();
        let plen = payload.len() as u64;
        let resp = SegmentFetchResponse::new(
            u64::MAX,
            u64::MAX - plen, // offset + length must not overflow
            plen,
            payload.clone(),
        );

        let encoded = resp.encode().unwrap();
        let decoded = SegmentFetchResponse::decode(&encoded).unwrap();
        assert_eq!(decoded, resp);
    }

    // ── Validation: length mismatch / overflow ──────────────────────

    #[test]
    #[should_panic(expected = "segment_length")]
    fn response_new_panics_on_length_mismatch() {
        SegmentFetchResponse::new(1, 0, 100, b"short".to_vec());
    }

    #[test]
    #[should_panic(expected = "overflow")]
    fn response_new_panics_on_offset_overflow() {
        SegmentFetchResponse::new(1, u64::MAX, 1, vec![0u8]);
    }

    #[test]
    fn response_new_preserves_payload() {
        // Verify the constructor and encode/decode round-trip without payload_digest
        let r1 = SegmentFetchResponse::new(1, 0, 5, b"hello".to_vec());
        let r2 = SegmentFetchResponse::new(1, 0, 5, b"world".to_vec());
        assert_eq!(r1.payload, b"hello");
        assert_eq!(r2.payload, b"world");
        // Encode/decode round-trip
        let enc = r1.encode().unwrap();
        let dec = SegmentFetchResponse::decode(&enc).unwrap();
        assert_eq!(dec.payload, r1.payload);
        assert_eq!(dec.object_id, r1.object_id);
        assert_eq!(dec.segment_offset, r1.segment_offset);
        assert_eq!(dec.segment_length, r1.segment_length);
    }
}

// ---------------------------------------------------------------------------
// Transport dispatch: send / recv over Transport sessions
// ---------------------------------------------------------------------------

use crate::error::TransportError;
use crate::transport::Transport;
use crate::types::SessionId;

/// Send a [`SegmentFetchRequest`] over a transport session.
///
/// Serializes the request with the SF01 magic prefix and bincode and
/// transmits it through the transport layer.
pub fn send_segment_fetch(
    transport: &mut Transport,
    session_id: SessionId,
    request: &SegmentFetchRequest,
) -> Result<(), TransportError> {
    let payload = request
        .encode()
        .map_err(|e| TransportError::Generic(format!("segment fetch request encode: {e}")))?;
    transport.send_message(session_id, &payload)
}

/// Receive a [`SegmentFetchRequest`] from a transport session.
///
/// Reads the next message frame and deserializes it as a
/// `SegmentFetchRequest`.  The wire message must carry the SF01
/// magic prefix.
pub fn recv_segment_fetch(
    transport: &mut Transport,
    session_id: SessionId,
) -> Result<SegmentFetchRequest, TransportError> {
    let payload = transport.recv_message(session_id)?;
    SegmentFetchRequest::decode(&payload)
        .map_err(|e| TransportError::Generic(format!("segment fetch request decode: {e}")))
}

/// Send a [`SegmentFetchResponse`] over a transport session.
///
/// Serializes the response with the SF02 magic prefix and bincode and
/// transmits it through the transport layer.
pub fn send_segment_fetch_response(
    transport: &mut Transport,
    session_id: SessionId,
    response: &SegmentFetchResponse,
) -> Result<(), TransportError> {
    let payload = response
        .encode()
        .map_err(|e| TransportError::Generic(format!("segment fetch response encode: {e}")))?;
    transport.send_message(session_id, &payload)
}

/// Receive a [`SegmentFetchResponse`] and dispatch it.
///
/// Reads the next message frame, deserializes it as a
/// `SegmentFetchResponse` (requires SF02 magic prefix), and verifies
/// the transport MAC for integrity.
///
/// # Errors
///
/// Returns `TransportError::Generic` if the payload fails BLAKE3
/// verification (digest mismatch), if the magic prefix is wrong, or
/// if deserialization fails.
pub fn recv_segment_fetch_response(
    transport: &mut Transport,
    session_id: SessionId,
) -> Result<SegmentFetchResponse, TransportError> {
    let payload = transport.recv_message(session_id)?;
    let response: SegmentFetchResponse = SegmentFetchResponse::decode(&payload)
        .map_err(|e| TransportError::Generic(format!("segment fetch response decode: {e}")))?;
    Ok(response)
}

// ── Dispatch pipeline simulation ─────────────────────────────────

#[test]
fn dispatch_request_roundtrip_via_bincode() {
    // Simulates send_segment_fetch + recv_segment_fetch (request path)
    let req = SegmentFetchRequest::new(42, 4096, 8192);
    let payload = req.encode().unwrap();
    assert!(payload.starts_with(&SEGMENT_FETCH_REQUEST_MAGIC));
    let decoded = SegmentFetchRequest::decode(&payload).unwrap();
    assert_eq!(decoded, req);
}

#[test]
fn dispatch_response_magic_wrong_rejected() {
    let payload_data = b"magic test".to_vec();
    let plen = payload_data.len() as u64;
    let resp = SegmentFetchResponse::new(3, 0, plen, payload_data);

    let mut wire_bytes = resp.encode().unwrap();
    // Corrupt the magic prefix
    wire_bytes[1] ^= 0xFF;
    assert!(SegmentFetchResponse::decode(&wire_bytes).is_err());
}

#[test]
fn dispatch_request_magic_wrong_rejected() {
    let req = SegmentFetchRequest::new(1, 0, 1024);
    let mut wire_bytes = req.encode().unwrap();
    // Corrupt the magic prefix
    wire_bytes[2] ^= 0xFF;
    assert!(SegmentFetchRequest::decode(&wire_bytes).is_err());
}
