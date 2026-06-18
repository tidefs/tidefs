// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Object enumeration message types for rebuild/backfill state transfer.
//!
//! These types carry compact object entries (object_key, size, BLAKE3 root)
//! with domain-separated BLAKE3 integrity verification over the full
//! response payload.
//!
//! ## Wire format
//!
//! Every object list message is prefixed with a 4-byte ASCII magic tag
//! (`LO01` for request, `LO02` for response) followed by bincode-encoded
//! payload. This allows receivers to distinguish list-object messages
//! from other wire protocols without ambiguous fallback decoding.
//!
//! ## Message flow
//!
//! ```text
//! Requester                          Holder
//!   |                                  |
//!   |-- ListObjectsRequest -------->  |
//!   |                                  |
//!   |<-- ListObjectsResponse -------- |
//! ```

use serde::{Deserialize, Serialize};
use tidefs_binary_schema_checksum::blake3_domain_digest;
use tidefs_binary_schema_core::{
    BinarySchemaError, DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion,
};

// ---------------------------------------------------------------------------
// Wire magic -- self-describing 4-byte ASCII prefix
// ---------------------------------------------------------------------------

/// Magic bytes for ListObjectsRequest wire frames.
pub const LIST_OBJECTS_REQUEST_MAGIC: [u8; 4] = *b"LO01";

/// Magic bytes for ListObjectsResponse wire frames.
pub const LIST_OBJECTS_RESPONSE_MAGIC: [u8; 4] = *b"LO02";

// ---------------------------------------------------------------------------
// Domain constants for object list integrity.
// ---------------------------------------------------------------------------

/// Schema family for object list messages (next after segment-fetch's 10).
const OL_FAMILY: SchemaFamilyId = SchemaFamilyId(11);

/// Schema type for object list payloads.
const OL_TYPE: SchemaTypeId = SchemaTypeId(1);

/// Schema version for object list v1.0.
const OL_VERSION: SchemaVersion = SchemaVersion::new(1, 0);

/// Domain tag: ObjectEnumeration.
const OL_DOMAIN_TAG: DomainTag = DomainTag::ObjectEnumeration;

// ---------------------------------------------------------------------------
// ObjectListEntry -- compact per-object identity for enumeration
// ---------------------------------------------------------------------------

/// A compact entry describing one object in an enumeration response.
///
/// Carries the fields a backfill/rebuild planner needs to decide which
/// objects to transfer: identity, size, and a BLAKE3 content root for
/// integrity verification without fetching the full object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectListEntry {
    /// Object identifier in the local object store.
    pub object_key: [u8; 32],
    /// Total object size in bytes.
    pub size: u64,
    /// BLAKE3-256 root hash of the full object content.
    pub blake3_root: [u8; 32],
}

impl ObjectListEntry {
    /// Create a new object list entry.
    pub fn new(object_key: [u8; 32], size: u64, blake3_root: [u8; 32]) -> Self {
        Self {
            object_key,
            size,
            blake3_root,
        }
    }
}

// ---------------------------------------------------------------------------
// ListObjectsRequest
// ---------------------------------------------------------------------------

/// Request from one node to enumerate objects held by a peer.
///
/// Supports range-based scanning via an optional `start_after` cursor
/// and a `max_entries` limit. The receiver responds with a
/// [`ListObjectsResponse`] containing up to `max_entries` entries.
///
/// Wire format: 4-byte ASCII magic `LO01` followed by bincode-encoded struct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListObjectsRequest {
    /// If set, only return objects whose `object_id` is strictly greater
    /// than this value. Used for cursor-based pagination.
    pub start_after: Option<[u8; 32]>,
    /// Maximum number of entries to return in one response.
    pub max_entries: u32,
}

impl ListObjectsRequest {
    /// Create a new list-objects request.
    pub fn new(start_after: Option<[u8; 32]>, max_entries: u32) -> Self {
        Self {
            start_after,
            max_entries,
        }
    }

    /// Encode to wire format: 4-byte LO01 magic + bincode payload.
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        let mut buf = Vec::with_capacity(4 + 32);
        buf.extend_from_slice(&LIST_OBJECTS_REQUEST_MAGIC);
        let inner = bincode::serialize(self)?;
        buf.extend_from_slice(&inner);
        Ok(buf)
    }

    /// Decode from wire format. Requires the 4-byte LO01 magic prefix.
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        if bytes.len() < 4 {
            return Err(bincode::Error::new(bincode::ErrorKind::SizeLimit));
        }
        if bytes[..4] != LIST_OBJECTS_REQUEST_MAGIC {
            return Err(bincode::Error::new(bincode::ErrorKind::Custom(format!(
                "bad list objects request magic: expected {:?}, got {:?}",
                &LIST_OBJECTS_REQUEST_MAGIC,
                &bytes[..4]
            ))));
        }
        bincode::deserialize(&bytes[4..])
    }

    /// Fast-path check for protocol discrimination.
    pub fn has_magic_prefix(bytes: &[u8]) -> bool {
        bytes.len() >= 4 && bytes[..4] == LIST_OBJECTS_REQUEST_MAGIC
    }
}

// ---------------------------------------------------------------------------
// ListObjectsResponse
// ---------------------------------------------------------------------------

/// Response carrying a page of object entries with BLAKE3 integrity.
///
/// The `payload_digest` covers `entries`, `has_more`, `start_after`, and
/// `max_entries` together under a domain-separated BLAKE3 key. This binds
/// the response to its semantic context and prevents tampering or replay
/// of entries for a different request.
///
/// Wire format: 4-byte ASCII magic `LO02` followed by bincode-encoded struct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListObjectsResponse {
    /// The enumerated object entries (zero or more).
    pub entries: Vec<ObjectListEntry>,
    /// True if more entries are available beyond this page.
    pub has_more: bool,
    /// Echoes the request's `start_after` for request correlation.
    pub start_after: Option<[u8; 32]>,
    /// Echoes the request's `max_entries` for request correlation.
    pub max_entries: u32,
    /// Domain-separated BLAKE3 digest binding entries, has_more, start_after,
    /// and max_entries together (32 bytes).
    pub payload_digest: [u8; 32],
}

impl ListObjectsResponse {
    /// Create a new response, computing the BLAKE3 integrity digest over
    /// the bound fields (entries, has_more, start_after, max_entries).
    ///
    /// The digest is computed over a canonical binary encoding of the
    /// bound fields using bincode, same as what would appear on the wire
    /// for these fields (excluding the magic prefix and the digest field
    /// itself).
    pub fn new(
        entries: Vec<ObjectListEntry>,
        has_more: bool,
        start_after: Option<[u8; 32]>,
        max_entries: u32,
    ) -> Self {
        let payload_digest =
            Self::compute_bound_digest(&entries, has_more, start_after, max_entries);
        Self {
            entries,
            has_more,
            start_after,
            max_entries,
            payload_digest,
        }
    }

    /// Compute the domain-separated BLAKE3 digest over the response's
    /// semantically-bound fields.
    fn compute_bound_digest(
        entries: &[ObjectListEntry],
        has_more: bool,
        start_after: Option<[u8; 32]>,
        max_entries: u32,
    ) -> [u8; 32] {
        // Serialize the bound fields with bincode for a canonical digest input.
        let bound = BoundFields {
            entries,
            has_more,
            start_after,
            max_entries,
        };
        let serialized =
            bincode::serialize(&bound).expect("bincode serialize of bound fields should not fail");
        blake3_domain_digest(&serialized, OL_FAMILY, OL_TYPE, OL_VERSION, OL_DOMAIN_TAG)
    }

    /// Verify the payload against the embedded BLAKE3 digest.
    ///
    /// Returns `Ok(())` if the entries match their digest, or
    /// `BinarySchemaError::DigestMismatch` if they do not.
    pub fn verify_payload(&self) -> Result<(), BinarySchemaError> {
        let expected = Self::compute_bound_digest(
            &self.entries,
            self.has_more,
            self.start_after,
            self.max_entries,
        );
        if expected == self.payload_digest {
            Ok(())
        } else {
            Err(BinarySchemaError::DigestMismatch)
        }
    }

    /// Number of entries in this response.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Encode to wire format: 4-byte LO02 magic + bincode payload.
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        let mut buf = Vec::with_capacity(4 + self.entries.len() * 72 + 64);
        buf.extend_from_slice(&LIST_OBJECTS_RESPONSE_MAGIC);
        let inner = bincode::serialize(self)?;
        buf.extend_from_slice(&inner);
        Ok(buf)
    }

    /// Decode from wire format. Requires the 4-byte LO02 magic prefix.
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        if bytes.len() < 4 {
            return Err(bincode::Error::new(bincode::ErrorKind::SizeLimit));
        }
        if bytes[..4] != LIST_OBJECTS_RESPONSE_MAGIC {
            return Err(bincode::Error::new(bincode::ErrorKind::Custom(format!(
                "bad list objects response magic: expected {:?}, got {:?}",
                &LIST_OBJECTS_RESPONSE_MAGIC,
                &bytes[..4]
            ))));
        }
        bincode::deserialize(&bytes[4..])
    }

    /// Fast-path check for protocol discrimination.
    pub fn has_magic_prefix(bytes: &[u8]) -> bool {
        bytes.len() >= 4 && bytes[..4] == LIST_OBJECTS_RESPONSE_MAGIC
    }
}

// ---------------------------------------------------------------------------
// BoundFields -- canonical digest input (not exposed on the wire directly)
// ---------------------------------------------------------------------------

/// Canonical struct for computing the response digest.
///
/// This is serialized with bincode to produce the digest input, ensuring
/// the same byte representation as the on-wire fields (minus magic and
/// the digest field itself).
#[derive(Serialize)]
struct BoundFields<'a> {
    entries: &'a [ObjectListEntry],
    has_more: bool,
    start_after: Option<[u8; 32]>,
    max_entries: u32,
}

// ---------------------------------------------------------------------------
// Dispatch functions
// ---------------------------------------------------------------------------

/// Error type for object-list dispatch operations.
#[derive(Debug)]
pub enum ListObjectsError {
    /// Underlying transport error.
    Transport(String),
    /// Message encode error (bincode).
    Encode(String),
    /// Message decode error (bincode).
    Decode(String),
    /// Payload digest verification failed.
    DigestMismatch,
}

impl std::fmt::Display for ListObjectsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport error: {e}"),
            Self::Encode(e) => write!(f, "encode error: {e}"),
            Self::Decode(e) => write!(f, "decode error: {e}"),
            Self::DigestMismatch => write!(f, "payload digest mismatch"),
        }
    }
}

impl std::error::Error for ListObjectsError {}

impl From<crate::error::TransportError> for ListObjectsError {
    fn from(e: crate::error::TransportError) -> Self {
        Self::Transport(e.to_string())
    }
}

/// Send a ListObjectsRequest over a transport session.
pub fn send_list_objects_request(
    transport: &mut crate::transport::Transport,
    session_id: crate::types::SessionId,
    start_after: Option<[u8; 32]>,
    max_entries: u32,
) -> Result<(), ListObjectsError> {
    let req = ListObjectsRequest::new(start_after, max_entries);
    let encoded = req
        .encode()
        .map_err(|e| ListObjectsError::Encode(e.to_string()))?;
    transport.send_message(session_id, &encoded)?;
    Ok(())
}

/// Receive a ListObjectsRequest from a transport session.
pub fn recv_list_objects_request(
    transport: &mut crate::transport::Transport,
    session_id: crate::types::SessionId,
) -> Result<ListObjectsRequest, ListObjectsError> {
    let raw = transport.recv_message(session_id)?;
    ListObjectsRequest::decode(&raw).map_err(|e| ListObjectsError::Decode(e.to_string()))
}

/// Send a ListObjectsResponse over a transport session.
pub fn send_list_objects_response(
    transport: &mut crate::transport::Transport,
    session_id: crate::types::SessionId,
    response: &ListObjectsResponse,
) -> Result<(), ListObjectsError> {
    let encoded = response
        .encode()
        .map_err(|e| ListObjectsError::Encode(e.to_string()))?;
    transport.send_message(session_id, &encoded)?;
    Ok(())
}

/// Receive a ListObjectsResponse from a transport session and verify
/// the payload digest.
pub fn recv_list_objects_response(
    transport: &mut crate::transport::Transport,
    session_id: crate::types::SessionId,
) -> Result<ListObjectsResponse, ListObjectsError> {
    let raw = transport.recv_message(session_id)?;
    let response =
        ListObjectsResponse::decode(&raw).map_err(|e| ListObjectsError::Decode(e.to_string()))?;
    response
        .verify_payload()
        .map_err(|_| ListObjectsError::DigestMismatch)?;
    Ok(response)
}

// ---------------------------------------------------------------------------
// ListObjectsHandler -- trait for serving enumeration requests
// ---------------------------------------------------------------------------

/// Trait for handling object enumeration requests within a transport
/// session context.
///
/// Implementors query a local object catalog and return matching entries
/// for the given request range. The trait is object-safe and `Send + Sync`
/// so it can be stored in session dispatch tables.
pub trait ListObjectsHandler {
    /// Return object entries matching the request.
    ///
    /// `start_after` limits results to objects with `object_id` strictly
    /// greater than this value (or all objects if `None`). `max_entries`
    /// limits the number of entries returned; the implementation may
    /// return fewer.
    ///
    /// Returns `(entries, has_more)` where `has_more` indicates whether
    /// additional entries exist beyond this page.
    fn list_objects(
        &self,
        start_after: Option<[u8; 32]>,
        max_entries: u32,
    ) -> (Vec<ObjectListEntry>, bool);
}

/// Serve a single ListObjects request on an established transport session.
///
/// Receives a [`ListObjectsRequest`] from `transport`, queries `handler`,
/// builds a [`ListObjectsResponse`] with BLAKE3 integrity, and sends it
/// back on the same session.
///
/// This is the server-side counterpart to the client-side
/// [`send_list_objects_request`] / [`recv_list_objects_response`] pair.
pub fn serve_list_objects_request(
    transport: &mut crate::transport::Transport,
    session_id: crate::types::SessionId,
    handler: &dyn ListObjectsHandler,
) -> Result<ListObjectsRequest, ListObjectsError> {
    let request = recv_list_objects_request(transport, session_id)?;
    let (entries, has_more) = handler.list_objects(request.start_after, request.max_entries);
    let response =
        ListObjectsResponse::new(entries, has_more, request.start_after, request.max_entries);
    send_list_objects_response(transport, session_id, &response)?;
    Ok(request)
}

// ===========================================================================
// Tests
// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a [u8; 32] key from a u8 for test compactness.
    fn k(v: u8) -> [u8; 32] {
        [v; 32]
    }

    fn k32(v: u32) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[..4].copy_from_slice(&v.to_be_bytes());
        k
    }

    // ── ObjectListEntry ───────────────────────────────────────────────

    #[test]
    fn entry_roundtrip_bincode() {
        let entry = ObjectListEntry::new(k(42), 1024, [0xAA; 32]);
        let encoded = bincode::serialize(&entry).unwrap();
        let decoded: ObjectListEntry = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn entry_fields_preserved() {
        let hash = [0xBB; 32];
        let entry = ObjectListEntry::new(k(7), 65536, hash);
        assert_eq!(entry.object_key, k(7));
        assert_eq!(entry.size, 65536);
        assert_eq!(entry.blake3_root, hash);
    }

    // ── ListObjectsRequest round-trip ─────────────────────────────────

    #[test]
    fn request_roundtrip_with_start_after() {
        let req = ListObjectsRequest::new(Some(k(100)), 50);
        let encoded = req.encode().unwrap();
        let decoded = ListObjectsRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_roundtrip_no_start_after() {
        let req = ListObjectsRequest::new(None, 25);
        let encoded = req.encode().unwrap();
        let decoded = ListObjectsRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_roundtrip_zero_max_entries() {
        let req = ListObjectsRequest::new(Some(k(0)), 0);
        let encoded = req.encode().unwrap();
        let decoded = ListObjectsRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_encode_has_magic_prefix() {
        let req = ListObjectsRequest::new(Some(k(1)), 10);
        let encoded = req.encode().unwrap();
        assert!(ListObjectsRequest::has_magic_prefix(&encoded));
        assert_eq!(&encoded[..4], b"LO01");
    }

    #[test]
    fn request_decode_rejects_wrong_magic() {
        let mut buf = b"BAD!".to_vec();
        buf.extend_from_slice(&bincode::serialize(&ListObjectsRequest::new(None, 1)).unwrap());
        let result = ListObjectsRequest::decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn request_decode_rejects_short_buffer() {
        let result = ListObjectsRequest::decode(b"LO");
        assert!(result.is_err());
    }

    #[test]
    fn request_encode_produces_non_empty_bytes() {
        let req = ListObjectsRequest::new(Some(k(42)), 100);
        let encoded = req.encode().unwrap();
        assert!(!encoded.is_empty());
        assert!(encoded.len() >= 4);
    }

    // ── ListObjectsResponse round-trip ────────────────────────────────

    #[test]
    fn response_roundtrip_single_entry() {
        let entries = vec![ObjectListEntry::new(k(1), 256, [0xCC; 32])];
        let resp = ListObjectsResponse::new(entries.clone(), false, Some(k(0)), 10);
        let encoded = resp.encode().unwrap();
        let decoded = ListObjectsResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.entries, entries);
        assert!(!decoded.has_more);
        assert_eq!(decoded.start_after, Some(k(0)));
        assert_eq!(decoded.max_entries, 10);
        assert_eq!(decoded.payload_digest, resp.payload_digest);
    }

    #[test]
    fn response_roundtrip_empty_entries() {
        let resp = ListObjectsResponse::new(vec![], false, None, 0);
        let encoded = resp.encode().unwrap();
        let decoded = ListObjectsResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.entries, vec![]);
        assert_eq!(decoded.entry_count(), 0);
    }

    #[test]
    fn response_roundtrip_multi_entry() {
        let entries = vec![
            ObjectListEntry::new(k(1), 100, [0x11; 32]),
            ObjectListEntry::new(k(2), 200, [0x22; 32]),
            ObjectListEntry::new(k(3), 300, [0x33; 32]),
        ];
        let resp = ListObjectsResponse::new(entries.clone(), true, Some(k(0)), 20);
        let encoded = resp.encode().unwrap();
        let decoded = ListObjectsResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.entries, entries);
        assert_eq!(decoded.entry_count(), 3);
        assert!(decoded.has_more);
    }

    #[test]
    fn response_roundtrip_large_entry_count() {
        let entries: Vec<_> = (0..1000u32)
            .map(|i| ObjectListEntry::new(k32(i), 4096, [0xAA; 32]))
            .collect();
        let resp = ListObjectsResponse::new(entries.clone(), false, None, 1000);
        let encoded = resp.encode().unwrap();
        let decoded = ListObjectsResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.entries.len(), 1000);
        assert_eq!(decoded.entry_count(), 1000);
    }

    #[test]
    fn response_encode_has_magic_prefix() {
        let resp = ListObjectsResponse::new(
            vec![ObjectListEntry::new(k(1), 10, [0; 32])],
            false,
            None,
            1,
        );
        let encoded = resp.encode().unwrap();
        assert!(ListObjectsResponse::has_magic_prefix(&encoded));
        assert_eq!(&encoded[..4], b"LO02");
    }

    #[test]
    fn response_decode_rejects_wrong_magic() {
        let resp = ListObjectsResponse::new(vec![], false, None, 1);
        let inner = bincode::serialize(&resp).unwrap();
        let mut buf = b"BAD!".to_vec();
        buf.extend_from_slice(&inner);
        let result = ListObjectsResponse::decode(&buf);
        assert!(result.is_err());
    }

    // ── Digest determinism and verification ───────────────────────────

    #[test]
    fn digest_is_deterministic() {
        let entries = vec![ObjectListEntry::new(k(1), 256, [0xCC; 32])];
        let r1 = ListObjectsResponse::new(entries.clone(), false, Some(k(0)), 10);
        let r2 = ListObjectsResponse::new(entries, false, Some(k(0)), 10);
        assert_eq!(r1.payload_digest, r2.payload_digest);
    }

    #[test]
    fn digest_differs_by_entries() {
        let e1 = vec![ObjectListEntry::new(k(1), 100, [0; 32])];
        let e2 = vec![ObjectListEntry::new(k(2), 200, [0; 32])];
        let r1 = ListObjectsResponse::new(e1, false, None, 1);
        let r2 = ListObjectsResponse::new(e2, false, None, 1);
        assert_ne!(r1.payload_digest, r2.payload_digest);
    }

    #[test]
    fn digest_differs_by_has_more() {
        let entries = vec![ObjectListEntry::new(k(1), 100, [0; 32])];
        let r1 = ListObjectsResponse::new(entries.clone(), false, None, 1);
        let r2 = ListObjectsResponse::new(entries, true, None, 1);
        assert_ne!(r1.payload_digest, r2.payload_digest);
    }

    #[test]
    fn digest_differs_by_start_after() {
        let entries = vec![ObjectListEntry::new(k(1), 100, [0; 32])];
        let r1 = ListObjectsResponse::new(entries.clone(), false, Some(k(0)), 1);
        let r2 = ListObjectsResponse::new(entries, false, Some(k(1)), 1);
        assert_ne!(r1.payload_digest, r2.payload_digest);
    }

    #[test]
    fn digest_differs_by_max_entries() {
        let entries = vec![ObjectListEntry::new(k(1), 100, [0; 32])];
        let r1 = ListObjectsResponse::new(entries.clone(), false, None, 5);
        let r2 = ListObjectsResponse::new(entries, false, None, 10);
        assert_ne!(r1.payload_digest, r2.payload_digest);
    }

    #[test]
    fn verify_payload_succeeds_for_valid_response() {
        let entries = vec![ObjectListEntry::new(k(42), 4096, [0xAA; 32])];
        let resp = ListObjectsResponse::new(entries, false, Some(k(0)), 20);
        assert!(resp.verify_payload().is_ok());
    }

    #[test]
    fn verify_payload_succeeds_for_empty_response() {
        let resp = ListObjectsResponse::new(vec![], false, None, 0);
        assert!(resp.verify_payload().is_ok());
    }

    #[test]
    fn verify_payload_fails_for_tampered_entries() {
        let entries = vec![ObjectListEntry::new(k(1), 100, [0; 32])];
        let mut resp = ListObjectsResponse::new(entries, false, None, 1);
        // Tamper with an entry without updating the digest
        resp.entries[0].size = 999;
        let result = resp.verify_payload();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BinarySchemaError::DigestMismatch
        ));
    }

    #[test]
    fn verify_payload_fails_for_tampered_has_more() {
        let entries = vec![ObjectListEntry::new(k(1), 100, [0; 32])];
        let mut resp = ListObjectsResponse::new(entries, false, None, 1);
        resp.has_more = true;
        let result = resp.verify_payload();
        assert!(result.is_err());
    }

    #[test]
    fn verify_payload_fails_for_tampered_digest() {
        let entries = vec![ObjectListEntry::new(k(1), 100, [0; 32])];
        let mut resp = ListObjectsResponse::new(entries, false, None, 1);
        resp.payload_digest[0] ^= 0xFF;
        let result = resp.verify_payload();
        assert!(result.is_err());
    }

    #[test]
    fn verify_payload_succeeds_for_large_multi_entry() {
        let entries: Vec<_> = (0..500u32)
            .map(|i| ObjectListEntry::new(k32(i), i as u64 * 4096, [0xBB; 32]))
            .collect();
        let resp = ListObjectsResponse::new(entries, true, Some(k(0)), 500);
        assert!(resp.verify_payload().is_ok());
    }

    // ── has_more and start_after semantics ────────────────────────────

    #[test]
    fn has_more_false_when_no_more_entries() {
        let resp = ListObjectsResponse::new(
            vec![ObjectListEntry::new(k(1), 100, [0; 32])],
            false,
            None,
            10,
        );
        assert!(!resp.has_more);
    }

    #[test]
    fn has_more_true_when_entries_equal_max() {
        let entries: Vec<_> = (0..10u8)
            .map(|i| ObjectListEntry::new(k(i), 100, [0; 32]))
            .collect();
        let resp = ListObjectsResponse::new(entries, true, Some(k(0)), 10);
        assert!(resp.has_more);
    }

    #[test]
    fn start_after_none_for_initial_request() {
        let resp = ListObjectsResponse::new(
            vec![ObjectListEntry::new(k(1), 100, [0; 32])],
            false,
            None,
            10,
        );
        assert_eq!(resp.start_after, None);
    }

    // ── ObjectListEntry round-trip through response ───────────────────

    #[test]
    fn entry_blake3_root_roundtrip() {
        let root: [u8; 32] = {
            let mut h = [0u8; 32];
            for (i, byte) in h.iter_mut().enumerate() {
                *byte = i as u8;
            }
            h
        };
        let entry = ObjectListEntry::new(k(99), 1_048_576, root);
        let resp = ListObjectsResponse::new(vec![entry.clone()], false, None, 1);
        let encoded = resp.encode().unwrap();
        let decoded = ListObjectsResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.entries[0].blake3_root, root);
        assert_eq!(decoded.entries[0], entry);
    }

    // ── ListObjectsHandler trait ──────────────────────────────────────

    /// A mock handler that returns a static set of objects.
    struct MockHandler {
        entries: Vec<ObjectListEntry>,
    }

    impl ListObjectsHandler for MockHandler {
        fn list_objects(
            &self,
            start_after: Option<[u8; 32]>,
            max_entries: u32,
        ) -> (Vec<ObjectListEntry>, bool) {
            let max = max_entries as usize;
            let filtered: Vec<_> = self
                .entries
                .iter()
                .filter(|e| start_after.is_none_or(|s| e.object_key > s))
                .take(max)
                .cloned()
                .collect();
            let has_more = self
                .entries
                .iter()
                .filter(|e| start_after.is_none_or(|s| e.object_key > s))
                .nth(max)
                .is_some();
            (filtered, has_more)
        }
    }

    #[test]
    fn handler_trait_returns_all_when_no_cursor() {
        let handler = MockHandler {
            entries: vec![
                ObjectListEntry::new(k(1), 100, [0xAA; 32]),
                ObjectListEntry::new(k(2), 200, [0xBB; 32]),
            ],
        };
        let (entries, has_more) = handler.list_objects(None, 10);
        assert_eq!(entries.len(), 2);
        assert!(!has_more);
    }

    #[test]
    fn handler_trait_respects_start_after() {
        let handler = MockHandler {
            entries: vec![
                ObjectListEntry::new(k(1), 100, [0; 32]),
                ObjectListEntry::new(k(2), 200, [0; 32]),
                ObjectListEntry::new(k(3), 300, [0; 32]),
            ],
        };
        let (entries, has_more) = handler.list_objects(Some(k(1)), 10);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].object_key, k(2));
        assert_eq!(entries[1].object_key, k(3));
        assert!(!has_more);
    }

    #[test]
    fn handler_trait_respects_max_entries() {
        let handler = MockHandler {
            entries: (0..10u8)
                .map(|i| ObjectListEntry::new(k(i), 100, [0; 32]))
                .collect(),
        };
        let (entries, has_more) = handler.list_objects(None, 3);
        assert_eq!(entries.len(), 3);
        assert!(has_more);
        assert_eq!(entries[0].object_key, k(0));
        assert_eq!(entries[2].object_key, k(2));
    }

    #[test]
    fn handler_trait_has_more_false_at_exact_boundary() {
        let handler = MockHandler {
            entries: (0..5u8)
                .map(|i| ObjectListEntry::new(k(i), 100, [0; 32]))
                .collect(),
        };
        let (entries, has_more) = handler.list_objects(None, 5);
        assert_eq!(entries.len(), 5);
        assert!(!has_more);
    }

    #[test]
    fn handler_trait_empty_catalog() {
        let handler = MockHandler { entries: vec![] };
        let (entries, has_more) = handler.list_objects(None, 100);
        assert!(entries.is_empty());
        assert!(!has_more);
    }

    #[test]
    fn handler_trait_cursor_past_end() {
        let handler = MockHandler {
            entries: vec![ObjectListEntry::new(k(1), 100, [0; 32])],
        };
        let (entries, has_more) = handler.list_objects(Some(k(10)), 10);
        assert!(entries.is_empty());
        assert!(!has_more);
    }

    #[test]
    fn serve_response_has_correct_bound_digest() {
        let handler = MockHandler {
            entries: vec![
                ObjectListEntry::new(k(1), 100, [0xAA; 32]),
                ObjectListEntry::new(k(2), 200, [0xBB; 32]),
            ],
        };
        let (entries, has_more) = handler.list_objects(None, 10);
        let response = ListObjectsResponse::new(entries, has_more, None, 10);
        assert!(response.verify_payload().is_ok());
        assert_eq!(response.entry_count(), 2);
        assert!(!response.has_more);
    }
}
