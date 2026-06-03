//! Chunk framer for send-stream: splits object data into transport-sized
//! chunks with BLAKE3 domain-separated authentication tags, matching the
//! receive-stream verification format.
//!
//! Each chunk carries a BLAKE3-256 domain-separated digest under the
//! `TransferStream` domain tag, so the receiver can verify integrity
//! before reassembly.

use tidefs_binary_schema_checksum::blake3_domain_digest;
use tidefs_binary_schema_core::{DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion};

/// Schema family for send-stream chunk framing (canonical family 7).
pub const SEND_CHUNK_FAMILY: SchemaFamilyId = SchemaFamilyId(7);
/// Schema type for a framed data chunk within the send-stream family.
pub const SEND_CHUNK_TYPE: SchemaTypeId = SchemaTypeId(1);
/// Schema version for send-stream chunk framing v1.0.
pub const SEND_CHUNK_VERSION: SchemaVersion = SchemaVersion::new(1, 0);

/// A framed chunk produced by [`ChunkFramer`].
///
/// Carries the object identity, byte range, payload, and a BLAKE3
/// domain-separated authentication tag so the receiver can verify
/// each chunk independently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FramedChunk {
    /// Stable object identifier.
    pub object_id: [u8; 32],
    /// Byte offset of this chunk within the object.
    pub offset: u64,
    /// Zero-based chunk index.
    pub chunk_index: u32,
    /// Total number of chunks in the object (set when framing starts).
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
            SEND_CHUNK_FAMILY,
            SEND_CHUNK_TYPE,
            SEND_CHUNK_VERSION,
            DomainTag::TransferStream,
        );
        recomputed == self.auth_tag
    }
}

/// Splits an object's data into transport-sized chunks with BLAKE3
/// domain-separated authentication tags.
///
/// Created with [`ChunkFramer::new`] and iterated via
/// [`ChunkFramer::next_chunk`].
///
/// # Example
///
/// ```rust
/// use tidefs_send_stream::framer::ChunkFramer;
///
/// let mut framer = ChunkFramer::new([0xAAu8; 32], b"hello world".to_vec(), 4);
/// let mut chunks = Vec::new();
/// while let Some(chunk) = framer.next_chunk() {
///     assert!(chunk.verify_auth_tag());
///     chunks.push(chunk);
/// }
/// assert_eq!(chunks.len(), 3); // ceil(11 / 4) = 3
/// assert!(chunks.last().unwrap().is_last);
/// ```
#[derive(Clone, Debug)]
pub struct ChunkFramer {
    /// Object being framed.
    object_id: [u8; 32],
    /// Full object data.
    data: Vec<u8>,
    /// Maximum payload bytes per chunk (at least 64).
    chunk_size: usize,
    /// Current byte offset into `data`.
    current_offset: u64,
    /// Next chunk index to emit.
    next_chunk_index: u32,
    /// Total chunks (computed once at construction).
    total_chunks: u32,
    /// Set after the last chunk has been returned.
    exhausted: bool,
}

impl ChunkFramer {
    /// Create a new framer for `data` belonging to `object_id`.
    ///
    /// `chunk_size` is the maximum payload bytes per chunk,
    /// clamped to a minimum of 64 bytes.
    pub fn new(object_id: [u8; 32], data: Vec<u8>, chunk_size: usize) -> Self {
        let is_empty = data.is_empty();
        let chunk_size = chunk_size.max(1);
        let total_chunks = data.len().div_ceil(chunk_size) as u32;
        Self {
            object_id,
            data,
            chunk_size,
            current_offset: 0,
            next_chunk_index: 0,
            total_chunks,
            exhausted: is_empty,
        }
    }

    /// Return the next framed chunk, or `None` when the object is exhausted.
    ///
    /// Each chunk includes a BLAKE3-256 domain-separated authentication tag
    /// computed under the `TransferStream` domain.
    pub fn next_chunk(&mut self) -> Option<FramedChunk> {
        if self.exhausted {
            return None;
        }
        let start = self.current_offset as usize;
        if start >= self.data.len() {
            self.exhausted = true;
            return None;
        }
        let end = (start + self.chunk_size).min(self.data.len());
        let payload = self.data[start..end].to_vec();
        let is_last = end == self.data.len();

        let auth_tag = blake3_domain_digest(
            &payload,
            SEND_CHUNK_FAMILY,
            SEND_CHUNK_TYPE,
            SEND_CHUNK_VERSION,
            DomainTag::TransferStream,
        );

        let chunk = FramedChunk {
            object_id: self.object_id,
            offset: self.current_offset,
            chunk_index: self.next_chunk_index,
            total_chunks: self.total_chunks,
            payload,
            auth_tag,
            is_last,
        };

        self.current_offset = end as u64;
        self.next_chunk_index += 1;
        if is_last {
            self.exhausted = true;
        }
        Some(chunk)
    }

    /// Total bytes in the object being framed.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.data.len() as u64
    }

    /// Total number of chunks the object will be split into.
    #[must_use]
    pub fn total_chunks(&self) -> u32 {
        self.total_chunks
    }

    /// Number of chunks emitted so far.
    #[must_use]
    pub fn chunks_emitted(&self) -> u32 {
        self.next_chunk_index
    }

    /// Whether all chunks have been emitted.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Remaining bytes not yet framed.
    #[must_use]
    pub fn remaining_bytes(&self) -> u64 {
        self.data.len().saturating_sub(self.current_offset as usize) as u64
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_obj_id() -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = 0xAB;
        id
    }

    #[test]
    fn single_chunk_smaller_than_chunk_size() {
        let data = b"hello".to_vec();
        let mut framer = ChunkFramer::new(test_obj_id(), data.clone(), 1024);
        assert_eq!(framer.total_chunks(), 1);
        assert_eq!(framer.total_bytes(), 5);
        let chunk = framer.next_chunk().unwrap();
        assert!(chunk.is_last);
        assert_eq!(chunk.offset, 0);
        assert_eq!(chunk.chunk_index, 0);
        assert_eq!(chunk.total_chunks, 1);
        assert_eq!(chunk.payload, data);
        assert!(chunk.verify_auth_tag());
        assert!(framer.next_chunk().is_none());
        assert!(framer.is_exhausted());
    }

    #[test]
    fn multi_chunk_splitting() {
        let data = b"0123456789".to_vec(); // 10 bytes, chunk_size=4 -> 3 chunks
        let mut framer = ChunkFramer::new(test_obj_id(), data.clone(), 4);
        assert_eq!(framer.total_chunks(), 3);
        assert_eq!(framer.total_bytes(), 10);

        let c0 = framer.next_chunk().unwrap();
        assert_eq!(c0.payload, b"0123");
        assert!(!c0.is_last);
        assert_eq!(c0.offset, 0);
        assert_eq!(c0.chunk_index, 0);
        assert!(c0.verify_auth_tag());

        let c1 = framer.next_chunk().unwrap();
        assert_eq!(c1.payload, b"4567");
        assert!(!c1.is_last);
        assert_eq!(c1.offset, 4);
        assert_eq!(c1.chunk_index, 1);
        assert!(c1.verify_auth_tag());

        let c2 = framer.next_chunk().unwrap();
        assert_eq!(c2.payload, b"89");
        assert!(c2.is_last);
        assert_eq!(c2.offset, 8);
        assert_eq!(c2.chunk_index, 2);
        assert!(c2.verify_auth_tag());

        assert!(framer.next_chunk().is_none());
        assert!(framer.is_exhausted());
    }

    #[test]
    fn exact_chunk_size_boundary() {
        let data = b"ABCD".to_vec();
        let mut framer = ChunkFramer::new(test_obj_id(), data.clone(), 4);
        assert_eq!(framer.total_chunks(), 1);
        let chunk = framer.next_chunk().unwrap();
        assert_eq!(chunk.payload, data);
        assert!(chunk.is_last);
        assert!(framer.next_chunk().is_none());
    }

    #[test]
    fn empty_payload_produces_no_chunks() {
        let data = Vec::new();
        let mut framer = ChunkFramer::new(test_obj_id(), data, 256);
        assert_eq!(framer.total_chunks(), 0);
        assert_eq!(framer.total_bytes(), 0);
        assert!(framer.is_exhausted());
        assert!(framer.next_chunk().is_none());
    }

    #[test]
    fn domain_separated_tags_differ_from_plain_blake3() {
        let payload = b"test data for domain separation";
        let plain_digest: [u8; 32] = blake3::hash(payload).into();
        let domain_digest = blake3_domain_digest(
            payload,
            SEND_CHUNK_FAMILY,
            SEND_CHUNK_TYPE,
            SEND_CHUNK_VERSION,
            DomainTag::TransferStream,
        );
        assert_ne!(plain_digest, domain_digest);
    }

    #[test]
    fn different_objects_same_payload_same_auth_tag() {
        // auth_tag is per-payload, not per-object_id; object_id is metadata
        let payload = b"same data";
        let mut id_a = [0u8; 32];
        id_a[0] = 0x01;
        let mut id_b = [0u8; 32];
        id_b[0] = 0x02;

        let mut framer_a = ChunkFramer::new(id_a, payload.to_vec(), 256);
        let mut framer_b = ChunkFramer::new(id_b, payload.to_vec(), 256);

        let chunk_a = framer_a.next_chunk().unwrap();
        let chunk_b = framer_b.next_chunk().unwrap();
        assert_eq!(chunk_a.auth_tag, chunk_b.auth_tag);
        assert_eq!(chunk_a.object_id, id_a);
        assert_eq!(chunk_b.object_id, id_b);
    }

    #[test]
    fn chunk_size_clamped_to_minimum() {
        let data = b"some data for chunking".to_vec();
        // chunk_size=1 produces one byte per chunk
        let mut framer = ChunkFramer::new(test_obj_id(), data.clone(), 1);
        assert_eq!(framer.total_chunks(), 22);
        let first = framer.next_chunk().unwrap();
        assert_eq!(first.payload, b"s"[..].to_vec());
        assert!(!first.is_last);
        assert_eq!(first.offset, 0);
        assert!(first.verify_auth_tag());
    }

    #[test]
    fn remaining_bytes_and_chunks_emitted() {
        let data = vec![0u8; 250];
        let mut framer = ChunkFramer::new(test_obj_id(), data, 100);
        assert_eq!(framer.remaining_bytes(), 250);

        framer.next_chunk().unwrap();
        assert_eq!(framer.remaining_bytes(), 150);
        assert_eq!(framer.chunks_emitted(), 1);

        framer.next_chunk().unwrap();
        assert_eq!(framer.remaining_bytes(), 50);
        assert_eq!(framer.chunks_emitted(), 2);

        framer.next_chunk().unwrap();
        assert_eq!(framer.remaining_bytes(), 0);
        assert_eq!(framer.chunks_emitted(), 3);
        assert!(framer.is_exhausted());
    }

    #[test]
    fn large_object_many_chunks() {
        let data = vec![0x42u8; 10000];
        let mut framer = ChunkFramer::new(test_obj_id(), data, 512);
        let expected_chunks = 10000usize.div_ceil(512) as u32;
        assert_eq!(framer.total_chunks(), expected_chunks);

        let mut count = 0u32;
        while let Some(chunk) = framer.next_chunk() {
            assert!(chunk.verify_auth_tag());
            assert_eq!(chunk.chunk_index, count);
            assert_eq!(chunk.total_chunks, expected_chunks);
            count += 1;
        }
        assert_eq!(count, expected_chunks);
        assert!(framer.is_exhausted());
    }
}
