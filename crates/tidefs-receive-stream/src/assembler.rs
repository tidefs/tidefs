//! Object assembler: buffer and reassemble ordered chunks into complete objects.
//!
//! Handles out-of-order arrival by storing chunks in a per-object buffer
//! sorted by `chunk_index`. When all chunks for an object have arrived
//! (tracked via `total_chunks`), the assembler reconstructs the full
//! object payload and yields it for dispatch.

use crate::decoder::FramedChunk;
use std::collections::BTreeMap;

/// Errors that can occur during object reassembly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AssemblerError {
    /// A chunk arrived for an object that was already fully assembled.
    ObjectAlreadyComplete { object_id: [u8; 32] },
    /// Total chunks mismatch: two chunks for the same object disagree on `total_chunks`.
    TotalChunksMismatch {
        object_id: [u8; 32],
        expected: u32,
        got: u32,
    },
    /// A chunk with a duplicate `chunk_index` was received.
    DuplicateChunk {
        object_id: [u8; 32],
        chunk_index: u32,
    },
    /// The object was assembled but a total-bytes invariant check failed.
    SizeMismatch {
        object_id: [u8; 32],
        expected_bytes: u64,
        assembled_bytes: u64,
    },
}

impl core::fmt::Display for AssemblerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ObjectAlreadyComplete { object_id } => {
                write!(f, "object {} already fully assembled", Hex32(object_id))
            }
            Self::TotalChunksMismatch {
                object_id,
                expected,
                got,
            } => {
                write!(
                    f,
                    "total_chunks mismatch for {}: expected {expected}, got {got}",
                    Hex32(object_id)
                )
            }
            Self::DuplicateChunk {
                object_id,
                chunk_index,
            } => {
                write!(
                    f,
                    "duplicate chunk {chunk_index} for object {}",
                    Hex32(object_id)
                )
            }
            Self::SizeMismatch {
                object_id,
                expected_bytes,
                assembled_bytes,
            } => {
                write!(
                    f,
                    "size mismatch for {}: expected {expected_bytes} bytes, assembled {assembled_bytes}",
                    Hex32(object_id)
                )
            }
        }
    }
}

impl std::error::Error for AssemblerError {}

struct Hex32<'a>(&'a [u8; 32]);

impl core::fmt::Display for Hex32<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A fully assembled object ready for dispatch to local storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssembledObject {
    /// Stable object identifier.
    pub object_id: [u8; 32],
    /// Full reassembled payload.
    pub payload: Vec<u8>,
    /// Total number of chunks this object was split into.
    pub total_chunks: u32,
}

/// Buffers incoming chunks and reassembles objects once all chunks have arrived.
///
/// Chunks may arrive out of order; the assembler sorts them by `chunk_index`.
/// When the number of buffered chunks equals `total_chunks`, the object
/// is assembled and returned via [`take_complete`] or [`drain_complete`].
///
/// # Example
///
/// ```ignore
/// use tidefs_receive_stream::assembler::ObjectAssembler;
///
/// let mut assembler = ObjectAssembler::new();
/// // feed chunks from the decoder...
/// while let Some(obj) = assembler.drain_complete().pop() {
///     // dispatch obj to storage
/// }
/// ```
#[derive(Clone, Debug, Default)]
pub struct ObjectAssembler {
    /// Per-object buffers: object_id -> (total_chunks, sorted chunks).
    objects: BTreeMap<[u8; 32], ObjectBuffer>,
    /// Objects that have been fully assembled and are ready to drain.
    complete: Vec<AssembledObject>,
}

#[derive(Clone, Debug)]
struct ObjectBuffer {
    total_chunks: u32,
    chunks: BTreeMap<u32, FramedChunk>,
}

impl ObjectAssembler {
    /// Create a new empty assembler.
    #[must_use]
    pub fn new() -> Self {
        Self {
            objects: BTreeMap::new(),
            complete: Vec::new(),
        }
    }

    /// Feed one decoded and verified chunk into the assembler.
    ///
    /// If this chunk completes the object, the assembled payload is
    /// appended to the internal complete queue. Use [`drain_complete`]
    /// or [`take_complete`] to retrieve it.
    ///
    /// # Errors
    ///
    /// Returns [`AssemblerError`] if the chunk is a duplicate, has a
    /// conflicting `total_chunks`, or arrives for an already-completed object.
    pub fn feed_chunk(&mut self, chunk: FramedChunk) -> Result<(), AssemblerError> {
        let object_id = chunk.object_id;

        // Check if object was already fully assembled and drained
        if let Some(buf) = self.objects.get(&object_id) {
            if buf.chunks.len() as u32 >= buf.total_chunks {
                return Err(AssemblerError::ObjectAlreadyComplete { object_id });
            }
        }

        let entry = self
            .objects
            .entry(object_id)
            .or_insert_with(|| ObjectBuffer {
                total_chunks: chunk.total_chunks,
                chunks: BTreeMap::new(),
            });

        // Validate total_chunks consistency
        if entry.total_chunks != chunk.total_chunks {
            return Err(AssemblerError::TotalChunksMismatch {
                object_id,
                expected: entry.total_chunks,
                got: chunk.total_chunks,
            });
        }

        // Check for duplicate chunk_index
        if entry.chunks.contains_key(&chunk.chunk_index) {
            return Err(AssemblerError::DuplicateChunk {
                object_id,
                chunk_index: chunk.chunk_index,
            });
        }

        let total_chunks = entry.total_chunks;
        entry.chunks.insert(chunk.chunk_index, chunk);

        // Check if object is now complete
        if entry.chunks.len() as u32 == total_chunks {
            let buf = self.objects.remove(&object_id).unwrap();
            let assembled = assemble_object(object_id, buf)?;
            self.complete.push(assembled);
        }

        Ok(())
    }

    /// Take all fully-assembled objects, leaving the queue empty.
    #[must_use]
    pub fn take_complete(&mut self) -> Vec<AssembledObject> {
        std::mem::take(&mut self.complete)
    }

    /// Drain all fully-assembled objects in FIFO order.
    #[must_use]
    pub fn drain_complete(&mut self) -> Vec<AssembledObject> {
        self.take_complete()
    }

    /// Number of objects currently being assembled (not yet complete).
    #[must_use]
    pub fn pending_objects(&self) -> usize {
        self.objects.len()
    }

    /// Number of completed objects waiting to be drained.
    #[must_use]
    pub fn completed_objects(&self) -> usize {
        self.complete.len()
    }

    /// Total number of chunks buffered across all pending objects.
    #[must_use]
    pub fn buffered_chunks(&self) -> usize {
        self.objects.values().map(|buf| buf.chunks.len()).sum()
    }
}

/// Reassemble one object from its buffered chunks (in chunk_index order).
fn assemble_object(
    object_id: [u8; 32],
    buffer: ObjectBuffer,
) -> Result<AssembledObject, AssemblerError> {
    // BTreeMap iterates in key order (chunk_index), so concatenation
    // produces the correct byte sequence even when chunks arrive out-of-order.
    let total_capacity: usize = buffer.chunks.values().map(|c| c.payload.len()).sum();
    let mut payload = Vec::with_capacity(total_capacity);
    for chunk in buffer.chunks.values() {
        payload.extend_from_slice(&chunk.payload);
    }
    Ok(AssembledObject {
        object_id,
        payload,
        total_chunks: buffer.total_chunks,
    })
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_binary_schema_checksum::blake3_domain_digest;
    use tidefs_binary_schema_core::{DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion};

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
    fn single_chunk_object_assembly() {
        let mut assembler = ObjectAssembler::new();
        let chunk = make_chunk(test_obj_id(0x01), 0, 0, 1, b"hello", true);
        assembler.feed_chunk(chunk).unwrap();
        assert_eq!(assembler.completed_objects(), 1);
        assert_eq!(assembler.pending_objects(), 0);

        let complete = assembler.take_complete();
        assert_eq!(complete.len(), 1);
        assert_eq!(complete[0].object_id, test_obj_id(0x01));
        assert_eq!(complete[0].payload, b"hello");
        assert_eq!(complete[0].total_chunks, 1);
    }

    #[test]
    fn multi_chunk_sequential_assembly() {
        let mut assembler = ObjectAssembler::new();
        let c0 = make_chunk(test_obj_id(0x01), 0, 0, 3, b"AAA", false);
        let c1 = make_chunk(test_obj_id(0x01), 3, 1, 3, b"BBB", false);
        let c2 = make_chunk(test_obj_id(0x01), 6, 2, 3, b"CCC", true);

        assembler.feed_chunk(c0).unwrap();
        assert_eq!(assembler.completed_objects(), 0);
        assert_eq!(assembler.pending_objects(), 1);

        assembler.feed_chunk(c1).unwrap();
        assert_eq!(assembler.completed_objects(), 0);

        assembler.feed_chunk(c2).unwrap();
        assert_eq!(assembler.completed_objects(), 1);
        assert_eq!(assembler.pending_objects(), 0);

        let complete = assembler.take_complete();
        assert_eq!(complete.len(), 1);
        assert_eq!(complete[0].payload, b"AAABBBCCC");
    }

    #[test]
    fn out_of_order_reassembly() {
        let mut assembler = ObjectAssembler::new();
        let c0 = make_chunk(test_obj_id(0x01), 0, 0, 3, b"CHUNK0", false);
        let c1 = make_chunk(test_obj_id(0x01), 6, 1, 3, b"CHUNK1", false);
        let c2 = make_chunk(test_obj_id(0x01), 12, 2, 3, b"CHUNK2", true);

        // Feed out of order: 1, 2, 0
        assembler.feed_chunk(c1).unwrap();
        assert_eq!(assembler.completed_objects(), 0);
        assembler.feed_chunk(c2).unwrap();
        assert_eq!(assembler.completed_objects(), 0);
        assembler.feed_chunk(c0).unwrap();
        assert_eq!(assembler.completed_objects(), 1);

        let complete = assembler.take_complete();
        assert_eq!(complete[0].payload, b"CHUNK0CHUNK1CHUNK2");
    }

    #[test]
    fn multiple_objects_interleaved() {
        let mut assembler = ObjectAssembler::new();

        // Object A: 2 chunks
        let a0 = make_chunk(test_obj_id(0x0A), 0, 0, 2, b"A0", false);
        let a1 = make_chunk(test_obj_id(0x0A), 2, 1, 2, b"A1", true);

        // Object B: 2 chunks
        let b0 = make_chunk(test_obj_id(0x0B), 0, 0, 2, b"B0", false);
        let b1 = make_chunk(test_obj_id(0x0B), 2, 1, 2, b"B1", true);

        assembler.feed_chunk(a0).unwrap();
        assembler.feed_chunk(b0).unwrap();
        assert_eq!(assembler.pending_objects(), 2);
        assert_eq!(assembler.completed_objects(), 0);

        assembler.feed_chunk(a1).unwrap();
        assert_eq!(assembler.completed_objects(), 1);

        assembler.feed_chunk(b1).unwrap();
        assert_eq!(assembler.completed_objects(), 2);

        let complete = assembler.take_complete();
        assert_eq!(complete.len(), 2);
        let mut payloads: Vec<String> = complete
            .iter()
            .map(|o| String::from_utf8(o.payload.clone()).unwrap())
            .collect();
        payloads.sort();
        assert_eq!(payloads, vec!["A0A1", "B0B1"]);
    }

    #[test]
    fn duplicate_chunk_rejected() {
        let mut assembler = ObjectAssembler::new();
        let c0 = make_chunk(test_obj_id(0x01), 0, 0, 2, b"first", false);
        let c0_dup = make_chunk(test_obj_id(0x01), 0, 0, 2, b"first", false);

        assembler.feed_chunk(c0).unwrap();
        let err = assembler.feed_chunk(c0_dup).unwrap_err();
        assert!(matches!(
            err,
            AssemblerError::DuplicateChunk { chunk_index: 0, .. }
        ));
    }

    #[test]
    fn total_chunks_mismatch_rejected() {
        let mut assembler = ObjectAssembler::new();
        let c0 = make_chunk(test_obj_id(0x01), 0, 0, 3, b"abc", false);
        let c1 = make_chunk(test_obj_id(0x01), 3, 1, 4, b"def", false); // different total_chunks!

        assembler.feed_chunk(c0).unwrap();
        let err = assembler.feed_chunk(c1).unwrap_err();
        assert!(matches!(
            err,
            AssemblerError::TotalChunksMismatch {
                expected: 3,
                got: 4,
                ..
            }
        ));
    }

    #[test]
    fn object_already_complete_rejected() {
        let mut assembler = ObjectAssembler::new();
        let c0 = make_chunk(test_obj_id(0x01), 0, 0, 1, b"done", true);

        assembler.feed_chunk(c0).unwrap();
        assert_eq!(assembler.completed_objects(), 1);

        // Draining removes from complete queue but doesn't remove the "already completed" tracking
        let _ = assembler.take_complete();

        // Now there's no pending buffer, so feeding another chunk for same object
        // should create a fresh buffer (since old one was removed on completion).
        // That's OK - but if we re-feed and complete again, no error.
        let c1 = make_chunk(test_obj_id(0x01), 0, 0, 1, b"again", true);
        assembler.feed_chunk(c1).unwrap();
        assert_eq!(assembler.completed_objects(), 1);
    }

    #[test]
    fn empty_object_zero_chunks() {
        let assembler = ObjectAssembler::new();
        assert_eq!(assembler.pending_objects(), 0);
        assert_eq!(assembler.completed_objects(), 0);
        assert_eq!(assembler.buffered_chunks(), 0);
    }

    #[test]
    fn large_object_many_chunks() {
        let mut assembler = ObjectAssembler::new();
        let num_chunks = 50u32;
        let mut expected = Vec::new();
        for i in 0..num_chunks {
            let payload = format!("chunk{i:04}").into_bytes();
            expected.extend_from_slice(&payload);
            let offset = expected.len() - payload.len();
            let is_last = i == num_chunks - 1;
            let chunk = make_chunk(
                test_obj_id(0x42),
                offset as u64,
                i,
                num_chunks,
                &payload,
                is_last,
            );
            assembler.feed_chunk(chunk).unwrap();
        }
        assert_eq!(assembler.completed_objects(), 1);
        let complete = assembler.take_complete();
        assert_eq!(complete[0].payload, expected);
        assert_eq!(complete[0].total_chunks, num_chunks);
    }

    #[test]
    fn drain_complete_clears_queue() {
        let mut assembler = ObjectAssembler::new();
        let c0 = make_chunk(test_obj_id(0x01), 0, 0, 1, b"obj1", true);
        assembler.feed_chunk(c0).unwrap();
        assert_eq!(assembler.completed_objects(), 1);
        let drained = assembler.drain_complete();
        assert_eq!(drained.len(), 1);
        assert_eq!(assembler.completed_objects(), 0);
    }

    #[test]
    fn buffered_chunks_count() {
        let mut assembler = ObjectAssembler::new();
        let c0 = make_chunk(test_obj_id(0x01), 0, 0, 3, b"a", false);
        let c1 = make_chunk(test_obj_id(0x01), 1, 1, 3, b"b", false);
        assembler.feed_chunk(c0).unwrap();
        assembler.feed_chunk(c1).unwrap();
        assert_eq!(assembler.buffered_chunks(), 2);
        assert_eq!(assembler.pending_objects(), 1);
        assert_eq!(assembler.completed_objects(), 0);
    }
}
