// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Receive dispatch trait for consuming reassembled objects into local storage.
//!
//! Provides a trait-based abstraction so the receive-stream crate can
//! dispatch [`AssembledObject`]s to different storage backends without
//! coupling to a concrete storage implementation.

use crate::assembler::AssembledObject;
use crate::assembler::{AssemblerError, ObjectAssembler};
use crate::decoder::{ChunkDecodeError, ChunkDecoder};

/// Trait for dispatching reassembled objects to a storage backend.
///
/// Implementations handle the concrete storage protocol. A no-op
/// implementation ([`NoOpDispatch`]) is provided for testing.
pub trait ReceiveDispatch {
    /// The error type for dispatch operations.
    type Error: std::fmt::Debug;

    /// Store one fully reassembled object.
    ///
    /// The implementation is responsible for writing the object data
    /// to local storage and updating any metadata indexes.
    fn store_object(&mut self, object: AssembledObject) -> Result<(), Self::Error>;

    /// Flush any buffered objects to stable storage.
    ///
    /// Default implementation is a no-op.
    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// A no-op dispatch for testing the receive pipeline without a real storage backend.
///
/// Stores all received objects in a `Vec` for later inspection.
#[derive(Debug, Default)]
pub struct NoOpDispatch {
    /// Objects received so far.
    pub objects_received: Vec<AssembledObject>,
    /// Total payload bytes received.
    pub total_bytes_received: u64,
    /// Total chunks processed.
    pub total_chunks_processed: u64,
}

impl NoOpDispatch {
    /// Create a new no-op dispatch buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            objects_received: Vec::new(),
            total_bytes_received: 0,
            total_chunks_processed: 0,
        }
    }
}

impl ReceiveDispatch for NoOpDispatch {
    type Error = std::convert::Infallible;

    fn store_object(&mut self, object: AssembledObject) -> Result<(), Self::Error> {
        self.total_bytes_received += object.payload.len() as u64;
        self.total_chunks_processed += object.total_chunks as u64;
        self.objects_received.push(object);
        Ok(())
    }
}

/// Errors from the top-level [`receive_object`] pipeline.
#[derive(Debug)]
pub enum ReceiveError<D: std::fmt::Debug> {
    /// Chunk decoding or verification failed.
    Decode(ChunkDecodeError),
    /// Object reassembly failed.
    Assemble(AssemblerError),
    /// Storage dispatch failed.
    Dispatch(D),
}

impl<D: std::fmt::Debug> std::fmt::Display for ReceiveError<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "decode error: {e}"),
            Self::Assemble(e) => write!(f, "assembly error: {e}"),
            Self::Dispatch(e) => write!(f, "dispatch error: {e:?}"),
        }
    }
}

impl<D: std::fmt::Debug + 'static> std::error::Error for ReceiveError<D> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(e) => Some(e),
            Self::Assemble(e) => Some(e),
            Self::Dispatch(_) => None,
        }
    }
}

/// Receive a complete multi-chunk object from wire-format bytes and
/// dispatch it to local storage.
///
/// This is the top-level entry point for the receive pipeline. It:
/// 1. Decodes all chunk frames from `wire_bytes` using [`ChunkDecoder`]
/// 2. Feeds each verified chunk into an [`ObjectAssembler`]
/// 3. Dispatches each completed object to `dispatch`
///
/// The `max_chunk_payload` parameter limits the maximum payload bytes
/// per chunk (0 = unlimited).
///
/// # Returns
///
/// On success, returns (objects_count, total_bytes) where objects_count
/// is the number of fully assembled objects dispatched and total_bytes
/// is the sum of all payload bytes across all received objects.
pub fn receive_object<D: ReceiveDispatch>(
    wire_bytes: &[u8],
    max_chunk_payload: u32,
    dispatch: &mut D,
) -> Result<(u64, u64), ReceiveError<D::Error>> {
    let decoder = if max_chunk_payload > 0 {
        ChunkDecoder::with_max_payload(max_chunk_payload)
    } else {
        ChunkDecoder::new()
    };
    let mut assembler = ObjectAssembler::new();
    let mut bytes = wire_bytes;
    let mut objects_count = 0u64;
    let mut total_bytes = 0u64;
    let mut chunks_decoded = 0u64;

    while !bytes.is_empty() {
        let (chunk, rest) = decoder.decode_chunk(bytes).map_err(ReceiveError::Decode)?;
        assembler
            .feed_chunk(chunk)
            .map_err(ReceiveError::Assemble)?;
        bytes = rest;
        chunks_decoded += 1;

        // Dispatch complete objects as they become ready
        for obj in assembler.drain_complete() {
            let obj_bytes = obj.payload.len() as u64;
            total_bytes += obj_bytes;
            objects_count += 1;
            dispatch.store_object(obj).map_err(ReceiveError::Dispatch)?;
        }
    }

    dispatch.flush().map_err(ReceiveError::Dispatch)?;

    let _ = chunks_decoded;

    Ok((objects_count, total_bytes))
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::{encode_chunk_to_wire, FramedChunk};
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
    fn noop_dispatch_stores_single_object() {
        let mut dispatch = NoOpDispatch::new();
        let chunk = make_chunk(test_obj_id(0x10), 0, 0, 1, b"hello dispatch", true);
        let wire = encode_chunk_to_wire(&chunk);

        receive_object(&wire, 0, &mut dispatch).unwrap();
        assert_eq!(dispatch.objects_received.len(), 1);
        assert_eq!(dispatch.objects_received[0].payload, b"hello dispatch");
        assert_eq!(dispatch.total_bytes_received, 14);
    }

    #[test]
    fn noop_dispatch_multi_chunk_object() {
        let mut dispatch = NoOpDispatch::new();
        let c0 = make_chunk(test_obj_id(0x20), 0, 0, 3, b"AAA", false);
        let c1 = make_chunk(test_obj_id(0x20), 3, 1, 3, b"BBB", false);
        let c2 = make_chunk(test_obj_id(0x20), 6, 2, 3, b"CCC", true);

        let mut wire = Vec::new();
        wire.extend_from_slice(&encode_chunk_to_wire(&c0));
        wire.extend_from_slice(&encode_chunk_to_wire(&c1));
        wire.extend_from_slice(&encode_chunk_to_wire(&c2));

        receive_object(&wire, 0, &mut dispatch).unwrap();
        assert_eq!(dispatch.objects_received.len(), 1);
        assert_eq!(dispatch.objects_received[0].payload, b"AAABBBCCC");
        assert_eq!(dispatch.total_chunks_processed, 3);
    }

    #[test]
    fn noop_dispatch_multiple_objects() {
        let mut dispatch = NoOpDispatch::new();
        let a0 = make_chunk(test_obj_id(0x0A), 0, 0, 1, b"objA", true);
        let b0 = make_chunk(test_obj_id(0x0B), 0, 0, 1, b"objB", true);

        let mut wire = Vec::new();
        wire.extend_from_slice(&encode_chunk_to_wire(&a0));
        wire.extend_from_slice(&encode_chunk_to_wire(&b0));

        receive_object(&wire, 0, &mut dispatch).unwrap();
        assert_eq!(dispatch.objects_received.len(), 2);
        let mut payloads: Vec<Vec<u8>> = dispatch
            .objects_received
            .iter()
            .map(|o| o.payload.clone())
            .collect();
        payloads.sort();
        assert_eq!(payloads, vec![b"objA".to_vec(), b"objB".to_vec()]);
        assert_eq!(dispatch.total_bytes_received, 8);
    }

    #[test]
    fn receive_object_rejects_corrupt_wire() {
        let mut dispatch = NoOpDispatch::new();
        let chunk = make_chunk(test_obj_id(0x01), 0, 0, 1, b"data", true);
        let mut wire = encode_chunk_to_wire(&chunk);
        wire[0] ^= 0xFF; // corrupt magic
        let err = receive_object(&wire, 0, &mut dispatch).unwrap_err();
        assert!(matches!(
            err,
            ReceiveError::Decode(ChunkDecodeError::BadMagic { .. })
        ));
        assert!(dispatch.objects_received.is_empty());
    }

    #[test]
    fn receive_object_enforces_max_payload() {
        let mut dispatch = NoOpDispatch::new();
        let chunk = make_chunk(test_obj_id(0x01), 0, 0, 1, b"too-large", true);
        let wire = encode_chunk_to_wire(&chunk);
        let err = receive_object(&wire, 4, &mut dispatch).unwrap_err();
        assert!(matches!(
            err,
            ReceiveError::Decode(ChunkDecodeError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn receive_object_handles_empty_wire() {
        let mut dispatch = NoOpDispatch::new();
        let (_, _) = receive_object(b"", 0, &mut dispatch).unwrap();
        assert!(dispatch.objects_received.is_empty());
    }

    #[test]
    fn receive_object_auth_tag_failure_stops_pipeline() {
        let mut dispatch = NoOpDispatch::new();
        let mut chunk = make_chunk(test_obj_id(0x01), 0, 0, 1, b"evil", true);
        chunk.auth_tag[0] ^= 0xFF;
        let wire = encode_chunk_to_wire(&chunk);
        let err = receive_object(&wire, 0, &mut dispatch).unwrap_err();
        assert!(matches!(
            err,
            ReceiveError::Decode(ChunkDecodeError::AuthTagMismatch)
        ));
        assert!(dispatch.objects_received.is_empty());
    }
}
