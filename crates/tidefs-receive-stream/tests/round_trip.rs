//! Cross-crate round-trip validation: send-stream ChunkFramer output
//! decoded by receive-stream ChunkDecoder with BLAKE3 verification.
//!
//! This integration test verifies the wire-format contract between
//! the two crates without coupling them at the library level.

use tidefs_binary_schema_checksum::blake3_domain_digest;
use tidefs_binary_schema_core::{DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion};
use tidefs_receive_stream::assembler::ObjectAssembler;
use tidefs_receive_stream::decoder::{encode_chunk_to_wire, ChunkDecoder};
use tidefs_receive_stream::dispatch::{receive_object, NoOpDispatch};
use tidefs_send_stream::framer::ChunkFramer as SendChunkFramer;

fn test_obj_id(byte: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = byte;
    id
}

/// Convert a send-stream FramedChunk to a receive-stream wire-format
/// byte sequence that receive-stream can decode.
///
/// Both crates use the same auth-tag parameters (family 7, type 1,
/// version 1.0, TransferStream domain), so the receiver should
/// verify the auth tags produced by the sender.
fn send_chunk_to_wire(chunk: &tidefs_send_stream::framer::FramedChunk) -> Vec<u8> {
    let recv_chunk = tidefs_receive_stream::decoder::FramedChunk {
        object_id: chunk.object_id,
        offset: chunk.offset,
        chunk_index: chunk.chunk_index,
        total_chunks: chunk.total_chunks,
        payload: chunk.payload.clone(),
        auth_tag: chunk.auth_tag,
        is_last: chunk.is_last,
    };
    encode_chunk_to_wire(&recv_chunk)
}

#[test]
fn single_chunk_round_trip_through_wire() {
    let data = b"hello cross-crate round trip".to_vec();
    let object_id = test_obj_id(0xA1);
    let mut framer = SendChunkFramer::new(object_id, data.clone(), 1024);
    let send_chunk = framer.next_chunk().unwrap();
    assert!(send_chunk.is_last);
    assert_eq!(send_chunk.total_chunks, 1);

    // Verify send-stream auth tag
    assert!(send_chunk.verify_auth_tag());

    // Encode to wire format
    let wire = send_chunk_to_wire(&send_chunk);

    // Decode via receive-stream
    let decoder = ChunkDecoder::new();
    let (recv_chunk, rest) = decoder.decode_chunk(&wire).unwrap();
    assert!(rest.is_empty());
    assert!(recv_chunk.verify_auth_tag());

    // Field-level equality
    assert_eq!(recv_chunk.object_id, object_id);
    assert_eq!(recv_chunk.offset, 0);
    assert_eq!(recv_chunk.chunk_index, 0);
    assert_eq!(recv_chunk.total_chunks, 1);
    assert_eq!(recv_chunk.payload, data);
    assert!(recv_chunk.is_last);

    // Auth tags must match (same payload, same domain parameters)
    assert_eq!(recv_chunk.auth_tag, send_chunk.auth_tag);
}

#[test]
fn multi_chunk_round_trip_and_reassembly() {
    let data = b"0123456789ABCDEFGHIJ".to_vec(); // 20 bytes, chunk_size=6 -> 4 chunks
    let object_id = test_obj_id(0xB2);
    let mut framer = SendChunkFramer::new(object_id, data.clone(), 6);

    let mut wire_bytes = Vec::new();
    let mut send_chunks = Vec::new();

    while let Some(chunk) = framer.next_chunk() {
        assert!(chunk.verify_auth_tag());
        wire_bytes.extend_from_slice(&send_chunk_to_wire(&chunk));
        send_chunks.push(chunk);
    }

    assert_eq!(send_chunks.len(), 4);
    assert!(send_chunks.last().unwrap().is_last);

    // Now receive the whole wire sequence
    let decoder = ChunkDecoder::new();
    let mut assembler = ObjectAssembler::new();
    let mut bytes = &wire_bytes[..];

    let mut recv_count = 0;
    while !bytes.is_empty() {
        let (chunk, rest) = decoder.decode_chunk(bytes).unwrap();
        assert!(chunk.verify_auth_tag());
        assert_eq!(chunk.object_id, object_id);
        assert_eq!(chunk.total_chunks, 4);
        assembler.feed_chunk(chunk).unwrap();
        bytes = rest;
        recv_count += 1;
    }
    assert_eq!(recv_count, 4);

    // Object should be fully assembled
    let complete = assembler.drain_complete();
    assert_eq!(complete.len(), 1);
    assert_eq!(complete[0].object_id, object_id);
    assert_eq!(complete[0].payload, data);
    assert_eq!(complete[0].total_chunks, 4);
}

#[test]
fn round_trip_large_object_many_chunks() {
    let data = vec![0x77u8; 10000];
    let object_id = test_obj_id(0xC3);
    let mut framer = SendChunkFramer::new(object_id, data.clone(), 512);

    let mut wire_bytes = Vec::new();
    let expected_chunks = 10000usize.div_ceil(512) as u32;
    assert_eq!(framer.total_chunks(), expected_chunks);

    let mut chunks_seen = 0u32;
    while let Some(chunk) = framer.next_chunk() {
        assert!(chunk.verify_auth_tag());
        assert_eq!(chunk.total_chunks, expected_chunks);
        assert_eq!(chunk.chunk_index, chunks_seen);
        wire_bytes.extend_from_slice(&send_chunk_to_wire(&chunk));
        chunks_seen += 1;
    }
    assert_eq!(chunks_seen, expected_chunks);

    // Decode and reassemble
    let decoder = ChunkDecoder::new();
    let mut assembler = ObjectAssembler::new();
    let mut bytes = &wire_bytes[..];
    let mut decoded = 0;

    while !bytes.is_empty() {
        let (chunk, rest) = decoder.decode_chunk(bytes).unwrap();
        assert!(chunk.verify_auth_tag());
        assembler.feed_chunk(chunk).unwrap();
        bytes = rest;
        decoded += 1;
    }
    assert_eq!(decoded, expected_chunks);

    let complete = assembler.drain_complete();
    assert_eq!(complete.len(), 1);
    assert_eq!(complete[0].payload, data);
}

#[test]
fn round_trip_object_ids_preserved() {
    // Verify multiple objects with distinct IDs round-trip correctly
    let objects: Vec<([u8; 32], Vec<u8>)> = vec![
        (test_obj_id(0x01), b"object-one-data".to_vec()),
        (test_obj_id(0x02), b"object-two-more-bytes".to_vec()),
        (test_obj_id(0xFF), b"third".to_vec()),
    ];

    let mut wire_bytes = Vec::new();
    for (obj_id, data) in &objects {
        let mut framer = SendChunkFramer::new(*obj_id, data.clone(), 64);
        while let Some(chunk) = framer.next_chunk() {
            wire_bytes.extend_from_slice(&send_chunk_to_wire(&chunk));
        }
    }

    // Receive all
    let decoder = ChunkDecoder::new();
    let mut assembler = ObjectAssembler::new();
    let mut bytes = &wire_bytes[..];
    while !bytes.is_empty() {
        let (chunk, rest) = decoder.decode_chunk(bytes).unwrap();
        assembler.feed_chunk(chunk).unwrap();
        bytes = rest;
    }

    let complete = assembler.drain_complete();
    assert_eq!(complete.len(), 3);

    // Verify each object's payload matches origin
    for obj in &complete {
        let expected = objects.iter().find(|(id, _)| *id == obj.object_id).unwrap();
        assert_eq!(obj.payload, expected.1);
    }
}

#[test]
fn round_trip_empty_data_object() {
    let data = Vec::new();
    let object_id = test_obj_id(0xEE);
    let mut framer = SendChunkFramer::new(object_id, data, 256);

    assert_eq!(framer.total_chunks(), 0);
    assert!(framer.is_exhausted());
    assert!(framer.next_chunk().is_none());
    // No chunks to send or receive for empty objects
}

#[test]
fn round_trip_rejects_domain_tag_mismatch() {
    // Produce a chunk with the send-stream auth tag, but then verify
    // that a different domain tag produces a different auth tag.
    let payload = b"domain mismatch test";
    let send_tag = blake3_domain_digest(
        payload,
        SchemaFamilyId(7),
        SchemaTypeId(1),
        SchemaVersion::new(1, 0),
        DomainTag::TransferStream,
    );
    let other_tag = blake3_domain_digest(
        payload,
        SchemaFamilyId(7),
        SchemaTypeId(1),
        SchemaVersion::new(1, 0),
        DomainTag::ObjectPayloadChunk,
    );
    assert_ne!(send_tag, other_tag);

    // If a chunk carries a non-TransferStream tag, decode should reject it
    let chunk = tidefs_receive_stream::decoder::FramedChunk {
        object_id: test_obj_id(0x01),
        offset: 0,
        chunk_index: 0,
        total_chunks: 1,
        payload: payload.to_vec(),
        auth_tag: other_tag, // wrong domain
        is_last: true,
    };
    let wire = encode_chunk_to_wire(&chunk);
    let decoder = ChunkDecoder::new();
    let err = decoder.decode_chunk(&wire).unwrap_err();
    assert!(matches!(
        err,
        tidefs_receive_stream::decoder::ChunkDecodeError::AuthTagMismatch
    ));
}

#[test]
fn round_trip_receive_object_pipeline_single_object() {
    let data = b"pipeline integration test".to_vec();
    let object_id = test_obj_id(0xD4);
    let mut framer = SendChunkFramer::new(object_id, data.clone(), 8);

    let mut wire_bytes = Vec::new();
    while let Some(chunk) = framer.next_chunk() {
        wire_bytes.extend_from_slice(&send_chunk_to_wire(&chunk));
    }

    let mut dispatch = NoOpDispatch::new();
    let (objects_count, total_bytes) = receive_object(&wire_bytes, 0, &mut dispatch).unwrap();

    assert_eq!(objects_count, 1);
    assert_eq!(total_bytes, data.len() as u64);
    assert_eq!(dispatch.objects_received.len(), 1);
    assert_eq!(dispatch.objects_received[0].payload, data);
    assert_eq!(dispatch.objects_received[0].object_id, object_id);
    assert_eq!(dispatch.total_bytes_received, data.len() as u64);
}

#[test]
fn round_trip_receive_object_multi_object() {
    let objects: Vec<([u8; 32], Vec<u8>)> = vec![
        (test_obj_id(0xAA), b"first-object".to_vec()),
        (test_obj_id(0xBB), b"second-object-data".to_vec()),
    ];

    let mut wire_bytes = Vec::new();
    let mut expected_total_bytes = 0u64;
    for (obj_id, data) in &objects {
        expected_total_bytes += data.len() as u64;
        let mut framer = SendChunkFramer::new(*obj_id, data.clone(), 64);
        while let Some(chunk) = framer.next_chunk() {
            wire_bytes.extend_from_slice(&send_chunk_to_wire(&chunk));
        }
    }

    let mut dispatch = NoOpDispatch::new();
    let (objects_count, total_bytes) = receive_object(&wire_bytes, 0, &mut dispatch).unwrap();

    assert_eq!(objects_count, 2);
    assert_eq!(total_bytes, expected_total_bytes);
    assert_eq!(dispatch.objects_received.len(), 2);
}

#[test]
fn round_trip_partial_chunk_rejected() {
    // Feed a truncated wire to receive_object, verify it fails cleanly
    let data = b"partial chunk test".to_vec();
    let object_id = test_obj_id(0xE5);
    let mut framer = SendChunkFramer::new(object_id, data, 64);
    let chunk = framer.next_chunk().unwrap();
    let mut wire = send_chunk_to_wire(&chunk);

    // Truncate wire mid-payload
    wire.truncate(wire.len() - 3);

    let mut dispatch = NoOpDispatch::new();
    let err = receive_object(&wire, 0, &mut dispatch).unwrap_err();
    assert!(matches!(
        err,
        tidefs_receive_stream::dispatch::ReceiveError::Decode(
            tidefs_receive_stream::decoder::ChunkDecodeError::TruncatedPayload { .. }
        )
    ));
    // No objects should have been dispatched
    assert!(dispatch.objects_received.is_empty());
}

#[test]
fn round_trip_chunk_ordering_preserved() {
    // Chunks sent in order should be decoded in order and reassemble correctly
    let data: Vec<u8> = (0..50u8).collect(); // [0, 1, 2, ..., 49]
    let object_id = test_obj_id(0xF6);
    let mut framer = SendChunkFramer::new(object_id, data.clone(), 7);

    let mut wire_bytes = Vec::new();
    while let Some(chunk) = framer.next_chunk() {
        wire_bytes.extend_from_slice(&send_chunk_to_wire(&chunk));
    }

    let decoder = ChunkDecoder::new();
    let mut assembler = ObjectAssembler::new();
    let mut bytes = &wire_bytes[..];
    while !bytes.is_empty() {
        let (chunk, rest) = decoder.decode_chunk(bytes).unwrap();
        assembler.feed_chunk(chunk).unwrap();
        bytes = rest;
    }

    let complete = assembler.drain_complete();
    assert_eq!(complete.len(), 1);
    assert_eq!(complete[0].payload, data);
}
