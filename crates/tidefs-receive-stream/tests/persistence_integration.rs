//! Integration test: receive-stream persistence bridge with a real
//! LocalObjectStore backed by a temporary directory.
//!
//! Validates that objects framed via send-stream, decoded and reassembled
//! via receive-stream, and dispatched through ReceivePersistenceBridge
//! are durably persisted in the local object store with correct BLAKE3
//! content hashes.

use std::path::PathBuf;
use tidefs_local_object_store::{LocalObjectStore, ObjectKey};
use tidefs_receive_stream::decoder::encode_chunk_to_wire;
use tidefs_receive_stream::decoder::FramedChunk as RecvFramedChunk;
use tidefs_receive_stream::dispatch::receive_object;
use tidefs_receive_stream::ReceiveDispatch;
use tidefs_receive_stream::ReceivePersistenceBridge;
use tidefs_send_stream::framer::ChunkFramer;

/// Convert a send-stream chunk to wire format decodable by receive-stream.
fn send_chunk_to_wire(chunk: &tidefs_send_stream::framer::FramedChunk) -> Vec<u8> {
    let recv = RecvFramedChunk {
        object_id: chunk.object_id,
        offset: chunk.offset,
        chunk_index: chunk.chunk_index,
        total_chunks: chunk.total_chunks,
        payload: chunk.payload.clone(),
        auth_tag: chunk.auth_tag,
        is_last: chunk.is_last,
    };
    encode_chunk_to_wire(&recv)
}

fn temp_store() -> (LocalObjectStore, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.keep();
    let store = LocalObjectStore::open(&path).expect("open store");
    (store, path)
}

#[test]
fn single_small_object_round_trip() {
    let (mut store, _path) = temp_store();
    let payload = b"hello persistence bridge";
    let object_id = ObjectKey::from_content(payload).as_bytes32();

    // Frame via send-stream
    let mut framer = ChunkFramer::new(object_id, payload.to_vec(), 4096);
    let chunk = framer.next_chunk().expect("single chunk");
    let wire = send_chunk_to_wire(&chunk);

    // Receive and persist via bridge
    let mut bridge = ReceivePersistenceBridge::new(&mut store);
    let (objects, bytes) = receive_object(&wire, 0, &mut bridge).expect("receive+persist");

    assert_eq!(objects, 1);
    assert_eq!(bytes, payload.len() as u64);
    assert_eq!(bridge.objects_persisted(), 1);
    assert_eq!(bridge.bytes_persisted(), payload.len() as u64);

    // Verify the store has the object
    let key = ObjectKey::from_content(payload);
    let stored = store.get(key).expect("get").expect("object present");
    assert_eq!(stored, payload);

    // Verify the store has correct metadata
    let attr = store.get_attr(&key).expect("get_attr");
    assert_eq!(attr.size, payload.len() as u64);
    assert_eq!(attr.key, key);
}

#[test]
fn multi_chunk_object_round_trip() {
    let (mut store, _path) = temp_store();
    let payload = vec![0xABu8; 10000];
    let object_id = ObjectKey::from_content(&payload).as_bytes32();

    // Frame into multiple chunks
    let mut framer = ChunkFramer::new(object_id, payload.clone(), 2048);
    let mut wire = Vec::new();
    let mut chunk_count = 0u32;
    while let Some(chunk) = framer.next_chunk() {
        wire.extend_from_slice(&send_chunk_to_wire(&chunk));
        chunk_count += 1;
    }
    assert!(chunk_count > 1, "should produce multiple chunks");

    // Receive and persist via bridge
    let mut bridge = ReceivePersistenceBridge::new(&mut store);
    let (objects, bytes) = receive_object(&wire, 0, &mut bridge).expect("receive+persist");

    assert_eq!(objects, 1);
    assert_eq!(bytes, payload.len() as u64);
    assert_eq!(bridge.objects_persisted(), 1);
    assert_eq!(bridge.bytes_persisted(), payload.len() as u64);
    assert_eq!(bridge.chunks_received(), chunk_count as u64);

    // Verify store contents
    let key = ObjectKey::from_content(&payload);
    let stored = store.get(key).expect("get").expect("object present");
    assert_eq!(stored, payload);
}

#[test]
fn multiple_objects_in_single_pipeline() {
    let (mut store, _path) = temp_store();
    let payloads: Vec<&[u8]> = vec![b"alpha", b"beta", b"gamma"];

    let mut wire = Vec::new();
    let expected_bytes: u64 = payloads.iter().map(|p| p.len() as u64).sum();

    for payload in &payloads {
        let object_id = ObjectKey::from_content(payload).as_bytes32();
        let mut framer = ChunkFramer::new(object_id, payload.to_vec(), 1024);
        while let Some(chunk) = framer.next_chunk() {
            wire.extend_from_slice(&send_chunk_to_wire(&chunk));
        }
    }

    let mut bridge = ReceivePersistenceBridge::new(&mut store);
    let (objects, bytes) = receive_object(&wire, 0, &mut bridge).expect("receive+persist");

    assert_eq!(objects, payloads.len() as u64);
    assert_eq!(bytes, expected_bytes);
    assert_eq!(bridge.objects_persisted(), payloads.len() as u64);
    assert_eq!(bridge.bytes_persisted(), expected_bytes);

    // Verify all objects in store
    for payload in &payloads {
        let key = ObjectKey::from_content(payload);
        let stored = store.get(key).expect("get").expect("object present");
        assert_eq!(stored, *payload);
    }
}

#[test]
fn disabled_key_verification_stores_content_key() {
    let (mut store, _path) = temp_store();
    let payload = b"noverify data";
    let non_content_id = [0xDDu8; 32]; // object_id differs from BLAKE3-derived key

    let mut framer = ChunkFramer::new(non_content_id, payload.to_vec(), 4096);
    let chunk = framer.next_chunk().expect("single chunk");
    let wire = send_chunk_to_wire(&chunk);

    // With verification disabled, the bridge stores under the content key,
    // not the sender's non_content_id
    let mut bridge = ReceivePersistenceBridge::new(&mut store).with_key_verification(false);
    let (objects, _bytes) = receive_object(&wire, 0, &mut bridge).expect("receive+persist");

    assert_eq!(objects, 1);
    assert_eq!(bridge.objects_persisted(), 1);

    // Object is stored under BLAKE3-derived content key
    let content_key = ObjectKey::from_content(payload);
    let stored = store
        .get(content_key)
        .expect("get")
        .expect("object present");
    assert_eq!(stored, payload);

    // Non_content_id is NOT the storage key
    let non_content_key = ObjectKey::from_bytes32(non_content_id);
    assert!(
        store.get(non_content_key).expect("get").is_none(),
        "non-content-derived key should not map to stored object"
    );
}

#[test]
fn empty_payload_object_persists_to_store() {
    let (mut store, _path) = temp_store();
    let payload: &[u8] = b"";
    let object_id = ObjectKey::from_content(payload).as_bytes32();

    let mut framer = ChunkFramer::new(object_id, payload.to_vec(), 256);
    // Empty payload produces zero chunks from ChunkFramer
    let mut wire = Vec::new();
    while let Some(chunk) = framer.next_chunk() {
        wire.extend_from_slice(&send_chunk_to_wire(&chunk));
    }

    let mut bridge = ReceivePersistenceBridge::new(&mut store);
    let (objects, _bytes) = receive_object(&wire, 0, &mut bridge).expect("receive+persist");

    // Empty payload = 0 chunks, so 0 objects dispatched through the pipeline
    assert_eq!(objects, 0);

    // Manually persist an empty object through the bridge to verify the store
    // accepts it
    let assembled = tidefs_receive_stream::assembler::AssembledObject {
        object_id,
        payload: vec![],
        total_chunks: 0,
    };
    bridge.store_object(assembled).expect("store empty object");
    assert_eq!(bridge.objects_persisted(), 1);
    assert_eq!(bridge.bytes_persisted(), 0);

    let key = ObjectKey::from_content(b"");
    let stored = store.get(key).expect("get").expect("object present");
    assert!(stored.is_empty());
}
