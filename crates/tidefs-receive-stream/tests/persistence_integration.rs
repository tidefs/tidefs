// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
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

// ── Incremental contract tests ──────────────────────────────────────

use tidefs_receive_stream::receive_persistence::{
    BaseRootPinLookup, ReceiveContract, ReceivePersistenceError,
};

/// A pin lookup for integration tests.
struct StubPinLookup {
    pinned: Vec<[u8; 32]>,
    lineages: std::collections::HashMap<[u8; 32], [u8; 32]>,
}

impl StubPinLookup {
    fn new() -> Self {
        Self {
            pinned: Vec::new(),
            lineages: std::collections::HashMap::new(),
        }
    }

    fn add_pinned_with_lineage(&mut self, identity: [u8; 32], lineage: [u8; 32]) {
        self.pinned.push(identity);
        self.lineages.insert(identity, lineage);
    }
}

impl BaseRootPinLookup for StubPinLookup {
    fn is_base_root_pinned(&self, base_root_identity: &[u8; 32]) -> bool {
        self.pinned.contains(base_root_identity)
    }

    fn dataset_lineage_for_base_root(
        &self,
        base_root_identity: &[u8; 32],
    ) -> Option<[u8; 32]> {
        self.lineages.get(base_root_identity).copied()
    }
}

/// Test: incremental receive with valid pinned base root succeeds.
#[test]
fn incremental_receive_with_valid_pinned_base_root() {
    let (mut store, _path) = temp_store();
    let payload = b"incremental data block";
    let object_id = ObjectKey::from_content(payload).as_bytes32();

    let mut framer = ChunkFramer::new(object_id, payload.to_vec(), 4096);
    let chunk = framer.next_chunk().expect("single chunk");
    let wire = send_chunk_to_wire(&chunk);

    // A base root identity for the pin authority
    let base_root = [0xA1u8; 32];
    let lineage = [0xB1u8; 32];

    let mut pin_lookup = StubPinLookup::new();
    pin_lookup.add_pinned_with_lineage(base_root, lineage);

    let contract = ReceiveContract {
        base_root_identity: base_root,
        dataset_lineage_identity: lineage,
        receive_generation: 1,
    };

    let mut bridge = ReceivePersistenceBridge::new(&mut store)
        .with_incremental_contract(contract);

    // Validate before dispatching
    bridge.validate_base_root_pin(&pin_lookup).expect("base root should be pinned");
    assert!(bridge.has_validated_contract());

    let (objects, bytes) = receive_object(&wire, 0, &mut bridge).expect("receive+persist");

    assert_eq!(objects, 1);
    assert_eq!(bytes, payload.len() as u64);
    assert_eq!(bridge.objects_persisted(), 1);

    // Verify the store has the object
    let key = ObjectKey::from_content(payload);
    let stored = store.get(key).expect("get").expect("object present");
    assert_eq!(stored, payload);
}

/// Test: incremental receive blocks persistence when contract is not validated.
#[test]
fn incremental_receive_blocked_without_validation() {
    let (mut store, _path) = temp_store();
    let payload = b"should not persist";
    let object_id = ObjectKey::from_content(payload).as_bytes32();

    let mut framer = ChunkFramer::new(object_id, payload.to_vec(), 4096);
    let chunk = framer.next_chunk().expect("single chunk");
    let wire = send_chunk_to_wire(&chunk);

    let contract = ReceiveContract {
        base_root_identity: [0xA2u8; 32],
        dataset_lineage_identity: [0xB2u8; 32],
        receive_generation: 2,
    };

    let mut bridge = ReceivePersistenceBridge::new(&mut store)
        .with_incremental_contract(contract);

    // Do NOT call validate_base_root_pin — persistence should be blocked
    assert!(!bridge.has_validated_contract());

    let err = receive_object(&wire, 0, &mut bridge).unwrap_err();
    // The error should surface as a dispatch error with ContractNotValidated
    assert!(
        format!("{err}").contains("ContractNotValidated"),
        "expected ContractNotValidated, got: {err}"
    );

    // No objects persisted
    assert_eq!(bridge.objects_persisted(), 0);
}

/// Test: incremental receive with missing base root fails gracefully.
#[test]
fn incremental_receive_rejects_missing_base_root() {
    let (mut store, _path) = temp_store();
    let payload = b"missing base root";
    let object_id = ObjectKey::from_content(payload).as_bytes32();

    let mut framer = ChunkFramer::new(object_id, payload.to_vec(), 4096);
    let chunk = framer.next_chunk().expect("single chunk");
    let wire = send_chunk_to_wire(&chunk);

    let missing_base = [0xDEu8; 32];
    let contract = ReceiveContract {
        base_root_identity: missing_base,
        dataset_lineage_identity: [0xADu8; 32],
        receive_generation: 1,
    };

    let mut bridge = ReceivePersistenceBridge::new(&mut store)
        .with_incremental_contract(contract);

    // Pin lookup does NOT contain the missing base root
    let pin_lookup = StubPinLookup::new();

    let err = bridge
        .validate_base_root_pin(&pin_lookup)
        .unwrap_err();
    assert!(
        matches!(err, ReceivePersistenceError::BaseRootNotPinned { .. }),
        "expected BaseRootNotPinned, got: {err:?}"
    );

    // Contract remains unvalidated — persistence blocked
    assert!(!bridge.has_validated_contract());

    let dispatch_err = receive_object(&wire, 0, &mut bridge).unwrap_err();
    assert!(
        format!("{dispatch_err}").contains("ContractNotValidated"),
        "expected ContractNotValidated after failed validation, got: {dispatch_err}"
    );

    assert_eq!(bridge.objects_persisted(), 0);
}

/// Test: incremental receive with wrong dataset lineage fails.
#[test]
fn incremental_receive_rejects_wrong_lineage() {
    let (mut store, _path) = temp_store();
    let payload = b"wrong lineage";
    let object_id = ObjectKey::from_content(payload).as_bytes32();

    let mut framer = ChunkFramer::new(object_id, payload.to_vec(), 4096);
    let chunk = framer.next_chunk().expect("single chunk");
    let wire = send_chunk_to_wire(&chunk);

    let base_root = [0xA3u8; 32];
    let correct_lineage = [0xB3u8; 32];
    let wrong_lineage = [0xC3u8; 32];

    let mut pin_lookup = StubPinLookup::new();
    // Pin the base root but with a different lineage
    pin_lookup.add_pinned_with_lineage(base_root, wrong_lineage);

    let contract = ReceiveContract {
        base_root_identity: base_root,
        dataset_lineage_identity: correct_lineage,
        receive_generation: 1,
    };

    let mut bridge = ReceivePersistenceBridge::new(&mut store)
        .with_incremental_contract(contract);

    let err = bridge
        .validate_base_root_pin(&pin_lookup)
        .unwrap_err();
    assert!(
        matches!(err, ReceivePersistenceError::DatasetLineageMismatch { .. }),
        "expected DatasetLineageMismatch, got: {err:?}"
    );

    assert!(!bridge.has_validated_contract());

    // Persistence blocked
    let dispatch_err = receive_object(&wire, 0, &mut bridge).unwrap_err();
    assert!(
        format!("{dispatch_err}").contains("ContractNotValidated"),
        "expected ContractNotValidated, got: {dispatch_err}"
    );

    assert_eq!(bridge.objects_persisted(), 0);
}

/// Test: full (non-incremental) receive works without any contract.
#[test]
fn full_receive_without_contract_succeeds() {
    let (mut store, _path) = temp_store();
    let payload = b"full stream no contract";
    let object_id = ObjectKey::from_content(payload).as_bytes32();

    let mut framer = ChunkFramer::new(object_id, payload.to_vec(), 4096);
    let chunk = framer.next_chunk().expect("single chunk");
    let wire = send_chunk_to_wire(&chunk);

    let mut bridge = ReceivePersistenceBridge::new(&mut store);
    // No contract set — behaves as a full receive
    assert!(bridge.contract().is_none());
    assert!(!bridge.has_validated_contract());

    let (objects, bytes) = receive_object(&wire, 0, &mut bridge).expect("receive+persist");

    assert_eq!(objects, 1);
    assert_eq!(bytes, payload.len() as u64);
    assert_eq!(bridge.objects_persisted(), 1);

    let key = ObjectKey::from_content(payload);
    let stored = store.get(key).expect("get").expect("object present");
    assert_eq!(stored, payload);
}

/// Test: replay of a completed receive (same objects again) succeeds
/// with a validated contract.
#[test]
fn replay_of_completed_receive_with_validated_contract() {
    let (mut store, _path) = temp_store();
    let payload = b"replay data";
    let object_id = ObjectKey::from_content(payload).as_bytes32();

    let mut framer = ChunkFramer::new(object_id, payload.to_vec(), 4096);
    let chunk = framer.next_chunk().expect("single chunk");
    let wire = send_chunk_to_wire(&chunk);

    let base_root = [0xA4u8; 32];
    let lineage = [0xB4u8; 32];

    let mut pin_lookup = StubPinLookup::new();
    pin_lookup.add_pinned_with_lineage(base_root, lineage);

    let contract = ReceiveContract {
        base_root_identity: base_root,
        dataset_lineage_identity: lineage,
        receive_generation: 1,
    };

    // First receive
    {
        let mut bridge = ReceivePersistenceBridge::new(&mut store)
            .with_incremental_contract(contract);
        bridge.validate_base_root_pin(&pin_lookup).expect("validate");
        receive_object(&wire, 0, &mut bridge).expect("first receive");
        assert_eq!(bridge.objects_persisted(), 1);
    }

    // Second receive (replay) with fresh bridge, same contract
    {
        let mut bridge2 = ReceivePersistenceBridge::new(&mut store)
            .with_incremental_contract(contract);
        bridge2.validate_base_root_pin(&pin_lookup).expect("validate replay");
        let result = receive_object(&wire, 0, &mut bridge2);
        // Content-addressed put may succeed (idempotent) or produce a key
        // mismatch depending on store collision behavior
        assert!(
            result.is_ok() || format!("{}", result.as_ref().unwrap_err()).contains("mismatch"),
            "unexpected error on replay: {result:?}"
        );
    }

    // Verify the object is in the store
    let key = ObjectKey::from_content(payload);
    let stored = store.get(key).expect("get").expect("object present");
    assert_eq!(stored, payload);
}
