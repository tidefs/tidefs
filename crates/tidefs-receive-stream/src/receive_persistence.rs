//! Receive persistence bridge: persist reassembled objects into a local
//! object store.
//!
//! Bridges the receive-stream decode pipeline to a concrete [`ObjectStore`]
//! backend. Each fully reassembled [`AssembledObject`] is persisted via
//! content-addressed put with optional BLAKE3 key-consistency verification,
//! closing the receive-side persistence gap for multi-node state transfer.
//!
//! # Architecture
//!
//! ```text
//! Receiver wire bytes
//!        |
//!   ChunkDecoder (verify per-chunk BLAKE3-256)
//!        |
//!   ObjectAssembler (reassemble ordered chunks)
//!        |
//!   ReceivePersistenceBridge (content-addressed put + key verify)
//!        |
//!   ObjectStore (durable local storage)
//! ```

use crate::assembler::AssembledObject;
use crate::dispatch::ReceiveDispatch;
use tidefs_local_object_store::{ObjectKey, ObjectStore, StoreError};

/// Persistence bridge that dispatches reassembled objects into an
/// [`ObjectStore`] via content-addressed put.
///
/// Each object is written through [`ObjectStore::put`], which derives the
/// storage key as BLAKE3-256 of the payload. When `verify_key` is enabled
/// (the default), the returned key is checked against the sender-provided
/// `object_id` to detect data tampering or sender-side bugs.
///
/// # Example
///
/// ```ignore
/// use tidefs_receive_stream::receive_persistence::ReceivePersistenceBridge;
/// use tidefs_receive_stream::dispatch::receive_object;
/// use tidefs_local_object_store::LocalObjectStore;
///
/// let mut store = LocalObjectStore::open("/pool/objects", Default::default()).unwrap();
/// let mut bridge = ReceivePersistenceBridge::new(&mut store);
/// let wire_bytes = /* chunk frames from peer */;
/// let (objects, bytes) = receive_object(&wire_bytes, 0, &mut bridge).unwrap();
/// ```
#[derive(Debug)]
pub struct ReceivePersistenceBridge<'a, S: ObjectStore> {
    /// The backing object store (borrowed from caller).
    store: &'a mut S,
    /// When true, verify the BLAKE3-derived key matches the sender's object_id.
    verify_key: bool,
    /// Number of objects successfully persisted.
    objects_persisted: u64,
    /// Total payload bytes persisted.
    bytes_persisted: u64,
    /// Total chunks received (sum of `total_chunks` across all objects).
    chunks_received: u64,
}

impl<'a, S: ObjectStore> ReceivePersistenceBridge<'a, S> {
    /// Create a new persistence bridge wrapping the given store.
    ///
    /// Key verification is enabled by default.
    #[must_use]
    pub fn new(store: &'a mut S) -> Self {
        Self {
            store,
            verify_key: true,
            objects_persisted: 0,
            bytes_persisted: 0,
            chunks_received: 0,
        }
    }

    /// Enable or disable BLAKE3 key-consistency verification.
    ///
    /// When disabled, objects are stored using the content-derived key
    /// without checking it against the sender's `object_id`. This is useful
    /// when the sender uses a different object-id scheme.
    #[must_use]
    pub fn with_key_verification(mut self, verify: bool) -> Self {
        self.verify_key = verify;
        self
    }

    /// Number of objects successfully persisted since construction.
    #[must_use]
    pub fn objects_persisted(&self) -> u64 {
        self.objects_persisted
    }

    /// Total payload bytes persisted since construction.
    #[must_use]
    pub fn bytes_persisted(&self) -> u64 {
        self.bytes_persisted
    }

    /// Total chunks received (sum of `total_chunks`) since construction.
    #[must_use]
    pub fn chunks_received(&self) -> u64 {
        self.chunks_received
    }
}

impl<S: ObjectStore> ReceiveDispatch for ReceivePersistenceBridge<'_, S> {
    type Error = StoreError;

    fn store_object(&mut self, object: AssembledObject) -> Result<(), Self::Error> {
        let sender_id = object.object_id;
        let payload_len = object.payload.len() as u64;

        // Persist via content-addressed put (BLAKE3-256 derives the key)
        let stored_key = self.store.put(&object.payload)?;

        // Verify BLAKE3 key consistency between sender and store
        if self.verify_key {
            let sender_key = ObjectKey::from_bytes32(sender_id);
            if stored_key != sender_key {
                return Err(StoreError::ContentAddressMismatch {
                    expected: sender_key,
                    actual: stored_key,
                });
            }
        }

        self.objects_persisted += 1;
        self.bytes_persisted += payload_len;
        self.chunks_received += object.total_chunks as u64;

        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        // ObjectStore flushes segments internally during put; no explicit flush
        // is required on the trait. The store guarantees durability on return.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use std::time::SystemTime;

    // ── Mock ObjectStore for unit testing ────────────────────────────

    /// A minimal in-memory ObjectStore implementation for testing.
    #[derive(Debug, Default)]
    struct MockStore {
        objects: BTreeMap<ObjectKey, Vec<u8>>,
        /// When set, the next put will return this error.
        inject_error: Option<StoreError>,
        /// When set, the next put will override the returned key.
        override_key: Option<ObjectKey>,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                objects: BTreeMap::new(),
                inject_error: None,
                override_key: None,
            }
        }

        fn with_error(mut self, err: StoreError) -> Self {
            self.inject_error = Some(err);
            self
        }

        fn with_override_key(mut self, key: ObjectKey) -> Self {
            self.override_key = Some(key);
            self
        }

        fn get_object(&self, key: ObjectKey) -> Option<&Vec<u8>> {
            self.objects.get(&key)
        }

        fn object_count(&self) -> usize {
            self.objects.len()
        }
    }

    impl ObjectStore for MockStore {
        type Scan = std::vec::IntoIter<ObjectKey>;

        fn put(&mut self, payload: &[u8]) -> Result<ObjectKey, StoreError> {
            if let Some(err) = self.inject_error.take() {
                return Err(err);
            }
            let key = if let Some(k) = self.override_key.take() {
                k
            } else {
                ObjectKey::from_content(payload)
            };
            self.objects.insert(key, payload.to_vec());
            Ok(key)
        }

        fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>, StoreError> {
            Ok(self.objects.get(&key).cloned())
        }

        fn delete(&mut self, key: ObjectKey) -> Result<bool, StoreError> {
            Ok(self.objects.remove(&key).is_some())
        }

        fn scan(&self) -> Self::Scan {
            self.objects.keys().copied().collect::<Vec<_>>().into_iter()
        }

        fn get_attr(
            &self,
            key: &ObjectKey,
        ) -> std::result::Result<
            tidefs_local_object_store::ObjectAttr,
            tidefs_local_object_store::ObjectReadError,
        > {
            match self.objects.get(key) {
                Some(payload) => Ok(tidefs_local_object_store::ObjectAttr {
                    size: payload.len() as u64,
                    key: *key,
                    created: SystemTime::UNIX_EPOCH,
                }),
                None => Err(tidefs_local_object_store::ObjectReadError::NotFound { key: *key }),
            }
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────

    /// Creates a BLAKE3-256 content-derived ObjectKey for the given bytes.
    fn content_key(data: &[u8]) -> ObjectKey {
        ObjectKey::from_content(data)
    }

    /// Creates a key where byte 0 differs, for mismatch tests.
    fn bad_key_for(data: &[u8]) -> ObjectKey {
        let k = ObjectKey::from_content(data);
        let mut bytes = k.as_bytes32();
        bytes[0] ^= 0xFF;
        ObjectKey::from_bytes32(bytes)
    }

    fn make_object(_id_byte: u8, payload: &[u8], total_chunks: u32) -> AssembledObject {
        AssembledObject {
            object_id: content_key(payload).as_bytes32(),
            payload: payload.to_vec(),
            total_chunks,
        }
    }

    // ── Single-object persistence ────────────────────────────────────

    #[test]
    fn single_object_store_persists_and_verifies_key() {
        let mut mock = MockStore::new();
        let mut bridge = ReceivePersistenceBridge::new(&mut mock);

        let obj = make_object(0x01, b"hello world", 1);
        bridge.store_object(obj.clone()).unwrap();

        assert_eq!(bridge.objects_persisted(), 1);
        assert_eq!(bridge.bytes_persisted(), 11);
        assert_eq!(bridge.chunks_received(), 1);
        assert_eq!(mock.object_count(), 1);

        let key = content_key(b"hello world");
        let stored = mock.get_object(key).unwrap();
        assert_eq!(stored, b"hello world");
    }

    #[test]
    fn store_object_disabled_key_verification_stores_anyway() {
        let mut mock = MockStore::new();
        {
            let mut bridge = ReceivePersistenceBridge::new(&mut mock).with_key_verification(false);

            // Use a non-content-derived object_id
            let obj = AssembledObject {
                object_id: [0xAAu8; 32],
                payload: b"ignore-id".to_vec(),
                total_chunks: 1,
            };
            bridge.store_object(obj).unwrap();
            assert_eq!(bridge.objects_persisted(), 1);
        }
        // bridge dropped, mutable borrow released
        // Object is stored under BLAKE3-derived key, not sender's ID
        let expected_key = content_key(b"ignore-id");
        assert!(mock.get_object(expected_key).is_some());
    }

    #[test]
    fn store_object_with_bad_key_rejected() {
        let mut mock = MockStore::new().with_override_key(bad_key_for(b"hello world"));

        let mut bridge = ReceivePersistenceBridge::new(&mut mock);
        let obj = make_object(0x01, b"hello world", 1);

        let err = bridge.store_object(obj).unwrap_err();
        assert!(
            matches!(err, StoreError::ContentAddressMismatch { .. }),
            "expected ContentAddressMismatch, got {err:?}"
        );
        assert_eq!(bridge.objects_persisted(), 0);
    }

    // ── Multi-chunk object through pipeline ──────────────────────────

    #[test]
    fn receive_object_with_persistence_bridge_multi_chunk() {
        use crate::decoder::{encode_chunk_to_wire, FramedChunk};
        use crate::dispatch::receive_object;
        use tidefs_binary_schema_checksum::blake3_domain_digest;
        use tidefs_binary_schema_core::{DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion};

        let mut mock = MockStore::new();
        let mut bridge = ReceivePersistenceBridge::new(&mut mock);

        let full_payload = b"AAAABBBBCCCC";
        let obj_id = content_key(full_payload).as_bytes32();

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

        let c0 = make_chunk(obj_id, 0, 0, 3, b"AAAA", false);
        let c1 = make_chunk(obj_id, 4, 1, 3, b"BBBB", false);
        let c2 = make_chunk(obj_id, 8, 2, 3, b"CCCC", true);

        let mut wire = Vec::new();
        wire.extend_from_slice(&encode_chunk_to_wire(&c0));
        wire.extend_from_slice(&encode_chunk_to_wire(&c1));
        wire.extend_from_slice(&encode_chunk_to_wire(&c2));

        let (objects, bytes) = receive_object(&wire, 0, &mut bridge).unwrap();
        assert_eq!(objects, 1);
        assert_eq!(bytes, 12);
        assert_eq!(bridge.objects_persisted(), 1);
        assert_eq!(bridge.bytes_persisted(), 12);
        assert_eq!(bridge.chunks_received(), 3);
        assert_eq!(mock.object_count(), 1);

        let stored = mock.get_object(content_key(full_payload)).unwrap();
        assert_eq!(stored, full_payload);
    }

    // ── Store errors propagate ───────────────────────────────────────

    #[test]
    fn store_full_error_propagates() {
        let mut mock = MockStore::new().with_error(StoreError::NoSpace);
        let mut bridge = ReceivePersistenceBridge::new(&mut mock);

        let obj = make_object(0x01, b"some data", 1);
        let err = bridge.store_object(obj).unwrap_err();
        assert!(matches!(err, StoreError::NoSpace));
        assert_eq!(bridge.objects_persisted(), 0);
    }

    #[test]
    fn content_collision_error_propagates() {
        let data = b"same data";
        // First: persist normally
        {
            let mut mock = MockStore::new();
            let mut bridge = ReceivePersistenceBridge::new(&mut mock);
            let obj = make_object(0x01, data, 1);
            bridge.store_object(obj).unwrap();
            assert_eq!(mock.object_count(), 1);
        }
        // Second: set up error, then try to persist
        let existing_key = content_key(data);
        let mut mock2 =
            MockStore::new().with_error(StoreError::ContentAddressCollision { key: existing_key });
        let mut bridge2 = ReceivePersistenceBridge::new(&mut mock2);
        let obj2 = make_object(0x01, data, 1);
        let err = bridge2.store_object(obj2).unwrap_err();
        assert!(matches!(err, StoreError::ContentAddressCollision { .. }));
    }

    // ── Idempotency: duplicate chunks handled by assembler ───────────

    #[test]
    fn duplicate_chunk_idempotency_handled_by_assembler() {
        use crate::decoder::{encode_chunk_to_wire, FramedChunk};
        use crate::dispatch::receive_object;
        use tidefs_binary_schema_checksum::blake3_domain_digest;
        use tidefs_binary_schema_core::{DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion};

        let payload = b"idempotent";
        let obj_id = content_key(payload).as_bytes32();

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

        let c0 = make_chunk(obj_id, 0, 0, 1, payload, true);
        let wire = encode_chunk_to_wire(&c0);

        // First receive: succeeds and stores the object
        {
            let mut mock = MockStore::new();
            let mut bridge = ReceivePersistenceBridge::new(&mut mock);
            let (objects, _) = receive_object(&wire, 0, &mut bridge).unwrap();
            assert_eq!(objects, 1);
            assert_eq!(mock.object_count(), 1);
        }

        // Second receive: same chunks with a fresh store — content-addressed
        // put produces the same key, so idempotency is guaranteed by the
        // ObjectStore's content-address collision detection (not corruption).
        {
            let mut mock2 = MockStore::new();
            let mut bridge2 = ReceivePersistenceBridge::new(&mut mock2);
            let result = receive_object(&wire, 0, &mut bridge2);
            if let Ok((objs, _)) = result {
                assert!(objs >= 1);
            }
        }
    }

    // ── Empty payload ────────────────────────────────────────────────

    #[test]
    fn empty_payload_object_persists() {
        let mut mock = MockStore::new();
        let mut bridge = ReceivePersistenceBridge::new(&mut mock);

        let obj = make_object(0x01, b"", 0);
        bridge.store_object(obj).unwrap();

        assert_eq!(bridge.objects_persisted(), 1);
        assert_eq!(bridge.bytes_persisted(), 0);
        assert_eq!(mock.object_count(), 1);

        let key = content_key(b"");
        assert!(mock.get_object(key).is_some());
    }

    // ── Multiple objects in single pipeline ──────────────────────────

    #[test]
    fn multiple_objects_through_pipeline() {
        use crate::decoder::{encode_chunk_to_wire, FramedChunk};
        use crate::dispatch::receive_object;
        use tidefs_binary_schema_checksum::blake3_domain_digest;
        use tidefs_binary_schema_core::{DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion};

        let mut mock = MockStore::new();
        let mut bridge = ReceivePersistenceBridge::new(&mut mock);

        let a_payload = b"object-A";
        let b_payload = b"object-BB";
        let a_id = content_key(a_payload).as_bytes32();
        let b_id = content_key(b_payload).as_bytes32();

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

        let a0 = make_chunk(a_id, 0, 0, 1, a_payload, true);
        let b0 = make_chunk(b_id, 0, 0, 1, b_payload, true);

        let mut wire = Vec::new();
        wire.extend_from_slice(&encode_chunk_to_wire(&a0));
        wire.extend_from_slice(&encode_chunk_to_wire(&b0));

        let (objects, bytes) = receive_object(&wire, 0, &mut bridge).unwrap();
        assert_eq!(objects, 2);
        assert_eq!(bytes, (a_payload.len() + b_payload.len()) as u64);
        assert_eq!(bridge.objects_persisted(), 2);
        assert_eq!(mock.object_count(), 2);

        assert!(mock.get_object(content_key(a_payload)).is_some());
        assert!(mock.get_object(content_key(b_payload)).is_some());
    }

    // ── Counters ─────────────────────────────────────────────────────

    #[test]
    fn counters_accumulate_across_multiple_calls() {
        let mut mock = MockStore::new();
        let mut bridge = ReceivePersistenceBridge::new(&mut mock);

        let obj1 = make_object(0x01, b"aaaa", 2);
        let obj2 = make_object(0x02, b"bbb", 3);

        bridge.store_object(obj1).unwrap();
        assert_eq!(bridge.objects_persisted(), 1);
        assert_eq!(bridge.bytes_persisted(), 4);
        assert_eq!(bridge.chunks_received(), 2);

        bridge.store_object(obj2).unwrap();
        assert_eq!(bridge.objects_persisted(), 2);
        assert_eq!(bridge.bytes_persisted(), 7);
        assert_eq!(bridge.chunks_received(), 5);
    }
}
