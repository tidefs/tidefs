//! Send-stream writer that reads objects from local-object-store and produces
//! TransferStream chunk frames for multi-node state transfer.
//!
//! The `SendStreamWriter` wraps an [`ObjectStore`] and uses a
//! [`TransferChunkEncoder`](super::chunk_encoder::TransferChunkEncoder) to
//! split each object into domain-separated BLAKE3-authenticated chunks. The
//! output frames are wire-compatible with
//! `tidefs_receive_stream::decoder::ChunkDecoder`.

use std::collections::BTreeMap;

use tidefs_local_object_store::store::ObjectStore;
use tidefs_local_object_store::ObjectKey;

use super::chunk_encoder::{TransferChunk, TransferChunkEncoder, TransferChunkEncoderConfig};
use super::encoder::LineageManifestFrame;
use crate::LineageManifest;

/// A send-stream writer output frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendStreamWriterFrame {
    /// Lineage manifest that must precede object chunks.
    LineageManifest(LineageManifestFrame),
    /// Object payload chunk.
    ObjectChunk {
        /// Object key whose payload produced this chunk.
        key: ObjectKey,
        /// TransferStream chunk frame.
        chunk: TransferChunk,
    },
}

/// Drives chunk encoding for objects read from a local-object-store.
///
/// Produces [`TransferChunk`] frames that can be fed directly into the
/// receive-stream decoder for multi-node state transfer.
pub struct SendStreamWriter<'a, T: ObjectStore> {
    store: &'a T,
    encoder: TransferChunkEncoder,
    manifest: Option<LineageManifest>,
}

impl<'a, T: ObjectStore> SendStreamWriter<'a, T> {
    /// Create a new writer wrapping an object store.
    pub fn new(store: &'a T, config: TransferChunkEncoderConfig) -> Self {
        Self {
            store,
            encoder: TransferChunkEncoder::new(config),
            manifest: None,
        }
    }

    /// Create a new writer that emits `manifest` before object chunks.
    pub fn new_with_manifest(
        store: &'a T,
        config: TransferChunkEncoderConfig,
        manifest: LineageManifest,
    ) -> Self {
        Self {
            store,
            encoder: TransferChunkEncoder::new(config),
            manifest: Some(manifest),
        }
    }

    /// Return a copy of the encoder configuration.
    pub fn config(&self) -> TransferChunkEncoderConfig {
        self.encoder.config()
    }

    /// Return the configured lineage manifest, if one was supplied.
    #[must_use]
    pub fn lineage_manifest(&self) -> Option<&LineageManifest> {
        self.manifest.as_ref()
    }

    /// Encode the configured lineage manifest frame.
    ///
    /// # Errors
    ///
    /// Returns an error when the writer was created without a manifest.
    pub fn write_manifest_frame(&self) -> Result<LineageManifestFrame, std::io::Error> {
        self.manifest
            .clone()
            .map(LineageManifestFrame::new)
            .ok_or_else(|| std::io::Error::other("send lineage manifest is missing"))
    }

    /// Read one object from the store and encode it into TransferStream chunks.
    ///
    /// Returns `Ok(None)` when the object key is not found.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the store read fails.
    pub fn write_object(
        &self,
        key: ObjectKey,
    ) -> Result<Option<Vec<TransferChunk>>, std::io::Error> {
        match self.store.get(key) {
            Ok(Some(data)) => Ok(Some(self.encoder.encode_object(key.as_bytes32(), &data))),
            Ok(None) => Ok(None),
            Err(e) => Err(std::io::Error::other(format!(
                "object store read failed: {e}"
            ))),
        }
    }

    /// Scan all live object keys from the store and encode every object.
    ///
    /// Returns a map from object key to its encoded chunks.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if any store read fails.
    pub fn write_all(&self) -> Result<BTreeMap<ObjectKey, Vec<TransferChunk>>, std::io::Error> {
        let mut results = BTreeMap::new();
        for key in self.store.scan() {
            if let Some(chunks) = self.write_object(key)? {
                results.insert(key, chunks);
            }
        }
        Ok(results)
    }

    /// Encode the lineage manifest followed by every live object chunk.
    ///
    /// # Errors
    ///
    /// Returns an error if the writer has no manifest or if any store read fails.
    pub fn write_all_frames(&self) -> Result<Vec<SendStreamWriterFrame>, std::io::Error> {
        let mut frames = vec![SendStreamWriterFrame::LineageManifest(
            self.write_manifest_frame()?,
        )];
        for key in self.store.scan() {
            if let Some(chunks) = self.write_object(key)? {
                frames.extend(
                    chunks
                        .into_iter()
                        .map(|chunk| SendStreamWriterFrame::ObjectChunk { key, chunk }),
                );
            }
        }
        Ok(frames)
    }

    /// Estimate how many chunks an object will produce without reading it.
    ///
    /// Uses [`ObjectStore::get_attr`] to obtain the payload length.
    pub fn estimate_chunk_count(
        &self,
        key: &ObjectKey,
    ) -> std::result::Result<usize, tidefs_local_object_store::ObjectReadError> {
        let attr = self.store.get_attr(key)?;
        Ok(self.encoder.chunk_count(attr.size as usize))
    }

    /// Maximum chunk payload size (for transport buffer sizing).
    pub fn max_payload(&self) -> u32 {
        self.encoder.max_payload()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    // Lightweight mock object store for testing
    struct MockStore {
        objects: BTreeMap<ObjectKey, Vec<u8>>,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                objects: BTreeMap::new(),
            }
        }

        fn insert(&mut self, key: ObjectKey, data: Vec<u8>) {
            self.objects.insert(key, data);
        }
    }

    impl ObjectStore for MockStore {
        type Scan = std::vec::IntoIter<ObjectKey>;

        fn put(
            &mut self,
            _payload: &[u8],
        ) -> Result<ObjectKey, tidefs_local_object_store::StoreError> {
            unimplemented!("mock put not used in tests")
        }

        fn get(
            &self,
            key: ObjectKey,
        ) -> Result<Option<Vec<u8>>, tidefs_local_object_store::StoreError> {
            Ok(self.objects.get(&key).cloned())
        }

        fn delete(
            &mut self,
            _key: ObjectKey,
        ) -> Result<bool, tidefs_local_object_store::StoreError> {
            unimplemented!("mock delete not used in tests")
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
                Some(data) => Ok(tidefs_local_object_store::ObjectAttr {
                    size: data.len() as u64,
                    created: std::time::SystemTime::UNIX_EPOCH,
                    key: *key,
                }),
                None => Err(tidefs_local_object_store::ObjectReadError::NotFound { key: *key }),
            }
        }
    }

    fn test_key(byte: u8) -> ObjectKey {
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        ObjectKey::from_bytes(bytes)
    }

    fn manifest() -> LineageManifest {
        let header = crate::SendStreamHeader::new([1; 16], [2; 16], [3; 16]);
        LineageManifest::full(&header, [4; 32])
    }

    #[test]
    fn write_single_object_produces_chunks() {
        let mut store = MockStore::new();
        let key = test_key(1);
        let data = vec![0x42u8; 200_000];
        store.insert(key, data.clone());

        let config = TransferChunkEncoderConfig { chunk_size: 65536 };
        let writer = SendStreamWriter::new(&store, config);

        let chunks = writer.write_object(key).unwrap().unwrap();
        assert!(chunks.len() >= 4);

        let reassembled: Vec<u8> = chunks.iter().flat_map(|c| c.payload.clone()).collect();
        assert_eq!(reassembled, data);

        for c in &chunks {
            assert!(c.verify_auth_tag());
        }
    }

    #[test]
    fn write_single_object_empty_data() {
        let mut store = MockStore::new();
        let key = test_key(2);
        store.insert(key, Vec::new());

        let config = TransferChunkEncoderConfig::default();
        let writer = SendStreamWriter::new(&store, config);

        let chunks = writer.write_object(key).unwrap().unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].payload.len(), 0);
        assert!(chunks[0].is_last);
        assert!(chunks[0].verify_auth_tag());
    }

    #[test]
    fn write_object_missing_key_returns_none() {
        let store = MockStore::new();
        let config = TransferChunkEncoderConfig::default();
        let writer = SendStreamWriter::new(&store, config);

        let result = writer.write_object(test_key(99)).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn write_all_scans_all_keys() {
        let mut store = MockStore::new();
        let k1 = test_key(1);
        let k2 = test_key(2);
        let k3 = test_key(3);

        store.insert(k1, vec![0xAAu8; 100]);
        store.insert(k2, vec![0xBBu8; 70_000]);
        store.insert(k3, vec![0xCCu8; 256]);

        let config = TransferChunkEncoderConfig { chunk_size: 65536 };
        let writer = SendStreamWriter::new(&store, config);

        let all = writer.write_all().unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[&k1].len(), 1);
        assert_eq!(all[&k2].len(), 2);
        assert_eq!(all[&k3].len(), 1);
    }

    #[test]
    fn write_all_frames_emits_manifest_before_chunks() {
        let mut store = MockStore::new();
        let key = test_key(1);
        store.insert(key, vec![0xAAu8; 100]);

        let writer = SendStreamWriter::new_with_manifest(
            &store,
            TransferChunkEncoderConfig { chunk_size: 64 },
            manifest(),
        );
        let frames = writer.write_all_frames().unwrap();

        assert!(matches!(
            frames.first(),
            Some(SendStreamWriterFrame::LineageManifest(frame)) if frame.verify()
        ));
        assert!(frames[1..]
            .iter()
            .all(|frame| matches!(frame, SendStreamWriterFrame::ObjectChunk { .. })));
    }

    #[test]
    fn estimate_chunk_count() {
        let mut store = MockStore::new();
        let key = test_key(5);
        store.insert(key, vec![0u8; 200_000]);

        let config = TransferChunkEncoderConfig { chunk_size: 65536 };
        let writer = SendStreamWriter::new(&store, config);

        let estimate = writer.estimate_chunk_count(&key).unwrap();
        assert_eq!(estimate, 4);

        let chunks = writer.write_object(key).unwrap().unwrap();
        assert_eq!(chunks.len(), estimate);
    }

    #[test]
    fn estimate_chunk_count_missing_object() {
        let store = MockStore::new();
        let config = TransferChunkEncoderConfig::default();
        let writer = SendStreamWriter::new(&store, config);

        assert!(writer.estimate_chunk_count(&test_key(99)).is_err());
    }

    #[test]
    fn chunks_have_correct_object_id_and_total() {
        let mut store = MockStore::new();
        let key = test_key(0xAB);
        store.insert(key, vec![0xFFu8; 1000]);

        let config = TransferChunkEncoderConfig { chunk_size: 512 };
        let writer = SendStreamWriter::new(&store, config);

        let chunks = writer.write_object(key).unwrap().unwrap();
        let expected_id: [u8; 32] = key.as_bytes32();

        for c in &chunks {
            assert_eq!(c.object_id, expected_id);
            assert_eq!(c.total_chunks, chunks.len() as u32);
        }
    }

    #[test]
    fn domain_separated_tags_are_consistent() {
        let mut store = MockStore::new();
        let key = test_key(7);
        let data = b"domain consistency check".to_vec();
        store.insert(key, data);

        let config = TransferChunkEncoderConfig::default();
        let writer = SendStreamWriter::new(&store, config);

        let chunks1 = writer.write_object(key).unwrap().unwrap();
        let chunks2 = writer.write_object(key).unwrap().unwrap();

        assert_eq!(chunks1.len(), chunks2.len());
        for (c1, c2) in chunks1.iter().zip(chunks2.iter()) {
            assert_eq!(c1.auth_tag, c2.auth_tag);
        }
    }

    #[test]
    fn config_is_accessible() {
        let store = MockStore::new();
        let config = TransferChunkEncoderConfig { chunk_size: 32768 };
        let writer = SendStreamWriter::new(&store, config);
        assert_eq!(writer.config().chunk_size, 32768);
    }
}
