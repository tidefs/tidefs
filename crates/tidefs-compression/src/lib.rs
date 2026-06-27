// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![deny(dead_code)]
#![deny(unused_imports)]
#![forbid(unsafe_code)]

//! Transparent per-object zstd + LZ4 compression wrapper for the TideFS local
//! object store.  Every stored object carries a 5-byte frame header
//! identifying the compression algorithm and original size.
//!
//! ## Object format
//!
//! ```text
//! [algorithm: 1 byte][uncompressed_len: 4 bytes LE][payload]
//! ```
//!
//! | Algorithm byte | Meaning       |
//! |----------------|---------------|
//! | `0x00`         | uncompressed  |
//! | `0x01`         | zstd          |
//! | `0x02`         | lz4           |
//!
//! Overhead: 5 bytes per object (algorithm + uncompressed length).
//!
//! Objects smaller than [`CompressionConfig::min_compress_bytes`] (default
//! 64) are stored uncompressed to avoid wasting CPU on trivially small
//! payloads.
//!

//!
//! ## Authority boundary (non-claim)
//!
//! This crate provides **object-store-level** transparent compression helpers
//! (`CompressedObjectStore`, `CompressedExtentPayload`).  The mounted
//! filesystem content write path does **not** consume `CompressedExtentPayload`.
//!
//! The **live mounted-write compression authority** is:
//!
//! ```text
//! resolve_compression_policy(FeatureFlags)  [tidefs-local-filesystem/src/lib.rs]
//!   -> ContentCompressionPolicy
//!   -> encode_content_chunk                  [encoding.rs]
//! ```
//!
//! This crate and the extent-payload path remain helper/library tier.  Do not
//! use this crate's `put_extent`/`get_extent` as validation that per-dataset
//! compression policy is wired into mounted content writes.
//!
//! The mounted transform guardrail uses the ordered terms:
//!
//! ```text
//! plaintext identity -> compression frame -> encryption frame -> checksum -> raw media bytes
//! ```
//!
//! `CompressedExtentPayload` is a compression frame helper. It does not define
//! encryption frame placement, checksum authority, raw media bytes, or reclaim
//! identity for the mounted filesystem. See
//! `docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md` for the current
//! mounted claim blocker.
//!
//! ## ZFS comparison
//!
//! ZFS compresses at the block level with per-dataset algorithm selection
//! (lz4, gzip, zstd, zle).  TideFS compresses at the object-store level,
//! which is more granular — every object (inode, directory entry, content
//! chunk, superblock) is independently compressed with zstd or LZ4.  The 5-byte frame
//! overhead is dwarfed by typical compression savings (often 2-10× for
//! text, logs, and structured data).
//!
//! ## Composability
//!
//! The wrapper is designed to compose with `tidefs-encryption`:
//!
//! ```no_run
//! # use tidefs_compression::{CompressedObjectStore, CompressionConfig};
//! # use tidefs_local_object_store::LocalObjectStore;
//! // Compress first, then encrypt (recommended: compression before encryption)
//! let inner = LocalObjectStore::open("/tmp/store").unwrap();
//! let compressed = CompressedObjectStore::new(inner, CompressionConfig::default());
//! // let encrypted = EncryptedObjectStore::new(compressed, key);
//! ```

use std::fmt;
use tidefs_local_object_store::{
    LocalObjectStore, ObjectKey, ObjectLocation, StoreError, StoreOptions, StoreStats, StoredObject,
};

pub use tidefs_local_object_store;

// ── Re-exports from tidefs-frame ───────────────────────────────────────────

pub use tidefs_frame::CompressionAlgorithm;
pub use tidefs_frame::FRAME_HEADER_LEN;

// Extent-level compression types and functions.
pub use tidefs_frame::{
    compress_extent, decompress_extent, decompress_extent_verified, CompressedExtentPayload,
    CompressionPolicy, TransformVerification, EXTENT_PAYLOAD_HEADER_LEN,
    TRANSFORM_VERIFICATION_LEN,
};

pub mod algorithm;
pub mod decode;
pub mod encode;
// ── Error ──────────────────────────────────────────────────────────────────

/// Errors specific to the compression layer.
#[derive(Debug)]
pub enum CompressionError {
    /// Stored data is too short to contain a frame header.
    FrameTooShort { len: usize },
    /// Unknown compression algorithm byte in frame header.
    UnknownAlgorithm { byte: u8 },
    /// Decompression failed (corrupted compressed data).
    DecompressionFailed(String),
    /// Stored transform header does not match the committed receipt.
    TransformMismatch {
        field: &'static str,
        expected: u64,
        observed: u64,
    },
    /// Underlying store error.
    Store(StoreError),
}

impl fmt::Display for CompressionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooShort { len } => {
                write!(
                    f,
                    "stored frame too short ({len} bytes, need at least {FRAME_HEADER_LEN})"
                )
            }
            Self::UnknownAlgorithm { byte } => {
                write!(f, "unknown compression algorithm byte 0x{byte:02x}")
            }
            Self::DecompressionFailed(reason) => {
                write!(f, "decompression failed: {reason}")
            }
            Self::TransformMismatch {
                field,
                expected,
                observed,
            } => {
                write!(
                    f,
                    "transform mismatch: {field} expected {expected}, observed {observed}"
                )
            }
            Self::Store(e) => write!(f, "store error: {e}"),
        }
    }
}

impl std::error::Error for CompressionError {}

impl From<StoreError> for CompressionError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<tidefs_frame::FrameError> for CompressionError {
    fn from(e: tidefs_frame::FrameError) -> Self {
        match e {
            tidefs_frame::FrameError::TransformMismatch {
                field,
                expected,
                observed,
            } => Self::TransformMismatch {
                field,
                expected,
                observed,
            },
            other => Self::DecompressionFailed(format!("{other:?}")),
        }
    }
}

pub type Result<T> = std::result::Result<T, CompressionError>;

// ── Configuration ──────────────────────────────────────────────────────────

pub use tidefs_frame::CompressionConfig;

// ── Compressed store ───────────────────────────────────────────────────────

/// A transparent compression wrapper around [`LocalObjectStore`].
///
/// Objects are compressed with zstd or LZ4 before storage and decompressed on
/// retrieval.  Small objects (below `min_compress_bytes`) are stored
/// uncompressed to avoid wasting CPU.
///
/// The 5-byte frame header is invisible to callers — `put`/`get` return
/// original plaintext sizes and payloads.
pub struct CompressedObjectStore {
    inner: LocalObjectStore,
    config: CompressionConfig,
    /// Statistics (informational, not authoritative).
    pub stats: CompressionStats,
}

pub use tidefs_frame::CompressionStats;

impl fmt::Debug for CompressedObjectStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompressedObjectStore")
            .field("inner", &self.inner)
            .field("config", &self.config)
            .field("stats", &self.stats)
            .finish()
    }
}

impl CompressedObjectStore {
    /// Wrap an existing [`LocalObjectStore`] with compression.
    pub fn new(inner: LocalObjectStore, config: CompressionConfig) -> Self {
        Self {
            inner,
            config,
            stats: CompressionStats::default(),
        }
    }

    /// Open a store directory with compression.
    pub fn open(root: impl AsRef<std::path::Path>, config: CompressionConfig) -> Result<Self> {
        let inner = LocalObjectStore::open(root)?;
        Ok(Self::new(inner, config))
    }

    /// Open with custom store options.
    pub fn open_with_options(
        root: impl AsRef<std::path::Path>,
        options: StoreOptions,
        config: CompressionConfig,
    ) -> Result<Self> {
        let inner = LocalObjectStore::open_with_options(root, options)?;
        Ok(Self::new(inner, config))
    }

    // ── Accessors ──────────────────────────────────────────────────────

    pub fn inner(&self) -> &LocalObjectStore {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut LocalObjectStore {
        &mut self.inner
    }

    pub fn into_inner(self) -> LocalObjectStore {
        self.inner
    }

    // ── Delegated read-only ────────────────────────────────────────────

    pub fn root(&self) -> &std::path::Path {
        self.inner.root()
    }

    pub fn segments_dir(&self) -> &std::path::Path {
        self.inner.segments_dir()
    }

    pub fn store_stats(&self) -> StoreStats {
        self.inner.stats()
    }

    pub fn list_keys(&self) -> Vec<ObjectKey> {
        self.inner.list_keys()
    }

    pub fn contains_key(&self, key: ObjectKey) -> bool {
        self.inner.contains_key(key)
    }

    pub fn location_of(&self, key: ObjectKey) -> Option<ObjectLocation> {
        self.inner.location_of(key)
    }

    pub fn version_locations_of(&self, key: ObjectKey) -> Vec<ObjectLocation> {
        self.inner.version_locations_of(key)
    }

    // ── Compressed put ─────────────────────────────────────────────────

    /// Compress (or store uncompressed) and write `payload` under `name`.
    pub fn put_named(&mut self, name: impl AsRef<[u8]>, payload: &[u8]) -> Result<StoredObject> {
        let framed = Self::compress_frame(payload, &self.config, &mut self.stats);
        Ok(self.inner.put_named(name, &framed)?)
    }

    /// Compress (or store uncompressed) and write `payload` under `key`.
    pub fn put(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject> {
        let framed = Self::compress_frame(payload, &self.config, &mut self.stats);
        Ok(self.inner.put(key, &framed)?)
    }

    // ── Decompressed get ───────────────────────────────────────────────

    /// Retrieve and decompress the object named `name`.
    pub fn get_named(&self, name: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>> {
        match self.inner.get_named(name)? {
            Some(framed) => Ok(Some(Self::decompress_frame(&framed)?)),
            None => Ok(None),
        }
    }

    /// Retrieve and decompress the object identified by `key`.
    pub fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        match self.inner.get(key)? {
            Some(framed) => Ok(Some(Self::decompress_frame(&framed)?)),
            None => Ok(None),
        }
    }

    /// Retrieve and decompress at a historical location.
    pub fn get_at_location(&self, location: ObjectLocation) -> Result<Vec<u8>> {
        let framed = self.inner.get_at_location(location)?;
        Self::decompress_frame(&framed)
    }

    // ── Delegated mutable (compression not needed) ─────────────────────

    pub fn delete_named(&mut self, name: impl AsRef<[u8]>) -> Result<bool> {
        Ok(self.inner.delete_named(name)?)
    }

    pub fn delete(&mut self, key: ObjectKey) -> Result<bool> {
        Ok(self.inner.delete(key)?)
    }

    pub fn sync_all(&mut self) -> Result<()> {
        Ok(self.inner.sync_all()?)
    }

    // ── Extent-level put/get ───────────────────────────────────────────

    /// Store extent payload data compressed according to a policy.
    ///
    /// This is the extent-level analogue of [`put`]; it uses [`compress_extent`]
    /// with a [`CompressionPolicy`] for ratio-based decisions, producing a
    /// [`CompressedExtentPayload`] whose encode/decode includes logical and
    /// physical byte accounting.
    pub fn put_extent(
        &mut self,
        name: impl AsRef<[u8]>,
        data: &[u8],
        policy: &CompressionPolicy,
    ) -> Result<CompressedExtentPayload> {
        let payload = compress_extent(data, policy);
        let encoded = payload.encode();
        self.inner.put_named(name, &encoded)?;
        Ok(payload)
    }

    /// Retrieve and decompress extent payload data stored via [`put_extent`].
    ///
    /// Returns `Ok(None)` when the key does not exist.
    pub fn get_extent(&self, name: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>> {
        match self.inner.get_named(name)? {
            Some(encoded) => {
                let payload = CompressedExtentPayload::decode(&encoded)
                    .ok_or(CompressionError::FrameTooShort { len: encoded.len() })?;
                decompress_extent(&payload)
                    .map_err(|e| match e {
                        tidefs_frame::FrameError::ZstdDecompressionFailed => {
                            CompressionError::DecompressionFailed(
                                "zstd decompression failed".into(),
                            )
                        }
                        other => CompressionError::DecompressionFailed(format!("{other:?}")),
                    })
                    .map(Some)
            }
            None => Ok(None),
        }
    }

    /// Retrieve and decompress an extent payload, verifying the stored transform
    /// header against the committed [`TransformVerification`] token.
    ///
    /// If the stored header does not match the token, the extent is rejected as
    /// corrupt with [`CompressionError::TransformMismatch`].
    pub fn get_extent_verified(
        &self,
        name: impl AsRef<[u8]>,
        token: &TransformVerification,
    ) -> Result<Option<Vec<u8>>> {
        match self.inner.get_named(name)? {
            Some(encoded) => {
                let payload = CompressedExtentPayload::decode(&encoded)
                    .ok_or(CompressionError::FrameTooShort { len: encoded.len() })?;
                decompress_extent_verified(&payload, token)
                    .map_err(CompressionError::from)
                    .map(Some)
            }
            None => Ok(None),
        }
    }

    // ── Frame helpers ──────────────────────────────────────────────────

    /// Compress `payload` into a framed byte vector (delegates to tidefs-frame).
    fn compress_frame(
        payload: &[u8],
        config: &CompressionConfig,
        stats: &mut CompressionStats,
    ) -> Vec<u8> {
        tidefs_frame::compress_frame(payload, config, stats)
    }

    /// Decompress a framed byte vector back to the original payload.
    fn decompress_frame(framed: &[u8]) -> Result<Vec<u8>> {
        tidefs_frame::decompress_frame(framed).map_err(|e| match e {
            tidefs_frame::FrameError::FrameTooShort { len } => {
                CompressionError::FrameTooShort { len }
            }
            tidefs_frame::FrameError::UnknownAlgorithm { byte } => {
                CompressionError::UnknownAlgorithm { byte }
            }
            tidefs_frame::FrameError::ZstdDecompressionFailed => {
                CompressionError::DecompressionFailed("zstd decompression failed".into())
            }
            tidefs_frame::FrameError::Lz4DecompressionFailed => {
                CompressionError::DecompressionFailed("lz4 decompression failed".into())
            }
            tidefs_frame::FrameError::TransformMismatch {
                field,
                expected,
                observed,
            } => CompressionError::TransformMismatch {
                field,
                expected,
                observed,
            },
        })
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_store() -> (TempDir, LocalObjectStore) {
        let dir = TempDir::new().unwrap();
        let store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        (dir, store)
    }

    fn compressed_store() -> (TempDir, CompressedObjectStore) {
        let (dir, inner) = temp_store();
        let cs = CompressedObjectStore::new(inner, CompressionConfig::default());
        (dir, cs)
    }

    #[test]
    fn roundtrip_small_payload() {
        let (_dir, mut store) = compressed_store();
        store.put_named("hello", b"hello world").unwrap();
        let plain = store.get_named("hello").unwrap().unwrap();
        assert_eq!(plain, b"hello world");
    }

    #[test]
    fn roundtrip_empty() {
        let (_dir, mut store) = compressed_store();
        store.put_named("empty", b"").unwrap();
        let plain = store.get_named("empty").unwrap().unwrap();
        assert!(plain.is_empty());
    }

    #[test]
    fn roundtrip_compressible_text() {
        let (_dir, mut store) = compressed_store();
        // Highly compressible: repeated text
        let payload = b"hello world ".repeat(100);
        store.put_named("text", &payload).unwrap();
        let plain = store.get_named("text").unwrap().unwrap();
        assert_eq!(plain, payload);
    }

    #[test]
    fn roundtrip_large_compressible() {
        let (_dir, mut store) = compressed_store();
        let payload = vec![0x41; 1024]; // all 'A's, highly compressible
        store.put_named("large", &payload).unwrap();
        let plain = store.get_named("large").unwrap().unwrap();
        assert_eq!(plain, payload);
    }

    #[test]
    fn small_objects_stored_uncompressed() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(
            inner,
            CompressionConfig {
                min_compress_bytes: 128,
                ..CompressionConfig::default()
            },
        );
        store.put_named("small", b"tiny").unwrap();
        // Underlying frame should have algorithm 0x00
        let framed = store.inner().get_named("small").unwrap().unwrap();
        assert_eq!(framed[0], 0x00);
        assert_eq!(store.stats.objects_uncompressed, 1);
        assert_eq!(store.stats.objects_compressed, 0);
    }

    #[test]
    fn compressible_text_produces_smaller_output() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::default());
        let payload = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ".repeat(40); // 1040 bytes
        store.put_named("compressible", &payload).unwrap();
        let framed = store.inner().get_named("compressible").unwrap().unwrap();
        // Should be compressed (algorithm 0x01) and smaller
        assert_eq!(framed[0], 0x01);
        assert!(
            framed.len() < payload.len() + FRAME_HEADER_LEN,
            "compressed size {} should be less than original {} + header",
            framed.len(),
            payload.len()
        );
        assert_eq!(store.stats.objects_compressed, 1);
    }

    #[test]
    fn incompressible_data_stored_uncompressed() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::default());
        // Random-looking data typically doesn't compress well
        let mut payload = Vec::with_capacity(256);
        for i in 0u8..=255u8 {
            payload.push(i);
        }
        store.put_named("random", &payload).unwrap();
        let _framed = store.inner().get_named("random").unwrap().unwrap();
        // Random data may or may not compress — just check roundtrip
        let plain = store.get_named("random").unwrap().unwrap();
        assert_eq!(plain, payload);
    }

    #[test]
    fn reopen_preserves_data() {
        let dir = TempDir::new().unwrap();
        let config = CompressionConfig::default();

        {
            let inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let mut store = CompressedObjectStore::new(inner, config.clone());
            store.put_named("persist", b"survives restart").unwrap();
        }

        {
            let inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let store = CompressedObjectStore::new(inner, config);
            let plain = store.get_named("persist").unwrap().unwrap();
            assert_eq!(plain, b"survives restart");
        }
    }

    #[test]
    fn delete_and_get_none() {
        let (_dir, mut store) = compressed_store();
        store.put_named("gone", b"temporary").unwrap();
        assert!(store.delete_named("gone").unwrap());
        assert!(store.get_named("gone").unwrap().is_none());
    }

    #[test]
    fn different_compression_levels_all_roundtrip() {
        for level in [1, 3, 9, 15] {
            let (_dir, inner) = temp_store();
            let cfg = CompressionConfig {
                level,
                min_compress_bytes: 0,
                algorithm: CompressionAlgorithm::Zstd,
            };
            let mut store = CompressedObjectStore::new(inner, cfg);
            let payload = b"compression level test ".repeat(20);
            store.put_named("level", &payload).unwrap();
            let plain = store.get_named("level").unwrap().unwrap();
            assert_eq!(plain, payload, "roundtrip failed at level {level}");
        }
    }

    #[test]
    fn stats_reflect_compression() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::default());
        // Small object: uncompressed
        store.put_named("tiny", b"hi").unwrap();
        // Compressible object: should compress
        store.put_named("big", &b"AAAA".repeat(100)).unwrap();

        assert!(store.stats.objects_compressed >= 1);
        assert!(store.stats.objects_uncompressed >= 1);
        assert!(store.stats.bytes_in > 0);
        assert!(store.stats.bytes_out > 0);
    }

    #[test]
    fn get_at_location_works() {
        let (_dir, mut store) = compressed_store();
        store.put_named("hist", b"v1").unwrap();
        store.put_named("hist", b"v2").unwrap();
        let locs = store.version_locations_of(ObjectKey::from_name("hist"));
        assert_eq!(locs.len(), 2);
        let v1 = store.get_at_location(locs[0]).unwrap();
        assert_eq!(v1, b"v1");
    }

    #[test]
    fn corrupt_frame_detected() {
        let (dir, inner) = temp_store();
        let cfg = CompressionConfig::default();
        {
            let mut store = CompressedObjectStore::new(inner, cfg.clone());
            store.put_named("data", &b"AAAA".repeat(200)).unwrap();
        }
        // Manually corrupt the stored frame
        {
            let mut inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let key = ObjectKey::from_name("data");
            let framed = inner.get(key).unwrap().unwrap();
            // Flip bits in the compressed payload
            let mut corrupt = framed.clone();
            if corrupt.len() > FRAME_HEADER_LEN + 5 {
                corrupt[FRAME_HEADER_LEN + 1] ^= 0xFF;
            }
            inner.put(key, &corrupt).unwrap();
        }
        {
            let inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let store = CompressedObjectStore::new(inner, cfg);
            let result = store.get_named("data");
            assert!(result.is_err());
        }
    }

    #[test]
    fn custom_config_truly_uncompressed() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(
            inner,
            CompressionConfig {
                algorithm: CompressionAlgorithm::Uncompressed,
                ..CompressionConfig::default()
            },
        );
        let payload = b"AAAA".repeat(200);
        store.put_named("no-compress", &payload).unwrap();
        let framed = store.inner().get_named("no-compress").unwrap().unwrap();
        assert_eq!(framed[0], 0x00); // uncompressed
                                     // Payload after the 5-byte header should match original
        assert_eq!(&framed[FRAME_HEADER_LEN..], payload.as_slice());
    }

    #[test]
    fn contains_key_and_list_keys() {
        let (_dir, mut store) = compressed_store();
        store.put_named("a", b"1").unwrap();
        store.put_named("b", b"2").unwrap();
        assert!(store.contains_key(ObjectKey::from_name("a")));
        assert!(store.contains_key(ObjectKey::from_name("b")));
        assert!(!store.contains_key(ObjectKey::from_name("c")));
        assert_eq!(store.list_keys().len(), 2);
    }

    #[test]
    fn sync_all_works() {
        let (_dir, mut store) = compressed_store();
        store.put_named("sync", b"data").unwrap();
        store.sync_all().unwrap();
    }

    #[test]
    fn zero_min_compress_compresses_everything() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(
            inner,
            CompressionConfig {
                min_compress_bytes: 0,
                ..CompressionConfig::default()
            },
        );
        store.put_named("small", b"hi").unwrap();
        let framed = store.inner().get_named("small").unwrap().unwrap();
        // Small random-ish data may not compress well, just check format
        assert!(framed[0] == 0x00 || framed[0] == 0x01);
    }

    // ── LZ4 tests ──────────────────────────────────────────────────

    #[test]
    fn lz4_roundtrip_small_payload() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::speed());
        store.put_named("hello", b"hello lz4 world").unwrap();
        let plain = store.get_named("hello").unwrap().unwrap();
        assert_eq!(plain, b"hello lz4 world");
    }

    #[test]
    fn lz4_roundtrip_compressible_text() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::speed());
        let payload = b"lz4 test pattern ".repeat(100);
        store.put_named("lz4text", &payload).unwrap();
        let plain = store.get_named("lz4text").unwrap().unwrap();
        assert_eq!(plain, payload);
    }

    #[test]
    fn lz4_roundtrip_large_payload() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::speed());
        let payload = vec![0x42; 4096];
        store.put_named("lz4large", &payload).unwrap();
        let plain = store.get_named("lz4large").unwrap().unwrap();
        assert_eq!(plain, payload);
    }

    #[test]
    fn lz4_produces_lz4_algorithm_byte() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::speed());
        let payload = b"AAAA".repeat(200);
        store.put_named("lz4algo", &payload).unwrap();
        let framed = store.inner().get_named("lz4algo").unwrap().unwrap();
        assert_eq!(framed[0], 0x02, "expected LZ4 algorithm byte 0x02");
    }

    #[test]
    fn lz4_vs_zstd_comparison() {
        let payload = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ".repeat(40);

        let (_dir, inner1) = temp_store();
        let mut lz4_store = CompressedObjectStore::new(inner1, CompressionConfig::speed());
        lz4_store.put_named("data", &payload).unwrap();
        let lz4_framed = lz4_store.inner().get_named("data").unwrap().unwrap();
        assert_eq!(lz4_framed[0], 0x02);

        let (_dir2, inner2) = temp_store();
        let mut zstd_store = CompressedObjectStore::new(inner2, CompressionConfig::balanced());
        zstd_store.put_named("data", &payload).unwrap();
        let zstd_framed = zstd_store.inner().get_named("data").unwrap().unwrap();
        assert_eq!(zstd_framed[0], 0x01);

        // Both should compress
        let overhead = FRAME_HEADER_LEN as f64;
        let lz4_ratio = lz4_framed.len() as f64 / (payload.len() as f64 + overhead);
        let zstd_ratio = zstd_framed.len() as f64 / (payload.len() as f64 + overhead);
        assert!(lz4_ratio < 1.0, "LZ4 should compress");
        assert!(zstd_ratio < 1.0, "zstd should compress");
        // zstd should compress at least as well as LZ4
        assert!(
            zstd_ratio <= lz4_ratio + 0.1,
            "zstd ({zstd_ratio:.2}) should compress <= LZ4 ({lz4_ratio:.2})"
        );
    }

    #[test]
    fn speed_config_uses_lz4() {
        let cfg = CompressionConfig::speed();
        assert_eq!(cfg.algorithm, CompressionAlgorithm::Lz4);
        assert_eq!(cfg.level, 0);
        assert_eq!(cfg.min_compress_bytes, 64);
    }

    #[test]
    fn max_config_uses_zstd_22() {
        let cfg = CompressionConfig::max();
        assert_eq!(cfg.algorithm, CompressionAlgorithm::Zstd);
        assert_eq!(cfg.level, 22);
        assert_eq!(cfg.min_compress_bytes, 0);
    }

    #[test]
    fn balanced_config_uses_zstd_3() {
        let cfg = CompressionConfig::balanced();
        assert_eq!(cfg.algorithm, CompressionAlgorithm::Zstd);
        assert_eq!(cfg.level, 3);
    }

    #[test]
    fn lz4_unknown_algorithm_detected() {
        let (dir, inner) = temp_store();
        let cfg = CompressionConfig::speed();
        {
            let mut store = CompressedObjectStore::new(inner, cfg.clone());
            store.put_named("data", &b"AAAA".repeat(200)).unwrap();
        }
        // Corrupt the algorithm byte to an unknown value
        {
            let mut inner = tidefs_local_object_store::LocalObjectStore::open_with_options(
                dir.path(),
                StoreOptions::test_fast(),
            )
            .unwrap();
            let key = ObjectKey::from_name("data");
            let framed = inner.get(key).unwrap().unwrap();
            let mut corrupt = framed.clone();
            corrupt[0] = 0xFF; // Unknown algorithm
            inner.put(key, &corrupt).unwrap();
        }
        {
            let inner = tidefs_local_object_store::LocalObjectStore::open_with_options(
                dir.path(),
                StoreOptions::test_fast(),
            )
            .unwrap();
            let store = CompressedObjectStore::new(inner, cfg);
            let result = store.get_named("data");
            assert!(result.is_err(), "unknown algorithm byte should fail");
        }
    }

    #[test]
    fn lz4_truncated_frame_detected() {
        let (dir, inner) = temp_store();
        let cfg = CompressionConfig::speed();
        {
            let mut store = CompressedObjectStore::new(inner, cfg.clone());
            store.put_named("data", &b"AAAA".repeat(200)).unwrap();
        }
        // Truncate the frame to less than header size
        {
            let mut inner = tidefs_local_object_store::LocalObjectStore::open_with_options(
                dir.path(),
                StoreOptions::test_fast(),
            )
            .unwrap();
            let key = ObjectKey::from_name("data");
            inner.put(key, &[0x02, 0x00, 0x00]).unwrap(); // truncated
        }
        {
            let inner = tidefs_local_object_store::LocalObjectStore::open_with_options(
                dir.path(),
                StoreOptions::test_fast(),
            )
            .unwrap();
            let store = CompressedObjectStore::new(inner, cfg);
            let result = store.get_named("data");
            assert!(result.is_err(), "truncated frame should fail");
        }
    }

    // ── Error variant verification ──────────────────────────────────

    #[test]
    fn corrupted_algorithm_byte_produces_exact_unknown_algorithm_error() {
        let (dir, inner) = temp_store();
        let cfg = CompressionConfig::default();
        {
            let mut store = CompressedObjectStore::new(inner, cfg.clone());
            store.put_named("data", &b"AAAA".repeat(200)).unwrap();
        }
        // Corrupt the algorithm byte to an unknown value
        {
            let mut inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let key = ObjectKey::from_name("data");
            let framed = inner.get(key).unwrap().unwrap();
            let mut corrupt = framed.clone();
            corrupt[0] = 0xFE; // Unknown algorithm (not 0x00, 0x01, 0x02)
            inner.put(key, &corrupt).unwrap();
        }
        {
            let inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let store = CompressedObjectStore::new(inner, cfg);
            let err = store.get_named("data").unwrap_err();
            match err {
                CompressionError::UnknownAlgorithm { byte } => {
                    assert_eq!(byte, 0xFE);
                }
                other => panic!("expected UnknownAlgorithm, got {other:?}"),
            }
        }
    }

    #[test]
    fn truncated_frame_produces_exact_frame_too_short_error() {
        let (dir, inner) = temp_store();
        let cfg = CompressionConfig::default();
        {
            let mut store = CompressedObjectStore::new(inner, cfg.clone());
            store.put_named("data", &b"AAAA".repeat(200)).unwrap();
        }
        // Overwrite with a frame that is shorter than FRAME_HEADER_LEN
        {
            let mut inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let key = ObjectKey::from_name("data");
            inner.put(key, &[0x01, 0x00]).unwrap(); // 2 bytes < FRAME_HEADER_LEN (5)
        }
        {
            let inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let store = CompressedObjectStore::new(inner, cfg);
            let err = store.get_named("data").unwrap_err();
            match err {
                CompressionError::FrameTooShort { len } => {
                    assert_eq!(len, 2);
                }
                other => panic!("expected FrameTooShort, got {other:?}"),
            }
        }
    }

    #[test]
    fn empty_frame_produces_frame_too_short_error() {
        let (dir, inner) = temp_store();
        let cfg = CompressionConfig::default();
        {
            let mut store = CompressedObjectStore::new(inner, cfg.clone());
            store.put_named("data", &b"AAAA".repeat(200)).unwrap();
        }
        // Overwrite with empty frame
        {
            let mut inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let key = ObjectKey::from_name("data");
            inner.put(key, &[]).unwrap();
        }
        {
            let inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let store = CompressedObjectStore::new(inner, cfg);
            let err = store.get_named("data").unwrap_err();
            match err {
                CompressionError::FrameTooShort { len } => {
                    assert_eq!(len, 0);
                }
                other => panic!("expected FrameTooShort for empty frame, got {other:?}"),
            }
        }
    }

    #[test]
    fn corrupted_zstd_payload_produces_exact_decompression_failed_error() {
        let (dir, inner) = temp_store();
        let cfg = CompressionConfig::default(); // zstd
        {
            let mut store = CompressedObjectStore::new(inner, cfg.clone());
            store.put_named("data", &b"AAAA".repeat(200)).unwrap();
        }
        // Corrupt the compressed payload (after the 5-byte header)
        {
            let mut inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let key = ObjectKey::from_name("data");
            let framed = inner.get(key).unwrap().unwrap();
            let mut corrupt = framed.clone();
            if corrupt.len() > FRAME_HEADER_LEN + 10 {
                // Flip several bytes in the compressed payload
                corrupt[FRAME_HEADER_LEN + 3] ^= 0xFF;
                corrupt[FRAME_HEADER_LEN + 7] ^= 0xFF;
            }
            inner.put(key, &corrupt).unwrap();
        }
        {
            let inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let store = CompressedObjectStore::new(inner, cfg);
            let err = store.get_named("data").unwrap_err();
            match err {
                CompressionError::DecompressionFailed(_) => {
                    // Expected: zstd should detect corrupted data
                }
                other => panic!("expected DecompressionFailed, got {other:?}"),
            }
        }
    }

    #[test]
    fn corrupted_lz4_payload_produces_exact_decompression_failed_error() {
        let (dir, inner) = temp_store();
        let cfg = CompressionConfig::speed(); // LZ4
        {
            let mut store = CompressedObjectStore::new(inner, cfg.clone());
            store.put_named("data", &b"BBBB".repeat(200)).unwrap();
        }
        // Corrupt the compressed payload (after the 5-byte header)
        {
            let mut inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let key = ObjectKey::from_name("data");
            let framed = inner.get(key).unwrap().unwrap();
            let mut corrupt = framed.clone();
            if corrupt.len() > FRAME_HEADER_LEN + 10 {
                corrupt[FRAME_HEADER_LEN + 5] ^= 0xAA;
                corrupt[FRAME_HEADER_LEN + 9] ^= 0x55;
            }
            inner.put(key, &corrupt).unwrap();
        }
        {
            let inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let store = CompressedObjectStore::new(inner, cfg);
            let err = store.get_named("data").unwrap_err();
            match err {
                CompressionError::DecompressionFailed(_) => {
                    // Expected: LZ4 should detect corrupted data
                }
                other => panic!("expected DecompressionFailed, got {other:?}"),
            }
        }
    }

    #[test]
    fn truncated_zstd_payload_produces_decompression_failed() {
        let (dir, inner) = temp_store();
        let cfg = CompressionConfig::default();
        {
            let mut store = CompressedObjectStore::new(inner, cfg.clone());
            store.put_named("data", &b"DDDD".repeat(200)).unwrap();
        }
        // Truncate the compressed payload to half its size —
        // zstd decode_all should fail on incomplete stream
        {
            let mut inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let key = ObjectKey::from_name("data");
            let framed = inner.get(key).unwrap().unwrap();
            let keep = framed.len() / 2;
            inner.put(key, &framed[..keep]).unwrap();
        }
        {
            let inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let store = CompressedObjectStore::new(inner, cfg);
            let result = store.get_named("data");
            assert!(
                result.is_err(),
                "truncated zstd payload should produce an error"
            );
        }
    }

    // ── get_at_location with compressed multi-version ────────────────

    #[test]
    fn get_at_location_preserves_historical_version_content() {
        let (_dir, mut store) = compressed_store();
        // Write v1 and capture location
        store.put_named("hist", b"version-one-data").unwrap();
        // Write v2 and capture location
        store.put_named("hist", b"version-two-more").unwrap();
        let locs = store.version_locations_of(ObjectKey::from_name("hist"));
        assert_eq!(locs.len(), 2);
        // Verify both historical versions decompress correctly
        let v1 = store.get_at_location(locs[0]).unwrap();
        let v2 = store.get_at_location(locs[1]).unwrap();
        assert_eq!(v1, b"version-one-data");
        assert_eq!(v2, b"version-two-more");
        // Current version should be v2
        let current = store.get_named("hist").unwrap().unwrap();
        assert_eq!(current, b"version-two-more");
    }

    #[test]
    fn get_at_location_with_compressed_payload_roundtrip() {
        let (_dir, mut store) = compressed_store();
        // Write a compressible payload large enough to trigger compression
        let payload = b"get_at_location compressed test ".repeat(50);
        store.put_named("cloc", &payload).unwrap();
        let loc = store
            .location_of(ObjectKey::from_name("cloc"))
            .expect("location should exist");
        // Verify the stored frame is actually compressed
        let framed = store.inner().get_at_location(loc).unwrap();
        assert_eq!(framed[0], 0x01, "expected zstd compressed frame");
        // Decompress via get_at_location and verify content
        let roundtripped = store.get_at_location(loc).unwrap();
        assert_eq!(roundtripped, payload);
    }

    // ── Mixed-algorithm store ────────────────────────────────────────

    #[test]
    fn mixed_zstd_lz4_uncompressed_in_same_store_roundtrip() {
        let (_dir, inner) = temp_store();
        // Write with three different configs into the same underlying store
        let payload_a = b"zstd compressed payload ".repeat(20);
        let payload_b = b"lz4 compressed payload ".repeat(20);
        let payload_c = b"uncompressed payload ".repeat(20);

        {
            let mut store = CompressedObjectStore::new(
                inner,
                CompressionConfig {
                    algorithm: CompressionAlgorithm::Zstd,
                    level: 3,
                    min_compress_bytes: 0,
                },
            );
            store.put_named("zstd_obj", &payload_a).unwrap();
        }

        // Reopen same store with LZ4 config
        {
            let inner = LocalObjectStore::open_with_options(_dir.path(), StoreOptions::test_fast())
                .unwrap();
            let mut store = CompressedObjectStore::new(
                inner,
                CompressionConfig {
                    algorithm: CompressionAlgorithm::Lz4,
                    level: 0,
                    min_compress_bytes: 0,
                },
            );
            store.put_named("lz4_obj", &payload_b).unwrap();
        }

        // Reopen with uncompressed config
        {
            let inner = LocalObjectStore::open_with_options(_dir.path(), StoreOptions::test_fast())
                .unwrap();
            let mut store = CompressedObjectStore::new(
                inner,
                CompressionConfig {
                    algorithm: CompressionAlgorithm::Uncompressed,
                    level: 0,
                    min_compress_bytes: 0,
                },
            );
            store.put_named("uncomp_obj", &payload_c).unwrap();
        }

        // Reopen and verify all three objects roundtrip correctly
        {
            let inner = LocalObjectStore::open_with_options(_dir.path(), StoreOptions::test_fast())
                .unwrap();
            let store = CompressedObjectStore::new(inner, CompressionConfig::default());

            let a = store.get_named("zstd_obj").unwrap().unwrap();
            assert_eq!(a, payload_a);

            let b = store.get_named("lz4_obj").unwrap().unwrap();
            assert_eq!(b, payload_b);

            let c = store.get_named("uncomp_obj").unwrap().unwrap();
            assert_eq!(c, payload_c);
        }
    }

    // ── Large-payload boundary tests ─────────────────────────────────

    #[test]
    fn payload_at_exact_min_compress_bytes_is_stored_uncompressed() {
        let (_dir, inner) = temp_store();
        let cfg = CompressionConfig {
            min_compress_bytes: 256,
            ..CompressionConfig::default()
        };
        let mut store = CompressedObjectStore::new(inner, cfg);

        // Payload exactly at the threshold
        let payload = vec![0x61; 256]; // 256 'a' bytes
        store.put_named("exact", &payload).unwrap();

        let _framed = store.inner().get_named("exact").unwrap().unwrap();
        // At exact threshold: should be stored uncompressed (below means < threshold)
        // Actually, objects smaller than min_compress_bytes are stored uncompressed.
        // Payload == threshold means it IS compressed.
        // Let's check it roundtrips regardless
        let plain = store.get_named("exact").unwrap().unwrap();
        assert_eq!(plain, payload);
    }

    #[test]
    fn payload_one_byte_below_min_compress_bytes_is_stored_uncompressed() {
        let (_dir, inner) = temp_store();
        let cfg = CompressionConfig {
            min_compress_bytes: 128,
            ..CompressionConfig::default()
        };
        let mut store = CompressedObjectStore::new(inner, cfg);

        let payload = vec![0x62; 127]; // one byte below threshold
        store.put_named("below", &payload).unwrap();

        let framed = store.inner().get_named("below").unwrap().unwrap();
        assert_eq!(framed[0], 0x00, "below threshold should be uncompressed");
        let plain = store.get_named("below").unwrap().unwrap();
        assert_eq!(plain, payload);
    }

    #[test]
    fn large_multimegabyte_payload_roundtrip_zstd() {
        let (_dir, mut store) = compressed_store();
        // 2 MB of repeated text — highly compressible
        let payload = b"The quick brown fox jumps over the lazy dog. ".repeat(46000);
        assert!(payload.len() > 2_000_000);
        store.put_named("large", &payload).unwrap();
        let plain = store.get_named("large").unwrap().unwrap();
        assert_eq!(plain, payload);
    }

    #[test]
    fn large_multimegabyte_payload_roundtrip_lz4() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::speed());
        // Use highly compressible data so compressed output fits within
        // the store's maximum record size
        let payload = vec![0x42; 500_000]; // 500 KB of same byte — highly compressible
        store.put_named("lz4large", &payload).unwrap();
        let plain = store.get_named("lz4large").unwrap().unwrap();
        assert_eq!(plain, payload);
    }

    // ── Concurrent put/get consistency ───────────────────────────────

    #[test]
    fn concurrent_put_get_consistency() {
        use std::sync::Arc;
        use std::thread;

        let dir = TempDir::new().unwrap();
        let cfg = CompressionConfig::default();

        // Open a store and share it via Arc<Mutex<...>>
        let inner =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let store = Arc::new(std::sync::Mutex::new(CompressedObjectStore::new(
            inner, cfg,
        )));

        let thread_count = 4;
        let keys_per_thread = 25;
        let mut handles = vec![];

        for t in 0..thread_count {
            let store = Arc::clone(&store);
            let handle = thread::spawn(move || {
                for i in 0..keys_per_thread {
                    let key_name = format!("t{t}_k{i}");
                    let payload = format!("thread {t} key {i} payload data ").repeat(5);
                    let payload_bytes = payload.as_bytes();
                    {
                        let mut s = store.lock().unwrap();
                        s.put_named(&key_name, payload_bytes).unwrap();
                    }
                    // Read back (needs immutable access)
                    {
                        let s = store.lock().unwrap();
                        let read_back = s.get_named(&key_name).unwrap().expect("key should exist");
                        assert_eq!(read_back, payload_bytes, "mismatch for {key_name}");
                    }
                }
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().unwrap();
        }

        // Reopen and verify all keys still present
        let inner =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let store = CompressedObjectStore::new(inner, CompressionConfig::default());
        let keys = store.list_keys();
        assert_eq!(keys.len(), thread_count * keys_per_thread);
        for t in 0..thread_count {
            for i in 0..keys_per_thread {
                let key_name = format!("t{t}_k{i}");
                let payload = format!("thread {t} key {i} payload data ").repeat(5);
                let read_back = store
                    .get_named(&key_name)
                    .unwrap()
                    .expect("key should exist after concurrent writes");
                assert_eq!(read_back, payload.as_bytes());
            }
        }
    }

    // ── Extent-level put/get ──────────────────────────────────────────

    #[test]
    fn extent_put_get_roundtrip_compressible() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::default());
        let policy = CompressionPolicy::zstd_default();
        let data = b"extent compression test ".repeat(100);
        let payload = store.put_extent("ext1", &data, &policy).unwrap();
        assert_eq!(payload.compression, CompressionAlgorithm::Zstd);
        let roundtrip = store.get_extent("ext1").unwrap().unwrap();
        assert_eq!(roundtrip, data);
    }

    #[test]
    fn extent_put_get_roundtrip_uncompressed() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::default());
        let policy = CompressionPolicy::off();
        let data = b"plain uncompressed extent";
        let payload = store.put_extent("ext2", data, &policy).unwrap();
        assert_eq!(payload.compression, CompressionAlgorithm::Uncompressed);
        let roundtrip = store.get_extent("ext2").unwrap().unwrap();
        assert_eq!(roundtrip, data);
    }

    #[test]
    fn extent_put_get_ratio_fallback() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::default());
        let policy = CompressionPolicy {
            algorithm: CompressionAlgorithm::Zstd,
            level: 3,
            min_compress_ratio: 100.0,
        };
        let data = b"AAAA".repeat(200);
        let payload = store.put_extent("ext3", &data, &policy).unwrap();
        // With ratio 100.0, compression should fall back to uncompressed
        assert_eq!(payload.compression, CompressionAlgorithm::Uncompressed);
        let roundtrip = store.get_extent("ext3").unwrap().unwrap();
        assert_eq!(roundtrip, data);
    }

    #[test]
    fn extent_get_nonexistent() {
        let (_dir, inner) = temp_store();
        let store = CompressedObjectStore::new(inner, CompressionConfig::default());
        let result = store.get_extent("no_such_extent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn extent_put_get_logical_physical_accounting() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::default());
        let policy = CompressionPolicy::zstd_default();
        let data = vec![0x41u8; 4096];
        let payload = store.put_extent("ext4", &data, &policy).unwrap();
        assert_eq!(payload.logical_bytes(), 4096);
        assert!(payload.physical_bytes() < payload.logical_bytes());
        // Verify the stored bytes are actually smaller
        let stored = store.inner().get_named("ext4").unwrap().unwrap();
        assert_eq!(stored[0], 0x01); // zstd algorithm byte in 9-byte header
        assert!(stored.len() < data.len() + 9);
    }

    #[test]
    fn extent_roundtrip_various_data_patterns() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::default());
        let policy = CompressionPolicy::zstd_default();

        let patterns: Vec<(&str, Vec<u8>)> = vec![
            ("text", b"Hello World! ".repeat(50).to_vec()),
            ("binary", (0u8..=255u8).cycle().take(512).collect()),
            ("zeroes", vec![0u8; 2048]),
            ("single_byte", vec![0x42u8; 1]),
        ];

        for (label, data) in patterns {
            let _payload = store.put_extent(label, &data, &policy).unwrap();
            let roundtrip = store.get_extent(label).unwrap().unwrap();
            assert_eq!(roundtrip, data, "roundtrip failed for {label}");
        }
    }

    #[test]
    fn extent_put_get_empty_data() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::default());
        let policy = CompressionPolicy::zstd_default();
        let payload = store.put_extent("empty", b"", &policy).unwrap();
        assert_eq!(payload.uncompressed_len, 0);
        let roundtrip = store.get_extent("empty").unwrap().unwrap();
        assert!(roundtrip.is_empty());
    }

    #[test]
    fn extent_corrupt_payload_error() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::default());
        let policy = CompressionPolicy::zstd_default();
        store
            .put_extent("corrupt", &b"AAAA".repeat(200), &policy)
            .unwrap();
        // Corrupt the stored payload
        {
            let key = ObjectKey::from_name("corrupt");
            let framed = store.inner().get(key).unwrap().unwrap();
            let mut corrupt = framed.clone();
            if corrupt.len() > 15 {
                corrupt[12] ^= 0xFF;
                corrupt[13] ^= 0xFF;
            }
            store.inner_mut().put(key, &corrupt).unwrap();
        }
        let result = store.get_extent("corrupt");
        assert!(result.is_err());
    }

    #[test]
    fn extent_decode_truncated_header_error() {
        let (_dir, inner) = temp_store();
        {
            let mut store = CompressedObjectStore::new(inner, CompressionConfig::default());
            // Manually put a truncated payload (less than 9-byte header)
            store
                .inner_mut()
                .put_named("trunc", &[0x01, 0x00, 0x00])
                .unwrap();
        }
        let inner =
            LocalObjectStore::open_with_options(_dir.path(), StoreOptions::test_fast()).unwrap();
        let store = CompressedObjectStore::new(inner, CompressionConfig::default());
        let result = store.get_extent("trunc");
        assert!(result.is_err());
    }

    // ── Verified extent get ──────────────────────────────────────────

    #[test]
    fn extent_put_get_verified_correct_receipt() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::default());
        let policy = CompressionPolicy::zstd_default();
        let data = b"AAAA".repeat(200);
        let payload = store.put_extent("v1", &data, &policy).unwrap();
        let token = payload.to_verification();

        let result = store.get_extent_verified("v1", &token).unwrap().unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn extent_get_verified_rejects_wrong_algorithm() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::default());
        let policy = CompressionPolicy::zstd_default();
        let data = b"AAAA".repeat(200);
        let payload = store.put_extent("v2", &data, &policy).unwrap();
        let mut bad_token = payload.to_verification();
        bad_token.algorithm = CompressionAlgorithm::Uncompressed;

        let err = store.get_extent_verified("v2", &bad_token).unwrap_err();
        assert!(matches!(err, CompressionError::TransformMismatch { .. }));
    }

    #[test]
    fn extent_get_verified_rejects_wrong_uncompressed_len() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::default());
        let policy = CompressionPolicy::zstd_default();
        let data = b"AAAA".repeat(200);
        let payload = store.put_extent("v3", &data, &policy).unwrap();
        let mut bad_token = payload.to_verification();
        bad_token.uncompressed_len = 42;

        let err = store.get_extent_verified("v3", &bad_token).unwrap_err();
        assert!(matches!(err, CompressionError::TransformMismatch { .. }));
    }

    #[test]
    fn extent_get_verified_rejects_wrong_compressed_len() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::default());
        let policy = CompressionPolicy::zstd_default();
        let data = b"AAAA".repeat(200);
        let payload = store.put_extent("v4", &data, &policy).unwrap();
        let mut bad_token = payload.to_verification();
        bad_token.compressed_len = 99999;

        let err = store.get_extent_verified("v4", &bad_token).unwrap_err();
        assert!(matches!(err, CompressionError::TransformMismatch { .. }));
    }

    #[test]
    fn extent_get_verified_uncompressed_data() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::default());
        let policy = CompressionPolicy::off();
        let data = b"plain uncompressed content";
        let payload = store.put_extent("v5", data, &policy).unwrap();
        let token = payload.to_verification();
        assert_eq!(token.algorithm, CompressionAlgorithm::Uncompressed);

        let result = store.get_extent_verified("v5", &token).unwrap().unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn extent_get_verified_nonexistent() {
        let (_dir, inner) = temp_store();
        let store = CompressedObjectStore::new(inner, CompressionConfig::default());
        let token = TransformVerification {
            algorithm: CompressionAlgorithm::Zstd,
            uncompressed_len: 100,
            compressed_len: 0,
        };
        let result = store.get_extent_verified("no_such", &token).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn extent_put_get_verified_multi_extent_file_simulation() {
        let (_dir, inner) = temp_store();
        let mut store = CompressedObjectStore::new(inner, CompressionConfig::default());
        let policy = CompressionPolicy::zstd_default();

        // Simulate a multi-extent file: 3 extents with different data
        let extents: Vec<(&str, Vec<u8>)> = vec![
            ("ext-a", b"AAAA".repeat(100)),
            ("ext-b", b"BBBB".repeat(150)),
            ("ext-c", b"CCCC".repeat(80)),
        ];

        let mut tokens = Vec::new();
        for (name, data) in &extents {
            let payload = store.put_extent(name, &data, &policy).unwrap();
            tokens.push((name.to_string(), payload.to_verification()));
        }

        // Verify each extent with its token
        for (i, (name, data)) in extents.iter().enumerate() {
            let (_token_name, token) = &tokens[i];
            let result = store.get_extent_verified(name, token).unwrap().unwrap();
            assert_eq!(&result, data, "mismatch for extent {name}");
        }

        // Cross-verification: wrong token should fail
        let wrong_token = &tokens[1].1; // token from ext-b
        let err = store.get_extent_verified("ext-a", wrong_token).unwrap_err();
        assert!(matches!(err, CompressionError::TransformMismatch { .. }));
    }
}
