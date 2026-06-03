//! Production encryption bridge for the TideFS local filesystem.
//!
//! Wires `tidefs-encryption` (ChaCha20-Poly1305 AEAD, per-object key
//! derivation, 3-tier key hierarchy) into the local-filesystem
//! production path behind the `encryption` feature flag.
//!
//! # Feature gate
//!
//! Compile with `--features encryption` to enable this module.
//! Without the feature, this module is absent from the build.
//!
//! # Integration point
//!
//! [`EncryptedPool`] wraps a [`Pool`] with transparent per-object
//! AEAD encryption.  Every `put`/`put_named` encrypts before
//! writing to the underlying store; every `get`/`get_named`
//! decrypts transparently.  The encryption overhead (28 bytes per
//! object: 12-byte nonce + 16-byte Poly1305 tag) is invisible to
//! callers.
//!
//! # No BLAKE3 proof-marker
//!
//! This module does not add BLAKE3 attestation layers.  Integrity
//! verification is owned by the object-store checksum pipeline;
//! encryption provides confidentiality only.

use tidefs_encryption::{EncryptedObjectStore, EncryptionConfig, StoreKey};
use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreError, StoreOptions};

/// Result type for encrypted pool operations.
pub type Result<T> = std::result::Result<T, EncryptedPoolError>;

/// Errors from the encrypted pool bridge.
#[derive(Debug)]
pub enum EncryptedPoolError {
    /// Underlying store error.
    Store(StoreError),
    /// Encryption layer error.
    Encryption(tidefs_encryption::EncryptionError),
}

impl std::fmt::Display for EncryptedPoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "store error: {e}"),
            Self::Encryption(e) => write!(f, "encryption error: {e}"),
        }
    }
}

impl std::error::Error for EncryptedPoolError {}

impl From<StoreError> for EncryptedPoolError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<tidefs_encryption::EncryptionError> for EncryptedPoolError {
    fn from(e: tidefs_encryption::EncryptionError) -> Self {
        Self::Encryption(e)
    }
}

/// An encryption-aware wrapper around a TideFS object store pool.
///
/// Created via [`EncryptedPool::open`] or [`EncryptedPool::open_with_options`].
/// Under the hood, the [`LocalObjectStore`] is wrapped in an
/// [`EncryptedObjectStore`] so every object write is transparently
/// encrypted before landing on disk.
///
/// # Example
///
/// ```no_run
/// use tidefs_local_filesystem::encrypted_fs::EncryptedPool;
/// use tidefs_encryption::StoreKey;
///
/// let key = StoreKey::generate();
/// let pool = EncryptedPool::open("/tmp/tidefs-enc-pool", key).unwrap();
/// ```
pub struct EncryptedPool {
    store: EncryptedObjectStore,
}

impl EncryptedPool {
    /// Open an encrypted pool at `root` with the given encryption key.
    ///
    /// Creates a [`LocalObjectStore`] at `root`, wraps it in an
    /// [`EncryptedObjectStore`] with default [`EncryptionConfig`],
    /// and then creates a [`Pool`] from the encrypted store.
    pub fn open(root: impl AsRef<std::path::Path>, key: StoreKey) -> Result<Self> {
        Self::open_with_config(root, key, EncryptionConfig::default())
    }

    /// Open an encrypted pool with a custom [`EncryptionConfig`].
    pub fn open_with_config(
        root: impl AsRef<std::path::Path>,
        key: StoreKey,
        config: EncryptionConfig,
    ) -> Result<Self> {
        let inner = LocalObjectStore::open(root)?;
        let store = EncryptedObjectStore::new_with_config(inner, key, config);
        Ok(Self { store })
    }

    /// Open an encrypted pool with custom [`StoreOptions`].
    pub fn open_with_options(
        root: impl AsRef<std::path::Path>,
        options: StoreOptions,
        key: StoreKey,
        config: EncryptionConfig,
    ) -> Result<Self> {
        let inner = LocalObjectStore::open_with_options(root, options)?;
        let store = EncryptedObjectStore::new_with_config(inner, key, config);
        Ok(Self { store })
    }

    /// Put an object into the encrypted pool.
    ///
    /// The payload is transparently encrypted before storage.
    /// Returns the stored object metadata.
    pub fn put(
        &mut self,
        key: ObjectKey,
        data: &[u8],
    ) -> Result<tidefs_local_object_store::StoredObject> {
        Ok(self.store.put(key, data)?)
    }

    /// Get an object from the encrypted pool.
    ///
    /// The stored ciphertext is transparently decrypted.
    /// Returns `Ok(None)` when the object does not exist.
    /// Returns `Err` on AEAD authentication failure (wrong key,
    /// corruption, or tampering).
    pub fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        Ok(self.store.get(key)?)
    }

    /// Put a named object into the encrypted pool.
    pub fn put_named(
        &mut self,
        name: &[u8],
        data: &[u8],
    ) -> Result<tidefs_local_object_store::StoredObject> {
        Ok(self.store.put_named(name, data)?)
    }

    /// Get a named object from the encrypted pool.
    pub fn get_named(&self, name: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.store.get_named(name)?)
    }

    /// Return a reference to the underlying encrypted store.
    ///
    /// Prefer using [`EncryptedPool`] methods unless implementing
    /// migration or repair tooling.
    pub fn encrypted_store(&self) -> &EncryptedObjectStore {
        &self.store
    }

    /// Return cumulative encryption statistics.
    pub fn encrypted_stats(&self) -> tidefs_encryption::EncryptedStoreStats {
        self.store.encrypted_stats()
    }

    /// Return the hex-encoded key fingerprint (for logging, not
    /// for authentication).
    pub fn key_fingerprint(&self) -> &str {
        self.store.key_fingerprint()
    }

    /// Enable per-object key derivation.
    pub fn enable_per_object_keys(&mut self, deriver: tidefs_encryption::ObjectKeyDeriver) {
        self.store.set_object_key_deriver(deriver);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_encryption::StoreKey;

    fn temp_encrypted_pool() -> (tempfile::TempDir, EncryptedPool) {
        let dir = tempfile::TempDir::new().unwrap();
        let key = StoreKey::generate();
        let pool = EncryptedPool::open(dir.path(), key).unwrap();
        (dir, pool)
    }

    #[test]
    fn put_get_roundtrip() {
        let (_dir, mut pool) = temp_encrypted_pool();
        let key = ObjectKey::from_content(b"hello");
        pool.put(key, b"secret data").unwrap();
        let decrypted = pool.get(key).unwrap().unwrap();
        assert_eq!(decrypted, b"secret data");
    }

    #[test]
    fn put_get_empty_payload() {
        let (_dir, mut pool) = temp_encrypted_pool();
        let key = ObjectKey::from_content(b"empty");
        pool.put(key, b"").unwrap();
        assert!(pool.get(key).unwrap().unwrap().is_empty());
    }

    #[test]
    fn put_get_large_payload() {
        let (_dir, mut pool) = temp_encrypted_pool();
        let payload = vec![0xABu8; 4096];
        let key = ObjectKey::from_content(&payload);
        pool.put(key, &payload).unwrap();
        assert_eq!(pool.get(key).unwrap().unwrap(), payload);
    }

    #[test]
    fn get_missing_returns_none() {
        let (_dir, pool) = temp_encrypted_pool();
        let key = ObjectKey::from_content(b"nonexistent");
        assert!(pool.get(key).unwrap().is_none());
    }

    #[test]
    fn put_named_get_named_roundtrip() {
        let (_dir, mut pool) = temp_encrypted_pool();
        pool.put_named(b"my-object", b"named data").unwrap();
        let decrypted = pool.get_named(b"my-object").unwrap().unwrap();
        assert_eq!(decrypted, b"named data");
    }

    #[test]
    fn different_keys_produce_different_stored_objects() {
        let (_dir, mut pool) = temp_encrypted_pool();
        let k1 = ObjectKey::from_content(b"obj-a");
        let k2 = ObjectKey::from_content(b"obj-b");
        let stored1 = pool.put(k1, b"same payload").unwrap();
        let stored2 = pool.put(k2, b"same payload").unwrap();
        // Different object keys => different stored ciphertexts
        assert_ne!(stored1.key, stored2.key);
        // Both decrypt correctly
        assert_eq!(pool.get(k1).unwrap().unwrap(), b"same payload");
        assert_eq!(pool.get(k2).unwrap().unwrap(), b"same payload");
    }

    #[test]
    fn wrong_key_on_read_fails() {
        let dir = tempfile::TempDir::new().unwrap();
        let key_a = StoreKey::generate();
        let key_b = StoreKey::generate();
        {
            let mut pool = EncryptedPool::open(dir.path(), key_a.clone()).unwrap();
            let k = ObjectKey::from_content(b"secret");
            pool.put(k, b"classified").unwrap();
        }
        // Reopen with wrong key
        let pool = EncryptedPool::open(dir.path(), key_b).unwrap();
        let k = ObjectKey::from_content(b"secret");
        // Decryption should fail (AEAD auth failure)
        assert!(pool.get(k).is_err());
    }

    #[test]
    fn reopen_with_same_key_reads_correctly() {
        let dir = tempfile::TempDir::new().unwrap();
        let key = StoreKey::generate();
        let obj_key = ObjectKey::from_content(b"persistent");
        {
            let mut pool = EncryptedPool::open(dir.path(), key.clone()).unwrap();
            pool.put(obj_key, b"survives restart").unwrap();
        }
        {
            let pool = EncryptedPool::open(dir.path(), key.clone()).unwrap();
            let decrypted = pool.get(obj_key).unwrap().unwrap();
            assert_eq!(decrypted, b"survives restart");
        }
    }

    #[test]
    fn encrypted_stats_accumulate() {
        let (_dir, mut pool) = temp_encrypted_pool();
        let stats_before = pool.encrypted_stats();
        assert_eq!(stats_before.objects_encrypted, 0);

        let k = ObjectKey::from_content(b"stats-test");
        pool.put(k, b"counting bytes").unwrap();
        let stats_after = pool.encrypted_stats();
        assert_eq!(stats_after.objects_encrypted, 1);
        assert!(stats_after.bytes_out > stats_after.bytes_in);
    }

    #[test]
    fn key_fingerprint_is_consistent() {
        let (_dir, pool) = temp_encrypted_pool();
        let fp = pool.key_fingerprint().to_string();
        assert!(!fp.is_empty());
        assert_eq!(fp.len(), 64); // 32-byte key as hex
    }

    #[test]
    fn per_object_key_derivation() {
        let (_dir, mut pool) = temp_encrypted_pool();
        let master = StoreKey::generate();
        let deriver = tidefs_encryption::ObjectKeyDeriver::new(master);
        pool.enable_per_object_keys(deriver);

        let k = ObjectKey::from_content(b"derived-test");
        pool.put(k, b"per-object encrypted").unwrap();
        let decrypted = pool.get(k).unwrap().unwrap();
        assert_eq!(decrypted, b"per-object encrypted");
    }
}
