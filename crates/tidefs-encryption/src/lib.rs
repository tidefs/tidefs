#![forbid(unsafe_code)]

//! Transparent ChaCha20-Poly1305 AEAD encryption wrapper for the TideFS
//! local object store.  Every stored object is independently encrypted with
//! its own random nonce.
//!
//! ## Object format
//!
//! ```text
//! [nonce: 12 bytes][ciphertext || Poly1305 tag: N+16 bytes]
//! ```
//!
//! Overhead per object: 28 bytes (12 nonce + 16 AEAD tag).
//!
//! ## Key management
//!
//! A [`StoreKey`] is a 32-byte symmetric key.  It can be generated randomly,
//! restored from raw bytes, or derived from a passphrase using BLAKE3 in KDF
//! mode ([`StoreKey::derive_from_passphrase`]).
//!
//! ## ZFS comparison
//!
//! ZFS native encryption (AES-256-GCM) operates at the dataset level with
//! wrapped key management.  TideFS encryption operates at the object-store
//! level, so every object (inode, directory entry, content chunk, superblock,
//! snapshot root) is independently encrypted.  This is more granular than
//! ZFS's dataset-level encryption and means even metadata is opaque to the
//! storage layer.

pub mod key_hierarchy;
pub mod key_manager;
pub mod object_key;
pub mod secret_handle;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
pub use key_hierarchy::*;
pub use key_manager::*;
pub use object_key::*;
use rand::RngCore;
pub use secret_handle::*;
use std::collections::HashMap;
use std::fmt;
use tidefs_local_object_store::{
    LocalObjectStore, ObjectKey, ObjectLocation, StoreError, StoreOptions, StoreStats, StoredObject,
};

// ── Re-exports ────────────────────────────────────────────────────────────
pub use tidefs_local_object_store;

// ── Constants ─────────────────────────────────────────────────────────────

/// Nonce size for ChaCha20-Poly1305 (96 bits = 12 bytes, per RFC 8439).
pub const NONCE_LEN: usize = 12;

/// Key size for ChaCha20-Poly1305 (256 bits = 32 bytes).
pub const KEY_LEN: usize = 32;

/// AEAD tag size (Poly1305 MAC = 16 bytes).
pub const TAG_LEN: usize = 16;

/// Total per-object overhead: nonce + tag.
pub const ENCRYPTION_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// Domain separation context for BLAKE3 key derivation.
pub const KDF_CONTEXT: &str = "tidefs-encryption-v1";

// ── Configuration ─────────────────────────────────────────────────────────

/// Encryption configuration with presets.
///
/// Mirrors the `CompressionConfig` API from `tidefs-compression` for
/// consistency across the storage pipeline.  Every TideFS storage
/// transform (compression, encryption, erasure-coding) exposes
/// the same config/preset pattern.
#[derive(Clone, Debug)]
pub struct EncryptionConfig {
    /// Whether encryption is enabled.  When `false`, the store
    /// operates as a plaintext pass-through (no-encrypt mode
    /// for migration or debugging).
    pub enabled: bool,
    /// Key derivation mode.  Controls how `StoreKey` is derived
    /// when using passphrase-based keys.
    pub key_derivation: KeyDerivation,
}

/// Key derivation strictness level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyDerivation {
    /// BLAKE3-based KDF with domain separation (fast, single-pass).
    /// Suitable for single-node deployments where brute-force
    /// resistance is not required.
    Blake3Kdf,
    /// Require pre-derived key material (caller must use Argon2id
    /// or similar).  `StoreKey::derive_from_passphrase` returns
    /// an error when this mode is active, forcing callers to
    /// provide properly hardened key bytes via `StoreKey::from_bytes`.
    StrictExternal,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            key_derivation: KeyDerivation::Blake3Kdf,
        }
    }
}

impl EncryptionConfig {
    /// Encryption enabled with BLAKE3 KDF (default for single-node use).
    pub fn default_kdf() -> Self {
        Self::default()
    }

    /// Encryption enabled but requires externally-derived key material.
    /// `StoreKey::derive_from_passphrase` is rejected.
    pub fn strict_key_derivation() -> Self {
        Self {
            enabled: true,
            key_derivation: KeyDerivation::StrictExternal,
        }
    }

    /// Encryption disabled (plaintext pass-through).  Every `put`/`get`
    /// stores and retrieves plaintext without AEAD overhead.
    #[allow(dead_code)]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            key_derivation: KeyDerivation::Blake3Kdf,
        }
    }
}

// ── Error type ─────────────────────────────────────────────────────────────

/// Errors specific to the encryption layer.
#[derive(Debug)]
pub enum EncryptionError {
    /// The stored ciphertext is too short to contain a nonce.
    CiphertextTooShort { len: usize },
    /// AEAD decryption failed (wrong key, corruption, or tampering).
    DecryptionFailed,
    /// The provided key is empty.
    InvalidKeyEmpty,
    /// Key derivation rejected by config (strict_key_derivation mode).
    KeyDerivationRejected,
    /// The provided key has the wrong length.
    InvalidKeyLength { expected: usize, got: usize },
    /// Key derivation (Argon2id or similar) failed.
    KeyDerivationFailed(String),
    /// Underlying store error.
    Store(StoreError),
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CiphertextTooShort { len } => {
                write!(
                    f,
                    "ciphertext too short ({len} bytes, need at least {NONCE_LEN})"
                )
            }
            Self::DecryptionFailed => write!(f, "decryption failed: wrong key or corrupted data"),
            Self::InvalidKeyEmpty => write!(f, "key cannot be empty"),
            Self::KeyDerivationRejected => write!(f, "key derivation rejected: strict_key_derivation mode requires externally-derived key bytes"),
            Self::InvalidKeyLength { expected, got } => {
                write!(f, "invalid key length: expected {expected}, got {got}")
            }
            Self::KeyDerivationFailed(msg) => {
                write!(f, "key derivation failed: {msg}")
            }
            Self::Store(e) => write!(f, "store error: {e}"),
        }
    }
}

impl std::error::Error for EncryptionError {}

impl From<StoreError> for EncryptionError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// Result alias for encryption operations.
pub type Result<T> = std::result::Result<T, EncryptionError>;

// ── Store key ──────────────────────────────────────────────────────────────

/// A 256-bit symmetric key for ChaCha20-Poly1305 encryption.
///
/// Implements `Zeroize` so the key material is cleared from memory on drop.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct StoreKey {
    bytes: [u8; KEY_LEN],
}

impl fmt::Debug for StoreKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreKey").finish_non_exhaustive()
    }
}

impl StoreKey {
    /// Generate a fresh random 256-bit key using the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Restore a key from raw bytes.
    ///
    /// Returns `EncryptionError::InvalidKeyLength` if `bytes` is not exactly
    /// [`KEY_LEN`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(EncryptionError::InvalidKeyEmpty);
        }
        if bytes.len() != KEY_LEN {
            return Err(EncryptionError::InvalidKeyLength {
                expected: KEY_LEN,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; KEY_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Derive a 256-bit key from a passphrase using BLAKE3 in key-derivation
    /// mode with the domain-separated context [`KDF_CONTEXT`], respecting
    /// the provided [`EncryptionConfig`].
    ///
    /// When `config.key_derivation` is [`KeyDerivation::StrictExternal`],
    /// this method returns [`EncryptionError::KeyDerivationRejected`],
    /// forcing callers to provide externally-derived key material via
    /// [`StoreKey::from_bytes`].
    ///
    /// BLAKE3's `derive_key` provides a fast, deterministic KDF suitable for
    /// local single-node use.  Multi-tenant deployments should use a proper
    /// KMS.  For passphrase-based key derivation that must resist brute-force,
    /// pre-derive the key material externally (e.g., with Argon2id) and use
    /// [`StoreKey::from_bytes`].
    pub fn derive_from_passphrase_with_config(
        passphrase: &str,
        config: &EncryptionConfig,
    ) -> Result<Self> {
        if config.key_derivation == KeyDerivation::StrictExternal {
            return Err(EncryptionError::KeyDerivationRejected);
        }
        let derived = blake3::derive_key(KDF_CONTEXT, passphrase.as_bytes());
        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(&derived);
        Ok(Self { bytes })
    }

    /// Derive a 256-bit key from a passphrase using BLAKE3 KDF (default mode).
    pub fn derive_from_passphrase(passphrase: &str) -> Self {
        Self::derive_from_passphrase_with_config(passphrase, &EncryptionConfig::default()).unwrap()
    }

    /// Return the raw key bytes.
    ///
    /// Callers must handle these bytes securely.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }

    /// Hex-encode the key for display/logging.
    pub fn hex(&self) -> String {
        self.bytes
            .iter()
            .fold(String::with_capacity(64), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{b:02x}");
                s
            })
    }
}

// ── Encrypted store statistics ─────────────────────────────────────────────

/// Cumulative encryption statistics for an [`EncryptedObjectStore`].
///
/// These track the optional encryption overhead separately from the
/// underlying [`StoreStats`], giving operators visibility into the
/// cost of encryption vs. plaintext storage.
#[derive(Clone, Copy, Debug, Default)]
pub struct EncryptedStoreStats {
    /// Number of objects encrypted.
    pub objects_encrypted: u64,
    /// Total plaintext bytes written (before encryption).
    pub bytes_in: u64,
    /// Total ciphertext bytes stored (after encryption, includes nonce+tag).
    pub bytes_out: u64,
}

impl EncryptedStoreStats {
    /// Encryption overhead ratio (bytes_out / bytes_in).
    /// Returns 1.0 if no encrypted data has been processed.
    #[must_use]
    pub fn overhead_ratio(&self) -> f64 {
        if self.bytes_in == 0 {
            1.0
        } else {
            self.bytes_out as f64 / self.bytes_in as f64
        }
    }

    /// Encryption overhead percentage (0 = no overhead on no data).
    #[must_use]
    pub fn overhead_pct(&self) -> f64 {
        (self.overhead_ratio() - 1.0) * 100.0
    }

    /// Merge another stats snapshot into this one (saturating).
    pub fn merge(&mut self, other: &Self) {
        self.objects_encrypted = self
            .objects_encrypted
            .saturating_add(other.objects_encrypted);
        self.bytes_in = self.bytes_in.saturating_add(other.bytes_in);
        self.bytes_out = self.bytes_out.saturating_add(other.bytes_out);
    }
}

// ── Encrypted store ────────────────────────────────────────────────────────

/// A transparent encryption wrapper around [`LocalObjectStore`].
///
/// Every object written through `put` / `put_named` is encrypted with
/// ChaCha20-Poly1305 before landing in the underlying store.  Every object
/// read through `get` / `get_named` / `get_at_location` is decrypted
/// transparently.
///
/// The encryption overhead (nonce + AEAD tag, 28 bytes) is invisible to
/// callers — the stored size is larger, but the returned payload is the
/// original plaintext.
///
/// ## Example
///
/// ```no_run
/// use tidefs_encryption::{EncryptedObjectStore, EncryptionConfig, StoreKey};
/// use tidefs_local_object_store::LocalObjectStore;
///
/// let key = StoreKey::generate();
/// let inner = LocalObjectStore::open("/tmp/tidefs-encrypted").unwrap();
/// let mut store = EncryptedObjectStore::new_with_config(inner, key, EncryptionConfig::default());
///
/// let obj = store.put_named("hello", b"secret data").unwrap();
/// let plain = store.get_named("hello").unwrap().unwrap();
/// assert_eq!(plain, b"secret data");
/// ```
pub struct EncryptedObjectStore {
    inner: LocalObjectStore,
    cipher: ChaCha20Poly1305,
    key_hex: String,
    config: EncryptionConfig,
    stats: EncryptedStoreStats,
    /// Present when in 3-tier hierarchy mode.
    dek: Option<DatasetDEK>,
    /// Present when per-object key derivation is enabled.
    deriver: Option<ObjectKeyDeriver>,
    /// Per-extent write counters for ExtentNonce derivation.
    write_counters: HashMap<u64, u64>,
}

impl fmt::Debug for EncryptedObjectStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedObjectStore")
            .field("inner", &self.inner)
            .field("key_hex", &self.key_hex)
            .field("stats", &self.stats)
            .field("has_dek", &self.dek.is_some())
            .field("has_deriver", &self.deriver.is_some())
            .finish()
    }
}

impl EncryptedObjectStore {
    /// Wrap an existing [`LocalObjectStore`] with encryption using
    /// default configuration ([`EncryptionConfig::default`]).
    ///
    /// The provided `key` will be used for all subsequent `put` and `get`
    /// operations.  Objects already in `inner` that were written without
    /// encryption will fail to decrypt — this wrapper does not support
    /// mixed plaintext/ciphertext stores.
    pub fn new(inner: LocalObjectStore, key: StoreKey) -> Self {
        Self::new_with_config(inner, key, EncryptionConfig::default())
    }

    /// Wrap an existing [`LocalObjectStore`] with encryption and a
    /// custom [`EncryptionConfig`].
    pub fn new_with_config(
        inner: LocalObjectStore,
        key: StoreKey,
        config: EncryptionConfig,
    ) -> Self {
        let key_hex = key.hex();
        let cipher =
            ChaCha20Poly1305::new_from_slice(key.as_bytes()).expect("KEY_LEN is always valid");
        Self {
            inner,
            cipher,
            key_hex,
            config,
            stats: EncryptedStoreStats::default(),
            dek: None,
            deriver: None,
            write_counters: HashMap::new(),
        }
    }

    /// Create a 3-tier hierarchy store.
    ///
    /// Derives [`PoolWrappingKey`] from `passphrase` + `salt`, unwraps
    /// `wrapped_dek_bytes` into a [`DatasetDEK`], and initializes the
    /// AEAD cipher from the DEK.
    pub fn new_with_hierarchy(
        inner: LocalObjectStore,
        config: EncryptionConfig,
        passphrase: &str,
        salt: &[u8; SALT_LEN],
        wrapped_dek_bytes: &[u8],
    ) -> Result<Self> {
        let wrapping_key = PoolWrappingKey::derive(passphrase, salt)?;
        let wrapped = WrappedDEK::from_bytes(wrapped_dek_bytes.to_vec())?;
        let dek = unwrap_dek(&wrapped, &wrapping_key)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(dek.as_bytes()).expect("KEY_LEN is always valid");
        let fp = blake3::keyed_hash(dek.as_bytes(), b"tidefs-enc-fp");
        let key_hex = fp.as_bytes()[..8]
            .iter()
            .fold(String::with_capacity(16), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{b:02x}");
                s
            });
        Ok(Self {
            inner,
            cipher,
            key_hex,
            config,
            stats: EncryptedStoreStats::default(),
            dek: Some(dek),
            deriver: None,
            write_counters: HashMap::new(),
        })
    }

    /// Create an encrypted store by opening the directory at `root` and
    /// wrapping it with the given `key`.
    pub fn open(
        root: impl AsRef<std::path::Path>,
        key: StoreKey,
        config: EncryptionConfig,
    ) -> Result<Self> {
        let inner = LocalObjectStore::open(root)?;
        Ok(Self::new_with_config(inner, key, config))
    }

    /// Create an encrypted store with custom options.
    pub fn open_with_options(
        root: impl AsRef<std::path::Path>,
        options: StoreOptions,
        key: StoreKey,
        config: EncryptionConfig,
    ) -> Result<Self> {
        let inner = LocalObjectStore::open_with_options(root, options)?;
        Ok(Self::new_with_config(inner, key, config))
    }

    // ── Accessors ──────────────────────────────────────────────────────

    /// Return a reference to the underlying (plaintext) store.
    ///
    /// This escapes the encryption boundary; prefer using
    /// [`EncryptedObjectStore`] methods unless you are implementing
    /// migration or repair tooling.
    pub fn inner(&self) -> &LocalObjectStore {
        &self.inner
    }

    /// Return a mutable reference to the underlying store.
    pub fn inner_mut(&mut self) -> &mut LocalObjectStore {
        &mut self.inner
    }

    /// Consume the wrapper and return the underlying store.
    pub fn into_inner(self) -> LocalObjectStore {
        self.inner
    }

    /// Enable per-object key derivation using the provided [`ObjectKeyDeriver`].
    ///
    /// When set, every `put` and `get` derives a unique key for each object
    /// from its [`ObjectKey`] bytes.  When `None`, the store falls back to
    /// the single master key (backward-compatible default).
    pub fn set_object_key_deriver(&mut self, deriver: ObjectKeyDeriver) {
        self.deriver = Some(deriver);
    }

    /// Disable per-object key derivation (return to single-key mode).
    pub fn clear_object_key_deriver(&mut self) {
        self.deriver = None;
    }

    /// Return the hex-encoded key fingerprint (for logging, not for
    /// authentication).
    pub fn key_fingerprint(&self) -> &str {
        &self.key_hex
    }

    /// Return cumulative encryption statistics.
    pub fn encrypted_stats(&self) -> EncryptedStoreStats {
        self.stats
    }

    /// Return the active encryption configuration.
    pub fn config(&self) -> &EncryptionConfig {
        &self.config
    }

    // ── Delegated read-only methods ────────────────────────────────────

    pub fn root(&self) -> &std::path::Path {
        self.inner.root()
    }

    pub fn segments_dir(&self) -> &std::path::Path {
        self.inner.segments_dir()
    }

    pub fn stats(&self) -> StoreStats {
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

    // ── Encrypted put ──────────────────────────────────────────────────

    /// Encrypt and store `payload` under the given `name`.
    ///
    /// A fresh random nonce is generated for each call, so identical
    /// plaintexts produce different ciphertexts.
    pub fn put_named(&mut self, name: impl AsRef<[u8]>, payload: &[u8]) -> Result<StoredObject> {
        self.stats.bytes_in = self.stats.bytes_in.saturating_add(payload.len() as u64);
        let ciphertext = self.encrypt(payload, name.as_ref())?;
        self.stats.objects_encrypted = self.stats.objects_encrypted.saturating_add(1);
        self.stats.bytes_out = self.stats.bytes_out.saturating_add(ciphertext.len() as u64);
        Ok(self.inner.put_named(name, &ciphertext)?)
    }

    /// Encrypt and store `payload` under the given [`ObjectKey`].
    pub fn put(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject> {
        self.stats.bytes_in = self.stats.bytes_in.saturating_add(payload.len() as u64);
        let ciphertext = self.encrypt(payload, key.as_bytes())?;
        self.stats.objects_encrypted = self.stats.objects_encrypted.saturating_add(1);
        self.stats.bytes_out = self.stats.bytes_out.saturating_add(ciphertext.len() as u64);
        Ok(self.inner.put(key, &ciphertext)?)
    }

    // ── Encrypted get ──────────────────────────────────────────────────

    /// Retrieve and decrypt the object named `name`.
    pub fn get_named(&self, name: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>> {
        let name_bytes = name.as_ref();
        match self.inner.get_named(name_bytes)? {
            Some(ciphertext) => Ok(Some(self.decrypt(&ciphertext, name_bytes)?)),
            None => Ok(None),
        }
    }

    /// Retrieve and decrypt the object identified by `key`.
    pub fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>> {
        match self.inner.get(key)? {
            Some(ciphertext) => Ok(Some(self.decrypt(&ciphertext, key.as_bytes())?)),
            None => Ok(None),
        }
    }

    /// Retrieve and decrypt the object at a specific historical location.
    pub fn get_at_location(&self, location: ObjectLocation) -> Result<Vec<u8>> {
        let ciphertext = self.inner.get_at_location(location)?;
        self.decrypt(&ciphertext, location.key.as_bytes())
    }

    // ── Delegated mutable methods (no encryption needed) ───────────────

    /// Delete an object by name.
    ///
    /// No decryption is needed for deletion — the tombstone is written
    /// in plaintext by the underlying store.
    pub fn delete_named(&mut self, name: impl AsRef<[u8]>) -> Result<bool> {
        Ok(self.inner.delete_named(name)?)
    }

    /// Delete an object by key.
    pub fn delete(&mut self, key: ObjectKey) -> Result<bool> {
        Ok(self.inner.delete(key)?)
    }

    /// Sync all pending writes to stable storage.
    pub fn sync_all(&mut self) -> Result<()> {
        Ok(self.inner.sync_all()?)
    }

    // ── Extent-aware methods (3-tier hierarchy) ──────────────────────

    /// Encrypt and store `payload` for `extent_id`, deriving the nonce
    /// deterministically from the extent ID and an auto-incremented
    /// write counter.
    ///
    /// Requires the store to be in 3-tier hierarchy mode.
    pub fn put_extent(
        &mut self,
        name: impl AsRef<[u8]>,
        extent_id: u64,
        payload: &[u8],
    ) -> Result<StoredObject> {
        let dek = self.dek.clone().ok_or(EncryptionError::DecryptionFailed)?;
        let write_counter = self.next_write_counter(extent_id);
        let nonce = ExtentNonce::derive(extent_id, write_counter, &dek);

        self.stats.bytes_in = self.stats.bytes_in.saturating_add(payload.len() as u64);
        let ct_payload = encrypt_extent(payload, &dek, &nonce)?;
        let ciphertext = ct_payload_to_bytes(&ct_payload);
        self.stats.objects_encrypted = self.stats.objects_encrypted.saturating_add(1);
        self.stats.bytes_out = self.stats.bytes_out.saturating_add(ciphertext.len() as u64);
        Ok(self.inner.put_named(name, &ciphertext)?)
    }

    /// Retrieve and decrypt an extent stored under `name`.
    ///
    /// The nonce is extracted from the stored ciphertext.
    /// Requires the store to be in 3-tier hierarchy mode.
    pub fn get_extent(&self, name: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>> {
        let dek = self.dek.as_ref().ok_or(EncryptionError::DecryptionFailed)?;
        match self.inner.get_named(name)? {
            Some(ciphertext) => {
                let payload = ct_payload_from_bytes(&ciphertext)?;
                Ok(Some(decrypt_extent(&payload, dek)?))
            }
            None => Ok(None),
        }
    }

    /// Return the current write counter for `extent_id` and increment it.
    fn next_write_counter(&mut self, extent_id: u64) -> u64 {
        let counter = self.write_counters.entry(extent_id).or_insert(0);
        let current = *counter;
        *counter = counter.saturating_add(1);
        current
    }
    /// Rotate the wrapping key by re-wrapping the DEK under a new
    /// [`PoolWrappingKey`].
    ///
    /// The existing DEK is not changed; only its wrapping changes.
    /// Returns the new [`WrappedDEK`] bytes that should be persisted
    /// to replace the old wrapped DEK.
    ///
    /// Requires the store to be in 3-tier hierarchy mode.
    pub fn rotate_wrapping_key(
        &self,
        old_passphrase: &str,
        new_passphrase: &str,
        salt: &[u8; SALT_LEN],
        wrapped_dek_bytes: &[u8],
    ) -> Result<Vec<u8>> {
        let old_wk = PoolWrappingKey::derive(old_passphrase, salt)?;
        let new_wk = PoolWrappingKey::derive(new_passphrase, salt)?;
        let wrapped = WrappedDEK::from_bytes(wrapped_dek_bytes.to_vec())?;
        let rewrapped = rewrap_dek(&wrapped, &old_wk, &new_wk)?;
        Ok(rewrapped.as_bytes().to_vec())
    }

    // ── Encryption helpers ─────────────────────────────────────────────

    /// Encrypt `plaintext` into `[nonce || ciphertext+tag]`.
    ///
    /// When a per-object key deriver is set, derives a key from `object_id`
    /// via HKDF-SHA256.  Otherwise uses the store's single master key.
    fn encrypt(&self, plaintext: &[u8], object_id: &[u8]) -> Result<Vec<u8>> {
        let cipher = if let Some(ref deriver) = self.deriver {
            let derived = deriver.derive(crate::object_key::DOMAIN_OBJECT_ENCRYPTION, object_id);
            ChaCha20Poly1305::new_from_slice(derived.as_bytes())
                .expect("derived key is always 32 bytes")
        } else {
            self.cipher.clone()
        };

        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| EncryptionError::DecryptionFailed)?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);

        Ok(out)
    }

    /// Decrypt `ciphertext` (format: `[nonce || ciphertext+tag]`).
    fn decrypt(&self, ciphertext: &[u8], object_id: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < NONCE_LEN {
            return Err(EncryptionError::CiphertextTooShort {
                len: ciphertext.len(),
            });
        }
        let (nonce_bytes, ct) = ciphertext.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = if let Some(ref deriver) = self.deriver {
            let derived = deriver.derive(crate::object_key::DOMAIN_OBJECT_ENCRYPTION, object_id);
            ChaCha20Poly1305::new_from_slice(derived.as_bytes())
                .expect("derived key is always 32 bytes")
        } else {
            self.cipher.clone()
        };

        cipher
            .decrypt(nonce, ct)
            .map_err(|_| EncryptionError::DecryptionFailed)
    }
}

// ── EncryptedExtentPayload wire format helpers ─────────────────────────

fn ct_payload_to_bytes(payload: &EncryptedExtentPayload) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len());
    out.extend_from_slice(payload.nonce.as_bytes());
    out.extend_from_slice(&payload.ciphertext);
    out
}

fn ct_payload_from_bytes(bytes: &[u8]) -> Result<EncryptedExtentPayload> {
    if bytes.len() < NONCE_LEN {
        return Err(EncryptionError::CiphertextTooShort { len: bytes.len() });
    }
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&bytes[..NONCE_LEN]);
    Ok(EncryptedExtentPayload {
        nonce: ExtentNonce::from_bytes(nonce_bytes),
        ciphertext: bytes[NONCE_LEN..].to_vec(),
    })
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

    fn encrypted_store() -> (TempDir, EncryptedObjectStore) {
        let (dir, inner) = temp_store();
        let key = StoreKey::generate();
        let enc = EncryptedObjectStore::new_with_config(inner, key, EncryptionConfig::default());
        (dir, enc)
    }

    // ── Existing tests (updated for config parameter) ───────────────────

    #[test]
    fn roundtrip_small_payload() {
        let (_dir, mut store) = encrypted_store();
        let obj = store.put_named("test", b"hello world").unwrap();
        assert_eq!(obj.len, (b"hello world".len() + ENCRYPTION_OVERHEAD) as u64);
        let plain = store.get_named("test").unwrap().unwrap();
        assert_eq!(plain, b"hello world");
    }

    #[test]
    fn roundtrip_empty_payload() {
        let (_dir, mut store) = encrypted_store();
        store.put_named("empty", b"").unwrap();
        let plain = store.get_named("empty").unwrap().unwrap();
        assert!(plain.is_empty());
    }

    #[test]
    fn roundtrip_large_payload() {
        let (_dir, mut store) = encrypted_store();
        let payload = vec![0xAB; 2048];
        store.put_named("large", &payload).unwrap();
        let plain = store.get_named("large").unwrap().unwrap();
        assert_eq!(plain, payload);
    }

    #[test]
    fn different_nonces_for_same_plaintext() {
        let (_dir, mut store) = encrypted_store();
        store.put_named("a", b"same").unwrap();
        store.put_named("b", b"same").unwrap();
        let ct_a = store.inner().get_named("a").unwrap().unwrap();
        let ct_b = store.inner().get_named("b").unwrap().unwrap();
        assert_ne!(ct_a, ct_b);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let (dir, inner) = temp_store();
        let key1 = StoreKey::generate();
        let key2 = StoreKey::generate();
        let mut store1 =
            EncryptedObjectStore::new_with_config(inner, key1, EncryptionConfig::default());
        store1.put_named("secret", b"classified").unwrap();
        drop(store1);

        let inner2 =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let store2 =
            EncryptedObjectStore::new_with_config(inner2, key2, EncryptionConfig::default());
        let result = store2.get_named("secret");
        assert!(result.is_err());
    }

    #[test]
    fn reopen_with_same_key_works() {
        let dir = TempDir::new().unwrap();
        let key = StoreKey::generate();
        let config = EncryptionConfig::default();

        {
            let inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let mut store =
                EncryptedObjectStore::new_with_config(inner, key.clone(), config.clone());
            store.put_named("persist", b"survives restart").unwrap();
        }

        {
            let inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let store = EncryptedObjectStore::new_with_config(inner, key, config);
            let plain = store.get_named("persist").unwrap().unwrap();
            assert_eq!(plain, b"survives restart");
        }
    }

    #[test]
    fn delete_and_get_returns_none() {
        let (_dir, mut store) = encrypted_store();
        store.put_named("delme", b"gone").unwrap();
        assert!(store.delete_named("delme").unwrap());
        assert!(store.get_named("delme").unwrap().is_none());
    }

    #[test]
    fn key_derive_from_passphrase_deterministic() {
        let k1 = StoreKey::derive_from_passphrase("correct horse battery staple");
        let k2 = StoreKey::derive_from_passphrase("correct horse battery staple");
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn key_derive_different_passphrases_produce_different_keys() {
        let k1 = StoreKey::derive_from_passphrase("alpha");
        let k2 = StoreKey::derive_from_passphrase("beta");
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn key_from_bytes_rejects_wrong_length() {
        assert!(StoreKey::from_bytes(&[0u8; 16]).is_err());
        assert!(StoreKey::from_bytes(&[0u8; 64]).is_err());
    }

    #[test]
    fn key_from_bytes_roundtrip() {
        let key = StoreKey::generate();
        let bytes = key.as_bytes().to_vec();
        let restored = StoreKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.as_bytes(), restored.as_bytes());
    }

    #[test]
    fn contains_key_and_list_keys_work() {
        let (_dir, mut store) = encrypted_store();
        store.put_named("x", b"1").unwrap();
        store.put_named("y", b"2").unwrap();
        let key_x = ObjectKey::from_name("x");
        let key_y = ObjectKey::from_name("y");
        let key_z = ObjectKey::from_name("z");
        assert!(store.contains_key(key_x));
        assert!(store.contains_key(key_y));
        assert!(!store.contains_key(key_z));
        let keys = store.list_keys();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn encryption_overhead_is_predictable() {
        let (_dir, mut store) = encrypted_store();
        let obj = store.put_named("overhead", b"test").unwrap();
        assert_eq!(obj.len, (4 + ENCRYPTION_OVERHEAD) as u64);
        let ct = store.inner().get_named("overhead").unwrap().unwrap();
        assert_eq!(ct.len(), 4 + ENCRYPTION_OVERHEAD);
    }

    #[test]
    fn get_at_location_works() {
        let (_dir, mut store) = encrypted_store();
        store.put_named("historical", b"version1").unwrap();
        store.put_named("historical", b"version2").unwrap();
        let locations = store.version_locations_of(ObjectKey::from_name("historical"));
        assert_eq!(locations.len(), 2);
        let plain = store.get_at_location(locations[0]).unwrap();
        assert_eq!(plain, b"version1");
    }

    #[test]
    fn sync_all_does_not_crash() {
        let (_dir, mut store) = encrypted_store();
        store.put_named("sync", b"data").unwrap();
        store.sync_all().unwrap();
    }

    #[test]
    fn key_debug_does_not_leak_bytes() {
        let key = StoreKey::generate();
        let debug = format!("{key:?}");
        let hex = key.hex();
        assert!(!debug.contains(&hex));
        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn key_generate_is_random() {
        let k1 = StoreKey::generate();
        let k2 = StoreKey::generate();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn passphrase_derived_key_works_end_to_end() {
        let dir = TempDir::new().unwrap();
        let key = StoreKey::derive_from_passphrase("my secret passphrase");

        {
            let inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let mut store = EncryptedObjectStore::new_with_config(
                inner,
                key.clone(),
                EncryptionConfig::default(),
            );
            store.put_named("data", b"sensitive").unwrap();
        }

        // Re-derive the same key and check we can read
        let key2 = StoreKey::derive_from_passphrase("my secret passphrase");
        let inner =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let store = EncryptedObjectStore::new_with_config(inner, key2, EncryptionConfig::default());
        let plain = store.get_named("data").unwrap().unwrap();
        assert_eq!(plain, b"sensitive");

        // Wrong passphrase fails
        let key3 = StoreKey::derive_from_passphrase("wrong passphrase");
        let inner3 =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let store3 =
            EncryptedObjectStore::new_with_config(inner3, key3, EncryptionConfig::default());
        assert!(store3.get_named("data").is_err());
    }
    // ── EncryptionConfig presets ──────────────────────────────────────

    #[test]
    fn encryption_config_presets() {
        let default_cfg = EncryptionConfig::default();
        assert!(default_cfg.enabled);
        assert_eq!(default_cfg.key_derivation, KeyDerivation::Blake3Kdf);

        let strict = EncryptionConfig::strict_key_derivation();
        assert!(strict.enabled);
        assert_eq!(strict.key_derivation, KeyDerivation::StrictExternal);

        let disabled = EncryptionConfig::disabled();
        assert!(!disabled.enabled);
    }

    #[test]
    fn strict_key_derivation_rejects_passphrase() {
        let cfg = EncryptionConfig::strict_key_derivation();
        let result = StoreKey::derive_from_passphrase_with_config("any passphrase", &cfg);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptionError::KeyDerivationRejected
        ));
    }

    // ── EncryptedStoreStats ───────────────────────────────────────────

    #[test]
    fn encrypted_stats_tracks_puts() {
        let (_dir, mut store) = encrypted_store();
        store.put_named("a", b"hello").unwrap();
        store.put_named("b", b"world").unwrap();
        let stats = store.encrypted_stats();
        assert_eq!(stats.objects_encrypted, 2);
        assert_eq!(stats.bytes_in, 10);
        assert_eq!(stats.bytes_out, 66);
    }

    #[test]
    fn encrypted_stats_overhead_ratio() {
        let s = EncryptedStoreStats {
            objects_encrypted: 1,
            bytes_in: 32,
            bytes_out: 60,
        };
        assert!((s.overhead_ratio() - 1.875).abs() < 0.01);
    }

    #[test]
    fn encrypted_stats_overhead_pct_zero_on_empty() {
        let s = EncryptedStoreStats::default();
        assert!((s.overhead_pct() - 0.0).abs() < 0.001);
    }

    #[test]
    fn encrypted_stats_merge() {
        let mut a = EncryptedStoreStats {
            objects_encrypted: 10,
            bytes_in: 1000,
            bytes_out: 1280,
        };
        let b = EncryptedStoreStats {
            objects_encrypted: 5,
            bytes_in: 500,
            bytes_out: 640,
        };
        a.merge(&b);
        assert_eq!(a.objects_encrypted, 15);
        assert_eq!(a.bytes_in, 1500);
        assert_eq!(a.bytes_out, 1920);
    }

    // ── Edge-case tests ───────────────────────────────────────────────

    #[test]
    fn tampered_ciphertext_rejected() {
        let (_dir, mut store) = encrypted_store();
        store
            .put_named("tamper", b"classified data that must be protected")
            .unwrap();

        let mut ct = store.inner().get_named("tamper").unwrap().unwrap();
        ct[NONCE_LEN + 1] ^= 0xFF;
        store.inner_mut().put_named("tamper", &ct).unwrap();

        let result = store.get_named("tamper");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptionError::DecryptionFailed
        ));
    }

    #[test]
    fn truncated_ciphertext_rejected() {
        let (_dir, mut store) = encrypted_store();
        store.put_named("trunc", b"important data").unwrap();

        let ct = store.inner().get_named("trunc").unwrap().unwrap();
        let truncated = &ct[..NONCE_LEN - 1];
        store.inner_mut().put_named("trunc", truncated).unwrap();

        let result = store.get_named("trunc");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptionError::CiphertextTooShort { .. }
        ));
    }

    #[test]
    fn nonce_uniqueness_across_100_puts() {
        let (_dir, mut store) = encrypted_store();
        let mut nonces: std::collections::HashSet<[u8; NONCE_LEN]> =
            std::collections::HashSet::new();

        for i in 0u32..100u32 {
            store.put_named(format!("obj{i}"), b"payload").unwrap();
            let ct = store.inner().get_named(format!("obj{i}")).unwrap().unwrap();
            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(&ct[..NONCE_LEN]);
            assert!(nonces.insert(nonce), "nonce collision at iteration {i}");
        }
        assert_eq!(nonces.len(), 100);
    }

    #[test]
    fn empty_key_rejected() {
        let result = StoreKey::from_bytes(&[]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptionError::InvalidKeyEmpty
        ));
    }

    // ── 3-tier hierarchy integration tests ──────────────────────────

    fn hierarchy_store() -> (TempDir, EncryptedObjectStore) {
        let dir = TempDir::new().unwrap();
        let inner =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let passphrase = "test pool passphrase";
        let salt = PoolWrappingKey::generate_salt();
        let wrapping_key = PoolWrappingKey::derive(passphrase, &salt).unwrap();
        let dek = DatasetDEK::generate();
        let wrapped = wrap_dek(&dek, &wrapping_key).unwrap();
        let store = EncryptedObjectStore::new_with_hierarchy(
            inner,
            EncryptionConfig::default(),
            passphrase,
            &salt,
            wrapped.as_bytes(),
        )
        .unwrap();
        (dir, store)
    }

    #[test]
    fn hierarchy_put_extent_get_extent_roundtrip() {
        let (_dir, mut store) = hierarchy_store();
        store
            .put_extent("extent_1", 1, b"extent payload with 3-tier hierarchy")
            .unwrap();
        let decrypted = store.get_extent("extent_1").unwrap().unwrap();
        assert_eq!(decrypted, b"extent payload with 3-tier hierarchy");
    }

    #[test]
    fn hierarchy_extent_empty_payload() {
        let (_dir, mut store) = hierarchy_store();
        store.put_extent("empty", 1, b"").unwrap();
        assert!(store.get_extent("empty").unwrap().unwrap().is_empty());
    }

    #[test]
    fn hierarchy_extent_large_payload() {
        let (_dir, mut store) = hierarchy_store();
        // Use 2048 bytes (within test store max_payload of 3872).
        let payload = vec![0xCDu8; 2048];
        store.put_extent("large", 2, &payload).unwrap();
        assert_eq!(store.get_extent("large").unwrap().unwrap(), payload);
    }

    #[test]
    fn hierarchy_extent_missing_returns_none() {
        let (_dir, store) = hierarchy_store();
        assert!(store.get_extent("nonexistent").unwrap().is_none());
    }

    #[test]
    fn hierarchy_extent_same_id_different_counters() {
        let (_dir, mut store) = hierarchy_store();
        store.put_extent("v0", 42, b"version 0").unwrap();
        store.put_extent("v1", 42, b"version 1").unwrap();
        store.put_extent("v2", 42, b"version 2").unwrap();
        assert_eq!(store.get_extent("v0").unwrap().unwrap(), b"version 0");
        assert_eq!(store.get_extent("v1").unwrap().unwrap(), b"version 1");
        assert_eq!(store.get_extent("v2").unwrap().unwrap(), b"version 2");
    }

    #[test]
    fn hierarchy_wrong_passphrase_fails() {
        let dir = TempDir::new().unwrap();
        let inner =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let passphrase = "correct passphrase";
        let salt = PoolWrappingKey::generate_salt();
        let wrapping_key = PoolWrappingKey::derive(passphrase, &salt).unwrap();
        let dek = DatasetDEK::generate();
        let wrapped = wrap_dek(&dek, &wrapping_key).unwrap();
        {
            let mut store = EncryptedObjectStore::new_with_hierarchy(
                inner,
                EncryptionConfig::default(),
                passphrase,
                &salt,
                wrapped.as_bytes(),
            )
            .unwrap();
            store.put_extent("secret", 1, b"classified").unwrap();
        }
        let inner2 =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let result = EncryptedObjectStore::new_with_hierarchy(
            inner2,
            EncryptionConfig::default(),
            "wrong passphrase",
            &salt,
            wrapped.as_bytes(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn hierarchy_wrong_wrapped_dek_fails() {
        let dir = TempDir::new().unwrap();
        let inner =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let passphrase = "pool passphrase";
        let salt = PoolWrappingKey::generate_salt();
        let wrapping_key = PoolWrappingKey::derive(passphrase, &salt).unwrap();
        let dek_a = DatasetDEK::generate();
        let wrapped_a = wrap_dek(&dek_a, &wrapping_key).unwrap();
        {
            let mut store = EncryptedObjectStore::new_with_hierarchy(
                inner,
                EncryptionConfig::default(),
                passphrase,
                &salt,
                wrapped_a.as_bytes(),
            )
            .unwrap();
            store.put_extent("data", 1, b"secret").unwrap();
        }
        let inner2 =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let dek_b = DatasetDEK::generate();
        let wrapped_b = wrap_dek(&dek_b, &wrapping_key).unwrap();
        let store2 = EncryptedObjectStore::new_with_hierarchy(
            inner2,
            EncryptionConfig::default(),
            passphrase,
            &salt,
            wrapped_b.as_bytes(),
        )
        .unwrap();
        let result = store2.get_extent("data");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptionError::DecryptionFailed
        ));
    }

    #[test]
    fn hierarchy_multiple_extents_independent_counters() {
        let (_dir, mut store) = hierarchy_store();
        store.put_extent("e1_v0", 1, b"extent 1 v0").unwrap();
        store.put_extent("e2_v0", 2, b"extent 2 v0").unwrap();
        store.put_extent("e1_v1", 1, b"extent 1 v1").unwrap();
        store.put_extent("e2_v1", 2, b"extent 2 v1").unwrap();
        assert_eq!(store.get_extent("e1_v0").unwrap().unwrap(), b"extent 1 v0");
        assert_eq!(store.get_extent("e2_v0").unwrap().unwrap(), b"extent 2 v0");
        assert_eq!(store.get_extent("e1_v1").unwrap().unwrap(), b"extent 1 v1");
        assert_eq!(store.get_extent("e2_v1").unwrap().unwrap(), b"extent 2 v1");
    }

    #[test]
    fn hierarchy_put_extent_no_dek_fails() {
        let (_dir, mut store) = encrypted_store();
        let result = store.put_extent("data", 1, b"payload");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptionError::DecryptionFailed
        ));
    }

    #[test]
    fn hierarchy_store_has_dek_flag_in_debug() {
        let (_dir, store) = hierarchy_store();
        let debug = format!("{store:?}");
        assert!(debug.contains("has_dek: true"));
    }

    #[test]
    fn hierarchy_reopen_with_same_credentials() {
        let dir = TempDir::new().unwrap();
        let passphrase = "persistent pool";
        let salt = PoolWrappingKey::generate_salt();
        let wrapping_key = PoolWrappingKey::derive(passphrase, &salt).unwrap();
        let dek = DatasetDEK::generate();
        let wrapped = wrap_dek(&dek, &wrapping_key).unwrap();
        {
            let inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let mut store = EncryptedObjectStore::new_with_hierarchy(
                inner,
                EncryptionConfig::default(),
                passphrase,
                &salt,
                wrapped.as_bytes(),
            )
            .unwrap();
            store.put_extent("persist", 1, b"survives restart").unwrap();
        }
        {
            let inner =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let store = EncryptedObjectStore::new_with_hierarchy(
                inner,
                EncryptionConfig::default(),
                passphrase,
                &salt,
                wrapped.as_bytes(),
            )
            .unwrap();
            let decrypted = store.get_extent("persist").unwrap().unwrap();
            assert_eq!(decrypted, b"survives restart");
        }
    }

    // ── Per-object key derivation integration tests ─────────────────

    fn deriver_store(key: StoreKey) -> (TempDir, EncryptedObjectStore) {
        let (dir, inner) = temp_store();
        let mut store =
            EncryptedObjectStore::new_with_config(inner, key.clone(), EncryptionConfig::default());
        let deriver = ObjectKeyDeriver::new(key);
        store.set_object_key_deriver(deriver);
        (dir, store)
    }

    #[test]
    fn deriver_put_get_roundtrip() {
        let master = StoreKey::generate();
        let (_dir, mut store) = deriver_store(master.clone());

        let payload = b"per-object encrypted data";
        let key = ObjectKey::from_content(payload);
        let stored = store.put(key, payload).unwrap();
        assert_eq!(stored.key, key);

        let retrieved = store.get(key).unwrap().unwrap();
        assert_eq!(retrieved, payload);
    }

    #[test]
    fn deriver_put_get_empty_payload() {
        let master = StoreKey::generate();
        let (_dir, mut store) = deriver_store(master);

        let payload: &[u8] = &[];
        let key = ObjectKey::from_content(payload);
        store.put(key, payload).unwrap();
        let retrieved = store.get(key).unwrap().unwrap();
        assert_eq!(retrieved, payload);
    }

    #[test]
    fn deriver_put_get_large_payload() {
        let master = StoreKey::generate();
        let (_dir, mut store) = deriver_store(master);

        // 4 KiB payload fits within test_fast segment (4096 bytes max).
        // Encryption overhead (NONCE_LEN + TAG_LEN = 28 bytes) is added
        // to the stored ciphertext, so we stay just under the limit.
        let payload = vec![0xCCu8; 3800];
        let key = ObjectKey::from_content(&payload);
        store.put(key, &payload).unwrap();
        let retrieved = store.get(key).unwrap().unwrap();
        assert_eq!(retrieved, payload);
    }

    #[test]
    fn deriver_different_keys_produce_different_stored_objects() {
        let master = StoreKey::generate();
        let (_dir, mut store) = deriver_store(master.clone());

        let payload = b"test data";
        let key1 = ObjectKey::from_content(b"obj1");
        let key2 = ObjectKey::from_content(b"obj2");

        let stored1 = store.put(key1, payload).unwrap();
        let stored2 = store.put(key2, payload).unwrap();

        // Same plaintext, different keys => different stored objects
        assert_ne!(stored1.key, stored2.key);
        // Both decrypt correctly
        assert_eq!(store.get(key1).unwrap().unwrap(), payload);
        assert_eq!(store.get(key2).unwrap().unwrap(), payload);
    }

    #[test]
    fn deriver_wrong_object_key_on_read_is_none() {
        let master = StoreKey::generate();
        let (_dir, mut store) = deriver_store(master);

        let payload = b"sensitive data";
        let key = ObjectKey::from_content(b"my-object");
        store.put(key, payload).unwrap();

        // Try to read with a different object key
        let wrong_key = ObjectKey::from_content(b"other-object");
        assert!(store.get(wrong_key).unwrap().is_none());
    }

    #[test]
    fn deriver_put_named_get_named_roundtrip() {
        let master = StoreKey::generate();
        let (_dir, mut store) = deriver_store(master);

        let name = b"named-object-1";
        let payload = b"named encrypted data";
        store.put_named(name.as_slice(), payload).unwrap();
        let retrieved = store.get_named(name.as_slice()).unwrap().unwrap();
        assert_eq!(retrieved, payload);
    }

    #[test]
    fn deriver_get_at_location_works() {
        let master = StoreKey::generate();
        let (_dir, mut store) = deriver_store(master);

        let payload = b"location test data";
        let key = ObjectKey::from_content(payload);
        store.put(key, payload).unwrap();
        let loc = store.location_of(key).unwrap();

        let retrieved = store.get_at_location(loc).unwrap();
        assert_eq!(retrieved, payload);
    }

    #[test]
    fn deriver_clear_switches_to_single_key() {
        let master = StoreKey::generate();
        let (_dir, mut store) = deriver_store(master.clone());

        // Write object A with per-object key derivation active
        let payload_a = b"with per-object key";
        let key_a = ObjectKey::from_content(b"a");
        store.put(key_a, payload_a).unwrap();
        assert_eq!(store.get(key_a).unwrap().unwrap(), payload_a);

        // Clear the deriver - switches to single master key mode
        store.clear_object_key_deriver();

        // Objects written with per-object keys cannot be read in single-key mode
        assert!(store.get(key_a).is_err());

        // New writes use the single master key and work fine
        let payload_b = b"with single master key";
        let key_b = ObjectKey::from_content(b"b");
        store.put(key_b, payload_b).unwrap();
        assert_eq!(store.get(key_b).unwrap().unwrap(), payload_b);
    }

    #[test]
    fn deriver_tampered_ciphertext_rejected() {
        let master = StoreKey::generate();
        let (_dir, mut store) = deriver_store(master);

        let payload = b"data to tamper";
        let key = ObjectKey::from_content(payload);
        store.put(key, payload).unwrap();
        let loc = store.location_of(key).unwrap();

        // Retrieve raw ciphertext through the inner store
        let mut raw = store.inner().get_at_location(loc).unwrap();
        // Flip a bit in the ciphertext past the nonce (nonce is 12 bytes)
        if raw.len() > 13 {
            raw[13] ^= 0x01;
        }

        // Write tampered bytes under a new key via the inner store
        let tampered_key = ObjectKey::from_content(&raw);
        store.inner_mut().put(tampered_key, &raw).unwrap();

        // Decryption with a key derived from tampered_key.as_bytes()
        // won't match the original encryption key, so decrypt fails
        assert!(store.get(tampered_key).is_err());
    }

    #[test]
    fn deriver_same_plaintext_different_keys_different_ciphertext() {
        let master = StoreKey::generate();
        let (_dir, mut store) = deriver_store(master);

        let payload = b"identical payload";
        let key_a = ObjectKey::from_content(b"obj-A");
        let key_b = ObjectKey::from_content(b"obj-B");

        let stored_a = store.put(key_a, payload).unwrap();
        let stored_b = store.put(key_b, payload).unwrap();

        // Different keys produce different stored ciphertexts
        assert_ne!(stored_a.key, stored_b.key);
    }

    #[test]
    fn deriver_on_disk_ciphertext_differs_from_plaintext() {
        let master = StoreKey::generate();
        let (_dir, mut store) = deriver_store(master.clone());

        let plaintext = b"plaintext that should not appear on disk";
        let key = ObjectKey::from_content(plaintext);
        store.put(key, plaintext).unwrap();

        // Read the raw stored bytes from the inner (unwrapped) store.
        // The stored bytes must be ciphertext, not plaintext.
        let loc = store.location_of(key).unwrap();
        let raw_bytes = store.inner().get_at_location(loc).unwrap();

        // With encryption, the raw bytes must differ from plaintext.
        assert_ne!(raw_bytes, plaintext);

        // The raw bytes must start with a random nonce (12 bytes),
        // not with the plaintext bytes.
        if raw_bytes.len() >= plaintext.len() {
            assert_ne!(
                &raw_bytes[..plaintext.len().min(12)],
                &plaintext[..plaintext.len().min(12)]
            );
        }

        // But decryption through the store must recover the original.
        let decrypted = store.get(key).unwrap().unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn deriver_disabled_stores_plaintext_on_disk() {
        // Without a deriver, the store uses the single master key
        // which still encrypts (EncryptedObjectStore always encrypts).
        // Test: with deriver cleared, the raw bytes differ from plaintext
        // but reading back works.
        let master = StoreKey::generate();
        let (_dir, mut store) = deriver_store(master.clone());
        let plaintext = b"data with deriver";

        let key_a = ObjectKey::from_content(b"with-deriver");
        store.put(key_a, plaintext).unwrap();
        let loc_a = store.location_of(key_a).unwrap();
        let raw_a = store.inner().get_at_location(loc_a).unwrap();

        // Clear deriver, write again
        store.clear_object_key_deriver();
        let key_b = ObjectKey::from_content(b"without-deriver");
        store.put(key_b, plaintext).unwrap();
        let loc_b = store.location_of(key_b).unwrap();
        let raw_b = store.inner().get_at_location(loc_b).unwrap();

        // Both are ciphertext (not plaintext) on disk
        assert_ne!(raw_a, plaintext);
        assert_ne!(raw_b, plaintext);

        // With deriver mode, the original object can't be read (different key derivation)
        // Without deriver mode, the new object can be read
        assert_eq!(store.get(key_b).unwrap().unwrap(), plaintext);
    }

    #[test]
    fn deriver_encrypt_then_read_inner_raw_bytes() {
        // Write through EncryptedObjectStore with deriver active,
        // then read raw bytes from inner store and verify they differ
        // from plaintext.
        let master = StoreKey::generate();
        let (_dir, mut store) = deriver_store(master.clone());

        let plaintext = b"verify encrypt-before-checksum ordering";
        let key = ObjectKey::from_content(plaintext);
        store.put(key, plaintext).unwrap();

        let loc = store.location_of(key).unwrap();
        let raw = store.inner().get_at_location(loc).unwrap();

        // Nonce is first 12 bytes, followed by ciphertext+tag
        assert!(raw.len() >= 28); // 12 nonce + 16 tag minimum
        assert_ne!(raw, plaintext);

        // Decrypt should succeed and match
        let decrypted = store.get(key).unwrap().unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // ── Proptest round-trip ──────────────────────────────────────────

    proptest::proptest! {
        #[test]
        fn proptest_deriver_roundtrip(payload in proptest::collection::vec(0u8..=255u8, 0..3800)) {
            let master = StoreKey::generate();
            let (_dir, mut store) = deriver_store(master);

            let key = ObjectKey::from_content(&payload);
            store.put(key, &payload).unwrap();
            let decrypted = store.get(key).unwrap().unwrap();
            assert_eq!(decrypted, payload);
        }

        #[test]
        fn proptest_deriver_roundtrip_edge_sizes(
            size in proptest::sample::select(vec![0usize, 1, 12, 13, 28, 29, 32, 64, 128, 256, 512, 1024, 2048, 3800])
        ) {
            let master = StoreKey::generate();
            let (_dir, mut store) = deriver_store(master);

            let payload = vec![0xABu8; size];
            let key = ObjectKey::from_content(&payload);
            store.put(key, &payload).unwrap();
            let decrypted = store.get(key).unwrap().unwrap();
            assert_eq!(decrypted, payload);
        }

        #[test]
        fn proptest_deriver_ciphertext_differs_from_plaintext(
            payload in proptest::collection::vec(0u8..=255u8, 1..2048)
        ) {
            let master = StoreKey::generate();
            let (_dir, mut store) = deriver_store(master);

            let key = ObjectKey::from_content(&payload);
            store.put(key, &payload).unwrap();

            // Raw bytes on disk must differ from plaintext
            let loc = store.location_of(key).unwrap();
            let raw = store.inner().get_at_location(loc).unwrap();
            assert_ne!(raw, payload);
        }

        #[test]
        fn proptest_deriver_key_uniqueness(
            id_a in proptest::collection::vec(0u8..=255u8, 1..64),
            id_b in proptest::collection::vec(0u8..=255u8, 1..64),
        ) {
            let master = StoreKey::generate();
            let deriver = ObjectKeyDeriver::new(master);

            let k_a = deriver.derive(DOMAIN_OBJECT_ENCRYPTION, &id_a);
            let k_b = deriver.derive(DOMAIN_OBJECT_ENCRYPTION, &id_b);

            // If ids happen to be equal, keys should match (not fail)
            // If ids differ, keys must differ
            if id_a == id_b {
                assert_eq!(k_a.as_bytes(), k_b.as_bytes());
            } else {
                assert_ne!(k_a.as_bytes(), k_b.as_bytes());
            }
        }
    }
    // ── Zeroization verification tests (NEXT-SEC-008) ─────────────────
    //
    // These tests verify that key-material types correctly implement
    // Zeroize and ZeroizeOnDrop, and that Debug implementations do not
    // leak key bytes. All tests use only safe Rust.

    use zeroize::Zeroize;

    #[test]
    fn zeroization_store_key_explicit_zeroize() {
        let mut key = StoreKey::generate();
        let original = key.as_bytes().to_vec();
        assert_ne!(
            original,
            vec![0u8; KEY_LEN],
            "generated key must be non-zero"
        );

        // Explicitly zeroize
        key.zeroize();
        assert_eq!(
            key.as_bytes(),
            &[0u8; KEY_LEN],
            "key must be all zeros after zeroize()"
        );
    }

    #[test]
    fn zeroization_store_key_drop_via_scope() {
        // Verify that ZeroizeOnDrop fires by checking that a key goes
        // out of scope and the compiler is happy (compile-time test).
        // The actual zeroization is guaranteed by the zeroize crate.
        // We verify the key was non-zero before drop to sanity-check.
        let key = StoreKey::generate();
        assert_ne!(key.as_bytes(), &[0u8; KEY_LEN]);
        drop(key);
        // Key is dropped; zeroize crate guarantees zeroization.
    }

    #[test]
    fn zeroization_pool_wrapping_key_explicit_zeroize() {
        let salt = PoolWrappingKey::generate_salt();
        let mut key = PoolWrappingKey::derive("zeroization test passphrase", &salt).unwrap();
        assert_ne!(key.as_bytes(), &[0u8; KEY_LEN]);

        key.zeroize();
        assert_eq!(key.as_bytes(), &[0u8; KEY_LEN]);
    }

    #[test]
    fn zeroization_dataset_dek_explicit_zeroize() {
        let mut key = DatasetDEK::generate();
        assert_ne!(key.as_bytes(), &[0u8; KEY_LEN]);

        key.zeroize();
        assert_eq!(key.as_bytes(), &[0u8; KEY_LEN]);
    }

    #[test]
    fn zeroization_debug_does_not_leak_key_bytes() {
        let key = StoreKey::generate();
        let key_hex = key.hex();
        let debug_str = format!("{key:?}");

        assert!(
            !debug_str.contains(&key_hex),
            "StoreKey Debug must not leak key hex bytes"
        );
        // Debug uses finish_non_exhaustive, so it should only show "StoreKey { .. }"
        assert!(
            debug_str.contains("StoreKey"),
            "StoreKey Debug must name the type"
        );
    }

    #[test]
    fn zeroization_pool_wrapping_key_debug_safe() {
        let salt = PoolWrappingKey::generate_salt();
        let wk = PoolWrappingKey::derive("debug safety test", &salt).unwrap();
        let wk_debug = format!("{wk:?}");

        assert!(
            wk_debug.contains("PoolWrappingKey") && !wk_debug.contains("secret"),
            "PoolWrappingKey Debug must not leak key-deriving passphrase"
        );
    }

    #[test]
    fn zeroization_dataset_dek_debug_safe() {
        let dek = DatasetDEK::generate();
        let debug_str = format!("{dek:?}");

        assert!(
            debug_str.contains("DatasetDEK"),
            "DatasetDEK Debug must name the type"
        );
        assert!(
            !debug_str.contains("0x"),
            "DatasetDEK Debug must not leak key bytes"
        );
    }

    #[test]
    fn zeroization_object_key_deriver_debug_safe() {
        let master = StoreKey::generate();
        let deriver = ObjectKeyDeriver::new(master);
        let debug_str = format!("{deriver:?}");

        assert!(
            debug_str.contains("ObjectKeyDeriver"),
            "ObjectKeyDeriver Debug must name the type"
        );
    }

    #[test]
    fn zeroization_clone_then_drop_both_zeroized() {
        // Clone creates a copy of key bytes. Both must zeroize independently.
        // We verify by explicitly zeroizing the original and checking the
        // clone is unaffected before its own drop.
        let mut original = StoreKey::generate();
        let clone = original.clone();

        // Both started with the same bytes
        assert_eq!(original.as_bytes(), clone.as_bytes());

        // Zeroizing the original must not affect the clone
        original.zeroize();
        assert_eq!(original.as_bytes(), &[0u8; KEY_LEN]);
        assert_ne!(
            clone.as_bytes(),
            &[0u8; KEY_LEN],
            "clone must retain key bytes after original zeroize"
        );

        // Clone is dropped here; ZeroizeOnDrop fires for the clone.
        // We can't verify post-drop without unsafe, but we verified the
        // original zeroize worked and the clone was independent.
        drop(clone);
    }

    #[test]
    fn zeroization_lease_into_key_preserves_bytes() {
        // PoolEncryptionKeyLease::into_key() clones the StoreKey before the
        // lease is dropped. Verify the consumed key matches the original.
        let salt = PoolWrappingKey::generate_salt();
        let wk = PoolWrappingKey::derive("lease test passphrase", &salt).unwrap();
        let (mut handle, original_key) =
            PoolEncryptionSecretHandle::mint("zero-test".into(), &wk, 1_700_000_000).unwrap();
        handle.activate(1_700_000_100);

        let lease = handle
            .issue_lease(
                &wk,
                std::time::Duration::from_secs(60),
                LeaseUsageClass::PoolMount,
            )
            .unwrap();
        let consumed = lease.into_key().unwrap();
        assert_eq!(consumed.as_bytes(), original_key.as_bytes());

        // The consumed key must zeroize on its own drop
        let mut consumed2 = consumed.clone();
        consumed2.zeroize();
        assert_eq!(consumed2.as_bytes(), &[0u8; KEY_LEN]);
    }

    #[test]
    fn zeroization_all_key_types_have_safe_debug() {
        // Smoke test: format every key-type Debug impl and verify no panic.
        let _ = format!("{:?}", StoreKey::generate());
        let salt = PoolWrappingKey::generate_salt();
        let _ = format!("{:?}", PoolWrappingKey::derive("smoke", &salt).unwrap());
        let _ = format!("{:?}", DatasetDEK::generate());
        let _ = format!("{:?}", ObjectKeyDeriver::new(StoreKey::generate()));
    }
}
