//! Key manager integration for TideFS encryption-at-rest.
//!
//! Phase 2 of encryption-at-rest (#1246): persistent sealed-key storage
//! with Argon2id-wrapped DEKs, key rotation, and operational statistics.
//!
//! ## Storage layout
//!
//! Each dataset's sealed DEK is stored under `__tidefs_keystore__/<id>`.
//! A manifest object at `__tidefs_keystore_manifest__` tracks which
//! datasets have sealed DEKs (newline-separated dataset ids).
//!
//! ## SealedDEK wire format
//!
//! ```text
//! [magic "VSEK": 4 bytes]
//! [version: 1 byte = 0x01]
//! [flags: 1 byte reserved]
//! [dataset_id_len: 2 bytes LE]
//! [dataset_id: variable]
//! [created_at: 8 bytes LE (unix seconds)]
//! [kek_generation: 4 bytes LE]
//! [wrapped_dek_len: 2 bytes LE]
//! [wrapped_dek: wrapped_dek_len bytes]
//! ```

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

use super::key_hierarchy::{
    rewrap_dek, unwrap_dek, wrap_dek, DatasetDEK, PoolWrappingKey, WrappedDEK, SALT_LEN,
};
use super::{EncryptionError, Result};

// ── Wire format constants ──────────────────────────────────────────────

/// Magic bytes for SealedDEK wire format: "VSEK"
const SEALED_DEK_MAGIC: [u8; 4] = *b"VSEK";
/// Current wire format version.
const SEALED_DEK_VERSION: u8 = 1;

/// Object-store key for a dataset's sealed DEK.
const KEYSTORE_PREFIX: &str = "__tidefs_keystore__";

/// Object-store key for the dataset manifest.
const MANIFEST_KEY: &str = "__tidefs_keystore_manifest__";

// ── SealedDEK ──────────────────────────────────────────────────────────

/// A [`DatasetDEK`] encrypted under a [`PoolWrappingKey`] with metadata.
///
/// The sealed DEK stores the wrapped key bytes plus operational metadata
/// (dataset identity, creation time, key-generation counter) in a
/// self-describing binary format suitable for persistent storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedDEK {
    /// Dataset that owns this DEK.
    pub dataset_id: String,
    /// Unix timestamp when this sealed DEK was created.
    pub created_at: u64,
    /// Monotonic key-encryption-key generation.  Incremented on each
    /// key rotation to detect stale wrapped DEKs.
    pub kek_generation: u32,
    /// The DEK ciphertext under the pool wrapping key.
    pub wrapped_dek: WrappedDEK,
}

impl SealedDEK {
    /// Serialise to the VSEK v1 wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let did = self.dataset_id.as_bytes();
        let wdb = self.wrapped_dek.as_bytes();
        let mut out = Vec::with_capacity(12 + did.len() + wdb.len());
        out.extend_from_slice(&SEALED_DEK_MAGIC);
        out.push(SEALED_DEK_VERSION);
        out.push(0); // flags (reserved)
        out.extend_from_slice(&(did.len() as u16).to_le_bytes());
        out.extend_from_slice(did);
        out.extend_from_slice(&self.created_at.to_le_bytes());
        out.extend_from_slice(&self.kek_generation.to_le_bytes());
        out.extend_from_slice(&(wdb.len() as u16).to_le_bytes());
        out.extend_from_slice(wdb);
        out
    }

    /// Deserialise from the VSEK v1 wire format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 12 {
            return Err(EncryptionError::CiphertextTooShort { len: bytes.len() });
        }
        if bytes[..4] != SEALED_DEK_MAGIC {
            return Err(EncryptionError::DecryptionFailed);
        }
        if bytes[4] != SEALED_DEK_VERSION {
            return Err(EncryptionError::DecryptionFailed);
        }
        let did_len = u16::from_le_bytes([bytes[6], bytes[7]]) as usize;
        let pos = 8 + did_len;
        if bytes.len() < pos + 12 {
            return Err(EncryptionError::CiphertextTooShort { len: bytes.len() });
        }
        let dataset_id = String::from_utf8(bytes[8..pos].to_vec())
            .map_err(|_| EncryptionError::DecryptionFailed)?;
        let created_at = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
        let kek_generation = u32::from_le_bytes(bytes[pos + 8..pos + 12].try_into().unwrap());
        let wdb_len = u16::from_le_bytes([bytes[pos + 12], bytes[pos + 13]]) as usize;
        let wdb_start = pos + 14;
        if bytes.len() < wdb_start + wdb_len {
            return Err(EncryptionError::CiphertextTooShort { len: bytes.len() });
        }
        let wrapped_dek = WrappedDEK::from_bytes(bytes[wdb_start..wdb_start + wdb_len].to_vec())?;
        Ok(Self {
            dataset_id,
            created_at,
            kek_generation,
            wrapped_dek,
        })
    }

    /// Current time in Unix seconds (non-fatal; returns 0 on clock error).
    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

// ── KeyManagerStats ────────────────────────────────────────────────────

/// Cumulative statistics for key manager operations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyManagerStats {
    /// Number of datasets with at least one sealed DEK.
    pub datasets_encrypted: u64,
    /// Total number of seal operations performed.
    pub keys_sealed: u64,
    /// Total number of DEKs rotated (rekeyed) across all datasets.
    pub keys_rotated: u64,
}

impl KeyManagerStats {
    /// Merge `other` into `self` with saturating arithmetic.
    pub fn merge(&mut self, other: &Self) {
        self.datasets_encrypted = self
            .datasets_encrypted
            .saturating_add(other.datasets_encrypted);
        self.keys_sealed = self.keys_sealed.saturating_add(other.keys_sealed);
        self.keys_rotated = self.keys_rotated.saturating_add(other.keys_rotated);
    }
}

// ── KeyManager ─────────────────────────────────────────────────────────

/// Stateless key-management operations.
///
/// Provides the public API for wrapping-key derivation, DEK sealing
/// (encryption + metadata), and DEK unsealing (decryption).
pub struct KeyManager;

impl KeyManager {
    /// Derive a [`PoolWrappingKey`] from a passphrase and salt using
    /// Argon2id with the standard TideFS parameters
    /// (64 MiB memory, 3 iterations, 1 lane).
    pub fn derive_wrapping_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<PoolWrappingKey> {
        PoolWrappingKey::derive(passphrase, salt)
    }

    /// Seal a [`DatasetDEK`] under a [`PoolWrappingKey`].
    ///
    /// Produces a [`SealedDEK`] that includes the wrapped DEK plus
    /// dataset identity, a creation timestamp, and the current KEK
    /// generation counter.
    pub fn seal_dek(
        dek: &DatasetDEK,
        wrapping_key: &PoolWrappingKey,
        dataset_id: &str,
        kek_generation: u32,
    ) -> Result<SealedDEK> {
        let wrapped_dek = wrap_dek(dek, wrapping_key)?;
        Ok(SealedDEK {
            dataset_id: dataset_id.to_string(),
            created_at: SealedDEK::now_secs(),
            kek_generation,
            wrapped_dek,
        })
    }

    /// Unseal a [`SealedDEK`] back to its plaintext [`DatasetDEK`].
    ///
    /// Returns an error if the wrapping key does not match (wrong
    /// passphrase) or the wrapped DEK is corrupted.
    pub fn unseal_dek(sealed: &SealedDEK, wrapping_key: &PoolWrappingKey) -> Result<DatasetDEK> {
        unwrap_dek(&sealed.wrapped_dek, wrapping_key)
    }
}

// ── KeyStore ───────────────────────────────────────────────────────────

/// Persistent sealed-DEK storage backed by a [`LocalObjectStore`].
///
/// Each dataset's sealed DEK is stored as a named object under
/// `__tidefs_keystore__/<dataset_id>`.  A manifest object at
/// `__tidefs_keystore_manifest__` tracks which datasets are present.
///
/// # Security
///
/// The salt is stored in memory only; callers are responsible for
/// persisting the salt alongside the pool configuration.  The sealed
/// DEKs themselves can be stored in any object-store backend.
pub struct KeyStore {
    store: LocalObjectStore,
    salt: [u8; SALT_LEN],
    stats: KeyManagerStats,
}

impl KeyStore {
    /// Create a new keystore wrapping an existing [`LocalObjectStore`].
    pub fn new(store: LocalObjectStore, salt: [u8; SALT_LEN]) -> Self {
        Self {
            store,
            salt,
            stats: KeyManagerStats::default(),
        }
    }

    /// Open a keystore at `root` with the given salt.
    pub fn open(root: impl AsRef<Path>, salt: [u8; SALT_LEN]) -> Result<Self> {
        let store = LocalObjectStore::open(root)?;
        Ok(Self::new(store, salt))
    }

    /// Open a keystore at `root` with custom store options.
    pub fn open_with_options(
        root: impl AsRef<Path>,
        options: StoreOptions,
        salt: [u8; SALT_LEN],
    ) -> Result<Self> {
        let store = LocalObjectStore::open_with_options(root, options)?;
        Ok(Self::new(store, salt))
    }

    /// Return the salt used for wrapping-key derivation.
    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    /// Update the salt (called by [`KeyRotation`] after rekey).
    pub fn set_salt(&mut self, salt: [u8; SALT_LEN]) {
        self.salt = salt;
    }

    /// Return a reference to the underlying object store.
    pub fn store(&self) -> &LocalObjectStore {
        &self.store
    }

    /// Return a mutable reference to the underlying object store.
    pub fn store_mut(&mut self) -> &mut LocalObjectStore {
        &mut self.store
    }

    /// Return cumulative key-manager statistics.
    pub fn stats(&self) -> KeyManagerStats {
        self.stats
    }

    // ── Manifest helpers ────────────────────────────────────────────

    /// Build the store key for a dataset's sealed DEK.
    fn sealed_dek_key(dataset_id: &str) -> String {
        format!("{KEYSTORE_PREFIX}/{dataset_id}")
    }

    /// Read the manifest (newline-separated dataset ids).
    fn load_manifest(&self) -> Result<Vec<String>> {
        match self.store.get_named(MANIFEST_KEY)? {
            Some(data) => {
                let text =
                    String::from_utf8(data).map_err(|_| EncryptionError::DecryptionFailed)?;
                Ok(text
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect())
            }
            None => Ok(Vec::new()),
        }
    }

    /// Write the manifest.
    fn save_manifest(&mut self, datasets: &[String]) -> Result<()> {
        let text = datasets.join("\n");
        self.store.put_named(MANIFEST_KEY, text.as_bytes())?;
        Ok(())
    }

    // ── Operations ──────────────────────────────────────────────────

    /// Store a sealed DEK for a dataset.
    ///
    /// If a sealed DEK already exists for this dataset it is
    /// overwritten.  The dataset manifest is updated so the dataset
    /// appears in `list_datasets`.
    pub fn store_sealed_dek(&mut self, sealed: &SealedDEK) -> Result<()> {
        let key = Self::sealed_dek_key(&sealed.dataset_id);
        self.store.put_named(&key, &sealed.to_bytes())?;

        // Update manifest
        let mut ds = self.load_manifest()?;
        if !ds.contains(&sealed.dataset_id) {
            ds.push(sealed.dataset_id.clone());
            self.save_manifest(&ds)?;
        }

        self.stats.keys_sealed = self.stats.keys_sealed.saturating_add(1);
        self.stats.datasets_encrypted = self.stats.datasets_encrypted.saturating_add(1);
        Ok(())
    }

    /// Load the sealed DEK for `dataset_id`, if one exists.
    ///
    /// Returns `Ok(None)` when no sealed DEK has been stored for the
    /// dataset.
    pub fn load_sealed_dek(&self, dataset_id: &str) -> Result<Option<SealedDEK>> {
        let key = Self::sealed_dek_key(dataset_id);
        let data = match self.store.get_named(&key)? {
            Some(d) => d,
            None => return Ok(None),
        };
        SealedDEK::from_bytes(&data).map(Some)
    }

    /// List all dataset ids that have a sealed DEK in this store.
    pub fn list_datasets(&self) -> Result<Vec<String>> {
        self.load_manifest()
    }

    /// Delete the sealed DEK for `dataset_id`.
    ///
    /// Returns `true` if a sealed DEK was deleted, `false` if none
    /// existed.  The dataset manifest is updated so the dataset no
    /// longer appears in `list_datasets`.
    pub fn delete_sealed_dek(&mut self, dataset_id: &str) -> Result<bool> {
        let key = Self::sealed_dek_key(dataset_id);
        let existed = self.store.delete_named(&key)?;

        if existed {
            let mut ds = self.load_manifest()?;
            ds.retain(|d| d != dataset_id);
            self.save_manifest(&ds)?;
        }

        Ok(existed)
    }
}

// ── KeyRotation ────────────────────────────────────────────────────────

/// Key-rotation operations.
///
/// Supports rekeying the pool wrapping key: deriving a new wrapping key
/// from a new passphrase and salt, then re-wrapping every sealed DEK in
/// the store under the new key.
pub struct KeyRotation;

impl KeyRotation {
    /// Rekey all sealed DEKs from an old wrapping key to a new one.
    ///
    /// Derives the old wrapping key from `old_passphrase` + the
    /// keystore's current salt, derives the new wrapping key from
    /// `new_passphrase` + `new_salt`, then iterates every sealed DEK
    /// in `keystore`, re-wraps it, and persists the updated sealed
    /// DEK with an incremented `kek_generation`.
    ///
    /// After a successful rekey, the keystore's salt is updated to
    /// `new_salt`.
    ///
    /// # Errors
    ///
    /// Returns an error if the old passphrase does not match (can't
    /// unwrap any DEK), or if any individual rewrap or store operation
    /// fails.  Partial rekey is not supported — callers should back up
    /// the keystore before rotating.
    pub fn rekey_wrapping_key(
        old_passphrase: &str,
        new_passphrase: &str,
        new_salt: &[u8; SALT_LEN],
        keystore: &mut KeyStore,
    ) -> Result<KeyManagerStats> {
        let old_wk = PoolWrappingKey::derive(old_passphrase, keystore.salt())?;
        let new_wk = PoolWrappingKey::derive(new_passphrase, new_salt)?;

        let datasets = keystore.list_datasets()?;
        let mut stats = KeyManagerStats::default();

        for ds_id in &datasets {
            let sealed = match keystore.load_sealed_dek(ds_id)? {
                Some(s) => s,
                None => continue,
            };
            let new_wrapped = rewrap_dek(&sealed.wrapped_dek, &old_wk, &new_wk)?;
            let new_sealed = SealedDEK {
                dataset_id: sealed.dataset_id.clone(),
                created_at: SealedDEK::now_secs(),
                kek_generation: sealed.kek_generation.wrapping_add(1),
                wrapped_dek: new_wrapped,
            };
            keystore.store_sealed_dek(&new_sealed)?;
            stats.keys_rotated = stats.keys_rotated.saturating_add(1);
        }

        keystore.set_salt(*new_salt);
        Ok(stats)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::key_hierarchy::SALT_LEN;
    use super::*;
    use tempfile::TempDir;
    use tidefs_local_object_store::StoreOptions;

    // ── Helpers ──────────────────────────────────────────────────────

    fn test_salt() -> [u8; SALT_LEN] {
        let mut s = [0u8; SALT_LEN];
        s[0] = 42;
        s
    }

    fn test_keystore() -> (TempDir, KeyStore) {
        let dir = TempDir::new().unwrap();
        let store =
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
        let ks = KeyStore::new(store, test_salt());
        (dir, ks)
    }

    fn test_dek_and_wk() -> (DatasetDEK, PoolWrappingKey) {
        let dek = DatasetDEK::generate();
        let wk = PoolWrappingKey::derive("test passphrase", &test_salt()).unwrap();
        (dek, wk)
    }

    // ── SealedDEK wire format ────────────────────────────────────────

    #[test]
    fn sealed_dek_roundtrip() {
        let (dek, wk) = test_dek_and_wk();
        let sealed = KeyManager::seal_dek(&dek, &wk, "ds-1", 1).unwrap();
        let bytes = sealed.to_bytes();
        let restored = SealedDEK::from_bytes(&bytes).unwrap();
        assert_eq!(sealed, restored);
    }

    #[test]
    fn sealed_dek_from_bytes_rejects_bad_magic() {
        let mut bad = vec![0u8; 20];
        bad[0] = 0xFF;
        bad[1] = 0xFF;
        assert!(SealedDEK::from_bytes(&bad).is_err());
    }

    #[test]
    fn sealed_dek_from_bytes_rejects_truncated() {
        assert!(SealedDEK::from_bytes(&[0u8; 4]).is_err());
    }

    #[test]
    fn sealed_dek_from_bytes_rejects_short_wrapped_dek() {
        let (dek, wk) = test_dek_and_wk();
        let sealed = KeyManager::seal_dek(&dek, &wk, "ds", 0).unwrap();
        let mut bytes = sealed.to_bytes();
        let trunc = bytes.len() - 1;
        bytes.truncate(trunc);
        assert!(SealedDEK::from_bytes(&bytes).is_err());
    }

    #[test]
    fn sealed_dek_preserves_dataset_id() {
        let (dek, wk) = test_dek_and_wk();
        let sealed = KeyManager::seal_dek(&dek, &wk, "my-dataset-42", 0).unwrap();
        let restored = SealedDEK::from_bytes(&sealed.to_bytes()).unwrap();
        assert_eq!(restored.dataset_id, "my-dataset-42");
    }

    #[test]
    fn sealed_dek_preserves_kek_generation() {
        let (dek, wk) = test_dek_and_wk();
        let sealed = KeyManager::seal_dek(&dek, &wk, "ds", 7).unwrap();
        let restored = SealedDEK::from_bytes(&sealed.to_bytes()).unwrap();
        assert_eq!(restored.kek_generation, 7);
    }

    #[test]
    fn sealed_dek_created_at_is_recent() {
        let (dek, wk) = test_dek_and_wk();
        let sealed = KeyManager::seal_dek(&dek, &wk, "ds", 0).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(sealed.created_at <= now);
        assert!(sealed.created_at >= now.saturating_sub(5));
    }

    #[test]
    fn sealed_dek_different_nonce_per_seal() {
        let (dek, wk) = test_dek_and_wk();
        let s1 = KeyManager::seal_dek(&dek, &wk, "ds", 0).unwrap();
        let s2 = KeyManager::seal_dek(&dek, &wk, "ds", 0).unwrap();
        assert_ne!(s1.wrapped_dek.as_bytes(), s2.wrapped_dek.as_bytes());
    }

    // ── KeyManager seal / unseal ─────────────────────────────────────

    #[test]
    fn seal_unseal_roundtrip() {
        let (dek, wk) = test_dek_and_wk();
        let sealed = KeyManager::seal_dek(&dek, &wk, "pool/ds-1", 1).unwrap();
        let unsealed = KeyManager::unseal_dek(&sealed, &wk).unwrap();
        assert_eq!(dek.as_bytes(), unsealed.as_bytes());
    }

    #[test]
    fn unseal_wrong_passphrase_fails() {
        let (dek, _) = test_dek_and_wk();
        let wk1 = PoolWrappingKey::derive("correct", &test_salt()).unwrap();
        let wk2 = PoolWrappingKey::derive("wrong", &test_salt()).unwrap();
        let sealed = KeyManager::seal_dek(&dek, &wk1, "ds", 0).unwrap();
        let result = KeyManager::unseal_dek(&sealed, &wk2);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptionError::DecryptionFailed
        ));
    }

    #[test]
    fn unseal_wrong_salt_fails() {
        let (dek, _) = test_dek_and_wk();
        let salt_a = PoolWrappingKey::generate_salt();
        let salt_b = PoolWrappingKey::generate_salt();
        let wk1 = PoolWrappingKey::derive("same", &salt_a).unwrap();
        let wk2 = PoolWrappingKey::derive("same", &salt_b).unwrap();
        let sealed = KeyManager::seal_dek(&dek, &wk1, "ds", 0).unwrap();
        assert!(KeyManager::unseal_dek(&sealed, &wk2).is_err());
    }

    // ── KeyStore persistence ─────────────────────────────────────────

    #[test]
    fn store_and_load_sealed_dek() {
        let (_dir, mut ks) = test_keystore();
        let (dek, wk) = test_dek_and_wk();
        let sealed = KeyManager::seal_dek(&dek, &wk, "ds-store", 0).unwrap();
        ks.store_sealed_dek(&sealed).unwrap();

        let loaded = ks.load_sealed_dek("ds-store").unwrap().unwrap();
        assert_eq!(loaded.dataset_id, "ds-store");
        assert_eq!(loaded.kek_generation, 0);

        let unsealed = KeyManager::unseal_dek(&loaded, &wk).unwrap();
        assert_eq!(dek.as_bytes(), unsealed.as_bytes());
    }

    #[test]
    fn load_nonexistent_dataset_returns_none() {
        let (_dir, ks) = test_keystore();
        assert!(ks.load_sealed_dek("no-such-dataset").unwrap().is_none());
    }

    #[test]
    fn list_datasets_after_multiple_stores() {
        let (_dir, mut ks) = test_keystore();
        let (dek, wk) = test_dek_and_wk();

        ks.store_sealed_dek(&KeyManager::seal_dek(&dek, &wk, "a", 0).unwrap())
            .unwrap();
        ks.store_sealed_dek(&KeyManager::seal_dek(&dek, &wk, "b", 1).unwrap())
            .unwrap();

        let mut ds = ks.list_datasets().unwrap();
        ds.sort();
        assert_eq!(ds, vec!["a", "b"]);
    }

    #[test]
    fn list_datasets_empty_on_new_store() {
        let (_dir, ks) = test_keystore();
        assert!(ks.list_datasets().unwrap().is_empty());
    }

    #[test]
    fn delete_sealed_dek_removes_dataset() {
        let (_dir, mut ks) = test_keystore();
        let (dek, wk) = test_dek_and_wk();
        let sealed = KeyManager::seal_dek(&dek, &wk, "del-me", 0).unwrap();
        ks.store_sealed_dek(&sealed).unwrap();
        assert!(ks.load_sealed_dek("del-me").unwrap().is_some());

        assert!(ks.delete_sealed_dek("del-me").unwrap());
        assert!(ks.load_sealed_dek("del-me").unwrap().is_none());

        // Dataset no longer in manifest
        assert!(ks.list_datasets().unwrap().is_empty());
    }

    #[test]
    fn delete_nonexistent_dataset_returns_false() {
        let (_dir, mut ks) = test_keystore();
        assert!(!ks.delete_sealed_dek("ghost").unwrap());
    }

    #[test]
    fn keystore_persistence_across_reopen() {
        let dir = TempDir::new().unwrap();
        let (dek, wk) = test_dek_and_wk();
        let salt = test_salt();

        {
            let store =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let mut ks = KeyStore::new(store, salt);
            let sealed = KeyManager::seal_dek(&dek, &wk, "persist", 0).unwrap();
            ks.store_sealed_dek(&sealed).unwrap();
        }

        {
            let store =
                LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
            let ks = KeyStore::new(store, salt);
            let loaded = ks.load_sealed_dek("persist").unwrap().unwrap();
            assert_eq!(loaded.dataset_id, "persist");
            assert_eq!(ks.list_datasets().unwrap(), vec!["persist"]);
        }
    }

    #[test]
    fn keystore_does_not_mix_non_keystore_keys() {
        let (_dir, mut ks) = test_keystore();
        let (dek, wk) = test_dek_and_wk();

        // Store a sealed DEK
        let sealed = KeyManager::seal_dek(&dek, &wk, "mine", 0).unwrap();
        ks.store_sealed_dek(&sealed).unwrap();

        // Write a non-keystore object directly
        ks.store_mut().put_named("other-data", b"hello").unwrap();

        // Manifest only shows keystore datasets
        let datasets = ks.list_datasets().unwrap();
        assert_eq!(datasets, vec!["mine"]);
    }

    // ── KeyRotation ──────────────────────────────────────────────────

    #[test]
    fn rekey_roundtrip() {
        let (_dir, mut ks) = test_keystore();
        let (dek, _) = test_dek_and_wk();
        let old_salt = test_salt();
        let old_wk = PoolWrappingKey::derive("old pass", &old_salt).unwrap();

        let sealed = KeyManager::seal_dek(&dek, &old_wk, "ds-rekey", 0).unwrap();
        ks.store_sealed_dek(&sealed).unwrap();

        let new_salt = PoolWrappingKey::generate_salt();
        let stats =
            KeyRotation::rekey_wrapping_key("old pass", "new pass", &new_salt, &mut ks).unwrap();
        assert_eq!(stats.keys_rotated, 1);

        let loaded = ks.load_sealed_dek("ds-rekey").unwrap().unwrap();
        let new_wk = PoolWrappingKey::derive("new pass", &new_salt).unwrap();
        let unsealed = KeyManager::unseal_dek(&loaded, &new_wk).unwrap();
        assert_eq!(dek.as_bytes(), unsealed.as_bytes());
        assert_eq!(loaded.kek_generation, 1);

        // Old wrapping key no longer works
        let old_wk2 = PoolWrappingKey::derive("old pass", &old_salt).unwrap();
        assert!(KeyManager::unseal_dek(&loaded, &old_wk2).is_err());
    }

    #[test]
    fn rekey_wrong_old_passphrase_fails() {
        let (_dir, mut ks) = test_keystore();
        let (dek, _) = test_dek_and_wk();
        let old_salt = test_salt();
        let old_wk = PoolWrappingKey::derive("old pass", &old_salt).unwrap();

        let sealed = KeyManager::seal_dek(&dek, &old_wk, "ds", 0).unwrap();
        ks.store_sealed_dek(&sealed).unwrap();

        let new_salt = PoolWrappingKey::generate_salt();
        let result =
            KeyRotation::rekey_wrapping_key("WRONG old pass", "new pass", &new_salt, &mut ks);
        assert!(result.is_err());
    }

    #[test]
    fn rekey_multiple_datasets() {
        let (_dir, mut ks) = test_keystore();
        let (dek, _) = test_dek_and_wk();
        let old_salt = test_salt();
        let old_wk = PoolWrappingKey::derive("old", &old_salt).unwrap();

        for i in 0..5 {
            let sealed = KeyManager::seal_dek(&dek, &old_wk, &format!("ds-{i}"), 0).unwrap();
            ks.store_sealed_dek(&sealed).unwrap();
        }

        let new_salt = PoolWrappingKey::generate_salt();
        let stats = KeyRotation::rekey_wrapping_key("old", "new", &new_salt, &mut ks).unwrap();
        assert_eq!(stats.keys_rotated, 5);

        let new_wk = PoolWrappingKey::derive("new", &new_salt).unwrap();
        let mut ds = ks.list_datasets().unwrap();
        ds.sort();
        assert_eq!(ds.len(), 5);

        for i in 0..5 {
            let loaded = ks.load_sealed_dek(&format!("ds-{i}")).unwrap().unwrap();
            let unsealed = KeyManager::unseal_dek(&loaded, &new_wk).unwrap();
            assert_eq!(dek.as_bytes(), unsealed.as_bytes());
            assert_eq!(loaded.kek_generation, 1);
        }
    }

    #[test]
    fn rekey_updates_salt() {
        let (_dir, mut ks) = test_keystore();
        let old_salt = test_salt();
        let new_salt = PoolWrappingKey::generate_salt();
        let (dek, _) = test_dek_and_wk();
        let old_wk = PoolWrappingKey::derive("old", &old_salt).unwrap();

        let sealed = KeyManager::seal_dek(&dek, &old_wk, "ds", 0).unwrap();
        ks.store_sealed_dek(&sealed).unwrap();

        assert_eq!(ks.salt(), &old_salt);
        KeyRotation::rekey_wrapping_key("old", "new", &new_salt, &mut ks).unwrap();
        assert_eq!(ks.salt(), &new_salt);
    }

    #[test]
    fn rekey_idempotent_across_multiple_calls() {
        let (_dir, mut ks) = test_keystore();
        let (dek, _) = test_dek_and_wk();
        let old_salt = test_salt();
        let old_wk = PoolWrappingKey::derive("old", &old_salt).unwrap();

        let sealed = KeyManager::seal_dek(&dek, &old_wk, "ds", 0).unwrap();
        ks.store_sealed_dek(&sealed).unwrap();

        let s1 = PoolWrappingKey::generate_salt();
        KeyRotation::rekey_wrapping_key("old", "p1", &s1, &mut ks).unwrap();
        let s2 = PoolWrappingKey::generate_salt();
        KeyRotation::rekey_wrapping_key("p1", "p2", &s2, &mut ks).unwrap();

        let wk2 = PoolWrappingKey::derive("p2", &s2).unwrap();
        let loaded = ks.load_sealed_dek("ds").unwrap().unwrap();
        assert_eq!(loaded.kek_generation, 2);
        let unsealed = KeyManager::unseal_dek(&loaded, &wk2).unwrap();
        assert_eq!(dek.as_bytes(), unsealed.as_bytes());
    }

    #[test]
    fn rekey_empty_keystore_succeeds() {
        let (_dir, mut ks) = test_keystore();
        let new_salt = PoolWrappingKey::generate_salt();
        let stats = KeyRotation::rekey_wrapping_key("old", "new", &new_salt, &mut ks).unwrap();
        assert_eq!(stats.keys_rotated, 0);
        assert_eq!(ks.salt(), &new_salt);
    }

    // ── KeyManagerStats ──────────────────────────────────────────────

    #[test]
    fn key_manager_stats_merge() {
        let mut a = KeyManagerStats {
            datasets_encrypted: 3,
            keys_sealed: 10,
            keys_rotated: 2,
        };
        let b = KeyManagerStats {
            datasets_encrypted: 1,
            keys_sealed: 5,
            keys_rotated: 3,
        };
        a.merge(&b);
        assert_eq!(a.datasets_encrypted, 4);
        assert_eq!(a.keys_sealed, 15);
        assert_eq!(a.keys_rotated, 5);
    }

    #[test]
    fn keystore_stats_tracks_operations() {
        let (_dir, mut ks) = test_keystore();
        let (dek, wk) = test_dek_and_wk();

        ks.store_sealed_dek(&KeyManager::seal_dek(&dek, &wk, "a", 0).unwrap())
            .unwrap();
        ks.store_sealed_dek(&KeyManager::seal_dek(&dek, &wk, "b", 0).unwrap())
            .unwrap();

        let stats = ks.stats();
        assert_eq!(stats.keys_sealed, 2);
        assert_eq!(stats.datasets_encrypted, 2);
    }

    #[test]
    fn rekey_stats_tracks_rotated_count() {
        let (_dir, mut ks) = test_keystore();
        let (dek, _) = test_dek_and_wk();
        let old_salt = test_salt();
        let old_wk = PoolWrappingKey::derive("old", &old_salt).unwrap();

        for i in 0..3 {
            let sealed = KeyManager::seal_dek(&dek, &old_wk, &format!("d{i}"), 0).unwrap();
            ks.store_sealed_dek(&sealed).unwrap();
        }

        let new_salt = PoolWrappingKey::generate_salt();
        let stats = KeyRotation::rekey_wrapping_key("old", "new", &new_salt, &mut ks).unwrap();
        assert_eq!(stats.keys_rotated, 3);
    }
}
