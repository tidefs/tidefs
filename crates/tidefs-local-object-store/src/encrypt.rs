// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Per-object ChaCha20-Poly1305 AEAD encryption for the device I/O path.
//!
//! Every stored object carries a 12-byte random nonce followed by the
//! authenticated ciphertext (payload + 16-byte Poly1305 tag):
//! ```text
//! [nonce: 12 bytes][ciphertext || Poly1305 tag: N+16 bytes]
//! ```
//!
//! Overhead: 28 bytes per object (12 nonce + 16 AEAD tag).
//!
//! ## ZFS comparison
//!
//! ZFS native encryption (AES-256-GCM) operates at the dataset level with
//! wrapped key management, encrypting blocks within a dataset. TideFS
//! encrypts at the per-object level — every object (inode, directory entry,
//! content chunk, superblock, snapshot root) is independently encrypted with
//! its own random nonce. This provides finer granularity than ZFS's
//! dataset-level encryption and means even metadata is opaque at rest.
//!
//! ## Ceph comparison
//!
//! Ceph supports messenger-level (wire) encryption and OSD-level encryption
//! via dm-crypt. TideFS per-object encryption gives end-to-end confidentiality
//! at the object granularity regardless of replication topology.

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use std::fmt;

// ── Constants ─────────────────────────────────────────────────────────────

/// Nonce size for ChaCha20-Poly1305 (96 bits = 12 bytes, per RFC 8439).
pub const NONCE_LEN: usize = 12;

/// Key size for ChaCha20-Poly1305 (256 bits = 32 bytes).
pub const KEY_LEN: usize = 32;

/// AEAD tag size (Poly1305 MAC = 16 bytes).
pub const TAG_LEN: usize = 16;

/// Total per-object overhead: nonce + tag.
pub const ENCRYPTION_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

// ── StoreEncryptionKey ───────────────────────────────────────────────────

/// A 256-bit symmetric key for per-object ChaCha20-Poly1305 encryption.
///
/// Implements `Zeroize` so the key material is cleared from memory on drop.
/// Debug output is suppressed to avoid accidental key exposure.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct StoreEncryptionKey {
    bytes: [u8; KEY_LEN],
}

impl fmt::Debug for StoreEncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreEncryptionKey").finish_non_exhaustive()
    }
}

impl StoreEncryptionKey {
    /// Generate a fresh random 256-bit key using the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Restore a key from raw bytes.
    ///
    /// Returns `None` if `bytes` is not exactly [`KEY_LEN`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != KEY_LEN {
            return None;
        }
        let mut arr = [0u8; KEY_LEN];
        arr.copy_from_slice(bytes);
        Some(Self { bytes: arr })
    }

    /// Return the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

// ── EncryptionConfig ────────────────────────────────────────────────────

/// Configuration for per-object encryption.
#[derive(Clone, Debug)]
pub struct EncryptionConfig {
    /// Symmetric key used for ChaCha20-Poly1305 AEAD.
    pub key: StoreEncryptionKey,
}

impl EncryptionConfig {
    /// Create a new encryption config with the given key.
    pub fn new(key: StoreEncryptionKey) -> Self {
        Self { key }
    }
}

// ── Encrypt / Decrypt ────────────────────────────────────────────────────

/// Encrypt `plaintext` with a fresh random nonce.
///
/// Returns the framed ciphertext: `[nonce: 12 bytes][ciphertext || tag]`.
/// Total output length = `plaintext.len() + ENCRYPTION_OVERHEAD`.
pub fn encrypt_object(key: &StoreEncryptionKey, plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
        .expect("KEY_LEN is correct for ChaCha20Poly1305");

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = *Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("ChaCha20Poly1305 encrypt should not fail for valid nonce");

    let mut framed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    framed.extend_from_slice(&nonce_bytes);
    framed.extend_from_slice(&ciphertext);
    framed
}

/// Decrypt a framed ciphertext produced by [`encrypt_object`].
///
/// Returns `None` if the ciphertext is too short, or if AEAD decryption
/// fails (wrong key, corruption, or tampering).
pub fn decrypt_object(key: &StoreEncryptionKey, framed: &[u8]) -> Option<Vec<u8>> {
    if framed.len() < NONCE_LEN + TAG_LEN {
        return None;
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
        .expect("KEY_LEN is correct for ChaCha20Poly1305");

    let nonce = *Nonce::from_slice(&framed[..NONCE_LEN]);
    let ciphertext = &framed[NONCE_LEN..];

    cipher.decrypt(&nonce, ciphertext).ok()
}

// ── Tests ─────────────────────────────────────────────────────────────────

// ── PoolEncryptionKey ───────────────────────────────────────────────────────

/// A 256-bit symmetric pool encryption key, generated randomly at pool creation.
///
/// This key encrypts every object in the pool. It is never stored in plaintext
/// on disk, in environment variables, or in CLI arguments. Instead it is sealed
/// into a [`SealedPoolKeyEnvelope`] under a wrapping key derived from the root
/// authentication key, following the P9-04 sealed-envelope model.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct PoolEncryptionKey {
    bytes: [u8; KEY_LEN],
}

impl std::fmt::Debug for PoolEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolEncryptionKey").finish_non_exhaustive()
    }
}

impl PoolEncryptionKey {
    /// Generate a fresh random 256-bit pool encryption key using the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Return the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }

    /// Restore a pool encryption key from raw bytes.
    ///
    /// Returns `None` if `bytes` is not exactly [`KEY_LEN`] bytes.
    /// This is the inverse of [`as_bytes`](Self::as_bytes).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != KEY_LEN {
            return None;
        }
        let mut arr = [0u8; KEY_LEN];
        arr.copy_from_slice(bytes);
        Some(Self { bytes: arr })
    }

    /// Convert this pool key into a [`StoreEncryptionKey`] for per-object
    /// encryption/decryption operations.
    pub fn into_store_key(self) -> StoreEncryptionKey {
        StoreEncryptionKey { bytes: self.bytes }
    }

    /// Seal this pool key into a [`SealedPoolKeyEnvelope`] under the given
    /// wrapping key bytes.
    ///
    /// Uses ChaCha20-Poly1305 AEAD with a fresh random nonce. The wrapping key
    /// should be the 32-byte root authentication key (`as_bytes32()`).
    pub fn seal(&self, wrapping_key_bytes: &[u8; KEY_LEN]) -> SealedPoolKeyEnvelope {
        let cipher = ChaCha20Poly1305::new_from_slice(wrapping_key_bytes)
            .expect("KEY_LEN is correct for ChaCha20Poly1305");

        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = *Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(&nonce, self.bytes.as_slice())
            .expect("ChaCha20Poly1305 encrypt should not fail for valid nonce");

        SealedPoolKeyEnvelope::build(&nonce_bytes, &ciphertext)
    }

    /// Unseal a [`SealedPoolKeyEnvelope`] using the given wrapping key bytes.
    ///
    /// Returns `None` if the envelope is corrupt, tampered with, or the
    /// wrapping key is wrong (fail-closed).
    pub fn unseal(
        envelope: &SealedPoolKeyEnvelope,
        wrapping_key_bytes: &[u8; KEY_LEN],
    ) -> Option<Self> {
        let cipher = ChaCha20Poly1305::new_from_slice(wrapping_key_bytes)
            .expect("KEY_LEN is correct for ChaCha20Poly1305");

        let nonce = Nonce::from_slice(&envelope.nonce);
        let plain = cipher.decrypt(nonce, envelope.ciphertext.as_slice()).ok()?;

        if plain.len() != KEY_LEN {
            return None;
        }
        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(&plain);
        Some(Self { bytes })
    }
}

// ── SealedPoolKeyEnvelope ─────────────────────────────────────────────────

/// Wire format magic: "VEKF" (TideFS Encryption Key File).
const VEKF_MAGIC: [u8; 4] = *b"VEKF";

/// Current envelope format version.
const VEKF_VERSION: u8 = 1;

/// Total envelope size: magic(4) + version(1) + flags(1) + reserved(18)
///                      + nonce(12) + ciphertext(32+16=48) = 84 bytes.
pub const SEALED_POOL_KEY_ENVELOPE_LEN: usize = 84;

/// A sealed pool encryption key envelope stored on disk.
///
/// The pool encryption key is encrypted under the root authentication key using
/// ChaCha20-Poly1305 AEAD. The envelope is a fixed-size 84-byte file that can
/// be safely stored alongside pool metadata. No plaintext key material appears
/// in the envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedPoolKeyEnvelope {
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>, // KEY_LEN + TAG_LEN = 48 bytes
}

impl SealedPoolKeyEnvelope {
    /// Build an envelope from nonce and ciphertext (with appended tag).
    fn build(nonce: &[u8; NONCE_LEN], ciphertext_with_tag: &[u8]) -> Self {
        debug_assert_eq!(ciphertext_with_tag.len(), KEY_LEN + TAG_LEN);
        Self {
            nonce: *nonce,
            ciphertext: ciphertext_with_tag.to_vec(),
        }
    }

    /// Serialize the envelope to the VEKF v1 wire format (84 bytes).
    pub fn to_bytes(&self) -> [u8; SEALED_POOL_KEY_ENVELOPE_LEN] {
        let mut out = [0u8; SEALED_POOL_KEY_ENVELOPE_LEN];
        out[0..4].copy_from_slice(&VEKF_MAGIC);
        out[4] = VEKF_VERSION;
        out[5] = 0; // flags (reserved)
                    // bytes 6..24: reserved (18 bytes, zero-filled)
        out[24..36].copy_from_slice(&self.nonce);
        out[36..84].copy_from_slice(&self.ciphertext);
        out
    }

    /// Deserialize an envelope from VEKF v1 wire format bytes.
    ///
    /// Returns `None` if the magic does not match, the version is unsupported,
    /// or the data is too short.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SEALED_POOL_KEY_ENVELOPE_LEN {
            return None;
        }
        if bytes[0..4] != VEKF_MAGIC {
            return None;
        }
        if bytes[4] != VEKF_VERSION {
            return None;
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[24..36]);
        let ciphertext = bytes[36..84].to_vec();
        Some(Self { nonce, ciphertext })
    }

    /// Read the envelope from a file at `path`.
    pub fn read_from_file(path: &std::path::Path) -> Option<Self> {
        let raw = std::fs::read(path).ok()?;
        Self::from_bytes(&raw)
    }

    /// Write the envelope to a file at `path`.
    ///
    /// The file is created with mode 0o600 (owner read/write only) on
    /// Unix systems.
    pub fn write_to_file(&self, path: &std::path::Path) -> Result<(), std::io::Error> {
        use std::io::Write;
        let bytes = self.to_bytes();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(&bytes)?;
        Ok(())
    }
}

// ── Pool key tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod pool_key_tests {
    use super::*;

    fn dummy_wrapping_key() -> [u8; KEY_LEN] {
        [0x42u8; KEY_LEN]
    }

    #[test]
    fn pool_key_generate_is_random() {
        let k1 = PoolEncryptionKey::generate();
        let k2 = PoolEncryptionKey::generate();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let pool_key = PoolEncryptionKey::generate();
        let wk = dummy_wrapping_key();
        let envelope = pool_key.seal(&wk);
        let unsealed = PoolEncryptionKey::unseal(&envelope, &wk).unwrap();
        assert_eq!(pool_key.as_bytes(), unsealed.as_bytes());
    }

    #[test]
    fn unseal_wrong_wrapping_key_fails() {
        let pool_key = PoolEncryptionKey::generate();
        let wk1 = dummy_wrapping_key();
        let mut wk2 = dummy_wrapping_key();
        wk2[0] ^= 0xFF;
        let envelope = pool_key.seal(&wk1);
        assert!(PoolEncryptionKey::unseal(&envelope, &wk2).is_none());
    }

    #[test]
    fn seal_random_nonce_per_call() {
        let pool_key = PoolEncryptionKey::generate();
        let wk = dummy_wrapping_key();
        let e1 = pool_key.seal(&wk);
        let e2 = pool_key.seal(&wk);
        assert_ne!(&e1.nonce, &e2.nonce);
        assert_ne!(&e1.ciphertext, &e2.ciphertext);
    }

    #[test]
    fn envelope_to_bytes_roundtrip() {
        let pool_key = PoolEncryptionKey::generate();
        let wk = dummy_wrapping_key();
        let envelope = pool_key.seal(&wk);
        let bytes = envelope.to_bytes();
        assert_eq!(bytes.len(), SEALED_POOL_KEY_ENVELOPE_LEN);
        let restored = SealedPoolKeyEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(envelope, restored);
    }

    #[test]
    fn envelope_from_bytes_rejects_bad_magic() {
        let mut bad = [0u8; SEALED_POOL_KEY_ENVELOPE_LEN];
        bad[0] = 0xFF;
        assert!(SealedPoolKeyEnvelope::from_bytes(&bad).is_none());
    }

    #[test]
    fn envelope_from_bytes_rejects_wrong_size() {
        assert!(SealedPoolKeyEnvelope::from_bytes(&[0u8; 10]).is_none());
        assert!(SealedPoolKeyEnvelope::from_bytes(&[0u8; 100]).is_none());
    }

    #[test]
    fn envelope_from_bytes_rejects_wrong_version() {
        let pool_key = PoolEncryptionKey::generate();
        let wk = dummy_wrapping_key();
        let envelope = pool_key.seal(&wk);
        let mut bytes = envelope.to_bytes();
        bytes[4] = 0xFF; // corrupt version
        assert!(SealedPoolKeyEnvelope::from_bytes(&bytes).is_none());
    }

    #[test]
    fn into_store_key_produces_valid_key() {
        let pool_key = PoolEncryptionKey::generate();
        let store_key = pool_key.into_store_key();
        // Encrypt something with it to prove it's a valid key
        let pt = b"test payload";
        let ct = encrypt_object(&store_key, pt);
        let dec = decrypt_object(&store_key, &ct).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn envelope_file_roundtrip() {
        let pool_key = PoolEncryptionKey::generate();
        let wk = dummy_wrapping_key();
        let envelope = pool_key.seal(&wk);

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.vekf");
        envelope.write_to_file(&path).unwrap();

        let loaded = SealedPoolKeyEnvelope::read_from_file(&path).unwrap();
        assert_eq!(envelope, loaded);

        let unsealed = PoolEncryptionKey::unseal(&loaded, &wk).unwrap();
        assert_eq!(pool_key.as_bytes(), unsealed.as_bytes());
    }

    #[test]
    fn read_from_file_missing_returns_none() {
        assert!(SealedPoolKeyEnvelope::read_from_file(std::path::Path::new(
            "/nonexistent/path/foo.vekf"
        ))
        .is_none());
    }
}
