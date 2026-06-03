//! 3-tier key management hierarchy for TideFS encryption-at-rest.
//!
//! ## Tier 1: PoolWrappingKey
//! 256-bit key derived from a user passphrase via Argon2id with a random
//! salt.  The wrapping key never touches plaintext data — it encrypts and
//! decrypts per-dataset DEKs.
//!
//! ## Tier 2: DatasetDEK
//! Per-dataset 256-bit Data Encryption Key from the OS CSPRNG.  Stored
//! wrapped (encrypted) by the PoolWrappingKey in the object store.
//!
//! ## Tier 3: ExtentNonce
//! Per-extent 96-bit nonce for ChaCha20-Poly1305 AEAD, derived
//! deterministically from (extent_id, write_counter) keyed with the
//! dataset DEK via BLAKE3 keyed hash.
//!
//! ## WrappedDEK format
//! [nonce: 12 bytes][ciphertext(DEK) || Poly1305 tag: 32+16 bytes]
//! Total size: 60 bytes.

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;

use super::{EncryptionError, Result, KEY_LEN, NONCE_LEN, TAG_LEN};

// ── Constants ────────────────────────────────────────────────────────

pub const SALT_LEN: usize = 16;
pub const ARGON2_MEMORY_COST: u32 = 65536;
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 1;

/// WrappedDEK: nonce (12) + DEK (32) + tag (16) = 60 bytes.
pub const WRAPPED_DEK_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN;

const EXTENT_ID_LEN: usize = 8;
const WRITE_COUNTER_LEN: usize = 8;
const NONCE_INPUT_LEN: usize = EXTENT_ID_LEN + WRITE_COUNTER_LEN;

// ── PoolWrappingKey ─────────────────────────────────────────────────

/// 256-bit pool wrapping key derived via Argon2id from passphrase + salt.
///
/// Never touches plaintext data.  Only wraps/unwraps DatasetDEKs.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct PoolWrappingKey {
    bytes: [u8; KEY_LEN],
}

impl std::fmt::Debug for PoolWrappingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolWrappingKey").finish_non_exhaustive()
    }
}

impl PoolWrappingKey {
    /// Derive a wrapping key from passphrase + salt via Argon2id.
    pub fn derive(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<Self> {
        if passphrase.is_empty() {
            return Err(EncryptionError::InvalidKeyEmpty);
        }
        let mut bytes = [0u8; KEY_LEN];
        argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                ARGON2_MEMORY_COST,
                ARGON2_ITERATIONS,
                ARGON2_PARALLELISM,
                Some(KEY_LEN),
            )
            .map_err(|e| EncryptionError::KeyDerivationFailed(format!("Argon2 params: {e}")))?,
        )
        .hash_password_into(passphrase.as_bytes(), salt, &mut bytes)
        .map_err(|e| EncryptionError::KeyDerivationFailed(format!("Argon2: {e}")))?;
        Ok(Self { bytes })
    }

    pub fn from_bytes(bytes: &[u8; KEY_LEN]) -> Self {
        Self { bytes: *bytes }
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }

    pub fn generate_salt() -> [u8; SALT_LEN] {
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        salt
    }
}

// ── DatasetDEK ───────────────────────────────────────────────────────

/// 256-bit per-dataset data encryption key, generated randomly.
///
/// Stored wrapped by PoolWrappingKey; never persisted in plaintext.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct DatasetDEK {
    bytes: [u8; KEY_LEN],
}

impl std::fmt::Debug for DatasetDEK {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatasetDEK").finish_non_exhaustive()
    }
}

impl DatasetDEK {
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    pub fn from_bytes(bytes: &[u8; KEY_LEN]) -> Self {
        Self { bytes: *bytes }
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

// ── WrappedDEK ───────────────────────────────────────────────────────

/// A DatasetDEK encrypted under a PoolWrappingKey (nonce || ct || tag).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedDEK {
    bytes: Vec<u8>,
}

impl WrappedDEK {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() != WRAPPED_DEK_LEN {
            return Err(EncryptionError::InvalidKeyLength {
                expected: WRAPPED_DEK_LEN,
                got: bytes.len(),
            });
        }
        Ok(Self { bytes })
    }
}

// ── DEK wrap / unwrap ────────────────────────────────────────────────

/// Encrypt a DatasetDEK under a PoolWrappingKey.
/// A fresh random nonce is used for each call.
pub fn wrap_dek(dek: &DatasetDEK, wrapping_key: &PoolWrappingKey) -> Result<WrappedDEK> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(wrapping_key.as_bytes()).expect("KEY_LEN is always valid");

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, dek.as_bytes().as_slice())
        .map_err(|_| EncryptionError::DecryptionFailed)?;

    let mut out = Vec::with_capacity(WRAPPED_DEK_LEN);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    debug_assert_eq!(out.len(), WRAPPED_DEK_LEN);
    Ok(WrappedDEK { bytes: out })
}

/// Decrypt a WrappedDEK back into a DatasetDEK.
pub fn unwrap_dek(wrapped: &WrappedDEK, wrapping_key: &PoolWrappingKey) -> Result<DatasetDEK> {
    let bytes = wrapped.as_bytes();
    if bytes.len() < NONCE_LEN + TAG_LEN {
        return Err(EncryptionError::CiphertextTooShort { len: bytes.len() });
    }

    let cipher =
        ChaCha20Poly1305::new_from_slice(wrapping_key.as_bytes()).expect("KEY_LEN is always valid");
    let (nonce_bytes, ct) = bytes.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plain = cipher
        .decrypt(nonce, ct)
        .map_err(|_| EncryptionError::DecryptionFailed)?;

    if plain.len() != KEY_LEN {
        return Err(EncryptionError::InvalidKeyLength {
            expected: KEY_LEN,
            got: plain.len(),
        });
    }

    let mut dek_bytes = [0u8; KEY_LEN];
    dek_bytes.copy_from_slice(&plain);
    Ok(DatasetDEK::from_bytes(&dek_bytes))
}

/// Re-wrap a [`DatasetDEK`] from an old [`PoolWrappingKey`] to a new one.
///
/// The DEK plaintext never changes; only the wrapping key changes.
/// This enables key rotation without re-encrypting any extent data.
///
/// # Errors
/// Returns [`EncryptionError::DecryptionFailed`] if the old wrapping key
/// cannot unwrap the DEK (wrong passphrase or corrupted wrapped DEK).
pub fn rewrap_dek(
    wrapped_dek: &WrappedDEK,
    old_wrapping_key: &PoolWrappingKey,
    new_wrapping_key: &PoolWrappingKey,
) -> Result<WrappedDEK> {
    let dek = unwrap_dek(wrapped_dek, old_wrapping_key)?;
    wrap_dek(&dek, new_wrapping_key)
}

// ── ExtentNonce ──────────────────────────────────────────────────────

/// 96-bit per-extent nonce derived deterministically from
/// (extent_id, write_counter) keyed with the dataset DEK.
///
/// BLAKE3 keyed hash ensures uniqueness per (extent, version) and
/// unpredictability without the DEK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtentNonce {
    bytes: [u8; NONCE_LEN],
}

impl ExtentNonce {
    /// Construct an ExtentNonce from raw bytes.
    pub fn from_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self { bytes }
    }

    /// Derive a nonce from extent_id and write_counter, keyed with the DEK.
    pub fn derive(extent_id: u64, write_counter: u64, dek: &DatasetDEK) -> Self {
        let mut input = [0u8; NONCE_INPUT_LEN];
        input[..EXTENT_ID_LEN].copy_from_slice(&extent_id.to_be_bytes());
        input[EXTENT_ID_LEN..].copy_from_slice(&write_counter.to_be_bytes());

        let hash = blake3::keyed_hash(dek.as_bytes(), &input);
        let mut bytes = [0u8; NONCE_LEN];
        bytes.copy_from_slice(&hash.as_bytes()[..NONCE_LEN]);
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.bytes
    }
}

impl From<ExtentNonce> for [u8; NONCE_LEN] {
    fn from(n: ExtentNonce) -> Self {
        n.bytes
    }
}

// ── EncryptedExtentPayload ───────────────────────────────────────────

/// Ciphertext produced by encrypting an extent with ChaCha20-Poly1305.
///
/// On-disk format: [nonce: 12 bytes][ciphertext || Poly1305 tag: N+16 bytes]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedExtentPayload {
    pub nonce: ExtentNonce,
    /// Ciphertext with appended 16-byte Poly1305 tag.
    pub ciphertext: Vec<u8>,
}

impl EncryptedExtentPayload {
    pub fn len(&self) -> usize {
        NONCE_LEN + self.ciphertext.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ciphertext.len() == TAG_LEN
    }
}

/// Encrypt plaintext under a DEK with the given nonce.
pub fn encrypt_extent(
    plaintext: &[u8],
    dek: &DatasetDEK,
    nonce: &ExtentNonce,
) -> Result<EncryptedExtentPayload> {
    let cipher = ChaCha20Poly1305::new_from_slice(dek.as_bytes()).expect("KEY_LEN is always valid");
    let c_nonce = Nonce::from_slice(nonce.as_bytes());

    let ciphertext = cipher
        .encrypt(c_nonce, plaintext)
        .map_err(|_| EncryptionError::DecryptionFailed)?;

    Ok(EncryptedExtentPayload {
        nonce: *nonce,
        ciphertext,
    })
}

/// Decrypt an EncryptedExtentPayload back to plaintext.
pub fn decrypt_extent(payload: &EncryptedExtentPayload, dek: &DatasetDEK) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(dek.as_bytes()).expect("KEY_LEN is always valid");
    let c_nonce = Nonce::from_slice(payload.nonce.as_bytes());

    cipher
        .decrypt(c_nonce, payload.ciphertext.as_slice())
        .map_err(|_| EncryptionError::DecryptionFailed)
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ── PoolWrappingKey ──────────────────────────────────────────

    #[test]
    fn wrapping_key_deterministic() {
        let salt = PoolWrappingKey::generate_salt();
        let k1 = PoolWrappingKey::derive("correct horse battery staple", &salt).unwrap();
        let k2 = PoolWrappingKey::derive("correct horse battery staple", &salt).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn wrapping_key_different_passphrase() {
        let salt = PoolWrappingKey::generate_salt();
        let k1 = PoolWrappingKey::derive("alpha", &salt).unwrap();
        let k2 = PoolWrappingKey::derive("beta", &salt).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn wrapping_key_different_salt() {
        let s1 = PoolWrappingKey::generate_salt();
        let s2 = PoolWrappingKey::generate_salt();
        assert_ne!(s1, s2);
        let k1 = PoolWrappingKey::derive("same", &s1).unwrap();
        let k2 = PoolWrappingKey::derive("same", &s2).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn wrapping_key_rejects_empty_passphrase() {
        let salt = PoolWrappingKey::generate_salt();
        let r = PoolWrappingKey::derive("", &salt);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), EncryptionError::InvalidKeyEmpty));
    }

    #[test]
    fn wrapping_key_from_bytes_roundtrip() {
        let salt = PoolWrappingKey::generate_salt();
        let key = PoolWrappingKey::derive("test", &salt).unwrap();
        let restored = PoolWrappingKey::from_bytes(key.as_bytes());
        assert_eq!(key.as_bytes(), restored.as_bytes());
    }

    #[test]
    fn wrapping_key_debug_safe() {
        let salt = PoolWrappingKey::generate_salt();
        let key = PoolWrappingKey::derive("secret", &salt).unwrap();
        let d = format!("{key:?}");
        assert!(d.contains("PoolWrappingKey"));
        assert!(!d.contains("secret"));
    }

    // ── DatasetDEK ────────────────────────────────────────────────

    #[test]
    fn dek_generate_random() {
        let d1 = DatasetDEK::generate();
        let d2 = DatasetDEK::generate();
        assert_ne!(d1.as_bytes(), d2.as_bytes());
    }

    #[test]
    fn dek_from_bytes_roundtrip() {
        let dek = DatasetDEK::generate();
        let r = DatasetDEK::from_bytes(dek.as_bytes());
        assert_eq!(dek.as_bytes(), r.as_bytes());
    }

    #[test]
    fn dek_debug_safe() {
        let dek = DatasetDEK::generate();
        assert!(format!("{dek:?}").contains("DatasetDEK"));
    }

    // ── Wrap / unwrap ─────────────────────────────────────────────

    #[test]
    fn wrap_unwrap_roundtrip() {
        let salt = PoolWrappingKey::generate_salt();
        let wk = PoolWrappingKey::derive("pool passphrase", &salt).unwrap();
        let dek = DatasetDEK::generate();

        let wrapped = wrap_dek(&dek, &wk).unwrap();
        assert_eq!(wrapped.as_bytes().len(), WRAPPED_DEK_LEN);

        let unwrapped = unwrap_dek(&wrapped, &wk).unwrap();
        assert_eq!(dek.as_bytes(), unwrapped.as_bytes());
    }

    #[test]
    fn wrap_random_nonce_per_call() {
        let salt = PoolWrappingKey::generate_salt();
        let wk = PoolWrappingKey::derive("pool passphrase", &salt).unwrap();
        let dek = DatasetDEK::generate();

        let w1 = wrap_dek(&dek, &wk).unwrap();
        let w2 = wrap_dek(&dek, &wk).unwrap();
        assert_ne!(&w1.as_bytes()[..NONCE_LEN], &w2.as_bytes()[..NONCE_LEN]);
        assert_ne!(w1.as_bytes(), w2.as_bytes());

        // Both unwrap to same DEK.
        assert_eq!(
            unwrap_dek(&w1, &wk).unwrap().as_bytes(),
            unwrap_dek(&w2, &wk).unwrap().as_bytes()
        );
    }

    #[test]
    fn unwrap_wrong_wrapping_key_fails() {
        let salt = PoolWrappingKey::generate_salt();
        let wk1 = PoolWrappingKey::derive("correct", &salt).unwrap();
        let wk2 = PoolWrappingKey::derive("wrong", &salt).unwrap();
        let dek = DatasetDEK::generate();

        let wrapped = wrap_dek(&dek, &wk1).unwrap();
        let r = unwrap_dek(&wrapped, &wk2);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), EncryptionError::DecryptionFailed));
    }

    #[test]
    fn wrapped_dek_from_bytes_rejects_bad_length() {
        assert!(WrappedDEK::from_bytes(vec![0; 10]).is_err());
        assert!(WrappedDEK::from_bytes(vec![0; WRAPPED_DEK_LEN]).is_ok());
    }

    #[test]
    fn unwrap_truncated_wrapped_dek_fails() {
        let salt = PoolWrappingKey::generate_salt();
        let wk = PoolWrappingKey::derive("pass", &salt).unwrap();
        let dek = DatasetDEK::generate();
        let wrapped = wrap_dek(&dek, &wk).unwrap();

        let truncated = WrappedDEK {
            bytes: wrapped.as_bytes()[..NONCE_LEN + 1].to_vec(),
        };
        assert!(unwrap_dek(&truncated, &wk).is_err());
    }

    #[test]
    fn cross_dataset_isolation() {
        let salt = PoolWrappingKey::generate_salt();
        let wk = PoolWrappingKey::derive("pass", &salt).unwrap();
        let da = DatasetDEK::generate();
        let db = DatasetDEK::generate();

        let wa = wrap_dek(&da, &wk).unwrap();
        let wb = wrap_dek(&db, &wk).unwrap();

        let ra = unwrap_dek(&wa, &wk).unwrap();
        let rb = unwrap_dek(&wb, &wk).unwrap();

        assert_eq!(da.as_bytes(), ra.as_bytes());
        assert_eq!(db.as_bytes(), rb.as_bytes());
        assert_ne!(da.as_bytes(), db.as_bytes());
    }

    // ── ExtentNonce ────────────────────────────────────────────────

    #[test]
    fn nonce_deterministic() {
        let dek = DatasetDEK::generate();
        assert_eq!(
            ExtentNonce::derive(42, 1, &dek).as_bytes(),
            ExtentNonce::derive(42, 1, &dek).as_bytes()
        );
    }

    #[test]
    fn nonce_differs_by_extent_id() {
        let dek = DatasetDEK::generate();
        assert_ne!(
            ExtentNonce::derive(1, 0, &dek).as_bytes(),
            ExtentNonce::derive(2, 0, &dek).as_bytes()
        );
    }

    #[test]
    fn nonce_differs_by_write_counter() {
        let dek = DatasetDEK::generate();
        assert_ne!(
            ExtentNonce::derive(42, 0, &dek).as_bytes(),
            ExtentNonce::derive(42, 1, &dek).as_bytes()
        );
    }

    #[test]
    fn nonce_differs_by_dek() {
        let da = DatasetDEK::generate();
        let db = DatasetDEK::generate();
        assert_ne!(
            ExtentNonce::derive(42, 0, &da).as_bytes(),
            ExtentNonce::derive(42, 0, &db).as_bytes()
        );
    }

    #[test]
    fn nonce_is_12_bytes() {
        let dek = DatasetDEK::generate();
        assert_eq!(ExtentNonce::derive(1, 1, &dek).as_bytes().len(), NONCE_LEN);
    }

    #[test]
    fn nonce_into_array() {
        let dek = DatasetDEK::generate();
        let n = ExtentNonce::derive(1, 1, &dek);
        let arr: [u8; NONCE_LEN] = n.into();
        assert_eq!(&arr, n.as_bytes());
    }

    #[test]
    fn nonce_no_collision_1000_extents() {
        let dek = DatasetDEK::generate();
        let mut seen = HashSet::new();
        for eid in 0u64..1000 {
            let n = ExtentNonce::derive(eid, 0, &dek);
            assert!(seen.insert(*n.as_bytes()), "collision at extent {eid}");
        }
        assert_eq!(seen.len(), 1000);
    }

    // ── Encrypt / decrypt extent ───────────────────────────────────

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let dek = DatasetDEK::generate();
        let nonce = ExtentNonce::derive(1, 0, &dek);
        let pt = b"extent payload test data";

        let payload = encrypt_extent(pt, &dek, &nonce).unwrap();
        let dec = decrypt_extent(&payload, &dek).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn encrypt_empty_payload() {
        let dek = DatasetDEK::generate();
        let nonce = ExtentNonce::derive(1, 0, &dek);

        let payload = encrypt_extent(&[], &dek, &nonce).unwrap();
        assert!(payload.is_empty());
        assert_eq!(payload.len(), NONCE_LEN + TAG_LEN);

        let dec = decrypt_extent(&payload, &dek).unwrap();
        assert!(dec.is_empty());
    }

    #[test]
    fn encrypt_different_nonce_different_ciphertext() {
        let dek = DatasetDEK::generate();
        let pt = b"same data";
        let n1 = ExtentNonce::derive(1, 0, &dek);
        let n2 = ExtentNonce::derive(1, 1, &dek);

        let p1 = encrypt_extent(pt, &dek, &n1).unwrap();
        let p2 = encrypt_extent(pt, &dek, &n2).unwrap();
        assert_ne!(p1.ciphertext, p2.ciphertext);
    }

    #[test]
    fn decrypt_wrong_dek_fails() {
        let da = DatasetDEK::generate();
        let db = DatasetDEK::generate();
        let nonce = ExtentNonce::derive(1, 0, &da);
        let payload = encrypt_extent(b"secret", &da, &nonce).unwrap();

        let r = decrypt_extent(&payload, &db);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), EncryptionError::DecryptionFailed));
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let dek = DatasetDEK::generate();
        let nonce = ExtentNonce::derive(1, 0, &dek);
        let mut payload = encrypt_extent(b"classified", &dek, &nonce).unwrap();
        if payload.ciphertext.len() > TAG_LEN {
            payload.ciphertext[1] ^= 0xFF;
        }
        let r = decrypt_extent(&payload, &dek);
        assert!(r.is_err());
    }

    #[test]
    fn decrypt_wrong_nonce_fails() {
        let dek = DatasetDEK::generate();
        let nonce = ExtentNonce::derive(1, 0, &dek);
        let wrong = ExtentNonce::derive(2, 0, &dek);
        let payload = encrypt_extent(b"data", &dek, &nonce).unwrap();

        let tampered = EncryptedExtentPayload {
            nonce: wrong,
            ciphertext: payload.ciphertext,
        };
        let r = decrypt_extent(&tampered, &dek);
        assert!(r.is_err());
    }

    #[test]
    fn encrypt_large_payload() {
        let dek = DatasetDEK::generate();
        let nonce = ExtentNonce::derive(1, 0, &dek);
        let pt = vec![0xABu8; 65536];

        let payload = encrypt_extent(&pt, &dek, &nonce).unwrap();
        assert_eq!(payload.len(), NONCE_LEN + pt.len() + TAG_LEN);

        let dec = decrypt_extent(&payload, &dek).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn multiple_extent_versions() {
        let dek = DatasetDEK::generate();
        for counter in 0u64..10 {
            let nonce = ExtentNonce::derive(100, counter, &dek);
            let pt = format!("extent 100 v{counter}");
            let payload = encrypt_extent(pt.as_bytes(), &dek, &nonce).unwrap();
            let dec = decrypt_extent(&payload, &dek).unwrap();
            assert_eq!(dec, pt.as_bytes());
        }
    }

    // ── Key rotation tests ──────────────────────────────────────────

    #[test]
    fn rewrap_dek_roundtrip() {
        let salt = PoolWrappingKey::generate_salt();
        let old_wk = PoolWrappingKey::derive("old passphrase", &salt).unwrap();
        let new_wk = PoolWrappingKey::derive("new passphrase", &salt).unwrap();
        let dek = DatasetDEK::generate();

        let wrapped_old = wrap_dek(&dek, &old_wk).unwrap();
        let wrapped_new = rewrap_dek(&wrapped_old, &old_wk, &new_wk).unwrap();

        // Old wrapped DEK still unwraps with old key
        let d1 = unwrap_dek(&wrapped_old, &old_wk).unwrap();
        assert_eq!(d1.as_bytes(), dek.as_bytes());

        // New wrapped DEK unwraps with new key
        let d2 = unwrap_dek(&wrapped_new, &new_wk).unwrap();
        assert_eq!(d2.as_bytes(), dek.as_bytes());

        // But old wrapped DEK does NOT unwrap with new key
        assert!(unwrap_dek(&wrapped_old, &new_wk).is_err());
    }

    #[test]
    fn rewrap_dek_wrong_old_key_fails() {
        let salt = PoolWrappingKey::generate_salt();
        let correct_wk = PoolWrappingKey::derive("correct", &salt).unwrap();
        let wrong_wk = PoolWrappingKey::derive("wrong", &salt).unwrap();
        let new_wk = PoolWrappingKey::derive("new passphrase", &salt).unwrap();
        let dek = DatasetDEK::generate();

        let wrapped = wrap_dek(&dek, &correct_wk).unwrap();
        let result = rewrap_dek(&wrapped, &wrong_wk, &new_wk);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptionError::DecryptionFailed
        ));
    }

    #[test]
    fn rewrap_dek_idempotent() {
        let salt = PoolWrappingKey::generate_salt();
        let old_wk = PoolWrappingKey::derive("old", &salt).unwrap();
        let new_wk = PoolWrappingKey::derive("new", &salt).unwrap();
        let dek = DatasetDEK::generate();

        let wrapped = wrap_dek(&dek, &old_wk).unwrap();
        let rewrapped1 = rewrap_dek(&wrapped, &old_wk, &new_wk).unwrap();
        let rewrapped2 = rewrap_dek(&wrapped, &old_wk, &new_wk).unwrap();

        // Both rewrapped DEKs unwrap to the same plaintext DEK with new key
        let d1 = unwrap_dek(&rewrapped1, &new_wk).unwrap();
        let d2 = unwrap_dek(&rewrapped2, &new_wk).unwrap();
        assert_eq!(d1.as_bytes(), dek.as_bytes());
        assert_eq!(d2.as_bytes(), dek.as_bytes());

        // Each rewrap produces different ciphertext (random nonce)
        assert_ne!(rewrapped1.as_bytes(), rewrapped2.as_bytes());
    }

    #[test]
    fn rewrap_dek_different_salts() {
        let salt_a = PoolWrappingKey::generate_salt();
        let salt_b = PoolWrappingKey::generate_salt();
        let old_wk = PoolWrappingKey::derive("old", &salt_a).unwrap();
        let new_wk = PoolWrappingKey::derive("new", &salt_b).unwrap();
        let dek = DatasetDEK::generate();

        let wrapped = wrap_dek(&dek, &old_wk).unwrap();
        let rewrapped = rewrap_dek(&wrapped, &old_wk, &new_wk).unwrap();
        let d = unwrap_dek(&rewrapped, &new_wk).unwrap();
        assert_eq!(d.as_bytes(), dek.as_bytes());
    }
}
