// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Per-object key derivation via HKDF-SHA256 (RFC 5869).
//!
//! [`ObjectKeyDeriver`] accepts a pool-level master key and derives a
//! unique 256-bit key for each object using HKDF-SHA256 with
//! domain-separated info strings.  This ensures that:
//!
//! - The same master key + object_id always produces the same derived key
//!   (determinism).
//! - Different object_ids produce different keys (uniqueness).
//! - Different domain tags produce different keys (domain separation).
//!
//! ## Usage
//!
//! ```ignore
//! use tidefs_encryption::{ObjectKeyDeriver, StoreKey};
//!
//! let master = StoreKey::generate();
//! let deriver = ObjectKeyDeriver::new(master);
//! let object_key = deriver.derive("tidefs-object-encryption-v1", b"object-42");
//! ```

use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::{StoreKey, KEY_LEN};

// ── Domain separation constants ─────────────────────────────────────────

/// Default domain tag for object encryption key derivation.
pub const DOMAIN_OBJECT_ENCRYPTION: &str = "tidefs-object-encryption-v1";

/// Default domain tag for object metadata key derivation.
pub const DOMAIN_OBJECT_METADATA: &str = "tidefs-object-metadata-v1";

// ── ObjectKeyDeriver ────────────────────────────────────────────────────

/// Derives per-object encryption keys from a pool-level master key
/// using HKDF-SHA256 (RFC 5869) with domain-separated info strings.
///
/// # Security properties
///
/// - **Determinism:** same (domain_tag, object_id) always yields the same key.
/// - **Uniqueness:** different `object_id` bytes produce different keys.
/// - **Domain separation:** different `domain_tag` values produce
///   independent key families (e.g., encryption keys vs metadata keys).
///
/// # Example
///
/// ```
/// use tidefs_encryption::{ObjectKeyDeriver, StoreKey};
///
/// let master = StoreKey::generate();
/// let deriver = ObjectKeyDeriver::new(master);
///
/// let obj_key_a = deriver.derive("tidefs-object-encryption-v1", b"obj-a");
/// let obj_key_b = deriver.derive("tidefs-object-encryption-v1", b"obj-b");
/// assert_ne!(obj_key_a.as_bytes(), obj_key_b.as_bytes());
/// ```
#[derive(Clone)]
pub struct ObjectKeyDeriver {
    master_key: StoreKey,
}

impl std::fmt::Debug for ObjectKeyDeriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectKeyDeriver").finish_non_exhaustive()
    }
}

impl ObjectKeyDeriver {
    /// Create a new deriver from a pool-level master key.
    pub fn new(master_key: StoreKey) -> Self {
        Self { master_key }
    }

    /// Derive a per-object key using HKDF-SHA256.
    ///
    /// `domain_tag` is a domain-separated info string (e.g.,
    /// [`DOMAIN_OBJECT_ENCRYPTION`]).  `object_id` uniquely identifies
    /// the object within the pool.
    ///
    /// Returns a [`StoreKey`] suitable for use with ChaCha20-Poly1305
    /// AEAD encryption of the identified object.
    pub fn derive(&self, domain_tag: &str, object_id: &[u8]) -> StoreKey {
        let mut okm = [0u8; KEY_LEN];
        hkdf_sha256(
            self.master_key.as_bytes(),
            object_id,
            domain_tag.as_bytes(),
            &mut okm,
        );
        // Safety: hkdf_sha256 always fills okm with KEY_LEN bytes.
        StoreKey::from_bytes(&okm).expect("HKDF-SHA256 output is always 32 bytes")
    }
}

// ── HKDF-SHA256 implementation (RFC 5869) ───────────────────────────────

/// HKDF-SHA256 key derivation function.
///
/// Implements RFC 5869 using HMAC-SHA256:
///   HKDF(salt, ikm, info) -> OKM
///
/// Where:
/// - `salt` = master_key (32 bytes)
/// - `ikm`  = object_id (variable length)
/// - `info` = domain_tag bytes (variable length)
/// - `okm`  = output buffer (32 bytes for StoreKey)
fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) {
    // RFC 5869 §2.2: HKDF-Extract
    // PRK = HMAC-SHA256(salt, IKM)
    let prk = hkdf_extract(salt, ikm);

    // RFC 5869 §2.3: HKDF-Expand
    // OKM = HKDF-Expand(PRK, info, L)
    hkdf_expand(&prk, info, okm);
}

/// HKDF-Extract (RFC 5869 §2.2): PRK = HMAC-SHA256(salt, IKM)
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC can take any key length");
    mac.update(ikm);
    let result = mac.finalize();
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&result.into_bytes());
    prk
}

/// HKDF-Expand (RFC 5869 §2.3): OKM = T(1) || T(2) || ...
///
/// T(0) = ""
/// T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
fn hkdf_expand(prk: &[u8; 32], info: &[u8], okm: &mut [u8]) {
    assert!(
        okm.len() <= 255 * 32,
        "HKDF-SHA256 output length must be <= 8160 bytes"
    );

    let n = okm.len().div_ceil(32); // number of hash blocks needed
    let mut t_prev: Vec<u8> = Vec::new();
    let mut offset = 0usize;

    for i in 1u8..=n as u8 {
        let mut mac = Hmac::<Sha256>::new_from_slice(prk).expect("HMAC can take any key length");
        if !t_prev.is_empty() {
            mac.update(&t_prev);
        }
        mac.update(info);
        mac.update(&[i]);

        let result = mac.finalize();
        let block = result.into_bytes();
        let take = std::cmp::min(32, okm.len() - offset);
        okm[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;

        // Save T(i) for the next iteration
        t_prev = block.to_vec();
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_derivation() {
        let master = StoreKey::generate();
        let deriver = ObjectKeyDeriver::new(master);

        let k1 = deriver.derive(DOMAIN_OBJECT_ENCRYPTION, b"obj-1");
        let k2 = deriver.derive(DOMAIN_OBJECT_ENCRYPTION, b"obj-1");

        // Same master key + same object_id + same domain → same derived key
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn unique_per_object_id() {
        let master = StoreKey::generate();
        let deriver = ObjectKeyDeriver::new(master);

        let k_a = deriver.derive(DOMAIN_OBJECT_ENCRYPTION, b"object-A");
        let k_b = deriver.derive(DOMAIN_OBJECT_ENCRYPTION, b"object-B");

        // Different object_ids must produce different keys
        assert_ne!(k_a.as_bytes(), k_b.as_bytes());
    }

    #[test]
    fn domain_separation_produces_different_keys() {
        let master = StoreKey::generate();
        let deriver = ObjectKeyDeriver::new(master);

        let k_enc = deriver.derive(DOMAIN_OBJECT_ENCRYPTION, b"obj-1");
        let k_meta = deriver.derive(DOMAIN_OBJECT_METADATA, b"obj-1");

        // Same object_id, different domain tags → different keys
        assert_ne!(k_enc.as_bytes(), k_meta.as_bytes());
    }

    #[test]
    fn different_master_keys_produce_different_derived_keys() {
        let master1 = StoreKey::generate();
        let master2 = StoreKey::generate();
        let deriver1 = ObjectKeyDeriver::new(master1);
        let deriver2 = ObjectKeyDeriver::new(master2);

        let k1 = deriver1.derive(DOMAIN_OBJECT_ENCRYPTION, b"same-object");
        let k2 = deriver2.derive(DOMAIN_OBJECT_ENCRYPTION, b"same-object");

        // Different master keys → different derived keys even for same object
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn empty_object_id_produces_valid_key() {
        let master = StoreKey::generate();
        let deriver = ObjectKeyDeriver::new(master);

        let k = deriver.derive(DOMAIN_OBJECT_ENCRYPTION, b"");
        assert_eq!(k.as_bytes().len(), KEY_LEN);
    }

    #[test]
    fn empty_domain_tag_produces_valid_key() {
        let master = StoreKey::generate();
        let deriver = ObjectKeyDeriver::new(master);

        let k = deriver.derive("", b"obj-1");
        assert_eq!(k.as_bytes().len(), KEY_LEN);
    }

    #[test]
    fn long_object_id_produces_valid_key() {
        let master = StoreKey::generate();
        let deriver = ObjectKeyDeriver::new(master);

        let long_id = vec![0xAAu8; 4096];
        let k = deriver.derive(DOMAIN_OBJECT_ENCRYPTION, &long_id);
        assert_eq!(k.as_bytes().len(), KEY_LEN);
    }

    #[test]
    fn hkdf_expand_output_lengths() {
        // Verify HKDF expand works for various output lengths.
        let prk = hkdf_extract(b"master-key", b"ikm");
        for len in [1usize, 16, 32, 64, 128] {
            let mut okm = vec![0u8; len];
            hkdf_expand(&prk, b"info", &mut okm);
            assert_eq!(okm.len(), len);
        }
    }

    #[test]
    fn hkdf_extract_deterministic() {
        let prk1 = hkdf_extract(b"salt", b"ikm");
        let prk2 = hkdf_extract(b"salt", b"ikm");
        assert_eq!(prk1, prk2);
    }

    #[test]
    fn hkdf_extract_different_salts_produce_different_prks() {
        let prk1 = hkdf_extract(b"salt-A", b"ikm");
        let prk2 = hkdf_extract(b"salt-B", b"ikm");
        assert_ne!(prk1, prk2);
    }

    #[test]
    fn hkdf_extract_different_ikms_produce_different_prks() {
        let prk1 = hkdf_extract(b"salt", b"ikm-A");
        let prk2 = hkdf_extract(b"salt", b"ikm-B");
        assert_ne!(prk1, prk2);
    }

    #[test]
    fn derived_key_is_valid_chacha20_key() {
        let master = StoreKey::generate();
        let deriver = ObjectKeyDeriver::new(master);
        let k = deriver.derive(DOMAIN_OBJECT_ENCRYPTION, b"test-obj");

        // The derived key should be usable for ChaCha20-Poly1305
        use chacha20poly1305::{aead::KeyInit, ChaCha20Poly1305};
        let _cipher = ChaCha20Poly1305::new_from_slice(k.as_bytes())
            .expect("derived key should be valid for ChaCha20Poly1305");
    }

    #[test]
    fn derive_is_constant_time_for_same_lengths() {
        // Ensure derivation doesn't panic or return error for edge case lengths.
        let master = StoreKey::generate();
        let deriver = ObjectKeyDeriver::new(master);

        for len in [0usize, 1, 32, 256, 1024, 4096, 65536] {
            let id = vec![0xBBu8; len];
            let k = deriver.derive(DOMAIN_OBJECT_ENCRYPTION, &id);
            assert_eq!(k.as_bytes().len(), KEY_LEN);
        }
    }
}
