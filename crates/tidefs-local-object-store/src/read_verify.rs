//! Read-path checksum verification for the local object store.
//! When `verify_read_checksums` is enabled on [`StoreOptions`],
//! every read-path call validates the payload against the stored
//! per-object BLAKE3 checksum. On mismatch, [`StoreError::ObjectChecksumMismatch`] is returned.

use crate::{ObjectKey, Result, StoreError};
use tidefs_checksum_tree::{DomainTag, ObjectDigest};

/// Verify that `payload` matches the per-object checksum stored under `key`.
pub fn verify_read_payload(
    key: ObjectKey,
    payload: &[u8],
    checksums: &std::collections::BTreeMap<ObjectKey, ObjectDigest>,
) -> Result<()> {
    let stored_digest = match checksums.get(&key).copied() {
        Some(d) => d,
        None => return Ok(()),
    };
    let domain_key = DomainTag::ReadVerify.derive_key();
    if !stored_digest.verify(payload, &domain_key) {
        let actual = ObjectDigest::compute(payload, &domain_key);
        return Err(StoreError::ObjectChecksumMismatch {
            key,
            expected: stored_digest,
            actual,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ObjectKey;
    use std::collections::BTreeMap;
    fn tk(name: &str) -> ObjectKey {
        ObjectKey::from_name(name.as_bytes())
    }

    #[test]
    fn matching_checksum_passes() {
        let k = tk("v/m");
        let dk = DomainTag::ReadVerify.derive_key();
        let d = ObjectDigest::compute(b"matching", &dk);
        let mut m = BTreeMap::new();
        m.insert(k, d);
        assert!(verify_read_payload(k, b"matching", &m).is_ok());
    }

    #[test]
    fn corrupted_data_detected() {
        let k = tk("v/c");
        let dk = DomainTag::ReadVerify.derive_key();
        let d = ObjectDigest::compute(b"original", &dk);
        let mut m = BTreeMap::new();
        m.insert(k, d);
        assert!(verify_read_payload(k, b"different", &m).is_err());
    }

    #[test]
    fn missing_checksum_skips_gracefully() {
        assert!(verify_read_payload(tk("v/n"), b"any", &BTreeMap::new()).is_ok());
    }

    #[test]
    fn empty_payload_with_matching_checksum_passes() {
        let k = tk("v/e");
        let dk = DomainTag::ReadVerify.derive_key();
        let d = ObjectDigest::compute(&[], &dk);
        let mut m = BTreeMap::new();
        m.insert(k, d);
        assert!(verify_read_payload(k, &[], &m).is_ok());
    }

    #[test]
    fn single_byte_corruption_detected() {
        let k = tk("v/sb");
        let orig = vec![0x42u8; 4096];
        let dk = DomainTag::ReadVerify.derive_key();
        let d = ObjectDigest::compute(&orig, &dk);
        let mut m = BTreeMap::new();
        m.insert(k, d);
        let mut bad = orig;
        bad[1024] ^= 0x01;
        assert!(verify_read_payload(k, &bad, &m).is_err());
    }

    #[test]
    fn large_payload_verified() {
        let k = tk("v/lg");
        let data = vec![0xABu8; 64 * 1024];
        let dk = DomainTag::ReadVerify.derive_key();
        let d = ObjectDigest::compute(&data, &dk);
        let mut m = BTreeMap::new();
        m.insert(k, d);
        assert!(verify_read_payload(k, &data, &m).is_ok());
    }

    #[test]
    fn different_key_with_no_checksum_passes() {
        let k1 = tk("v/k1");
        let dk = DomainTag::ReadVerify.derive_key();
        let d = ObjectDigest::compute(b"stuff", &dk);
        let mut m = BTreeMap::new();
        m.insert(k1, d);
        assert!(verify_read_payload(tk("v/k2"), b"stuff", &m).is_ok());
    }

    #[test]
    fn zero_len_read_with_nonempty_checksum_mismatch() {
        let k = tk("v/zl");
        let dk = DomainTag::ReadVerify.derive_key();
        let d = ObjectDigest::compute(b"some data", &dk);
        let mut m = BTreeMap::new();
        m.insert(k, d);
        assert!(verify_read_payload(k, &[], &m).is_err());
    }
}
