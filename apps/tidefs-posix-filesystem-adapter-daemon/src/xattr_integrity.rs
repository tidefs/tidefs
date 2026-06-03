//! BLAKE3-verified xattr state integrity helpers.
//!
//! Domain: `tidefs-fuse-xattr-statx-v1`
//!
//! Provides the domain-separated BLAKE3 context for computing
//! deterministic xattr state digests used in statx reply enrichment
//! and validation.

/// BLAKE3 domain separator for TideFS FUSE xattr/statx integrity.
///
/// All xattr state digests produced under this domain use
/// `blake3::Hasher::new_derive_key` with this context string to
/// ensure cryptographic domain separation from other TideFS hashing.
pub const XATTR_STATE_DOMAIN: &str = "tidefs-fuse-xattr-statx-v1";

/// Compute a BLAKE3-256 xattr state digest from packed NUL-separated
/// name list and a value lookup function.
///
/// Names are iterated in the order they appear in `packed_names`.
/// Each name and its corresponding value (returned by `value_of`)
/// are fed into the hasher. The resulting 32-byte digest is
/// deterministic for a given ordered set of (name, value) pairs.
pub fn compute_xattr_state_digest<V>(packed_names: &[u8], value_of: V) -> blake3::Hash
where
    V: Fn(&[u8]) -> Option<Vec<u8>>,
{
    let mut hasher = blake3::Hasher::new_derive_key(XATTR_STATE_DOMAIN);
    for name in packed_names.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        hasher.update(name);
        if let Some(val) = value_of(name) {
            hasher.update(&val);
        }
    }
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_xattr_state_digest_is_deterministic() {
        let d1 = compute_xattr_state_digest(b"", |_| None);
        let d2 = compute_xattr_state_digest(b"", |_| None);
        assert_eq!(d1, d2);
    }

    #[test]
    fn xattr_state_digest_reflects_values() {
        let packed = b"user.a\x00user.b\x00";
        let d1 = compute_xattr_state_digest(packed, |name| match name {
            b"user.a" => Some(b"val1".to_vec()),
            b"user.b" => Some(b"val2".to_vec()),
            _ => None,
        });
        let d2 = compute_xattr_state_digest(packed, |name| match name {
            b"user.a" => Some(b"val1-changed".to_vec()),
            b"user.b" => Some(b"val2".to_vec()),
            _ => None,
        });
        assert_ne!(d1, d2, "digest must differ when a value changes");
    }

    #[test]
    fn xattr_state_digest_reflects_names() {
        let d1 = compute_xattr_state_digest(b"user.a\x00", |n| {
            if n == b"user.a" {
                Some(b"v".to_vec())
            } else {
                None
            }
        });
        let d2 = compute_xattr_state_digest(b"user.b\x00", |n| {
            if n == b"user.b" {
                Some(b"v".to_vec())
            } else {
                None
            }
        });
        assert_ne!(d1, d2, "digest must differ when a name changes");
    }

    #[test]
    fn domain_separation_produces_distinct_hashes() {
        let packed = b"user.test\x00";
        let val = |n: &[u8]| {
            if n == b"user.test" {
                Some(b"val".to_vec())
            } else {
                None
            }
        };
        let d1 = compute_xattr_state_digest(packed, val);

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"user.test");
        hasher.update(b"val");
        let d2 = hasher.finalize();

        assert_ne!(
            d1, d2,
            "domain-separated digest must differ from raw BLAKE3"
        );
    }
}
