// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! BLAKE3-verified ACL persistence: domain-separated hashing, sealed
//! encode, and verified decode for POSIX ACL xattr blobs.
//!
//! Every stored ACL is prefixed with a 32-byte BLAKE3-256 hash of the
//! serialized xattr payload, domain-separated by ACL type (access vs
//! default). The hash is verified on every load so silent corruption,
//! bit-rot, or tampering is detected before the ACL enters the
//! permission-check path.

use crate::{decode_posix_acl_xattr, encode_posix_acl_xattr};
use crate::{AclError, AclType, PosixAcl, PosixAclEntry};
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Domain separation constants
// ---------------------------------------------------------------------------

/// BLAKE3 domain-separation context for access ACL xattr blobs.
const DOMAIN_ACCESS: &[u8] = b"TideFS POSIX ACL access v1";
/// BLAKE3 domain-separation context for default ACL xattr blobs.
const DOMAIN_DEFAULT: &[u8] = b"TideFS POSIX ACL default v1";

/// Size of a BLAKE3-256 hash in bytes.
pub const BLAKE3_HASH_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// Compute the BLAKE3-256 hash of a serialized ACL for integrity
/// verification. The hash is domain-separated by `acl_type` so that
/// an access ACL can never be mistaken for a default ACL.
#[must_use]
pub fn hash_acl(entries: &[PosixAclEntry], acl_type: AclType) -> [u8; BLAKE3_HASH_LEN] {
    let raw = encode_posix_acl_xattr(entries);
    hash_bytes(&raw, acl_type)
}

/// Compute the BLAKE3-256 hash of an already-encoded ACL xattr blob.
#[must_use]
pub fn hash_acl_bytes(raw: &[u8], acl_type: AclType) -> [u8; BLAKE3_HASH_LEN] {
    hash_bytes(raw, acl_type)
}

fn hash_bytes(data: &[u8], acl_type: AclType) -> [u8; BLAKE3_HASH_LEN] {
    let domain = match acl_type {
        AclType::Access => DOMAIN_ACCESS,
        AclType::Default => DOMAIN_DEFAULT,
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(data);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Verified decode
// ---------------------------------------------------------------------------

/// Decode a raw xattr blob and verify its BLAKE3-256 hash matches
/// `expected_hash`. Returns the decoded ACL on success, or an error
/// on hash mismatch or malformed data.
///
/// Use this when the hash is stored separately (e.g. in a metadata
/// locator or intent-log record).
pub fn verify_and_decode_acl(
    data: &[u8],
    expected_hash: &[u8; BLAKE3_HASH_LEN],
    acl_type: AclType,
) -> Result<PosixAcl, AclError> {
    let computed = hash_acl_bytes(data, acl_type);
    if computed != *expected_hash {
        return Err(AclError::ChecksumMismatch);
    }
    decode_posix_acl_xattr(data)
}

// ---------------------------------------------------------------------------
// Sealed (self-describing) format
// ---------------------------------------------------------------------------

/// Encode the ACL and prepend its BLAKE3-256 hash, producing a
/// self-verifying sealed blob suitable for persistent storage.
///
/// Layout: `[hash: 32 bytes][xattr_payload: N bytes]`
#[must_use]
pub fn seal_acl(entries: &[PosixAclEntry], acl_type: AclType) -> Vec<u8> {
    let raw = encode_posix_acl_xattr(entries);
    let hash = hash_bytes(&raw, acl_type);
    let mut sealed = Vec::with_capacity(BLAKE3_HASH_LEN + raw.len());
    sealed.extend_from_slice(&hash);
    sealed.extend_from_slice(&raw);
    sealed
}

/// Verify and decode a sealed ACL blob produced by [`seal_acl`].
///
/// Returns `Err(AclError::ChecksumMismatch)` on hash mismatch,
/// `Err(AclError::SealedBlobTooShort)` if the blob is too short to
/// contain a hash, or other `AclError` variants on malformed xattr
/// data.
pub fn open_acl(sealed: &[u8], acl_type: AclType) -> Result<PosixAcl, AclError> {
    if sealed.len() < BLAKE3_HASH_LEN {
        return Err(AclError::SealedBlobTooShort {
            len: sealed.len(),
            min: BLAKE3_HASH_LEN,
        });
    }
    let (hash_bytes, payload) = sealed.split_at(BLAKE3_HASH_LEN);
    let expected_hash: [u8; BLAKE3_HASH_LEN] = hash_bytes.try_into().unwrap();
    verify_and_decode_acl(payload, &expected_hash, acl_type)
}

/// Return the sealed-blob hash prefix without decoding the payload.
/// Useful for integrity checks that only need the hash.
#[must_use]
pub fn sealed_acl_hash(sealed: &[u8]) -> Option<[u8; BLAKE3_HASH_LEN]> {
    if sealed.len() < BLAKE3_HASH_LEN {
        return None;
    }
    let mut hash = [0u8; BLAKE3_HASH_LEN];
    hash.copy_from_slice(&sealed[..BLAKE3_HASH_LEN]);
    Some(hash)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn sample_acl() -> Vec<PosixAclEntry> {
        vec![
            PosixAclEntry {
                tag: crate::ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: crate::ACL_USER,
                perm: 5,
                id: 1000,
            },
            PosixAclEntry {
                tag: crate::ACL_GROUP_OBJ,
                perm: 6,
                id: 0,
            },
            PosixAclEntry {
                tag: crate::ACL_GROUP,
                perm: 4,
                id: 500,
            },
            PosixAclEntry {
                tag: crate::ACL_MASK,
                perm: 6,
                id: 0,
            },
            PosixAclEntry {
                tag: crate::ACL_OTHER,
                perm: 1,
                id: 0,
            },
        ]
    }

    fn minimal_acl() -> Vec<PosixAclEntry> {
        vec![
            PosixAclEntry {
                tag: crate::ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: crate::ACL_GROUP_OBJ,
                perm: 5,
                id: 0,
            },
            PosixAclEntry {
                tag: crate::ACL_OTHER,
                perm: 4,
                id: 0,
            },
        ]
    }

    // -- hash_acl -------------------------------------------------------

    #[test]
    fn hash_acl_deterministic() {
        let acl = sample_acl();
        let h1 = hash_acl(&acl, AclType::Access);
        let h2 = hash_acl(&acl, AclType::Access);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_acl_domain_separation() {
        let acl = sample_acl();
        let h_access = hash_acl(&acl, AclType::Access);
        let h_default = hash_acl(&acl, AclType::Default);
        assert_ne!(h_access, h_default);
    }

    #[test]
    fn hash_acl_changes_with_content() {
        let acl1 = sample_acl();
        let acl2 = minimal_acl();
        let h1 = hash_acl(&acl1, AclType::Access);
        let h2 = hash_acl(&acl2, AclType::Access);
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_acl_empty() {
        let empty: Vec<PosixAclEntry> = vec![];
        let h = hash_acl(&empty, AclType::Access);
        assert_eq!(h.len(), 32);
    }

    // -- verify_and_decode_acl ------------------------------------------

    #[test]
    fn verify_and_decode_round_trip() {
        let acl = sample_acl();
        let raw = encode_posix_acl_xattr(&acl);
        let hash = hash_acl_bytes(&raw, AclType::Access);
        let decoded = verify_and_decode_acl(&raw, &hash, AclType::Access).unwrap();
        assert_eq!(decoded, acl);
    }

    #[test]
    fn verify_and_decode_tamper_detected() {
        let acl = sample_acl();
        let raw = encode_posix_acl_xattr(&acl);
        let hash = hash_acl_bytes(&raw, AclType::Access);

        let mut corrupted = raw.clone();
        corrupted[0] ^= 0xFF;
        let result = verify_and_decode_acl(&corrupted, &hash, AclType::Access);
        assert!(matches!(result, Err(AclError::ChecksumMismatch)));
    }

    #[test]
    fn verify_and_decode_wrong_hash() {
        let acl = sample_acl();
        let raw = encode_posix_acl_xattr(&acl);
        let mut wrong_hash = [0u8; 32];
        wrong_hash[0] = 0xAA;
        let result = verify_and_decode_acl(&raw, &wrong_hash, AclType::Access);
        assert!(matches!(result, Err(AclError::ChecksumMismatch)));
    }

    #[test]
    fn verify_and_decode_wrong_domain() {
        let acl = sample_acl();
        let raw = encode_posix_acl_xattr(&acl);
        let hash = hash_acl_bytes(&raw, AclType::Access);
        let result = verify_and_decode_acl(&raw, &hash, AclType::Default);
        assert!(matches!(result, Err(AclError::ChecksumMismatch)));
    }

    // -- seal / open ----------------------------------------------------

    #[test]
    fn seal_open_round_trip_access() {
        let acl = sample_acl();
        let sealed = seal_acl(&acl, AclType::Access);
        let opened = open_acl(&sealed, AclType::Access).unwrap();
        assert_eq!(opened, acl);
    }

    #[test]
    fn seal_open_round_trip_default() {
        let acl = minimal_acl();
        let sealed = seal_acl(&acl, AclType::Default);
        let opened = open_acl(&sealed, AclType::Default).unwrap();
        assert_eq!(opened, acl);
    }

    #[test]
    fn seal_open_tamper_byte() {
        let acl = sample_acl();
        let mut sealed = seal_acl(&acl, AclType::Access);
        let pay_start = 32;
        sealed[pay_start] ^= 0xFF;
        let result = open_acl(&sealed, AclType::Access);
        assert!(matches!(result, Err(AclError::ChecksumMismatch)));
    }

    #[test]
    fn seal_open_tamper_hash() {
        let acl = sample_acl();
        let mut sealed = seal_acl(&acl, AclType::Access);
        sealed[0] ^= 0xFF;
        let result = open_acl(&sealed, AclType::Access);
        assert!(matches!(result, Err(AclError::ChecksumMismatch)));
    }

    #[test]
    fn seal_open_wrong_domain() {
        let acl = sample_acl();
        let sealed = seal_acl(&acl, AclType::Access);
        let result = open_acl(&sealed, AclType::Default);
        assert!(matches!(result, Err(AclError::ChecksumMismatch)));
    }

    #[test]
    fn open_too_short() {
        let result = open_acl(&[0u8; 16], AclType::Access);
        assert!(matches!(result, Err(AclError::SealedBlobTooShort { .. })));
    }

    #[test]
    fn open_exact_hash_len() {
        let sealed = [0u8; 32];
        let result = open_acl(&sealed, AclType::Access);
        assert!(matches!(result, Err(AclError::ChecksumMismatch)));
    }

    // -- sealed_acl_hash ------------------------------------------------

    #[test]
    fn sealed_acl_hash_round_trip() {
        let acl = sample_acl();
        let sealed = seal_acl(&acl, AclType::Access);
        let extracted = sealed_acl_hash(&sealed).unwrap();
        let expected = hash_acl(&acl, AclType::Access);
        assert_eq!(extracted, expected);
    }

    #[test]
    fn sealed_acl_hash_too_short() {
        assert!(sealed_acl_hash(&[0u8; 16]).is_none());
    }

    // -- hash consistency -----------------------------------------------

    #[test]
    fn seal_embeds_correct_hash() {
        let acl = sample_acl();
        let sealed = seal_acl(&acl, AclType::Access);
        let embedded = sealed_acl_hash(&sealed).unwrap();
        let direct = hash_acl(&acl, AclType::Access);
        assert_eq!(embedded, direct);
    }

    #[test]
    fn hash_acl_bytes_matches_hash_acl() {
        let acl = sample_acl();
        let raw = encode_posix_acl_xattr(&acl);
        let h1 = hash_acl(&acl, AclType::Access);
        let h2 = hash_acl_bytes(&raw, AclType::Access);
        assert_eq!(h1, h2);
    }
}
