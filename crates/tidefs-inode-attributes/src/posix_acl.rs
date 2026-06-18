// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! POSIX ACL types and serialization helpers.
//!
//! Re-exports the core POSIX.1e ACL entry and tag types from
//! [`tidefs_posix_acl`] plus thin convenience wrappers for the
//! common parse → validate → encode lifecycle that xattr storage
//! and permission evaluation need.

use tidefs_posix_acl;

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

pub use tidefs_posix_acl::AclError;
pub use tidefs_posix_acl::PosixAclEntry;
pub use tidefs_posix_acl::ACL_GROUP;
pub use tidefs_posix_acl::ACL_GROUP_OBJ;
pub use tidefs_posix_acl::ACL_MASK;
pub use tidefs_posix_acl::ACL_OTHER;
pub use tidefs_posix_acl::ACL_USER;
pub use tidefs_posix_acl::ACL_USER_OBJ;
pub use tidefs_posix_acl::MAX_ACL_ENTRIES;
pub use tidefs_posix_acl::POSIX_ACL_XATTR_VERSION;

/// A decoded POSIX ACL: ordered list of entries.
pub type PosixAcl = Vec<PosixAclEntry>;

// ---------------------------------------------------------------------------
// Convenience wrappers
// ---------------------------------------------------------------------------

/// Decode a Linux binary `system.posix_acl_*` xattr payload.
///
/// Thin wrapper around [`tidefs_posix_acl::decode_posix_acl_xattr`].
#[inline]
pub fn decode(buf: &[u8]) -> Result<PosixAcl, AclError> {
    tidefs_posix_acl::decode_posix_acl_xattr(buf)
}

/// Encode a `PosixAcl` into Linux binary xattr wire format.
///
/// Thin wrapper around [`tidefs_posix_acl::encode_posix_acl_xattr`].
#[inline]
#[must_use]
pub fn encode(entries: &[PosixAclEntry]) -> Vec<u8> {
    tidefs_posix_acl::encode_posix_acl_xattr(entries)
}

/// Validate the structural rules for a POSIX access ACL.
///
/// Thin wrapper around [`tidefs_posix_acl::validate_posix_acl_access_structure`].
#[inline]
pub fn validate(entries: &[PosixAclEntry]) -> Result<(), tidefs_posix_acl::PosixAclStructureError> {
    tidefs_posix_acl::validate_posix_acl_access_structure(entries)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_minimal() {
        let acl: PosixAcl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 6,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 4,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 4,
                id: 0,
            },
        ];
        let encoded = encode(&acl);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, acl);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode(b"not a valid acl blob").is_err());
    }

    #[test]
    fn decode_rejects_wrong_version() {
        let bad = [0x01u8, 0x00, 0x00, 0x00];
        assert!(matches!(decode(&bad), Err(AclError::UnsupportedVersion)));
    }

    #[test]
    fn validate_rejects_missing_required_entries() {
        let acl: PosixAcl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 6,
                id: 0,
            },
            // missing GROUP_OBJ and OTHER
        ];
        assert!(validate(&acl).is_err());
    }

    #[test]
    fn validate_accepts_minimal_valid_acl() {
        let acl: PosixAcl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 5,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 5,
                id: 0,
            },
        ];
        assert!(validate(&acl).is_ok());
    }

    #[test]
    fn encode_is_deterministic() {
        let acl: PosixAcl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let a = encode(&acl);
        let b = encode(&acl);
        assert_eq!(a, b);
    }

    #[test]
    fn tag_constants_are_unique() {
        let tags = [
            ACL_USER_OBJ,
            ACL_USER,
            ACL_GROUP_OBJ,
            ACL_GROUP,
            ACL_MASK,
            ACL_OTHER,
        ];
        let mut seen = std::collections::HashSet::new();
        for t in &tags {
            assert!(seen.insert(*t), "duplicate tag {t:#06x}");
        }
    }

    #[test]
    fn max_entries_bound_constant() {
        assert_eq!(MAX_ACL_ENTRIES, 32);
    }

    #[test]
    fn version_constant_matches_wire() {
        assert_eq!(POSIX_ACL_XATTR_VERSION, 0x0002);
    }
}
