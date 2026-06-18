// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! POSIX ACL convenience layer wrapping [`tidefs_posix_acl`] for xattr storage
//! and ACL enforcement paths in [`crate::LocalFileSystem`].
//!
//! The [`PosixAcl`] newtype provides `parse` (decode Linux binary xattr),
//! `to_bytes` (encode), and `validate` (structural rules) methods, while
//! [`PosixAclError`] unifies decode and structure errors.

use tidefs_posix_acl::{
    decode_posix_acl_xattr, encode_posix_acl_xattr, validate_posix_acl_access_structure, AclError,
    PosixAclStructureError,
};

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

pub use tidefs_posix_acl::{
    PosixAclEntry, ACL_GROUP, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER, ACL_USER, ACL_USER_OBJ,
    MAX_ACL_ENTRIES, POSIX_ACL_XATTR_VERSION,
};

// ---------------------------------------------------------------------------
// PosixAclError
// ---------------------------------------------------------------------------

/// Unified error type for POSIX ACL decode and validation failures.
///
/// Wraps [`AclError`] (wire-format problems) and
/// [`PosixAclStructureError`] (semantic violations).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosixAclError {
    /// Wire-format decode error: truncated buffer, bad version, invalid tag,
    /// invalid permissions, or too many entries.
    Decode(AclError),
    /// Structural validation error: missing required entry, duplicate entry,
    /// invalid special-entry id, or missing mask for named entries.
    Validate(PosixAclStructureError),
}

impl core::fmt::Display for PosixAclError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "ACL decode error: {e:?}"),
            Self::Validate(e) => write!(f, "ACL validation error: {e:?}"),
        }
    }
}

impl From<AclError> for PosixAclError {
    fn from(e: AclError) -> Self {
        PosixAclError::Decode(e)
    }
}

impl From<PosixAclStructureError> for PosixAclError {
    fn from(e: PosixAclStructureError) -> Self {
        PosixAclError::Validate(e)
    }
}

// ---------------------------------------------------------------------------
// PosixAcl
// ---------------------------------------------------------------------------

/// A POSIX ACL carried as an ordered list of [`PosixAclEntry`] values.
///
/// This newtype wraps the `Vec<PosixAclEntry>` used by [`tidefs_posix_acl`]
/// and adds convenience methods for the common parse → validate → encode
/// lifecycle that xattr storage and ACL enforcement need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixAcl(Vec<PosixAclEntry>);

impl PosixAcl {
    // -- constructors -------------------------------------------------------

    /// Build a `PosixAcl` from a pre-built entry list.
    ///
    /// No validation is performed; call [`validate`](Self::validate)
    /// before storage or enforcement if the source is untrusted.
    #[must_use]
    pub fn from_entries(entries: Vec<PosixAclEntry>) -> Self {
        Self(entries)
    }

    // -- parse / serialize / validate --------------------------------------

    /// Decode a Linux binary `system.posix_acl_*` xattr payload into a
    /// `PosixAcl`.
    ///
    /// Returns [`PosixAclError::Decode`] on any wire-format problem.
    pub fn parse(buf: &[u8]) -> Result<Self, PosixAclError> {
        let entries = decode_posix_acl_xattr(buf)?;
        Ok(Self(entries))
    }

    /// Encode this ACL to the Linux binary xattr wire format (version u32 LE
    /// followed by packed `(tag u16 LE, perm u16 LE, id u32 LE)` entries).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_posix_acl_xattr(&self.0)
    }

    /// Validate that this ACL satisfies the POSIX ACL structural rules:
    /// exactly one `USER_OBJ`, `GROUP_OBJ`, and `OTHER`; a `MASK` entry
    /// when named users or groups are present; no duplicate qualifiers.
    ///
    /// Returns [`PosixAclError::Validate`] on any rule violation.
    pub fn validate(&self) -> Result<(), PosixAclError> {
        validate_posix_acl_access_structure(&self.0)?;
        Ok(())
    }

    // -- accessors ----------------------------------------------------------

    /// Borrow the inner entry list.
    #[must_use]
    pub fn entries(&self) -> &[PosixAclEntry] {
        &self.0
    }

    /// Consume and return the inner entry list.
    #[must_use]
    pub fn into_entries(self) -> Vec<PosixAclEntry> {
        self.0
    }

    /// Return the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return `true` if this ACL has zero entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- helpers -----------------------------------------------------------

    /// Build a minimal valid ACL: USER_OBJ(6), GROUP_OBJ(4), OTHER(4).
    fn minimal_acl() -> PosixAcl {
        PosixAcl::from_entries(vec![
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
        ])
    }

    /// Build a valid ACL with named user, named group, and mask.
    fn rich_acl() -> PosixAcl {
        PosixAcl::from_entries(vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 6,
                id: 1000,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 3,
                id: 500,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 6,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 1,
                id: 0,
            },
        ])
    }

    // -- round-trip tests --------------------------------------------------

    #[test]
    fn round_trip_minimal() {
        let acl = minimal_acl();
        let bytes = acl.to_bytes();
        let parsed = PosixAcl::parse(&bytes).unwrap();
        assert_eq!(parsed, acl);
    }

    #[test]
    fn round_trip_rich() {
        let acl = rich_acl();
        let bytes = acl.to_bytes();
        let parsed = PosixAcl::parse(&bytes).unwrap();
        assert_eq!(parsed, acl);
    }

    #[test]
    fn round_trip_empty() {
        // zero entries is a valid payload (used to remove an ACL via setxattr)
        let acl = PosixAcl::from_entries(vec![]);
        let bytes = acl.to_bytes();
        let parsed = PosixAcl::parse(&bytes).unwrap();
        assert!(parsed.is_empty());
        assert_eq!(parsed, acl);
    }

    #[test]
    fn round_trip_max_id_values() {
        let acl = PosixAcl::from_entries(vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 5,
                id: 0xFFFF_FFFF,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 5,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ]);
        let bytes = acl.to_bytes();
        let parsed = PosixAcl::parse(&bytes).unwrap();
        assert_eq!(parsed, acl);
    }

    #[test]
    fn round_trip_boundary_perms() {
        let acl = PosixAcl::from_entries(vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ]);
        let bytes = acl.to_bytes();
        let parsed = PosixAcl::parse(&bytes).unwrap();
        assert_eq!(parsed, acl);
    }

    // -- byte-identical re-serialization -----------------------------------

    #[test]
    fn re_serialize_is_byte_identical() {
        // Known-good binary blob from Linux
        let known: &[u8] = &[
            0x02, 0x00, 0x00, 0x00, // version 2
            0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, // USER_OBJ rw-
            0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // GROUP_OBJ r--
            0x20, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // OTHER r--
        ];
        let parsed = PosixAcl::parse(known).unwrap();
        let reencoded = parsed.to_bytes();
        assert_eq!(reencoded, known);
    }

    // -- parse error tests -------------------------------------------------

    #[test]
    fn parse_too_short() {
        assert!(matches!(
            PosixAcl::parse(&[]),
            Err(PosixAclError::Decode(AclError::TooShort))
        ));
        assert!(matches!(
            PosixAcl::parse(&[0x02, 0x00]),
            Err(PosixAclError::Decode(AclError::TooShort))
        ));
    }

    #[test]
    fn parse_unsupported_version() {
        let bad = [0x01, 0x00, 0x00, 0x00]; // version 1
        assert!(matches!(
            PosixAcl::parse(&bad),
            Err(PosixAclError::Decode(AclError::UnsupportedVersion))
        ));
    }

    #[test]
    fn parse_bad_length() {
        let mut bad = vec![0x02, 0x00, 0x00, 0x00];
        bad.extend_from_slice(&[0; 9]); // 9 trailing bytes, not multiple of 8
        assert!(matches!(
            PosixAcl::parse(&bad),
            Err(PosixAclError::Decode(AclError::BadLength))
        ));
    }

    #[test]
    fn parse_invalid_tag() {
        let mut buf = vec![0x02, 0x00, 0x00, 0x00]; // version 2
        buf.extend_from_slice(&0x00u16.to_le_bytes()); // bad tag 0x00
        buf.extend_from_slice(&0x07u16.to_le_bytes()); // perm
        buf.extend_from_slice(&0u32.to_le_bytes()); // id
        assert!(matches!(
            PosixAcl::parse(&buf),
            Err(PosixAclError::Decode(AclError::InvalidTag))
        ));
    }

    #[test]
    fn parse_invalid_perm() {
        let mut buf = vec![0x02, 0x00, 0x00, 0x00]; // version 2
        buf.extend_from_slice(&ACL_USER_OBJ.to_le_bytes());
        buf.extend_from_slice(&0x08u16.to_le_bytes()); // perm = 8 (> 7)
        buf.extend_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            PosixAcl::parse(&buf),
            Err(PosixAclError::Decode(AclError::InvalidPerm))
        ));
    }

    #[test]
    fn parse_too_many_entries() {
        let entry = PosixAclEntry {
            tag: ACL_USER_OBJ,
            perm: 7,
            id: 0,
        };
        let mut entries = Vec::with_capacity(33);
        for _ in 0..33 {
            entries.push(entry);
        }
        let bytes = encode_posix_acl_xattr(&entries);
        assert!(matches!(
            PosixAcl::parse(&bytes),
            Err(PosixAclError::Decode(AclError::TooManyEntries))
        ));
    }

    // -- validation tests --------------------------------------------------

    #[test]
    fn validate_minimal_ok() {
        minimal_acl().validate().unwrap();
    }

    #[test]
    fn validate_rich_ok() {
        rich_acl().validate().unwrap();
    }

    #[test]
    fn validate_missing_user_obj() {
        let acl = PosixAcl::from_entries(vec![
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
        ]);
        assert!(matches!(
            acl.validate(),
            Err(PosixAclError::Validate(
                PosixAclStructureError::MissingUserObj
            ))
        ));
    }

    #[test]
    fn validate_missing_group_obj() {
        let acl = PosixAcl::from_entries(vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 6,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 4,
                id: 0,
            },
        ]);
        assert!(matches!(
            acl.validate(),
            Err(PosixAclError::Validate(
                PosixAclStructureError::MissingGroupObj
            ))
        ));
    }

    #[test]
    fn validate_missing_other() {
        let acl = PosixAcl::from_entries(vec![
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
        ]);
        assert!(matches!(
            acl.validate(),
            Err(PosixAclError::Validate(
                PosixAclStructureError::MissingOther
            ))
        ));
    }

    #[test]
    fn validate_missing_mask_with_named_entries() {
        let acl = PosixAcl::from_entries(vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 5,
                id: 1000,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 4,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ]);
        assert!(matches!(
            acl.validate(),
            Err(PosixAclError::Validate(
                PosixAclStructureError::MissingMaskForNamedEntries
            ))
        ));
    }

    #[test]
    fn validate_duplicate_named_user() {
        let acl = PosixAcl::from_entries(vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 5,
                id: 1000,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 3,
                id: 1000,
            }, // duplicate
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 4,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 6,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ]);
        assert!(matches!(
            acl.validate(),
            Err(PosixAclError::Validate(
                PosixAclStructureError::DuplicateNamedUser
            ))
        ));
    }

    #[test]
    fn validate_empty_is_rejected() {
        // An empty ACL fails structural validation (missing required entries).
        let acl = PosixAcl::from_entries(vec![]);
        assert!(acl.validate().is_err());
    }

    #[test]
    fn validate_nonzero_special_entry_id() {
        let acl = PosixAcl::from_entries(vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 6,
                id: 99,
            }, // bad: id must be 0
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
        ]);
        assert!(matches!(
            acl.validate(),
            Err(PosixAclError::Validate(
                PosixAclStructureError::InvalidSpecialEntryId
            ))
        ));
    }

    // -- Display -----------------------------------------------------------

    #[test]
    fn error_display_decode() {
        let err = PosixAclError::Decode(AclError::TooShort);
        let s = format!("{err}");
        assert!(s.contains("ACL decode error"), "{s}");
    }

    #[test]
    fn error_display_validate() {
        let err = PosixAclError::Validate(PosixAclStructureError::MissingUserObj);
        let s = format!("{err}");
        assert!(s.contains("ACL validation error"), "{s}");
    }

    // -- accessor tests ----------------------------------------------------

    #[test]
    fn accessors() {
        let acl = minimal_acl();
        assert_eq!(acl.len(), 3);
        assert!(!acl.is_empty());
        assert_eq!(acl.entries().len(), 3);
        let inner = acl.into_entries();
        assert_eq!(inner.len(), 3);
    }

    #[test]
    fn empty_accessors() {
        let acl = PosixAcl::from_entries(vec![]);
        assert_eq!(acl.len(), 0);
        assert!(acl.is_empty());
    }

    // -- Encode is deterministic -------------------------------------------

    #[test]
    fn encode_deterministic() {
        let acl = minimal_acl();
        let a = acl.to_bytes();
        let b = acl.to_bytes();
        assert_eq!(a, b);
    }
}
