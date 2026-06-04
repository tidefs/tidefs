#![no_std]
#![forbid(unsafe_code)]

//! POSIX ACL xattr codec: encode/decode the Linux binary xattr format.
//!
//! Phase 1 delivers `PosixAclEntry`, `PosixAcl`, `AclError`, tag constants,
//! `decode_posix_acl_xattr`, and `encode_posix_acl_xattr`.
//!
//! All functions are pure, deterministic, and allocation-free apart from the
//! returned `Vec<PosixAclEntry>` on decode.

extern crate alloc;

pub mod acl_persist;

use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// ACL xattr version (Linux `POSIX_ACL_XATTR_VERSION`).
pub const POSIX_ACL_XATTR_VERSION: u32 = 0x0002;

/// Maximum ACL entries (ext4 safety bound, 32 entries).
pub const MAX_ACL_ENTRIES: u8 = 32;

// ---------------------------------------------------------------------------
// Tag constants (from linux/posix_acl_xattr.h)
// ---------------------------------------------------------------------------

/// File owner.
pub const ACL_USER_OBJ: u16 = 0x01;
/// Named user (id = uid).
pub const ACL_USER: u16 = 0x02;
/// File owning group.
pub const ACL_GROUP_OBJ: u16 = 0x04;
/// Named group (id = gid).
pub const ACL_GROUP: u16 = 0x08;
/// Maximum permissions for group class.
pub const ACL_MASK: u16 = 0x10;
/// Everyone else.
pub const ACL_OTHER: u16 = 0x20;
/// Undefined qualifier id used by Linux for entries without a uid/gid.
pub const ACL_UNDEFINED_ID: u32 = u32::MAX;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// One entry in a POSIX ACL.
///
/// Each entry is 8 bytes on-wire: tag (u16 LE), perm (u16 LE, only bits
/// 0..2 used), id (u32 LE, uid/gid for USER/GROUP; 0 or
/// `ACL_UNDEFINED_ID` otherwise).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PosixAclEntry {
    /// Tag: one of `ACL_USER_OBJ`, `ACL_USER`, `ACL_GROUP_OBJ`,
    /// `ACL_GROUP`, `ACL_MASK`, `ACL_OTHER`.
    pub tag: u16,
    /// Permissions: `0..7` (rwx bits).
    pub perm: u16,
    /// uid or gid for `ACL_USER` / `ACL_GROUP`; 0 or `ACL_UNDEFINED_ID`
    /// for other tags.
    pub id: u32,
}

/// A decoded POSIX ACL: ordered list of entries.
pub type PosixAcl = Vec<PosixAclEntry>;
/// Distinguishes access ACLs from default ACLs for directory inheritance.
///
/// An access ACL (`system.posix_acl_access`) controls permission checks
/// on the inode itself.  A default ACL (`system.posix_acl_default`) is
/// stored only on directories and defines the ACLs that will be
/// inherited by newly created children.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclType {
    /// Access ACL — governs permission checks on this inode.
    Access,
    /// Default ACL — directory-only; defines inheritance for new children.
    Default,
}

impl AclType {
    /// Xattr name constant for this ACL type.
    #[must_use]
    pub const fn xattr_name(self) -> &'static [u8] {
        match self {
            Self::Access => b"system.posix_acl_access",
            Self::Default => b"system.posix_acl_default",
        }
    }
}

/// An xattr name-value pair for ACL inheritance results.
pub type PosixAclXattrPair = (&'static [u8], Vec<u8>);

/// Permission class selected while evaluating an access ACL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosixAclPermissionClass {
    /// The caller owns the inode and matched `ACL_USER_OBJ`.
    Owner,
    /// The caller matched an `ACL_USER` entry.
    NamedUser,
    /// The caller matched the owning group or at least one `ACL_GROUP` entry.
    GroupClass,
    /// The caller matched no owner, named user, or group-class entry.
    Other,
}

/// Mask-aware permission evaluation result for a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PosixAclPermissionPlan {
    /// ACL class that supplied the raw permission bits.
    pub class: PosixAclPermissionClass,
    /// Permission bits before `ACL_MASK` is applied.
    pub raw_perm: u8,
    /// Mask permission bits when the selected class is mask-constrained.
    pub mask_perm: Option<u8>,
    /// Effective permission bits after applying `mask_perm`.
    pub effective_perm: u8,
}

impl PosixAclPermissionPlan {
    fn new(class: PosixAclPermissionClass, raw_perm: u8, mask_perm: Option<u8>) -> Self {
        let raw_perm = raw_perm & 0x7;
        let mask_perm = mask_perm.map(|perm| perm & 0x7);
        let effective_perm = mask_perm.map_or(raw_perm, |mask| raw_perm & mask);
        Self {
            class,
            raw_perm,
            mask_perm,
            effective_perm,
        }
    }
}

/// ACL entry class affected by a chmod-style mode synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosixAclModeSyncTarget {
    /// The owning-user ACL entry.
    UserObj,
    /// The owning-group ACL entry.
    GroupObj,
    /// The group-class mask ACL entry.
    Mask,
    /// The other ACL entry.
    Other,
}

/// One permission change planned for an ACL mode synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PosixAclModeSyncChange {
    /// Entry index in the original ACL.
    pub index: usize,
    /// ACL tag for the changed entry.
    pub tag: u16,
    /// ACL id for the changed entry.
    pub id: u32,
    /// Semantic target updated by the mode synchronization.
    pub target: PosixAclModeSyncTarget,
    /// Permission bits before the synchronization.
    pub old_perm: u16,
    /// Permission bits after the synchronization.
    pub new_perm: u16,
}

/// Deterministic plan for synchronizing a POSIX access ACL with mode bits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixAclModeSyncPlan {
    /// Owner permission bits derived from `new_mode`.
    pub owner_perm: u16,
    /// Group-class permission bits derived from `new_mode`.
    pub group_perm: u16,
    /// Other permission bits derived from `new_mode`.
    pub other_perm: u16,
    /// Full ACL after applying the synchronization.
    pub updated_acl: PosixAcl,
    /// Entries whose permission bits changed.
    pub changes: Vec<PosixAclModeSyncChange>,
}

/// Deterministic default-ACL inheritance plan for file or directory creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixAclDefaultInheritancePlan {
    /// Access ACL to install on the new child inode.
    pub child_access_acl: Option<PosixAcl>,
    /// Default ACL to install on the new child directory.
    pub child_default_acl: Option<PosixAcl>,
}

impl PosixAclDefaultInheritancePlan {
    /// Return an inheritance plan that installs no ACL xattrs.
    #[must_use]
    pub const fn no_inheritance() -> Self {
        Self {
            child_access_acl: None,
            child_default_acl: None,
        }
    }

    /// Whether this plan installs at least one inherited ACL.
    #[must_use]
    pub const fn is_inheriting(&self) -> bool {
        self.child_access_acl.is_some() || self.child_default_acl.is_some()
    }
}

/// Structural validation errors for access ACL planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosixAclStructureError {
    /// Entry count exceeds `MAX_ACL_ENTRIES` (32).
    TooManyEntries,
    /// Tag value is not one of the known ACL tag constants.
    InvalidTag,
    /// Permission bits exceed the allowed 0..7 range.
    InvalidPerm,
    /// Non-id-bearing entries must use id 0.
    InvalidSpecialEntryId,
    /// The required owner entry is missing.
    MissingUserObj,
    /// The required owning-group entry is missing.
    MissingGroupObj,
    /// The required other entry is missing.
    MissingOther,
    /// Named user or group entries require a mask entry.
    MissingMaskForNamedEntries,
    /// More than one owner entry was present.
    DuplicateUserObj,
    /// More than one owning-group entry was present.
    DuplicateGroupObj,
    /// More than one mask entry was present.
    DuplicateMask,
    /// More than one other entry was present.
    DuplicateOther,
    /// More than one named-user entry used the same uid.
    DuplicateNamedUser,
    /// More than one named-group entry used the same gid.
    DuplicateNamedGroup,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error cases for ACL decode operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclError {
    /// Payload too short (fewer than 4 bytes).
    TooShort,
    /// Version field does not match `POSIX_ACL_XATTR_VERSION` (0x0002).
    UnsupportedVersion,
    /// Payload length is not `4 + 8*N` for some integer N.
    BadLength,
    /// Entry count exceeds `MAX_ACL_ENTRIES` (32).
    TooManyEntries,
    /// Tag value is not one of the known ACL tag constants.
    InvalidTag,
    /// Permission bits exceed the allowed 0..7 range.
    InvalidPerm,
    /// BLAKE3-256 hash verification failed: data was corrupted or tampered.
    ChecksumMismatch,
    /// Sealed ACL blob is too short to contain a BLAKE3-256 hash prefix.
    SealedBlobTooShort { len: usize, min: usize },
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

/// Decode a Linux binary POSIX ACL xattr payload into a `PosixAcl`.
///
/// The payload format is:
/// - 4 bytes: version (u32 LE, must be `0x0002`)
/// - N × 8 bytes: entries, each `(tag u16 LE, perm u16 LE, id u32 LE)`
pub fn decode_posix_acl_xattr(data: &[u8]) -> Result<PosixAcl, AclError> {
    // Minimum length: version (4 bytes) + at least 1 entry (8 bytes) = 12.
    // But we'll validate incrementally.
    if data.len() < 4 {
        return Err(AclError::TooShort);
    }

    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if version != POSIX_ACL_XATTR_VERSION {
        return Err(AclError::UnsupportedVersion);
    }

    let remaining = &data[4..];
    if remaining.len() % 8 != 0 {
        return Err(AclError::BadLength);
    }

    let entry_count = remaining.len() / 8;
    if entry_count > MAX_ACL_ENTRIES as usize {
        return Err(AclError::TooManyEntries);
    }

    let mut entries: PosixAcl = Vec::with_capacity(entry_count);

    for chunk in remaining.chunks_exact(8) {
        let tag = u16::from_le_bytes([chunk[0], chunk[1]]);
        let perm = u16::from_le_bytes([chunk[2], chunk[3]]);
        let id = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);

        if perm > 0x7 {
            return Err(AclError::InvalidPerm);
        }

        match tag {
            ACL_USER_OBJ | ACL_USER | ACL_GROUP_OBJ | ACL_GROUP | ACL_MASK | ACL_OTHER => {}
            _ => return Err(AclError::InvalidTag),
        }

        entries.push(PosixAclEntry { tag, perm, id });
    }

    Ok(entries)
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

/// Encode a `PosixAcl` into the Linux binary xattr format.
///
/// The output is `4 + 8 * entries.len()` bytes: version u32 LE followed by
/// each entry packed as `(tag u16 LE, perm u16 LE, id u32 LE)`.
pub fn encode_posix_acl_xattr(entries: &[PosixAclEntry]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + 8 * entries.len());

    // version
    buf.extend_from_slice(&POSIX_ACL_XATTR_VERSION.to_le_bytes());

    // entries
    for e in entries {
        buf.extend_from_slice(&e.tag.to_le_bytes());
        buf.extend_from_slice(&e.perm.to_le_bytes());
        buf.extend_from_slice(&e.id.to_le_bytes());
    }

    buf
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // -- round-trip tests ---------------------------------------------------

    #[test]
    fn round_trip_minimal_access_acl() {
        let acl = vec![
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
        let encoded = encode_posix_acl_xattr(&acl);
        let decoded = decode_posix_acl_xattr(&encoded).unwrap();
        assert_eq!(decoded, acl);
    }

    #[test]
    fn round_trip_with_named_user_and_mask() {
        let acl = vec![
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
                tag: ACL_MASK,
                perm: 6,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let encoded = encode_posix_acl_xattr(&acl);
        let decoded = decode_posix_acl_xattr(&encoded).unwrap();
        assert_eq!(decoded, acl);
    }

    #[test]
    fn round_trip_all_tag_types() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 5,
                id: 1001,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 4,
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
        ];
        let encoded = encode_posix_acl_xattr(&acl);
        let decoded = decode_posix_acl_xattr(&encoded).unwrap();
        assert_eq!(decoded, acl);
    }

    #[test]
    fn round_trip_boundary_perms() {
        let acl = vec![
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
        ];
        let encoded = encode_posix_acl_xattr(&acl);
        let decoded = decode_posix_acl_xattr(&encoded).unwrap();
        assert_eq!(decoded, acl);
    }

    #[test]
    fn round_trip_max_id_values() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 5,
                id: 0xFFFFFFFF,
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
        ];
        let encoded = encode_posix_acl_xattr(&acl);
        let decoded = decode_posix_acl_xattr(&encoded).unwrap();
        assert_eq!(decoded, acl);
    }

    // -- decode error tests ------------------------------------------------

    #[test]
    fn decode_too_short() {
        assert_eq!(decode_posix_acl_xattr(&[]), Err(AclError::TooShort));
        assert_eq!(
            decode_posix_acl_xattr(&[0x02, 0x00]),
            Err(AclError::TooShort)
        );
    }

    #[test]
    fn decode_unsupported_version() {
        let bad = [0x01, 0x00, 0x00, 0x00]; // version 1
        assert_eq!(
            decode_posix_acl_xattr(&bad),
            Err(AclError::UnsupportedVersion)
        );

        let bad2 = [0x03, 0x00, 0x00, 0x00]; // version 3
        assert_eq!(
            decode_posix_acl_xattr(&bad2),
            Err(AclError::UnsupportedVersion)
        );
    }

    #[test]
    fn decode_bad_length() {
        // 4-byte version + 9 trailing bytes (not multiple of 8)
        let mut bad = vec![0x02, 0x00, 0x00, 0x00];
        bad.extend_from_slice(&[0; 9]);
        assert_eq!(decode_posix_acl_xattr(&bad), Err(AclError::BadLength));
    }

    #[test]
    fn decode_too_many_entries() {
        // Create 33 entries in a valid binary blob
        let entry = PosixAclEntry {
            tag: ACL_USER_OBJ,
            perm: 7,
            id: 0,
        };
        let mut acl = Vec::with_capacity(33);
        for _ in 0..33 {
            acl.push(entry);
        }
        let encoded = encode_posix_acl_xattr(&acl);
        assert_eq!(
            decode_posix_acl_xattr(&encoded),
            Err(AclError::TooManyEntries)
        );
    }

    #[test]
    fn decode_invalid_tag() {
        // tag 0x00 is not valid
        let mut buf = vec![0x02, 0x00, 0x00, 0x00]; // version 2
        buf.extend_from_slice(&0x00u16.to_le_bytes()); // bad tag
        buf.extend_from_slice(&0x07u16.to_le_bytes()); // perm
        buf.extend_from_slice(&0u32.to_le_bytes()); // id
        assert_eq!(decode_posix_acl_xattr(&buf), Err(AclError::InvalidTag));
    }

    #[test]
    fn decode_invalid_perm() {
        // perm 0x08 exceeds 0..7
        let mut buf = vec![0x02, 0x00, 0x00, 0x00]; // version 2
        buf.extend_from_slice(&ACL_USER_OBJ.to_le_bytes());
        buf.extend_from_slice(&0x08u16.to_le_bytes()); // perm = 8
        buf.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(decode_posix_acl_xattr(&buf), Err(AclError::InvalidPerm));
    }

    #[test]
    fn decode_empty_acl_is_ok() {
        // 0 entries is valid (used for deleting an ACL via setxattr)
        let buf = [0x02, 0x00, 0x00, 0x00]; // version 2, 0 entries
        let decoded = decode_posix_acl_xattr(&buf).unwrap();
        assert!(decoded.is_empty());
    }

    // -- encode tests ------------------------------------------------------

    #[test]
    fn encode_empty_acl() {
        let encoded = encode_posix_acl_xattr(&[]);
        assert_eq!(encoded.len(), 4);
        assert_eq!(&encoded[..4], &POSIX_ACL_XATTR_VERSION.to_le_bytes());
    }

    #[test]
    fn encode_preserves_order() {
        let acl = vec![
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
        let encoded = encode_posix_acl_xattr(&acl);
        let decoded = decode_posix_acl_xattr(&encoded).unwrap();
        // Decoded order must match encoded order entry-by-entry
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].tag, ACL_USER_OBJ);
        assert_eq!(decoded[1].tag, ACL_OTHER);
    }

    #[test]
    fn encode_deterministic() {
        let acl = vec![PosixAclEntry {
            tag: ACL_USER_OBJ,
            perm: 6,
            id: 0,
        }];
        let a = encode_posix_acl_xattr(&acl);
        let b = encode_posix_acl_xattr(&acl);
        assert_eq!(a, b);
    }

    // -- constant tests ----------------------------------------------------

    #[test]
    fn version_constant_matches_wire() {
        // POSIX_ACL_XATTR_VERSION must be 2 on Linux
        assert_eq!(POSIX_ACL_XATTR_VERSION, 0x0002);
    }

    #[test]
    fn max_entries_bound() {
        // 32 entries at 8 bytes each = 256 bytes of entries + 4 bytes version
        let mut entries = Vec::with_capacity(32);
        for _ in 0..32 {
            entries.push(PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            });
        }
        let encoded = encode_posix_acl_xattr(&entries);
        assert_eq!(encoded.len(), 4 + 32 * 8);
        assert!(decode_posix_acl_xattr(&encoded).is_ok());
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
        let mut seen = alloc::vec::Vec::new();
        for t in &tags {
            assert!(!seen.contains(t), "duplicate tag {t:#06x}");
            seen.push(*t);
        }
    }
    // -- AclType tests ---------------------------------------------------

    #[test]
    fn acl_type_access_xattr_name() {
        assert_eq!(AclType::Access.xattr_name(), b"system.posix_acl_access");
    }

    #[test]
    fn acl_type_default_xattr_name() {
        assert_eq!(AclType::Default.xattr_name(), b"system.posix_acl_default");
    }

    #[test]
    fn acl_type_clone_and_eq() {
        assert_eq!(AclType::Access, AclType::Access);
        assert_ne!(AclType::Access, AclType::Default);
        let cloned = AclType::Access;
        assert_eq!(cloned, AclType::Access);
    }
    // -- has_required_entries tests -------------------------------------

    #[test]
    fn has_required_entries_accepts_minimal_acl() {
        let acl = vec![
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
        assert!(has_required_entries(&acl));
    }

    #[test]
    fn has_required_entries_rejects_missing_user_obj() {
        let acl = vec![
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
        assert!(!has_required_entries(&acl));
    }

    #[test]
    fn has_required_entries_rejects_missing_group_obj() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 5,
                id: 0,
            },
        ];
        assert!(!has_required_entries(&acl));
    }

    #[test]
    fn has_required_entries_rejects_missing_other() {
        let acl = vec![
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
        ];
        assert!(!has_required_entries(&acl));
    }

    #[test]
    fn has_required_entries_rejects_named_without_mask() {
        let acl = vec![
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
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        assert!(!has_required_entries(&acl));
    }

    #[test]
    fn has_required_entries_accepts_named_with_mask() {
        let acl = vec![
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
        ];
        assert!(has_required_entries(&acl));
    }
}

// ===========================================================================
// Phase 2: ACL evaluation and mode↔ACL synchronisation
// ===========================================================================

// ---------------------------------------------------------------------------
// Helper: find an entry by tag
// ---------------------------------------------------------------------------

/// Return the first entry with the given tag, if any.
fn find_entry(acl: &[PosixAclEntry], tag: u16) -> Option<&PosixAclEntry> {
    acl.iter().find(|e| e.tag == tag)
}

/// Return the first entry with the given tag, if any.
#[must_use]
pub fn find_posix_acl_entry(acl: &[PosixAclEntry], tag: u16) -> Option<&PosixAclEntry> {
    find_entry(acl, tag)
}

/// Return the first named-user or named-group entry with the given id.
#[must_use]
pub fn find_named_posix_acl_entry(
    acl: &[PosixAclEntry],
    tag: u16,
    id: u32,
) -> Option<&PosixAclEntry> {
    match tag {
        ACL_USER | ACL_GROUP => acl.iter().find(|entry| entry.tag == tag && entry.id == id),
        _ => None,
    }
}

/// Validate that an access ACL has the singleton entries and mask shape needed
/// for deterministic POSIX access planning.
pub fn validate_posix_acl_access_structure(
    acl: &[PosixAclEntry],
) -> Result<(), PosixAclStructureError> {
    if acl.len() > MAX_ACL_ENTRIES as usize {
        return Err(PosixAclStructureError::TooManyEntries);
    }

    let mut user_obj_count = 0usize;
    let mut group_obj_count = 0usize;
    let mut mask_count = 0usize;
    let mut other_count = 0usize;
    let mut has_named_entry = false;

    for entry in acl {
        if entry.perm > 0x7 {
            return Err(PosixAclStructureError::InvalidPerm);
        }

        let special_id_is_valid = entry.id == 0 || entry.id == ACL_UNDEFINED_ID;

        match entry.tag {
            ACL_USER_OBJ => {
                if !special_id_is_valid {
                    return Err(PosixAclStructureError::InvalidSpecialEntryId);
                }
                user_obj_count += 1;
            }
            ACL_USER => {
                has_named_entry = true;
            }
            ACL_GROUP_OBJ => {
                if !special_id_is_valid {
                    return Err(PosixAclStructureError::InvalidSpecialEntryId);
                }
                group_obj_count += 1;
            }
            ACL_GROUP => {
                has_named_entry = true;
            }
            ACL_MASK => {
                if !special_id_is_valid {
                    return Err(PosixAclStructureError::InvalidSpecialEntryId);
                }
                mask_count += 1;
            }
            ACL_OTHER => {
                if !special_id_is_valid {
                    return Err(PosixAclStructureError::InvalidSpecialEntryId);
                }
                other_count += 1;
            }
            _ => return Err(PosixAclStructureError::InvalidTag),
        }
    }

    if user_obj_count == 0 {
        return Err(PosixAclStructureError::MissingUserObj);
    }
    if user_obj_count > 1 {
        return Err(PosixAclStructureError::DuplicateUserObj);
    }
    if group_obj_count == 0 {
        return Err(PosixAclStructureError::MissingGroupObj);
    }
    if group_obj_count > 1 {
        return Err(PosixAclStructureError::DuplicateGroupObj);
    }
    if other_count == 0 {
        return Err(PosixAclStructureError::MissingOther);
    }
    if other_count > 1 {
        return Err(PosixAclStructureError::DuplicateOther);
    }
    if mask_count > 1 {
        return Err(PosixAclStructureError::DuplicateMask);
    }
    if has_named_entry && mask_count == 0 {
        return Err(PosixAclStructureError::MissingMaskForNamedEntries);
    }

    for index in 0..acl.len() {
        let entry = acl[index];
        if entry.tag != ACL_USER && entry.tag != ACL_GROUP {
            continue;
        }

        for later in &acl[index + 1..] {
            if later.tag == entry.tag && later.id == entry.id {
                return if entry.tag == ACL_USER {
                    Err(PosixAclStructureError::DuplicateNamedUser)
                } else {
                    Err(PosixAclStructureError::DuplicateNamedGroup)
                };
            }
        }
    }

    Ok(())
}

/// Convenience: returns `true` when `validate_posix_acl_access_structure`
/// succeeds for `acl`.
#[must_use]
pub fn has_required_entries(acl: &[PosixAclEntry]) -> bool {
    validate_posix_acl_access_structure(acl).is_ok()
}

// ---------------------------------------------------------------------------
// apply_chmod_to_acl
// ---------------------------------------------------------------------------

/// Apply a `chmod(2)` mode change to an access ACL.
///
/// Returns a new `PosixAcl` with the equivalence entries updated to
/// reflect `new_mode`:
///
/// - `USER_OBJ.perm` ← `(new_mode >> 6) & 0x7`
/// - `GROUP_OBJ.perm` ← `(new_mode >> 3) & 0x7` when no `MASK` is present
/// - `OTHER.perm` ← `new_mode & 0x7`
/// - `MASK.perm` (if present) ← `(new_mode >> 3) & 0x7`
/// - Named `USER` and `GROUP` entries are **unchanged**.
///
/// This is called when the FUSE adapter handles a `setattr` with mode
/// change on an inode that carries an access ACL.
pub fn apply_chmod_to_acl(acl: &[PosixAclEntry], new_mode: u32) -> PosixAcl {
    let owner_perm = ((new_mode >> 6) & 0x7) as u16;
    let group_perm = ((new_mode >> 3) & 0x7) as u16;
    let other_perm = (new_mode & 0x7) as u16;
    let has_acl_mask = find_entry(acl, ACL_MASK).is_some();

    acl.iter()
        .map(|e| {
            let perm = match e.tag {
                ACL_USER_OBJ => owner_perm,
                ACL_GROUP_OBJ if !has_acl_mask => group_perm,
                ACL_OTHER => other_perm,
                ACL_MASK => group_perm,
                _ => e.perm, // named USER / GROUP unchanged
            };
            PosixAclEntry {
                tag: e.tag,
                perm,
                id: e.id,
            }
        })
        .collect()
}

/// Plan a chmod-style synchronization for a structurally valid access ACL.
///
/// The returned plan contains the complete updated ACL plus the exact entries
/// whose permission bits change:
///
/// - `ACL_USER_OBJ` receives owner bits from `new_mode`.
/// - `ACL_GROUP_OBJ` receives group bits from `new_mode` when no mask exists.
/// - `ACL_MASK`, when present, receives group bits from `new_mode`.
/// - `ACL_OTHER` receives other bits from `new_mode`.
/// - Named `ACL_USER` and `ACL_GROUP` entries are preserved.
pub fn plan_posix_acl_mode_sync(
    acl: &[PosixAclEntry],
    new_mode: u32,
) -> Result<PosixAclModeSyncPlan, PosixAclStructureError> {
    validate_posix_acl_access_structure(acl)?;

    let owner_perm = ((new_mode >> 6) & 0x7) as u16;
    let group_perm = ((new_mode >> 3) & 0x7) as u16;
    let other_perm = (new_mode & 0x7) as u16;
    let has_acl_mask = find_entry(acl, ACL_MASK).is_some();
    let mut updated_acl = Vec::with_capacity(acl.len());
    let mut changes = Vec::new();

    for (index, entry) in acl.iter().copied().enumerate() {
        let planned = match entry.tag {
            ACL_USER_OBJ => Some((PosixAclModeSyncTarget::UserObj, owner_perm)),
            ACL_GROUP_OBJ if !has_acl_mask => Some((PosixAclModeSyncTarget::GroupObj, group_perm)),
            ACL_GROUP_OBJ => None,
            ACL_MASK => Some((PosixAclModeSyncTarget::Mask, group_perm)),
            ACL_OTHER => Some((PosixAclModeSyncTarget::Other, other_perm)),
            ACL_USER | ACL_GROUP => None,
            _ => unreachable!("ACL structure was validated before planning"),
        };

        let mut updated_entry = entry;
        if let Some((target, new_perm)) = planned {
            updated_entry.perm = new_perm;
            if entry.perm != new_perm {
                changes.push(PosixAclModeSyncChange {
                    index,
                    tag: entry.tag,
                    id: entry.id,
                    target,
                    old_perm: entry.perm,
                    new_perm,
                });
            }
        }
        updated_acl.push(updated_entry);
    }

    Ok(PosixAclModeSyncPlan {
        owner_perm,
        group_perm,
        other_perm,
        updated_acl,
        changes,
    })
}
/// Build a minimal 3-entry access ACL from standard Unix mode bits.
///
/// Produces `[USER_OBJ, GROUP_OBJ, OTHER]` with permissions derived
/// directly from the mode.  This is the canonical on-media representation
/// when an inode has no explicit ACL set (for example, after
/// `removexattr("system.posix_acl_access")`).
#[must_use]
pub fn minimal_access_acl_from_mode(mode: u32) -> PosixAcl {
    use alloc::vec;
    vec![
        PosixAclEntry {
            tag: ACL_USER_OBJ,
            perm: ((mode >> 6) & 0x7) as u16,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_GROUP_OBJ,
            perm: ((mode >> 3) & 0x7) as u16,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_OTHER,
            perm: (mode & 0x7) as u16,
            id: 0,
        },
    ]
}

/// Build the child access ACL derived from a parent directory default ACL.
///
/// The requested create mode acts as a mask: it may remove permissions from
/// the parent default ACL but must not grant permissions absent from it. When
/// an ACL mask entry exists, group-class create mode bits mask `ACL_MASK`;
/// otherwise they mask `ACL_GROUP_OBJ`.
#[must_use]
pub fn access_acl_from_default_acl(
    parent_default_acl: &[PosixAclEntry],
    new_mode: u32,
) -> PosixAcl {
    let owner_mask = ((new_mode >> 6) & 0x7) as u16;
    let group_mask = ((new_mode >> 3) & 0x7) as u16;
    let other_mask = (new_mode & 0x7) as u16;
    let has_acl_mask = find_entry(parent_default_acl, ACL_MASK).is_some();

    parent_default_acl
        .iter()
        .map(|entry| {
            let perm = match entry.tag {
                ACL_USER_OBJ => entry.perm & owner_mask,
                ACL_GROUP_OBJ if !has_acl_mask => entry.perm & group_mask,
                ACL_MASK => entry.perm & group_mask,
                ACL_OTHER => entry.perm & other_mask,
                _ => entry.perm,
            };

            PosixAclEntry {
                tag: entry.tag,
                perm,
                id: entry.id,
            }
        })
        .collect()
}

/// Plan POSIX default-ACL inheritance for file or directory creation.
///
/// Empty parent default ACLs produce a deterministic no-op plan. Non-empty
/// parent default ACLs are validated with the same shape rules as access ACLs.
/// Files inherit only an access ACL. Directories inherit an access ACL plus a
/// verbatim copy of the parent default ACL.
pub fn plan_posix_acl_default_inheritance(
    parent_default_acl: &[PosixAclEntry],
    new_mode: u32,
    is_directory: bool,
) -> Result<PosixAclDefaultInheritancePlan, PosixAclStructureError> {
    if parent_default_acl.is_empty() {
        return Ok(PosixAclDefaultInheritancePlan::no_inheritance());
    }

    validate_posix_acl_access_structure(parent_default_acl)?;

    Ok(PosixAclDefaultInheritancePlan {
        child_access_acl: Some(access_acl_from_default_acl(parent_default_acl, new_mode)),
        child_default_acl: if is_directory {
            Some(parent_default_acl.to_vec())
        } else {
            None
        },
    })
}

/// Plan inherited xattrs from a parent directory's default ACL, validating
/// the parent default ACL before emitting encoded xattrs.
///
/// Returns an empty vector when the parent has no default ACL. For non-empty
/// input, the parent default ACL must have the same structure required for
/// access ACL planning: one owner entry, one group-owner entry, one other
/// entry, valid permissions, valid special-entry ids, no duplicate singleton
/// entries, no duplicate named uid/gid entries, and a mask whenever named
/// user/group entries are present.
pub fn plan_default_acl_inheritance_for_parent(
    parent_default_acl: &[PosixAclEntry],
    new_mode: u32,
    is_directory: bool,
) -> Result<Vec<PosixAclXattrPair>, PosixAclStructureError> {
    let mut xattrs = Vec::new();
    let plan = plan_posix_acl_default_inheritance(parent_default_acl, new_mode, is_directory)?;

    if let Some(access_acl) = plan.child_access_acl {
        xattrs.push((
            b"system.posix_acl_access" as &[u8],
            encode_posix_acl_xattr(&access_acl),
        ));
    }

    if let Some(default_acl) = plan.child_default_acl {
        xattrs.push((
            b"system.posix_acl_default" as &[u8],
            encode_posix_acl_xattr(&default_acl),
        ));
    }

    Ok(xattrs)
}

/// Compute inherited xattrs from a parent directory's default ACL.
///
/// Linux semantics (§6 of the POSIX ACL design doc):
/// - For files/symlinks: inherit only `system.posix_acl_access`, derived from
///   the parent's default ACL by masking it with the new inode's mode.
/// - For directories: inherit both `system.posix_acl_access` (mode-masked)
///   and `system.posix_acl_default` (copied verbatim from the parent).
///
/// Returns a `Vec` of `(xattr_name, encoded_value)` pairs ready to insert
/// into the new inode's xattr map.  Returns an empty `Vec` when the parent
/// has no default ACL or decoding fails (caller should check the parent
/// for the xattr before calling this function).
#[must_use]
pub fn default_acl_inheritance_for_parent(
    parent_default_acl: &[PosixAclEntry],
    new_mode: u32,
    is_directory: bool,
) -> Vec<PosixAclXattrPair> {
    let mut xattrs = Vec::new();

    if parent_default_acl.is_empty() {
        return xattrs;
    }

    let access_acl = access_acl_from_default_acl(parent_default_acl, new_mode);
    xattrs.push((
        b"system.posix_acl_access" as &[u8],
        encode_posix_acl_xattr(&access_acl),
    ));

    if is_directory {
        let default_encoded = encode_posix_acl_xattr(parent_default_acl);
        xattrs.push((b"system.posix_acl_default" as &[u8], default_encoded));
    }

    xattrs
}

// ---------------------------------------------------------------------------
// posix_mode_from_access_acl
// ---------------------------------------------------------------------------

/// Derive `st_mode` permission bits from an access ACL.
///
/// Preserves file-type and special bits (setuid/setgid/sticky) from
/// `old_mode` and replaces the permission bits:
///
/// - User bits ← `USER_OBJ.perm` (or `(old_mode >> 6) & 0x7` if missing)
/// - Group bits ← `MASK.perm` if `MASK` present, else `GROUP_OBJ.perm`
///   (or `(old_mode >> 3) & 0x7` if missing)
/// - Other bits ← `OTHER.perm` (or `old_mode & 0x7` if missing)
///
/// This is called after `setxattr("system.posix_acl_access", ...)` to
/// update the inode's visible `st_mode`.
pub fn posix_mode_from_access_acl(acl: &[PosixAclEntry], old_mode: u32) -> u32 {
    let type_and_special = old_mode & !0o777;

    let user_bits = find_entry(acl, ACL_USER_OBJ)
        .map(|e| e.perm & 0x7)
        .unwrap_or(((old_mode >> 6) & 0x7) as u16);

    let group_bits = if let Some(mask) = find_entry(acl, ACL_MASK) {
        mask.perm & 0x7
    } else if let Some(group_obj) = find_entry(acl, ACL_GROUP_OBJ) {
        group_obj.perm & 0x7
    } else {
        ((old_mode >> 3) & 0x7) as u16
    };

    let other_bits = find_entry(acl, ACL_OTHER)
        .map(|e| e.perm & 0x7)
        .unwrap_or((old_mode & 0x7) as u16);

    type_and_special | ((user_bits as u32) << 6) | ((group_bits as u32) << 3) | (other_bits as u32)
}

// ---------------------------------------------------------------------------
// posix_acl_perm_bits_for_caller
// ---------------------------------------------------------------------------

/// Plan POSIX access ACL evaluation for a specific caller.
///
/// The algorithm follows the Linux kernel convention:
///
/// 1. **Owner check.** If `caller_uid == file_uid`, return `USER_OBJ.perm`.
///    Falls back to owner bits from `mode_fallback` if `USER_OBJ` is missing.
///
/// 2. **Named user check.** Iterates named `USER` entries; the first match
///    on `entry.id == caller_uid` returns `entry.perm & MASK.perm` (when
///    `MASK` is present) or `entry.perm` directly.
///
/// 3. **Group class check.** If the caller's gid or any supplementary group
///    matches `file_gid` or any named `GROUP` entry's id:
///    - Start with `GROUP_OBJ.perm` if matching the owning group.
///    - OR-in each matching named `GROUP.perm`.
///    - Clamp by `MASK.perm` if `MASK` is present.
///
/// 4. **Other fallback.** Return `OTHER.perm`, or fall back to other bits
///    from `mode_fallback`.
pub fn plan_posix_acl_access_for_caller(
    acl: &[PosixAclEntry],
    file_uid: u32,
    file_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
    mode_fallback: u32,
) -> PosixAclPermissionPlan {
    let mask_perm = find_entry(acl, ACL_MASK).map(|entry| (entry.perm & 0x7) as u8);

    // Step 1: Owner check
    if caller_uid == file_uid {
        if let Some(owner) = find_entry(acl, ACL_USER_OBJ) {
            return PosixAclPermissionPlan::new(
                PosixAclPermissionClass::Owner,
                (owner.perm & 0x7) as u8,
                None,
            );
        }
        return PosixAclPermissionPlan::new(
            PosixAclPermissionClass::Owner,
            ((mode_fallback >> 6) & 0x7) as u8,
            None,
        );
    }

    // Step 2: Named user check
    for entry in acl.iter().filter(|e| e.tag == ACL_USER) {
        if entry.id == caller_uid {
            return PosixAclPermissionPlan::new(
                PosixAclPermissionClass::NamedUser,
                (entry.perm & 0x7) as u8,
                mask_perm,
            );
        }
    }

    // Step 3: Group class check
    let in_owning_group = caller_gid == file_gid || caller_groups.contains(&file_gid);

    let matches_named_group = acl
        .iter()
        .filter(|e| e.tag == ACL_GROUP)
        .any(|e| caller_gid == e.id || caller_groups.contains(&e.id));

    if in_owning_group || matches_named_group {
        let mut perm: u16 = 0;

        if in_owning_group {
            if let Some(group_obj) = find_entry(acl, ACL_GROUP_OBJ) {
                perm |= group_obj.perm & 0x7;
            } else {
                perm |= ((mode_fallback >> 3) & 0x7) as u16;
            }
        }

        for entry in acl.iter().filter(|e| e.tag == ACL_GROUP) {
            if caller_gid == entry.id || caller_groups.contains(&entry.id) {
                perm |= entry.perm & 0x7;
            }
        }

        return PosixAclPermissionPlan::new(
            PosixAclPermissionClass::GroupClass,
            (perm & 0x7) as u8,
            mask_perm,
        );
    }

    // Step 4: Other fallback
    if let Some(other) = find_entry(acl, ACL_OTHER) {
        return PosixAclPermissionPlan::new(
            PosixAclPermissionClass::Other,
            (other.perm & 0x7) as u8,
            None,
        );
    }
    PosixAclPermissionPlan::new(
        PosixAclPermissionClass::Other,
        (mode_fallback & 0x7) as u8,
        None,
    )
}

/// Validate an access ACL before planning effective caller permissions.
///
/// This keeps the legacy fallback behavior in `plan_posix_acl_access_for_caller`
/// available for incomplete ACL inputs while giving FUSE/permission callers a
/// deterministic path that rejects malformed access ACLs before evaluation.
pub fn plan_validated_posix_acl_access_for_caller(
    acl: &[PosixAclEntry],
    file_uid: u32,
    file_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
    mode_fallback: u32,
) -> Result<PosixAclPermissionPlan, PosixAclStructureError> {
    validate_posix_acl_access_structure(acl)?;
    Ok(plan_posix_acl_access_for_caller(
        acl,
        file_uid,
        file_gid,
        caller_uid,
        caller_gid,
        caller_groups,
        mode_fallback,
    ))
}

/// Evaluate a POSIX access ACL for a specific caller, returning the
/// effective rwx permission bits (0..7).
pub fn posix_acl_perm_bits_for_caller(
    acl: &[PosixAclEntry],
    file_uid: u32,
    file_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
    mode_fallback: u32,
) -> u8 {
    plan_posix_acl_access_for_caller(
        acl,
        file_uid,
        file_gid,
        caller_uid,
        caller_gid,
        caller_groups,
        mode_fallback,
    )
    .effective_perm
}

// ---------------------------------------------------------------------------
// AccessMask
// ---------------------------------------------------------------------------

/// Access rights requested by a caller (rwx bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessMask(u8);

impl AccessMask {
    /// Read access.
    pub const READ: u8 = 0x4;
    /// Write access.
    pub const WRITE: u8 = 0x2;
    /// Execute access.
    pub const EXECUTE: u8 = 0x1;

    /// Construct an `AccessMask` from raw bits (only 0..7 used).
    #[must_use]
    pub const fn new(bits: u8) -> Self {
        Self(bits & 0x7)
    }

    /// Whether read access is requested.
    #[must_use]
    pub const fn is_read(self) -> bool {
        self.0 & Self::READ != 0
    }

    /// Whether write access is requested.
    #[must_use]
    pub const fn is_write(self) -> bool {
        self.0 & Self::WRITE != 0
    }

    /// Whether execute access is requested.
    #[must_use]
    pub const fn is_execute(self) -> bool {
        self.0 & Self::EXECUTE != 0
    }

    /// Raw bits (0..7).
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// AclEvaluator
// ---------------------------------------------------------------------------

/// POSIX ACL evaluation engine.
///
/// Given a process uid/gid and a file's ACL, determines whether access
/// (read/write/execute) is granted following the POSIX ACL
/// most-specific-match algorithm (IEEE 1003.1e draft 17).
///
/// Evaluation order:
/// 1. If `caller_uid == file_uid`: use `USER_OBJ` entry (MASK not applied).
/// 2. Else if a named `USER` entry matches `caller_uid`: use that entry,
///    limited by `MASK` when present.
/// 3. Else if `caller_gid` or any supplementary group matches `GROUP_OBJ`
///    or a named `GROUP` entry: OR together all matching group permissions,
///    limited by `MASK` when present.
/// 4. Else: use `OTHER` entry (MASK not applied).
pub struct AclEvaluator;

impl AclEvaluator {
    /// Check whether the caller has the requested access to the file.
    ///
    /// Returns `true` when all requested access bits are granted.
    ///
    /// # Arguments
    ///
    /// * `acl` - The file's access ACL.
    /// * `file_uid` - Owner uid of the file.
    /// * `file_gid` - Owning gid of the file.
    /// * `caller_uid` - uid of the process requesting access.
    /// * `caller_gid` - gid of the process requesting access.
    /// * `groups` - Supplementary groups of the process.
    /// * `requested` - Access bits requested (R/W/X).
    #[must_use]
    pub fn check_access(
        acl: &PosixAcl,
        file_uid: u32,
        file_gid: u32,
        caller_uid: u32,
        caller_gid: u32,
        groups: &[u32],
        requested: AccessMask,
    ) -> bool {
        let effective = posix_acl_perm_bits_for_caller(
            acl, file_uid, file_gid, caller_uid, caller_gid, groups, 0,
        );
        (effective & requested.bits()) == requested.bits()
    }

    /// Compute the effective file mode bits from an access ACL.
    ///
    /// Returns the low 9 bits (0..0o777) that correspond to the ACL's
    /// permission structure:
    /// - Owner bits: from `USER_OBJ` entry.
    /// - Group bits: from `MASK` (when present) or `GROUP_OBJ`.
    /// - Other bits: from `OTHER` entry.
    ///
    /// When a required entry is missing, the corresponding bits are 0.
    #[must_use]
    pub fn effective_mode(acl: &PosixAcl) -> u32 {
        posix_mode_from_access_acl(acl, 0) & 0o777
    }
}

// =======================================================================
// Phase 2: ACL evaluation and mode↔ACL synchronisation tests

// ===========================================================================
// Tests: Phase 2 — ACL evaluation and mode↔ACL synchronisation
// ===========================================================================

#[cfg(test)]
mod phase2_tests {
    use super::*;
    use alloc::vec;

    // -- apply_chmod_to_acl ------------------------------------------------

    #[test]
    fn chmod_sync_apply_updates_mask_when_present() {
        let acl = vec![
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
                perm: 5,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 3,
                id: 500,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 5,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 4,
                id: 0,
            },
        ];
        let updated = apply_chmod_to_acl(&acl, 0o640);
        assert_eq!(updated[0].perm, 6); // USER_OBJ ← rw-
        assert_eq!(updated[1].perm, 5); // named USER unchanged
        assert_eq!(updated[2].perm, 5); // GROUP_OBJ unchanged when MASK exists
        assert_eq!(updated[3].perm, 3); // named GROUP unchanged
        assert_eq!(updated[4].perm, 4); // MASK ← r--
        assert_eq!(updated[5].perm, 0); // OTHER ← ---
    }

    #[test]
    fn chmod_all_possible_modes() {
        for mode in 0u32..512 {
            let acl = vec![
                PosixAclEntry {
                    tag: ACL_USER_OBJ,
                    perm: 7,
                    id: 0,
                },
                PosixAclEntry {
                    tag: ACL_GROUP_OBJ,
                    perm: 7,
                    id: 0,
                },
                PosixAclEntry {
                    tag: ACL_OTHER,
                    perm: 7,
                    id: 0,
                },
            ];
            let updated = apply_chmod_to_acl(&acl, mode);
            assert_eq!(updated[0].perm, ((mode >> 6) & 0x7) as u16);
            assert_eq!(updated[1].perm, ((mode >> 3) & 0x7) as u16);
            assert_eq!(updated[2].perm, (mode & 0x7) as u16);
        }
    }

    #[test]
    fn chmod_without_mask_does_not_add_mask() {
        let acl = vec![
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
                perm: 0,
                id: 0,
            },
        ];
        let updated = apply_chmod_to_acl(&acl, 0o751);
        assert_eq!(updated.len(), 3);
        assert_eq!(updated.iter().filter(|e| e.tag == ACL_MASK).count(), 0);
    }

    #[test]
    fn chmod_preserves_entry_order() {
        let acl = vec![
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
                perm: 5,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 3,
                id: 500,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let updated = apply_chmod_to_acl(&acl, 0o777);
        for (i, (old, new)) in acl.iter().zip(updated.iter()).enumerate() {
            assert_eq!(old.tag, new.tag, "tag mismatch at index {i}");
            assert_eq!(old.id, new.id, "id mismatch at index {i}");
        }
    }

    // -- plan_posix_acl_mode_sync ------------------------------------------

    #[test]
    fn chmod_sync_plan_updates_mask_when_present() {
        let acl = vec![
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
                perm: 5,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 3,
                id: 500,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 5,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 4,
                id: 0,
            },
        ];

        let plan = plan_posix_acl_mode_sync(&acl, 0o640).unwrap();

        assert_eq!(plan.owner_perm, 6);
        assert_eq!(plan.group_perm, 4);
        assert_eq!(plan.other_perm, 0);
        assert_eq!(plan.updated_acl[0].perm, 6);
        assert_eq!(plan.updated_acl[2].perm, 5);
        assert_eq!(plan.updated_acl[4].perm, 4);
        assert_eq!(plan.updated_acl[5].perm, 0);
        assert_eq!(
            plan.changes,
            vec![
                PosixAclModeSyncChange {
                    index: 0,
                    tag: ACL_USER_OBJ,
                    id: 0,
                    target: PosixAclModeSyncTarget::UserObj,
                    old_perm: 7,
                    new_perm: 6,
                },
                PosixAclModeSyncChange {
                    index: 4,
                    tag: ACL_MASK,
                    id: 0,
                    target: PosixAclModeSyncTarget::Mask,
                    old_perm: 5,
                    new_perm: 4,
                },
                PosixAclModeSyncChange {
                    index: 5,
                    tag: ACL_OTHER,
                    id: 0,
                    target: PosixAclModeSyncTarget::Other,
                    old_perm: 4,
                    new_perm: 0,
                },
            ]
        );
    }

    #[test]
    fn chmod_sync_plan_updates_group_obj_without_mask() {
        let acl = minimal_access_acl_from_mode(0o754);

        let plan = plan_posix_acl_mode_sync(&acl, 0o640).unwrap();

        assert_eq!(plan.updated_acl, minimal_access_acl_from_mode(0o640));
        assert_eq!(
            plan.changes,
            vec![
                PosixAclModeSyncChange {
                    index: 0,
                    tag: ACL_USER_OBJ,
                    id: 0,
                    target: PosixAclModeSyncTarget::UserObj,
                    old_perm: 7,
                    new_perm: 6,
                },
                PosixAclModeSyncChange {
                    index: 1,
                    tag: ACL_GROUP_OBJ,
                    id: 0,
                    target: PosixAclModeSyncTarget::GroupObj,
                    old_perm: 5,
                    new_perm: 4,
                },
                PosixAclModeSyncChange {
                    index: 2,
                    tag: ACL_OTHER,
                    id: 0,
                    target: PosixAclModeSyncTarget::Other,
                    old_perm: 4,
                    new_perm: 0,
                },
            ]
        );
    }

    #[test]
    fn chmod_sync_plan_preserves_named_entries() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 2,
                id: 1000,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 4,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 1,
                id: 500,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 4,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];

        let plan = plan_posix_acl_mode_sync(&acl, 0o640).unwrap();

        assert_eq!(plan.updated_acl[1], acl[1]);
        assert_eq!(plan.updated_acl[3], acl[3]);
        assert!(plan
            .changes
            .iter()
            .all(|change| { change.tag != ACL_USER && change.tag != ACL_GROUP }));
    }

    #[test]
    fn chmod_sync_plan_projects_mask_and_preserves_default_acl_state() {
        let access_acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 7,
                id: 1000,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 6,
                id: 2000,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 5,
                id: 0,
            },
        ];
        let default_acl = vec![
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
                perm: 1,
                id: 0,
            },
        ];
        let default_acl_before = default_acl.clone();

        let plan = plan_posix_acl_mode_sync(&access_acl, 0o100640).unwrap();

        assert_eq!(plan.owner_perm, 6);
        assert_eq!(plan.group_perm, 4);
        assert_eq!(plan.other_perm, 0);
        assert_eq!(
            find_named_posix_acl_entry(&plan.updated_acl, ACL_USER, 1000),
            find_named_posix_acl_entry(&access_acl, ACL_USER, 1000)
        );
        assert_eq!(
            find_named_posix_acl_entry(&plan.updated_acl, ACL_GROUP, 2000),
            find_named_posix_acl_entry(&access_acl, ACL_GROUP, 2000)
        );
        assert_eq!(
            find_posix_acl_entry(&plan.updated_acl, ACL_GROUP_OBJ)
                .unwrap()
                .perm,
            7
        );
        assert_eq!(
            find_posix_acl_entry(&plan.updated_acl, ACL_MASK)
                .unwrap()
                .perm,
            4
        );

        let projected_mode = posix_mode_from_access_acl(&plan.updated_acl, 0o040777);
        assert_eq!(projected_mode, 0o040640);

        let named_user_plan =
            plan_posix_acl_access_for_caller(&plan.updated_acl, 1, 2, 1000, 3, &[], 0);
        assert_eq!(named_user_plan.raw_perm, 7);
        assert_eq!(named_user_plan.mask_perm, Some(4));
        assert_eq!(named_user_plan.effective_perm, 4);

        let named_group_plan =
            plan_posix_acl_access_for_caller(&plan.updated_acl, 1, 2, 3000, 2000, &[], 0);
        assert_eq!(named_group_plan.raw_perm, 6);
        assert_eq!(named_group_plan.mask_perm, Some(4));
        assert_eq!(named_group_plan.effective_perm, 4);
        assert_eq!(default_acl, default_acl_before);
    }

    #[test]
    fn chmod_sync_plan_noop_has_empty_changes() {
        let acl = minimal_access_acl_from_mode(0o640);

        let plan = plan_posix_acl_mode_sync(&acl, 0o640).unwrap();

        assert_eq!(plan.updated_acl, acl);
        assert!(plan.changes.is_empty());
    }

    #[test]
    fn chmod_sync_plan_rejects_invalid_access_acl() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 4,
                id: 0,
            },
        ];

        assert_eq!(
            plan_posix_acl_mode_sync(&acl, 0o640),
            Err(PosixAclStructureError::MissingOther)
        );
    }

    // -- posix_mode_from_access_acl -----------------------------------------

    #[test]
    fn mode_from_acl_with_mask() {
        let acl = vec![
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
                tag: ACL_MASK,
                perm: 5,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 1,
                id: 0,
            },
        ];
        let mode = posix_mode_from_access_acl(&acl, 0);
        assert_eq!(mode & 0o777, 0o651);
    }

    #[test]
    fn mode_from_acl_without_mask_uses_group_obj() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
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
        let mode = posix_mode_from_access_acl(&acl, 0);
        assert_eq!(mode & 0o777, 0o744);
    }

    #[test]
    fn mode_from_acl_preserves_file_type_and_special_bits() {
        let acl = vec![
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
        let old_mode = 0o407755;
        let mode = posix_mode_from_access_acl(&acl, old_mode);
        assert_eq!(mode, 0o407755);
    }

    #[test]
    fn mode_from_acl_missing_user_obj_falls_back() {
        let acl = vec![
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
        let old_mode = 0o755;
        let mode = posix_mode_from_access_acl(&acl, old_mode);
        assert_eq!(mode & 0o700, 0o700);
        assert_eq!((mode >> 3) & 0x7, 4);
        assert_eq!(mode & 0x7, 4);
    }

    #[test]
    fn mode_from_acl_missing_group_falls_back() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 6,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let old_mode = 0o750;
        let mode = posix_mode_from_access_acl(&acl, old_mode);
        assert_eq!(mode & 0o700, 0o600);
        assert_eq!((mode >> 3) & 0x7, 5);
        assert_eq!(mode & 0x7, 0);
    }

    #[test]
    fn mode_from_acl_missing_other_falls_back() {
        let acl = vec![
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
        ];
        let old_mode = 0o751;
        let mode = posix_mode_from_access_acl(&acl, old_mode);
        assert_eq!(mode & 0x7, 1);
    }

    #[test]
    fn mode_from_acl_empty_acl_falls_back_entirely() {
        let old_mode = 0o755;
        let mode = posix_mode_from_access_acl(&[], old_mode);
        assert_eq!(mode & 0o777, 0o755);
    }

    // -- planning helpers --------------------------------------------------

    #[test]
    fn find_helpers_locate_singletons_and_named_entries() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 5,
                id: 1001,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 4,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 2,
                id: 300,
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
        ];

        assert_eq!(find_posix_acl_entry(&acl, ACL_MASK).unwrap().perm, 6);
        assert_eq!(
            find_named_posix_acl_entry(&acl, ACL_USER, 1001)
                .unwrap()
                .perm,
            5
        );
        assert_eq!(
            find_named_posix_acl_entry(&acl, ACL_GROUP, 300)
                .unwrap()
                .perm,
            2
        );
        assert!(find_named_posix_acl_entry(&acl, ACL_MASK, 0).is_none());
    }

    #[test]
    fn validate_access_structure_accepts_minimal_acl() {
        let acl = minimal_access_acl_from_mode(0o750);
        assert_eq!(validate_posix_acl_access_structure(&acl), Ok(()));
    }

    #[test]
    fn validate_access_structure_accepts_mask_without_named_entries() {
        let acl = vec![
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
                tag: ACL_MASK,
                perm: 4,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];

        assert_eq!(validate_posix_acl_access_structure(&acl), Ok(()));
    }

    #[test]
    fn validate_access_structure_accepts_linux_undefined_special_ids() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 4,
                id: ACL_UNDEFINED_ID,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 7,
                id: ACL_UNDEFINED_ID,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 6,
                id: ACL_UNDEFINED_ID,
            },
        ];

        assert_eq!(validate_posix_acl_access_structure(&acl), Ok(()));
        assert_eq!(posix_mode_from_access_acl(&acl, 0o100644), 0o100476);
    }

    #[test]
    fn validate_access_structure_requires_mask_for_named_entries() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 5,
                id: 1001,
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
        ];

        assert_eq!(
            validate_posix_acl_access_structure(&acl),
            Err(PosixAclStructureError::MissingMaskForNamedEntries)
        );
    }

    #[test]
    fn validate_access_structure_rejects_duplicate_named_ids() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 4,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 2,
                id: 300,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 1,
                id: 300,
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
        ];

        assert_eq!(
            validate_posix_acl_access_structure(&acl),
            Err(PosixAclStructureError::DuplicateNamedGroup)
        );
    }

    #[test]
    fn validate_access_structure_rejects_nonzero_special_entry_id() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 99,
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
        ];

        assert_eq!(
            validate_posix_acl_access_structure(&acl),
            Err(PosixAclStructureError::InvalidSpecialEntryId)
        );
    }

    #[test]
    fn access_plan_owner_bypasses_mask() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];

        let plan = plan_posix_acl_access_for_caller(&acl, 1000, 100, 1000, 100, &[], 0);
        assert_eq!(plan.class, PosixAclPermissionClass::Owner);
        assert_eq!(plan.raw_perm, 7);
        assert_eq!(plan.mask_perm, None);
        assert_eq!(plan.effective_perm, 7);
    }

    #[test]
    fn access_plan_owner_precedes_named_user_and_group_mask_matches() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 0,
                id: 1000,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 7,
                id: 300,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];

        let plan =
            plan_validated_posix_acl_access_for_caller(&acl, 1000, 200, 1000, 200, &[300], 0)
                .unwrap();

        assert_eq!(plan.class, PosixAclPermissionClass::Owner);
        assert_eq!(plan.raw_perm, 7);
        assert_eq!(plan.mask_perm, None);
        assert_eq!(plan.effective_perm, 7);
        assert_eq!(
            posix_acl_perm_bits_for_caller(&acl, 1000, 200, 1000, 200, &[300], 0),
            7
        );
    }

    #[test]
    fn access_plan_named_user_reports_masked_effective_perm() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 7,
                id: 1001,
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
        ];

        let plan = plan_posix_acl_access_for_caller(&acl, 1000, 100, 1001, 200, &[], 0);
        assert_eq!(plan.class, PosixAclPermissionClass::NamedUser);
        assert_eq!(plan.raw_perm, 7);
        assert_eq!(plan.mask_perm, Some(5));
        assert_eq!(plan.effective_perm, 5);
    }

    #[test]
    fn access_plan_named_user_precedes_owning_and_named_group_matches() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 7,
                id: 1001,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 1,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 1,
                id: 300,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 4,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];

        let plan =
            plan_validated_posix_acl_access_for_caller(&acl, 1000, 500, 1001, 500, &[300], 0)
                .unwrap();
        assert_eq!(plan.class, PosixAclPermissionClass::NamedUser);
        assert_eq!(plan.raw_perm, 7);
        assert_eq!(plan.mask_perm, Some(4));
        assert_eq!(plan.effective_perm, 4);
        assert_eq!(
            posix_acl_perm_bits_for_caller(&acl, 1000, 500, 1001, 500, &[300], 0),
            4
        );
    }

    #[test]
    fn access_plan_group_class_reports_union_before_mask() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 1,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 6,
                id: 300,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 4,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];

        let plan = plan_posix_acl_access_for_caller(&acl, 1000, 500, 1001, 500, &[300], 0);
        assert_eq!(plan.class, PosixAclPermissionClass::GroupClass);
        assert_eq!(plan.raw_perm, 7);
        assert_eq!(plan.mask_perm, Some(4));
        assert_eq!(plan.effective_perm, 4);
    }

    #[test]
    fn validated_access_plan_owner_bypasses_mask() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];

        let plan =
            plan_validated_posix_acl_access_for_caller(&acl, 1000, 100, 1000, 200, &[], 0).unwrap();
        assert_eq!(plan.class, PosixAclPermissionClass::Owner);
        assert_eq!(plan.raw_perm, 7);
        assert_eq!(plan.mask_perm, None);
        assert_eq!(plan.effective_perm, 7);
    }

    #[test]
    fn validated_access_plan_named_user_applies_mask() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 7,
                id: 1001,
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
        ];

        let plan =
            plan_validated_posix_acl_access_for_caller(&acl, 1000, 100, 1001, 200, &[], 0).unwrap();
        assert_eq!(plan.class, PosixAclPermissionClass::NamedUser);
        assert_eq!(plan.raw_perm, 7);
        assert_eq!(plan.mask_perm, Some(5));
        assert_eq!(plan.effective_perm, 5);
    }

    #[test]
    fn validated_access_plan_group_class_applies_mask_to_union() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 1,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 6,
                id: 300,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 4,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];

        let plan =
            plan_validated_posix_acl_access_for_caller(&acl, 1000, 500, 1001, 500, &[300], 0)
                .unwrap();
        assert_eq!(plan.class, PosixAclPermissionClass::GroupClass);
        assert_eq!(plan.raw_perm, 7);
        assert_eq!(plan.mask_perm, Some(4));
        assert_eq!(plan.effective_perm, 4);
    }

    #[test]
    fn validated_access_plan_other_ignores_mask() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 6,
                id: 0,
            },
        ];

        let plan =
            plan_validated_posix_acl_access_for_caller(&acl, 1000, 100, 1001, 200, &[], 0).unwrap();
        assert_eq!(plan.class, PosixAclPermissionClass::Other);
        assert_eq!(plan.raw_perm, 6);
        assert_eq!(plan.mask_perm, None);
        assert_eq!(plan.effective_perm, 6);
    }

    #[test]
    fn validated_access_plan_rejects_named_entry_without_mask() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 7,
                id: 1001,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];

        assert_eq!(
            plan_validated_posix_acl_access_for_caller(&acl, 1000, 100, 1001, 200, &[], 0),
            Err(PosixAclStructureError::MissingMaskForNamedEntries)
        );
    }

    // -- posix_acl_perm_bits_for_caller ------------------------------------

    #[test]
    fn eval_owner_gets_owner_perm() {
        let acl = vec![
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
                perm: 0,
                id: 0,
            },
        ];
        let perm = posix_acl_perm_bits_for_caller(&acl, 1000, 100, 1000, 200, &[], 0);
        assert_eq!(perm, 6);
    }

    #[test]
    fn eval_owner_ignores_group_and_other() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 7,
                id: 0,
            },
        ];
        let perm = posix_acl_perm_bits_for_caller(&acl, 42, 0, 42, 100, &[100], 0);
        assert_eq!(perm, 7);
    }

    #[test]
    fn eval_named_user_match_without_mask() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 5,
                id: 1001,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let perm = posix_acl_perm_bits_for_caller(&acl, 1000, 100, 1001, 200, &[], 0);
        assert_eq!(perm, 5);
    }

    #[test]
    fn eval_named_user_match_with_mask() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 7,
                id: 1001,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 2,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let perm = posix_acl_perm_bits_for_caller(&acl, 1000, 100, 1001, 200, &[], 0);
        assert_eq!(perm, 2);
    }

    #[test]
    fn eval_named_user_first_match_wins() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 5,
                id: 1001,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 3,
                id: 1001,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let perm = posix_acl_perm_bits_for_caller(&acl, 1000, 100, 1001, 200, &[], 0);
        assert_eq!(perm, 5);
    }

    #[test]
    fn eval_named_user_no_match_falls_through() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 5,
                id: 1001,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 4,
                id: 0,
            },
        ];
        let perm = posix_acl_perm_bits_for_caller(&acl, 1000, 100, 1002, 200, &[], 0);
        assert_eq!(perm, 4);
    }

    #[test]
    fn eval_owning_group_match() {
        let acl = vec![
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
                perm: 0,
                id: 0,
            },
        ];
        let perm = posix_acl_perm_bits_for_caller(&acl, 1000, 500, 1001, 500, &[], 0);
        assert_eq!(perm, 5);
    }

    #[test]
    fn eval_supplementary_group_match() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 3,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let perm = posix_acl_perm_bits_for_caller(&acl, 1000, 500, 1001, 200, &[500], 0);
        assert_eq!(perm, 3);
    }

    #[test]
    fn eval_named_group_match() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 6,
                id: 300,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let perm = posix_acl_perm_bits_for_caller(&acl, 1000, 500, 1001, 300, &[], 0);
        assert_eq!(perm, 6);
    }

    #[test]
    fn eval_named_group_via_supplementary() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 3,
                id: 400,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let perm = posix_acl_perm_bits_for_caller(&acl, 1000, 500, 1001, 200, &[400], 0);
        assert_eq!(perm, 3);
    }

    #[test]
    fn eval_group_class_union_of_perms() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 1,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 2,
                id: 300,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let perm = posix_acl_perm_bits_for_caller(&acl, 1000, 500, 1001, 500, &[300], 0);
        assert_eq!(perm, 3);
    }

    #[test]
    fn eval_group_class_clamped_by_mask() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 1,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let perm = posix_acl_perm_bits_for_caller(&acl, 1000, 500, 1001, 500, &[], 0);
        assert_eq!(perm, 1);
    }

    #[test]
    fn eval_other_matches_non_owner_non_group() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 4,
                id: 0,
            },
        ];
        let perm = posix_acl_perm_bits_for_caller(&acl, 1000, 500, 1001, 200, &[], 0);
        assert_eq!(perm, 4);
    }

    #[test]
    fn eval_missing_user_obj_falls_back_to_mode() {
        let acl = vec![
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
        ];
        let perm = posix_acl_perm_bits_for_caller(&acl, 1000, 500, 1000, 200, &[], 0o755);
        assert_eq!(perm, 7);
    }

    #[test]
    fn eval_missing_other_falls_back_to_mode() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 0,
                id: 0,
            },
        ];
        let perm = posix_acl_perm_bits_for_caller(&acl, 1000, 500, 1001, 200, &[], 0o754);
        assert_eq!(perm, 4);
    }

    #[test]
    fn eval_empty_acl_all_fallback() {
        let perm = posix_acl_perm_bits_for_caller(&[], 1000, 500, 1000, 200, &[], 0o755);
        assert_eq!(perm, 7);

        let perm2 = posix_acl_perm_bits_for_caller(&[], 1000, 500, 1001, 500, &[], 0o755);
        assert_eq!(perm2, 5);

        let perm3 = posix_acl_perm_bits_for_caller(&[], 1000, 500, 1001, 200, &[], 0o755);
        assert_eq!(perm3, 5);
    }

    // -- Integration: chmod + eval roundtrip -------------------------------
    #[test]
    fn chmod_then_eval_reflects_new_mode() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 7,
                id: 0,
            },
        ];
        let updated = apply_chmod_to_acl(&acl, 0o640);
        let owner_perm = posix_acl_perm_bits_for_caller(&updated, 1000, 500, 1000, 200, &[], 0);
        let group_perm = posix_acl_perm_bits_for_caller(&updated, 1000, 500, 1001, 500, &[], 0);
        let other_perm = posix_acl_perm_bits_for_caller(&updated, 1000, 500, 1001, 200, &[], 0);
        assert_eq!(owner_perm, 6);
        assert_eq!(group_perm, 4);
        assert_eq!(other_perm, 0);
    }

    // -- Integration: mode_from_acl roundtrip ------------------------------

    #[test]
    fn mode_from_acl_reflects_acurate_perms() {
        let acl = vec![
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
                tag: ACL_MASK,
                perm: 5,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 1,
                id: 0,
            },
        ];
        let mode = posix_mode_from_access_acl(&acl, 0);
        assert_eq!((mode >> 6) & 0x7, 6);
        assert_eq!((mode >> 3) & 0x7, 5);
        assert_eq!(mode & 0x7, 1);
    }

    // -- minimal_access_acl_from_mode tests --------------------------------

    #[test]
    fn minimal_access_acl_from_mode_standard() {
        let acl = minimal_access_acl_from_mode(0o751);
        assert_eq!(acl.len(), 3);
        assert_eq!(acl[0].tag, ACL_USER_OBJ);
        assert_eq!(acl[0].perm, 7);
        assert_eq!(acl[1].tag, ACL_GROUP_OBJ);
        assert_eq!(acl[1].perm, 5);
        assert_eq!(acl[2].tag, ACL_OTHER);
        assert_eq!(acl[2].perm, 1);
    }

    #[test]
    fn minimal_access_acl_from_mode_zero() {
        let acl = minimal_access_acl_from_mode(0);
        assert_eq!(acl.len(), 3);
        assert!(acl.iter().all(|e| e.perm == 0));
    }

    #[test]
    fn minimal_access_acl_round_trips_through_mode() {
        let mode = 0o750;
        let acl = minimal_access_acl_from_mode(mode);
        let mode2 = posix_mode_from_access_acl(&acl, 0o000);
        assert_eq!(mode, mode2);
    }

    #[test]
    fn minimal_access_acl_applies_chmod() {
        let acl = minimal_access_acl_from_mode(0o755);
        let updated = apply_chmod_to_acl(&acl, 0o640);
        assert_eq!(updated[0].perm, 6); // USER_OBJ
        assert_eq!(updated[1].perm, 4); // GROUP_OBJ
        assert_eq!(updated[2].perm, 0); // OTHER
    }

    #[test]
    fn minimal_access_acl_encodes_and_decodes() {
        let acl = minimal_access_acl_from_mode(0o751);
        let encoded = encode_posix_acl_xattr(&acl);
        let decoded = decode_posix_acl_xattr(&encoded).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].perm, 7);
        assert_eq!(decoded[1].perm, 5);
        assert_eq!(decoded[2].perm, 1);
    }

    #[test]
    fn mode_from_minimal_acl_respects_all_bits() {
        let acl = minimal_access_acl_from_mode(0o777);
        let mode = posix_mode_from_access_acl(&acl, 0o000);
        assert_eq!(mode, 0o777);
    }

    // -- default_acl_inheritance_for_parent tests --------------------------

    #[test]
    fn default_acl_inheritance_empty() {
        // Empty parent ACL produces no inherited xattrs.
        let xattrs = default_acl_inheritance_for_parent(&[], 0o755, false);
        assert!(xattrs.is_empty());
        let xattrs = default_acl_inheritance_for_parent(&[], 0o755, true);
        assert!(xattrs.is_empty());
    }

    #[test]
    fn planned_default_acl_inheritance_empty_is_ok() {
        let plan = plan_posix_acl_default_inheritance(&[], 0o755, false).unwrap();
        assert_eq!(plan, PosixAclDefaultInheritancePlan::no_inheritance());
        assert!(!plan.is_inheriting());

        let xattrs = plan_default_acl_inheritance_for_parent(&[], 0o755, false).unwrap();
        assert!(xattrs.is_empty());

        let xattrs = plan_default_acl_inheritance_for_parent(&[], 0o755, true).unwrap();
        assert!(xattrs.is_empty());
    }

    #[test]
    fn planned_default_acl_inheritance_rejects_invalid_parent_structure() {
        let parent_default = vec![
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
        ];

        assert_eq!(
            plan_default_acl_inheritance_for_parent(&parent_default, 0o755, false),
            Err(PosixAclStructureError::MissingOther)
        );
    }

    #[test]
    fn planned_default_acl_inheritance_file_gets_access_only() {
        let parent_default = vec![
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
                tag: ACL_MASK,
                perm: 6,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 1,
                id: 0,
            },
        ];

        let xattrs =
            plan_default_acl_inheritance_for_parent(&parent_default, 0o640, false).unwrap();
        assert_eq!(xattrs.len(), 1);
        assert_eq!(xattrs[0].0, b"system.posix_acl_access");

        let decoded = decode_posix_acl_xattr(&xattrs[0].1).unwrap();
        assert_eq!(decoded[0].perm, 6);
        assert_eq!(decoded[1].perm, 5);
        assert_eq!(decoded[2].perm, 4);
        assert_eq!(decoded[3].perm, 4);
        assert_eq!(decoded[4].perm, 0);
    }

    #[test]
    fn default_acl_plan_masks_without_granting_parent_permissions() {
        let parent_default = minimal_access_acl_from_mode(0o640);

        let plan = plan_posix_acl_default_inheritance(&parent_default, 0o777, false).unwrap();

        assert!(plan.is_inheriting());
        assert_eq!(plan.child_default_acl, None);
        assert_eq!(plan.child_access_acl.unwrap(), parent_default);
    }

    #[test]
    fn default_acl_plan_directory_keeps_default_and_masks_access_mask_entry() {
        let parent_default = vec![
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
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 3,
                id: 2000,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 5,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 1,
                id: 0,
            },
        ];

        let plan = plan_posix_acl_default_inheritance(&parent_default, 0o730, true).unwrap();
        let access_acl = plan.child_access_acl.unwrap();

        assert_eq!(access_acl[0].perm, 7);
        assert_eq!(access_acl[1].perm, 6);
        assert_eq!(access_acl[2].perm, 7);
        assert_eq!(access_acl[3].perm, 3);
        assert_eq!(access_acl[4].perm, 1);
        assert_eq!(access_acl[5].perm, 0);
        assert_eq!(plan.child_default_acl.unwrap(), parent_default);
    }

    #[test]
    fn default_acl_plan_directory_preserves_named_entries_and_projected_mode() {
        let parent_default = vec![
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
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 5,
                id: 2000,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 5,
                id: 0,
            },
        ];

        let plan = plan_posix_acl_default_inheritance(&parent_default, 0o640, true).unwrap();
        assert!(plan.is_inheriting());

        let child_access_acl = plan.child_access_acl.as_ref().unwrap();
        assert_eq!(
            find_posix_acl_entry(child_access_acl, ACL_USER_OBJ)
                .unwrap()
                .perm,
            6
        );
        assert_eq!(
            find_posix_acl_entry(child_access_acl, ACL_GROUP_OBJ)
                .unwrap()
                .perm,
            7
        );
        assert_eq!(
            find_posix_acl_entry(child_access_acl, ACL_MASK)
                .unwrap()
                .perm,
            4
        );
        assert_eq!(
            find_posix_acl_entry(child_access_acl, ACL_OTHER)
                .unwrap()
                .perm,
            0
        );
        assert_eq!(
            find_named_posix_acl_entry(child_access_acl, ACL_USER, 1000)
                .unwrap()
                .perm,
            6
        );
        assert_eq!(
            find_named_posix_acl_entry(child_access_acl, ACL_GROUP, 2000)
                .unwrap()
                .perm,
            5
        );

        let projected_mode = posix_mode_from_access_acl(child_access_acl, 0o042777);
        assert_eq!(projected_mode, 0o042640);
        assert_eq!(plan.child_default_acl.as_ref().unwrap(), &parent_default);
    }

    #[test]
    fn planned_default_acl_inheritance_directory_copies_default_acl() {
        let parent_default = minimal_access_acl_from_mode(0o751);

        let xattrs = plan_default_acl_inheritance_for_parent(&parent_default, 0o755, true).unwrap();
        assert_eq!(xattrs.len(), 2);
        assert_eq!(xattrs[0].0, b"system.posix_acl_access");
        assert_eq!(xattrs[1].0, b"system.posix_acl_default");

        let decoded_default = decode_posix_acl_xattr(&xattrs[1].1).unwrap();
        assert_eq!(decoded_default, parent_default);
    }

    #[test]
    fn default_acl_inheritance_file_gets_access_only() {
        let parent_default = minimal_access_acl_from_mode(0o750);
        let xattrs = default_acl_inheritance_for_parent(&parent_default, 0o640, false);
        assert_eq!(xattrs.len(), 1);
        assert_eq!(xattrs[0].0, b"system.posix_acl_access");
        // Verify the decoded access ACL matches the chmod of parent default
        let decoded = decode_posix_acl_xattr(&xattrs[0].1).unwrap();
        assert_eq!(decoded[0].perm, 6); // user
        assert_eq!(decoded[1].perm, 4); // group
        assert_eq!(decoded[2].perm, 0); // other
    }

    #[test]
    fn default_acl_inheritance_directory_gets_both() {
        let parent_default = minimal_access_acl_from_mode(0o751);
        let xattrs = default_acl_inheritance_for_parent(&parent_default, 0o755, true);
        assert_eq!(xattrs.len(), 2);
        // Access ACL comes first
        assert_eq!(xattrs[0].0, b"system.posix_acl_access");
        // Default ACL copied verbatim
        assert_eq!(xattrs[1].0, b"system.posix_acl_default");
        let decoded_default = decode_posix_acl_xattr(&xattrs[1].1).unwrap();
        assert_eq!(decoded_default.len(), parent_default.len());
        assert_eq!(decoded_default[0].perm, parent_default[0].perm);
    }

    #[test]
    fn default_acl_inheritance_chmod_applied_to_access() {
        // Parent default 0o777, file mode 0o500 -> access ACL should have user=5,group=0,other=0
        let parent_default = minimal_access_acl_from_mode(0o777);
        let xattrs = default_acl_inheritance_for_parent(&parent_default, 0o500, false);
        let decoded = decode_posix_acl_xattr(&xattrs[0].1).unwrap();
        assert_eq!(decoded[0].perm, 5); // user_obj: r-x
        assert_eq!(decoded[1].perm, 0); // group_obj: ---
        assert_eq!(decoded[2].perm, 0); // other: ---
    }

    // ==================================================================
    // AclEvaluator tests
    // ==================================================================

    fn minimal_acl_with_mask() -> PosixAcl {
        vec![
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
        ]
    }

    // -- AclEvaluator::check_access -------------------------------------

    #[test]
    fn evaluator_owner_has_full_access() {
        let acl = minimal_acl_with_mask();
        // Owner (uid 0) gets USER_OBJ perm=7, no mask applied
        assert!(AclEvaluator::check_access(
            &acl,
            0,
            100,
            0,
            200,
            &[],
            AccessMask::new(7)
        ));
        assert!(AclEvaluator::check_access(
            &acl,
            0,
            100,
            0,
            200,
            &[],
            AccessMask::new(4)
        ));
        assert!(AclEvaluator::check_access(
            &acl,
            0,
            100,
            0,
            200,
            &[],
            AccessMask::new(2)
        ));
        assert!(AclEvaluator::check_access(
            &acl,
            0,
            100,
            0,
            200,
            &[],
            AccessMask::new(1)
        ));
    }

    #[test]
    fn evaluator_named_user_masked() {
        let acl = minimal_acl_with_mask();
        // Named user uid=1000: raw perm=5 (r-x), mask=5 => effective=5
        assert!(AclEvaluator::check_access(
            &acl,
            0,
            100,
            1000,
            200,
            &[],
            AccessMask::new(5)
        ));
        assert!(AclEvaluator::check_access(
            &acl,
            0,
            100,
            1000,
            200,
            &[],
            AccessMask::new(4)
        ));
        // Write (2) is not granted by perm=5 (r-x)
        assert!(!AclEvaluator::check_access(
            &acl,
            0,
            100,
            1000,
            200,
            &[],
            AccessMask::new(2)
        ));
        assert!(!AclEvaluator::check_access(
            &acl,
            0,
            100,
            1000,
            200,
            &[],
            AccessMask::new(7)
        ));
    }

    #[test]
    fn evaluator_group_match_by_gid() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 6,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        // Caller gid matches GROUP_OBJ (owning group)
        assert!(AclEvaluator::check_access(
            &acl,
            99,
            200,
            999,
            200,
            &[],
            AccessMask::new(6)
        ));
        assert!(AclEvaluator::check_access(
            &acl,
            99,
            200,
            999,
            200,
            &[],
            AccessMask::new(4)
        ));
        assert!(AclEvaluator::check_access(
            &acl,
            99,
            200,
            999,
            200,
            &[],
            AccessMask::new(2)
        ));
        assert!(!AclEvaluator::check_access(
            &acl,
            99,
            200,
            999,
            200,
            &[],
            AccessMask::new(1)
        ));
    }

    #[test]
    fn evaluator_group_match_by_supplementary() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 3,
                id: 500,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        // Caller gid=200, supplementary groups=[500] -> matches named GROUP id=500 perm=3
        assert!(AclEvaluator::check_access(
            &acl,
            99,
            100,
            999,
            200,
            &[500],
            AccessMask::new(3)
        ));
        assert!(AclEvaluator::check_access(
            &acl,
            99,
            100,
            999,
            200,
            &[500],
            AccessMask::new(2)
        ));
        assert!(AclEvaluator::check_access(
            &acl,
            99,
            100,
            999,
            200,
            &[500],
            AccessMask::new(1)
        ));
        assert!(!AclEvaluator::check_access(
            &acl,
            99,
            100,
            999,
            200,
            &[500],
            AccessMask::new(4)
        ));
    }

    #[test]
    fn evaluator_other_access() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 4,
                id: 0,
            },
        ];
        // Non-owner, non-group caller gets OTHER perm=4 (r--)
        assert!(AclEvaluator::check_access(
            &acl,
            0,
            100,
            999,
            200,
            &[],
            AccessMask::new(4)
        ));
        assert!(!AclEvaluator::check_access(
            &acl,
            0,
            100,
            999,
            200,
            &[],
            AccessMask::new(2)
        ));
        assert!(!AclEvaluator::check_access(
            &acl,
            0,
            100,
            999,
            200,
            &[],
            AccessMask::new(7)
        ));
    }

    #[test]
    fn evaluator_mask_limits_named_user() {
        // Named user uid=1000 raw perm=7 (rwx), mask=4 (r--) => effective=4
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 7,
                id: 1000,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 4,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        assert!(AclEvaluator::check_access(
            &acl,
            0,
            100,
            1000,
            200,
            &[],
            AccessMask::new(4)
        ));
        assert!(!AclEvaluator::check_access(
            &acl,
            0,
            100,
            1000,
            200,
            &[],
            AccessMask::new(2)
        ));
        assert!(!AclEvaluator::check_access(
            &acl,
            0,
            100,
            1000,
            200,
            &[],
            AccessMask::new(7)
        ));
    }

    #[test]
    fn evaluator_mask_limits_group_class() {
        // GROUP_OBJ perm=6 (rw-), MASK perm=2 (-w-), named GROUP id=500 perm=4 (r--)
        // Caller matches GROUP_OBJ by gid and named GROUP by supplementary
        // OR'd group perms = 6|4 = 6, masked by 2 => effective=2
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 0,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 6,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP,
                perm: 4,
                id: 500,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 2,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        // Caller gid=200 == file_gid, supp groups=[500] -> matches both
        assert!(AclEvaluator::check_access(
            &acl,
            99,
            200,
            999,
            200,
            &[500],
            AccessMask::new(2)
        ));
        assert!(!AclEvaluator::check_access(
            &acl,
            99,
            200,
            999,
            200,
            &[500],
            AccessMask::new(4)
        ));
    }

    #[test]
    fn evaluator_no_match_denied() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
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
        ];
        // Non-owner, non-group caller gets OTHER perm=0 => denied
        assert!(!AclEvaluator::check_access(
            &acl,
            0,
            100,
            999,
            200,
            &[],
            AccessMask::new(4)
        ));
        assert!(!AclEvaluator::check_access(
            &acl,
            0,
            100,
            999,
            200,
            &[],
            AccessMask::new(1)
        ));
        // Even with empty request, 0&0 == 0 => false? No: 0 & 0 == 0, 0 == 0 => true
        // Empty access mask should always succeed
        assert!(AclEvaluator::check_access(
            &acl,
            0,
            100,
            999,
            200,
            &[],
            AccessMask::new(0)
        ));
    }

    // -- AclEvaluator::effective_mode -----------------------------------

    #[test]
    fn evaluator_effective_mode_basic() {
        let acl = vec![
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
                perm: 4,
                id: 0,
            },
        ];
        assert_eq!(AclEvaluator::effective_mode(&acl), 0o754);
    }

    #[test]
    fn evaluator_effective_mode_with_mask() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 2,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 4,
                id: 0,
            },
        ];
        assert_eq!(AclEvaluator::effective_mode(&acl), 0o724);
    }

    #[test]
    fn evaluator_effective_mode_mask_overrides_group_obj() {
        let acl = vec![
            PosixAclEntry {
                tag: ACL_USER_OBJ,
                perm: 6,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_GROUP_OBJ,
                perm: 7,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_USER,
                perm: 5,
                id: 1000,
            },
            PosixAclEntry {
                tag: ACL_MASK,
                perm: 3,
                id: 0,
            },
            PosixAclEntry {
                tag: ACL_OTHER,
                perm: 1,
                id: 0,
            },
        ];
        // group bits come from MASK (3), not GROUP_OBJ (7)
        assert_eq!(AclEvaluator::effective_mode(&acl), 0o631);
    }
}
