//! FUSE `unlink` handler helpers -- name validation, sticky-bit
//! enforcement, read-only mount guard, and convenience entry-points for POSIX-compliant
//! file removal.
//!
//! Provides:
//! - [`validate_unlink_name`]: reject empty, overlong, dot/dotdot, NUL,
//!   and slash-containing names; returns `Ok(())` or a [`UnlinkError`].
//! - [`check_unlink_sticky_bit`]: enforce POSIX sticky-bit semantics
//!   (S_ISVTX) -- when the parent directory has the sticky bit set,
//!   only the file owner, directory owner, or superuser may unlink;
//!   returns `Ok(())` or a [`UnlinkError`].
//! - [`check_unlink_readonly`]: reject read-only mounts; returns
//!   `Ok(())` or a [`UnlinkError`].
//! - [`plan_unlink`]: combined name validation + sticky-bit +
//!   parent-directory permission check returning a validated
//!   [`UnlinkPlan`] or a [`UnlinkError`].
//! - [`UnlinkPlan`]: validated unlink request ready for backend dispatch.
//! - [`handle_unlink`]: canonical FUSE dispatch entry-point combining
//!   read-only guard, name validation, sticky-bit enforcement, and
//!   parent-directory permission checking; returns `Ok(`[`UnlinkPlan`]`)`
//!   or a [`UnlinkError`].
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::unlink;
//!
//! let plan = unlink::handle_unlink(
//!     b"myfile", false, false, true, false, false,
//!     0o300, 1000, 100, 1000, 100, &[], &mount_identity,
//! )?;
//! ```

use crate::errno;
use libc::c_int;
use std::fmt;

/// Maximum length of a single file-name component in bytes
/// (POSIX `NAME_MAX` on Linux).
pub const UNLINK_MAX_NAME_BYTES: usize = 255;

// ---------------------------------------------------------------------------
// UnlinkError -- domain error type for unlink(2) operations
// ---------------------------------------------------------------------------

/// Check that the caller has write and execute (search) permission
/// on the parent directory for an unlink operation.
///
/// POSIX requires both directory write permission (to remove the entry)
/// and directory search permission (to traverse to the entry).
pub fn check_unlink_parent_permission(
    parent_mode: u32,
    parent_uid: u32,
    parent_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
    mount_identity: &tidefs_permission::MountIdentity,
) -> Result<(), UnlinkError> {
    crate::access::check_fuse_access(
        parent_mode,
        parent_uid,
        parent_gid,
        caller_uid,
        caller_gid,
        caller_groups,
        crate::access::ACCESS_WRITE | crate::access::ACCESS_EXECUTE,
        mount_identity,
    )
    .map_err(|_e| UnlinkError::PermissionDenied)
}

/// Errors that can occur during unlink name validation, sticky-bit
/// enforcement, or permission checking.  Each variant maps to a POSIX
/// errno via [`UnlinkError::to_errno`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlinkError {
    /// The provided name is empty, `"."`, `".."`, contains a NUL byte,
    /// or contains a forward slash.
    InvalidName,
    /// The provided name exceeds [`UNLINK_MAX_NAME_BYTES`] bytes.
    NameTooLong,
    /// The parent directory has the sticky bit (S_ISVTX) set and the
    /// caller is neither the file owner, the directory owner, nor the
    /// superuser.  POSIX requires `EPERM` for this case.
    StickyPermissionDenied,
    /// Caller lacks write and search permission on the parent directory.
    PermissionDenied,
    /// The filesystem is mounted read-only.
    ReadOnlyFilesystem,
}

impl UnlinkError {
    /// Convert this error to the matching POSIX errno value.
    #[must_use]
    pub fn to_errno(self) -> c_int {
        match self {
            UnlinkError::InvalidName => errno::EINVAL,
            UnlinkError::NameTooLong => errno::ENAMETOOLONG,
            UnlinkError::StickyPermissionDenied => errno::EPERM,
            UnlinkError::PermissionDenied => errno::EACCES,
            UnlinkError::ReadOnlyFilesystem => errno::EROFS,
        }
    }
}

impl fmt::Display for UnlinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnlinkError::InvalidName => write!(f, "invalid unlink name"),
            UnlinkError::NameTooLong => {
                write!(
                    f,
                    "unlink name too long (max {UNLINK_MAX_NAME_BYTES} bytes)"
                )
            }
            UnlinkError::StickyPermissionDenied => {
                write!(
                    f,
                    "sticky-bit permission denied: caller must be file owner, \
                       directory owner, or superuser"
                )
            }
            UnlinkError::PermissionDenied => write!(f, "permission denied for unlink"),
            UnlinkError::ReadOnlyFilesystem => {
                write!(f, "cannot unlink on read-only filesystem")
            }
        }
    }
}

impl std::error::Error for UnlinkError {}

impl From<UnlinkError> for c_int {
    fn from(e: UnlinkError) -> c_int {
        e.to_errno()
    }
}

// ---------------------------------------------------------------------------
// Name validation
// ---------------------------------------------------------------------------

/// Validate a file name for `unlink`.
///
/// Returns `Err(`[`UnlinkError::InvalidName`]`)` when the name is empty,
/// `"."`, `".."`, contains a NUL byte, or contains a forward slash.
///
/// Returns `Err(`[`UnlinkError::NameTooLong`]`)` when the name exceeds
/// [`UNLINK_MAX_NAME_BYTES`].
///
/// Returns `Ok(())` on success.
pub fn validate_unlink_name(name: &[u8]) -> Result<(), UnlinkError> {
    if name.is_empty() {
        return Err(UnlinkError::InvalidName);
    }
    if name.len() > UNLINK_MAX_NAME_BYTES {
        return Err(UnlinkError::NameTooLong);
    }
    if name == b"." || name == b".." {
        return Err(UnlinkError::InvalidName);
    }
    if name.contains(&0) {
        return Err(UnlinkError::InvalidName);
    }
    if name.contains(&b'/') {
        return Err(UnlinkError::InvalidName);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sticky-bit enforcement
// ---------------------------------------------------------------------------

/// Enforce POSIX sticky-bit (S_ISVTX) semantics for `unlink`.
///
/// When the parent directory has the sticky bit set, only these callers
/// may remove a file from it:
///
/// - the owner of the file itself (`caller_is_owner`),
/// - the owner of the directory (`caller_is_dir_owner`),
/// - the superuser (`caller_is_root`).
///
/// If the directory does not have the sticky bit set, this check
/// always passes.
///
/// # Errors
///
/// Returns [`UnlinkError::StickyPermissionDenied`] when the sticky bit
/// is set and none of the three ownership conditions hold.
pub fn check_unlink_sticky_bit(
    dir_has_sticky: bool,
    caller_is_owner: bool,
    caller_is_dir_owner: bool,
    caller_is_root: bool,
) -> Result<(), UnlinkError> {
    if !dir_has_sticky {
        return Ok(());
    }
    if caller_is_owner || caller_is_dir_owner || caller_is_root {
        return Ok(());
    }
    Err(UnlinkError::StickyPermissionDenied)
}

// ---------------------------------------------------------------------------
// Combined validation (convenience)
// ---------------------------------------------------------------------------

/// Validate the unlink name, enforce sticky-bit semantics, and check
/// parent-directory write+execute permission in one call.
///
/// Returns `Ok(`[`UnlinkPlan`]`)` on success. On failure returns a
/// [`UnlinkError`].
#[allow(clippy::too_many_arguments)]
pub fn plan_unlink(
    name: &[u8],
    dir_has_sticky: bool,
    caller_is_owner: bool,
    caller_is_dir_owner: bool,
    caller_is_root: bool,
    parent_mode: u32,
    parent_uid: u32,
    parent_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
    mount_identity: &tidefs_permission::MountIdentity,
) -> Result<UnlinkPlan, UnlinkError> {
    validate_unlink_name(name)?;
    check_unlink_sticky_bit(
        dir_has_sticky,
        caller_is_owner,
        caller_is_dir_owner,
        caller_is_root,
    )?;
    check_unlink_parent_permission(
        parent_mode,
        parent_uid,
        parent_gid,
        caller_uid,
        caller_gid,
        caller_groups,
        mount_identity,
    )?;
    Ok(UnlinkPlan {
        name: name.to_vec(),
    })
}
// ---------------------------------------------------------------------------
// UnlinkPlan -- validated unlink request
// ---------------------------------------------------------------------------

/// A validated `unlink` request ready for backend dispatch.
///
/// Created by [`handle_unlink`], which performs all client-visible
/// validation (name checks, read-only mount guard, sticky-bit enforcement,
/// and parent-directory permission checking) before the backend is invoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlinkPlan {
    /// The validated file name.  Guaranteed to be non-empty,
    /// not `"."` or `".."`, free of NUL bytes and slashes, and
    /// at most [`UNLINK_MAX_NAME_BYTES`] bytes long.
    pub name: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Read-only mount guard
// ---------------------------------------------------------------------------

/// Reject `unlink` on a read-only mount.
///
/// POSIX `unlink(2)` returns `EROFS` when the filesystem containing the
/// file is mounted read-only.
///
/// # Errors
///
/// Returns [`UnlinkError::ReadOnlyFilesystem`] when `read_only` is
/// `true`.
pub fn check_unlink_readonly(read_only: bool) -> Result<(), UnlinkError> {
    if read_only {
        return Err(UnlinkError::ReadOnlyFilesystem);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// handle_unlink -- canonical FUSE dispatch entry-point
// ---------------------------------------------------------------------------

/// Perform full unlink validation and return a validated [`UnlinkPlan`].
///
/// This is the canonical FUSE dispatch entry-point for `unlink` (opcode 10).
/// It validates:
/// 1. The filesystem is not mounted read-only.
/// 2. The file name is valid (non-empty, within [`UNLINK_MAX_NAME_BYTES`],
///    not `"."` / `".."`, no NUL, no slash).
/// 3. Sticky-bit ownership rules are satisfied when the parent directory
///    has `S_ISVTX` set.
/// 4. The caller has write and execute/search permission on the parent
///    directory.
///
/// Returns `Ok(`[`UnlinkPlan`]`)` with the validated name on success.
///
/// # Errors
///
/// Returns [`UnlinkError::ReadOnlyFilesystem`] for read-only mounts,
/// [`UnlinkError::InvalidName`] for invalid names,
/// [`UnlinkError::NameTooLong`] for overlong names, and
/// [`UnlinkError::StickyPermissionDenied`] for sticky-bit violations.
/// Returns [`UnlinkError::PermissionDenied`] when the caller lacks
/// parent-directory write or execute/search permission.
pub fn handle_unlink(
    name: &[u8],
    read_only: bool,
    dir_has_sticky: bool,
    caller_is_owner: bool,
    caller_is_dir_owner: bool,
    caller_is_root: bool,
    parent_mode: u32,
    parent_uid: u32,
    parent_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
    mount_identity: &tidefs_permission::MountIdentity,
) -> Result<UnlinkPlan, UnlinkError> {
    check_unlink_readonly(read_only)?;
    plan_unlink(
        name,
        dir_has_sticky,
        caller_is_owner,
        caller_is_dir_owner,
        caller_is_root,
        parent_mode,
        parent_uid,
        parent_gid,
        caller_uid,
        caller_gid,
        caller_groups,
        mount_identity,
    )
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const VALID_MOUNT: tidefs_permission::MountIdentity =
        tidefs_permission::MountIdentity::new([0x41; 16], 1);

    fn plan_unlink_for_owner(
        name: &[u8],
        dir_has_sticky: bool,
        caller_is_owner: bool,
        caller_is_dir_owner: bool,
        caller_is_root: bool,
    ) -> Result<UnlinkPlan, UnlinkError> {
        plan_unlink(
            name,
            dir_has_sticky,
            caller_is_owner,
            caller_is_dir_owner,
            caller_is_root,
            0o300,
            1000,
            100,
            1000,
            100,
            &[],
            &VALID_MOUNT,
        )
    }

    fn handle_unlink_for_owner(
        name: &[u8],
        read_only: bool,
        dir_has_sticky: bool,
        caller_is_owner: bool,
        caller_is_dir_owner: bool,
        caller_is_root: bool,
    ) -> Result<UnlinkPlan, UnlinkError> {
        handle_unlink(
            name,
            read_only,
            dir_has_sticky,
            caller_is_owner,
            caller_is_dir_owner,
            caller_is_root,
            0o300,
            1000,
            100,
            1000,
            100,
            &[],
            &VALID_MOUNT,
        )
    }

    // -- check_unlink_parent_permission ---------------------------------------

    #[test]
    fn unlink_parent_permission_owner_write_execute_allowed() {
        assert_eq!(
            check_unlink_parent_permission(0o300, 1000, 100, 1000, 200, &[], &VALID_MOUNT),
            Ok(())
        );
    }

    #[test]
    fn unlink_parent_permission_group_write_execute_allowed() {
        assert_eq!(
            check_unlink_parent_permission(0o030, 1000, 100, 2000, 100, &[], &VALID_MOUNT),
            Ok(())
        );
    }

    #[test]
    fn unlink_parent_permission_supplementary_group_write_execute_allowed() {
        assert_eq!(
            check_unlink_parent_permission(0o030, 1000, 100, 2000, 200, &[100], &VALID_MOUNT),
            Ok(())
        );
    }

    #[test]
    fn unlink_parent_permission_other_write_execute_allowed() {
        assert_eq!(
            check_unlink_parent_permission(0o003, 1000, 100, 2000, 200, &[], &VALID_MOUNT),
            Ok(())
        );
    }

    #[test]
    fn unlink_parent_permission_root_allowed_without_permission_bits() {
        assert_eq!(
            check_unlink_parent_permission(0o000, 1000, 100, 0, 0, &[], &VALID_MOUNT),
            Ok(())
        );
    }

    #[test]
    fn unlink_parent_permission_denied_without_write_bit() {
        let err =
            check_unlink_parent_permission(0o100, 1000, 100, 1000, 100, &[], &VALID_MOUNT)
                .unwrap_err();
        assert_eq!(err, UnlinkError::PermissionDenied);
        assert_eq!(err.to_errno(), errno::EACCES);
    }

    #[test]
    fn unlink_parent_permission_denied_without_execute_bit() {
        let err =
            check_unlink_parent_permission(0o200, 1000, 100, 1000, 100, &[], &VALID_MOUNT)
                .unwrap_err();
        assert_eq!(err, UnlinkError::PermissionDenied);
        assert_eq!(err.to_errno(), errno::EACCES);
    }

    // -- validate_unlink_name -----------------------------------------------

    #[test]
    fn name_empty_rejected() {
        assert_eq!(validate_unlink_name(b""), Err(UnlinkError::InvalidName));
    }

    #[test]
    fn name_too_long_rejected() {
        let long = vec![b'a'; 256];
        assert_eq!(validate_unlink_name(&long), Err(UnlinkError::NameTooLong));
    }

    #[test]
    fn name_max_length_accepted() {
        let max = vec![b'a'; 255];
        assert_eq!(validate_unlink_name(&max), Ok(()));
    }

    #[test]
    fn dot_rejected() {
        assert_eq!(validate_unlink_name(b"."), Err(UnlinkError::InvalidName));
    }

    #[test]
    fn dotdot_rejected() {
        assert_eq!(validate_unlink_name(b".."), Err(UnlinkError::InvalidName));
    }

    #[test]
    fn nul_byte_rejected() {
        assert_eq!(
            validate_unlink_name(b"foo\0bar"),
            Err(UnlinkError::InvalidName)
        );
    }

    #[test]
    fn slash_rejected() {
        assert_eq!(validate_unlink_name(b"a/b"), Err(UnlinkError::InvalidName));
    }

    #[test]
    fn normal_name_accepted() {
        assert_eq!(validate_unlink_name(b"myfile"), Ok(()));
        assert_eq!(validate_unlink_name(b"file with spaces"), Ok(()));
        assert_eq!(validate_unlink_name(b"file-with-dashes"), Ok(()));
        assert_eq!(validate_unlink_name(b"file_with_underscores"), Ok(()));
    }

    #[test]
    fn name_single_char_accepted() {
        assert_eq!(validate_unlink_name(b"a"), Ok(()));
    }

    #[test]
    fn name_with_leading_dot_accepted() {
        assert_eq!(validate_unlink_name(b".hidden"), Ok(()));
    }

    #[test]
    fn name_256_bytes_rejected() {
        let name = vec![b'x'; 256];
        assert_eq!(validate_unlink_name(&name), Err(UnlinkError::NameTooLong));
    }

    #[test]
    fn name_255_bytes_accepted() {
        let name = vec![b'x'; 255];
        assert_eq!(validate_unlink_name(&name), Ok(()));
    }

    // -- check_unlink_sticky_bit --------------------------------------------

    #[test]
    fn sticky_bit_not_set_always_passes() {
        assert_eq!(check_unlink_sticky_bit(false, false, false, false), Ok(()));
        assert_eq!(check_unlink_sticky_bit(false, true, false, false), Ok(()));
        assert_eq!(check_unlink_sticky_bit(false, false, true, false), Ok(()));
        assert_eq!(check_unlink_sticky_bit(false, false, false, true), Ok(()));
        assert_eq!(check_unlink_sticky_bit(false, true, true, true), Ok(()));
    }

    #[test]
    fn sticky_bit_file_owner_passes() {
        assert_eq!(check_unlink_sticky_bit(true, true, false, false), Ok(()));
    }

    #[test]
    fn sticky_bit_dir_owner_passes() {
        assert_eq!(check_unlink_sticky_bit(true, false, true, false), Ok(()));
    }

    #[test]
    fn sticky_bit_root_passes() {
        assert_eq!(check_unlink_sticky_bit(true, false, false, true), Ok(()));
    }

    #[test]
    fn sticky_bit_file_and_dir_owner_passes() {
        assert_eq!(check_unlink_sticky_bit(true, true, true, false), Ok(()));
    }

    #[test]
    fn sticky_bit_all_three_passes() {
        assert_eq!(check_unlink_sticky_bit(true, true, true, true), Ok(()));
    }

    #[test]
    fn sticky_bit_no_ownership_denied() {
        assert_eq!(
            check_unlink_sticky_bit(true, false, false, false),
            Err(UnlinkError::StickyPermissionDenied)
        );
    }

    #[test]
    fn sticky_bit_root_overrides_all() {
        assert_eq!(check_unlink_sticky_bit(true, false, false, true), Ok(()));
    }

    // -- plan_unlink --------------------------------------------------------

    #[test]
    fn plan_unlink_valid_no_sticky() {
        let plan = plan_unlink_for_owner(b"myfile", false, false, false, false).unwrap();
        assert_eq!(plan.name, b"myfile");
    }

    #[test]
    fn plan_unlink_valid_with_sticky_as_owner() {
        let plan = plan_unlink_for_owner(b"myfile", true, true, false, false).unwrap();
        assert_eq!(plan.name, b"myfile");
    }

    #[test]
    fn plan_unlink_empty_name() {
        assert_eq!(
            plan_unlink_for_owner(b"", false, false, false, false),
            Err(UnlinkError::InvalidName)
        );
    }

    #[test]
    fn plan_unlink_dot_name() {
        assert_eq!(
            plan_unlink_for_owner(b".", false, false, false, false),
            Err(UnlinkError::InvalidName)
        );
    }

    #[test]
    fn plan_unlink_dotdot_name() {
        assert_eq!(
            plan_unlink_for_owner(b"..", false, false, false, false),
            Err(UnlinkError::InvalidName)
        );
    }

    #[test]
    fn plan_unlink_name_too_long() {
        let long = vec![b'a'; 256];
        assert_eq!(
            plan_unlink_for_owner(&long, false, false, false, false),
            Err(UnlinkError::NameTooLong)
        );
    }

    #[test]
    fn plan_unlink_nul_byte() {
        assert_eq!(
            plan_unlink_for_owner(b"bad\0name", false, false, false, false),
            Err(UnlinkError::InvalidName)
        );
    }

    #[test]
    fn plan_unlink_slash() {
        assert_eq!(
            plan_unlink_for_owner(b"a/b", false, false, false, false),
            Err(UnlinkError::InvalidName)
        );
    }

    #[test]
    fn plan_unlink_sticky_no_ownership() {
        assert_eq!(
            plan_unlink_for_owner(b"myfile", true, false, false, false),
            Err(UnlinkError::StickyPermissionDenied)
        );
    }

    #[test]
    fn plan_unlink_name_error_takes_priority_over_sticky() {
        assert_eq!(
            plan_unlink_for_owner(b"", true, true, true, true),
            Err(UnlinkError::InvalidName)
        );
    }

    #[test]
    fn plan_unlink_sticky_takes_priority_over_parent_permission() {
        let err = plan_unlink(
            b"myfile",
            true,
            false,
            false,
            false,
            0o000,
            1000,
            100,
            2000,
            200,
            &[],
            &VALID_MOUNT,
        )
        .unwrap_err();

        assert_eq!(err, UnlinkError::StickyPermissionDenied);
        assert_eq!(err.to_errno(), errno::EPERM);
    }

    #[test]
    fn plan_unlink_parent_permission_denied_maps_to_eacces() {
        let err = plan_unlink(
            b"myfile",
            false,
            false,
            false,
            false,
            0o000,
            1000,
            100,
            2000,
            200,
            &[],
            &VALID_MOUNT,
        )
        .unwrap_err();

        assert_eq!(err, UnlinkError::PermissionDenied);
        assert_eq!(err.to_errno(), errno::EACCES);
    }

    // -- UnlinkError --------------------------------------------------------

    #[test]
    fn unlink_error_display_produces_human_message() {
        let msg = format!("{}", UnlinkError::InvalidName);
        assert!(!msg.is_empty());
        let msg = format!("{}", UnlinkError::StickyPermissionDenied);
        assert!(msg.contains("sticky-bit"));
        let msg = format!("{}", UnlinkError::ReadOnlyFilesystem);
        assert!(msg.contains("read-only"));
    }

    #[test]
    fn unlink_error_is_std_error() {
        let e: &dyn Error = &UnlinkError::NameTooLong;
        let _ = e.to_string();
    }

    #[test]
    fn unlink_error_to_errno_maps_correctly() {
        assert_eq!(UnlinkError::InvalidName.to_errno(), errno::EINVAL);
        assert_eq!(UnlinkError::NameTooLong.to_errno(), errno::ENAMETOOLONG);
        assert_eq!(UnlinkError::StickyPermissionDenied.to_errno(), errno::EPERM);
        assert_eq!(UnlinkError::PermissionDenied.to_errno(), errno::EACCES);
        assert_eq!(UnlinkError::ReadOnlyFilesystem.to_errno(), errno::EROFS);
    }

    #[test]
    fn unlink_error_into_c_int() {
        let e: c_int = UnlinkError::StickyPermissionDenied.into();
        assert_eq!(e, errno::EPERM);
    }

    #[test]
    fn unlink_error_debug_includes_variant() {
        let dbg = format!("{:?}", UnlinkError::StickyPermissionDenied);
        assert!(dbg.contains("StickyPermissionDenied"));
    }

    #[test]
    fn unlink_error_clone_and_eq() {
        let e1 = UnlinkError::NameTooLong;
        let e2 = e1;
        assert_eq!(e1, e2);
        assert_ne!(e1, UnlinkError::InvalidName);
    }

    // -- Constants ----------------------------------------------------------

    #[test]
    fn unlink_max_name_bytes_is_posix_name_max() {
        assert_eq!(UNLINK_MAX_NAME_BYTES, 255);
    }
    // -- check_unlink_readonly ----------------------------------------------

    #[test]
    fn check_readonly_rejected() {
        assert_eq!(
            check_unlink_readonly(true),
            Err(UnlinkError::ReadOnlyFilesystem)
        );
    }

    #[test]
    fn check_writable_accepted() {
        assert_eq!(check_unlink_readonly(false), Ok(()));
    }

    // -- handle_unlink ------------------------------------------------------

    #[test]
    fn handle_unlink_valid_no_sticky() {
        let plan = handle_unlink_for_owner(b"myfile", false, false, false, false, false);
        assert!(plan.is_ok());
        assert_eq!(plan.unwrap().name, b"myfile");
    }

    #[test]
    fn handle_unlink_valid_with_sticky_as_owner() {
        let plan = handle_unlink_for_owner(b"myfile", false, true, true, false, false);
        assert!(plan.is_ok());
        assert_eq!(plan.unwrap().name, b"myfile");
    }

    #[test]
    fn handle_unlink_read_only_rejected() {
        assert_eq!(
            handle_unlink_for_owner(b"myfile", true, false, false, false, false),
            Err(UnlinkError::ReadOnlyFilesystem)
        );
    }

    #[test]
    fn handle_unlink_empty_name() {
        assert_eq!(
            handle_unlink_for_owner(b"", false, false, false, false, false),
            Err(UnlinkError::InvalidName)
        );
    }

    #[test]
    fn handle_unlink_dot_name() {
        assert_eq!(
            handle_unlink_for_owner(b".", false, false, false, false, false),
            Err(UnlinkError::InvalidName)
        );
    }

    #[test]
    fn handle_unlink_dotdot_name() {
        assert_eq!(
            handle_unlink_for_owner(b"..", false, false, false, false, false),
            Err(UnlinkError::InvalidName)
        );
    }

    #[test]
    fn handle_unlink_name_too_long() {
        let long = vec![b'a'; 256];
        assert_eq!(
            handle_unlink_for_owner(&long, false, false, false, false, false),
            Err(UnlinkError::NameTooLong)
        );
    }

    #[test]
    fn handle_unlink_nul_byte() {
        assert_eq!(
            handle_unlink_for_owner(b"bad\0name", false, false, false, false, false),
            Err(UnlinkError::InvalidName)
        );
    }

    #[test]
    fn handle_unlink_slash() {
        assert_eq!(
            handle_unlink_for_owner(b"a/b", false, false, false, false, false),
            Err(UnlinkError::InvalidName)
        );
    }

    #[test]
    fn handle_unlink_sticky_no_ownership() {
        assert_eq!(
            handle_unlink_for_owner(b"myfile", false, true, false, false, false),
            Err(UnlinkError::StickyPermissionDenied)
        );
    }

    #[test]
    fn handle_unlink_read_only_takes_priority_over_name_error() {
        assert_eq!(
            handle_unlink_for_owner(b"", true, false, false, false, false),
            Err(UnlinkError::ReadOnlyFilesystem)
        );
    }

    #[test]
    fn handle_unlink_read_only_takes_priority_over_parent_permission() {
        let err = handle_unlink(
            b"myfile",
            true,
            false,
            false,
            false,
            false,
            0o000,
            1000,
            100,
            2000,
            200,
            &[],
            &VALID_MOUNT,
        )
        .unwrap_err();

        assert_eq!(err, UnlinkError::ReadOnlyFilesystem);
        assert_eq!(err.to_errno(), errno::EROFS);
    }

    #[test]
    fn handle_unlink_parent_permission_denied_maps_to_eacces() {
        let err = handle_unlink(
            b"myfile",
            false,
            false,
            false,
            false,
            false,
            0o000,
            1000,
            100,
            2000,
            200,
            &[],
            &VALID_MOUNT,
        )
        .unwrap_err();

        assert_eq!(err, UnlinkError::PermissionDenied);
        assert_eq!(err.to_errno(), errno::EACCES);
    }

    #[test]
    fn handle_unlink_name_preserves_exact_bytes() {
        let plan = handle_unlink_for_owner(b"MiXeDcAsE", false, false, false, false, false);
        assert!(plan.is_ok());
        assert_eq!(plan.unwrap().name, b"MiXeDcAsE");
    }

    // -- UnlinkPlan ----------------------------------------------------------

    #[test]
    fn unlink_plan_debug_includes_name() {
        let plan = handle_unlink_for_owner(b"testfile", false, false, false, false, false).unwrap();
        let dbg = format!("{plan:?}");
        assert!(dbg.contains("UnlinkPlan"));
        assert!(dbg.contains("116")); // t byte
    }

    #[test]
    fn unlink_plan_clone_preserves_name() {
        let plan = handle_unlink_for_owner(b"testfile", false, false, false, false, false).unwrap();
        let clone = plan.clone();
        assert_eq!(plan.name, clone.name);
    }

    #[test]
    fn handle_unlink_plan_longest_valid_name() {
        let max = vec![b'a'; 255];
        let plan = handle_unlink_for_owner(&max, false, false, false, false, false);
        assert!(plan.is_ok());
        assert_eq!(plan.unwrap().name.len(), 255);
    }
}
