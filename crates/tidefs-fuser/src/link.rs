//! FUSE `link` handler helpers — new-name validation, target planning,
//! nlink accounting, combined pre-flight checks, and the canonical
//! dispatch entry-point for POSIX-compliant hard-link creation.
//!
//! Provides:
//! - [`validate_link_name`]: reject empty, overlong, dot/dotdot, NUL,
//!   and slash-containing names; returns `Ok(())` or a [`LinkError`].
//! - [`check_link_readonly`]: reject read-only mounts; returns
//!   `Err(LinkError::ReadOnlyFilesystem)` when the filesystem is
//!   mounted read-only.  Called first in [`handle_link`] to maintain
//!   EROFS-priority semantics.
//! - [`plan_link_name`]: convenience wrapper returning `Ok(())` or a
//!   [`LinkError`].
//! - [`plan_link_target`]: verify the target is not a directory and that
//!   the link is on the same filesystem; returns `Ok(())` or a [`LinkError`].
//! - [`compute_new_nlink`]: compute the post-link `nlink` with overflow
//!   protection; returns `Ok(new_nlink)` or a [`LinkError`].
//! - [`validate_link_request`]: combined pre-flight validation of name,
//!   target admissibility, and nlink headroom; returns `Ok(())` or a
//!   [`LinkError`].  Does *not* include the read-only guard; callers
//!   should use [`handle_link`] which includes it.
//! - [`handle_link`]: canonical FUSE dispatch entry point combining
//!   read-only guard, validation, and nlink computation; returns
//!   `Ok(new_nlink)` or a
//!   [`LinkError`].
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::link;
//!
//! // Individual validators
//! link::validate_link_name(b"mylink")?;
//! link::plan_link_target(false, false)?;   // target is file, same fs
//! link::check_link_readonly(false)?;
//! let new_nlink = link::compute_new_nlink(1)?;
//! assert_eq!(new_nlink, 2);
//!
//! // Or use the canonical dispatch entry point
//! let new_nlink = link::handle_link(false, b"mylink", false, false, 1)?;
//! assert_eq!(new_nlink, 2);
//! ```

use crate::errno;
use libc::c_int;
use std::fmt;

/// Maximum length of a single link-name component in bytes
/// (POSIX `NAME_MAX` on Linux).
pub const LINK_MAX_NAME_BYTES: usize = 255;

/// Maximum hard-link count before overflow (POSIX-compatible ceiling).
pub const LINK_MAX_NLINK: u32 = u32::MAX;

// ---------------------------------------------------------------------------
// LinkError — domain error type for link(2) operations
// ---------------------------------------------------------------------------

/// Errors that can occur during link-name validation, target planning,
/// or nlink computation.
/// Check that the caller has write and execute (search) permission
/// on the parent directory for a link operation.
///
/// POSIX requires directory write permission (to create the link) and
/// execute/search permission (to traverse to the directory).
pub fn check_link_parent_permission(
    parent_mode: u32,
    parent_uid: u32,
    parent_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
) -> Result<(), LinkError> {
    crate::access::check_fuse_access(
        parent_mode,
        parent_uid,
        parent_gid,
        caller_uid,
        caller_gid,
        caller_groups,
        crate::access::ACCESS_WRITE | crate::access::ACCESS_EXECUTE,
    )
    .map_err(|_e| LinkError::PermissionDenied)
}
/// Errors that can occur during FUSE `link` (hard-link) request processing.
///
/// Each variant maps to a POSIX errno via [`LinkError::to_errno`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    /// The provided name is empty, `"."`, `".."`, contains a NUL byte,
    /// or contains a forward slash.
    InvalidName,
    /// The provided name exceeds [`LINK_MAX_NAME_BYTES`] bytes.
    NameTooLong,
    /// The link target is a directory.  POSIX forbids hard links to
    /// directories (only the superuser can create `"."` and `".."`,
    /// which are handled by the filesystem, not by `link(2)`).
    TargetIsDirectory,
    /// The link target and the link directory reside on different
    /// filesystems.  POSIX `link(2)` requires both to be on the same
    /// mounted filesystem.
    CrossFilesystemLink,
    /// Hard-link count would overflow (reached [`LINK_MAX_NLINK`]).
    NlinkOverflow,
    /// Caller lacks permission to create the hard link (stub; wired
    /// when `tidefs-permission` integration lands — see #5378).
    PermissionDenied,
    /// The filesystem is mounted read-only.  Mutating operations
    /// (including `link`) must be rejected with `EROFS`.
    ReadOnlyFilesystem,
}

impl LinkError {
    /// Convert this error to the matching POSIX errno value.
    #[must_use]
    pub fn to_errno(self) -> c_int {
        match self {
            LinkError::InvalidName => errno::EINVAL,
            LinkError::NameTooLong => errno::ENAMETOOLONG,
            LinkError::TargetIsDirectory => errno::EPERM,
            LinkError::CrossFilesystemLink => errno::EXDEV,
            LinkError::NlinkOverflow => errno::EMLINK,
            LinkError::PermissionDenied => errno::EACCES,
            LinkError::ReadOnlyFilesystem => errno::EROFS,
        }
    }
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkError::InvalidName => write!(f, "invalid link name"),
            LinkError::NameTooLong => {
                write!(f, "link name too long (max {LINK_MAX_NAME_BYTES} bytes)")
            }
            LinkError::TargetIsDirectory => {
                write!(f, "cannot create hard link to a directory")
            }
            LinkError::CrossFilesystemLink => {
                write!(f, "cannot create hard link across filesystems")
            }
            LinkError::NlinkOverflow => {
                write!(f, "hard-link count overflow (max {LINK_MAX_NLINK})")
            }
            LinkError::PermissionDenied => write!(f, "permission denied for hard link"),
            LinkError::ReadOnlyFilesystem => write!(f, "read-only filesystem"),
        }
    }
}

impl std::error::Error for LinkError {}

impl From<LinkError> for c_int {
    fn from(e: LinkError) -> c_int {
        e.to_errno()
    }
}

// ---------------------------------------------------------------------------
// Name validation
// ---------------------------------------------------------------------------

/// Validate a link name for `link`.
///
/// Returns `Err(`[`LinkError::InvalidName`]`)` when the name is empty,
/// `"."`, `".."`, contains a NUL byte, or contains a forward slash.
///
/// Returns `Err(`[`LinkError::NameTooLong`]`)` when the name exceeds
/// [`LINK_MAX_NAME_BYTES`].
///
/// Returns `Ok(())` on success.
pub fn validate_link_name(name: &[u8]) -> Result<(), LinkError> {
    if name.is_empty() {
        return Err(LinkError::InvalidName);
    }
    if name.len() > LINK_MAX_NAME_BYTES {
        return Err(LinkError::NameTooLong);
    }
    if name == b"." || name == b".." {
        return Err(LinkError::InvalidName);
    }
    if name.contains(&0) {
        return Err(LinkError::InvalidName);
    }
    if name.contains(&b'/') {
        return Err(LinkError::InvalidName);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Combined validation (convenience)
// ---------------------------------------------------------------------------

/// Validate the new link name in one call.
///
/// Returns `Ok(())` on success.
/// On failure returns a [`LinkError`].
pub fn plan_link_name(name: &[u8]) -> Result<(), LinkError> {
    validate_link_name(name)
}

// ---------------------------------------------------------------------------
// Target planning
// ---------------------------------------------------------------------------

/// Verify that the link target is admissible for a POSIX `link(2)` call.
///
/// # Parameters
///
/// - `target_is_dir` — `true` when the existing target inode is a
///   directory.  POSIX forbids hard links to directories.
/// - `cross_fs` — `true` when the target and the link parent directory
///   reside on different filesystems.  POSIX `link(2)` returns `EXDEV`
///   in that case.
///
/// # Errors
///
/// - [`LinkError::TargetIsDirectory`] when `target_is_dir` is `true`.
/// - [`LinkError::CrossFilesystemLink`] when `cross_fs` is `true`.
///
/// # Stub permission check
///
/// Permission checking is deferred to `tidefs-permission` integration
/// (see #5378).  When wired, this function will also return
/// [`LinkError::PermissionDenied`] when the caller lacks write+search
/// permission on the parent directory.
pub fn plan_link_target(target_is_dir: bool, cross_fs: bool) -> Result<(), LinkError> {
    if target_is_dir {
        return Err(LinkError::TargetIsDirectory);
    }
    if cross_fs {
        return Err(LinkError::CrossFilesystemLink);
    }
    // Review debt TFR-011: integrate tidefs-permission parent access
    // checks tracked by historical issue #5378.
    Ok(())
}

// ---------------------------------------------------------------------------
// Nlink accounting
// ---------------------------------------------------------------------------

/// Compute the post-link hard-link count with overflow protection.
///
/// Returns `Ok(new_nlink)` where `new_nlink == current_nlink + 1`.
///
/// # Errors
///
/// Returns [`LinkError::NlinkOverflow`] when `current_nlink` is already
/// at [`LINK_MAX_NLINK`] (`u32::MAX`).
pub fn compute_new_nlink(current_nlink: u32) -> Result<u32, LinkError> {
    current_nlink.checked_add(1).ok_or(LinkError::NlinkOverflow)
}

// -- validate_link_request --- combined pre-flight validation -------------------

/// Validate a link request: name format, target admissibility, and nlink headroom.
///
/// This combines [`validate_link_name`], [`plan_link_target`], and overflow
/// headroom into a single pre-flight check suitable for the FUSE dispatch path.
///
/// Returns `Ok(())` when the link request passes all validation gates.
pub fn validate_link_request(
    new_name: &[u8],
    target_is_dir: bool,
    cross_fs: bool,
    current_nlink: u32,
) -> Result<(), LinkError> {
    validate_link_name(new_name)?;
    plan_link_target(target_is_dir, cross_fs)?;
    // Dry-run nlink computation to detect overflow before mutating state.
    let _ = compute_new_nlink(current_nlink)?;
    Ok(())
}

// -- handle_link --- canonical FUSE dispatch entry point -----------------------

/// Check whether the filesystem is mounted read-only.
///
/// When `read_only` is `true`, returns
/// [`LinkError::ReadOnlyFilesystem`] (which maps to `EROFS`).
/// Callers should invoke this guard as the first step in
/// [`handle_link`] to maintain EROFS-priority semantics: the
/// read-only rejection takes precedence over name or target
/// validation.
///
/// # Errors
///
/// Returns [`LinkError::ReadOnlyFilesystem`] when `read_only` is
/// `true`.
#[inline]
pub fn check_link_readonly(read_only: bool) -> Result<(), LinkError> {
    if read_only {
        return Err(LinkError::ReadOnlyFilesystem);
    }
    Ok(())
}

/// Canonical FUSE dispatch entry point for `link` (opcode 15).
///
/// Validates the new name, target admissibility, and nlink headroom,
/// then returns the post-link `nlink` count on success.
///
/// The caller is responsible for performing namespace insertion and
/// intent-log recording using the returned `nlink` value.
///
/// # Examples
///
/// ```rust,ignore
/// use fuser::link;
///
/// let new_nlink = link::handle_link(false, b"hardlink", false, false, 1)?;
/// assert_eq!(new_nlink, 2);
/// ```
#[inline]
pub fn handle_link(
    read_only: bool,
    new_name: &[u8],
    target_is_dir: bool,
    cross_fs: bool,
    current_nlink: u32,
) -> Result<u32, LinkError> {
    check_link_readonly(read_only)?;
    validate_link_request(new_name, target_is_dir, cross_fs, current_nlink)?;
    compute_new_nlink(current_nlink)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    // -- validate_link_name --------------------------------------------------

    #[test]
    fn name_empty_rejected() {
        assert_eq!(validate_link_name(b""), Err(LinkError::InvalidName));
    }

    #[test]
    fn name_too_long_rejected() {
        let long = vec![b'a'; 256];
        assert_eq!(validate_link_name(&long), Err(LinkError::NameTooLong));
    }

    #[test]
    fn name_max_length_accepted() {
        let max = vec![b'a'; 255];
        assert_eq!(validate_link_name(&max), Ok(()));
    }

    #[test]
    fn dot_rejected() {
        assert_eq!(validate_link_name(b"."), Err(LinkError::InvalidName));
    }

    #[test]
    fn dotdot_rejected() {
        assert_eq!(validate_link_name(b".."), Err(LinkError::InvalidName));
    }

    #[test]
    fn nul_byte_rejected() {
        assert_eq!(validate_link_name(b"foo\0bar"), Err(LinkError::InvalidName));
    }

    #[test]
    fn slash_rejected() {
        assert_eq!(validate_link_name(b"a/b"), Err(LinkError::InvalidName));
    }

    #[test]
    fn normal_name_accepted() {
        assert_eq!(validate_link_name(b"mylink"), Ok(()));
        assert_eq!(validate_link_name(b"hard link name"), Ok(()));
        assert_eq!(validate_link_name(b"link-with-dashes"), Ok(()));
        assert_eq!(validate_link_name(b"link_with_underscores"), Ok(()));
    }

    // -- plan_link_name -------------------------------------------------------

    #[test]
    fn plan_link_name_valid() {
        assert_eq!(plan_link_name(b"hardlink"), Ok(()));
    }

    #[test]
    fn plan_link_name_empty() {
        assert_eq!(plan_link_name(b""), Err(LinkError::InvalidName));
    }

    #[test]
    fn plan_link_name_dot() {
        assert_eq!(plan_link_name(b"."), Err(LinkError::InvalidName));
    }

    #[test]
    fn plan_link_name_dotdot() {
        assert_eq!(plan_link_name(b".."), Err(LinkError::InvalidName));
    }

    #[test]
    fn plan_link_name_slash() {
        assert_eq!(plan_link_name(b"a/b"), Err(LinkError::InvalidName));
    }

    #[test]
    fn plan_link_name_nul() {
        assert_eq!(plan_link_name(b"foo\0bar"), Err(LinkError::InvalidName));
    }

    // -- plan_link_target ----------------------------------------------------

    #[test]
    fn plan_link_target_file_same_fs_ok() {
        assert_eq!(plan_link_target(false, false), Ok(()));
    }

    #[test]
    fn plan_link_target_directory_rejected() {
        assert_eq!(
            plan_link_target(true, false),
            Err(LinkError::TargetIsDirectory)
        );
    }

    #[test]
    fn plan_link_target_cross_fs_rejected() {
        assert_eq!(
            plan_link_target(false, true),
            Err(LinkError::CrossFilesystemLink)
        );
    }

    #[test]
    fn plan_link_target_dir_and_cross_fs_reports_directory_first() {
        assert_eq!(
            plan_link_target(true, true),
            Err(LinkError::TargetIsDirectory)
        );
    }

    // -- compute_new_nlink ---------------------------------------------------

    #[test]
    fn compute_nlink_normal_increment() {
        assert_eq!(compute_new_nlink(1), Ok(2));
        assert_eq!(compute_new_nlink(0), Ok(1));
        assert_eq!(compute_new_nlink(42), Ok(43));
    }

    #[test]
    fn compute_nlink_at_max_overflows() {
        assert_eq!(compute_new_nlink(u32::MAX), Err(LinkError::NlinkOverflow));
    }

    #[test]
    fn compute_nlink_near_max_ok() {
        assert_eq!(compute_new_nlink(u32::MAX - 1), Ok(u32::MAX));
    }

    // -- LinkError -----------------------------------------------------------

    #[test]
    fn link_error_display_produces_human_message() {
        let msg = format!("{}", LinkError::InvalidName);
        assert!(!msg.is_empty());
        let msg = format!("{}", LinkError::NlinkOverflow);
        assert!(msg.contains("overflow"));
    }

    #[test]
    fn link_error_is_std_error() {
        let e: &dyn Error = &LinkError::CrossFilesystemLink;
        let _ = e.to_string();
    }

    #[test]
    fn link_error_to_errno_maps_correctly() {
        assert_eq!(LinkError::InvalidName.to_errno(), errno::EINVAL);
        assert_eq!(LinkError::NameTooLong.to_errno(), errno::ENAMETOOLONG);
        assert_eq!(LinkError::TargetIsDirectory.to_errno(), errno::EPERM);
        assert_eq!(LinkError::CrossFilesystemLink.to_errno(), errno::EXDEV);
        assert_eq!(LinkError::NlinkOverflow.to_errno(), errno::EMLINK);
        assert_eq!(LinkError::PermissionDenied.to_errno(), errno::EACCES);
    }

    #[test]
    fn link_error_into_c_int() {
        let e: c_int = LinkError::TargetIsDirectory.into();
        assert_eq!(e, errno::EPERM);
    }

    #[test]
    fn link_error_debug_includes_variant() {
        let dbg = format!("{:?}", LinkError::CrossFilesystemLink);
        assert!(dbg.contains("CrossFilesystemLink"));
    }

    #[test]
    fn link_error_clone_and_eq() {
        let e1 = LinkError::NlinkOverflow;
        let e2 = e1;
        assert_eq!(e1, e2);
        assert_ne!(e1, LinkError::InvalidName);
    }

    // -- Constants -----------------------------------------------------------

    #[test]
    fn link_max_name_bytes_is_posix_name_max() {
        assert_eq!(LINK_MAX_NAME_BYTES, 255);
    }

    #[test]
    fn link_max_nlink_is_u32_max() {
        assert_eq!(LINK_MAX_NLINK, u32::MAX);
    }
    // -- validate_link_request -----------------------------------------------

    #[test]
    fn validate_link_request_valid_file_ok() {
        assert_eq!(validate_link_request(b"hardlink", false, false, 1), Ok(()));
        assert_eq!(validate_link_request(b"link2", false, false, 0), Ok(()));
        // nlink near max is still ok for validation (no overflow yet)
        assert_eq!(
            validate_link_request(b"link3", false, false, u32::MAX - 1),
            Ok(())
        );
    }

    #[test]
    fn validate_link_request_directory_target_rejected() {
        assert_eq!(
            validate_link_request(b"hardlink", true, false, 1),
            Err(LinkError::TargetIsDirectory)
        );
    }

    #[test]
    fn validate_link_request_cross_fs_rejected() {
        assert_eq!(
            validate_link_request(b"hardlink", false, true, 1),
            Err(LinkError::CrossFilesystemLink)
        );
    }

    #[test]
    fn validate_link_request_invalid_name_rejected() {
        assert_eq!(
            validate_link_request(b"", false, false, 1),
            Err(LinkError::InvalidName)
        );
        assert_eq!(
            validate_link_request(b".", false, false, 1),
            Err(LinkError::InvalidName)
        );
        assert_eq!(
            validate_link_request(b"a/b", false, false, 1),
            Err(LinkError::InvalidName)
        );
    }

    #[test]
    fn validate_link_request_nlink_overflow_rejected() {
        assert_eq!(
            validate_link_request(b"hardlink", false, false, u32::MAX),
            Err(LinkError::NlinkOverflow)
        );
    }

    #[test]
    fn validate_link_request_directory_error_wins_over_overflow() {
        // TargetIsDirectory is checked before NlinkOverflow
        assert_eq!(
            validate_link_request(b"hardlink", true, false, u32::MAX),
            Err(LinkError::TargetIsDirectory)
        );
    }

    #[test]
    fn validate_link_request_name_error_wins_over_target() {
        // InvalidName is checked before TargetIsDirectory
        assert_eq!(
            validate_link_request(b"", true, false, 1),
            Err(LinkError::InvalidName)
        );
    }

    // -- handle_link ---------------------------------------------------------

    #[test]
    fn handle_link_valid_returns_new_nlink() {
        assert_eq!(handle_link(false, b"hardlink", false, false, 1), Ok(2));
        assert_eq!(handle_link(false, b"link2", false, false, 0), Ok(1));
        assert_eq!(handle_link(false, b"link3", false, false, 41), Ok(42));
        assert_eq!(
            handle_link(false, b"link4", false, false, u32::MAX - 1),
            Ok(u32::MAX)
        );
    }

    #[test]
    fn handle_link_directory_target_returns_eperm() {
        assert_eq!(
            handle_link(false, b"hardlink", true, false, 1),
            Err(LinkError::TargetIsDirectory)
        );
    }

    #[test]
    fn handle_link_cross_fs_returns_exdev() {
        assert_eq!(
            handle_link(false, b"hardlink", false, true, 1),
            Err(LinkError::CrossFilesystemLink)
        );
    }

    #[test]
    fn handle_link_invalid_name_returns_einval() {
        assert_eq!(
            handle_link(false, b"", false, false, 1),
            Err(LinkError::InvalidName)
        );
        assert_eq!(
            handle_link(false, b".", false, false, 1),
            Err(LinkError::InvalidName)
        );
    }

    #[test]
    fn handle_link_nlink_overflow_returns_emlink() {
        assert_eq!(
            handle_link(false, b"hardlink", false, false, u32::MAX),
            Err(LinkError::NlinkOverflow)
        );
    }

    #[test]
    fn handle_link_name_too_long_returns_ename_toolong() {
        let long = vec![b'a'; 256];
        assert_eq!(
            handle_link(false, &long, false, false, 1),
            Err(LinkError::NameTooLong)
        );
    }

    #[test]
    fn handle_link_zero_nlink_works() {
        // nlink can be zero (e.g. after unlink of last name but inode still
        // referenced via open fd); link bumps it to 1.
        assert_eq!(handle_link(false, b"resurrect", false, false, 0), Ok(1));
    }

    #[test]
    fn handle_link_nlink_near_max_still_works() {
        assert_eq!(
            handle_link(false, b"alias", false, false, u32::MAX - 1),
            Ok(u32::MAX)
        );
    }

    // -- check_link_readonly ------------------------------------------------

    #[test]
    fn check_link_readonly_false_ok() {
        assert_eq!(check_link_readonly(false), Ok(()));
    }

    #[test]
    fn check_link_readonly_true_returns_erofs() {
        assert_eq!(
            check_link_readonly(true),
            Err(LinkError::ReadOnlyFilesystem)
        );
    }

    // -- handle_link read-only guard tests ----------------------------------

    #[test]
    fn handle_link_read_only_rejected() {
        assert_eq!(
            handle_link(true, b"hardlink", false, false, 1),
            Err(LinkError::ReadOnlyFilesystem)
        );
    }

    #[test]
    fn handle_link_writable_allows() {
        assert_eq!(handle_link(false, b"hardlink", false, false, 1), Ok(2));
    }

    #[test]
    fn handle_link_read_only_priority_over_name_error() {
        // EROFS must take priority over name validation errors.
        assert_eq!(
            handle_link(true, b"", false, false, 1),
            Err(LinkError::ReadOnlyFilesystem)
        );
    }

    // -- ReadOnlyFilesystem error variant -----------------------------------

    #[test]
    fn readonly_error_to_errno_returns_erofs() {
        assert_eq!(LinkError::ReadOnlyFilesystem.to_errno(), errno::EROFS);
    }

    #[test]
    fn readonly_error_display_mentions_readonly() {
        let msg = format!("{}", LinkError::ReadOnlyFilesystem);
        assert!(msg.contains("read-only"));
    }
}
