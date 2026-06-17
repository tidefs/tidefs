//! FUSE `rmdir` handler helpers — directory name validation, read-only
//! mount guard, and convenience entry-points for POSIX-compliant
//! directory removal.
//!
//! Provides:
//! - [`handle_rmdir`]: canonical dispatch entry-point combining read-only
//!   mount guard and name validation into a single call — returns a
//!   validated [`RmdirPlan`] or a [`RmdirError`].
//! - [`validate_rmdir_name`]: reject empty, overlong, dot/dotdot, NUL,
//!   and slash-containing names; returns `Ok(())` or a [`RmdirError`].
//! - [`check_rmdir_readonly`]: reject read-only mounts; returns
//!   `Ok(())` or a [`RmdirError`].
//! - [`plan_rmdir`]: combined name validation, RO-mount guard, and
//!   permission-stub returning `Ok(RmdirPlan)` or a [`RmdirError`].
//! - [`RmdirPlan`]: validated rmdir request ready for backend dispatch.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::rmdir;
//!
//! let plan = rmdir::handle_rmdir(b"emptydir", false)?;
//! // dispatch plan.name to the backend...
//! ```

use crate::errno;
use libc::c_int;
use std::fmt;

/// Maximum length of a single directory-name component in bytes
/// (POSIX `NAME_MAX` on Linux).
pub const RMDIR_MAX_NAME_BYTES: usize = 255;

// ---------------------------------------------------------------------------
// RmdirPlan -- validated rmdir request
// ---------------------------------------------------------------------------

/// A validated `rmdir` request ready for backend dispatch.
///
/// Created by [`plan_rmdir`], which performs all client-visible
/// validation (name checks, read-only mount guard) before the
/// backend is invoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RmdirPlan {
    /// The validated directory name.  Guaranteed to be non-empty,
    /// not `"."` or `".."`, free of NUL bytes and slashes, and
    /// at most [`RMDIR_MAX_NAME_BYTES`] bytes long.
    pub name: Vec<u8>,
}

// ---------------------------------------------------------------------------
// RmdirError -- domain error type for rmdir(2) operations
// ---------------------------------------------------------------------------

/// Errors that can occur during rmdir name validation, read-only
/// mount checking, or permission enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RmdirError {
    /// The provided name is empty, `"."`, `".."`, contains a NUL byte,
    /// or contains a forward slash.
    InvalidName,
    /// The provided name exceeds [`RMDIR_MAX_NAME_BYTES`] bytes.
    NameTooLong,
    /// The filesystem is mounted read-only.
    ReadOnlyFilesystem,
    /// Caller lacks write+search permission on the parent directory
    /// (stub; wired when `tidefs-permission` integration lands —
    /// see #5378).
    PermissionDenied,
    /// The directory is not empty.  POSIX `rmdir(2)` requires that
    /// only `"."` and `".."` remain.  This error is reported by the
    /// backend (`VfsEngine::rmdir`) and surfaced through the FUSE
    /// handler so the daemon can format the correct reply.
    DirectoryNotEmpty,
    /// The parent directory does not exist.
    NotFound,
    /// The target path component is not a directory.
    NotADirectory,
}

impl RmdirError {
    /// Convert this error to the matching POSIX errno value.
    #[must_use]
    pub fn to_errno(self) -> c_int {
        match self {
            RmdirError::InvalidName => errno::EINVAL,
            RmdirError::NameTooLong => errno::ENAMETOOLONG,
            RmdirError::ReadOnlyFilesystem => errno::EROFS,
            RmdirError::PermissionDenied => errno::EACCES,
            RmdirError::DirectoryNotEmpty => errno::ENOTEMPTY,
            RmdirError::NotFound => errno::ENOENT,
            RmdirError::NotADirectory => errno::ENOTDIR,
        }
    }
}

impl fmt::Display for RmdirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RmdirError::InvalidName => write!(f, "invalid rmdir name"),
            RmdirError::NameTooLong => {
                write!(f, "rmdir name too long (max {RMDIR_MAX_NAME_BYTES} bytes)")
            }
            RmdirError::ReadOnlyFilesystem => {
                write!(f, "cannot rmdir on read-only filesystem")
            }
            RmdirError::PermissionDenied => write!(f, "permission denied for rmdir"),
            RmdirError::DirectoryNotEmpty => {
                write!(f, "directory not empty")
            }
            RmdirError::NotFound => write!(f, "parent directory not found"),
            RmdirError::NotADirectory => write!(f, "path component is not a directory"),
        }
    }
}

impl std::error::Error for RmdirError {}

impl From<RmdirError> for c_int {
    fn from(e: RmdirError) -> c_int {
        e.to_errno()
    }
}

// ---------------------------------------------------------------------------
// Name validation
// ---------------------------------------------------------------------------

/// Validate a directory name for `rmdir`.
///
/// Returns `Err(`[`RmdirError::InvalidName`]`)` when the name is empty,
/// `"."`, `".."`, contains a NUL byte, or contains a forward slash.
///
/// Returns `Err(`[`RmdirError::NameTooLong`]`)` when the name exceeds
/// [`RMDIR_MAX_NAME_BYTES`].
///
/// Returns `Ok(())` on success.
pub fn validate_rmdir_name(name: &[u8]) -> Result<(), RmdirError> {
    if name.is_empty() {
        return Err(RmdirError::InvalidName);
    }
    if name.len() > RMDIR_MAX_NAME_BYTES {
        return Err(RmdirError::NameTooLong);
    }
    if name == b"." || name == b".." {
        return Err(RmdirError::InvalidName);
    }
    if name.contains(&0) {
        return Err(RmdirError::InvalidName);
    }
    if name.contains(&b'/') {
        return Err(RmdirError::InvalidName);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Read-only mount guard
// ---------------------------------------------------------------------------

/// Reject `rmdir` on a read-only mount.
///
/// POSIX `rmdir(2)` returns `EROFS` when the filesystem containing the
/// directory is mounted read-only.
///
/// # Errors
///
/// Returns [`RmdirError::ReadOnlyFilesystem`] when `read_only` is
/// `true`.
pub fn check_rmdir_readonly(read_only: bool) -> Result<(), RmdirError> {
    if read_only {
        return Err(RmdirError::ReadOnlyFilesystem);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Combined validation (convenience)
// ---------------------------------------------------------------------------

/// Validate the rmdir name, enforce the read-only mount guard, and
/// (in a future integration) check parent-directory write permission
/// in one call.
///
/// Returns `Ok(`[`RmdirPlan`]`)` on success.  On failure returns a
/// [`RmdirError`].
///
/// # Stub permission check
///
/// Permission checking for parent-directory write access is deferred to
/// `tidefs-permission` integration (see #5378).  When wired, this
/// function will also return [`RmdirError::PermissionDenied`] when the
/// caller lacks write+search permission on the parent directory.
///
/// # Directory-not-empty check
///
/// The `ENOTEMPTY` check (the removed directory must be empty) is a
/// backend concern — the VFS engine must verify that only `"."` and
/// `".."` entries remain.  The FUSE handler helper does not perform
/// this check; it is the caller's responsibility to reject with
/// `errno::ENOTEMPTY` after the backend reports the directory is
/// non-empty.
pub fn plan_rmdir(name: &[u8], read_only: bool) -> Result<RmdirPlan, RmdirError> {
    validate_rmdir_name(name)?;
    check_rmdir_readonly(read_only)?;
    // Review debt TFR-011: add tidefs-permission parent W_OK|X_OK checks.
    Ok(RmdirPlan {
        name: name.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// handle_rmdir — canonical dispatch entry-point
// ---------------------------------------------------------------------------

/// Canonical dispatch entry-point for FUSE `rmdir` requests.
///
/// Combines read-only mount guard and name validation into a single
/// `Result<RmdirPlan, RmdirError>`.  This is the preferred entry point
/// for daemon dispatch: it rejects read-only mounts early (EROFS),
/// validates the directory name (EINVAL/ENAMETOOLONG), and returns a
/// validated [`RmdirPlan`] ready for backend execution.
///
/// # Parameters
///
/// - `name`: directory name to remove (must be non-empty, not `"."` or
///   `".."`, NUL-free, slash-free, and ≤ [`RMDIR_MAX_NAME_BYTES`]).
/// - `read_only`: when `true`, the filesystem is mounted read-only.
///
/// # Errors
///
/// Returns [`RmdirError::ReadOnlyFilesystem`] when `read_only` is
/// `true` (priority: read-only check runs before name validation,
/// matching POSIX `EROFS` semantics for `rmdir(2)` on a read-only
/// filesystem).
///
/// Returns [`RmdirError::InvalidName`] or [`RmdirError::NameTooLong`]
/// when the name fails validation.
///
/// # Examples
///
/// ```rust,ignore
/// let plan = rmdir::handle_rmdir(b"emptydir", false)?;
/// // dispatch plan.name to the backend...
/// ```
#[inline]
pub fn handle_rmdir(name: &[u8], read_only: bool) -> Result<RmdirPlan, RmdirError> {
    check_rmdir_readonly(read_only)?;
    validate_rmdir_name(name)?;
    Ok(RmdirPlan {
        name: name.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    // -- validate_rmdir_name -------------------------------------------------

    #[test]
    fn name_empty_rejected() {
        assert_eq!(validate_rmdir_name(b""), Err(RmdirError::InvalidName));
    }

    #[test]
    fn name_too_long_rejected() {
        let long = vec![b'a'; 256];
        assert_eq!(validate_rmdir_name(&long), Err(RmdirError::NameTooLong));
    }

    #[test]
    fn name_max_length_accepted() {
        let max = vec![b'a'; 255];
        assert_eq!(validate_rmdir_name(&max), Ok(()));
    }

    #[test]
    fn dot_rejected() {
        assert_eq!(validate_rmdir_name(b"."), Err(RmdirError::InvalidName));
    }

    #[test]
    fn dotdot_rejected() {
        assert_eq!(validate_rmdir_name(b".."), Err(RmdirError::InvalidName));
    }

    #[test]
    fn nul_byte_rejected() {
        assert_eq!(
            validate_rmdir_name(b"foo\0bar"),
            Err(RmdirError::InvalidName)
        );
    }

    #[test]
    fn slash_rejected() {
        assert_eq!(validate_rmdir_name(b"a/b"), Err(RmdirError::InvalidName));
    }

    #[test]
    fn normal_name_accepted() {
        assert_eq!(validate_rmdir_name(b"mydir"), Ok(()));
        assert_eq!(validate_rmdir_name(b"dir with spaces"), Ok(()));
        assert_eq!(validate_rmdir_name(b"dir-with-dashes"), Ok(()));
        assert_eq!(validate_rmdir_name(b"dir_with_underscores"), Ok(()));
    }

    #[test]
    fn name_single_char_accepted() {
        assert_eq!(validate_rmdir_name(b"a"), Ok(()));
    }

    #[test]
    fn name_with_leading_dot_accepted() {
        // ".hidden" is a valid directory name (POSIX allows it)
        assert_eq!(validate_rmdir_name(b".hidden"), Ok(()));
    }

    #[test]
    fn name_256_bytes_rejected() {
        let name = vec![b'x'; 256];
        assert_eq!(validate_rmdir_name(&name), Err(RmdirError::NameTooLong));
    }

    #[test]
    fn name_255_bytes_accepted() {
        let name = vec![b'x'; 255];
        assert_eq!(validate_rmdir_name(&name), Ok(()));
    }

    #[test]
    fn name_dot_dot_variants_accepted() {
        // "..a" and "a.." are not exactly "." or ".."
        assert_eq!(validate_rmdir_name(b"..a"), Ok(()));
        assert_eq!(validate_rmdir_name(b"a.."), Ok(()));
    }

    // -- check_rmdir_readonly ------------------------------------------------

    #[test]
    fn rw_mount_passes() {
        assert_eq!(check_rmdir_readonly(false), Ok(()));
    }

    #[test]
    fn ro_mount_rejected() {
        assert_eq!(
            check_rmdir_readonly(true),
            Err(RmdirError::ReadOnlyFilesystem)
        );
    }

    // -- plan_rmdir ----------------------------------------------------------

    #[test]
    fn plan_rmdir_valid_rw() {
        let plan = plan_rmdir(b"emptydir", false);
        assert!(plan.is_ok());
        let plan = plan.unwrap();
        assert_eq!(plan.name, b"emptydir");
    }

    #[test]
    fn plan_rmdir_empty_name() {
        assert_eq!(plan_rmdir(b"", false), Err(RmdirError::InvalidName));
    }

    #[test]
    fn plan_rmdir_dot_name() {
        assert_eq!(plan_rmdir(b".", false), Err(RmdirError::InvalidName));
    }

    #[test]
    fn plan_rmdir_dotdot_name() {
        assert_eq!(plan_rmdir(b"..", false), Err(RmdirError::InvalidName));
    }

    #[test]
    fn plan_rmdir_name_too_long() {
        let long = vec![b'a'; 256];
        assert_eq!(plan_rmdir(&long, false), Err(RmdirError::NameTooLong));
    }

    #[test]
    fn plan_rmdir_nul_byte() {
        assert_eq!(
            plan_rmdir(b"bad\0name", false),
            Err(RmdirError::InvalidName)
        );
    }

    #[test]
    fn plan_rmdir_slash() {
        assert_eq!(plan_rmdir(b"a/b", false), Err(RmdirError::InvalidName));
    }

    #[test]
    fn plan_rmdir_ro_mount() {
        assert_eq!(
            plan_rmdir(b"emptydir", true),
            Err(RmdirError::ReadOnlyFilesystem)
        );
    }

    #[test]
    fn plan_rmdir_name_error_takes_priority_over_ro() {
        // Empty name on RO mount: InvalidName should win
        assert_eq!(plan_rmdir(b"", true), Err(RmdirError::InvalidName));
    }

    #[test]
    fn plan_rmdir_name_preserves_exact_bytes() {
        let plan = plan_rmdir(b"MiXeDcAsE", false).unwrap();
        assert_eq!(plan.name, b"MiXeDcAsE");
    }

    // -- RmdirError ----------------------------------------------------------

    #[test]
    fn rmdir_error_display_produces_human_message() {
        let msg = format!("{}", RmdirError::InvalidName);
        assert!(!msg.is_empty());
        let msg = format!("{}", RmdirError::ReadOnlyFilesystem);
        assert!(msg.contains("read-only"));
    }

    #[test]
    fn rmdir_error_is_std_error() {
        let e: &dyn Error = &RmdirError::NameTooLong;
        let _ = e.to_string();
    }

    #[test]
    fn rmdir_error_to_errno_maps_correctly() {
        assert_eq!(RmdirError::InvalidName.to_errno(), errno::EINVAL);
        assert_eq!(RmdirError::NameTooLong.to_errno(), errno::ENAMETOOLONG);
        assert_eq!(RmdirError::ReadOnlyFilesystem.to_errno(), errno::EROFS);
        assert_eq!(RmdirError::PermissionDenied.to_errno(), errno::EACCES);
    }

    #[test]
    fn rmdir_error_into_c_int() {
        let e: c_int = RmdirError::ReadOnlyFilesystem.into();
        assert_eq!(e, errno::EROFS);
    }

    #[test]
    fn rmdir_error_debug_includes_variant() {
        let dbg = format!("{:?}", RmdirError::ReadOnlyFilesystem);
        assert!(dbg.contains("ReadOnlyFilesystem"));
    }

    #[test]
    fn rmdir_error_clone_and_eq() {
        let e1 = RmdirError::NameTooLong;
        let e2 = e1;
        assert_eq!(e1, e2);
        assert_ne!(e1, RmdirError::InvalidName);
    }

    // -- RmdirPlan -----------------------------------------------------------

    #[test]
    fn rmdir_plan_debug_includes_name() {
        let plan = plan_rmdir(b"testdir", false).unwrap();
        let dbg = format!("{plan:?}");
        // Vec<u8> debug prints as e.g. [116, 101, 115, 116, 100, 105, 114]
        assert!(dbg.contains("RmdirPlan"));
        assert!(dbg.contains("116")); // t byte
    }

    #[test]
    fn rmdir_plan_clone_preserves_name() {
        let plan = plan_rmdir(b"testdir", false).unwrap();
        let clone = plan.clone();
        assert_eq!(plan.name, clone.name);
    }

    // -- Constants -----------------------------------------------------------

    #[test]
    fn rmdir_max_name_bytes_is_posix_name_max() {
        assert_eq!(RMDIR_MAX_NAME_BYTES, 255);
    }

    // -- handle_rmdir --------------------------------------------------------

    #[test]
    fn handle_rmdir_valid_rw() {
        let plan = handle_rmdir(b"emptydir", false).unwrap();
        assert_eq!(plan.name, b"emptydir");
    }

    #[test]
    fn handle_rmdir_ro_mount_rejected() {
        assert_eq!(
            handle_rmdir(b"emptydir", true),
            Err(RmdirError::ReadOnlyFilesystem)
        );
    }

    #[test]
    fn handle_rmdir_empty_name() {
        assert_eq!(handle_rmdir(b"", false), Err(RmdirError::InvalidName));
    }

    #[test]
    fn handle_rmdir_dot_name() {
        assert_eq!(handle_rmdir(b".", false), Err(RmdirError::InvalidName));
    }

    #[test]
    fn handle_rmdir_dotdot_name() {
        assert_eq!(handle_rmdir(b"..", false), Err(RmdirError::InvalidName));
    }

    #[test]
    fn handle_rmdir_name_too_long() {
        let long = vec![b'a'; 256];
        assert_eq!(handle_rmdir(&long, false), Err(RmdirError::NameTooLong));
    }
    #[test]
    fn handle_rmdir_nul_byte() {
        assert_eq!(
            handle_rmdir(b"bad\0name", false),
            Err(RmdirError::InvalidName)
        );
    }

    #[test]
    fn handle_rmdir_slash() {
        assert_eq!(handle_rmdir(b"a/b", false), Err(RmdirError::InvalidName));
    }

    #[test]
    fn handle_rmdir_read_only_takes_priority() {
        // RO mount check runs first, so invalid name on RO returns RO error
        assert_eq!(handle_rmdir(b"", true), Err(RmdirError::ReadOnlyFilesystem));
    }

    #[test]
    fn handle_rmdir_name_preserves_exact_bytes() {
        let plan = handle_rmdir(b"MiXeDcAsE", false).unwrap();
        assert_eq!(plan.name, b"MiXeDcAsE");
    }

    #[test]
    fn handle_rmdir_max_length_name() {
        let max = vec![b'a'; 255];
        let plan = handle_rmdir(&max, false).unwrap();
        assert_eq!(plan.name.len(), 255);
    }

    // -- DirectoryNotEmpty error variant ---------------------------------

    #[test]
    fn directory_not_empty_errno_is_enotempty() {
        assert_eq!(RmdirError::DirectoryNotEmpty.to_errno(), errno::ENOTEMPTY);
    }

    #[test]
    fn directory_not_empty_into_c_int() {
        let e: c_int = RmdirError::DirectoryNotEmpty.into();
        assert_eq!(e, errno::ENOTEMPTY);
    }

    #[test]
    fn directory_not_empty_display() {
        let msg = format!("{}", RmdirError::DirectoryNotEmpty);
        assert!(!msg.is_empty());
        assert!(msg.contains("not empty"));
    }

    // -- NotFound and NotADirectory error variants --------------------------

    #[test]
    fn not_found_errno_is_enoent() {
        assert_eq!(RmdirError::NotFound.to_errno(), errno::ENOENT);
    }

    #[test]
    fn not_found_into_c_int() {
        let e: c_int = RmdirError::NotFound.into();
        assert_eq!(e, errno::ENOENT);
    }

    #[test]
    fn not_found_display() {
        let msg = format!("{}", RmdirError::NotFound);
        assert!(!msg.is_empty());
        assert!(msg.contains("not found"));
    }

    #[test]
    fn not_a_directory_errno_is_enotdir() {
        assert_eq!(RmdirError::NotADirectory.to_errno(), errno::ENOTDIR);
    }

    #[test]
    fn not_a_directory_into_c_int() {
        let e: c_int = RmdirError::NotADirectory.into();
        assert_eq!(e, errno::ENOTDIR);
    }

    #[test]
    fn not_a_directory_display() {
        let msg = format!("{}", RmdirError::NotADirectory);
        assert!(!msg.is_empty());
        assert!(msg.contains("not a directory"));
    }

    // -- Priority: name validation before RO check ---------------------------

    #[test]
    fn plan_rmdir_invalid_name_on_ro_returns_name_error() {
        // A dot name on a RO mount should return InvalidName, not ReadOnlyFilesystem
        assert_eq!(plan_rmdir(b".", true), Err(RmdirError::InvalidName));
    }
}
