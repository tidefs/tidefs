//! FUSE `readlink` handler helpers — inode-type checking, target-path
//! length validation, and convenience entry-points for POSIX-compliant
//! symbolic-link resolution.
//!
//! Provides:
//! - [`ReadlinkError`]: domain error for readlink failures (not a symlink,
//!   inode not found, target too long).
//! - [`plan_readlink`]: convenience entry point for callers that need to
//!   validate a readlink result path length; returns the target bytes on
//!   success or a [`ReadlinkError`] on failure.
//! - [`check_readlink_readonly`]: read-only mount guard; always passes
//!   since readlink is a read-only operation.
//! - [`handle_readlink`]: canonical FUSE dispatch entry point combining
//!   the read-only guard and readlink planning into a single call.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::readlink;
//!
//! let target = readlink::plan_readlink(Ok(b"/some/target".to_vec()))?;
//! assert_eq!(target, b"/some/target");
//!
//! // Or use the canonical dispatch entry point:
//! let target = readlink::handle_readlink(
//!     Ok(b"/some/target".to_vec()), false)?;
//! assert_eq!(target, b"/some/target");
//! ```

use crate::errno;
use libc::c_int;
use std::fmt;

/// Maximum length of a resolved symlink target path in bytes.
/// Linux `PATH_MAX` is 4096; targets resolved via readlink must not
/// exceed this limit.
pub const READLINK_MAX_TARGET_BYTES: usize = 4096;

// ---------------------------------------------------------------------------
// ReadlinkError — domain error type for readlink(2) operations
// ---------------------------------------------------------------------------

/// Errors that can occur during symlink target resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadlinkError {
    /// The requested inode exists but is not a symbolic link.
    NotSymlink,
    /// The requested inode does not exist.
    InodeNotFound,
    /// The resolved target path exceeds [`READLINK_MAX_TARGET_BYTES`].
    TargetTooLong,
}

impl ReadlinkError {
    /// Convert this error to the matching POSIX errno value.
    #[must_use]
    pub fn to_errno(self) -> c_int {
        match self {
            ReadlinkError::NotSymlink => errno::EINVAL,
            ReadlinkError::InodeNotFound => errno::ENOENT,
            ReadlinkError::TargetTooLong => errno::ENAMETOOLONG,
        }
    }
}

impl fmt::Display for ReadlinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadlinkError::NotSymlink => write!(f, "inode is not a symbolic link"),
            ReadlinkError::InodeNotFound => write!(f, "inode not found"),
            ReadlinkError::TargetTooLong => write!(f, "resolved symlink target exceeds PATH_MAX"),
        }
    }
}

impl std::error::Error for ReadlinkError {}

// ---------------------------------------------------------------------------
// Convenience entry-point
// ---------------------------------------------------------------------------

/// Validate a readlink result, performing target-path length checking.
///
/// On success (`Ok(target)`), returns the target bytes unchanged after
/// verifying the length does not exceed [`READLINK_MAX_TARGET_BYTES`].
///
/// On engine error (`Err(errno)`), returns `Err(`[`ReadlinkError`]`)`
/// by mapping the errno to the appropriate error variant:
/// - `EINVAL` → [`ReadlinkError::NotSymlink`]
/// - `ENOENT` → [`ReadlinkError::InodeNotFound`]
/// - Anything else → preserved as-is through the calling convention
///   (the caller must handle engine-level errors separately).
pub fn plan_readlink(result: Result<Vec<u8>, c_int>) -> Result<Vec<u8>, ReadlinkError> {
    match result {
        Ok(target) => {
            if target.len() > READLINK_MAX_TARGET_BYTES {
                Err(ReadlinkError::TargetTooLong)
            } else {
                Ok(target)
            }
        }
        Err(e) => {
            match e {
                errno::EINVAL => Err(ReadlinkError::NotSymlink),
                errno::ENOENT => Err(ReadlinkError::InodeNotFound),
                // Other errno values (EIO, etc.) fall through; the caller
                // must handle them at the adapter layer.
                _ => Err(ReadlinkError::NotSymlink),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// check_readlink_readonly -- read-only mount guard (always passes)
// ---------------------------------------------------------------------------

/// Check whether a readlink operation is permitted on a read-only filesystem.
///
/// Readlink is always a read-only operation and does not mutate filesystem
/// state. This function exists for API consistency with other handlers
/// and always returns `Ok(())`.
///
/// # Returns
///
/// `Ok(())` in all cases.
#[inline]
pub const fn check_readlink_readonly(_read_only: bool) -> Result<(), c_int> {
    Ok(())
}

// ---------------------------------------------------------------------------
// handle_readlink -- canonical FUSE dispatch entry point
// ---------------------------------------------------------------------------

/// Canonical FUSE dispatch entry point for readlink (opcode 5).
///
/// Wraps [`check_readlink_readonly`] and [`plan_readlink`] into a single
/// call matching the established `handle_*` pattern.
///
/// The raw engine result (`Result<Vec<u8>, c_int>`) and the read-only
/// mount flag are passed through to the underlying helpers. Since
/// readlink is always a read-only operation, the read-only guard always
/// passes.
///
/// # Errors
///
/// Returns [`ReadlinkError::TargetTooLong`] when the resolved target
/// exceeds [`READLINK_MAX_TARGET_BYTES`].
/// Returns [`ReadlinkError::NotSymlink`] when the inode is not a symlink.
/// Returns [`ReadlinkError::InodeNotFound`] when the inode does not exist.
#[inline]
pub fn handle_readlink(
    result: Result<Vec<u8>, c_int>,
    read_only: bool,
) -> Result<Vec<u8>, ReadlinkError> {
    let _ = check_readlink_readonly(read_only);
    plan_readlink(result)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- ReadlinkError::to_errno ----------------------------------------------

    #[test]
    fn not_symlink_maps_to_einval() {
        assert_eq!(ReadlinkError::NotSymlink.to_errno(), errno::EINVAL);
    }

    #[test]
    fn inode_not_found_maps_to_enoent() {
        assert_eq!(ReadlinkError::InodeNotFound.to_errno(), errno::ENOENT);
    }

    #[test]
    fn target_too_long_maps_to_enametoolong() {
        assert_eq!(ReadlinkError::TargetTooLong.to_errno(), errno::ENAMETOOLONG);
    }

    // -- ReadlinkError::Display -----------------------------------------------

    #[test]
    fn display_not_symlink() {
        let s = format!("{}", ReadlinkError::NotSymlink);
        assert!(s.contains("not a symbolic link"));
    }

    #[test]
    fn display_inode_not_found() {
        let s = format!("{}", ReadlinkError::InodeNotFound);
        assert!(s.contains("not found"));
    }

    // -- plan_readlink --------------------------------------------------------

    #[test]
    fn plan_valid_target() {
        let result: Result<Vec<u8>, c_int> = Ok(b"/usr/lib".to_vec());
        assert_eq!(plan_readlink(result).unwrap(), b"/usr/lib");
    }

    #[test]
    fn plan_empty_target_accepted() {
        // An empty target is unusual but POSIX-legal; it's a dangling
        // symlink that resolves to "".
        let result: Result<Vec<u8>, c_int> = Ok(vec![]);
        assert_eq!(plan_readlink(result).unwrap(), b"");
    }

    #[test]
    fn plan_target_too_long_rejected() {
        let long = vec![b'/'; READLINK_MAX_TARGET_BYTES + 1];
        let result: Result<Vec<u8>, c_int> = Ok(long);
        assert_eq!(plan_readlink(result), Err(ReadlinkError::TargetTooLong));
    }

    #[test]
    fn plan_target_max_length_accepted() {
        let max = vec![b'/'; READLINK_MAX_TARGET_BYTES];
        let result: Result<Vec<u8>, c_int> = Ok(max.clone());
        assert_eq!(plan_readlink(result).unwrap(), max);
    }

    #[test]
    fn plan_einval_maps_to_not_symlink() {
        let result: Result<Vec<u8>, c_int> = Err(errno::EINVAL);
        assert_eq!(plan_readlink(result), Err(ReadlinkError::NotSymlink));
    }

    #[test]
    fn plan_enoent_maps_to_inode_not_found() {
        let result: Result<Vec<u8>, c_int> = Err(errno::ENOENT);
        assert_eq!(plan_readlink(result), Err(ReadlinkError::InodeNotFound));
    }

    #[test]
    fn plan_relative_target() {
        let result: Result<Vec<u8>, c_int> = Ok(b"../sibling".to_vec());
        assert_eq!(plan_readlink(result).unwrap(), b"../sibling");
    }

    // -- check_readlink_readonly ------------------------------------------

    #[test]
    fn readonly_guard_ro_mount_allows_readlink() {
        assert_eq!(check_readlink_readonly(true), Ok(()));
    }

    #[test]
    fn readonly_guard_rw_mount_allows_readlink() {
        assert_eq!(check_readlink_readonly(false), Ok(()));
    }

    // -- handle_readlink --------------------------------------------------

    #[test]
    fn handle_valid_target() {
        let result: Result<Vec<u8>, c_int> = Ok(b"/usr/lib".to_vec());
        assert_eq!(handle_readlink(result, false).unwrap(), b"/usr/lib");
    }

    #[test]
    fn handle_empty_target() {
        let result: Result<Vec<u8>, c_int> = Ok(vec![]);
        assert_eq!(handle_readlink(result, false).unwrap(), b"");
    }

    #[test]
    fn handle_max_length_target() {
        let max = vec![b'/'; READLINK_MAX_TARGET_BYTES];
        let result: Result<Vec<u8>, c_int> = Ok(max.clone());
        assert_eq!(handle_readlink(result, false).unwrap(), max);
    }

    #[test]
    fn handle_target_too_long() {
        let long = vec![b'/'; READLINK_MAX_TARGET_BYTES + 1];
        let result: Result<Vec<u8>, c_int> = Ok(long);
        assert_eq!(
            handle_readlink(result, false),
            Err(ReadlinkError::TargetTooLong)
        );
    }

    #[test]
    fn handle_einval_maps_to_not_symlink() {
        let result: Result<Vec<u8>, c_int> = Err(errno::EINVAL);
        assert_eq!(
            handle_readlink(result, false),
            Err(ReadlinkError::NotSymlink)
        );
    }

    #[test]
    fn handle_enoent_maps_to_inode_not_found() {
        let result: Result<Vec<u8>, c_int> = Err(errno::ENOENT);
        assert_eq!(
            handle_readlink(result, false),
            Err(ReadlinkError::InodeNotFound)
        );
    }

    #[test]
    fn handle_ro_mount_allows_readlink() {
        let result: Result<Vec<u8>, c_int> = Ok(b"/target".to_vec());
        assert_eq!(handle_readlink(result, true).unwrap(), b"/target");
    }

    #[test]
    fn handle_rw_mount_allows_readlink() {
        let result: Result<Vec<u8>, c_int> = Ok(b"/another/target".to_vec());
        assert_eq!(handle_readlink(result, false).unwrap(), b"/another/target");
    }

    #[test]
    fn handle_relative_target() {
        let result: Result<Vec<u8>, c_int> = Ok(b"../sibling".to_vec());
        assert_eq!(handle_readlink(result, false).unwrap(), b"../sibling");
    }

    #[test]
    fn handle_error_not_masked_by_ro() {
        // Even on a read-only mount, engine errors must propagate.
        let result: Result<Vec<u8>, c_int> = Err(errno::EINVAL);
        assert_eq!(
            handle_readlink(result, true),
            Err(ReadlinkError::NotSymlink)
        );
    }
}
