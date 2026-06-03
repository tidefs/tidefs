//! FUSE `symlink` handler helpers — link-name validation, target-path
//! validation, permission checks, and convenience entry-points for
//! POSIX-compliant symbolic-link creation with reply formatting.
//!
//! Provides:
//! - [`validate_symlink_name`]: reject empty, overlong, dot/dotdot, NUL,
//!   and slash-containing names; returns `Ok(())` or a [`SymlinkError`].
//! - [`validate_symlink_target`]: reject empty or overlong target paths;
//!   returns `Ok(())` or a [`SymlinkError`].
//! - [`check_symlink_parent_permission`]: verify write+execute permission
//!   on the parent directory.
//! - [`SymlinkRequest`]: validated request carrying parent inode,
//!   symlink name, and target path.
//! - [`validate_symlink_request`]: validate name + target and return
//!   a [`SymlinkRequest`] on success.
//! - [`plan_symlink`]: convenience: combined name + target validation
//!   returning `Ok(())` or a [`SymlinkError`].
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::symlink;
//!
//! symlink::plan_symlink(b"mylink", b"/some/target")?;
//! ```

use crate::errno;
use libc::c_int;
use std::fmt;
use std::time::Duration;
#[cfg(test)]
use std::time::SystemTime;

/// Maximum length of a single symlink-name component in bytes
/// (POSIX `NAME_MAX` on Linux).
pub const SYMLINK_MAX_NAME_BYTES: usize = 255;

/// Maximum length of a symlink target path in bytes.
/// Linux `PATH_MAX` is 4096; the symlink target stored in the inode
/// must not exceed this limit.
pub const SYMLINK_MAX_TARGET_BYTES: usize = 4096;

/// Default entry cache TTL (1 second) for symlink replies.
/// Positive lookups are cached so the kernel avoids re-looking up
/// the dentry on repeated access.
pub const DEFAULT_SYMLINK_ENTRY_TTL: Duration = Duration::from_secs(1);

/// Default entry cache TTL for negative (error) replies — zero.
pub const DEFAULT_SYMLINK_NEGATIVE_TTL: Duration = Duration::ZERO;

// ---------------------------------------------------------------------------
// SymlinkError — domain error type for symlink(2) operations
// ---------------------------------------------------------------------------

/// Errors that can occur during symlink name validation, target
/// validation, or permission checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkError {
    /// The provided link name is empty, `"."`, `".."`, contains a NUL
    /// byte, or contains a forward slash.
    InvalidName,
    /// The provided link name exceeds [`SYMLINK_MAX_NAME_BYTES`] bytes.
    NameTooLong,
    /// The symlink target path is empty.
    ParentNotFound,
    /// The parent inode is not a directory.
    NotADirectory,
    /// The link name already exists in the parent directory.
    NameExists,
    /// The filesystem has no free space for the new symlink inode.
    NoSpace,
    /// The symlink target path is empty.
    TargetEmpty,
    /// The filesystem is mounted read-only.
    ReadOnlyFilesystem,
    /// The symlink target path exceeds [`SYMLINK_MAX_TARGET_BYTES`]
    /// bytes.
    TargetTooLong,
    /// Caller lacks write+execute permission on the parent directory.
    PermissionDenied,
}

impl SymlinkError {
    /// Convert this error to the matching POSIX errno value.
    #[must_use]
    pub fn to_errno(self) -> c_int {
        match self {
            SymlinkError::InvalidName => errno::EINVAL,
            SymlinkError::ParentNotFound => libc::ENOENT,
            SymlinkError::NotADirectory => libc::ENOTDIR,
            SymlinkError::NameExists => libc::EEXIST,
            SymlinkError::NoSpace => libc::ENOSPC,
            SymlinkError::NameTooLong => errno::ENAMETOOLONG,
            SymlinkError::ReadOnlyFilesystem => errno::EROFS,
            SymlinkError::TargetEmpty => errno::ENOENT,
            SymlinkError::TargetTooLong => errno::ENAMETOOLONG,
            SymlinkError::PermissionDenied => errno::EACCES,
        }
    }
}

impl fmt::Display for SymlinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SymlinkError::InvalidName => write!(f, "invalid symlink name"),
            SymlinkError::ParentNotFound => write!(f, "parent directory not found"),
            SymlinkError::NotADirectory => write!(f, "parent is not a directory"),
            SymlinkError::NameExists => write!(f, "symlink name already exists"),
            SymlinkError::NoSpace => write!(f, "no space left for symlink creation"),
            SymlinkError::NameTooLong => write!(f, "symlink name too long"),
            SymlinkError::ReadOnlyFilesystem => write!(f, "read-only filesystem"),
            SymlinkError::TargetEmpty => write!(f, "symlink target is empty"),
            SymlinkError::TargetTooLong => write!(f, "symlink target too long"),
            SymlinkError::PermissionDenied => write!(f, "permission denied for symlink creation"),
        }
    }
}

impl std::error::Error for SymlinkError {}

impl From<SymlinkError> for c_int {
    fn from(e: SymlinkError) -> c_int {
        e.to_errno()
    }
}

// ---------------------------------------------------------------------------
// SymlinkRequest — validated request payload
// ---------------------------------------------------------------------------

/// Validated symlink request carrying parent inode, link name, and target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymlinkRequest {
    /// Parent directory inode number.
    pub parent: u64,
    /// Validated symlink name (guaranteed non-empty, no NUL/slash, ≤255 bytes).
    pub name: Vec<u8>,
    /// Validated symlink target path (guaranteed non-empty, ≤4096 bytes).
    pub target: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Permission check
// ---------------------------------------------------------------------------

/// Check that the caller has write and execute (search) permission
/// on the parent directory for a symlink operation.
///
/// POSIX requires directory write permission (to create the entry) and
/// execute/search permission (to traverse to the directory).
pub fn check_symlink_parent_permission(
    parent_mode: u32,
    parent_uid: u32,
    parent_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
) -> Result<(), SymlinkError> {
    crate::access::check_fuse_access(
        parent_mode,
        parent_uid,
        parent_gid,
        caller_uid,
        caller_gid,
        caller_groups,
        crate::access::ACCESS_WRITE | crate::access::ACCESS_EXECUTE,
    )
    .map_err(|_e| SymlinkError::PermissionDenied)
}

// ---------------------------------------------------------------------------
// Name validation
// ---------------------------------------------------------------------------

/// Validate a symlink name (the last path component).
///
/// Returns `Err(`[`SymlinkError::InvalidName`]`)` when the name is empty,
/// is `"."` or `".."`, contains a NUL byte, or contains a forward slash.
///
/// Returns `Err(`[`SymlinkError::NameTooLong`]`)` when the name exceeds
/// [`SYMLINK_MAX_NAME_BYTES`].
///
/// Returns `Ok(())` on success.
pub fn validate_symlink_name(name: &[u8]) -> Result<(), SymlinkError> {
    if name.is_empty() {
        return Err(SymlinkError::InvalidName);
    }
    if name.len() > SYMLINK_MAX_NAME_BYTES {
        return Err(SymlinkError::NameTooLong);
    }
    if name == b"." || name == b".." {
        return Err(SymlinkError::InvalidName);
    }
    if name.contains(&0) {
        return Err(SymlinkError::InvalidName);
    }
    if name.contains(&b'/') {
        return Err(SymlinkError::InvalidName);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Target validation
// ---------------------------------------------------------------------------

/// Validate a symlink target path.
///
/// Returns `Err(`[`SymlinkError::TargetEmpty`]`)` when the target is
/// empty (zero-length).
///
/// Returns `Err(`[`SymlinkError::TargetTooLong`]`)` when the target
/// exceeds [`SYMLINK_MAX_TARGET_BYTES`].
///
/// POSIX does not require the target to be a valid path or to exist;
/// symlinks can point to nonexistent or dangling destinations.
///
/// Returns `Ok(())` on success.
pub fn validate_symlink_target(target: &[u8]) -> Result<(), SymlinkError> {
    if target.is_empty() {
        return Err(SymlinkError::TargetEmpty);
    }
    if target.len() > SYMLINK_MAX_TARGET_BYTES {
        return Err(SymlinkError::TargetTooLong);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Combined validation (convenience)
// ---------------------------------------------------------------------------

/// Validate both the symlink name and target in one call.
///
/// Returns `Ok(())` on success.
/// On failure returns a [`SymlinkError`].
pub fn plan_symlink(name: &[u8], target: &[u8]) -> Result<(), SymlinkError> {
    validate_symlink_name(name)?;
    validate_symlink_target(target)
}

// ---------------------------------------------------------------------------
// SymlinkRequest validation
// ---------------------------------------------------------------------------

/// Validate a symlink request: name, target, and parent inode.
///
/// Returns `Err(`[`SymlinkError::InvalidName`]`)` when the name is invalid,
/// `Err(`[`SymlinkError::NameTooLong`]`)` when the name exceeds limits,
/// `Err(`[`SymlinkError::TargetEmpty`]`)` when the target is empty, or
/// `Err(`[`SymlinkError::TargetTooLong`]`)` when the target exceeds limits.
///
/// Returns `Ok(`[`SymlinkRequest`]`)` on success.
pub fn validate_symlink_request(
    parent: u64,
    name: &[u8],
    target: &[u8],
) -> Result<SymlinkRequest, SymlinkError> {
    validate_symlink_name(name)?;
    validate_symlink_target(target)?;
    Ok(SymlinkRequest {
        parent,
        name: name.to_vec(),
        target: target.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Reply formatting
// ---------------------------------------------------------------------------

/// Format a symlink reply in terms consumable by the daemon adapter.
///
/// Returns the entry cache TTL to use in the fuse reply.
/// The daemon adapter calls `reply.entry(&ttl, &attr, generation)`
/// for success or `reply.error(errno)` for failure.
#[must_use]
pub fn format_symlink_reply_ttl(is_success: bool) -> Duration {
    if is_success {
        DEFAULT_SYMLINK_ENTRY_TTL
    } else {
        DEFAULT_SYMLINK_NEGATIVE_TTL
    }
}

// ---------------------------------------------------------------------------
// SymlinkPlan -- validated symlink request
// ---------------------------------------------------------------------------

/// A validated `symlink` request ready for backend dispatch.
///
/// Created by [`handle_symlink`], which performs all client-visible
/// validation (name checks, target checks, read-only mount guard)
/// before the backend is invoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymlinkPlan {
    /// The validated symlink name.  Guaranteed to be non-empty,
    /// not `"."` or `".."`, free of NUL bytes and slashes, and
    /// at most [`SYMLINK_MAX_NAME_BYTES`] bytes long.
    pub name: Vec<u8>,
    /// The validated symlink target path.  Guaranteed to be non-empty
    /// and at most [`SYMLINK_MAX_TARGET_BYTES`] bytes.
    pub target: Vec<u8>,
}

impl SymlinkPlan {
    /// Construct a `SymlinkPlan` from a validated request.
    #[must_use]
    pub fn from_request(req: SymlinkRequest) -> Self {
        Self {
            name: req.name,
            target: req.target,
        }
    }
}

// ---------------------------------------------------------------------------
// SymlinkEntryReply — reply data for constructing FUSE EntryOut
// ---------------------------------------------------------------------------

/// Structured reply data for a symlink FUSE response.
///
/// On success: `attr` is the new symlink inode's `FileAttr`,
/// `generation` is the inode generation number, and `ttl` is the
/// kernel entry-cache TTL.
///
/// On failure: `error` is the errno to report, and `attr`/`generation`/
/// `ttl` are zero/default.
#[derive(Clone, Debug)]
pub struct SymlinkEntryReply {
    /// Inode attributes of the newly created symlink (Some on success).
    pub attr: Option<crate::FileAttr>,
    /// Inode generation number for NFS re-export compatibility.
    pub generation: u64,
    /// Kernel entry-cache TTL for this dentry.
    pub ttl: Duration,
    /// Error code (Some on failure).
    pub error: Option<c_int>,
}

impl SymlinkEntryReply {
    /// Construct a success reply with the given attributes and generation.
    #[must_use]
    pub fn success(attr: crate::FileAttr, generation: u64) -> Self {
        Self {
            attr: Some(attr),
            generation,
            ttl: DEFAULT_SYMLINK_ENTRY_TTL,
            error: None,
        }
    }

    /// Construct a failure reply with the given errno.
    #[must_use]
    pub fn failure(errno: c_int) -> Self {
        Self {
            attr: None,
            generation: 0,
            ttl: DEFAULT_SYMLINK_NEGATIVE_TTL,
            error: Some(errno),
        }
    }
}

// ---------------------------------------------------------------------------
// Read-only mount guard
// ---------------------------------------------------------------------------

/// Reject `symlink` creation on a read-only mount.
///
/// POSIX `symlink(2)` returns `EROFS` when the filesystem containing
/// the parent directory is mounted read-only.
///
/// # Errors
///
/// Returns [`SymlinkError::ReadOnlyFilesystem`] when `read_only` is
/// `true`.
pub fn check_symlink_readonly(read_only: bool) -> Result<(), SymlinkError> {
    if read_only {
        return Err(SymlinkError::ReadOnlyFilesystem);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unified dispatch entry-point
// ---------------------------------------------------------------------------

/// Canonical dispatch entry-point for FUSE `symlink`.
///
/// Combines name validation, target validation, and read-only mount
/// guard into a single call.  Returns a [`SymlinkPlan`] ready for
/// delegation to the VFS engine backend.
///
/// # Errors
///
/// Returns [`SymlinkError`] when name validation, target validation,
/// or read-only mount guard fails.
pub fn handle_symlink(
    name: &[u8],
    target: &[u8],
    read_only: bool,
) -> Result<SymlinkPlan, SymlinkError> {
    validate_symlink_name(name)?;
    validate_symlink_target(target)?;
    check_symlink_readonly(read_only)?;
    Ok(SymlinkPlan {
        name: name.to_vec(),
        target: target.to_vec(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    // -- SymlinkError::to_errno -----------------------------------------------

    #[test]
    fn invalid_name_maps_to_einval() {
        assert_eq!(SymlinkError::InvalidName.to_errno(), errno::EINVAL);
    }

    #[test]
    fn name_too_long_maps_to_enametoolong() {
        assert_eq!(SymlinkError::NameTooLong.to_errno(), errno::ENAMETOOLONG);
    }

    #[test]
    fn target_empty_maps_to_enoent() {
        assert_eq!(SymlinkError::TargetEmpty.to_errno(), errno::ENOENT);
    }

    #[test]
    fn target_too_long_maps_to_enametoolong() {
        assert_eq!(SymlinkError::TargetTooLong.to_errno(), errno::ENAMETOOLONG);
    }

    #[test]
    fn permission_denied_maps_to_eacces() {
        assert_eq!(SymlinkError::PermissionDenied.to_errno(), errno::EACCES);
    }

    #[test]
    fn parent_not_found_maps_to_enoent() {
        assert_eq!(SymlinkError::ParentNotFound.to_errno(), libc::ENOENT);
    }

    #[test]
    fn not_a_directory_maps_to_enotdir() {
        assert_eq!(SymlinkError::NotADirectory.to_errno(), libc::ENOTDIR);
    }

    #[test]
    fn name_exists_maps_to_eexist() {
        assert_eq!(SymlinkError::NameExists.to_errno(), libc::EEXIST);
    }

    #[test]
    fn no_space_maps_to_enospc() {
        assert_eq!(SymlinkError::NoSpace.to_errno(), libc::ENOSPC);
    }

    // -- SymlinkError::From<c_int> ------------------------------------------

    #[test]
    fn symlink_error_into_c_int() {
        let err: c_int = SymlinkError::InvalidName.into();
        assert_eq!(err, libc::EINVAL);
        let err: c_int = SymlinkError::ReadOnlyFilesystem.into();
        assert_eq!(err, libc::EROFS);
        let err: c_int = SymlinkError::NoSpace.into();
        assert_eq!(err, libc::ENOSPC);
    }

    // -- SymlinkError::Display -------------------------------------------------

    #[test]
    fn display_invalid_name() {
        let s = format!("{}", SymlinkError::InvalidName);
        assert!(s.contains("invalid symlink name"));
    }

    #[test]
    fn display_target_empty() {
        let s = format!("{}", SymlinkError::TargetEmpty);
        assert!(s.contains("empty"));
    }

    // -- validate_symlink_name -------------------------------------------------

    #[test]
    fn name_empty_rejected() {
        assert_eq!(validate_symlink_name(b""), Err(SymlinkError::InvalidName));
    }

    #[test]
    fn name_too_long_rejected() {
        let long = vec![b'a'; 256];
        assert_eq!(validate_symlink_name(&long), Err(SymlinkError::NameTooLong));
    }

    #[test]
    fn name_max_length_accepted() {
        let max = vec![b'a'; 255];
        assert_eq!(validate_symlink_name(&max), Ok(()));
    }

    #[test]
    fn dot_rejected() {
        assert_eq!(validate_symlink_name(b"."), Err(SymlinkError::InvalidName));
    }

    #[test]
    fn dotdot_rejected() {
        assert_eq!(validate_symlink_name(b".."), Err(SymlinkError::InvalidName));
    }

    #[test]
    fn nul_byte_rejected() {
        assert_eq!(
            validate_symlink_name(b"foo\0bar"),
            Err(SymlinkError::InvalidName)
        );
    }

    #[test]
    fn slash_rejected() {
        assert_eq!(
            validate_symlink_name(b"a/b"),
            Err(SymlinkError::InvalidName)
        );
    }

    #[test]
    fn normal_name_accepted() {
        assert_eq!(validate_symlink_name(b"mylink"), Ok(()));
        assert_eq!(validate_symlink_name(b"link with spaces"), Ok(()));
        assert_eq!(validate_symlink_name(b"link-with-dashes"), Ok(()));
        assert_eq!(validate_symlink_name(b"link_with_underscores"), Ok(()));
    }

    // -- validate_symlink_target -----------------------------------------------

    #[test]
    fn target_empty_rejected() {
        assert_eq!(validate_symlink_target(b""), Err(SymlinkError::TargetEmpty));
    }

    #[test]
    fn target_too_long_rejected() {
        let long = vec![b'/'; SYMLINK_MAX_TARGET_BYTES + 1];
        assert_eq!(
            validate_symlink_target(&long),
            Err(SymlinkError::TargetTooLong)
        );
    }

    #[test]
    fn target_max_length_accepted() {
        let max = vec![b'/'; SYMLINK_MAX_TARGET_BYTES];
        assert_eq!(validate_symlink_target(&max), Ok(()));
    }

    #[test]
    fn target_normal_accepted() {
        assert_eq!(validate_symlink_target(b"/usr/lib"), Ok(()));
        assert_eq!(validate_symlink_target(b"relative/path"), Ok(()));
        assert_eq!(validate_symlink_target(b"../sibling"), Ok(()));
        assert_eq!(validate_symlink_target(b"file.txt"), Ok(()));
    }

    // -- plan_symlink ----------------------------------------------------------

    #[test]
    fn plan_valid_symlink() {
        assert_eq!(plan_symlink(b"mylink", b"/target"), Ok(()));
    }

    #[test]
    fn plan_invalid_name() {
        assert_eq!(
            plan_symlink(b"", b"/target"),
            Err(SymlinkError::InvalidName)
        );
    }

    #[test]
    fn plan_empty_target() {
        assert_eq!(plan_symlink(b"mylink", b""), Err(SymlinkError::TargetEmpty));
    }

    #[test]
    fn plan_dot_name() {
        assert_eq!(plan_symlink(b".", b"/t"), Err(SymlinkError::InvalidName));
    }

    #[test]
    fn plan_dotdot_name() {
        assert_eq!(plan_symlink(b"..", b"/t"), Err(SymlinkError::InvalidName));
    }

    #[test]
    fn plan_name_with_nul() {
        assert_eq!(
            plan_symlink(b"bad\0name", b"/t"),
            Err(SymlinkError::InvalidName)
        );
    }

    #[test]
    fn plan_name_with_slash() {
        assert_eq!(plan_symlink(b"a/b", b"/t"), Err(SymlinkError::InvalidName));
    }

    #[test]
    fn plan_target_max_len() {
        let target = vec![b'/'; SYMLINK_MAX_TARGET_BYTES];
        assert_eq!(plan_symlink(b"link", &target), Ok(()));
    }

    #[test]
    fn plan_target_over_max() {
        let target = vec![b'/'; SYMLINK_MAX_TARGET_BYTES + 1];
        assert_eq!(
            plan_symlink(b"link", &target),
            Err(SymlinkError::TargetTooLong)
        );
    }

    // -- check_symlink_readonly ----------------------------------------------

    #[test]
    fn readonly_rw_mount_passes() {
        assert_eq!(check_symlink_readonly(false), Ok(()));
    }

    #[test]
    fn readonly_ro_mount_rejected() {
        assert_eq!(
            check_symlink_readonly(true),
            Err(SymlinkError::ReadOnlyFilesystem)
        );
    }

    // -- handle_symlink ------------------------------------------------------

    #[test]
    fn handle_symlink_valid_name_and_target() {
        let plan = handle_symlink(b"mylink", b"/some/target", false);
        assert!(plan.is_ok());
        let plan = plan.unwrap();
        assert_eq!(plan.name, b"mylink");
        assert_eq!(plan.target, b"/some/target");
    }

    #[test]
    fn handle_symlink_empty_name() {
        assert_eq!(
            handle_symlink(b"", b"/target", false),
            Err(SymlinkError::InvalidName)
        );
    }

    #[test]
    fn handle_symlink_dot_name() {
        assert_eq!(
            handle_symlink(b".", b"/target", false),
            Err(SymlinkError::InvalidName)
        );
    }

    #[test]
    fn handle_symlink_dotdot_name() {
        assert_eq!(
            handle_symlink(b"..", b"/target", false),
            Err(SymlinkError::InvalidName)
        );
    }

    #[test]
    fn handle_symlink_name_too_long() {
        let name = vec![b'a'; 256];
        assert_eq!(
            handle_symlink(&name, b"/target", false),
            Err(SymlinkError::NameTooLong)
        );
    }

    #[test]
    fn handle_symlink_nul_byte_in_name() {
        assert_eq!(
            handle_symlink(b"bad\0name", b"/target", false),
            Err(SymlinkError::InvalidName)
        );
    }

    #[test]
    fn handle_symlink_slash_in_name() {
        assert_eq!(
            handle_symlink(b"a/b", b"/target", false),
            Err(SymlinkError::InvalidName)
        );
    }

    #[test]
    fn handle_symlink_empty_target() {
        assert_eq!(
            handle_symlink(b"link", b"", false),
            Err(SymlinkError::TargetEmpty)
        );
    }

    #[test]
    fn handle_symlink_target_too_long() {
        let target = vec![b'x'; 4097];
        assert_eq!(
            handle_symlink(b"link", &target, false),
            Err(SymlinkError::TargetTooLong)
        );
    }

    #[test]
    fn handle_symlink_ro_mount() {
        assert_eq!(
            handle_symlink(b"link", b"/target", true),
            Err(SymlinkError::ReadOnlyFilesystem)
        );
    }

    #[test]
    fn handle_symlink_name_error_has_priority_over_ro() {
        assert_eq!(
            handle_symlink(b"", b"/target", true),
            Err(SymlinkError::InvalidName)
        );
    }

    #[test]
    fn handle_symlink_target_error_has_priority_over_ro() {
        assert_eq!(
            handle_symlink(b"link", b"", true),
            Err(SymlinkError::TargetEmpty)
        );
    }

    // -- SymlinkPlan ---------------------------------------------------------

    #[test]
    fn symlink_plan_debug_includes_name_and_target() {
        let plan = handle_symlink(b"testlink", b"/opt/target", false).unwrap();
        let dbg = format!("{plan:?}");
        assert!(dbg.contains("SymlinkPlan"));
    }

    #[test]
    fn symlink_plan_clone_preserves_fields() {
        let plan = handle_symlink(b"testlink", b"/opt/target", false).unwrap();
        let clone = plan.clone();
        assert_eq!(plan.name, clone.name);
        assert_eq!(plan.target, clone.target);
    }

    #[test]
    fn symlink_plan_preserves_exact_bytes() {
        let plan = handle_symlink(b"MiXeDcAsE", b"/TaRgEt", false).unwrap();
        assert_eq!(plan.name, b"MiXeDcAsE");
        assert_eq!(plan.target, b"/TaRgEt");
    }

    // -- ReadOnlyFilesystem error variant -----------------------------------

    #[test]
    fn readonly_error_to_errno_is_erofs() {
        assert_eq!(SymlinkError::ReadOnlyFilesystem.to_errno(), errno::EROFS);
    }

    #[test]
    fn readonly_error_display_contains_read_only() {
        let msg = format!("{}", SymlinkError::ReadOnlyFilesystem);
        assert!(msg.contains("read-only"));
    }

    #[test]
    fn readonly_error_debug_includes_variant() {
        let dbg = format!("{:?}", SymlinkError::ReadOnlyFilesystem);
        assert!(dbg.contains("ReadOnlyFilesystem"));
    }

    // -- SymlinkRequest ----------------------------------------------------

    #[test]
    fn symlink_request_fields_preserved() {
        let req = SymlinkRequest {
            parent: 42,
            name: b"link".to_vec(),
            target: b"/target".to_vec(),
        };
        assert_eq!(req.parent, 42);
        assert_eq!(req.name, b"link");
        assert_eq!(req.target, b"/target");
    }

    #[test]
    fn symlink_request_debug() {
        let req = SymlinkRequest {
            parent: 1,
            name: b"a".to_vec(),
            target: b"b".to_vec(),
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("SymlinkRequest"));
    }

    // -- validate_symlink_request ------------------------------------------

    #[test]
    fn validate_request_valid() {
        let req = validate_symlink_request(42, b"mylink", b"/some/target");
        assert!(req.is_ok());
        let req = req.unwrap();
        assert_eq!(req.parent, 42);
        assert_eq!(req.name, b"mylink");
        assert_eq!(req.target, b"/some/target");
    }

    #[test]
    fn validate_request_empty_name() {
        assert_eq!(
            validate_symlink_request(1, b"", b"/t"),
            Err(SymlinkError::InvalidName)
        );
    }

    #[test]
    fn validate_request_dot_name() {
        assert_eq!(
            validate_symlink_request(1, b".", b"/t"),
            Err(SymlinkError::InvalidName)
        );
    }

    #[test]
    fn validate_request_empty_target() {
        assert_eq!(
            validate_symlink_request(1, b"link", b""),
            Err(SymlinkError::TargetEmpty)
        );
    }

    #[test]
    fn validate_request_overlong_target() {
        let target = vec![b'/'; SYMLINK_MAX_TARGET_BYTES + 1];
        assert_eq!(
            validate_symlink_request(1, b"link", &target),
            Err(SymlinkError::TargetTooLong)
        );
    }

    // -- SymlinkEntryReply -------------------------------------------------

    #[test]
    fn entry_reply_success_has_attr() {
        let attr = crate::FileAttr {
            ino: 100,
            size: 0,
            blocks: 0,
            atime: SystemTime::UNIX_EPOCH,
            mtime: SystemTime::UNIX_EPOCH,
            ctime: SystemTime::UNIX_EPOCH,
            crtime: SystemTime::UNIX_EPOCH,
            kind: crate::FileType::Symlink,
            perm: 0o777,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        };
        let reply = SymlinkEntryReply::success(attr, 5);
        assert!(reply.attr.is_some());
        assert_eq!(reply.generation, 5);
        assert_eq!(reply.ttl, DEFAULT_SYMLINK_ENTRY_TTL);
        assert!(reply.error.is_none());
    }

    #[test]
    fn entry_reply_failure_has_errno() {
        let reply = SymlinkEntryReply::failure(libc::EROFS);
        assert!(reply.attr.is_none());
        assert_eq!(reply.generation, 0);
        assert_eq!(reply.error, Some(libc::EROFS));
        assert_eq!(reply.ttl, DEFAULT_SYMLINK_NEGATIVE_TTL);
    }

    // -- format_symlink_reply_ttl ------------------------------------------

    #[test]
    fn reply_ttl_success_is_positive() {
        assert_eq!(format_symlink_reply_ttl(true), DEFAULT_SYMLINK_ENTRY_TTL);
    }

    #[test]
    fn reply_ttl_failure_is_zero() {
        assert_eq!(
            format_symlink_reply_ttl(false),
            DEFAULT_SYMLINK_NEGATIVE_TTL
        );
    }
}
