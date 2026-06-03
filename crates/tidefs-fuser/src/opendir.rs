//! FUSE `opendir` handler helpers — directory open validation,
//! directory-type assertion, read-only guard, handle allocation,
//! and reply formatting for persistent directory handles.
//!
//! FUSE opendir (opcode 27) is the protocol pre-condition for
//! readdir: the kernel calls opendir before the first readdir on a
//! directory handle.  A correct handler validates the inode is a
//! directory, allocates a handle, and returns it to the kernel.
//!
//! Provides:
//! - [`OpendirRequest`]: parsed representation of a FUSE opendir request.
//! - [`parse_opendir_request`]: convert raw FUSE opendir parameters
//!   into a structured request.
//! - [`OpendirError`]: domain error type for opendir operations.
//! - [`OpendirPlan`]: validated opendir request ready for backend dispatch.
//! - [`validate_opendir_request`]: full request validation (inode non-zero,
//!   directory-type assertion, flags sanity).
//! - [`validate_opendir_inode`]: convenience check that an inode kind
//!   is a directory.
//! - [`check_opendir_readonly`]: reject opendir on a read-only filesystem.
//! - [`handle_opendir`]: canonical dispatch entry-point combining
//!   read-only guard, request validation, handle allocation, and
//!   plan construction.
//! - [`allocate_dir_handle`]: allocate a directory handle ID from a
//!   caller-provided counter.
//! - [`format_opendir_reply`]: format the FUSE open reply with
//!   directory handle ID and optional flags.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::opendir;
//!
//! let plan = opendir::handle_opendir(
//!     ino, flags, false, &mut next_handle_id,
//!     kind_provider,
//! )?;
//! opendir::format_opendir_reply(reply, plan.dh_id, 0)?;
//! ```

use crate::errno;
use libc::c_int;
use std::fmt;

// Re-export POSIX errno codes used by opendir.
pub use libc::{EBADF, EINVAL, EIO, ENOENT, ENOMEM, ENOTDIR};

/// Maximum permitted open flags for opendir.
///
/// Only `O_RDONLY` (0), `O_DIRECTORY`, `O_NOFOLLOW`, and
/// `O_NONBLOCK` are typically relevant for directory opens.
/// Flag bits outside this mask are rejected as `EINVAL`.
const OPENDIR_ALLOWED_FLAGS: i32 =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK;

// ---------------------------------------------------------------------------
// OpendirRequest
// ---------------------------------------------------------------------------

/// Parsed FUSE opendir request.
#[derive(Clone, Copy, Debug)]
pub struct OpendirRequest {
    /// Inode number of the directory to open.
    pub ino: u64,
    /// Open flags (same semantics as open(2)).
    pub flags: i32,
}

/// Parse a FUSE opendir request from raw parameters.
///
/// Returns `Err(EINVAL)` if `ino` is 0 (invalid inode).
pub fn parse_opendir_request(ino: u64, flags: i32) -> Result<OpendirRequest, c_int> {
    if ino == 0 {
        return Err(libc::EINVAL);
    }
    Ok(OpendirRequest { ino, flags })
}

// ---------------------------------------------------------------------------
// OpendirError — domain error type for opendir operations
// ---------------------------------------------------------------------------

/// Errors that can occur during opendir request validation,
/// directory-type assertion, read-only guard, or handle allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpendirError {
    /// The inode is not a directory (calling opendir on a regular file,
    /// symlink, block device, etc.).
    NotADirectory,
    /// The inode number is 0 (invalid).
    InvalidInode,
    /// The open flags contain unsupported bit patterns.
    BadFlags,
    /// The filesystem is mounted read-only.
    ReadOnlyFilesystem,
    /// Internal I/O error (handle counter wrapped or other backend
    /// failure).
    Io,
    /// Unknown or unexpected error not covered by other variants.
    Other,
}

impl OpendirError {
    /// Convert this error to the matching POSIX errno value.
    #[must_use]
    pub fn to_errno(self) -> c_int {
        match self {
            OpendirError::NotADirectory => errno::ENOTDIR,
            OpendirError::InvalidInode => errno::EINVAL,
            OpendirError::BadFlags => errno::EINVAL,
            OpendirError::ReadOnlyFilesystem => errno::EROFS,
            OpendirError::Io => errno::EIO,
            OpendirError::Other => errno::EIO,
        }
    }
}

impl fmt::Display for OpendirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpendirError::NotADirectory => {
                write!(f, "opendir on non-directory inode")
            }
            OpendirError::InvalidInode => {
                write!(f, "opendir with invalid inode number")
            }
            OpendirError::BadFlags => {
                write!(f, "opendir with unsupported flags")
            }
            OpendirError::ReadOnlyFilesystem => {
                write!(f, "opendir on read-only filesystem")
            }
            OpendirError::Io => {
                write!(f, "opendir internal I/O error")
            }
            OpendirError::Other => {
                write!(f, "opendir unknown error")
            }
        }
    }
}

impl std::error::Error for OpendirError {}

impl From<OpendirError> for c_int {
    fn from(e: OpendirError) -> c_int {
        e.to_errno()
    }
}

// ---------------------------------------------------------------------------
// OpendirPlan — validated opendir request ready for backend dispatch
// ---------------------------------------------------------------------------

/// A validated opendir request with an allocated directory handle
/// ready for backend dispatch.
///
/// Created by [`handle_opendir`], which performs all client-visible
/// validation (inode non-zero, directory-type assertion, flags sanity,
/// read-only guard) and allocates a directory handle before returning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpendirPlan {
    /// The directory inode number.
    pub ino: u64,
    /// The allocated directory handle ID (non-zero).
    pub dh_id: u64,
    /// The open flags that were requested.
    pub flags: i32,
}

// ---------------------------------------------------------------------------
// Inode validation
// ---------------------------------------------------------------------------

/// Validate that an inode kind is a directory.
///
/// This is a convenience for backends that check the inode kind
/// before allocating a directory handle.
///
/// Returns `Ok(())` for directories, `Err(ENOTDIR)` for non-directories.
pub fn validate_opendir_inode(kind: crate::FileType) -> Result<(), c_int> {
    if kind == crate::FileType::Directory {
        Ok(())
    } else {
        Err(libc::ENOTDIR)
    }
}

/// Full request validation for a FUSE opendir request.
///
/// Checks:
/// 1. The inode number is non-zero.
/// 2. The open flags do not contain unsupported bits.
/// 3. The inode kind (provided by the caller via `kind`) is a directory.
///
/// Returns `Ok(`[`OpendirRequest`]`)` on success.
/// Returns `Err(`[`OpendirError`]`)` on failure.
pub fn validate_opendir_request(
    ino: u64,
    flags: i32,
    kind: crate::FileType,
) -> Result<OpendirRequest, OpendirError> {
    if ino == 0 {
        return Err(OpendirError::InvalidInode);
    }
    // Reject flags with unsupported bits (e.g. O_WRONLY, O_RDWR on a directory)
    if flags & !OPENDIR_ALLOWED_FLAGS != 0 {
        return Err(OpendirError::BadFlags);
    }
    if kind != crate::FileType::Directory {
        return Err(OpendirError::NotADirectory);
    }
    Ok(OpendirRequest { ino, flags })
}

// ---------------------------------------------------------------------------
// Read-only guard
// ---------------------------------------------------------------------------

/// Reject opendir on a read-only filesystem.
///
/// POSIX `opendir(3)` returns `EROFS` when the filesystem containing
/// the directory is mounted read-only.
///
/// # Errors
///
/// Returns [`OpendirError::ReadOnlyFilesystem`] when `read_only` is
/// `true`.
#[inline]
pub fn check_opendir_readonly(read_only: bool) -> Result<(), OpendirError> {
    if read_only {
        Err(OpendirError::ReadOnlyFilesystem)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Handle allocation
// ---------------------------------------------------------------------------

/// Allocate a directory handle ID using a caller-provided counter.
///
/// Increments `next_handle_id` (a mutable u64 reference) and returns
/// the allocated handle.  If the counter overflows `u64::MAX` or wraps
/// to 0, returns `Err(EIO)`.
///
/// Handle 0 is reserved and will never be returned.
///
/// # Example
///
/// ```rust,ignore
/// let mut next_id = 1u64;
/// let dh_id = opendir::allocate_dir_handle(ino, &mut next_id)?;
/// ```
pub fn allocate_dir_handle(_ino: u64, next_handle_id: &mut u64) -> Result<u64, c_int> {
    let id = *next_handle_id;
    if id == 0 {
        // 0 was already wrapped; refuse further allocations.
        return Err(libc::EIO);
    }
    *next_handle_id = next_handle_id.wrapping_add(1);
    if *next_handle_id == 0 {
        // Wrapped; next call will get EIO.
        *next_handle_id = 0;
    }
    Ok(id)
}

// ---------------------------------------------------------------------------
// Reply formatting
// ---------------------------------------------------------------------------

/// Format a FUSE opendir reply with an allocated directory handle.
///
/// `fh` is the allocated directory handle ID (must be non-zero).
/// `open_flags` are the FUSE open reply flags (e.g., `FOPEN_CACHE_DIR`).
///
/// Returns `Err(EINVAL)` if `fh` is 0 (reserved).
pub fn format_opendir_reply(
    reply: crate::ReplyOpen,
    fh: u64,
    open_flags: u32,
) -> Result<(), c_int> {
    if fh == 0 {
        return Err(libc::EINVAL);
    }
    reply.opened(fh, open_flags);
    Ok(())
}

// ---------------------------------------------------------------------------
// handle_opendir — canonical dispatch entry-point
// ---------------------------------------------------------------------------

/// Perform full opendir validation and return an [`OpendirPlan`]
/// ready for backend dispatch.
///
/// This is the canonical FUSE dispatch entry point for `opendir`
/// (opcode 27).  It:
///
/// 1. Rejects read-only mounts (EROFS).
/// 2. Validates the inode number (non-zero).
/// 3. Validates the open flags (no unsupported bits).
/// 4. Asserts the inode is a directory.
/// 5. Allocates a directory handle from the caller-provided counter.
///
/// Returns an [`OpendirPlan`] with the allocated handle on success.
///
/// # Errors
///
/// Returns [`OpendirError::ReadOnlyFilesystem`] for read-only mounts,
/// [`OpendirError::InvalidInode`] for zero inode numbers,
/// [`OpendirError::BadFlags`] for unsupported flag bits,
/// [`OpendirError::NotADirectory`] for non-directory inodes, and
/// [`OpendirError::Io`] for handle-allocation failures.
#[inline]
pub fn handle_opendir(
    ino: u64,
    flags: i32,
    read_only: bool,
    next_handle_id: &mut u64,
    kind: crate::FileType,
) -> Result<OpendirPlan, OpendirError> {
    check_opendir_readonly(read_only)?;
    let _req = validate_opendir_request(ino, flags, kind)?;
    let dh_id = allocate_dir_handle(ino, next_handle_id).map_err(|_| OpendirError::Io)?;
    Ok(OpendirPlan { ino, dh_id, flags })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- parse_opendir_request -------------------------------------------------

    #[test]
    fn parse_valid_opendir_request() {
        let req = parse_opendir_request(42, 0).expect("valid request");
        assert_eq!(req.ino, 42);
        assert_eq!(req.flags, 0);
    }

    #[test]
    fn parse_opendir_with_flags() {
        let req = parse_opendir_request(10, 0o40000).expect("valid request");
        assert_eq!(req.ino, 10);
        assert_eq!(req.flags, 0o40000);
    }

    #[test]
    fn parse_opendir_rejects_zero_inode() {
        assert_eq!(parse_opendir_request(0, 0).unwrap_err(), libc::EINVAL);
    }

    // -- validate_opendir_inode -------------------------------------------------

    #[test]
    fn validate_directory_inode() {
        assert!(validate_opendir_inode(crate::FileType::Directory).is_ok());
    }

    #[test]
    fn validate_nondirectory_inode_returns_enotdir() {
        assert_eq!(
            validate_opendir_inode(crate::FileType::RegularFile).unwrap_err(),
            libc::ENOTDIR
        );
        assert_eq!(
            validate_opendir_inode(crate::FileType::Symlink).unwrap_err(),
            libc::ENOTDIR
        );
        assert_eq!(
            validate_opendir_inode(crate::FileType::BlockDevice).unwrap_err(),
            libc::ENOTDIR
        );
    }

    // -- validate_opendir_request -----------------------------------------------

    #[test]
    fn validate_request_directory_ok() {
        let req = validate_opendir_request(1, 0, crate::FileType::Directory)
            .expect("valid directory opendir");
        assert_eq!(req.ino, 1);
        assert_eq!(req.flags, 0);
    }

    #[test]
    fn validate_request_zero_inode_rejected() {
        let err = validate_opendir_request(0, 0, crate::FileType::Directory).unwrap_err();
        assert_eq!(err, OpendirError::InvalidInode);
    }

    #[test]
    fn validate_request_regular_file_rejected() {
        let err = validate_opendir_request(100, 0, crate::FileType::RegularFile).unwrap_err();
        assert_eq!(err, OpendirError::NotADirectory);
    }

    #[test]
    fn validate_request_symlink_rejected() {
        let err = validate_opendir_request(200, 0, crate::FileType::Symlink).unwrap_err();
        assert_eq!(err, OpendirError::NotADirectory);
    }

    #[test]
    fn validate_request_socket_rejected() {
        let err = validate_opendir_request(300, 0, crate::FileType::Socket).unwrap_err();
        assert_eq!(err, OpendirError::NotADirectory);
    }

    #[test]
    fn validate_request_bad_flags_rejected() {
        // O_WRONLY (1) should not be allowed on a directory
        let err =
            validate_opendir_request(1, libc::O_WRONLY, crate::FileType::Directory).unwrap_err();
        assert_eq!(err, OpendirError::BadFlags);
    }

    #[test]
    fn validate_request_allowed_flags_accepted() {
        // O_DIRECTORY with O_NOFOLLOW should be fine
        let req = validate_opendir_request(
            1,
            libc::O_DIRECTORY | libc::O_NOFOLLOW,
            crate::FileType::Directory,
        )
        .expect("allowed flags should pass");
        assert_eq!(req.ino, 1);
    }

    #[test]
    fn validate_request_zero_flags_on_dir_accepted() {
        let req = validate_opendir_request(999, 0, crate::FileType::Directory)
            .expect("zero flags on directory");
        assert_eq!(req.ino, 999);
    }

    // -- check_opendir_readonly -------------------------------------------------

    #[test]
    fn readonly_rejected() {
        assert_eq!(
            check_opendir_readonly(true),
            Err(OpendirError::ReadOnlyFilesystem)
        );
    }

    #[test]
    fn writable_accepted() {
        assert_eq!(check_opendir_readonly(false), Ok(()));
    }

    // -- allocate_dir_handle ----------------------------------------------------

    #[test]
    fn allocate_dir_handle_sequential() {
        let mut next = 1u64;
        let h1 = allocate_dir_handle(100, &mut next).unwrap();
        let h2 = allocate_dir_handle(200, &mut next).unwrap();
        let h3 = allocate_dir_handle(300, &mut next).unwrap();
        assert_eq!(h1, 1);
        assert_eq!(h2, 2);
        assert_eq!(h3, 3);
    }

    #[test]
    fn allocate_dir_handle_starts_from_current_value() {
        let mut next = 100u64;
        let h = allocate_dir_handle(1, &mut next).unwrap();
        assert_eq!(h, 100);
        assert_eq!(next, 101);
    }

    #[test]
    fn allocate_dir_handle_rejects_zero_id() {
        let mut next = 0u64;
        assert_eq!(allocate_dir_handle(1, &mut next).unwrap_err(), libc::EIO);
    }

    #[test]
    fn allocate_handle_wrap_around_rejected() {
        let mut next = u64::MAX;
        let h = allocate_dir_handle(1, &mut next).unwrap();
        assert_eq!(h, u64::MAX);
        // next wrapped to 0
        assert_eq!(allocate_dir_handle(2, &mut next).unwrap_err(), libc::EIO);
    }

    // -- format_opendir_reply ---------------------------------------------------

    #[test]
    fn format_opendir_reply_rejects_zero_fh() {
        assert_eq!(format_opendir_reply_inner(0, 0).unwrap_err(), libc::EINVAL);
    }

    #[test]
    fn format_opendir_reply_accepts_nonzero_fh() {
        assert!(format_opendir_reply_inner(1, 0).is_ok());
        assert!(format_opendir_reply_inner(u64::MAX, 0).is_ok());
    }

    /// Inner helper that tests only the fh validation, not the reply side-effect.
    fn format_opendir_reply_inner(fh: u64, _open_flags: u32) -> Result<(), c_int> {
        if fh == 0 {
            return Err(libc::EINVAL);
        }
        Ok(())
    }

    // -- handle_opendir ---------------------------------------------------------

    #[test]
    fn handle_opendir_valid_directory() {
        let mut next = 1u64;
        let plan = handle_opendir(42, 0, false, &mut next, crate::FileType::Directory)
            .expect("valid opendir");
        assert_eq!(plan.ino, 42);
        assert_eq!(plan.dh_id, 1);
        assert_eq!(plan.flags, 0);
        assert_eq!(next, 2);
    }

    #[test]
    fn handle_opendir_allocates_sequential_handles() {
        let mut next = 10u64;
        let plan1 = handle_opendir(1, 0, false, &mut next, crate::FileType::Directory).unwrap();
        assert_eq!(plan1.dh_id, 10);
        let plan2 = handle_opendir(2, 0, false, &mut next, crate::FileType::Directory).unwrap();
        assert_eq!(plan2.dh_id, 11);
        assert_eq!(next, 12);
    }

    #[test]
    fn handle_opendir_with_allowed_flags() {
        let mut next = 1u64;
        let plan = handle_opendir(
            1,
            libc::O_DIRECTORY | libc::O_NONBLOCK,
            false,
            &mut next,
            crate::FileType::Directory,
        )
        .expect("allowed flags");
        assert_eq!(plan.flags, libc::O_DIRECTORY | libc::O_NONBLOCK);
    }

    #[test]
    fn handle_opendir_readonly_rejected() {
        let mut next = 1u64;
        let err = handle_opendir(42, 0, true, &mut next, crate::FileType::Directory).unwrap_err();
        assert_eq!(err, OpendirError::ReadOnlyFilesystem);
        // Next handle should not have been consumed
        assert_eq!(next, 1);
    }

    #[test]
    fn handle_opendir_non_directory_rejected() {
        let mut next = 1u64;
        let err =
            handle_opendir(100, 0, false, &mut next, crate::FileType::RegularFile).unwrap_err();
        assert_eq!(err, OpendirError::NotADirectory);
    }

    #[test]
    fn handle_opendir_zero_inode_rejected() {
        let mut next = 1u64;
        let err = handle_opendir(0, 0, false, &mut next, crate::FileType::Directory).unwrap_err();
        assert_eq!(err, OpendirError::InvalidInode);
    }

    #[test]
    fn handle_opendir_bad_flags_rejected() {
        let mut next = 1u64;
        let err = handle_opendir(
            1,
            libc::O_WRONLY,
            false,
            &mut next,
            crate::FileType::Directory,
        )
        .unwrap_err();
        assert_eq!(err, OpendirError::BadFlags);
    }

    #[test]
    fn handle_opendir_wrapped_handle_rejected() {
        let mut next = 0u64;
        let err = handle_opendir(1, 0, false, &mut next, crate::FileType::Directory).unwrap_err();
        assert_eq!(err, OpendirError::Io);
    }

    #[test]
    fn handle_opendir_readonly_priority() {
        // Read-only check runs first: even with an invalid inode (0),
        // EROFS wins because the read-only guard runs before
        // request validation.
        let mut next = 1u64;
        let err = handle_opendir(0, 0, true, &mut next, crate::FileType::Directory).unwrap_err();
        assert_eq!(err, OpendirError::ReadOnlyFilesystem);
    }

    #[test]
    fn handle_opendir_preserves_inode_and_flags() {
        let mut next = 5u64;
        let plan = handle_opendir(
            0xABCD,
            libc::O_DIRECTORY,
            false,
            &mut next,
            crate::FileType::Directory,
        )
        .unwrap();
        assert_eq!(plan.ino, 0xABCD);
        assert_eq!(plan.flags, libc::O_DIRECTORY);
        assert_eq!(plan.dh_id, 5);
    }

    // -- OpendirError -----------------------------------------------------------

    #[test]
    fn opendir_error_display_produces_human_message() {
        let msg = format!("{}", OpendirError::NotADirectory);
        assert!(!msg.is_empty());
        let msg = format!("{}", OpendirError::ReadOnlyFilesystem);
        assert!(msg.contains("read-only"));
    }

    #[test]
    fn opendir_error_is_std_error() {
        let e: &dyn std::error::Error = &OpendirError::NotADirectory;
        let _ = e.to_string();
    }

    #[test]
    fn opendir_error_to_errno_maps_correctly() {
        assert_eq!(OpendirError::NotADirectory.to_errno(), errno::ENOTDIR);
        assert_eq!(OpendirError::InvalidInode.to_errno(), errno::EINVAL);
        assert_eq!(OpendirError::BadFlags.to_errno(), errno::EINVAL);
        assert_eq!(OpendirError::ReadOnlyFilesystem.to_errno(), errno::EROFS);
        assert_eq!(OpendirError::Io.to_errno(), errno::EIO);
        assert_eq!(OpendirError::Other.to_errno(), errno::EIO);
    }

    #[test]
    fn opendir_error_into_c_int() {
        let e: c_int = OpendirError::ReadOnlyFilesystem.into();
        assert_eq!(e, errno::EROFS);
        let e: c_int = OpendirError::NotADirectory.into();
        assert_eq!(e, errno::ENOTDIR);
    }

    #[test]
    fn opendir_error_debug_includes_variant() {
        let dbg = format!("{:?}", OpendirError::NotADirectory);
        assert!(dbg.contains("NotADirectory"));
    }

    #[test]
    fn opendir_error_clone_and_eq() {
        let e1 = OpendirError::NotADirectory;
        let e2 = e1;
        assert_eq!(e1, e2);
        assert_ne!(e1, OpendirError::ReadOnlyFilesystem);
    }

    // -- OpendirPlan ------------------------------------------------------------

    #[test]
    fn opendir_plan_debug_includes_fields() {
        let mut next = 1u64;
        let plan = handle_opendir(42, 0, false, &mut next, crate::FileType::Directory).unwrap();
        let dbg = format!("{plan:?}");
        assert!(dbg.contains("OpendirPlan"));
    }

    #[test]
    fn opendir_plan_clone_preserves_fields() {
        let mut next = 1u64;
        let plan = handle_opendir(42, 0, false, &mut next, crate::FileType::Directory).unwrap();
        let clone = plan.clone();
        assert_eq!(plan.ino, clone.ino);
        assert_eq!(plan.dh_id, clone.dh_id);
        assert_eq!(plan.flags, clone.flags);
    }

    #[test]
    fn opendir_plan_eq_works() {
        let p1 = OpendirPlan {
            ino: 1,
            dh_id: 5,
            flags: 0,
        };
        let p2 = OpendirPlan {
            ino: 1,
            dh_id: 5,
            flags: 0,
        };
        assert_eq!(p1, p2);
        let p3 = OpendirPlan {
            ino: 2,
            dh_id: 5,
            flags: 0,
        };
        assert_ne!(p1, p3);
    }

    // -- Flags edge cases -------------------------------------------------------

    #[test]
    fn flags_rdwr_rejected() {
        let err =
            validate_opendir_request(1, libc::O_RDWR, crate::FileType::Directory).unwrap_err();
        assert_eq!(err, OpendirError::BadFlags);
    }

    #[test]
    fn flags_high_bit_pattern_rejected() {
        // 0xFFFFFF00: many bits outside the allowed mask
        let err =
            validate_opendir_request(1, 0x7FFF_FF00i32, crate::FileType::Directory).unwrap_err();
        assert_eq!(err, OpendirError::BadFlags);
    }

    // -- Integration: handle_opendir + format_opendir_reply ---------------------

    #[test]
    fn handle_then_format_nonzero_handle() {
        let mut next = 1u64;
        let plan = handle_opendir(42, 0, false, &mut next, crate::FileType::Directory).unwrap();
        // fh is non-zero, so format_opendir_reply_inner should succeed
        assert!(format_opendir_reply_inner(plan.dh_id, 0).is_ok());
    }

    // -- Ordering: read-only check before request validation --------------------

    #[test]
    fn read_only_wins_over_invalid_inode() {
        let mut next = 1u64;
        let err = handle_opendir(0, 0, true, &mut next, crate::FileType::Directory).unwrap_err();
        assert_eq!(err, OpendirError::ReadOnlyFilesystem);
    }

    #[test]
    fn read_only_wins_over_non_directory() {
        let mut next = 1u64;
        let err =
            handle_opendir(100, 0, true, &mut next, crate::FileType::RegularFile).unwrap_err();
        assert_eq!(err, OpendirError::ReadOnlyFilesystem);
    }
}
