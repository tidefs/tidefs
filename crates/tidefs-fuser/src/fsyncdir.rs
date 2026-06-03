//! FUSE `fsyncdir` handler helpers.
//!
//! Provides:
//! - [`check_fsyncdir_allowed`]: validate that an fsyncdir operation is
//!   applicable to the given file kind (directories only; reject regular
//!   files, pipes, sockets, symlinks, and devices).
//! - [`check_fsyncdir_readonly`]: reject fsyncdir on read-only mounts
//!   where directory metadata mutations were never permitted.
//! - [`plan_fsyncdir`]: combined inode-kind + read-only validation
//!   returning an `Ok(())` on success or the appropriate FUSE errno.
//! - Re-exported POSIX errno codes relevant to the fsyncdir path.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::fsyncdir;
//!
//! fsyncdir::plan_fsyncdir(file_kind, read_only)?;
//! // ... perform directory metadata flush and commit barrier ...
//! ```
//!
//! # Distinction from fsync
//!
//! [`crate::fsync::check_sync_allowed`] permits regular files, directories,
//! and block devices.  [`check_fsyncdir_allowed`] is narrower: it only
//! permits directories, because `fsyncdir` flushes directory metadata
//! (entries, timestamps, link counts), not file data extents.

use libc::c_int;

use crate::FileType;

// ---------------------------------------------------------------------------
// Re-exports: standard errno codes for fsyncdir error paths
// ---------------------------------------------------------------------------

pub use libc::{EBADF, EINTR, EINVAL, EIO, ENOSPC, ENOTDIR, EROFS};

// ---------------------------------------------------------------------------
// File-kind validation (directory-only)
// ---------------------------------------------------------------------------

/// Check whether an `fsyncdir` operation is allowed for the given
/// [`FileType`].
///
/// `fsyncdir` flushes directory metadata through the dir-index and
/// inserts an intent-log commit barrier.  It applies exclusively to
/// directories.  Regular files, block devices, pipes, sockets, symlinks,
/// and character devices are rejected.
///
/// # Returns
///
/// `Ok(())` when `kind` is [`FileType::Directory`].
///
/// `Err(EINVAL)` for all other file kinds.
///
/// # Rationale
///
/// Per POSIX, `fsync(2)` on a directory descriptor guarantees that
/// directory entries reach stable storage.  The FUSE `fsyncdir` opcode
/// provides the same semantic for in-kernel FUSE filesystems.  Applying
/// it to a non-directory inode is a caller bug -- the kernel should
/// never send `fsyncdir` for a non-directory file handle, but the guard
/// is included for defense in depth.
#[inline]
pub fn check_fsyncdir_allowed(kind: FileType) -> Result<(), c_int> {
    match kind {
        FileType::Directory => Ok(()),
        _ => Err(libc::EINVAL),
    }
}

// ---------------------------------------------------------------------------
// Read-only mount check
// ---------------------------------------------------------------------------

/// Check whether an `fsyncdir` operation is permitted on a read-only
/// filesystem.
///
/// When `read_only` is `true`, the mount was established with `-o ro`,
/// preventing any directory-mutation handlers (create, unlink, mkdir,
/// rmdir, rename, link) from executing.  Since there can be no pending
/// directory metadata to flush, `fsyncdir` is rejected with `EROFS`.
///
/// When `read_only` is `false`, the operation is allowed.
///
/// # Returns
///
/// `Ok(())` when the mount is read-write; `Err(EROFS)` when read-only.
#[inline]
pub fn check_fsyncdir_readonly(read_only: bool) -> Result<(), c_int> {
    if read_only {
        Err(libc::EROFS)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Combined validation
// ---------------------------------------------------------------------------

/// Perform all pre-flight validations for an `fsyncdir` operation.
///
/// This convenience function calls [`check_fsyncdir_allowed`] and
/// [`check_fsyncdir_readonly`] in sequence, short-circuiting on the
/// first error.
///
/// # Returns
///
/// `Ok(())` when the inode is a directory and the mount is read-write.
///
/// `Err(EINVAL)` when the inode is not a directory.
/// `Err(EROFS)` when the mount is read-only.
#[inline]
pub fn plan_fsyncdir(kind: FileType, read_only: bool) -> Result<(), c_int> {
    check_fsyncdir_allowed(kind)?;
    check_fsyncdir_readonly(read_only)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// handle_fsyncdir -- combined entry-point for FUSE fsyncdir dispatch
// ---------------------------------------------------------------------------

/// Perform full `fsyncdir` validation.
///
/// This is the canonical FUSE dispatch entry point for `fsyncdir` (opcode 30).
/// It validates:
/// 1. The inode kind is a directory.
/// 2. The filesystem is not mounted read-only.
///
/// Returns `Ok(())` on success.  The caller should then perform the
/// directory metadata flush and commit barrier.
///
/// # Errors
///
/// Returns `EINVAL` when the inode is not a directory.
/// Returns `EROFS` when the filesystem is mounted read-only.
#[inline]
pub fn handle_fsyncdir(kind: FileType, read_only: bool) -> Result<(), c_int> {
    plan_fsyncdir(kind, read_only)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- check_fsyncdir_allowed -------------------------------------------

    #[test]
    fn allowed_on_directory() {
        assert_eq!(check_fsyncdir_allowed(FileType::Directory), Ok(()));
    }

    #[test]
    fn denied_on_regular_file() {
        assert_eq!(
            check_fsyncdir_allowed(FileType::RegularFile),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn denied_on_block_device() {
        assert_eq!(
            check_fsyncdir_allowed(FileType::BlockDevice),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn denied_on_char_device() {
        assert_eq!(
            check_fsyncdir_allowed(FileType::CharDevice),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn denied_on_named_pipe() {
        assert_eq!(
            check_fsyncdir_allowed(FileType::NamedPipe),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn denied_on_socket() {
        assert_eq!(check_fsyncdir_allowed(FileType::Socket), Err(libc::EINVAL));
    }

    #[test]
    fn denied_on_symlink() {
        assert_eq!(check_fsyncdir_allowed(FileType::Symlink), Err(libc::EINVAL));
    }

    // -- check_fsyncdir_readonly ------------------------------------------

    #[test]
    fn ro_mount_rejects_fsyncdir() {
        assert_eq!(check_fsyncdir_readonly(true), Err(libc::EROFS));
    }

    #[test]
    fn rw_mount_allows_fsyncdir() {
        assert_eq!(check_fsyncdir_readonly(false), Ok(()));
    }

    // -- plan_fsyncdir ----------------------------------------------------

    #[test]
    fn plan_succeeds_for_directory_rw() {
        assert_eq!(plan_fsyncdir(FileType::Directory, false), Ok(()));
    }

    #[test]
    fn plan_fails_for_directory_ro() {
        assert_eq!(plan_fsyncdir(FileType::Directory, true), Err(libc::EROFS));
    }

    #[test]
    fn plan_fails_for_regular_file_rw() {
        assert_eq!(
            plan_fsyncdir(FileType::RegularFile, false),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn plan_fails_for_regular_file_ro() {
        // EINVAL takes priority over EROFS: the inode is not a directory
        assert_eq!(
            plan_fsyncdir(FileType::RegularFile, true),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn plan_fails_for_symlink_rw() {
        assert_eq!(plan_fsyncdir(FileType::Symlink, false), Err(libc::EINVAL));
    }

    // -- idempotency: repeated validation returns same result -------------

    #[test]
    fn idempotent_check_allowed() {
        for _ in 0..5 {
            assert_eq!(check_fsyncdir_allowed(FileType::Directory), Ok(()));
            assert_eq!(
                check_fsyncdir_allowed(FileType::RegularFile),
                Err(libc::EINVAL)
            );
        }
    }

    #[test]
    fn idempotent_check_readonly() {
        for _ in 0..5 {
            assert_eq!(check_fsyncdir_readonly(true), Err(libc::EROFS));
            assert_eq!(check_fsyncdir_readonly(false), Ok(()));
        }
    }
}
