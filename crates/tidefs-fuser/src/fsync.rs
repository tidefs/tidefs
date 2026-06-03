//! FUSE `fsync` / `fdatasync` / `flush` handler helpers.
//!
//! Provides:
//! - [`SyncType`]: enum distinguishing between fsync, fdatasync, and flush
//!   semantics derived from the FUSE `datasync` flag and operation opcode.
//! - [`FsyncMode`]: narrower enum for just fsync/fdatasync (no flush).
//! - [`datasync_to_sync_type`]: convert the FUSE `datasync` boolean into a
//!   [`SyncType`].
//! - [`datasync_to_fsync_mode`]: convert the FUSE `datasync` boolean into a
//!   [`FsyncMode`].
//! - [`sync_handle`]: combined entry-point validation for fsync/fdatasync.
//! - [`check_sync_allowed`]: validate that a sync operation is applicable to
//!   the given file kind (reject pipes, sockets, symlinks, and character
//!   devices that lack persistent backing).
//! - [`is_datasync_flag`]: constant predicate for the fdatasync case.
//! - Re-exported POSIX errno codes relevant to the sync path.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::fsync;
//!
//! let mode = fsync::sync_handle(file_kind, read_only, datasync)?;
//! // ... perform backend flush with `mode` ...
//! ```

use crate::errno;
use libc::c_int;
use std::convert::TryFrom;

use crate::FileType;

// ---------------------------------------------------------------------------
// FsyncMode -- stripped-down enum for fsync/fdatasync only (no flush)
// ---------------------------------------------------------------------------

/// Distinguishes between full metadata+data sync (`fsync`) and data-only
/// sync (`fdatasync`).
///
/// This is a narrower variant of [`SyncType`] that excludes the `Flush`
/// case.  It is the canonical type for the `IntentLogRecord::Fsync` payload
/// and for any code path that only deals with durability barriers (not
/// close-time hints).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsyncMode {
    /// Full metadata + data flush (POSIX fsync / `datasync=false`).
    Fsync,
    /// Data-only flush (POSIX fdatasync / `datasync=true`).
    Fdatasync,
}

impl FsyncMode {
    /// Returns `true` when the operation is data-only.
    #[must_use]
    pub const fn is_datasync(self) -> bool {
        matches!(self, Self::Fdatasync)
    }

    /// Returns `true` when the operation is full metadata+data.
    #[must_use]
    pub const fn is_fsync(self) -> bool {
        matches!(self, Self::Fsync)
    }
}

impl From<FsyncMode> for SyncType {
    fn from(mode: FsyncMode) -> Self {
        match mode {
            FsyncMode::Fsync => Self::Fsync,
            FsyncMode::Fdatasync => Self::Fdatasync,
        }
    }
}

/// Convert the FUSE `datasync` boolean into a [`FsyncMode`].
#[must_use]
pub const fn datasync_to_fsync_mode(datasync: bool) -> FsyncMode {
    if datasync {
        FsyncMode::Fdatasync
    } else {
        FsyncMode::Fsync
    }
}

// ---------------------------------------------------------------------------
// u8 conversion -- bridge to IntentLogRecord::Fsync.mode
// ---------------------------------------------------------------------------

impl From<FsyncMode> for u8 {
    fn from(mode: FsyncMode) -> Self {
        match mode {
            FsyncMode::Fsync => 0,
            FsyncMode::Fdatasync => 1,
        }
    }
}

impl TryFrom<u8> for FsyncMode {
    type Error = c_int;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Fsync),
            1 => Ok(Self::Fdatasync),
            _ => Err(libc::EINVAL),
        }
    }
}

// ---------------------------------------------------------------------------
// Re-exports: standard errno codes for sync error paths
// ---------------------------------------------------------------------------

pub use libc::{EBADF, EINTR, EINVAL, EIO, ENOSPC, ENOTDIR, EROFS};

// ---------------------------------------------------------------------------
// SyncType -- semantic classification of a sync operation
// ---------------------------------------------------------------------------

/// Classifies a FUSE sync operation by its durability semantics.
///
/// - [`SyncType::Fsync`]: full metadata + data flush (fsync with
///   `datasync=false`).
/// - [`SyncType::Fdatasync`]: data-only flush (fdatasync, or fsync with
///   `datasync=true`).
/// - [`SyncType::Flush`]: close-time flush hint -- the filesystem may
///   flush or defer; this is not a durability guarantee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncType {
    /// Full metadata + data flush (POSIX fsync).
    Fsync,
    /// Data-only flush (POSIX fdatasync).
    Fdatasync,
    /// Close-time flush hint (FUSE flush, not a durability barrier).
    Flush,
}

impl SyncType {
    /// Returns `true` when the operation is data-only (fdatasync).
    #[must_use]
    pub const fn is_datasync(self) -> bool {
        matches!(self, Self::Fdatasync)
    }

    /// Returns `true` when the operation is fsync (full metadata+data).
    #[must_use]
    pub const fn is_fsync(self) -> bool {
        matches!(self, Self::Fsync)
    }

    /// Returns `true` when the operation is a flush hint.
    #[must_use]
    pub const fn is_flush(self) -> bool {
        matches!(self, Self::Flush)
    }
}

// ---------------------------------------------------------------------------
// Datasync flag conversion
// ---------------------------------------------------------------------------

/// Convert the FUSE `datasync` boolean parameter into a [`SyncType`].
///
/// When `datasync` is `true` (the FUSE `FSYNC` request has the fdatasync flag
/// set), the operation is [`SyncType::Fdatasync`] -- only data extents are
/// flushed; metadata updates such as mtime may be skipped.
///
/// When `datasync` is `false`, the operation is [`SyncType::Fsync`] -- both
/// data and metadata are flushed.
#[must_use]
pub const fn datasync_to_sync_type(datasync: bool) -> SyncType {
    if datasync {
        SyncType::Fdatasync
    } else {
        SyncType::Fsync
    }
}

/// Returns `true` when `datasync` requests data-only flush semantics.
///
/// This is a convenience predicate for callers that don't need the full
/// [`SyncType`] enum.
#[must_use]
pub const fn is_datasync_flag(datasync: bool) -> bool {
    datasync
}

// ---------------------------------------------------------------------------
// Inode-kind validation
// ---------------------------------------------------------------------------

/// Check whether a sync operation (fsync, fdatasync, or flush) is allowed
/// for the given [`FileType`].
///
/// # Returns
///
/// `Ok(())` for regular files, directories, and block devices that have
/// persistent backing storage.
///
/// `Err(EINVAL)` for named pipes, Unix domain sockets, symbolic links, and
/// character devices that do not support data or metadata durability.
///
/// # Rationale
///
/// Per POSIX, fsync(2) on a pipe or socket returns `EINVAL`.  Symlinks
/// are resolved by the kernel before the FUSE handler is invoked, so they
/// should not appear here in practice, but the guard is included for
/// defense in depth.
#[inline]
pub fn check_sync_allowed(kind: FileType) -> Result<(), c_int> {
    match kind {
        FileType::RegularFile | FileType::Directory | FileType::BlockDevice => Ok(()),
        FileType::NamedPipe | FileType::Socket | FileType::CharDevice | FileType::Symlink => {
            Err(errno::EINVAL)
        }
    }
}

// ---------------------------------------------------------------------------
// Read-only mount check
// ---------------------------------------------------------------------------

/// Check whether a sync operation is permitted on a read-only filesystem.
///
/// When `read_only` is `true`, mutating sync operations (fsync/fdatasync
/// on dirty files) are rejected with `EROFS`.  Flush on a read-only fd
/// (no dirty data) is permitted -- the caller should decide based on actual
/// dirtiness.
///
/// # Returns
///
/// `Ok(())` when the operation is allowed; `Err(EROFS)` otherwise.
#[inline]
pub fn check_sync_readonly(read_only: bool) -> Result<(), c_int> {
    if read_only {
        Err(errno::EROFS)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// sync_handle -- combined entry-point validation for fsync/fdatasync
// ---------------------------------------------------------------------------

/// Validate all preconditions for a `fsync`/`fdatasync` FUSE request before
/// delegating to the backend flush path.
///
/// Checks (in order):
/// 1. The inode kind is sync-allowed (regular file, dir, or block device).
/// 2. The filesystem is not mounted read-only when dirty data may exist.
///
/// Returns the resolved [`FsyncMode`] on success so the caller can pass it
/// to the backend.
///
/// # Errors
///
/// Returns the appropriate POSIX errno (`EINVAL`, `EROFS`) on failure.
#[inline]
pub fn sync_handle(kind: FileType, read_only: bool, datasync: bool) -> Result<FsyncMode, c_int> {
    check_sync_allowed(kind)?;
    check_sync_readonly(read_only)?;
    Ok(datasync_to_fsync_mode(datasync))
}

// ---------------------------------------------------------------------------
// handle_fsync -- combined entry-point for FUSE fsync/fdatasync dispatch
// ---------------------------------------------------------------------------

/// Perform full fsync/fdatasync validation and return the resolved [`FsyncMode`].
///
/// This is the canonical FUSE dispatch entry point for `fsync` (opcode 20).
/// It validates:
/// 1. The inode kind supports sync (regular file, directory, block device).
/// 2. The filesystem is not mounted read-only (when dirty data may exist).
///
/// Returns the [`FsyncMode`] on success.  The caller should then perform
/// the backend flush (dirty-page writeback, intent-log commit, txg barrier)
/// guided by the returned mode.
///
/// # Errors
///
/// Returns `EINVAL` for unsupported inode kinds (pipes, sockets, symlinks,
/// character devices) and `EROFS` for read-only mounts.
#[inline]
pub fn handle_fsync(kind: FileType, read_only: bool, datasync: bool) -> Result<FsyncMode, c_int> {
    sync_handle(kind, read_only, datasync)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- SyncType ---------------------------------------------------------

    #[test]
    fn sync_type_is_datasync() {
        assert!(SyncType::Fdatasync.is_datasync());
        assert!(!SyncType::Fsync.is_datasync());
        assert!(!SyncType::Flush.is_datasync());
    }

    #[test]
    fn sync_type_is_fsync() {
        assert!(SyncType::Fsync.is_fsync());
        assert!(!SyncType::Fdatasync.is_fsync());
        assert!(!SyncType::Flush.is_fsync());
    }

    #[test]
    fn sync_type_is_flush() {
        assert!(SyncType::Flush.is_flush());
        assert!(!SyncType::Fsync.is_flush());
        assert!(!SyncType::Fdatasync.is_flush());
    }

    // -- datasync_to_sync_type --------------------------------------------

    #[test]
    fn datasync_true_maps_to_fdatasync() {
        assert_eq!(datasync_to_sync_type(true), SyncType::Fdatasync);
    }

    #[test]
    fn datasync_false_maps_to_fsync() {
        assert_eq!(datasync_to_sync_type(false), SyncType::Fsync);
    }

    // -- is_datasync_flag -------------------------------------------------

    #[test]
    fn datasync_flag() {
        assert!(is_datasync_flag(true));
        assert!(!is_datasync_flag(false));
    }

    // -- check_sync_allowed -----------------------------------------------

    #[test]
    fn sync_allowed_on_regular_file() {
        assert_eq!(check_sync_allowed(FileType::RegularFile), Ok(()));
    }

    #[test]
    fn sync_allowed_on_directory() {
        assert_eq!(check_sync_allowed(FileType::Directory), Ok(()));
    }

    #[test]
    fn sync_allowed_on_block_device() {
        assert_eq!(check_sync_allowed(FileType::BlockDevice), Ok(()));
    }

    #[test]
    fn sync_denied_on_named_pipe() {
        assert_eq!(check_sync_allowed(FileType::NamedPipe), Err(errno::EINVAL));
    }

    #[test]
    fn sync_denied_on_socket() {
        assert_eq!(check_sync_allowed(FileType::Socket), Err(errno::EINVAL));
    }

    #[test]
    fn sync_denied_on_char_device() {
        assert_eq!(check_sync_allowed(FileType::CharDevice), Err(errno::EINVAL));
    }

    #[test]
    fn sync_denied_on_symlink() {
        assert_eq!(check_sync_allowed(FileType::Symlink), Err(errno::EINVAL));
    }

    // -- check_sync_readonly ----------------------------------------------

    #[test]
    fn ro_mount_rejects_sync() {
        assert_eq!(check_sync_readonly(true), Err(errno::EROFS));
    }

    #[test]
    fn rw_mount_allows_sync() {
        assert_eq!(check_sync_readonly(false), Ok(()));
    }
    // -- FsyncMode ---------------------------------------------------------

    #[test]
    fn fsync_mode_is_datasync() {
        assert!(FsyncMode::Fdatasync.is_datasync());
        assert!(!FsyncMode::Fsync.is_datasync());
    }

    #[test]
    fn fsync_mode_is_fsync() {
        assert!(FsyncMode::Fsync.is_fsync());
        assert!(!FsyncMode::Fdatasync.is_fsync());
    }

    #[test]
    fn fsync_mode_converts_to_sync_type() {
        assert_eq!(SyncType::from(FsyncMode::Fsync), SyncType::Fsync);
        assert_eq!(SyncType::from(FsyncMode::Fdatasync), SyncType::Fdatasync);
    }

    // -- datasync_to_fsync_mode --------------------------------------------

    #[test]
    fn datasync_true_maps_to_fdatasync_mode() {
        assert_eq!(datasync_to_fsync_mode(true), FsyncMode::Fdatasync);
    }

    // -- u8 conversion round-trip ---------------------------------------

    #[test]
    fn fsync_mode_to_u8_round_trip() {
        assert_eq!(u8::from(FsyncMode::Fsync), 0);
        assert_eq!(u8::from(FsyncMode::Fdatasync), 1);
    }

    #[test]
    fn u8_to_fsync_mode_round_trip() {
        assert_eq!(FsyncMode::try_from(0u8), Ok(FsyncMode::Fsync));
        assert_eq!(FsyncMode::try_from(1u8), Ok(FsyncMode::Fdatasync));
    }

    #[test]
    fn u8_invalid_mode_returns_einval() {
        assert_eq!(FsyncMode::try_from(2u8), Err(libc::EINVAL));
        assert_eq!(FsyncMode::try_from(255u8), Err(libc::EINVAL));
    }

    #[test]
    fn fsync_mode_u8_round_trip_all_variants() {
        for mode in [FsyncMode::Fsync, FsyncMode::Fdatasync] {
            let val: u8 = mode.into();
            let round_tripped = FsyncMode::try_from(val).expect("valid u8");
            assert_eq!(round_tripped, mode);
        }
    }

    #[test]
    fn datasync_false_maps_to_fsync_mode() {
        assert_eq!(datasync_to_fsync_mode(false), FsyncMode::Fsync);
    }

    // -- sync_handle -------------------------------------------------------

    #[test]
    fn sync_handle_regular_file_rw_fsync() {
        let result = sync_handle(FileType::RegularFile, false, false);
        assert_eq!(result, Ok(FsyncMode::Fsync));
    }

    #[test]
    fn sync_handle_regular_file_rw_fdatasync() {
        let result = sync_handle(FileType::RegularFile, false, true);
        assert_eq!(result, Ok(FsyncMode::Fdatasync));
    }

    #[test]
    fn sync_handle_directory_rw_fsync() {
        let result = sync_handle(FileType::Directory, false, false);
        assert_eq!(result, Ok(FsyncMode::Fsync));
    }

    #[test]
    fn sync_handle_block_device_rw_fdatasync() {
        let result = sync_handle(FileType::BlockDevice, false, true);
        assert_eq!(result, Ok(FsyncMode::Fdatasync));
    }

    #[test]
    fn sync_handle_pipe_returns_einval() {
        let result = sync_handle(FileType::NamedPipe, false, false);
        assert_eq!(result, Err(errno::EINVAL));
    }

    #[test]
    fn sync_handle_socket_returns_einval() {
        let result = sync_handle(FileType::Socket, false, true);
        assert_eq!(result, Err(errno::EINVAL));
    }

    #[test]
    fn sync_handle_ro_mount_returns_erofs() {
        let result = sync_handle(FileType::RegularFile, true, false);
        assert_eq!(result, Err(errno::EROFS));
    }

    #[test]
    fn sync_handle_ro_mount_fdatasync_returns_erofs() {
        let result = sync_handle(FileType::Directory, true, true);
        assert_eq!(result, Err(errno::EROFS));
    }

    #[test]
    fn sync_handle_invalid_kind_beats_ro_check() {
        // When both fail, kind check should come first (EINVAL before EROFS).
        let result = sync_handle(FileType::NamedPipe, true, false);
        assert_eq!(result, Err(errno::EINVAL));
    }

    #[test]
    fn sync_handle_consecutive_calls_idempotent() {
        // Multiple calls with the same args produce the same result.
        for _ in 0..5 {
            assert_eq!(
                sync_handle(FileType::RegularFile, false, false),
                Ok(FsyncMode::Fsync)
            );
        }
    }

    // -- FsyncMode Debug/Display round-trip --------------------------------

    #[test]
    fn fsync_mode_debug_output() {
        assert_eq!(format!("{:?}", FsyncMode::Fsync), "Fsync");
        assert_eq!(format!("{:?}", FsyncMode::Fdatasync), "Fdatasync");
    }

    // -- FsyncMode Eq / PartialEq ------------------------------------------

    #[test]
    fn fsync_mode_equality() {
        assert_eq!(FsyncMode::Fsync, FsyncMode::Fsync);
        assert_ne!(FsyncMode::Fsync, FsyncMode::Fdatasync);
    }

    // -- Errnos are re-exported -------------------------------------------

    #[test]
    fn errno_re_exports_are_available() {
        // Verify all documented errno constants are accessible.
        let _ = EBADF;
        let _ = EINTR;
        let _ = EINVAL;
        let _ = EIO;
        let _ = ENOSPC;
        let _ = ENOTDIR;
        let _ = EROFS;
    }
}
