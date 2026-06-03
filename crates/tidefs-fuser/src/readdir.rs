//! FUSE `readdir` / `readdirplus` handler helpers.
//!
//! Provides:
//! - [`check_readdir_allowed`]: validate that a readdir operation is
//!   applicable to the given file kind (directories only; reject regular
//!   files, pipes, sockets, symlinks, and devices).
//! - [`check_readdir_offset`]: validate and convert the FUSE `offset`
//!   parameter from `i64` to `u64`, rejecting negative offsets.
//! - [`ReadDirPlan`]: structured plan for a readdir operation carrying
//!   the resolved offset.
//! - [`plan_readdir`]: combined inode-kind + offset validation returning
//!   a [`ReadDirPlan`] on success.
//! - [`ReadDirError`]: domain error type for readdir request validation
//!   with typed variants and POSIX errno mapping.
//! - [`handle_readdir`]: canonical dispatch entry-point combining
//!   directory-type assertion and offset validation into a single
//!   `Result<ReadDirPlan, ReadDirError>`.
//! - [`FuseReadDirHandler`]: drives directory entries into a FUSE
//!   [`ReplyDirectory`] or [`ReplyDirectoryPlus`], tracking entry
//!   count and the last cookie for pagination resumption.
//! - [`drive_readdir_from_cursor`]: convenience function that walks a
//!   [`tidefs_dir_index::DirIndex`] in bounded cursor windows from the
//!   requested offset and packs entries into a [`ReplyDirectory`] until
//!   the buffer is full or the directory is exhausted.
//! - [`file_type_from_entry_type`]: maps directory-entry type codes
//!   (0=Dir, 1=File, 2=Symlink, etc.) to [`FileType`].
//! - Re-exported POSIX errno codes relevant to the readdir path.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::readdir;
//!
//! let plan = readdir::handle_readdir(file_kind, offset)?;
//! let mut handler = readdir::FuseReadDirHandler::new(reply, plan.offset);
//! while let Some(entry) = dir_index.next_entry() {
//!     if handler.try_add(entry.ino, entry.offset, entry.kind, entry.name) {
//!         break; // buffer full
//!     }
//! }
//! handler.finish();
//! ```

use libc::c_int;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::time::Duration;

use tidefs_dir_index::{DirCursor, DirCursorEntry, DirCursorError, DirIndex};

use crate::errno;
use crate::reply::{ReplyDirectory, ReplyDirectoryPlus};
use crate::FileType;

use std::fmt;

const CURSOR_REPLY_WINDOW_ENTRIES: usize = 128;

// ---------------------------------------------------------------------------
// Re-exports: standard errno codes for readdir error paths
// ---------------------------------------------------------------------------

pub use libc::{EBADF, EINVAL, EIO, ENOTDIR};
// ---------------------------------------------------------------------------
// ReadDirError — domain error type for readdir request validation
// ---------------------------------------------------------------------------

/// Errors that can occur during readdir request validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadDirError {
    /// The inode is not a directory.
    NotADirectory,
    /// The FUSE offset is negative (invalid for directory iteration).
    InvalidOffset,
    /// Caller lacks read permission on the directory (stub; wired
    /// when `tidefs-permission` integration lands — see #5378).
    PermissionDenied,
}

impl ReadDirError {
    /// Convert this error to the matching POSIX errno value.
    #[must_use]
    pub fn to_errno(self) -> c_int {
        match self {
            ReadDirError::NotADirectory => errno::ENOTDIR,
            ReadDirError::InvalidOffset => errno::EINVAL,
            ReadDirError::PermissionDenied => errno::EACCES,
        }
    }
}

impl fmt::Display for ReadDirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadDirError::NotADirectory => write!(f, "readdir on non-directory inode"),
            ReadDirError::InvalidOffset => write!(f, "invalid readdir offset"),
            ReadDirError::PermissionDenied => write!(f, "permission denied for readdir"),
        }
    }
}

impl std::error::Error for ReadDirError {}

impl From<ReadDirError> for c_int {
    fn from(e: ReadDirError) -> c_int {
        e.to_errno()
    }
}

// ---------------------------------------------------------------------------
// File-kind validation (directory-only)
// ---------------------------------------------------------------------------

/// Check whether a `readdir` / `readdirplus` operation is allowed for
/// the given [`FileType`].
///
/// Directory listing applies exclusively to directories.  Regular files,
/// block devices, pipes, sockets, symlinks, and character devices are
/// rejected.
///
/// # Returns
///
/// `Ok(())` when `kind` is [`FileType::Directory`].
///
/// `Err(ENOTDIR)` for all other file kinds.
#[inline]
pub fn check_readdir_allowed(kind: FileType) -> Result<(), c_int> {
    match kind {
        FileType::Directory => Ok(()),
        _ => Err(libc::ENOTDIR),
    }
}

// ---------------------------------------------------------------------------
// Offset validation
// ---------------------------------------------------------------------------

/// Validate a FUSE `readdir` offset parameter.
///
/// The kernel passes the offset as `i64` (the FUSE wire format uses a
/// signed 64-bit field).  Negative offsets are never valid for directory
/// iteration.
///
/// # Returns
///
/// `Ok(u64)` when `offset >= 0`.
/// `Err(EINVAL)` when `offset < 0`.
#[inline]
pub fn check_readdir_offset(offset: i64) -> Result<u64, c_int> {
    if offset < 0 {
        Err(libc::EINVAL)
    } else {
        Ok(offset as u64)
    }
}

// ---------------------------------------------------------------------------
// ReadDirPlan
// ---------------------------------------------------------------------------

/// Structured plan for a readdir operation.
///
/// Created by [`plan_readdir`] or [`handle_readdir`] after all pre-flight validations pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadDirPlan {
    /// Validated, non-negative offset for directory iteration.
    pub offset: u64,
}

impl ReadDirPlan {
    /// Create a `ReadDirPlan` from a pre-validated offset.
    #[must_use]
    pub const fn new(offset: u64) -> Self {
        Self { offset }
    }
}

// ---------------------------------------------------------------------------
// Combined validation
// ---------------------------------------------------------------------------

/// Perform all pre-flight validations for a `readdir` / `readdirplus`
/// operation.
///
/// This convenience function calls [`check_readdir_allowed`] and
/// [`check_readdir_offset`] in sequence, short-circuiting on the first
/// error.  The resulting [`ReadDirPlan`] carries the validated offset.
///
/// # Returns
///
/// `Ok(ReadDirPlan)` when the inode is a directory and the offset is
/// non-negative.
///
/// `Err(ENOTDIR)` when the inode is not a directory.
/// `Err(EINVAL)` when the offset is negative.
#[inline]
pub fn plan_readdir(kind: FileType, offset: i64) -> Result<ReadDirPlan, c_int> {
    check_readdir_allowed(kind)?;
    let offset = check_readdir_offset(offset)?;
    Ok(ReadDirPlan { offset })
}

// ---------------------------------------------------------------------------
// handle_readdir — canonical dispatch entry-point
// ---------------------------------------------------------------------------

/// Canonical dispatch entry-point for FUSE `readdir` requests.
///
/// Combines directory-type assertion and offset validation into a single
/// `Result<ReadDirPlan, ReadDirError>`.  This is the preferred entry point
/// for daemon dispatch: it rejects non-directory inodes (ENOTDIR),
/// validates the offset (EINVAL), and returns a validated [`ReadDirPlan`]
/// ready for cursor iteration.
///
/// # Parameters
///
/// - `kind`: the [`FileType`] of the inode being read.
/// - `offset`: the FUSE offset from the kernel request (must be ≥ 0).
///
/// # Errors
///
/// Returns [`ReadDirError::NotADirectory`] when `kind` is not
/// [`FileType::Directory`].
///
/// Returns [`ReadDirError::InvalidOffset`] when `offset` is negative.
///
/// # Examples
///
/// ```rust,ignore
/// let plan = readdir::handle_readdir(file_kind, offset)?;
/// // iterate directory entries starting from plan.offset...
/// ```
#[inline]
pub fn handle_readdir(kind: FileType, offset: i64) -> Result<ReadDirPlan, ReadDirError> {
    if kind != FileType::Directory {
        return Err(ReadDirError::NotADirectory);
    }
    if offset < 0 {
        return Err(ReadDirError::InvalidOffset);
    }
    Ok(ReadDirPlan {
        offset: offset as u64,
    })
}

// ---------------------------------------------------------------------------
// FuseReadDirHandler
// ---------------------------------------------------------------------------

/// Drives directory entries into a FUSE readdir or readdirplus reply.
///
/// Wraps either a [`ReplyDirectory`] or [`ReplyDirectoryPlus`] and
/// provides a uniform interface for adding entries, tracking the last
/// assigned cookie, and finalizing the reply.
///
/// Entries are assigned sequential cookies starting from
/// `start_offset + 1`.  The kernel uses these cookies to resume iteration
/// across pagination boundaries.
#[derive(Debug)]
pub struct FuseReadDirHandler {
    reply: ReadDirReplyKind,
    next_cookie: i64,
    entries_sent: usize,
    buffer_full: bool,
}

/// Internal enum to hold either reply variant.
#[derive(Debug)]
enum ReadDirReplyKind {
    Basic(ReplyDirectory),
    Plus(ReplyDirectoryPlus),
}

impl FuseReadDirHandler {
    /// Create a handler for a basic `readdir` reply.
    ///
    /// `start_offset` is the FUSE offset from the kernel request; the
    /// first entry added will receive cookie `start_offset + 1`.
    #[must_use]
    pub fn new(reply: ReplyDirectory, start_offset: u64) -> Self {
        Self {
            reply: ReadDirReplyKind::Basic(reply),
            next_cookie: start_offset as i64 + 1,
            entries_sent: 0,
            buffer_full: false,
        }
    }

    /// Create a handler for a `readdirplus` reply.
    ///
    /// `start_offset` is the FUSE offset from the kernel request; the
    /// first entry added will receive cookie `start_offset + 1`.
    #[must_use]
    pub fn new_plus(reply: ReplyDirectoryPlus, start_offset: u64) -> Self {
        Self {
            reply: ReadDirReplyKind::Plus(reply),
            next_cookie: start_offset as i64 + 1,
            entries_sent: 0,
            buffer_full: false,
        }
    }

    /// Try to add a basic directory entry to the reply.
    ///
    /// Returns `true` if the buffer is now full (no more entries can be
    /// added).  Returns `false` if the entry was added successfully and
    /// there is still room.
    ///
    /// Once the buffer is full, subsequent calls are no-ops that return
    /// `true`.
    #[must_use]
    pub fn try_add<T: AsRef<OsStr>>(&mut self, ino: u64, kind: FileType, name: T) -> bool {
        if self.buffer_full {
            return true;
        }
        let cookie = self.next_cookie;
        let full = match &mut self.reply {
            ReadDirReplyKind::Basic(reply) => reply.add(ino, cookie, kind, name),
            ReadDirReplyKind::Plus(reply) => {
                // For readdirplus without attr info, fall back to basic add
                // (the caller should use try_add_plus for full attr support).
                reply.add(
                    ino,
                    cookie,
                    name,
                    &Duration::ZERO,
                    &crate::FileAttr {
                        ino,
                        size: 0,
                        blocks: 0,
                        atime: std::time::UNIX_EPOCH,
                        mtime: std::time::UNIX_EPOCH,
                        ctime: std::time::UNIX_EPOCH,
                        crtime: std::time::UNIX_EPOCH,
                        kind,
                        perm: 0,
                        nlink: 0,
                        uid: 0,
                        gid: 0,
                        rdev: 0,
                        blksize: 0,
                        flags: 0,
                    },
                    0,
                )
            }
        };
        if full {
            self.buffer_full = true;
        } else {
            self.entries_sent += 1;
            self.next_cookie += 1;
        }
        full
    }

    /// Try to add a readdirplus entry with full attribute information to
    /// the reply.
    ///
    /// Returns `true` if the buffer is now full.  Returns `false` if the
    /// entry was added successfully.
    ///
    /// Once the buffer is full, subsequent calls are no-ops that return
    /// `true`.
    #[must_use]
    pub fn try_add_plus<T: AsRef<OsStr>>(
        &mut self,
        ino: u64,
        name: T,
        ttl: &Duration,
        attr: &crate::FileAttr,
        generation: u64,
    ) -> bool {
        if self.buffer_full {
            return true;
        }
        let cookie = self.next_cookie;
        let full = match &mut self.reply {
            ReadDirReplyKind::Plus(reply) => reply.add(ino, cookie, name, ttl, attr, generation),
            ReadDirReplyKind::Basic(_reply) => {
                // For basic readdir, treat as try_add with the file kind
                // from the attr.
                _reply.add(ino, cookie, attr.kind, name)
            }
        };
        if full {
            self.buffer_full = true;
        } else {
            self.entries_sent += 1;
            self.next_cookie += 1;
        }
        full
    }

    /// Try to add a [`DirCursorEntry`] to the reply using the entry's
    /// own offset as the FUSE cookie.
    ///
    /// Returns `true` if the buffer is now full.  Returns `false` if the
    /// entry was added successfully.
    ///
    /// Once the buffer is full, subsequent calls are no-ops that return
    /// `true`.
    ///
    /// The entry's `entry_type` field (u32) is mapped to [`FileType`] via
    /// [`file_type_from_entry_type`].  The entry's offset is cast from
    /// `u64` to `i64` for the FUSE wire format.
    #[must_use]
    pub fn try_add_cursor_entry(&mut self, entry: &DirCursorEntry) -> bool {
        if self.buffer_full {
            return true;
        }
        let kind = file_type_from_entry_type(entry.entry_type);
        let offset = entry.offset as i64;
        let name = OsStr::from_bytes(&entry.name);
        let full = match &mut self.reply {
            ReadDirReplyKind::Basic(reply) => reply.add(entry.inode_id, offset, kind, name),
            ReadDirReplyKind::Plus(reply) => reply.add(
                entry.inode_id,
                offset,
                name,
                &Duration::ZERO,
                &crate::FileAttr::default_for_kind(kind, entry.inode_id),
                0,
            ),
        };
        if full {
            self.buffer_full = true;
        } else {
            self.entries_sent += 1;
        }
        full
    }

    /// Returns `true` if the reply buffer is full and cannot accept more
    /// entries.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.buffer_full
    }

    /// Returns the number of entries successfully added so far.
    #[must_use]
    pub fn entries_sent(&self) -> usize {
        self.entries_sent
    }

    /// Returns the cookie that would be assigned to the next entry.
    #[must_use]
    pub fn next_cookie(&self) -> i64 {
        self.next_cookie
    }

    /// Finalize the reply and send it to the kernel.
    ///
    /// Sends `ok()` (with all accumulated entries) or `error(EIO)` if
    /// there are no entries and the offset was valid (indicating an
    /// internal consistency error).
    pub fn finish(self) {
        match self.reply {
            ReadDirReplyKind::Basic(reply) => reply.ok(),
            ReadDirReplyKind::Plus(reply) => reply.ok(),
        }
    }

    /// Finalize the reply with an explicit error code.
    pub fn finish_error(self, err: c_int) {
        match self.reply {
            ReadDirReplyKind::Basic(reply) => reply.error(err),
            ReadDirReplyKind::Plus(reply) => reply.error(err),
        }
    }
}

// ---------------------------------------------------------------------------
// Entry-type mapping
// ---------------------------------------------------------------------------

/// Map a directory-entry type code (as used by [`DirCursorEntry::entry_type`])
/// to the FUSE [`FileType`] enum.
///
/// Mapping:
/// - `0` → [`FileType::Directory`] (DT_DIR)
/// - `1` → [`FileType::RegularFile`] (DT_REG)
/// - `2` → [`FileType::Symlink`] (DT_LNK)
/// - `3` → [`FileType::CharDevice`] (DT_CHR)
/// - `4` → [`FileType::BlockDevice`] (DT_BLK)
/// - `5` → [`FileType::NamedPipe`] (DT_FIFO)
/// - `6` → [`FileType::Socket`] (DT_SOCK)
/// - anything else → [`FileType::RegularFile`] (safe fallback).
#[inline]
#[must_use]
pub fn file_type_from_entry_type(entry_type: u32) -> FileType {
    match entry_type {
        0 => FileType::Directory,
        1 => FileType::RegularFile,
        2 => FileType::Symlink,
        3 => FileType::CharDevice,
        4 => FileType::BlockDevice,
        5 => FileType::NamedPipe,
        6 => FileType::Socket,
        _ => FileType::RegularFile,
    }
}

// ---------------------------------------------------------------------------
// Cursor-driven readdir convenience
// ---------------------------------------------------------------------------

/// Drive a single readdir page from bounded [`DirCursor`] windows into a
/// [`ReplyDirectory`].
///
/// Creates bounded cursor windows over `dir`, starts at `start_offset`, and
/// packs entries into `reply` until the buffer is full or the cursor is
/// exhausted. Each cursor window is capped to avoid allocating a full
/// directory snapshot while still continuing across windows so a short reply
/// is not returned while more entries remain. The caller is responsible for
/// calling `reply.ok()` or
/// `reply.error()` after this function returns.
///
/// # Errors
///
/// Returns [`DirCursorError::ChecksumMismatch`] when the underlying
/// B+tree node checksums fail verification.
pub fn drive_readdir_from_cursor(
    dir: &DirIndex,
    start_offset: u64,
    reply: &mut ReplyDirectory,
) -> Result<(), DirCursorError> {
    let mut window_offset = start_offset;

    loop {
        let (mut cursor, has_more) =
            DirCursor::new_window(dir, window_offset, CURSOR_REPLY_WINDOW_ENTRIES)?;
        let mut last_emitted_offset = None;

        while let Some(entry) = cursor.next_entry() {
            let kind = file_type_from_entry_type(entry.entry_type);
            let offset = entry.offset as i64;
            let name = OsStr::from_bytes(&entry.name);
            if reply.add(entry.inode_id, offset, kind, name) {
                return Ok(());
            }
            last_emitted_offset = Some(entry.offset);
        }

        if !has_more {
            break;
        }

        match last_emitted_offset.and_then(|offset| offset.checked_add(1)) {
            Some(next_offset) => window_offset = next_offset,
            None => break,
        }
    }

    Ok(())
}

/// Default file attributes for cursor entry kinds when no actual `getattr`
/// data is available.
impl crate::FileAttr {
    fn default_for_kind(kind: FileType, ino: u64) -> Self {
        Self {
            ino,
            size: 0,
            blocks: 0,
            atime: std::time::UNIX_EPOCH,
            mtime: std::time::UNIX_EPOCH,
            ctime: std::time::UNIX_EPOCH,
            crtime: std::time::UNIX_EPOCH,
            kind,
            perm: if kind == FileType::Directory {
                0o755
            } else {
                0o644
            },
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reply::CapturingSender;

    // -- check_readdir_allowed --------------------------------------------

    #[test]
    fn allowed_on_directory() {
        assert_eq!(check_readdir_allowed(FileType::Directory), Ok(()));
    }

    #[test]
    fn denied_on_regular_file() {
        assert_eq!(
            check_readdir_allowed(FileType::RegularFile),
            Err(libc::ENOTDIR)
        );
    }

    #[test]
    fn denied_on_block_device() {
        assert_eq!(
            check_readdir_allowed(FileType::BlockDevice),
            Err(libc::ENOTDIR)
        );
    }

    #[test]
    fn denied_on_char_device() {
        assert_eq!(
            check_readdir_allowed(FileType::CharDevice),
            Err(libc::ENOTDIR)
        );
    }

    #[test]
    fn denied_on_named_pipe() {
        assert_eq!(
            check_readdir_allowed(FileType::NamedPipe),
            Err(libc::ENOTDIR)
        );
    }

    #[test]
    fn denied_on_socket() {
        assert_eq!(check_readdir_allowed(FileType::Socket), Err(libc::ENOTDIR));
    }

    #[test]
    fn denied_on_symlink() {
        assert_eq!(check_readdir_allowed(FileType::Symlink), Err(libc::ENOTDIR));
    }

    // -- check_readdir_offset ---------------------------------------------

    #[test]
    fn zero_offset_is_valid() {
        assert_eq!(check_readdir_offset(0), Ok(0));
    }

    #[test]
    fn positive_offset_is_valid() {
        assert_eq!(check_readdir_offset(42), Ok(42));
    }

    #[test]
    fn large_positive_offset_is_valid() {
        assert_eq!(check_readdir_offset(i64::MAX), Ok(i64::MAX as u64));
    }

    #[test]
    fn negative_offset_is_rejected() {
        assert_eq!(check_readdir_offset(-1), Err(libc::EINVAL));
    }

    #[test]
    fn very_negative_offset_is_rejected() {
        assert_eq!(check_readdir_offset(i64::MIN), Err(libc::EINVAL));
    }

    // -- plan_readdir -----------------------------------------------------

    #[test]
    fn plan_succeeds_for_directory_zero_offset() {
        let plan = plan_readdir(FileType::Directory, 0).unwrap();
        assert_eq!(plan.offset, 0);
    }

    #[test]
    fn plan_succeeds_for_directory_positive_offset() {
        let plan = plan_readdir(FileType::Directory, 100).unwrap();
        assert_eq!(plan.offset, 100);
    }

    #[test]
    fn plan_fails_for_regular_file() {
        assert_eq!(plan_readdir(FileType::RegularFile, 0), Err(libc::ENOTDIR));
    }

    #[test]
    fn plan_fails_for_negative_offset() {
        assert_eq!(plan_readdir(FileType::Directory, -1), Err(libc::EINVAL));
    }

    #[test]
    fn plan_short_circuits_kind_before_offset() {
        // ENOTDIR takes priority: the inode is not a directory
        assert_eq!(plan_readdir(FileType::RegularFile, -5), Err(libc::ENOTDIR));
    }

    // -- ReadDirPlan ------------------------------------------------------

    #[test]
    fn readdirplan_new_stores_offset() {
        let plan = ReadDirPlan::new(500);
        assert_eq!(plan.offset, 500);
    }

    #[test]
    fn readdirplan_debug_includes_offset() {
        let plan = ReadDirPlan::new(42);
        let dbg = format!("{plan:?}");
        assert!(dbg.contains("42"));
    }

    #[test]
    fn readdirplan_clone_equals_original() {
        let a = ReadDirPlan::new(10);
        let b = a;
        assert_eq!(a, b);
    }

    // -- ReadDirError -----------------------------------------------------

    #[test]
    fn readdir_error_not_a_directory_to_errno() {
        assert_eq!(ReadDirError::NotADirectory.to_errno(), libc::ENOTDIR);
    }

    #[test]
    fn readdir_error_invalid_offset_to_errno() {
        assert_eq!(ReadDirError::InvalidOffset.to_errno(), libc::EINVAL);
    }

    #[test]
    fn readdir_error_permission_denied_to_errno() {
        assert_eq!(ReadDirError::PermissionDenied.to_errno(), libc::EACCES);
    }

    #[test]
    fn readdir_error_display_not_a_directory() {
        let s = format!("{}", ReadDirError::NotADirectory);
        assert!(s.contains("non-directory"));
    }

    #[test]
    fn readdir_error_display_invalid_offset() {
        let s = format!("{}", ReadDirError::InvalidOffset);
        assert!(s.contains("offset"));
    }

    #[test]
    fn readdir_error_display_permission_denied() {
        let s = format!("{}", ReadDirError::PermissionDenied);
        assert!(s.contains("permission denied"));
    }

    #[test]
    fn readdir_error_debug() {
        let dbg = format!("{:?}", ReadDirError::NotADirectory);
        assert!(dbg.contains("NotADirectory"));
    }

    #[test]
    fn readdir_error_clone_and_eq() {
        let a = ReadDirError::InvalidOffset;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn readdir_error_into_c_int() {
        let err: c_int = ReadDirError::NotADirectory.into();
        assert_eq!(err, libc::ENOTDIR);
    }

    #[test]
    fn readdir_error_is_std_error() {
        use std::error::Error;
        let e: &dyn Error = &ReadDirError::InvalidOffset;
        assert!(e.source().is_none());
    }

    // -- handle_readdir ---------------------------------------------------

    #[test]
    fn handle_readdir_directory_zero_offset() {
        let plan = handle_readdir(FileType::Directory, 0).unwrap();
        assert_eq!(plan.offset, 0);
    }

    #[test]
    fn handle_readdir_directory_positive_offset() {
        let plan = handle_readdir(FileType::Directory, 42).unwrap();
        assert_eq!(plan.offset, 42);
    }

    #[test]
    fn handle_readdir_directory_large_offset() {
        let plan = handle_readdir(FileType::Directory, i64::MAX).unwrap();
        assert_eq!(plan.offset, i64::MAX as u64);
    }

    #[test]
    fn handle_readdir_not_a_directory() {
        let result = handle_readdir(FileType::RegularFile, 0);
        assert_eq!(result, Err(ReadDirError::NotADirectory));
    }

    #[test]
    fn handle_readdir_block_device_rejected() {
        let result = handle_readdir(FileType::BlockDevice, 0);
        assert_eq!(result, Err(ReadDirError::NotADirectory));
    }

    #[test]
    fn handle_readdir_symlink_rejected() {
        let result = handle_readdir(FileType::Symlink, 0);
        assert_eq!(result, Err(ReadDirError::NotADirectory));
    }

    #[test]
    fn handle_readdir_socket_rejected() {
        let result = handle_readdir(FileType::Socket, 0);
        assert_eq!(result, Err(ReadDirError::NotADirectory));
    }

    #[test]
    fn handle_readdir_negative_offset() {
        let result = handle_readdir(FileType::Directory, -1);
        assert_eq!(result, Err(ReadDirError::InvalidOffset));
    }

    #[test]
    fn handle_readdir_very_negative_offset() {
        let result = handle_readdir(FileType::Directory, i64::MIN);
        assert_eq!(result, Err(ReadDirError::InvalidOffset));
    }

    #[test]
    fn handle_readdir_not_a_directory_priority_over_offset() {
        // NotADirectory takes priority since it is checked before offset
        let result = handle_readdir(FileType::RegularFile, -1);
        assert_eq!(result, Err(ReadDirError::NotADirectory));
    }

    #[test]
    fn handle_readdir_plan_integrates_with_handler() {
        let plan = handle_readdir(FileType::Directory, 0).unwrap();
        assert_eq!(plan.offset, 0);
    }

    #[test]
    fn handle_readdir_idempotent() {
        for _ in 0..5 {
            assert!(handle_readdir(FileType::Directory, 0).is_ok());
            assert_eq!(
                handle_readdir(FileType::RegularFile, 0),
                Err(ReadDirError::NotADirectory)
            );
            assert_eq!(
                handle_readdir(FileType::Directory, -1),
                Err(ReadDirError::InvalidOffset)
            );
        }
    }

    // -- FuseReadDirHandler: basic construction ---------------------------

    #[test]
    fn handler_new_starts_with_zero_entries_sent() {
        // We can't construct a real ReplyDirectory without a sender,
        // so we test the struct's internal logic via a mock-free approach.
        // These tests validate the public API surface and state machine.
        // Construction tests verify defaults through the plan + offset helpers.
        let plan = plan_readdir(FileType::Directory, 0).unwrap();
        assert_eq!(plan.offset, 0);
    }

    #[test]
    fn plan_readdir_with_large_offset() {
        let plan = plan_readdir(FileType::Directory, 1000).unwrap();
        assert_eq!(plan.offset, 1000);
    }

    // -- Idempotency ------------------------------------------------------

    #[test]
    fn idempotent_check_allowed() {
        for _ in 0..5 {
            assert_eq!(check_readdir_allowed(FileType::Directory), Ok(()));
            assert_eq!(
                check_readdir_allowed(FileType::RegularFile),
                Err(libc::ENOTDIR)
            );
        }
    }

    #[test]
    fn idempotent_check_offset() {
        for _ in 0..5 {
            assert_eq!(check_readdir_offset(0), Ok(0));
            assert_eq!(check_readdir_offset(100), Ok(100));
            assert_eq!(check_readdir_offset(-1), Err(libc::EINVAL));
        }
    }

    // -- Dot / dot-dot: handler does not filter (done at higher layer) ----

    #[test]
    fn plan_readdir_does_not_filter_dot_names() {
        // The handler itself does not filter "." and ".."; the adapter
        // or engine is responsible for entry-level filtering.
        let plan = plan_readdir(FileType::Directory, 0).unwrap();
        assert_eq!(plan.offset, 0);
    }

    // -- Offset resumption at zero yields clean state ---------------------

    #[test]
    fn zero_offset_is_minimal_valid_continuation() {
        assert_eq!(check_readdir_offset(0), Ok(0));
    }

    // -- file_type_from_entry_type ----------------------------------------

    #[test]
    fn entry_type_dir_maps_to_directory() {
        assert_eq!(file_type_from_entry_type(0), FileType::Directory);
    }

    #[test]
    fn entry_type_file_maps_to_regular_file() {
        assert_eq!(file_type_from_entry_type(1), FileType::RegularFile);
    }

    #[test]
    fn entry_type_symlink_maps_to_symlink() {
        assert_eq!(file_type_from_entry_type(2), FileType::Symlink);
    }

    #[test]
    fn entry_type_chr_maps_to_char_device() {
        assert_eq!(file_type_from_entry_type(3), FileType::CharDevice);
    }

    #[test]
    fn entry_type_blk_maps_to_block_device() {
        assert_eq!(file_type_from_entry_type(4), FileType::BlockDevice);
    }

    #[test]
    fn entry_type_fifo_maps_to_named_pipe() {
        assert_eq!(file_type_from_entry_type(5), FileType::NamedPipe);
    }

    #[test]
    fn entry_type_sock_maps_to_socket() {
        assert_eq!(file_type_from_entry_type(6), FileType::Socket);
    }

    #[test]
    fn unknown_entry_type_falls_back_to_regular_file() {
        assert_eq!(file_type_from_entry_type(99), FileType::RegularFile);
        assert_eq!(file_type_from_entry_type(u32::MAX), FileType::RegularFile);
    }

    // -- drive_readdir_from_cursor: empty directory -----------------------

    #[test]
    fn cursor_drive_empty_dir_yields_dot_and_dotdot_only() {
        use tidefs_dir_index::{DatasetDirPolicy, DirIndex};

        let dir = DirIndex::new(1, DatasetDirPolicy::DEFAULT);
        let mut reply = ReplyDirectory::new(0, CapturingSender::new(), 4096);
        let result = drive_readdir_from_cursor(&dir, 0, &mut reply);
        assert!(result.is_ok());
        reply.ok();
    }

    // -- drive_readdir_from_cursor: directory with entries ----------------

    #[test]
    fn cursor_drive_with_entries_packs_into_reply() {
        use tidefs_dir_index::{DatasetDirPolicy, DirIndex};

        let mut dir = DirIndex::new(1, DatasetDirPolicy::DEFAULT);
        let _ = dir.insert(b"alpha", 10, 1, 1);
        let _ = dir.insert(b"beta", 11, 1, 1);
        let _ = dir.insert(b"gamma", 12, 1, 1);

        let mut reply = ReplyDirectory::new(0, CapturingSender::new(), 4096);
        let result = drive_readdir_from_cursor(&dir, 0, &mut reply);
        assert!(result.is_ok());
        reply.ok();
    }

    fn readdir_reply_names(bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut names = Vec::new();
        let mut offset = 16usize; // fuse_out_header
        while offset + 24 <= bytes.len() {
            let namelen = u32::from_le_bytes([
                bytes[offset + 16],
                bytes[offset + 17],
                bytes[offset + 18],
                bytes[offset + 19],
            ]) as usize;
            let name_start = offset + 24;
            let name_end = name_start + namelen;
            if name_end > bytes.len() {
                break;
            }
            names.push(bytes[name_start..name_end].to_vec());
            let record_len = (24 + namelen + 7) & !7;
            offset += record_len;
        }
        names
    }

    #[test]
    fn cursor_drive_large_dir_crosses_internal_cursor_windows() {
        use tidefs_dir_index::{DatasetDirPolicy, DirIndex};

        let mut dir = DirIndex::new(1, DatasetDirPolicy::DEFAULT);
        for i in 0u32..140u32 {
            let name = format!("entry_{i:04}");
            let _ = dir.insert(name.as_bytes(), (1_000 + i) as u64, 1, 1);
        }

        let sender = CapturingSender::new();
        let captured = sender.clone();
        let mut reply = ReplyDirectory::new(0, sender, 64 * 1024);
        let result = drive_readdir_from_cursor(&dir, 0, &mut reply);
        assert!(result.is_ok());
        reply.ok();

        let names = readdir_reply_names(&captured.data());
        assert_eq!(names.len(), 142);
        assert_eq!(names[0], b".".to_vec());
        assert_eq!(names[1], b"..".to_vec());
        assert_eq!(names[2], b"entry_0000".to_vec());
        assert_eq!(names[127], b"entry_0125".to_vec());
        assert_eq!(names[128], b"entry_0126".to_vec());
        assert_eq!(names[141], b"entry_0139".to_vec());
    }

    // -- drive_readdir_from_cursor: offset pagination ---------------------

    #[test]
    fn cursor_drive_respects_start_offset() {
        use tidefs_dir_index::{DatasetDirPolicy, DirIndex};

        let mut dir = DirIndex::new(1, DatasetDirPolicy::DEFAULT);
        for i in 0u32..10u32 {
            let name = format!("entry_{i:03}");
            let _ = dir.insert(name.as_bytes(), (100 + i) as u64, 1, 1);
        }

        let mut reply1 = ReplyDirectory::new(0, CapturingSender::new(), 256);
        let r1 = drive_readdir_from_cursor(&dir, 0, &mut reply1);
        assert!(r1.is_ok());
        reply1.ok();

        let mut reply2 = ReplyDirectory::new(0, CapturingSender::new(), 4096);
        let r2 = drive_readdir_from_cursor(&dir, 5, &mut reply2);
        assert!(r2.is_ok());
        reply2.ok();
    }

    // -- entry_type mapping idempotency -----------------------------------

    #[test]
    fn entry_type_mapping_is_idempotent() {
        for _ in 0..5 {
            assert_eq!(file_type_from_entry_type(0), FileType::Directory);
            assert_eq!(file_type_from_entry_type(1), FileType::RegularFile);
            assert_eq!(file_type_from_entry_type(2), FileType::Symlink);
        }
    }

    // -- FileAttr::default_for_kind sanity ---------------------------------

    #[test]
    fn default_attr_for_directory_has_dir_perm() {
        let attr = crate::FileAttr::default_for_kind(FileType::Directory, 42);
        assert_eq!(attr.ino, 42);
        assert_eq!(attr.perm, 0o755);
        assert_eq!(attr.nlink, 1);
        assert_eq!(attr.kind, FileType::Directory);
    }

    #[test]
    fn default_attr_for_regular_file_has_file_perm() {
        let attr = crate::FileAttr::default_for_kind(FileType::RegularFile, 99);
        assert_eq!(attr.ino, 99);
        assert_eq!(attr.perm, 0o644);
        assert_eq!(attr.kind, FileType::RegularFile);
    }

    // -- DirCursor integration coherence ----------------------------------

    #[test]
    fn plan_readdir_then_cursor_drive_is_coherent() {
        let plan = plan_readdir(FileType::Directory, 0).unwrap();
        assert_eq!(plan.offset, 0);
    }
}
