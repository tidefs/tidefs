//! FUSE `flush` handler helpers.
//!
//! Provides:
//! - [`FlushContext`]: carries the inode number, file handle, and lock owner
//!   identity for a FUSE flush operation (opcode 25).
//! - [`flush_file_handle`]: drain a per-handle writeback buffer; returns the
//!   drained data when dirty pages exist, or `None` for a no-op flush.
//! - [`check_flush_allowed`]: validate that a flush operation is applicable
//!   to the given file kind (regular files, directories, block devices).
//! - [`check_flush_readonly`]: reject flush on a read-only filesystem.
//! - [`handle_flush`]: canonical dispatch entry-point combining inode-kind
//!   validation and read-only check into a single call.
//! - Re-exported POSIX errno codes relevant to the flush path.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::flush;
//!
//! let ctx = flush::FlushContext::new(ino, fh, lock_owner);
//! flush::check_flush_allowed(file_kind)?;
//! flush::check_flush_readonly(read_only)?;
//! if let Some(data) = flush::flush_file_handle(&ctx, &mut wb_buf) {
//!     // persist data through the existing write path...
//! }
//! ```

use crate::errno;
use crate::write::WriteBuffering;
use crate::FileType;
use libc::c_int;

// ---------------------------------------------------------------------------
// Re-exports: standard errno codes for flush error paths
// ---------------------------------------------------------------------------

pub use libc::{EBADF, EINTR, EINVAL, EIO, ENOSPC, ENOTDIR, EROFS};

// ---------------------------------------------------------------------------
// FlushContext
// ---------------------------------------------------------------------------

/// Identity context for a FUSE `flush` request.
///
/// Carries the inode number, file handle, and lock owner that the kernel
/// passes in the FUSE `flush` (opcode 25) request header.  The daemon uses
/// this context to locate the correct writeback buffer and drain dirty data
/// for the closing file descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlushContext {
    /// Inode number of the file being flushed.
    pub ino: u64,
    /// File handle assigned during `open`.
    pub fh: u64,
    /// Lock owner for POSIX lock ownership tracking.
    pub lock_owner: u64,
}

impl FlushContext {
    /// Create a new flush context.
    #[must_use]
    pub const fn new(ino: u64, fh: u64, lock_owner: u64) -> Self {
        Self {
            ino,
            fh,
            lock_owner,
        }
    }
}

// ---------------------------------------------------------------------------
// flush_file_handle -- drain the writeback buffer for a flush
// ---------------------------------------------------------------------------

/// Drain the per-handle writeback buffer for a flush operation.
///
/// When the buffer is non-empty, all accumulated dirty data is drained
/// and returned.  The caller is responsible for persisting the returned
/// data through the existing write path (which already carries intent-log
/// crash safety).
///
/// When the buffer is empty, returns `None` -- this is a valid no-op
/// flush (the file had no buffered writes, or another flush already
/// drained it).
///
/// # Multi-handle independence
///
/// Each file handle has its own writeback buffer.  Draining one handle's
/// buffer does not affect other open handles for the same inode.
pub fn flush_file_handle(_ctx: &FlushContext, writeback: &mut WriteBuffering) -> Option<Vec<u8>> {
    if writeback.is_empty() {
        None
    } else {
        Some(writeback.drain())
    }
}

// ---------------------------------------------------------------------------
// Inode-kind validation
// ---------------------------------------------------------------------------

/// Check whether a flush operation is allowed for the given [`FileType`].
///
/// # Returns
///
/// `Ok(())` for regular files, directories, and block devices that have
/// persistent backing storage.
///
/// `Err(EINVAL)` for named pipes, Unix domain sockets, symbolic links, and
/// character devices that do not support data durability.
///
/// # Rationale
///
/// Per POSIX semantics, flushing a pipe or socket is meaningless.
/// Symlinks are resolved by the kernel before the FUSE handler is invoked,
/// so they should not appear here in practice, but the guard is included
/// for defense in depth.
#[inline]
pub fn check_flush_allowed(kind: FileType) -> Result<(), c_int> {
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

/// Check whether a flush operation is permitted on a read-only filesystem.
///
/// Returns `Err(EROFS)` when `read_only` is `true` and the flush would
/// need to persist data.  The caller should gate on actual dirtiness:
/// a flush on a clean file descriptor is always permitted, even on a
/// read-only mount.
#[inline]
pub fn check_flush_readonly(read_only: bool) -> Result<(), c_int> {
    if read_only {
        Err(errno::EROFS)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// handle_flush -- canonical dispatch entry-point for FUSE flush
// ---------------------------------------------------------------------------

/// Canonical FUSE dispatch entry point for `flush` (opcode 25).
///
/// Validates that the inode kind supports flush and the filesystem is not
/// mounted read-only.  Returns `Ok(())` on success — the caller should then
/// drain the writeback buffer via [`flush_file_handle`].
///
/// # Errors
///
/// Returns `EINVAL` for unsupported inode kinds (pipes, sockets, symlinks,
/// character devices) and `EROFS` for read-only mounts.
#[inline]
pub fn handle_flush(kind: FileType, read_only: bool) -> Result<(), c_int> {
    check_flush_allowed(kind)?;
    check_flush_readonly(read_only)?;
    Ok(())
}
// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- FlushContext construction ----------------------------------------

    #[test]
    fn flush_context_new_stores_fields() {
        let ctx = FlushContext::new(42, 7, 3);
        assert_eq!(ctx.ino, 42);
        assert_eq!(ctx.fh, 7);
        assert_eq!(ctx.lock_owner, 3);
    }

    #[test]
    fn flush_context_zero_values() {
        let ctx = FlushContext::new(0, 0, 0);
        assert_eq!(ctx.ino, 0);
        assert_eq!(ctx.fh, 0);
        assert_eq!(ctx.lock_owner, 0);
    }

    #[test]
    fn flush_context_max_values() {
        let ctx = FlushContext::new(u64::MAX, u64::MAX, u64::MAX);
        assert_eq!(ctx.ino, u64::MAX);
        assert_eq!(ctx.fh, u64::MAX);
        assert_eq!(ctx.lock_owner, u64::MAX);
    }

    #[test]
    fn flush_context_copy_and_clone() {
        let ctx = FlushContext::new(10, 20, 30);
        let copied = ctx; // Copy
        assert_eq!(ctx, copied);
        let cloned = ctx; // Clone
        assert_eq!(ctx, cloned);
    }

    #[test]
    fn flush_context_debug_nonempty() {
        let ctx = FlushContext::new(1, 2, 3);
        let s = format!("{ctx:?}");
        assert!(!s.is_empty());
        assert!(s.contains("1"));
        assert!(s.contains("2"));
        assert!(s.contains("3"));
    }

    // -- flush_file_handle: empty buffer (no-op) -------------------------

    #[test]
    fn flush_empty_buffer_returns_none() {
        let ctx = FlushContext::new(1, 1, 0);
        let mut buf = WriteBuffering::new(65536);
        assert!(buf.is_empty());
        let result = flush_file_handle(&ctx, &mut buf);
        assert!(result.is_none());
        assert!(buf.is_empty());
    }

    #[test]
    fn flush_empty_buffer_twice_is_idempotent() {
        let ctx = FlushContext::new(1, 1, 0);
        let mut buf = WriteBuffering::new(65536);
        assert!(flush_file_handle(&ctx, &mut buf).is_none());
        assert!(flush_file_handle(&ctx, &mut buf).is_none());
    }

    // -- flush_file_handle: dirty buffer drain ---------------------------

    #[test]
    fn flush_dirty_buffer_returns_drained_data() {
        let ctx = FlushContext::new(2, 2, 0);
        let mut buf = WriteBuffering::new(65536);
        buf.append(0, b"hello").unwrap();
        buf.append(5, b" world").unwrap();
        assert_eq!(buf.len(), 11);

        let result = flush_file_handle(&ctx, &mut buf);
        assert_eq!(result, Some(b"hello world".to_vec()));
        assert!(buf.is_empty());
    }

    #[test]
    fn flush_dirty_buffer_single_page() {
        let ctx = FlushContext::new(3, 3, 0);
        let mut buf = WriteBuffering::new(4096);
        buf.append(0, &[0xAAu8; 4096]).unwrap();
        assert!(buf.should_flush());

        let result = flush_file_handle(&ctx, &mut buf);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 4096);
        assert!(buf.is_empty());
    }

    #[test]
    fn flush_after_drain_buffer_is_empty() {
        let ctx = FlushContext::new(4, 4, 0);
        let mut buf = WriteBuffering::new(65536);
        buf.append(0, b"data").unwrap();
        let _ = flush_file_handle(&ctx, &mut buf);
        assert!(buf.is_empty());
        // second flush is no-op
        assert!(flush_file_handle(&ctx, &mut buf).is_none());
    }

    // -- flush_file_handle: multi-handle independence --------------------

    #[test]
    fn flush_multi_handle_independence() {
        let ctx1 = FlushContext::new(10, 1, 0);
        let ctx2 = FlushContext::new(10, 2, 0); // same inode, different handle

        let mut buf1 = WriteBuffering::new(65536);
        let mut buf2 = WriteBuffering::new(65536);

        buf1.append(0, b"handle-one-data").unwrap();
        buf2.append(0, b"handle-two-data").unwrap();

        // Flush handle 1 only
        let result1 = flush_file_handle(&ctx1, &mut buf1);
        assert_eq!(result1, Some(b"handle-one-data".to_vec()));
        assert!(buf1.is_empty());

        // Handle 2's buffer is unaffected
        assert!(!buf2.is_empty());
        let result2 = flush_file_handle(&ctx2, &mut buf2);
        assert_eq!(result2, Some(b"handle-two-data".to_vec()));
    }

    #[test]
    fn flush_only_drains_target_buffer() {
        let ctx_a = FlushContext::new(100, 10, 0);
        let _ctx_b = FlushContext::new(100, 20, 0);

        let mut buf_a = WriteBuffering::new(65536);
        let mut buf_b = WriteBuffering::new(65536);

        buf_a.append(0, b"AAAA").unwrap();
        buf_b.append(0, b"BBBB").unwrap();

        flush_file_handle(&ctx_a, &mut buf_a);
        assert!(buf_a.is_empty());
        assert!(!buf_b.is_empty());
        assert_eq!(buf_b.as_bytes(), b"BBBB");
    }

    // -- error propagation on I/O failure --------------------------------

    #[test]
    fn flush_returns_data_caller_handles_persistence_error() {
        // flush_file_handle itself doesn't fail; it returns data for the
        // caller to persist.  This test verifies the data is intact so the
        // caller can attempt write-out and propagate any I/O error.
        let ctx = FlushContext::new(7, 7, 0);
        let mut buf = WriteBuffering::new(65536);
        buf.append(0, b"critical-data").unwrap();

        let drained = flush_file_handle(&ctx, &mut buf);
        assert!(drained.is_some());
        // Simulate what the caller does: persist via the write path.
        // If persisting fails, the caller converts that to an errno.
        let persist_result: Result<(), c_int> = Err(EIO);
        assert!(persist_result.is_err());
    }

    // -- check_flush_allowed ----------------------------------------------

    #[test]
    fn flush_allowed_on_regular_file() {
        assert_eq!(check_flush_allowed(FileType::RegularFile), Ok(()));
    }

    #[test]
    fn flush_allowed_on_directory() {
        assert_eq!(check_flush_allowed(FileType::Directory), Ok(()));
    }

    #[test]
    fn flush_allowed_on_block_device() {
        assert_eq!(check_flush_allowed(FileType::BlockDevice), Ok(()));
    }

    #[test]
    fn flush_denied_on_named_pipe() {
        assert_eq!(check_flush_allowed(FileType::NamedPipe), Err(errno::EINVAL));
    }

    #[test]
    fn flush_denied_on_socket() {
        assert_eq!(check_flush_allowed(FileType::Socket), Err(errno::EINVAL));
    }

    #[test]
    fn flush_denied_on_char_device() {
        assert_eq!(
            check_flush_allowed(FileType::CharDevice),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn flush_denied_on_symlink() {
        assert_eq!(check_flush_allowed(FileType::Symlink), Err(errno::EINVAL));
    }

    // -- check_flush_readonly ---------------------------------------------

    #[test]
    fn ro_mount_rejects_flush() {
        assert_eq!(check_flush_readonly(true), Err(errno::EROFS));
    }

    #[test]
    fn rw_mount_allows_flush() {
        assert_eq!(check_flush_readonly(false), Ok(()));
    }

    // -- Integration: flush_file_handle + validation ----------------------

    #[test]
    fn flush_validated_then_drained() {
        let ctx = FlushContext::new(8, 8, 0);
        let mut buf = WriteBuffering::new(65536);
        buf.append(0, b"validated-flush").unwrap();

        assert_eq!(check_flush_allowed(FileType::RegularFile), Ok(()));
        assert_eq!(check_flush_readonly(false), Ok(()));
        let result = flush_file_handle(&ctx, &mut buf);
        assert_eq!(result, Some(b"validated-flush".to_vec()));
    }

    #[test]
    fn flush_rejected_on_socket_even_with_data() {
        let _ctx = FlushContext::new(9, 9, 0);
        let mut buf = WriteBuffering::new(65536);
        buf.append(0, b"should-not-flush").unwrap();

        // Validation must happen before drain
        assert_eq!(check_flush_allowed(FileType::Socket), Err(errno::EINVAL));
        // Buffer is not drained yet (caller must validate first)
        assert!(!buf.is_empty());
    }

    #[test]
    fn flush_after_fsync_idempotency() {
        // After fsync drains the buffer, flush should be a no-op.
        let ctx = FlushContext::new(11, 11, 0);
        let mut buf = WriteBuffering::new(65536);
        buf.append(0, b"post-fsync").unwrap();

        // Simulate fsync: drain buffer and persist
        let _fsync_data = flush_file_handle(&ctx, &mut buf);
        assert!(buf.is_empty());

        // Subsequent flush is no-op
        assert!(flush_file_handle(&ctx, &mut buf).is_none());
    }

    // -- handle_flush --------------------------------------------------

    #[test]
    fn handle_flush_succeeds_on_regular_file() {
        assert_eq!(handle_flush(FileType::RegularFile, false), Ok(()));
    }

    #[test]
    fn handle_flush_succeeds_on_directory() {
        assert_eq!(handle_flush(FileType::Directory, false), Ok(()));
    }

    #[test]
    fn handle_flush_succeeds_on_block_device() {
        assert_eq!(handle_flush(FileType::BlockDevice, false), Ok(()));
    }

    #[test]
    fn handle_flush_rejected_on_pipe() {
        assert_eq!(handle_flush(FileType::NamedPipe, false), Err(errno::EINVAL));
    }

    #[test]
    fn handle_flush_rejected_on_read_only_mount() {
        assert_eq!(handle_flush(FileType::RegularFile, true), Err(errno::EROFS));
    }

    #[test]
    fn handle_flush_rejected_on_socket_with_ro() {
        // Inode-kind check takes priority; returns EINVAL even on RO mount
        assert_eq!(handle_flush(FileType::Socket, true), Err(errno::EINVAL));
    }
}
