//! Shared dispatch helpers for FUSE operation handlers.
//!
//! This module centralizes error-to-errno mapping and reply boilerplate
//! that was previously duplicated across ~25 FUSE operation handlers in
//! [`FuseVfsAdapter`](crate::fuse_vfs_adapter::FuseVfsAdapter).
//!
//! # Error-to-errno mapping catalogue
//!
//! Every error path in the daemon maps to a POSIX errno before reaching
//! the kernel. This catalogue documents every mapping site and the errno
//! values in use. The two primary centralized mappers are:
//!
//! - `crate::fuse_vfs_adapter::namespace_error_to_errno`:
//!   maps [`tidefs_namespace::NamespaceError`] to [`Errno`].
//! - `crate::fuse_vfs_adapter::errno_from_meta_error`:
//!   maps [`MetaError`](crate::workers_meta::MetaError) to [`Errno`].
//!
//! ## 1. NamespaceError → Errno (namespace_error_to_errno, line 120)
//!
//! | NamespaceError variant          | Errno       |
//! |--------------------------------|-------------|
//! | `NotFound`, `InodeNotFound`    | `ENOENT`    |
//! | `AlreadyExists`                | `EEXIST`    |
//! | `NotEmpty`                     | `ENOTEMPTY` |
//! | `NotDirectory`                 | `ENOTDIR`   |
//! | `IsDirectory`                  | `EISDIR`    |
//! | `InvalidName`                  | `EINVAL`    |
//! | `TooManySymlinks`              | `ELOOP`     |
//! | `NotSymlink`                   | `EINVAL`    |
//! | `LinkCountOverflow`            | `EMLINK`    |
//! | `RenameCycle`                  | `EINVAL`    |
//! | (other)                        | `EIO`       |
//!
//! ## 2. MetaError → Errno (errno_from_meta_error, line 1610)
//!
//! | MetaError variant   | Errno     |
//! |--------------------|-----------|
//! | `InoNotFound`      | `ENOENT`  |
//! | `AttrStoreError`   | `ENOLINK` |
//! | `NotDir`           | `ENOTDIR` |
//! | `PermDenied`       | `EPERM`   |
//! | `ReplyError`, `Io` | `EIO`     |
//!
//! ## 3. Domain error enums with to_errno() methods
//!
//! | Error enum            | Module                  | Returns | Variants mapped to errno                       |
//! |-----------------------|-------------------------|---------|-------------------------------------------------|
//! | `WriteError`          | `fuse_write`            | `Errno` | `BadFileDescriptor→EBADF`, `NotWritable→EBADF`, `NoSpace→ENOSPC`, `IoError→EIO`, `InvalidArgument→EINVAL` |
//! | `FlushError`          | `fuse_flush_fsync`      | `Errno` | `BadFileDescriptor→EBADF`, `IoError→EIO`, `NoSpace→ENOSPC`, `Interrupted→EINTR` |
//! | `FsyncError`          | `fuse_flush_fsync`      | `Errno` | Same as FlushError                              |
//! | `LockDispatchError`   | `lock_dispatch`         | `Errno` | `InvalidLockType→EINVAL`, `Conflict→EAGAIN`, `WouldBlock→EAGAIN` |
//!
//! ## 4. Inline Errno values in helper functions (fuse_vfs_adapter.rs)
//!
//! | Location / function                    | Condition                            | Errno        |
//! |----------------------------------------|--------------------------------------|--------------|
//! | `errno_for_missing_dir_handle`         | kind is `Dir`                        | `EBADF`      |
//! | `errno_for_missing_dir_handle`         | kind is not `Dir` (file)             | `ENOTDIR`    |
//! | `errno_for_missing_dir_handle`         | kind is `None` (not found)           | `ENOENT`     |
//! | `fuse_dir_offset`                      | cookie overflow                      | `EOVERFLOW`  |
//! | `copy_file_range_ranges_overlap`       | offset overflow                      | `EINVAL`     |
//! | `plan_vfs_copy_file_range_dispatch`    | bad plan                             | `EINVAL`     |
//! | `plan_vfs_copy_file_range_dispatch`    | src handle not found                 | `EBADF`      |
//! | `plan_vfs_copy_file_range_dispatch`    | dst handle not found                 | `EBADF`      |
//! | `plan_vfs_copy_file_range_dispatch`    | overlapping ranges                   | `EINVAL`     |
//! | `plan_vfs_bmap`                        | blocksize == 0                       | `EINVAL`     |
//! | `parse_vfs_fiemap_request`             | unknown ioctl cmd                    | `EOPNOTSUPP` |
//! | `parse_vfs_fiemap_request`             | malformed header                     | `EINVAL`     |
//! | `dispatch_lookup` (negative cache hit) |                                      | `ENOENT`     |
//! | `lookup_attr` (engine error)           |                                      | `ENOENT`     |
//! | `dispatch_getattr` (ENOENT→ESTALE)     |                                      | `ESTALE`     |
//! | `dispatch_fallocate_file` (length==0)  |                                      | `EINVAL`     |
//! | `dispatch_fallocate_file` (bad offset) |                                      | `EFBIG`      |
//! | `dispatch_fallocate_file` (bad mode)   |                                      | `EINVAL`     |
//! | `dispatch_truncate` (bad size)         |                                      | `EFBIG`      |
//! | `dispatch_lseek` (bad offset)          |                                      | `EINVAL`     |
//! | `dispatch_lseek` (invalid whence)      |                                      | `EINVAL`     |
//! | Handle table `resolve` (not found)     |                                      | `EBADF`      |
//! | Handle table `check_open_allowed`      |                                      | `EBUSY`      |
//! | `readdir` (non-dir handle)             |                                      | `ENOTDIR`    |
//! | `readdir` (bad cookie)                 |                                      | `EINVAL`     |
//! | `readdir` negative lookup              |                                      | `ENOENT`     |
//! | `readdir` negative lookup (not dir)    |                                      | `ENOTDIR`    |
//! | `readdir` permission denied            |                                      | `EACCES`     |
//! | Namespace path (non-UTF-8 name)        |                                      | `EINVAL`     |
//! | Namespace path (name too long)         |                                      | `ENAMETOOLONG` |
//! | Namespace path (bad link target)       |                                      | `EINVAL`     |
//! | xattr value > max size                 |                                      | `ERANGE`     |
//! | `dispatch_poll_file` (bad handle)      |                                      | `EBADF`      |
//! | `statfs` empty reply sink              |                                      | `EIO`        |
//!
//! ## 5. FUSE handler inline error returns
//!
//! | Handler    | Condition                            | Errno        |
//! |-----------|--------------------------------------|--------------|
//! | `write`   | `FUSE_WRITE_CACHE` (when writeback-cache disabled) or unknown flags  | `EINVAL`     |
//! | `lookup`  | `emit_lookup_reply` (no attr+no err) | `EIO`        |
//! | `ioctl`   | bad fiemap request                   | (varies)     |
//! | `getlk`   | deadlock detected                    | `EDEADLK`    |
//!
//! # Reply helpers
//!
//! The [`ReplyError`] trait provides a uniform `reply_errno` method for all
//! FUSE reply types, eliminating the repeated `reply.error(errno.raw() as i32)`
//! pattern found in every handler.

use fuser::{
    ReplyAttr, ReplyBmap, ReplyCreate, ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty,
    ReplyEntry, ReplyIoctl, ReplyLock, ReplyLseek, ReplyOpen, ReplyPoll, ReplyStatfs, ReplyStatx,
    ReplyWrite, ReplyXattr,
};
use tidefs_types_vfs_core::Errno;

/// Trait for FUSE reply types that can report an error.
///
/// Provides a uniform method to send an [`Errno`] error code back to the
/// kernel, replacing the repeated `reply.error(errno.raw() as i32)` pattern
/// that appears in every FUSE operation handler.
pub trait ReplyError {
    /// Send the given errno back to the kernel as the FUSE reply.
    fn reply_errno(self, errno: Errno);
}

// ── ReplyError impls for all reply types used in the daemon ─────────────

impl ReplyError for ReplyEmpty {
    fn reply_errno(self, errno: Errno) {
        self.error(errno.raw() as i32);
    }
}

impl ReplyError for ReplyEntry {
    fn reply_errno(self, errno: Errno) {
        self.error(errno.raw() as i32);
    }
}

impl ReplyError for ReplyAttr {
    fn reply_errno(self, errno: Errno) {
        self.error(errno.raw() as i32);
    }
}

impl ReplyError for ReplyData {
    fn reply_errno(self, errno: Errno) {
        self.error(errno.raw() as i32);
    }
}

impl ReplyError for ReplyWrite {
    fn reply_errno(self, errno: Errno) {
        self.error(errno.raw() as i32);
    }
}

impl ReplyError for ReplyOpen {
    fn reply_errno(self, errno: Errno) {
        self.error(errno.raw() as i32);
    }
}

impl ReplyError for ReplyCreate {
    fn reply_errno(self, errno: Errno) {
        self.error(errno.raw() as i32);
    }
}

impl ReplyError for ReplyLock {
    fn reply_errno(self, errno: Errno) {
        self.error(errno.raw() as i32);
    }
}

impl ReplyError for ReplyBmap {
    fn reply_errno(self, errno: Errno) {
        self.error(errno.raw() as i32);
    }
}

impl ReplyError for ReplyIoctl {
    fn reply_errno(self, errno: Errno) {
        self.error(errno.raw() as i32);
    }
}

impl ReplyError for ReplyLseek {
    fn reply_errno(self, errno: Errno) {
        self.error(errno.raw() as i32);
    }
}

impl ReplyError for ReplyPoll {
    fn reply_errno(self, errno: Errno) {
        self.error(errno.raw() as i32);
    }
}

impl ReplyError for ReplyXattr {
    fn reply_errno(self, errno: Errno) {
        self.error(errno.raw() as i32);
    }
}

impl ReplyError for ReplyStatfs {
    fn reply_errno(self, errno: Errno) {
        self.error(errno.raw() as i32);
    }
}

impl ReplyError for ReplyStatx {
    fn reply_errno(self, errno: Errno) {
        self.error(errno.raw() as i32);
    }
}

impl ReplyError for ReplyDirectory {
    fn reply_errno(self, errno: Errno) {
        self.error(errno.raw() as i32);
    }
}

impl ReplyError for ReplyDirectoryPlus {
    fn reply_errno(self, errno: Errno) {
        self.error(errno.raw() as i32);
    }
}

/// Helper: for `ReplyEmpty` results, consume the reply with the result.
///
/// Replaces the common pattern across 11 handlers:
/// ```ignore
/// match result {
///     Ok(()) => reply.ok(),
///     Err(errno) => reply.reply_errno(errno),
/// }
/// ```
#[inline]
pub fn reply_empty_ok_or_errno(reply: ReplyEmpty, result: Result<(), Errno>) {
    match result {
        Ok(()) => reply.ok(),
        Err(errno) => reply.reply_errno(errno),
    }
}

/// Derive a synthetic [`tidefs_local_object_store::ObjectKey`] for commit_group tracking.
///
/// Constructs a 32-byte key from the inode number and byte offset so that
/// writes to distinct (ino, offset) pairs map to distinct commit_group accumulator
/// entries. This is NOT a cryptographic content key — it only needs to be
/// distinct within a transaction group for dirty-page accounting.
pub fn derive_commit_group_object_key(
    ino: u64,
    offset: u64,
) -> tidefs_local_object_store::ObjectKey {
    use tidefs_local_object_store::ObjectKey;
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&ino.to_le_bytes());
    bytes[8..16].copy_from_slice(&offset.to_le_bytes());
    ObjectKey::from_bytes32(bytes)
}
