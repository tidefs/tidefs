// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! P5-02 FUSE wire decode/encode: header parsing and canonical request extraction.
//!
//! Part of the P5-02 classified multipool topology for the userspace FUSE runtime.
//! This seam family is one of 10 explicit crate boundaries that separate ingress,
//! scheduling, workers, reply commit, and maintenance so they do not blur
//! into one daemon blob.

use std::vec::Vec;
use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterReplyClass, PosixFilesystemAdapterRequestClass,
    PosixFilesystemAdapterShardKeyPolicy,
};
#[allow(unused_imports)]
pub use tidefs_types_vfs_core::{
    compose_posix_time_ns, SetAttr, FATTR_ATIME, FATTR_ATIME_NOW, FATTR_CTIME, FATTR_FH, FATTR_GID,
    FATTR_LOCKOWNER, FATTR_MODE, FATTR_MTIME, FATTR_MTIME_NOW, FATTR_SIZE, FATTR_UID,
};

/// Re-export all P5-02 request-queue types and runtime functions for this seam family.
pub const SEAM_FAMILY_DOC: &str = concat!("seam.", env!("CARGO_PKG_NAME"), ".    P5-02.v0");

// ── FUSE opcode constants ───────────────────────────────────────────────────

/// Linux FUSE opcodes (kernel ABI, fuse_kernel.h).
pub mod opcode {
    pub const FUSE_LOOKUP: u32 = 1;
    pub const FUSE_FORGET: u32 = 2;
    pub const FUSE_GETATTR: u32 = 3;
    pub const FUSE_SETATTR: u32 = 4;
    pub const FUSE_READLINK: u32 = 5;
    pub const FUSE_SYMLINK: u32 = 6;
    pub const FUSE_MKNOD: u32 = 8;
    pub const FUSE_MKDIR: u32 = 9;
    pub const FUSE_UNLINK: u32 = 10;
    pub const FUSE_RMDIR: u32 = 11;
    pub const FUSE_RENAME: u32 = 12;
    pub const FUSE_LINK: u32 = 13;
    pub const FUSE_OPEN: u32 = 14;
    pub const FUSE_READ: u32 = 15;
    pub const FUSE_WRITE: u32 = 16;
    pub const FUSE_STATFS: u32 = 17;
    pub const FUSE_RELEASE: u32 = 18;
    pub const FUSE_FSYNC: u32 = 20;
    pub const FUSE_SETXATTR: u32 = 21;
    pub const FUSE_GETXATTR: u32 = 22;
    pub const FUSE_LISTXATTR: u32 = 23;
    pub const FUSE_REMOVEXATTR: u32 = 24;
    pub const FUSE_FLUSH: u32 = 25;
    pub const FUSE_INIT: u32 = 26;
    pub const FUSE_OPENDIR: u32 = 27;
    pub const FUSE_READDIR: u32 = 28;
    pub const FUSE_RELEASEDIR: u32 = 29;
    pub const FUSE_FSYNCDIR: u32 = 30;
    pub const FUSE_GETLK: u32 = 31;
    pub const FUSE_SETLK: u32 = 32;
    pub const FUSE_SETLKW: u32 = 33;
    pub const FUSE_ACCESS: u32 = 34;
    pub const FUSE_CREATE: u32 = 35;
    pub const FUSE_INTERRUPT: u32 = 36;
    pub const FUSE_BMAP: u32 = 37;
    pub const FUSE_DESTROY: u32 = 38;
    pub const FUSE_IOCTL: u32 = 39;
    pub const FUSE_POLL: u32 = 40;
    pub const FUSE_NOTIFY_REPLY: u32 = 41;
    pub const FUSE_BATCH_FORGET: u32 = 42;
    pub const FUSE_FALLOCATE: u32 = 43;
    pub const FUSE_READDIRPLUS: u32 = 44;
    pub const FUSE_RENAME2: u32 = 45;
    pub const FUSE_LSEEK: u32 = 46;
    pub const FUSE_COPY_FILE_RANGE: u32 = 47;
    pub const FUSE_SETUPMAPPING: u32 = 48;
    pub const FUSE_REMOVEMAPPING: u32 = 49;
    pub const FUSE_SYNCFS: u32 = 50;
    pub const FUSE_TMPFILE: u32 = 51;
    pub const FUSE_STATX: u32 = 52;
    pub const FUSE_SETVOLNAME: u32 = 61;
    pub const FUSE_GETXTIMES: u32 = 62;
    pub const FUSE_EXCHANGE: u32 = 63;
}

// ── Request classification ──────────────────────────────────────────────────

/// Classify a FUSE opcode into its canonical P5-02 request class.
///
/// §4.1 specifies 8 request classes with strict opcode membership.
#[must_use]
pub const fn classify_fuse_request(opcode: u32) -> PosixFilesystemAdapterRequestClass {
    match opcode {
        // queue_class_0.control_urgent — INIT, DESTROY, INTERRUPT, FORGET, BATCH_FORGET
        opcode::FUSE_INIT
        | opcode::FUSE_DESTROY
        | opcode::FUSE_INTERRUPT
        | opcode::FUSE_FORGET
        | opcode::FUSE_BATCH_FORGET => PosixFilesystemAdapterRequestClass::ControlUrgent,

        // queue_class_1.meta_read — LOOKUP, GETATTR, ACCESS, READLINK, STATFS, STATX
        opcode::FUSE_LOOKUP
        | opcode::FUSE_GETATTR
        | opcode::FUSE_ACCESS
        | opcode::FUSE_READLINK
        | opcode::FUSE_STATFS
        | opcode::FUSE_STATX
        | opcode::FUSE_GETXTIMES => PosixFilesystemAdapterRequestClass::MetaRead,

        // queue_class_2.namespace_mut — create/unlink/rename/link/symlink/mknod/xattr
        opcode::FUSE_MKDIR
        | opcode::FUSE_UNLINK
        | opcode::FUSE_RMDIR
        | opcode::FUSE_RENAME
        | opcode::FUSE_RENAME2
        | opcode::FUSE_LINK
        | opcode::FUSE_SYMLINK
        | opcode::FUSE_MKNOD
        | opcode::FUSE_CREATE
        | opcode::FUSE_TMPFILE
        | opcode::FUSE_SETXATTR
        | opcode::FUSE_GETXATTR
        | opcode::FUSE_LISTXATTR
        | opcode::FUSE_REMOVEXATTR
        | opcode::FUSE_EXCHANGE => PosixFilesystemAdapterRequestClass::NamespaceMut,

        // queue_class_3.dir_stream — OPENDIR, READDIR, READDIRPLUS, RELEASEDIR, FSYNCDIR
        opcode::FUSE_OPENDIR
        | opcode::FUSE_READDIR
        | opcode::FUSE_READDIRPLUS
        | opcode::FUSE_RELEASEDIR
        | opcode::FUSE_FSYNCDIR => PosixFilesystemAdapterRequestClass::DirStream,

        // queue_class_4.file_read — OPEN, READ, LSEEK, small ioctls/poll
        opcode::FUSE_OPEN
        | opcode::FUSE_READ
        | opcode::FUSE_LSEEK
        | opcode::FUSE_IOCTL
        | opcode::FUSE_POLL => PosixFilesystemAdapterRequestClass::FileRead,

        // queue_class_5.file_writeback — WRITE, SETATTR, FALLOCATE, COPY_FILE_RANGE, FLUSH, FSYNC, RELEASE
        opcode::FUSE_WRITE
        | opcode::FUSE_SETATTR
        | opcode::FUSE_FALLOCATE
        | opcode::FUSE_COPY_FILE_RANGE
        | opcode::FUSE_FLUSH
        | opcode::FUSE_FSYNC
        | opcode::FUSE_RELEASE
        | opcode::FUSE_SYNCFS => PosixFilesystemAdapterRequestClass::FileWriteback,

        // queue_class_6.lock_wait — GETLK, SETLK, SETLKW.
        opcode::FUSE_GETLK | opcode::FUSE_SETLK | opcode::FUSE_SETLKW => {
            PosixFilesystemAdapterRequestClass::LockWait
        }

        // queue_class_7.maintenance — BMAP, NOTIFY_REPLY, SETUPMAPPING, REMOVEMAPPING
        opcode::FUSE_BMAP
        | opcode::FUSE_NOTIFY_REPLY
        | opcode::FUSE_SETUPMAPPING
        | opcode::FUSE_REMOVEMAPPING
        | opcode::FUSE_SETVOLNAME => PosixFilesystemAdapterRequestClass::Maintenance,

        // Unrecognized opcodes → Maintenance (safe fallback; does not starve control)
        _ => PosixFilesystemAdapterRequestClass::Maintenance,
    }
}

/// Derive the canonical shard-key policy for a FUSE opcode.
///
/// §5 specifies 7 shard keys that workers use instead of one global FIFO.
#[must_use]
pub const fn derive_shard_key_policy(opcode: u32) -> PosixFilesystemAdapterShardKeyPolicy {
    match opcode {
        // Session-global: control and maintenance operations
        opcode::FUSE_INIT
        | opcode::FUSE_DESTROY
        | opcode::FUSE_INTERRUPT
        | opcode::FUSE_FORGET
        | opcode::FUSE_BATCH_FORGET
        | opcode::FUSE_NOTIFY_REPLY
        | opcode::FUSE_SYNCFS
        | opcode::FUSE_STATFS
        | opcode::FUSE_SETVOLNAME => PosixFilesystemAdapterShardKeyPolicy::Session,

        // Parent-directory: single-parent namespace mutations and metadata reads
        opcode::FUSE_LOOKUP
        | opcode::FUSE_GETATTR
        | opcode::FUSE_ACCESS
        | opcode::FUSE_READLINK
        | opcode::FUSE_STATX
        | opcode::FUSE_GETXTIMES
        | opcode::FUSE_MKDIR
        | opcode::FUSE_UNLINK
        | opcode::FUSE_RMDIR
        | opcode::FUSE_SYMLINK
        | opcode::FUSE_MKNOD
        | opcode::FUSE_CREATE
        | opcode::FUSE_TMPFILE
        | opcode::FUSE_LINK
        | opcode::FUSE_SETXATTR
        | opcode::FUSE_GETXATTR
        | opcode::FUSE_LISTXATTR
        | opcode::FUSE_REMOVEXATTR => PosixFilesystemAdapterShardKeyPolicy::ParentDir,

        // Dual-parent: rename-style operations
        opcode::FUSE_RENAME | opcode::FUSE_RENAME2 | opcode::FUSE_EXCHANGE => {
            PosixFilesystemAdapterShardKeyPolicy::DualParentPair
        }

        // Object-read: handle/object read locality
        opcode::FUSE_OPEN | opcode::FUSE_READ | opcode::FUSE_LSEEK | opcode::FUSE_IOCTL => {
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead
        }

        // Object-write: dirty/writeback locality
        opcode::FUSE_WRITE
        | opcode::FUSE_SETATTR
        | opcode::FUSE_FALLOCATE
        | opcode::FUSE_COPY_FILE_RANGE
        | opcode::FUSE_FLUSH
        | opcode::FUSE_FSYNC
        | opcode::FUSE_RELEASE => PosixFilesystemAdapterShardKeyPolicy::ObjectWrite,

        // Dir-handle: directory stream locality
        opcode::FUSE_OPENDIR
        | opcode::FUSE_READDIR
        | opcode::FUSE_READDIRPLUS
        | opcode::FUSE_RELEASEDIR
        | opcode::FUSE_FSYNCDIR => PosixFilesystemAdapterShardKeyPolicy::DirHandle,

        // Lock-scope: file/record lock scope. BSD flock is carried by lock flags.
        opcode::FUSE_GETLK | opcode::FUSE_SETLK | opcode::FUSE_SETLKW => {
            PosixFilesystemAdapterShardKeyPolicy::LockScope
        }

        // Default: session-scoped for unrecognized opcodes
        _ => PosixFilesystemAdapterShardKeyPolicy::Session,
    }
}

/// Classify which reply lane a request class should use.
///
/// Metadata and small-data replies use `SmallReply`;
/// bulk data replies use `BulkReply` under reply-byte credits.
#[must_use]
pub const fn classify_reply_class(
    request_class: PosixFilesystemAdapterRequestClass,
) -> PosixFilesystemAdapterReplyClass {
    match request_class {
        PosixFilesystemAdapterRequestClass::ControlUrgent
        | PosixFilesystemAdapterRequestClass::MetaRead
        | PosixFilesystemAdapterRequestClass::NamespaceMut
        | PosixFilesystemAdapterRequestClass::DirStream
        | PosixFilesystemAdapterRequestClass::LockWait
        | PosixFilesystemAdapterRequestClass::Maintenance => {
            PosixFilesystemAdapterReplyClass::SmallReply
        }
        PosixFilesystemAdapterRequestClass::FileRead
        | PosixFilesystemAdapterRequestClass::FileWriteback => {
            PosixFilesystemAdapterReplyClass::BulkReply
        }
    }
}

// ── FUSE request payload parsing ────────────────────────────────────────────

/// Wire size of `struct fuse_init_in` for the ABI used by fuser 0.14.
pub const FUSE_INIT_IN_WIRE_SIZE: usize = 16;

/// FUSE protocol major version supported by the current userspace adapter.
pub const FUSE_INIT_SUPPORTED_MAJOR: u32 = 7;

/// Highest FUSE protocol minor version this helper plans reply fields for.
pub const FUSE_INIT_SUPPORTED_MINOR: u32 = 28;

/// Smallest max-write value accepted in a planned FUSE INIT reply.
pub const FUSE_INIT_MIN_MAX_WRITE: u32 = 4 * 1024;

/// Default max-write advertised by the current userspace adapter plan.
pub const FUSE_INIT_DEFAULT_MAX_WRITE: u32 = 128 * 1024;

/// Largest max-write value this deterministic planner will advertise.
pub const FUSE_INIT_MAX_WRITE_LIMIT: u32 = 1024 * 1024;

/// Default max-readahead advertised by the current userspace adapter plan.
pub const FUSE_INIT_DEFAULT_MAX_READAHEAD: u32 = 128 * 1024;

/// Default background request limit advertised in the INIT reply.
pub const FUSE_INIT_DEFAULT_MAX_BACKGROUND: u16 = 16;

/// Default congestion threshold advertised in the INIT reply.
pub const FUSE_INIT_DEFAULT_CONGESTION_THRESHOLD: u16 = 12;

/// Default timestamp granularity in nanoseconds.
pub const FUSE_INIT_DEFAULT_TIME_GRAN_NS: u32 = 1;

/// Default maximum pages per request when FUSE_MAX_PAGES is negotiated.
pub const FUSE_INIT_DEFAULT_MAX_PAGES: u16 = 32;

/// Linux FUSE INIT capability flags used by the current userspace adapter.
pub mod init_flags {
    pub const FUSE_ASYNC_READ: u32 = 1 << 0;
    pub const FUSE_POSIX_LOCKS: u32 = 1 << 1;
    pub const FUSE_FILE_OPS: u32 = 1 << 2;
    pub const FUSE_ATOMIC_O_TRUNC: u32 = 1 << 3;
    pub const FUSE_EXPORT_SUPPORT: u32 = 1 << 4;
    pub const FUSE_BIG_WRITES: u32 = 1 << 5;
    pub const FUSE_DONT_MASK: u32 = 1 << 6;
    pub const FUSE_SPLICE_WRITE: u32 = 1 << 7;
    pub const FUSE_SPLICE_MOVE: u32 = 1 << 8;
    pub const FUSE_SPLICE_READ: u32 = 1 << 9;
    pub const FUSE_FLOCK_LOCKS: u32 = 1 << 10;
    pub const FUSE_HAS_IOCTL_DIR: u32 = 1 << 11;
    pub const FUSE_AUTO_INVAL_DATA: u32 = 1 << 12;
    pub const FUSE_DO_READDIRPLUS: u32 = 1 << 13;
    pub const FUSE_READDIRPLUS_AUTO: u32 = 1 << 14;
    pub const FUSE_ASYNC_DIO: u32 = 1 << 15;
    pub const FUSE_WRITEBACK_CACHE: u32 = 1 << 16;
    pub const FUSE_NO_OPEN_SUPPORT: u32 = 1 << 17;
    pub const FUSE_PARALLEL_DIROPS: u32 = 1 << 18;
    pub const FUSE_HANDLE_KILLPRIV: u32 = 1 << 19;
    pub const FUSE_POSIX_ACL: u32 = 1 << 20;
    pub const FUSE_ABORT_ERROR: u32 = 1 << 21;
    pub const FUSE_MAX_PAGES: u32 = 1 << 22;
    pub const FUSE_CACHE_SYMLINKS: u32 = 1 << 23;
    pub const FUSE_NO_OPENDIR_SUPPORT: u32 = 1 << 24;
    pub const FUSE_EXPLICIT_INVAL_DATA: u32 = 1 << 25;
}

/// Capabilities the current daemon treats as required during INIT.
pub const TIDEFS_FUSE_INIT_REQUIRED_FLAGS: u32 = init_flags::FUSE_POSIX_ACL
    | init_flags::FUSE_PARALLEL_DIROPS
    | init_flags::FUSE_DO_READDIRPLUS
    | init_flags::FUSE_HANDLE_KILLPRIV;

/// Capabilities the current daemon requests opportunistically during INIT.
pub const TIDEFS_FUSE_INIT_BEST_EFFORT_FLAGS: u32 = init_flags::FUSE_WRITEBACK_CACHE
    | init_flags::FUSE_SPLICE_WRITE
    | init_flags::FUSE_SPLICE_MOVE
    | init_flags::FUSE_SPLICE_READ;

/// Full INIT capability request set used by the deterministic current-adapter plan.
pub const TIDEFS_FUSE_INIT_DEFAULT_WANTED_FLAGS: u32 = init_flags::FUSE_ASYNC_READ
    | init_flags::FUSE_BIG_WRITES
    | init_flags::FUSE_MAX_PAGES
    | TIDEFS_FUSE_INIT_REQUIRED_FLAGS
    | TIDEFS_FUSE_INIT_BEST_EFFORT_FLAGS;

/// Wire size of `struct fuse_interrupt_in`.
pub const FUSE_INTERRUPT_IN_WIRE_SIZE: usize = 8;

/// Minimum wire size of FUSE_LOOKUP name payload: one byte plus NUL.
pub const FUSE_LOOKUP_MIN_WIRE_SIZE: usize = 2;

/// Wire size of `struct fuse_forget_in`.
pub const FUSE_FORGET_IN_WIRE_SIZE: usize = 8;

/// Wire size of `struct fuse_batch_forget_in`.
pub const FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE: usize = 8;

/// Wire size of `struct fuse_forget_one`.
pub const FUSE_FORGET_ONE_WIRE_SIZE: usize = 16;

/// Wire size of `struct fuse_release_in`.
pub const FUSE_RELEASE_IN_WIRE_SIZE: usize = 24;

/// Wire size of `struct fuse_release_in`, reused by FUSE_RELEASEDIR.
pub const FUSE_RELEASEDIR_IN_WIRE_SIZE: usize = 24;

/// Wire size of `struct fuse_getattr_in`.
pub const FUSE_GETATTR_IN_WIRE_SIZE: usize = 16;

/// Linux FUSE_GETATTR flag indicating `fh` carries an open file handle.
pub const FUSE_GETATTR_FH: u32 = 1 << 0;

/// Wire size of `struct fuse_statx_in`.
pub const FUSE_STATX_IN_WIRE_SIZE: usize = 24;

/// Wire size of `struct fuse_statx_out` (kernel ABI, fuse_kernel.h).
pub const FUSE_STATX_OUT_WIRE_SIZE: usize = 288;

/// Wire size of `struct fuse_open_in`.
pub const FUSE_OPEN_IN_WIRE_SIZE: usize = 8;

/// Wire size of `struct fuse_open_in` for FUSE_OPENDIR.
pub const FUSE_OPENDIR_IN_WIRE_SIZE: usize = FUSE_OPEN_IN_WIRE_SIZE;

/// Wire size of FUSE_READLINK payload after `fuse_in_header`.
pub const FUSE_READLINK_IN_WIRE_SIZE: usize = 0;

/// Wire size of FUSE_TMPFILE payload after `fuse_in_header`.
pub const FUSE_TMPFILE_IN_WIRE_SIZE: usize = 0;

/// Wire size of FUSE_STATFS payload after `fuse_in_header`.
pub const FUSE_STATFS_IN_WIRE_SIZE: usize = 0;

/// Wire size of FUSE_DESTROY payload after `fuse_in_header`.
pub const FUSE_DESTROY_IN_WIRE_SIZE: usize = 0;

/// Wire size of FUSE_SYNCFS payload after `fuse_in_header`.
pub const FUSE_SYNCFS_IN_WIRE_SIZE: usize = 8;

/// Wire size of `struct fuse_setattr_in`.
pub const FUSE_SETATTR_IN_WIRE_SIZE: usize = 88;

/// Wire size of `struct fuse_link_in`, excluding the trailing nul-terminated name.
pub const FUSE_LINK_IN_WIRE_SIZE: usize = 8;

/// Fixed wire prefix size of `struct fuse_rename_in` before the two names.
pub const FUSE_RENAME_IN_WIRE_SIZE: usize = 8;

/// Fixed wire prefix size of `struct fuse_rename2_in` before the two names.
pub const FUSE_RENAME2_IN_WIRE_SIZE: usize = 16;

/// Maximum single FUSE path component length accepted by Linux.
pub const FUSE_NAME_MAX_BYTES: usize = 255;

/// Wire size of `struct fuse_setxattr_in`.
pub const FUSE_SETXATTR_IN_WIRE_SIZE: usize = 16;

/// Wire size of `struct fuse_getxattr_in`, also used by LISTXATTR.
pub const FUSE_GETXATTR_IN_WIRE_SIZE: usize = 8;

/// Wire size of `struct fuse_mkdir_in`.
pub const FUSE_MKDIR_IN_WIRE_SIZE: usize = 8;

/// Wire size of `struct fuse_create_in`.
pub const FUSE_CREATE_IN_WIRE_SIZE: usize = 16;

/// Wire size of `struct fuse_mknod_in`.
pub const FUSE_MKNOD_IN_WIRE_SIZE: usize = 16;

/// Wire size of `struct fuse_read_in`, used by READDIR and READDIRPLUS.
pub const FUSE_READDIR_IN_WIRE_SIZE: usize = 40;

/// Wire size of `struct fuse_read_in`.
pub const FUSE_READ_IN_WIRE_SIZE: usize = 40;

/// Wire size of `struct fuse_read_in`, used by FUSE_READDIRPLUS.
pub const FUSE_READDIRPLUS_IN_WIRE_SIZE: usize = FUSE_READDIR_IN_WIRE_SIZE;

/// Wire size of `struct fuse_fsync_in`.
pub const FUSE_FSYNC_IN_WIRE_SIZE: usize = 16;

/// Wire size of `struct fuse_fsync_in`, used by FSYNCDIR.
pub const FUSE_FSYNCDIR_IN_WIRE_SIZE: usize = 16;

/// Wire size of `struct fuse_bmap_in`.
pub const FUSE_BMAP_IN_WIRE_SIZE: usize = 16;

/// Minimum wire size of FUSE_RMDIR name payload: one byte plus NUL.
pub const FUSE_RMDIR_MIN_WIRE_SIZE: usize = 2;

/// Wire size of `struct fuse_access_in`.
pub const FUSE_ACCESS_IN_WIRE_SIZE: usize = 8;

/// Wire size of `struct fuse_flush_in`.
pub const FUSE_FLUSH_IN_WIRE_SIZE: usize = 24;

/// Wire size of `struct fuse_poll_in`.
pub const FUSE_POLL_IN_WIRE_SIZE: usize = 24;

/// Minimum wire size of FUSE_UNLINK name payload: one byte plus NUL.
pub const FUSE_UNLINK_MIN_WIRE_SIZE: usize = 2;

/// Wire size of `struct fuse_fallocate_in`.
pub const FUSE_FALLOCATE_IN_WIRE_SIZE: usize = 32;

/// Wire size of the fixed prefix of `struct fuse_ioctl_in`.
pub const FUSE_IOCTL_IN_WIRE_SIZE: usize = 24;

/// Wire size of `struct fuse_ioctl_in` when extended sizes are present.
pub const FUSE_IOCTL_IN_EXTENDED_WIRE_SIZE: usize = 32;

/// Wire size of `struct fuse_lseek_in`.
pub const FUSE_LSEEK_IN_WIRE_SIZE: usize = 24;

/// Wire size of `struct fuse_copy_file_range_in`.
pub const FUSE_COPY_FILE_RANGE_IN_WIRE_SIZE: usize = 56;

/// Wire size of `struct fuse_exchange_in` (olddir + newdir + options).
pub const FUSE_EXCHANGE_IN_WIRE_SIZE: usize = 24;

/// Wire size of `struct fuse_write_in`.
pub const FUSE_WRITE_IN_WIRE_SIZE: usize = 40;

/// Minimum variable payload size for FUSE_SYMLINK: name NUL plus target NUL.
pub const FUSE_SYMLINK_MIN_WIRE_SIZE: usize = 2;

/// Wire size of `struct fuse_lk_in`, used by GETLK, SETLK, and SETLKW.
pub const FUSE_GETLK_IN_WIRE_SIZE: usize = 48;
pub const FUSE_SETLK_IN_WIRE_SIZE: usize = FUSE_GETLK_IN_WIRE_SIZE;
pub const FUSE_SETLKW_IN_WIRE_SIZE: usize = FUSE_SETLK_IN_WIRE_SIZE;

/// Linux `fcntl(2)` lock types carried inside `struct fuse_file_lock`.
pub const FUSE_LK_TYPE_RDLCK: u32 = 0;
pub const FUSE_LK_TYPE_WRLCK: u32 = 1;
pub const FUSE_LK_TYPE_UNLCK: u32 = 2;

/// Linux `FUSE_LK_FLOCK` flag set in `lk_flags` when the lock request originates
/// from `flock(2)` rather than `fcntl(2)`.  The `owner` field carries the
/// open file description identity instead of a PID.
pub const FUSE_LK_FLOCK: u32 = 1;

/// Linux `fallocate(2)` flags carried by FUSE_FALLOCATE.
pub mod fallocate_flags {
    #[allow(unused_imports)]
    pub use tidefs_types_posix_filesystem_adapter_core::fallocate_flags::*;
}

/// Linux `lseek(2)` whence values carried by FUSE_LSEEK.
pub mod lseek_whence {
    #[allow(unused_imports)]
    pub use tidefs_types_posix_filesystem_adapter_core::lseek_whence::*;
}

/// Linux FUSE ioctl request flags carried by FUSE_IOCTL.
pub mod ioctl_flags {
    pub const FUSE_IOCTL_COMPAT: u32 = 1 << 0;
    pub const FUSE_IOCTL_UNRESTRICTED: u32 = 1 << 1;
    pub const FUSE_IOCTL_RETRY: u32 = 1 << 2;
    pub const FUSE_IOCTL_DIR: u32 = 1 << 4;
}

pub const FUSE_IOCTL_COMPAT: u32 = ioctl_flags::FUSE_IOCTL_COMPAT;
pub const FUSE_IOCTL_UNRESTRICTED: u32 = ioctl_flags::FUSE_IOCTL_UNRESTRICTED;
pub const FUSE_IOCTL_RETRY: u32 = ioctl_flags::FUSE_IOCTL_RETRY;
pub const FUSE_IOCTL_DIR: u32 = ioctl_flags::FUSE_IOCTL_DIR;
pub const FUSE_IOCTL_SUPPORTED_FLAGS: u32 =
    FUSE_IOCTL_COMPAT | FUSE_IOCTL_UNRESTRICTED | FUSE_IOCTL_RETRY | FUSE_IOCTL_DIR;

/// Linux FUSE write request flags carried by FUSE_WRITE.
pub mod write_flags {
    pub const FUSE_WRITE_LOCKOWNER: u32 = 1 << 1;
}

/// FUSE read flags carried by FUSE_READDIRPLUS.
pub mod readdirplus_read_flags {
    pub const FUSE_READ_LOCKOWNER: u32 = 1 << 1;
}

/// Linux FUSE fsync flags used by FSYNC and FSYNCDIR.
pub mod fsync_flags {
    pub const FUSE_FSYNC_FDATASYNC: u32 = 1 << 0;
}

/// Linux `STATX_*` mask bits from `include/uapi/linux/stat.h`.
/// These are used in the `stx_mask` field of the STATX reply to indicate
/// which fields are populated.
pub mod statx_mask {
    pub const STATX_TYPE: u32 = 0x0000_0001;
    pub const STATX_MODE: u32 = 0x0000_0002;
    pub const STATX_NLINK: u32 = 0x0000_0004;
    pub const STATX_UID: u32 = 0x0000_0008;
    pub const STATX_GID: u32 = 0x0000_0010;
    pub const STATX_ATIME: u32 = 0x0000_0020;
    pub const STATX_MTIME: u32 = 0x0000_0040;
    pub const STATX_CTIME: u32 = 0x0000_0080;
    pub const STATX_INO: u32 = 0x0000_0100;
    pub const STATX_SIZE: u32 = 0x0000_0200;
    pub const STATX_BLOCKS: u32 = 0x0000_0400;
    pub const STATX_BASIC_STATS: u32 = 0x0000_07ff;
    pub const STATX_BTIME: u32 = 0x0000_0800;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitNegotiationError {
    UnsupportedMajor {
        kernel_major: u32,
        supported_major: u32,
    },
    RequiredFlagsUnavailable {
        required: u32,
        available: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LookupRequestParseError {
    EmptyPayload,
    MissingNulTerminator,
    EmptyName,
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForgetRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchForgetRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
    EntryCountTooLarge { count: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GetattrRequestParseError {
    TooShort { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

impl core::fmt::Display for GetattrRequestParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort { required, actual } => write!(
                f,
                "FUSE_GETATTR payload too short: required {required} bytes, got {actual}"
            ),
            Self::TrailingBytes { expected, actual } => write!(
                f,
                "FUSE_GETATTR payload has trailing bytes: expected {expected} bytes, got {actual}"
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatxRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpendirRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleasedirRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadlinkRequestParseError {
    NonEmptyPayload { actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TmpfileRequestParseError {
    NonEmptyPayload { actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatfsRequestParseError {
    NonEmptyPayload { actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestroyRequestParseError {
    NonEmptyPayload { actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncfsRequestParseError {
    UnexpectedPayloadSize { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetattrRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
    InvalidPadding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    MissingNulTerminator,
    EmptyName,
    InvalidNameUtf8,
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenameRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
    EmptyOldName,
    EmptyNewName,
    NameTooLong { max: usize, actual: usize },
    MissingNulTerminator,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    MissingNulTerminator,
    EmptyName,
    ValueSizeMismatch { declared: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MkdirRequestParseError {
    PayloadTooShort { required: usize, actual: usize },
    NameNotNulTerminated,
    EmptyName,
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    MissingNulTerminator,
    EmptyName,
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MknodRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    MissingNulTerminator,
    EmptyName,
    InvalidPadding,
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnlinkRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    MissingNulTerminator,
    EmptyName,
    TrailingBytes { expected: usize, actual: usize },
}

impl core::fmt::Display for UnlinkRequestParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooSmall { required, actual } => write!(
                f,
                "FUSE_UNLINK payload too short: required {required} bytes, got {actual}"
            ),
            Self::MissingNulTerminator => {
                f.write_str("FUSE_UNLINK payload is missing NUL terminator")
            }
            Self::EmptyName => f.write_str("FUSE_UNLINK payload has an empty name"),
            Self::TrailingBytes { expected, actual } => write!(
                f,
                "FUSE_UNLINK payload has trailing bytes: expected {expected} bytes, got {actual}"
            ),
        }
    }
}

impl core::error::Error for UnlinkRequestParseError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RmdirRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    MissingNulTerminator,
    EmptyName,
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReaddirRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReaddirplusRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
    UnsupportedReadFlags { supported: u32, actual: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsyncRequestParseError {
    PayloadTooShort { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

impl core::fmt::Display for FsyncRequestParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PayloadTooShort { required, actual } => write!(
                f,
                "FUSE_FSYNC payload too short: required {required} bytes, got {actual}"
            ),
            Self::TrailingBytes { expected, actual } => write!(
                f,
                "FUSE_FSYNC payload has trailing bytes: expected {expected} bytes, got {actual}"
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsyncdirRequestParseError {
    PayloadTooShort { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

impl core::fmt::Display for FsyncdirRequestParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PayloadTooShort { required, actual } => write!(
                f,
                "FUSE_FSYNCDIR payload too short: required {required} bytes, got {actual}"
            ),
            Self::TrailingBytes { expected, actual } => write!(
                f,
                "FUSE_FSYNCDIR payload has trailing bytes: expected {expected} bytes, got {actual}"
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BmapRequestParseError {
    PayloadTooShort { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

impl core::fmt::Display for BmapRequestParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PayloadTooShort { required, actual } => write!(
                f,
                "FUSE_BMAP payload too short: required {required} bytes, got {actual}"
            ),
            Self::TrailingBytes { expected, actual } => write!(
                f,
                "FUSE_BMAP payload has trailing bytes: expected {expected} bytes, got {actual}"
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlushRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PollRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FallocateRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LseekRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
    InvalidPadding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoctlRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
    UnsupportedFlags { supported: u32, actual: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyFileRangeRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymlinkRequestParseError {
    TooShort { required: usize, actual: usize },
    InvalidName,
    MissingTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GetlkRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetlkRequestParseError {
    BufferTooSmall { required: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseInitRequest {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseInitNegotiationConfig {
    pub supported_major: u32,
    pub supported_minor: u32,
    pub required_flags: u32,
    pub wanted_flags: u32,
    pub max_readahead: u32,
    pub max_write: u32,
    pub max_background: u16,
    pub congestion_threshold: u16,
    pub time_gran: u32,
    pub max_pages: u16,
}

impl FuseInitNegotiationConfig {
    #[must_use]
    pub const fn current_adapter_defaults() -> Self {
        Self {
            supported_major: FUSE_INIT_SUPPORTED_MAJOR,
            supported_minor: FUSE_INIT_SUPPORTED_MINOR,
            required_flags: TIDEFS_FUSE_INIT_REQUIRED_FLAGS,
            wanted_flags: TIDEFS_FUSE_INIT_DEFAULT_WANTED_FLAGS,
            max_readahead: FUSE_INIT_DEFAULT_MAX_READAHEAD,
            max_write: FUSE_INIT_DEFAULT_MAX_WRITE,
            max_background: FUSE_INIT_DEFAULT_MAX_BACKGROUND,
            congestion_threshold: FUSE_INIT_DEFAULT_CONGESTION_THRESHOLD,
            time_gran: FUSE_INIT_DEFAULT_TIME_GRAN_NS,
            max_pages: FUSE_INIT_DEFAULT_MAX_PAGES,
        }
    }
}

impl Default for FuseInitNegotiationConfig {
    fn default() -> Self {
        Self::current_adapter_defaults()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseInitReplyPlan {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub max_background: u16,
    pub congestion_threshold: u16,
    pub max_write: u32,
    pub time_gran: u32,
    pub max_pages: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseInterruptRequest {
    pub unique: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseLookupRequest<'a> {
    pub parent: u64,
    pub name: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseForgetRequest {
    pub nlookup: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseForgetOneEntry {
    pub nodeid: u64,
    pub nlookup: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FuseBatchForgetRequest {
    pub entries: Vec<FuseForgetOneEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseGetattrRequest {
    pub getattr_flags: u32,
    pub fh: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseStatxRequest {
    pub getattr_flags: u32,
    pub reserved: u32,
    pub fh: u64,
    pub sx_flags: u32,
    pub sx_mask: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseOpenRequest {
    pub flags: u32,
    pub padding: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseOpendirRequest {
    pub flags: u32,
    pub padding: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseReleaseRequest {
    pub fh: u64,
    pub flags: u32,
    pub release_flags: u32,
    pub lock_owner: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseReleasedirRequest {
    pub fh: u64,
    pub flags: u32,
    pub release_flags: u32,
    pub lock_owner: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseReadlinkRequest {
    pub nodeid: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseTmpfileRequest {
    pub nodeid: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseStatfsRequest;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseDestroyRequest;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseSyncfsRequest;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseSetattrRequest {
    pub valid: u32,
    pub fh: u64,
    pub size: u64,
    pub lock_owner: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseLinkRequest<'a> {
    pub olobject_nodeid: u64,
    pub name: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseRenameRequest<'a> {
    pub newdir: u64,
    pub flags: u32,
    pub old_name: &'a [u8],
    pub new_name: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseSetxattrRequest<'a> {
    pub size: u32,
    pub flags: u32,
    pub setxattr_flags: u32,
    pub name: &'a [u8],
    pub value: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseGetxattrRequest<'a> {
    pub size: u32,
    pub name: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseListxattrRequest {
    pub size: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseRemovexattrRequest<'a> {
    pub name: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseMkdirRequest<'a> {
    pub mode: u32,
    pub umask: u32,
    pub name: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseCreateRequest<'a> {
    pub flags: u32,
    pub mode: u32,
    pub umask: u32,
    pub open_flags: u32,
    pub name: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseMknodRequest<'a> {
    pub parent: u64,
    pub mode: u32,
    pub rdev: u32,
    pub umask: u32,
    pub name: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseUnlinkRequest<'a> {
    pub parent: u64,
    pub name: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseRmdirRequest<'a> {
    pub parent: u64,
    pub name: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseAccessRequest {
    pub mask: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseReaddirRequest {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub read_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseReadRequest {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub read_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseReaddirplusRequest {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub read_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseFsyncRequest {
    pub fh: u64,
    pub fsync_flags: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseFsyncdirRequest {
    pub fh: u64,
    pub fsync_flags: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseBmapRequest {
    pub block: u64,
    pub blocksize: u32,
    pub padding: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseFlushRequest {
    pub fh: u64,
    pub unused: u32,
    pub padding: u32,
    pub lock_owner: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FusePollRequest {
    pub fh: u64,
    pub kh: u64,
    pub flags: u32,
    pub events: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseSymlinkRequest<'a> {
    pub name: &'a [u8],
    pub target: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseFallocateRequest {
    pub fh: u64,
    pub offset: u64,
    pub length: u64,
    pub mode: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseLseekRequest {
    pub fh: u64,
    pub offset: u64,
    pub whence: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseIoctlRequest {
    pub fh: u64,
    pub flags: u32,
    pub cmd: u32,
    pub arg: u64,
    pub in_size: u32,
    pub out_size: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseCopyFileRangeRequest {
    pub fh_in: u64,
    pub off_in: u64,
    /// Destination inode. The source inode is carried by `fuse_in_header.nodeid`.
    pub nodeid_out: u64,
    pub fh_out: u64,
    pub off_out: u64,
    pub len: u64,
    pub flags: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseWriteRequest<'a> {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub write_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
    pub data: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseLockIn {
    pub start: u64,
    pub end: u64,
    pub typ: u32,
    pub pid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseGetlkRequest {
    pub fh: u64,
    pub owner: u64,
    pub lk: FuseLockIn,
    pub lk_flags: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseSetlkRequest {
    pub fh: u64,
    pub owner: u64,
    pub lk: FuseLockIn,
    pub lk_flags: u32,
    pub sleep: bool,
}

// ── FIEMAP ioctl types ─────────────────────────────────────────────────────

/// Linux `FS_IOC_FIEMAP` ioctl command value.
pub const FS_IOC_FIEMAP: u32 = 0xC020_660B;

/// Linux `FS_IOC_FSGETXATTR` ioctl command value.
pub const FS_IOC_FSGETXATTR: u32 = 0x801C_581F;

/// Linux `FS_IOC_FSSETXATTR` ioctl command value.
pub const FS_IOC_FSSETXATTR: u32 = 0x401C_5820;

/// Linux `FIFREEZE` ioctl command value.
pub const FS_IOC_FREEZE: u32 = 0xC004_5877;

/// Linux `FITHAW` ioctl command value.
pub const FS_IOC_THAW: u32 = 0xC004_5878;

/// Wire size of `struct fsxattr`.
pub const FSXATTR_WIRE_SIZE: usize = 28;

/// Response for Linux `struct fsxattr`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsxattrOutput {
    pub fsx_xflags: u32,
    pub fsx_extsize: u32,
    pub fsx_nextents: u32,
    pub fsx_projid: u32,
    pub fsx_cowextsize: u32,
}

impl FsxattrOutput {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            fsx_xflags: 0,
            fsx_extsize: 0,
            fsx_nextents: 0,
            fsx_projid: 0,
            fsx_cowextsize: 0,
        }
    }

    #[must_use]
    pub fn encode(&self) -> std::vec::Vec<u8> {
        let mut buf = std::vec::Vec::with_capacity(FSXATTR_WIRE_SIZE);
        buf.extend_from_slice(&self.fsx_xflags.to_le_bytes());
        buf.extend_from_slice(&self.fsx_extsize.to_le_bytes());
        buf.extend_from_slice(&self.fsx_nextents.to_le_bytes());
        buf.extend_from_slice(&self.fsx_projid.to_le_bytes());
        buf.extend_from_slice(&self.fsx_cowextsize.to_le_bytes());
        buf.extend_from_slice(&[0u8; 8]);
        buf
    }
}

/// Wire size of a `struct fiemap` header.
pub const FIEMAP_HEADER_SIZE: usize = 32;

/// Wire size of a `struct fiemap_extent`.
pub const FIEMAP_EXTENT_SIZE: usize = 56;

/// Re-export `FiemapExtent` so adapter code can use it directly.
#[allow(unused_imports)]
pub use tidefs_types_extent_map_core::FiemapExtent;

/// FIEMAP request decoded from the FUSE ioctl input buffer.
///
/// Fields correspond to `struct fiemap` from `<linux/fiemap.h>`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FiemapInput {
    /// Logical offset (inclusive) in bytes to start mapping.
    pub fm_start: u64,
    /// Length in bytes of the mapping range.
    pub fm_length: u64,
    /// FIEMAP flags (e.g. `FIEMAP_FLAG_SYNC`).
    pub fm_flags: u32,
    /// Number of extents requested (0 = query only, reports count).
    pub fm_extent_count: u32,
}

/// Decode a `FiemapInput` from the FUSE ioctl input buffer.
///
/// Returns `None` if the buffer is smaller than [`FIEMAP_HEADER_SIZE`].
#[must_use]
pub fn parse_fiemap_input(data: &[u8]) -> Option<FiemapInput> {
    if data.len() < FIEMAP_HEADER_SIZE {
        return None;
    }
    Some(FiemapInput {
        fm_start: u64::from_le_bytes(data[0..8].try_into().unwrap()),
        fm_length: u64::from_le_bytes(data[8..16].try_into().unwrap()),
        fm_flags: u32::from_le_bytes(data[16..20].try_into().unwrap()),
        fm_extent_count: u32::from_le_bytes(data[24..28].try_into().unwrap()),
    })
}

/// FIEMAP response ready for wire encoding.
#[derive(Clone, Debug)]
pub struct FiemapOutput {
    /// The total number of extents mapped (may exceed `extents.len()`).
    pub fm_mapped_extents: u32,
    /// The extent descriptors to encode.
    pub extents: std::vec::Vec<FiemapExtent>,
}

impl FiemapOutput {
    /// Encode the FIEMAP response into a wire buffer.
    ///
    /// The returned buffer contains the `struct fiemap` header followed by
    /// `extents.len()` `struct fiemap_extent` records in little-endian order.
    #[must_use]
    pub fn encode(&self, fm_start: u64, fm_length: u64, fm_flags: u32) -> std::vec::Vec<u8> {
        let mut buf = std::vec::Vec::with_capacity(
            FIEMAP_HEADER_SIZE + FIEMAP_EXTENT_SIZE * self.extents.len(),
        );
        // struct fiemap header
        buf.extend_from_slice(&fm_start.to_le_bytes());
        buf.extend_from_slice(&fm_length.to_le_bytes());
        buf.extend_from_slice(&fm_flags.to_le_bytes());
        buf.extend_from_slice(&self.fm_mapped_extents.to_le_bytes());
        buf.extend_from_slice(
            &u32::try_from(self.extents.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
                                                    // struct fiemap_extent[]
        for ext in &self.extents {
            buf.extend_from_slice(&ext.fe_logical.to_le_bytes());
            buf.extend_from_slice(&ext.fe_physical.to_le_bytes());
            buf.extend_from_slice(&ext.fe_length.to_le_bytes());
            buf.extend_from_slice(&[0u8; 16]); // reserved[2]
            buf.extend_from_slice(&ext.fe_flags.to_le_bytes());
            buf.extend_from_slice(&[0u8; 12]); // reserved[3]
        }
        buf
    }
}

// ── Defrag ioctl types ─────────────────────────────────────────────────────

/// TideFS `TIDEFS_IOC_DEFRAG` ioctl command value.
///
/// Triggers online extent map defragmentation for the inode specified
/// in the input buffer. Returns fragmentation statistics.
pub const TIDEFS_IOC_DEFRAG: u32 = 0xC020_660C;

/// Wire size of the defrag ioctl input buffer (target inode + flags).
pub const DEFRAG_IOCTL_INPUT_SIZE: usize = 16;

/// Wire size of the defrag ioctl output buffer.
pub const DEFRAG_IOCTL_OUTPUT_SIZE: usize = 24;

/// Defrag ioctl request decoded from the FUSE ioctl input buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DefragIoctlInput {
    /// Target inode number. 0 means "defrag all inodes".
    pub ino: u64,
    /// Flags: bit 0 = recursive (defrag all inodes under a directory).
    pub flags: u64,
}

/// Decode a [`DefragIoctlInput`] from the FUSE ioctl input buffer.
///
/// Returns `None` if the buffer is smaller than [`DEFRAG_IOCTL_INPUT_SIZE`].
#[must_use]
pub fn parse_defrag_input(data: &[u8]) -> Option<DefragIoctlInput> {
    if data.len() < DEFRAG_IOCTL_INPUT_SIZE {
        return None;
    }
    Some(DefragIoctlInput {
        ino: u64::from_le_bytes(data[0..8].try_into().unwrap()),
        flags: u64::from_le_bytes(data[8..16].try_into().unwrap()),
    })
}

/// Defrag ioctl response ready for wire encoding.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct DefragIoctlOutput {
    /// Total extent count before defrag.
    pub extents_before: u64,
    /// Total extent count after defrag.
    pub extents_after: u64,
    /// Fragmentation reduction as a percentage (0.0–100.0), encoded as a
    /// fixed-point u32 with 2 decimal places (e.g. 4025 = 40.25%).
    pub fragmentation_reduction_pct: u32,
    /// Number of inodes defragmented.
    pub inodes_defragmented: u64,
}

impl DefragIoctlOutput {
    /// Encode the defrag response into a wire buffer.
    ///
    /// Layout (24 bytes, little-endian):
    /// - `extents_before`   (u64 at offset 0)
    /// - `extents_after`    (u64 at offset 8)
    /// - `frag_reduction`   (u32 at offset 16)
    /// - `inodes_defragged` (u32 at offset 20) — stored as u32 for wire
    ///   compactness; wraps at 4B.
    #[must_use]
    pub fn encode(&self) -> std::vec::Vec<u8> {
        let mut buf = std::vec::Vec::with_capacity(DEFRAG_IOCTL_OUTPUT_SIZE);
        buf.extend_from_slice(&self.extents_before.to_le_bytes());
        buf.extend_from_slice(&self.extents_after.to_le_bytes());
        buf.extend_from_slice(&self.fragmentation_reduction_pct.to_le_bytes());
        let inodes = u32::try_from(self.inodes_defragmented).unwrap_or(u32::MAX);
        buf.extend_from_slice(&inodes.to_le_bytes());
        buf
    }
}

#[must_use]
fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[must_use]
fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[must_use]
fn min_u32(left: u32, right: u32) -> u32 {
    if left < right {
        left
    } else {
        right
    }
}

#[must_use]
fn clamp_u32(value: u32, minimum: u32, maximum: u32) -> u32 {
    if value < minimum {
        minimum
    } else if value > maximum {
        maximum
    } else {
        value
    }
}

#[must_use]
fn at_least_one_u16(value: u16) -> u16 {
    if value == 0 {
        1
    } else {
        value
    }
}

#[must_use]
fn bounded_congestion_threshold(value: u16, max_background: u16) -> u16 {
    if max_background == 0 {
        0
    } else if value == 0 {
        1
    } else if value > max_background {
        max_background
    } else {
        value
    }
}

fn find_nul_terminator(bytes: &[u8]) -> Option<usize> {
    bytes.iter().position(|byte| *byte == 0)
}

fn split_nul_terminated_name(bytes: &[u8]) -> Result<(&[u8], &[u8]), XattrRequestParseError> {
    let Some(index) = find_nul_terminator(bytes) else {
        return Err(XattrRequestParseError::MissingNulTerminator);
    };
    if index == 0 {
        return Err(XattrRequestParseError::EmptyName);
    }
    Ok((&bytes[..index], &bytes[index + 1..]))
}

fn split_link_name(bytes: &[u8]) -> Result<(&str, &[u8]), LinkRequestParseError> {
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == 0 {
            if index == 0 {
                return Err(LinkRequestParseError::EmptyName);
            }
            let name = core::str::from_utf8(&bytes[..index])
                .map_err(|_| LinkRequestParseError::InvalidNameUtf8)?;
            return Ok((name, &bytes[index + 1..]));
        }
    }
    Err(LinkRequestParseError::MissingNulTerminator)
}

fn split_rename_name(
    bytes: &[u8],
    empty_error: RenameRequestParseError,
) -> Result<(&[u8], &[u8]), RenameRequestParseError> {
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == 0 {
            if index == 0 {
                return Err(empty_error);
            }
            if index > FUSE_NAME_MAX_BYTES {
                return Err(RenameRequestParseError::NameTooLong {
                    max: FUSE_NAME_MAX_BYTES,
                    actual: index,
                });
            }
            return Ok((&bytes[..index], &bytes[index + 1..]));
        }
    }
    Err(RenameRequestParseError::MissingNulTerminator)
}

fn split_rename_names(
    payload: &[u8],
    fixed_header_size: usize,
) -> Result<(&[u8], &[u8]), RenameRequestParseError> {
    let names = &payload[fixed_header_size..];
    let (old_name, trailing) = split_rename_name(names, RenameRequestParseError::EmptyOldName)?;
    let (new_name, trailing) = split_rename_name(trailing, RenameRequestParseError::EmptyNewName)?;
    if !trailing.is_empty() {
        return Err(RenameRequestParseError::TrailingBytes {
            expected: payload.len() - trailing.len(),
            actual: payload.len(),
        });
    }
    Ok((old_name, new_name))
}

fn parse_mkdir_name(payload: &[u8]) -> Result<&[u8], MkdirRequestParseError> {
    let name_bytes = &payload[FUSE_MKDIR_IN_WIRE_SIZE..];
    let Some(index) = find_nul_terminator(name_bytes) else {
        return Err(MkdirRequestParseError::NameNotNulTerminated);
    };
    if index == 0 {
        return Err(MkdirRequestParseError::EmptyName);
    }

    let trailing_start = FUSE_MKDIR_IN_WIRE_SIZE + index + 1;
    if trailing_start != payload.len() {
        return Err(MkdirRequestParseError::TrailingBytes {
            expected: trailing_start,
            actual: payload.len(),
        });
    }

    Ok(&name_bytes[..index])
}

fn parse_create_name(payload: &[u8]) -> Result<&[u8], CreateRequestParseError> {
    let name_bytes = &payload[FUSE_CREATE_IN_WIRE_SIZE..];
    let Some(index) = find_nul_terminator(name_bytes) else {
        return Err(CreateRequestParseError::MissingNulTerminator);
    };
    if index == 0 {
        return Err(CreateRequestParseError::EmptyName);
    }

    let trailing_start = FUSE_CREATE_IN_WIRE_SIZE + index + 1;
    if trailing_start != payload.len() {
        return Err(CreateRequestParseError::TrailingBytes {
            expected: trailing_start,
            actual: payload.len(),
        });
    }

    Ok(&name_bytes[..index])
}

fn parse_mknod_name(payload: &[u8]) -> Result<&[u8], MknodRequestParseError> {
    let name_bytes = &payload[FUSE_MKNOD_IN_WIRE_SIZE..];
    let Some(index) = find_nul_terminator(name_bytes) else {
        return Err(MknodRequestParseError::MissingNulTerminator);
    };
    if index == 0 {
        return Err(MknodRequestParseError::EmptyName);
    }

    let trailing_start = FUSE_MKNOD_IN_WIRE_SIZE + index + 1;
    if trailing_start != payload.len() {
        return Err(MknodRequestParseError::TrailingBytes {
            expected: trailing_start,
            actual: payload.len(),
        });
    }

    Ok(&name_bytes[..index])
}

#[must_use]
fn split_nul_terminated_symlink_component(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == 0 {
            return Some((&bytes[..index], &bytes[index + 1..]));
        }
    }

    None
}

fn parse_fuse_lock(payload: &[u8], offset: usize) -> FuseLockIn {
    FuseLockIn {
        start: read_u64_le(payload, offset),
        end: read_u64_le(payload, offset + 8),
        typ: read_u32_le(payload, offset + 16),
        pid: read_u32_le(payload, offset + 20),
    }
}

#[must_use]
fn parse_fuse_lk_payload(payload: &[u8]) -> (u64, u64, FuseLockIn, u32) {
    (
        read_u64_le(payload, 0),
        read_u64_le(payload, 8),
        parse_fuse_lock(payload, 16),
        read_u32_le(payload, 40),
    )
}

/// Parse the payload after `fuse_in_header` for FUSE_INIT.
pub fn parse_fuse_init_request(payload: &[u8]) -> Result<FuseInitRequest, InitRequestParseError> {
    if payload.len() < FUSE_INIT_IN_WIRE_SIZE {
        return Err(InitRequestParseError::BufferTooSmall {
            required: FUSE_INIT_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseInitRequest {
        major: read_u32_le(payload, 0),
        minor: read_u32_le(payload, 4),
        max_readahead: read_u32_le(payload, 8),
        flags: read_u32_le(payload, 12),
    })
}

/// Plan a deterministic FUSE_INIT reply from a parsed kernel request.
pub fn plan_fuse_init_reply(
    request: FuseInitRequest,
    config: FuseInitNegotiationConfig,
) -> Result<FuseInitReplyPlan, InitNegotiationError> {
    if request.major != config.supported_major {
        return Err(InitNegotiationError::UnsupportedMajor {
            kernel_major: request.major,
            supported_major: config.supported_major,
        });
    }

    let available_required = request.flags & config.required_flags;
    if available_required != config.required_flags {
        return Err(InitNegotiationError::RequiredFlagsUnavailable {
            required: config.required_flags,
            available: available_required,
        });
    }

    let flags = request.flags & (config.required_flags | config.wanted_flags);
    let max_pages = if flags & init_flags::FUSE_MAX_PAGES == 0 {
        0
    } else {
        at_least_one_u16(config.max_pages)
    };

    Ok(FuseInitReplyPlan {
        major: config.supported_major,
        minor: min_u32(request.minor, config.supported_minor),
        max_readahead: min_u32(request.max_readahead, config.max_readahead),
        flags,
        max_background: config.max_background,
        congestion_threshold: bounded_congestion_threshold(
            config.congestion_threshold,
            config.max_background,
        ),
        max_write: clamp_u32(
            config.max_write,
            FUSE_INIT_MIN_MAX_WRITE,
            FUSE_INIT_MAX_WRITE_LIMIT,
        ),
        time_gran: if config.time_gran == 0 {
            1
        } else {
            config.time_gran
        },
        max_pages,
    })
}

/// Plan the current userspace adapter's deterministic FUSE_INIT reply.
pub fn plan_current_adapter_fuse_init_reply(
    request: FuseInitRequest,
) -> Result<FuseInitReplyPlan, InitNegotiationError> {
    plan_fuse_init_reply(
        request,
        FuseInitNegotiationConfig::current_adapter_defaults(),
    )
}

/// Parse the payload after `fuse_in_header` for FUSE_INTERRUPT.
pub fn parse_fuse_interrupt_request(
    payload: &[u8],
) -> Result<FuseInterruptRequest, InterruptRequestParseError> {
    if payload.len() < FUSE_INTERRUPT_IN_WIRE_SIZE {
        return Err(InterruptRequestParseError::BufferTooSmall {
            required: FUSE_INTERRUPT_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_INTERRUPT_IN_WIRE_SIZE {
        return Err(InterruptRequestParseError::TrailingBytes {
            expected: FUSE_INTERRUPT_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseInterruptRequest {
        unique: read_u64_le(payload, 0),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_LOOKUP.
pub fn parse_fuse_lookup_request(
    parent: u64,
    payload: &[u8],
) -> Result<FuseLookupRequest<'_>, LookupRequestParseError> {
    if payload.is_empty() {
        return Err(LookupRequestParseError::EmptyPayload);
    }

    let Some(nul_index) = find_nul_terminator(payload) else {
        return Err(LookupRequestParseError::MissingNulTerminator);
    };
    if nul_index == 0 {
        return Err(LookupRequestParseError::EmptyName);
    }

    let trailing_start = nul_index + 1;
    if trailing_start != payload.len() {
        return Err(LookupRequestParseError::TrailingBytes {
            expected: trailing_start,
            actual: payload.len(),
        });
    }

    Ok(FuseLookupRequest {
        parent,
        name: &payload[..nul_index],
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_FORGET.
pub fn parse_fuse_forget_request(
    payload: &[u8],
) -> Result<FuseForgetRequest, ForgetRequestParseError> {
    if payload.len() < FUSE_FORGET_IN_WIRE_SIZE {
        return Err(ForgetRequestParseError::BufferTooSmall {
            required: FUSE_FORGET_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_FORGET_IN_WIRE_SIZE {
        return Err(ForgetRequestParseError::TrailingBytes {
            expected: FUSE_FORGET_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseForgetRequest {
        nlookup: read_u64_le(payload, 0),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_BATCH_FORGET.
pub fn parse_fuse_batch_forget_request(
    payload: &[u8],
) -> Result<FuseBatchForgetRequest, BatchForgetRequestParseError> {
    if payload.len() < FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE {
        return Err(BatchForgetRequestParseError::BufferTooSmall {
            required: FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE,
            actual: payload.len(),
        });
    }

    let count = read_u32_le(payload, 0);
    let entries_len = (count as usize)
        .checked_mul(FUSE_FORGET_ONE_WIRE_SIZE)
        .ok_or(BatchForgetRequestParseError::EntryCountTooLarge { count })?;
    let expected_len = FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE
        .checked_add(entries_len)
        .ok_or(BatchForgetRequestParseError::EntryCountTooLarge { count })?;

    if payload.len() < expected_len {
        return Err(BatchForgetRequestParseError::BufferTooSmall {
            required: expected_len,
            actual: payload.len(),
        });
    }
    if payload.len() != expected_len {
        return Err(BatchForgetRequestParseError::TrailingBytes {
            expected: expected_len,
            actual: payload.len(),
        });
    }

    let mut entries = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let offset = FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE + index * FUSE_FORGET_ONE_WIRE_SIZE;
        entries.push(FuseForgetOneEntry {
            nodeid: read_u64_le(payload, offset),
            nlookup: read_u64_le(payload, offset + 8),
        });
    }

    Ok(FuseBatchForgetRequest { entries })
}

/// Parse the payload after `fuse_in_header` for FUSE_GETATTR.
pub fn parse_fuse_getattr_request(
    payload: &[u8],
) -> Result<FuseGetattrRequest, GetattrRequestParseError> {
    if payload.len() < FUSE_GETATTR_IN_WIRE_SIZE {
        return Err(GetattrRequestParseError::TooShort {
            required: FUSE_GETATTR_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_GETATTR_IN_WIRE_SIZE {
        return Err(GetattrRequestParseError::TrailingBytes {
            expected: FUSE_GETATTR_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseGetattrRequest {
        getattr_flags: read_u32_le(payload, 0),
        fh: read_u64_le(payload, 8),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_STATX.
pub fn parse_fuse_statx_request(
    payload: &[u8],
) -> Result<FuseStatxRequest, StatxRequestParseError> {
    if payload.len() < FUSE_STATX_IN_WIRE_SIZE {
        return Err(StatxRequestParseError::BufferTooSmall {
            required: FUSE_STATX_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_STATX_IN_WIRE_SIZE {
        return Err(StatxRequestParseError::TrailingBytes {
            expected: FUSE_STATX_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseStatxRequest {
        getattr_flags: read_u32_le(payload, 0),
        reserved: read_u32_le(payload, 4),
        fh: read_u64_le(payload, 8),
        sx_flags: read_u32_le(payload, 16),
        sx_mask: read_u32_le(payload, 20),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_OPEN.
pub fn parse_fuse_open_request(payload: &[u8]) -> Result<FuseOpenRequest, OpenRequestParseError> {
    if payload.len() < FUSE_OPEN_IN_WIRE_SIZE {
        return Err(OpenRequestParseError::BufferTooSmall {
            required: FUSE_OPEN_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_OPEN_IN_WIRE_SIZE {
        return Err(OpenRequestParseError::TrailingBytes {
            expected: FUSE_OPEN_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseOpenRequest {
        flags: read_u32_le(payload, 0),
        padding: read_u32_le(payload, 4),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_OPENDIR.
pub fn parse_fuse_opendir_request(
    payload: &[u8],
) -> Result<FuseOpendirRequest, OpendirRequestParseError> {
    if payload.len() < FUSE_OPENDIR_IN_WIRE_SIZE {
        return Err(OpendirRequestParseError::BufferTooSmall {
            required: FUSE_OPENDIR_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_OPENDIR_IN_WIRE_SIZE {
        return Err(OpendirRequestParseError::TrailingBytes {
            expected: FUSE_OPENDIR_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseOpendirRequest {
        flags: read_u32_le(payload, 0),
        padding: read_u32_le(payload, 4),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_RELEASE.
pub fn parse_fuse_release_request(
    payload: &[u8],
) -> Result<FuseReleaseRequest, ReleaseRequestParseError> {
    if payload.len() < FUSE_RELEASE_IN_WIRE_SIZE {
        return Err(ReleaseRequestParseError::BufferTooSmall {
            required: FUSE_RELEASE_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_RELEASE_IN_WIRE_SIZE {
        return Err(ReleaseRequestParseError::TrailingBytes {
            expected: FUSE_RELEASE_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseReleaseRequest {
        fh: read_u64_le(payload, 0),
        flags: read_u32_le(payload, 8),
        release_flags: read_u32_le(payload, 12),
        lock_owner: read_u64_le(payload, 16),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_RELEASEDIR.
pub fn parse_fuse_releasedir_request(
    payload: &[u8],
) -> Result<FuseReleasedirRequest, ReleasedirRequestParseError> {
    if payload.len() < FUSE_RELEASEDIR_IN_WIRE_SIZE {
        return Err(ReleasedirRequestParseError::BufferTooSmall {
            required: FUSE_RELEASEDIR_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_RELEASEDIR_IN_WIRE_SIZE {
        return Err(ReleasedirRequestParseError::TrailingBytes {
            expected: FUSE_RELEASEDIR_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseReleasedirRequest {
        fh: read_u64_le(payload, 0),
        flags: read_u32_le(payload, 8),
        release_flags: read_u32_le(payload, 12),
        lock_owner: read_u64_le(payload, 16),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_READLINK.
pub fn parse_fuse_readlink_request(
    payload: &[u8],
    nodeid: u64,
) -> Result<FuseReadlinkRequest, ReadlinkRequestParseError> {
    if payload.len() != FUSE_READLINK_IN_WIRE_SIZE {
        return Err(ReadlinkRequestParseError::NonEmptyPayload {
            actual: payload.len(),
        });
    }

    Ok(FuseReadlinkRequest { nodeid })
}

/// Parse the payload after `fuse_in_header` for FUSE_TMPFILE.
pub fn parse_fuse_tmpfile_request(
    payload: &[u8],
    nodeid: u64,
) -> Result<FuseTmpfileRequest, TmpfileRequestParseError> {
    if payload.len() != FUSE_TMPFILE_IN_WIRE_SIZE {
        return Err(TmpfileRequestParseError::NonEmptyPayload {
            actual: payload.len(),
        });
    }

    Ok(FuseTmpfileRequest { nodeid })
}

/// Parse the payload after `fuse_in_header` for FUSE_STATFS.
pub fn parse_fuse_statfs_request(
    payload: &[u8],
) -> Result<FuseStatfsRequest, StatfsRequestParseError> {
    if payload.len() != FUSE_STATFS_IN_WIRE_SIZE {
        return Err(StatfsRequestParseError::NonEmptyPayload {
            actual: payload.len(),
        });
    }

    Ok(FuseStatfsRequest)
}

/// Parse the payload after `fuse_in_header` for FUSE_DESTROY.
pub fn parse_fuse_destroy_request(
    payload: &[u8],
) -> Result<FuseDestroyRequest, DestroyRequestParseError> {
    if payload.len() != FUSE_DESTROY_IN_WIRE_SIZE {
        return Err(DestroyRequestParseError::NonEmptyPayload {
            actual: payload.len(),
        });
    }

    Ok(FuseDestroyRequest)
}

/// Parse the payload after `fuse_in_header` for FUSE_SYNCFS.
pub fn parse_fuse_syncfs_request(
    payload: &[u8],
) -> Result<FuseSyncfsRequest, SyncfsRequestParseError> {
    if payload.len() != FUSE_SYNCFS_IN_WIRE_SIZE {
        return Err(SyncfsRequestParseError::UnexpectedPayloadSize {
            expected: FUSE_SYNCFS_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseSyncfsRequest)
}

/// Parse the payload after `fuse_in_header` for FUSE_SETATTR.
pub fn parse_fuse_setattr_request(
    payload: &[u8],
) -> Result<FuseSetattrRequest, SetattrRequestParseError> {
    if payload.len() < FUSE_SETATTR_IN_WIRE_SIZE {
        return Err(SetattrRequestParseError::BufferTooSmall {
            required: FUSE_SETATTR_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_SETATTR_IN_WIRE_SIZE {
        return Err(SetattrRequestParseError::TrailingBytes {
            expected: FUSE_SETATTR_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    if read_u32_le(payload, 4) != 0
        || read_u32_le(payload, 72) != 0
        || read_u32_le(payload, 84) != 0
    {
        return Err(SetattrRequestParseError::InvalidPadding);
    }

    Ok(FuseSetattrRequest {
        valid: read_u32_le(payload, 0),
        fh: read_u64_le(payload, 8),
        size: read_u64_le(payload, 16),
        lock_owner: read_u64_le(payload, 24),
        atime: read_u64_le(payload, 32),
        mtime: read_u64_le(payload, 40),
        ctime: read_u64_le(payload, 48),
        atimensec: read_u32_le(payload, 56),
        mtimensec: read_u32_le(payload, 60),
        ctimensec: read_u32_le(payload, 64),
        mode: read_u32_le(payload, 68),
        uid: read_u32_le(payload, 76),
        gid: read_u32_le(payload, 80),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_LINK.
pub fn parse_fuse_link_request(
    payload: &[u8],
) -> Result<FuseLinkRequest<'_>, LinkRequestParseError> {
    if payload.len() < FUSE_LINK_IN_WIRE_SIZE {
        return Err(LinkRequestParseError::BufferTooSmall {
            required: FUSE_LINK_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    let olobject_nodeid = read_u64_le(payload, 0);
    let (name, trailing) = split_link_name(&payload[FUSE_LINK_IN_WIRE_SIZE..])?;
    if !trailing.is_empty() {
        return Err(LinkRequestParseError::TrailingBytes {
            expected: payload.len() - trailing.len(),
            actual: payload.len(),
        });
    }

    Ok(FuseLinkRequest {
        olobject_nodeid,
        name,
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_RENAME.
pub fn parse_fuse_rename_request(
    payload: &[u8],
) -> Result<FuseRenameRequest<'_>, RenameRequestParseError> {
    if payload.len() < FUSE_RENAME_IN_WIRE_SIZE {
        return Err(RenameRequestParseError::BufferTooSmall {
            required: FUSE_RENAME_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    let (old_name, new_name) = split_rename_names(payload, FUSE_RENAME_IN_WIRE_SIZE)?;
    Ok(FuseRenameRequest {
        newdir: read_u64_le(payload, 0),
        flags: 0,
        old_name,
        new_name,
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_RENAME2.
pub fn parse_fuse_rename2_request(
    payload: &[u8],
) -> Result<FuseRenameRequest<'_>, RenameRequestParseError> {
    if payload.len() < FUSE_RENAME2_IN_WIRE_SIZE {
        return Err(RenameRequestParseError::BufferTooSmall {
            required: FUSE_RENAME2_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    let (old_name, new_name) = split_rename_names(payload, FUSE_RENAME2_IN_WIRE_SIZE)?;
    Ok(FuseRenameRequest {
        newdir: read_u64_le(payload, 0),
        flags: read_u32_le(payload, 8),
        old_name,
        new_name,
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_SETXATTR.
pub fn parse_fuse_setxattr_request(
    payload: &[u8],
) -> Result<FuseSetxattrRequest<'_>, XattrRequestParseError> {
    if payload.len() < FUSE_SETXATTR_IN_WIRE_SIZE {
        return Err(XattrRequestParseError::BufferTooSmall {
            required: FUSE_SETXATTR_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    let size = read_u32_le(payload, 0);
    let flags = read_u32_le(payload, 4);
    let setxattr_flags = read_u32_le(payload, 8);
    let (name, value) = split_nul_terminated_name(&payload[FUSE_SETXATTR_IN_WIRE_SIZE..])?;
    let declared = size as usize;
    if value.len() != declared {
        return Err(XattrRequestParseError::ValueSizeMismatch {
            declared,
            actual: value.len(),
        });
    }

    Ok(FuseSetxattrRequest {
        size,
        flags,
        setxattr_flags,
        name,
        value,
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_GETXATTR.
pub fn parse_fuse_getxattr_request(
    payload: &[u8],
) -> Result<FuseGetxattrRequest<'_>, XattrRequestParseError> {
    if payload.len() < FUSE_GETXATTR_IN_WIRE_SIZE {
        return Err(XattrRequestParseError::BufferTooSmall {
            required: FUSE_GETXATTR_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    let size = read_u32_le(payload, 0);
    let (name, trailing) = split_nul_terminated_name(&payload[FUSE_GETXATTR_IN_WIRE_SIZE..])?;
    if !trailing.is_empty() {
        return Err(XattrRequestParseError::TrailingBytes {
            expected: payload.len() - trailing.len(),
            actual: payload.len(),
        });
    }

    Ok(FuseGetxattrRequest { size, name })
}

/// Parse the payload after `fuse_in_header` for FUSE_LISTXATTR.
pub fn parse_fuse_listxattr_request(
    payload: &[u8],
) -> Result<FuseListxattrRequest, XattrRequestParseError> {
    if payload.len() < FUSE_GETXATTR_IN_WIRE_SIZE {
        return Err(XattrRequestParseError::BufferTooSmall {
            required: FUSE_GETXATTR_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_GETXATTR_IN_WIRE_SIZE {
        return Err(XattrRequestParseError::TrailingBytes {
            expected: FUSE_GETXATTR_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseListxattrRequest {
        size: read_u32_le(payload, 0),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_REMOVEXATTR.
pub fn parse_fuse_removexattr_request(
    payload: &[u8],
) -> Result<FuseRemovexattrRequest<'_>, XattrRequestParseError> {
    let (name, trailing) = split_nul_terminated_name(payload)?;
    if !trailing.is_empty() {
        return Err(XattrRequestParseError::TrailingBytes {
            expected: payload.len() - trailing.len(),
            actual: payload.len(),
        });
    }

    Ok(FuseRemovexattrRequest { name })
}

/// Parse the payload after `fuse_in_header` for FUSE_MKDIR.
pub fn parse_fuse_mkdir_request(
    payload: &[u8],
) -> Result<FuseMkdirRequest<'_>, MkdirRequestParseError> {
    if payload.len() < FUSE_MKDIR_IN_WIRE_SIZE {
        return Err(MkdirRequestParseError::PayloadTooShort {
            required: FUSE_MKDIR_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseMkdirRequest {
        mode: read_u32_le(payload, 0),
        umask: read_u32_le(payload, 4),
        name: parse_mkdir_name(payload)?,
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_CREATE.
pub fn parse_fuse_create_request(
    payload: &[u8],
) -> Result<FuseCreateRequest<'_>, CreateRequestParseError> {
    if payload.len() < FUSE_CREATE_IN_WIRE_SIZE {
        return Err(CreateRequestParseError::BufferTooSmall {
            required: FUSE_CREATE_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseCreateRequest {
        flags: read_u32_le(payload, 0),
        mode: read_u32_le(payload, 4),
        umask: read_u32_le(payload, 8),
        open_flags: read_u32_le(payload, 12),
        name: parse_create_name(payload)?,
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_MKNOD.
pub fn parse_fuse_mknod_request(
    parent: u64,
    payload: &[u8],
) -> Result<FuseMknodRequest<'_>, MknodRequestParseError> {
    if payload.len() < FUSE_MKNOD_IN_WIRE_SIZE {
        return Err(MknodRequestParseError::BufferTooSmall {
            required: FUSE_MKNOD_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if read_u32_le(payload, 12) != 0 {
        return Err(MknodRequestParseError::InvalidPadding);
    }

    Ok(FuseMknodRequest {
        parent,
        mode: read_u32_le(payload, 0),
        rdev: read_u32_le(payload, 4),
        umask: read_u32_le(payload, 8),
        name: parse_mknod_name(payload)?,
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_UNLINK.
pub fn parse_fuse_unlink_request(
    parent: u64,
    payload: &[u8],
) -> Result<FuseUnlinkRequest<'_>, UnlinkRequestParseError> {
    if payload.is_empty() {
        return Err(UnlinkRequestParseError::BufferTooSmall {
            required: FUSE_UNLINK_MIN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    let Some(nul_index) = find_nul_terminator(payload) else {
        return Err(UnlinkRequestParseError::MissingNulTerminator);
    };
    if nul_index == 0 {
        return Err(UnlinkRequestParseError::EmptyName);
    }

    let trailing_start = nul_index + 1;
    if trailing_start != payload.len() {
        return Err(UnlinkRequestParseError::TrailingBytes {
            expected: trailing_start,
            actual: payload.len(),
        });
    }

    Ok(FuseUnlinkRequest {
        parent,
        name: &payload[..nul_index],
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_RMDIR.
pub fn parse_fuse_rmdir_request(
    parent: u64,
    payload: &[u8],
) -> Result<FuseRmdirRequest<'_>, RmdirRequestParseError> {
    if payload.is_empty() {
        return Err(RmdirRequestParseError::BufferTooSmall {
            required: FUSE_RMDIR_MIN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    let Some(nul_index) = find_nul_terminator(payload) else {
        return Err(RmdirRequestParseError::MissingNulTerminator);
    };
    if nul_index == 0 {
        return Err(RmdirRequestParseError::EmptyName);
    }

    let trailing_start = nul_index + 1;
    if trailing_start != payload.len() {
        return Err(RmdirRequestParseError::TrailingBytes {
            expected: trailing_start,
            actual: payload.len(),
        });
    }

    Ok(FuseRmdirRequest {
        parent,
        name: &payload[..nul_index],
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_ACCESS.
pub fn parse_fuse_access_request(
    payload: &[u8],
) -> Result<FuseAccessRequest, AccessRequestParseError> {
    if payload.len() < FUSE_ACCESS_IN_WIRE_SIZE {
        return Err(AccessRequestParseError::BufferTooSmall {
            required: FUSE_ACCESS_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_ACCESS_IN_WIRE_SIZE {
        return Err(AccessRequestParseError::TrailingBytes {
            expected: FUSE_ACCESS_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseAccessRequest {
        mask: read_u32_le(payload, 0),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_READDIR.
pub fn parse_fuse_readdir_request(
    payload: &[u8],
) -> Result<FuseReaddirRequest, ReaddirRequestParseError> {
    if payload.len() < FUSE_READDIR_IN_WIRE_SIZE {
        return Err(ReaddirRequestParseError::BufferTooSmall {
            required: FUSE_READDIR_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_READDIR_IN_WIRE_SIZE {
        return Err(ReaddirRequestParseError::TrailingBytes {
            expected: FUSE_READDIR_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseReaddirRequest {
        fh: read_u64_le(payload, 0),
        offset: read_u64_le(payload, 8),
        size: read_u32_le(payload, 16),
        read_flags: read_u32_le(payload, 20),
        lock_owner: read_u64_le(payload, 24),
        flags: read_u32_le(payload, 32),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_READ.
pub fn parse_fuse_read_request(payload: &[u8]) -> Result<FuseReadRequest, ReadRequestParseError> {
    if payload.len() < FUSE_READ_IN_WIRE_SIZE {
        return Err(ReadRequestParseError::BufferTooSmall {
            required: FUSE_READ_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_READ_IN_WIRE_SIZE {
        return Err(ReadRequestParseError::TrailingBytes {
            expected: FUSE_READ_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseReadRequest {
        fh: read_u64_le(payload, 0),
        offset: read_u64_le(payload, 8),
        size: read_u32_le(payload, 16),
        read_flags: read_u32_le(payload, 20),
        lock_owner: read_u64_le(payload, 24),
        flags: read_u32_le(payload, 32),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_READDIRPLUS.
pub fn parse_fuse_readdirplus_request(
    payload: &[u8],
) -> Result<FuseReaddirplusRequest, ReaddirplusRequestParseError> {
    if payload.len() < FUSE_READDIRPLUS_IN_WIRE_SIZE {
        return Err(ReaddirplusRequestParseError::BufferTooSmall {
            required: FUSE_READDIRPLUS_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_READDIRPLUS_IN_WIRE_SIZE {
        return Err(ReaddirplusRequestParseError::TrailingBytes {
            expected: FUSE_READDIRPLUS_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    let read_flags = read_u32_le(payload, 20);
    let supported_read_flags = readdirplus_read_flags::FUSE_READ_LOCKOWNER;
    if (read_flags & !supported_read_flags) != 0 {
        return Err(ReaddirplusRequestParseError::UnsupportedReadFlags {
            supported: supported_read_flags,
            actual: read_flags,
        });
    }

    Ok(FuseReaddirplusRequest {
        fh: read_u64_le(payload, 0),
        offset: read_u64_le(payload, 8),
        size: read_u32_le(payload, 16),
        read_flags,
        lock_owner: read_u64_le(payload, 24),
        flags: read_u32_le(payload, 32),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_FSYNC.
pub fn parse_fuse_fsync_request(
    payload: &[u8],
) -> Result<FuseFsyncRequest, FsyncRequestParseError> {
    if payload.len() < FUSE_FSYNC_IN_WIRE_SIZE {
        return Err(FsyncRequestParseError::PayloadTooShort {
            required: FUSE_FSYNC_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_FSYNC_IN_WIRE_SIZE {
        return Err(FsyncRequestParseError::TrailingBytes {
            expected: FUSE_FSYNC_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseFsyncRequest {
        fh: read_u64_le(payload, 0),
        fsync_flags: read_u32_le(payload, 8),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_FSYNCDIR.
pub fn parse_fuse_fsyncdir_request(
    payload: &[u8],
) -> Result<FuseFsyncdirRequest, FsyncdirRequestParseError> {
    if payload.len() < FUSE_FSYNCDIR_IN_WIRE_SIZE {
        return Err(FsyncdirRequestParseError::PayloadTooShort {
            required: FUSE_FSYNCDIR_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_FSYNCDIR_IN_WIRE_SIZE {
        return Err(FsyncdirRequestParseError::TrailingBytes {
            expected: FUSE_FSYNCDIR_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseFsyncdirRequest {
        fh: read_u64_le(payload, 0),
        fsync_flags: read_u32_le(payload, 8),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_BMAP.
pub fn parse_fuse_bmap_request(payload: &[u8]) -> Result<FuseBmapRequest, BmapRequestParseError> {
    if payload.len() < FUSE_BMAP_IN_WIRE_SIZE {
        return Err(BmapRequestParseError::PayloadTooShort {
            required: FUSE_BMAP_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_BMAP_IN_WIRE_SIZE {
        return Err(BmapRequestParseError::TrailingBytes {
            expected: FUSE_BMAP_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseBmapRequest {
        block: read_u64_le(payload, 0),
        blocksize: read_u32_le(payload, 8),
        padding: read_u32_le(payload, 12),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_FLUSH.
pub fn parse_fuse_flush_request(
    payload: &[u8],
) -> Result<FuseFlushRequest, FlushRequestParseError> {
    if payload.len() < FUSE_FLUSH_IN_WIRE_SIZE {
        return Err(FlushRequestParseError::BufferTooSmall {
            required: FUSE_FLUSH_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_FLUSH_IN_WIRE_SIZE {
        return Err(FlushRequestParseError::TrailingBytes {
            expected: FUSE_FLUSH_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseFlushRequest {
        fh: read_u64_le(payload, 0),
        unused: read_u32_le(payload, 8),
        padding: read_u32_le(payload, 12),
        lock_owner: read_u64_le(payload, 16),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_POLL.
pub fn parse_fuse_poll_request(payload: &[u8]) -> Result<FusePollRequest, PollRequestParseError> {
    if payload.len() < FUSE_POLL_IN_WIRE_SIZE {
        return Err(PollRequestParseError::BufferTooSmall {
            required: FUSE_POLL_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_POLL_IN_WIRE_SIZE {
        return Err(PollRequestParseError::TrailingBytes {
            expected: FUSE_POLL_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FusePollRequest {
        fh: read_u64_le(payload, 0),
        kh: read_u64_le(payload, 8),
        flags: read_u32_le(payload, 16),
        events: read_u32_le(payload, 20),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_SYMLINK.
pub fn parse_fuse_symlink_request(
    payload: &[u8],
) -> Result<FuseSymlinkRequest<'_>, SymlinkRequestParseError> {
    if payload.len() < FUSE_SYMLINK_MIN_WIRE_SIZE {
        return Err(SymlinkRequestParseError::TooShort {
            required: FUSE_SYMLINK_MIN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    let (name, target_payload) = split_nul_terminated_symlink_component(payload)
        .ok_or(SymlinkRequestParseError::InvalidName)?;
    if name.is_empty() {
        return Err(SymlinkRequestParseError::InvalidName);
    }

    let (target, _) = split_nul_terminated_symlink_component(target_payload)
        .ok_or(SymlinkRequestParseError::MissingTarget)?;
    if target.is_empty() {
        return Err(SymlinkRequestParseError::MissingTarget);
    }

    Ok(FuseSymlinkRequest { name, target })
}

/// Parse the payload after `fuse_in_header` for FUSE_FALLOCATE.
pub fn parse_fuse_fallocate_request(
    payload: &[u8],
) -> Result<FuseFallocateRequest, FallocateRequestParseError> {
    if payload.len() < FUSE_FALLOCATE_IN_WIRE_SIZE {
        return Err(FallocateRequestParseError::BufferTooSmall {
            required: FUSE_FALLOCATE_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_FALLOCATE_IN_WIRE_SIZE {
        return Err(FallocateRequestParseError::TrailingBytes {
            expected: FUSE_FALLOCATE_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseFallocateRequest {
        fh: read_u64_le(payload, 0),
        offset: read_u64_le(payload, 8),
        length: read_u64_le(payload, 16),
        mode: read_u32_le(payload, 24),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_LSEEK.
pub fn parse_fuse_lseek_request(
    payload: &[u8],
) -> Result<FuseLseekRequest, LseekRequestParseError> {
    if payload.len() < FUSE_LSEEK_IN_WIRE_SIZE {
        return Err(LseekRequestParseError::BufferTooSmall {
            required: FUSE_LSEEK_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_LSEEK_IN_WIRE_SIZE {
        return Err(LseekRequestParseError::TrailingBytes {
            expected: FUSE_LSEEK_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if read_u32_le(payload, 20) != 0 {
        return Err(LseekRequestParseError::InvalidPadding);
    }

    Ok(FuseLseekRequest {
        fh: read_u64_le(payload, 0),
        offset: read_u64_le(payload, 8),
        whence: read_u32_le(payload, 16),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_IOCTL.
pub fn parse_fuse_ioctl_request(
    payload: &[u8],
) -> Result<FuseIoctlRequest, IoctlRequestParseError> {
    if payload.len() < FUSE_IOCTL_IN_WIRE_SIZE {
        return Err(IoctlRequestParseError::BufferTooSmall {
            required: FUSE_IOCTL_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    let flags = read_u32_le(payload, 8);
    if (flags & !FUSE_IOCTL_SUPPORTED_FLAGS) != 0 {
        return Err(IoctlRequestParseError::UnsupportedFlags {
            supported: FUSE_IOCTL_SUPPORTED_FLAGS,
            actual: flags,
        });
    }

    let expected = if (flags & FUSE_IOCTL_COMPAT) == 0 {
        FUSE_IOCTL_IN_WIRE_SIZE
    } else {
        FUSE_IOCTL_IN_EXTENDED_WIRE_SIZE
    };
    if payload.len() < expected {
        return Err(IoctlRequestParseError::BufferTooSmall {
            required: expected,
            actual: payload.len(),
        });
    }
    if payload.len() != expected {
        return Err(IoctlRequestParseError::TrailingBytes {
            expected,
            actual: payload.len(),
        });
    }

    let (in_size, out_size) = if expected == FUSE_IOCTL_IN_EXTENDED_WIRE_SIZE {
        (read_u32_le(payload, 24), read_u32_le(payload, 28))
    } else {
        (0, 0)
    };

    Ok(FuseIoctlRequest {
        fh: read_u64_le(payload, 0),
        flags,
        cmd: read_u32_le(payload, 12),
        arg: read_u64_le(payload, 16),
        in_size,
        out_size,
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_COPY_FILE_RANGE.
pub fn parse_fuse_copy_file_range_request(
    payload: &[u8],
) -> Result<FuseCopyFileRangeRequest, CopyFileRangeRequestParseError> {
    if payload.len() < FUSE_COPY_FILE_RANGE_IN_WIRE_SIZE {
        return Err(CopyFileRangeRequestParseError::BufferTooSmall {
            required: FUSE_COPY_FILE_RANGE_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_COPY_FILE_RANGE_IN_WIRE_SIZE {
        return Err(CopyFileRangeRequestParseError::TrailingBytes {
            expected: FUSE_COPY_FILE_RANGE_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    Ok(FuseCopyFileRangeRequest {
        fh_in: read_u64_le(payload, 0),
        off_in: read_u64_le(payload, 8),
        nodeid_out: read_u64_le(payload, 16),
        fh_out: read_u64_le(payload, 24),
        off_out: read_u64_le(payload, 32),
        len: read_u64_le(payload, 40),
        flags: read_u64_le(payload, 48),
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_WRITE.
pub fn parse_fuse_write_request(
    payload: &[u8],
) -> Result<FuseWriteRequest<'_>, WriteRequestParseError> {
    if payload.len() < FUSE_WRITE_IN_WIRE_SIZE {
        return Err(WriteRequestParseError::BufferTooSmall {
            required: FUSE_WRITE_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    let size = read_u32_le(payload, 16);
    let expected = FUSE_WRITE_IN_WIRE_SIZE + size as usize;
    if payload.len() < expected {
        return Err(WriteRequestParseError::BufferTooSmall {
            required: expected,
            actual: payload.len(),
        });
    }
    if payload.len() != expected {
        return Err(WriteRequestParseError::TrailingBytes {
            expected,
            actual: payload.len(),
        });
    }

    Ok(FuseWriteRequest {
        fh: read_u64_le(payload, 0),
        offset: read_u64_le(payload, 8),
        size,
        write_flags: read_u32_le(payload, 20),
        lock_owner: read_u64_le(payload, 24),
        flags: read_u32_le(payload, 32),
        padding: read_u32_le(payload, 36),
        data: &payload[FUSE_WRITE_IN_WIRE_SIZE..],
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_GETLK.
pub fn parse_fuse_getlk_request(
    payload: &[u8],
) -> Result<FuseGetlkRequest, GetlkRequestParseError> {
    if payload.len() < FUSE_GETLK_IN_WIRE_SIZE {
        return Err(GetlkRequestParseError::BufferTooSmall {
            required: FUSE_GETLK_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }
    if payload.len() != FUSE_GETLK_IN_WIRE_SIZE {
        return Err(GetlkRequestParseError::TrailingBytes {
            expected: FUSE_GETLK_IN_WIRE_SIZE,
            actual: payload.len(),
        });
    }

    let (fh, owner, lk, lk_flags) = parse_fuse_lk_payload(payload);
    Ok(FuseGetlkRequest {
        fh,
        owner,
        lk,
        lk_flags,
    })
}

fn parse_fuse_setlk_request_with_sleep(
    payload: &[u8],
    wire_size: usize,
    sleep: bool,
) -> Result<FuseSetlkRequest, SetlkRequestParseError> {
    if payload.len() < wire_size {
        return Err(SetlkRequestParseError::BufferTooSmall {
            required: wire_size,
            actual: payload.len(),
        });
    }
    if payload.len() != wire_size {
        return Err(SetlkRequestParseError::TrailingBytes {
            expected: wire_size,
            actual: payload.len(),
        });
    }

    let (fh, owner, lk, lk_flags) = parse_fuse_lk_payload(payload);
    Ok(FuseSetlkRequest {
        fh,
        owner,
        lk,
        lk_flags,
        sleep,
    })
}

/// Parse the payload after `fuse_in_header` for FUSE_SETLK.
pub fn parse_fuse_setlk_request(
    payload: &[u8],
) -> Result<FuseSetlkRequest, SetlkRequestParseError> {
    parse_fuse_setlk_request_with_sleep(payload, FUSE_SETLK_IN_WIRE_SIZE, false)
}

/// Parse the payload after `fuse_in_header` for FUSE_SETLKW.
pub fn parse_fuse_setlkw_request(
    payload: &[u8],
) -> Result<FuseSetlkRequest, SetlkRequestParseError> {
    parse_fuse_setlk_request_with_sleep(payload, FUSE_SETLKW_IN_WIRE_SIZE, true)
}

/// Convert a parsed FUSE setattr request into a VFS [`SetAttr`].
///
/// This bridges the FUSE wire format to the inode-attribute mutation layer.
/// The caller should validate the inode exists and plan the setattr operation
/// before passing the result to `InodeAttributeStore::setattr`.
#[must_use]
pub fn fuse_setattr_request_to_vfs(req: &FuseSetattrRequest) -> SetAttr {
    SetAttr {
        valid: req.valid,
        mode: req.mode,
        uid: req.uid,
        gid: req.gid,
        size: req.size,
        atime_ns: compose_posix_time_ns(req.atime as i64, req.atimensec),
        mtime_ns: compose_posix_time_ns(req.mtime as i64, req.mtimensec),
        ctime_ns: compose_posix_time_ns(req.ctime as i64, req.ctimensec),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u32_le(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64_le(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn fuse_init_payload(
        major: u32,
        minor: u32,
        max_readahead: u32,
        flags: u32,
    ) -> [u8; FUSE_INIT_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_INIT_IN_WIRE_SIZE];
        put_u32_le(&mut payload, 0, major);
        put_u32_le(&mut payload, 4, minor);
        put_u32_le(&mut payload, 8, max_readahead);
        put_u32_le(&mut payload, 12, flags);
        payload
    }

    fn fuse_access_payload(mask: u32, padding: u32) -> [u8; FUSE_ACCESS_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_ACCESS_IN_WIRE_SIZE];
        put_u32_le(&mut payload, 0, mask);
        put_u32_le(&mut payload, 4, padding);
        payload
    }

    fn fuse_readdir_payload(
        fh: u64,
        offset: u64,
        size: u32,
        read_flags: u32,
        lock_owner: u64,
        flags: u32,
        padding: u32,
    ) -> [u8; FUSE_READDIR_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_READDIR_IN_WIRE_SIZE];
        put_u64_le(&mut payload, 0, fh);
        put_u64_le(&mut payload, 8, offset);
        put_u32_le(&mut payload, 16, size);
        put_u32_le(&mut payload, 20, read_flags);
        put_u64_le(&mut payload, 24, lock_owner);
        put_u32_le(&mut payload, 32, flags);
        put_u32_le(&mut payload, 36, padding);
        payload
    }

    fn fuse_read_payload(
        fh: u64,
        offset: u64,
        size: u32,
        read_flags: u32,
        lock_owner: u64,
        flags: u32,
    ) -> [u8; FUSE_READ_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_READ_IN_WIRE_SIZE];
        put_u64_le(&mut payload, 0, fh);
        put_u64_le(&mut payload, 8, offset);
        put_u32_le(&mut payload, 16, size);
        put_u32_le(&mut payload, 20, read_flags);
        put_u64_le(&mut payload, 24, lock_owner);
        put_u32_le(&mut payload, 32, flags);
        payload
    }

    fn fuse_readdirplus_payload(
        fh: u64,
        offset: u64,
        size: u32,
        read_flags: u32,
        lock_owner: u64,
        flags: u32,
    ) -> [u8; FUSE_READDIRPLUS_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_READDIRPLUS_IN_WIRE_SIZE];
        put_u64_le(&mut payload, 0, fh);
        put_u64_le(&mut payload, 8, offset);
        put_u32_le(&mut payload, 16, size);
        put_u32_le(&mut payload, 20, read_flags);
        put_u64_le(&mut payload, 24, lock_owner);
        put_u32_le(&mut payload, 32, flags);
        payload
    }

    fn fuse_fsync_payload(fh: u64, fsync_flags: u32) -> [u8; FUSE_FSYNC_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_FSYNC_IN_WIRE_SIZE];
        put_u64_le(&mut payload, 0, fh);
        put_u32_le(&mut payload, 8, fsync_flags);
        payload
    }

    fn fuse_fsyncdir_payload(fh: u64, fsync_flags: u32) -> [u8; FUSE_FSYNCDIR_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_FSYNCDIR_IN_WIRE_SIZE];
        put_u64_le(&mut payload, 0, fh);
        put_u32_le(&mut payload, 8, fsync_flags);
        payload
    }

    fn fuse_bmap_payload(block: u64, blocksize: u32, padding: u32) -> [u8; FUSE_BMAP_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_BMAP_IN_WIRE_SIZE];
        put_u64_le(&mut payload, 0, block);
        put_u32_le(&mut payload, 8, blocksize);
        put_u32_le(&mut payload, 12, padding);
        payload
    }

    fn fuse_getattr_payload(getattr_flags: u32, fh: u64) -> [u8; FUSE_GETATTR_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_GETATTR_IN_WIRE_SIZE];
        put_u32_le(&mut payload, 0, getattr_flags);
        put_u64_le(&mut payload, 8, fh);
        payload
    }

    fn fuse_open_payload(flags: u32, padding: u32) -> [u8; FUSE_OPEN_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_OPEN_IN_WIRE_SIZE];
        put_u32_le(&mut payload, 0, flags);
        put_u32_le(&mut payload, 4, padding);
        payload
    }

    fn fuse_opendir_payload(flags: u32, padding: u32) -> [u8; FUSE_OPENDIR_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_OPENDIR_IN_WIRE_SIZE];
        put_u32_le(&mut payload, 0, flags);
        put_u32_le(&mut payload, 4, padding);
        payload
    }

    fn fuse_release_payload(
        fh: u64,
        flags: u32,
        release_flags: u32,
        lock_owner: u64,
    ) -> [u8; FUSE_RELEASE_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_RELEASE_IN_WIRE_SIZE];
        put_u64_le(&mut payload, 0, fh);
        put_u32_le(&mut payload, 8, flags);
        put_u32_le(&mut payload, 12, release_flags);
        put_u64_le(&mut payload, 16, lock_owner);
        payload
    }

    fn fuse_releasedir_payload(
        fh: u64,
        flags: u32,
        release_flags: u32,
        lock_owner: u64,
    ) -> [u8; FUSE_RELEASEDIR_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_RELEASEDIR_IN_WIRE_SIZE];
        put_u64_le(&mut payload, 0, fh);
        put_u32_le(&mut payload, 8, flags);
        put_u32_le(&mut payload, 12, release_flags);
        put_u64_le(&mut payload, 16, lock_owner);
        payload
    }

    fn fuse_flush_payload(
        fh: u64,
        unused: u32,
        padding: u32,
        lock_owner: u64,
    ) -> [u8; FUSE_FLUSH_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_FLUSH_IN_WIRE_SIZE];
        put_u64_le(&mut payload, 0, fh);
        put_u32_le(&mut payload, 8, unused);
        put_u32_le(&mut payload, 12, padding);
        put_u64_le(&mut payload, 16, lock_owner);
        payload
    }

    fn fuse_poll_payload(
        fh: u64,
        kh: u64,
        flags: u32,
        events: u32,
    ) -> [u8; FUSE_POLL_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_POLL_IN_WIRE_SIZE];
        put_u64_le(&mut payload, 0, fh);
        put_u64_le(&mut payload, 8, kh);
        put_u32_le(&mut payload, 16, flags);
        put_u32_le(&mut payload, 20, events);
        payload
    }

    fn fuse_fallocate_payload(
        fh: u64,
        offset: u64,
        length: u64,
        mode: u32,
    ) -> [u8; FUSE_FALLOCATE_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_FALLOCATE_IN_WIRE_SIZE];
        put_u64_le(&mut payload, 0, fh);
        put_u64_le(&mut payload, 8, offset);
        put_u64_le(&mut payload, 16, length);
        put_u32_le(&mut payload, 24, mode);
        payload
    }

    fn fuse_lseek_payload(fh: u64, offset: u64, whence: u32) -> [u8; FUSE_LSEEK_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_LSEEK_IN_WIRE_SIZE];
        put_u64_le(&mut payload, 0, fh);
        put_u64_le(&mut payload, 8, offset);
        put_u32_le(&mut payload, 16, whence);
        payload
    }

    fn fuse_ioctl_payload(
        fh: u64,
        flags: u32,
        cmd: u32,
        arg: u64,
    ) -> [u8; FUSE_IOCTL_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_IOCTL_IN_WIRE_SIZE];
        put_u64_le(&mut payload, 0, fh);
        put_u32_le(&mut payload, 8, flags);
        put_u32_le(&mut payload, 12, cmd);
        put_u64_le(&mut payload, 16, arg);
        payload
    }

    fn fuse_ioctl_extended_payload(
        fh: u64,
        flags: u32,
        cmd: u32,
        arg: u64,
        in_size: u32,
        out_size: u32,
    ) -> [u8; FUSE_IOCTL_IN_EXTENDED_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_IOCTL_IN_EXTENDED_WIRE_SIZE];
        put_u64_le(&mut payload, 0, fh);
        put_u32_le(&mut payload, 8, flags);
        put_u32_le(&mut payload, 12, cmd);
        put_u64_le(&mut payload, 16, arg);
        put_u32_le(&mut payload, 24, in_size);
        put_u32_le(&mut payload, 28, out_size);
        payload
    }

    fn fuse_copy_file_range_payload(
        fh_in: u64,
        off_in: u64,
        nodeid_out: u64,
        fh_out: u64,
        off_out: u64,
        len: u64,
        flags: u64,
    ) -> [u8; FUSE_COPY_FILE_RANGE_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_COPY_FILE_RANGE_IN_WIRE_SIZE];
        put_u64_le(&mut payload, 0, fh_in);
        put_u64_le(&mut payload, 8, off_in);
        put_u64_le(&mut payload, 16, nodeid_out);
        put_u64_le(&mut payload, 24, fh_out);
        put_u64_le(&mut payload, 32, off_out);
        put_u64_le(&mut payload, 40, len);
        put_u64_le(&mut payload, 48, flags);
        payload
    }

    struct FuseWriteHeaderFixture {
        fh: u64,
        offset: u64,
        size: u32,
        write_flags: u32,
        lock_owner: u64,
        flags: u32,
        padding: u32,
    }

    fn put_fuse_write_header(payload: &mut [u8], header: FuseWriteHeaderFixture) {
        put_u64_le(payload, 0, header.fh);
        put_u64_le(payload, 8, header.offset);
        put_u32_le(payload, 16, header.size);
        put_u32_le(payload, 20, header.write_flags);
        put_u64_le(payload, 24, header.lock_owner);
        put_u32_le(payload, 32, header.flags);
        put_u32_le(payload, 36, header.padding);
    }

    fn fuse_forget_payload(nlookup: u64) -> [u8; FUSE_FORGET_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_FORGET_IN_WIRE_SIZE];
        put_u64_le(&mut payload, 0, nlookup);
        payload
    }

    fn fuse_batch_forget_payload(entries: &[(u64, u64)]) -> Vec<u8> {
        let mut payload = vec![
            0;
            FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE
                + entries.len() * FUSE_FORGET_ONE_WIRE_SIZE
        ];
        put_u32_le(&mut payload, 0, entries.len() as u32);

        for (index, &(nodeid, nlookup)) in entries.iter().enumerate() {
            let offset = FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE + index * FUSE_FORGET_ONE_WIRE_SIZE;
            put_u64_le(&mut payload, offset, nodeid);
            put_u64_le(&mut payload, offset + 8, nlookup);
        }

        payload
    }

    fn fuse_setattr_payload() -> [u8; FUSE_SETATTR_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_SETATTR_IN_WIRE_SIZE];
        put_u32_le(
            &mut payload,
            0,
            FATTR_SIZE | FATTR_MODE | FATTR_UID | FATTR_GID,
        );
        put_u64_le(&mut payload, 8, 0x0102_0304_0506_0708);
        put_u64_le(&mut payload, 16, 0x1112_1314_1516_1718);
        put_u64_le(&mut payload, 24, 0x2122_2324_2526_2728);
        put_u64_le(&mut payload, 32, 1_700_000_001);
        put_u64_le(&mut payload, 40, 1_700_000_002);
        put_u64_le(&mut payload, 48, 1_700_000_003);
        put_u32_le(&mut payload, 56, 101);
        put_u32_le(&mut payload, 60, 202);
        put_u32_le(&mut payload, 64, 303);
        put_u32_le(&mut payload, 68, 0o100644);
        put_u32_le(&mut payload, 76, 1_000);
        put_u32_le(&mut payload, 80, 1_001);
        payload
    }

    fn put_create_header(payload: &mut [u8], flags: u32, mode: u32, umask: u32, open_flags: u32) {
        put_u32_le(payload, 0, flags);
        put_u32_le(payload, 4, mode);
        put_u32_le(payload, 8, umask);
        put_u32_le(payload, 12, open_flags);
    }

    fn put_mkdir_header(payload: &mut [u8], mode: u32, umask: u32) {
        put_u32_le(payload, 0, mode);
        put_u32_le(payload, 4, umask);
    }

    fn put_mknod_header(payload: &mut [u8], mode: u32, rdev: u32, umask: u32, padding: u32) {
        put_u32_le(payload, 0, mode);
        put_u32_le(payload, 4, rdev);
        put_u32_le(payload, 8, umask);
        put_u32_le(payload, 12, padding);
    }

    fn fill_rename_payload_header(payload: &mut [u8], newdir: u64) {
        put_u64_le(payload, 0, newdir);
    }

    fn fill_rename2_payload_header(payload: &mut [u8], newdir: u64, flags: u32) {
        put_u64_le(payload, 0, newdir);
        put_u32_le(payload, 8, flags);
    }

    fn fuse_lk_payload(
        fh: u64,
        owner: u64,
        start: u64,
        end: u64,
        typ: u32,
        pid: u32,
        lk_flags: u32,
    ) -> [u8; FUSE_GETLK_IN_WIRE_SIZE] {
        let mut payload = [0_u8; FUSE_GETLK_IN_WIRE_SIZE];
        put_u64_le(&mut payload, 0, fh);
        put_u64_le(&mut payload, 8, owner);
        put_u64_le(&mut payload, 16, start);
        put_u64_le(&mut payload, 24, end);
        put_u32_le(&mut payload, 32, typ);
        put_u32_le(&mut payload, 36, pid);
        put_u32_le(&mut payload, 40, lk_flags);
        payload
    }

    // ── Exhaustive shard-key-policy mapping for all FUSE opcodes ───────────

    #[test]
    fn all_opcodes_map_to_correct_shard_key_policy() {
        let session_ops = &[
            opcode::FUSE_INIT,
            opcode::FUSE_DESTROY,
            opcode::FUSE_INTERRUPT,
            opcode::FUSE_FORGET,
            opcode::FUSE_BATCH_FORGET,
            opcode::FUSE_NOTIFY_REPLY,
            opcode::FUSE_SYNCFS,
            opcode::FUSE_STATFS,
        ];
        for &op in session_ops {
            assert_eq!(
                derive_shard_key_policy(op),
                PosixFilesystemAdapterShardKeyPolicy::Session,
                "opcode {op} expected Session"
            );
        }
        let parent_ops = &[
            opcode::FUSE_LOOKUP,
            opcode::FUSE_GETATTR,
            opcode::FUSE_ACCESS,
            opcode::FUSE_READLINK,
            opcode::FUSE_STATX,
            opcode::FUSE_MKDIR,
            opcode::FUSE_UNLINK,
            opcode::FUSE_RMDIR,
            opcode::FUSE_SYMLINK,
            opcode::FUSE_MKNOD,
            opcode::FUSE_CREATE,
            opcode::FUSE_TMPFILE,
            opcode::FUSE_LINK,
            opcode::FUSE_SETXATTR,
            opcode::FUSE_GETXATTR,
            opcode::FUSE_LISTXATTR,
            opcode::FUSE_REMOVEXATTR,
        ];
        for &op in parent_ops {
            assert_eq!(
                derive_shard_key_policy(op),
                PosixFilesystemAdapterShardKeyPolicy::ParentDir,
                "opcode {op} expected ParentDir"
            );
        }
        assert_eq!(
            derive_shard_key_policy(opcode::FUSE_RENAME),
            PosixFilesystemAdapterShardKeyPolicy::DualParentPair,
        );
        assert_eq!(
            derive_shard_key_policy(opcode::FUSE_RENAME2),
            PosixFilesystemAdapterShardKeyPolicy::DualParentPair,
        );
        let obj_read_ops = &[
            opcode::FUSE_OPEN,
            opcode::FUSE_READ,
            opcode::FUSE_LSEEK,
            opcode::FUSE_IOCTL,
        ];
        for &op in obj_read_ops {
            assert_eq!(
                derive_shard_key_policy(op),
                PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
                "opcode {op} expected ObjectRead"
            );
        }
        let obj_write_ops = &[
            opcode::FUSE_WRITE,
            opcode::FUSE_SETATTR,
            opcode::FUSE_FALLOCATE,
            opcode::FUSE_COPY_FILE_RANGE,
            opcode::FUSE_FLUSH,
            opcode::FUSE_FSYNC,
            opcode::FUSE_RELEASE,
        ];
        for &op in obj_write_ops {
            assert_eq!(
                derive_shard_key_policy(op),
                PosixFilesystemAdapterShardKeyPolicy::ObjectWrite,
                "opcode {op} expected ObjectWrite"
            );
        }
        let dir_ops = &[
            opcode::FUSE_OPENDIR,
            opcode::FUSE_READDIR,
            opcode::FUSE_READDIRPLUS,
            opcode::FUSE_RELEASEDIR,
            opcode::FUSE_FSYNCDIR,
        ];
        for &op in dir_ops {
            assert_eq!(
                derive_shard_key_policy(op),
                PosixFilesystemAdapterShardKeyPolicy::DirHandle,
                "opcode {op} expected DirHandle"
            );
        }
        assert_eq!(
            derive_shard_key_policy(opcode::FUSE_GETLK),
            PosixFilesystemAdapterShardKeyPolicy::LockScope,
        );
        assert_eq!(
            derive_shard_key_policy(opcode::FUSE_SETLK),
            PosixFilesystemAdapterShardKeyPolicy::LockScope,
        );
        assert_eq!(
            derive_shard_key_policy(opcode::FUSE_SETLKW),
            PosixFilesystemAdapterShardKeyPolicy::LockScope,
        );
        assert_eq!(
            derive_shard_key_policy(999),
            PosixFilesystemAdapterShardKeyPolicy::Session,
        );
    }

    // ── Exhaustive reply-class round-trip for all FUSE opcodes ─────────────

    #[test]
    fn all_opcodes_roundtrip_to_correct_reply_class() {
        let small_reply_ops = &[
            opcode::FUSE_INIT,
            opcode::FUSE_DESTROY,
            opcode::FUSE_INTERRUPT,
            opcode::FUSE_FORGET,
            opcode::FUSE_BATCH_FORGET,
            opcode::FUSE_LOOKUP,
            opcode::FUSE_GETATTR,
            opcode::FUSE_ACCESS,
            opcode::FUSE_READLINK,
            opcode::FUSE_STATFS,
            opcode::FUSE_STATX,
            opcode::FUSE_GETXTIMES,
            opcode::FUSE_MKDIR,
            opcode::FUSE_UNLINK,
            opcode::FUSE_RMDIR,
            opcode::FUSE_RENAME,
            opcode::FUSE_RENAME2,
            opcode::FUSE_LINK,
            opcode::FUSE_SYMLINK,
            opcode::FUSE_MKNOD,
            opcode::FUSE_CREATE,
            opcode::FUSE_TMPFILE,
            opcode::FUSE_SETXATTR,
            opcode::FUSE_GETXATTR,
            opcode::FUSE_LISTXATTR,
            opcode::FUSE_REMOVEXATTR,
            opcode::FUSE_EXCHANGE,
            opcode::FUSE_OPENDIR,
            opcode::FUSE_READDIR,
            opcode::FUSE_READDIRPLUS,
            opcode::FUSE_RELEASEDIR,
            opcode::FUSE_FSYNCDIR,
            opcode::FUSE_GETLK,
            opcode::FUSE_SETLK,
            opcode::FUSE_SETLKW,
            opcode::FUSE_BMAP,
            opcode::FUSE_NOTIFY_REPLY,
            opcode::FUSE_SETUPMAPPING,
            opcode::FUSE_REMOVEMAPPING,
            opcode::FUSE_SETVOLNAME,
        ];
        for &op in small_reply_ops {
            let rc = classify_fuse_request(op);
            assert_eq!(
                classify_reply_class(rc),
                PosixFilesystemAdapterReplyClass::SmallReply,
                "opcode {op} expected SmallReply, got {:?}",
                rc.as_str()
            );
        }
        let bulk_reply_ops = &[
            opcode::FUSE_OPEN,
            opcode::FUSE_READ,
            opcode::FUSE_LSEEK,
            opcode::FUSE_IOCTL,
            opcode::FUSE_POLL,
            opcode::FUSE_WRITE,
            opcode::FUSE_SETATTR,
            opcode::FUSE_FALLOCATE,
            opcode::FUSE_COPY_FILE_RANGE,
            opcode::FUSE_FLUSH,
            opcode::FUSE_FSYNC,
            opcode::FUSE_RELEASE,
            opcode::FUSE_SYNCFS,
        ];
        for &op in bulk_reply_ops {
            let rc = classify_fuse_request(op);
            assert_eq!(
                classify_reply_class(rc),
                PosixFilesystemAdapterReplyClass::BulkReply,
                "opcode {op} expected BulkReply, got {:?}",
                rc.as_str()
            );
        }
    }

    // ── Init flag bit uniqueness ───────────────────────────────────────────

    #[test]
    fn init_flags_have_unique_bits() {
        let flags: &[u32] = &[
            init_flags::FUSE_ASYNC_READ,
            init_flags::FUSE_POSIX_LOCKS,
            init_flags::FUSE_FILE_OPS,
            init_flags::FUSE_ATOMIC_O_TRUNC,
            init_flags::FUSE_EXPORT_SUPPORT,
            init_flags::FUSE_BIG_WRITES,
            init_flags::FUSE_DONT_MASK,
            init_flags::FUSE_SPLICE_WRITE,
            init_flags::FUSE_SPLICE_MOVE,
            init_flags::FUSE_SPLICE_READ,
            init_flags::FUSE_FLOCK_LOCKS,
            init_flags::FUSE_HAS_IOCTL_DIR,
            init_flags::FUSE_AUTO_INVAL_DATA,
            init_flags::FUSE_DO_READDIRPLUS,
            init_flags::FUSE_READDIRPLUS_AUTO,
            init_flags::FUSE_ASYNC_DIO,
            init_flags::FUSE_WRITEBACK_CACHE,
            init_flags::FUSE_NO_OPEN_SUPPORT,
            init_flags::FUSE_PARALLEL_DIROPS,
            init_flags::FUSE_HANDLE_KILLPRIV,
            init_flags::FUSE_POSIX_ACL,
            init_flags::FUSE_ABORT_ERROR,
            init_flags::FUSE_MAX_PAGES,
            init_flags::FUSE_CACHE_SYMLINKS,
            init_flags::FUSE_NO_OPENDIR_SUPPORT,
            init_flags::FUSE_EXPLICIT_INVAL_DATA,
        ];
        for bit in 0..32 {
            let matching: Vec<usize> = flags
                .iter()
                .enumerate()
                .filter(|(_, &f)| (f >> bit) & 1 == 1)
                .map(|(i, _)| i)
                .collect();
            assert!(
                matching.len() <= 1,
                "bit {bit} set by multiple init_flags: indices {matching:?}"
            );
        }
        assert_eq!(flags.len(), 26, "init_flags count should be 26");
        for (i, &f) in flags.iter().enumerate() {
            assert_ne!(f, 0, "init_flag at index {i} is zero");
        }
    }

    // ── FUSE_INIT default value assertions ─────────────────────────────────

    #[test]
    fn fuse_init_defaults_match_spec() {
        assert_eq!(FUSE_INIT_SUPPORTED_MAJOR, 7);
        assert_eq!(FUSE_INIT_SUPPORTED_MINOR, 28);
        assert_eq!(FUSE_INIT_MIN_MAX_WRITE, 4096);
        assert_eq!(FUSE_INIT_DEFAULT_MAX_WRITE, 128 * 1024);
        assert_eq!(FUSE_INIT_MAX_WRITE_LIMIT, 1024 * 1024);
        assert_eq!(FUSE_INIT_DEFAULT_MAX_READAHEAD, 128 * 1024);
        assert_eq!(FUSE_INIT_DEFAULT_MAX_BACKGROUND, 16);
        assert_eq!(FUSE_INIT_DEFAULT_CONGESTION_THRESHOLD, 12);
        assert_eq!(FUSE_INIT_DEFAULT_TIME_GRAN_NS, 1);
        assert_eq!(FUSE_INIT_DEFAULT_MAX_PAGES, 32);
    }

    #[test]
    fn fuse_init_required_flags_are_subset_of_wanted() {
        assert_eq!(
            TIDEFS_FUSE_INIT_REQUIRED_FLAGS & TIDEFS_FUSE_INIT_DEFAULT_WANTED_FLAGS,
            TIDEFS_FUSE_INIT_REQUIRED_FLAGS,
        );
    }

    #[test]
    fn fuse_init_best_effort_flags_are_subset_of_wanted() {
        assert_eq!(
            TIDEFS_FUSE_INIT_BEST_EFFORT_FLAGS & TIDEFS_FUSE_INIT_DEFAULT_WANTED_FLAGS,
            TIDEFS_FUSE_INIT_BEST_EFFORT_FLAGS,
        );
    }

    #[test]
    fn fuse_init_required_and_best_effort_disjoint() {
        assert_eq!(
            TIDEFS_FUSE_INIT_REQUIRED_FLAGS & TIDEFS_FUSE_INIT_BEST_EFFORT_FLAGS,
            0,
            "required and best-effort flag sets must not overlap"
        );
    }

    // ── Wire-size constant cross-reference checks ──────────────────────────

    #[test]
    fn wire_size_aliased_constants_are_consistent() {
        assert_eq!(FUSE_OPENDIR_IN_WIRE_SIZE, FUSE_OPEN_IN_WIRE_SIZE);
        assert_eq!(FUSE_RELEASEDIR_IN_WIRE_SIZE, FUSE_RELEASE_IN_WIRE_SIZE);
        assert_eq!(FUSE_READDIRPLUS_IN_WIRE_SIZE, FUSE_READDIR_IN_WIRE_SIZE);
        assert_eq!(FUSE_FSYNCDIR_IN_WIRE_SIZE, FUSE_FSYNC_IN_WIRE_SIZE);
        assert_eq!(FUSE_SETLK_IN_WIRE_SIZE, FUSE_GETLK_IN_WIRE_SIZE);
        assert_eq!(FUSE_SETLKW_IN_WIRE_SIZE, FUSE_SETLK_IN_WIRE_SIZE);
    }

    #[test]
    fn bodyless_ops_have_zero_wire_size() {
        assert_eq!(FUSE_READLINK_IN_WIRE_SIZE, 0);
        assert_eq!(FUSE_TMPFILE_IN_WIRE_SIZE, 0);
        assert_eq!(FUSE_STATFS_IN_WIRE_SIZE, 0);
        assert_eq!(FUSE_DESTROY_IN_WIRE_SIZE, 0);
    }

    #[test]
    fn wire_sizes_are_nonzero_where_expected() {
        let nonzero: &[(&str, usize)] = &[
            ("INIT", FUSE_INIT_IN_WIRE_SIZE),
            ("INTERRUPT", FUSE_INTERRUPT_IN_WIRE_SIZE),
            ("FORGET", FUSE_FORGET_IN_WIRE_SIZE),
            ("BATCH_FORGET header", FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE),
            ("FORGET_ONE", FUSE_FORGET_ONE_WIRE_SIZE),
            ("RELEASE", FUSE_RELEASE_IN_WIRE_SIZE),
            ("GETATTR", FUSE_GETATTR_IN_WIRE_SIZE),
            ("STATX", FUSE_STATX_IN_WIRE_SIZE),
            ("OPEN", FUSE_OPEN_IN_WIRE_SIZE),
            ("SETATTR", FUSE_SETATTR_IN_WIRE_SIZE),
            ("LINK", FUSE_LINK_IN_WIRE_SIZE),
            ("RENAME", FUSE_RENAME_IN_WIRE_SIZE),
            ("RENAME2", FUSE_RENAME2_IN_WIRE_SIZE),
            ("NAME_MAX", FUSE_NAME_MAX_BYTES),
            ("SETXATTR", FUSE_SETXATTR_IN_WIRE_SIZE),
            ("GETXATTR", FUSE_GETXATTR_IN_WIRE_SIZE),
            ("MKDIR", FUSE_MKDIR_IN_WIRE_SIZE),
            ("CREATE", FUSE_CREATE_IN_WIRE_SIZE),
            ("MKNOD", FUSE_MKNOD_IN_WIRE_SIZE),
            ("READDIR", FUSE_READDIR_IN_WIRE_SIZE),
            ("READ", FUSE_READ_IN_WIRE_SIZE),
            ("FSYNC", FUSE_FSYNC_IN_WIRE_SIZE),
            ("BMAP", FUSE_BMAP_IN_WIRE_SIZE),
            ("ACCESS", FUSE_ACCESS_IN_WIRE_SIZE),
            ("FLUSH", FUSE_FLUSH_IN_WIRE_SIZE),
            ("POLL", FUSE_POLL_IN_WIRE_SIZE),
            ("FALLOCATE", FUSE_FALLOCATE_IN_WIRE_SIZE),
            ("IOCTL", FUSE_IOCTL_IN_WIRE_SIZE),
            ("LSEEK", FUSE_LSEEK_IN_WIRE_SIZE),
            ("COPY_FILE_RANGE", FUSE_COPY_FILE_RANGE_IN_WIRE_SIZE),
            ("EXCHANGE", FUSE_EXCHANGE_IN_WIRE_SIZE),
            ("WRITE", FUSE_WRITE_IN_WIRE_SIZE),
            ("GETLK", FUSE_GETLK_IN_WIRE_SIZE),
        ];
        for &(name, size) in nonzero {
            assert!(size > 0, "{name} wire size ({size}) must be > 0");
        }
    }

    #[test]
    fn all_8_request_classes_covered_by_opcode_set() {
        let mut covered = [false; 8];
        let all_opcodes: &[u32] = &[
            opcode::FUSE_INIT,
            opcode::FUSE_LOOKUP,
            opcode::FUSE_MKDIR,
            opcode::FUSE_OPENDIR,
            opcode::FUSE_READ,
            opcode::FUSE_WRITE,
            opcode::FUSE_GETLK,
            opcode::FUSE_BMAP,
            opcode::FUSE_DESTROY,
            opcode::FUSE_INTERRUPT,
            opcode::FUSE_FORGET,
            opcode::FUSE_BATCH_FORGET,
            opcode::FUSE_GETATTR,
            opcode::FUSE_ACCESS,
            opcode::FUSE_READLINK,
            opcode::FUSE_STATFS,
            opcode::FUSE_STATX,
            opcode::FUSE_GETXTIMES,
            opcode::FUSE_UNLINK,
            opcode::FUSE_RMDIR,
            opcode::FUSE_RENAME,
            opcode::FUSE_LINK,
            opcode::FUSE_SYMLINK,
            opcode::FUSE_MKNOD,
            opcode::FUSE_CREATE,
            opcode::FUSE_TMPFILE,
            opcode::FUSE_SETXATTR,
            opcode::FUSE_GETXATTR,
            opcode::FUSE_LISTXATTR,
            opcode::FUSE_REMOVEXATTR,
            opcode::FUSE_EXCHANGE,
            opcode::FUSE_READDIR,
            opcode::FUSE_READDIRPLUS,
            opcode::FUSE_RELEASEDIR,
            opcode::FUSE_FSYNCDIR,
            opcode::FUSE_OPEN,
            opcode::FUSE_LSEEK,
            opcode::FUSE_IOCTL,
            opcode::FUSE_POLL,
            opcode::FUSE_SETATTR,
            opcode::FUSE_FALLOCATE,
            opcode::FUSE_COPY_FILE_RANGE,
            opcode::FUSE_FLUSH,
            opcode::FUSE_FSYNC,
            opcode::FUSE_RELEASE,
            opcode::FUSE_SYNCFS,
            opcode::FUSE_SETLK,
            opcode::FUSE_SETLKW,
            opcode::FUSE_NOTIFY_REPLY,
            opcode::FUSE_SETUPMAPPING,
            opcode::FUSE_REMOVEMAPPING,
            opcode::FUSE_SETVOLNAME,
        ];
        for &op in all_opcodes {
            let class = classify_fuse_request(op);
            covered[class.as_u32() as usize] = true;
        }
        for (i, &c) in covered.iter().enumerate() {
            assert!(c, "request class {i} not covered by any opcode");
        }
    }

    #[test]
    fn control_urgent_has_correct_members() {
        assert_eq!(
            classify_fuse_request(opcode::FUSE_INIT),
            PosixFilesystemAdapterRequestClass::ControlUrgent
        );
        assert_eq!(
            classify_fuse_request(opcode::FUSE_DESTROY),
            PosixFilesystemAdapterRequestClass::ControlUrgent
        );
        assert_eq!(
            classify_fuse_request(opcode::FUSE_INTERRUPT),
            PosixFilesystemAdapterRequestClass::ControlUrgent
        );
        assert_eq!(
            classify_fuse_request(opcode::FUSE_FORGET),
            PosixFilesystemAdapterRequestClass::ControlUrgent
        );
        assert_eq!(
            classify_fuse_request(opcode::FUSE_BATCH_FORGET),
            PosixFilesystemAdapterRequestClass::ControlUrgent
        );
    }

    #[test]
    fn unknown_opcode_falls_to_maintenance() {
        assert_eq!(
            classify_fuse_request(999),
            PosixFilesystemAdapterRequestClass::Maintenance
        );
    }

    #[test]
    fn reply_class_is_consistent() {
        assert_eq!(
            classify_reply_class(PosixFilesystemAdapterRequestClass::ControlUrgent),
            PosixFilesystemAdapterReplyClass::SmallReply
        );
        assert_eq!(
            classify_reply_class(PosixFilesystemAdapterRequestClass::MetaRead),
            PosixFilesystemAdapterReplyClass::SmallReply
        );
        assert_eq!(
            classify_reply_class(PosixFilesystemAdapterRequestClass::FileRead),
            PosixFilesystemAdapterReplyClass::BulkReply
        );
        assert_eq!(
            classify_reply_class(PosixFilesystemAdapterRequestClass::FileWriteback),
            PosixFilesystemAdapterReplyClass::BulkReply
        );
    }

    #[test]
    fn rename_uses_dual_parent_shard() {
        assert_eq!(
            derive_shard_key_policy(opcode::FUSE_RENAME),
            PosixFilesystemAdapterShardKeyPolicy::DualParentPair
        );
        assert_eq!(
            derive_shard_key_policy(opcode::FUSE_RENAME2),
            PosixFilesystemAdapterShardKeyPolicy::DualParentPair
        );
    }

    #[test]
    fn lock_ops_use_lock_scope_shard() {
        assert_eq!(
            derive_shard_key_policy(opcode::FUSE_GETLK),
            PosixFilesystemAdapterShardKeyPolicy::LockScope
        );
        assert_eq!(
            derive_shard_key_policy(opcode::FUSE_SETLK),
            PosixFilesystemAdapterShardKeyPolicy::LockScope
        );
        assert_eq!(
            derive_shard_key_policy(opcode::FUSE_SETLKW),
            PosixFilesystemAdapterShardKeyPolicy::LockScope
        );
    }

    #[test]
    fn init_request_parses_kernel_payload() {
        let flags = TIDEFS_FUSE_INIT_REQUIRED_FLAGS
            | init_flags::FUSE_ASYNC_READ
            | init_flags::FUSE_BIG_WRITES
            | 0x8000_0000;
        let payload = fuse_init_payload(7, 35, 512 * 1024, flags);

        let request = parse_fuse_init_request(&payload).expect("init request");

        assert_eq!(request.major, 7);
        assert_eq!(request.minor, 35);
        assert_eq!(request.max_readahead, 512 * 1024);
        assert_eq!(request.flags, flags);
    }

    #[test]
    fn init_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_init_request(&[0_u8; FUSE_INIT_IN_WIRE_SIZE - 1]),
            Err(InitRequestParseError::BufferTooSmall {
                required: FUSE_INIT_IN_WIRE_SIZE,
                actual: FUSE_INIT_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn init_negotiation_caps_high_kernel_minor() {
        let request = FuseInitRequest {
            major: FUSE_INIT_SUPPORTED_MAJOR,
            minor: FUSE_INIT_SUPPORTED_MINOR + 7,
            max_readahead: FUSE_INIT_DEFAULT_MAX_READAHEAD,
            flags: init_flags::FUSE_ASYNC_READ,
        };
        let config = FuseInitNegotiationConfig {
            required_flags: 0,
            wanted_flags: init_flags::FUSE_ASYNC_READ,
            ..FuseInitNegotiationConfig::current_adapter_defaults()
        };

        let plan = plan_fuse_init_reply(request, config).expect("init reply plan");

        assert_eq!(plan.minor, FUSE_INIT_SUPPORTED_MINOR);
        assert_eq!(plan.flags, init_flags::FUSE_ASYNC_READ);
    }

    #[test]
    fn init_negotiation_preserves_supported_lower_minor() {
        let request = FuseInitRequest {
            major: FUSE_INIT_SUPPORTED_MAJOR,
            minor: 21,
            max_readahead: FUSE_INIT_DEFAULT_MAX_READAHEAD,
            flags: 0,
        };
        let config = FuseInitNegotiationConfig {
            required_flags: 0,
            wanted_flags: 0,
            ..FuseInitNegotiationConfig::current_adapter_defaults()
        };

        let plan = plan_fuse_init_reply(request, config).expect("init reply plan");

        assert_eq!(plan.minor, 21);
    }

    #[test]
    fn init_negotiation_masks_unwanted_flags() {
        let requested = init_flags::FUSE_ASYNC_READ
            | init_flags::FUSE_BIG_WRITES
            | init_flags::FUSE_WRITEBACK_CACHE
            | init_flags::FUSE_EXPORT_SUPPORT;
        let request = FuseInitRequest {
            major: FUSE_INIT_SUPPORTED_MAJOR,
            minor: FUSE_INIT_SUPPORTED_MINOR,
            max_readahead: FUSE_INIT_DEFAULT_MAX_READAHEAD,
            flags: requested,
        };
        let config = FuseInitNegotiationConfig {
            required_flags: 0,
            wanted_flags: init_flags::FUSE_ASYNC_READ | init_flags::FUSE_BIG_WRITES,
            ..FuseInitNegotiationConfig::current_adapter_defaults()
        };

        let plan = plan_fuse_init_reply(request, config).expect("init reply plan");

        assert_eq!(
            plan.flags,
            init_flags::FUSE_ASYNC_READ | init_flags::FUSE_BIG_WRITES
        );
    }

    #[test]
    fn init_negotiation_rejects_missing_required_flags() {
        let request = FuseInitRequest {
            major: FUSE_INIT_SUPPORTED_MAJOR,
            minor: FUSE_INIT_SUPPORTED_MINOR,
            max_readahead: FUSE_INIT_DEFAULT_MAX_READAHEAD,
            flags: init_flags::FUSE_POSIX_ACL,
        };
        let required = init_flags::FUSE_POSIX_ACL | init_flags::FUSE_DO_READDIRPLUS;
        let config = FuseInitNegotiationConfig {
            required_flags: required,
            wanted_flags: required,
            ..FuseInitNegotiationConfig::current_adapter_defaults()
        };

        assert_eq!(
            plan_fuse_init_reply(request, config),
            Err(InitNegotiationError::RequiredFlagsUnavailable {
                required,
                available: init_flags::FUSE_POSIX_ACL
            })
        );
    }

    #[test]
    fn init_negotiation_rejects_unsupported_major() {
        let request = FuseInitRequest {
            major: FUSE_INIT_SUPPORTED_MAJOR + 1,
            minor: FUSE_INIT_SUPPORTED_MINOR,
            max_readahead: FUSE_INIT_DEFAULT_MAX_READAHEAD,
            flags: 0,
        };
        let config = FuseInitNegotiationConfig {
            required_flags: 0,
            wanted_flags: 0,
            ..FuseInitNegotiationConfig::current_adapter_defaults()
        };

        assert_eq!(
            plan_fuse_init_reply(request, config),
            Err(InitNegotiationError::UnsupportedMajor {
                kernel_major: FUSE_INIT_SUPPORTED_MAJOR + 1,
                supported_major: FUSE_INIT_SUPPORTED_MAJOR
            })
        );
    }

    #[test]
    fn init_negotiation_clamps_max_write_limits() {
        let request = FuseInitRequest {
            major: FUSE_INIT_SUPPORTED_MAJOR,
            minor: FUSE_INIT_SUPPORTED_MINOR,
            max_readahead: FUSE_INIT_DEFAULT_MAX_READAHEAD,
            flags: 0,
        };
        let too_small = FuseInitNegotiationConfig {
            required_flags: 0,
            wanted_flags: 0,
            max_write: 1,
            ..FuseInitNegotiationConfig::current_adapter_defaults()
        };
        let too_large = FuseInitNegotiationConfig {
            required_flags: 0,
            wanted_flags: 0,
            max_write: FUSE_INIT_MAX_WRITE_LIMIT + 4096,
            ..FuseInitNegotiationConfig::current_adapter_defaults()
        };

        assert_eq!(
            plan_fuse_init_reply(request, too_small)
                .expect("small max-write plan")
                .max_write,
            FUSE_INIT_MIN_MAX_WRITE
        );
        assert_eq!(
            plan_fuse_init_reply(request, too_large)
                .expect("large max-write plan")
                .max_write,
            FUSE_INIT_MAX_WRITE_LIMIT
        );
    }

    #[test]
    fn current_adapter_init_plan_has_deterministic_reply_fields() {
        let kernel_flags = TIDEFS_FUSE_INIT_DEFAULT_WANTED_FLAGS
            | init_flags::FUSE_EXPORT_SUPPORT
            | init_flags::FUSE_READDIRPLUS_AUTO;
        let payload = fuse_init_payload(
            FUSE_INIT_SUPPORTED_MAJOR,
            FUSE_INIT_SUPPORTED_MINOR + 4,
            FUSE_INIT_DEFAULT_MAX_READAHEAD * 2,
            kernel_flags,
        );
        let request = parse_fuse_init_request(&payload).expect("init request");

        let plan = plan_current_adapter_fuse_init_reply(request).expect("current init plan");

        assert_eq!(plan.major, FUSE_INIT_SUPPORTED_MAJOR);
        assert_eq!(plan.minor, FUSE_INIT_SUPPORTED_MINOR);
        assert_eq!(plan.max_readahead, FUSE_INIT_DEFAULT_MAX_READAHEAD);
        assert_eq!(plan.flags, TIDEFS_FUSE_INIT_DEFAULT_WANTED_FLAGS);
        assert_eq!(plan.max_background, FUSE_INIT_DEFAULT_MAX_BACKGROUND);
        assert_eq!(
            plan.congestion_threshold,
            FUSE_INIT_DEFAULT_CONGESTION_THRESHOLD
        );
        assert_eq!(plan.max_write, FUSE_INIT_DEFAULT_MAX_WRITE);
        assert_eq!(plan.time_gran, FUSE_INIT_DEFAULT_TIME_GRAN_NS);
        assert_eq!(plan.max_pages, FUSE_INIT_DEFAULT_MAX_PAGES);
    }

    #[test]
    fn interrupt_request_parses_interrupted_unique() {
        let mut payload = [0_u8; FUSE_INTERRUPT_IN_WIRE_SIZE];
        put_u64_le(&mut payload, 0, 0x0123_4567_89ab_cdef);

        let request = parse_fuse_interrupt_request(&payload).expect("interrupt request");

        assert_eq!(request.unique, 0x0123_4567_89ab_cdef);
    }

    #[test]
    fn interrupt_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_interrupt_request(&[0_u8; FUSE_INTERRUPT_IN_WIRE_SIZE - 1]),
            Err(InterruptRequestParseError::BufferTooSmall {
                required: FUSE_INTERRUPT_IN_WIRE_SIZE,
                actual: FUSE_INTERRUPT_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn interrupt_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_interrupt_request(&[0_u8; FUSE_INTERRUPT_IN_WIRE_SIZE + 1]),
            Err(InterruptRequestParseError::TrailingBytes {
                expected: FUSE_INTERRUPT_IN_WIRE_SIZE,
                actual: FUSE_INTERRUPT_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn lookup_request_parses_parent_and_single_byte_name() {
        let request =
            parse_fuse_lookup_request(0x0102_0304_0506_0708, b"a\0").expect("lookup request");

        assert_eq!(
            request,
            FuseLookupRequest {
                parent: 0x0102_0304_0506_0708,
                name: b"a"
            }
        );
    }

    #[test]
    fn lookup_request_parses_parent_and_multi_byte_name() {
        let request = parse_fuse_lookup_request(42, b"child.name\0").expect("lookup request");

        assert_eq!(request.parent, 42);
        assert_eq!(request.name, b"child.name");
    }

    #[test]
    fn lookup_request_rejects_empty_payload() {
        assert_eq!(
            parse_fuse_lookup_request(1, b""),
            Err(LookupRequestParseError::EmptyPayload)
        );
    }

    #[test]
    fn lookup_request_rejects_missing_nul_empty_name_and_trailing_bytes() {
        assert_eq!(
            parse_fuse_lookup_request(1, b"child"),
            Err(LookupRequestParseError::MissingNulTerminator)
        );
        assert_eq!(
            parse_fuse_lookup_request(1, b"\0"),
            Err(LookupRequestParseError::EmptyName)
        );
        assert_eq!(
            parse_fuse_lookup_request(1, b"child\0extra"),
            Err(LookupRequestParseError::TrailingBytes {
                expected: 6,
                actual: 11
            })
        );
    }

    #[test]
    fn forget_request_parses_lookup_decrement() {
        let payload = fuse_forget_payload(0x0123_4567_89ab_cdef);

        let request = parse_fuse_forget_request(&payload).expect("forget request");

        assert_eq!(
            request,
            FuseForgetRequest {
                nlookup: 0x0123_4567_89ab_cdef
            }
        );
    }

    #[test]
    fn forget_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_forget_request(&[0_u8; FUSE_FORGET_IN_WIRE_SIZE - 1]),
            Err(ForgetRequestParseError::BufferTooSmall {
                required: FUSE_FORGET_IN_WIRE_SIZE,
                actual: FUSE_FORGET_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn forget_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_forget_request(&[0_u8; FUSE_FORGET_IN_WIRE_SIZE + 1]),
            Err(ForgetRequestParseError::TrailingBytes {
                expected: FUSE_FORGET_IN_WIRE_SIZE,
                actual: FUSE_FORGET_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn batch_forget_request_parses_one_entry() {
        let payload = fuse_batch_forget_payload(&[(99, 4)]);

        let request = parse_fuse_batch_forget_request(&payload).expect("batch forget request");

        assert_eq!(
            request.entries.as_slice(),
            &[FuseForgetOneEntry {
                nodeid: 99,
                nlookup: 4
            }]
        );
    }

    #[test]
    fn batch_forget_request_parses_multiple_entries() {
        let payload = fuse_batch_forget_payload(&[(2, 1), (3, 8), (5, u64::MAX)]);

        let request = parse_fuse_batch_forget_request(&payload).expect("batch forget request");

        assert_eq!(request.entries.len(), 3);
        assert_eq!(
            request.entries[0],
            FuseForgetOneEntry {
                nodeid: 2,
                nlookup: 1
            }
        );
        assert_eq!(
            request.entries[1],
            FuseForgetOneEntry {
                nodeid: 3,
                nlookup: 8
            }
        );
        assert_eq!(
            request.entries[2],
            FuseForgetOneEntry {
                nodeid: 5,
                nlookup: u64::MAX
            }
        );
    }

    #[test]
    fn batch_forget_request_accepts_empty_batch() {
        let payload = fuse_batch_forget_payload(&[]);

        let request = parse_fuse_batch_forget_request(&payload).expect("batch forget request");

        assert!(request.entries.is_empty());
    }

    #[test]
    fn batch_forget_request_rejects_truncated_header() {
        assert_eq!(
            parse_fuse_batch_forget_request(&[0_u8; FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE - 1]),
            Err(BatchForgetRequestParseError::BufferTooSmall {
                required: FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE,
                actual: FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE - 1
            })
        );
    }

    #[test]
    fn batch_forget_request_rejects_count_mismatch_with_missing_entry() {
        let mut payload = fuse_batch_forget_payload(&[(7, 2)]);
        put_u32_le(&mut payload, 0, 2);

        assert_eq!(
            parse_fuse_batch_forget_request(&payload),
            Err(BatchForgetRequestParseError::BufferTooSmall {
                required: FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE + 2 * FUSE_FORGET_ONE_WIRE_SIZE,
                actual: FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE + FUSE_FORGET_ONE_WIRE_SIZE
            })
        );
    }

    #[test]
    fn batch_forget_request_rejects_count_mismatch_with_trailing_entry() {
        let mut payload = fuse_batch_forget_payload(&[(7, 2), (8, 3)]);
        put_u32_le(&mut payload, 0, 1);

        assert_eq!(
            parse_fuse_batch_forget_request(&payload),
            Err(BatchForgetRequestParseError::TrailingBytes {
                expected: FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE + FUSE_FORGET_ONE_WIRE_SIZE,
                actual: FUSE_BATCH_FORGET_IN_WIRE_HEADER_SIZE + 2 * FUSE_FORGET_ONE_WIRE_SIZE
            })
        );
    }

    #[test]
    fn getattr_request_parses_inode_metadata_probe_without_file_handle() {
        let payload = fuse_getattr_payload(0, 0);

        let request = parse_fuse_getattr_request(&payload).expect("getattr request");

        assert_eq!(request.getattr_flags, 0);
        assert_eq!(request.fh, 0);
    }

    #[test]
    fn getattr_request_preserves_file_handle_flag_and_unknown_bits() {
        let flags = FUSE_GETATTR_FH | 0x8000_0000;
        let payload = fuse_getattr_payload(flags, 0x0123_4567_89ab_cdef);

        let request = parse_fuse_getattr_request(&payload).expect("getattr request");

        assert_eq!(
            request,
            FuseGetattrRequest {
                getattr_flags: flags,
                fh: 0x0123_4567_89ab_cdef
            }
        );
    }

    #[test]
    fn getattr_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_getattr_request(&[0_u8; FUSE_GETATTR_IN_WIRE_SIZE - 1]),
            Err(GetattrRequestParseError::TooShort {
                required: FUSE_GETATTR_IN_WIRE_SIZE,
                actual: FUSE_GETATTR_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn getattr_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_getattr_request(&[0_u8; FUSE_GETATTR_IN_WIRE_SIZE + 1]),
            Err(GetattrRequestParseError::TrailingBytes {
                expected: FUSE_GETATTR_IN_WIRE_SIZE,
                actual: FUSE_GETATTR_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn statx_request_parses_flags_handle_and_mask() {
        let mut payload = [0_u8; FUSE_STATX_IN_WIRE_SIZE];
        put_u32_le(&mut payload, 0, 0x1);
        put_u32_le(&mut payload, 4, 0x2233_4455);
        put_u64_le(&mut payload, 8, 0x0123_4567_89ab_cdef);
        put_u32_le(&mut payload, 16, 0x0400);
        put_u32_le(&mut payload, 20, 0x07ff);

        let request = parse_fuse_statx_request(&payload).expect("statx request");

        assert_eq!(request.getattr_flags, 0x1);
        assert_eq!(request.reserved, 0x2233_4455);
        assert_eq!(request.fh, 0x0123_4567_89ab_cdef);
        assert_eq!(request.sx_flags, 0x0400);
        assert_eq!(request.sx_mask, 0x07ff);
    }

    #[test]
    fn statx_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_statx_request(&[0_u8; FUSE_STATX_IN_WIRE_SIZE - 1]),
            Err(StatxRequestParseError::BufferTooSmall {
                required: FUSE_STATX_IN_WIRE_SIZE,
                actual: FUSE_STATX_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn statx_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_statx_request(&[0_u8; FUSE_STATX_IN_WIRE_SIZE + 1]),
            Err(StatxRequestParseError::TrailingBytes {
                expected: FUSE_STATX_IN_WIRE_SIZE,
                actual: FUSE_STATX_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn open_request_parses_flags_and_padding() {
        let payload = fuse_open_payload(0x0000_8002, 0);

        let request = parse_fuse_open_request(&payload).expect("open request");

        assert_eq!(request.flags, 0x0000_8002);
        assert_eq!(request.padding, 0);
    }

    #[test]
    fn open_request_preserves_all_flag_and_padding_bits() {
        let payload = fuse_open_payload(u32::MAX, 0x8000_0041);

        let request = parse_fuse_open_request(&payload).expect("open request");

        assert_eq!(
            request,
            FuseOpenRequest {
                flags: u32::MAX,
                padding: 0x8000_0041
            }
        );
    }

    #[test]
    fn open_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_open_request(&[0_u8; FUSE_OPEN_IN_WIRE_SIZE - 1]),
            Err(OpenRequestParseError::BufferTooSmall {
                required: FUSE_OPEN_IN_WIRE_SIZE,
                actual: FUSE_OPEN_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn open_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_open_request(&[0_u8; FUSE_OPEN_IN_WIRE_SIZE + 1]),
            Err(OpenRequestParseError::TrailingBytes {
                expected: FUSE_OPEN_IN_WIRE_SIZE,
                actual: FUSE_OPEN_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn opendir_request_parses_flags_and_padding() {
        let payload = fuse_opendir_payload(0x0001_0000, 0);

        let request = parse_fuse_opendir_request(&payload).expect("opendir request");

        assert_eq!(request.flags, 0x0001_0000);
        assert_eq!(request.padding, 0);
    }

    #[test]
    fn opendir_request_preserves_all_flag_and_padding_bits() {
        let payload = fuse_opendir_payload(u32::MAX, 0x8000_0041);

        let request = parse_fuse_opendir_request(&payload).expect("opendir request");

        assert_eq!(
            request,
            FuseOpendirRequest {
                flags: u32::MAX,
                padding: 0x8000_0041
            }
        );
    }

    #[test]
    fn opendir_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_opendir_request(&[0_u8; FUSE_OPENDIR_IN_WIRE_SIZE - 1]),
            Err(OpendirRequestParseError::BufferTooSmall {
                required: FUSE_OPENDIR_IN_WIRE_SIZE,
                actual: FUSE_OPENDIR_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn opendir_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_opendir_request(&[0_u8; FUSE_OPENDIR_IN_WIRE_SIZE + 1]),
            Err(OpendirRequestParseError::TrailingBytes {
                expected: FUSE_OPENDIR_IN_WIRE_SIZE,
                actual: FUSE_OPENDIR_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn readlink_request_parses_bodyless_inode_request() {
        let request =
            parse_fuse_readlink_request(&[], 0x0102_0304_0506_0708).expect("readlink request");

        assert_eq!(
            request,
            FuseReadlinkRequest {
                nodeid: 0x0102_0304_0506_0708
            }
        );
    }

    #[test]
    fn readlink_request_rejects_nonempty_payload() {
        assert_eq!(
            parse_fuse_readlink_request(&[0_u8], 7),
            Err(ReadlinkRequestParseError::NonEmptyPayload { actual: 1 })
        );
    }

    #[test]
    fn tmpfile_request_parses_bodyless_inode_request() {
        let request =
            parse_fuse_tmpfile_request(&[], 0x0807_0605_0403_0201).expect("tmpfile request");

        assert_eq!(
            request,
            FuseTmpfileRequest {
                nodeid: 0x0807_0605_0403_0201
            }
        );
    }

    #[test]
    fn tmpfile_request_rejects_nonempty_payload() {
        assert_eq!(
            parse_fuse_tmpfile_request(&[0_u8], 9),
            Err(TmpfileRequestParseError::NonEmptyPayload { actual: 1 })
        );
    }

    #[test]
    fn statfs_request_parses_bodyless_request() {
        assert_eq!(
            parse_fuse_statfs_request(&[]).expect("statfs request"),
            FuseStatfsRequest
        );
    }

    #[test]
    fn statfs_request_rejects_nonempty_payload() {
        assert_eq!(
            parse_fuse_statfs_request(&[0_u8]),
            Err(StatfsRequestParseError::NonEmptyPayload { actual: 1 })
        );
    }

    #[test]
    fn statfs_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_statfs_request(&[0_u8; FUSE_STATFS_IN_WIRE_SIZE + 3]),
            Err(StatfsRequestParseError::NonEmptyPayload { actual: 3 })
        );
    }

    #[test]
    fn destroy_request_parses_bodyless_request() {
        assert_eq!(parse_fuse_destroy_request(&[]), Ok(FuseDestroyRequest));
    }

    #[test]
    fn destroy_request_rejects_nonempty_payload() {
        assert_eq!(
            parse_fuse_destroy_request(&[0_u8, 1]),
            Err(DestroyRequestParseError::NonEmptyPayload { actual: 2 })
        );
    }

    #[test]
    fn parse_fuse_syncfs_request_parses_padding_payload() {
        assert_eq!(
            parse_fuse_syncfs_request(&[0_u8; FUSE_SYNCFS_IN_WIRE_SIZE]),
            Ok(FuseSyncfsRequest)
        );
    }

    #[test]
    fn parse_fuse_syncfs_request_rejects_wrong_payload_size() {
        assert_eq!(
            parse_fuse_syncfs_request(&[0_u8; FUSE_SYNCFS_IN_WIRE_SIZE - 1]),
            Err(SyncfsRequestParseError::UnexpectedPayloadSize {
                expected: FUSE_SYNCFS_IN_WIRE_SIZE,
                actual: FUSE_SYNCFS_IN_WIRE_SIZE - 1
            })
        );
        assert_eq!(
            parse_fuse_syncfs_request(&[0_u8; FUSE_SYNCFS_IN_WIRE_SIZE + 1]),
            Err(SyncfsRequestParseError::UnexpectedPayloadSize {
                expected: FUSE_SYNCFS_IN_WIRE_SIZE,
                actual: FUSE_SYNCFS_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn setattr_request_parses_size_mode_uid_and_gid() {
        let payload = fuse_setattr_payload();

        let request = parse_fuse_setattr_request(&payload).expect("setattr request");

        assert_eq!(
            request.valid,
            FATTR_SIZE | FATTR_MODE | FATTR_UID | FATTR_GID
        );
        assert_eq!(request.size, 0x1112_1314_1516_1718);
        assert_eq!(request.mode, 0o100644);
        assert_eq!(request.uid, 1_000);
        assert_eq!(request.gid, 1_001);
    }

    #[test]
    fn setattr_request_parses_timestamp_fields() {
        let mut payload = [0_u8; FUSE_SETATTR_IN_WIRE_SIZE];
        put_u32_le(&mut payload, 0, FATTR_ATIME | FATTR_MTIME | FATTR_CTIME);
        put_u64_le(&mut payload, 32, 1_800_000_001);
        put_u64_le(&mut payload, 40, 1_800_000_002);
        put_u64_le(&mut payload, 48, 1_800_000_003);
        put_u32_le(&mut payload, 56, 111_222_333);
        put_u32_le(&mut payload, 60, 222_333_444);
        put_u32_le(&mut payload, 64, 333_444_555);

        let request = parse_fuse_setattr_request(&payload).expect("setattr request");

        assert_eq!(request.valid, FATTR_ATIME | FATTR_MTIME | FATTR_CTIME);
        assert_eq!(request.atime, 1_800_000_001);
        assert_eq!(request.mtime, 1_800_000_002);
        assert_eq!(request.ctime, 1_800_000_003);
        assert_eq!(request.atimensec, 111_222_333);
        assert_eq!(request.mtimensec, 222_333_444);
        assert_eq!(request.ctimensec, 333_444_555);
    }

    #[test]
    fn setattr_request_parses_file_handle_and_lock_owner() {
        let mut payload = [0_u8; FUSE_SETATTR_IN_WIRE_SIZE];
        put_u32_le(&mut payload, 0, FATTR_FH | FATTR_LOCKOWNER);
        put_u64_le(&mut payload, 8, 0xfeed_face_cafe_beef);
        put_u64_le(&mut payload, 24, 0x0102_0304_0506_0708);

        let request = parse_fuse_setattr_request(&payload).expect("setattr request");

        assert_eq!(request.valid, FATTR_FH | FATTR_LOCKOWNER);
        assert_eq!(request.fh, 0xfeed_face_cafe_beef);
        assert_eq!(request.lock_owner, 0x0102_0304_0506_0708);
    }

    #[test]
    fn setattr_request_preserves_now_and_unknown_valid_bits() {
        let mut payload = [0_u8; FUSE_SETATTR_IN_WIRE_SIZE];
        let valid = FATTR_ATIME_NOW | FATTR_MTIME_NOW | 0x8000_0000;
        put_u32_le(&mut payload, 0, valid);

        let request = parse_fuse_setattr_request(&payload).expect("setattr request");

        assert_eq!(request.valid, valid);
    }

    #[test]
    fn setattr_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_setattr_request(&[0_u8; FUSE_SETATTR_IN_WIRE_SIZE - 1]),
            Err(SetattrRequestParseError::BufferTooSmall {
                required: FUSE_SETATTR_IN_WIRE_SIZE,
                actual: FUSE_SETATTR_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn setattr_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_setattr_request(&[0_u8; FUSE_SETATTR_IN_WIRE_SIZE + 1]),
            Err(SetattrRequestParseError::TrailingBytes {
                expected: FUSE_SETATTR_IN_WIRE_SIZE,
                actual: FUSE_SETATTR_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn setattr_request_rejects_nonzero_padding() {
        let mut payload = [0_u8; FUSE_SETATTR_IN_WIRE_SIZE];
        put_u32_le(&mut payload, 4, 1);

        assert_eq!(
            parse_fuse_setattr_request(&payload),
            Err(SetattrRequestParseError::InvalidPadding)
        );
    }

    #[test]
    fn setattr_request_rejects_nonzero_unused_fields() {
        let mut unused4_payload = [0_u8; FUSE_SETATTR_IN_WIRE_SIZE];
        put_u32_le(&mut unused4_payload, 72, 1);
        assert_eq!(
            parse_fuse_setattr_request(&unused4_payload),
            Err(SetattrRequestParseError::InvalidPadding)
        );

        let mut unused5_payload = [0_u8; FUSE_SETATTR_IN_WIRE_SIZE];
        put_u32_le(&mut unused5_payload, 84, 1);
        assert_eq!(
            parse_fuse_setattr_request(&unused5_payload),
            Err(SetattrRequestParseError::InvalidPadding)
        );
    }

    #[test]
    fn setattr_request_round_trips_all_wire_fields() {
        let mut payload = fuse_setattr_payload();
        put_u32_le(
            &mut payload,
            0,
            FATTR_MODE
                | FATTR_UID
                | FATTR_GID
                | FATTR_SIZE
                | FATTR_ATIME
                | FATTR_MTIME
                | FATTR_CTIME
                | FATTR_FH
                | FATTR_LOCKOWNER,
        );

        let request = parse_fuse_setattr_request(&payload).expect("setattr request");

        assert_eq!(request.valid, read_u32_le(&payload, 0));
        assert_eq!(request.fh, read_u64_le(&payload, 8));
        assert_eq!(request.size, read_u64_le(&payload, 16));
        assert_eq!(request.lock_owner, read_u64_le(&payload, 24));
        assert_eq!(request.atime, read_u64_le(&payload, 32));
        assert_eq!(request.mtime, read_u64_le(&payload, 40));
        assert_eq!(request.ctime, read_u64_le(&payload, 48));
        assert_eq!(request.atimensec, read_u32_le(&payload, 56));
        assert_eq!(request.mtimensec, read_u32_le(&payload, 60));
        assert_eq!(request.ctimensec, read_u32_le(&payload, 64));
        assert_eq!(request.mode, read_u32_le(&payload, 68));
        assert_eq!(request.uid, read_u32_le(&payload, 76));
        assert_eq!(request.gid, read_u32_le(&payload, 80));
    }

    #[test]
    fn fuse_setattr_request_to_vfs_converts_mode() {
        let req = FuseSetattrRequest {
            valid: FATTR_MODE,
            fh: 0,
            size: 0,
            lock_owner: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            atimensec: 0,
            mtimensec: 0,
            ctimensec: 0,
            mode: 0o755,
            uid: 0,
            gid: 0,
        };

        let set = fuse_setattr_request_to_vfs(&req);

        assert_eq!(set.valid, FATTR_MODE);
        assert_eq!(set.mode, 0o755);
        assert_eq!(set.uid, 0);
        assert_eq!(set.gid, 0);
        assert_eq!(set.size, 0);
    }

    #[test]
    fn fuse_setattr_request_to_vfs_converts_uid_gid() {
        let req = FuseSetattrRequest {
            valid: FATTR_UID | FATTR_GID,
            fh: 0,
            size: 0,
            lock_owner: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            atimensec: 0,
            mtimensec: 0,
            ctimensec: 0,
            mode: 0,
            uid: 1000,
            gid: 100,
        };

        let set = fuse_setattr_request_to_vfs(&req);

        assert_eq!(set.valid, FATTR_UID | FATTR_GID);
        assert_eq!(set.uid, 1000);
        assert_eq!(set.gid, 100);
    }

    #[test]
    fn fuse_setattr_request_to_vfs_converts_size() {
        let req = FuseSetattrRequest {
            valid: FATTR_SIZE,
            fh: 0,
            size: 65536,
            lock_owner: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            atimensec: 0,
            mtimensec: 0,
            ctimensec: 0,
            mode: 0,
            uid: 0,
            gid: 0,
        };

        let set = fuse_setattr_request_to_vfs(&req);

        assert_eq!(set.valid, FATTR_SIZE);
        assert_eq!(set.size, 65536);
    }

    #[test]
    fn fuse_setattr_request_to_vfs_converts_timestamps() {
        let req = FuseSetattrRequest {
            valid: FATTR_ATIME | FATTR_MTIME | FATTR_CTIME,
            fh: 0,
            size: 0,
            lock_owner: 0,
            atime: 1,
            mtime: 2,
            ctime: 3,
            atimensec: 500_000_000,
            mtimensec: 250_000_000,
            ctimensec: 750_000_000,
            mode: 0,
            uid: 0,
            gid: 0,
        };

        let set = fuse_setattr_request_to_vfs(&req);

        assert_eq!(set.valid, FATTR_ATIME | FATTR_MTIME | FATTR_CTIME);
        assert_eq!(set.atime_ns, 1_500_000_000);
        assert_eq!(set.mtime_ns, 2_250_000_000);
        assert_eq!(set.ctime_ns, 3_750_000_000);
    }

    #[test]
    fn fuse_setattr_request_to_vfs_handles_zero_timestamps() {
        let req = FuseSetattrRequest {
            valid: FATTR_ATIME | FATTR_MTIME,
            fh: 0,
            size: 0,
            lock_owner: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            atimensec: 0,
            mtimensec: 0,
            ctimensec: 0,
            mode: 0,
            uid: 0,
            gid: 0,
        };

        let set = fuse_setattr_request_to_vfs(&req);

        assert_eq!(set.atime_ns, 0);
        assert_eq!(set.mtime_ns, 0);
        assert_eq!(set.ctime_ns, 0);
    }

    #[test]
    fn fuse_setattr_request_to_vfs_handles_max_timestamps() {
        let req = FuseSetattrRequest {
            valid: FATTR_ATIME,
            fh: 0,
            size: 0,
            lock_owner: 0,
            atime: u64::MAX,
            mtime: 0,
            ctime: 0,
            atimensec: 999_999_999,
            mtimensec: 0,
            ctimensec: 0,
            mode: 0,
            uid: 0,
            gid: 0,
        };

        let set = fuse_setattr_request_to_vfs(&req);
        assert_eq!(set.atime_ns, -1);
    }

    #[test]
    fn fuse_setattr_request_to_vfs_preserves_negative_timestamps() {
        let req = FuseSetattrRequest {
            valid: FATTR_ATIME | FATTR_MTIME,
            fh: 0,
            size: 0,
            lock_owner: 0,
            atime: (-315_619_200_i64) as u64,
            mtime: (-315_619_199_i64) as u64,
            ctime: 0,
            atimensec: 0,
            mtimensec: 123_456_789,
            ctimensec: 0,
            mode: 0,
            uid: 0,
            gid: 0,
        };

        let set = fuse_setattr_request_to_vfs(&req);

        assert_eq!(set.atime_ns, -315_619_200_000_000_000);
        assert_eq!(set.mtime_ns, -315_619_198_876_543_211);
    }

    #[test]
    fn fuse_setattr_request_to_vfs_preserves_all_fields() {
        let req = FuseSetattrRequest {
            valid: FATTR_MODE
                | FATTR_UID
                | FATTR_GID
                | FATTR_SIZE
                | FATTR_ATIME
                | FATTR_MTIME
                | FATTR_CTIME,
            fh: 42,
            size: 8192,
            lock_owner: 99,
            atime: 10,
            mtime: 20,
            ctime: 30,
            atimensec: 100_000_000,
            mtimensec: 200_000_000,
            ctimensec: 300_000_000,
            mode: 0o644,
            uid: 500,
            gid: 50,
        };

        let set = fuse_setattr_request_to_vfs(&req);

        assert_eq!(set.mode, 0o644);
        assert_eq!(set.uid, 500);
        assert_eq!(set.gid, 50);
        assert_eq!(set.size, 8192);
        assert_eq!(set.atime_ns, 10_100_000_000);
        assert_eq!(set.mtime_ns, 20_200_000_000);
        assert_eq!(set.ctime_ns, 30_300_000_000);
    }

    #[test]
    fn link_request_parses_olobject_nodeid_and_name() {
        let mut payload = [0_u8; FUSE_LINK_IN_WIRE_SIZE + 10];
        put_u64_le(&mut payload, 0, 0x0102_0304_0506_0708);
        payload[FUSE_LINK_IN_WIRE_SIZE..].copy_from_slice(b"hard.link\0");

        let request = parse_fuse_link_request(&payload).expect("link request");

        assert_eq!(request.olobject_nodeid, 0x0102_0304_0506_0708);
        assert_eq!(request.name, "hard.link");
    }

    #[test]
    fn link_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_link_request(&[0_u8; FUSE_LINK_IN_WIRE_SIZE - 1]),
            Err(LinkRequestParseError::BufferTooSmall {
                required: FUSE_LINK_IN_WIRE_SIZE,
                actual: FUSE_LINK_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn link_request_requires_nul_terminated_nonempty_name() {
        assert_eq!(
            parse_fuse_link_request(&[0_u8; FUSE_LINK_IN_WIRE_SIZE]),
            Err(LinkRequestParseError::MissingNulTerminator)
        );

        let mut payload = [0_u8; FUSE_LINK_IN_WIRE_SIZE + 1];
        put_u64_le(&mut payload, 0, 1);
        assert_eq!(
            parse_fuse_link_request(&payload),
            Err(LinkRequestParseError::EmptyName)
        );
    }

    #[test]
    fn link_request_rejects_trailing_bytes_after_name() {
        let mut payload = [0_u8; FUSE_LINK_IN_WIRE_SIZE + 11];
        put_u64_le(&mut payload, 0, 7);
        payload[FUSE_LINK_IN_WIRE_SIZE..].copy_from_slice(b"child\0extra");

        assert_eq!(
            parse_fuse_link_request(&payload),
            Err(LinkRequestParseError::TrailingBytes {
                expected: FUSE_LINK_IN_WIRE_SIZE + 6,
                actual: FUSE_LINK_IN_WIRE_SIZE + 11
            })
        );
    }

    #[test]
    fn link_request_rejects_invalid_utf8_name() {
        let mut payload = [0_u8; FUSE_LINK_IN_WIRE_SIZE + 2];
        put_u64_le(&mut payload, 0, 1);
        payload[FUSE_LINK_IN_WIRE_SIZE] = 0xff;

        assert_eq!(
            parse_fuse_link_request(&payload),
            Err(LinkRequestParseError::InvalidNameUtf8)
        );
    }

    #[test]
    fn setxattr_request_parses_flags_name_and_value() {
        let mut payload = [0_u8; FUSE_SETXATTR_IN_WIRE_SIZE + 10 + 5];
        put_u32_le(&mut payload, 0, 5);
        put_u32_le(&mut payload, 4, 0x2);
        put_u32_le(&mut payload, 8, 0x4);
        payload[FUSE_SETXATTR_IN_WIRE_SIZE..FUSE_SETXATTR_IN_WIRE_SIZE + 10]
            .copy_from_slice(b"user.test\0");
        payload[FUSE_SETXATTR_IN_WIRE_SIZE + 10..].copy_from_slice(b"value");

        let request = parse_fuse_setxattr_request(&payload).expect("setxattr request");

        assert_eq!(request.size, 5);
        assert_eq!(request.flags, 0x2);
        assert_eq!(request.setxattr_flags, 0x4);
        assert_eq!(request.name, b"user.test");
        assert_eq!(request.value, b"value");
    }

    #[test]
    fn setxattr_request_rejects_value_size_mismatch() {
        let mut payload = [0_u8; FUSE_SETXATTR_IN_WIRE_SIZE + 10 + 4];
        put_u32_le(&mut payload, 0, 5);
        payload[FUSE_SETXATTR_IN_WIRE_SIZE..FUSE_SETXATTR_IN_WIRE_SIZE + 10]
            .copy_from_slice(b"user.test\0");
        payload[FUSE_SETXATTR_IN_WIRE_SIZE + 10..].copy_from_slice(b"oops");

        assert_eq!(
            parse_fuse_setxattr_request(&payload),
            Err(XattrRequestParseError::ValueSizeMismatch {
                declared: 5,
                actual: 4
            })
        );
    }

    #[test]
    fn getxattr_request_parses_size_and_name() {
        let mut payload = [0_u8; FUSE_GETXATTR_IN_WIRE_SIZE + 10];
        put_u32_le(&mut payload, 0, 4096);
        payload[FUSE_GETXATTR_IN_WIRE_SIZE..].copy_from_slice(b"user.test\0");

        let request = parse_fuse_getxattr_request(&payload).expect("getxattr request");

        assert_eq!(request.size, 4096);
        assert_eq!(request.name, b"user.test");
    }

    #[test]
    fn listxattr_request_requires_exact_header_payload() {
        let mut payload = [0_u8; FUSE_GETXATTR_IN_WIRE_SIZE];
        put_u32_le(&mut payload, 0, 8192);

        let request = parse_fuse_listxattr_request(&payload).expect("listxattr request");

        assert_eq!(request.size, 8192);
        assert_eq!(
            parse_fuse_listxattr_request(&[0_u8; FUSE_GETXATTR_IN_WIRE_SIZE + 1]),
            Err(XattrRequestParseError::TrailingBytes {
                expected: FUSE_GETXATTR_IN_WIRE_SIZE,
                actual: FUSE_GETXATTR_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn removexattr_request_parses_exact_name_payload() {
        let request = parse_fuse_removexattr_request(b"user.test\0").expect("removexattr request");

        assert_eq!(request.name, b"user.test");
        assert_eq!(
            parse_fuse_removexattr_request(b"user.test\0extra"),
            Err(XattrRequestParseError::TrailingBytes {
                expected: 10,
                actual: 15
            })
        );
    }

    #[test]
    fn xattr_name_parsing_rejects_missing_or_empty_name() {
        assert_eq!(
            parse_fuse_removexattr_request(b"user.test"),
            Err(XattrRequestParseError::MissingNulTerminator)
        );
        assert_eq!(
            parse_fuse_removexattr_request(b"\0"),
            Err(XattrRequestParseError::EmptyName)
        );
    }

    #[test]
    fn mkdir_request_parses_kernel_payload() {
        let mut payload = [0_u8; FUSE_MKDIR_IN_WIRE_SIZE + 5];
        put_mkdir_header(&mut payload, 0o040755, 0o022);
        payload[FUSE_MKDIR_IN_WIRE_SIZE..].copy_from_slice(b"docs\0");

        let request = parse_fuse_mkdir_request(&payload).expect("mkdir request");

        assert_eq!(
            request,
            FuseMkdirRequest {
                mode: 0o040755,
                umask: 0o022,
                name: b"docs"
            }
        );
    }

    #[test]
    fn mkdir_request_preserves_mode_and_umask_bits() {
        let mut payload = [0_u8; FUSE_MKDIR_IN_WIRE_SIZE + 7];
        put_mkdir_header(&mut payload, 0o040777 | 0x8000_0000, 0x1234_5678);
        payload[FUSE_MKDIR_IN_WIRE_SIZE..].copy_from_slice(b"opaque\0");

        let request = parse_fuse_mkdir_request(&payload).expect("mkdir request");

        assert_eq!(request.mode, 0o040777 | 0x8000_0000);
        assert_eq!(request.umask, 0x1234_5678);
        assert_eq!(request.name, b"opaque");
    }

    #[test]
    fn mkdir_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_mkdir_request(&[0_u8; FUSE_MKDIR_IN_WIRE_SIZE - 1]),
            Err(MkdirRequestParseError::PayloadTooShort {
                required: FUSE_MKDIR_IN_WIRE_SIZE,
                actual: FUSE_MKDIR_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn mkdir_request_rejects_missing_or_empty_name() {
        assert_eq!(
            parse_fuse_mkdir_request(&[0_u8; FUSE_MKDIR_IN_WIRE_SIZE]),
            Err(MkdirRequestParseError::NameNotNulTerminated)
        );

        let mut payload = [0_u8; FUSE_MKDIR_IN_WIRE_SIZE + 1];
        put_mkdir_header(&mut payload, 0o040755, 0o022);
        assert_eq!(
            parse_fuse_mkdir_request(&payload),
            Err(MkdirRequestParseError::EmptyName)
        );
    }

    #[test]
    fn mkdir_request_rejects_non_nul_terminated_name() {
        let mut payload = [0_u8; FUSE_MKDIR_IN_WIRE_SIZE + 4];
        put_mkdir_header(&mut payload, 0o040755, 0o022);
        payload[FUSE_MKDIR_IN_WIRE_SIZE..].copy_from_slice(b"docs");

        assert_eq!(
            parse_fuse_mkdir_request(&payload),
            Err(MkdirRequestParseError::NameNotNulTerminated)
        );
    }

    #[test]
    fn mkdir_request_rejects_trailing_bytes_after_name_nul() {
        let mut payload = [0_u8; FUSE_MKDIR_IN_WIRE_SIZE + 9];
        put_mkdir_header(&mut payload, 0o040755, 0o022);
        payload[FUSE_MKDIR_IN_WIRE_SIZE..].copy_from_slice(b"docs\0tail");

        assert_eq!(
            parse_fuse_mkdir_request(&payload),
            Err(MkdirRequestParseError::TrailingBytes {
                expected: FUSE_MKDIR_IN_WIRE_SIZE + 5,
                actual: FUSE_MKDIR_IN_WIRE_SIZE + 9
            })
        );
    }

    #[test]
    fn create_request_parses_kernel_payload() {
        let mut payload = [0_u8; FUSE_CREATE_IN_WIRE_SIZE + 13];
        put_create_header(&mut payload, 0x8002, 0o100644, 0o022, 0x20);
        payload[FUSE_CREATE_IN_WIRE_SIZE..FUSE_CREATE_IN_WIRE_SIZE + 12]
            .copy_from_slice(b"new-file.txt");

        let request = parse_fuse_create_request(&payload).expect("create request");

        assert_eq!(request.flags, 0x8002);
        assert_eq!(request.mode, 0o100644);
        assert_eq!(request.umask, 0o022);
        assert_eq!(request.open_flags, 0x20);
        assert_eq!(request.name, b"new-file.txt");
    }

    #[test]
    fn create_request_preserves_unknown_flag_bits() {
        let flags = 0x8000_0000 | 0x0001_0000 | 0x0042;
        let open_flags = 0x4000_0000 | 0x0002;
        let mut payload = [0_u8; FUSE_CREATE_IN_WIRE_SIZE + 13];
        put_create_header(&mut payload, flags, 0o100600, 0, open_flags);
        payload[FUSE_CREATE_IN_WIRE_SIZE..FUSE_CREATE_IN_WIRE_SIZE + 12]
            .copy_from_slice(b"opaque-flags");

        let request = parse_fuse_create_request(&payload).expect("create request");

        assert_eq!(
            request,
            FuseCreateRequest {
                flags,
                mode: 0o100600,
                umask: 0,
                open_flags,
                name: b"opaque-flags"
            }
        );
    }

    #[test]
    fn create_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_create_request(&[0_u8; FUSE_CREATE_IN_WIRE_SIZE - 1]),
            Err(CreateRequestParseError::BufferTooSmall {
                required: FUSE_CREATE_IN_WIRE_SIZE,
                actual: FUSE_CREATE_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn create_request_rejects_missing_or_empty_name() {
        assert_eq!(
            parse_fuse_create_request(&[0_u8; FUSE_CREATE_IN_WIRE_SIZE]),
            Err(CreateRequestParseError::MissingNulTerminator)
        );

        let mut payload = [0_u8; FUSE_CREATE_IN_WIRE_SIZE + 1];
        put_create_header(&mut payload, 0, 0o100644, 0o022, 0);
        assert_eq!(
            parse_fuse_create_request(&payload),
            Err(CreateRequestParseError::EmptyName)
        );
    }

    #[test]
    fn create_request_rejects_non_nul_terminated_name() {
        let mut payload = [0_u8; FUSE_CREATE_IN_WIRE_SIZE + 4];
        put_create_header(&mut payload, 0, 0o100644, 0o022, 0);
        payload[FUSE_CREATE_IN_WIRE_SIZE..].copy_from_slice(b"name");

        assert_eq!(
            parse_fuse_create_request(&payload),
            Err(CreateRequestParseError::MissingNulTerminator)
        );
    }

    #[test]
    fn create_request_rejects_trailing_bytes_after_name_nul() {
        let mut payload = [0_u8; FUSE_CREATE_IN_WIRE_SIZE + 10];
        put_create_header(&mut payload, 0, 0o100644, 0o022, 0);
        payload[FUSE_CREATE_IN_WIRE_SIZE..].copy_from_slice(b"child\0tail");

        assert_eq!(
            parse_fuse_create_request(&payload),
            Err(CreateRequestParseError::TrailingBytes {
                expected: FUSE_CREATE_IN_WIRE_SIZE + 6,
                actual: FUSE_CREATE_IN_WIRE_SIZE + 10
            })
        );
    }

    #[test]
    fn mknod_request_parses_kernel_payload() {
        let mut payload = [0_u8; FUSE_MKNOD_IN_WIRE_SIZE + 9];
        put_mknod_header(&mut payload, 0o020666, 0x0102_0304, 0o022, 0);
        payload[FUSE_MKNOD_IN_WIRE_SIZE..].copy_from_slice(b"node.dev\0");

        let request =
            parse_fuse_mknod_request(0x0102_0304_0506_0708, &payload).expect("mknod request");

        assert_eq!(
            request,
            FuseMknodRequest {
                parent: 0x0102_0304_0506_0708,
                mode: 0o020666,
                rdev: 0x0102_0304,
                umask: 0o022,
                name: b"node.dev"
            }
        );
    }

    #[test]
    fn mknod_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_mknod_request(1, &[0_u8; FUSE_MKNOD_IN_WIRE_SIZE - 1]),
            Err(MknodRequestParseError::BufferTooSmall {
                required: FUSE_MKNOD_IN_WIRE_SIZE,
                actual: FUSE_MKNOD_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn mknod_request_rejects_missing_nul_terminator() {
        let mut payload = [0_u8; FUSE_MKNOD_IN_WIRE_SIZE + 4];
        put_mknod_header(&mut payload, 0o100644, 0, 0o022, 0);
        payload[FUSE_MKNOD_IN_WIRE_SIZE..].copy_from_slice(b"name");

        assert_eq!(
            parse_fuse_mknod_request(1, &payload),
            Err(MknodRequestParseError::MissingNulTerminator)
        );
    }

    #[test]
    fn mknod_request_rejects_empty_name() {
        let mut payload = [0_u8; FUSE_MKNOD_IN_WIRE_SIZE + 1];
        put_mknod_header(&mut payload, 0o100644, 0, 0o022, 0);

        assert_eq!(
            parse_fuse_mknod_request(1, &payload),
            Err(MknodRequestParseError::EmptyName)
        );
    }

    #[test]
    fn mknod_request_rejects_nonzero_padding() {
        let mut payload = [0_u8; FUSE_MKNOD_IN_WIRE_SIZE + 5];
        put_mknod_header(&mut payload, 0o100644, 0, 0o022, 1);
        payload[FUSE_MKNOD_IN_WIRE_SIZE..].copy_from_slice(b"name\0");

        assert_eq!(
            parse_fuse_mknod_request(1, &payload),
            Err(MknodRequestParseError::InvalidPadding)
        );
    }

    #[test]
    fn mknod_request_rejects_trailing_bytes_after_name() {
        let mut payload = [0_u8; FUSE_MKNOD_IN_WIRE_SIZE + 6];
        put_mknod_header(&mut payload, 0o100644, 0, 0o022, 0);
        payload[FUSE_MKNOD_IN_WIRE_SIZE..].copy_from_slice(b"name\0x");

        assert_eq!(
            parse_fuse_mknod_request(1, &payload),
            Err(MknodRequestParseError::TrailingBytes {
                expected: FUSE_MKNOD_IN_WIRE_SIZE + 5,
                actual: FUSE_MKNOD_IN_WIRE_SIZE + 6
            })
        );
    }

    #[test]
    fn unlink_request_parses_parent_and_exact_name_payload() {
        let request = parse_fuse_unlink_request(0x0102_0304_0506_0708, b"file.txt\0")
            .expect("unlink request");

        assert_eq!(request.parent, 0x0102_0304_0506_0708);
        assert_eq!(request.name, b"file.txt");
    }

    #[test]
    fn unlink_request_rejects_empty_payload() {
        assert_eq!(
            parse_fuse_unlink_request(1, b""),
            Err(UnlinkRequestParseError::BufferTooSmall {
                required: FUSE_UNLINK_MIN_WIRE_SIZE,
                actual: 0
            })
        );
    }

    #[test]
    fn unlink_request_rejects_missing_nul_and_empty_name() {
        assert_eq!(
            parse_fuse_unlink_request(1, b"file.txt"),
            Err(UnlinkRequestParseError::MissingNulTerminator)
        );
        assert_eq!(
            parse_fuse_unlink_request(1, b"\0"),
            Err(UnlinkRequestParseError::EmptyName)
        );
    }

    #[test]
    fn unlink_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_unlink_request(1, b"file.txt\0extra"),
            Err(UnlinkRequestParseError::TrailingBytes {
                expected: 9,
                actual: 14
            })
        );
    }

    #[test]
    fn rmdir_request_parses_parent_and_exact_name_payload() {
        let request =
            parse_fuse_rmdir_request(0x0102_0304_0506_0708, b"docs\0").expect("rmdir request");

        assert_eq!(request.parent, 0x0102_0304_0506_0708);
        assert_eq!(request.name, b"docs");
    }

    #[test]
    fn rmdir_request_rejects_empty_payload() {
        assert_eq!(
            parse_fuse_rmdir_request(1, b""),
            Err(RmdirRequestParseError::BufferTooSmall {
                required: FUSE_RMDIR_MIN_WIRE_SIZE,
                actual: 0
            })
        );
    }

    #[test]
    fn rmdir_request_rejects_missing_nul_empty_name_and_trailing_bytes() {
        assert_eq!(
            parse_fuse_rmdir_request(1, b"docs"),
            Err(RmdirRequestParseError::MissingNulTerminator)
        );
        assert_eq!(
            parse_fuse_rmdir_request(1, b"\0"),
            Err(RmdirRequestParseError::EmptyName)
        );
        assert_eq!(
            parse_fuse_rmdir_request(1, b"docs\0extra"),
            Err(RmdirRequestParseError::TrailingBytes {
                expected: 5,
                actual: 10
            })
        );
    }

    #[test]
    fn access_request_parses_kernel_payload() {
        let payload = fuse_access_payload(0x0000_0005, 0xffff_ffff);

        let request = parse_fuse_access_request(&payload).expect("access request");

        assert_eq!(request, FuseAccessRequest { mask: 0x0000_0005 });
    }

    #[test]
    fn access_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_access_request(&[0_u8; FUSE_ACCESS_IN_WIRE_SIZE - 1]),
            Err(AccessRequestParseError::BufferTooSmall {
                required: FUSE_ACCESS_IN_WIRE_SIZE,
                actual: FUSE_ACCESS_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn access_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_access_request(&[0_u8; FUSE_ACCESS_IN_WIRE_SIZE + 1]),
            Err(AccessRequestParseError::TrailingBytes {
                expected: FUSE_ACCESS_IN_WIRE_SIZE,
                actual: FUSE_ACCESS_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn parse_fuse_readdir_request_parses_kernel_payload() {
        let payload = fuse_readdir_payload(
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
            4096,
            0x20,
            0x2122_2324_2526_2728,
            0x40,
            0xdead_beef,
        );

        let request = parse_fuse_readdir_request(&payload).expect("readdir request");

        assert_eq!(
            request,
            FuseReaddirRequest {
                fh: 0x0102_0304_0506_0708,
                offset: 0x1112_1314_1516_1718,
                size: 4096,
                read_flags: 0x20,
                lock_owner: 0x2122_2324_2526_2728,
                flags: 0x40
            }
        );
    }

    #[test]
    fn parse_fuse_readdir_request_preserves_zero_size_request() {
        let payload = fuse_readdir_payload(7, 11, 0, 0, 13, 0, 0);

        let request = parse_fuse_readdir_request(&payload).expect("readdir request");

        assert_eq!(request.size, 0);
        assert_eq!(request.offset, 11);
    }

    #[test]
    fn parse_fuse_readdir_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_readdir_request(&[0_u8; FUSE_READDIR_IN_WIRE_SIZE - 1]),
            Err(ReaddirRequestParseError::BufferTooSmall {
                required: FUSE_READDIR_IN_WIRE_SIZE,
                actual: FUSE_READDIR_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn parse_fuse_readdir_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_readdir_request(&[0_u8; FUSE_READDIR_IN_WIRE_SIZE + 1]),
            Err(ReaddirRequestParseError::TrailingBytes {
                expected: FUSE_READDIR_IN_WIRE_SIZE,
                actual: FUSE_READDIR_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn read_request_parses_kernel_payload() {
        let payload = fuse_read_payload(
            0x11_22_33_44_55_66_77_88,
            0x99_aa_bb_cc_dd_ee_ff_00,
            131_072,
            0x5,
            0x12_34_56_78_9a_bc_de_f0,
            0xa5a5_0001,
        );

        let request = parse_fuse_read_request(&payload).expect("read request");

        assert_eq!(
            request,
            FuseReadRequest {
                fh: 0x11_22_33_44_55_66_77_88,
                offset: 0x99_aa_bb_cc_dd_ee_ff_00,
                size: 131_072,
                read_flags: 0x5,
                lock_owner: 0x12_34_56_78_9a_bc_de_f0,
                flags: 0xa5a5_0001
            }
        );
    }

    #[test]
    fn read_request_ignores_padding_bytes() {
        let mut payload = fuse_read_payload(9, 4096, 8192, 0, 7, 0x20);
        put_u32_le(&mut payload, 36, 0xffff_ffff);

        let request = parse_fuse_read_request(&payload).expect("read request");

        assert_eq!(request.fh, 9);
        assert_eq!(request.offset, 4096);
        assert_eq!(request.size, 8192);
        assert_eq!(request.read_flags, 0);
        assert_eq!(request.lock_owner, 7);
        assert_eq!(request.flags, 0x20);
    }

    #[test]
    fn read_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_read_request(&[0_u8; FUSE_READ_IN_WIRE_SIZE - 1]),
            Err(ReadRequestParseError::BufferTooSmall {
                required: FUSE_READ_IN_WIRE_SIZE,
                actual: FUSE_READ_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn read_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_read_request(&[0_u8; FUSE_READ_IN_WIRE_SIZE + 1]),
            Err(ReadRequestParseError::TrailingBytes {
                expected: FUSE_READ_IN_WIRE_SIZE,
                actual: FUSE_READ_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn readdirplus_request_parses_kernel_payload() {
        let payload = fuse_readdirplus_payload(
            0x11_22_33_44,
            4096,
            8192,
            readdirplus_read_flags::FUSE_READ_LOCKOWNER,
            0xaa_bb_cc_dd,
            0o200000,
        );

        let request = parse_fuse_readdirplus_request(&payload).expect("readdirplus request");

        assert_eq!(
            request,
            FuseReaddirplusRequest {
                fh: 0x11_22_33_44,
                offset: 4096,
                size: 8192,
                read_flags: readdirplus_read_flags::FUSE_READ_LOCKOWNER,
                lock_owner: 0xaa_bb_cc_dd,
                flags: 0o200000
            }
        );
    }

    #[test]
    fn readdirplus_request_accepts_absent_lock_owner_flag() {
        let payload = fuse_readdirplus_payload(9, u64::MAX - 7, u32::MAX, 0, 0, 0x8000_0000);

        let request = parse_fuse_readdirplus_request(&payload).expect("readdirplus request");

        assert_eq!(request.fh, 9);
        assert_eq!(request.offset, u64::MAX - 7);
        assert_eq!(request.size, u32::MAX);
        assert_eq!(request.read_flags, 0);
        assert_eq!(request.lock_owner, 0);
        assert_eq!(request.flags, 0x8000_0000);
    }

    #[test]
    fn readdirplus_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_readdirplus_request(&[0_u8; FUSE_READDIRPLUS_IN_WIRE_SIZE - 1]),
            Err(ReaddirplusRequestParseError::BufferTooSmall {
                required: FUSE_READDIRPLUS_IN_WIRE_SIZE,
                actual: FUSE_READDIRPLUS_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn readdirplus_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_readdirplus_request(&[0_u8; FUSE_READDIRPLUS_IN_WIRE_SIZE + 1]),
            Err(ReaddirplusRequestParseError::TrailingBytes {
                expected: FUSE_READDIRPLUS_IN_WIRE_SIZE,
                actual: FUSE_READDIRPLUS_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn readdirplus_request_rejects_unsupported_read_flags() {
        let unsupported_flags = readdirplus_read_flags::FUSE_READ_LOCKOWNER | 0x8000_0000;
        let payload = fuse_readdirplus_payload(1, 2, 3, unsupported_flags, 4, 5);

        assert_eq!(
            parse_fuse_readdirplus_request(&payload),
            Err(ReaddirplusRequestParseError::UnsupportedReadFlags {
                supported: readdirplus_read_flags::FUSE_READ_LOCKOWNER,
                actual: unsupported_flags
            })
        );
    }

    #[test]
    fn fsync_request_parses_kernel_payload() {
        let payload = fuse_fsync_payload(0x0102_0304_0506_0708, fsync_flags::FUSE_FSYNC_FDATASYNC);

        let request = parse_fuse_fsync_request(&payload).expect("fsync request");

        assert_eq!(
            request,
            FuseFsyncRequest {
                fh: 0x0102_0304_0506_0708,
                fsync_flags: fsync_flags::FUSE_FSYNC_FDATASYNC
            }
        );
    }

    #[test]
    fn fsync_request_preserves_zero_and_unknown_flags() {
        let zero =
            parse_fuse_fsync_request(&fuse_fsync_payload(7, 0)).expect("zero-flags fsync request");
        let unknown_flags = fsync_flags::FUSE_FSYNC_FDATASYNC | 0x8000_0000;
        let unknown = parse_fuse_fsync_request(&fuse_fsync_payload(9, unknown_flags))
            .expect("unknown-flags fsync request");

        assert_eq!(zero.fsync_flags, 0);
        assert_eq!(unknown.fh, 9);
        assert_eq!(unknown.fsync_flags, unknown_flags);
    }

    #[test]
    fn fsync_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_fsync_request(&[0_u8; FUSE_FSYNC_IN_WIRE_SIZE - 1]),
            Err(FsyncRequestParseError::PayloadTooShort {
                required: FUSE_FSYNC_IN_WIRE_SIZE,
                actual: FUSE_FSYNC_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn fsync_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_fsync_request(&[0_u8; FUSE_FSYNC_IN_WIRE_SIZE + 1]),
            Err(FsyncRequestParseError::TrailingBytes {
                expected: FUSE_FSYNC_IN_WIRE_SIZE,
                actual: FUSE_FSYNC_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn fsyncdir_request_parses_kernel_payload() {
        let payload =
            fuse_fsyncdir_payload(0x0102_0304_0506_0708, fsync_flags::FUSE_FSYNC_FDATASYNC);

        let request = parse_fuse_fsyncdir_request(&payload).expect("fsyncdir request");

        assert_eq!(
            request,
            FuseFsyncdirRequest {
                fh: 0x0102_0304_0506_0708,
                fsync_flags: fsync_flags::FUSE_FSYNC_FDATASYNC
            }
        );
    }

    #[test]
    fn fsyncdir_request_preserves_zero_and_unknown_flags() {
        let zero = parse_fuse_fsyncdir_request(&fuse_fsyncdir_payload(7, 0))
            .expect("zero-flags fsyncdir request");
        let unknown_flags = fsync_flags::FUSE_FSYNC_FDATASYNC | 0x8000_0000;
        let unknown = parse_fuse_fsyncdir_request(&fuse_fsyncdir_payload(9, unknown_flags))
            .expect("unknown-flags fsyncdir request");

        assert_eq!(zero.fsync_flags, 0);
        assert_eq!(unknown.fh, 9);
        assert_eq!(unknown.fsync_flags, unknown_flags);
    }

    #[test]
    fn fsyncdir_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_fsyncdir_request(&[0_u8; FUSE_FSYNCDIR_IN_WIRE_SIZE - 1]),
            Err(FsyncdirRequestParseError::PayloadTooShort {
                required: FUSE_FSYNCDIR_IN_WIRE_SIZE,
                actual: FUSE_FSYNCDIR_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn fsyncdir_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_fsyncdir_request(&[0_u8; FUSE_FSYNCDIR_IN_WIRE_SIZE + 1]),
            Err(FsyncdirRequestParseError::TrailingBytes {
                expected: FUSE_FSYNCDIR_IN_WIRE_SIZE,
                actual: FUSE_FSYNCDIR_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn fsyncdir_fdatasync_flag_matches_linux_fuse_abi() {
        assert_eq!(fsync_flags::FUSE_FSYNC_FDATASYNC, 1 << 0);
    }

    #[test]
    fn bmap_request_parses_kernel_payload() {
        let payload = fuse_bmap_payload(0x0102_0304_0506_0708, 4096, 0);

        let request = parse_fuse_bmap_request(&payload).expect("bmap request");

        assert_eq!(
            request,
            FuseBmapRequest {
                block: 0x0102_0304_0506_0708,
                blocksize: 4096,
                padding: 0
            }
        );
    }

    #[test]
    fn bmap_request_preserves_zero_block_and_zero_blocksize() {
        let request =
            parse_fuse_bmap_request(&fuse_bmap_payload(0, 0, 0)).expect("zero bmap request");

        assert_eq!(
            request,
            FuseBmapRequest {
                block: 0,
                blocksize: 0,
                padding: 0
            }
        );
    }

    #[test]
    fn bmap_request_preserves_max_block_and_blocksize() {
        let request = parse_fuse_bmap_request(&fuse_bmap_payload(u64::MAX, u32::MAX, u32::MAX))
            .expect("max bmap request");

        assert_eq!(
            request,
            FuseBmapRequest {
                block: u64::MAX,
                blocksize: u32::MAX,
                padding: u32::MAX
            }
        );
    }

    #[test]
    fn bmap_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_bmap_request(&[0_u8; FUSE_BMAP_IN_WIRE_SIZE - 1]),
            Err(BmapRequestParseError::PayloadTooShort {
                required: FUSE_BMAP_IN_WIRE_SIZE,
                actual: FUSE_BMAP_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn bmap_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_bmap_request(&[0_u8; FUSE_BMAP_IN_WIRE_SIZE + 1]),
            Err(BmapRequestParseError::TrailingBytes {
                expected: FUSE_BMAP_IN_WIRE_SIZE,
                actual: FUSE_BMAP_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn release_request_parses_kernel_payload() {
        let payload = fuse_release_payload(0x11_22_33_44, 0o100_002, 0x8000_0001, u64::MAX - 5);

        let request = parse_fuse_release_request(&payload).expect("release request");

        assert_eq!(
            request,
            FuseReleaseRequest {
                fh: 0x11_22_33_44,
                flags: 0o100_002,
                release_flags: 0x8000_0001,
                lock_owner: u64::MAX - 5
            }
        );
    }

    #[test]
    fn release_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_release_request(&[0_u8; FUSE_RELEASE_IN_WIRE_SIZE - 1]),
            Err(ReleaseRequestParseError::BufferTooSmall {
                required: FUSE_RELEASE_IN_WIRE_SIZE,
                actual: FUSE_RELEASE_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn release_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_release_request(&[0_u8; FUSE_RELEASE_IN_WIRE_SIZE + 1]),
            Err(ReleaseRequestParseError::TrailingBytes {
                expected: FUSE_RELEASE_IN_WIRE_SIZE,
                actual: FUSE_RELEASE_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn releasedir_request_parses_kernel_payload() {
        let payload = fuse_releasedir_payload(
            0x99_88_77_66_55_44_33_22,
            0o200_000,
            0x4000_0002,
            u64::MAX - 17,
        );

        let request = parse_fuse_releasedir_request(&payload).expect("releasedir request");

        assert_eq!(
            request,
            FuseReleasedirRequest {
                fh: 0x99_88_77_66_55_44_33_22,
                flags: 0o200_000,
                release_flags: 0x4000_0002,
                lock_owner: u64::MAX - 17
            }
        );
    }

    #[test]
    fn releasedir_request_rejects_empty_payload() {
        assert_eq!(
            parse_fuse_releasedir_request(&[]),
            Err(ReleasedirRequestParseError::BufferTooSmall {
                required: FUSE_RELEASEDIR_IN_WIRE_SIZE,
                actual: 0
            })
        );
    }

    #[test]
    fn releasedir_request_rejects_short_field_boundary_payloads() {
        let payload_8 = [0_u8; 8];
        let payload_16 = [0_u8; 16];
        let payload_23 = [0_u8; FUSE_RELEASEDIR_IN_WIRE_SIZE - 1];

        for payload in [&payload_8[..], &payload_16[..], &payload_23[..]] {
            let actual = payload.len();
            assert_eq!(
                parse_fuse_releasedir_request(payload),
                Err(ReleasedirRequestParseError::BufferTooSmall {
                    required: FUSE_RELEASEDIR_IN_WIRE_SIZE,
                    actual
                })
            );
        }
    }

    #[test]
    fn releasedir_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_releasedir_request(&[0_u8; FUSE_RELEASEDIR_IN_WIRE_SIZE + 1]),
            Err(ReleasedirRequestParseError::TrailingBytes {
                expected: FUSE_RELEASEDIR_IN_WIRE_SIZE,
                actual: FUSE_RELEASEDIR_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn rename_request_parses_newdir_and_dual_names() {
        let mut payload = [0_u8; FUSE_RENAME_IN_WIRE_SIZE + 16];
        fill_rename_payload_header(&mut payload, 0x0102_0304_0506_0708);
        payload[FUSE_RENAME_IN_WIRE_SIZE..].copy_from_slice(b"old.txt\0new.txt\0");

        let request = parse_fuse_rename_request(&payload).expect("rename request");

        assert_eq!(request.newdir, 0x0102_0304_0506_0708);
        assert_eq!(request.flags, 0);
        assert_eq!(request.old_name, b"old.txt");
        assert_eq!(request.new_name, b"new.txt");
    }

    #[test]
    fn rename2_request_preserves_flags_and_dual_names() {
        let mut payload = [0_u8; FUSE_RENAME2_IN_WIRE_SIZE + 8];
        let flags = 0x1 | 0x2 | 0x8000_0000;
        fill_rename2_payload_header(&mut payload, 42, flags);
        payload[FUSE_RENAME2_IN_WIRE_SIZE..].copy_from_slice(b"old\0new\0");

        let request = parse_fuse_rename2_request(&payload).expect("rename2 request");

        assert_eq!(
            request,
            FuseRenameRequest {
                newdir: 42,
                flags,
                old_name: b"old",
                new_name: b"new",
            }
        );
    }

    #[test]
    fn rename_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_rename_request(&[0_u8; FUSE_RENAME_IN_WIRE_SIZE - 1]),
            Err(RenameRequestParseError::BufferTooSmall {
                required: FUSE_RENAME_IN_WIRE_SIZE,
                actual: FUSE_RENAME_IN_WIRE_SIZE - 1
            })
        );
        assert_eq!(
            parse_fuse_rename2_request(&[0_u8; FUSE_RENAME2_IN_WIRE_SIZE - 1]),
            Err(RenameRequestParseError::BufferTooSmall {
                required: FUSE_RENAME2_IN_WIRE_SIZE,
                actual: FUSE_RENAME2_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn rename_request_rejects_empty_old_and_new_names() {
        let mut empty_old = [0_u8; FUSE_RENAME_IN_WIRE_SIZE + 5];
        fill_rename_payload_header(&mut empty_old, 9);
        empty_old[FUSE_RENAME_IN_WIRE_SIZE..].copy_from_slice(b"\0new\0");

        assert_eq!(
            parse_fuse_rename_request(&empty_old),
            Err(RenameRequestParseError::EmptyOldName)
        );

        let mut empty_new = [0_u8; FUSE_RENAME_IN_WIRE_SIZE + 5];
        fill_rename_payload_header(&mut empty_new, 9);
        empty_new[FUSE_RENAME_IN_WIRE_SIZE..].copy_from_slice(b"old\0\0");

        assert_eq!(
            parse_fuse_rename_request(&empty_new),
            Err(RenameRequestParseError::EmptyNewName)
        );
    }

    #[test]
    fn rename_request_rejects_missing_nul_terminator() {
        let mut missing_old_nul = [0_u8; FUSE_RENAME_IN_WIRE_SIZE + 7];
        fill_rename_payload_header(&mut missing_old_nul, 9);
        missing_old_nul[FUSE_RENAME_IN_WIRE_SIZE..].copy_from_slice(b"old.txt");

        assert_eq!(
            parse_fuse_rename_request(&missing_old_nul),
            Err(RenameRequestParseError::MissingNulTerminator)
        );

        let mut missing_new_nul = [0_u8; FUSE_RENAME_IN_WIRE_SIZE + 7];
        fill_rename_payload_header(&mut missing_new_nul, 9);
        missing_new_nul[FUSE_RENAME_IN_WIRE_SIZE..].copy_from_slice(b"old\0new");

        assert_eq!(
            parse_fuse_rename_request(&missing_new_nul),
            Err(RenameRequestParseError::MissingNulTerminator)
        );
    }

    #[test]
    fn rename_request_rejects_name_too_long() {
        let mut payload = [0_u8; FUSE_RENAME_IN_WIRE_SIZE + FUSE_NAME_MAX_BYTES + 1 + 1 + 3];
        fill_rename_payload_header(&mut payload, 9);
        let old_name_start = FUSE_RENAME_IN_WIRE_SIZE;
        let old_name_end = old_name_start + FUSE_NAME_MAX_BYTES + 1;
        payload[old_name_start..old_name_end].fill(b'a');
        payload[old_name_end] = 0;
        payload[old_name_end + 1..].copy_from_slice(b"ok\0");

        assert_eq!(
            parse_fuse_rename_request(&payload),
            Err(RenameRequestParseError::NameTooLong {
                max: FUSE_NAME_MAX_BYTES,
                actual: FUSE_NAME_MAX_BYTES + 1
            })
        );
    }

    #[test]
    fn rename_request_rejects_trailing_bytes() {
        let mut payload = [0_u8; FUSE_RENAME2_IN_WIRE_SIZE + 12];
        fill_rename2_payload_header(&mut payload, 9, 2);
        payload[FUSE_RENAME2_IN_WIRE_SIZE..].copy_from_slice(b"old\0new\0tail");

        assert_eq!(
            parse_fuse_rename2_request(&payload),
            Err(RenameRequestParseError::TrailingBytes {
                expected: FUSE_RENAME2_IN_WIRE_SIZE + 8,
                actual: FUSE_RENAME2_IN_WIRE_SIZE + 12
            })
        );
    }

    #[test]
    fn flush_request_parses_kernel_payload() {
        let payload = fuse_flush_payload(
            0x11_22_33_44,
            0x5566_7788,
            0x99aa_bbcc,
            0xdead_beef_cafe_f00d,
        );

        let request = parse_fuse_flush_request(&payload).expect("flush request");

        assert_eq!(
            request,
            FuseFlushRequest {
                fh: 0x11_22_33_44,
                unused: 0x5566_7788,
                padding: 0x99aa_bbcc,
                lock_owner: 0xdead_beef_cafe_f00d
            }
        );
    }

    #[test]
    fn flush_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_flush_request(&[0_u8; FUSE_FLUSH_IN_WIRE_SIZE - 1]),
            Err(FlushRequestParseError::BufferTooSmall {
                required: FUSE_FLUSH_IN_WIRE_SIZE,
                actual: FUSE_FLUSH_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn flush_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_flush_request(&[0_u8; FUSE_FLUSH_IN_WIRE_SIZE + 1]),
            Err(FlushRequestParseError::TrailingBytes {
                expected: FUSE_FLUSH_IN_WIRE_SIZE,
                actual: FUSE_FLUSH_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn poll_request_parses_kernel_payload() {
        let payload = fuse_poll_payload(
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
            0x2122_2324,
            0x3132_3334,
        );

        let request = parse_fuse_poll_request(&payload).expect("poll request");

        assert_eq!(
            request,
            FusePollRequest {
                fh: 0x0102_0304_0506_0708,
                kh: 0x1112_1314_1516_1718,
                flags: 0x2122_2324,
                events: 0x3132_3334
            }
        );
    }

    #[test]
    fn poll_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_poll_request(&[0_u8; FUSE_POLL_IN_WIRE_SIZE - 1]),
            Err(PollRequestParseError::BufferTooSmall {
                required: FUSE_POLL_IN_WIRE_SIZE,
                actual: FUSE_POLL_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn poll_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_poll_request(&[0_u8; FUSE_POLL_IN_WIRE_SIZE + 1]),
            Err(PollRequestParseError::TrailingBytes {
                expected: FUSE_POLL_IN_WIRE_SIZE,
                actual: FUSE_POLL_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn symlink_request_parses_name_and_target() {
        let request =
            parse_fuse_symlink_request(b"link-name\0target/path\0").expect("symlink request");

        assert_eq!(request.name, b"link-name");
        assert_eq!(request.target, b"target/path");
    }

    #[test]
    fn symlink_request_parses_minimal_non_empty_components() {
        let request = parse_fuse_symlink_request(b"l\0t\0").expect("symlink request");

        assert_eq!(
            request,
            FuseSymlinkRequest {
                name: b"l",
                target: b"t"
            }
        );
    }

    #[test]
    fn symlink_request_rejects_too_short_payload() {
        assert_eq!(
            parse_fuse_symlink_request(&[0_u8]),
            Err(SymlinkRequestParseError::TooShort {
                required: FUSE_SYMLINK_MIN_WIRE_SIZE,
                actual: 1
            })
        );
    }

    #[test]
    fn symlink_request_rejects_invalid_name() {
        assert_eq!(
            parse_fuse_symlink_request(b"\0target\0"),
            Err(SymlinkRequestParseError::InvalidName)
        );
        assert_eq!(
            parse_fuse_symlink_request(b"link-target"),
            Err(SymlinkRequestParseError::InvalidName)
        );
    }

    #[test]
    fn symlink_request_rejects_missing_target() {
        assert_eq!(
            parse_fuse_symlink_request(b"link\0target"),
            Err(SymlinkRequestParseError::MissingTarget)
        );
        assert_eq!(
            parse_fuse_symlink_request(b"link\0\0"),
            Err(SymlinkRequestParseError::MissingTarget)
        );
    }

    #[test]
    fn fallocate_request_parses_kernel_payload() {
        let mode = fallocate_flags::FALLOC_FL_PUNCH_HOLE
            | fallocate_flags::FALLOC_FL_KEEP_SIZE
            | fallocate_flags::FALLOC_FL_ZERO_RANGE;
        let payload = fuse_fallocate_payload(0x11_22_33_44, 4096, 8192, mode);

        let request = parse_fuse_fallocate_request(&payload).expect("fallocate request");

        assert_eq!(request.fh, 0x11_22_33_44);
        assert_eq!(request.offset, 4096);
        assert_eq!(request.length, 8192);
        assert_eq!(request.mode, mode);
    }

    #[test]
    fn fallocate_request_preserves_deferred_and_unknown_mode_bits() {
        let mode = fallocate_flags::FALLOC_FL_COLLAPSE_RANGE
            | fallocate_flags::FALLOC_FL_INSERT_RANGE
            | fallocate_flags::FALLOC_FL_UNSHARE_RANGE
            | 0x8000_0000;
        let payload = fuse_fallocate_payload(9, u64::MAX - 7, 7, mode);

        let request = parse_fuse_fallocate_request(&payload).expect("fallocate request");

        assert_eq!(
            request,
            FuseFallocateRequest {
                fh: 9,
                offset: u64::MAX - 7,
                length: 7,
                mode
            }
        );
    }

    #[test]
    fn fallocate_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_fallocate_request(&[0_u8; FUSE_FALLOCATE_IN_WIRE_SIZE - 1]),
            Err(FallocateRequestParseError::BufferTooSmall {
                required: FUSE_FALLOCATE_IN_WIRE_SIZE,
                actual: FUSE_FALLOCATE_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn fallocate_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_fallocate_request(&[0_u8; FUSE_FALLOCATE_IN_WIRE_SIZE + 1]),
            Err(FallocateRequestParseError::TrailingBytes {
                expected: FUSE_FALLOCATE_IN_WIRE_SIZE,
                actual: FUSE_FALLOCATE_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn lseek_request_parses_kernel_payload() {
        let payload = fuse_lseek_payload(
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
            lseek_whence::SEEK_DATA,
        );

        let request = parse_fuse_lseek_request(&payload).expect("lseek request");

        assert_eq!(request.fh, 0x0102_0304_0506_0708);
        assert_eq!(request.offset, 0x1112_1314_1516_1718);
        assert_eq!(request.whence, lseek_whence::SEEK_DATA);
    }

    #[test]
    fn lseek_request_preserves_known_and_unknown_whence_values() {
        let whence_values = [
            lseek_whence::SEEK_SET,
            lseek_whence::SEEK_CUR,
            lseek_whence::SEEK_END,
            lseek_whence::SEEK_DATA,
            lseek_whence::SEEK_HOLE,
            0x8000_0000,
        ];

        for whence in whence_values {
            let payload = fuse_lseek_payload(9, u64::MAX - 11, whence);
            let request = parse_fuse_lseek_request(&payload).expect("lseek request");

            assert_eq!(
                request,
                FuseLseekRequest {
                    fh: 9,
                    offset: u64::MAX - 11,
                    whence
                }
            );
        }
    }

    #[test]
    fn lseek_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_lseek_request(&[0_u8; FUSE_LSEEK_IN_WIRE_SIZE - 1]),
            Err(LseekRequestParseError::BufferTooSmall {
                required: FUSE_LSEEK_IN_WIRE_SIZE,
                actual: FUSE_LSEEK_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn lseek_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_lseek_request(&[0_u8; FUSE_LSEEK_IN_WIRE_SIZE + 1]),
            Err(LseekRequestParseError::TrailingBytes {
                expected: FUSE_LSEEK_IN_WIRE_SIZE,
                actual: FUSE_LSEEK_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn lseek_request_rejects_nonzero_padding() {
        let mut payload = fuse_lseek_payload(1, 2, lseek_whence::SEEK_SET);
        put_u32_le(&mut payload, 20, 1);

        assert_eq!(
            parse_fuse_lseek_request(&payload),
            Err(LseekRequestParseError::InvalidPadding)
        );
    }

    #[test]
    fn ioctl_request_parses_compact_payload() {
        let flags = FUSE_IOCTL_UNRESTRICTED | FUSE_IOCTL_DIR;
        let payload = fuse_ioctl_payload(
            0x0102_0304_0506_0708,
            flags,
            0x1122_3344,
            0x5152_5354_5556_5758,
        );

        let request = parse_fuse_ioctl_request(&payload).expect("ioctl request");

        assert_eq!(
            request,
            FuseIoctlRequest {
                fh: 0x0102_0304_0506_0708,
                flags,
                cmd: 0x1122_3344,
                arg: 0x5152_5354_5556_5758,
                in_size: 0,
                out_size: 0,
            }
        );
    }

    #[test]
    fn ioctl_request_parses_extended_payload_when_compat_flag_is_set() {
        let flags = FUSE_IOCTL_COMPAT | FUSE_IOCTL_RETRY;
        let payload = fuse_ioctl_extended_payload(9, flags, 0x4455_6677, u64::MAX - 9, 4096, 8192);

        let request = parse_fuse_ioctl_request(&payload).expect("ioctl request");

        assert_eq!(
            request,
            FuseIoctlRequest {
                fh: 9,
                flags,
                cmd: 0x4455_6677,
                arg: u64::MAX - 9,
                in_size: 4096,
                out_size: 8192,
            }
        );
    }

    #[test]
    fn ioctl_request_rejects_truncated_fixed_header() {
        assert_eq!(
            parse_fuse_ioctl_request(&[0_u8; FUSE_IOCTL_IN_WIRE_SIZE - 1]),
            Err(IoctlRequestParseError::BufferTooSmall {
                required: FUSE_IOCTL_IN_WIRE_SIZE,
                actual: FUSE_IOCTL_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn ioctl_request_rejects_truncated_extended_payload() {
        let payload = fuse_ioctl_payload(1, FUSE_IOCTL_COMPAT, 2, 3);

        assert_eq!(
            parse_fuse_ioctl_request(&payload),
            Err(IoctlRequestParseError::BufferTooSmall {
                required: FUSE_IOCTL_IN_EXTENDED_WIRE_SIZE,
                actual: FUSE_IOCTL_IN_WIRE_SIZE
            })
        );
    }

    #[test]
    fn ioctl_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_ioctl_request(&[0_u8; FUSE_IOCTL_IN_WIRE_SIZE + 1]),
            Err(IoctlRequestParseError::TrailingBytes {
                expected: FUSE_IOCTL_IN_WIRE_SIZE,
                actual: FUSE_IOCTL_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn ioctl_request_rejects_unsupported_flags() {
        let flags = FUSE_IOCTL_SUPPORTED_FLAGS | 0x8000_0000;
        let payload = fuse_ioctl_payload(1, flags, 2, 3);

        assert_eq!(
            parse_fuse_ioctl_request(&payload),
            Err(IoctlRequestParseError::UnsupportedFlags {
                supported: FUSE_IOCTL_SUPPORTED_FLAGS,
                actual: flags
            })
        );
    }

    #[test]
    fn copy_file_range_request_parses_kernel_payload() {
        let payload = fuse_copy_file_range_payload(
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
            0x2122_2324_2526_2728,
            0x3132_3334_3536_3738,
            0x4142_4344_4546_4748,
            0x5152_5354_5556_5758,
            0x6162_6364_6566_6768,
        );

        let request =
            parse_fuse_copy_file_range_request(&payload).expect("copy_file_range request");

        assert_eq!(
            request,
            FuseCopyFileRangeRequest {
                fh_in: 0x0102_0304_0506_0708,
                off_in: 0x1112_1314_1516_1718,
                nodeid_out: 0x2122_2324_2526_2728,
                fh_out: 0x3132_3334_3536_3738,
                off_out: 0x4142_4344_4546_4748,
                len: 0x5152_5354_5556_5758,
                flags: 0x6162_6364_6566_6768,
            }
        );
    }

    #[test]
    fn copy_file_range_request_preserves_zero_length_and_unknown_flags() {
        let payload = fuse_copy_file_range_payload(7, u64::MAX - 1, 8, 9, u64::MAX, 0, u64::MAX);

        let request =
            parse_fuse_copy_file_range_request(&payload).expect("copy_file_range request");

        assert_eq!(
            request,
            FuseCopyFileRangeRequest {
                fh_in: 7,
                off_in: u64::MAX - 1,
                nodeid_out: 8,
                fh_out: 9,
                off_out: u64::MAX,
                len: 0,
                flags: u64::MAX,
            }
        );
    }

    #[test]
    fn copy_file_range_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_copy_file_range_request(&[0_u8; FUSE_COPY_FILE_RANGE_IN_WIRE_SIZE - 1]),
            Err(CopyFileRangeRequestParseError::BufferTooSmall {
                required: FUSE_COPY_FILE_RANGE_IN_WIRE_SIZE,
                actual: FUSE_COPY_FILE_RANGE_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn copy_file_range_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_copy_file_range_request(&[0_u8; FUSE_COPY_FILE_RANGE_IN_WIRE_SIZE + 1]),
            Err(CopyFileRangeRequestParseError::TrailingBytes {
                expected: FUSE_COPY_FILE_RANGE_IN_WIRE_SIZE,
                actual: FUSE_COPY_FILE_RANGE_IN_WIRE_SIZE + 1
            })
        );
    }

    #[test]
    fn write_request_parses_header_and_data_payload() {
        let write_flags = write_flags::FUSE_WRITE_LOCKOWNER | 0x8000_0000;
        let mut payload = [0_u8; FUSE_WRITE_IN_WIRE_SIZE + 5];
        put_fuse_write_header(
            &mut payload,
            FuseWriteHeaderFixture {
                fh: 0x0123_4567_89ab_cdef,
                offset: 4096,
                size: 5,
                write_flags,
                lock_owner: 0xfedc_ba98_7654_3210,
                flags: 0x55aa_aa55,
                padding: 0xa5a5_5a5a,
            },
        );
        payload[FUSE_WRITE_IN_WIRE_SIZE..].copy_from_slice(b"hello");

        let request = parse_fuse_write_request(&payload).expect("write request");

        assert_eq!(request.fh, 0x0123_4567_89ab_cdef);
        assert_eq!(request.offset, 4096);
        assert_eq!(request.size, 5);
        assert_eq!(request.write_flags, write_flags);
        assert_eq!(request.lock_owner, 0xfedc_ba98_7654_3210);
        assert_eq!(request.flags, 0x55aa_aa55);
        assert_eq!(request.padding, 0xa5a5_5a5a);
        assert_eq!(request.data, b"hello");
    }

    #[test]
    fn write_request_accepts_zero_length_payload() {
        let mut payload = [0_u8; FUSE_WRITE_IN_WIRE_SIZE];
        put_fuse_write_header(
            &mut payload,
            FuseWriteHeaderFixture {
                fh: 9,
                offset: 0,
                size: 0,
                write_flags: 0,
                lock_owner: 0,
                flags: 0,
                padding: 0,
            },
        );

        let request = parse_fuse_write_request(&payload).expect("write request");

        assert_eq!(request.size, 0);
        assert!(request.data.is_empty());
    }

    #[test]
    fn write_request_rejects_truncated_header() {
        assert_eq!(
            parse_fuse_write_request(&[0_u8; FUSE_WRITE_IN_WIRE_SIZE - 1]),
            Err(WriteRequestParseError::BufferTooSmall {
                required: FUSE_WRITE_IN_WIRE_SIZE,
                actual: FUSE_WRITE_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn write_request_rejects_truncated_data_payload() {
        let mut payload = [0_u8; FUSE_WRITE_IN_WIRE_SIZE + 3];
        put_fuse_write_header(
            &mut payload,
            FuseWriteHeaderFixture {
                fh: 7,
                offset: 0,
                size: 4,
                write_flags: 0,
                lock_owner: 0,
                flags: 0,
                padding: 0,
            },
        );
        payload[FUSE_WRITE_IN_WIRE_SIZE..].copy_from_slice(b"abc");

        assert_eq!(
            parse_fuse_write_request(&payload),
            Err(WriteRequestParseError::BufferTooSmall {
                required: FUSE_WRITE_IN_WIRE_SIZE + 4,
                actual: FUSE_WRITE_IN_WIRE_SIZE + 3
            })
        );
    }

    #[test]
    fn write_request_rejects_trailing_bytes_after_declared_data() {
        let mut payload = [0_u8; FUSE_WRITE_IN_WIRE_SIZE + 5];
        put_fuse_write_header(
            &mut payload,
            FuseWriteHeaderFixture {
                fh: 7,
                offset: 0,
                size: 4,
                write_flags: 0,
                lock_owner: 0,
                flags: 0,
                padding: 0,
            },
        );
        payload[FUSE_WRITE_IN_WIRE_SIZE..FUSE_WRITE_IN_WIRE_SIZE + 4].copy_from_slice(b"abcd");
        payload[FUSE_WRITE_IN_WIRE_SIZE + 4] = 0xff;

        assert_eq!(
            parse_fuse_write_request(&payload),
            Err(WriteRequestParseError::TrailingBytes {
                expected: FUSE_WRITE_IN_WIRE_SIZE + 4,
                actual: FUSE_WRITE_IN_WIRE_SIZE + 5
            })
        );
    }

    #[test]
    fn getlk_request_parses_kernel_payload() {
        let payload = fuse_lk_payload(
            0x1122_3344_5566_7788,
            0x8877_6655_4433_2211,
            4096,
            8191,
            FUSE_LK_TYPE_RDLCK,
            1234,
            0x40,
        );

        let request = parse_fuse_getlk_request(&payload).expect("getlk request");

        assert_eq!(
            request,
            FuseGetlkRequest {
                fh: 0x1122_3344_5566_7788,
                owner: 0x8877_6655_4433_2211,
                lk: FuseLockIn {
                    start: 4096,
                    end: 8191,
                    typ: FUSE_LK_TYPE_RDLCK,
                    pid: 1234,
                },
                lk_flags: 0x40,
            }
        );
    }

    #[test]
    fn setlk_request_parses_nonblocking_kernel_payload() {
        let payload = fuse_lk_payload(
            7,
            0xfeed_face_cafe_beef,
            0,
            u64::MAX,
            FUSE_LK_TYPE_WRLCK,
            42,
            0,
        );

        let request = parse_fuse_setlk_request(&payload).expect("setlk request");

        assert_eq!(
            request,
            FuseSetlkRequest {
                fh: 7,
                owner: 0xfeed_face_cafe_beef,
                lk: FuseLockIn {
                    start: 0,
                    end: u64::MAX,
                    typ: FUSE_LK_TYPE_WRLCK,
                    pid: 42,
                },
                lk_flags: 0,
                sleep: false,
            }
        );
    }

    #[test]
    fn setlkw_request_marks_sleeping_lock_request() {
        let payload = fuse_lk_payload(11, 99, 128, 255, FUSE_LK_TYPE_UNLCK, 77, 0x8000_0000);

        let request = parse_fuse_setlkw_request(&payload).expect("setlkw request");

        assert_eq!(
            request,
            FuseSetlkRequest {
                fh: 11,
                owner: 99,
                lk: FuseLockIn {
                    start: 128,
                    end: 255,
                    typ: FUSE_LK_TYPE_UNLCK,
                    pid: 77,
                },
                lk_flags: 0x8000_0000,
                sleep: true,
            }
        );
    }

    #[test]
    fn getlk_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_getlk_request(&[0_u8; FUSE_GETLK_IN_WIRE_SIZE - 1]),
            Err(GetlkRequestParseError::BufferTooSmall {
                required: FUSE_GETLK_IN_WIRE_SIZE,
                actual: FUSE_GETLK_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn setlk_request_rejects_truncated_payload() {
        assert_eq!(
            parse_fuse_setlk_request(&[0_u8; FUSE_SETLK_IN_WIRE_SIZE - 1]),
            Err(SetlkRequestParseError::BufferTooSmall {
                required: FUSE_SETLK_IN_WIRE_SIZE,
                actual: FUSE_SETLK_IN_WIRE_SIZE - 1
            })
        );
        assert_eq!(
            parse_fuse_setlkw_request(&[0_u8; FUSE_SETLKW_IN_WIRE_SIZE - 1]),
            Err(SetlkRequestParseError::BufferTooSmall {
                required: FUSE_SETLKW_IN_WIRE_SIZE,
                actual: FUSE_SETLKW_IN_WIRE_SIZE - 1
            })
        );
    }

    #[test]
    fn setlk_request_rejects_trailing_bytes() {
        assert_eq!(
            parse_fuse_setlk_request(&[0_u8; FUSE_SETLK_IN_WIRE_SIZE + 1]),
            Err(SetlkRequestParseError::TrailingBytes {
                expected: FUSE_SETLK_IN_WIRE_SIZE,
                actual: FUSE_SETLK_IN_WIRE_SIZE + 1
            })
        );
        assert_eq!(
            parse_fuse_setlkw_request(&[0_u8; FUSE_SETLKW_IN_WIRE_SIZE + 1]),
            Err(SetlkRequestParseError::TrailingBytes {
                expected: FUSE_SETLKW_IN_WIRE_SIZE,
                actual: FUSE_SETLKW_IN_WIRE_SIZE + 1
            })
        );
    }

    // ── FIEMAP wire-format tests ──────────────────────────────────────────

    #[test]
    fn fiemap_input_parses_valid_header() {
        let mut data = [0u8; 32];
        data[0..8].copy_from_slice(&4096u64.to_le_bytes());
        data[8..16].copy_from_slice(&8192u64.to_le_bytes());
        data[16..20].copy_from_slice(&0x1u32.to_le_bytes()); // flags
        data[24..28].copy_from_slice(&4u32.to_le_bytes()); // extent_count

        let input = parse_fiemap_input(&data).expect("parse fiemap input");
        assert_eq!(input.fm_start, 4096);
        assert_eq!(input.fm_length, 8192);
        assert_eq!(input.fm_flags, 0x1);
        assert_eq!(input.fm_extent_count, 4);
    }

    #[test]
    fn fiemap_input_rejects_short_header() {
        assert!(parse_fiemap_input(&[0u8; 31]).is_none());
    }

    #[test]
    fn fiemap_output_encode_produces_correct_wire_format() {
        let ext = FiemapExtent::new(0, 1024, 4096, FiemapExtent::FLAG_UNWRITTEN);
        let output = FiemapOutput {
            fm_mapped_extents: 1,
            extents: std::vec![ext],
        };
        let buf = output.encode(0, 4096, 0);
        // Header (32 bytes) + 1 extent (56 bytes) = 88 bytes
        assert_eq!(buf.len(), 88);
        // Check header fields
        assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 0); // fm_start
        assert_eq!(u64::from_le_bytes(buf[8..16].try_into().unwrap()), 4096); // fm_length
        assert_eq!(u32::from_le_bytes(buf[16..20].try_into().unwrap()), 0); // fm_flags
        assert_eq!(u32::from_le_bytes(buf[20..24].try_into().unwrap()), 1); // fm_mapped_extents
        assert_eq!(u32::from_le_bytes(buf[24..28].try_into().unwrap()), 1); // fm_extent_count
                                                                            // Check extent fields
        let ext_off = FIEMAP_HEADER_SIZE;
        assert_eq!(
            u64::from_le_bytes(buf[ext_off..ext_off + 8].try_into().unwrap()),
            0
        ); // fe_logical
        assert_eq!(
            u64::from_le_bytes(buf[ext_off + 8..ext_off + 16].try_into().unwrap()),
            1024
        ); // fe_physical
        assert_eq!(
            u64::from_le_bytes(buf[ext_off + 16..ext_off + 24].try_into().unwrap()),
            4096
        ); // fe_length
        assert_eq!(
            u32::from_le_bytes(buf[ext_off + 40..ext_off + 44].try_into().unwrap()),
            FiemapExtent::FLAG_UNWRITTEN
        ); // fe_flags
    }

    #[test]
    fn fiemap_output_encode_sets_last_flag_on_final_extent() {
        let ext1 = FiemapExtent::new(0, 0, 4096, 0);
        let mut ext2 = FiemapExtent::new(4096, 4096, 4096, 0);
        ext2.fe_flags |= FiemapExtent::FLAG_LAST;
        let output = FiemapOutput {
            fm_mapped_extents: 2,
            extents: std::vec![ext1, ext2],
        };
        let buf = output.encode(0, 8192, 0);
        assert_eq!(buf.len(), 32 + 56 * 2);
        // Check second extent's flags
        let ext2_off = FIEMAP_HEADER_SIZE + FIEMAP_EXTENT_SIZE;
        let flags = u32::from_le_bytes(buf[ext2_off + 40..ext2_off + 44].try_into().unwrap());
        assert_eq!(flags & FiemapExtent::FLAG_LAST, FiemapExtent::FLAG_LAST);
    }
}
