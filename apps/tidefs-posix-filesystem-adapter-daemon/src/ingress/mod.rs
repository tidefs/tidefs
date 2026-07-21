// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! P5-02 FUSE ingress reader set: request classification, admission against backpressure.
//!
//! Part of the P5-02 classified multipool topology for the userspace FUSE runtime.
//! This seam family is one of 10 explicit crate boundaries that separate ingress,
//! scheduling, workers, reply commit, and maintenance so they do not blur
//! into one daemon blob.

use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterBackpressureStateRecord, PosixFilesystemAdapterFuseIngressFrame,
    PosixFilesystemAdapterRequestClass, PosixFilesystemAdapterRequestContextMirrorRecord,
    PosixFilesystemAdapterShardKeyPolicy, PosixFilesystemAdapterWriteStagingRequest,
};

/// Re-export all P5-02 request-queue types and runtime functions for this seam family.
pub const SEAM_FAMILY_DOC: &str = concat!("seam.", env!("CARGO_PKG_NAME"), ".    P5-02.v0");

/// FUSE write operation opcode (kernel ABI).
pub const FUSE_WRITE_OPCODE: u32 = 16;
/// FUSE fallocate operation opcode (kernel ABI).
pub const FUSE_FALLOCATE_OPCODE: u32 = 43;
/// Kernel writeback-cache marker. The adapter never negotiates the
/// corresponding capability, so ingress rejects this bit.
#[cfg(test)]
const FUSE_WRITE_CACHE: u32 = 1;
/// FUSE_WRITE_LOCKOWNER marks `lock_owner` as valid.
pub const FUSE_WRITE_LOCKOWNER: u32 = 2;
/// FUSE_WRITE_KILL_PRIV / FUSE_WRITE_KILL_SUIDGID may be carried downstream.
pub const FUSE_WRITE_KILL_PRIV: u32 = 4;
/// POSIX EBADF.
pub const WRITE_ERRNO_EBADF: i32 = 9;
/// POSIX EINVAL.
pub const WRITE_ERRNO_EINVAL: i32 = 22;

const SUPPORTED_WRITE_FLAGS: u32 = FUSE_WRITE_LOCKOWNER | FUSE_WRITE_KILL_PRIV;

/// Open-file handle projection needed by write ingress classification.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IngressWriteHandle {
    pub inode: u64,
    pub writable: bool,
}

/// Handle lookup boundary owned by the runtime/open-file tracker.
pub trait IngressWriteHandleTable {
    fn lookup_write_handle(&self, fh: u64) -> Option<IngressWriteHandle>;
}

/// Raw write request fields extracted from the FUSE wire request.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RawFuseWriteRequest {
    pub unique: u64,
    pub inode: u64,
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub payload_len: u32,
    pub write_flags: u32,
    pub lock_owner: u64,
}

/// Write classification result handed to the IO staging worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClassifiedWrite {
    DirtyExtent(PosixFilesystemAdapterWriteStagingRequest),
    Rejected { unique: u64, errno: i32 },
}

impl ClassifiedWrite {
    #[must_use]
    pub const fn errno(self) -> Option<i32> {
        match self {
            Self::Rejected { errno, .. } => Some(errno),
            Self::DirtyExtent(_) => None,
        }
    }
}

/// Stateless FUSE write classifier.
#[derive(Clone, Copy, Debug, Default)]
pub struct WriteClassifier;

impl WriteClassifier {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn classify<H: IngressWriteHandleTable>(
        &self,
        handles: &H,
        request: RawFuseWriteRequest,
    ) -> ClassifiedWrite {
        if request.size != request.payload_len
            || request.offset.checked_add(request.size as u64).is_none()
        {
            return ClassifiedWrite::Rejected {
                unique: request.unique,
                errno: WRITE_ERRNO_EINVAL,
            };
        }

        if (request.write_flags & !SUPPORTED_WRITE_FLAGS) != 0 {
            return ClassifiedWrite::Rejected {
                unique: request.unique,
                errno: WRITE_ERRNO_EINVAL,
            };
        }

        let Some(handle) = handles.lookup_write_handle(request.fh) else {
            return ClassifiedWrite::Rejected {
                unique: request.unique,
                errno: WRITE_ERRNO_EBADF,
            };
        };

        if !handle.writable || handle.inode != request.inode {
            return ClassifiedWrite::Rejected {
                unique: request.unique,
                errno: WRITE_ERRNO_EBADF,
            };
        }

        ClassifiedWrite::DirtyExtent(PosixFilesystemAdapterWriteStagingRequest {
            unique: request.unique,
            inode: request.inode,
            fh: request.fh,
            offset: request.offset,
            length: request.size,
            write_flags: request.write_flags,
            lock_owner: request.lock_owner,
            _reserved: [0_u32; 2],
        })
    }
}

// ── Backpressure admission law ──────────────────────────────────────────────

/// P5-02 §8 backpressure ceiling constants.
pub mod backpressure_constants {
    /// Maximum inflight request count before admission blocks non-urgent classes.
    pub const MAX_INFLIGHT_REQUEST_COUNT: u64 = 4096;

    /// Maximum inflight request bytes before admission blocks non-urgent classes.
    pub const MAX_INFLIGHT_REQUEST_BYTES: u64 = 64 * 1024 * 1024;

    /// Maximum reply bytes inflight before backpressure applies.
    pub const MAX_REPLY_BYTES_INFLIGHT: u64 = 128 * 1024 * 1024;

    /// Maximum dirty-window bytes (writeback queue capacity).
    pub const MAX_DIRTY_WINDOW_BYTES: u64 = 256 * 1024 * 1024;

    /// Maximum lock-wait count before admission blocks.
    pub const MAX_LOCK_WAIT_COUNT: u32 = 256;

    /// Reserved capacity floor for queue_class_0 (urgent control).
    /// Heavy read/write may not starve INTERRUPT, FORGET, or DESTROY.
    pub const RESERVED_URGENT_CAPACITY: u64 = 16;

    /// Reserved entry count for control lane.
    pub const RESERVED_URGENT_ENTRY_COUNT: u64 = 4;
}

/// Admit (or reject) a request based on backpressure state and request class.
///
/// §8: `queue_class_0.control_urgent` always passes. Other classes block
/// when backpressure ceilings are exceeded.
#[must_use]
pub fn admit_request(
    backpressure: &PosixFilesystemAdapterBackpressureStateRecord,
    request_class: PosixFilesystemAdapterRequestClass,
) -> bool {
    match request_class {
        // Control-urgent always admitted (reserved capacity floor).
        PosixFilesystemAdapterRequestClass::ControlUrgent => true,

        // Lock-wait: check lock_wait_count ceiling.
        PosixFilesystemAdapterRequestClass::LockWait => {
            backpressure.lock_wait_count < backpressure_constants::MAX_LOCK_WAIT_COUNT
                && backpressure.inflight_request_count
                    < backpressure_constants::MAX_INFLIGHT_REQUEST_COUNT
                        .saturating_sub(backpressure_constants::RESERVED_URGENT_ENTRY_COUNT)
        }

        // File writeback: check dirty_window_bytes ceiling.
        PosixFilesystemAdapterRequestClass::FileWriteback => {
            backpressure.dirty_window_bytes < backpressure_constants::MAX_DIRTY_WINDOW_BYTES
                && backpressure.inflight_request_count
                    < backpressure_constants::MAX_INFLIGHT_REQUEST_COUNT
                        .saturating_sub(backpressure_constants::RESERVED_URGENT_ENTRY_COUNT)
        }

        // Bulk class: check bulk_read_reply_bytes and inflight bytes.
        PosixFilesystemAdapterRequestClass::FileRead => {
            backpressure.bulk_read_reply_bytes < backpressure_constants::MAX_REPLY_BYTES_INFLIGHT
                && backpressure.inflight_request_bytes
                    < backpressure_constants::MAX_INFLIGHT_REQUEST_BYTES
                        .saturating_sub(backpressure_constants::RESERVED_URGENT_CAPACITY)
        }

        // All other classes: check general inflight count and bytes, minus urgent reserve.
        PosixFilesystemAdapterRequestClass::MetaRead
        | PosixFilesystemAdapterRequestClass::NamespaceMut
        | PosixFilesystemAdapterRequestClass::DirStream
        | PosixFilesystemAdapterRequestClass::Maintenance => {
            backpressure.inflight_request_count
                < backpressure_constants::MAX_INFLIGHT_REQUEST_COUNT
                    .saturating_sub(backpressure_constants::RESERVED_URGENT_ENTRY_COUNT)
                && backpressure.inflight_request_bytes
                    < backpressure_constants::MAX_INFLIGHT_REQUEST_BYTES
                        .saturating_sub(backpressure_constants::RESERVED_URGENT_CAPACITY)
        }
    }
}

/// Update backpressure counters on ingress of a new request.
///
/// Call after admission passes.
pub fn update_backpressure_on_ingress(
    backpressure: &mut PosixFilesystemAdapterBackpressureStateRecord,
    request_class: PosixFilesystemAdapterRequestClass,
    payload_len: u32,
) {
    backpressure.inflight_request_count = backpressure.inflight_request_count.saturating_add(1);
    backpressure.inflight_request_bytes = backpressure
        .inflight_request_bytes
        .saturating_add(payload_len as u64);

    match request_class {
        PosixFilesystemAdapterRequestClass::FileWriteback => {
            backpressure.dirty_window_bytes = backpressure
                .dirty_window_bytes
                .saturating_add(payload_len as u64);
        }
        PosixFilesystemAdapterRequestClass::FileRead => {
            backpressure.bulk_read_reply_bytes = backpressure
                .bulk_read_reply_bytes
                .saturating_add(payload_len as u64);
        }
        PosixFilesystemAdapterRequestClass::LockWait => {
            backpressure.lock_wait_count = backpressure.lock_wait_count.saturating_add(1);
        }
        PosixFilesystemAdapterRequestClass::Maintenance => {
            backpressure.maintenance_backlog = backpressure.maintenance_backlog.saturating_add(1);
        }
        _ => {}
    }
}

/// Update backpressure counters on completion/reply of a request.
///
/// Call when a reply is committed or a request is drained.
pub fn update_backpressure_on_drain(
    backpressure: &mut PosixFilesystemAdapterBackpressureStateRecord,
    request_class: PosixFilesystemAdapterRequestClass,
    payload_len: u32,
    reply_len: u32,
) {
    backpressure.inflight_request_count = backpressure.inflight_request_count.saturating_sub(1);
    backpressure.inflight_request_bytes = backpressure
        .inflight_request_bytes
        .saturating_sub(payload_len as u64);
    backpressure.reply_bytes_inflight = backpressure
        .reply_bytes_inflight
        .saturating_sub(reply_len as u64);

    match request_class {
        PosixFilesystemAdapterRequestClass::FileWriteback => {
            backpressure.dirty_window_bytes = backpressure
                .dirty_window_bytes
                .saturating_sub(payload_len as u64);
        }
        PosixFilesystemAdapterRequestClass::FileRead => {
            backpressure.bulk_read_reply_bytes = backpressure
                .bulk_read_reply_bytes
                .saturating_sub(payload_len as u64);
        }
        PosixFilesystemAdapterRequestClass::LockWait => {
            backpressure.lock_wait_count = backpressure.lock_wait_count.saturating_sub(1);
        }
        PosixFilesystemAdapterRequestClass::Maintenance => {
            backpressure.maintenance_backlog = backpressure.maintenance_backlog.saturating_sub(1);
        }
        _ => {}
    }
}

// ── Request context classification ──────────────────────────────────────────

/// Build a request context mirror from raw FUSE header fields.
///
/// The caller supplies the opcode and shard key; classification
/// uses the fusewire crate's `classify_fuse_request` and
/// `derive_shard_key_policy`.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn classify_request_context(
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    opcode: u32,
    request_class: PosixFilesystemAdapterRequestClass,
    shard_key_policy: PosixFilesystemAdapterShardKeyPolicy,
    shard_key: u64,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    PosixFilesystemAdapterRequestContextMirrorRecord {
        unique,
        nodeid,
        uid,
        gid,
        pid,
        opcode,
        request_class: request_class.as_u32(),
        shard_key_policy: shard_key_policy.as_u32(),
        shard_key,
        _reserved: [0_u32; 1],
    }
}

// ── Lookup-specific classification ─────────────────────────────────────────

/// FUSE lookup operation opcode (kernel ABI).
pub const FUSE_LOOKUP_OPCODE: u32 = 1;

/// Classify an incoming FUSE_LOOKUP request.
///
/// Sets the request class to `MetaRead`, shard key policy to `ParentDir`,
/// and shard key to the parent inode. The FUSE opcode is set to
/// `FUSE_LOOKUP_OPCODE`.
#[must_use]
pub fn classify_lookup_request(
    unique: u64,
    parent_ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        parent_ino,
        uid,
        gid,
        pid,
        FUSE_LOOKUP_OPCODE,
        PosixFilesystemAdapterRequestClass::MetaRead,
        PosixFilesystemAdapterShardKeyPolicy::ParentDir,
        parent_ino,
    )
}

// ── Read-side operation classification ─────────────────────────────────────

/// FUSE getattr operation opcode (kernel ABI).
pub const FUSE_GETATTR_OPCODE: u32 = 3;

/// FUSE setattr operation opcode (kernel ABI).
pub const FUSE_SETATTR_OPCODE: u32 = 4;

/// FUSE readlink operation opcode (kernel ABI).
pub const FUSE_READLINK_OPCODE: u32 = 5;

/// FUSE open operation opcode (kernel ABI).
pub const FUSE_OPEN_OPCODE: u32 = 14;

/// FUSE read operation opcode (kernel ABI).
pub const FUSE_READ_OPCODE: u32 = 15;

/// FUSE statfs operation opcode (kernel ABI).
pub const FUSE_STATFS_OPCODE: u32 = 17;

/// FUSE release operation opcode (kernel ABI).
pub const FUSE_RELEASE_OPCODE: u32 = 18;

/// FUSE fsync operation opcode (kernel ABI).
pub const FUSE_FSYNC_OPCODE: u32 = 20;

/// FUSE setxattr operation opcode (kernel ABI).
pub const FUSE_SETXATTR_OPCODE: u32 = 21;

/// FUSE getxattr operation opcode (kernel ABI).
pub const FUSE_GETXATTR_OPCODE: u32 = 22;

/// FUSE listxattr operation opcode (kernel ABI).
pub const FUSE_LISTXATTR_OPCODE: u32 = 23;

/// FUSE removexattr operation opcode (kernel ABI).
pub const FUSE_REMOVEXATTR_OPCODE: u32 = 24;

/// FUSE flush operation opcode (kernel ABI).
pub const FUSE_FLUSH_OPCODE: u32 = 25;

/// FUSE opendir operation opcode (kernel ABI).
pub const FUSE_OPENDIR_OPCODE: u32 = 27;

/// FUSE readdir operation opcode (kernel ABI).
pub const FUSE_READDIR_OPCODE: u32 = 28;

/// FUSE releasedir operation opcode (kernel ABI).
pub const FUSE_RELEASEDIR_OPCODE: u32 = 29;

/// FUSE fsyncdir operation opcode (kernel ABI).
pub const FUSE_FSYNCDIR_OPCODE: u32 = 30;

/// FUSE getlk operation opcode (kernel ABI).
pub const FUSE_GETLK_OPCODE: u32 = 31;

/// FUSE setlk operation opcode (kernel ABI).
pub const FUSE_SETLK_OPCODE: u32 = 32;

/// FUSE setlkw operation opcode (kernel ABI).
pub const FUSE_SETLKW_OPCODE: u32 = 33;

/// FUSE access operation opcode (kernel ABI).
pub const FUSE_ACCESS_OPCODE: u32 = 34;

/// FUSE bmap operation opcode (kernel ABI).
pub const FUSE_BMAP_OPCODE: u32 = 37;

/// FUSE ioctl operation opcode (kernel ABI).
pub const FUSE_IOCTL_OPCODE: u32 = 39;

/// FUSE poll operation opcode (kernel ABI).
pub const FUSE_POLL_OPCODE: u32 = 40;

/// FUSE readdirplus operation opcode (kernel ABI).
pub const FUSE_READDIRPLUS_OPCODE: u32 = 44;

/// FUSE lseek operation opcode (kernel ABI).
pub const FUSE_LSEEK_OPCODE: u32 = 46;

/// FUSE copy_file_range operation opcode (kernel ABI).
pub const FUSE_COPY_FILE_RANGE_OPCODE: u32 = 47;

/// FUSE syncfs operation opcode (kernel ABI).
pub const FUSE_SYNCFS_OPCODE: u32 = 50;

/// FUSE statx operation opcode (kernel ABI).
pub const FUSE_STATX_OPCODE: u32 = 52;

/// Classify an incoming FUSE_GETATTR request.
#[must_use]
pub fn classify_getattr_request(
    unique: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_GETATTR_OPCODE,
        PosixFilesystemAdapterRequestClass::MetaRead,
        PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
        ino,
    )
}

/// Classify an incoming FUSE_SETATTR request.
#[must_use]
pub fn classify_setattr_request(
    unique: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_SETATTR_OPCODE,
        PosixFilesystemAdapterRequestClass::FileWriteback,
        PosixFilesystemAdapterShardKeyPolicy::ObjectWrite,
        ino,
    )
}

/// Classify an incoming FUSE_READLINK request.
#[must_use]
pub fn classify_readlink_request(
    unique: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_READLINK_OPCODE,
        PosixFilesystemAdapterRequestClass::MetaRead,
        PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
        ino,
    )
}

/// Classify an incoming FUSE_OPEN request.
#[must_use]
pub fn classify_open_request(
    unique: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_OPEN_OPCODE,
        PosixFilesystemAdapterRequestClass::MetaRead,
        PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
        ino,
    )
}

/// Classify an incoming FUSE_READ request.
#[must_use]
pub fn classify_read_request(
    unique: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_READ_OPCODE,
        PosixFilesystemAdapterRequestClass::FileRead,
        PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
        ino,
    )
}

/// Classify an incoming FUSE_WRITE request.
#[must_use]
pub fn classify_write_request(
    unique: u64,
    ino: u64,
    fh: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_WRITE_OPCODE,
        PosixFilesystemAdapterRequestClass::FileWriteback,
        PosixFilesystemAdapterShardKeyPolicy::ObjectWrite,
        fh,
    )
}

/// Classify an incoming FUSE_FALLOCATE request.
#[must_use]
pub fn classify_fallocate_request(
    unique: u64,
    ino: u64,
    _fh: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_FALLOCATE_OPCODE,
        PosixFilesystemAdapterRequestClass::FileWriteback,
        PosixFilesystemAdapterShardKeyPolicy::ObjectWrite,
        ino,
    )
}

/// Classify an incoming FUSE_FLUSH request.
#[must_use]
pub fn classify_flush_request(
    unique: u64,
    ino: u64,
    fh: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_FLUSH_OPCODE,
        PosixFilesystemAdapterRequestClass::FileWriteback,
        PosixFilesystemAdapterShardKeyPolicy::ObjectWrite,
        fh,
    )
}

/// Classify an incoming FUSE_FSYNC request.
#[must_use]
pub fn classify_fsync_request(
    unique: u64,
    ino: u64,
    fh: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_FSYNC_OPCODE,
        PosixFilesystemAdapterRequestClass::FileWriteback,
        PosixFilesystemAdapterShardKeyPolicy::ObjectWrite,
        fh,
    )
}

/// Classify an incoming FUSE_SETXATTR request.
#[must_use]
pub fn classify_setxattr_request(
    unique: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_SETXATTR_OPCODE,
        PosixFilesystemAdapterRequestClass::NamespaceMut,
        PosixFilesystemAdapterShardKeyPolicy::ParentDir,
        ino,
    )
}

/// Classify an incoming FUSE_GETXATTR request.
#[must_use]
pub fn classify_getxattr_request(
    unique: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_GETXATTR_OPCODE,
        PosixFilesystemAdapterRequestClass::NamespaceMut,
        PosixFilesystemAdapterShardKeyPolicy::ParentDir,
        ino,
    )
}

/// Classify an incoming FUSE_LISTXATTR request.
#[must_use]
pub fn classify_listxattr_request(
    unique: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_LISTXATTR_OPCODE,
        PosixFilesystemAdapterRequestClass::NamespaceMut,
        PosixFilesystemAdapterShardKeyPolicy::ParentDir,
        ino,
    )
}

/// Classify an incoming FUSE_REMOVEXATTR request.
#[must_use]
pub fn classify_removexattr_request(
    unique: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_REMOVEXATTR_OPCODE,
        PosixFilesystemAdapterRequestClass::NamespaceMut,
        PosixFilesystemAdapterShardKeyPolicy::ParentDir,
        ino,
    )
}

/// Classify an incoming FUSE_LSEEK request.
#[must_use]
pub fn classify_lseek_request(
    unique: u64,
    ino: u64,
    fh: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_LSEEK_OPCODE,
        PosixFilesystemAdapterRequestClass::FileRead,
        PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
        fh,
    )
}

/// Classify an incoming FUSE_IOCTL request.
#[must_use]
pub fn classify_ioctl_request(
    unique: u64,
    ino: u64,
    fh: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_IOCTL_OPCODE,
        PosixFilesystemAdapterRequestClass::FileRead,
        PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
        fh,
    )
}

/// Classify an incoming FUSE_POLL request.
#[must_use]
pub fn classify_poll_request(
    unique: u64,
    ino: u64,
    fh: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_POLL_OPCODE,
        PosixFilesystemAdapterRequestClass::FileRead,
        PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
        fh,
    )
}

/// Classify an incoming FUSE_COPY_FILE_RANGE request.
#[must_use]
pub fn classify_copy_file_range_request(
    unique: u64,
    ino: u64,
    fh_in: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_COPY_FILE_RANGE_OPCODE,
        PosixFilesystemAdapterRequestClass::FileWriteback,
        PosixFilesystemAdapterShardKeyPolicy::ObjectWrite,
        fh_in,
    )
}

/// Classify an incoming FUSE_STATFS request.
#[must_use]
pub fn classify_statfs_request(
    unique: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_STATFS_OPCODE,
        PosixFilesystemAdapterRequestClass::MetaRead,
        PosixFilesystemAdapterShardKeyPolicy::Session,
        ino,
    )
}

/// Classify an incoming FUSE_SYNCFS request.
#[must_use]
pub fn classify_syncfs_request(
    unique: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_SYNCFS_OPCODE,
        PosixFilesystemAdapterRequestClass::FileWriteback,
        PosixFilesystemAdapterShardKeyPolicy::Session,
        0,
    )
}

/// Classify an incoming FUSE_STATX request.
#[must_use]
pub fn classify_statx_request(
    unique: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_STATX_OPCODE,
        PosixFilesystemAdapterRequestClass::MetaRead,
        PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
        ino,
    )
}

/// Classify an incoming FUSE_RELEASE request.
#[must_use]
pub fn classify_release_request(
    unique: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_RELEASE_OPCODE,
        PosixFilesystemAdapterRequestClass::MetaRead,
        PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
        ino,
    )
}

/// Classify an incoming FUSE_OPENDIR request.
#[must_use]
pub fn classify_opendir_request(
    unique: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_OPENDIR_OPCODE,
        PosixFilesystemAdapterRequestClass::DirStream,
        PosixFilesystemAdapterShardKeyPolicy::DirHandle,
        ino,
    )
}

/// Classify an incoming FUSE_READDIR request.
#[must_use]
pub fn classify_readdir_request(
    unique: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_READDIR_OPCODE,
        PosixFilesystemAdapterRequestClass::DirStream,
        PosixFilesystemAdapterShardKeyPolicy::DirHandle,
        ino,
    )
}

/// Classify an incoming FUSE_RELEASEDIR request.
#[must_use]
pub fn classify_releasedir_request(
    unique: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_RELEASEDIR_OPCODE,
        PosixFilesystemAdapterRequestClass::DirStream,
        PosixFilesystemAdapterShardKeyPolicy::DirHandle,
        ino,
    )
}

/// Classify an incoming FUSE_FSYNCDIR request.
#[must_use]
pub fn classify_fsyncdir_request(
    unique: u64,
    ino: u64,
    fh: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_FSYNCDIR_OPCODE,
        PosixFilesystemAdapterRequestClass::DirStream,
        PosixFilesystemAdapterShardKeyPolicy::DirHandle,
        fh,
    )
}

/// Classify an incoming FUSE_GETLK request.
#[must_use]
pub fn classify_getlk_request(
    unique: u64,
    ino: u64,
    fh: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_GETLK_OPCODE,
        PosixFilesystemAdapterRequestClass::LockWait,
        PosixFilesystemAdapterShardKeyPolicy::LockScope,
        fh,
    )
}

/// Classify an incoming FUSE_SETLK request.
#[must_use]
pub fn classify_setlk_request(
    unique: u64,
    ino: u64,
    fh: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_SETLK_OPCODE,
        PosixFilesystemAdapterRequestClass::LockWait,
        PosixFilesystemAdapterShardKeyPolicy::LockScope,
        fh,
    )
}

/// Classify an incoming FUSE_SETLKW request.
#[must_use]
pub fn classify_setlkw_request(
    unique: u64,
    ino: u64,
    fh: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_SETLKW_OPCODE,
        PosixFilesystemAdapterRequestClass::LockWait,
        PosixFilesystemAdapterShardKeyPolicy::LockScope,
        fh,
    )
}

/// Classify an incoming BSD flock operation.
///
/// Linux FUSE carries flock through the lock request family using
/// `FUSE_LK_FLOCK`; it does not define a standalone FLOCK request opcode.
#[must_use]
pub fn classify_flock_request(
    unique: u64,
    ino: u64,
    fh: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_SETLK_OPCODE,
        PosixFilesystemAdapterRequestClass::LockWait,
        PosixFilesystemAdapterShardKeyPolicy::LockScope,
        fh,
    )
}

/// Classify an incoming FUSE_ACCESS request.
#[must_use]
pub fn classify_access_request(
    unique: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_ACCESS_OPCODE,
        PosixFilesystemAdapterRequestClass::MetaRead,
        PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
        ino,
    )
}

/// Classify an incoming FUSE_BMAP request.
#[must_use]
pub fn classify_bmap_request(
    unique: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_BMAP_OPCODE,
        PosixFilesystemAdapterRequestClass::MetaRead,
        PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
        ino,
    )
}

/// Classify an incoming FUSE_READDIRPLUS request.
#[must_use]
pub fn classify_readdirplus_request(
    unique: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        ino,
        uid,
        gid,
        pid,
        FUSE_READDIRPLUS_OPCODE,
        PosixFilesystemAdapterRequestClass::DirStream,
        PosixFilesystemAdapterShardKeyPolicy::DirHandle,
        ino,
    )
}

// ── Rename-specific classification ──────────────────────────────────────────

/// FUSE rename (renameat) operation opcode (kernel ABI).
pub const FUSE_RENAME_OPCODE: u32 = 12;

/// FUSE rename2 (renameat2) operation opcode (kernel ABI).
pub const FUSE_RENAME2_OPCODE: u32 = 45;

/// FUSE symlink operation opcode (kernel ABI).
pub const FUSE_SYMLINK_OPCODE: u32 = 6;

/// FUSE mknod operation opcode (kernel ABI).
pub const FUSE_MKNOD_OPCODE: u32 = 8;

/// FUSE mkdir operation opcode (kernel ABI).
pub const FUSE_MKDIR_OPCODE: u32 = 9;

/// FUSE unlink operation opcode (kernel ABI).
pub const FUSE_UNLINK_OPCODE: u32 = 10;

/// FUSE rmdir operation opcode (kernel ABI).
pub const FUSE_RMDIR_OPCODE: u32 = 11;

/// FUSE link operation opcode (kernel ABI).
pub const FUSE_LINK_OPCODE: u32 = 13;

/// FUSE create operation opcode (kernel ABI).
pub const FUSE_CREATE_OPCODE: u32 = 35;

/// FUSE tmpfile operation opcode (kernel ABI).
pub const FUSE_TMPFILE_OPCODE: u32 = 51;

/// Classify an incoming FUSE_RENAME request.
///
/// Sets the request class to `NamespaceMut`, shard key policy to `DualParentPair`,
/// and shard key to the XOR of old_parent and new_parent inode numbers.
/// The FUSE opcode is set to `FUSE_RENAME_OPCODE`.
#[must_use]
pub fn classify_rename_request(
    unique: u64,
    old_parent_ino: u64,
    new_parent_ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        old_parent_ino,
        uid,
        gid,
        pid,
        FUSE_RENAME_OPCODE,
        PosixFilesystemAdapterRequestClass::NamespaceMut,
        PosixFilesystemAdapterShardKeyPolicy::DualParentPair,
        old_parent_ino ^ new_parent_ino,
    )
}

/// Classify an incoming FUSE_RENAME2 request (renameat2 with flags).
///
/// Same classification as `classify_rename_request` but uses `FUSE_RENAME2_OPCODE`.
#[must_use]
pub fn classify_rename2_request(
    unique: u64,
    old_parent_ino: u64,
    new_parent_ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        old_parent_ino,
        uid,
        gid,
        pid,
        FUSE_RENAME2_OPCODE,
        PosixFilesystemAdapterRequestClass::NamespaceMut,
        PosixFilesystemAdapterShardKeyPolicy::DualParentPair,
        old_parent_ino ^ new_parent_ino,
    )
}

/// Classify an incoming FUSE_CREATE request.
///
/// Sets the request class to `NamespaceMut`, shard key policy to `ParentDir`,
/// and shard key to the parent inode. The FUSE opcode is set to
/// `FUSE_CREATE_OPCODE`.
#[must_use]
pub fn classify_create_request(
    unique: u64,
    parent_ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        parent_ino,
        uid,
        gid,
        pid,
        FUSE_CREATE_OPCODE,
        PosixFilesystemAdapterRequestClass::NamespaceMut,
        PosixFilesystemAdapterShardKeyPolicy::ParentDir,
        parent_ino,
    )
}

/// Classify an incoming FUSE_TMPFILE request.
///
/// Sets the request class to `NamespaceMut`, shard key policy to `ParentDir`,
/// and shard key to the parent inode. The FUSE opcode is set to
/// `FUSE_TMPFILE_OPCODE`.
#[must_use]
pub fn classify_tmpfile_request(
    unique: u64,
    parent_ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        parent_ino,
        uid,
        gid,
        pid,
        FUSE_TMPFILE_OPCODE,
        PosixFilesystemAdapterRequestClass::NamespaceMut,
        PosixFilesystemAdapterShardKeyPolicy::ParentDir,
        parent_ino,
    )
}

/// Classify an incoming FUSE_MKNOD request.
///
/// Sets the request class to `NamespaceMut`, shard key policy to `ParentDir`,
/// and shard key to the parent inode. The FUSE opcode is set to
/// `FUSE_MKNOD_OPCODE`.
#[must_use]
pub fn classify_mknod_request(
    unique: u64,
    parent_ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        parent_ino,
        uid,
        gid,
        pid,
        FUSE_MKNOD_OPCODE,
        PosixFilesystemAdapterRequestClass::NamespaceMut,
        PosixFilesystemAdapterShardKeyPolicy::ParentDir,
        parent_ino,
    )
}

/// Classify an incoming FUSE_MKDIR request.
///
/// Sets the request class to `NamespaceMut`, shard key policy to `ParentDir`,
/// and shard key to the parent inode. The FUSE opcode is set to
/// `FUSE_MKDIR_OPCODE`.
#[must_use]
pub fn classify_mkdir_request(
    unique: u64,
    parent_ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        parent_ino,
        uid,
        gid,
        pid,
        FUSE_MKDIR_OPCODE,
        PosixFilesystemAdapterRequestClass::NamespaceMut,
        PosixFilesystemAdapterShardKeyPolicy::ParentDir,
        parent_ino,
    )
}

/// Classify an incoming FUSE_UNLINK request.
///
/// Sets the request class to `NamespaceMut`, shard key policy to `ParentDir`,
/// and shard key to the parent inode. The FUSE opcode is set to
/// `FUSE_UNLINK_OPCODE`.
#[must_use]
pub fn classify_unlink_request(
    unique: u64,
    parent_ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        parent_ino,
        uid,
        gid,
        pid,
        FUSE_UNLINK_OPCODE,
        PosixFilesystemAdapterRequestClass::NamespaceMut,
        PosixFilesystemAdapterShardKeyPolicy::ParentDir,
        parent_ino,
    )
}

/// Classify an incoming FUSE_RMDIR request.
///
/// Sets the request class to `NamespaceMut`, shard key policy to `ParentDir`,
/// and shard key to the parent inode. The FUSE opcode is set to
/// `FUSE_RMDIR_OPCODE`.
#[must_use]
pub fn classify_rmdir_request(
    unique: u64,
    parent_ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        parent_ino,
        uid,
        gid,
        pid,
        FUSE_RMDIR_OPCODE,
        PosixFilesystemAdapterRequestClass::NamespaceMut,
        PosixFilesystemAdapterShardKeyPolicy::ParentDir,
        parent_ino,
    )
}

/// Classify an incoming FUSE_SYMLINK request.
///
/// Sets the request class to `NamespaceMut`, shard key policy to `ParentDir`,
/// and shard key to the parent inode. The FUSE opcode is set to
/// `FUSE_SYMLINK_OPCODE`.
#[must_use]
pub fn classify_symlink_request(
    unique: u64,
    parent_ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        parent_ino,
        uid,
        gid,
        pid,
        FUSE_SYMLINK_OPCODE,
        PosixFilesystemAdapterRequestClass::NamespaceMut,
        PosixFilesystemAdapterShardKeyPolicy::ParentDir,
        parent_ino,
    )
}

/// Classify an incoming FUSE_LINK request.
///
/// Sets the request class to `NamespaceMut`, shard key policy to `DualParentPair`,
/// and shard key to the XOR of source inode and destination parent inode. The
/// FUSE opcode is set to `FUSE_LINK_OPCODE`.
#[must_use]
pub fn classify_link_request(
    unique: u64,
    source_ino: u64,
    dest_parent_ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    classify_request_context(
        unique,
        source_ino,
        uid,
        gid,
        pid,
        FUSE_LINK_OPCODE,
        PosixFilesystemAdapterRequestClass::NamespaceMut,
        PosixFilesystemAdapterShardKeyPolicy::DualParentPair,
        source_ino ^ dest_parent_ino,
    )
}
// ── Ingress frame helpers ───────────────────────────────────────────────────

/// Create an ingress frame marker from a frame id and payload length.
#[must_use]
pub fn make_ingress_frame(
    frame_id: u64,
    payload_len: u32,
) -> PosixFilesystemAdapterFuseIngressFrame {
    PosixFilesystemAdapterFuseIngressFrame {
        frame_id,
        payload_len,
        _reserved: [0_u32; 1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_urgent_always_admitted() {
        let bp = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: backpressure_constants::MAX_INFLIGHT_REQUEST_COUNT,
            inflight_request_bytes: backpressure_constants::MAX_INFLIGHT_REQUEST_BYTES,
            dirty_window_bytes: backpressure_constants::MAX_DIRTY_WINDOW_BYTES,
            lock_wait_count: backpressure_constants::MAX_LOCK_WAIT_COUNT,
            ..Default::default()
        };
        assert!(admit_request(
            &bp,
            PosixFilesystemAdapterRequestClass::ControlUrgent
        ));
    }

    #[test]
    fn meta_read_blocked_when_inflight_full() {
        let bp = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: backpressure_constants::MAX_INFLIGHT_REQUEST_COUNT,
            ..Default::default()
        };
        assert!(!admit_request(
            &bp,
            PosixFilesystemAdapterRequestClass::MetaRead
        ));
    }

    #[test]
    fn meta_read_admitted_when_under_ceiling() {
        let bp = PosixFilesystemAdapterBackpressureStateRecord::default();
        assert!(admit_request(
            &bp,
            PosixFilesystemAdapterRequestClass::MetaRead
        ));
    }

    #[test]
    fn lock_wait_blocked_when_count_at_max() {
        let bp = PosixFilesystemAdapterBackpressureStateRecord {
            lock_wait_count: backpressure_constants::MAX_LOCK_WAIT_COUNT,
            ..Default::default()
        };
        assert!(!admit_request(
            &bp,
            PosixFilesystemAdapterRequestClass::LockWait
        ));
    }

    #[test]
    fn file_writeback_blocked_when_dirty_window_full() {
        let bp = PosixFilesystemAdapterBackpressureStateRecord {
            dirty_window_bytes: backpressure_constants::MAX_DIRTY_WINDOW_BYTES,
            ..Default::default()
        };
        assert!(!admit_request(
            &bp,
            PosixFilesystemAdapterRequestClass::FileWriteback
        ));
    }

    #[test]
    fn ingress_updates_counters() {
        let mut bp = PosixFilesystemAdapterBackpressureStateRecord::default();
        update_backpressure_on_ingress(
            &mut bp,
            PosixFilesystemAdapterRequestClass::FileWriteback,
            4096,
        );
        assert_eq!(bp.inflight_request_count, 1);
        assert_eq!(bp.inflight_request_bytes, 4096);
        assert_eq!(bp.dirty_window_bytes, 4096);
    }

    #[test]
    fn drain_reduces_counters() {
        let mut bp = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: 2,
            inflight_request_bytes: 8192,
            dirty_window_bytes: 4096,
            reply_bytes_inflight: 512,
            ..Default::default()
        };
        update_backpressure_on_drain(
            &mut bp,
            PosixFilesystemAdapterRequestClass::FileWriteback,
            4096,
            512,
        );
        assert_eq!(bp.inflight_request_count, 1);
        assert_eq!(bp.inflight_request_bytes, 4096);
        assert_eq!(bp.dirty_window_bytes, 0);
        assert_eq!(bp.reply_bytes_inflight, 0);
    }

    #[test]
    fn lock_wait_ingress_increments_count() {
        let mut bp = PosixFilesystemAdapterBackpressureStateRecord::default();
        update_backpressure_on_ingress(&mut bp, PosixFilesystemAdapterRequestClass::LockWait, 0);
        assert_eq!(bp.lock_wait_count, 1);
        update_backpressure_on_drain(&mut bp, PosixFilesystemAdapterRequestClass::LockWait, 0, 0);
        assert_eq!(bp.lock_wait_count, 0);
    }

    #[test]
    fn maintenance_ingress_increments_backlog() {
        let mut bp = PosixFilesystemAdapterBackpressureStateRecord::default();
        update_backpressure_on_ingress(&mut bp, PosixFilesystemAdapterRequestClass::Maintenance, 0);
        assert_eq!(bp.maintenance_backlog, 1);
        update_backpressure_on_drain(
            &mut bp,
            PosixFilesystemAdapterRequestClass::Maintenance,
            0,
            0,
        );
        assert_eq!(bp.maintenance_backlog, 0);
    }

    #[test]
    fn context_mirror_preserves_fields() {
        let ctx = classify_request_context(
            42,
            100,
            500,
            500,
            1234,
            14,
            PosixFilesystemAdapterRequestClass::FileRead,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
            100,
        );
        assert_eq!(ctx.unique, 42);
        assert_eq!(ctx.nodeid, 100);
        assert_eq!(
            ctx.request_class,
            PosixFilesystemAdapterRequestClass::FileRead.as_u32()
        );
        assert_eq!(
            ctx.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead.as_u32()
        );
        assert_eq!(ctx.shard_key, 100);
    }

    #[test]
    fn classify_lookup_sets_meta_read_class() {
        let ctx = classify_lookup_request(42, 1, 1000, 1000, 1234);
        assert_eq!(ctx.unique, 42);
        assert_eq!(ctx.nodeid, 1);
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1000);
        assert_eq!(ctx.pid, 1234);
        assert_eq!(ctx.opcode, FUSE_LOOKUP_OPCODE);
        assert_eq!(
            ctx.request_class,
            PosixFilesystemAdapterRequestClass::MetaRead.as_u32()
        );
        assert_eq!(
            ctx.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32()
        );
        assert_eq!(ctx.shard_key, 1);
    }

    #[test]
    fn classify_lookup_shard_key_is_parent_ino() {
        let ctx = classify_lookup_request(99, 7, 0, 0, 0);
        assert_eq!(ctx.shard_key, 7);
        assert_eq!(ctx.nodeid, 7);
    }

    fn assert_inode_classifier(
        ctx: PosixFilesystemAdapterRequestContextMirrorRecord,
        opcode: u32,
        request_class: PosixFilesystemAdapterRequestClass,
        shard_key_policy: PosixFilesystemAdapterShardKeyPolicy,
    ) {
        assert_eq!(ctx.unique, 42);
        assert_eq!(ctx.nodeid, 100);
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1000);
        assert_eq!(ctx.pid, 1234);
        assert_eq!(ctx.opcode, opcode);
        assert_eq!(ctx.request_class, request_class.as_u32());
        assert_eq!(ctx.shard_key_policy, shard_key_policy.as_u32());
        assert_eq!(ctx.shard_key, 100);
    }

    #[test]
    fn classify_getattr_sets_meta_read_object_read_class() {
        assert_inode_classifier(
            classify_getattr_request(42, 100, 1000, 1000, 1234),
            FUSE_GETATTR_OPCODE,
            PosixFilesystemAdapterRequestClass::MetaRead,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
        );
    }

    #[test]
    fn classify_setattr_sets_file_writeback_object_write_class() {
        assert_inode_classifier(
            classify_setattr_request(42, 100, 1000, 1000, 1234),
            FUSE_SETATTR_OPCODE,
            PosixFilesystemAdapterRequestClass::FileWriteback,
            PosixFilesystemAdapterShardKeyPolicy::ObjectWrite,
        );
    }

    #[test]
    fn classify_setattr_shards_by_inode() {
        let ctx = classify_setattr_request(7, 0x42, 0, 0, 0);
        assert_eq!(ctx.nodeid, 0x42);
        assert_eq!(ctx.shard_key, 0x42);
    }

    #[test]
    fn classify_readlink_sets_meta_read_object_read_class() {
        assert_inode_classifier(
            classify_readlink_request(42, 100, 1000, 1000, 1234),
            FUSE_READLINK_OPCODE,
            PosixFilesystemAdapterRequestClass::MetaRead,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
        );
    }

    #[test]
    fn classify_open_sets_meta_read_object_read_class() {
        assert_inode_classifier(
            classify_open_request(42, 100, 1000, 1000, 1234),
            FUSE_OPEN_OPCODE,
            PosixFilesystemAdapterRequestClass::MetaRead,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
        );
    }

    #[test]
    fn classify_read_sets_file_read_object_read_class() {
        assert_inode_classifier(
            classify_read_request(42, 100, 1000, 1000, 1234),
            FUSE_READ_OPCODE,
            PosixFilesystemAdapterRequestClass::FileRead,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
        );
    }

    #[test]
    fn classify_write_sets_file_writeback_object_write_class() {
        let ctx = classify_write_request(42, 100, 0xfeed, 1000, 1000, 1234);
        assert_eq!(ctx.unique, 42);
        assert_eq!(ctx.nodeid, 100);
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1000);
        assert_eq!(ctx.pid, 1234);
        assert_eq!(ctx.opcode, FUSE_WRITE_OPCODE);
        assert_eq!(
            ctx.request_class,
            PosixFilesystemAdapterRequestClass::FileWriteback.as_u32()
        );
        assert_eq!(
            ctx.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ObjectWrite.as_u32()
        );
        assert_eq!(ctx.shard_key, 0xfeed);
    }

    #[test]
    fn classify_write_shards_by_file_handle_not_inode() {
        let ctx = classify_write_request(0, 0, u64::MAX, 0, 0, 0);
        assert_eq!(ctx.nodeid, 0);
        assert_eq!(ctx.shard_key, u64::MAX);
        assert_ne!(ctx.shard_key, ctx.nodeid);
    }

    #[test]
    fn classify_fallocate_sets_file_writeback_object_write_class() {
        assert_inode_classifier(
            classify_fallocate_request(42, 100, 9, 1000, 1000, 1234),
            FUSE_FALLOCATE_OPCODE,
            PosixFilesystemAdapterRequestClass::FileWriteback,
            PosixFilesystemAdapterShardKeyPolicy::ObjectWrite,
        );
    }

    #[test]
    fn classify_fallocate_shards_by_inode_not_file_handle() {
        let ctx = classify_fallocate_request(7, 0x42, 0x99, 0, 0, 0);
        assert_eq!(ctx.nodeid, 0x42);
        assert_eq!(ctx.shard_key, 0x42);
        assert_ne!(ctx.shard_key, 0x99);
    }

    #[test]
    fn classify_flush_sets_file_writeback_object_write_class() {
        let ctx = classify_flush_request(42, 100, 0xfeed, 1000, 1000, 1234);
        assert_eq!(ctx.unique, 42);
        assert_eq!(ctx.nodeid, 100);
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1000);
        assert_eq!(ctx.pid, 1234);
        assert_eq!(ctx.opcode, FUSE_FLUSH_OPCODE);
        assert_eq!(
            ctx.request_class,
            PosixFilesystemAdapterRequestClass::FileWriteback.as_u32()
        );
        assert_eq!(
            ctx.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ObjectWrite.as_u32()
        );
        assert_eq!(ctx.shard_key, 0xfeed);
    }

    #[test]
    fn classify_flush_shards_by_file_handle_not_inode() {
        let ctx = classify_flush_request(7, 0x42, 0x99, 0, 0, 0);
        assert_eq!(ctx.nodeid, 0x42);
        assert_eq!(ctx.shard_key, 0x99);
        assert_ne!(ctx.shard_key, ctx.nodeid);
    }

    #[test]
    fn classify_fsync_sets_file_writeback_object_write_class() {
        let ctx = classify_fsync_request(42, 100, 0xfeed, 1000, 1000, 1234);
        assert_eq!(ctx.unique, 42);
        assert_eq!(ctx.nodeid, 100);
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1000);
        assert_eq!(ctx.pid, 1234);
        assert_eq!(ctx.opcode, FUSE_FSYNC_OPCODE);
        assert_eq!(
            ctx.request_class,
            PosixFilesystemAdapterRequestClass::FileWriteback.as_u32()
        );
        assert_eq!(
            ctx.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ObjectWrite.as_u32()
        );
        assert_eq!(ctx.shard_key, 0xfeed);
    }

    #[test]
    fn classify_fsync_shards_by_file_handle_not_inode() {
        let ctx = classify_fsync_request(7, 0x42, 0x99, 0, 0, 0);
        assert_eq!(ctx.nodeid, 0x42);
        assert_eq!(ctx.shard_key, 0x99);
        assert_ne!(ctx.shard_key, ctx.nodeid);
    }

    fn assert_xattr_classifier(ctx: PosixFilesystemAdapterRequestContextMirrorRecord, opcode: u32) {
        assert_eq!(ctx.unique, 42);
        assert_eq!(ctx.nodeid, 0x78);
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1001);
        assert_eq!(ctx.pid, 1234);
        assert_eq!(ctx.opcode, opcode);
        assert_eq!(
            ctx.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(
            ctx.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32()
        );
        assert_eq!(ctx.shard_key, 0x78);
    }

    #[test]
    fn classify_setxattr_sets_namespace_mut_parent_dir_class() {
        assert_xattr_classifier(
            classify_setxattr_request(42, 0x78, 1000, 1001, 1234),
            FUSE_SETXATTR_OPCODE,
        );
    }

    #[test]
    fn classify_getxattr_sets_namespace_mut_parent_dir_class() {
        assert_xattr_classifier(
            classify_getxattr_request(42, 0x78, 1000, 1001, 1234),
            FUSE_GETXATTR_OPCODE,
        );
    }

    #[test]
    fn classify_listxattr_sets_namespace_mut_parent_dir_class() {
        assert_xattr_classifier(
            classify_listxattr_request(42, 0x78, 1000, 1001, 1234),
            FUSE_LISTXATTR_OPCODE,
        );
    }

    #[test]
    fn classify_removexattr_sets_namespace_mut_parent_dir_class() {
        assert_xattr_classifier(
            classify_removexattr_request(42, 0x78, 1000, 1001, 1234),
            FUSE_REMOVEXATTR_OPCODE,
        );
    }

    #[test]
    fn classify_lseek_sets_file_read_object_read_class() {
        let ctx = classify_lseek_request(42, 100, 0xfeed, 1000, 1000, 1234);
        assert_eq!(ctx.unique, 42);
        assert_eq!(ctx.nodeid, 100);
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1000);
        assert_eq!(ctx.pid, 1234);
        assert_eq!(ctx.opcode, FUSE_LSEEK_OPCODE);
        assert_eq!(
            ctx.request_class,
            PosixFilesystemAdapterRequestClass::FileRead.as_u32()
        );
        assert_eq!(
            ctx.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead.as_u32()
        );
        assert_eq!(ctx.shard_key, 0xfeed);
    }

    #[test]
    fn classify_lseek_shards_by_file_handle_not_inode() {
        let ctx = classify_lseek_request(0, 0, u64::MAX, 0, 0, 0);
        assert_eq!(ctx.nodeid, 0);
        assert_eq!(ctx.shard_key, u64::MAX);
        assert_ne!(ctx.shard_key, ctx.nodeid);
    }

    #[test]
    fn classify_ioctl_sets_file_read_object_read_class() {
        let ctx = classify_ioctl_request(42, 100, 0xfeed, 1000, 1000, 1234);
        assert_eq!(ctx.unique, 42);
        assert_eq!(ctx.nodeid, 100);
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1000);
        assert_eq!(ctx.pid, 1234);
        assert_eq!(ctx.opcode, FUSE_IOCTL_OPCODE);
        assert_eq!(
            ctx.request_class,
            PosixFilesystemAdapterRequestClass::FileRead.as_u32()
        );
        assert_eq!(
            ctx.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead.as_u32()
        );
        assert_eq!(ctx.shard_key, 0xfeed);
    }

    #[test]
    fn classify_ioctl_shards_by_file_handle_not_inode() {
        let ctx = classify_ioctl_request(0, 0x42, 0x99, 0, 0, 0);
        assert_eq!(ctx.nodeid, 0x42);
        assert_eq!(ctx.shard_key, 0x99);
        assert_ne!(ctx.shard_key, ctx.nodeid);
    }

    #[test]
    fn classify_poll_sets_file_read_object_read_class() {
        let ctx = classify_poll_request(42, 100, 0xfeed, 1000, 1000, 1234);
        assert_eq!(ctx.unique, 42);
        assert_eq!(ctx.nodeid, 100);
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1000);
        assert_eq!(ctx.pid, 1234);
        assert_eq!(ctx.opcode, FUSE_POLL_OPCODE);
        assert_eq!(
            ctx.request_class,
            PosixFilesystemAdapterRequestClass::FileRead.as_u32()
        );
        assert_eq!(
            ctx.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead.as_u32()
        );
        assert_eq!(ctx.shard_key, 0xfeed);
    }

    #[test]
    fn classify_poll_shards_by_file_handle_not_inode() {
        let ctx = classify_poll_request(0, 0x42, 0x99, 0, 0, 0);
        assert_eq!(ctx.nodeid, 0x42);
        assert_eq!(ctx.shard_key, 0x99);
        assert_ne!(ctx.shard_key, ctx.nodeid);
    }

    #[test]
    fn classify_copy_file_range_sets_file_writeback_object_write_class() {
        let ctx = classify_copy_file_range_request(42, 100, 0xfeed, 1000, 1000, 1234);
        assert_eq!(ctx.unique, 42);
        assert_eq!(ctx.nodeid, 100);
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1000);
        assert_eq!(ctx.pid, 1234);
        assert_eq!(ctx.opcode, FUSE_COPY_FILE_RANGE_OPCODE);
        assert_eq!(
            ctx.request_class,
            PosixFilesystemAdapterRequestClass::FileWriteback.as_u32()
        );
        assert_eq!(
            ctx.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ObjectWrite.as_u32()
        );
        assert_eq!(ctx.shard_key, 0xfeed);
    }

    #[test]
    fn classify_copy_file_range_shards_by_input_file_handle_not_inode() {
        let ctx = classify_copy_file_range_request(0, 0, u64::MAX, 0, 0, 0);
        assert_eq!(ctx.nodeid, 0);
        assert_eq!(ctx.shard_key, u64::MAX);
        assert_ne!(ctx.shard_key, ctx.nodeid);
    }

    #[test]
    fn classify_statfs_sets_meta_read_session_class() {
        assert_inode_classifier(
            classify_statfs_request(42, 100, 1000, 1000, 1234),
            FUSE_STATFS_OPCODE,
            PosixFilesystemAdapterRequestClass::MetaRead,
            PosixFilesystemAdapterShardKeyPolicy::Session,
        );
    }

    #[test]
    fn classify_syncfs_sets_file_writeback_session_class() {
        let ctx = classify_syncfs_request(42, 100, 1000, 1001, 1234);
        assert_eq!(ctx.unique, 42);
        assert_eq!(ctx.nodeid, 100);
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1001);
        assert_eq!(ctx.pid, 1234);
        assert_eq!(ctx.opcode, FUSE_SYNCFS_OPCODE);
        assert_eq!(
            ctx.request_class,
            PosixFilesystemAdapterRequestClass::FileWriteback.as_u32()
        );
        assert_eq!(
            ctx.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::Session.as_u32()
        );
        assert_eq!(ctx.shard_key, 0);
    }

    #[test]
    fn classify_syncfs_uses_filesystem_global_shard_key() {
        let ctx = classify_syncfs_request(99, 0x42, 0, 0, 0);
        assert_eq!(ctx.nodeid, 0x42);
        assert_eq!(ctx.shard_key, 0);
        assert_ne!(ctx.shard_key, ctx.nodeid);
    }

    #[test]
    fn classify_statx_sets_meta_read_object_read_class() {
        assert_inode_classifier(
            classify_statx_request(42, 100, 1000, 1000, 1234),
            FUSE_STATX_OPCODE,
            PosixFilesystemAdapterRequestClass::MetaRead,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
        );
    }

    #[test]
    fn classify_statx_shard_key_is_target_inode() {
        let ctx = classify_statx_request(99, 7, 0, 0, 0);
        assert_eq!(ctx.nodeid, 7);
        assert_eq!(ctx.shard_key, 7);
    }

    #[test]
    fn classify_release_sets_meta_read_object_read_class() {
        assert_inode_classifier(
            classify_release_request(42, 100, 1000, 1000, 1234),
            FUSE_RELEASE_OPCODE,
            PosixFilesystemAdapterRequestClass::MetaRead,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
        );
    }

    #[test]
    fn classify_opendir_sets_dir_stream_dir_handle_class() {
        assert_inode_classifier(
            classify_opendir_request(42, 100, 1000, 1000, 1234),
            FUSE_OPENDIR_OPCODE,
            PosixFilesystemAdapterRequestClass::DirStream,
            PosixFilesystemAdapterShardKeyPolicy::DirHandle,
        );
    }

    #[test]
    fn classify_readdir_sets_dir_stream_dir_handle_class() {
        assert_inode_classifier(
            classify_readdir_request(42, 100, 1000, 1000, 1234),
            FUSE_READDIR_OPCODE,
            PosixFilesystemAdapterRequestClass::DirStream,
            PosixFilesystemAdapterShardKeyPolicy::DirHandle,
        );
    }

    #[test]
    fn classify_releasedir_sets_dir_stream_dir_handle_class() {
        assert_inode_classifier(
            classify_releasedir_request(42, 100, 1000, 1000, 1234),
            FUSE_RELEASEDIR_OPCODE,
            PosixFilesystemAdapterRequestClass::DirStream,
            PosixFilesystemAdapterShardKeyPolicy::DirHandle,
        );
    }

    #[test]
    fn classify_fsyncdir_sets_dir_stream_dir_handle_class() {
        let ctx = classify_fsyncdir_request(42, 100, 0xbeef, 1000, 1000, 1234);
        assert_eq!(ctx.unique, 42);
        assert_eq!(ctx.nodeid, 100);
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1000);
        assert_eq!(ctx.pid, 1234);
        assert_eq!(ctx.opcode, FUSE_FSYNCDIR_OPCODE);
        assert_eq!(
            ctx.request_class,
            PosixFilesystemAdapterRequestClass::DirStream.as_u32()
        );
        assert_eq!(
            ctx.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::DirHandle.as_u32()
        );
        assert_eq!(ctx.shard_key, 0xbeef);
    }

    #[test]
    fn classify_fsyncdir_shards_by_directory_handle_not_inode() {
        let ctx = classify_fsyncdir_request(7, 0x42, 0x99, 0, 0, 0);
        assert_eq!(ctx.nodeid, 0x42);
        assert_eq!(ctx.shard_key, 0x99);
        assert_ne!(ctx.shard_key, ctx.nodeid);
    }

    #[test]
    fn classify_getlk_sets_lock_wait_lock_scope_class() {
        let ctx = classify_getlk_request(42, 100, 0xfeed, 1000, 1000, 1234);
        assert_eq!(ctx.unique, 42);
        assert_eq!(ctx.nodeid, 100);
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1000);
        assert_eq!(ctx.pid, 1234);
        assert_eq!(ctx.opcode, FUSE_GETLK_OPCODE);
        assert_eq!(
            ctx.request_class,
            PosixFilesystemAdapterRequestClass::LockWait.as_u32()
        );
        assert_eq!(
            ctx.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::LockScope.as_u32()
        );
        assert_eq!(ctx.shard_key, 0xfeed);
    }

    #[test]
    fn classify_getlk_shards_by_file_handle_not_inode() {
        let ctx = classify_getlk_request(7, 0x42, 0x99, 0, 0, 0);
        assert_eq!(ctx.nodeid, 0x42);
        assert_eq!(ctx.shard_key, 0x99);
        assert_ne!(ctx.shard_key, ctx.nodeid);
    }

    #[test]
    fn classify_setlk_sets_lock_wait_lock_scope_class() {
        let ctx = classify_setlk_request(42, 100, 0xfeed, 1000, 1000, 1234);
        assert_eq!(ctx.unique, 42);
        assert_eq!(ctx.nodeid, 100);
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1000);
        assert_eq!(ctx.pid, 1234);
        assert_eq!(ctx.opcode, FUSE_SETLK_OPCODE);
        assert_eq!(
            ctx.request_class,
            PosixFilesystemAdapterRequestClass::LockWait.as_u32()
        );
        assert_eq!(
            ctx.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::LockScope.as_u32()
        );
        assert_eq!(ctx.shard_key, 0xfeed);
    }

    #[test]
    fn classify_setlk_shards_by_file_handle_not_inode() {
        let ctx = classify_setlk_request(7, 0x42, 0x99, 0, 0, 0);
        assert_eq!(ctx.nodeid, 0x42);
        assert_eq!(ctx.shard_key, 0x99);
        assert_ne!(ctx.shard_key, ctx.nodeid);
    }

    #[test]
    fn classify_setlkw_sets_lock_wait_lock_scope_class() {
        let ctx = classify_setlkw_request(42, 100, 0xfeed, 1000, 1000, 1234);
        assert_eq!(ctx.unique, 42);
        assert_eq!(ctx.nodeid, 100);
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1000);
        assert_eq!(ctx.pid, 1234);
        assert_eq!(ctx.opcode, FUSE_SETLKW_OPCODE);
        assert_eq!(
            ctx.request_class,
            PosixFilesystemAdapterRequestClass::LockWait.as_u32()
        );
        assert_eq!(
            ctx.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::LockScope.as_u32()
        );
        assert_eq!(ctx.shard_key, 0xfeed);
    }

    #[test]
    fn classify_setlkw_shards_by_file_handle_not_inode() {
        let ctx = classify_setlkw_request(7, 0x42, 0x99, 0, 0, 0);
        assert_eq!(ctx.nodeid, 0x42);
        assert_eq!(ctx.shard_key, 0x99);
        assert_ne!(ctx.shard_key, ctx.nodeid);
    }

    #[test]
    fn classify_flock_shards_by_file_handle_not_inode() {
        let ctx = classify_flock_request(7, 0x42, 0x99, 0, 0, 0);
        assert_eq!(ctx.nodeid, 0x42);
        assert_eq!(ctx.opcode, FUSE_SETLK_OPCODE);
        assert_eq!(ctx.shard_key, 0x99);
        assert_ne!(ctx.shard_key, ctx.nodeid);
    }

    #[test]
    fn classify_access_sets_meta_read_object_read_class() {
        assert_inode_classifier(
            classify_access_request(42, 100, 1000, 1000, 1234),
            FUSE_ACCESS_OPCODE,
            PosixFilesystemAdapterRequestClass::MetaRead,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
        );
    }

    #[test]
    fn classify_bmap_sets_meta_read_object_read_class() {
        assert_inode_classifier(
            classify_bmap_request(42, 100, 1000, 1000, 1234),
            FUSE_BMAP_OPCODE,
            PosixFilesystemAdapterRequestClass::MetaRead,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead,
        );
    }

    #[test]
    fn classify_bmap_shard_key_is_target_inode() {
        let ctx = classify_bmap_request(99, 7, 0, 0, 0);
        assert_eq!(ctx.nodeid, 7);
        assert_eq!(ctx.shard_key, 7);
    }

    #[test]
    fn classify_bmap_opcode_is_distinct_from_other_meta_read_inode_classifiers() {
        let opcodes = [
            classify_getattr_request(1, 1, 0, 0, 0).opcode,
            classify_readlink_request(1, 1, 0, 0, 0).opcode,
            classify_access_request(1, 1, 0, 0, 0).opcode,
            classify_statx_request(1, 1, 0, 0, 0).opcode,
            classify_bmap_request(1, 1, 0, 0, 0).opcode,
        ];

        for (index, opcode) in opcodes.iter().enumerate() {
            assert!(!opcodes[..index].contains(opcode));
        }
    }

    #[test]
    fn classify_readdirplus_sets_dir_stream_dir_handle_class() {
        assert_inode_classifier(
            classify_readdirplus_request(42, 100, 1000, 1000, 1234),
            FUSE_READDIRPLUS_OPCODE,
            PosixFilesystemAdapterRequestClass::DirStream,
            PosixFilesystemAdapterShardKeyPolicy::DirHandle,
        );
    }

    struct TestWriteHandles {
        fh: u64,
        handle: IngressWriteHandle,
    }

    impl IngressWriteHandleTable for TestWriteHandles {
        fn lookup_write_handle(&self, fh: u64) -> Option<IngressWriteHandle> {
            (fh == self.fh).then_some(self.handle)
        }
    }

    fn write_req() -> RawFuseWriteRequest {
        RawFuseWriteRequest {
            unique: 77,
            inode: 42,
            fh: 9,
            offset: 4096,
            size: 4096,
            payload_len: 4096,
            write_flags: FUSE_WRITE_LOCKOWNER,
            lock_owner: 123,
        }
    }

    fn write_handles() -> TestWriteHandles {
        TestWriteHandles {
            fh: 9,
            handle: IngressWriteHandle {
                inode: 42,
                writable: true,
            },
        }
    }

    #[test]
    fn classify_write_accepts_known_writable_handle() {
        let result = WriteClassifier::new().classify(&write_handles(), write_req());

        match result {
            ClassifiedWrite::DirtyExtent(staging) => {
                assert_eq!(staging.unique, 77);
                assert_eq!(staging.inode, 42);
                assert_eq!(staging.fh, 9);
                assert_eq!(staging.offset, 4096);
                assert_eq!(staging.length, 4096);
                assert_eq!(staging.write_flags, FUSE_WRITE_LOCKOWNER);
                assert_eq!(staging.lock_owner, 123);
            }
            other => panic!("expected dirty extent, got {other:?}"),
        }
    }

    #[test]
    fn classify_write_rejects_overflow_range() {
        let request = RawFuseWriteRequest {
            offset: u64::MAX,
            size: 1,
            payload_len: 1,
            ..write_req()
        };

        assert_eq!(
            WriteClassifier::new()
                .classify(&write_handles(), request)
                .errno(),
            Some(WRITE_ERRNO_EINVAL)
        );
    }

    #[test]
    fn classify_rename_sets_namespace_mut_class() {
        let ctx = classify_rename_request(42, 1, 2, 1000, 1000, 1234);
        assert_eq!(ctx.unique, 42);
        assert_eq!(ctx.nodeid, 1);
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1000);
        assert_eq!(ctx.pid, 1234);
        assert_eq!(ctx.opcode, FUSE_RENAME_OPCODE);
        assert_eq!(
            ctx.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(
            ctx.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::DualParentPair.as_u32()
        );
    }

    #[test]
    fn classify_write_rejects_unknown_handle() {
        let mut request = write_req();
        request.fh = 99;

        assert_eq!(
            WriteClassifier::new()
                .classify(&write_handles(), request)
                .errno(),
            Some(WRITE_ERRNO_EBADF)
        );
    }

    #[test]
    fn classify_write_rejects_non_writable_handle() {
        let handles = TestWriteHandles {
            fh: 9,
            handle: IngressWriteHandle {
                inode: 42,
                writable: false,
            },
        };

        assert_eq!(
            WriteClassifier::new()
                .classify(&handles, write_req())
                .errno(),
            Some(WRITE_ERRNO_EBADF)
        );
    }

    #[test]
    fn classify_write_rejects_cache_flag() {
        let request = RawFuseWriteRequest {
            write_flags: FUSE_WRITE_CACHE,
            ..write_req()
        };

        assert_eq!(
            WriteClassifier::new()
                .classify(&write_handles(), request)
                .errno(),
            Some(WRITE_ERRNO_EINVAL)
        );
    }

    #[test]
    fn classify_write_accepts_zero_length_write() {
        let request = RawFuseWriteRequest {
            size: 0,
            payload_len: 0,
            ..write_req()
        };

        match WriteClassifier::new().classify(&write_handles(), request) {
            ClassifiedWrite::DirtyExtent(staging) => {
                assert_eq!(staging.length, 0);
                assert!(staging.is_empty());
            }
            other => panic!("expected dirty extent, got {other:?}"),
        }
    }

    #[test]
    fn classify_rename_shard_key_xors_parents() {
        let ctx = classify_rename_request(99, 0x42, 0x17, 0, 0, 0);
        assert_eq!(ctx.shard_key, 0x42 ^ 0x17);
        assert_eq!(ctx.nodeid, 0x42);
    }

    #[test]
    fn classify_rename2_sets_correct_opcode() {
        let ctx = classify_rename2_request(1, 10, 20, 0, 0, 0);
        assert_eq!(ctx.opcode, FUSE_RENAME2_OPCODE);
        assert_eq!(
            ctx.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(ctx.shard_key, 10 ^ 20);
    }

    #[test]
    fn classify_rename_same_parent_has_zero_shard_key() {
        let ctx = classify_rename_request(1, 5, 5, 0, 0, 0);
        assert_eq!(ctx.shard_key, 0);
    }

    fn assert_parent_dir_namespace_mut(
        ctx: PosixFilesystemAdapterRequestContextMirrorRecord,
        opcode: u32,
        parent_ino: u64,
    ) {
        assert_eq!(ctx.nodeid, parent_ino);
        assert_eq!(ctx.opcode, opcode);
        assert_eq!(
            ctx.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(
            ctx.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32()
        );
        assert_eq!(ctx.shard_key, parent_ino);
    }

    #[test]
    fn classify_create_sets_namespace_mut_class() {
        let ctx = classify_create_request(42, 9, 1000, 1001, 1234);
        assert_eq!(ctx.unique, 42);
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1001);
        assert_eq!(ctx.pid, 1234);
        assert_parent_dir_namespace_mut(ctx, FUSE_CREATE_OPCODE, 9);
    }

    #[test]
    fn classify_tmpfile_sets_parent_dir_key_policy() {
        let ctx = classify_tmpfile_request(42, 0x51, 1000, 1001, 1234);
        assert_eq!(ctx.unique, 42);
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1001);
        assert_eq!(ctx.pid, 1234);
        assert_parent_dir_namespace_mut(ctx, FUSE_TMPFILE_OPCODE, 0x51);
    }

    #[test]
    fn classify_mkdir_sets_parent_dir_key_policy() {
        let ctx = classify_mkdir_request(1, 0x20, 0, 0, 0);
        assert_parent_dir_namespace_mut(ctx, FUSE_MKDIR_OPCODE, 0x20);
    }

    #[test]
    fn classify_mknod_sets_parent_dir_key_policy() {
        let ctx = classify_mknod_request(1, 0x25, 0, 0, 0);
        assert_parent_dir_namespace_mut(ctx, FUSE_MKNOD_OPCODE, 0x25);
    }

    #[test]
    fn classify_unlink_uses_parent_inode_as_shard_key() {
        let ctx = classify_unlink_request(1, 0x33, 0, 0, 0);
        assert_parent_dir_namespace_mut(ctx, FUSE_UNLINK_OPCODE, 0x33);
    }

    #[test]
    fn classify_rmdir_sets_correct_opcode() {
        let ctx = classify_rmdir_request(1, 0x44, 0, 0, 0);
        assert_parent_dir_namespace_mut(ctx, FUSE_RMDIR_OPCODE, 0x44);
    }

    #[test]
    fn classify_symlink_sets_namespace_mut_class() {
        let ctx = classify_symlink_request(1, 0x55, 0, 0, 0);
        assert_parent_dir_namespace_mut(ctx, FUSE_SYMLINK_OPCODE, 0x55);
    }

    #[test]
    fn classify_link_uses_dual_parent_pair_policy() {
        let ctx = classify_link_request(42, 0x10, 0x20, 1000, 1001, 1234);
        assert_eq!(ctx.unique, 42);
        assert_eq!(ctx.nodeid, 0x10);
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1001);
        assert_eq!(ctx.pid, 1234);
        assert_eq!(ctx.opcode, FUSE_LINK_OPCODE);
        assert_eq!(
            ctx.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(
            ctx.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::DualParentPair.as_u32()
        );
    }

    #[test]
    fn classify_link_xor_key_matches() {
        let ctx = classify_link_request(1, 0x42, 0x17, 0, 0, 0);
        assert_eq!(ctx.shard_key, 0x42 ^ 0x17);
    }

    #[test]
    fn namespace_mut_classifiers_have_distinct_opcodes() {
        let opcodes = [
            classify_create_request(1, 1, 0, 0, 0).opcode,
            classify_tmpfile_request(1, 1, 0, 0, 0).opcode,
            classify_mknod_request(1, 1, 0, 0, 0).opcode,
            classify_mkdir_request(1, 1, 0, 0, 0).opcode,
            classify_unlink_request(1, 1, 0, 0, 0).opcode,
            classify_rmdir_request(1, 1, 0, 0, 0).opcode,
            classify_symlink_request(1, 1, 0, 0, 0).opcode,
            classify_link_request(1, 1, 2, 0, 0, 0).opcode,
            classify_setxattr_request(1, 1, 0, 0, 0).opcode,
            classify_getxattr_request(1, 1, 0, 0, 0).opcode,
            classify_listxattr_request(1, 1, 0, 0, 0).opcode,
            classify_removexattr_request(1, 1, 0, 0, 0).opcode,
        ];

        for (index, opcode) in opcodes.iter().enumerate() {
            assert!(!opcodes[..index].contains(opcode));
        }
    }

    #[test]
    fn errno_returns_none_for_dirty_extent() {
        let staging = PosixFilesystemAdapterWriteStagingRequest::default();
        let cw = ClassifiedWrite::DirtyExtent(staging);
        assert_eq!(cw.errno(), None);
    }

    #[test]
    fn errno_returns_some_for_rejected() {
        let cw = ClassifiedWrite::Rejected {
            unique: 1,
            errno: WRITE_ERRNO_EBADF,
        };
        assert_eq!(cw.errno(), Some(WRITE_ERRNO_EBADF));
    }

    #[test]
    fn classify_write_rejects_size_payload_len_mismatch() {
        let request = RawFuseWriteRequest {
            size: 4096,
            payload_len: 2048,
            ..write_req()
        };
        assert_eq!(
            WriteClassifier::new()
                .classify(&write_handles(), request)
                .errno(),
            Some(WRITE_ERRNO_EINVAL)
        );
    }

    #[test]
    fn classify_write_rejects_unsupported_write_flag() {
        let request = RawFuseWriteRequest {
            write_flags: 0x08, // unsupported flag, not in SUPPORTED_WRITE_FLAGS
            ..write_req()
        };
        assert_eq!(
            WriteClassifier::new()
                .classify(&write_handles(), request)
                .errno(),
            Some(WRITE_ERRNO_EINVAL)
        );
    }

    #[test]
    fn classify_write_rejects_inode_mismatch_on_writable_handle() {
        let handles = TestWriteHandles {
            fh: 9,
            handle: IngressWriteHandle {
                inode: 99, // different from request's inode=42
                writable: true,
            },
        };
        assert_eq!(
            WriteClassifier::new()
                .classify(&handles, write_req())
                .errno(),
            Some(WRITE_ERRNO_EBADF)
        );
    }

    #[test]
    fn file_read_blocked_when_inflight_bytes_full() {
        let bp = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_bytes: backpressure_constants::MAX_INFLIGHT_REQUEST_BYTES,
            ..Default::default()
        };
        assert!(!admit_request(
            &bp,
            PosixFilesystemAdapterRequestClass::FileRead
        ));
    }

    #[test]
    fn file_read_admitted_when_under_byte_ceiling() {
        let bp = PosixFilesystemAdapterBackpressureStateRecord::default();
        assert!(admit_request(
            &bp,
            PosixFilesystemAdapterRequestClass::FileRead
        ));
    }

    #[test]
    fn file_read_blocked_when_bulk_read_reply_bytes_full() {
        let bp = PosixFilesystemAdapterBackpressureStateRecord {
            bulk_read_reply_bytes: backpressure_constants::MAX_REPLY_BYTES_INFLIGHT,
            ..Default::default()
        };
        assert!(!admit_request(
            &bp,
            PosixFilesystemAdapterRequestClass::FileRead
        ));
    }

    #[test]
    fn file_read_ingress_increments_bulk_read_reply_bytes() {
        let mut bp = PosixFilesystemAdapterBackpressureStateRecord::default();
        update_backpressure_on_ingress(&mut bp, PosixFilesystemAdapterRequestClass::FileRead, 8192);
        assert_eq!(bp.inflight_request_count, 1);
        assert_eq!(bp.inflight_request_bytes, 8192);
        assert_eq!(bp.bulk_read_reply_bytes, 8192);
    }

    #[test]
    fn file_read_drain_decrements_bulk_read_reply_bytes() {
        let mut bp = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: 1,
            inflight_request_bytes: 8192,
            bulk_read_reply_bytes: 8192,
            reply_bytes_inflight: 256,
            ..Default::default()
        };
        update_backpressure_on_drain(
            &mut bp,
            PosixFilesystemAdapterRequestClass::FileRead,
            8192,
            256,
        );
        assert_eq!(bp.inflight_request_count, 0);
        assert_eq!(bp.inflight_request_bytes, 0);
        assert_eq!(bp.bulk_read_reply_bytes, 0);
        assert_eq!(bp.reply_bytes_inflight, 0);
    }

    #[test]
    fn drain_saturates_inflight_count_at_zero() {
        let mut bp = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: 0,
            inflight_request_bytes: 0,
            ..Default::default()
        };
        update_backpressure_on_drain(&mut bp, PosixFilesystemAdapterRequestClass::MetaRead, 0, 0);
        assert_eq!(bp.inflight_request_count, 0);
        assert_eq!(bp.inflight_request_bytes, 0);
    }

    #[test]
    fn drain_saturates_reply_bytes_at_zero() {
        let mut bp = PosixFilesystemAdapterBackpressureStateRecord {
            reply_bytes_inflight: 0,
            ..Default::default()
        };
        update_backpressure_on_drain(
            &mut bp,
            PosixFilesystemAdapterRequestClass::MetaRead,
            0,
            128,
        );
        assert_eq!(bp.reply_bytes_inflight, 0);
    }

    #[test]
    fn drain_saturates_dirty_window_at_zero() {
        let mut bp = PosixFilesystemAdapterBackpressureStateRecord {
            dirty_window_bytes: 0,
            ..Default::default()
        };
        update_backpressure_on_drain(
            &mut bp,
            PosixFilesystemAdapterRequestClass::FileWriteback,
            0,
            0,
        );
        assert_eq!(bp.dirty_window_bytes, 0);
    }

    #[test]
    fn drain_saturates_lock_wait_count_at_zero() {
        let mut bp = PosixFilesystemAdapterBackpressureStateRecord {
            lock_wait_count: 0,
            ..Default::default()
        };
        update_backpressure_on_drain(&mut bp, PosixFilesystemAdapterRequestClass::LockWait, 0, 0);
        assert_eq!(bp.lock_wait_count, 0);
    }

    #[test]
    fn drain_saturates_maintenance_backlog_at_zero() {
        let mut bp = PosixFilesystemAdapterBackpressureStateRecord {
            maintenance_backlog: 0,
            ..Default::default()
        };
        update_backpressure_on_drain(
            &mut bp,
            PosixFilesystemAdapterRequestClass::Maintenance,
            0,
            0,
        );
        assert_eq!(bp.maintenance_backlog, 0);
    }

    #[test]
    fn ingress_file_writeback_does_not_overflow_inflight_count() {
        let mut bp = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: u64::MAX,
            ..Default::default()
        };
        update_backpressure_on_ingress(
            &mut bp,
            PosixFilesystemAdapterRequestClass::FileWriteback,
            4096,
        );
        assert_eq!(bp.inflight_request_count, u64::MAX);
    }

    #[test]
    fn ingress_file_writeback_does_not_overflow_inflight_bytes() {
        let mut bp = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_bytes: u64::MAX,
            ..Default::default()
        };
        update_backpressure_on_ingress(
            &mut bp,
            PosixFilesystemAdapterRequestClass::FileWriteback,
            4096,
        );
        assert_eq!(bp.inflight_request_bytes, u64::MAX);
    }

    #[test]
    fn make_ingress_frame_preserves_frame_id() {
        let frame = make_ingress_frame(42, 8192);
        assert_eq!(frame.frame_id, 42);
        assert_eq!(frame.payload_len, 8192);
    }

    #[test]
    fn make_ingress_frame_reserved_is_zero() {
        let frame = make_ingress_frame(0, 0);
        assert_eq!(frame._reserved, [0_u32; 1]);
    }

    #[test]
    fn make_ingress_frame_zero_payload() {
        let frame = make_ingress_frame(99, 0);
        assert_eq!(frame.frame_id, 99);
        assert_eq!(frame.payload_len, 0);
    }

    #[test]
    fn backpressure_constants_match_spec() {
        assert_eq!(backpressure_constants::MAX_INFLIGHT_REQUEST_COUNT, 4096);
        assert_eq!(
            backpressure_constants::MAX_INFLIGHT_REQUEST_BYTES,
            64 * 1024 * 1024
        );
        assert_eq!(
            backpressure_constants::MAX_REPLY_BYTES_INFLIGHT,
            128 * 1024 * 1024
        );
        assert_eq!(
            backpressure_constants::MAX_DIRTY_WINDOW_BYTES,
            256 * 1024 * 1024
        );
        assert_eq!(backpressure_constants::MAX_LOCK_WAIT_COUNT, 256);
        assert_eq!(backpressure_constants::RESERVED_URGENT_CAPACITY, 16);
        assert_eq!(backpressure_constants::RESERVED_URGENT_ENTRY_COUNT, 4);
    }

    #[test]
    fn file_writeback_blocked_when_inflight_count_at_max() {
        let bp = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: backpressure_constants::MAX_INFLIGHT_REQUEST_COUNT,
            ..Default::default()
        };
        assert!(!admit_request(
            &bp,
            PosixFilesystemAdapterRequestClass::FileWriteback
        ));
    }

    #[test]
    fn file_writeback_admitted_when_under_count_ceiling() {
        let bp = PosixFilesystemAdapterBackpressureStateRecord {
            dirty_window_bytes: backpressure_constants::MAX_DIRTY_WINDOW_BYTES - 1,
            ..Default::default()
        };
        assert!(admit_request(
            &bp,
            PosixFilesystemAdapterRequestClass::FileWriteback
        ));
    }

    #[test]
    fn namespace_mut_blocked_when_inflight_count_full() {
        let bp = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: backpressure_constants::MAX_INFLIGHT_REQUEST_COUNT,
            ..Default::default()
        };
        assert!(!admit_request(
            &bp,
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ));
    }

    #[test]
    fn namespace_mut_admitted_when_under_count_ceiling() {
        let bp = PosixFilesystemAdapterBackpressureStateRecord::default();
        assert!(admit_request(
            &bp,
            PosixFilesystemAdapterRequestClass::NamespaceMut
        ));
    }

    #[test]
    fn dir_stream_blocked_when_inflight_count_full() {
        let bp = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: backpressure_constants::MAX_INFLIGHT_REQUEST_COUNT,
            ..Default::default()
        };
        assert!(!admit_request(
            &bp,
            PosixFilesystemAdapterRequestClass::DirStream
        ));
    }

    #[test]
    fn dir_stream_admitted_when_under_count_ceiling() {
        let bp = PosixFilesystemAdapterBackpressureStateRecord::default();
        assert!(admit_request(
            &bp,
            PosixFilesystemAdapterRequestClass::DirStream
        ));
    }

    #[test]
    fn maintenance_blocked_when_inflight_count_full() {
        let bp = PosixFilesystemAdapterBackpressureStateRecord {
            inflight_request_count: backpressure_constants::MAX_INFLIGHT_REQUEST_COUNT,
            ..Default::default()
        };
        assert!(!admit_request(
            &bp,
            PosixFilesystemAdapterRequestClass::Maintenance
        ));
    }

    #[test]
    fn maintenance_admitted_when_under_count_ceiling() {
        let bp = PosixFilesystemAdapterBackpressureStateRecord::default();
        assert!(admit_request(
            &bp,
            PosixFilesystemAdapterRequestClass::Maintenance
        ));
    }

    #[test]
    fn lock_wait_admitted_when_under_count_ceiling() {
        let bp = PosixFilesystemAdapterBackpressureStateRecord::default();
        assert!(admit_request(
            &bp,
            PosixFilesystemAdapterRequestClass::LockWait
        ));
    }

    #[test]
    fn ingress_saturates_dirty_window_at_max() {
        let mut bp = PosixFilesystemAdapterBackpressureStateRecord {
            dirty_window_bytes: u64::MAX,
            ..Default::default()
        };
        update_backpressure_on_ingress(
            &mut bp,
            PosixFilesystemAdapterRequestClass::FileWriteback,
            4096,
        );
        assert_eq!(bp.dirty_window_bytes, u64::MAX);
    }

    #[test]
    fn ingress_saturates_lock_wait_count_at_max() {
        let mut bp = PosixFilesystemAdapterBackpressureStateRecord {
            lock_wait_count: u32::MAX,
            ..Default::default()
        };
        update_backpressure_on_ingress(&mut bp, PosixFilesystemAdapterRequestClass::LockWait, 0);
        assert_eq!(bp.lock_wait_count, u32::MAX);
    }

    #[test]
    fn ingress_saturates_maintenance_backlog_at_max() {
        let mut bp = PosixFilesystemAdapterBackpressureStateRecord {
            maintenance_backlog: u64::MAX,
            ..Default::default()
        };
        update_backpressure_on_ingress(&mut bp, PosixFilesystemAdapterRequestClass::Maintenance, 0);
        assert_eq!(bp.maintenance_backlog, u64::MAX);
    }
}
