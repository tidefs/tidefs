// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE `STATFS`, `OPENDIR`, `READDIR`, `RELEASEDIR`, `READ`, and `WRITE` request dispatch glue.

use crate::fusewire::{classify_fuse_request, derive_shard_key_policy, opcode};
use crate::ingress::classify_request_context;
use crate::reply::{
    commit_bulk_reply, commit_rename_error, commit_rename_reply, commit_small_reply,
};
use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterReplyCommitRecord, PosixFilesystemAdapterRequestContextMirrorRecord,
};

#[cfg(test)]
use super::{CapacityFacade, StatfsReply};

/// Synthetic dispatch result for a FUSE `STATFS` request.
#[derive(Clone, Copy, Debug)]
#[cfg(test)]
pub struct StatfsDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record for the serialized statfs payload.
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// Serialized `fuse_statfs_out` payload.
    pub payload: [u8; StatfsReply::ENCODED_LEN],
}

/// Classify and answer a FUSE `STATFS` request from the capacity facade.
#[must_use]
#[cfg(test)]
pub fn dispatch_statfs(
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    capacity: &CapacityFacade,
) -> StatfsDispatch {
    let opcode = opcode::FUSE_STATFS;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        nodeid,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        0,
    );
    let statfs = capacity.statfs();
    let payload = statfs.as_fuse_bytes();
    let commit = commit_small_reply(unique, 0, StatfsReply::ENCODED_LEN as u32);

    StatfsDispatch {
        context,
        commit,
        payload,
    }
}

// ── OPENDIR dispatch ────────────────────────────────────────────────────

/// FUSE open-out wire size: fh (u64) + open_flags (u32) + padding (u32).
const FUSE_OPEN_OUT_WIRE_SIZE: u32 = 16;

/// Negative POSIX errno for `ENOENT` (no such file or directory).
const ERRNO_ENOENT: i32 = -2;

/// Negative POSIX errno for `EBADF` (bad file descriptor).
const ERRNO_EBADF: i32 = -9;

/// Negative POSIX errno for `EIO` (generic I/O error fallback).
const ERRNO_EIO: i32 = -5;

/// Synthetic dispatch result for a FUSE `OPENDIR` request.
#[derive(Clone, Copy, Debug)]
pub struct OpendirDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (success with fh, or error).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// Serialized open-out payload (fh + open_flags).
    pub payload: [u8; FUSE_OPEN_OUT_WIRE_SIZE as usize],
}

/// Classify and answer a FUSE `OPENDIR` request.
///
/// On success the caller should allocate a directory handle and return the
/// `fh` value.  Error cases (ENOENT, ENOTDIR) are mapped into the commit
/// record's `error_or_zero` field.
#[must_use]
pub fn dispatch_opendir(
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    success: bool,
    fh: u64,
) -> OpendirDispatch {
    let opcode = opcode::FUSE_OPENDIR;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        nodeid,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        0,
    );

    let (payload, commit) = if success {
        let mut payload = [0u8; FUSE_OPEN_OUT_WIRE_SIZE as usize];
        payload[0..8].copy_from_slice(&fh.to_le_bytes());
        let commit = commit_small_reply(unique, 0, FUSE_OPEN_OUT_WIRE_SIZE);
        (payload, commit)
    } else {
        let payload = [0u8; FUSE_OPEN_OUT_WIRE_SIZE as usize];
        let commit = commit_small_reply(unique, ERRNO_ENOENT, 0);
        (payload, commit)
    };

    OpendirDispatch {
        context,
        commit,
        payload,
    }
}

// ── READDIR dispatch ────────────────────────────────────────────────────

/// Synthetic dispatch result for a FUSE `READDIR` request.
///
/// Carries the directory inode, the readdir offset cookie, and a size hint
/// so the P5-02 classification seam can reason about per-directory stream
/// capacity and continuation behaviour.
#[derive(Clone, Copy, Debug)]
pub struct ReaddirDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (success with payload_len updated by caller, or error).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// Directory inode being enumerated.
    pub ino: u64,
    /// FUSE readdir offset (cookie-based continuation).
    pub offset: u64,
    /// size hint from the FUSE request header.
    pub size_hint: u32,
}

/// Classify a FUSE `READDIR` request.
///
/// The reply commit payload length is set to 0; the caller must update it
/// once directory entries have been serialized.
#[must_use]
pub fn dispatch_readdir(
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    offset: u64,
    size_hint: u32,
) -> ReaddirDispatch {
    let opcode = opcode::FUSE_READDIR;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        nodeid,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        0,
    );
    let commit = commit_small_reply(unique, 0, 0);

    ReaddirDispatch {
        context,
        commit,
        ino: nodeid,
        offset,
        size_hint,
    }
}

// ── READDIRPLUS dispatch ────────────────────────────────────────────────

/// Synthetic dispatch result for a FUSE `READDIRPLUS` request.
///
/// Mirrors [`ReaddirDispatch`] with the additional expectation that the
/// caller will populate per-entry attributes so the FUSE reply can carry
/// full `InodeAttr` records without a per-entry lookup round-trip.
#[derive(Clone, Copy, Debug)]
pub struct ReaddirplusDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (success with payload_len updated by caller, or error).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// Directory inode being enumerated.
    pub ino: u64,
    /// FUSE readdirplus offset (cookie-based continuation).
    pub offset: u64,
    /// size hint from the FUSE request header.
    pub size_hint: u32,
}

/// Classify a FUSE `READDIRPLUS` request.
///
/// Returns a [`ReaddirplusDispatch`] with the reply commit payload length
/// set to 0; the caller must update it once directory entries plus attrs
/// have been serialized.
#[must_use]
pub fn dispatch_readdirplus(
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    offset: u64,
    size_hint: u32,
) -> ReaddirplusDispatch {
    let opcode = opcode::FUSE_READDIRPLUS;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        nodeid,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        0,
    );
    let commit = commit_small_reply(unique, 0, 0);

    ReaddirplusDispatch {
        context,
        commit,
        ino: nodeid,
        offset,
        size_hint,
    }
}
// ── RELEASEDIR dispatch ─────────────────────────────────────────────────

/// Synthetic dispatch result for a FUSE `RELEASEDIR` request.
#[derive(Clone, Copy, Debug)]
pub struct ReleasedirDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (success or error like EBADF).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
}

/// Classify and answer a FUSE `RELEASEDIR` request.
#[must_use]
pub fn dispatch_releasedir(
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    success: bool,
) -> ReleasedirDispatch {
    let opcode = opcode::FUSE_RELEASEDIR;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        nodeid,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        0,
    );

    let commit = if success {
        commit_small_reply(unique, 0, 0)
    } else {
        commit_small_reply(unique, ERRNO_EBADF, 0)
    };

    ReleasedirDispatch { context, commit }
}
// ── READ dispatch ───────────────────────────────────────────────────────

/// Synthetic dispatch result for a FUSE `READ` request.
///
/// The commit is a bulk reply with zero payload length; the
/// caller fills in the actual data payload length before
/// emitting the reply.
#[derive(Clone, Copy, Debug)]
pub struct ReadDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (bulk reply, payload_len updated by caller).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
}

/// Classify a FUSE `READ` request.
///
/// Returns a bulk-reply commit with zero payload length. The caller must
/// update `commit.payload_len` to the actual byte count before emitting
/// the reply.
#[must_use]
pub fn dispatch_read(unique: u64, nodeid: u64, uid: u32, gid: u32, pid: u32) -> ReadDispatch {
    let opcode = opcode::FUSE_READ;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        nodeid,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        0,
    );
    let commit = commit_bulk_reply(unique, 0, 0);

    ReadDispatch { context, commit }
}

// ── WRITE dispatch ──────────────────────────────────────────────────────

/// FUSE write-out wire size: size (u32) + padding (u32).
const FUSE_WRITE_OUT_WIRE_SIZE: u32 = 8;

/// Synthetic dispatch result for a FUSE `WRITE` request.
///
/// The payload carries the serialized `fuse_write_out` (written bytes).
/// On error the commit's `error_or_zero` is set by the caller.
#[derive(Clone, Copy, Debug)]
pub struct WriteDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (small reply, 8-byte fuse_write_out).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// Serialized `fuse_write_out` payload.
    pub payload: [u8; FUSE_WRITE_OUT_WIRE_SIZE as usize],
}

/// Classify and prepare a FUSE `WRITE` reply.
///
/// `written` is the number of bytes accepted (0 for error paths).
/// On success the payload encodes `fuse_write_out { size: written, padding: 0 }`.
#[must_use]
pub fn dispatch_write(
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    written: u32,
) -> WriteDispatch {
    let opcode = opcode::FUSE_WRITE;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        nodeid,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        0,
    );
    let mut payload = [0u8; FUSE_WRITE_OUT_WIRE_SIZE as usize];
    payload[0..4].copy_from_slice(&written.to_le_bytes());
    let commit = commit_small_reply(unique, 0, FUSE_WRITE_OUT_WIRE_SIZE);

    WriteDispatch {
        context,
        commit,
        payload,
    }
}

// ── RENAME dispatch ─────────────────────────────────────────────────────

/// Synthetic dispatch result for a FUSE `RENAME` request.
#[derive(Clone, Copy, Debug)]
pub struct RenameDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (success or error).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// Old parent inode.
    pub old_parent: u64,
    /// New parent inode.
    pub new_parent: u64,
    /// Rename flags (RENAME_NOREPLACE, RENAME_EXCHANGE, etc.).
    pub flags: u32,
}

/// Input parameters for a synthetic FUSE rename dispatch.
#[derive(Clone, Copy, Debug)]
pub struct RenameDispatchRequest {
    pub unique: u64,
    pub old_parent_ino: u64,
    pub new_parent_ino: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub flags: u32,
    pub success: bool,
}

/// Classify and answer a FUSE `RENAME` request.
///
/// On success the reply carries zero payload; on error `errno` is mapped
/// into the commit record's `error_or_zero` field.
#[must_use]
pub fn dispatch_rename(request: RenameDispatchRequest) -> RenameDispatch {
    let RenameDispatchRequest {
        unique,
        old_parent_ino,
        new_parent_ino,
        uid,
        gid,
        pid,
        flags,
        success,
    } = request;
    let opcode = opcode::FUSE_RENAME;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        old_parent_ino,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        old_parent_ino ^ new_parent_ino,
    );

    let commit = if success {
        commit_rename_reply(unique)
    } else {
        commit_rename_error(unique, ERRNO_EIO)
    };

    RenameDispatch {
        context,
        commit,
        old_parent: old_parent_ino,
        new_parent: new_parent_ino,
        flags,
    }
}

/// Classify and answer a FUSE `RENAME2` request (renameat2 with flags).
///
/// Same classification as `dispatch_rename` but uses `FUSE_RENAME2` opcode.
#[must_use]
pub fn dispatch_rename2(request: RenameDispatchRequest) -> RenameDispatch {
    let RenameDispatchRequest {
        unique,
        old_parent_ino,
        new_parent_ino,
        uid,
        gid,
        pid,
        flags,
        success,
    } = request;
    let opcode = opcode::FUSE_RENAME2;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        old_parent_ino,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        old_parent_ino ^ new_parent_ino,
    );

    let commit = if success {
        commit_rename_reply(unique)
    } else {
        commit_rename_error(unique, ERRNO_EIO)
    };

    RenameDispatch {
        context,
        commit,
        old_parent: old_parent_ino,
        new_parent: new_parent_ino,
        flags,
    }
}

// ── FLUSH dispatch ───────────────────────────────────────────────────────

/// Synthetic dispatch result for a FUSE `FLUSH` request.
///
/// Flush has no reply payload beyond the error field; the kernel
/// expects only an empty response with a possible error.
#[derive(Clone, Copy, Debug)]
pub struct FlushDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (empty small reply, payload_len = 0).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
}

/// Classify and prepare a FUSE `FLUSH` reply.
///
/// `fh` is used as the shard key (ObjectWrite locality).
/// The reply is always an empty small reply; the daemon sets
/// `error_or_zero` for error paths after the engine flush completes.
#[must_use]
pub fn dispatch_flush(
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    fh: u64,
) -> FlushDispatch {
    let opcode = opcode::FUSE_FLUSH;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        nodeid,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        fh,
    );
    let commit = commit_small_reply(unique, 0, 0);

    FlushDispatch { context, commit }
}

// ── UNLINK dispatch ─────────────────────────────────────────────────────

/// Synthetic dispatch result for a FUSE `UNLINK` request.
///
/// Unlink removes a regular file directory entry.  It carries no
/// reply payload beyond the error field; the kernel expects an empty
/// response on success.
#[derive(Clone, Copy, Debug)]
pub struct UnlinkDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (success or error).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// Parent directory inode.
    pub parent: u64,
}

/// Classify and answer a FUSE `UNLINK` request.
///
/// On success the reply carries zero payload; on error `errno` is
/// mapped into the commit record's `error_or_zero` field.
#[must_use]
pub fn dispatch_unlink(
    unique: u64,
    parent_ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    success: bool,
) -> UnlinkDispatch {
    let opcode = opcode::FUSE_UNLINK;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        parent_ino,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        parent_ino,
    );
    let commit = if success {
        commit_small_reply(unique, 0, 0)
    } else {
        commit_small_reply(unique, ERRNO_EIO, 0)
    };

    UnlinkDispatch {
        context,
        commit,
        parent: parent_ino,
    }
}

// ── CREATE dispatch ─────────────────────────────────────────────────────

/// FUSE entry-out wire size: `fuse_entry_out` = nodeid(8) + generation(8) +
/// entry_valid(8) + attr_valid(8) + entry_valid_nsec(4) + attr_valid_nsec(4) +
/// fuse_attr (88 bytes) = 128 bytes.
const FUSE_ENTRY_OUT_WIRE_SIZE: u32 = 128;

/// FUSE create-out wire size: `fuse_entry_out` (128) + `fuse_open_out` (16).
const FUSE_CREATE_OUT_WIRE_SIZE: u32 = 144;

/// Negative POSIX errno for `EEXIST` (file already exists).
const ERRNO_EEXIST: i32 = -17;

/// Synthetic dispatch result for a FUSE `CREATE` request (create + open in one call).
#[derive(Clone, Copy, Debug)]
pub struct CreateDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (success with entry + open payload, or error).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// Parent directory inode.
    pub parent: u64,
}

/// Classify a FUSE `CREATE` request for the P5-02 multi-pool dispatch seam.
///
/// The caller is responsible for executing the actual creation and reporting
/// the true errno on failure via `commit.error_or_zero`.
#[must_use]
pub fn dispatch_create(
    unique: u64,
    parent: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    success: bool,
) -> CreateDispatch {
    let opcode = opcode::FUSE_CREATE;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        parent,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        parent,
    );

    let commit = if success {
        commit_small_reply(unique, 0, FUSE_CREATE_OUT_WIRE_SIZE)
    } else {
        commit_small_reply(unique, ERRNO_EEXIST, 0)
    };

    CreateDispatch {
        context,
        commit,
        parent,
    }
}

// ── MKNOD dispatch ──────────────────────────────────────────────────────

/// Synthetic dispatch result for a FUSE `MKNOD` request (S_IFREG path).
#[derive(Clone, Copy, Debug)]
pub struct MknodDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (success with entry payload, or error).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// Parent directory inode.
    pub parent: u64,
}

/// Classify a FUSE `MKNOD` request (regular-file creation path).
///
/// Regular-file mknod (S_IFREG) is semantically equivalent to `create`
/// without the open step.  Non-regular modes (FIFO, block, char) are
/// classified but the caller is responsible for rejecting unsupported
/// types with `EOPNOTSUPP`.
#[must_use]
pub fn dispatch_mknod(
    unique: u64,
    parent: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    success: bool,
) -> MknodDispatch {
    let opcode = opcode::FUSE_MKNOD;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        parent,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        parent,
    );

    let commit = if success {
        commit_small_reply(unique, 0, FUSE_ENTRY_OUT_WIRE_SIZE)
    } else {
        commit_small_reply(unique, ERRNO_EEXIST, 0)
    };

    MknodDispatch {
        context,
        commit,
        parent,
    }
}

// ── LINK dispatch ───────────────────────────────────────────────────────

/// Synthetic dispatch result for a FUSE `LINK` request (hard link creation).
///
/// Link creates a new directory entry pointing to an existing inode and
/// returns the target inode attributes with an updated `nlink` count.
#[derive(Clone, Copy, Debug)]
pub struct LinkDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (success with entry payload, or error).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// Parent directory inode where the new link will be placed.
    pub parent: u64,
    /// Target inode being linked to.
    pub target: u64,
}

/// Classify a FUSE `LINK` request for the P5-02 multi-pool dispatch seam.
///
/// The caller is responsible for executing the actual link and reporting
/// the true errno on failure via `commit.error_or_zero`.
#[must_use]
pub fn dispatch_link(
    unique: u64,
    parent_ino: u64,
    target_ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    success: bool,
) -> LinkDispatch {
    let opcode = opcode::FUSE_LINK;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        parent_ino,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        parent_ino,
    );

    let commit = if success {
        commit_small_reply(unique, 0, FUSE_ENTRY_OUT_WIRE_SIZE)
    } else {
        commit_small_reply(unique, ERRNO_EIO, 0)
    };

    LinkDispatch {
        context,
        commit,
        parent: parent_ino,
        target: target_ino,
    }
}
// ── RMDIR dispatch ─────────────────────────────────────────────────────

/// Synthetic dispatch result for a FUSE `RMDIR` request.
///
/// Rmdir removes an empty directory entry.  It carries no
/// reply payload beyond the error field; the kernel expects an empty
/// response on success.
#[derive(Clone, Copy, Debug)]
pub struct RmdirDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (success or error).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// Parent directory inode.
    pub parent: u64,
}

/// Classify and answer a FUSE `RMDIR` request.
///
/// On success the reply carries zero payload; on error `errno` is
/// mapped into the commit record's `error_or_zero` field.
#[must_use]
pub fn dispatch_rmdir(
    unique: u64,
    parent_ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    success: bool,
) -> RmdirDispatch {
    let opcode = opcode::FUSE_RMDIR;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        parent_ino,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        parent_ino,
    );
    let commit = if success {
        commit_small_reply(unique, 0, 0)
    } else {
        commit_small_reply(unique, ERRNO_EIO, 0)
    };

    RmdirDispatch {
        context,
        commit,
        parent: parent_ino,
    }
}

// ── MKDIR dispatch ──────────────────────────────────────────────────────

/// Synthetic dispatch result for a FUSE `MKDIR` request.
///
/// Mkdir creates a new directory entry with the supplied mode and
/// returns the created directory inode attributes via `fuse_entry_out`.
#[derive(Clone, Copy, Debug)]
pub struct MkdirDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (success with entry payload, or error).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// Parent directory inode where the new directory will be created.
    pub parent: u64,
}

/// Classify and answer a FUSE `MKDIR` request.
///
/// On success the reply carries a `fuse_entry_out` (128 bytes).
/// On failure `errno` is mapped into the commit record's `error_or_zero`
/// field (EEXIST, ENOSPC, EPERM, etc.).
#[must_use]
pub fn dispatch_mkdir(
    unique: u64,
    parent_ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    success: bool,
) -> MkdirDispatch {
    let opcode = opcode::FUSE_MKDIR;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        parent_ino,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        parent_ino,
    );

    let commit = if success {
        commit_small_reply(unique, 0, FUSE_ENTRY_OUT_WIRE_SIZE)
    } else {
        commit_small_reply(unique, ERRNO_EEXIST, 0)
    };

    MkdirDispatch {
        context,
        commit,
        parent: parent_ino,
    }
}
// ── GETXATTR dispatch ──────────────────────────────────────────────────

/// Synthetic dispatch result for a FUSE `GETXATTR` request.
///
/// The reply payload length is set to 0; the caller must update it once
/// the attribute value has been serialized into the reply buffer.
#[derive(Clone, Copy, Debug)]
pub struct GetxattrDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (small reply, payload_len updated by caller).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// Inode whose extended attribute is being read.
    pub ino: u64,
}

/// Classify a FUSE `GETXATTR` request.
///
/// Returns a small-reply commit with zero payload length. The caller must
/// update `commit.payload_len` to the actual attribute value byte count
/// before emitting the reply, and set `error_or_zero` on failure (e.g. ENODATA).
#[must_use]
pub fn dispatch_getxattr(
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> GetxattrDispatch {
    let opcode = opcode::FUSE_GETXATTR;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        nodeid,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        nodeid,
    );
    let commit = commit_small_reply(unique, 0, 0);

    GetxattrDispatch {
        context,
        commit,
        ino: nodeid,
    }
}

// ── SETXATTR dispatch ──────────────────────────────────────────────────

/// Synthetic dispatch result for a FUSE `SETXATTR` request.
///
/// Setxattr has no reply payload beyond the error field; the kernel
/// expects only an empty response with a possible error.
#[derive(Clone, Copy, Debug)]
pub struct SetxattrDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (empty small reply, payload_len = 0).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// Inode whose extended attribute is being set.
    pub ino: u64,
}

/// Classify a FUSE `SETXATTR` request.
///
/// Returns an empty small-reply commit. The daemon sets `error_or_zero`
/// for error paths (ENOSPC, EPERM, etc.) after the attribute write completes.
#[must_use]
pub fn dispatch_setxattr(
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> SetxattrDispatch {
    let opcode = opcode::FUSE_SETXATTR;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        nodeid,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        nodeid,
    );
    let commit = commit_small_reply(unique, 0, 0);

    SetxattrDispatch {
        context,
        commit,
        ino: nodeid,
    }
}

// ── LISTXATTR dispatch ─────────────────────────────────────────────────

/// Synthetic dispatch result for a FUSE `LISTXATTR` request.
///
/// The reply payload length is set to 0; the caller must update it once
/// the list of null-terminated attribute names has been serialized.
#[derive(Clone, Copy, Debug)]
pub struct ListxattrDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (small reply, payload_len updated by caller).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// Inode whose extended attribute list is being enumerated.
    pub ino: u64,
}

/// Classify a FUSE `LISTXATTR` request.
///
/// Returns a small-reply commit with zero payload length. The caller must
/// update `commit.payload_len` to the actual byte count of the serialized
/// name list before emitting the reply, and set `error_or_zero` on failure.
#[must_use]
pub fn dispatch_listxattr(
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> ListxattrDispatch {
    let opcode = opcode::FUSE_LISTXATTR;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        nodeid,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        nodeid,
    );
    let commit = commit_small_reply(unique, 0, 0);

    ListxattrDispatch {
        context,
        commit,
        ino: nodeid,
    }
}

// ── REMOVEXATTR dispatch ───────────────────────────────────────────────

/// Synthetic dispatch result for a FUSE `REMOVEXATTR` request.
///
/// Removexattr has no reply payload beyond the error field; the kernel
/// expects only an empty response with a possible error.
#[derive(Clone, Copy, Debug)]
pub struct RemovexattrDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (empty small reply, payload_len = 0).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// Inode whose extended attribute is being removed.
    pub ino: u64,
}

/// Classify a FUSE `REMOVEXATTR` request.
///
/// Returns an empty small-reply commit. The daemon sets `error_or_zero`
/// for error paths (ENODATA, EPERM, etc.) after the attribute removal completes.
#[must_use]
pub fn dispatch_removexattr(
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> RemovexattrDispatch {
    let opcode = opcode::FUSE_REMOVEXATTR;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        nodeid,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        nodeid,
    );
    let commit = commit_small_reply(unique, 0, 0);

    RemovexattrDispatch {
        context,
        commit,
        ino: nodeid,
    }
}
// ── FSYNC dispatch ────────────────────────────────────────────────────────

/// Synthetic dispatch result for a FUSE `FSYNC` / `FDATASYNC` request.
///
/// `fsync_flags` encodes the sync granularity:
/// - `0`            — full fsync (metadata + data).
/// - `FSYNC_FDATASYNC` (bit 0) — fdatasync (data only, no metadata).
#[derive(Clone, Copy, Debug)]
pub struct FsyncDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (empty small reply, payload_len = 0).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// File handle from `fuse_file_info::fh`.
    pub fh: u64,
    /// Sync flags: 0 for fsync, `FSYNC_FDATASYNC` for fdatasync.
    pub fsync_flags: u32,
}

/// Classify and prepare a FUSE `FSYNC` / `FDATASYNC` reply.
///
/// `fh` is used as the shard key (ObjectWrite locality).
/// `fsync_flags` distinguishes fsync (0) from fdatasync (bit 0
/// set).  The daemon sets the commit error field after the
/// backing-store flush completes.
#[must_use]
pub fn dispatch_fsync(
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    fh: u64,
    fsync_flags: u32,
) -> FsyncDispatch {
    let opcode = opcode::FUSE_FSYNC;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        nodeid,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        fh,
    );
    let commit = commit_small_reply(unique, 0, 0);

    FsyncDispatch {
        context,
        commit,
        fh,
        fsync_flags,
    }
}

// ── FSYNCDIR dispatch ─────────────────────────────────────────────────────

/// Synthetic dispatch result for a FUSE `FSYNCDIR` request.
#[derive(Clone, Copy, Debug)]
pub struct FsyncdirDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (empty small reply, payload_len = 0).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// Directory handle from `fuse_file_info::fh`.
    pub fh: u64,
}

/// Classify and prepare a FUSE `FSYNCDIR` reply.
///
/// `fh` is used as the shard key (DirHandle locality).
/// The daemon sets the commit error field after the directory
/// metadata flush completes.
#[must_use]
pub fn dispatch_fsyncdir(
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    fh: u64,
) -> FsyncdirDispatch {
    let opcode = opcode::FUSE_FSYNCDIR;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        nodeid,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        fh,
    );
    let commit = commit_small_reply(unique, 0, 0);

    FsyncdirDispatch {
        context,
        commit,
        fh,
    }
}

// ── FALLOCATE dispatch ────────────────────────────────────────────────────

/// Fallocate mode flags carried by `FUSE_FALLOCATE`.
pub mod falloc_flags {
    #[allow(unused_imports)]
    pub use tidefs_types_posix_filesystem_adapter_core::fallocate_flags::{
        FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE,
    };
}
#[derive(Clone, Copy, Debug)]
pub struct FallocateDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (empty small reply, payload_len = 0).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// File handle from `fuse_file_info::fh`.
    pub fh: u64,
    /// Byte offset of the fallocate request.
    pub offset: u64,
    /// Length in bytes of the fallocate request.
    pub length: u64,
    /// Fallocate mode flags (see `falloc_flags`).
    pub mode: u32,
}

/// Input parameters for a synthetic FUSE fallocate dispatch.
#[derive(Clone, Copy, Debug)]
pub struct FallocateDispatchRequest {
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub fh: u64,
    pub offset: u64,
    pub length: u64,
    pub mode: u32,
}

/// Classify and prepare a FUSE `FALLOCATE` reply.
///
/// `fh` is used as the shard key (ObjectWrite locality).
/// The daemon sets the commit error field after the extent
/// allocation / hole-punch / zero-range completes.
#[must_use]
pub fn dispatch_fallocate(request: FallocateDispatchRequest) -> FallocateDispatch {
    let FallocateDispatchRequest {
        unique,
        nodeid,
        uid,
        gid,
        pid,
        fh,
        offset,
        length,
        mode,
    } = request;
    let opcode = opcode::FUSE_FALLOCATE;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        nodeid,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        fh,
    );
    let commit = commit_small_reply(unique, 0, 0);

    FallocateDispatch {
        context,
        commit,
        fh,
        offset,
        length,
        mode,
    }
}

// ── SYMLINK dispatch ──────────────────────────────────────────────────────

/// Synthetic dispatch result for a FUSE `SYMLINK` request (symbolic link creation).
///
/// Symlink creates a new symbolic link entry pointing to a target path and
/// returns the created symlink inode attributes.
#[derive(Clone, Copy, Debug)]
pub struct SymlinkDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (success with entry payload, or error).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// Parent directory inode where the symlink will be placed.
    pub parent: u64,
}

/// Classify a FUSE `SYMLINK` request for the P5-02 multi-pool dispatch seam.
///
/// The caller is responsible for executing the actual symlink creation and
/// reporting the true errno on failure via `commit.error_or_zero`.
#[must_use]
pub fn dispatch_symlink(
    unique: u64,
    parent_ino: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    success: bool,
) -> SymlinkDispatch {
    let opcode = opcode::FUSE_SYMLINK;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        parent_ino,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        parent_ino,
    );

    let commit = if success {
        commit_small_reply(unique, 0, FUSE_ENTRY_OUT_WIRE_SIZE)
    } else {
        commit_small_reply(unique, ERRNO_EEXIST, 0)
    };

    SymlinkDispatch {
        context,
        commit,
        parent: parent_ino,
    }
}

// ── READLINK dispatch ────────────────────────────────────────────────────

/// Synthetic dispatch result for a FUSE `READLINK` request (symlink target resolution).
///
/// The reply payload length is set to 0; the caller must update it once
/// the symlink target path has been serialized into the reply buffer.
#[derive(Clone, Copy, Debug)]
pub struct ReadlinkDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (small reply, payload_len updated by caller).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// Inode of the symlink being resolved.
    pub ino: u64,
}

/// Classify a FUSE `READLINK` request.
///
/// Returns a small-reply commit with zero payload length. The caller must
/// update `commit.payload_len` to the actual target path byte count before
/// emitting the reply, and set `error_or_zero` on failure (e.g. EINVAL for
/// non-symlink, ENOENT for nonexistent inode).
#[must_use]
pub fn dispatch_readlink(
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
) -> ReadlinkDispatch {
    let opcode = opcode::FUSE_READLINK;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        nodeid,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        nodeid,
    );
    let commit = commit_small_reply(unique, 0, 0);

    ReadlinkDispatch {
        context,
        commit,
        ino: nodeid,
    }
}

// ── TMPFILE dispatch ──────────────────────────────────────────────────

/// Synthetic dispatch result for a FUSE `TMPFILE` request (O_TMPFILE).
///
/// TMPFILE creates an unnamed regular file with no directory entry.
/// The reply carries a fuse_entry_out + fuse_open_out on success,
/// identical to CREATE.
#[derive(Clone, Copy, Debug)]
pub struct TmpfileDispatch {
    /// Classified ingress context.
    pub context: PosixFilesystemAdapterRequestContextMirrorRecord,
    /// Reply commit record (success with entry + open payload, or error).
    pub commit: PosixFilesystemAdapterReplyCommitRecord,
    /// Parent directory inode.
    pub parent: u64,
}

/// Classify a FUSE `TMPFILE` request for the P5-02 multi-pool dispatch seam.
///
/// The caller is responsible for executing the actual tmpfile creation and
/// reporting the true errno on failure via `commit.error_or_zero`.
#[must_use]
pub fn dispatch_tmpfile(
    unique: u64,
    parent: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    success: bool,
) -> TmpfileDispatch {
    let opcode = opcode::FUSE_TMPFILE;
    let request_class = classify_fuse_request(opcode);
    let shard_key_policy = derive_shard_key_policy(opcode);
    let context = classify_request_context(
        unique,
        parent,
        uid,
        gid,
        pid,
        opcode,
        request_class,
        shard_key_policy,
        parent,
    );

    let commit = if success {
        commit_small_reply(unique, 0, FUSE_CREATE_OUT_WIRE_SIZE)
    } else {
        commit_small_reply(unique, ERRNO_EIO, 0)
    };

    TmpfileDispatch {
        context,
        commit,
        parent,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_block_allocator::{BlockAllocator, Region};
    use tidefs_types_posix_filesystem_adapter_core::{
        PosixFilesystemAdapterReplyClass, PosixFilesystemAdapterRequestClass,
        PosixFilesystemAdapterShardKeyPolicy,
    };

    fn capacity() -> CapacityFacade {
        let allocator = BlockAllocator::with_root_reserve(
            128,
            4096,
            Region::new(0, BlockAllocator::required_bitmap_bytes(128)),
            8,
        );
        CapacityFacade::new(allocator)
    }

    fn rename_request(
        unique: u64,
        old_parent_ino: u64,
        new_parent_ino: u64,
        flags: u32,
        success: bool,
    ) -> RenameDispatchRequest {
        RenameDispatchRequest {
            unique,
            old_parent_ino,
            new_parent_ino,
            uid: 1000,
            gid: 1000,
            pid: 42,
            flags,
            success,
        }
    }

    fn fallocate_request(unique: u64, nodeid: u64, fh: u64) -> FallocateDispatchRequest {
        FallocateDispatchRequest {
            unique,
            nodeid,
            uid: 1000,
            gid: 1000,
            pid: 42,
            fh,
            offset: 0,
            length: 4096,
            mode: 0,
        }
    }

    // ── STATFS dispatch tests ──────────────────────────────────────────

    #[test]
    fn statfs_dispatch_classifies_and_commits_small_reply() {
        let dispatch = dispatch_statfs(99, 1, 1000, 1000, 42, &capacity());

        assert_eq!(dispatch.context.unique, 99);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_STATFS);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::MetaRead.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::Session.as_u32()
        );
        assert_eq!(dispatch.commit.unique, 99);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
        assert_eq!(dispatch.commit.payload_len, StatfsReply::ENCODED_LEN as u32);
    }

    #[test]
    fn statfs_dispatch_payload_preserves_allocator_capacity() {
        let dispatch = dispatch_statfs(99, 1, 1000, 1000, 42, &capacity());
        let read_u64 = |offset: usize| -> u64 {
            u64::from_le_bytes(
                dispatch.payload[offset..offset + 8]
                    .try_into()
                    .expect("u64 field"),
            )
        };

        assert_eq!(read_u64(0), 128);
        assert_eq!(read_u64(8), 128);
        assert_eq!(read_u64(16), 120);
        assert_eq!(read_u64(48), 4096);
        assert_eq!(read_u64(64), 4096);
    }

    #[test]
    fn statfs_dispatch_context_includes_uid_gid_pid() {
        let dispatch = dispatch_statfs(99, 1, 500, 501, 123, &capacity());

        assert_eq!(dispatch.context.uid, 500);
        assert_eq!(dispatch.context.gid, 501);
        assert_eq!(dispatch.context.pid, 123);
    }

    #[test]
    fn statfs_dispatch_shard_key_policy_is_session() {
        let dispatch = dispatch_statfs(100, 0x42, 0, 0, 0, &capacity());

        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::Session.as_u32()
        );
        assert_eq!(dispatch.context.shard_key, 0);
        assert_eq!(dispatch.context.nodeid, 0x42);
    }

    #[test]
    fn statfs_dispatch_payload_has_nonzero_block_size() {
        let dispatch = dispatch_statfs(1, 1, 0, 0, 0, &capacity());
        let read_u64 = |offset: usize| -> u64 {
            u64::from_le_bytes(
                dispatch.payload[offset..offset + 8]
                    .try_into()
                    .expect("u64 field"),
            )
        };

        // bsize at offset 48, frsize at offset 64 — both must be nonzero
        assert!(read_u64(48) > 0, "bsize must be nonzero");
        assert!(read_u64(64) > 0, "frsize must be nonzero");
    }

    // ── OPENDIR dispatch tests ─────────────────────────────────────────

    #[test]
    fn opendir_success_classifies_as_dir_stream() {
        let dispatch = dispatch_opendir(111, 2, 1000, 1000, 42, true, 7);

        assert_eq!(dispatch.context.unique, 111);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_OPENDIR);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::DirStream.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::DirHandle.as_u32()
        );
        assert_eq!(dispatch.commit.unique, 111);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
        assert_eq!(dispatch.commit.payload_len, FUSE_OPEN_OUT_WIRE_SIZE);
        assert_eq!(
            u64::from_le_bytes(dispatch.payload[0..8].try_into().unwrap()),
            7
        );
    }

    #[test]
    fn opendir_error_returns_enoent_commit() {
        let dispatch = dispatch_opendir(112, 2, 1000, 1000, 42, false, 0);

        assert_eq!(dispatch.commit.unique, 112);
        assert_eq!(dispatch.commit.error_or_zero, ERRNO_ENOENT);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn opendir_error_preserves_context_classification() {
        let dispatch = dispatch_opendir(113, 2, 1000, 1000, 42, false, 0);

        assert_eq!(dispatch.context.unique, 113);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_OPENDIR);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::DirStream.as_u32()
        );
    }

    // ── READDIR dispatch tests ─────────────────────────────────────────

    #[test]
    fn readdir_classifies_as_dir_stream() {
        let dispatch = dispatch_readdir(201, 3, 1000, 1000, 42, 0, 4096);

        assert_eq!(dispatch.context.unique, 201);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_READDIR);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::DirStream.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::DirHandle.as_u32()
        );
        assert_eq!(dispatch.commit.unique, 201);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
        assert_eq!(dispatch.ino, 3);
        assert_eq!(dispatch.offset, 0);
        assert_eq!(dispatch.size_hint, 4096);
    }

    #[test]
    fn readdir_offset_zero_preserves_inode() {
        let dispatch = dispatch_readdir(203, 99, 1000, 1000, 42, 0, 4096);
        assert_eq!(dispatch.ino, 99);
        assert_eq!(dispatch.offset, 0);
        assert_eq!(dispatch.size_hint, 4096);
    }

    #[test]
    fn readdir_nonzero_offset_stores_cookie() {
        let dispatch = dispatch_readdir(204, 10, 1000, 1000, 42, 42, 4096);
        assert_eq!(dispatch.offset, 42);
        assert_eq!(dispatch.ino, 10);
    }

    #[test]
    fn readdir_large_size_hint_stored() {
        let dispatch = dispatch_readdir(205, 1, 1000, 1000, 42, 0, 65536);
        assert_eq!(dispatch.size_hint, 65536);
    }

    #[test]
    fn readdir_context_includes_nodeid() {
        let dispatch = dispatch_readdir(202, 42, 1000, 1000, 42, 0, 8192);
        assert_eq!(dispatch.context.nodeid, 42);
        assert_eq!(dispatch.ino, 42);
    }

    // ── READDIRPLUS dispatch tests ─────────────────────────────────────

    #[test]
    fn readdirplus_classifies_as_dir_stream() {
        let dispatch = dispatch_readdirplus(301, 3, 1000, 1000, 42, 0, 4096);

        assert_eq!(dispatch.context.unique, 301);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_READDIRPLUS);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::DirStream.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::DirHandle.as_u32()
        );
        assert_eq!(dispatch.commit.unique, 301);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(dispatch.ino, 3);
        assert_eq!(dispatch.offset, 0);
        assert_eq!(dispatch.size_hint, 4096);
    }

    #[test]
    fn readdirplus_carries_inode_and_offset() {
        let dispatch = dispatch_readdirplus(302, 47, 1000, 1000, 42, 10, 4096);
        assert_eq!(dispatch.ino, 47);
        assert_eq!(dispatch.offset, 10);
    }

    #[test]
    fn readdirplus_large_size_hint_stored() {
        let dispatch = dispatch_readdirplus(303, 1, 1000, 1000, 42, 0, 131072);
        assert_eq!(dispatch.size_hint, 131072);
    }

    #[test]
    fn readdirplus_nonzero_offset_stores_cookie() {
        let dispatch = dispatch_readdirplus(304, 10, 1000, 1000, 42, 99, 8192);
        assert_eq!(dispatch.offset, 99);
        assert_eq!(dispatch.ino, 10);
    }

    #[test]
    fn readdirplus_context_includes_nodeid() {
        let dispatch = dispatch_readdirplus(305, 55, 1000, 1000, 42, 0, 4096);
        assert_eq!(dispatch.context.nodeid, 55);
        assert_eq!(dispatch.ino, 55);
    }

    #[test]
    fn readdirplus_context_includes_uid_gid_pid() {
        let dispatch = dispatch_readdirplus(306, 10, 500, 501, 99, 0, 4096);
        assert_eq!(dispatch.context.uid, 500);
        assert_eq!(dispatch.context.gid, 501);
        assert_eq!(dispatch.context.pid, 99);
    }

    // ── RELEASEDIR dispatch tests ──────────────────────────────────────

    #[test]
    fn releasedir_success_classifies_as_dir_stream() {
        let dispatch = dispatch_releasedir(301, 4, 1000, 1000, 42, true);

        assert_eq!(dispatch.context.unique, 301);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_RELEASEDIR);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::DirStream.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::DirHandle.as_u32()
        );
        assert_eq!(dispatch.commit.unique, 301);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn releasedir_error_returns_ebadf() {
        let dispatch = dispatch_releasedir(302, 4, 1000, 1000, 42, false);

        assert_eq!(dispatch.commit.unique, 302);
        assert_eq!(dispatch.commit.error_or_zero, ERRNO_EBADF);
        assert_eq!(dispatch.commit.payload_len, 0);
    }

    #[test]
    fn releasedir_error_preserves_context_classification() {
        let dispatch = dispatch_releasedir(303, 4, 1000, 1000, 42, false);

        assert_eq!(dispatch.context.unique, 303);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_RELEASEDIR);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::DirStream.as_u32()
        );
    }

    // ── READ dispatch tests ────────────────────────────────────────────

    #[test]
    fn read_dispatch_classifies_as_file_read() {
        let dispatch = dispatch_read(401, 5, 1000, 1000, 42);

        assert_eq!(dispatch.context.unique, 401);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_READ);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::FileRead.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ObjectRead.as_u32()
        );
    }

    #[test]
    fn read_dispatch_commits_bulk_reply_with_zero_payload_len() {
        let dispatch = dispatch_read(402, 5, 1000, 1000, 42);

        assert_eq!(dispatch.commit.unique, 402);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::BulkReply.as_u32()
        );
    }

    #[test]
    fn read_dispatch_context_includes_nodeid() {
        let dispatch = dispatch_read(403, 42, 1000, 1000, 42);
        assert_eq!(dispatch.context.nodeid, 42);
    }

    // ── WRITE dispatch tests ───────────────────────────────────────────

    #[test]
    fn write_dispatch_classifies_as_file_writeback() {
        let dispatch = dispatch_write(501, 6, 1000, 1000, 42, 4096);

        assert_eq!(dispatch.context.unique, 501);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_WRITE);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::FileWriteback.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ObjectWrite.as_u32()
        );
    }

    #[test]
    fn write_dispatch_commits_small_reply_with_fuse_write_out_size() {
        let dispatch = dispatch_write(502, 6, 1000, 1000, 42, 128);

        assert_eq!(dispatch.commit.unique, 502);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, FUSE_WRITE_OUT_WIRE_SIZE);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn write_dispatch_payload_encodes_written_bytes() {
        let dispatch = dispatch_write(503, 6, 1000, 1000, 42, 65536);

        let written = u32::from_le_bytes(dispatch.payload[0..4].try_into().unwrap());
        assert_eq!(written, 65536);
        assert_eq!(dispatch.payload[4..8], [0u8; 4]);
    }

    #[test]
    fn write_dispatch_zero_written_encodes_zero() {
        let dispatch = dispatch_write(504, 6, 1000, 1000, 42, 0);

        let written = u32::from_le_bytes(dispatch.payload[0..4].try_into().unwrap());
        assert_eq!(written, 0);
    }

    #[test]
    fn write_dispatch_context_includes_nodeid() {
        let dispatch = dispatch_write(505, 99, 1000, 1000, 42, 1024);
        assert_eq!(dispatch.context.nodeid, 99);
    }
    // ── RENAME dispatch tests ───────────────────────────────────────────

    #[test]
    fn rename_success_classifies_as_namespace_mut() {
        let dispatch = dispatch_rename(rename_request(401, 10, 20, 0, true));

        assert_eq!(dispatch.context.unique, 401);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_RENAME);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::DualParentPair.as_u32()
        );
        assert_eq!(dispatch.context.nodeid, 10);
        assert_eq!(dispatch.context.shard_key, 10 ^ 20);
        assert_eq!(dispatch.commit.unique, 401);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
        assert_eq!(dispatch.old_parent, 10);
        assert_eq!(dispatch.new_parent, 20);
        assert_eq!(dispatch.flags, 0);
    }

    #[test]
    fn rename_error_returns_eio_commit() {
        let dispatch = dispatch_rename(rename_request(402, 10, 20, 0, false));

        assert_eq!(dispatch.commit.unique, 402);
        assert_eq!(dispatch.commit.error_or_zero, ERRNO_EIO);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn rename_error_preserves_context_classification() {
        let dispatch = dispatch_rename(rename_request(403, 10, 20, 0, false));

        assert_eq!(dispatch.context.unique, 403);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_RENAME);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
    }

    #[test]
    fn rename2_uses_correct_opcode() {
        let dispatch = dispatch_rename2(rename_request(501, 30, 40, 1, true));

        assert_eq!(dispatch.context.unique, 501);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_RENAME2);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::DualParentPair.as_u32()
        );
        assert_eq!(dispatch.context.shard_key, 30 ^ 40);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.flags, 1);
    }

    #[test]
    fn rename2_with_flags_preserves_flags_field() {
        let flags = 0x0001; // RENAME_NOREPLACE
        let dispatch = dispatch_rename2(rename_request(502, 50, 60, flags, true));

        assert_eq!(dispatch.flags, flags);
        assert_eq!(dispatch.old_parent, 50);
        assert_eq!(dispatch.new_parent, 60);
    }

    #[test]
    fn rename2_error_returns_eio_commit() {
        let dispatch = dispatch_rename2(rename_request(503, 70, 80, 0, false));

        assert_eq!(dispatch.commit.unique, 503);
        assert_eq!(dispatch.commit.error_or_zero, ERRNO_EIO);
        assert_eq!(dispatch.commit.payload_len, 0);
    }

    #[test]
    fn rename_same_directory_shard_key_is_zero() {
        let dispatch = dispatch_rename(rename_request(601, 99, 99, 0, true));

        assert_eq!(dispatch.context.shard_key, 0);
        assert_eq!(dispatch.old_parent, 99);
        assert_eq!(dispatch.new_parent, 99);
    }

    #[test]
    fn rename_different_parents_shard_key_is_xor() {
        let dispatch = dispatch_rename(rename_request(602, 0x1234, 0x5678, 0, true));

        assert_eq!(dispatch.context.shard_key, 0x1234 ^ 0x5678);
    }

    #[test]
    fn rename_context_includes_uid_gid_pid() {
        let dispatch = dispatch_rename(RenameDispatchRequest {
            uid: 500,
            gid: 501,
            pid: 99,
            ..rename_request(603, 10, 20, 0, true)
        });

        assert_eq!(dispatch.context.uid, 500);
        assert_eq!(dispatch.context.gid, 501);
        assert_eq!(dispatch.context.pid, 99);
    }

    // ── FLUSH dispatch tests ────────────────────────────────────────────

    #[test]
    fn flush_dispatch_classifies_as_file_writeback() {
        let dispatch = dispatch_flush(601, 7, 1000, 1000, 42, 0xfeed);

        assert_eq!(dispatch.context.unique, 601);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_FLUSH);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::FileWriteback.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ObjectWrite.as_u32()
        );
    }

    #[test]
    fn flush_dispatch_commits_empty_small_reply() {
        let dispatch = dispatch_flush(602, 7, 1000, 1000, 42, 0xfeed);

        assert_eq!(dispatch.commit.unique, 602);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn flush_dispatch_shard_key_is_fh() {
        let dispatch = dispatch_flush(603, 0x42, 1000, 1000, 42, 0x99);

        assert_eq!(dispatch.context.nodeid, 0x42);
        assert_eq!(dispatch.context.shard_key, 0x99);
        assert_ne!(dispatch.context.shard_key, dispatch.context.nodeid);
    }

    #[test]
    fn flush_dispatch_context_includes_uid_gid_pid() {
        let dispatch = dispatch_flush(604, 8, 2000, 3000, 99, 0xfeed);

        assert_eq!(dispatch.context.uid, 2000);
        assert_eq!(dispatch.context.gid, 3000);
        assert_eq!(dispatch.context.pid, 99);
    }
    // ── UNLINK dispatch tests ──────────────────────────────────────────

    #[test]
    fn unlink_success_classifies_as_namespace_mut() {
        let dispatch = dispatch_unlink(701, 42, 1000, 1000, 99, true);

        assert_eq!(dispatch.context.unique, 701);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_UNLINK);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32()
        );
        assert_eq!(dispatch.context.nodeid, 42);
        assert_eq!(dispatch.context.shard_key, 42);
        assert_eq!(dispatch.parent, 42);
        assert_eq!(dispatch.commit.unique, 701);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn unlink_error_returns_eio_commit() {
        let dispatch = dispatch_unlink(702, 42, 1000, 1000, 99, false);

        assert_eq!(dispatch.commit.unique, 702);
        assert_eq!(dispatch.commit.error_or_zero, ERRNO_EIO);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn unlink_error_preserves_context_classification() {
        let dispatch = dispatch_unlink(703, 42, 1000, 1000, 99, false);

        assert_eq!(dispatch.context.unique, 703);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_UNLINK);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(dispatch.parent, 42);
    }

    #[test]
    fn unlink_context_includes_uid_gid_pid() {
        let dispatch = dispatch_unlink(704, 99, 500, 501, 123, true);

        assert_eq!(dispatch.context.uid, 500);
        assert_eq!(dispatch.context.gid, 501);
        assert_eq!(dispatch.context.pid, 123);
    }

    #[test]
    fn unlink_shard_key_is_parent_inode() {
        let dispatch = dispatch_unlink(705, 0x1234, 0, 0, 0, true);

        assert_eq!(dispatch.context.shard_key, 0x1234);
        assert_eq!(dispatch.context.nodeid, 0x1234);
    }

    // -- CREATE dispatch tests -------------------------------------------------

    #[test]
    fn create_success_classifies_as_namespace_mut() {
        let dispatch = dispatch_create(701, 10, 1000, 1000, 42, true);

        assert_eq!(dispatch.context.unique, 701);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_CREATE);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32()
        );
        assert_eq!(dispatch.context.nodeid, 10);
        assert_eq!(dispatch.context.shard_key, 10);
        assert_eq!(dispatch.commit.unique, 701);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, FUSE_CREATE_OUT_WIRE_SIZE);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
        assert_eq!(dispatch.parent, 10);
    }

    #[test]
    fn create_error_returns_eexist_commit() {
        let dispatch = dispatch_create(702, 20, 1000, 1000, 42, false);

        assert_eq!(dispatch.commit.unique, 702);
        assert_eq!(dispatch.commit.error_or_zero, ERRNO_EEXIST);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn create_error_preserves_context_classification() {
        let dispatch = dispatch_create(703, 30, 1000, 1000, 42, false);

        assert_eq!(dispatch.context.unique, 703);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_CREATE);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
    }

    #[test]
    fn create_context_includes_uid_gid_pid() {
        let dispatch = dispatch_create(704, 40, 500, 501, 99, true);

        assert_eq!(dispatch.context.uid, 500);
        assert_eq!(dispatch.context.gid, 501);
        assert_eq!(dispatch.context.pid, 99);
    }

    #[test]
    fn create_shard_key_is_parent_inode() {
        let dispatch = dispatch_create(705, 0xABCD, 1000, 1000, 42, true);

        assert_eq!(dispatch.context.shard_key, 0xABCD);
        assert_eq!(dispatch.parent, 0xABCD);
    }

    // -- MKNOD dispatch tests --------------------------------------------------

    #[test]
    fn mknod_success_classifies_as_namespace_mut() {
        let dispatch = dispatch_mknod(801, 10, 1000, 1000, 42, true);

        assert_eq!(dispatch.context.unique, 801);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_MKNOD);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32()
        );
        assert_eq!(dispatch.context.nodeid, 10);
        assert_eq!(dispatch.context.shard_key, 10);
        assert_eq!(dispatch.commit.unique, 801);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, FUSE_ENTRY_OUT_WIRE_SIZE);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
        assert_eq!(dispatch.parent, 10);
    }

    #[test]
    fn mknod_error_returns_eexist_commit() {
        let dispatch = dispatch_mknod(802, 20, 1000, 1000, 42, false);

        assert_eq!(dispatch.commit.unique, 802);
        assert_eq!(dispatch.commit.error_or_zero, ERRNO_EEXIST);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn mknod_error_preserves_context_classification() {
        let dispatch = dispatch_mknod(803, 30, 1000, 1000, 42, false);

        assert_eq!(dispatch.context.unique, 803);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_MKNOD);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
    }

    #[test]
    fn mknod_context_includes_uid_gid_pid() {
        let dispatch = dispatch_mknod(804, 40, 500, 501, 99, true);

        assert_eq!(dispatch.context.uid, 500);
        assert_eq!(dispatch.context.gid, 501);
        assert_eq!(dispatch.context.pid, 99);
    }

    #[test]
    fn mknod_shard_key_is_parent_inode() {
        let dispatch = dispatch_mknod(805, 0x1234, 1000, 1000, 42, true);

        assert_eq!(dispatch.context.shard_key, 0x1234);
        assert_eq!(dispatch.parent, 0x1234);
    }

    // ── LINK dispatch tests ────────────────────────────────────────────

    #[test]
    fn link_success_classifies_as_namespace_mut() {
        let dispatch = dispatch_link(901, 10, 20, 1000, 1000, 42, true);

        assert_eq!(dispatch.context.unique, 901);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_LINK);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32()
        );
        assert_eq!(dispatch.context.nodeid, 10);
        assert_eq!(dispatch.context.shard_key, 10);
        assert_eq!(dispatch.parent, 10);
        assert_eq!(dispatch.target, 20);
        assert_eq!(dispatch.commit.unique, 901);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, FUSE_ENTRY_OUT_WIRE_SIZE);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn link_error_returns_eio_commit() {
        let dispatch = dispatch_link(902, 10, 20, 1000, 1000, 42, false);

        assert_eq!(dispatch.commit.unique, 902);
        assert_eq!(dispatch.commit.error_or_zero, ERRNO_EIO);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn link_error_preserves_context_classification() {
        let dispatch = dispatch_link(903, 10, 20, 1000, 1000, 42, false);

        assert_eq!(dispatch.context.unique, 903);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_LINK);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(dispatch.parent, 10);
        assert_eq!(dispatch.target, 20);
    }

    #[test]
    fn link_context_includes_uid_gid_pid() {
        let dispatch = dispatch_link(904, 99, 88, 500, 501, 123, true);

        assert_eq!(dispatch.context.uid, 500);
        assert_eq!(dispatch.context.gid, 501);
        assert_eq!(dispatch.context.pid, 123);
    }

    #[test]
    fn link_shard_key_is_parent_inode() {
        let dispatch = dispatch_link(905, 0x1234, 0x5678, 0, 0, 0, true);

        assert_eq!(dispatch.context.shard_key, 0x1234);
        assert_eq!(dispatch.context.nodeid, 0x1234);
        assert_eq!(dispatch.parent, 0x1234);
    }

    #[test]
    fn link_target_preserved_on_error() {
        let dispatch = dispatch_link(906, 42, 99, 1000, 1000, 42, false);

        assert_eq!(dispatch.target, 99);
        assert_eq!(dispatch.parent, 42);
        assert_eq!(dispatch.commit.error_or_zero, ERRNO_EIO);
    }

    #[test]
    fn link_same_parent_and_target_is_valid_classification() {
        let dispatch = dispatch_link(907, 42, 99, 1000, 1000, 42, true);

        assert_eq!(dispatch.parent, 42);
        assert_eq!(dispatch.target, 99);
        assert_ne!(dispatch.parent, dispatch.target);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, FUSE_ENTRY_OUT_WIRE_SIZE);
    }

    // ── SYMLINK dispatch tests ─────────────────────────────────────────

    #[test]
    fn symlink_success_classifies_as_namespace_mut() {
        let dispatch = dispatch_symlink(1501, 42, 1000, 1000, 99, true);

        assert_eq!(dispatch.context.unique, 1501);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_SYMLINK);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32()
        );
        assert_eq!(dispatch.context.nodeid, 42);
        assert_eq!(dispatch.context.shard_key, 42);
        assert_eq!(dispatch.parent, 42);
        assert_eq!(dispatch.commit.unique, 1501);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, FUSE_ENTRY_OUT_WIRE_SIZE);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn symlink_error_returns_eexist_commit() {
        let dispatch = dispatch_symlink(1502, 42, 1000, 1000, 99, false);

        assert_eq!(dispatch.commit.unique, 1502);
        assert_eq!(dispatch.commit.error_or_zero, ERRNO_EEXIST);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn symlink_error_preserves_context_classification() {
        let dispatch = dispatch_symlink(1503, 42, 1000, 1000, 99, false);

        assert_eq!(dispatch.context.unique, 1503);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_SYMLINK);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(dispatch.parent, 42);
    }

    #[test]
    fn symlink_context_includes_uid_gid_pid() {
        let dispatch = dispatch_symlink(1504, 99, 500, 501, 123, true);

        assert_eq!(dispatch.context.uid, 500);
        assert_eq!(dispatch.context.gid, 501);
        assert_eq!(dispatch.context.pid, 123);
    }

    #[test]
    fn symlink_shard_key_is_parent_inode() {
        let dispatch = dispatch_symlink(1505, 0x1234, 0, 0, 0, true);

        assert_eq!(dispatch.context.shard_key, 0x1234);
        assert_eq!(dispatch.context.nodeid, 0x1234);
        assert_eq!(dispatch.parent, 0x1234);
    }

    // ── READLINK dispatch tests ────────────────────────────────────────

    #[test]
    fn readlink_classifies_as_meta_read() {
        let dispatch = dispatch_readlink(1601, 42, 1000, 1000, 99);

        assert_eq!(dispatch.context.unique, 1601);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_READLINK);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::MetaRead.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32()
        );
        assert_eq!(dispatch.context.nodeid, 42);
        assert_eq!(dispatch.context.shard_key, 42);
        assert_eq!(dispatch.ino, 42);
        assert_eq!(dispatch.commit.unique, 1601);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn readlink_context_includes_uid_gid_pid() {
        let dispatch = dispatch_readlink(1602, 99, 500, 501, 123);

        assert_eq!(dispatch.context.uid, 500);
        assert_eq!(dispatch.context.gid, 501);
        assert_eq!(dispatch.context.pid, 123);
    }

    #[test]
    fn readlink_shard_key_matches_nodeid() {
        let dispatch = dispatch_readlink(1603, 0xABCD, 0, 0, 0);

        assert_eq!(dispatch.context.shard_key, 0xABCD);
        assert_eq!(dispatch.ino, 0xABCD);
    }

    #[test]
    fn readlink_commit_allows_caller_to_set_payload_len() {
        let dispatch = dispatch_readlink(1604, 5, 1000, 1000, 42);
        assert_eq!(dispatch.commit.payload_len, 0);
    }
    // ── RMDIR dispatch tests ──────────────────────────────────────────

    #[test]
    fn rmdir_success_classifies_as_namespace_mut() {
        let dispatch = dispatch_rmdir(1001, 42, 1000, 1000, 99, true);

        assert_eq!(dispatch.context.unique, 1001);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_RMDIR);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32()
        );
        assert_eq!(dispatch.context.nodeid, 42);
        assert_eq!(dispatch.context.shard_key, 42);
        assert_eq!(dispatch.parent, 42);
        assert_eq!(dispatch.commit.unique, 1001);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn rmdir_error_returns_eio_commit() {
        let dispatch = dispatch_rmdir(1002, 42, 1000, 1000, 99, false);

        assert_eq!(dispatch.commit.unique, 1002);
        assert_eq!(dispatch.commit.error_or_zero, ERRNO_EIO);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn rmdir_error_preserves_context_classification() {
        let dispatch = dispatch_rmdir(1003, 42, 1000, 1000, 99, false);

        assert_eq!(dispatch.context.unique, 1003);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_RMDIR);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(dispatch.parent, 42);
    }

    #[test]
    fn rmdir_context_includes_uid_gid_pid() {
        let dispatch = dispatch_rmdir(1004, 99, 500, 501, 123, true);

        assert_eq!(dispatch.context.uid, 500);
        assert_eq!(dispatch.context.gid, 501);
        assert_eq!(dispatch.context.pid, 123);
    }

    #[test]
    fn rmdir_shard_key_is_parent_inode() {
        let dispatch = dispatch_rmdir(1005, 0x1234, 0, 0, 0, true);

        assert_eq!(dispatch.context.shard_key, 0x1234);
        assert_eq!(dispatch.context.nodeid, 0x1234);
    }
    // ── MKDIR dispatch tests ──────────────────────────────────────────

    #[test]
    fn mkdir_success_classifies_as_namespace_mut() {
        let dispatch = dispatch_mkdir(2001, 42, 1000, 1000, 99, true);

        assert_eq!(dispatch.context.unique, 2001);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_MKDIR);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32()
        );
        assert_eq!(dispatch.context.nodeid, 42);
        assert_eq!(dispatch.context.shard_key, 42);
        assert_eq!(dispatch.parent, 42);
        assert_eq!(dispatch.commit.unique, 2001);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, FUSE_ENTRY_OUT_WIRE_SIZE);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn mkdir_error_returns_eexist_commit() {
        let dispatch = dispatch_mkdir(2002, 42, 1000, 1000, 99, false);

        assert_eq!(dispatch.commit.unique, 2002);
        assert_eq!(dispatch.commit.error_or_zero, ERRNO_EEXIST);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn mkdir_error_preserves_context_classification() {
        let dispatch = dispatch_mkdir(2003, 42, 1000, 1000, 99, false);

        assert_eq!(dispatch.context.unique, 2003);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_MKDIR);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(dispatch.parent, 42);
    }

    #[test]
    fn mkdir_context_includes_uid_gid_pid() {
        let dispatch = dispatch_mkdir(2004, 99, 500, 501, 123, true);

        assert_eq!(dispatch.context.uid, 500);
        assert_eq!(dispatch.context.gid, 501);
        assert_eq!(dispatch.context.pid, 123);
    }

    #[test]
    fn mkdir_shard_key_is_parent_inode() {
        let dispatch = dispatch_mkdir(2005, 0x1234, 0, 0, 0, true);

        assert_eq!(dispatch.context.shard_key, 0x1234);
        assert_eq!(dispatch.context.nodeid, 0x1234);
    }
    // ── GETXATTR dispatch tests ───────────────────────────────────────

    #[test]
    fn getxattr_classifies_as_namespace_mut() {
        let dispatch = dispatch_getxattr(1101, 42, 1000, 1000, 99);

        assert_eq!(dispatch.context.unique, 1101);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_GETXATTR);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32()
        );
        assert_eq!(dispatch.context.nodeid, 42);
        assert_eq!(dispatch.context.shard_key, 42);
        assert_eq!(dispatch.ino, 42);
        assert_eq!(dispatch.commit.unique, 1101);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn getxattr_context_includes_uid_gid_pid() {
        let dispatch = dispatch_getxattr(1102, 99, 500, 501, 123);

        assert_eq!(dispatch.context.uid, 500);
        assert_eq!(dispatch.context.gid, 501);
        assert_eq!(dispatch.context.pid, 123);
    }

    #[test]
    fn getxattr_shard_key_is_inode() {
        let dispatch = dispatch_getxattr(1103, 0x1234, 0, 0, 0);

        assert_eq!(dispatch.context.shard_key, 0x1234);
        assert_eq!(dispatch.ino, 0x1234);
    }

    // ── SETXATTR dispatch tests ───────────────────────────────────────

    #[test]
    fn setxattr_classifies_as_namespace_mut() {
        let dispatch = dispatch_setxattr(1201, 42, 1000, 1000, 99);

        assert_eq!(dispatch.context.unique, 1201);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_SETXATTR);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32()
        );
        assert_eq!(dispatch.context.nodeid, 42);
        assert_eq!(dispatch.context.shard_key, 42);
        assert_eq!(dispatch.ino, 42);
        assert_eq!(dispatch.commit.unique, 1201);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn setxattr_context_includes_uid_gid_pid() {
        let dispatch = dispatch_setxattr(1202, 99, 500, 501, 123);

        assert_eq!(dispatch.context.uid, 500);
        assert_eq!(dispatch.context.gid, 501);
        assert_eq!(dispatch.context.pid, 123);
    }

    #[test]
    fn setxattr_shard_key_is_inode() {
        let dispatch = dispatch_setxattr(1203, 0x5678, 0, 0, 0);

        assert_eq!(dispatch.context.shard_key, 0x5678);
        assert_eq!(dispatch.ino, 0x5678);
    }

    // ── LISTXATTR dispatch tests ──────────────────────────────────────

    #[test]
    fn listxattr_classifies_as_namespace_mut() {
        let dispatch = dispatch_listxattr(1301, 42, 1000, 1000, 99);

        assert_eq!(dispatch.context.unique, 1301);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_LISTXATTR);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32()
        );
        assert_eq!(dispatch.context.nodeid, 42);
        assert_eq!(dispatch.context.shard_key, 42);
        assert_eq!(dispatch.ino, 42);
        assert_eq!(dispatch.commit.unique, 1301);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn listxattr_context_includes_uid_gid_pid() {
        let dispatch = dispatch_listxattr(1302, 99, 500, 501, 123);

        assert_eq!(dispatch.context.uid, 500);
        assert_eq!(dispatch.context.gid, 501);
        assert_eq!(dispatch.context.pid, 123);
    }

    #[test]
    fn listxattr_shard_key_is_inode() {
        let dispatch = dispatch_listxattr(1303, 0xABCD, 0, 0, 0);

        assert_eq!(dispatch.context.shard_key, 0xABCD);
        assert_eq!(dispatch.ino, 0xABCD);
    }

    // ── REMOVEXATTR dispatch tests ────────────────────────────────────

    #[test]
    fn removexattr_classifies_as_namespace_mut() {
        let dispatch = dispatch_removexattr(1401, 42, 1000, 1000, 99);

        assert_eq!(dispatch.context.unique, 1401);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_REMOVEXATTR);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32()
        );
        assert_eq!(dispatch.context.nodeid, 42);
        assert_eq!(dispatch.context.shard_key, 42);
        assert_eq!(dispatch.ino, 42);
        assert_eq!(dispatch.commit.unique, 1401);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn removexattr_context_includes_uid_gid_pid() {
        let dispatch = dispatch_removexattr(1402, 99, 500, 501, 123);

        assert_eq!(dispatch.context.uid, 500);
        assert_eq!(dispatch.context.gid, 501);
        assert_eq!(dispatch.context.pid, 123);
    }

    #[test]
    fn removexattr_shard_key_is_inode() {
        let dispatch = dispatch_removexattr(1403, 0xDEAD, 0, 0, 0);

        assert_eq!(dispatch.context.shard_key, 0xDEAD);
        assert_eq!(dispatch.ino, 0xDEAD);
    }

    // ── FSYNC dispatch tests ──────────────────────────────────────────

    #[test]
    fn fsync_dispatch_classifies_as_file_writeback() {
        let dispatch = dispatch_fsync(1501, 7, 1000, 1000, 42, 0xfeed, 0);

        assert_eq!(dispatch.context.unique, 1501);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_FSYNC);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::FileWriteback.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ObjectWrite.as_u32()
        );
    }

    #[test]
    fn fsync_dispatch_commits_empty_small_reply() {
        let dispatch = dispatch_fsync(1502, 7, 1000, 1000, 42, 0xfeed, 0);

        assert_eq!(dispatch.commit.unique, 1502);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn fsync_dispatch_shard_key_is_fh() {
        let dispatch = dispatch_fsync(1503, 0x42, 1000, 1000, 42, 0x99, 0);

        assert_eq!(dispatch.context.nodeid, 0x42);
        assert_eq!(dispatch.context.shard_key, 0x99);
        assert_ne!(dispatch.context.shard_key, dispatch.context.nodeid);
    }

    #[test]
    fn fsync_dispatch_context_includes_uid_gid_pid() {
        let dispatch = dispatch_fsync(1504, 8, 2000, 3000, 99, 0xfeed, 0);

        assert_eq!(dispatch.context.uid, 2000);
        assert_eq!(dispatch.context.gid, 3000);
        assert_eq!(dispatch.context.pid, 99);
    }

    #[test]
    fn fsync_dispatch_stores_fh_and_fsync_flags() {
        let dispatch = dispatch_fsync(1505, 9, 1000, 1000, 42, 0xCAFE, 0);

        assert_eq!(dispatch.fh, 0xCAFE);
        assert_eq!(dispatch.fsync_flags, 0);
    }

    #[test]
    fn fsync_dispatch_fdatasync_flag() {
        let dispatch = dispatch_fsync(
            1506,
            10,
            1000,
            1000,
            42,
            0xBEEF,
            crate::fusewire::fsync_flags::FUSE_FSYNC_FDATASYNC,
        );

        assert_eq!(dispatch.fh, 0xBEEF);
        assert_eq!(dispatch.fsync_flags, 1 << 0);
    }

    // ── FSYNCDIR dispatch tests ───────────────────────────────────────

    #[test]
    fn fsyncdir_dispatch_classifies_as_dirstream() {
        let dispatch = dispatch_fsyncdir(1601, 7, 1000, 1000, 42, 0xfeed);

        assert_eq!(dispatch.context.unique, 1601);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_FSYNCDIR);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::DirStream.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::DirHandle.as_u32()
        );
    }

    #[test]
    fn fsyncdir_dispatch_commits_empty_small_reply() {
        let dispatch = dispatch_fsyncdir(1602, 7, 1000, 1000, 42, 0xfeed);

        assert_eq!(dispatch.commit.unique, 1602);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn fsyncdir_dispatch_shard_key_is_fh() {
        let dispatch = dispatch_fsyncdir(1603, 0x42, 1000, 1000, 42, 0x99);

        assert_eq!(dispatch.context.nodeid, 0x42);
        assert_eq!(dispatch.context.shard_key, 0x99);
        assert_ne!(dispatch.context.shard_key, dispatch.context.nodeid);
    }

    #[test]
    fn fsyncdir_dispatch_context_includes_uid_gid_pid() {
        let dispatch = dispatch_fsyncdir(1604, 8, 2000, 3000, 99, 0xfeed);

        assert_eq!(dispatch.context.uid, 2000);
        assert_eq!(dispatch.context.gid, 3000);
        assert_eq!(dispatch.context.pid, 99);
    }

    #[test]
    fn fsyncdir_dispatch_stores_fh() {
        let dispatch = dispatch_fsyncdir(1605, 9, 1000, 1000, 42, 0xCAFE);

        assert_eq!(dispatch.fh, 0xCAFE);
    }

    // ── FALLOCATE dispatch tests ──────────────────────────────────────

    #[test]
    fn fallocate_dispatch_classifies_as_file_writeback() {
        let dispatch = dispatch_fallocate(fallocate_request(1701, 7, 0xfeed));

        assert_eq!(dispatch.context.unique, 1701);
        assert_eq!(dispatch.context.opcode, opcode::FUSE_FALLOCATE);
        assert_eq!(
            dispatch.context.request_class,
            PosixFilesystemAdapterRequestClass::FileWriteback.as_u32()
        );
        assert_eq!(
            dispatch.context.shard_key_policy,
            PosixFilesystemAdapterShardKeyPolicy::ObjectWrite.as_u32()
        );
    }

    #[test]
    fn fallocate_dispatch_commits_empty_small_reply() {
        let dispatch = dispatch_fallocate(fallocate_request(1702, 7, 0xfeed));

        assert_eq!(dispatch.commit.unique, 1702);
        assert_eq!(dispatch.commit.error_or_zero, 0);
        assert_eq!(dispatch.commit.payload_len, 0);
        assert_eq!(
            dispatch.commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn fallocate_dispatch_shard_key_is_fh() {
        let dispatch = dispatch_fallocate(fallocate_request(1703, 0x42, 0x99));

        assert_eq!(dispatch.context.nodeid, 0x42);
        assert_eq!(dispatch.context.shard_key, 0x99);
        assert_ne!(dispatch.context.shard_key, dispatch.context.nodeid);
    }

    #[test]
    fn fallocate_dispatch_context_includes_uid_gid_pid() {
        let dispatch = dispatch_fallocate(FallocateDispatchRequest {
            uid: 2000,
            gid: 3000,
            pid: 99,
            ..fallocate_request(1704, 8, 0xfeed)
        });

        assert_eq!(dispatch.context.uid, 2000);
        assert_eq!(dispatch.context.gid, 3000);
        assert_eq!(dispatch.context.pid, 99);
    }

    #[test]
    fn fallocate_dispatch_stores_offset_length_mode() {
        let dispatch = dispatch_fallocate(FallocateDispatchRequest {
            offset: 0x1000,
            length: 0x2000,
            mode: falloc_flags::FALLOC_FL_KEEP_SIZE,
            ..fallocate_request(1705, 9, 0xBEEF)
        });

        assert_eq!(dispatch.fh, 0xBEEF);
        assert_eq!(dispatch.offset, 0x1000);
        assert_eq!(dispatch.length, 0x2000);
        assert_eq!(dispatch.mode, falloc_flags::FALLOC_FL_KEEP_SIZE);
    }

    #[test]
    fn fallocate_mode_flags() {
        assert_eq!(falloc_flags::FALLOC_FL_KEEP_SIZE, 0x01);
        assert_eq!(falloc_flags::FALLOC_FL_PUNCH_HOLE, 0x02);
        assert_eq!(falloc_flags::FALLOC_FL_ZERO_RANGE, 0x10);

        let combined = falloc_flags::FALLOC_FL_KEEP_SIZE | falloc_flags::FALLOC_FL_PUNCH_HOLE;
        let dispatch = dispatch_fallocate(FallocateDispatchRequest {
            mode: combined,
            ..fallocate_request(1706, 10, 0xBEEF)
        });
        assert_eq!(dispatch.mode, 0x03);
    }
}
