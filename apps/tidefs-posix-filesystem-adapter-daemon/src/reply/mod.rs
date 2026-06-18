// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! P5-02 FUSE reply commit lanes (reply_class_0.small_reply, reply_class_1.bulk_reply)
//! and directory-entry wire-format serialization (issue #2523).
//!
//! Provides reply formatting helpers for FUSE operations including lookup
//! entry replies with entry/attribute timeout encoding, error replies, and
//! commit-record builders for both small (metadata) and bulk (data) reply
//! classes.
//!
//! Part of the P5-02 classified multipool topology for the userspace FUSE runtime.
//! This seam family is one of 10 explicit crate boundaries that separate ingress,
//! scheduling, workers, reply commit, and maintenance so they do not blur
//! into one daemon blob.
//!
//! # Directory-entry wire format (issue #2523)
//!
//! The `DirentPlusWire` type and its associated packer encode directory entries
//! plus resolved inode attributes into the FUSE wire layout expected by the
//! kernel for READDIRPLUS responses.  The layout mirrors `struct fuse_direntplus`
//! from Linux `fuse_kernel.h`:
//!
//! ```text
//! fuse_direntplus {
//!   fuse_entry_out entry_out;   // inode attr + generation + ttl
//!   fuse_dirent    dirent;       // ino, off, namelen, type, name[N]
//! }
//! ```
//!
//! The packer respects kernel buffer limits (`max_readdir`) and returns the
//! next `off` cookie so the kernel can resume iteration.

use std::vec::Vec;
use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterReplyClass, PosixFilesystemAdapterReplyCommitRecord,
};

/// Re-export all P5-02 request-queue types and runtime functions for this seam family.
pub const SEAM_FAMILY_DOC: &str = concat!("seam.", env!("CARGO_PKG_NAME"), ".    P5-02.v0");

// ── Lookup entry reply ───────────────────────────────────────────────────

/// FUSE entry-out reply payload sent in response to a lookup operation.
///
/// Carries the resolved child inode number, generation, entry/attribute
/// cache timeout values, and a result flag (success or negative lookup).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LookupEntryAttr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
    pub padding: u32,
}

impl LookupEntryAttr {
    pub const ZERO: Self = Self {
        ino: 0,
        size: 0,
        blocks: 0,
        atime: 0,
        mtime: 0,
        ctime: 0,
        atimensec: 0,
        mtimensec: 0,
        ctimensec: 0,
        mode: 0,
        nlink: 0,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 0,
        padding: 0,
    };

    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        ino: u64,
        size: u64,
        blocks: u64,
        atime: u64,
        mtime: u64,
        ctime: u64,
        atimensec: u32,
        mtimensec: u32,
        ctimensec: u32,
        mode: u32,
        nlink: u32,
        uid: u32,
        gid: u32,
        rdev: u32,
        blksize: u32,
    ) -> Self {
        Self {
            ino,
            size,
            blocks,
            atime,
            mtime,
            ctime,
            atimensec,
            mtimensec,
            ctimensec,
            mode,
            nlink,
            uid,
            gid,
            rdev,
            blksize,
            padding: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LookupEntryReply {
    /// Child inode number (zero for negative lookups).
    pub nodeid: u64,
    /// Inode generation (incremented on reuse).
    pub generation: u64,
    /// Entry timeout seconds (directory entry cache).
    pub entry_valid: u64,
    /// Entry timeout nanoseconds.
    pub entry_valid_nsec: u32,
    /// Attribute timeout seconds (inode attribute cache).
    pub attr_valid: u64,
    /// Attribute timeout nanoseconds.
    pub attr_valid_nsec: u32,
    /// If true, this is a negative lookup (ENOENT).
    /// The kernel will cache the negative result.
    pub negative: bool,
    /// Embedded `fuse_attr` payload.
    pub attr: LookupEntryAttr,
}

impl LookupEntryReply {
    /// Build a positive lookup reply (child found).
    #[must_use]
    pub const fn positive(
        nodeid: u64,
        generation: u64,
        entry_ttl_secs: u64,
        entry_ttl_nsec: u32,
        attr_ttl_secs: u64,
        attr_ttl_nsec: u32,
    ) -> Self {
        Self {
            nodeid,
            generation,
            entry_valid: entry_ttl_secs,
            entry_valid_nsec: entry_ttl_nsec,
            attr_valid: attr_ttl_secs,
            attr_valid_nsec: attr_ttl_nsec,
            negative: false,
            attr: LookupEntryAttr::ZERO,
        }
    }

    #[must_use]
    pub const fn with_attr(mut self, attr: LookupEntryAttr) -> Self {
        self.attr = attr;
        self
    }

    /// Build a negative lookup reply (child not found).
    ///
    /// Sets nodeid=0, generation=0, and uses only entry_valid_nsec
    /// to signal negative caching duration (as per FUSE protocol).
    #[must_use]
    pub const fn negative(entry_ttl_secs: u64, entry_ttl_nsec: u32) -> Self {
        Self {
            nodeid: 0,
            generation: 0,
            entry_valid: entry_ttl_secs,
            entry_valid_nsec: entry_ttl_nsec,
            attr_valid: 0,
            attr_valid_nsec: 0,
            negative: true,
            attr: LookupEntryAttr::ZERO,
        }
    }
}

/// FUSE `statfs_out` reply payload.
///
/// This mirrors the repo-local statfs reply contract used by the capacity
/// adapter: eleven little-endian `u64` fields for an 88-byte payload.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StatfsReply {
    /// Total number of blocks in the filesystem.
    pub blocks: u64,
    /// Number of free blocks.
    pub bfree: u64,
    /// Number of free blocks available to unprivileged users.
    pub bavail: u64,
    /// Total number of file slots / inodes.
    pub files: u64,
    /// Number of free file slots.
    pub ffree: u64,
    /// Number of free file slots available to unprivileged users.
    pub favail: u64,
    /// Block size in bytes.
    pub bsize: u64,
    /// Maximum filename length.
    pub namemax: u32,
    /// Fragment size in bytes.
    pub frsize: u64,
}

impl StatfsReply {
    /// Create a minimal reply with only block and fragment size set.
    #[must_use]
    pub const fn new(block_size: u64) -> Self {
        Self {
            blocks: 0,
            bfree: 0,
            bavail: 0,
            files: 0,
            ffree: 0,
            favail: 0,
            bsize: block_size,
            namemax: 0,
            frsize: block_size,
        }
    }
}

/// FUSE `statx` reply fields carried inside `struct fuse_statx_out`.
///
/// Populated by the STATX dispatch handler from `PosixAttrs` fields.
/// The `stx_mask` field indicates which fields are valid.
/// The reply builder wraps these fields in the FUSE `fuse_statx_out` envelope.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StatxReply {
    pub stx_mask: u32,
    pub stx_blksize: u32,
    pub stx_attributes: u64,
    pub stx_nlink: u32,
    pub stx_uid: u32,
    pub stx_gid: u32,
    pub stx_mode: u16,
    pub __spare0: u16,
    pub stx_ino: u64,
    pub stx_size: u64,
    pub stx_blocks: u64,
    pub stx_attributes_mask: u64,
    pub stx_atime_sec: i64,
    pub stx_atime_nsec: u32,
    pub stx_mtime_sec: i64,
    pub stx_mtime_nsec: u32,
    pub stx_ctime_sec: i64,
    pub stx_ctime_nsec: u32,
    pub stx_btime_sec: i64,
    pub stx_btime_nsec: u32,
    pub stx_mnt_id: u64,
    pub stx_dio_mem_align: u32,
    pub stx_dio_offset_align: u32,
    pub __spare3: [u64; 12],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LookupEntryEncodeError {
    BufferTooSmall { required: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrReplyEncodeError {
    PayloadTooLarge { max: usize, actual: usize },
}

/// POSIX errno constants used by reply formatting.
pub mod reply_errno {
    pub const EPERM: i32 = 1;
    pub const ENOENT: i32 = 2;
    pub const EIO: i32 = 5;
    pub const EACCES: i32 = 13;
    pub const EEXIST: i32 = 17;
    pub const ENOTDIR: i32 = 20;
    pub const EINVAL: i32 = 22;
    pub const ENOSPC: i32 = 28;
    pub const EROFS: i32 = 30;
    pub const ENOSYS: i32 = 38;
    pub const ENOTEMPTY: i32 = 39;
}

/// Reply-layer error categories with stable POSIX errno mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyError {
    PermissionDenied,
    NotFound,
    Io,
    AccessDenied,
    AlreadyExists,
    NotDirectory,
    InvalidInput,
    NoSpace,
    ReadOnly,
    NotSupported,
    NotEmpty,
}

/// Maps domain errors into positive POSIX errno values.
pub trait ErrorMapper {
    fn errno(&self) -> i32;
}

impl ErrorMapper for ReplyError {
    fn errno(&self) -> i32 {
        match self {
            Self::PermissionDenied => reply_errno::EPERM,
            Self::NotFound => reply_errno::ENOENT,
            Self::Io => reply_errno::EIO,
            Self::AccessDenied => reply_errno::EACCES,
            Self::AlreadyExists => reply_errno::EEXIST,
            Self::NotDirectory => reply_errno::ENOTDIR,
            Self::InvalidInput => reply_errno::EINVAL,
            Self::NoSpace => reply_errno::ENOSPC,
            Self::ReadOnly => reply_errno::EROFS,
            Self::NotSupported => reply_errno::ENOSYS,
            Self::NotEmpty => reply_errno::ENOTEMPTY,
        }
    }
}

impl ErrorMapper for i32 {
    fn errno(&self) -> i32 {
        *self
    }
}

// ── Reply commit helpers ────────────────────────────────────────────────────

/// Build a reply commit record for a small (metadata/errno) reply.
///
/// `reply_class_0.small_reply` — single committer for metadata/errno/short buffers.
#[must_use]
pub fn commit_small_reply(
    unique: u64,
    error_or_zero: i32,
    payload_len: u32,
) -> PosixFilesystemAdapterReplyCommitRecord {
    PosixFilesystemAdapterReplyCommitRecord {
        unique,
        reply_class: PosixFilesystemAdapterReplyClass::SmallReply.as_u32(),
        error_or_zero,
        payload_len,
        _reserved: [0_u32; 2],
    }
}

/// Build a reply commit record for a bulk data reply.
///
/// `reply_class_1.bulk_reply` — one or two committers under reply-byte credits.
#[must_use]
pub fn commit_bulk_reply(
    unique: u64,
    error_or_zero: i32,
    payload_len: u32,
) -> PosixFilesystemAdapterReplyCommitRecord {
    PosixFilesystemAdapterReplyCommitRecord {
        unique,
        reply_class: PosixFilesystemAdapterReplyClass::BulkReply.as_u32(),
        error_or_zero,
        payload_len,
        _reserved: [0_u32; 2],
    }
}

/// Build a reply commit record with explicit reply class.
#[must_use]
pub fn commit_reply(
    unique: u64,
    reply_class: PosixFilesystemAdapterReplyClass,
    error_or_zero: i32,
    payload_len: u32,
) -> PosixFilesystemAdapterReplyCommitRecord {
    PosixFilesystemAdapterReplyCommitRecord {
        unique,
        reply_class: reply_class.as_u32(),
        error_or_zero,
        payload_len,
        _reserved: [0_u32; 2],
    }
}

/// Build a reply commit record for a successful lookup.
///
/// Returns a SmallReply commit with `error_or_zero = 0` and
/// `payload_len = sizeof(fuse_entry_out)` (the FUSE wire size
/// for an entry reply).
#[must_use]
pub fn commit_lookup_reply(
    unique: u64,
    _entry: &LookupEntryReply,
) -> PosixFilesystemAdapterReplyCommitRecord {
    // fuse_entry_out is 128 bytes on 64-bit:
    //   nodeid(8) + generation(8) + entry_valid(8) + attr_valid(8)
    //   + entry_valid_nsec(4) + attr_valid_nsec(4) + padding
    //   + fuse_attr (88 bytes) = 128
    const FUSE_ENTRY_OUT_LEN: u32 = 128;
    commit_small_reply(unique, 0, FUSE_ENTRY_OUT_LEN)
}

/// Build a reply commit record for a failed lookup (error reply).
///
/// Returns a SmallReply commit with `error_or_zero = errno` (negative)
/// and `payload_len = 0`.
#[must_use]
pub fn commit_lookup_error(unique: u64, errno: i32) -> PosixFilesystemAdapterReplyCommitRecord {
    commit_small_reply(unique, errno, 0)
}

/// Build a reply commit record for a successful rename.
///
/// FUSE rename replies carry no success payload.
#[must_use]
pub fn commit_rename_reply(unique: u64) -> PosixFilesystemAdapterReplyCommitRecord {
    commit_small_reply(unique, 0, FUSE_RENAME_OUT_WIRE_SIZE)
}

/// Build a reply commit record for a failed rename.
///
/// Returns a SmallReply commit with `error_or_zero = errno` and no payload.
#[must_use]
pub fn commit_rename_error(unique: u64, errno: i32) -> PosixFilesystemAdapterReplyCommitRecord {
    commit_small_reply(unique, errno, 0)
}

/// Build a reply commit record for a successful getattr/setattr reply.
///
/// Returns a SmallReply commit with `error_or_zero = 0` and
/// `payload_len = sizeof(fuse_attr_out)`.
#[must_use]
pub fn commit_attr_reply(unique: u64) -> PosixFilesystemAdapterReplyCommitRecord {
    commit_small_reply(unique, 0, FUSE_ATTR_OUT_WIRE_SIZE)
}

/// Build a reply commit record for a failed getattr/setattr reply.
///
/// Returns a SmallReply commit with `error_or_zero = errno` (negative)
/// and `payload_len = 0`.
#[must_use]
pub fn commit_attr_error(unique: u64, errno: i32) -> PosixFilesystemAdapterReplyCommitRecord {
    commit_small_reply(unique, errno, 0)
}

fn write_u32_le(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_le(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn append_fuse_out_header(out: &mut Vec<u8>, len: u32, error: i32, unique: u64) {
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&error.to_le_bytes());
    out.extend_from_slice(&unique.to_le_bytes());
}

fn append_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn append_u16_le(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn append_u64_le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn fuse_error(errno: i32) -> i32 {
    if errno > 0 {
        -errno
    } else {
        errno
    }
}

fn reply_with_payload(unique: u64, error: i32, payload: &[u8]) -> Vec<u8> {
    let len = (FUSE_OUT_HEADER_WIRE_SIZE + payload.len()) as u32;
    let mut out = Vec::with_capacity(len as usize);
    append_fuse_out_header(&mut out, len, error, unique);
    out.extend_from_slice(payload);
    out
}

fn append_lookup_entry_payload(out: &mut Vec<u8>, entry: &LookupEntryReply) -> usize {
    let start = out.len();
    let len = lookup_entry_wire_len();
    out.resize(start + len, 0);
    let _ = encode_lookup_entry_reply(entry, &mut out[start..start + len]);
    len
}

fn append_open_out_payload(out: &mut Vec<u8>, fh: u64, open_flags: u32) -> usize {
    append_u64_le(out, fh);
    append_u32_le(out, open_flags);
    append_u32_le(out, 0);
    FUSE_OPEN_OUT_WIRE_SIZE
}

fn append_statfs_payload(out: &mut Vec<u8>, statfs: &StatfsReply) -> usize {
    append_u64_le(out, statfs.blocks);
    append_u64_le(out, statfs.bfree);
    append_u64_le(out, statfs.bavail);
    append_u64_le(out, statfs.files);
    append_u64_le(out, statfs.ffree);
    append_u64_le(out, statfs.favail);
    append_u64_le(out, statfs.bsize);
    append_u64_le(out, u64::from(statfs.namemax));
    append_u64_le(out, statfs.frsize);
    append_u64_le(out, 0);
    append_u64_le(out, 0);
    FUSE_STATFS_OUT_WIRE_SIZE
}

/// Encode a [`StatxReply`] into the FUSE wire format.
///
/// The output buffer is extended by [`FUSE_STATX_OUT_WIRE_SIZE`] bytes
/// as `struct fuse_statx_out` from Linux `include/uapi/linux/fuse.h`.
fn append_statx_payload(out: &mut Vec<u8>, statx: &StatxReply) -> usize {
    let start = out.len();
    append_u64_le(out, 0); // attr_valid
    append_u32_le(out, 0); // attr_valid_nsec
    append_u32_le(out, 0); // flags
    append_u64_le(out, 0); // spare[0]
    append_u64_le(out, 0); // spare[1]

    append_u32_le(out, statx.stx_mask);
    append_u32_le(out, statx.stx_blksize);
    append_u64_le(out, statx.stx_attributes);
    append_u32_le(out, statx.stx_nlink);
    append_u32_le(out, statx.stx_uid);
    append_u32_le(out, statx.stx_gid);
    append_u16_le(out, statx.stx_mode);
    append_u16_le(out, statx.__spare0);
    append_u64_le(out, statx.stx_ino);
    append_u64_le(out, statx.stx_size);
    append_u64_le(out, statx.stx_blocks);
    append_u64_le(out, statx.stx_attributes_mask);
    append_u64_le(out, statx.stx_atime_sec as u64);
    append_u32_le(out, statx.stx_atime_nsec);
    append_u32_le(out, 0); // padding after atime
    append_u64_le(out, statx.stx_btime_sec as u64);
    append_u32_le(out, statx.stx_btime_nsec);
    append_u32_le(out, 0); // padding after btime
    append_u64_le(out, statx.stx_ctime_sec as u64);
    append_u32_le(out, statx.stx_ctime_nsec);
    append_u32_le(out, 0); // padding after ctime
    append_u64_le(out, statx.stx_mtime_sec as u64);
    append_u32_le(out, statx.stx_mtime_nsec);
    append_u32_le(out, 0); // padding after mtime
    append_u32_le(out, 0); // rdev_major
    append_u32_le(out, 0); // rdev_minor
    append_u32_le(out, 0); // dev_major
    append_u32_le(out, 0); // dev_minor
    append_u64_le(out, statx.stx_mnt_id);
    append_u32_le(out, statx.stx_dio_mem_align);
    append_u32_le(out, statx.stx_dio_offset_align);
    for value in statx.__spare3.iter().copied() {
        append_u64_le(out, value);
    }
    debug_assert_eq!(out.len() - start, FUSE_STATX_OUT_WIRE_SIZE);
    FUSE_STATX_OUT_WIRE_SIZE
}

fn append_xattr_size_payload(out: &mut Vec<u8>, size: u32) -> usize {
    append_u32_le(out, size);
    append_u32_le(out, 0);
    FUSE_GETXATTR_OUT_WIRE_SIZE
}

fn append_dirent_payload(out: &mut Vec<u8>, entry: &ReplyDirEntry<'_>) -> usize {
    let (wire, size) = pack_dirent(entry.ino, entry.off, entry.kind, entry.name);
    let start = out.len();
    append_u64_le(out, wire.ino);
    append_u64_le(out, wire.off);
    append_u32_le(out, wire.namelen);
    append_u32_le(out, wire.r#type);
    out.extend_from_slice(&wire.name[..wire.namelen as usize]);
    out.resize(start + size, 0);
    size
}

fn dirent_payload_size(entry: &ReplyDirEntry<'_>) -> usize {
    let name_len = entry.name.len().min(DIRENT_MAX_NAME);
    let total = FUSE_DIRENT_HEADER_SIZE + name_len;
    (total + 7) & !7
}

/// Builder for complete FUSE reply buffers.
///
/// Each returned buffer starts with a `fuse_out_header` followed by the
/// operation-specific payload, matching the Linux FUSE device wire contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplyBuilder {
    unique: u64,
}

impl ReplyBuilder {
    #[must_use]
    pub const fn new(unique: u64) -> Self {
        Self { unique }
    }

    #[must_use]
    pub const fn unique(self) -> u64 {
        self.unique
    }

    /// Build a successful reply with no payload.
    #[must_use]
    pub fn reply_none(self) -> Vec<u8> {
        reply_with_payload(self.unique, 0, &[])
    }

    /// Build an error reply with no payload.
    ///
    /// FUSE expects negative errno values in `fuse_out_header.error`; positive
    /// errno inputs are normalized for callers that carry conventional POSIX
    /// errno values.
    #[must_use]
    pub fn reply_error(self, errno: i32) -> Vec<u8> {
        reply_with_payload(self.unique, fuse_error(errno), &[])
    }

    /// Build an error reply from an [`ErrorMapper`] source.
    #[must_use]
    pub fn reply_mapped_error<E: ErrorMapper + ?Sized>(self, error: &E) -> Vec<u8> {
        self.reply_error(error.errno())
    }

    /// Build a lookup reply (`struct fuse_entry_out`).
    #[must_use]
    pub fn reply_lookup(self, entry: &LookupEntryReply) -> Vec<u8> {
        let mut payload = Vec::with_capacity(lookup_entry_wire_len());
        append_lookup_entry_payload(&mut payload, entry);
        reply_with_payload(self.unique, 0, &payload)
    }

    /// Build a read reply whose payload is the file data bytes.
    #[must_use]
    pub fn reply_read(self, data: &[u8]) -> Vec<u8> {
        reply_with_payload(self.unique, 0, data)
    }

    /// Build a readlink reply whose payload is the raw symlink target bytes.
    #[must_use]
    pub fn reply_readlink(self, target: &[u8]) -> Vec<u8> {
        self.reply_read(target)
    }

    /// Build a write reply payload (`struct fuse_write_out`).
    #[must_use]
    pub fn reply_write(self, size: u32) -> Vec<u8> {
        let mut payload = [0_u8; FUSE_WRITE_OUT_WIRE_SIZE];
        write_u32_le(&mut payload, 0, size);
        reply_with_payload(self.unique, 0, &payload)
    }

    /// Build a create reply (`struct fuse_create_out`).
    #[must_use]
    pub fn reply_create(self, entry: &LookupEntryReply, fh: u64, open_flags: u32) -> Vec<u8> {
        let mut payload = Vec::with_capacity(FUSE_CREATE_OUT_WIRE_SIZE);
        append_lookup_entry_payload(&mut payload, entry);
        append_open_out_payload(&mut payload, fh, open_flags);
        reply_with_payload(self.unique, 0, &payload)
    }

    /// Build a mkdir reply with the same entry payload as lookup.
    #[must_use]
    pub fn reply_mkdir(self, entry: &LookupEntryReply) -> Vec<u8> {
        self.reply_lookup(entry)
    }

    /// Build an unlink success reply.
    #[must_use]
    pub fn reply_unlink(self) -> Vec<u8> {
        self.reply_none()
    }

    /// Build an rmdir success reply.
    #[must_use]
    pub fn reply_rmdir(self) -> Vec<u8> {
        self.reply_none()
    }

    /// Build a rename success reply.
    #[must_use]
    pub fn reply_rename(self) -> Vec<u8> {
        self.reply_none()
    }

    /// Build a statfs reply payload (`struct fuse_statfs_out`).
    #[must_use]
    pub fn reply_statfs(self, statfs: &StatfsReply) -> Vec<u8> {
        let mut payload = Vec::with_capacity(FUSE_STATFS_OUT_WIRE_SIZE);
        append_statfs_payload(&mut payload, statfs);
        reply_with_payload(self.unique, 0, &payload)
    }

    /// Build a statx reply payload (`struct fuse_statx_out`).
    #[must_use]
    pub fn reply_statx(self, statx: &StatxReply) -> Vec<u8> {
        let mut payload = Vec::with_capacity(FUSE_STATX_OUT_WIRE_SIZE);
        append_statx_payload(&mut payload, statx);
        reply_with_payload(self.unique, 0, &payload)
    }

    /// Build a GETXATTR size-probe reply (`struct fuse_getxattr_out`).
    #[must_use]
    pub fn reply_getxattr_size(self, size: u32) -> Vec<u8> {
        let mut payload = Vec::with_capacity(FUSE_GETXATTR_OUT_WIRE_SIZE);
        append_xattr_size_payload(&mut payload, size);
        reply_with_payload(self.unique, 0, &payload)
    }

    /// Build a LISTXATTR size-probe reply (`struct fuse_getxattr_out`).
    #[must_use]
    pub fn reply_listxattr_size(self, size: u32) -> Vec<u8> {
        self.reply_getxattr_size(size)
    }

    /// Build a GETXATTR value reply whose payload is the raw xattr value bytes.
    pub fn reply_getxattr_value(self, value: &[u8]) -> Result<Vec<u8>, XattrReplyEncodeError> {
        if value.len() > XATTR_REPLY_MAX_PAYLOAD {
            return Err(XattrReplyEncodeError::PayloadTooLarge {
                max: XATTR_REPLY_MAX_PAYLOAD,
                actual: value.len(),
            });
        }
        Ok(reply_with_payload(self.unique, 0, value))
    }

    /// Build a LISTXATTR reply whose payload is the raw NUL-separated name list.
    pub fn reply_listxattr_names(self, names: &[u8]) -> Result<Vec<u8>, XattrReplyEncodeError> {
        if names.len() > XATTR_REPLY_MAX_PAYLOAD {
            return Err(XattrReplyEncodeError::PayloadTooLarge {
                max: XATTR_REPLY_MAX_PAYLOAD,
                actual: names.len(),
            });
        }
        Ok(reply_with_payload(self.unique, 0, names))
    }

    /// Build a READDIR reply from packed directory entries.
    #[must_use]
    pub fn reply_readdir(self, entries: &[ReplyDirEntry<'_>], max_payload_bytes: usize) -> Vec<u8> {
        let limit = max_payload_bytes.min(READDIR_MAX_BUFFER);
        let mut payload = Vec::new();
        for entry in entries {
            let entry_size = dirent_payload_size(entry);
            let remaining = limit.saturating_sub(payload.len());
            if would_overflow(remaining, entry_size) {
                break;
            }
            append_dirent_payload(&mut payload, entry);
        }
        reply_with_payload(self.unique, 0, &payload)
    }

    /// Build a READDIRPLUS reply from packed directory entries and attributes.
    #[must_use]
    pub fn reply_readdirplus(
        self,
        entries: &[ReplyDirEntryPlus<'_>],
        max_payload_bytes: usize,
    ) -> Vec<u8> {
        let limit = max_payload_bytes.min(READDIR_MAX_BUFFER);
        let mut payload = Vec::new();
        for entry in entries {
            let dirent_size = dirent_payload_size(&entry.dirent);
            let entry_size = lookup_entry_wire_len() + dirent_size;
            let remaining = limit.saturating_sub(payload.len());
            if would_overflow(remaining, entry_size) {
                break;
            }
            let lookup = entry.lookup_entry();
            append_lookup_entry_payload(&mut payload, &lookup);
            append_dirent_payload(&mut payload, &entry.dirent);
        }
        reply_with_payload(self.unique, 0, &payload)
    }
}

#[must_use]
pub const fn lookup_entry_wire_len() -> usize {
    FUSE_ENTRY_OUT_WIRE_SIZE as usize
}

#[must_use]
pub const fn rename_reply_wire_len() -> usize {
    FUSE_RENAME_OUT_WIRE_SIZE as usize
}

pub fn encode_lookup_entry_reply(
    entry: &LookupEntryReply,
    out: &mut [u8],
) -> Result<usize, LookupEntryEncodeError> {
    let required = lookup_entry_wire_len();
    if out.len() < required {
        return Err(LookupEntryEncodeError::BufferTooSmall {
            required,
            actual: out.len(),
        });
    }

    let out = &mut out[..required];
    for byte in out.iter_mut() {
        *byte = 0;
    }

    write_u64_le(out, 0, entry.nodeid);
    write_u64_le(out, 8, entry.generation);
    write_u64_le(out, 16, entry.entry_valid);
    write_u64_le(out, 24, entry.attr_valid);
    write_u32_le(out, 32, entry.entry_valid_nsec);
    write_u32_le(out, 36, entry.attr_valid_nsec);

    write_u64_le(out, 40, entry.attr.ino);
    write_u64_le(out, 48, entry.attr.size);
    write_u64_le(out, 56, entry.attr.blocks);
    write_u64_le(out, 64, entry.attr.atime);
    write_u64_le(out, 72, entry.attr.mtime);
    write_u64_le(out, 80, entry.attr.ctime);
    write_u32_le(out, 88, entry.attr.atimensec);
    write_u32_le(out, 92, entry.attr.mtimensec);
    write_u32_le(out, 96, entry.attr.ctimensec);
    write_u32_le(out, 100, entry.attr.mode);
    write_u32_le(out, 104, entry.attr.nlink);
    write_u32_le(out, 108, entry.attr.uid);
    write_u32_le(out, 112, entry.attr.gid);
    write_u32_le(out, 116, entry.attr.rdev);
    write_u32_le(out, 120, entry.attr.blksize);
    write_u32_le(out, 124, entry.attr.padding);

    Ok(required)
}

// ── FUSE wire-size constants ─────────────────────────────────────────────

/// Wire size of `fuse_out_header` in bytes.
pub const FUSE_OUT_HEADER_WIRE_SIZE: usize = 16;

/// Wire size of `fuse_entry_out` in bytes (including embedded `fuse_attr`).
pub const FUSE_ENTRY_OUT_WIRE_SIZE: u32 = 128;

/// Wire size of `fuse_attr_out` in bytes.
pub const FUSE_ATTR_OUT_WIRE_SIZE: u32 = 120;

/// Wire size of `fuse_write_out` in bytes.
pub const FUSE_WRITE_OUT_WIRE_SIZE: usize = 8;

/// Wire size of `fuse_getxattr_out` in bytes.
pub const FUSE_GETXATTR_OUT_WIRE_SIZE: usize = 8;

/// Wire size of `fuse_open_out` in bytes.
pub const FUSE_OPEN_OUT_WIRE_SIZE: usize = 16;

/// Wire size of `fuse_create_out` in bytes.
pub const FUSE_CREATE_OUT_WIRE_SIZE: usize =
    FUSE_ENTRY_OUT_WIRE_SIZE as usize + FUSE_OPEN_OUT_WIRE_SIZE;

/// Wire size of the repo-local `fuse_statfs_out` payload in bytes.
pub const FUSE_STATFS_OUT_WIRE_SIZE: usize = 88;

/// Wire size of the repo-local `fuse_statx_out` payload in bytes.
pub const FUSE_STATX_OUT_WIRE_SIZE: usize = 288;

/// Maximum payload accepted by Linux xattr value and list replies.
pub const XATTR_REPLY_MAX_PAYLOAD: usize = 65_536;

// ── Directory-entry wire format (issue #2523) ────────────────────────────

/// Maximum length of a directory entry name on the wire.
pub const DIRENT_MAX_NAME: usize = 255;

/// Packed wire-format directory entry without attributes (used by READDIR).
///
/// Mirrors `struct fuse_dirent` from Linux fuse_kernel.h:
/// ```text
/// struct fuse_dirent {
///   __u64 ino;
///   __u64 off;
///   __u32 namelen;
///   __u32 type;
///   char  name[];
/// };
/// ```
#[derive(Clone, Copy, Debug)]
pub struct DirentWire {
    pub ino: u64,
    pub off: u64,
    pub namelen: u32,
    pub r#type: u32,
    pub name: [u8; DIRENT_MAX_NAME],
}

impl DirentWire {
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            ino: 0,
            off: 0,
            namelen: 0,
            r#type: 0,
            name: [0u8; DIRENT_MAX_NAME],
        }
    }
}

/// Directory entry input for a READDIR reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplyDirEntry<'a> {
    pub ino: u64,
    pub off: u64,
    pub kind: u32,
    pub name: &'a [u8],
}

impl<'a> ReplyDirEntry<'a> {
    #[must_use]
    pub const fn new(ino: u64, off: u64, kind: u32, name: &'a [u8]) -> Self {
        Self {
            ino,
            off,
            kind,
            name,
        }
    }
}

/// Directory entry input for a READDIRPLUS reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplyDirEntryPlus<'a> {
    pub dirent: ReplyDirEntry<'a>,
    pub generation: u64,
    pub entry_valid: u64,
    pub entry_valid_nsec: u32,
    pub attr_valid: u64,
    pub attr_valid_nsec: u32,
    pub attr: LookupEntryAttr,
}

impl<'a> ReplyDirEntryPlus<'a> {
    #[must_use]
    pub const fn new(
        dirent: ReplyDirEntry<'a>,
        generation: u64,
        entry_valid: u64,
        entry_valid_nsec: u32,
        attr_valid: u64,
        attr_valid_nsec: u32,
        attr: LookupEntryAttr,
    ) -> Self {
        Self {
            dirent,
            generation,
            entry_valid,
            entry_valid_nsec,
            attr_valid,
            attr_valid_nsec,
            attr,
        }
    }

    #[must_use]
    pub const fn lookup_entry(self) -> LookupEntryReply {
        LookupEntryReply {
            nodeid: self.dirent.ino,
            generation: self.generation,
            entry_valid: self.entry_valid,
            entry_valid_nsec: self.entry_valid_nsec,
            attr_valid: self.attr_valid,
            attr_valid_nsec: self.attr_valid_nsec,
            negative: false,
            attr: self.attr,
        }
    }
}

/// Wire size of `struct fuse_dirent` header (ino + off + namelen + type)
/// excluding the variable-length name.
pub const FUSE_DIRENT_HEADER_SIZE: usize = 24;

/// Pack a single directory entry into wire format.
///
/// Returns the total wire size consumed (header + padded name).
/// The kernel requires each dirent to be aligned to 8 bytes;
/// the name is padded to the next 8-byte boundary.
#[must_use]
pub fn pack_dirent(ino: u64, off: u64, r#type: u32, name: &[u8]) -> (DirentWire, usize) {
    let namelen = (name.len().min(DIRENT_MAX_NAME)) as u32;
    let mut wire = DirentWire::zeroed();
    wire.ino = ino;
    wire.off = off;
    wire.namelen = namelen;
    wire.r#type = r#type;
    let n = namelen as usize;
    wire.name[..n].copy_from_slice(&name[..n]);
    let total = FUSE_DIRENT_HEADER_SIZE + n;
    let padded = (total + 7) & !7; // 8-byte alignment
    (wire, padded)
}

/// Packed wire-format directory entry with attributes (used by READDIRPLUS).
///
/// Mirrors `struct fuse_direntplus` from Linux fuse_kernel.h:
/// ```text
/// struct fuse_direntplus {
///   fuse_entry_out entry_out;   // 128 bytes on 64-bit
///   fuse_dirent    dirent;       // header + name
/// };
/// ```
#[derive(Clone, Copy, Debug)]
pub struct DirentPlusWire {
    /// Inode ID for the entry (from `fuse_entry_out::nodeid`).
    pub ino: u64,
    /// Generation number (from `fuse_entry_out::generation`).
    pub generation: u64,
    /// Entry validity timeout in nanoseconds (from `fuse_entry_out::entry_valid_nsec`).
    pub entry_valid_nsec: u64,
    /// Attribute validity timeout in nanoseconds (from `fuse_entry_out::attr_valid_nsec`).
    pub attr_valid_nsec: u64,
    /// POSIX attributes packed into `fuse_attr` layout.
    pub attr: DirentPlusAttr,
    /// The directory entry proper.
    pub dirent: DirentWire,
}

/// Packed `fuse_attr` within a `fuse_direntplus` entry (simplified).
///
/// Mirrors the core fields of `struct fuse_attr` that readdirplus needs.
#[derive(Clone, Copy, Debug, Default)]
pub struct DirentPlusAttr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime_ns: u64,
    pub mtime_ns: u64,
    pub ctime_ns: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
}

impl DirentPlusWire {
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            ino: 0,
            generation: 0,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr: DirentPlusAttr {
                ino: 0,
                size: 0,
                blocks: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                mode: 0,
                nlink: 0,
                uid: 0,
                gid: 0,
                rdev: 0,
                blksize: 0,
            },
            dirent: DirentWire::zeroed(),
        }
    }
}

/// Wire size of `fuse_entry_out` + `fuse_attr` structures (simplified layout).
///
/// `fuse_entry_out` = 16 bytes (nodeid: u64, generation: u64)
///   + entry_valid: u64 + attr_valid: u64 + entry_valid_nsec: u32 + attr_valid_nsec: u32 = 128 bytes total on 64-bit
///     `fuse_attr` = 64 bytes
pub const FUSE_ENTRY_OUT_SIZE: usize = 128;

/// Pack a directory entry with full attributes for READDIRPLUS.
///
/// Returns the packed entry and the total wire size consumed
/// (entry_out + dirent header + padded name).
#[must_use]
pub fn pack_dirent_plus(
    ino: u64,
    generation: u64,
    off: u64,
    name: &[u8],
    ttl_ns: u64,
    attr: DirentPlusAttr,
) -> (DirentPlusWire, usize) {
    let (dirent, dirent_size) = pack_dirent(ino, off, attr.mode >> 12, name);
    let wire = DirentPlusWire {
        ino,
        generation,
        entry_valid_nsec: ttl_ns,
        attr_valid_nsec: ttl_ns,
        attr,
        dirent,
    };
    let total = FUSE_ENTRY_OUT_SIZE + dirent_size;
    (wire, total)
}

/// Maximum reply buffer size for readdir/readdirplus (default Linux limit).
pub const READDIR_MAX_BUFFER: usize = 65536;

/// Check whether adding another entry (of `entry_wire_size` bytes) would
/// overflow the remaining `buf_remaining` capacity.
#[must_use]
pub fn would_overflow(buf_remaining: usize, entry_wire_size: usize) -> bool {
    entry_wire_size > buf_remaining
}
/// Wire size of a successful rename reply.
pub const FUSE_RENAME_OUT_WIRE_SIZE: u32 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }

    fn read_i32_le(bytes: &[u8], offset: usize) -> i32 {
        i32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }

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

    fn test_attr() -> LookupEntryAttr {
        LookupEntryAttr::new(
            42, 4096, 8, 10, 20, 30, 111, 222, 333, 0o100644, 2, 1000, 1001, 0, 4096,
        )
    }

    #[test]
    fn reply_builder_preserves_unique() {
        let builder = ReplyBuilder::new(123);
        assert_eq!(builder.unique(), 123);
    }

    #[test]
    fn reply_none_builds_empty_success_header() {
        let bytes = ReplyBuilder::new(42).reply_none();

        assert_eq!(bytes.len(), FUSE_OUT_HEADER_WIRE_SIZE);
        assert_eq!(read_u32_le(&bytes, 0), FUSE_OUT_HEADER_WIRE_SIZE as u32);
        assert_eq!(read_i32_le(&bytes, 4), 0);
        assert_eq!(read_u64_le(&bytes, 8), 42);
    }

    #[test]
    fn reply_error_normalizes_positive_errno() {
        let bytes = ReplyBuilder::new(77).reply_error(2);

        assert_eq!(bytes.len(), FUSE_OUT_HEADER_WIRE_SIZE);
        assert_eq!(read_u32_le(&bytes, 0), FUSE_OUT_HEADER_WIRE_SIZE as u32);
        assert_eq!(read_i32_le(&bytes, 4), -2);
        assert_eq!(read_u64_le(&bytes, 8), 77);
    }

    #[test]
    fn reply_error_preserves_negative_errno() {
        let bytes = ReplyBuilder::new(88).reply_error(-5);

        assert_eq!(read_i32_le(&bytes, 4), -5);
        assert_eq!(read_u64_le(&bytes, 8), 88);
    }

    #[test]
    fn reply_error_mapper_uses_stable_errno_values() {
        assert_eq!(ReplyError::NotFound.errno(), reply_errno::ENOENT);
        assert_eq!(ReplyError::NoSpace.errno(), reply_errno::ENOSPC);
        assert_eq!(ReplyError::ReadOnly.errno(), reply_errno::EROFS);
        assert_eq!(ReplyError::NotSupported.errno(), reply_errno::ENOSYS);
    }

    #[test]
    fn reply_mapped_error_builds_negative_fuse_error() {
        let bytes = ReplyBuilder::new(89).reply_mapped_error(&ReplyError::NoSpace);

        assert_eq!(bytes.len(), FUSE_OUT_HEADER_WIRE_SIZE);
        assert_eq!(read_i32_le(&bytes, 4), -reply_errno::ENOSPC);
        assert_eq!(read_u64_le(&bytes, 8), 89);
    }

    #[test]
    fn reply_read_embeds_data_after_header() {
        let bytes = ReplyBuilder::new(99).reply_read(b"hello");

        assert_eq!(read_u32_le(&bytes, 0), 21);
        assert_eq!(read_i32_le(&bytes, 4), 0);
        assert_eq!(read_u64_le(&bytes, 8), 99);
        assert_eq!(&bytes[FUSE_OUT_HEADER_WIRE_SIZE..], b"hello");
    }

    #[test]
    fn reply_readlink_embeds_target_after_header() {
        let bytes = ReplyBuilder::new(110).reply_readlink(b"../target");

        assert_eq!(read_u32_le(&bytes, 0), 25);
        assert_eq!(read_i32_le(&bytes, 4), 0);
        assert_eq!(read_u64_le(&bytes, 8), 110);
        assert_eq!(&bytes[FUSE_OUT_HEADER_WIRE_SIZE..], b"../target");
    }

    #[test]
    fn reply_write_serializes_fuse_write_out() {
        let bytes = ReplyBuilder::new(100).reply_write(4096);

        assert_eq!(
            bytes.len(),
            FUSE_OUT_HEADER_WIRE_SIZE + FUSE_WRITE_OUT_WIRE_SIZE
        );
        assert_eq!(read_u32_le(&bytes, 0), 24);
        assert_eq!(read_i32_le(&bytes, 4), 0);
        assert_eq!(read_u64_le(&bytes, 8), 100);
        assert_eq!(read_u32_le(&bytes, 16), 4096);
        assert_eq!(read_u32_le(&bytes, 20), 0);
    }

    #[test]
    fn reply_lookup_wraps_fuse_entry_out_after_header() {
        let entry = LookupEntryReply::positive(42, 7, 5, 123, 2, 456).with_attr(test_attr());
        let bytes = ReplyBuilder::new(101).reply_lookup(&entry);

        assert_eq!(
            bytes.len(),
            FUSE_OUT_HEADER_WIRE_SIZE + lookup_entry_wire_len()
        );
        assert_eq!(read_u32_le(&bytes, 0), 144);
        assert_eq!(read_i32_le(&bytes, 4), 0);
        assert_eq!(read_u64_le(&bytes, 8), 101);
        assert_eq!(read_u64_le(&bytes, 16), 42);
        assert_eq!(read_u64_le(&bytes, 24), 7);
        assert_eq!(read_u64_le(&bytes, 32), 5);
        assert_eq!(read_u64_le(&bytes, 40), 2);
        assert_eq!(read_u64_le(&bytes, 64), 4096);
    }

    #[test]
    fn reply_create_serializes_fuse_create_out() {
        let entry = LookupEntryReply::positive(55, 8, 1, 0, 1, 0).with_attr(test_attr());
        let bytes = ReplyBuilder::new(102).reply_create(&entry, 0xAABB_CCDD_EEFF_0011, 0x22);

        assert_eq!(
            bytes.len(),
            FUSE_OUT_HEADER_WIRE_SIZE + FUSE_CREATE_OUT_WIRE_SIZE
        );
        assert_eq!(read_u32_le(&bytes, 0), 160);
        assert_eq!(read_i32_le(&bytes, 4), 0);
        assert_eq!(read_u64_le(&bytes, 8), 102);
        assert_eq!(read_u64_le(&bytes, 16), 55);
        assert_eq!(read_u64_le(&bytes, 24), 8);
        assert_eq!(read_u64_le(&bytes, 144), 0xAABB_CCDD_EEFF_0011);
        assert_eq!(read_u32_le(&bytes, 152), 0x22);
        assert_eq!(read_u32_le(&bytes, 156), 0);
    }

    #[test]
    fn statfs_reply_new_sets_block_and_fragment_size() {
        let statfs = StatfsReply::new(4096);

        assert_eq!(statfs.bsize, 4096);
        assert_eq!(statfs.frsize, 4096);
        assert_eq!(statfs.blocks, 0);
        assert_eq!(statfs.namemax, 0);
    }

    #[test]
    fn reply_statfs_serializes_fuse_statfs_out_after_header() {
        let statfs = StatfsReply {
            blocks: 1_000,
            bfree: 900,
            bavail: 800,
            files: 700,
            ffree: 600,
            favail: 500,
            bsize: 4096,
            namemax: 255,
            frsize: 4096,
        };
        let bytes = ReplyBuilder::new(111).reply_statfs(&statfs);
        let payload = FUSE_OUT_HEADER_WIRE_SIZE;

        assert_eq!(
            bytes.len(),
            FUSE_OUT_HEADER_WIRE_SIZE + FUSE_STATFS_OUT_WIRE_SIZE
        );
        assert_eq!(read_u32_le(&bytes, 0), 104);
        assert_eq!(read_i32_le(&bytes, 4), 0);
        assert_eq!(read_u64_le(&bytes, 8), 111);
        assert_eq!(read_u64_le(&bytes, payload), 1_000);
        assert_eq!(read_u64_le(&bytes, payload + 8), 900);
        assert_eq!(read_u64_le(&bytes, payload + 16), 800);
        assert_eq!(read_u64_le(&bytes, payload + 24), 700);
        assert_eq!(read_u64_le(&bytes, payload + 32), 600);
        assert_eq!(read_u64_le(&bytes, payload + 40), 500);
        assert_eq!(read_u64_le(&bytes, payload + 48), 4096);
        assert_eq!(read_u64_le(&bytes, payload + 56), 255);
        assert_eq!(read_u64_le(&bytes, payload + 64), 4096);
        assert_eq!(read_u64_le(&bytes, payload + 72), 0);
        assert_eq!(read_u64_le(&bytes, payload + 80), 0);
    }

    #[test]
    fn reply_getxattr_size_serializes_fuse_getxattr_out() {
        let bytes = ReplyBuilder::new(112).reply_getxattr_size(4_096);
        let payload = FUSE_OUT_HEADER_WIRE_SIZE;

        assert_eq!(
            bytes.len(),
            FUSE_OUT_HEADER_WIRE_SIZE + FUSE_GETXATTR_OUT_WIRE_SIZE
        );
        assert_eq!(read_u32_le(&bytes, 0), 24);
        assert_eq!(read_i32_le(&bytes, 4), 0);
        assert_eq!(read_u64_le(&bytes, 8), 112);
        assert_eq!(read_u32_le(&bytes, payload), 4_096);
        assert_eq!(read_u32_le(&bytes, payload + 4), 0);
    }

    #[test]
    fn reply_listxattr_size_uses_getxattr_out_shape() {
        let bytes = ReplyBuilder::new(113).reply_listxattr_size(33);

        assert_eq!(bytes.len(), FUSE_OUT_HEADER_WIRE_SIZE + 8);
        assert_eq!(read_u32_le(&bytes, 0), 24);
        assert_eq!(read_i32_le(&bytes, 4), 0);
        assert_eq!(read_u64_le(&bytes, 8), 113);
        assert_eq!(read_u32_le(&bytes, 16), 33);
        assert_eq!(read_u32_le(&bytes, 20), 0);
    }

    #[test]
    fn reply_getxattr_value_embeds_value_after_header() {
        let bytes = ReplyBuilder::new(114)
            .reply_getxattr_value(b"opaque-value")
            .expect("xattr value reply");

        assert_eq!(read_u32_le(&bytes, 0), 28);
        assert_eq!(read_i32_le(&bytes, 4), 0);
        assert_eq!(read_u64_le(&bytes, 8), 114);
        assert_eq!(&bytes[FUSE_OUT_HEADER_WIRE_SIZE..], b"opaque-value");
    }

    #[test]
    fn reply_listxattr_names_allows_empty_list() {
        let bytes = ReplyBuilder::new(115)
            .reply_listxattr_names(&[])
            .expect("empty listxattr reply");

        assert_eq!(bytes.len(), FUSE_OUT_HEADER_WIRE_SIZE);
        assert_eq!(read_u32_le(&bytes, 0), FUSE_OUT_HEADER_WIRE_SIZE as u32);
        assert_eq!(read_i32_le(&bytes, 4), 0);
        assert_eq!(read_u64_le(&bytes, 8), 115);
    }

    #[test]
    fn reply_listxattr_names_embeds_nul_separated_names() {
        let names = b"user.alpha\0security.beta\0";
        let bytes = ReplyBuilder::new(116)
            .reply_listxattr_names(names)
            .expect("listxattr names reply");

        assert_eq!(read_u32_le(&bytes, 0), 16 + names.len() as u32);
        assert_eq!(read_i32_le(&bytes, 4), 0);
        assert_eq!(read_u64_le(&bytes, 8), 116);
        assert_eq!(&bytes[FUSE_OUT_HEADER_WIRE_SIZE..], names);
    }

    #[test]
    fn xattr_payload_replies_reject_oversized_payloads() {
        let too_large = std::vec![0_u8; XATTR_REPLY_MAX_PAYLOAD + 1];

        assert_eq!(
            ReplyBuilder::new(117).reply_getxattr_value(&too_large),
            Err(XattrReplyEncodeError::PayloadTooLarge {
                max: XATTR_REPLY_MAX_PAYLOAD,
                actual: XATTR_REPLY_MAX_PAYLOAD + 1
            })
        );
        assert_eq!(
            ReplyBuilder::new(118).reply_listxattr_names(&too_large),
            Err(XattrReplyEncodeError::PayloadTooLarge {
                max: XATTR_REPLY_MAX_PAYLOAD,
                actual: XATTR_REPLY_MAX_PAYLOAD + 1
            })
        );
    }

    #[test]
    fn reply_mkdir_uses_entry_payload() {
        let entry = LookupEntryReply::positive(55, 8, 1, 0, 1, 0).with_attr(test_attr());

        assert_eq!(
            ReplyBuilder::new(103).reply_mkdir(&entry),
            ReplyBuilder::new(103).reply_lookup(&entry)
        );
    }

    #[test]
    fn no_payload_mutation_replies_share_success_header() {
        let unlink = ReplyBuilder::new(104).reply_unlink();
        let rmdir = ReplyBuilder::new(105).reply_rmdir();
        let rename = ReplyBuilder::new(106).reply_rename();

        for (bytes, unique) in [(unlink, 104_u64), (rmdir, 105), (rename, 106)] {
            assert_eq!(bytes.len(), FUSE_OUT_HEADER_WIRE_SIZE);
            assert_eq!(read_u32_le(&bytes, 0), FUSE_OUT_HEADER_WIRE_SIZE as u32);
            assert_eq!(read_i32_le(&bytes, 4), 0);
            assert_eq!(read_u64_le(&bytes, 8), unique);
        }
    }

    #[test]
    fn reply_readdir_packs_entries_after_header() {
        let entries = [
            ReplyDirEntry::new(7, 11, 8, b"alpha"),
            ReplyDirEntry::new(8, 12, 4, b"beta"),
        ];
        let bytes = ReplyBuilder::new(107).reply_readdir(&entries, READDIR_MAX_BUFFER);

        assert_eq!(bytes.len(), FUSE_OUT_HEADER_WIRE_SIZE + 64);
        assert_eq!(read_u32_le(&bytes, 0), 80);
        assert_eq!(read_u64_le(&bytes, 8), 107);
        assert_eq!(read_u64_le(&bytes, 16), 7);
        assert_eq!(read_u64_le(&bytes, 24), 11);
        assert_eq!(read_u32_le(&bytes, 32), 5);
        assert_eq!(read_u32_le(&bytes, 36), 8);
        assert_eq!(&bytes[40..45], b"alpha");
        assert_eq!(read_u64_le(&bytes, 48), 8);
        assert_eq!(read_u64_le(&bytes, 56), 12);
        assert_eq!(read_u32_le(&bytes, 64), 4);
        assert_eq!(read_u32_le(&bytes, 68), 4);
        assert_eq!(&bytes[72..76], b"beta");
    }

    #[test]
    fn reply_readdir_stops_before_max_payload_overflow() {
        let entries = [
            ReplyDirEntry::new(7, 11, 8, b"alpha"),
            ReplyDirEntry::new(8, 12, 4, b"beta"),
        ];
        let bytes = ReplyBuilder::new(108).reply_readdir(&entries, 31);

        assert_eq!(bytes.len(), FUSE_OUT_HEADER_WIRE_SIZE);
        assert_eq!(read_u32_le(&bytes, 0), FUSE_OUT_HEADER_WIRE_SIZE as u32);
    }

    #[test]
    fn reply_readdirplus_packs_entry_out_then_dirent() {
        let attr = LookupEntryAttr::new(
            42, 2048, 4, 10, 20, 30, 111, 222, 333, 0o100644, 1, 1000, 1001, 0, 4096,
        );
        let dirent = ReplyDirEntry::new(42, 5, 8, b"file");
        let plus = ReplyDirEntryPlus::new(dirent, 9, 3, 123, 4, 456, attr);
        let bytes = ReplyBuilder::new(109).reply_readdirplus(&[plus], READDIR_MAX_BUFFER);

        assert_eq!(bytes.len(), FUSE_OUT_HEADER_WIRE_SIZE + 128 + 32);
        assert_eq!(read_u32_le(&bytes, 0), 176);
        assert_eq!(read_u64_le(&bytes, 8), 109);
        assert_eq!(read_u64_le(&bytes, 16), 42);
        assert_eq!(read_u64_le(&bytes, 24), 9);
        assert_eq!(read_u64_le(&bytes, 32), 3);
        assert_eq!(read_u64_le(&bytes, 40), 4);
        assert_eq!(read_u32_le(&bytes, 48), 123);
        assert_eq!(read_u32_le(&bytes, 52), 456);
        assert_eq!(read_u64_le(&bytes, 56), 42);
        assert_eq!(read_u64_le(&bytes, 144), 42);
        assert_eq!(read_u64_le(&bytes, 152), 5);
        assert_eq!(read_u32_le(&bytes, 160), 4);
        assert_eq!(read_u32_le(&bytes, 164), 8);
        assert_eq!(&bytes[168..172], b"file");
    }

    #[test]
    fn reply_readdirplus_max_name_length() {
        let name = std::vec![b'x'; DIRENT_MAX_NAME];
        let dirent_payload_len = (FUSE_DIRENT_HEADER_SIZE + DIRENT_MAX_NAME + 7) & !7;
        let attr = DirentPlusAttr {
            ino: 77,
            size: 4096,
            blocks: 8,
            mode: 0o100644,
            nlink: 1,
            uid: 1000,
            gid: 1001,
            blksize: 4096,
            ..Default::default()
        };
        let (wire, packed_len) = pack_dirent_plus(77, 12, 34, &name, 987_654_321, attr);

        assert_eq!(packed_len, FUSE_ENTRY_OUT_SIZE + dirent_payload_len);
        assert_eq!(packed_len, 408);
        assert_eq!(wire.ino, 77);
        assert_eq!(wire.generation, 12);
        assert_eq!(wire.entry_valid_nsec, 987_654_321);
        assert_eq!(wire.attr_valid_nsec, 987_654_321);
        assert_eq!(wire.dirent.ino, 77);
        assert_eq!(wire.dirent.off, 34);
        assert_eq!(wire.dirent.namelen as usize, DIRENT_MAX_NAME);
        assert_eq!(wire.dirent.r#type, 8);
        assert_eq!(&wire.dirent.name[..DIRENT_MAX_NAME], name.as_slice());

        let attr = LookupEntryAttr::new(
            77, 4096, 8, 10, 20, 30, 111, 222, 333, 0o100644, 1, 1000, 1001, 0, 4096,
        );
        let dirent = ReplyDirEntry::new(77, 34, 8, &name);
        let plus = ReplyDirEntryPlus::new(dirent, 12, 5, 123, 6, 456, attr);
        let bytes = ReplyBuilder::new(119).reply_readdirplus(&[plus], READDIR_MAX_BUFFER);
        let dirent_start = FUSE_OUT_HEADER_WIRE_SIZE + lookup_entry_wire_len();
        let name_start = dirent_start + FUSE_DIRENT_HEADER_SIZE;

        assert_eq!(bytes.len(), FUSE_OUT_HEADER_WIRE_SIZE + packed_len);
        assert_eq!(read_u32_le(&bytes, 0), bytes.len() as u32);
        assert_eq!(read_i32_le(&bytes, 4), 0);
        assert_eq!(read_u64_le(&bytes, 8), 119);
        assert!(bytes.len() > FUSE_OUT_HEADER_WIRE_SIZE);
        assert_eq!(read_u64_le(&bytes, dirent_start), 77);
        assert_eq!(read_u64_le(&bytes, dirent_start + 8), 34);
        assert_eq!(
            read_u32_le(&bytes, dirent_start + 16) as usize,
            DIRENT_MAX_NAME
        );
        assert_eq!(read_u32_le(&bytes, dirent_start + 20), 8);
        assert_eq!(
            &bytes[name_start..name_start + DIRENT_MAX_NAME],
            name.as_slice()
        );
        assert_eq!(bytes[name_start + DIRENT_MAX_NAME], 0);
    }

    #[test]
    fn reply_readdirplus_empty_directory() {
        let bytes = ReplyBuilder::new(120).reply_readdirplus(&[], READDIR_MAX_BUFFER);

        assert_eq!(bytes.len(), FUSE_OUT_HEADER_WIRE_SIZE);
        assert_eq!(read_u32_le(&bytes, 0), FUSE_OUT_HEADER_WIRE_SIZE as u32);
        assert_eq!(read_i32_le(&bytes, 4), 0);
        assert_eq!(read_u64_le(&bytes, 8), 120);
        assert!(bytes[FUSE_OUT_HEADER_WIRE_SIZE..].is_empty());
    }

    #[test]
    fn small_reply_preserves_unique_and_error() {
        let reply = commit_small_reply(42, 0, 128);
        assert_eq!(reply.unique, 42);
        assert_eq!(reply.error_or_zero, 0);
        assert_eq!(reply.payload_len, 128);
        assert_eq!(
            reply.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn bulk_reply_has_correct_class() {
        let reply = commit_bulk_reply(99, -5, 65536);
        assert_eq!(reply.unique, 99);
        assert_eq!(reply.error_or_zero, -5);
        assert_eq!(reply.payload_len, 65536);
        assert_eq!(
            reply.reply_class,
            PosixFilesystemAdapterReplyClass::BulkReply.as_u32()
        );
    }

    #[test]
    fn explicit_commit_reply_class() {
        let reply = commit_reply(7, PosixFilesystemAdapterReplyClass::SmallReply, 0, 64);
        assert_eq!(reply.unique, 7);
        assert_eq!(
            reply.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn positive_lookup_entry() {
        let entry = LookupEntryReply::positive(42, 1, 1, 0, 1, 500_000_000).with_attr(test_attr());
        assert_eq!(entry.nodeid, 42);
        assert_eq!(entry.generation, 1);
        assert_eq!(entry.entry_valid, 1);
        assert_eq!(entry.entry_valid_nsec, 0);
        assert_eq!(entry.attr_valid, 1);
        assert_eq!(entry.attr_valid_nsec, 500_000_000);
        assert_eq!(entry.attr, test_attr());
        assert!(!entry.negative);
    }

    #[test]
    fn negative_lookup_entry() {
        let entry = LookupEntryReply::negative(1, 0);
        assert_eq!(entry.nodeid, 0);
        assert_eq!(entry.generation, 0);
        assert_eq!(entry.entry_valid, 1);
        assert_eq!(entry.entry_valid_nsec, 0);
        assert_eq!(entry.attr_valid, 0);
        assert_eq!(entry.attr_valid_nsec, 0);
        assert!(entry.negative);
    }

    #[test]
    fn commit_lookup_reply_uses_small_reply() {
        let entry = LookupEntryReply::positive(100, 5, 1, 0, 1, 0);
        let commit = commit_lookup_reply(77, &entry);
        assert_eq!(commit.unique, 77);
        assert_eq!(commit.error_or_zero, 0);
        assert_eq!(commit.payload_len, FUSE_ENTRY_OUT_WIRE_SIZE);
        assert_eq!(
            commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn commit_lookup_error_uses_negative_errno() {
        let commit = commit_lookup_error(99, -2);
        assert_eq!(commit.unique, 99);
        assert_eq!(commit.error_or_zero, -2);
        assert_eq!(commit.payload_len, 0);
    }

    #[test]
    fn commit_rename_reply_uses_empty_small_reply() {
        let commit = commit_rename_reply(123);
        assert_eq!(commit.unique, 123);
        assert_eq!(commit.error_or_zero, 0);
        assert_eq!(commit.payload_len, FUSE_RENAME_OUT_WIRE_SIZE);
        assert_eq!(
            commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn commit_rename_error_uses_negative_errno() {
        let commit = commit_rename_error(124, -17);
        assert_eq!(commit.unique, 124);
        assert_eq!(commit.error_or_zero, -17);
        assert_eq!(commit.payload_len, 0);
        assert_eq!(
            commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn commit_attr_reply_uses_small_reply_with_correct_size() {
        let commit = commit_attr_reply(42);
        assert_eq!(commit.unique, 42);
        assert_eq!(commit.error_or_zero, 0);
        assert_eq!(commit.payload_len, FUSE_ATTR_OUT_WIRE_SIZE);
        assert_eq!(
            commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn commit_attr_error_uses_negative_errno() {
        let commit = commit_attr_error(99, -2);
        assert_eq!(commit.unique, 99);
        assert_eq!(commit.error_or_zero, -2);
        assert_eq!(commit.payload_len, 0);
        assert_eq!(
            commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn rename_reply_wire_size_is_zero() {
        assert_eq!(FUSE_RENAME_OUT_WIRE_SIZE, 0);
        assert_eq!(rename_reply_wire_len(), 0);
    }

    #[test]
    fn encode_positive_lookup_entry_writes_fuse_entry_out() {
        let entry = LookupEntryReply::positive(42, 7, 5, 123, 2, 456).with_attr(test_attr());
        let mut bytes = [0xAA; 128];
        let len = encode_lookup_entry_reply(&entry, &mut bytes).expect("encode");

        assert_eq!(len, lookup_entry_wire_len());
        assert_eq!(read_u64_le(&bytes, 0), 42);
        assert_eq!(read_u64_le(&bytes, 8), 7);
        assert_eq!(read_u64_le(&bytes, 16), 5);
        assert_eq!(read_u64_le(&bytes, 24), 2);
        assert_eq!(read_u32_le(&bytes, 32), 123);
        assert_eq!(read_u32_le(&bytes, 36), 456);

        assert_eq!(read_u64_le(&bytes, 40), 42);
        assert_eq!(read_u64_le(&bytes, 48), 4096);
        assert_eq!(read_u64_le(&bytes, 56), 8);
        assert_eq!(read_u64_le(&bytes, 64), 10);
        assert_eq!(read_u64_le(&bytes, 72), 20);
        assert_eq!(read_u64_le(&bytes, 80), 30);
        assert_eq!(read_u32_le(&bytes, 88), 111);
        assert_eq!(read_u32_le(&bytes, 92), 222);
        assert_eq!(read_u32_le(&bytes, 96), 333);
        assert_eq!(read_u32_le(&bytes, 100), 0o100644);
        assert_eq!(read_u32_le(&bytes, 104), 2);
        assert_eq!(read_u32_le(&bytes, 108), 1000);
        assert_eq!(read_u32_le(&bytes, 112), 1001);
        assert_eq!(read_u32_le(&bytes, 116), 0);
        assert_eq!(read_u32_le(&bytes, 120), 4096);
        assert_eq!(read_u32_le(&bytes, 124), 0);
    }

    #[test]
    fn encode_negative_lookup_entry_writes_zero_node_and_attr() {
        let entry = LookupEntryReply::negative(3, 250_000_000);
        let mut bytes = [0xAA; 128];
        encode_lookup_entry_reply(&entry, &mut bytes).expect("encode");

        assert_eq!(read_u64_le(&bytes, 0), 0);
        assert_eq!(read_u64_le(&bytes, 8), 0);
        assert_eq!(read_u64_le(&bytes, 16), 3);
        assert_eq!(read_u64_le(&bytes, 24), 0);
        assert_eq!(read_u32_le(&bytes, 32), 250_000_000);
        assert_eq!(read_u32_le(&bytes, 36), 0);
        assert!(bytes[40..128].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn encode_lookup_entry_rejects_short_buffer() {
        let entry = LookupEntryReply::positive(1, 1, 1, 0, 1, 0);
        let mut bytes = [0_u8; 127];
        assert_eq!(
            encode_lookup_entry_reply(&entry, &mut bytes),
            Err(LookupEntryEncodeError::BufferTooSmall {
                required: 128,
                actual: 127
            })
        );
    }

    #[test]
    fn lookup_entry_default_is_zeroed_negative() {
        let entry = LookupEntryReply::default();
        assert_eq!(entry.nodeid, 0);
        assert_eq!(entry.generation, 0);
        assert_eq!(entry.attr, LookupEntryAttr::default());
        assert!(!entry.negative);
    }
    // ── Dirent wire-format tests ──────────────────────────────────────

    #[test]
    fn pack_dirent_computes_padded_size() {
        let (wire, size) = pack_dirent(10, 1, 8, b"hello");
        assert_eq!(wire.ino, 10);
        assert_eq!(wire.off, 1);
        assert_eq!(wire.namelen, 5);
        assert_eq!(wire.r#type, 8);
        assert_eq!(&wire.name[..5], b"hello");
        // 24 (header) + 5 (name) = 29, padded to 32
        assert_eq!(size, 32);
    }

    #[test]
    fn pack_dirent_name_truncation() {
        let long_name = [b'x'; 300];
        let (wire, _size) = pack_dirent(1, 2, 4, &long_name);
        assert_eq!(wire.namelen as usize, DIRENT_MAX_NAME);
    }

    #[test]
    fn pack_dirent_alignment() {
        // Name exactly 8 bytes → no padding needed beyond alignment
        let (_wire, size) = pack_dirent(1, 0, 4, b"12345678");
        assert_eq!(size, 32); // 24 + 8 = 32, already 8-aligned
    }

    #[test]
    fn pack_dirent_plus_includes_entry_out() {
        let attr = DirentPlusAttr {
            ino: 42,
            size: 1024,
            blocks: 2,
            mode: 0o100644,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            blksize: 4096,
            ..Default::default()
        };
        let (wire, size) = pack_dirent_plus(42, 1, 10, b"data.txt", 1_000_000_000, attr);
        assert_eq!(wire.ino, 42);
        assert_eq!(wire.generation, 1);
        assert_eq!(wire.entry_valid_nsec, 1_000_000_000);
        assert_eq!(wire.attr.size, 1024);
        assert_eq!(wire.attr.mode, 0o100644);
        // FUSE_ENTRY_OUT_SIZE (128) + dirent padded size
        assert!(size >= FUSE_ENTRY_OUT_SIZE + FUSE_DIRENT_HEADER_SIZE);
        assert_eq!(wire.dirent.ino, 42);
        assert_eq!(wire.dirent.off, 10);
    }

    #[test]
    fn would_overflow_true_when_entry_exceeds_buffer() {
        assert!(would_overflow(100, 200));
    }

    #[test]
    fn would_overflow_false_when_entry_fits() {
        assert!(!would_overflow(200, 100));
    }

    #[test]
    fn would_overflow_exact_fit() {
        // Fits exactly — no overflow
        assert!(!would_overflow(128, 128));
    }

    #[test]
    fn zeroed_dirent_plus_is_all_zeros() {
        let w = DirentPlusWire::zeroed();
        assert_eq!(w.ino, 0);
        assert_eq!(w.generation, 0);
        assert_eq!(w.dirent.ino, 0);
        assert_eq!(w.attr.size, 0);
    }

    #[test]
    fn default_dirent_plus_attr_is_zeroed() {
        let a = DirentPlusAttr::default();
        assert_eq!(a.ino, 0);
        assert_eq!(a.size, 0);
        assert_eq!(a.mode, 0);
    }

    // ── ReplyError exhaustive errno mapping ────────────────────────────

    #[test]
    fn reply_error_all_variants_map_to_distinct_errno() {
        let variants = [
            ReplyError::PermissionDenied,
            ReplyError::NotFound,
            ReplyError::Io,
            ReplyError::AccessDenied,
            ReplyError::AlreadyExists,
            ReplyError::NotDirectory,
            ReplyError::InvalidInput,
            ReplyError::NoSpace,
            ReplyError::ReadOnly,
            ReplyError::NotSupported,
            ReplyError::NotEmpty,
        ];
        let expected = [
            reply_errno::EPERM,
            reply_errno::ENOENT,
            reply_errno::EIO,
            reply_errno::EACCES,
            reply_errno::EEXIST,
            reply_errno::ENOTDIR,
            reply_errno::EINVAL,
            reply_errno::ENOSPC,
            reply_errno::EROFS,
            reply_errno::ENOSYS,
            reply_errno::ENOTEMPTY,
        ];
        for (variant, exp) in variants.iter().zip(expected.iter()) {
            assert_eq!(variant.errno(), *exp, "mismatch for {variant:?}");
        }
        let mut sorted: Vec<i32> = expected.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            expected.len(),
            "errno values must be distinct"
        );
    }

    // ── Errno constant distinctness ────────────────────────────────────

    #[test]
    fn reply_errno_constants_are_distinct() {
        let errnos = [
            reply_errno::EPERM,
            reply_errno::ENOENT,
            reply_errno::EIO,
            reply_errno::EACCES,
            reply_errno::EEXIST,
            reply_errno::ENOTDIR,
            reply_errno::EINVAL,
            reply_errno::ENOSPC,
            reply_errno::EROFS,
            reply_errno::ENOSYS,
            reply_errno::ENOTEMPTY,
        ];
        let mut sorted = errnos.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            errnos.len(),
            "all errno constants must be distinct"
        );
    }

    // ── LookupEntryAttr boundary tests ─────────────────────────────────

    #[test]
    fn lookup_entry_attr_zero_matches_default() {
        assert_eq!(LookupEntryAttr::ZERO, LookupEntryAttr::default());
    }

    #[test]
    fn lookup_entry_attr_new_padding_is_zero() {
        let attr = LookupEntryAttr::new(1, 2, 3, 4, 5, 6, 7, 8, 9, 0o755, 10, 1000, 1001, 0, 512);
        assert_eq!(attr.padding, 0);
        assert_eq!(attr.ino, 1);
        assert_eq!(attr.mode, 0o755);
    }

    // ── with_attr chaining ─────────────────────────────────────────────

    #[test]
    fn with_attr_replaces_attr_field() {
        let entry = LookupEntryReply::positive(10, 2, 1, 0, 1, 0);
        let attr1 = LookupEntryAttr::new(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        let attr2 = LookupEntryAttr::new(99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        let e1 = entry.with_attr(attr1);
        assert_eq!(e1.attr.ino, 1);
        let e2 = e1.with_attr(attr2);
        assert_eq!(e2.attr.ino, 99);
        assert_eq!(e2.nodeid, 10);
    }

    // ── StatfsReply field preservation ──────────────────────────────────

    #[test]
    fn statfs_reply_preserves_all_fields() {
        let s = StatfsReply {
            blocks: 1_000_000,
            bfree: 500_000,
            bavail: 400_000,
            files: 3_000_000,
            ffree: 2_000_000,
            favail: 1_000_000,
            bsize: 4096,
            namemax: 255,
            frsize: 4096,
        };
        assert_eq!(s.blocks, 1_000_000);
        assert_eq!(s.bfree, 500_000);
        assert_eq!(s.bavail, 400_000);
        assert_eq!(s.files, 3_000_000);
        assert_eq!(s.ffree, 2_000_000);
        assert_eq!(s.favail, 1_000_000);
        assert_eq!(s.bsize, 4096);
        assert_eq!(s.namemax, 255);
        assert_eq!(s.frsize, 4096);
    }

    // ── Commit helpers for rename_error, attr_reply, attr_error ────────

    #[test]
    fn commit_rename_error_uses_small_reply() {
        let c = commit_rename_error(42, -reply_errno::ENOENT);
        assert_eq!(c.unique, 42);
        assert_eq!(c.error_or_zero, -reply_errno::ENOENT);
        assert_eq!(c.payload_len, 0);
        assert_eq!(
            c.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn commit_attr_reply_uses_small_reply() {
        let c = commit_attr_reply(77);
        assert_eq!(c.unique, 77);
        assert_eq!(c.error_or_zero, 0);
        assert_eq!(c.payload_len, FUSE_ATTR_OUT_WIRE_SIZE);
        assert_eq!(
            c.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn commit_attr_error_uses_small_reply() {
        let c = commit_attr_error(88, -reply_errno::EIO);
        assert_eq!(c.unique, 88);
        assert_eq!(c.error_or_zero, -reply_errno::EIO);
        assert_eq!(c.payload_len, 0);
        assert_eq!(
            c.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }
}
