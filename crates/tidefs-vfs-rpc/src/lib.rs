#![forbid(unsafe_code)]

//! VFS_RPC wire protocol for forwarding VFS engine operations between nodes.
//!
//! This crate implements the stable service surface from
//! `docs/design/vfs-rpc-wire-protocol.md`: service id `0x06`, the fixed
//! request/response prefixes, stable method ids, inline-or-bulk payload
//! descriptors, transferable handle encoding, request id correlation, and a
//! bounded per-peer deduplication window for retry-safe mutation replay.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use tidefs_types_vfs_core::{
    DirEntry, DirHandleId, EngineDirHandle, EngineFileHandle, Errno, FileHandleId, Generation,
    InodeAttr, InodeFlags, InodeId, NodeKind, PosixAttrs, RenameFlags, SetAttr, StatFs,
};

/// Stable VFS_RPC service id in the cluster service registry.
pub const VFS_RPC_SERVICE_ID: u8 = 0x06;

/// Wire format version for this crate's VFS_RPC payloads.
pub const VFS_RPC_WIRE_VERSION: u8 = 1;

/// Byte length of `VfsRpcRequestHeaderV1`.
pub const REQUEST_HEADER_LEN: usize = 44;

/// Byte length of `VfsRpcResponseHeaderV1`.
pub const RESPONSE_HEADER_LEN: usize = 24;

/// Default inline payload threshold before callers should hand data to BULK.
pub const DEFAULT_INLINE_THRESHOLD: usize = 128 * 1024;

/// Request message-type high bits.
pub const MESSAGE_TYPE_REQUEST: u8 = 0b00 << 6;

/// Response message-type high bits.
pub const MESSAGE_TYPE_RESPONSE: u8 = 0b01 << 6;

/// Request carries a BULK token whose data transfer is still pending.
pub const REQ_FLAG_BULK_PENDING: u16 = 1 << 0;

/// Request bypasses the per-peer dedup cache.
pub const REQ_FLAG_NO_DEDUP: u16 = 1 << 1;

/// Locally served stale data is acceptable for this read.
pub const REQ_FLAG_UPTODATE_OK: u16 = 1 << 2;

/// Response payload points at the BULK plane.
pub const RESP_FLAG_BULK: u16 = 1 << 0;

/// Response was replayed from a dedup cache entry.
pub const RESP_FLAG_DEDUP_REPLAY: u16 = 1 << 1;

/// Inline response was truncated to fit the negotiated frame size.
pub const RESP_FLAG_TRUNCATED: u16 = 1 << 2;

/// Stable peer identity supplied by the transport authentication layer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PeerId(pub u64);

/// Dataset identity carried by VFS_RPC headers and transferable handles.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DatasetId(pub u128);

impl DatasetId {
    #[must_use]
    pub const fn new(value: u128) -> Self {
        Self(value)
    }
}

/// Stable per-peer request identifier. Retries reuse the same value.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct OpId(pub u64);

impl OpId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// VFS_RPC method ids. Values are protocol-stable.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum VfsRpcMethod {
    Lookup = 0x00,
    Mknod = 0x01,
    Mkdir = 0x02,
    Unlink = 0x03,
    Rmdir = 0x04,
    Symlink = 0x05,
    Readlink = 0x06,
    Rename = 0x07,
    Link = 0x08,
    Getxattr = 0x09,
    Setxattr = 0x0A,
    Listxattr = 0x0B,
    Removexattr = 0x0C,
    Access = 0x0D,
    Create = 0x0E,
    Getattr = 0x10,
    Setattr = 0x11,
    Open = 0x12,
    Close = 0x13,
    Opendir = 0x14,
    Closedir = 0x15,
    Readdir = 0x16,
    Readdirplus = 0x17,
    Statfs = 0x18,
    Flush = 0x19,
    Release = 0x1A,
    Releasedir = 0x1B,
    Forget = 0x1C,
    BatchForget = 0x1D,
    DirRev = 0x1E,
    Read = 0x20,
    Write = 0x21,
    Fsync = 0x22,
    Fallocate = 0x23,
    LseekData = 0x24,
    LseekHole = 0x25,
    Fiemap = 0x26,
    Truncate = 0x27,
    CopyFileRange = 0x28,
    LockGet = 0x29,
    LockSet = 0x2A,
}

impl VfsRpcMethod {
    #[must_use]
    pub const fn id(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn request_message_type(self) -> u8 {
        MESSAGE_TYPE_REQUEST | (self.id() as u8 & 0x3F)
    }

    #[must_use]
    pub const fn response_message_type(self) -> u8 {
        MESSAGE_TYPE_RESPONSE | (self.id() as u8 & 0x3F)
    }

    pub fn from_id(id: u16) -> Result<Self, VfsRpcError> {
        let method = match id {
            0x00 => Self::Lookup,
            0x01 => Self::Mknod,
            0x02 => Self::Mkdir,
            0x03 => Self::Unlink,
            0x04 => Self::Rmdir,
            0x05 => Self::Symlink,
            0x06 => Self::Readlink,
            0x07 => Self::Rename,
            0x08 => Self::Link,
            0x09 => Self::Getxattr,
            0x0A => Self::Setxattr,
            0x0B => Self::Listxattr,
            0x0C => Self::Removexattr,
            0x0D => Self::Access,
            0x0E => Self::Create,
            0x10 => Self::Getattr,
            0x11 => Self::Setattr,
            0x12 => Self::Open,
            0x13 => Self::Close,
            0x14 => Self::Opendir,
            0x15 => Self::Closedir,
            0x16 => Self::Readdir,
            0x17 => Self::Readdirplus,
            0x18 => Self::Statfs,
            0x19 => Self::Flush,
            0x1A => Self::Release,
            0x1B => Self::Releasedir,
            0x1C => Self::Forget,
            0x1D => Self::BatchForget,
            0x1E => Self::DirRev,
            0x20 => Self::Read,
            0x21 => Self::Write,
            0x22 => Self::Fsync,
            0x23 => Self::Fallocate,
            0x24 => Self::LseekData,
            0x25 => Self::LseekHole,
            0x26 => Self::Fiemap,
            0x27 => Self::Truncate,
            0x28 => Self::CopyFileRange,
            0x29 => Self::LockGet,
            0x2A => Self::LockSet,
            _ => return Err(VfsRpcError::UnknownMethod(id)),
        };
        Ok(method)
    }

    pub fn from_message_type(
        message_type: u8,
        expected: VfsRpcMessageKind,
    ) -> Result<Self, VfsRpcError> {
        let kind = VfsRpcMessageKind::from_message_type(message_type)?;
        if kind != expected {
            return Err(VfsRpcError::WrongMessageKind {
                expected,
                found: kind,
            });
        }
        Self::from_id((message_type & 0x3F) as u16)
    }
}

/// Message kind encoded in the high two bits of the transport message type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VfsRpcMessageKind {
    Request,
    Response,
}

impl VfsRpcMessageKind {
    pub fn from_message_type(message_type: u8) -> Result<Self, VfsRpcError> {
        match message_type >> 6 {
            0b00 => Ok(Self::Request),
            0b01 => Ok(Self::Response),
            other => Err(VfsRpcError::ReservedMessageKind(other)),
        }
    }
}

/// Fixed request prefix from VfsRpcReqCommonV1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VfsRpcRequestHeader {
    pub op_id: OpId,
    pub term: u64,
    pub epoch: u64,
    pub flags: u16,
    pub method: VfsRpcMethod,
    pub payload_len: u32,
    pub creds_len: u32,
}

impl VfsRpcRequestHeader {
    #[must_use]
    pub const fn new(
        op_id: OpId,
        term: u64,
        epoch: u64,
        flags: u16,
        method: VfsRpcMethod,
        payload_len: u32,
        creds_len: u32,
    ) -> Self {
        Self {
            op_id,
            term,
            epoch,
            flags,
            method,
            payload_len,
            creds_len,
        }
    }

    pub fn encode_into(self, out: &mut Vec<u8>) {
        put_u64(out, self.op_id.0);
        put_u64(out, self.term);
        put_u64(out, self.epoch);
        put_u16(out, self.flags);
        put_u16(out, self.method.id());
        put_u32(out, self.payload_len);
        put_u32(out, self.creds_len);
        put_u64(out, 0);
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, VfsRpcError> {
        let mut cursor = WireCursor::new(bytes);
        let header = Self {
            op_id: OpId(cursor.u64()?),
            term: cursor.u64()?,
            epoch: cursor.u64()?,
            flags: cursor.u16()?,
            method: VfsRpcMethod::from_id(cursor.u16()?)?,
            payload_len: cursor.u32()?,
            creds_len: cursor.u32()?,
        };
        let reserved = cursor.u64()?;
        if reserved != 0 {
            return Err(VfsRpcError::ReservedNonZero);
        }
        cursor.finish()?;
        Ok(header)
    }
}

/// Fixed response prefix from VfsRpcRespCommonV1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VfsRpcResponseHeader {
    pub op_id: OpId,
    pub errno: Errno,
    pub flags: u16,
    pub payload_len: u32,
}

impl VfsRpcResponseHeader {
    #[must_use]
    pub const fn new(op_id: OpId, errno: Errno, flags: u16, payload_len: u32) -> Self {
        Self {
            op_id,
            errno,
            flags,
            payload_len,
        }
    }

    pub fn encode_into(self, out: &mut Vec<u8>) {
        put_u64(out, self.op_id.0);
        put_u16(out, self.errno.raw());
        put_u16(out, self.flags);
        put_u32(out, self.payload_len);
        put_u64(out, 0);
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, VfsRpcError> {
        let mut cursor = WireCursor::new(bytes);
        let header = Self {
            op_id: OpId(cursor.u64()?),
            errno: Errno::from_raw(cursor.u16()?),
            flags: cursor.u16()?,
            payload_len: cursor.u32()?,
        };
        let reserved = cursor.u64()?;
        if reserved != 0 {
            return Err(VfsRpcError::ReservedNonZero);
        }
        cursor.finish()?;
        Ok(header)
    }
}

/// Authenticated caller credentials carried after the method payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VfsRpcCredentials {
    pub peer_id: PeerId,
    pub auth_tag: [u8; 16],
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
}

impl VfsRpcCredentials {
    #[must_use]
    pub fn root(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            auth_tag: [0; 16],
            uid: 0,
            gid: 0,
            groups: vec![0],
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), VfsRpcError> {
        if self.groups.len() > u16::MAX as usize {
            return Err(VfsRpcError::TooManyGroups(self.groups.len()));
        }
        put_u64(out, self.peer_id.0);
        out.extend_from_slice(&self.auth_tag);
        put_u32(out, self.uid);
        put_u32(out, self.gid);
        put_u16(out, self.groups.len() as u16);
        for group in &self.groups {
            put_u32(out, *group);
        }
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, VfsRpcError> {
        let mut cursor = WireCursor::new(bytes);
        let peer_id = PeerId(cursor.u64()?);
        let auth_tag = cursor.array16()?;
        let uid = cursor.u32()?;
        let gid = cursor.u32()?;
        let group_count = cursor.u16()? as usize;
        let mut groups = Vec::with_capacity(group_count);
        for _ in 0..group_count {
            groups.push(cursor.u32()?);
        }
        cursor.finish()?;
        Ok(Self {
            peer_id,
            auth_tag,
            uid,
            gid,
            groups,
        })
    }
}

/// Payload storage strategy for data-bearing VFS_RPC messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InlineOrBulk {
    Inline(Vec<u8>),
    Bulk { token: [u8; 32], len: u64 },
}

impl InlineOrBulk {
    #[must_use]
    pub fn len(&self) -> u64 {
        match self {
            Self::Inline(data) => data.len() as u64,
            Self::Bulk { len, .. } => *len,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn from_data(data: Vec<u8>, inline_threshold: usize, token: [u8; 32]) -> Self {
        if data.len() <= inline_threshold {
            Self::Inline(data)
        } else {
            Self::Bulk {
                token,
                len: data.len() as u64,
            }
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), VfsRpcError> {
        match self {
            Self::Inline(data) => {
                put_u8(out, 0);
                put_bytes(out, data)?;
            }
            Self::Bulk { token, len } => {
                put_u8(out, 1);
                out.extend_from_slice(token);
                put_u64(out, *len);
            }
        }
        Ok(())
    }

    fn decode(cursor: &mut WireCursor<'_>) -> Result<Self, VfsRpcError> {
        match cursor.u8()? {
            0 => Ok(Self::Inline(cursor.bytes()?)),
            1 => Ok(Self::Bulk {
                token: cursor.array32()?,
                len: cursor.u64()?,
            }),
            other => Err(VfsRpcError::UnknownInlineOrBulkKind(other)),
        }
    }
}

/// Transferable file/dir handle representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VfsRpcHandle {
    pub handle_type: VfsRpcHandleType,
    pub flags: u8,
    pub dataset_id: DatasetId,
    pub inode: InodeId,
    pub generation: Generation,
    pub writer_node: u64,
    pub handle_cookie: u64,
}

impl VfsRpcHandle {
    #[must_use]
    pub fn from_file_handle(
        dataset_id: DatasetId,
        writer_node: u64,
        handle: EngineFileHandle,
        generation: Generation,
    ) -> Self {
        Self {
            handle_type: VfsRpcHandleType::File,
            flags: handle_flags_from_open_flags(handle.open_flags),
            dataset_id,
            inode: handle.inode_id,
            generation,
            writer_node,
            handle_cookie: handle.fh_id.get(),
        }
    }

    #[must_use]
    pub fn from_dir_handle(
        dataset_id: DatasetId,
        writer_node: u64,
        handle: EngineDirHandle,
        generation: Generation,
    ) -> Self {
        Self {
            handle_type: VfsRpcHandleType::Dir,
            flags: 0,
            dataset_id,
            inode: handle.inode_id,
            generation,
            writer_node,
            handle_cookie: handle.dh_id.get(),
        }
    }

    #[must_use]
    pub const fn as_file_handle(&self, open_flags: u32, lock_owner: u64) -> EngineFileHandle {
        EngineFileHandle {
            inode_id: self.inode,
            open_flags,
            fh_id: FileHandleId(self.handle_cookie),
            lock_owner,
        }
    }

    #[must_use]
    pub const fn as_dir_handle(&self) -> EngineDirHandle {
        EngineDirHandle {
            inode_id: self.inode,
            dh_id: DirHandleId(self.handle_cookie),
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        put_u8(out, self.handle_type as u8);
        put_u8(out, self.flags);
        put_u128(out, self.dataset_id.0);
        put_u64(out, self.inode.get());
        put_u64(out, self.generation.get());
        put_u64(out, self.writer_node);
        put_u64(out, self.handle_cookie);
    }

    fn decode(cursor: &mut WireCursor<'_>) -> Result<Self, VfsRpcError> {
        Ok(Self {
            handle_type: VfsRpcHandleType::from_u8(cursor.u8()?)?,
            flags: cursor.u8()?,
            dataset_id: DatasetId(cursor.u128()?),
            inode: InodeId(cursor.u64()?),
            generation: Generation(cursor.u64()?),
            writer_node: cursor.u64()?,
            handle_cookie: cursor.u64()?,
        })
    }
}

/// Handle kind encoded in VfsHandleV1.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VfsRpcHandleType {
    File = 0,
    Dir = 1,
}

impl VfsRpcHandleType {
    fn from_u8(value: u8) -> Result<Self, VfsRpcError> {
        match value {
            0 => Ok(Self::File),
            1 => Ok(Self::Dir),
            other => Err(VfsRpcError::UnknownHandleType(other)),
        }
    }
}

/// Method-specific VFS_RPC request body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VfsRpcRequestPayload {
    Lookup {
        parent: InodeId,
        name: Vec<u8>,
    },
    Mknod {
        parent: InodeId,
        name: Vec<u8>,
        mode: u32,
        rdev: u32,
    },
    Mkdir {
        parent: InodeId,
        name: Vec<u8>,
        mode: u32,
    },
    Unlink {
        parent: InodeId,
        name: Vec<u8>,
    },
    Rmdir {
        parent: InodeId,
        name: Vec<u8>,
    },
    Symlink {
        parent: InodeId,
        name: Vec<u8>,
        target: Vec<u8>,
    },
    Readlink {
        inode: InodeId,
    },
    Rename {
        old_parent: InodeId,
        old_name: Vec<u8>,
        new_parent: InodeId,
        new_name: Vec<u8>,
        flags: RenameFlags,
    },
    Link {
        inode: InodeId,
        new_parent: InodeId,
        new_name: Vec<u8>,
    },
    Getxattr {
        inode: InodeId,
        name: Vec<u8>,
        size: u32,
    },
    Setxattr {
        inode: InodeId,
        name: Vec<u8>,
        value: Vec<u8>,
        flags: u32,
    },
    Listxattr {
        inode: InodeId,
        size: u32,
    },
    Removexattr {
        inode: InodeId,
        name: Vec<u8>,
    },
    Access {
        inode: InodeId,
        mask: u32,
    },
    Create {
        parent: InodeId,
        name: Vec<u8>,
        mode: u32,
        flags: u32,
    },
    Getattr {
        inode: InodeId,
    },
    Setattr {
        inode: InodeId,
        attr: SetAttr,
    },
    Open {
        inode: InodeId,
        flags: u32,
        lock_owner: u64,
    },
    Close {
        handle: VfsRpcHandle,
    },
    Opendir {
        inode: InodeId,
    },
    Closedir {
        handle: VfsRpcHandle,
    },
    Readdir {
        handle: VfsRpcHandle,
        offset: u64,
        max_entries: u32,
    },
    Readdirplus {
        handle: VfsRpcHandle,
        offset: u64,
        max_entries: u32,
    },
    Statfs {
        inode: InodeId,
    },
    Flush {
        handle: VfsRpcHandle,
        lock_owner: u64,
    },
    Release {
        handle: VfsRpcHandle,
        flags: u32,
    },
    Releasedir {
        handle: VfsRpcHandle,
    },
    Forget {
        inode: InodeId,
        nlookup: u64,
    },
    BatchForget {
        entries: Vec<(InodeId, u64)>,
    },
    DirRev {
        handle: VfsRpcHandle,
    },
    Read {
        handle: VfsRpcHandle,
        offset: u64,
        length: u64,
    },
    Write {
        handle: VfsRpcHandle,
        offset: u64,
        data: InlineOrBulk,
    },
    Fsync {
        handle: VfsRpcHandle,
        datasync: bool,
    },
    Fallocate {
        handle: VfsRpcHandle,
        mode: u32,
        offset: u64,
        length: u64,
    },
    LseekData {
        handle: VfsRpcHandle,
        offset: u64,
    },
    LseekHole {
        handle: VfsRpcHandle,
        offset: u64,
    },
    Fiemap {
        handle: VfsRpcHandle,
        start: u64,
        length: u64,
    },
    Truncate {
        inode: InodeId,
        length: u64,
    },
    CopyFileRange {
        src: VfsRpcHandle,
        src_offset: u64,
        dst: VfsRpcHandle,
        dst_offset: u64,
        length: u64,
        flags: u32,
    },
    LockGet {
        handle: VfsRpcHandle,
        owner: u64,
        start: u64,
        end: u64,
    },
    LockSet {
        handle: VfsRpcHandle,
        owner: u64,
        start: u64,
        end: u64,
        write: bool,
        block: bool,
    },
}

impl VfsRpcRequestPayload {
    #[must_use]
    pub const fn method(&self) -> VfsRpcMethod {
        match self {
            Self::Lookup { .. } => VfsRpcMethod::Lookup,
            Self::Mknod { .. } => VfsRpcMethod::Mknod,
            Self::Mkdir { .. } => VfsRpcMethod::Mkdir,
            Self::Unlink { .. } => VfsRpcMethod::Unlink,
            Self::Rmdir { .. } => VfsRpcMethod::Rmdir,
            Self::Symlink { .. } => VfsRpcMethod::Symlink,
            Self::Readlink { .. } => VfsRpcMethod::Readlink,
            Self::Rename { .. } => VfsRpcMethod::Rename,
            Self::Link { .. } => VfsRpcMethod::Link,
            Self::Getxattr { .. } => VfsRpcMethod::Getxattr,
            Self::Setxattr { .. } => VfsRpcMethod::Setxattr,
            Self::Listxattr { .. } => VfsRpcMethod::Listxattr,
            Self::Removexattr { .. } => VfsRpcMethod::Removexattr,
            Self::Access { .. } => VfsRpcMethod::Access,
            Self::Create { .. } => VfsRpcMethod::Create,
            Self::Getattr { .. } => VfsRpcMethod::Getattr,
            Self::Setattr { .. } => VfsRpcMethod::Setattr,
            Self::Open { .. } => VfsRpcMethod::Open,
            Self::Close { .. } => VfsRpcMethod::Close,
            Self::Opendir { .. } => VfsRpcMethod::Opendir,
            Self::Closedir { .. } => VfsRpcMethod::Closedir,
            Self::Readdir { .. } => VfsRpcMethod::Readdir,
            Self::Readdirplus { .. } => VfsRpcMethod::Readdirplus,
            Self::Statfs { .. } => VfsRpcMethod::Statfs,
            Self::Flush { .. } => VfsRpcMethod::Flush,
            Self::Release { .. } => VfsRpcMethod::Release,
            Self::Releasedir { .. } => VfsRpcMethod::Releasedir,
            Self::Forget { .. } => VfsRpcMethod::Forget,
            Self::BatchForget { .. } => VfsRpcMethod::BatchForget,
            Self::DirRev { .. } => VfsRpcMethod::DirRev,
            Self::Read { .. } => VfsRpcMethod::Read,
            Self::Write { .. } => VfsRpcMethod::Write,
            Self::Fsync { .. } => VfsRpcMethod::Fsync,
            Self::Fallocate { .. } => VfsRpcMethod::Fallocate,
            Self::LseekData { .. } => VfsRpcMethod::LseekData,
            Self::LseekHole { .. } => VfsRpcMethod::LseekHole,
            Self::Fiemap { .. } => VfsRpcMethod::Fiemap,
            Self::Truncate { .. } => VfsRpcMethod::Truncate,
            Self::CopyFileRange { .. } => VfsRpcMethod::CopyFileRange,
            Self::LockGet { .. } => VfsRpcMethod::LockGet,
            Self::LockSet { .. } => VfsRpcMethod::LockSet,
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), VfsRpcError> {
        match self {
            Self::Lookup { parent, name } => {
                put_inode(out, *parent);
                put_bytes(out, name)?;
            }
            Self::Mknod {
                parent,
                name,
                mode,
                rdev,
            } => {
                put_inode(out, *parent);
                put_u32(out, *mode);
                put_u32(out, *rdev);
                put_bytes(out, name)?;
            }
            Self::Mkdir { parent, name, mode } => {
                put_inode(out, *parent);
                put_u32(out, *mode);
                put_bytes(out, name)?;
            }
            Self::Unlink { parent, name } | Self::Rmdir { parent, name } => {
                put_inode(out, *parent);
                put_bytes(out, name)?;
            }
            Self::Symlink {
                parent,
                name,
                target,
            } => {
                put_inode(out, *parent);
                put_bytes(out, name)?;
                put_bytes(out, target)?;
            }
            Self::Readlink { inode } | Self::Getattr { inode } | Self::Statfs { inode } => {
                put_inode(out, *inode);
            }
            Self::Rename {
                old_parent,
                old_name,
                new_parent,
                new_name,
                flags,
            } => {
                put_inode(out, *old_parent);
                put_inode(out, *new_parent);
                put_u32(out, *flags);
                put_bytes(out, old_name)?;
                put_bytes(out, new_name)?;
            }
            Self::Link {
                inode,
                new_parent,
                new_name,
            } => {
                put_inode(out, *inode);
                put_inode(out, *new_parent);
                put_bytes(out, new_name)?;
            }
            Self::Getxattr { inode, name, size } => {
                put_inode(out, *inode);
                put_u32(out, *size);
                put_bytes(out, name)?;
            }
            Self::Setxattr {
                inode,
                name,
                value,
                flags,
            } => {
                put_inode(out, *inode);
                put_u32(out, *flags);
                put_bytes(out, name)?;
                put_bytes(out, value)?;
            }
            Self::Listxattr { inode, size } => {
                put_inode(out, *inode);
                put_u32(out, *size);
            }
            Self::Removexattr { inode, name } => {
                put_inode(out, *inode);
                put_bytes(out, name)?;
            }
            Self::Access { inode, mask } => {
                put_inode(out, *inode);
                put_u32(out, *mask);
            }
            Self::Create {
                parent,
                name,
                mode,
                flags,
            } => {
                put_inode(out, *parent);
                put_u32(out, *mode);
                put_u32(out, *flags);
                put_bytes(out, name)?;
            }
            Self::Setattr { inode, attr } => {
                put_inode(out, *inode);
                put_setattr(out, *attr);
            }
            Self::Open {
                inode,
                flags,
                lock_owner,
            } => {
                put_inode(out, *inode);
                put_u32(out, *flags);
                put_u64(out, *lock_owner);
            }
            Self::Close { handle }
            | Self::Closedir { handle }
            | Self::Releasedir { handle }
            | Self::DirRev { handle } => handle.encode_into(out),
            Self::Opendir { inode } => put_inode(out, *inode),
            Self::Readdir {
                handle,
                offset,
                max_entries,
            }
            | Self::Readdirplus {
                handle,
                offset,
                max_entries,
            } => {
                handle.encode_into(out);
                put_u64(out, *offset);
                put_u32(out, *max_entries);
            }
            Self::Flush { handle, lock_owner } => {
                handle.encode_into(out);
                put_u64(out, *lock_owner);
            }
            Self::Release { handle, flags } => {
                handle.encode_into(out);
                put_u32(out, *flags);
            }
            Self::Forget { inode, nlookup } => {
                put_inode(out, *inode);
                put_u64(out, *nlookup);
            }
            Self::BatchForget { entries } => {
                put_len(out, entries.len())?;
                for (inode, nlookup) in entries {
                    put_inode(out, *inode);
                    put_u64(out, *nlookup);
                }
            }
            Self::Read {
                handle,
                offset,
                length,
            } => {
                handle.encode_into(out);
                put_u64(out, *offset);
                put_u64(out, *length);
            }
            Self::Write {
                handle,
                offset,
                data,
            } => {
                handle.encode_into(out);
                put_u64(out, *offset);
                data.encode_into(out)?;
            }
            Self::Fsync { handle, datasync } => {
                handle.encode_into(out);
                put_bool(out, *datasync);
            }
            Self::Fallocate {
                handle,
                mode,
                offset,
                length,
            } => {
                handle.encode_into(out);
                put_u32(out, *mode);
                put_u64(out, *offset);
                put_u64(out, *length);
            }
            Self::LseekData { handle, offset } | Self::LseekHole { handle, offset } => {
                handle.encode_into(out);
                put_u64(out, *offset);
            }
            Self::Fiemap {
                handle,
                start,
                length,
            } => {
                handle.encode_into(out);
                put_u64(out, *start);
                put_u64(out, *length);
            }
            Self::Truncate { inode, length } => {
                put_inode(out, *inode);
                put_u64(out, *length);
            }
            Self::CopyFileRange {
                src,
                src_offset,
                dst,
                dst_offset,
                length,
                flags,
            } => {
                src.encode_into(out);
                put_u64(out, *src_offset);
                dst.encode_into(out);
                put_u64(out, *dst_offset);
                put_u64(out, *length);
                put_u32(out, *flags);
            }
            Self::LockGet {
                handle,
                owner,
                start,
                end,
            } => {
                handle.encode_into(out);
                put_u64(out, *owner);
                put_u64(out, *start);
                put_u64(out, *end);
            }
            Self::LockSet {
                handle,
                owner,
                start,
                end,
                write,
                block,
            } => {
                handle.encode_into(out);
                put_u64(out, *owner);
                put_u64(out, *start);
                put_u64(out, *end);
                put_bool(out, *write);
                put_bool(out, *block);
            }
        }
        Ok(())
    }

    fn decode(method: VfsRpcMethod, bytes: &[u8]) -> Result<Self, VfsRpcError> {
        let mut cursor = WireCursor::new(bytes);
        let payload = match method {
            VfsRpcMethod::Lookup => Self::Lookup {
                parent: cursor.inode()?,
                name: cursor.bytes()?,
            },
            VfsRpcMethod::Mknod => {
                let parent = cursor.inode()?;
                let mode = cursor.u32()?;
                let rdev = cursor.u32()?;
                Self::Mknod {
                    parent,
                    mode,
                    rdev,
                    name: cursor.bytes()?,
                }
            }
            VfsRpcMethod::Mkdir => {
                let parent = cursor.inode()?;
                let mode = cursor.u32()?;
                Self::Mkdir {
                    parent,
                    mode,
                    name: cursor.bytes()?,
                }
            }
            VfsRpcMethod::Unlink => Self::Unlink {
                parent: cursor.inode()?,
                name: cursor.bytes()?,
            },
            VfsRpcMethod::Rmdir => Self::Rmdir {
                parent: cursor.inode()?,
                name: cursor.bytes()?,
            },
            VfsRpcMethod::Symlink => Self::Symlink {
                parent: cursor.inode()?,
                name: cursor.bytes()?,
                target: cursor.bytes()?,
            },
            VfsRpcMethod::Readlink => Self::Readlink {
                inode: cursor.inode()?,
            },
            VfsRpcMethod::Rename => {
                let old_parent = cursor.inode()?;
                let new_parent = cursor.inode()?;
                let flags = cursor.u32()?;
                Self::Rename {
                    old_parent,
                    new_parent,
                    flags,
                    old_name: cursor.bytes()?,
                    new_name: cursor.bytes()?,
                }
            }
            VfsRpcMethod::Link => Self::Link {
                inode: cursor.inode()?,
                new_parent: cursor.inode()?,
                new_name: cursor.bytes()?,
            },
            VfsRpcMethod::Getxattr => Self::Getxattr {
                inode: cursor.inode()?,
                size: cursor.u32()?,
                name: cursor.bytes()?,
            },
            VfsRpcMethod::Setxattr => Self::Setxattr {
                inode: cursor.inode()?,
                flags: cursor.u32()?,
                name: cursor.bytes()?,
                value: cursor.bytes()?,
            },
            VfsRpcMethod::Listxattr => Self::Listxattr {
                inode: cursor.inode()?,
                size: cursor.u32()?,
            },
            VfsRpcMethod::Removexattr => Self::Removexattr {
                inode: cursor.inode()?,
                name: cursor.bytes()?,
            },
            VfsRpcMethod::Access => Self::Access {
                inode: cursor.inode()?,
                mask: cursor.u32()?,
            },
            VfsRpcMethod::Create => Self::Create {
                parent: cursor.inode()?,
                mode: cursor.u32()?,
                flags: cursor.u32()?,
                name: cursor.bytes()?,
            },
            VfsRpcMethod::Getattr => Self::Getattr {
                inode: cursor.inode()?,
            },
            VfsRpcMethod::Setattr => Self::Setattr {
                inode: cursor.inode()?,
                attr: cursor.setattr()?,
            },
            VfsRpcMethod::Open => Self::Open {
                inode: cursor.inode()?,
                flags: cursor.u32()?,
                lock_owner: cursor.u64()?,
            },
            VfsRpcMethod::Close => Self::Close {
                handle: VfsRpcHandle::decode(&mut cursor)?,
            },
            VfsRpcMethod::Opendir => Self::Opendir {
                inode: cursor.inode()?,
            },
            VfsRpcMethod::Closedir => Self::Closedir {
                handle: VfsRpcHandle::decode(&mut cursor)?,
            },
            VfsRpcMethod::Readdir => Self::Readdir {
                handle: VfsRpcHandle::decode(&mut cursor)?,
                offset: cursor.u64()?,
                max_entries: cursor.u32()?,
            },
            VfsRpcMethod::Readdirplus => Self::Readdirplus {
                handle: VfsRpcHandle::decode(&mut cursor)?,
                offset: cursor.u64()?,
                max_entries: cursor.u32()?,
            },
            VfsRpcMethod::Statfs => Self::Statfs {
                inode: cursor.inode()?,
            },
            VfsRpcMethod::Flush => Self::Flush {
                handle: VfsRpcHandle::decode(&mut cursor)?,
                lock_owner: cursor.u64()?,
            },
            VfsRpcMethod::Release => Self::Release {
                handle: VfsRpcHandle::decode(&mut cursor)?,
                flags: cursor.u32()?,
            },
            VfsRpcMethod::Releasedir => Self::Releasedir {
                handle: VfsRpcHandle::decode(&mut cursor)?,
            },
            VfsRpcMethod::Forget => Self::Forget {
                inode: cursor.inode()?,
                nlookup: cursor.u64()?,
            },
            VfsRpcMethod::BatchForget => {
                let count = cursor.len()?;
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    entries.push((cursor.inode()?, cursor.u64()?));
                }
                Self::BatchForget { entries }
            }
            VfsRpcMethod::DirRev => Self::DirRev {
                handle: VfsRpcHandle::decode(&mut cursor)?,
            },
            VfsRpcMethod::Read => Self::Read {
                handle: VfsRpcHandle::decode(&mut cursor)?,
                offset: cursor.u64()?,
                length: cursor.u64()?,
            },
            VfsRpcMethod::Write => Self::Write {
                handle: VfsRpcHandle::decode(&mut cursor)?,
                offset: cursor.u64()?,
                data: InlineOrBulk::decode(&mut cursor)?,
            },
            VfsRpcMethod::Fsync => Self::Fsync {
                handle: VfsRpcHandle::decode(&mut cursor)?,
                datasync: cursor.bool()?,
            },
            VfsRpcMethod::Fallocate => Self::Fallocate {
                handle: VfsRpcHandle::decode(&mut cursor)?,
                mode: cursor.u32()?,
                offset: cursor.u64()?,
                length: cursor.u64()?,
            },
            VfsRpcMethod::LseekData => Self::LseekData {
                handle: VfsRpcHandle::decode(&mut cursor)?,
                offset: cursor.u64()?,
            },
            VfsRpcMethod::LseekHole => Self::LseekHole {
                handle: VfsRpcHandle::decode(&mut cursor)?,
                offset: cursor.u64()?,
            },
            VfsRpcMethod::Fiemap => Self::Fiemap {
                handle: VfsRpcHandle::decode(&mut cursor)?,
                start: cursor.u64()?,
                length: cursor.u64()?,
            },
            VfsRpcMethod::Truncate => Self::Truncate {
                inode: cursor.inode()?,
                length: cursor.u64()?,
            },
            VfsRpcMethod::CopyFileRange => Self::CopyFileRange {
                src: VfsRpcHandle::decode(&mut cursor)?,
                src_offset: cursor.u64()?,
                dst: VfsRpcHandle::decode(&mut cursor)?,
                dst_offset: cursor.u64()?,
                length: cursor.u64()?,
                flags: cursor.u32()?,
            },
            VfsRpcMethod::LockGet => Self::LockGet {
                handle: VfsRpcHandle::decode(&mut cursor)?,
                owner: cursor.u64()?,
                start: cursor.u64()?,
                end: cursor.u64()?,
            },
            VfsRpcMethod::LockSet => Self::LockSet {
                handle: VfsRpcHandle::decode(&mut cursor)?,
                owner: cursor.u64()?,
                start: cursor.u64()?,
                end: cursor.u64()?,
                write: cursor.bool()?,
                block: cursor.bool()?,
            },
        };
        cursor.finish()?;
        Ok(payload)
    }
}

/// Method-specific VFS_RPC response body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VfsRpcResponsePayload {
    Empty,
    Attr(InodeAttr),
    Lookup {
        inode: InodeId,
        attr: InodeAttr,
    },
    Created {
        inode: InodeId,
        attr: InodeAttr,
        handle: VfsRpcHandle,
    },
    FileHandle(VfsRpcHandle),
    DirHandle(VfsRpcHandle),
    Data(InlineOrBulk),
    BytesWritten(u64),
    DirEntries(Vec<DirEntry>),
    Statfs(StatFs),
    XattrValue(Vec<u8>),
    XattrList(Vec<Vec<u8>>),
    Offset(u64),
    DirRev(u64),
    LockConflict {
        owner: u64,
        start: u64,
        end: u64,
    },
}

impl VfsRpcResponsePayload {
    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), VfsRpcError> {
        match self {
            Self::Empty => {}
            Self::Attr(attr) => put_inode_attr(out, attr),
            Self::Lookup { inode, attr } => {
                put_inode(out, *inode);
                put_inode_attr(out, attr);
            }
            Self::Created {
                inode,
                attr,
                handle,
            } => {
                put_inode(out, *inode);
                put_inode_attr(out, attr);
                handle.encode_into(out);
            }
            Self::FileHandle(handle) | Self::DirHandle(handle) => handle.encode_into(out),
            Self::Data(data) => data.encode_into(out)?,
            Self::BytesWritten(bytes) | Self::Offset(bytes) | Self::DirRev(bytes) => {
                put_u64(out, *bytes);
            }
            Self::DirEntries(entries) => {
                put_len(out, entries.len())?;
                for entry in entries {
                    put_dir_entry(out, entry)?;
                }
            }
            Self::Statfs(statfs) => put_statfs(out, *statfs),
            Self::XattrValue(value) => put_bytes(out, value)?,
            Self::XattrList(names) => {
                put_len(out, names.len())?;
                for name in names {
                    put_bytes(out, name)?;
                }
            }
            Self::LockConflict { owner, start, end } => {
                put_u64(out, *owner);
                put_u64(out, *start);
                put_u64(out, *end);
            }
        }
        Ok(())
    }

    fn decode(method: VfsRpcMethod, bytes: &[u8]) -> Result<Self, VfsRpcError> {
        let mut cursor = WireCursor::new(bytes);
        let payload = match method {
            VfsRpcMethod::Lookup => Self::Lookup {
                inode: cursor.inode()?,
                attr: cursor.inode_attr()?,
            },
            VfsRpcMethod::Mknod
            | VfsRpcMethod::Mkdir
            | VfsRpcMethod::Getattr
            | VfsRpcMethod::Setattr => Self::Attr(cursor.inode_attr()?),
            VfsRpcMethod::Create => Self::Created {
                inode: cursor.inode()?,
                attr: cursor.inode_attr()?,
                handle: VfsRpcHandle::decode(&mut cursor)?,
            },
            VfsRpcMethod::Open => Self::FileHandle(VfsRpcHandle::decode(&mut cursor)?),
            VfsRpcMethod::Opendir => Self::DirHandle(VfsRpcHandle::decode(&mut cursor)?),
            VfsRpcMethod::Read | VfsRpcMethod::Readlink | VfsRpcMethod::Getxattr => {
                Self::Data(InlineOrBulk::decode(&mut cursor)?)
            }
            VfsRpcMethod::Write | VfsRpcMethod::CopyFileRange => Self::BytesWritten(cursor.u64()?),
            VfsRpcMethod::Readdir | VfsRpcMethod::Readdirplus => {
                let count = cursor.len()?;
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    entries.push(cursor.dir_entry()?);
                }
                Self::DirEntries(entries)
            }
            VfsRpcMethod::Statfs => Self::Statfs(cursor.statfs()?),
            VfsRpcMethod::Listxattr => {
                let count = cursor.len()?;
                let mut names = Vec::with_capacity(count);
                for _ in 0..count {
                    names.push(cursor.bytes()?);
                }
                Self::XattrList(names)
            }
            VfsRpcMethod::LseekData | VfsRpcMethod::LseekHole => Self::Offset(cursor.u64()?),
            VfsRpcMethod::DirRev => Self::DirRev(cursor.u64()?),
            VfsRpcMethod::LockGet => Self::LockConflict {
                owner: cursor.u64()?,
                start: cursor.u64()?,
                end: cursor.u64()?,
            },
            _ => {
                if bytes.is_empty() {
                    Self::Empty
                } else {
                    return Err(VfsRpcError::UnexpectedPayload {
                        method,
                        len: bytes.len(),
                    });
                }
            }
        };
        cursor.finish()?;
        Ok(payload)
    }
}

/// Full request frame body carried inside service id `0x06`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VfsRpcRequest {
    pub header: VfsRpcRequestHeader,
    pub payload: VfsRpcRequestPayload,
    pub credentials: Option<VfsRpcCredentials>,
}

impl VfsRpcRequest {
    pub fn new(
        op_id: OpId,
        term: u64,
        epoch: u64,
        flags: u16,
        payload: VfsRpcRequestPayload,
        credentials: Option<VfsRpcCredentials>,
    ) -> Result<Self, VfsRpcError> {
        let mut payload_bytes = Vec::new();
        payload.encode_into(&mut payload_bytes)?;
        let mut creds_bytes = Vec::new();
        if let Some(creds) = &credentials {
            creds.encode_into(&mut creds_bytes)?;
        }
        let method = payload.method();
        Ok(Self {
            header: VfsRpcRequestHeader::new(
                op_id,
                term,
                epoch,
                flags,
                method,
                checked_u32_len(payload_bytes.len())?,
                checked_u32_len(creds_bytes.len())?,
            ),
            payload,
            credentials,
        })
    }

    #[must_use]
    pub const fn message_type(&self) -> u8 {
        self.header.method.request_message_type()
    }

    pub fn encode(&self) -> Result<Vec<u8>, VfsRpcError> {
        let mut payload_bytes = Vec::new();
        self.payload.encode_into(&mut payload_bytes)?;
        let mut creds_bytes = Vec::new();
        if let Some(creds) = &self.credentials {
            creds.encode_into(&mut creds_bytes)?;
        }
        if payload_bytes.len() != self.header.payload_len as usize {
            return Err(VfsRpcError::HeaderLengthMismatch);
        }
        if creds_bytes.len() != self.header.creds_len as usize {
            return Err(VfsRpcError::HeaderLengthMismatch);
        }
        let mut out =
            Vec::with_capacity(REQUEST_HEADER_LEN + payload_bytes.len() + creds_bytes.len());
        self.header.encode_into(&mut out);
        out.extend_from_slice(&payload_bytes);
        out.extend_from_slice(&creds_bytes);
        Ok(out)
    }

    pub fn decode(message_type: u8, bytes: &[u8]) -> Result<Self, VfsRpcError> {
        let method = VfsRpcMethod::from_message_type(message_type, VfsRpcMessageKind::Request)?;
        if bytes.len() < REQUEST_HEADER_LEN {
            return Err(VfsRpcError::Truncated);
        }
        let header = VfsRpcRequestHeader::decode(&bytes[..REQUEST_HEADER_LEN])?;
        if header.method != method {
            return Err(VfsRpcError::MethodMismatch {
                outer: method,
                inner: header.method,
            });
        }
        let payload_start = REQUEST_HEADER_LEN;
        let payload_end = payload_start
            .checked_add(header.payload_len as usize)
            .ok_or(VfsRpcError::LengthOverflow)?;
        let creds_end = payload_end
            .checked_add(header.creds_len as usize)
            .ok_or(VfsRpcError::LengthOverflow)?;
        if bytes.len() != creds_end {
            return Err(VfsRpcError::FrameLengthMismatch {
                expected: creds_end,
                actual: bytes.len(),
            });
        }
        let payload = VfsRpcRequestPayload::decode(method, &bytes[payload_start..payload_end])?;
        let credentials = if header.creds_len == 0 {
            None
        } else {
            Some(VfsRpcCredentials::decode(&bytes[payload_end..creds_end])?)
        };
        Ok(Self {
            header,
            payload,
            credentials,
        })
    }
}

/// Full response frame body carried inside service id `0x06`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VfsRpcResponse {
    pub method: VfsRpcMethod,
    pub header: VfsRpcResponseHeader,
    pub payload: VfsRpcResponsePayload,
}

impl VfsRpcResponse {
    pub fn ok(
        op_id: OpId,
        method: VfsRpcMethod,
        flags: u16,
        payload: VfsRpcResponsePayload,
    ) -> Result<Self, VfsRpcError> {
        Self::new(op_id, method, Errno::SUCCESS, flags, payload)
    }

    pub fn error(op_id: OpId, method: VfsRpcMethod, errno: Errno) -> Result<Self, VfsRpcError> {
        Self::new(op_id, method, errno, 0, VfsRpcResponsePayload::Empty)
    }

    pub fn new(
        op_id: OpId,
        method: VfsRpcMethod,
        errno: Errno,
        flags: u16,
        payload: VfsRpcResponsePayload,
    ) -> Result<Self, VfsRpcError> {
        let mut payload_bytes = Vec::new();
        payload.encode_into(&mut payload_bytes)?;
        Ok(Self {
            method,
            header: VfsRpcResponseHeader::new(
                op_id,
                errno,
                flags,
                checked_u32_len(payload_bytes.len())?,
            ),
            payload,
        })
    }

    #[must_use]
    pub const fn message_type(&self) -> u8 {
        self.method.response_message_type()
    }

    pub fn with_flag(mut self, flag: u16) -> Self {
        self.header.flags |= flag;
        self
    }

    pub fn encode(&self) -> Result<Vec<u8>, VfsRpcError> {
        let mut payload_bytes = Vec::new();
        self.payload.encode_into(&mut payload_bytes)?;
        if payload_bytes.len() != self.header.payload_len as usize {
            return Err(VfsRpcError::HeaderLengthMismatch);
        }
        let mut out = Vec::with_capacity(RESPONSE_HEADER_LEN + payload_bytes.len());
        self.header.encode_into(&mut out);
        out.extend_from_slice(&payload_bytes);
        Ok(out)
    }

    pub fn decode(message_type: u8, bytes: &[u8]) -> Result<Self, VfsRpcError> {
        let method = VfsRpcMethod::from_message_type(message_type, VfsRpcMessageKind::Response)?;
        if bytes.len() < RESPONSE_HEADER_LEN {
            return Err(VfsRpcError::Truncated);
        }
        let header = VfsRpcResponseHeader::decode(&bytes[..RESPONSE_HEADER_LEN])?;
        let payload_start = RESPONSE_HEADER_LEN;
        let payload_end = payload_start
            .checked_add(header.payload_len as usize)
            .ok_or(VfsRpcError::LengthOverflow)?;
        if bytes.len() != payload_end {
            return Err(VfsRpcError::FrameLengthMismatch {
                expected: payload_end,
                actual: bytes.len(),
            });
        }
        let payload = if header.errno.is_error() {
            if header.payload_len != 0 {
                return Err(VfsRpcError::ErrorResponseWithPayload);
            }
            VfsRpcResponsePayload::Empty
        } else {
            VfsRpcResponsePayload::decode(method, &bytes[payload_start..payload_end])?
        };
        Ok(Self {
            method,
            header,
            payload,
        })
    }
}

/// Transport-facing service frame wrapper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VfsRpcTransportFrame {
    pub service_id: u8,
    pub message_type: u8,
    pub body: Vec<u8>,
}

impl VfsRpcTransportFrame {
    pub fn from_request(request: &VfsRpcRequest) -> Result<Self, VfsRpcError> {
        Ok(Self {
            service_id: VFS_RPC_SERVICE_ID,
            message_type: request.message_type(),
            body: request.encode()?,
        })
    }

    pub fn from_response(response: &VfsRpcResponse) -> Result<Self, VfsRpcError> {
        Ok(Self {
            service_id: VFS_RPC_SERVICE_ID,
            message_type: response.message_type(),
            body: response.encode()?,
        })
    }

    pub fn decode_request(&self) -> Result<VfsRpcRequest, VfsRpcError> {
        self.check_service()?;
        VfsRpcRequest::decode(self.message_type, &self.body)
    }

    pub fn decode_response(&self) -> Result<VfsRpcResponse, VfsRpcError> {
        self.check_service()?;
        VfsRpcResponse::decode(self.message_type, &self.body)
    }

    fn check_service(&self) -> Result<(), VfsRpcError> {
        if self.service_id != VFS_RPC_SERVICE_ID {
            return Err(VfsRpcError::UnexpectedServiceId(self.service_id));
        }
        Ok(())
    }
}

/// Runtime counters for VFS_RPC correlation and replay behavior.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VfsRpcStats {
    pub requests_sent: u64,
    pub responses_received: u64,
    pub responses_unknown: u64,
    pub timeouts: u64,
    pub retries: u64,
    pub dedup_hits: u64,
    pub dedup_inserts: u64,
    pub avg_latency_ms: u64,
}

/// Client-side request id correlation and retry accounting.
#[derive(Clone, Debug)]
pub struct VfsRpcClient {
    term: u64,
    epoch: u64,
    next_op_id: u64,
    retry_after: Duration,
    max_in_flight: usize,
    in_flight: BTreeMap<OpId, PendingRequest>,
    stats: VfsRpcStats,
    total_latency_ms: u128,
}

impl VfsRpcClient {
    #[must_use]
    pub fn new(term: u64, epoch: u64, max_in_flight: usize, retry_after: Duration) -> Self {
        Self {
            term,
            epoch,
            next_op_id: 1,
            retry_after,
            max_in_flight: max_in_flight.max(1),
            in_flight: BTreeMap::new(),
            stats: VfsRpcStats::default(),
            total_latency_ms: 0,
        }
    }

    pub fn begin_request(
        &mut self,
        now: Instant,
        flags: u16,
        payload: VfsRpcRequestPayload,
        credentials: Option<VfsRpcCredentials>,
    ) -> Result<VfsRpcRequest, VfsRpcError> {
        if self.in_flight.len() >= self.max_in_flight {
            return Err(VfsRpcError::TooManyInFlight(self.max_in_flight));
        }
        let op_id = OpId(self.next_op_id);
        self.next_op_id = self.next_op_id.saturating_add(1).max(1);
        let method = payload.method();
        let request =
            VfsRpcRequest::new(op_id, self.term, self.epoch, flags, payload, credentials)?;
        self.in_flight.insert(
            op_id,
            PendingRequest {
                method,
                sent_at: now,
                last_attempt_at: now,
                retries: 0,
            },
        );
        self.stats.requests_sent = self.stats.requests_sent.saturating_add(1);
        Ok(request)
    }

    pub fn complete_response(
        &mut self,
        now: Instant,
        response: &VfsRpcResponse,
    ) -> Result<PendingRequest, VfsRpcError> {
        let pending = match self.in_flight.remove(&response.header.op_id) {
            Some(pending) => pending,
            None => {
                self.stats.responses_unknown = self.stats.responses_unknown.saturating_add(1);
                return Err(VfsRpcError::UnknownResponse(response.header.op_id));
            }
        };
        if pending.method != response.method {
            return Err(VfsRpcError::MethodMismatch {
                outer: pending.method,
                inner: response.method,
            });
        }
        self.stats.responses_received = self.stats.responses_received.saturating_add(1);
        let latency = now.saturating_duration_since(pending.sent_at).as_millis();
        self.total_latency_ms = self.total_latency_ms.saturating_add(latency);
        if self.stats.responses_received > 0 {
            self.stats.avg_latency_ms =
                (self.total_latency_ms / u128::from(self.stats.responses_received)) as u64;
        }
        Ok(pending)
    }

    pub fn retry_due(&mut self, now: Instant) -> Vec<OpId> {
        let mut due = Vec::new();
        for (op_id, pending) in &mut self.in_flight {
            if now.saturating_duration_since(pending.last_attempt_at) >= self.retry_after {
                pending.last_attempt_at = now;
                pending.retries = pending.retries.saturating_add(1);
                self.stats.retries = self.stats.retries.saturating_add(1);
                due.push(*op_id);
            }
        }
        due
    }

    pub fn expire_timed_out(&mut self, now: Instant, max_age: Duration) -> Vec<OpId> {
        let expired: Vec<OpId> = self
            .in_flight
            .iter()
            .filter_map(|(op_id, pending)| {
                if now.saturating_duration_since(pending.sent_at) >= max_age {
                    Some(*op_id)
                } else {
                    None
                }
            })
            .collect();
        for op_id in &expired {
            self.in_flight.remove(op_id);
            self.stats.timeouts = self.stats.timeouts.saturating_add(1);
        }
        expired
    }

    #[must_use]
    pub fn in_flight_len(&self) -> usize {
        self.in_flight.len()
    }

    #[must_use]
    pub const fn stats(&self) -> VfsRpcStats {
        self.stats
    }
}

/// Client-side record for one in-flight request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingRequest {
    pub method: VfsRpcMethod,
    pub sent_at: Instant,
    pub last_attempt_at: Instant,
    pub retries: u32,
}

/// Server-side per-peer deduplication window.
#[derive(Clone, Debug)]
pub struct VfsRpcDedupWindow {
    capacity: usize,
    order: VecDeque<(PeerId, OpId)>,
    entries: BTreeMap<(PeerId, OpId), VfsRpcResponse>,
    stats: VfsRpcStats,
}

impl VfsRpcDedupWindow {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::new(),
            entries: BTreeMap::new(),
            stats: VfsRpcStats::default(),
        }
    }

    pub fn lookup(&mut self, peer: PeerId, request: &VfsRpcRequest) -> Option<VfsRpcResponse> {
        if request.header.flags & REQ_FLAG_NO_DEDUP != 0 {
            return None;
        }
        let key = (peer, request.header.op_id);
        let response = self
            .entries
            .get(&key)?
            .clone()
            .with_flag(RESP_FLAG_DEDUP_REPLAY);
        self.touch(key);
        self.stats.dedup_hits = self.stats.dedup_hits.saturating_add(1);
        Some(response)
    }

    pub fn insert(&mut self, peer: PeerId, response: VfsRpcResponse) {
        let key = (peer, response.header.op_id);
        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(key, response);
        self.touch(key);
        self.stats.dedup_inserts = self.stats.dedup_inserts.saturating_add(1);
    }

    pub fn clear_peer(&mut self, peer: PeerId) {
        self.entries
            .retain(|(entry_peer, _), _| *entry_peer != peer);
        self.order.retain(|(entry_peer, _)| *entry_peer != peer);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub const fn stats(&self) -> VfsRpcStats {
        self.stats
    }

    fn touch(&mut self, key: (PeerId, OpId)) {
        if let Some(pos) = self.order.iter().position(|candidate| *candidate == key) {
            self.order.remove(pos);
        }
        self.order.push_back(key);
    }
}

/// Errors emitted by VFS_RPC wire decoding and correlation state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VfsRpcError {
    UnknownMethod(u16),
    ReservedMessageKind(u8),
    WrongMessageKind {
        expected: VfsRpcMessageKind,
        found: VfsRpcMessageKind,
    },
    MethodMismatch {
        outer: VfsRpcMethod,
        inner: VfsRpcMethod,
    },
    UnexpectedServiceId(u8),
    UnknownInlineOrBulkKind(u8),
    UnknownHandleType(u8),
    UnknownNodeKind(u32),
    Truncated,
    TrailingBytes(usize),
    LengthOverflow,
    LengthTooLarge(usize),
    FrameLengthMismatch {
        expected: usize,
        actual: usize,
    },
    HeaderLengthMismatch,
    ReservedNonZero,
    BoolOutOfRange(u8),
    TooManyGroups(usize),
    TooManyInFlight(usize),
    UnknownResponse(OpId),
    ErrorResponseWithPayload,
    UnexpectedPayload {
        method: VfsRpcMethod,
        len: usize,
    },
}

impl fmt::Display for VfsRpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownMethod(id) => write!(f, "unknown VFS_RPC method id {id:#04x}"),
            Self::ReservedMessageKind(kind) => {
                write!(f, "reserved VFS_RPC message kind bits {kind:#04b}")
            }
            Self::WrongMessageKind { expected, found } => {
                write!(
                    f,
                    "wrong VFS_RPC message kind: expected {expected:?}, found {found:?}"
                )
            }
            Self::MethodMismatch { outer, inner } => {
                write!(
                    f,
                    "VFS_RPC method mismatch: outer {outer:?}, inner {inner:?}"
                )
            }
            Self::UnexpectedServiceId(id) => {
                write!(f, "unexpected VFS_RPC service id {id:#04x}")
            }
            Self::UnknownInlineOrBulkKind(kind) => {
                write!(f, "unknown inline-or-bulk kind {kind}")
            }
            Self::UnknownHandleType(kind) => write!(f, "unknown VFS_RPC handle type {kind}"),
            Self::UnknownNodeKind(kind) => write!(f, "unknown node kind {kind}"),
            Self::Truncated => write!(f, "truncated VFS_RPC frame"),
            Self::TrailingBytes(len) => write!(f, "VFS_RPC frame has {len} trailing byte(s)"),
            Self::LengthOverflow => write!(f, "VFS_RPC length overflow"),
            Self::LengthTooLarge(len) => write!(f, "VFS_RPC length {len} exceeds u32::MAX"),
            Self::FrameLengthMismatch { expected, actual } => {
                write!(
                    f,
                    "VFS_RPC frame length mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::HeaderLengthMismatch => write!(f, "VFS_RPC header length does not match payload"),
            Self::ReservedNonZero => write!(f, "VFS_RPC reserved field is non-zero"),
            Self::BoolOutOfRange(value) => write!(f, "VFS_RPC boolean value {value} is invalid"),
            Self::TooManyGroups(count) => write!(f, "too many VFS_RPC credential groups: {count}"),
            Self::TooManyInFlight(limit) => {
                write!(f, "VFS_RPC in-flight limit reached: {limit}")
            }
            Self::UnknownResponse(op_id) => write!(f, "unknown VFS_RPC response op_id {}", op_id.0),
            Self::ErrorResponseWithPayload => {
                write!(f, "VFS_RPC error response carried a payload")
            }
            Self::UnexpectedPayload { method, len } => {
                write!(
                    f,
                    "unexpected {len}-byte payload for VFS_RPC method {method:?}"
                )
            }
        }
    }
}

impl std::error::Error for VfsRpcError {}

fn handle_flags_from_open_flags(open_flags: u32) -> u8 {
    let mut flags = 0;
    if open_flags & 0o3 != 0 {
        flags |= 0b0000_0001;
    }
    if open_flags & 0o3 != 0o0 {
        flags |= 0b0000_0010;
    }
    const O_APPEND: u32 = 0o2000;
    const O_DSYNC: u32 = 0o10000;
    const O_DIRECT: u32 = 0o40000;
    const O_SYNC: u32 = 0o4010000;
    if open_flags & O_APPEND != 0 {
        flags |= 0b0000_0100;
    }
    if open_flags & O_DIRECT != 0 {
        flags |= 0b0000_1000;
    }
    if open_flags & O_DSYNC != 0 {
        flags |= 0b0001_0000;
    }
    if open_flags & O_SYNC != 0 {
        flags |= 0b0010_0000;
    }
    flags
}

fn checked_u32_len(len: usize) -> Result<u32, VfsRpcError> {
    u32::try_from(len).map_err(|_| VfsRpcError::LengthTooLarge(len))
}

fn put_len(out: &mut Vec<u8>, len: usize) -> Result<(), VfsRpcError> {
    put_u32(out, checked_u32_len(len)?);
    Ok(())
}

fn put_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn put_bool(out: &mut Vec<u8>, value: bool) {
    out.push(u8::from(value));
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u128(out: &mut Vec<u8>, value: u128) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), VfsRpcError> {
    put_len(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_inode(out: &mut Vec<u8>, inode: InodeId) {
    put_u64(out, inode.get());
}

fn put_generation(out: &mut Vec<u8>, generation: Generation) {
    put_u64(out, generation.get());
}

fn put_setattr(out: &mut Vec<u8>, attr: SetAttr) {
    put_u32(out, attr.valid);
    put_u32(out, attr.mode);
    put_u32(out, attr.uid);
    put_u32(out, attr.gid);
    put_u64(out, attr.size);
    put_i64(out, attr.atime_ns);
    put_i64(out, attr.mtime_ns);
    put_i64(out, attr.ctime_ns);
}

fn put_posix_attrs(out: &mut Vec<u8>, attrs: PosixAttrs) {
    put_u32(out, attrs.mode);
    put_u32(out, attrs.uid);
    put_u32(out, attrs.gid);
    put_u32(out, attrs.nlink);
    put_u32(out, attrs.rdev);
    put_i64(out, attrs.atime_ns);
    put_i64(out, attrs.mtime_ns);
    put_i64(out, attrs.ctime_ns);
    put_i64(out, attrs.btime_ns);
    put_u64(out, attrs.size);
    put_u64(out, attrs.blocks_512);
    put_u32(out, attrs.blksize);
}

fn put_inode_flags(out: &mut Vec<u8>, flags: InodeFlags) {
    put_bool(out, flags.immutable);
    put_bool(out, flags.append_only);
    put_bool(out, flags.noatime);
    put_bool(out, flags.nodump);
}

fn put_inode_attr(out: &mut Vec<u8>, attr: &InodeAttr) {
    put_inode(out, attr.inode_id);
    put_generation(out, attr.generation);
    put_u32(out, attr.kind.as_u32());
    put_posix_attrs(out, attr.posix);
    put_inode_flags(out, attr.flags);
    put_u64(out, attr.subtree_rev);
    put_u64(out, attr.dir_rev);
}

fn put_statfs(out: &mut Vec<u8>, statfs: StatFs) {
    put_u32(out, statfs.block_size);
    put_u32(out, statfs.fragment_size);
    put_u64(out, statfs.total_blocks);
    put_u64(out, statfs.free_blocks);
    put_u64(out, statfs.avail_blocks);
    put_u64(out, statfs.files);
    put_u64(out, statfs.files_free);
    put_u32(out, statfs.name_max);
    put_u32(out, statfs.fsid_hi);
    put_u32(out, statfs.fsid_lo);
}

fn put_dir_entry(out: &mut Vec<u8>, entry: &DirEntry) -> Result<(), VfsRpcError> {
    put_bytes(out, &entry.name)?;
    put_inode(out, entry.inode_id);
    put_u32(out, entry.kind.as_u32());
    put_generation(out, entry.generation);
    put_u64(out, entry.cookie);
    Ok(())
}

struct WireCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> WireCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn finish(&self) -> Result<(), VfsRpcError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(VfsRpcError::TrailingBytes(self.bytes.len() - self.pos))
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], VfsRpcError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(VfsRpcError::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(VfsRpcError::Truncated);
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, VfsRpcError> {
        Ok(self.take(1)?[0])
    }

    fn bool(&mut self) -> Result<bool, VfsRpcError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(VfsRpcError::BoolOutOfRange(other)),
        }
    }

    fn u16(&mut self) -> Result<u16, VfsRpcError> {
        let mut buf = [0; 2];
        buf.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(buf))
    }

    fn u32(&mut self) -> Result<u32, VfsRpcError> {
        let mut buf = [0; 4];
        buf.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(buf))
    }

    fn u64(&mut self) -> Result<u64, VfsRpcError> {
        let mut buf = [0; 8];
        buf.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(buf))
    }

    fn i64(&mut self) -> Result<i64, VfsRpcError> {
        let mut buf = [0; 8];
        buf.copy_from_slice(self.take(8)?);
        Ok(i64::from_le_bytes(buf))
    }

    fn u128(&mut self) -> Result<u128, VfsRpcError> {
        let mut buf = [0; 16];
        buf.copy_from_slice(self.take(16)?);
        Ok(u128::from_le_bytes(buf))
    }

    fn array16(&mut self) -> Result<[u8; 16], VfsRpcError> {
        let mut buf = [0; 16];
        buf.copy_from_slice(self.take(16)?);
        Ok(buf)
    }

    fn array32(&mut self) -> Result<[u8; 32], VfsRpcError> {
        let mut buf = [0; 32];
        buf.copy_from_slice(self.take(32)?);
        Ok(buf)
    }

    fn len(&mut self) -> Result<usize, VfsRpcError> {
        Ok(self.u32()? as usize)
    }

    fn bytes(&mut self) -> Result<Vec<u8>, VfsRpcError> {
        let len = self.len()?;
        Ok(self.take(len)?.to_vec())
    }

    fn inode(&mut self) -> Result<InodeId, VfsRpcError> {
        Ok(InodeId(self.u64()?))
    }

    fn generation(&mut self) -> Result<Generation, VfsRpcError> {
        Ok(Generation(self.u64()?))
    }

    fn node_kind(&mut self) -> Result<NodeKind, VfsRpcError> {
        let raw = self.u32()?;
        NodeKind::try_from(raw).map_err(|_| VfsRpcError::UnknownNodeKind(raw))
    }

    fn setattr(&mut self) -> Result<SetAttr, VfsRpcError> {
        Ok(SetAttr {
            valid: self.u32()?,
            mode: self.u32()?,
            uid: self.u32()?,
            gid: self.u32()?,
            size: self.u64()?,
            atime_ns: self.i64()?,
            mtime_ns: self.i64()?,
            ctime_ns: self.i64()?,
        })
    }

    fn posix_attrs(&mut self) -> Result<PosixAttrs, VfsRpcError> {
        Ok(PosixAttrs {
            mode: self.u32()?,
            uid: self.u32()?,
            gid: self.u32()?,
            nlink: self.u32()?,
            rdev: self.u32()?,
            atime_ns: self.i64()?,
            mtime_ns: self.i64()?,
            ctime_ns: self.i64()?,
            btime_ns: self.i64()?,
            size: self.u64()?,
            blocks_512: self.u64()?,
            blksize: self.u32()?,
        })
    }

    fn inode_flags(&mut self) -> Result<InodeFlags, VfsRpcError> {
        Ok(InodeFlags {
            immutable: self.bool()?,
            append_only: self.bool()?,
            noatime: self.bool()?,
            nodump: self.bool()?,
        })
    }

    fn inode_attr(&mut self) -> Result<InodeAttr, VfsRpcError> {
        Ok(InodeAttr {
            inode_id: self.inode()?,
            generation: self.generation()?,
            kind: self.node_kind()?,
            posix: self.posix_attrs()?,
            flags: self.inode_flags()?,
            subtree_rev: self.u64()?,
            dir_rev: self.u64()?,
        })
    }

    fn statfs(&mut self) -> Result<StatFs, VfsRpcError> {
        Ok(StatFs {
            block_size: self.u32()?,
            fragment_size: self.u32()?,
            total_blocks: self.u64()?,
            free_blocks: self.u64()?,
            avail_blocks: self.u64()?,
            files: self.u64()?,
            files_free: self.u64()?,
            name_max: self.u32()?,
            fsid_hi: self.u32()?,
            fsid_lo: self.u32()?,
        })
    }

    fn dir_entry(&mut self) -> Result<DirEntry, VfsRpcError> {
        Ok(DirEntry {
            name: self.bytes()?,
            inode_id: self.inode()?,
            kind: self.node_kind()?,
            generation: self.generation()?,
            cookie: self.u64()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_vfs_core::{S_IFDIR, S_IFREG};

    fn sample_attr(ino: u64) -> InodeAttr {
        InodeAttr {
            inode_id: InodeId(ino),
            generation: Generation(7),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode: S_IFREG | 0o644,
                uid: 1000,
                gid: 1000,
                nlink: 1,
                rdev: 0,
                atime_ns: 1,
                mtime_ns: 2,
                ctime_ns: 3,
                btime_ns: 4,
                size: 4096,
                blocks_512: 8,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 11,
            dir_rev: 12,
        }
    }

    fn sample_handle() -> VfsRpcHandle {
        VfsRpcHandle {
            handle_type: VfsRpcHandleType::File,
            flags: 0b11,
            dataset_id: DatasetId(0xfeed),
            inode: InodeId(42),
            generation: Generation(3),
            writer_node: 9,
            handle_cookie: 77,
        }
    }

    fn roundtrip_request(payload: VfsRpcRequestPayload) {
        let request = VfsRpcRequest::new(
            OpId(19),
            2,
            3,
            0,
            payload.clone(),
            Some(VfsRpcCredentials::root(PeerId(4))),
        )
        .unwrap();
        let frame = VfsRpcTransportFrame::from_request(&request).unwrap();
        assert_eq!(frame.service_id, VFS_RPC_SERVICE_ID);
        let decoded = frame.decode_request().unwrap();
        assert_eq!(decoded.header.op_id, OpId(19));
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.credentials.unwrap().peer_id, PeerId(4));
        assert_eq!(
            decoded.header.payload_len as usize
                + decoded.header.creds_len as usize
                + REQUEST_HEADER_LEN,
            frame.body.len()
        );
    }

    #[test]
    fn request_header_is_fixed_width_and_rejects_reserved_bits() {
        let header = VfsRpcRequestHeader::new(OpId(1), 2, 3, 4, VfsRpcMethod::Lookup, 5, 6);
        let mut encoded = Vec::new();
        header.encode_into(&mut encoded);
        assert_eq!(encoded.len(), REQUEST_HEADER_LEN);
        assert_eq!(VfsRpcRequestHeader::decode(&encoded).unwrap(), header);
        encoded[36] = 1;
        assert_eq!(
            VfsRpcRequestHeader::decode(&encoded).unwrap_err(),
            VfsRpcError::ReservedNonZero
        );
    }

    #[test]
    fn response_header_is_fixed_width() {
        let header = VfsRpcResponseHeader::new(OpId(9), Errno::ENOENT, RESP_FLAG_TRUNCATED, 0);
        let mut encoded = Vec::new();
        header.encode_into(&mut encoded);
        assert_eq!(encoded.len(), RESPONSE_HEADER_LEN);
        assert_eq!(VfsRpcResponseHeader::decode(&encoded).unwrap(), header);
    }

    #[test]
    fn method_ids_and_message_types_match_design() {
        assert_eq!(VfsRpcMethod::Lookup.id(), 0x00);
        assert_eq!(VfsRpcMethod::Read.id(), 0x20);
        assert_eq!(VfsRpcMethod::Write.id(), 0x21);
        assert_eq!(VfsRpcMethod::LockSet.id(), 0x2A);
        assert_eq!(VfsRpcMethod::Lookup.request_message_type(), 0x00);
        assert_eq!(VfsRpcMethod::Lookup.response_message_type(), 0x40);
        assert_eq!(
            VfsRpcMethod::from_message_type(0x61, VfsRpcMessageKind::Response).unwrap(),
            VfsRpcMethod::Write
        );
    }

    #[test]
    fn request_payload_roundtrips_for_vfs_surface() {
        let handle = sample_handle();
        let payloads = vec![
            VfsRpcRequestPayload::Lookup {
                parent: InodeId(1),
                name: b"a".to_vec(),
            },
            VfsRpcRequestPayload::Mknod {
                parent: InodeId(1),
                name: b"fifo".to_vec(),
                mode: 0o100644,
                rdev: 0,
            },
            VfsRpcRequestPayload::Mkdir {
                parent: InodeId(1),
                name: b"d".to_vec(),
                mode: 0o755,
            },
            VfsRpcRequestPayload::Unlink {
                parent: InodeId(1),
                name: b"a".to_vec(),
            },
            VfsRpcRequestPayload::Rmdir {
                parent: InodeId(1),
                name: b"d".to_vec(),
            },
            VfsRpcRequestPayload::Symlink {
                parent: InodeId(1),
                name: b"l".to_vec(),
                target: b"target".to_vec(),
            },
            VfsRpcRequestPayload::Readlink { inode: InodeId(5) },
            VfsRpcRequestPayload::Rename {
                old_parent: InodeId(1),
                old_name: b"a".to_vec(),
                new_parent: InodeId(2),
                new_name: b"b".to_vec(),
                flags: 1,
            },
            VfsRpcRequestPayload::Link {
                inode: InodeId(5),
                new_parent: InodeId(1),
                new_name: b"hard".to_vec(),
            },
            VfsRpcRequestPayload::Getxattr {
                inode: InodeId(5),
                name: b"user.key".to_vec(),
                size: 128,
            },
            VfsRpcRequestPayload::Setxattr {
                inode: InodeId(5),
                name: b"user.key".to_vec(),
                value: b"value".to_vec(),
                flags: 0,
            },
            VfsRpcRequestPayload::Listxattr {
                inode: InodeId(5),
                size: 1024,
            },
            VfsRpcRequestPayload::Removexattr {
                inode: InodeId(5),
                name: b"user.key".to_vec(),
            },
            VfsRpcRequestPayload::Access {
                inode: InodeId(5),
                mask: 4,
            },
            VfsRpcRequestPayload::Create {
                parent: InodeId(1),
                name: b"new".to_vec(),
                mode: 0o644,
                flags: 0,
            },
            VfsRpcRequestPayload::Getattr { inode: InodeId(5) },
            VfsRpcRequestPayload::Setattr {
                inode: InodeId(5),
                attr: SetAttr {
                    valid: 8,
                    size: 10,
                    ..SetAttr::new()
                },
            },
            VfsRpcRequestPayload::Setattr {
                inode: InodeId(5),
                attr: SetAttr {
                    valid: 0x30,
                    atime_ns: -315_619_200_000_000_000,
                    mtime_ns: -315_619_198_876_543_211,
                    ..SetAttr::new()
                },
            },
            VfsRpcRequestPayload::Open {
                inode: InodeId(5),
                flags: 2,
                lock_owner: 77,
            },
            VfsRpcRequestPayload::Close {
                handle: handle.clone(),
            },
            VfsRpcRequestPayload::Opendir { inode: InodeId(1) },
            VfsRpcRequestPayload::Closedir {
                handle: handle.clone(),
            },
            VfsRpcRequestPayload::Readdir {
                handle: handle.clone(),
                offset: 3,
                max_entries: 64,
            },
            VfsRpcRequestPayload::Readdirplus {
                handle: handle.clone(),
                offset: 3,
                max_entries: 64,
            },
            VfsRpcRequestPayload::Statfs { inode: InodeId(1) },
            VfsRpcRequestPayload::Flush {
                handle: handle.clone(),
                lock_owner: 77,
            },
            VfsRpcRequestPayload::Release {
                handle: handle.clone(),
                flags: 0,
            },
            VfsRpcRequestPayload::Releasedir {
                handle: handle.clone(),
            },
            VfsRpcRequestPayload::Forget {
                inode: InodeId(5),
                nlookup: 2,
            },
            VfsRpcRequestPayload::BatchForget {
                entries: vec![(InodeId(5), 1), (InodeId(6), 2)],
            },
            VfsRpcRequestPayload::DirRev {
                handle: handle.clone(),
            },
            VfsRpcRequestPayload::Read {
                handle: handle.clone(),
                offset: 4,
                length: 512,
            },
            VfsRpcRequestPayload::Write {
                handle: handle.clone(),
                offset: 4,
                data: InlineOrBulk::Inline(b"abc".to_vec()),
            },
            VfsRpcRequestPayload::Fsync {
                handle: handle.clone(),
                datasync: true,
            },
            VfsRpcRequestPayload::Fallocate {
                handle: handle.clone(),
                mode: 1,
                offset: 0,
                length: 4096,
            },
            VfsRpcRequestPayload::LseekData {
                handle: handle.clone(),
                offset: 0,
            },
            VfsRpcRequestPayload::LseekHole {
                handle: handle.clone(),
                offset: 0,
            },
            VfsRpcRequestPayload::Fiemap {
                handle: handle.clone(),
                start: 0,
                length: 8192,
            },
            VfsRpcRequestPayload::Truncate {
                inode: InodeId(5),
                length: 1,
            },
            VfsRpcRequestPayload::CopyFileRange {
                src: handle.clone(),
                src_offset: 0,
                dst: handle.clone(),
                dst_offset: 10,
                length: 20,
                flags: 0,
            },
            VfsRpcRequestPayload::LockGet {
                handle: handle.clone(),
                owner: 3,
                start: 0,
                end: 10,
            },
            VfsRpcRequestPayload::LockSet {
                handle,
                owner: 3,
                start: 0,
                end: 10,
                write: true,
                block: false,
            },
        ];
        for payload in payloads {
            roundtrip_request(payload);
        }
    }

    #[test]
    fn response_roundtrips_and_errors_preserve_errno() {
        let attr = sample_attr(42);
        let response = VfsRpcResponse::ok(
            OpId(1),
            VfsRpcMethod::Getattr,
            0,
            VfsRpcResponsePayload::Attr(attr),
        )
        .unwrap();
        let frame = VfsRpcTransportFrame::from_response(&response).unwrap();
        let decoded = frame.decode_response().unwrap();
        assert_eq!(decoded.payload, VfsRpcResponsePayload::Attr(attr));

        let mut signed_attr = sample_attr(43);
        signed_attr.posix.atime_ns = -1;
        signed_attr.posix.mtime_ns = -315_619_198_876_543_211;
        signed_attr.posix.ctime_ns = -315_619_200_000_000_000;
        let signed_response = VfsRpcResponse::ok(
            OpId(3),
            VfsRpcMethod::Getattr,
            0,
            VfsRpcResponsePayload::Attr(signed_attr.clone()),
        )
        .unwrap();
        let signed_frame = VfsRpcTransportFrame::from_response(&signed_response).unwrap();
        let signed_decoded = signed_frame.decode_response().unwrap();
        assert_eq!(
            signed_decoded.payload,
            VfsRpcResponsePayload::Attr(signed_attr)
        );

        let err = VfsRpcResponse::error(OpId(2), VfsRpcMethod::Lookup, Errno::ENOENT).unwrap();
        let decoded_err =
            VfsRpcResponse::decode(err.message_type(), &err.encode().unwrap()).unwrap();
        assert_eq!(decoded_err.header.errno, Errno::ENOENT);
        assert_eq!(decoded_err.payload, VfsRpcResponsePayload::Empty);
    }

    #[test]
    fn response_payload_roundtrips_for_data_and_directory_results() {
        let entry = DirEntry {
            name: b"child".to_vec(),
            inode_id: InodeId(8),
            kind: NodeKind::Dir,
            generation: Generation(1),
            cookie: 9,
        };
        let response = VfsRpcResponse::ok(
            OpId(3),
            VfsRpcMethod::Readdir,
            0,
            VfsRpcResponsePayload::DirEntries(vec![entry.clone()]),
        )
        .unwrap();
        let decoded =
            VfsRpcResponse::decode(response.message_type(), &response.encode().unwrap()).unwrap();
        assert_eq!(
            decoded.payload,
            VfsRpcResponsePayload::DirEntries(vec![entry])
        );

        let read = VfsRpcResponse::ok(
            OpId(4),
            VfsRpcMethod::Read,
            0,
            VfsRpcResponsePayload::Data(InlineOrBulk::Inline(b"payload".to_vec())),
        )
        .unwrap();
        let decoded_read =
            VfsRpcResponse::decode(read.message_type(), &read.encode().unwrap()).unwrap();
        assert_eq!(
            decoded_read.payload,
            VfsRpcResponsePayload::Data(InlineOrBulk::Inline(b"payload".to_vec()))
        );
    }

    #[test]
    fn inline_or_bulk_selects_threshold_without_copying_bulk_payload() {
        let token = [7; 32];
        assert_eq!(
            InlineOrBulk::from_data(b"small".to_vec(), 16, token),
            InlineOrBulk::Inline(b"small".to_vec())
        );
        assert_eq!(
            InlineOrBulk::from_data(vec![1; 17], 16, token),
            InlineOrBulk::Bulk { token, len: 17 }
        );
    }

    #[test]
    fn client_correlates_responses_and_tracks_retry_timeout_state() {
        let start = Instant::now();
        let mut client = VfsRpcClient::new(1, 1, 4, Duration::from_millis(10));
        let request = client
            .begin_request(
                start,
                0,
                VfsRpcRequestPayload::Lookup {
                    parent: InodeId(1),
                    name: b"a".to_vec(),
                },
                None,
            )
            .unwrap();
        assert_eq!(client.in_flight_len(), 1);
        assert!(client
            .retry_due(start + Duration::from_millis(9))
            .is_empty());
        assert_eq!(
            client.retry_due(start + Duration::from_millis(10)),
            vec![OpId(1)]
        );
        let response =
            VfsRpcResponse::error(request.header.op_id, request.header.method, Errno::ENOENT)
                .unwrap();
        let pending = client
            .complete_response(start + Duration::from_millis(15), &response)
            .unwrap();
        assert_eq!(pending.method, VfsRpcMethod::Lookup);
        assert_eq!(client.stats().responses_received, 1);
        assert_eq!(client.stats().retries, 1);
        assert_eq!(client.in_flight_len(), 0);
    }

    #[test]
    fn client_enforces_in_flight_bound() {
        let start = Instant::now();
        let mut client = VfsRpcClient::new(1, 1, 1, Duration::from_secs(1));
        client
            .begin_request(
                start,
                0,
                VfsRpcRequestPayload::Getattr { inode: InodeId(1) },
                None,
            )
            .unwrap();
        let err = client
            .begin_request(
                start,
                0,
                VfsRpcRequestPayload::Getattr { inode: InodeId(2) },
                None,
            )
            .unwrap_err();
        assert_eq!(err, VfsRpcError::TooManyInFlight(1));
    }

    #[test]
    fn dedup_window_replays_mutation_response_and_evicts_lru() {
        let mut window = VfsRpcDedupWindow::new(1);
        let request = VfsRpcRequest::new(
            OpId(10),
            1,
            1,
            0,
            VfsRpcRequestPayload::Unlink {
                parent: InodeId(1),
                name: b"a".to_vec(),
            },
            None,
        )
        .unwrap();
        let response = VfsRpcResponse::ok(
            request.header.op_id,
            request.header.method,
            0,
            VfsRpcResponsePayload::Empty,
        )
        .unwrap();
        window.insert(PeerId(1), response);
        let replay = window.lookup(PeerId(1), &request).unwrap();
        assert_ne!(replay.header.flags & RESP_FLAG_DEDUP_REPLAY, 0);
        assert_eq!(window.stats().dedup_hits, 1);

        let second = VfsRpcResponse::error(OpId(11), VfsRpcMethod::Lookup, Errno::ENOENT).unwrap();
        window.insert(PeerId(1), second);
        assert!(window.lookup(PeerId(1), &request).is_none());
        assert_eq!(window.len(), 1);
    }

    #[test]
    fn no_dedup_flag_bypasses_replay() {
        let mut window = VfsRpcDedupWindow::new(8);
        let request = VfsRpcRequest::new(
            OpId(10),
            1,
            1,
            REQ_FLAG_NO_DEDUP,
            VfsRpcRequestPayload::Getattr { inode: InodeId(1) },
            None,
        )
        .unwrap();
        let response = VfsRpcResponse::ok(
            OpId(10),
            VfsRpcMethod::Getattr,
            0,
            VfsRpcResponsePayload::Attr(sample_attr(1)),
        )
        .unwrap();
        window.insert(PeerId(1), response);
        assert!(window.lookup(PeerId(1), &request).is_none());
    }

    #[test]
    fn handle_converts_to_engine_handles() {
        let file = EngineFileHandle::new(InodeId(9), 2, FileHandleId(44), 55);
        let rpc = VfsRpcHandle::from_file_handle(DatasetId(1), 2, file, Generation(3));
        assert_eq!(rpc.as_file_handle(2, 55), file);

        let dir = EngineDirHandle::new(InodeId(1), DirHandleId(22));
        let rpc_dir = VfsRpcHandle::from_dir_handle(DatasetId(1), 2, dir, Generation(3));
        assert_eq!(rpc_dir.as_dir_handle(), dir);
    }

    #[test]
    fn statfs_and_xattr_responses_roundtrip() {
        let statfs = StatFs {
            block_size: 4096,
            fragment_size: 4096,
            total_blocks: 100,
            free_blocks: 90,
            avail_blocks: 80,
            files: 10,
            files_free: 5,
            name_max: 255,
            fsid_hi: 1,
            fsid_lo: 2,
        };
        let response = VfsRpcResponse::ok(
            OpId(5),
            VfsRpcMethod::Statfs,
            0,
            VfsRpcResponsePayload::Statfs(statfs),
        )
        .unwrap();
        assert_eq!(
            VfsRpcResponse::decode(response.message_type(), &response.encode().unwrap())
                .unwrap()
                .payload,
            VfsRpcResponsePayload::Statfs(statfs)
        );

        let xattrs = VfsRpcResponse::ok(
            OpId(6),
            VfsRpcMethod::Listxattr,
            0,
            VfsRpcResponsePayload::XattrList(vec![b"user.a".to_vec(), b"user.b".to_vec()]),
        )
        .unwrap();
        assert_eq!(
            VfsRpcResponse::decode(xattrs.message_type(), &xattrs.encode().unwrap())
                .unwrap()
                .payload,
            VfsRpcResponsePayload::XattrList(vec![b"user.a".to_vec(), b"user.b".to_vec()])
        );
    }

    #[test]
    fn directory_attr_sample_uses_dir_mode() {
        let mut attr = sample_attr(2);
        attr.kind = NodeKind::Dir;
        attr.posix.mode = S_IFDIR | 0o755;
        let response = VfsRpcResponse::ok(
            OpId(7),
            VfsRpcMethod::Lookup,
            0,
            VfsRpcResponsePayload::Lookup {
                inode: attr.inode_id,
                attr,
            },
        )
        .unwrap();
        let decoded =
            VfsRpcResponse::decode(response.message_type(), &response.encode().unwrap()).unwrap();
        assert_eq!(
            decoded.payload,
            VfsRpcResponsePayload::Lookup {
                inode: InodeId(2),
                attr
            }
        );
    }
}
