// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! VFS operation enum and request/response types.
//!
//! This module defines [`VfsOperation`] — a canonical operation type covering
//! the full VFS namespace, file I/O, directory, xattr, and lock surface. Each
//! variant wraps a request struct carrying the operation parameters. Companion
//! response types provide type-safe return values for dispatch implementations.
//!
//! The design enables a single dispatch point that both FUSE and ublk consumers
//! use, eliminating duplicate dispatch logic across access paths.

use alloc::vec::Vec;

use crate::{
    DirEntry, EngineDirHandle, EngineFileHandle, Errno, InodeAttr, InodeId, LockSpec, RequestCtx,
    SetAttr, StatFs,
};

// ── Namespace operation requests ───────────────────────────────────────

/// `get_root_inode` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetRootInodeRequest {
    pub ctx: RequestCtx,
}

/// `lookup` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupRequest {
    pub parent: InodeId,
    pub name: Vec<u8>,
    pub ctx: RequestCtx,
}

/// `getattr` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetAttrRequest {
    pub inode: InodeId,
    pub handle: Option<EngineFileHandle>,
    pub ctx: RequestCtx,
}

/// `setattr` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetAttrRequest {
    pub inode: InodeId,
    pub attr: SetAttr,
    pub handle: Option<EngineFileHandle>,
    pub ctx: RequestCtx,
}

/// `mkdir` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MkdirRequest {
    pub parent: InodeId,
    pub name: Vec<u8>,
    pub mode: u32,
    pub ctx: RequestCtx,
}

/// `create` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateRequest {
    pub parent: InodeId,
    pub name: Vec<u8>,
    pub mode: u32,
    pub flags: u32,
    pub ctx: RequestCtx,
}

/// `create_excl` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateExclRequest {
    pub parent: InodeId,
    pub name: Vec<u8>,
    pub mode: u32,
    /// Linux open flags (e.g. O_WRONLY, O_RDWR, O_NONBLOCK, ...).
    ///
    /// This exists because `O_CREAT|O_EXCL` creation still needs to return
    /// an open handle registered with the correct access mode and flag set.
    pub flags: u32,
    pub ctx: RequestCtx,
}

/// `tmpfile` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TmpfileRequest {
    pub parent: InodeId,
    pub mode: u32,
    pub flags: u32,
    pub ctx: RequestCtx,
}

/// `unlink` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnlinkRequest {
    pub parent: InodeId,
    pub name: Vec<u8>,
    pub ctx: RequestCtx,
}

/// `rmdir` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RmdirRequest {
    pub parent: InodeId,
    pub name: Vec<u8>,
    pub ctx: RequestCtx,
}

/// `rename` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenameRequest {
    pub old_parent: InodeId,
    pub old_name: Vec<u8>,
    pub new_parent: InodeId,
    pub new_name: Vec<u8>,
    pub flags: u32,
    pub ctx: RequestCtx,
}

/// `link` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkRequest {
    pub target: InodeId,
    pub new_parent: InodeId,
    pub new_name: Vec<u8>,
    pub ctx: RequestCtx,
}

/// `symlink` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymlinkRequest {
    pub parent: InodeId,
    pub name: Vec<u8>,
    pub target: Vec<u8>,
    pub ctx: RequestCtx,
}

/// `readlink` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadLinkRequest {
    pub inode: InodeId,
    pub ctx: RequestCtx,
}

/// `mknod` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MknodRequest {
    pub parent: InodeId,
    pub name: Vec<u8>,
    pub mode: u32,
    pub rdev: u32,
    pub ctx: RequestCtx,
}

// ── File I/O operation requests ────────────────────────────────────────

/// `open` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenRequest {
    pub inode: InodeId,
    pub flags: u32,
    pub ctx: RequestCtx,
}

/// `release` (close) request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseRequest {
    pub fh: EngineFileHandle,
}

/// `read` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadRequest {
    pub fh: EngineFileHandle,
    pub offset: u64,
    pub size: u32,
    pub ctx: RequestCtx,
}

/// `write` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteRequest {
    pub fh: EngineFileHandle,
    pub offset: u64,
    pub data: Vec<u8>,
    pub ctx: RequestCtx,
}

/// `copy_file_range` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopyFileRangeRequest {
    pub source_fh: EngineFileHandle,
    pub offset_in: u64,
    pub dest_fh: EngineFileHandle,
    pub offset_out: u64,
    pub length: u64,
    pub ctx: RequestCtx,
}

/// `flush` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlushRequest {
    pub fh: EngineFileHandle,
    pub ctx: RequestCtx,
}

/// `fsync` / `fdatasync` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsyncRequest {
    pub fh: EngineFileHandle,
    pub datasync: bool,
    pub ctx: RequestCtx,
}

/// `fallocate` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FallocateRequest {
    pub fh: EngineFileHandle,
    pub mode: u32,
    pub offset: u64,
    pub length: u64,
    pub ctx: RequestCtx,
}

// ── Directory operation requests ───────────────────────────────────────

/// `opendir` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenDirRequest {
    pub inode: InodeId,
    pub ctx: RequestCtx,
}

/// `releasedir` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseDirRequest {
    pub dh: EngineDirHandle,
}

/// `readdir` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadDirRequest {
    pub dh: EngineDirHandle,
    pub offset: u64,
    pub ctx: RequestCtx,
}

/// `fsyncdir` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsyncDirRequest {
    pub dh: EngineDirHandle,
    pub datasync: bool,
    pub ctx: RequestCtx,
}

// ── Extended attribute operation requests ──────────────────────────────

/// `getxattr` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetXattrRequest {
    pub inode: InodeId,
    pub name: Vec<u8>,
    pub ctx: RequestCtx,
}

/// `setxattr` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetXattrRequest {
    pub inode: InodeId,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub flags: u32,
    pub ctx: RequestCtx,
}

/// `listxattr` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListXattrRequest {
    pub inode: InodeId,
    pub ctx: RequestCtx,
}

/// `removexattr` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoveXattrRequest {
    pub inode: InodeId,
    pub name: Vec<u8>,
    pub ctx: RequestCtx,
}

// ── Lock operation requests ────────────────────────────────────────────

/// `getlk` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetLkRequest {
    pub inode: InodeId,
    pub lock: LockSpec,
    pub ctx: RequestCtx,
}

/// `setlk` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetLkRequest {
    pub inode: InodeId,
    pub lock: LockSpec,
    pub ctx: RequestCtx,
}

/// `setlkw` (blocking setlk) request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetLkwRequest {
    pub inode: InodeId,
    pub lock: LockSpec,
    pub ctx: RequestCtx,
}

// ── Misc operation requests ────────────────────────────────────────────

/// `statfs` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatFsRequest {
    pub inode: InodeId,
    pub ctx: RequestCtx,
}

/// `syncfs` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncFsRequest {
    pub ctx: RequestCtx,
}

// ── Response types ─────────────────────────────────────────────────────

/// `get_root_inode` response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetRootInodeResponse {
    pub inode: InodeId,
}

/// `lookup` / `getattr` / `setattr` / `mkdir` / `link` / `symlink` /
/// `mknod` response — an inode's attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InodeAttrResponse {
    pub attr: InodeAttr,
}

/// `create` / `create_excl` / `tmpfile` response — new file attributes
/// plus an open file handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateResponse {
    pub attr: InodeAttr,
    pub fh: EngineFileHandle,
}

/// `open` response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenResponse {
    pub fh: EngineFileHandle,
}

/// `read` response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadResponse {
    pub data: Vec<u8>,
}

/// `write` response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteResponse {
    pub written: u32,
}

/// `copy_file_range` response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopyFileRangeResponse {
    pub copied: u32,
}

/// `readlink` / `getxattr` / `listxattr` response — raw byte payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BytePayloadResponse {
    pub data: Vec<u8>,
}

/// `opendir` response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenDirResponse {
    pub dh: EngineDirHandle,
}

/// `readdir` response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadDirResponse {
    pub entries: Vec<DirEntry>,
    pub has_more: bool,
}

/// `statfs` response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatFsResponse {
    pub stat: StatFs,
}

/// `getlk` response — `None` when no conflicting lock exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetLkResponse {
    pub conflict: Option<LockSpec>,
}

/// Unit response for operations returning `()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnitResponse;

/// `VfsResponse` — type-safe response wrapper for all VFS operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VfsResponse {
    GetRootInode(GetRootInodeResponse),
    InodeAttr(InodeAttrResponse),
    Create(CreateResponse),
    Open(OpenResponse),
    Read(ReadResponse),
    Write(WriteResponse),
    CopyFileRange(CopyFileRangeResponse),
    BytePayload(BytePayloadResponse),
    OpenDir(OpenDirResponse),
    ReadDir(ReadDirResponse),
    StatFs(StatFsResponse),
    GetLk(GetLkResponse),
    Unit(UnitResponse),
    Err(Errno),
}

// ── VfsOperation enum ──────────────────────────────────────────────────

/// Canonical VFS operation type covering the full filesystem surface.
///
/// Each variant wraps a request struct carrying all parameters for that
/// operation. Dispatch implementations match on the variant and delegate
/// to the corresponding [`VfsEngine`](crate::VfsEngine) method.
///
/// # Variants
///
/// - 16 namespace: `GetRootInode`, `Lookup`, `GetAttr`, `SetAttr`, `Mkdir`,
///   `Create`, `CreateExcl`, `Tmpfile`, `Unlink`, `Rmdir`, `Rename`, `Link`,
///   `Symlink`, `ReadLink`, `Mknod`
/// - 9 file I/O: `Open`, `Release`, `Read`, `Write`, `CopyFileRange`,
///   `Flush`, `Fsync`, `Fallocate`
/// - 4 directory: `OpenDir`, `ReleaseDir`, `ReadDir`, `FsyncDir`
/// - 4 xattr: `GetXattr`, `SetXattr`, `ListXattr`, `RemoveXattr`
/// - 3 lock: `GetLk`, `SetLk`, `SetLkw`
/// - 2 misc: `StatFs`, `SyncFs`
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VfsOperation {
    // Namespace
    GetRootInode(GetRootInodeRequest),
    Lookup(LookupRequest),
    GetAttr(GetAttrRequest),
    SetAttr(SetAttrRequest),
    Mkdir(MkdirRequest),
    Create(CreateRequest),
    CreateExcl(CreateExclRequest),
    Tmpfile(TmpfileRequest),
    Unlink(UnlinkRequest),
    Rmdir(RmdirRequest),
    Rename(RenameRequest),
    Link(LinkRequest),
    Symlink(SymlinkRequest),
    ReadLink(ReadLinkRequest),
    Mknod(MknodRequest),

    // File I/O
    Open(OpenRequest),
    Release(ReleaseRequest),
    Read(ReadRequest),
    Write(WriteRequest),
    CopyFileRange(CopyFileRangeRequest),
    Flush(FlushRequest),
    Fsync(FsyncRequest),
    Fallocate(FallocateRequest),

    // Directory
    OpenDir(OpenDirRequest),
    ReleaseDir(ReleaseDirRequest),
    ReadDir(ReadDirRequest),
    FsyncDir(FsyncDirRequest),

    // Extended attributes
    GetXattr(GetXattrRequest),
    SetXattr(SetXattrRequest),
    ListXattr(ListXattrRequest),
    RemoveXattr(RemoveXattrRequest),

    // Advisory locks
    GetLk(GetLkRequest),
    SetLk(SetLkRequest),
    SetLkw(SetLkwRequest),

    // Misc
    StatFs(StatFsRequest),
    SyncFs(SyncFsRequest),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DirHandleId, EngineDirHandle, FileHandleId, LockSpec, SetAttr};

    fn test_ctx() -> RequestCtx {
        RequestCtx {
            uid: 1000,
            gid: 1000,
            pid: 42,
            umask: 0o022,
            groups: alloc::vec![1000],
        }
    }

    // ── Operation codec round-trip: namespace ──────────────────────────

    #[test]
    fn op_get_root_inode_roundtrip() {
        let ctx = test_ctx();
        let op = VfsOperation::GetRootInode(GetRootInodeRequest { ctx: ctx.clone() });
        match op {
            VfsOperation::GetRootInode(req) => {
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_lookup_roundtrip() {
        let ctx = test_ctx();
        let parent = InodeId::new(1);
        let name: Vec<u8> = b"hello".to_vec();
        let op = VfsOperation::Lookup(LookupRequest {
            parent,
            name: name.clone(),
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::Lookup(req) => {
                assert_eq!(req.parent, parent);
                assert_eq!(req.name, name);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_getattr_roundtrip() {
        let ctx = test_ctx();
        let inode = InodeId::new(10);
        let fh = EngineFileHandle::new(inode, 0o2, FileHandleId::new(1), 0);
        let op = VfsOperation::GetAttr(GetAttrRequest {
            inode,
            handle: Some(fh),
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::GetAttr(req) => {
                assert_eq!(req.inode, inode);
                assert_eq!(req.handle, Some(fh));
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_setattr_roundtrip() {
        let ctx = test_ctx();
        let inode = InodeId::new(10);
        let attr = SetAttr {
            valid: crate::FATTR_MODE,
            mode: 0o644,
            ..SetAttr::new()
        };
        let op = VfsOperation::SetAttr(SetAttrRequest {
            inode,
            attr,
            handle: None,
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::SetAttr(req) => {
                assert_eq!(req.inode, inode);
                assert_eq!(req.attr, attr);
                assert!(req.handle.is_none());
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_mkdir_roundtrip() {
        let ctx = test_ctx();
        let parent = InodeId::new(1);
        let name: Vec<u8> = b"subdir".to_vec();
        let op = VfsOperation::Mkdir(MkdirRequest {
            parent,
            name: name.clone(),
            mode: 0o755,
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::Mkdir(req) => {
                assert_eq!(req.parent, parent);
                assert_eq!(req.name, name);
                assert_eq!(req.mode, 0o755);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_create_roundtrip() {
        let ctx = test_ctx();
        let parent = InodeId::new(1);
        let name: Vec<u8> = b"newfile".to_vec();
        let op = VfsOperation::Create(CreateRequest {
            parent,
            name: name.clone(),
            mode: 0o644,
            flags: 0o2 | 0o100, // O_RDWR | O_CREAT
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::Create(req) => {
                assert_eq!(req.parent, parent);
                assert_eq!(req.name, name);
                assert_eq!(req.mode, 0o644);
                assert_eq!(req.flags, 0o2 | 0o100);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_unlink_roundtrip() {
        let ctx = test_ctx();
        let parent = InodeId::new(1);
        let name: Vec<u8> = b"todelete".to_vec();
        let op = VfsOperation::Unlink(UnlinkRequest {
            parent,
            name: name.clone(),
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::Unlink(req) => {
                assert_eq!(req.parent, parent);
                assert_eq!(req.name, name);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_rmdir_roundtrip() {
        let ctx = test_ctx();
        let parent = InodeId::new(1);
        let name: Vec<u8> = b"emptydir".to_vec();
        let op = VfsOperation::Rmdir(RmdirRequest {
            parent,
            name: name.clone(),
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::Rmdir(req) => {
                assert_eq!(req.parent, parent);
                assert_eq!(req.name, name);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_rename_roundtrip() {
        let ctx = test_ctx();
        let old_parent = InodeId::new(1);
        let old_name: Vec<u8> = b"old".to_vec();
        let new_parent = InodeId::new(2);
        let new_name: Vec<u8> = b"new".to_vec();
        let op = VfsOperation::Rename(RenameRequest {
            old_parent,
            old_name: old_name.clone(),
            new_parent,
            new_name: new_name.clone(),
            flags: crate::RENAME_NOREPLACE,
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::Rename(req) => {
                assert_eq!(req.old_parent, old_parent);
                assert_eq!(req.old_name, old_name);
                assert_eq!(req.new_parent, new_parent);
                assert_eq!(req.new_name, new_name);
                assert_eq!(req.flags, crate::RENAME_NOREPLACE);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_symlink_roundtrip() {
        let ctx = test_ctx();
        let parent = InodeId::new(1);
        let name: Vec<u8> = b"mysym".to_vec();
        let target: Vec<u8> = b"/some/path".to_vec();
        let op = VfsOperation::Symlink(SymlinkRequest {
            parent,
            name: name.clone(),
            target: target.clone(),
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::Symlink(req) => {
                assert_eq!(req.parent, parent);
                assert_eq!(req.name, name);
                assert_eq!(req.target, target);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_readlink_roundtrip() {
        let ctx = test_ctx();
        let inode = InodeId::new(5);
        let op = VfsOperation::ReadLink(ReadLinkRequest {
            inode,
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::ReadLink(req) => {
                assert_eq!(req.inode, inode);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_link_roundtrip() {
        let ctx = test_ctx();
        let target = InodeId::new(10);
        let new_parent = InodeId::new(2);
        let new_name: Vec<u8> = b"hardlink".to_vec();
        let op = VfsOperation::Link(LinkRequest {
            target,
            new_parent,
            new_name: new_name.clone(),
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::Link(req) => {
                assert_eq!(req.target, target);
                assert_eq!(req.new_parent, new_parent);
                assert_eq!(req.new_name, new_name);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_mknod_roundtrip() {
        let ctx = test_ctx();
        let parent = InodeId::new(1);
        let name: Vec<u8> = b"fifo0".to_vec();
        let op = VfsOperation::Mknod(MknodRequest {
            parent,
            name: name.clone(),
            mode: crate::S_IFIFO | 0o644,
            rdev: 0,
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::Mknod(req) => {
                assert_eq!(req.parent, parent);
                assert_eq!(req.name, name);
                assert_eq!(req.mode, crate::S_IFIFO | 0o644);
                assert_eq!(req.rdev, 0);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    // ── Operation codec round-trip: file I/O ───────────────────────────

    #[test]
    fn op_open_roundtrip() {
        let ctx = test_ctx();
        let inode = InodeId::new(10);
        let op = VfsOperation::Open(OpenRequest {
            inode,
            flags: 0o2, // O_RDWR
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::Open(req) => {
                assert_eq!(req.inode, inode);
                assert_eq!(req.flags, 0o2);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_release_roundtrip() {
        let inode = InodeId::new(10);
        let fh = EngineFileHandle::new(inode, 0o2, FileHandleId::new(7), 0);
        let op = VfsOperation::Release(ReleaseRequest { fh });
        match op {
            VfsOperation::Release(req) => {
                assert_eq!(req.fh, fh);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_read_roundtrip() {
        let ctx = test_ctx();
        let inode = InodeId::new(10);
        let fh = EngineFileHandle::new(inode, 0o2, FileHandleId::new(1), 0);
        let op = VfsOperation::Read(ReadRequest {
            fh,
            offset: 4096,
            size: 1024,
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::Read(req) => {
                assert_eq!(req.fh, fh);
                assert_eq!(req.offset, 4096);
                assert_eq!(req.size, 1024);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_write_roundtrip() {
        let ctx = test_ctx();
        let inode = InodeId::new(10);
        let fh = EngineFileHandle::new(inode, 0o2, FileHandleId::new(1), 0);
        let data: Vec<u8> = b"payload".to_vec();
        let op = VfsOperation::Write(WriteRequest {
            fh,
            offset: 0,
            data: data.clone(),
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::Write(req) => {
                assert_eq!(req.fh, fh);
                assert_eq!(req.offset, 0);
                assert_eq!(req.data, data);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_copy_file_range_roundtrip() {
        let ctx = test_ctx();
        let src_fh = EngineFileHandle::new(InodeId::new(10), 0o2, FileHandleId::new(1), 0);
        let dst_fh = EngineFileHandle::new(InodeId::new(11), 0o2, FileHandleId::new(2), 0);
        let op = VfsOperation::CopyFileRange(CopyFileRangeRequest {
            source_fh: src_fh,
            offset_in: 0,
            dest_fh: dst_fh,
            offset_out: 8192,
            length: 4096,
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::CopyFileRange(req) => {
                assert_eq!(req.source_fh, src_fh);
                assert_eq!(req.offset_in, 0);
                assert_eq!(req.dest_fh, dst_fh);
                assert_eq!(req.offset_out, 8192);
                assert_eq!(req.length, 4096);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_flush_roundtrip() {
        let ctx = test_ctx();
        let fh = EngineFileHandle::new(InodeId::new(10), 0o2, FileHandleId::new(1), 0);
        let op = VfsOperation::Flush(FlushRequest {
            fh,
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::Flush(req) => {
                assert_eq!(req.fh, fh);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_fsync_roundtrip() {
        let ctx = test_ctx();
        let fh = EngineFileHandle::new(InodeId::new(10), 0o2, FileHandleId::new(1), 0);
        let op = VfsOperation::Fsync(FsyncRequest {
            fh,
            datasync: true,
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::Fsync(req) => {
                assert_eq!(req.fh, fh);
                assert!(req.datasync);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_fallocate_roundtrip() {
        let ctx = test_ctx();
        let fh = EngineFileHandle::new(InodeId::new(10), 0o2, FileHandleId::new(1), 0);
        let op = VfsOperation::Fallocate(FallocateRequest {
            fh,
            mode: crate::FALLOC_FL_KEEP_SIZE,
            offset: 0,
            length: 65536,
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::Fallocate(req) => {
                assert_eq!(req.fh, fh);
                assert_eq!(req.mode, crate::FALLOC_FL_KEEP_SIZE);
                assert_eq!(req.offset, 0);
                assert_eq!(req.length, 65536);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    // ── Operation codec round-trip: directory ──────────────────────────

    #[test]
    fn op_opendir_roundtrip() {
        let ctx = test_ctx();
        let inode = InodeId::new(1);
        let op = VfsOperation::OpenDir(OpenDirRequest {
            inode,
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::OpenDir(req) => {
                assert_eq!(req.inode, inode);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_releasedir_roundtrip() {
        let dh = EngineDirHandle::new(InodeId::new(1), DirHandleId::new(3));
        let op = VfsOperation::ReleaseDir(ReleaseDirRequest { dh });
        match op {
            VfsOperation::ReleaseDir(req) => {
                assert_eq!(req.dh, dh);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_readdir_roundtrip() {
        let ctx = test_ctx();
        let dh = EngineDirHandle::new(InodeId::new(1), DirHandleId::new(3));
        let op = VfsOperation::ReadDir(ReadDirRequest {
            dh,
            offset: 42,
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::ReadDir(req) => {
                assert_eq!(req.dh, dh);
                assert_eq!(req.offset, 42);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_fsyncdir_roundtrip() {
        let ctx = test_ctx();
        let dh = EngineDirHandle::new(InodeId::new(1), DirHandleId::new(3));
        let op = VfsOperation::FsyncDir(FsyncDirRequest {
            dh,
            datasync: false,
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::FsyncDir(req) => {
                assert_eq!(req.dh, dh);
                assert!(!req.datasync);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    // ── Operation codec round-trip: xattr ──────────────────────────────

    #[test]
    fn op_getxattr_roundtrip() {
        let ctx = test_ctx();
        let inode = InodeId::new(10);
        let name: Vec<u8> = b"user.mine".to_vec();
        let op = VfsOperation::GetXattr(GetXattrRequest {
            inode,
            name: name.clone(),
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::GetXattr(req) => {
                assert_eq!(req.inode, inode);
                assert_eq!(req.name, name);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_setxattr_roundtrip() {
        let ctx = test_ctx();
        let inode = InodeId::new(10);
        let name: Vec<u8> = b"user.foo".to_vec();
        let value: Vec<u8> = b"bar".to_vec();
        let op = VfsOperation::SetXattr(SetXattrRequest {
            inode,
            name: name.clone(),
            value: value.clone(),
            flags: crate::XATTR_CREATE,
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::SetXattr(req) => {
                assert_eq!(req.inode, inode);
                assert_eq!(req.name, name);
                assert_eq!(req.value, value);
                assert_eq!(req.flags, crate::XATTR_CREATE);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_listxattr_roundtrip() {
        let ctx = test_ctx();
        let inode = InodeId::new(10);
        let op = VfsOperation::ListXattr(ListXattrRequest {
            inode,
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::ListXattr(req) => {
                assert_eq!(req.inode, inode);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_removexattr_roundtrip() {
        let ctx = test_ctx();
        let inode = InodeId::new(10);
        let name: Vec<u8> = b"user.remove_me".to_vec();
        let op = VfsOperation::RemoveXattr(RemoveXattrRequest {
            inode,
            name: name.clone(),
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::RemoveXattr(req) => {
                assert_eq!(req.inode, inode);
                assert_eq!(req.name, name);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    // ── Operation codec round-trip: lock ───────────────────────────────

    #[test]
    fn op_getlk_roundtrip() {
        let ctx = test_ctx();
        let inode = InodeId::new(10);
        let lock = LockSpec {
            typ: crate::F_WRLCK,
            whence: 0,
            start: 0,
            end: 99,
            pid: 100,
        };
        let op = VfsOperation::GetLk(GetLkRequest {
            inode,
            lock,
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::GetLk(req) => {
                assert_eq!(req.inode, inode);
                assert_eq!(req.lock, lock);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_setlk_roundtrip() {
        let ctx = test_ctx();
        let inode = InodeId::new(10);
        let lock = LockSpec {
            typ: crate::F_RDLCK,
            whence: 0,
            start: 0,
            end: 99,
            pid: 200,
        };
        let op = VfsOperation::SetLk(SetLkRequest {
            inode,
            lock,
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::SetLk(req) => {
                assert_eq!(req.inode, inode);
                assert_eq!(req.lock, lock);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_setlkw_roundtrip() {
        let ctx = test_ctx();
        let inode = InodeId::new(10);
        let lock = LockSpec {
            typ: crate::F_WRLCK,
            whence: 0,
            start: 50,
            end: 60,
            pid: 300,
        };
        let op = VfsOperation::SetLkw(SetLkwRequest {
            inode,
            lock,
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::SetLkw(req) => {
                assert_eq!(req.inode, inode);
                assert_eq!(req.lock, lock);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    // ── Operation codec round-trip: misc ───────────────────────────────

    #[test]
    fn op_statfs_roundtrip() {
        let ctx = test_ctx();
        let inode = InodeId::new(1);
        let op = VfsOperation::StatFs(StatFsRequest {
            inode,
            ctx: ctx.clone(),
        });
        match op {
            VfsOperation::StatFs(req) => {
                assert_eq!(req.inode, inode);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn op_syncfs_roundtrip() {
        let ctx = test_ctx();
        let op = VfsOperation::SyncFs(SyncFsRequest { ctx: ctx.clone() });
        match op {
            VfsOperation::SyncFs(req) => {
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    // ── VfsResponse round-trip tests ───────────────────────────────────

    #[test]
    fn resp_get_root_inode_roundtrip() {
        let inode = InodeId::new(1);
        let resp = VfsResponse::GetRootInode(GetRootInodeResponse { inode });
        match resp {
            VfsResponse::GetRootInode(r) => assert_eq!(r.inode, inode),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_inode_attr_roundtrip() {
        let inode = InodeId::new(10);
        let _fh = EngineFileHandle::new(inode, 0o2, FileHandleId::new(1), 0);
        let attr = crate::InodeAttr::new(
            inode,
            crate::Generation::new(1),
            crate::NodeKind::File,
            crate::PosixAttrs {
                mode: crate::S_IFREG | 0o644,
                uid: 1000,
                gid: 1000,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            crate::InodeFlags::default(),
            0,
            0,
        );
        let resp = VfsResponse::InodeAttr(InodeAttrResponse { attr });
        match resp {
            VfsResponse::InodeAttr(r) => assert_eq!(r.attr, attr),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_create_roundtrip() {
        let inode = InodeId::new(10);
        let fh = EngineFileHandle::new(inode, 0o2, FileHandleId::new(1), 0);
        let attr = crate::InodeAttr::new(
            inode,
            crate::Generation::new(1),
            crate::NodeKind::File,
            crate::PosixAttrs {
                mode: crate::S_IFREG | 0o644,
                uid: 1000,
                gid: 1000,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            crate::InodeFlags::default(),
            0,
            0,
        );
        let resp = VfsResponse::Create(CreateResponse { attr, fh });
        match resp {
            VfsResponse::Create(r) => {
                assert_eq!(r.attr, attr);
                assert_eq!(r.fh, fh);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_read_roundtrip() {
        let data: Vec<u8> = b"response data".to_vec();
        let resp = VfsResponse::Read(ReadResponse { data: data.clone() });
        match resp {
            VfsResponse::Read(r) => assert_eq!(r.data, data),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_readdir_roundtrip() {
        let entries = alloc::vec![
            crate::DirEntry::new(
                b"file1".to_vec(),
                InodeId::new(10),
                crate::NodeKind::File,
                crate::Generation::new(1),
                0,
            ),
            crate::DirEntry::new(
                b"file2".to_vec(),
                InodeId::new(11),
                crate::NodeKind::File,
                crate::Generation::new(1),
                0,
            ),
        ];
        let resp = VfsResponse::ReadDir(ReadDirResponse {
            entries: entries.clone(),
            has_more: false,
        });
        match resp {
            VfsResponse::ReadDir(r) => {
                assert_eq!(r.entries.len(), 2);
                assert_eq!(r.entries[0].inode_id, InodeId::new(10));
                assert_eq!(r.entries[1].inode_id, InodeId::new(11));
                assert!(!r.has_more);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_err_roundtrip() {
        let resp = VfsResponse::Err(Errno::ENOENT);
        match resp {
            VfsResponse::Err(e) => assert_eq!(e, Errno::ENOENT),
            _ => panic!("wrong variant"),
        }
    }

    // ── Cross-variant round-trip stress ────────────────────────────────

    #[test]
    fn op_all_variants_distinct() {
        // Verify two different operation variants are not equal.
        let ctx = test_ctx();
        let op_a = VfsOperation::Open(OpenRequest {
            inode: InodeId::new(1),
            flags: 0,
            ctx: ctx.clone(),
        });
        let op_b = VfsOperation::Read(ReadRequest {
            fh: EngineFileHandle::new(InodeId::new(1), 0, FileHandleId::new(1), 0),
            offset: 0,
            size: 10,
            ctx: ctx.clone(),
        });
        assert_ne!(op_a, op_b);
    }

    #[test]
    fn op_same_variant_different_data_not_equal() {
        let ctx = test_ctx();
        let op_a = VfsOperation::Lookup(LookupRequest {
            parent: InodeId::new(1),
            name: b"a".to_vec(),
            ctx: ctx.clone(),
        });
        let op_b = VfsOperation::Lookup(LookupRequest {
            parent: InodeId::new(1),
            name: b"b".to_vec(),
            ctx: ctx.clone(),
        });
        assert_ne!(op_a, op_b);
    }

    #[test]
    fn op_same_variant_same_data_equal() {
        let ctx = test_ctx();
        let name: Vec<u8> = b"same".to_vec();
        let op_a = VfsOperation::Lookup(LookupRequest {
            parent: InodeId::new(1),
            name: name.clone(),
            ctx: ctx.clone(),
        });
        let op_b = VfsOperation::Lookup(LookupRequest {
            parent: InodeId::new(1),
            name,
            ctx: ctx.clone(),
        });
        assert_eq!(op_a, op_b);
    }

    #[test]
    fn op_clone_roundtrip() {
        let ctx = test_ctx();
        let data: Vec<u8> = b"clone me".to_vec();
        let original = VfsOperation::Write(WriteRequest {
            fh: EngineFileHandle::new(InodeId::new(10), 0o2, FileHandleId::new(1), 0),
            offset: 100,
            data: data.clone(),
            ctx: ctx.clone(),
        });
        let cloned = original.clone();
        assert_eq!(original, cloned);
        match cloned {
            VfsOperation::Write(req) => {
                assert_eq!(req.offset, 100);
                assert_eq!(req.data, data);
                assert_eq!(req.ctx, ctx);
            }
            _ => panic!("wrong variant"),
        }
    }

    // ── VfsResponse coverage ───────────────────────────────────────────

    #[test]
    fn resp_open_roundtrip() {
        let fh = EngineFileHandle::new(InodeId::new(10), 0o2, FileHandleId::new(1), 0);
        let resp = VfsResponse::Open(OpenResponse { fh });
        match resp {
            VfsResponse::Open(r) => assert_eq!(r.fh, fh),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_write_roundtrip() {
        let resp = VfsResponse::Write(WriteResponse { written: 42 });
        match resp {
            VfsResponse::Write(r) => assert_eq!(r.written, 42),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_copy_file_range_roundtrip() {
        let resp = VfsResponse::CopyFileRange(CopyFileRangeResponse { copied: 8192 });
        match resp {
            VfsResponse::CopyFileRange(r) => assert_eq!(r.copied, 8192),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_byte_payload_roundtrip() {
        let data: Vec<u8> = b"xattr value".to_vec();
        let resp = VfsResponse::BytePayload(BytePayloadResponse { data: data.clone() });
        match resp {
            VfsResponse::BytePayload(r) => assert_eq!(r.data, data),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_opendir_roundtrip() {
        let dh = EngineDirHandle::new(InodeId::new(1), DirHandleId::new(5));
        let resp = VfsResponse::OpenDir(OpenDirResponse { dh });
        match resp {
            VfsResponse::OpenDir(r) => assert_eq!(r.dh, dh),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_statfs_roundtrip() {
        let stat = crate::StatFs {
            block_size: 4096,
            fragment_size: 4096,
            total_blocks: 1000,
            free_blocks: 500,
            avail_blocks: 500,
            files: 100,
            files_free: 80,
            name_max: 255,
            fsid_hi: 0,
            fsid_lo: 0,
        };
        let resp = VfsResponse::StatFs(StatFsResponse { stat });
        match resp {
            VfsResponse::StatFs(r) => assert_eq!(r.stat, stat),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_getlk_roundtrip() {
        let lock = Some(LockSpec {
            typ: crate::F_WRLCK,
            whence: 0,
            start: 0,
            end: 99,
            pid: 100,
        });
        let resp = VfsResponse::GetLk(GetLkResponse { conflict: lock });
        match resp {
            VfsResponse::GetLk(r) => assert_eq!(r.conflict, lock),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_getlk_none_roundtrip() {
        let resp = VfsResponse::GetLk(GetLkResponse { conflict: None });
        match resp {
            VfsResponse::GetLk(r) => assert!(r.conflict.is_none()),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_unit_roundtrip() {
        let resp = VfsResponse::Unit(UnitResponse);
        match resp {
            VfsResponse::Unit(_) => {}
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_different_variants_not_equal() {
        let r1 = VfsResponse::Err(Errno::ENOENT);
        let r2 = VfsResponse::Unit(UnitResponse);
        assert_ne!(r1, r2);
    }
}
