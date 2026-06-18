// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! VFS dispatch trait — the canonical dispatch interface.
//!
//! Defines [`VfsDispatch`], the trait that both `tidefs-local-filesystem`
//! and future backends implement. Consumers route [`VfsOperation`] values
//! through a single `dispatch` entry point and receive a typed
//! [`VfsResponse`].
//!
//! The trait is object-safe so adapters can hold `Box<dyn VfsDispatch>`
//! and route operations through it without monomorphization.

use alloc::boxed::Box;

use crate::{
    operation::{
        CopyFileRangeRequest, CreateExclRequest, CreateRequest, FallocateRequest, FlushRequest,
        FsyncDirRequest, FsyncRequest, GetAttrRequest, GetLkRequest, GetRootInodeRequest,
        GetXattrRequest, LinkRequest, ListXattrRequest, LookupRequest, MkdirRequest, MknodRequest,
        OpenDirRequest, OpenRequest, ReadDirRequest, ReadLinkRequest, ReadRequest,
        ReleaseDirRequest, ReleaseRequest, RemoveXattrRequest, RenameRequest, RmdirRequest,
        SetAttrRequest, SetLkRequest, SetLkwRequest, SetXattrRequest, StatFsRequest,
        SymlinkRequest, SyncFsRequest, TmpfileRequest, UnlinkRequest, WriteRequest,
    },
    operation::{VfsOperation, VfsResponse},
    Errno,
};

/// Canonical dispatch interface for VFS operations.
///
/// Implementors receive a single [`VfsOperation`] and return a
/// [`VfsResponse`]. This is the shared surface that FUSE, ublk, and
/// admin consumers use to route operations to the filesystem backend.
///
/// The trait is object-safe: all methods except `dispatch` have default
/// implementations that forward through `dispatch`. Adapters that need
/// zero-alloc dispatch can override the typed methods directly.
///
/// # Example
///
/// ```ignore
/// let backend: Box<dyn VfsDispatch> = Box::new(MyBackend::new());
/// let op = VfsOperation::Lookup(LookupRequest {
///     parent: InodeId::new(1),
///     name: b"hello".to_vec(),
///     ctx: my_ctx(),
/// });
/// match backend.dispatch(op) {
///     Ok(VfsResponse::InodeAttr(r)) => println!("found {:?}", r.attr),
///     Ok(VfsResponse::Err(e)) => println!("error: {:?}", e),
///     _ => unreachable!(),
/// }
/// ```
pub trait VfsDispatch {
    /// Dispatch a VFS operation and return a typed response.
    fn dispatch(&self, op: VfsOperation) -> Result<VfsResponse, Errno>;

    // ── Namespace ──────────────────────────────────────────────────────

    /// `get_root_inode` — return the filesystem root inode.
    fn get_root_inode(&self, req: GetRootInodeRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::GetRootInode(req))
    }

    /// `lookup` — resolve `name` in `parent`.
    fn lookup(&self, req: LookupRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::Lookup(req))
    }

    /// `getattr` — get attributes for `inode`.
    fn getattr(&self, req: GetAttrRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::GetAttr(req))
    }

    /// `setattr` — set attributes on `inode`.
    fn setattr(&self, req: SetAttrRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::SetAttr(req))
    }

    /// `mkdir` — create subdirectory.
    fn mkdir(&self, req: MkdirRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::Mkdir(req))
    }

    /// `create` — create regular file.
    fn create(&self, req: CreateRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::Create(req))
    }

    /// `create_excl` — atomic O_EXCL create.
    fn create_excl(&self, req: CreateExclRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::CreateExcl(req))
    }

    /// `tmpfile` — create unnamed temporary file.
    fn tmpfile(&self, req: TmpfileRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::Tmpfile(req))
    }

    /// `unlink` — remove directory entry.
    fn unlink(&self, req: UnlinkRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::Unlink(req))
    }

    /// `rmdir` — remove empty directory.
    fn rmdir(&self, req: RmdirRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::Rmdir(req))
    }

    /// `rename` — atomically rename entry.
    fn rename(&self, req: RenameRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::Rename(req))
    }

    /// `link` — create hard link.
    fn link(&self, req: LinkRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::Link(req))
    }

    /// `symlink` — create symbolic link.
    fn symlink(&self, req: SymlinkRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::Symlink(req))
    }

    /// `readlink` — read symlink target.
    fn readlink(&self, req: ReadLinkRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::ReadLink(req))
    }

    /// `mknod` — create special file.
    fn mknod(&self, req: MknodRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::Mknod(req))
    }

    // ── File I/O ───────────────────────────────────────────────────────

    /// `open` — open a file.
    fn open(&self, req: OpenRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::Open(req))
    }

    /// `release` — close a file handle.
    fn release(&self, req: ReleaseRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::Release(req))
    }

    /// `read` — read data from a file.
    fn read(&self, req: ReadRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::Read(req))
    }

    /// `write` — write data to a file.
    fn write(&self, req: WriteRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::Write(req))
    }

    /// `copy_file_range` — copy data between open files.
    fn copy_file_range(&self, req: CopyFileRangeRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::CopyFileRange(req))
    }

    /// `flush` — flush dirty data.
    fn flush(&self, req: FlushRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::Flush(req))
    }

    /// `fsync` / `fdatasync` — synchronize file data.
    fn fsync(&self, req: FsyncRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::Fsync(req))
    }

    /// `fallocate` — allocate or punch file space.
    fn fallocate(&self, req: FallocateRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::Fallocate(req))
    }

    // ── Directory ──────────────────────────────────────────────────────

    /// `opendir` — open a directory for reading.
    fn opendir(&self, req: OpenDirRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::OpenDir(req))
    }

    /// `releasedir` — close a directory handle.
    fn releasedir(&self, req: ReleaseDirRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::ReleaseDir(req))
    }

    /// `readdir` — read directory entries.
    fn readdir(&self, req: ReadDirRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::ReadDir(req))
    }

    /// `fsyncdir` — synchronize directory metadata.
    fn fsyncdir(&self, req: FsyncDirRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::FsyncDir(req))
    }

    // ── Extended attributes ────────────────────────────────────────────

    /// `getxattr` — get extended attribute value.
    fn getxattr(&self, req: GetXattrRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::GetXattr(req))
    }

    /// `setxattr` — set extended attribute.
    fn setxattr(&self, req: SetXattrRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::SetXattr(req))
    }

    /// `listxattr` — list extended attributes.
    fn listxattr(&self, req: ListXattrRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::ListXattr(req))
    }

    /// `removexattr` — remove extended attribute.
    fn removexattr(&self, req: RemoveXattrRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::RemoveXattr(req))
    }

    // ── Locks ──────────────────────────────────────────────────────────

    /// `getlk` — test for conflicting lock.
    fn getlk(&self, req: GetLkRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::GetLk(req))
    }

    /// `setlk` — acquire or release a lock (non-blocking).
    fn setlk(&self, req: SetLkRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::SetLk(req))
    }

    /// `setlkw` — acquire or release a lock (blocking).
    fn setlkw(&self, req: SetLkwRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::SetLkw(req))
    }

    // ── Misc ───────────────────────────────────────────────────────────

    /// `statfs` — get filesystem statistics.
    fn statfs(&self, req: StatFsRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::StatFs(req))
    }

    /// `syncfs` — synchronize filesystem.
    fn syncfs(&self, req: SyncFsRequest) -> Result<VfsResponse, Errno> {
        self.dispatch(VfsOperation::SyncFs(req))
    }
}

// ── Default blanket impl for Box<dyn VfsDispatch> ─────────────────────

impl<T: VfsDispatch + ?Sized> VfsDispatch for Box<T> {
    fn dispatch(&self, op: VfsOperation) -> Result<VfsResponse, Errno> {
        (**self).dispatch(op)
    }
}

/// Bridge that adapts any [`VfsEngine`] implementor into a [`VfsDispatch`].
///
/// Wraps a reference to a VFS engine and dispatches each
/// [`VfsOperation`] variant by calling the corresponding method on
/// the engine.  This lets existing engine implementations serve as
/// dispatch backends without modification.
///
/// # Usage
///
/// ```ignore
/// let engine: Box<dyn VfsEngineStatFs + Send> = ...;
/// let bridge = VfsEngineDispatchBridge::new(&*engine);
/// let resp = bridge.dispatch(VfsOperation::Lookup(...));
/// ```
pub struct VfsEngineDispatchBridge<'a> {
    engine: &'a (dyn crate::VfsEngineStatFs + 'a),
}

impl<'a> VfsEngineDispatchBridge<'a> {
    /// Wrap a reference to a VFS engine so it can be used as a
    /// [`VfsDispatch`].
    #[must_use]
    pub fn new(engine: &'a (dyn crate::VfsEngineStatFs + 'a)) -> Self {
        Self { engine }
    }
}

impl VfsDispatch for VfsEngineDispatchBridge<'_> {
    fn dispatch(&self, op: VfsOperation) -> Result<VfsResponse, Errno> {
        use crate::operation::{
            BytePayloadResponse, CopyFileRangeResponse, CreateResponse, GetLkResponse,
            GetRootInodeResponse, InodeAttrResponse, OpenDirResponse, OpenResponse,
            ReadDirResponse, ReadResponse, StatFsResponse, UnitResponse, WriteResponse,
        };

        match op {
            // ── Namespace ──────────────────────────────────────────────
            VfsOperation::GetRootInode(req) => self
                .engine
                .get_root_inode(&req.ctx)
                .map(|inode| VfsResponse::GetRootInode(GetRootInodeResponse { inode })),
            VfsOperation::Lookup(req) => self
                .engine
                .lookup(req.parent, &req.name, &req.ctx)
                .map(|attr| VfsResponse::InodeAttr(InodeAttrResponse { attr })),
            VfsOperation::GetAttr(req) => self
                .engine
                .getattr(req.inode, req.handle.as_ref(), &req.ctx)
                .map(|attr| VfsResponse::InodeAttr(InodeAttrResponse { attr })),
            VfsOperation::SetAttr(req) => self
                .engine
                .setattr(req.inode, &req.attr, req.handle.as_ref(), &req.ctx)
                .map(|attr| VfsResponse::InodeAttr(InodeAttrResponse { attr })),
            VfsOperation::Mkdir(req) => self
                .engine
                .mkdir(req.parent, &req.name, req.mode, &req.ctx)
                .map(|attr| VfsResponse::InodeAttr(InodeAttrResponse { attr })),
            VfsOperation::Create(req) => self
                .engine
                .create(req.parent, &req.name, req.mode, req.flags, &req.ctx)
                .map(|(attr, fh)| VfsResponse::Create(CreateResponse { attr, fh })),
            VfsOperation::CreateExcl(req) => self
                .engine
                .create_excl(req.parent, &req.name, req.mode, req.flags, &req.ctx)
                .map(|(attr, fh)| VfsResponse::Create(CreateResponse { attr, fh })),
            VfsOperation::Tmpfile(req) => self
                .engine
                .tmpfile(req.parent, req.mode, req.flags, &req.ctx)
                .map(|(attr, fh)| VfsResponse::Create(CreateResponse { attr, fh })),
            VfsOperation::Unlink(req) => self
                .engine
                .unlink(req.parent, &req.name, &req.ctx)
                .map(|()| VfsResponse::Unit(UnitResponse)),
            VfsOperation::Rmdir(req) => self
                .engine
                .rmdir(req.parent, &req.name, &req.ctx)
                .map(|()| VfsResponse::Unit(UnitResponse)),
            VfsOperation::Rename(req) => self
                .engine
                .rename(
                    req.old_parent,
                    &req.old_name,
                    req.new_parent,
                    &req.new_name,
                    req.flags,
                    &req.ctx,
                )
                .map(|()| VfsResponse::Unit(UnitResponse)),
            VfsOperation::Link(req) => self
                .engine
                .link(req.target, req.new_parent, &req.new_name, &req.ctx)
                .map(|attr| VfsResponse::InodeAttr(InodeAttrResponse { attr })),
            VfsOperation::Symlink(req) => self
                .engine
                .symlink(req.parent, &req.name, &req.target, &req.ctx)
                .map(|attr| VfsResponse::InodeAttr(InodeAttrResponse { attr })),
            VfsOperation::ReadLink(req) => self
                .engine
                .readlink(req.inode, &req.ctx)
                .map(|data| VfsResponse::BytePayload(BytePayloadResponse { data })),
            VfsOperation::Mknod(req) => self
                .engine
                .mknod(req.parent, &req.name, req.mode, req.rdev, &req.ctx)
                .map(|attr| VfsResponse::InodeAttr(InodeAttrResponse { attr })),
            // ── File I/O ───────────────────────────────────────────────
            VfsOperation::Open(req) => self
                .engine
                .open(req.inode, req.flags, &req.ctx)
                .map(|fh| VfsResponse::Open(OpenResponse { fh })),
            VfsOperation::Release(req) => self
                .engine
                .release(&req.fh)
                .map(|()| VfsResponse::Unit(UnitResponse)),
            VfsOperation::Read(req) => self
                .engine
                .read(&req.fh, req.offset, req.size, &req.ctx)
                .map(|data| VfsResponse::Read(ReadResponse { data })),
            VfsOperation::Write(req) => self
                .engine
                .write(&req.fh, req.offset, &req.data, &req.ctx)
                .map(|written| VfsResponse::Write(WriteResponse { written })),
            VfsOperation::CopyFileRange(req) => self
                .engine
                .copy_file_range(
                    &req.source_fh,
                    req.offset_in,
                    &req.dest_fh,
                    req.offset_out,
                    req.length,
                    &req.ctx,
                )
                .map(|copied| VfsResponse::CopyFileRange(CopyFileRangeResponse { copied })),
            VfsOperation::Flush(req) => self
                .engine
                .flush(&req.fh, &req.ctx)
                .map(|()| VfsResponse::Unit(UnitResponse)),
            VfsOperation::Fsync(req) => self
                .engine
                .fsync(&req.fh, req.datasync, &req.ctx)
                .map(|()| VfsResponse::Unit(UnitResponse)),
            VfsOperation::Fallocate(req) => self
                .engine
                .fallocate(&req.fh, req.mode, req.offset, req.length, &req.ctx)
                .map(|()| VfsResponse::Unit(UnitResponse)),
            // ── Directory ──────────────────────────────────────────────
            VfsOperation::OpenDir(req) => self
                .engine
                .opendir(req.inode, &req.ctx)
                .map(|dh| VfsResponse::OpenDir(OpenDirResponse { dh })),
            VfsOperation::ReleaseDir(req) => self
                .engine
                .releasedir(&req.dh)
                .map(|()| VfsResponse::Unit(UnitResponse)),
            VfsOperation::ReadDir(req) => {
                self.engine
                    .readdir(&req.dh, req.offset, &req.ctx)
                    .map(|(entries, has_more)| {
                        VfsResponse::ReadDir(ReadDirResponse { entries, has_more })
                    })
            }
            VfsOperation::FsyncDir(req) => self
                .engine
                .fsyncdir(&req.dh, req.datasync, &req.ctx)
                .map(|()| VfsResponse::Unit(UnitResponse)),
            // ── Extended attributes ────────────────────────────────────
            VfsOperation::GetXattr(req) => self
                .engine
                .getxattr(req.inode, &req.name, &req.ctx)
                .map(|data| VfsResponse::BytePayload(BytePayloadResponse { data })),
            VfsOperation::SetXattr(req) => self
                .engine
                .setxattr(req.inode, &req.name, &req.value, req.flags, &req.ctx)
                .map(|()| VfsResponse::Unit(UnitResponse)),
            VfsOperation::ListXattr(req) => self
                .engine
                .listxattr(req.inode, &req.ctx)
                .map(|data| VfsResponse::BytePayload(BytePayloadResponse { data })),
            VfsOperation::RemoveXattr(req) => self
                .engine
                .removexattr(req.inode, &req.name, &req.ctx)
                .map(|()| VfsResponse::Unit(UnitResponse)),
            // ── Locks ──────────────────────────────────────────────────
            VfsOperation::GetLk(req) => self
                .engine
                .getlk(req.inode, &req.lock, &req.ctx)
                .map(|conflict| VfsResponse::GetLk(GetLkResponse { conflict })),
            VfsOperation::SetLk(req) => self
                .engine
                .setlk(req.inode, &req.lock, &req.ctx)
                .map(|()| VfsResponse::Unit(UnitResponse)),
            VfsOperation::SetLkw(req) => self
                .engine
                .setlkw(req.inode, &req.lock, &req.ctx)
                .map(|()| VfsResponse::Unit(UnitResponse)),
            // ── Misc ───────────────────────────────────────────────────
            VfsOperation::StatFs(req) => self
                .engine
                .statfs(&req.ctx)
                .map(|stat| VfsResponse::StatFs(StatFsResponse { stat })),
            VfsOperation::SyncFs(req) => self
                .engine
                .syncfs(&req.ctx)
                .map(|()| VfsResponse::Unit(UnitResponse)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DirEntry, DirHandleId, EngineDirHandle, EngineFileHandle, FileHandleId, Generation,
        InodeAttr, InodeFlags, InodeId, LockSpec, NodeKind, PosixAttrs, RequestCtx,
    };

    fn test_ctx() -> RequestCtx {
        RequestCtx {
            uid: 1000,
            gid: 1000,
            pid: 42,
            umask: 0o022,
            groups: alloc::vec![1000],
        }
    }

    fn test_attr(inode_id: u64, kind: NodeKind) -> InodeAttr {
        InodeAttr::new(
            InodeId::new(inode_id),
            Generation::new(1),
            kind,
            PosixAttrs {
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
            InodeFlags::default(),
            0,
            0,
        )
    }

    // ── Mock backend for testing dispatch trait ────────────────────────

    struct MockBackend {
        attr: InodeAttr,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                attr: test_attr(1, NodeKind::Dir),
            }
        }
    }

    impl VfsDispatch for MockBackend {
        fn dispatch(&self, op: VfsOperation) -> Result<VfsResponse, Errno> {
            match op {
                VfsOperation::GetRootInode(_) => Ok(VfsResponse::GetRootInode(
                    crate::operation::GetRootInodeResponse {
                        inode: InodeId::new(1),
                    },
                )),
                VfsOperation::Lookup(req) => {
                    if req.name == b"nonesuch" {
                        Ok(VfsResponse::Err(Errno::ENOENT))
                    } else {
                        Ok(VfsResponse::InodeAttr(
                            crate::operation::InodeAttrResponse { attr: self.attr },
                        ))
                    }
                }
                VfsOperation::Create(req) => {
                    Ok(VfsResponse::Create(crate::operation::CreateResponse {
                        attr: test_attr(100, NodeKind::File),
                        fh: EngineFileHandle::new(
                            InodeId::new(100),
                            req.flags,
                            FileHandleId::new(1),
                            0,
                        ),
                    }))
                }
                VfsOperation::Write(req) => {
                    Ok(VfsResponse::Write(crate::operation::WriteResponse {
                        written: req.data.len() as u32,
                    }))
                }
                VfsOperation::Unlink(_) => Ok(VfsResponse::Unit(crate::operation::UnitResponse)),
                VfsOperation::Rename(req)
                    if req.flags & crate::RENAME_NOREPLACE != 0 && req.new_name == b"exists" =>
                {
                    Ok(VfsResponse::Err(Errno::EEXIST))
                }
                _ => Ok(VfsResponse::Err(Errno::ENOSYS)),
            }
        }
    }

    // ── Trait object safety ────────────────────────────────────────────

    #[test]
    fn dispatch_trait_is_object_safe() {
        let backend: Box<dyn VfsDispatch> = Box::new(MockBackend::new());
        let resp = backend
            .dispatch(VfsOperation::GetRootInode(GetRootInodeRequest {
                ctx: test_ctx(),
            }))
            .expect("get_root_inode");
        match resp {
            VfsResponse::GetRootInode(r) => assert_eq!(r.inode, InodeId::new(1)),
            _ => panic!("wrong variant"),
        }
    }

    // ── Named method dispatch ──────────────────────────────────────────

    #[test]
    fn named_method_lookup_ok() {
        let backend = MockBackend::new();
        let req = LookupRequest {
            parent: InodeId::new(1),
            name: b"somefile".to_vec(),
            ctx: test_ctx(),
        };
        match backend.lookup(req).expect("lookup") {
            VfsResponse::InodeAttr(r) => {
                assert_eq!(r.attr.inode_id, InodeId::new(1));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn named_method_lookup_enoent() {
        let backend = MockBackend::new();
        let req = LookupRequest {
            parent: InodeId::new(1),
            name: b"nonesuch".to_vec(),
            ctx: test_ctx(),
        };
        match backend.lookup(req).expect("lookup") {
            VfsResponse::Err(e) => assert_eq!(e, Errno::ENOENT),
            _ => panic!("expected error"),
        }
    }

    #[test]
    fn named_method_create() {
        let backend = MockBackend::new();
        let req = CreateRequest {
            parent: InodeId::new(1),
            name: b"newfile".to_vec(),
            mode: 0o644,
            flags: 0,
            ctx: test_ctx(),
        };
        match backend.create(req).expect("create") {
            VfsResponse::Create(r) => {
                assert_eq!(r.attr.inode_id, InodeId::new(100));
                assert_eq!(r.fh.inode_id, InodeId::new(100));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn named_method_write() {
        let backend = MockBackend::new();
        let req = WriteRequest {
            fh: EngineFileHandle::new(InodeId::new(100), 0o2, FileHandleId::new(1), 0),
            offset: 0,
            data: b"hello".to_vec(),
            ctx: test_ctx(),
        };
        match backend.write(req).expect("write") {
            VfsResponse::Write(r) => assert_eq!(r.written, 5),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn named_method_unlink() {
        let backend = MockBackend::new();
        let req = UnlinkRequest {
            parent: InodeId::new(1),
            name: b"oldfile".to_vec(),
            ctx: test_ctx(),
        };
        match backend.unlink(req).expect("unlink") {
            VfsResponse::Unit(_) => {} // success
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn named_method_rename_noreplace_conflict() {
        let backend = MockBackend::new();
        let req = RenameRequest {
            old_parent: InodeId::new(1),
            old_name: b"old".to_vec(),
            new_parent: InodeId::new(1),
            new_name: b"exists".to_vec(),
            flags: crate::RENAME_NOREPLACE,
            ctx: test_ctx(),
        };
        match backend.rename(req).expect("rename") {
            VfsResponse::Err(e) => assert_eq!(e, Errno::EEXIST),
            _ => panic!("expected EEXIST"),
        }
    }

    #[test]
    fn named_method_enosys_for_unsupported() {
        let backend = MockBackend::new();
        let req = ReadLinkRequest {
            inode: InodeId::new(10),
            ctx: test_ctx(),
        };
        match backend.readlink(req).expect("readlink") {
            VfsResponse::Err(e) => assert_eq!(e, Errno::ENOSYS),
            _ => panic!("expected ENOSYS"),
        }
    }

    // ── Box delegation ─────────────────────────────────────────────────

    #[test]
    fn box_dyn_dispatch_delegates() {
        let backend: Box<dyn VfsDispatch> = Box::new(MockBackend::new());
        let req = LookupRequest {
            parent: InodeId::new(1),
            name: b"nonesuch".to_vec(),
            ctx: test_ctx(),
        };
        match backend.lookup(req).expect("lookup") {
            VfsResponse::Err(e) => assert_eq!(e, Errno::ENOENT),
            _ => panic!("expected error"),
        }
    }

    // ── Integration: operation lifecycle ───────────────────────────────

    #[test]
    fn integration_create_lookup_unlink() {
        let backend = MockBackend::new();

        // Create a file.
        let create_req = CreateRequest {
            parent: InodeId::new(1),
            name: b"myfile".to_vec(),
            mode: 0o644,
            flags: 0,
            ctx: test_ctx(),
        };
        let create_resp = backend.create(create_req).expect("create");
        let attr = match create_resp {
            VfsResponse::Create(r) => r.attr,
            _ => panic!("expected Create"),
        };
        assert_eq!(attr.inode_id, InodeId::new(100));

        // Look it up.
        let lookup_req = LookupRequest {
            parent: InodeId::new(1),
            name: b"myfile".to_vec(),
            ctx: test_ctx(),
        };
        let lookup_resp = backend.lookup(lookup_req).expect("lookup");
        match lookup_resp {
            VfsResponse::InodeAttr(r) => assert_eq!(r.attr.inode_id, InodeId::new(1)),
            _ => panic!("expected InodeAttr"),
        }

        // Unlink it.
        let unlink_req = UnlinkRequest {
            parent: InodeId::new(1),
            name: b"myfile".to_vec(),
            ctx: test_ctx(),
        };
        match backend.unlink(unlink_req).expect("unlink") {
            VfsResponse::Unit(_) => {} // success
            _ => panic!("expected Unit"),
        }
    }

    // ── In-memory backend for integration smoke test ──────────────────

    extern crate std;
    use std::cell::RefCell;
    use std::collections::BTreeMap as StdBTreeMap;

    /// A stateful in-memory VfsDispatch backend that maintains real
    /// inode lifecycle tracking and directory entries, suitable for
    /// integration testing the full create→lookup→readdir→unlink
    /// lifecycle with reference-count verification.
    struct InMemoryBackend {
        table: RefCell<crate::inode::InodeTable>,
        dirs: RefCell<StdBTreeMap<u64, StdBTreeMap<alloc::vec::Vec<u8>, u64>>>,
        next_ino: RefCell<u64>,
    }

    impl InMemoryBackend {
        fn new() -> Self {
            let mut table = crate::inode::InodeTable::new();
            // Pre-populate root directory inode
            let root_attr = InodeAttr::new(
                InodeId::new(1),
                Generation::new(1),
                NodeKind::Dir,
                PosixAttrs {
                    mode: crate::S_IFDIR | 0o755,
                    uid: 0,
                    gid: 0,
                    nlink: 2,
                    rdev: 0,
                    atime_ns: 0,
                    mtime_ns: 0,
                    ctime_ns: 0,
                    btime_ns: 0,
                    size: 0,
                    blocks_512: 0,
                    blksize: 4096,
                },
                InodeFlags::default(),
                0,
                0,
            );
            table.allocate(root_attr);
            // Pin root directory so it's never reclaimable.
            table.pin(InodeId::new(1)).unwrap();

            let mut dirs = StdBTreeMap::new();
            dirs.insert(1, StdBTreeMap::new());

            Self {
                table: RefCell::new(table),
                dirs: RefCell::new(dirs),
                next_ino: RefCell::new(2),
            }
        }

        fn alloc_ino(&self) -> InodeId {
            let mut n = self.next_ino.borrow_mut();
            let id = *n;
            *n += 1;
            InodeId::new(id)
        }
    }

    impl VfsDispatch for InMemoryBackend {
        fn dispatch(&self, op: VfsOperation) -> Result<VfsResponse, Errno> {
            match op {
                VfsOperation::GetRootInode(_) => Ok(VfsResponse::GetRootInode(
                    crate::operation::GetRootInodeResponse {
                        inode: InodeId::new(1),
                    },
                )),

                VfsOperation::Lookup(req) => {
                    let dirs = self.dirs.borrow();
                    let parent_dir = match dirs.get(&req.parent.get()) {
                        Some(d) => d,
                        None => return Ok(VfsResponse::Err(Errno::ENOENT)),
                    };
                    let child_ino = match parent_dir.get(&req.name) {
                        Some(c) => c,
                        None => return Ok(VfsResponse::Err(Errno::ENOENT)),
                    };
                    let table = self.table.borrow();
                    let handle = match table.lookup(InodeId::new(*child_ino)) {
                        Some(h) => h,
                        None => return Ok(VfsResponse::Err(Errno::ENOENT)),
                    };
                    Ok(VfsResponse::InodeAttr(
                        crate::operation::InodeAttrResponse { attr: handle.attr },
                    ))
                }

                VfsOperation::Create(req) => {
                    // Verify parent exists and is a directory.
                    {
                        let table = self.table.borrow();
                        if table.lookup(req.parent).is_none() {
                            return Ok(VfsResponse::Err(Errno::ENOENT));
                        }
                    }

                    let ino = self.alloc_ino();
                    let attr = InodeAttr::new(
                        ino,
                        Generation::new(1),
                        NodeKind::File,
                        PosixAttrs {
                            mode: crate::S_IFREG | (req.mode & 0o777),
                            uid: req.ctx.uid,
                            gid: req.ctx.gid,
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
                        InodeFlags::default(),
                        0,
                        0,
                    );

                    self.table.borrow_mut().allocate(attr);

                    // Add directory entry.
                    self.dirs
                        .borrow_mut()
                        .entry(req.parent.get())
                        .or_default()
                        .insert(req.name, ino.get());

                    let fh = EngineFileHandle::new(ino, req.flags, FileHandleId::new(1), 0);
                    Ok(VfsResponse::Create(crate::operation::CreateResponse {
                        attr,
                        fh,
                    }))
                }

                VfsOperation::Unlink(req) => {
                    let child_ino = {
                        let dirs = self.dirs.borrow();
                        let parent_dir = match dirs.get(&req.parent.get()) {
                            Some(d) => d,
                            None => return Ok(VfsResponse::Err(Errno::ENOENT)),
                        };
                        match parent_dir.get(&req.name) {
                            Some(c) => *c,
                            None => return Ok(VfsResponse::Err(Errno::ENOENT)),
                        }
                    };

                    // Remove directory entry.
                    self.dirs
                        .borrow_mut()
                        .get_mut(&req.parent.get())
                        .unwrap()
                        .remove(&req.name);

                    // Decrement refcount (nlink).
                    if self
                        .table
                        .borrow_mut()
                        .dec_ref(InodeId::new(child_ino))
                        .is_err()
                    {
                        return Ok(VfsResponse::Err(Errno::EINVAL));
                    }

                    Ok(VfsResponse::Unit(crate::operation::UnitResponse))
                }

                VfsOperation::OpenDir(req) => {
                    // Verify inode is a directory.
                    let table = self.table.borrow();
                    if table.lookup(req.inode).is_none() {
                        return Ok(VfsResponse::Err(Errno::ENOENT));
                    }
                    let dh = crate::EngineDirHandle::new(req.inode, crate::DirHandleId::new(1));
                    Ok(VfsResponse::OpenDir(crate::operation::OpenDirResponse {
                        dh,
                    }))
                }

                VfsOperation::ReadDir(req) => {
                    let dirs = self.dirs.borrow();
                    let dir_entries = match dirs.get(&req.dh.inode_id.get()) {
                        Some(d) => d,
                        None => return Ok(VfsResponse::Err(Errno::ENOENT)),
                    };
                    let table = self.table.borrow();

                    let mut entries: alloc::vec::Vec<crate::DirEntry> = alloc::vec::Vec::new();
                    for (idx, (name, ino)) in dir_entries.iter().enumerate() {
                        if (idx as u64) < req.offset {
                            continue;
                        }
                        if let Some(handle) = table.lookup(InodeId::new(*ino)) {
                            entries.push(crate::DirEntry::new(
                                name.clone(),
                                handle.inode_id,
                                handle.attr.kind,
                                handle.attr.generation,
                                idx as u64 + 1,
                            ));
                        }
                    }
                    let has_more = false;
                    Ok(VfsResponse::ReadDir(crate::operation::ReadDirResponse {
                        entries,
                        has_more,
                    }))
                }

                VfsOperation::Open(req) => {
                    let mut table = self.table.borrow_mut();
                    let handle = match table.lookup_mut(req.inode) {
                        Some(h) => h,
                        None => return Ok(VfsResponse::Err(Errno::ENOENT)),
                    };
                    handle.inc_ref();
                    let fh = EngineFileHandle::new(req.inode, req.flags, FileHandleId::new(1), 0);
                    Ok(VfsResponse::Open(crate::operation::OpenResponse { fh }))
                }

                VfsOperation::Release(req) => {
                    let mut table = self.table.borrow_mut();
                    let handle = match table.lookup_mut(req.fh.inode_id) {
                        Some(h) => h,
                        None => return Ok(VfsResponse::Err(Errno::ENOENT)),
                    };
                    if handle.dec_ref().is_err() {
                        return Ok(VfsResponse::Err(Errno::EINVAL));
                    }
                    Ok(VfsResponse::Unit(crate::operation::UnitResponse))
                }

                _ => Ok(VfsResponse::Err(Errno::ENOSYS)),
            }
        }
    }

    // ── Integration smoke test ─────────────────────────────────────────

    #[test]
    fn integration_smoke_create_lookup_readdir_unlink_lifecycle() {
        let backend = InMemoryBackend::new();
        let ctx = test_ctx();

        // 1. Create "hello.txt" in root directory.
        let create_req = CreateRequest {
            parent: InodeId::new(1),
            name: b"hello.txt".to_vec(),
            mode: 0o644,
            flags: 0,
            ctx: ctx.clone(),
        };
        let create_resp = backend.create(create_req).expect("create");
        let file_attr = match create_resp {
            VfsResponse::Create(r) => r.attr,
            _ => panic!("expected Create"),
        };
        let file_ino = file_attr.inode_id;
        assert!(file_ino.get() >= 2);
        assert_eq!(file_attr.kind, NodeKind::File);

        // 2. Lookup the created file.
        let lookup_req = LookupRequest {
            parent: InodeId::new(1),
            name: b"hello.txt".to_vec(),
            ctx: ctx.clone(),
        };
        let lookup_resp = backend.lookup(lookup_req).expect("lookup");
        match lookup_resp {
            VfsResponse::InodeAttr(r) => {
                assert_eq!(r.attr.inode_id, file_ino);
                assert_eq!(r.attr.kind, NodeKind::File);
            }
            _ => panic!("expected InodeAttr"),
        }

        // 3. Open the file (increments refcount).
        let open_req = OpenRequest {
            inode: file_ino,
            flags: 0,
            ctx: ctx.clone(),
        };
        backend.open(open_req).expect("open");

        // 4. Read root directory entries — should contain "hello.txt".
        let opendir_req = OpenDirRequest {
            inode: InodeId::new(1),
            ctx: ctx.clone(),
        };
        let opendir_resp = backend.opendir(opendir_req).expect("opendir");
        let dh = match opendir_resp {
            VfsResponse::OpenDir(r) => r.dh,
            _ => panic!("expected OpenDir"),
        };

        let readdir_req = ReadDirRequest {
            dh,
            offset: 0,
            ctx: ctx.clone(),
        };
        let readdir_resp = backend.readdir(readdir_req).expect("readdir");
        let entries = match readdir_resp {
            VfsResponse::ReadDir(r) => r.entries,
            _ => panic!("expected ReadDir"),
        };
        let found = entries.iter().find(|e| e.inode_id == file_ino);
        assert!(found.is_some(), "created file should appear in readdir");
        assert_eq!(found.unwrap().name, b"hello.txt");

        // 5. Release the open handle (decrements refcount but nlink=1 still).
        let release_req = ReleaseRequest {
            fh: EngineFileHandle::new(file_ino, 0, FileHandleId::new(1), 0),
        };
        backend.release(release_req).expect("release");

        // 6. Unlink the file — removes directory entry, decrements nlink.
        let unlink_req = UnlinkRequest {
            parent: InodeId::new(1),
            name: b"hello.txt".to_vec(),
            ctx: ctx.clone(),
        };
        backend.unlink(unlink_req).expect("unlink");

        // 7. After unlink, the inode should be reclaimable (refcount 0).
        let reclaimable = backend.table.borrow().collect_reclaimable();
        assert!(
            reclaimable.contains(&file_ino),
            "unlinked file with no open handles should be reclaimable"
        );

        // 8. Lookup after unlink should return ENOENT.
        let lookup_after = backend.lookup(LookupRequest {
            parent: InodeId::new(1),
            name: b"hello.txt".to_vec(),
            ctx: ctx.clone(),
        });
        match lookup_after {
            Ok(VfsResponse::Err(e)) => assert_eq!(e, Errno::ENOENT),
            _ => panic!("expected ENOENT after unlink, got {:?}", lookup_after),
        }

        // 9. Reclaim the inode.
        let reclaimed = backend.table.borrow_mut().reclaim(file_ino);
        assert!(reclaimed.is_ok(), "should successfully reclaim");
        assert!(backend.table.borrow().lookup(file_ino).is_none());
    }

    #[test]
    fn integration_smoke_refcount_open_prevents_reclaim() {
        let backend = InMemoryBackend::new();
        let ctx = test_ctx();

        // Create file.
        let create_resp = backend
            .create(CreateRequest {
                parent: InodeId::new(1),
                name: b"pinned.txt".to_vec(),
                mode: 0o644,
                flags: 0,
                ctx: ctx.clone(),
            })
            .expect("create");
        let file_ino = match create_resp {
            VfsResponse::Create(r) => r.attr.inode_id,
            _ => panic!("expected Create"),
        };

        // Open the file (refcount: 1 (nlink) + 1 (open) = 2).
        backend
            .open(OpenRequest {
                inode: file_ino,
                flags: 0,
                ctx: ctx.clone(),
            })
            .expect("open");

        // Unlink (removes dir entry, decrements nlink: refcount 2 -> 1).
        backend
            .unlink(UnlinkRequest {
                parent: InodeId::new(1),
                name: b"pinned.txt".to_vec(),
                ctx: ctx.clone(),
            })
            .expect("unlink");

        // Table lookup should still find it (refcount > 0).
        assert!(
            backend.table.borrow().lookup(file_ino).is_some(),
            "open handle should prevent reclamation"
        );

        // It should NOT be reclaimable yet.
        let reclaimable = backend.table.borrow().collect_reclaimable();
        assert!(
            !reclaimable.contains(&file_ino),
            "inode with open handle should not be reclaimable"
        );

        // Release the handle (refcount 1 -> 0).
        backend
            .release(ReleaseRequest {
                fh: EngineFileHandle::new(file_ino, 0, FileHandleId::new(1), 0),
            })
            .expect("release");

        // Now it should be reclaimable.
        let reclaimable = backend.table.borrow().collect_reclaimable();
        assert!(
            reclaimable.contains(&file_ino),
            "after release, unlinked inode should be reclaimable"
        );
    }

    // ── VfsEngineDispatchBridge tests ──────────────────────────────────

    /// Minimal VfsEngineStatFs mock that records dispatch calls and
    /// returns canned responses for bridge testing.
    struct BridgeMockEngine {
        root_ino: u64,
        lookup_attr: InodeAttr,
    }

    impl BridgeMockEngine {
        fn new() -> Self {
            Self {
                root_ino: 1,
                lookup_attr: test_attr(42, NodeKind::File),
            }
        }
    }

    #[allow(unused_variables)]
    impl crate::VfsEngine for BridgeMockEngine {
        fn get_root_inode(&self, ctx: &RequestCtx) -> Result<InodeId, Errno> {
            Ok(InodeId::new(self.root_ino))
        }
        fn lookup(
            &self,
            parent: InodeId,
            name: &[u8],
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            if name == b"found" {
                Ok(self.lookup_attr)
            } else {
                Err(Errno::ENOENT)
            }
        }
        fn getattr(
            &self,
            inode: InodeId,
            handle: Option<&EngineFileHandle>,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Ok(test_attr(inode.get(), NodeKind::File))
        }
        fn setattr(
            &self,
            inode: InodeId,
            attr: &crate::SetAttr,
            handle: Option<&EngineFileHandle>,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Ok(test_attr(inode.get(), NodeKind::File))
        }
        fn mkdir(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Ok(test_attr(100, NodeKind::Dir))
        }
        fn create(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            let attr = test_attr(200, NodeKind::File);
            let fh = EngineFileHandle::new(InodeId::new(200), flags, FileHandleId::new(1), 0);
            Ok((attr, fh))
        }
        fn create_excl(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            Err(Errno::ENOSYS)
        }
        fn tmpfile(
            &self,
            parent: InodeId,
            mode: u32,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            Err(Errno::ENOSYS)
        }
        fn unlink(&self, parent: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
            Ok(())
        }
        fn rmdir(&self, parent: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
            Ok(())
        }
        fn rename(
            &self,
            old_parent: InodeId,
            old_name: &[u8],
            new_parent: InodeId,
            new_name: &[u8],
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Ok(())
        }
        fn link(
            &self,
            target: InodeId,
            new_parent: InodeId,
            new_name: &[u8],
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Ok(test_attr(target.get(), NodeKind::File))
        }
        fn symlink(
            &self,
            parent: InodeId,
            name: &[u8],
            target: &[u8],
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Ok(test_attr(300, NodeKind::Symlink))
        }
        fn readlink(&self, inode: InodeId, ctx: &RequestCtx) -> Result<alloc::vec::Vec<u8>, Errno> {
            Ok(b"/target/path".to_vec())
        }
        fn mknod(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            rdev: u32,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Ok(test_attr(400, NodeKind::CharDev))
        }
        fn open(
            &self,
            inode: InodeId,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<EngineFileHandle, Errno> {
            Ok(EngineFileHandle::new(inode, flags, FileHandleId::new(1), 0))
        }
        fn release(&self, fh: &EngineFileHandle) -> Result<(), Errno> {
            Ok(())
        }
        fn read(
            &self,
            fh: &EngineFileHandle,
            offset: u64,
            size: u32,
            ctx: &RequestCtx,
        ) -> Result<alloc::vec::Vec<u8>, Errno> {
            Ok(b"hello".to_vec())
        }
        fn write(
            &self,
            fh: &EngineFileHandle,
            offset: u64,
            data: &[u8],
            ctx: &RequestCtx,
        ) -> Result<u32, Errno> {
            Ok(data.len() as u32)
        }
        fn copy_file_range(
            &self,
            source_fh: &EngineFileHandle,
            offset_in: u64,
            dest_fh: &EngineFileHandle,
            offset_out: u64,
            length: u64,
            ctx: &RequestCtx,
        ) -> Result<u32, Errno> {
            Ok(0)
        }
        fn flush(&self, fh: &EngineFileHandle, ctx: &RequestCtx) -> Result<(), Errno> {
            Ok(())
        }
        fn fsync(
            &self,
            fh: &EngineFileHandle,
            datasync: bool,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Ok(())
        }
        fn fallocate(
            &self,
            fh: &EngineFileHandle,
            mode: u32,
            offset: u64,
            length: u64,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Ok(())
        }
        fn opendir(&self, inode: InodeId, ctx: &RequestCtx) -> Result<EngineDirHandle, Errno> {
            Ok(EngineDirHandle::new(inode, DirHandleId::new(1)))
        }
        fn releasedir(&self, dh: &EngineDirHandle) -> Result<(), Errno> {
            Ok(())
        }
        fn readdir(
            &self,
            dh: &EngineDirHandle,
            offset: u64,
            ctx: &RequestCtx,
        ) -> Result<(alloc::vec::Vec<DirEntry>, bool), Errno> {
            Ok((alloc::vec::Vec::new(), false))
        }
        fn fsyncdir(
            &self,
            dh: &EngineDirHandle,
            datasync: bool,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Ok(())
        }
        fn syncfs(&self, ctx: &RequestCtx) -> Result<(), Errno> {
            Ok(())
        }
        fn getxattr(
            &self,
            inode: InodeId,
            name: &[u8],
            ctx: &RequestCtx,
        ) -> Result<alloc::vec::Vec<u8>, Errno> {
            Ok(b"xattr-val".to_vec())
        }
        fn setxattr(
            &self,
            inode: InodeId,
            name: &[u8],
            value: &[u8],
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Ok(())
        }
        fn listxattr(
            &self,
            inode: InodeId,
            ctx: &RequestCtx,
        ) -> Result<alloc::vec::Vec<u8>, Errno> {
            Ok(b"user.a\0user.b".to_vec())
        }
        fn removexattr(&self, inode: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
            Ok(())
        }
        fn getlk(
            &self,
            inode: InodeId,
            lock: &LockSpec,
            ctx: &RequestCtx,
        ) -> Result<Option<LockSpec>, Errno> {
            Ok(None)
        }
        fn setlk(&self, inode: InodeId, lock: &LockSpec, ctx: &RequestCtx) -> Result<(), Errno> {
            Ok(())
        }
        fn setlkw(&self, inode: InodeId, lock: &LockSpec, ctx: &RequestCtx) -> Result<(), Errno> {
            Ok(())
        }
    }

    impl crate::VfsEngineStatFs for BridgeMockEngine {
        fn statfs(&self, _ctx: &RequestCtx) -> Result<crate::StatFs, Errno> {
            Ok(crate::StatFs {
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
            })
        }
    }

    #[test]
    fn bridge_get_root_inode() {
        let engine = BridgeMockEngine::new();
        let bridge = super::VfsEngineDispatchBridge::new(&engine);
        let resp = bridge
            .dispatch(VfsOperation::GetRootInode(GetRootInodeRequest {
                ctx: test_ctx(),
            }))
            .expect("get_root_inode");
        match resp {
            VfsResponse::GetRootInode(r) => assert_eq!(r.inode, InodeId::new(1)),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn bridge_lookup_found() {
        let engine = BridgeMockEngine::new();
        let bridge = super::VfsEngineDispatchBridge::new(&engine);
        let resp = bridge
            .dispatch(VfsOperation::Lookup(LookupRequest {
                parent: InodeId::new(1),
                name: b"found".to_vec(),
                ctx: test_ctx(),
            }))
            .expect("lookup");
        match resp {
            VfsResponse::InodeAttr(r) => {
                assert_eq!(r.attr.inode_id, InodeId::new(42));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn bridge_lookup_not_found() {
        let engine = BridgeMockEngine::new();
        let bridge = super::VfsEngineDispatchBridge::new(&engine);
        // VfsEngine::lookup returns Err(Errno::ENOENT) directly
        let result = bridge.dispatch(VfsOperation::Lookup(LookupRequest {
            parent: InodeId::new(1),
            name: b"missing".to_vec(),
            ctx: test_ctx(),
        }));
        assert_eq!(result, Err(Errno::ENOENT));
    }

    #[test]
    fn bridge_create_returns_attr_and_fh() {
        let engine = BridgeMockEngine::new();
        let bridge = super::VfsEngineDispatchBridge::new(&engine);
        let resp = bridge
            .dispatch(VfsOperation::Create(CreateRequest {
                parent: InodeId::new(1),
                name: b"new".to_vec(),
                mode: 0o644,
                flags: 0,
                ctx: test_ctx(),
            }))
            .expect("create");
        match resp {
            VfsResponse::Create(r) => {
                assert_eq!(r.attr.inode_id, InodeId::new(200));
                assert_eq!(r.fh.inode_id, InodeId::new(200));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn bridge_unlink_returns_unit() {
        let engine = BridgeMockEngine::new();
        let bridge = super::VfsEngineDispatchBridge::new(&engine);
        let resp = bridge
            .dispatch(VfsOperation::Unlink(UnlinkRequest {
                parent: InodeId::new(1),
                name: b"gone".to_vec(),
                ctx: test_ctx(),
            }))
            .expect("unlink");
        match resp {
            VfsResponse::Unit(_) => {} // success
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn bridge_statfs_returns_stat() {
        let engine = BridgeMockEngine::new();
        let bridge = super::VfsEngineDispatchBridge::new(&engine);
        let resp = bridge
            .dispatch(VfsOperation::StatFs(StatFsRequest {
                inode: InodeId::new(1),
                ctx: test_ctx(),
            }))
            .expect("statfs");
        match resp {
            VfsResponse::StatFs(r) => {
                assert_eq!(r.stat.block_size, 4096);
                assert_eq!(r.stat.total_blocks, 1000);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn bridge_is_object_safe_via_box() {
        let engine: Box<dyn crate::VfsEngineStatFs + Send> = Box::new(BridgeMockEngine::new());
        let bridge = super::VfsEngineDispatchBridge::new(&*engine);
        let resp = bridge
            .dispatch(VfsOperation::Lookup(LookupRequest {
                parent: InodeId::new(1),
                name: b"found".to_vec(),
                ctx: test_ctx(),
            }))
            .expect("lookup via Box<dyn>");
        match resp {
            VfsResponse::InodeAttr(r) => {
                assert_eq!(r.attr.inode_id, InodeId::new(42));
            }
            _ => panic!("wrong variant"),
        }
    }
}
