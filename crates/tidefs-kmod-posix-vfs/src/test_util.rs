// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Shared test utilities for kmod-posix-vfs tests.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;
use crate::TideBox as Box;
use crate::TideVec as Vec;

use tidefs_kmod_bridge::kernel_types::AllocatedInode;
use tidefs_kmod_bridge::kernel_types::{
    AllocateExtentsOutcome, FiemapExtentVec, LseekDataRange, VfsEngine, VfsEngineStatFs,
    WritebackOutcome, WritebackRange,
};
use tidefs_kmod_bridge::kernel_types::{
    DirEntry, EngineDirHandle, EngineFileHandle, Errno, Generation, InodeAttr, InodeFlags, InodeId,
    LockSpec, NodeKind, PosixAttrs, RequestCtx, SetAttr, StatFs,
};
use tidefs_vfs_engine::{MmapPolicy, VmFaultOutcome, VM_FAULT_MAJOR, VM_FAULT_NOPAGE};

type LookupFn = Box<dyn Fn(InodeId, &[u8], &RequestCtx) -> Result<InodeAttr, Errno>>;
type GetattrFn =
    Box<dyn Fn(InodeId, Option<&EngineFileHandle>, &RequestCtx) -> Result<InodeAttr, Errno>>;
type StatfsFn = Box<dyn Fn(&RequestCtx) -> Result<StatFs, Errno>>;
type OpenFn = Box<dyn Fn(InodeId, u32, &RequestCtx) -> Result<EngineFileHandle, Errno>>;
type ReadFn = Box<dyn Fn(&EngineFileHandle, u64, u32, &RequestCtx) -> Result<Vec<u8>, Errno>>;
type OpendirFn = Box<dyn Fn(InodeId, &RequestCtx) -> Result<EngineDirHandle, Errno>>;
type ReaddirFn =
    Box<dyn Fn(&EngineDirHandle, u64, &RequestCtx) -> Result<(Vec<DirEntry>, bool), Errno>>;
type CreateFn = Box<
    dyn Fn(InodeId, &[u8], u32, u32, &RequestCtx) -> Result<(InodeAttr, EngineFileHandle), Errno>,
>;
type WriteFn = Box<dyn Fn(&EngineFileHandle, u64, &[u8], &RequestCtx) -> Result<u32, Errno>>;
type FlushFn = Box<dyn Fn(&EngineFileHandle, &RequestCtx) -> Result<(), Errno>>;
type LinkFn = Box<dyn Fn(InodeId, InodeId, &[u8], &RequestCtx) -> Result<InodeAttr, Errno>>;
type NameMutationFn = Box<dyn Fn(InodeId, &[u8], &RequestCtx) -> Result<(), Errno>>;
type MkdirFn = Box<dyn Fn(InodeId, &[u8], u32, &RequestCtx) -> Result<InodeAttr, Errno>>;
type AllocateInodeFn =
    Box<dyn Fn(NodeKind, InodeId, u32, u32, u32) -> Result<AllocatedInode, Errno>>;
type MknodFn = Box<dyn Fn(InodeId, &[u8], u32, u32, &RequestCtx) -> Result<InodeAttr, Errno>>;
type RenameFn = Box<dyn Fn(InodeId, &[u8], InodeId, &[u8], u32, &RequestCtx) -> Result<(), Errno>>;
type GetxattrFn = Box<dyn Fn(InodeId, &[u8], &RequestCtx) -> Result<Vec<u8>, Errno>>;
type SetxattrFn = Box<dyn Fn(InodeId, &[u8], &[u8], u32, &RequestCtx) -> Result<(), Errno>>;
type ListxattrFn = Box<dyn Fn(InodeId, &RequestCtx) -> Result<Vec<u8>, Errno>>;
type FallocateFn = Box<dyn Fn(&EngineFileHandle, u32, u64, u64, &RequestCtx) -> Result<(), Errno>>;
type ReadaheadFn = Box<dyn Fn(&EngineFileHandle, u64, u32, &RequestCtx) -> Result<(), Errno>>;
type SymlinkFn = Box<dyn Fn(InodeId, &[u8], &[u8], &RequestCtx) -> Result<InodeAttr, Errno>>;
type ReadlinkFn = Box<dyn Fn(InodeId, &RequestCtx) -> Result<Vec<u8>, Errno>>;
type SetattrFn = Box<
    dyn Fn(InodeId, &SetAttr, Option<&EngineFileHandle>, &RequestCtx) -> Result<InodeAttr, Errno>,
>;
type GetlkFn = Box<dyn Fn(InodeId, &LockSpec, &RequestCtx) -> Result<Option<LockSpec>, Errno>>;
type SetlkFn = Box<dyn Fn(InodeId, &LockSpec, &RequestCtx) -> Result<(), Errno>>;
type FsyncFn = Box<dyn Fn(&EngineFileHandle, bool, &RequestCtx) -> Result<(), Errno>>;
type FsyncdirFn = Box<dyn Fn(&EngineDirHandle, bool, &RequestCtx) -> Result<(), Errno>>;
type CopyFileRangeFn = Box<
    dyn Fn(&EngineFileHandle, u64, &EngineFileHandle, u64, u64, &RequestCtx) -> Result<u32, Errno>,
>;
type TmpfileFn =
    Box<dyn Fn(InodeId, u32, u32, &RequestCtx) -> Result<(InodeAttr, EngineFileHandle), Errno>>;
type SyncfsFn = Box<dyn Fn(&RequestCtx) -> Result<(), Errno>>;
type DataRangesFn =
    Box<dyn Fn(&EngineFileHandle, u64, u64, &RequestCtx) -> Result<Vec<LseekDataRange>, Errno>>;
type WritebackFoliosFn = Box<
    dyn Fn(
        InodeId,
        &EngineFileHandle,
        WritebackRange,
        &RequestCtx,
    ) -> Result<WritebackOutcome, Errno>,
>;
type AllocateExtentsFn =
    Box<dyn Fn(InodeId, u64, u64, &RequestCtx) -> Result<AllocateExtentsOutcome, Errno>>;
type FiemapFn = Box<dyn Fn(&EngineFileHandle, &RequestCtx) -> Result<FiemapExtentVec, Errno>>;
type MmapFn = Box<dyn Fn(InodeId, u64, u64, u32, &RequestCtx) -> Result<MmapPolicy, Errno>>;
type FaultFn =
    Box<dyn Fn(&EngineFileHandle, u64, u32, &RequestCtx) -> Result<VmFaultOutcome, Errno>>;
type TxgCommitBarrierFn = Box<dyn Fn() -> Result<(), Errno>>;

pub struct MockEngine {
    pub root_ino: InodeId,
    pub lookup_fn: LookupFn,
    pub getattr_fn: GetattrFn,
    pub statfs_fn: StatfsFn,
    pub open_fn: OpenFn,
    pub read_fn: ReadFn,
    pub opendir_fn: OpendirFn,
    pub readdir_fn: ReaddirFn,
    pub create_fn: CreateFn,
    pub create_excl_fn: CreateFn,
    pub write_fn: WriteFn,
    pub flush_fn: FlushFn,
    pub link_fn: LinkFn,
    pub unlink_fn: NameMutationFn,
    pub rmdir_fn: NameMutationFn,
    pub mkdir_fn: MkdirFn,
    pub allocate_inode_fn: AllocateInodeFn,
    pub mknod_fn: MknodFn,
    pub rename_fn: RenameFn,
    pub getxattr_fn: GetxattrFn,
    pub setxattr_fn: SetxattrFn,
    pub listxattr_fn: ListxattrFn,
    pub removexattr_fn: NameMutationFn,
    pub fallocate_fn: FallocateFn,
    pub readahead_fn: ReadaheadFn,
    pub symlink_fn: SymlinkFn,
    pub readlink_fn: ReadlinkFn,
    pub setattr_fn: SetattrFn,
    pub getlk_fn: GetlkFn,
    pub setlk_fn: SetlkFn,
    pub fsync_fn: FsyncFn,
    pub fsyncdir_fn: FsyncdirFn,
    pub copy_file_range_fn: CopyFileRangeFn,
    pub tmpfile_fn: TmpfileFn,
    pub syncfs_fn: SyncfsFn,
    pub data_ranges_fn: DataRangesFn,
    pub writeback_folios_fn: WritebackFoliosFn,
    pub allocate_extents_fn: AllocateExtentsFn,
    pub fiemap_fn: FiemapFn,
    pub mmap_fn: MmapFn,
    pub fault_fn: Option<FaultFn>,
    pub txg_commit_barrier_fn: TxgCommitBarrierFn,
}
impl core::fmt::Debug for MockEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MockEngine").finish_non_exhaustive()
    }
}

impl Default for MockEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MockEngine {
    pub fn new() -> Self {
        Self {
            root_ino: InodeId::new(0),
            // Default lookup returns a file inode for intent-record
            // fidelity: create, unlink, mkdir, rmdir, rename, symlink,
            // and mknod encoders now call lookup to capture real ino data.
            lookup_fn: Box::new(|_parent, _name, _ctx| {
                Ok(InodeAttr {
                    inode_id: InodeId::new(99),
                    generation: Generation::new(1),
                    kind: NodeKind::File,
                    posix: PosixAttrs {
                        mode: 0o100644,
                        uid: 0,
                        gid: 0,
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
                    flags: InodeFlags::none(),
                    subtree_rev: 0,
                    dir_rev: 0,
                })
            }),
            getattr_fn: Box::new(|_, _, _| Err(Errno::ENOSYS)),
            statfs_fn: Box::new(|_| Err(Errno::ENOSYS)),
            open_fn: Box::new(|_, _, _| Err(Errno::ENOSYS)),
            read_fn: Box::new(|_, _, _, _| Err(Errno::ENOSYS)),
            opendir_fn: Box::new(|_, _| Err(Errno::ENOSYS)),
            readdir_fn: Box::new(|_, _, _| Err(Errno::ENOSYS)),
            create_fn: Box::new(|_, _, _, _, _| Err(Errno::ENOSYS)),
            create_excl_fn: Box::new(|_, _, _, _, _| Err(Errno::ENOSYS)),
            write_fn: Box::new(|_, _, _, _| Err(Errno::ENOSYS)),
            flush_fn: Box::new(|_, _| Err(Errno::ENOSYS)),
            link_fn: Box::new(|_, _, _, _| Err(Errno::ENOSYS)),
            unlink_fn: Box::new(|_, _, _| Err(Errno::ENOSYS)),
            rmdir_fn: Box::new(|_, _, _| Err(Errno::ENOSYS)),
            mkdir_fn: Box::new(|_, _, _, _| Err(Errno::ENOSYS)),
            mknod_fn: Box::new(|_, _, _, _, _| Err(Errno::ENOSYS)),
            allocate_inode_fn: Box::new(|k, _p, m, u, g| {
                Ok(AllocatedInode::new(
                    InodeId::new(1),
                    InodeAttr {
                        inode_id: InodeId::new(1),
                        generation: Generation::new(1),
                        kind: k,
                        posix: PosixAttrs {
                            mode: m,
                            uid: u,
                            gid: g,
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
                        flags: InodeFlags::none(),
                        subtree_rev: 0,
                        dir_rev: 0,
                    },
                ))
            }),
            rename_fn: Box::new(|_, _, _, _, _, _| Err(Errno::ENOSYS)),
            getxattr_fn: Box::new(|_, _, _| Err(Errno::ENOSYS)),
            setxattr_fn: Box::new(|_, _, _, _, _| Err(Errno::ENOSYS)),
            listxattr_fn: Box::new(|_, _| Err(Errno::ENOSYS)),
            removexattr_fn: Box::new(|_, _, _| Err(Errno::ENOSYS)),
            fallocate_fn: Box::new(|_, _, _, _, _| Err(Errno::ENOSYS)),
            readahead_fn: Box::new(|_, _, _, _| Ok(())),
            symlink_fn: Box::new(|_, _, _, _| Err(Errno::ENOSYS)),
            readlink_fn: Box::new(|_, _| Err(Errno::ENOSYS)),
            setattr_fn: Box::new(|_, _, _, _| Err(Errno::ENOSYS)),
            fsync_fn: Box::new(|_, _, _| Err(Errno::ENOSYS)),
            fsyncdir_fn: Box::new(|_, _, _| Err(Errno::ENOSYS)),
            getlk_fn: Box::new(|_, _, _| Err(Errno::ENOSYS)),
            setlk_fn: Box::new(|_, _, _| Err(Errno::ENOSYS)),
            tmpfile_fn: Box::new(|_, _, _, _| Err(Errno::ENOSYS)),
            copy_file_range_fn: Box::new(|_, _, _, _, _, _| Err(Errno::ENOSYS)),
            syncfs_fn: Box::new(|_| Err(Errno::ENOSYS)),
            data_ranges_fn: Box::new(|_, _, _, _| Err(Errno::ENOSYS)),
            writeback_folios_fn: Box::new(|_, _, _, _| {
                Ok(WritebackOutcome {
                    bytes_written: 0,
                    complete: false,
                })
            }),
            allocate_extents_fn: Box::new(|_, _, _, _| {
                Ok(AllocateExtentsOutcome {
                    bytes_allocated: 0,
                    complete: true,
                })
            }),
            fiemap_fn: Box::new(|_, _| {
                Ok(FiemapExtentVec {
                    extents: crate::TideVec::new(),
                })
            }),
            mmap_fn: Box::new(|_, _, _, _, _| Ok(MmapPolicy::PopulateOnFault)),
            fault_fn: None,
            txg_commit_barrier_fn: Box::new(|| Err(Errno::ENOSYS)),
        }
    }
    pub fn dir_attr(ino: u64) -> InodeAttr {
        InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind: NodeKind::Dir,
            posix: PosixAttrs {
                mode: 0o40755,
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
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        }
    }
    pub fn file_attr(ino: u64, size: u64) -> InodeAttr {
        InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode: 0o100644,
                uid: 1000,
                gid: 1000,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size,
                blocks_512: size.div_ceil(512),
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        }
    }
    pub fn test_ctx() -> RequestCtx {
        RequestCtx {
            uid: 1000,
            gid: 1000,
            pid: 42,
            umask: 0o022,
            groups: crate::TideVec::from([1000].as_slice()),
        }
    }
}

impl VfsEngine for MockEngine {
    fn get_root_inode(&self, _ctx: &RequestCtx) -> Result<InodeId, Errno> {
        Ok(self.root_ino)
    }
    fn lookup(&self, p: InodeId, n: &[u8], c: &RequestCtx) -> Result<InodeAttr, Errno> {
        (self.lookup_fn)(p, n, c)
    }
    fn getattr(
        &self,
        i: InodeId,
        h: Option<&EngineFileHandle>,
        c: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        (self.getattr_fn)(i, h, c)
    }
    fn open(&self, i: InodeId, f: u32, c: &RequestCtx) -> Result<EngineFileHandle, Errno> {
        (self.open_fn)(i, f, c)
    }
    fn release(&self, _fh: &EngineFileHandle) -> Result<(), Errno> {
        Ok(())
    }
    fn read(
        &self,
        fh: &EngineFileHandle,
        o: u64,
        s: u32,
        c: &RequestCtx,
    ) -> Result<Vec<u8>, Errno> {
        (self.read_fn)(fh, o, s, c)
    }
    fn opendir(&self, i: InodeId, c: &RequestCtx) -> Result<EngineDirHandle, Errno> {
        (self.opendir_fn)(i, c)
    }
    fn releasedir(&self, _dh: &EngineDirHandle) -> Result<(), Errno> {
        Ok(())
    }
    fn readdir(
        &self,
        dh: &EngineDirHandle,
        o: u64,
        c: &RequestCtx,
    ) -> Result<(Vec<DirEntry>, bool), Errno> {
        (self.readdir_fn)(dh, o, c)
    }
    fn setattr(
        &self,
        i: InodeId,
        a: &SetAttr,
        h: Option<&EngineFileHandle>,
        c: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        (self.setattr_fn)(i, a, h, c)
    }
    fn create(
        &self,
        p: InodeId,
        n: &[u8],
        m: u32,
        f: u32,
        c: &RequestCtx,
    ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
        (self.create_fn)(p, n, m, f, c)
    }
    fn create_excl(
        &self,
        p: InodeId,
        n: &[u8],
        m: u32,
        f: u32,
        c: &RequestCtx,
    ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
        (self.create_excl_fn)(p, n, m, f, c)
    }
    fn tmpfile(
        &self,
        p: InodeId,
        m: u32,
        f: u32,
        c: &RequestCtx,
    ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
        (self.tmpfile_fn)(p, m, f, c)
    }
    fn unlink(&self, p: InodeId, n: &[u8], c: &RequestCtx) -> Result<(), Errno> {
        (self.unlink_fn)(p, n, c)
    }
    fn rmdir(&self, p: InodeId, n: &[u8], c: &RequestCtx) -> Result<(), Errno> {
        (self.rmdir_fn)(p, n, c)
    }
    fn mkdir(&self, p: InodeId, n: &[u8], m: u32, c: &RequestCtx) -> Result<InodeAttr, Errno> {
        (self.mkdir_fn)(p, n, m, c)
    }
    fn rename(
        &self,
        op: InodeId,
        on: &[u8],
        np: InodeId,
        nn: &[u8],
        f: u32,
        c: &RequestCtx,
    ) -> Result<(), Errno> {
        (self.rename_fn)(op, on, np, nn, f, c)
    }
    fn link(&self, t: InodeId, np: InodeId, nn: &[u8], c: &RequestCtx) -> Result<InodeAttr, Errno> {
        (self.link_fn)(t, np, nn, c)
    }
    fn symlink(&self, p: InodeId, n: &[u8], t: &[u8], c: &RequestCtx) -> Result<InodeAttr, Errno> {
        (self.symlink_fn)(p, n, t, c)
    }
    fn readlink(&self, i: InodeId, c: &RequestCtx) -> Result<Vec<u8>, Errno> {
        (self.readlink_fn)(i, c)
    }
    fn mknod(
        &self,
        p: InodeId,
        n: &[u8],
        m: u32,
        r: u32,
        c: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        (self.mknod_fn)(p, n, m, r, c)
    }
    fn allocate_inode(
        &self,
        k: NodeKind,
        p: InodeId,
        m: u32,
        u: u32,
        g: u32,
    ) -> Result<AllocatedInode, Errno> {
        (self.allocate_inode_fn)(k, p, m, u, g)
    }
    fn write(&self, fh: &EngineFileHandle, o: u64, d: &[u8], c: &RequestCtx) -> Result<u32, Errno> {
        (self.write_fn)(fh, o, d, c)
    }
    fn flush(&self, fh: &EngineFileHandle, c: &RequestCtx) -> Result<(), Errno> {
        (self.flush_fn)(fh, c)
    }
    fn fsync(&self, fh: &EngineFileHandle, d: bool, c: &RequestCtx) -> Result<(), Errno> {
        (self.fsync_fn)(fh, d, c)
    }
    fn fallocate(
        &self,
        fh: &EngineFileHandle,
        m: u32,
        o: u64,
        l: u64,
        c: &RequestCtx,
    ) -> Result<(), Errno> {
        (self.fallocate_fn)(fh, m, o, l, c)
    }
    fn readahead(
        &self,
        fh: &EngineFileHandle,
        o: u64,
        l: u32,
        c: &RequestCtx,
    ) -> Result<(), Errno> {
        (self.readahead_fn)(fh, o, l, c)
    }
    fn fsyncdir(&self, dh: &EngineDirHandle, d: bool, c: &RequestCtx) -> Result<(), Errno> {
        (self.fsyncdir_fn)(dh, d, c)
    }
    fn getxattr(&self, i: InodeId, n: &[u8], c: &RequestCtx) -> Result<Vec<u8>, Errno> {
        (self.getxattr_fn)(i, n, c)
    }
    fn setxattr(
        &self,
        i: InodeId,
        n: &[u8],
        v: &[u8],
        f: u32,
        c: &RequestCtx,
    ) -> Result<(), Errno> {
        (self.setxattr_fn)(i, n, v, f, c)
    }
    fn listxattr(&self, i: InodeId, c: &RequestCtx) -> Result<Vec<u8>, Errno> {
        (self.listxattr_fn)(i, c)
    }
    fn removexattr(&self, i: InodeId, n: &[u8], c: &RequestCtx) -> Result<(), Errno> {
        (self.removexattr_fn)(i, n, c)
    }
    fn getlk(&self, i: InodeId, l: &LockSpec, c: &RequestCtx) -> Result<Option<LockSpec>, Errno> {
        (self.getlk_fn)(i, l, c)
    }
    fn setlk(&self, i: InodeId, l: &LockSpec, c: &RequestCtx) -> Result<(), Errno> {
        (self.setlk_fn)(i, l, c)
    }
    fn copy_file_range(
        &self,
        sfh: &EngineFileHandle,
        oi: u64,
        dfh: &EngineFileHandle,
        oo: u64,
        l: u64,
        c: &RequestCtx,
    ) -> Result<u32, Errno> {
        (self.copy_file_range_fn)(sfh, oi, dfh, oo, l, c)
    }
    fn syncfs(&self, c: &RequestCtx) -> Result<(), Errno> {
        (self.syncfs_fn)(c)
    }
    fn data_ranges(
        &self,
        fh: &EngineFileHandle,
        o: u64,
        l: u64,
        c: &RequestCtx,
    ) -> Result<Vec<LseekDataRange>, Errno> {
        (self.data_ranges_fn)(fh, o, l, c)
    }
    fn writeback_folios(
        &self,
        inode: InodeId,
        fh: &EngineFileHandle,
        range: WritebackRange,
        ctx: &RequestCtx,
    ) -> Result<WritebackOutcome, Errno> {
        (self.writeback_folios_fn)(inode, fh, range, ctx)
    }
    fn allocate_extents(
        &self,
        inode: InodeId,
        offset: u64,
        length: u64,
        ctx: &RequestCtx,
    ) -> Result<AllocateExtentsOutcome, Errno> {
        (self.allocate_extents_fn)(inode, offset, length, ctx)
    }
    fn fiemap(&self, fh: &EngineFileHandle, ctx: &RequestCtx) -> Result<FiemapExtentVec, Errno> {
        (self.fiemap_fn)(fh, ctx)
    }

    fn mmap(
        &self,
        inode: InodeId,
        offset: u64,
        length: u64,
        flags: u32,
        ctx: &RequestCtx,
    ) -> Result<MmapPolicy, Errno> {
        (self.mmap_fn)(inode, offset, length, flags, ctx)
    }

    fn fault(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        size: u32,
        ctx: &RequestCtx,
    ) -> Result<VmFaultOutcome, Errno> {
        if let Some(ref cb) = self.fault_fn {
            cb(fh, offset, size, ctx)
        } else {
            // Fall through to default trait impl: delegates to read()
            let data = self.read(fh, offset, size, ctx)?;
            let vm_fault_code = if data.is_empty() {
                VM_FAULT_NOPAGE
            } else {
                VM_FAULT_MAJOR
            };
            Ok(VmFaultOutcome {
                page: data,
                vm_fault_code,
            })
        }
    }

    fn txg_commit_barrier(&self) -> Result<(), Errno> {
        (self.txg_commit_barrier_fn)()
    }
}

impl VfsEngineStatFs for MockEngine {
    fn statfs(&self, ctx: &RequestCtx) -> Result<StatFs, Errno> {
        (self.statfs_fn)(ctx)
    }
}
