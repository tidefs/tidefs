// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Directory operations bridge — canonical namespace mutation entry point.
//!
//! Provides no_std-compatible bridge functions that translate kernel VFS
//! directory inode_operations dispatch parameters into VfsEngine calls.
//! These functions are pure delegation wrappers without BLAKE3 attestation,
//! keeping namespace mutation policy in the delegated VfsEngine path.
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;
use crate::TideVec as Vec;

use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{
    DirEntry, EngineDirHandle, EngineFileHandle, Errno, InodeAttr, InodeId, RequestCtx,
};

#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::ByteSliceExt;
/// Kernel `file_operations::iterate_shared` bridge — directory entry batch fetch.
///
/// Pure delegation wrapper around [`VfsEngine::readdir`]. Accepts the
/// directory handle, starting cookie (offset), and request context.
/// Returns a batch of [`DirEntry`] records and a `more` flag indicating
/// whether additional entries remain beyond this batch.
///
/// This is the canonical kernel directory enumeration bridge; the
/// [`crate::file::KmodPosixVfs::dispatch_iterate`] method uses a
/// [`crate::dir_cursor::DirCursor`] to track offset state across
/// multiple calls, calling this bridge when the cursor's buffer is
/// exhausted.
///
/// # No-daemon boundary
///
/// Resolves locally within kernel authority. No userspace daemon
/// required.
pub fn bridge_readdir<E: VfsEngine + ?Sized>(
    engine: &E,
    dh: &EngineDirHandle,
    offset: u64,
    ctx: &RequestCtx,
) -> Result<(Vec<DirEntry>, bool), Errno> {
    engine.readdir(dh, offset, ctx)
}

pub fn bridge_lookup<E: VfsEngine + ?Sized>(
    engine: &E,
    parent: InodeId,
    name: &[u8],
    ctx: &RequestCtx,
) -> Result<InodeAttr, Errno> {
    engine.lookup(parent, name, ctx)
}

pub fn bridge_getattr<E: VfsEngine + ?Sized>(
    engine: &E,
    inode: InodeId,
    handle: Option<&EngineFileHandle>,
    ctx: &RequestCtx,
) -> Result<InodeAttr, Errno> {
    engine.getattr(inode, handle, ctx)
}
pub fn bridge_create<E: VfsEngine + ?Sized>(
    engine: &E,
    parent: InodeId,
    name: &[u8],
    mode: u32,
    flags: u32,
    ctx: &RequestCtx,
) -> Result<(InodeAttr, EngineFileHandle), Errno> {
    engine.create(parent, name, mode, flags, ctx)
}
pub fn bridge_rename<E: VfsEngine + ?Sized>(
    engine: &E,
    old_parent: InodeId,
    old_name: &[u8],
    new_parent: InodeId,
    new_name: &[u8],
    flags: u32,
    ctx: &RequestCtx,
) -> Result<(), Errno> {
    engine.rename(old_parent, old_name, new_parent, new_name, flags, ctx)
}
pub fn bridge_unlink<E: VfsEngine + ?Sized>(
    engine: &E,
    parent: InodeId,
    name: &[u8],
    ctx: &RequestCtx,
) -> Result<(), Errno> {
    engine.unlink(parent, name, ctx)
}
pub fn bridge_mkdir<E: VfsEngine + ?Sized>(
    engine: &E,
    parent: InodeId,
    name: &[u8],
    mode: u32,
    ctx: &RequestCtx,
) -> Result<InodeAttr, Errno> {
    engine.mkdir(parent, name, mode, ctx)
}

pub fn bridge_link<E: VfsEngine + ?Sized>(
    engine: &E,
    target: InodeId,
    new_parent: InodeId,
    new_name: &[u8],
    ctx: &RequestCtx,
) -> Result<InodeAttr, Errno> {
    engine.link(target, new_parent, new_name, ctx)
}
pub fn bridge_rmdir<E: VfsEngine + ?Sized>(
    engine: &E,
    parent: InodeId,
    name: &[u8],
    ctx: &RequestCtx,
) -> Result<(), Errno> {
    engine.rmdir(parent, name, ctx)
}

pub fn bridge_symlink<E: VfsEngine + ?Sized>(
    engine: &E,
    parent: InodeId,
    name: &[u8],
    target: &[u8],
    ctx: &RequestCtx,
) -> Result<InodeAttr, Errno> {
    engine.symlink(parent, name, target, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::KernelErrno;
    use crate::TideVec as Vec;
    use alloc::vec; // Kbuild: use crate::TideVec;
    use tidefs_kmod_bridge::kernel_types::{
        DirEntry, DirHandleId, EngineDirHandle, FileHandleId, Generation, InodeFlags, LockSpec,
        NodeKind, PosixAttrs, SetAttr,
    };

    struct MockEngine {
        lr: Result<InodeAttr, Errno>,
        cr: Result<(InodeAttr, EngineFileHandle), Errno>,
        rr: Result<(), Errno>,
        ur: Result<(), Errno>,
        mkr: Result<InodeAttr, Errno>,
        rmr: Result<(), Errno>,
        rdr: Result<(Vec<DirEntry>, bool), Errno>,
        slr: Result<InodeAttr, Errno>,
    }
    impl MockEngine {
        fn new() -> Self {
            Self {
                lr: Err(KernelErrno::UNIMPLEMENTED_SYSCALL),
                cr: Err(KernelErrno::UNIMPLEMENTED_SYSCALL),
                rr: Err(KernelErrno::UNIMPLEMENTED_SYSCALL),
                ur: Err(KernelErrno::UNIMPLEMENTED_SYSCALL),
                mkr: Err(KernelErrno::UNIMPLEMENTED_SYSCALL),
                rmr: Err(KernelErrno::UNIMPLEMENTED_SYSCALL),
                rdr: Err(KernelErrno::UNIMPLEMENTED_SYSCALL),
                slr: Err(KernelErrno::UNIMPLEMENTED_SYSCALL),
            }
        }
        fn with_lk(mut self, r: Result<InodeAttr, Errno>) -> Self {
            self.lr = r;
            self
        }
        fn with_cr(mut self, r: Result<(InodeAttr, EngineFileHandle), Errno>) -> Self {
            self.cr = r;
            self
        }
        fn with_rn(mut self, r: Result<(), Errno>) -> Self {
            self.rr = r;
            self
        }
        fn with_ul(mut self, r: Result<(), Errno>) -> Self {
            self.ur = r;
            self
        }
        fn with_mk(mut self, r: Result<InodeAttr, Errno>) -> Self {
            self.mkr = r;
            self
        }
        fn with_rm(mut self, r: Result<(), Errno>) -> Self {
            self.rmr = r;
            self
        }
        fn with_sl(mut self, r: Result<InodeAttr, Errno>) -> Self {
            self.slr = r;
            self
        }
        fn with_rd(mut self, r: Result<(Vec<DirEntry>, bool), Errno>) -> Self {
            self.rdr = r;
            self
        }
    }

    fn fa(ino: u64, size: u64) -> InodeAttr {
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
    fn da(ino: u64) -> InodeAttr {
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
    fn efh(ino: u64, id: u64) -> EngineFileHandle {
        EngineFileHandle {
            inode_id: InodeId::new(ino),
            open_flags: 0,
            fh_id: FileHandleId::new(id),
            lock_owner: 0,
        }
    }
    fn ctx() -> RequestCtx {
        RequestCtx {
            uid: 1000,
            gid: 1000,
            pid: 42,
            umask: 0o022,
            groups: crate::TideVec::from([1000].as_slice()),
        }
    }

    #[allow(unused_variables)]
    impl VfsEngine for MockEngine {
        fn get_root_inode(&self, c: &RequestCtx) -> Result<InodeId, Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn lookup(&self, p: InodeId, n: &[u8], c: &RequestCtx) -> Result<InodeAttr, Errno> {
            self.lr
        }
        fn getattr(
            &self,
            i: InodeId,
            h: Option<&EngineFileHandle>,
            c: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn setattr(
            &self,
            i: InodeId,
            a: &SetAttr,
            h: Option<&EngineFileHandle>,
            c: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn mkdir(&self, p: InodeId, n: &[u8], m: u32, c: &RequestCtx) -> Result<InodeAttr, Errno> {
            self.mkr
        }
        fn create(
            &self,
            p: InodeId,
            n: &[u8],
            m: u32,
            f: u32,
            c: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            self.cr
        }
        fn tmpfile(
            &self,
            p: InodeId,
            m: u32,
            f: u32,
            c: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn unlink(&self, p: InodeId, n: &[u8], c: &RequestCtx) -> Result<(), Errno> {
            self.ur
        }
        fn rmdir(&self, p: InodeId, n: &[u8], c: &RequestCtx) -> Result<(), Errno> {
            self.rmr
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
            self.rr
        }
        fn link(
            &self,
            t: InodeId,
            np: InodeId,
            nn: &[u8],
            c: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn symlink(
            &self,
            p: InodeId,
            n: &[u8],
            t: &[u8],
            c: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            self.slr
        }
        fn readlink(&self, i: InodeId, c: &RequestCtx) -> Result<Vec<u8>, Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn mknod(
            &self,
            p: InodeId,
            n: &[u8],
            m: u32,
            r: u32,
            c: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn open(&self, i: InodeId, f: u32, c: &RequestCtx) -> Result<EngineFileHandle, Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn release(&self, fh: &EngineFileHandle) -> Result<(), Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn read(
            &self,
            fh: &EngineFileHandle,
            o: u64,
            s: u32,
            c: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn write(
            &self,
            fh: &EngineFileHandle,
            o: u64,
            d: &[u8],
            c: &RequestCtx,
        ) -> Result<u32, Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn flush(&self, fh: &EngineFileHandle, c: &RequestCtx) -> Result<(), Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn fsync(&self, fh: &EngineFileHandle, ds: bool, c: &RequestCtx) -> Result<(), Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn fallocate(
            &self,
            fh: &EngineFileHandle,
            m: u32,
            o: u64,
            l: u64,
            c: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn opendir(&self, i: InodeId, c: &RequestCtx) -> Result<EngineDirHandle, Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn releasedir(&self, dh: &EngineDirHandle) -> Result<(), Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn readdir(
            &self,
            dh: &EngineDirHandle,
            o: u64,
            c: &RequestCtx,
        ) -> Result<(Vec<DirEntry>, bool), Errno> {
            self.rdr.clone()
        }
        fn fsyncdir(&self, dh: &EngineDirHandle, ds: bool, c: &RequestCtx) -> Result<(), Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn getxattr(&self, i: InodeId, n: &[u8], c: &RequestCtx) -> Result<Vec<u8>, Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn setxattr(
            &self,
            i: InodeId,
            n: &[u8],
            v: &[u8],
            f: u32,
            c: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn listxattr(&self, i: InodeId, c: &RequestCtx) -> Result<Vec<u8>, Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn removexattr(&self, i: InodeId, n: &[u8], c: &RequestCtx) -> Result<(), Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn getlk(
            &self,
            i: InodeId,
            l: &LockSpec,
            c: &RequestCtx,
        ) -> Result<Option<LockSpec>, Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn setlk(&self, i: InodeId, l: &LockSpec, c: &RequestCtx) -> Result<(), Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
    }

    #[test]
    fn lookup_found() {
        let a = fa(10, 4096);
        let e = MockEngine::new().with_lk(Ok(a));
        let r = bridge_lookup(&e, InodeId::new(1), b"f", &ctx()).unwrap();
        assert_eq!(r.inode_id, InodeId::new(10));
        assert_eq!(r.kind, NodeKind::File);
    }
    #[test]
    fn lookup_enoent() {
        let e = MockEngine::new().with_lk(Err(Errno::ENOENT));
        assert_eq!(
            bridge_lookup(&e, InodeId::new(1), b"nope", &ctx()).unwrap_err(),
            Errno::ENOENT
        );
    }
    #[test]
    fn lookup_dir_attr() {
        let a = da(5);
        let e = MockEngine::new().with_lk(Ok(a));
        let r = bridge_lookup(&e, InodeId::new(1), b"sub", &ctx()).unwrap();
        assert_eq!(r.kind, NodeKind::Dir);
    }
    #[test]
    fn lookup_long_name() {
        let n = vec![b'x'; 255];
        let a = fa(99, 1);
        let e = MockEngine::new().with_lk(Ok(a));
        let r = bridge_lookup(&e, InodeId::new(1), &n, &ctx()).unwrap();
        assert_eq!(r.inode_id, InodeId::new(99));
    }
    #[test]
    fn create_works() {
        let a = fa(20, 0);
        let h = efh(20, 1);
        let e = MockEngine::new().with_cr(Ok((a, h)));
        let (ra, rf) = bridge_create(&e, InodeId::new(2), b"f", 0o644, 0, &ctx()).unwrap();
        assert_eq!(ra.inode_id, InodeId::new(20));
        assert_eq!(rf.inode_id, InodeId::new(20));
    }
    #[test]
    fn create_eexist() {
        let e = MockEngine::new().with_cr(Err(Errno::EEXIST));
        assert_eq!(
            bridge_create(&e, InodeId::new(2), b"dup", 0o644, 0, &ctx()).unwrap_err(),
            Errno::EEXIST
        );
    }
    #[test]
    fn create_enospc() {
        let e = MockEngine::new().with_cr(Err(Errno::ENOSPC));
        assert_eq!(
            bridge_create(&e, InodeId::new(2), b"big", 0o644, 0, &ctx()).unwrap_err(),
            Errno::ENOSPC
        );
    }
    #[test]
    fn rename_simple() {
        let e = MockEngine::new().with_rn(Ok(()));
        bridge_rename(&e, InodeId::new(1), b"a", InodeId::new(2), b"b", 0, &ctx()).unwrap();
    }
    #[test]
    fn rename_noreplace() {
        let e = MockEngine::new().with_rn(Ok(()));
        bridge_rename(&e, InodeId::new(1), b"a", InodeId::new(1), b"b", 1, &ctx()).unwrap();
    }
    #[test]
    fn rename_exchange() {
        let e = MockEngine::new().with_rn(Ok(()));
        bridge_rename(&e, InodeId::new(1), b"a", InodeId::new(1), b"b", 2, &ctx()).unwrap();
    }
    #[test]
    fn rename_enoent() {
        let e = MockEngine::new().with_rn(Err(Errno::ENOENT));
        assert_eq!(
            bridge_rename(&e, InodeId::new(1), b"x", InodeId::new(2), b"y", 0, &ctx()).unwrap_err(),
            Errno::ENOENT
        );
    }
    #[test]
    fn rename_exdev() {
        let e = MockEngine::new().with_rn(Err(Errno::EXDEV));
        assert_eq!(
            bridge_rename(&e, InodeId::new(1), b"x", InodeId::new(2), b"y", 0, &ctx()).unwrap_err(),
            Errno::EXDEV
        );
    }
    #[test]
    fn rename_eisdir() {
        let e = MockEngine::new().with_rn(Err(Errno::EISDIR));
        assert_eq!(
            bridge_rename(&e, InodeId::new(1), b"f", InodeId::new(1), b"d", 0, &ctx()).unwrap_err(),
            Errno::EISDIR
        );
    }
    #[test]
    fn unlink_works() {
        let e = MockEngine::new().with_ul(Ok(()));
        bridge_unlink(&e, InodeId::new(2), b"f", &ctx()).unwrap();
    }
    #[test]
    fn unlink_enoent() {
        let e = MockEngine::new().with_ul(Err(Errno::ENOENT));
        assert_eq!(
            bridge_unlink(&e, InodeId::new(2), b"x", &ctx()).unwrap_err(),
            Errno::ENOENT
        );
    }
    #[test]
    fn unlink_eisdir() {
        let e = MockEngine::new().with_ul(Err(Errno::EISDIR));
        assert_eq!(
            bridge_unlink(&e, InodeId::new(2), b"d", &ctx()).unwrap_err(),
            Errno::EISDIR
        );
    }
    #[test]
    fn unlink_eacces() {
        let e = MockEngine::new().with_ul(Err(Errno::EACCES));
        assert_eq!(
            bridge_unlink(&e, InodeId::new(2), b"p", &ctx()).unwrap_err(),
            Errno::EACCES
        );
    }
    #[test]
    fn unlink_eperm() {
        let e = MockEngine::new().with_ul(Err(Errno::EPERM));
        assert_eq!(
            bridge_unlink(&e, InodeId::new(2), b"s", &ctx()).unwrap_err(),
            Errno::EPERM
        );
    }
    #[test]
    fn multi_op_sequence() {
        let a = fa(100, 0);
        let h = efh(100, 1);
        let (ra, _) = bridge_create(
            &MockEngine::new().with_cr(Ok((a, h))),
            InodeId::new(1),
            b"seq",
            0o644,
            0,
            &ctx(),
        )
        .unwrap();
        assert_eq!(ra.inode_id, InodeId::new(100));
        let r = bridge_lookup(
            &MockEngine::new().with_lk(Ok(a)),
            InodeId::new(1),
            b"seq",
            &ctx(),
        )
        .unwrap();
        assert_eq!(r.inode_id, InodeId::new(100));
        bridge_rename(
            &MockEngine::new().with_rn(Ok(())),
            InodeId::new(1),
            b"seq",
            InodeId::new(2),
            b"moved",
            0,
            &ctx(),
        )
        .unwrap();
        bridge_unlink(
            &MockEngine::new().with_ul(Ok(())),
            InodeId::new(2),
            b"moved",
            &ctx(),
        )
        .unwrap();
    }
    #[test]
    fn unlink_long_name() {
        let n = vec![b'x'; 255];
        let e = MockEngine::new().with_ul(Ok(()));
        bridge_unlink(&e, InodeId::new(5), &n, &ctx()).unwrap();
    }

    // ── bridge_readdir tests ──────────────────────────────────────

    fn edh(ino: u64, id: u64) -> EngineDirHandle {
        EngineDirHandle {
            inode_id: InodeId::new(ino),
            dh_id: DirHandleId::new(id),
        }
    }
    fn rde(ino: u64, name: &[u8], cookie: u64) -> DirEntry {
        DirEntry {
            name: name.to_vec(),
            inode_id: InodeId::new(ino),
            kind: NodeKind::File,
            generation: Generation::new(1),
            cookie,
        }
    }

    #[test]
    fn bridge_readdir_returns_entries() {
        let entries = vec![rde(10, b"a", 1), rde(20, b"b", 2)];
        let e = MockEngine::new().with_rd(Ok((entries.clone(), false)));
        let dh = edh(1, 1);
        let (r, more) = bridge_readdir(&e, &dh, 0, &ctx()).unwrap();
        assert_eq!(r.len(), 2);
        assert!(!more);
        assert_eq!(r[0].name, b"a");
        assert_eq!(r[1].name, b"b");
    }

    #[test]
    fn bridge_readdir_empty_directory() {
        let e = MockEngine::new().with_rd(Ok((vec![], false)));
        let dh = edh(1, 1);
        let (r, more) = bridge_readdir(&e, &dh, 0, &ctx()).unwrap();
        assert!(r.is_empty());
        assert!(!more);
    }

    #[test]
    fn bridge_readdir_more_flag() {
        let entries = vec![rde(10, b"first", 1)];
        let e = MockEngine::new().with_rd(Ok((entries, true)));
        let dh = edh(1, 1);
        let (r, more) = bridge_readdir(&e, &dh, 0, &ctx()).unwrap();
        assert_eq!(r.len(), 1);
        assert!(more);
    }

    #[test]
    fn bridge_readdir_offset_passed_through() {
        let entries = vec![rde(10, b"item", 5)];
        let e = MockEngine::new().with_rd(Ok((entries, false)));
        let dh = edh(1, 1);
        let (r, _) = bridge_readdir(&e, &dh, 42, &ctx()).unwrap();
        assert_eq!(r[0].cookie, 5);
    }

    #[test]
    fn bridge_readdir_eio_propagates() {
        let e = MockEngine::new().with_rd(Err(Errno::EIO));
        let dh = edh(1, 1);
        assert_eq!(bridge_readdir(&e, &dh, 0, &ctx()).unwrap_err(), Errno::EIO);
    }

    #[test]
    fn bridge_readdir_enotdir_propagates() {
        let e = MockEngine::new().with_rd(Err(Errno::ENOTDIR));
        let dh = edh(1, 1);
        assert_eq!(
            bridge_readdir(&e, &dh, 0, &ctx()).unwrap_err(),
            Errno::ENOTDIR
        );
    }
    #[test]
    fn rename_self_noop() {
        let e = MockEngine::new().with_rn(Ok(()));
        bridge_rename(&e, InodeId::new(5), b"s", InodeId::new(5), b"s", 0, &ctx()).unwrap();
    }
    #[test]
    fn dyn_engine_works() {
        let a = fa(10, 0);
        let e: &dyn VfsEngine = &MockEngine::new().with_lk(Ok(a));
        let r = bridge_lookup(e, InodeId::new(1), b"dyn", &ctx()).unwrap();
        assert_eq!(r.inode_id, InodeId::new(10));
    }

    // -- bridge_mkdir tests ---

    #[test]
    fn mkdir_bridge_works() {
        let a = da(50);
        let e = MockEngine::new().with_mk(Ok(a));
        let r = bridge_mkdir(&e, InodeId::new(2), b"newdir", 0o755, &ctx()).unwrap();
        assert_eq!(r.inode_id, InodeId::new(50));
        assert_eq!(r.kind, NodeKind::Dir);
    }

    #[test]
    fn mkdir_bridge_eexist() {
        let e = MockEngine::new().with_mk(Err(Errno::EEXIST));
        assert_eq!(
            bridge_mkdir(&e, InodeId::new(2), b"dup", 0o755, &ctx()).unwrap_err(),
            Errno::EEXIST
        );
    }

    #[test]
    fn mkdir_bridge_enospc() {
        let e = MockEngine::new().with_mk(Err(Errno::ENOSPC));
        assert_eq!(
            bridge_mkdir(&e, InodeId::new(2), b"full", 0o755, &ctx()).unwrap_err(),
            Errno::ENOSPC
        );
    }

    #[test]
    fn mkdir_bridge_mode_preserved() {
        let e = MockEngine::new().with_mk(Ok(da(50)));
        let r = bridge_mkdir(&e, InodeId::new(2), b"mode", 0o700, &ctx()).unwrap();
        assert_eq!(r.inode_id, InodeId::new(50));
    }

    // -- bridge_rmdir tests ---

    #[test]
    fn rmdir_bridge_works() {
        let e = MockEngine::new().with_rm(Ok(()));
        bridge_rmdir(&e, InodeId::new(2), b"subdir", &ctx()).unwrap();
    }

    #[test]
    fn rmdir_bridge_enotempty() {
        let e = MockEngine::new().with_rm(Err(Errno::ENOTEMPTY));
        assert_eq!(
            bridge_rmdir(&e, InodeId::new(2), b"full", &ctx()).unwrap_err(),
            Errno::ENOTEMPTY
        );
    }

    #[test]
    fn rmdir_bridge_enoent() {
        let e = MockEngine::new().with_rm(Err(Errno::ENOENT));
        assert_eq!(
            bridge_rmdir(&e, InodeId::new(2), b"nope", &ctx()).unwrap_err(),
            Errno::ENOENT
        );
    }

    #[test]
    fn rmdir_bridge_eacces() {
        let e = MockEngine::new().with_rm(Err(Errno::EACCES));
        assert_eq!(
            bridge_rmdir(&e, InodeId::new(2), b"locked", &ctx()).unwrap_err(),
            Errno::EACCES
        );
    }

    // -- bridge_symlink tests ---

    #[test]
    fn symlink_bridge_works() {
        let a = da(80);
        let e = MockEngine::new().with_sl(Ok(a));
        let r = bridge_symlink(&e, InodeId::new(2), b"mylink", b"/target", &ctx()).unwrap();
        assert_eq!(r.inode_id, InodeId::new(80));
    }

    #[test]
    fn symlink_bridge_eexist() {
        let e = MockEngine::new().with_sl(Err(Errno::EEXIST));
        assert_eq!(
            bridge_symlink(&e, InodeId::new(2), b"dup", b"/t", &ctx()).unwrap_err(),
            Errno::EEXIST
        );
    }

    #[test]
    fn symlink_bridge_enospc() {
        let e = MockEngine::new().with_sl(Err(Errno::ENOSPC));
        assert_eq!(
            bridge_symlink(&e, InodeId::new(2), b"full", b"/t", &ctx()).unwrap_err(),
            Errno::ENOSPC
        );
    }

    #[test]
    fn symlink_bridge_preserves_args() {
        let e = MockEngine::new().with_sl(Ok(da(80)));
        let r = bridge_symlink(&e, InodeId::new(2), b"link", b"/target/path", &ctx()).unwrap();
        assert_eq!(r.inode_id, InodeId::new(80));
    }

    #[test]
    fn symlink_bridge_long_target() {
        let t = vec![b'x'; 4096];
        let e = MockEngine::new().with_sl(Ok(da(99)));
        let r = bridge_symlink(&e, InodeId::new(2), b"link", &t, &ctx()).unwrap();
        assert_eq!(r.inode_id, InodeId::new(99));
    }
}
