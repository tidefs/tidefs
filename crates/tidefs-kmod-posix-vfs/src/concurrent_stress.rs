//! Concurrent operation safety stress tests for the kernel VFS adapter.
//!
//! Exercises concurrent create/write/rename/unlink/fsync through the
//! KmodPosixVfs dispatch spine under multi-threaded contention (mutex-
//! serialized to simulate kernel VFS lock serialization).
//!
//! These tests run in cargo mode (not Kbuild); the kernel runtime
//! equivalent must be validated through a QEMU lockdep-enabled guest.

#[cfg(test)]
mod tests {
    extern crate std;
    use alloc::format;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;
    use std::thread;

    use crate::KmodPosixVfs;
    use tidefs_kmod_bridge::kernel_types::DirHandleId;
    use tidefs_kmod_bridge::kernel_types::{
        AllocateExtentsOutcome, DirEntry, EngineDirHandle, EngineFileHandle, Errno, FileHandleId,
        Generation, InodeAttr, InodeFlags, InodeId, LockSpec, NodeKind, PosixAttrs, RequestCtx,
        StatFs, VfsEngine, VfsEngineStatFs, WritebackOutcome, WritebackRange,
    };

    struct SyncTestEngine {
        create_count: Arc<AtomicU64>,
        write_count: Arc<AtomicU64>,
        fsync_count: Arc<AtomicU64>,
        rename_count: Arc<AtomicU64>,
        unlink_count: Arc<AtomicU64>,
        next_ino: Arc<AtomicU64>,
        next_fh: Arc<AtomicU64>,
    }

    impl SyncTestEngine {
        fn new() -> Self {
            Self {
                create_count: Arc::new(AtomicU64::new(0)),
                write_count: Arc::new(AtomicU64::new(0)),
                fsync_count: Arc::new(AtomicU64::new(0)),
                rename_count: Arc::new(AtomicU64::new(0)),
                unlink_count: Arc::new(AtomicU64::new(0)),
                next_ino: Arc::new(AtomicU64::new(100)),
                next_fh: Arc::new(AtomicU64::new(1)),
            }
        }
    }

    fn make_attr(ino: u64, kind: NodeKind) -> InodeAttr {
        InodeAttr::new(
            InodeId::new(ino),
            Generation::new(0),
            kind,
            PosixAttrs {
                mode: 0o644,
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
            InodeFlags::none(),
            0,
            0,
        )
    }

    fn make_fh(ino: u64, fh_id: u64) -> EngineFileHandle {
        EngineFileHandle {
            inode_id: InodeId::new(ino),
            open_flags: 0,
            fh_id: FileHandleId::new(fh_id),
            lock_owner: 0,
        }
    }

    impl VfsEngine for SyncTestEngine {
        fn get_root_inode(&self, _ctx: &RequestCtx) -> Result<InodeId, Errno> {
            Ok(InodeId::new(0))
        }
        fn lookup(
            &self,
            _parent: InodeId,
            _name: &[u8],
            _ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOENT)
        }
        fn getattr(
            &self,
            _inode: InodeId,
            _handle: Option<&EngineFileHandle>,
            _ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Ok(make_attr(0, NodeKind::Dir))
        }
        fn setattr(
            &self,
            inode: InodeId,
            _attr: &tidefs_kmod_bridge::kernel_types::SetAttr,
            _handle: Option<&EngineFileHandle>,
            _ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Ok(make_attr(inode.0, NodeKind::File))
        }
        fn mkdir(
            &self,
            _parent: InodeId,
            _name: &[u8],
            _mode: u32,
            _ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            let ino = self.next_ino.fetch_add(1, Ordering::Relaxed);
            Ok(make_attr(ino, NodeKind::Dir))
        }
        fn create(
            &self,
            _parent: InodeId,
            _name: &[u8],
            _mode: u32,
            _flags: u32,
            _ctx: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            self.create_count.fetch_add(1, Ordering::Relaxed);
            let ino = self.next_ino.fetch_add(1, Ordering::Relaxed);
            let fh_id = self.next_fh.fetch_add(1, Ordering::Relaxed);
            let attr = make_attr(ino, NodeKind::File);
            let fh = make_fh(ino, fh_id);
            Ok((attr, fh))
        }
        fn tmpfile(
            &self,
            parent: InodeId,
            mode: u32,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            self.create(parent, &[], mode, flags, ctx)
        }
        fn unlink(&self, _parent: InodeId, _name: &[u8], _ctx: &RequestCtx) -> Result<(), Errno> {
            self.unlink_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn rmdir(&self, _parent: InodeId, _name: &[u8], _ctx: &RequestCtx) -> Result<(), Errno> {
            Ok(())
        }
        fn rename(
            &self,
            _old_parent: InodeId,
            _old_name: &[u8],
            _new_parent: InodeId,
            _new_name: &[u8],
            _flags: u32,
            _ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            self.rename_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn link(
            &self,
            _t: InodeId,
            _np: InodeId,
            _nn: &[u8],
            _ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn symlink(
            &self,
            _p: InodeId,
            _n: &[u8],
            _t: &[u8],
            _ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn readlink(&self, _i: InodeId, _ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }
        fn mknod(
            &self,
            _p: InodeId,
            _n: &[u8],
            _m: u32,
            _r: u32,
            _ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn open(
            &self,
            inode: InodeId,
            _flags: u32,
            _ctx: &RequestCtx,
        ) -> Result<EngineFileHandle, Errno> {
            let fh_id = self.next_fh.fetch_add(1, Ordering::Relaxed);
            Ok(make_fh(inode.0, fh_id))
        }
        fn release(&self, _fh: &EngineFileHandle) -> Result<(), Errno> {
            Ok(())
        }
        fn read(
            &self,
            _fh: &EngineFileHandle,
            _offset: u64,
            _size: u32,
            _ctx: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            Ok(Vec::new())
        }
        fn write(
            &self,
            _fh: &EngineFileHandle,
            _offset: u64,
            data: &[u8],
            _ctx: &RequestCtx,
        ) -> Result<u32, Errno> {
            self.write_count.fetch_add(1, Ordering::Relaxed);
            Ok(data.len() as u32)
        }
        fn flush(&self, _fh: &EngineFileHandle, _ctx: &RequestCtx) -> Result<(), Errno> {
            Ok(())
        }
        fn fsync(
            &self,
            _fh: &EngineFileHandle,
            _datasync: bool,
            _ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            self.fsync_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn fallocate(
            &self,
            _fh: &EngineFileHandle,
            _m: u32,
            _o: u64,
            _l: u64,
            _ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn readahead(
            &self,
            _fh: &EngineFileHandle,
            _o: u64,
            _l: u32,
            _ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Ok(())
        }
        fn opendir(&self, inode: InodeId, _ctx: &RequestCtx) -> Result<EngineDirHandle, Errno> {
            Ok(EngineDirHandle {
                inode_id: inode,
                dh_id: DirHandleId::new(inode.0),
            })
        }
        fn releasedir(&self, _dh: &EngineDirHandle) -> Result<(), Errno> {
            Ok(())
        }
        fn readdir(
            &self,
            _dh: &EngineDirHandle,
            _offset: u64,
            _ctx: &RequestCtx,
        ) -> Result<(Vec<DirEntry>, bool), Errno> {
            Ok((Vec::new(), false))
        }
        fn fsyncdir(
            &self,
            _dh: &EngineDirHandle,
            _datasync: bool,
            _ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Ok(())
        }
        fn getxattr(&self, _i: InodeId, _n: &[u8], _ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENODATA)
        }
        fn setxattr(
            &self,
            _i: InodeId,
            _n: &[u8],
            _v: &[u8],
            _f: u32,
            _ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn listxattr(&self, _i: InodeId, _ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
            Ok(Vec::new())
        }
        fn removexattr(&self, _i: InodeId, _n: &[u8], _ctx: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn getlk(
            &self,
            _i: InodeId,
            _l: &LockSpec,
            _ctx: &RequestCtx,
        ) -> Result<Option<LockSpec>, Errno> {
            Ok(None)
        }
        fn setlk(&self, _i: InodeId, _l: &LockSpec, _ctx: &RequestCtx) -> Result<(), Errno> {
            Ok(())
        }
        fn writeback_folios(
            &self,
            _i: InodeId,
            _fh: &EngineFileHandle,
            _r: WritebackRange,
            _ctx: &RequestCtx,
        ) -> Result<WritebackOutcome, Errno> {
            Ok(WritebackOutcome {
                bytes_written: 0,
                complete: false,
            })
        }
        fn allocate_extents(
            &self,
            _i: InodeId,
            _o: u64,
            _l: u64,
            _ctx: &RequestCtx,
        ) -> Result<AllocateExtentsOutcome, Errno> {
            Ok(AllocateExtentsOutcome {
                bytes_allocated: 0,
                complete: false,
            })
        }
        fn syncfs(&self, _ctx: &RequestCtx) -> Result<(), Errno> {
            Ok(())
        }
    }

    impl VfsEngineStatFs for SyncTestEngine {
        fn statfs(&self, _ctx: &RequestCtx) -> Result<StatFs, Errno> {
            Ok(StatFs::new(
                4096, 4096, 1_000_000, 900_000, 900_000, 1_000_000, 900_000, 255, 0, 0,
            ))
        }
    }

    fn test_ctx() -> RequestCtx {
        RequestCtx::default()
    }

    // ── Concurrent stress tests ────────────────────────────────────────

    #[test]
    fn concurrent_create_write_fsync_stress() {
        let engine = SyncTestEngine::new();
        let vfs = Arc::new(Mutex::new(KmodPosixVfs::new(engine)));
        let thread_count = 4;
        let ops_per_thread = 50;
        let mut handles = Vec::new();
        for t in 0..thread_count {
            let vfs = Arc::clone(&vfs);
            handles.push(thread::spawn(move || {
                let ctx = test_ctx();
                for i in 0..ops_per_thread {
                    let parent = InodeId::new(1);
                    let name = format!("f-{t}-{i}");
                    let mut guard = vfs.lock().unwrap();
                    let (_plan, state) = match guard.create(parent, name.as_bytes(), 0o644, 0, &ctx)
                    {
                        Ok(r) => r,
                        Err(_) => continue,
                    };
                    let wdata = format!("data-{t}-{i}");
                    let _ = guard.write(&state.handle, 0, wdata.as_bytes(), &ctx);
                    let _ = guard.fsync(&state.handle, false, &ctx);
                    drop(guard);
                }
            }));
        }
        for h in handles {
            h.join().expect("thread should not panic");
        }
    }

    #[test]
    fn concurrent_rename_unlink_stress() {
        let engine = SyncTestEngine::new();
        let vfs = Arc::new(Mutex::new(KmodPosixVfs::new(engine)));
        let thread_count = 4;
        let ops_per_thread = 30;
        let ctx = test_ctx();
        {
            let guard = vfs.lock().unwrap();
            for t in 0..thread_count {
                for i in 0..ops_per_thread {
                    let parent = InodeId::new(1);
                    let name = format!("pre-{t}-{i}");
                    let _ = guard.create(parent, name.as_bytes(), 0o644, 0, &ctx);
                }
            }
        }
        let mut handles = Vec::new();
        for t in 0..thread_count {
            let vfs = Arc::clone(&vfs);
            handles.push(thread::spawn(move || {
                let ctx = test_ctx();
                for i in 0..ops_per_thread {
                    let parent = InodeId::new(1);
                    let old_name = format!("pre-{t}-{i}");
                    let new_name = format!("renamed-{t}-{i}");
                    let guard = vfs.lock().unwrap();
                    let _ = guard.rename(
                        parent,
                        old_name.as_bytes(),
                        parent,
                        new_name.as_bytes(),
                        0,
                        &ctx,
                    );
                    let _ = guard.unlink(parent, new_name.as_bytes(), &ctx);
                    drop(guard);
                }
            }));
        }
        for h in handles {
            h.join().expect("thread should not panic");
        }
    }

    #[test]
    fn concurrent_mixed_operation_stress() {
        let engine = SyncTestEngine::new();
        let vfs = Arc::new(Mutex::new(KmodPosixVfs::new(engine)));
        let thread_count = 8;
        let ops_per_thread = 40;
        let mut handles = Vec::new();
        for t in 0..thread_count {
            let vfs = Arc::clone(&vfs);
            handles.push(thread::spawn(move || {
                let ctx = test_ctx();
                for i in 0..ops_per_thread {
                    let parent = InodeId::new(1);
                    let name = format!("mix-{t}-{i}");
                    let mut guard = vfs.lock().unwrap();
                    let (plan, state) = match guard.create(parent, name.as_bytes(), 0o644, 0, &ctx)
                    {
                        Ok(r) => r,
                        Err(_) => continue,
                    };
                    let wdata = format!("data-{t}-{i}");
                    let _ = guard.write(&state.handle, 0, wdata.as_bytes(), &ctx);
                    let _ = guard.fsync(&state.handle, false, &ctx);
                    let new_name = format!("r-{t}-{i}");
                    let _ = guard.rename(
                        parent,
                        name.as_bytes(),
                        parent,
                        new_name.as_bytes(),
                        0,
                        &ctx,
                    );
                    let _ = guard.getattr(plan.attr.inode_id, None, &ctx);
                    let _ = guard.unlink(parent, new_name.as_bytes(), &ctx);
                    drop(guard);
                }
            }));
        }
        for h in handles {
            h.join().expect("thread should not panic");
        }
    }

    #[test]
    fn concurrent_create_contention_stress() {
        let engine = SyncTestEngine::new();
        let cc = Arc::clone(&engine.create_count);
        let vfs = Arc::new(Mutex::new(KmodPosixVfs::new(engine)));
        let thread_count = 8;
        let ops_per_thread = 25;
        let mut handles = Vec::new();
        for t in 0..thread_count {
            let vfs = Arc::clone(&vfs);
            handles.push(thread::spawn(move || {
                let ctx = test_ctx();
                for i in 0..ops_per_thread {
                    let parent = InodeId::new(1);
                    let name = format!("contend-{t}-{i}");
                    let guard = vfs.lock().unwrap();
                    let _ = guard.create(parent, name.as_bytes(), 0o644, 0, &ctx);
                    drop(guard);
                }
            }));
        }
        for h in handles {
            h.join().expect("thread should not panic");
        }
        let expected = (thread_count * ops_per_thread) as u64;
        assert_eq!(cc.load(Ordering::Relaxed), expected);
    }
}
