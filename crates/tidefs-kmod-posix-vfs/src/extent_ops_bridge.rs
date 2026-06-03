//! Extent operations bridge — canonical kernel extent allocation entry point.
//!
//! Provides the `bridge_allocate_extents` function that translates kernel
//! VFS extent allocation dispatch parameters into VfsEngine calls. This is
//! a pure delegation wrapper without BLAKE3 attestation, serving as the
//! production kernel extent-provisioning surface.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use tidefs_kmod_bridge::kernel_types::{AllocateExtentsOutcome, VfsEngine};
use tidefs_kmod_bridge::kernel_types::{Errno, InodeId, RequestCtx};

/// Delegate extent allocation to the [`VfsEngine`].
///
/// Provisions `length` bytes of new backing storage starting at `offset`
/// for `inode`. The engine records the allocation in the intent log
/// for crash-safety.
///
/// # Errors
/// - `ENOSPC`: no free space
/// - `EIO`: storage error
/// - `EBADF`: inode does not exist
/// - `EINVAL`: invalid offset/length
pub fn bridge_allocate_extents<E: VfsEngine + ?Sized>(
    engine: &E,
    inode: InodeId,
    offset: u64,
    length: u64,
    ctx: &RequestCtx,
) -> Result<AllocateExtentsOutcome, Errno> {
    engine.allocate_extents(inode, offset, length, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::KernelErrno;
    use crate::TideVec as Vec;
    use tidefs_kmod_bridge::kernel_types::{
        AllocateExtentsOutcome, WritebackOutcome, WritebackRange,
    };
    use tidefs_kmod_bridge::kernel_types::{
        DirEntry, EngineDirHandle, EngineFileHandle, InodeAttr, LockSpec, SetAttr,
    };

    struct MockEngine {
        result: Result<AllocateExtentsOutcome, Errno>,
    }

    #[allow(unused_variables)]
    impl VfsEngine for MockEngine {
        fn get_root_inode(&self, ctx: &RequestCtx) -> Result<InodeId, Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn lookup(&self, p: InodeId, n: &[u8], c: &RequestCtx) -> Result<InodeAttr, Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
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
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn create(
            &self,
            p: InodeId,
            n: &[u8],
            m: u32,
            f: u32,
            c: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn create_excl(
            &self,
            p: InodeId,
            n: &[u8],
            m: u32,
            f: u32,
            c: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
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
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }
        fn rmdir(&self, p: InodeId, n: &[u8], c: &RequestCtx) -> Result<(), Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
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
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
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
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
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
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
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
        fn writeback_folios(
            &self,
            i: InodeId,
            fh: &EngineFileHandle,
            r: WritebackRange,
            c: &RequestCtx,
        ) -> Result<WritebackOutcome, Errno> {
            Err(KernelErrno::UNIMPLEMENTED_SYSCALL)
        }

        fn allocate_extents(
            &self,
            _inode: InodeId,
            _offset: u64,
            _length: u64,
            _ctx: &RequestCtx,
        ) -> Result<AllocateExtentsOutcome, Errno> {
            self.result
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

    #[test]
    fn bridge_allocate_works() {
        let engine = MockEngine {
            result: Ok(AllocateExtentsOutcome::new(4096, true)),
        };
        let outcome = bridge_allocate_extents(&engine, InodeId::new(10), 0, 8192, &ctx()).unwrap();
        assert_eq!(outcome.bytes_allocated, 4096);
        assert!(outcome.complete);
    }

    #[test]
    fn bridge_allocate_partial() {
        let engine = MockEngine {
            result: Ok(AllocateExtentsOutcome::new(2048, false)),
        };
        let outcome = bridge_allocate_extents(&engine, InodeId::new(10), 0, 8192, &ctx()).unwrap();
        assert_eq!(outcome.bytes_allocated, 2048);
        assert!(!outcome.complete);
    }

    #[test]
    fn bridge_allocate_enospc() {
        let engine = MockEngine {
            result: Err(KernelErrno::SPACE_EXHAUSTED),
        };
        assert_eq!(
            bridge_allocate_extents(&engine, InodeId::new(10), 0, 4096, &ctx()).unwrap_err(),
            KernelErrno::SPACE_EXHAUSTED,
        );
    }

    #[test]
    fn bridge_allocate_eio() {
        let engine = MockEngine {
            result: Err(KernelErrno::STORAGE_IO),
        };
        assert_eq!(
            bridge_allocate_extents(&engine, InodeId::new(10), 0, 4096, &ctx()).unwrap_err(),
            KernelErrno::STORAGE_IO,
        );
    }

    #[test]
    fn bridge_allocate_ebadf() {
        let engine = MockEngine {
            result: Err(KernelErrno::INVALID_FILE_DESCRIPTOR),
        };
        assert_eq!(
            bridge_allocate_extents(&engine, InodeId::new(99), 0, 4096, &ctx()).unwrap_err(),
            KernelErrno::INVALID_FILE_DESCRIPTOR,
        );
    }

    #[test]
    fn bridge_allocate_einval() {
        let engine = MockEngine {
            result: Err(KernelErrno::INVALID_ARGUMENT),
        };
        assert_eq!(
            bridge_allocate_extents(&engine, InodeId::new(10), u64::MAX, 4096, &ctx()).unwrap_err(),
            KernelErrno::INVALID_ARGUMENT,
        );
    }

    #[test]
    fn bridge_allocate_zero_bytes() {
        let engine = MockEngine {
            result: Ok(AllocateExtentsOutcome::new(0, false)),
        };
        let outcome = bridge_allocate_extents(&engine, InodeId::new(10), 0, 0, &ctx()).unwrap();
        assert_eq!(outcome.bytes_allocated, 0);
        assert!(!outcome.complete);
    }
}
