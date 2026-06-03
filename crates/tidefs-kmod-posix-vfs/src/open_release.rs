//! Open / release bridge — kernel file_operations open/release dispatch.
//!
//! Provides no_std-compatible bridge functions that translate kernel VFS
//! `file_operations::open` and `file_operations::release` parameters into
//! VfsEngine calls. These functions are pure delegation wrappers without BLAKE3 attestation,
//! serving as the production kernel per-file session
//! lifecycle surface.
//!
//! ## Kernel wiring
//!
//! During inode creation (`fill_super` / `inode_init_always`), the kernel
//! module sets the inode's file_operations vtable where:
//!
//! - `file_operations::open` → `bridge_open()`
//! - `file_operations::release` → `bridge_release()`
//!
//! The returned [`FileSession`] is stored in `file->private_data` by the
//! kernel VFS and passed back on subsequent `read`, `write`, `fsync`,
//! `fallocate`, `flush`, `llseek`, and `release` calls.
//!
//! ## No-daemon boundary
//!
//! Both open and release resolve locally within kernel authority through
//! VfsEngine. No userspace daemon or helper process is required.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::OpenFileState;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{Errno, InodeId, RequestCtx};
/// Linux O_DIRECT open(2) flag value.
///
/// O_DIRECT bypasses the page cache entirely, directing I/O straight
/// to the backing storage. The kernel VFS detects this flag during open
/// and routes read/write through `generic_file_direct_io`.
///
/// Value per Linux <fcntl.h>: `O_DIRECT = 00040000` (= 0x4000).
pub const O_DIRECT: u32 = 0o40000;

/// Check whether the given open(2) flags include O_DIRECT.
///
/// Returns true when the caller requested direct I/O, which bypasses
/// the kernel page cache and requires storage-adapter direct-I/O support.
///
/// The returned bool is used by the O_DIRECT validation module
/// to verify flag propagation through VfsEngine dispatch during open.
#[inline]
pub fn has_odirect_flag(flags: u32) -> bool {
    flags & O_DIRECT != 0
}

/// Linux O_DSYNC open(2) flag value (0x1000 = __O_DSYNC).
///
/// O_DSYNC causes every write(2) to implicitly perform a data-only sync
/// (fdatasync) before returning. Metadata not required for data retrieval
/// (e.g., atime) is not flushed.
pub const O_DSYNC: u32 = 0o10000;

/// Core bit of the Linux O_SYNC flag (__O_SYNC, 0x100000).
///
/// On Linux, O_SYNC = __O_SYNC | O_DSYNC, so the presence of __O_SYNC
/// (not just O_DSYNC) determines whether full-file-sync semantics apply.
/// This constant isolates the __O_SYNC bit for detection purposes.
const O_SYNC_CORE: u32 = 0o4000000;

/// Linux O_SYNC open(2) flag value (0x101000 = __O_SYNC | O_DSYNC).
///
/// O_SYNC causes every write(2) to implicitly perform a full fsync(2)
/// (data + metadata) before returning.
pub const O_SYNC: u32 = O_SYNC_CORE | O_DSYNC;

/// Check whether the given open(2) flags include O_SYNC semantics.
///
/// Tests the __O_SYNC core bit (0x100000), not the combined O_SYNC constant,
/// because Linux defines O_SYNC = __O_SYNC | O_DSYNC. This avoids a false
/// positive when only O_DSYNC is set.
#[inline]
pub fn has_osync_flag(flags: u32) -> bool {
    flags & O_SYNC_CORE != 0
}

/// Check whether the given open(2) flags include O_DSYNC.
///
/// Returns true when the caller requested data-synchronous write semantics:
/// every write(2) must perform an implicit fdatasync before returning.
/// When O_SYNC is also set, the stronger O_SYNC semantics take precedence.
#[inline]
pub fn has_odsync_flag(flags: u32) -> bool {
    flags & O_DSYNC != 0
}

/// Check whether any per-write sync flag (O_SYNC or O_DSYNC) is set.
///
/// Used by the write path to determine whether an implicit fsync/fdatasync
/// must follow a completed write.
#[inline]
pub fn has_any_sync_flag(flags: u32) -> bool {
    flags & (O_SYNC_CORE | O_DSYNC) != 0
}

/// Per-open-file session state stored in kernel `file->private_data`.
///
/// Carries the VfsEngine file handle, the inode this file was opened on,
/// and the open(2) flags. This is the canonical kernel-side representation
/// of an open-file session.
pub type FileSession = OpenFileState;

/// Bridge kernel `file_operations::open` to [`VfsEngine::open`].
///
/// Resolves the kernel inode to a VfsEngine inode identifier, calls
/// [`VfsEngine::open`] to acquire a file handle, and returns a
/// [`FileSession`] that the kernel VFS stores in `file->private_data`.
///
/// # Errors
/// Propagates engine errors directly: `ENOENT`, `EACCES`, `ENOMEM`,
/// `EIO`, and any other engine refusal.
pub fn bridge_open<E: VfsEngine + ?Sized>(
    engine: &E,
    inode: InodeId,
    flags: u32,
    ctx: &RequestCtx,
) -> Result<FileSession, Errno> {
    let handle = engine.open(inode, flags, ctx)?;
    Ok(FileSession {
        handle,
        inode,
        flags,
    })
}

/// Bridge kernel `file_operations::release` to [`VfsEngine::release`].
///
/// Extracts the [`FileSession`] from `file->private_data`, calls
/// [`VfsEngine::release`] to release the engine file handle, and
/// returns. After this call, the `FileSession` is deallocated by the
/// kernel VFS.
///
/// # Errors
/// Propagates engine errors directly: `EIO` for I/O failure during
/// release cleanup, or any other engine refusal. The kernel VFS
/// continues teardown regardless of error.
pub fn bridge_release<E: VfsEngine + ?Sized>(
    engine: &E,
    session: &FileSession,
) -> Result<(), Errno> {
    engine.release(&session.handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::KernelErrno;
    use crate::TideVec as Vec;
    use tidefs_kmod_bridge::kernel_types::{
        DirEntry, EngineDirHandle, EngineFileHandle, FileHandleId, InodeAttr, LockSpec, SetAttr,
    };

    struct MockEngine {
        open_result: Result<EngineFileHandle, Errno>,
        release_result: Result<(), Errno>,
    }

    impl MockEngine {
        fn new() -> Self {
            Self {
                open_result: Err(KernelErrno::UNIMPLEMENTED_SYSCALL),
                release_result: Err(KernelErrno::UNIMPLEMENTED_SYSCALL),
            }
        }

        fn with_open(mut self, r: Result<EngineFileHandle, Errno>) -> Self {
            self.open_result = r;
            self
        }

        fn with_release(mut self, r: Result<(), Errno>) -> Self {
            self.release_result = r;
            self
        }
    }

    fn fh(ino: u64, id: u64, flags: u32) -> EngineFileHandle {
        EngineFileHandle::new(InodeId::new(ino), flags, FileHandleId::new(id), 0)
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
            self.open_result
        }
        fn release(&self, fh: &EngineFileHandle) -> Result<(), Errno> {
            self.release_result
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
    }

    // -- bridge_open tests -----------------------------------------------

    #[test]
    fn bridge_open_works() {
        let handle = fh(10, 1, 0o100644);
        let e = MockEngine::new().with_open(Ok(handle));
        let session = bridge_open(&e, InodeId::new(10), 0o100644, &ctx()).unwrap();
        assert_eq!(session.inode, InodeId::new(10));
        assert_eq!(session.flags, 0o100644);
        assert_eq!(session.handle, handle);
    }

    #[test]
    fn bridge_open_readonly_flag() {
        let handle = fh(20, 2, 0);
        let e = MockEngine::new().with_open(Ok(handle));
        let session = bridge_open(&e, InodeId::new(20), 0, &ctx()).unwrap();
        assert_eq!(session.flags, 0);
        assert_eq!(session.inode, InodeId::new(20));
    }

    #[test]
    fn bridge_open_o_append_flag() {
        let handle = fh(30, 3, 0o2000);
        let e = MockEngine::new().with_open(Ok(handle));
        let session = bridge_open(&e, InodeId::new(30), 0o2000, &ctx()).unwrap();
        assert_eq!(session.flags, 0o2000);
    }

    // -- O_DIRECT flag tests --------------------------------------------

    #[test]
    fn odirect_flag_constant_correct() {
        assert_eq!(O_DIRECT, 0x4000_u32);
    }

    #[test]
    fn has_odirect_flag_set() {
        let flags = O_DIRECT | 0o100644;
        assert!(has_odirect_flag(flags));
    }

    #[test]
    fn has_odirect_flag_unset() {
        assert!(!has_odirect_flag(0o100644));
        assert!(!has_odirect_flag(0));
        assert!(!has_odirect_flag(0o2000)); // O_APPEND only
    }

    #[test]
    fn bridge_open_odirect_flag_preserved() {
        let handle = fh(50, 5, O_DIRECT);
        let e = MockEngine::new().with_open(Ok(handle));
        let session = bridge_open(&e, InodeId::new(50), O_DIRECT, &ctx()).unwrap();
        assert!(has_odirect_flag(session.flags));
    }

    #[test]
    fn bridge_open_odirect_with_other_flags() {
        let flags = O_DIRECT | 0o100644;
        let handle = fh(60, 6, flags);
        let e = MockEngine::new().with_open(Ok(handle));
        let session = bridge_open(&e, InodeId::new(60), flags, &ctx()).unwrap();
        assert!(has_odirect_flag(session.flags));
        assert_eq!(session.flags & O_DIRECT, O_DIRECT);
    }

    // -- O_SYNC flag tests ----------------------------------------------

    #[test]
    fn osync_flag_constant_correct() {
        assert_eq!(O_SYNC, 0x101000_u32);
    }

    #[test]
    fn has_osync_flag_set() {
        assert!(has_osync_flag(O_SYNC));
        assert!(has_osync_flag(O_SYNC | 0o100644));
    }

    #[test]
    fn has_osync_flag_unset() {
        assert!(!has_osync_flag(0o100644));
        assert!(!has_osync_flag(O_DSYNC));
        assert!(!has_osync_flag(0));
    }

    #[test]
    fn bridge_open_osync_flag_preserved() {
        let handle = fh(70, 7, O_SYNC);
        let e = MockEngine::new().with_open(Ok(handle));
        let session = bridge_open(&e, InodeId::new(70), O_SYNC, &ctx()).unwrap();
        assert!(has_osync_flag(session.flags));
    }

    // -- O_DSYNC flag tests ---------------------------------------------

    #[test]
    fn odsync_flag_constant_correct() {
        assert_eq!(O_DSYNC, 0x1000_u32);
    }

    #[test]
    fn has_odsync_flag_set() {
        assert!(has_odsync_flag(O_DSYNC));
        assert!(has_odsync_flag(O_DSYNC | 0o100644));
    }

    #[test]
    fn has_odsync_flag_unset() {
        assert!(!has_odsync_flag(0o100644));
        assert!(!has_odsync_flag(0));
    }

    #[test]
    fn bridge_open_odsync_flag_preserved() {
        let handle = fh(80, 8, O_DSYNC);
        let e = MockEngine::new().with_open(Ok(handle));
        let session = bridge_open(&e, InodeId::new(80), O_DSYNC, &ctx()).unwrap();
        assert!(has_odsync_flag(session.flags));
    }

    // -- Combined flag tests --------------------------------------------

    #[test]
    fn has_any_sync_flag_detects_osync() {
        assert!(has_any_sync_flag(O_SYNC));
    }

    #[test]
    fn has_any_sync_flag_detects_odsync() {
        assert!(has_any_sync_flag(O_DSYNC));
    }

    #[test]
    fn has_any_sync_flag_detects_both() {
        assert!(has_any_sync_flag(O_SYNC | O_DSYNC));
    }

    #[test]
    fn has_any_sync_flag_none() {
        assert!(!has_any_sync_flag(0o100644));
        assert!(!has_any_sync_flag(O_DIRECT));
        assert!(!has_any_sync_flag(0));
    }

    #[test]
    fn bridge_open_osync_with_odirect() {
        let flags = O_SYNC | O_DIRECT | 0o100600;
        let handle = fh(90, 9, flags);
        let e = MockEngine::new().with_open(Ok(handle));
        let session = bridge_open(&e, InodeId::new(90), flags, &ctx()).unwrap();
        assert!(has_osync_flag(session.flags));
        assert!(has_odirect_flag(session.flags));
        assert!(has_any_sync_flag(session.flags));
    }

    #[test]
    fn bridge_open_enoent_propagates() {
        let e = MockEngine::new().with_open(Err(KernelErrno::NS_NOT_FOUND));
        assert_eq!(
            bridge_open(&e, InodeId::new(99), 0, &ctx()).unwrap_err(),
            KernelErrno::NS_NOT_FOUND,
        );
    }

    #[test]
    fn bridge_open_eacces_propagates() {
        let e = MockEngine::new().with_open(Err(KernelErrno::PERM_DENIED));
        assert_eq!(
            bridge_open(&e, InodeId::new(10), 0, &ctx()).unwrap_err(),
            KernelErrno::PERM_DENIED,
        );
    }

    #[test]
    fn bridge_open_eio_propagates() {
        let e = MockEngine::new().with_open(Err(KernelErrno::STORAGE_IO));
        assert_eq!(
            bridge_open(&e, InodeId::new(10), 0, &ctx()).unwrap_err(),
            KernelErrno::STORAGE_IO,
        );
    }

    #[test]
    fn bridge_open_enomem_propagates() {
        let e = MockEngine::new().with_open(Err(KernelErrno::RESOURCE_MEMORY));
        assert_eq!(
            bridge_open(&e, InodeId::new(10), 0, &ctx()).unwrap_err(),
            KernelErrno::RESOURCE_MEMORY,
        );
    }

    // -- bridge_release tests --------------------------------------------

    #[test]
    fn bridge_release_works() {
        let session = FileSession {
            handle: fh(10, 1, 0),
            inode: InodeId::new(10),
            flags: 0,
        };
        let e = MockEngine::new().with_release(Ok(()));
        bridge_release(&e, &session).unwrap();
    }

    #[test]
    fn bridge_release_eio_propagates() {
        let session = FileSession {
            handle: fh(10, 1, 0),
            inode: InodeId::new(10),
            flags: 0,
        };
        let e = MockEngine::new().with_release(Err(KernelErrno::STORAGE_IO));
        assert_eq!(
            bridge_release(&e, &session).unwrap_err(),
            KernelErrno::STORAGE_IO,
        );
    }

    #[test]
    fn bridge_release_tolerates_stale_handle() {
        let session = FileSession {
            handle: fh(99, 99, 0),
            inode: InodeId::new(99),
            flags: 0,
        };
        let e = MockEngine::new().with_release(Err(KernelErrno::STALE_GENERATION));
        assert_eq!(
            bridge_release(&e, &session).unwrap_err(),
            KernelErrno::STALE_GENERATION,
        );
    }

    // -- open/release round-trip -----------------------------------------

    #[test]
    fn bridge_open_release_round_trip() {
        let handle = fh(42, 7, 0o644);
        let e = MockEngine::new().with_open(Ok(handle)).with_release(Ok(()));
        let session = bridge_open(&e, InodeId::new(42), 0o644, &ctx()).unwrap();
        assert_eq!(session.inode, InodeId::new(42));
        assert_eq!(session.flags, 0o644);
        bridge_release(&e, &session).unwrap();
    }

    // -- FileSession identity tests --------------------------------------

    #[test]
    fn file_session_equality() {
        let s1 = FileSession {
            handle: fh(10, 1, 0),
            inode: InodeId::new(10),
            flags: 0,
        };
        let s2 = FileSession {
            handle: fh(10, 1, 0),
            inode: InodeId::new(10),
            flags: 0,
        };
        assert_eq!(s1, s2);
    }

    #[test]
    fn file_session_different_inodes_are_unequal() {
        let s1 = FileSession {
            handle: fh(10, 1, 0),
            inode: InodeId::new(10),
            flags: 0,
        };
        let s2 = FileSession {
            handle: fh(20, 1, 0),
            inode: InodeId::new(20),
            flags: 0,
        };
        assert_ne!(s1, s2);
    }

    #[test]
    fn file_session_clone_preserves_state() {
        let s1 = FileSession {
            handle: fh(10, 1, 0o100),
            inode: InodeId::new(10),
            flags: 0o100,
        };
        let s2 = s1.clone();
        assert_eq!(s1, s2);
    }
}
