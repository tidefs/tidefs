//! getattr read-side dispatch for the kernel VFS adapter -- K7 read seam.
//!
//! Bridges the kernel VFS `inode_operations::getattr` callback to `VfsEngine`,
//! retrieving committed inode attributes and populating the kernel `struct inode`
//! fields.
//!
//! ## Attribute Population Field Mapping
//!
//! VfsEngine `InodeAttr` -> kernel `struct inode`:
//!
//! | VfsEngine field     | Kernel inode field   | Notes                          |
//! |---------------------|----------------------|--------------------------------|
//! | `posix.mode`        | `i_mode`             | File type + permission bits    |
//! | `posix.uid`         | `i_uid`              | Owner UID                      |
//! | `posix.gid`         | `i_gid`              | Owner GID                      |
//! | `posix.size`        | `i_size`             | File size in bytes             |
//! | `posix.nlink`       | `i_nlink`            | Hard-link count                |
//! | `posix.blocks_512`  | `i_blocks`           | 512-byte block count           |
//! | `posix.blksize`     | `i_blkbits`/`i_blksize` | Preferred I/O block size    |
//! | `posix.atime_ns`    | `i_atime`            | Last access time (ns)          |
//! | `posix.mtime_ns`    | `i_mtime`            | Last modification time (ns)    |
//! | `posix.ctime_ns`    | `i_ctime`            | Last status change time (ns)   |
//! | `posix.rdev`        | `i_rdev`             | Device number (dev nodes only) |
//! | `kind`              | `i_mode` (type bits)  | `S_IFREG`, `S_IFDIR`, etc.    |
//!
//! ## Error Handling
//!
//! - `ENOENT` -- inode not found in engine
//! - `ESTALE` -- generation mismatch (inode invalidated after lookup)
//! - `EIO` -- engine or storage unavailable
//! - Other engine errors propagated unchanged

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{EngineFileHandle, Errno, InodeAttr, InodeId, RequestCtx};

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Get file attributes from the committed inode state.
    ///
    /// Retrieves the `InodeAttr` for the given inode from the VfsEngine.
    /// An optional open file handle may be provided to access per-open
    /// inode state cached by the engine.
    ///
    /// Returns:
    /// - `Ok(attr)` with committed attributes on success
    /// - `Err(ENOENT)` if the inode does not exist
    /// - `Err(ESTALE)` if the inode generation has been invalidated
    /// - `Err(EIO)` if the engine or backing storage is unavailable
    pub fn getattr(
        &self,
        inode: InodeId,
        handle: Option<&EngineFileHandle>,
        ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        self.engine.getattr(inode, handle, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use tidefs_kmod_bridge::kernel_types::{
        FileHandleId, Generation, InodeFlags, NodeKind, PosixAttrs,
    };

    fn file_attr(ino: u64, size: u64, mode: u32) -> InodeAttr {
        InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode,
                uid: 1000,
                gid: 1000,
                nlink: 1,
                rdev: 0,
                atime_ns: 1_700_000_000_000_000_000,
                mtime_ns: 1_700_000_001_000_000_000,
                ctime_ns: 1_700_000_002_000_000_000,
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

    fn dir_attr(ino: u64) -> InodeAttr {
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

    #[test]
    fn getattr_file_returns_attributes() {
        let a = file_attr(10, 4096, 0o100644);
        let a2 = a;
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |ino, h, _| {
            assert_eq!(ino, InodeId::new(10));
            assert!(h.is_none());
            Ok(a2)
        });
        let r = KmodPosixVfs::new(e)
            .getattr(InodeId::new(10), None, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(r.inode_id, InodeId::new(10));
        assert_eq!(r.posix.mode, 0o100644);
        assert_eq!(r.posix.uid, 1000);
        assert_eq!(r.posix.gid, 1000);
        assert_eq!(r.posix.size, 4096);
        assert_eq!(r.posix.nlink, 1);
        assert_eq!(r.posix.blocks_512, 8);
        assert_eq!(r.posix.blksize, 4096);
    }

    #[test]
    fn getattr_with_file_handle() {
        let a = file_attr(15, 1024, 0o100644);
        let a2 = a;
        let fh = tidefs_kmod_bridge::kernel_types::EngineFileHandle {
            inode_id: InodeId::new(15),
            open_flags: 0o2,
            fh_id: FileHandleId::new(1),
            lock_owner: 0,
        };
        let fh2 = fh;
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |ino, h, _| {
            assert_eq!(ino, InodeId::new(15));
            assert!(h.is_some());
            assert_eq!(h.unwrap().fh_id, fh2.fh_id);
            Ok(a2)
        });
        let r = KmodPosixVfs::new(e)
            .getattr(InodeId::new(15), Some(&fh), &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(r.posix.size, 1024);
    }

    #[test]
    fn getattr_directory_returns_attributes() {
        let a = dir_attr(5);
        let a2 = a;
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(a2));
        let r = KmodPosixVfs::new(e)
            .getattr(InodeId::new(5), None, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(r.inode_id, InodeId::new(5));
        assert_eq!(r.kind, NodeKind::Dir);
        assert_eq!(r.posix.mode, 0o40755);
    }

    #[test]
    fn getattr_enoent_propagated() {
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(|_, _, _| Err(Errno::ENOENT));
        assert_eq!(
            KmodPosixVfs::new(e)
                .getattr(InodeId::new(99), None, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOENT,
        );
    }

    #[test]
    fn getattr_estale_propagated() {
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(|_, _, _| Err(Errno::ESTALE));
        assert_eq!(
            KmodPosixVfs::new(e)
                .getattr(InodeId::new(42), None, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ESTALE,
        );
    }

    #[test]
    fn getattr_eio_propagated() {
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(|_, _, _| Err(Errno::EIO));
        assert_eq!(
            KmodPosixVfs::new(e)
                .getattr(InodeId::new(1), None, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EIO,
        );
    }

    #[test]
    fn getattr_eacces_propagated() {
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(|_, _, _| Err(Errno::EACCES));
        assert_eq!(
            KmodPosixVfs::new(e)
                .getattr(InodeId::new(1), None, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EACCES,
        );
    }

    #[test]
    fn getattr_enosys_propagated() {
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(|_, _, _| Err(Errno::ENOSYS));
        assert_eq!(
            KmodPosixVfs::new(e)
                .getattr(InodeId::new(1), None, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOSYS,
        );
    }

    #[test]
    fn getattr_all_posix_fields_present() {
        let a = InodeAttr {
            inode_id: InodeId::new(42),
            generation: Generation::new(7),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode: 0o100755,
                uid: 500,
                gid: 600,
                nlink: 3,
                rdev: 0,
                atime_ns: 1_700_000_000_000_000_000,
                mtime_ns: 1_700_000_001_000_000_000,
                ctime_ns: 1_700_000_002_000_000_000,
                btime_ns: 1_700_000_003_000_000_000,
                size: 65536,
                blocks_512: 128,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        };
        let a2 = a;
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(a2));
        let r = KmodPosixVfs::new(e)
            .getattr(InodeId::new(42), None, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(r.inode_id, InodeId::new(42));
        assert_eq!(r.generation, Generation::new(7));
        assert_eq!(r.posix.mode, 0o100755);
        assert_eq!(r.posix.uid, 500);
        assert_eq!(r.posix.gid, 600);
        assert_eq!(r.posix.nlink, 3);
        assert_eq!(r.posix.size, 65536);
        assert_eq!(r.posix.blocks_512, 128);
        assert_eq!(r.posix.blksize, 4096);
        assert_eq!(r.posix.atime_ns, 1_700_000_000_000_000_000);
        assert_eq!(r.posix.mtime_ns, 1_700_000_001_000_000_000);
        assert_eq!(r.posix.ctime_ns, 1_700_000_002_000_000_000);
        assert_eq!(r.posix.btime_ns, 1_700_000_003_000_000_000);
    }

    #[test]
    fn getattr_symlink_has_correct_kind() {
        let a = InodeAttr {
            inode_id: InodeId::new(20),
            generation: Generation::new(1),
            kind: NodeKind::Symlink,
            posix: PosixAttrs {
                mode: 0o120777,
                uid: 0,
                gid: 0,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 10,
                blocks_512: 0,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        };
        let a2 = a;
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(a2));
        let r = KmodPosixVfs::new(e)
            .getattr(InodeId::new(20), None, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(r.kind, NodeKind::Symlink);
    }

    #[test]
    fn getattr_device_node_has_rdev() {
        let a = InodeAttr {
            inode_id: InodeId::new(30),
            generation: Generation::new(1),
            kind: NodeKind::CharDev,
            posix: PosixAttrs {
                mode: 0o020644,
                uid: 0,
                gid: 0,
                nlink: 1,
                rdev: 0x0801,
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
        };
        let a2 = a;
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(a2));
        let r = KmodPosixVfs::new(e)
            .getattr(InodeId::new(30), None, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(r.kind, NodeKind::CharDev);
        assert_eq!(r.posix.rdev, 0x0801);
    }

    #[test]
    fn getattr_zero_size_file() {
        let a = file_attr(1, 0, 0o100644);
        let a2 = a;
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(a2));
        let r = KmodPosixVfs::new(e)
            .getattr(InodeId::new(1), None, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(r.posix.size, 0);
        assert_eq!(r.posix.blocks_512, 0);
    }

    #[test]
    fn getattr_large_file_roundtrips() {
        let large_size: u64 = 1_099_511_627_776; // 1 TiB
        let a = file_attr(99, large_size, 0o100644);
        let a2 = a;
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(a2));
        let r = KmodPosixVfs::new(e)
            .getattr(InodeId::new(99), None, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(r.posix.size, large_size);
    }

    #[test]
    fn getattr_idempotent() {
        let a = file_attr(5, 4096, 0o100644);
        let a2 = a;
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |ino, _, _| {
            if ino == InodeId::new(5) {
                Ok(a2)
            } else {
                Err(Errno::ENOENT)
            }
        });
        let kmod = KmodPosixVfs::new(e);
        let r1 = kmod
            .getattr(InodeId::new(5), None, &MockEngine::test_ctx())
            .unwrap();
        let r2 = kmod
            .getattr(InodeId::new(5), None, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(r1.inode_id, r2.inode_id);
        assert_eq!(r1.posix.size, r2.posix.size);
        assert_eq!(r1.posix.mode, r2.posix.mode);
    }
}
