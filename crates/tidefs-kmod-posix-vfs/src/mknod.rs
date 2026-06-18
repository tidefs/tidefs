// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! mknod mutation for the kernel VFS adapter -- K7-12 mutation seam.
//!
//! Creates device nodes (char/block), FIFOs, and Unix-domain sockets.
//! Regular files are rejected: use `create` for those.
//! Delegates mode-valid mknod calls to the VfsEngine, returning the
//! new inode's InodeAttr on success.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::intent_record::encode_mknod_intent;
use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{Errno, InodeAttr, InodeId, RequestCtx, S_IFMT, S_IFREG};

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Create a device node, FIFO, or socket.
    ///
    /// `mode` must include a valid special-file type (S_IFCHR, S_IFBLK,
    /// S_IFIFO, S_IFSOCK). S_IFREG is rejected with EINVAL -- regular
    /// files must use `create`. `rdev` encodes the device major/minor
    /// for char/block nodes; it should be zero for FIFOs and sockets.
    /// Returns the new inode's attributes on success.
    pub fn mknod(
        &self,
        parent: InodeId,
        name: &[u8],
        mode: u32,
        rdev: u32,
        ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        let file_type = mode & S_IFMT;
        if file_type == S_IFREG {
            return Err(Errno::EINVAL);
        }
        let attr = self.engine.mknod(parent, name, mode, rdev, ctx)?;
        // Record mknod-intent after engine call so the real inode is known.
        let entry = encode_mknod_intent(parent, name, mode, rdev, attr.inode_id);
        self.record_mutation_intent(&entry)?;
        Ok(attr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use tidefs_kmod_bridge::kernel_types::{
        Generation, InodeFlags, InodeId, NodeKind, PosixAttrs, S_IFBLK, S_IFCHR, S_IFIFO, S_IFSOCK,
    };

    fn dev_attr(ino: u64, kind: NodeKind, rdev: u32) -> InodeAttr {
        InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind,
            posix: PosixAttrs {
                mode: match kind {
                    NodeKind::CharDev => 0o200_000 | 0o600,
                    NodeKind::BlockDev => 0o600_000 | 0o660,
                    NodeKind::Fifo => 0o100_000 | 0o644,
                    NodeKind::Socket => 0o140_000 | 0o755,
                    _ => 0,
                },
                uid: 0,
                gid: 0,
                nlink: 1,
                rdev,
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
    fn mknod_regular_file_rejected() {
        let e = MockEngine::new();
        let result = KmodPosixVfs::new(e).mknod(
            InodeId::new(1),
            b"somefile",
            S_IFREG | 0o644,
            0,
            &MockEngine::test_ctx(),
        );
        assert_eq!(result, Err(Errno::EINVAL));
    }

    #[test]
    fn mknod_char_device() {
        let parent = InodeId::new(1);
        let name = b"null";
        let mode = S_IFCHR | 0o666;
        let rdev: u32 = 0x0103;
        let expected = dev_attr(100, NodeKind::CharDev, rdev);
        let expected_clone = expected;
        let mut e = MockEngine::new();
        e.mknod_fn = Box::new(move |p, n, m, r, c| {
            assert_eq!(p, parent);
            assert_eq!(n, name);
            assert_eq!(m, mode);
            assert_eq!(r, rdev);
            assert_eq!(c.uid, 1000);
            Ok(expected_clone)
        });
        let result = KmodPosixVfs::new(e)
            .mknod(parent, name, mode, rdev, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(result.inode_id, expected.inode_id);
        assert_eq!(result.kind, NodeKind::CharDev);
        assert_eq!(result.posix.rdev, rdev);
    }

    #[test]
    fn mknod_block_device() {
        let parent = InodeId::new(1);
        let name = b"sda";
        let mode = S_IFBLK | 0o660;
        let rdev: u32 = 0x0800;
        let expected = dev_attr(101, NodeKind::BlockDev, rdev);
        let expected_clone = expected;
        let mut e = MockEngine::new();
        e.mknod_fn = Box::new(move |p, n, m, r, c| {
            assert_eq!(p, parent);
            assert_eq!(n, name);
            assert_eq!(m, mode);
            assert_eq!(r, rdev);
            assert_eq!(c.uid, 1000);
            Ok(expected_clone)
        });
        let result = KmodPosixVfs::new(e)
            .mknod(parent, name, mode, rdev, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(result.inode_id, expected.inode_id);
        assert_eq!(result.kind, NodeKind::BlockDev);
        assert_eq!(result.posix.rdev, rdev);
    }

    #[test]
    fn mknod_fifo() {
        let parent = InodeId::new(1);
        let name = b"pipe";
        let mode = S_IFIFO | 0o644;
        let rdev: u32 = 0;
        let expected = dev_attr(102, NodeKind::Fifo, 0);
        let expected_clone = expected;
        let mut e = MockEngine::new();
        e.mknod_fn = Box::new(move |p, n, m, r, c| {
            assert_eq!(p, parent);
            assert_eq!(n, name);
            assert_eq!(m, mode);
            assert_eq!(r, rdev);
            assert_eq!(c.uid, 1000);
            Ok(expected_clone)
        });
        let result = KmodPosixVfs::new(e)
            .mknod(parent, name, mode, rdev, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(result.inode_id, expected.inode_id);
        assert_eq!(result.kind, NodeKind::Fifo);
        assert_eq!(result.posix.rdev, 0);
    }

    #[test]
    fn mknod_socket() {
        let parent = InodeId::new(1);
        let name = b"mysock";
        let mode = S_IFSOCK | 0o755;
        let rdev: u32 = 0;
        let expected = dev_attr(103, NodeKind::Socket, 0);
        let expected_clone = expected;
        let mut e = MockEngine::new();
        e.mknod_fn = Box::new(move |p, n, m, r, c| {
            assert_eq!(p, parent);
            assert_eq!(n, name);
            assert_eq!(m, mode);
            assert_eq!(r, rdev);
            assert_eq!(c.uid, 1000);
            Ok(expected_clone)
        });
        let result = KmodPosixVfs::new(e)
            .mknod(parent, name, mode, rdev, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(result.inode_id, expected.inode_id);
        assert_eq!(result.kind, NodeKind::Socket);
        assert_eq!(result.posix.rdev, 0);
    }

    #[test]
    fn mknod_eexist_propagates() {
        let mut e = MockEngine::new();
        e.mknod_fn = Box::new(|_, _, _, _, _| Err(Errno::EEXIST));
        let result = KmodPosixVfs::new(e).mknod(
            InodeId::new(1),
            b"dev",
            S_IFCHR | 0o600,
            0,
            &MockEngine::test_ctx(),
        );
        assert_eq!(result, Err(Errno::EEXIST));
    }

    #[test]
    fn mknod_enospc_propagates() {
        let mut e = MockEngine::new();
        e.mknod_fn = Box::new(|_, _, _, _, _| Err(Errno::ENOSPC));
        let result = KmodPosixVfs::new(e).mknod(
            InodeId::new(1),
            b"dev",
            S_IFCHR | 0o600,
            0,
            &MockEngine::test_ctx(),
        );
        assert_eq!(result, Err(Errno::ENOSPC));
    }

    #[test]
    fn mknod_eacces_propagates() {
        let mut e = MockEngine::new();
        e.mknod_fn = Box::new(|_, _, _, _, _| Err(Errno::EACCES));
        let result = KmodPosixVfs::new(e).mknod(
            InodeId::new(1),
            b"dev",
            S_IFCHR | 0o600,
            0,
            &MockEngine::test_ctx(),
        );
        assert_eq!(result, Err(Errno::EACCES));
    }
}
