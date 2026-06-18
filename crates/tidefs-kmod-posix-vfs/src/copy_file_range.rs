// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Server-side copy_file_range delegation for the kernel VFS adapter -- K7-20.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{EngineFileHandle, Errno, RequestCtx};

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Delegate server-side copy to the VfsEngine.
    ///
    /// Copies up to `length` bytes from `source_fh` at `offset_in` to
    /// `dest_fh` at `offset_out`. Returns the number of bytes copied,
    /// which may be less than `length` if source EOF is reached.
    pub fn copy_file_range(
        &self,
        source_fh: &EngineFileHandle,
        offset_in: u64,
        dest_fh: &EngineFileHandle,
        offset_out: u64,
        length: u64,
        ctx: &RequestCtx,
    ) -> Result<u32, Errno> {
        self.engine
            .copy_file_range(source_fh, offset_in, dest_fh, offset_out, length, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use tidefs_kmod_bridge::kernel_types::{EngineFileHandle, FileHandleId, InodeId};

    fn fh(ino: u64, id: u64) -> EngineFileHandle {
        EngineFileHandle {
            inode_id: InodeId::new(ino),
            open_flags: 0,
            fh_id: FileHandleId::new(id),
            lock_owner: 0,
        }
    }

    #[test]
    fn copy_file_range_works() {
        let src = fh(10, 1);
        let dst = fh(20, 2);
        let mut e = MockEngine::new();
        e.copy_file_range_fn = Box::new(move |sfh, so, dfh, do_, len, _| {
            assert_eq!(sfh.inode_id, InodeId::new(10));
            assert_eq!(so, 0);
            assert_eq!(dfh.inode_id, InodeId::new(20));
            assert_eq!(do_, 0);
            assert_eq!(len, 1024);
            Ok(1024)
        });
        let copied = KmodPosixVfs::new(e)
            .copy_file_range(&src, 0, &dst, 0, 1024, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(copied, 1024);
    }

    #[test]
    fn copy_file_range_zero_length_returns_zero() {
        let src = fh(10, 1);
        let dst = fh(20, 2);
        let mut e = MockEngine::new();
        e.copy_file_range_fn = Box::new(|_, _, _, _, _, _| Ok(0));
        let copied = KmodPosixVfs::new(e)
            .copy_file_range(&src, 0, &dst, 0, 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(copied, 0);
    }

    #[test]
    fn copy_file_range_partial_at_eof() {
        let src = fh(10, 1);
        let dst = fh(20, 2);
        let mut e = MockEngine::new();
        e.copy_file_range_fn = Box::new(|_, _, _, _, _, _| Ok(512));
        let copied = KmodPosixVfs::new(e)
            .copy_file_range(&src, 0, &dst, 0, 1024, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(copied, 512);
    }

    #[test]
    fn copy_file_range_einval_propagates() {
        let src = fh(10, 1);
        let dst = fh(20, 2);
        let mut e = MockEngine::new();
        e.copy_file_range_fn = Box::new(|_, _, _, _, _, _| Err(Errno::EINVAL));
        assert_eq!(
            KmodPosixVfs::new(e)
                .copy_file_range(&src, 0, &dst, 0, 4, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EINVAL,
        );
    }

    #[test]
    fn copy_file_range_ebadf_propagates() {
        let src = fh(10, 1);
        let dst = fh(20, 2);
        let mut e = MockEngine::new();
        e.copy_file_range_fn = Box::new(|_, _, _, _, _, _| Err(Errno::EBADF));
        assert_eq!(
            KmodPosixVfs::new(e)
                .copy_file_range(&src, 0, &dst, 0, 4, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EBADF,
        );
    }

    #[test]
    fn copy_file_range_mid_file_offsets() {
        let src = fh(10, 1);
        let dst = fh(20, 2);
        let mut e = MockEngine::new();
        e.copy_file_range_fn = Box::new(move |_, so, _, do_, len, _| {
            assert_eq!(so, 4096);
            assert_eq!(do_, 8192);
            assert_eq!(len, 256);
            Ok(256)
        });
        let copied = KmodPosixVfs::new(e)
            .copy_file_range(&src, 4096, &dst, 8192, 256, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(copied, 256);
    }
}
