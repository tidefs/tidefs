// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! File data read operation for the kernel VFS adapter -- K7-09 mutation seam.
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{Errno, RequestCtx};

#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::ByteSliceExt;

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Read data from a file at the given offset. Returns the read buffer
    /// (may be shorter than `size` on EOF or when data is sparse).
    pub fn read(
        &self,
        fh: &tidefs_kmod_bridge::kernel_types::EngineFileHandle,
        offset: u64,
        size: u32,
        ctx: &RequestCtx,
    ) -> Result<crate::TideVec<u8>, Errno> {
        self.engine.read(fh, offset, size, ctx)
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
    fn read_works() {
        let h = fh(20, 1);
        let mut e = MockEngine::new();
        e.read_fn = Box::new(move |fh, off, size, _| {
            assert_eq!(fh.inode_id, InodeId::new(20));
            assert_eq!(off, 0);
            assert_eq!(size, 5);
            Ok(b"hello".to_vec())
        });
        let data = KmodPosixVfs::new(e)
            .read(&h, 0, 5, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(data, b"hello");
    }

    #[test]
    fn read_zero_length() {
        let h = fh(20, 1);
        let mut e = MockEngine::new();
        e.read_fn = Box::new(|_, _, size, _| {
            assert_eq!(size, 0);
            Ok(crate::TideVec::new())
        });
        let data = KmodPosixVfs::new(e)
            .read(&h, 0, 0, &MockEngine::test_ctx())
            .unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn read_eof_short_read() {
        let h = fh(20, 1);
        let mut e = MockEngine::new();
        e.read_fn = Box::new(|_, off, size, _| {
            assert_eq!(off, 100);
            assert_eq!(size, 20);
            // Return only 3 bytes -- simulating EOF
            Ok(b"end".to_vec())
        });
        let data = KmodPosixVfs::new(e)
            .read(&h, 100, 20, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(data.len(), 3);
        assert_eq!(data, b"end");
    }

    #[test]
    fn read_eio_propagates() {
        let h = fh(20, 1);
        let mut e = MockEngine::new();
        e.read_fn = Box::new(|_, _, _, _| Err(Errno::EIO));
        assert_eq!(
            KmodPosixVfs::new(e)
                .read(&h, 0, 64, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EIO,
        );
    }

    #[test]
    fn read_enospc_propagates() {
        let h = fh(20, 1);
        let mut e = MockEngine::new();
        e.read_fn = Box::new(|_, _, _, _| Err(Errno::ENOSPC));
        assert_eq!(
            KmodPosixVfs::new(e)
                .read(&h, 0, 64, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOSPC,
        );
    }

    #[test]
    fn read_offset_isolation() {
        let h = fh(30, 2);
        // Read at offset 0
        let mut e1 = MockEngine::new();
        e1.read_fn = Box::new(|_, off, _, _| {
            assert_eq!(off, 0);
            Ok(b"first".to_vec())
        });
        let d1 = KmodPosixVfs::new(e1)
            .read(&h, 0, 5, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(d1, b"first");

        // Read at offset 4096
        let mut e2 = MockEngine::new();
        e2.read_fn = Box::new(|_, off, _, _| {
            assert_eq!(off, 4096);
            Ok(b"second".to_vec())
        });
        let d2 = KmodPosixVfs::new(e2)
            .read(&h, 4096, 6, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(d2, b"second");
    }

    #[test]
    fn read_large_clamping() {
        let h = fh(40, 3);
        let requested: u32 = 1_048_576; // 1 MiB
        let mut e = MockEngine::new();
        e.read_fn = Box::new(move |_, _, size, _| {
            assert_eq!(size, requested);
            // Return fewer bytes than requested
            Ok(b"short".to_vec())
        });
        let data = KmodPosixVfs::new(e)
            .read(&h, 0, requested, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(data.len(), 5);
        assert_eq!(data, b"short");
    }
}
