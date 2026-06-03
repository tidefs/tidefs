//! File data flush for the kernel VFS adapter -- K7-17 mutation seam.
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{Errno, RequestCtx};

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Push per-fd dirty data to stable storage.
    pub fn flush(
        &self,
        fh: &tidefs_kmod_bridge::kernel_types::EngineFileHandle,
        ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        self.engine.flush(fh, ctx)
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
    fn flush_works() {
        let h = fh(20, 1);
        let mut e = MockEngine::new();
        e.flush_fn = Box::new(move |fh, _| {
            assert_eq!(fh.inode_id, InodeId::new(20));
            Ok(())
        });
        KmodPosixVfs::new(e)
            .flush(&h, &MockEngine::test_ctx())
            .unwrap();
    }

    #[test]
    fn flush_error_propagates() {
        let h = fh(20, 1);
        let mut e = MockEngine::new();
        e.flush_fn = Box::new(|_, _| Err(Errno::EIO));
        assert_eq!(
            KmodPosixVfs::new(e)
                .flush(&h, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EIO,
        );
    }

    #[test]
    fn flush_different_inodes_independent() {
        let h1 = fh(10, 1);
        let h2 = fh(20, 2);
        let mut e = MockEngine::new();
        e.flush_fn = Box::new(|_fh, _| {
            // Both inodes should flush successfully
            Ok(())
        });
        let kmod = KmodPosixVfs::new(e);
        kmod.flush(&h1, &MockEngine::test_ctx()).unwrap();
        kmod.flush(&h2, &MockEngine::test_ctx()).unwrap();
    }

    #[test]
    fn flush_idempotent() {
        let h = fh(20, 1);
        let mut e = MockEngine::new();
        e.flush_fn = Box::new(|_, _| Ok(()));
        let kmod = KmodPosixVfs::new(e);
        // First flush
        kmod.flush(&h, &MockEngine::test_ctx()).unwrap();
        // Second flush on same handle
        kmod.flush(&h, &MockEngine::test_ctx()).unwrap();
    }
}
