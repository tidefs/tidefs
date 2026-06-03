//! Filesystem-wide synchronization delegation for the kernel VFS adapter --
//! K7-24 syncfs seam.
//!
//! Delegates to VfsEngine::syncfs, which flushes all dirty data and
//! metadata to stable storage, equivalent to the Linux syncfs(2) syscall.
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{Errno, RequestCtx};

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Synchronize the entire filesystem to stable storage.
    ///
    /// Flushes all dirty data and metadata, equivalent to `syncfs(2)`.
    /// Delegates to `VfsEngine::syncfs()`; engines that do not support
    /// syncfs return `ENOSYS`.
    pub fn syncfs(&self, ctx: &RequestCtx) -> Result<(), Errno> {
        self.engine.syncfs(ctx)?;
        self.commit_fs_barrier()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;

    #[test]
    fn syncfs_success() {
        let mut e = MockEngine::new();
        e.syncfs_fn = Box::new(|_| Ok(()));
        KmodPosixVfs::new(e)
            .syncfs(&MockEngine::test_ctx())
            .unwrap();
    }

    #[test]
    fn syncfs_eio_propagates() {
        let mut e = MockEngine::new();
        e.syncfs_fn = Box::new(|_| Err(Errno::EIO));
        assert_eq!(
            KmodPosixVfs::new(e)
                .syncfs(&MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EIO,
        );
    }

    #[test]
    fn syncfs_enosys_propagates() {
        let mut e = MockEngine::new();
        e.syncfs_fn = Box::new(|_| Err(Errno::ENOSYS));
        assert_eq!(
            KmodPosixVfs::new(e)
                .syncfs(&MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOSYS,
        );
    }

    #[test]
    fn syncfs_default_returns_enosys() {
        // MockEngine without explicit syncfs_fn uses the VfsEngine default
        // which returns ENOSYS.
        let e = MockEngine::new();
        assert_eq!(
            KmodPosixVfs::new(e)
                .syncfs(&MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOSYS,
        );
    }
}
