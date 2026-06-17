//! Filesystem-wide synchronization delegation for the kernel VFS adapter --
//! K7-24 syncfs seam.
//!
//! Delegates to VfsEngine::syncfs, which flushes all dirty data and
//! metadata to stable storage, equivalent to the Linux syncfs(2) syscall.
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::TideVec as Vec;
use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{
    EngineFileHandle, Errno, FileHandleId, InodeId, RequestCtx, WritebackRange,
};

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Synchronize the entire filesystem to stable storage.
    ///
    /// Drains all dirty page-cache ranges tracked in
    /// [`DirtyFolioTracker`] through [`VfsEngine::writeback_folios`]
    /// before calling the engine durability barrier.  Writeback errors
    /// (EIO, ENOSPC) are surfaced to the caller and prevent a clean
    /// syncfs from being reported.  Engines that do not support syncfs
    /// return `ENOSYS`.
    ///
    /// Equivalent to `syncfs(2)`.
    pub fn syncfs(&mut self, ctx: &RequestCtx) -> Result<(), Errno> {
        // Drain all tracked dirty inodes through writeback before the
        // engine-level sync barrier.  Collect inode list first so we
        // can iterate without borrow conflicts.
        // Build inode list manually: KmodVec does not implement
        // FromIterator, so collect() fails in the kernel build.
        let mut dirty_inodes: Vec<InodeId> = Vec::new();
        for (ino, _) in self.dirty_folio_tracker.iter() {
            dirty_inodes.push(ino);
        }
        for inode in dirty_inodes {
            let ranges = self.dirty_folio_tracker.drain_inode(inode);
            for range in &ranges {
                let wb_range = WritebackRange::new(range.offset, range.length as u64);
                // We need a file handle for writeback_folios.  When no
                // open handle is available (syncfs is filesystem-wide),
                // construct a minimal handle from the inode.
                let fh = EngineFileHandle::new(inode, 0, FileHandleId::default(), 0);
                let outcome = self.engine.writeback_folios(inode, &fh, wb_range, ctx)?;
                if !outcome.complete && outcome.bytes_written < wb_range.length {
                    let tail_offset = range.offset + outcome.bytes_written;
                    let tail_len = (wb_range.length - outcome.bytes_written) as u32;
                    let _ = self.dirty_folio_tracker.try_add(inode, tail_offset, tail_len);
                }
            }
        }
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
        let mut kmod = KmodPosixVfs::new(e);
        kmod.syncfs(&MockEngine::test_ctx())
            .unwrap();
    }

    #[test]
    fn syncfs_eio_propagates() {
        let mut e = MockEngine::new();
        e.syncfs_fn = Box::new(|_| Err(Errno::EIO));
        let mut kmod = KmodPosixVfs::new(e);
        assert_eq!(
            kmod.syncfs(&MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EIO,
        );
    }

    #[test]
    fn syncfs_enosys_propagates() {
        let mut e = MockEngine::new();
        e.syncfs_fn = Box::new(|_| Err(Errno::ENOSYS));
        let mut kmod = KmodPosixVfs::new(e);
        assert_eq!(
            kmod.syncfs(&MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOSYS,
        );
    }

    #[test]
    fn syncfs_default_returns_enosys() {
        // MockEngine without explicit syncfs_fn uses the VfsEngine default
        // which returns ENOSYS.
        let e = MockEngine::new();
        let mut kmod = KmodPosixVfs::new(e);
        assert_eq!(
            kmod.syncfs(&MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOSYS,
        );
    }
}
