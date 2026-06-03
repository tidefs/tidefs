//! Statfs filesystem statistics delegation for the kernel VFS adapter --
//! K7-21 filesystem statistics seam.
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::{Errno, RequestCtx, StatFs};
use tidefs_kmod_bridge::kernel_types::{VfsEngine, VfsEngineStatFs};

impl<E: VfsEngine + VfsEngineStatFs> KmodPosixVfs<E> {
    /// Return filesystem statistics (total/free blocks, total/free inodes,
    /// block size, maximum filename length, filesystem id).
    ///
    /// Delegates to `VfsEngineStatFs::statfs()` so `df(1)` and `statvfs(2)`
    /// on a kernel-mounted TideFS report accurate capacity data from the
    /// VfsEngine capacity path.
    pub fn statfs(&self, ctx: &RequestCtx) -> Result<StatFs, Errno> {
        self.engine.statfs(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;

    /// A well-populated StatFs with all non-zero fields.
    fn populated_statfs() -> StatFs {
        StatFs {
            block_size: 4096,
            fragment_size: 4096,
            total_blocks: 1_000_000,
            free_blocks: 750_000,
            avail_blocks: 740_000,
            files: 500_000,
            files_free: 490_000,
            name_max: 255,
            fsid_hi: 0xabcd,
            fsid_lo: 0x1234,
        }
    }

    #[test]
    fn statfs_works() {
        let s = populated_statfs();
        let s2 = s;
        let mut e = MockEngine::new();
        e.statfs_fn = Box::new(move |_| Ok(s2));
        let r = KmodPosixVfs::new(e)
            .statfs(&MockEngine::test_ctx())
            .unwrap();
        assert_eq!(r.block_size, s.block_size);
        assert_eq!(r.total_blocks, s.total_blocks);
        assert_eq!(r.free_blocks, s.free_blocks);
        assert_eq!(r.avail_blocks, s.avail_blocks);
        assert_eq!(r.files, s.files);
        assert_eq!(r.files_free, s.files_free);
        assert_eq!(r.name_max, s.name_max);
    }

    #[test]
    fn statfs_zero_capacity_pool() {
        let s = StatFs {
            block_size: 4096,
            fragment_size: 4096,
            total_blocks: 0,
            free_blocks: 0,
            avail_blocks: 0,
            files: 0,
            files_free: 0,
            name_max: 255,
            fsid_hi: 0,
            fsid_lo: 0,
        };
        let s2 = s;
        let mut e = MockEngine::new();
        e.statfs_fn = Box::new(move |_| Ok(s2));
        let r = KmodPosixVfs::new(e)
            .statfs(&MockEngine::test_ctx())
            .unwrap();
        assert_eq!(r.total_blocks, 0);
        assert_eq!(r.free_blocks, 0);
        assert_eq!(r.files, 0);
    }

    #[test]
    fn statfs_full_filesystem() {
        let s = StatFs {
            block_size: 4096,
            fragment_size: 4096,
            total_blocks: 100_000,
            free_blocks: 0,
            avail_blocks: 0,
            files: 1000,
            files_free: 0,
            name_max: 255,
            fsid_hi: 0,
            fsid_lo: 0,
        };
        let s2 = s;
        let mut e = MockEngine::new();
        e.statfs_fn = Box::new(move |_| Ok(s2));
        let r = KmodPosixVfs::new(e)
            .statfs(&MockEngine::test_ctx())
            .unwrap();
        assert_eq!(r.free_blocks, 0);
        assert_eq!(r.avail_blocks, 0);
        assert_eq!(r.files_free, 0);
        // total_blocks is non-zero even when full
        assert_eq!(r.total_blocks, 100_000);
    }

    #[test]
    fn statfs_eio_propagates() {
        let mut e = MockEngine::new();
        e.statfs_fn = Box::new(|_| Err(Errno::EIO));
        assert_eq!(
            KmodPosixVfs::new(e)
                .statfs(&MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EIO,
        );
    }

    #[test]
    fn statfs_enosys_propagates() {
        let mut e = MockEngine::new();
        e.statfs_fn = Box::new(|_| Err(Errno::ENOSYS));
        assert_eq!(
            KmodPosixVfs::new(e)
                .statfs(&MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOSYS,
        );
    }

    #[test]
    fn statfs_erofs_propagates() {
        let mut e = MockEngine::new();
        e.statfs_fn = Box::new(|_| Err(Errno::EROFS));
        assert_eq!(
            KmodPosixVfs::new(e)
                .statfs(&MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EROFS,
        );
    }

    #[test]
    fn statfs_fields_round_trip() {
        let s = populated_statfs();
        let s2 = s;
        let mut e = MockEngine::new();
        e.statfs_fn = Box::new(move |_| Ok(s2));
        let r = KmodPosixVfs::new(e)
            .statfs(&MockEngine::test_ctx())
            .unwrap();
        assert_eq!(r.block_size, 4096);
        assert_eq!(r.fragment_size, 4096);
        assert_eq!(r.total_blocks, 1_000_000);
        assert_eq!(r.free_blocks, 750_000);
        assert_eq!(r.avail_blocks, 740_000);
        assert_eq!(r.files, 500_000);
        assert_eq!(r.files_free, 490_000);
        assert_eq!(r.name_max, 255);
        assert_eq!(r.fsid_hi, 0xabcd);
        assert_eq!(r.fsid_lo, 0x1234);
    }
}
