//! File advisory hints for the kernel VFS adapter -- K7-25.
//!
//! `posix_fadvise(2)` accepts WILLNEED, DONTNEED, NOREUSE, and NORMAL
//! hints. TideFS delegates all page-cache behavior to the kernel; this
//! adapter accepts the call and returns success. The kernel's
//! page-cache layers apply default advice behavior.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::{Errno, InodeId, RequestCtx};

impl<E> KmodPosixVfs<E> {
    /// Accept `posix_fadvise(2)` advisory calls and return success.
    ///
    /// The kernel's page cache handles all advice semantics; TideFS
    /// does not need custom handling.
    pub fn fadvise(
        &self,
        _inode: InodeId,
        _offset: u64,
        _len: u64,
        _advice: u32,
        _ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;

    #[test]
    fn fadvise_willneed_returns_ok() {
        let kmod = KmodPosixVfs::new(MockEngine::new());
        kmod.fadvise(
            InodeId::new(1),
            0,
            4096,
            3, // POSIX_FADV_WILLNEED
            &MockEngine::test_ctx(),
        )
        .unwrap();
    }

    #[test]
    fn fadvise_dontneed_returns_ok() {
        let kmod = KmodPosixVfs::new(MockEngine::new());
        kmod.fadvise(
            InodeId::new(1),
            0,
            4096,
            4, // POSIX_FADV_DONTNEED
            &MockEngine::test_ctx(),
        )
        .unwrap();
    }

    #[test]
    fn fadvise_noreuse_returns_ok() {
        let kmod = KmodPosixVfs::new(MockEngine::new());
        kmod.fadvise(
            InodeId::new(1),
            0,
            4096,
            5, // POSIX_FADV_NOREUSE
            &MockEngine::test_ctx(),
        )
        .unwrap();
    }

    #[test]
    fn fadvise_normal_returns_ok() {
        let kmod = KmodPosixVfs::new(MockEngine::new());
        kmod.fadvise(
            InodeId::new(1),
            0,
            4096,
            0, // POSIX_FADV_NORMAL
            &MockEngine::test_ctx(),
        )
        .unwrap();
    }
}
