//! Extent allocation dispatch for the kernel VFS adapter -- K7-24
//! writeback extent-provisioning seam.
//!
//! Provides `AllocateExtentsPlan` for kernel-mode extent allocation.
//! The writeback path uses this dispatch to provision new blocks for
//! extending writes without userspace intervention.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::{AllocateExtentsOutcome, VfsEngine};
use tidefs_kmod_bridge::kernel_types::{Errno, InodeId, RequestCtx};

// -- AllocateExtentsPlan ---

/// Operation result for a kernel VFS extent allocation.
///
/// Captures the target inode, allocation range, and the engine
/// outcome (bytes allocated, completion status).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocateExtentsPlan {
    /// Inode for which extents are allocated.
    pub inode: InodeId,
    /// Starting byte offset of the allocation request.
    pub offset: u64,
    /// Length in bytes requested for allocation.
    pub length: u64,
    /// Number of bytes actually allocated.
    pub bytes_allocated: u64,
    /// Whether the full request was satisfied.
    pub complete: bool,
}

impl AllocateExtentsPlan {
    /// Create an AllocateExtentsPlan capturing the operation result fields.
    pub fn new(inode: InodeId, offset: u64, length: u64, outcome: AllocateExtentsOutcome) -> Self {
        Self {
            inode,
            offset,
            length,
            bytes_allocated: outcome.bytes_allocated,
            complete: outcome.complete,
        }
    }
}

// -- dispatch ---

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Kernel VFS extent allocation dispatch.
    ///
    /// Provisions `length` bytes of new backing storage starting at `offset`
    /// for `inode`. Delegates to `VfsEngine::allocate_extents` via the
    /// extent_ops_bridge for intent-log crash-safety.
    /// Returns an `AllocateExtentsPlan` on success.
    ///
    /// # Errors
    /// - `ENOSPC`: no free space for allocation
    /// - `EIO`: storage error
    /// - `EBADF`: inode does not exist
    /// - `EINVAL`: invalid offset/length
    pub fn allocate_extents(
        &self,
        inode: InodeId,
        offset: u64,
        length: u64,
        ctx: &RequestCtx,
    ) -> Result<AllocateExtentsPlan, Errno> {
        let outcome = crate::extent_ops_bridge::bridge_allocate_extents(
            &self.engine,
            inode,
            offset,
            length,
            ctx,
        )?;
        Ok(AllocateExtentsPlan::new(inode, offset, length, outcome))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;

    fn ctx() -> RequestCtx {
        RequestCtx {
            uid: 1000,
            gid: 1000,
            pid: 42,
            umask: 0o022,
            groups: crate::TideVec::from([1000].as_slice()),
        }
    }

    #[test]
    fn allocate_extents_works() {
        let ino = InodeId::new(10);
        let mut e = MockEngine::new();
        let outcome = AllocateExtentsOutcome::new(4096, true);
        e.allocate_extents_fn = Box::new(move |i, off, len, _| {
            assert_eq!(i, InodeId::new(10));
            assert_eq!(off, 0);
            assert_eq!(len, 8192);
            Ok(outcome)
        });
        let plan = KmodPosixVfs::new(e)
            .allocate_extents(ino, 0, 8192, &ctx())
            .unwrap();
        assert_eq!(plan.inode, ino);
        assert_eq!(plan.offset, 0);
        assert_eq!(plan.length, 8192);
        assert_eq!(plan.bytes_allocated, 4096);
        assert!(plan.complete);
    }

    #[test]
    fn allocate_extents_enospc_propagates() {
        let mut e = MockEngine::new();
        e.allocate_extents_fn = Box::new(|_, _, _, _| Err(Errno::ENOSPC));
        assert_eq!(
            KmodPosixVfs::new(e)
                .allocate_extents(InodeId::new(10), 0, 4096, &ctx())
                .unwrap_err(),
            Errno::ENOSPC,
        );
    }

    #[test]
    fn allocate_extents_eio_propagates() {
        let mut e = MockEngine::new();
        e.allocate_extents_fn = Box::new(|_, _, _, _| Err(Errno::EIO));
        assert_eq!(
            KmodPosixVfs::new(e)
                .allocate_extents(InodeId::new(10), 0, 4096, &ctx())
                .unwrap_err(),
            Errno::EIO,
        );
    }

    #[test]
    fn allocate_extents_partial() {
        let mut e = MockEngine::new();
        let outcome = AllocateExtentsOutcome::new(2048, false);
        e.allocate_extents_fn = Box::new(move |_, _, _, _| Ok(outcome));
        let plan = KmodPosixVfs::new(e)
            .allocate_extents(InodeId::new(10), 0, 8192, &ctx())
            .unwrap();
        assert_eq!(plan.bytes_allocated, 2048);
        assert!(!plan.complete);
    }

    #[test]
    fn allocate_extents_ebadf_propagates() {
        let mut e = MockEngine::new();
        e.allocate_extents_fn = Box::new(|_, _, _, _| Err(Errno::EBADF));
        assert_eq!(
            KmodPosixVfs::new(e)
                .allocate_extents(InodeId::new(99), 0, 4096, &ctx())
                .unwrap_err(),
            Errno::EBADF,
        );
    }

    #[test]
    fn allocate_extents_einval_propagates() {
        let mut e = MockEngine::new();
        e.allocate_extents_fn = Box::new(|_, _, _, _| Err(Errno::EINVAL));
        assert_eq!(
            KmodPosixVfs::new(e)
                .allocate_extents(InodeId::new(10), u64::MAX, 4096, &ctx())
                .unwrap_err(),
            Errno::EINVAL,
        );
    }
}
