//! fallocate space-management delegation for the kernel VFS adapter -- K7-16.
//!
//! Provides typed [`FallocateMode`] classification, [`FallocatePlan`]
//! operation record, and the canonical [`KmodPosixVfs::fallocate`] dispatch
//! bridging kernel VFS `file_operations::fallocate` to [`VfsEngine`].

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::intent_record::encode_fallocate_intent;
use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{EngineFileHandle, Errno, RequestCtx};

// ---------------------------------------------------------------------------
// FallocateMode -- typed fallocate operation classification
// ---------------------------------------------------------------------------

/// Kernel `fallocate(2)` operation kind derived from Linux FALLOC_FL_* flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FallocateMode {
    /// Allocate space (default, no special flag or FALLOC_FL_KEEP_SIZE only).
    Allocate,
    /// Punch a hole: deallocate backed storage (FALLOC_FL_PUNCH_HOLE).
    PunchHole,
    /// Zero a range: ensure the range reads as zeroes (FALLOC_FL_ZERO_RANGE).
    ZeroRange,
    /// Collapse a range: remove a range and shift subsequent data left
    /// (FALLOC_FL_COLLAPSE_RANGE).
    CollapseRange,
    /// Insert a range: shift data right to create a hole (FALLOC_FL_INSERT_RANGE).
    InsertRange,
}

impl FallocateMode {
    /// Classify a raw Linux `fallocate(2)` mode flags word.
    ///
    /// Ignores `FALLOC_FL_KEEP_SIZE` (0x01) and `FALLOC_FL_UNSHARE_RANGE`
    /// (0x40) for classification; extracts the primary operation kind.
    pub fn from_flags(flags: u32) -> Self {
        if flags & 0x02 != 0 {
            // FALLOC_FL_PUNCH_HOLE
            Self::PunchHole
        } else if flags & 0x10 != 0 {
            // FALLOC_FL_ZERO_RANGE
            Self::ZeroRange
        } else if flags & 0x08 != 0 {
            // FALLOC_FL_COLLAPSE_RANGE
            Self::CollapseRange
        } else if flags & 0x20 != 0 {
            // FALLOC_FL_INSERT_RANGE
            Self::InsertRange
        } else {
            Self::Allocate
        }
    }
}

// ---------------------------------------------------------------------------
// FallocatePlan -- kernel VFS fallocate operation record
// ---------------------------------------------------------------------------

/// Operation record for a kernel VFS `fallocate(2)` dispatch.
///
/// Captures the file handle, classified mode, offset, and length of a
/// successful space-management operation delegated to [`VfsEngine`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FallocatePlan {
    /// File handle for the target file.
    pub fh: EngineFileHandle,
    /// Classified fallocate operation mode.
    pub mode: FallocateMode,
    /// Byte offset into the file.
    pub offset: u64,
    /// Length of the range in bytes.
    pub length: u64,
}

impl FallocatePlan {
    /// Create a new [`FallocatePlan`] from the operation parameters.
    pub fn new(fh: &EngineFileHandle, mode: FallocateMode, offset: u64, length: u64) -> Self {
        Self {
            fh: fh.clone(),
            mode,
            offset,
            length,
        }
    }
}

// ---------------------------------------------------------------------------
// KmodPosixVfs fallocate dispatch
// ---------------------------------------------------------------------------

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Reserve, punch, zero, collapse, or insert a range in a file.
    ///
    /// Delegates to [`VfsEngine::fallocate`] with the file handle, raw
    /// Linux mode flags, offset, length, and caller context. On success,
    /// returns a [`FallocatePlan`] recording the operation parameters.
    ///
    /// The [`FallocatePlan::mode`] field classifies the raw flags into a
    /// typed [`FallocateMode`] variant for testability and validation
    /// recording.
    pub fn fallocate(
        &self,
        fh: &EngineFileHandle,
        mode: u32,
        offset: u64,
        length: u64,
        ctx: &RequestCtx,
    ) -> Result<FallocatePlan, Errno> {
        // Record fallocate-intent before space preallocation for crash-safety.
        let entry = encode_fallocate_intent(fh.inode_id, mode, offset, length);
        self.record_mutation_intent(&entry)?;
        self.engine.fallocate(fh, mode, offset, length, ctx)?;
        Ok(FallocatePlan::new(
            fh,
            FallocateMode::from_flags(mode),
            offset,
            length,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;

    fn fh() -> EngineFileHandle {
        EngineFileHandle {
            inode_id: tidefs_kmod_bridge::kernel_types::InodeId::new(10),
            open_flags: 0o2,
            fh_id: tidefs_kmod_bridge::kernel_types::FileHandleId::new(1),
            lock_owner: 0,
        }
    }

    // -- FallocateMode::from_flags unit tests -------------------------

    #[test]
    fn mode_allocate_on_zero_flags() {
        assert_eq!(FallocateMode::from_flags(0), FallocateMode::Allocate);
    }

    #[test]
    fn mode_allocate_with_keep_size() {
        // FALLOC_FL_KEEP_SIZE alone -> Allocate
        assert_eq!(FallocateMode::from_flags(0x01), FallocateMode::Allocate);
    }

    #[test]
    fn mode_punch_hole() {
        assert_eq!(FallocateMode::from_flags(0x02), FallocateMode::PunchHole);
    }

    #[test]
    fn mode_punch_hole_with_keep_size() {
        assert_eq!(FallocateMode::from_flags(0x03), FallocateMode::PunchHole);
    }

    #[test]
    fn mode_zero_range() {
        assert_eq!(FallocateMode::from_flags(0x10), FallocateMode::ZeroRange);
    }

    #[test]
    fn mode_collapse_range() {
        assert_eq!(
            FallocateMode::from_flags(0x08),
            FallocateMode::CollapseRange
        );
    }

    #[test]
    fn mode_insert_range() {
        assert_eq!(FallocateMode::from_flags(0x20), FallocateMode::InsertRange);
    }

    // -- FallocatePlan unit tests ------------------------------------

    #[test]
    fn plan_roundtrip_fields() {
        let f = fh();
        let plan = FallocatePlan::new(&f, FallocateMode::Allocate, 0, 4096);
        assert_eq!(plan.fh.inode_id, f.inode_id);
        assert_eq!(plan.mode, FallocateMode::Allocate);
        assert_eq!(plan.offset, 0);
        assert_eq!(plan.length, 4096);
    }

    #[test]
    fn plan_punch_hole_mode_preserved() {
        let f = fh();
        let plan = FallocatePlan::new(&f, FallocateMode::PunchHole, 8192, 16384);
        assert_eq!(plan.mode, FallocateMode::PunchHole);
        assert_eq!(plan.offset, 8192);
        assert_eq!(plan.length, 16384);
    }

    // -- fallocate dispatch tests (updated for FallocatePlan) --------

    #[test]
    fn fallocate_works() {
        let f = fh();
        let mut e = MockEngine::new();
        e.fallocate_fn = Box::new(move |got_fh, mode, offset, length, _| {
            assert_eq!(got_fh.inode_id, f.inode_id);
            assert_eq!(mode, 0);
            assert_eq!(offset, 0);
            assert_eq!(length, 4096);
            Ok(())
        });
        let plan = KmodPosixVfs::new(e)
            .fallocate(&f, 0, 0, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.mode, FallocateMode::Allocate);
        assert_eq!(plan.offset, 0);
        assert_eq!(plan.length, 4096);
    }

    #[test]
    fn fallocate_ebadf_propagates() {
        let mut e = MockEngine::new();
        e.fallocate_fn = Box::new(|_, _, _, _, _| Err(Errno::EBADF));
        assert_eq!(
            KmodPosixVfs::new(e)
                .fallocate(&fh(), 0, 0, 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EBADF,
        );
    }

    #[test]
    fn fallocate_einval_propagates() {
        let mut e = MockEngine::new();
        e.fallocate_fn = Box::new(|_, _, _, _, _| Err(Errno::EINVAL));
        assert_eq!(
            KmodPosixVfs::new(e)
                .fallocate(&fh(), 0, 0, 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EINVAL,
        );
    }

    #[test]
    fn fallocate_eacces_propagates() {
        let mut e = MockEngine::new();
        e.fallocate_fn = Box::new(|_, _, _, _, _| Err(Errno::EACCES));
        assert_eq!(
            KmodPosixVfs::new(e)
                .fallocate(&fh(), 0, 0, 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EACCES,
        );
    }

    #[test]
    fn fallocate_erofs_propagates() {
        let mut e = MockEngine::new();
        e.fallocate_fn = Box::new(|_, _, _, _, _| Err(Errno::EROFS));
        assert_eq!(
            KmodPosixVfs::new(e)
                .fallocate(&fh(), 0, 0, 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EROFS,
        );
    }

    #[test]
    fn fallocate_enospc_propagates() {
        let mut e = MockEngine::new();
        e.fallocate_fn = Box::new(|_, _, _, _, _| Err(Errno::ENOSPC));
        assert_eq!(
            KmodPosixVfs::new(e)
                .fallocate(&fh(), 0, 0, 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOSPC,
        );
    }

    #[test]
    fn fallocate_eio_propagates() {
        let mut e = MockEngine::new();
        e.fallocate_fn = Box::new(|_, _, _, _, _| Err(Errno::EIO));
        assert_eq!(
            KmodPosixVfs::new(e)
                .fallocate(&fh(), 0, 0, 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EIO,
        );
    }

    #[test]
    fn fallocate_preserves_mode_and_range() {
        let f = fh();
        let mut e = MockEngine::new();
        e.fallocate_fn = Box::new(move |got_fh, m, off, len, _| {
            assert_eq!(m, 0x01); // FALLOC_FL_KEEP_SIZE
            assert_eq!(off, 8192);
            assert_eq!(len, 16384);
            assert_eq!(got_fh.inode_id, f.inode_id);
            Ok(())
        });
        let plan = KmodPosixVfs::new(e)
            .fallocate(&f, 0x01, 8192, 16384, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.mode, FallocateMode::Allocate);
        assert_eq!(plan.offset, 8192);
        assert_eq!(plan.length, 16384);
    }

    #[test]
    fn fallocate_punch_hole_mode_classified() {
        let f = fh();
        let mut e = MockEngine::new();
        e.fallocate_fn = Box::new(|_, _, _, _, _| Ok(()));
        let plan = KmodPosixVfs::new(e)
            .fallocate(&f, 0x03, 4096, 8192, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.mode, FallocateMode::PunchHole);
    }

    #[test]
    fn fallocate_zero_range_mode_classified() {
        let f = fh();
        let mut e = MockEngine::new();
        e.fallocate_fn = Box::new(|_, _, _, _, _| Ok(()));
        let plan = KmodPosixVfs::new(e)
            .fallocate(&f, 0x10, 0, 16384, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.mode, FallocateMode::ZeroRange);
    }

    #[test]
    fn fallocate_collapse_range_mode_classified() {
        let f = fh();
        let mut e = MockEngine::new();
        e.fallocate_fn = Box::new(|_, _, _, _, _| Ok(()));
        let plan = KmodPosixVfs::new(e)
            .fallocate(&f, 0x08, 4096, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.mode, FallocateMode::CollapseRange);
    }

    #[test]
    fn fallocate_insert_range_mode_classified() {
        let f = fh();
        let mut e = MockEngine::new();
        e.fallocate_fn = Box::new(|_, _, _, _, _| Ok(()));
        let plan = KmodPosixVfs::new(e)
            .fallocate(&f, 0x20, 8192, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.mode, FallocateMode::InsertRange);
    }
}
