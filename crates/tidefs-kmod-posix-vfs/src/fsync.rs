//! Fsync and fsyncdir durability flush for the kernel VFS adapter --
//! K7-15 durability flush seam.
//! This module provides:
//! - [`KmodPosixVfs::fsync`] / [`KmodPosixVfs::fsyncdir`]: thin VfsEngine
//!   delegation for file and directory durability flush.
//! - [`KmodPosixVfs::fsync_range`]: enhanced fsync path that produces a
//!   [`FsyncCommit`] anchoring the inode, txg, and byte
//!   range to the committed state.
//!   kernel VFS fsync/fdatasync durability. The digest covers (inode ||
//!   committed_txg || range_start || range_end || datasync), matching
//!   the Linux 7.0 file_operations::fsync(loff_t start, loff_t end, int
//!   datasync) signature.
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;
use crate::TideVec as Vec;

use crate::writeback::DirtyFolioTracker;
use crate::{KmodPosixVfs, OpenFileState};
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{
    EngineDirHandle, EngineFileHandle, Errno, InodeId, RequestCtx,
};

/// Maximum byte range to writeback in one chunk during pre-fsync dirty-page flush.
const FSYNC_WRITEBACK_CHUNK: u64 = 1_048_576; // 1 MiB

// ---------------------------------------------------------------------------
// FsyncCommit -- BLAKE3-verified fsync durability validation
// ---------------------------------------------------------------------------

/// A fsync commitment binding the inode, committed
///
/// This is the kernel VFS equivalent of intent-log commit validation:
/// after a successful fsync/fdatasync through VfsEngine, the kmod
/// adapter produces a [`FsyncCommit`] that can be retained as crash-
/// consistency proof or compared against a post-replay anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsyncCommit {
    /// Inode that was synchronized.
    pub inode: InodeId,
    /// Committed transaction group at fsync time.
    ///
    /// Currently forwarded from the caller; the VfsEngine trait does
    /// not yet expose the txg to callers, so this is zero when the
    /// engine does not provide it. Future engine revisions should
    /// populate this from the committed-root anchor.
    pub committed_txg: u64,
    /// Start of the synced byte range (inclusive).  Zero means
    /// "beginning of file" for a full-file fsync.
    pub range_start: u64,
    /// End of the synced byte range (inclusive).  `u64::MAX` means
    /// "end of file" for a full-file fsync (matching the Linux VFS
    /// convention where LLONG_MAX signals EOF).
    pub range_end: u64,
    /// Whether this was a datasync-only flush (`fdatasync`).
    pub datasync: bool,
}

impl FsyncCommit {
    /// Create a new fsync commit from the given parameters.
    pub fn new(
        inode: InodeId,
        committed_txg: u64,
        range_start: u64,
        range_end: u64,
        datasync: bool,
    ) -> Self {
        Self {
            inode,
            committed_txg,
            range_start,
            range_end,
            datasync,
        }
    }

    /// Full-file fsync convenience: range_start=0, range_end=u64::MAX.
    pub fn full_file(inode: InodeId, committed_txg: u64, datasync: bool) -> Self {
        Self::new(inode, committed_txg, 0, u64::MAX, datasync)
    }

    /// Return the byte ranges covered by this commit.
    ///
    /// A full-file fsync (range_start == 0 && range_end == u64::MAX)
    /// returns an empty vec, meaning "entire file".
    pub fn ranges(&self) -> Vec<(u64, u64)> {
        if self.range_start == 0 && self.range_end == u64::MAX {
            Vec::new()
        } else {
            Vec::from([(self.range_start, self.range_end)])
        }
    }
}

// ---------------------------------------------------------------------------
// KmodPosixVfs fsync / fsyncdir methods
// ---------------------------------------------------------------------------

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Synchronize file data and metadata for `fh`.
    ///
    /// If `datasync` is true, only data and metadata needed to retrieve the
    /// data (size, mtime) must be flushed; other metadata may be skipped.
    /// Delegates to VfsEngine::fsync.
    ///
    /// For commit validation, use [`fsync_range`] instead.
    pub fn fsync(
        &self,
        fh: &EngineFileHandle,
        datasync: bool,
        ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        self.engine.fsync(fh, datasync, ctx)?;
        self.commit_fs_barrier()
    }

    /// Synchronize a byte range of `fh` and return a BLAKE3-verified
    /// [`FsyncCommit`] as durability validation.
    ///
    /// This is the enhanced fsync path matching the Linux 7.0
    /// `file_operations::fsync(struct file *file, loff_t start,
    /// loff_t end, int datasync)` signature. It delegates the
    /// durability flush to [`VfsEngine::fsync`] and then produces a
    /// domain-separated BLAKE3 commitment covering the inode,
    /// transaction group, byte range, and datasync flag.
    ///
    /// Use `range_start = 0, range_end = u64::MAX` for a full-file
    /// fsync (matching the Linux VFS convention of LLONG_MAX for EOF).
    /// Use [`fsync`] when commit validation is not required.
    pub fn fsync_range(
        &self,
        fh: &EngineFileHandle,
        range_start: u64,
        range_end: u64,
        datasync: bool,
        ctx: &RequestCtx,
        committed_txg: u64,
    ) -> Result<FsyncCommit, Errno> {
        self.engine.fsync(fh, datasync, ctx)?;
        self.commit_fs_barrier()?;
        Ok(FsyncCommit::new(
            fh.inode_id,
            committed_txg,
            range_start,
            range_end,
            datasync,
        ))
    }

    /// Synchronize directory metadata for `dh`.
    ///
    /// If `datasync` is true, only the directory's entry data must be
    /// flushed; other metadata may be skipped.
    /// Delegates to VfsEngine::fsyncdir.
    pub fn fsyncdir(
        &self,
        dh: &EngineDirHandle,
        datasync: bool,
        ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        self.engine.fsyncdir(dh, datasync, ctx)
    }
}
// ---------------------------------------------------------------------------
// Source-model bridge functions for file_operations-shaped fsync wiring
// ---------------------------------------------------------------------------

/// Source-model bridge from kernel file_operations::fsync to VfsEngine::fsync.
///
/// Resolves the OpenFileState (kernel file->private_data), flushes
/// dirty source-model address_space ranges through the provided
/// DirtyFolioTracker (when available), then calls VfsEngine::fsync to request
/// a transaction-group commit barrier. The mounted C shim does not use this
/// tracker for mmap dirties; it calls `filemap_write_and_wait_range()` and the
/// registered C `writepages` callback before `tidefs_posix_vfs_engine_fsync()`.
///
/// When datasync is true, only data and the metadata needed to retrieve
/// it (size, mtime) must be flushed; other metadata may be skipped.
///
/// start and end define the byte range to synchronize. When both are
/// zero (start == 0 && end == 0), the kernel VFS signals a full-file
/// fsync; the VfsEngine::fsync call makes no range distinction.
///
/// The .fasync file_operations member should be set to None in the
/// kernel vtable; fasync is for asynchronous I/O notifications and is
/// not required for fsync correctness.
///
/// # No-daemon boundary
///
/// All fsync operations resolve locally within kernel authority through
/// VfsEngine. No userspace daemon is required.
pub fn bridge_fsync<E: VfsEngine + ?Sized>(
    engine: &E,
    session: &OpenFileState,
    tracker: Option<&mut DirtyFolioTracker>,
    _start: i64,
    _end: i64,
    datasync: bool,
    ctx: &RequestCtx,
) -> Result<(), Errno> {
    // Flush dirty address_space pages for this inode before the engine
    // durability barrier, so all dirty data enters the intent-log pipeline.
    if let Some(tracker) = tracker {
        let dirty_ranges = tracker.drain_inode(session.inode);
        for range in &dirty_ranges {
            let mut offset = range.offset;
            let remaining = range.length as u64;
            let mut written = 0u64;
            while written < remaining {
                let chunk = (remaining - written).min(FSYNC_WRITEBACK_CHUNK);
                let chunk_size = u32::try_from(chunk).unwrap_or(u32::MAX);
                let data = engine.read(&session.handle, offset, chunk_size, ctx)?;
                if data.is_empty() {
                    break;
                }
                let n = engine.write(&session.handle, offset, &data, ctx)?;
                written += n as u64;
                offset += n as u64;
                if n == 0 {
                    break;
                }
            }
        }
    }

    engine.fsync(&session.handle, datasync, ctx)
}

/// Bridge kernel file_operations::fdatasync -- equivalent to
/// bridge_fsync with datasync = true.
pub fn bridge_fdatasync<E: VfsEngine + ?Sized>(
    engine: &E,
    session: &OpenFileState,
    tracker: Option<&mut DirtyFolioTracker>,
    ctx: &RequestCtx,
) -> Result<(), Errno> {
    bridge_fsync(engine, session, tracker, 0, 0, true, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use tidefs_kmod_bridge::kernel_types::{
        DirHandleId, EngineDirHandle, EngineFileHandle, FileHandleId, InodeId,
    };

    fn make_fh() -> EngineFileHandle {
        EngineFileHandle::new(InodeId::new(1), 0, FileHandleId(0), 0)
    }

    fn make_dh() -> EngineDirHandle {
        EngineDirHandle::new(InodeId::new(1), DirHandleId(0))
    }

    // -- FsyncCommit unit tests ---------------------------------------

    #[test]
    fn fsync_commit_partial_range() {
        let c = FsyncCommit::new(InodeId::new(5), 2, 1024, 2048, false);
        let ranges = c.ranges();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], (1024, 2048));
    }

    #[test]
    fn fsync_commit_full_file_convenience() {
        let c = FsyncCommit::full_file(InodeId::new(10), 3, true);
        assert_eq!(c.inode, InodeId::new(10));
        assert_eq!(c.committed_txg, 3);
        assert_eq!(c.range_start, 0);
        assert_eq!(c.range_end, u64::MAX);
        assert!(c.datasync);
    }

    // -- fsync delegation tests (existing) ----------------------------

    #[test]
    fn fsync_works() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        let fh2 = fh;
        e.fsync_fn = Box::new(move |fh, datasync, _ctx| {
            assert_eq!(fh, &fh2);
            assert!(!datasync);
            Ok(())
        });
        KmodPosixVfs::new(e)
            .fsync(&fh, false, &MockEngine::test_ctx())
            .unwrap();
    }

    #[test]
    fn fsync_datasync_flag() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        let fh2 = fh;
        e.fsync_fn = Box::new(move |fh, datasync, _ctx| {
            assert_eq!(fh, &fh2);
            assert!(datasync);
            Ok(())
        });
        KmodPosixVfs::new(e)
            .fsync(&fh, true, &MockEngine::test_ctx())
            .unwrap();
    }

    #[test]
    fn fsync_eio_propagates() {
        let mut e = MockEngine::new();
        e.fsync_fn = Box::new(|_, _, _| Err(Errno::EIO));
        let fh = make_fh();
        assert_eq!(
            KmodPosixVfs::new(e)
                .fsync(&fh, false, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EIO,
        );
    }

    #[test]
    fn fsync_ebadf_propagates() {
        let mut e = MockEngine::new();
        e.fsync_fn = Box::new(|_, _, _| Err(Errno::EBADF));
        let fh = make_fh();
        assert_eq!(
            KmodPosixVfs::new(e)
                .fsync(&fh, false, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EBADF,
        );
    }

    #[test]
    fn fsyncdir_works() {
        let mut e = MockEngine::new();
        let dh = make_dh();
        let dh2 = dh;
        e.fsyncdir_fn = Box::new(move |dh, datasync, _ctx| {
            assert_eq!(dh, &dh2);
            assert!(!datasync);
            Ok(())
        });
        KmodPosixVfs::new(e)
            .fsyncdir(&dh, false, &MockEngine::test_ctx())
            .unwrap();
    }

    #[test]
    fn fsyncdir_datasync_flag() {
        let mut e = MockEngine::new();
        let dh = make_dh();
        let dh2 = dh;
        e.fsyncdir_fn = Box::new(move |dh, datasync, _ctx| {
            assert_eq!(dh, &dh2);
            assert!(datasync);
            Ok(())
        });
        KmodPosixVfs::new(e)
            .fsyncdir(&dh, true, &MockEngine::test_ctx())
            .unwrap();
    }

    #[test]
    fn fsyncdir_eio_propagates() {
        let mut e = MockEngine::new();
        e.fsyncdir_fn = Box::new(|_, _, _| Err(Errno::EIO));
        let dh = make_dh();
        assert_eq!(
            KmodPosixVfs::new(e)
                .fsyncdir(&dh, false, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EIO,
        );
    }

    #[test]
    fn fsyncdir_enotdir_propagates() {
        let mut e = MockEngine::new();
        e.fsyncdir_fn = Box::new(|_, _, _| Err(Errno::ENOTDIR));
        let dh = make_dh();
        assert_eq!(
            KmodPosixVfs::new(e)
                .fsyncdir(&dh, false, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOTDIR,
        );
    }

    // -- fsync_on_readonly_fd -----------------------------------------

    #[test]
    fn fsync_on_readonly_fd_returns_ero() {
        let mut e = MockEngine::new();
        e.fsync_fn = Box::new(|_, _, _| Err(Errno::EROFS));
        let fh = make_fh();
        assert_eq!(
            KmodPosixVfs::new(e)
                .fsync(&fh, false, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EROFS,
        );
    }

    #[test]
    fn fsync_range_on_readonly_fd_returns_ero() {
        let mut e = MockEngine::new();
        e.fsync_fn = Box::new(|_, _, _| Err(Errno::EROFS));
        let fh = make_fh();
        assert_eq!(
            KmodPosixVfs::new(e)
                .fsync_range(&fh, 0, u64::MAX, false, &MockEngine::test_ctx(), 0)
                .unwrap_err(),
            Errno::EROFS,
        );
    }

    // -- fsync_after_write_sequence -----------------------------------

    #[test]
    fn fsync_after_write_sequence() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        let fh2 = fh;
        let data = b"write-then-fsync payload";

        e.write_fn = Box::new(move |fh, off, data_in, _| {
            assert_eq!(fh.inode_id, InodeId::new(1));
            assert_eq!(off, 0);
            assert_eq!(data_in, data);
            Ok(data.len() as u32)
        });
        e.fsync_fn = Box::new(move |fh, datasync, _| {
            assert_eq!(fh, &fh2);
            assert!(!datasync);
            Ok(())
        });

        let kmod = KmodPosixVfs::new(e);
        let written = kmod.write(&fh, 0, data, &MockEngine::test_ctx()).unwrap();
        assert_eq!(written, data.len() as u32);
        kmod.fsync(&fh, false, &MockEngine::test_ctx()).unwrap();
    }

    #[test]
    fn fsync_range_after_write_with_commit_validation() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        let fh2 = fh;

        e.write_fn = Box::new(move |fh, off, data_in, _| {
            assert_eq!(fh.inode_id, InodeId::new(1));
            assert_eq!(off, 0);
            Ok(data_in.len() as u32)
        });
        e.fsync_fn = Box::new(move |fh, datasync, _| {
            assert_eq!(fh, &fh2);
            assert!(!datasync);
            Ok(())
        });

        let kmod = KmodPosixVfs::new(e);
        kmod.write(&fh, 0, b"payload", &MockEngine::test_ctx())
            .unwrap();
        let commit = kmod
            .fsync_range(&fh, 0, u64::MAX, false, &MockEngine::test_ctx(), 7)
            .unwrap();
        assert_eq!(commit.inode, InodeId::new(1));
        assert_eq!(commit.committed_txg, 7);
    }
    // -- bridge_fsync tests --------------------------------------------

    fn make_session(ino: u64, fh_id: u64) -> OpenFileState {
        OpenFileState {
            handle: EngineFileHandle::new(InodeId::new(ino), 0, FileHandleId(fh_id), 0),
            inode: InodeId::new(ino),
            flags: 0,
        }
    }

    #[test]
    fn bridge_fsync_delegates_to_engine() {
        let mut e = MockEngine::new();
        let session = make_session(42, 1);
        let handle = session.handle;
        e.fsync_fn = Box::new(move |fh, ds, _| {
            assert_eq!(fh, &handle);
            assert!(!ds);
            Ok(())
        });
        bridge_fsync(&e, &session, None, 0, 0, false, &MockEngine::test_ctx()).unwrap();
    }

    #[test]
    fn bridge_fsync_datasync_forwarded() {
        let mut e = MockEngine::new();
        let session = make_session(10, 2);
        e.fsync_fn = Box::new(|_, ds, _| {
            assert!(ds);
            Ok(())
        });
        bridge_fsync(&e, &session, None, 0, 0, true, &MockEngine::test_ctx()).unwrap();
    }

    #[test]
    fn bridge_fsync_eio_propagated() {
        let mut e = MockEngine::new();
        let session = make_session(1, 1);
        e.fsync_fn = Box::new(|_, _, _| Err(Errno::EIO));
        assert_eq!(
            bridge_fsync(&e, &session, None, 0, 0, false, &MockEngine::test_ctx()).unwrap_err(),
            Errno::EIO,
        );
    }

    #[test]
    fn bridge_fdatasync_uses_datasync_true() {
        let mut e = MockEngine::new();
        let session = make_session(7, 3);
        e.fsync_fn = Box::new(|_, ds, _| {
            assert!(ds);
            Ok(())
        });
        bridge_fdatasync(&e, &session, None, &MockEngine::test_ctx()).unwrap();
    }
}
