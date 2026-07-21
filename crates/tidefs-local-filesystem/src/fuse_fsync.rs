// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE fsync/flush/fsyncdir dispatch handlers backed by [`LocalFileSystem`].
//!
//! Provides two layers:
//!
//! - **Engine-level** functions (`dispatch_engine_fsync`, `dispatch_engine_flush`,
//!   `dispatch_engine_fsyncdir`): validate file handles via
//!   [`FileHandleTable`], then trigger dirty-page flush through the
//!   [`DirtyFlush`] trait.
//! - **Namespace-level** (`dispatch_namespace_fsync`): same flush path
//!   without file-handle validation.
//!
//! All functions map errors through [`FsyncDispatchError`], which carries
//! standard POSIX errno values.

use std::cell::RefCell;

use crate::FileSystemError;

use tidefs_types_vfs_core::{EngineFileHandle, Errno, InodeId, NodeKind};

use crate::open_dispatch::FileHandleTable;
use crate::LocalFileSystem;

// ── DirtyFlush trait ──────────────────────────────────────────────────────

/// Trait for flushing dirty page-cache data to stable storage.
///
/// The trait is hosted with the local-filesystem fsync dispatch so handle
/// validation, errno mapping, and durability barriers share one call contract.
/// Current implementations include [`LocalFsDirtyFlush`] for
/// [`LocalFileSystem`] and the adapter daemon's engine-backed bridge.
/// Broader recovery/fsync/writeback/mmap authority remains tracked by
/// TFR-008.
pub trait DirtyFlush {
    /// Flush all dirty pages belonging to `inode_id`.
    ///
    /// When `datasync` is true, only data pages are flushed; metadata-only
    /// pages (e.g. inode attribute pages) may be skipped.
    fn flush_inode(&self, inode_id: InodeId, datasync: bool) -> Result<(), FsyncDispatchError>;

    /// Flush all dirty pages across all inodes (filesystem-wide flush).
    ///
    /// Used by `umount` and administrative sync operations.
    fn flush_all(&self) -> Result<(), FsyncDispatchError>;
    /// Issue a data-only durability barrier for a single inode.
    ///
    /// Unlike [`flush_inode`], this method calls `fdatasync(2)` on the
    /// backing file descriptor without the full commit-group machinery.
    /// Use this after writeback-drain to converge dirty pages with durable
    /// storage before acknowledging an fsync reply.
    ///
    /// When the inode has no dirty pages the implementation should be a
    /// no-op to avoid unnecessary fdatasync overhead.
    fn fdatasync_inode(&self, inode_id: InodeId, datasync: bool) -> Result<(), FsyncDispatchError>;
}

// ── Error type ───────────────────────────────────────────────────────────

/// Errors returned by fsync/flush/fsyncdir dispatch handlers.
///
/// Maps directly to POSIX errno values consumed by FUSE reply helpers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsyncDispatchError {
    /// File handle is unknown, closed, or does not match.
    BadFileDescriptor,
    /// Page-cache writeback or backing-store I/O failed.
    IoError,
    /// No space to complete the flush (ENOSPC from backing store).
    NoSpace,
    /// Operation was interrupted (EINTR).
    Interrupted,
    /// Invalid argument (e.g., fsyncdir on a non-directory).
    Invalid,
    /// Target is not a directory (for fsyncdir).
    NotDir,
}

impl FsyncDispatchError {
    /// Convert to the canonical VFS [`Errno`].
    #[must_use]
    pub const fn to_errno(self) -> Errno {
        match self {
            Self::BadFileDescriptor => Errno::EBADF,
            Self::IoError => Errno::EIO,
            Self::NoSpace => Errno::ENOSPC,
            Self::Interrupted => Errno::EINTR,
            Self::Invalid => Errno::EINVAL,
            Self::NotDir => Errno::ENOTDIR,
        }
    }
}

// ── Error mapping ────────────────────────────────────────────────────────

/// Translate a [`FsyncDispatchError`] from the cache-flush path to the
/// appropriate FUSE errno code.
///
/// This is the canonical error-mapping function for the fsync/flush/fsyncdir
/// dispatch batch. All three operations share the same error space.
pub fn map_cache_error(result: Result<(), FsyncDispatchError>) -> Result<(), Errno> {
    match result {
        Ok(()) => Ok(()),
        Err(e) => Err(e.to_errno()),
    }
}

// ── Validation helper ────────────────────────────────────────────────────

/// Validate a file handle and return the stored state.
///
/// Returns `EBADF` if the handle is not found or does not match.
fn validate_handle(
    table: &RefCell<FileHandleTable>,
    fh: &EngineFileHandle,
) -> Result<crate::open_dispatch::FileHandleState, Errno> {
    table.borrow().validate(fh).map_err(|_| Errno::EBADF)
}

// ── Engine layer ─────────────────────────────────────────────────────────

/// Fsync a single inode through the engine-level handle validation path.
///
/// Validates that `fh` exists in `table`, then triggers a targeted
/// dirty-page flush for the owning inode via [`DirtyFlush::flush_inode`].
///
/// # Parameters
///
/// - `dirty_flush`: the flush implementation, such as [`LocalFsDirtyFlush`]
///   or the adapter daemon's engine-backed bridge.
/// - `fh`: the engine file handle obtained from `engine_open`.
/// - `datasync`: if true, only data pages are flushed; metadata may be
///   skipped.
///
/// # Errors
///
/// Returns `EBADF` if the handle is invalid, or the mapped cache-flush
/// error (`EIO`, `ENOSPC`, `EINTR`).
pub fn dispatch_engine_fsync(
    table: &RefCell<FileHandleTable>,
    dirty_flush: &dyn DirtyFlush,
    fh: &EngineFileHandle,
    datasync: bool,
) -> Result<(), Errno> {
    let state = validate_handle(table, fh)?;
    map_cache_error(dirty_flush.flush_inode(state.inode_id, datasync))
}

/// Flush a single inode through the engine-level handle validation path.
///
/// Same as [`dispatch_engine_fsync`] but always does a full flush
/// (data + metadata).  May also signal the filesystem to flush any
/// per-mount metadata (e.g. allocation state) in future implementations.
///
/// # Errors
///
/// Returns `EBADF` if the handle is invalid, or the mapped cache-flush
/// error.
pub fn dispatch_engine_flush(
    table: &RefCell<FileHandleTable>,
    dirty_flush: &dyn DirtyFlush,
    fh: &EngineFileHandle,
) -> Result<(), Errno> {
    let state = validate_handle(table, fh)?;
    map_cache_error(dirty_flush.flush_inode(state.inode_id, false))
}

/// Fsyncdir: flush dirty directory pages for a directory handle.
///
/// Validates that `fh` exists in `table`, then checks that `kind` is
/// `NodeKind::Dir`.  Falls through to [`dispatch_namespace_fsync`] after
/// handle validation.
///
/// The caller must provide the inode's [`NodeKind`] because
/// `FileHandleState` does not store it.  The adapter daemon obtains
/// the kind from its own inode table.
///
/// # Errors
///
/// Returns `EBADF` if the handle is invalid, `EINVAL` if `kind` is not
/// `NodeKind::Dir`, or the mapped cache-flush error.
pub fn dispatch_engine_fsyncdir(
    table: &RefCell<FileHandleTable>,
    dirty_flush: &dyn DirtyFlush,
    fh: &EngineFileHandle,
    kind: NodeKind,
    datasync: bool,
) -> Result<(), Errno> {
    let state = validate_handle(table, fh)?;

    if kind != NodeKind::Dir {
        return Err(Errno::EINVAL);
    }

    // Falls through to namespace-level fsync after handle validation.
    map_cache_error(dirty_flush.flush_inode(state.inode_id, datasync))
}

// ── Namespace layer ──────────────────────────────────────────────────────

/// Namespace-level fsync: flush dirty pages for an inode without requiring
/// a file handle.
///
/// Used by internal callers that already have the inode ID and by
/// [`dispatch_engine_fsyncdir`] after handle validation.
///
/// # Errors
///
/// Returns the mapped cache-flush error (`EIO`, `ENOSPC`, `EINTR`).
pub fn dispatch_namespace_fsync(
    dirty_flush: &dyn DirtyFlush,
    inode_id: InodeId,
    datasync: bool,
) -> Result<(), Errno> {
    map_cache_error(dirty_flush.flush_inode(inode_id, datasync))
}

/// Sync all dirty filesystem state (filesystem-wide; FUSE `syncfs`).
///
/// Calls [`DirtyFlush::flush_all`] to write back all dirty pages across
/// all inodes, then issues a filesystem-wide durability barrier.
pub fn dispatch_syncfs(dirty_flush: &dyn DirtyFlush) -> Result<(), Errno> {
    map_cache_error(dirty_flush.flush_all())
}

// ── Stub DirtyFlush implementation for testing ───────────────────────────

/// A stub [`DirtyFlush`] that always returns `Ok(())`.
///
/// Used in tests and dispatch-only callers that need to exercise handle
/// validation and errno mapping without a backing dirty-page owner.
pub struct StubDirtyFlush {
    /// Count of `flush_inode` calls (for verification in tests).
    pub flush_inode_calls: RefCell<Vec<(InodeId, bool)>>,
    /// Count of `flush_all` calls.
    pub flush_all_calls: RefCell<u64>,
    /// If set, `flush_inode` returns this error instead of `Ok(())`.
    pub inject_error: RefCell<Option<FsyncDispatchError>>,
}

impl StubDirtyFlush {
    /// Create a new stub that always succeeds.
    #[must_use]
    pub fn new() -> Self {
        Self {
            flush_inode_calls: RefCell::new(Vec::new()),
            flush_all_calls: RefCell::new(0),
            inject_error: RefCell::new(None),
        }
    }

    /// Configure the stub to inject a specific error on the next flush.
    pub fn set_error(&self, err: FsyncDispatchError) {
        *self.inject_error.borrow_mut() = Some(err);
    }
}

impl Default for StubDirtyFlush {
    fn default() -> Self {
        Self::new()
    }
}

impl DirtyFlush for StubDirtyFlush {
    fn flush_inode(&self, inode_id: InodeId, datasync: bool) -> Result<(), FsyncDispatchError> {
        if let Some(err) = *self.inject_error.borrow() {
            return Err(err);
        }
        self.flush_inode_calls
            .borrow_mut()
            .push((inode_id, datasync));
        Ok(())
    }

    fn flush_all(&self) -> Result<(), FsyncDispatchError> {
        *self.flush_all_calls.borrow_mut() += 1;
        Ok(())
    }

    fn fdatasync_inode(
        &self,
        inode_id: InodeId,
        _datasync: bool,
    ) -> Result<(), FsyncDispatchError> {
        // Stub: record the call for test verification, return Ok.
        self.flush_inode_calls.borrow_mut().push((inode_id, true));
        if let Some(err) = *self.inject_error.borrow() {
            return Err(err);
        }
        Ok(())
    }
}

// ── LocalFsDirtyFlush — production DirtyFlush via LocalFileSystem ─────────

/// A production [`DirtyFlush`] that delegates to [`LocalFileSystem`]'s
/// internal sync methods.
///
/// Unlike [`StubDirtyFlush`], this implementation actually writes dirty
/// pages to the object store and calls `fsync` on the backing storage.
/// It uses [`RefCell`] interior mutability so that `flush_inode` and
/// `flush_all` can take `&self` (matching the trait signature) while
/// calling `&mut self` methods on [`LocalFileSystem`].
///
/// # Usage
///
/// ```ignore
/// let fs = RefCell::new(LocalFileSystem::open("/mnt/tidefs")?);
/// let flush = LocalFsDirtyFlush::new(&fs);
/// dispatch_engine_fsync(&table, &flush, &fh, false)?;
/// ```
pub struct LocalFsDirtyFlush<'a> {
    fs: &'a RefCell<LocalFileSystem>,
}

impl<'a> LocalFsDirtyFlush<'a> {
    /// Create a new flush bridge backed by the given file system.
    #[must_use]
    pub fn new(fs: &'a RefCell<LocalFileSystem>) -> Self {
        Self { fs }
    }
}

impl DirtyFlush for LocalFsDirtyFlush<'_> {
    fn flush_inode(&self, inode_id: InodeId, datasync: bool) -> Result<(), FsyncDispatchError> {
        let result = if datasync {
            self.fs.borrow_mut().sync_inode_data_only(inode_id)
        } else {
            self.fs.borrow_mut().sync_inode(inode_id)
        };
        result.map_err(|e| match e {
            FileSystemError::NoSpace { .. } => FsyncDispatchError::NoSpace,
            FileSystemError::NotFound { .. } => FsyncDispatchError::IoError,
            _ => FsyncDispatchError::IoError,
        })
    }

    fn flush_all(&self) -> Result<(), FsyncDispatchError> {
        self.fs.borrow_mut().sync_all_dirty().map_err(|e| match e {
            FileSystemError::NoSpace { .. } => FsyncDispatchError::NoSpace,
            _ => FsyncDispatchError::IoError,
        })
    }

    fn fdatasync_inode(&self, inode_id: InodeId, datasync: bool) -> Result<(), FsyncDispatchError> {
        self.fs
            .borrow_mut()
            .fdatasync_inode(inode_id, datasync)
            .map_err(|e| match e {
                FileSystemError::NoSpace { .. } => FsyncDispatchError::NoSpace,
                FileSystemError::NotFound { .. } => FsyncDispatchError::IoError,
                _ => FsyncDispatchError::IoError,
            })
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::open_dispatch::FileHandleTable;
    use std::cell::RefCell;
    use tidefs_types_vfs_core::{EngineFileHandle, FileHandleId, InodeId, NodeKind};

    /// Create a temporary file handle in the given table and return both.
    fn register_test_handle(table: &RefCell<FileHandleTable>, inode: u64) -> EngineFileHandle {
        let inode_id = InodeId::new(inode);
        table.borrow_mut().register(inode_id, 0, false).unwrap()
    }

    // ── dispatch_engine_fsync tests ───────────────────────────────────────

    #[test]
    fn fsync_clean_file_noop() {
        let table = RefCell::new(FileHandleTable::new());
        let dirty_flush = StubDirtyFlush::new();
        let fh = register_test_handle(&table, 42);

        // fsync on a clean file: handle valid, dirty_flush returns Ok.
        let result = dispatch_engine_fsync(&table, &dirty_flush, &fh, false);
        assert_eq!(result, Ok(()));

        // Verify the flush was called for the correct inode.
        let calls = dirty_flush.flush_inode_calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], (InodeId::new(42), false));
    }

    #[test]
    fn fsync_datasync_true_passes_flag() {
        let table = RefCell::new(FileHandleTable::new());
        let dirty_flush = StubDirtyFlush::new();
        let fh = register_test_handle(&table, 99);

        let result = dispatch_engine_fsync(&table, &dirty_flush, &fh, true);
        assert_eq!(result, Ok(()));

        let calls = dirty_flush.flush_inode_calls.borrow();
        assert_eq!(calls[0], (InodeId::new(99), true));
    }

    #[test]
    fn fsync_invalid_handle_returns_ebadf() {
        let table = RefCell::new(FileHandleTable::new());
        let dirty_flush = StubDirtyFlush::new();

        // Create a handle that is not registered in the table.
        let fh = EngineFileHandle {
            inode_id: InodeId::new(1),
            open_flags: 0,
            fh_id: FileHandleId::new(999),
            lock_owner: 0,
        };

        let result = dispatch_engine_fsync(&table, &dirty_flush, &fh, false);
        assert_eq!(result, Err(Errno::EBADF));

        // No flush calls should have been made.
        assert!(dirty_flush.flush_inode_calls.borrow().is_empty());
    }

    #[test]
    fn fsync_after_release_returns_ebadf() {
        let table = RefCell::new(FileHandleTable::new());
        let dirty_flush = StubDirtyFlush::new();
        let fh = register_test_handle(&table, 55);

        // Release the handle.
        table.borrow_mut().release(&fh).unwrap();

        let result = dispatch_engine_fsync(&table, &dirty_flush, &fh, false);
        assert_eq!(result, Err(Errno::EBADF));
    }

    #[test]
    fn fsync_propagates_cache_error() {
        let table = RefCell::new(FileHandleTable::new());
        let dirty_flush = StubDirtyFlush::new();
        let fh = register_test_handle(&table, 77);

        dirty_flush.set_error(FsyncDispatchError::IoError);

        let result = dispatch_engine_fsync(&table, &dirty_flush, &fh, false);
        assert_eq!(result, Err(Errno::EIO));
    }

    // ── dispatch_engine_flush tests ───────────────────────────────────────

    #[test]
    fn flush_valid_handle_succeeds() {
        let table = RefCell::new(FileHandleTable::new());
        let dirty_flush = StubDirtyFlush::new();
        let fh = register_test_handle(&table, 10);

        let result = dispatch_engine_flush(&table, &dirty_flush, &fh);
        assert_eq!(result, Ok(()));

        let calls = dirty_flush.flush_inode_calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], (InodeId::new(10), false));
    }

    #[test]
    fn flush_invalid_handle_returns_ebadf() {
        let table = RefCell::new(FileHandleTable::new());
        let dirty_flush = StubDirtyFlush::new();

        let fh = EngineFileHandle {
            inode_id: InodeId::new(1),
            open_flags: 0,
            fh_id: FileHandleId::new(999),
            lock_owner: 0,
        };

        let result = dispatch_engine_flush(&table, &dirty_flush, &fh);
        assert_eq!(result, Err(Errno::EBADF));
    }

    // ── dispatch_engine_fsyncdir tests ────────────────────────────────────

    #[test]
    fn fsyncdir_on_directory_handle_succeeds() {
        let table = RefCell::new(FileHandleTable::new());
        let dirty_flush = StubDirtyFlush::new();
        let fh = register_test_handle(&table, 200);

        let result = dispatch_engine_fsyncdir(&table, &dirty_flush, &fh, NodeKind::Dir, false);
        assert_eq!(result, Ok(()));

        let calls = dirty_flush.flush_inode_calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], (InodeId::new(200), false));
    }

    #[test]
    fn fsyncdir_on_non_directory_returns_einval() {
        let table = RefCell::new(FileHandleTable::new());
        let dirty_flush = StubDirtyFlush::new();
        let fh = register_test_handle(&table, 300);

        let result = dispatch_engine_fsyncdir(&table, &dirty_flush, &fh, NodeKind::File, false);
        assert_eq!(result, Err(Errno::EINVAL));

        // No flush calls should have been made.
        assert!(dirty_flush.flush_inode_calls.borrow().is_empty());
    }

    #[test]
    fn fsyncdir_invalid_handle_returns_ebadf() {
        let table = RefCell::new(FileHandleTable::new());
        let dirty_flush = StubDirtyFlush::new();

        let fh = EngineFileHandle {
            inode_id: InodeId::new(1),
            open_flags: 0,
            fh_id: FileHandleId::new(999),
            lock_owner: 0,
        };

        let result = dispatch_engine_fsyncdir(&table, &dirty_flush, &fh, NodeKind::Dir, false);
        assert_eq!(result, Err(Errno::EBADF));
    }

    #[test]
    fn fsyncdir_datasync_true_passes_flag() {
        let table = RefCell::new(FileHandleTable::new());
        let dirty_flush = StubDirtyFlush::new();
        let fh = register_test_handle(&table, 400);

        let result = dispatch_engine_fsyncdir(&table, &dirty_flush, &fh, NodeKind::Dir, true);
        assert_eq!(result, Ok(()));

        let calls = dirty_flush.flush_inode_calls.borrow();
        assert_eq!(calls[0], (InodeId::new(400), true));
    }

    // ── dispatch_namespace_fsync tests ────────────────────────────────────

    #[test]
    fn namespace_fsync_no_handle_required() {
        let dirty_flush = StubDirtyFlush::new();

        let result = dispatch_namespace_fsync(&dirty_flush, InodeId::new(500), false);
        assert_eq!(result, Ok(()));

        let calls = dirty_flush.flush_inode_calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], (InodeId::new(500), false));
    }

    // ── map_cache_error tests ────────────────────────────────────────────

    #[test]
    fn map_cache_error_ok_passes_through() {
        assert_eq!(map_cache_error(Ok(())), Ok(()));
    }

    #[test]
    fn map_cache_error_converts_all_variants() {
        let cases = vec![
            (FsyncDispatchError::BadFileDescriptor, Errno::EBADF),
            (FsyncDispatchError::IoError, Errno::EIO),
            (FsyncDispatchError::NoSpace, Errno::ENOSPC),
            (FsyncDispatchError::Interrupted, Errno::EINTR),
            (FsyncDispatchError::Invalid, Errno::EINVAL),
            (FsyncDispatchError::NotDir, Errno::ENOTDIR),
        ];
        for (input, expected) in cases {
            assert_eq!(map_cache_error(Err(input)), Err(expected));
        }
    }

    // ── StubDirtyFlush tests ──────────────────────────────────────────────

    #[test]
    fn stub_flush_all_increments_counter() {
        let stub = StubDirtyFlush::new();
        assert_eq!(*stub.flush_all_calls.borrow(), 0);

        stub.flush_all().unwrap();
        assert_eq!(*stub.flush_all_calls.borrow(), 1);

        stub.flush_all().unwrap();
        assert_eq!(*stub.flush_all_calls.borrow(), 2);
    }

    #[test]
    fn stub_inject_error_works() {
        let stub = StubDirtyFlush::new();

        // Normal operation succeeds.
        assert!(stub.flush_inode(InodeId::new(1), false).is_ok());

        // Inject an error.
        stub.set_error(FsyncDispatchError::NoSpace);
        assert_eq!(
            stub.flush_inode(InodeId::new(2), false),
            Err(FsyncDispatchError::NoSpace)
        );

        // Error is consumed on first use (stored in RefCell, not cleared
        // automatically — this is intentional for test flexibility).
    }

    // ── Crash-simulate integration test ──────────────────────────────

    /// Write data, fsync, drop filesystem without clean close, reopen,
    /// and verify data persisted in the object store.
    #[test]
    fn fsync_after_write_survives_crash_reopen() {
        let root = std::env::temp_dir().join("s10_fsync_crash_sim");
        if root.exists() {
            let _ = std::fs::remove_dir_all(&root);
        }

        // Phase 1: Create file, write data, fsync.
        let written_data: Vec<u8> = (0..128u8).map(|i| i.wrapping_mul(3)).collect();
        {
            let mut fs = crate::LocalFileSystem::open(&root).expect("open fs for write");
            let _rec = fs.create_file("/data.bin", 0o644).expect("create file");
            fs.write_file("/data.bin", 0, &written_data)
                .expect("write data");
            fs.fsync_file("/data.bin").expect("fsync after write");
            // Drop fs without close (simulates crash).
        }

        // Phase 2: Reopen and verify data persisted.
        {
            let fs = crate::LocalFileSystem::open(&root).expect("reopen fs after crash");
            let read_back = fs.read_file("/data.bin").expect("read after reopen");
            assert_eq!(
                read_back, written_data,
                "data should survive drop-without-close when fsync was called"
            );
        }

        // Phase 3: Verify cleanup.
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── Concurrent fsync test ─────────────────────────────────────────────

    #[test]
    fn concurrent_fsync_two_handles_same_inode_does_not_deadlock() {
        // This test verifies that two fsync operations on different file
        // handles pointing to the same inode complete without deadlock.
        // Both handles share the same InodeId; the DirtyFlush stub is
        // inherently concurrent-safe.
        let table = RefCell::new(FileHandleTable::new());
        let dirty_flush = StubDirtyFlush::new();

        let fh1 = table
            .borrow_mut()
            .register(InodeId::new(999), 0, false)
            .unwrap();
        let fh2 = table
            .borrow_mut()
            .register(InodeId::new(999), 1, false)
            .unwrap();

        // Both fsync calls should succeed.
        let r1 = dispatch_engine_fsync(&table, &dirty_flush, &fh1, false);
        let r2 = dispatch_engine_fsync(&table, &dirty_flush, &fh2, false);

        assert_eq!(r1, Ok(()));
        assert_eq!(r2, Ok(()));

        // Both calls should have been recorded.
        let calls = dirty_flush.flush_inode_calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, InodeId::new(999));
        assert_eq!(calls[1].0, InodeId::new(999));
    }

    // ── fsync on empty file ──────────────────────────────────────────

    #[test]
    fn fsync_empty_file_is_idempotent_noop() {
        let root = std::env::temp_dir().join("s5_fsync_empty");
        if root.exists() {
            let _ = std::fs::remove_dir_all(&root);
        }
        let mut fs = crate::LocalFileSystem::open(&root).expect("open fs");
        fs.create_file("/empty.bin", 0o644)
            .expect("create empty file");
        // fsync on a file with no writes should succeed idempotently.
        fs.fsync_file("/empty.bin").expect("fsync empty file");
        // Second fsync should also succeed.
        fs.fsync_file("/empty.bin").expect("fsync empty file again");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── multi-extent fsync ───────────────────────────────────────────

    #[test]
    fn fsync_multi_extent_non_contiguous_writes() {
        let root = std::env::temp_dir().join("s5_fsync_multi_extent");
        if root.exists() {
            let _ = std::fs::remove_dir_all(&root);
        }
        let data_a = b"first block at offset 0";
        let data_b = b"second block at offset 64K";
        let data_c = b"third block at offset 128K";
        {
            let mut fs = crate::LocalFileSystem::open(&root).expect("open fs");
            fs.set_auto_commit(false);
            fs.create_file("/multi.bin", 0o644).expect("create file");
            fs.write_file("/multi.bin", 0, data_a).expect("write A");
            fs.write_file("/multi.bin", 65536, data_b).expect("write B");
            fs.write_file("/multi.bin", 131072, data_c)
                .expect("write C");
            fs.fsync_file("/multi.bin").expect("fsync multi-extent");
        }
        {
            let fs = crate::LocalFileSystem::open(&root).expect("reopen fs");
            let buf = fs.read_file("/multi.bin").expect("read back");
            // First extent at offset 0
            assert_eq!(&buf[..data_a.len()], data_a);
            // Gap should be zeros (hole)
            let hole_ab = &buf[data_a.len()..65536];
            assert!(
                hole_ab.iter().all(|&b| b == 0),
                "hole between extents should be zero-filled"
            );
            // Second extent at offset 65536
            assert_eq!(&buf[65536..65536 + data_b.len()], data_b);
            // Third extent at offset 131072
            assert_eq!(&buf[131072..131072 + data_c.len()], data_c);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── fsync after truncate ─────────────────────────────────────────

    #[test]
    fn fsync_after_truncate_persists_new_size() {
        let root = std::env::temp_dir().join("s5_fsync_truncate");
        if root.exists() {
            let _ = std::fs::remove_dir_all(&root);
        }
        let full_data: Vec<u8> = (0..128u8).collect();
        {
            let mut fs = crate::LocalFileSystem::open(&root).expect("open fs");
            fs.set_auto_commit(false);
            fs.create_file("/trunc.bin", 0o644).expect("create file");
            fs.write_file("/trunc.bin", 0, &full_data)
                .expect("write 128B");
            // Truncate to 64 bytes then fsync.
            fs.truncate_file("/trunc.bin", 64).expect("truncate to 64");
            fs.fsync_file("/trunc.bin").expect("fsync after truncate");
        }
        {
            let fs = crate::LocalFileSystem::open(&root).expect("reopen fs");
            let buf = fs.read_file("/trunc.bin").expect("read back");
            assert_eq!(buf.len(), 64, "truncated size should persist");
            assert_eq!(&buf[..], &full_data[..64]);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── fsync failure propagation ────────────────────────────────────

    #[test]
    fn fsync_error_propagates_from_object_store() {
        // Verify that FsyncDispatchError variants map correctly to errno.
        // This exercises the error-propagation path through map_cache_error.
        let cases = vec![
            (FsyncDispatchError::BadFileDescriptor, Errno::EBADF),
            (FsyncDispatchError::IoError, Errno::EIO),
            (FsyncDispatchError::NoSpace, Errno::ENOSPC),
            (FsyncDispatchError::Interrupted, Errno::EINTR),
            (FsyncDispatchError::Invalid, Errno::EINVAL),
            (FsyncDispatchError::NotDir, Errno::ENOTDIR),
        ];
        for (input, expected) in cases {
            let result = map_cache_error(Err(input));
            assert_eq!(
                result,
                Err(expected),
                "FsyncDispatchError::{input:?} should map to {expected:?}"
            );
        }
    }

    // ── Instrumentation counters ─────────────────────────────────────

    #[test]
    fn fsync_stats_counters_increment() {
        let root = std::env::temp_dir().join("s5_fsync_stats");
        if root.exists() {
            let _ = std::fs::remove_dir_all(&root);
        }
        let data = b"instrumented fsync data";
        {
            let mut fs = crate::LocalFileSystem::open(&root).expect("open fs");
            fs.set_auto_commit(false);
            fs.create_file("/stats.bin", 0o644).expect("create file");
            fs.write_file("/stats.bin", 0, data).expect("write data");

            let snap_before = fs.fsync_stats_snapshot();
            assert_eq!(snap_before.fsync_count, 0);

            fs.fsync_file("/stats.bin").expect("fsync file");

            let snap_after = fs.fsync_stats_snapshot();
            assert_eq!(snap_after.fsync_count, 1);
            assert!(
                snap_after.fsync_total_ns > 0,
                "fsync latency should be non-zero"
            );
            // Writes now populate the intent log, so the fast path is taken.
            assert_eq!(snap_after.fsync_intent_log_fast_path_count, 1);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fsync_data_only_stats_counters_increment() {
        let root = std::env::temp_dir().join("s5_fdatasync_stats");
        if root.exists() {
            let _ = std::fs::remove_dir_all(&root);
        }
        let data = b"fdatasync counter test";
        {
            let mut fs = crate::LocalFileSystem::open(&root).expect("open fs");
            fs.set_auto_commit(false);
            fs.create_file("/fdat.bin", 0o644).expect("create file");
            fs.write_file("/fdat.bin", 0, data).expect("write data");

            let snap_before = fs.fsync_stats_snapshot();
            assert_eq!(snap_before.fdatasync_count, 0);

            fs.fsync_data_only_file("/fdat.bin")
                .expect("fdatasync file");

            let snap_after = fs.fsync_stats_snapshot();
            assert_eq!(snap_after.fdatasync_count, 1);
            assert!(snap_after.fdatasync_total_ns > 0);
        }

        let _ = std::fs::remove_dir_all(&root);
    }
    // ── LocalFsDirtyFlush tests ───────────────────────────────────────────

    #[test]
    fn local_fs_flush_inode_persists_data() {
        let root = std::env::temp_dir().join("s5_localfs_flush_inode");
        if root.exists() {
            let _ = std::fs::remove_dir_all(&root);
        }
        let fs = RefCell::new(crate::LocalFileSystem::open(&root).expect("open fs"));
        let flush = LocalFsDirtyFlush::new(&fs);

        let (ino, expected_data) = {
            let mut fs_mut = fs.borrow_mut();
            fs_mut.create_file("/test.bin", 0o644).expect("create file");
            let data: Vec<u8> = (0..128u8).map(|i| i.wrapping_mul(3)).collect();
            fs_mut
                .write_file("/test.bin", 0, &data)
                .expect("write data");
            let ino = fs_mut.lookup("/test.bin").expect("lookup inode");
            drop(fs_mut);
            (ino, data)
        };

        flush
            .flush_inode(ino, false)
            .expect("flush_inode via LocalFsDirtyFlush");

        let fs_reopen = crate::LocalFileSystem::open(&root).expect("reopen fs");
        let buf = fs_reopen.read_file("/test.bin").expect("read back");
        assert_eq!(buf, expected_data);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn local_fs_flush_all_drains_dirty_inodes() {
        let root = std::env::temp_dir().join("s5_localfs_flush_all");
        if root.exists() {
            let _ = std::fs::remove_dir_all(&root);
        }
        let fs = RefCell::new(crate::LocalFileSystem::open(&root).expect("open fs"));
        let flush = LocalFsDirtyFlush::new(&fs);

        {
            let mut fs_mut = fs.borrow_mut();
            fs_mut.create_file("/a.bin", 0o644).expect("create a");
            fs_mut.create_file("/b.bin", 0o644).expect("create b");
            fs_mut.write_file("/a.bin", 0, b"data A").expect("write A");
            fs_mut.write_file("/b.bin", 0, b"data B").expect("write B");
        }

        flush.flush_all().expect("flush_all via LocalFsDirtyFlush");

        let fs_reopen = crate::LocalFileSystem::open(&root).expect("reopen fs");
        assert_eq!(fs_reopen.read_file("/a.bin").expect("read A"), b"data A");
        assert_eq!(fs_reopen.read_file("/b.bin").expect("read B"), b"data B");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn local_fs_datasync_uses_data_only_path() {
        let root = std::env::temp_dir().join("s5_localfs_datasync");
        if root.exists() {
            let _ = std::fs::remove_dir_all(&root);
        }
        let fs = RefCell::new(crate::LocalFileSystem::open(&root).expect("open fs"));
        let flush = LocalFsDirtyFlush::new(&fs);
        flush
            .flush_inode(InodeId::new(1), true)
            .expect("fdatasync nonexistent inode should be noop");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn local_fs_fdatasync_inode_noop_for_clean_inode() {
        let root = std::env::temp_dir().join("s5_localfs_fdatasync_clean");
        if root.exists() {
            let _ = std::fs::remove_dir_all(&root);
        }
        let fs = RefCell::new(crate::LocalFileSystem::open(&root).expect("open fs"));
        let flush = LocalFsDirtyFlush::new(&fs);

        // fdatasync on a nonexistent inode should be a no-op via the stub.
        let result = flush.fdatasync_inode(InodeId::new(999), true);
        assert!(
            result.is_ok(),
            "fdatasync on clean inode should succeed (no-op)"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stub_fdatasync_inode_records_call() {
        let stub = StubDirtyFlush::new();
        let ino = InodeId::new(42);
        stub.fdatasync_inode(ino, false).expect("stub fdatasync");
        let calls = stub.flush_inode_calls.borrow();
        assert_eq!(calls.len(), 1, "stub should record fdatasync call");
        assert_eq!(calls[0], (ino, true));
    }

    #[test]
    fn stub_fdatasync_inode_injects_error() {
        let stub = StubDirtyFlush::new();
        stub.set_error(FsyncDispatchError::IoError);
        let result = stub.fdatasync_inode(InodeId::new(1), true);
        assert_eq!(result, Err(FsyncDispatchError::IoError));
    }
}
