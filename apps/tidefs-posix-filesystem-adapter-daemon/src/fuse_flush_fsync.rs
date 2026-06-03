//! FUSE flush/fsync dispatch with PageCache writeback and dirty-extent commit.
//!
//! This module provides the FUSE flush and fsync dispatch handlers that drain
//! the PageCache dirty set for a target inode, commit dirty extents through
//! the extent-map write path, and return appropriate POSIX errno outcomes.
//!
//! The flush path (FUSE opcode 25) drains data for a single file handle;
//! the fsync path (FUSE opcode 26) does the same with an optional datasync
//! flag controlling whether metadata is also forced to stable storage.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use crate::workers_writeback::DirtyPageTracker;
use tidefs_cache_core::page_cache::PageCache;
use tidefs_cache_core::page_cache::PageFlushError;
use tidefs_types_vfs_core::{
    EngineFileHandle, Errno, FileHandleId, InodeId, OpenFlags, RequestCtx,
};
use tidefs_vfs_engine::VfsEngine;

// ---------------------------------------------------------------------------
// FileHandle — the handle context required by flush/fsync dispatch
// ---------------------------------------------------------------------------

/// A resolved file handle carrying the inode, open flags, and the engine
/// handle identity fields needed to construct an [`EngineFileHandle`].
///
/// This is the contract that [#3558] will satisfy through a full handle table.
#[derive(Clone, Debug)]
pub struct FileHandle {
    /// The inode this handle refers to.
    pub inode: InodeId,
    /// Open flags (O_RDONLY, O_WRONLY, O_RDWR, etc.).
    pub open_flags: OpenFlags,
    /// Engine file-handle identifier assigned during open.
    pub fh_id: u64,
    /// Lock owner for POSIX lock tracking.
    pub lock_owner: u64,
}

impl FileHandle {
    /// Create a new file handle.
    #[must_use]
    pub const fn new(inode: InodeId, open_flags: OpenFlags, fh_id: u64, lock_owner: u64) -> Self {
        Self {
            inode,
            open_flags,
            fh_id,
            lock_owner,
        }
    }

    /// Convert to an [`EngineFileHandle`] suitable for the VfsEngine trait.
    #[must_use]
    pub fn to_engine_file_handle(&self) -> EngineFileHandle {
        EngineFileHandle::new(
            self.inode,
            self.open_flags,
            FileHandleId::new(self.fh_id),
            self.lock_owner,
        )
    }
}

// ---------------------------------------------------------------------------
// HandleTable trait — minimal contract for handle resolution
// ---------------------------------------------------------------------------

/// Minimal handle-table trait for resolving FUSE file-handle ids to
/// [`FileHandle`] references.
///
/// This is the contract that [#3558] will satisfy.  Flush/fsync dispatch
/// uses this to validate that the handle exists and to retrieve the
/// inode + open-flags context.
pub trait HandleTable: Send + Sync {
    /// Resolve `fh` to a shared file handle, or `None` if the handle
    /// is unknown, closed, or invalid.
    fn resolve(&self, fh: u64) -> Option<Arc<FileHandle>>;
}

// ---------------------------------------------------------------------------
// FlushError — errors from dispatch_flush
// ---------------------------------------------------------------------------

/// Errors returned by [`dispatch_flush`].
///
/// Each variant maps to a POSIX errno for the FUSE reply path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlushError {
    /// Handle is unknown or closed (EBADF).
    BadFileDescriptor,
    /// PageCache writeback or engine flush failed (EIO).
    IoError,
    /// Extent-map commit failed due to no space (ENOSPC).
    NoSpace,
    /// Operation was interrupted (EINTR).
    Interrupted,
}

impl FlushError {
    /// Map this error to a POSIX errno value.
    #[must_use]
    pub const fn to_errno(self) -> Errno {
        match self {
            Self::BadFileDescriptor => Errno::EBADF,
            Self::IoError => Errno::EIO,
            Self::NoSpace => Errno::ENOSPC,
            Self::Interrupted => Errno::EINTR,
        }
    }
}

// ---------------------------------------------------------------------------
// FsyncError — errors from dispatch_fsync
// ---------------------------------------------------------------------------

/// Errors returned by [`dispatch_fsync`].
///
/// Same variants as [`FlushError`] with identical errno mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsyncError {
    /// Handle is unknown or closed (EBADF).
    BadFileDescriptor,
    /// PageCache writeback or engine fsync failed (EIO).
    IoError,
    /// Extent-map commit failed due to no space (ENOSPC).
    NoSpace,
    /// Operation was interrupted (EINTR).
    Interrupted,
}

impl FsyncError {
    /// Map this error to a POSIX errno value.
    #[must_use]
    pub const fn to_errno(self) -> Errno {
        match self {
            Self::BadFileDescriptor => Errno::EBADF,
            Self::IoError => Errno::EIO,
            Self::NoSpace => Errno::ENOSPC,
            Self::Interrupted => Errno::EINTR,
        }
    }
}

// ---------------------------------------------------------------------------
// FlushOutcome — public-facing flush result
// ---------------------------------------------------------------------------

/// Outcome of a flush operation, mapped to a FUSE reply errno.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlushOutcome {
    /// Flush completed successfully.
    Success,
    /// Handle is unknown or closed.
    BadFileDescriptor,
    /// No space to complete the flush.
    NoSpace,
    /// I/O error during writeback or extent commit.
    IoError,
    /// Operation was interrupted.
    Interrupted,
}

impl FlushOutcome {
    /// Convert a [`FlushError`] into the corresponding outcome.
    #[must_use]
    pub const fn from_error(err: FlushError) -> Self {
        match err {
            FlushError::BadFileDescriptor => Self::BadFileDescriptor,
            FlushError::IoError => Self::IoError,
            FlushError::NoSpace => Self::NoSpace,
            FlushError::Interrupted => Self::Interrupted,
        }
    }

    /// Map this outcome to a POSIX errno for the FUSE reply.
    #[must_use]
    pub const fn to_errno(self) -> Errno {
        match self {
            Self::Success => Errno::SUCCESS,
            Self::BadFileDescriptor => Errno::EBADF,
            Self::NoSpace => Errno::ENOSPC,
            Self::IoError => Errno::EIO,
            Self::Interrupted => Errno::EINTR,
        }
    }
}

// ---------------------------------------------------------------------------
// FsyncOutcome — public-facing fsync result
// ---------------------------------------------------------------------------

/// Outcome of an fsync operation, mapped to a FUSE reply errno.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsyncOutcome {
    /// Fsync completed successfully.
    Success,
    /// Handle is unknown or closed.
    BadFileDescriptor,
    /// No space to complete the sync.
    NoSpace,
    /// I/O error during writeback or metadata sync.
    IoError,
    /// Operation was interrupted.
    Interrupted,
}

impl FsyncOutcome {
    /// Convert a [`FsyncError`] into the corresponding outcome.
    #[must_use]
    pub const fn from_error(err: FsyncError) -> Self {
        match err {
            FsyncError::BadFileDescriptor => Self::BadFileDescriptor,
            FsyncError::IoError => Self::IoError,
            FsyncError::NoSpace => Self::NoSpace,
            FsyncError::Interrupted => Self::Interrupted,
        }
    }

    /// Map this outcome to a POSIX errno for the FUSE reply.
    #[must_use]
    pub const fn to_errno(self) -> Errno {
        match self {
            Self::Success => Errno::SUCCESS,
            Self::BadFileDescriptor => Errno::EBADF,
            Self::NoSpace => Errno::ENOSPC,
            Self::IoError => Errno::EIO,
            Self::Interrupted => Errno::EINTR,
        }
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// engine_err_to_flush_err — map VFS engine errors to PageFlushError
// ---------------------------------------------------------------------------

/// Convert an engine [`Errno`] to a [`PageFlushError`] for use as the
/// error type in [`PageCache::flush_dirty_range`] write closures.
#[inline]
fn engine_err_to_flush_err(e: Errno) -> PageFlushError {
    match e {
        Errno::ENOSPC => PageFlushError::NoSpace,
        Errno::EINTR => PageFlushError::Interrupted,
        _ => PageFlushError::IoError,
    }
}

// ---------------------------------------------------------------------------
// page_flush_err_to_fsync_dispatch_err — map PageCache errors to dispatch errors
// ---------------------------------------------------------------------------

#[inline]
fn page_flush_err_to_fsync_dispatch_err(e: PageFlushError) -> FsyncDispatchError {
    match e {
        PageFlushError::IoError => FsyncDispatchError::IoError,
        PageFlushError::NoSpace => FsyncDispatchError::NoSpace,
        PageFlushError::Interrupted => FsyncDispatchError::Interrupted,
    }
}

// ---------------------------------------------------------------------------
// dispatch_flush — drain dirty pages and commit for a single file handle
// ---------------------------------------------------------------------------

/// Drain dirty pages for the handle's inode through
/// [`PageCache::flush_dirty_range`], then call `engine.flush()`.
///
/// Dirty pages are written back through the engine's `write` method
/// and marked clean by `flush_dirty_range`.  The engine's `flush`
/// method is then called to commit extent-map dirtiness.
///
/// # Errors
///
/// Returns [`FlushError`] on I/O failure during writeback, ENOSPC from the
/// engine, or if the handle is invalid.
pub fn dispatch_flush(
    handle: &FileHandle,
    engine: &dyn VfsEngine,
    page_cache: Option<&Arc<PageCache>>,
    ctx: &RequestCtx,
) -> Result<(), FlushError> {
    dispatch_flush_with_tracker(handle, engine, page_cache, ctx, None)
}

/// Like [`dispatch_flush`] but with an optional dirty-page tracker
/// for fsync boundary group accounting.
pub fn dispatch_flush_with_tracker(
    handle: &FileHandle,
    engine: &dyn VfsEngine,
    page_cache: Option<&Arc<PageCache>>,
    ctx: &RequestCtx,
    dirty_page_tracker: Option<&Arc<Mutex<DirtyPageTracker>>>,
) -> Result<(), FlushError> {
    let efh = handle.to_engine_file_handle();
    let ino = handle.inode.get();

    // Snapshot the fsync boundary before flushing.
    let boundary_token = dirty_page_tracker
        .as_ref()
        .map(|t| t.lock().unwrap().take_boundary());

    // Phase 1: Writeback dirty pages through the PageCache.
    // flush_dirty_range handles start_writeback, write, and
    // complete_writeback in a single coordinated pass.
    if let Some(wb_cache) = page_cache {
        wb_cache
            .flush_dirty_range(ino, 0, u64::MAX, |offset, data| {
                engine
                    .write(&efh, offset, data, ctx)
                    .map(|_| ())
                    .map_err(engine_err_to_flush_err)
            })
            .map_err(|e| match e {
                PageFlushError::IoError => FlushError::IoError,
                PageFlushError::NoSpace => FlushError::NoSpace,
                PageFlushError::Interrupted => FlushError::Interrupted,
            })?;
    }

    // Phase 2: Commit through the engine flush path.
    engine.flush(&efh, ctx).map_err(|e| {
        if e == Errno::ENOSPC {
            FlushError::NoSpace
        } else if e == Errno::EINTR {
            FlushError::Interrupted
        } else {
            FlushError::IoError
        }
    })?;

    // Clear dirty ranges up to the snapshotted boundary.
    if let (Some(tracker), Some(token)) = (dirty_page_tracker, boundary_token) {
        tracker.lock().unwrap().clear_until_boundary(ino, token);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// dispatch_fsync — drain dirty pages and sync data (+ metadata if !datasync)
// ---------------------------------------------------------------------------

/// Drain dirty pages for the handle's inode through
/// [`PageCache::flush_dirty_range`], then call `engine.fsync()` to
/// force data (and optionally metadata) to stable storage.
///
/// When `datasync` is true, only data is synced; when false, both data and
/// metadata reach stable storage.
///
/// # Errors
///
/// Returns [`FsyncError`] on I/O failure during writeback, ENOSPC from the
/// engine, or if the handle is invalid.
pub fn dispatch_fsync(
    handle: &FileHandle,
    datasync: bool,
    engine: &dyn VfsEngine,
    page_cache: Option<&Arc<PageCache>>,
    ctx: &RequestCtx,
) -> Result<(), FsyncError> {
    dispatch_fsync_with_tracker(handle, datasync, engine, page_cache, ctx, None)
}

/// Like [`dispatch_fsync`] but with an optional dirty-page tracker
/// for fsync boundary group accounting.
pub fn dispatch_fsync_with_tracker(
    handle: &FileHandle,
    datasync: bool,
    engine: &dyn VfsEngine,
    page_cache: Option<&Arc<PageCache>>,
    ctx: &RequestCtx,
    dirty_page_tracker: Option<&Arc<Mutex<DirtyPageTracker>>>,
) -> Result<(), FsyncError> {
    let efh = handle.to_engine_file_handle();
    let ino = handle.inode.get();

    // Snapshot the fsync boundary before flushing.
    let boundary_token = dirty_page_tracker
        .as_ref()
        .map(|t| t.lock().unwrap().take_boundary());

    // Phase 1: Writeback dirty pages through the PageCache.
    // flush_dirty_range handles start_writeback, write, and
    // complete_writeback in a single coordinated pass.
    if let Some(wb_cache) = page_cache {
        wb_cache
            .flush_dirty_range(ino, 0, u64::MAX, |offset, data| {
                engine
                    .write(&efh, offset, data, ctx)
                    .map(|_| ())
                    .map_err(engine_err_to_flush_err)
            })
            .map_err(|e| match e {
                PageFlushError::IoError => FsyncError::IoError,
                PageFlushError::NoSpace => FsyncError::NoSpace,
                PageFlushError::Interrupted => FsyncError::Interrupted,
            })?;
    }

    // Phase 2: Commit through the engine fsync path.
    engine.fsync(&efh, datasync, ctx).map_err(|e| {
        if e == Errno::ENOSPC {
            FsyncError::NoSpace
        } else if e == Errno::EINTR {
            FsyncError::Interrupted
        } else {
            FsyncError::IoError
        }
    })?;

    // Clear dirty ranges up to the snapshotted boundary.
    if let (Some(tracker), Some(token)) = (dirty_page_tracker, boundary_token) {
        tracker.lock().unwrap().clear_until_boundary(ino, token);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// PageCacheDirtyFlush bridge — DirtyFlush adapter for the adapter daemon
// ---------------------------------------------------------------------------

use tidefs_local_filesystem::fuse_fsync::{DirtyFlush, FsyncDispatchError};

/// Implements [`DirtyFlush`] using the adapter daemon's [`PageCache`] and
/// [`VfsEngine`].
///
/// This bridge connects the local-filesystem dispatch layer to the adapter
/// daemon's runtime.  It is constructed per flush/fsync call and holds
/// borrowed references to the adapter's page cache, engine, file handle,
/// and request context.
///
/// The bridge performs two phases:
/// 1. Writeback: iterate dirty [`PageCache`] pages for the target inode,
///    write them through the engine, and mark them clean.
/// 2. Commit: call `engine.flush()` to persist any per-mount state.
///
/// For filesystem-wide flush (`flush_all`), all dirty pages across all
/// inodes are written back.
pub struct PageCacheDirtyFlush<'a> {
    page_cache: Option<&'a Arc<PageCache>>,
    engine: &'a dyn VfsEngine,
    efh: &'a EngineFileHandle,
    ctx: &'a RequestCtx,
    dirty_page_tracker: Option<&'a Arc<Mutex<DirtyPageTracker>>>,
}

impl<'a> PageCacheDirtyFlush<'a> {
    /// Create a new bridge for a flush/fsync operation.
    #[must_use]
    pub fn new(
        page_cache: Option<&'a Arc<PageCache>>,
        engine: &'a dyn VfsEngine,
        efh: &'a EngineFileHandle,
        ctx: &'a RequestCtx,
    ) -> Self {
        Self {
            page_cache,
            engine,
            efh,
            ctx,
            dirty_page_tracker: None,
        }
    }

    /// Attach a shared dirty-page tracker for fsync boundary tracking.
    #[must_use]
    pub fn with_dirty_page_tracker(mut self, tracker: &'a Arc<Mutex<DirtyPageTracker>>) -> Self {
        self.dirty_page_tracker = Some(tracker);
        self
    }
}

impl DirtyFlush for PageCacheDirtyFlush<'_> {
    fn flush_inode(&self, inode_id: InodeId, _datasync: bool) -> Result<(), FsyncDispatchError> {
        let ino = inode_id.get();

        // Snapshot the fsync boundary before flushing.
        let boundary_token = self
            .dirty_page_tracker
            .as_ref()
            .map(|t| t.lock().unwrap().take_boundary());

        // Phase 1: Writeback dirty pages through the PageCache.
        // flush_dirty_range handles start_writeback, write, and
        // complete_writeback in a single coordinated pass.
        if let Some(wb_cache) = self.page_cache {
            wb_cache
                .flush_dirty_range(ino, 0, u64::MAX, |offset, data| {
                    self.engine
                        .write(self.efh, offset, data, self.ctx)
                        .map(|_| ())
                        .map_err(engine_err_to_flush_err)
                })
                .map_err(|e| match e {
                    PageFlushError::IoError => FsyncDispatchError::IoError,
                    PageFlushError::NoSpace => FsyncDispatchError::NoSpace,
                    PageFlushError::Interrupted => FsyncDispatchError::Interrupted,
                })?;
        }

        // Phase 2: Commit through the engine flush path.
        self.engine.flush(self.efh, self.ctx).map_err(|e| {
            if e == Errno::ENOSPC {
                FsyncDispatchError::NoSpace
            } else if e == Errno::EINTR {
                FsyncDispatchError::Interrupted
            } else {
                FsyncDispatchError::IoError
            }
        })?;

        // Clear dirty ranges up to the snapshotted boundary.
        if let (Some(tracker), Some(token)) = (self.dirty_page_tracker, boundary_token) {
            tracker.lock().unwrap().clear_until_boundary(ino, token);
        }

        Ok(())
    }
    fn flush_all(&self) -> Result<(), FsyncDispatchError> {
        // Snapshot the fsync boundary before flushing all inodes.
        let boundary_token = self
            .dirty_page_tracker
            .as_ref()
            .map(|t| t.lock().unwrap().take_boundary());

        // Filesystem-wide flush: drain dirty pages with real writable handles
        // for the inode each page belongs to.  syncfs has no caller file
        // handle, so using the bridge's per-file handle here would either
        // write through the wrong inode or, for synthetic handles, fail handle
        // validation and leave data dirty.
        if let Some(wb_cache) = self.page_cache {
            let all_dirty = wb_cache.dirty_pages();
            let dirty_inodes: BTreeSet<u64> = all_dirty.iter().map(|key| key.inode).collect();
            for ino in dirty_inodes {
                let handle = self
                    .engine
                    .open(InodeId::new(ino), libc::O_RDWR as OpenFlags, self.ctx)
                    .map_err(|e| {
                        page_flush_err_to_fsync_dispatch_err(engine_err_to_flush_err(e))
                    })?;

                let flush_result = wb_cache.flush_dirty_range(ino, 0, u64::MAX, |offset, data| {
                    let written = self
                        .engine
                        .write(&handle, offset, data, self.ctx)
                        .map_err(engine_err_to_flush_err)?;
                    if written as usize == data.len() {
                        Ok(())
                    } else {
                        Err(PageFlushError::IoError)
                    }
                });
                let release_result = self.engine.release(&handle);

                if let Err(e) = flush_result {
                    return Err(page_flush_err_to_fsync_dispatch_err(e));
                }
                if release_result.is_err() {
                    return Err(FsyncDispatchError::IoError);
                }
            }
        }

        // Clear all dirty ranges up to the snapshotted boundary.
        if let (Some(tracker), Some(token)) = (self.dirty_page_tracker, boundary_token) {
            tracker.lock().unwrap().clear_all_until_boundary(token);
        }

        Ok(())
    }
    fn fdatasync_inode(
        &self,
        _inode_id: InodeId,
        datasync: bool,
    ) -> Result<(), FsyncDispatchError> {
        // After writeback drain, issue a lightweight fdatasync on the
        // backing file descriptor via the engine.  This converges dirty
        // pages with durable storage without the full commit-group commit.
        self.engine
            .fdatasync_inode(self.efh, datasync, self.ctx)
            .map_err(|e| {
                if e == Errno::ENOSPC {
                    FsyncDispatchError::NoSpace
                } else if e == Errno::EINTR {
                    FsyncDispatchError::Interrupted
                } else {
                    FsyncDispatchError::IoError
                }
            })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // ── In-memory test engine ──────────────────────

    /// A minimal in-memory VfsEngine test double that tracks flush/fsync calls and can be
    /// configured to return errors.
    struct InMemoryTestEngine {
        pub data: Mutex<HashMap<u64, Vec<u8>>>,
        pub open_calls: Mutex<Vec<(u64, u32)>>, // (inode, flags)
        pub release_calls: Mutex<Vec<(u64, u64)>>, // (inode, fh_id)
        pub write_calls: Mutex<Vec<(u64, u64, u64, usize)>>, // (inode, fh_id, offset, len)
        pub flush_calls: Mutex<Vec<(u64, u64)>>, // (inode, fh_id)
        pub fsync_calls: Mutex<Vec<(u64, u64, bool)>>, // (inode, fh_id, datasync)
        pub open_error: Mutex<Option<Errno>>,
        pub release_error: Mutex<Option<Errno>>,
        pub flush_error: Mutex<Option<Errno>>,
        pub fsync_error: Mutex<Option<Errno>>,
        pub write_error: Mutex<Option<Errno>>,
    }

    impl InMemoryTestEngine {
        fn new() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
                open_calls: Mutex::new(Vec::new()),
                release_calls: Mutex::new(Vec::new()),
                write_calls: Mutex::new(Vec::new()),
                flush_calls: Mutex::new(Vec::new()),
                fsync_calls: Mutex::new(Vec::new()),
                open_error: Mutex::new(None),
                release_error: Mutex::new(None),
                flush_error: Mutex::new(None),
                fsync_error: Mutex::new(None),
                write_error: Mutex::new(None),
            }
        }
    }

    impl VfsEngine for InMemoryTestEngine {
        fn get_root_inode(&self, _ctx: &RequestCtx) -> Result<InodeId, Errno> {
            Ok(InodeId::new(1))
        }

        fn lookup(
            &self,
            _parent: InodeId,
            _name: &[u8],
            _ctx: &RequestCtx,
        ) -> Result<tidefs_vfs_engine::InodeAttr, Errno> {
            Err(Errno::ENOENT)
        }

        fn getattr(
            &self,
            _inode: InodeId,
            _handle: Option<&EngineFileHandle>,
            _ctx: &RequestCtx,
        ) -> Result<tidefs_vfs_engine::InodeAttr, Errno> {
            Err(Errno::ENOENT)
        }

        fn setattr(
            &self,
            _inode: InodeId,
            _attr: &tidefs_vfs_engine::SetAttr,
            _handle: Option<&EngineFileHandle>,
            _ctx: &RequestCtx,
        ) -> Result<tidefs_vfs_engine::InodeAttr, Errno> {
            Err(Errno::ENOENT)
        }

        fn mkdir(
            &self,
            _parent: InodeId,
            _name: &[u8],
            _mode: u32,
            _ctx: &RequestCtx,
        ) -> Result<tidefs_vfs_engine::InodeAttr, Errno> {
            Err(Errno::ENOSPC)
        }

        fn create(
            &self,
            _parent: InodeId,
            _name: &[u8],
            _mode: u32,
            _flags: u32,
            _ctx: &RequestCtx,
        ) -> Result<(tidefs_vfs_engine::InodeAttr, EngineFileHandle), Errno> {
            Err(Errno::ENOSPC)
        }

        fn tmpfile(
            &self,
            _parent: InodeId,
            _mode: u32,
            _flags: u32,
            _ctx: &RequestCtx,
        ) -> Result<(tidefs_vfs_engine::InodeAttr, EngineFileHandle), Errno> {
            Err(Errno::ENOSPC)
        }

        fn unlink(&self, _parent: InodeId, _name: &[u8], _ctx: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOENT)
        }

        fn rmdir(&self, _parent: InodeId, _name: &[u8], _ctx: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOENT)
        }

        fn rename(
            &self,
            _old_parent: InodeId,
            _old_name: &[u8],
            _new_parent: InodeId,
            _new_name: &[u8],
            _flags: u32,
            _ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOENT)
        }

        fn link(
            &self,
            _target: InodeId,
            _new_parent: InodeId,
            _new_name: &[u8],
            _ctx: &RequestCtx,
        ) -> Result<tidefs_vfs_engine::InodeAttr, Errno> {
            Err(Errno::ENOENT)
        }

        fn symlink(
            &self,
            _parent: InodeId,
            _name: &[u8],
            _target: &[u8],
            _ctx: &RequestCtx,
        ) -> Result<tidefs_vfs_engine::InodeAttr, Errno> {
            Err(Errno::ENOSPC)
        }

        fn readlink(&self, _inode: InodeId, _ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOENT)
        }

        fn mknod(
            &self,
            _parent: InodeId,
            _name: &[u8],
            _mode: u32,
            _rdev: u32,
            _ctx: &RequestCtx,
        ) -> Result<tidefs_vfs_engine::InodeAttr, Errno> {
            Err(Errno::ENOSPC)
        }

        fn open(
            &self,
            inode: InodeId,
            flags: u32,
            _ctx: &RequestCtx,
        ) -> Result<EngineFileHandle, Errno> {
            if let Some(ref err) = *self.open_error.lock().unwrap() {
                return Err(*err);
            }
            let mut calls = self.open_calls.lock().unwrap();
            let fh_id = inode.get() * 1000 + calls.len() as u64 + 1;
            calls.push((inode.get(), flags));
            Ok(EngineFileHandle::new(
                inode,
                flags,
                FileHandleId::new(fh_id),
                0,
            ))
        }

        fn release(&self, fh: &EngineFileHandle) -> Result<(), Errno> {
            if let Some(ref err) = *self.release_error.lock().unwrap() {
                return Err(*err);
            }
            self.release_calls
                .lock()
                .unwrap()
                .push((fh.inode_id.get(), fh.fh_id.get()));
            Ok(())
        }

        fn read(
            &self,
            _fh: &EngineFileHandle,
            _offset: u64,
            _size: u32,
            _ctx: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            Err(Errno::EIO)
        }

        fn write(
            &self,
            fh: &EngineFileHandle,
            offset: u64,
            data: &[u8],
            _ctx: &RequestCtx,
        ) -> Result<u32, Errno> {
            if let Some(ref err) = *self.write_error.lock().unwrap() {
                return Err(*err);
            }
            self.write_calls.lock().unwrap().push((
                fh.inode_id.get(),
                fh.fh_id.get(),
                offset,
                data.len(),
            ));
            let mut store = self.data.lock().unwrap();
            let key = (fh.inode_id.get() << 32) | (offset / 4096);
            store.insert(key, data.to_vec());
            Ok(data.len() as u32)
        }

        fn flush(&self, fh: &EngineFileHandle, _ctx: &RequestCtx) -> Result<(), Errno> {
            if let Some(ref err) = *self.flush_error.lock().unwrap() {
                return Err(*err);
            }
            self.flush_calls
                .lock()
                .unwrap()
                .push((fh.inode_id.get(), fh.fh_id.get()));
            Ok(())
        }

        fn fsync(
            &self,
            fh: &EngineFileHandle,
            datasync: bool,
            _ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            if let Some(ref err) = *self.fsync_error.lock().unwrap() {
                return Err(*err);
            }
            self.fsync_calls
                .lock()
                .unwrap()
                .push((fh.inode_id.get(), fh.fh_id.get(), datasync));
            Ok(())
        }

        fn opendir(
            &self,
            _inode: InodeId,
            _ctx: &RequestCtx,
        ) -> Result<tidefs_types_vfs_core::EngineDirHandle, Errno> {
            Err(Errno::ENOENT)
        }

        fn releasedir(&self, _dh: &tidefs_types_vfs_core::EngineDirHandle) -> Result<(), Errno> {
            Ok(())
        }

        fn readdir(
            &self,
            _dh: &tidefs_types_vfs_core::EngineDirHandle,
            _offset: u64,
            _ctx: &RequestCtx,
        ) -> Result<(Vec<tidefs_types_vfs_core::DirEntry>, bool), Errno> {
            Err(Errno::ENOENT)
        }

        fn fsyncdir(
            &self,
            _dh: &tidefs_types_vfs_core::EngineDirHandle,
            _datasync: bool,
            _ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Ok(())
        }

        fn getxattr(
            &self,
            _inode: InodeId,
            _name: &[u8],
            _ctx: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENODATA)
        }

        fn setxattr(
            &self,
            _inode: InodeId,
            _name: &[u8],
            _value: &[u8],
            _flags: u32,
            _ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSPC)
        }

        fn listxattr(&self, _inode: InodeId, _ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENODATA)
        }

        fn removexattr(
            &self,
            _inode: InodeId,
            _name: &[u8],
            _ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENODATA)
        }

        fn getlk(
            &self,
            _inode: tidefs_types_vfs_core::InodeId,
            _lock: &tidefs_types_vfs_core::LockSpec,
            _ctx: &tidefs_types_vfs_core::RequestCtx,
        ) -> std::result::Result<
            std::option::Option<tidefs_types_vfs_core::LockSpec>,
            tidefs_types_vfs_core::Errno,
        > {
            Err(tidefs_types_vfs_core::Errno::ENOSYS)
        }

        fn setlk(
            &self,
            _inode: tidefs_types_vfs_core::InodeId,
            _lock: &tidefs_types_vfs_core::LockSpec,
            _ctx: &tidefs_types_vfs_core::RequestCtx,
        ) -> std::result::Result<(), tidefs_types_vfs_core::Errno> {
            Err(tidefs_types_vfs_core::Errno::ENOSYS)
        }
        fn fallocate(
            &self,
            _fh: &EngineFileHandle,
            _mode: u32,
            _offset: u64,
            _length: u64,
            _ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::EOPNOTSUPP)
        }
    }

    impl tidefs_vfs_engine::VfsEngineStatFs for InMemoryTestEngine {
        fn statfs(&self, _ctx: &RequestCtx) -> Result<tidefs_vfs_engine::StatFs, Errno> {
            Err(Errno::ENOENT)
        }
    }

    fn test_ctx() -> RequestCtx {
        RequestCtx {
            uid: 1000,
            gid: 1000,
            pid: 42,
            umask: 0o022,
            groups: Vec::new(),
        }
    }

    fn test_handle(inode: u64) -> FileHandle {
        FileHandle::new(InodeId::new(inode), 0x8002, inode * 10, inode * 100)
    }

    // ── FileHandle tests ─────────────────────────────────────────────

    #[test]
    fn file_handle_new_stores_inode_and_flags() {
        let fh = FileHandle::new(InodeId::new(42), 0x8000, 5, 100);
        assert_eq!(fh.inode.get(), 42);
        assert_eq!(fh.open_flags, 0x8000);
        assert_eq!(fh.fh_id, 5);
        assert_eq!(fh.lock_owner, 100);
    }

    #[test]
    fn file_handle_to_engine_file_handle() {
        let fh = FileHandle::new(InodeId::new(7), 0x8002, 10, 200);
        let efh = fh.to_engine_file_handle();
        assert_eq!(efh.inode_id.get(), 7);
        assert_eq!(efh.open_flags, 0x8002);
        assert_eq!(efh.fh_id.get(), 10);
        assert_eq!(efh.lock_owner, 200);
    }

    #[test]
    fn file_handle_clone_is_equal() {
        let fh = FileHandle::new(InodeId::new(7), 0, 1, 2);
        let cloned = fh.clone();
        assert_eq!(cloned.inode.get(), fh.inode.get());
        assert_eq!(cloned.open_flags, fh.open_flags);
        assert_eq!(cloned.fh_id, fh.fh_id);
    }

    // ── FlushError mapping tests ─────────────────────────────────────

    #[test]
    fn flush_error_to_errno_badfd() {
        assert_eq!(FlushError::BadFileDescriptor.to_errno(), Errno::EBADF);
    }

    #[test]
    fn flush_error_to_errno_io() {
        assert_eq!(FlushError::IoError.to_errno(), Errno::EIO);
    }

    #[test]
    fn flush_error_to_errno_nospace() {
        assert_eq!(FlushError::NoSpace.to_errno(), Errno::ENOSPC);
    }

    #[test]
    fn flush_error_to_errno_intr() {
        assert_eq!(FlushError::Interrupted.to_errno(), Errno::EINTR);
    }

    // ── FsyncError mapping tests ─────────────────────────────────────

    #[test]
    fn fsync_error_to_errno_badfd() {
        assert_eq!(FsyncError::BadFileDescriptor.to_errno(), Errno::EBADF);
    }

    #[test]
    fn fsync_error_to_errno_io() {
        assert_eq!(FsyncError::IoError.to_errno(), Errno::EIO);
    }

    #[test]
    fn fsync_error_to_errno_nospace() {
        assert_eq!(FsyncError::NoSpace.to_errno(), Errno::ENOSPC);
    }

    #[test]
    fn fsync_error_to_errno_intr() {
        assert_eq!(FsyncError::Interrupted.to_errno(), Errno::EINTR);
    }

    // ── FlushOutcome mapping tests ───────────────────────────────────

    #[test]
    fn flush_outcome_success_errno_is_zero() {
        assert_eq!(FlushOutcome::Success.to_errno().raw(), 0);
    }

    #[test]
    fn flush_outcome_from_error_roundtrip() {
        for err in [
            FlushError::BadFileDescriptor,
            FlushError::IoError,
            FlushError::NoSpace,
            FlushError::Interrupted,
        ] {
            let outcome = FlushOutcome::from_error(err);
            assert_eq!(outcome.to_errno(), err.to_errno());
        }
    }

    // ── FsyncOutcome mapping tests ───────────────────────────────────

    #[test]
    fn fsync_outcome_success_errno_is_zero() {
        assert_eq!(FsyncOutcome::Success.to_errno().raw(), 0);
    }

    #[test]
    fn fsync_outcome_from_error_roundtrip() {
        for err in [
            FsyncError::BadFileDescriptor,
            FsyncError::IoError,
            FsyncError::NoSpace,
            FsyncError::Interrupted,
        ] {
            let outcome = FsyncOutcome::from_error(err);
            assert_eq!(outcome.to_errno(), err.to_errno());
        }
    }

    // ── dispatch_flush behavior tests ────────────────────────────────

    // ── FlushOutcome to_errno per-variant tests ──────────────────────

    #[test]
    fn flush_outcome_to_errno_badfd() {
        assert_eq!(FlushOutcome::BadFileDescriptor.to_errno(), Errno::EBADF);
    }

    #[test]
    fn flush_outcome_to_errno_nospace() {
        assert_eq!(FlushOutcome::NoSpace.to_errno(), Errno::ENOSPC);
    }

    #[test]
    fn flush_outcome_to_errno_ioerror() {
        assert_eq!(FlushOutcome::IoError.to_errno(), Errno::EIO);
    }

    #[test]
    fn flush_outcome_to_errno_interrupted() {
        assert_eq!(FlushOutcome::Interrupted.to_errno(), Errno::EINTR);
    }

    // ── FsyncOutcome to_errno per-variant tests ──────────────────────

    #[test]
    fn fsync_outcome_to_errno_badfd() {
        assert_eq!(FsyncOutcome::BadFileDescriptor.to_errno(), Errno::EBADF);
    }

    #[test]
    fn fsync_outcome_to_errno_nospace() {
        assert_eq!(FsyncOutcome::NoSpace.to_errno(), Errno::ENOSPC);
    }

    #[test]
    fn fsync_outcome_to_errno_ioerror() {
        assert_eq!(FsyncOutcome::IoError.to_errno(), Errno::EIO);
    }

    #[test]
    fn fsync_outcome_to_errno_interrupted() {
        assert_eq!(FsyncOutcome::Interrupted.to_errno(), Errno::EINTR);
    }

    // ── FlushOutcome variant coverage ────────────────────────────────

    #[test]
    fn flush_outcome_all_variants_distinct_errno() {
        let outcomes = [
            FlushOutcome::Success,
            FlushOutcome::BadFileDescriptor,
            FlushOutcome::NoSpace,
            FlushOutcome::IoError,
            FlushOutcome::Interrupted,
        ];
        for i in 0..outcomes.len() {
            for j in (i + 1)..outcomes.len() {
                assert_ne!(
                    outcomes[i].to_errno().raw(),
                    outcomes[j].to_errno().raw(),
                    "outcome variants {i} and {j} should map to distinct errnos"
                );
            }
        }
    }

    #[test]
    fn fsync_outcome_all_variants_distinct_errno() {
        let outcomes = [
            FsyncOutcome::Success,
            FsyncOutcome::BadFileDescriptor,
            FsyncOutcome::NoSpace,
            FsyncOutcome::IoError,
            FsyncOutcome::Interrupted,
        ];
        for i in 0..outcomes.len() {
            for j in (i + 1)..outcomes.len() {
                assert_ne!(
                    outcomes[i].to_errno().raw(),
                    outcomes[j].to_errno().raw(),
                    "outcome variants {i} and {j} should map to distinct errnos"
                );
            }
        }
    }

    // ── engine_err_to_flush_err tests ────────────────────────────────

    #[test]
    fn engine_err_to_flush_err_eio_maps_to_ioerror() {
        assert_eq!(engine_err_to_flush_err(Errno::EIO), PageFlushError::IoError);
    }

    #[test]
    fn engine_err_to_flush_err_unknown_maps_to_ioerror() {
        assert_eq!(
            engine_err_to_flush_err(Errno::EAGAIN),
            PageFlushError::IoError
        );
    }

    // ── Outcome Debug format tests ───────────────────────────────────

    #[test]
    fn flush_outcome_debug_nonempty_all_variants() {
        for outcome in [
            FlushOutcome::Success,
            FlushOutcome::BadFileDescriptor,
            FlushOutcome::NoSpace,
            FlushOutcome::IoError,
            FlushOutcome::Interrupted,
        ] {
            let s = format!("{outcome:?}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn fsync_outcome_debug_nonempty_all_variants() {
        for outcome in [
            FsyncOutcome::Success,
            FsyncOutcome::BadFileDescriptor,
            FsyncOutcome::NoSpace,
            FsyncOutcome::IoError,
            FsyncOutcome::Interrupted,
        ] {
            let s = format!("{outcome:?}");
            assert!(!s.is_empty());
        }
    }

    // ── Outcome Clone/Eq tests ───────────────────────────────────────

    #[test]
    fn flush_outcome_clone_is_equal() {
        for var in [
            FlushOutcome::Success,
            FlushOutcome::BadFileDescriptor,
            FlushOutcome::NoSpace,
            FlushOutcome::IoError,
            FlushOutcome::Interrupted,
        ] {
            assert_eq!(var, var.clone());
        }
    }

    #[test]
    fn fsync_outcome_clone_is_equal() {
        for var in [
            FsyncOutcome::Success,
            FsyncOutcome::BadFileDescriptor,
            FsyncOutcome::NoSpace,
            FsyncOutcome::IoError,
            FsyncOutcome::Interrupted,
        ] {
            assert_eq!(var, var.clone());
        }
    }
    #[test]
    fn dispatch_flush_no_pagecache_calls_engine_flush() {
        let engine = InMemoryTestEngine::new();
        let handle = test_handle(1);
        let ctx = test_ctx();

        let result = dispatch_flush(&handle, &engine, None, &ctx);
        assert!(result.is_ok());

        let calls = engine.flush_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], (1, 10));
    }

    #[test]
    fn dispatch_flush_engine_returns_enospc() {
        let engine = InMemoryTestEngine::new();
        *engine.flush_error.lock().unwrap() = Some(Errno::ENOSPC);
        let handle = test_handle(2);
        let ctx = test_ctx();

        let result = dispatch_flush(&handle, &engine, None, &ctx);
        assert_eq!(result, Err(FlushError::NoSpace));
    }

    #[test]
    fn dispatch_flush_engine_returns_eio() {
        let engine = InMemoryTestEngine::new();
        *engine.flush_error.lock().unwrap() = Some(Errno::EIO);
        let handle = test_handle(3);
        let ctx = test_ctx();

        let result = dispatch_flush(&handle, &engine, None, &ctx);
        assert_eq!(result, Err(FlushError::IoError));
    }

    #[test]
    fn dispatch_flush_engine_returns_eintr() {
        let engine = InMemoryTestEngine::new();
        *engine.flush_error.lock().unwrap() = Some(Errno::EINTR);
        let handle = test_handle(4);
        let ctx = test_ctx();

        let result = dispatch_flush(&handle, &engine, None, &ctx);
        assert_eq!(result, Err(FlushError::Interrupted));
    }

    #[test]
    fn dispatch_flush_multiple_calls_independent() {
        let engine = InMemoryTestEngine::new();
        let ctx = test_ctx();

        let h1 = test_handle(10);
        let h2 = test_handle(20);

        assert!(dispatch_flush(&h1, &engine, None, &ctx).is_ok());
        assert!(dispatch_flush(&h2, &engine, None, &ctx).is_ok());

        let calls = engine.flush_calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], (10, 100)); // inode=10, fh_id=10*10
        assert_eq!(calls[1], (20, 200)); // inode=20, fh_id=20*10
    }

    // ── dispatch_flush with PageCache tests ──────────────────────────

    #[test]
    fn dispatch_flush_pagecache_clean_inode_is_noop() {
        let engine = InMemoryTestEngine::new();
        let pc = Arc::new(PageCache::new(64, 4096));
        let handle = test_handle(5);
        let ctx = test_ctx();

        // No dirty pages: flush should still call engine.flush().
        let result = dispatch_flush(&handle, &engine, Some(&pc), &ctx);
        assert!(result.is_ok());

        let calls = engine.flush_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn dispatch_flush_pagecache_dirty_pages_written_back() {
        let engine = InMemoryTestEngine::new();
        let pc = Arc::new(PageCache::new(64, 4096));
        let ctx = test_ctx();
        let ino = 6u64;

        // Insert and dirty a page.
        {
            let _key = pc.insert(ino, 0).expect("insert page 0");
            let mut handle = pc.lookup(ino, 0).expect("lookup page 0");
            handle.data_mut()[..5].copy_from_slice(b"HELLO");
            handle.mark_dirty();
        }
        {
            let _key = pc.insert(ino, 4096).expect("insert page 4096");
            let mut handle = pc.lookup(ino, 4096).expect("lookup page 4096");
            handle.data_mut()[..5].copy_from_slice(b"WORLD");
            handle.mark_dirty();
        }

        let fh = test_handle(ino);
        let result = dispatch_flush(&fh, &engine, Some(&pc), &ctx);
        assert!(result.is_ok());

        // Verify pages are clean after successful writeback.
        let dirty = pc.dirty_pages_for_inode(ino);
        assert!(dirty.is_empty(), "all pages should be clean after flush");

        // Engine should have been called.
        let calls = engine.flush_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn dispatch_flush_pagecache_writeback_failure_propagates_eio() {
        let engine = InMemoryTestEngine::new();
        *engine.write_error.lock().unwrap() = Some(Errno::EIO);
        let pc = Arc::new(PageCache::new(64, 4096));
        let ctx = test_ctx();
        let ino = 7u64;

        {
            let _key = pc.insert(ino, 0).expect("insert page 0");
            let mut handle = pc.lookup(ino, 0).expect("lookup page 0");
            handle.data_mut()[..4].copy_from_slice(b"DATA");
            handle.mark_dirty();
        }

        let fh = test_handle(ino);
        let result = dispatch_flush(&fh, &engine, Some(&pc), &ctx);
        assert_eq!(result, Err(FlushError::IoError));

        // Pages should remain dirty after failed writeback.
        let dirty = pc.dirty_pages_for_inode(ino);
        assert_eq!(dirty.len(), 1, "dirty page should be retained on failure");

        // Engine.flush should NOT have been called
        // (writeback failure short-circuits).
        let calls = engine.flush_calls.lock().unwrap();
        assert!(
            calls.is_empty(),
            "engine.flush should be skipped on writeback failure"
        );
    }

    #[test]
    fn dispatch_flush_pagecache_dirty_count_matches() {
        let engine = InMemoryTestEngine::new();
        let pc = Arc::new(PageCache::new(64, 4096));
        let ctx = test_ctx();
        let ino = 8u64;

        // Dirty 3 pages.
        for off in [0u64, 4096, 8192] {
            let _key = pc.insert(ino, off).expect("insert page");
            let mut handle = pc.lookup(ino, off).expect("lookup page");
            handle.data_mut()[0] = 0xAB;
            handle.mark_dirty();
        }

        let fh = test_handle(ino);
        let result = dispatch_flush(&fh, &engine, Some(&pc), &ctx);
        assert!(result.is_ok());

        let dirty = pc.dirty_pages_for_inode(ino);
        assert!(dirty.is_empty());
    }

    // ── dispatch_fsync behavior tests ────────────────────────────────

    #[test]
    fn dispatch_fsync_no_pagecache_calls_engine_fsync_datasync_false() {
        let engine = InMemoryTestEngine::new();
        let handle = test_handle(10);
        let ctx = test_ctx();

        let result = dispatch_fsync(&handle, false, &engine, None, &ctx);
        assert!(result.is_ok());

        let calls = engine.fsync_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], (10, 100, false));
    }

    #[test]
    fn dispatch_fsync_datasync_true_passes_flag_to_engine() {
        let engine = InMemoryTestEngine::new();
        let handle = test_handle(11);
        let ctx = test_ctx();

        let result = dispatch_fsync(&handle, true, &engine, None, &ctx);
        assert!(result.is_ok());

        let calls = engine.fsync_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], (11, 110, true));
    }

    #[test]
    fn dispatch_fsync_engine_returns_enospc() {
        let engine = InMemoryTestEngine::new();
        *engine.fsync_error.lock().unwrap() = Some(Errno::ENOSPC);
        let handle = test_handle(12);
        let ctx = test_ctx();

        let result = dispatch_fsync(&handle, false, &engine, None, &ctx);
        assert_eq!(result, Err(FsyncError::NoSpace));
    }

    #[test]
    fn dispatch_fsync_engine_returns_eio() {
        let engine = InMemoryTestEngine::new();
        *engine.fsync_error.lock().unwrap() = Some(Errno::EIO);
        let handle = test_handle(13);
        let ctx = test_ctx();

        let result = dispatch_fsync(&handle, false, &engine, None, &ctx);
        assert_eq!(result, Err(FsyncError::IoError));
    }

    #[test]
    fn dispatch_fsync_engine_returns_eintr() {
        let engine = InMemoryTestEngine::new();
        *engine.fsync_error.lock().unwrap() = Some(Errno::EINTR);
        let handle = test_handle(14);
        let ctx = test_ctx();

        let result = dispatch_fsync(&handle, false, &engine, None, &ctx);
        assert_eq!(result, Err(FsyncError::Interrupted));
    }

    // ── dispatch_fsync with PageCache tests ──────────────────────────

    #[test]
    fn dispatch_fsync_pagecache_dirty_writeback_then_engine_fsync() {
        let engine = InMemoryTestEngine::new();
        let pc = Arc::new(PageCache::new(64, 4096));
        let ctx = test_ctx();
        let ino = 15u64;

        {
            let _key = pc.insert(ino, 0).expect("insert");
            let mut h = pc.lookup(ino, 0).expect("lookup");
            h.data_mut()[..3].copy_from_slice(b"XYZ");
            h.mark_dirty();
        }

        let fh = test_handle(ino);
        let result = dispatch_fsync(&fh, true, &engine, Some(&pc), &ctx);
        assert!(result.is_ok());

        assert!(pc.dirty_pages_for_inode(ino).is_empty());
        let calls = engine.fsync_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].2); // datasync
    }

    #[test]
    fn dispatch_fsync_pagecache_writeback_failure_skips_engine() {
        let engine = InMemoryTestEngine::new();
        *engine.write_error.lock().unwrap() = Some(Errno::EIO);
        let pc = Arc::new(PageCache::new(64, 4096));
        let ctx = test_ctx();
        let ino = 16u64;

        {
            let _key = pc.insert(ino, 0).expect("insert");
            let mut h = pc.lookup(ino, 0).expect("lookup");
            h.data_mut()[0] = 0xFF;
            h.mark_dirty();
        }

        let fh = test_handle(ino);
        let result = dispatch_fsync(&fh, false, &engine, Some(&pc), &ctx);
        assert_eq!(result, Err(FsyncError::IoError));

        // Dirty page retained.
        assert_eq!(pc.dirty_pages_for_inode(ino).len(), 1);
        // Engine.fsync skipped.
        assert!(engine.fsync_calls.lock().unwrap().is_empty());
    }

    // ── HandleTable trait object safety ──────────────────────────────

    #[test]
    fn handle_table_trait_is_object_safe() {
        struct TestTable {
            handles: HashMap<u64, Arc<FileHandle>>,
        }
        impl HandleTable for TestTable {
            fn resolve(&self, fh: u64) -> Option<Arc<FileHandle>> {
                self.handles.get(&fh).cloned()
            }
        }

        let h = Arc::new(FileHandle::new(InodeId::new(1), 0x8002, 42, 7));
        let mut handles = HashMap::new();
        handles.insert(42, h);
        let table = TestTable { handles };

        assert!(table.resolve(42).is_some());
        assert!(table.resolve(99).is_none());
    }

    // ── FlushError Debug and distinctness ───────────────────────────

    #[test]
    fn flush_error_debug_non_empty() {
        for variant in [
            FlushError::BadFileDescriptor,
            FlushError::IoError,
            FlushError::NoSpace,
            FlushError::Interrupted,
        ] {
            let s = format!("{variant:?}");
            assert!(!s.is_empty(), "Debug output empty for {variant:?}");
        }
    }

    #[test]
    fn flush_error_variants_are_distinct() {
        assert_ne!(FlushError::BadFileDescriptor, FlushError::IoError);
        assert_ne!(FlushError::BadFileDescriptor, FlushError::NoSpace);
        assert_ne!(FlushError::BadFileDescriptor, FlushError::Interrupted);
        assert_ne!(FlushError::IoError, FlushError::NoSpace);
        assert_ne!(FlushError::IoError, FlushError::Interrupted);
        assert_ne!(FlushError::NoSpace, FlushError::Interrupted);
    }

    // ── FsyncError Debug and distinctness ───────────────────────────

    #[test]
    fn fsync_error_debug_non_empty() {
        for variant in [
            FsyncError::BadFileDescriptor,
            FsyncError::IoError,
            FsyncError::NoSpace,
            FsyncError::Interrupted,
        ] {
            let s = format!("{variant:?}");
            assert!(!s.is_empty(), "Debug output empty for {variant:?}");
        }
    }

    #[test]
    fn fsync_error_variants_are_distinct() {
        assert_ne!(FsyncError::BadFileDescriptor, FsyncError::IoError);
        assert_ne!(FsyncError::BadFileDescriptor, FsyncError::NoSpace);
        assert_ne!(FsyncError::BadFileDescriptor, FsyncError::Interrupted);
        assert_ne!(FsyncError::IoError, FsyncError::NoSpace);
        assert_ne!(FsyncError::IoError, FsyncError::Interrupted);
        assert_ne!(FsyncError::NoSpace, FsyncError::Interrupted);
    }

    // ── FlushOutcome exhaustive per-variant to_errno ────────────────

    #[test]
    fn flush_outcome_all_variants_to_errno() {
        assert_eq!(FlushOutcome::Success.to_errno(), Errno::SUCCESS);
        assert_eq!(FlushOutcome::BadFileDescriptor.to_errno(), Errno::EBADF);
        assert_eq!(FlushOutcome::NoSpace.to_errno(), Errno::ENOSPC);
        assert_eq!(FlushOutcome::IoError.to_errno(), Errno::EIO);
        assert_eq!(FlushOutcome::Interrupted.to_errno(), Errno::EINTR);
    }

    #[test]
    fn flush_outcome_variants_are_distinct() {
        assert_ne!(FlushOutcome::Success, FlushOutcome::BadFileDescriptor);
        assert_ne!(FlushOutcome::Success, FlushOutcome::NoSpace);
        assert_ne!(FlushOutcome::BadFileDescriptor, FlushOutcome::IoError);
        assert_ne!(FlushOutcome::NoSpace, FlushOutcome::Interrupted);
    }

    // ── FsyncOutcome exhaustive per-variant to_errno ────────────────

    #[test]
    fn fsync_outcome_all_variants_to_errno() {
        assert_eq!(FsyncOutcome::Success.to_errno(), Errno::SUCCESS);
        assert_eq!(FsyncOutcome::BadFileDescriptor.to_errno(), Errno::EBADF);
        assert_eq!(FsyncOutcome::NoSpace.to_errno(), Errno::ENOSPC);
        assert_eq!(FsyncOutcome::IoError.to_errno(), Errno::EIO);
        assert_eq!(FsyncOutcome::Interrupted.to_errno(), Errno::EINTR);
    }

    #[test]
    fn fsync_outcome_variants_are_distinct() {
        assert_ne!(FsyncOutcome::Success, FsyncOutcome::BadFileDescriptor);
        assert_ne!(FsyncOutcome::Success, FsyncOutcome::NoSpace);
        assert_ne!(FsyncOutcome::BadFileDescriptor, FsyncOutcome::IoError);
        assert_ne!(FsyncOutcome::NoSpace, FsyncOutcome::Interrupted);
    }

    #[test]
    fn engine_err_to_flush_err_success_falls_back_to_io_error() {
        assert_eq!(
            engine_err_to_flush_err(Errno::SUCCESS),
            PageFlushError::IoError
        );
    }

    // ── dispatch_flush with unexpected engine errno ─────────────────

    #[test]
    fn dispatch_flush_engine_eperm_maps_to_io_error() {
        let engine = InMemoryTestEngine::new();
        *engine.flush_error.lock().unwrap() = Some(Errno::EPERM);
        let handle = test_handle(17);
        let ctx = test_ctx();
        let result = dispatch_flush(&handle, &engine, None, &ctx);
        assert_eq!(result, Err(FlushError::IoError));
    }

    // ── dispatch_fsync with unexpected engine errno ─────────────────

    #[test]
    fn dispatch_fsync_engine_eperm_maps_to_io_error() {
        let engine = InMemoryTestEngine::new();
        *engine.fsync_error.lock().unwrap() = Some(Errno::EPERM);
        let handle = test_handle(18);
        let ctx = test_ctx();
        let result = dispatch_fsync(&handle, false, &engine, None, &ctx);
        assert_eq!(result, Err(FsyncError::IoError));
    }

    // ── PageCacheDirtyFlush builder and flush_inode ─────────────────

    #[test]
    fn page_cache_dirty_flush_new_and_flush_inode_without_pagecache() {
        let engine = InMemoryTestEngine::new();
        let handle = test_handle(42);
        let efh = handle.to_engine_file_handle();
        let ctx = test_ctx();

        let bridge = PageCacheDirtyFlush::new(None, &engine, &efh, &ctx);
        let result = bridge.flush_inode(InodeId::new(42), false);
        assert!(result.is_ok());

        let calls = engine.flush_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 42);
    }

    #[test]
    fn page_cache_dirty_flush_flush_inode_with_datasync() {
        let engine = InMemoryTestEngine::new();
        let handle = test_handle(42);
        let efh = handle.to_engine_file_handle();
        let ctx = test_ctx();

        let bridge = PageCacheDirtyFlush::new(None, &engine, &efh, &ctx);
        let result = bridge.flush_inode(InodeId::new(42), true);
        assert!(result.is_ok());

        // flush_inode ignores datasync for the engine.flush call
        let calls = engine.flush_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn page_cache_dirty_flush_flush_inode_engine_enospc() {
        let engine = InMemoryTestEngine::new();
        *engine.flush_error.lock().unwrap() = Some(Errno::ENOSPC);
        let handle = test_handle(42);
        let efh = handle.to_engine_file_handle();
        let ctx = test_ctx();

        let bridge = PageCacheDirtyFlush::new(None, &engine, &efh, &ctx);
        let result = bridge.flush_inode(InodeId::new(42), false);
        assert_eq!(result, Err(FsyncDispatchError::NoSpace));
    }

    #[test]
    fn page_cache_dirty_flush_flush_all_without_pagecache() {
        let engine = InMemoryTestEngine::new();
        let handle = test_handle(99);
        let efh = handle.to_engine_file_handle();
        let ctx = test_ctx();

        let bridge = PageCacheDirtyFlush::new(None, &engine, &efh, &ctx);
        let result = bridge.flush_all();
        assert!(result.is_ok());

        assert!(engine.open_calls.lock().unwrap().is_empty());
        assert!(engine.write_calls.lock().unwrap().is_empty());
        assert!(engine.release_calls.lock().unwrap().is_empty());
        assert!(engine.flush_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn page_cache_dirty_flush_flush_all_uses_per_inode_write_handles() {
        let engine = InMemoryTestEngine::new();
        let pc = Arc::new(PageCache::new(64, 4096));
        let synthetic = EngineFileHandle::new(InodeId::new(0), 0, FileHandleId::new(0), 0);
        let ctx = test_ctx();

        for (ino, offset, data) in [
            (21u64, 0u64, b"alpha".as_slice()),
            (22u64, 4096u64, b"bravo".as_slice()),
        ] {
            let _key = pc.insert(ino, offset).expect("insert dirty page");
            let mut page = pc.lookup(ino, offset).expect("lookup dirty page");
            page.data_mut()[..data.len()].copy_from_slice(data);
            page.mark_dirty();
        }

        let bridge = PageCacheDirtyFlush::new(Some(&pc), &engine, &synthetic, &ctx);
        let result = bridge.flush_all();
        assert!(result.is_ok());

        assert!(pc.dirty_pages_for_inode(21).is_empty());
        assert!(pc.dirty_pages_for_inode(22).is_empty());
        assert_eq!(
            *engine.open_calls.lock().unwrap(),
            vec![(21, libc::O_RDWR as u32), (22, libc::O_RDWR as u32),]
        );
        let writes = engine.write_calls.lock().unwrap();
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0].0, 21);
        assert_eq!(writes[0].2, 0);
        assert_eq!(writes[1].0, 22);
        assert_eq!(writes[1].2, 4096);
        assert!(
            writes.iter().all(|(ino, _, _, _)| *ino != 0),
            "flush_all must not write dirty data through the synthetic syncfs handle"
        );
        assert_eq!(engine.release_calls.lock().unwrap().len(), 2);
        assert!(engine.flush_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn page_cache_dirty_flush_flush_all_open_failure_retains_dirty_page() {
        let engine = InMemoryTestEngine::new();
        *engine.open_error.lock().unwrap() = Some(Errno::ENOENT);
        let pc = Arc::new(PageCache::new(64, 4096));
        let synthetic = EngineFileHandle::new(InodeId::new(0), 0, FileHandleId::new(0), 0);
        let ctx = test_ctx();

        let _key = pc.insert(31, 0).expect("insert dirty page");
        let mut page = pc.lookup(31, 0).expect("lookup dirty page");
        page.data_mut()[..4].copy_from_slice(b"data");
        page.mark_dirty();
        drop(page);

        let bridge = PageCacheDirtyFlush::new(Some(&pc), &engine, &synthetic, &ctx);
        let result = bridge.flush_all();
        assert_eq!(result, Err(FsyncDispatchError::IoError));
        assert_eq!(pc.dirty_pages_for_inode(31).len(), 1);
        assert!(engine.write_calls.lock().unwrap().is_empty());
        assert!(engine.release_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn page_cache_dirty_flush_flush_all_write_enospc_retains_dirty_page() {
        let engine = InMemoryTestEngine::new();
        *engine.write_error.lock().unwrap() = Some(Errno::ENOSPC);
        let pc = Arc::new(PageCache::new(64, 4096));
        let synthetic = EngineFileHandle::new(InodeId::new(0), 0, FileHandleId::new(0), 0);
        let ctx = test_ctx();

        let _key = pc.insert(32, 0).expect("insert dirty page");
        let mut page = pc.lookup(32, 0).expect("lookup dirty page");
        page.data_mut()[..4].copy_from_slice(b"data");
        page.mark_dirty();
        drop(page);

        let bridge = PageCacheDirtyFlush::new(Some(&pc), &engine, &synthetic, &ctx);
        let result = bridge.flush_all();
        assert_eq!(result, Err(FsyncDispatchError::NoSpace));
        assert_eq!(pc.dirty_pages_for_inode(32).len(), 1);
        assert_eq!(engine.release_calls.lock().unwrap().len(), 1);
    }

    // ── FlushError/ FsyncError Error-like impls ─────────────────────

    #[test]
    fn flush_error_copy_and_clone_equivalence() {
        let e = FlushError::IoError;
        let copied = e; // Copy
        assert_eq!(e, copied);
        let cloned = e; // Clone explicitly
        assert_eq!(e, cloned);
    }

    #[test]
    fn fsync_error_copy_and_clone_equivalence() {
        let e = FsyncError::NoSpace;
        let copied = e;
        assert_eq!(e, copied);
        let cloned = e;
        assert_eq!(e, cloned);
    }
}
