// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE projection of the canonical local-filesystem flush boundary.
//!
//! Incoming FUSE writes are written through to the engine before the adapter
//! acknowledges them.  Adapter page caches and dirty trackers are therefore
//! non-authoritative mirrors.  This bridge performs only the lower engine
//! flush required by [`DirtyFlush`]; the caller-visible adapter operation owns
//! final durability and may retire its snapshotted mirrors only after every
//! later barrier stage succeeds.

use tidefs_local_filesystem::fuse_fsync::{DirtyFlush, FsyncDispatchError};
use tidefs_types_vfs_core::{EngineFileHandle, Errno, InodeId, RequestCtx};
use tidefs_vfs_engine::VfsEngine;

/// Bridge from local-filesystem namespace flush dispatch to the live FUSE
/// engine handle.
pub struct PageCacheDirtyFlush<'a> {
    engine: &'a dyn VfsEngine,
    efh: &'a EngineFileHandle,
    ctx: &'a RequestCtx,
}

impl<'a> PageCacheDirtyFlush<'a> {
    /// Create a bridge for one live file handle.
    #[must_use]
    pub fn new(engine: &'a dyn VfsEngine, efh: &'a EngineFileHandle, ctx: &'a RequestCtx) -> Self {
        Self { engine, efh, ctx }
    }
}

impl DirtyFlush for PageCacheDirtyFlush<'_> {
    fn flush_inode(&self, _inode_id: InodeId, _datasync: bool) -> Result<(), FsyncDispatchError> {
        self.engine
            .flush(self.efh, self.ctx)
            .map_err(|errno| match errno {
                Errno::ENOSPC => FsyncDispatchError::NoSpace,
                Errno::EINTR => FsyncDispatchError::Interrupted,
                _ => FsyncDispatchError::IoError,
            })
    }

    fn flush_all(&self) -> Result<(), FsyncDispatchError> {
        // The adapter owns the mount-wide engine.syncfs() call.  There is no
        // file-handle-scoped lower flush to perform for this projection.
        Ok(())
    }
}
