// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Engine-backed dirty-flush bridge for mounted FUSE durability operations.
//!
//! Adapter writes reach the VFS engine before a successful kernel reply. This
//! module therefore contains no second byte cache or standalone dispatch path:
//! it only adapts the engine's flush operations to the local-filesystem
//! [`DirtyFlush`] contract used by the mounted handlers.

use tidefs_local_filesystem::fuse_fsync::{DirtyFlush, FsyncDispatchError};
use tidefs_types_vfs_core::{EngineFileHandle, Errno, InodeId, RequestCtx};
use tidefs_vfs_engine::VfsEngine;

fn map_engine_error(error: Errno) -> FsyncDispatchError {
    match error {
        Errno::ENOSPC => FsyncDispatchError::NoSpace,
        Errno::EINTR => FsyncDispatchError::Interrupted,
        _ => FsyncDispatchError::IoError,
    }
}

/// Adapts one engine file handle to the shared dirty-flush contract.
pub struct EngineDirtyFlush<'a> {
    engine: &'a dyn VfsEngine,
    handle: &'a EngineFileHandle,
    ctx: &'a RequestCtx,
}

impl<'a> EngineDirtyFlush<'a> {
    /// Create an engine-backed flush bridge for one mounted request.
    #[must_use]
    pub const fn new(
        engine: &'a dyn VfsEngine,
        handle: &'a EngineFileHandle,
        ctx: &'a RequestCtx,
    ) -> Self {
        Self {
            engine,
            handle,
            ctx,
        }
    }
}

impl DirtyFlush for EngineDirtyFlush<'_> {
    fn flush_inode(&self, _inode_id: InodeId, _datasync: bool) -> Result<(), FsyncDispatchError> {
        self.engine
            .flush(self.handle, self.ctx)
            .map_err(map_engine_error)
    }

    fn flush_all(&self) -> Result<(), FsyncDispatchError> {
        // The mounted syncfs handler immediately issues the engine-wide syncfs
        // barrier. There is no adapter-owned dirty-byte cache to drain first.
        Ok(())
    }

    fn fdatasync_inode(
        &self,
        _inode_id: InodeId,
        datasync: bool,
    ) -> Result<(), FsyncDispatchError> {
        self.engine
            .fdatasync_inode(self.handle, datasync, self.ctx)
            .map_err(map_engine_error)
    }
}
