// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE getattr dispatch handler backed by [`LocalFileSystem`].
//!
//! Provides an engine-level function (`engine_getattr`) that resolves
//! an inode number to its [`InodeAttr`] through the filesystem's
//! inode table and ARC cache. Used by the VFS engine implementation
//! and FUSE setattr dispatch.
//!
//! All functions map errors through [`GetattrDispatchError`], which carries
//! standard POSIX errno values.

use crate::{FileSystemError, LocalFileSystem};
use tidefs_types_vfs_core::{Errno, InodeAttr, InodeId};

// POSIX errno constants (no direct libc dependency)
const ENOENT: i32 = 2;
const EIO: i32 = 5;

// ---------------------------------------------------------------------------
// Dispatch error
// ---------------------------------------------------------------------------

/// Errors that can occur during getattr dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GetattrDispatchError {
    /// The inode does not exist or is stale.
    NoEntry,
    /// Generic I/O error (corrupt state, object-store read failure).
    Io,
}

impl GetattrDispatchError {
    /// Return the closest POSIX errno for this error.
    #[must_use]
    pub fn to_errno(self) -> Errno {
        match self {
            Self::NoEntry => Errno(ENOENT as u16),
            Self::Io => Errno(EIO as u16),
        }
    }
}

impl From<&FileSystemError> for GetattrDispatchError {
    fn from(err: &FileSystemError) -> Self {
        match err {
            FileSystemError::NotFound { .. } => Self::NoEntry,
            FileSystemError::CorruptState { .. } => Self::Io,
            _ => Self::Io,
        }
    }
}

// ---------------------------------------------------------------------------
// Engine layer
// ---------------------------------------------------------------------------

/// Resolve inode attributes from the local filesystem by inode number.
///
/// Uses the filesystem's in-memory inode table and ARC cache to look up
/// the inode record and convert it into an [`InodeAttr`].
///
/// # Errors
///
/// Returns [`GetattrDispatchError::NoEntry`] when the inode ID is not
/// found in the inode table or cache.
/// Returns [`GetattrDispatchError::Io`] on corrupt state or object-store
/// read failures.
pub fn engine_getattr(fs: &LocalFileSystem, ino: u64) -> Result<InodeAttr, GetattrDispatchError> {
    // Inode 0 is invalid (FUSE root is ROOT_INODE_ID=1).
    if ino == 0 {
        return Err(GetattrDispatchError::NoEntry);
    }
    let inode_id = InodeId(ino);
    let record = fs
        .inode(inode_id)
        .map_err(|e| GetattrDispatchError::from(&e))?;
    Ok(record.to_inode_attr())
}
