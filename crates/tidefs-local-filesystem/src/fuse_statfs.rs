// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE statfs dispatch handler backed by [`LocalFileSystem`].
//!
//! Provides an engine-level function (`engine_statfs`) that queries the
//! local filesystem for filesystem statistics and maps them into a
//! FUSE-compatible [`StatFs`] reply struct. Used by the VFS engine
//! implementation.
//!
//! FUSE-level dispatch (`dispatch_statfs`) was dead code and removed
//! in #4362; the engine function is the canonical entry point.
//!
//! All functions map errors through [`StatfsDispatchError`], which carries
//! standard POSIX errno values.

use crate::{FileSystemError, LocalFileSystem};
use tidefs_types_vfs_core::{Errno, StatFs};

// POSIX errno constants (no direct libc dependency)
const ENOENT: i32 = 2;
const EIO: i32 = 5;

// ---------------------------------------------------------------------------
// Dispatch error
// ---------------------------------------------------------------------------

/// Errors that can occur during statfs dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatfsDispatchError {
    /// The inode does not exist or is not mounted.
    NoEntry,
    /// Generic I/O error (corrupt state, object-store read failure).
    Io,
}

impl StatfsDispatchError {
    /// Return the closest POSIX errno for this error.
    #[must_use]
    pub fn to_errno(self) -> Errno {
        match self {
            Self::NoEntry => Errno(ENOENT as u16),
            Self::Io => Errno(EIO as u16),
        }
    }
}

impl From<&FileSystemError> for StatfsDispatchError {
    fn from(err: &FileSystemError) -> Self {
        match err {
            FileSystemError::NotFound { .. } => Self::NoEntry,
            _ => Self::Io,
        }
    }
}

// ---------------------------------------------------------------------------
// Engine layer
// ---------------------------------------------------------------------------

/// Query filesystem statistics from the local filesystem and produce a
/// FUSE-compatible [`StatFs`] reply.
///
/// Calls [`LocalFileSystem::statfs`] once and preserves its block counters,
/// inode counters, and fsid. That keeps FUSE aligned with the same quota and
/// effective-capacity clamping used by the local filesystem API.
///
/// # Errors
///
/// Returns [`StatfsDispatchError::Io`] when the filesystem state is
/// corrupt or the underlying object store cannot be read.
pub fn engine_statfs(fs: &mut LocalFileSystem) -> Result<StatFs, StatfsDispatchError> {
    let st = fs.statfs().map_err(|e| StatfsDispatchError::from(&e))?;
    Ok(StatFs {
        block_size: st.bsize,
        fragment_size: st.frsize,
        total_blocks: st.blocks,
        free_blocks: st.bfree,
        avail_blocks: st.bavail,
        files: st.files,
        files_free: st.ffree,
        name_max: st.namelen,
        fsid_hi: st.fsid_hi,
        fsid_lo: st.fsid_lo,
    })
}
