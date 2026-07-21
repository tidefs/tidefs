// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE setattr dispatch handler backed by [`LocalFileSystem`].
//!
//! Provides an engine-level function (`engine_setattr`) that applies a
//! [`SetAttr`] mask to an inode's metadata fields (mode, uid, gid,
//! timestamps) through the filesystem's mutation machinery and returns
//! the updated [`InodeAttr`]. Used by the VFS engine implementation.
//!
//! Note: `FATTR_SIZE` is handled by the caller (the VFS engine) through
//! file-content manipulation (truncate/extend). This module handles only
//! metadata fields: mode, uid, gid, and timestamps.
//!
//! All functions map errors through [`SetattrDispatchError`], which carries
//! standard POSIX errno values.

use crate::{FileSystemError, LocalFileSystem};
use tidefs_types_vfs_core::{
    Errno, InodeAttr, InodeId, SetAttr, FATTR_ATIME, FATTR_ATIME_NOW, FATTR_CTIME, FATTR_GID,
    FATTR_MODE, FATTR_MTIME, FATTR_MTIME_NOW, FATTR_UID, S_IFMT,
};

// POSIX errno constants
const ENOENT: i32 = 2;
const EIO: i32 = 5;
const EPERM: i32 = 1;
const EINVAL: i32 = 22;

// ---------------------------------------------------------------------------
// Dispatch error
// ---------------------------------------------------------------------------

/// Errors that can occur during setattr dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetattrDispatchError {
    /// The inode does not exist or is stale.
    NoEntry,
    /// Generic I/O error (corrupt state, object-store write failure).
    Io,
    #[allow(dead_code)] // INTENT: setattr dispatch error variants for planned FUSE setattr handler
    /// Caller lacks permission to change the requested attributes.
    PermissionDenied,
    /// Invalid combination of flags or values.
    InvalidArg,
}

impl SetattrDispatchError {
    /// Return the closest POSIX errno for this error.
    #[must_use]
    pub fn to_errno(self) -> Errno {
        match self {
            Self::NoEntry => Errno(ENOENT as u16),
            Self::Io => Errno(EIO as u16),
            Self::PermissionDenied => Errno(EPERM as u16),
            Self::InvalidArg => Errno(EINVAL as u16),
        }
    }
}

impl From<&FileSystemError> for SetattrDispatchError {
    fn from(err: &FileSystemError) -> Self {
        match err {
            FileSystemError::NotFound { .. } => Self::NoEntry,
            FileSystemError::CorruptState { .. } => Self::Io,
            _ => Self::Io,
        }
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Setattr bits that this metadata engine implementation supports.
const SUPPORTED_SETATTR_BITS: u32 = FATTR_MODE
    | FATTR_UID
    | FATTR_GID
    | FATTR_ATIME
    | FATTR_MTIME
    | FATTR_CTIME
    | FATTR_ATIME_NOW
    | FATTR_MTIME_NOW;

// ---------------------------------------------------------------------------
// Engine layer
// ---------------------------------------------------------------------------

/// Apply a [`SetAttr`] mask to an inode's metadata fields in the local
/// filesystem.
///
/// Reads the current inode record, applies the requested metadata changes
/// (mode, uid, gid, timestamps), writes the updated record back through
/// the filesystem's mutation machinery, and returns the updated [`InodeAttr`].
///
/// The following `FATTR_*` bits are supported:
///
/// - `FATTR_MODE` — file-type bits are preserved; only permission bits change.
/// - `FATTR_UID` / `FATTR_GID` — owner/group.
/// - `FATTR_ATIME` / `FATTR_MTIME` — explicit nanosecond timestamps.
/// - `FATTR_ATIME_NOW` / `FATTR_MTIME_NOW` — set to current generation tick.
/// - `FATTR_CTIME` — explicit ctime value.
///
/// Ctime is automatically advanced when any metadata field changes and no
/// explicit `FATTR_CTIME` was provided.
///
/// # Errors
///
/// Returns [`SetattrDispatchError::NoEntry`] when the inode does not exist.
/// Returns [`SetattrDispatchError::InvalidArg`] for unsupported flag bits.
/// Returns [`SetattrDispatchError::Io`] on corrupt state or store failures.
pub fn engine_setattr(
    fs: &mut LocalFileSystem,
    ino: u64,
    set: &SetAttr,
) -> Result<InodeAttr, SetattrDispatchError> {
    // Inode 0 is invalid (FUSE root is ROOT_INODE_ID=1).
    if ino == 0 {
        return Err(SetattrDispatchError::NoEntry);
    }

    let inode_id = InodeId(ino);

    // Reject unsupported valid bits.
    if set.valid & !SUPPORTED_SETATTR_BITS != 0 {
        return Err(SetattrDispatchError::InvalidArg);
    }

    // No-op for empty mask.
    if set.valid & SUPPORTED_SETATTR_BITS == 0 {
        return crate::fuse_getattr::engine_getattr(fs, ino).map_err(|e| match e {
            crate::fuse_getattr::GetattrDispatchError::NoEntry => SetattrDispatchError::NoEntry,
            crate::fuse_getattr::GetattrDispatchError::Io => SetattrDispatchError::Io,
        });
    }

    // Metadata-only setattr must not persist the write-buffer-adjusted size;
    // content size and data_version change only when the buffer is flushed.
    let record = fs
        .committed_inode_record(inode_id)
        .map_err(|e| SetattrDispatchError::from(&e))?;
    let mut updated = record.clone();

    let now_ns = crate::types::current_posix_time_ns();
    let mut changed = false;
    let mut should_bump_ctime = false;

    if set.valid & FATTR_MODE != 0 {
        let mode = (updated.mode & S_IFMT) | (set.mode & !S_IFMT);
        if updated.mode != mode {
            updated.mode = mode;
            changed = true;
            should_bump_ctime = true;
        }

        // ACL mode synchronization: when chmod changes mode and the inode has
        // a POSIX access ACL, update the ACL entries to match the new mode
        // bits via plan_posix_acl_mode_sync.  The updated ACL is stored back
        // so that subsequent permission checks see consistent ACL + mode.
        const ACL_ACCESS: &[u8] = b"system.posix_acl_access";
        if let Some(acl_raw) = updated.xattrs.get(ACL_ACCESS) {
            if let Ok(acl_entries) = tidefs_posix_acl::decode_posix_acl_xattr(acl_raw) {
                if let Ok(sync_plan) =
                    tidefs_posix_acl::plan_posix_acl_mode_sync(&acl_entries, updated.mode)
                {
                    updated.xattrs.insert(
                        ACL_ACCESS.to_vec(),
                        tidefs_posix_acl::encode_posix_acl_xattr(&sync_plan.updated_acl),
                    );
                }
            }
        }
    }
    if set.valid & FATTR_UID != 0 {
        if updated.uid != set.uid {
            updated.uid = set.uid;
            changed = true;
            should_bump_ctime = true;
        }
    }
    if set.valid & FATTR_GID != 0 {
        if updated.gid != set.gid {
            updated.gid = set.gid;
            changed = true;
            should_bump_ctime = true;
        }
    }
    if set.valid & FATTR_ATIME != 0 {
        if updated.posix_time.atime_ns != set.atime_ns {
            updated.posix_time.atime_ns = set.atime_ns;
            changed = true;
            should_bump_ctime = true;
        }
    }
    if set.valid & FATTR_CTIME != 0 {
        if updated.posix_time.ctime_ns != set.ctime_ns {
            updated.posix_time.ctime_ns = set.ctime_ns;
            changed = true;
        }
    }
    if set.valid & FATTR_ATIME_NOW != 0 {
        if updated.posix_time.atime_ns != now_ns {
            updated.posix_time.atime_ns = now_ns;
            changed = true;
            should_bump_ctime = true;
        }
    }
    if set.valid & FATTR_MTIME != 0 {
        if updated.posix_time.mtime_ns != set.mtime_ns {
            updated.posix_time.mtime_ns = set.mtime_ns;
            changed = true;
            should_bump_ctime = true;
        }
    }
    if set.valid & FATTR_MTIME_NOW != 0 {
        if updated.posix_time.mtime_ns != now_ns {
            updated.posix_time.mtime_ns = now_ns;
            changed = true;
            should_bump_ctime = true;
        }
    }

    // POSIX: advance ctime when any metadata field changed and no explicit
    // ctime was provided by the caller.
    if should_bump_ctime && set.valid & FATTR_CTIME == 0 {
        if updated.posix_time.ctime_ns != now_ns {
            updated.posix_time.ctime_ns = now_ns;
            changed = true;
        }
    }

    if !changed {
        let visible = fs
            .inode(inode_id)
            .map_err(|e| SetattrDispatchError::from(&e))?;
        return Ok(visible.to_inode_attr());
    }

    fs.begin_mutation();
    let tick = fs.bump_generation();
    updated.metadata_version = updated.metadata_version.max(tick);

    // Write back through mutation machinery.
    fs.mark_inode_metadata_dirty(inode_id);
    use std::sync::Arc;
    Arc::make_mut(&mut fs.state.inodes).insert(inode_id, updated);
    fs.inode_cache.borrow_mut().invalidate(inode_id);
    fs.commit_mutation(())
        .map_err(|e| SetattrDispatchError::from(&e))?;

    // Re-read to return the committed state.
    let result = fs
        .inode(inode_id)
        .map_err(|e| SetattrDispatchError::from(&e))?;
    Ok(result.to_inode_attr())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_setattr_preserves_pending_write_content() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut fs = LocalFileSystem::open(root.path()).expect("open filesystem");
        fs.set_auto_commit(false);
        fs.begin_transaction().expect("begin deferred transaction");
        fs.set_write_buffer_flush_threshold_bytes(usize::MAX);

        let record = fs
            .create_file("/pending-write", 0o644)
            .expect("create file");
        let payload = b"pending content survives metadata setattr";
        fs.write_file("/pending-write", 0, payload)
            .expect("buffer write");

        assert!(
            fs.write_buffers.contains_key(&record.inode_id),
            "test setup must leave the write pending"
        );
        assert_eq!(
            fs.committed_inode_record(record.inode_id)
                .expect("committed inode before setattr")
                .size,
            0,
            "pending content must not already be committed"
        );

        let no_change = SetAttr {
            valid: FATTR_MODE,
            mode: 0o644,
            ..SetAttr::default()
        };
        let attr = engine_setattr(&mut fs, record.inode_id.get(), &no_change)
            .expect("no-change metadata setattr");
        assert_eq!(
            attr.posix.size,
            payload.len() as u64,
            "no-change setattr must return the write-buffer-adjusted size"
        );

        let set = SetAttr {
            valid: FATTR_MODE,
            mode: 0o600,
            ..SetAttr::default()
        };
        let attr =
            engine_setattr(&mut fs, record.inode_id.get(), &set).expect("metadata-only setattr");

        assert_eq!(attr.posix.size, payload.len() as u64);
        assert!(
            fs.write_buffers.contains_key(&record.inode_id),
            "metadata setattr must not flush or discard pending content"
        );
        assert_eq!(
            fs.committed_inode_record(record.inode_id)
                .expect("committed inode after setattr")
                .size,
            0,
            "metadata setattr must not publish the visible overlay size"
        );
        assert_eq!(
            fs.read_file("/pending-write")
                .expect("read after metadata setattr"),
            payload
        );

        fs.rollback_transaction().expect("rollback test fixture");
    }
}
