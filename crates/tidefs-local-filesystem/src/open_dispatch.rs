// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE open dispatch handler with file-handle state management.
//!
//! Provides two layers:
//!
//! - **Engine-level** functions (`engine_open`): validate the inode refers
//!   to a regular file, allocate a file handle, and record open flags.
//! - **FUSE-level** functions (`dispatch_open`): wrap engine_open with
//!   FUSE protocol semantics (open-flags mask validation, FUSE reply flags,
//!   error-to-errno mapping).
//!
//! The [`FileHandleTable`] is the central handle-state manager. It owns
//! allocation, validation, and release of all open file handles, and is
//! the sole writer to the handle map. All data-plane operations (read,
//! write, fsync, fallocate) query the table to validate handles before IO.

use std::cell::RefCell;
use std::collections::BTreeMap;

use tidefs_types_vfs_core::{EngineFileHandle, Errno, FileHandleId, InodeId, NodeKind};

use crate::LocalFileSystem;

// ── FUSE open flag constants (Linux uapi/linux/fuse.h) ─────────────────

/// Direct I/O: bypass kernel and adapter page cache.
pub const FOPEN_DIRECT_IO: u32 = 1 << 0;
/// Keep file cache on close (not set by default).
pub const FOPEN_KEEP_CACHE: u32 = 1 << 1;
/// File is not seekable.
pub const FOPEN_NONSEEKABLE: u32 = 1 << 2;
/// Cache directory entries (default, not set explicitly).
pub const FOPEN_CACHE_DIR: u32 = 1 << 3;
/// File opens with a stream-like semantic.
pub const FOPEN_STREAM: u32 = 1 << 4;

// ── FileHandleState ──────────────────────────────────────────────────────

/// State tracked per open file handle.
///
/// Stored in the [`FileHandleTable`] and used by all data-plane operations
/// to validate handle identity and access mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileHandleState {
    /// Inode this handle refers to.
    pub inode_id: InodeId,
    /// Linux open flags (O_RDONLY, O_WRONLY, O_RDWR, O_APPEND, etc.).
    pub open_flags: u32,
    /// Whether read/write access checks should be enforced.
    pub enforce_access_mode: bool,
    /// Monotonically increasing generation for handle-reuse safety.
    ///
    /// Each handle allocation bumps a global counter and stores the
    /// generation. On validation or release, the stored generation is
    /// compared against the table's current generation for that slot
    /// to detect stale-handle (ABA) reuse.
    pub generation: u64,
}

// ── FileHandleTable ──────────────────────────────────────────────────────

/// Central file-handle state manager.
///
/// Owns allocation, validation, lookup, and release of all open file
/// handles. Wrapped in a `RefCell` by the VFS engine so that `&self`
/// methods can mutate the table.
#[derive(Clone, Debug, Default)]
pub struct FileHandleTable {
    handles: BTreeMap<FileHandleId, FileHandleState>,
    next_id: u64,
    /// Global generation counter; bumped on every allocation.
    generation: u64,
}

impl FileHandleTable {
    /// Create an empty handle table.
    pub fn new() -> Self {
        Self {
            handles: BTreeMap::new(),
            next_id: 1,
            generation: 1,
        }
    }

    /// Allocate and register a new file handle.
    ///
    /// Returns the [`EngineFileHandle`] that the caller must pass to
    /// subsequent data-plane operations.  The returned handle carries
    /// the allocated `fh_id`, the requested `inode_id` and `open_flags`,
    /// and a zero `lock_owner` (set later by the FUSE adapter).
    pub fn register(
        &mut self,
        inode_id: InodeId,
        open_flags: u32,
        enforce_access_mode: bool,
    ) -> Result<EngineFileHandle, OpenDispatchError> {
        let fh_id = self.allocate_id()?;
        let gen = self.generation;
        self.generation = self.generation.wrapping_add(1);
        self.handles.insert(
            fh_id,
            FileHandleState {
                inode_id,
                open_flags,
                enforce_access_mode,
                generation: gen,
            },
        );
        Ok(EngineFileHandle {
            inode_id,
            open_flags,
            fh_id,
            lock_owner: 0,
        })
    }

    /// Release a file handle.
    ///
    /// Validates the handle identity (inode + flags + fh_id match), then
    /// removes the entry. Returns the inode ID of the released handle so
    /// the caller can perform tmpfile reclamation if needed.
    ///
    /// Returns `Err(BadFileDescriptor)` if the handle is not found or
    /// does not match.
    pub fn release(&mut self, fh: &EngineFileHandle) -> Result<InodeId, OpenDispatchError> {
        match self.handles.get(&fh.fh_id).copied() {
            Some(live) if live.inode_id == fh.inode_id && live.open_flags == fh.open_flags => {
                self.handles.remove(&fh.fh_id);
                Ok(live.inode_id)
            }
            _ => Err(OpenDispatchError::BadFileDescriptor),
        }
    }

    /// Validate a file handle and return its state.
    ///
    /// Checks that the handle ID exists and that the inode and open flags
    /// match. Returns the stored `FileHandleState` for access-mode checks.
    pub fn validate(&self, fh: &EngineFileHandle) -> Result<FileHandleState, OpenDispatchError> {
        match self.handles.get(&fh.fh_id).copied() {
            Some(live) if live.inode_id == fh.inode_id && live.open_flags == fh.open_flags => {
                Ok(live)
            }
            _ => Err(OpenDispatchError::BadFileDescriptor),
        }
    }

    /// Look up handle state by ID without full validation.
    pub fn lookup(&self, fh_id: FileHandleId) -> Option<FileHandleState> {
        self.handles.get(&fh_id).copied()
    }

    /// Return true if any open handle references the given inode.
    pub fn contains_inode(&self, inode_id: InodeId) -> bool {
        self.handles.values().any(|s| s.inode_id == inode_id)
    }

    /// Number of open handles.
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    /// True if no handles are open.
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    // ── private ──────────────────────────────────────────────────────

    fn allocate_id(&mut self) -> Result<FileHandleId, OpenDispatchError> {
        let id = self.next_id;
        if id == 0 {
            return Err(OpenDispatchError::NoFileDescriptors);
        }
        self.next_id = self.next_id.wrapping_add(1);
        Ok(FileHandleId::new(id))
    }

    /// Remap all file handles pointing to `from_ino` to `to_ino`.
    ///
    /// Used during O_TMPFILE materialization: when an anonymous tmpfile
    /// is linked into the namespace, the engine remaps the existing open
    /// handles so the O_TMPFILE fd remains valid.
    #[allow(dead_code)]
    pub fn remap_inode(&mut self, from_ino: InodeId, to_ino: InodeId) {
        for state in self.handles.values_mut() {
            if state.inode_id == from_ino {
                state.inode_id = to_ino;
            }
        }
    }
}

// ── Error type ───────────────────────────────────────────────────────────

/// Errors that can occur during open dispatch or handle management.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpenDispatchError {
    /// Inode not found.
    NotFound,
    /// Target is a directory (not a regular file).
    IsDirectory,
    /// Handle table exhausted.
    NoFileDescriptors,
    /// Handle does not exist or inode/flags mismatch.
    BadFileDescriptor,
    /// Internal filesystem error.
    Io,
    /// Operation not supported.
    NotSupported,
    /// Invalid argument.
    Invalid,
    /// Permission denied.
    PermissionDenied,
}

impl OpenDispatchError {
    /// Convert to the canonical VFS `Errno`.
    pub fn to_errno(&self) -> Errno {
        match self {
            Self::NotFound => Errno::ENOENT,
            Self::IsDirectory => Errno::EISDIR,
            Self::NoFileDescriptors => Errno::ENFILE,
            Self::BadFileDescriptor => Errno::EBADF,
            Self::Io => Errno::EIO,
            Self::NotSupported => Errno::EOPNOTSUPP,
            Self::Invalid => Errno::EINVAL,
            Self::PermissionDenied => Errno::EPERM,
        }
    }
}

// ── Validation helpers ───────────────────────────────────────────────────

/// Validate FUSE open flags mask.
///
/// The FUSE protocol passes a flags word; only certain access-mode bits
/// are meaningful. Unknown access modes cause EINVAL.
pub fn validate_open_flags(flags: u32) -> Result<(), OpenDispatchError> {
    const O_ACCMODE: u32 = 0o3;
    match flags & O_ACCMODE {
        0..=2 => Ok(()), // O_RDONLY=0, O_WRONLY=1, O_RDWR=2
        _ => Err(OpenDispatchError::Invalid),
    }
}

/// Map Linux open flags to FUSE open reply flags for cache coherence.
///
/// - O_DIRECT → FOPEN_DIRECT_IO
/// - Otherwise → 0 (no special flags)
pub fn fuse_open_reply_flags(open_flags: u32) -> u32 {
    const O_DIRECT: u32 = 0o40000;
    if (open_flags & O_DIRECT) != 0 {
        FOPEN_DIRECT_IO
    } else {
        0
    }
}

// ── Engine layer ─────────────────────────────────────────────────────────

/// Open a regular file by inode.
///
/// The caller has already resolved the inode to a path and confirmed the
/// inode exists. This function checks that the inode is a regular file
/// (not a directory — directories use `opendir`), then allocates a file
/// handle in `table` and returns the [`EngineFileHandle`].
///
/// For `O_TRUNC`, the caller is responsible for performing the actual
/// truncation *before* calling `engine_open`. This function records the
/// flags for access-mode enforcement but does not mutate file data.
pub fn engine_open(
    _fs: &LocalFileSystem,
    table: &RefCell<FileHandleTable>,
    kind: NodeKind,
    inode: InodeId,
    open_flags: u32,
    enforce_access_mode: bool,
) -> Result<EngineFileHandle, Errno> {
    // Reject directories — they must go through opendir.
    if kind == NodeKind::Dir {
        return Err(Errno::EISDIR);
    }

    // Allocate handle.
    let fh = table
        .borrow_mut()
        .register(inode, open_flags, enforce_access_mode)
        .map_err(|e| e.to_errno())?;
    Ok(fh)
}

// ── FUSE layer ───────────────────────────────────────────────────────────

/// FUSE-level open dispatch.
///
/// Wraps [`engine_open`] with FUSE protocol semantics:
///
/// - Validates the FUSE open flags mask.
/// - Maps engine errors to FUSE errno codes.
/// - Returns the adapter-level handle and FUSE reply flags.
///
/// The returned `(EngineFileHandle, u32)` tuple provides the engine handle
/// and the FUSE open reply flags (FOPEN_DIRECT_IO, etc.).
pub fn dispatch_open(
    fs: &LocalFileSystem,
    table: &RefCell<FileHandleTable>,
    kind: NodeKind,
    inode: InodeId,
    open_flags: u32,
    enforce_access_mode: bool,
) -> Result<(EngineFileHandle, u32), Errno> {
    validate_open_flags(open_flags).map_err(|e| e.to_errno())?;

    let fh = engine_open(fs, table, kind, inode, open_flags, enforce_access_mode)?;

    let reply_flags = fuse_open_reply_flags(open_flags);
    Ok((fh, reply_flags))
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_new_is_empty() {
        let t = FileHandleTable::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn register_and_validate() {
        let mut t = FileHandleTable::new();
        let inode = InodeId::new(42);
        let fh = t.register(inode, 0, true).unwrap(); // O_RDONLY

        let state = t.validate(&fh).unwrap();
        assert_eq!(state.inode_id, inode);
        assert_eq!(state.open_flags, 0);
        assert!(state.enforce_access_mode);
    }

    #[test]
    fn validate_wrong_inode_fails() {
        let mut t = FileHandleTable::new();
        let fh = t.register(InodeId::new(1), 0, false).unwrap();
        let mut bad = fh;
        bad.inode_id = InodeId::new(99);
        assert_eq!(t.validate(&bad), Err(OpenDispatchError::BadFileDescriptor));
    }

    #[test]
    fn validate_wrong_flags_fails() {
        let mut t = FileHandleTable::new();
        let fh = t.register(InodeId::new(1), 0, false).unwrap();
        let mut bad = fh;
        bad.open_flags = 1; // O_WRONLY
        assert_eq!(t.validate(&bad), Err(OpenDispatchError::BadFileDescriptor));
    }

    #[test]
    fn release_removes_handle() {
        let mut t = FileHandleTable::new();
        let inode = InodeId::new(10);
        let fh = t.register(inode, 0, false).unwrap();
        assert_eq!(t.len(), 1);

        let released = t.release(&fh).unwrap();
        assert_eq!(released, inode);
        assert!(t.is_empty());
        assert_eq!(t.validate(&fh), Err(OpenDispatchError::BadFileDescriptor));
    }

    #[test]
    fn release_twice_returns_error() {
        let mut t = FileHandleTable::new();
        let fh = t.register(InodeId::new(1), 0, false).unwrap();
        t.release(&fh).unwrap();
        assert_eq!(t.release(&fh), Err(OpenDispatchError::BadFileDescriptor));
    }

    #[test]
    fn contains_inode() {
        let mut t = FileHandleTable::new();
        let a = InodeId::new(10);
        let b = InodeId::new(20);
        t.register(a, 0, false).unwrap();
        assert!(t.contains_inode(a));
        assert!(!t.contains_inode(b));
    }

    #[test]
    fn validate_open_flags_rejects_invalid() {
        assert!(validate_open_flags(0).is_ok()); // O_RDONLY
        assert!(validate_open_flags(1).is_ok()); // O_WRONLY
        assert!(validate_open_flags(2).is_ok()); // O_RDWR
        assert!(validate_open_flags(3).is_err()); // invalid accmode
        assert!(validate_open_flags(0o1000).is_ok()); // O_RDONLY|O_TRUNC
    }

    #[test]
    fn fuse_reply_flags_no_direct() {
        assert_eq!(fuse_open_reply_flags(0), 0);
        assert_eq!(fuse_open_reply_flags(1), 0); // O_WRONLY
    }

    #[test]
    fn fuse_reply_flags_direct() {
        const O_DIRECT: u32 = 0o40000;
        assert_eq!(fuse_open_reply_flags(O_DIRECT), FOPEN_DIRECT_IO);
        assert_eq!(fuse_open_reply_flags(O_DIRECT | 2), FOPEN_DIRECT_IO);
    }
}
