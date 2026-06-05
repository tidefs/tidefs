//! FUSE extended-attribute dispatch handlers backed by [`LocalFileSystem`].
//!
//! Provides engine-level functions (`engine_getxattr`, `engine_setxattr`,
//! `engine_listxattr`, `engine_removexattr`) for VFS engine use: validate
//! inputs, interact with [`LocalFileSystem`], and map errors.  The engine
//! layer adds namespace permission checks (trusted.*) and POSIX ACL
//! validation on top.
//!
//! All functions map errors through [`XattrDispatchError`], which carries
//! standard POSIX errno values.

use tidefs_types_vfs_core::InodeId;

use crate::{FileSystemError, LocalFileSystem};

// Xattr limits (mirrors tidefs-inode-table constants)
const MAX_XATTR_VALUE_LEN: usize = 64 * 1024;
const MAX_XATTR_NAME_LEN: usize = 255;
const MAX_XATTR_COUNT: usize = 256;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate an xattr name: non-empty, no embedded NUL, not too long.
fn validate_xattr_name(name: &[u8]) -> Result<(), XattrDispatchError> {
    if name.is_empty() || name.contains(&0) {
        return Err(XattrDispatchError::Invalid);
    }
    if name.len() > MAX_XATTR_NAME_LEN {
        return Err(XattrDispatchError::NameTooLong);
    }
    // Must have a known namespace prefix with non-empty suffix.
    if (name.starts_with(b"user.") && name.len() > b"user.".len())
        || (name.starts_with(b"system.") && name.len() > b"system.".len())
        || (name.starts_with(b"security.") && name.len() > b"security.".len())
        || (name.starts_with(b"trusted.") && name.len() > b"trusted.".len())
    {
        return Ok(());
    }
    Err(XattrDispatchError::NotSupported)
}

/// Validate an xattr value: must not exceed the 64 KiB limit.
fn validate_xattr_value(value: &[u8]) -> Result<(), XattrDispatchError> {
    if value.len() > MAX_XATTR_VALUE_LEN {
        return Err(XattrDispatchError::TooBig);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Dispatch error
// ---------------------------------------------------------------------------

/// Errors returned by xattr dispatch handlers.
///
/// Maps directly to POSIX errno values consumed by FUSE reply helpers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrDispatchError {
    /// No such file or directory (inode not found).
    NoEntry,
    /// Attribute does not exist.
    NoData,
    /// Attribute already exists (XATTR_CREATE on existing key).
    AlreadyExists,
    #[allow(dead_code)] // INTENT: xattr dispatch error variants for planned FUSE xattr handler
    /// Caller buffer too small for the value / name list.
    Range,
    /// Value exceeds the 64 KiB per-xattr limit.
    TooBig,
    /// Per-inode xattr count limit reached (256).
    NoSpace,
    /// Invalid name (empty, contains NUL, too long, unsupported namespace).
    Invalid,
    /// Name exceeds the 255-byte POSIX xattr name limit.
    NameTooLong,
    /// Operation not supported (e.g. unsupported xattr namespace).
    NotSupported,
    #[allow(dead_code)] // INTENT: xattr dispatch error variants for planned FUSE xattr handler
    /// Permission denied (non-root accessing trusted.* or security.*).
    PermissionDenied,
    /// Internal I/O or consistency error.
    Io,
}

impl From<&FileSystemError> for XattrDispatchError {
    fn from(e: &FileSystemError) -> Self {
        match e {
            FileSystemError::NotFound { .. } => Self::NoEntry,
            FileSystemError::AlreadyExists { .. } => Self::AlreadyExists,
            FileSystemError::InvalidName { .. } => Self::Invalid,
            FileSystemError::NoSpace { .. } => Self::NoSpace,
            FileSystemError::CorruptState { .. } | FileSystemError::CorruptContent { .. } => {
                Self::Io
            }
            FileSystemError::AclValidationFailed { .. } => Self::Invalid,
            _ => Self::Io,
        }
    }
}

fn inode_xattr_mutation_error(e: &FileSystemError) -> XattrDispatchError {
    match e {
        FileSystemError::NotFound { path }
            if path.starts_with("<inode:") && path.contains(">:") =>
        {
            XattrDispatchError::NoData
        }
        _ => XattrDispatchError::from(e),
    }
}

// ---------------------------------------------------------------------------
// Errno conversion
// ---------------------------------------------------------------------------

/// Convert an [`XattrDispatchError`] to a [`tidefs_vfs_engine::Errno`].
///
/// Used by `VfsLocalFileSystem` to map dispatch errors into the VFS engine
/// error space.
#[must_use]
pub fn errno_from_dispatch_error(e: XattrDispatchError) -> tidefs_vfs_engine::Errno {
    use tidefs_vfs_engine::Errno;
    match e {
        XattrDispatchError::NoEntry => Errno::ENOENT,
        XattrDispatchError::NoData => Errno::ENODATA,
        XattrDispatchError::AlreadyExists => Errno::EEXIST,
        XattrDispatchError::Range => Errno::ERANGE,
        XattrDispatchError::TooBig => Errno::E2BIG,
        XattrDispatchError::NoSpace => Errno::ENOSPC,
        XattrDispatchError::Invalid => Errno::EINVAL,
        XattrDispatchError::NameTooLong => Errno::ENAMETOOLONG,
        XattrDispatchError::NotSupported => Errno::EOPNOTSUPP,
        XattrDispatchError::PermissionDenied => Errno::EPERM,
        XattrDispatchError::Io => Errno::EIO,
    }
}

// ---------------------------------------------------------------------------
// Engine-level dispatch functions
// ---------------------------------------------------------------------------

/// Get an extended attribute value for `path` by `name`.
///
/// Returns `None` when the attribute does not exist. The caller must
/// handle namespace permission checks and inode-to-path resolution.
#[allow(dead_code)] // INTENT: path-dispatch support retained for crate tests; VFS hot path uses inode dispatch.
pub fn engine_getxattr(
    fs: &LocalFileSystem,
    path: &str,
    name: &[u8],
) -> Result<Option<Vec<u8>>, XattrDispatchError> {
    validate_xattr_name(name)?;
    fs.get_xattr(path, name)
        .map_err(|e| XattrDispatchError::from(&e))
}

/// Get an extended attribute value for `inode` by `name`.
pub fn engine_getxattr_by_inode(
    fs: &LocalFileSystem,
    inode: InodeId,
    name: &[u8],
) -> Result<Option<Vec<u8>>, XattrDispatchError> {
    validate_xattr_name(name)?;
    fs.get_xattr_by_inode(inode, name)
        .map_err(|e| XattrDispatchError::from(&e))
}

/// Set an extended attribute on `path`.
///
/// `flags` is one of: 0 (create or replace), 1 (XATTR_CREATE), 2 (XATTR_REPLACE).
/// Handles flag pre-checks (existence, count limit) and value-size validation.
/// The caller must handle namespace permission checks.
#[allow(dead_code)] // INTENT: path-dispatch support retained for crate tests; VFS hot path uses inode dispatch.
pub fn engine_setxattr(
    fs: &mut LocalFileSystem,
    path: &str,
    name: &[u8],
    value: &[u8],
    flags: u32,
) -> Result<(), XattrDispatchError> {
    validate_xattr_name(name)?;
    validate_xattr_value(value)?;

    // Validate flags
    if flags > 2 {
        return Err(XattrDispatchError::Invalid);
    }

    // Pre-check flag constraints against current state without materializing
    // the full xattr list or cloning the old value. xattr-heavy fsstress
    // workloads call this path thousands of times.
    let (exists, current_count) = fs
        .xattr_exists_and_count(path, name)
        .map_err(|e| XattrDispatchError::from(&e))?;

    match flags {
        1 => {
            // XATTR_CREATE
            if exists {
                return Err(XattrDispatchError::AlreadyExists);
            }
            if current_count >= MAX_XATTR_COUNT {
                return Err(XattrDispatchError::NoSpace);
            }
        }
        2 => {
            // XATTR_REPLACE
            if !exists {
                return Err(XattrDispatchError::NoData);
            }
        }
        _ => {
            // flag 0: create or replace — only check count when adding new
            if !exists && current_count >= MAX_XATTR_COUNT {
                return Err(XattrDispatchError::NoSpace);
            }
        }
    }

    fs.set_xattr(path, name, value, flags as i32)
        .map_err(|e| XattrDispatchError::from(&e))
}

/// Set an extended attribute on `inode` without resolving the inode back to a
/// path. This is the VFS/FUSE hot path.
pub fn engine_setxattr_by_inode(
    fs: &mut LocalFileSystem,
    inode: InodeId,
    name: &[u8],
    value: &[u8],
    flags: u32,
) -> Result<(), XattrDispatchError> {
    validate_xattr_name(name)?;
    validate_xattr_value(value)?;

    if flags > 2 {
        return Err(XattrDispatchError::Invalid);
    }

    fs.set_xattr_by_inode_limited(inode, name, value, flags as i32, MAX_XATTR_COUNT)
        .map_err(|e| inode_xattr_mutation_error(&e))
}

/// List extended attribute names for `path`.
///
/// Returns null-separated name bytes. The caller must handle
/// trusted.* filtering for non-root callers.
#[allow(dead_code)] // INTENT: path-dispatch support retained for crate tests; VFS hot path uses inode dispatch.
pub fn engine_listxattr(fs: &LocalFileSystem, path: &str) -> Result<Vec<u8>, XattrDispatchError> {
    fs.list_xattr(path)
        .map_err(|e| XattrDispatchError::from(&e))
}

/// List extended attribute names for `inode`.
pub fn engine_listxattr_by_inode(
    fs: &LocalFileSystem,
    inode: InodeId,
) -> Result<Vec<u8>, XattrDispatchError> {
    fs.list_xattr_by_inode(inode)
        .map_err(|e| XattrDispatchError::from(&e))
}

/// Remove an extended attribute from `path`.
///
/// Returns `NoData` when the attribute does not exist. The caller must
/// handle namespace permission checks.
#[allow(dead_code)] // INTENT: path-dispatch support retained for crate tests; VFS hot path uses inode dispatch.
pub fn engine_removexattr(
    fs: &mut LocalFileSystem,
    path: &str,
    name: &[u8],
) -> Result<(), XattrDispatchError> {
    validate_xattr_name(name)?;

    // Check existence without cloning the old value.
    let exists = fs
        .xattr_exists_and_count(path, name)
        .map_err(|e| XattrDispatchError::from(&e))?
        .0;
    if !exists {
        return Err(XattrDispatchError::NoData);
    }
    fs.remove_xattr(path, name)
        .map_err(|e| XattrDispatchError::from(&e))
}

/// Remove an extended attribute from `inode`.
pub fn engine_removexattr_by_inode(
    fs: &mut LocalFileSystem,
    inode: InodeId,
    name: &[u8],
) -> Result<(), XattrDispatchError> {
    validate_xattr_name(name)?;
    fs.remove_xattr_by_inode(inode, name)
        .map_err(|e| inode_xattr_mutation_error(&e))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::human::local_filesystem::StoreOptions;
    use crate::RootAuthenticationKey;

    fn setup() -> (LocalFileSystem, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let fs = LocalFileSystem::open_with_root_authentication_key(
            dir.path(),
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open fs");
        (fs, dir)
    }

    fn create_file(fs: &mut LocalFileSystem, path: &str) {
        fs.create_file(path, 0o644).expect("create_file");
    }

    // ── engine-level tests ─────────────────────────────────────────────

    #[test]
    fn engine_getxattr_success() {
        let (mut fs, _dir) = setup();
        create_file(&mut fs, "/f");
        fs.set_xattr("/f", b"user.key", b"engine-val", 0).unwrap();

        let val = engine_getxattr(&fs, "/f", b"user.key").unwrap();
        assert_eq!(val, Some(b"engine-val".to_vec()));
    }

    #[test]
    fn engine_getxattr_missing_returns_none() {
        let (mut fs, _dir) = setup();
        create_file(&mut fs, "/f");

        let val = engine_getxattr(&fs, "/f", b"user.nope").unwrap();
        assert_eq!(val, None);
    }

    #[test]
    fn engine_setxattr_create_replace_roundtrip() {
        let (mut fs, _dir) = setup();
        create_file(&mut fs, "/f");

        engine_setxattr(&mut fs, "/f", b"user.eng", b"first", 0).unwrap();
        engine_setxattr(&mut fs, "/f", b"user.eng", b"second", 0).unwrap();
        let val = engine_getxattr(&fs, "/f", b"user.eng").unwrap();
        assert_eq!(val, Some(b"second".to_vec()));
    }

    #[test]
    fn engine_listxattr_returns_names() {
        let (mut fs, _dir) = setup();
        create_file(&mut fs, "/f");
        fs.set_xattr("/f", b"user.x", b"1", 0).unwrap();
        fs.set_xattr("/f", b"user.y", b"2", 0).unwrap();

        let names = engine_listxattr(&fs, "/f").unwrap();
        let parts: Vec<&[u8]> = names.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
        assert_eq!(parts.len(), 2);
    }
}
