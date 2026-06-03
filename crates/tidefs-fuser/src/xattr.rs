//! FUSE extended-attribute operation handlers backed by
//! [`tidefs_xattr_storage::XattrStore`].
//!
//! Provides per-inode xattr stores with FUSE buffer-size semantics,
//! namespace permission checks, and POSIX setxattr flag handling.
//! Intended for use by [`Filesystem`] trait implementations that
//! need persistent, production-quality xattr support.
//!
//! # Usage
//!
//! ```rust,ignore
//! let mut handlers = FuseXattrHandlers::new();
//! handlers.set(ino, b"user.comment", b"hello", XATTR_CREATE)?;
//! let value = handlers.get(ino, b"user.comment", 512)?;
//! ```

use std::collections::HashMap;
use std::ffi::OsStr;

use crate::errno;

use tidefs_xattr_storage::{validate_posix_xattr_name, XattrSetPlanError, XattrStore};

// Re-export POSIX xattr flag constants for callers.
pub use tidefs_xattr_storage::{POSIX_XATTR_CREATE, POSIX_XATTR_REPLACE};

// ---------------------------------------------------------------------------
// FUSE errno integration
// ---------------------------------------------------------------------------

/// Map xattr-set planning errors to [`libc`] errno codes.
#[must_use]
pub fn errno_from_set_plan_error(e: XattrSetPlanError) -> libc::c_int {
    match e {
        XattrSetPlanError::InvalidName(_) => errno::EINVAL,
        XattrSetPlanError::InvalidValue(_) => errno::E2BIG,
        XattrSetPlanError::InvalidFlags { .. } => errno::EINVAL,
        XattrSetPlanError::EntryExists => errno::EEXIST,
        XattrSetPlanError::EntryNotFound => errno::ENODATA,
    }
}

// ---------------------------------------------------------------------------
// FuseXattrHandlers
// ---------------------------------------------------------------------------

/// Per-inode xattr handler collection backed by [`XattrStore`].
///
/// Manages a map of inode → [`XattrStore`] and provides FUSE operation
/// handlers with buffer-size semantics, namespace permission checks,
/// and POSIX setxattr flag handling.
#[derive(Clone, Debug, Default)]
pub struct FuseXattrHandlers {
    stores: HashMap<u64, XattrStore>,
}

impl FuseXattrHandlers {
    /// Create an empty handler set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stores: HashMap::new(),
        }
    }

    /// Ensure a store exists for `ino`.
    fn store_for(&mut self, ino: u64) -> &mut XattrStore {
        self.stores
            .entry(ino)
            .or_insert_with(|| XattrStore::new(tidefs_xattr_storage::DatasetXattrPolicy::DEFAULT))
    }

    /// Return the namespace-permission-capped value for a name, or `None`
    /// when the caller is not allowed to see it.
    fn visible_value(store: &XattrStore, name: &[u8], uid: u32) -> Option<Vec<u8>> {
        if name.starts_with(b"trusted.") && uid != 0 {
            return None;
        }
        store.get(name)
    }

    // ------------------------------------------------------------------
    // getxattr
    // ------------------------------------------------------------------

    /// Handle `getxattr` with FUSE buffer semantics.
    ///
    /// * `ino`   – inode number
    /// * `name`  – xattr name bytes
    /// * `size`  – caller buffer size (0 = report size only)
    /// * `uid`   – requesting user id
    ///
    /// Returns `Ok((value_bytes, required_size))` on success.
    /// Returns `Err(errno)` on failure.
    pub fn get(
        &self,
        ino: u64,
        name: &OsStr,
        size: u32,
        uid: u32,
    ) -> Result<(Vec<u8>, u32), libc::c_int> {
        let name = name.as_encoded_bytes();
        // Validate name
        validate_posix_xattr_name(name).map_err(|e| match e {
            tidefs_xattr_storage::XattrNameValidationError::EmptyName
            | tidefs_xattr_storage::XattrNameValidationError::NameContainsNul => errno::EINVAL,
            tidefs_xattr_storage::XattrNameValidationError::NameTooLong { .. } => {
                errno::ENAMETOOLONG
            }
        })?;

        let store = self.stores.get(&ino).ok_or(errno::ENOENT)?;

        let value = Self::visible_value(store, name, uid).ok_or(errno::ENODATA)?;

        let value_len = value.len() as u32;
        if size == 0 {
            // Caller wants only the size
            Ok((Vec::new(), value_len))
        } else if value_len <= size {
            Ok((value, value_len))
        } else {
            Err(errno::ERANGE)
        }
    }

    /// Handle `getxattr` (mutable self for on-demand store creation).
    ///
    /// This variant creates the inode store on first access, which is
    /// needed when the handler must track inodes that have zero xattrs.
    pub fn get_mut(
        &mut self,
        ino: u64,
        name: &OsStr,
        size: u32,
        uid: u32,
    ) -> Result<(Vec<u8>, u32), libc::c_int> {
        let name = name.as_encoded_bytes();
        validate_posix_xattr_name(name).map_err(|e| match e {
            tidefs_xattr_storage::XattrNameValidationError::EmptyName
            | tidefs_xattr_storage::XattrNameValidationError::NameContainsNul => errno::EINVAL,
            tidefs_xattr_storage::XattrNameValidationError::NameTooLong { .. } => {
                errno::ENAMETOOLONG
            }
        })?;

        // Create the store on first access so callers can track inodes
        // that have zero xattrs.
        let store = self.store_for(ino);

        let value = Self::visible_value(store, name, uid).ok_or(errno::ENODATA)?;

        let value_len = value.len() as u32;
        if size == 0 {
            Ok((Vec::new(), value_len))
        } else if value_len <= size {
            Ok((value, value_len))
        } else {
            Err(errno::ERANGE)
        }
    }

    // ------------------------------------------------------------------
    // setxattr
    // ------------------------------------------------------------------

    /// Handle `setxattr` with POSIX flag handling.
    ///
    /// * `flags` – 0 (upsert), `XATTR_CREATE` (1), or `XATTR_REPLACE` (2)
    /// * `uid`   – requesting user id
    ///
    /// Returns `Ok(())` on success, `Err(errno)` on failure.
    pub fn set(
        &mut self,
        ino: u64,
        name: &OsStr,
        value: &[u8],
        flags: u32,
        uid: u32,
    ) -> Result<(), libc::c_int> {
        let name = name.as_encoded_bytes();

        // Validate name
        validate_posix_xattr_name(name).map_err(|e| match e {
            tidefs_xattr_storage::XattrNameValidationError::EmptyName
            | tidefs_xattr_storage::XattrNameValidationError::NameContainsNul => errno::EINVAL,
            tidefs_xattr_storage::XattrNameValidationError::NameTooLong { .. } => {
                errno::ENAMETOOLONG
            }
        })?;

        // Validate value
        if name.starts_with(b"trusted.") && uid != 0 {
            return Err(errno::EPERM);
        }

        // Permission check: security.* is generally immutable from userspace
        if name.starts_with(b"security.") && uid != 0 {
            return Err(errno::EPERM);
        }

        let store = self.store_for(ino);
        let _previous = store
            .set_with_posix_flags(name, value, flags)
            .map_err(errno_from_set_plan_error)?;

        Ok(())
    }

    // ------------------------------------------------------------------
    // listxattr
    // ------------------------------------------------------------------

    /// Handle `listxattr` with FUSE buffer semantics.
    ///
    /// Returns a NUL-separated list of xattr names. Non-root callers
    /// never see `trusted.*` names.
    ///
    /// * `size` – caller buffer size (0 = report size only)
    pub fn list(&self, ino: u64, size: u32, uid: u32) -> Result<(Vec<u8>, u32), libc::c_int> {
        let store = self.stores.get(&ino).ok_or(errno::ENOENT)?;

        let mut names: Vec<Vec<u8>> = store
            .list_names()
            .into_iter()
            .filter(|n| !n.starts_with(b"trusted.") || uid == 0)
            .collect();

        // Sort for deterministic output
        names.sort();

        // Build NUL-separated packed list
        let mut packed = Vec::new();
        for name in &names {
            packed.extend_from_slice(name);
            packed.push(0);
        }

        let packed_len = packed.len() as u32;
        if size == 0 {
            Ok((Vec::new(), packed_len))
        } else if packed_len <= size {
            Ok((packed, packed_len))
        } else {
            Err(errno::ERANGE)
        }
    }

    /// Handle `listxattr` (mutable self variant).
    pub fn list_mut(
        &mut self,
        ino: u64,
        size: u32,
        uid: u32,
    ) -> Result<(Vec<u8>, u32), libc::c_int> {
        // Delegates to immutable version
        self.list(ino, size, uid)
    }

    // ------------------------------------------------------------------
    // removexattr
    // ------------------------------------------------------------------

    /// Handle `removexattr`.
    ///
    /// Returns `Ok(())` on success, `Err(ENODATA)` if absent,
    /// `Err(EPERM)` for immutable namespaces.
    pub fn remove(&mut self, ino: u64, name: &OsStr, uid: u32) -> Result<(), libc::c_int> {
        let name = name.as_encoded_bytes();

        // Validate name
        validate_posix_xattr_name(name).map_err(|e| match e {
            tidefs_xattr_storage::XattrNameValidationError::EmptyName
            | tidefs_xattr_storage::XattrNameValidationError::NameContainsNul => errno::EINVAL,
            tidefs_xattr_storage::XattrNameValidationError::NameTooLong { .. } => {
                errno::ENAMETOOLONG
            }
        })?;

        // Permission checks
        if name.starts_with(b"trusted.") && uid != 0 {
            return Err(errno::EPERM);
        }
        if name.starts_with(b"security.") && uid != 0 {
            return Err(errno::EPERM);
        }

        let store = self.stores.get_mut(&ino).ok_or(errno::ENOENT)?;

        store.remove(name).map_err(|e| match e {
            tidefs_xattr_storage::XattrStoreError::EntryNotFound => errno::ENODATA,
        })?;

        Ok(())
    }

    // ------------------------------------------------------------------
    // Inspection
    // ------------------------------------------------------------------

    /// Return the number of xattrs stored for an inode.
    #[must_use]
    pub fn count(&self, ino: u64) -> usize {
        self.stores.get(&ino).map_or(0, |s| s.len() as usize)
    }

    /// Return true if the inode has an ACL (system.posix_acl_access present).
    #[must_use]
    pub fn has_acl(&self, ino: u64) -> bool {
        self.stores.get(&ino).is_some_and(|s| s.has_acl())
    }

    /// Return the number of tracked inodes (including empty stores).
    #[must_use]
    pub fn inode_count(&self) -> usize {
        self.stores.len()
    }

    /// Remove all xattr state for an inode (e.g., on unlink).
    pub fn evict_inode(&mut self, ino: u64) {
        self.stores.remove(&ino);
    }
}

// ---------------------------------------------------------------------------
// handle_* -- canonical FUSE dispatch entry points for xattr operations
// ---------------------------------------------------------------------------

/// Canonical FUSE dispatch entry point for `getxattr` (opcode 22).
///
/// Wraps [`FuseXattrHandlers::get`] with a consistent entry-point signature.
/// All name validation, namespace permission checks, and buffer-size semantics
/// are delegated to the underlying handler.
#[inline]
pub fn handle_getxattr(
    handlers: &FuseXattrHandlers,
    ino: u64,
    name: &OsStr,
    size: u32,
    uid: u32,
) -> Result<(Vec<u8>, u32), libc::c_int> {
    handlers.get(ino, name, size, uid)
}

/// Canonical FUSE dispatch entry point for `setxattr` (opcode 6).
///
/// Wraps [`FuseXattrHandlers::set`] with a read-only filesystem guard
/// (`EROFS`). All name validation, namespace permission checks, POSIX flag
/// handling, and value-size validation are delegated to the underlying handler.
#[inline]
pub fn handle_setxattr(
    handlers: &mut FuseXattrHandlers,
    ino: u64,
    name: &OsStr,
    value: &[u8],
    flags: u32,
    uid: u32,
    read_only: bool,
) -> Result<(), libc::c_int> {
    if read_only {
        return Err(libc::EROFS);
    }
    handlers.set(ino, name, value, flags, uid)
}

/// Canonical FUSE dispatch entry point for `listxattr` (opcode 23).
///
/// Wraps [`FuseXattrHandlers::list`] with a consistent entry-point signature.
/// All namespace filtering (`trusted.*` hidden from non-root) and buffer-size
/// semantics are delegated to the underlying handler.
#[inline]
pub fn handle_listxattr(
    handlers: &FuseXattrHandlers,
    ino: u64,
    size: u32,
    uid: u32,
) -> Result<(Vec<u8>, u32), libc::c_int> {
    handlers.list(ino, size, uid)
}

/// Canonical FUSE dispatch entry point for `removexattr` (opcode 24).
///
/// Wraps [`FuseXattrHandlers::remove`] with a read-only filesystem guard
/// (`EROFS`). All name validation and namespace permission checks
/// (`trusted.*` / `security.*`) are delegated to the underlying handler.
#[inline]
pub fn handle_removexattr(
    handlers: &mut FuseXattrHandlers,
    ino: u64,
    name: &OsStr,
    uid: u32,
    read_only: bool,
) -> Result<(), libc::c_int> {
    if read_only {
        return Err(libc::EROFS);
    }
    handlers.remove(ino, name, uid)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    fn name(s: &str) -> &OsStr {
        OsStr::new(s)
    }

    #[test]
    fn getxattr_returns_value() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.comment"), b"hello", 0, 1000).unwrap();

        let (val, len) = h.get(1, name("user.comment"), 1024, 1000).unwrap();
        assert_eq!(val, b"hello");
        assert_eq!(len, 5);
    }

    #[test]
    fn getxattr_size_zero_reports_size_only() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.comment"), b"hello", 0, 1000).unwrap();

        let (val, len) = h.get(1, name("user.comment"), 0, 1000).unwrap();
        assert!(val.is_empty());
        assert_eq!(len, 5);
    }

    #[test]
    fn getxattr_oversized_buffer_returns_erange() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.comment"), b"hello", 0, 1000).unwrap();

        assert_eq!(
            h.get(1, name("user.comment"), 3, 1000).unwrap_err(),
            errno::ERANGE
        );
    }

    #[test]
    fn getxattr_missing_attribute_returns_enodata() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.a"), b"v", 0, 1000).unwrap();

        assert_eq!(
            h.get(1, name("user.b"), 1024, 1000).unwrap_err(),
            errno::ENODATA
        );
    }

    #[test]
    fn getxattr_missing_inode_returns_enoent() {
        let h = FuseXattrHandlers::new();
        assert_eq!(
            h.get(42, name("user.a"), 1024, 1000).unwrap_err(),
            errno::ENOENT
        );
    }

    #[test]
    fn getxattr_empty_name_returns_einval() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.a"), b"v", 0, 1000).unwrap();
        assert_eq!(h.get(1, name(""), 1024, 1000).unwrap_err(), errno::EINVAL);
    }

    #[test]
    fn getxattr_trusted_returns_enodata_for_non_root() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("trusted.overlay"), b"secret", 0, 0).unwrap();

        // root can see it
        assert!(h.get(1, name("trusted.overlay"), 1024, 0).is_ok());
        // non-root gets ENODATA
        assert_eq!(
            h.get(1, name("trusted.overlay"), 1024, 1000).unwrap_err(),
            errno::ENODATA
        );
    }

    // -- setxattr --

    #[test]
    fn setxattr_upsert_creates_and_replaces() {
        let mut h = FuseXattrHandlers::new();

        h.set(1, name("user.a"), b"first", 0, 1000).unwrap();
        let (val, _) = h.get(1, name("user.a"), 1024, 1000).unwrap();
        assert_eq!(val, b"first");

        h.set(1, name("user.a"), b"second", 0, 1000).unwrap();
        let (val, _) = h.get(1, name("user.a"), 1024, 1000).unwrap();
        assert_eq!(val, b"second");
    }

    #[test]
    fn setxattr_create_fails_on_existing() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.a"), b"v", 0, 1000).unwrap();

        assert_eq!(
            h.set(1, name("user.a"), b"v2", POSIX_XATTR_CREATE, 1000)
                .unwrap_err(),
            errno::EEXIST
        );
    }

    #[test]
    fn setxattr_replace_fails_on_missing() {
        let mut h = FuseXattrHandlers::new();

        assert_eq!(
            h.set(1, name("user.a"), b"v", POSIX_XATTR_REPLACE, 1000)
                .unwrap_err(),
            errno::ENODATA
        );
    }

    #[test]
    fn setxattr_create_succeeds_when_absent() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.a"), b"v", POSIX_XATTR_CREATE, 1000)
            .unwrap();
        let (val, _) = h.get(1, name("user.a"), 1024, 1000).unwrap();
        assert_eq!(val, b"v");
    }

    #[test]
    fn setxattr_replace_succeeds_when_present() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.a"), b"old", 0, 1000).unwrap();
        h.set(1, name("user.a"), b"new", POSIX_XATTR_REPLACE, 1000)
            .unwrap();
        let (val, _) = h.get(1, name("user.a"), 1024, 1000).unwrap();
        assert_eq!(val, b"new");
    }

    #[test]
    fn setxattr_trusted_requires_root() {
        let mut h = FuseXattrHandlers::new();

        // root succeeds
        assert!(h.set(1, name("trusted.key"), b"v", 0, 0).is_ok());

        // non-root fails
        assert_eq!(
            h.set(2, name("trusted.key"), b"v", 0, 1000).unwrap_err(),
            errno::EPERM
        );
    }

    #[test]
    fn setxattr_security_requires_root() {
        let mut h = FuseXattrHandlers::new();
        assert_eq!(
            h.set(1, name("security.selinux"), b"v", 0, 1000)
                .unwrap_err(),
            errno::EPERM
        );
        assert!(h.set(1, name("security.selinux"), b"v", 0, 0).is_ok());
    }

    #[test]
    fn setxattr_zero_length_value() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.empty"), b"", 0, 1000).unwrap();
        let (val, len) = h.get(1, name("user.empty"), 1024, 1000).unwrap();
        assert!(val.is_empty());
        assert_eq!(len, 0);
    }

    #[test]
    fn setxattr_oversized_value_returns_e2big() {
        let mut h = FuseXattrHandlers::new();
        let big = vec![0u8; 65537]; // 64 KiB + 1
        assert_eq!(
            h.set(1, name("user.big"), &big, 0, 1000).unwrap_err(),
            errno::E2BIG
        );
    }

    #[test]
    fn setxattr_long_name_returns_enametoolong() {
        let mut h = FuseXattrHandlers::new();
        let long_name = format!("user.{}", "x".repeat(251)); // exceeds 255
        assert_eq!(
            h.set(1, name(&long_name), b"v", 0, 1000).unwrap_err(),
            errno::ENAMETOOLONG
        );
    }

    // -- listxattr --

    #[test]
    fn listxattr_returns_packed_names() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.b"), b"vb", 0, 1000).unwrap();
        h.set(1, name("user.a"), b"va", 0, 1000).unwrap();

        let (names, len) = h.list(1, 1024, 1000).unwrap();
        // Sorted: user.a\0user.b\0
        assert_eq!(names, b"user.a\0user.b\0");
        assert_eq!(len, 14);
    }

    #[test]
    fn listxattr_size_zero_reports_size_only() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.a"), b"v", 0, 1000).unwrap();

        let (names, len) = h.list(1, 0, 1000).unwrap();
        assert!(names.is_empty());
        assert_eq!(len, 7); // "user.a\0"
    }

    #[test]
    fn listxattr_undersized_buffer_returns_erange() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.a"), b"v", 0, 1000).unwrap();

        assert_eq!(h.list(1, 3, 1000).unwrap_err(), errno::ERANGE);
    }

    #[test]
    fn listxattr_filters_trusted_for_non_root() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.a"), b"v", 0, 0).unwrap();
        h.set(1, name("trusted.overlay"), b"secret", 0, 0).unwrap();

        // Root sees both
        let (names, _) = h.list(1, 1024, 0).unwrap();
        let decoded: Vec<&[u8]> = names.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
        assert_eq!(decoded.len(), 2);

        // Non-root sees only user.*
        let (names, _) = h.list(1, 1024, 1000).unwrap();
        let decoded: Vec<&[u8]> = names.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], b"user.a");
    }

    #[test]
    fn listxattr_missing_inode_returns_enoent() {
        let h = FuseXattrHandlers::new();
        assert_eq!(h.list(42, 1024, 1000).unwrap_err(), errno::ENOENT);
    }

    // -- removexattr --

    #[test]
    fn removexattr_deletes_attribute() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.a"), b"v", 0, 1000).unwrap();
        assert_eq!(h.count(1), 1);

        h.remove(1, name("user.a"), 1000).unwrap();
        assert_eq!(h.count(1), 0);
        assert_eq!(
            h.get(1, name("user.a"), 1024, 1000).unwrap_err(),
            errno::ENODATA
        );
    }

    #[test]
    fn removexattr_missing_returns_enodata() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.a"), b"v", 0, 1000).unwrap();

        assert_eq!(
            h.remove(1, name("user.b"), 1000).unwrap_err(),
            errno::ENODATA
        );
    }

    #[test]
    fn removexattr_missing_inode_returns_enoent() {
        let mut h = FuseXattrHandlers::new();
        assert_eq!(
            h.remove(42, name("user.a"), 1000).unwrap_err(),
            errno::ENOENT
        );
    }

    #[test]
    fn removexattr_trusted_requires_root() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("trusted.key"), b"v", 0, 0).unwrap();

        assert_eq!(
            h.remove(1, name("trusted.key"), 1000).unwrap_err(),
            errno::EPERM
        );
        assert!(h.remove(1, name("trusted.key"), 0).is_ok());
    }

    #[test]
    fn removexattr_keeps_empty_store_tracked() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.a"), b"v", 0, 1000).unwrap();
        assert_eq!(h.inode_count(), 1);

        h.remove(1, name("user.a"), 1000).unwrap();
        // Store persists even when empty; subsequent get returns ENODATA, not ENOENT
        assert_eq!(h.inode_count(), 1);
        assert_eq!(h.count(1), 0);
    }
    #[test]
    fn evict_inode_removes_all_state() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.a"), b"va", 0, 1000).unwrap();
        h.set(1, name("user.b"), b"vb", 0, 1000).unwrap();
        assert_eq!(h.inode_count(), 1);
        assert_eq!(h.count(1), 2);

        h.evict_inode(1);
        assert_eq!(h.inode_count(), 0);
        assert_eq!(
            h.get(1, name("user.a"), 1024, 1000).unwrap_err(),
            errno::ENOENT
        );
    }

    // -- multi-inode isolation --

    #[test]
    fn multi_inode_isolation() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.a"), b"v1", 0, 1000).unwrap();
        h.set(2, name("user.a"), b"v2", 0, 1000).unwrap();

        let (val1, _) = h.get(1, name("user.a"), 1024, 1000).unwrap();
        let (val2, _) = h.get(2, name("user.a"), 1024, 1000).unwrap();
        assert_eq!(val1, b"v1");
        assert_eq!(val2, b"v2");

        h.remove(1, name("user.a"), 1000).unwrap();
        assert_eq!(h.count(1), 0);
        assert_eq!(h.count(2), 1);
    }

    // -- handle_getxattr ------------------------------------------------------

    #[test]
    fn handle_getxattr_forward_returns_value() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.a"), b"hello", 0, 1000).unwrap();
        let (val, len) = handle_getxattr(&h, 1, name("user.a"), 1024, 1000).unwrap();
        assert_eq!(val, b"hello");
        assert_eq!(len, 5);
    }

    #[test]
    fn handle_getxattr_missing_inode_returns_enoent() {
        let h = FuseXattrHandlers::new();
        assert_eq!(
            handle_getxattr(&h, 42, name("user.a"), 1024, 1000).unwrap_err(),
            errno::ENOENT
        );
    }

    #[test]
    fn handle_getxattr_missing_attr_returns_enodata() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.a"), b"v", 0, 1000).unwrap();
        assert_eq!(
            handle_getxattr(&h, 1, name("user.b"), 1024, 1000).unwrap_err(),
            errno::ENODATA
        );
    }

    // -- handle_setxattr ------------------------------------------------------

    #[test]
    fn handle_setxattr_writable_succeeds() {
        let mut h = FuseXattrHandlers::new();
        handle_setxattr(&mut h, 1, name("user.a"), b"v", 0, 1000, false).unwrap();
        let (val, _) = h.get(1, name("user.a"), 1024, 1000).unwrap();
        assert_eq!(val, b"v");
    }

    #[test]
    fn handle_setxattr_read_only_rejected() {
        let mut h = FuseXattrHandlers::new();
        assert_eq!(
            handle_setxattr(&mut h, 1, name("user.a"), b"v", 0, 1000, true).unwrap_err(),
            libc::EROFS
        );
    }

    #[test]
    fn handle_setxattr_read_only_takes_priority_over_name_validation() {
        let mut h = FuseXattrHandlers::new();
        // read-only guard fires before name validation
        assert_eq!(
            handle_setxattr(&mut h, 1, name(""), b"v", 0, 1000, true).unwrap_err(),
            libc::EROFS
        );
    }

    // -- handle_listxattr -----------------------------------------------------

    #[test]
    fn handle_listxattr_forward_returns_packed() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.b"), b"vb", 0, 1000).unwrap();
        h.set(1, name("user.a"), b"va", 0, 1000).unwrap();
        let (names, len) = handle_listxattr(&h, 1, 1024, 1000).unwrap();
        assert_eq!(names, b"user.a user.b ");
        assert_eq!(len, 14);
    }

    #[test]
    fn handle_listxattr_missing_inode_returns_enoent() {
        let h = FuseXattrHandlers::new();
        assert_eq!(
            handle_listxattr(&h, 42, 1024, 1000).unwrap_err(),
            errno::ENOENT
        );
    }

    #[test]
    fn handle_listxattr_undersized_buffer_returns_erange() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.a"), b"v", 0, 1000).unwrap();
        assert_eq!(handle_listxattr(&h, 1, 3, 1000).unwrap_err(), errno::ERANGE);
    }

    // -- handle_removexattr ---------------------------------------------------

    #[test]
    fn handle_removexattr_writable_succeeds() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.a"), b"v", 0, 1000).unwrap();
        handle_removexattr(&mut h, 1, name("user.a"), 1000, false).unwrap();
        assert_eq!(h.count(1), 0);
    }

    #[test]
    fn handle_removexattr_read_only_rejected() {
        let mut h = FuseXattrHandlers::new();
        h.set(1, name("user.a"), b"v", 0, 1000).unwrap();
        assert_eq!(
            handle_removexattr(&mut h, 1, name("user.a"), 1000, true).unwrap_err(),
            libc::EROFS
        );
    }

    #[test]
    fn handle_removexattr_missing_inode_returns_enoent() {
        let mut h = FuseXattrHandlers::new();
        assert_eq!(
            handle_removexattr(&mut h, 42, name("user.a"), 1000, false).unwrap_err(),
            errno::ENOENT
        );
    }
}
