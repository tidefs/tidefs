// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Kernel-compatible xattr bridge -- K7-19 xattr-storage seam.
//!
//! Bridges kernel extended attribute operations to the canonical
//! [`tidefs_xattr_storage::XattrStore`] persistence primitives.
//!
//! This module provides pure bridge functions that translate
//! kernel VFS xattr dispatch parameters into xattr-storage calls,
//! with namespace validation, flag handling, and error mapping.
//!
//! Under cargo builds the bridge uses `alloc::vec::Vec` for xattr
//! value buffers. Under Kbuild (`CONFIG_RUST`) it uses
//! `kernel::alloc::KVec` for kernel-compatible allocations.
//!
//! # No-daemon boundary
//!
//! All operations in this module resolve locally within kernel
//! authority through `XattrStore`. No userspace daemon, helper,
//! or upcall is required for xattr persistence.
//!
//! # Integration
//!
//! This bridge is a companion to [`crate::xattr`], which dispatches
//! to the [`tidefs_kmod_bridge::kernel_types::VfsEngine`] trait.
//! Engine implementations that use `XattrStore` directly call
//! these bridge functions for per-inode xattr persistence.

// Under Kbuild, use the internal tidefs_kmod_bridge module.
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::errno::KernelErrno;
use tidefs_kmod_bridge::kernel_types::{Errno, InodeId, RequestCtx};

// Under cargo, use the real tidefs-xattr-storage crate.
// Under Kbuild, use the kernel-compatible stubs from the bridge.
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge::kernel_types::{
    pack_posix_xattr_name_list, DatasetXattrPolicy, XattrStore, XattrStoreError,
};
#[cfg(not(CONFIG_RUST))]
use tidefs_xattr_storage::{pack_posix_xattr_name_list, XattrStore, XattrStoreError};

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

/// Byte buffer for xattr values and name lists.
#[cfg(not(CONFIG_RUST))]
type XattrBuf = alloc::vec::Vec<u8>;
#[cfg(CONFIG_RUST)]
type XattrBuf = kernel::alloc::KVec<u8>;

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

fn copy_to_buf(slice: &[u8]) -> XattrBuf {
    #[cfg(not(CONFIG_RUST))]
    {
        let mut v = alloc::vec::Vec::with_capacity(slice.len());
        v.extend_from_slice(slice);
        v
    }
    #[cfg(CONFIG_RUST)]
    {
        let mut kv =
            kernel::alloc::KVec::<u8>::with_capacity(slice.len(), kernel::alloc::flags::GFP_KERNEL)
                .unwrap_or_else(|_| kernel::alloc::KVec::<u8>::new());
        let _ = kv.extend_from_slice(slice, kernel::alloc::flags::GFP_KERNEL);
        kv
    }
}

// ---------------------------------------------------------------------------
// Xattr name validation
// ---------------------------------------------------------------------------

const VALID_XATTR_NAMESPACES: &[&[u8]] = &[b"security.", b"system.", b"trusted.", b"user."];

/// Validate that `name` starts with a recognised namespace prefix.
pub fn validate_xattr_namespace(name: &[u8]) -> Result<(), Errno> {
    if VALID_XATTR_NAMESPACES
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        Ok(())
    } else {
        Err(KernelErrno::UNSUPPORTED_OP)
    }
}

/// Validate basic xattr name constraints.
pub fn validate_xattr_name_basic(name: &[u8]) -> Result<(), Errno> {
    if name.is_empty() || name.contains(&0) {
        return Err(KernelErrno::INVALID_ARGUMENT);
    }
    if name.len() > 255 {
        return Err(KernelErrno::NS_NAME_TOO_LONG);
    }
    Ok(())
}

/// Full xattr name validation: namespace prefix + basic constraints.
pub fn validate_xattr_name(name: &[u8]) -> Result<(), Errno> {
    validate_xattr_namespace(name)?;
    validate_xattr_name_basic(name)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// POSIX xattr flags
// ---------------------------------------------------------------------------

/// `XATTR_CREATE` -- fail if the xattr already exists.
pub const XATTR_CREATE: u32 = 0x01;
/// `XATTR_REPLACE` -- fail if the xattr does not exist.
pub const XATTR_REPLACE: u32 = 0x02;

/// Validate setxattr flags.
pub fn validate_xattr_flags(flags: u32) -> Result<(), Errno> {
    if flags > XATTR_REPLACE || flags == (XATTR_CREATE | XATTR_REPLACE) {
        return Err(KernelErrno::INVALID_ARGUMENT);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Xattr storage bridge
// ---------------------------------------------------------------------------

/// Get an extended attribute value through `XattrStore`.
pub fn bridge_getxattr(
    store: &XattrStore,
    _inode: InodeId,
    name: &[u8],
    _ctx: &RequestCtx,
) -> Result<XattrBuf, Errno> {
    validate_xattr_name(name)?;
    let value = store.get(name).ok_or(KernelErrno::XATTR_NOT_FOUND)?;
    Ok(copy_to_buf(&value))
}

/// Set an extended attribute through `XattrStore`.
pub fn bridge_setxattr(
    store: &mut XattrStore,
    _inode: InodeId,
    name: &[u8],
    value: &[u8],
    flags: u32,
    _ctx: &RequestCtx,
) -> Result<(), Errno> {
    validate_xattr_name(name)?;
    validate_xattr_flags(flags)?;

    let exists = store.contains(name);
    match flags {
        XATTR_CREATE if exists => return Err(KernelErrno::NS_ALREADY_EXISTS),
        XATTR_REPLACE if !exists => return Err(KernelErrno::XATTR_NOT_FOUND),
        _ => {}
    }

    store.set(name, value, flags as u8);
    Ok(())
}

/// List extended attribute names through `XattrStore`.
pub fn bridge_listxattr(
    store: &XattrStore,
    _inode: InodeId,
    _ctx: &RequestCtx,
) -> Result<XattrBuf, Errno> {
    let names = store.list_names();
    if names.is_empty() {
        return Ok(copy_to_buf(&[]));
    }
    let packed = pack_posix_xattr_name_list(&names).map_err(|_| KernelErrno::STORAGE_IO)?;
    Ok(copy_to_buf(&packed))
}

/// Remove an extended attribute through `XattrStore`.
pub fn bridge_removexattr(
    store: &mut XattrStore,
    _inode: InodeId,
    name: &[u8],
    _ctx: &RequestCtx,
) -> Result<(), Errno> {
    validate_xattr_name(name)?;
    store.remove(name).map_err(|e| match e {
        XattrStoreError::EntryNotFound => KernelErrno::XATTR_NOT_FOUND,
    })
}

/// Count of xattr entries on a store.
pub fn bridge_xattr_count(store: &XattrStore) -> u64 {
    store.len()
}

/// Whether a specific xattr name exists.
pub fn bridge_xattr_exists(store: &XattrStore, name: &[u8]) -> bool {
    store.contains(name)
}

/// Monotonic version counter of the store.
pub fn bridge_xattr_version(store: &XattrStore) -> u64 {
    store.version()
}
#[cfg(test)]
use tidefs_xattr_storage::DatasetXattrPolicy;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::KernelErrno;
    use tidefs_kmod_bridge::kernel_types::InodeId;

    fn test_store() -> XattrStore {
        XattrStore::new(DatasetXattrPolicy::new(32, 4096, 0, 0))
    }

    fn test_ctx() -> RequestCtx {
        RequestCtx {
            uid: 1000,
            gid: 1000,
            pid: 42,
            umask: 0o022,
            groups: alloc::vec![1000],
        }
    }

    fn test_ino() -> InodeId {
        InodeId::new(1)
    }

    // ── Namespace validation ─────────────────────────────────────────

    #[test]
    fn accepts_valid_namespaces() {
        for name in &[
            b"user.test" as &[u8],
            b"security.selinux",
            b"system.posix_acl_access",
            b"trusted.overlay",
        ] {
            assert_eq!(validate_xattr_namespace(name), Ok(()));
        }
    }

    #[test]
    fn rejects_unknown_namespace() {
        assert_eq!(
            validate_xattr_namespace(b"custom.foo"),
            Err(KernelErrno::UNSUPPORTED_OP)
        );
        assert_eq!(
            validate_xattr_namespace(b"barename"),
            Err(KernelErrno::UNSUPPORTED_OP)
        );
    }

    #[test]
    fn rejects_empty_and_nul_names() {
        assert_eq!(
            validate_xattr_name_basic(b""),
            Err(KernelErrno::INVALID_ARGUMENT)
        );
        assert_eq!(
            validate_xattr_name_basic(b"user.\0bad"),
            Err(KernelErrno::INVALID_ARGUMENT)
        );
    }

    #[test]
    fn rejects_too_long_name() {
        let long = alloc::vec![b'a'; 256];
        assert_eq!(
            validate_xattr_name_basic(&long),
            Err(KernelErrno::NS_NAME_TOO_LONG)
        );
    }

    #[test]
    fn full_validation_combines_checks() {
        assert_eq!(validate_xattr_name(b"user.valid"), Ok(()));
        assert_eq!(
            validate_xattr_name(b"bad.name"),
            Err(KernelErrno::UNSUPPORTED_OP)
        );
    }

    // ── Flag validation ──────────────────────────────────────────────

    #[test]
    fn accepts_valid_flags() {
        assert_eq!(validate_xattr_flags(0), Ok(()));
        assert_eq!(validate_xattr_flags(XATTR_CREATE), Ok(()));
        assert_eq!(validate_xattr_flags(XATTR_REPLACE), Ok(()));
    }

    #[test]
    fn rejects_invalid_flags() {
        assert_eq!(validate_xattr_flags(3), Err(KernelErrno::INVALID_ARGUMENT));
        assert_eq!(validate_xattr_flags(4), Err(KernelErrno::INVALID_ARGUMENT));
    }

    // ── getxattr bridge ──────────────────────────────────────────────

    #[test]
    fn bridge_getxattr_retrieves_value() {
        let mut store = test_store();
        store.set(b"user.test", b"hello-bridge", 0);
        let result = bridge_getxattr(&store, test_ino(), b"user.test", &test_ctx()).unwrap();
        assert_eq!(&result[..], b"hello-bridge");
    }

    #[test]
    fn bridge_getxattr_missing_returns_enodata() {
        let store = test_store();
        assert_eq!(
            bridge_getxattr(&store, test_ino(), b"user.missing", &test_ctx()).unwrap_err(),
            KernelErrno::XATTR_NOT_FOUND
        );
    }

    #[test]
    fn bridge_getxattr_invalid_name_rejected() {
        let store = test_store();
        assert_eq!(
            bridge_getxattr(&store, test_ino(), b"bad.name", &test_ctx()).unwrap_err(),
            KernelErrno::UNSUPPORTED_OP
        );
    }

    // ── setxattr bridge ──────────────────────────────────────────────

    #[test]
    fn bridge_setxattr_create_and_retrieve() {
        let mut store = test_store();
        bridge_setxattr(
            &mut store,
            test_ino(),
            b"user.new",
            b"payload",
            0,
            &test_ctx(),
        )
        .unwrap();
        assert_eq!(store.get(b"user.new"), Some(b"payload".to_vec()));
    }

    #[test]
    fn bridge_setxattr_overwrite() {
        let mut store = test_store();
        bridge_setxattr(
            &mut store,
            test_ino(),
            b"user.key",
            b"first",
            0,
            &test_ctx(),
        )
        .unwrap();
        bridge_setxattr(
            &mut store,
            test_ino(),
            b"user.key",
            b"second",
            0,
            &test_ctx(),
        )
        .unwrap();
        assert_eq!(store.get(b"user.key"), Some(b"second".to_vec()));
    }

    #[test]
    fn bridge_setxattr_create_fails_eexist() {
        let mut store = test_store();
        store.set(b"user.dup", b"original", 0);
        assert_eq!(
            bridge_setxattr(
                &mut store,
                test_ino(),
                b"user.dup",
                b"new",
                XATTR_CREATE,
                &test_ctx()
            )
            .unwrap_err(),
            KernelErrno::NS_ALREADY_EXISTS
        );
        assert_eq!(store.get(b"user.dup"), Some(b"original".to_vec()));
    }

    #[test]
    fn bridge_setxattr_replace_fails_enodata() {
        let mut store = test_store();
        assert_eq!(
            bridge_setxattr(
                &mut store,
                test_ino(),
                b"user.missing",
                b"new",
                XATTR_REPLACE,
                &test_ctx()
            )
            .unwrap_err(),
            KernelErrno::XATTR_NOT_FOUND
        );
    }

    // ── listxattr bridge ─────────────────────────────────────────────

    #[test]
    fn bridge_listxattr_returns_packed_names() {
        let mut store = test_store();
        store.set(b"user.b", b"vb", 0);
        store.set(b"user.a", b"va", 0);
        let result = bridge_listxattr(&store, test_ino(), &test_ctx()).unwrap();
        assert_eq!(&result[..], b"user.a\0user.b\0");
    }

    #[test]
    fn bridge_listxattr_empty_store() {
        let store = test_store();
        let result = bridge_listxattr(&store, test_ino(), &test_ctx()).unwrap();
        assert!(result.is_empty());
    }

    // ── removexattr bridge ───────────────────────────────────────────

    #[test]
    fn bridge_removexattr_deletes_existing() {
        let mut store = test_store();
        store.set(b"user.del", b"val", 0);
        bridge_removexattr(&mut store, test_ino(), b"user.del", &test_ctx()).unwrap();
        assert!(store.get(b"user.del").is_none());
    }

    #[test]
    fn bridge_removexattr_missing_returns_enodata() {
        let mut store = test_store();
        assert_eq!(
            bridge_removexattr(&mut store, test_ino(), b"user.missing", &test_ctx()).unwrap_err(),
            KernelErrno::XATTR_NOT_FOUND
        );
    }

    // ── Multi-store isolation ────────────────────────────────────────

    #[test]
    fn multi_store_isolation() {
        let mut s1 = test_store();
        let mut s2 = test_store();
        bridge_setxattr(&mut s1, InodeId::new(1), b"user.a", b"one", 0, &test_ctx()).unwrap();
        bridge_setxattr(&mut s2, InodeId::new(2), b"user.a", b"two", 0, &test_ctx()).unwrap();
        assert_eq!(s1.get(b"user.a"), Some(b"one".to_vec()));
        assert_eq!(s2.get(b"user.a"), Some(b"two".to_vec()));
        bridge_removexattr(&mut s1, InodeId::new(1), b"user.a", &test_ctx()).unwrap();
        assert!(s1.get(b"user.a").is_none());
        assert_eq!(s2.get(b"user.a"), Some(b"two".to_vec()));
    }

    // ── Empty value round-trip ───────────────────────────────────────

    #[test]
    fn empty_value_roundtrip() {
        let mut store = test_store();
        bridge_setxattr(&mut store, test_ino(), b"user.empty", b"", 0, &test_ctx()).unwrap();
        let result = bridge_getxattr(&store, test_ino(), b"user.empty", &test_ctx()).unwrap();
        assert!(result.is_empty());
    }

    // ── Version counter ──────────────────────────────────────────────

    #[test]
    fn version_counter_bumps_on_mutation() {
        let mut store = test_store();
        assert_eq!(bridge_xattr_version(&store), 0);
        store.set(b"user.k", b"v", 0);
        assert_eq!(bridge_xattr_version(&store), 1);
        store.remove(b"user.k").unwrap();
        assert_eq!(bridge_xattr_version(&store), 2);
    }

    // ── Bulk helpers ─────────────────────────────────────────────────

    #[test]
    fn count_and_exists() {
        let mut store = test_store();
        assert_eq!(bridge_xattr_count(&store), 0);
        assert!(!bridge_xattr_exists(&store, b"user.test"));
        store.set(b"user.test", b"val", 0);
        assert_eq!(bridge_xattr_count(&store), 1);
        assert!(bridge_xattr_exists(&store, b"user.test"));
    }

    // ── Value boundary (64 KiB) ──────────────────────────────────────

    #[test]
    fn large_value_64kib_roundtrip() {
        let mut store = test_store();
        let big = alloc::vec![0xABu8; 65536];
        bridge_setxattr(&mut store, test_ino(), b"user.big", &big, 0, &test_ctx()).unwrap();
        let retrieved = bridge_getxattr(&store, test_ino(), b"user.big", &test_ctx()).unwrap();
        assert_eq!(&retrieved[..], &big[..]);
    }
}
