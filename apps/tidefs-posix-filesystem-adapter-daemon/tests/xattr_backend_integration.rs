// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests for the P5-02 workers-ns XattrBackend bridge
//! to the VFS engine via LocalFileSystem.
//!
//! Exercises the XattrStoreBridge (wrapping MemXattrStore) through
//! the workers-ns dispatch handlers and validates the full pipeline:
//!   dispatch_* → XattrBackend → MemXattrStore.

use std::collections::BTreeSet;
use tidefs_posix_filesystem_adapter_daemon::workers_ns::{
    dispatch_getxattr, dispatch_listxattr, dispatch_removexattr, dispatch_setxattr, ns_errno,
    xattr_err_to_ns, NsOpError, XattrStoreBridge, XATTR_CREATE, XATTR_REPLACE,
};

/// Build a bridge with inodes 1, 2, and 3 pre-registered.
fn test_bridge() -> XattrStoreBridge {
    let mut inodes = BTreeSet::new();
    inodes.insert(1);
    inodes.insert(2);
    inodes.insert(3);
    XattrStoreBridge::new(inodes)
}

// ── CRUD round-trips ─────────────────────────────────────────────────

#[test]
fn bridge_set_get_roundtrip() {
    let bridge = test_bridge();
    dispatch_setxattr(&bridge, 1, b"user.key", b"value", 0).unwrap();
    let val = dispatch_getxattr(&bridge, 1, b"user.key").unwrap();
    assert_eq!(val, b"value");
}

#[test]
fn bridge_set_create_flag_succeeds_on_new() {
    let bridge = test_bridge();
    dispatch_setxattr(&bridge, 1, b"user.new", b"val", XATTR_CREATE).unwrap();
    assert_eq!(dispatch_getxattr(&bridge, 1, b"user.new").unwrap(), b"val");
}

#[test]
fn bridge_set_create_flag_fails_on_existing() {
    let bridge = test_bridge();
    dispatch_setxattr(&bridge, 1, b"user.dup", b"first", 0).unwrap();
    let err = dispatch_setxattr(&bridge, 1, b"user.dup", b"second", XATTR_CREATE).unwrap_err();
    assert_eq!(err, NsOpError::XattrExists);
    assert_eq!(err.errno(), ns_errno::EEXIST);
}

#[test]
fn bridge_set_replace_flag_succeeds_on_existing() {
    let bridge = test_bridge();
    dispatch_setxattr(&bridge, 1, b"user.rep", b"old", 0).unwrap();
    dispatch_setxattr(&bridge, 1, b"user.rep", b"new", XATTR_REPLACE).unwrap();
    assert_eq!(dispatch_getxattr(&bridge, 1, b"user.rep").unwrap(), b"new");
}

#[test]
fn bridge_set_replace_flag_fails_on_missing() {
    let bridge = test_bridge();
    let err = dispatch_setxattr(&bridge, 1, b"user.missing", b"val", XATTR_REPLACE).unwrap_err();
    assert_eq!(err, NsOpError::XattrNotFound);
}

#[test]
fn bridge_overwrite_with_flag_zero() {
    let bridge = test_bridge();
    dispatch_setxattr(&bridge, 1, b"user.over", b"first", 0).unwrap();
    dispatch_setxattr(&bridge, 1, b"user.over", b"second", 0).unwrap();
    assert_eq!(
        dispatch_getxattr(&bridge, 1, b"user.over").unwrap(),
        b"second"
    );
}

#[test]
fn bridge_remove_deletes_and_get_returns_error() {
    let bridge = test_bridge();
    dispatch_setxattr(&bridge, 1, b"user.del", b"v", 0).unwrap();
    dispatch_removexattr(&bridge, 1, b"user.del").unwrap();
    let err = dispatch_getxattr(&bridge, 1, b"user.del").unwrap_err();
    assert_eq!(err, NsOpError::XattrNotFound);
}

#[test]
fn bridge_listxattr_returns_keys() {
    let bridge = test_bridge();
    dispatch_setxattr(&bridge, 1, b"user.a", b"1", 0).unwrap();
    dispatch_setxattr(&bridge, 1, b"user.b", b"2", 0).unwrap();
    let list = dispatch_listxattr(&bridge, 1).unwrap();
    let names: Vec<&[u8]> = list.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&b"user.a".as_slice()));
    assert!(names.contains(&b"user.b".as_slice()));
}

#[test]
fn bridge_listxattr_empty_inode() {
    let bridge = test_bridge();
    let list = dispatch_listxattr(&bridge, 1).unwrap();
    assert!(list.is_empty());
}

#[test]
fn bridge_listxattr_ends_with_null() {
    let bridge = test_bridge();
    dispatch_setxattr(&bridge, 1, b"user.z", b"x", 0).unwrap();
    let list = dispatch_listxattr(&bridge, 1).unwrap();
    assert_eq!(list.last(), Some(&0));
}

// ── Error paths ──────────────────────────────────────────────────────

#[test]
fn bridge_nonexistent_inode_rejected() {
    let bridge = test_bridge();
    let err = dispatch_getxattr(&bridge, 999, b"user.key").unwrap_err();
    assert_eq!(err, NsOpError::InodeNotFound);
}

#[test]
fn bridge_setxattr_nonexistent_inode() {
    let bridge = test_bridge();
    let err = dispatch_setxattr(&bridge, 999, b"user.key", b"val", 0).unwrap_err();
    assert_eq!(err, NsOpError::InodeNotFound);
}

#[test]
fn bridge_invalid_name_rejected() {
    let bridge = test_bridge();
    let err = dispatch_getxattr(&bridge, 1, b"").unwrap_err();
    assert_eq!(err, NsOpError::XattrInvalidName);
}

#[test]
fn bridge_value_too_large_rejected() {
    let bridge = test_bridge();
    let big = vec![0xCCu8; 65 * 1024]; // over 64 KiB limit
    let err = dispatch_setxattr(&bridge, 1, b"user.big", &big, 0).unwrap_err();
    assert_eq!(err, NsOpError::XattrTooLarge);
}

#[test]
fn bridge_unsupported_namespace() {
    let bridge = test_bridge();
    let err = dispatch_setxattr(&bridge, 1, b"custom.myattr", b"val", 0).unwrap_err();
    assert_eq!(err, NsOpError::XattrNotSupported);
}

// ── Per-inode isolation ──────────────────────────────────────────────

#[test]
fn bridge_multi_inode_isolation() {
    let bridge = test_bridge();
    dispatch_setxattr(&bridge, 1, b"user.shared", b"i1", 0).unwrap();
    dispatch_setxattr(&bridge, 2, b"user.shared", b"i2", 0).unwrap();
    assert_eq!(
        dispatch_getxattr(&bridge, 1, b"user.shared").unwrap(),
        b"i1"
    );
    assert_eq!(
        dispatch_getxattr(&bridge, 2, b"user.shared").unwrap(),
        b"i2"
    );
    assert_eq!(
        dispatch_getxattr(&bridge, 3, b"user.shared").unwrap_err(),
        NsOpError::XattrNotFound
    );
}

// ── Large values ─────────────────────────────────────────────────────

#[test]
fn bridge_accepts_exact_max_value() {
    let bridge = test_bridge();
    let exact = vec![0xBBu8; 64 * 1024];
    dispatch_setxattr(&bridge, 1, b"user.exact", &exact, 0).unwrap();
    assert_eq!(dispatch_getxattr(&bridge, 1, b"user.exact").unwrap(), exact);
}

// ── 256 xattr stress ─────────────────────────────────────────────────

#[test]
fn bridge_256_xattrs_per_inode() {
    let bridge = test_bridge();
    for i in 0..256u32 {
        let name = format!("user.attr_{i:03}");
        let val = format!("val_{i:03}");
        dispatch_setxattr(&bridge, 1, name.as_bytes(), val.as_bytes(), 0).unwrap();
    }
    let list = dispatch_listxattr(&bridge, 1).unwrap();
    let count = list.split(|b| *b == 0).filter(|s| !s.is_empty()).count();
    assert_eq!(count, 256);
}

// ── Error translation ────────────────────────────────────────────────

#[test]
fn xattr_err_to_ns_maps_all_variants() {
    use tidefs_inode_attributes::xattr::XattrError;
    assert_eq!(
        xattr_err_to_ns(XattrError::InvalidName),
        NsOpError::XattrInvalidName
    );
    assert_eq!(
        xattr_err_to_ns(XattrError::NameTooLong),
        NsOpError::XattrInvalidName
    );
    assert_eq!(
        xattr_err_to_ns(XattrError::ValueTooLarge),
        NsOpError::XattrTooLarge
    );
    assert_eq!(
        xattr_err_to_ns(XattrError::UnsupportedNamespace),
        NsOpError::XattrNotSupported
    );
    assert_eq!(
        xattr_err_to_ns(XattrError::AttrNotFound),
        NsOpError::XattrNotFound
    );
    assert_eq!(
        xattr_err_to_ns(XattrError::AttrExists),
        NsOpError::XattrExists
    );
    assert_eq!(
        xattr_err_to_ns(XattrError::PermissionDenied),
        NsOpError::PermissionDenied
    );
}
