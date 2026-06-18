// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Attribute get/set round-trip validation tests.
//!
//! Exercises every field independently and in combination through the
//! MemInodeAttributeStore setattr/getattr path, verifying bit-identical
//! round-trips.  Does not require FUSE mount, cross-crate orchestration,
//! or persistence.

use tidefs_inode_attributes::{InodeAttributeStore, MemInodeAttributeStore, SetAttr};
use tidefs_types_vfs_core::{
    InodeAttr, InodeFlags, InodeId, NodeKind, PosixAttrs, FATTR_ATIME, FATTR_ATIME_NOW,
    FATTR_CTIME, FATTR_GID, FATTR_MODE, FATTR_MTIME, FATTR_MTIME_NOW, FATTR_SIZE, FATTR_UID,
    S_IFREG,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn dummy_attrs(ino: u64) -> InodeAttr {
    InodeAttr {
        inode_id: InodeId(ino),
        generation: tidefs_types_vfs_core::Generation(1),
        kind: NodeKind::File,
        posix: PosixAttrs::new(
            S_IFREG | 0o644,
            1000,
            100,
            1,
            0,
            1_000_000_000,
            2_000_000_000,
            3_000_000_000,
            0,
            4096,
            8,
            4096,
        ),
        flags: InodeFlags::none(),
        subtree_rev: 0,
        dir_rev: 0,
    }
}

// ---------------------------------------------------------------------------
// Single-field round-trips
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_mode_only() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_MODE;
    set.mode = 0o755;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.mode & !S_IFREG, 0o755);
    assert_eq!(updated.posix.mode & S_IFREG, S_IFREG);

    let read = store.getattr(1).unwrap();
    assert_eq!(read, updated);
    assert_eq!(read.posix.mode & !S_IFREG, 0o755);
}

#[test]
fn roundtrip_uid_only() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_UID;
    set.uid = 2000;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.uid, 2000);

    let read = store.getattr(1).unwrap();
    assert_eq!(read, updated);
    assert_eq!(read.posix.uid, 2000);
}

#[test]
fn roundtrip_gid_only() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_GID;
    set.gid = 2000;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.gid, 2000);

    let read = store.getattr(1).unwrap();
    assert_eq!(read, updated);
}

#[test]
fn roundtrip_size_only() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_SIZE;
    set.size = 1048576; // 1 MiB
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.size, 1048576);
    assert_eq!(updated.posix.blocks_512, 1048576 / 512);

    let read = store.getattr(1).unwrap();
    assert_eq!(read, updated);
}

#[test]
fn roundtrip_size_zero() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_SIZE;
    set.size = 0;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.size, 0);
    assert_eq!(updated.posix.blocks_512, 0);

    let read = store.getattr(1).unwrap();
    assert_eq!(read, updated);
}

#[test]
fn roundtrip_atime_explicit() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_ATIME;
    set.atime_ns = 9_000_000_000;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.atime_ns, 9_000_000_000);

    let read = store.getattr(1).unwrap();
    assert_eq!(read, updated);
}

#[test]
fn roundtrip_mtime_explicit() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_MTIME;
    set.mtime_ns = 8_000_000_000;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.mtime_ns, 8_000_000_000);

    let read = store.getattr(1).unwrap();
    assert_eq!(read, updated);
}

#[test]
fn roundtrip_ctime_explicit() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_CTIME;
    set.ctime_ns = 7_000_000_000;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.ctime_ns, 7_000_000_000);

    let read = store.getattr(1).unwrap();
    assert_eq!(read, updated);
}

// ---------------------------------------------------------------------------
// Timestamp NOW round-trips
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_atime_now() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .try_into()
        .unwrap_or(i64::MAX);

    let mut set = SetAttr::new();
    set.valid = FATTR_ATIME_NOW;
    let updated = store.setattr(1, &set).unwrap();
    assert!(updated.posix.atime_ns >= before);

    let read = store.getattr(1).unwrap();
    assert_eq!(read, updated);
}

#[test]
fn roundtrip_mtime_now() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .try_into()
        .unwrap_or(i64::MAX);

    let mut set = SetAttr::new();
    set.valid = FATTR_MTIME_NOW;
    let updated = store.setattr(1, &set).unwrap();
    assert!(updated.posix.mtime_ns >= before);

    let read = store.getattr(1).unwrap();
    assert_eq!(read, updated);
}

// ---------------------------------------------------------------------------
// Multi-field round-trips
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_all_metadata_fields() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_MODE | FATTR_UID | FATTR_GID;
    set.mode = 0o700;
    set.uid = 500;
    set.gid = 500;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.mode & !S_IFREG, 0o700);
    assert_eq!(updated.posix.uid, 500);
    assert_eq!(updated.posix.gid, 500);

    let read = store.getattr(1).unwrap();
    assert_eq!(read, updated);
}

#[test]
fn roundtrip_mode_uid_gid_size_all_at_once() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_MODE | FATTR_UID | FATTR_GID | FATTR_SIZE;
    set.mode = 0o755;
    set.uid = 42;
    set.gid = 99;
    set.size = 8192;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.mode & !S_IFREG, 0o755);
    assert_eq!(updated.posix.uid, 42);
    assert_eq!(updated.posix.gid, 99);
    assert_eq!(updated.posix.size, 8192);

    let read = store.getattr(1).unwrap();
    assert_eq!(read, updated);
}

#[test]
fn roundtrip_size_and_timestamps() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_SIZE | FATTR_ATIME | FATTR_MTIME;
    set.size = 2048;
    set.atime_ns = 100;
    set.mtime_ns = 200;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.size, 2048);
    assert_eq!(updated.posix.atime_ns, 100);
    assert_eq!(updated.posix.mtime_ns, 200);

    let read = store.getattr(1).unwrap();
    assert_eq!(read, updated);
}

// ---------------------------------------------------------------------------
// setattr returns bit-identical result to subsequent getattr
// ---------------------------------------------------------------------------

#[test]
fn setattr_result_matches_getattr() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_MODE | FATTR_UID | FATTR_GID | FATTR_SIZE;
    set.mode = 0o600;
    set.uid = 1234;
    set.gid = 5678;
    set.size = 65536;
    let result = store.setattr(1, &set).unwrap();
    let re_read = store.getattr(1).unwrap();
    assert_eq!(result, re_read);

    // Verify specific fields
    assert_eq!(result.inode_id, re_read.inode_id);
    assert_eq!(result.kind, re_read.kind);
    assert_eq!(result.posix, re_read.posix);
    assert_eq!(result.flags, re_read.flags);
    assert_eq!(result.subtree_rev, re_read.subtree_rev);
    assert_eq!(result.dir_rev, re_read.dir_rev);
}

// ---------------------------------------------------------------------------
// No-op setattr preserves all fields exactly
// ---------------------------------------------------------------------------

#[test]
fn empty_setattr_preserves_all_fields() {
    let store = MemInodeAttributeStore::new();
    let original = dummy_attrs(1);
    store.insert(1, original);

    let set = SetAttr::new(); // valid == 0
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.inode_id, original.inode_id);
    assert_eq!(updated.kind, original.kind);
    assert_eq!(updated.posix.mode, original.posix.mode);
    assert_eq!(updated.posix.uid, original.posix.uid);
    assert_eq!(updated.posix.gid, original.posix.gid);
    assert_eq!(updated.posix.nlink, original.posix.nlink);
    assert_eq!(updated.posix.size, original.posix.size);
    assert_eq!(updated.posix.blocks_512, original.posix.blocks_512);
    assert_eq!(updated.posix.atime_ns, original.posix.atime_ns);
    assert_eq!(updated.posix.mtime_ns, original.posix.mtime_ns);
    assert_eq!(updated.posix.ctime_ns, original.posix.ctime_ns);
    assert_eq!(updated.flags, original.flags);
}

// ---------------------------------------------------------------------------
// Successive setattrs accumulate correctly
// ---------------------------------------------------------------------------

#[test]
fn successive_setattrs_accumulate() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    // First: set mode
    let mut set = SetAttr::new();
    set.valid = FATTR_MODE;
    set.mode = 0o700;
    let after1 = store.setattr(1, &set).unwrap();
    assert_eq!(after1.posix.mode & !S_IFREG, 0o700);

    // Second: set uid (mode should persist)
    let mut set2 = SetAttr::new();
    set2.valid = FATTR_UID;
    set2.uid = 999;
    let after2 = store.setattr(1, &set2).unwrap();
    assert_eq!(after2.posix.mode & !S_IFREG, 0o700);
    assert_eq!(after2.posix.uid, 999);

    // Third: set size
    let mut set3 = SetAttr::new();
    set3.valid = FATTR_SIZE;
    set3.size = 128;
    let after3 = store.setattr(1, &set3).unwrap();
    assert_eq!(after3.posix.mode & !S_IFREG, 0o700);
    assert_eq!(after3.posix.uid, 999);
    assert_eq!(after3.posix.size, 128);

    let read = store.getattr(1).unwrap();
    assert_eq!(read, after3);
}

// ---------------------------------------------------------------------------
// Sparse size / truncate round-trips
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_truncate_down() {
    let store = MemInodeAttributeStore::new();
    let mut a = dummy_attrs(1);
    a.posix.size = 1048576;
    a.posix.blocks_512 = 1048576 / 512;
    store.insert(1, a);

    let mut set = SetAttr::new();
    set.valid = FATTR_SIZE;
    set.size = 1024;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.size, 1024);
    assert_eq!(updated.posix.blocks_512, 2); // 1024 / 512

    let read = store.getattr(1).unwrap();
    assert_eq!(read, updated);
}

#[test]
fn roundtrip_truncate_up_sparse() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_SIZE;
    set.size = 1_000_000_000; // ~954 MiB
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.size, 1_000_000_000);
    assert!(updated.posix.blocks_512 > 0);

    let read = store.getattr(1).unwrap();
    assert_eq!(read, updated);
}

// ---------------------------------------------------------------------------
// UID/GID boundary values
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_uid_max() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_UID;
    set.uid = u32::MAX;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.uid, u32::MAX);

    let read = store.getattr(1).unwrap();
    assert_eq!(read, updated);
}

#[test]
fn roundtrip_gid_max() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_GID;
    set.gid = u32::MAX;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.gid, u32::MAX);

    let read = store.getattr(1).unwrap();
    assert_eq!(read, updated);
}

#[test]
fn roundtrip_uid_zero() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_UID;
    set.uid = 0;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.uid, 0);

    let read = store.getattr(1).unwrap();
    assert_eq!(read, updated);
}

// ---------------------------------------------------------------------------
// setattr on non-existent inode
// ---------------------------------------------------------------------------

#[test]
fn setattr_not_found() {
    let store = MemInodeAttributeStore::new();
    let set = SetAttr::new();
    let err = store.setattr(1, &set).unwrap_err();
    assert_eq!(err, tidefs_inode_attributes::AttrError::InoNotFound);
}

// ---------------------------------------------------------------------------
// Mode bits: S_IFMT preserved, permission bits replaced
// ---------------------------------------------------------------------------

#[test]
fn setattr_mode_preserves_file_type() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_MODE;
    set.mode = 0o777; // all perms, no type bits
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.mode & S_IFREG, S_IFREG);
    assert_eq!(updated.posix.mode & !S_IFREG, 0o777);
}

#[test]
fn setattr_mode_does_not_change_kind_field() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_MODE;
    set.mode = S_IFREG | 0o755;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.kind, NodeKind::File);
}

// ---------------------------------------------------------------------------
// Multiple inodes remain independent
// ---------------------------------------------------------------------------

#[test]
fn multiple_inodes_independent() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));
    store.insert(2, dummy_attrs(2));

    let mut set = SetAttr::new();
    set.valid = FATTR_MODE;
    set.mode = 0o700;
    store.setattr(1, &set).unwrap();

    // Inode 2 should be unaffected
    let a2 = store.getattr(2).unwrap();
    assert_eq!(a2.posix.mode & !S_IFREG, 0o644);

    // Inode 1 should reflect the change
    let a1 = store.getattr(1).unwrap();
    assert_eq!(a1.posix.mode & !S_IFREG, 0o700);
}
