// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Persistence round-trip validation tests.
//!
//! Exercises serialization of InodeAttr / PosixAttrs through the
//! TableAttributeStore → InodeTable → LocalObjectStore pipeline
//! and verifies field-level bit-identical recovery.
//!
//! Does not require FUSE mount.

use std::sync::Arc;

use tidefs_inode_attributes::{table_store::TableAttributeStore, InodeAttributeStore};
use tidefs_inode_table::{InodeAttributes, InodeKind, InodeTable, SystemTimeSource};
use tidefs_local_object_store::LocalObjectStore;
use tidefs_types_vfs_core::{
    NodeKind, SetAttr, FATTR_ATIME, FATTR_CTIME, FATTR_GID, FATTR_MODE, FATTR_MTIME, FATTR_SIZE,
    FATTR_UID, S_IFDIR, S_IFLNK, S_IFREG,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn temp_store() -> (LocalObjectStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let store = LocalObjectStore::open(dir.path()).expect("open store");
    (store, dir)
}

fn make_table(store: &mut LocalObjectStore) -> (Arc<InodeTable>, TableAttributeStore) {
    let tbl = InodeTable::open(store, 128, Box::new(SystemTimeSource)).expect("open inode table");
    let tbl = Arc::new(tbl);
    let attr_store = TableAttributeStore::new(Arc::clone(&tbl));
    (tbl, attr_store)
}

// ---------------------------------------------------------------------------
// Mode & permission persistence
// ---------------------------------------------------------------------------

#[test]
fn mode_survives_commit_reopen() {
    let (mut store, _dir) = temp_store();
    let (tbl, attr_store) = make_table(&mut store);

    let ino = attr_store
        .create(
            InodeKind::File,
            InodeAttributes::new(0o755, 1000, 100, InodeKind::File),
        )
        .expect("create");
    tbl.commit(&mut store).expect("commit");

    let (_tbl2, attr_store2) = make_table(&mut store);
    let attr = attr_store2.getattr(ino.0).expect("getattr");
    assert_eq!(attr.posix.mode & !S_IFREG, 0o755);
}

#[test]
fn uid_gid_survive_commit_reopen() {
    let (mut store, _dir) = temp_store();
    let (tbl, attr_store) = make_table(&mut store);

    let ino = attr_store
        .create(
            InodeKind::File,
            InodeAttributes::new(0o644, 1234, 5678, InodeKind::File),
        )
        .expect("create");
    tbl.commit(&mut store).expect("commit");

    let (_tbl2, attr_store2) = make_table(&mut store);
    let attr = attr_store2.getattr(ino.0).expect("getattr");
    assert_eq!(attr.posix.uid, 1234);
    assert_eq!(attr.posix.gid, 5678);
}

#[test]
fn size_survives_commit_reopen() {
    let (mut store, _dir) = temp_store();
    let (tbl, attr_store) = make_table(&mut store);

    let ino = attr_store
        .create(
            InodeKind::File,
            InodeAttributes {
                mode: 0o644,
                uid: 1000,
                gid: 100,
                size: 10485760,
                blocks: 10485760 / 512,
                ..InodeAttributes::new(0o644, 1000, 100, InodeKind::File)
            },
        )
        .expect("create");
    tbl.commit(&mut store).expect("commit");

    let (_tbl2, attr_store2) = make_table(&mut store);
    let attr = attr_store2.getattr(ino.0).expect("getattr");
    assert_eq!(attr.posix.size, 10485760);
    assert_eq!(attr.posix.blocks_512, 10485760 / 512);
}

// ---------------------------------------------------------------------------
// setattr then persist
// ---------------------------------------------------------------------------

#[test]
fn setattr_mode_persists() {
    let (mut store, _dir) = temp_store();
    let (tbl, attr_store) = make_table(&mut store);

    let ino = attr_store
        .create(
            InodeKind::File,
            InodeAttributes::new(0o600, 1000, 100, InodeKind::File),
        )
        .expect("create");

    let mut set = SetAttr::new();
    set.valid = FATTR_MODE;
    set.mode = 0o700;
    attr_store.setattr(ino.0, &set).expect("setattr");

    tbl.commit(&mut store).expect("commit");

    let (_tbl2, attr_store2) = make_table(&mut store);
    let attr = attr_store2.getattr(ino.0).expect("getattr");
    assert_eq!(attr.posix.mode & !S_IFREG, 0o700);
}

#[test]
fn setattr_size_persists() {
    let (mut store, _dir) = temp_store();
    let (tbl, attr_store) = make_table(&mut store);

    let ino = attr_store
        .create(
            InodeKind::File,
            InodeAttributes::new(0o644, 1000, 100, InodeKind::File),
        )
        .expect("create");

    let mut set = SetAttr::new();
    set.valid = FATTR_SIZE;
    set.size = 999999;
    attr_store.setattr(ino.0, &set).expect("setattr");

    tbl.commit(&mut store).expect("commit");

    let (_tbl2, attr_store2) = make_table(&mut store);
    let attr = attr_store2.getattr(ino.0).expect("getattr");
    assert_eq!(attr.posix.size, 999999);
}

#[test]
fn setattr_uid_gid_persists() {
    let (mut store, _dir) = temp_store();
    let (tbl, attr_store) = make_table(&mut store);

    let ino = attr_store
        .create(
            InodeKind::File,
            InodeAttributes::new(0o644, 1000, 100, InodeKind::File),
        )
        .expect("create");

    let mut set = SetAttr::new();
    set.valid = FATTR_UID | FATTR_GID;
    set.uid = 42;
    set.gid = 99;
    attr_store.setattr(ino.0, &set).expect("setattr");

    tbl.commit(&mut store).expect("commit");

    let (_tbl2, attr_store2) = make_table(&mut store);
    let attr = attr_store2.getattr(ino.0).expect("getattr");
    assert_eq!(attr.posix.uid, 42);
    assert_eq!(attr.posix.gid, 99);
}

// ---------------------------------------------------------------------------
// Timestamp persistence
// ---------------------------------------------------------------------------

#[test]
fn timestamps_survive_commit_reopen() {
    let (mut store, _dir) = temp_store();
    let (tbl, attr_store) = make_table(&mut store);

    let ino = attr_store
        .create(
            InodeKind::File,
            InodeAttributes::new(0o644, 1000, 100, InodeKind::File),
        )
        .expect("create");

    // Set explicit timestamps
    let mut set = SetAttr::new();
    set.valid = FATTR_ATIME | FATTR_MTIME | FATTR_CTIME;
    set.atime_ns = 100_000_000_000;
    set.mtime_ns = 200_000_000_000;
    set.ctime_ns = 300_000_000_000;
    attr_store.setattr(ino.0, &set).expect("setattr");

    tbl.commit(&mut store).expect("commit");

    let (_tbl2, attr_store2) = make_table(&mut store);
    let attr = attr_store2.getattr(ino.0).expect("getattr");
    assert_eq!(attr.posix.atime_ns, 100_000_000_000);
    assert_eq!(attr.posix.mtime_ns, 200_000_000_000);
    assert_eq!(attr.posix.ctime_ns, 300_000_000_000);
}

// ---------------------------------------------------------------------------
// nlink persistence
// ---------------------------------------------------------------------------

#[test]
fn nlink_survives_commit_reopen() {
    let (mut store, _dir) = temp_store();
    let (tbl, attr_store) = make_table(&mut store);

    let ino = attr_store
        .create(
            InodeKind::File,
            InodeAttributes::new(0o644, 1000, 100, InodeKind::File),
        )
        .expect("create");

    // Bump link count a few times
    attr_store.bump_link(ino.0).unwrap();
    attr_store.bump_link(ino.0).unwrap();
    assert_eq!(attr_store.getattr(ino.0).unwrap().posix.nlink, 3);

    tbl.commit(&mut store).expect("commit");

    let (_tbl2, attr_store2) = make_table(&mut store);
    let attr = attr_store2.getattr(ino.0).expect("getattr");
    assert_eq!(attr.posix.nlink, 3);
}

// ---------------------------------------------------------------------------
// Kind persistence (File / Directory / Symlink)
// ---------------------------------------------------------------------------

#[test]
fn file_kind_persists() {
    let (mut store, _dir) = temp_store();
    let (tbl, attr_store) = make_table(&mut store);

    let ino = attr_store
        .create(
            InodeKind::File,
            InodeAttributes::new(0o644, 1000, 100, InodeKind::File),
        )
        .expect("create");
    tbl.commit(&mut store).expect("commit");

    let (_tbl2, attr_store2) = make_table(&mut store);
    let attr = attr_store2.getattr(ino.0).expect("getattr");
    assert_eq!(attr.kind, NodeKind::File);
    assert_eq!(attr.posix.mode & S_IFREG, S_IFREG);
}

#[test]
fn directory_kind_persists() {
    let (mut store, _dir) = temp_store();
    let (tbl, attr_store) = make_table(&mut store);

    let ino = attr_store
        .create(
            InodeKind::Directory,
            InodeAttributes::new(0o755, 0, 0, InodeKind::Directory),
        )
        .expect("create");
    tbl.commit(&mut store).expect("commit");

    let (_tbl2, attr_store2) = make_table(&mut store);
    let attr = attr_store2.getattr(ino.0).expect("getattr");
    assert_eq!(attr.kind, NodeKind::Dir);
    assert_eq!(attr.posix.mode & S_IFDIR, S_IFDIR);
}

#[test]
fn symlink_kind_persists() {
    let (mut store, _dir) = temp_store();
    let (tbl, attr_store) = make_table(&mut store);

    let ino = attr_store
        .create(
            InodeKind::Symlink,
            InodeAttributes::new(0o777, 1000, 100, InodeKind::Symlink),
        )
        .expect("create");
    tbl.commit(&mut store).expect("commit");

    let (_tbl2, attr_store2) = make_table(&mut store);
    let attr = attr_store2.getattr(ino.0).expect("getattr");
    assert_eq!(attr.kind, NodeKind::Symlink);
    assert_eq!(attr.posix.mode & S_IFLNK, S_IFLNK);
}

// ---------------------------------------------------------------------------
// Multiple inodes persist independently
// ---------------------------------------------------------------------------

#[test]
fn multiple_inodes_roundtrip() {
    let (mut store, _dir) = temp_store();
    let (tbl, attr_store) = make_table(&mut store);

    let ino1 = attr_store
        .create(
            InodeKind::File,
            InodeAttributes::new(0o644, 1000, 100, InodeKind::File),
        )
        .expect("create");
    let ino2 = attr_store
        .create(
            InodeKind::File,
            InodeAttributes::new(0o755, 2000, 200, InodeKind::File),
        )
        .expect("create");
    let ino3 = attr_store
        .create(
            InodeKind::Directory,
            InodeAttributes::new(0o700, 0, 0, InodeKind::Directory),
        )
        .expect("create");

    tbl.commit(&mut store).expect("commit");

    let (_tbl2, attr_store2) = make_table(&mut store);

    let a1 = attr_store2.getattr(ino1.0).unwrap();
    assert_eq!(a1.posix.mode & !S_IFREG, 0o644);
    assert_eq!(a1.posix.uid, 1000);
    assert_eq!(a1.kind, NodeKind::File);

    let a2 = attr_store2.getattr(ino2.0).unwrap();
    assert_eq!(a2.posix.mode & !S_IFREG, 0o755);
    assert_eq!(a2.posix.uid, 2000);

    let a3 = attr_store2.getattr(ino3.0).unwrap();
    assert_eq!(a3.kind, NodeKind::Dir);
    assert_eq!(a3.posix.mode & !S_IFDIR, 0o700);
}

// ---------------------------------------------------------------------------
// Deletion persistence (nlink drop to zero)
// ---------------------------------------------------------------------------

#[test]
fn drop_link_to_zero_persists_removal() {
    let (mut store, _dir) = temp_store();
    let (tbl, attr_store) = make_table(&mut store);

    let ino = attr_store
        .create(
            InodeKind::File,
            InodeAttributes::new(0o644, 1000, 100, InodeKind::File),
        )
        .expect("create");

    assert_eq!(attr_store.drop_link(ino.0).unwrap(), 0);
    tbl.commit(&mut store).expect("commit");

    let (_tbl2, attr_store2) = make_table(&mut store);
    // After link count drops to 0 and commit, inode should be auto-removed
    match attr_store2.getattr(ino.0) {
        Err(tidefs_inode_attributes::AttrError::InoNotFound) => {}
        other => panic!("expected InoNotFound, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Boundary-value persistence
// ---------------------------------------------------------------------------

#[test]
fn max_uid_persists() {
    let (mut store, _dir) = temp_store();
    let (tbl, attr_store) = make_table(&mut store);

    let ino = attr_store
        .create(
            InodeKind::File,
            InodeAttributes {
                mode: 0o644,
                uid: u32::MAX,
                gid: 100,
                ..InodeAttributes::new(0o644, u32::MAX, 100, InodeKind::File)
            },
        )
        .expect("create");
    tbl.commit(&mut store).expect("commit");

    let (_tbl2, attr_store2) = make_table(&mut store);
    let attr = attr_store2.getattr(ino.0).expect("getattr");
    assert_eq!(attr.posix.uid, u32::MAX);
}

#[test]
fn max_gid_persists() {
    let (mut store, _dir) = temp_store();
    let (tbl, attr_store) = make_table(&mut store);

    let ino = attr_store
        .create(
            InodeKind::File,
            InodeAttributes {
                mode: 0o644,
                uid: 1000,
                gid: u32::MAX,
                ..InodeAttributes::new(0o644, 1000, u32::MAX, InodeKind::File)
            },
        )
        .expect("create");
    tbl.commit(&mut store).expect("commit");

    let (_tbl2, attr_store2) = make_table(&mut store);
    let attr = attr_store2.getattr(ino.0).expect("getattr");
    assert_eq!(attr.posix.gid, u32::MAX);
}

#[test]
fn zero_size_persists() {
    let (mut store, _dir) = temp_store();
    let (tbl, attr_store) = make_table(&mut store);

    let ino = attr_store
        .create(
            InodeKind::File,
            InodeAttributes {
                mode: 0o644,
                uid: 1000,
                gid: 100,
                size: 0,
                blocks: 0,
                ..InodeAttributes::new(0o644, 1000, 100, InodeKind::File)
            },
        )
        .expect("create");
    tbl.commit(&mut store).expect("commit");

    let (_tbl2, attr_store2) = make_table(&mut store);
    let attr = attr_store2.getattr(ino.0).expect("getattr");
    assert_eq!(attr.posix.size, 0);
    assert_eq!(attr.posix.blocks_512, 0);
}
