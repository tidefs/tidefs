#![cfg(feature = "std")]
//! Integration tests for inode-table persistence through LocalObjectStore.
//!
//! These tests cover the full lifecycle:
//! alloc → setattrs → commit → reopen → verify → delete → commit → reopen → absent.

use std::time::Duration;
use tidefs_inode_table::{InodeAttributes, InodeKind, InodeTable, SystemTimeSource};
use tidefs_local_object_store::LocalObjectStore;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn temp_store() -> (LocalObjectStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let store = LocalObjectStore::open(dir.path()).expect("open store");
    (store, dir)
}

fn file_attrs(mode: u32, size: u64) -> InodeAttributes {
    InodeAttributes {
        mode,
        uid: 1000,
        gid: 100,
        size,
        blocks: 0,
        atime: Duration::ZERO,
        mtime: Duration::ZERO,
        ctime: Duration::ZERO,
        nlink: 1,
        generation: 0,
        kind: InodeKind::File,
        xattrs: std::collections::BTreeMap::new(),
        dirty_bits: 0,
        mutation_gen: 0,
    }
}

fn dir_attrs(mode: u32) -> InodeAttributes {
    InodeAttributes {
        mode,
        uid: 0,
        gid: 0,
        size: 0,
        blocks: 0,
        atime: Duration::ZERO,
        mtime: Duration::ZERO,
        ctime: Duration::ZERO,
        nlink: 1,
        generation: 0,
        kind: InodeKind::Directory,
        xattrs: std::collections::BTreeMap::new(),
        dirty_bits: 0,
        mutation_gen: 0,
    }
}

// ---------------------------------------------------------------------------
// Basic persistence round-trip
// ---------------------------------------------------------------------------

#[test]
fn alloc_commit_reopen_roundtrip() {
    let (mut store, _dir) = temp_store();

    // Phase 1: Create and commit
    let tbl = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("open table");
    let ino = tbl
        .create(InodeKind::File, file_attrs(0o644, 4096))
        .expect("create inode");
    tbl.commit(&mut store).expect("commit");

    // Phase 2: Reopen and verify
    let tbl2 = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("reopen table");
    let attrs = tbl2.lookup(ino).expect("inode should survive restart");
    assert_eq!(attrs.mode, 0o644);
    assert_eq!(attrs.size, 4096);
    assert_eq!(attrs.kind, InodeKind::File);
    assert_eq!(attrs.nlink, 1);
    assert!(attrs.generation > 0);
}

#[test]
fn multiple_inodes_survive_roundtrip() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("open table");
    let ino1 = tbl.create(InodeKind::File, file_attrs(0o644, 100)).unwrap();
    let ino2 = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();
    let ino3 = tbl
        .create(InodeKind::Symlink, {
            let mut a = file_attrs(0o777, 0);
            a.kind = InodeKind::Symlink;
            a
        })
        .unwrap();
    tbl.commit(&mut store).expect("commit");

    let tbl2 = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("reopen");
    assert_eq!(tbl2.len(), 3);

    let a1 = tbl2.lookup(ino1).unwrap();
    assert_eq!(a1.mode, 0o644);
    assert_eq!(a1.size, 100);

    let a2 = tbl2.lookup(ino2).unwrap();
    assert_eq!(a2.kind, InodeKind::Directory);
    assert_eq!(a2.mode, 0o755);

    let a3 = tbl2.lookup(ino3).unwrap();
    assert_eq!(a3.kind, InodeKind::Symlink);
    assert_eq!(a3.mode, 0o777);
}

#[test]
fn update_and_reopen_preserves_changes() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("open");
    let ino = tbl.create(InodeKind::File, file_attrs(0o644, 0)).unwrap();

    // Modify and commit
    let mut attrs = tbl.lookup(ino).unwrap();
    attrs.size = 8192;
    attrs.mode = 0o600;
    tbl.setattr(ino, attrs).unwrap();
    tbl.commit(&mut store).expect("commit");

    let tbl2 = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("reopen");
    let a = tbl2.lookup(ino).unwrap();
    assert_eq!(a.size, 8192);
    assert_eq!(a.mode, 0o600);
}

#[test]
fn delete_then_commit_reopen_inode_gone() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("open");
    let ino = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();
    tbl.commit(&mut store).expect("commit 1");

    // Delete: unlink (nlink→0) then remove
    tbl.unlink(ino).unwrap();
    tbl.delete(ino).unwrap();
    tbl.commit(&mut store).expect("commit 2");

    let tbl2 = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("reopen");
    assert!(tbl2.lookup(ino).is_none());
    assert_eq!(tbl2.len(), 0);
}

#[test]
fn file_auto_remove_on_unlink_to_zero_commits_tombstone() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("open");
    let ino = tbl.create(InodeKind::File, file_attrs(0o644, 0)).unwrap();
    tbl.commit(&mut store).expect("commit 1");

    // File auto-removal on nlink→0
    tbl.unlink(ino).unwrap();
    assert!(tbl.lookup(ino).is_none()); // auto-removed
    tbl.commit(&mut store).expect("commit 2");

    let tbl2 = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("reopen");
    assert!(tbl2.lookup(ino).is_none());
}

// ---------------------------------------------------------------------------
// Header persistence
// ---------------------------------------------------------------------------

#[test]
fn header_next_generation_survives_restart() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("open");
    for _ in 0..5 {
        tbl.create(InodeKind::File, file_attrs(0o644, 0)).unwrap();
    }
    // All 5 inodes get generation numbers 1..5
    tbl.commit(&mut store).expect("commit");

    let tbl2 = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("reopen");
    // Next allocation should get generation > 5
    let ino = tbl2.create(InodeKind::File, file_attrs(0o644, 0)).unwrap();
    let gen = tbl2.lookup(ino).unwrap().generation;
    assert!(gen > 5, "generation {gen} should be > 5");
}

#[test]
fn free_list_survives_restart() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("open");
    let ino1 = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();
    let _ino2 = tbl.create(InodeKind::File, file_attrs(0o644, 0)).unwrap();

    // Remove ino1 to populate free list
    tbl.unlink(ino1).unwrap();
    tbl.delete(ino1).unwrap();
    tbl.commit(&mut store).expect("commit");

    // Reopen: the free list entry for ino1 should be preserved
    let tbl2 = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("reopen");
    let ino3 = tbl2.create(InodeKind::File, file_attrs(0o600, 0)).unwrap();
    // ino3 should reuse ino1's slot (from the free list)
    assert_eq!(ino3.0, ino1.0);
}

#[test]
fn capacity_survives_restart() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 32, Box::new(SystemTimeSource)).expect("open");
    tbl.commit(&mut store).expect("commit");

    let tbl2 = InodeTable::open(&mut store, 32, Box::new(SystemTimeSource)).expect("reopen");
    assert_eq!(tbl2.capacity(), 32);
}

// ---------------------------------------------------------------------------
// Dirty tracking
// ---------------------------------------------------------------------------

#[test]
fn dirty_count_tracks_uncommitted_changes() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("open");
    assert_eq!(tbl.dirty_count(), 0);

    let _ino = tbl.create(InodeKind::File, file_attrs(0o644, 0)).unwrap();
    assert_eq!(tbl.dirty_count(), 1);

    tbl.commit(&mut store).expect("commit");
    assert_eq!(tbl.dirty_count(), 0);
}

#[test]
fn modify_then_dirty_then_commit_clears_dirty() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("open");
    let ino = tbl.create(InodeKind::File, file_attrs(0o644, 0)).unwrap();
    tbl.commit(&mut store).expect("commit");
    assert_eq!(tbl.dirty_count(), 0);

    // Modify: setattr
    let mut attrs = tbl.lookup(ino).unwrap();
    attrs.size = 1024;
    tbl.setattr(ino, attrs).unwrap();
    assert_eq!(tbl.dirty_count(), 1);

    tbl.commit(&mut store).expect("commit");
    assert_eq!(tbl.dirty_count(), 0);
}

// ---------------------------------------------------------------------------
// Flush alias
// ---------------------------------------------------------------------------

#[test]
fn flush_is_alias_for_commit() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("open");
    let ino = tbl.create(InodeKind::File, file_attrs(0o644, 0)).unwrap();
    tbl.flush(&mut store).expect("flush");

    // Reopen and verify flush worked just like commit
    let tbl2 = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("reopen");
    assert!(tbl2.lookup(ino).is_some());
}

// ---------------------------------------------------------------------------
// Fresh store (no prior header)
// ---------------------------------------------------------------------------

#[test]
fn fresh_store_creates_empty_table() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("open");
    assert!(tbl.is_empty());
    assert_eq!(tbl.len(), 0);
    assert_eq!(tbl.capacity(), 64);
}

// ---------------------------------------------------------------------------
// Large batch
// ---------------------------------------------------------------------------

#[test]
fn batch_100_inodes_roundtrip() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 256, Box::new(SystemTimeSource)).expect("open");
    let mut inos = Vec::new();
    for i in 0..100 {
        let ino = tbl
            .create(
                InodeKind::File,
                InodeAttributes::new(0o644, i, 1000, InodeKind::File),
            )
            .unwrap();
        inos.push(ino);
    }
    tbl.commit(&mut store).expect("commit");

    let tbl2 = InodeTable::open(&mut store, 256, Box::new(SystemTimeSource)).expect("reopen");
    assert_eq!(tbl2.len(), 100);
    for (i, ino) in inos.iter().enumerate() {
        let a = tbl2.lookup(*ino).expect("inode should exist");
        assert_eq!(a.uid, i as u32);
        assert_eq!(a.gid, 1000);
    }
}

// ---------------------------------------------------------------------------
// Inode with all fields set to non-zero / max values
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_all_fields_set() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("open");

    let now = Duration::new(1_700_000_000, 123_456_789);
    // Use setattr after create to set max values and custom timestamps
    // (create fills in timestamps from the time source; we override after)
    let ino = tbl.create(InodeKind::File, file_attrs(0o644, 0)).unwrap();
    let attrs = InodeAttributes {
        mode: 0o755,
        uid: 1234,
        gid: 5678,
        size: 1_048_576,
        blocks: 2048,
        atime: now,
        mtime: now,
        ctime: now,
        nlink: 3,
        generation: 0, // preserved by setattr
        kind: InodeKind::File,
        xattrs: std::collections::BTreeMap::new(),
        dirty_bits: 0,
        mutation_gen: 0,
    };
    tbl.setattr(ino, attrs.clone()).unwrap();
    tbl.commit(&mut store).expect("commit");

    let tbl2 = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).expect("reopen");
    let stored = tbl2.lookup(ino).unwrap();
    assert_eq!(stored.mode, 0o755);
    assert_eq!(stored.uid, 1234);
    assert_eq!(stored.gid, 5678);
    assert_eq!(stored.size, 1_048_576);
    assert_eq!(stored.blocks, 2048);
    assert_eq!(stored.atime, now);
    assert_eq!(stored.mtime, now);
    assert_eq!(stored.ctime, now);
    assert_eq!(stored.nlink, 3);
    // generation was explicitly set to 0 by setattr
    assert_eq!(stored.generation, 0);
}

// ---------------------------------------------------------------------------
// Stress: create, modify, delete interleaving
// ---------------------------------------------------------------------------

#[test]
fn create_modify_delete_interleaving() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 128, Box::new(SystemTimeSource)).expect("open");

    // Create 20 files
    let mut file_inos = Vec::new();
    for i in 0..20 {
        let ino = tbl
            .create(
                InodeKind::File,
                InodeAttributes::new(0o644, i, 1000, InodeKind::File),
            )
            .unwrap();
        file_inos.push(ino);
    }
    tbl.commit(&mut store).expect("commit after create");

    // Modify every other one
    for (i, &ino) in file_inos.iter().enumerate() {
        if i % 2 == 0 {
            let mut a = tbl.lookup(ino).unwrap();
            a.size = (i as u64) * 1024;
            tbl.setattr(ino, a).unwrap();
        }
    }

    // Delete several: unlink all, then delete (for files, unlink auto-removes)
    for i in (0..20).step_by(3) {
        tbl.unlink(file_inos[i]).unwrap();
        // Only call delete for non-files (files are auto-removed by unlink)
        if tbl.lookup(file_inos[i]).is_some() {
            tbl.delete(file_inos[i]).unwrap();
        }
    }
    tbl.commit(&mut store).expect("commit after modify/delete");

    // Reopen and verify
    let tbl2 = InodeTable::open(&mut store, 128, Box::new(SystemTimeSource)).expect("reopen");

    for (i, &ino) in file_inos.iter().enumerate() {
        if i % 3 == 0 {
            assert!(tbl2.lookup(ino).is_none(), "ino {ino:?} should be deleted");
        } else {
            let a = tbl2.lookup(ino).expect("ino should exist");
            if i % 2 == 0 {
                assert_eq!(a.size, (i as u64) * 1024);
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════════
// Xattr persistence roundtrip
// ═════════════════════════════════════════════════════════════════════

#[test]
fn xattr_survives_commit_reopen_roundtrip() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).unwrap();

    // Create an inode with xattrs
    let ino = tbl
        .create(
            InodeKind::File,
            InodeAttributes::new(0o644, 1000, 1000, InodeKind::File),
        )
        .unwrap();

    // Set some xattrs through the InodeTable API
    tbl.set_xattr(ino, b"user.key1", b"value1", 0).unwrap();
    tbl.set_xattr(ino, b"user.key2", b"hello world", 0).unwrap();
    tbl.set_xattr(ino, b"user.key3", b"third", 0).unwrap();

    // Commit and reopen
    tbl.commit(&mut store).expect("commit");

    let tbl2 = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).unwrap();

    // Verify xattrs survived
    assert_eq!(tbl2.get_xattr(ino, b"user.key1").unwrap(), b"value1");
    assert_eq!(tbl2.get_xattr(ino, b"user.key2").unwrap(), b"hello world");
    assert_eq!(tbl2.get_xattr(ino, b"user.key3").unwrap(), b"third");
    // Missing xattr still returns AttrNotFound
    assert_eq!(
        tbl2.get_xattr(ino, b"user.missing"),
        Err(tidefs_inode_table::XattrError::AttrNotFound)
    );
}

#[test]
fn xattr_survives_multiple_commits_with_modifications() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).unwrap();

    let ino = tbl
        .create(
            InodeKind::File,
            InodeAttributes::new(0o644, 1000, 1000, InodeKind::File),
        )
        .unwrap();

    // Phase 1: set xattrs, commit
    tbl.set_xattr(ino, b"user.phase1", b"first", 0).unwrap();
    tbl.commit(&mut store).expect("commit phase 1");

    // Phase 2: reopen, modify, add, remove, commit
    let t2 = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).unwrap();
    assert_eq!(t2.get_xattr(ino, b"user.phase1").unwrap(), b"first");

    // Add new xattr
    t2.set_xattr(ino, b"user.phase2", b"second", 0).unwrap();
    // Modify existing xattr
    t2.set_xattr(ino, b"user.phase1", b"modified", 0).unwrap();
    // Remove one (doesn't exist yet)
    assert_eq!(
        t2.remove_xattr(ino, b"user.nonexistent"),
        Err(tidefs_inode_table::XattrError::AttrNotFound)
    );

    t2.commit(&mut store).expect("commit phase 2");

    // Phase 3: reopen and verify
    let t3 = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).unwrap();
    assert_eq!(t3.get_xattr(ino, b"user.phase1").unwrap(), b"modified");
    assert_eq!(t3.get_xattr(ino, b"user.phase2").unwrap(), b"second");
}

#[test]
fn xattr_removed_does_not_survive_commit() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).unwrap();

    let ino = tbl
        .create(
            InodeKind::File,
            InodeAttributes::new(0o644, 1000, 1000, InodeKind::File),
        )
        .unwrap();

    tbl.set_xattr(ino, b"user.keep", b"retained", 0).unwrap();
    tbl.set_xattr(ino, b"user.drop", b"transient", 0).unwrap();
    tbl.commit(&mut store).expect("commit");

    // Reopen, remove, commit again
    let t2 = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).unwrap();
    t2.remove_xattr(ino, b"user.drop").unwrap();
    t2.commit(&mut store).expect("commit after remove");

    // Reopen and verify
    let t3 = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).unwrap();
    assert_eq!(t3.get_xattr(ino, b"user.keep").unwrap(), b"retained");
    assert_eq!(
        t3.get_xattr(ino, b"user.drop"),
        Err(tidefs_inode_table::XattrError::AttrNotFound)
    );
}

#[test]
fn xattr_empty_xattrs_no_persistence_overhead() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).unwrap();

    let ino = tbl
        .create(
            InodeKind::File,
            InodeAttributes::new(0o644, 1000, 1000, InodeKind::File),
        )
        .unwrap();

    // Commit without any xattrs
    tbl.commit(&mut store).expect("commit");

    // Reopen — xattrs should be empty
    let t2 = InodeTable::open(&mut store, 64, Box::new(SystemTimeSource)).unwrap();

    assert_eq!(t2.xattr_count(ino).unwrap(), 0);
    assert!(t2.list_xattr(ino).unwrap().is_empty());
}
