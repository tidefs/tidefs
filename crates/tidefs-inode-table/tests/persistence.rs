#![cfg(feature = "std")]
//! Integration tests for inode-table persistence through the object store.
//!
//! Covers multi-commit cycles, kind-specific survival (file/dir/symlink),
//! empty commits, delete-then-reopen, timestamp fidelity across commits,
//! dirty-count lifecycle, free-list reuse after reopen, and capacity
//! mismatch detection.
//!
//! Uses [`InodeTable::open`] / [`InodeTable::commit`] with a tempdir-backed
//! [`LocalObjectStore`].

use std::time::Duration;
use tidefs_inode_table::{
    InodeAttributes, InodeKind, InodeTable, InodeTableError, SystemTimeSource,
};
use tidefs_local_object_store::LocalObjectStore;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn temp_store() -> (LocalObjectStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let store = LocalObjectStore::open(dir.path()).expect("open store");
    (store, dir)
}

fn file_attrs(mode: u32) -> InodeAttributes {
    InodeAttributes::new(mode, 1000, 1000, InodeKind::File)
}

fn dir_attrs(mode: u32) -> InodeAttributes {
    InodeAttributes::new(mode, 0, 0, InodeKind::Directory)
}

fn symlink_attrs(mode: u32) -> InodeAttributes {
    InodeAttributes::new(mode, 1000, 1000, InodeKind::Symlink)
}

fn time_source() -> Box<dyn tidefs_inode_table::TimeSource> {
    Box::new(SystemTimeSource)
}

// ---------------------------------------------------------------------------
// 1. Multi-commit cycle: create → commit → modify → commit → reopen
// ---------------------------------------------------------------------------

#[test]
fn multi_commit_cycle_preserves_all_changes() {
    let (mut store, _dir) = temp_store();
    let cap = 64;

    // Phase 1: Create 3 inodes, commit
    let tbl = InodeTable::open(&mut store, cap, time_source()).unwrap();
    let ino1 = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let ino2 = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let ino3 = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();
    tbl.commit(&mut store).unwrap();
    assert_eq!(tbl.dirty_count(), 0);

    // Phase 2: Capture ino2 generation, modify ino1, delete ino2
    let gen2 = tbl.lookup(ino2).unwrap().generation;
    let mut attrs = tbl.lookup(ino1).unwrap();
    attrs.size = 4096;
    tbl.setattr(ino1, attrs).unwrap();
    tbl.unlink(ino2).unwrap(); // file auto-remove
    tbl.commit(&mut store).unwrap(); // flush deletion tombstone

    // Phase 3: Create ino4 (reuses ino2's slot), commit
    let ino4 = tbl
        .create(InodeKind::Symlink, symlink_attrs(0o777))
        .unwrap();
    assert_eq!(ino4.0, ino2.0, "should reuse same slot");
    tbl.commit(&mut store).unwrap();

    // Phase 4: Reopen and verify
    let tbl2 = InodeTable::open(&mut store, cap, time_source()).unwrap();
    assert_eq!(tbl2.len(), 3); // ino1, ino3, ino4 survive

    assert_eq!(tbl2.lookup(ino1).unwrap().size, 4096);
    // ino2 slot reused — old generation is stale
    assert_eq!(
        tbl2.validate_generation(ino2, gen2),
        Err(InodeTableError::GenerationMismatch)
    );
    assert_eq!(tbl2.lookup(ino3).unwrap().kind, InodeKind::Directory);
    let a4 = tbl2.lookup(ino4).unwrap();
    assert_eq!(a4.kind, InodeKind::Symlink);
    assert!(a4.generation > gen2, "generation must advance on reuse");
}

// ---------------------------------------------------------------------------
// 2. Symlink and directory persistence round-trip
// ---------------------------------------------------------------------------

#[test]
fn symlink_survives_commit_reopen() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 32, time_source()).unwrap();
    let ino = tbl
        .create(InodeKind::Symlink, symlink_attrs(0o777))
        .unwrap();
    tbl.commit(&mut store).unwrap();

    let tbl2 = InodeTable::open(&mut store, 32, time_source()).unwrap();
    let attrs = tbl2.lookup(ino).unwrap();
    assert_eq!(attrs.kind, InodeKind::Symlink);
    assert_eq!(attrs.mode, 0o777);
    assert_eq!(attrs.nlink, 1);
    assert!(attrs.generation > 0);
}

#[test]
fn directory_survives_commit_reopen() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 32, time_source()).unwrap();
    let ino = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();
    tbl.commit(&mut store).unwrap();

    let tbl2 = InodeTable::open(&mut store, 32, time_source()).unwrap();
    let attrs = tbl2.lookup(ino).unwrap();
    assert_eq!(attrs.kind, InodeKind::Directory);
    assert_eq!(attrs.mode, 0o755);
}

// ---------------------------------------------------------------------------
// 3. Empty commit (no dirty inodes) succeeds
// ---------------------------------------------------------------------------

#[test]
fn empty_commit_succeeds() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 32, time_source()).unwrap();
    assert_eq!(tbl.dirty_count(), 0);
    tbl.commit(&mut store).unwrap();
    assert_eq!(tbl.dirty_count(), 0);

    let tbl2 = InodeTable::open(&mut store, 32, time_source()).unwrap();
    assert!(tbl2.is_empty());
}

#[test]
fn commit_after_create_then_empty_commit_is_idempotent() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 32, time_source()).unwrap();
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    tbl.commit(&mut store).unwrap();
    assert_eq!(tbl.dirty_count(), 0);

    // Second empty commit should not harm anything
    tbl.commit(&mut store).unwrap();

    let tbl2 = InodeTable::open(&mut store, 32, time_source()).unwrap();
    assert_eq!(tbl2.len(), 1);
    assert!(tbl2.lookup(ino).is_some());
}

// ---------------------------------------------------------------------------
// 4. Delete-then-reopen: all inodes gone
// ---------------------------------------------------------------------------

#[test]
fn delete_all_then_reopen_empty() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 64, time_source()).unwrap();
    let f_ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let d_ino = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();
    let s_ino = tbl
        .create(InodeKind::Symlink, symlink_attrs(0o777))
        .unwrap();
    tbl.commit(&mut store).unwrap();

    // Delete all
    tbl.unlink(f_ino).unwrap(); // file auto-remove
    tbl.unlink(d_ino).unwrap();
    tbl.delete(d_ino).unwrap(); // dir needs explicit delete
    tbl.unlink(s_ino).unwrap();
    tbl.delete(s_ino).unwrap(); // symlink needs explicit delete
    assert_eq!(tbl.len(), 0);
    tbl.commit(&mut store).unwrap();

    let tbl2 = InodeTable::open(&mut store, 64, time_source()).unwrap();
    assert!(tbl2.is_empty());
    assert_eq!(tbl2.len(), 0);
}

// ---------------------------------------------------------------------------
// 5. Free-list reuse survives reopen
// ---------------------------------------------------------------------------

#[test]
fn free_list_reuse_after_reopen() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 32, time_source()).unwrap();
    let ino_a = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let ino_b = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let _ino_c = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    tbl.unlink(ino_b).unwrap(); // file auto-remove, slot goes to free list
    tbl.commit(&mut store).unwrap();

    let tbl2 = InodeTable::open(&mut store, 32, time_source()).unwrap();
    let reused = tbl2.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();
    assert_eq!(reused.0, ino_b.0, "free list should survive reopen");
    assert!(tbl2.lookup(ino_a).is_some());
    assert_eq!(tbl2.len(), 3); // ino_a, _ino_c, reused
}

// ---------------------------------------------------------------------------
// 6. Generation counter advances across reopen
// ---------------------------------------------------------------------------

#[test]
fn generation_counter_advances_across_reopen() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 16, time_source()).unwrap();
    let ino1 = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let gen1 = tbl.lookup(ino1).unwrap().generation;
    tbl.commit(&mut store).unwrap();

    let tbl2 = InodeTable::open(&mut store, 16, time_source()).unwrap();
    let ino2 = tbl2.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let gen2 = tbl2.lookup(ino2).unwrap().generation;
    assert!(
        gen2 > gen1,
        "generation should advance across reopen: {gen2} <= {gen1}"
    );
}

// ---------------------------------------------------------------------------
// 7. Timestamp fidelity across persist
// ---------------------------------------------------------------------------

#[test]
fn timestamps_survive_commit_reopen() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 16, time_source()).unwrap();
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let at_create = tbl.lookup(ino).unwrap();

    assert!(at_create.atime > Duration::ZERO);
    assert!(at_create.mtime > Duration::ZERO);
    assert!(at_create.ctime > Duration::ZERO);

    tbl.commit(&mut store).unwrap();

    let tbl2 = InodeTable::open(&mut store, 16, time_source()).unwrap();
    let after_reopen = tbl2.lookup(ino).unwrap();
    assert_eq!(after_reopen.atime, at_create.atime);
    assert_eq!(after_reopen.mtime, at_create.mtime);
    assert_eq!(after_reopen.ctime, at_create.ctime);
}

// ---------------------------------------------------------------------------
// 8. All attribute fields survive round-trip
// ---------------------------------------------------------------------------

#[test]
fn all_attribute_fields_survive_roundtrip() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 16, time_source()).unwrap();
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();

    let custom = InodeAttributes {
        mode: 0o755,
        uid: 42,
        gid: 99,
        size: 1_048_576,
        blocks: 2048,
        atime: Duration::new(1_700_000_000, 123_456_789),
        mtime: Duration::new(1_700_000_001, 987_654_321),
        ctime: Duration::new(1_700_000_002, 111_222_333),
        nlink: 3,
        generation: 0,
        kind: InodeKind::File,
        xattrs: std::collections::BTreeMap::new(),
        dirty_bits: 0,
        mutation_gen: 0,
    };
    tbl.setattr(ino, custom.clone()).unwrap();
    tbl.commit(&mut store).unwrap();

    let tbl2 = InodeTable::open(&mut store, 16, time_source()).unwrap();
    let stored = tbl2.lookup(ino).unwrap();
    assert_eq!(stored.mode, custom.mode);
    assert_eq!(stored.uid, custom.uid);
    assert_eq!(stored.gid, custom.gid);
    assert_eq!(stored.size, custom.size);
    assert_eq!(stored.blocks, custom.blocks);
    assert_eq!(stored.atime, custom.atime);
    assert_eq!(stored.mtime, custom.mtime);
    assert_eq!(stored.ctime, custom.ctime);
    assert_eq!(stored.nlink, custom.nlink);
    assert_eq!(stored.kind, custom.kind);
}

// ---------------------------------------------------------------------------
// 9. Mixed-kind batch survives round-trip
// ---------------------------------------------------------------------------

#[test]
fn mixed_kind_batch_survives_roundtrip() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 64, time_source()).unwrap();
    let mut entries: Vec<(tidefs_inode_table::Ino, InodeKind, u32)> = Vec::new();

    for i in 0..30 {
        let (kind, mode) = match i % 3 {
            0 => (InodeKind::File, 0o644),
            1 => (InodeKind::Directory, 0o755),
            _ => (InodeKind::Symlink, 0o777),
        };
        let attrs = InodeAttributes::new(mode, i, i * 10, kind);
        let ino = tbl.create(kind, attrs).unwrap();
        entries.push((ino, kind, mode));
    }
    tbl.commit(&mut store).unwrap();
    assert_eq!(tbl.len(), 30);

    let tbl2 = InodeTable::open(&mut store, 64, time_source()).unwrap();
    assert_eq!(tbl2.len(), 30);

    for (ino, expected_kind, expected_mode) in &entries {
        let attrs = tbl2.lookup(*ino).expect("inode should survive");
        assert_eq!(attrs.kind, *expected_kind);
        assert_eq!(attrs.mode, *expected_mode);
    }
}

// ---------------------------------------------------------------------------
// 10. Sequential inode numbers survive reopen
// ---------------------------------------------------------------------------

#[test]
fn sequential_inode_numbers_survive_reopen() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 256, time_source()).unwrap();
    let mut inos = Vec::new();
    for i in 0..50u32 {
        let ino = tbl
            .create(
                InodeKind::File,
                InodeAttributes::new(0o644, i, 0, InodeKind::File),
            )
            .unwrap();
        inos.push(ino);
    }
    for (i, ino) in inos.iter().enumerate() {
        assert_eq!(ino.0, (i + 1) as u64);
    }
    tbl.commit(&mut store).unwrap();

    let tbl2 = InodeTable::open(&mut store, 256, time_source()).unwrap();
    assert_eq!(tbl2.len(), 50);
    for (i, ino) in inos.iter().enumerate() {
        let attrs = tbl2.lookup(*ino).unwrap();
        assert_eq!(attrs.uid, i as u32, "uid mismatch at index {i}");
    }
}

// ---------------------------------------------------------------------------
// 11. Uncommitted changes do not survive reopen
// ---------------------------------------------------------------------------

#[test]
fn uncommitted_changes_do_not_survive() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 32, time_source()).unwrap();
    let ino_committed = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    tbl.commit(&mut store).unwrap();

    let _ino_uncommitted = tbl.create(InodeKind::File, file_attrs(0o755)).unwrap();
    assert_eq!(tbl.len(), 2);

    let tbl2 = InodeTable::open(&mut store, 32, time_source()).unwrap();
    assert_eq!(tbl2.len(), 1);
    assert!(tbl2.lookup(ino_committed).is_some());
}

// ---------------------------------------------------------------------------
// 12. Capacity mismatch: reopen with smaller capacity preserves original
// ---------------------------------------------------------------------------

#[test]
fn reopen_preserves_original_capacity() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 128, time_source()).unwrap();
    tbl.commit(&mut store).unwrap();

    let tbl2 = InodeTable::open(&mut store, 32, time_source()).unwrap();
    assert_eq!(
        tbl2.capacity(),
        128,
        "capacity should be the originally persisted value, not the reopen argument"
    );
}

// ---------------------------------------------------------------------------
// 13. Link count survives multiple commits
// ---------------------------------------------------------------------------

#[test]
fn link_count_survives_multiple_commits() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 16, time_source()).unwrap();
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();

    tbl.link(ino).unwrap(); // nlink 2
    tbl.link(ino).unwrap(); // nlink 3
    tbl.commit(&mut store).unwrap();
    assert_eq!(tbl.lookup(ino).unwrap().nlink, 3);

    tbl.link(ino).unwrap(); // nlink 4
    tbl.commit(&mut store).unwrap();
    assert_eq!(tbl.lookup(ino).unwrap().nlink, 4);

    let tbl2 = InodeTable::open(&mut store, 16, time_source()).unwrap();
    assert_eq!(tbl2.lookup(ino).unwrap().nlink, 4);
}

// ---------------------------------------------------------------------------
// 14. Large batch (500 inodes) survives round-trip
// ---------------------------------------------------------------------------

#[test]
fn batch_500_inodes_survives_roundtrip() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 1024, time_source()).unwrap();
    let mut inos = Vec::new();
    for i in 0..500u32 {
        let ino = tbl
            .create(
                InodeKind::File,
                InodeAttributes::new(0o600 | (i & 0x1FF), i, i * 2, InodeKind::File),
            )
            .unwrap();
        inos.push(ino);
    }
    assert_eq!(tbl.len(), 500);
    tbl.commit(&mut store).unwrap();

    let tbl2 = InodeTable::open(&mut store, 1024, time_source()).unwrap();
    assert_eq!(tbl2.len(), 500);
    for (i, ino) in inos.iter().enumerate() {
        let attrs = tbl2.lookup(*ino).expect("inode must survive");
        assert_eq!(attrs.uid, i as u32);
        assert_eq!(attrs.gid, (i * 2) as u32);
    }
}

// ---------------------------------------------------------------------------
// 15. Inode reuse with fresh generation after free+commit+reopen
// ---------------------------------------------------------------------------

#[test]
fn reuse_after_free_commit_reopen_has_fresh_generation() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 16, time_source()).unwrap();
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let gen1 = tbl.lookup(ino).unwrap().generation;
    tbl.unlink(ino).unwrap(); // file auto-remove
    tbl.commit(&mut store).unwrap();

    let tbl2 = InodeTable::open(&mut store, 16, time_source()).unwrap();
    assert!(tbl2.lookup(ino).is_none());
    let reused = tbl2.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();
    assert_eq!(reused.0, ino.0, "should reuse freed slot");
    let gen2 = tbl2.lookup(reused).unwrap().generation;
    assert!(
        gen2 > gen1,
        "generation must advance on reuse: {gen2} <= {gen1}"
    );
}

// ---------------------------------------------------------------------------
// 16. Multiple free+realloc cycles survive across commits
// ---------------------------------------------------------------------------

#[test]
fn multiple_free_realloc_cycles_across_commits() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 16, time_source()).unwrap();

    // Fill 3 slots
    let ino1 = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let ino2 = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let ino3 = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    tbl.commit(&mut store).unwrap();

    // Free ino2, flush deletion, then re-allocate
    tbl.unlink(ino2).unwrap();
    tbl.commit(&mut store).unwrap(); // flush deletion before re-alloc
    let reused1 = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();
    assert_eq!(reused1.0, ino2.0);
    tbl.commit(&mut store).unwrap();

    // Free reused1, flush deletion, then re-allocate again
    tbl.unlink(reused1).unwrap();
    tbl.delete(reused1).unwrap();
    tbl.commit(&mut store).unwrap(); // flush deletion before re-alloc
    let reused2 = tbl
        .create(InodeKind::Symlink, symlink_attrs(0o777))
        .unwrap();
    assert_eq!(reused2.0, ino2.0);
    tbl.commit(&mut store).unwrap();

    // Reopen: reused2 should be a symlink, ino1/ino3 survive
    let tbl2 = InodeTable::open(&mut store, 16, time_source()).unwrap();
    assert_eq!(tbl2.lookup(reused2).unwrap().kind, InodeKind::Symlink);
    assert!(tbl2.lookup(ino1).is_some());
    assert!(tbl2.lookup(ino3).is_some());
    assert_eq!(tbl2.len(), 3);
}

// ---------------------------------------------------------------------------
// 17. Corrupt persisted metadata fails closed
// ---------------------------------------------------------------------------

#[test]
fn corrupt_header_fails_reopen() {
    let (mut store, _dir) = temp_store();

    store
        .put_named("tidefs:inode:header", &[0xAA, 0xBB, 0xCC])
        .expect("write corrupt header");

    assert!(
        InodeTable::open(&mut store, 16, time_source()).is_err(),
        "a present but malformed inode-table header must not reopen as a fresh table"
    );
}

#[test]
fn corrupt_inode_record_fails_reopen_and_direct_lookup() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 16, time_source()).unwrap();
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    tbl.commit(&mut store).unwrap();

    store
        .put_named(format!("tidefs:inode:{}", ino.0), &[0x55; 95])
        .expect("write corrupt inode record");

    assert!(
        InodeTable::lookup_persisted(&store, ino).is_err(),
        "direct persisted lookup must report a corrupt present inode record"
    );
    assert!(
        InodeTable::open(&mut store, 16, time_source()).is_err(),
        "full open must report a corrupt present inode record"
    );
}

#[test]
fn corrupt_xattr_record_fails_reopen_and_direct_lookup() {
    let (mut store, _dir) = temp_store();

    let tbl = InodeTable::open(&mut store, 16, time_source()).unwrap();
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    tbl.set_xattr(ino, b"user.key", b"value", 0).unwrap();
    tbl.commit(&mut store).unwrap();

    store
        .put_named(format!("tidefs:inode:{}:xattrs", ino.0), &[0x01])
        .expect("write corrupt xattr record");

    assert!(
        InodeTable::lookup_persisted(&store, ino).is_err(),
        "direct persisted lookup must report a corrupt present xattr record"
    );
    assert!(
        InodeTable::open(&mut store, 16, time_source()).is_err(),
        "full open must report a corrupt present xattr record"
    );
}
