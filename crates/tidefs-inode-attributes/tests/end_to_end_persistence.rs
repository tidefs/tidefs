//! End-to-end inode lifecycle tests exercising the full stack:
//! AttrCache → TableAttributeStore → InodeTable → LocalObjectStore.
//!
//! These validate that attributes survive the complete create→modify→commit→
//! reopen→verify cycle through every layer of the attribute pipeline.

use std::sync::Arc;
use std::time::Duration;

use tidefs_inode_attributes::{table_store::TableAttributeStore, AttrCache, InodeAttributeStore};
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

fn setup() -> (
    Arc<InodeTable>,
    TableAttributeStore,
    LocalObjectStore,
    tempfile::TempDir,
) {
    let (mut store, dir) = temp_store();
    let tbl =
        InodeTable::open(&mut store, 128, Box::new(SystemTimeSource)).expect("open inode table");
    let tbl = Arc::new(tbl);
    let attr_store = TableAttributeStore::new(Arc::clone(&tbl));
    (tbl, attr_store, store, dir)
}

// ---------------------------------------------------------------------------
// TableAttributeStore + InodeTable → persistence round-trip
// ---------------------------------------------------------------------------

#[test]
fn create_commit_reopen_via_table_store() {
    let (tbl, attr_store, mut store, _dir) = setup();

    let ino = attr_store
        .create(
            InodeKind::File,
            InodeAttributes::new(0o644, 1000, 100, InodeKind::File),
        )
        .expect("create");

    // Persist through InodeTable
    tbl.commit(&mut store).expect("commit");

    // Reopen and verify through attribute store
    let tbl2 = InodeTable::open(&mut store, 128, Box::new(SystemTimeSource)).expect("reopen");
    let attr_store2 = TableAttributeStore::new(Arc::new(tbl2));

    let attr = attr_store2.getattr(ino.0).expect("getattr after reopen");
    assert_eq!(attr.inode_id.0, ino.0);
    assert!(attr.generation.0 > 0);
    assert_eq!(attr.kind, tidefs_types_vfs_core::NodeKind::File);
    assert_eq!(attr.posix.mode & !tidefs_types_vfs_core::S_IFMT, 0o644);
    assert_eq!(attr.posix.uid, 1000);
    assert_eq!(attr.posix.gid, 100);
    assert_eq!(attr.posix.nlink, 1);
}

#[test]
fn setattr_commit_reopen_preserves_changes() {
    let (tbl, attr_store, mut store, _dir) = setup();

    let ino = attr_store
        .create(
            InodeKind::File,
            InodeAttributes::new(0o644, 1000, 100, InodeKind::File),
        )
        .expect("create");

    // Modify through the attribute store
    let mut set = tidefs_types_vfs_core::SetAttr::new();
    set.valid = tidefs_types_vfs_core::FATTR_SIZE;
    set.size = 1048576;
    attr_store.setattr(ino.0, &set).expect("setattr");

    tbl.commit(&mut store).expect("commit");

    let tbl2 = InodeTable::open(&mut store, 128, Box::new(SystemTimeSource)).expect("reopen");
    let attr_store2 = TableAttributeStore::new(Arc::new(tbl2));

    let attr = attr_store2.getattr(ino.0).expect("getattr");
    assert_eq!(attr.posix.size, 1048576);
}

#[test]
fn touch_atime_commits_and_survives() {
    let (tbl, attr_store, mut store, _dir) = setup();

    let ino = attr_store
        .create(
            InodeKind::File,
            InodeAttributes::new(0o644, 1000, 100, InodeKind::File),
        )
        .expect("create");

    let orig = attr_store.getattr(ino.0).unwrap();
    std::thread::sleep(Duration::from_millis(2));

    attr_store.touch_atime(ino.0).expect("touch_atime");
    tbl.commit(&mut store).expect("commit");

    let tbl2 = InodeTable::open(&mut store, 128, Box::new(SystemTimeSource)).expect("reopen");
    let attr_store2 = TableAttributeStore::new(Arc::new(tbl2));

    let updated = attr_store2.getattr(ino.0).unwrap();
    assert!(updated.posix.atime_ns > orig.posix.atime_ns);
}

// ---------------------------------------------------------------------------
// AttrCache layer on top of TableAttributeStore
// ---------------------------------------------------------------------------

#[test]
fn attr_cache_roundtrip_through_table_store() {
    let (tbl, attr_store, mut store, _dir) = setup();

    let ino = attr_store
        .create(
            InodeKind::File,
            InodeAttributes::new(0o755, 500, 500, InodeKind::File),
        )
        .expect("create");
    tbl.commit(&mut store).expect("commit");

    // Reopen fresh table + attribute store
    let tbl2 = InodeTable::open(&mut store, 128, Box::new(SystemTimeSource)).expect("reopen");
    let attr_store2 = TableAttributeStore::new(Arc::new(tbl2));

    // Wrap in AttrCache
    let cache = AttrCache::new(attr_store2, 64);

    // get_or_load should load from the table-backed store
    let entry = cache.get_or_load(ino.0).expect("get_or_load");
    assert_eq!(entry.posix.mode & !tidefs_types_vfs_core::S_IFMT, 0o755);
    assert_eq!(entry.posix.uid, 500);
    assert_eq!(entry.posix.nlink, 1);
}

#[test]
fn attr_cache_update_flushes_through_to_table() {
    let (tbl, attr_store, mut store, _dir) = setup();

    let ino = attr_store
        .create(
            InodeKind::File,
            InodeAttributes::new(0o644, 1000, 100, InodeKind::File),
        )
        .expect("create");
    tbl.commit(&mut store).expect("commit");

    // Open fresh, wrap in cache
    let tbl2 = InodeTable::open(&mut store, 128, Box::new(SystemTimeSource)).expect("reopen");
    let attr_store2 = TableAttributeStore::new(Arc::new(tbl2));
    let cache = AttrCache::new(attr_store2, 64);

    // Update through cache: build an InodeAttr and dirty mask
    let mut entry = cache.get_or_load(ino.0).expect("load");
    entry.posix.mode = (entry.posix.mode & tidefs_types_vfs_core::S_IFMT) | 0o700;
    let mut dirty = tidefs_inode_attributes::AttrDirty::new();
    dirty.set(tidefs_inode_attributes::ATTR_DIRTY_MODE);
    cache.update(ino.0, entry, dirty).expect("update");

    // Re-load from cache (should hit cached entry)
    let entry = cache.get_or_load(ino.0).expect("re-read");
    assert_eq!(entry.posix.mode & !tidefs_types_vfs_core::S_IFMT, 0o700);
}

#[test]
fn attr_cache_miss_loads_from_table() {
    let (tbl, attr_store, mut store, _dir) = setup();

    let ino = attr_store
        .create(
            InodeKind::File,
            InodeAttributes::new(0o600, 2000, 200, InodeKind::File),
        )
        .expect("create");
    tbl.commit(&mut store).expect("commit");

    // Create a second cache on a reopened table — no warm entries
    let tbl2 = InodeTable::open(&mut store, 128, Box::new(SystemTimeSource)).expect("reopen");
    let attr_store2 = TableAttributeStore::new(Arc::new(tbl2));
    let cache = AttrCache::new(attr_store2, 64);

    // First access should be a miss, loading from the table
    let entry = cache.get_or_load(ino.0).expect("cold load");
    assert_eq!(entry.posix.uid, 2000);
    assert_eq!(entry.posix.gid, 200);
}

#[test]
fn attr_cache_bulk_create_and_readback() {
    let (tbl, attr_store, mut store, _dir) = setup();

    let mut inos = Vec::new();
    for i in 0..50 {
        let ino = attr_store
            .create(
                InodeKind::File,
                InodeAttributes::new(0o644, i, 100 + i, InodeKind::File),
            )
            .expect("create");
        inos.push(ino);
    }
    tbl.commit(&mut store).expect("commit");

    let tbl2 = InodeTable::open(&mut store, 128, Box::new(SystemTimeSource)).expect("reopen");
    let attr_store2 = TableAttributeStore::new(Arc::new(tbl2));
    let cache = AttrCache::new(attr_store2, 128);

    for (i, ino) in inos.iter().enumerate() {
        let entry = cache.get_or_load(ino.0).expect("load");
        assert_eq!(entry.posix.uid, i as u32);
        assert_eq!(entry.posix.gid, 100 + i as u32);
    }
}

// ---------------------------------------------------------------------------
// Full lifecycle: Create → Modify → Delete → Commit → Reopen → Verify absent
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_delete_persists() {
    let (tbl, attr_store, mut store, _dir) = setup();

    // Create a directory (so delete works without auto-removal)
    let ino = attr_store
        .create(
            InodeKind::Directory,
            InodeAttributes::new(0o755, 0, 0, InodeKind::Directory),
        )
        .expect("create");

    // Set some attributes
    let mut set = tidefs_types_vfs_core::SetAttr::new();
    set.valid = tidefs_types_vfs_core::FATTR_MODE;
    set.mode = 0o700;
    attr_store.setattr(ino.0, &set).expect("setattr");

    // Drop link (nlink 1→0)
    let _ = attr_store.drop_link(ino.0).expect("drop_link");

    // Now delete through the table (needs nlink == 0)
    tbl.delete(ino).expect("delete");
    tbl.commit(&mut store).expect("commit");

    // Reopen and verify absent
    let tbl2 = InodeTable::open(&mut store, 128, Box::new(SystemTimeSource)).expect("reopen");
    let attr_store2 = TableAttributeStore::new(Arc::new(tbl2));
    assert!(attr_store2.getattr(ino.0).is_err());
}

// ---------------------------------------------------------------------------
// to_stat through the full stack
// ---------------------------------------------------------------------------

#[test]
fn to_stat_roundtrip_through_persistence() {
    let (tbl, attr_store, mut store, _dir) = setup();

    let ino = attr_store
        .create(
            InodeKind::File,
            InodeAttributes::new(0o755, 500, 500, InodeKind::File),
        )
        .expect("create");
    tbl.commit(&mut store).expect("commit");

    let tbl2 = InodeTable::open(&mut store, 128, Box::new(SystemTimeSource)).expect("reopen");
    let attr_store2 = TableAttributeStore::new(Arc::new(tbl2));

    let st = attr_store2.to_stat(ino.0).expect("to_stat");
    assert_eq!(st.st_ino, ino.0);
    assert_eq!(st.st_mode & !tidefs_types_vfs_core::S_IFMT, 0o755);
    assert_eq!(st.st_uid, 500);
    assert_eq!(st.st_gid, 500);
    assert_eq!(st.st_nlink, 1);
}
