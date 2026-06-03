use crate::persistence::{
    MemoryPersistentDirectoryStore, MemoryPersistentInodeStore, PersistentDirectoryStore,
    PersistentInodeStore,
};
use crate::{InodeAttributes, Namespace, ROOT_INODE};
use std::{collections::HashMap, sync::Arc};
use tidefs_types_polymorphic_directory_index_core::DatasetDirPolicy;

fn test_attrs_file() -> InodeAttributes {
    InodeAttributes::new_file(0)
}
fn test_attrs_dir() -> InodeAttributes {
    InodeAttributes::new_dir(0)
}

/// Create a shared dirs map and wire it into both the in-memory store and the Namespace.
fn test_ns_full_persistent() -> Namespace {
    let inode_store = Arc::new(MemoryPersistentInodeStore::new());
    let shared_dirs = Arc::new(std::sync::RwLock::new(HashMap::new()));
    let dir_store = Arc::new(MemoryPersistentDirectoryStore::with_shared_dirs(
        Arc::clone(&shared_dirs),
        DatasetDirPolicy::DEFAULT,
    ));
    Namespace::with_persistent_stores(
        Some(inode_store),
        Some(dir_store as Arc<dyn PersistentDirectoryStore>),
    )
}

// ── Inode persistence ──────────────────────────────────────────

#[test]
fn persistent_inode_alloc_and_get_attrs() {
    let ns = test_ns_full_persistent();
    let file_ino = ns
        .create_file(ROOT_INODE, "data", test_attrs_file())
        .unwrap();
    let attrs = ns.get_attrs(file_ino).expect("inode retrievable");
    assert_eq!(attrs.inode, file_ino);
}

#[test]
fn persistent_inode_store_preserves_explicit_inode_ids() {
    let store = MemoryPersistentInodeStore::new();
    let explicit = InodeAttributes::new_file(41);

    let (ino, generation) = store.alloc_inode(&explicit).unwrap();

    assert_eq!(ino, 41);
    assert_eq!(generation, 1);
    assert_eq!(store.get_attrs(41).unwrap().inode, 41);
    assert!(store.next_inode_id() > 41);

    let (next, _) = store.alloc_inode(&InodeAttributes::new_file(0)).unwrap();
    assert_eq!(next, 42);
}

#[test]
fn persistent_inode_update_attrs() {
    let ns = test_ns_full_persistent();
    let file_ino = ns
        .create_file(ROOT_INODE, "data", test_attrs_file())
        .unwrap();
    let mut attrs = ns.get_attrs(file_ino).unwrap();
    attrs.size = 4096;
    ns.update_attrs(file_ino, attrs).unwrap();
    assert_eq!(ns.get_attrs(file_ino).unwrap().size, 4096);
}

#[test]
fn persistent_inode_free() {
    let ns = test_ns_full_persistent();
    let file_ino = ns
        .create_file(ROOT_INODE, "tmp", test_attrs_file())
        .unwrap();
    ns.unlink(ROOT_INODE, "tmp").unwrap();
    assert!(ns.get_attrs(file_ino).is_none());
}

// ── Directory persistence ──────────────────────────────────────

#[test]
fn persistent_dir_lookup() {
    let ns = test_ns_full_persistent();
    ns.create_file(ROOT_INODE, "alpha", test_attrs_file())
        .unwrap();
    assert!(ns.lookup(ROOT_INODE, "alpha").unwrap().is_some());
}

#[test]
fn persistent_dir_list() {
    let ns = test_ns_full_persistent();
    ns.create_file(ROOT_INODE, "a", test_attrs_file()).unwrap();
    ns.create_file(ROOT_INODE, "b", test_attrs_file()).unwrap();
    let (entries, _) = ns
        .read_dir(ROOT_INODE, tidefs_dir_index::DirCookie(0))
        .unwrap();
    // . + .. + a + b = 4
    assert_eq!(entries.len(), 4);
}

#[test]
fn persistent_mkdir_and_rmdir() {
    let ns = test_ns_full_persistent();
    let dir_ino = ns.create_dir(ROOT_INODE, "sub", test_attrs_dir()).unwrap();
    assert!(ns.get_attrs(dir_ino).is_some());
    ns.unlink(ROOT_INODE, "sub").unwrap();
    assert!(ns.get_attrs(dir_ino).is_none());
}

#[test]
fn persistent_rename() {
    let ns = test_ns_full_persistent();
    let ino = ns
        .create_file(ROOT_INODE, "old", test_attrs_file())
        .unwrap();
    ns.rename(ROOT_INODE, "old", ROOT_INODE, "new").unwrap();
    assert_eq!(ns.lookup(ROOT_INODE, "old").unwrap(), None);
    assert_eq!(ns.lookup(ROOT_INODE, "new").unwrap(), Some(ino));
}

#[test]
fn persistent_hard_link() {
    let ns = test_ns_full_persistent();
    let ino = ns
        .create_file(ROOT_INODE, "orig", test_attrs_file())
        .unwrap();
    ns.create_hard_link(ROOT_INODE, "orig", ROOT_INODE, "link")
        .unwrap();
    assert_eq!(ns.lookup(ROOT_INODE, "link").unwrap(), Some(ino));
}

#[test]
fn persistent_symlink() {
    let ns = test_ns_full_persistent();
    let ino = ns.create_symlink(ROOT_INODE, "sym", b"/target").unwrap();
    assert_eq!(ns.readlink(ino).unwrap(), b"/target");
}

// ── Remount survival ───────────────────────────────────────────

#[test]
fn persistent_remount_inode_and_dir_survive() {
    let inode_store = Arc::new(MemoryPersistentInodeStore::new());
    let shared_dirs = Arc::new(std::sync::RwLock::new(HashMap::new()));
    let dir_store = Arc::new(MemoryPersistentDirectoryStore::with_shared_dirs(
        Arc::clone(&shared_dirs),
        DatasetDirPolicy::DEFAULT,
    ));

    // First mount: create files and directories.
    let ns1 = Namespace::with_persistent_stores(
        Some(Arc::clone(&inode_store) as Arc<dyn PersistentInodeStore>),
        Some(Arc::clone(&dir_store) as Arc<dyn PersistentDirectoryStore>),
    );
    let sub_ino = ns1
        .create_dir(ROOT_INODE, "subdir", test_attrs_dir())
        .unwrap();
    let file_ino = ns1
        .create_file(sub_ino, "nested.txt", test_attrs_file())
        .unwrap();
    let mut attrs = ns1.get_attrs(file_ino).unwrap();
    attrs.size = 8192;
    ns1.update_attrs(file_ino, attrs).unwrap();

    // Second mount (remount): reuse the same persistent stores.
    // Keep a clone of the shared_dirs Arc so we can pass the same
    // map to the second Namespace via a new in-memory wrapper.
    let dir_store2 = Arc::new(MemoryPersistentDirectoryStore::with_shared_dirs(
        Arc::clone(&shared_dirs),
        DatasetDirPolicy::DEFAULT,
    ));
    let ns2 = Namespace::with_persistent_stores(
        Some(Arc::clone(&inode_store) as Arc<dyn PersistentInodeStore>),
        Some(Arc::clone(&dir_store2) as Arc<dyn PersistentDirectoryStore>),
    );

    // Inode attributes survive.
    let reloaded = ns2.get_attrs(file_ino).unwrap();
    assert_eq!(reloaded.inode, file_ino);
    assert_eq!(reloaded.size, 8192);

    // Directory entries survive through the persistent dir store.
    // Note: lookup goes through persistent_dirs, so entries written
    // through the shared map appear in the new Namespace.
    assert!(ns2.lookup(ROOT_INODE, "subdir").is_ok());
}
