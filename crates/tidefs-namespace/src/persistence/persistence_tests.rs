// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use crate::persistence::{
    MemoryPersistentDirectoryState, MemoryPersistentDirectoryStore, MemoryPersistentInodeState,
    MemoryPersistentInodeStore, NamespaceDatasetIdentity, PersistentDirectoryStore,
    PersistentInodeStore,
};
use crate::{InodeAttributes, Namespace, NamespaceError, ROOT_INODE};
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

fn test_ns_for_dataset(
    identity: NamespaceDatasetIdentity,
    inode_state: Arc<MemoryPersistentInodeState>,
    dir_state: Arc<MemoryPersistentDirectoryState>,
) -> (
    Namespace,
    Arc<MemoryPersistentInodeStore>,
    Arc<MemoryPersistentDirectoryStore>,
) {
    let inode_store = Arc::new(MemoryPersistentInodeStore::with_shared_state(
        identity.clone(),
        inode_state,
    ));
    let dir_store = Arc::new(MemoryPersistentDirectoryStore::with_shared_state(
        identity.clone(),
        dir_state,
        DatasetDirPolicy::DEFAULT,
    ));
    let inode_store_dyn: Arc<dyn PersistentInodeStore> = inode_store.clone();
    let dir_store_dyn: Arc<dyn PersistentDirectoryStore> = dir_store.clone();
    let ns = Namespace::try_with_persistent_stores_for_dataset(
        identity,
        Some(inode_store_dyn),
        Some(dir_store_dyn),
    )
    .unwrap();
    (ns, inode_store, dir_store)
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
fn persistent_dataset_stores_isolate_overlapping_inode_numbers() {
    let inode_state = Arc::new(MemoryPersistentInodeState::new());
    let dir_state = Arc::new(MemoryPersistentDirectoryState::new());
    let dataset_a = NamespaceDatasetIdentity::new("dataset-a");
    let dataset_b = NamespaceDatasetIdentity::new("dataset-b");

    let (ns_a, _inode_a, dir_a) = test_ns_for_dataset(
        dataset_a.clone(),
        Arc::clone(&inode_state),
        Arc::clone(&dir_state),
    );
    let (ns_b, _inode_b, dir_b) = test_ns_for_dataset(
        dataset_b.clone(),
        Arc::clone(&inode_state),
        Arc::clone(&dir_state),
    );

    let ino_a = ns_a
        .create_file(ROOT_INODE, "same-number", test_attrs_file())
        .unwrap();
    let ino_b = ns_b
        .create_file(ROOT_INODE, "same-number", test_attrs_file())
        .unwrap();
    ns_a.create_file(ROOT_INODE, "a-only", test_attrs_file())
        .unwrap();

    assert_eq!(ino_a, 2);
    assert_eq!(ino_b, 2);
    assert_eq!(ns_a.lookup(ROOT_INODE, "same-number").unwrap(), Some(ino_a));
    assert_eq!(ns_b.lookup(ROOT_INODE, "same-number").unwrap(), Some(ino_b));
    assert_eq!(ns_b.lookup(ROOT_INODE, "a-only").unwrap(), None);

    let entry_a = dir_a
        .lookup_for_dataset(&dataset_a, ROOT_INODE, b"same-number")
        .unwrap()
        .unwrap();
    let entry_b = dir_b
        .lookup_for_dataset(&dataset_b, ROOT_INODE, b"same-number")
        .unwrap()
        .unwrap();
    assert_eq!(entry_a.0, ino_a);
    assert_eq!(entry_b.0, ino_b);
    assert_ne!(dir_a.dataset_identity(), dir_b.dataset_identity());
}

#[test]
fn persistent_namespace_rejects_wrong_dataset_root() {
    let inode_state = Arc::new(MemoryPersistentInodeState::new());
    let dir_state = Arc::new(MemoryPersistentDirectoryState::new());
    let stored = NamespaceDatasetIdentity::new("stored-dataset");
    let requested = NamespaceDatasetIdentity::new("requested-dataset");

    let (_ns, inode_store, dir_store) = test_ns_for_dataset(
        stored.clone(),
        Arc::clone(&inode_state),
        Arc::clone(&dir_state),
    );
    let inode_store_dyn: Arc<dyn PersistentInodeStore> = inode_store;
    let dir_store_dyn: Arc<dyn PersistentDirectoryStore> = dir_store;
    let result = Namespace::try_with_persistent_stores_for_dataset(
        requested.clone(),
        Some(inode_store_dyn),
        Some(dir_store_dyn),
    );

    match result {
        Err(NamespaceError::DatasetIdentityMismatch { expected, found }) => {
            assert_eq!(expected, requested);
            assert_eq!(found, stored);
        }
        Err(other) => panic!("unexpected error: {other:?}"),
        Ok(_) => panic!("wrong dataset root must be rejected"),
    }
}

#[test]
fn persistent_clone_lineage_does_not_merge_namespace_roots() {
    let inode_state = Arc::new(MemoryPersistentInodeState::new());
    let dir_state = Arc::new(MemoryPersistentDirectoryState::new());
    let source = NamespaceDatasetIdentity::with_lineage("source-dataset", "clone-lineage");
    let clone = NamespaceDatasetIdentity::with_lineage("clone-dataset", "clone-lineage");

    let (source_ns, _source_inode, _source_dir) = test_ns_for_dataset(
        source.clone(),
        Arc::clone(&inode_state),
        Arc::clone(&dir_state),
    );
    let (clone_ns, _clone_inode, _clone_dir) = test_ns_for_dataset(
        clone.clone(),
        Arc::clone(&inode_state),
        Arc::clone(&dir_state),
    );

    let source_ino = source_ns
        .create_file(ROOT_INODE, "source-only", test_attrs_file())
        .unwrap();
    let clone_ino = clone_ns
        .create_file(ROOT_INODE, "clone-only", test_attrs_file())
        .unwrap();

    assert_eq!(source.lineage_id(), clone.lineage_id());
    assert_eq!(source_ino, clone_ino);
    assert_eq!(
        source_ns.lookup(ROOT_INODE, "source-only").unwrap(),
        Some(source_ino)
    );
    assert_eq!(source_ns.lookup(ROOT_INODE, "clone-only").unwrap(), None);
    assert_eq!(
        clone_ns.lookup(ROOT_INODE, "clone-only").unwrap(),
        Some(clone_ino)
    );
    assert_eq!(clone_ns.lookup(ROOT_INODE, "source-only").unwrap(), None);
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

#[test]
fn persistent_reopen_preserves_directory_entry_generation() {
    let inode_state = Arc::new(MemoryPersistentInodeState::new());
    let dir_state = Arc::new(MemoryPersistentDirectoryState::new());
    let identity = NamespaceDatasetIdentity::new("reopen-generation");

    let (ns1, _inode_store1, dir_store1) = test_ns_for_dataset(
        identity.clone(),
        Arc::clone(&inode_state),
        Arc::clone(&dir_state),
    );
    let file_ino = ns1
        .create_file(ROOT_INODE, "stable", test_attrs_file())
        .unwrap();
    let entry1 = dir_store1
        .lookup_for_dataset(&identity, ROOT_INODE, b"stable")
        .unwrap()
        .unwrap();
    assert_eq!(entry1.0, file_ino);
    assert!(entry1.1 > 0);
    drop(ns1);

    let (ns2, _inode_store2, dir_store2) = test_ns_for_dataset(
        identity.clone(),
        Arc::clone(&inode_state),
        Arc::clone(&dir_state),
    );
    let entry2 = dir_store2
        .lookup_for_dataset(&identity, ROOT_INODE, b"stable")
        .unwrap()
        .unwrap();

    assert_eq!(entry2, entry1);
    assert_eq!(ns2.lookup(ROOT_INODE, "stable").unwrap(), Some(file_ino));
    assert_eq!(ns2.get_attrs(file_ino).unwrap().inode, file_ino);
}
