use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_dir_index::{DatasetDirPolicy, DirIndex};
use tidefs_local_filesystem::{
    vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem, RootAuthenticationKey,
};
use tidefs_local_object_store::StoreOptions;
use tidefs_posix_filesystem_adapter_daemon::reply::pack_dirent;
use tidefs_posix_filesystem_adapter_daemon::workers_ns::handle_readdir;
use tidefs_types_vfs_core::{InodeId, NodeKind, RequestCtx};
use tidefs_vfs_engine::VfsEngine;

#[derive(Debug, Eq, PartialEq)]
struct PackedEntry {
    name: String,
    ino: u64,
    off: u64,
    wire_size: usize,
}

fn ctx() -> RequestCtx {
    RequestCtx {
        uid: 1000,
        gid: 1000,
        pid: 1,
        umask: 0o022,
        groups: vec![1000],
    }
}

fn unique_test_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "tidefs-readdir-smoke-{}-{nanos}",
        std::process::id()
    ))
}

fn open_engine(root: &PathBuf) -> VfsLocalFileSystem {
    fs::create_dir_all(root).expect("create root");
    let fs = LocalFileSystem::open_with_root_authentication_key(
        root,
        StoreOptions::test_fast(),
        RootAuthenticationKey::demo_key(),
    )
    .expect("open filesystem");
    VfsLocalFileSystem::new(fs)
}

fn dir_index_kind(kind: NodeKind) -> u32 {
    match kind {
        NodeKind::Dir => 0,
        NodeKind::File => 1,
        NodeKind::Symlink => 2,
        NodeKind::CharDev => 3,
        NodeKind::BlockDev => 4,
        NodeKind::Fifo => 5,
        NodeKind::Socket => 6,
        NodeKind::Whiteout => 7,
    }
}

fn fuse_dtype(kind: u32) -> u32 {
    match kind {
        0 => 4,
        1 => 8,
        2 => 10,
        3 => 2,
        4 => 6,
        5 => 1,
        6 => 12,
        _ => 0,
    }
}

fn index_from_vfs_entries(
    entries: &[tidefs_types_vfs_core::DirEntry],
) -> (DirIndex, BTreeMap<Vec<u8>, InodeId>) {
    let mut index = DirIndex::new(1, DatasetDirPolicy::DEFAULT);
    let mut inodes = BTreeMap::new();
    for entry in entries {
        index
            .insert(
                &entry.name,
                entry.inode_id.get(),
                entry.generation.get(),
                dir_index_kind(entry.kind),
            )
            .expect("insert dir-index entry");
        inodes.insert(entry.name.clone(), entry.inode_id);
    }
    (index, inodes)
}

fn pack_readdir_page(index: &DirIndex, offset: u64, max_bytes: usize) -> (Vec<PackedEntry>, u64) {
    let (entries, worker_next_offset) = handle_readdir(index, offset, usize::MAX);
    let mut used = 0usize;
    let mut packed = Vec::new();

    for entry in &entries {
        let (wire, wire_size) = pack_dirent(
            entry.inode_id,
            entry.cookie,
            fuse_dtype(entry.kind),
            entry.name.as_bytes(),
        );
        if used + wire_size > max_bytes {
            break;
        }
        used += wire_size;
        packed.push(PackedEntry {
            name: String::from_utf8(entry.name.as_bytes().to_vec()).expect("utf8 name"),
            ino: wire.ino,
            off: wire.off,
            wire_size,
        });
    }

    let next_offset = if packed.len() < entries.len() {
        packed.last().map_or(0, |entry| entry.off)
    } else {
        worker_next_offset
    };
    (packed, next_offset)
}

#[test]
fn readdir_smoke_pages_ordered_vfs_entries_into_fuse_dirents() {
    let root_path = unique_test_root();
    let engine = open_engine(&root_path);
    let ctx = ctx();
    let root = engine.get_root_inode(&ctx).expect("root inode");
    let parent = engine
        .mkdir(root, b"paged", 0o755, &ctx)
        .expect("create parent dir");

    let created = [
        b"file_003.txt".as_slice(),
        b"file_001.txt".as_slice(),
        b"file_005.txt".as_slice(),
        b"file_002.txt".as_slice(),
        b"file_004.txt".as_slice(),
    ];
    let mut expected_inodes = BTreeMap::new();
    for name in created {
        let (attr, _fh) = engine
            .create(parent.inode_id, name, 0o644, 0, &ctx)
            .expect("create child");
        expected_inodes.insert(name.to_vec(), attr.inode_id.get());
    }

    let dh = engine.opendir(parent.inode_id, &ctx).expect("opendir");
    let (vfs_entries, has_more) = engine.readdir(&dh, 0, &ctx).expect("vfs readdir");
    assert!(!has_more);
    assert_eq!(vfs_entries.len(), 5);

    let (index, indexed_inodes) = index_from_vfs_entries(&vfs_entries);
    assert_eq!(indexed_inodes.len(), expected_inodes.len());

    let (page1, off1) = pack_readdir_page(&index, 0, 96);
    let (page2, off2) = pack_readdir_page(&index, off1, 96);
    let (page3, off3) = pack_readdir_page(&index, off2, 96);

    assert_eq!(
        page1
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        vec!["file_001.txt", "file_002.txt"]
    );
    assert_eq!(
        page2
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        vec!["file_003.txt", "file_004.txt"]
    );
    assert_eq!(
        page3
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        vec!["file_005.txt"]
    );

    let all_pages = page1
        .iter()
        .chain(page2.iter())
        .chain(page3.iter())
        .collect::<Vec<&PackedEntry>>();
    assert_eq!(all_pages.len(), 5);
    for (idx, entry) in all_pages.iter().enumerate() {
        let expected_name = format!("file_{:03}.txt", idx + 1);
        assert_eq!(entry.name, expected_name);
        assert_eq!(entry.ino, expected_inodes[expected_name.as_bytes()]);
        assert_eq!(entry.off, (idx + 1) as u64);
        assert!(entry.wire_size <= 96);
    }
    assert_eq!(off1, 2);
    assert_eq!(off2, 4);
    assert_eq!(off3, 0);

    let empty = engine
        .mkdir(root, b"empty", 0o755, &ctx)
        .expect("create empty dir");
    let empty_dh = engine.opendir(empty.inode_id, &ctx).expect("opendir empty");
    let (empty_entries, empty_has_more) = engine
        .readdir(&empty_dh, 0, &ctx)
        .expect("readdir empty dir");
    assert!(empty_entries.is_empty());
    assert!(!empty_has_more);
    let (empty_index, _) = index_from_vfs_entries(&empty_entries);
    let (packed_empty, empty_next) = pack_readdir_page(&empty_index, 0, 96);
    assert!(packed_empty.is_empty());
    assert_eq!(empty_next, 0);

    engine.releasedir(&empty_dh).expect("release empty dir");
    engine.releasedir(&dh).expect("release dir");
    let _ = fs::remove_dir_all(root_path);
}
