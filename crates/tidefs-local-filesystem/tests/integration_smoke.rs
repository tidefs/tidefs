// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration smoke test: object store → local filesystem → read-back → verify.
use std::env;
use std::fs;
use std::path::PathBuf;

use tidefs_local_filesystem::{
    LocalFileSystem, DEFAULT_DIRECTORY_PERMISSIONS, DEFAULT_FILE_PERMISSIONS,
};
use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

fn set_test_key() {
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn temp_dir(label: &str) -> PathBuf {
    let dir = env::temp_dir().join(format!("tidefs-smoke-{label}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn full_stack_write_sync_reopen_verify() {
    set_test_key();
    let root = temp_dir("full_stack");

    // 1. Open LocalObjectStore (creates)
    let opts = StoreOptions::test_fast();
    let store = LocalObjectStore::open_with_options(&root, opts).expect("open store");
    drop(store);

    // 2. Create LocalFileSystem on top of store
    let mut fs = LocalFileSystem::open(&root).expect("open filesystem");

    // 3. Write files and directories
    fs.create_dir("/dir1", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("mkdir dir1");
    fs.create_file("/dir1/file_a.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create file_a");
    fs.write_file("/dir1/file_a.txt", 0, b"hello world")
        .expect("write file_a");
    fs.create_dir("/dir1/sub", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("mkdir sub");
    fs.create_file("/dir1/sub/file_b.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create file_b");
    fs.write_file("/dir1/sub/file_b.txt", 0, b"nested content")
        .expect("write file_b");
    fs.create_file("/root_file.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create root_file");
    fs.write_file("/root_file.txt", 0, b"at root")
        .expect("write root_file");

    // 4. Sync to disk
    fs.sync_all().expect("sync_all");

    // 5. Reopen and verify all written data
    drop(fs);
    let reopened_fs = LocalFileSystem::open(&root).expect("reopen filesystem");

    let file_a = reopened_fs
        .read_file("/dir1/file_a.txt")
        .expect("read file_a");
    assert_eq!(String::from_utf8_lossy(&file_a), "hello world");

    let file_b = reopened_fs
        .read_file("/dir1/sub/file_b.txt")
        .expect("read file_b");
    assert_eq!(String::from_utf8_lossy(&file_b), "nested content");

    let root_file = reopened_fs
        .read_file("/root_file.txt")
        .expect("read root_file");
    assert_eq!(String::from_utf8_lossy(&root_file), "at root");

    // Verify directory listing
    let root_listing = reopened_fs.list_dir("/").expect("list_dir /");
    let root_names: Vec<String> = root_listing.iter().map(|e| e.name_lossy()).collect();
    assert!(root_names.contains(&"dir1".to_string()), "dir1 in root");
    assert!(
        root_names.contains(&"root_file.txt".to_string()),
        "root_file in root"
    );

    let dir1 = reopened_fs.list_dir("/dir1").expect("list_dir dir1");
    let dir1_names: Vec<String> = dir1.iter().map(|e| e.name_lossy()).collect();
    assert!(dir1_names.contains(&"file_a.txt".to_string()));
    assert!(dir1_names.contains(&"sub".to_string()));

    let sub = reopened_fs.list_dir("/dir1/sub").expect("list_dir sub");
    let sub_names: Vec<String> = sub.iter().map(|e| e.name_lossy()).collect();
    assert!(sub_names.contains(&"file_b.txt".to_string()));

    drop(reopened_fs);

    // Clean up
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn empty_filesystem_syncs_and_reopens() {
    set_test_key();
    let root = temp_dir("empty");

    let opts = StoreOptions::test_fast();
    let store = LocalObjectStore::open_with_options(&root, opts).expect("open store");
    drop(store);

    let mut fs = LocalFileSystem::open(&root).expect("open filesystem");
    fs.sync_all().expect("sync empty");
    drop(fs);

    let _reopened_fs = LocalFileSystem::open(&root).expect("reopen empty filesystem");

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn unlink_removes_file_and_clears_from_listing() {
    set_test_key();
    let root = temp_dir("unlink");

    let opts = StoreOptions::test_fast();
    let store = LocalObjectStore::open_with_options(&root, opts).expect("open store");
    drop(store);

    let mut fs = LocalFileSystem::open(&root).expect("open fs");
    fs.create_file("/tmp_file.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/tmp_file.txt", 0, b"temp").expect("write");
    fs.sync_all().expect("sync");

    let before = fs.list_dir("/").expect("list");
    assert!(before.iter().any(|e| e.name_lossy() == "tmp_file.txt"));

    fs.unlink("/tmp_file.txt").expect("unlink");
    fs.sync_all().expect("sync after unlink");

    let after = fs.list_dir("/").expect("list after");
    assert!(!after.iter().any(|e| e.name_lossy() == "tmp_file.txt"));

    drop(fs);
    let _ = fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// End-to-end data path: exercises the complete write → sync → reopen → verify
// pipeline across multiple file sizes, offsets, overwrites, and directory
// nesting levels.
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_data_path() {
    set_test_key();
    let root = temp_dir("e2e_data_path");

    // 1. Open LocalObjectStore
    let opts = StoreOptions::test_fast();
    let store = LocalObjectStore::open_with_options(&root, opts).expect("open store");
    drop(store);

    // 2. Create LocalFileSystem on top of store
    let mut fs = LocalFileSystem::open(&root).expect("open filesystem");

    // ── Phase 1: Write files at various offsets (sparse, aligned, unaligned) ──
    fs.create_file("/sparse.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create sparse");
    // Write at offset 0
    fs.write_file("/sparse.bin", 0, b"AAAA")
        .expect("write offset 0");
    // Write at offset 8192 (creates a hole)
    fs.write_file("/sparse.bin", 8192, b"BBBB")
        .expect("write offset 8192");
    // Write at offset 4096 (unaligned with page)
    fs.write_file("/sparse.bin", 4096, b"CCCC")
        .expect("write offset 4096");

    // ── Phase 2: Overwrite existing data ──
    fs.create_file("/overwrite.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create overwrite");
    fs.write_file("/overwrite.txt", 0, b"initial content here")
        .expect("initial write");
    // Overwrite a portion in the middle
    fs.write_file("/overwrite.txt", 8, b"UPDATED")
        .expect("overwrite middle");
    // Overwrite at the boundary
    fs.write_file("/overwrite.txt", 15, b"X")
        .expect("overwrite boundary");

    // ── Phase 3: Deeply nested directory tree ──
    fs.create_dir("/a", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("mkdir /a");
    fs.create_dir("/a/b", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("mkdir /a/b");
    fs.create_dir("/a/b/c", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("mkdir /a/b/c");
    fs.create_file("/a/b/c/deep.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create deep file");
    fs.write_file("/a/b/c/deep.txt", 0, b"deeply nested")
        .expect("write deep");

    // ── Phase 4: Empty file ──
    fs.create_file("/empty.dat", DEFAULT_FILE_PERMISSIONS)
        .expect("create empty");

    // ── Phase 5: Multiple files in a single directory ──
    fs.create_dir("/many", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("mkdir /many");
    for i in 0..10 {
        let name = format!("/many/file_{i:02}.dat");
        fs.create_file(&name, DEFAULT_FILE_PERMISSIONS)
            .expect("create numbered");
        let data = format!("data-{i:04}");
        fs.write_file(&name, 0, data.as_bytes())
            .expect("write numbered");
    }

    // ── Phase 6: Large write (multi-block) ──
    fs.create_file("/large.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create large");
    let large_data: Vec<u8> = (0..128u8).cycle().take(65536).collect();
    fs.write_file("/large.bin", 0, &large_data)
        .expect("write large");

    // ── Sync and reopen ──
    fs.sync_all().expect("sync_all");
    drop(fs);
    let reopened_fs = LocalFileSystem::open(&root).expect("reopen filesystem");

    // ── Verify Phase 1: Sparse file ──
    let sparse = reopened_fs.read_file("/sparse.bin").expect("read sparse");
    assert_eq!(&sparse[0..4], b"AAAA", "sparse offset 0");
    assert_eq!(&sparse[4096..4100], b"CCCC", "sparse offset 4096");
    assert_eq!(&sparse[8192..8196], b"BBBB", "sparse offset 8192");

    // ── Verify Phase 2: Overwrite ──
    let overwrite = reopened_fs
        .read_file("/overwrite.txt")
        .expect("read overwrite");
    // "initial content here" → "initial UPDATEDXhere"
    assert_eq!(&overwrite[0..8], b"initial ");
    assert_eq!(&overwrite[8..15], b"UPDATED");
    assert_eq!(overwrite[15], b'X');
    assert_eq!(&overwrite[16..20], b"here");

    // ── Verify Phase 3: Deep nesting ──
    let deep = reopened_fs.read_file("/a/b/c/deep.txt").expect("read deep");
    assert_eq!(String::from_utf8_lossy(&deep), "deeply nested");

    let a_list = reopened_fs.list_dir("/a").expect("list /a");
    let a_names: Vec<String> = a_list.iter().map(|e| e.name_lossy()).collect();
    assert!(a_names.contains(&"b".to_string()), "/a contains b");

    let b_list = reopened_fs.list_dir("/a/b").expect("list /a/b");
    let b_names: Vec<String> = b_list.iter().map(|e| e.name_lossy()).collect();
    assert!(b_names.contains(&"c".to_string()), "/a/b contains c");

    let c_list = reopened_fs.list_dir("/a/b/c").expect("list /a/b/c");
    let c_names: Vec<String> = c_list.iter().map(|e| e.name_lossy()).collect();
    assert!(
        c_names.contains(&"deep.txt".to_string()),
        "/a/b/c contains deep.txt"
    );

    // ── Verify Phase 4: Empty file ──
    let empty = reopened_fs.read_file("/empty.dat").expect("read empty");
    assert!(empty.is_empty(), "empty file must be empty");

    // ── Verify Phase 5: Multiple files ──
    let many_list = reopened_fs.list_dir("/many").expect("list /many");
    let many_names: Vec<String> = many_list.iter().map(|e| e.name_lossy()).collect();
    for i in 0..10 {
        let name = format!("file_{i:02}.dat");
        assert!(many_names.contains(&name), "/many contains {name}");
        let path = format!("/many/{name}");
        let content = reopened_fs.read_file(&path).expect("read numbered");
        let expected = format!("data-{i:04}");
        assert_eq!(
            String::from_utf8_lossy(&content),
            expected,
            "content of {path}"
        );
    }

    // ── Verify Phase 6: Large file ──
    let large_read = reopened_fs.read_file("/large.bin").expect("read large");
    assert_eq!(large_read.len(), 65536, "large file size");
    assert_eq!(
        &large_read[0..128],
        &large_data[0..128],
        "large file first 128 bytes"
    );
    assert_eq!(
        &large_read[65408..65536],
        &large_data[65408..65536],
        "large file last 128 bytes"
    );
    // Spot-check a middle region
    assert_eq!(
        &large_read[32000..32128],
        &large_data[32000..32128],
        "large file middle region"
    );

    // ── Root listing completeness ──
    let root_list = reopened_fs.list_dir("/").expect("list /");
    let root_names: Vec<String> = root_list.iter().map(|e| e.name_lossy()).collect();
    for expected in &[
        "sparse.bin",
        "overwrite.txt",
        "a",
        "empty.dat",
        "many",
        "large.bin",
    ] {
        assert!(
            root_names.contains(&expected.to_string()),
            "root contains {expected}"
        );
    }

    drop(reopened_fs);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn end_to_end_data_path_multiple_sync_cycles() {
    set_test_key();
    let root = temp_dir("e2e_multisync");

    let opts = StoreOptions::test_fast();
    let store = LocalObjectStore::open_with_options(&root, opts).expect("open store");
    drop(store);

    let mut fs = LocalFileSystem::open(&root).expect("open filesystem");

    // Cycle 1: create and write, then sync
    fs.create_file("/cycle.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create cycle");
    fs.write_file("/cycle.txt", 0, b"cycle-1")
        .expect("write cycle 1");
    fs.sync_all().expect("sync after cycle 1");

    // Cycle 2: overwrite and sync
    fs.write_file("/cycle.txt", 0, b"cycle-2-extra")
        .expect("write cycle 2");
    fs.sync_all().expect("sync after cycle 2");

    // Cycle 3: append (write at end) and sync
    let cur = fs.read_file("/cycle.txt").expect("read for offset");
    let offset = cur.len() as u64;
    fs.write_file("/cycle.txt", offset, b"/appended")
        .expect("write append");
    fs.sync_all().expect("sync after cycle 3");

    // Verify before drop
    let content = fs.read_file("/cycle.txt").expect("read before drop");
    assert_eq!(String::from_utf8_lossy(&content), "cycle-2-extra/appended");

    drop(fs);

    // Reopen and verify all cycles persisted
    let reopened = LocalFileSystem::open(&root).expect("reopen filesystem");
    let persisted = reopened.read_file("/cycle.txt").expect("read after reopen");
    assert_eq!(
        String::from_utf8_lossy(&persisted),
        "cycle-2-extra/appended",
        "all sync cycles must persist across reopen"
    );

    drop(reopened);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn end_to_end_data_path_rename_and_readback() {
    set_test_key();
    let root = temp_dir("e2e_rename");

    let opts = StoreOptions::test_fast();
    let store = LocalObjectStore::open_with_options(&root, opts).expect("open store");
    drop(store);

    let mut fs = LocalFileSystem::open(&root).expect("open filesystem");

    // Create and write
    fs.create_file("/original.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create original");
    fs.write_file("/original.txt", 0, b"rename me")
        .expect("write original");

    fs.create_dir("/subdir", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("mkdir subdir");

    // Rename into subdirectory
    fs.rename("/original.txt", "/subdir/renamed.txt", false)
        .expect("rename");

    fs.sync_all().expect("sync after rename");
    drop(fs);

    // Reopen and verify data survived rename
    let reopened = LocalFileSystem::open(&root).expect("reopen filesystem");

    assert!(
        reopened.read_file("/original.txt").is_err(),
        "old path must not exist"
    );
    let renamed_content = reopened
        .read_file("/subdir/renamed.txt")
        .expect("read renamed");
    assert_eq!(String::from_utf8_lossy(&renamed_content), "rename me");

    let subdir_list = reopened.list_dir("/subdir").expect("list subdir");
    let subdir_names: Vec<String> = subdir_list.iter().map(|e| e.name_lossy()).collect();
    assert!(subdir_names.contains(&"renamed.txt".to_string()));

    drop(reopened);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn write_path_fallocate_and_truncate() {
    set_test_key();
    let root = temp_dir("write_path_ft");

    let opts = StoreOptions::test_fast();
    let store = LocalObjectStore::open_with_options(&root, opts).expect("open store");
    drop(store);

    let mut fs = LocalFileSystem::open(&root).expect("open filesystem");

    // ── Phase 1: Write initial content ──
    fs.create_file("/data.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create data.bin");
    fs.write_file("/data.bin", 0, b"hello")
        .expect("write hello");
    let stat1 = fs.stat("/data.bin").expect("stat after write");
    assert_eq!(stat1.size, 5, "initial size");

    // ── Phase 2: Fallocate to extend beyond current EOF ──
    fs.fallocate_file("/data.bin", 0, 64)
        .expect("fallocate to 64");
    let stat2 = fs.stat("/data.bin").expect("stat after fallocate");
    assert_eq!(stat2.size, 64, "fallocate extends size to 64");
    // Read: first 5 bytes must be "hello", rest zero-fill
    let falloc_content = fs.read_file("/data.bin").expect("read after fallocate");
    assert_eq!(
        &falloc_content[0..5],
        b"hello",
        "first 5 bytes survive fallocate"
    );
    assert!(
        falloc_content[5..].iter().all(|&b| b == 0),
        "remainder must be zero-filled by fallocate"
    );

    // ── Phase 3: Truncate down ──
    fs.truncate_file("/data.bin", 16)
        .expect("truncate down to 16");
    let stat3 = fs.stat("/data.bin").expect("stat after truncate down");
    assert_eq!(stat3.size, 16, "truncated size down to 16");
    let trunc_content = fs.read_file("/data.bin").expect("read after truncate down");
    assert_eq!(
        &trunc_content[0..5],
        b"hello",
        "content survives truncate down"
    );
    assert_eq!(trunc_content.len(), 16, "truncated content length");
    // Remaining bytes after "hello" should be zero (from fallocate)
    assert!(
        trunc_content[5..].iter().all(|&b| b == 0),
        "tail after truncate is zero-filled"
    );

    // ── Phase 4: Truncate to larger size (zero-fill extension) ──
    fs.truncate_file("/data.bin", 32)
        .expect("truncate up to 32");
    let stat4 = fs.stat("/data.bin").expect("stat after truncate up");
    assert_eq!(stat4.size, 32, "truncate up extends to 32");
    let trunc_up = fs.read_file("/data.bin").expect("read after truncate up");
    assert_eq!(trunc_up.len(), 32, "length after truncate up");
    assert_eq!(&trunc_up[0..5], b"hello", "content survives truncate up");
    assert!(
        trunc_up[5..].iter().all(|&b| b == 0),
        "zero-fill after truncate extend"
    );

    // ── Phase 5: Write at offset beyond current EOF (sparse via write) ──
    fs.create_file("/sparse_write.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create sparse_write.bin");
    fs.write_file("/sparse_write.bin", 4096, b"beyond eof")
        .expect("write beyond EOF");
    let sparse_write = fs
        .read_file("/sparse_write.bin")
        .expect("read sparse write");
    assert_eq!(
        sparse_write.len() as u64,
        4096 + 10,
        "size after sparse write"
    );
    assert_eq!(
        &sparse_write[4096..4106],
        b"beyond eof",
        "data at offset 4096"
    );
    assert!(
        sparse_write[0..4096].iter().all(|&b| b == 0),
        "gap before offset 4096 must be zero-filled"
    );

    // ── Phase 6: Fallocate on empty file ──
    fs.create_file("/alloc_only.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create alloc_only.bin");
    fs.fallocate_file("/alloc_only.bin", 0, 1024)
        .expect("fallocate 1024 on empty file");
    let alloc_only = fs
        .read_file("/alloc_only.bin")
        .expect("read alloc_only.bin");
    assert_eq!(alloc_only.len(), 1024, "alloc_only size");
    assert!(
        alloc_only.iter().all(|&b| b == 0),
        "fallocate-only file is all zeros"
    );

    // ── Phase 7: Fallocate at non-zero offset ──
    fs.create_file("/falloc_offset.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create falloc_offset.bin");
    fs.write_file("/falloc_offset.bin", 0, b"first")
        .expect("write first");
    fs.fallocate_file("/falloc_offset.bin", 64, 32)
        .expect("fallocate 32 at offset 64");
    let falloc_off = fs
        .read_file("/falloc_offset.bin")
        .expect("read falloc_offset.bin");
    assert_eq!(falloc_off.len(), 96, "size after fallocate at offset");
    assert_eq!(&falloc_off[0..5], b"first", "original data intact");
    assert_eq!(&falloc_off[64..96], &[0u8; 32], "fallocated range is zeros");

    // ── Sync and reopen ──
    fs.sync_all().expect("sync all");
    drop(fs);
    let reopened = LocalFileSystem::open(&root).expect("reopen");

    // Verify data.bin: hello + zeros → total 32
    let r1 = reopened
        .read_file("/data.bin")
        .expect("read data.bin after reopen");
    assert_eq!(r1.len(), 32, "data.bin size after reopen");
    assert_eq!(&r1[0..5], b"hello");

    // Verify sparse_write.bin
    let r2 = reopened
        .read_file("/sparse_write.bin")
        .expect("read sparse_write.bin after reopen");
    assert_eq!(&r2[4096..4106], b"beyond eof");
    assert!(r2[0..4096].iter().all(|&b| b == 0));

    // Verify alloc_only.bin
    let r3 = reopened
        .read_file("/alloc_only.bin")
        .expect("read alloc_only.bin after reopen");
    assert_eq!(r3.len(), 1024);
    assert!(r3.iter().all(|&b| b == 0));

    // Verify falloc_offset.bin
    let r4 = reopened
        .read_file("/falloc_offset.bin")
        .expect("read falloc_offset.bin after reopen");
    assert_eq!(r4.len(), 96);
    assert_eq!(&r4[0..5], b"first");
    assert_eq!(&r4[64..96], &[0u8; 32]);

    drop(reopened);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn write_path_rename_exchange_and_readback() {
    set_test_key();
    let root = temp_dir("rename_exchange");

    let opts = StoreOptions::test_fast();
    let store = LocalObjectStore::open_with_options(&root, opts).expect("open store");
    drop(store);

    let mut fs = LocalFileSystem::open(&root).expect("open filesystem");

    // Create two files with different content
    fs.create_file("/alpha.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create alpha");
    fs.write_file("/alpha.txt", 0, b"content alpha")
        .expect("write alpha");

    fs.create_file("/bravo.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create bravo");
    fs.write_file("/bravo.txt", 0, b"content bravo")
        .expect("write bravo");

    // Atomic exchange: swap the two files
    fs.rename_exchange("/alpha.txt", "/bravo.txt")
        .expect("rename_exchange");

    fs.sync_all().expect("sync after exchange");
    drop(fs);

    // Reopen and verify content was swapped
    let reopened = LocalFileSystem::open(&root).expect("reopen filesystem");

    let alpha_content = reopened
        .read_file("/alpha.txt")
        .expect("read alpha after exchange");
    assert_eq!(String::from_utf8_lossy(&alpha_content), "content bravo");

    let bravo_content = reopened
        .read_file("/bravo.txt")
        .expect("read bravo after exchange");
    assert_eq!(String::from_utf8_lossy(&bravo_content), "content alpha");

    drop(reopened);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn statfs_lifecycle_create_write_truncate_unlink_reopen() {
    set_test_key();
    let root = temp_dir("statfs_lifecycle");

    let opts = StoreOptions::test_fast();
    let store = LocalObjectStore::open_with_options(&root, opts).expect("open store");
    drop(store);

    let mut fs = LocalFileSystem::open(&root).expect("open filesystem");

    // Phase 1: statfs on empty filesystem.
    let s0 = fs.statfs().expect("statfs on empty fs");
    assert!(s0.bsize > 0, "block size must be positive");
    assert!(s0.namelen > 0, "max name length must be positive");
    assert!(s0.blocks > 0, "total blocks must be positive");
    assert!(
        s0.bfree <= s0.blocks,
        "free blocks must fit within total blocks"
    );
    assert!(
        s0.bavail <= s0.blocks,
        "available blocks must fit within total blocks"
    );

    // Phase 2: create file, write data, statfs.
    let initial = b"hello statfs";
    fs.create_file("/life.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create life.bin");
    fs.write_file("/life.bin", 0, initial)
        .expect("write life.bin");
    let stat_after_initial = fs
        .stat("/life.bin")
        .expect("stat life.bin after initial write");
    assert_eq!(
        stat_after_initial.size,
        initial.len() as u64,
        "initial write size"
    );

    let s1 = fs.statfs().expect("statfs after create+write");
    assert_eq!(s1.bsize, s0.bsize, "block size stable");
    assert_eq!(s1.namelen, s0.namelen, "namelen stable");
    assert!(
        s1.bfree <= s1.blocks,
        "post-write free blocks within total blocks"
    );
    assert!(
        s1.bavail <= s1.blocks,
        "post-write available blocks within total blocks"
    );

    // Phase 3: append more data, statfs.
    let more_data = vec![0xAB_u8; 8192];
    fs.write_file("/life.bin", initial.len() as u64, &more_data)
        .expect("append 8 KiB to life.bin");
    let stat_after_append = fs.stat("/life.bin").expect("stat life.bin after append");
    assert_eq!(
        stat_after_append.size,
        initial.len() as u64 + more_data.len() as u64,
        "append extends file"
    );

    let s2 = fs.statfs().expect("statfs after larger write");
    assert_eq!(s2.bsize, s0.bsize, "block size unchanged after rewrite");

    // Phase 4: truncate file down, statfs.
    fs.truncate_file("/life.bin", 32)
        .expect("truncate life.bin to 32");
    let stat_after_truncate = fs.stat("/life.bin").expect("stat life.bin after truncate");
    assert_eq!(stat_after_truncate.size, 32, "truncate updates file size");

    let s3 = fs.statfs().expect("statfs after truncate");
    assert_eq!(s3.bsize, s0.bsize, "block size unchanged after truncate");

    // Phase 5: read back truncated content.
    let content = fs.read_file("/life.bin").expect("read truncated life.bin");
    assert_eq!(content.len(), 32, "truncated file length");
    assert_eq!(
        &content[0..initial.len()],
        initial,
        "original content survives append and truncate"
    );
    assert!(
        content[initial.len()..].iter().all(|&b| b == 0xAB),
        "remaining content is from second write"
    );

    // Phase 6: unlink file, statfs.
    fs.unlink("/life.bin").expect("unlink life.bin");
    assert!(
        fs.stat("/life.bin").is_err(),
        "life.bin is absent after unlink"
    );

    let s4 = fs.statfs().expect("statfs after unlink");
    assert_eq!(s4.bsize, s0.bsize, "block size unchanged after unlink");
    assert!(
        s4.bfree <= s4.blocks,
        "post-unlink free blocks within total blocks"
    );

    // Phase 7: sync, reopen, verify namespace.
    fs.sync_all().expect("sync all");
    drop(fs);

    let mut reopened = LocalFileSystem::open(&root).expect("reopen filesystem");

    let listing = reopened.list_dir("/").expect("list root after reopen");
    assert!(
        !listing.iter().any(|e| e.name_lossy() == "life.bin"),
        "life.bin must be gone after unlink + sync + reopen"
    );

    let s5 = reopened.statfs().expect("statfs after reopen");
    assert_eq!(s5.bsize, s0.bsize, "block size stable across reopen");
    assert_eq!(s5.namelen, s0.namelen, "namelen stable across reopen");

    drop(reopened);
    let _ = fs::remove_dir_all(&root);
}
