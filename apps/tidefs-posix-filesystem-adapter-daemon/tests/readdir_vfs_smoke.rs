// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mounted FUSE integration tests for readdir/readdirplus through the VFS adapter.
//!
//! These tests mount a FuseVfsAdapter and exercise directory enumeration
//! through standard POSIX calls, verifying the dispatch_readdir and
//! dispatch_readdirplus data paths end-to-end.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;

fn unique_test_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "tidefs-readdir-vfs-smoke-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-readdir-vfs-smoke".to_string()),
        fuser::MountOption::RW,
        fuser::MountOption::NoDev,
        fuser::MountOption::NoSuid,
        fuser::MountOption::Subtype("tidefs".to_string()),
    ]
}

struct MountedVfs {
    root: PathBuf,
    mount: PathBuf,
    session: Option<fuser::BackgroundSession>,
}

impl MountedVfs {
    fn new() -> Self {
        let root = unique_test_root();
        let store = root.join("store");
        let mount = root.join("mnt");
        fs::create_dir_all(&store).expect("create store dir");
        fs::create_dir_all(&mount).expect("create mount dir");

        let filesystem = LocalFileSystem::open_with_root_authentication_key(
            &store,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open local filesystem");
        let engine = VfsLocalFileSystem::new(filesystem);
        let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create FUSE VFS adapter");
        let session = fuser::spawn_mount2(adapter, &mount, &mount_options()).expect("mount FUSE");

        Self {
            root,
            mount,
            session: Some(session),
        }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.mount.join(relative.trim_start_matches('/'))
    }
}

impl Drop for MountedVfs {
    fn drop(&mut self) {
        drop(self.session.take());
        let _ = fs::remove_dir_all(&self.root);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn readdir_vfs_empty_directory_returns_no_entries() {
    let mnt = MountedVfs::new();
    let dir = mnt.path("/empty");
    fs::create_dir(&dir).expect("create empty dir");

    let entries: Vec<String> = fs::read_dir(&dir)
        .expect("read_dir empty")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();

    assert!(
        entries.is_empty(),
        "empty dir should list no entries, got {entries:?}"
    );
}

#[test]
fn readdir_vfs_ls_la_populated_directory() {
    // Simulates `ls -la` behaviour: list entries with type, permissions,
    // size, and owner metadata all verifiable through the mount point.
    let mnt = MountedVfs::new();
    let dir = mnt.path("/populated");
    fs::create_dir(&dir).expect("create dir");

    // Create files with different modes and contents
    let specs: &[(&str, u32, &[u8])] = &[
        ("readme.txt", 0o644, b"hello world"),
        ("secret.dat", 0o600, b"classified"),
        ("script.sh", 0o755, b"#!/bin/sh\necho ok"),
        ("notes.md", 0o640, b"# Notes\nPending"),
    ];

    let mut expected_names = BTreeSet::new();
    let mut expected_sizes: Vec<(String, u64)> = Vec::new();
    let mut expected_modes: Vec<(String, u32)> = Vec::new();

    for (name, mode, data) in specs {
        let path = dir.join(name);
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(*mode)
            .open(&path)
            .expect("create file");
        f.write_all(data).expect("write data");
        f.flush().expect("flush");
        expected_names.insert(name.to_string());
        expected_sizes.push((name.to_string(), data.len() as u64));
        expected_modes.push((name.to_string(), *mode));
    }

    // Create a subdirectory
    let subdir = dir.join("subdir");
    fs::create_dir(&subdir).expect("create subdir");
    expected_names.insert("subdir".to_string());

    // Read directory entries + metadata (simulating ls -la)
    let mut found_names = BTreeSet::new();
    for entry in fs::read_dir(&dir).expect("read_dir populated") {
        let entry = entry.expect("entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        let meta = entry.metadata().expect("metadata");

        found_names.insert(name.clone());

        // Verify size for regular files
        if meta.is_file() {
            let expected = expected_sizes
                .iter()
                .find(|(n, _)| n == &name)
                .expect("known file");
            assert_eq!(
                meta.len(),
                expected.1,
                "size mismatch for {name}: expected {} got {}",
                expected.1,
                meta.len()
            );
        }

        // Verify permissions
        if let Some((_, expected_mode)) = expected_modes.iter().find(|(n, _)| n == &name) {
            assert_eq!(
                meta.mode() & 0o777,
                *expected_mode & 0o777,
                "mode mismatch for {name}"
            );
        }

        // Inode must be non-zero
        assert!(meta.ino() > 0, "inode for {name} should be non-zero");
    }

    assert_eq!(found_names, expected_names, "directory listing mismatch");
}

#[test]
fn readdir_vfs_find_recursive_traversal() {
    // Simulates `find /root-dir` recursive traversal through the VFS adapter.
    let mnt = MountedVfs::new();
    let root = mnt.path("/root-dir");
    fs::create_dir(&root).expect("create root-dir");

    // Create a nested directory structure:
    //   root-dir/
    //     a.txt
    //     sub1/
    //       b.txt
    //       sub1a/
    //         c.txt
    //     sub2/
    //       d.txt
    let a = root.join("a.txt");
    File::create(&a).expect("create a.txt");

    let sub1 = root.join("sub1");
    fs::create_dir(&sub1).expect("create sub1");
    let b = sub1.join("b.txt");
    File::create(&b).expect("create b.txt");

    let sub1a = sub1.join("sub1a");
    fs::create_dir(&sub1a).expect("create sub1a");
    let c = sub1a.join("c.txt");
    File::create(&c).expect("create c.txt");

    let sub2 = root.join("sub2");
    fs::create_dir(&sub2).expect("create sub2");
    let d = sub2.join("d.txt");
    File::create(&d).expect("create d.txt");

    // Recursive traversal (simulating find)
    let mut found_files = Vec::new();
    let mut found_dirs = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.clone()];

    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("read_dir") {
            let entry = entry.expect("entry");
            let path = entry.path();
            let ft = entry.file_type().expect("file_type");
            if ft.is_dir() {
                found_dirs.push(entry.file_name().to_string_lossy().into_owned());
                stack.push(path);
            } else if ft.is_file() {
                found_files.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }

    found_files.sort();
    found_dirs.sort();

    assert_eq!(found_files, vec!["a.txt", "b.txt", "c.txt", "d.txt"]);
    assert_eq!(found_dirs, vec!["sub1", "sub1a", "sub2"]);
}

#[test]
fn readdir_vfs_readdirplus_attributes_match_stat() {
    // Verify that attributes returned by read_dir (via readdirplus) match
    // a subsequent stat(2) call for each entry. This simulates `ls -l`
    // consistency where the kernel caches attributes from readdirplus
    // and they must agree with an explicit stat.
    let mnt = MountedVfs::new();
    let dir = mnt.path("/attr-check");
    fs::create_dir(&dir).expect("create attr-check");

    // Create files with varying sizes
    let file_specs: &[(&str, &[u8])] = &[
        ("small.bin", b"abc"),
        ("medium.bin", &[0xAAu8; 4096]),
        ("large.bin", &[0xBBu8; 16384]),
    ];

    for (name, data) in file_specs {
        let path = dir.join(name);
        let mut f = File::create(&path).expect("create file");
        f.write_all(data).expect("write");
        f.flush().expect("flush");
    }

    // Create a subdirectory and a symlink
    let subdir = dir.join("sub");
    fs::create_dir(&subdir).expect("create subdir");
    let symlink = dir.join("link_to_small");
    std::os::unix::fs::symlink("small.bin", &symlink).expect("create symlink");

    // Read directory and compare attrs with stat
    for entry in fs::read_dir(&dir).expect("read_dir attr-check") {
        let entry = entry.expect("entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        let readdir_meta = entry.metadata().expect("readdir metadata");
        let stat_meta = fs::metadata(entry.path()).expect("explicit stat");

        assert_eq!(
            readdir_meta.ino(),
            stat_meta.ino(),
            "inode mismatch for {name}: readdir={} stat={}",
            readdir_meta.ino(),
            stat_meta.ino()
        );
        assert_eq!(
            readdir_meta.mode(),
            stat_meta.mode(),
            "mode mismatch for {name}"
        );
        assert_eq!(
            readdir_meta.len(),
            stat_meta.len(),
            "size mismatch for {name}"
        );
        assert_eq!(
            readdir_meta.nlink(),
            stat_meta.nlink(),
            "nlink mismatch for {name}"
        );
        assert_eq!(
            readdir_meta.file_type().is_dir(),
            stat_meta.file_type().is_dir(),
            "dir-type mismatch for {name}"
        );
        assert_eq!(
            readdir_meta.file_type().is_file(),
            stat_meta.file_type().is_file(),
            "file-type mismatch for {name}"
        );
        assert_eq!(
            readdir_meta.file_type().is_symlink(),
            stat_meta.file_type().is_symlink(),
            "symlink-type mismatch for {name}"
        );
    }

    // Verify specific sizes for the known files
    for (name, data) in file_specs {
        let entry_path = dir.join(name);
        let meta = fs::metadata(&entry_path).expect("stat known file");
        assert_eq!(
            meta.len(),
            data.len() as u64,
            "size mismatch for {name}: expected {} got {}",
            data.len(),
            meta.len()
        );
    }
}

#[test]
fn readdir_vfs_readdirplus_inode_consistency_with_getattr() {
    // Verify that inode numbers returned from readdirplus are consistent
    // with subsequent getattr calls, including after file creation.
    let mnt = MountedVfs::new();
    let dir = mnt.path("/inode-consistency");
    fs::create_dir(&dir).expect("create dir");

    // Create files and collect inode numbers from readdir
    let mut file_inodes: Vec<(String, u64)> = Vec::new();
    for i in 0..5 {
        let name = format!("file_{i}.txt");
        let path = dir.join(&name);
        File::create(&path).expect("create file");
        file_inodes.push((name, 0));
    }

    // Now stat each file through the mount to get real inode numbers
    for (name, inode_ref) in &mut file_inodes {
        let path = dir.join(name.as_str());
        let meta = fs::metadata(&path).expect("stat file");
        *inode_ref = meta.ino();
        assert!(*inode_ref > 0, "inode for {name} should be non-zero");
    }

    // All inode numbers should be distinct across different files
    let inodes: BTreeSet<u64> = file_inodes.iter().map(|(_, ino)| *ino).collect();
    assert_eq!(
        inodes.len(),
        file_inodes.len(),
        "each file should have a unique inode"
    );

    // Re-stat through readdir and verify inodes match
    for entry in fs::read_dir(&dir).expect("read_dir") {
        let entry = entry.expect("entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        let readdir_ino = entry.metadata().expect("readdir meta").ino();
        let expected = file_inodes
            .iter()
            .find(|(n, _)| n == &name)
            .expect("known file");
        assert_eq!(
            readdir_ino, expected.1,
            "inode mismatch for {name} via readdir: expected {} got {}",
            expected.1, readdir_ino
        );
    }
}

#[test]
fn readdir_vfs_large_directory_offset_continuation() {
    // Verify that a directory with many entries is fully enumerable,
    // exercising the offset-continuation / pagination path.
    let mnt = MountedVfs::new();
    let dir = mnt.path("/large");
    fs::create_dir(&dir).expect("create large dir");

    const COUNT: usize = 100;
    let mut expected = BTreeSet::new();
    for i in 0..COUNT {
        let name = format!("entry_{i:04}.dat");
        let path = dir.join(&name);
        File::create(&path).expect("create entry");
        expected.insert(name);
    }

    let mut found = BTreeSet::new();
    for entry in fs::read_dir(&dir).expect("read_dir large") {
        let entry = entry.expect("entry");
        found.insert(entry.file_name().to_string_lossy().into_owned());
    }

    assert_eq!(found.len(), COUNT);
    assert_eq!(found, expected);
}

#[test]
fn readdir_vfs_readdir_on_file_returns_enotdir() {
    // readdir on a regular file path should fail with ENOTDIR.
    let mnt = MountedVfs::new();
    let file = mnt.path("/not-a-dir.txt");
    File::create(&file).expect("create file");

    let result = fs::read_dir(&file);
    assert!(result.is_err(), "read_dir on a file should fail");
    let err = result.unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOTDIR),
        "expected ENOTDIR, got {err:?}"
    );
}

#[test]
fn readdir_vfs_readdir_after_unlink_excludes_entry() {
    // Entries removed via unlink should not appear in subsequent readdir.
    let mnt = MountedVfs::new();
    let dir = mnt.path("/unlink-test");
    fs::create_dir(&dir).expect("create dir");

    let keep = dir.join("keep.txt");
    let remove = dir.join("remove.txt");
    File::create(&keep).expect("create keep");
    File::create(&remove).expect("create remove");

    // Verify both entries visible before unlink
    let before: BTreeSet<String> = fs::read_dir(&dir)
        .expect("read_dir before")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert!(before.contains("keep.txt"));
    assert!(before.contains("remove.txt"));

    // Unlink and verify only keep.txt remains
    fs::remove_file(&remove).expect("unlink remove");
    let after: BTreeSet<String> = fs::read_dir(&dir)
        .expect("read_dir after")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert!(after.contains("keep.txt"));
    assert!(!after.contains("remove.txt"));
    assert_eq!(after.len(), 1);
}

#[test]
fn readdir_vfs_mixed_entry_types_correct_file_type() {
    // Verify file_type() from read_dir correctly distinguishes file, dir, symlink.
    let mnt = MountedVfs::new();
    let dir = mnt.path("/types");
    fs::create_dir(&dir).expect("create dir");

    // Regular file
    File::create(dir.join("regular")).expect("create regular");

    // Subdirectory
    fs::create_dir(dir.join("nested")).expect("create nested");

    // Symlink
    std::os::unix::fs::symlink("regular", dir.join("symlink")).expect("create symlink");

    for entry in fs::read_dir(&dir).expect("read_dir types") {
        let entry = entry.expect("entry");
        let ft = entry.file_type().expect("file_type");
        match entry.file_name().to_str().unwrap() {
            "regular" => assert!(ft.is_file()),
            "nested" => assert!(ft.is_dir()),
            "symlink" => assert!(ft.is_symlink()),
            other => panic!("unexpected entry: {other}"),
        }
    }
}
