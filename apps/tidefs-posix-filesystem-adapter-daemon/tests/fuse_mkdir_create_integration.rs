// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mounted FUSE integration tests for mkdir/create through the VFS adapter.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
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
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "tidefs-mkdir-create-test-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-mkdir-create-test".to_string()),
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

fn assert_raw_errno(err: &io::Error, expected: i32) {
    assert_eq!(
        err.raw_os_error(),
        Some(expected),
        "unexpected error: {err}"
    );
}

#[test]
fn mkdir_creates_visible_directory() {
    let mnt = MountedVfs::new();
    let dir = mnt.path("/created-dir");

    fs::create_dir(&dir).expect("mkdir through FUSE mount");

    let metadata = fs::metadata(&dir).expect("metadata for created directory");
    assert!(metadata.is_dir());
}

#[test]
fn create_creates_regular_file_with_content() {
    let mnt = MountedVfs::new();
    let path = mnt.path("/created-file.txt");

    {
        let mut file = File::create_new(&path).expect("create file through FUSE mount");
        file.write_all(b"created through mounted VFS adapter\n")
            .expect("write file contents");
    }

    let metadata = fs::metadata(&path).expect("metadata for created file");
    assert!(metadata.is_file());
    assert_eq!(metadata.len(), 36);

    let mut readback = String::new();
    File::open(&path)
        .expect("open created file")
        .read_to_string(&mut readback)
        .expect("read created file");
    assert_eq!(readback, "created through mounted VFS adapter\n");
}

#[test]
fn mkdir_on_existing_name_returns_eexist() {
    let mnt = MountedVfs::new();
    let existing = mnt.path("/existing");
    File::create_new(&existing).expect("create existing regular file");

    let err = fs::create_dir(&existing).expect_err("mkdir over file should fail");

    assert_raw_errno(&err, libc::EEXIST);
}

#[test]
fn mkdir_on_existing_directory_returns_eexist_and_preserves_directory() {
    let mnt = MountedVfs::new();
    let existing = mnt.path("/existing-dir");
    fs::create_dir(&existing).expect("create existing directory through FUSE mount");

    let err = fs::create_dir(&existing).expect_err("mkdir over directory should fail");

    assert_raw_errno(&err, libc::EEXIST);
    assert!(
        fs::metadata(&existing)
            .expect("metadata for preserved directory")
            .is_dir(),
        "existing directory should survive failed duplicate mkdir"
    );
}

#[test]
fn create_in_missing_parent_returns_enoent() {
    let mnt = MountedVfs::new();
    let missing_parent_child = mnt.path("/missing-parent/child.txt");

    let err = File::create_new(&missing_parent_child)
        .expect_err("create under missing parent should fail");

    assert_raw_errno(&err, libc::ENOENT);
}

#[test]
fn mkdir_in_file_component_returns_enotdir() {
    let mnt = MountedVfs::new();
    let file = mnt.path("/plain-file");
    File::create_new(&file).expect("create regular file");
    let child = file.join("child-dir");

    let err = fs::create_dir(&child).expect_err("mkdir below regular file should fail");

    assert_raw_errno(&err, libc::ENOTDIR);
}

#[test]
fn create_with_excl_on_existing_file_returns_eexist() {
    let mnt = MountedVfs::new();
    let existing = mnt.path("/already-there.txt");
    File::create_new(&existing).expect("create existing file");

    let err = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&existing)
        .expect_err("O_CREAT|O_EXCL should fail when file exists");

    assert_raw_errno(&err, libc::EEXIST);
}
