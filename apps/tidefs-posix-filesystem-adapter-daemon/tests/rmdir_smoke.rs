// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mounted FUSE integration tests for rmdir through the VFS-backed adapter.

use std::fs::{self, File};
use std::io;
use std::os::unix::fs::MetadataExt;
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
    std::env::temp_dir().join(format!("tidefs-rmdir-smoke-{}-{nanos}", std::process::id()))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-rmdir-smoke".to_string()),
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

    fn mount_path(&self) -> &PathBuf {
        &self.mount
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
fn rmdir_empty_directory_succeeds() {
    let mnt = MountedVfs::new();
    let dir = mnt.path("/empty");

    fs::create_dir(&dir).expect("create directory through FUSE mount");
    assert!(dir.is_dir(), "directory should be visible before rmdir");

    fs::remove_dir(&dir).expect("rmdir empty directory through FUSE mount");

    assert!(!dir.exists(), "removed directory should no longer exist");
    let err = fs::metadata(&dir).expect_err("metadata for removed directory should fail");
    assert_raw_errno(&err, libc::ENOENT);
}

#[test]
fn rmdir_nonexistent_directory_returns_enoent() {
    let mnt = MountedVfs::new();
    let missing = mnt.path("/missing");

    let err = fs::remove_dir(&missing).expect_err("rmdir missing directory should fail");

    assert_raw_errno(&err, libc::ENOENT);
}

#[test]
fn rmdir_file_returns_enotdir() {
    let mnt = MountedVfs::new();
    let file = mnt.path("/regular-file");
    File::create_new(&file).expect("create regular file through FUSE mount");

    let err = fs::remove_dir(&file).expect_err("rmdir regular file should fail");

    assert_raw_errno(&err, libc::ENOTDIR);
    assert!(file.is_file(), "regular file should survive failed rmdir");
}

#[test]
fn rmdir_nonempty_directory_returns_enotempty() {
    let mnt = MountedVfs::new();
    let dir = mnt.path("/nonempty");
    let child = dir.join("child");
    fs::create_dir(&dir).expect("create parent directory through FUSE mount");
    File::create_new(&child).expect("create child file through FUSE mount");

    let err = fs::remove_dir(&dir).expect_err("rmdir non-empty directory should fail");

    assert_raw_errno(&err, libc::ENOTEMPTY);
    assert!(dir.is_dir(), "directory should survive failed rmdir");
    assert!(child.is_file(), "child should survive failed rmdir");
}

#[test]
fn rmdir_root_returns_ebusy() {
    let mnt = MountedVfs::new();

    let err = fs::remove_dir(mnt.mount_path()).expect_err("rmdir mount root should fail");

    assert_raw_errno(&err, libc::EBUSY);
    assert!(
        mnt.mount_path().is_dir(),
        "mount root should survive failed rmdir"
    );
}

#[test]
fn rmdir_then_recreate_and_stat_reports_new_inode() {
    let mnt = MountedVfs::new();
    let dir = mnt.path("/recreate");
    fs::create_dir(&dir).expect("create directory through FUSE mount");
    let first_inode = fs::metadata(&dir)
        .expect("metadata for initial directory")
        .ino();

    fs::remove_dir(&dir).expect("rmdir initial directory through FUSE mount");
    fs::create_dir(&dir).expect("recreate directory with same name through FUSE mount");

    let metadata = fs::metadata(&dir).expect("metadata for recreated directory");
    assert!(metadata.is_dir());
    assert_ne!(
        metadata.ino(),
        first_inode,
        "recreated directory should receive a fresh inode"
    );
}

#[test]
fn rmdir_then_stat_returns_enoent() {
    let mnt = MountedVfs::new();
    let dir = mnt.path("/gone");
    fs::create_dir(&dir).expect("create directory through FUSE mount");

    fs::remove_dir(&dir).expect("rmdir directory through FUSE mount");

    let err = fs::metadata(&dir).expect_err("stat removed directory should fail");
    assert_raw_errno(&err, libc::ENOENT);
}
