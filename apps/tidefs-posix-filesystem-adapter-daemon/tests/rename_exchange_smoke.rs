// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg(target_os = "linux")]

//! Mounted FUSE integration tests for RENAME_EXCHANGE through the VFS adapter.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;

const RENAME_NOREPLACE: u32 = 1;
const RENAME_EXCHANGE: u32 = 2;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn test_lock() -> MutexGuard<'static, ()> {
    TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn unique_test_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "tidefs-rename-exchange-smoke-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-rename-exchange-smoke".to_string()),
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

fn rename_exchange(old_path: &Path, new_path: &Path) -> io::Result<()> {
    renameat2(old_path, new_path, RENAME_EXCHANGE)
}

fn renameat2(old_path: &Path, new_path: &Path, flags: u32) -> io::Result<()> {
    let old_c = CString::new(old_path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "old path contains nul byte"))?;
    let new_c = CString::new(new_path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "new path contains nul byte"))?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            old_c.as_ptr(),
            libc::AT_FDCWD,
            new_c.as_ptr(),
            flags,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
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
fn rename_exchange_swaps_regular_files_and_preserves_inodes() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    let left = mnt.path("/left.txt");
    let right = mnt.path("/right.txt");
    fs::write(&left, b"left contents").expect("write left file");
    fs::write(&right, b"right contents").expect("write right file");
    let left_before = fs::metadata(&left).expect("left metadata before exchange");
    let right_before = fs::metadata(&right).expect("right metadata before exchange");

    rename_exchange(&left, &right).expect("RENAME_EXCHANGE regular files through FUSE mount");

    let left_after = fs::metadata(&left).expect("left metadata after exchange");
    let right_after = fs::metadata(&right).expect("right metadata after exchange");
    assert_eq!(left_after.ino(), right_before.ino());
    assert_eq!(right_after.ino(), left_before.ino());
    assert_eq!(
        fs::read(&left).expect("read exchanged left"),
        b"right contents"
    );
    assert_eq!(
        fs::read(&right).expect("read exchanged right"),
        b"left contents"
    );
}

#[test]
fn rename_exchange_swaps_directories_across_parents() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    fs::create_dir(mnt.path("/a")).expect("create parent a");
    fs::create_dir(mnt.path("/b")).expect("create parent b");
    fs::create_dir(mnt.path("/a/left")).expect("create left dir");
    fs::create_dir(mnt.path("/b/right")).expect("create right dir");
    fs::create_dir(mnt.path("/a/left/left-child")).expect("create left child dir");
    fs::create_dir(mnt.path("/b/right/right-child")).expect("create right child dir");
    fs::write(mnt.path("/a/left/left-child/marker.txt"), b"left child")
        .expect("write left child marker");
    fs::write(mnt.path("/b/right/right-child/marker.txt"), b"right child")
        .expect("write right child marker");
    let left_before = fs::metadata(mnt.path("/a/left")).expect("left dir before exchange");
    let right_before = fs::metadata(mnt.path("/b/right")).expect("right dir before exchange");

    rename_exchange(&mnt.path("/a/left"), &mnt.path("/b/right"))
        .expect("RENAME_EXCHANGE directories through FUSE mount");

    let left_after = fs::metadata(mnt.path("/a/left")).expect("left dir after exchange");
    let right_after = fs::metadata(mnt.path("/b/right")).expect("right dir after exchange");
    assert_eq!(left_after.ino(), right_before.ino());
    assert_eq!(right_after.ino(), left_before.ino());
    assert_eq!(
        fs::read(mnt.path("/a/left/right-child/marker.txt")).expect("read exchanged right child"),
        b"right child"
    );
    assert_eq!(
        fs::read(mnt.path("/b/right/left-child/marker.txt")).expect("read exchanged left child"),
        b"left child"
    );
    assert_eq!(
        fs::metadata(mnt.path("/a/left/right-child/.."))
            .expect("metadata through right child parent")
            .ino(),
        left_after.ino()
    );
    assert_eq!(
        fs::metadata(mnt.path("/b/right/left-child/.."))
            .expect("metadata through left child parent")
            .ino(),
        right_after.ino()
    );
}

#[test]
fn rename_exchange_file_and_directory_returns_current_unsupported_boundary() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    let file = mnt.path("/plain-file");
    let dir = mnt.path("/plain-dir");
    fs::write(&file, b"plain file").expect("write file");
    fs::create_dir(&dir).expect("create dir");

    let err = rename_exchange(&file, &dir).expect_err("file/dir exchange should fail");

    assert_raw_errno(&err, libc::EOPNOTSUPP);
}

#[test]
fn rename_exchange_missing_source_returns_enoent() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    let missing = mnt.path("/missing.txt");
    let present = mnt.path("/present.txt");
    fs::write(&present, b"present").expect("write present file");

    let err = rename_exchange(&missing, &present).expect_err("missing source should fail");

    assert_raw_errno(&err, libc::ENOENT);
}

#[test]
fn rename_exchange_same_name_is_noop() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    let same = mnt.path("/same.txt");
    fs::write(&same, b"same contents").expect("write file");
    let before = fs::metadata(&same).expect("metadata before same-name exchange");

    rename_exchange(&same, &same).expect("same-name RENAME_EXCHANGE should succeed");

    let after = fs::metadata(&same).expect("metadata after same-name exchange");
    assert_eq!(after.ino(), before.ino());
    assert_eq!(fs::read(&same).expect("read same file"), b"same contents");
}

#[test]
fn rename_exchange_combined_with_noreplace_returns_einval() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    let left = mnt.path("/left.txt");
    let right = mnt.path("/right.txt");
    fs::write(&left, b"left").expect("write left file");
    fs::write(&right, b"right").expect("write right file");

    let err = renameat2(&left, &right, RENAME_EXCHANGE | RENAME_NOREPLACE)
        .expect_err("combined flags should fail");

    assert_raw_errno(&err, libc::EINVAL);
}
