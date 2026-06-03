#![cfg(target_os = "linux")]

//! Mounted FUSE integration tests for RENAME_NOREPLACE through the VFS adapter.

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
        "tidefs-rename-noreplace-smoke-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-rename-noreplace-smoke".to_string()),
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

fn rename_noreplace(old_path: &Path, new_path: &Path) -> io::Result<()> {
    renameat2(old_path, new_path, RENAME_NOREPLACE)
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
fn rename_noreplace_moves_file_when_destination_absent_and_preserves_inode() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    let old_path = mnt.path("/source.txt");
    let new_path = mnt.path("/renamed.txt");
    fs::write(&old_path, b"source contents").expect("write source file");
    let before = fs::metadata(&old_path).expect("source metadata before rename");

    rename_noreplace(&old_path, &new_path)
        .expect("RENAME_NOREPLACE to absent destination through FUSE mount");

    let after = fs::metadata(&new_path).expect("destination metadata after rename");
    assert_eq!(after.ino(), before.ino());
    assert_eq!(
        fs::read(&new_path).expect("read renamed file"),
        b"source contents"
    );
    let err = fs::metadata(&old_path).expect_err("old path should be removed after rename");
    assert_raw_errno(&err, libc::ENOENT);
}

#[test]
fn rename_noreplace_existing_destination_returns_eexist_and_preserves_both_files() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    let old_path = mnt.path("/source.txt");
    let new_path = mnt.path("/existing.txt");
    fs::write(&old_path, b"source contents").expect("write source file");
    fs::write(&new_path, b"existing contents").expect("write existing file");
    let old_before = fs::metadata(&old_path).expect("source metadata before failed rename");
    let new_before = fs::metadata(&new_path).expect("existing metadata before failed rename");

    let err = rename_noreplace(&old_path, &new_path)
        .expect_err("RENAME_NOREPLACE must reject an existing destination");

    assert_raw_errno(&err, libc::EEXIST);
    let old_after = fs::metadata(&old_path).expect("source metadata after failed rename");
    let new_after = fs::metadata(&new_path).expect("existing metadata after failed rename");
    assert_eq!(old_after.ino(), old_before.ino());
    assert_eq!(new_after.ino(), new_before.ino());
    assert_eq!(
        fs::read(&old_path).expect("read source after failed rename"),
        b"source contents"
    );
    assert_eq!(
        fs::read(&new_path).expect("read destination after failed rename"),
        b"existing contents"
    );
}

#[test]
fn rename_noreplace_combined_with_exchange_returns_einval() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    let left = mnt.path("/left.txt");
    let right = mnt.path("/right.txt");
    fs::write(&left, b"left contents").expect("write left file");
    fs::write(&right, b"right contents").expect("write right file");

    let err = renameat2(&left, &right, RENAME_NOREPLACE | RENAME_EXCHANGE)
        .expect_err("combined NOREPLACE and EXCHANGE flags should fail");

    assert_raw_errno(&err, libc::EINVAL);
    assert_eq!(
        fs::read(&left).expect("read left after invalid rename"),
        b"left contents"
    );
    assert_eq!(
        fs::read(&right).expect("read right after invalid rename"),
        b"right contents"
    );
}
