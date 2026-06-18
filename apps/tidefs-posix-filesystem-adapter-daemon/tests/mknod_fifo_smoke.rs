// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mounted FUSE integration tests for mknod FIFO creation through the VFS adapter.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;

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
        "tidefs-mknod-fifo-smoke-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-mknod-fifo-smoke".to_string()),
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

struct UmaskGuard {
    previous: libc::mode_t,
}

impl UmaskGuard {
    fn set(mask: libc::mode_t) -> Self {
        let previous = unsafe { libc::umask(mask) };
        Self { previous }
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        unsafe {
            libc::umask(self.previous);
        }
    }
}

fn mknod_fifo(path: &Path, mode: libc::mode_t) -> io::Result<()> {
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains nul byte"))?;
    let result = unsafe { libc::mknod(cpath.as_ptr(), libc::S_IFIFO | mode, 0) };
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
fn mknod_fifo_creates_visible_directory_entry() {
    let _guard = test_lock();
    let mount = MountedVfs::new();
    let pipe = mount.path("/visible-pipe");

    mknod_fifo(&pipe, 0o644).expect("mknod FIFO through FUSE mount");

    let entry = fs::read_dir(&mount.mount)
        .expect("read mount root")
        .find_map(|entry| {
            let entry = entry.expect("directory entry");
            (entry.file_name().as_bytes() == b"visible-pipe").then_some(entry)
        })
        .expect("visible-pipe directory entry");
    assert!(entry.file_type().expect("entry file type").is_fifo());
}

#[test]
fn mknod_fifo_has_correct_metadata() {
    let _guard = test_lock();
    let mount = MountedVfs::new();
    let pipe = mount.path("/metadata-pipe");
    let _umask = UmaskGuard::set(0);

    mknod_fifo(&pipe, 0o660).expect("mknod FIFO through FUSE mount");

    let metadata = fs::metadata(&pipe).expect("FIFO metadata");
    assert!(metadata.file_type().is_fifo());
    assert_eq!(metadata.mode() & libc::S_IFMT, libc::S_IFIFO);
    assert_eq!(metadata.mode() & 0o777, 0o660);
    assert_eq!(metadata.len(), 0);
    metadata.accessed().expect("FIFO access time");
    metadata.modified().expect("FIFO modified time");
}

#[test]
fn mknod_fifo_duplicate_name_returns_eexist() {
    let _guard = test_lock();
    let mount = MountedVfs::new();
    let pipe = mount.path("/duplicate-pipe");
    mknod_fifo(&pipe, 0o644).expect("create initial FIFO");

    let err = mknod_fifo(&pipe, 0o644).expect_err("duplicate FIFO should fail");

    assert_raw_errno(&err, libc::EEXIST);
}

#[test]
fn mknod_fifo_under_nonexistent_parent_returns_enoent() {
    let _guard = test_lock();
    let mount = MountedVfs::new();
    let pipe = mount.path("/missing-parent/pipe");

    let err = mknod_fifo(&pipe, 0o644).expect_err("mknod under missing parent should fail");

    assert_raw_errno(&err, libc::ENOENT);
}

#[test]
fn mknod_fifo_default_mode_respects_umask() {
    let _guard = test_lock();
    let mount = MountedVfs::new();
    let pipe = mount.path("/umask-pipe");
    let _umask = UmaskGuard::set(0o027);

    mknod_fifo(&pipe, 0o666).expect("mknod FIFO with custom umask");

    let metadata = fs::metadata(&pipe).expect("FIFO metadata");
    assert!(metadata.file_type().is_fifo());
    assert_eq!(metadata.mode() & 0o777, 0o640);
}
