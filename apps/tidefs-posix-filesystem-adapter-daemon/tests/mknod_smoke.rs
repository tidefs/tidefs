// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mounted FUSE integration tests for mknod through the VFS-backed adapter.

use std::ffi::CString;
use std::fs;
use std::io;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_namespace::Namespace;
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;

static UMASK_LOCK: Mutex<()> = Mutex::new(());

fn unique_test_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("tidefs-mknod-smoke-{}-{nanos}", std::process::id()))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-mknod-smoke".to_string()),
        fuser::MountOption::RW,
        fuser::MountOption::Dev,
        fuser::MountOption::NoSuid,
        fuser::MountOption::NoAtime,
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
        let adapter = FuseVfsAdapter::new(Box::new(engine))
            .expect("create FUSE VFS adapter")
            .with_namespace(Arc::new(Namespace::new()));
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

struct UmaskRestore {
    previous: libc::mode_t,
}

impl Drop for UmaskRestore {
    fn drop(&mut self) {
        // SAFETY: restoring the saved scalar umask value has no pointer or fd
        // preconditions.
        unsafe {
            libc::umask(self.previous);
        }
    }
}

fn with_umask<T>(umask: libc::mode_t, f: impl FnOnce() -> T) -> T {
    let _guard = UMASK_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    // SAFETY: umask only updates the process mask from a scalar mode and
    // returns the previous value for restoration under `UMASK_LOCK`.
    let previous = unsafe { libc::umask(umask) };
    let _restore = UmaskRestore { previous };
    f()
}

fn mknod_path(path: &Path, mode: libc::mode_t, rdev: libc::dev_t) -> io::Result<()> {
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains nul byte"))?;
    // SAFETY: `cpath` is a NUL-terminated path alive for the mknod call, and
    // mode/rdev are copied scalar arguments supplied by the test.
    let result = unsafe { libc::mknod(cpath.as_ptr(), mode, rdev) };
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
fn mknod_fifo_creates_visible_fifo_with_mode() {
    with_umask(0, || {
        let mount = MountedVfs::new();
        let fifo = mount.path("/pipe");

        mknod_path(&fifo, libc::S_IFIFO | 0o660, 0).expect("mknod FIFO through FUSE mount");

        let metadata = fs::metadata(&fifo).expect("metadata for mknod FIFO");
        assert!(metadata.file_type().is_fifo());
        assert_eq!(metadata.mode() & libc::S_IFMT, libc::S_IFIFO);
        assert_eq!(metadata.mode() & 0o777, 0o660);
    });
}

#[test]
fn mknod_fifo_duplicate_name_returns_eexist() {
    with_umask(0, || {
        let mount = MountedVfs::new();
        let fifo = mount.path("/duplicate-pipe");

        mknod_path(&fifo, libc::S_IFIFO | 0o644, 0).expect("initial FIFO mknod");

        let err =
            mknod_path(&fifo, libc::S_IFIFO | 0o644, 0).expect_err("duplicate mknod should fail");
        assert_raw_errno(&err, libc::EEXIST);

        let metadata = fs::metadata(&fifo).expect("metadata for original FIFO");
        assert!(metadata.file_type().is_fifo());
    });
}

#[test]
fn mknod_special_device_nodes_preserve_rdev_and_null_is_writable() {
    with_umask(0, || {
        let mount = MountedVfs::new();
        let null = mount.path("/null");
        let disk = mount.path("/disk");
        let sock = mount.path("/sock");
        let null_rdev: libc::dev_t = 0x0103;
        let disk_rdev: libc::dev_t = 0x0801;

        mknod_path(&null, libc::S_IFCHR | 0o600, null_rdev)
            .expect("mknod char device through FUSE mount");
        let metadata = fs::metadata(&null).expect("metadata for char device");
        assert!(metadata.file_type().is_char_device());
        assert_eq!(metadata.mode() & libc::S_IFMT, libc::S_IFCHR);
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.rdev(), null_rdev);
        let mut null_file = fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(&null)
            .expect("char device rdev 1:3 should open like /dev/null");
        null_file
            .write_all(b"fred\n")
            .expect("char device rdev 1:3 should accept writes like /dev/null");
        drop(null_file);
        let metadata = fs::metadata(&null).expect("metadata after char device write");
        assert_eq!(metadata.size(), 0);

        mknod_path(&disk, libc::S_IFBLK | 0o660, disk_rdev)
            .expect("mknod block device through FUSE mount");
        let metadata = fs::metadata(&disk).expect("metadata for block device");
        assert!(metadata.file_type().is_block_device());
        assert_eq!(metadata.mode() & libc::S_IFMT, libc::S_IFBLK);
        assert_eq!(metadata.mode() & 0o777, 0o660);
        assert_eq!(metadata.rdev(), disk_rdev);

        mknod_path(&sock, libc::S_IFSOCK | 0o700, 0).expect("mknod socket through FUSE mount");
        let metadata = fs::metadata(&sock).expect("metadata for socket node");
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.mode() & libc::S_IFMT, libc::S_IFSOCK);
        assert_eq!(metadata.mode() & 0o777, 0o700);
        assert_eq!(metadata.rdev(), 0);
    });
}
