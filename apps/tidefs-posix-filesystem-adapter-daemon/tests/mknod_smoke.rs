//! Mounted FUSE integration tests for mknod through the VFS-backed adapter.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
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

struct UmaskRestore {
    previous: libc::mode_t,
}

impl Drop for UmaskRestore {
    fn drop(&mut self) {
        unsafe {
            libc::umask(self.previous);
        }
    }
}

fn with_umask<T>(umask: libc::mode_t, f: impl FnOnce() -> T) -> T {
    let _guard = UMASK_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let previous = unsafe { libc::umask(umask) };
    let _restore = UmaskRestore { previous };
    f()
}

fn mknod_path(path: &Path, mode: libc::mode_t, rdev: libc::dev_t) -> io::Result<()> {
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains nul byte"))?;
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

fn assert_mknod_errno(path: &Path, mode: libc::mode_t, rdev: libc::dev_t, expected: i32) {
    let err = mknod_path(path, mode, rdev).expect_err("mknod should fail");
    assert_raw_errno(&err, expected);
    assert!(
        !path.exists(),
        "failed mknod should not leave an entry at {}",
        path.display()
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
fn mknod_regular_device_and_socket_nodes_return_eopnotsupp() {
    with_umask(0, || {
        let mount = MountedVfs::new();

        assert_mknod_errno(
            &mount.path("/regular-via-mknod"),
            libc::S_IFREG | 0o640,
            0,
            libc::EOPNOTSUPP,
        );
        assert_mknod_errno(
            &mount.path("/char-device"),
            libc::S_IFCHR | 0o600,
            0x0103,
            libc::EOPNOTSUPP,
        );
        assert_mknod_errno(
            &mount.path("/block-device"),
            libc::S_IFBLK | 0o600,
            0x0800,
            libc::EOPNOTSUPP,
        );
        assert_mknod_errno(
            &mount.path("/socket-node"),
            libc::S_IFSOCK | 0o600,
            0,
            libc::EOPNOTSUPP,
        );
    });
}
