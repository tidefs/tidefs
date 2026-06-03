//! Mounted FUSE integration tests for open/release file handle lifecycle.

use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{IntoRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;
use tidefs_types_vfs_core::RequestCtx;
use tidefs_vfs_engine::VfsEngine;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn serial_test_guard() -> MutexGuard<'static, ()> {
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
        "tidefs-open-release-smoke-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-open-release-smoke".to_string()),
        fuser::MountOption::RW,
        fuser::MountOption::NoDev,
        fuser::MountOption::NoSuid,
        fuser::MountOption::Subtype("tidefs".to_string()),
    ]
}

fn request_ctx() -> RequestCtx {
    let gid = unsafe { libc::getegid() } as u32;
    RequestCtx {
        uid: unsafe { libc::geteuid() } as u32,
        gid,
        pid: std::process::id(),
        umask: 0o022,
        groups: vec![gid],
    }
}

struct MountedVfs {
    root: PathBuf,
    mount: PathBuf,
    session: Option<fuser::BackgroundSession>,
}

impl MountedVfs {
    fn new_with_seed(seed: impl FnOnce(&VfsLocalFileSystem)) -> Self {
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
        seed(&engine);
        let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create FUSE VFS adapter");
        let session = fuser::spawn_mount2(adapter, &mount, &mount_options()).expect("mount FUSE");

        Self {
            root,
            mount,
            session: Some(session),
        }
    }

    fn new() -> Self {
        Self::new_with_seed(|_| {})
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

fn seed_file(engine: &VfsLocalFileSystem, name: &[u8], payload: &[u8]) {
    let ctx = request_ctx();
    let root = engine.get_root_inode(&ctx).expect("root inode");
    let (_attr, fh) = engine
        .create(root, name, 0o644, 0, &ctx)
        .expect("create open/release fixture");
    engine
        .write(&fh, 0, payload, &ctx)
        .expect("write open/release fixture");
}

fn assert_raw_errno(err: &io::Error, expected: i32) {
    assert_eq!(
        err.raw_os_error(),
        Some(expected),
        "unexpected error: {err}"
    );
}

fn assert_errno<T: std::fmt::Debug>(result: io::Result<T>, expected: i32, context: &str) {
    let err = result.expect_err(context);
    assert_raw_errno(&err, expected);
}

fn path_cstring(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("path should not contain nul")
}

fn close_fd(fd: RawFd) -> io::Result<()> {
    let result = unsafe { libc::close(fd) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    let result = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

fn write_fd(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    let result = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

fn open_dir_for_write(path: &Path) -> io::Result<RawFd> {
    let cpath = path_cstring(path);
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

#[test]
fn open_readonly_returns_readable_handle_and_rejects_write() {
    let _guard = serial_test_guard();
    let mount = MountedVfs::new_with_seed(|engine| {
        seed_file(engine, b"readonly.txt", b"readonly payload");
    });
    let path = mount.path("/readonly.txt");
    let mut file = OpenOptions::new()
        .read(true)
        .open(&path)
        .expect("open existing file read-only through FUSE mount");

    let mut readback = String::new();
    file.read_to_string(&mut readback)
        .expect("read through read-only handle");
    assert_eq!(readback, "readonly payload");
    assert_errno(
        file.write_all(b"denied"),
        libc::EBADF,
        "write through read-only handle should fail",
    );
}

#[test]
fn open_writeonly_returns_writable_handle_and_rejects_read() {
    let _guard = serial_test_guard();
    let mount = MountedVfs::new_with_seed(|engine| {
        seed_file(engine, b"writeonly.txt", b"initial");
    });
    let path = mount.path("/writeonly.txt");
    let mut file = OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open existing file write-only through FUSE mount");

    file.write_all(b"updated")
        .expect("write through write-only handle");
    file.flush().expect("flush write-only handle");
    assert_errno(
        file.read(&mut [0_u8; 1]),
        libc::EBADF,
        "read through write-only handle should fail",
    );
}

#[test]
fn open_rdwr_returns_handle_that_can_read_and_write() {
    let _guard = serial_test_guard();
    let mount = MountedVfs::new_with_seed(|engine| {
        seed_file(engine, b"rdwr.txt", b"alpha");
    });
    let path = mount.path("/rdwr.txt");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("open existing file read-write through FUSE mount");

    let mut first = [0_u8; 5];
    file.read_exact(&mut first)
        .expect("read through read-write handle");
    assert_eq!(&first, b"alpha");
    file.seek(SeekFrom::Start(0)).expect("seek to start");
    file.write_all(b"omega")
        .expect("write through read-write handle");
    file.flush().expect("flush read-write handle");

    assert_eq!(fs::read(&path).expect("read updated file"), b"omega");
}

#[test]
fn create_and_exclusive_open_report_expected_results() {
    let _guard = serial_test_guard();
    let mount = MountedVfs::new();
    let created = mount.path("/created.txt");
    let missing = mount.path("/missing.txt");

    {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&created)
            .expect("create new file through FUSE mount");
        file.write_all(b"created by open")
            .expect("write newly created file");
    }

    assert_eq!(
        fs::read(&created).expect("read created file"),
        b"created by open"
    );
    assert_errno(
        OpenOptions::new().read(true).open(&missing),
        libc::ENOENT,
        "open without O_CREAT should fail for a missing file",
    );
    assert_errno(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&created),
        libc::EEXIST,
        "O_CREAT|O_EXCL should fail for an existing file",
    );
}

#[test]
fn close_releases_fd_and_reuse_reports_ebadf() {
    let _guard = serial_test_guard();
    let mount = MountedVfs::new_with_seed(|engine| {
        seed_file(engine, b"released.txt", b"release me");
    });
    let path = mount.path("/released.txt");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("open file before release");
    let fd = file.into_raw_fd();

    close_fd(fd).expect("close should release the mounted file handle");

    assert_errno(
        read_fd(fd, &mut [0_u8; 1]),
        libc::EBADF,
        "read after release should fail",
    );
    assert_errno(
        write_fd(fd, b"x"),
        libc::EBADF,
        "write after release should fail",
    );
    assert_errno(
        close_fd(fd),
        libc::EBADF,
        "second close of released fd should fail",
    );
}

#[test]
fn multiple_concurrent_opens_have_independent_live_handles() {
    let _guard = serial_test_guard();
    let mount = MountedVfs::new_with_seed(|engine| {
        seed_file(engine, b"concurrent.txt", b"before");
    });
    let path = mount.path("/concurrent.txt");
    let mut first = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("open first handle");
    let mut second = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("open second handle");

    first
        .write_all(b"FIRST")
        .expect("write through first handle");
    first.flush().expect("flush first handle");
    drop(first);

    second.seek(SeekFrom::Start(0)).expect("seek second handle");
    let mut readback = [0_u8; 5];
    second
        .read_exact(&mut readback)
        .expect("second handle remains readable after first release");
    assert_eq!(&readback, b"FIRST");

    second
        .write_all(b"-second")
        .expect("second handle remains writable after first release");
    second.flush().expect("flush second handle");
    assert_eq!(
        fs::read(&path).expect("read after concurrent handles"),
        b"FIRST-second"
    );
}

#[test]
fn open_trunc_clears_existing_content() {
    let _guard = serial_test_guard();
    let mount = MountedVfs::new_with_seed(|engine| {
        seed_file(engine, b"truncate.txt", b"content before truncate");
    });
    let path = mount.path("/truncate.txt");

    let file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .expect("open with O_TRUNC through FUSE mount");

    assert_eq!(file.metadata().expect("metadata after O_TRUNC").len(), 0);
    drop(file);
    assert!(fs::read(&path).expect("read truncated file").is_empty());
}

#[test]
fn open_directory_for_write_returns_eisdir() {
    let _guard = serial_test_guard();
    let mount = MountedVfs::new();
    let dir = mount.path("/directory");
    fs::create_dir(&dir).expect("create directory through FUSE mount");

    assert_errno(
        open_dir_for_write(&dir),
        libc::EISDIR,
        "opening a directory for write should fail",
    );
}
