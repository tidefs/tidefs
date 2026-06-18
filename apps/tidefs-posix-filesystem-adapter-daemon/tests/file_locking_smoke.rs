// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mounted FUSE integration tests for POSIX file locking through the VFS adapter.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, MutexGuard,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
        "tidefs-file-locking-smoke-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-file-locking-smoke".to_string()),
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

struct ChildLock {
    pid: libc::pid_t,
    release_write_fd: libc::c_int,
    reaped: bool,
}

impl ChildLock {
    fn release_and_wait(&mut self) {
        if self.reaped {
            return;
        }
        let byte = [1u8];
        unsafe {
            let _ = libc::write(self.release_write_fd, byte.as_ptr().cast(), byte.len());
            let _ = libc::close(self.release_write_fd);
        }
        let mut status = 0;
        unsafe {
            let _ = libc::waitpid(self.pid, &mut status, 0);
        }
        self.reaped = true;
    }
}

impl Drop for ChildLock {
    fn drop(&mut self) {
        self.release_and_wait();
    }
}

fn open_read_write(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open lock target read/write")
}

fn lock_file(file: &File, lock_type: libc::c_short, start: i64, len: i64) -> io::Result<()> {
    set_lock_fd(file.as_raw_fd(), lock_type, start, len)
}

fn unlock_file(file: &File, start: i64, len: i64) -> io::Result<()> {
    lock_file(file, libc::F_UNLCK as libc::c_short, start, len)
}

fn get_lock(
    file: &File,
    lock_type: libc::c_short,
    start: i64,
    len: i64,
) -> io::Result<libc::flock> {
    let mut lock = flock(lock_type, start, len);
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut lock) };
    if result == 0 {
        Ok(lock)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn set_lock_fd(fd: libc::c_int, lock_type: libc::c_short, start: i64, len: i64) -> io::Result<()> {
    let lock = flock(lock_type, start, len);
    let result = unsafe { libc::fcntl(fd, libc::F_SETLK, &lock) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn setlkw_fd(fd: libc::c_int, lock_type: libc::c_short, start: i64, len: i64) -> io::Result<()> {
    let lock = flock(lock_type, start, len);
    loop {
        let result = unsafe { libc::fcntl(fd, libc::F_SETLKW, &lock) };
        if result == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(err);
        }
    }
}

fn setlkw_in_thread(
    fd: libc::c_int,
    lock_type: libc::c_short,
    start: i64,
    len: i64,
) -> (Arc<AtomicBool>, thread::JoinHandle<io::Result<()>>) {
    let acquired = Arc::new(AtomicBool::new(false));
    let acquired_clone = Arc::clone(&acquired);
    let handle = thread::spawn(move || {
        let result = setlkw_fd(fd, lock_type, start, len);
        acquired_clone.store(result.is_ok(), Ordering::SeqCst);
        result
    });
    (acquired, handle)
}

fn flock(lock_type: libc::c_short, start: i64, len: i64) -> libc::flock {
    libc::flock {
        l_type: lock_type,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: start as libc::off_t,
        l_len: len as libc::off_t,
        l_pid: 0,
    }
}

fn spawn_child_holding_lock(
    path: &Path,
    lock_type: libc::c_short,
    start: i64,
    len: i64,
) -> io::Result<ChildLock> {
    let path = c_path(path)?;
    let mut ready_pipe = [-1; 2];
    let mut release_pipe = [-1; 2];
    pipe(&mut ready_pipe)?;
    pipe(&mut release_pipe)?;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let err = io::Error::last_os_error();
        close_fd(ready_pipe[0]);
        close_fd(ready_pipe[1]);
        close_fd(release_pipe[0]);
        close_fd(release_pipe[1]);
        return Err(err);
    }

    if pid == 0 {
        close_fd(ready_pipe[0]);
        close_fd(release_pipe[1]);
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        let errno = if fd < 0 {
            errno()
        } else {
            let result = child_set_lock_fd(fd, lock_type, start, len);
            if result == 0 {
                write_i32_fd(ready_pipe[1], 0);
                let mut byte = [0u8; 1];
                let _ = unsafe { libc::read(release_pipe[0], byte.as_mut_ptr().cast(), 1) };
                0
            } else {
                result
            }
        };
        if errno != 0 {
            write_i32_fd(ready_pipe[1], errno);
        }
        if fd >= 0 {
            close_fd(fd);
        }
        close_fd(ready_pipe[1]);
        close_fd(release_pipe[0]);
        unsafe {
            libc::_exit(if errno == 0 { 0 } else { 1 });
        }
    }

    close_fd(ready_pipe[1]);
    close_fd(release_pipe[0]);
    let errno = read_i32_fd(ready_pipe[0]);
    close_fd(ready_pipe[0]);
    if errno == 0 {
        Ok(ChildLock {
            pid,
            release_write_fd: release_pipe[1],
            reaped: false,
        })
    } else {
        close_fd(release_pipe[1]);
        let mut status = 0;
        unsafe {
            let _ = libc::waitpid(pid, &mut status, 0);
        }
        Err(io::Error::from_raw_os_error(errno))
    }
}

fn child_lock_attempt(
    path: &Path,
    lock_type: libc::c_short,
    start: i64,
    len: i64,
) -> io::Result<()> {
    let path = c_path(path)?;
    let mut result_pipe = [-1; 2];
    pipe(&mut result_pipe)?;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let err = io::Error::last_os_error();
        close_fd(result_pipe[0]);
        close_fd(result_pipe[1]);
        return Err(err);
    }

    if pid == 0 {
        close_fd(result_pipe[0]);
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        let errno = if fd < 0 {
            errno()
        } else {
            child_set_lock_fd(fd, lock_type, start, len)
        };
        write_i32_fd(result_pipe[1], errno);
        if fd >= 0 {
            close_fd(fd);
        }
        close_fd(result_pipe[1]);
        unsafe {
            libc::_exit(if errno == 0 { 0 } else { 1 });
        }
    }

    close_fd(result_pipe[1]);
    let errno = read_i32_fd(result_pipe[0]);
    close_fd(result_pipe[0]);
    let mut status = 0;
    unsafe {
        let _ = libc::waitpid(pid, &mut status, 0);
    }
    if errno == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(errno))
    }
}

fn child_lock_attempt_until_success(
    path: &Path,
    lock_type: libc::c_short,
    start: i64,
    len: i64,
) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut last_error = None;
    while Instant::now() < deadline {
        match child_lock_attempt(path, lock_type, start, len) {
            Ok(()) => return Ok(()),
            Err(err) if matches!(err.raw_os_error(), Some(libc::EAGAIN | libc::EACCES)) => {
                last_error = Some(err);
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::from_raw_os_error(libc::ETIMEDOUT)))
}

fn child_set_lock_fd(fd: libc::c_int, lock_type: libc::c_short, start: i64, len: i64) -> i32 {
    let lock = flock(lock_type, start, len);
    let result = unsafe { libc::fcntl(fd, libc::F_SETLK, &lock) };
    if result == 0 {
        0
    } else {
        errno()
    }
}

fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains nul byte"))
}

fn pipe(fds: &mut [libc::c_int; 2]) -> io::Result<()> {
    let result = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn write_i32_fd(fd: libc::c_int, value: i32) {
    let bytes = value.to_ne_bytes();
    let mut written = 0;
    while written < bytes.len() {
        let result = unsafe {
            libc::write(
                fd,
                bytes[written..].as_ptr().cast(),
                bytes.len().saturating_sub(written),
            )
        };
        if result <= 0 {
            break;
        }
        written += result as usize;
    }
}

fn read_i32_fd(fd: libc::c_int) -> i32 {
    let mut bytes = [0u8; std::mem::size_of::<i32>()];
    let mut read = 0;
    while read < bytes.len() {
        let result = unsafe {
            libc::read(
                fd,
                bytes[read..].as_mut_ptr().cast(),
                bytes.len().saturating_sub(read),
            )
        };
        if result <= 0 {
            return libc::EIO;
        }
        read += result as usize;
    }
    i32::from_ne_bytes(bytes)
}

fn close_fd(fd: libc::c_int) {
    if fd >= 0 {
        unsafe {
            let _ = libc::close(fd);
        }
    }
}

fn errno() -> i32 {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

fn assert_conflict_errno(err: &io::Error) {
    assert!(
        matches!(err.raw_os_error(), Some(libc::EAGAIN | libc::EACCES)),
        "unexpected lock conflict error: {err}"
    );
}

#[test]
fn getlk_reports_child_write_lock_conflict() {
    let _guard = test_lock();
    let mount = MountedVfs::new();
    let path = mount.path("/locked-file");
    fs::write(&path, b"lock target").expect("create lock target");
    let file = open_read_write(&path);
    let mut child = spawn_child_holding_lock(&path, libc::F_WRLCK as libc::c_short, 0, 128)
        .expect("child write lock");

    let conflict = get_lock(&file, libc::F_WRLCK as libc::c_short, 64, 16).expect("getlk");

    assert_eq!(conflict.l_type, libc::F_WRLCK as libc::c_short);
    assert_eq!(conflict.l_start, 0);
    assert_eq!(conflict.l_len, 128);
    assert_eq!(conflict.l_pid, child.pid);

    child.release_and_wait();
}

#[test]
fn conflicting_write_lock_returns_eagain_until_child_unlocks() {
    let _guard = test_lock();
    let mount = MountedVfs::new();
    let path = mount.path("/contended-file");
    fs::write(&path, b"lock target").expect("create lock target");
    let file = open_read_write(&path);
    let mut child = spawn_child_holding_lock(&path, libc::F_WRLCK as libc::c_short, 0, 128)
        .expect("child write lock");

    let err = lock_file(&file, libc::F_WRLCK as libc::c_short, 0, 128)
        .expect_err("parent write lock should conflict with child");
    assert_conflict_errno(&err);

    child.release_and_wait();
    lock_file(&file, libc::F_WRLCK as libc::c_short, 0, 128)
        .expect("write lock succeeds after child releases");
    unlock_file(&file, 0, 128).expect("unlock parent write lock");
}

#[test]
fn read_locks_share_but_write_lock_conflicts() {
    let _guard = test_lock();
    let mount = MountedVfs::new();
    let path = mount.path("/shared-read-file");
    fs::write(&path, b"lock target").expect("create lock target");
    let file = open_read_write(&path);

    lock_file(&file, libc::F_RDLCK as libc::c_short, 0, 128).expect("parent read lock");
    child_lock_attempt(&path, libc::F_RDLCK as libc::c_short, 0, 128)
        .expect("child read lock should share");
    let err = child_lock_attempt(&path, libc::F_WRLCK as libc::c_short, 0, 128)
        .expect_err("child write lock should conflict with parent read lock");
    assert_conflict_errno(&err);

    unlock_file(&file, 0, 128).expect("unlock parent read lock");
}

#[test]
fn non_overlapping_child_lock_succeeds_while_overlapping_lock_conflicts() {
    let _guard = test_lock();
    let mount = MountedVfs::new();
    let path = mount.path("/range-file");
    fs::write(&path, b"lock target").expect("create lock target");
    let file = open_read_write(&path);

    lock_file(&file, libc::F_WRLCK as libc::c_short, 0, 64).expect("parent write lock");
    child_lock_attempt(&path, libc::F_WRLCK as libc::c_short, 64, 64)
        .expect("adjacent child write lock should not conflict");
    let err = child_lock_attempt(&path, libc::F_WRLCK as libc::c_short, 63, 1)
        .expect_err("overlapping child write lock should conflict");
    assert_conflict_errno(&err);

    unlock_file(&file, 0, 64).expect("unlock parent range");
}

#[test]
fn close_releases_process_lock() {
    let _guard = test_lock();
    let mount = MountedVfs::new();
    let path = mount.path("/close-release-file");
    fs::write(&path, b"lock target").expect("create lock target");
    let file = open_read_write(&path);

    lock_file(&file, libc::F_WRLCK as libc::c_short, 0, 0).expect("parent eof write lock");
    let err = child_lock_attempt(&path, libc::F_WRLCK as libc::c_short, 0, 128)
        .expect_err("child write lock should conflict before close");
    assert_conflict_errno(&err);

    drop(file);
    child_lock_attempt_until_success(&path, libc::F_WRLCK as libc::c_short, 0, 128)
        .expect("child write lock succeeds after parent close releases process lock");
}

#[test]
fn setlkw_blocks_until_lock_released() {
    let _guard = test_lock();
    let mount = MountedVfs::new();
    let path = mount.path("/setlkw-block-file");
    fs::write(&path, b"lock target").expect("create lock target");
    let mut child = spawn_child_holding_lock(&path, libc::F_WRLCK as libc::c_short, 0, 128)
        .expect("child write lock");

    let file = open_read_write(&path);
    let fd = file.as_raw_fd();
    let (acquired, handle) = setlkw_in_thread(fd, libc::F_WRLCK as libc::c_short, 0, 128);

    // Give the thread time to start blocking on F_SETLKW
    thread::sleep(Duration::from_millis(200));
    assert!(
        !acquired.load(Ordering::SeqCst),
        "F_SETLKW should still be blocked"
    );

    child.release_and_wait();
    let result = handle.join().expect("setlkw thread panicked");
    assert!(
        result.is_ok(),
        "F_SETLKW should succeed after child releases"
    );

    unlock_file(&file, 0, 128).expect("unlock");
}

#[test]
fn read_lock_upgrades_to_write_lock_on_same_fd() {
    let _guard = test_lock();
    let mount = MountedVfs::new();
    let path = mount.path("/upgrade-file");
    fs::write(&path, b"lock target").expect("create lock target");
    let file = open_read_write(&path);

    lock_file(&file, libc::F_RDLCK as libc::c_short, 0, 128).expect("acquire read lock");

    // Confirm a read lock is held
    let conflict = get_lock(&file, libc::F_WRLCK as libc::c_short, 0, 128).expect("getlk");
    assert_eq!(
        conflict.l_type,
        libc::F_RDLCK as libc::c_short,
        "getlk should report a read lock"
    );

    // Upgrade to write lock on the same fd
    lock_file(&file, libc::F_WRLCK as libc::c_short, 0, 128).expect("upgrade to write lock");

    // Confirm write lock is held
    let conflict = get_lock(&file, libc::F_WRLCK as libc::c_short, 0, 128).expect("getlk");
    assert_eq!(
        conflict.l_type,
        libc::F_WRLCK as libc::c_short,
        "getlk should report a write lock after upgrade"
    );

    // Another process must be blocked from write lock
    let err = child_lock_attempt(&path, libc::F_WRLCK as libc::c_short, 0, 128)
        .expect_err("child write lock should conflict");
    assert_conflict_errno(&err);

    unlock_file(&file, 0, 128).expect("unlock");
}

#[test]
fn process_sigkill_releases_locks_and_unblocks_setlkw_waiter() {
    let _guard = test_lock();
    let mount = MountedVfs::new();
    let path = mount.path("/sigkill-release-file");
    fs::write(&path, b"lock target").expect("create lock target");

    // Spawn child holding write lock but do not use the release mechanism
    let mut child = spawn_child_holding_lock(&path, libc::F_WRLCK as libc::c_short, 0, 128)
        .expect("child write lock");
    let child_pid = child.pid;

    let file = open_read_write(&path);
    let fd = file.as_raw_fd();
    let (acquired, handle) = setlkw_in_thread(fd, libc::F_WRLCK as libc::c_short, 0, 128);

    thread::sleep(Duration::from_millis(200));
    assert!(
        !acquired.load(Ordering::SeqCst),
        "F_SETLKW should still be blocked while child holds lock"
    );

    // SIGKILL the child; close its release fd so Drop does not try to signal it
    close_fd(child.release_write_fd);
    child.release_write_fd = -1;
    unsafe {
        libc::kill(child_pid, libc::SIGKILL);
    }
    let mut status = 0;
    unsafe {
        libc::waitpid(child_pid, &mut status, 0);
    }

    // Mark as reaped so Drop is a no-op
    child.reaped = true;

    let result = handle.join().expect("setlkw thread panicked");
    assert!(
        result.is_ok(),
        "F_SETLKW should succeed after child process killed"
    );

    unlock_file(&file, 0, 128).expect("unlock");
}

// ── BSD flock(2) helpers ──────────────────────────────────────────────

extern "C" {
    #[link_name = "flock"]
    fn sys_flock(fd: libc::c_int, operation: libc::c_int) -> libc::c_int;
}

fn bsd_flock(file: &File, operation: libc::c_int) -> io::Result<()> {
    let result = unsafe { sys_flock(file.as_raw_fd(), operation) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn spawn_child_holding_flock(path: &Path, operation: libc::c_int) -> io::Result<ChildLock> {
    let path = c_path(path)?;
    let mut ready_pipe = [-1; 2];
    let mut release_pipe = [-1; 2];
    pipe(&mut ready_pipe)?;
    pipe(&mut release_pipe)?;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let err = io::Error::last_os_error();
        close_fd(ready_pipe[0]);
        close_fd(ready_pipe[1]);
        close_fd(release_pipe[0]);
        close_fd(release_pipe[1]);
        return Err(err);
    }

    if pid == 0 {
        close_fd(ready_pipe[0]);
        close_fd(release_pipe[1]);
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        let errno = if fd < 0 {
            errno()
        } else {
            let result = unsafe { sys_flock(fd, operation) };
            if result == 0 {
                write_i32_fd(ready_pipe[1], 0);
                let mut byte = [0u8; 1];
                let _ = unsafe { libc::read(release_pipe[0], byte.as_mut_ptr().cast(), 1) };
                0
            } else {
                errno()
            }
        };
        if errno != 0 {
            write_i32_fd(ready_pipe[1], errno);
        }
        if fd >= 0 {
            close_fd(fd);
        }
        close_fd(ready_pipe[1]);
        close_fd(release_pipe[0]);
        unsafe {
            libc::_exit(if errno == 0 { 0 } else { 1 });
        }
    }

    close_fd(ready_pipe[1]);
    close_fd(release_pipe[0]);
    let errno = read_i32_fd(ready_pipe[0]);
    close_fd(ready_pipe[0]);
    if errno == 0 {
        Ok(ChildLock {
            pid,
            release_write_fd: release_pipe[1],
            reaped: false,
        })
    } else {
        close_fd(release_pipe[1]);
        let mut status = 0;
        unsafe {
            let _ = libc::waitpid(pid, &mut status, 0);
        }
        Err(io::Error::from_raw_os_error(errno))
    }
}

fn child_flock_attempt(path: &Path, operation: libc::c_int) -> io::Result<()> {
    let path = c_path(path)?;
    let mut result_pipe = [-1; 2];
    pipe(&mut result_pipe)?;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let err = io::Error::last_os_error();
        close_fd(result_pipe[0]);
        close_fd(result_pipe[1]);
        return Err(err);
    }

    if pid == 0 {
        close_fd(result_pipe[0]);
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        let errno = if fd < 0 {
            errno()
        } else {
            let result = unsafe { sys_flock(fd, operation) };
            if result == 0 {
                0
            } else {
                errno()
            }
        };
        write_i32_fd(result_pipe[1], errno);
        if fd >= 0 {
            close_fd(fd);
        }
        close_fd(result_pipe[1]);
        unsafe {
            libc::_exit(if errno == 0 { 0 } else { 1 });
        }
    }

    close_fd(result_pipe[1]);
    let errno = read_i32_fd(result_pipe[0]);
    close_fd(result_pipe[0]);
    let mut status = 0;
    unsafe {
        let _ = libc::waitpid(pid, &mut status, 0);
    }
    if errno == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(errno))
    }
}

fn child_flock_attempt_until_success(path: &Path, operation: libc::c_int) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut last_error = None;
    while Instant::now() < deadline {
        match child_flock_attempt(path, operation) {
            Ok(()) => return Ok(()),
            Err(err) if matches!(err.raw_os_error(), Some(libc::EAGAIN | libc::EACCES)) => {
                last_error = Some(err);
                thread::sleep(Duration::from_millis(10));
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::from_raw_os_error(libc::ETIMEDOUT)))
}

// ── BSD flock(2) integration tests ─────────────────────────────────────

#[test]
fn flock_shared_locks_share_concurrently() {
    let _guard = test_lock();
    let mount = MountedVfs::new();
    let path = mount.path("/flock-shared");
    fs::write(&path, b"flock target").expect("create lock target");
    let file = open_read_write(&path);

    bsd_flock(&file, libc::LOCK_SH).expect("parent shared flock");
    child_flock_attempt(&path, libc::LOCK_SH).expect("child shared flock should share");
    let err = child_flock_attempt(&path, libc::LOCK_EX)
        .expect_err("child exclusive flock should conflict with shared holder");
    assert_conflict_errno(&err);

    bsd_flock(&file, libc::LOCK_UN).expect("unlock parent shared flock");
}

#[test]
fn flock_exclusive_blocks_other_locks() {
    let _guard = test_lock();
    let mount = MountedVfs::new();
    let path = mount.path("/flock-exclusive");
    fs::write(&path, b"flock target").expect("create lock target");
    let file = open_read_write(&path);

    bsd_flock(&file, libc::LOCK_EX).expect("parent exclusive flock");
    let err = child_flock_attempt(&path, libc::LOCK_EX)
        .expect_err("child exclusive flock should conflict");
    assert_conflict_errno(&err);
    let err = child_flock_attempt(&path, libc::LOCK_SH)
        .expect_err("child shared flock should conflict with exclusive holder");
    assert_conflict_errno(&err);

    bsd_flock(&file, libc::LOCK_UN).expect("unlock parent exclusive flock");
    child_flock_attempt(&path, libc::LOCK_EX)
        .expect("child exclusive flock succeeds after parent unlocks");
}

#[test]
fn flock_lock_nb_returns_eagain_on_conflict() {
    let _guard = test_lock();
    let mount = MountedVfs::new();
    let path = mount.path("/flock-nb-conflict");
    fs::write(&path, b"flock target").expect("create lock target");
    let file = open_read_write(&path);

    bsd_flock(&file, libc::LOCK_EX).expect("parent exclusive flock");
    let err = bsd_flock(&file, libc::LOCK_EX | libc::LOCK_NB)
        .expect_err("LOCK_EX|LOCK_NB should conflict on same fd");
    assert_conflict_errno(&err);

    bsd_flock(&file, libc::LOCK_UN).expect("unlock");
}

#[test]
fn flock_close_releases_all_locks() {
    let _guard = test_lock();
    let mount = MountedVfs::new();
    let path = mount.path("/flock-close-release");
    fs::write(&path, b"flock target").expect("create lock target");
    let file = open_read_write(&path);

    bsd_flock(&file, libc::LOCK_EX).expect("parent exclusive flock");
    let err = child_flock_attempt(&path, libc::LOCK_EX)
        .expect_err("child exclusive flock should conflict before close");
    assert_conflict_errno(&err);

    drop(file);
    child_flock_attempt_until_success(&path, libc::LOCK_EX)
        .expect("child exclusive flock succeeds after parent close");
}

#[test]
fn flock_upgrade_from_shared_to_exclusive() {
    let _guard = test_lock();
    let mount = MountedVfs::new();
    let path = mount.path("/flock-upgrade");
    fs::write(&path, b"flock target").expect("create lock target");
    let file = open_read_write(&path);

    bsd_flock(&file, libc::LOCK_SH).expect("parent shared flock");
    // Upgrading to exclusive on the same fd
    bsd_flock(&file, libc::LOCK_EX).expect("upgrade to exclusive flock");

    // Another process should be blocked
    let err = child_flock_attempt(&path, libc::LOCK_EX)
        .expect_err("child exclusive flock should conflict after upgrade");
    assert_conflict_errno(&err);

    bsd_flock(&file, libc::LOCK_UN).expect("unlock");
}

#[test]
fn flock_process_exit_releases_locks() {
    let _guard = test_lock();
    let mount = MountedVfs::new();
    let path = mount.path("/flock-exit-release");
    fs::write(&path, b"flock target").expect("create lock target");

    let mut child = spawn_child_holding_flock(&path, libc::LOCK_EX).expect("child exclusive flock");
    let child_pid = child.pid;

    let err = child_flock_attempt(&path, libc::LOCK_EX)
        .expect_err("second child should conflict with flock holder");
    assert_conflict_errno(&err);

    // SIGKILL the lock holder
    close_fd(child.release_write_fd);
    child.release_write_fd = -1;
    unsafe {
        libc::kill(child_pid, libc::SIGKILL);
    }
    let mut status = 0;
    unsafe {
        libc::waitpid(child_pid, &mut status, 0);
    }
    child.reaped = true;

    child_flock_attempt_until_success(&path, libc::LOCK_EX)
        .expect("flock succeeds after holder killed");
}
