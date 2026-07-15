// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE file-locking integration test: exercises POSIX advisory file locking
//! (getlk / setlk / setlkw) through a real read-write FUSE mount.
//!
//! Each test issues `libc::fcntl` with F_GETLK, F_SETLK, and F_SETLKW on
//! files under the mount point, validating:
//!
//!   1. Lock acquisition and release (setlk write lock, then unlock).
//!   2. Conflict detection (getlk reports a conflicting lock held by
//!      another process).
//!   3. EAGAIN / EACCES on non-blocking setlk when a conflict exists.
//!   4. Blocking setlkw waits for lock release, then succeeds.
//!   5. Mandatory unlock on file close (kernel releases all locks on fd
//!      close, verified by another fd acquiring the same range).
//!   6. Lock release on process exit.
//!
//! Cross-process tests use `libc::fork` to create a child process that
//! holds a lock, enabling true conflict detection through the FUSE path.

use std::fs;
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::{Duration, Instant};
use tidefs_validation::mount_harness::MountHarness;

// ── Lock helpers ─────────────────────────────────────────────────────────

/// Build a POSIX advisory lock structure.
fn flock(typ: i16, start: i64, len: i64) -> libc::flock {
    libc::flock {
        l_type: typ,
        l_whence: libc::SEEK_SET as i16,
        l_start: start,
        l_len: len,
        l_pid: 0,
    }
}

/// Acquire or release a lock via F_SETLK (non-blocking).
fn setlk(fd: &impl AsRawFd, fl: &libc::flock) -> Result<(), i32> {
    // SAFETY: fcntl F_SETLK[W] is a C FFI call; fd is a valid open
    // fd; the flock pointer is a valid stack-local.
    let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETLK, fl) };
    if rc == -1 {
        Err(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    } else {
        Ok(())
    }
}

/// Acquire a lock via F_SETLKW (blocking -- waits until available).
fn setlkw(fd: &impl AsRawFd, fl: &libc::flock) -> Result<(), i32> {
    // SAFETY: fcntl F_SETLK[W] is a C FFI call; fd is a valid open
    // fd; the flock pointer is a valid stack-local.
    let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETLKW, fl) };
    if rc == -1 {
        Err(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    } else {
        Ok(())
    }
}

/// Query lock state via F_GETLK.  Returns the flock structure filled
/// by the kernel: l_type == F_UNLCK means no conflicting lock exists.
fn getlk(fd: &impl AsRawFd, fl: &libc::flock) -> Result<libc::flock, i32> {
    let mut query = *fl;
    // SAFETY: fcntl F_GETLK is a C FFI call; fd is valid; the flock
    // pointer is a valid stack-local mutable reference.
    let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETLK, &mut query) };
    if rc == -1 {
        Err(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    } else {
        Ok(query)
    }
}

// ── Fork-based cross-process helpers ──────────────────────────────────────

/// Fork a child process that acquires a write lock on `file_path` over
/// [0, bytes_len), waits for the parent to signal via a pipe, then
/// releases and exits.
///
/// Returns (child_pid, read_fd) where read_fd is the read end of a
/// pipe.  Once the child has acquired the lock, it writes a single byte
/// to the pipe.  The parent reads that byte to synchronise.
///
/// # Safety
///
/// Calls `libc::fork`. The caller must ensure this helper runs in a
/// single-threaded test context where the child will not panic, allocate, or
/// call async-signal-unsafe functions beyond what POSIX allows.
unsafe fn fork_lock_holder(file_path: &Path, bytes_len: u64) -> io::Result<(i32, i32)> {
    // Create a pipe for synchronisation: child writes a byte when the
    // lock is acquired.
    let mut pipe_fds: [libc::c_int; 2] = [0; 2];
    if libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
        return Err(io::Error::last_os_error());
    }
    let (read_fd, write_fd) = (pipe_fds[0], pipe_fds[1]);

    let pid = libc::fork();
    if pid < 0 {
        let e = io::Error::last_os_error();
        libc::close(read_fd);
        libc::close(write_fd);
        return Err(e);
    }

    if pid == 0 {
        // ── child ────────────────────────────────────────────────────
        libc::close(read_fd);

        // Open the file.  Use libc directly to avoid std allocation in
        // the forked child.
        let path_c = match std::ffi::CString::new(file_path.as_os_str().as_encoded_bytes()) {
            Ok(s) => s,
            Err(_) => libc::_exit(1),
        };
        let fd = libc::open(path_c.as_ptr(), libc::O_RDWR);
        if fd < 0 {
            libc::_exit(1);
        }

        let fl = libc::flock {
            l_type: libc::F_WRLCK as i16,
            l_whence: libc::SEEK_SET as i16,
            l_start: 0,
            l_len: bytes_len as i64,
            l_pid: 0,
        };
        if libc::fcntl(fd, libc::F_SETLK, &fl) != 0 {
            libc::_exit(1);
        }

        // Signal parent: lock acquired.
        let sig: u8 = 1;
        if libc::write(write_fd, &sig as *const u8 as *const libc::c_void, 1) != 1 {
            libc::_exit(1);
        }
        libc::close(write_fd);

        // Block until parent closes the pipe (parent drops read_fd) or
        // we receive a signal.
        let mut _buf: [u8; 1] = [0];
        // Reading from write_fd would fail; just sleep and check if
        // parent is alive via a simple timer.
        // Wait up to 30 seconds for parent to tell us to exit by
        // closing its end of a second pipe or by killing us.
        // For simplicity, sleep in 100ms increments and exit after
        // timeout.
        for _ in 0..300 {
            let ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 100_000_000,
            };
            libc::nanosleep(&ts, std::ptr::null_mut());
        }

        libc::close(fd);
        libc::_exit(0);
    }

    // ── parent ──────────────────────────────────────────────────────
    libc::close(write_fd);
    Ok((pid, read_fd))
}

/// Wait for the child to signal lock acquisition by writing to the pipe.
/// Returns after reading one byte.  Caller must close `read_fd` after.
fn wait_child_ready(read_fd: i32) -> io::Result<()> {
    let mut buf: [u8; 1] = [0];
    loop {
        // SAFETY: read(2) is a C FFI call; read_fd is a valid fd;
        // the buffer is valid for writes.
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr() as *mut libc::c_void, 1) };
        if n == 1 {
            return Ok(());
        }
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        // n == 0: pipe closed (child exited or failed).
        return Err(io::Error::other(
            "child process closed pipe without signalling readiness",
        ));
    }
}

// ── Test: setlk exclusive acquire and release ─────────────────────────────

/// Acquire a write lock, confirm the lock is held via getlk on a second
/// fd (self-conflict), release via F_UNLCK, and verify re-acquisition
/// succeeds from the same fd.
#[test]
fn setlk_exclusive_acquire_and_release() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP setlk_exclusive_acquire_and_release: daemon not available -- {e}");
            return;
        }
    };
    harness
        .create_file("lock_excl.bin", b"0123456789abcdef")
        .expect("create lock file");

    let fd = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(harness.mount_path().join("lock_excl.bin"))
        .expect("open fd");

    // Acquire write lock on bytes 0..9.
    let wrlock = flock(libc::F_WRLCK as i16, 0, 10);
    setlk(&fd, &wrlock).expect("acquire write lock");

    // getlk from a second fd (same PID) on an overlapping range: the
    // kernel should report F_UNLCK since the same process owns the lock.
    let fd2 = fs::File::open(harness.mount_path().join("lock_excl.bin")).expect("open second fd");
    let query = flock(libc::F_WRLCK as i16, 3, 5);
    let result = getlk(&fd2, &query).expect("getlk query");
    assert_eq!(
        result.l_type,
        libc::F_UNLCK as i16,
        "getlk from second fd (same PID) should see no conflict"
    );

    // Release.
    let unlock = flock(libc::F_UNLCK as i16, 0, 10);
    setlk(&fd, &unlock).expect("unlock");

    // Re-acquire the same range on the same fd.
    setlk(&fd, &wrlock).expect("re-acquire write lock after unlock");
}

// ── Test: getlk reports conflicting lock from another process ─────────────

/// F_GETLK must report the PID and type of a lock held by a different
/// process when querying an overlapping range.
#[test]
fn getlk_reports_conflicting_lock() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP getlk_reports_conflicting_lock: daemon not available -- {e}");
            return;
        }
    };
    harness
        .create_file("lock_getlk.bin", b"data for getlk conflict test")
        .expect("create lock file");

    let file_path = harness.mount_path().join("lock_getlk.bin");

    // Fork a child that holds a write lock on bytes 0..99.
    let (child_pid, ready_fd) =
        // SAFETY: fork_lock_holder calls fork(), safe from single-threaded tests.
        unsafe { fork_lock_holder(&file_path, 100) }.expect("fork lock holder");
    wait_child_ready(ready_fd).expect("child did not signal readiness");
    // SAFETY: close(2) is a C FFI call; ready_fd is a valid fd.
    unsafe {
        libc::close(ready_fd);
    }

    // Query from this process (different PID).
    let querier = fs::File::open(&file_path).expect("open querier fd");
    let query = flock(libc::F_WRLCK as i16, 50, 20);
    let result = getlk(&querier, &query).expect("getlk query");

    // Clean up: kill child.
    // SAFETY: kill(2) is a C FFI call; child_pid is a valid PID from fork().
    unsafe {
        libc::kill(child_pid, libc::SIGTERM);
    }
    let mut status: i32 = 0;
    // SAFETY: waitpid(2) is a C FFI call; child_pid is a valid PID from fork();
    // status is a live stack-local integer.
    unsafe {
        libc::waitpid(child_pid, &mut status, 0);
    }

    assert_eq!(
        result.l_type,
        libc::F_WRLCK as i16,
        "getlk on overlapping range from different PID should report F_WRLCK"
    );
    assert_ne!(
        result.l_pid, 0,
        "getlk should report a non-zero PID of the lock holder"
    );
}

// ── Test: setlk conflict returns EAGAIN / EACCES ──────────────────────────

/// Non-blocking F_SETLK must fail with EAGAIN or EACCES when a
/// different process holds a conflicting write lock.
#[test]
fn setlk_conflict_detection() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP setlk_conflict_detection: daemon not available -- {e}");
            return;
        }
    };
    harness
        .create_file("lock_conflict.bin", b"setlk conflict test data")
        .expect("create lock file");

    let file_path = harness.mount_path().join("lock_conflict.bin");

    let (child_pid, ready_fd) =
        // SAFETY: fork_lock_holder calls fork(), safe from single-threaded tests.
        unsafe { fork_lock_holder(&file_path, 50) }.expect("fork lock holder");
    wait_child_ready(ready_fd).expect("child did not signal readiness");
    // SAFETY: close(2) is a C FFI call; ready_fd is a valid fd.
    unsafe {
        libc::close(ready_fd);
    }

    // Try to acquire overlapping lock from this process.
    let competitor = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open competitor fd");

    let conflicting = flock(libc::F_WRLCK as i16, 0, 50);
    let err = setlk(&competitor, &conflicting).expect_err("setlk should fail with conflict");

    // SAFETY: kill(2) is a C FFI call; child_pid is a valid PID from fork().
    unsafe {
        libc::kill(child_pid, libc::SIGTERM);
    }
    let mut status: i32 = 0;
    // SAFETY: waitpid(2) is a C FFI call; child_pid is a valid PID from fork();
    // status is a live stack-local integer.
    unsafe {
        libc::waitpid(child_pid, &mut status, 0);
    }

    assert!(
        err == libc::EAGAIN || err == libc::EACCES,
        "expected EAGAIN(11) or EACCES(13), got errno={err}"
    );
}

// ── Test: setlkw blocks until lock is released ────────────────────────────

/// F_SETLKW must block the caller until the conflicting lock held by
/// another process is released, then succeed.
#[test]
fn setlkw_blocking_acquire() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP setlkw_blocking_acquire: daemon not available -- {e}");
            return;
        }
    };
    harness
        .create_file("lock_setlkw.bin", b"setlkw blocking test data")
        .expect("create lock file");

    let file_path = harness.mount_path().join("lock_setlkw.bin");

    let (child_pid, ready_fd) =
        // SAFETY: fork_lock_holder calls fork(), safe from single-threaded tests.
        unsafe { fork_lock_holder(&file_path, 100) }.expect("fork lock holder");
    wait_child_ready(ready_fd).expect("child did not signal readiness");
    // SAFETY: close(2) is a C FFI call; ready_fd is a valid fd.
    unsafe {
        libc::close(ready_fd);
    }

    let file_path2 = file_path.clone();
    let start = Instant::now();

    // Spawn a thread that calls setlkw (blocking).  It will block until
    // the child releases the lock.
    let handle = std::thread::spawn(move || {
        let blocker = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file_path2)
            .expect("open blocker fd");
        let blocking_lock = flock(libc::F_WRLCK as i16, 0, 100);
        setlkw(&blocker, &blocking_lock)
    });

    // Give the thread time to start blocking.
    std::thread::sleep(Duration::from_millis(500));

    // Kill the child to release its lock.
    // SAFETY: kill(2) is a C FFI call; child_pid is a valid PID from fork().
    unsafe {
        libc::kill(child_pid, libc::SIGTERM);
    }
    let mut status: i32 = 0;
    // SAFETY: waitpid(2) is a C FFI call; child_pid is a valid PID from fork();
    // status is a live stack-local integer.
    unsafe {
        libc::waitpid(child_pid, &mut status, 0);
    }

    let result = handle.join().expect("setlkw thread panicked");
    let elapsed = start.elapsed();

    result.expect("setlkw should succeed after holder releases");

    assert!(
        elapsed >= Duration::from_millis(400),
        "setlkw returned too quickly ({elapsed:.1?}); expected blocking delay"
    );
}

// ── Test: lock release on close ───────────────────────────────────────────

/// Closing the file descriptor must release all locks held by that fd.
/// Verified by acquiring the same range from a new fd after close.
#[test]
fn lock_release_on_close() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP lock_release_on_close: daemon not available -- {e}");
            return;
        }
    };
    harness
        .create_file("lock_close.bin", b"close releases lock test")
        .expect("create lock file");

    let fd1 = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(harness.mount_path().join("lock_close.bin"))
        .expect("open fd1");

    let wrlock = flock(libc::F_WRLCK as i16, 0, 50);
    setlk(&fd1, &wrlock).expect("fd1 acquire write lock");

    // Close fd1.
    drop(fd1);

    // A new fd must be able to acquire the same range.
    let fd2 = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(harness.mount_path().join("lock_close.bin"))
        .expect("open fd2 after fd1 close");

    setlk(&fd2, &wrlock).expect("fd2 should acquire lock after fd1 close releases it");
}

// ── Test: lock release on process exit ────────────────────────────────────

/// When a process exits, all locks it holds must be released.
#[test]
fn lock_release_on_process_exit() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP lock_release_on_process_exit: daemon not available -- {e}");
            return;
        }
    };
    harness
        .create_file("lock_pexit.bin", b"process exit releases lock")
        .expect("create lock file");

    let file_path = harness.mount_path().join("lock_pexit.bin");

    let (child_pid, ready_fd) =
        // SAFETY: fork_lock_holder calls fork(), safe from single-threaded tests.
        unsafe { fork_lock_holder(&file_path, 100) }.expect("fork lock holder");
    wait_child_ready(ready_fd).expect("child did not signal readiness");
    // SAFETY: close(2) is a C FFI call; ready_fd is a valid fd.
    unsafe {
        libc::close(ready_fd);
    }

    // Kill the child.
    // SAFETY: kill(2) is a C FFI call; child_pid is a valid PID from fork().
    unsafe {
        libc::kill(child_pid, libc::SIGTERM);
    }
    let mut status: i32 = 0;
    // SAFETY: waitpid(2) is a C FFI call; child_pid is a valid PID from fork();
    // status is a live stack-local integer.
    unsafe {
        libc::waitpid(child_pid, &mut status, 0);
    }

    // Now a new process should acquire the same range.
    let fd = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open fd after holder exit");

    let wrlock = flock(libc::F_WRLCK as i16, 0, 100);
    setlk(&fd, &wrlock).expect("should acquire lock after holder process exits");
}

// ── Test: read locks are compatible across processes ──────────────────────

/// Two processes holding F_RDLCK on overlapping ranges must not conflict.
#[test]
fn read_locks_are_compatible() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP read_locks_are_compatible: daemon not available -- {e}");
            return;
        }
    };
    harness
        .create_file("lock_rdlk.bin", b"read lock compatibility test data")
        .expect("create lock file");

    let file_path = harness.mount_path().join("lock_rdlk.bin");

    // Fork a child that holds a READ lock.
    let mut pipe_fds: [libc::c_int; 2] = [0; 2];
    // SAFETY: pipe2 is a C FFI call; pipe_fds is a valid stack-local array;
    // O_CLOEXEC is a valid flag.
    unsafe {
        libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC);
    }
    let (read_fd, write_fd) = (pipe_fds[0], pipe_fds[1]);

    // SAFETY: fork() is safe from a single-threaded test process.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        panic!("fork failed");
    }
    if child_pid == 0 {
        // child
        // SAFETY: close(2) on valid fd; standard child cleanup.
        unsafe {
            libc::close(read_fd);
        }
        let path_c = std::ffi::CString::new(file_path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: open(2) is a C FFI call; the path pointer is a valid
        // null-terminated CString; the flags are valid O_* constants.
        // SAFETY: open(2) is a C FFI call; path_c is a valid CString; O_RDWR is valid.
        let fd = unsafe { libc::open(path_c.as_ptr(), libc::O_RDWR) };
        if fd < 0 {
            unsafe {
                libc::_exit(1);
            }
        }
        let fl = libc::flock {
            l_type: libc::F_RDLCK as i16,
            l_whence: libc::SEEK_SET as i16,
            l_start: 0,
            l_len: 200,
            l_pid: 0,
        };
        // SAFETY: fcntl F_SETLK is a C FFI call; fd is valid; fl is valid.
        if unsafe { libc::fcntl(fd, libc::F_SETLK, &fl) } != 0 {
            unsafe {
                libc::_exit(1);
            }
        }
        let sig: u8 = 1;
        // SAFETY: write(2) on valid fd; sig is a live stack byte.
        unsafe {
            libc::write(write_fd, &sig as *const u8 as *const libc::c_void, 1);
        }
        // SAFETY: close(2) on valid fd; standard child cleanup.
        unsafe {
            libc::close(write_fd);
        }
        // Sleep until killed.
        let ts = libc::timespec {
            tv_sec: 30,
            tv_nsec: 0,
        };
        // SAFETY: nanosleep is a C FFI call; ts is a valid timespec on the
        // stack; null remainder is valid per the API.
        unsafe {
            libc::nanosleep(&ts, std::ptr::null_mut());
        }
        // SAFETY: close(2) on valid fd; _exit(2) terminates the forked child.
        unsafe {
            libc::close(fd);
            libc::_exit(0);
        }
    }

    // SAFETY: close(2) on valid fd; standard parent cleanup after fork.
    unsafe {
        libc::close(write_fd);
    }
    wait_child_ready(read_fd).expect("child did not signal readiness");
    // SAFETY: close(2) on valid fd; parent cleanup after receiving child signal.
    unsafe {
        libc::close(read_fd);
    }

    // This process acquires a read lock on an overlapping range.
    let fd = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open fd for read lock");

    let rdlock = flock(libc::F_RDLCK as i16, 50, 100);
    setlk(&fd, &rdlock)
        .expect("read lock on overlapping range must succeed (read-read compatible)");

    drop(fd);

    // SAFETY: kill(2) is a C FFI call; child_pid is a valid PID from fork().
    unsafe {
        libc::kill(child_pid, libc::SIGTERM);
    }
    let mut status: i32 = 0;
    // SAFETY: waitpid(2) is a C FFI call; child_pid is a valid PID from fork();
    // status is a live stack-local integer.
    unsafe {
        libc::waitpid(child_pid, &mut status, 0);
    }
}

// ── Test: write-read conflict across processes ────────────────────────────

/// A write lock must conflict with a read lock request from another
/// process on an overlapping range.
#[test]
fn write_lock_blocks_read_lock() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_lock_blocks_read_lock: daemon not available -- {e}");
            return;
        }
    };
    harness
        .create_file("lock_wr_block.bin", b"write blocks read test")
        .expect("create lock file");

    let file_path = harness.mount_path().join("lock_wr_block.bin");

    let (child_pid, ready_fd) =
        // SAFETY: fork_lock_holder calls fork(), safe from single-threaded tests.
        unsafe { fork_lock_holder(&file_path, 100) }.expect("fork write-lock holder");
    wait_child_ready(ready_fd).expect("child did not signal readiness");
    // SAFETY: close(2) is a C FFI call; ready_fd is a valid fd.
    unsafe {
        libc::close(ready_fd);
    }

    let fd = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open fd for read lock attempt");

    let rdlock = flock(libc::F_RDLCK as i16, 50, 20);
    let err = setlk(&fd, &rdlock).expect_err("read lock should conflict with existing write lock");

    // SAFETY: kill(2) is a C FFI call; child_pid is a valid PID from fork().
    unsafe {
        libc::kill(child_pid, libc::SIGTERM);
    }
    let mut status: i32 = 0;
    // SAFETY: waitpid(2) is a C FFI call; child_pid is a valid PID from fork();
    // status is a live stack-local integer.
    unsafe {
        libc::waitpid(child_pid, &mut status, 0);
    }

    assert!(
        err == libc::EAGAIN || err == libc::EACCES,
        "expected EAGAIN(11) or EACCES(13) for read-write conflict, got errno={err}"
    );
}

// ── Test: file content integrity under locking ────────────────────────────

/// Write to a file while holding a write lock, release, then re-read
/// from a second fd to verify content integrity is preserved through
/// the FUSE locking path.
#[test]
fn file_content_integrity_under_locking() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP file_content_integrity_under_locking: daemon not available -- {e}");
            return;
        }
    };
    harness
        .create_file("lock_content.bin", b"initial data\n")
        .expect("create lock file");

    let mut fd = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(harness.mount_path().join("lock_content.bin"))
        .expect("open fd");

    // Acquire exclusive lock.
    let wrlock = flock(libc::F_WRLCK as i16, 0, 0);
    setlk(&fd, &wrlock).expect("acquire write lock");

    // Write under lock.
    use std::io::Write;
    fd.set_len(0).expect("truncate");
    fd.write_all(b"updated under lock\n")
        .expect("write under lock");
    fd.flush().expect("flush");

    // Release lock.
    let unlock = flock(libc::F_UNLCK as i16, 0, 0);
    setlk(&fd, &unlock).expect("unlock");
    drop(fd);

    // Read back via a fresh fd.
    let read_back = harness.read_file("lock_content.bin").expect("read back");
    assert_eq!(
        read_back, b"updated under lock\n",
        "file content must match what was written under the lock"
    );
}

// ── Test: non-overlapping ranges do not conflict ──────────────────────────

/// Two write locks on non-overlapping byte ranges from different processes
/// must both succeed.
#[test]
fn non_overlapping_write_locks_independent() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP non_overlapping_write_locks_independent: daemon not available -- {e}");
            return;
        }
    };
    harness
        .create_file("lock_nonoverlap.bin", &vec![0u8; 1024])
        .expect("create lock file");

    let file_path = harness.mount_path().join("lock_nonoverlap.bin");

    // Fork a child that holds write lock on bytes 0..99.
    let mut pipe_fds: [libc::c_int; 2] = [0; 2];
    // SAFETY: pipe2 is a C FFI call; pipe_fds is a valid stack-local array;
    // O_CLOEXEC is a valid flag.
    unsafe {
        libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC);
    }
    let (read_fd, write_fd) = (pipe_fds[0], pipe_fds[1]);

    // SAFETY: fork() is safe from a single-threaded test process.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        panic!("fork failed");
    }
    if child_pid == 0 {
        // SAFETY: the child closes its inherited read end before opening the
        // target file and never uses `read_fd` afterward.
        unsafe {
            libc::close(read_fd);
        }
        let path_c = std::ffi::CString::new(file_path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: open(2) is a C FFI call; the path pointer is a valid
        // null-terminated CString; the flags are valid O_* constants.
        // SAFETY: open(2) is a C FFI call; path_c is a valid CString; O_RDWR is valid.
        let fd = unsafe { libc::open(path_c.as_ptr(), libc::O_RDWR) };
        if fd < 0 {
            unsafe {
                libc::_exit(1);
            }
        }
        let fl = libc::flock {
            l_type: libc::F_WRLCK as i16,
            l_whence: libc::SEEK_SET as i16,
            l_start: 0,
            l_len: 100,
            l_pid: 0,
        };
        // SAFETY: fcntl F_SETLK is a C FFI call; fd is valid; fl is valid.
        if unsafe { libc::fcntl(fd, libc::F_SETLK, &fl) } != 0 {
            unsafe {
                libc::_exit(1);
            }
        }
        let sig: u8 = 1;
        // SAFETY: write(2) on valid fd; sig is a live stack byte.
        unsafe {
            libc::write(write_fd, &sig as *const u8 as *const libc::c_void, 1);
        }
        // SAFETY: close(2) on valid fd; standard child cleanup.
        unsafe {
            libc::close(write_fd);
        }
        let ts = libc::timespec {
            tv_sec: 30,
            tv_nsec: 0,
        };
        // SAFETY: nanosleep is a C FFI call; ts is a valid timespec on the
        // stack; null remainder is valid per the API.
        unsafe {
            libc::nanosleep(&ts, std::ptr::null_mut());
        }
        // SAFETY: close(2) on valid fd; _exit(2) terminates the forked child.
        unsafe {
            libc::close(fd);
            libc::_exit(0);
        }
    }

    // SAFETY: close(2) on valid fd; standard parent cleanup after fork.
    unsafe {
        libc::close(write_fd);
    }
    wait_child_ready(read_fd).expect("child did not signal readiness");
    // SAFETY: close(2) on valid fd; parent cleanup after receiving child signal.
    unsafe {
        libc::close(read_fd);
    }

    // This process locks a non-overlapping range.
    let fd = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open fd for non-overlapping lock");

    let wrlock = flock(libc::F_WRLCK as i16, 200, 100);
    setlk(&fd, &wrlock).expect("write lock on non-overlapping range must succeed");

    drop(fd);

    // SAFETY: kill(2) is a C FFI call; child_pid is a valid PID from fork().
    unsafe {
        libc::kill(child_pid, libc::SIGTERM);
    }
    let mut status: i32 = 0;
    // SAFETY: waitpid(2) is a C FFI call; child_pid is a valid PID from fork();
    // status is a live stack-local integer.
    unsafe {
        libc::waitpid(child_pid, &mut status, 0);
    }
}

// ── Test: getlk returns F_UNLCK when no lock is held ──────────────────────

/// F_GETLK must return l_type == F_UNLCK when no conflicting lock
/// exists for the queried range.
#[test]
fn getlk_returns_unlck_when_no_lock_held() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP getlk_returns_unlck_when_no_lock_held: daemon not available -- {e}");
            return;
        }
    };
    harness
        .create_file("lock_nolock.bin", b"unlocked file for getlk test")
        .expect("create lock file");

    let fd = fs::File::open(harness.mount_path().join("lock_nolock.bin")).expect("open fd");

    let query = flock(libc::F_WRLCK as i16, 0, 100);
    let result = getlk(&fd, &query).expect("getlk query");

    assert_eq!(
        result.l_type,
        libc::F_UNLCK as i16,
        "getlk on unlocked file should return F_UNLCK"
    );
    assert_eq!(
        result.l_pid, 0,
        "getlk should return pid=0 when no conflicting lock exists"
    );
}

// ── Test: same-PID lock upgrade ───────────────────────────────────────────

/// A process holding a read lock on a range should be able to upgrade
/// to a write lock on the same range (kernel merges/replaces).
#[test]
fn same_pid_lock_upgrade() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP same_pid_lock_upgrade: daemon not available -- {e}");
            return;
        }
    };
    harness
        .create_file("lock_upgrade.bin", b"lock upgrade test data")
        .expect("create lock file");

    let fd = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(harness.mount_path().join("lock_upgrade.bin"))
        .expect("open fd");

    // Acquire read lock.
    let rdlock = flock(libc::F_RDLCK as i16, 0, 100);
    setlk(&fd, &rdlock).expect("acquire read lock");

    // Upgrade to write lock on same range.
    let wrlock = flock(libc::F_WRLCK as i16, 0, 100);
    setlk(&fd, &wrlock).expect("upgrade to write lock on same fd");

    // Release.
    let unlock = flock(libc::F_UNLCK as i16, 0, 100);
    setlk(&fd, &unlock).expect("unlock");
}
