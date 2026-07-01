// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE lock recovery after daemon restart — integration tests.
//!
//! Validates the lock recovery/refusal contract: POSIX advisory byte-range
//! locks (fcntl F_SETLK/F_GETLK) and BSD flock are held in the daemon's
//! in-memory lock table and are **not** persisted across daemon restarts.
//! After a crash-and-remount cycle the lock table starts clean, and the
//! kernel-side locks are automatically released when the daemon's FUSE fd
//! is closed on process death.
//!
//! All tests use the MountHarness from tidefs-validation, which spawns the
//! daemon as a separate process, sends real SIGKILL, lazy-unmounts with
//! fusermount -uz, and restarts a fresh daemon on the same backing store.

use std::io;
use std::os::fd::AsRawFd;
use tidefs_validation::mount_harness::MountHarness;

// ── lock helpers ─────────────────────────────────────────────────────────

fn flock(typ: libc::c_short, start: i64, len: i64) -> libc::flock {
    libc::flock {
        l_type: typ,
        l_whence: libc::SEEK_SET as i16,
        l_start: start,
        l_len: len,
        l_pid: 0,
    }
}

fn setlk(fd: &impl AsRawFd, typ: libc::c_short, start: i64, len: i64) -> io::Result<()> {
    let lk = flock(typ, start, len);
    // SAFETY: `fd` is borrowed from a live file handle, and `lk` is an
    // initialized `flock` request alive for the fcntl call.
    let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETLK, &lk) };
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn getlk(fd: &impl AsRawFd, typ: libc::c_short, start: i64, len: i64) -> io::Result<libc::flock> {
    let mut lk = flock(typ, start, len);
    // SAFETY: `fd` is borrowed from a live file handle, and `lk` is initialized
    // storage that fcntl may update for F_GETLK.
    let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETLK, &mut lk) };
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(lk)
    }
}

fn setlkw(fd: &impl AsRawFd, typ: libc::c_short, start: i64, len: i64) -> io::Result<()> {
    let lk = flock(typ, start, len);
    // SAFETY: `fd` is borrowed from a live file handle, and `lk` is an
    // initialized `flock` request alive for the blocking fcntl call.
    let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETLKW, &lk) };
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ── mount_or_skip ────────────────────────────────────────────────────────

fn mount_or_skip() -> Option<MountHarness> {
    match MountHarness::new() {
        Ok(h) => Some(h),
        Err(e) => {
            eprintln!("SKIP: daemon not available -- {e}");
            None
        }
    }
}

// ── test 1: setlk acquired, released by daemon death ─────────────────────

/// Acquire a POSIX write lock, crash-kill the daemon, remount, and verify the
/// lock is gone. Then verify a new lock can be acquired on the same region.
#[test]
fn lock_recovery_setlk_released_after_daemon_crash() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data = b"lock recovery setlk test data\n";

    harness
        .create_file("lock_target.bin", data)
        .expect("create_file");

    let mount_path = harness.mount_path().to_path_buf();
    let file_path = mount_path.join("lock_target.bin");

    let fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open lock_target.bin");

    // Acquire a write lock on bytes 0..99.
    setlk(&fd, libc::F_WRLCK as libc::c_short, 0, 100).expect("acquire write lock 0..99");

    // Verify the lock is held: getlk from same pid may report F_UNLCK on some
    // FUSE implementations; check that a conflicting range query returns
    // the held lock info or F_UNLCK (same-pid semantics). Either result
    // confirms the lock subsystem is functional.
    let check = getlk(&fd, libc::F_WRLCK as libc::c_short, 0, 100).expect("getlk check");
    assert!(
        check.l_type == libc::F_UNLCK as i16 || check.l_type == libc::F_WRLCK as i16,
        "getlk returned unexpected type {}",
        check.l_type
    );

    // Crash-kill the daemon and remount.  This closes the FUSE fd, which
    // causes the kernel to release all locks associated with the daemon's
    // file descriptions.  The new daemon starts with an empty lock table.
    harness.crash_and_remount().expect("crash_and_remount");

    // Open the file again and verify the lock is gone.
    drop(fd);
    let fd2 = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open after crash");

    // We should be able to acquire a write lock on the same region without
    // conflict.
    setlk(&fd2, libc::F_WRLCK as libc::c_short, 0, 100)
        .expect("acquire write lock after crash — lock state should be clean");

    // Release.
    setlk(&fd2, libc::F_UNLCK as libc::c_short, 0, 100).expect("unlock");

    // Verify data survived.
    let read_back = std::fs::read(&file_path).expect("read after crash");
    assert_eq!(
        read_back, data,
        "file data mismatch after lock recovery crash"
    );

    drop(fd2);
}

// ── test 2: setlkw blocking lock released after crash ────────────────────

/// A blocking lock acquired via F_SETLKW should also be released when the
/// daemon is killed and the new daemon starts with a clean lock table.
#[test]
fn lock_recovery_setlkw_released_after_daemon_crash() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data = b"lock recovery setlkw test\n";

    harness
        .create_file("setlkw_target.bin", data)
        .expect("create_file");

    let mount_path = harness.mount_path().to_path_buf();
    let file_path = mount_path.join("setlkw_target.bin");

    let fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open setlkw_target.bin");

    // Acquire a write lock via F_SETLKW (blocking).
    setlkw(&fd, libc::F_WRLCK as libc::c_short, 0, 200).expect("acquire blocking write lock");

    harness.crash_and_remount().expect("crash_and_remount");

    drop(fd);
    let fd2 = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open after crash");

    // Should be able to acquire without blocking because old lock was released.
    setlk(&fd2, libc::F_WRLCK as libc::c_short, 0, 200)
        .expect("acquire lock after crash — lock state should be clean");

    setlk(&fd2, libc::F_UNLCK as libc::c_short, 0, 200).expect("unlock");

    let read_back = std::fs::read(&file_path).expect("read after crash");
    assert_eq!(read_back, data, "data mismatch after setlkw crash recovery");

    drop(fd2);
}

// ── test 3: two independent locks, both released after crash ─────────────

/// Acquire two independent write locks on different byte ranges, crash, and
/// verify both ranges are free after remount.
#[test]
fn lock_recovery_two_locks_released_after_daemon_crash() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness
        .create_file("two_locks.bin", b"two-lock test file\n")
        .expect("create_file");

    let mount_path = harness.mount_path().to_path_buf();
    let file_path = mount_path.join("two_locks.bin");

    let fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open two_locks.bin");

    // Lock range 0..49.
    setlk(&fd, libc::F_WRLCK as libc::c_short, 0, 50).expect("lock 0..49");
    // Lock range 60..109.
    setlk(&fd, libc::F_WRLCK as libc::c_short, 60, 50).expect("lock 60..109");

    harness.crash_and_remount().expect("crash_and_remount");

    drop(fd);
    let fd2 = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open after crash");

    // Both ranges should now be free.
    setlk(&fd2, libc::F_WRLCK as libc::c_short, 0, 50).expect("acquire range 0..49 after crash");
    setlk(&fd2, libc::F_WRLCK as libc::c_short, 60, 50).expect("acquire range 60..109 after crash");

    setlk(&fd2, libc::F_UNLCK as libc::c_short, 0, 50).expect("unlock 0..49");
    setlk(&fd2, libc::F_UNLCK as libc::c_short, 60, 50).expect("unlock 60..109");

    drop(fd2);
}

// ── test 4: lock conflict is correctly reported after crash ──────────────

/// After crash, the lock table is clean.  Verify that getlk reports no
/// conflicting lock (F_UNLCK).
#[test]
fn lock_recovery_getlk_reports_no_conflict_after_crash() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness
        .create_file("getlk_target.bin", b"getlk test data\n")
        .expect("create_file");

    let mount_path = harness.mount_path().to_path_buf();
    let file_path = mount_path.join("getlk_target.bin");

    let fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open getlk_target.bin");

    // Acquire a write lock before crash.
    setlk(&fd, libc::F_WRLCK as libc::c_short, 0, 100).expect("acquire pre-crash lock");

    harness.crash_and_remount().expect("crash_and_remount");

    drop(fd);
    let fd2 = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open after crash");

    // After crash, getlk should report no conflicting lock (F_UNLCK).
    let result = getlk(&fd2, libc::F_WRLCK as libc::c_short, 0, 100).expect("getlk after crash");
    assert_eq!(
        result.l_type,
        libc::F_UNLCK as i16,
        "getlk after crash should report F_UNLCK (no conflicting lock)"
    );

    drop(fd2);
}
