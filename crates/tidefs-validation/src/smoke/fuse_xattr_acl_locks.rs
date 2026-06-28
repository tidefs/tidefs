// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE integration smoke: exercises getxattr/setxattr/listxattr/removexattr,
//! POSIX ACL get/set round-trip, and POSIX file locking (getlk/setlk) through
//! a real FUSE mount.
//!
//! Locking tests use a Python subprocess to produce a different PID for
//! cross-process conflict detection.
//!
//! Gated on `feature = "fuse"`.

use crate::mount_harness::MountHarness;
use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::Duration;

use tidefs_posix_acl::{
    decode_posix_acl_xattr, encode_posix_acl_xattr, PosixAclEntry, ACL_GROUP_OBJ, ACL_MASK,
    ACL_OTHER, ACL_USER_OBJ,
};

/// Run the fuse integration smoke sequence.
///
/// Returns `Ok(())` when all non-ignored tests pass; returns an error
/// string when the harness setup or a test assertion fails.
pub fn run_fuse_xattr_acl_locks_integration() -> Result<(), String> {
    let harness = MountHarness::new().map_err(|e| format!("harness setup failed: {e}"))?;

    eprintln!(
        "fuse: mount={} store={} pid={}",
        harness.mount_path().display(),
        harness.store_path().display(),
        harness.daemon_pid(),
    );

    run_locking_tests(&harness)?;
    run_xattr_tests(&harness)?;
    run_acl_tests(&harness)?;

    Ok(())
}

// ── Locking helpers ─────────────────────────────────────────────────────

/// Build a POSIX advisory lock request via `libc::flock`.
fn make_flock(typ: i16, start: i64, len: i64) -> libc::flock {
    libc::flock {
        l_type: typ,
        l_whence: libc::SEEK_SET as i16,
        l_start: start,
        l_len: len,
        l_pid: 0,
    }
}

/// Acquire a lock via `F_SETLK` (non-blocking).
fn fcntl_setlk(fd: &impl AsRawFd, flock: &libc::flock) -> Result<(), i32> {
    // SAFETY: fcntl F_SETLK[W] is a C FFI call; fd is a valid open
    // fd; the flock pointer is a valid stack-local.
    let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETLK, flock) };
    if rc == -1 {
        Err(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    } else {
        Ok(())
    }
}

/// Acquire a lock via `F_SETLKW` (blocking — waits until available).
fn fcntl_setlkw(fd: &impl AsRawFd, flock: &libc::flock) -> Result<(), i32> {
    // SAFETY: fcntl F_SETLK[W] is a C FFI call; fd is a valid open
    // fd; the flock pointer is a valid stack-local.
    let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETLKW, flock) };
    if rc == -1 {
        Err(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    } else {
        Ok(())
    }
}

/// Query a lock via `F_GETLK`.
fn fcntl_getlk(fd: &impl AsRawFd, flock: &libc::flock) -> Result<libc::flock, i32> {
    let mut query = *flock;
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

// ── Subprocess lock holder (Python) ──────────────────────────────────────

/// Spawn a Python process that acquires a write lock via fcntl on
/// `file_path`, signals readiness by creating `ready_path`, holds the
/// lock for `hold_secs` seconds, then releases and exits.
///
/// The lock is acquired on bytes [0, bytes_len).
fn spawn_lock_holder(
    file_path: &Path,
    ready_path: &Path,
    hold_secs: u64,
    bytes_len: u64,
) -> io::Result<std::process::Child> {
    let script = format!(
        r#"
import fcntl, os, struct, time

fd = os.open({file:?}, os.O_RDWR)
try:
    lock = struct.pack('hhllh', fcntl.F_WRLCK, 0, 0, {length}, 0)
    fcntl.fcntl(fd, fcntl.F_SETLK, lock)
    # Signal ready
    with open({ready:?}, 'w') as f:
        f.write('ok')
        f.flush()
    time.sleep({hold_secs})
finally:
    os.close(fd)
"#,
        file = file_path.to_string_lossy(),
        ready = ready_path.to_string_lossy(),
        hold_secs = hold_secs,
        length = bytes_len,
    );
    std::process::Command::new("python3")
        .arg("-c")
        .arg(&script)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| io::Error::other(format!("spawn lock holder: {e}")))
}

/// Wait for a ready-file to appear, polling every 50ms up to `timeout`.
fn wait_for_ready(ready_path: &Path, timeout: Duration) -> io::Result<()> {
    let start = std::time::Instant::now();
    loop {
        if ready_path.exists() {
            let _ = std::fs::read_to_string(ready_path);
            return Ok(());
        }
        if start.elapsed() >= timeout {
            return Err(io::Error::other(format!(
                "timeout waiting for ready file {}",
                ready_path.display()
            )));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ── Locking tests ────────────────────────────────────────────────────────

fn run_locking_tests(harness: &MountHarness) -> Result<(), String> {
    eprintln!("--- locking tests ---");

    test_lock_acquire_and_getlk(harness)?;
    test_lock_cross_process_conflict_detection(harness)?;
    test_lock_cross_process_eagain(harness)?;
    test_lock_unlock_and_reacquire(harness)?;
    test_lock_release_on_close(harness)?;
    test_lock_setlkw_blocks_and_succeeds(harness)?;

    Ok(())
}

/// Acquire a write lock and verify getlk returns no conflict on a
/// non-overlapping range (same PID — own lock is invisible).
fn test_lock_acquire_and_getlk(harness: &MountHarness) -> Result<(), String> {
    let path = "lock_test_acquire.bin";
    harness
        .create_file(path, b"abcdefghijklmnopqrstuvwxyz")
        .map_err(|e| format!("create lock file: {e}"))?;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(harness.mount_path().join(path))
        .map_err(|e| format!("open lock file: {e}"))?;

    // Acquire write lock on bytes 0-9.
    let write_lock = make_flock(libc::F_WRLCK as i16, 0, 10);
    fcntl_setlk(&file, &write_lock).map_err(|e| format!("acquire write lock: errno={e}"))?;

    // Query a non-overlapping range: same PID, so returns F_UNLCK.
    // This is correct POSIX behaviour — a process doesn't see its
    // own locks as conflicting.
    let query = make_flock(libc::F_WRLCK as i16, 20, 10);
    let result =
        fcntl_getlk(&file, &query).map_err(|e| format!("getlk non-overlapping: errno={e}"))?;

    if result.l_type != libc::F_UNLCK as i16 {
        return Err(format!(
            "getlk on non-overlapping range (same PID): expected F_UNLCK, got type={} pid={}",
            result.l_type, result.l_pid
        ));
    }

    eprintln!("  PASS: lock_acquire_and_getlk");
    Ok(())
}

/// Verify that getlk reports the conflicting lock when a **different
/// process** (Python subprocess) holds a write lock and our process
/// queries an overlapping range.
fn test_lock_cross_process_conflict_detection(harness: &MountHarness) -> Result<(), String> {
    let rel_path = "lock_test_conflict.bin";
    harness
        .create_file(rel_path, b"some data for lock conflict test")
        .map_err(|e| format!("create lock file: {e}"))?;

    let file_path = harness.mount_path().join(rel_path);
    let ready_path = harness.mount_path().join("lock_holder_ready");

    // Subprocess holds a write lock on bytes 0-99.
    let mut holder = spawn_lock_holder(&file_path, &ready_path, 8, 100)
        .map_err(|e| format!("spawn lock holder: {e}"))?;

    wait_for_ready(&ready_path, Duration::from_secs(5))
        .map_err(|e| format!("lock holder did not become ready: {e}"))?;

    // Query from this process (different PID) — should see a conflict.
    let querier = std::fs::File::open(&file_path).map_err(|e| format!("open querier fd: {e}"))?;

    let query = make_flock(libc::F_WRLCK as i16, 50, 20);
    let result =
        fcntl_getlk(&querier, &query).map_err(|e| format!("getlk conflicting: errno={e}"))?;

    // Clean up holder before checking result.
    let _ = holder.kill();
    let _ = holder.wait();
    let _ = std::fs::remove_file(&ready_path);

    if result.l_type != libc::F_WRLCK as i16 {
        return Err(format!(
            "getlk on overlapping range (cross-process): expected F_WRLCK, got type={}",
            result.l_type
        ));
    }

    eprintln!("  PASS: lock_cross_process_conflict_detection");
    Ok(())
}

/// Verify setlk returns EAGAIN (or EACCES) when a **different process**
/// holds a conflicting write lock.
fn test_lock_cross_process_eagain(harness: &MountHarness) -> Result<(), String> {
    let rel_path = "lock_test_eagain.bin";
    harness
        .create_file(rel_path, b"eagain lock test data here")
        .map_err(|e| format!("create lock file: {e}"))?;

    let file_path = harness.mount_path().join(rel_path);
    let ready_path = harness.mount_path().join("lock_holder_eagain_ready");

    // Subprocess holds a write lock on bytes 0-49.
    let mut holder = spawn_lock_holder(&file_path, &ready_path, 8, 50)
        .map_err(|e| format!("spawn lock holder: {e}"))?;

    wait_for_ready(&ready_path, Duration::from_secs(5))
        .map_err(|e| format!("lock holder not ready: {e}"))?;

    // Now from this process (different PID), try to acquire overlapping lock.
    let competitor = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .map_err(|e| format!("open competitor fd: {e}"))?;

    let conflicting = make_flock(libc::F_WRLCK as i16, 0, 50);
    let err = fcntl_setlk(&competitor, &conflicting).expect_err("setlk should fail with conflict");

    // Clean up holder before checking result.
    let _ = holder.kill();
    let _ = holder.wait();
    let _ = std::fs::remove_file(&ready_path);

    if err != libc::EAGAIN && err != libc::EACCES {
        return Err(format!(
            "setlk conflict (cross-process): expected EAGAIN(11)/EACCES(13), got errno={err}"
        ));
    }

    eprintln!("  PASS: lock_cross_process_eagain");
    Ok(())
}

/// Verify unlock (F_UNLCK) releases the range and allows re-acquire
/// from a different file descriptor in the same process.
fn test_lock_unlock_and_reacquire(harness: &MountHarness) -> Result<(), String> {
    let path = "lock_test_unlock.bin";
    harness
        .create_file(path, b"unlock reacquire test data")
        .map_err(|e| format!("create lock file: {e}"))?;

    let fd1 = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(harness.mount_path().join(path))
        .map_err(|e| format!("open fd1: {e}"))?;

    // Acquire write lock on bytes 0-99.
    let lock = make_flock(libc::F_WRLCK as i16, 0, 100);
    fcntl_setlk(&fd1, &lock).map_err(|e| format!("fd1 acquire write lock: errno={e}"))?;

    // Unlock.
    let unlock = make_flock(libc::F_UNLCK as i16, 0, 100);
    fcntl_setlk(&fd1, &unlock).map_err(|e| format!("fd1 unlock: errno={e}"))?;

    // Another fd should now acquire the same range.
    let fd2 = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(harness.mount_path().join(path))
        .map_err(|e| format!("open fd2: {e}"))?;

    fcntl_setlk(&fd2, &lock).map_err(|e| format!("fd2 reacquire after unlock: errno={e}"))?;

    eprintln!("  PASS: lock_unlock_and_reacquire");
    Ok(())
}

/// Verify lock release on file close (implicit unlock via the kernel
/// releasing all locks held by that fd).
fn test_lock_release_on_close(harness: &MountHarness) -> Result<(), String> {
    let path = "lock_test_close.bin";
    harness
        .create_file(path, b"close releases lock test")
        .map_err(|e| format!("create lock file: {e}"))?;

    let fd1 = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(harness.mount_path().join(path))
        .map_err(|e| format!("open fd1: {e}"))?;

    // Acquire write lock.
    let lock = make_flock(libc::F_WRLCK as i16, 0, 50);
    fcntl_setlk(&fd1, &lock).map_err(|e| format!("fd1 acquire write lock: errno={e}"))?;

    // Close fd1 to release the lock.
    drop(fd1);

    // New fd should now acquire the same range.
    let fd2 = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(harness.mount_path().join(path))
        .map_err(|e| format!("open fd2 after close: {e}"))?;

    fcntl_setlk(&fd2, &lock).map_err(|e| format!("fd2 acquire after fd1 close: errno={e}"))?;

    eprintln!("  PASS: lock_release_on_close");
    Ok(())
}

/// Verify that `F_SETLKW` blocks until a conflicting lock is released
/// by a different process, then succeeds.
fn test_lock_setlkw_blocks_and_succeeds(harness: &MountHarness) -> Result<(), String> {
    let path = "lock_test_setlkw.bin";
    harness
        .create_file(path, b"setlkw blocking test data")
        .map_err(|e| format!("create lock file: {e}"))?;

    let file_path = harness.mount_path().join(path);
    let ready_path = harness.mount_path().join("lock_holder_setlkw_ready");

    // Subprocess holds a write lock on bytes 0-99 for 2 seconds.
    let mut holder = spawn_lock_holder(&file_path, &ready_path, 2, 100)
        .map_err(|e| format!("spawn lock holder: {e}"))?;

    wait_for_ready(&ready_path, Duration::from_secs(5))
        .map_err(|e| format!("lock holder not ready: {e}"))?;

    // Call F_SETLKW from this process in a separate thread — it should
    // block until the subprocess releases (after ~2 seconds).
    let blocker = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .map_err(|e| format!("open blocker fd: {e}"))?;

    let start = std::time::Instant::now();
    let blocking_lock = make_flock(libc::F_WRLCK as i16, 0, 100);

    let handle = std::thread::spawn(move || fcntl_setlkw(&blocker, &blocking_lock));

    let result = handle
        .join()
        .map_err(|_| "setlkw thread panicked".to_string())?;
    let elapsed = start.elapsed();

    let _ = holder.wait();
    let _ = std::fs::remove_file(&ready_path);

    result.map_err(|errno| format!("setlkw failed with errno={errno}"))?;

    if elapsed < Duration::from_secs(1) {
        return Err(format!(
            "setlkw returned too quickly ({:.1?}); expected blocking delay >= 1s",
            elapsed
        ));
    }

    eprintln!(
        "  PASS: lock_setlkw_blocks_and_succeeds (blocked for {:.1?})",
        elapsed
    );
    Ok(())
}

// ── Xattr integration helpers ───────────────────────────────────────────

/// Run all xattr integration tests against `harness`.
fn run_xattr_tests(harness: &MountHarness) -> Result<(), String> {
    eprintln!("--- xattr tests ---");

    test_xattr_set_get_roundtrip(harness)?;
    test_xattr_empty_value_roundtrip(harness)?;
    test_xattr_list_all_set_names(harness)?;
    test_xattr_remove_then_get_returns_enodata(harness)?;
    test_xattr_create_flag_fails_on_existing(harness)?;
    test_xattr_replace_flag_fails_on_missing(harness)?;

    Ok(())
}

fn test_xattr_set_get_roundtrip(harness: &MountHarness) -> Result<(), String> {
    harness
        .create_file("xattr_test.txt", b"xattr roundtrip")
        .map_err(|e| format!("create file: {e}"))?;
    harness
        .set_xattr("xattr_test.txt", "test", b"hello")
        .map_err(|e| format!("set_xattr: {e}"))?;
    let val = harness
        .get_xattr("xattr_test.txt", "test")
        .map_err(|e| format!("get_xattr: {e}"))?;
    if val != Some(b"hello".to_vec()) {
        return Err(format!("expected Some(b\"hello\"), got {val:?}"));
    }
    eprintln!("  PASS: xattr_set_get_roundtrip");
    Ok(())
}

fn test_xattr_empty_value_roundtrip(harness: &MountHarness) -> Result<(), String> {
    harness
        .create_file("xattr_empty.txt", b"empty xattr test")
        .map_err(|e| format!("create file: {e}"))?;
    harness
        .set_xattr("xattr_empty.txt", "empty", b"")
        .map_err(|e| format!("set empty xattr: {e}"))?;
    let val = harness
        .get_xattr("xattr_empty.txt", "empty")
        .map_err(|e| format!("get empty xattr: {e}"))?;
    if val != Some(b"".to_vec()) {
        return Err(format!("expected Some(b\"\"), got {val:?}"));
    }
    eprintln!("  PASS: xattr_empty_value_roundtrip");
    Ok(())
}

fn test_xattr_list_all_set_names(harness: &MountHarness) -> Result<(), String> {
    harness
        .create_file("xattr_list.txt", b"list test")
        .map_err(|e| format!("create file: {e}"))?;
    harness
        .set_xattr("xattr_list.txt", "alpha", b"1")
        .map_err(|e| format!("set alpha: {e}"))?;
    harness
        .set_xattr("xattr_list.txt", "beta", b"2")
        .map_err(|e| format!("set beta: {e}"))?;
    let mut names = harness
        .list_xattr("xattr_list.txt")
        .map_err(|e| format!("list_xattr: {e}"))?;
    names.sort();
    if names != vec!["alpha", "beta"] {
        return Err(format!("expected [\"alpha\", \"beta\"], got {names:?}"));
    }
    eprintln!("  PASS: xattr_list_all_set_names");
    Ok(())
}

fn test_xattr_remove_then_get_returns_enodata(harness: &MountHarness) -> Result<(), String> {
    harness
        .create_file("xattr_remove.txt", b"remove test")
        .map_err(|e| format!("create file: {e}"))?;
    harness
        .set_xattr("xattr_remove.txt", "delme", b"val")
        .map_err(|e| format!("set xattr: {e}"))?;
    harness
        .remove_xattr("xattr_remove.txt", "delme")
        .map_err(|e| format!("remove xattr: {e}"))?;
    let val = harness
        .get_xattr("xattr_remove.txt", "delme")
        .map_err(|e| format!("get after remove: {e}"))?;
    if val != None {
        return Err(format!("expected None after remove, got {val:?}"));
    }
    eprintln!("  PASS: xattr_remove_then_get_returns_enodata");
    Ok(())
}

fn test_xattr_create_flag_fails_on_existing(harness: &MountHarness) -> Result<(), String> {
    harness
        .create_file("xattr_create.txt", b"create flag test")
        .map_err(|e| format!("create file: {e}"))?;

    let full_path = harness.mount_path().join("xattr_create.txt");
    let path_c = CString::new(full_path.as_os_str().as_bytes())
        .map_err(|_| "path contains nul byte".to_string())?;
    let name_c =
        CString::new("user.create_test").map_err(|_| "name contains nul byte".to_string())?;

    // SAFETY: setxattr is a C FFI call; path and name CStrings are valid;
    // value is a valid slice.
    let rc = unsafe {
        libc::setxattr(
            path_c.as_ptr(),
            name_c.as_ptr(),
            b"first".as_ptr() as *const libc::c_void,
            5,
            0,
        )
    };
    if rc != 0 {
        return Err(format!(
            "first setxattr failed: {}",
            io::Error::last_os_error()
        ));
    }

    // SAFETY: setxattr is a C FFI call; all pointers valid.
    let rc2 = unsafe {
        libc::setxattr(
            path_c.as_ptr(),
            name_c.as_ptr(),
            b"second".as_ptr() as *const libc::c_void,
            6,
            libc::XATTR_CREATE as i32,
        )
    };
    if rc2 == 0 {
        return Err("setxattr with XATTR_CREATE on existing attr should fail".into());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() != Some(libc::EEXIST) {
        return Err(format!(
            "XATTR_CREATE should return EEXIST, got {:?}",
            err.raw_os_error()
        ));
    }
    eprintln!("  PASS: xattr_create_flag_fails_on_existing");
    Ok(())
}

fn test_xattr_replace_flag_fails_on_missing(harness: &MountHarness) -> Result<(), String> {
    harness
        .create_file("xattr_replace.txt", b"replace flag test")
        .map_err(|e| format!("create file: {e}"))?;

    let full_path = harness.mount_path().join("xattr_replace.txt");
    let path_c = CString::new(full_path.as_os_str().as_bytes())
        .map_err(|_| "path contains nul byte".to_string())?;
    let name_c =
        CString::new("user.replace_test").map_err(|_| "name contains nul byte".to_string())?;

    // SAFETY: setxattr is a C FFI call; path and name CStrings are valid;
    // value is a valid slice.
    let rc = unsafe {
        libc::setxattr(
            path_c.as_ptr(),
            name_c.as_ptr(),
            b"val".as_ptr() as *const libc::c_void,
            3,
            libc::XATTR_REPLACE as i32,
        )
    };
    if rc == 0 {
        return Err("setxattr with XATTR_REPLACE on missing attr should fail".into());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() != Some(libc::ENODATA) {
        return Err(format!(
            "XATTR_REPLACE should return ENODATA, got {:?}",
            err.raw_os_error()
        ));
    }
    eprintln!("  PASS: xattr_replace_flag_fails_on_missing");
    Ok(())
}

// ── ACL integration helpers ─────────────────────────────────────────────

/// Run all ACL integration tests against `harness`.
fn run_acl_tests(harness: &MountHarness) -> Result<(), String> {
    eprintln!("--- ACL tests ---");

    test_acl_access_get_set_roundtrip(harness)?;
    test_acl_default_on_directory(harness)?;
    test_posix_acl_access_valid_accepted_invalid_rejected(harness)?;
    test_posix_acl_enforcement_denies_nonowner_access(harness)?;
    test_posix_acl_default_roundtrip(harness)?;

    Ok(())
}

fn test_acl_access_get_set_roundtrip(harness: &MountHarness) -> Result<(), String> {
    harness
        .create_file("acl_test.txt", b"acl roundtrip")
        .map_err(|e| format!("create file: {e}"))?;

    let acl = vec![
        PosixAclEntry {
            tag: ACL_USER_OBJ,
            perm: 7,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_GROUP_OBJ,
            perm: 5,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_MASK,
            perm: 5,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_OTHER,
            perm: 0,
            id: 0,
        },
    ];
    let encoded = encode_posix_acl_xattr(&acl);
    harness
        .set_xattr("acl_test.txt", "posix_acl_access_value_test", &encoded)
        .map_err(|e| format!("set ACL xattr: {e}"))?;

    let val = harness
        .get_xattr("acl_test.txt", "posix_acl_access_value_test")
        .map_err(|e| format!("get ACL xattr: {e}"))?
        .ok_or("ACL xattr value missing".to_string())?;
    let decoded = decode_posix_acl_xattr(&val).map_err(|e| format!("decode ACL xattr: {e:?}"))?;
    if decoded.len() != 4 {
        return Err(format!("expected 4 entries, got {}", decoded.len()));
    }
    if decoded[0].perm != 7 {
        return Err(format!("expected perm=7, got {}", decoded[0].perm));
    }
    eprintln!("  PASS: acl_access_get_set_roundtrip");
    Ok(())
}

fn test_acl_default_on_directory(harness: &MountHarness) -> Result<(), String> {
    harness
        .mkdir("acl_dir")
        .map_err(|e| format!("mkdir: {e}"))?;

    let acl = vec![
        PosixAclEntry {
            tag: ACL_USER_OBJ,
            perm: 7,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_GROUP_OBJ,
            perm: 5,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_MASK,
            perm: 5,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_OTHER,
            perm: 0,
            id: 0,
        },
    ];
    let encoded = encode_posix_acl_xattr(&acl);
    harness
        .set_xattr("acl_dir", "posix_acl_default_value_test", &encoded)
        .map_err(|e| format!("set default ACL xattr: {e}"))?;

    let val = harness
        .get_xattr("acl_dir", "posix_acl_default_value_test")
        .map_err(|e| format!("get default ACL xattr: {e}"))?
        .ok_or("default ACL xattr value missing".to_string())?;
    let decoded =
        decode_posix_acl_xattr(&val).map_err(|e| format!("decode default ACL xattr: {e:?}"))?;
    if decoded.len() != 4 {
        return Err(format!("expected 4 entries, got {}", decoded.len()));
    }
    eprintln!("  PASS: acl_default_on_directory");
    Ok(())
}

fn test_posix_acl_access_valid_accepted_invalid_rejected(
    harness: &MountHarness,
) -> Result<(), String> {
    harness
        .create_file("acl_enforce.txt", b"ACL enforcement test")
        .map_err(|e| format!("create file: {e}"))?;

    let full_path = harness.mount_path().join("acl_enforce.txt");
    let path_c = CString::new(full_path.as_os_str().as_bytes())
        .map_err(|_| "path contains nul byte".to_string())?;

    let valid_acl = vec![
        PosixAclEntry {
            tag: ACL_USER_OBJ,
            perm: 6,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_GROUP_OBJ,
            perm: 0,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_MASK,
            perm: 0,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_OTHER,
            perm: 0,
            id: 0,
        },
    ];
    let valid_encoded = encode_posix_acl_xattr(&valid_acl);
    let acl_name = CString::new("system.posix_acl_access")
        .map_err(|_| "name contains nul byte".to_string())?;

    // SAFETY: setxattr is a C FFI call; path and name CStrings are valid;
    // value is a valid slice.
    let rc = unsafe {
        libc::setxattr(
            path_c.as_ptr(),
            acl_name.as_ptr(),
            valid_encoded.as_ptr() as *const libc::c_void,
            valid_encoded.len(),
            0,
        )
    };
    if rc != 0 {
        return Err(format!(
            "valid ACL set should succeed, got errno={:?}",
            io::Error::last_os_error().raw_os_error()
        ));
    }

    // SAFETY: getxattr with null buf queries attribute size per POSIX.
    let size =
        unsafe { libc::getxattr(path_c.as_ptr(), acl_name.as_ptr(), std::ptr::null_mut(), 0) };
    if size <= 0 {
        return Err("valid ACL should be readable".into());
    }
    let mut buf = vec![0u8; size as usize];
    // SAFETY: getxattr is a C FFI call; path and name are valid CStrings;
    // buf size matches the prior size query result.
    let rc2 = unsafe {
        libc::getxattr(
            path_c.as_ptr(),
            acl_name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if rc2 != size {
        return Err("valid ACL read should match size".into());
    }
    buf.truncate(rc2 as usize);
    let decoded = decode_posix_acl_xattr(&buf).map_err(|e| format!("decode valid ACL: {e:?}"))?;
    if decoded.len() != 4 {
        return Err(format!("expected 4 entries, got {}", decoded.len()));
    }

    let garbage: &[u8] = b"garbage_not_an_acl";
    // SAFETY: setxattr is a C FFI call; all pointers valid.
    let rc3 = unsafe {
        libc::setxattr(
            path_c.as_ptr(),
            acl_name.as_ptr(),
            garbage.as_ptr() as *const libc::c_void,
            garbage.len(),
            0,
        )
    };
    if rc3 == 0 {
        return Err("garbage ACL payload should be rejected".into());
    }
    let err_code = io::Error::last_os_error().raw_os_error();
    if err_code != Some(libc::EINVAL) && err_code != Some(libc::EOPNOTSUPP) {
        return Err(format!(
            "garbage ACL should be rejected (EINVAL or EOPNOTSUPP), got errno={err_code:?}"
        ));
    }
    eprintln!("  PASS: posix_acl_access_valid_accepted_invalid_rejected");
    Ok(())
}

fn test_posix_acl_enforcement_denies_nonowner_access(harness: &MountHarness) -> Result<(), String> {
    harness
        .create_file("acl_deny.txt", b"ACL deny test data here")
        .map_err(|e| format!("create file: {e}"))?;

    let full_path = harness.mount_path().join("acl_deny.txt");
    let path_c = CString::new(full_path.as_os_str().as_bytes())
        .map_err(|_| "path contains nul byte".to_string())?;

    let acl = vec![
        PosixAclEntry {
            tag: ACL_USER_OBJ,
            perm: 6,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_GROUP_OBJ,
            perm: 0,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_MASK,
            perm: 0,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_OTHER,
            perm: 0,
            id: 0,
        },
    ];
    let encoded = encode_posix_acl_xattr(&acl);
    let acl_name = CString::new("system.posix_acl_access")
        .map_err(|_| "name contains nul byte".to_string())?;

    // SAFETY: setxattr is a C FFI call; path and name CStrings are valid;
    // value is a valid slice.
    let rc = unsafe {
        libc::setxattr(
            path_c.as_ptr(),
            acl_name.as_ptr(),
            encoded.as_ptr() as *const libc::c_void,
            encoded.len(),
            0,
        )
    };
    if rc != 0 {
        return Err(format!(
            "setting system.posix_acl_access should succeed, got errno={:?}",
            io::Error::last_os_error().raw_os_error()
        ));
    }

    let script = format!(
        r#"
import os, sys
os.seteuid(65534)
try:
    fd = os.open({path:?}, os.O_RDONLY)
    os.close(fd)
    sys.exit(1)
except PermissionError:
    sys.exit(0)
except OSError as e:
    if e.errno == 13:
        sys.exit(0)
    sys.exit(2)
"#,
        path = full_path.to_string_lossy(),
    );
    let output = std::process::Command::new("python3")
        .arg("-c")
        .arg(&script)
        .output()
        .map_err(|e| format!("spawn ACL enforcement subprocess: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "non-owner should be denied access by POSIX ACL; stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }

    std::fs::File::open(&full_path)
        .map_err(|e| format!("root should bypass ACL and open file: {e}"))?;

    eprintln!("  PASS: posix_acl_enforcement_denies_nonowner_access");
    Ok(())
}

fn test_posix_acl_default_roundtrip(harness: &MountHarness) -> Result<(), String> {
    harness
        .mkdir("acl_def_dir")
        .map_err(|e| format!("mkdir: {e}"))?;

    let full_path = harness.mount_path().join("acl_def_dir");
    let path_c = CString::new(full_path.as_os_str().as_bytes())
        .map_err(|_| "path contains nul byte".to_string())?;

    let acl = vec![
        PosixAclEntry {
            tag: ACL_USER_OBJ,
            perm: 7,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_GROUP_OBJ,
            perm: 5,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_MASK,
            perm: 5,
            id: 0,
        },
        PosixAclEntry {
            tag: ACL_OTHER,
            perm: 0,
            id: 0,
        },
    ];
    let encoded = encode_posix_acl_xattr(&acl);
    let name_c = CString::new("system.posix_acl_default")
        .map_err(|_| "name contains nul byte".to_string())?;

    // SAFETY: setxattr is a C FFI call; path and name CStrings are valid;
    // value is a valid slice.
    let rc = unsafe {
        libc::setxattr(
            path_c.as_ptr(),
            name_c.as_ptr(),
            encoded.as_ptr() as *const libc::c_void,
            encoded.len(),
            0,
        )
    };
    if rc != 0 {
        return Err(format!(
            "set system.posix_acl_default should succeed, got errno={:?}",
            io::Error::last_os_error().raw_os_error()
        ));
    }

    // SAFETY: getxattr with null buf and size=0 returns required size per POSIX.
    let size = unsafe { libc::getxattr(path_c.as_ptr(), name_c.as_ptr(), std::ptr::null_mut(), 0) };
    if size <= 0 {
        return Err("default ACL should be readable".into());
    }
    let mut buf = vec![0u8; size as usize];
    // SAFETY: `path_c` and `name_c` remain live C strings, and `buf` is
    // allocated to the size reported by the preceding getxattr query.
    let rc2 = unsafe {
        libc::getxattr(
            path_c.as_ptr(),
            name_c.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if rc2 != size {
        return Err("default ACL read should match size".into());
    }
    buf.truncate(rc2 as usize);
    let decoded = decode_posix_acl_xattr(&buf).map_err(|e| format!("decode default ACL: {e:?}"))?;
    if decoded.len() != 4 {
        return Err(format!("expected 4 entries, got {}", decoded.len()));
    }
    if decoded[0].perm != 7 {
        return Err(format!("expected perm=7, got {}", decoded[0].perm));
    }
    eprintln!("  PASS: posix_acl_default_roundtrip");
    Ok(())
}

// ── Xattr and ACL tests (thin #[test] wrappers) ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Locking tests (should pass immediately) ────────────────────────

    #[test]
    fn locking_acquire_and_getlk() {
        let harness = MountHarness::new().expect("harness setup");
        test_lock_acquire_and_getlk(&harness).expect("lock acquire and getlk");
    }

    #[test]
    fn locking_cross_process_conflict_detection() {
        let harness = MountHarness::new().expect("harness setup");
        test_lock_cross_process_conflict_detection(&harness)
            .expect("cross-process conflict detection");
    }

    #[test]
    fn locking_cross_process_eagain() {
        let harness = MountHarness::new().expect("harness setup");
        test_lock_cross_process_eagain(&harness).expect("cross-process setlk eagain");
    }

    #[test]
    fn locking_unlock_and_reacquire() {
        let harness = MountHarness::new().expect("harness setup");
        test_lock_unlock_and_reacquire(&harness).expect("lock unlock and reacquire");
    }

    #[test]
    fn locking_release_on_close() {
        let harness = MountHarness::new().expect("harness setup");
        test_lock_release_on_close(&harness).expect("lock release on close");
    }

    #[test]
    fn locking_setlkw_blocks_and_succeeds() {
        let harness = MountHarness::new().expect("harness setup");
        test_lock_setlkw_blocks_and_succeeds(&harness).expect("setlkw blocking");
    }

    // ── Xattr tests (initially #[ignore]) ───────────────────────────

    #[test]
    fn xattr_set_get_roundtrip() {
        let harness = MountHarness::new().expect("harness setup");
        test_xattr_set_get_roundtrip(&harness).expect("xattr set/get roundtrip");
    }

    #[test]
    fn xattr_empty_value_roundtrip() {
        let harness = MountHarness::new().expect("harness setup");
        test_xattr_empty_value_roundtrip(&harness).expect("xattr empty value roundtrip");
    }

    #[test]
    fn xattr_list_all_set_names() {
        let harness = MountHarness::new().expect("harness setup");
        test_xattr_list_all_set_names(&harness).expect("xattr list all set names");
    }

    #[test]
    fn xattr_remove_then_get_returns_enodata() {
        let harness = MountHarness::new().expect("harness setup");
        test_xattr_remove_then_get_returns_enodata(&harness).expect("xattr remove then get");
    }

    #[test]
    fn xattr_create_flag_fails_on_existing() {
        let harness = MountHarness::new().expect("harness setup");
        test_xattr_create_flag_fails_on_existing(&harness).expect("xattr create flag fails");
    }

    #[test]
    fn xattr_replace_flag_fails_on_missing() {
        let harness = MountHarness::new().expect("harness setup");
        test_xattr_replace_flag_fails_on_missing(&harness).expect("xattr replace flag fails");
    }

    // ── ACL tests (initially #[ignore]) ─────────────────────────────

    #[test]
    fn acl_access_get_set_roundtrip() {
        let harness = MountHarness::new().expect("harness setup");
        test_acl_access_get_set_roundtrip(&harness).expect("acl access get/set roundtrip");
    }

    #[test]
    fn acl_default_on_directory() {
        let harness = MountHarness::new().expect("harness setup");
        test_acl_default_on_directory(&harness).expect("acl default on directory");
    }

    // ── POSIX ACL enforcement through kernel (system.posix_acl_access) ──

    #[test]
    fn posix_acl_access_valid_accepted_invalid_rejected() {
        let harness = MountHarness::new().expect("harness setup");
        test_posix_acl_access_valid_accepted_invalid_rejected(&harness)
            .expect("posix acl access valid accepted invalid rejected");
    }

    #[test]
    fn posix_acl_enforcement_denies_nonowner_access() {
        let harness = MountHarness::new().expect("harness setup");
        test_posix_acl_enforcement_denies_nonowner_access(&harness)
            .expect("posix acl enforcement denies nonowner access");
    }

    #[test]
    fn posix_acl_default_roundtrip() {
        let harness = MountHarness::new().expect("harness setup");
        test_posix_acl_default_roundtrip(&harness).expect("posix acl default roundtrip");
    }

    // ── Unified integration runner test ───────────────────────────────

    #[test]
    fn full_xattr_acl_locks_integration_cycle() {
        run_fuse_xattr_acl_locks_integration().expect("full xattr-acl-locks integration cycle");
    }
}
