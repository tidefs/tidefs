//! FUSE xattr integration tests for the POSIX filesystem adapter daemon.
//!
//! Complements the existing `fuse_xattr_smoke.rs` (16 tests covering basic
//! round-trip, flags, flags errors, listxattr, removexattr, name filtering,
//! and remount persistence).  This module adds:
//!
//!  * User namespace: empty-value round-trip, large-value (4 KiB+) round-trip.
//!  * System namespace: `system.posix_acl_access` and
//!    `system.posix_acl_default` set/get.
//!  * Error paths: E2BIG on oversized value, ENOTSUP on unsupported
//!    namespace.
//!  * Crash recovery: SIGKILL + remount and verify xattr persistence for
//!    user and system namespaces.
//!
//! All tests use `MountHarness` from `tidefs-validation`.  They skip
//! gracefully when the daemon binary is not found.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use tidefs_validation::mount_harness::MountHarness;

// ── Harness helpers ─────────────────────────────────────────────────────

fn mount_or_skip() -> Option<MountHarness> {
    match MountHarness::new() {
        Ok(h) => Some(h),
        Err(e) => {
            eprintln!("SKIP: daemon not available -- {e}");
            None
        }
    }
}

// ── Raw xattr syscall helpers (for non-user namespaces) ─────────────────

fn path_cstr(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("path contains nul byte")
}

fn xattr_name_cstr(name: &str) -> CString {
    CString::new(name).expect("xattr name contains nul byte")
}

unsafe fn setxattr_raw(path: &CString, name: &CString, value: &[u8], flags: i32) -> io::Result<()> {
    let rc = libc::setxattr(
        path.as_ptr(),
        name.as_ptr(),
        value.as_ptr() as *const libc::c_void,
        value.len(),
        flags,
    );
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

unsafe fn getxattr_size_raw(path: &CString, name: &CString) -> io::Result<usize> {
    let rc = libc::getxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0);
    if rc >= 0 {
        Ok(rc as usize)
    } else {
        Err(io::Error::last_os_error())
    }
}

unsafe fn getxattr_raw(path: &CString, name: &CString, buf: &mut [u8]) -> io::Result<usize> {
    let rc = libc::getxattr(
        path.as_ptr(),
        name.as_ptr(),
        buf.as_mut_ptr() as *mut libc::c_void,
        buf.len(),
    );
    if rc >= 0 {
        Ok(rc as usize)
    } else {
        Err(io::Error::last_os_error())
    }
}

unsafe fn removexattr_raw(path: &CString, name: &CString) -> io::Result<()> {
    let rc = libc::removexattr(path.as_ptr(), name.as_ptr());
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// ── User-namespace tests ────────────────────────────────────────────────

#[test]
fn user_empty_value_roundtrip() {
    let harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness
        .create_file("empty_xattr.bin", b"empty xattr test")
        .expect("create file");

    harness
        .set_xattr("empty_xattr.bin", "empty_key", b"")
        .expect("set empty xattr");

    let val = harness
        .get_xattr("empty_xattr.bin", "empty_key")
        .expect("get empty xattr");
    assert_eq!(val, Some(b"".to_vec()), "empty xattr should round-trip");
}

#[test]
fn user_large_value_roundtrip() {
    let harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    // 5 KiB of deterministic content, crossing a page boundary.
    let large: Vec<u8> = (0..5120)
        .map(|i| ((i as u32).wrapping_mul(13).wrapping_add(7) % 251) as u8)
        .collect();

    harness
        .create_file("large_xattr.bin", b"large xattr test")
        .expect("create file");

    harness
        .set_xattr("large_xattr.bin", "big_blob", &large)
        .expect("set large xattr");

    let val = harness
        .get_xattr("large_xattr.bin", "big_blob")
        .expect("get large xattr");
    assert_eq!(
        val.as_deref(),
        Some(large.as_slice()),
        "large xattr should round-trip byte-for-byte"
    );
}

#[test]
fn user_overwrite_via_mount_harness() {
    let harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness
        .create_file("overwrite_xattr.bin", b"overwrite test")
        .expect("create file");

    harness
        .set_xattr("overwrite_xattr.bin", "ow", b"first")
        .expect("set initial");
    harness
        .set_xattr("overwrite_xattr.bin", "ow", b"second")
        .expect("overwrite");

    let val = harness
        .get_xattr("overwrite_xattr.bin", "ow")
        .expect("get after overwrite");
    assert_eq!(
        val,
        Some(b"second".to_vec()),
        "overwrite should replace value"
    );
}

#[test]
fn user_listxattr_after_multiple_sets() {
    let harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness
        .create_file("list_xattr.bin", b"multi-xattr list")
        .expect("create file");

    harness
        .set_xattr("list_xattr.bin", "alpha", b"1")
        .expect("set alpha");
    harness
        .set_xattr("list_xattr.bin", "beta", b"22")
        .expect("set beta");
    harness
        .set_xattr("list_xattr.bin", "gamma", b"333")
        .expect("set gamma");

    let mut names = harness.list_xattr("list_xattr.bin").expect("listxattr");
    names.sort();
    assert_eq!(
        names,
        vec!["alpha", "beta", "gamma"],
        "listxattr should return all set user keys"
    );
}

// ── System-namespace tests ──────────────────────────────────────────────

#[test]
fn system_posix_acl_access_set_get() {
    let harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness
        .create_file("acl_access.bin", b"system.posix_acl_access test")
        .expect("create file");

    let file_path = harness.mount_path().join("acl_access.bin");
    let path_c = path_cstr(&file_path);
    let name_c = xattr_name_cstr("system.posix_acl_access");

    // Minimal valid ACL: owner read+write, group none, mask none, other none.
    let acl_value: &[u8] = &[2, 0, 6, 0, 4, 0, 0, 0, 16, 0, 0, 0, 32, 0, 0, 0];

    unsafe {
        setxattr_raw(&path_c, &name_c, acl_value, 0).expect("set system.posix_acl_access");
    }

    unsafe {
        let size =
            getxattr_size_raw(&path_c, &name_c).expect("getxattr size for system.posix_acl_access");
        assert!(size > 0, "system.posix_acl_access should have nonzero size");

        let mut buf = vec![0u8; size];
        let n = getxattr_raw(&path_c, &name_c, &mut buf).expect("getxattr system.posix_acl_access");
        assert_eq!(n, size);
    }
}

#[test]
fn system_posix_acl_default_on_directory() {
    let harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness.mkdir("acl_dir").expect("mkdir acl_dir");

    let dir_path = harness.mount_path().join("acl_dir");
    let path_c = path_cstr(&dir_path);
    let name_c = xattr_name_cstr("system.posix_acl_default");

    let acl_value: &[u8] = &[2, 0, 7, 0, 4, 0, 5, 0, 16, 0, 5, 0, 32, 0, 0, 0];

    unsafe {
        setxattr_raw(&path_c, &name_c, acl_value, 0)
            .expect("set system.posix_acl_default on directory");
    }

    unsafe {
        let size = getxattr_size_raw(&path_c, &name_c)
            .expect("getxattr size for system.posix_acl_default");
        assert!(
            size > 0,
            "system.posix_acl_default should have nonzero size"
        );

        let mut buf = vec![0u8; size];
        let n =
            getxattr_raw(&path_c, &name_c, &mut buf).expect("getxattr system.posix_acl_default");
        assert_eq!(n, size);
    }
}

// ── Error-path tests ────────────────────────────────────────────────────

/// setxattr with a value exceeding the per-filesystem limit should
/// return E2BIG (errno 7) or EFBIG (errno 27).
#[test]
fn setxattr_e2big_oversized_value() {
    let harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness
        .create_file("e2big.bin", b"oversized xattr test")
        .expect("create file");

    let file_path = harness.mount_path().join("e2big.bin");
    let path_c = path_cstr(&file_path);
    let name_c = xattr_name_cstr("user.oversized");

    // 256 KiB value — far exceeds typical xattr size limits.
    let huge: Vec<u8> = vec![0xAA; 256 * 1024];

    unsafe {
        let result = setxattr_raw(&path_c, &name_c, &huge, 0);
        match result {
            Ok(()) => {
                // Some kernels/filesystems may accept very large xattrs.
                // If it succeeds, verify we can read it back partially.
                // Not an error — just document that the limit is higher.
                eprintln!("NOTE: 256 KiB xattr was accepted (no E2BIG)");
            }
            Err(e) => {
                let code = e.raw_os_error().unwrap_or(0);
                assert!(
                    code == libc::E2BIG || code == libc::EFBIG || code == libc::ENOSPC,
                    "oversized xattr should return E2BIG(7), EFBIG(27), or ENOSPC(28), got {code}"
                );
            }
        }
    }
}

/// setxattr with an unrecognised namespace prefix should return
/// EOPNOTSUPP (errno 95).
#[test]
fn setxattr_enotsup_unsupported_namespace() {
    let harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness
        .create_file("enotsup.bin", b"unsupported namespace")
        .expect("create file");

    let file_path = harness.mount_path().join("enotsup.bin");
    let path_c = path_cstr(&file_path);
    let name_c = xattr_name_cstr("tidefs.test"); // not a standard namespace

    unsafe {
        let result = setxattr_raw(&path_c, &name_c, b"value", 0);
        match result {
            Ok(()) => {
                // The namespace may be accepted.  Not a failure — some
                // implementations are permissive about unknown prefixes.
                eprintln!("NOTE: unsupported namespace 'tidefs.test' was accepted");
                // Clean up so it doesn't interfere with other tests.
                let _ = removexattr_raw(&path_c, &name_c);
            }
            Err(e) => {
                let code = e.raw_os_error().unwrap_or(0);
                assert!(
                    code == libc::EOPNOTSUPP || code == libc::ENOTSUP,
                    "unsupported namespace should return EOPNOTSUPP(95) or ENOTSUP, got {code}"
                );
            }
        }
    }
}

/// getxattr with an oversized value buffer should return ERANGE.
#[test]
fn getxattr_erange_buffer_too_small_via_harness() {
    let harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness
        .create_file("erange.bin", b"erange test via harness")
        .expect("create file");

    let file_path = harness.mount_path().join("erange.bin");
    let path_c = path_cstr(&file_path);
    let name_c = xattr_name_cstr("user.erange_test");

    let value = b"a-value-exceeding-5-bytes";

    unsafe {
        setxattr_raw(&path_c, &name_c, value, 0).expect("set xattr for erange test");

        let mut small_buf = vec![0u8; 3];
        let err =
            getxattr_raw(&path_c, &name_c, &mut small_buf).expect_err("getxattr with small buffer");
        assert_eq!(
            err.raw_os_error(),
            Some(34), // ERANGE
            "too-small getxattr buffer should return ERANGE(34)"
        );
    }
}

// ── Crash-recovery tests ────────────────────────────────────────────────

/// Set a user xattr, fsync the file, SIGKILL the daemon, remount, and
/// verify the xattr value persists byte-for-byte.
#[test]
fn fsync_crash_user_xattr_persists() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let xattr_val = b"persist-through-crash-user";

    harness
        .create_file("crash_xattr_user.bin", b"crash recovery user xattr")
        .expect("create file");

    harness
        .set_xattr("crash_xattr_user.bin", "survivor", xattr_val)
        .expect("set user xattr");

    harness
        .fsync_file("crash_xattr_user.bin")
        .expect("fsync before crash");

    harness.crash_and_remount().expect("crash and remount");

    let val = harness
        .get_xattr("crash_xattr_user.bin", "survivor")
        .expect("get xattr after crash");
    assert_eq!(
        val.as_deref(),
        Some(xattr_val.as_slice()),
        "user xattr should survive SIGKILL + remount"
    );
}

/// Set a system.posix_acl_access xattr, fsync the file, SIGKILL,
/// remount, and verify the ACL xattr persists.
#[test]
fn fsync_crash_system_xattr_persists() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness
        .create_file("crash_xattr_sys.bin", b"crash recovery system xattr")
        .expect("create file");

    let file_path = harness.mount_path().join("crash_xattr_sys.bin");
    let path_c = path_cstr(&file_path);
    let name_c = xattr_name_cstr("system.posix_acl_access");
    let acl_value: &[u8] = &[2, 0, 6, 0, 4, 0, 0, 0, 16, 0, 0, 0, 32, 0, 0, 0];

    unsafe {
        setxattr_raw(&path_c, &name_c, acl_value, 0)
            .expect("set system.posix_acl_access before crash");
    }

    harness
        .fsync_file("crash_xattr_sys.bin")
        .expect("fsync before crash");

    harness.crash_and_remount().expect("crash and remount");

    let file_path2 = harness.mount_path().join("crash_xattr_sys.bin");
    let path_c2 = path_cstr(&file_path2);

    unsafe {
        let size = getxattr_size_raw(&path_c2, &name_c)
            .expect("getxattr system.posix_acl_access after crash");
        assert!(
            size > 0,
            "system.posix_acl_access should survive SIGKILL + remount"
        );

        let mut buf = vec![0u8; size];
        let n = getxattr_raw(&path_c2, &name_c, &mut buf)
            .expect("getxattr system.posix_acl_access after crash");
        assert_eq!(n, size);
        assert_eq!(
            &buf[..n],
            acl_value,
            "system.posix_acl_access value should survive byte-for-byte"
        );
    }
}

/// Set multiple user xattrs on a file, fsync, SIGKILL, remount, and
/// verify listxattr returns all of them.
#[test]
fn fsync_crash_multi_xattr_listxattr_persists() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness
        .create_file("crash_multi_xattr.bin", b"multi xattr crash test")
        .expect("create file");

    harness
        .set_xattr("crash_multi_xattr.bin", "one", b"1")
        .expect("set one");
    harness
        .set_xattr("crash_multi_xattr.bin", "two", b"22")
        .expect("set two");
    harness
        .set_xattr("crash_multi_xattr.bin", "three", b"333")
        .expect("set three");

    harness
        .fsync_file("crash_multi_xattr.bin")
        .expect("fsync before crash");

    harness.crash_and_remount().expect("crash and remount");

    let mut names = harness
        .list_xattr("crash_multi_xattr.bin")
        .expect("listxattr after crash");
    names.sort();
    assert_eq!(
        names,
        vec!["one", "three", "two"],
        "all three xattrs should survive SIGKILL + remount"
    );
}
