// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mounted FUSE integration tests for extended attribute operations
//! through the VFS adapter.
//!
//! Validates getxattr, setxattr, listxattr, and removexattr FUSE handlers
//! with 16 focused test cases covering round-trip, flags, errors, remount
//! persistence, and namespace filtering.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;

// ENODATA (61) is not exported by libc on Linux.
const ENODATA: i32 = 61;

// ── helpers ────────────────────────────────────────────────────────────

fn unique_test_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "tidefs-fuse-xattr-smoke-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-fuse-xattr-smoke".to_string()),
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

fn create_file(path: &Path, mode: u32, payload: &[u8]) -> File {
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(mode)
        .open(path)
        .expect("create file through FUSE mount");
    file.write_all(payload)
        .expect("write file through FUSE mount");
    file.flush().expect("flush file through FUSE mount");
    file
}

fn current_uid() -> u32 {
    (unsafe { libc::geteuid() }) as u32
}

// ── xattr syscall wrappers ─────────────────────────────────────────────

fn path_cstr(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("path contains nul byte")
}

fn xattr_name_cstr(name: &str) -> CString {
    CString::new(name).expect("xattr name contains nul byte")
}

unsafe fn setxattr_sys(path: &CString, name: &CString, value: &[u8], flags: i32) -> io::Result<()> {
    let result = libc::setxattr(
        path.as_ptr(),
        name.as_ptr(),
        value.as_ptr() as *const libc::c_void,
        value.len(),
        flags,
    );
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

unsafe fn getxattr_sys(path: &CString, name: &CString, buf: &mut [u8]) -> io::Result<usize> {
    let result = libc::getxattr(
        path.as_ptr(),
        name.as_ptr(),
        buf.as_mut_ptr() as *mut libc::c_void,
        buf.len(),
    );
    if result >= 0 {
        Ok(result as usize)
    } else {
        Err(io::Error::last_os_error())
    }
}

unsafe fn getxattr_size(path: &CString, name: &CString) -> io::Result<usize> {
    let result = libc::getxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0);
    if result >= 0 {
        Ok(result as usize)
    } else {
        Err(io::Error::last_os_error())
    }
}

unsafe fn listxattr_sys(path: &CString, buf: &mut [u8]) -> io::Result<usize> {
    let result = libc::listxattr(
        path.as_ptr(),
        buf.as_mut_ptr() as *mut libc::c_char,
        buf.len(),
    );
    if result >= 0 {
        Ok(result as usize)
    } else {
        Err(io::Error::last_os_error())
    }
}

unsafe fn listxattr_size(path: &CString) -> io::Result<usize> {
    let result = libc::listxattr(path.as_ptr(), std::ptr::null_mut(), 0);
    if result >= 0 {
        Ok(result as usize)
    } else {
        Err(io::Error::last_os_error())
    }
}

unsafe fn removexattr_sys(path: &CString, name: &CString) -> io::Result<()> {
    let result = libc::removexattr(path.as_ptr(), name.as_ptr());
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Parse the null-separated name list returned by listxattr.
fn parse_xattr_names(raw: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    for chunk in raw.split(|byte| *byte == 0) {
        if chunk.is_empty() {
            continue;
        }
        names.push(String::from_utf8_lossy(chunk).to_string());
    }
    names
}

/// Check that a list of xattr name bytes contains the expected name.
fn xattr_names_contain(raw: &[u8], expected: &str) -> bool {
    parse_xattr_names(raw).contains(&expected.to_string())
}

// ── test cases ─────────────────────────────────────────────────────────

#[test]
fn setxattr_getxattr_roundtrip() {
    let mnt = MountedVfs::new();
    let path = mnt.path("/roundtrip.txt");
    create_file(&path, 0o644, b"xattr roundtrip payload");

    let path_c = path_cstr(&path);
    let name_c = xattr_name_cstr("user.roundtrip");
    let value = b"mounted xattr roundtrip value";

    unsafe {
        setxattr_sys(&path_c, &name_c, value, 0).expect("setxattr user.roundtrip");
    }

    unsafe {
        let size = getxattr_size(&path_c, &name_c).expect("getxattr size query");
        assert_eq!(size, value.len());

        let mut buf = vec![0u8; size];
        let n = getxattr_sys(&path_c, &name_c, &mut buf).expect("getxattr user.roundtrip");
        assert_eq!(n, value.len());
        assert_eq!(&buf[..n], value);
    }
}

#[test]
fn setxattr_create_flag_succeeds() {
    let mnt = MountedVfs::new();
    let path = mnt.path("/create-ok.txt");
    create_file(&path, 0o644, b"xattr create flag");

    let path_c = path_cstr(&path);
    let name_c = xattr_name_cstr("user.create");
    let value = b"created with XATTR_CREATE";

    unsafe {
        setxattr_sys(&path_c, &name_c, value, libc::XATTR_CREATE)
            .expect("setxattr with XATTR_CREATE should succeed on new attr");
    }

    unsafe {
        let size = getxattr_size(&path_c, &name_c).expect("getxattr size after create");
        assert_eq!(size, value.len());
    }
}

#[test]
fn setxattr_create_flag_fails_on_existing() {
    let mnt = MountedVfs::new();
    let path = mnt.path("/create-dup.txt");
    create_file(&path, 0o644, b"xattr create dup");

    let path_c = path_cstr(&path);
    let name_c = xattr_name_cstr("user.dup");

    unsafe {
        setxattr_sys(&path_c, &name_c, b"first", 0).expect("initial setxattr");
        let err = setxattr_sys(&path_c, &name_c, b"second", libc::XATTR_CREATE)
            .expect_err("XATTR_CREATE on existing attr should fail");
        assert_eq!(err.raw_os_error(), Some(libc::EEXIST));
    }
}

#[test]
fn setxattr_replace_flag_succeeds() {
    let mnt = MountedVfs::new();
    let path = mnt.path("/replace-ok.txt");
    create_file(&path, 0o644, b"xattr replace ok");

    let path_c = path_cstr(&path);
    let name_c = xattr_name_cstr("user.replace");

    unsafe {
        setxattr_sys(&path_c, &name_c, b"old", 0).expect("initial setxattr");
        setxattr_sys(&path_c, &name_c, b"new-value", libc::XATTR_REPLACE)
            .expect("XATTR_REPLACE on existing attr should succeed");

        let mut buf = vec![0u8; 32];
        let n = getxattr_sys(&path_c, &name_c, &mut buf).expect("getxattr after replace");
        assert_eq!(&buf[..n], b"new-value");
    }
}

#[test]
fn setxattr_replace_flag_fails_on_missing() {
    let mnt = MountedVfs::new();
    let path = mnt.path("/replace-missing.txt");
    create_file(&path, 0o644, b"xattr replace missing");

    let path_c = path_cstr(&path);
    let name_c = xattr_name_cstr("user.never-set");

    unsafe {
        let err = setxattr_sys(&path_c, &name_c, b"value", libc::XATTR_REPLACE)
            .expect_err("XATTR_REPLACE on missing attr should fail");
        assert_eq!(err.raw_os_error(), Some(ENODATA));
    }
}

#[test]
fn setxattr_default_flag_overwrites() {
    let mnt = MountedVfs::new();
    let path = mnt.path("/overwrite.txt");
    create_file(&path, 0o644, b"xattr overwrite");

    let path_c = path_cstr(&path);
    let name_c = xattr_name_cstr("user.overwrite");

    unsafe {
        setxattr_sys(&path_c, &name_c, b"first", 0).expect("initial setxattr");
        setxattr_sys(&path_c, &name_c, b"second", 0).expect("overwrite with flag=0");

        let mut buf = vec![0u8; 32];
        let n = getxattr_sys(&path_c, &name_c, &mut buf).expect("getxattr after overwrite");
        assert_eq!(&buf[..n], b"second");
    }
}

#[test]
fn listxattr_returns_set_keys() {
    let mnt = MountedVfs::new();
    let path = mnt.path("/list-keys.txt");
    create_file(&path, 0o644, b"listxattr keys");

    let path_c = path_cstr(&path);

    unsafe {
        setxattr_sys(&path_c, &xattr_name_cstr("user.a"), b"1", 0).expect("set user.a");
        setxattr_sys(&path_c, &xattr_name_cstr("user.b"), b"2", 0).expect("set user.b");
    }

    unsafe {
        let size = listxattr_size(&path_c).expect("listxattr size query");
        let mut buf = vec![0u8; size];
        let n = listxattr_sys(&path_c, &mut buf).expect("listxattr");
        assert_eq!(n, size);

        let raw = &buf[..n];
        assert!(
            xattr_names_contain(raw, "user.a"),
            "listxattr should contain user.a"
        );
        assert!(
            xattr_names_contain(raw, "user.b"),
            "listxattr should contain user.b"
        );
    }
}

#[test]
fn listxattr_size_query_returns_expected_length() {
    let mnt = MountedVfs::new();
    let path = mnt.path("/list-size.txt");
    create_file(&path, 0o644, b"listxattr size");

    let path_c = path_cstr(&path);

    unsafe {
        setxattr_sys(&path_c, &xattr_name_cstr("user.s1"), b"xyz", 0).expect("set user.s1");
    }

    unsafe {
        let size = listxattr_size(&path_c).expect("listxattr size=0 query");
        // "user.s1\0" = 8 bytes
        assert_eq!(size, 8, "size=0 query should return total name bytes");

        let mut buf = vec![0u8; size];
        let n = listxattr_sys(&path_c, &mut buf).expect("listxattr read");
        assert_eq!(n, size);
    }
}

#[test]
fn removexattr_then_getxattr_returns_enodata() {
    let mnt = MountedVfs::new();
    let path = mnt.path("/remove.txt");
    create_file(&path, 0o644, b"xattr remove");

    let path_c = path_cstr(&path);
    let name_c = xattr_name_cstr("user.del");

    unsafe {
        setxattr_sys(&path_c, &name_c, b"value", 0).expect("set user.del");
        removexattr_sys(&path_c, &name_c).expect("remove user.del");

        let err = getxattr_size(&path_c, &name_c).expect_err("getxattr after remove should fail");
        assert_eq!(err.raw_os_error(), Some(ENODATA));
    }
}

#[test]
fn getxattr_missing_returns_enodata() {
    let mnt = MountedVfs::new();
    let path = mnt.path("/missing-xattr.txt");
    create_file(&path, 0o644, b"xattr missing");

    let path_c = path_cstr(&path);
    let name_c = xattr_name_cstr("user.never");

    unsafe {
        let err =
            getxattr_size(&path_c, &name_c).expect_err("getxattr on never-set attr should fail");
        assert_eq!(err.raw_os_error(), Some(ENODATA));
    }
}

#[test]
fn removexattr_missing_returns_enodata() {
    let mnt = MountedVfs::new();
    let path = mnt.path("/remove-missing.txt");
    create_file(&path, 0o644, b"xattr remove missing");

    let path_c = path_cstr(&path);
    let name_c = xattr_name_cstr("user.never-here");

    unsafe {
        let err =
            removexattr_sys(&path_c, &name_c).expect_err("removexattr on missing attr should fail");
        assert_eq!(err.raw_os_error(), Some(ENODATA));
    }
}

#[test]
fn setxattr_on_nonexistent_file_returns_enoent() {
    let mnt = MountedVfs::new();
    let bad_path = mnt.path("/no-such-file.txt");

    let path_c = path_cstr(&bad_path);
    let name_c = xattr_name_cstr("user.test");

    unsafe {
        let err = setxattr_sys(&path_c, &name_c, b"value", 0)
            .expect_err("setxattr on missing file should fail");
        assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
    }
}

#[test]
fn xattr_survives_remount() {
    // Manually manage mount lifecycles to remount the same store.
    let root = unique_test_root();
    let store = root.join("store");
    let mount = root.join("mnt");
    fs::create_dir_all(&store).expect("create store dir");
    fs::create_dir_all(&mount).expect("create mount dir");

    // First mount: create file and set xattr.
    {
        let filesystem = LocalFileSystem::open_with_root_authentication_key(
            &store,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open local filesystem (first mount)");
        let engine = VfsLocalFileSystem::new(filesystem);
        let adapter =
            FuseVfsAdapter::new(Box::new(engine)).expect("create FUSE VFS adapter (first mount)");
        let _session =
            fuser::spawn_mount2(adapter, &mount, &mount_options()).expect("mount FUSE (first)");

        let file_path = mount.join("remount.txt");
        create_file(&file_path, 0o644, b"remount payload");

        let path_c = path_cstr(&file_path);
        let name_c = xattr_name_cstr("user.persist");
        unsafe {
            setxattr_sys(&path_c, &name_c, b"survive-remount", 0).expect("setxattr before remount");
        }
        // _session drops here, unmounting.
    }

    // Second mount: verify the xattr persists.
    {
        let filesystem = LocalFileSystem::open_with_root_authentication_key(
            &store,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open local filesystem (second mount)");
        let engine = VfsLocalFileSystem::new(filesystem);
        let adapter =
            FuseVfsAdapter::new(Box::new(engine)).expect("create FUSE VFS adapter (second mount)");
        let _session =
            fuser::spawn_mount2(adapter, &mount, &mount_options()).expect("mount FUSE (second)");

        let file_path = mount.join("remount.txt");
        let path_c = path_cstr(&file_path);
        let name_c = xattr_name_cstr("user.persist");

        unsafe {
            let mut buf = vec![0u8; 64];
            let n = getxattr_sys(&path_c, &name_c, &mut buf).expect("getxattr after remount");
            assert_eq!(&buf[..n], b"survive-remount");
        }
    }

    let _ = fs::remove_dir_all(&root);
}

/// When running as non-root, trusted.* xattrs are rejected (EPERM) and
/// filtered from listxattr. When running as root, trusted.* xattrs work
/// normally.
#[test]
fn trusted_xattr_filtered_for_nonroot() {
    let mnt = MountedVfs::new();
    let path = mnt.path("/trusted.txt");
    create_file(&path, 0o644, b"trusted xattr test");

    let path_c = path_cstr(&path);
    let trusted_name = xattr_name_cstr("trusted.test");
    let user_name = xattr_name_cstr("user.visible");

    let uid = current_uid();

    unsafe {
        // Always set a user.* xattr to have something visible.
        setxattr_sys(&path_c, &user_name, b"visible", 0).expect("set user.visible");

        if uid == 0 {
            // Root can set and get trusted.*.
            setxattr_sys(&path_c, &trusted_name, b"root-trusted", 0)
                .expect("root should set trusted.*");

            let mut buf = vec![0u8; 64];
            let n =
                getxattr_sys(&path_c, &trusted_name, &mut buf).expect("root should get trusted.*");
            assert_eq!(&buf[..n], b"root-trusted");

            // listxattr should include both.
            let size = listxattr_size(&path_c).expect("listxattr size");
            let mut buf = vec![0u8; size];
            let n = listxattr_sys(&path_c, &mut buf).expect("listxattr");
            let raw = &buf[..n];
            assert!(xattr_names_contain(raw, "trusted.test"));
            assert!(xattr_names_contain(raw, "user.visible"));
        } else {
            // Non-root: setxattr with trusted.* should fail with EPERM.
            let err = setxattr_sys(&path_c, &trusted_name, b"val", 0)
                .expect_err("non-root setxattr trusted.* should fail");
            assert_eq!(err.raw_os_error(), Some(libc::EPERM));

            // listxattr should only contain user.*.
            let size = listxattr_size(&path_c).expect("listxattr size");
            let mut buf = vec![0u8; size];
            let n = listxattr_sys(&path_c, &mut buf).expect("listxattr");
            let raw = &buf[..n];
            assert!(
                !xattr_names_contain(raw, "trusted.test"),
                "non-root listxattr should not include trusted.*"
            );
            assert!(xattr_names_contain(raw, "user.visible"));
        }
    }
}

#[test]
fn getxattr_buffer_too_small_returns_erange() {
    let mnt = MountedVfs::new();
    let path = mnt.path("/erange.txt");
    create_file(&path, 0o644, b"xattr erange test");

    let path_c = path_cstr(&path);
    let name_c = xattr_name_cstr("user.erange");
    let value = b"a-value-longer-than-5-bytes";

    unsafe {
        setxattr_sys(&path_c, &name_c, value, 0).expect("setxattr user.erange");

        // getxattr with a buffer smaller than the value should return ERANGE.
        let mut small_buf = vec![0u8; 5];
        let err = getxattr_sys(&path_c, &name_c, &mut small_buf)
            .expect_err("getxattr with too-small buffer should fail with ERANGE");
        // ERANGE = 34 on Linux
        assert_eq!(err.raw_os_error(), Some(34));
    }
}

#[test]
fn security_xattr_rejected_for_nonroot() {
    let mnt = MountedVfs::new();
    let path = mnt.path("/security.txt");
    create_file(&path, 0o644, b"security xattr test");

    let path_c = path_cstr(&path);
    let sec_name = xattr_name_cstr("security.test");

    let uid = current_uid();

    unsafe {
        if uid == 0 {
            // Root may be able to set security.* depending on CAP_SYS_ADMIN
            // and namespace configuration. Accept success or EPERM/EACCES.
            let result = setxattr_sys(&path_c, &sec_name, b"root-sec", 0);
            // Nothing to assert — root behavior varies by environment.
            let _ = result;
        } else {
            // Non-root: setxattr with security.* should fail (EPERM or EACCES).
            let err = setxattr_sys(&path_c, &sec_name, b"val", 0)
                .expect_err("non-root setxattr security.* should fail");
            assert!(
                err.raw_os_error() == Some(libc::EPERM) || err.raw_os_error() == Some(libc::EACCES),
                "expected EPERM or EACCES, got {:?}",
                err.raw_os_error()
            );

            // getxattr on security.* should also fail for non-root.
            let mut buf = vec![0u8; 64];
            let err = getxattr_sys(&path_c, &sec_name, &mut buf)
                .expect_err("non-root getxattr security.* should fail");
            assert!(
                err.raw_os_error() == Some(libc::ENODATA)
                    || err.raw_os_error() == Some(libc::EPERM)
                    || err.raw_os_error() == Some(libc::EACCES),
                "expected ENODATA, EPERM, or EACCES, got {:?}",
                err.raw_os_error()
            );
        }
    }
}
