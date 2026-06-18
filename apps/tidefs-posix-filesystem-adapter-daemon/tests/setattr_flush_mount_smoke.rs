// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mounted FUSE integration tests for setattr and flush through the VFS adapter.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;

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
        "tidefs-setattr-flush-smoke-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-setattr-flush-smoke".to_string()),
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

fn read_all(path: &Path) -> Vec<u8> {
    let mut file = File::open(path).expect("open file through FUSE mount");
    let mut readback = Vec::new();
    file.read_to_end(&mut readback)
        .expect("read file through FUSE mount");
    readback
}

fn assert_raw_errno(err: &io::Error, expected: i32) {
    assert_eq!(
        err.raw_os_error(),
        Some(expected),
        "unexpected error: {err}"
    );
}

fn path_cstring(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("path should not contain nul")
}

fn chown_path(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    let cpath = path_cstring(path);
    let result = unsafe { libc::chown(cpath.as_ptr(), uid, gid) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn set_path_times(path: &Path, atime: libc::time_t, mtime: libc::time_t) -> io::Result<()> {
    let cpath = path_cstring(path);
    let times = [
        libc::timespec {
            tv_sec: atime,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: mtime,
            tv_nsec: 0,
        },
    ];
    let result = unsafe { libc::utimensat(libc::AT_FDCWD, cpath.as_ptr(), times.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn current_uid_gid() -> (u32, u32) {
    (
        unsafe { libc::geteuid() } as u32,
        unsafe { libc::getegid() } as u32,
    )
}

#[test]
fn setattr_flush_mount_smoke_chmod_reflected_in_stat() {
    let _guard = serial_test_guard();
    let mnt = MountedVfs::new();
    let path = mnt.path("/chmod.txt");
    create_file(&path, 0o600, b"chmod payload");

    fs::set_permissions(&path, Permissions::from_mode(0o754)).expect("chmod through FUSE mount");

    let metadata = fs::metadata(&path).expect("stat chmod result through FUSE mount");
    assert_eq!(metadata.mode() & 0o777, 0o754);
}

#[test]
fn setattr_flush_mount_smoke_chown_reflected_in_stat_when_permitted() {
    let _guard = serial_test_guard();
    let mnt = MountedVfs::new();
    let path = mnt.path("/chown.txt");
    create_file(&path, 0o644, b"chown payload");
    let (uid, gid) = current_uid_gid();

    match chown_path(&path, uid, gid) {
        Ok(()) => {
            let metadata = fs::metadata(&path).expect("stat chown result through FUSE mount");
            assert_eq!(metadata.uid(), uid);
            assert_eq!(metadata.gid(), gid);
        }
        Err(err) if err.raw_os_error() == Some(libc::EPERM) => {
            let metadata = fs::metadata(&path).expect("stat after denied chown");
            assert_eq!(metadata.uid(), uid);
            assert_eq!(metadata.gid(), gid);
        }
        Err(err) => panic!("unexpected chown error: {err}"),
    }
}

#[test]
fn setattr_flush_mount_smoke_truncate_reflected_in_stat_and_readback() {
    let _guard = serial_test_guard();
    let mnt = MountedVfs::new();
    let path = mnt.path("/truncate.txt");
    let file = create_file(&path, 0o644, b"truncate payload");

    file.set_len(8).expect("truncate through FUSE mount");

    let metadata = fs::metadata(&path).expect("stat truncate result through FUSE mount");
    assert_eq!(metadata.len(), 8);
    assert_eq!(read_all(&path), b"truncate");
}

#[test]
fn setattr_flush_mount_smoke_truncate_extend_reads_zero_filled_gap() {
    let _guard = serial_test_guard();
    let mnt = MountedVfs::new();
    let path = mnt.path("/truncate-extend.bin");
    let file = create_file(&path, 0o644, b"abc");

    file.set_len(8).expect("extend through FUSE mount");

    let metadata = fs::metadata(&path).expect("stat extended file through FUSE mount");
    assert_eq!(metadata.len(), 8);
    assert_eq!(read_all(&path), b"abc\0\0\0\0\0");
}

#[test]
fn setattr_flush_mount_smoke_utimens_reflected_in_stat() {
    let _guard = serial_test_guard();
    let mnt = MountedVfs::new();
    let path = mnt.path("/utimens.txt");
    create_file(&path, 0o644, b"utimens payload");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs() as libc::time_t;
    let atime = now.saturating_sub(300);
    let mtime = now.saturating_sub(180);

    set_path_times(&path, atime, mtime).expect("utimensat through FUSE mount");

    let metadata = fs::metadata(&path).expect("stat utimens result through FUSE mount");
    assert_eq!(metadata.atime(), atime);
    assert_eq!(metadata.mtime(), mtime);
}

#[test]
fn setattr_flush_mount_smoke_flush_on_close_preserves_data_for_reopen() {
    let _guard = serial_test_guard();
    let mnt = MountedVfs::new();
    let path = mnt.path("/flush.txt");
    let payload = b"flush should preserve data for the next opener";
    {
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o644)
            .open(&path)
            .expect("create file through FUSE mount");
        file.write_all(payload)
            .expect("write file through FUSE mount");
        file.flush().expect("flush userspace file handle");
    }

    assert_eq!(read_all(&path), payload);
}

#[test]
fn setattr_flush_mount_smoke_chmod_missing_path_returns_enoent() {
    let _guard = serial_test_guard();
    let mnt = MountedVfs::new();
    let missing = mnt.path("/missing.txt");

    let err = fs::set_permissions(&missing, Permissions::from_mode(0o600))
        .expect_err("chmod missing mounted path should fail");

    assert_raw_errno(&err, libc::ENOENT);
}

#[test]
fn setattr_flush_mount_smoke_chmod_persists_across_remount() {
    let _guard = serial_test_guard();
    let root = unique_test_root();
    let store = root.join("store");
    let mount = root.join("mnt");
    fs::create_dir_all(&store).expect("create store dir");
    fs::create_dir_all(&mount).expect("create mount dir");

    let path = mount.join("chmod-remount.bin");

    // First mount: create file and chmod 600
    {
        let filesystem = LocalFileSystem::open_with_root_authentication_key(
            &store,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open local filesystem");
        let engine = VfsLocalFileSystem::new(filesystem);
        let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create FUSE VFS adapter");
        let session = fuser::spawn_mount2(adapter, &mount, &mount_options()).expect("mount FUSE");

        create_file(&path, 0o644, b"chmod remount test payload");

        fs::set_permissions(&path, Permissions::from_mode(0o600))
            .expect("chmod through FUSE mount");

        let metadata = fs::metadata(&path).expect("stat after chmod");
        assert_eq!(metadata.mode() & 0o777, 0o600);

        drop(session);
    } // unmount

    // Remount and verify mode persisted
    {
        let filesystem = LocalFileSystem::open_with_root_authentication_key(
            &store,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("reopen local filesystem");
        let engine = VfsLocalFileSystem::new(filesystem);
        let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create FUSE VFS adapter");
        let session = fuser::spawn_mount2(adapter, &mount, &mount_options()).expect("remount FUSE");

        let metadata = fs::metadata(&path).expect("stat after remount");
        assert_eq!(metadata.mode() & 0o777, 0o600);

        let readback = read_all(&path);
        assert_eq!(readback, b"chmod remount test payload");

        drop(session);
    }

    let _ = fs::remove_dir_all(&root);
}

// ── Permission gate integration test ───────────────────────────────────

/// Verify that a non-owner, non-root chmod through the FUSE mount is
/// rejected with EPERM by the `can_setattr` permission gate.
#[test]
fn setattr_permission_gate_denies_non_owner_chmod() {
    let _guard = serial_test_guard();
    let mnt = MountedVfs::new();
    let path = mnt.path("/chmod-perm.txt");
    create_file(&path, 0o644, b"can_setattr gate test");

    let original_uid = unsafe { libc::geteuid() };
    let non_owner_uid = if original_uid == 0 {
        65534
    } else {
        original_uid.wrapping_add(1000)
    };
    if non_owner_uid == original_uid {
        eprintln!("skipping: no suitable non-owner uid");
        return;
    }

    let cpath = path_cstring(&path);
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EPERM) {
            eprintln!("skipping: fork not permitted");
            return;
        }
        panic!("fork failed: {err}");
    }

    if pid == 0 {
        if unsafe { libc::setreuid(non_owner_uid, non_owner_uid) } != 0 {
            unsafe { libc::_exit(77) };
        }
        if unsafe { libc::chmod(cpath.as_ptr(), 0o600) } == 0 {
            unsafe { libc::_exit(1) };
        }
        let en = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        unsafe { libc::_exit(if en == libc::EPERM { 0 } else { 2 }) };
    }

    let mut st: i32 = 0;
    assert!(unsafe { libc::waitpid(pid, &mut st as *mut i32, 0) } >= 0);
    match libc::WEXITSTATUS(st) {
        0 => {} // EPERM returned
        77 => eprintln!("integration test skipped (setuid unavailable)"),
        1 => panic!("can_setattr FAILED: non-owner chmod succeeded"),
        2 => panic!("can_setattr FAILED: unexpected errno"),
        o => panic!("unexpected child exit code: {o}"),
    }

    let meta = fs::metadata(&path).expect("stat after denied chmod");
    assert_eq!(
        meta.mode() & 0o777,
        0o644,
        "file mode unchanged after denied chmod"
    );
}
