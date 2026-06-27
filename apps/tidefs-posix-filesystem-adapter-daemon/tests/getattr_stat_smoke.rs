// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mounted FUSE integration tests for getattr/stat through the VFS adapter.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{self as unix_fs, DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;

fn unique_test_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "tidefs-getattr-stat-smoke-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-getattr-stat-smoke".to_string()),
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

fn assert_raw_errno(err: &io::Error, expected: i32) {
    assert_eq!(
        err.raw_os_error(),
        Some(expected),
        "unexpected error: {err}"
    );
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

fn current_uid_gid() -> (u32, u32) {
    // SAFETY: `geteuid`/`getegid` read the current process credentials and do
    // not require pointer, fd, or buffer invariants.
    let uid = unsafe { libc::geteuid() } as u32;
    let gid = unsafe { libc::getegid() } as u32;
    (uid, gid)
}

fn mknod_fifo(path: &Path, mode: libc::mode_t) -> io::Result<()> {
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains nul byte"))?;
    // SAFETY: `cpath` is a NUL-terminated path alive for the mknod call; FIFO
    // creation passes a zero device id as required.
    let result = unsafe { libc::mknod(cpath.as_ptr(), libc::S_IFIFO | mode, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[test]
fn stat_regular_file_reports_size_type_links_and_owner() {
    let mnt = MountedVfs::new();
    let path = mnt.path("/regular.txt");
    let payload = b"mounted getattr stat payload";

    create_file(&path, 0o640, payload);
    let metadata = fs::metadata(&path).expect("stat regular file through FUSE mount");
    let (uid, gid) = current_uid_gid();
    assert!(metadata.is_file());
    assert_eq!(metadata.mode() & libc::S_IFMT, libc::S_IFREG);
    assert_eq!(metadata.mode() & 0o777, 0o640);
    assert_eq!(metadata.len(), payload.len() as u64);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.uid(), uid);
    assert_eq!(metadata.gid(), gid);
    assert!(metadata.ino() > 0);
}

#[test]
fn stat_directory_reports_directory_type_and_link_count() {
    let mnt = MountedVfs::new();
    let dir = mnt.path("/stat-dir");

    fs::DirBuilder::new()
        .mode(0o750)
        .create(&dir)
        .expect("mkdir through FUSE mount");

    let metadata = fs::metadata(&dir).expect("stat directory through FUSE mount");
    assert!(metadata.is_dir());
    assert_eq!(metadata.mode() & libc::S_IFMT, libc::S_IFDIR);
    assert_eq!(metadata.mode() & 0o777, 0o750);
    assert!(metadata.nlink() >= 2);
    assert!(metadata.ino() > 0);
}

#[test]
fn symlink_metadata_reports_link_while_stat_follows_target() {
    let mnt = MountedVfs::new();
    let target = mnt.path("/target.txt");
    let link = mnt.path("/target-link");
    let target_payload = b"target bytes visible through symlink";

    create_file(&target, 0o644, target_payload);
    unix_fs::symlink("target.txt", &link).expect("create symlink through FUSE mount");

    let link_metadata = fs::symlink_metadata(&link).expect("lstat symlink through FUSE mount");
    assert!(link_metadata.file_type().is_symlink());
    assert_eq!(link_metadata.mode() & libc::S_IFMT, libc::S_IFLNK);
    assert_eq!(link_metadata.size(), "target.txt".len() as u64);

    let followed_metadata = fs::metadata(&link).expect("stat symlink target through FUSE mount");
    assert!(followed_metadata.is_file());
    assert_eq!(followed_metadata.mode() & libc::S_IFMT, libc::S_IFREG);
    assert_eq!(followed_metadata.len(), target_payload.len() as u64);
}

#[test]
fn fstat_open_file_matches_path_stat() {
    let mnt = MountedVfs::new();
    let path = mnt.path("/open-file.txt");
    let payload = b"metadata from open file handle";
    let file = create_file(&path, 0o644, payload);

    let path_metadata = fs::metadata(&path).expect("path stat through FUSE mount");
    let file_metadata = file.metadata().expect("fstat through FUSE mount");

    assert_eq!(file_metadata.ino(), path_metadata.ino());
    assert_eq!(file_metadata.mode() & libc::S_IFMT, libc::S_IFREG);
    assert_eq!(file_metadata.len(), payload.len() as u64);
    assert_eq!(file_metadata.nlink(), 1);
}

#[test]
fn stat_reflects_write_size_updates() {
    let mnt = MountedVfs::new();
    let path = mnt.path("/write-sized.txt");
    let payload = b"mounted write updates getattr-visible size";
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o644)
        .open(&path)
        .expect("create empty file through FUSE mount");
    let before = fs::metadata(&path).expect("metadata before write");
    assert_eq!(before.len(), 0);

    file.write_all(payload).expect("write through FUSE mount");
    file.flush().expect("flush write through FUSE mount");

    let after = fs::metadata(&path).expect("metadata after write");
    assert_eq!(after.mode() & 0o777, before.mode() & 0o777);
    assert_eq!(after.len(), payload.len() as u64);
    assert_eq!(after.ino(), before.ino());
}

#[test]
fn stat_hard_link_reports_shared_inode_and_nlink_two() {
    let mnt = MountedVfs::new();
    let source = mnt.path("/source.txt");
    let linked = mnt.path("/linked.txt");
    create_file(&source, 0o644, b"hard link payload");

    fs::hard_link(&source, &linked).expect("hard link through FUSE mount");

    let source_metadata = fs::metadata(&source).expect("source stat after hard link");
    let linked_metadata = fs::metadata(&linked).expect("linked stat after hard link");
    assert_eq!(source_metadata.ino(), linked_metadata.ino());
    assert_eq!(source_metadata.nlink(), 2);
    assert_eq!(linked_metadata.nlink(), 2);
}

#[test]
fn stat_removed_and_missing_paths_return_enoent() {
    let mnt = MountedVfs::new();
    let removed = mnt.path("/removed.txt");
    let missing = mnt.path("/missing.txt");
    create_file(&removed, 0o644, b"removed payload");

    fs::remove_file(&removed).expect("unlink through FUSE mount");

    let removed_err = fs::metadata(&removed).expect_err("stat removed path should fail");
    assert_raw_errno(&removed_err, libc::ENOENT);
    let missing_err = fs::metadata(&missing).expect_err("stat missing path should fail");
    assert_raw_errno(&missing_err, libc::ENOENT);
}

#[test]
fn stat_fifo_reports_fifo_type_mode_and_zero_rdev() {
    let mnt = MountedVfs::new();
    let pipe = mnt.path("/stat-pipe");

    mknod_fifo(&pipe, 0o660).expect("mknod FIFO through FUSE mount");

    let metadata = fs::metadata(&pipe).expect("stat FIFO through FUSE mount");
    assert!(metadata.file_type().is_fifo());
    assert_eq!(metadata.mode() & libc::S_IFMT, libc::S_IFIFO);
    assert_eq!(metadata.mode() & 0o600, 0o600);
    assert_eq!(metadata.mode() & 0o111, 0);
    assert_eq!(metadata.len(), 0);
    assert_eq!(metadata.rdev(), 0);
}
