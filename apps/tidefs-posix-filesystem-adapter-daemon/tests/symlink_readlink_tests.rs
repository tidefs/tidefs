// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mounted FUSE integration tests for symlink/readlink through the VFS adapter.

use std::fs;
use std::io;
use std::os::unix::fs::{self as unix_fs, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;
use tidefs_vfs_engine::{RequestCtx, VfsEngine};

fn unique_test_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "tidefs-symlink-readlink-test-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-symlink-readlink-test".to_string()),
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
        Self::new_with_seed(|_| {})
    }

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

fn seed_file(engine: &VfsLocalFileSystem, name: &[u8], contents: &[u8]) {
    let ctx = request_ctx();
    let root = engine.get_root_inode(&ctx).expect("root inode");
    let (_, handle) = engine
        .create(root, name, 0o644, 0, &ctx)
        .expect("seed regular file");
    engine
        .write(&handle, 0, contents, &ctx)
        .expect("seed file contents");
}

fn assert_raw_errno(err: &io::Error, expected: i32) {
    assert_eq!(
        err.raw_os_error(),
        Some(expected),
        "unexpected error: {err}"
    );
}

#[test]
fn create_symlink_and_readlink_returns_target() {
    let mnt = MountedVfs::new_with_seed(|engine| {
        seed_file(engine, b"target.txt", b"target content");
    });
    let target = mnt.path("/target.txt");
    let link = mnt.path("/link.txt");

    assert!(
        target.exists(),
        "seeded target should be visible through mount"
    );
    unix_fs::symlink("target.txt", &link).expect("create symlink");

    assert_eq!(
        fs::read_link(&link).expect("readlink"),
        Path::new("target.txt")
    );
}

#[test]
fn open_symlink_follows_to_target_file_content() {
    let mnt = MountedVfs::new_with_seed(|engine| {
        seed_file(engine, b"payload.txt", b"symlink traversal content\n");
    });
    let link = mnt.path("/payload-link.txt");

    unix_fs::symlink("payload.txt", &link).expect("create symlink");

    assert_eq!(
        fs::read_to_string(&link).expect("read through symlink"),
        "symlink traversal content\n"
    );
}

#[test]
fn symlink_to_nonexistent_target_succeeds() {
    let mnt = MountedVfs::new();
    let link = mnt.path("/dangling-link");

    unix_fs::symlink("missing-target", &link).expect("create dangling symlink");

    assert_eq!(
        fs::read_link(&link).expect("read dangling symlink"),
        Path::new("missing-target")
    );
    let err = fs::read_to_string(&link).expect_err("open through dangling symlink should fail");
    assert_raw_errno(&err, libc::ENOENT);
}

#[test]
fn unlink_dangling_symlink_after_target_removed_succeeds() {
    let mnt = MountedVfs::new();
    let target = mnt.path("/target");
    let link = mnt.path("/link");

    fs::write(&target, b"target content").expect("create target");
    unix_fs::symlink("target", &link).expect("create symlink");

    fs::remove_file(&target).expect("remove target first");
    assert!(
        fs::symlink_metadata(&link)
            .expect("dangling symlink metadata")
            .file_type()
            .is_symlink(),
        "symlink entry must remain after target removal"
    );
    fs::remove_file(&link).expect("remove dangling symlink");

    assert!(
        fs::symlink_metadata(&link).is_err(),
        "dangling symlink entry should be gone"
    );
}

#[test]
fn readlink_on_regular_file_returns_einval() {
    let mnt = MountedVfs::new_with_seed(|engine| {
        seed_file(engine, b"regular.txt", b"not a symlink");
    });
    let regular = mnt.path("/regular.txt");

    let err = fs::read_link(&regular).expect_err("readlink regular file should fail");
    assert_raw_errno(&err, libc::EINVAL);
}

#[test]
fn symlink_metadata_reports_correct_type_and_size() {
    let mnt = MountedVfs::new();
    let link = mnt.path("/metadata-link");
    let target = "metadata-target.txt";

    unix_fs::symlink(target, &link).expect("create symlink");

    let metadata = fs::symlink_metadata(&link).expect("symlink metadata");
    assert!(metadata.file_type().is_symlink());
    assert_eq!(metadata.size(), target.len() as u64);
}

#[test]
fn symlink_over_existing_name_returns_eexist() {
    let mnt = MountedVfs::new_with_seed(|engine| {
        seed_file(engine, b"existing", b"existing file");
    });
    let existing = mnt.path("/existing");

    let err =
        unix_fs::symlink("other-target", &existing).expect_err("symlink over file should fail");
    assert_raw_errno(&err, libc::EEXIST);
}
