// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration smoke for hard links through the VFS-backed FUSE adapter.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;
use tidefs_types_vfs_core::RequestCtx;
use tidefs_vfs_engine::VfsEngine;

fn unique_test_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "tidefs-vfs-link-smoke-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-vfs-link-smoke".to_string()),
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

fn seed_source_file(engine: &VfsLocalFileSystem) {
    let ctx = request_ctx();
    let root = engine.get_root_inode(&ctx).expect("root inode");
    engine
        .create(root, b"source.txt", 0o644, 0, &ctx)
        .expect("create hard-link source fixture");
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
        seed_source_file(&engine);
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

#[test]
fn vfs_adapter_hard_link_preserves_inode_and_reports_errors() {
    let mount = MountedVfs::new();
    let source = mount.path("/source.txt");
    let linked = mount.path("/linked.txt");

    let source_before = fs::metadata(&source).expect("source metadata before link");
    assert_eq!(source_before.nlink(), 1);

    fs::hard_link(&source, &linked).expect("hard link through FuseVfsAdapter");

    let source_after = fs::metadata(&source).expect("source metadata after link");
    let linked_meta = fs::metadata(&linked).expect("linked metadata");
    assert_eq!(linked_meta.ino(), source_after.ino());
    assert_eq!(linked_meta.ino(), source_before.ino());
    assert_eq!(source_after.nlink(), 2);
    assert_eq!(linked_meta.nlink(), 2);

    let duplicate = fs::hard_link(&source, &linked).expect_err("duplicate link should fail");
    assert_eq!(duplicate.raw_os_error(), Some(libc::EEXIST));

    let missing = fs::hard_link(
        mount.path("/missing.txt"),
        mount.path("/missing-linked.txt"),
    )
    .expect_err("missing source link should fail");
    assert_eq!(missing.raw_os_error(), Some(libc::ENOENT));
}
