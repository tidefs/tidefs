// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tidefs_intent_log::IntentLogBuffer;
use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;
use tidefs_types_vfs_core::RequestCtx;
use tidefs_vfs_engine::VfsEngine;

fn fuse_available() -> bool {
    Path::new("/dev/fuse").exists()
}

fn unique_test_root(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
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

struct IntentLogMount {
    root: PathBuf,
    mount: PathBuf,
    session: Option<fuser::BackgroundSession>,
    pub intent_log_buffer: Arc<IntentLogBuffer>,
}

impl IntentLogMount {
    fn new(enable_log: bool) -> Self {
        if !fuse_available() {
            panic!("FUSE is not available; guard test with require_fuse!()");
        }
        let root = unique_test_root("tidefs-intent-log-mount");
        let store = root.join("store");
        let mount = root.join("mnt");
        fs::create_dir_all(&store).expect("create store dir");
        fs::create_dir_all(&mount).expect("create mount dir");

        let engine = Self::open_engine(&store);
        let ctx = request_ctx();
        let root_ino = engine.get_root_inode(&ctx).expect("root inode");
        engine
            .create(root_ino, b"test_file", 0o644, 0, &ctx)
            .expect("seed test_file");

        let buf = Arc::new(IntentLogBuffer::new());
        let mut adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create adapter");
        adapter = adapter.with_intent_log_buffer(Arc::clone(&buf));
        if !enable_log {
            adapter = adapter.without_intent_log_write();
        }

        let session = fuser::spawn_mount2(
            adapter,
            &mount,
            &[
                fuser::MountOption::FSName("tidefs-intent-log-mount".to_string()),
                fuser::MountOption::RW,
                fuser::MountOption::NoDev,
                fuser::MountOption::NoSuid,
                fuser::MountOption::Subtype("tidefs".to_string()),
            ],
        )
        .expect("mount FUSE");

        IntentLogMount {
            root,
            mount,
            session: Some(session),
            intent_log_buffer: buf,
        }
    }

    fn open_engine(store: &Path) -> VfsLocalFileSystem {
        let fs = LocalFileSystem::open_with_root_authentication_key(
            store,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open store");
        VfsLocalFileSystem::new(fs)
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.mount.join(rel.trim_start_matches('/'))
    }
}

impl Drop for IntentLogMount {
    fn drop(&mut self) {
        drop(self.session.take());
        std::thread::sleep(Duration::from_millis(50));
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn intent_log_write_disabled_mount_no_buffer_records() {
    let harness = IntentLogMount::new(false);
    let file_path = harness.path("test_file");

    let data = b"data written with intent logging disabled";
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&file_path)
            .expect("open for write");
        f.write_all(data).expect("write");
        f.sync_all().expect("fsync");
    }
    assert!(
        harness.intent_log_buffer.is_empty(),
        "intent log buffer should be empty when intent_log_write is false"
    );
}

#[test]
fn intent_log_write_enabled_mount_produces_records() {
    let harness = IntentLogMount::new(true);
    let file_path = harness.path("test_file");

    let data = b"data written with intent logging enabled";
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&file_path)
            .expect("open for write");
        f.write_all(data).expect("write");
        f.sync_all().expect("fsync");
    }
    assert!(
        !harness.intent_log_buffer.is_empty(),
        "intent log buffer should have records when intent_log_write is true"
    );
}

#[test]
fn intent_log_write_disabled_mount_multiple_writes_no_records() {
    let harness = IntentLogMount::new(false);
    let file_path = harness.path("test_file");

    for i in 0..5 {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&file_path)
            .expect("open for write");
        let data = format!("write round {i}").into_bytes();
        f.write_all(&data).expect("write");
    }
    assert!(
        harness.intent_log_buffer.is_empty(),
        "buffer should be empty after multiple writes with logging disabled"
    );
}
