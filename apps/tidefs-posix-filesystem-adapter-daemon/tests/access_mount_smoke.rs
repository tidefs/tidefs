// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration smoke for POSIX access probes through the current FUSE adapter.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
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
        "tidefs-access-mount-smoke-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-access-mount-smoke".to_string()),
        fuser::MountOption::RW,
        fuser::MountOption::NoDev,
        fuser::MountOption::NoSuid,
        fuser::MountOption::Subtype("tidefs".to_string()),
    ]
}

fn request_ctx() -> RequestCtx {
    // SAFETY: `geteuid`/`getegid` read the current process credentials and do
    // not require pointer, fd, or buffer invariants.
    let gid = unsafe { libc::getegid() } as u32;
    RequestCtx {
        uid: unsafe { libc::geteuid() } as u32,
        gid,
        pid: std::process::id(),
        umask: 0o022,
        groups: vec![gid],
    }
}

fn seed_access_fixtures(engine: &VfsLocalFileSystem) {
    let ctx = request_ctx();
    let root = engine.get_root_inode(&ctx).expect("root inode");
    engine
        .create(root, b"readable.txt", 0o644, 0, &ctx)
        .expect("create readable fixture");
    engine
        .create(root, b"executable.sh", 0o755, 0, &ctx)
        .expect("create executable fixture");
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
        seed_access_fixtures(&engine);
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

fn access_path(path: &Path, mode: i32) -> io::Result<()> {
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains nul byte"))?;
    // SAFETY: `cpath` is a NUL-terminated path buffer alive for the access
    // call, and `mode` is supplied by the test as libc access flags.
    let result = unsafe { libc::access(cpath.as_ptr(), mode) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn assert_access_denied(path: &Path, mode: i32, expected_errno: i32) {
    let err = access_path(path, mode).expect_err("access should fail");
    assert_eq!(err.raw_os_error(), Some(expected_errno));
}

#[test]
fn access_smoke_reports_existence_modes_and_missing_targets() {
    let mount = MountedVfs::new();
    let readable = mount.path("/readable.txt");
    let executable = mount.path("/executable.sh");

    access_path(&readable, libc::F_OK).expect("F_OK for existing file");
    access_path(&readable, libc::R_OK).expect("R_OK for readable file");
    access_path(&readable, libc::W_OK).expect("W_OK for writable file");
    assert_access_denied(&readable, libc::X_OK, libc::EACCES);

    access_path(&executable, libc::X_OK).expect("X_OK for executable file");

    let missing = mount.path("/missing-access-target");
    assert_access_denied(&missing, libc::F_OK, libc::ENOENT);
}
