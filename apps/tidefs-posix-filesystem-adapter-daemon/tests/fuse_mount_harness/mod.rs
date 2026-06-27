// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Reusable FUSE mount harness for integration tests.
//!
//! Provides MountedVfs with mount/unmount/remount lifecycle, path helpers,
//! and common file-system operations through the kernel FUSE layer.
//! Tests using this harness require /dev/fuse access; they skip gracefully
//! when it is unavailable.

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;
use tidefs_types_vfs_core::RequestCtx;
use tidefs_vfs_engine::VfsEngine;

// ---------------------------------------------------------------------------
// FUSE availability
// ---------------------------------------------------------------------------

/// Returns true when /dev/fuse exists and is accessible.
pub fn fuse_available() -> bool {
    Path::new("/dev/fuse").exists()
}

// ---------------------------------------------------------------------------
// Test isolation helpers
// ---------------------------------------------------------------------------

pub fn unique_test_root(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}

pub fn mount_options(fsname: &str) -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName(fsname.to_string()),
        fuser::MountOption::RW,
        fuser::MountOption::NoDev,
        fuser::MountOption::NoSuid,
        fuser::MountOption::Subtype("tidefs".to_string()),
    ]
}

pub fn request_ctx() -> RequestCtx {
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

// ---------------------------------------------------------------------------
// MountedVfs
// ---------------------------------------------------------------------------

pub struct MountedVfs {
    pub root: PathBuf,
    pub store: PathBuf,
    pub mount: PathBuf,
    session: Option<fuser::BackgroundSession>,
}

impl MountedVfs {
    /// Create store + mount dirs, seed pre-existing entries, then mount.
    /// Panics (and fails the test) if FUSE is unavailable — callers should
    /// guard with `require_fuse!()` first.
    pub fn new(fsname: &str, filenames: &[&str], dirnames: &[&str]) -> Self {
        if !fuse_available() {
            panic!("FUSE is not available; guard test with require_fuse!()");
        }
        let root = unique_test_root(fsname);
        let store = root.join("store");
        let mount = root.join("mnt");
        fs::create_dir_all(&store).expect("create store dir");
        fs::create_dir_all(&mount).expect("create mount dir");

        let mut mounted = Self {
            root,
            store,
            mount,
            session: None,
        };
        mounted.seed_entries(filenames, dirnames);
        mounted.mount();
        mounted
    }

    /// Resolve a path relative to the mount point.
    pub fn path(&self, relative: &str) -> PathBuf {
        self.mount.join(relative.trim_start_matches('/'))
    }

    /// Mount the FUSE filesystem (re)using the current store directory.
    pub fn mount(&mut self) {
        let engine = self.open_engine();
        let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create FUSE VFS adapter");
        let session = fuser::spawn_mount2(adapter, &self.mount, &mount_options("tidefs"))
            .expect("mount FUSE");
        self.session = Some(session);
    }

    /// Unmount the FUSE filesystem, waiting briefly for kernel teardown.
    pub fn unmount(&mut self) {
        if let Some(session) = self.session.take() {
            drop(session);
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Unmount and then re-mount, re-reading the backing store.
    #[allow(dead_code)] // Shared harness API: not every integration-test crate remounts.
    pub fn remount(&mut self) {
        self.unmount();
        self.mount();
    }

    fn open_engine(&self) -> VfsLocalFileSystem {
        let filesystem = LocalFileSystem::open_with_root_authentication_key(
            &self.store,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open local filesystem");
        VfsLocalFileSystem::new(filesystem)
    }

    fn seed_entries(&self, filenames: &[&str], dirnames: &[&str]) {
        let engine = self.open_engine();
        let ctx = request_ctx();
        let root = engine.get_root_inode(&ctx).expect("root inode");

        for dirname in dirnames {
            engine
                .mkdir(root, dirname.as_bytes(), 0o755, &ctx)
                .unwrap_or_else(|err| panic!("seed directory {dirname}: {err:?}"));
        }
        for filename in filenames {
            engine
                .create(root, filename.as_bytes(), 0o644, 0, &ctx)
                .unwrap_or_else(|err| panic!("seed file {filename}: {err:?}"));
        }
    }
}

impl Drop for MountedVfs {
    fn drop(&mut self) {
        self.unmount();
        let _ = fs::remove_dir_all(&self.root);
    }
}

// ---------------------------------------------------------------------------
// Convenience I/O helpers for test bodies
// ---------------------------------------------------------------------------

/// Create and open a mounted file for reading and writing.
/// Uses create_new (O_CREAT|O_EXCL) to match the pattern validated by
/// existing FUSE integration tests.
#[allow(dead_code)] // Shared harness API: some includers only need mount lifecycle.
pub fn create_read_write(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .expect("create mounted file read-write")
}

/// Open a mounted file for reading only.
#[allow(dead_code)] // Shared harness API: only large-file tests need direct read handles.
pub fn open_read_only(path: &Path) -> File {
    File::open(path).expect("open mounted file read-only")
}

/// Read the entire contents of a mounted file into a Vec<u8>.
#[allow(dead_code)] // Shared harness API: several includers verify metadata only.
pub fn read_all(path: &Path) -> Vec<u8> {
    let mut file = open_read_only(path);
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .expect("read mounted file to end");
    buf
}

/// Generate deterministic patterned bytes of a given length.
#[allow(dead_code)] // Shared harness API: metadata-only includers do not need payloads.
pub fn patterned_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|idx| ((idx.wrapping_mul(31).wrapping_add(7)) % 251) as u8)
        .collect()
}
