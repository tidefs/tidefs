#![cfg(target_os = "linux")]

//! Mounted FUSE integration tests filling coverage gaps for POSIX
//! directory-name operations (rename, link, symlink) through the VFS
//! adapter.
//!
//! Existing coverage in sibling test files already exercises the bulk
//! of rename/link/symlink semantics. This file adds three edge cases
//! that were not yet covered:
//!
//!  1. hard-link to self → EEXIST
//!  2. symlink chain → readlink returns raw intermediate, stat follows
//!  3. rename over symlink → symlink atomically replaced by real file
//!
//! The harness mirrors rename_mount_integration.rs: each test acquires a
//! global test lock, mounts a fresh VFS-backed FUSE daemon, performs
//! operations through the kernel VFS, and unmounts cleanly on drop.

use std::fs;
use std::io;
use std::os::unix::fs::{self as unix_fs, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;

// ── harness ────────────────────────────────────────────────────────

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn test_lock() -> MutexGuard<'static, ()> {
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
        "tidefs-rename-link-symlink-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-rename-link-symlink".to_string()),
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

// ── hard-link to self ──────────────────────────────────────────────

/// Issue #3993 case 7: linking a file to itself must return EEXIST.
/// POSIX requires that link(old, new) with old == new (same inode)
/// fails with EEXIST.
#[test]
fn hard_link_to_self_returns_eexist() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();
    let file = mnt.path("/file.txt");

    fs::write(&file, b"self-link content").expect("write file");

    let err = fs::hard_link(&file, &file).expect_err("link to self must fail");
    assert_raw_errno(&err, libc::EEXIST);

    // After the failed operation the file must be intact.
    let meta = fs::metadata(&file).expect("file metadata after failed self-link");
    assert_eq!(
        meta.nlink(),
        1,
        "link count unchanged after failed self-link"
    );
    assert_eq!(
        fs::read(&file).expect("read after failed self-link"),
        b"self-link content"
    );
}

// ── symlink chain ──────────────────────────────────────────────────

/// Issue #3993 case 9: a symlink chain `a → b → c`.
/// readlink("c") returns "b" (raw target, no kernel-side resolution).
/// stat("c") follows the chain and resolves to the file "a".
#[test]
fn symlink_chain_readlink_returns_raw_target_stat_follows() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();

    let a = mnt.path("/a");
    let b = mnt.path("/b");
    let c = mnt.path("/c");

    fs::write(&a, b"chain payload").expect("write a");

    unix_fs::symlink("a", &b).expect("symlink b → a");
    unix_fs::symlink("b", &c).expect("symlink c → b");

    // readlink returns the raw target — no kernel-side resolution.
    assert_eq!(
        fs::read_link(&c).expect("readlink c"),
        Path::new("b"),
        "readlink(c) must return raw target 'b'"
    );
    assert_eq!(
        fs::read_link(&b).expect("readlink b"),
        Path::new("a"),
        "readlink(b) must return raw target 'a'"
    );

    // stat follows the full chain.
    let st = fs::metadata(&c).expect("stat c through symlink chain");
    assert!(st.is_file(), "stat(c) should resolve to a regular file");

    // Content visible through the chain.
    assert_eq!(
        fs::read_to_string(&c).expect("read through symlink chain"),
        "chain payload"
    );
}

// ── rename over symlink ────────────────────────────────────────────

/// Issue #3993 case 10: rename("realfile", "symlink") replaces the
/// symlink atomically with the real file. The symlink is gone and the
/// file content is accessible at the former symlink path.
#[test]
fn rename_over_symlink_replaces_symlink_with_file() {
    let _guard = test_lock();
    let mnt = MountedVfs::new();

    let real = mnt.path("/realfile");
    let sym = mnt.path("/symlink");

    fs::write(&real, b"rename-over-symlink payload").expect("write realfile");
    unix_fs::symlink("nonexistent-target", &sym).expect("create symlink");

    // Verify the symlink exists before rename.
    let sym_meta_before = fs::symlink_metadata(&sym).expect("symlink metadata before");
    assert!(
        sym_meta_before.file_type().is_symlink(),
        "entry must be a symlink before rename"
    );

    fs::rename(&real, &sym).expect("rename realfile over symlink");

    // After rename: symlink is gone, real file occupies the path.
    let sym_meta_after = fs::symlink_metadata(&sym).expect("metadata after rename");
    assert!(
        sym_meta_after.file_type().is_file(),
        "entry must be a regular file after rename over symlink"
    );

    assert_eq!(
        fs::read_to_string(&sym).expect("read renamed file"),
        "rename-over-symlink payload"
    );

    // The old realfile path must be gone.
    assert!(
        fs::metadata(&real).is_err(),
        "old realfile path must not exist after rename"
    );
}
