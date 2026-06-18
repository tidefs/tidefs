// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mounted fsync/fdatasync/fsyncdir smoke tests for the VFS-backed FUSE adapter.
//!
//! Consolidates coverage previously split across:
//! - fuse_fsync_smoke.rs (preview adapter fsync/fdatasync)
//! - fsync_fdatasync_tests.rs (VFS-backed fsync/fdatasync)
//! - fsyncdir_smoke.rs (VFS-backed fsyncdir)
//!
//! All tests use the unified MountedVfs harness through FuseVfsAdapter.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::sync::Arc;
use tidefs_cache_core::page_cache::PageCache;
use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;
use tidefs_types_vfs_core::RequestCtx;
use tidefs_vfs_engine::VfsEngine;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn unique_test_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "tidefs-fuse-sync-smoke-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-fuse-sync-smoke".to_string()),
        fuser::MountOption::RW,
        fuser::MountOption::NoDev,
        fuser::MountOption::NoSuid,
        fuser::MountOption::Subtype("tidefs".to_string()),
    ]
}

struct MountedVfs {
    root: PathBuf,
    store: PathBuf,
    mount: PathBuf,
    session: Option<fuser::BackgroundSession>,
    writeback_page_cache: Option<Arc<PageCache>>,
}

impl MountedVfs {
    fn new(filenames: &[&str], dirnames: &[&str]) -> Self {
        let root = unique_test_root();
        let store = root.join("store");
        let mount = root.join("mnt");
        fs::create_dir_all(&store).expect("create store dir");
        fs::create_dir_all(&mount).expect("create mount dir");

        let mut mounted = Self {
            root,
            store,
            mount,
            session: None,
            writeback_page_cache: None,
        };
        mounted.seed_entries(filenames, dirnames);
        mounted.mount();
        mounted
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.mount.join(relative.trim_start_matches('/'))
    }

    fn with_writeback_page_cache(mut self, cache: Arc<PageCache>) -> Self {
        self.writeback_page_cache = Some(cache);
        if self.session.is_some() {
            self.unmount();
            self.mount();
        }
        self
    }

    fn mount(&mut self) {
        let engine = self.open_engine();
        let mut adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create FUSE VFS adapter");
        if let Some(ref cache) = self.writeback_page_cache {
            adapter = adapter.with_writeback_page_cache(Arc::clone(cache));
        }
        let session =
            fuser::spawn_mount2(adapter, &self.mount, &mount_options()).expect("mount FUSE");
        self.session = Some(session);
    }

    fn unmount(&mut self) {
        if let Some(session) = self.session.take() {
            drop(session);
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn remount(&mut self) {
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
                .unwrap_or_else(|err| panic!("seed mounted VFS directory {dirname}: {err:?}"));
        }
        for filename in filenames {
            engine
                .create(root, filename.as_bytes(), 0o644, 0, &ctx)
                .unwrap_or_else(|err| panic!("seed mounted VFS file {filename}: {err:?}"));
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
// Shared helpers
// ---------------------------------------------------------------------------

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

fn read_all(path: &Path) -> Vec<u8> {
    let mut file = File::open(path).expect("open mounted VFS file for readback");
    let mut readback = Vec::new();
    file.read_to_end(&mut readback)
        .expect("read mounted VFS file");
    readback
}

fn create_read_write(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open mounted VFS file read-write")
}

fn write_payload(path: &Path, payload: &[u8]) {
    let mut file = create_read_write(path);
    file.write_all(payload)
        .expect("write payload through mounted VFS file");
}

fn open_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(path)
}

fn sync_directory(path: &Path) {
    let directory = open_directory(path).expect("open mounted VFS directory");
    directory
        .sync_all()
        .expect("fsyncdir mounted VFS directory");
}

fn write_file_create(path: &Path, payload: &[u8]) {
    let mut file = File::create(path).expect("create mounted VFS file");
    file.write_all(payload)
        .expect("write mounted VFS file payload");
}

fn assert_raw_errno(err: &io::Error, expected: i32) {
    assert_eq!(
        err.raw_os_error(),
        Some(expected),
        "unexpected error: {err}"
    );
}

// ===========================================================================
// fsync after write
// ===========================================================================

/// fsync on the same handle that performed the write survives remount.
#[test]
fn fsync_after_write_same_handle_survives_remount() {
    let mut mnt = MountedVfs::new(&["fsync-same-handle.bin"], &[]);
    let path = mnt.path("/fsync-same-handle.bin");
    let payload = b"fsync on write handle survives VFS adapter remount\n";

    {
        let mut file = create_read_write(&path);
        file.write_all(payload).expect("write payload");
        file.sync_all().expect("fsync on write handle");
    }

    mnt.remount();

    assert_eq!(read_all(&mnt.path("/fsync-same-handle.bin")), payload);
}

/// fsync on a separate handle opened after write survives remount.
#[test]
fn fsync_after_write_close_survives_remount() {
    let mut mnt = MountedVfs::new(&["fsync-separate-handle.bin"], &[]);
    let path = mnt.path("/fsync-separate-handle.bin");
    let payload = b"fsync on separate handle survives VFS adapter remount";

    write_payload(&path, payload);
    let file = create_read_write(&path);
    file.sync_all().expect("fsync mounted VFS file");
    drop(file);

    mnt.remount();

    assert_eq!(read_all(&mnt.path("/fsync-separate-handle.bin")), payload);
}

/// fsync after overwriting an existing file survives remount.
#[test]
fn fsync_after_overwrite_survives_remount() {
    let mut mnt = MountedVfs::new(&["overwrite-sync.bin"], &[]);
    let path = mnt.path("/overwrite-sync.bin");

    write_payload(&path, b"stale payload");
    write_payload(&path, b"fresh payload");
    let file = create_read_write(&path);
    file.sync_all().expect("fsync overwritten mounted VFS file");
    drop(file);

    mnt.remount();

    assert_eq!(read_all(&mnt.path("/overwrite-sync.bin")), b"fresh payload");
}

// ===========================================================================
// fdatasync
// ===========================================================================

/// fdatasync on a clean (already-persisted) file handle succeeds and survives
/// remount.
#[test]
fn fdatasync_on_clean_file_handle_succeeds() {
    let mut mnt = MountedVfs::new(&["fdatasync-clean.bin"], &[]);
    let path = mnt.path("/fdatasync-clean.bin");
    let payload = b"fdatasync on clean durable data succeeds\n";

    write_payload(&path, payload);
    let file = create_read_write(&path);
    file.sync_all().expect("fsync to make file durable");
    drop(file);

    {
        let file = File::open(&path).expect("open durable mounted file for fdatasync");
        file.sync_data().expect("fdatasync clean mounted file");
    }

    mnt.remount();

    assert_eq!(read_all(&mnt.path("/fdatasync-clean.bin")), payload);
}

/// fdatasync after writing survives remount.
#[test]
fn fdatasync_after_write_survives_remount() {
    let mut mnt = MountedVfs::new(&["fdatasync-write.bin"], &[]);
    let path = mnt.path("/fdatasync-write.bin");
    let payload = b"fdatasync data survives VFS adapter remount";

    write_payload(&path, payload);
    let file = create_read_write(&path);
    file.sync_data().expect("fdatasync mounted VFS file");
    drop(file);

    mnt.remount();

    assert_eq!(read_all(&mnt.path("/fdatasync-write.bin")), payload);
}

// ===========================================================================
// fsync on read-only file
// ===========================================================================

/// fsync on a read-only file descriptor succeeds (no error).
#[test]
fn sync_all_on_read_only_file_is_accepted() {
    let mnt = MountedVfs::new(&["read-only-sync.bin"], &[]);
    let path = mnt.path("/read-only-sync.bin");
    let payload = b"read-only fsync uses the live FUSE file handle";

    write_payload(&path, payload);

    let file = File::open(&path).expect("open mounted VFS file read-only");
    file.sync_all().expect("fsync read-only mounted VFS file");

    assert_eq!(read_all(&path), payload);
}

// ===========================================================================
// fsync after truncate
// ===========================================================================

/// fsync after truncate + seek + partial overwrite survives remount.
#[test]
fn fsync_after_truncate_survives_remount() {
    let mut mnt = MountedVfs::new(&["truncate-sync.bin"], &[]);
    let path = mnt.path("/truncate-sync.bin");

    {
        let mut file = File::create(&path).expect("create mounted file for truncate test");
        file.write_all(b"0123456789abcdef")
            .expect("write initial payload");
        file.set_len(6).expect("truncate mounted file");
        file.seek(SeekFrom::Start(0))
            .expect("seek mounted file after truncate");
        file.write_all(b"SYNC")
            .expect("overwrite beginning of truncated file");
        file.sync_all().expect("fsync truncated mounted file");
    }

    mnt.remount();

    let remounted_path = mnt.path("/truncate-sync.bin");
    assert_eq!(
        fs::metadata(&remounted_path)
            .expect("metadata after remount")
            .len(),
        6
    );
    assert_eq!(read_all(&remounted_path), b"SYNC45");
}

// ===========================================================================
// fsync on directory
// ===========================================================================

/// fsync on a directory handle succeeds and the directory survives remount.
#[test]
fn fsync_on_directory_succeeds_and_survives_remount() {
    let mut mnt = MountedVfs::new(&[], &["synced-dir"]);
    let dir = mnt.path("/synced-dir");

    let dir_handle = File::open(&dir).expect("open mounted VFS directory");
    dir_handle.sync_all().expect("fsync mounted VFS directory");
    drop(dir_handle);

    mnt.remount();

    assert!(mnt.path("/synced-dir").is_dir());
}

// ===========================================================================
// fsyncdir smoke
// ===========================================================================

/// fsyncdir on an empty directory succeeds.
#[test]
fn fsyncdir_empty_directory_succeeds() {
    let mnt = MountedVfs::new(&[], &["empty-dir"]);

    sync_directory(&mnt.path("/empty-dir"));

    assert!(mnt.path("/empty-dir").is_dir());
}

/// fsyncdir on a directory with entries persists those entries across remount.
#[test]
fn fsyncdir_directory_entries_survive_remount() {
    let mut mnt = MountedVfs::new(&[], &["synced-dir"]);
    let dir = mnt.path("/synced-dir");
    let child = dir.join("child.txt");
    let payload = b"directory entry survives fsyncdir remount";

    write_file_create(&child, payload);
    sync_directory(&dir);

    mnt.remount();

    assert_eq!(
        fs::read(mnt.path("/synced-dir/child.txt")).expect("read child after remount"),
        payload
    );
}

/// Parent-directory fsyncdir after mkdir persists the new directory through
/// remount.
#[test]
fn fsyncdir_after_mkdir_persists_new_directory_through_parent_sync() {
    let mut mnt = MountedVfs::new(&[], &[]);
    let parent = mnt.path("/");
    let created = mnt.path("/created-dir");

    fs::create_dir(&created).expect("mkdir through mounted VFS");
    sync_directory(&parent);

    mnt.remount();

    assert!(mnt.path("/created-dir").is_dir());
}

/// Opening a regular file with O_DIRECTORY returns ENOTDIR.
#[test]
fn fsyncdir_regular_file_cannot_be_opened_as_directory() {
    let mnt = MountedVfs::new(&["regular-file"], &[]);

    let err = open_directory(&mnt.path("/regular-file"))
        .expect_err("regular file should not produce a directory handle");

    assert_raw_errno(&err, libc::ENOTDIR);
}

// ===========================================================================
// PageCache writeback integration tests (issue #3538)
// ===========================================================================

/// Write data, fsync, and verify the writeback PageCache has no remaining
/// dirty pages for the inode — all were flushed.
#[test]
fn fsync_pagecache_writeback_clears_dirty_pages() {
    use std::sync::Arc;
    use tidefs_cache_core::page_cache::PageCache;

    let page_cache = Arc::new(PageCache::new(1024, 4096));
    let mnt =
        MountedVfs::new(&["fsync-pc.bin"], &[]).with_writeback_page_cache(Arc::clone(&page_cache));
    let path = mnt.path("/fsync-pc.bin");
    let payload = &[0xAB_u8; 8192]; // 2 pages

    // Write 8 KiB of data through the FUSE mount.
    {
        let mut file = create_read_write(&path);
        file.write_all(payload).expect("write payload");
        // fsync triggers PageCache writeback.
        file.sync_all().expect("fsync via FUSE mount");
    }

    // After fsync, the writeback PageCache should have no dirty pages
    // for this inode (all were written back and cleared).
    // We need the inode number.  Since the file was newly created as
    // the first child of the root, it should be inode 2 or 3 depending
    // on root-inode numbering.  We iterate the dirty_pages list to
    // check virtually.
    assert!(
        page_cache.dirty_pages().is_empty(),
        "all dirty pages must be cleared after fsync"
    );

    // Read back to confirm data integrity.
    let readback = read_all(&path);
    assert_eq!(readback, payload);
}

/// Write data, close (triggering flush), then reopen and verify data
/// survives.  Also verify PageCache dirty pages are cleared by flush.
#[test]
fn flush_pagecache_writeback_clears_dirty_pages_on_close() {
    let page_cache = Arc::new(PageCache::new(1024, 4096));
    let mut mnt = MountedVfs::new(&[], &[]).with_writeback_page_cache(Arc::clone(&page_cache));
    let path = mnt.path("/flush-pc.bin");
    let payload = b"flush on close writes back dirty pages via PageCache";

    // Write through FUSE, then close.  close() triggers FUSE flush.
    {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create mounted VFS file");
        file.write_all(payload).expect("write payload");
        // file drops here -> close() -> FUSE flush -> PageCache writeback
    }

    // After close+flush, PageCache should have no dirty pages.
    assert!(
        page_cache.dirty_pages().is_empty(),
        "dirty pages must be cleared after flush (close)"
    );

    // Remount and verify data survived.
    mnt.remount();
    assert_eq!(read_all(&mnt.path("/flush-pc.bin")), payload);
}

/// Write data, fsync, then check that the writeback PageCache has
/// evictable clean pages (not dirty, not pinned) for the written ranges.
#[test]
fn fsync_pagecache_pages_are_clean_not_pinned_after_writeback() {
    let page_cache = Arc::new(PageCache::new(1024, 4096));
    let mnt = MountedVfs::new(&["clean-pages.bin"], &[])
        .with_writeback_page_cache(Arc::clone(&page_cache));
    let path = mnt.path("/clean-pages.bin");

    // Write 12 KiB (3 pages).
    {
        let mut file = create_read_write(&path);
        file.write_all(&[0xCC_u8; 12288]).expect("write 3 pages");
        file.sync_all().expect("fsync");
    }

    // All dirty pages must be clean now.
    assert!(
        page_cache.dirty_pages().is_empty(),
        "all dirty pages must be cleared after fsync"
    );

    // The pages should still be resident (clean, evictable) in the cache
    // since mark_dirty inserted them and complete_writeback made them clean.
    // We can't directly count by inode without knowing the inode number,
    // but we can verify the cache is non-empty.
    assert!(
        page_cache.len() >= 3,
        "at least 3 pages should remain resident after fsync"
    );

    // Read back and verify data.
    assert_eq!(read_all(&path), &[0xCC_u8; 12288]);
}

/// Write through FUSE, fsync, verify data persists across remount,
/// and confirm the writeback PageCache dirty-set is empty after fsync.
#[test]
fn fsync_pagecache_writeback_remount_persistence() {
    let page_cache = Arc::new(PageCache::new(1024, 4096));
    let mut mnt = MountedVfs::new(&["persist-pc.bin"], &[])
        .with_writeback_page_cache(Arc::clone(&page_cache));
    let path = mnt.path("/persist-pc.bin");
    let payload = b"fsync pagecache writeback survives remount cycle";

    {
        let mut file = create_read_write(&path);
        file.write_all(payload).expect("write payload");
        file.sync_all().expect("fsync");
    }

    assert!(page_cache.dirty_pages().is_empty());

    mnt.remount();
    assert_eq!(read_all(&mnt.path("/persist-pc.bin")), payload);
}

// ===========================================================================
// Object-store persistence verification (issue #3732)
// ===========================================================================

/// Write through FUSE, fsync, unmount, then open the same LocalFileSystem
/// store directly (bypassing FUSE) and verify the data is present in the
/// backing object store.  This confirms that fsync flushes writeback
/// through the LocalFileSystem into durable segment storage.
#[test]
fn fsync_flushes_writeback_to_object_store_verified_direct() {
    let page_cache = Arc::new(PageCache::new(1024, 4096));
    let mut mnt = MountedVfs::new(&["store-verify.bin"], &[])
        .with_writeback_page_cache(Arc::clone(&page_cache));
    let path = mnt.path("/store-verify.bin");
    let payload: Vec<u8> = (0..2048u16).map(|i| (i % 251) as u8).collect();

    // Write through FUSE mount, then fsync.
    {
        let mut file = create_read_write(&path);
        file.write_all(&payload).expect("write payload via FUSE");
        file.sync_all().expect("fsync via FUSE");
    }

    // PageCache dirty set must be empty after fsync.
    assert!(
        page_cache.dirty_pages().is_empty(),
        "no dirty pages should remain after fsync"
    );

    // Unmount to flush all adapter state.
    mnt.unmount();

    // Open the store directly via LocalFileSystem (bypass FUSE entirely).
    {
        let store_path = mnt.store.clone();
        let direct_fs = LocalFileSystem::open_with_root_authentication_key(
            &store_path,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open LocalFileSystem directly on object store");

        // Read the file directly through LocalFileSystem, not through FUSE.
        let direct_read = direct_fs
            .read_file("/store-verify.bin")
            .expect("read file directly from LocalFileSystem");
        assert_eq!(
            direct_read, payload,
            "data read directly from object store must match written payload"
        );

        // Verify the store has committed objects via filesystem stats.
        let stats = direct_fs.stats();
        assert!(
            stats.object_store.live_objects > 0,
            "object store must contain at least one live object after fsync"
        );
    }
}

// ===========================================================================
// fdatasync object-store persistence verification (issue #3732)
// ===========================================================================

/// Write through FUSE, fdatasync, unmount, then open the local store
/// directly and verify data is present.  Same pattern as the fsync
/// variant but uses fdatasync (sync_data) instead of sync_all.
#[test]
fn fdatasync_flushes_writeback_to_object_store_verified_direct() {
    let page_cache = Arc::new(PageCache::new(1024, 4096));
    let mut mnt = MountedVfs::new(&["fdatasync-store.bin"], &[])
        .with_writeback_page_cache(Arc::clone(&page_cache));
    let path = mnt.path("/fdatasync-store.bin");
    let payload: Vec<u8> = (0..4096u16)
        .map(|i| (i.wrapping_mul(17) % 251) as u8)
        .collect();

    // Write through FUSE mount, then fdatasync (data-only sync).
    {
        let mut file = create_read_write(&path);
        file.write_all(&payload).expect("write payload via FUSE");
        file.sync_data().expect("fdatasync via FUSE");
    }

    // PageCache dirty set must be empty after fdatasync.
    assert!(
        page_cache.dirty_pages().is_empty(),
        "no dirty pages should remain after fdatasync"
    );

    // Unmount to flush all adapter state.
    mnt.unmount();

    // Open the store directly via LocalFileSystem (bypass FUSE entirely).
    {
        let store_path = mnt.store.clone();
        let direct_fs = LocalFileSystem::open_with_root_authentication_key(
            &store_path,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open LocalFileSystem directly on object store");

        let direct_read = direct_fs
            .read_file("/fdatasync-store.bin")
            .expect("read file directly from LocalFileSystem");
        assert_eq!(
            direct_read, payload,
            "data read directly from object store must match fdatasync'd payload"
        );

        let stats = direct_fs.stats();
        assert!(
            stats.object_store.live_objects > 0,
            "object store must contain at least one live object after fdatasync"
        );
    }
}
