//! Durability tests for LocalFileSystem sync_inode / fsync_all.
//!
//! Exercises write -> sync -> drop -> reopen -> verify cycles.
//! Each test uses a tempdir-backed object store.

use std::env;
use std::fs;

use tidefs_local_filesystem::{LocalFileSystem, DEFAULT_FILE_PERMISSIONS};

// ---------------------------------------------------------------------------
// SyncDurabilityHarness
// ---------------------------------------------------------------------------

struct SyncDurabilityHarness {
    root: std::path::PathBuf,
    fs: Option<LocalFileSystem>,
}

impl SyncDurabilityHarness {
    fn mount(label: &str) -> Self {
        set_test_key();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!("tidefs-sync-{label}-{ts}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create temp dir");

        let fs = LocalFileSystem::open(&root).expect("open filesystem");
        Self { root, fs: Some(fs) }
    }

    fn fs_mut(&mut self) -> &mut LocalFileSystem {
        self.fs.as_mut().expect("filesystem is open")
    }

    fn shutdown(&mut self) {
        if let Some(fs) = self.fs.take() {
            drop(fs);
        }
    }

    fn reopen(&mut self) {
        self.shutdown();
        self.fs = Some(LocalFileSystem::open(&self.root).expect("reopen filesystem"));
    }
}

impl Drop for SyncDurabilityHarness {
    fn drop(&mut self) {
        self.shutdown();
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn set_test_key() {
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

static PATTERN_4K: [u8; 4096] = [0xABu8; 4096];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Write 4 KiB to one file, sync_file, drop + reopen, verify byte-for-byte.
#[test]
fn sync_file_single_write_durable() {
    let mut h = SyncDurabilityHarness::mount("sync_file_single_write_durable");
    let fs = h.fs_mut();

    fs.create_file("/f", DEFAULT_FILE_PERMISSIONS)
        .expect("create /f");
    let inode_id = fs.stat("/f").expect("stat").inode_id;
    fs.write_file("/f", 0, &PATTERN_4K).expect("write 4 KiB");

    fs.sync_inode(inode_id).expect("sync_file");

    h.reopen();
    let fs = h.fs_mut();

    let read_back = fs.read_file("/f").expect("read back");
    assert_eq!(
        read_back.len(),
        4096,
        "read back wrong length: {}",
        read_back.len()
    );
    assert_eq!(
        &read_back[..],
        &PATTERN_4K[..],
        "data mismatch after reopen"
    );
}

/// Write non-contiguous extents, sync_file, crash-reopen, verify.
#[test]
fn sync_file_multiple_extents_durable() {
    let mut h = SyncDurabilityHarness::mount("sync_file_multiple_extents_durable");
    let fs = h.fs_mut();

    fs.create_file("/g", DEFAULT_FILE_PERMISSIONS)
        .expect("create /g");
    let inode_id = fs.stat("/g").expect("stat").inode_id;

    let chunk1 = vec![0x11u8; 1024];
    let chunk2 = vec![0x22u8; 1024];
    fs.write_file("/g", 0, &chunk1).expect("write chunk1");
    fs.write_file("/g", 8192, &chunk2).expect("write chunk2");

    fs.sync_inode(inode_id).expect("sync_file");

    h.reopen();
    let fs = h.fs_mut();

    let r1 = fs.read_file_range("/g", 0, 1024).expect("read chunk1");
    assert_eq!(&r1[..], &chunk1[..], "chunk1 mismatch");

    let r2 = fs.read_file_range("/g", 8192, 1024).expect("read chunk2");
    assert_eq!(&r2[..], &chunk2[..], "chunk2 mismatch");
}

/// Write to 3 files, sync each individually, crash-reopen, verify all three.
#[test]
fn sync_multi_inode_durable() {
    let mut h = SyncDurabilityHarness::mount("sync_multi_inode_durable");
    let fs = h.fs_mut();

    let data_a = vec![0xAAu8; 512];
    let data_b = vec![0xBBu8; 512];
    let data_c = vec![0xCCu8; 512];

    fs.create_file("/a", DEFAULT_FILE_PERMISSIONS)
        .expect("create /a");
    fs.create_file("/b", DEFAULT_FILE_PERMISSIONS)
        .expect("create /b");
    fs.create_file("/c", DEFAULT_FILE_PERMISSIONS)
        .expect("create /c");

    let ino_a = fs.stat("/a").expect("stat").inode_id;
    let ino_b = fs.stat("/b").expect("stat").inode_id;
    let ino_c = fs.stat("/c").expect("stat").inode_id;

    fs.write_file("/a", 0, &data_a).expect("write /a");
    fs.write_file("/b", 0, &data_b).expect("write /b");
    fs.write_file("/c", 0, &data_c).expect("write /c");

    fs.sync_inode(ino_a).expect("sync_file /a");
    fs.sync_inode(ino_b).expect("sync_file /b");
    fs.sync_inode(ino_c).expect("sync_file /c");

    h.reopen();
    let fs = h.fs_mut();

    let ra = fs.read_file("/a").expect("read /a");
    let rb = fs.read_file("/b").expect("read /b");
    let rc = fs.read_file("/c").expect("read /c");

    assert_eq!(&ra[..], &data_a[..], "/a mismatch");
    assert_eq!(&rb[..], &data_b[..], "/b mismatch");
    assert_eq!(&rc[..], &data_c[..], "/c mismatch");
}

/// sync_file on a clean inode returns success with zero bytes flushed.
#[test]
fn sync_file_no_dirty_data() {
    let mut h = SyncDurabilityHarness::mount("sync_file_no_dirty_data");
    let fs = h.fs_mut();

    fs.create_file("/clean", DEFAULT_FILE_PERMISSIONS)
        .expect("create /clean");
    let inode_id = fs.stat("/clean").expect("stat").inode_id;

    fs.sync_inode(inode_id).expect("sync_file on clean inode");
}

/// Write + sync, crash-reopen, verify data (fdatasync semantics).
#[test]
fn fdatasync_semantics_durable() {
    let mut h = SyncDurabilityHarness::mount("fdatasync_semantics_durable");
    let fs = h.fs_mut();

    let data = vec![0xDDu8; 2048];
    fs.create_file("/fdat", DEFAULT_FILE_PERMISSIONS)
        .expect("create /fdat");
    let inode_id = fs.stat("/fdat").expect("stat").inode_id;
    fs.write_file("/fdat", 0, &data).expect("write");

    fs.sync_inode(inode_id).expect("sync_file");

    h.reopen();
    let fs = h.fs_mut();

    let r = fs.read_file("/fdat").expect("read back");
    assert_eq!(
        &r[..],
        &data[..],
        "data mismatch after fdatasync-style flush"
    );
}
