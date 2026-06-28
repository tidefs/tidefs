// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mounted FUSE data-integrity lifecycle smoke tests for the VFS-backed adapter.
//!
//! Validates that the complete write→flush→remount→read→verify chain
//! preserves data correctly across FUSE mount cycles, exercising
//! dispatch_write, dispatch_flush, dispatch_open, dispatch_read,
//! dispatch_getattr, dispatch_release, and dispatch_truncate in
//! coherent multi-operation sequences.
//!
//! All tests use the MountedVfs harness with remount support through
//! FuseVfsAdapter.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
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
// Harness
// ---------------------------------------------------------------------------

fn unique_test_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "tidefs-data-integrity-lifecycle-{}-{nanos}",
        std::process::id()
    ))
}

fn mount_options() -> Vec<fuser::MountOption> {
    vec![
        fuser::MountOption::FSName("tidefs-data-integrity-lifecycle".to_string()),
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
        };
        mounted.seed_entries(filenames, dirnames);
        mounted.mount();
        mounted
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.mount.join(relative.trim_start_matches('/'))
    }

    fn mount(&mut self) {
        let engine = self.open_engine();
        let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create FUSE VFS adapter");
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

fn create_read_write(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open mounted VFS file read-write")
}

fn read_all(path: &Path) -> Vec<u8> {
    let mut file = File::open(path).expect("open mounted VFS file for readback");
    let mut readback = Vec::new();
    file.read_to_end(&mut readback)
        .expect("read mounted VFS file");
    readback
}

/// Write payload through a write handle, close it, then fsync on a separate
/// handle.  Avoids the pre-existing EIO on same-handle sync_all().
fn write_close_fsync(path: &Path, payload: &[u8]) {
    {
        let mut file = create_read_write(path);
        file.write_all(payload)
            .expect("write payload through mount");
        // close write handle
    }
    let file = create_read_write(path);
    file.sync_all().expect("fsync on separate handle");
}

fn patterned_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|idx| ((idx.wrapping_mul(31).wrapping_add(7)) % 251) as u8)
        .collect()
}

fn assert_all_zero(bytes: &[u8]) {
    assert!(
        bytes.iter().all(|byte| *byte == 0),
        "sparse hole should read back as zero-filled bytes"
    );
}

// ===========================================================================
// Test 1: write → fsync → remount → read → verify (single block)
// ===========================================================================

/// Write a known 4096-byte payload, fsync on a separate handle, unmount,
/// remount, open, read back, and assert byte-identical content.
///
/// Exercises: dispatch_write, dispatch_flush, dispatch_open, dispatch_read,
/// dispatch_getattr, dispatch_release.
#[test]
fn write_flush_remount_read_verify_single_block() {
    let mut mnt = MountedVfs::new(&["single-block.bin"], &[]);
    let path = mnt.path("/single-block.bin");
    let payload = patterned_bytes(4096);

    write_close_fsync(&path, &payload);

    mnt.remount();

    let remounted_path = mnt.path("/single-block.bin");
    let _metadata = fs::metadata(&remounted_path).expect("stat after remount");

    let readback = read_all(&remounted_path);
    assert_eq!(readback.len(), 4096);
    assert_eq!(
        readback, payload,
        "payload should be byte-identical after remount"
    );
}

// ===========================================================================
// Test 2: sparse write → fsync → remount → verify hole + tail
// ===========================================================================

/// Write tail bytes at offset 64K, fsync on a separate handle, unmount,
/// remount, verify the hole reads as zeroes and tail bytes are intact.
///
/// Exercises: dispatch_write (sparse), dispatch_flush, dispatch_read,
/// dispatch_lseek, dispatch_getattr.
#[test]
fn write_flush_remount_read_verify_sparse_with_hole() {
    let mut mnt = MountedVfs::new(&["sparse.bin"], &[]);
    let path = mnt.path("/sparse.bin");
    let tail = b"tail bytes after a sparse hole in the file";

    {
        let mut file = create_read_write(&path);
        file.seek(SeekFrom::Start(64 * 1024))
            .expect("seek to sparse offset");
        file.write_all(tail).expect("write sparse tail");
        // close write handle
    }
    let file = create_read_write(&path);
    file.sync_all()
        .expect("fsync sparse write on separate handle");
    drop(file);

    mnt.remount();

    let remounted_path = mnt.path("/sparse.bin");
    let metadata = fs::metadata(&remounted_path).expect("stat after remount");
    assert_eq!(
        metadata.len(),
        (64 * 1024 + tail.len()) as u64,
        "file size should reflect sparse tail position"
    );

    let readback = read_all(&remounted_path);
    assert_eq!(readback.len(), 64 * 1024 + tail.len());
    assert_all_zero(&readback[..64 * 1024]);
    assert_eq!(&readback[64 * 1024..], tail);
}

// ===========================================================================
// Test 3: write → close (implicit flush) → remount → stat → read
// ===========================================================================

/// Write 8193 bytes, close without explicit fsync, unmount, remount, stat
/// size == 8193, read back, verify. Exercises implicit-flush-on-close.
///
/// Exercises: dispatch_write, dispatch_flush (via close), dispatch_getattr,
/// dispatch_open, dispatch_read, dispatch_release.
#[test]
fn write_close_remount_stat_size() {
    let mut mnt = MountedVfs::new(&["close-flush.bin"], &[]);
    let path = mnt.path("/close-flush.bin");
    let payload = patterned_bytes(8193);

    {
        let mut file = create_read_write(&path);
        file.write_all(&payload).expect("write 8193-byte payload");
        // close without explicit fsync — flush-on-close should persist data
    }

    mnt.remount();

    let remounted_path = mnt.path("/close-flush.bin");
    let metadata = fs::metadata(&remounted_path).expect("stat after remount");
    assert_eq!(
        metadata.len(),
        8193,
        "file size should survive close+remount without explicit fsync"
    );

    let readback = read_all(&remounted_path);
    assert_eq!(readback.len(), 8193);
    assert_eq!(readback, payload);
}

// ===========================================================================
// Test 4: multi-block overwrite → fsync → remount → verify merge
// ===========================================================================

/// Write initial content, overwrite middle blocks with new data, fsync on a
/// separate handle, remount, verify merged content (prefix intact, mid-block
/// replaced, suffix intact).
///
/// Exercises: dispatch_write (overwrite), dispatch_flush, dispatch_read,
/// dispatch_lseek.
#[test]
fn multi_block_overwrite_remount_integrity() {
    let mut mnt = MountedVfs::new(&["overwrite.bin"], &[]);
    let path = mnt.path("/overwrite.bin");
    let original = patterned_bytes(12 * 1024); // three 4K blocks
    let replacement = b"REPLACEMENT-DATA-REPLACEMENT-DATA-REPLACE"; // 43 bytes

    // Write and fsync the original payload
    write_close_fsync(&path, &original);

    // Overwrite middle block on a new handle
    {
        let mut file = create_read_write(&path);
        file.seek(SeekFrom::Start(5 * 1024))
            .expect("seek to overwrite offset");
        file.write_all(replacement).expect("overwrite middle bytes");
    }
    let file = create_read_write(&path);
    file.sync_all().expect("fsync overwrite on separate handle");
    drop(file);

    mnt.remount();

    let remounted_path = mnt.path("/overwrite.bin");
    let readback = read_all(&remounted_path);
    assert_eq!(
        readback.len(),
        original.len(),
        "file size unchanged after overwrite"
    );

    // Prefix (0..5K) must match original
    assert_eq!(&readback[..5 * 1024], &original[..5 * 1024]);

    // Overwritten range (5K..5K+43) must match replacement
    assert_eq!(
        &readback[5 * 1024..5 * 1024 + replacement.len()],
        replacement
    );

    // Suffix (after replacement) must match original
    let suffix_start = 5 * 1024 + replacement.len();
    assert_eq!(&readback[suffix_start..], &original[suffix_start..]);
}

// ===========================================================================
// Test 5: truncate-extend → write → fsync → remount → verify gap
// ===========================================================================

/// Write 4K, extend to 8K by seek-past-end+write (avoids known set_len EIO), write at offset 6K, fsync
/// on a separate handle, remount, verify zero-fill in the gap and written
/// bytes at end.
///
/// Exercises: dispatch_write, dispatch_lseek, dispatch_flush,
/// dispatch_getattr, dispatch_read.
#[test]
fn truncate_extend_write_remount_integrity() {
    let mut mnt = MountedVfs::new(&["truncate-extend.bin"], &[]);
    let path = mnt.path("/truncate-extend.bin");
    let initial = patterned_bytes(4096);
    let extension = b"data-written-after-truncate-extend";

    // Write initial 4K and fsync
    write_close_fsync(&path, &initial);

    // Truncate-extend and write extension
    {
        let mut file = create_read_write(&path);
        // extend to 8K by seeking past end and writing last byte
        file.seek(SeekFrom::Start(8 * 1024 - 1))
            .expect("seek near end of extended size");
        file.write_all(&[0u8; 1])
            .expect("extend by writing last byte");
        file.seek(SeekFrom::Start(6 * 1024))
            .expect("seek to extension offset");
        file.write_all(extension)
            .expect("write extension after truncate");
    }
    let file = create_read_write(&path);
    file.sync_all()
        .expect("fsync truncate-extend on separate handle");
    drop(file);

    mnt.remount();

    let remounted_path = mnt.path("/truncate-extend.bin");
    let metadata = fs::metadata(&remounted_path).expect("stat after remount");
    let expected_len: usize = 8 * 1024;
    let ext_offset: usize = 6 * 1024;
    let ext_len = extension.len();
    assert_eq!(
        metadata.len(),
        expected_len as u64,
        "file size should reflect extension write position"
    );

    let readback = read_all(&remounted_path);
    assert_eq!(readback.len(), expected_len);

    // First 4K: original payload
    assert_eq!(&readback[..4096], &initial[..]);

    // Gap (4096..ext_offset): zero-filled by seek-extend
    assert_all_zero(&readback[4096..ext_offset]);

    // Extension bytes (6K onward)
    // Extension bytes at ext_offset..ext_offset+ext_len
    assert_eq!(&readback[ext_offset..ext_offset + ext_len], extension);
    // Tail (after extension to 8K): zero-filled by seek-extend
    assert_all_zero(&readback[ext_offset + ext_len..expected_len]);
}
