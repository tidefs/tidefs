// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Concurrent-operation and data-integrity validation tests for the
//! VFS-backed FUSE adapter.
//!
//! Exercises the adapter under concurrent read/write/create/unlink/readdir
//! operations to validate locking, buffer management, and inode state
//! transitions.  Tests use the adapter's dispatch API directly (bypassing
//! FUSE mount) so they run without `/dev/fuse` or kernel FUSE support.
//!
//! Review debt TFR-008: add mount-aware variants once the FUSE
//! mount harness (#3241) is available in the test environment.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Barrier, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

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

type SharedAdapter = Arc<Mutex<FuseVfsAdapter>>;

struct AdapterHarness {
    adapter: SharedAdapter,
    root_ino: u64,
    store_dir: PathBuf,
}

impl AdapterHarness {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let store_dir = std::env::temp_dir().join(format!(
            "tidefs-concurrent-ops-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&store_dir).expect("create store dir");

        let filesystem = LocalFileSystem::open_with_root_authentication_key(
            &store_dir,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open local filesystem");
        let engine = VfsLocalFileSystem::new(filesystem);
        let ctx = request_ctx();
        let root = engine.get_root_inode(&ctx).expect("root inode");
        let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create FUSE VFS adapter");
        Self {
            adapter: Arc::new(Mutex::new(adapter)),
            root_ino: root.get(),
            store_dir,
        }
    }

    fn ctx(&self) -> RequestCtx {
        request_ctx()
    }

    fn shared_adapter(&self) -> SharedAdapter {
        Arc::clone(&self.adapter)
    }

    /// Create a file and return (inode, file_handle).
    fn create_file(&self, name: &[u8]) -> (u64, u64) {
        let a = self.adapter.lock().unwrap();
        let dispatch = a
            .dispatch_create(&self.ctx(), self.root_ino, name, 0o644, libc::O_RDWR as u32)
            .expect("create file");
        (dispatch.inode(), dispatch.file_handle())
    }

    /// Make a directory and return its inode.
    fn mkdir(&self, name: &[u8]) -> u64 {
        let a = self.adapter.lock().unwrap();
        a.dispatch_mkdir(&self.ctx(), self.root_ino, name, 0o755)
            .expect("mkdir");
        a.dispatch_lookup(&self.ctx(), self.root_ino, name)
            .expect("lookup dir")
            .inode_id
            .get()
    }
}

impl Drop for AdapterHarness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.store_dir);
    }
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

fn patterned_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|idx| ((idx.wrapping_mul(31).wrapping_add(7)) % 251) as u8)
        .collect()
}

// ===========================================================================
// Test 1: Concurrent writers, non-overlapping ranges
// ===========================================================================

/// Two threads write to disjoint byte ranges of the same file through the
/// adapter dispatch API, then a reader verifies both ranges are intact.
#[test]
fn concurrent_writers_non_overlapping_ranges() {
    let harness = AdapterHarness::new();
    let ctx = harness.ctx();
    let adapter = harness.shared_adapter();

    let (ino, fh) = harness.create_file(b"concurrent-write.bin");
    let barrier = Arc::new(Barrier::new(2));

    let payload_a = patterned_bytes(4096);
    let payload_b = {
        let mut p = patterned_bytes(4096);
        p[0] = p[0].wrapping_add(1);
        p
    };

    let adapter_a = Arc::clone(&adapter);
    let barrier_a = Arc::clone(&barrier);
    let payload_a_clone = payload_a.clone();

    let adapter_b = Arc::clone(&adapter);
    let barrier_b = Arc::clone(&barrier);
    let payload_b_clone = payload_b.clone();

    let thread_a = std::thread::spawn(move || {
        barrier_a.wait();
        let a = adapter_a.lock().unwrap();
        let written = a
            .dispatch_write(&request_ctx(), ino, fh, 0, &payload_a_clone, 0)
            .expect("thread A write");
        assert_eq!(written as usize, payload_a_clone.len());
    });

    let thread_b = std::thread::spawn(move || {
        barrier_b.wait();
        let a = adapter_b.lock().unwrap();
        let written = a
            .dispatch_write(&request_ctx(), ino, fh, 4096, &payload_b_clone, 0)
            .expect("thread B write");
        assert_eq!(written as usize, payload_b_clone.len());
    });

    thread_a.join().expect("thread A join");
    thread_b.join().expect("thread B join");

    // Read back and verify both ranges
    let a = adapter.lock().unwrap();
    let buf = a
        .dispatch_read(&ctx, ino, fh, 0, 8192, None)
        .expect("read back");
    assert_eq!(buf.len(), 8192);
    assert_eq!(&buf[0..4096], &payload_a[..], "range A mismatch");
    assert_eq!(&buf[4096..8192], &payload_b[..], "range B mismatch");
}

// ===========================================================================
// Test 2: Concurrent reader and writer
// ===========================================================================

/// Writer appends data while reader concurrently reads the existing prefix.
/// The reader must see at least the prefix (no torn data). After both
/// complete, the full content must equal prefix + suffix.
#[test]
fn concurrent_reader_and_writer() {
    let harness = AdapterHarness::new();
    let ctx = harness.ctx();
    let adapter = harness.shared_adapter();

    let prefix = patterned_bytes(4096);
    let suffix = b"APPENDED-CONCURRENT-SUFFIX-DATA";

    let (ino, fh) = harness.create_file(b"reader-writer.bin");

    // Pre-write the prefix so the reader has something to observe
    {
        let a = adapter.lock().unwrap();
        let written = a
            .dispatch_write(&ctx, ino, fh, 0, &prefix, 0)
            .expect("write prefix");
        assert_eq!(written as usize, prefix.len());
    }

    let prefix_for_check = prefix.clone();
    let barrier = Arc::new(Barrier::new(2));
    let prefix_len = prefix.len();

    let adapter_w = Arc::clone(&adapter);
    let barrier_w = Arc::clone(&barrier);

    let adapter_r = Arc::clone(&adapter);
    let barrier_r = Arc::clone(&barrier);

    let writer = std::thread::spawn(move || {
        barrier_w.wait();
        let a = adapter_w.lock().unwrap();
        let written = a
            .dispatch_write(&request_ctx(), ino, fh, prefix_len as i64, suffix, 0)
            .expect("write suffix");
        assert_eq!(written as usize, suffix.len());
    });

    let reader = std::thread::spawn(move || {
        barrier_r.wait();
        let a = adapter_r.lock().unwrap();
        // Open a separate read handle to avoid cursor interference
        let open_dispatch = a
            .dispatch_open(&request_ctx(), ino, libc::O_RDONLY as u32)
            .expect("reader open");
        let read_fh = open_dispatch.file_handle();
        let buf = a
            .dispatch_read(&request_ctx(), ino, read_fh, 0, 8192, None)
            .expect("reader read");
        // Must see at least the prefix
        assert!(
            buf.len() >= prefix_len,
            "reader must see at least prefix, got {} bytes",
            buf.len()
        );
    });

    writer.join().expect("writer join");
    reader.join().expect("reader join");

    // After both complete, full content must be prefix + suffix
    let a = adapter.lock().unwrap();
    let full = a
        .dispatch_read(&ctx, ino, fh, 0, (prefix.len() + suffix.len()) as u32, None)
        .expect("final read");

    let expected: Vec<u8> = prefix_for_check
        .iter()
        .chain(suffix.iter())
        .copied()
        .collect();
    assert_eq!(full, expected, "full content must equal prefix + suffix");
}

// ===========================================================================
// Test 3: Concurrent create in same directory
// ===========================================================================

/// Two threads create distinct files in the same directory concurrently.
/// Both must succeed and readdir must return both entries.
#[test]
fn concurrent_create_in_same_directory() {
    let harness = AdapterHarness::new();
    let ctx = harness.ctx();
    let adapter = harness.shared_adapter();

    let dir_ino = harness.mkdir(b"concurrent-create-dir");
    let barrier = Arc::new(Barrier::new(2));

    let adapter_a = Arc::clone(&adapter);
    let barrier_a = Arc::clone(&barrier);

    let adapter_b = Arc::clone(&adapter);
    let barrier_b = Arc::clone(&barrier);

    let thread_a = std::thread::spawn(move || {
        barrier_a.wait();
        let a = adapter_a.lock().unwrap();
        let dispatch = a
            .dispatch_create(&request_ctx(), dir_ino, b"file-a.txt", 0o644, 0)
            .expect("thread A create");
        dispatch.inode()
    });

    let thread_b = std::thread::spawn(move || {
        barrier_b.wait();
        let a = adapter_b.lock().unwrap();
        let dispatch = a
            .dispatch_create(&request_ctx(), dir_ino, b"file-b.txt", 0o644, 0)
            .expect("thread B create");
        dispatch.inode()
    });

    let ino_a = thread_a.join().expect("thread A join");
    let ino_b = thread_b.join().expect("thread B join");

    assert!(ino_a > 0, "file-a.txt must have valid inode");
    assert!(ino_b > 0, "file-b.txt must have valid inode");

    // readdir must return both entries
    let mut a = adapter.lock().unwrap();
    let dh = a.dispatch_opendir(&ctx, dir_ino).expect("opendir");
    let (entries, _has_more) = a
        .dispatch_readdir(&ctx, dir_ino, dh.dh_id.0, 0)
        .expect("readdir");

    let names: Vec<&[u8]> = entries.iter().map(|e| e.name.as_slice()).collect();
    assert!(
        names.contains(&b"file-a.txt".as_slice()),
        "readdir missing file-a.txt"
    );
    assert!(
        names.contains(&b"file-b.txt".as_slice()),
        "readdir missing file-b.txt"
    );
}

// ===========================================================================
// Test 4: Concurrent unlink and readdir
// ===========================================================================

/// One thread unlinks a file while another iterates the directory.
/// The operation must not panic and must not leave dangling entries.
#[test]
fn concurrent_unlink_and_readdir() {
    let harness = AdapterHarness::new();
    let ctx = harness.ctx();
    let adapter = harness.shared_adapter();

    let dir_ino = harness.mkdir(b"unlink-readdir-dir");

    // Pre-populate directory with two files
    {
        let a = adapter.lock().unwrap();
        a.dispatch_create(&ctx, dir_ino, b"dir-to-unlink.bin", 0o644, 0)
            .expect("create dir-to-unlink.bin");
        a.dispatch_create(&ctx, dir_ino, b"dir-keep-me.bin", 0o644, 0)
            .expect("create dir-keep-me.bin");
    }

    // Pre-open the directory on the main thread; store dh_id for the
    // reader thread.  dispatch_opendir needs &mut self -- available
    // through the Mutex.
    let dh_id = {
        let mut a = adapter.lock().unwrap();
        let dh = a
            .dispatch_opendir(&ctx, dir_ino)
            .expect("opendir for concurrent test");
        dh.dh_id.0
    };

    let barrier = Arc::new(Barrier::new(2));

    let adapter_ul = Arc::clone(&adapter);
    let barrier_ul = Arc::clone(&barrier);

    let adapter_rd = Arc::clone(&adapter);
    let barrier_rd = Arc::clone(&barrier);

    let unlinker = std::thread::spawn(move || {
        barrier_ul.wait();
        let a = adapter_ul.lock().unwrap();
        a.dispatch_unlink(&request_ctx(), dir_ino, b"dir-to-unlink.bin")
            .expect("unlink dir-to-unlink.bin");
    });

    let reader = std::thread::spawn(move || {
        barrier_rd.wait();
        let a = adapter_rd.lock().unwrap();
        let (entries, _has_more) = a
            .dispatch_readdir(&request_ctx(), dir_ino, dh_id, 0)
            .expect("readdir");
        // Must not panic; must include the kept file.
        let names: Vec<&[u8]> = entries.iter().map(|e| e.name.as_slice()).collect();
        assert!(
            names.contains(&b"dir-keep-me.bin".as_slice()),
            "readdir must include the kept file"
        );
    });

    unlinker.join().expect("unlinker join");
    reader.join().expect("reader join");

    // After unlink completes, lookup must return ENOENT
    let a = adapter.lock().unwrap();
    let lookup_result = a.dispatch_lookup(&ctx, dir_ino, b"dir-to-unlink.bin");
    assert!(
        lookup_result.is_err(),
        "unlinked file must not be found by lookup"
    );
}

// ===========================================================================
// Test 5: Sequential write → read → overwrite → read data-integrity baseline
// ===========================================================================

/// Single-threaded sanity baseline: write patterned bytes, read back,
/// overwrite a middle range with different content, read back again,
/// and verify prefix/overwrite/suffix are all correct.
#[test]
fn sequential_write_read_overwrite_read_data_integrity() {
    let harness = AdapterHarness::new();
    let ctx = harness.ctx();
    let adapter = harness.shared_adapter();

    let original = patterned_bytes(12 * 1024);
    let replacement = b"OVERWRITE-MIDDLE-RANGE-OVERWRITE-OK"; // 35 bytes

    let (ino, fh) = harness.create_file(b"integrity-baseline.bin");

    let a = adapter.lock().unwrap();

    // Write original content
    let written = a
        .dispatch_write(&ctx, ino, fh, 0, &original, 0)
        .expect("write original");
    assert_eq!(written as usize, original.len());

    // Read back -- must be byte-identical
    let buf = a
        .dispatch_read(&ctx, ino, fh, 0, original.len() as u32, None)
        .expect("read original back");
    assert_eq!(buf, original, "initial readback mismatch");

    // Overwrite middle range
    let ow_offset: i64 = 5 * 1024;
    let written = a
        .dispatch_write(&ctx, ino, fh, ow_offset, replacement, 0)
        .expect("overwrite middle range");
    assert_eq!(written as usize, replacement.len());

    // Read back -- prefix intact, middle replaced, suffix intact
    let buf = a
        .dispatch_read(&ctx, ino, fh, 0, original.len() as u32, None)
        .expect("read after overwrite");

    assert_eq!(
        buf.len(),
        original.len(),
        "file size unchanged after overwrite"
    );

    // Prefix (0..5K)
    assert_eq!(&buf[..5 * 1024], &original[..5 * 1024], "prefix mismatch");

    // Overwritten range (5K..5K+35)
    let ow_end = 5 * 1024 + replacement.len();
    assert_eq!(
        &buf[5 * 1024..ow_end],
        replacement,
        "overwrite range mismatch"
    );

    // Suffix (after overwrite)
    assert_eq!(&buf[ow_end..], &original[ow_end..], "suffix mismatch");
}
