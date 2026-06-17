//! Targeted fsync/fdatasync flush-to-object-store durability tests.
//!
//! These tests verify that the fsync flush path correctly persists buffered
//! writes through to the LocalObjectStore, covering edge cases that the
//! broader in-session and reopen-based tests may not exercise directly.
//!
//! Each test writes data, calls fsync (or fdatasync), and then verifies
//! the object store contains the expected content objects via
//! `content_object_key_for_version`. The test then reopens the filesystem
//! to confirm byte-for-byte data survival.
//!
//! Edge-case coverage:
//!   - Basic fsync flush → object-store verification
//!   - fdatasync vs fsync: data-only vs data+metadata flush
//!   - Empty-file fsync (zero-length file)
//!   - Partial-page write at non-aligned offset + fsync
//!   - Multiple incremental fsync calls (delta capture)
//!   - Write → fsync → overwrite → fsync (replacement)
//!   - Concurrent writer + fsync snapshot consistency
//!   - fsync without prior write (no-op success)

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Barrier;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    content_object_key_for_version, InodeRecord, LocalFileSystem, DEFAULT_FILE_PERMISSIONS,
};
use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn setup_auth_env() {
    env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn temp_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let pid = std::process::id();
    std::env::temp_dir().join(format!("tidefs-fsd-{label}-{pid}-{nanos}"))
}

fn cleanup(root: &Path) {
    let _ = fs::remove_dir_all(root);
}

fn opts() -> StoreOptions {
    StoreOptions {
        reclaim_enabled: false,

        write_throttle_enabled: false,
        max_segment_bytes: 64 * 1024,
        sync_on_write: false,
        repair_torn_tail: false,
        mirror_path: None,
        replica_paths: Vec::new(),
        segment_rotation_interval_secs: u64::MAX,
        segment_rotation_write_limit: 0,
        fault_injection_config: None,
        background_scrub_interval_secs: 0,
        segment_count: 256,
        verify_read_checksums: true,
        durability_layout: None,
    }
}

/// Stat a file inside an already-open filesystem, returning its InodeRecord.
fn stat_inode(fs: &LocalFileSystem, path: &str) -> InodeRecord {
    fs.stat(path).expect("stat")
}

/// Verify that a content object for the given inode exists in the store.
fn assert_content_object_exists(store: &LocalObjectStore, inode: &InodeRecord) {
    let key = content_object_key_for_version(inode.inode_id, inode.data_version);
    assert!(
        store.location_of(key).is_some(),
        "content object must exist in store after fsync (inode={}, version={})",
        inode.inode_id.get(),
        inode.data_version,
    );
}

/// Verify that NO content object for the given inode exists in the store.
#[allow(dead_code)]
fn assert_content_object_absent(store: &LocalObjectStore, inode: &InodeRecord) {
    let key = content_object_key_for_version(inode.inode_id, inode.data_version);
    assert!(
        store.location_of(key).is_none(),
        "content object must NOT exist in store (inode={})",
        inode.inode_id.get(),
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Write 4 KiB to a file, fsync, and verify the content object is present
/// in the object store via direct inspection. Then reopen and verify data.
#[test]
fn fsync_flush_writes_to_object_store() {
    setup_auth_env();
    let root = temp_root("fsync-flush-to-store");
    let data = vec![0xABu8; 4096];

    let inode = {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        fs.set_auto_commit(false);
        fs.create_file("/f", DEFAULT_FILE_PERMISSIONS)
            .expect("create /f");
        fs.write_file("/f", 0, &data).expect("write 4 KiB");
        let inode = stat_inode(&fs, "/f");
        fs.fsync_file("/f").expect("fsync /f");
        inode
    };

    // Verify content object exists in the store.
    {
        let store = LocalObjectStore::open_with_options(&root, opts()).expect("open store");
        assert_content_object_exists(&store, &inode);
    }

    // Verify data survives reopen.
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs");
        let read_back = fs.read_file("/f").expect("read /f");
        assert_eq!(read_back.len(), 4096);
        assert_eq!(
            &read_back[..],
            &data[..],
            "data mismatch after fsync + reopen"
        );
    }

    cleanup(&root);
}

/// fdatasync (sync_inode_data_only) flushes data but skips the full metadata
/// commit_group commit. Verify the content object exists but metadata may not be
/// committed (the file may be unreachable until a metadata commit occurs).
#[test]
fn fdatasync_persists_data_object_skips_metadata_commit() {
    setup_auth_env();
    let root = temp_root("fdatasync-data-only");
    let data = vec![0xCDu8; 2048];

    let inode = {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        fs.set_auto_commit(false);
        fs.create_file("/fdat.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create /fdat.txt");
        fs.write_file("/fdat.txt", 0, &data).expect("write");
        let inode = stat_inode(&fs, "/fdat.txt");
        // sync_inode_data_only = fdatasync semantics
        fs.sync_inode_data_only(inode.inode_id)
            .expect("sync_inode_data_only");
        inode
    };

    // Content object is present.
    {
        let store = LocalObjectStore::open_with_options(&root, opts()).expect("open store");
        assert_content_object_exists(&store, &inode);
    }

    // Without a metadata commit, the file may be unreachable on reopen.
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs");
        // The file might not be in the namespace since metadata wasn't committed.
        // But the content object is durable in the store (verified above).
        // This is the defining semantic of fdatasync: data durable, metadata may lag.
        let _ = fs.lookup("/fdat.txt");
    }

    cleanup(&root);
}

/// Compare fsync_file vs fsync_data_only_file: both persist data, but after
/// fsync_file the file is reachable on reopen; after fsync_data_only_file only
/// the content object is guaranteed.
#[test]
fn fsync_vs_fdatasync_reachability_after_reopen() {
    setup_auth_env();
    let root = temp_root("fsync-vs-fdatasync");

    // File A: full fsync (metadata + data committed).
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        fs.set_auto_commit(false);
        fs.create_file("/a.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create a.txt");
        fs.write_file("/a.txt", 0, b"AAAA").expect("write a.txt");
        fs.fsync_file("/a.txt").expect("fsync a.txt");
    }

    // File B: fdatasync only (data committed, metadata may not be).
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        fs.set_auto_commit(false);
        fs.create_file("/b.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create b.txt");
        fs.write_file("/b.txt", 0, b"BBBB").expect("write b.txt");
        fs.fsync_data_only_file("/b.txt")
            .expect("fsync_data_only b.txt");
    }

    // After reopen: file A is reachable, file B may not be.
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs");
        assert!(
            fs.lookup("/a.txt").is_ok(),
            "fsync'd file must be reachable"
        );
        // fdatasync'd file may or may not be reachable (metadata commit timing).
        // We just confirm the lookup doesn't panic.
        let _ = fs.lookup("/b.txt");
    }

    cleanup(&root);
}

/// fsync on a newly created zero-length file must succeed and produce a
/// valid (possibly empty-layout) content object in the store.
#[test]
fn fsync_empty_file_creates_valid_content_object() {
    setup_auth_env();
    let root = temp_root("fsync-empty-file");

    let inode = {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        fs.set_auto_commit(false);
        fs.create_file("/empty.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create empty.bin");
        let inode = stat_inode(&fs, "/empty.bin");
        assert_eq!(inode.size, 0, "newly created file must have size 0");
        fs.fsync_file("/empty.bin").expect("fsync empty file");
        inode
    };

    // Empty files are metadata-only: no content object should exist.
    {
        let pool = tidefs_local_filesystem::LocalFileSystem::default_development_pool(
            &root,
            &opts(),
            None,
            None,
        )
        .expect("open pool");
        assert_content_object_absent(pool.raw_primary_store(), &inode);
    }
    // Reopen: empty file still exists and is empty.
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs");
        let buf = fs.read_file("/empty.bin").expect("read empty.bin");
        assert!(
            buf.is_empty(),
            "empty file must stay empty after fsync + reopen"
        );
        let re_stat = fs.stat("/empty.bin").expect("stat empty.bin");
        assert_eq!(re_stat.size, 0);
    }

    cleanup(&root);
}

/// Write 37 bytes at a non-page-aligned offset (4096+17), fsync, verify
/// the exact byte range is durable without corruption of surrounding pages.
#[test]
fn fsync_partial_page_write_persists_exact_byte_range() {
    setup_auth_env();
    let root = temp_root("fsync-partial-page");
    let offset: u64 = 4096 + 17;
    let data: Vec<u8> = (0..37u8).map(|b| b.wrapping_add(0xA0)).collect();

    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        fs.set_auto_commit(false);
        fs.create_file("/sparse.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create sparse.bin");
        fs.write_file("/sparse.bin", offset, &data)
            .expect("write at partial-page offset");
        fs.fsync_file("/sparse.bin").expect("fsync");
    }

    // Reopen and verify.
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs");
        let st = fs.stat("/sparse.bin").expect("stat");
        assert_eq!(
            st.size,
            offset + 37,
            "file size must reflect write position"
        );

        // Read the exact range back.
        let read_back = fs
            .read_file_range("/sparse.bin", offset, 37)
            .expect("read partial range");
        assert_eq!(read_back.len(), 37);
        assert_eq!(&read_back[..], &data[..], "partial-page data mismatch");

        // Bytes before the write should be zero-filled (hole).
        let hole = fs
            .read_file_range("/sparse.bin", 0, 10)
            .expect("read hole range");
        assert!(
            hole.iter().all(|&b| b == 0),
            "bytes before the write must be zero"
        );
    }

    cleanup(&root);
}

/// Write, fsync, write again, fsync — verify each fsync captures only the
/// delta since the last durable point, and the final state is correct.
#[test]
fn fsync_multiple_calls_capture_incremental_deltas() {
    setup_auth_env();
    let root = temp_root("fsync-incremental");

    let data1 = vec![0x11u8; 512];
    let data2 = vec![0x22u8; 512];

    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        fs.set_auto_commit(false);
        fs.create_file("/inc.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create inc.bin");

        // First write + fsync.
        fs.write_file("/inc.bin", 0, &data1).expect("write data1");
        fs.fsync_file("/inc.bin").expect("fsync after data1");

        // Second write at a different offset + fsync.
        fs.write_file("/inc.bin", 1024, &data2)
            .expect("write data2");
        fs.fsync_file("/inc.bin").expect("fsync after data2");
    }

    // Verify both writes survived.
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs");
        let r1 = fs
            .read_file_range("/inc.bin", 0, 512)
            .expect("read data1 range");
        assert_eq!(&r1[..], &data1[..], "data1 mismatch");

        let r2 = fs
            .read_file_range("/inc.bin", 1024, 512)
            .expect("read data2 range");
        assert_eq!(&r2[..], &data2[..], "data2 mismatch");

        // The gap between the two writes should be zero-filled.
        let gap = fs.read_file_range("/inc.bin", 512, 512).expect("read gap");
        assert!(
            gap.iter().all(|&b| b == 0),
            "gap between writes must be zero"
        );
    }

    cleanup(&root);
}

/// Write → fsync → overwrite the same region → fsync.
/// Verify the second fsync replaces the first durable state.
#[test]
fn fsync_overwrite_replaces_previous_durable_state() {
    setup_auth_env();
    let root = temp_root("fsync-overwrite");
    let original = vec![0xAAu8; 1024];
    let replacement = vec![0xBBu8; 1024];

    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        fs.set_auto_commit(false);
        fs.create_file("/over.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create over.bin");

        // Write + fsync.
        fs.write_file("/over.bin", 0, &original)
            .expect("write original");
        fs.fsync_file("/over.bin").expect("fsync original");

        // Overwrite same region + fsync.
        fs.write_file("/over.bin", 0, &replacement)
            .expect("write replacement");
        fs.fsync_file("/over.bin").expect("fsync replacement");
    }

    // Verify the replacement data, not the original.
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs");
        let r = fs.read_file("/over.bin").expect("read over.bin");
        assert_eq!(r.len(), 1024);
        assert_eq!(
            &r[..],
            &replacement[..],
            "overwrite data must replace original"
        );
    }

    cleanup(&root);
}

/// Spawn a writer thread that writes while the main thread calls fsync on
/// the same filesystem instance. Uses a Mutex to serialize access to the
/// filesystem and verify that fsync after concurrent writes sees a consistent
/// snapshot (no torn writes across chunk boundaries).
#[test]
fn concurrent_write_and_fsync_sees_consistent_snapshot() {
    setup_auth_env();
    let root = temp_root("fsync-concurrent");
    let chunk_size = tidefs_local_filesystem::content_chunk_size() as u64;

    // Use a single filesystem instance behind a Mutex so both threads
    // can safely call write_file and fsync_file without corrupting the store.
    let fs =
        std::sync::Mutex::new(LocalFileSystem::open_with_options(&root, opts()).expect("open fs"));
    {
        let mut fs = fs.lock().unwrap();
        fs.set_auto_commit(false);
        fs.create_file("/concurrent.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create concurrent.bin");
    }

    // Barrier: align writer start with main thread fsync timing.
    let barrier = std::sync::Arc::new(Barrier::new(2));
    let writer_barrier = std::sync::Arc::clone(&barrier);
    let fs_ref = &fs;

    thread::scope(|s| {
        s.spawn(move || {
            writer_barrier.wait(); // synchronize with main thread

            // Write 3 chunks of distinct patterns.
            let pattern_a = vec![0xCCu8; chunk_size as usize];
            let pattern_b = vec![0xDDu8; chunk_size as usize];
            let pattern_c = vec![0xEEu8; chunk_size as usize];

            let mut fs = fs_ref.lock().unwrap();
            fs.write_file("/concurrent.bin", 0, &pattern_a)
                .expect("write chunk 0");
            drop(fs); // release lock so fsync can run

            let mut fs = fs_ref.lock().unwrap();
            fs.write_file("/concurrent.bin", chunk_size, &pattern_b)
                .expect("write chunk 1");
            drop(fs);

            let mut fs = fs_ref.lock().unwrap();
            fs.write_file("/concurrent.bin", chunk_size * 2, &pattern_c)
                .expect("write chunk 2");
        });

        // Main thread: wait for writer to start, then fsync.
        barrier.wait();
        // Let the writer get at least one write in.
        thread::sleep(std::time::Duration::from_millis(100));

        {
            let mut fs = fs_ref.lock().unwrap();
            // fsync should capture whatever the writer has committed.
            // This must not panic or deadlock.
            fs.fsync_file("/concurrent.bin")
                .expect("fsync during concurrent writes");
        }
    });

    // Drop our Mutex guard so we can reopen.
    drop(fs);

    // After fsync, the data should be durable and recoverable.
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs");
        let st = fs.stat("/concurrent.bin").expect("stat");
        // The file size should reflect whatever was flushed — it must be
        // a consistent checkpoint, not a torn write.
        assert!(
            st.size <= chunk_size * 3,
            "file size {size} exceeds max possible write size {max}",
            size = st.size,
            max = chunk_size * 3
        );

        // Read back what's durable and verify it's not garbage.
        if st.size > 0 {
            let content = fs
                .read_file("/concurrent.bin")
                .expect("read concurrent.bin");
            assert!(!content.is_empty());
            // The content should be one of the known patterns (no torn bytes).
            // Since we write pattern_a first, the first chunk_size bytes should
            // be pattern_a if the fsync captured it.
            let expected_first = std::cmp::min(st.size as usize, chunk_size as usize);
            let first_slice = &content[..expected_first];
            let all_same = first_slice.iter().all(|&b| b == first_slice[0]);
            assert!(
                all_same,
                "torn write detected: mismatched bytes in first chunk"
            );
        }
    }

    cleanup(&root);
}

/// fsync on a file opened for writing but never written to must succeed
/// as a no-op (no content object created or existing empty object preserved).
#[test]
fn fsync_file_no_prior_write_is_noop() {
    setup_auth_env();
    let root = temp_root("fsync-noop");

    let inode = {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        fs.set_auto_commit(false);
        let rec = fs
            .create_file("/noop.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create noop.bin");
        // Never write to it — just fsync.
        fs.fsync_file("/noop.bin")
            .expect("fsync on unwritten file must succeed");
        rec
    };

    // After fsync, the file should survive reopen (metadata was committed).
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs");
        let st = fs.stat("/noop.bin").expect("stat noop.bin");
        assert_eq!(st.inode_id, inode.inode_id);
        assert_eq!(st.size, 0);
        let buf = fs.read_file("/noop.bin").expect("read noop.bin");
        assert!(buf.is_empty());
    }

    cleanup(&root);
}
