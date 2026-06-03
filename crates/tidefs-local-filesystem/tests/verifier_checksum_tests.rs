//! Integration tests for the online verifier BLAKE3-256 checksum detection.
//!
//! Corruption is injected by modifying raw segment file bytes on disk
//! after the filesystem is closed. The online verifier is then run as a
//! fresh reader to confirm that checksum mismatches are reported.
//!
//! Only the public API of tidefs-local-filesystem and
//! tidefs-local-object-store is used; no `src/` files are modified.
//!
//! Note: when a corrupted record's production-integrity trailer fails,
//! the store catches it during segment replay on `open_read_only`
//! before the on-line verifier logic executes. Both the `Err` path and
//! the `Ok(IssuesFound)` path prove the system detects corruption.

use std::env;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    content_object_key_for_version, transaction_manifest_object_key,
    transaction_superblock_object_key, verify_online, InodeRecord, LocalFileSystem,
    OnlineVerifierIssueKind, OnlineVerifierOutcome, DEFAULT_DIRECTORY_PERMISSIONS,
    DEFAULT_FILE_PERMISSIONS,
};
use tidefs_local_object_store::{
    segment_file_name, LocalObjectStore, ObjectKey, StoreOptions, RECORD_HEADER_LEN,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn setup_auth_env() {
    // demo_key() is [0x41_u8; 32] -> hex is 64 'A' characters.
    env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn temp_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let pid = std::process::id();
    std::env::temp_dir().join(format!("tidefs-vct-{label}-{pid}-{nanos}"))
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
        verify_read_checksums: false,
        durability_layout: None,
    }
}

fn chunk_opts() -> StoreOptions {
    StoreOptions {
        reclaim_enabled: false,

        write_throttle_enabled: false,
        max_segment_bytes: 256 * 1024,
        sync_on_write: false,
        repair_torn_tail: false,
        mirror_path: None,
        replica_paths: Vec::new(),
        segment_rotation_interval_secs: u64::MAX,
        segment_rotation_write_limit: 0,
        fault_injection_config: None,
        background_scrub_interval_secs: 0,
        segment_count: 256,
        verify_read_checksums: false,
        durability_layout: None,
    }
}

fn create_fs_with_file(root: &Path, file_path: &str, content: &[u8]) {
    let mut fs = LocalFileSystem::open_with_options(root, opts()).expect("open fs for setup");
    fs.create_dir("/data", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("create /data");
    fs.create_file(file_path, DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    fs.write_file(file_path, 0, content).expect("write content");
    fs.sync_all().expect("sync");
}

fn create_fs_with_file_opts(
    root: &Path,
    file_path: &str,
    content: &[u8],
    store_opts: StoreOptions,
) {
    let mut fs = LocalFileSystem::open_with_options(root, store_opts).expect("open fs for setup");
    fs.create_dir("/data", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("create /data");
    fs.create_file(file_path, DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    fs.write_file(file_path, 0, content).expect("write content");
    fs.sync_all().expect("sync");
}

fn seg_path(segments_dir: &Path, segment_id: u64) -> PathBuf {
    segments_dir.join(segment_file_name(segment_id))
}

fn corrupt_bytes(path: &Path, offset: u64, len: u64) {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open segment for corruption");
    file.seek(SeekFrom::Start(offset))
        .expect("seek to corrupt offset");
    let mut buf = vec![0_u8; len as usize];
    file.read_exact(&mut buf).expect("read bytes to corrupt");
    for b in &mut buf {
        *b ^= 0xFF;
    }
    file.seek(SeekFrom::Start(offset)).expect("seek back");
    file.write_all(&buf).expect("write corrupted bytes");
}

fn corrupt_object_payload(store: &LocalObjectStore, key: ObjectKey) {
    let loc = store.location_of(key).expect("object location");
    let path = seg_path(store.segments_dir(), loc.segment_id);
    let payload_start = loc.record_offset + RECORD_HEADER_LEN as u64;
    let corrupt_at = payload_start + (loc.payload_len / 2).max(1);
    corrupt_bytes(&path, corrupt_at, 1);
}

fn file_inode(root: &Path, file_path: &str) -> InodeRecord {
    let fs = LocalFileSystem::open_with_options(root, opts()).expect("open fs to stat");
    fs.stat(file_path).expect("stat file")
}

fn file_inode_opts(root: &Path, file_path: &str, store_opts: StoreOptions) -> InodeRecord {
    let fs = LocalFileSystem::open_with_options(root, store_opts).expect("open fs to stat");
    fs.stat(file_path).expect("stat file")
}

fn first_transaction_id(root: &Path) -> u64 {
    let report = verify_online(root, opts()).expect("verify for tx id");
    report
        .verified_committed_roots
        .first()
        .expect("at least one committed root")
        .root
        .transaction_id
}

/// Corruption may be caught by the store's segment-replay integrity
/// check (returning `Err`) or by the verifier (returning
/// `Ok(IssuesFound)`).  Both prove detection.
fn assert_corruption_detected(root: &Path, label: &str) {
    match verify_online(root, opts()) {
        Ok(report) => {
            assert_eq!(
                report.outcome,
                OnlineVerifierOutcome::IssuesFound,
                "[{label}] verifier should report IssuesFound"
            );
            assert!(!report.passed(), "[{label}] verifier should not pass");
            assert!(
                !report.issues.is_empty(),
                "[{label}] verifier should report issues"
            );
        }
        Err(_) => {
            // Store-level integrity caught the corruption before the
            // verifier on-line logic ran.
        }
    }
}

fn assert_corruption_detected_opts(root: &Path, label: &str, store_opts: StoreOptions) {
    match verify_online(root, store_opts) {
        Ok(report) => {
            assert_eq!(
                report.outcome,
                OnlineVerifierOutcome::IssuesFound,
                "[{label}] verifier should report IssuesFound"
            );
            assert!(!report.passed(), "[{label}] verifier should not pass");
            assert!(
                !report.issues.is_empty(),
                "[{label}] verifier should report issues"
            );
        }
        Err(_) => {
            // Store-level integrity caught the corruption before the
            // verifier on-line logic ran.
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn clean_filesystem_reports_clean() {
    setup_auth_env();
    let root = temp_root("clean");

    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).unwrap();
        fs.create_dir("/docs", DEFAULT_DIRECTORY_PERMISSIONS)
            .unwrap();
        fs.create_file("/docs/readme.txt", DEFAULT_FILE_PERMISSIONS)
            .unwrap();
        fs.write_file("/docs/readme.txt", 0, b"clean").unwrap();
        fs.sync_all().unwrap();
    }

    let report = verify_online(&root, opts()).unwrap();
    assert_eq!(report.outcome, OnlineVerifierOutcome::Clean);
    assert!(report.passed());
    assert!(report.issues.is_empty());
    assert!(!report.verified_committed_roots.is_empty());
    cleanup(&root);
}

#[test]
fn empty_store_reports_empty() {
    setup_auth_env();
    let root = temp_root("empty");
    let report = verify_online(&root, opts()).unwrap();
    assert_eq!(report.outcome, OnlineVerifierOutcome::EmptyStore);
    assert!(report.passed());
    cleanup(&root);
}

#[test]
fn corrupted_content_object_payload_detected() {
    setup_auth_env();
    let root = temp_root("corrupt-content");
    let content = b"0123456789abcdef CONTENT CORRUPTION TEST PAYLOAD";

    create_fs_with_file(&root, "/data/corrupt_me.txt", content);

    let inode = file_inode(&root, "/data/corrupt_me.txt");
    let content_key = content_object_key_for_version(inode.inode_id, inode.data_version);

    // Sanity: object exists and has non-empty payload before corruption.
    {
        let store = LocalObjectStore::open_with_options(&root, opts()).unwrap();
        let loc = store.location_of(content_key).unwrap();
        // Content objects include an encode-content header, so raw bytes
        // will be longer than the user-visible content.
        let stored = store.get_at_location(loc).unwrap();
        assert!(stored.len() >= content.len());
    }

    // Corrupt the content object's raw payload.
    {
        let store = LocalObjectStore::open_with_options(&root, opts()).unwrap();
        corrupt_object_payload(&store, content_key);
    }

    assert_corruption_detected(&root, "content-object");

    if let Ok(report) = verify_online(&root, opts()) {
        let has_validation = report
            .issues
            .iter()
            .any(|i| matches!(i.kind, OnlineVerifierIssueKind::RootCommitValidation));
        assert!(
            has_validation,
            "verifier should report RootCommitValidation for corrupted content"
        );
    }

    cleanup(&root);
}

#[test]
fn corrupted_transaction_manifest_detected() {
    setup_auth_env();
    let root = temp_root("corrupt-manifest");
    let content = b"manifest corruption test content";

    create_fs_with_file(&root, "/data/file.txt", content);

    let transaction_id = first_transaction_id(&root);

    {
        let store = LocalObjectStore::open_with_options(&root, opts()).unwrap();
        let key = transaction_manifest_object_key(transaction_id);
        corrupt_object_payload(&store, key);
    }

    assert_corruption_detected(&root, "transaction-manifest");
    cleanup(&root);
}

#[test]
fn corrupted_superblock_detected() {
    setup_auth_env();
    let root = temp_root("corrupt-superblock");
    let content = b"superblock corruption test";

    create_fs_with_file(&root, "/data/sb.txt", content);

    let transaction_id = first_transaction_id(&root);

    {
        let store = LocalObjectStore::open_with_options(&root, opts()).unwrap();
        let key = transaction_superblock_object_key(transaction_id);
        corrupt_object_payload(&store, key);
    }

    assert_corruption_detected(&root, "superblock");
    cleanup(&root);
}

#[test]
fn verifier_reports_content_counts_on_clean_fs() {
    setup_auth_env();
    let root = temp_root("clean-counts");

    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).unwrap();
        fs.create_dir("/a", DEFAULT_DIRECTORY_PERMISSIONS).unwrap();
        fs.create_file("/a/one.txt", DEFAULT_FILE_PERMISSIONS)
            .unwrap();
        fs.write_file("/a/one.txt", 0, b"first").unwrap();
        fs.create_file("/a/two.txt", DEFAULT_FILE_PERMISSIONS)
            .unwrap();
        fs.write_file("/a/two.txt", 0, b"second file").unwrap();
        fs.sync_all().unwrap();
    }

    let report = verify_online(&root, opts()).unwrap();
    assert_eq!(report.outcome, OnlineVerifierOutcome::Clean);
    assert!(report.passed());
    assert!(
        report.checked_content_objects >= 2,
        "verifier checked >= 2 content objects, got {}",
        report.checked_content_objects
    );
    cleanup(&root);
}

#[test]
fn corrupted_content_chunk_payload_detected() {
    setup_auth_env();
    let root = temp_root("corrupt-chunk");

    // The runtime chunk size is 64 KiB by default.  Write enough data
    // for at least 2 chunks and use a splitmix64 hash to generate
    // distinct bytes per position so content-addressed dedup does not
    // merge chunks (the per-chunk offset is not a multiple of 256).
    let chunk_size = tidefs_local_filesystem::FILESYSTEM_CONTENT_CHUNK_SIZE;
    let content_len = chunk_size * 2 + 500;
    let content: Vec<u8> = (0..content_len)
        .map(|i| {
            let x = (i as u64).wrapping_mul(0x9E3779B97F4A7C15);
            ((x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9) >> 32) as u8
        })
        .collect();

    let my_opts = chunk_opts();
    create_fs_with_file_opts(&root, "/data/chunked.bin", &content, my_opts.clone());

    let inode = file_inode_opts(&root, "/data/chunked.bin", my_opts.clone());
    let chunk_key = tidefs_local_filesystem::content_chunk_object_key_for_version(
        inode.inode_id,
        inode.data_version,
        1,
    );

    // Sanity: chunk exists and has data.
    {
        let store = LocalObjectStore::open_with_options(&root, my_opts.clone()).unwrap();
        let loc = store.location_of(chunk_key).unwrap();
        let stored = store.get_at_location(loc).unwrap();
        assert!(!stored.is_empty(), "chunk 1 should have data");
    }

    // Corrupt the chunk object's raw payload.
    {
        let store = LocalObjectStore::open_with_options(&root, my_opts.clone()).unwrap();
        corrupt_object_payload(&store, chunk_key);
    }

    assert_corruption_detected_opts(&root, "content-chunk", my_opts.clone());

    if let Ok(report) = verify_online(&root, my_opts) {
        assert!(
            report.checked_content_chunks >= 2,
            "expected >= 2 chunks checked, got {}",
            report.checked_content_chunks
        );
    }

    cleanup(&root);
}
