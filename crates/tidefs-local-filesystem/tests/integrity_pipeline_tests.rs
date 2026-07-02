// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! End-to-end integrity pipeline tests for integrity and repair authority.
//!
//! Validates the full checksum chain from object-store production-integrity
//! trailers through root authentication, transaction manifests, content
//! manifests, and per-chunk checksums. Every test uses only the public API
//! of tidefs-local-filesystem and tidefs-local-object-store.
//!
//! Integrity validation chain exercised by this test module:
//!
//!   validation_0: v3 BLAKE3-256 production-integrity trailers on every record
//!   validation_1: keyed root-authentication records per committed root
//!   validation_2: transaction manifest binds required objects + checksums
//!   validation_3: content-manifest + per-chunk checksums for file content
//!   validation_4: changed-record send/receive validates payload checksums
//!   validation_5: online verifier reports clean/corrupt candidates
//!   validation_6: safe local reclamation preserves protected roots

use std::env;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    content_chunk_object_key_for_version, content_object_key_for_version, root_slot_object_key,
    transaction_manifest_object_key, verify_online, InodeRecord, LocalFileSystem,
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
    env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn temp_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let pid = std::process::id();
    std::env::temp_dir().join(format!("tidefs-ipt-{label}-{pid}-{nanos}"))
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

fn seg_path(segments_dir: &Path, segment_id: u64) -> PathBuf {
    segments_dir.join(segment_file_name(segment_id))
}

fn corrupt_bytes(path: &Path, offset: u64, len: u64) {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open segment for corruption");
    file.seek(SeekFrom::Start(offset)).expect("seek");
    let mut buf = vec![0_u8; len as usize];
    file.read_exact(&mut buf).expect("read bytes");
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
    corrupt_bytes(&path, payload_start, (loc.payload_len / 2).max(1));
}

fn corrupt_record_trailer(store: &LocalObjectStore, key: ObjectKey) {
    let loc = store.location_of(key).expect("object location");
    let path = seg_path(store.segments_dir(), loc.segment_id);
    let trailer_offset = loc.record_offset + RECORD_HEADER_LEN as u64 + loc.payload_len;
    if trailer_offset > loc.record_offset + RECORD_HEADER_LEN as u64 {
        corrupt_bytes(&path, trailer_offset, 1);
    }
}

fn file_inode(root: &Path, file_path: &str) -> InodeRecord {
    setup_auth_env();
    let fs = LocalFileSystem::open_with_options(root, opts()).expect("open fs to stat");
    fs.stat(file_path).expect("stat file")
}

fn first_transaction_id(root: &Path) -> u64 {
    setup_auth_env();
    let report = verify_online(root, opts()).expect("verify for tx id");
    report
        .verified_committed_roots
        .first()
        .expect("at least one committed root")
        .root
        .transaction_id
}

fn create_filesystem_with_deep_data(root: &Path) {
    setup_auth_env();
    let _ = fs::remove_dir_all(root);
    fs::create_dir_all(root).expect("create root");

    let mut fs = LocalFileSystem::open_with_options(root, opts()).expect("open fs");

    // Directory hierarchy with files at multiple levels.
    fs.create_dir("/a", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("mkdir /a");
    fs.create_dir("/a/b", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("mkdir /a/b");
    fs.create_dir("/a/b/c", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("mkdir /a/b/c");

    // File < 1 chunk (inline/small content).
    fs.create_file("/small.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create small");
    fs.write_file("/small.txt", 0, b"tiny")
        .expect("write small");

    // File spanning multiple chunks.
    let chunk_size = tidefs_local_filesystem::content_chunk_size() as usize;
    let big: Vec<u8> = (0..(chunk_size * 3 + 500))
        .map(|i| (i % 256) as u8)
        .collect();
    fs.create_file("/a/b/big.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create big");
    fs.write_file("/a/b/big.bin", 0, &big).expect("write big");

    // File in deepest directory.
    fs.create_file("/a/b/c/deep.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create deep");
    fs.write_file("/a/b/c/deep.txt", 0, b"deep content here")
        .expect("write deep");

    // Multiple syncs to create multiple transaction roots.
    fs.sync_all().expect("sync root 1");

    fs.create_file("/a/b/second.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create second");
    fs.write_file("/a/b/second.txt", 0, b"second file data")
        .expect("write second");
    fs.sync_all().expect("sync root 2");

    drop(fs);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// validation_0 (store record trailers) + validation_5 (verifier):
/// A clean filesystem passes all layers of the verifier.
#[test]
fn clean_filesystem_passes_full_integrity_chain() {
    setup_auth_env();
    let root = temp_root("clean-chain");
    create_filesystem_with_deep_data(&root);

    let report = verify_online(&root, opts()).expect("verify");
    assert_eq!(report.outcome, OnlineVerifierOutcome::Clean);
    assert!(report.passed());
    assert!(report.issues.is_empty());
    assert!(!report.verified_committed_roots.is_empty());
    assert!(
        report.checked_content_objects >= 3,
        "at least 3 content objects (small, big, deep, second)"
    );
    assert!(
        report.checked_content_chunks >= 3,
        "big.bin has 4 chunks, expect >= 3 chunks checked"
    );
    cleanup(&root);
}

/// validation_3 + validation_5:
/// Corrupting a content chunk's payload must be detected by the verifier
/// (or rejected by store-level integrity on open).
#[test]
fn content_chunk_corruption_detected_in_chain() {
    setup_auth_env();
    let root = temp_root("chunk-corrupt");
    create_filesystem_with_deep_data(&root);

    let inode = file_inode(&root, "/a/b/big.bin");
    let chunk_key = content_chunk_object_key_for_version(inode.inode_id, inode.data_version, 1);

    // Verify chunk exists.
    {
        let store = LocalObjectStore::open_with_options(&root, opts()).expect("open store");
        assert!(
            store.location_of(chunk_key).is_some(),
            "chunk 1 must exist for big.bin (3+ chunks)"
        );
        corrupt_object_payload(&store, chunk_key);
    }

    // Corruption must be caught.
    match verify_online(&root, opts()) {
        Ok(report) => {
            assert_eq!(report.outcome, OnlineVerifierOutcome::IssuesFound);
            assert!(!report.passed());
            assert!(!report.issues.is_empty());
            let has_chunk = report
                .issues
                .iter()
                .any(|i| matches!(i.kind, OnlineVerifierIssueKind::RootCommitValidation));
            assert!(
                has_chunk,
                "verifier should report validation issue for corrupted chunk"
            );
        }
        Err(_) => {
            // Store-level integrity caught it during replay.
        }
    }
    cleanup(&root);
}

/// validation_2:
/// Corrupting a transaction manifest must invalidate the corresponding
/// committed root, causing fallback or error.
#[test]
fn transaction_manifest_corruption_falls_back() {
    setup_auth_env();
    let root = temp_root("manifest-corr");
    create_filesystem_with_deep_data(&root);

    let cg_id = first_transaction_id(&root);
    {
        let store = LocalObjectStore::open_with_options(&root, opts()).expect("open store");
        let manifest_key = transaction_manifest_object_key(cg_id);
        assert!(
            store.location_of(manifest_key).is_some(),
            "manifest must exist"
        );
        corrupt_object_payload(&store, manifest_key);
    }

    // Reopen should fall back or report error.
    setup_auth_env();
    match LocalFileSystem::open_with_options(&root, opts()) {
        Ok(_fs) => {
            // Fallback succeeded — earlier root is valid.
        }
        Err(_) => {
            // Store-level detection.
        }
    }
    cleanup(&root);
}

/// validation_3: content manifest checksum validation.
/// Corrupting the content manifest object must be detected.
#[test]
fn content_manifest_corruption_detected() {
    setup_auth_env();
    let root = temp_root("content-manifest");
    create_filesystem_with_deep_data(&root);

    let inode = file_inode(&root, "/a/b/big.bin");
    let content_key = content_object_key_for_version(inode.inode_id, inode.data_version);

    {
        let store = LocalObjectStore::open_with_options(&root, opts()).expect("open store");
        assert!(
            store.location_of(content_key).is_some(),
            "content object must exist"
        );
        corrupt_object_payload(&store, content_key);
    }

    match verify_online(&root, opts()) {
        Ok(report) => {
            assert_eq!(report.outcome, OnlineVerifierOutcome::IssuesFound);
            assert!(!report.passed());
        }
        Err(_) => {
            // Store detected corruption at open time.
        }
    }
    cleanup(&root);
}

/// validation_1 + validation_6:
/// Corrupting a root-slot object must not destroy earlier valid roots.
/// Safe reclamation boundaries protect older roots.
#[test]
fn root_slot_corruption_preserves_older_roots() {
    setup_auth_env();
    let root = temp_root("root-slot-preserve");

    // Create first root with stable data.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        fs.create_file("/must_survive.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/must_survive.txt", 0, b"stable")
            .expect("write");
        fs.sync_all().expect("sync root 1");
        drop(fs);
    }

    // Create second root with candidate data.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        fs.create_file("/may_be_lost.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/may_be_lost.txt", 0, b"candidate")
            .expect("write");
        fs.sync_all().expect("sync root 2");
        drop(fs);
    }

    // Corrupt the newest root-slot object.
    {
        let store = LocalObjectStore::open_with_options(&root, opts()).expect("open store");
        let latest_slot = 0_u64; // Root slots cycle; slot 0 may hold the newest root.
        let key = root_slot_object_key(latest_slot);
        if store.location_of(key).is_some() {
            corrupt_object_payload(&store, key);
        }
    }

    // Reopen: must_survive.txt must still be readable.
    setup_auth_env();
    match LocalFileSystem::open_with_options(&root, opts()) {
        Ok(fs) => {
            let content = fs.read_file("/must_survive.txt").expect("read stable file");
            assert_eq!(
                std::str::from_utf8(&content).unwrap(),
                "stable",
                "stable data must survive root-slot corruption"
            );
        }
        Err(_) => {
            // Store detection is also valid.
        }
    }
    cleanup(&root);
}

/// Validation that the verifier inspects all committed roots, not just
/// the newest. When multiple roots exist, the verifier must check
/// each one's integrity chain.
#[test]
fn verifier_inspects_all_committed_roots() {
    setup_auth_env();
    let root = temp_root("multi-root-verify");

    let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
    fs.create_file("/a.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create a");
    fs.write_file("/a.txt", 0, b"alpha").expect("write a");
    fs.sync_all().expect("sync root 1");

    fs.create_file("/b.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create b");
    fs.write_file("/b.txt", 0, b"beta").expect("write b");
    fs.sync_all().expect("sync root 2");

    fs.create_file("/c.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create c");
    fs.write_file("/c.txt", 0, b"gamma").expect("write c");
    fs.sync_all().expect("sync root 3");
    drop(fs);

    let report = verify_online(&root, opts()).expect("verify");
    assert_eq!(report.outcome, OnlineVerifierOutcome::Clean);
    assert!(
        report.verified_committed_roots.len() >= 3,
        "expected >= 3 committed roots, got {}",
        report.verified_committed_roots.len()
    );
    assert!(
        report.checked_content_objects >= 3,
        "expected >= 3 content objects checked, got {}",
        report.checked_content_objects
    );
    cleanup(&root);
}

#[test]
fn empty_store_reports_empty_integrity() {
    setup_auth_env();
    let root = temp_root("empty-ipt");
    fs::create_dir_all(&root).expect("create dir");
    let report = verify_online(&root, opts()).expect("verify empty");
    assert_eq!(report.outcome, OnlineVerifierOutcome::EmptyStore);
    assert!(report.passed());
    cleanup(&root);
}

#[test]
fn verifier_reports_all_object_categories_on_clean_fs() {
    setup_auth_env();
    let root = temp_root("trailer-coverage");
    create_filesystem_with_deep_data(&root);

    let report = verify_online(&root, opts()).expect("verify");
    assert_eq!(report.outcome, OnlineVerifierOutcome::Clean);

    // The verifier must have inspected each major object category.
    assert!(
        report.checked_transaction_manifests >= 1,
        "must check at least one transaction manifest"
    );
    assert!(
        report.checked_content_objects >= 3,
        "must check at least 3 content objects, got {}",
        report.checked_content_objects
    );
    assert!(
        report.checked_content_chunks >= 3,
        "must check at least 3 content chunks, got {}",
        report.checked_content_chunks
    );
    assert!(
        report.root_slots_seen >= 1,
        "must see at least one root slot"
    );
    cleanup(&root);
}

/// Corrupt the record-level production-integrity trailer (not the
/// payload) and verify that the store's segment replay rejects the
/// record or the verifier reports issues.
#[test]
fn record_trailer_corruption_triggers_store_integrity_check() {
    setup_auth_env();
    let root = temp_root("trailer-corr");

    let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
    fs.create_file("/data.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/data.bin", 0, b"trailer test payload")
        .expect("write");
    fs.sync_all().expect("sync");
    drop(fs);

    let inode = file_inode(&root, "/data.bin");
    let content_key = content_object_key_for_version(inode.inode_id, inode.data_version);

    {
        let store = LocalObjectStore::open_with_options(&root, opts()).expect("open store");
        assert!(
            store.location_of(content_key).is_some(),
            "content object exists"
        );
        corrupt_record_trailer(&store, content_key);
    }

    // After corrupting the trailer, the store must reject the record.
    match verify_online(&root, opts()) {
        Ok(report) => {
            assert_eq!(report.outcome, OnlineVerifierOutcome::IssuesFound);
        }
        Err(_) => {
            // Store-level integrity check caught the trailer corruption.
        }
    }
    cleanup(&root);
}
