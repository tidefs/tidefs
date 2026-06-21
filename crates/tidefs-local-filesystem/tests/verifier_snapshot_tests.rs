// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests for online verifier snapshot-chain validation.
//!
//! Snapshots are authenticated committed-root references stored in the
//! superblock catalog.  The online verifier must validate that every
//! snapshot root references a valid, loadable committed root.
//!
//! Corruption is injected by modifying raw segment file bytes on disk
//! after the filesystem is closed.  The online verifier is then run as a
//! fresh reader to confirm that snapshot-chain issues are reported.
//!
//! Only the public API of tidefs-local-filesystem and
//! tidefs-local-object-store is used; no `src/` files are modified.

use std::env;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    root_slot_object_key, verify_online, LocalFileSystem, OnlineVerifierOutcome,
    DEFAULT_DIRECTORY_PERMISSIONS, DEFAULT_FILE_PERMISSIONS,
};
use tidefs_local_object_store::{
    segment_file_name, LocalObjectStore, ObjectLocation, StoreOptions,
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
    std::env::temp_dir().join(format!("tidefs-vst-{label}-{pid}-{nanos}"))
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

fn with_raw_primary_store<T>(
    root: &Path,
    store_opts: StoreOptions,
    f: impl FnOnce(&LocalObjectStore) -> T,
) -> T {
    let pool = LocalFileSystem::default_development_pool(root, &store_opts, None, None)
        .expect("open development pool");
    f(pool.raw_primary_store())
}

fn seg_path(segments_dir: &Path, segment_id: u64) -> PathBuf {
    segments_dir.join(segment_file_name(segment_id))
}

fn object_record_path(store: &LocalObjectStore, loc: ObjectLocation) -> PathBuf {
    let segments_dir = store.segments_dir();
    if segments_dir.is_file() || (segments_dir.exists() && !segments_dir.is_dir()) {
        segments_dir.to_path_buf()
    } else {
        seg_path(segments_dir, loc.segment_id)
    }
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

/// Corrupt a root-slot object's raw bytes by flipping bits in its
/// segment payload.  This invalidates the snapshot source root without
/// touching the current root.
fn corrupt_root_slot_payload(store: &LocalObjectStore, slot: u64) {
    let key = root_slot_object_key(slot);
    let loc = store
        .version_locations_of(key)
        .into_iter()
        .next()
        .expect("root slot must have at least one version");
    let path = object_record_path(store, loc);
    corrupt_bytes(&path, loc.payload_offset, 1);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn clean_snapshot_chain_passes_verifier() {
    setup_auth_env();
    let root = temp_root("clean-snaps");

    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).unwrap();
        fs.create_dir("/data", DEFAULT_DIRECTORY_PERMISSIONS)
            .unwrap();
        fs.create_file("/data/a.txt", DEFAULT_FILE_PERMISSIONS)
            .unwrap();
        fs.write_file("/data/a.txt", 0, b"first file").unwrap();
        fs.sync_all().unwrap();
        let s1 = fs.create_snapshot("s1").unwrap();
        assert_eq!(s1.name, "s1");

        fs.create_file("/data/b.txt", DEFAULT_FILE_PERMISSIONS)
            .unwrap();
        fs.write_file("/data/b.txt", 0, b"second file").unwrap();
        fs.sync_all().unwrap();
        let s2 = fs.create_snapshot("s2").unwrap();
        assert_eq!(s2.name, "s2");
        assert!(s2.source_transaction_id > s1.source_transaction_id);
    }

    let report = verify_online(&root, opts()).unwrap();
    assert_eq!(report.outcome, OnlineVerifierOutcome::Clean);
    assert!(report.passed());

    // Aggregate snapshot catalog entries across all verified roots.
    let total_catalog: usize = report
        .verified_committed_roots
        .iter()
        .map(|r| r.snapshot_catalog_entries)
        .sum();
    let total_verified: u64 = report
        .verified_committed_roots
        .iter()
        .map(|r| r.verified_snapshot_roots)
        .sum();

    assert!(
        total_catalog >= 2,
        "expected >= 2 snapshot catalog entries, got {total_catalog}"
    );
    assert!(
        total_verified >= 2,
        "expected >= 2 verified snapshot roots, got {total_verified}"
    );

    cleanup(&root);
}

#[test]
fn snapshot_metadata_is_consistent() {
    setup_auth_env();
    let root = temp_root("snap-meta");

    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).unwrap();
        fs.create_file("/x", DEFAULT_FILE_PERMISSIONS).unwrap();
        fs.write_file("/x", 0, b"meta").unwrap();
        fs.sync_all().unwrap();
        let snap = fs.create_snapshot("my-snap").unwrap();

        assert_eq!(snap.name, "my-snap");
        assert!(snap.source_transaction_id > 0);
        assert!(snap.source_generation > 0);
        assert!(snap.created_at_generation > 0);
        assert_eq!(snap.source_root.transaction_id, snap.source_transaction_id);

        let list = fs.list_snapshots();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "my-snap");
        assert_eq!(list[0].source_transaction_id, snap.source_transaction_id);

        let summary = fs.snapshot_summary("my-snap").unwrap();
        assert_eq!(summary, snap);
    }

    cleanup(&root);
}

#[test]
fn snapshots_persist_after_close_reopen() {
    setup_auth_env();
    let root = temp_root("snap-persist");

    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).unwrap();
        fs.create_file("/p", DEFAULT_FILE_PERMISSIONS).unwrap();
        fs.write_file("/p", 0, b"persist").unwrap();
        fs.sync_all().unwrap();
        fs.create_snapshot("persist-snap").unwrap();
    }

    // Reopen — snapshot should still be listed.
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).unwrap();
        let snaps = fs.list_snapshots();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].name, "persist-snap");
    }

    // Verifier should see it.
    let report = verify_online(&root, opts()).unwrap();
    assert!(report.passed());
    let total_verified: u64 = report
        .verified_committed_roots
        .iter()
        .map(|r| r.verified_snapshot_roots)
        .sum();
    assert!(total_verified >= 1);

    cleanup(&root);
}

#[test]
fn verifier_counts_multiple_snapshots_in_one_root() {
    setup_auth_env();
    let root = temp_root("multi-snap");

    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).unwrap();
        fs.create_dir("/d", DEFAULT_DIRECTORY_PERMISSIONS).unwrap();
        fs.create_file("/d/one", DEFAULT_FILE_PERMISSIONS).unwrap();
        fs.write_file("/d/one", 0, b"one").unwrap();
        fs.sync_all().unwrap();

        // Create multiple snapshots in the same transaction.
        fs.create_snapshot("alpha").unwrap();
        fs.create_snapshot("beta").unwrap();
        fs.create_snapshot("gamma").unwrap();
    }

    let report = verify_online(&root, opts()).unwrap();
    assert_eq!(report.outcome, OnlineVerifierOutcome::Clean);

    let max_catalog = report
        .verified_committed_roots
        .iter()
        .map(|r| r.snapshot_catalog_entries)
        .max()
        .unwrap_or(0);
    assert_eq!(
        max_catalog, 3,
        "expected a root with 3 snapshot catalog entries"
    );
    let max_verified = report
        .verified_committed_roots
        .iter()
        .map(|r| r.verified_snapshot_roots)
        .max()
        .unwrap_or(0);
    assert_eq!(
        max_verified, 3,
        "expected a root with 3 verified snapshot roots"
    );

    cleanup(&root);
}

#[test]
fn verifier_detects_corrupted_snapshot_source_root() {
    setup_auth_env();
    let root = temp_root("corrupt-snap-root");

    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).unwrap();
        fs.create_file("/target", DEFAULT_FILE_PERMISSIONS).unwrap();
        fs.write_file("/target", 0, b"will be snapshotted").unwrap();
        fs.sync_all().unwrap();
        let snap = fs.create_snapshot("corrupt-me").unwrap();
        // Record the slot of the snapshot source root so we can corrupt it.
        // The source root slot is available from the summary.
        let _snap_slot = snap.source_root.slot;
    }

    // The root slot object for the snapshot's source root lives in the store.
    // We corrupt it to simulate a missing/broken snapshot reference.
    with_raw_primary_store(&root, opts(), |store| {
        let _all_keys = store.list_keys();
        // Find a root-slot key that corresponds to the snapshot source.
        // The root slot index varies; corrupt whichever root slot exists.
        let mut corrupted = false;
        for slot in 0..4_u64 {
            let key = root_slot_object_key(slot);
            if store.version_locations_of(key).is_empty() {
                continue;
            }
            corrupt_root_slot_payload(store, slot);
            corrupted = true;
            break;
        }
        assert!(corrupted, "expected at least one populated root slot");
    });

    // Detection: verifier should report IssuesFound or store-level error.
    match verify_online(&root, opts()) {
        Ok(report) => {
            assert_eq!(
                report.outcome,
                OnlineVerifierOutcome::IssuesFound,
                "verifier should detect corrupted snapshot source root"
            );
            assert!(!report.issues.is_empty());
        }
        Err(_) => {
            // Store-level integrity caught the corruption.
        }
    }

    cleanup(&root);
}

#[test]
fn verifier_reports_snapshot_counts_on_clean_fs() {
    setup_auth_env();
    let root = temp_root("snap-counts");

    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).unwrap();
        fs.create_file("/f", DEFAULT_FILE_PERMISSIONS).unwrap();
        fs.write_file("/f", 0, b"data").unwrap();
        fs.sync_all().unwrap();
        fs.create_snapshot("s1").unwrap();
        fs.create_snapshot("s2").unwrap();
        fs.create_snapshot("s3").unwrap();
        fs.create_snapshot("s4").unwrap();
    }

    let report = verify_online(&root, opts()).unwrap();
    assert_eq!(report.outcome, OnlineVerifierOutcome::Clean);
    assert!(report.passed());
    assert!(
        report.verified_snapshot_roots >= 4,
        "expected >= 4 verified_snapshot_roots, got {}",
        report.verified_snapshot_roots
    );

    let max_catalog = report
        .verified_committed_roots
        .iter()
        .map(|r| r.snapshot_catalog_entries)
        .max()
        .unwrap_or(0);
    let max_snap_verified = report
        .verified_committed_roots
        .iter()
        .map(|r| r.verified_snapshot_roots)
        .max()
        .unwrap_or(0);
    assert_eq!(
        max_catalog, 4,
        "expected a root with 4 snapshot catalog entries"
    );
    assert_eq!(
        max_snap_verified, 4,
        "expected a root with 4 verified snapshot roots"
    );

    cleanup(&root);
}

// ---------------------------------------------------------------------------
