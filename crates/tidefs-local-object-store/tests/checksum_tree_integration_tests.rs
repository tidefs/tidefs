//! Integration tests for LocalObjectStore get_checksum_tree /
//! verify_checksum_tree round-trip and tamper detection.
//!
//! Tests cover single-block, multi-block, tamper detection (overwrite),
//! empty object, block-alignment boundary, and tree determinism.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tidefs_local_object_store::{LeafScrubResult, LocalObjectStore, ObjectKey, StoreOptions};

// ── Fixture helpers ────────────────────────────────────────────────────────

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-checksum-tree-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn cleanup(root: &PathBuf) {
    let _ = fs::remove_dir_all(root);
}

const BLOCK_SIZE: usize = 1024; // BLAKE3 native block size

// ── 1. Single-block round-trip ────────────────────────────────────────────

/// Write data ≤ BLAKE3 block size, build a checksum tree, and verify
/// it against the stored data. Verification must pass.
#[test]
fn single_block_round_trip() {
    let root = temp_root("single-block-rt");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let payload = b"hello world, this is a single-block payload";
    let key = ObjectKey::from_name(b"single-block");
    store.put(key, payload).expect("put single-block");
    store.sync_all().expect("sync store");

    let tree = store
        .get_checksum_tree(key, BLOCK_SIZE)
        .expect("get_checksum_tree")
        .expect("tree should exist for stored key");
    assert!(
        !tree.is_empty(),
        "tree should not be empty for non-empty data"
    );
    assert_eq!(tree.block_count, 1, "single block of {BLOCK_SIZE} bytes");

    let verified = store
        .verify_checksum_tree(key, &tree)
        .expect("verify_checksum_tree");
    assert!(verified, "verification must pass for round-trip data");

    cleanup(&root);
}

// ── 2. Multi-block round-trip ─────────────────────────────────────────────

/// Write data spanning 2+ BLAKE3 leaf blocks, build tree, verify passes.
#[test]
fn multi_block_round_trip() {
    let root = temp_root("multi-block-rt");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    // ~2.5 blocks worth of data
    let payload = vec![0xAB_u8; 2500];
    let expected_blocks = 3_u64; // ceil(2500 / 1024) = 3

    let key = ObjectKey::from_name(b"multi-block");
    store.put(key, &payload).expect("put multi-block");
    store.sync_all().expect("sync store");

    let tree = store
        .get_checksum_tree(key, BLOCK_SIZE)
        .expect("get_checksum_tree")
        .expect("tree should exist");
    assert!(!tree.is_empty());
    assert_eq!(
        tree.block_count, expected_blocks,
        "multi-block payload should produce {expected_blocks} blocks"
    );

    let verified = store
        .verify_checksum_tree(key, &tree)
        .expect("verify_checksum_tree");
    assert!(
        verified,
        "verification must pass for multi-block round-trip"
    );

    cleanup(&root);
}

// ── 2b. Storage-backed checksum-tree scrub ────────────────────────────────

/// Scrub a stored object against its captured checksum tree and verify the
/// report is clean for the current payload.
#[test]
fn scrub_checksum_tree_round_trip_uses_store_payload() {
    let root = temp_root("scrub-round-trip");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let payload = vec![0x51_u8; 2500];
    let key = ObjectKey::from_name(b"scrub-round-trip");
    store.put(key, &payload).expect("put payload");
    store.sync_all().expect("sync store");

    let tree = store
        .get_checksum_tree(key, BLOCK_SIZE)
        .expect("get_checksum_tree")
        .expect("tree should exist");
    let report = store
        .scrub_checksum_tree(key, &tree)
        .expect("scrub_checksum_tree")
        .expect("object should exist");

    assert!(report.is_clean(), "stored payload should scrub clean");
    assert_eq!(report.leaves_examined, 3);
    assert_eq!(report.leaves_clean, 3);
    assert_eq!(report.missing_data_blocks, 0);
    assert_eq!(report.extra_data_bytes, 0);

    cleanup(&root);
}

/// Scrub must report the exact changed block when the stored object is
/// overwritten after a checksum tree was captured.
#[test]
fn scrub_checksum_tree_reports_overwrite_mismatch() {
    let root = temp_root("scrub-overwrite");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let original = vec![0xA5_u8; 3000];
    let key = ObjectKey::from_name(b"scrub-overwrite");
    store.put(key, &original).expect("put original");
    store.sync_all().expect("sync original");

    let original_tree = store
        .get_checksum_tree(key, BLOCK_SIZE)
        .expect("get_checksum_tree")
        .expect("tree should exist");

    let mut overwritten = original.clone();
    overwritten[0] ^= 0xFF;
    store.put(key, &overwritten).expect("overwrite payload");
    store.sync_all().expect("sync overwrite");

    let report = store
        .scrub_checksum_tree(key, &original_tree)
        .expect("scrub_checksum_tree")
        .expect("object should exist");

    assert!(
        !report.is_clean(),
        "overwritten payload must not scrub clean"
    );
    assert_eq!(report.leaves_examined, 3);
    assert_eq!(report.leaves_clean, 2);
    assert!(matches!(
        report.leaf_results.first(),
        Some(LeafScrubResult::Mismatch { leaf_index: 0, .. })
    ));

    cleanup(&root);
}

/// Missing keys produce no scrub report rather than a false clean result.
#[test]
fn scrub_checksum_tree_missing_key_returns_none() {
    let root = temp_root("scrub-missing-key");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let present = ObjectKey::from_name(b"present");
    store.put(present, b"present payload").expect("put present");
    store.sync_all().expect("sync store");
    let tree = store
        .get_checksum_tree(present, BLOCK_SIZE)
        .expect("get_checksum_tree")
        .expect("tree should exist");

    let missing = ObjectKey::from_name(b"missing");
    assert!(
        store
            .scrub_checksum_tree(missing, &tree)
            .expect("scrub missing")
            .is_none(),
        "missing object should not return a scrub report"
    );

    cleanup(&root);
}

// ── 3. Single-block tamper detection ──────────────────────────────────────

/// Write data, build tree, overwrite with different data, verify fails.
#[test]
fn single_block_tamper_detection() {
    let root = temp_root("tamper-single");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let original = b"original single-block data for tamper test";
    let key = ObjectKey::from_name(b"tamper-target");

    store.put(key, original).expect("put original");
    store.sync_all().expect("sync store");

    let original_tree = store
        .get_checksum_tree(key, BLOCK_SIZE)
        .expect("get_checksum_tree")
        .expect("tree should exist");

    // Overwrite with different data — this simulates tampering where an
    // attacker replaced the object with different valid content.
    let tampered = b"tampered data that differs from original!!!!";
    store.put(key, tampered).expect("put tampered");
    store.sync_all().expect("sync store");

    let verified = store
        .verify_checksum_tree(key, &original_tree)
        .expect("verify_checksum_tree");
    assert!(
        !verified,
        "verification must fail when stored data differs from original tree"
    );

    // Sanity check: a fresh tree built from the tampered data should verify.
    let tampered_tree = store
        .get_checksum_tree(key, BLOCK_SIZE)
        .expect("get_checksum_tree")
        .expect("tree should exist for tampered data");
    let tampered_verified = store
        .verify_checksum_tree(key, &tampered_tree)
        .expect("verify_checksum_tree");
    assert!(
        tampered_verified,
        "fresh tree must verify against current data"
    );

    cleanup(&root);
}

// ── 4. Multi-block tamper — first block ───────────────────────────────────

/// Write multi-block data, build tree, overwrite with data differing only
/// in the first block, and verify that detection catches it.
#[test]
fn multi_block_tamper_first_block() {
    let root = temp_root("tamper-first");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    // 3 blocks of 0xAA
    let original = vec![0xAA_u8; 3000];
    let key = ObjectKey::from_name(b"tamper-first");
    store.put(key, &original).expect("put original");
    store.sync_all().expect("sync store");

    let original_tree = store
        .get_checksum_tree(key, BLOCK_SIZE)
        .expect("get_checksum_tree")
        .expect("tree should exist");

    // Overwrite with data that differs in the first byte only
    let mut tampered = original.clone();
    tampered[0] ^= 0xFF;
    store.put(key, &tampered).expect("put tampered");
    store.sync_all().expect("sync store");

    let verified = store
        .verify_checksum_tree(key, &original_tree)
        .expect("verify_checksum_tree");
    assert!(
        !verified,
        "verification must detect tampering in the first block"
    );

    cleanup(&root);
}

// ── 5. Multi-block tamper — last block ────────────────────────────────────

/// Write multi-block data, build tree, overwrite with data differing only
/// in the last block, and verify that detection catches it.
#[test]
fn multi_block_tamper_last_block() {
    let root = temp_root("tamper-last");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    // 3 blocks of 0xAA
    let original = vec![0xAA_u8; 3000];
    let key = ObjectKey::from_name(b"tamper-last");
    store.put(key, &original).expect("put original");
    store.sync_all().expect("sync store");

    let original_tree = store
        .get_checksum_tree(key, BLOCK_SIZE)
        .expect("get_checksum_tree")
        .expect("tree should exist");

    // Overwrite with data that differs in the last byte only
    let mut tampered = original.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;
    store.put(key, &tampered).expect("put tampered");
    store.sync_all().expect("sync store");

    let verified = store
        .verify_checksum_tree(key, &original_tree)
        .expect("verify_checksum_tree");
    assert!(
        !verified,
        "verification must detect tampering in the last block"
    );

    cleanup(&root);
}

// ── 6. Empty object ───────────────────────────────────────────────────────

/// Write a zero-length object, build tree, verify — tree should represent
/// empty data correctly and verification should pass.
#[test]
fn empty_object_round_trip() {
    let root = temp_root("empty-object");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let key = ObjectKey::from_name(b"empty");
    store.put(key, &[]).expect("put empty");
    store.sync_all().expect("sync store");

    let tree = store
        .get_checksum_tree(key, BLOCK_SIZE)
        .expect("get_checksum_tree")
        .expect("tree should exist for empty object");
    assert!(tree.is_empty(), "tree should be empty for zero-length data");
    assert_eq!(tree.block_count, 0, "empty data has zero blocks");
    assert_eq!(tree.node_count(), 0, "empty tree has zero nodes");

    let verified = store
        .verify_checksum_tree(key, &tree)
        .expect("verify_checksum_tree");
    assert!(verified, "verification must pass for empty object");

    cleanup(&root);
}

// ── 7. Block-alignment boundary ───────────────────────────────────────────

/// Write data at exactly N × block_size to catch off-by-one errors in
/// block iteration (ceil division for block count).
#[test]
fn block_alignment_boundary() {
    let root = temp_root("align-boundary");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    // Exactly 2 blocks
    let payload = vec![0xCC_u8; BLOCK_SIZE * 2];
    let key = ObjectKey::from_name(b"aligned");
    store.put(key, &payload).expect("put aligned");
    store.sync_all().expect("sync store");

    let tree = store
        .get_checksum_tree(key, BLOCK_SIZE)
        .expect("get_checksum_tree")
        .expect("tree should exist");
    assert_eq!(
        tree.block_count, 2,
        "exactly 2-block data should produce 2-block tree"
    );

    let verified = store
        .verify_checksum_tree(key, &tree)
        .expect("verify_checksum_tree");
    assert!(verified, "verification must pass for block-aligned data");

    // Also test exactly 1 block
    let payload_1 = vec![0xDD_u8; BLOCK_SIZE];
    let key_1 = ObjectKey::from_name(b"aligned-1");
    store.put(key_1, &payload_1).expect("put 1-block aligned");
    store.sync_all().expect("sync store");

    let tree_1 = store
        .get_checksum_tree(key_1, BLOCK_SIZE)
        .expect("get_checksum_tree")
        .expect("tree should exist");
    assert_eq!(tree_1.block_count, 1, "exactly 1 block");

    let verified_1 = store
        .verify_checksum_tree(key_1, &tree_1)
        .expect("verify_checksum_tree");
    assert!(
        verified_1,
        "verification must pass for single-block aligned data"
    );

    cleanup(&root);
}

// ── 8. Tree determinism ───────────────────────────────────────────────────

/// Call get_checksum_tree twice on the same unchanged object; the two
/// trees must be bit-identical.
#[test]
fn tree_determinism() {
    let root = temp_root("determinism");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let payload = b"deterministic checksum tree construction test payload";
    let key = ObjectKey::from_name(b"determinism");
    store.put(key, payload).expect("put payload");
    store.sync_all().expect("sync store");

    let tree_a = store
        .get_checksum_tree(key, BLOCK_SIZE)
        .expect("get_checksum_tree")
        .expect("first tree should exist");

    let tree_b = store
        .get_checksum_tree(key, BLOCK_SIZE)
        .expect("get_checksum_tree")
        .expect("second tree should exist");

    assert_eq!(
        tree_a, tree_b,
        "two trees built from the same unchanged object must be identical"
    );
    assert_eq!(tree_a.root_hash, tree_b.root_hash, "root hashes must match");
    assert_eq!(
        tree_a.block_count, tree_b.block_count,
        "block counts must match"
    );

    // Both trees should verify against the stored data
    assert!(
        store
            .verify_checksum_tree(key, &tree_a)
            .expect("verify tree_a"),
        "tree_a must verify"
    );
    assert!(
        store
            .verify_checksum_tree(key, &tree_b)
            .expect("verify tree_b"),
        "tree_b must verify"
    );

    cleanup(&root);
}
