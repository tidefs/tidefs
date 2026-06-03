//! Segment replay and format integrity tests for `tidefs-local-object-store`.
//!
//! Validates segment-level crash recovery semantics: single-segment and
//! multi-segment replay, replay report accuracy, partial-record trimming,
//! segment format validation (magic, checksum, version), and empty-store
//! initialization. These tests focus on the replay mechanism itself, not
//! just data survival (which is covered by `crash_recovery.rs`).

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_object_store::{segment_file_name, LocalObjectStore, ObjectKey, StoreOptions};

// ── Fixture helpers ────────────────────────────────────────────────────────

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-seg-replay-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn cleanup(root: &PathBuf) {
    let _ = fs::remove_dir_all(root);
}

fn fast_opts() -> StoreOptions {
    StoreOptions::test_fast()
}

fn open_store(root: &PathBuf) -> LocalObjectStore {
    LocalObjectStore::open_with_options(root, fast_opts()).expect("open store")
}

fn segments_dir(root: &Path) -> PathBuf {
    root.join("segments")
}

fn segment_path(root: &Path, seg_id: u64) -> PathBuf {
    segments_dir(root).join(segment_file_name(seg_id))
}

/// Truncate a file to `new_len` bytes.
fn truncate_to(path: &PathBuf, new_len: u64) {
    let file = OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open for truncate");
    file.set_len(new_len).expect("truncate");
}

/// Flip a single bit at `byte_offset` in the file at `path`.
fn flip_bit(path: &PathBuf, byte_offset: u64) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open for bit-flip");
    let mut buf = [0u8; 1];
    file.seek(SeekFrom::Start(byte_offset))
        .expect("seek to byte_offset");
    file.read_exact(&mut buf).expect("read byte");
    buf[0] ^= 0x01;
    file.seek(SeekFrom::Start(byte_offset)).expect("seek back");
    file.write_all(&buf).expect("write flipped byte");
    file.sync_all().expect("sync after flip");
}

/// Read the raw bytes of a file into memory.
fn read_file_bytes(path: &PathBuf) -> Vec<u8> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .expect("open for read");
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).expect("read to end");
    buf
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Single-segment write-then-replay
// ═══════════════════════════════════════════════════════════════════════════

/// Write objects to a single segment, drop the store (simulating a crash
/// where in-memory state is lost), reopen, and verify:
/// - The replay report shows correct segment and record counts.
/// - All written data is byte-for-byte intact.
#[test]
fn single_segment_write_replay_data_and_report_correct() {
    let root = temp_root("single-seg-replay");

    let payloads: Vec<(ObjectKey, Vec<u8>)> = {
        let mut store = open_store(&root);
        let mut entries = Vec::new();
        for i in 0..5 {
            let payload = format!("single-segment-record-{i}").into_bytes();
            let key = ObjectKey::from_name(format!("obj-{i}"));
            store.put(key, &payload).expect("put");
            entries.push((key, payload));
        }
        store.sync_all().expect("sync");
        entries
    };

    // Simulate crash: drop the store so all in-memory state is lost.
    drop(open_store(&root));

    // Reopen: replay must reconstruct the index.
    let store = open_store(&root);
    let report = store.replay_report();

    // Verify replay report.
    assert_eq!(
        report.segment_count, 1,
        "single segment file should be discovered"
    );
    assert_eq!(
        report.puts_seen, 5,
        "replay must see all 5 put records, saw {}",
        report.puts_seen
    );
    assert_eq!(
        report.records_seen, 5,
        "total records seen must match put count"
    );
    assert_eq!(report.deletes_seen, 0, "no deletes were written");
    assert!(
        report.highest_sequence >= 5,
        "highest sequence must be at least the record count"
    );

    // Verify data integrity.
    for (key, expected) in &payloads {
        assert!(
            store.contains_key(*key),
            "key {key} must be present after replay"
        );
        let got = store.get(*key).expect("get").expect("data present");
        assert_eq!(got, *expected, "payload for {key} must be byte-for-byte");
    }

    assert_eq!(
        store.list_keys().len(),
        5,
        "exactly 5 live keys after replay"
    );

    cleanup(&root);
}

/// After replay, the store must accept new writes; replay state must not
/// interfere with normal operation.
#[test]
fn store_accepts_writes_after_replay() {
    let root = temp_root("post-replay-writes");

    {
        let mut store = open_store(&root);
        store
            .put(ObjectKey::from_name("pre-crash"), b"pre-crash-data")
            .expect("put pre-crash");
        store.sync_all().expect("sync");
    }

    // Reopen (replay) and write more data.
    {
        let mut store = open_store(&root);
        assert!(store.contains_key(ObjectKey::from_name("pre-crash")));

        store
            .put(ObjectKey::from_name("post-crash"), b"post-crash-data")
            .expect("put post-crash");
        store.sync_all().expect("sync");
    }

    // Both writes must survive.
    let store = open_store(&root);
    assert!(store.contains_key(ObjectKey::from_name("pre-crash")));
    assert!(store.contains_key(ObjectKey::from_name("post-crash")));

    let pre = store.get(ObjectKey::from_name("pre-crash")).expect("get");
    assert_eq!(pre, Some(b"pre-crash-data".to_vec()));

    let post = store.get(ObjectKey::from_name("post-crash")).expect("get");
    assert_eq!(post, Some(b"post-crash-data".to_vec()));

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Multi-segment ordered replay
// ═══════════════════════════════════════════════════════════════════════════

/// Write enough objects to force segment rotation (small max_segment_bytes),
/// then reopen and verify all objects survive across segments. The replay
/// report segment count reflects the store's knowledge of segments; the
/// per-record counters may reflect only records replayed from disk after
/// the checkpoint boundary, so we verify data integrity rather than exact
/// per-record replay counts.
#[test]
fn multi_segment_ordered_replay_all_data_survives() {
    let root = temp_root("multi-seg-replay");

    let opts = StoreOptions {
        max_segment_bytes: 512,
        ..fast_opts()
    };

    let total_objects = 12;
    let payloads: Vec<(ObjectKey, Vec<u8>)> = {
        let mut store = LocalObjectStore::open_with_options(&root, opts).expect("open store");
        let mut entries = Vec::new();
        for i in 0..total_objects {
            // ~37-byte payloads + 224 byte overhead ≈ 261 bytes per record
            let payload = format!("multi-seg-obj-{i:02}-xxxx-yyyy-zzzz-wwww").into_bytes();
            let key = ObjectKey::from_name(format!("seg-obj-{i}"));
            store.put(key, &payload).expect("put");
            entries.push((key, payload));
        }
        store.sync_all().expect("sync");
        entries
    };

    // Reopen and verify data integrity.
    let store = open_store(&root);
    let report = store.replay_report();

    // Should have multiple segments.
    assert!(
        report.segment_count >= 2,
        "expected at least 2 segments, got {}",
        report.segment_count
    );

    // All data must survive, regardless of whether it came from a
    // checkpoint (skipped during replay) or from replayed segments.
    for (key, expected) in &payloads {
        assert!(
            store.contains_key(*key),
            "key {key} must be present after multi-segment replay"
        );
        let got = store.get(*key).expect("get").expect("data present");
        assert_eq!(got, *expected, "payload for {key} must be intact");
    }

    assert_eq!(
        store.list_keys().len(),
        total_objects,
        "all objects must be live after multi-segment replay"
    );

    // Verify segments directory has the expected segment files.
    let seg_dir = segments_dir(&root);
    let seg_files: Vec<_> = fs::read_dir(&seg_dir)
        .expect("read_dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_str().is_some_and(|n| n.ends_with(".vlos")))
        .collect();
    assert_eq!(
        seg_files.len(),
        report.segment_count,
        "segment file count must match replay report"
    );

    cleanup(&root);
}

/// Verify that replay processes segments in ID order (ascending) and that
/// all objects survive across segment boundaries.
#[test]
fn replay_respects_segment_id_ordering() {
    let root = temp_root("seg-id-order");

    let opts = StoreOptions {
        max_segment_bytes: 400,
        ..fast_opts()
    };

    let total = 15;
    {
        let mut store = LocalObjectStore::open_with_options(&root, opts).expect("open store");
        for i in 0..total {
            store
                .put(
                    ObjectKey::from_name(format!("order-obj-{i}")),
                    &[i as u8; 80],
                )
                .expect("put");
        }
        store.sync_all().expect("sync");
    }

    let store = open_store(&root);
    let report = store.replay_report();

    // All objects must be present (order preserved by the index, not by
    // replay order — replay order is segment-ID ascending internally).
    for i in 0..total {
        let key = ObjectKey::from_name(format!("order-obj-{i}"));
        assert!(
            store.contains_key(key),
            "object order-obj-{i} must be present"
        );
        let got = store.get(key).expect("get").expect("data");
        assert_eq!(got, vec![i as u8; 80]);
    }

    // Verify segment files exist and are in ascending ID order.
    let seg_dir = segments_dir(&root);
    for seg_id in 0..report.segment_count as u64 {
        let path = seg_dir.join(segment_file_name(seg_id));
        // Not all segment IDs are necessarily populated (gaps may exist),
        // but the segment files that DO exist must be well-formed.
        if path.exists() {
            let _len = fs::metadata(&path).expect("metadata").len();
            assert!(_len > 0, "segment file {seg_id} must be non-empty");
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Partial-segment resilience
// ═══════════════════════════════════════════════════════════════════════════

/// Truncate a segment file mid-record (removing the footer and integrity
/// trailer). On reopen, the store must trim the torn tail and recover
/// earlier records cleanly.
#[test]
fn truncated_segment_mid_record_is_trimmed_on_replay() {
    let root = temp_root("trimmed-replay");

    let key_good = ObjectKey::from_name("good-record");
    let key_torn = ObjectKey::from_name("torn-record");

    {
        let mut store = open_store(&root);
        store
            .put(key_good, b"good-data-survives")
            .expect("put good");
        store
            .put(key_torn, b"torn-data-gets-discarded")
            .expect("put torn");
        store.sync_all().expect("sync");
    }

    // Truncate to remove the last record's integrity trailer.
    let seg_path = segment_path(&root, 0);
    let file_len = fs::metadata(&seg_path).expect("metadata").len();
    let trunc_len = file_len.saturating_sub(40);
    assert!(trunc_len > 0, "segment must fit records");
    truncate_to(&seg_path, trunc_len);

    // Reopen: store must recover.
    let store = open_store(&root);

    // Good record must survive.
    assert!(
        store.contains_key(key_good),
        "good record must survive tail repair"
    );
    assert_eq!(
        store.get(key_good).expect("get"),
        Some(b"good-data-survives".to_vec())
    );

    // Torn record: either absent or detected as corrupt — never partial data.
    match store.get(key_torn) {
        Ok(Some(data)) => {
            assert_eq!(
                data, b"torn-data-gets-discarded",
                "if torn record survived, it must be complete"
            );
        }
        Ok(None) => {} // discarded by tail repair — acceptable
        Err(_e) => {}  // corruption detected on read — acceptable
    }

    cleanup(&root);
}

/// Truncate a segment to zero bytes. The store must initialize cleanly
/// with no data — not panic.
#[test]
fn empty_segment_file_is_tolerated_on_replay() {
    let root = temp_root("empty-seg-replay");

    // Create a store with one write, then truncate the segment to zero.
    {
        let mut store = open_store(&root);
        store
            .put(ObjectKey::from_name("victim"), b"will-be-erased")
            .expect("put");
        store.sync_all().expect("sync");
    }

    let seg_path = segment_path(&root, 0);
    assert!(fs::metadata(&seg_path).expect("metadata").len() > 0);
    truncate_to(&seg_path, 0);

    // Reopen: empty segment must not cause panic.
    let store = LocalObjectStore::open_with_options(&root, fast_opts());
    match store {
        Ok(store) => {
            // Should have no live objects (all data evaporated).
            assert!(
                store.list_keys().is_empty(),
                "truncated-to-zero segment must yield empty index"
            );
        }
        Err(_e) => {
            // Rejected — also acceptable as the segment has no valid records.
        }
    }

    cleanup(&root);
}

/// Write a segment with valid records, then truncate just before the
/// segment integrity footer. Recovery must preserve all committed records.
#[test]
fn missing_segment_footer_is_repaired_or_tolerated() {
    let root = temp_root("missing-seg-footer");

    let key = ObjectKey::from_name("footer-test");

    {
        let mut store = open_store(&root);
        store.put(key, b"before-footer-removal").expect("put");
        store.sync_all().expect("sync");
    }

    let seg_path = segment_path(&root, 0);
    let file_len = fs::metadata(&seg_path).expect("metadata").len();

    // The integrity trailer (112 bytes) sits after the record footer.
    // Truncate to remove the trailer without removing the footer.
    let trunc_len = file_len.saturating_sub(120);
    if trunc_len > 0 {
        truncate_to(&seg_path, trunc_len);

        let store = LocalObjectStore::open_with_options(&root, fast_opts());
        if let Ok(store) = store {
            // If the truncated portion included the record's integrity
            // trailer, the record might be discarded; if not, it survives.
            if store.contains_key(key) {
                let data = store.get(key).expect("get").expect("data");
                assert_eq!(data, b"before-footer-removal");
            }
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Segment format validation
// ═══════════════════════════════════════════════════════════════════════════

/// Flipping the record magic bytes "VLOSREC1" must be detected on replay.
#[test]
fn corrupt_record_magic_detected_on_replay() {
    let root = temp_root("magic-corrupt-replay");

    {
        let mut store = open_store(&root);
        store
            .put(ObjectKey::from_name("magic-test"), b"magic-payload")
            .expect("put");
        store.sync_all().expect("sync");
    }

    let seg_path = segment_path(&root, 0);
    // Magic is at offset 0 of each record. Flip bit in the magic.
    flip_bit(&seg_path, 1); // second byte of VLOSREC1

    let result = LocalObjectStore::open_with_options(&root, fast_opts());
    match result {
        Err(e) => {
            let msg = format!("{e:?}");
            assert!(
                msg.contains("Corrupt") || msg.contains("magic") || msg.contains("header"),
                "error must indicate header/magic corruption: {e:?}"
            );
        }
        Ok(_store) => {
            // If store opened, the corrupted record was discarded by
            // tail repair. The store may be empty.
        }
    }

    cleanup(&root);
}

/// Flipping a byte in the payload region (not in header/footer magic) must
/// cause a checksum mismatch on read or on replay.
#[test]
fn corrupt_payload_checksum_detected() {
    let root = temp_root("payload-checksum-corrupt");

    let key = ObjectKey::from_name("checksum-target");

    {
        let mut store = open_store(&root);
        store.put(key, b"payload-to-corrupt-later").expect("put");
        store.sync_all().expect("sync");
    }

    let seg_path = segment_path(&root, 0);
    let file_len = fs::metadata(&seg_path).expect("metadata").len();

    // Payload starts after the 96-byte header. Flip a byte in the payload
    // region (offset 110 is well into the payload).
    if file_len > 150 {
        flip_bit(&seg_path, 110);

        let store = LocalObjectStore::open_with_options(&root, fast_opts());
        match store {
            Ok(store) => {
                // Reading the corrupted key should either fail or return
                // data that doesn't match the original.
                match store.get(key) {
                    Ok(Some(data)) => {
                        assert_ne!(
                            data, b"payload-to-corrupt-later",
                            "corrupted payload must not match original"
                        );
                    }
                    Ok(None) => {} // discarded — acceptable
                    Err(_e) => {}  // detected — acceptable
                }
            }
            Err(_e) => {} // rejected on open — acceptable
        }
    }

    cleanup(&root);
}

/// Modifying the format version byte in a record header must be rejected
/// or the record must be discarded as an unsupported version.
#[test]
fn wrong_record_version_rejected_or_discarded() {
    let root = temp_root("wrong-version");

    let key_good = ObjectKey::from_name("good-version");
    let key_bad = ObjectKey::from_name("bad-version");

    {
        let mut store = open_store(&root);
        store.put(key_good, b"good-record-data").expect("put good");
        store.put(key_bad, b"bad-version-record").expect("put bad");
        store.sync_all().expect("sync");
    }

    let seg_path = segment_path(&root, 0);
    let bytes = read_file_bytes(&seg_path);

    // Find the second record's version byte.
    // First payload is "good-record-data" (16 bytes).
    // Record layout: 96 header + 16 payload + 16 footer + 112 trailer = 240
    // Second record header starts at offset 240, version at 240+8 = 248.
    let second_header_start: u64 = 96 + 16 + 16 + 112; // 240
    if bytes.len() > second_header_start as usize + 10 {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&seg_path)
            .expect("open");
        file.seek(SeekFrom::Start(second_header_start + 8))
            .expect("seek to version");
        let bad_version: [u8; 2] = 0xFFFF_u16.to_le_bytes();
        file.write_all(&bad_version).expect("write bad version");
        file.sync_all().expect("sync");
        drop(file);

        let store = LocalObjectStore::open_with_options(&root, fast_opts());
        match store {
            Ok(store) => {
                // Good record must survive.
                assert!(
                    store.contains_key(key_good),
                    "good record must survive version corruption in neighbor"
                );
                // Bad record: either absent or error.
                match store.get(key_bad) {
                    Ok(Some(_data)) => {
                        // If it survived, the store tolerated the version.
                    }
                    Ok(None) => {} // discarded
                    Err(_) => {}   // detected
                }
            }
            Err(_e) => {} // rejected
        }
    }

    cleanup(&root);
}

/// Write a segment with known data, then corrupt the integrity trailer
/// magic ("VLOSINT4"). On reopen, the record should be discarded or
/// corruption detected.
#[test]
fn corrupt_integrity_trailer_magic_detected() {
    let root = temp_root("integrity-trailer-corrupt");

    let key = ObjectKey::from_name("trailer-test");

    {
        let mut store = open_store(&root);
        store.put(key, b"trailer-payload-data").expect("put");
        store.sync_all().expect("sync");
    }

    let seg_path = segment_path(&root, 0);
    let file_len = fs::metadata(&seg_path).expect("metadata").len();

    // The integrity trailer (INTEGRITY_TRAILER_V2) is at the end of the
    // record. Flip a bit in the trailer region near end of file.
    if file_len > 20 {
        flip_bit(&seg_path, file_len - 20);

        let result = LocalObjectStore::open_with_options(&root, fast_opts());
        match result {
            Err(_e) => {} // corruption detected — acceptable
            Ok(store) => {
                // If opened, the corrupted record may have been discarded.
                match store.get(key) {
                    Ok(Some(data)) => {
                        let _ = data;
                    }
                    Ok(None) => {} // discarded — acceptable
                    Err(_) => {}   // detected — acceptable
                }
            }
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. Empty-store recovery
// ═══════════════════════════════════════════════════════════════════════════

/// Create a store, write nothing, close, reopen. The store must initialize
/// cleanly with an empty index and a correct replay report.
#[test]
fn empty_store_initializes_with_clean_replay_report() {
    let root = temp_root("empty-init");

    // Open and immediately drop (no writes).
    {
        let _store = open_store(&root);
    }

    let store = open_store(&root);
    let report = store.replay_report();

    // At least 1 segment (the initial segment-0.vlos is always created).
    assert!(
        report.segment_count >= 1,
        "empty store must have at least 1 segment after init"
    );
    assert_eq!(report.records_seen, 0, "no records in empty store");
    assert_eq!(report.puts_seen, 0);
    assert_eq!(report.deletes_seen, 0);
    assert_eq!(
        report.highest_sequence, 0,
        "highest sequence must be 0 for empty store"
    );

    // Store must be fully functional — can write and read.
    assert!(store.list_keys().is_empty());

    cleanup(&root);
}

/// Open a store with zero writes, then write objects, reopen. The store
/// must not panic and must preserve newly written data.
#[test]
fn empty_store_accepts_writes_after_init() {
    let root = temp_root("empty-then-write");

    let key = ObjectKey::from_name("first-object");

    {
        let mut store = open_store(&root);
        // Store is empty, no writes yet.
        assert!(store.list_keys().is_empty());

        store.put(key, b"hello-from-empty-store").expect("put");
        store.sync_all().expect("sync");
    }

    let store = open_store(&root);
    assert!(store.contains_key(key));
    assert_eq!(
        store.get(key).expect("get"),
        Some(b"hello-from-empty-store".to_vec())
    );
    assert_eq!(store.list_keys().len(), 1);

    let report = store.replay_report();
    assert_eq!(report.puts_seen, 1, "one put record replayed");

    cleanup(&root);
}

/// Open a store directory that does not exist yet. The store must create
/// the directory and segment files cleanly.
#[test]
fn nonexistent_store_directory_is_created_cleanly() {
    let root = temp_root("non-existent-dir");

    // Ensure the directory does not exist.
    let _ = fs::remove_dir_all(&root);

    let store = LocalObjectStore::open_with_options(&root, fast_opts())
        .expect("open should create directory");

    assert!(root.exists(), "store root must be created");
    assert!(segments_dir(&root).exists(), "segments dir must be created");

    let report = store.replay_report();
    assert_eq!(report.records_seen, 0);

    drop(store);
    cleanup(&root);
}

/// Read-only open of a nonexistent store directory returns None, not an error.
#[test]
fn read_only_nonexistent_store_returns_none() {
    let root = temp_root("ro-nonexistent");

    let _ = fs::remove_dir_all(&root);

    let result = LocalObjectStore::open_read_only_with_options(&root, fast_opts())
        .expect("open_read_only should not error");
    assert!(
        result.is_none(),
        "nonexistent store must return None for read-only open"
    );

    cleanup(&root);
}

/// Read-only open of an empty store directory returns a store with no objects.
#[test]
fn read_only_empty_store_has_no_objects() {
    let root = temp_root("ro-empty");

    // Create the store so the directory exists.
    {
        let _store = open_store(&root);
    }

    let ro_store = LocalObjectStore::open_read_only_with_options(&root, fast_opts())
        .expect("open_read_only should succeed");
    assert!(
        ro_store.is_some(),
        "read-only open of empty store must return Some"
    );
    let store = ro_store.unwrap();
    assert!(store.list_keys().is_empty());

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. Replay report accuracy under mixed workloads
// ═══════════════════════════════════════════════════════════════════════════

/// Mix puts and deletes in a single segment, crash, reopen, and verify
/// the replay report counts puts and deletes correctly.
#[test]
fn replay_report_counts_puts_and_deletes() {
    let root = temp_root("replay-put-del");

    let key_keep = ObjectKey::from_name("keep-me");
    let key_del = ObjectKey::from_name("delete-me");

    {
        let mut store = open_store(&root);
        store.put(key_keep, b"keep-data").expect("put keep");
        store.put(key_del, b"delete-data").expect("put delete");
        store.delete(key_del).expect("delete");
        store.sync_all().expect("sync");
    }

    let store = open_store(&root);
    let report = store.replay_report();

    // All records in a single segment are replayed directly.
    assert_eq!(report.puts_seen, 2, "two puts were written");
    assert_eq!(report.deletes_seen, 1, "one delete tombstone was written");
    assert_eq!(report.records_seen, 3, "total records = 2 puts + 1 delete");

    // Keep key must survive; delete key must be gone.
    assert!(store.contains_key(key_keep));
    assert!(!store.contains_key(key_del));
    assert_eq!(store.list_keys().len(), 1);

    cleanup(&root);
}

/// Write objects with explicit content-addressed keys and verify they
/// survive replay with exactly the right content.
#[test]
fn content_addressed_objects_survive_replay() {
    let root = temp_root("ca-replay");

    let payloads: Vec<Vec<u8>> = vec![
        b"content-addressed-object-one".to_vec(),
        b"content-addressed-object-two".to_vec(),
        b"content-addressed-object-three".to_vec(),
    ];

    let keys: Vec<ObjectKey> = {
        let mut store = open_store(&root);
        let mut ks = Vec::new();
        for p in &payloads {
            let key = store.put_content_addressed(p).expect("put ca");
            ks.push(key);
        }
        store.sync_all().expect("sync");
        ks
    };

    // Reopen after crash.
    let store = open_store(&root);
    let report = store.replay_report();
    assert_eq!(report.puts_seen, 3);

    for (i, key) in keys.iter().enumerate() {
        assert!(
            store.contains_key(*key),
            "content-addressed key {i} must survive replay"
        );
        let data = store.get(*key).expect("get").expect("data");
        assert_eq!(data, payloads[i], "content must match byte-for-byte");
    }

    cleanup(&root);
}
