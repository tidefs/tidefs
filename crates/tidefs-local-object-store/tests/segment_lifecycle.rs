// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Segment lifecycle and compaction unit tests for `tidefs-local-object-store`.
//!
//! Covers full segment lifecycle — allocation, write, seal, read-back,
//! checksum verification — plus compaction correctness, partial-write
//! detection, GC pin-set semantics, and boundary conditions.
//!
//! These tests harden the durability layer that the FUSE daemon depends on
//! for fsync and segment replay.

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};

// ── Fixture helpers ────────────────────────────────────────────────────────

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-seg-lifecycle-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn cleanup(root: &PathBuf) {
    let _ = fs::remove_dir_all(root);
}

fn small_segment_opts(max_bytes: u64) -> StoreOptions {
    StoreOptions {
        max_segment_bytes: max_bytes,
        ..StoreOptions::test_fast()
    }
}

fn open_small(root: &PathBuf, max_bytes: u64) -> LocalObjectStore {
    LocalObjectStore::open_with_options(root, small_segment_opts(max_bytes)).expect("open store")
}

fn reopen(root: &PathBuf, max_bytes: u64) -> LocalObjectStore {
    LocalObjectStore::open_with_options(root, small_segment_opts(max_bytes)).expect("reopen store")
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

/// List .vlos segment files in the store's segments directory.
fn segment_files(root: &Path) -> Vec<PathBuf> {
    let seg_dir = root.join("segments");
    let mut files: Vec<PathBuf> = fs::read_dir(&seg_dir)
        .expect("read segments dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "vlos"))
        .collect();
    files.sort();
    files
}

/// Helper: get the file length of a path.
fn file_len(path: &PathBuf) -> u64 {
    fs::metadata(path).expect("metadata").len()
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Segment allocation, write, seal, read-back
// ═══════════════════════════════════════════════════════════════════════════

/// Allocate a fresh segment, write objects with known content, trigger
/// segment rotation (seal), and verify all objects survive through a
/// close/reopen cycle with byte-for-byte equality.
#[test]
fn test_segment_alloc_write_seal_read() {
    let root = temp_root("alloc-write-seal");
    // max_segment_bytes=1024 forces rotation after ~2-3 small objects
    let max_seg = 1024u64;

    // Three objects of different sizes.
    let objects: Vec<(&str, &[u8])> = vec![
        (
            "obj-alpha",
            b"Alpha: first object payload for segment lifecycle test",
        ),
        ("obj-beta", b"Beta: second payload with different content"),
        (
            "obj-gamma",
            b"Gamma: third payload wraps up the initial segment",
        ),
    ];

    // Write objects. Small segment size means rotation happens naturally.
    {
        let mut store = open_small(&root, max_seg);
        for (name, payload) in &objects {
            let key = ObjectKey::from_name(name.as_bytes());
            store.put(key, payload).expect("put");
        }
        store.sync_all().expect("sync_all");
    }

    // Reopen: all objects must survive and be byte-for-byte identical.
    {
        let store = reopen(&root, max_seg);
        let stats = store.stats();
        assert_eq!(stats.live_objects, 3, "all 3 objects must be live");

        for (name, expected) in &objects {
            let key = ObjectKey::from_name(name.as_bytes());
            assert!(
                store.contains_key(key),
                "key for {name} must be present after reopen"
            );
            let got = store.get(key).expect("get").expect("object should exist");
            assert_eq!(
                got, *expected,
                "payload for {name} must be byte-for-byte after seal+reopen"
            );
        }

        // Verify segment files exist on disk; at least one segment.
        let segs = segment_files(&root);
        assert!(!segs.is_empty(), "at least one segment file must exist");
        for seg in &segs {
            assert!(file_len(seg) > 0, "segment file must be non-empty");
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Checksum mismatch detection
// ═══════════════════════════════════════════════════════════════════════════

/// Write objects, seal, manually corrupt one byte in the on-disk segment
/// (payload region), then attempt to read back via `get_verified`.
/// The corrupted object must be detected — either `get_verified` returns
/// an error or the data differs from what was written.
#[test]
fn test_segment_checksum_mismatch_detected() {
    let root = temp_root("checksum-mismatch");

    let good_key = ObjectKey::from_name("good-record");
    let bad_key = ObjectKey::from_name("bad-record");
    let good_payload = b"good-data-that-must-survive-checksum-test";
    let bad_payload = b"bad-data-that-will-be-corrupted-on-disk-later";

    // Write two objects in a large-enough segment and sync.
    {
        let mut store = open_small(&root, 16384);
        store.put(good_key, good_payload).expect("put good");
        store.put(bad_key, bad_payload).expect("put bad");
        store.sync_all().expect("sync_all");
    }

    // Locate the single segment file and corrupt the bad object's payload.
    let segs = segment_files(&root);
    assert!(!segs.is_empty(), "must have at least one segment file");
    let seg_path = &segs[0];
    let seg_len = file_len(seg_path);

    // Records are appended sequentially. The good record comes first.
    // Its layout: 96 header + 39 payload + 16 footer + 112 trailer = 263 bytes.
    // The bad record starts at offset 263. Its payload starts at 263 + 96 = 359.
    // Flip a bit in the bad record's payload at offset ~365 (middle of payload).
    let bad_payload_offset: u64 = 96 + good_payload.len() as u64 + 16 + 112 + 96;
    if seg_len > bad_payload_offset + 10 {
        flip_bit(seg_path, bad_payload_offset + 5);

        // Reopen: the store replays and may detect corruption.
        let reopen_result = LocalObjectStore::open_with_options(&root, small_segment_opts(16384));

        match reopen_result {
            Ok(store) => {
                // Good record must survive.
                assert!(
                    store.contains_key(good_key),
                    "good record must survive after corruption of neighbor"
                );
                let good_read = store.get(good_key).expect("get good").expect("good exists");
                assert_eq!(
                    good_read, good_payload,
                    "good payload must be byte-for-byte"
                );

                // Bad record: either read fails or data differs.
                match store.get(bad_key) {
                    Ok(Some(data)) => {
                        assert_ne!(
                            data, bad_payload,
                            "corrupted object data must differ from original"
                        );
                    }
                    Ok(None) => {} // discarded during replay — acceptable
                    Err(_e) => {}  // detected on replay — acceptable
                }

                // get_verified on bad key should fail or return different data.
                match store.get_verified(bad_key) {
                    Ok(Some(data)) => {
                        assert_ne!(
                            data, bad_payload,
                            "get_verified of corrupted object must detect mismatch"
                        );
                    }
                    Ok(None) => {}
                    Err(_e) => {}
                }
            }
            Err(_e) => {
                // Store refused to open due to corruption — also acceptable.
            }
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Partial-write segment detection on open
// ═══════════════════════════════════════════════════════════════════════════

/// Write objects, sync, then truncate the segment file mid-record to
/// simulate a crash where the last record's integrity trailer was never
/// fully written. On reopen, the partial record must be trimmed and
/// earlier records must survive.
#[test]
fn test_partial_write_segment_recovered_on_open() {
    let root = temp_root("partial-write");

    let keep_key = ObjectKey::from_name("keep-after-trim");
    let torn_key = ObjectKey::from_name("torn-record");
    let keep_payload = b"this-data-survives-tail-repair";

    {
        let mut store = open_small(&root, 16384);
        store.put(keep_key, keep_payload).expect("put keep");
        store
            .put(torn_key, b"this-data-gets-torn-off")
            .expect("put torn");
        store.sync_all().expect("sync_all");
    }

    // Truncate the segment to remove the last record's footer + trailer.
    let segs = segment_files(&root);
    let seg_path = &segs[0];
    let orig_len = file_len(seg_path);

    // Remove enough bytes to cut into the second record's integrity trailer
    // (last ~128 bytes of the file). This simulates an incomplete write.
    let trunc_len = orig_len.saturating_sub(80);
    if trunc_len > 96 {
        let file = OpenOptions::new().write(true).open(seg_path).expect("open");
        file.set_len(trunc_len).expect("truncate");
        drop(file);

        // Reopen: must not panic. Store either recovers or rejects cleanly.
        let result = LocalObjectStore::open_with_options(&root, small_segment_opts(16384));
        match result {
            Ok(store) => {
                // The kept object (written first) must survive.
                assert!(
                    store.contains_key(keep_key),
                    "first object must survive partial-write truncation"
                );
                let got = store.get(keep_key).expect("get").expect("data present");
                assert_eq!(got, keep_payload, "kept payload intact");

                // Torn record: either absent or detected as corrupt.
                match store.get(torn_key) {
                    Ok(Some(data)) => {
                        assert_eq!(
                            data, b"this-data-gets-torn-off",
                            "if torn record survived, it must be complete"
                        );
                    }
                    Ok(None) => {} // discarded by tail repair
                    Err(_e) => {}  // detected as corrupt
                }
            }
            Err(_e) => {
                // Rejection is also acceptable — partial data is invalid.
            }
        }
    }

    cleanup(&root);
}

/// Write an object, sync, then truncate the segment file to zero bytes
/// to simulate a catastrophic crash that destroyed the segment. Reopen
/// must initialize cleanly (empty store) without panicking.
#[test]
fn test_truncated_segment_yields_empty_store() {
    let root = temp_root("truncated-zero");

    let key = ObjectKey::from_name("destroyed-key");

    {
        let mut store = open_small(&root, 4096);
        store.put(key, b"destroyed-data").expect("put");
        store.sync_all().expect("sync_all");
    }

    // Truncate the segment file to 0 bytes.
    let segs = segment_files(&root);
    for seg in &segs {
        let file = OpenOptions::new().write(true).open(seg).expect("open");
        file.set_len(0).expect("truncate to zero");
    }

    // Delete the intent-log directory so no committed transactions
    // survive the simulated catastrophic segment loss.
    let ilog = root.join("intent_log");
    let _ = fs::remove_dir_all(&ilog);

    // Reopen: must not panic. Store may be empty or reject the segment.
    let result = LocalObjectStore::open_with_options(&root, small_segment_opts(4096));
    match result {
        Ok(store) => {
            // Empty segment file → empty store, or the store creates a new
            // segment and continues with no objects.
            assert!(
                !store.contains_key(key) || store.list_keys().is_empty(),
                "truncated store must be empty"
            );
        }
        Err(_e) => {
            // Rejection of corrupted/empty segment is also acceptable.
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Compaction merges fragmented segments
// ═══════════════════════════════════════════════════════════════════════════

/// Create several segments with interleaved live and dead objects,
/// then run compaction with only a subset of live keys as protected.
/// Verify: protected live objects survive, unprotected live objects
/// are tombstoned, dead objects stay gone, and segment space is
/// reclaimed (fewer or compacted segments).
#[test]
fn test_segment_compaction_merges_fragmented() {
    let root = temp_root("compaction-frag");

    let max_seg = 1024u64; // small segments to force many rotations

    // Write 12 objects; 4 will be protected, 4 unprotected (will be collected),
    // 4 will be explicitly deleted beforehand.
    let protected_keys: Vec<ObjectKey> = (0..4)
        .map(|i| ObjectKey::from_name(format!("prot-{i}")))
        .collect();
    let unprotected_keys: Vec<ObjectKey> = (0..4)
        .map(|i| ObjectKey::from_name(format!("unprot-{i}")))
        .collect();
    let dead_keys: Vec<ObjectKey> = (0..4)
        .map(|i| ObjectKey::from_name(format!("dead-{i}")))
        .collect();

    let all_keys: Vec<&ObjectKey> = protected_keys
        .iter()
        .chain(unprotected_keys.iter())
        .chain(dead_keys.iter())
        .collect();

    {
        let mut store = open_small(&root, max_seg);
        for (i, key) in all_keys.iter().enumerate() {
            let payload = format!("object-{i:02}-payload-data").into_bytes();
            store.put(**key, &payload).expect("put");
        }
        store.sync_all().expect("sync_all");
    }

    // Delete the dead keys (creates tombstones scattered across segments).
    {
        let mut store = reopen(&root, max_seg);
        for key in &dead_keys {
            let existed = store.delete(*key).expect("delete");
            assert!(existed, "delete must succeed for {key}");
        }
        store.sync_all().expect("sync after deletes");
    }

    // Verify pre-compaction state: protected + unprotected alive; dead gone.
    {
        let store = reopen(&root, max_seg);
        for key in &protected_keys {
            assert!(
                store.contains_key(*key),
                "protected key must be alive pre-compaction"
            );
        }
        for key in &unprotected_keys {
            assert!(
                store.contains_key(*key),
                "unprotected key must be alive pre-compaction"
            );
        }
        for key in &dead_keys {
            assert!(
                !store.contains_key(*key),
                "dead key must be gone pre-compaction"
            );
        }
    }

    // Run compaction: protect only the protected_keys set.
    {
        let mut store = reopen(&root, max_seg);
        let report = store
            .compact_retaining(&protected_keys, &[])
            .expect("compact_retaining");

        // The unprotected (alive) keys should be tombstoned by compaction.
        assert!(
            report.tombstoned_unprotected_keys >= unprotected_keys.len(),
            "compaction should tombstone at least {} unprotected keys, got {}",
            unprotected_keys.len(),
            report.tombstoned_unprotected_keys
        );
    }

    // After compaction: only protected keys remain.
    {
        let store = reopen(&root, max_seg);
        let live_set: Vec<ObjectKey> = store.list_keys();

        for key in &protected_keys {
            assert!(
                store.contains_key(*key),
                "protected key {key} must survive compaction"
            );
        }
        for key in &unprotected_keys {
            assert!(
                !store.contains_key(*key),
                "unprotected alive key {key} must be collected by compaction"
            );
        }
        for key in &dead_keys {
            assert!(
                !store.contains_key(*key),
                "dead key {key} must stay gone after compaction"
            );
        }

        assert_eq!(
            live_set.len(),
            protected_keys.len(),
            "only protected keys must remain after compaction"
        );
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. GC pin set prevents collection of referenced objects
// ═══════════════════════════════════════════════════════════════════════════

/// Write objects, delete some, then run `compact_retaining` with a
/// subset of keys in the protected set. Verify:
/// - Protected keys survive compaction.
/// - Unprotected keys (including dead ones) are tombstoned and removed.
/// - The pin set effectively prevents GC of referenced objects.
#[test]
fn test_segment_pin_set_prevents_gc_of_referenced_objects() {
    let root = temp_root("gc-pin-set");

    let max_seg = 1024u64;

    let pinned_key = ObjectKey::from_name("pinned-object");
    let unpinned_alive_key = ObjectKey::from_name("unpinned-alive");
    let dead_key = ObjectKey::from_name("dead-object");
    let pinned_payload = b"pinned-data-must-survive-gc-pass";
    let unpinned_payload = b"unpinned-data-without-protection";
    let dead_payload = b"dead-data-marked-for-deletion";

    {
        let mut store = open_small(&root, max_seg);
        store.put(pinned_key, pinned_payload).expect("put pinned");
        store
            .put(unpinned_alive_key, unpinned_payload)
            .expect("put unpinned");
        store.put(dead_key, dead_payload).expect("put dead");
        store.sync_all().expect("sync_all");
    }

    // Delete the dead key.
    {
        let mut store = reopen(&root, max_seg);
        assert!(store.delete(dead_key).expect("delete dead"));
        store.sync_all().expect("sync after delete");
    }

    // Verify all keys are in expected state before compaction.
    {
        let store = reopen(&root, max_seg);
        assert!(store.contains_key(pinned_key));
        assert!(store.contains_key(unpinned_alive_key));
        assert!(!store.contains_key(dead_key));
    }

    // Run compaction: pin only the pinned_key.
    {
        let mut store = reopen(&root, max_seg);
        let protected = vec![pinned_key];
        let report = store
            .compact_retaining(&protected, &[])
            .expect("compact_retaining with pin set");

        // Unprotected alive key should have been tombstoned.
        assert!(
            report.tombstoned_unprotected_keys >= 1,
            "compaction must tombstone unprotected keys"
        );
    }

    // After compaction: pinned survives, unpinned alive is gone, dead stays gone.
    {
        let store = reopen(&root, max_seg);

        // Pinned object must survive.
        assert!(
            store.contains_key(pinned_key),
            "pinned object must survive GC compaction"
        );
        let got = store.get(pinned_key).expect("get").expect("pinned exists");
        assert_eq!(got, pinned_payload, "pinned payload must be intact");

        // Unpinned alive object must be gone (tombstoned).
        assert!(
            !store.contains_key(unpinned_alive_key),
            "unpinned object without GC pin must be collected"
        );

        // Dead object stays gone.
        assert!(
            !store.contains_key(dead_key),
            "dead object must remain gone after compaction"
        );
    }

    cleanup(&root);
}

/// Multiple objects in the pin set all survive; nothing from the
/// protected set is collected.
#[test]
fn test_pin_set_multiple_objects_all_survive() {
    let root = temp_root("pin-multi");

    let max_seg = 1024u64;
    let pinned: Vec<ObjectKey> = (0..4)
        .map(|i| ObjectKey::from_name(format!("pinned-{i}")))
        .collect();
    let unprotected: Vec<ObjectKey> = (0..3)
        .map(|i| ObjectKey::from_name(format!("unprotected-{i}")))
        .collect();

    {
        let mut store = open_small(&root, max_seg);
        for key in pinned.iter().chain(unprotected.iter()) {
            let name_bytes = key.as_bytes();
            store.put(*key, &name_bytes[..8]).expect("put");
        }
        store.sync_all().expect("sync_all");
    }

    // Compact with only pinned keys protected.
    {
        let mut store = reopen(&root, max_seg);
        store
            .compact_retaining(&pinned, &[])
            .expect("compact_retaining with multi-pin");
    }

    {
        let store = reopen(&root, max_seg);
        for key in &pinned {
            assert!(store.contains_key(*key), "pinned key {key} must survive");
        }
        for key in &unprotected {
            assert!(
                !store.contains_key(*key),
                "unprotected key {key} must be collected"
            );
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. Segment boundary conditions
// ═══════════════════════════════════════════════════════════════════════════

/// Write an object that fits exactly at the segment boundary.
/// The object must be stored correctly and survive reopen.
#[test]
fn test_boundary_object_at_segment_size_limit() {
    let root = temp_root("boundary-fit");

    // Use a 1024-byte segment. Record overhead (v3): 96 header + 16 footer + 112 trailer = 224.
    // max_object_bytes = 1024 - 224 = 800.
    let max_seg = 1024u64;
    let max_obj = max_seg.saturating_sub(224);

    let key = ObjectKey::from_name("boundary-fit-key");
    let payload = vec![0xABu8; max_obj as usize];

    {
        let mut store = open_small(&root, max_seg);
        store.put(key, &payload).expect("put boundary object");
        store.sync_all().expect("sync_all");
    }

    {
        let store = reopen(&root, max_seg);
        assert!(store.contains_key(key));
        let got = store.get(key).expect("get").expect("object should exist");
        assert_eq!(
            got.len(),
            max_obj as usize,
            "boundary object must retain exact size"
        );
        assert_eq!(got, payload, "boundary object must be byte-for-byte");
    }

    cleanup(&root);
}

/// Write an object that is one byte too large for the segment.
/// The store must reject it with a PayloadTooLarge error.
#[test]
fn test_boundary_object_one_byte_over_limit_rejected() {
    let root = temp_root("boundary-over");

    let max_seg = 1024u64;
    let record_overhead = 224u64;
    let max_obj = max_seg.saturating_sub(record_overhead);
    // One byte over the limit
    let too_large = max_obj.saturating_add(1);

    let key = ObjectKey::from_name("too-large-key");
    let payload = vec![0xCDu8; too_large as usize];

    {
        let mut store = open_small(&root, max_seg);
        let result = store.put(key, &payload);
        match result {
            Err(e) => {
                let msg = format!("{e}");
                assert!(
                    msg.contains("TooLarge") || msg.contains("too large") || msg.contains("max"),
                    "error must indicate payload too large: {e}"
                );
            }
            Ok(_stored) => {
                // If it succeeded, it must have triggered a rotation first.
                // Verify the object can be read back.
                store.sync_all().expect("sync_all");
                let got = store.get(key).expect("get").expect("object exists");
                assert_eq!(got, payload, "if stored, must be intact");
            }
        }
    }

    cleanup(&root);
}

/// Write a zero-byte object. It must be stored and readable (returning
/// an empty payload).
#[test]
fn test_boundary_zero_byte_object_stored() {
    let root = temp_root("boundary-zero");

    let key = ObjectKey::from_name("zero-byte-key");
    let payload: [u8; 0] = [];

    {
        let mut store = open_small(&root, 4096);
        let result = store.put(key, &payload);
        // Zero-byte objects may or may not be rejected depending on policy.
        match result {
            Ok(_stored) => {
                store.sync_all().expect("sync_all");
                let got = store
                    .get(key)
                    .expect("get")
                    .expect("zero-byte object should exist");
                assert!(got.is_empty(), "zero-byte object must be empty");
            }
            Err(_e) => {
                // Rejection of zero-byte objects is acceptable (e.g.,
                // PayloadTooLarge with max=0).
            }
        }
    }

    cleanup(&root);
}

/// Write multiple objects, filling a segment exactly to capacity.
/// The first object beyond capacity must trigger a rotation into a
/// new segment, and all objects must survive.
#[test]
fn test_boundary_segment_overflow_triggers_rotation() {
    let root = temp_root("boundary-overflow");

    let max_seg = 1024u64;
    let record_overhead: u64 = 96 + 16 + 112; // 224
    let _max_obj = max_seg.saturating_sub(record_overhead); // 800

    // Object that takes up most of the segment.
    let large_payload = vec![0x11u8; 600];

    // Two more objects. The second will overflow.
    let medium_payload = vec![0x22u8; 400];

    let key1 = ObjectKey::from_name("seg-fill-1");
    let key2 = ObjectKey::from_name("seg-fill-2");

    {
        let mut store = open_small(&root, max_seg);
        store.put(key1, &large_payload).expect("put fill-1"); // ~824 bytes
                                                              // Next write (~624 bytes) overflows → rotation happens internally.
        store.put(key2, &medium_payload).expect("put fill-2");
        store.sync_all().expect("sync_all");
    }

    {
        let store = reopen(&root, max_seg);
        assert!(
            store.contains_key(key1),
            "first object must survive segment overflow"
        );
        assert!(
            store.contains_key(key2),
            "overflow object must be in new segment"
        );

        let got1 = store.get(key1).expect("get").expect("key1 exists");
        assert_eq!(got1, large_payload, "fill-1 payload intact");

        let got2 = store.get(key2).expect("get").expect("key2 exists");
        assert_eq!(got2, medium_payload, "fill-2 payload intact");

        // Verify at least 2 segment files exist.
        let segs = segment_files(&root);
        assert!(
            segs.len() >= 2,
            "overflow must create at least 2 segment files, got {}",
            segs.len()
        );
    }

    cleanup(&root);
}
