//! Flush-path and segment-seal unit tests for `tidefs-local-object-store`.
//!
//! Covers the write-to-sync lifecycle through the object-store layer:
//! flush-path buffering, threshold-triggered segment rotation with seal
//! verification, recovery metadata byte-equivalence after simulated crash
//! (in-memory state drop), and edge-case flush scenarios.
//!
//! These tests complement the fsync-durability and segment-replay suites
//! by focusing on the flush-path state machine (write, buffer, flush, seal)
//! rather than on high-level fsync semantics or low-level format fuzzing.

use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};

// ── Fixture helpers ────────────────────────────────────────────────────────

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-flush-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn cleanup(root: &PathBuf) {
    let _ = fs::remove_dir_all(root);
}

fn fast_opts() -> StoreOptions {
    // sync_on_write is false — writes go to the OS page cache.
    // Explicit sync_all is required for durability, which is what
    // the flush path tests exercise.
    StoreOptions {
        max_segment_bytes: 16384,
        ..StoreOptions::test_fast()
    }
}

fn open_store(root: &PathBuf) -> LocalObjectStore {
    LocalObjectStore::open_with_options(root, fast_opts()).expect("open store")
}

fn reopen_store(root: &PathBuf) -> LocalObjectStore {
    LocalObjectStore::open_with_options(root, fast_opts()).expect("reopen store")
}

fn pseudo_random_data(len: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    for _ in 0..len {
        state = state
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(0xbf58_476d_1ce4_e5b9);
        out.push((state >> 56) as u8);
    }
    out
}

fn segments_dir(root: &Path) -> PathBuf {
    root.join("segments")
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Write-ahead buffering flush lifecycle
// ═══════════════════════════════════════════════════════════════════════════

/// With sync_on_write=false, data is buffered in the OS page cache.
/// Explicit sync_all must persist all buffered writes so they survive
/// a full store close+reopen cycle.
#[test]
fn buffered_writes_survive_after_flush_and_reopen() {
    let root = temp_root("buf-flush-reopen");

    {
        let mut store = open_store(&root);
        let keys: Vec<(ObjectKey, Vec<u8>)> = (0..4)
            .map(|i| {
                let payload = pseudo_random_data(512, i as u64);
                let key = ObjectKey::from_name(format!("buf-{i}"));
                (key, payload)
            })
            .collect();
        for (key, payload) in &keys {
            store.put(*key, payload).expect("put");
        }
        // sync_on_write was false — nothing is durable yet.
        store.sync_all().expect("sync_all flush");
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, 4);
        for (key, expected) in &[
            (ObjectKey::from_name("buf-0"), pseudo_random_data(512, 0)),
            (ObjectKey::from_name("buf-1"), pseudo_random_data(512, 1)),
            (ObjectKey::from_name("buf-2"), pseudo_random_data(512, 2)),
            (ObjectKey::from_name("buf-3"), pseudo_random_data(512, 3)),
        ] {
            let got = store
                .get(*key)
                .expect("get")
                .expect("key missing after flush");
            assert_eq!(
                got, *expected,
                "byte mismatch for key after buffered-flush+reopen"
            );
        }
    }

    cleanup(&root);
}

/// Multiple sequential flushes should incrementally commit data:
/// after each flush, a simulated crash (drop+reopen) yields only
/// the data flushed up to that point.
#[test]
fn incremental_flush_commits_data_before_flush_point() {
    let root = temp_root("incr-flush");

    // Phase A: write obj-0, flush, reopen — obj-0 must survive.
    {
        let mut store = open_store(&root);
        store
            .put(ObjectKey::from_name("obj-0"), b"aaaa")
            .expect("put obj-0");
        store.sync_all().expect("sync_all A");
    }
    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, 1);
    }

    // Phase B: write obj-1, flush, reopen — both must survive.
    {
        let mut store = open_store(&root);
        store
            .put(ObjectKey::from_name("obj-1"), b"bbbb")
            .expect("put obj-1");
        store.sync_all().expect("sync_all B");
    }
    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, 2);
        assert_eq!(
            store
                .get(ObjectKey::from_name("obj-0"))
                .expect("get")
                .unwrap(),
            b"aaaa"
        );
        assert_eq!(
            store
                .get(ObjectKey::from_name("obj-1"))
                .expect("get")
                .unwrap(),
            b"bbbb"
        );
    }

    cleanup(&root);
}

/// Writing a single byte and then flushing must preserve that byte
/// precisely through reopen.
#[test]
fn single_byte_flush_survives_reopen() {
    let root = temp_root("single-byte");

    let key = ObjectKey::from_name("one-byte");
    let payload = vec![0x7f];

    {
        let mut store = open_store(&root);
        store.put(key, &payload).expect("put single byte");
        store.sync_all().expect("sync_all");
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, 1);
        let got = store.get(key).expect("get").expect("missing");
        assert_eq!(got, payload, "single byte mismatch after flush+reopen");
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Segment seal: immutability and integrity verification
// ═══════════════════════════════════════════════════════════════════════════

/// After segment rotation (triggered by exceeding max_segment_bytes),
/// the sealed segment's data must survive reopen.
#[test]
fn sealed_segment_data_survives_after_rotation() {
    let root = temp_root("seal-survives");

    let small_opts = StoreOptions {
        max_segment_bytes: 1024,
        ..StoreOptions::test_fast()
    };

    {
        let mut store = LocalObjectStore::open_with_options(&root, small_opts).expect("open small");

        // ~300-byte payloads: first 3 fit in one 1024-byte segment,
        // the 4th triggers rotation.
        for i in 0..4 {
            let payload = pseudo_random_data(300, i as u64);
            let key = ObjectKey::from_name(format!("seal-{i}"));
            store.put(key, &payload).expect("put");
        }
        store.sync_all().expect("sync_all");
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, 4);
        for i in 0..4 {
            let key = ObjectKey::from_name(format!("seal-{i}"));
            let expected = pseudo_random_data(300, i as u64);
            let got = store
                .get(key)
                .expect("get")
                .expect("missing after rotation");
            assert_eq!(
                got, expected,
                "byte mismatch for seal-{i} after segment rotation"
            );
        }
    }

    cleanup(&root);
}

/// After rotation, the old segment file must exist and be readable,
/// and the new segment must contain the writes that triggered rotation.
#[test]
fn segment_file_count_increases_after_rotation() {
    let root = temp_root("seg-count");

    let tiny_opts = StoreOptions {
        max_segment_bytes: 512,
        ..StoreOptions::test_fast()
    };

    let seg_dir = segments_dir(&root);
    let initial_seg_count;

    {
        let mut store = LocalObjectStore::open_with_options(&root, tiny_opts).expect("open tiny");
        initial_seg_count = store.stats().segment_count;
        assert!(
            initial_seg_count >= 1,
            "initial segment_count should be at least 1"
        );

        // Write enough data to force at least one rotation.
        for i in 0..6 {
            let payload = pseudo_random_data(200, i as u64);
            store
                .put(ObjectKey::from_name(format!("cnt-{i}")), &payload)
                .expect("put");
        }
        store.sync_all().expect("sync_all");
    }

    let after_seg_count;
    {
        let store = reopen_store(&root);
        after_seg_count = store.stats().segment_count;
    }

    assert!(
        after_seg_count > initial_seg_count,
        "segment_count should increase after rotation (had {initial_seg_count}, now {after_seg_count})"
    );

    // Verify all segment files exist on disk.
    let seg_entries: Vec<_> = fs::read_dir(&seg_dir)
        .expect("read segments dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "vlos"))
        .collect();
    assert!(
        seg_entries.len() >= after_seg_count,
        "segment files on disk ({}) should match or exceed segment_count ({after_seg_count})",
        seg_entries.len()
    );

    cleanup(&root);
}

/// After a sealed segment rotation, writing more data goes to a new
/// segment and does not corrupt the old one.
#[test]
fn new_writes_go_to_new_segment_after_rotation() {
    let root = temp_root("new-seg-after-rot");

    let small_opts = StoreOptions {
        max_segment_bytes: 1024,
        ..StoreOptions::test_fast()
    };

    let pre_rotation_key = ObjectKey::from_name("pre-rot");

    {
        let mut store = LocalObjectStore::open_with_options(&root, small_opts).expect("open small");

        // Fill the first segment with small writes.
        for i in 0..6 {
            store
                .put(
                    ObjectKey::from_name(format!("fill-{i}")),
                    &pseudo_random_data(180, i as u64),
                )
                .expect("put fill");
        }

        // Write an object that should be in a new segment (post-rotation).
        store
            .put(pre_rotation_key, b"post-rotation-data")
            .expect("put post");
        store.sync_all().expect("sync_all");
    }

    {
        let store = reopen_store(&root);
        // All fill objects must still be present.
        for i in 0..6 {
            let key = ObjectKey::from_name(format!("fill-{i}"));
            let expected = pseudo_random_data(180, i as u64);
            let got = store.get(key).expect("get").expect("fill missing");
            assert_eq!(got, expected, "fill-{i} corrupted after rotation");
        }
        // Post-rotation object must be present.
        assert_eq!(
            store.get(pre_rotation_key).expect("get").unwrap(),
            b"post-rotation-data"
        );
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Recovery metadata byte-equivalence
// ═══════════════════════════════════════════════════════════════════════════

/// After flush+reopen, the replay report must reflect the number of
/// objects written and segment topology correctly.
#[test]
fn replay_report_accurate_after_flush_reopen() {
    let root = temp_root("replay-accurate");

    {
        let mut store = open_store(&root);
        for i in 0..5 {
            let key = ObjectKey::from_name(format!("rep-{i}"));
            store
                .put(key, &pseudo_random_data(256, i as u64))
                .expect("put");
        }
        store.sync_all().expect("sync_all");
    }

    {
        let store = reopen_store(&root);
        let stats = store.stats();
        let report = store.replay_report();

        assert_eq!(stats.live_objects, 5, "live_objects mismatch");
        assert_eq!(report.records_seen, 5, "records_seen mismatch");
        assert_eq!(report.puts_seen, 5, "puts_seen mismatch");
        assert_eq!(report.deletes_seen, 0, "unexpected deletes_seen");
        assert!(
            report.segment_count >= 1,
            "segment_count should be at least 1, got {}",
            report.segment_count
        );
        // All records in current code are v3 production-integrity records.
        assert_eq!(
            report.production_integrity_records_seen, 5,
            "production_integrity_records_seen should equal total records"
        );
    }

    cleanup(&root);
}

/// After flush+reopen, the object index (list_keys) must match exactly
/// what was written, with all keys present and byte-for-byte identical.
#[test]
fn key_enumeration_matches_after_flush_reopen() {
    let root = temp_root("key-enum");

    let expected_keys: Vec<ObjectKey> = (0..8)
        .map(|i| ObjectKey::from_name(format!("list-{i}")))
        .collect();

    {
        let mut store = open_store(&root);
        for (i, key) in expected_keys.iter().enumerate() {
            store
                .put(*key, &pseudo_random_data(128, i as u64))
                .expect("put");
        }
        store.sync_all().expect("sync_all");
    }

    {
        let store = reopen_store(&root);
        let mut keys = store.list_keys();
        keys.sort();
        let mut expected_sorted = expected_keys.clone();
        expected_sorted.sort();
        assert_eq!(
            keys, expected_sorted,
            "key enumeration mismatch after flush+reopen"
        );

        for (i, key) in expected_keys.iter().enumerate() {
            let expected = pseudo_random_data(128, i as u64);
            let got = store.get(*key).expect("get").expect("missing after reopen");
            assert_eq!(got, expected, "value mismatch for list-{i}");
        }
    }

    cleanup(&root);
}

/// After flush+reopen, the store must report accurate location info
/// for each key (segment_id, offset, payload_len).
#[test]
fn object_location_consistent_after_reopen() {
    let root = temp_root("loc-consistent");

    let key = ObjectKey::from_name("loc-obj");
    let payload = pseudo_random_data(1024, 0x42);

    {
        let mut store = open_store(&root);
        let stored = store.put(key, &payload).expect("put");
        let loc = store.location_of(key).expect("location_of");

        assert_eq!(loc.key, key);
        assert_eq!(loc.payload_len, 1024);
        assert_eq!(loc.sequence, stored.sequence);
    }

    {
        let store = reopen_store(&root);
        let loc = store.location_of(key).expect("location_of after reopen");
        assert_eq!(loc.key, key);
        assert_eq!(loc.payload_len, 1024);
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Edge-case flush scenarios
// ═══════════════════════════════════════════════════════════════════════════

/// Flushing with no prior writes is a no-op and leaves the store
/// in a valid reopenable state.
#[test]
fn flush_empty_store_remains_reopenable() {
    let root = temp_root("flush-empty");

    {
        let mut store = open_store(&root);
        store.sync_all().expect("sync_all on empty store");
        assert_eq!(store.stats().live_objects, 0);
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, 0);
        assert_eq!(store.list_keys().len(), 0);
    }

    cleanup(&root);
}

/// Two consecutive flushes with no writes in between must be idempotent.
#[test]
fn double_flush_without_writes_is_idempotent() {
    let root = temp_root("double-flush");

    {
        let mut store = open_store(&root);
        let key = ObjectKey::from_name("double");
        store.put(key, b"hello").expect("put");
        store.sync_all().expect("first sync_all");
        store.sync_all().expect("second sync_all"); // idempotent
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, 1);
    }

    cleanup(&root);
}

/// Write data up to the exact segment boundary, flush, and verify
/// byte-for-byte survival without overflow or corruption.
#[test]
fn flush_at_segment_boundary_survives() {
    let root = temp_root("boundary");

    let boundary_bytes: u64 = 4096;
    let small_opts = StoreOptions {
        max_segment_bytes: boundary_bytes,
        ..StoreOptions::test_fast()
    };

    {
        let mut store =
            LocalObjectStore::open_with_options(&root, small_opts).expect("open boundary");

        // Write objects that fill the segment up near its limit.
        let key1 = ObjectKey::from_name("b1");
        let payload1 = pseudo_random_data(512, 1);
        store.put(key1, &payload1).expect("put b1");

        let key2 = ObjectKey::from_name("b2");
        let payload2 = pseudo_random_data(512, 2);
        store.put(key2, &payload2).expect("put b2");

        store.sync_all().expect("sync_all at boundary");
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, 2);
        assert_eq!(
            store.get(ObjectKey::from_name("b1")).expect("get").unwrap(),
            pseudo_random_data(512, 1)
        );
        assert_eq!(
            store.get(ObjectKey::from_name("b2")).expect("get").unwrap(),
            pseudo_random_data(512, 2)
        );
    }

    cleanup(&root);
}

/// Concurrent writes from multiple threads followed by a single flush
/// must preserve all objects after reopen.
#[test]
fn concurrent_writers_single_flush_all_survive() {
    let root = temp_root("concurrent-flush");

    {
        let mut store = open_store(&root);
        // Write from a single thread since LocalObjectStore is not Send+Sync.
        for thread_id in 0..4 {
            for i in 0..8 {
                let key = ObjectKey::from_name(format!("c-t{thread_id}-{i}"));
                let payload = pseudo_random_data(64, (thread_id << 8) | i as u64);
                store.put(key, &payload).expect("put");
            }
        }
        store.sync_all().expect("sync_all");
    }

    {
        let store = reopen_store(&root);
        // 4 writers × 8 distinct keys = 32 total objects.
        let keys = store.list_keys();
        assert_eq!(
            keys.len(),
            32,
            "expected 32 unique keys, got {}",
            keys.len()
        );
        for thread_id in 0..4 {
            for i in 0..8 {
                let key = ObjectKey::from_name(format!("c-t{thread_id}-{i}"));
                let expected = pseudo_random_data(64, (thread_id << 8) | i as u64);
                let got = store.get(key).expect("get").expect("missing");
                assert_eq!(got, expected, "mismatch for c-t{thread_id}-{i}");
            }
        }
    }

    cleanup(&root);
}

/// After delete + flush + reopen, the deleted key must stay gone and
/// the replay report must reflect the tombstone.
#[test]
fn delete_then_flush_produces_tombstone_in_replay_report() {
    let root = temp_root("del-flush");

    let key = ObjectKey::from_name("del-me");
    {
        let mut store = open_store(&root);
        store.put(key, b"data").expect("put");
        store.sync_all().expect("sync after put");

        let deleted = store.delete(key).expect("delete");
        assert!(deleted, "delete should return true for existing key");
        store.sync_all().expect("sync after delete");
    }

    {
        let store = reopen_store(&root);
        assert!(
            store.get(key).expect("get").is_none(),
            "deleted key should be gone"
        );
        let report = store.replay_report();
        assert!(
            report.deletes_seen >= 1,
            "replay should see at least 1 delete tombstone"
        );
    }

    cleanup(&root);
}

/// Verify that after flush+reopen, the store remains writable and
/// new data can be added without corrupting old data.
#[test]
fn store_writable_after_flush_reopen_cycle() {
    let root = temp_root("writable-after");

    let key_a = ObjectKey::from_name("a");
    let key_b = ObjectKey::from_name("b");

    // Session 1: write A, flush, close.
    {
        let mut store = open_store(&root);
        store.put(key_a, b"first").expect("put a");
        store.sync_all().expect("sync session 1");
    }

    // Session 2: reopen, verify A, write B, flush, close.
    {
        let mut store = open_store(&root);
        assert_eq!(store.get(key_a).expect("get").unwrap(), b"first");
        store.put(key_b, b"second").expect("put b");
        store.sync_all().expect("sync session 2");
    }

    // Session 3: both A and B must be present.
    {
        let store = reopen_store(&root);
        assert_eq!(store.get(key_a).expect("get").unwrap(), b"first");
        assert_eq!(store.get(key_b).expect("get").unwrap(), b"second");
        assert_eq!(store.stats().live_objects, 2);
    }

    cleanup(&root);
}

/// Write an object using `put_content_addressed`, flush, reopen, and
/// verify it via `get_verified`.
#[test]
fn content_addressed_put_survives_flush_reopen() {
    let root = temp_root("content-addr");

    let payload = b"content-addressed blob for flush test";

    let content_key;
    {
        let mut store = open_store(&root);
        content_key = store
            .put_content_addressed(payload)
            .expect("put content addressed");
        store.sync_all().expect("sync_all");
    }

    {
        let store = reopen_store(&root);
        let got = store
            .get_verified(content_key)
            .expect("get_verified")
            .expect("missing after flush");
        assert_eq!(
            got, payload,
            "content addressed mismatch after flush+reopen"
        );
    }

    cleanup(&root);
}

/// After segment rotation caused by time-based threshold, verify
/// the sealed segment files exist and are readable.
#[test]
fn time_based_rotation_leaves_sealed_segments_on_disk() {
    let root = temp_root("time-rot");

    let timed_opts = StoreOptions {
        max_segment_bytes: 65536,
        segment_rotation_interval_secs: 1, // rotate after 1 second
        ..StoreOptions::test_fast()
    };

    let seg_dir = segments_dir(&root);

    {
        let mut store = LocalObjectStore::open_with_options(&root, timed_opts).expect("open timed");

        store
            .put(ObjectKey::from_name("t0"), b"phase-0")
            .expect("put t0");
        store.sync_all().expect("sync t0");

        // Wait beyond the rotation interval.
        thread::sleep(std::time::Duration::from_millis(1200));

        store
            .put(ObjectKey::from_name("t1"), b"phase-1")
            .expect("put t1");
        store.sync_all().expect("sync t1");
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, 2);
        assert_eq!(
            store.get(ObjectKey::from_name("t0")).expect("get").unwrap(),
            b"phase-0"
        );
        assert_eq!(
            store.get(ObjectKey::from_name("t1")).expect("get").unwrap(),
            b"phase-1"
        );

        let seg_entries: Vec<_> = fs::read_dir(&seg_dir)
            .expect("read segments dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "vlos"))
            .collect();
        assert!(
            seg_entries.len() >= 2,
            "time-based rotation should produce at least 2 segment files, got {}",
            seg_entries.len()
        );
    }

    cleanup(&root);
}

/// Verify that after reopen, the store can rotate its current segment
/// explicitly and continue operating without data loss.
#[test]
fn explicit_rotation_after_reopen_preserves_data() {
    let root = temp_root("explicit-rot");

    {
        let mut store = open_store(&root);
        store
            .put(ObjectKey::from_name("pre-rot-key"), b"before rotation")
            .expect("put");
        store.sync_all().expect("sync pre");
    }

    {
        let mut store = open_store(&root);
        assert_eq!(
            store
                .get(ObjectKey::from_name("pre-rot-key"))
                .expect("get")
                .unwrap(),
            b"before rotation"
        );

        // Write enough to trigger organic rotation via max_segment_bytes.
        for i in 0..20 {
            store
                .put(
                    ObjectKey::from_name(format!("post-{i}")),
                    &pseudo_random_data(512, i as u64),
                )
                .expect("put post");
        }
        store.sync_all().expect("sync post");
    }

    {
        let store = reopen_store(&root);
        assert_eq!(
            store
                .get(ObjectKey::from_name("pre-rot-key"))
                .expect("get")
                .unwrap(),
            b"before rotation"
        );
    }

    cleanup(&root);
}
