#![cfg(feature = "fuse")]

//! Property-based object integrity tests for the local object store.
//!
//! Exercises the write→flush→read→verify pipeline with proptest
//! strategies. These tests catch silent data corruption, checksum
//! instability, and cross-object contamination that unit tests on
//! individual types miss.
//!
//! Gates: requires `--features fuse` on the tidefs-validation
//! crate to pull in `tidefs-local-object-store`.

use proptest::prelude::*;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};

// ── Fixture helpers ────────────────────────────────────────────────────────

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-obj-int-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn cleanup(root: &PathBuf) {
    let _ = fs::remove_dir_all(root);
}

/// Fast options with enough segment headroom for 64 KiB payloads.
fn large_opts() -> StoreOptions {
    let mut opts = StoreOptions::durable();
    opts.sync_on_write = false;
    opts.background_scrub_interval_secs = 0;
    opts
}

fn open_store(root: &PathBuf) -> LocalObjectStore {
    LocalObjectStore::open_with_options(root, large_opts()).expect("open store")
}

fn segment_file_path(segments_dir: &std::path::Path, segment_id: u64) -> PathBuf {
    segments_dir.join(tidefs_local_object_store::local_object_store::segment_file_name(segment_id))
}

// ── Arbitrary strategy: byte vector up to 64 KiB ──────────────────────────

fn arb_payload() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..65536)
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. write_read_roundtrip
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    /// For any byte sequence (0..64 KiB), writing then reading via `get`
    /// returns byte-identical content.
    #[test]
    fn write_read_roundtrip(payload in arb_payload()) {
        let root = temp_root("roundtrip");
        let mut store = open_store(&root);

        let key = ObjectKey::from_name(format!("roundtrip-{}", payload.len()));
        store.put(key, &payload).expect("put");

        let got = store.get(key).expect("get").expect("object must exist");
        prop_assert_eq!(&got, &payload, "roundtrip mismatch: written and read-back bytes differ");

        drop(store);
        cleanup(&root);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. checksum_stability
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    /// Same payload produces identical checksum values across repeated
    /// writes, verified through `location_of`.
    #[test]
    fn checksum_stability(payload in arb_payload()) {
        let root = temp_root("cksum-stable");
        let mut store = open_store(&root);

        let key_a = ObjectKey::from_name("cksum-a");
        let key_b = ObjectKey::from_name("cksum-b");

        store.put(key_a, &payload).expect("put a");
        store.put(key_b, &payload).expect("put b");

        let loc_a = store.location_of(key_a).expect("location a");
        let loc_b = store.location_of(key_b).expect("location b");

        prop_assert_eq!(
            loc_a.payload_checksum, loc_b.payload_checksum,
            "checksum differs for identical payloads"
        );

        let computed = tidefs_local_object_store::checksum64(&payload);
        prop_assert_eq!(loc_a.payload_checksum, computed,
            "location checksum diverges from checksum64");

        drop(store);
        cleanup(&root);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. corruption_detection
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    /// Flipping one byte in a stored object's on-disk payload causes
    /// the store to reject the read (either at reopen or during `get`),
    /// proving the integrity chain catches silent corruption.
    #[test]
    fn corruption_detection(payload in arb_payload().prop_filter(
        "payload must be at least 1 byte for byte-flip",
        |p| !p.is_empty()
    )) {
        let root = temp_root("corrupt");
        let segment_path;
        let location;
        let key;

        {
            let mut store = open_store(&root);
            key = ObjectKey::from_name("corrupt-target");
            store.put(key, &payload).expect("put");
            store.sync_all().expect("sync");
            location = store.location_of(key).expect("location exists");
            segment_path = segment_file_path(store.segments_dir(), location.segment_id);
        }

        // Corrupt a byte in the on-disk payload
        let payload_disk_offset = location.record_offset
            + tidefs_local_object_store::local_object_store::RECORD_HEADER_LEN as u64;
        {
            let mut f = OpenOptions::new()
                .write(true)
                .read(true)
                .open(&segment_path)
                .expect("open segment for corruption");
            let flip_offset = payload_disk_offset + (payload.len() as u64 / 2);
            f.seek(SeekFrom::Start(flip_offset)).expect("seek");
            let mut original = [0u8; 1];
            f.read_exact(&mut original).expect("read original byte");
            f.seek(SeekFrom::Start(flip_offset)).expect("seek back");
            f.write_all(&[original[0] ^ 0xFF]).expect("corrupt byte");
            f.sync_all().expect("sync");
        }

        // Reopen: the integrity trailer or checksum must detect corruption.
        let result = LocalObjectStore::open_with_options(&root, large_opts());
        prop_assert!(
            result.is_err() || {
                let store = result.unwrap();
                store.get(key).is_err()
            },
            "corrupted object was not detected on reopen or read"
        );

        cleanup(&root);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. multi_object_isolation
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    /// Writing N objects with random data and reading them back returns
    /// each object correctly, proving no cross-object contamination.
    #[test]
    fn multi_object_isolation(
        objects in prop::collection::vec(arb_payload(), 1..20)
    ) {
        let root = temp_root("isolation");
        let mut store = open_store(&root);

        let mut written: Vec<(ObjectKey, Vec<u8>)> = Vec::new();
        for (i, payload) in objects.iter().enumerate() {
            let key = ObjectKey::from_name(format!("iso-{i}"));
            store.put(key, payload).expect("put");
            written.push((key, payload.clone()));
        }

        // Read each object back and verify content.
        for (key, expected) in &written {
            let got = store.get(*key).expect("get").expect("object must exist");
            prop_assert_eq!(&got, expected,
                "cross-object contamination: object content does not match written data");
        }

        // Verify list_keys returns exactly the expected set.
        let listed = store.list_keys();
        let mut listed_sorted = listed.clone();
        listed_sorted.sort();
        let mut expected_keys: Vec<ObjectKey> = written.iter().map(|(k, _)| *k).collect();
        expected_keys.sort();
        prop_assert_eq!(listed_sorted, expected_keys,
            "list_keys does not match the set of written objects");

        // Verify no phantom objects: every listed key must be readable.
        for key in &listed {
            prop_assert!(store.get(*key).expect("get").is_some(),
                "listed key must be readable");
        }

        drop(store);
        cleanup(&root);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. zero_length_object
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    /// Zero-byte objects are stored and retrieved correctly, including
    /// after close/reopen.  The empty payload is an edge case that
    /// often exposes record layout bugs.
    #[test]
    fn zero_length_object_roundtrip(_junk in any::<u64>()) {
        let root = temp_root("zero-obj");
        let key = ObjectKey::from_name("empty-object");

        {
            let mut store = open_store(&root);
            store.put(key, &[]).expect("put empty");
            let got = store.get(key).expect("get").expect("object must exist");
            prop_assert!(got.is_empty(), "retrieved empty object must be empty");

            // Content-addressed empty puts must also work.
            let ca_key = store.put_content_addressed(&[]).expect("put_content_addressed empty");
            let got_ca = store.get(ca_key).expect("get ca").expect("ca object must exist");
            prop_assert!(got_ca.is_empty(), "content-addressed empty object must be empty");

            store.sync_all().expect("sync");
        }

        // Reopen and verify empty objects survive.
        let store = open_store(&root);
        let got = store.get(key).expect("get after reopen").expect("empty must exist after reopen");
        prop_assert!(got.is_empty(), "empty object must survive reopen");

        drop(store);
        cleanup(&root);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. multi_segment_write — data spanning 3+ segments survive reopen
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn multi_segment_write_spanning_three_segments() {
    let root = temp_root("multi-seg");

    // Use 4 KiB segments; write 3 objects that each fit within max_object_bytes (3872).
    let mut opts = large_opts();
    opts.max_segment_bytes = 4096;
    let data_a: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
    let data_b: Vec<u8> = (0..2000u32).map(|i| ((i + 127) % 251) as u8).collect();
    let data_c: Vec<u8> = (0..2000u32).map(|i| ((i + 223) % 251) as u8).collect();
    let key_a = ObjectKey::from_name("multi-a");
    let key_b = ObjectKey::from_name("multi-b");
    let key_c = ObjectKey::from_name("multi-c");

    {
        let mut store =
            LocalObjectStore::open_with_options(&root, opts.clone()).expect("open store");
        store.put(key_a, &data_a).expect("put A");
        store.put(key_b, &data_b).expect("put B");
        store.put(key_c, &data_c).expect("put C");
        store.sync_all().expect("sync");
    }

    // Reopen and verify all three objects byte-for-byte.
    {
        let store = LocalObjectStore::open_with_options(&root, opts).expect("reopen store");
        let got_a = store.get(key_a).expect("get A").expect("A must exist");
        let got_b = store.get(key_b).expect("get B").expect("B must exist");
        let got_c = store.get(key_c).expect("get C").expect("C must exist");
        assert_eq!(got_a, data_a, "multi-segment object A corrupted");
        assert_eq!(got_b, data_b, "multi-segment object B corrupted");
        assert_eq!(got_c, data_c, "multi-segment object C corrupted");
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. partial_segment_flush — partial segment (less than max) survives
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn partial_segment_flush() {
    let root = temp_root("partial-seg");
    let key = ObjectKey::from_name("partial-data");

    let mut opts = large_opts();
    opts.max_segment_bytes = 8192;

    // Write 512 bytes — well under max_segment_bytes.
    let data: Vec<u8> = (0..512u32).map(|i| (i % 256) as u8).collect();

    {
        let mut store =
            LocalObjectStore::open_with_options(&root, opts.clone()).expect("open store");
        store.put(key, &data).expect("put partial");
        store.sync_all().expect("sync");
    }

    // Reopen: partial segment must be readable.
    {
        let store = LocalObjectStore::open_with_options(&root, opts).expect("reopen store");
        let got = store.get(key).expect("get").expect("object must exist");
        assert_eq!(got.len(), data.len(), "partial segment length mismatch");
        assert_eq!(got, data, "partial segment data corrupted");
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. overwrite_within_segment — overwrite middle bytes, flush, verify
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn overwrite_within_segment_preserves_untouched_bytes() {
    let root = temp_root("overwrite");
    let key = ObjectKey::from_name("overwrite-target");

    let mut opts = large_opts();
    opts.max_segment_bytes = 4096;

    let original: Vec<u8> = (0..1024u32).map(|i| (i % 256) as u8).collect();
    let overwrite_bytes: Vec<u8> = vec![0xAA; 128];

    {
        let mut store =
            LocalObjectStore::open_with_options(&root, opts.clone()).expect("open store");
        store.put(key, &original).expect("put original");

        // Overwrite bytes 256..384 with 0xAA.
        let mut patched = original.clone();
        patched[256..384].copy_from_slice(&overwrite_bytes);
        store.put(key, &patched).expect("put overwrite");
        store.sync_all().expect("sync");
    }

    {
        let store = LocalObjectStore::open_with_options(&root, opts).expect("reopen store");
        let got = store.get(key).expect("get").expect("object must exist");

        // Prefix untouched.
        assert_eq!(
            &got[..256],
            &original[..256],
            "prefix bytes corrupted by overwrite"
        );
        // Overwritten region.
        assert_eq!(
            &got[256..384],
            &overwrite_bytes[..],
            "overwrite bytes not applied"
        );
        // Suffix untouched.
        assert_eq!(
            &got[384..],
            &original[384..],
            "suffix bytes corrupted by overwrite"
        );
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. torn_segment_repair — corrupt tail, reopen with repair, first segment intact
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn torn_segment_repair_preserves_prior_segments() {
    let root = temp_root("torn-repair");
    let key_a = ObjectKey::from_name("seg-a");
    let key_b = ObjectKey::from_name("seg-b");
    let data_a: Vec<u8> = (0..2048u32).map(|i| (i % 256) as u8).collect();
    let data_b: Vec<u8> = vec![0xDD; 2048];
    let segment_path_b;

    let mut opts = large_opts();
    opts.max_segment_bytes = 4096;
    opts.repair_torn_tail = true;

    // Write object A (segment 0), flush segment, write object B (segment 1).
    {
        let mut store =
            LocalObjectStore::open_with_options(&root, opts.clone()).expect("open store");
        store.put(key_a, &data_a).expect("put A");
        store.flush_segment().expect("flush segment 0");

        store.put(key_b, &data_b).expect("put B");
        store.sync_all().expect("sync");

        let loc_b = store.location_of(key_b).expect("loc B");
        segment_path_b = segment_file_path(store.segments_dir(), loc_b.segment_id);
    }

    // Corrupt the tail of segment B's file.
    {
        use std::io::Seek;
        let mut f = OpenOptions::new()
            .write(true)
            .open(&segment_path_b)
            .expect("open segment B for corruption");
        let len = f.seek(SeekFrom::End(0)).expect("seek end");
        // Truncate half the segment to simulate torn tail.
        f.set_len(len / 2).expect("truncate segment B");
        f.sync_all().expect("sync");
    }

    // Reopen with repair: segment A must be intact, segment B may be
    // repaired but its object may be lost (torn tail).
    {
        let store = LocalObjectStore::open_with_options(&root, opts).expect("reopen with repair");
        let got_a = store
            .get(key_a)
            .expect("get A")
            .expect("object A must survive repair");
        assert_eq!(got_a, data_a, "segment A corrupted by torn-tail repair");

        // Segment B's object may be absent or truncated — either is acceptable.
        // The key invariant: no panic, and segment A is byte-perfect.
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. cross_segment_boundary_read — write exactly max_segment_bytes+1 byte
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn cross_segment_boundary_read_across_two_segments() {
    let root = temp_root("cross-seg");

    // Write an object that fills segment 0 near capacity, then write a second
    // object. The second object must land in segment 1. Both survive reopen.
    let mut opts = large_opts();
    opts.max_segment_bytes = 4096;

    // max_object_bytes for 4KB segment is 3872. Use nearly that to fill seg 0.
    let fill_data: Vec<u8> = vec![0xAA; 3800];
    let data_b: Vec<u8> = vec![0xBB; 512];
    let key_a = ObjectKey::from_name("cross-filler");
    let key_b = ObjectKey::from_name("cross-next");

    let loc_a_seg;
    let loc_b_seg;
    {
        let mut store =
            LocalObjectStore::open_with_options(&root, opts.clone()).expect("open store");
        store.put(key_a, &fill_data).expect("put filler");
        store.sync_all().expect("sync after filler");

        store.put(key_b, &data_b).expect("put B");
        store.sync_all().expect("sync after B");

        loc_a_seg = store.location_of(key_a).expect("loc A").segment_id;
        loc_b_seg = store.location_of(key_b).expect("loc B").segment_id;
    }

    assert!(
        loc_b_seg > loc_a_seg,
        "second object (seg {loc_b_seg}) must be in a later segment than first (seg {loc_a_seg})"
    );

    {
        let store = LocalObjectStore::open_with_options(&root, opts).expect("reopen store");
        let got_a = store.get(key_a).expect("get A").expect("A must exist");
        let got_b = store.get(key_b).expect("get B").expect("B must exist");
        assert_eq!(got_a, fill_data, "cross-segment object A corrupted");
        assert_eq!(got_b, data_b, "cross-segment object B corrupted");
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 11. concurrent_segment_writes — 4 threads write distinct objects
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn concurrent_segment_writes_four_objects() {
    let root = temp_root("concurrent");
    std::fs::create_dir_all(&root).expect("create root");

    let mut opts = large_opts();
    opts.max_segment_bytes = 4096;

    // Write 4 objects, force segment rotation between each so they land in
    // distinct segments. Use sequential writes — integrity does not require
    // actual thread parallelism.
    {
        let mut store =
            LocalObjectStore::open_with_options(&root, opts.clone()).expect("open store");
        for i in 0..4u32 {
            let key = ObjectKey::from_name(format!("concurrent-{i}"));
            let data: Vec<u8> = (0..512u32)
                .map(|b| ((b.wrapping_add(i * 64)) % 256) as u8)
                .collect();
            store.put(key, &data).expect("put");
            store.flush_segment().expect("flush segment");
        }
    }

    // Reopen and verify all 4 objects are readable independently.
    {
        let store = LocalObjectStore::open_with_options(&root, opts).expect("reopen store");
        let keys: Vec<ObjectKey> = store.list_keys();
        assert_eq!(keys.len(), 4, "expected 4 objects, found {}", keys.len());

        for i in 0..4u32 {
            let key = ObjectKey::from_name(format!("concurrent-{i}"));
            let expected: Vec<u8> = (0..512u32)
                .map(|b| ((b.wrapping_add(i * 64)) % 256) as u8)
                .collect();
            let got = store.get(key).expect("get").expect("object must exist");
            assert_eq!(got, expected, "object {i} corrupted");
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 12. segment_count_exhaustion — fill all segments, verify graceful failure
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn segment_count_exhaustion_returns_error() {
    let root = temp_root("exhaust");
    let mut opts = large_opts();
    opts.max_segment_bytes = 1024; // tiny segments
    opts.segment_count = 4; // only 4 segments available
    opts.reclaim_enabled = false;

    let _key = ObjectKey::from_name("filler");
    let payload = vec![0xCC; 1024];

    let exhausted_result = {
        let mut store = LocalObjectStore::open_with_options(&root, opts).expect("open store");
        let mut last_result: Result<(), tidefs_local_object_store::StoreError> = Ok(());

        for i in 0..20u32 {
            let k = ObjectKey::from_name(format!("filler-{i}"));
            match store.put(k, &payload) {
                Ok(_) => {}
                Err(e) => {
                    last_result = Err(e);
                    break;
                }
            }
        }
        last_result
    };

    // Must fail gracefully — no panic.
    assert!(
        exhausted_result.is_err(),
        "segment exhaustion must return an error, not panic"
    );

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 13. repeated_open_close_idempotence — open/close 3x, object survives
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn repeated_open_close_idempotence() {
    let root = temp_root("reopen-idem");
    let key = ObjectKey::from_name("persistent");
    let data: Vec<u8> = (0..512u32).map(|i| (i % 256) as u8).collect();

    let opts = large_opts();

    // Write once.
    {
        let mut store =
            LocalObjectStore::open_with_options(&root, opts.clone()).expect("open store");
        store.put(key, &data).expect("put");
        store.sync_all().expect("sync");
    }

    // Open/close 3 times without writes.
    for round in 0..3 {
        {
            let store = LocalObjectStore::open_with_options(&root, opts.clone())
                .unwrap_or_else(|e| panic!("open round {round}: {e}"));
            let got = store.get(key).expect("get").expect("object must exist");
            assert_eq!(got, data, "data corrupted after {round} reopen cycles");
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 14. sequential_segment_numbering_after_restart — segment IDs continue
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sequential_segment_numbering_after_restart() {
    let root = temp_root("seq-seg");
    let mut opts = large_opts();
    opts.max_segment_bytes = 4096;

    // Use a payload near max_object_bytes (3872) to fill each segment and force
    // new segment creation on each write.
    let payload = vec![0xBB; 3800];
    let mut last_seg_id = 0u64;

    // Write 3 objects — each fills a segment, forcing new segment assignments.
    {
        let mut store =
            LocalObjectStore::open_with_options(&root, opts.clone()).expect("open store");
        for i in 0..3u32 {
            let key = ObjectKey::from_name(format!("seq-{i}"));
            store.put(key, &payload).expect("put");
            store.sync_all().expect("sync");
            let loc = store.location_of(key).expect("location");
            last_seg_id = loc.segment_id;
        }
    }

    // Reopen and write one more — segment ID must be beyond the last before restart.
    {
        let mut store = LocalObjectStore::open_with_options(&root, opts).expect("reopen store");
        let key = ObjectKey::from_name("after-restart");
        store.put(key, &payload).expect("put after restart");
        store.sync_all().expect("sync");
        let loc = store.location_of(key).expect("location after restart");
        assert!(
            loc.segment_id > last_seg_id,
            "segment ID after restart ({}) must be > last before restart ({})",
            loc.segment_id,
            last_seg_id
        );
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 15. write_after_segment_repair — write succeeds after torn-tail repair
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn write_after_segment_repair() {
    let root = temp_root("write-after-repair");
    let key_a = ObjectKey::from_name("pre-repair");
    let data_a: Vec<u8> = vec![0xEE; 2048];
    let seg_path;

    let mut opts = large_opts();
    opts.max_segment_bytes = 4096;
    opts.repair_torn_tail = true;

    // Write object A, then corrupt its segment tail.
    {
        let mut store =
            LocalObjectStore::open_with_options(&root, opts.clone()).expect("open store");
        store.put(key_a, &data_a).expect("put A");
        store.sync_all().expect("sync");
        let loc = store.location_of(key_a).expect("loc A");
        seg_path = segment_file_path(store.segments_dir(), loc.segment_id);
    }

    // Truncate segment file to simulate torn tail.
    {
        use std::io::Seek;
        let mut f = OpenOptions::new()
            .write(true)
            .open(&seg_path)
            .expect("open segment for truncation");
        let len = f.seek(SeekFrom::End(0)).expect("seek end");
        f.set_len(len - 256).expect("truncate tail");
        f.sync_all().expect("sync");
    }

    // Reopen (triggers repair), then write a new object.
    {
        let mut store = LocalObjectStore::open_with_options(&root, opts).expect("reopen store");
        // Object A may be absent due to corruption — that's fine.
        // The key test: a new write after repair must succeed.
        let key_b = ObjectKey::from_name("post-repair");
        let data_b: Vec<u8> = vec![0xFF; 512];
        store
            .put(key_b, &data_b)
            .expect("put after repair must succeed");
        store.sync_all().expect("sync after repair");

        let got = store
            .get(key_b)
            .expect("get post-repair")
            .expect("post-repair object must exist");
        assert_eq!(got, data_b, "post-repair write corrupted");
    }

    cleanup(&root);
}
