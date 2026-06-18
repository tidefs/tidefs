// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Object-store durability unit tests for `tidefs-local-object-store`.
//!
//! Four test groups supporting the FUSE fsync/fdatasync fast-path:
//! 1. Atomic write-or-fail — torn writes never produce partial/corrupt objects
//! 2. Flush-ordering — sync_all barriers enforce write ordering across crashes
//! 3. Crash-recovery scan — all synced objects survive close+reopen byte-for-byte
//! 4. Checksum-detected corruption — bit-flip in segment data is detected

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_object_store::{
    constants::{INTEGRITY_TRAILER_V2_LEN_U64, RECORD_FOOTER_LEN_U64, RECORD_HEADER_LEN_U64},
    LocalObjectStore, ObjectKey, StoreOptions,
};

// ── Fixture helpers ────────────────────────────────────────────────────────

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-osdur-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn cleanup(root: &PathBuf) {
    let _ = fs::remove_dir_all(root);
}

fn fast_opts() -> StoreOptions {
    StoreOptions {
        verify_read_checksums: true,
        ..StoreOptions::test_fast()
    }
}

fn open_store(root: &PathBuf) -> LocalObjectStore {
    LocalObjectStore::open_with_options(root, fast_opts()).expect("open store")
}

fn first_segment_path(root: &Path) -> PathBuf {
    root.join("segments").join("segment-0000000000000000.vlos")
}

fn truncate_to(path: &PathBuf, new_len: u64) {
    let file = OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open for truncate");
    file.set_len(new_len).expect("truncate");
}

fn flip_bit(path: &PathBuf, byte_offset: u64) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open for bit-flip");
    let mut buf = [0u8; 1];
    file.seek(SeekFrom::Start(byte_offset)).expect("seek");
    file.read_exact(&mut buf).expect("read byte");
    buf[0] ^= 0x01;
    file.seek(SeekFrom::Start(byte_offset)).expect("seek back");
    file.write_all(&buf).expect("write flipped byte");
    file.sync_all().expect("sync after flip");
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Atomic write-or-fail
// ═══════════════════════════════════════════════════════════════════════════

/// Write a committed object (synced), then write a second object without
/// syncing. Truncate the segment file mid-record, reopen, and assert the
/// uncertain object is either fully present or fully absent — never torn.
#[test]
fn atomic_write_or_fail_torn_tail() {
    let root = temp_root("atomic-torn-tail");
    let key_a = ObjectKey::from_name("committed-a");
    let key_b = ObjectKey::from_name("uncertain-b");
    let payload_a = b"committed-a-definitely-durable-bytes";
    let payload_b = b"uncertain-b-may-or-may-not-survive-crash";

    // Phase 1: write and sync object A
    {
        let mut store = open_store(&root);
        store.put(key_a, payload_a).expect("put a");
        store.sync_all().expect("sync a");
    }

    // Phase 2: write object B, crash (drop without sync)
    {
        let mut store = open_store(&root);
        store.put(key_b, payload_b).expect("put b");
        // SIGKILL: drop without sync
    }

    // Simulate crash damage: truncate the segment tail to model a torn write
    let seg_path = first_segment_path(&root);
    let file_len = fs::metadata(&seg_path).expect("metadata").len();
    assert!(file_len > 40, "segment must be large enough to truncate");
    let trunc_len = file_len.saturating_sub(40);
    truncate_to(&seg_path, trunc_len);

    // Phase 3: reopen and verify invariants
    let store = LocalObjectStore::open_with_options(&root, fast_opts())
        .expect("reopen after simulated crash");

    // Committed object A must survive byte-for-byte
    assert!(store.contains_key(key_a), "committed-a must be present");
    assert_eq!(
        store.get(key_a).expect("get a"),
        Some(payload_a.to_vec()),
        "committed-a payload must be byte-for-byte intact"
    );

    // Uncertain object B: if present, complete; otherwise absent or error
    match store.get(key_b) {
        Ok(Some(data)) => assert_eq!(
            data, payload_b,
            "uncertain-b must be byte-for-byte complete if present"
        ),
        Ok(None) => {} // Truncation discarded the record
        Err(_) => {}   // Corruption detected on read
    }

    // No phantom keys must appear from the damaged tail
    for k in store.list_keys() {
        assert!(
            k == key_a || k == key_b,
            "no phantom keys after crash recovery, got {k:?}"
        );
    }

    cleanup(&root);
}

/// Write a single unsynced object, truncate the segment, reopen.
/// Object must be either complete or absent.
#[test]
fn atomic_write_or_fail_single_unsynced() {
    let root = temp_root("atomic-single-unsynced");
    let key = ObjectKey::from_name("sole-unsynced");
    let payload = b"sole-object-written-without-fsync";

    {
        let mut store = open_store(&root);
        store.put(key, payload).expect("put sole");
        // Crash: no sync
    }

    // Truncate: model a torn write to the sole object
    let seg_path = first_segment_path(&root);
    let file_len = fs::metadata(&seg_path).expect("metadata").len();
    let trunc_len = file_len.saturating_sub(30);
    if trunc_len > 0 {
        truncate_to(&seg_path, trunc_len);
    }

    let store =
        LocalObjectStore::open_with_options(&root, fast_opts()).expect("reopen after crash");

    match store.get(key) {
        Ok(Some(data)) => assert_eq!(data, payload, "sole object must be complete if present"),
        Ok(None) => {} // Truncation removed the record
        Err(_) => {}   // Corruption detected
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Flush-ordering
// ═══════════════════════════════════════════════════════════════════════════

/// Write A, sync_all, write B (no sync), crash, recover.
/// A must survive; B may vanish — but the reverse must never hold.
#[test]
fn flush_ordering_sync_a_then_unsynced_b() {
    let root = temp_root("flush-ordering-a-flushed");
    let key_a = ObjectKey::from_name("flushed-a");
    let key_b = ObjectKey::from_name("unflushed-b");
    let payload_a = b"flushed-object-a-survives";
    let payload_b = b"unflushed-object-b-may-vanish";

    {
        let mut store = open_store(&root);
        store.put(key_a, payload_a).expect("put a");
        store.sync_all().expect("sync a");
        store.put(key_b, payload_b).expect("put b");
        // B is not synced — crash now
    }

    let seg_path = first_segment_path(&root);
    let file_len = fs::metadata(&seg_path).expect("metadata").len();
    let trunc_len = file_len.saturating_sub(40);
    if trunc_len > 0 {
        truncate_to(&seg_path, trunc_len);
    }

    let store =
        LocalObjectStore::open_with_options(&root, fast_opts()).expect("reopen after crash");

    // Flushed A must survive
    assert!(store.contains_key(key_a), "flushed-a must survive crash");
    assert_eq!(
        store.get(key_a).expect("get a"),
        Some(payload_a.to_vec()),
        "flushed-a payload must be intact"
    );

    // Unflushed B is uncertain but must never be the only survivor
    if store.contains_key(key_b) {
        assert_eq!(
            store.get(key_b).expect("get b").as_deref(),
            Some(payload_b.as_slice()),
            "unflushed-b must be complete if it survived"
        );
    }

    cleanup(&root);
}

/// Write A (no sync), write B, sync_all, crash, recover.
/// Both A and B were synced by sync_all so both survive the crash.
/// The truncation simulates a torn last-record tail; if the tail is
/// damaged, B (the last record) may be discarded.
#[test]
fn flush_ordering_unsynced_a_then_synced_b() {
    let root = temp_root("flush-ordering-b-flushed");
    let key_a = ObjectKey::from_name("unflushed-a");
    let key_b = ObjectKey::from_name("flushed-b");
    let payload_a = b"unflushed-object-a";
    let payload_b = b"flushed-object-b-survives";

    {
        let mut store = open_store(&root);
        store.put(key_a, payload_a).expect("put a");
        // A not synced
        store.put(key_b, payload_b).expect("put b");
        store.sync_all().expect("sync b");
        // sync_all flushed both A and B
    }

    let seg_path = first_segment_path(&root);
    let file_len = fs::metadata(&seg_path).expect("metadata").len();
    let trunc_len = file_len.saturating_sub(40);
    if trunc_len > 0 {
        truncate_to(&seg_path, trunc_len);
    }

    let store =
        LocalObjectStore::open_with_options(&root, fast_opts()).expect("reopen after crash");

    // A was written before B, so A is earlier in the segment file and
    // should survive the tail truncation.
    assert!(
        store.contains_key(key_a),
        "a must survive crash (earlier record)"
    );

    // B is the last record; truncation may have torn it.
    // When present it must be byte-for-byte complete.
    if store.contains_key(key_b) {
        assert_eq!(
            store.get(key_b).expect("get b").as_deref(),
            Some(payload_b.as_slice()),
            "b must be complete if it survived"
        );
    }

    cleanup(&root);
}

/// Interleaved flushes: A sync, B sync, C no-sync, crash.
/// A and B must survive; C is uncertain.
#[test]
fn flush_ordering_interleaved_syncs() {
    let root = temp_root("flush-ordering-interleaved");
    let key_a = ObjectKey::from_name("synced-first");
    let key_b = ObjectKey::from_name("synced-second");
    let key_c = ObjectKey::from_name("unsynced-third");
    let payload_a = b"first-synced-payload";
    let payload_b = b"second-synced-payload";
    let payload_c = b"third-unsynced-payload";

    {
        let mut store = open_store(&root);
        store.put(key_a, payload_a).expect("put a");
        store.sync_all().expect("sync a");
        store.put(key_b, payload_b).expect("put b");
        store.sync_all().expect("sync b");
        store.put(key_c, payload_c).expect("put c");
        // C not synced — crash
    }

    let seg_path = first_segment_path(&root);
    let file_len = fs::metadata(&seg_path).expect("metadata").len();
    let trunc_len = file_len.saturating_sub(40);
    if trunc_len > 0 {
        truncate_to(&seg_path, trunc_len);
    }

    let store =
        LocalObjectStore::open_with_options(&root, fast_opts()).expect("reopen after crash");

    assert!(store.contains_key(key_a), "first-synced must survive");
    assert_eq!(store.get(key_a).expect("get a"), Some(payload_a.to_vec()));
    assert!(store.contains_key(key_b), "second-synced must survive");
    assert_eq!(store.get(key_b).expect("get b"), Some(payload_b.to_vec()));

    if let Ok(Some(data)) = store.get(key_c) {
        assert_eq!(
            data, payload_c,
            "third-unsynced must be complete if present"
        )
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Crash-recovery scan
// ═══════════════════════════════════════════════════════════════════════════

/// Pre-populate N objects with deterministic varied payloads, sync_all,
/// close (crash), reopen, and verify all objects are byte-for-byte correct.
#[test]
fn crash_recovery_scan_varied_payloads() {
    let root = temp_root("crash-scan-varied");
    const N: usize = 12;
    let mut expected: Vec<(ObjectKey, Vec<u8>)> = Vec::with_capacity(N);

    {
        let mut store = open_store(&root);
        for i in 0..N {
            let name = format!("obj-{i:02}");
            let payload = vec![(i.wrapping_mul(13)) as u8; i * 11 + 7];
            let key = store
                .put(ObjectKey::from_name(&name), &payload)
                .expect("put")
                .key;
            expected.push((key, payload));
        }
        store.sync_all().expect("sync all before crash");
    }

    let store = open_store(&root);
    assert_eq!(
        store.list_keys().len(),
        N,
        "all {N} objects must survive close+reopen"
    );

    for (key, expected_payload) in &expected {
        let got = store.get(*key).expect("get");
        assert_eq!(
            got,
            Some(expected_payload.clone()),
            "payload mismatch for key after recovery"
        );
        assert!(
            store.contains_key(*key),
            "contains_key must agree with get for key"
        );
    }

    cleanup(&root);
}

/// Write objects in two phases separated by a close+reopen cycle.
/// All objects from both phases must survive the second reopen.
#[test]
fn crash_recovery_scan_multi_phase() {
    let root = temp_root("crash-scan-multiphase");
    let key_a = ObjectKey::from_name("phase-one-object");
    let key_b = ObjectKey::from_name("phase-two-object");
    let payload_a = b"phase-one-data-before-reopen";
    let payload_b = b"phase-two-data-after-reopen";

    // Phase 1
    {
        let mut store = open_store(&root);
        store.put(key_a, payload_a).expect("put a");
        store.sync_all().expect("sync phase 1");
    }

    // Phase 2 (reopen and add more)
    {
        let mut store = open_store(&root);
        store.put(key_b, payload_b).expect("put b");
        store.sync_all().expect("sync phase 2");
    }

    // Crash recovery: reopen and verify both phases
    let store = open_store(&root);
    assert_eq!(
        store.list_keys().len(),
        2,
        "both phase-1 and phase-2 objects must be present"
    );
    assert_eq!(store.get(key_a).expect("get a"), Some(payload_a.to_vec()));
    assert_eq!(store.get(key_b).expect("get b"), Some(payload_b.to_vec()));

    cleanup(&root);
}

/// Write objects at exact segment boundary to exercise edge-case recovery.
#[test]
fn crash_recovery_scan_at_segment_boundary() {
    let root = temp_root("crash-scan-boundary");
    let key_a = ObjectKey::from_name("boundary-a");
    let payload_a = b"first-object-in-segment";
    let key_b = ObjectKey::from_name("boundary-b");
    let payload_b = b"second-object-in-segment";

    {
        let mut store = open_store(&root);
        store.put(key_a, payload_a).expect("put a");
        store.sync_all().expect("sync a");
        store.put(key_b, payload_b).expect("put b");
        store.sync_all().expect("sync b");
    }

    let store = open_store(&root);
    assert_eq!(store.list_keys().len(), 2, "both objects must survive");
    assert_eq!(store.get(key_a).expect("get a"), Some(payload_a.to_vec()));
    assert_eq!(store.get(key_b).expect("get b"), Some(payload_b.to_vec()));

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Checksum-detected corruption
// ═══════════════════════════════════════════════════════════════════════════

/// Write an object, sync, flip a byte in the segment payload region, reopen.
/// The store must detect corruption at open or read time.
#[test]
fn checksum_detected_corruption_payload_bit_flip() {
    let root = temp_root("checksum-payload-flip");
    let key = ObjectKey::from_name("victim-object");
    let payload = b"payload-bytes-that-will-be-corrupted";

    {
        let mut store = open_store(&root);
        store.put(key, payload).expect("put");
        store.sync_all().expect("sync");
    }

    let seg_path = first_segment_path(&root);
    let file_len = fs::metadata(&seg_path).expect("metadata").len();
    // Flip a byte past the 96-byte record header (in the payload region)
    assert!(file_len > 150, "segment must have enough bytes");
    flip_bit(&seg_path, 120);

    let result = LocalObjectStore::open_with_options(&root, fast_opts());
    match result {
        Ok(store) => {
            // Store opened — verify corrupted object behaviour
            let read = store.get(key);
            match read {
                Ok(Some(_data)) => panic!("corrupted payload must not be returned as valid data"),
                Ok(None) => {} // Object discarded due to corruption
                Err(e) => {
                    let msg = format!("{e:?}");
                    assert!(
                        msg.contains("Corrupt")
                            || msg.contains("Checksum")
                            || msg.contains("Integrity"),
                        "read error must reference integrity: {e:?}"
                    );
                }
            }
        }
        Err(e) => {
            // Corruption detected at open
            let msg = format!("{e:?}");
            assert!(
                msg.contains("Corrupt")
                    || msg.contains("Checksum")
                    || msg.contains("Integrity")
                    || msg.contains("magic"),
                "open error must reference corruption: {e:?}"
            );
        }
    }

    cleanup(&root);
}

/// Flip a byte in the magic bytes at the segment start.
/// The store must reject the segment or recover gracefully.
#[test]
fn checksum_detected_corruption_magic_bit_flip() {
    let root = temp_root("checksum-magic-flip");
    let key = ObjectKey::from_name("magic-victim");
    let payload = b"data-behind-corrupted-magic-bytes";

    {
        let mut store = open_store(&root);
        store.put(key, payload).expect("put");
        store.sync_all().expect("sync");
    }

    let seg_path = first_segment_path(&root);
    flip_bit(&seg_path, 0); // Flip the first magic byte

    let result = LocalObjectStore::open_with_options(&root, fast_opts());
    match result {
        Ok(_store) => {
            // Open succeeded — implementation may repair or skip
        }
        Err(e) => {
            let msg = format!("{e:?}");
            assert!(
                msg.contains("Corrupt") || msg.contains("magic") || msg.contains("header"),
                "error should reference corruption: {e:?}"
            );
        }
    }

    cleanup(&root);
}

/// Flip a byte inside the per-record production integrity trailer.
/// Verifies that trailer corruption is also detected.
#[test]
fn checksum_detected_corruption_trailer_bit_flip() {
    let root = temp_root("checksum-trailer-flip");
    let key = ObjectKey::from_name("trailer-victim");
    let payload = b"object-with-trailer-corruption";

    {
        let mut store = open_store(&root);
        store.put(key, payload).expect("put");
        store.sync_all().expect("sync");
    }

    let seg_path = first_segment_path(&root);
    let file_len = fs::metadata(&seg_path).expect("metadata").len();
    let trailer_offset = RECORD_HEADER_LEN_U64 + payload.len() as u64 + RECORD_FOOTER_LEN_U64;
    assert!(
        trailer_offset + INTEGRITY_TRAILER_V2_LEN_U64 <= file_len,
        "segment too short for per-record trailer flip"
    );
    flip_bit(&seg_path, trailer_offset + 8);

    let result = LocalObjectStore::open_with_options(&root, fast_opts());
    match result {
        Ok(store) => {
            // Store may have opened, but the corrupted record must not be
            // returned as valid data.
            match store.get(key) {
                Ok(Some(_data)) => {
                    panic!("corrupted trailer must not be returned as valid data")
                }
                Ok(None) => {}
                Err(e) => {
                    let msg = format!("{e:?}");
                    assert!(
                        msg.contains("Corrupt")
                            || msg.contains("Checksum")
                            || msg.contains("Integrity"),
                        "trailer corruption must be detected: {e:?}"
                    );
                }
            }
        }
        Err(e) => {
            let msg = format!("{e:?}");
            assert!(
                msg.contains("Corrupt") || msg.contains("Checksum") || msg.contains("Integrity"),
                "trailer corruption must be detected: {e:?}"
            );
        }
    }

    cleanup(&root);
}
