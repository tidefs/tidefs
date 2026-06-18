// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Durability and integrity validation tests for `tidefs-local-object-store`.
//!
//! Covers write-then-read roundtrip correctness at canonical block sizes
//! (empty, half-page 512, full-page 4096), get_range offset verification,
//! overwrite shrink/grow semantics, and zero-filled region preservation.
//! All tests use the crate's public API with temporary directory isolation.

use std::fs;
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
        "tidefs-los-durability-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn fast_opts() -> StoreOptions {
    // Use a segment large enough for 4096+ byte payloads (test_fast's 4096-byte
    // segment only fits 3872 bytes after record overhead).
    StoreOptions {
        max_segment_bytes: 16384,
        verify_read_checksums: true,
        ..StoreOptions::test_fast()
    }
}

fn cleanup(root: &PathBuf) {
    let _ = fs::remove_dir_all(root);
}

fn open_store(root: &PathBuf) -> LocalObjectStore {
    LocalObjectStore::open_with_options(root, fast_opts()).expect("open store")
}

fn reopen_store(root: &PathBuf) -> LocalObjectStore {
    LocalObjectStore::open_with_options(root, fast_opts()).expect("reopen store")
}

/// Return a deterministic pseudo-random byte vector of `len` bytes.
fn pseudo_random_data(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(1);
        out.push((state >> 24) as u8);
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Write-then-read roundtrip at canonical block sizes
// ═══════════════════════════════════════════════════════════════════════════

/// Empty (zero-length) payload round-trips through put/get.
#[test]
fn write_read_roundtrip_empty_payload() {
    let root = temp_root("roundtrip-empty");
    let mut store = open_store(&root);

    let key = ObjectKey::from_name("empty-block");
    let stored = store.put(key, b"").expect("put empty");
    assert_eq!(stored.len, 0);

    let got = store
        .get(key)
        .expect("get empty")
        .expect("object must exist");
    assert!(got.is_empty(), "empty payload must round-trip as empty");

    // get_range on empty object
    let range = store.get_range(key, 0, 1).expect("get_range on empty");
    assert!(
        range.is_none() || range == Some(vec![]),
        "get_range on empty object should be None or empty"
    );

    cleanup(&root);
}

/// 512-byte payload round-trips byte-for-byte (unaligned / half-page).
#[test]
fn write_read_roundtrip_unaligned_512() {
    let root = temp_root("roundtrip-512");
    let mut store = open_store(&root);

    let payload = pseudo_random_data(512, 0x512_DEAD);
    let key = ObjectKey::from_name("unaligned-512");
    store.put(key, &payload).expect("put 512");

    let got = store.get(key).expect("get 512").expect("object must exist");
    assert_eq!(got.len(), 512);
    assert_eq!(
        &got, &payload,
        "512-byte payload must round-trip byte-for-byte"
    );

    // Verify at sub-offsets via get_range
    for off in &[0u64, 64, 128, 256, 384, 448] {
        let len = 32u64.min(512 - off);
        let expected = &payload[*off as usize..(*off + len) as usize];
        let range = store
            .get_range(key, *off, len)
            .expect("get_range")
            .unwrap_or_else(|| panic!("range at offset {off} should exist"));
        assert_eq!(
            &range[..],
            expected,
            "range [{off}, {}) mismatch",
            off + len
        );
    }

    cleanup(&root);
}

/// 4096-byte payload round-trips byte-for-byte (page-aligned boundary).
#[test]
fn write_read_roundtrip_page_aligned_4096() {
    let root = temp_root("roundtrip-4096");
    let mut store = open_store(&root);

    let payload = pseudo_random_data(4096, 0x4096_BEEF);
    let key = ObjectKey::from_name("page-aligned-4096");
    store.put(key, &payload).expect("put 4096");

    let got = store
        .get(key)
        .expect("get 4096")
        .expect("object must exist");
    assert_eq!(got.len(), 4096);
    assert_eq!(
        &got, &payload,
        "4096-byte payload must round-trip byte-for-byte"
    );

    // Verify at page-aligned sub-offsets
    for page in 0..4 {
        let off = page * 1024;
        let len = 256;
        let expected = &payload[off as usize..(off + len) as usize];
        let range = store
            .get_range(key, off, len)
            .expect("get_range")
            .unwrap_or_else(|| panic!("range at page {page} should exist"));
        assert_eq!(&range[..], expected, "range at {off} mismatch");
    }

    // Also verify a non-page-aligned range crosses a 4K boundary doesn't
    // apply here (4096 is the whole object), but verify offset near end
    let tail_off = 4096 - 128;
    let tail_len = 128;
    let expected_tail = &payload[tail_off as usize..];
    let tail_range = store
        .get_range(key, tail_off, tail_len)
        .expect("get_range tail")
        .expect("tail range should exist");
    assert_eq!(&tail_range[..], expected_tail, "tail range mismatch");

    cleanup(&root);
}

/// Write multiple objects at each canonical size, close, reopen, and verify
/// all survive intact.
#[test]
fn all_canonical_sizes_survive_reopen() {
    let root = temp_root("canonical-reopen");
    let sizes: &[(usize, &str)] = &[(0, "empty"), (512, "unaligned"), (4096, "aligned")];
    let mut expected: Vec<(ObjectKey, Vec<u8>)> = Vec::new();

    {
        let mut store = open_store(&root);
        for &(size, name) in sizes {
            let payload = pseudo_random_data(size, size as u64);
            let key = store
                .put(ObjectKey::from_name(name), &payload)
                .expect("put canonical size")
                .key;
            expected.push((key, payload));
        }
        store.sync_all().expect("sync before close");
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, sizes.len());
        for (key, exp_payload) in &expected {
            let got = store
                .get(*key)
                .expect("get after reopen")
                .unwrap_or_else(|| panic!("key {key} missing after reopen"));
            assert_eq!(
                &got, exp_payload,
                "payload mismatch after reopen for key {key}"
            );
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Overwrite shrink/grow semantics
// ═══════════════════════════════════════════════════════════════════════════

/// Overwriting a 4096-byte payload with a 512-byte payload (shrink) must
/// return the smaller payload on subsequent reads.
#[test]
fn overwrite_shrinks_payload_4096_to_512() {
    let root = temp_root("overwrite-shrink");
    let mut store = open_store(&root);

    let key = ObjectKey::from_name("shrink-target");
    let large = pseudo_random_data(4096, 1);
    let small = pseudo_random_data(512, 2);

    store.put(key, &large).expect("put large");
    assert_eq!(
        store
            .get(key)
            .expect("get large")
            .expect("large must exist")
            .len(),
        4096
    );

    store.put(key, &small).expect("put small (overwrite)");
    let got = store
        .get(key)
        .expect("get after shrink")
        .expect("object must exist");
    assert_eq!(got.len(), 512, "overwrite should shrink payload");
    assert_eq!(&got, &small, "shrunk payload must match the new data");

    // get_range past the new size should return truncated or None
    let beyond = store
        .get_range(key, 500, 32)
        .expect("get_range beyond new size");
    // The range 500..532 within a 512-byte object: 500..512 is valid, rest is truncated
    assert!(
        beyond.is_some(),
        "range partially within shrunk object should return available bytes"
    );
    let beyond_val = beyond.unwrap();
    assert_eq!(beyond_val.len(), 12, "range truncated at new size boundary");
    assert_eq!(&beyond_val, &small[500..512]);

    // Range entirely past the object
    let entirely_past = store.get_range(key, 512, 10).expect("get_range past end");
    assert!(
        entirely_past.is_none() || entirely_past == Some(vec![]),
        "range entirely past shrunk object should be None/empty"
    );

    cleanup(&root);
}

/// Overwriting a 512-byte payload with a 4096-byte payload (grow) must
/// return the larger payload on subsequent reads.
#[test]
fn overwrite_grows_payload_512_to_4096() {
    let root = temp_root("overwrite-grow");
    let mut store = open_store(&root);

    let key = ObjectKey::from_name("grow-target");
    let small = pseudo_random_data(512, 3);
    let large = pseudo_random_data(4096, 4);

    store.put(key, &small).expect("put small");
    assert_eq!(
        store
            .get(key)
            .expect("get small")
            .expect("small must exist")
            .len(),
        512
    );

    store.put(key, &large).expect("put large (overwrite)");
    let got = store
        .get(key)
        .expect("get after grow")
        .expect("object must exist");
    assert_eq!(got.len(), 4096, "overwrite should grow payload");
    assert_eq!(&got, &large, "grown payload must match the new data");

    // get_range into the newly grown region
    let grown_region = store
        .get_range(key, 512, 256)
        .expect("get_range in grown region")
        .expect("range in grown region should exist");
    assert_eq!(
        &grown_region[..],
        &large[512..768],
        "grown region data mismatch"
    );

    cleanup(&root);
}

/// Repeated overwrites cycling between sizes preserve the latest write.
#[test]
fn overwrite_cycle_shrink_grow_shrink() {
    let root = temp_root("overwrite-cycle");
    let mut store = open_store(&root);

    let key = ObjectKey::from_name("cycle-target");
    let v1 = pseudo_random_data(4096, 10);
    let v2 = pseudo_random_data(512, 11);
    let v3 = pseudo_random_data(2048, 12);

    store.put(key, &v1).expect("put v1 4096");
    store.put(key, &v2).expect("put v2 512");
    store.put(key, &v3).expect("put v3 2048");

    let got = store
        .get(key)
        .expect("get final")
        .expect("object must exist");
    assert_eq!(&got, &v3, "final overwrite v3 (2048) should be visible");

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Zero-filled region integrity
// ═══════════════════════════════════════════════════════════════════════════

/// A payload containing embedded zero-filled regions preserves them intact.
#[test]
fn zero_filled_region_survives_roundtrip() {
    let root = temp_root("zero-filled");
    let mut store = open_store(&root);

    // Construct payload: 128 non-zero, 128 zeros, 128 non-zero, 128 zeros, 128 non-zero
    let mut payload = Vec::with_capacity(640);
    payload.extend_from_slice(&pseudo_random_data(128, 100));
    payload.extend(std::iter::repeat_n(0u8, 128));
    payload.extend_from_slice(&pseudo_random_data(128, 101));
    payload.extend(std::iter::repeat_n(0u8, 128));
    payload.extend_from_slice(&pseudo_random_data(128, 102));

    let key = ObjectKey::from_name("zero-filled");
    store.put(key, &payload).expect("put with zeros");

    let got = store.get(key).expect("get").expect("object must exist");
    assert_eq!(got.len(), 640);
    assert_eq!(
        &got, &payload,
        "zero-filled regions must preserve exact bytes"
    );

    // Verify zero regions explicitly
    let zero_region_1 = store
        .get_range(key, 128, 128)
        .expect("get_range zero region 1")
        .expect("zero region 1 must exist");
    assert!(
        zero_region_1.iter().all(|&b| b == 0),
        "region [128, 256) must be all zeros"
    );

    let non_zero_region = store
        .get_range(key, 256, 16)
        .expect("get_range non-zero region")
        .expect("non-zero region must exist");
    assert_eq!(
        &non_zero_region[..],
        &payload[256..272],
        "non-zero region must survive adjacent zeros"
    );

    let zero_region_2 = store
        .get_range(key, 384, 128)
        .expect("get_range zero region 2")
        .expect("zero region 2 must exist");
    assert!(
        zero_region_2.iter().all(|&b| b == 0),
        "region [384, 512) must be all zeros"
    );

    cleanup(&root);
}

/// A payload that is entirely zeros round-trips correctly.
#[test]
fn entirely_zero_payload_roundtrip() {
    let root = temp_root("all-zeros");
    let mut store = open_store(&root);

    let payload = vec![0u8; 4096];
    let key = ObjectKey::from_name("all-zeros");
    store.put(key, &payload).expect("put all zeros");

    let got = store
        .get(key)
        .expect("get all zeros")
        .expect("object must exist");
    assert_eq!(got.len(), 4096);
    assert!(
        got.iter().all(|&b| b == 0),
        "all-zero payload must survive intact"
    );

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Cross-boundary get_range across block-size boundaries
// ═══════════════════════════════════════════════════════════════════════════

/// get_range that straddles a 512-byte boundary returns correct bytes.
#[test]
fn get_range_across_512_byte_boundary() {
    let root = temp_root("range-across-512");
    let mut store = open_store(&root);

    // 1024-byte payload with known pattern
    let payload = pseudo_random_data(1024, 0x1024_DEAD);
    let key = ObjectKey::from_name("boundary-target");
    store.put(key, &payload).expect("put");

    // Range that crosses 512-byte boundary: offset 480, length 64
    let range = store
        .get_range(key, 480, 64)
        .expect("get_range across 512")
        .expect("range should exist");
    assert_eq!(range.len(), 64);
    assert_eq!(
        &range[..],
        &payload[480..544],
        "cross-512-boundary range mismatch"
    );

    // Range that crosses 1024-byte boundary (right at end): offset 1000, length 32
    let range_end = store
        .get_range(key, 1000, 32)
        .expect("get_range near end")
        .expect("range should exist");
    assert_eq!(range_end.len(), 24, "range truncated at end of object");
    assert_eq!(&range_end[..], &payload[1000..1024]);

    cleanup(&root);
}

/// get_range across a 4096-byte page boundary (within a larger object).
#[test]
fn get_range_across_4096_byte_boundary() {
    let root = temp_root("range-across-4k");
    let mut store = open_store(&root);

    // 8192-byte payload spanning two pages
    let payload = pseudo_random_data(8192, 0x8192_BEEF);
    let key = ObjectKey::from_name("large-boundary");
    store.put(key, &payload).expect("put 8K");

    // Range that crosses the 4096-byte boundary
    let range = store
        .get_range(key, 4080, 32)
        .expect("get_range across 4K boundary")
        .expect("range should exist");
    assert_eq!(range.len(), 32);
    assert_eq!(
        &range[..],
        &payload[4080..4112],
        "cross-4K-boundary range mismatch"
    );

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. Durability: sync_all + reopen preserves all sizes
// ═══════════════════════════════════════════════════════════════════════════

/// After writing objects at each canonical size, syncing, and reopening,
/// every object must be byte-identical. This is the strongest durability
/// guarantee the store provides.
#[test]
fn durability_sync_all_preserves_all_canonical_sizes() {
    let root = temp_root("durability-sync");
    let sizes: &[(usize, &str)] = &[
        (0, "z"),
        (1, "one"),
        (511, "odd"),
        (512, "half"),
        (1024, "kilo"),
        (4095, "subpage"),
        (4096, "page"),
        (4097, "overpage"),
    ];

    let mut expected: Vec<(ObjectKey, Vec<u8>)> = Vec::new();

    {
        let mut store = open_store(&root);
        for &(size, name) in sizes {
            let payload = pseudo_random_data(size, size.wrapping_mul(7) as u64);
            let key = store
                .put(ObjectKey::from_name(name), &payload)
                .expect("put")
                .key;
            expected.push((key, payload));
        }
        store.sync_all().expect("sync_all");
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, sizes.len());
        for (key, exp) in &expected {
            let got = store
                .get(*key)
                .expect("get after reopen")
                .unwrap_or_else(|| panic!("key {key} missing after sync+reopen"));
            assert_eq!(
                &got, exp,
                "payload mismatch after sync+reopen for key {key}"
            );
        }
    }

    cleanup(&root);
}
