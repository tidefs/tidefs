//! Integration tests bridging `tidefs-extent-map` and
//! `tidefs-local-object-store`.
//!
//! These tests validate the composite storage path: extent-map allocation
//! (logical byte ranges) paired with object-store persistence, simulating
//! what the FUSE write path (#3581), writeback (#3587), and local-filesystem
//! layer do in production.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_extent_map::ExtentMap;
use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};

// ── Fixture helpers ────────────────────────────────────────────────────────

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-emap-los-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn cleanup(root: &PathBuf) {
    let _ = fs::remove_dir_all(root);
}

fn fast_opts() -> StoreOptions {
    StoreOptions {
        verify_read_checksums: false,
        max_segment_bytes: 65536,
        sync_on_write: false,
        repair_torn_tail: true,
        segment_rotation_interval_secs: u64::MAX,
        segment_rotation_write_limit: 0,
        background_scrub_interval_secs: 0,
        mirror_path: None,
        replica_paths: Vec::new(),
        fault_injection_config: None,
        reclaim_enabled: false,
        segment_count: 256,
        durability_layout: None,
        write_throttle_enabled: false,
    }
}

fn open_store(root: &PathBuf) -> LocalObjectStore {
    LocalObjectStore::open_with_options(root, fast_opts()).expect("open store")
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Extent allocation → object-store put → extent lookup round-trip
// ═══════════════════════════════════════════════════════════════════════════

/// Allocate an extent, store its payload in the object-store using a key
/// derived from the extent ID, then verify the extent map correctly
/// reports the allocated range.
#[test]
fn allocate_extent_put_data_lookup_extent() {
    let root = temp_root("emap-put-lookup");
    let mut emap = ExtentMap::new();
    let mut store = open_store(&root);

    // Allocate a 4096-byte extent at logical offset 0
    let extent_id = emap.allocate(0, 4096).expect("allocate extent");
    assert_eq!(extent_id.0, 1, "first extent ID should be 1");

    // Store the extent's data payload in the object store.
    // In production, the key would be derived from the inode + extent ID.
    let payload = vec![0xABu8; 4096];
    let obj_key = ObjectKey::from_name(format!("extent-{}", extent_id.0).as_bytes());
    store.put(obj_key, &payload).expect("put extent data");

    // Verify extent map reflects the allocation
    let entry = emap.lookup(0).expect("lookup offset 0");
    assert_eq!(entry.logical_offset, 0);
    assert_eq!(entry.length, 4096);
    assert!(
        entry.is_unwritten(),
        "extent starts unwritten (data not yet committed in extent map)"
    );

    // Verify the object store has the data
    let got = store
        .get(obj_key)
        .expect("get extent data")
        .expect("object must exist");
    assert_eq!(got, payload);

    // Verify extent count
    assert_eq!(emap.extent_count(), 1);
    assert_eq!(emap.next_extent_id().0, 2);

    store.sync_all().expect("sync");
    cleanup(&root);
}

/// Allocate multiple non-contiguous extents, store each as a separate
/// object, and verify each extent is independently retrievable from
/// both the extent map and the object store.
#[test]
fn allocate_multiple_extents_put_and_lookup_each() {
    let root = temp_root("emap-multi-extent");
    let mut emap = ExtentMap::new();
    let mut store = open_store(&root);

    let allocations = vec![
        (0u64, 4096u64, b"first-block-data".to_vec()),
        (4096, 8192, b"second-block-data-longer".to_vec()),
        (16384, 2048, b"third-block".to_vec()),
        (20480, 512, b"fourth".to_vec()),
    ];

    let mut extent_ids = Vec::new();
    for (off, len, data) in &allocations {
        let eid = emap.allocate(*off, *len).expect("allocate");
        let obj_key = ObjectKey::from_name(format!("extent-{}", eid.0).as_bytes());
        store.put(obj_key, data).expect("put extent data");
        extent_ids.push((eid, obj_key, data.clone()));
    }

    // Extent map coalesces adjacent extents; count may be less than allocations
    assert!(emap.extent_count() >= 1, "should have at least one extent");
    assert!(
        emap.extent_count() <= allocations.len(),
        "extent count should not exceed allocation count"
    );

    // Verify each extent via the extent map
    for &(off, len, _) in &allocations {
        let entry = emap.lookup(off).expect("lookup extent by offset");
        assert_eq!(entry.logical_offset, off);
        assert_eq!(entry.length, len);
    }

    // Verify each extent via the object store
    for (eid, obj_key, expected) in &extent_ids {
        let got = store
            .get(*obj_key)
            .expect("get")
            .expect("object must exist");
        assert_eq!(&got, expected, "extent {}: data mismatch", eid.0);
    }

    // lookup_range should return all extents for a broad range
    let all = emap.lookup_range(0, 25000).expect("lookup_range");
    // lookup_range returns coalesced extents, count may be less
    assert!(
        !all.is_empty() && all.len() <= allocations.len(),
        "lookup_range returned {} extents, expected between 1 and {}",
        all.len(),
        allocations.len()
    );

    store.sync_all().expect("sync");
    cleanup(&root);
}

/// Free an extent, verify the extent map reports a hole at that
/// offset, and that the object store still contains the data
/// (physical deletion is a separate compaction concern).
#[test]
fn free_extent_creates_hole_object_store_data_survives() {
    let root = temp_root("emap-free-hole");
    let mut emap = ExtentMap::new();
    let mut store = open_store(&root);

    // Allocate and store
    let eid = emap.allocate(0, 4096).expect("allocate");
    let obj_key = ObjectKey::from_name(format!("extent-{}", eid.0).as_bytes());
    let payload = vec![0x7Eu8; 4096];
    store.put(obj_key, &payload).expect("put data");

    // Free the extent
    emap.free(eid).expect("free extent");

    // Extent map should report no extent at offset 0
    assert!(
        emap.lookup(0).is_none(),
        "freed extent should be gone from map"
    );

    // Object store still has the data (physical deletion is separate)
    let got = store.get(obj_key).expect("get after free");
    assert_eq!(got, Some(payload), "physical data survives logical free");

    cleanup(&root);
}

/// Punch a hole in the middle of two extents, verify extent splitting.
#[test]
fn punch_hole_splits_extents() {
    let root = temp_root("emap-punch-split");
    let mut emap = ExtentMap::new();
    let mut store = open_store(&root);

    // Allocate a large extent spanning 0..16384
    let eid = emap.allocate(0, 16384).expect("allocate large extent");
    let payload = vec![0x42u8; 16384];
    let obj_key = ObjectKey::from_name(format!("extent-{}", eid.0).as_bytes());
    store.put(obj_key, &payload).expect("put large extent");

    // Punch a hole from 4096..8192
    emap.punch_range(4096, 4096).expect("punch hole");

    // Before the hole: extent at 0..4096 should exist
    let entry_before = emap.lookup(0).expect("entry before hole");
    assert_eq!(entry_before.logical_offset, 0);
    assert_eq!(entry_before.length, 4096);

    // Inside the hole: no extent
    assert!(emap.lookup(5000).is_none(), "hole at 5000");

    // After the hole: extent at 8192..16384 should exist
    let entry_after = emap.lookup(10000).expect("entry after hole");
    assert_eq!(entry_after.logical_offset, 8192);
    assert_eq!(entry_after.length, 8192);

    // Total extent count now: 2
    assert_eq!(emap.extent_count(), 2);

    // Object store still holds the original full payload
    let got = store.get(obj_key).expect("get after punch");
    assert_eq!(got, Some(payload));

    store.sync_all().expect("sync");
    cleanup(&root);
}

/// Serialize an extent map to a buffer, deserialize it, and verify
/// all extents and their IDs are preserved. Then verify the object
/// store data survives a close+reopen cycle.
#[test]
fn extent_map_serialize_round_trip_with_object_store_reopen() {
    let root = temp_root("emap-serde-reopen");
    let mut emap = ExtentMap::new();
    let mut store = open_store(&root);

    // Allocate several extents with data
    let extents = vec![(0u64, 2048u64), (2048, 4096), (8192, 1024)];
    let mut keys_and_data = Vec::new();
    for (off, len) in &extents {
        let eid = emap.allocate(*off, *len).expect("allocate");
        let data = vec![(*off % 251) as u8; *len as usize];
        let obj_key = ObjectKey::from_name(format!("extent-{}", eid.0).as_bytes());
        store.put(obj_key, &data).expect("put data");
        keys_and_data.push((eid, obj_key, data));
    }

    // Serialize extent map
    let mut buf = Vec::new();
    emap.serialize(&mut buf).expect("serialize");

    // Deserialize into a new extent map
    let emap2 = ExtentMap::deserialize(&mut buf.as_slice()).expect("deserialize");
    // Adjacent extents coalesce: (0,2048)+(2048,4096) merge, (8192,1024) separate
    assert!(
        emap2.extent_count() >= 1 && emap2.extent_count() <= extents.len(),
        "deserialized extent count {} should be between 1 and {}",
        emap2.extent_count(),
        extents.len()
    );

    // Verify each extent is visible in the deserialized map
    for (off, len) in &extents {
        let entry = emap2.lookup(*off).expect("lookup after deserialize");
        assert_eq!(entry.logical_offset, *off);
        assert_eq!(entry.length, *len);
    }

    // Sync and reopen the object store
    store.sync_all().expect("sync");
    drop(store);

    let store2 = open_store(&root);
    for (_eid, obj_key, expected) in &keys_and_data {
        let got = store2
            .get(*obj_key)
            .expect("get after reopen")
            .expect("object must exist");
        assert_eq!(
            &got, expected,
            "data mismatch after extent map serde + store reopen"
        );
    }

    cleanup(&root);
}

/// Stress test: allocate many extents, store many objects, then
/// verify both the extent map and object store are consistent.
#[test]
fn stress_many_extents_and_objects() {
    let root = temp_root("emap-stress");
    let mut emap = ExtentMap::new();
    let mut store = open_store(&root);

    let count = 64;
    let _stride = 4096u64;
    let mut total_offset = 0u64;
    let mut extent_ids = Vec::new();

    for i in 0..count {
        let len = if i % 3 == 0 { 8192 } else { 4096 };
        let eid = emap.allocate(total_offset, len).expect("allocate");
        let data = vec![(i % 256) as u8; len as usize];
        let obj_key = ObjectKey::from_name(format!("stress-extent-{}", eid.0).as_bytes());
        store.put(obj_key, &data).expect("put");
        extent_ids.push((eid, obj_key, data, total_offset, len));
        total_offset += len;
    }

    // All consecutive allocations coalesce into fewer extents
    assert!(
        emap.extent_count() >= 1 && emap.extent_count() <= count as usize,
        "extent count {} should be between 1 and {}",
        emap.extent_count(),
        count
    );

    // Verify each extent in both systems
    for (eid, obj_key, expected_data, off, len) in &extent_ids {
        let entry = emap.lookup(*off).expect("lookup");
        assert_eq!(entry.length, *len);

        let got = store
            .get(*obj_key)
            .expect("get")
            .expect("object must exist");
        assert_eq!(&got, expected_data, "extent {}: data mismatch", eid.0);
    }

    // Full range lookup
    let all = emap.lookup_range(0, total_offset).expect("lookup_range");
    // Consecutive allocations coalesce, count may be less
    assert!(
        !all.is_empty() && all.len() <= count as usize,
        "lookup_range returned {} extents, expected between 1 and {}",
        all.len(),
        count
    );

    // After sync + reopen, all objects survive
    store.sync_all().expect("sync");
    drop(store);

    let store2 = open_store(&root);
    for (_eid, obj_key, expected, _off, _len) in &extent_ids {
        let got = store2
            .get(*obj_key)
            .expect("get after reopen")
            .expect("must exist");
        assert_eq!(&got, expected);
    }

    cleanup(&root);
}
