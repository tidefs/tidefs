// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::fs;
use std::path::PathBuf;
use tidefs_erasure_coded_store::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tidefs-ec-pr-{label}-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn make_paths(n: usize, label: &str) -> Vec<PathBuf> {
    (0..n).map(|i| temp_dir(&format!("{label}-r{i}"))).collect()
}

fn cleanup_dirs(dirs: &[PathBuf]) {
    for d in dirs {
        let _ = fs::remove_dir_all(d);
    }
}

fn ec_config(
    data_shards: usize,
    parity_shards: usize,
    shard_len: usize,
) -> ErasureCodedStoreConfig {
    ErasureCodedStoreConfig {
        data_shards,
        parity_shards,
        shard_len,
        store_options: tidefs_local_object_store::StoreOptions::test_fast(),
        failure_domain: None,
        device_candidates: None,
    }
}

/// Drop (delete) all shards from the specified store indices.
fn drop_stores(store: &mut ErasureCodedStore, indices: &[usize]) {
    for &idx in indices {
        let all_keys: Vec<_> = store.stores[idx].list_keys();
        for k in &all_keys {
            store.stores[idx].delete(*k).unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// k=2, m=1 (3 stores): drop 1 of 3 -> reconstruct succeeds
// ---------------------------------------------------------------------------

#[test]
fn k2_m1_drop_any_single_store_reconstructs() {
    for drop in 0..3 {
        let cfg = ec_config(2, 1, 64);
        let paths = make_paths(3, &format!("k2m1-drop{drop}"));
        let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

        let payload: Vec<u8> = (0..200).map(|i: usize| (i & 0xFF) as u8).collect();
        store.put_named("obj", &payload).unwrap();

        drop_stores(&mut store, &[drop]);

        let data = store.get_named("obj").unwrap();
        assert_eq!(
            data,
            Some(payload),
            "dropping store {drop} should still allow reconstruction with k=2,m=1"
        );

        cleanup_dirs(&paths);
    }
}

// ---------------------------------------------------------------------------
// k=2, m=1: drop 2 of 3 stores -> reconstruction fails
// ---------------------------------------------------------------------------

#[test]
fn k2_m1_drop_two_stores_fails() {
    let drops_cases: &[&[usize]] = &[&[0, 1], &[0, 2], &[1, 2]];
    for (case_idx, drops) in drops_cases.iter().enumerate() {
        let cfg = ec_config(2, 1, 64);
        let paths = make_paths(3, &format!("k2m1-fail{case_idx}"));
        let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

        store.put_named("obj", b"data").unwrap();
        drop_stores(&mut store, drops);

        let result = store.get_named("obj");
        assert!(
            result.is_err(),
            "dropping {drops:?} should fail reconstruction (only 1 survivor, need k=2)"
        );

        cleanup_dirs(&paths);
    }
}

// ---------------------------------------------------------------------------
// k=3, m=1 (4 stores): drop 1 of 4 -> succeed
// ---------------------------------------------------------------------------

#[test]
fn k3_m1_drop_single_store_reconstructs() {
    for drop in 0..4 {
        let cfg = ec_config(3, 1, 32);
        let paths = make_paths(4, &format!("k3m1-drop{drop}"));
        let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

        let payload: Vec<u8> = (0..120).map(|i: usize| (i.wrapping_mul(7)) as u8).collect();
        store.put_named("obj", &payload).unwrap();

        drop_stores(&mut store, &[drop]);

        let data = store.get_named("obj").unwrap();
        assert_eq!(
            data,
            Some(payload),
            "dropping store {drop} should still allow reconstruction with k=3,m=1"
        );

        cleanup_dirs(&paths);
    }
}

// ---------------------------------------------------------------------------
// k=3, m=1: drop 2 of 4 -> fail (1 parity can only cover 1 loss)
// ---------------------------------------------------------------------------

#[test]
fn k3_m1_drop_two_stores_fails() {
    let cfg = ec_config(3, 1, 32);
    let paths = make_paths(4, "k3m1-fail");
    let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

    store.put_named("obj", b"data-here").unwrap();
    drop_stores(&mut store, &[0, 1]);

    let result = store.get_named("obj");
    assert!(
        result.is_err(),
        "dropping 2 stores should fail with only single parity (k=3,m=1)"
    );

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// k=3, m=2 (5 stores): drop 2 of 5 -> succeed
// ---------------------------------------------------------------------------

#[test]
fn k3_m2_drop_two_stores_reconstructs() {
    // Test a few representative 2-drop patterns
    let drops_cases: &[&[usize]] = &[&[0, 1], &[0, 4], &[1, 2], &[3, 4]];
    for (case_idx, drops) in drops_cases.iter().enumerate() {
        let cfg = ec_config(3, 2, 32);
        let paths = make_paths(5, &format!("k3m2-ok{case_idx}"));
        let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

        let payload: Vec<u8> = (0..100).map(|i: usize| (i ^ (i >> 3)) as u8).collect();
        store.put_named("obj", &payload).unwrap();

        drop_stores(&mut store, drops);

        let data = store.get_named("obj").unwrap();
        assert_eq!(
            data,
            Some(payload),
            "dropping {drops:?} should still reconstruct with k=3,m=2"
        );

        cleanup_dirs(&paths);
    }
}

// ---------------------------------------------------------------------------
// k=3, m=2: drop 3 of 5 -> fail (double parity covers at most 2 losses)
// ---------------------------------------------------------------------------

#[test]
fn k3_m2_drop_three_stores_fails() {
    let cfg = ec_config(3, 2, 32);
    let paths = make_paths(5, "k3m2-fail");
    let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

    store.put_named("obj", b"too-many-lost").unwrap();
    drop_stores(&mut store, &[0, 1, 2]);

    let result = store.get_named("obj");
    assert!(
        result.is_err(),
        "dropping 3 stores should fail with double parity (k=3,m=2)"
    );

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// k=4, m=1 (5 stores): drop 1 of 5 -> succeed
// ---------------------------------------------------------------------------

#[test]
fn k4_m1_drop_single_store_reconstructs() {
    for drop in 0..5 {
        let cfg = ec_config(4, 1, 16);
        let paths = make_paths(5, &format!("k4m1-drop{drop}"));
        let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

        let payload: Vec<u8> = (0..80).map(|i: usize| (i & 0xFF) as u8).collect();
        store.put_named("obj", &payload).unwrap();

        drop_stores(&mut store, &[drop]);

        let data = store.get_named("obj").unwrap();
        assert_eq!(
            data,
            Some(payload),
            "dropping store {drop} should still reconstruct with k=4,m=1"
        );

        cleanup_dirs(&paths);
    }
}

// ---------------------------------------------------------------------------
// k=4, m=2 (6 stores): drop 2 of 6 -> succeed
// ---------------------------------------------------------------------------

#[test]
fn k4_m2_drop_two_stores_reconstructs() {
    let drops_cases: &[&[usize]] = &[&[0, 1], &[0, 5], &[2, 3], &[4, 5]];
    for (case_idx, drops) in drops_cases.iter().enumerate() {
        let cfg = ec_config(4, 2, 16);
        let paths = make_paths(6, &format!("k4m2-ok{case_idx}"));
        let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

        let payload: Vec<u8> = (0..80).map(|i: usize| (i.wrapping_mul(3)) as u8).collect();
        store.put_named("obj", &payload).unwrap();

        drop_stores(&mut store, drops);

        let data = store.get_named("obj").unwrap();
        assert_eq!(
            data,
            Some(payload),
            "dropping {drops:?} should still reconstruct with k=4,m=2"
        );

        cleanup_dirs(&paths);
    }
}

// ---------------------------------------------------------------------------
// k=4, m=2: drop 3 of 6 -> fail (double parity covers at most 2 losses)
// ---------------------------------------------------------------------------

#[test]
fn k4_m2_drop_three_stores_fails() {
    let cfg = ec_config(4, 2, 16);
    let paths = make_paths(6, "k4m2-fail");
    let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

    store.put_named("obj", b"too-many-lost-4-2").unwrap();
    drop_stores(&mut store, &[0, 1, 2]);

    let result = store.get_named("obj");
    assert!(
        result.is_err(),
        "dropping 3 stores should fail with double parity (k=4,m=2)"
    );

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// Multi-object: different objects survive different drop patterns
// ---------------------------------------------------------------------------

#[test]
fn multi_object_partial_reconstruction() {
    let cfg = ec_config(3, 2, 32);
    let paths = make_paths(5, "multiobjpr");

    let p1: Vec<u8> = b"object-one-data".to_vec();
    let p2: Vec<u8> = b"object-two-longer-data".to_vec();
    let p3: Vec<u8> = b"object-three".to_vec();
    {
        let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();
        store.put_named("one", &p1).unwrap();
        store.put_named("two", &p2).unwrap();
        store.put_named("three", &p3).unwrap();
        store.sync_all().unwrap();
    }

    // Drop store 0 - all objects should survive (4 survivors >= k=3)
    let mut s = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();
    drop_stores(&mut s, &[0]);
    assert_eq!(s.get_named("one").unwrap(), Some(p1.clone()));
    assert_eq!(s.get_named("two").unwrap(), Some(p2.clone()));
    assert_eq!(s.get_named("three").unwrap(), Some(p3.clone()));

    // Drop stores 0 and 3 - still 3 survivors = k, all should work
    let mut s = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();
    drop_stores(&mut s, &[0, 3]);
    assert_eq!(s.get_named("one").unwrap(), Some(p1.clone()));
    assert_eq!(s.get_named("two").unwrap(), Some(p2.clone()));
    assert_eq!(s.get_named("three").unwrap(), Some(p3));

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// Degraded read stats tracking
// ---------------------------------------------------------------------------

#[test]
fn degraded_read_increments_stats() {
    let cfg = ec_config(2, 1, 64);
    let paths = make_paths(3, "degstats");

    let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();
    store.put_named("s", b"stats-check").unwrap();

    // Degraded read - drop store 0
    drop_stores(&mut store, &[0]);
    let _ = store.get_named("s").unwrap();
    assert!(store.stats().degraded_reads.get() >= 1);

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// Repair restores reconstruction capability
// ---------------------------------------------------------------------------

#[test]
fn repair_restores_full_reconstruction() {
    let cfg = ec_config(3, 2, 32);
    let paths = make_paths(5, "repairrec");

    let payload: Vec<u8> = (0..200).map(|i: usize| (i & 0xFF) as u8).collect();
    let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();
    store.put_named("repairable", &payload).unwrap();
    store.sync_all().unwrap();

    // Wipe store 0
    let k0: Vec<_> = store.stores[0].list_keys();
    for k in &k0 {
        store.stores[0].delete(*k).unwrap();
    }

    // Degraded read still works (4 survivors >= k=3)
    let data = store.get_named("repairable").unwrap();
    assert_eq!(data, Some(payload.clone()));

    // Repair store 0
    let repaired = store.repair_store(0).unwrap();
    assert!(repaired >= 1, "repair should rebuild at least 1 shard");

    // Read should now be clean again
    let data = store.get_named("repairable").unwrap();
    assert_eq!(data, Some(payload));

    cleanup_dirs(&paths);
}
