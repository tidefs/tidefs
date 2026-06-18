// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::fs;
use std::path::PathBuf;
use tidefs_erasure_coded_store::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tidefs-ec-ec-{label}-{}", std::process::id()));
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

// ---------------------------------------------------------------------------
// Zero-length object with k=1,m=1
// ---------------------------------------------------------------------------

#[test]
fn zero_length_k1_m1() {
    let cfg = ec_config(1, 1, 64);
    let paths = make_paths(2, "zlenk1m1");
    let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

    store.put_named("empty", b"").unwrap();
    let data = store.get_named("empty").unwrap();
    assert_eq!(data, Some(b"".to_vec()));

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// Zero-length object with k=8,m=3
// ---------------------------------------------------------------------------

#[test]
fn zero_length_k8_m3() {
    let cfg = ec_config(8, 3, 32);
    let paths = make_paths(11, "zlenk8m3");
    let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

    store.put_named("empty", b"").unwrap();
    let data = store.get_named("empty").unwrap();
    assert_eq!(data, Some(b"".to_vec()));

    // Verify it can be read even with store losses
    let s = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();
    let data = s.get_named("empty").unwrap();
    assert_eq!(data, Some(b"".to_vec()));

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// Zero-length object survives store loss (all shards identical - zeros)
// ---------------------------------------------------------------------------

#[test]
fn zero_length_survives_store_loss() {
    let cfg = ec_config(3, 2, 32);
    let paths = make_paths(5, "zlenloss");
    let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

    store.put_named("z", b"").unwrap();

    // Drop stores 0 and 1
    let k0: Vec<_> = store.stores[0].list_keys();
    for k in &k0 {
        store.stores[0].delete(*k).unwrap();
    }
    let k1: Vec<_> = store.stores[1].list_keys();
    for k in &k1 {
        store.stores[1].delete(*k).unwrap();
    }

    let data = store.get_named("z").unwrap();
    assert_eq!(data, Some(b"".to_vec()));

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// k=1,m=1 degenerate: single data + single parity
// ---------------------------------------------------------------------------

#[test]
fn k1_m1_degenerate_full_roundtrip() {
    let cfg = ec_config(1, 1, 128);
    let paths = make_paths(2, "k1m1");
    let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

    // Single-byte
    store.put_named("s", b"X").unwrap();
    assert_eq!(store.get_named("s").unwrap(), Some(b"X".to_vec()));

    // Exact shard capacity
    let payload: Vec<u8> = (0..128).map(|i| (i & 0xFF) as u8).collect();
    store.put_named("full", &payload).unwrap();
    assert_eq!(store.get_named("full").unwrap(), Some(payload.clone()));

    // Multi-stripe
    let big: Vec<u8> = (0..300).map(|i: usize| (i.wrapping_mul(7)) as u8).collect();
    store.put_named("big", &big).unwrap();
    assert_eq!(store.get_named("big").unwrap(), Some(big));

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// k=1,m=1: drop data store, reconstruct from parity
// ---------------------------------------------------------------------------

#[test]
fn k1_m1_drop_data_reconstruct_from_parity() {
    let cfg = ec_config(1, 1, 64);
    let paths = make_paths(2, "k1m1drop");
    let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

    store.put_named("p", b"parity-only-test-data").unwrap();

    // Drop store 0 (data store)
    let k0: Vec<_> = store.stores[0].list_keys();
    for k in &k0 {
        store.stores[0].delete(*k).unwrap();
    }

    let data = store.get_named("p").unwrap();
    assert_eq!(data, Some(b"parity-only-test-data".to_vec()));

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// k=1,m=1: drop parity store, read from data directly
// ---------------------------------------------------------------------------

#[test]
fn k1_m1_drop_parity_read_from_data() {
    let cfg = ec_config(1, 1, 64);
    let paths = make_paths(2, "k1m1droppar");
    let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

    store.put_named("d", b"data-only-test-data").unwrap();

    // Drop store 1 (parity store)
    let k1: Vec<_> = store.stores[1].list_keys();
    for k in &k1 {
        store.stores[1].delete(*k).unwrap();
    }

    let data = store.get_named("d").unwrap();
    assert_eq!(data, Some(b"data-only-test-data".to_vec()));

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// k=1,m=2 degenerate: single data + double parity
// ---------------------------------------------------------------------------

#[test]
fn k1_m2_double_parity_degenerate() {
    let cfg = ec_config(1, 2, 64);
    let paths = make_paths(3, "k1m2");
    let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

    let payload: Vec<u8> = (0..200).map(|i| (i & 0xFF) as u8).collect();
    store.put_named("d", &payload).unwrap();
    assert_eq!(store.get_named("d").unwrap(), Some(payload.clone()));

    // Drop store 0 (data): should reconstruct from either parity
    let k0: Vec<_> = store.stores[0].list_keys();
    for k in &k0 {
        store.stores[0].delete(*k).unwrap();
    }
    let data = store.get_named("d").unwrap();
    assert_eq!(data, Some(payload));

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// Maximum practical k with minimum shard_len (k=8,m=1,shard_len=1)
// ---------------------------------------------------------------------------

#[test]
fn max_k_shard_len_1() {
    let cfg = ec_config(8, 1, 1);
    let paths = make_paths(9, "maxksl1");
    let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

    // Data capacity = 8 * 1 = 8 bytes
    // Write exactly 8 bytes
    let payload: Vec<u8> = (0..8).map(|i| i as u8).collect();
    store.put_named("s", &payload).unwrap();
    assert_eq!(store.get_named("s").unwrap(), Some(payload));

    // Write 3 bytes (partial last shard)
    store.put_named("p", &[1, 2, 3]).unwrap();
    assert_eq!(store.get_named("p").unwrap(), Some(vec![1, 2, 3]));

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// Maximum shard count at API boundary (k=8,m=3 → 11 stores)
// ---------------------------------------------------------------------------

#[test]
fn max_store_count_eight_plus_three() {
    let cfg = ec_config(8, 3, 128);
    let paths = make_paths(11, "maxsc");
    let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

    let payload: Vec<u8> = (0..500).map(|i: usize| (i.wrapping_mul(3)) as u8).collect();
    store.put_named("max", &payload).unwrap();
    assert_eq!(store.get_named("max").unwrap(), Some(payload));

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// Single-byte writes across different configs
// ---------------------------------------------------------------------------

#[test]
fn single_byte_all_configs() {
    let configs = [
        (1, 1, 1),
        (1, 2, 10),
        (2, 1, 8),
        (3, 2, 16),
        (4, 3, 4),
        (8, 3, 2),
    ];

    for &(k, m, sl) in &configs {
        let cfg = ec_config(k, m, sl);
        let n = cfg.store_count();
        let paths = make_paths(n, &format!("1b-k{k}-m{m}"));
        let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

        store.put_named("x", b"\x7F").unwrap();
        let data = store.get_named("x").unwrap();
        assert_eq!(data, Some(vec![0x7F]), "single-byte failed: k={k} m={m}");

        cleanup_dirs(&paths);
    }
}

// ---------------------------------------------------------------------------
// Object names at length boundaries (1-char, 255-char, 4K-char)
// ---------------------------------------------------------------------------

#[test]
fn object_name_length_boundaries() {
    let cfg = ec_config(2, 1, 64);
    let paths = make_paths(3, "namelen");
    let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

    // 1-character name
    store.put_named("a", b"short").unwrap();
    assert_eq!(store.get_named("a").unwrap(), Some(b"short".to_vec()));

    // 8-character name
    store.put_named("abcdefgh", b"eight").unwrap();
    assert_eq!(
        store.get_named("abcdefgh").unwrap(),
        Some(b"eight".to_vec())
    );

    // Long name
    let long_name = "a".repeat(100);
    store.put_named(&long_name, b"long-name-data").unwrap();
    assert_eq!(
        store.get_named(&long_name).unwrap(),
        Some(b"long-name-data".to_vec())
    );

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// Repeated open/close cycle preserves data
// ---------------------------------------------------------------------------

#[test]
fn repeated_open_close_preserves_data() {
    let cfg = ec_config(2, 1, 64);
    let paths = make_paths(3, "reopen2");

    // Write
    {
        let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();
        store.put_named("persist", b"across-cycles").unwrap();
        store.sync_all().unwrap();
    }

    // Read back after re-open multiple times
    for cycle in 0..3 {
        let store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();
        let data = store.get_named("persist").unwrap();
        assert_eq!(
            data,
            Some(b"across-cycles".to_vec()),
            "data lost on cycle {cycle}"
        );
    }

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// Delete then re-put same object name
// ---------------------------------------------------------------------------

#[test]
fn delete_and_reput_same_name() {
    let cfg = ec_config(2, 1, 64);
    let paths = make_paths(3, "delreput");
    let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

    store.put_named("x", b"first").unwrap();
    assert_eq!(store.get_named("x").unwrap(), Some(b"first".to_vec()));

    let deleted = store.delete_named("x").unwrap();
    assert!(deleted);
    assert_eq!(store.get_named("x").unwrap(), None);

    store.put_named("x", b"second").unwrap();
    assert_eq!(store.get_named("x").unwrap(), Some(b"second".to_vec()));

    cleanup_dirs(&paths);
}
