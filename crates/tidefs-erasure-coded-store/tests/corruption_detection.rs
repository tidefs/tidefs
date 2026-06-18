// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::fs;
use std::path::PathBuf;
use tidefs_erasure_coded_store::*;

use tidefs_local_object_store::ObjectKey;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tidefs-ec-cd-{label}-{}", std::process::id()));
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

/// Delete all shards from the specified store indices.
fn drop_stores(store: &mut ErasureCodedStore, indices: &[usize]) {
    for &idx in indices {
        let all_keys: Vec<_> = store.stores[idx].list_keys();
        for k in &all_keys {
            store.stores[idx].delete(*k).unwrap();
        }
    }
}

/// Corrupt all shards in the given store by applying the mutator.
fn corrupt_all_shards(
    store: &mut ErasureCodedStore,
    store_index: usize,
    mutator: &mut dyn FnMut(&mut Vec<u8>),
) -> usize {
    let all_keys: Vec<_> = store.stores[store_index].list_keys();
    let mut count = 0;
    for key in &all_keys {
        let key_bytes = key.as_bytes32();
        let stripe = u64::from_le_bytes(key_bytes[16..24].try_into().unwrap());
        if stripe == u64::MAX {
            continue;
        }
        if let Ok(Some(mut data)) = store.stores[store_index].get(*key) {
            if !data.is_empty() {
                mutator(&mut data);
                let _ = store.stores[store_index].put(*key, &data);
                count += 1;
            }
        }
    }
    count
}

// ---------------------------------------------------------------------------
// Bit flip in data shard: with all shards present, the corrupt shard is
// rejected and the payload is reconstructed from verified alternatives.
// ---------------------------------------------------------------------------

#[test]
fn bit_flip_with_all_shards_present_reconstructs_from_verified_alternatives() {
    let cfg = ec_config(3, 2, 64);
    let paths = make_paths(5, "bitflip-all");
    let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

    let payload: Vec<u8> = (0..200).map(|i| (i & 0xFF) as u8).collect();
    store.put_named("flipped", &payload).unwrap();
    store.sync_all().unwrap();

    // Corrupt store 0: flip a bit in the first byte
    corrupt_all_shards(&mut store, 0, &mut |data| {
        data[0] ^= 0x01;
    });

    // Read: all data shards are present, but the corrupt envelope is skipped.
    let result = store.get_named("flipped").unwrap();
    assert_eq!(
        result,
        Some(payload.clone()),
        "verified alternatives should reconstruct the original payload"
    );
    assert!(store.stats().degraded_reads.get() >= 1);
    assert!(store.stats().shard_verification_failures.get() >= 1);

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// Bit flip + drop store: reconstruction from parity corrects the error
// ---------------------------------------------------------------------------

#[test]
fn bit_flip_and_drop_store_reconstructs_from_parity() {
    let cfg = ec_config(3, 2, 64);
    let paths = make_paths(5, "bitflip-drop");
    let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

    let payload: Vec<u8> = (0..200).map(|i| (i & 0xFF) as u8).collect();
    store.put_named("fixable", &payload).unwrap();
    store.sync_all().unwrap();

    // Corrupt store 0, then drop it
    corrupt_all_shards(&mut store, 0, &mut |data| {
        data[0] ^= 0xFF;
    });
    drop_stores(&mut store, &[0]);

    // With store 0 dropped, reconstruction uses stores 1,2 + parity
    let result = store.get_named("fixable").unwrap();
    assert_eq!(
        result,
        Some(payload),
        "dropping corrupt store should allow reconstruction from healthy shards + parity"
    );

    assert!(store.stats().degraded_reads.get() >= 1);

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// Multiple stores dropped exceeding parity → reconstruction fails
// ---------------------------------------------------------------------------

#[test]
fn too_many_stores_dropped_causes_reconstruction_failure() {
    let cfg = ec_config(2, 1, 64);
    let paths = make_paths(3, "toomany");
    let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

    store.put_named("doomed", b"too-many-losses").unwrap();
    store.sync_all().unwrap();

    // Drop both data stores (0 and 1) — only 1 parity store survives, need k=2
    drop_stores(&mut store, &[0, 1]);

    let result = store.get_named("doomed");
    assert!(
        result.is_err(),
        "read should fail when only 1 of required 2 shards survive"
    );

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// Truncated shard + drop: reconstruction from parity corrects
// ---------------------------------------------------------------------------

#[test]
fn truncated_shard_and_drop_reconstructs_from_parity() {
    let cfg = ec_config(3, 2, 64);
    let paths = make_paths(5, "trunc-drop");
    let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

    let payload: Vec<u8> = (0..200).map(|i| (i & 0xFF) as u8).collect();
    store.put_named("truncated", &payload).unwrap();
    store.sync_all().unwrap();

    // Truncate shards in store 0, then drop store 0
    corrupt_all_shards(&mut store, 0, &mut |data| {
        data.truncate(data.len() / 2);
    });
    drop_stores(&mut store, &[0]);

    // With store 0 dropped, reconstruction uses healthy shards + parity
    let result = store.get_named("truncated").unwrap();
    assert_eq!(
        result,
        Some(payload),
        "dropping store with truncated shards should reconstruct from parity"
    );

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// Zeroed shard + drop: reconstruction from parity corrects
// ---------------------------------------------------------------------------

#[test]
fn zeroed_shard_and_drop_reconstructs_from_parity() {
    let cfg = ec_config(3, 2, 32);
    let paths = make_paths(5, "zero-drop");
    let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

    let payload: Vec<u8> = (0..150).map(|i| (i & 0xFF) as u8).collect();
    store.put_named("zero", &payload).unwrap();
    store.sync_all().unwrap();

    // Zero out store 0, then drop it
    corrupt_all_shards(&mut store, 0, &mut |data| {
        data.fill(0);
    });
    drop_stores(&mut store, &[0]);

    let result = store.get_named("zero").unwrap();
    assert_eq!(
        result,
        Some(payload),
        "dropping zeroed store should reconstruct from healthy shards + parity"
    );

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// Parity shard corruption doesn't affect clean reads (data shards intact)
// ---------------------------------------------------------------------------

#[test]
fn parity_shard_corruption_does_not_affect_clean_read() {
    let cfg = ec_config(3, 2, 64);
    let paths = make_paths(5, "parcorr");
    let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

    let payload: Vec<u8> = (0..180).map(|i: usize| (i.wrapping_mul(3)) as u8).collect();
    store.put_named("par", &payload).unwrap();
    store.sync_all().unwrap();

    // Corrupt a parity store (store 3)
    corrupt_all_shards(&mut store, 3, &mut |data| {
        if data.len() > 5 {
            data[5] ^= 0x80;
        }
    });

    // Read — all data shards (0,1,2) are healthy, parity corruption doesn't matter
    let result = store.get_named("par").unwrap();
    assert_eq!(
        result,
        Some(payload),
        "parity shard corruption should not affect clean read from data shards"
    );

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// Shard reordering is rejected by the per-shard envelope before decode.
// ---------------------------------------------------------------------------

#[test]
fn shard_reordering_causes_data_corruption() {
    let cfg = ec_config(2, 1, 64);
    let paths = make_paths(3, "reorder");
    let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

    let payload: Vec<u8> = (0..150).map(|i: usize| (i.wrapping_mul(5)) as u8).collect();
    store.put_named("reorder", &payload).unwrap();
    store.sync_all().unwrap();

    // Swap shard records between store 0 and store 1 for stripe 0.
    let k0_all: Vec<_> = store.stores[0].list_keys();
    let k1_all: Vec<_> = store.stores[1].list_keys();

    let find_stripe0 = |keys: &[ObjectKey]| -> Option<ObjectKey> {
        for k in keys {
            let kb = k.as_bytes32();
            let stripe = u64::from_le_bytes(kb[16..24].try_into().unwrap());
            if stripe == 0 {
                return Some(*k);
            }
        }
        None
    };

    if let (Some(k0), Some(k1)) = (find_stripe0(&k0_all), find_stripe0(&k1_all)) {
        let d0 = store.stores[0].get(k0).unwrap().unwrap();
        let d1 = store.stores[1].get(k1).unwrap().unwrap();
        store.stores[0].put(k0, &d1).unwrap();
        store.stores[1].put(k1, &d0).unwrap();
    }

    // Now open a fresh store and read. The envelope binds each record to its
    // original shard index, so swapped records must not decode silently.
    let s = ErasureCodedStore::open(&paths, cfg).unwrap();
    let result = s.get_named("reorder");

    match result {
        Ok(Some(data)) => {
            assert_ne!(
                data, payload,
                "swapped shards should not produce correct data"
            );
        }
        Ok(None) => panic!("object should still have metadata"),
        Err(_) => {}
    }

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// Combination: drop one store, corrupt another — reconstruction from remaining
// ---------------------------------------------------------------------------

#[test]
#[allow(unused_variables)]
fn drop_and_corrupt_reconstructs_from_surviving_shards() {
    let cfg = ec_config(4, 2, 32);
    let paths = make_paths(6, "combo2");
    let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

    let payload: Vec<u8> = (0..200)
        .map(|i: usize| (i.wrapping_mul(13)) as u8)
        .collect();
    store.put_named("combo", &payload).unwrap();
    store.sync_all().unwrap();

    // Drop store 0, corrupt store 1 — then we have 4 healthy (2,3,4,5) = k=4
    drop_stores(&mut store, &[0]);
    corrupt_all_shards(&mut store, 1, &mut |data| {
        if !data.is_empty() {
            data[0] ^= 0xFF;
        }
    });

    // With 4 healthy shards (stores 2,3,4,5), reconstruction should work while
    // the corrupted present shard is ignored.
    let result = store.get_named("combo");
    match result {
        Ok(Some(data)) => {
            assert_eq!(
                data, payload,
                "corrupt present shard should be skipped in favor of verified survivors"
            );
        }
        Ok(None) => panic!("object not found"),
        Err(e) => panic!("reconstruction should use the 4 verified survivors: {e}"),
    }
    assert!(store.stats().shard_verification_failures.get() >= 1);

    cleanup_dirs(&paths);
}
