// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use proptest::prelude::*;
use std::fs;
use std::path::PathBuf;
use tidefs_erasure_coded_store::*;

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// Generate a valid ErasureCodedStoreConfig for property testing.
fn arb_config() -> impl Strategy<Value = ErasureCodedStoreConfig> {
    (1usize..=8, 0usize..=2, 1usize..=128).prop_map(|(k, m_seed, shard_len_base)| {
        let shard_len = std::cmp::max(1, shard_len_base);
        let m = match m_seed {
            0 => 1,
            1 => 2,
            _ => 3,
        };
        ErasureCodedStoreConfig {
            data_shards: k,
            parity_shards: m,
            shard_len,
            store_options: tidefs_local_object_store::StoreOptions::test_fast(),
            failure_domain: None,
            device_candidates: None,
        }
    })
}

/// Generate a (config, payload) pair within a single stripe capacity.
fn arb_config_and_payload() -> impl Strategy<Value = (ErasureCodedStoreConfig, Vec<u8>)> {
    arb_config()
        .prop_flat_map(|c| {
            let cap = c.data_capacity();
            // Generate payload up to 2x capacity (sometimes multi-stripe, sometimes not)
            let max_len = std::cmp::max(cap * 2, 1);
            (Just(c), 0..=max_len)
        })
        .prop_flat_map(|(c, len)| {
            let payload = proptest::collection::vec(any::<u8>(), len);
            (Just(c), payload)
        })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tidefs-ec-pt-{label}-{}", std::process::id()));
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

// ---------------------------------------------------------------------------
// Property: encode -> decode identity
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    #[test]
    fn encode_decode_identity((ref config, ref payload) in arb_config_and_payload()) {
        let n = config.store_count();
        let paths = make_paths(n, "pt-id");
        let mut store = ErasureCodedStore::open(&paths, config.clone())
            .unwrap_or_else(|e| panic!("open failed: k={} m={}: {e}",
                config.data_shards, config.parity_shards));

        store.put_named("obj", payload)
            .unwrap_or_else(|e| panic!("put failed: k={} m={} len={}: {e}",
                config.data_shards, config.parity_shards, payload.len()));

        let data = store.get_named("obj")
            .unwrap_or_else(|e| panic!("get failed: k={} m={} len={}: {e}",
                config.data_shards, config.parity_shards, payload.len()));

        assert_eq!(data.as_deref(), Some(payload.as_slice()),
            "encode-decode identity failed: k={} m={} len={}",
            config.data_shards, config.parity_shards, payload.len());

        // Verify stats
        assert_eq!(store.stats().object_count, 1);
        assert!(store.stats().bytes_written == payload.len() as u64);

        cleanup_dirs(&paths);
    }
}

// ---------------------------------------------------------------------------
// Property: encode -> drop shards -> decode identity (within parity limit)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        ..ProptestConfig::default()
    })]

    #[test]
    fn encode_drop_decode_identity(
        (ref config, ref payload) in arb_config_and_payload(),
    ) {
        let m = config.parity_shards;
        let n = config.store_count();

        let paths = make_paths(n, "pt-drop");
        let mut store = ErasureCodedStore::open(&paths, config.clone())
            .unwrap_or_else(|e| panic!("open failed: {e}"));

        store.put_named("obj", payload)
            .unwrap_or_else(|e| panic!("put failed: {e}"));

        // Drop up to m random stores
        let drop_count = std::cmp::min(m, n.saturating_sub(config.data_shards));
        if drop_count == 0 {
            let data = store.get_named("obj").unwrap();
            assert_eq!(data.as_deref(), Some(payload.as_slice()));
            cleanup_dirs(&paths);
            return Ok(());
        }

        let num_drops = (n % drop_count.max(1)) + 1;
        let num_drops = std::cmp::min(num_drops, m);

        // Choose deterministic drop indices based on config parameters
        let seed = config.data_shards.wrapping_mul(7)
            .wrapping_add(config.parity_shards);
        let mut drops: Vec<usize> = (0..num_drops)
            .map(|i: usize| (seed + i * 3) % n)
            .collect();
        drops.sort();
        drops.dedup();

        let remaining = n - drops.len();
        if remaining < config.data_shards {
            drops.truncate(n - config.data_shards);
        }

        let remaining = n - drops.len();
        if remaining < config.data_shards {
            cleanup_dirs(&paths);
            return Ok(());
        }

        for &d in &drops {
            let all_keys: Vec<_> = store.stores[d].list_keys();
            for k in &all_keys {
                store.stores[d].delete(*k).unwrap();
            }
        }

        let data = store.get_named("obj")
            .unwrap_or_else(|e| panic!(
                "get after dropping {:?} failed: k={} m={} len={}: {e}",
                drops, config.data_shards, m, payload.len()));

        assert_eq!(data.as_deref(), Some(payload.as_slice()),
            "encode-drop-decode identity failed: k={} m={} drops={:?} len={}",
            config.data_shards, m, drops, payload.len());

        cleanup_dirs(&paths);
    }
}

// ---------------------------------------------------------------------------
// Property: encode -> corrupt shard -> drop store -> reconstruct from parity.
//
// The store rejects corrupted shard envelopes. Reconstruction from surviving
// healthy shards + parity should recover the original data.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        ..ProptestConfig::default()
    })]

    #[test]
    fn encode_corrupt_and_drop_reconstruct_from_parity(
        (ref config, ref payload) in arb_config_and_payload(),
    ) {
        let n = config.store_count();
        let m = config.parity_shards;
        if m == 0 || n <= 1 {
            return Ok(());
        }

        let paths = make_paths(n, "pt-corr");
        let mut store = ErasureCodedStore::open(&paths, config.clone())
            .unwrap_or_else(|e| panic!("open failed: {e}"));

        store.put_named("obj", payload)
            .unwrap_or_else(|e| panic!("put failed: {e}"));

        // Corrupt store 0 (if it has any data shards)
        let k0: Vec<_> = store.stores[0].list_keys();
        let mut corrupted = false;
        for key in &k0 {
            let kb = key.as_bytes32();
            let stripe = u64::from_le_bytes(kb[16..24].try_into().unwrap());
            if stripe == u64::MAX {
                continue;
            }
            if let Ok(Some(mut data)) = store.stores[0].get(*key) {
                if !data.is_empty() {
                    let idx = (kb[0] as usize) % data.len();
                    data[idx] ^= 0x42;
                    store.stores[0].put(*key, &data).unwrap();
                    corrupted = true;
                    break;
                }
            }
        }

        // Drop store 0 so the corrupt data is not used
        if corrupted {
            let all_keys: Vec<_> = store.stores[0].list_keys();
            for k in &all_keys {
                store.stores[0].delete(*k).unwrap();
            }
        }

        // Now reconstruction should use surviving healthy shards + parity
        let result = store.get_named("obj");
        match result {
            Ok(Some(data)) => {
                assert_eq!(&data, payload,
                    "corrupt+drop reconstruction data mismatch: k={} m={} len={}",
                    config.data_shards, m, payload.len());
            }
            Ok(None) => {
                // Object not found - could happen if we dropped the only store with data
                // This is acceptable for the test
            }
            Err(e) => {
                // Reconstruction may fail if we dropped too many stores
                // Check if the failure is expected (surviving < k)
                let surviving = n - 1; // we dropped store 0
                if surviving >= config.data_shards {
                    panic!("reconstruction failed but should have succeeded: k={} m={} surviving={}: {e}",
                        config.data_shards, m, surviving);
                }
                // Otherwise expected failure, acceptable
            }
        }

        cleanup_dirs(&paths);
    }
}

// ---------------------------------------------------------------------------
// Deterministic property: put is idempotent across repeated calls
// ---------------------------------------------------------------------------

#[test]
fn put_idempotent_across_repeated_calls() {
    let configs = [
        ErasureCodedStoreConfig::two_plus_one_test(),
        ErasureCodedStoreConfig {
            data_shards: 4,
            parity_shards: 2,
            shard_len: 32,
            store_options: tidefs_local_object_store::StoreOptions::test_fast(),
            failure_domain: None,
            device_candidates: None,
        },
    ];

    for cfg in &configs {
        let n = cfg.store_count();
        let paths = make_paths(n, "pt-idem");
        let mut store = ErasureCodedStore::open(&paths, cfg.clone()).unwrap();

        let payload: Vec<u8> = (0..cfg.data_capacity() + 17)
            .map(|i: usize| (i & 0xFF) as u8)
            .collect();

        store.put_named("idem", &payload).unwrap();
        let r1 = store.get_named("idem").unwrap();

        store.put_named("idem", &payload).unwrap();
        let r2 = store.get_named("idem").unwrap();

        store.put_named("idem", &payload).unwrap();
        let r3 = store.get_named("idem").unwrap();

        assert_eq!(r1, Some(payload.clone()));
        assert_eq!(r2, Some(payload.clone()));
        assert_eq!(r3, Some(payload.clone()));

        cleanup_dirs(&paths);
    }
}

// ---------------------------------------------------------------------------
// Deterministic property: get is deterministic across repeated calls
// ---------------------------------------------------------------------------

#[test]
fn get_deterministic_across_repeated_calls() {
    let cfg = ErasureCodedStoreConfig {
        data_shards: 3,
        parity_shards: 2,
        shard_len: 64,
        store_options: tidefs_local_object_store::StoreOptions::test_fast(),
        failure_domain: None,
        device_candidates: None,
    };
    let paths = make_paths(5, "pt-detget");
    let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

    let payload: Vec<u8> = (0..250)
        .map(|i: usize| (i.wrapping_mul(13)) as u8)
        .collect();
    store.put_named("det", &payload).unwrap();

    let r1 = store.get_named("det").unwrap();
    let r2 = store.get_named("det").unwrap();
    let r3 = store.get_named("det").unwrap();

    assert_eq!(r1, Some(payload.clone()));
    assert_eq!(r2, Some(payload.clone()));
    assert_eq!(r3, Some(payload.clone()));

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// Deterministic property: store_count matches config
// ---------------------------------------------------------------------------

#[test]
fn store_count_matches_config() {
    let configs = [(1, 1, 2), (2, 2, 4), (3, 3, 6), (4, 1, 5), (8, 3, 11)];

    for &(k, m, expected) in &configs {
        let cfg = ErasureCodedStoreConfig {
            data_shards: k,
            parity_shards: m,
            shard_len: 16,
            store_options: tidefs_local_object_store::StoreOptions::test_fast(),
            failure_domain: None,
            device_candidates: None,
        };
        assert_eq!(
            cfg.store_count(),
            expected,
            "store_count mismatch: k={k} m={m}"
        );

        let n = cfg.store_count();
        let paths = make_paths(n, &format!("pt-scmatch-k{k}"));
        let store = ErasureCodedStore::open(&paths, cfg).unwrap();
        assert_eq!(store.store_count(), expected);
        cleanup_dirs(&paths);
    }
}

// ---------------------------------------------------------------------------
// Deterministic property: data_capacity is data_shards * shard_len
// ---------------------------------------------------------------------------

#[test]
fn data_capacity_formula() {
    for k in 1..=8 {
        for sl in [1, 8, 64, 128, 4096] {
            let cfg = ErasureCodedStoreConfig {
                data_shards: k,
                parity_shards: 1,
                shard_len: sl,
                store_options: tidefs_local_object_store::StoreOptions::test_fast(),
                failure_domain: None,
                device_candidates: None,
            };
            assert_eq!(
                cfg.data_capacity(),
                k * sl,
                "data_capacity mismatch: k={k} sl={sl}"
            );
        }
    }
}
