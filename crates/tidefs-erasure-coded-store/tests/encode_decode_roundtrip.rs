use std::fs;
use std::path::PathBuf;
use tidefs_erasure_coded_store::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tidefs-ec-rt-{label}-{}", std::process::id()));
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

fn sequential_payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i & 0xFF) as u8).collect()
}

/// Create a config for testing.
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
// Empty payload roundtrip across configurations
// ---------------------------------------------------------------------------

#[test]
fn empty_payload_roundtrip_varied_configs() {
    let configs = [
        (2, 1, 64),
        (3, 1, 128),
        (4, 2, 256),
        (5, 2, 64),
        (6, 3, 32),
        (8, 3, 16),
        (8, 2, 100),
    ];

    for &(k, m, sl) in &configs {
        let cfg = ec_config(k, m, sl);
        let n = cfg.store_count();
        let paths = make_paths(n, &format!("empty-k{k}-m{m}"));
        let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

        store.put_named("empty", b"").unwrap();
        let data = store.get_named("empty").unwrap();
        assert_eq!(
            data,
            Some(b"".to_vec()),
            "empty roundtrip failed: k={k} m={m}"
        );

        cleanup_dirs(&paths);
    }
}

// ---------------------------------------------------------------------------
// Single-byte payload roundtrip across configurations
// ---------------------------------------------------------------------------

#[test]
fn single_byte_roundtrip_varied_configs() {
    let configs = [
        (2, 1, 64),
        (3, 2, 128),
        (4, 2, 256),
        (6, 3, 32),
        (7, 1, 8),
        (8, 3, 10),
    ];

    for &(k, m, sl) in &configs {
        let cfg = ec_config(k, m, sl);
        let n = cfg.store_count();
        let paths = make_paths(n, &format!("1b-k{k}-m{m}"));
        let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

        store.put_named("one", b"\xAB").unwrap();
        let data = store.get_named("one").unwrap();
        assert_eq!(
            data,
            Some(vec![0xAB]),
            "single-byte roundtrip failed: k={k} m={m}"
        );

        cleanup_dirs(&paths);
    }
}

// ---------------------------------------------------------------------------
// Block-aligned payload (exactly data_capacity bytes)
// ---------------------------------------------------------------------------

#[test]
fn block_aligned_roundtrip_varied_configs() {
    let configs = [
        (2, 1, 64),  // cap = 128
        (3, 2, 100), // cap = 300
        (4, 2, 64),  // cap = 256
        (5, 1, 20),  // cap = 100
        (6, 3, 24),  // cap = 144
        (8, 3, 30),  // cap = 240
    ];

    for &(k, m, sl) in &configs {
        let cfg = ec_config(k, m, sl);
        let cap = cfg.data_capacity();
        let n = cfg.store_count();
        let paths = make_paths(n, &format!("aligned-k{k}-m{m}"));
        let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

        let payload = sequential_payload(cap);
        store.put_named("aligned", &payload).unwrap();
        let data = store.get_named("aligned").unwrap();
        assert_eq!(
            data,
            Some(payload),
            "aligned roundtrip failed: k={k} m={m} cap={cap}"
        );

        cleanup_dirs(&paths);
    }
}

// ---------------------------------------------------------------------------
// Unaligned payload (not a multiple of data_capacity)
// ---------------------------------------------------------------------------

#[test]
fn unaligned_payload_roundtrip_varied_configs() {
    let configs = [
        (2, 1, 64), // cap = 128, payload = 200
        (3, 2, 50), // cap = 150, payload = 233
        (4, 2, 32), // cap = 128, payload = 199
        (5, 3, 16), // cap =  80, payload = 137
        (6, 1, 10), // cap =  60, payload =  77
        (8, 2, 12), // cap =  96, payload = 155
    ];

    for &(k, m, sl) in &configs {
        let cfg = ec_config(k, m, sl);
        let cap = cfg.data_capacity();
        let payload_len = cap + cap / 2 + 7; // unaligned, > 1 stripe
        let n = cfg.store_count();
        let paths = make_paths(n, &format!("unaligned-k{k}-m{m}"));
        let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

        let payload = sequential_payload(payload_len);
        store.put_named("unaligned", &payload).unwrap();
        let data = store.get_named("unaligned").unwrap();
        assert_eq!(
            data,
            Some(payload),
            "unaligned roundtrip failed: k={k} m={m} cap={cap} len={payload_len}"
        );

        cleanup_dirs(&paths);
    }
}

// ---------------------------------------------------------------------------
// Multi-stripe payload (3x capacity)
// ---------------------------------------------------------------------------

#[test]
fn multi_stripe_roundtrip_varied_configs() {
    let configs = [
        (2, 1, 64), // cap = 128, 3x = 384
        (3, 2, 32), // cap =  96, 3x = 288
        (4, 1, 48), // cap = 192, 3x = 576
        (4, 3, 16), // cap =  64, 3x = 192
        (8, 2, 10), // cap =  80, 3x = 240
    ];

    for &(k, m, sl) in &configs {
        let cfg = ec_config(k, m, sl);
        let cap = cfg.data_capacity();
        let payload_len = cap * 3 + 42; // unaligned 3-stripe payload
        let n = cfg.store_count();
        let paths = make_paths(n, &format!("multi-k{k}-m{m}"));
        let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

        let payload = sequential_payload(payload_len);
        store.put_named("multi", &payload).unwrap();
        let data = store.get_named("multi").unwrap();
        assert_eq!(
            data,
            Some(payload),
            "multi-stripe roundtrip failed: k={k} m={m} cap={cap} len={payload_len}"
        );

        // Verify stripe count
        let expected_stripes = payload_len.div_ceil(cap);
        assert!(
            store.stats().stripes_written >= expected_stripes as u64,
            "expected at least {expected_stripes} stripes: k={k} m={m}"
        );

        cleanup_dirs(&paths);
    }
}

// ---------------------------------------------------------------------------
// High-parity configurations (8+4, 4+4, 2+3)
// ---------------------------------------------------------------------------

#[test]
fn high_parity_roundtrip() {
    let configs = [
        (8, 3, 32),  // standard 8+3
        (4, 3, 64),  // 4+3
        (2, 2, 128), // 2+2
        (3, 3, 16),  // 3+3 (parity heavy)
    ];

    for &(k, m, sl) in &configs {
        let cfg = ec_config(k, m, sl);
        let cap = cfg.data_capacity();
        let n = cfg.store_count();
        let paths = make_paths(n, &format!("highpar-k{k}-m{m}"));
        let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

        let payload = sequential_payload(cap + 17); // unaligned
        store.put_named("hp", &payload).unwrap();
        let data = store.get_named("hp").unwrap();
        assert_eq!(
            data,
            Some(payload),
            "high-parity roundtrip failed: k={k} m={m}"
        );

        cleanup_dirs(&paths);
    }
}

// ---------------------------------------------------------------------------
// Large shard size roundtrip
// ---------------------------------------------------------------------------

#[test]
fn large_shard_size_roundtrip() {
    let configs = [(2, 1, 1024), (3, 2, 512), (4, 1, 256)];

    for &(k, m, sl) in &configs {
        let cfg = ec_config(k, m, sl);
        let cap = cfg.data_capacity();
        let n = cfg.store_count();
        let paths = make_paths(n, &format!("large-k{k}-m{m}"));
        let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

        // 1.5 stripes worth of data
        let payload_len = cap + cap / 2;
        let payload: Vec<u8> = (0..payload_len)
            .map(|i: usize| (i.wrapping_mul(17)) as u8)
            .collect();
        store.put_named("large", &payload).unwrap();
        let data = store.get_named("large").unwrap();
        assert_eq!(
            data,
            Some(payload),
            "large shard roundtrip failed: k={k} m={m}"
        );

        cleanup_dirs(&paths);
    }
}

// ---------------------------------------------------------------------------
// k=1 edge case roundtrip (single data shard + parity)
// ---------------------------------------------------------------------------

#[test]
fn k1_with_parity_roundtrip() {
    let configs = [(1, 1, 64), (1, 2, 32), (1, 3, 16)];

    for &(k, m, sl) in &configs {
        let cfg = ec_config(k, m, sl);
        let n = cfg.store_count();
        let paths = make_paths(n, &format!("k1-m{m}"));
        let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

        let payload: Vec<u8> = (0..sl + 7).map(|i| (i & 0xFF) as u8).collect();
        store.put_named("k1", &payload).unwrap();
        let data = store.get_named("k1").unwrap();
        assert_eq!(data, Some(payload), "k=1 m={m} roundtrip failed");

        cleanup_dirs(&paths);
    }
}

// ---------------------------------------------------------------------------
// Repeated put/get on same object (overwrite)
// ---------------------------------------------------------------------------

#[test]
fn overwrite_same_object_roundtrip() {
    let cfg = ec_config(3, 2, 64);
    let paths = make_paths(5, "overwrite");
    let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

    for iteration in 0..5 {
        let payload: Vec<u8> = vec![iteration as u8; 100 + iteration * 20];
        store.put_named("obj", &payload).unwrap();
        let data = store.get_named("obj").unwrap();
        assert_eq!(
            data,
            Some(payload),
            "overwrite iteration {iteration} failed"
        );
    }

    cleanup_dirs(&paths);
}

// ---------------------------------------------------------------------------
// Roundtrip with non-ASCII object names
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_non_ascii_names() {
    let cfg = ec_config(2, 1, 64);
    let paths = make_paths(3, "names");
    let mut store = ErasureCodedStore::open(&paths, cfg).unwrap();

    let names = [
        "object/with/slashes",
        "object.with.dots",
        "object-with-hyphens_underscores",
        "0123456789",
        "a",
    ];

    for name in &names {
        let payload = name.as_bytes().to_vec();
        store.put_named(name, &payload).unwrap();
        let data = store.get_named(name).unwrap();
        assert_eq!(data, Some(payload), "name roundtrip failed for '{name}'");
    }

    cleanup_dirs(&paths);
}
