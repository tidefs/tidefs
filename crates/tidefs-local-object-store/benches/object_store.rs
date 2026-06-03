use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::fs;
use std::path::PathBuf;
use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};

fn temp_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("tidefs-bench-{name}"));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create bench temp dir");
    root
}

fn bench_put_small_payloads(c: &mut Criterion) {
    let root = temp_root("put-small");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::default()).expect("open store");
    let payload = b"bench-payload-data";
    let mut counter = 0_u64;

    c.bench_function("object_store/put_small", |b| {
        b.iter(|| {
            counter += 1;
            let key = ObjectKey::from_name(format!("key-{counter}"));
            store.put(key, payload).expect("put");
        })
    });

    let _ = fs::remove_dir_all(&root);
}

fn bench_get_small_payloads(c: &mut Criterion) {
    let root = temp_root("get-small");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::default()).expect("open store");
    let key = ObjectKey::from_name("stable-key");
    store.put(key, b"stable-data").expect("put init");
    store.sync_all().expect("sync");

    c.bench_function("object_store/get_small", |b| {
        b.iter(|| {
            let _ = black_box(store.get(key).expect("get"));
        })
    });

    let _ = fs::remove_dir_all(&root);
}

fn bench_replay(c: &mut Criterion) {
    c.bench_function("object_store/replay", |b| {
        b.iter(|| {
            let root = temp_root("replay");
            {
                let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::default())
                    .expect("open store");
                for i in 0_u64..50 {
                    let key = ObjectKey::from_name(format!("rkey-{i}"));
                    store.put(key, b"replay-data").expect("put");
                }
                store.sync_all().expect("sync");
            }
            let store = LocalObjectStore::open_with_options(&root, StoreOptions::default())
                .expect("reopen store");
            let report = store.replay_report();
            assert!(report.records_seen > 0);
            let _ = fs::remove_dir_all(&root);
        })
    });
}

fn bench_delete(c: &mut Criterion) {
    let root = temp_root("delete");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::default()).expect("open store");
    let mut counter = 0_u64;

    c.bench_function("object_store/delete", |b| {
        b.iter(|| {
            counter += 1;
            let key = ObjectKey::from_name(format!("dkey-{counter}"));
            store.put(key, b"delete-me").expect("put");
            let _ = black_box(store.delete(key).expect("delete"));
        })
    });

    let _ = fs::remove_dir_all(&root);
}

fn bench_sync_all_standalone(c: &mut Criterion) {
    let root = temp_root("sync-all");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::default()).expect("open store");
    let mut counter = 0_u64;

    c.bench_function("object_store/sync_all", |b| {
        b.iter(|| {
            counter += 1;
            let key = ObjectKey::from_name(format!("skey-{counter}"));
            store.put(key, b"sync-payload").expect("put");
            {
                store.sync_all().expect("sync");
                black_box(())
            };
        })
    });

    let _ = fs::remove_dir_all(&root);
}

fn bench_put_large_payload(c: &mut Criterion) {
    let root = temp_root("put-large");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::default()).expect("open store");
    let payload = vec![0xEF_u8; 65536];
    let mut counter = 0_u64;

    c.bench_function("object_store/put_large", |b| {
        b.iter(|| {
            counter += 1;
            let key = ObjectKey::from_name(format!("lkey-{counter}"));
            let _ = black_box(store.put(key, &payload).expect("put large"));
        })
    });

    let _ = fs::remove_dir_all(&root);
}

fn bench_contains_key(c: &mut Criterion) {
    let root = temp_root("contains");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::default()).expect("open store");
    let present = ObjectKey::from_name("present");
    store.put(present, b"here").expect("put");
    let absent = ObjectKey::from_name("absent");

    c.bench_function("object_store/contains_key", |b| {
        b.iter(|| {
            let _ = black_box(store.contains_key(present));
            let _ = black_box(store.contains_key(absent));
        })
    });

    let _ = fs::remove_dir_all(&root);
}

criterion_group!(
    benches,
    bench_put_small_payloads,
    bench_get_small_payloads,
    bench_replay,
    bench_delete,
    bench_sync_all_standalone,
    bench_put_large_payload,
    bench_contains_key,
);
criterion_main!(benches);
