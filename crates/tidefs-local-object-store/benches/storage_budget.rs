// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Storage performance budget measurement -- throughput, latency, IOPS.
//!
//! Measures key storage KPIs for the REL-STOR-015 storage lane performance
//! budget gate: sequential write/read throughput (MiB/s), small-I/O latency
//! percentiles (p50, p95, p99), sync/flush cost, and random I/O IOPS.
//! Includes raw-file comparator baselines for throughput disclosure.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;
use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};

fn temp_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("tidefs-storage-budget-{name}"));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create bench temp dir");
    root
}

fn sized_payload(size: usize) -> Vec<u8> {
    vec![0x5A_u8; size]
}

// ── bench: sequential write throughput ────────────────────────────────

fn bench_write_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage_budget/write_throughput");
    for &size_kb in &[4, 64, 1024] {
        let data_size = size_kb * 1024;
        let batch_count = match size_kb {
            4 => 4096,
            64 => 512,
            _ => 128,
        };
        let total_bytes = data_size * batch_count;
        let payload = sized_payload(data_size);
        let id = BenchmarkId::new(format!("{size_kb}KiB"), format!("{total_bytes}B_total"));
        group.bench_function(id, |b| {
            let root = temp_root("write-tput");
            let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::default())
                .expect("open store");
            let mut counter = 0_u64;
            b.iter(|| {
                let start = Instant::now();
                for _ in 0..batch_count {
                    counter += 1;
                    let key = ObjectKey::from_name(format!("wt-{counter}"));
                    store.put(key, &payload).expect("put");
                }
                let elapsed = start.elapsed().as_secs_f64();
                let mb_s = (total_bytes as f64) / elapsed / 1_048_576.0;
                black_box(mb_s);
                black_box(elapsed);
            });
            let _ = fs::remove_dir_all(&root);
        });
    }
    group.finish();
}

// ── bench: sequential read throughput ─────────────────────────────────

fn bench_read_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage_budget/read_throughput");
    for &size_kb in &[4, 64, 1024] {
        let data_size = size_kb * 1024;
        let batch_count = match size_kb {
            4 => 4096,
            64 => 512,
            _ => 128,
        };
        let total_bytes = data_size * batch_count;
        let payload = sized_payload(data_size);
        let id = BenchmarkId::new(format!("{size_kb}KiB"), format!("{total_bytes}B_total"));
        group.bench_function(id, |b| {
            let root = temp_root("read-tput");
            let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::default())
                .expect("open store");
            let mut keys = Vec::new();
            for i in 0..batch_count {
                let key = ObjectKey::from_name(format!("rt-{i}"));
                store.put(key, &payload).expect("put");
                keys.push(key);
            }
            store.sync_all().expect("sync");
            b.iter(|| {
                let start = Instant::now();
                for key in &keys {
                    let _ = store.get(*key).expect("get");
                }
                let elapsed = start.elapsed().as_secs_f64();
                let mb_s = (total_bytes as f64) / elapsed / 1_048_576.0;
                black_box(mb_s);
                black_box(elapsed);
            });
            let _ = fs::remove_dir_all(&root);
        });
    }
    group.finish();
}

// ── bench: write latency (4 KiB) ──────────────────────────────────────

fn bench_write_latency(c: &mut Criterion) {
    let root = temp_root("write-lat");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::default()).expect("open store");
    let payload = sized_payload(4096);
    let mut counter = 0_u64;
    c.bench_function("storage_budget/write_latency_4KiB", |b| {
        b.iter(|| {
            counter += 1;
            let key = ObjectKey::from_name(format!("wl-{counter}"));
            let start = Instant::now();
            store.put(key, &payload).expect("put");
            let us = start.elapsed().as_micros() as f64;
            black_box(us);
        })
    });
    let _ = fs::remove_dir_all(&root);
}

// ── bench: read latency (4 KiB) ───────────────────────────────────────

fn bench_read_latency(c: &mut Criterion) {
    let root = temp_root("read-lat");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::default()).expect("open store");
    let payload = sized_payload(4096);
    let key = ObjectKey::from_name("rl-stable");
    store.put(key, &payload).expect("put");
    store.sync_all().expect("sync");
    c.bench_function("storage_budget/read_latency_4KiB", |b| {
        b.iter(|| {
            let start = Instant::now();
            let _ = store.get(key).expect("get");
            let us = start.elapsed().as_micros() as f64;
            black_box(us);
        })
    });
    let _ = fs::remove_dir_all(&root);
}

// ── bench: sync/flush latency ─────────────────────────────────────────

fn bench_sync_latency(c: &mut Criterion) {
    let root = temp_root("sync-lat");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::default()).expect("open store");
    c.bench_function("storage_budget/sync_latency", |b| {
        b.iter(|| {
            let key = ObjectKey::from_name("sync-key");
            store.put(key, b"sync-data").expect("put");
            let start = Instant::now();
            store.sync_all().expect("sync");
            let us = start.elapsed().as_micros() as f64;
            black_box(us);
        })
    });
    let _ = fs::remove_dir_all(&root);
}

// ── bench: IOPS random read ───────────────────────────────────────────

fn bench_iops_random_read(c: &mut Criterion) {
    let root = temp_root("iops-rr");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::default()).expect("open store");
    let n_keys: usize = 256;
    let mut keys = Vec::new();
    for i in 0..n_keys {
        let key = ObjectKey::from_name(format!("iops-rr-{i}"));
        store.put(key, b"iops-data").expect("put");
        keys.push(key);
    }
    store.sync_all().expect("sync");
    let batch = 1000_usize;
    c.bench_function("storage_budget/iops_random_read", |b| {
        b.iter(|| {
            let start = Instant::now();
            for i in 0..batch {
                let key = keys[i % n_keys];
                let _ = store.get(key).expect("get");
            }
            let elapsed = start.elapsed().as_secs_f64();
            let iops = batch as f64 / elapsed;
            black_box(iops);
        })
    });
    let _ = fs::remove_dir_all(&root);
}

// ── bench: IOPS random write ──────────────────────────────────────────

fn bench_iops_random_write(c: &mut Criterion) {
    let root = temp_root("iops-rw");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::default()).expect("open store");
    let batch = 1000_usize;
    let payload = sized_payload(4096);
    let mut counter = 0_u64;
    c.bench_function("storage_budget/iops_random_write", |b| {
        b.iter(|| {
            let start = Instant::now();
            for _ in 0..batch {
                counter += 1;
                let key = ObjectKey::from_name(format!("iops-rw-{counter}"));
                store.put(key, &payload).expect("put");
            }
            let elapsed = start.elapsed().as_secs_f64();
            let iops = batch as f64 / elapsed;
            black_box(iops);
        })
    });
    let _ = fs::remove_dir_all(&root);
}

// ── bench: replay throughput ──────────────────────────────────────────

fn bench_replay_throughput(c: &mut Criterion) {
    let n_objects = 200_u64;
    c.bench_function("storage_budget/replay_throughput", |b| {
        b.iter(|| {
            let root = temp_root("replay-tput");
            {
                let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::default())
                    .expect("open store");
                for i in 0..n_objects {
                    let key = ObjectKey::from_name(format!("rp-{i}"));
                    store.put(key, b"replay-data").expect("put");
                }
                store.sync_all().expect("sync");
            }
            let start = Instant::now();
            let store = LocalObjectStore::open_with_options(&root, StoreOptions::default())
                .expect("reopen");
            let report = store.replay_report();
            let elapsed = start.elapsed().as_secs_f64();
            let objs_per_sec = n_objects as f64 / elapsed;
            black_box(report.records_seen);
            black_box(objs_per_sec);
            black_box(elapsed);
            let _ = fs::remove_dir_all(&root);
        })
    });
}

// ── bench: large write throughput (1 MiB objects) ─────────────────────

fn bench_large_write_throughput(c: &mut Criterion) {
    let payload = sized_payload(1_048_576);
    let batch = 64_usize;
    let total_bytes = payload.len() * batch;
    c.bench_function("storage_budget/large_write_1MiB", |b| {
        let root = temp_root("large-write");
        let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::default())
            .expect("open store");
        let mut counter = 0_u64;
        b.iter(|| {
            let start = Instant::now();
            for _ in 0..batch {
                counter += 1;
                let key = ObjectKey::from_name(format!("lw-{counter}"));
                store.put(key, &payload).expect("put");
            }
            let elapsed = start.elapsed().as_secs_f64();
            let mb_s = (total_bytes as f64) / elapsed / 1_048_576.0;
            black_box(mb_s);
            black_box(elapsed);
        });
        let _ = fs::remove_dir_all(&root);
    });
}

// ── bench: large read throughput (1 MiB objects) ──────────────────────

fn bench_large_read_throughput(c: &mut Criterion) {
    let payload = sized_payload(1_048_576);
    let batch = 64_usize;
    let total_bytes = payload.len() * batch;
    c.bench_function("storage_budget/large_read_1MiB", |b| {
        let root = temp_root("large-read");
        let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::default())
            .expect("open store");
        let mut keys = Vec::new();
        for i in 0..batch {
            let key = ObjectKey::from_name(format!("lr-{i}"));
            store.put(key, &payload).expect("put");
            keys.push(key);
        }
        store.sync_all().expect("sync");
        b.iter(|| {
            let start = Instant::now();
            for key in &keys {
                let _ = store.get(*key).expect("get");
            }
            let elapsed = start.elapsed().as_secs_f64();
            let mb_s = (total_bytes as f64) / elapsed / 1_048_576.0;
            black_box(mb_s);
            black_box(elapsed);
        });
        let _ = fs::remove_dir_all(&root);
    });
}

// ── comparator: raw-file write throughput baseline ────────────────────

fn bench_comparator_raw_file_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("comparator/raw_file_write");
    for &size_kb in &[4, 64, 1024] {
        let data_size = size_kb * 1024;
        let batch_count = match size_kb {
            4 => 4096,
            64 => 512,
            _ => 128,
        };
        let total_bytes = data_size * batch_count;
        let payload = sized_payload(data_size);
        let id = BenchmarkId::new(format!("{size_kb}KiB"), format!("{total_bytes}B_total"));
        group.bench_function(id, |b| {
            let file_path = std::env::temp_dir().join(format!("tidefs-raw-bench-{size_kb}k"));
            b.iter(|| {
                let start = Instant::now();
                {
                    let mut f = fs::OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(&file_path)
                        .expect("open raw file");
                    for _ in 0..batch_count {
                        f.write_all(&payload).expect("raw write");
                    }
                    f.sync_all().expect("raw fsync");
                }
                let elapsed = start.elapsed().as_secs_f64();
                let mb_s = (total_bytes as f64) / elapsed / 1_048_576.0;
                black_box(mb_s);
                black_box(elapsed);
            });
            let _ = fs::remove_file(&file_path);
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_write_throughput,
    bench_read_throughput,
    bench_write_latency,
    bench_read_latency,
    bench_sync_latency,
    bench_iops_random_read,
    bench_iops_random_write,
    bench_replay_throughput,
    bench_large_write_throughput,
    bench_large_read_throughput,
    bench_comparator_raw_file_write,
);
criterion_main!(benches);
