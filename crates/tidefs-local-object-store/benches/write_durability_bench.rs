// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Write-durability flush-path latency benchmarks.
//!
//! Measures the SegmentBuilder-driven write path introduced in #4160:
//! segment build, BLAKE3 checksum anchoring, durable commit, and
//! batched multi-object flush latency.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::fs;
use std::path::PathBuf;
use tidefs_local_object_store::{
    compute_segment_digest,
    segment_builder::{FlushResult, PendingWrite, SegmentBuilder},
    LocalObjectStore, ObjectKey, StoreOptions,
};

// ── helpers ──────────────────────────────────────────────────────────

fn temp_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("tidefs-bench-{name}"));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create bench temp dir");
    root
}

/// Create a synthetic payload of `size` bytes filled with repeating pattern.
fn sized_payload(size: usize) -> Vec<u8> {
    vec![0xAB_u8; size]
}

/// Build a vec of `count` random-looking 32-byte record digests.
fn make_record_digests(count: usize) -> Vec<[u8; 32]> {
    (0..count)
        .map(|i| {
            let mut d = [0u8; 32];
            let seed = (i as u64).wrapping_mul(0x9E3779B97F4A7C15);
            d[..8].copy_from_slice(&seed.to_le_bytes());
            d[8..16].copy_from_slice(&seed.swap_bytes().to_le_bytes());
            d[16..24].copy_from_slice(&(seed ^ 0xDEAD_BEEF).to_le_bytes());
            d[24..32].copy_from_slice(&(seed.swap_bytes() ^ 0xCAFE_BABE).to_le_bytes());
            d
        })
        .collect()
}

// ── bench 1: segment build latency ───────────────────────────────────

fn bench_segment_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("segment_build");

    for &size_kb in &[4, 64, 1024, 16384] {
        let data_size = size_kb * 1024;
        let id = BenchmarkId::from_parameter(format!("{size_kb}KiB"));
        let payload = sized_payload(data_size);

        group.bench_with_input(id, &payload, |b, payload| {
            b.iter(|| {
                let mut sb = SegmentBuilder::new((data_size + 256) as u64);
                sb.push(PendingWrite::put(
                    ObjectKey::from_name("bench-key"),
                    payload.clone(),
                ))
                .expect("push");
                let segment = sb.finish().expect("finish");
                black_box(segment.checksum);
            })
        });
    }

    group.finish();
}

// ── bench 2: BLAKE3 checksum anchor latency ──────────────────────────

fn bench_checksum_anchor(c: &mut Criterion) {
    let mut group = c.benchmark_group("checksum_anchor");

    for &digest_count in &[1, 64, 256, 1024] {
        let digests = make_record_digests(digest_count as usize);
        let id = BenchmarkId::from_parameter(format!("{digest_count}_digests"));

        group.bench_with_input(id, &digests, |b, digests| {
            b.iter(|| {
                let checksum = compute_segment_digest(digests);
                black_box(checksum);
            })
        });
    }

    group.finish();
}

// ── bench 3: end-to-end flush commit latency ─────────────────────────

fn bench_flush_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("flush_commit");

    for &size_kb in &[4, 64, 1024, 16384] {
        let data_size = size_kb * 1024;
        let id = BenchmarkId::from_parameter(format!("{size_kb}KiB"));
        let payload = sized_payload(data_size);

        group.bench_with_input(id, &payload, |b, payload| {
            b.iter_custom(|iters| {
                let root = temp_root("flush-commit");
                let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::default())
                    .expect("open store");
                let mut elapsed = std::time::Duration::ZERO;

                for i in 0..iters {
                    let key = ObjectKey::from_name(format!("fc-{i:06}"));
                    store.put(key, payload).expect("put");
                    let start = std::time::Instant::now();
                    let result: FlushResult = store.flush_segment().expect("flush_segment");
                    black_box(result.checksum);
                    elapsed += start.elapsed();
                }

                let _ = fs::remove_dir_all(&root);
                elapsed
            })
        });
    }

    group.finish();
}

// ── bench 4: batched flush latency ───────────────────────────────────

fn bench_batch_flush(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_flush");

    for &batch_width in &[1u64, 4, 16, 64] {
        let id = BenchmarkId::from_parameter(format!("{batch_width}_objects"));
        let payload = sized_payload(4096); // 4 KiB per object

        group.bench_with_input(id, &(batch_width, payload), |b, (batch_width, payload)| {
            b.iter_custom(|iters| {
                let root = temp_root("batch-flush");
                let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::default())
                    .expect("open store");
                let mut counter: u64 = 0;
                let mut elapsed = std::time::Duration::ZERO;

                for _ in 0..iters {
                    for _ in 0..*batch_width {
                        counter += 1;
                        store
                            .put(ObjectKey::from_name(format!("bf-{counter:08}")), payload)
                            .expect("put");
                    }
                    let start = std::time::Instant::now();
                    let result: FlushResult = store.flush_segment().expect("flush_segment");
                    black_box(result.checksum);
                    elapsed += start.elapsed();
                }

                let _ = fs::remove_dir_all(&root);
                elapsed
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_segment_build,
    bench_checksum_anchor,
    bench_flush_commit,
    bench_batch_flush,
);
criterion_main!(benches);
