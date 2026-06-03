//! Criterion benchmarks for tidefs-compression.
//!
//! Measures:
//!   - Compression throughput (MiB/s) per algorithm at 4 KiB, 64 KiB, 1 MiB
//!   - Decompression throughput (MiB/s) per algorithm at same sizes
//!   - Compression ratio for typical filesystem data patterns
//!   - Scaling: encode/decode latency vs input size (1 byte to 16 MiB)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tidefs_compression::{CompressionAlgorithm, CompressionConfig, CompressionStats};
use tidefs_frame::{compress_frame, decompress_frame};

type DataPattern = (&'static str, fn(usize) -> Vec<u8>);

// ── Input generators ──────────────────────────────────────────────────────

fn source_code_pattern(size: usize) -> Vec<u8> {
    // Simulate source code: ASCII text with newlines, indentation, keywords.
    let pattern =
        b"    let result = store.put(key, payload)?;\n    store.sync_all()?;\n    Ok(result)\n";
    pattern.iter().cycle().take(size).copied().collect()
}

fn binary_pattern(size: usize) -> Vec<u8> {
    // Simulate binary/executable: mix of zeroes and random-ish bytes.
    let mut v = Vec::with_capacity(size);
    let mut seed: u32 = 0xDEADBEEF;
    for _ in 0..size {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        v.push((seed >> 16) as u8);
    }
    v
}

fn database_page_pattern(size: usize) -> Vec<u8> {
    // Simulate database pages: structured records with padding.
    let record = b"ROW\x00\x00\x00\x10\x00\x00\x00\x00\xDE\xAD\xBE\xEF\x00\x00\x00\x00";
    let mut v = Vec::with_capacity(size);
    while v.len() < size {
        v.extend_from_slice(record);
    }
    v.truncate(size);
    v
}

fn all_zeros_pattern(size: usize) -> Vec<u8> {
    vec![0u8; size]
}

// ── Throughput benchmarks ─────────────────────────────────────────────────

fn bench_compress_throughput(c: &mut Criterion) {
    let sizes = [4096usize, 65536, 1048576]; // 4 KiB, 64 KiB, 1 MiB
    let algorithms = [
        ("zstd", CompressionAlgorithm::Zstd, 3i32),
        ("lz4", CompressionAlgorithm::Lz4, 0i32),
        ("uncompressed", CompressionAlgorithm::Uncompressed, 0i32),
    ];

    for &size in &sizes {
        let payload = source_code_pattern(size);
        let mut group = c.benchmark_group(format!("compress_throughput/{}", format_size(size)));

        for &(algo_name, algo, level) in &algorithms {
            let config = CompressionConfig {
                algorithm: algo,
                level,
                min_compress_bytes: 0,
            };

            group.throughput(Throughput::Bytes(size as u64));
            group.bench_function(BenchmarkId::new("encode", algo_name), |b| {
                b.iter(|| {
                    let mut stats = CompressionStats::default();
                    let framed = compress_frame(black_box(&payload), &config, &mut stats);
                    black_box(framed)
                })
            });
        }
        group.finish();
    }
}

fn bench_decompress_throughput(c: &mut Criterion) {
    let sizes = [4096usize, 65536, 1048576]; // 4 KiB, 64 KiB, 1 MiB
    let algorithms = [
        ("zstd", CompressionAlgorithm::Zstd, 3i32),
        ("lz4", CompressionAlgorithm::Lz4, 0i32),
        ("uncompressed", CompressionAlgorithm::Uncompressed, 0i32),
    ];

    for &size in &sizes {
        let payload = source_code_pattern(size);
        let mut group = c.benchmark_group(format!("decompress_throughput/{}", format_size(size)));

        for &(algo_name, algo, level) in &algorithms {
            let config = CompressionConfig {
                algorithm: algo,
                level,
                min_compress_bytes: 0,
            };
            let mut stats = CompressionStats::default();
            let framed = compress_frame(&payload, &config, &mut stats);

            group.throughput(Throughput::Bytes(size as u64));
            group.bench_function(BenchmarkId::new("decode", algo_name), |b| {
                b.iter(|| {
                    let recovered =
                        decompress_frame(black_box(&framed)).expect("decompress must succeed");
                    black_box(recovered)
                })
            });
        }
        group.finish();
    }
}

// ── Compression ratio benchmarks ──────────────────────────────────────────

fn bench_compression_ratio(c: &mut Criterion) {
    let size = 65536; // 64 KiB
    let patterns: &[DataPattern] = &[
        ("source_code", source_code_pattern),
        ("binary", binary_pattern),
        ("database_page", database_page_pattern),
        ("all_zeros", all_zeros_pattern),
    ];
    let algorithms: &[(&str, CompressionAlgorithm, i32)] = &[
        ("zstd", CompressionAlgorithm::Zstd, 3),
        ("lz4", CompressionAlgorithm::Lz4, 0),
    ];

    let mut group = c.benchmark_group("compression_ratio");

    for &(pattern_name, pattern_fn) in patterns {
        let payload = pattern_fn(size);

        for &(algo_name, algo, level) in algorithms {
            let config = CompressionConfig {
                algorithm: algo,
                level,
                min_compress_bytes: 0,
            };

            group.bench_function(BenchmarkId::new(algo_name, pattern_name), |b| {
                b.iter(|| {
                    let mut stats = CompressionStats::default();
                    let framed = compress_frame(black_box(&payload), &config, &mut stats);
                    let ratio = framed.len() as f64 / payload.len() as f64;
                    black_box(ratio)
                })
            });
        }
    }
    group.finish();
}

// ── Scaling benchmarks ────────────────────────────────────────────────────

fn bench_scaling(c: &mut Criterion) {
    let sizes: &[usize] = &[
        1, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 16777216,
    ];
    let algorithms: &[(&str, CompressionAlgorithm, i32)] = &[
        ("zstd", CompressionAlgorithm::Zstd, 3),
        ("lz4", CompressionAlgorithm::Lz4, 0),
    ];

    for &(algo_name, algo, level) in algorithms {
        let mut group = c.benchmark_group(format!("scaling_encode/{algo_name}"));

        for &size in sizes {
            let payload = source_code_pattern(size);
            let config = CompressionConfig {
                algorithm: algo,
                level,
                min_compress_bytes: 0,
            };

            group.throughput(Throughput::Bytes(size as u64));
            group.bench_function(BenchmarkId::from_parameter(format_size(size)), |b| {
                b.iter(|| {
                    let mut stats = CompressionStats::default();
                    compress_frame(black_box(&payload), &config, &mut stats)
                })
            });
        }
        group.finish();
    }

    for &(algo_name, algo, level) in algorithms {
        let mut group = c.benchmark_group(format!("scaling_decode/{algo_name}"));

        for &size in sizes {
            let payload = source_code_pattern(size);
            let config = CompressionConfig {
                algorithm: algo,
                level,
                min_compress_bytes: 0,
            };
            let mut stats = CompressionStats::default();
            let framed = compress_frame(&payload, &config, &mut stats);

            group.throughput(Throughput::Bytes(size as u64));
            group.bench_function(BenchmarkId::from_parameter(format_size(size)), |b| {
                b.iter(|| decompress_frame(black_box(&framed)).expect("decompress must succeed"))
            });
        }
        group.finish();
    }
}

// ── Helper ────────────────────────────────────────────────────────────────

fn format_size(bytes: usize) -> String {
    if bytes >= 1048576 && bytes % 1048576 == 0 {
        format!("{}MiB", bytes / 1048576)
    } else if bytes >= 1024 && bytes % 1024 == 0 {
        format!("{}KiB", bytes / 1024)
    } else if bytes == 1 {
        "1B".to_string()
    } else {
        format!("{bytes}B")
    }
}

criterion_group!(
    benches,
    bench_compress_throughput,
    bench_decompress_throughput,
    bench_compression_ratio,
    bench_scaling,
);
criterion_main!(benches);
