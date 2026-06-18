// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Determinism and cross-algorithm isolation tests for tidefs-compression.
//!
//! Determinism: same input + same config → identical framed output.
//! Cross-algorithm isolation: compress with A, modify header to claim B →
//!   decompress must produce a clean error (never undefined behavior).

use tidefs_compression::{CompressionAlgorithm, CompressionConfig, CompressionStats};
use tidefs_frame::{compress_frame, decompress_frame};

// ── Determinism ───────────────────────────────────────────────────────────

#[test]
fn zstd_determinism_small() {
    let payload = b"determinism test payload ".repeat(20);
    let config = CompressionConfig::balanced();
    let mut stats1 = CompressionStats::default();
    let mut stats2 = CompressionStats::default();
    let framed1 = compress_frame(&payload, &config, &mut stats1);
    let framed2 = compress_frame(&payload, &config, &mut stats2);
    assert_eq!(
        framed1, framed2,
        "zstd small: same input must produce identical output"
    );
}

#[test]
fn zstd_determinism_large() {
    let payload = vec![0x41u8; 16384];
    let config = CompressionConfig::balanced();
    let mut stats1 = CompressionStats::default();
    let mut stats2 = CompressionStats::default();
    let framed1 = compress_frame(&payload, &config, &mut stats1);
    let framed2 = compress_frame(&payload, &config, &mut stats2);
    assert_eq!(
        framed1, framed2,
        "zstd large: same input must produce identical output"
    );
}

#[test]
fn zstd_determinism_different_levels_may_differ() {
    // Different levels may produce different output; that's expected.
    // But each level should be internally consistent.
    let payload = b"level-specific determinism ".repeat(50);
    for level in [1, 5, 10, 15, 22] {
        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level,
            min_compress_bytes: 0,
        };
        let mut stats1 = CompressionStats::default();
        let mut stats2 = CompressionStats::default();
        let framed1 = compress_frame(&payload, &config, &mut stats1);
        let framed2 = compress_frame(&payload, &config, &mut stats2);
        assert_eq!(
            framed1, framed2,
            "zstd level {level}: same input must produce identical output"
        );
    }
}

#[test]
fn lz4_determinism_small() {
    let payload = b"lz4 determinism test ".repeat(20);
    let config = CompressionConfig::speed();
    let mut stats1 = CompressionStats::default();
    let mut stats2 = CompressionStats::default();
    let framed1 = compress_frame(&payload, &config, &mut stats1);
    let framed2 = compress_frame(&payload, &config, &mut stats2);
    assert_eq!(
        framed1, framed2,
        "lz4 small: same input must produce identical output"
    );
}

#[test]
fn lz4_determinism_large() {
    let payload = vec![0x42u8; 16384];
    let config = CompressionConfig::speed();
    let mut stats1 = CompressionStats::default();
    let mut stats2 = CompressionStats::default();
    let framed1 = compress_frame(&payload, &config, &mut stats1);
    let framed2 = compress_frame(&payload, &config, &mut stats2);
    assert_eq!(
        framed1, framed2,
        "lz4 large: same input must produce identical output"
    );
}

#[test]
fn uncompressed_determinism() {
    let payload = b"always uncompressed determinism".repeat(10);
    let config = CompressionConfig {
        algorithm: CompressionAlgorithm::Uncompressed,
        level: 0,
        min_compress_bytes: 0,
    };
    let mut stats1 = CompressionStats::default();
    let mut stats2 = CompressionStats::default();
    let framed1 = compress_frame(&payload, &config, &mut stats1);
    let framed2 = compress_frame(&payload, &config, &mut stats2);
    assert_eq!(
        framed1, framed2,
        "uncompressed: same input must produce identical output"
    );
}

#[test]
fn determinism_below_min_compress_threshold() {
    // Payloads below min_compress_bytes are stored uncompressed.
    let payload = b"small";
    let config = CompressionConfig {
        algorithm: CompressionAlgorithm::Zstd,
        level: 3,
        min_compress_bytes: 128,
    };
    let mut stats1 = CompressionStats::default();
    let mut stats2 = CompressionStats::default();
    let framed1 = compress_frame(payload, &config, &mut stats1);
    let framed2 = compress_frame(payload, &config, &mut stats2);
    assert_eq!(
        framed1, framed2,
        "below-threshold: same input must produce identical output"
    );
}

// ── Cross-algorithm isolation ─────────────────────────────────────────────

#[test]
fn zstd_frame_labeled_as_lz4_fails() {
    let payload = b"AAAA".repeat(200);
    let config = CompressionConfig::balanced(); // zstd level 3
    let mut stats = CompressionStats::default();
    let mut framed = compress_frame(&payload, &config, &mut stats);

    // The frame should have zstd algorithm byte (0x01).
    assert_eq!(framed[0], 0x01, "expected zstd algorithm byte");

    // Rewrite algorithm byte to claim it's LZ4 (0x02).
    framed[0] = 0x02;
    let result = decompress_frame(&framed);
    assert!(
        result.is_err(),
        "zstd payload with LZ4 header must error, not produce garbage"
    );
}

#[test]
fn lz4_frame_labeled_as_zstd_fails() {
    let payload = b"BBBB".repeat(200);
    let config = CompressionConfig::speed(); // lz4 level 0
    let mut stats = CompressionStats::default();
    let mut framed = compress_frame(&payload, &config, &mut stats);

    // The frame should have LZ4 algorithm byte (0x02).
    assert_eq!(framed[0], 0x02, "expected lz4 algorithm byte");

    // Rewrite algorithm byte to claim it's zstd (0x01).
    framed[0] = 0x01;
    let result = decompress_frame(&framed);
    assert!(
        result.is_err(),
        "lz4 payload with zstd header must error, not produce garbage"
    );
}

#[test]
fn zstd_frame_labeled_as_uncompressed_gives_garbage() {
    let payload = b"CCCC".repeat(200);
    let config = CompressionConfig::balanced();
    let mut stats = CompressionStats::default();
    let mut framed = compress_frame(&payload, &config, &mut stats);
    assert_eq!(framed[0], 0x01); // zstd

    // Rewrite to uncompressed (0x00) — decompress_frame will return
    // the raw compressed bytes as-is without decompressing.
    framed[0] = 0x00;
    let result = decompress_frame(&framed);
    // Must not panic; result is the raw compressed payload interpreted as
    // plaintext — wrong but safe.
    assert!(
        result.is_ok(),
        "uncompressed header on zstd data is safe, just wrong"
    );
    let garbage = result.unwrap();
    assert_ne!(
        garbage, payload,
        "mislabeled zstd decoded as uncompressed must not match original"
    );
}

#[test]
fn lz4_frame_labeled_as_uncompressed_gives_garbage() {
    let payload = b"DDDD".repeat(200);
    let config = CompressionConfig::speed();
    let mut stats = CompressionStats::default();
    let mut framed = compress_frame(&payload, &config, &mut stats);
    assert_eq!(framed[0], 0x02); // lz4

    framed[0] = 0x00;
    let result = decompress_frame(&framed);
    assert!(
        result.is_ok(),
        "uncompressed header on lz4 data is safe, just wrong"
    );
    let garbage = result.unwrap();
    assert_ne!(
        garbage, payload,
        "mislabeled lz4 decoded as uncompressed must not match original"
    );
}

// ── Cross-algorithm: correct frame, wrong decompressor (byte swap) ────────

#[test]
fn algorithm_byte_roundtrip_identity() {
    // Verify that compress-then-decompress through an intermediate
    // algorithm-byte corruption-and-restore cycle still works.
    let payload = b"identity through byte flip ".repeat(30);
    for (algo, expected_byte) in [
        (CompressionAlgorithm::Zstd, 0x01u8),
        (CompressionAlgorithm::Lz4, 0x02u8),
        (CompressionAlgorithm::Uncompressed, 0x00u8),
    ] {
        let config = CompressionConfig {
            algorithm: algo,
            level: 3,
            min_compress_bytes: 0,
        };
        let mut stats = CompressionStats::default();
        let mut framed = compress_frame(&payload, &config, &mut stats);
        assert_eq!(
            framed[0], expected_byte,
            "{algo:?}: expected byte 0x{expected_byte:02x}"
        );

        // Corrupt the byte then restore it — round-trip should still work.
        let original_byte = framed[0];
        framed[0] = 0xFF;
        framed[0] = original_byte;
        let recovered = decompress_frame(&framed)
            .unwrap_or_else(|e| panic!("{algo:?}: restore-byte round-trip failed: {e}"));
        assert_eq!(
            recovered, payload,
            "{algo:?}: round-trip through byte corruption failed"
        );
    }
}

// ── Determinism with empty payload ────────────────────────────────────────

#[test]
fn determinism_empty_payload() {
    for algo in [
        CompressionAlgorithm::Uncompressed,
        CompressionAlgorithm::Zstd,
        CompressionAlgorithm::Lz4,
    ] {
        let config = CompressionConfig {
            algorithm: algo,
            level: 3,
            min_compress_bytes: 0,
        };
        let mut stats1 = CompressionStats::default();
        let mut stats2 = CompressionStats::default();
        let framed1 = compress_frame(b"", &config, &mut stats1);
        let framed2 = compress_frame(b"", &config, &mut stats2);
        assert_eq!(
            framed1, framed2,
            "{algo:?} empty: same input must produce identical output"
        );
    }
}

// ── Determinism after repeated decompression ──────────────────────────────

#[test]
fn determinism_roundtrip_cycle() {
    // compress → decompress → compress again → should produce identical
    // output to the original compress (for algorithms with deterministic
    // compressors).
    let payload = b"roundtrip cycle determinism ".repeat(30);
    for algo in [CompressionAlgorithm::Zstd, CompressionAlgorithm::Lz4] {
        let config = CompressionConfig {
            algorithm: algo,
            level: 3,
            min_compress_bytes: 0,
        };
        let mut stats = CompressionStats::default();
        let framed1 = compress_frame(&payload, &config, &mut stats);

        let recovered = decompress_frame(&framed1)
            .unwrap_or_else(|e| panic!("{algo:?} first decompress failed: {e}"));
        assert_eq!(recovered, payload, "{algo:?} first round-trip mismatch");

        let mut stats2 = CompressionStats::default();
        let framed2 = compress_frame(&recovered, &config, &mut stats2);
        assert_eq!(
            framed1, framed2,
            "{algo:?} re-compress must produce identical frame"
        );

        let recovered2 = decompress_frame(&framed2)
            .unwrap_or_else(|e| panic!("{algo:?} second decompress failed: {e}"));
        assert_eq!(recovered2, payload, "{algo:?} second round-trip mismatch");
    }
}
