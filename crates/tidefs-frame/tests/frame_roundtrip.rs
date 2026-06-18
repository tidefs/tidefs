// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Property-based round-trip tests for tidefs-frame wire encoding.
//!
//! Every public frame type and encode/decode function is exercised under
//! random input generation via proptest. The core invariant:
//!   decompress_frame(compress_frame(payload)) == payload
//!
//! These tests complement the inline unit tests in src/lib.rs by covering
//! arbitrary payloads, configs, and boundary sizes that manual test cases
//! might miss.

use proptest::prelude::*;
use tidefs_frame::{
    compress_frame, decompress_frame, read_frame_header, CompressionAlgorithm, CompressionConfig,
    CompressionStats, FrameError, FRAME_HEADER_LEN,
};

// ── Strategies ────────────────────────────────────────────────────────────

/// Generate a valid compression algorithm.
fn arb_algorithm() -> impl Strategy<Value = CompressionAlgorithm> {
    prop_oneof![
        Just(CompressionAlgorithm::Uncompressed),
        Just(CompressionAlgorithm::Zstd),
        Just(CompressionAlgorithm::Lz4),
    ]
}

/// Generate a compression config with all fields randomized.
fn arb_config() -> impl Strategy<Value = CompressionConfig> {
    (arb_algorithm(), 0i32..=22, 0usize..=512).prop_map(|(algorithm, level, min_bytes)| {
        CompressionConfig {
            algorithm,
            level,
            min_compress_bytes: min_bytes,
        }
    })
}

/// Generate arbitrary byte payloads across a wide size range.
fn arb_payload() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..16384)
}

/// Generate payloads large enough to trigger compression.
fn arb_large_payload() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1024..32768)
}

// ── Core round-trip property ──────────────────────────────────────────────

proptest! {
    /// For any payload and config, encode then decode recovers the original.
    #[test]
    fn proptest_roundtrip_identity(
        payload in arb_payload(),
        config in arb_config(),
    ) {
        let mut stats = CompressionStats::default();
        let framed = compress_frame(&payload, &config, &mut stats);
        let recovered = decompress_frame(&framed).expect("decompress must succeed");
        prop_assert_eq!(&recovered, &payload,
            "round-trip failed: decoded payload does not match original");
    }

    /// For any payload and config, the frame header encodes correct algorithm.
    #[test]
    fn proptest_header_algorithm_byte(
        payload in arb_payload(),
        config in arb_config(),
    ) {
        let mut stats = CompressionStats::default();
        let framed = compress_frame(&payload, &config, &mut stats);
        // Algorithm byte in header must be a valid CompressionAlgorithm.
        let algo = CompressionAlgorithm::from_byte(framed[0]);
        prop_assert!(algo.is_some(), "algorithm byte 0x{:02x} is invalid", framed[0]);
    }

    /// The frame header uncompressed length always matches the payload length.
    #[test]
    fn proptest_header_uncompressed_length(
        payload in arb_payload(),
        config in arb_config(),
    ) {
        let mut stats = CompressionStats::default();
        let framed = compress_frame(&payload, &config, &mut stats);
        let (_, uncompressed_len) = read_frame_header(&framed).unwrap();
        prop_assert_eq!(uncompressed_len, payload.len(),
            "header uncompressed_len {} != payload.len() {}", uncompressed_len, payload.len());
    }

    /// read_frame_header on any valid frame returns valid results.
    #[test]
    fn proptest_read_header_roundtrip(
        payload in arb_payload(),
        config in arb_config(),
    ) {
        let mut stats = CompressionStats::default();
        let framed = compress_frame(&payload, &config, &mut stats);
        let (algo, len) = read_frame_header(&framed).unwrap();
        prop_assert_eq!(len, payload.len());
        // The algorithm byte must round-trip through from_byte.
        let decoded = CompressionAlgorithm::from_byte(algo as u8).unwrap();
        prop_assert_eq!(decoded, algo);
    }
}

// ── Large payload round-trip ──────────────────────────────────────────────

proptest! {
    /// Large payloads round-trip correctly under all compression algorithms.
    #[test]
    fn proptest_large_roundtrip(
        payload in arb_large_payload(),
        config in arb_config(),
    ) {
        let mut stats = CompressionStats::default();
        let framed = compress_frame(&payload, &config, &mut stats);
        let recovered = decompress_frame(&framed).expect("decompress large payload");
        prop_assert_eq!(&recovered, &payload);
    }
}

// ── Frame too short error ─────────────────────────────────────────────────

#[test]
fn decompress_frame_too_short_0_bytes() {
    match decompress_frame(&[]) {
        Err(FrameError::FrameTooShort { len: 0 }) => {}
        other => panic!("expected FrameTooShort(0), got {other:?}"),
    }
}

#[test]
fn decompress_frame_too_short_4_bytes() {
    match decompress_frame(&[0x00, 0x00, 0x00, 0x00]) {
        Err(FrameError::FrameTooShort { len: 4 }) => {}
        other => panic!("expected FrameTooShort(4), got {other:?}"),
    }
}

#[test]
fn read_frame_header_too_short_0_bytes() {
    assert!(read_frame_header(&[]).is_none());
}

#[test]
fn read_frame_header_too_short_4_bytes() {
    assert!(read_frame_header(&[0x00, 0x00, 0x00, 0x00]).is_none());
}

// ── Unknown algorithm ─────────────────────────────────────────────────────

#[test]
fn decompress_unknown_algorithm_byte_0xff() {
    let buf = vec![0xFF, 0x10, 0x00, 0x00, 0x00, 0x00];
    match decompress_frame(&buf) {
        Err(FrameError::UnknownAlgorithm { byte: 0xFF }) => {}
        other => panic!("expected UnknownAlgorithm(0xFF), got {other:?}"),
    }
}

#[test]
fn decompress_unknown_algorithm_byte_0x03_to_0xfe() {
    for byte in 0x03u8..=0xFE {
        let buf = vec![
            byte, 0x08, 0x00, 0x00, 0x00, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        ];
        match decompress_frame(&buf) {
            Err(FrameError::UnknownAlgorithm { .. }) => {}
            other => panic!("expected UnknownAlgorithm for byte 0x{byte:02x}, got {other:?}"),
        }
    }
}

#[test]
fn read_frame_header_unknown_algorithm() {
    let buf = vec![0xFF, 0x10, 0x00, 0x00, 0x00];
    assert!(read_frame_header(&buf).is_none());
}

// ── Corrupt payload ───────────────────────────────────────────────────────

#[test]
fn zstd_frame_with_truncated_payload() {
    // Valid zstd header claiming 1000 uncompressed bytes, but only 1 byte of payload
    let mut buf = vec![0x01]; // zstd
    buf.extend_from_slice(&1000u32.to_le_bytes());
    buf.push(0x00); // single garbage byte, not valid zstd
    match decompress_frame(&buf) {
        Err(FrameError::ZstdDecompressionFailed) => {}
        other => panic!("expected ZstdDecompressionFailed, got {other:?}"),
    }
}

#[test]
fn lz4_frame_with_truncated_payload() {
    let mut buf = vec![0x02]; // lz4
    buf.extend_from_slice(&1000u32.to_le_bytes());
    buf.push(0x00); // single garbage byte, not valid lz4
    match decompress_frame(&buf) {
        Err(FrameError::Lz4DecompressionFailed) => {}
        other => panic!("expected Lz4DecompressionFailed, got {other:?}"),
    }
}

#[test]
fn zstd_frame_with_zero_payload() {
    // zstd header claiming 0 uncompressed bytes, no payload
    let buf = vec![0x01, 0x00, 0x00, 0x00, 0x00];
    match decompress_frame(&buf) {
        Err(FrameError::ZstdDecompressionFailed) => {}
        other => panic!("expected ZstdDecompressionFailed for empty zstd payload, got {other:?}"),
    }
}

// ── Frame statistics ──────────────────────────────────────────────────────

proptest! {
    /// After compressing, stats.bytes_in always equals payload sum.
    #[test]
    fn proptest_stats_bytes_in(
        payload in arb_payload(),
        config in arb_config(),
    ) {
        let mut stats = CompressionStats::default();
        let pre_bytes_in = stats.bytes_in;
        compress_frame(&payload, &config, &mut stats);
        prop_assert_eq!(stats.bytes_in, pre_bytes_in + payload.len() as u64);
    }

    /// After compressing, stats.bytes_out is at least FRAME_HEADER_LEN if
    /// there is any output.
    #[test]
    fn proptest_stats_bytes_out_minimum(
        payload in arb_payload(),
        config in arb_config(),
    ) {
        let mut stats = CompressionStats::default();
        compress_frame(&payload, &config, &mut stats);
        prop_assert!(stats.bytes_out >= FRAME_HEADER_LEN as u64,
            "bytes_out {} should be >= FRAME_HEADER_LEN {}", stats.bytes_out, FRAME_HEADER_LEN);
    }

    /// CompressionStats ratio is never negative or NaN.
    #[test]
    fn proptest_stats_ratio_sane(
        payload in arb_payload(),
        config in arb_config(),
    ) {
        let mut stats = CompressionStats::default();
        compress_frame(&payload, &config, &mut stats);
        let r = stats.ratio();
        prop_assert!(r.is_finite(), "ratio must be finite, got {r}");
        prop_assert!(r >= 0.0, "ratio must be non-negative, got {r}");
    }
}

// ── Config presets ────────────────────────────────────────────────────────

#[test]
fn speed_config_roundtrip() {
    let cfg = CompressionConfig::speed();
    let mut stats = CompressionStats::default();
    let payload = b"speed test payload with some repetition AAAA BBBB CCCC";
    let framed = compress_frame(payload, &cfg, &mut stats);
    let recovered = decompress_frame(&framed).unwrap();
    assert_eq!(recovered, payload);
    // Algorithm byte must be LZ4 (0x02) or uncompressed (if threshold not met).
    assert!(
        framed[0] == 0x02 || framed[0] == 0x00,
        "speed config produced unexpected algorithm 0x{:02x}",
        framed[0]
    );
}

#[test]
fn balanced_config_roundtrip() {
    let cfg = CompressionConfig::balanced();
    let mut stats = CompressionStats::default();
    let payload = b"balanced test payload with some repetition AAAA BBBB CCCC";
    let framed = compress_frame(payload, &cfg, &mut stats);
    let recovered = decompress_frame(&framed).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn max_config_roundtrip() {
    let cfg = CompressionConfig::max();
    let mut stats = CompressionStats::default();
    let payload = vec![0x41u8; 1024];
    let framed = compress_frame(&payload, &cfg, &mut stats);
    let recovered = decompress_frame(&framed).unwrap();
    assert_eq!(recovered, payload);
    // max config has min_compress_bytes=0 so even small payloads try compression.
    assert_eq!(cfg.min_compress_bytes, 0);
}

// ── Uncompressed frame boundary values ────────────────────────────────────

#[test]
fn zero_byte_payload_roundtrip() {
    let cfg = CompressionConfig::default();
    let mut stats = CompressionStats::default();
    let framed = compress_frame(b"", &cfg, &mut stats);
    assert_eq!(framed.len(), FRAME_HEADER_LEN);
    assert_eq!(framed[0], 0x00);
    let recovered = decompress_frame(&framed).unwrap();
    assert!(recovered.is_empty());
}

#[test]
fn single_byte_payload_roundtrip() {
    let cfg = CompressionConfig::default();
    let mut stats = CompressionStats::default();
    let framed = compress_frame(&[0xAB], &cfg, &mut stats);
    assert_eq!(framed.len(), FRAME_HEADER_LEN + 1);
    assert_eq!(framed[0], 0x00); // single byte stored uncompressed
    let recovered = decompress_frame(&framed).unwrap();
    assert_eq!(recovered, &[0xAB]);
}

#[test]
fn exactly_min_compress_boundary() {
    // Payload exactly at the threshold: should NOT be compressed.
    let cfg = CompressionConfig {
        min_compress_bytes: 64,
        ..CompressionConfig::default()
    };
    let mut stats = CompressionStats::default();
    let payload = vec![0x41u8; 63]; // one byte below threshold
    let framed = compress_frame(&payload, &cfg, &mut stats);
    assert_eq!(
        framed[0], 0x00,
        "payload below threshold should be uncompressed"
    );
    let recovered = decompress_frame(&framed).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn one_byte_above_min_compress_boundary() {
    let cfg = CompressionConfig {
        min_compress_bytes: 64,
        ..CompressionConfig::default()
    };
    let mut stats = CompressionStats::default();
    let payload = vec![0x41u8; 64]; // at threshold
    let framed = compress_frame(&payload, &cfg, &mut stats);
    // At threshold, compression is attempted; if not effective, falls back
    let recovered = decompress_frame(&framed).unwrap();
    assert_eq!(recovered, payload);
}

// ── Mismatched uncompressed length ────────────────────────────────────────

#[test]
fn uncompressed_frame_with_wrong_length_field() {
    // Uncompressed frame where header says 10 bytes but payload is 20.
    let mut buf = vec![0x00]; // uncompressed
    buf.extend_from_slice(&10u32.to_le_bytes()); // claims 10 bytes
    buf.extend_from_slice(b"AAAAAAAAAAAAAAAAAAAA"); // 20 bytes
                                                    // decompress_frame returns payload.len() bytes; it notes mismatch but
                                                    // returns what's there for robustness.
    let result = decompress_frame(&buf);
    assert!(
        result.is_ok(),
        "uncompressed frame with wrong length should not error"
    );
    assert_eq!(
        result.unwrap().len(),
        20,
        "returns actual payload, not claimed length"
    );
}

// ── Exhaustive algorithm byte enumeration ──────────────────────────────────

#[test]
fn algorithm_from_byte_exhaustive() {
    for b in 0u8..=255u8 {
        match b {
            0x00 => assert_eq!(
                CompressionAlgorithm::from_byte(b),
                Some(CompressionAlgorithm::Uncompressed)
            ),
            0x01 => assert_eq!(
                CompressionAlgorithm::from_byte(b),
                Some(CompressionAlgorithm::Zstd)
            ),
            0x02 => assert_eq!(
                CompressionAlgorithm::from_byte(b),
                Some(CompressionAlgorithm::Lz4)
            ),
            _ => assert_eq!(
                CompressionAlgorithm::from_byte(b),
                None,
                "byte 0x{b:02x} should be None"
            ),
        }
    }
}

// ── All-zero payload round-trips ──────────────────────────────────────────

#[test]
fn all_zero_payload_roundtrip_64b() {
    let cfg = CompressionConfig::default();
    let mut stats = CompressionStats::default();
    let payload = vec![0x00u8; 64];
    let framed = compress_frame(&payload, &cfg, &mut stats);
    let recovered = decompress_frame(&framed).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn all_zero_payload_roundtrip_1kib() {
    let cfg = CompressionConfig::default();
    let mut stats = CompressionStats::default();
    let payload = vec![0x00u8; 1024];
    let framed = compress_frame(&payload, &cfg, &mut stats);
    let recovered = decompress_frame(&framed).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn all_zero_payload_roundtrip_4kib() {
    let cfg = CompressionConfig::default();
    let mut stats = CompressionStats::default();
    let payload = vec![0x00u8; 4096];
    let framed = compress_frame(&payload, &cfg, &mut stats);
    let recovered = decompress_frame(&framed).unwrap();
    assert_eq!(recovered, payload);
}

// ── All-0xFF payload round-trips ──────────────────────────────────────────

#[test]
fn all_ff_payload_roundtrip_64b() {
    let cfg = CompressionConfig::default();
    let mut stats = CompressionStats::default();
    let payload = vec![0xFFu8; 64];
    let framed = compress_frame(&payload, &cfg, &mut stats);
    let recovered = decompress_frame(&framed).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn all_ff_payload_roundtrip_1kib() {
    let cfg = CompressionConfig::default();
    let mut stats = CompressionStats::default();
    let payload = vec![0xFFu8; 1024];
    let framed = compress_frame(&payload, &cfg, &mut stats);
    let recovered = decompress_frame(&framed).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn all_ff_payload_roundtrip_4kib() {
    let cfg = CompressionConfig::default();
    let mut stats = CompressionStats::default();
    let payload = vec![0xFFu8; 4096];
    let framed = compress_frame(&payload, &cfg, &mut stats);
    let recovered = decompress_frame(&framed).unwrap();
    assert_eq!(recovered, payload);
}

// ── Large payload ─────────────────────────────────────────────────────────

#[test]
fn large_payload_64kib_roundtrip() {
    let cfg = CompressionConfig::default();
    let mut stats = CompressionStats::default();
    let payload = vec![0x41u8; 65536];
    let framed = compress_frame(&payload, &cfg, &mut stats);
    let recovered = decompress_frame(&framed).unwrap();
    assert_eq!(recovered, payload);
}

// ── Header type-max boundary ──────────────────────────────────────────────

#[test]
fn header_claims_u32_max_length() {
    // Header says uncompressed with u32::MAX bytes, but actual payload is
    // only 4 bytes. Decompress gracefully returns what's there.
    let mut buf = vec![0x00]; // uncompressed
    buf.extend_from_slice(&u32::MAX.to_le_bytes());
    buf.extend_from_slice(b"XXXX"); // only 4 bytes, not u32::MAX
    let result = decompress_frame(&buf);
    // Should not panic; returns the available payload.
    assert!(result.is_ok());
}

#[test]
fn minimum_viable_frame_exactly_header_len() {
    // Frame consisting solely of the 5-byte header (uncompressed, 0-length payload).
    let buf = vec![0x00, 0x00, 0x00, 0x00, 0x00];
    let recovered = decompress_frame(&buf).unwrap();
    assert!(recovered.is_empty());
    let (algo, len) = read_frame_header(&buf).unwrap();
    assert_eq!(algo, CompressionAlgorithm::Uncompressed);
    assert_eq!(len, 0);
}
