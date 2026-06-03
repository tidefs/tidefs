//! Property-based round-trip tests for tidefs-compression.
//!
//! Exercises frame-level compress/decompress through the tidefs-compression
//! re-export path (CompressionAlgorithm, CompressionConfig, CompressionStats,
//! FRAME_HEADER_LEN) combined with tidefs-frame functions (compress_frame,
//! decompress_frame, read_frame_header, FrameError).
//!
//! Also includes CompressedObjectStore integration tests that exercise the
//! full put/get round-trip through a temp directory store.
//!
//! Invariants:
//!   decompress_frame(compress_frame(payload)) == payload
//!   Corrupted frames produce errors, never undefined behavior

use proptest::prelude::*;
use tidefs_compression::{
    CompressionAlgorithm, CompressionConfig, CompressionError, CompressionStats, FRAME_HEADER_LEN,
};
use tidefs_frame::{compress_frame, decompress_frame, read_frame_header};

// ── Strategies ────────────────────────────────────────────────────────────

fn arb_algorithm() -> impl Strategy<Value = CompressionAlgorithm> {
    prop_oneof![
        Just(CompressionAlgorithm::Uncompressed),
        Just(CompressionAlgorithm::Zstd),
        Just(CompressionAlgorithm::Lz4),
    ]
}

fn arb_config() -> impl Strategy<Value = CompressionConfig> {
    (arb_algorithm(), 0i32..=22i32, 0usize..=512usize).prop_map(|(algorithm, level, min_bytes)| {
        CompressionConfig {
            algorithm,
            level,
            min_compress_bytes: min_bytes,
        }
    })
}

fn arb_payload() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..16384)
}

fn arb_payload_nonempty() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..16384)
}

fn arb_large_payload() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1024..65536)
}

// ── Core round-trip property ──────────────────────────────────────────────

proptest! {
    /// For any payload and config, encode then decode recovers the original.
    #[test]
    fn round_trip_arbitrary_bytes(
        payload in arb_payload(),
        config in arb_config(),
    ) {
        let mut stats = CompressionStats::default();
        let framed = compress_frame(&payload, &config, &mut stats);
        let recovered = decompress_frame(&framed).expect("decompress must succeed");
        prop_assert_eq!(&recovered, &payload,
            "round-trip failed: len(orig)={}, len(recovered)={}",
            payload.len(), recovered.len());
    }

    /// The frame header uncompressed length always matches the payload length.
    #[test]
    fn round_trip_header_matches_payload_len(
        payload in arb_payload(),
        config in arb_config(),
    ) {
        let mut stats = CompressionStats::default();
        let framed = compress_frame(&payload, &config, &mut stats);
        let (_, uncompressed_len) = read_frame_header(&framed).unwrap();
        prop_assert_eq!(uncompressed_len, payload.len());
    }

    /// read_frame_header on any valid frame returns a decodable algorithm.
    #[test]
    fn round_trip_header_algorithm_valid(
        payload in arb_payload(),
        config in arb_config(),
    ) {
        let mut stats = CompressionStats::default();
        let framed = compress_frame(&payload, &config, &mut stats);
        let (algo, _) = read_frame_header(&framed).unwrap();
        let decoded = CompressionAlgorithm::from_byte(algo as u8);
        prop_assert!(decoded.is_some(),
            "algorithm byte 0x{:02x} not decodable", algo as u8);
    }
}

// ── Large payload round-trip ──────────────────────────────────────────────

proptest! {
    #[test]
    fn round_trip_max_size(
        payload in arb_large_payload(),
        algo in arb_algorithm(),
    ) {
        let config = CompressionConfig {
            algorithm: algo,
            level: 3,
            min_compress_bytes: 0,
        };
        let mut stats = CompressionStats::default();
        let framed = compress_frame(&payload, &config, &mut stats);
        let recovered = decompress_frame(&framed).expect("decompress large payload");
        prop_assert_eq!(recovered, payload);
    }
}

// ── Stats invariants ──────────────────────────────────────────────────────

proptest! {
    /// bytes_in always accumulates the payload length.
    #[test]
    fn round_trip_stats_bytes_in(
        payload in arb_payload(),
        config in arb_config(),
    ) {
        let mut stats = CompressionStats::default();
        let pre = stats.bytes_in;
        compress_frame(&payload, &config, &mut stats);
        prop_assert_eq!(stats.bytes_in, pre + payload.len() as u64);
    }

    /// bytes_out is at least FRAME_HEADER_LEN for non-empty output.
    #[test]
    fn round_trip_stats_bytes_out(
        payload in arb_payload(),
        config in arb_config(),
    ) {
        let mut stats = CompressionStats::default();
        compress_frame(&payload, &config, &mut stats);
        prop_assert!(stats.bytes_out >= FRAME_HEADER_LEN as u64,
            "bytes_out {} < FRAME_HEADER_LEN {}", stats.bytes_out, FRAME_HEADER_LEN);
    }

    /// ratio() is never negative or NaN.
    #[test]
    fn round_trip_stats_ratio_sane(
        payload in arb_payload(),
        config in arb_config(),
    ) {
        let mut stats = CompressionStats::default();
        compress_frame(&payload, &config, &mut stats);
        let r = stats.ratio();
        prop_assert!(r.is_finite());
        prop_assert!(r >= 0.0);
    }
}

// ── Corrupted input detection ─────────────────────────────────────────────

proptest! {
    /// Flipping a single bit in a compressed frame must not panic.
    #[test]
    fn decode_corrupted_input_bitflip(
        payload in arb_payload_nonempty(),
        config in arb_config(),
    ) {
        let mut stats = CompressionStats::default();
        let mut framed = compress_frame(&payload, &config, &mut stats);

        // Flip a bit somewhere in the framed buffer.
        let flip_pos = (framed.len() / 2).max(1);
        framed[flip_pos] ^= 0x01;

        // Must not panic; either error or successful decode.
        let _ = decompress_frame(&framed);
    }

    /// A truncated frame (shorter than FRAME_HEADER_LEN) must error.
    #[test]
    fn decode_truncated_frame(
        payload in arb_payload(),
        config in arb_config(),
    ) {
        let mut stats = CompressionStats::default();
        let framed = compress_frame(&payload, &config, &mut stats);
        for truncate_len in 0..FRAME_HEADER_LEN.min(framed.len()) {
            let truncated = &framed[..truncate_len];
            let result = decompress_frame(truncated);
            prop_assert!(result.is_err(),
                "truncated to {truncate_len} bytes should error");
        }
    }

    /// An unknown algorithm byte must produce an error.
    #[test]
    fn decode_unknown_algorithm(byte in (3u8..=255u8)) {
        let mut buf = vec![byte, 0x08, 0x00, 0x00, 0x00];
        buf.extend_from_slice(b"some data that is not valid compressed");
        let result = decompress_frame(&buf);
        prop_assert!(result.is_err(),
            "unknown algorithm byte 0x{byte:02x} should error");
    }
}

// ── Deterministic edge cases ──────────────────────────────────────────────

#[test]
fn round_trip_empty() {
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
        let mut stats = CompressionStats::default();
        let framed = compress_frame(b"", &config, &mut stats);
        assert_eq!(framed.len(), FRAME_HEADER_LEN);
        assert_eq!(framed[0], 0x00); // empty always stored uncompressed
        let recovered = decompress_frame(&framed).expect("empty decompress");
        assert!(recovered.is_empty(), "empty round-trip failed for {algo:?}");
    }
}

#[test]
fn round_trip_single_byte() {
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
        let mut stats = CompressionStats::default();
        let payload = &[0xABu8];
        let framed = compress_frame(payload, &config, &mut stats);
        let recovered = decompress_frame(&framed)
            .unwrap_or_else(|e| panic!("single-byte {algo:?} decompress failed: {e}"));
        assert_eq!(
            recovered, payload,
            "single-byte round-trip failed for {algo:?}"
        );
    }
}

#[test]
fn round_trip_incompressible_data() {
    // Highly entropic data (all byte values 0..255) — typically incompressible.
    let payload: Vec<u8> = (0u8..=255u8).collect();
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
        let mut stats = CompressionStats::default();
        let framed = compress_frame(&payload, &config, &mut stats);
        let recovered = decompress_frame(&framed)
            .unwrap_or_else(|e| panic!("incompressible {algo:?} decompress failed: {e}"));
        assert_eq!(
            recovered, payload,
            "incompressible round-trip failed for {algo:?}"
        );
    }
}

#[test]
fn round_trip_min_compress_boundary() {
    // Payload exactly one byte below threshold: stored uncompressed.
    let config = CompressionConfig {
        min_compress_bytes: 64,
        ..CompressionConfig::default()
    };
    let mut stats = CompressionStats::default();
    let payload = vec![0x41u8; 63];
    let framed = compress_frame(&payload, &config, &mut stats);
    assert_eq!(
        framed[0], 0x00,
        "payload below min_compress must be uncompressed"
    );
    let recovered = decompress_frame(&framed).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn round_trip_64kib_payload() {
    // 64 KiB payload: large enough to stress internal buffers.
    let payload = vec![0x42u8; 65536];
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
        let mut stats = CompressionStats::default();
        let framed = compress_frame(&payload, &config, &mut stats);
        let recovered = decompress_frame(&framed)
            .unwrap_or_else(|e| panic!("64 KiB {algo:?} decompress failed: {e}"));
        assert_eq!(recovered, payload, "64 KiB round-trip failed for {algo:?}");
    }
}

// ── Algorithm enumeration helper ──────────────────────────────────────────

#[test]
fn test_all_algorithms_roundtrip() {
    let payload = b"algorithm round-trip test pattern ".repeat(50);
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
        let mut stats = CompressionStats::default();
        let framed = compress_frame(&payload, &config, &mut stats);
        let recovered =
            decompress_frame(&framed).unwrap_or_else(|e| panic!("{algo:?} decompress failed: {e}"));
        assert_eq!(
            recovered,
            payload.as_slice(),
            "round-trip failed for {algo:?}"
        );
    }
}

#[test]
fn test_all_algorithms_empty_roundtrip() {
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
        let mut stats = CompressionStats::default();
        let framed = compress_frame(b"", &config, &mut stats);
        let recovered = decompress_frame(&framed)
            .unwrap_or_else(|e| panic!("{algo:?} empty decompress failed: {e}"));
        assert!(recovered.is_empty(), "empty round-trip failed for {algo:?}");
    }
}

// ── CompressedObjectStore integration ─────────────────────────────────────

#[test]
fn compressed_store_roundtrip_varied_payloads() {
    use tempfile::TempDir;
    use tidefs_compression::CompressedObjectStore;
    use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

    let dir = TempDir::new().unwrap();

    let short = b"AAAA".repeat(50);
    let medium = b"BBBB".repeat(200);
    let incompressible = {
        let mut v = Vec::with_capacity(256);
        for i in 0u8..=255u8 {
            v.push(i);
        }
        v
    };
    let test_cases: &[(&str, &[u8])] = &[
        ("empty", b""),
        ("single_byte", b"X"),
        ("short_compressible", &short),
        ("medium_compressible", &medium),
        ("incompressible", &incompressible),
    ];

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
        let mut store = CompressedObjectStore::new(
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap(),
            config,
        );

        for (name, payload) in test_cases {
            store.put_named(name, payload).unwrap();
            let recovered = store
                .get_named(name)
                .unwrap()
                .unwrap_or_else(|| panic!("{algo:?}: get_named({name}) returned None"));
            assert_eq!(
                recovered, *payload,
                "{algo:?}: round-trip mismatch for '{name}'"
            );
        }
    }
}

// ── CompressionError display ──────────────────────────────────────────────

#[test]
fn compression_error_display() {
    let e = CompressionError::FrameTooShort { len: 2 };
    assert!(e.to_string().contains("too short"));

    let e = CompressionError::UnknownAlgorithm { byte: 0xFF };
    assert!(e.to_string().contains("unknown"));

    let e = CompressionError::DecompressionFailed("test".into());
    assert!(e.to_string().contains("decompression failed"));

    // FrameTooShort via decompress_frame
    let result = decompress_frame(&[0x00, 0x01]);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("too short"), "got: {msg}");
}
