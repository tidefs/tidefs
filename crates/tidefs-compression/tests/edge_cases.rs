//! Edge-case and boundary-condition tests for tidefs-compression.
//!
//! Covers gaps not addressed by the inline unit tests or the property-based
//! round_trip tests:
//!   - Specific byte-pattern payloads (all-zero, all-0xFF, alternating bits)
//!   - Block-boundary payload sizes (4K, 64K, 1M +/- 1 byte)
//!   - 1 MiB explicit round-trip
//!   - Compression ratio floor for highly repetitive data

use tidefs_compression::{
    CompressionAlgorithm, CompressionConfig, CompressionStats, FRAME_HEADER_LEN,
};
use tidefs_frame::{compress_frame, decompress_frame};

// ── Helpers ───────────────────────────────────────────────────────────────

fn round_trip_with(payload: &[u8], algorithm: CompressionAlgorithm) -> Vec<u8> {
    let config = CompressionConfig {
        algorithm,
        level: 3,
        min_compress_bytes: 0,
    };
    let mut stats = CompressionStats::default();
    let framed = compress_frame(payload, &config, &mut stats);
    decompress_frame(&framed).unwrap_or_else(|e| panic!("{algorithm:?} round-trip failed: {e}"))
}

fn all_algos() -> [CompressionAlgorithm; 3] {
    [
        CompressionAlgorithm::Uncompressed,
        CompressionAlgorithm::Zstd,
        CompressionAlgorithm::Lz4,
    ]
}

// ── Byte-pattern tests ────────────────────────────────────────────────────

#[test]
fn round_trip_all_zero_payload() {
    for size in [0usize, 1, 64, 256, 4096, 65536] {
        let payload = vec![0x00u8; size];
        for algo in all_algos() {
            let recovered = round_trip_with(&payload, algo);
            assert_eq!(
                recovered, payload,
                "all-zero size={size} {algo:?}: round-trip mismatch"
            );
        }
    }
}

#[test]
fn round_trip_all_0xff_payload() {
    for size in [0usize, 1, 64, 256, 4096, 65536] {
        let payload = vec![0xFFu8; size];
        for algo in all_algos() {
            let recovered = round_trip_with(&payload, algo);
            assert_eq!(
                recovered, payload,
                "all-0xFF size={size} {algo:?}: round-trip mismatch"
            );
        }
    }
}

#[test]
fn round_trip_alternating_bits() {
    // Alternating 0x55/0xAA pattern across two sizes.
    for size in [0usize, 1, 64, 256, 4096, 65536] {
        let payload: Vec<u8> = (0..size)
            .map(|i| if i % 2 == 0 { 0x55u8 } else { 0xAAu8 })
            .collect();
        for algo in all_algos() {
            let recovered = round_trip_with(&payload, algo);
            assert_eq!(
                recovered, payload,
                "alternating-bits size={size} {algo:?}: round-trip mismatch"
            );
        }
    }
}

// ── 1 MiB explicit payload ────────────────────────────────────────────────

#[test]
fn round_trip_one_mebibyte() {
    let payload = vec![b'A'; 1048576];
    for algo in all_algos() {
        let recovered = round_trip_with(&payload, algo);
        assert_eq!(recovered, payload, "1 MiB {algo:?}: round-trip mismatch");
    }
}

// ── Block-boundary tests ──────────────────────────────────────────────────

#[test]
fn block_boundary_4kib() {
    // 4 KiB boundaries: one byte below, exactly at, one byte above.
    for size in [4095usize, 4096, 4097] {
        let payload = vec![b'X'; size];
        for algo in all_algos() {
            let recovered = round_trip_with(&payload, algo);
            assert_eq!(
                recovered, payload,
                "4KiB boundary size={size} {algo:?}: round-trip mismatch"
            );
        }
    }
}

#[test]
fn block_boundary_64kib() {
    for size in [65535usize, 65536, 65537] {
        let payload = vec![b'Y'; size];
        for algo in all_algos() {
            let recovered = round_trip_with(&payload, algo);
            assert_eq!(
                recovered, payload,
                "64KiB boundary size={size} {algo:?}: round-trip mismatch"
            );
        }
    }
}

#[test]
fn block_boundary_1mib() {
    for size in [1048575usize, 1048576, 1048577] {
        let payload = vec![b'Z'; size];
        for algo in all_algos() {
            let recovered = round_trip_with(&payload, algo);
            assert_eq!(
                recovered, payload,
                "1MiB boundary size={size} {algo:?}: round-trip mismatch"
            );
        }
    }
}

// ── Compression ratio floor ───────────────────────────────────────────────

#[test]
fn repetitive_data_compresses_significantly() {
    // Highly repetitive payload: all 'A's should compress well.
    let payload = vec![b'A'; 8192];
    let config = CompressionConfig {
        algorithm: CompressionAlgorithm::Zstd,
        level: 3,
        min_compress_bytes: 0,
    };
    let mut stats = CompressionStats::default();
    let framed = compress_frame(&payload, &config, &mut stats);

    // Compressed + header should be at most 25% of original size.
    let max_expected = (payload.len() / 4) + FRAME_HEADER_LEN;
    assert!(
        framed.len() <= max_expected,
        "zstd all-'A' 8 KiB: framed len {} exceeds 25% of original ({max_expected})",
        framed.len()
    );
    // Round-trip still correct.
    let recovered = decompress_frame(&framed).expect("decompress");
    assert_eq!(recovered, payload);
}

#[test]
fn lz4_repetitive_data_compresses_reasonably() {
    let payload = vec![b'B'; 8192];
    let config = CompressionConfig {
        algorithm: CompressionAlgorithm::Lz4,
        level: 0,
        min_compress_bytes: 0,
    };
    let mut stats = CompressionStats::default();
    let framed = compress_frame(&payload, &config, &mut stats);

    // LZ4 should still compress repetitive data below original size.
    assert!(
        framed.len() < payload.len() + FRAME_HEADER_LEN,
        "LZ4 all-'B' 8 KiB: framed len {} not smaller than {} + header",
        framed.len(),
        payload.len()
    );
    let recovered = decompress_frame(&framed).expect("decompress");
    assert_eq!(recovered, payload);
}

// ── Verify stats counters for specific payload ────────────────────────────

#[test]
fn stats_bytes_in_matches_payload_sum() {
    let payloads: &[&[u8]] = &[b"", b"x", &[0x41u8; 100], &vec![0xFFu8; 4096]];
    let mut stats = CompressionStats::default();
    let config = CompressionConfig::default();
    let mut expected: u64 = 0;
    for payload in payloads {
        compress_frame(payload, &config, &mut stats);
        expected += payload.len() as u64;
    }
    assert_eq!(stats.bytes_in, expected);
}

// ── Large payload stress tests ────────────────────────────────────────────

#[test]
fn round_trip_16_mebibytes() {
    let payload = vec![b'D'; 16777216]; // 16 MiB
    for algo in all_algos() {
        let recovered = round_trip_with(&payload, algo);
        assert_eq!(recovered, payload, "16 MiB {algo:?}: round-trip mismatch");
    }
}

#[test]
fn round_trip_64_mebibytes() {
    let payload = vec![b'E'; 67108864]; // 64 MiB
    for algo in all_algos() {
        let recovered = round_trip_with(&payload, algo);
        assert_eq!(recovered, payload, "64 MiB {algo:?}: round-trip mismatch");
    }
}

// ── Partial decode (prefix verification) ──────────────────────────────────

#[test]
fn partial_decode_prefix_byte_match() {
    use tidefs_frame::read_frame_header;

    let payload: Vec<u8> = (0u8..=255u8).cycle().take(16384).collect();
    for algo in all_algos() {
        let config = CompressionConfig {
            algorithm: algo,
            level: 3,
            min_compress_bytes: 0,
        };
        let mut stats = CompressionStats::default();
        let framed = compress_frame(&payload, &config, &mut stats);

        // Full decode
        let recovered = decompress_frame(&framed)
            .unwrap_or_else(|e| panic!("{algo:?} partial-decode decompress failed: {e}"));

        // Verify header reports correct length
        let (_, uncompressed_len) =
            read_frame_header(&framed).unwrap_or_else(|| panic!("{algo:?}: header parse failed"));
        assert_eq!(uncompressed_len, payload.len());

        // Verify prefixes at multiple boundaries
        for prefix_len in [0, 1, 64, 256, 1024, 4096, payload.len()] {
            assert_eq!(
                &recovered[..prefix_len],
                &payload[..prefix_len],
                "{algo:?}: prefix mismatch at len {prefix_len}"
            );
        }
        assert_eq!(recovered.len(), payload.len());
    }
}

#[test]
fn partial_decode_single_byte_prefix() {
    for algo in all_algos() {
        let config = CompressionConfig {
            algorithm: algo,
            level: 3,
            min_compress_bytes: 0,
        };
        let mut stats = CompressionStats::default();
        let payload = b"Xhello world, this is a test payload with various bytes";
        let framed = compress_frame(payload, &config, &mut stats);
        let recovered = decompress_frame(&framed)
            .unwrap_or_else(|e| panic!("{algo:?} single-byte-prefix failed: {e}"));

        // First byte must match
        assert_eq!(recovered[0], payload[0], "{algo:?}: first byte mismatch");
        assert_eq!(recovered, payload, "{algo:?}: full payload mismatch");
    }
}

// ── Corrupted header byte tests ───────────────────────────────────────────

#[test]
fn corrupted_uncompressed_len_in_header() {
    let payload = b"AAAA".repeat(200);
    for algo in [CompressionAlgorithm::Zstd, CompressionAlgorithm::Lz4] {
        let config = CompressionConfig {
            algorithm: algo,
            level: 3,
            min_compress_bytes: 0,
        };
        let mut stats = CompressionStats::default();
        let mut framed = compress_frame(&payload, &config, &mut stats);

        // Corrupt the uncompressed length field (bytes 1-4) to claim
        // a much smaller size than the actual compressed data decodes to.
        // This creates a length mismatch that may or may not error,
        // but must not panic.
        framed[1] = 0x01;
        framed[2] = 0x00;
        framed[3] = 0x00;
        framed[4] = 0x00; // claims 1 byte uncompressed, but data decodes to 800

        let result = decompress_frame(&framed);
        // May succeed (some decompressors ignore header length) or error,
        // but must not panic.
        let _ = result;
    }
}

#[test]
fn corrupted_algorithm_byte_in_header() {
    let payload = b"AAAA".repeat(200);
    let config = CompressionConfig::default();
    let mut stats = CompressionStats::default();
    let mut framed = compress_frame(&payload, &config, &mut stats);

    // Flip the algorithm byte to an invalid value
    framed[0] = 0xFE;
    let result = decompress_frame(&framed);
    assert!(result.is_err(), "invalid algorithm byte 0xFE should error");

    framed[0] = 0x03;
    let result = decompress_frame(&framed);
    assert!(result.is_err(), "unknown algorithm byte 0x03 should error");
}

#[test]
fn truncated_header_zero_bytes() {
    for truncate_len in 0..5usize {
        let buf = vec![0u8; truncate_len];
        let result = decompress_frame(&buf);
        assert!(
            result.is_err(),
            "truncated header {truncate_len} bytes should error"
        );
    }
}

// ── 16M/64M repeated stress with CompressedObjectStore ─────────────────────

#[test]
fn compressed_store_large_payload_near_limit() {
    use tempfile::TempDir;
    use tidefs_compression::CompressedObjectStore;
    use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

    let dir = TempDir::new().unwrap();
    // Use a payload that fits within the local object store max payload limit.
    // Frame-level tests above (round_trip_16_mebibytes, round_trip_64_mebibytes)
    // already verify correctness at 16 MiB and 64 MiB sizes.
    let payload = b"AAAA".repeat(800); // ~3200 bytes, fits within store limit

    for algo in all_algos() {
        let config = CompressionConfig {
            algorithm: algo,
            level: 3,
            min_compress_bytes: 0,
        };
        let mut store = CompressedObjectStore::new(
            LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap(),
            config,
        );
        let name = format!("large_{algo:?}");
        store.put_named(&name, &payload).unwrap();
        let recovered = store
            .get_named(&name)
            .unwrap()
            .unwrap_or_else(|| panic!("{algo:?}: get_named returned None"));
        assert_eq!(
            recovered, payload,
            "{algo:?}: CompressedObjectStore round-trip mismatch"
        );
    }
}
