// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Single-record compression with algorithm selection and threshold gating.
//!
//! These functions are the low-level encode entry points for per-record
//! compression.  They produce the 5-byte frame format defined in
//! `tidefs-frame`: `[algorithm: 1 byte][uncompressed_len: 4 bytes LE][payload]`.
//!
//! For store-integrated compression with statistics tracking, use
//! [`crate::CompressedObjectStore`].

use tidefs_frame::{compress_frame, CompressionAlgorithm, CompressionConfig, CompressionStats};

use crate::algorithm::CompressionDecision;
use crate::Result;

/// Compress `input` with the given algorithm and return framed bytes.
///
/// The output includes the 5-byte frame header.  When compression would
/// expand the data, the original payload is stored uncompressed.
///
/// Uses per-algorithm default levels (zstd=3, lz4=0) and no minimum-size
/// threshold: every record is considered for compression.
pub fn compress(algorithm: CompressionAlgorithm, input: &[u8]) -> Result<Vec<u8>> {
    let config = CompressionConfig {
        algorithm,
        level: default_level_for(algorithm),
        min_compress_bytes: 0,
    };
    let mut stats = CompressionStats::default();
    Ok(compress_frame(input, &config, &mut stats))
}

/// Compress with a size-ratio threshold, returning a [`CompressionDecision`].
///
/// If the framed output (header + compressed payload) is not at most
/// `input.len() * threshold` bytes, or if compression falls back to
/// uncompressed, returns `Unchanged` with the original bytes.
///
/// * `threshold = 0.9`: keep only when saving >= 10% of space.
/// * `threshold = 1.0`: keep whenever it doesn't expand.
/// * `threshold = 0.0`: always return unchanged (compression disabled).
pub fn compress_with_threshold(
    algorithm: CompressionAlgorithm,
    threshold: f64,
    input: &[u8],
) -> Result<CompressionDecision> {
    if threshold <= 0.0 || algorithm == CompressionAlgorithm::Uncompressed {
        return Ok(CompressionDecision::Unchanged {
            original: input.to_vec(),
        });
    }

    let config = CompressionConfig {
        algorithm,
        level: default_level_for(algorithm),
        min_compress_bytes: 0,
    };
    let mut stats = CompressionStats::default();
    let framed = compress_frame(input, &config, &mut stats);

    let max_allowed = (input.len() as f64 * threshold) as usize;
    if framed.len() <= max_allowed {
        let detected_algo = CompressionAlgorithm::from_byte(framed[0])
            .unwrap_or(CompressionAlgorithm::Uncompressed);
        if detected_algo == CompressionAlgorithm::Uncompressed {
            return Ok(CompressionDecision::Unchanged {
                original: input.to_vec(),
            });
        }
        Ok(CompressionDecision::Compressed {
            algorithm: detected_algo,
            framed,
        })
    } else {
        Ok(CompressionDecision::Unchanged {
            original: input.to_vec(),
        })
    }
}

fn default_level_for(algo: CompressionAlgorithm) -> i32 {
    match algo {
        CompressionAlgorithm::Zstd => 3,
        CompressionAlgorithm::Lz4 => 0,
        CompressionAlgorithm::Uncompressed => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- compress + decompress round-trip -----------------------------

    #[test]
    fn compress_roundtrip_zstd() {
        let payload = b"AAAA".repeat(200);
        let framed = compress(CompressionAlgorithm::Zstd, &payload).unwrap();
        assert_eq!(framed[0], 0x01);
        let plain = crate::decode::decompress(&framed).unwrap();
        assert_eq!(plain, payload);
    }

    #[test]
    fn compress_roundtrip_lz4() {
        let payload = b"BBBB".repeat(200);
        let framed = compress(CompressionAlgorithm::Lz4, &payload).unwrap();
        assert_eq!(framed[0], 0x02);
        let plain = crate::decode::decompress(&framed).unwrap();
        assert_eq!(plain, payload);
    }

    #[test]
    fn compress_roundtrip_uncompressed() {
        let payload = b"plain text";
        let framed = compress(CompressionAlgorithm::Uncompressed, payload).unwrap();
        assert_eq!(framed[0], 0x00);
        let plain = crate::decode::decompress(&framed).unwrap();
        assert_eq!(plain, payload);
    }

    #[test]
    fn compress_empty_input() {
        let framed = compress(CompressionAlgorithm::Zstd, b"").unwrap();
        let plain = crate::decode::decompress(&framed).unwrap();
        assert!(plain.is_empty());
    }

    #[test]
    fn compress_single_byte() {
        let framed = compress(CompressionAlgorithm::Lz4, b"X").unwrap();
        let plain = crate::decode::decompress(&framed).unwrap();
        assert_eq!(plain, b"X");
    }

    #[test]
    fn compress_various_sizes() {
        for size in [0, 1, 10, 100, 1000, 4096, 65536] {
            let payload = vec![0x41u8; size];
            let framed = compress(CompressionAlgorithm::Zstd, &payload).unwrap();
            let plain = crate::decode::decompress(&framed).unwrap();
            assert_eq!(plain, payload, "roundtrip failed at size {size}");
        }
    }

    #[test]
    fn compress_reduces_size_for_repeated_data() {
        let payload = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ".repeat(40);
        let framed = compress(CompressionAlgorithm::Zstd, &payload).unwrap();
        assert!(
            framed.len() < payload.len() + 5,
            "compressed {}/{}+5",
            framed.len(),
            payload.len()
        );
    }

    // --- compress_with_threshold --------------------------------------

    #[test]
    fn threshold_zero_returns_unchanged() {
        let payload = b"AAAA".repeat(200);
        let d = compress_with_threshold(CompressionAlgorithm::Zstd, 0.0, &payload).unwrap();
        assert!(matches!(d, CompressionDecision::Unchanged { .. }));
    }

    #[test]
    fn threshold_uncompressed_algo_returns_unchanged() {
        let payload = b"AAAA".repeat(200);
        let d = compress_with_threshold(CompressionAlgorithm::Uncompressed, 0.9, &payload).unwrap();
        assert!(matches!(d, CompressionDecision::Unchanged { .. }));
    }

    #[test]
    fn threshold_allows_compressible_data() {
        let payload = b"AAAA".repeat(200);
        let d = compress_with_threshold(CompressionAlgorithm::Zstd, 0.9, &payload).unwrap();
        assert!(d.is_compressed());
        if let CompressionDecision::Compressed { algorithm, .. } = &d {
            assert_eq!(*algorithm, CompressionAlgorithm::Zstd);
        }
    }

    #[test]
    fn threshold_rejects_incompressible_data() {
        let mut payload = Vec::with_capacity(256);
        for i in 0u8..=255u8 {
            payload.push(i);
        }
        let d = compress_with_threshold(CompressionAlgorithm::Zstd, 0.5, &payload).unwrap();
        assert!(
            matches!(d, CompressionDecision::Unchanged { .. }),
            "incompressible data should be Unchanged"
        );
    }

    #[test]
    fn threshold_stored_len_accurate() {
        let payload = b"AAAA".repeat(200);
        let d = compress_with_threshold(CompressionAlgorithm::Zstd, 1.0, &payload).unwrap();
        let stored = d.stored_len();
        assert!(stored > 0);
        assert!(stored < payload.len() + 5);
    }

    #[test]
    fn threshold_unchanged_stored_len_equals_input() {
        let payload = b"AAAA".repeat(200);
        let d = compress_with_threshold(CompressionAlgorithm::Lz4, 0.0, &payload).unwrap();
        assert!(!d.is_compressed());
        assert_eq!(d.stored_len(), payload.len());
    }

    #[test]
    fn threshold_algorithm_byte_correct() {
        let payload = b"AAAA".repeat(200);
        let d = compress_with_threshold(CompressionAlgorithm::Lz4, 1.0, &payload).unwrap();
        assert_eq!(d.algorithm_byte(), 0x02);
    }

    #[test]
    fn threshold_empty_input() {
        let d = compress_with_threshold(CompressionAlgorithm::Zstd, 1.0, b"").unwrap();
        assert!(!d.is_compressed());
        assert_eq!(d.stored_len(), 0);
    }
}
