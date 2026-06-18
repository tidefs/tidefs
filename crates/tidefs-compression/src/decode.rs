// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Single-record decompression with algorithm detection.
//!
//! Reads the 5-byte frame header to determine the compression algorithm and
//! uncompressed length, then decompresses the payload.  Panic-free; all
//! failures are reported as [`crate::CompressionError`].

use tidefs_frame::{decompress_frame, read_frame_header, CompressionAlgorithm};

use crate::{CompressionError, Result};

/// Decompress a framed byte buffer back to the original payload.
///
/// The frame format is `[algorithm: 1 byte][uncompressed_len: 4 bytes LE][payload]`.
/// Algorithm detection is automatic: the first byte selects zstd, lz4, or
/// uncompressed (identity).
///
/// # Errors
///
/// * [`CompressionError::FrameTooShort`] when the input has fewer than 5 bytes.
/// * [`CompressionError::UnknownAlgorithm`] when the first byte is not a
///   recognised algorithm tag.
/// * [`CompressionError::DecompressionFailed`] when the compressed payload is
///   corrupt or truncated.
pub fn decompress(framed: &[u8]) -> Result<Vec<u8>> {
    decompress_frame(framed).map_err(|e| match e {
        tidefs_frame::FrameError::FrameTooShort { len } => CompressionError::FrameTooShort { len },
        tidefs_frame::FrameError::UnknownAlgorithm { byte } => {
            CompressionError::UnknownAlgorithm { byte }
        }
        tidefs_frame::FrameError::ZstdDecompressionFailed => {
            CompressionError::DecompressionFailed("zstd decompression failed".into())
        }
        tidefs_frame::FrameError::Lz4DecompressionFailed => {
            CompressionError::DecompressionFailed("lz4 decompression failed".into())
        }
        tidefs_frame::FrameError::TransformMismatch { field, expected, observed } => {
            CompressionError::TransformMismatch { field, expected, observed }
        }
    })
}

/// Read the algorithm and uncompressed length from a frame without
/// decompressing the payload.
///
/// Returns `None` when the frame is too short or the algorithm byte is
/// unrecognised.
pub fn read_header(framed: &[u8]) -> Option<(CompressionAlgorithm, usize)> {
    read_frame_header(framed)
}

/// Return `true` when a buffer looks like a valid compressed frame
/// (at least [`FRAME_HEADER_LEN`] bytes with a known algorithm byte).
pub fn is_compressed_frame(framed: &[u8]) -> bool {
    read_frame_header(framed).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_frame::CompressionAlgorithm;

    // --- decompress via compress round-trip ---------------------------

    #[test]
    fn decompress_zstd_roundtrip() {
        let payload = b"AAAA".repeat(200);
        let framed = crate::encode::compress(CompressionAlgorithm::Zstd, &payload).unwrap();
        let plain = decompress(&framed).unwrap();
        assert_eq!(plain, payload);
    }

    #[test]
    fn decompress_lz4_roundtrip() {
        let payload = b"BBBB".repeat(200);
        let framed = crate::encode::compress(CompressionAlgorithm::Lz4, &payload).unwrap();
        let plain = decompress(&framed).unwrap();
        assert_eq!(plain, payload);
    }

    #[test]
    fn decompress_uncompressed_roundtrip() {
        let payload = b"plain uncompressed data";
        let framed = crate::encode::compress(CompressionAlgorithm::Uncompressed, payload).unwrap();
        let plain = decompress(&framed).unwrap();
        assert_eq!(plain, payload);
    }

    #[test]
    fn decompress_empty() {
        let framed = crate::encode::compress(CompressionAlgorithm::Zstd, b"").unwrap();
        let plain = decompress(&framed).unwrap();
        assert!(plain.is_empty());
    }

    #[test]
    fn decompress_single_byte() {
        let framed = crate::encode::compress(CompressionAlgorithm::Lz4, b"X").unwrap();
        let plain = decompress(&framed).unwrap();
        assert_eq!(plain, b"X");
    }

    #[test]
    fn decompress_various_sizes() {
        for size in [0, 1, 10, 100, 1000, 4096, 65536] {
            let payload = vec![0x42u8; size];
            let framed = crate::encode::compress(CompressionAlgorithm::Zstd, &payload).unwrap();
            let plain = decompress(&framed).unwrap();
            assert_eq!(plain, payload, "size {size}");
        }
    }

    // --- error cases --------------------------------------------------

    #[test]
    fn decompress_too_short() {
        let err = decompress(&[0x00, 0x01, 0x02]).unwrap_err();
        assert!(matches!(err, CompressionError::FrameTooShort { len: 3 }));
    }

    #[test]
    fn decompress_empty_slice() {
        let err = decompress(&[]).unwrap_err();
        assert!(matches!(err, CompressionError::FrameTooShort { len: 0 }));
    }

    #[test]
    fn decompress_unknown_algorithm() {
        let mut buf = vec![0xFF, 0x00, 0x00, 0x00, 0x00];
        buf.extend_from_slice(b"payload");
        let err = decompress(&buf).unwrap_err();
        assert!(matches!(
            err,
            CompressionError::UnknownAlgorithm { byte: 0xFF }
        ));
    }

    #[test]
    fn decompress_corrupt_zstd_fails() {
        let mut buf = vec![0x01, 0x10, 0x00, 0x00, 0x00];
        buf.extend_from_slice(b"not valid zstd!!");
        let err = decompress(&buf).unwrap_err();
        assert!(matches!(err, CompressionError::DecompressionFailed(_)));
    }

    #[test]
    fn decompress_corrupt_lz4_fails() {
        let mut buf = vec![0x02, 0x10, 0x00, 0x00, 0x00];
        buf.extend_from_slice(b"not valid lz4!!!");
        let err = decompress(&buf).unwrap_err();
        assert!(matches!(err, CompressionError::DecompressionFailed(_)));
    }

    #[test]
    fn decompress_truncated_frame() {
        let mut buf = vec![0x01, 0x64, 0x00, 0x00, 0x00]; // zstd, 100 bytes claimed
        buf.extend_from_slice(b"too short"); // far less than 100 bytes
                                             // zstd decode_all should fail on truncated input
        let result = decompress(&buf);
        assert!(result.is_err());
    }

    // --- read_header --------------------------------------------------

    #[test]
    fn read_header_works() {
        let payload = b"test header";
        let framed = crate::encode::compress(CompressionAlgorithm::Zstd, payload).unwrap();
        let (algo, len) = read_header(&framed).unwrap();
        assert!(algo == CompressionAlgorithm::Zstd || algo == CompressionAlgorithm::Uncompressed);
        assert_eq!(len, payload.len());
    }

    #[test]
    fn read_header_too_short() {
        assert!(read_header(&[]).is_none());
        assert!(read_header(&[0x00, 0x01, 0x02]).is_none());
    }

    #[test]
    fn read_header_unknown_algorithm() {
        let buf = [0xFF, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(read_header(&buf).is_none());
    }

    // --- is_compressed_frame ------------------------------------------

    #[test]
    fn is_compressed_frame_true_for_valid() {
        let framed =
            crate::encode::compress(CompressionAlgorithm::Zstd, b"AAAA".repeat(50).as_slice())
                .unwrap();
        assert!(is_compressed_frame(&framed));
    }

    #[test]
    fn is_compressed_frame_false_for_short() {
        assert!(!is_compressed_frame(&[0x00, 0x01]));
    }

    #[test]
    fn is_compressed_frame_false_for_unknown_algo() {
        let buf = [0xFF, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(!is_compressed_frame(&buf));
    }
}
