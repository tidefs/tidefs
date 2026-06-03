//! CRC32C-verified transport message compression with per-message algorithm
//! negotiation and compressed-frame wire format.
//!
//! ## Compression pipeline
//!
//! The compression layer sits between message dispatch and the transport
//! wire encoder. Each outbound message can optionally be compressed using a
//! per-session negotiated algorithm. The compressed frame carries:
//!
//! - Algorithm tag (wire discriminant for None/Lz4/Zstd)
//! - Uncompressed payload length (for decompressed-size validation)
//! - Compressed payload length
//! - Compressed payload bytes
//! - CRC32C checksum over the frame prefix
//!
//! ## Wire format
//!
//! ```text
//! [algorithm:1][uncomp_len:4 LE][comp_len:4 LE][payload:n][CRC32C:4 LE]
//! ```
//!
//! Minimum frame size: 9 header bytes + 4 byte CRC32C = 13 bytes.
//! The CRC32C checksum covers the algorithm tag, both length fields, and
//! the compressed payload. CRC32C is hardware-accelerated and sufficient
//! for framing error detection; the transport MAC provides cryptographic
//! integrity for the transport payload.
//!
//! ## Per-session negotiation
//!
//! [`CompressionState`] tracks the negotiated algorithm and maintains
//! compression statistics (frames processed, bytes in/out, ratio).
//! Payloads below a configurable threshold skip compression entirely,
//! using the [`CompressionAlgorithm::None`] frame format for uniformity.
//!
//! ## Integration
//!
//! This module integrates with the session handshake via capability
//! negotiation (algorithm preference exchange) and applies compression
//! per-message before the transport envelope is framed.
//!
//! ## Per-session self-describing wire format
//!
//! Compressed frames carry a 2-byte marker prefix (`COMPRESSION_MARKER`)
//! so the receive path can auto-detect and decompress without relying on
//! hidden session-local compression state. Payloads without the marker are
//! passed through as raw uncompressed data.

use std::fmt;

// ---------------------------------------------------------------------------
// Domain-separation constants
// ---------------------------------------------------------------------------

/// 2-byte marker prepended to compressed frames so the receiver can
/// distinguish compressed from uncompressed payloads without local state.
pub const COMPRESSION_MARKER: [u8; 2] = [0x1C, 0xCC];

/// Minimum compressed frame size (header + empty payload + CRC32C).
/// 9-byte header + 4-byte CRC32C = 13 bytes (not including the marker).
const MIN_FRAME_SIZE: usize = 13;

/// Header size before payload: algorithm (1) + uncomp_len (4) + comp_len (4).
const FRAME_HEADER_SIZE: usize = 9;

// ---------------------------------------------------------------------------
// CompressionAlgorithm
// ---------------------------------------------------------------------------

/// Supported compression algorithms for transport message payloads.
///
/// Each variant has a stable wire tag used in the compressed frame header.
/// Tags are permanently assigned: None=0, Lz4=1, Zstd=2.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum CompressionAlgorithm {
    /// No compression; payload is stored as-is in the compressed frame.
    None = 0,
    /// LZ4 fast compression via the `lz4_flex` crate (pure Rust).
    Lz4 = 1,
    /// Zstd compression at default level via the `zstd` crate.
    Zstd = 2,
}

impl CompressionAlgorithm {
    /// Wire tag for serialization.
    #[must_use]
    pub fn wire_tag(self) -> u8 {
        self as u8
    }

    /// Look up a [`CompressionAlgorithm`] from its wire tag.
    ///
    /// Returns `None` if the tag is not recognized (forward-compatible
    /// extension: receivers ignore unknown algorithm tags gracefully).
    #[must_use]
    pub fn from_wire_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::None),
            1 => Some(Self::Lz4),
            2 => Some(Self::Zstd),
            _ => None,
        }
    }

    /// All known variants in wire-tag order.
    pub const fn all() -> [CompressionAlgorithm; 3] {
        [Self::None, Self::Lz4, Self::Zstd]
    }

    /// Number of well-known algorithm variants.
    pub const fn known_count() -> usize {
        3
    }

    /// Human-readable label for this algorithm.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Lz4 => "lz4",
            Self::Zstd => "zstd",
        }
    }

    /// Whether this algorithm performs actual compression.
    #[must_use]
    pub fn is_compressed(self) -> bool {
        !matches!(self, Self::None)
    }
}

impl fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// CompressionError
// ---------------------------------------------------------------------------

/// Errors from the compression layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompressionError {
    /// The frame is too short to contain a valid compressed frame.
    FrameTooShort {
        /// Number of bytes received.
        got: usize,
    },
    /// The algorithm tag is not in the known set.
    UnknownAlgorithm {
        /// The unrecognized wire tag.
        tag: u8,
    },
    /// The CRC32C checksum does not match the frame prefix.
    IntegrityMismatch,
    /// Decompression of the compressed payload failed.
    DecompressionFailed {
        /// The algorithm that was attempted.
        algorithm: CompressionAlgorithm,
    },
    /// The decompressed payload size does not match `uncomp_len`.
    SizeMismatch {
        /// Expected size from the frame header.
        expected: u32,
        /// Actual decompressed size.
        got: usize,
    },
}

impl fmt::Display for CompressionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooShort { got } => {
                write!(
                    f,
                    "compressed frame too short: {got} bytes (min {MIN_FRAME_SIZE})"
                )
            }
            Self::UnknownAlgorithm { tag } => {
                write!(f, "unknown compression algorithm tag: {tag}")
            }
            Self::IntegrityMismatch => {
                write!(f, "CRC32C integrity mismatch on compressed frame")
            }
            Self::DecompressionFailed { algorithm } => {
                write!(f, "decompression failed for algorithm: {algorithm}")
            }
            Self::SizeMismatch { expected, got } => {
                write!(
                    f,
                    "decompressed size mismatch: expected {expected}, got {got}"
                )
            }
        }
    }
}

impl std::error::Error for CompressionError {}

// ---------------------------------------------------------------------------
// CompressedFrame
// ---------------------------------------------------------------------------

/// A decoded and CRC32C-verified compressed frame.
///
/// Produced by [`decompress_frame`]; carries the decompressed payload,
/// the algorithm used, and the verified CRC32C checksum.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompressedFrame {
    /// The compression algorithm that was applied.
    pub algorithm: CompressionAlgorithm,
    /// Original uncompressed payload length (from the frame header).
    pub uncomp_len: u32,
    /// The decompressed payload bytes.
    pub payload: Vec<u8>,
    /// The CRC32C checksum that was verified during decode.
    pub crc32c: u32,
}

// ---------------------------------------------------------------------------
// Core encode / decode
// ---------------------------------------------------------------------------

/// Compute the CRC32C checksum for a compressed frame prefix
/// (algorithm + lengths + payload, excluding the trailing checksum).
fn compute_frame_crc32c(prefix: &[u8]) -> u32 {
    crc32c::crc32c(prefix)
}

/// Compress a payload into a CRC32C-verified compressed frame.
///
/// For [`CompressionAlgorithm::None`], the payload is stored as-is with
/// `comp_len` equal to the payload length, producing a uniform frame
/// format for all algorithm choices.
///
/// Returns the wire-format bytes ready for transmission.
#[must_use]
pub fn compress_frame(algorithm: CompressionAlgorithm, payload: &[u8]) -> Vec<u8> {
    let uncomp_len = payload.len() as u32;

    let compressed: Vec<u8> = match algorithm {
        CompressionAlgorithm::None => payload.to_vec(),
        CompressionAlgorithm::Lz4 => lz4_flex::compress_prepend_size(payload),
        CompressionAlgorithm::Zstd => {
            zstd::encode_all(payload, 0).unwrap_or_else(|_| payload.to_vec())
        }
    };
    let comp_len = compressed.len() as u32;

    // Build frame: header + compressed payload + CRC32C.
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + compressed.len() + 4);
    frame.push(algorithm.wire_tag());
    frame.extend_from_slice(&uncomp_len.to_le_bytes());
    frame.extend_from_slice(&comp_len.to_le_bytes());
    frame.extend_from_slice(&compressed);

    let crc = compute_frame_crc32c(&frame);
    frame.extend_from_slice(&crc.to_le_bytes());

    frame
}

/// Decompress and verify a CRC32C-verified compressed frame.
///
/// # Errors
///
/// Returns [`CompressionError`] on any failure: frame too short, unknown
/// algorithm tag, CRC32C checksum mismatch, decompression failure,
/// or uncompressed-size mismatch.
pub fn decompress_frame(data: &[u8]) -> Result<CompressedFrame, CompressionError> {
    if data.len() < MIN_FRAME_SIZE {
        return Err(CompressionError::FrameTooShort { got: data.len() });
    }

    let integrity_start = data.len() - 4;
    let framed = &data[..integrity_start];
    let stored_crc = u32::from_le_bytes(data[integrity_start..].try_into().unwrap());

    // Verify CRC32C before touching any other field.
    let expected = compute_frame_crc32c(framed);
    if stored_crc != expected {
        return Err(CompressionError::IntegrityMismatch);
    }

    if framed.len() < FRAME_HEADER_SIZE {
        return Err(CompressionError::FrameTooShort { got: data.len() });
    }

    let algorithm_tag = framed[0];
    let algorithm = CompressionAlgorithm::from_wire_tag(algorithm_tag)
        .ok_or(CompressionError::UnknownAlgorithm { tag: algorithm_tag })?;

    let uncomp_len = u32::from_le_bytes([framed[1], framed[2], framed[3], framed[4]]);
    let comp_len = u32::from_le_bytes([framed[5], framed[6], framed[7], framed[8]]) as usize;

    if framed.len() < FRAME_HEADER_SIZE + comp_len {
        return Err(CompressionError::FrameTooShort { got: data.len() });
    }

    let compressed = &framed[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + comp_len];

    let payload: Vec<u8> = match algorithm {
        CompressionAlgorithm::None => compressed.to_vec(),
        CompressionAlgorithm::Lz4 => lz4_flex::decompress_size_prepended(compressed)
            .map_err(|_| CompressionError::DecompressionFailed { algorithm })?,
        CompressionAlgorithm::Zstd => zstd::decode_all(compressed)
            .map_err(|_| CompressionError::DecompressionFailed { algorithm })?,
    };

    if payload.len() != uncomp_len as usize {
        return Err(CompressionError::SizeMismatch {
            expected: uncomp_len,
            got: payload.len(),
        });
    }

    Ok(CompressedFrame {
        algorithm,
        uncomp_len,
        payload,
        crc32c: stored_crc,
    })
}

// ---------------------------------------------------------------------------
// Marker-based encode / decode (self-describing wire format)
// ---------------------------------------------------------------------------

/// Build a wire-format compressed payload.
///
/// Returns `[COMPRESSION_MARKER][compress_frame(algorithm, payload)]`.
/// The marker makes the frame self-describing on the receive path.
#[must_use]
pub fn encode_compressed_payload(algorithm: CompressionAlgorithm, payload: &[u8]) -> Vec<u8> {
    let inner = compress_frame(algorithm, payload);
    let mut out = Vec::with_capacity(COMPRESSION_MARKER.len() + inner.len());
    out.extend_from_slice(&COMPRESSION_MARKER);
    out.extend_from_slice(&inner);
    out
}

/// Check whether `data` starts with the compression marker.
#[must_use]
pub fn is_marked_compression(data: &[u8]) -> bool {
    data.len() >= COMPRESSION_MARKER.len() && data[..COMPRESSION_MARKER.len()] == COMPRESSION_MARKER
}

/// Decompress a marked payload (marker strip + decode + verify).
///
/// Returns `None` when the payload does not start with the compression
/// marker (caller should treat it as raw uncompressed data).
pub fn decode_compressed_payload(data: &[u8]) -> Option<Result<CompressedFrame, CompressionError>> {
    is_marked_compression(data).then(|| decompress_frame(&data[COMPRESSION_MARKER.len()..]))
}

// ---------------------------------------------------------------------------
// Threshold-based compression helper
// ---------------------------------------------------------------------------

/// Compress a payload with a configurable threshold.
///
/// Payloads smaller than `threshold` bytes bypass compression and use
/// [`CompressionAlgorithm::None`] frame format. Payloads at or above the
/// threshold are compressed with the requested algorithm.
#[must_use]
pub fn compress_frame_with_threshold(
    algorithm: CompressionAlgorithm,
    payload: &[u8],
    threshold: usize,
) -> Vec<u8> {
    if payload.len() < threshold || algorithm == CompressionAlgorithm::None {
        compress_frame(CompressionAlgorithm::None, payload)
    } else {
        compress_frame(algorithm, payload)
    }
}

// ---------------------------------------------------------------------------
// CompressionConfig
// ---------------------------------------------------------------------------

/// Configuration governing per-message compression behavior for a session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompressionConfig {
    /// The negotiated compression algorithm.
    pub algorithm: CompressionAlgorithm,
    /// Payloads smaller than this byte count skip compression.
    pub threshold: usize,
}

impl CompressionConfig {
    /// Create a new config.
    #[must_use]
    pub fn new(algorithm: CompressionAlgorithm, threshold: usize) -> Self {
        Self {
            algorithm,
            threshold,
        }
    }

    /// Whether this config actually requests compression.
    ///
    /// Returns `true` when the algorithm is not `None`.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.algorithm != CompressionAlgorithm::None
    }

    /// Whether this config is the disabled default.
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        self.algorithm == CompressionAlgorithm::None && self.threshold == 0
    }

    /// Config that disables all compression.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            algorithm: CompressionAlgorithm::None,
            threshold: 0,
        }
    }
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            algorithm: CompressionAlgorithm::None,
            // Skip compression for frames under 256 bytes by default.
            threshold: 256,
        }
    }
}

// ---------------------------------------------------------------------------
// CompressionState
// ---------------------------------------------------------------------------

/// Per-session compression state.
///
/// Tracks the negotiated algorithm configuration and maintains throughput
/// counters (frames processed, bytes before/after compression, ratio).
#[derive(Clone, Debug)]
pub struct CompressionState {
    /// Active compression configuration.
    pub config: CompressionConfig,
    /// Number of outbound frames compressed.
    pub frames_compressed: u64,
    /// Number of inbound frames decompressed.
    pub frames_decompressed: u64,
    /// Total uncompressed payload bytes processed (send payload + received
    /// post-decompression).
    pub total_uncompressed_bytes: u64,
    /// Total wire bytes of compressed frames (send output + received input).
    pub total_compressed_bytes: u64,
}

impl CompressionState {
    /// Create a new state with the given config.
    #[must_use]
    pub fn new(config: CompressionConfig) -> Self {
        Self {
            config,
            frames_compressed: 0,
            frames_decompressed: 0,
            total_uncompressed_bytes: 0,
            total_compressed_bytes: 0,
        }
    }

    /// Compress a payload (outbound path) and update counters.
    #[must_use]
    pub fn compress(&mut self, payload: &[u8]) -> Vec<u8> {
        let frame =
            compress_frame_with_threshold(self.config.algorithm, payload, self.config.threshold);
        self.frames_compressed += 1;
        self.total_uncompressed_bytes += payload.len() as u64;
        self.total_compressed_bytes += frame.len() as u64;
        frame
    }

    /// Decompress a frame (inbound path) and update counters.
    ///
    /// # Errors
    ///
    /// Returns [`CompressionError`] on verification or decompression failure.
    pub fn decompress(&mut self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let frame = decompress_frame(data)?;
        self.frames_decompressed += 1;
        self.total_compressed_bytes += data.len() as u64;
        self.total_uncompressed_bytes += frame.payload.len() as u64;
        Ok(frame.payload)
    }

    /// Overall compression ratio (compressed / uncompressed).
    ///
    /// Returns 1.0 when no data has been processed.
    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        if self.total_uncompressed_bytes == 0 {
            1.0
        } else {
            self.total_compressed_bytes as f64 / self.total_uncompressed_bytes as f64
        }
    }

    /// Reset all counters to zero (keeps the config).
    pub fn reset_counters(&mut self) {
        self.frames_compressed = 0;
        self.frames_decompressed = 0;
        self.total_uncompressed_bytes = 0;
        self.total_compressed_bytes = 0;
    }
}

impl Default for CompressionState {
    fn default() -> Self {
        Self::new(CompressionConfig::default())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // CompressionAlgorithm tests
    // -----------------------------------------------------------------------

    #[test]
    fn algorithm_wire_tags_are_deterministic() {
        assert_eq!(CompressionAlgorithm::None.wire_tag(), 0);
        assert_eq!(CompressionAlgorithm::Lz4.wire_tag(), 1);
        assert_eq!(CompressionAlgorithm::Zstd.wire_tag(), 2);
    }

    #[test]
    fn algorithm_round_trip_known_tags() {
        for alg in CompressionAlgorithm::all() {
            let tag = alg.wire_tag();
            let restored = CompressionAlgorithm::from_wire_tag(tag);
            assert_eq!(restored, Some(alg), "round-trip failed for {alg}");
        }
    }

    #[test]
    fn algorithm_unknown_tag() {
        assert_eq!(CompressionAlgorithm::from_wire_tag(255), None);
        assert_eq!(CompressionAlgorithm::from_wire_tag(3), None);
    }

    #[test]
    fn algorithm_labels() {
        assert_eq!(CompressionAlgorithm::None.label(), "none");
        assert_eq!(CompressionAlgorithm::Lz4.label(), "lz4");
        assert_eq!(CompressionAlgorithm::Zstd.label(), "zstd");
    }

    #[test]
    fn algorithm_display() {
        assert_eq!(format!("{}", CompressionAlgorithm::None), "none");
        assert_eq!(format!("{}", CompressionAlgorithm::Lz4), "lz4");
        assert_eq!(format!("{}", CompressionAlgorithm::Zstd), "zstd");
    }

    #[test]
    fn algorithm_is_compressed() {
        assert!(!CompressionAlgorithm::None.is_compressed());
        assert!(CompressionAlgorithm::Lz4.is_compressed());
        assert!(CompressionAlgorithm::Zstd.is_compressed());
    }

    #[test]
    fn algorithm_known_count() {
        assert_eq!(CompressionAlgorithm::known_count(), 3);
    }

    // -----------------------------------------------------------------------
    // Round-trip tests (each algorithm)
    // -----------------------------------------------------------------------

    #[test]
    fn round_trip_none() {
        let payload = b"hello, transport compression layer";
        let frame = compress_frame(CompressionAlgorithm::None, payload);
        let decoded = decompress_frame(&frame).unwrap();

        assert_eq!(decoded.algorithm, CompressionAlgorithm::None);
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.uncomp_len, payload.len() as u32);
    }

    #[test]
    fn round_trip_lz4() {
        let payload = b"The quick brown fox jumps over the lazy dog. ".repeat(50);
        let frame = compress_frame(CompressionAlgorithm::Lz4, &payload);
        let decoded = decompress_frame(&frame).unwrap();

        assert_eq!(decoded.algorithm, CompressionAlgorithm::Lz4);
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.uncomp_len, payload.len() as u32);
    }

    #[test]
    fn round_trip_zstd() {
        let payload = b"abcdefghijklmnopqrstuvwxyz".repeat(100);
        let frame = compress_frame(CompressionAlgorithm::Zstd, &payload);
        let decoded = decompress_frame(&frame).unwrap();

        assert_eq!(decoded.algorithm, CompressionAlgorithm::Zstd);
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.uncomp_len, payload.len() as u32);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn empty_payload_round_trip() {
        for alg in CompressionAlgorithm::all() {
            let frame = compress_frame(alg, b"");
            let decoded = decompress_frame(&frame).unwrap();
            assert_eq!(decoded.algorithm, alg);
            assert!(decoded.payload.is_empty());
            assert_eq!(decoded.uncomp_len, 0);
        }
    }

    #[test]
    fn single_byte_payload() {
        let payload = b"x";
        for alg in CompressionAlgorithm::all() {
            let frame = compress_frame(alg, payload);
            let decoded = decompress_frame(&frame).unwrap();
            assert_eq!(decoded.payload, payload);
        }
    }

    #[test]
    fn large_payload_64k() {
        let payload = vec![0xABu8; 65536];
        for alg in CompressionAlgorithm::all() {
            let frame = compress_frame(alg, &payload);
            let decoded = decompress_frame(&frame).unwrap();
            assert_eq!(decoded.payload, payload);
            assert_eq!(decoded.uncomp_len, 65536);
        }
    }

    // -----------------------------------------------------------------------
    // CRC32C tamper detection
    // -----------------------------------------------------------------------

    #[test]
    fn tamper_algorithm_byte_detected() {
        let payload = b"sensitive data that must not be altered";
        let mut frame = compress_frame(CompressionAlgorithm::Lz4, payload);

        // Flip the algorithm byte.
        frame[0] ^= 0xFF;

        let result = decompress_frame(&frame);
        assert!(matches!(result, Err(CompressionError::IntegrityMismatch)));
    }

    #[test]
    fn tamper_payload_byte_detected() {
        let payload = b"data integrity under test";
        let mut frame = compress_frame(CompressionAlgorithm::Zstd, payload);

        // Flip a byte in the compressed payload region.
        let mid = (frame.len() - 4) / 2;
        frame[mid] ^= 0x01;

        let result = decompress_frame(&frame);
        assert!(matches!(result, Err(CompressionError::IntegrityMismatch)));
    }

    #[test]
    fn tamper_uncomp_len_detected() {
        let payload = b"tamper the length field";
        let mut frame = compress_frame(CompressionAlgorithm::None, payload);

        // Modify uncomp_len (bytes 1-4).
        frame[1] ^= 0x01;

        let result = decompress_frame(&frame);
        assert!(matches!(result, Err(CompressionError::IntegrityMismatch)));
    }

    #[test]
    fn tamper_integrity_hash_detected() {
        let payload = b"hash tamper test";
        let mut frame = compress_frame(CompressionAlgorithm::Lz4, payload);

        // Flip a byte in the integrity hash region.
        let last = frame.len() - 1;
        frame[last] ^= 0xFF;

        let result = decompress_frame(&frame);
        assert!(matches!(result, Err(CompressionError::IntegrityMismatch)));
    }

    #[test]
    fn truncated_frame_detected() {
        let payload = b"will be truncated";
        let frame = compress_frame(CompressionAlgorithm::None, payload);

        // Truncate to less than MIN_FRAME_SIZE (now 13).
        let short = &frame[..10];
        let result = decompress_frame(short);
        assert!(matches!(
            result,
            Err(CompressionError::FrameTooShort { got: 10 })
        ));
    }

    // -----------------------------------------------------------------------
    // Corrupted payload (valid hash, invalid compressed data)
    // -----------------------------------------------------------------------

    #[test]
    fn corrupt_lz4_payload_detected() {
        let payload = vec![b'A'; 256];
        let mut frame = compress_frame(CompressionAlgorithm::Lz4, &payload);

        // Corrupt the compressed data after the header.
        let hash_start = frame.len() - 4;
        // Overwrite a substantial portion of the compressed payload with
        // garbage bytes to force LZ4 decompression failure.
        let corrupt_start = FRAME_HEADER_SIZE;
        let corrupt_end = hash_start.min(corrupt_start + 16);
        for b in &mut frame[corrupt_start..corrupt_end] {
            *b = 0xFF;
        }

        // Recompute the correct hash over the now-corrupt data.
        let new_hash = compute_frame_crc32c(&frame[..hash_start]);
        frame[hash_start..hash_start + 4].copy_from_slice(&new_hash.to_le_bytes());

        let result = decompress_frame(&frame);
        assert!(matches!(
            result,
            Err(CompressionError::DecompressionFailed { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Threshold skip
    // -----------------------------------------------------------------------

    #[test]
    fn threshold_skip_small_payload() {
        let payload = b"tiny";
        let threshold = 512;

        let frame = compress_frame_with_threshold(CompressionAlgorithm::Lz4, payload, threshold);
        let decoded = decompress_frame(&frame).unwrap();

        assert_eq!(decoded.algorithm, CompressionAlgorithm::None);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn threshold_compress_large_payload() {
        let payload = vec![b'B'; 1024];
        let threshold = 512;

        let frame = compress_frame_with_threshold(CompressionAlgorithm::Lz4, &payload, threshold);
        let decoded = decompress_frame(&frame).unwrap();

        assert_eq!(decoded.algorithm, CompressionAlgorithm::Lz4);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn threshold_at_boundary() {
        let payload = vec![b'C'; 256];
        let threshold = 256; // equality: >= threshold -> compress.

        let frame = compress_frame_with_threshold(CompressionAlgorithm::Lz4, &payload, threshold);
        let decoded = decompress_frame(&frame).unwrap();
        assert_eq!(decoded.algorithm, CompressionAlgorithm::Lz4);

        // One byte below threshold.
        let payload_small = vec![b'D'; 255];
        let frame2 =
            compress_frame_with_threshold(CompressionAlgorithm::Lz4, &payload_small, threshold);
        let decoded2 = decompress_frame(&frame2).unwrap();
        assert_eq!(decoded2.algorithm, CompressionAlgorithm::None);
    }

    // -----------------------------------------------------------------------
    // None algorithm passthrough
    // -----------------------------------------------------------------------

    #[test]
    fn none_algorithm_round_trip_with_threshold() {
        let payload = vec![b'E'; 2048];
        let threshold = 64;

        let frame = compress_frame_with_threshold(CompressionAlgorithm::None, &payload, threshold);
        let decoded = decompress_frame(&frame).unwrap();

        assert_eq!(decoded.algorithm, CompressionAlgorithm::None);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn none_algorithm_preserves_binary() {
        let payload = b"\x00\xFF\xAB\xCD\xEF";
        let frame = compress_frame(CompressionAlgorithm::None, payload);
        let decoded = decompress_frame(&frame).unwrap();
        assert_eq!(decoded.payload, payload);
    }

    // -----------------------------------------------------------------------
    // Frame size invariants
    // -----------------------------------------------------------------------

    #[test]
    fn frame_minimum_size() {
        let frame = compress_frame(CompressionAlgorithm::None, b"");
        assert_eq!(frame.len(), MIN_FRAME_SIZE);
    }

    #[test]
    fn frame_headers_consistent() {
        let payload = b"consistent header test";
        for alg in CompressionAlgorithm::all() {
            let frame = compress_frame(alg, payload);
            let decoded = decompress_frame(&frame).unwrap();
            assert_eq!(decoded.uncomp_len, payload.len() as u32);
        }
    }

    // -----------------------------------------------------------------------
    // CompressionState tests
    // -----------------------------------------------------------------------

    #[test]
    fn compression_state_defaults() {
        let state = CompressionState::default();
        assert_eq!(state.config.algorithm, CompressionAlgorithm::None);
        assert_eq!(state.config.threshold, 256);
        assert_eq!(state.frames_compressed, 0);
        assert_eq!(state.frames_decompressed, 0);
        assert!((state.compression_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn compression_state_compress_updates_counters() {
        let mut state = CompressionState::new(CompressionConfig::new(CompressionAlgorithm::Lz4, 0));
        let payload = b"counter test payload for compression state";

        let frame = state.compress(payload);
        assert_eq!(state.frames_compressed, 1);
        assert_eq!(state.total_uncompressed_bytes, payload.len() as u64);
        assert!(state.total_compressed_bytes > 0);

        let decompressed = state.decompress(&frame).unwrap();
        assert_eq!(state.frames_decompressed, 1);
        assert_eq!(decompressed, payload);
    }

    #[test]
    fn compression_state_ratio() {
        let mut state = CompressionState::new(CompressionConfig::new(CompressionAlgorithm::Lz4, 0));
        for _ in 0..10 {
            let payload = vec![0x42u8; 1024];
            let frame = state.compress(&payload);
            let _ = state.decompress(&frame).unwrap();
        }
        let ratio = state.compression_ratio();
        assert!(ratio < 1.0, "expected ratio < 1.0, got {ratio}");
        assert!(ratio > 0.0);
    }

    #[test]
    fn compression_state_reset_counters() {
        let mut state =
            CompressionState::new(CompressionConfig::new(CompressionAlgorithm::None, 64));
        let _ = state.compress(b"data");
        state
            .decompress(&compress_frame(CompressionAlgorithm::None, b"data"))
            .unwrap();

        assert!(state.frames_compressed > 0);
        assert!(state.frames_decompressed > 0);

        state.reset_counters();
        assert_eq!(state.frames_compressed, 0);
        assert_eq!(state.frames_decompressed, 0);
        assert_eq!(state.total_uncompressed_bytes, 0);
        assert_eq!(state.total_compressed_bytes, 0);
        assert_eq!(state.config.algorithm, CompressionAlgorithm::None);
    }

    // -----------------------------------------------------------------------
    // Unknown algorithm forward-compatibility
    // -----------------------------------------------------------------------

    #[test]
    fn unknown_algorithm_tag_rejected() {
        let payload = b"future algorithm test";
        let mut frame = Vec::new();
        frame.push(99u8);
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(payload);
        let hash = compute_frame_crc32c(&frame);
        frame.extend_from_slice(&hash.to_le_bytes());

        let result = decompress_frame(&frame);
        assert!(matches!(
            result,
            Err(CompressionError::UnknownAlgorithm { tag: 99 })
        ));
    }

    // -----------------------------------------------------------------------
    // Size mismatch detection
    // -----------------------------------------------------------------------

    #[test]
    fn size_mismatch_detected() {
        let payload = b"correct size";
        let mut frame = compress_frame(CompressionAlgorithm::None, payload);

        let fake_len = (payload.len() + 10) as u32;
        frame[1..5].copy_from_slice(&fake_len.to_le_bytes());

        let hash_start = frame.len() - 4;
        let new_hash = compute_frame_crc32c(&frame[..hash_start]);
        frame[hash_start..hash_start + 4].copy_from_slice(&new_hash.to_le_bytes());

        let result = decompress_frame(&frame);
        assert!(matches!(
            result,
            Err(CompressionError::SizeMismatch { expected, .. }) if expected == fake_len
        ));
    }

    // -----------------------------------------------------------------------
    // CompressionConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn config_disabled() {
        let cfg = CompressionConfig::disabled();
        assert_eq!(cfg.algorithm, CompressionAlgorithm::None);
        assert_eq!(cfg.threshold, 0);
        assert!(cfg.is_disabled());
        assert!(!cfg.is_active());
    }

    #[test]
    fn config_new() {
        let cfg = CompressionConfig::new(CompressionAlgorithm::Zstd, 512);
        assert_eq!(cfg.algorithm, CompressionAlgorithm::Zstd);
        assert_eq!(cfg.threshold, 512);
        assert!(cfg.is_active());
        assert!(!cfg.is_disabled());
    }

    // -----------------------------------------------------------------------
    // Round-trip for all algorithms with varying sizes
    // -----------------------------------------------------------------------

    #[test]
    fn round_trip_varying_sizes() {
        let sizes = [0, 1, 10, 100, 255, 256, 257, 1023, 1024, 4096];
        for &size in &sizes {
            let payload = vec![(size % 256) as u8; size];
            for alg in CompressionAlgorithm::all() {
                let frame = compress_frame(alg, &payload);
                let decoded = decompress_frame(&frame).unwrap();
                assert_eq!(
                    decoded.payload, payload,
                    "mismatch for alg={alg}, size={size}"
                );
                assert_eq!(decoded.uncomp_len, size as u32);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Marker-based encode/decode tests
    // -----------------------------------------------------------------------

    #[test]
    fn marker_encode_round_trip_lz4() {
        let payload = b"marker round trip with LZ4 compression".repeat(10);
        let wire = encode_compressed_payload(CompressionAlgorithm::Lz4, &payload);
        assert!(is_marked_compression(&wire));
        let decoded = decode_compressed_payload(&wire).unwrap().unwrap();
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn marker_encode_round_trip_zstd() {
        let payload = b"marker round trip with Zstd compression".repeat(10);
        let wire = encode_compressed_payload(CompressionAlgorithm::Zstd, &payload);
        assert!(is_marked_compression(&wire));
        let decoded = decode_compressed_payload(&wire).unwrap().unwrap();
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn unmarked_payload_not_detected() {
        let payload = b"this is a raw uncompressed payload";
        assert!(!is_marked_compression(payload));
        assert!(decode_compressed_payload(payload).is_none());
    }

    #[test]
    fn empty_payload_not_marked() {
        assert!(!is_marked_compression(b""));
    }

    #[test]
    fn short_bytes_not_marked() {
        assert!(!is_marked_compression(&[0x1C]));
    }

    #[test]
    fn marker_collision_detected_by_crc32c() {
        let mut fake = Vec::new();
        fake.extend_from_slice(&COMPRESSION_MARKER);
        fake.extend_from_slice(b"not a valid compressed frame");
        while fake.len() < COMPRESSION_MARKER.len() + MIN_FRAME_SIZE {
            fake.push(0);
        }
        let result = decode_compressed_payload(&fake);
        assert!(result.is_some());
        assert!(matches!(
            result.unwrap(),
            Err(CompressionError::IntegrityMismatch)
        ));
    }

    #[test]
    fn marker_is_deterministic() {
        assert_eq!(COMPRESSION_MARKER, [0x1C, 0xCC]);
    }

    #[test]
    fn marked_frame_starts_with_marker() {
        let payload = b"verify marker prefix";
        let wire = encode_compressed_payload(CompressionAlgorithm::Lz4, payload);
        assert_eq!(&wire[..2], &COMPRESSION_MARKER);
    }
}
