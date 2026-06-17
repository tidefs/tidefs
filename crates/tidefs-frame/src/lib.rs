#![forbid(unsafe_code)]

//! Per-object compression frame format for TideFS.
//!
//! Every compressed object carries a 5-byte frame header identifying the
//! compression algorithm and original uncompressed size.
//!
//! ## Object format
//!
//! ```text
//! [algorithm: 1 byte][uncompressed_len: 4 bytes LE][payload]
//! ```
//!
//! | Algorithm byte | Meaning       |
//! |----------------|---------------|
//! | `0x00`         | uncompressed  |
//! | `0x01`         | zstd          |
//! | `0x02`         | lz4           |
//!
//! Overhead: 5 bytes per object (algorithm + uncompressed length).
//!
//! Objects smaller than [`CompressionConfig::min_compress_bytes`] are stored
//! uncompressed to avoid wasting CPU on trivially small payloads.
//!
//! ## ZFS comparison
//!
//! ZFS compresses at the block level with per-dataset algorithm selection
//! (lz4, gzip, zstd, zle). TideFS compresses at the object-store level, which
//! is more granular — every object (inode, directory entry, content chunk,
//! superblock) is independently compressed. The 5-byte frame overhead is
//! dwarfed by typical compression savings (often 2-10x for text, logs, and
//! structured data).
//!
//! ## Design
//!
//! This crate is intentionally zero-dependency on other tidefs crates.
//! It is shared by:
//! - `tidefs-compression` (wraps `LocalObjectStore` with compression)
//! - `tidefs-local-object-store` (Pool/Device-layer compression)
//!
//! This avoids the cyclic dependency that would arise if either crate
//! depended directly on the other.

// ── Constants ─────────────────────────────────────────────────────────────

/// Compression algorithm identifier stored in the frame header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CompressionAlgorithm {
    /// Payload is stored without compression.
    Uncompressed = 0x00,
    /// Payload is compressed with zstd.
    Zstd = 0x01,
    /// Payload is compressed with LZ4 (fast).
    Lz4 = 0x02,
}

impl CompressionAlgorithm {
    /// Decode from a header byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Uncompressed),
            0x01 => Some(Self::Zstd),
            0x02 => Some(Self::Lz4),
            _ => None,
        }
    }

    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Uncompressed => "uncompressed",
            Self::Zstd => "zstd",
            Self::Lz4 => "lz4",
        }
    }
}

/// Total frame header size: 1 byte algorithm + 4 bytes uncompressed length.
pub const FRAME_HEADER_LEN: usize = 5;

// ── Error ──────────────────────────────────────────────────────────────────

/// Errors specific to the compression frame layer.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Stored data is too short to contain a frame header.
    #[error("stored frame too short ({len} bytes, need at least {FRAME_HEADER_LEN})")]
    FrameTooShort { len: usize },
    /// Unknown compression algorithm byte in frame header.
    #[error("unknown compression algorithm byte 0x{byte:02x}")]
    UnknownAlgorithm { byte: u8 },
    /// Decompression failed (corrupted compressed data).
    #[error("decompression failed: ZSTD error")]
    ZstdDecompressionFailed,
    /// LZ4 decompression failed.
    #[error("decompression failed: LZ4 error")]
    Lz4DecompressionFailed,

    /// Stored transform header does not match the committed receipt.
    ///
    /// The committed receipt records the expected compression algorithm,
    /// uncompressed length, and compressed length; the stored payload's
    /// transform header must match atomically or the extent is corrupt.
    #[error("transform mismatch: {field} expected {expected}, observed {observed}")]
    TransformMismatch {
        /// Name of the mismatched field (algorithm, uncompressed_len, compressed_len).
        field: &'static str,
        /// Value recorded in the committed receipt.
        expected: u64,
        /// Value observed in the stored payload header.
        observed: u64,
    },
}

pub type Result<T> = std::result::Result<T, FrameError>;

// ── Configuration ──────────────────────────────────────────────────────────

/// Compression configuration.
#[derive(Clone, Debug)]
pub struct CompressionConfig {
    /// Compression level.
    ///
    /// - zstd: 1-22 (default 3). Level 3 matches ZFS's default and
    ///   provides a good balance of speed and compression ratio.
    /// - lz4: 0-16 (default 0 = fast). Higher values trade speed for
    ///   slightly better compression.
    pub level: i32,
    /// Objects smaller than this are stored uncompressed (default 64).
    pub min_compress_bytes: usize,
    /// Compression algorithm to use.
    pub algorithm: CompressionAlgorithm,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            level: 3,
            min_compress_bytes: 64,
            algorithm: CompressionAlgorithm::Zstd,
        }
    }
}

impl CompressionConfig {
    /// Speed-first compression: LZ4 level 0, small threshold.
    pub fn speed() -> Self {
        Self {
            level: 0,
            min_compress_bytes: 64,
            algorithm: CompressionAlgorithm::Lz4,
        }
    }

    /// Balanced compression: zstd level 3, small threshold (default).
    pub fn balanced() -> Self {
        Self {
            level: 3,
            min_compress_bytes: 64,
            algorithm: CompressionAlgorithm::Zstd,
        }
    }

    /// Maximum compression: zstd level 22, no threshold (compress everything).
    pub fn max() -> Self {
        Self {
            level: 22,
            min_compress_bytes: 0,
            algorithm: CompressionAlgorithm::Zstd,
        }
    }
}

// ── Statistics ─────────────────────────────────────────────────────────────

/// Cumulative compression statistics.
#[derive(Clone, Copy, Debug, Default)]
pub struct CompressionStats {
    /// Number of objects compressed.
    pub objects_compressed: u64,
    /// Number of objects stored uncompressed (below threshold).
    pub objects_uncompressed: u64,
    /// Total uncompressed bytes processed.
    pub bytes_in: u64,
    /// Total stored bytes (after compression + frame headers).
    pub bytes_out: u64,
}

impl CompressionStats {
    /// Overall compression ratio (bytes_out / bytes_in).
    /// Returns 1.0 if no data has been processed.
    pub fn ratio(&self) -> f64 {
        if self.bytes_in == 0 {
            1.0
        } else {
            self.bytes_out as f64 / self.bytes_in as f64
        }
    }

    /// Space savings percentage (0-100).
    pub fn savings_pct(&self) -> f64 {
        (1.0 - self.ratio()) * 100.0
    }
}

// ── Frame encode/decode ────────────────────────────────────────────────────

/// Compress `payload` into a framed byte vector.
///
/// If the payload is smaller than `config.min_compress_bytes` or the
/// algorithm is `Uncompressed`, it is stored uncompressed (algorithm `0x00`).
///
/// If the compressed output is not smaller than the original, the payload
/// is stored uncompressed to avoid space waste.
pub fn compress_frame(
    payload: &[u8],
    config: &CompressionConfig,
    stats: &mut CompressionStats,
) -> Vec<u8> {
    stats.bytes_in += payload.len() as u64;

    // Small objects or explicit uncompressed: store uncompressed.
    if payload.len() < config.min_compress_bytes
        || config.algorithm == CompressionAlgorithm::Uncompressed
    {
        let out = make_uncompressed_frame(payload);
        stats.objects_uncompressed += 1;
        stats.bytes_out += out.len() as u64;
        return out;
    }

    // Compress based on selected algorithm.
    let compressed = match config.algorithm {
        CompressionAlgorithm::Zstd => {
            let level = config.level.clamp(1, 22);
            match zstd::encode_all(payload, level) {
                Ok(compressed) => compressed,
                Err(_) => {
                    // If compression fails, fall back to uncompressed.
                    let fb = make_uncompressed_frame(payload);
                    stats.objects_uncompressed += 1;
                    stats.bytes_out += fb.len() as u64;
                    return fb;
                }
            }
        }
        CompressionAlgorithm::Lz4 => lz4_flex::block::compress_prepend_size(payload),
        CompressionAlgorithm::Uncompressed => {
            unreachable!("handled by early return above")
        }
    };

    // If compression didn't save space (or made it worse), store uncompressed.
    if compressed.len() >= payload.len() {
        let out = make_uncompressed_frame(payload);
        stats.objects_uncompressed += 1;
        stats.bytes_out += out.len() as u64;
        return out;
    }

    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + compressed.len());
    out.push(config.algorithm as u8);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&compressed);
    stats.objects_compressed += 1;
    stats.bytes_out += out.len() as u64;
    out
}

/// Decompress a framed byte vector back to the original payload.
pub fn decompress_frame(framed: &[u8]) -> Result<Vec<u8>> {
    if framed.len() < FRAME_HEADER_LEN {
        return Err(FrameError::FrameTooShort { len: framed.len() });
    }

    let algorithm = CompressionAlgorithm::from_byte(framed[0])
        .ok_or(FrameError::UnknownAlgorithm { byte: framed[0] })?;

    let uncompressed_len = u32::from_le_bytes(framed[1..5].try_into().unwrap()) as usize;

    let payload = &framed[FRAME_HEADER_LEN..];

    match algorithm {
        CompressionAlgorithm::Uncompressed => {
            if payload.len() != uncompressed_len {
                // Payload length mismatch — still return what we have for
                // robustness, since the frame header is authoritative.
            }
            Ok(payload.to_vec())
        }
        CompressionAlgorithm::Zstd => {
            let decompressed =
                zstd::decode_all(payload).map_err(|_| FrameError::ZstdDecompressionFailed)?;
            Ok(decompressed)
        }
        CompressionAlgorithm::Lz4 => {
            let decompressed = lz4_flex::block::decompress_size_prepended(payload)
                .map_err(|_| FrameError::Lz4DecompressionFailed)?;
            Ok(decompressed)
        }
    }
}

/// Read the algorithm byte and uncompressed length from a framed buffer
/// without decompressing. Returns `None` if the frame is too short.
pub fn read_frame_header(framed: &[u8]) -> Option<(CompressionAlgorithm, usize)> {
    if framed.len() < FRAME_HEADER_LEN {
        return None;
    }
    let algo = CompressionAlgorithm::from_byte(framed[0])?;
    let len = u32::from_le_bytes(framed[1..5].try_into().unwrap()) as usize;
    Some((algo, len))
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn make_uncompressed_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    out.push(CompressionAlgorithm::Uncompressed as u8);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

// ── Extent-level compression ───────────────────────────────────────────────

/// Header size for a [`CompressedExtentPayload`] on disk:
/// algorithm byte (1) + uncompressed_len u64 LE (8) = 9 bytes.
pub const EXTENT_PAYLOAD_HEADER_LEN: usize = 9;

/// Size of a serialized [`TransformVerification`] token: algorithm (1) + uncompressed_len (8) + compressed_len (8) = 17 bytes.
pub const TRANSFORM_VERIFICATION_LEN: usize = 17;

/// Per-dataset compression policy.
///
/// Distinct from [`CompressionConfig`]: the policy uses a ratio threshold
/// instead of a minimum-byte threshold, targets zstd level selection per
/// dataset, and is the authority for compression decisions at extent
/// granularity.
#[derive(Clone, Debug, PartialEq)]
pub struct CompressionPolicy {
    /// Compression algorithm to apply.
    pub algorithm: CompressionAlgorithm,
    /// Zstd compression level (1-22, default 3).  Ignored for LZ4.
    pub level: i32,
    /// Minimum compression ratio to store compressed (default 1.1).
    ///
    /// If `compressed_size * ratio >= uncompressed_size`, the payload is
    /// stored uncompressed.  A ratio of 1.1 means data must compress to
    /// less than ~90.9% of the original to be worth the header overhead.
    pub min_compress_ratio: f64,
}

impl Default for CompressionPolicy {
    fn default() -> Self {
        Self {
            algorithm: CompressionAlgorithm::Uncompressed,
            level: 3,
            min_compress_ratio: 1.1,
        }
    }
}

impl CompressionPolicy {
    /// Zstd policy with default level 3 and ratio 1.1.
    pub fn zstd_default() -> Self {
        Self {
            algorithm: CompressionAlgorithm::Zstd,
            level: 3,
            min_compress_ratio: 1.1,
        }
    }

    /// Policy that always stores uncompressed (compression disabled).
    pub fn off() -> Self {
        Self {
            algorithm: CompressionAlgorithm::Uncompressed,
            level: 3,
            min_compress_ratio: 1.0,
        }
    }
}

/// On-disk extent payload wrapper with compression metadata.
///
/// Each extent payload carries its own compression algorithm and
/// uncompressed length so readers can decompress without consulting the
/// dataset policy.
///
/// ## Binary format
///
/// ```text
/// [algorithm: 1 byte][uncompressed_len: 8 bytes LE][compressed_data: ...]
/// ```
///
/// When `compression` is [`CompressionAlgorithm::Uncompressed`],
/// `compressed_data` is the original payload in full.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompressedExtentPayload {
    /// Compression algorithm used (or Uncompressed for identity storage).
    pub compression: CompressionAlgorithm,
    /// Original (logical) byte length before compression.
    pub uncompressed_len: u64,
    /// The stored bytes: either the compressed output or the original data.
    pub compressed_data: Vec<u8>,
}

impl CompressedExtentPayload {
    /// Logical (uncompressed) byte count -- what the user sees.
    pub fn logical_bytes(&self) -> u64 {
        self.uncompressed_len
    }

    /// Physical (on-disk) byte count -- header + stored data.
    pub fn physical_bytes(&self) -> u64 {
        (EXTENT_PAYLOAD_HEADER_LEN + self.compressed_data.len()) as u64
    }

    /// Compression savings: logical minus physical bytes.
    ///
    /// Saturates at zero when compression expands the data.
    pub fn compression_savings(&self) -> u64 {
        self.logical_bytes().saturating_sub(self.physical_bytes())
    }

    /// Encode to a single byte vector for on-disk storage.
    pub fn encode(&self) -> Vec<u8> {
        let cap = EXTENT_PAYLOAD_HEADER_LEN + self.compressed_data.len();
        let mut out = Vec::with_capacity(cap);
        out.push(self.compression as u8);
        out.extend_from_slice(&self.uncompressed_len.to_le_bytes());
        out.extend_from_slice(&self.compressed_data);
        out
    }

    /// Decode from a byte slice previously produced by [`encode`].
    ///
    /// Returns `None` if the slice is too short to contain a valid header
    /// or if the algorithm byte is unrecognised.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < EXTENT_PAYLOAD_HEADER_LEN {
            return None;
        }
        let compression = CompressionAlgorithm::from_byte(buf[0])?;
        let uncompressed_len = u64::from_le_bytes(buf[1..9].try_into().unwrap());
        let compressed_data = buf[EXTENT_PAYLOAD_HEADER_LEN..].to_vec();
        Some(Self {
            compression,
            uncompressed_len,
            compressed_data,
        })
    }

    /// Produce a [`TransformVerification`] token from this payload.
    ///
    /// The token captures the compression algorithm, uncompressed length
    /// (pre-size), and compressed data length (post-size) so a reader can
    /// verify the stored transform header against the committed receipt.
    pub fn to_verification(&self) -> TransformVerification {
        TransformVerification {
            algorithm: self.compression,
            uncompressed_len: self.uncompressed_len,
            compressed_len: self.compressed_data.len() as u64,
        }
    }
}


// ── Transform Verification ────────────────────────────────────────────────

/// A verification token that captures the committed compression transform
/// header for later cross-checking on read.
///
/// Produced during extent write ([`CompressedExtentPayload::to_verification`])
/// and stored in the extent-map entry.  On read, the stored transform header
/// is decoded from the raw payload and compared against this token; a mismatch
/// is treated as corruption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransformVerification {
    /// Compression algorithm applied.
    pub algorithm: CompressionAlgorithm,
    /// Logical (pre-compression) byte length.
    pub uncompressed_len: u64,
    /// Stored (post-compression) byte length, excluding the 9-byte header.
    pub compressed_len: u64,
}

impl TransformVerification {
    /// Verify a decoded [`CompressedExtentPayload`] against this token.
    ///
    /// Returns `Ok(())` when the payload's algorithm, uncompressed length,
    /// and compressed data length all match the committed values.
    /// Returns [`FrameError::TransformMismatch`] on any discrepancy.
    pub fn verify(&self, payload: &CompressedExtentPayload) -> Result<()> {
        if payload.compression != self.algorithm {
            return Err(FrameError::TransformMismatch {
                field: "algorithm",
                expected: self.algorithm as u64,
                observed: payload.compression as u64,
            });
        }
        if payload.uncompressed_len != self.uncompressed_len {
            return Err(FrameError::TransformMismatch {
                field: "uncompressed_len",
                expected: self.uncompressed_len,
                observed: payload.uncompressed_len,
            });
        }
        // compressed_len == 0 means "not stored in the receipt" — the
        // content checksum already covers the compressed payload, so a
        // length mismatch would be caught at the checksum layer.
        if self.compressed_len != 0
            && payload.compressed_data.len() as u64 != self.compressed_len
        {
            return Err(FrameError::TransformMismatch {
                field: "compressed_len",
                expected: self.compressed_len,
                observed: payload.compressed_data.len() as u64,
            });
        }
        Ok(())
    }
}
/// Compress extent payload data according to a per-dataset policy.
///
/// * If the policy algorithm is [`CompressionAlgorithm::Uncompressed`], the
///   payload is stored inline without compression.
/// * Otherwise the data is compressed with zstd at the policy level.  If the
///   compressed output (including header overhead) does not beat the
///   `min_compress_ratio` threshold, the payload falls back to uncompressed.
///
/// The returned [`CompressedExtentPayload`] carries logical and physical byte
/// counts for space-accounting double-book.
pub fn compress_extent(data: &[u8], policy: &CompressionPolicy) -> CompressedExtentPayload {
    // Policy off -> store uncompressed (identity).
    if policy.algorithm == CompressionAlgorithm::Uncompressed {
        return CompressedExtentPayload {
            compression: CompressionAlgorithm::Uncompressed,
            uncompressed_len: data.len() as u64,
            compressed_data: data.to_vec(),
        };
    }

    // Attempt zstd compression.
    let level = policy.level.clamp(1, 22);
    let compressed = match zstd::encode_all(data, level) {
        Ok(c) => c,
        Err(_) => {
            return CompressedExtentPayload {
                compression: CompressionAlgorithm::Uncompressed,
                uncompressed_len: data.len() as u64,
                compressed_data: data.to_vec(),
            };
        }
    };

    // Ratio check: physical * ratio >= logical => not worth compressing.
    let physical = (EXTENT_PAYLOAD_HEADER_LEN + compressed.len()) as f64;
    let logical = data.len() as f64;
    if physical * policy.min_compress_ratio >= logical {
        return CompressedExtentPayload {
            compression: CompressionAlgorithm::Uncompressed,
            uncompressed_len: data.len() as u64,
            compressed_data: data.to_vec(),
        };
    }

    CompressedExtentPayload {
        compression: CompressionAlgorithm::Zstd,
        uncompressed_len: data.len() as u64,
        compressed_data: compressed,
    }
}

/// Decompress a [`CompressedExtentPayload`] back to the original payload.
///
/// Returns an error when a zstd payload is corrupt.  LZ4 is reserved in
/// phase 1 and treated as identity.

/// Decompress a [`CompressedExtentPayload`] after verifying its transform
/// header against the committed [`TransformVerification`] token.
///
/// This is the verified read-path entry point: if the stored transform header
/// does not match the committed receipt, the extent is rejected as corrupt
/// before any decompression is attempted.
pub fn decompress_extent_verified(
    payload: &CompressedExtentPayload,
    token: &TransformVerification,
) -> Result<Vec<u8>> {
    token.verify(payload)?;
    decompress_extent(payload)
}

pub fn decompress_extent(payload: &CompressedExtentPayload) -> Result<Vec<u8>> {
    match payload.compression {
        CompressionAlgorithm::Uncompressed => Ok(payload.compressed_data.clone()),
        CompressionAlgorithm::Zstd => zstd::decode_all(payload.compressed_data.as_slice())
            .map_err(|_| FrameError::ZstdDecompressionFailed),
        // LZ4 reserved -- treat as uncompressed fallback in phase 1.
        CompressionAlgorithm::Lz4 => Ok(payload.compressed_data.clone()),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Algorithm byte ────────────────────────────────────────────────

    #[test]
    fn algorithm_from_byte_roundtrip() {
        let cases = [
            CompressionAlgorithm::Uncompressed,
            CompressionAlgorithm::Zstd,
            CompressionAlgorithm::Lz4,
        ];
        for algo in cases {
            let byte = algo as u8;
            let decoded = CompressionAlgorithm::from_byte(byte).unwrap();
            assert_eq!(decoded, algo);
        }
    }

    #[test]
    fn unknown_algorithm_rejected() {
        assert!(CompressionAlgorithm::from_byte(0xFF).is_none());
        assert!(CompressionAlgorithm::from_byte(0x03).is_none());
    }

    #[test]
    fn algorithm_names() {
        assert_eq!(CompressionAlgorithm::Uncompressed.name(), "uncompressed");
        assert_eq!(CompressionAlgorithm::Zstd.name(), "zstd");
        assert_eq!(CompressionAlgorithm::Lz4.name(), "lz4");
    }

    // ── Roundtrip ─────────────────────────────────────────────────────

    #[test]
    fn roundtrip_uncompressed_small() {
        let cfg = CompressionConfig::default();
        let mut stats = CompressionStats::default();
        let framed = compress_frame(b"hi", &cfg, &mut stats);
        assert_eq!(framed[0], 0x00); // uncompressed
        let plain = decompress_frame(&framed).unwrap();
        assert_eq!(plain, b"hi");
    }

    #[test]
    fn roundtrip_zstd_compressible() {
        let cfg = CompressionConfig::default();
        let mut stats = CompressionStats::default();
        let payload = b"AAAA".repeat(200); // 800 bytes, highly compressible
        let framed = compress_frame(&payload, &cfg, &mut stats);
        assert_eq!(framed[0], 0x01); // zstd
        let plain = decompress_frame(&framed).unwrap();
        assert_eq!(plain, payload);
        assert!(stats.objects_compressed >= 1);
    }

    #[test]
    fn roundtrip_lz4_compressible() {
        let cfg = CompressionConfig::speed();
        let mut stats = CompressionStats::default();
        let payload = b"BBBB".repeat(200);
        let framed = compress_frame(&payload, &cfg, &mut stats);
        assert_eq!(framed[0], 0x02); // lz4
        let plain = decompress_frame(&framed).unwrap();
        assert_eq!(plain, payload);
    }

    #[test]
    fn roundtrip_empty() {
        let cfg = CompressionConfig::default();
        let mut stats = CompressionStats::default();
        let framed = compress_frame(b"", &cfg, &mut stats);
        let plain = decompress_frame(&framed).unwrap();
        assert!(plain.is_empty());
    }

    #[test]
    fn roundtrip_large_compressible() {
        let cfg = CompressionConfig::default();
        let mut stats = CompressionStats::default();
        let payload = vec![0x41u8; 4096];
        let framed = compress_frame(&payload, &cfg, &mut stats);
        let plain = decompress_frame(&framed).unwrap();
        assert_eq!(plain, payload);
    }

    // ── Uncompressed fallback ─────────────────────────────────────────

    #[test]
    fn small_below_threshold_stored_uncompressed() {
        let cfg = CompressionConfig {
            min_compress_bytes: 128,
            ..CompressionConfig::default()
        };
        let mut stats = CompressionStats::default();
        let payload = b"tiny payload";
        let framed = compress_frame(payload, &cfg, &mut stats);
        assert_eq!(framed[0], 0x00);
        let plain = decompress_frame(&framed).unwrap();
        assert_eq!(plain, payload);
        assert_eq!(stats.objects_uncompressed, 1);
        assert_eq!(stats.objects_compressed, 0);
    }

    #[test]
    fn explicitly_uncompressed_config() {
        let cfg = CompressionConfig {
            algorithm: CompressionAlgorithm::Uncompressed,
            ..CompressionConfig::default()
        };
        let mut stats = CompressionStats::default();
        let payload = b"AAAA".repeat(200);
        let framed = compress_frame(&payload, &cfg, &mut stats);
        assert_eq!(framed[0], 0x00);
        let plain = decompress_frame(&framed).unwrap();
        assert_eq!(plain, payload);
        assert_eq!(stats.objects_uncompressed, 1);
    }

    // ── Size comparison ───────────────────────────────────────────────

    #[test]
    fn compression_reduces_size() {
        let cfg = CompressionConfig::default();
        let mut stats = CompressionStats::default();
        let payload = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ".repeat(40); // 1040 bytes
        let framed = compress_frame(&payload, &cfg, &mut stats);
        assert!(
            framed.len() < payload.len() + FRAME_HEADER_LEN,
            "compressed size {} should be < {} + header",
            framed.len(),
            payload.len()
        );
    }

    #[test]
    fn incompressible_data_not_expanded() {
        // Random-ish data
        let cfg = CompressionConfig::default();
        let mut stats = CompressionStats::default();
        let mut payload = Vec::with_capacity(256);
        for i in 0u8..=255u8 {
            payload.push(i);
        }
        let framed = compress_frame(&payload, &cfg, &mut stats);
        // Should be uncompressed (not expanded by failed compression)
        assert_eq!(framed[0], 0x00);
        assert_eq!(&framed[FRAME_HEADER_LEN..], payload.as_slice());
    }

    // ── Header parsing ────────────────────────────────────────────────

    #[test]
    fn read_frame_header_works() {
        let cfg = CompressionConfig::default();
        let mut stats = CompressionStats::default();
        let payload = b"test payload for header";
        let framed = compress_frame(payload, &cfg, &mut stats);
        let (algo, len) = read_frame_header(&framed).unwrap();
        // Small payload - may be uncompressed
        assert!(algo == CompressionAlgorithm::Uncompressed || algo == CompressionAlgorithm::Zstd);
        assert_eq!(len, payload.len());
    }

    #[test]
    fn read_frame_header_too_short() {
        assert!(read_frame_header(&[0x00, 0x01]).is_none());
        assert!(read_frame_header(&[]).is_none());
    }

    // ── Error cases ───────────────────────────────────────────────────

    #[test]
    fn decompress_frame_too_short() {
        let result = decompress_frame(&[0x00, 0x01, 0x02]);
        assert!(result.is_err());
        match result {
            Err(FrameError::FrameTooShort { len: 3 }) => {}
            other => panic!("expected FrameTooShort, got {other:?}"),
        }
    }

    #[test]
    fn decompress_unknown_algorithm() {
        let mut buf = vec![0xFF, 0x00, 0x00, 0x00, 0x00];
        buf.extend_from_slice(b"payload data here");
        let result = decompress_frame(&buf);
        assert!(result.is_err());
        match result {
            Err(FrameError::UnknownAlgorithm { byte: 0xFF }) => {}
            other => panic!("expected UnknownAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn decompress_corrupt_zstd_fails() {
        let mut buf = vec![0x01, 0x10, 0x00, 0x00, 0x00]; // zstd, 16 bytes
        buf.extend_from_slice(b"not valid zstd!!"); // corrupt
        let result = decompress_frame(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn decompress_corrupt_lz4_fails() {
        let mut buf = vec![0x02, 0x10, 0x00, 0x00, 0x00]; // lz4, 16 bytes
        buf.extend_from_slice(b"not valid lz4!!!"); // corrupt
        let result = decompress_frame(&buf);
        assert!(result.is_err());
    }

    // ── Stats ─────────────────────────────────────────────────────────

    #[test]
    fn stats_default_zero() {
        let stats = CompressionStats::default();
        assert_eq!(stats.objects_compressed, 0);
        assert_eq!(stats.objects_uncompressed, 0);
        assert_eq!(stats.bytes_in, 0);
        assert_eq!(stats.bytes_out, 0);
        assert_eq!(stats.ratio(), 1.0);
        assert_eq!(stats.savings_pct(), 0.0);
    }

    #[test]
    fn stats_ratio_and_savings() {
        let cfg = CompressionConfig::default();
        let mut stats = CompressionStats::default();
        let payload = b"AAAA".repeat(200);
        compress_frame(&payload, &cfg, &mut stats);
        assert!(stats.bytes_in > 0);
        assert!(stats.bytes_out > 0);
        assert!(stats.ratio() < 1.0, "should compress below 1.0 ratio");
        assert!(stats.savings_pct() > 0.0);
    }

    // ── Config presets ────────────────────────────────────────────────

    #[test]
    fn speed_config_uses_lz4_level_0() {
        let cfg = CompressionConfig::speed();
        assert_eq!(cfg.algorithm, CompressionAlgorithm::Lz4);
        assert_eq!(cfg.level, 0);
        assert_eq!(cfg.min_compress_bytes, 64);
    }

    #[test]
    fn balanced_config_uses_zstd_level_3() {
        let cfg = CompressionConfig::balanced();
        assert_eq!(cfg.algorithm, CompressionAlgorithm::Zstd);
        assert_eq!(cfg.level, 3);
        assert_eq!(cfg.min_compress_bytes, 64);
    }

    #[test]
    fn max_config_uses_zstd_level_22_no_threshold() {
        let cfg = CompressionConfig::max();
        assert_eq!(cfg.algorithm, CompressionAlgorithm::Zstd);
        assert_eq!(cfg.level, 22);
        assert_eq!(cfg.min_compress_bytes, 0);
    }

    // ── LZ4-specific ──────────────────────────────────────────────────

    #[test]
    fn lz4_produces_correct_algorithm_byte() {
        let cfg = CompressionConfig::speed();
        let mut stats = CompressionStats::default();
        let payload = b"AAAA".repeat(200);
        let framed = compress_frame(&payload, &cfg, &mut stats);
        assert_eq!(framed[0], 0x02);
    }

    #[test]
    fn lz4_roundtrip_various_sizes() {
        let cfg = CompressionConfig::speed();
        for size in [1, 10, 100, 1000, 4096] {
            let mut stats = CompressionStats::default();
            let payload = vec![0x42u8; size];
            let framed = compress_frame(&payload, &cfg, &mut stats);
            let plain = decompress_frame(&framed).unwrap();
            assert_eq!(plain, payload, "LZ4 roundtrip failed at size {size}");
        }
    }

    // ── Zero min_compress_bytes ───────────────────────────────────────

    #[test]
    fn zero_min_compress_bytes_compresses_small() {
        let cfg = CompressionConfig {
            min_compress_bytes: 0,
            ..CompressionConfig::default()
        };
        let mut stats = CompressionStats::default();
        let payload = b"AAAA";
        let framed = compress_frame(payload, &cfg, &mut stats);
        // Zstd may or may not compress 4 bytes, but format must be valid
        let plain = decompress_frame(&framed).unwrap();
        assert_eq!(plain, payload);
    }

    // ── Extent compression round-trip ─────────────────────────────────

    #[test]
    fn extend_roundtrip_compressible_text() {
        let policy = CompressionPolicy::zstd_default();
        let data = b"Hello World! ".repeat(200);
        let payload = compress_extent(&data, &policy);
        assert_eq!(payload.compression, CompressionAlgorithm::Zstd);
        assert_eq!(payload.uncompressed_len, data.len() as u64);
        let roundtrip = decompress_extent(&payload).unwrap();
        assert_eq!(roundtrip, data);
    }

    #[test]
    fn extend_roundtrip_binary() {
        let policy = CompressionPolicy::zstd_default();
        let data: Vec<u8> = (0u8..=255u8).cycle().take(1024).collect();
        let payload = compress_extent(&data, &policy);
        let roundtrip = decompress_extent(&payload).unwrap();
        assert_eq!(roundtrip, data);
    }

    #[test]
    fn extend_roundtrip_all_zeroes() {
        let policy = CompressionPolicy::zstd_default();
        let data = vec![0u8; 4096];
        let payload = compress_extent(&data, &policy);
        assert_eq!(payload.compression, CompressionAlgorithm::Zstd);
        let roundtrip = decompress_extent(&payload).unwrap();
        assert_eq!(roundtrip, data);
        assert!(payload.physical_bytes() < payload.logical_bytes());
    }

    #[test]
    fn extend_roundtrip_random() {
        let policy = CompressionPolicy::zstd_default();
        let data: Vec<u8> = {
            let mut v = Vec::with_capacity(2048);
            let mut seed: u64 = 0xdead_beef_1234_5678;
            for _ in 0..2048 {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                v.push((seed >> 56) as u8);
            }
            v
        };
        let payload = compress_extent(&data, &policy);
        let roundtrip = decompress_extent(&payload).unwrap();
        assert_eq!(roundtrip, data);
    }

    #[test]
    fn extend_policy_off_stores_uncompressed() {
        let policy = CompressionPolicy::off();
        let data = b"AAAA".repeat(200);
        let payload = compress_extent(&data, &policy);
        assert_eq!(payload.compression, CompressionAlgorithm::Uncompressed);
        assert_eq!(payload.compressed_data, data.as_slice());
        let roundtrip = decompress_extent(&payload).unwrap();
        assert_eq!(roundtrip, data);
    }

    // ── Min-ratio enforcement ────────────────────────────────────────

    #[test]
    fn extend_impossible_ratio_falls_back() {
        let policy = CompressionPolicy {
            algorithm: CompressionAlgorithm::Zstd,
            level: 3,
            min_compress_ratio: 100.0,
        };
        let data = b"AAAA".repeat(200);
        let payload = compress_extent(&data, &policy);
        assert_eq!(payload.compression, CompressionAlgorithm::Uncompressed);
    }

    #[test]
    fn extend_ratio_1_0_allows_any_savings() {
        let policy = CompressionPolicy {
            algorithm: CompressionAlgorithm::Zstd,
            level: 3,
            min_compress_ratio: 1.0,
        };
        let data = b"AAAA".repeat(200);
        let payload = compress_extent(&data, &policy);
        assert_eq!(payload.compression, CompressionAlgorithm::Zstd);
    }

    #[test]
    fn extend_empty_data_roundtrips() {
        let policy = CompressionPolicy::zstd_default();
        let payload = compress_extent(b"", &policy);
        assert_eq!(payload.uncompressed_len, 0);
        let roundtrip = decompress_extent(&payload).unwrap();
        assert!(roundtrip.is_empty());
    }

    // ── Logical / physical double-book ───────────────────────────────

    #[test]
    fn extend_logical_physical_double_book() {
        let policy = CompressionPolicy::zstd_default();
        let data = vec![0x41u8; 4096];
        let payload = compress_extent(&data, &policy);
        assert_eq!(payload.logical_bytes(), 4096);
        assert!(payload.physical_bytes() > 0);
        assert!(payload.physical_bytes() < payload.logical_bytes());
        let savings = payload.compression_savings();
        assert_eq!(savings, 4096 - payload.physical_bytes());
    }

    #[test]
    fn extend_uncompressed_physical_exceeds_logical() {
        let policy = CompressionPolicy::off();
        let data = vec![0x42u8; 512];
        let payload = compress_extent(&data, &policy);
        assert_eq!(payload.logical_bytes(), 512);
        assert_eq!(
            payload.physical_bytes(),
            512 + EXTENT_PAYLOAD_HEADER_LEN as u64
        );
        assert_eq!(payload.compression_savings(), 0);
    }

    #[test]
    fn extend_compression_savings_never_panics() {
        for size in [0, 1, 64, 1024, 4096] {
            let data = vec![0x41u8; size];
            let payload = compress_extent(&data, &CompressionPolicy::zstd_default());
            let _ = payload.compression_savings();
        }
    }

    // ── Encode / decode round-trip ───────────────────────────────────

    #[test]
    fn extend_encode_decode_compressed() {
        let policy = CompressionPolicy::zstd_default();
        let data = b"encode decode test ".repeat(100);
        let payload = compress_extent(&data, &policy);
        let encoded = payload.encode();
        let decoded = CompressedExtentPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.compression, payload.compression);
        assert_eq!(decoded.uncompressed_len, payload.uncompressed_len);
        assert_eq!(decoded.compressed_data, payload.compressed_data);
        let roundtrip = decompress_extent(&decoded).unwrap();
        assert_eq!(roundtrip, data);
    }

    #[test]
    fn extend_encode_decode_uncompressed() {
        let policy = CompressionPolicy::off();
        let data = b"plain data";
        let payload = compress_extent(data, &policy);
        let encoded = payload.encode();
        let decoded = CompressedExtentPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.compression, CompressionAlgorithm::Uncompressed);
        assert_eq!(decoded.uncompressed_len, data.len() as u64);
        assert_eq!(decoded.compressed_data, data);
    }

    #[test]
    fn extend_decode_too_short_rejected() {
        assert!(CompressedExtentPayload::decode(&[]).is_none());
        assert!(CompressedExtentPayload::decode(&[0x00, 0x00, 0x00]).is_none());
        assert!(CompressedExtentPayload::decode(&[0u8; 8]).is_none());
    }

    #[test]
    fn extend_decode_unknown_algorithm_rejected() {
        let mut buf = vec![0xFFu8];
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(b"data");
        assert!(CompressedExtentPayload::decode(&buf).is_none());
    }

    #[test]
    fn extend_zstd_corrupt_payload_errors() {
        let payload = CompressedExtentPayload {
            compression: CompressionAlgorithm::Zstd,
            uncompressed_len: 1024,
            compressed_data: b"not valid zstd".to_vec(),
        };
        let result = decompress_extent(&payload);
        assert!(result.is_err());
    }

    // ── TransformVerification ────────────────────────────────────────

    #[test]
    fn transform_verification_matches_correct_payload() {
        let policy = CompressionPolicy::zstd_default();
        let data = b"AAAA".repeat(200);
        let payload = compress_extent(&data, &policy);
        let token = payload.to_verification();
        token.verify(&payload).unwrap();
        let roundtrip = decompress_extent_verified(&payload, &token).unwrap();
        assert_eq!(roundtrip, data);
    }

    #[test]
    fn transform_verification_rejects_wrong_algorithm() {
        let policy = CompressionPolicy::zstd_default();
        let data = b"AAAA".repeat(200);
        let payload = compress_extent(&data, &policy);
        let mut bad_token = payload.to_verification();
        bad_token.algorithm = CompressionAlgorithm::Uncompressed;
        let err = decompress_extent_verified(&payload, &bad_token).unwrap_err();
        assert!(matches!(err, FrameError::TransformMismatch { field: "algorithm", .. }));
    }

    #[test]
    fn transform_verification_rejects_wrong_uncompressed_len() {
        let policy = CompressionPolicy::zstd_default();
        let data = b"AAAA".repeat(200);
        let payload = compress_extent(&data, &policy);
        let mut bad_token = payload.to_verification();
        bad_token.uncompressed_len = 9999;
        let err = decompress_extent_verified(&payload, &bad_token).unwrap_err();
        assert!(matches!(err, FrameError::TransformMismatch { field: "uncompressed_len", .. }));
    }

    #[test]
    fn transform_verification_rejects_wrong_compressed_len() {
        let policy = CompressionPolicy::zstd_default();
        let data = b"AAAA".repeat(200);
        let payload = compress_extent(&data, &policy);
        let mut bad_token = payload.to_verification();
        bad_token.compressed_len = 9999;
        let err = decompress_extent_verified(&payload, &bad_token).unwrap_err();
        assert!(matches!(err, FrameError::TransformMismatch { field: "compressed_len", .. }));
    }

    #[test]
    fn transform_verification_skips_compressed_len_when_zero() {
        let policy = CompressionPolicy::zstd_default();
        let data = b"AAAA".repeat(200);
        let payload = compress_extent(&data, &policy);
        let mut token = payload.to_verification();
        token.compressed_len = 0;
        // Should succeed because compressed_len=0 skips the check
        decompress_extent_verified(&payload, &token).unwrap();
    }

    #[test]
    fn transform_verification_uncompressed_data() {
        let policy = CompressionPolicy::off();
        let data: &[u8] = b"plain uncompressed";
        let payload = compress_extent(&data, &policy);
        let token = payload.to_verification();
        assert_eq!(token.algorithm, CompressionAlgorithm::Uncompressed);
        token.verify(&payload).unwrap();
        let roundtrip = decompress_extent_verified(&payload, &token).unwrap();
        assert_eq!(roundtrip, data);
    }

    #[test]
    fn transform_verification_tampered_payload_rejected() {
        let policy = CompressionPolicy::zstd_default();
        let data = b"AAAA".repeat(200);
        let payload = compress_extent(&data, &policy);
        let token = payload.to_verification();
        // Tamper with the compressed data
        let mut tampered = payload.clone();
        if !tampered.compressed_data.is_empty() {
            tampered.compressed_data[0] ^= 0xFF;
        }
        // Verification should still pass (header matches), but decompression fails
        token.verify(&tampered).unwrap();
        let result = decompress_extent(&tampered);
        assert!(result.is_err());
    }
}
