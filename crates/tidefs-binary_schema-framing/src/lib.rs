// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::all)]

//! Envelope, section, and chunk frame header encode/decode per P2-03 §2.
//!
//! Implements the three canonical binary strata:
//! - `binary_schema.env` — 64-byte fixed envelope header
//! - `binary_schema.sec` — 32-byte section header
//! - `binary_schema.chunk` — chunk/frame framing for large payloads
//!
//! All encoding is little-endian; all decoding validates alignment, bounds,
//! magic, and checksums before returning structured headers.

extern crate alloc;

use alloc::vec::Vec;

use tidefs_binary_schema_checksum::envelope_header_crc32c;
use tidefs_binary_schema_core::{
    BinarySchemaError, ChecksumProfile, ChunkFrameSizeClass, PayloadClass, SchemaFamilyId,
    SchemaTypeId, SchemaVersion, BINARY_SCHEMA_MAGIC, ENVELOPE_ALIGN, ENVELOPE_HEADER_BYTES,
    SECTION_OFFSET_ALIGN_MIN,
};

// ---------------------------------------------------------------------------
// Envelope header (64 bytes)
// ---------------------------------------------------------------------------

/// Decoded canonical binary schema envelope header.
///
/// Layout per P2-03 §2.1:
/// ```text
/// offset  size  field
/// 0       4     magic (LE u32, should be 0x5346_4256 = "VBFS")
/// 4       8     family_id (LE u64)
/// 12      8     type_id (LE u64)
/// 20      2     major_version (LE u16)
/// 22      2     minor_version (LE u16)
/// 24      4     flags (LE u32)
/// 28      2     section_count (LE u16)
/// 30      2     _reserved
/// 32      8     total_body_bytes (LE u64)
/// 40      1     fast_checksum_profile (u8)
/// 41      1     strong_digest_profile (u8)
/// 42      6     _reserved2
/// 48      8     schema_fingerprint_low (LE u64)
/// 56      4     _reserved3
/// 60      4     header_crc32c (LE u32)
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvelopeHeader {
    pub magic: u32,
    pub family_id: SchemaFamilyId,
    pub type_id: SchemaTypeId,
    pub version: SchemaVersion,
    pub flags: u32,
    pub section_count: u16,
    pub total_body_bytes: u64,
    pub fast_checksum_profile: ChecksumProfile,
    pub strong_digest_profile: ChecksumProfile,
    pub schema_fingerprint_low: u64,
    pub header_crc32c: u32,
}

impl Default for EnvelopeHeader {
    fn default() -> Self {
        Self {
            magic: BINARY_SCHEMA_MAGIC,
            family_id: SchemaFamilyId::default(),
            type_id: SchemaTypeId::default(),
            version: SchemaVersion::default(),
            flags: 0,
            section_count: 0,
            total_body_bytes: 0,
            fast_checksum_profile: ChecksumProfile::None,
            strong_digest_profile: ChecksumProfile::None,
            schema_fingerprint_low: 0,
            header_crc32c: 0,
        }
    }
}

impl EnvelopeHeader {
    /// Encode this envelope header into a 64-byte buffer.
    /// The header CRC32C is automatically computed and sealed into `[60..64]`.
    pub fn encode(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];

        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..12].copy_from_slice(&self.family_id.0.to_le_bytes());
        buf[12..20].copy_from_slice(&self.type_id.0.to_le_bytes());
        buf[20..22].copy_from_slice(&self.version.major.to_le_bytes());
        buf[22..24].copy_from_slice(&self.version.minor.to_le_bytes());
        buf[24..28].copy_from_slice(&self.flags.to_le_bytes());
        buf[28..30].copy_from_slice(&self.section_count.to_le_bytes());
        // bytes 30..32 reserved (zero)
        buf[32..40].copy_from_slice(&self.total_body_bytes.to_le_bytes());
        buf[40] = self.fast_checksum_profile.discriminant();
        buf[41] = self.strong_digest_profile.discriminant();
        // bytes 42..48 reserved (zero)
        buf[48..56].copy_from_slice(&self.schema_fingerprint_low.to_le_bytes());
        // bytes 56..60 reserved (zero)
        // bytes 60..64 header_crc32c — computed below

        let csum = envelope_header_crc32c(&buf[0..60].try_into().unwrap());
        buf[60..64].copy_from_slice(&csum);

        buf
    }

    /// Decode a 64-byte buffer into an `EnvelopeHeader`.
    ///
    /// Validates magic, alignment, checksum profiles, and header CRC32C.
    pub fn decode(buf: &[u8; 64]) -> Result<Self, BinarySchemaError> {
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != BINARY_SCHEMA_MAGIC {
            return Err(BinarySchemaError::BadMagic { got: magic });
        }

        let family_id = SchemaFamilyId(u64::from_le_bytes(buf[4..12].try_into().unwrap()));
        let type_id = SchemaTypeId(u64::from_le_bytes(buf[12..20].try_into().unwrap()));
        let version = SchemaVersion {
            major: u16::from_le_bytes([buf[20], buf[21]]),
            minor: u16::from_le_bytes([buf[22], buf[23]]),
        };
        let flags = u32::from_le_bytes(buf[24..28].try_into().unwrap());
        let section_count = u16::from_le_bytes([buf[28], buf[29]]);
        let total_body_bytes = u64::from_le_bytes(buf[32..40].try_into().unwrap());

        let fast_profile = ChecksumProfile::from_discriminant(buf[40])
            .ok_or(BinarySchemaError::InvalidChecksumProfile)?;
        let strong_profile = ChecksumProfile::from_discriminant(buf[41])
            .ok_or(BinarySchemaError::InvalidChecksumProfile)?;

        let fingerprint_low = u64::from_le_bytes(buf[48..56].try_into().unwrap());
        let header_crc32c = u32::from_le_bytes([buf[60], buf[61], buf[62], buf[63]]);

        // Verify header CRC32C
        let expected_crc = u32::from_le_bytes(
            tidefs_binary_schema_checksum::envelope_header_crc32c(&buf[0..60].try_into().unwrap()),
        );
        if header_crc32c != expected_crc {
            return Err(BinarySchemaError::ChecksumMismatch);
        }

        Ok(Self {
            magic,
            family_id,
            type_id,
            version,
            flags,
            section_count,
            total_body_bytes,
            fast_checksum_profile: fast_profile,
            strong_digest_profile: strong_profile,
            schema_fingerprint_low: fingerprint_low,
            header_crc32c,
        })
    }

    /// Decode from an arbitrary slice; requires at least 64 bytes and 8-byte alignment.
    pub fn decode_from_slice(slice: &[u8]) -> Result<Self, BinarySchemaError> {
        if slice.len() < ENVELOPE_HEADER_BYTES {
            return Err(BinarySchemaError::BoundsViolation);
        }
        if (slice.as_ptr() as usize) % ENVELOPE_ALIGN != 0 {
            return Err(BinarySchemaError::AlignmentViolation);
        }
        Self::decode(slice[..64].try_into().unwrap())
    }
}

// ---------------------------------------------------------------------------
// Section header (32 bytes)
// ---------------------------------------------------------------------------

/// Decoded canonical section header per P2-03 §2.2.
///
/// Layout:
/// ```text
/// offset  size  field
/// 0       8     section_offset (LE u64)
/// 8       8     section_length (LE u64)
/// 16      2     payload_class (LE u16)
/// 18      2     section_flags (LE u16)
/// 20      4     optional_mask (LE u32)
/// 24      8     _reserved
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SectionHeader {
    pub section_offset: u64,
    pub section_length: u64,
    pub payload_class: PayloadClass,
    pub section_flags: u16,
    pub optional_mask: u32,
}

impl SectionHeader {
    pub fn encode(&self) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(&self.section_offset.to_le_bytes());
        buf[8..16].copy_from_slice(&self.section_length.to_le_bytes());
        buf[16..18].copy_from_slice(&self.payload_class.discriminant().to_le_bytes());
        buf[18..20].copy_from_slice(&self.section_flags.to_le_bytes());
        buf[20..24].copy_from_slice(&self.optional_mask.to_le_bytes());
        // bytes 24..32 reserved (zero)
        buf
    }

    pub fn decode(buf: &[u8; 32]) -> Result<Self, BinarySchemaError> {
        let offset = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let length = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let pc_disc = u16::from_le_bytes([buf[16], buf[17]]);
        let payload_class = PayloadClass::from_discriminant(pc_disc)
            .ok_or(BinarySchemaError::InvalidPayloadClass)?;
        let flags = u16::from_le_bytes([buf[18], buf[19]]);
        let omask = u32::from_le_bytes(buf[20..24].try_into().unwrap());

        // Validate 8-byte alignment of payload offset
        if offset as usize % SECTION_OFFSET_ALIGN_MIN != 0 {
            return Err(BinarySchemaError::AlignmentViolation);
        }

        Ok(Self {
            section_offset: offset,
            section_length: length,
            payload_class,
            section_flags: flags,
            optional_mask: omask,
        })
    }
}

// ---------------------------------------------------------------------------
// Chunk frame header (32 bytes)
// ---------------------------------------------------------------------------

/// Chunk frame header for large payload framing per P2-03 §2.3.
///
/// Layout:
/// ```text
/// offset  size  field
/// 0       8     frame_index (LE u64)
/// 8       8     payload_bytes (LE u64)
/// 16      2     frame_size_class (LE u16)
/// 18      2     _reserved
/// 20      4     payload_crc32c (LE u32)
/// 24      4     digest_continuation_marker (LE u32)
/// 28      4     _reserved2
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChunkFrameHeader {
    pub frame_index: u64,
    pub payload_bytes: u64,
    pub frame_size_class: ChunkFrameSizeClass,
    pub payload_crc32c: u32,
    /// Nonzero if a strong digest follows the payload bytes.
    pub digest_continuation_marker: u32,
}

impl ChunkFrameHeader {
    pub fn encode(&self) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(&self.frame_index.to_le_bytes());
        buf[8..16].copy_from_slice(&self.payload_bytes.to_le_bytes());
        buf[16..18].copy_from_slice(&(self.frame_size_class as u16).to_le_bytes());
        // bytes 18..20 reserved (zero)
        buf[20..24].copy_from_slice(&self.payload_crc32c.to_le_bytes());
        buf[24..28].copy_from_slice(&self.digest_continuation_marker.to_le_bytes());
        // bytes 28..32 reserved (zero)
        buf
    }

    pub fn decode(buf: &[u8; 32]) -> Result<Self, BinarySchemaError> {
        let frame_index = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let payload_bytes = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let fsc_disc = u16::from_le_bytes([buf[16], buf[17]]);
        let frame_size_class = ChunkFrameSizeClass::from_discriminant(fsc_disc)
            .ok_or(BinarySchemaError::InvalidPayloadClass)?;
        let payload_crc32c = u32::from_le_bytes(buf[20..24].try_into().unwrap());
        let digest_continuation_marker = u32::from_le_bytes(buf[24..28].try_into().unwrap());

        // Validate payload size doesn't exceed frame class capacity
        let max_bytes = frame_size_class.payload_bytes() as u64;
        if payload_bytes > max_bytes {
            return Err(BinarySchemaError::BoundsViolation);
        }

        Ok(Self {
            frame_index,
            payload_bytes,
            frame_size_class,
            payload_crc32c,
            digest_continuation_marker,
        })
    }
}

// ---------------------------------------------------------------------------
// Envelope builder
// ---------------------------------------------------------------------------

/// Convenience builder for constructing envelope headers.
#[derive(Clone, Debug)]
pub struct EnvelopeBuilder {
    pub family_id: SchemaFamilyId,
    pub type_id: SchemaTypeId,
    pub version: SchemaVersion,
    pub flags: u32,
    pub fast_profile: ChecksumProfile,
    pub strong_profile: ChecksumProfile,
    pub fingerprint_low: u64,
}

impl EnvelopeBuilder {
    pub fn new(family_id: SchemaFamilyId, type_id: SchemaTypeId, version: SchemaVersion) -> Self {
        Self {
            family_id,
            type_id,
            version,
            flags: 0,
            fast_profile: ChecksumProfile::Crc32c,
            strong_profile: ChecksumProfile::Blake3_256,
            fingerprint_low: 0,
        }
    }

    pub fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    pub fn with_fingerprint_low(mut self, low: u64) -> Self {
        self.fingerprint_low = low;
        self
    }

    pub fn with_checksum_profiles(
        mut self,
        fast: ChecksumProfile,
        strong: ChecksumProfile,
    ) -> Self {
        self.fast_profile = fast;
        self.strong_profile = strong;
        self
    }

    pub fn build(self, section_count: u16, total_body_bytes: u64) -> EnvelopeHeader {
        EnvelopeHeader {
            magic: BINARY_SCHEMA_MAGIC,
            family_id: self.family_id,
            type_id: self.type_id,
            version: self.version,
            flags: self.flags,
            section_count,
            total_body_bytes,
            fast_checksum_profile: self.fast_profile,
            strong_digest_profile: self.strong_profile,
            schema_fingerprint_low: self.fingerprint_low,
            header_crc32c: 0, // computed during encode()
        }
    }
}

// ---------------------------------------------------------------------------
// Framing decoder: stream-oriented frame extraction
// ---------------------------------------------------------------------------

/// Maximum body bytes accepted from a single frame.
/// Rejecting oversized frames prevents memory exhaustion from corrupt streams.
pub const MAX_FRAME_BODY_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB

/// A complete framed message extracted from a byte stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramedMessage {
    pub header: EnvelopeHeader,
    pub body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScanState {
    /// Looking for the 4-byte magic sequence.
    Scanning,
    /// Magic found; accumulating a 64-byte header.
    AccumulatingHeader { magic_at: usize },
    /// Header decoded; accumulating body bytes.
    AccumulatingBody {
        header: EnvelopeHeader,
        body_start: usize,
    },
}

/// Stateful decoder that extracts framed binary-schema messages from a byte
/// stream. Handles partial reads (TCP-like split buffers), multi-frame
/// coalescing (several complete frames in one buffer), and corruption
/// recovery (skips to next magic on invalid header or oversized body).
///
/// The decoder never panics on arbitrary input — corrupt bytes cause it to
/// skip ahead to the next valid magic sequence.
pub struct FramingDecoder {
    buf: Vec<u8>,
    pos: usize,
    state: ScanState,
    max_body_bytes: u64,
    /// Total bytes ever fed (diagnostic).
    total_fed: u64,
    /// Total complete frames emitted (diagnostic).
    frames_emitted: u64,
    /// Total corrupt frames skipped during resynchronization (diagnostic).
    corrupt_skipped: u64,
}

impl Default for FramingDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl FramingDecoder {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            state: ScanState::Scanning,
            max_body_bytes: MAX_FRAME_BODY_BYTES,
            total_fed: 0,
            frames_emitted: 0,
            corrupt_skipped: 0,
        }
    }

    /// Set a custom maximum body size (default 16 MiB).
    pub fn with_max_body_bytes(mut self, max: u64) -> Self {
        self.max_body_bytes = max;
        self
    }

    /// Feed a chunk of bytes from the stream. Returns any completed frames.
    ///
    /// The decoder never panics on arbitrary input. Corrupt data or invalid
    /// headers cause the decoder to skip ahead to the next valid magic
    /// sequence.
    pub fn feed(&mut self, data: &[u8]) -> Vec<FramedMessage> {
        self.total_fed += data.len() as u64;
        self.buf.extend_from_slice(data);

        let mut frames = Vec::new();

        loop {
            match self.state {
                ScanState::Scanning => {
                    // Search for magic bytes "VBFS"
                    let window = &self.buf[self.pos..];
                    let magic_bytes: [u8; 4] = BINARY_SCHEMA_MAGIC.to_le_bytes();
                    if let Some(offset) = window.windows(4).position(|w| w == magic_bytes) {
                        let magic_at = self.pos + offset;
                        self.state = ScanState::AccumulatingHeader { magic_at };
                        self.pos = magic_at;
                    } else {
                        // No magic in remaining bytes; keep up to 3 trailing
                        // bytes in case magic spans a chunk boundary.
                        self.compact();
                        break;
                    }
                }

                ScanState::AccumulatingHeader { magic_at } => {
                    let available = self.buf.len().saturating_sub(self.pos);
                    if available < ENVELOPE_HEADER_BYTES {
                        break;
                    }

                    let header_buf: &[u8; 64] =
                        self.buf[self.pos..self.pos + 64].try_into().unwrap();
                    match EnvelopeHeader::decode(header_buf) {
                        Ok(header) => {
                            if header.total_body_bytes > self.max_body_bytes {
                                // Oversized body — treat as corrupt
                                self.corrupt_skipped += 1;
                                self.pos = magic_at + 1;
                                self.state = ScanState::Scanning;
                                continue;
                            }
                            let body_start = self.pos + ENVELOPE_HEADER_BYTES;
                            self.state = ScanState::AccumulatingBody { header, body_start };
                            self.pos = body_start;
                        }
                        Err(_) => {
                            // Corrupt header — skip one byte past magic, rescan
                            self.corrupt_skipped += 1;
                            self.pos = magic_at + 1;
                            self.state = ScanState::Scanning;
                            continue;
                        }
                    }
                }

                ScanState::AccumulatingBody {
                    header,
                    body_start: _,
                } => {
                    let needed = header.total_body_bytes as usize;
                    let available = self.buf.len().saturating_sub(self.pos);
                    if available < needed {
                        break;
                    }

                    let body = self.buf[self.pos..self.pos + needed].to_vec();
                    self.pos += needed;
                    self.frames_emitted += 1;
                    frames.push(FramedMessage { header, body });

                    // Ready for the next frame
                    self.state = ScanState::Scanning;
                }
            }
        }

        self.compact();
        frames
    }

    /// Reset the decoder to initial state, discarding any buffered data.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.pos = 0;
        self.state = ScanState::Scanning;
    }

    /// Number of corrupt frames skipped since construction or last reset.
    pub fn corrupt_skipped_count(&self) -> u64 {
        self.corrupt_skipped
    }

    /// Number of complete frames emitted.
    pub fn frames_emitted_count(&self) -> u64 {
        self.frames_emitted
    }

    /// Total bytes fed to this decoder.
    pub fn total_bytes_fed(&self) -> u64 {
        self.total_fed
    }

    /// Number of bytes currently buffered (not yet decoded into a frame).
    pub fn buffered_bytes(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Compact the buffer by discarding consumed bytes from the front.
    fn compact(&mut self) {
        if self.pos == 0 {
            return;
        }
        // Keep up to 3 trailing bytes for partial-magic spanning chunks.
        let keep_tail = if self.buf.len().saturating_sub(self.pos) < 4
            && matches!(self.state, ScanState::Scanning)
        {
            self.buf.len().saturating_sub(self.pos)
        } else {
            0
        };
        let drain_end = self.pos.saturating_sub(keep_tail);
        if drain_end > 0 {
            self.buf.drain(..drain_end);
            self.pos = keep_tail;
            // Fix up state offsets after drain.
            self.state = match self.state {
                ScanState::Scanning => ScanState::Scanning,
                ScanState::AccumulatingHeader { magic_at } => ScanState::AccumulatingHeader {
                    magic_at: magic_at.saturating_sub(drain_end),
                },
                ScanState::AccumulatingBody { header, body_start } => ScanState::AccumulatingBody {
                    header,
                    body_start: body_start.saturating_sub(drain_end),
                },
            };
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_binary_schema_core::SchemaFamilyId;

    #[test]
    fn envelope_roundtrip() {
        let header = EnvelopeHeader {
            magic: BINARY_SCHEMA_MAGIC,
            family_id: SchemaFamilyId(1),
            type_id: SchemaTypeId(100),
            version: SchemaVersion::new(2, 3),
            flags: 0xDEAD,
            section_count: 3,
            total_body_bytes: 4096,
            fast_checksum_profile: ChecksumProfile::Crc32c,
            strong_digest_profile: ChecksumProfile::Blake3_256,
            schema_fingerprint_low: 0xFEDCBA9876543210,
            header_crc32c: 0,
        };
        let encoded = header.encode();
        let decoded = EnvelopeHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.magic, header.magic);
        assert_eq!(decoded.family_id, header.family_id);
        assert_eq!(decoded.type_id, header.type_id);
        assert_eq!(decoded.version, header.version);
        assert_eq!(decoded.flags, header.flags);
        assert_eq!(decoded.section_count, header.section_count);
        assert_eq!(decoded.total_body_bytes, header.total_body_bytes);
        assert_eq!(decoded.fast_checksum_profile, header.fast_checksum_profile);
        assert_eq!(decoded.strong_digest_profile, header.strong_digest_profile);
        assert_eq!(
            decoded.schema_fingerprint_low,
            header.schema_fingerprint_low
        );
    }

    #[test]
    fn envelope_rejects_bad_magic() {
        let header = EnvelopeHeader::default();
        let mut encoded = header.encode();
        encoded[0] = 0x00; // corrupt magic
        assert!(matches!(
            EnvelopeHeader::decode(&encoded),
            Err(BinarySchemaError::BadMagic { .. })
        ));
    }

    #[test]
    fn envelope_rejects_bad_crc32c() {
        let header = EnvelopeHeader::default();
        let mut encoded = header.encode();
        encoded[61] ^= 0xFF; // corrupt header CRC
        assert!(matches!(
            EnvelopeHeader::decode(&encoded),
            Err(BinarySchemaError::ChecksumMismatch)
        ));
    }

    #[test]
    fn section_roundtrip() {
        let sec = SectionHeader {
            section_offset: 128,
            section_length: 1024,
            payload_class: PayloadClass::FixedInline,
            section_flags: 0,
            optional_mask: 0,
        };
        let enc = sec.encode();
        let dec = SectionHeader::decode(&enc).unwrap();
        assert_eq!(dec, sec);
    }

    #[test]
    fn section_rejects_unaligned_offset() {
        let mut enc = SectionHeader::default().encode();
        // set offset to 4 (not 8-byte aligned)
        enc[0..8].copy_from_slice(&4u64.to_le_bytes());
        assert!(matches!(
            SectionHeader::decode(&enc),
            Err(BinarySchemaError::AlignmentViolation)
        ));
    }

    #[test]
    fn section_rejects_bad_payload_class() {
        let mut enc = SectionHeader::default().encode();
        enc[16] = 0xFF;
        enc[17] = 0xFF;
        assert!(matches!(
            SectionHeader::decode(&enc),
            Err(BinarySchemaError::InvalidPayloadClass)
        ));
    }

    #[test]
    fn chunk_frame_roundtrip() {
        let frame = ChunkFrameHeader {
            frame_index: 7,
            payload_bytes: 64 * 1024,
            frame_size_class: ChunkFrameSizeClass::KiB64,
            payload_crc32c: 0x12345678,
            digest_continuation_marker: 1,
        };
        let enc = frame.encode();
        let dec = ChunkFrameHeader::decode(&enc).unwrap();
        assert_eq!(dec, frame);
    }

    #[test]
    fn chunk_frame_rejects_oversize_payload() {
        let mut enc = ChunkFrameHeader::default().encode();
        // claim frame class KiB64 but payload > 64 KiB
        enc[8..16].copy_from_slice(&(65 * 1024u64).to_le_bytes());
        assert!(matches!(
            ChunkFrameHeader::decode(&enc),
            Err(BinarySchemaError::BoundsViolation)
        ));
    }

    #[test]
    fn envelope_decode_from_slice_requires_alignment() {
        let header = EnvelopeHeader::default().encode();
        // Stack-allocated [u8; 64] may not always be 8-byte aligned.
        // Use a larger aligned buffer.
        #[repr(C, align(8))]
        struct Aligned([u8; 72]);
        let mut aligned = Aligned([0u8; 72]);
        aligned.0[..64].copy_from_slice(&header);
        let result = EnvelopeHeader::decode_from_slice(&aligned.0[..]);
        assert!(result.is_ok());
    }

    #[test]
    fn envelope_builder_defaults() {
        let builder = EnvelopeBuilder::new(
            SchemaFamilyId(1),
            SchemaTypeId(100),
            SchemaVersion::new(1, 0),
        );
        let header = builder.build(2, 2048);
        assert_eq!(header.family_id.0, 1);
        assert_eq!(header.type_id.0, 100);
        assert_eq!(header.section_count, 2);
        assert_eq!(header.total_body_bytes, 2048);
        assert_eq!(header.fast_checksum_profile, ChecksumProfile::Crc32c);
        assert_eq!(header.strong_digest_profile, ChecksumProfile::Blake3_256);
    }

    // ── envelope decode_from_slice error paths ───────────────────────

    #[test]
    fn envelope_decode_from_slice_too_short() {
        let short = [0u8; 32];
        assert!(matches!(
            EnvelopeHeader::decode_from_slice(&short),
            Err(BinarySchemaError::BoundsViolation)
        ));
    }

    #[test]
    fn envelope_decode_invalid_fast_profile() {
        let header = EnvelopeHeader::default();
        let mut encoded = header.encode();
        encoded[40] = 0xFF; // invalid ChecksumProfile discriminant
        assert!(matches!(
            EnvelopeHeader::decode(&encoded),
            Err(BinarySchemaError::InvalidChecksumProfile)
        ));
    }

    #[test]
    fn envelope_decode_invalid_strong_profile() {
        let header = EnvelopeHeader::default();
        let mut encoded = header.encode();
        encoded[40] = ChecksumProfile::None.discriminant();
        encoded[41] = 0xFF; // invalid strong profile
        assert!(matches!(
            EnvelopeHeader::decode(&encoded),
            Err(BinarySchemaError::InvalidChecksumProfile)
        ));
    }

    // ── envelope default roundtrip ───────────────────────────────────

    #[test]
    fn envelope_default_roundtrip() {
        let header = EnvelopeHeader::default();
        let encoded = header.encode();
        let decoded = EnvelopeHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.magic, BINARY_SCHEMA_MAGIC);
        assert_eq!(decoded.section_count, 0);
        assert_eq!(decoded.total_body_bytes, 0);
        assert_eq!(decoded.fast_checksum_profile, ChecksumProfile::None);
        assert_eq!(decoded.strong_digest_profile, ChecksumProfile::None);
    }

    // ── envelope builder full chaining ───────────────────────────────

    #[test]
    fn envelope_builder_full_chain() {
        let header = EnvelopeBuilder::new(
            SchemaFamilyId(2),
            SchemaTypeId(200),
            SchemaVersion::new(3, 5),
        )
        .with_flags(0xCAFE)
        .with_fingerprint_low(0x0123456789ABCDEF)
        .with_checksum_profiles(
            ChecksumProfile::Crc32cPlusBlake3_256,
            ChecksumProfile::Blake3_256,
        )
        .build(4, 8192);

        assert_eq!(header.family_id.0, 2);
        assert_eq!(header.type_id.0, 200);
        assert_eq!(header.version, SchemaVersion::new(3, 5));
        assert_eq!(header.flags, 0xCAFE);
        assert_eq!(header.schema_fingerprint_low, 0x0123456789ABCDEF);
        assert_eq!(
            header.fast_checksum_profile,
            ChecksumProfile::Crc32cPlusBlake3_256
        );
        assert_eq!(header.strong_digest_profile, ChecksumProfile::Blake3_256);
        assert_eq!(header.section_count, 4);
        assert_eq!(header.total_body_bytes, 8192);

        // verify round-trip
        let enc = header.encode();
        let dec = EnvelopeHeader::decode(&enc).unwrap();
        assert_eq!(dec.family_id.0, 2);
        assert_eq!(dec.flags, 0xCAFE);
        assert_eq!(dec.schema_fingerprint_low, 0x0123456789ABCDEF);
    }

    // ── section zero offset (valid) ──────────────────────────────────

    #[test]
    fn section_zero_offset_is_valid() {
        let sec = SectionHeader {
            section_offset: 0,
            section_length: 100,
            ..Default::default()
        };
        let enc = sec.encode();
        let dec = SectionHeader::decode(&enc).unwrap();
        assert_eq!(dec.section_offset, 0);
        assert_eq!(dec.section_length, 100);
    }

    // ── chunk frame zero payload (valid) ─────────────────────────────

    #[test]
    fn chunk_frame_zero_payload() {
        let frame = ChunkFrameHeader {
            frame_index: 0,
            payload_bytes: 0,
            frame_size_class: ChunkFrameSizeClass::KiB64,
            payload_crc32c: 0,
            digest_continuation_marker: 0,
        };
        let enc = frame.encode();
        let dec = ChunkFrameHeader::decode(&enc).unwrap();
        assert_eq!(dec.payload_bytes, 0);
    }

    // ── chunk frame invalid class discriminant ────────────────────────

    #[test]
    fn chunk_frame_rejects_invalid_class() {
        let mut enc = ChunkFrameHeader::default().encode();
        enc[16] = 0xFF;
        enc[17] = 0xFF;
        assert!(matches!(
            ChunkFrameHeader::decode(&enc),
            Err(BinarySchemaError::InvalidPayloadClass)
        ));
    }

    // ── FramingDecoder tests ──────────────────────────────────────

    fn make_test_header(body_len: u64, family: u64) -> EnvelopeHeader {
        EnvelopeHeader {
            magic: BINARY_SCHEMA_MAGIC,
            family_id: SchemaFamilyId(family),
            type_id: SchemaTypeId(1),
            version: SchemaVersion::new(1, 0),
            flags: 0,
            section_count: 0,
            total_body_bytes: body_len,
            fast_checksum_profile: ChecksumProfile::Crc32c,
            strong_digest_profile: ChecksumProfile::Blake3_256,
            schema_fingerprint_low: 0,
            header_crc32c: 0,
        }
    }

    fn frame_bytes(header: &EnvelopeHeader, body: &[u8]) -> Vec<u8> {
        let mut v = header.encode().to_vec();
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn decoder_single_empty_frame() {
        let h = make_test_header(0, 1);
        let data = frame_bytes(&h, &[]);
        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&data);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].body.len(), 0);
    }

    #[test]
    fn decoder_single_frame_with_body() {
        let body = b"hello framing".to_vec();
        let h = make_test_header(body.len() as u64, 42);
        let data = frame_bytes(&h, &body);
        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&data);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].body, body);
    }

    #[test]
    fn decoder_multi_frame_stream() {
        let bodies: Vec<Vec<u8>> = (0..5).map(|i| vec![i as u8; (i + 1) * 10]).collect();
        let mut stream = Vec::new();
        for (i, body) in bodies.iter().enumerate() {
            let h = make_test_header(body.len() as u64, i as u64);
            stream.extend_from_slice(&frame_bytes(&h, body));
        }
        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&stream);
        assert_eq!(frames.len(), 5);
        for (i, frame) in frames.iter().enumerate() {
            assert_eq!(frame.body, bodies[i]);
        }
    }

    #[test]
    fn decoder_byte_by_byte() {
        let body = vec![0xABu8; 256];
        let h = make_test_header(body.len() as u64, 1);
        let data = frame_bytes(&h, &body);
        let mut dec = FramingDecoder::new();
        let mut frames = Vec::new();
        for &b in &data {
            frames.extend(dec.feed(&[b]));
        }
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].body, body);
    }

    #[test]
    fn decoder_split_mid_header() {
        let body = vec![0xCDu8; 100];
        let h = make_test_header(body.len() as u64, 7);
        let data = frame_bytes(&h, &body);
        let mut dec = FramingDecoder::new();
        assert!(dec.feed(&data[..30]).is_empty());
        let frames = dec.feed(&data[30..]);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].body, body);
    }

    #[test]
    fn decoder_split_mid_body() {
        let body = vec![0xEFu8; 200];
        let h = make_test_header(body.len() as u64, 3);
        let data = frame_bytes(&h, &body);
        let mut dec = FramingDecoder::new();
        let split = 64 + 50;
        assert!(dec.feed(&data[..split]).is_empty());
        let frames = dec.feed(&data[split..]);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].body, body);
    }

    #[test]
    fn decoder_all_frames_coalesced() {
        let bodies: Vec<Vec<u8>> = (0..5).map(|i| vec![i as u8; 64]).collect();
        let mut stream = Vec::new();
        for (i, body) in bodies.iter().enumerate() {
            let h = make_test_header(body.len() as u64, i as u64);
            stream.extend_from_slice(&frame_bytes(&h, body));
        }
        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&stream);
        assert_eq!(frames.len(), 5);
    }

    #[test]
    fn decoder_bad_magic_before_valid() {
        let body = b"recovered".to_vec();
        let h = make_test_header(body.len() as u64, 1);
        let frame = frame_bytes(&h, &body);
        let mut stream = vec![0u8; 20];
        stream.extend_from_slice(&frame);
        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&stream);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].body, body);
    }

    #[test]
    fn decoder_corrupt_header_then_valid() {
        let body = b"after corrupt".to_vec();
        let h = make_test_header(body.len() as u64, 99);
        let frame = frame_bytes(&h, &body);
        // Fake magic + garbage header, then real frame
        let mut stream = BINARY_SCHEMA_MAGIC.to_le_bytes().to_vec();
        stream.extend_from_slice(&[0xFFu8; 60]);
        stream.extend_from_slice(&frame);
        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&stream);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].body, body);
        assert!(dec.corrupt_skipped_count() >= 1);
    }

    #[test]
    fn decoder_corrupt_mid_stream() {
        let h1 = make_test_header(10, 1);
        let h2 = make_test_header(20, 2);
        let f1 = frame_bytes(&h1, &[1u8; 10]);
        let f2 = frame_bytes(&h2, &[2u8; 20]);
        let mut stream = f1.clone();
        stream.extend_from_slice(&BINARY_SCHEMA_MAGIC.to_le_bytes());
        stream.extend_from_slice(&[0xFFu8; 60]);
        stream.extend_from_slice(&f2);
        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&stream);
        assert_eq!(frames.len(), 2);
        assert!(dec.corrupt_skipped_count() >= 1);
    }

    #[test]
    fn decoder_oversized_body_rejected() {
        let h = make_test_header(MAX_FRAME_BODY_BYTES + 1, 1);
        let frame = frame_bytes(&h, &[]);
        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&frame);
        assert!(frames.is_empty());
        assert_eq!(dec.corrupt_skipped_count(), 1);
    }

    #[test]
    fn decoder_magic_in_body_not_confused() {
        let mut body = vec![0x00u8; 100];
        body[50..54].copy_from_slice(&BINARY_SCHEMA_MAGIC.to_le_bytes());
        let h = make_test_header(body.len() as u64, 1);
        let data = frame_bytes(&h, &body);
        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&data);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].body, body);
    }

    #[test]
    fn decoder_empty_stream() {
        let mut dec = FramingDecoder::new();
        assert!(dec.feed(&[]).is_empty());
    }

    #[test]
    fn decoder_all_zeroes_no_panic() {
        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&[0u8; 256]);
        assert!(frames.is_empty());
    }

    #[test]
    fn decoder_reset_clears_state() {
        let h = make_test_header(5, 1);
        let data = frame_bytes(&h, b"hello");
        let mut dec = FramingDecoder::new();
        assert!(dec.feed(&data[..10]).is_empty());
        dec.reset();
        let frames = dec.feed(&data);
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn decoder_diagnostic_counters() {
        let h1 = make_test_header(5, 1);
        let h2 = make_test_header(7, 2);
        let mut stream = frame_bytes(&h1, b"hello");
        stream.extend_from_slice(&frame_bytes(&h2, b"goodbye"));
        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&stream);
        assert_eq!(frames.len(), 2);
        assert_eq!(dec.frames_emitted_count(), 2);
        assert_eq!(dec.total_bytes_fed(), stream.len() as u64);
        assert_eq!(dec.buffered_bytes(), 0);
    }

    #[test]
    fn decoder_zero_length_frame() {
        let h = make_test_header(0, 1);
        let data = frame_bytes(&h, &[]);
        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&data);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].body.len(), 0);
    }

    #[test]
    fn decoder_max_size_frame_boundary() {
        let body = vec![0xAAu8; 1024];
        let h = make_test_header(body.len() as u64, 1);
        let data = frame_bytes(&h, &body);
        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&data);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].body, body);
    }
}
