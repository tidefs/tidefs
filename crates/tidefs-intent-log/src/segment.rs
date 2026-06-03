//! On-disk intent-log segment format with BLAKE3 checksums.
//!
//! A segment is the durable unit of the intent log. Each segment contains a
//! self-describing header, a sequence of BLAKE3-authenticated records, and a
//! footer with a record index for fast replay. Segments with a valid footer
//! are fully committed; segments without a footer are truncated crash
//! artifacts and must be replayed record-by-record.
//!
//! # Layout
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │ SegmentHeader (64 bytes)                                     │
//! │   magic(8) | version(4) | lsn_start(8) | lsn_end(8)         │
//! │   record_count(4) | reserved(32)                             │
//! ├──────────────────────────────────────────────────────────────┤
//! │ Record 0                                                      │
//! │   record_type(1) | record_length(4) | payload(N)             │
//! │   record_checksum(32)                                        │
//! ├──────────────────────────────────────────────────────────────┤
//! │ Record 1 ...                                                  │
//! ├──────────────────────────────────────────────────────────────┤
//! │ SegmentFooter (variable)                                     │
//! │   index_count(4) | index_entries(20 each)                    │
//! │   footer_checksum(32)                                        │
//! └──────────────────────────────────────────────────────────────┘
//! ```

use crate::IntentLogError;

// ── Constants ──────────────────────────────────────────────────────────

/// Magic bytes for intent-log segments: `"VIFSLOG"` as u64 LE.
pub const SEGMENT_MAGIC: u64 = 0x56_49_46_53_4C_4F_47;

/// Current segment format version.
pub const SEGMENT_VERSION: u32 = 1;

/// Size of the segment header on disk (including reserved space for the
/// header checksum, which is written last during seal).
pub const SEGMENT_HEADER_SIZE: usize = 64;

/// Number of bytes reserved between the header fields and the header
/// checksum. The checksum covers bytes [0..HEADER_RESERVED].
const HEADER_RESERVED: usize = 32;

/// Size of each record index entry: lsn(u64) + offset(u64) + length(u32).
const RECORD_INDEX_ENTRY_SIZE: usize = 20;

/// Size of a record entry before the payload: type(1) + length(4) +
/// checksum(32) = 37 bytes.
const RECORD_ENTRY_OVERHEAD: usize = 37;

/// Default maximum segment size (64 MiB).
pub const DEFAULT_MAX_SEGMENT_SIZE: u64 = 64 * 1024 * 1024;

// ── SegmentHeader ──────────────────────────────────────────────────────

/// Deserialized segment header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentHeader {
    /// Magic value; must equal [`SEGMENT_MAGIC`].
    pub magic: u64,
    /// Segment format version; must equal [`SEGMENT_VERSION`].
    pub version: u32,
    /// LSN of the first record in this segment.
    pub segment_lsn_start: u64,
    /// LSN of the last record in this segment (0 if segment is open/unsealed).
    pub segment_lsn_end: u64,
    /// Number of records in this segment.
    pub record_count: u32,
}

impl SegmentHeader {
    /// Encode the header fields (without checksum) into 32 bytes.
    pub fn encode_header(&self) -> [u8; HEADER_RESERVED] {
        let mut buf = [0u8; HEADER_RESERVED];
        buf[0..8].copy_from_slice(&self.magic.to_le_bytes());
        buf[8..12].copy_from_slice(&self.version.to_le_bytes());
        buf[12..20].copy_from_slice(&self.segment_lsn_start.to_le_bytes());
        buf[20..28].copy_from_slice(&self.segment_lsn_end.to_le_bytes());
        buf[28..32].copy_from_slice(&self.record_count.to_le_bytes());
        // bytes 32..64 are reserved (zero)
        buf
    }

    /// Decode the header fields from 32 bytes (without checksum).
    pub fn decode_header(buf: &[u8]) -> Result<Self, IntentLogError> {
        if buf.len() < HEADER_RESERVED {
            return Err(IntentLogError::BufferTooShort);
        }
        let magic = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let version = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let segment_lsn_start = u64::from_le_bytes(buf[12..20].try_into().unwrap());
        let segment_lsn_end = u64::from_le_bytes(buf[20..28].try_into().unwrap());
        let record_count = u32::from_le_bytes(buf[28..32].try_into().unwrap());
        Ok(Self {
            magic,
            version,
            segment_lsn_start,
            segment_lsn_end,
            record_count,
        })
    }

    /// Compute the BLAKE3 checksum of the header fields.
    pub fn compute_header_checksum(&self) -> [u8; 32] {
        let header_bytes = self.encode_header();
        blake3::hash(&header_bytes).into()
    }

    /// Encode the full header including checksum (64 bytes).
    pub fn encode(&self) -> [u8; SEGMENT_HEADER_SIZE] {
        let mut buf = [0u8; SEGMENT_HEADER_SIZE];
        let header = self.encode_header();
        let checksum = *blake3::hash(&header).as_bytes();
        buf[0..HEADER_RESERVED].copy_from_slice(&header);
        buf[HEADER_RESERVED..].copy_from_slice(&checksum);
        buf
    }

    /// Decode and validate a full segment header (64 bytes).
    pub fn decode(buf: &[u8]) -> Result<Self, IntentLogError> {
        if buf.len() < SEGMENT_HEADER_SIZE {
            return Err(IntentLogError::BufferTooShort);
        }
        let header = Self::decode_header(&buf[..HEADER_RESERVED])?;
        let expected = header.compute_header_checksum();
        let stored: [u8; 32] = buf[HEADER_RESERVED..SEGMENT_HEADER_SIZE]
            .try_into()
            .unwrap();
        if expected != stored {
            return Err(IntentLogError::ChecksumMismatch);
        }
        Ok(header)
    }
}

// ── Record Index Entry ─────────────────────────────────────────────────

/// A single entry in the segment footer record index.
///
/// Maps an LSN to its byte offset and record length within the segment,
/// enabling O(log n) lookup during replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordIndexEntry {
    /// Global log sequence number of this record.
    pub lsn: u64,
    /// Byte offset of the record entry from the start of the segment.
    pub offset: u64,
    /// Total length of the record entry (overhead + payload).
    pub length: u32,
}

impl RecordIndexEntry {
    /// Encode this entry to 20 bytes.
    pub fn encode(&self) -> [u8; RECORD_INDEX_ENTRY_SIZE] {
        let mut buf = [0u8; RECORD_INDEX_ENTRY_SIZE];
        buf[0..8].copy_from_slice(&self.lsn.to_le_bytes());
        buf[8..16].copy_from_slice(&self.offset.to_le_bytes());
        buf[16..20].copy_from_slice(&self.length.to_le_bytes());
        buf
    }

    /// Decode an entry from 20 bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, IntentLogError> {
        if buf.len() < RECORD_INDEX_ENTRY_SIZE {
            return Err(IntentLogError::BufferTooShort);
        }
        let lsn = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let offset = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let length = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        Ok(Self {
            lsn,
            offset,
            length,
        })
    }
}

// ── SegmentFooter ──────────────────────────────────────────────────────

/// Deserialized segment footer with record index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentFooter {
    /// Index entries mapping LSN to segment offset.
    pub record_index: Vec<RecordIndexEntry>,
}

impl SegmentFooter {
    /// Encode the footer (without checksum).
    pub fn encode_footer(&self) -> Vec<u8> {
        let count = self.record_index.len() as u32;
        let mut buf = Vec::with_capacity(4 + count as usize * RECORD_INDEX_ENTRY_SIZE);
        buf.extend_from_slice(&count.to_le_bytes());
        for entry in &self.record_index {
            buf.extend_from_slice(&entry.encode());
        }
        buf
    }

    /// Compute the BLAKE3 checksum of the footer body.
    pub fn compute_footer_checksum(&self) -> [u8; 32] {
        let body = self.encode_footer();
        blake3::hash(&body).into()
    }

    /// Encode the full footer including checksum.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = self.encode_footer();
        let checksum = self.compute_footer_checksum();
        buf.extend_from_slice(&checksum);
        buf
    }

    /// Total size of the encoded footer on disk.
    pub fn encoded_len(&self) -> usize {
        4 + self.record_index.len() * RECORD_INDEX_ENTRY_SIZE + 32
    }

    /// Decode a footer from bytes. Returns `None` if the buffer doesn't
    /// have enough bytes for a complete footer.
    pub fn decode(buf: &[u8]) -> Result<Self, IntentLogError> {
        if buf.len() < 4 {
            return Err(IntentLogError::BufferTooShort);
        }
        let count = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let index_bytes = 4 + count * RECORD_INDEX_ENTRY_SIZE;
        let total_needed = index_bytes + 32;
        if buf.len() < total_needed {
            return Err(IntentLogError::BufferTooShort);
        }

        // Verify footer checksum
        let expected: [u8; 32] = buf[index_bytes..index_bytes + 32].try_into().unwrap();
        let computed: [u8; 32] = blake3::hash(&buf[..index_bytes]).into();
        if expected != computed {
            return Err(IntentLogError::ChecksumMismatch);
        }

        let mut record_index = Vec::with_capacity(count);
        for i in 0..count {
            let start = 4 + i * RECORD_INDEX_ENTRY_SIZE;
            let entry = RecordIndexEntry::decode(&buf[start..start + RECORD_INDEX_ENTRY_SIZE])?;
            record_index.push(entry);
        }

        Ok(Self { record_index })
    }

    /// Try to decode a footer, returning `Ok(None)` if the buffer is too
    /// short to contain a complete footer (indicating a truncated segment).
    pub fn try_decode(buf: &[u8]) -> Result<Option<Self>, IntentLogError> {
        if buf.len() < 4 + 32 {
            return Ok(None); // Not enough data for even a minimal footer
        }
        let count = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let total_needed = 4 + count * RECORD_INDEX_ENTRY_SIZE + 32;
        if buf.len() < total_needed {
            return Ok(None); // Truncated: footer declared N entries but not enough data
        }
        Self::decode(buf).map(Some)
    }
}

// ── Record Entry encoding/decoding ─────────────────────────────────────

/// Compute the BLAKE3 checksum for a segment record entry.
///
/// Checksum covers: `record_type (1 byte) || record_length (4 bytes LE) ||
/// payload`.
pub fn compute_record_checksum(record_type: u8, payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[record_type]);
    hasher.update(&(payload.len() as u32).to_le_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

/// Verify a record checksum.
pub fn verify_record_checksum(record_type: u8, payload: &[u8], checksum: &[u8; 32]) -> bool {
    compute_record_checksum(record_type, payload) == *checksum
}

/// Encode a record entry to bytes.
///
/// Returns: `[record_type (1)] [record_length (4 LE)] [payload] [checksum (32)]`
pub fn encode_record_entry(record_type: u8, payload: &[u8]) -> Vec<u8> {
    let checksum = compute_record_checksum(record_type, payload);
    let mut buf = Vec::with_capacity(RECORD_ENTRY_OVERHEAD + payload.len());
    buf.push(record_type);
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);
    buf.extend_from_slice(&checksum);
    buf
}

/// Compute the total on-disk size of a record entry.
pub fn record_entry_size(payload_len: usize) -> usize {
    RECORD_ENTRY_OVERHEAD + payload_len
}

/// Decode a record entry from bytes.
///
/// Returns `(record_type, payload)` on success. Validates the record
/// checksum.
///
/// Returns `None` if the buffer is too short to contain a complete record
/// entry — this indicates a truncated segment and the caller should
/// attempt partial replay.
pub fn decode_record_entry(buf: &[u8]) -> Result<Option<(u8, Vec<u8>)>, IntentLogError> {
    if buf.len() < 5 {
        return Ok(None); // Too short even for type + length
    }
    let record_type = buf[0];
    let record_length = u32::from_le_bytes(buf[1..5].try_into().unwrap()) as usize;
    let total_needed = RECORD_ENTRY_OVERHEAD + record_length;
    if buf.len() < total_needed {
        return Ok(None); // Truncated: declared length exceeds available data
    }
    let payload = buf[5..5 + record_length].to_vec();
    let checksum_pos = 5 + record_length;
    let checksum: [u8; 32] = buf[checksum_pos..checksum_pos + 32].try_into().unwrap();
    if !verify_record_checksum(record_type, &payload, &checksum) {
        return Err(IntentLogError::ChecksumMismatch);
    }
    Ok(Some((record_type, payload)))
}

/// Attempt to decode a record entry, returning the consumed byte count on
/// success, or `0` if the buffer is truncated (to signal partial replay
/// should stop here).
pub fn try_decode_record_entry(buf: &[u8]) -> Result<(u8, Vec<u8>, usize), IntentLogError> {
    if buf.len() < 5 {
        return Ok((0, Vec::new(), 0)); // Truncated, consume 0
    }
    let record_length = u32::from_le_bytes(buf[1..5].try_into().unwrap()) as usize;
    let total_needed = RECORD_ENTRY_OVERHEAD + record_length;
    if buf.len() < total_needed {
        return Ok((0, Vec::new(), 0)); // Truncated
    }
    match decode_record_entry(buf)? {
        Some((rtype, payload)) => Ok((rtype, payload, total_needed)),
        None => Ok((0, Vec::new(), 0)),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let hdr = SegmentHeader {
            magic: SEGMENT_MAGIC,
            version: SEGMENT_VERSION,
            segment_lsn_start: 10,
            segment_lsn_end: 50,
            record_count: 7,
        };
        let encoded = hdr.encode();
        assert_eq!(encoded.len(), SEGMENT_HEADER_SIZE);
        let decoded = SegmentHeader::decode(&encoded).unwrap();
        assert_eq!(decoded, hdr);
    }
    #[test]
    fn header_rejects_checksum_mismatch() {
        let hdr = SegmentHeader {
            magic: SEGMENT_MAGIC,
            version: SEGMENT_VERSION,
            segment_lsn_start: 1,
            segment_lsn_end: 2,
            record_count: 3,
        };
        let mut encoded = hdr.encode();
        // Flip a byte in the checksum region
        encoded[SEGMENT_HEADER_SIZE - 1] ^= 0xFF;
        assert_eq!(
            SegmentHeader::decode(&encoded).unwrap_err(),
            IntentLogError::ChecksumMismatch
        );
    }

    #[test]
    fn record_entry_roundtrip() {
        let payload = b"hello world";
        let rtype = 1u8;
        let entry = encode_record_entry(rtype, payload);
        let (decoded_type, decoded_payload) = decode_record_entry(&entry).unwrap().unwrap();
        assert_eq!(decoded_type, rtype);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn record_entry_truncated_returns_none() {
        let entry = encode_record_entry(1, b"test");
        // Provide less than the full entry
        let result = decode_record_entry(&entry[..5]);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn record_entry_corrupt_checksum_detected() {
        let entry = encode_record_entry(1, b"test");
        let mut bad = entry.clone();
        bad[0] ^= 0xFF; // change record_type
        assert_eq!(
            decode_record_entry(&bad).unwrap_err(),
            IntentLogError::ChecksumMismatch
        );
    }

    #[test]
    fn footer_roundtrip() {
        let footer = SegmentFooter {
            record_index: vec![
                RecordIndexEntry {
                    lsn: 0,
                    offset: 64,
                    length: 100,
                },
                RecordIndexEntry {
                    lsn: 1,
                    offset: 164,
                    length: 120,
                },
            ],
        };
        let encoded = footer.encode();
        let decoded = SegmentFooter::decode(&encoded).unwrap();
        assert_eq!(decoded.record_index.len(), 2);
        assert_eq!(decoded.record_index[0], footer.record_index[0]);
        assert_eq!(decoded.record_index[1], footer.record_index[1]);
    }

    #[test]
    fn footer_truncated_returns_none() {
        let footer = SegmentFooter {
            record_index: vec![RecordIndexEntry {
                lsn: 0,
                offset: 64,
                length: 100,
            }],
        };
        let full = footer.encode();
        // Provide only partial data
        let result = SegmentFooter::try_decode(&full[..full.len() - 10]);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn footer_checksum_mismatch_detected() {
        let footer = SegmentFooter {
            record_index: vec![RecordIndexEntry {
                lsn: 0,
                offset: 64,
                length: 100,
            }],
        };
        let mut encoded = footer.encode();
        // Corrupt the checksum
        let len = encoded.len();
        encoded[len - 1] ^= 0xFF;
        assert_eq!(
            SegmentFooter::decode(&encoded).unwrap_err(),
            IntentLogError::ChecksumMismatch
        );
    }

    #[test]
    fn record_entry_size_calculation() {
        assert_eq!(record_entry_size(0), 37);
        assert_eq!(record_entry_size(100), 137);
    }
}
