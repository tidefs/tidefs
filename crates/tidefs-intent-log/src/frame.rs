// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! BLAKE3-authenticated intent-log frame.
//!
//! An [`IntentLogFrame`] wraps an [`IntentLogRecord`] with a transaction
//! group id, a monotonically increasing record sequence number, and a
//! BLAKE3-256 checksum computed over the serialized record + txg_id +
//! record_seq. The checksum binds the record to its position in the
//! commit pipeline, preventing reordering or tampering.

use alloc::vec::Vec;

use crate::{IntentLogError, IntentLogRecord};

/// A single framed intent-log record with BLAKE3-256 integrity.
///
/// The checksum covers the concatenation of:
/// ```text
///   encode(record) || txg_id (u64 LE) || record_seq (u64 LE)
/// ```
///
/// This binds each record to a specific transaction group and sequence
/// position, so replay can detect gaps, duplicates, or corruption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntentLogFrame {
    /// The mutating filesystem operation.
    pub record: IntentLogRecord,
    /// Transaction group this record belongs to.
    pub txg_id: u64,
    /// Monotonically increasing sequence number within the intent-log buffer.
    pub record_seq: u64,
    /// BLAKE3-256 checksum of `encode(record) || txg_id || record_seq`.
    pub checksum: [u8; 32],
}

impl IntentLogFrame {
    /// Create a new frame for `record` in transaction group `txg_id` at
    /// sequence position `record_seq`. The checksum is computed immediately.
    pub fn new(record: IntentLogRecord, txg_id: u64, record_seq: u64) -> Self {
        let checksum = Self::compute_checksum(&record, txg_id, record_seq);
        Self {
            record,
            txg_id,
            record_seq,
            checksum,
        }
    }

    /// Compute the BLAKE3-256 checksum for the given record, txg_id, and
    /// record_seq.
    pub fn compute_checksum(record: &IntentLogRecord, txg_id: u64, record_seq: u64) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        // Hash the serialized record
        let record_bytes = record.encode();
        hasher.update(&record_bytes);
        // Hash the framing fields
        hasher.update(&txg_id.to_le_bytes());
        hasher.update(&record_seq.to_le_bytes());
        hasher.finalize().into()
    }

    /// Verify that the stored checksum matches a fresh computation over the
    /// record + txg_id + record_seq.
    pub fn verify(&self) -> Result<(), IntentLogError> {
        let computed = Self::compute_checksum(&self.record, self.txg_id, self.record_seq);
        if computed == self.checksum {
            Ok(())
        } else {
            Err(IntentLogError::ChecksumMismatch)
        }
    }

    /// Serialize the frame to bytes.
    ///
    /// Format: `txg_id (u64 LE) || record_seq (u64 LE) || checksum (32 bytes)
    ///          || record_length (u32 LE) || record_bytes`
    pub fn encode(&self) -> Vec<u8> {
        let record_bytes = self.record.encode();
        let mut buf = Vec::with_capacity(8 + 8 + 32 + 4 + record_bytes.len());
        buf.extend_from_slice(&self.txg_id.to_le_bytes());
        buf.extend_from_slice(&self.record_seq.to_le_bytes());
        buf.extend_from_slice(&self.checksum);
        buf.extend_from_slice(&(record_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&record_bytes);
        buf
    }

    /// Deserialize a frame from bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, IntentLogError> {
        if buf.len() < 8 + 8 + 32 + 4 {
            return Err(IntentLogError::BufferTooShort);
        }
        let mut pos = 0;
        let txg_id = read_u64_le(buf, &mut pos);
        let record_seq = read_u64_le(buf, &mut pos);
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&buf[pos..pos + 32]);
        pos += 32;
        let record_len = read_u32_le(buf, &mut pos) as usize;
        if pos + record_len > buf.len() {
            return Err(IntentLogError::BufferTooShort);
        }
        let record = IntentLogRecord::decode(&buf[pos..pos + record_len])?;
        // Verify checksum on deserialized data
        let frame = Self {
            record,
            txg_id,
            record_seq,
            checksum,
        };
        frame.verify()?;
        Ok(frame)
    }
}

fn read_u64_le(buf: &[u8], pos: &mut usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[*pos..*pos + 8]);
    *pos += 8;
    u64::from_le_bytes(bytes)
}

fn read_u32_le(buf: &[u8], pos: &mut usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[*pos..*pos + 4]);
    *pos += 4;
    u32::from_le_bytes(bytes)
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let rec = IntentLogRecord::Create {
            parent: 1,
            name: b"test.txt".to_vec(),
            mode: 0o644,
            ino: 42,
        };
        let frame = IntentLogFrame::new(rec, 7, 3);
        let encoded = frame.encode();
        let decoded = IntentLogFrame::decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn frame_decode_rejects_corrupt_checksum() {
        let rec = IntentLogRecord::Truncate {
            ino: 1,
            new_size: 100,
        };
        let mut frame = IntentLogFrame::new(rec, 1, 0);
        frame.checksum[0] ^= 0xFF;
        let encoded = frame.encode();
        assert_eq!(
            IntentLogFrame::decode(&encoded).unwrap_err(),
            IntentLogError::ChecksumMismatch
        );
    }

    #[test]
    fn frame_decode_rejects_corrupt_record() {
        let rec = IntentLogRecord::Truncate {
            ino: 1,
            new_size: 100,
        };
        let frame = IntentLogFrame::new(rec, 1, 0);
        let mut encoded = frame.encode();
        // Corrupt the record payload (flip a byte in the record_length region)
        let record_len_pos = 8 + 8 + 32;
        encoded[record_len_pos] ^= 0xFF;
        assert!(IntentLogFrame::decode(&encoded).is_err());
    }

    #[test]
    fn identical_records_different_txg_have_different_checksums() {
        let rec = IntentLogRecord::Write {
            ino: 1,
            offset: 0,
            length: 64,
            data_hash: [0xAA; 32],
        };
        let f1 = IntentLogFrame::new(rec.clone(), 1, 0);
        let f2 = IntentLogFrame::new(rec, 2, 0);
        assert_ne!(f1.checksum, f2.checksum);
    }

    #[test]
    fn identical_records_different_seq_have_different_checksums() {
        let rec = IntentLogRecord::Write {
            ino: 1,
            offset: 0,
            length: 64,
            data_hash: [0xAA; 32],
        };
        let f1 = IntentLogFrame::new(rec.clone(), 1, 0);
        let f2 = IntentLogFrame::new(rec, 1, 1);
        assert_ne!(f1.checksum, f2.checksum);
    }
}
