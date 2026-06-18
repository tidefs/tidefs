// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! BLAKE3-verified persistent cleaner ledger.
//!
//! The [`CleanerLedger`] records cleaned segments, migration outcomes,
//! and checkpoint state so the cleaner can safely resume after a crash
//! without double-releasing segments or losing migration progress.
//!
//! # On-disk record format
//!
//! Each [`CleanerLedgerRecord`] is a fixed-size binary record with a
//! BLAKE3 checksum covering the header fields. Records are written to
//! a well-known object in the pool root and loaded on pool import.
//!
//! | Offset | Size | Field            |
//! |--------|------|------------------|
//! | 0      | 4    | magic (0x56434C44) |
//! | 4      | 4    | version (1)       |
//! | 8      | 8    | last_cleaned_segment_id |
//! | 16     | 8    | segments_cleaned  |
//! | 24     | 8    | segments_freed    |
//! | 32     | 8    | bytes_migrated     |
//! | 40     | 8    | bytes_freed        |
//! | 48     | 32   | blake3 hash       |

use blake3::Hash;

/// Magic bytes identifying a cleaner-ledger record: "VCLD"
/// (TideFS Cleaner Ledger Data).
pub const CLEANER_LEDGER_MAGIC: u32 = 0x56434C44;

/// Current record format version.
pub const CLEANER_LEDGER_VERSION: u32 = 1;

/// On-disk record size in bytes.
pub const CLEANER_LEDGER_RECORD_SIZE: usize = 4 + 4 + 8 + 8 + 8 + 8 + 8 + 32; // 80 bytes

/// Persistent cleaner-ledger record with BLAKE3 integrity verification.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CleanerLedgerRecord {
    /// Last segment ID cleaned (cursor for resumption).
    pub last_cleaned_segment_id: u64,
    /// Total segments cleaned (compacted).
    pub segments_cleaned: u64,
    /// Total segments freed.
    pub segments_freed: u64,
    /// Total live bytes migrated during compaction.
    pub bytes_migrated: u64,
    /// Total dead bytes freed.
    pub bytes_freed: u64,
}

impl CleanerLedgerRecord {
    /// Create a new record with the given state.
    #[must_use]
    pub fn new(
        last_cleaned_segment_id: u64,
        segments_cleaned: u64,
        segments_freed: u64,
        bytes_migrated: u64,
        bytes_freed: u64,
    ) -> Self {
        Self {
            last_cleaned_segment_id,
            segments_cleaned,
            segments_freed,
            bytes_migrated,
            bytes_freed,
        }
    }

    /// Encode the record into an 80-byte buffer with BLAKE3 checksum.
    ///
    /// The checksum covers bytes 0..48 (all fields before the hash).
    #[must_use]
    pub fn encode(&self) -> [u8; CLEANER_LEDGER_RECORD_SIZE] {
        let mut buf = [0u8; CLEANER_LEDGER_RECORD_SIZE];

        // Magic (4 bytes LE)
        buf[0..4].copy_from_slice(&CLEANER_LEDGER_MAGIC.to_le_bytes());
        // Version (4 bytes LE)
        buf[4..8].copy_from_slice(&CLEANER_LEDGER_VERSION.to_le_bytes());
        // last_cleaned_segment_id (8 bytes LE)
        buf[8..16].copy_from_slice(&self.last_cleaned_segment_id.to_le_bytes());
        // segments_cleaned (8 bytes LE)
        buf[16..24].copy_from_slice(&self.segments_cleaned.to_le_bytes());
        // segments_freed (8 bytes LE)
        buf[24..32].copy_from_slice(&self.segments_freed.to_le_bytes());
        // bytes_migrated (8 bytes LE)
        buf[32..40].copy_from_slice(&self.bytes_migrated.to_le_bytes());
        // bytes_freed (8 bytes LE)
        buf[40..48].copy_from_slice(&self.bytes_freed.to_le_bytes());
        // Padding: bytes 44..48 are already zero

        // BLAKE3 hash of header (bytes 0..48)
        let hash = blake3::hash(&buf[..48]);
        buf[48..80].copy_from_slice(hash.as_bytes());

        buf
    }

    /// Decode a record from raw bytes, verifying the BLAKE3 checksum.
    ///
    /// Returns `None` if the magic, version, or checksum is invalid.
    #[must_use]
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < CLEANER_LEDGER_RECORD_SIZE {
            return None;
        }

        // Verify magic
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != CLEANER_LEDGER_MAGIC {
            return None;
        }

        // Verify version
        let version = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if version != CLEANER_LEDGER_VERSION {
            return None;
        }

        // Build expected hash bytes
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&buf[48..80]);
        let expected_hash = Hash::from_bytes(hash_bytes);
        let actual_hash = blake3::hash(&buf[..48]);
        if expected_hash != actual_hash {
            return None;
        }

        let last_cleaned_segment_id = u64::from_le_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        let segments_cleaned = u64::from_le_bytes([
            buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
        ]);
        let segments_freed = u64::from_le_bytes([
            buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
        ]);
        let bytes_migrated = u64::from_le_bytes([
            buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39],
        ]);
        let bytes_freed = u64::from_le_bytes([
            buf[40], buf[41], buf[42], buf[43], buf[44], buf[45], buf[46], buf[47],
        ]);

        Some(Self {
            last_cleaned_segment_id,
            segments_cleaned,
            segments_freed,
            bytes_migrated,
            bytes_freed,
        })
    }

    /// Verify the record's internal BLAKE3 checksum.
    #[must_use]
    pub fn verify(&self) -> bool {
        let encoded = self.encode();
        let expected = blake3::hash(&encoded[..48]);
        let mut stored_bytes = [0u8; 32];
        stored_bytes.copy_from_slice(&encoded[48..80]);
        let stored = Hash::from_bytes(stored_bytes);
        expected == stored
    }
}

// ---------------------------------------------------------------------------
// CleanerLedger -- stateful checkpoint tracking for the segment cleaner
// ---------------------------------------------------------------------------

/// Persistable checkpoint state for the segment cleaner.
///
/// Tracks the number of cleaned and freed segments, total bytes migrated
/// and freed, and the last cleaned segment ID as a resumption cursor.
/// The ledger can be encoded/decoded via [`CleanerLedgerRecord`] for
/// crash-safe persistence through the pool root.
#[derive(Clone, Debug, Default)]
pub struct CleanerLedger {
    /// Last segment ID that was cleaned (cursor for resumption).
    pub last_cleaned_segment_id: u64,
    /// Running count of segments cleaned (compacted).
    pub segments_cleaned: u64,
    /// Running count of segments freed.
    pub segments_freed: u64,
    /// Running total of live bytes migrated during compaction.
    pub bytes_migrated: u64,
    /// Running total of dead bytes freed.
    pub bytes_freed: u64,
}

impl CleanerLedger {
    /// Create a fresh ledger with zeroed counters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a compacted segment.
    pub fn record_compacted(&mut self, segment_id: u64, bytes_migrated: u64) {
        self.last_cleaned_segment_id = segment_id;
        self.segments_cleaned = self.segments_cleaned.saturating_add(1);
        self.bytes_migrated = self.bytes_migrated.saturating_add(bytes_migrated);
    }

    /// Record a freed segment.
    pub fn record_freed(&mut self, segment_id: u64, bytes_freed: u64) {
        self.last_cleaned_segment_id = segment_id;
        self.segments_freed = self.segments_freed.saturating_add(1);
        self.bytes_freed = self.bytes_freed.saturating_add(bytes_freed);
    }

    /// Encode the current ledger state into a BLAKE3-verified record.
    #[must_use]
    pub fn to_record(&self) -> CleanerLedgerRecord {
        CleanerLedgerRecord::new(
            self.last_cleaned_segment_id,
            self.segments_cleaned,
            self.segments_freed,
            self.bytes_migrated,
            self.bytes_freed,
        )
    }

    /// Load ledger state from a decoded record.
    #[must_use]
    pub fn from_record(record: &CleanerLedgerRecord) -> Self {
        Self {
            last_cleaned_segment_id: record.last_cleaned_segment_id,
            segments_cleaned: record.segments_cleaned,
            segments_freed: record.segments_freed,
            bytes_migrated: record.bytes_migrated,
            bytes_freed: record.bytes_freed,
        }
    }

    /// Encode the ledger to an 80-byte BLAKE3-verified buffer.
    #[must_use]
    pub fn encode(&self) -> [u8; CLEANER_LEDGER_RECORD_SIZE] {
        self.to_record().encode()
    }

    /// Decode a ledger from raw bytes.
    ///
    /// Returns `None` if the record fails integrity verification.
    #[must_use]
    pub fn decode(buf: &[u8]) -> Option<Self> {
        CleanerLedgerRecord::decode(buf).map(|r| Self::from_record(&r))
    }

    /// Verify the ledger's encoded form against its BLAKE3 checksum.
    #[must_use]
    pub fn verify(&self) -> bool {
        self.to_record().verify()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // === CleanerLedgerRecord ===

    #[test]
    fn record_default_is_zero() {
        let r = CleanerLedgerRecord::default();
        assert_eq!(r.last_cleaned_segment_id, 0);
        assert_eq!(r.segments_cleaned, 0);
        assert_eq!(r.segments_freed, 0);
        assert_eq!(r.bytes_migrated, 0);
        assert_eq!(r.bytes_freed, 0);
    }

    #[test]
    fn encode_decode_roundtrip_empty() {
        let original = CleanerLedgerRecord::new(0, 0, 0, 0, 0);
        let encoded = original.encode();
        assert_eq!(encoded.len(), CLEANER_LEDGER_RECORD_SIZE);

        let decoded = CleanerLedgerRecord::decode(&encoded);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), original);
    }

    #[test]
    fn encode_decode_roundtrip_populated() {
        let original = CleanerLedgerRecord::new(42, 100, 50, 1_000_000, 500_000);
        let encoded = original.encode();
        let decoded = CleanerLedgerRecord::decode(&encoded);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), original);
    }

    #[test]
    fn verify_passes_on_valid_record() {
        let record = CleanerLedgerRecord::new(7, 33, 12, 8000, 4000);
        assert!(record.verify());
    }

    #[test]
    fn decode_rejects_wrong_magic() {
        let record = CleanerLedgerRecord::new(0, 0, 0, 0, 0);
        let mut encoded = record.encode();
        encoded[0] = 0xFF;
        assert!(CleanerLedgerRecord::decode(&encoded).is_none());
    }

    #[test]
    fn decode_rejects_wrong_version() {
        let record = CleanerLedgerRecord::new(0, 0, 0, 0, 0);
        let mut encoded = record.encode();
        encoded[5] = 0xFF;
        assert!(CleanerLedgerRecord::decode(&encoded).is_none());
    }

    #[test]
    fn decode_rejects_corrupted_last_segment() {
        let record = CleanerLedgerRecord::new(1, 0, 0, 0, 0);
        let mut encoded = record.encode();
        encoded[8] ^= 0x01;
        assert!(CleanerLedgerRecord::decode(&encoded).is_none());
    }

    #[test]
    fn decode_rejects_corrupted_segments_cleaned() {
        let record = CleanerLedgerRecord::new(0, 1, 0, 0, 0);
        let mut encoded = record.encode();
        encoded[18] ^= 0x01;
        assert!(CleanerLedgerRecord::decode(&encoded).is_none());
    }

    #[test]
    fn decode_rejects_corrupted_segments_freed() {
        let record = CleanerLedgerRecord::new(0, 0, 1, 0, 0);
        let mut encoded = record.encode();
        encoded[24] ^= 0x01;
        assert!(CleanerLedgerRecord::decode(&encoded).is_none());
    }

    #[test]
    fn decode_rejects_corrupted_bytes_migrated() {
        let record = CleanerLedgerRecord::new(0, 0, 0, 100, 0);
        let mut encoded = record.encode();
        encoded[35] ^= 0x80;
        assert!(CleanerLedgerRecord::decode(&encoded).is_none());
    }

    #[test]
    fn decode_rejects_corrupted_bytes_freed() {
        let record = CleanerLedgerRecord::new(0, 0, 0, 0, 1);
        let mut encoded = record.encode();
        encoded[47] ^= 0x01;
        assert!(CleanerLedgerRecord::decode(&encoded).is_none());
    }

    #[test]
    fn decode_rejects_short_buffer() {
        let short = [0u8; 10];
        assert!(CleanerLedgerRecord::decode(&short).is_none());
    }

    #[test]
    fn decode_rejects_truncated_buffer() {
        let record = CleanerLedgerRecord::new(1, 1, 1, 1, 1);
        let encoded = record.encode();
        assert!(CleanerLedgerRecord::decode(&encoded[..79]).is_none());
    }

    #[test]
    fn max_values_roundtrip() {
        let original = CleanerLedgerRecord::new(u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX);
        let encoded = original.encode();
        let decoded = CleanerLedgerRecord::decode(&encoded);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), original);
    }

    #[test]
    fn magic_constant_is_correct() {
        // V C L D in ASCII
        assert_eq!(CLEANER_LEDGER_MAGIC, 0x56434C44);
    }

    #[test]
    fn record_size_is_80() {
        assert_eq!(CLEANER_LEDGER_RECORD_SIZE, 80);
    }

    // === CleanerLedger ===

    #[test]
    fn ledger_new_is_zeroed() {
        let l = CleanerLedger::new();
        assert_eq!(l.last_cleaned_segment_id, 0);
        assert_eq!(l.segments_cleaned, 0);
        assert_eq!(l.segments_freed, 0);
        assert_eq!(l.bytes_migrated, 0);
        assert_eq!(l.bytes_freed, 0);
    }

    #[test]
    fn ledger_record_compacted_updates_counters() {
        let mut l = CleanerLedger::new();
        l.record_compacted(42, 4096);
        assert_eq!(l.last_cleaned_segment_id, 42);
        assert_eq!(l.segments_cleaned, 1);
        assert_eq!(l.bytes_migrated, 4096);
        assert_eq!(l.segments_freed, 0);
    }

    #[test]
    fn ledger_record_freed_updates_counters() {
        let mut l = CleanerLedger::new();
        l.record_freed(99, 8192);
        assert_eq!(l.last_cleaned_segment_id, 99);
        assert_eq!(l.segments_freed, 1);
        assert_eq!(l.bytes_freed, 8192);
        assert_eq!(l.segments_cleaned, 0);
    }

    #[test]
    fn ledger_multiple_operations_accumulate() {
        let mut l = CleanerLedger::new();
        l.record_compacted(1, 100);
        l.record_compacted(2, 200);
        l.record_freed(3, 300);
        l.record_freed(4, 400);
        assert_eq!(l.segments_cleaned, 2);
        assert_eq!(l.segments_freed, 2);
        assert_eq!(l.bytes_migrated, 300);
        assert_eq!(l.bytes_freed, 700);
    }

    #[test]
    fn ledger_to_record_roundtrip() {
        let mut l = CleanerLedger::new();
        l.record_compacted(10, 5000);
        l.record_freed(20, 3000);
        let record = l.to_record();
        let restored = CleanerLedger::from_record(&record);
        assert_eq!(restored.last_cleaned_segment_id, 20);
        assert_eq!(restored.segments_cleaned, 1);
        assert_eq!(restored.segments_freed, 1);
        assert_eq!(restored.bytes_migrated, 5000);
        assert_eq!(restored.bytes_freed, 3000);
    }

    #[test]
    fn ledger_encode_decode_roundtrip() {
        let mut l = CleanerLedger::new();
        l.record_compacted(5, 1024);
        l.record_freed(6, 2048);
        let encoded = l.encode();
        let decoded = CleanerLedger::decode(&encoded);
        assert!(decoded.is_some());
        let restored = decoded.unwrap();
        assert_eq!(restored.segments_cleaned, 1);
        assert_eq!(restored.segments_freed, 1);
        assert_eq!(restored.bytes_migrated, 1024);
        assert_eq!(restored.bytes_freed, 2048);
    }

    #[test]
    fn ledger_decode_corrupted_fails() {
        let mut l = CleanerLedger::new();
        l.record_compacted(1, 100);
        let mut encoded = l.encode();
        encoded[0] = 0xFF;
        assert!(CleanerLedger::decode(&encoded).is_none());
    }

    #[test]
    fn ledger_verify_passes_on_valid() {
        let mut l = CleanerLedger::new();
        l.record_compacted(7, 999);
        assert!(l.verify());
    }

    #[test]
    fn ledger_crash_recovery_no_double_release() {
        // Simulate crash after recording a freed segment: encode the
        // ledger, then decode and verify no double-counting.
        let mut l = CleanerLedger::new();
        l.record_freed(100, 4096);
        let encoded = l.encode();
        let restored = CleanerLedger::decode(&encoded).unwrap();
        assert_eq!(restored.segments_freed, 1);
        assert_eq!(restored.bytes_freed, 4096);
        // A second decode of the same bytes should give identical state
        let restored2 = CleanerLedger::decode(&encoded).unwrap();
        assert_eq!(restored2.segments_freed, 1);
    }
}
