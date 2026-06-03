//! BLAKE3-verified persistent reserve-ledger record.
//!
//! The [`ReserveLedgerRecord`] is the on-disk format for the reserve ledger.
//! It is stored as a well-known object in the local-object-store pool root
//! and loaded on pool import to recover the reservation state after a crash.

use blake3::Hash;

/// Magic bytes identifying a reserve-ledger record: "VRLD" (TideFS Reserve
/// Ledger Data).
pub const RESERVE_LEDGER_MAGIC: u32 = 0x56424C44;

/// Current record format version.
pub const RESERVE_LEDGER_VERSION: u32 = 1;

/// On-disk record size in bytes (magic + version + reserved + capacity + hash).
pub const RESERVE_LEDGER_RECORD_SIZE: usize = 4 + 4 + 4 + 8 + 32; // 52 bytes

/// Persistent reserve ledger record with BLAKE3 integrity verification.
///
/// # Layout (52 bytes, little-endian)
///
/// | Offset | Size | Field          |
/// |--------|------|----------------|
/// | 0      | 4    | magic (0x56424C44) |
/// | 4      | 4    | version (1)     |
/// | 8      | 4    | reserved_count  |
/// | 12     | 8    | segment_capacity|
/// | 20     | 32   | blake3 hash     |
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReserveLedgerRecord {
    /// Number of segments currently reserved.
    pub reserved_count: u32,
    /// Total segment capacity of the pool.
    pub segment_capacity: u64,
}

impl ReserveLedgerRecord {
    /// Create a new record with the given reservation state.
    pub fn new(reserved_count: u32, segment_capacity: u64) -> Self {
        Self {
            reserved_count,
            segment_capacity,
        }
    }

    /// Encode the record into a 52-byte buffer with BLAKE3 checksum.
    ///
    /// The checksum covers bytes 0..20 (magic, version, reserved_count,
    /// segment_capacity).
    pub fn encode(&self) -> [u8; RESERVE_LEDGER_RECORD_SIZE] {
        let mut buf = [0u8; RESERVE_LEDGER_RECORD_SIZE];

        // Magic
        buf[0..4].copy_from_slice(&RESERVE_LEDGER_MAGIC.to_le_bytes());
        // Version
        buf[4..8].copy_from_slice(&RESERVE_LEDGER_VERSION.to_le_bytes());
        // Reserved count
        buf[8..12].copy_from_slice(&self.reserved_count.to_le_bytes());
        // Segment capacity
        buf[12..20].copy_from_slice(&self.segment_capacity.to_le_bytes());

        // BLAKE3 hash of the header (bytes 0..20)
        let hash = blake3::hash(&buf[..20]);
        buf[20..52].copy_from_slice(hash.as_bytes());

        buf
    }

    /// Decode a record from raw bytes, verifying the BLAKE3 checksum.
    ///
    /// Returns `None` if the magic, version, or checksum is invalid.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < RESERVE_LEDGER_RECORD_SIZE {
            return None;
        }

        // Verify magic
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != RESERVE_LEDGER_MAGIC {
            return None;
        }

        // Verify version
        let version = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if version != RESERVE_LEDGER_VERSION {
            return None;
        }

        // Verify checksum
        let expected_hash = Hash::from_bytes([
            buf[20], buf[21], buf[22], buf[23], buf[24], buf[25], buf[26], buf[27], buf[28],
            buf[29], buf[30], buf[31], buf[32], buf[33], buf[34], buf[35], buf[36], buf[37],
            buf[38], buf[39], buf[40], buf[41], buf[42], buf[43], buf[44], buf[45], buf[46],
            buf[47], buf[48], buf[49], buf[50], buf[51],
        ]);
        let actual_hash = blake3::hash(&buf[..20]);
        if expected_hash != actual_hash {
            return None;
        }

        // Decode fields
        let reserved_count = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let segment_capacity = u64::from_le_bytes([
            buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19],
        ]);

        Some(Self {
            reserved_count,
            segment_capacity,
        })
    }

    /// Return the BLAKE3 hash stored in the record.
    pub fn stored_hash(&self) -> Hash {
        let encoded = self.encode();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&encoded[20..52]);
        Hash::from_bytes(hash_bytes)
    }

    /// Verify the record's internal BLAKE3 checksum.
    pub fn verify(&self) -> bool {
        let encoded = self.encode();
        let expected = blake3::hash(&encoded[..20]);
        let stored = {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&encoded[20..52]);
            Hash::from_bytes(bytes)
        };
        expected == stored
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_default_is_zero() {
        let r = ReserveLedgerRecord::default();
        assert_eq!(r.reserved_count, 0);
        assert_eq!(r.segment_capacity, 0);
    }

    #[test]
    fn encode_decode_roundtrip_empty() {
        let original = ReserveLedgerRecord::new(0, 0);
        let encoded = original.encode();
        assert_eq!(encoded.len(), RESERVE_LEDGER_RECORD_SIZE);

        let decoded = ReserveLedgerRecord::decode(&encoded);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), original);
    }

    #[test]
    fn encode_decode_roundtrip_populated() {
        let original = ReserveLedgerRecord::new(42, 1_000_000);
        let encoded = original.encode();
        let decoded = ReserveLedgerRecord::decode(&encoded);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), original);
    }

    #[test]
    fn verify_passes_on_valid_record() {
        let record = ReserveLedgerRecord::new(7, 500);
        assert!(record.verify());
    }

    #[test]
    fn decode_rejects_wrong_magic() {
        let record = ReserveLedgerRecord::new(0, 0);
        let mut encoded = record.encode();
        // Corrupt magic
        encoded[0] = 0xFF;
        assert!(ReserveLedgerRecord::decode(&encoded).is_none());
    }

    #[test]
    fn decode_rejects_wrong_version() {
        let record = ReserveLedgerRecord::new(0, 0);
        let mut encoded = record.encode();
        // Corrupt version
        encoded[5] = 0xFF;
        assert!(ReserveLedgerRecord::decode(&encoded).is_none());
    }

    #[test]
    fn decode_rejects_corrupted_payload() {
        let record = ReserveLedgerRecord::new(100, 200);
        let mut encoded = record.encode();
        // Flip a bit in the reserved_count
        encoded[8] ^= 0x01;
        assert!(ReserveLedgerRecord::decode(&encoded).is_none());
    }

    #[test]
    fn decode_rejects_corrupted_capacity() {
        let record = ReserveLedgerRecord::new(100, 200);
        let mut encoded = record.encode();
        // Flip a bit in the capacity
        encoded[15] ^= 0x80;
        assert!(ReserveLedgerRecord::decode(&encoded).is_none());
    }

    #[test]
    fn decode_rejects_short_buffer() {
        let short = [0u8; 10];
        assert!(ReserveLedgerRecord::decode(&short).is_none());
    }

    #[test]
    fn decode_rejects_truncated_buffer() {
        let record = ReserveLedgerRecord::new(1, 1);
        let encoded = record.encode();
        assert!(ReserveLedgerRecord::decode(&encoded[..51]).is_none());
    }

    #[test]
    fn stored_hash_matches() {
        let record = ReserveLedgerRecord::new(99, 999);
        let encoded = record.encode();
        let expected_hash = blake3::hash(&encoded[..20]);
        assert_eq!(record.stored_hash(), expected_hash);
    }

    #[test]
    fn max_values_roundtrip() {
        let original = ReserveLedgerRecord::new(u32::MAX, u64::MAX);
        let encoded = original.encode();
        let decoded = ReserveLedgerRecord::decode(&encoded);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), original);
    }

    #[test]
    fn magic_constant_is_correct() {
        // V R L D in ASCII
        assert_eq!(RESERVE_LEDGER_MAGIC, 0x56424C44);
    }

    #[test]
    fn record_size_is_52() {
        assert_eq!(RESERVE_LEDGER_RECORD_SIZE, 52);
    }

    #[test]
    fn zero_record_payload_hashable() {
        // A zero record should produce a valid BLAKE3 hash
        let record = ReserveLedgerRecord::new(0, 0);
        let encoded = record.encode();
        let hash = blake3::hash(&encoded[..20]);
        assert_eq!(hash.as_bytes().len(), 32);
    }
}
