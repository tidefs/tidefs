//! BLAKE3-verified persistent scrub progress ledger.
//!
//! [`ScrubLedger`] records the last-scanned position so that an interrupted
//! scrub can resume without re-scanning already-verified object ranges.
//!
//! # On-disk format (72 bytes)
//!
//! ```text
//! Offset  Size  Field
//! ------  ----  -----
//! 0       4     Magic ("VSCB")
//! 4       4     Version (u32 LE)
//! 8       8     last_scanned_object_id (u64 LE)
//! 16      8     current_epoch (u64 LE)
//! 24      8     scan_sequence (u64 LE)
//! 32      8     Reserved (zero)
//! 40      32    BLAKE3-256 hash (covers bytes 0..40)
//! ```

/// Magic bytes identifying a scrub ledger on disk.
const LEDGER_MAGIC: &[u8; 4] = b"VSCB";

/// Current ledger format version.
const LEDGER_VERSION: u32 = 1;

/// Total size of a serialized scrub ledger (72 bytes).
const LEDGER_SIZE: usize = 72;

/// Number of header bytes covered by the BLAKE3 hash.
const HEADER_SIZE: usize = 40;

/// Byte offset where the BLAKE3-256 hash is stored.
const HASH_OFFSET: usize = 40;

/// BLAKE3-verified persistent scrub progress ledger.
///
/// Records the position from which the next scrub cycle should start.
/// The ledger is sealed with a BLAKE3-256 hash covering the header so
/// that tampering or corruption is detectable on load.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScrubLedger {
    /// The last object ID that was fully verified.
    pub last_scanned_object_id: u64,
    /// The membership epoch during which this ledger was last updated.
    pub current_epoch: u64,
    /// Monotonically increasing scan sequence number.
    pub scan_sequence: u64,
    /// BLAKE3-256 hash covering the header (bytes 0..40).
    hash: [u8; 32],
}

impl ScrubLedger {
    /// Create a fresh ledger at position zero.
    #[must_use]
    pub fn new(current_epoch: u64) -> Self {
        let mut ledger = Self {
            last_scanned_object_id: 0,
            current_epoch,
            scan_sequence: 0,
            hash: [0u8; 32],
        };
        ledger.seal();
        ledger
    }

    /// Deserialize a ledger from raw bytes and verify its integrity.
    ///
    /// Returns `None` if the magic does not match, the version is unknown,
    /// or the BLAKE3 hash does not verify.
    #[must_use]
    pub fn read(bytes: &[u8; LEDGER_SIZE]) -> Option<Self> {
        if &bytes[0..4] != LEDGER_MAGIC {
            return None;
        }
        let version = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        if version != LEDGER_VERSION {
            return None;
        }

        let last_scanned_object_id = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
        let current_epoch = u64::from_le_bytes(bytes[16..24].try_into().ok()?);
        let scan_sequence = u64::from_le_bytes(bytes[24..32].try_into().ok()?);
        let stored_hash: [u8; 32] = bytes[HASH_OFFSET..HASH_OFFSET + 32].try_into().ok()?;

        let ledger = Self {
            last_scanned_object_id,
            current_epoch,
            scan_sequence,
            hash: stored_hash,
        };

        if !ledger.verify() {
            return None;
        }

        Some(ledger)
    }

    /// Serialize the ledger to a 72-byte array.
    #[must_use]
    pub fn serialize(&self) -> [u8; LEDGER_SIZE] {
        let mut buf = [0u8; LEDGER_SIZE];
        buf[0..4].copy_from_slice(LEDGER_MAGIC);
        buf[4..8].copy_from_slice(&LEDGER_VERSION.to_le_bytes());
        buf[8..16].copy_from_slice(&self.last_scanned_object_id.to_le_bytes());
        buf[16..24].copy_from_slice(&self.current_epoch.to_le_bytes());
        buf[24..32].copy_from_slice(&self.scan_sequence.to_le_bytes());
        // bytes 32..40 remain zero (reserved)
        buf[HASH_OFFSET..HASH_OFFSET + 32].copy_from_slice(&self.hash);
        buf
    }

    /// Compute the BLAKE3-256 hash over the header bytes and store it.
    pub fn seal(&mut self) {
        let header = self.header_bytes();
        let hash: [u8; 32] = blake3::hash(&header).into();
        self.hash = hash;
    }

    /// Verify that the stored hash matches a recomputed hash of the header.
    #[must_use]
    pub fn verify(&self) -> bool {
        let header = self.header_bytes();
        let computed: [u8; 32] = blake3::hash(&header).into();
        computed == self.hash
    }

    /// Update the ledger position after verifying a batch of objects.
    ///
    /// Advances `last_scanned_object_id` to `new_position`, increments
    /// `scan_sequence`, and re-seals the ledger.
    pub fn update_position(&mut self, new_position: u64) {
        self.last_scanned_object_id = new_position;
        self.scan_sequence = self.scan_sequence.wrapping_add(1);
        self.seal();
    }

    /// Build the header bytes (bytes 0..HEADER_SIZE) for hashing.
    fn header_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut header = [0u8; HEADER_SIZE];
        header[0..4].copy_from_slice(LEDGER_MAGIC);
        header[4..8].copy_from_slice(&LEDGER_VERSION.to_le_bytes());
        header[8..16].copy_from_slice(&self.last_scanned_object_id.to_le_bytes());
        header[16..24].copy_from_slice(&self.current_epoch.to_le_bytes());
        header[24..32].copy_from_slice(&self.scan_sequence.to_le_bytes());
        header
    }

    /// Return the stored BLAKE3 hash.
    #[must_use]
    pub fn stored_hash(&self) -> &[u8; 32] {
        &self.hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_ledger_has_valid_seal() {
        let ledger = ScrubLedger::new(1);
        assert!(ledger.verify());
        assert_eq!(ledger.last_scanned_object_id, 0);
        assert_eq!(ledger.current_epoch, 1);
        assert_eq!(ledger.scan_sequence, 0);
    }

    #[test]
    fn serialize_round_trip() {
        let mut ledger = ScrubLedger::new(5);
        ledger.update_position(42);
        let bytes = ledger.serialize();
        let restored = ScrubLedger::read(&bytes).expect("round-trip failed");
        assert_eq!(restored.last_scanned_object_id, 42);
        assert_eq!(restored.current_epoch, 5);
        assert_eq!(restored.scan_sequence, 1);
        assert!(restored.verify());
    }

    #[test]
    fn tampered_magic_rejected() {
        let ledger = ScrubLedger::new(1);
        let mut bytes = ledger.serialize();
        bytes[0] = b'X';
        assert!(ScrubLedger::read(&bytes).is_none());
    }

    #[test]
    fn tampered_hash_rejected() {
        let ledger = ScrubLedger::new(1);
        let mut bytes = ledger.serialize();
        bytes[HASH_OFFSET] ^= 0xFF;
        assert!(ScrubLedger::read(&bytes).is_none());
    }

    #[test]
    fn tampered_position_rejected() {
        let ledger = ScrubLedger::new(1);
        let mut bytes = ledger.serialize();
        bytes[8] ^= 0x01;
        assert!(ScrubLedger::read(&bytes).is_none());
    }

    #[test]
    fn update_position_advances_and_reseals() {
        let mut ledger = ScrubLedger::new(3);
        let old_hash = *ledger.stored_hash();

        ledger.update_position(100);
        assert_eq!(ledger.last_scanned_object_id, 100);
        assert_eq!(ledger.scan_sequence, 1);
        assert_ne!(*ledger.stored_hash(), old_hash);
        assert!(ledger.verify());
    }

    #[test]
    fn unknown_version_rejected() {
        let ledger = ScrubLedger::new(1);
        let mut bytes = ledger.serialize();
        bytes[4..8].copy_from_slice(&999u32.to_le_bytes());
        assert!(ScrubLedger::read(&bytes).is_none());
    }
}
