// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! BLAKE3 domain-separated slot integrity verification.
//!
//! Every TDMA slot is hashed with BLAKE3-256 under a domain tag `"TdmaSlot"`
//! so the hash can be verified later. Tampered slot data (any field mutation)
//! produces a mismatched hash.

/// Domain tag used for BLAKE3 keyed hashing of TDMA slot data.
pub const TDMA_SLOT_DOMAIN: &[u8] = b"TdmaSlot";

/// Errors from integrity verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SlotIntegrityError {
    /// The stored BLAKE3 hash does not match the slot data.
    #[error("BLAKE3 checksum mismatch for slot: computed {computed}, stored {stored}")]
    ChecksumMismatch { computed: String, stored: String },
}

/// Input to the slot-integrity hash: the fields that determine slot identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdmaSlotHashInput {
    /// Epoch this slot belongs to.
    pub epoch: u64,
    /// Node that owns this slot.
    pub node_id: u64,
    /// Write transaction-group identifier.
    pub write_txg: u64,
    /// Slot index within the epoch.
    pub slot_index: u64,
    /// Slot start wall-clock time in milliseconds.
    pub slot_start: u64,
    /// Slot end wall-clock time in milliseconds.
    pub slot_end: u64,
}

/// BLAKE3-256 domain-separated slot hasher.
///
/// Produces a 32-byte integrity hash for [`TdmaSlotHashInput`] data. Use
/// [`hash_slot`](Self::hash_slot) to compute and
/// [`verify_slot`](Self::verify_slot) to check.
pub struct SlotIntegrity;

impl SlotIntegrity {
    /// Hash slot data with BLAKE3-256 under domain tag `"TdmaSlot"`.
    ///
    /// The canonical wire encoding is the concatenation of all fields
    /// in little-endian u64 order: epoch, node_id, write_txg, slot_index,
    /// slot_start, slot_end.
    pub fn hash_slot(input: &TdmaSlotHashInput) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(TDMA_SLOT_DOMAIN);
        hasher.update(&input.epoch.to_le_bytes());
        hasher.update(&input.node_id.to_le_bytes());
        hasher.update(&input.write_txg.to_le_bytes());
        hasher.update(&input.slot_index.to_le_bytes());
        hasher.update(&input.slot_start.to_le_bytes());
        hasher.update(&input.slot_end.to_le_bytes());
        hasher.finalize().into()
    }

    /// Verify that `stored_hash` matches a fresh hash of `input`.
    ///
    /// Returns `Ok(())` on match or [`SlotIntegrityError::ChecksumMismatch`].
    pub fn verify_slot(
        input: &TdmaSlotHashInput,
        stored_hash: &[u8; 32],
    ) -> Result<(), SlotIntegrityError> {
        let computed = Self::hash_slot(input);
        if &computed == stored_hash {
            Ok(())
        } else {
            Err(SlotIntegrityError::ChecksumMismatch {
                computed: hex_encode(&computed),
                stored: hex_encode(stored_hash),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_input() -> TdmaSlotHashInput {
        TdmaSlotHashInput {
            epoch: 7,
            node_id: 42,
            write_txg: 3,
            slot_index: 15,
            slot_start: 1000,
            slot_end: 1100,
        }
    }

    #[test]
    fn hash_is_deterministic() {
        let h1 = SlotIntegrity::hash_slot(&test_input());
        let h2 = SlotIntegrity::hash_slot(&test_input());
        assert_eq!(h1, h2);
    }

    #[test]
    fn verify_matching_passes() {
        let input = test_input();
        let hash = SlotIntegrity::hash_slot(&input);
        assert!(SlotIntegrity::verify_slot(&input, &hash).is_ok());
    }

    #[test]
    fn verify_tampered_epoch_fails() {
        let input = test_input();
        let hash = SlotIntegrity::hash_slot(&input);
        let mut tampered = input;
        tampered.epoch = 99;
        assert!(SlotIntegrity::verify_slot(&tampered, &hash).is_err());
    }

    #[test]
    fn verify_tampered_node_id_fails() {
        let input = test_input();
        let hash = SlotIntegrity::hash_slot(&input);
        let mut tampered = input;
        tampered.node_id = 999;
        assert!(SlotIntegrity::verify_slot(&tampered, &hash).is_err());
    }

    #[test]
    fn verify_tampered_txg_fails() {
        let input = test_input();
        let hash = SlotIntegrity::hash_slot(&input);
        let mut tampered = input;
        tampered.write_txg = 99;
        assert!(SlotIntegrity::verify_slot(&tampered, &hash).is_err());
    }

    #[test]
    fn verify_tampered_slot_index_fails() {
        let input = test_input();
        let hash = SlotIntegrity::hash_slot(&input);
        let mut tampered = input;
        tampered.slot_index = 999;
        assert!(SlotIntegrity::verify_slot(&tampered, &hash).is_err());
    }

    #[test]
    fn verify_tampered_slot_start_fails() {
        let input = test_input();
        let hash = SlotIntegrity::hash_slot(&input);
        let mut tampered = input;
        tampered.slot_start = 9999;
        assert!(SlotIntegrity::verify_slot(&tampered, &hash).is_err());
    }

    #[test]
    fn verify_tampered_slot_end_fails() {
        let input = test_input();
        let hash = SlotIntegrity::hash_slot(&input);
        let mut tampered = input;
        tampered.slot_end = 9999;
        assert!(SlotIntegrity::verify_slot(&tampered, &hash).is_err());
    }

    #[test]
    fn error_message_contains_hex_hashes() {
        let input = test_input();
        let hash = SlotIntegrity::hash_slot(&input);
        let mut tampered = input;
        tampered.epoch = 0;
        let err = SlotIntegrity::verify_slot(&tampered, &hash).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("BLAKE3 checksum mismatch"));
        assert!(msg.contains("computed"));
        assert!(msg.contains("stored"));
    }

    #[test]
    fn domain_tag_separation_different_hashes() {
        // Hash without domain tag vs. with domain tag -- same data, different hash.
        let input = test_input();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&input.epoch.to_le_bytes());
        hasher.update(&input.node_id.to_le_bytes());
        hasher.update(&input.write_txg.to_le_bytes());
        hasher.update(&input.slot_index.to_le_bytes());
        hasher.update(&input.slot_start.to_le_bytes());
        hasher.update(&input.slot_end.to_le_bytes());
        let untagged: [u8; 32] = hasher.finalize().into();

        let tagged = SlotIntegrity::hash_slot(&input);
        assert_ne!(untagged, tagged, "domain tag should change hash output");
    }

    #[test]
    fn hash_is_32_bytes() {
        let h = SlotIntegrity::hash_slot(&test_input());
        assert_eq!(h.len(), 32);
    }
}
