// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Compact wire encoding for transition journal entries.
//!
//! Converts between the internal [`crate::transition_journal::TransitionRecord`]
//! and the compact wire representation [`JournalWireEntry`] defined in
//! `tidefs-membership-types`. Provides batch framing with
//! [`JournalSyncBatch`] for efficient multi-entry transport transmission.
//!
//! ## Wire format
//!
//! ### JournalWireEntry
//!
//! Each entry uses variable-length integer encoding for transition ids,
//! epochs, peer ids, and timestamps. Entry kinds use fixed 1-byte
//! discriminants (0x01=Join, 0x02=Leave, 0x03=CoordinatorChange).
//!
//! ### JournalSyncBatch
//!
//! ```text
//! [0..8)   base_epoch        u64 LE
//! [8..12)  entry_count       u32 LE
//! [12..16) total_byte_length u32 LE (payload bytes, excluding this 16-byte header)
//! [16..]   entries           concatenated JournalWireEntry records
//! ```
//!
//! ## Integration
//!
//! [`JournalSyncBatch`] is registered as `MembershipMessage::JournalSyncBatch`
//! (discriminant 27) and `MembershipOutboundMessage::JournalSyncBatch` for
//! transport peer synchronization of transition journal state.

use crate::transition_journal::{TransitionKind, TransitionRecord, TransitionStatus};
use crate::{EpochId, LeaveReason, MemberId};
use tidefs_membership_types::{JournalEntryKind, JournalWireEntry};

// ---------------------------------------------------------------------------
// TransitionJournalCodec
// ---------------------------------------------------------------------------

/// Converts between internal [`TransitionRecord`] and compact wire
/// [`JournalWireEntry`] representations.
pub struct TransitionJournalCodec;

impl TransitionJournalCodec {
    /// Encode a single [`TransitionRecord`] into a [`JournalWireEntry`].
    #[must_use]
    pub fn encode_entry(record: &TransitionRecord) -> JournalWireEntry {
        let (entry_kind, peer_id, epoch, reason) = match &record.kind {
            TransitionKind::Join { peer_id, epoch } => {
                (JournalEntryKind::Join, *peer_id, *epoch, 0u8)
            }
            TransitionKind::Leave {
                peer_id,
                epoch,
                reason: leave_reason,
            } => {
                let reason_byte = match leave_reason {
                    LeaveReason::Voluntary => 0,
                    LeaveReason::Maintenance => 1,
                    LeaveReason::Draining => 2,
                };
                (JournalEntryKind::Leave, *peer_id, *epoch, reason_byte)
            }
        };

        let status_byte = match record.status {
            TransitionStatus::Prepared => 0,
            TransitionStatus::Committed => 1,
            TransitionStatus::Aborted => 2,
        };

        JournalWireEntry {
            entry_kind,
            transition_id: record.id.0,
            epoch: epoch.0,
            peer_id: peer_id.0,
            prepared_at_millis: record.prepared_at_millis,
            finalised_at_millis: record.finalised_at_millis,
            status: status_byte,
            reason,
        }
    }

    /// Decode a [`JournalWireEntry`] back into a [`TransitionRecord`].
    ///
    /// # Errors
    ///
    /// Returns `Err` if the decoded entry has an invalid status byte or
    /// unsupported entry kind.
    pub fn decode_entry(entry: &JournalWireEntry) -> Result<TransitionRecord, String> {
        let status = match entry.status {
            0 => TransitionStatus::Prepared,
            1 => TransitionStatus::Committed,
            2 => TransitionStatus::Aborted,
            other => return Err(format!("invalid journal entry status: {other}")),
        };

        let kind = match entry.entry_kind {
            JournalEntryKind::Join => TransitionKind::Join {
                peer_id: MemberId::new(entry.peer_id),
                epoch: EpochId::new(entry.epoch),
            },
            JournalEntryKind::Leave => {
                let reason = match entry.reason {
                    0 => LeaveReason::Voluntary,
                    1 => LeaveReason::Maintenance,
                    2 => LeaveReason::Draining,
                    other => return Err(format!("invalid leave reason byte: {other}")),
                };
                TransitionKind::Leave {
                    peer_id: MemberId::new(entry.peer_id),
                    epoch: EpochId::new(entry.epoch),
                    reason,
                }
            }
            JournalEntryKind::CoordinatorChange => {
                return Err("CoordinatorChange entries not yet supported".to_string());
            }
        };

        Ok(TransitionRecord {
            id: crate::transition_journal::TransitionId::new(entry.transition_id),
            kind,
            status,
            prepared_at_millis: entry.prepared_at_millis,
            finalised_at_millis: entry.finalised_at_millis,
        })
    }
}

// ---------------------------------------------------------------------------
// JournalSyncBatch
// ---------------------------------------------------------------------------

/// A batch of transition journal entries for transport synchronization.
///
/// Carries a base epoch and one or more journal entries representing
/// transitions committed at or after that epoch. Encoded as a header
/// followed by concatenated [`JournalWireEntry`] records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalSyncBatch {
    /// The base epoch from which these entries start.
    pub base_epoch: u64,
    /// The journal entries in this batch (insertion order).
    pub entries: Vec<JournalWireEntry>,
}

impl JournalSyncBatch {
    /// Create a new empty batch at the given base epoch.
    #[must_use]
    pub fn new(base_epoch: u64) -> Self {
        Self {
            base_epoch,
            entries: Vec::new(),
        }
    }

    /// Number of entries in this batch.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Whether the batch is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add an entry to the batch.
    pub fn push(&mut self, entry: JournalWireEntry) {
        self.entries.push(entry);
    }

    /// Total encoded payload size (entries only, excluding 16-byte header).
    #[must_use]
    pub fn payload_byte_length(&self) -> usize {
        self.entries.iter().map(|e| e.encoded_size()).sum()
    }

    /// Total encoded size including the 16-byte header.
    #[must_use]
    pub fn total_encoded_size(&self) -> usize {
        16 + self.payload_byte_length()
    }

    /// Encode this batch into a byte vector.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let payload_len = self.payload_byte_length() as u32;
        let mut buf = Vec::with_capacity(16 + payload_len as usize);

        // Header: base_epoch (u64 LE) + entry_count (u32 LE) + total_byte_length (u32 LE)
        buf.extend_from_slice(&self.base_epoch.to_le_bytes());
        buf.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        buf.extend_from_slice(&payload_len.to_le_bytes());

        // Concatenated entries
        for entry in &self.entries {
            entry.encode(&mut buf);
        }

        buf
    }

    /// Decode a batch from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the header is too short, the payload length is
    /// inconsistent, or any entry fails to decode.
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < 16 {
            return Err("JournalSyncBatch: data too short for header (need 16 bytes)".to_string());
        }

        let base_epoch = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let entry_count = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let payload_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;

        if data.len() < 16 + payload_len {
            return Err(format!(
                "JournalSyncBatch: data too short: expected {} bytes, got {}",
                16 + payload_len,
                data.len()
            ));
        }

        let mut entries = Vec::with_capacity(entry_count);
        let mut pos: usize = 16;
        let payload_end = 16 + payload_len;

        for _ in 0..entry_count {
            if pos >= payload_end {
                return Err(format!(
                    "JournalSyncBatch: underflow at entry {}/{entry_count}",
                    entries.len()
                ));
            }
            let entry = JournalWireEntry::decode(data, &mut pos)
                .map_err(|e| format!("JournalSyncBatch: entry decode error: {e}"))?;
            entries.push(entry);
        }

        if pos != payload_end {
            return Err(format!(
                "JournalSyncBatch: payload length mismatch: consumed {pos}, declared {payload_end}"
            ));
        }

        Ok(Self {
            base_epoch,
            entries,
        })
    }

    /// Build a batch from transition records at a given base epoch.
    #[must_use]
    pub fn from_records(base_epoch: u64, records: &[TransitionRecord]) -> Self {
        let entries: Vec<JournalWireEntry> = records
            .iter()
            .map(TransitionJournalCodec::encode_entry)
            .collect();
        Self {
            base_epoch,
            entries,
        }
    }

    /// Decode all entries in this batch back to transition records.
    ///
    /// Returns `Err` if any entry fails to decode.
    pub fn to_records(&self) -> Result<Vec<TransitionRecord>, String> {
        self.entries
            .iter()
            .map(TransitionJournalCodec::decode_entry)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transition_journal::TransitionId;

    fn make_join_record(
        id: u64,
        peer: u64,
        epoch: u64,
        status: TransitionStatus,
    ) -> TransitionRecord {
        TransitionRecord {
            id: TransitionId::new(id),
            kind: TransitionKind::Join {
                peer_id: MemberId::new(peer),
                epoch: EpochId::new(epoch),
            },
            status,
            prepared_at_millis: 1000 * id,
            finalised_at_millis: if matches!(status, TransitionStatus::Prepared) {
                0
            } else {
                2000 * id
            },
        }
    }

    fn make_leave_record(
        id: u64,
        peer: u64,
        epoch: u64,
        status: TransitionStatus,
        reason: LeaveReason,
    ) -> TransitionRecord {
        TransitionRecord {
            id: TransitionId::new(id),
            kind: TransitionKind::Leave {
                peer_id: MemberId::new(peer),
                epoch: EpochId::new(epoch),
                reason,
            },
            status,
            prepared_at_millis: 1000 * id,
            finalised_at_millis: if matches!(status, TransitionStatus::Prepared) {
                0
            } else {
                2000 * id
            },
        }
    }

    // ── Single entry roundtrip ──────────────────────────────────────

    #[test]
    fn roundtrip_join_prepared() {
        let rec = make_join_record(1, 42, 5, TransitionStatus::Prepared);
        let wire = TransitionJournalCodec::encode_entry(&rec);
        let decoded = TransitionJournalCodec::decode_entry(&wire).unwrap();
        assert_eq!(decoded, rec);
    }

    #[test]
    fn roundtrip_join_committed() {
        let rec = make_join_record(3, 10, 7, TransitionStatus::Committed);
        let wire = TransitionJournalCodec::encode_entry(&rec);
        let decoded = TransitionJournalCodec::decode_entry(&wire).unwrap();
        assert_eq!(decoded, rec);
    }

    #[test]
    fn roundtrip_leave_voluntary_aborted() {
        let rec = make_leave_record(5, 99, 3, TransitionStatus::Aborted, LeaveReason::Voluntary);
        let wire = TransitionJournalCodec::encode_entry(&rec);
        let decoded = TransitionJournalCodec::decode_entry(&wire).unwrap();
        assert_eq!(decoded, rec);
    }

    #[test]
    fn roundtrip_leave_maintenance() {
        let rec = make_leave_record(
            7,
            77,
            10,
            TransitionStatus::Committed,
            LeaveReason::Maintenance,
        );
        let wire = TransitionJournalCodec::encode_entry(&rec);
        let decoded = TransitionJournalCodec::decode_entry(&wire).unwrap();
        assert_eq!(decoded, rec);
    }

    #[test]
    fn roundtrip_leave_draining() {
        let rec = make_leave_record(9, 55, 12, TransitionStatus::Prepared, LeaveReason::Draining);
        let wire = TransitionJournalCodec::encode_entry(&rec);
        let decoded = TransitionJournalCodec::decode_entry(&wire).unwrap();
        assert_eq!(decoded, rec);
    }

    // ── Boundary values ─────────────────────────────────────────────

    #[test]
    fn roundtrip_boundary_transition_id_max() {
        let rec = TransitionRecord {
            id: TransitionId::new(u64::MAX),
            kind: TransitionKind::Join {
                peer_id: MemberId::new(u64::MAX),
                epoch: EpochId::new(u64::MAX),
            },
            status: TransitionStatus::Committed,
            prepared_at_millis: u64::MAX,
            finalised_at_millis: u64::MAX,
        };
        let wire = TransitionJournalCodec::encode_entry(&rec);
        let decoded = TransitionJournalCodec::decode_entry(&wire).unwrap();
        assert_eq!(decoded, rec);
    }

    #[test]
    fn roundtrip_boundary_zero() {
        let rec = TransitionRecord {
            id: TransitionId::new(0),
            kind: TransitionKind::Join {
                peer_id: MemberId::new(0),
                epoch: EpochId::new(0),
            },
            status: TransitionStatus::Prepared,
            prepared_at_millis: 0,
            finalised_at_millis: 0,
        };
        let wire = TransitionJournalCodec::encode_entry(&rec);
        let decoded = TransitionJournalCodec::decode_entry(&wire).unwrap();
        assert_eq!(decoded, rec);
    }

    // ── Wire encoding size assertions ───────────────────────────────

    #[test]
    fn wire_entry_small_values_are_compact() {
        let rec = TransitionRecord {
            id: TransitionId::new(1),
            kind: TransitionKind::Join {
                peer_id: MemberId::new(2),
                epoch: EpochId::new(3),
            },
            status: TransitionStatus::Prepared,
            prepared_at_millis: 100,
            finalised_at_millis: 0,
        };
        let wire = TransitionJournalCodec::encode_entry(&rec);
        // TransitionId=1 (1 byte), Epoch=3 (1 byte), PeerId=2 (1 byte),
        // prepared_at=100 (1 byte, <253), finalised=0 (1 byte)
        // Total: kind(1) + 5*1 + status(1) + reason(1) = 8
        assert_eq!(wire.encoded_size(), 8);
    }

    #[test]
    fn wire_entry_large_values_use_more_space() {
        let rec = TransitionRecord {
            id: TransitionId::new(100_000),
            kind: TransitionKind::Join {
                peer_id: MemberId::new(100_000),
                epoch: EpochId::new(100_000),
            },
            status: TransitionStatus::Committed,
            prepared_at_millis: 1_700_000_000_000,
            finalised_at_millis: 1_700_000_000_100,
        };
        let wire = TransitionJournalCodec::encode_entry(&rec);
        // 100_000 > u16::MAX (65535), so all fields use 9-byte full u64 encoding.
        // 5 fields * 9 bytes + kind(1) + status(1) + reason(1) = 48
        assert_eq!(wire.encoded_size(), 48);
    }

    #[test]
    fn wire_encoding_smaller_than_bincode() {
        // A typical join record has small integers that should encode smaller
        // than bincode's full-width representation.
        let rec = make_join_record(5, 10, 3, TransitionStatus::Committed);
        let wire = TransitionJournalCodec::encode_entry(&rec);
        let encoded = wire.encoded_size();

        // Bincode would use 8 bytes per u64 field + enum tags
        let bincode_size = 8 + // TransitionId
            8 + // EpochId
            8 + // MemberId
            8 + // prepared_at_millis
            8 + // finalised_at_millis
            1 + // TransitionKind discriminant
            1 + // TransitionStatus discriminant
            1; // LeaveReason discriminant
               // = 43 bytes minimum

        assert!(
            encoded < bincode_size,
            "wire encoding size {encoded} should be smaller than bincode size {bincode_size}"
        );
    }

    // ── Batch encoding roundtrip ────────────────────────────────────

    #[test]
    fn batch_empty() {
        let batch = JournalSyncBatch::new(0);
        let data = batch.encode();
        let decoded = JournalSyncBatch::decode(&data).unwrap();
        assert_eq!(decoded.base_epoch, 0);
        assert!(decoded.entries.is_empty());
    }

    #[test]
    fn batch_single_entry() {
        let mut batch = JournalSyncBatch::new(5);
        let rec = make_join_record(1, 42, 5, TransitionStatus::Committed);
        batch.push(TransitionJournalCodec::encode_entry(&rec));

        let data = batch.encode();
        let decoded = JournalSyncBatch::decode(&data).unwrap();
        assert_eq!(decoded.base_epoch, 5);
        assert_eq!(decoded.entries.len(), 1);
        let rec2 = TransitionJournalCodec::decode_entry(&decoded.entries[0]).unwrap();
        assert_eq!(rec2, rec);
    }

    #[test]
    fn batch_multi_entry() {
        let mut batch = JournalSyncBatch::new(3);
        let r1 = make_join_record(1, 10, 3, TransitionStatus::Committed);
        let r2 = make_join_record(2, 20, 3, TransitionStatus::Committed);
        let r3 = make_leave_record(
            3,
            10,
            4,
            TransitionStatus::Committed,
            LeaveReason::Voluntary,
        );
        batch.push(TransitionJournalCodec::encode_entry(&r1));
        batch.push(TransitionJournalCodec::encode_entry(&r2));
        batch.push(TransitionJournalCodec::encode_entry(&r3));

        let data = batch.encode();
        let decoded = JournalSyncBatch::decode(&data).unwrap();
        assert_eq!(decoded.entries.len(), 3);

        let recovered: Vec<TransitionRecord> = decoded
            .entries
            .iter()
            .map(|e| TransitionJournalCodec::decode_entry(e).unwrap())
            .collect();
        assert_eq!(recovered, vec![r1, r2, r3]);
    }

    #[test]
    fn batch_from_records_roundtrip() {
        let records = vec![
            make_join_record(1, 10, 0, TransitionStatus::Committed),
            make_join_record(2, 20, 1, TransitionStatus::Committed),
            make_leave_record(
                3,
                10,
                2,
                TransitionStatus::Committed,
                LeaveReason::Voluntary,
            ),
        ];
        let batch = JournalSyncBatch::from_records(0, &records);
        let decoded_records = batch.to_records().unwrap();
        assert_eq!(decoded_records, records);
    }

    #[test]
    fn batch_decode_underflow_header() {
        let data = vec![0u8; 10]; // too short for 16-byte header
        assert!(JournalSyncBatch::decode(&data).is_err());
    }

    #[test]
    fn batch_decode_payload_length_mismatch() {
        let mut batch = JournalSyncBatch::new(0);
        batch.push(TransitionJournalCodec::encode_entry(&make_join_record(
            1,
            1,
            0,
            TransitionStatus::Committed,
        )));
        let mut data = batch.encode();
        // Corrupt payload length to be too large
        data[12] = 0xFF;
        assert!(JournalSyncBatch::decode(&data).is_err());
    }

    // ── Size assertions for batches ─────────────────────────────────

    #[test]
    fn batch_total_encoded_size_matches_actual() {
        let mut batch = JournalSyncBatch::new(0);
        for i in 1..=5 {
            batch.push(TransitionJournalCodec::encode_entry(&make_join_record(
                i,
                i * 10,
                0,
                TransitionStatus::Committed,
            )));
        }
        let expected = batch.total_encoded_size();
        let actual = batch.encode().len();
        assert_eq!(actual, expected);
    }
}
