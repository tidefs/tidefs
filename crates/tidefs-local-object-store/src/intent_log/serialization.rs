// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Serialization helpers that convert transaction mutations into
//! append-ready intent-log record buffers.
//!
//! Bridges the gap between the [`tidefs_commit_group`] accumulator types
//! and the [`IntentLogRecord`] on-disk format. Each mutation is converted
//! to a framed, BLAKE3-verified record suitable for durable append.
//!
//! # Record layout per mutation
//!
//! Each mutation is encoded as an [`IntentLogRecord`], which already
//! includes its own BLAKE3-256 checksum. The batch serialization helper
//! wraps the encoded records in a binary-schema envelope via
//! [`super::framing::encode_framed`] for segment storage.
//!
//! # Authority
//!
//! This module only handles **object-store mutations**: `WritePayload`,
//! `TxBegin`, `TxCommit`, and `ExportTerminal`. Filesystem-level mutations
//! are owned by [`tidefs_intent_log`].

use super::record::IntentLogRecord;
use crate::ObjectKey;

// ---------------------------------------------------------------------------
// TransactionMutation
// ---------------------------------------------------------------------------

/// A single transactional mutation ready for intent-log serialization.
///
/// This is the bridge type between the object-store write path and the
/// intent-log record format. Each variant carries the fields needed to
/// produce a complete [`IntentLogRecord`].
///
/// Only object-store mutations are supported. Filesystem mutations
/// (Create, Unlink, Rename, Mkdir, Rmdir, Fsync, SetAttr, XattrSet,
/// XattrRemove) belong to [`tidefs_intent_log::IntentLogRecord`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactionMutation {
    /// Write payload data to a content-addressed object.
    WritePayload {
        /// Content-addressed object identifier.
        object_id: ObjectKey,
        /// Byte offset within the object (0 for new puts).
        offset: u64,
        /// Payload data bytes.
        data: Vec<u8>,
    },
    /// Begin a transaction group.
    TxBegin {
        /// Monotonically increasing transaction identifier.
        cg_id: u64,
    },
    /// Commit a transaction group.
    TxCommit {
        /// Transaction identifier matching a prior `TxBegin`.
        cg_id: u64,
    },
    /// Export terminal: clean shutdown marker written at pool export time.
    ExportTerminal {
        /// Transaction identifier matching the final committed commit_group.
        cg_id: u64,
    },
}

impl TransactionMutation {
    /// Convert this mutation into an [`IntentLogRecord`].
    ///
    /// This is a pure data conversion with no allocation beyond what the
    /// record type requires. The caller is responsible for encoding the
    /// record (which adds the BLAKE3 checksum) via [`IntentLogRecord::encode`].
    pub fn to_intent_log_record(&self) -> IntentLogRecord {
        match self {
            Self::WritePayload {
                object_id,
                offset,
                data,
            } => IntentLogRecord::WritePayload {
                object_id: *object_id,
                offset: *offset,
                data: data.clone(),
            },
            Self::TxBegin { cg_id } => IntentLogRecord::TxBegin { cg_id: *cg_id },
            Self::TxCommit { cg_id } => IntentLogRecord::TxCommit { cg_id: *cg_id },
            Self::ExportTerminal { cg_id } => IntentLogRecord::ExportTerminal { cg_id: *cg_id },
        }
    }

    /// Encode this mutation into an append-ready byte buffer.
    ///
    /// Equivalent to `self.to_intent_log_record().encode()`.
    pub fn encode(&self) -> Vec<u8> {
        self.to_intent_log_record().encode()
    }

    /// Create a `WritePayload` mutation from an object key, offset, and data.
    pub fn from_write(object_id: ObjectKey, offset: u64, data: &[u8]) -> Self {
        Self::WritePayload {
            object_id,
            offset,
            data: data.to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// Batch serialization
// ---------------------------------------------------------------------------

/// Convert a slice of [`TransactionMutation`]s into a framed batch segment.
///
/// Each mutation is encoded via [`TransactionMutation::encode`] (which
/// includes its BLAKE3 checksum), then the encoded records are wrapped in
/// a binary-schema envelope via [`super::framing::encode_framed`].
///
/// Use [`super::framing::decode_framed`] to recover the individual records
/// during replay.
pub fn serialize_mutations(mutations: &[TransactionMutation]) -> Vec<u8> {
    let records: Vec<Vec<u8>> = mutations.iter().map(|m| m.encode()).collect();
    super::framing::encode_framed(&records)
}

/// Build a complete transaction batch: `TxBegin` + mutations + `TxCommit`.
///
/// Returns the framed segment bytes ready for durable append.
pub fn serialize_transaction(cg_id: u64, mutations: &[TransactionMutation]) -> Vec<u8> {
    let mut all = Vec::with_capacity(mutations.len() + 2);
    all.push(TransactionMutation::TxBegin { cg_id });
    all.extend_from_slice(mutations);
    all.push(TransactionMutation::TxCommit { cg_id });
    serialize_mutations(&all)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(id: u64) -> ObjectKey {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&id.to_le_bytes());
        ObjectKey::from_bytes(bytes)
    }

    // ── Single mutation round-trip ──────────────────────────────────

    #[test]
    fn write_payload_roundtrip() {
        let mutation = TransactionMutation::WritePayload {
            object_id: test_key(1),
            offset: 4096,
            data: b"test payload".to_vec(),
        };
        let encoded = mutation.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        let re_encoded = decoded.encode();
        assert_eq!(encoded, re_encoded);

        match decoded {
            IntentLogRecord::WritePayload {
                object_id,
                offset,
                data,
            } => {
                assert_eq!(object_id, test_key(1));
                assert_eq!(offset, 4096);
                assert_eq!(data, b"test payload");
            }
            _ => panic!("expected WritePayload"),
        }
    }

    #[test]
    fn tx_boundaries_roundtrip() {
        for mutation in &[
            TransactionMutation::TxBegin { cg_id: 1 },
            TransactionMutation::TxCommit { cg_id: 1 },
            TransactionMutation::ExportTerminal { cg_id: 99 },
        ] {
            let encoded = mutation.encode();
            let decoded = IntentLogRecord::decode(&encoded).unwrap();
            let re_encoded = decoded.encode();
            assert_eq!(encoded, re_encoded);
        }
    }

    // ── Batch serialization ─────────────────────────────────────────

    #[test]
    fn serialize_mutations_empty() {
        let framed = serialize_mutations(&[]);
        let decoded = super::super::framing::decode_framed(&framed).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn serialize_mutations_batch_roundtrip() {
        let mutations = vec![
            TransactionMutation::TxBegin { cg_id: 1 },
            TransactionMutation::WritePayload {
                object_id: test_key(2),
                offset: 0,
                data: b"batch data".to_vec(),
            },
            TransactionMutation::TxCommit { cg_id: 1 },
        ];

        let framed = serialize_mutations(&mutations);
        let decoded_records = super::super::framing::decode_framed(&framed).unwrap();
        assert_eq!(decoded_records.len(), 3);

        // Verify each decoded record re-encodes to match the original
        for (i, encoded) in decoded_records.iter().enumerate() {
            let decoded = IntentLogRecord::decode(encoded).unwrap();
            assert_eq!(decoded.encode(), *encoded, "record {i} round-trip mismatch");
        }
    }

    #[test]
    fn serialize_transaction_wraps_boundaries() {
        let mutations = vec![TransactionMutation::WritePayload {
            object_id: test_key(10),
            offset: 0,
            data: b"txn payload".to_vec(),
        }];

        let framed = serialize_transaction(42, &mutations);
        let decoded_records = super::super::framing::decode_framed(&framed).unwrap();

        // Expect: TxBegin(42) + 1 mutation + TxCommit(42) = 3 records
        assert_eq!(decoded_records.len(), 3);

        let decoded: Vec<IntentLogRecord> = decoded_records
            .iter()
            .map(|e| IntentLogRecord::decode(e).unwrap())
            .collect();

        assert!(matches!(decoded[0], IntentLogRecord::TxBegin { cg_id: 42 }));
        assert!(matches!(decoded[1], IntentLogRecord::WritePayload { .. }));
        assert!(matches!(
            decoded[2],
            IntentLogRecord::TxCommit { cg_id: 42 }
        ));
    }

    #[test]
    fn serialize_transaction_checksums_protect_data() {
        let mutations = vec![TransactionMutation::WritePayload {
            object_id: test_key(1),
            offset: 0,
            data: b"checksum test".to_vec(),
        }];

        let framed = serialize_transaction(1, &mutations);

        // Corrupt a byte in the middle of the frame (past the envelope header)
        let mut corrupted = framed.clone();
        if corrupted.len() > 80 {
            corrupted[80] ^= 0xFF;
        }

        // Decoding should fail because the BLAKE3 per-record checksum catches it
        let result = super::super::framing::decode_framed(&corrupted);
        if let Ok(records) = result {
            let all_valid = records.iter().all(|r| IntentLogRecord::decode(r).is_ok());
            assert!(!all_valid || records.is_empty());
        }
    }

    // ── Constructor helpers ─────────────────────────────────────────

    #[test]
    fn from_write_preserves_data() {
        let mutation = TransactionMutation::from_write(test_key(42), 4096, b"write data");
        match mutation {
            TransactionMutation::WritePayload {
                object_id,
                offset,
                data,
            } => {
                assert_eq!(object_id, test_key(42));
                assert_eq!(offset, 4096);
                assert_eq!(data, b"write data");
            }
            _ => panic!("expected WritePayload"),
        }
    }

    // ── Checksum verification ───────────────────────────────────────

    #[test]
    fn all_mutation_variants_produce_verifiable_records() {
        let mutations: &[TransactionMutation] = &[
            TransactionMutation::WritePayload {
                object_id: test_key(1),
                offset: 0,
                data: vec![0xAA; 64],
            },
            TransactionMutation::TxBegin { cg_id: 1 },
            TransactionMutation::TxCommit { cg_id: 1 },
            TransactionMutation::ExportTerminal { cg_id: 1 },
        ];

        for (i, m) in mutations.iter().enumerate() {
            let encoded = m.encode();
            let decoded = IntentLogRecord::decode(&encoded)
                .unwrap_or_else(|e| panic!("variant {i}: decode failed: {e}"));
            let re_encoded = decoded.encode();
            assert_eq!(encoded, re_encoded, "variant {i}: round-trip mismatch");
        }
    }

    /// Filesystem mutations must panic or be impossible — the
    /// `TransactionMutation` enum no longer accepts filesystem variants.
    #[test]
    fn no_filesystem_variants_in_transaction_mutation() {
        // Compile-time check: TransactionMutation has exactly 4 variants.
        // If someone adds a filesystem variant, this match will fail to compile
        // because it won't be exhaustive.
        let m = TransactionMutation::TxBegin { cg_id: 0 };
        match m {
            TransactionMutation::WritePayload { .. }
            | TransactionMutation::TxBegin { .. }
            | TransactionMutation::TxCommit { .. }
            | TransactionMutation::ExportTerminal { .. } => {}
        }
    }
}
