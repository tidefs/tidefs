//! Object-store-level intent-log record types with BLAKE3-verified binary
//! encode/decode.
//!
//! Every record is framed as:
//!
//! ```text
//! discriminant (u16 LE) | body_len (u32 LE) | body (variable) | checksum ([u8; 32])
//! ```
//!
//! The BLAKE3-256 checksum covers `discriminant || body_len || body` with a
//! domain-separated context `"TideFS ObjectStore IntentLogRecord v2"` to
//! prevent cross-schema digest collisions.
//!
//! # Authority boundary
//!
//! This record family is for **raw object-store mutations only**:
//! `WritePayload`, `TxBegin`, `TxCommit`, `TxAbort`, and `ExportTerminal`.
//! Filesystem-level operations (Create, Unlink, Rename, Mkdir, Rmdir, Fsync,
//! SetAttr, XattrSet, XattrRemove) are owned by
//! [`tidefs_intent_log::IntentLogRecord`].

use crate::ObjectKey;

// ---------------------------------------------------------------------------
// Domain context for intent-log record checksums
// ---------------------------------------------------------------------------

/// Domain context string for BLAKE3 key derivation on intent-log records.
const INTENT_LOG_RECORD_DOMAIN: &str = "TideFS ObjectStore IntentLogRecord v2";

// ---------------------------------------------------------------------------
// Record type discriminant values
// ---------------------------------------------------------------------------

/// Discriminant for [`IntentLogRecord::WritePayload`].
pub const DISCR_WRITE_PAYLOAD: u16 = 1;
/// Discriminant for [`IntentLogRecord::TxBegin`].
pub const DISCR_TX_BEGIN: u16 = 6;
/// Discriminant for [`IntentLogRecord::TxCommit`].
pub const DISCR_TX_COMMIT: u16 = 7;
/// Discriminant for [`IntentLogRecord::TxAbort`].
pub const DISCR_TX_ABORT: u16 = 8;
/// Discriminant for [`IntentLogRecord::ExportTerminal`].
pub const DISCR_EXPORT_TERMINAL: u16 = 9;

// ---------------------------------------------------------------------------
// IntentLogRecord
// ---------------------------------------------------------------------------

/// A single object-store-level intent-log record covering data writes and
/// transaction boundaries.
///
/// Variants:
///
/// | Variant          | Discriminant | Purpose                                       |
/// |------------------|-------------|-----------------------------------------------|
/// | `WritePayload`   | 1           | Data write with object_id, offset, payload    |
/// | `TxBegin`        | 6           | Begin a transaction                           |
/// | `TxCommit`       | 7           | Commit a transaction                          |
/// | `TxAbort`        | 8           | Abort a transaction                           |
/// | `ExportTerminal` | 9           | Clean shutdown marker written at pool export  |
///
/// Filesystem-level operations (Create, Unlink, Rename, Mkdir, Rmdir, Fsync,
/// SetAttr, XattrSet, XattrRemove) are owned by
/// [`tidefs_intent_log::IntentLogRecord`]. The object-store WAL must not
/// accept or record filesystem variants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntentLogRecord {
    /// Write payload data to an object at a specific offset.
    WritePayload {
        /// Content-addressed object identifier.
        object_id: ObjectKey,
        /// Byte offset within the object.
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
    /// Abort (roll back) a transaction group.
    TxAbort {
        /// Transaction identifier matching a prior `TxBegin`.
        cg_id: u64,
    },
    /// Export terminal: clean shutdown marker written at pool export time.
    ExportTerminal {
        /// Transaction identifier matching the final committed commit_group.
        cg_id: u64,
    },
}

impl IntentLogRecord {
    /// Compute a BLAKE3-256 domain-separated checksum over framed record bytes.
    ///
    /// The checksum covers `discriminant || body_len || body`.
    fn compute_checksum(framed: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(INTENT_LOG_RECORD_DOMAIN);
        hasher.update(framed);
        hasher.finalize().into()
    }

    /// Encode this record into a byte vector.
    ///
    /// Returns the framed bytes: `discriminant | body_len | body | checksum`.
    pub fn encode(&self) -> Vec<u8> {
        let (discr, body) = self.encode_body();
        let body_len = body.len() as u32;
        let capacity = 2 + 4 + body.len() + 32;
        let mut buf = Vec::with_capacity(capacity);

        buf.extend_from_slice(&discr.to_le_bytes());
        buf.extend_from_slice(&body_len.to_le_bytes());
        buf.extend_from_slice(&body);

        let checksum = Self::compute_checksum(&buf);
        buf.extend_from_slice(&checksum);

        buf
    }

    /// Encode the variant-specific body bytes (without framing or checksum).
    fn encode_body(&self) -> (u16, Vec<u8>) {
        match self {
            Self::WritePayload {
                object_id,
                offset,
                data,
            } => {
                let data_len = data.len().min(u32::MAX as usize) as u32;
                let mut body = Vec::with_capacity(32 + 8 + 4 + data.len());
                body.extend_from_slice(object_id.as_bytes());
                body.extend_from_slice(&offset.to_le_bytes());
                body.extend_from_slice(&data_len.to_le_bytes());
                body.extend_from_slice(data);
                (DISCR_WRITE_PAYLOAD, body)
            }
            Self::TxBegin { cg_id } => {
                let mut body = Vec::with_capacity(8);
                body.extend_from_slice(&cg_id.to_le_bytes());
                (DISCR_TX_BEGIN, body)
            }
            Self::TxCommit { cg_id } => {
                let mut body = Vec::with_capacity(8);
                body.extend_from_slice(&cg_id.to_le_bytes());
                (DISCR_TX_COMMIT, body)
            }
            Self::TxAbort { cg_id } => {
                let mut body = Vec::with_capacity(8);
                body.extend_from_slice(&cg_id.to_le_bytes());
                (DISCR_TX_ABORT, body)
            }
            Self::ExportTerminal { cg_id } => {
                let mut body = Vec::with_capacity(8);
                body.extend_from_slice(&cg_id.to_le_bytes());
                (DISCR_EXPORT_TERMINAL, body)
            }
        }
    }

    /// Decode an `IntentLogRecord` from framed bytes.
    ///
    /// Validates the BLAKE3-256 checksum before parsing the body. Returns
    /// `Ok(record)` on success, or `Err(description)` on any failure.
    pub fn decode(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < 2 + 4 + 32 {
            return Err("buffer too short for intent-log record framing".into());
        }

        let discr = u16::from_le_bytes([buf[0], buf[1]]);
        let body_len = u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]) as usize;
        let framed_end = 2 + 4 + body_len;
        let checksum_start = framed_end;
        let total_expected = checksum_start + 32;

        if buf.len() < total_expected {
            return Err(format!(
                "buffer too short: have {} bytes, need {total_expected} (body_len={body_len})",
                buf.len()
            ));
        }

        // Verify checksum over discriminant + body_len + body
        let expected_checksum: [u8; 32] =
            buf[checksum_start..checksum_start + 32].try_into().unwrap();
        let actual_checksum = Self::compute_checksum(&buf[..framed_end]);
        if actual_checksum != expected_checksum {
            return Err("BLAKE3 checksum mismatch on intent-log record".into());
        }

        let body = &buf[6..framed_end];
        Self::decode_body(discr, body)
    }

    /// Decode a record body from bytes (already checksum-verified).
    fn decode_body(discr: u16, body: &[u8]) -> Result<Self, String> {
        match discr {
            DISCR_WRITE_PAYLOAD => {
                if body.len() < 32 + 8 + 4 {
                    return Err("WritePayload body too short".into());
                }
                let object_id_bytes: [u8; 32] = body[0..32].try_into().unwrap();
                let object_id = ObjectKey::from_bytes(object_id_bytes);
                let offset = u64::from_le_bytes([
                    body[32], body[33], body[34], body[35], body[36], body[37], body[38], body[39],
                ]);
                let data_len =
                    u32::from_le_bytes([body[40], body[41], body[42], body[43]]) as usize;
                let data_start = 44;
                if body.len() < data_start + data_len {
                    return Err(format!(
                        "WritePayload data truncated: need {data_len} bytes, have {}",
                        body.len().saturating_sub(data_start)
                    ));
                }
                let data = body[data_start..data_start + data_len].to_vec();
                Ok(Self::WritePayload {
                    object_id,
                    offset,
                    data,
                })
            }
            DISCR_TX_BEGIN => {
                if body.len() < 8 {
                    return Err("TxBegin body too short".into());
                }
                let cg_id = u64::from_le_bytes([
                    body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
                ]);
                Ok(Self::TxBegin { cg_id })
            }
            DISCR_TX_COMMIT => {
                if body.len() < 8 {
                    return Err("TxCommit body too short".into());
                }
                let cg_id = u64::from_le_bytes([
                    body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
                ]);
                Ok(Self::TxCommit { cg_id })
            }
            DISCR_TX_ABORT => {
                if body.len() < 8 {
                    return Err("TxAbort body too short".into());
                }
                let cg_id = u64::from_le_bytes([
                    body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
                ]);
                Ok(Self::TxAbort { cg_id })
            }
            DISCR_EXPORT_TERMINAL => {
                if body.len() < 8 {
                    return Err("ExportTerminal body too short".into());
                }
                let cg_id = u64::from_le_bytes([
                    body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
                ]);
                Ok(Self::ExportTerminal { cg_id })
            }
            _ => Err(format!(
                "unknown or rejected intent-log record discriminant: {discr} (not a valid object-store mutation)"
            )),
        }
    }

    /// Return the discriminant value for this record variant.
    pub fn discriminant(&self) -> u16 {
        match self {
            Self::WritePayload { .. } => DISCR_WRITE_PAYLOAD,
            Self::TxBegin { .. } => DISCR_TX_BEGIN,
            Self::TxCommit { .. } => DISCR_TX_COMMIT,
            Self::TxAbort { .. } => DISCR_TX_ABORT,
            Self::ExportTerminal { .. } => DISCR_EXPORT_TERMINAL,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Build a deterministic test ObjectKey from a u64.
    fn test_key(id: u64) -> ObjectKey {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&id.to_le_bytes());
        ObjectKey::from_bytes(bytes)
    }

    // ── WritePayload round-trip and error paths ─────────────────────

    #[test]
    fn write_payload_roundtrip() {
        let record = IntentLogRecord::WritePayload {
            object_id: test_key(1),
            offset: 4096,
            data: b"hello write-ahead log payload".to_vec(),
        };
        let encoded = record.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(decoded, record);
    }

    #[test]
    fn write_payload_empty_data() {
        let record = IntentLogRecord::WritePayload {
            object_id: test_key(2),
            offset: 0,
            data: Vec::new(),
        };
        let encoded = record.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(decoded, record);
    }

    #[test]
    fn write_payload_large_offset() {
        let record = IntentLogRecord::WritePayload {
            object_id: test_key(3),
            offset: u64::MAX,
            data: vec![0xAAu8; 1024],
        };
        let encoded = record.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(decoded, record);
    }

    #[test]
    fn write_payload_checksum_rejects_corruption() {
        let record = IntentLogRecord::WritePayload {
            object_id: test_key(4),
            offset: 128,
            data: b"tamper test".to_vec(),
        };
        let mut encoded = record.encode();
        // Flip a bit in the framed body
        encoded[10] ^= 0x01;
        assert!(IntentLogRecord::decode(&encoded).is_err());
    }

    #[test]
    fn write_payload_checksum_rejects_truncation() {
        let record = IntentLogRecord::WritePayload {
            object_id: test_key(5),
            offset: 0,
            data: b"will be truncated".to_vec(),
        };
        let encoded = record.encode();
        let truncated = &encoded[..encoded.len() - 1];
        assert!(IntentLogRecord::decode(truncated).is_err());
    }

    #[test]
    fn write_payload_rejects_inflated_body_len() {
        let record = IntentLogRecord::WritePayload {
            object_id: test_key(6),
            offset: 0,
            data: b"small".to_vec(),
        };
        let mut encoded = record.encode();
        // Inflate body_len to exceed actual buffer
        encoded[2] = 0xFF;
        encoded[3] = 0xFF;
        assert!(IntentLogRecord::decode(&encoded).is_err());
    }

    // ── Transaction boundary round-trips ────────────────────────────

    #[test]
    fn tx_begin_roundtrip() {
        let record = IntentLogRecord::TxBegin { cg_id: 1 };
        let encoded = record.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(decoded, record);
    }

    #[test]
    fn tx_commit_roundtrip() {
        let record = IntentLogRecord::TxCommit { cg_id: 42 };
        let encoded = record.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(decoded, record);
    }

    #[test]
    fn tx_abort_roundtrip() {
        let record = IntentLogRecord::TxAbort { cg_id: 7 };
        let encoded = record.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(decoded, record);
    }

    #[test]
    fn export_terminal_roundtrip() {
        let record = IntentLogRecord::ExportTerminal { cg_id: 99 };
        let encoded = record.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(decoded, record);
    }

    // ── Discriminant uniqueness ─────────────────────────────────────

    #[test]
    fn discriminant_values_are_unique() {
        let records: &[IntentLogRecord] = &[
            IntentLogRecord::WritePayload {
                object_id: test_key(0),
                offset: 0,
                data: vec![],
            },
            IntentLogRecord::TxBegin { cg_id: 0 },
            IntentLogRecord::TxCommit { cg_id: 0 },
            IntentLogRecord::TxAbort { cg_id: 0 },
            IntentLogRecord::ExportTerminal { cg_id: 0 },
        ];
        let mut seen = HashSet::new();
        for r in records {
            let d = r.discriminant();
            assert!(seen.insert(d), "duplicate discriminant: {d}");
        }
    }

    // ── Decode error paths ──────────────────────────────────────────

    #[test]
    fn decode_rejects_empty_buffer() {
        assert!(IntentLogRecord::decode(&[]).is_err());
    }

    #[test]
    fn decode_rejects_short_buffer() {
        // Need at least 2+4+32 = 38 bytes for framing
        assert!(IntentLogRecord::decode(&[0u8; 37]).is_err());
    }

    #[test]
    fn decode_rejects_unknown_discriminant() {
        // Craft a valid frame with discriminant 0xFF (unknown), body_len=0
        let discr: u16 = 0xFF;
        let body_len: u32 = 0;
        let mut buf = Vec::new();
        buf.extend_from_slice(&discr.to_le_bytes());
        buf.extend_from_slice(&body_len.to_le_bytes());
        let checksum = IntentLogRecord::compute_checksum(&buf);
        buf.extend_from_slice(&checksum);
        assert!(IntentLogRecord::decode(&buf).is_err());
    }

    /// Filesystem discriminant values (2,3,4,5,10,11,12,13,14) must be
    /// rejected — they belong to the canonical `tidefs_intent_log`, not
    /// the object-store WAL.
    ///
    /// This covers every canonical `IntentLogRecord` discriminant that
    /// is not a valid object-store mutation variant
    /// (`WritePayload`=1, `TxBegin`=6, `TxCommit`=7, `TxAbort`=8,
    /// `ExportTerminal`=9).  The canonical record family uses u8
    /// discriminants; this test encodes them as u16 LE to match the
    /// object-store WAL framing.  Domain-separated BLAKE3 checksums
    /// provide an additional integrity boundary even for discriminant
    /// value 1, which exists in both families with different binary
    /// formats.
    #[test]
    fn decode_rejects_filesystem_discriminants() {
        // Canonical tidefs_intent_log::RECORD_DISCRIMINANT_* values that
        // are not valid object-store discriminants (1,6,7,8,9).
        let filesystem_discrs: &[u16] = &[
            2, 3, 4, 5, // Truncate,SetAttr,Create,Unlink
            10, 11, 12, 13, 14, // Rmdir,Mknod,XattrSet,Fallocate,BufferedWrite
            15, 16, 17, 18, 19, // WriteIntentAck,XattrRemove,Tmpfile,Flush,Lseek
            20, 21, 22, // Fsync,CleanupQueue,CopyFileRange
            23, 24, 25, 26, // TxBegin,TxCommit,TxAbort,ExportTerminal (canonical)
        ];
        for &discr in filesystem_discrs {
            let body_len: u32 = 0;
            let mut buf = Vec::new();
            buf.extend_from_slice(&discr.to_le_bytes());
            buf.extend_from_slice(&body_len.to_le_bytes());
            let checksum = IntentLogRecord::compute_checksum(&buf);
            buf.extend_from_slice(&checksum);
            let result = IntentLogRecord::decode(&buf);
            assert!(
                result.is_err(),
                "filesystem discriminant {discr} must be rejected by object-store WAL"
            );
        }
    }
}
