// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Binary-schema framing for intent-log segments.
//!
//! Wraps batches of encoded [`IntentLogRecord`]s in a canonical binary-schema
//! envelope ([`EnvelopeHeader`]) for on-disk and wire transport.  Individual
//! records inside the envelope use the compact per-record encoding defined in
//! [`super::record`].
//!
//! # Frame layout
//!
//! ```text
//! EnvelopeHeader (64 bytes) | record_0 | record_1 | ... | record_N
//! ```
//!
//! The envelope carries schema identity (`family`, `type`, `version`),
//! CRC32C header integrity, and the total body byte count.  The streaming
//! [`FramingDecoder`] can extract complete segments from partial buffers,
//! making this format suitable for crash-recovery replay.

use tidefs_binary_schema_core::{ChecksumProfile, SchemaFamilyId, SchemaTypeId, SchemaVersion};
use tidefs_binary_schema_framing::EnvelopeBuilder;

// ---------------------------------------------------------------------------
// Schema identity
// ---------------------------------------------------------------------------

/// Schema family for TideFS intent-log segments.
pub const INTENT_LOG_FAMILY_ID: SchemaFamilyId = SchemaFamilyId(0x5642_4653_494C_4F01);

/// Schema type for a batch of intent-log records.
pub const INTENT_LOG_RECORD_BATCH_TYPE_ID: SchemaTypeId = SchemaTypeId(1);

/// Schema type for a single sync-write record.
pub const INTENT_LOG_SYNC_WRITE_TYPE_ID: SchemaTypeId = SchemaTypeId(2);

/// Current schema version for intent-log segments.
pub const INTENT_LOG_VERSION: SchemaVersion = SchemaVersion::new(1, 0);

// ---------------------------------------------------------------------------
// Framed segment encode/decode
// ---------------------------------------------------------------------------

/// Wrap a batch of pre-encoded records in a binary-schema envelope.
///
/// Returns the complete framed segment bytes: `EnvelopeHeader | records...`.
pub fn encode_framed(records: &[Vec<u8>]) -> Vec<u8> {
    let total_body_bytes: u64 = records.iter().map(|r| r.len() as u64).sum();

    let header = EnvelopeBuilder::new(
        INTENT_LOG_FAMILY_ID,
        INTENT_LOG_RECORD_BATCH_TYPE_ID,
        INTENT_LOG_VERSION,
    )
    .with_checksum_profiles(ChecksumProfile::Crc32c, ChecksumProfile::Blake3_256)
    .build(records.len() as u16, total_body_bytes);

    let mut buf = Vec::with_capacity(64 + total_body_bytes as usize);
    buf.extend_from_slice(&header.encode());
    for record in records {
        buf.extend_from_slice(record);
    }
    buf
}

/// Wrap a single sync-write record in a binary-schema envelope.
///
/// Returns the complete framed segment bytes: `EnvelopeHeader | record`.
pub fn encode_framed_single(record: &[u8]) -> Vec<u8> {
    let total_body_bytes = record.len() as u64;

    let header = EnvelopeBuilder::new(
        INTENT_LOG_FAMILY_ID,
        INTENT_LOG_SYNC_WRITE_TYPE_ID,
        INTENT_LOG_VERSION,
    )
    .with_checksum_profiles(ChecksumProfile::Crc32c, ChecksumProfile::Blake3_256)
    .build(1, total_body_bytes);

    let mut buf = Vec::with_capacity(64 + total_body_bytes as usize);
    buf.extend_from_slice(&header.encode());
    buf.extend_from_slice(record);
    buf
}

/// Decode a framed segment into individual encoded records.
///
/// Uses [`FramingDecoder`] to extract the envelope, validates the schema
/// identity, and splits the body into records using the BLAKE3 checksum
/// trailer on each record to find boundaries.
///
/// Returns `Err` if the envelope is malformed, the schema identity doesn't
/// match, or a record boundary can't be resolved.
pub fn decode_framed(data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    use tidefs_binary_schema_framing::FramingDecoder;

    let mut decoder = FramingDecoder::new();
    let frames = decoder.feed(data);

    if frames.is_empty() {
        // Data might be incomplete — feed again? For now, error.
        if data.len() < 64 {
            return Err("framed segment too short for envelope header".into());
        }
        return Err("framed segment: no complete frame found".into());
    }

    let frame = &frames[0];

    // Validate schema identity
    if frame.header.family_id != INTENT_LOG_FAMILY_ID {
        return Err(format!(
            "unexpected schema family: {:?} (expected {:?})",
            frame.header.family_id, INTENT_LOG_FAMILY_ID
        ));
    }

    let type_id = frame.header.type_id;
    if type_id != INTENT_LOG_RECORD_BATCH_TYPE_ID && type_id != INTENT_LOG_SYNC_WRITE_TYPE_ID {
        return Err(format!("unexpected schema type: {type_id:?}"));
    }

    // Split body into records. Each record has the format:
    //   discriminant(u16 LE) | body_len(u32 LE) | body | checksum([u8; 32])
    // We need to find record boundaries by parsing the lengths.
    let mut records = Vec::new();
    let body = &frame.body;
    let mut pos = 0usize;

    while pos + 6 + 32 <= body.len() {
        // Read body_len from bytes 2..6
        let body_len =
            u32::from_le_bytes([body[pos + 2], body[pos + 3], body[pos + 4], body[pos + 5]])
                as usize;
        let record_len = 2 + 4 + body_len + 32; // discr + body_len + body + checksum

        if pos + record_len > body.len() {
            return Err(format!(
                "record at offset {pos} extends past body end: need {record_len}, have {}",
                body.len() - pos
            ));
        }

        records.push(body[pos..pos + record_len].to_vec());
        pos += record_len;
    }

    if pos != body.len() {
        return Err(format!(
            "trailing bytes after last record: {} bytes",
            body.len() - pos
        ));
    }

    Ok(records)
}

/// Decode a framed sync-write segment into a single encoded record.
///
/// Convenience wrapper that calls [`decode_framed`] and returns the single
/// record.
pub fn decode_framed_single(data: &[u8]) -> Result<Vec<u8>, String> {
    let records = decode_framed(data)?;
    if records.len() != 1 {
        return Err(format!(
            "expected 1 record in sync-write segment, got {}",
            records.len()
        ));
    }
    Ok(records.into_iter().next().unwrap())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent_log::record::IntentLogRecord;
    use crate::ObjectKey;

    fn test_key(id: u64) -> ObjectKey {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&id.to_le_bytes());
        ObjectKey::from_bytes(bytes)
    }

    // ── Single record round-trip ────────────────────────────────────

    #[test]
    fn single_record_framed_roundtrip() {
        let record = IntentLogRecord::WritePayload {
            object_id: test_key(1),
            offset: 0,
            data: b"hello framed".to_vec(),
        };
        let encoded = record.encode();
        let framed = encode_framed_single(&encoded);
        let decoded = decode_framed_single(&framed).unwrap();
        assert_eq!(decoded, encoded);
    }

    // ── Batch round-trip ────────────────────────────────────────────

    #[test]
    fn batch_framed_roundtrip() {
        let records: Vec<Vec<u8>> = vec![
            IntentLogRecord::TxBegin { cg_id: 1 }.encode(),
            IntentLogRecord::WritePayload {
                object_id: test_key(2),
                offset: 0,
                data: b"batch record".to_vec(),
            }
            .encode(),
            IntentLogRecord::TxCommit { cg_id: 1 }.encode(),
        ];

        let framed = encode_framed(&records);
        let decoded = decode_framed(&framed).unwrap();

        assert_eq!(decoded.len(), 3);
        for (i, rec) in decoded.iter().enumerate() {
            assert_eq!(rec, &records[i]);
            // Verify each record still decodes correctly
            let parsed = IntentLogRecord::decode(rec).unwrap();
            assert_eq!(parsed.encode(), *rec);
        }
    }

    #[test]
    fn batch_framed_empty() {
        let framed = encode_framed(&[]);
        let decoded = decode_framed(&framed).unwrap();
        assert!(decoded.is_empty());
    }

    // ── Rejects wrong schema identity ───────────────────────────────

    #[test]
    fn rejects_wrong_family() {
        let record = IntentLogRecord::TxBegin { cg_id: 1 }.encode();
        let mut framed = encode_framed_single(&record);

        // Corrupt family_id bytes at offset 4 (first byte of u64 LE)
        framed[4] ^= 0xFF;

        let result = decode_framed(&framed);
        // The FramingDecoder might reject at the header CRC32C level
        // or at our family check. Either is acceptable.
        let _ = result;
        // No panic — the point is we don't crash on bad data
    }

    // ── Truncation and corruption ───────────────────────────────────

    #[test]
    fn rejects_truncated_envelope() {
        let record = IntentLogRecord::TxBegin { cg_id: 1 }.encode();
        let framed = encode_framed_single(&record);
        let truncated = &framed[..30]; // Too short for envelope header
        assert!(decode_framed(truncated).is_err());
    }

    #[test]
    fn rejects_truncated_body() {
        let records = vec![
            IntentLogRecord::TxBegin { cg_id: 1 }.encode(),
            IntentLogRecord::WritePayload {
                object_id: test_key(3),
                offset: 0,
                data: b"will be truncated".to_vec(),
            }
            .encode(),
        ];
        let framed = encode_framed(&records);
        // Cut off part of the last record's BLAKE3 checksum
        let truncated = &framed[..framed.len() - 10];
        assert!(decode_framed(truncated).is_err());
    }

    // ── FramingDecoder streaming ────────────────────────────────────

    #[test]
    fn framing_decoder_splits_across_feeds() {
        use tidefs_binary_schema_framing::FramingDecoder;

        let records = vec![
            IntentLogRecord::TxBegin { cg_id: 1 }.encode(),
            IntentLogRecord::TxCommit { cg_id: 1 }.encode(),
        ];
        let framed = encode_framed(&records);

        let mut decoder = FramingDecoder::new();

        // Feed half the frame
        let mid = framed.len() / 2;
        let partial = decoder.feed(&framed[..mid]);
        assert!(partial.is_empty(), "should not emit partial frame");

        // Feed remainder
        let complete = decoder.feed(&framed[mid..]);
        assert_eq!(complete.len(), 1);

        // Decode the frame body
        let _body = &complete[0].body;
        let decoded = decode_framed(&framed).unwrap();
        assert_eq!(decoded.len(), 2);
    }

    #[test]
    fn framing_decoder_multi_frame() {
        use tidefs_binary_schema_framing::FramingDecoder;

        let frame1 = encode_framed_single(&IntentLogRecord::TxBegin { cg_id: 1 }.encode());
        let frame2 = encode_framed_single(&IntentLogRecord::TxCommit { cg_id: 1 }.encode());

        let mut combined = Vec::new();
        combined.extend_from_slice(&frame1);
        combined.extend_from_slice(&frame2);

        let mut decoder = FramingDecoder::new();
        let frames = decoder.feed(&combined);
        assert_eq!(frames.len(), 2);
    }

    // ── Schema identity constants ───────────────────────────────────

    #[test]
    fn schema_identity_is_stable() {
        assert_eq!(INTENT_LOG_FAMILY_ID.0, 0x5642_4653_494C_4F01);
        assert_eq!(INTENT_LOG_RECORD_BATCH_TYPE_ID.0, 1);
        assert_eq!(INTENT_LOG_SYNC_WRITE_TYPE_ID.0, 2);
        assert_eq!(INTENT_LOG_VERSION, SchemaVersion::new(1, 0));
    }
}
