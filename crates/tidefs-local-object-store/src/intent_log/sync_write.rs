//! Sync-write fast path: bypasses the ring buffer for O_SYNC/fsync writes.
//!
//! The [`IntentLog`] struct wraps [`InMemoryIntentLog`] and adds a
//! `sync_write` method that writes a [`WritePayload`](super::record::IntentLogRecord::WritePayload)
//! record directly to a durable segment with a BLAKE3-verified commit marker
//! and an [`IntegrityTrailerV2`](crate::IntegrityTrailerV2) footer.
//!
//! # Segment layout
//!
//! ```text
//! [encoded record (variable)] [commit_marker (32 bytes)] [IntegrityTrailerV2 (112 bytes)]
//! ```
//!
//! The commit marker is a BLAKE3-256 domain-separated digest of the encoded
//! record bytes. The `IntegrityTrailerV2` covers both the record and the
//! commit marker.

use std::io::{Seek, Write};

use super::buffer::InMemoryIntentLog;
use super::record::IntentLogRecord;
use crate::{IntegrityTrailerV2, ObjectKey, ProductionIntegrityDigest};

// ---------------------------------------------------------------------------
// Domain contexts
// ---------------------------------------------------------------------------

/// Domain context for BLAKE3 key derivation on sync-write commit markers.
const SYNC_WRITE_COMMIT_DOMAIN: &str = "TideFS IntentLog SyncWrite v1";

/// Domain context for BLAKE3 key derivation on sync-write IntegrityTrailerV2.
pub(crate) const SYNC_WRITE_TRAILER_DOMAIN: &str = "TideFS IntentLog SyncWrite Trailer v1";

/// Digest suite identifier: BLAKE3-256 = 1.
const TRAILER_DIGEST_SUITE_ID: u16 = 1;

// ---------------------------------------------------------------------------
// Commit marker
// ---------------------------------------------------------------------------

/// A BLAKE3-256 commit marker covering the encoded record bytes.
pub type CommitMarker = [u8; 32];

/// Compute a domain-separated BLAKE3-256 commit marker over `record_bytes`.
pub fn compute_commit_marker(record_bytes: &[u8]) -> CommitMarker {
    let mut hasher = blake3::Hasher::new_derive_key(SYNC_WRITE_COMMIT_DOMAIN);
    hasher.update(record_bytes);
    hasher.finalize().into()
}

/// Verify a commit marker against record bytes.
pub fn verify_commit_marker(record_bytes: &[u8], marker: &CommitMarker) -> bool {
    compute_commit_marker(record_bytes) == *marker
}

// ---------------------------------------------------------------------------
// IntentLog
// ---------------------------------------------------------------------------

/// An intent log combining an in-memory ring buffer with a sync-write fast
/// path for O_SYNC/fsync writes.
///
/// The ring buffer accumulates records for batch commit.  The sync-write
/// fast path bypasses the buffer entirely: it encodes the record, writes it
/// directly to a segment with a BLAKE3 commit marker and an
/// `IntegrityTrailerV2` footer, and flushes before returning.
#[derive(Clone, Debug)]
pub struct IntentLog {
    buffer: InMemoryIntentLog,
}

impl IntentLog {
    /// Create a new intent log with the given ring-buffer capacity in bytes.
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: InMemoryIntentLog::new(capacity),
        }
    }

    /// Access the underlying ring buffer.
    pub fn buffer(&self) -> &InMemoryIntentLog {
        &self.buffer
    }

    /// Mutably access the underlying ring buffer.
    pub fn buffer_mut(&mut self) -> &mut InMemoryIntentLog {
        &mut self.buffer
    }

    /// Append a record through the ring buffer (normal path).
    pub fn append(&mut self, record: IntentLogRecord) -> Result<(), String> {
        self.buffer.append(record)
    }

    /// Flush the oldest committed transaction region from the ring buffer.
    pub fn flush_committed(&mut self) -> Option<Vec<Vec<u8>>> {
        self.buffer.flush_committed()
    }

    /// Total encoded bytes currently stored in the ring buffer.
    pub fn stored_bytes(&self) -> usize {
        self.buffer.stored_bytes()
    }

    /// Number of records currently stored in the ring buffer.
    pub fn record_count(&self) -> usize {
        self.buffer.record_count()
    }

    /// Whether the ring buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Whether the ring buffer has any committed region ready to flush.
    pub fn has_committed(&self) -> bool {
        self.buffer.has_committed()
    }

    /// Sync-write fast path: write a `WritePayload` record directly to a
    /// durable segment, bypassing the ring buffer.
    ///
    /// Encodes the record, writes it to `writer`, appends a BLAKE3-256
    /// domain-separated commit marker, writes an `IntegrityTrailerV2` footer,
    /// and flushes the writer before returning.
    ///
    /// Returns the number of bytes written (record + marker + trailer).
    pub fn sync_write<W: Write + Seek>(
        &self,
        writer: &mut W,
        object_id: ObjectKey,
        offset: u64,
        data: &[u8],
    ) -> Result<u64, String> {
        let record = IntentLogRecord::WritePayload {
            object_id,
            offset,
            data: data.to_vec(),
        };
        let encoded = record.encode();

        // Compute commit marker over the encoded record
        let commit_marker = compute_commit_marker(&encoded);

        // Build IntegrityTrailerV2: payload_digest covers record + marker
        let payload_digest = {
            let mut hasher = blake3::Hasher::new_derive_key(SYNC_WRITE_TRAILER_DOMAIN);
            hasher.update(&encoded);
            hasher.update(&commit_marker);
            ProductionIntegrityDigest::from_bytes32(hasher.finalize().into())
        };

        let trailer = IntegrityTrailerV2 {
            format_version: 1,
            digest_suite: TRAILER_DIGEST_SUITE_ID,
            payload_digest,
            record_digest: payload_digest,
            shard_count: 0,
            shard_index: 0,
            ec_k: 0,
            ec_m: 0,
        };
        let trailer_bytes = crate::encode_integrity_trailer_v2(&trailer);

        // Write: encoded record | commit marker | trailer
        writer
            .write_all(&encoded)
            .map_err(|e| format!("sync_write: failed to write record: {e}"))?;
        writer
            .write_all(&commit_marker)
            .map_err(|e| format!("sync_write: failed to write commit marker: {e}"))?;
        writer
            .write_all(&trailer_bytes)
            .map_err(|e| format!("sync_write: failed to write trailer: {e}"))?;

        // Ensure durability
        writer
            .flush()
            .map_err(|e| format!("sync_write: flush failed: {e}"))?;

        let total_bytes = (encoded.len() + 32 + crate::INTEGRITY_TRAILER_V2_LEN) as u64;
        Ok(total_bytes)
    }

    /// Read back and verify a sync-written record from a reader.
    ///
    /// Reads the encoded record, commit marker, and trailer.  Verifies the
    /// commit marker and the `IntegrityTrailerV2` digests.  On success,
    /// returns the decoded `IntentLogRecord` and the commit marker.
    pub fn sync_read_verify(
        reader: &mut (impl std::io::Read + std::io::Seek),
    ) -> Result<(IntentLogRecord, CommitMarker), String> {
        let file_len = reader
            .seek(std::io::SeekFrom::End(0))
            .map_err(|e| format!("sync_read_verify: seek end: {e}"))?;

        let trailer_len = crate::INTEGRITY_TRAILER_V2_LEN as u64;
        if file_len < 32 + trailer_len {
            return Err("sync_read_verify: segment too short".into());
        }

        // Read trailer from the end
        reader
            .seek(std::io::SeekFrom::End(-(trailer_len as i64)))
            .map_err(|e| format!("sync_read_verify: seek trailer: {e}"))?;

        let mut trailer_buf = [0u8; crate::INTEGRITY_TRAILER_V2_LEN];
        reader
            .read_exact(&mut trailer_buf)
            .map_err(|e| format!("sync_read_verify: read trailer: {e}"))?;

        let trailer = crate::decode_integrity_trailer_v2(&trailer_buf)
            .map_err(|e| format!("sync_read_verify: bad trailer: {e}"))?;

        // Read commit marker (32 bytes before trailer)
        let marker_start = file_len - trailer_len - 32;
        reader
            .seek(std::io::SeekFrom::Start(marker_start))
            .map_err(|e| format!("sync_read_verify: seek marker: {e}"))?;

        let mut commit_marker = [0u8; 32];
        reader
            .read_exact(&mut commit_marker)
            .map_err(|e| format!("sync_read_verify: read marker: {e}"))?;

        // Read encoded record (everything before the marker)
        let record_len = marker_start as usize;
        let mut encoded = vec![0u8; record_len];
        reader
            .seek(std::io::SeekFrom::Start(0))
            .map_err(|e| format!("sync_read_verify: seek start: {e}"))?;
        reader
            .read_exact(&mut encoded)
            .map_err(|e| format!("sync_read_verify: read record: {e}"))?;

        // Verify commit marker
        if !verify_commit_marker(&encoded, &commit_marker) {
            return Err("sync_read_verify: commit marker mismatch".into());
        }

        // Verify IntegrityTrailerV2 payload digest covers record + marker
        let expected_digest = {
            let mut hasher = blake3::Hasher::new_derive_key(SYNC_WRITE_TRAILER_DOMAIN);
            hasher.update(&encoded);
            hasher.update(&commit_marker);
            ProductionIntegrityDigest::from_bytes32(hasher.finalize().into())
        };
        if trailer.payload_digest != expected_digest {
            return Err("sync_read_verify: trailer payload digest mismatch".into());
        }

        // Decode the record
        let record = IntentLogRecord::decode(&encoded)?;

        Ok((record, commit_marker))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn test_key(id: u64) -> ObjectKey {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&id.to_le_bytes());
        ObjectKey::from_bytes(bytes)
    }

    // ── Commit marker round-trip ─────────────────────────────────────

    #[test]
    fn commit_marker_deterministic() {
        let data = b"test commit marker data";
        let m1 = compute_commit_marker(data);
        let m2 = compute_commit_marker(data);
        assert_eq!(m1, m2);
    }

    #[test]
    fn commit_marker_differs_on_data_change() {
        let m1 = compute_commit_marker(b"data A");
        let m2 = compute_commit_marker(b"data B");
        assert_ne!(m1, m2);
    }

    #[test]
    fn verify_commit_marker_ok_and_fail() {
        let data = b"verify test";
        let marker = compute_commit_marker(data);
        assert!(verify_commit_marker(data, &marker));

        let mut bad_marker = marker;
        bad_marker[0] ^= 0xFF;
        assert!(!verify_commit_marker(data, &bad_marker));
    }

    // ── Sync-write round-trip through Cursor ─────────────────────────

    #[test]
    fn sync_write_roundtrip() {
        let log = IntentLog::new(65536);
        let mut buf = Cursor::new(Vec::new());

        let written = log
            .sync_write(&mut buf, test_key(1), 0, b"hello sync write")
            .unwrap();
        assert!(written > 0);

        // Read back and verify
        buf.set_position(0);
        let (decoded, marker) = IntentLog::sync_read_verify(&mut buf).unwrap();

        // Verify marker against the decoded record re-encoded
        {
            let encoded = decoded.encode();
            assert!(verify_commit_marker(&encoded, &marker));
        }

        match decoded {
            IntentLogRecord::WritePayload {
                object_id,
                offset,
                data,
            } => {
                assert_eq!(object_id, test_key(1));
                assert_eq!(offset, 0);
                assert_eq!(data, b"hello sync write");
            }
            _ => panic!("expected WritePayload"),
        }
    }

    #[test]
    fn sync_write_empty_payload() {
        let log = IntentLog::new(65536);
        let mut buf = Cursor::new(Vec::new());

        log.sync_write(&mut buf, test_key(2), 0, &[]).unwrap();

        buf.set_position(0);
        let (decoded, _marker) = IntentLog::sync_read_verify(&mut buf).unwrap();
        match decoded {
            IntentLogRecord::WritePayload { data, .. } => {
                assert!(data.is_empty());
            }
            _ => panic!("expected WritePayload"),
        }
    }

    #[test]
    fn sync_write_large_offset() {
        let log = IntentLog::new(65536);
        let mut buf = Cursor::new(Vec::new());

        log.sync_write(&mut buf, test_key(3), u64::MAX, b"max offset")
            .unwrap();

        buf.set_position(0);
        let (decoded, _marker) = IntentLog::sync_read_verify(&mut buf).unwrap();
        match decoded {
            IntentLogRecord::WritePayload { offset, .. } => {
                assert_eq!(offset, u64::MAX);
            }
            _ => panic!("expected WritePayload"),
        }
    }

    #[test]
    fn sync_write_large_payload() {
        let log = IntentLog::new(65536);
        let mut buf = Cursor::new(Vec::new());
        let data = vec![0xABu8; 64 * 1024]; // 64 KiB

        log.sync_write(&mut buf, test_key(4), 4096, &data).unwrap();

        buf.set_position(0);
        let (decoded, _marker) = IntentLog::sync_read_verify(&mut buf).unwrap();
        match decoded {
            IntentLogRecord::WritePayload {
                object_id,
                offset,
                data: decoded_data,
            } => {
                assert_eq!(object_id, test_key(4));
                assert_eq!(offset, 4096);
                assert_eq!(decoded_data, data);
            }
            _ => panic!("expected WritePayload"),
        }
    }

    // ── Tamper detection ─────────────────────────────────────────────

    #[test]
    fn sync_read_verify_rejects_corrupt_record() {
        let log = IntentLog::new(65536);
        let mut buf = Cursor::new(Vec::new());

        log.sync_write(&mut buf, test_key(5), 0, b"will be corrupted")
            .unwrap();

        // Corrupt a byte in the record payload
        let mut inner = buf.into_inner();
        if inner.len() > 50 {
            inner[50] ^= 0x01;
        }
        let mut buf = Cursor::new(inner);

        let result = IntentLog::sync_read_verify(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn sync_read_verify_rejects_corrupt_marker() {
        let log = IntentLog::new(65536);
        let mut buf = Cursor::new(Vec::new());

        let written = log
            .sync_write(&mut buf, test_key(6), 0, b"marker corruption test")
            .unwrap();

        let mut inner = buf.into_inner();
        let marker_offset = (written as usize) - crate::INTEGRITY_TRAILER_V2_LEN - 32;
        inner[marker_offset] ^= 0xFF;
        let mut buf = Cursor::new(inner);

        let result = IntentLog::sync_read_verify(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn sync_read_verify_rejects_truncated_segment() {
        let log = IntentLog::new(65536);
        let mut buf = Cursor::new(Vec::new());

        log.sync_write(&mut buf, test_key(7), 0, b"truncation test")
            .unwrap();

        let inner = buf.into_inner();
        let truncated = &inner[..inner.len().saturating_sub(10)];
        let mut buf = Cursor::new(truncated.to_vec());

        let result = IntentLog::sync_read_verify(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn sync_read_verify_rejects_empty() {
        let mut buf = Cursor::new(Vec::new());
        let result = IntentLog::sync_read_verify(&mut buf);
        assert!(result.is_err());
    }

    // ── Ring buffer delegation ──────────────────────────────────────

    #[test]
    fn intent_log_delegates_to_buffer() {
        let mut log = IntentLog::new(65536);

        log.append(IntentLogRecord::TxBegin { cg_id: 1 }).unwrap();
        log.append(IntentLogRecord::TxCommit { cg_id: 1 }).unwrap();

        assert!(log.has_committed());
        let flushed = log.flush_committed().unwrap();
        assert_eq!(flushed.len(), 2);
    }

    #[test]
    fn sync_write_does_not_affect_buffer() {
        let mut log = IntentLog::new(65536);
        let mut buf = Cursor::new(Vec::new());

        log.append(IntentLogRecord::TxBegin { cg_id: 1 }).unwrap();

        log.sync_write(&mut buf, test_key(8), 0, b"bypass").unwrap();

        // Ring buffer still has the TxBegin
        assert_eq!(log.record_count(), 1);
    }
}
