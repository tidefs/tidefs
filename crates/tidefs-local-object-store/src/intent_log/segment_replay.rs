//! Intent-log replay: scans committed segment files on pool import,
//! verifies BLAKE3 integrity via IntegrityTrailerV2, reconstructs
//! committed-but-unapplied transactions, and applies them to the
//! local object store so no acknowledged write is lost across crashes.
//!
//! # Replay protocol
//!
//! 1. Scan `intent_log/` for segment files ordered by sequence number.
//! 2. For each segment, read the framed body + IntegrityTrailerV2 footer,
//!    verify the BLAKE3 payload digest, and decode individual records.
//! 3. Group records into transactions: TxBegin → [WritePayload*] → TxCommit.
//!    Aborted transactions (TxAbort) are silently discarded.
//! 4. Apply valid write payloads and tombstones to the object store via
//!    the existing put/delete paths (bypassing re-logging to avoid
//!    infinite replay).
//! 5. After successful replay, rename replayed segments to `.replayed`
//!    so they are not re-applied on subsequent imports.

use std::fs;
use std::path::{Path, PathBuf};

use crate::constants::INTEGRITY_TRAILER_V2_LEN;
use crate::intent_log::framing;
use crate::intent_log::record::IntentLogRecord;
use crate::{decode_integrity_trailer_v2, ProductionIntegrityDigest};

type CommittedIntentLogRecords = Vec<(u64, Vec<IntentLogRecord>)>;
type IntentLogScanResult = (IntentLogReplayStats, CommittedIntentLogRecords);

// ---------------------------------------------------------------------------
// Replay stats
// ---------------------------------------------------------------------------

/// Statistics from an intent-log replay run.
#[derive(Clone, Debug, Default)]
pub struct IntentLogReplayStats {
    /// Total segment files discovered in `intent_log/`.
    pub segments_scanned: usize,
    /// Segments that passed BLAKE3 integrity verification.
    pub segments_replayed: usize,
    /// Segments that failed IntegrityTrailerV2 or record checksums.
    pub segments_corrupt: usize,
    /// Number of committed transactions found across all segments.
    pub transactions_committed: usize,
    /// Number of aborted transactions silently discarded.
    pub transactions_aborted: usize,
    /// WritePayload records applied to the object store.
    pub write_payloads_applied: usize,
    /// Tombstone (empty WritePayload) records applied.
    pub tombstones_applied: usize,
}

// ---------------------------------------------------------------------------
// Segment discovery
// ---------------------------------------------------------------------------

/// Scan the `intent_log/` directory and return segment paths sorted by
/// segment number.
///
/// Returns an empty vector if the directory does not exist or contains
/// no `.vlos` files.
pub fn discover_intent_log_segments(ilog_dir: &Path) -> Result<Vec<(u64, PathBuf)>, String> {
    if !ilog_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut segments = Vec::new();
    for entry in fs::read_dir(ilog_dir).map_err(|e| format!("read_dir intent_log: {e}"))? {
        let entry = entry.map_err(|e| format!("read_dir entry: {e}"))?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "vlos") {
            if let Some(seg_id) = crate::parse_segment_file_name(&path) {
                segments.push((seg_id, path));
            }
        }
    }
    segments.sort_by_key(|(id, _)| *id);
    Ok(segments)
}

// ---------------------------------------------------------------------------
// Segment parsing & verification
// ---------------------------------------------------------------------------

/// Parse and verify a single intent-log segment file.
///
/// Reads the segment, extracts the IntegrityTrailerV2, verifies the
/// BLAKE3 payload digest, decodes the framed body into individual
/// records, and returns them.
///
/// Returns an error if the segment is corrupt (bad trailer, digest
/// mismatch, malformed records).
pub fn parse_intent_log_segment(seg_path: &Path) -> Result<Vec<IntentLogRecord>, String> {
    let data = fs::read(seg_path).map_err(|e| {
        format!(
            "intent-log replay: read segment {}: {e}",
            seg_path.display()
        )
    })?;

    if data.len() < INTEGRITY_TRAILER_V2_LEN {
        return Err(format!(
            "intent-log replay: segment {} too short for trailer ({} bytes)",
            seg_path.display(),
            data.len()
        ));
    }

    // Extract and verify IntegrityTrailerV2 from the last 112 bytes.
    let trailer_start = data.len() - INTEGRITY_TRAILER_V2_LEN;
    let trailer_bytes: &[u8; INTEGRITY_TRAILER_V2_LEN] = data[trailer_start..]
        .try_into()
        .map_err(|_| "trailer slice wrong length".to_string())?;
    let trailer = decode_integrity_trailer_v2(trailer_bytes).map_err(|e| {
        format!(
            "intent-log replay: bad trailer in {}: {e}",
            seg_path.display()
        )
    })?;

    // Verify the payload digest covers the framed body.
    let framed_body = &data[..trailer_start];
    let computed_digest = {
        let mut hasher = blake3::Hasher::new_derive_key(
            crate::intent_log::sync_write::SYNC_WRITE_TRAILER_DOMAIN,
        );
        hasher.update(framed_body);
        ProductionIntegrityDigest::from_bytes32(hasher.finalize().into())
    };
    if trailer.payload_digest != computed_digest {
        return Err(format!(
            "intent-log replay: trailer payload digest mismatch in {}",
            seg_path.display()
        ));
    }

    // Decode the framed body into individual encoded records.
    let encoded_records = framing::decode_framed(framed_body).map_err(|e| {
        format!(
            "intent-log replay: decode framed segment {}: {e}",
            seg_path.display()
        )
    })?;

    // Decode each record with its own BLAKE3 checksum.
    let mut records = Vec::with_capacity(encoded_records.len());
    for encoded in &encoded_records {
        let record = IntentLogRecord::decode(encoded).map_err(|e| {
            format!(
                "intent-log replay: decode record in {}: {e}",
                seg_path.display()
            )
        })?;
        records.push(record);
    }

    Ok(records)
}

// ---------------------------------------------------------------------------
// Transaction grouping
// ---------------------------------------------------------------------------

/// Group records into transactions.
///
/// Scans for `TxBegin`/`TxCommit` pairs and collects the records between
/// them. `TxAbort` causes the matching transaction to be silently
/// discarded. Nested transactions are supported: records between an
/// inner `TxBegin`/`TxCommit` pair are flattened into the outer
/// transaction's record set.
///
/// Returns a list of `(tx_id, Vec<IntentLogRecord>)` for committed
/// transactions only.
pub fn group_transactions(records: &[IntentLogRecord]) -> Vec<(u64, Vec<IntentLogRecord>)> {
    let mut transactions = Vec::new();
    let mut open_stack: Vec<(u64, usize)> = Vec::new(); // (tx_id, start_index)
                                                        // Track (start, end) index ranges of already-resolved inner transactions
                                                        // so outer transactions can skip over them.
    let mut resolved_spans: Vec<(usize, usize)> = Vec::new();

    for (i, record) in records.iter().enumerate() {
        match record {
            IntentLogRecord::TxBegin { cg_id } => {
                open_stack.push((*cg_id, i + 1));
            }
            IntentLogRecord::TxCommit { cg_id } => {
                // Find the innermost matching TxBegin on the stack.
                if let Some(pos) = open_stack.iter().rposition(|(id, _)| id == cg_id) {
                    let (matched_id, start_idx) = open_stack.remove(pos);
                    // Collect records between TxBegin and TxCommit, but
                    // skip boundary markers AND records belonging to
                    // already-resolved inner transaction spans.
                    let txn_records: Vec<IntentLogRecord> = records[start_idx..i]
                        .iter()
                        .enumerate()
                        .filter(|(rel_idx, r)| {
                            let abs_idx = start_idx + rel_idx;
                            // Skip boundary markers
                            if matches!(
                                r,
                                IntentLogRecord::TxBegin { .. }
                                    | IntentLogRecord::TxCommit { .. }
                                    | IntentLogRecord::TxAbort { .. }
                            ) {
                                return false;
                            }
                            // Skip records inside resolved inner spans
                            for &(inner_start, inner_end) in &resolved_spans {
                                if abs_idx >= inner_start && abs_idx < inner_end {
                                    return false;
                                }
                            }
                            true
                        })
                        .map(|(_, r)| r)
                        .cloned()
                        .collect();
                    transactions.push((matched_id, txn_records));
                    // Record this transaction's span so outer transactions skip it.
                    resolved_spans.push((start_idx, i));
                }
            }
            IntentLogRecord::TxAbort { cg_id } => {
                // Remove the matching TxBegin from the open stack and
                // any nested transactions within it.
                if let Some(pos) = open_stack.iter().rposition(|(id, _)| id == cg_id) {
                    open_stack.truncate(pos);
                }
            }
            _ => {}
        }
    }

    transactions
}

// ---------------------------------------------------------------------------
// Full scan-and-parse
// ---------------------------------------------------------------------------

/// Scan all intent-log segments, verify integrity, group into transactions.
///
/// This is the top-level entry point for reading intent-log data without
/// applying it. Returns statistics and all committed transaction records.
pub fn scan_and_parse(ilog_dir: &Path) -> Result<IntentLogScanResult, String> {
    let segments = discover_intent_log_segments(ilog_dir)?;
    let mut stats = IntentLogReplayStats {
        segments_scanned: segments.len(),
        ..Default::default()
    };

    let mut all_committed: Vec<(u64, Vec<IntentLogRecord>)> = Vec::new();

    for (_seg_id, seg_path) in &segments {
        match parse_intent_log_segment(seg_path) {
            Ok(records) => {
                stats.segments_replayed += 1;
                let txns = group_transactions(&records);
                for (tx_id, txn_records) in txns {
                    stats.transactions_committed += 1;
                    all_committed.push((tx_id, txn_records));
                }
            }
            Err(e) => {
                stats.segments_corrupt += 1;
                tracing::warn!(
                    "intent-log replay: corrupt segment {}: {e}",
                    seg_path.display()
                );
            }
        }
    }

    Ok((stats, all_committed))
}

// ---------------------------------------------------------------------------
// Segment lifecycle
// ---------------------------------------------------------------------------

/// Mark an intent-log segment as replayed by renaming to `.vlos.replayed`.
///
/// The `.replayed` suffix prevents the segment from being re-applied on
/// subsequent pool imports. The renamed file is kept for operator
/// inspection and can be manually deleted after confirming recovery.
pub fn mark_segment_replayed(seg_path: &Path) -> Result<(), String> {
    let stem = seg_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");
    let parent = seg_path.parent().unwrap_or(Path::new("."));
    let new_name = format!("{stem}.vlos.replayed");
    let new_path = parent.join(new_name);

    fs::rename(seg_path, &new_path).map_err(|e| {
        format!(
            "intent-log replay: rename {} -> {}: {e}",
            seg_path.display(),
            new_path.display()
        )
    })?;
    Ok(())
}

/// Remove all `.replayed` intent-log segment files from the given
/// directory. Safe to call after confirming recovery is complete.
pub fn purge_replayed_segments(ilog_dir: &Path) -> Result<usize, String> {
    if !ilog_dir.is_dir() {
        return Ok(0);
    }
    let mut removed = 0usize;
    for entry in fs::read_dir(ilog_dir).map_err(|e| format!("read_dir intent_log: {e}"))? {
        let entry = entry.map_err(|e| format!("read_dir entry: {e}"))?;
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.ends_with(".vlos.replayed") {
                fs::remove_file(&path).map_err(|e| format!("remove {}: {e}", path.display()))?;
                removed += 1;
            }
        }
    }
    Ok(removed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent_log::framing::encode_framed;
    use crate::intent_log::record::IntentLogRecord;
    use crate::ObjectKey;

    fn test_key(id: u64) -> ObjectKey {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&id.to_le_bytes());
        ObjectKey::from_bytes(bytes)
    }

    /// Write a fake intent-log segment file with framing + IntegrityTrailerV2.
    fn write_test_segment(dir: &Path, seg_id: u64, records: &[IntentLogRecord]) -> PathBuf {
        use std::io::Write;

        let encoded: Vec<Vec<u8>> = records.iter().map(|r| r.encode()).collect();
        let framed = encode_framed(&encoded);

        // Build IntegrityTrailerV2
        let payload_digest = {
            let mut hasher = blake3::Hasher::new_derive_key(
                crate::intent_log::sync_write::SYNC_WRITE_TRAILER_DOMAIN,
            );
            hasher.update(&framed);
            ProductionIntegrityDigest::from_bytes32(hasher.finalize().into())
        };

        let trailer = crate::IntegrityTrailerV2 {
            format_version: 1,
            digest_suite: 1,
            payload_digest,
            record_digest: payload_digest,
            shard_count: 0,
            shard_index: 0,
            ec_k: 0,
            ec_m: 0,
        };
        let trailer_bytes = crate::encode_integrity_trailer_v2(&trailer);

        let seg_path = dir.join(crate::segment_file_name(seg_id));
        let mut f = std::fs::File::create(&seg_path).unwrap();
        f.write_all(&framed).unwrap();
        f.write_all(&trailer_bytes).unwrap();
        f.sync_all().unwrap();
        seg_path
    }

    // ── Discovery ───────────────────────────────────────────────────

    #[test]
    fn discover_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let segments = discover_intent_log_segments(dir.path()).unwrap();
        assert!(segments.is_empty());
    }

    #[test]
    fn discover_nonexistent_dir() {
        let segments = discover_intent_log_segments(Path::new("/nonexistent/ilog")).unwrap();
        assert!(segments.is_empty());
    }

    #[test]
    fn discover_sorts_by_segment_id() {
        let dir = tempfile::tempdir().unwrap();
        write_test_segment(
            dir.path(),
            5,
            &[
                IntentLogRecord::TxBegin { cg_id: 1 },
                IntentLogRecord::TxCommit { cg_id: 1 },
            ],
        );
        write_test_segment(
            dir.path(),
            0,
            &[
                IntentLogRecord::TxBegin { cg_id: 2 },
                IntentLogRecord::TxCommit { cg_id: 2 },
            ],
        );
        write_test_segment(
            dir.path(),
            10,
            &[
                IntentLogRecord::TxBegin { cg_id: 3 },
                IntentLogRecord::TxCommit { cg_id: 3 },
            ],
        );

        let segments = discover_intent_log_segments(dir.path()).unwrap();
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].0, 0);
        assert_eq!(segments[1].0, 5);
        assert_eq!(segments[2].0, 10);
    }

    // ── Segment parsing ─────────────────────────────────────────────

    #[test]
    fn parse_single_segment_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let records = vec![
            IntentLogRecord::TxBegin { cg_id: 1 },
            IntentLogRecord::WritePayload {
                object_id: test_key(1),
                offset: 0,
                data: b"hello replay".to_vec(),
            },
            IntentLogRecord::TxCommit { cg_id: 1 },
        ];
        let seg_path = write_test_segment(dir.path(), 0, &records);
        let parsed = parse_intent_log_segment(&seg_path).unwrap();
        assert_eq!(parsed, records);
    }

    #[test]
    fn parse_empty_segment_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let seg_path = dir.path().join("segment-000.vlos");
        std::fs::write(&seg_path, b"too short").unwrap();
        assert!(parse_intent_log_segment(&seg_path).is_err());
    }

    #[test]
    fn parse_corrupt_payload_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let records = vec![
            IntentLogRecord::TxBegin { cg_id: 1 },
            IntentLogRecord::TxCommit { cg_id: 1 },
        ];
        let seg_path = write_test_segment(dir.path(), 0, &records);

        // Corrupt a byte in the framed body
        let mut data = std::fs::read(&seg_path).unwrap();
        if data.len() > 50 {
            data[50] ^= 0xFF;
        }
        std::fs::write(&seg_path, &data).unwrap();

        assert!(parse_intent_log_segment(&seg_path).is_err());
    }

    #[test]
    fn parse_corrupt_record_checksum_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let records = vec![
            IntentLogRecord::TxBegin { cg_id: 1 },
            IntentLogRecord::WritePayload {
                object_id: test_key(2),
                offset: 0,
                data: b"will be corrupted".to_vec(),
            },
            IntentLogRecord::TxCommit { cg_id: 1 },
        ];
        let seg_path = write_test_segment(dir.path(), 0, &records);

        // Tamper a byte inside the encoded WritePayload
        let mut data = std::fs::read(&seg_path).unwrap();
        // The WritePayload is the second record. Its data starts after the
        // framing header and TxBegin record. Find a byte in the second half
        // and flip it.
        let mid = data.len() / 2;
        data[mid] ^= 0x01;
        std::fs::write(&seg_path, &data).unwrap();

        assert!(parse_intent_log_segment(&seg_path).is_err());
    }

    // ── Transaction grouping ────────────────────────────────────────

    #[test]
    fn group_single_transaction() {
        let records = vec![
            IntentLogRecord::TxBegin { cg_id: 1 },
            IntentLogRecord::WritePayload {
                object_id: test_key(1),
                offset: 0,
                data: b"txn data".to_vec(),
            },
            IntentLogRecord::TxCommit { cg_id: 1 },
        ];
        let txns = group_transactions(&records);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].0, 1);
        assert_eq!(txns[0].1.len(), 1);
    }

    #[test]
    fn group_multiple_transactions() {
        let records = vec![
            IntentLogRecord::TxBegin { cg_id: 1 },
            IntentLogRecord::WritePayload {
                object_id: test_key(1),
                offset: 0,
                data: b"first".to_vec(),
            },
            IntentLogRecord::TxCommit { cg_id: 1 },
            IntentLogRecord::TxBegin { cg_id: 2 },
            IntentLogRecord::WritePayload {
                object_id: test_key(2),
                offset: 0,
                data: b"second".to_vec(),
            },
            IntentLogRecord::TxCommit { cg_id: 2 },
        ];
        let txns = group_transactions(&records);
        assert_eq!(txns.len(), 2);
        assert_eq!(txns[0].0, 1);
        assert_eq!(txns[1].0, 2);
    }

    #[test]
    fn group_aborted_transaction_discarded() {
        let records = vec![
            IntentLogRecord::TxBegin { cg_id: 1 },
            IntentLogRecord::WritePayload {
                object_id: test_key(1),
                offset: 0,
                data: b"should be discarded".to_vec(),
            },
            IntentLogRecord::TxAbort { cg_id: 1 },
            IntentLogRecord::TxBegin { cg_id: 2 },
            IntentLogRecord::WritePayload {
                object_id: test_key(2),
                offset: 0,
                data: b"committed".to_vec(),
            },
            IntentLogRecord::TxCommit { cg_id: 2 },
        ];
        let txns = group_transactions(&records);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].0, 2);
        assert_eq!(txns[0].1.len(), 1);
    }

    #[test]
    fn group_nested_transactions() {
        let records = vec![
            IntentLogRecord::TxBegin { cg_id: 1 },
            IntentLogRecord::TxBegin { cg_id: 2 },
            IntentLogRecord::WritePayload {
                object_id: test_key(1),
                offset: 0,
                data: b"inner".to_vec(),
            },
            IntentLogRecord::TxCommit { cg_id: 2 },
            IntentLogRecord::WritePayload {
                object_id: test_key(2),
                offset: 0,
                data: b"outer".to_vec(),
            },
            IntentLogRecord::TxCommit { cg_id: 1 },
        ];
        let txns = group_transactions(&records);
        assert_eq!(txns.len(), 2);
        // Inner transaction (tx_id=2): just the inner write
        assert_eq!(txns[0].0, 2);
        assert_eq!(txns[0].1.len(), 1);
        assert!(matches!(
            &txns[0].1[0],
            IntentLogRecord::WritePayload { data, .. } if data == b"inner"
        ));
        // Outer transaction (tx_id=1): only the outer write,
        // inner span is excluded
        assert_eq!(txns[1].0, 1);
        assert_eq!(txns[1].1.len(), 1);
        assert!(matches!(
            &txns[1].1[0],
            IntentLogRecord::WritePayload { data, .. } if data == b"outer"
        ));
    }

    #[test]
    fn group_empty_returns_empty() {
        let txns = group_transactions(&[]);
        assert!(txns.is_empty());
    }

    #[test]
    fn group_open_transaction_not_returned() {
        let records = vec![
            IntentLogRecord::TxBegin { cg_id: 1 },
            IntentLogRecord::WritePayload {
                object_id: test_key(1),
                offset: 0,
                data: b"uncommitted".to_vec(),
            },
        ];
        let txns = group_transactions(&records);
        assert!(txns.is_empty());
    }

    // ── scan_and_parse integration ──────────────────────────────────

    #[test]
    fn scan_and_parse_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let (stats, txns) = scan_and_parse(dir.path()).unwrap();
        assert_eq!(stats.segments_scanned, 0);
        assert_eq!(stats.segments_replayed, 0);
        assert!(txns.is_empty());
    }

    #[test]
    fn scan_and_parse_single_segment() {
        let dir = tempfile::tempdir().unwrap();
        let records = vec![
            IntentLogRecord::TxBegin { cg_id: 1 },
            IntentLogRecord::WritePayload {
                object_id: test_key(1),
                offset: 0,
                data: b"scan test".to_vec(),
            },
            IntentLogRecord::TxCommit { cg_id: 1 },
        ];
        write_test_segment(dir.path(), 0, &records);

        let (stats, txns) = scan_and_parse(dir.path()).unwrap();
        assert_eq!(stats.segments_scanned, 1);
        assert_eq!(stats.segments_replayed, 1);
        assert_eq!(stats.segments_corrupt, 0);
        assert_eq!(stats.transactions_committed, 1);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].0, 1);
        assert_eq!(txns[0].1.len(), 1);
    }

    #[test]
    fn scan_and_parse_mixed_valid_and_corrupt() {
        let dir = tempfile::tempdir().unwrap();

        // Valid segment
        write_test_segment(
            dir.path(),
            0,
            &[
                IntentLogRecord::TxBegin { cg_id: 1 },
                IntentLogRecord::TxCommit { cg_id: 1 },
            ],
        );

        // Corrupt segment (empty file)
        let corrupt_path = dir.path().join(crate::segment_file_name(1));
        std::fs::write(&corrupt_path, b"bad").unwrap();

        // Another valid segment
        write_test_segment(
            dir.path(),
            2,
            &[
                IntentLogRecord::TxBegin { cg_id: 2 },
                IntentLogRecord::WritePayload {
                    object_id: test_key(2),
                    offset: 0,
                    data: b"after corrupt".to_vec(),
                },
                IntentLogRecord::TxCommit { cg_id: 2 },
            ],
        );

        let (stats, txns) = scan_and_parse(dir.path()).unwrap();
        assert_eq!(stats.segments_scanned, 3);
        assert_eq!(stats.segments_replayed, 2);
        assert_eq!(stats.segments_corrupt, 1);
        assert_eq!(stats.transactions_committed, 2);
        assert_eq!(txns.len(), 2);
    }

    // ── mark_segment_replayed ───────────────────────────────────────

    #[test]
    fn mark_segment_replayed_renames_file() {
        let dir = tempfile::tempdir().unwrap();
        let seg_path = write_test_segment(
            dir.path(),
            0,
            &[
                IntentLogRecord::TxBegin { cg_id: 1 },
                IntentLogRecord::TxCommit { cg_id: 1 },
            ],
        );

        assert!(seg_path.exists());
        mark_segment_replayed(&seg_path).unwrap();

        let replayed_path = dir
            .path()
            .join(crate::segment_file_name(0).replace(".vlos", ".vlos.replayed"));
        assert!(
            replayed_path.exists(),
            "expected replayed path: {}",
            replayed_path.display()
        );
        assert!(!seg_path.exists());
    }

    // ── purge_replayed_segments ─────────────────────────────────────

    #[test]
    fn purge_replayed_removes_marked_files() {
        let dir = tempfile::tempdir().unwrap();

        // Create a file and mark it replayed
        let seg_path = write_test_segment(
            dir.path(),
            0,
            &[
                IntentLogRecord::TxBegin { cg_id: 1 },
                IntentLogRecord::TxCommit { cg_id: 1 },
            ],
        );
        mark_segment_replayed(&seg_path).unwrap();

        // Create another replayed marker file directly
        std::fs::write(dir.path().join("segment-001.vlos.replayed"), b"old").unwrap();

        let removed = purge_replayed_segments(dir.path()).unwrap();
        assert_eq!(removed, 2);
    }
}
