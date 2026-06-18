// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Segment-level BLAKE3 integrity scrub for proactive at-rest corruption
//! detection.
//!
//! The [`SegmentIntegrityScrubber`] scans closed segments and
//! cryptographically verifies:
//!
//! - per-record [`IntegrityTrailerV2`] payload and record BLAKE3-256 digests,
//! - the segment footer digest chain (each footer commits to its predecessor).
//!
//! It is designed as an incremental background task: a [`ScrubCursor`] tracks
//! the last-verified segment and byte offset so forward progress can be made
//! across multiple scheduler ticks without blocking foreground I/O.

use crate::constants::*;
use crate::error::StoreError;
use crate::{
    decode_header, read_up_to, record_has_footer, record_has_production_integrity_trailer,
};
use crate::{
    decode_integrity_trailer_v2, discover_segment_ids, file_len, segment_path,
    verify_integrity_trailer_v2, Result, SuspectEntry, SuspectLog,
};
use crate::{SegmentChainStats, SegmentChainVerifier};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// ScrubOutcome
// ---------------------------------------------------------------------------

/// Structured outcome for a single corruption event found during scrub.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScrubOutcome {
    /// Segment passed all checks.
    Clean { segment_id: u64 },

    /// A record's payload digest did not match the stored IntegrityTrailerV2.
    PayloadMismatch {
        segment_id: u64,
        record_offset: u64,
        expected: [u8; 32],
        actual: [u8; 32],
    },

    /// A record's record-level digest did not match the stored IntegrityTrailerV2.
    RecordDigestMismatch {
        segment_id: u64,
        record_offset: u64,
        expected: [u8; 32],
        actual: [u8; 32],
    },

    /// The segment footer hash chain is broken.
    ChainBroken {
        segment_id: u64,
        expected: [u8; 32],
        actual: [u8; 32],
    },

    /// A segment is too short to carry a valid footer (truncated or torn).
    TruncatedSegment { segment_id: u64 },
}

// ---------------------------------------------------------------------------
// ScrubCursor
// ---------------------------------------------------------------------------

/// Persistent cursor tracking incremental scrub progress.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ScrubCursor {
    pub segment_id: u64,
    pub offset: u64,
}

impl ScrubCursor {
    pub fn is_initial(&self) -> bool {
        self.segment_id == 0 && self.offset == 0
    }

    pub fn reset(&mut self) {
        self.segment_id = 0;
        self.offset = 0;
    }
}

// ---------------------------------------------------------------------------
// ScrubReport
// ---------------------------------------------------------------------------

/// Aggregated report from a single scrub pass.
#[derive(Clone, Debug, Default)]
pub struct ScrubReport {
    pub segments_scanned: u64,
    pub records_verified: u64,
    pub bytes_scanned: u64,
    pub chain_breaks_detected: u64,
    pub outcomes: Vec<ScrubOutcome>,
    pub cursor: ScrubCursor,
    pub completed: bool,
    pub chain_stats: Option<SegmentChainStats>,
}

// ---------------------------------------------------------------------------
// SegmentIntegrityScrubber
// ---------------------------------------------------------------------------

/// Proactive segment-level integrity scrubber.
#[derive(Clone, Debug)]
pub struct SegmentIntegrityScrubber {
    segments_dir: PathBuf,
}

impl SegmentIntegrityScrubber {
    #[must_use]
    pub fn new(segments_dir: impl AsRef<Path>) -> Self {
        Self {
            segments_dir: segments_dir.as_ref().to_path_buf(),
        }
    }

    pub fn scrub_incremental(
        &self,
        cursor: &mut ScrubCursor,
        max_records: u64,
        max_bytes: u64,
        suspect_log: &mut SuspectLog,
    ) -> Result<ScrubReport> {
        let mut report = ScrubReport::default();
        let segment_ids = discover_segment_ids(&self.segments_dir)?;
        let mut seen_segments: u64 = 0;

        if segment_ids.is_empty() {
            report.completed = true;
            report.cursor = *cursor;
            return Ok(report);
        }

        let start_seg = cursor.segment_id;
        let mut found_start = start_seg == 0;
        let mut sorted_ids = segment_ids.clone();
        sorted_ids.sort_unstable();

        for &segment_id in &sorted_ids {
            if segment_id < start_seg {
                continue;
            }
            if segment_id == start_seg {
                found_start = true;
            }
            if !found_start {
                continue;
            }

            seen_segments += 1;
            let path = segment_path(&self.segments_dir, segment_id);
            let mut file = OpenOptions::new()
                .read(true)
                .open(&path)
                .map_err(|source| crate::io_error("open scrub", &path, source))?;

            let mut offset = if segment_id == start_seg {
                cursor.offset
            } else {
                0u64
            };
            file.seek(SeekFrom::Start(offset))
                .map_err(|source| crate::io_error("seek scrub", &path, source))?;

            loop {
                let hit_record_cap = max_records > 0 && report.records_verified >= max_records;
                let hit_byte_cap = max_bytes > 0 && report.bytes_scanned >= max_bytes;
                if hit_record_cap || hit_byte_cap {
                    cursor.segment_id = segment_id;
                    cursor.offset = offset;
                    report.cursor = *cursor;
                    report.segments_scanned = seen_segments;
                    return Ok(report);
                }

                let mut header = [0u8; RECORD_HEADER_LEN];
                let header_bytes = read_up_to(&mut file, &mut header)
                    .map_err(|source| crate::io_error("read header scrub", &path, source))?;
                if header_bytes == 0 {
                    break;
                }
                if header_bytes == RECORD_HEADER_LEN
                    && header[0..8] == SEGMENT_INTEGRITY_FOOTER_MAGIC_BYTES
                {
                    break;
                }
                if header_bytes < RECORD_HEADER_LEN {
                    break;
                }

                let record = match decode_header(&header, segment_id, offset) {
                    Ok(r) => r,
                    Err(_) => break,
                };

                let payload_len = match usize::try_from(record.payload_len) {
                    Ok(l) => l,
                    Err(_) => break,
                };
                let mut payload = vec![0u8; payload_len];
                let payload_bytes = read_up_to(&mut file, &mut payload)
                    .map_err(|source| crate::io_error("read payload scrub", &path, source))?;
                if payload_bytes < payload_len {
                    break;
                }

                let trailer_offset =
                    offset + RECORD_HEADER_LEN_U64 + record.payload_len + RECORD_FOOTER_LEN_U64;

                let footer = if record_has_footer(record.format_version) {
                    let mut footer_bytes = [0u8; RECORD_FOOTER_LEN];
                    let bytes_read = read_up_to(&mut file, &mut footer_bytes)
                        .map_err(|source| crate::io_error("read footer scrub", &path, source))?;
                    if bytes_read < RECORD_FOOTER_LEN {
                        break;
                    }
                    Some(footer_bytes)
                } else {
                    None
                };

                if record_has_production_integrity_trailer(record.format_version) {
                    let mut trailer_buf = [0u8; INTEGRITY_TRAILER_V2_LEN];
                    let trailer_bytes = read_up_to(&mut file, &mut trailer_buf)
                        .map_err(|source| crate::io_error("read trailer scrub", &path, source))?;
                    if trailer_bytes >= INTEGRITY_TRAILER_V2_LEN {
                        if let Ok(decoded) = decode_integrity_trailer_v2(&trailer_buf) {
                            let footer_ref = footer
                                .as_ref()
                                .map(|fb: &[u8; RECORD_FOOTER_LEN]| fb)
                                .unwrap_or(&[0u8; RECORD_FOOTER_LEN]);

                            match verify_integrity_trailer_v2(
                                &decoded,
                                record,
                                &header,
                                &payload,
                                footer_ref,
                                segment_id,
                                trailer_offset,
                            ) {
                                Ok(_actual) => {}
                                Err(StoreError::ProductionIntegrityMismatch {
                                    field,
                                    expected,
                                    actual,
                                    ..
                                }) => {
                                    let outcome = if field.contains("payload") {
                                        ScrubOutcome::PayloadMismatch {
                                            segment_id,
                                            record_offset: offset,
                                            expected: expected.as_bytes32(),
                                            actual: actual.as_bytes32(),
                                        }
                                    } else {
                                        ScrubOutcome::RecordDigestMismatch {
                                            segment_id,
                                            record_offset: offset,
                                            expected: expected.as_bytes32(),
                                            actual: actual.as_bytes32(),
                                        }
                                    };
                                    report.outcomes.push(outcome);
                                    suspect_log.record(SuspectEntry {
                                        locator_id: 0,
                                        segment_id,
                                        offset,
                                        record_type: 1,
                                        expected_hash: [0u8; 32],
                                        actual_hash: [0u8; 32],
                                        repair_attempts: 0,
                                        last_repair_attempt: 0,
                                        resolved: false,
                                        commit_group: record.sequence,
                                        timestamp_secs: 0,
                                        ..Default::default()
                                    });
                                }
                                Err(_other) => {
                                    suspect_log.record(SuspectEntry {
                                        locator_id: 0,
                                        segment_id,
                                        offset,
                                        record_type: 1,
                                        expected_hash: [0u8; 32],
                                        actual_hash: [0u8; 32],
                                        repair_attempts: 0,
                                        last_repair_attempt: 0,
                                        resolved: false,
                                        commit_group: record.sequence,
                                        timestamp_secs: 0,
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                }

                offset = trailer_offset + INTEGRITY_TRAILER_V2_LEN_U64;
                report.records_verified = report.records_verified.saturating_add(1);
                report.bytes_scanned = report.bytes_scanned.saturating_add(payload_len as u64);
                file.seek(SeekFrom::Start(offset))
                    .map_err(|source| crate::io_error("seek scrub", &path, source))?;
            }
        }

        // Verify segment footer chain.
        let chain_verifier = SegmentChainVerifier::new(&self.segments_dir);
        let (chain_stats, chain_suspects) = chain_verifier.verify_chain()?;
        report.chain_breaks_detected = chain_stats.chain_breaks_detected;
        report.chain_stats = Some(chain_stats);

        // Determine the newest (highest-ID) segment - it may not have a
        // footer if still being written. Skip truncation reports for it.
        let newest_seg = sorted_ids.last().copied().unwrap_or(0);
        for entry in chain_suspects.iter() {
            // Skip truncation reports for segments that never held records
            // (e.g., the initial empty segment file created during open)
            // OR the currently-active segment that may lack a footer.
            if entry.record_type != 3 {
                if entry.segment_id == newest_seg {
                    continue; // active segment may not have footer yet
                }
                let path = segment_path(&self.segments_dir, entry.segment_id);
                if let Ok(len) = file_len(&path) {
                    if len < RECORD_HEADER_LEN_U64 {
                        continue; // never had a record, skip
                    }
                }
            }
            let outcome = match entry.record_type {
                3 => ScrubOutcome::ChainBroken {
                    segment_id: entry.segment_id,
                    expected: [0u8; 32],
                    actual: [0u8; 32],
                },
                _ => ScrubOutcome::TruncatedSegment {
                    segment_id: entry.segment_id,
                },
            };
            report.outcomes.push(outcome);
            suspect_log.record(*entry);
        }

        report.completed = true;
        report.segments_scanned = report.segments_scanned.saturating_add(seen_segments);
        cursor.reset();
        report.cursor = *cursor;

        Ok(report)
    }

    pub fn scrub_full(&self, suspect_log: &mut SuspectLog) -> Result<ScrubReport> {
        let mut cursor = ScrubCursor::default();
        self.scrub_incremental(&mut cursor, 0, 0, suspect_log)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LocalObjectStore, StoreOptions};
    use std::fs;

    fn store_with_data(root: &Path) {
        let opts = StoreOptions {
            max_segment_bytes: 4096,
            segment_count: 16,
            sync_on_write: true,
            ..StoreOptions::test_fast()
        };
        let mut store = LocalObjectStore::open_with_options(root, opts).unwrap();
        for i in 0u8..5 {
            let data = vec![i; 200];
            store.put_named(format!("obj-{i}"), &data).unwrap();
        }
        store.flush_segment().unwrap();
        store.sync_all().unwrap();
        drop(store);
    }

    fn scratch_dir() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::TempDir::with_prefix("scrub-test").unwrap();
        let root = tmp.path().to_path_buf();
        (tmp, root)
    }

    #[test]
    fn scrub_clean_pool_reports_zero_findings() {
        let (_tmp, root) = scratch_dir();
        store_with_data(&root);
        let seg_dir = root.join(crate::constants::STORE_DIR_NAME);

        let scrubber = SegmentIntegrityScrubber::new(&seg_dir);
        let mut suspect_log = SuspectLog::new();
        let report = scrubber.scrub_full(&mut suspect_log).unwrap();

        assert!(report.completed);
        assert!(report.records_verified > 0);
        assert!(
            report.outcomes.is_empty(),
            "clean pool must have zero findings, got {:?}",
            report.outcomes
        );
        assert_eq!(suspect_log.len(), 0);
    }

    #[test]
    fn scrub_is_deterministic() {
        let (_tmp, root) = scratch_dir();
        store_with_data(&root);
        let seg_dir = root.join(crate::constants::STORE_DIR_NAME);

        let scrubber = SegmentIntegrityScrubber::new(&seg_dir);
        let mut log1 = SuspectLog::new();
        let report1 = scrubber.scrub_full(&mut log1).unwrap();

        let mut log2 = SuspectLog::new();
        let report2 = scrubber.scrub_full(&mut log2).unwrap();

        assert_eq!(report1.records_verified, report2.records_verified);
        assert_eq!(report1.bytes_scanned, report2.bytes_scanned);
        assert_eq!(report1.outcomes.len(), report2.outcomes.len());
    }

    #[test]
    fn scrub_incremental_makes_forward_progress() {
        let (_tmp, root) = scratch_dir();
        store_with_data(&root);
        let seg_dir = root.join(crate::constants::STORE_DIR_NAME);

        let scrubber = SegmentIntegrityScrubber::new(&seg_dir);
        let mut suspect_log = SuspectLog::new();
        let mut cursor = ScrubCursor::default();

        let mut total_records = 0u64;
        loop {
            let report = scrubber
                .scrub_incremental(&mut cursor, 1, 0, &mut suspect_log)
                .unwrap();
            total_records += report.records_verified;
            if report.completed {
                break;
            }
            assert!(report.records_verified <= 1);
        }
        let report_full = scrubber.scrub_full(&mut SuspectLog::new()).unwrap();
        assert_eq!(total_records, report_full.records_verified);
    }

    #[test]
    fn corruption_payload_byte_flip_detected() {
        let (_tmp, root) = scratch_dir();
        store_with_data(&root);
        let seg_dir = root.join(crate::constants::STORE_DIR_NAME);

        let seg_ids = discover_segment_ids(&seg_dir).unwrap();
        assert!(!seg_ids.is_empty());
        let seg_path = segment_path(&seg_dir, seg_ids[0]);
        let len = fs::metadata(&seg_path).unwrap().len();

        if len > RECORD_HEADER_LEN_U64 + 10 {
            let corrupt_offset = RECORD_HEADER_LEN_U64 + 5;
            let mut data = fs::read(&seg_path).unwrap();
            data[corrupt_offset as usize] ^= 0xFF;
            fs::write(&seg_path, &data).unwrap();

            let scrubber = SegmentIntegrityScrubber::new(&seg_dir);
            let mut suspect_log = SuspectLog::new();
            let report = scrubber.scrub_full(&mut suspect_log).unwrap();

            assert!(
                !report.outcomes.is_empty() || !suspect_log.is_empty(),
                "payload corruption must be detected"
            );
        }
    }

    #[test]
    fn scrub_cursor_is_initial_when_zero() {
        let cursor = ScrubCursor::default();
        assert!(cursor.is_initial());
    }

    #[test]
    fn scrub_cursor_reset_clears() {
        let mut cursor = ScrubCursor {
            segment_id: 42,
            offset: 100,
        };
        cursor.reset();
        assert!(cursor.is_initial());
    }

    #[test]
    fn scrub_outcome_variants_compare_equal() {
        let a = ScrubOutcome::Clean { segment_id: 1 };
        let b = ScrubOutcome::Clean { segment_id: 1 };
        assert_eq!(a, b);
    }

    #[test]
    fn scrub_report_default_is_empty() {
        let report = ScrubReport::default();
        assert_eq!(report.segments_scanned, 0);
        assert_eq!(report.records_verified, 0);
        assert!(report.outcomes.is_empty());
        assert!(!report.completed);
    }

    // -- Cursor persistence --------------------------------------------

    #[test]
    fn scrub_cursor_persists_across_close_reopen() {
        let (_tmp, root) = scratch_dir();
        let seg_dir = root.join(crate::constants::STORE_DIR_NAME);

        // Write a known cursor to disk.
        std::fs::create_dir_all(&seg_dir).unwrap();
        let cursor = ScrubCursor {
            segment_id: 3,
            offset: 1024,
        };
        crate::write_scrub_cursor(&seg_dir, &cursor).unwrap();

        // Load it back.
        let loaded = crate::load_scrub_cursor(&seg_dir);
        assert_eq!(loaded.segment_id, 3);
        assert_eq!(loaded.offset, 1024);
    }

    #[test]
    fn scrub_cursor_defaults_to_zero_when_no_file() {
        let (_tmp, root) = scratch_dir();
        let seg_dir = root.join(crate::constants::STORE_DIR_NAME);
        std::fs::create_dir_all(&seg_dir).unwrap();

        let loaded = crate::load_scrub_cursor(&seg_dir);
        assert!(loaded.is_initial());
    }

    // -- Integration: write, corrupt, scrub, detect --------------------

    #[test]
    fn integration_corrupt_segment_byte_detected_by_scrub() {
        let (_tmp, root) = scratch_dir();
        store_with_data(&root);
        let seg_dir = root.join(crate::constants::STORE_DIR_NAME);

        // Find a segment with data, corrupt a byte in its payload area,
        // scrub, and assert the corruption is detected.
        let seg_ids = discover_segment_ids(&seg_dir).unwrap();
        assert!(!seg_ids.is_empty(), "must have at least one segment");

        // Use a segment that contains records (skip segment 0 if it's
        // empty).
        let target_seg = seg_ids
            .iter()
            .find(|&&sid| {
                let p = segment_path(&seg_dir, sid);
                let len = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                len > RECORD_HEADER_LEN_U64 + RECORD_FOOTER_LEN_U64 + INTEGRITY_TRAILER_V2_LEN_U64
            })
            .copied()
            .unwrap_or(seg_ids[0]);

        let seg_path = segment_path(&seg_dir, target_seg);
        let len = std::fs::metadata(&seg_path).unwrap().len();
        assert!(
            len > RECORD_HEADER_LEN_U64 + 10,
            "segment must have enough data to corrupt"
        );

        // Corrupt a byte in the middle of the first record's payload.
        let corrupt_offset = RECORD_HEADER_LEN_U64 + 5;
        let mut data = std::fs::read(&seg_path).unwrap();
        data[corrupt_offset as usize] ^= 0xFF;
        std::fs::write(&seg_path, &data).unwrap();

        // Run the scrubber directly on the corrupted segment files
        // (without reopening the store, which would fail on replay).
        let scrubber = SegmentIntegrityScrubber::new(&seg_dir);
        let mut suspect_log = SuspectLog::new();
        let report = scrubber.scrub_full(&mut suspect_log).unwrap();

        assert!(
            !report.outcomes.is_empty() || !suspect_log.is_empty(),
            "corruption must be detected by scrub; outcomes={:?} log_len={}",
            report.outcomes,
            suspect_log.len()
        );
    }
}
