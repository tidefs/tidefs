// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Intent-log segment compaction for bounded replay at startup.
//!
//! After multiple transaction groups commit, intent-log segments contain a
//! mix of already-applied records (LSN <= committed_lsn) and still-relevant
//! records (LSN > committed_lsn).  Trimming alone can only delete segments
//! whose entire LSN range is below the committed LSN.  Compaction rewrites
//! partially-obsolete segments so that only the live records survive,
//! bounding the total number of segments and thus the worst-case replay
//! time at mount.
//!
//! # How it works
//!
//! 1. Parse each input segment via [`IntentLogReader`].
//! 2. Filter records: keep only those whose `lsn > committed_lsn`.
//! 3. Use [`IntentLogWriter`] to write the kept records into new, compacted
//!    segments (auto-rotating when the configured segment size is reached).
//! 4. Return the compacted segment bytes, a list of old segment indices to
//!    delete, and compaction statistics.
//!
//! # Replay bound
//!
//! If compaction runs regularly with a watermark that advances as txgs
//! commit, the total number of intent-log records that remain unapplied
//! across all segments is bounded by the compaction frequency times the
//! maximum write rate.  This guarantees that mount-time replay completes
//! in bounded time regardless of total uptime.

use crate::reader::{IntentLogReader, SegmentReadResult};
use crate::writer::IntentLogWriter;
use crate::IntentLogFrame;

// ---------- CompactionStats ----------------------------------------------------

/// Statistics from a compaction run.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CompactionStats {
    /// Number of input segments scanned.
    pub segments_scanned: usize,
    /// Number of new compacted segments produced.
    pub segments_compacted: usize,
    /// Number of records retained (lsn > committed_lsn).
    pub records_kept: u64,
    /// Number of records removed (lsn <= committed_lsn).
    pub records_removed: u64,
    /// Number of records that could not be read (corrupt segment or record).
    pub records_skipped: u64,
    /// Number of input segments that were entirely obsolete (all records removed).
    pub segments_fully_obsolete: usize,
    /// Number of input segments that were corrupt and skipped.
    pub segments_corrupt: usize,
    /// Total bytes of original segment data (approximate, from input buffers).
    pub input_bytes: u64,
    /// Total bytes of compacted segment data produced.
    pub output_bytes: u64,
}

/// Result of a single compaction run.
#[derive(Clone, Debug)]
pub struct CompactionResult {
    /// New compacted segment bytes to write to disk (replacing old segments).
    pub compacted_segments: Vec<Vec<u8>>,
    /// Indices into the original segment list of segments that can be
    /// deleted after the compacted segments are durably written.
    pub obsolete_segment_indices: Vec<usize>,
    /// Compaction statistics.
    pub stats: CompactionStats,
}

// ---------- IntentLogCompactor -------------------------------------------------

/// Compacts intent-log segments by removing already-applied records.
///
/// # Example
///
/// ```ignore
/// let segments: Vec<Vec<u8>> = load_existing_segments();
/// let compactor = IntentLogCompactor::new(64 * 1024 * 1024);
/// let result = compactor.compact(&segments, committed_lsn);
/// for seg in &result.compacted_segments {
///     write_new_segment(seg);
/// }
/// for idx in &result.obsolete_segment_indices {
///     delete_segment(idx);
/// }
/// ```
pub struct IntentLogCompactor {
    /// Maximum size of each output compacted segment (same meaning as
    /// [`IntentLogWriter::new`]).
    max_segment_size: u64,
}

impl IntentLogCompactor {
    /// Create a new compactor with the given maximum segment size.
    #[must_use]
    pub fn new(max_segment_size: u64) -> Self {
        Self { max_segment_size }
    }

    /// Compact a set of intent-log segments.
    ///
    /// `segments` is a list of raw segment byte buffers (one per segment
    /// file).  `committed_lsn` is the LSN watermark: records at or below
    /// this value have already been applied to the committed state and are
    /// removed during compaction.
    pub fn compact(&self, segments: &[Vec<u8>], committed_lsn: u64) -> CompactionResult {
        let mut writer = IntentLogWriter::new(self.max_segment_size);
        let mut stats = CompactionStats::default();
        let mut obsolete_indices: Vec<usize> = Vec::new();
        let mut compacted_segments: Vec<Vec<u8>> = Vec::new();

        for (idx, segment_data) in segments.iter().enumerate() {
            stats.segments_scanned += 1;
            stats.input_bytes += segment_data.len() as u64;

            let result = IntentLogReader::read_segment(segment_data);

            let live_records = match result {
                SegmentReadResult::Complete { records, .. } => records,
                SegmentReadResult::Truncated { valid_records, .. } => valid_records,
                SegmentReadResult::Corrupt => {
                    stats.segments_corrupt += 1;
                    obsolete_indices.push(idx);
                    continue;
                }
            };

            let mut kept_this_segment: u64 = 0;
            let mut removed_this_segment: u64 = 0;

            for seg_rec in &live_records {
                if seg_rec.lsn > committed_lsn {
                    let frame = IntentLogFrame::new(seg_rec.record.clone(), 0, seg_rec.lsn);

                    match writer.append_frame(&frame) {
                        Ok(Some(sealed)) => {
                            compacted_segments.push(sealed);
                            stats.segments_compacted += 1;
                        }
                        Ok(None) => {}
                        Err(_) => {
                            stats.records_skipped += 1;
                            continue;
                        }
                    }
                    kept_this_segment += 1;
                } else {
                    removed_this_segment += 1;
                }
            }

            stats.records_kept += kept_this_segment;
            stats.records_removed += removed_this_segment;

            if kept_this_segment == 0 {
                obsolete_indices.push(idx);
                stats.segments_fully_obsolete += 1;
            }
        }

        if let Ok(Some(final_segment)) = writer.finish() {
            compacted_segments.push(final_segment);
            stats.segments_compacted += 1;
        }

        stats.output_bytes = compacted_segments.iter().map(|s| s.len() as u64).sum();

        for (idx, segment_data) in segments.iter().enumerate() {
            let result = IntentLogReader::read_segment(segment_data);
            match result {
                SegmentReadResult::Corrupt => {}
                _ => {
                    if !obsolete_indices.contains(&idx) {
                        obsolete_indices.push(idx);
                    }
                }
            }
        }

        if compacted_segments.is_empty() {
            obsolete_indices.retain(|i| {
                let result = IntentLogReader::read_segment(&segments[*i]);
                matches!(result, SegmentReadResult::Corrupt)
            });
            for (idx, segment_data) in segments.iter().enumerate() {
                if obsolete_indices.contains(&idx) {
                    continue;
                }
                let result = IntentLogReader::read_segment(segment_data);
                match result {
                    SegmentReadResult::Complete { records, .. }
                    | SegmentReadResult::Truncated {
                        valid_records: records,
                        ..
                    } => {
                        if records.iter().all(|r| r.lsn <= committed_lsn) {
                            obsolete_indices.push(idx);
                        }
                    }
                    SegmentReadResult::Corrupt => {
                        obsolete_indices.push(idx);
                    }
                }
            }
        }

        obsolete_indices.sort_unstable();
        obsolete_indices.dedup();

        CompactionResult {
            compacted_segments,
            obsolete_segment_indices: obsolete_indices,
            stats,
        }
    }

    /// Return the configured maximum segment size.
    #[must_use]
    pub fn max_segment_size(&self) -> u64 {
        self.max_segment_size
    }
}

// ---------- On-disk compaction helper ------------------------------------------

/// Compact intent-log segment files on disk.
///
/// Scans a directory for segment files (named `segment-NNNNNNNNNN.viflodev`),
/// reads them into memory, compacts with the given committed LSN watermark,
/// writes the compacted segments back, and atomically replaces old segment
/// files by first writing to temporary files then renaming.
///
/// The caller must ensure no concurrent writer is active in the directory.
pub fn compact_on_disk(
    dir: &std::path::Path,
    committed_lsn: u64,
    max_segment_size: u64,
) -> Result<CompactionStats, std::io::Error> {
    use std::fs;
    use std::io::Read;

    let mut entries: Vec<(u64, std::path::PathBuf)> = Vec::new();
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("viflodev") {
                if let Some(seg_id) = segment_id_from_path(&path) {
                    entries.push((seg_id, path));
                }
            }
        }
    }
    entries.sort_by_key(|(id, _)| *id);

    if entries.is_empty() {
        return Ok(CompactionStats::default());
    }

    let mut segment_data: Vec<Vec<u8>> = Vec::new();
    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    for (_id, path) in &entries {
        let mut f = fs::File::open(path)?;
        let mut data = Vec::new();
        f.read_to_end(&mut data)?;
        segment_data.push(data);
        paths.push(path.clone());
    }

    let compactor = IntentLogCompactor::new(max_segment_size);
    let result = compactor.compact(&segment_data, committed_lsn);

    let max_id = entries.last().map(|(id, _)| *id).unwrap_or(0);
    for (i, data) in result.compacted_segments.iter().enumerate() {
        let new_id = max_id + 1 + i as u64;
        let tmp = dir.join(format!("segment-{new_id:010}.viflodev.tmp"));
        fs::write(&tmp, data)?;
        let final_path = dir.join(format!("segment-{new_id:010}.viflodev"));
        fs::rename(&tmp, &final_path)?;
    }

    for idx in &result.obsolete_segment_indices {
        if *idx < paths.len() {
            let _ = fs::remove_file(&paths[*idx]);
        }
    }

    Ok(result.stats)
}

/// Extract segment sequence number from a path like `segment-0000000001.viflodev`.
fn segment_id_from_path(path: &std::path::Path) -> Option<u64> {
    let stem = path.file_stem()?.to_str()?;
    stem.strip_prefix("segment-")?.parse::<u64>().ok()
}

// ---------- Tests ------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::SegmentReadResult;
    use crate::reader::SegmentRecord;
    use crate::replay::{IntentReplayEngine, IntentReplayHandler};
    use crate::{IntentLogFrame, IntentLogRecord, IntentLogWriter};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_TEMPDIR_ID: AtomicU64 = AtomicU64::new(0);

    fn test_tempdir() -> std::path::PathBuf {
        let id = TEST_TEMPDIR_ID.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("tidefs-compaction-{}-{}", std::process::id(), id));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_write_frame(seq: u64, ino: u64) -> IntentLogFrame {
        let rec = IntentLogRecord::Write {
            ino,
            offset: seq * 4096,
            length: seq * 4096,
            data_hash: [0xAA; 32],
        };
        IntentLogFrame::new(rec, 1, seq)
    }

    fn make_test_segment(frames: &[IntentLogFrame]) -> Vec<u8> {
        let mut writer = IntentLogWriter::new(64 * 1024 * 1024);
        for f in frames {
            writer.append_frame(f).unwrap();
        }
        writer.finish().unwrap().unwrap()
    }

    #[test]
    fn compaction_removes_records_below_lsn() {
        let segments = vec![make_test_segment(&[
            make_write_frame(0, 100),
            make_write_frame(1, 101),
            make_write_frame(2, 102),
            make_write_frame(3, 103),
            make_write_frame(4, 104),
        ])];

        let compactor = IntentLogCompactor::new(64 * 1024 * 1024);
        let result = compactor.compact(&segments, 2);

        assert_eq!(result.stats.records_kept, 2);
        assert_eq!(result.stats.records_removed, 3);
        assert_eq!(result.stats.segments_scanned, 1);
        assert!(!result.compacted_segments.is_empty());

        let compacted_data = &result.compacted_segments[0];
        let read_result = IntentLogReader::read_segment(compacted_data);
        match read_result {
            SegmentReadResult::Complete { records, .. } => {
                assert_eq!(records.len(), 2);
                assert_eq!(records[0].lsn, 3);
                assert_eq!(records[1].lsn, 4);
            }
            other => panic!("expected Complete, got {other:?}"),
        }

        assert_eq!(result.obsolete_segment_indices, vec![0]);
    }

    #[test]
    fn compaction_all_records_above_lsn_keeps_everything() {
        let segments = vec![make_test_segment(&[
            make_write_frame(10, 200),
            make_write_frame(11, 201),
            make_write_frame(12, 202),
        ])];

        let compactor = IntentLogCompactor::new(64 * 1024 * 1024);
        let result = compactor.compact(&segments, 5);

        assert_eq!(result.stats.records_kept, 3);
        assert_eq!(result.stats.records_removed, 0);
    }

    #[test]
    fn compaction_all_records_below_lsn_removes_all() {
        let segments = vec![make_test_segment(&[
            make_write_frame(0, 300),
            make_write_frame(1, 301),
        ])];

        let compactor = IntentLogCompactor::new(64 * 1024 * 1024);
        let result = compactor.compact(&segments, 10);

        assert_eq!(result.stats.records_kept, 0);
        assert_eq!(result.stats.records_removed, 2);
        assert_eq!(result.stats.segments_fully_obsolete, 1);
        assert!(result.compacted_segments.is_empty());
        assert_eq!(result.obsolete_segment_indices, vec![0]);
    }

    #[test]
    fn compaction_across_multiple_segments() {
        let seg1 = make_test_segment(&[
            make_write_frame(0, 100),
            make_write_frame(1, 101),
            make_write_frame(2, 102),
        ]);
        let seg2 = make_test_segment(&[
            make_write_frame(3, 103),
            make_write_frame(4, 104),
            make_write_frame(5, 105),
        ]);
        let seg3 = make_test_segment(&[make_write_frame(6, 106), make_write_frame(7, 107)]);
        let seg4 = make_test_segment(&[make_write_frame(8, 108), make_write_frame(9, 109)]);

        let segments = vec![seg1, seg2, seg3, seg4];
        let compactor = IntentLogCompactor::new(64 * 1024 * 1024);
        let result = compactor.compact(&segments, 5);

        assert_eq!(result.stats.records_kept, 4);
        assert_eq!(result.stats.records_removed, 6);
        assert_eq!(result.stats.segments_scanned, 4);
        assert_eq!(result.stats.segments_fully_obsolete, 2);
        assert!(!result.compacted_segments.is_empty());

        assert!(result.obsolete_segment_indices.contains(&0));
        assert!(result.obsolete_segment_indices.contains(&1));
        assert!(result.obsolete_segment_indices.contains(&2));
        assert!(result.obsolete_segment_indices.contains(&3));

        let mut all_records: Vec<SegmentRecord> = Vec::new();
        for data in &result.compacted_segments {
            match IntentLogReader::read_segment(data) {
                SegmentReadResult::Complete { records, .. } => {
                    all_records.extend(records);
                }
                other => panic!("expected Complete, got {other:?}"),
            }
        }
        assert_eq!(all_records.len(), 4);
        let lsns: Vec<u64> = all_records.iter().map(|r| r.lsn).collect();
        assert_eq!(lsns, vec![6, 7, 8, 9]);
    }

    #[test]
    fn compaction_with_empty_input() {
        let compactor = IntentLogCompactor::new(64 * 1024 * 1024);
        let result = compactor.compact(&[], 0);
        assert_eq!(result.stats.segments_scanned, 0);
        assert_eq!(result.stats.records_kept, 0);
        assert!(result.compacted_segments.is_empty());
        assert!(result.obsolete_segment_indices.is_empty());
    }

    #[test]
    fn compaction_skips_corrupt_segment() {
        let good_seg = make_test_segment(&[make_write_frame(10, 400), make_write_frame(11, 401)]);
        let corrupt_seg = vec![0xFFu8; 128];
        let segments = vec![good_seg, corrupt_seg];

        let compactor = IntentLogCompactor::new(64 * 1024 * 1024);
        let result = compactor.compact(&segments, 5);

        assert_eq!(result.stats.records_kept, 2);
        assert_eq!(result.stats.segments_corrupt, 1);
        assert_eq!(result.obsolete_segment_indices.len(), 2);
        assert!(result.obsolete_segment_indices.contains(&0));
        assert!(result.obsolete_segment_indices.contains(&1));
    }

    #[test]
    fn compacted_records_match_original() {
        let frames: Vec<IntentLogFrame> =
            (0..5).map(|i| make_write_frame(i + 100, 500 + i)).collect();
        let segment = make_test_segment(&frames);
        let segments = vec![segment];

        let compactor = IntentLogCompactor::new(64 * 1024 * 1024);
        let result = compactor.compact(&segments, 102);

        let compacted_data = &result.compacted_segments[0];
        let read_result = IntentLogReader::read_segment(compacted_data);
        match read_result {
            SegmentReadResult::Complete { records, .. } => {
                assert_eq!(records.len(), 2);
                assert_eq!(records[0].lsn, 103);
                assert_eq!(records[1].lsn, 104);
                assert_eq!(&records[0].record, &frames[3].record);
                assert_eq!(&records[1].record, &frames[4].record);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn compacted_segment_can_be_replayed() {
        #[derive(Debug, Default)]
        struct TestHandler {
            records: Vec<IntentLogRecord>,
        }
        impl IntentReplayHandler for TestHandler {
            type Error = String;
            fn handle_record(&mut self, record: &IntentLogRecord) -> Result<(), String> {
                self.records.push(record.clone());
                Ok(())
            }
        }

        let frames: Vec<IntentLogFrame> = (0..10).map(|i| make_write_frame(i, 600 + i)).collect();
        let segment = make_test_segment(&frames);
        let segments = vec![segment];

        let compactor = IntentLogCompactor::new(64 * 1024 * 1024);
        let result = compactor.compact(&segments, 5);

        let mut engine = IntentReplayEngine::new(0);
        let mut handler = TestHandler::default();
        for data in &result.compacted_segments {
            engine.replay_segment(data, &mut handler).unwrap();
        }

        assert_eq!(handler.records.len(), 4);
        assert_eq!(engine.state.entries_replayed, 4);
    }

    #[test]
    fn compaction_rotates_segments_when_max_size_reached() {
        let small_max = 2048u64;
        let compactor = IntentLogCompactor::new(small_max);

        let frames: Vec<IntentLogFrame> = (0..20).map(|i| make_write_frame(i, 700 + i)).collect();
        let segment = make_test_segment(&frames);
        let segments = vec![segment];

        let result = compactor.compact(&segments, 0);

        assert!(
            result.compacted_segments.len() > 1,
            "expected multiple compacted segments with small max size, got {}",
            result.compacted_segments.len()
        );
        assert_eq!(result.stats.records_kept, 19);

        let mut total_records = 0;
        for data in &result.compacted_segments {
            match IntentLogReader::read_segment(data) {
                SegmentReadResult::Complete { records, .. } => {
                    total_records += records.len();
                }
                other => panic!("expected Complete, got {other:?}"),
            }
        }
        assert_eq!(total_records, 19);
    }

    #[test]
    fn compaction_stats_are_accurate() {
        let seg = make_test_segment(&[
            make_write_frame(0, 800),
            make_write_frame(1, 801),
            make_write_frame(2, 802),
            make_write_frame(3, 803),
            make_write_frame(4, 804),
        ]);
        let input_size = seg.len() as u64;
        let segments = vec![seg];

        let compactor = IntentLogCompactor::new(64 * 1024 * 1024);
        let result = compactor.compact(&segments, 1);

        assert_eq!(result.stats.segments_scanned, 1);
        assert_eq!(result.stats.records_kept, 3);
        assert_eq!(result.stats.records_removed, 2);
        assert_eq!(result.stats.input_bytes, input_size);
        assert!(result.stats.output_bytes > 0);
        assert!(result.stats.output_bytes < result.stats.input_bytes);
    }

    #[test]
    fn compaction_is_idempotent() {
        let frames: Vec<IntentLogFrame> = (0..5).map(|i| make_write_frame(i, 900 + i)).collect();
        let segment = make_test_segment(&frames);
        let segments = vec![segment];

        let compactor = IntentLogCompactor::new(64 * 1024 * 1024);
        let result1 = compactor.compact(&segments, 2);
        let result2 = compactor.compact(&result1.compacted_segments, 2);

        assert_eq!(result1.stats.records_kept, result2.stats.records_kept);
        assert_eq!(result2.stats.records_removed, 0);
    }

    #[test]
    fn compaction_handles_truncated_segment() {
        let frames: Vec<IntentLogFrame> = (0..5).map(|i| make_write_frame(i, 1000 + i)).collect();
        let mut segment = make_test_segment(&frames);
        let trailer_start = segment.len() - 64;
        segment.truncate(trailer_start);

        let segments = vec![segment];
        let compactor = IntentLogCompactor::new(64 * 1024 * 1024);
        let result = compactor.compact(&segments, 2);

        assert!(result.stats.records_kept > 0);
        assert_eq!(result.stats.segments_corrupt, 0);
    }

    #[test]
    fn compaction_preserves_non_write_records() {
        let frames = vec![
            IntentLogFrame::new(
                IntentLogRecord::Create {
                    parent: 1,
                    name: b"f".to_vec(),
                    mode: 0o644,
                    ino: 10,
                },
                1,
                0,
            ),
            IntentLogFrame::new(
                IntentLogRecord::Unlink {
                    parent: 1,
                    name: b"f".to_vec(),
                    ino: 10,
                },
                1,
                1,
            ),
            IntentLogFrame::new(
                IntentLogRecord::Mkdir {
                    parent: 1,
                    name: b"d".to_vec(),
                    mode: 0o755,
                    ino: 11,
                },
                1,
                2,
            ),
        ];
        let segment = make_test_segment(&frames);
        let segments = vec![segment];

        let compactor = IntentLogCompactor::new(64 * 1024 * 1024);
        let result = compactor.compact(&segments, 0);

        assert_eq!(result.stats.records_kept, 2);
        let compacted = &result.compacted_segments[0];
        let read_result = IntentLogReader::read_segment(compacted);
        match read_result {
            SegmentReadResult::Complete { records, .. } => {
                assert_eq!(records.len(), 2);
                assert!(matches!(&records[0].record, IntentLogRecord::Unlink { .. }));
                assert!(matches!(&records[1].record, IntentLogRecord::Mkdir { .. }));
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    // ---- On-disk compaction and crash/reopen tests ----

    #[test]
    fn compact_on_disk_basic() {
        let dir = test_tempdir();
        let dir_path = &dir;

        // Write two segments directly to disk
        let seg1 = make_test_segment(&[
            make_write_frame(0, 10),
            make_write_frame(1, 11),
            make_write_frame(2, 12),
        ]);
        let seg2 = make_test_segment(&[make_write_frame(3, 13), make_write_frame(4, 14)]);
        std::fs::write(dir_path.join("segment-0000000000.viflodev"), &seg1).unwrap();
        std::fs::write(dir_path.join("segment-0000000001.viflodev"), &seg2).unwrap();

        // Compact with committed_lsn = 2: should keep lsn 3,4
        let stats = compact_on_disk(dir_path, 2, 64 * 1024 * 1024).unwrap();

        assert_eq!(stats.records_kept, 2);
        assert_eq!(stats.records_removed, 3);

        // Verify old segments removed, new segments present
        let remaining: Vec<_> = std::fs::read_dir(dir_path)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("viflodev"))
            .collect();
        assert!(!remaining.is_empty(), "should have compacted segments");

        // Read compacted segment and verify content
        let mut all_records: Vec<SegmentRecord> = Vec::new();
        for entry in &remaining {
            let data = std::fs::read(entry.path()).unwrap();
            match IntentLogReader::read_segment(&data) {
                SegmentReadResult::Complete { records, .. } => all_records.extend(records),
                _ => panic!("bad compacted segment"),
            }
        }
        assert_eq!(all_records.len(), 2);
        assert_eq!(all_records[0].lsn, 3);
        assert_eq!(all_records[1].lsn, 4);
    }

    #[test]
    fn crash_reopen_compaction_preserves_operations() {
        // Simulate a crash scenario:
        // 1. Write segments across multiple "txgs"
        // 2. Truncate the last segment (simulating crash before footer written)
        // 3. Compact segments
        // 4. Replay compacted segments and verify all unapplied operations survive

        let dir = test_tempdir();
        let dir_path = &dir;

        // Write segments representing committed txgs
        let seg1 = make_test_segment(&[
            make_write_frame(0, 100),
            make_write_frame(1, 101),
            make_write_frame(2, 102),
        ]);
        let seg2 = make_test_segment(&[
            make_write_frame(3, 103),
            make_write_frame(4, 104),
            make_write_frame(5, 105),
        ]);
        // seg3: active segment that was being written during crash
        let mut seg3 = make_test_segment(&[
            make_write_frame(6, 106),
            make_write_frame(7, 107),
            make_write_frame(8, 108),
            make_write_frame(9, 109),
        ]);
        // Simulate crash: truncate before footer
        let trailer_start = seg3.len() - 64;
        seg3.truncate(trailer_start);

        std::fs::write(dir_path.join("segment-0000000000.viflodev"), &seg1).unwrap();
        std::fs::write(dir_path.join("segment-0000000001.viflodev"), &seg2).unwrap();
        std::fs::write(dir_path.join("segment-0000000002.viflodev"), &seg3).unwrap();

        // Compaction: committed_lsn = 3 (lsns 0-3 are applied, 4+ need replay)
        let stats = compact_on_disk(dir_path, 3, 64 * 1024 * 1024).unwrap();

        assert!(
            stats.records_kept >= 5,
            "should keep lsn 4-8 (5 records from seg2[1:] + seg3)"
        );

        // Replay all compacted segments
        #[derive(Debug, Default)]
        struct VerifyHandler {
            records: Vec<IntentLogRecord>,
        }
        impl IntentReplayHandler for VerifyHandler {
            type Error = String;
            fn handle_record(&mut self, record: &IntentLogRecord) -> Result<(), String> {
                self.records.push(record.clone());
                Ok(())
            }
        }

        let mut engine = IntentReplayEngine::new(0);
        let mut handler = VerifyHandler::default();
        let remaining: Vec<_> = std::fs::read_dir(dir_path)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("viflodev"))
            .collect();

        for entry in &remaining {
            let data = std::fs::read(entry.path()).unwrap();
            engine.replay_segment(&data, &mut handler).unwrap();
        }

        // Verify: LSNs 4-8 should all be replayed (5 records)
        // LSN 4: from seg2 (ino 104 at offset 4*4096)
        // LSNs 6-8: from seg3 (truncated but readable)
        assert!(
            handler.records.len() >= 5,
            "expected at least 5 replayed records, got {}",
            handler.records.len()
        );

        // Verify specific records survived compaction and replay
        let write_ino_104 = handler
            .records
            .iter()
            .find(|r| matches!(r, IntentLogRecord::Write { ino: 104, .. }));
        assert!(
            write_ino_104.is_some(),
            "ino 104 write should survive compaction"
        );

        let write_ino_109 = handler
            .records
            .iter()
            .find(|r| matches!(r, IntentLogRecord::Write { ino: 109, .. }));
        assert!(
            write_ino_109.is_some(),
            "ino 109 write should survive crash + compaction"
        );
    }

    #[test]
    fn compaction_bounds_replay_count() {
        // Prove that compaction reduces the number of records that need replay.
        // Write 50 records across 5 segments, compact with a mid-point LSN,
        // and verify the compacted output has fewer records than the input.

        let dir = test_tempdir();
        let dir_path = &dir;

        let _total_records = 50u64;
        let records_per_seg = 10;
        for seg_idx in 0..5u64 {
            let frames: Vec<IntentLogFrame> = (0..records_per_seg)
                .map(|i| make_write_frame(seg_idx * records_per_seg + i, 1000 + seg_idx * 10 + i))
                .collect();
            let data = make_test_segment(&frames);
            std::fs::write(
                dir_path.join(format!("segment-{seg_idx:010}.viflodev")),
                &data,
            )
            .unwrap();
        }

        // Compact: remove first 25 records (lsn <= 24)
        let stats = compact_on_disk(dir_path, 24, 64 * 1024 * 1024).unwrap();

        // Verify reduction
        assert_eq!(stats.records_removed, 25);
        assert_eq!(stats.records_kept, 25);
        assert!(stats.segments_compacted > 0);
        assert!(
            stats.segments_compacted < 5,
            "compaction should reduce segment count: {} >= 5",
            stats.segments_compacted
        );

        // Replay compacted segments: should find exactly 25 unapplied records
        let remaining: Vec<_> = std::fs::read_dir(dir_path)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("viflodev"))
            .collect();

        let mut total_replay = 0u64;
        for entry in &remaining {
            let data = std::fs::read(entry.path()).unwrap();
            if let SegmentReadResult::Complete { records, .. } =
                IntentLogReader::read_segment(&data)
            {
                total_replay += records.len() as u64;
            }
        }
        assert_eq!(
            total_replay, 25,
            "compacted segments should contain exactly 25 records, got {total_replay}"
        );
    }
}
