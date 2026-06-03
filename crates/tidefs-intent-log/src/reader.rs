//! Intent-log segment reader with crash-consistent replay.
//!
//! [`IntentLogReader`] reads an on-disk segment and extracts committed
//! records. For segments with a valid footer (fully committed), all
//! records are replayed. For segments without a valid footer (truncated
//! during crash), records are replayed up to the last valid record
//! checksum.
//!
//! # Example
//!
//! ```ignore
//! let data = std::fs::read("intent_log/segment-000.viflodev").unwrap();
//! match IntentLogReader::read_segment(&data).unwrap() {
//!     SegmentState::Complete { records, .. } => {
//!         // Replay all records
//!     }
//!     SegmentState::Truncated { valid_records, .. } => {
//!         // Replay only valid_records
//!     }
//!     SegmentState::Corrupt => {
//!         // Segment is unreadable; skip
//!     }
//! }
//! ```

use crate::segment::{
    decode_record_entry, try_decode_record_entry, RecordIndexEntry, SegmentFooter, SegmentHeader,
    SEGMENT_HEADER_SIZE,
};
use crate::{IntentLogError, IntentLogRecord};

/// Result of reading a segment.
#[derive(Clone, Debug)]
pub enum SegmentReadResult {
    /// Segment is fully committed with a valid footer.
    Complete {
        /// Parsed segment header.
        header: SegmentHeader,
        /// All records from the segment in LSN order.
        records: Vec<SegmentRecord>,
        /// The footer index.
        footer: SegmentFooter,
    },
    /// Segment was truncated during crash (no valid footer).
    /// Contains records up to the last valid checksum.
    Truncated {
        /// Parsed segment header.
        header: SegmentHeader,
        /// Valid records replayed up to the truncation point.
        valid_records: Vec<SegmentRecord>,
    },
    /// Segment is corrupt (bad header checksum or no valid records).
    Corrupt,
}

/// A single record extracted from a segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentRecord {
    /// The record LSN (from the footer index, or inferred from position).
    pub lsn: u64,
    /// The record type discriminant.
    pub record_type: u8,
    /// The decoded [`IntentLogRecord`].
    pub record: IntentLogRecord,
}

/// Result of reading a segment filtered by LSN threshold.
#[derive(Clone, Debug)]
pub enum FilteredReadResult {
    /// At least one record met the LSN threshold.
    Records {
        /// The segment header.
        header: SegmentHeader,
        /// Records with lsn > min_lsn.
        records: Vec<SegmentRecord>,
    },
    /// All records in the segment were at or below the threshold.
    AllFiltered {
        /// The segment header.
        header: SegmentHeader,
    },
    /// The segment is corrupt and cannot be read.
    Corrupt,
}

/// Reader for intent-log segments.
pub struct IntentLogReader;

impl IntentLogReader {
    /// Read and validate a segment from raw bytes.
    ///
    /// Returns [`SegmentReadResult::Complete`] if the segment has a valid
    /// footer, [`SegmentReadResult::Truncated`] if it was truncated during
    /// a crash (no valid footer but some valid records), or
    /// [`SegmentReadResult::Corrupt`] if the header is invalid or no
    /// valid records could be found.
    pub fn read_segment(data: &[u8]) -> SegmentReadResult {
        // Step 1: parse and validate header
        let header = match SegmentHeader::decode(data) {
            Ok(h) => h,
            Err(_) => return SegmentReadResult::Corrupt,
        };

        if header.record_count == 0 {
            return SegmentReadResult::Complete {
                header,
                records: Vec::new(),
                footer: SegmentFooter {
                    record_index: Vec::new(),
                },
            };
        }

        // Step 2: scan records from start of payload area
        let payload_start = SEGMENT_HEADER_SIZE;
        let records_data = &data[payload_start..];

        let record_results = Self::scan_records(records_data, header.record_count);

        // Step 3: try to read footer after the last consumed byte
        let after_records = payload_start + record_results.consumed_bytes;

        if record_results.valid_records.is_empty() {
            return SegmentReadResult::Corrupt;
        }

        match SegmentFooter::try_decode(&data[after_records..]) {
            Ok(Some(footer)) => {
                // Fully committed segment
                // Remap LSNs from footer record_index for cross-segment consistency.
                let mut records = record_results.valid_records;
                for (j, entry) in footer.record_index.iter().enumerate() {
                    if j < records.len() {
                        records[j].lsn = entry.lsn;
                    }
                }
                SegmentReadResult::Complete {
                    header,
                    records,
                    footer,
                }
            }
            Ok(None) => {
                // Truncated: no valid footer
                // Remap LSNs from header segment_lsn_start for partial replay.
                let mut valid_records = record_results.valid_records;
                for (j, rec) in valid_records.iter_mut().enumerate() {
                    rec.lsn = header.segment_lsn_start + j as u64;
                }
                SegmentReadResult::Truncated {
                    header,
                    valid_records,
                }
            }
            Err(_) => {
                // Footer corrupt
                // Remap LSNs from header segment_lsn_start for partial replay.
                let mut valid_records = record_results.valid_records;
                for (j, rec) in valid_records.iter_mut().enumerate() {
                    rec.lsn = header.segment_lsn_start + j as u64;
                }
                SegmentReadResult::Truncated {
                    header,
                    valid_records,
                }
            }
        }
    }

    /// Scan records from the payload area, stopping when `expected_count`
    /// records are found or when a record can no longer be decoded.
    fn scan_records(data: &[u8], expected_count: u32) -> RecordScanResult {
        let mut valid_records = Vec::with_capacity(expected_count as usize);
        let mut consumed_bytes: usize = 0;

        for i in 0..expected_count as usize {
            let remaining = &data[consumed_bytes..];
            match try_decode_record_entry(remaining) {
                Ok((0, _, _)) => {
                    // Truncated mid-record: stop
                    break;
                }
                Ok((record_type, payload, entry_size)) => {
                    // Decode the IntentLogRecord from payload
                    match IntentLogRecord::decode(&payload) {
                        Ok(record) => {
                            valid_records.push(SegmentRecord {
                                lsn: i as u64, // base LSN; caller can remap
                                record_type,
                                record,
                            });
                            consumed_bytes += entry_size;
                        }
                        Err(_) => {
                            // Payload doesn't decode as a valid record
                            break;
                        }
                    }
                }
                Err(_) => {
                    // Checksum mismatch
                    break;
                }
            }
        }

        RecordScanResult {
            valid_records,
            consumed_bytes,
        }
    }

    /// Read a segment and return only records whose LSN is strictly greater
    /// than min_lsn.
    ///
    /// This is a convenience wrapper around read_segment for crash
    /// recovery replay. Records at or below min_lsn are already reflected
    /// in the committed state and are skipped.
    ///
    /// # Returns
    ///
    /// - FilteredReadResult::Records if at least one record met the
    ///   threshold. The header is always included for diagnostic use.
    /// - FilteredReadResult::AllFiltered if the segment was valid but
    ///   all records were at or below the threshold.
    /// - FilteredReadResult::Corrupt if the segment cannot be read.
    pub fn read_since(data: &[u8], min_lsn: u64) -> FilteredReadResult {
        let result = Self::read_segment(data);
        match result {
            SegmentReadResult::Complete {
                header, records, ..
            } => Self::filter_records(header, records, min_lsn),
            SegmentReadResult::Truncated {
                header,
                valid_records,
            } => Self::filter_records(header, valid_records, min_lsn),
            SegmentReadResult::Corrupt => FilteredReadResult::Corrupt,
        }
    }

    /// Filter a flat list of segment records by LSN threshold.
    fn filter_records(
        header: SegmentHeader,
        records: Vec<SegmentRecord>,
        min_lsn: u64,
    ) -> FilteredReadResult {
        let mut filtered = Vec::with_capacity(records.len());
        let mut any_above = false;
        for rec in records {
            if rec.lsn > min_lsn {
                any_above = true;
                filtered.push(rec);
            }
        }
        if any_above {
            FilteredReadResult::Records {
                header,
                records: filtered,
            }
        } else {
            FilteredReadResult::AllFiltered { header }
        }
    }

    /// Scan records from the payload area using the footer index for
    /// efficient random access.
    ///
    /// This is the preferred method when the footer is available.
    pub fn scan_records_by_index(
        data: &[u8],
        index: &[RecordIndexEntry],
    ) -> Result<Vec<SegmentRecord>, IntentLogError> {
        let mut records = Vec::with_capacity(index.len());
        for entry in index {
            let start = entry.offset as usize;
            let end = start + entry.length as usize;
            if end > data.len() {
                return Err(IntentLogError::BufferTooShort);
            }
            let record_data = &data[start..end];
            match decode_record_entry(record_data)? {
                Some((record_type, payload)) => {
                    let record = IntentLogRecord::decode(&payload)?;
                    records.push(SegmentRecord {
                        lsn: entry.lsn,
                        record_type,
                        record,
                    });
                }
                None => {
                    return Err(IntentLogError::BufferTooShort);
                }
            }
        }
        Ok(records)
    }
}

struct RecordScanResult {
    valid_records: Vec<SegmentRecord>,
    consumed_bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::IntentLogWriter;
    use crate::{IntentLogFrame, IntentLogRecord};

    fn make_frame(seq: u64, ino: u64) -> IntentLogFrame {
        let rec = IntentLogRecord::Write {
            ino,
            offset: seq * 4096,
            length: seq * 4096,
            data_hash: [0xAA; 32],
        };
        IntentLogFrame::new(rec, 1, seq)
    }

    #[test]
    fn read_complete_segment() {
        let mut writer = IntentLogWriter::new(1024 * 1024);
        for i in 0..3 {
            writer.append_frame(&make_frame(i, i + 100)).unwrap();
        }
        let sealed = writer.finish().unwrap().unwrap();

        let result = IntentLogReader::read_segment(&sealed);
        match result {
            SegmentReadResult::Complete {
                header,
                records,
                footer,
            } => {
                assert_eq!(header.record_count, 3);
                assert_eq!(records.len(), 3);
                assert_eq!(footer.record_index.len(), 3);
                assert_eq!(records[0].lsn, 0);
                assert_eq!(records[2].lsn, 2);
            }
            _ => panic!("expected Complete, got {result:?}"),
        }
    }

    #[test]
    fn read_truncated_segment() {
        let mut writer = IntentLogWriter::new(1024 * 1024);
        for i in 0..3 {
            writer.append_frame(&make_frame(i, i + 100)).unwrap();
        }
        let mut sealed = writer.finish().unwrap().unwrap();

        // Simulate crash: truncate before the footer
        let trailer_start = sealed.len() - 64; // roughly footer size
        sealed.truncate(trailer_start);

        let result = IntentLogReader::read_segment(&sealed);
        match result {
            SegmentReadResult::Truncated {
                header,
                valid_records,
            } => {
                assert_eq!(header.record_count, 3);
                // All records should be valid since we only truncated the footer
                assert_eq!(valid_records.len(), 3);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn read_corrupt_header() {
        let data = vec![0xFF; 128];
        let result = IntentLogReader::read_segment(&data);
        assert!(matches!(result, SegmentReadResult::Corrupt));
    }

    #[test]
    fn read_empty_segment() {
        let mut writer = IntentLogWriter::new(1024 * 1024);
        let sealed = writer.finish().unwrap();
        assert!(sealed.is_none(), "no records should mean no segment");
    }

    #[test]
    fn read_truncated_mid_record() {
        let mut writer = IntentLogWriter::new(1024 * 1024);
        for i in 0..3 {
            writer.append_frame(&make_frame(i, i + 100)).unwrap();
        }
        let mut sealed = writer.finish().unwrap().unwrap();

        // Truncate mid-way through the last record
        // Truncate mid-way: leave header + 2 full records + 5 bytes of 3rd record
        let record_size = 37 + make_frame(0, 100).record.encode().len();
        let truncate_at = SEGMENT_HEADER_SIZE + 2 * record_size + 5;
        sealed.truncate(truncate_at);

        let result = IntentLogReader::read_segment(&sealed);
        match result {
            SegmentReadResult::Truncated { valid_records, .. } => {
                assert!(valid_records.len() < 3, "last record should be lost");
            }
            _ => panic!("expected Truncated"),
        }
    }

    #[test]
    fn read_then_replay_records_match_original() {
        let mut writer = IntentLogWriter::new(1024 * 1024);
        let frames: Vec<IntentLogFrame> = (0..5).map(|i| make_frame(i, i + 100)).collect();
        for f in &frames {
            writer.append_frame(f).unwrap();
        }
        let sealed = writer.finish().unwrap().unwrap();

        let result = IntentLogReader::read_segment(&sealed);
        match result {
            SegmentReadResult::Complete { records, .. } => {
                assert_eq!(records.len(), frames.len());
                for (seg_rec, frame) in records.iter().zip(frames.iter()) {
                    assert_eq!(seg_rec.record, frame.record);
                }
            }
            _ => panic!("expected Complete"),
        }
    }

    #[test]
    fn read_since_filters_lsns() {
        let mut writer = IntentLogWriter::new(1024 * 1024);
        for i in 0..5 {
            writer.append_frame(&make_frame(i, i + 100)).unwrap();
        }
        let sealed = writer.finish().unwrap().unwrap();

        let result = IntentLogReader::read_since(&sealed, 2);
        match result {
            FilteredReadResult::Records { header, records } => {
                assert_eq!(header.record_count, 5);
                assert_eq!(records.len(), 2);
                assert_eq!(records[0].lsn, 3);
                assert_eq!(records[1].lsn, 4);
            }
            other => panic!("expected Records, got {other:?}"),
        }
    }

    #[test]
    fn read_since_all_filtered() {
        let mut writer = IntentLogWriter::new(1024 * 1024);
        for i in 0..3 {
            writer.append_frame(&make_frame(i, i + 100)).unwrap();
        }
        let sealed = writer.finish().unwrap().unwrap();

        let result = IntentLogReader::read_since(&sealed, 10);
        match result {
            FilteredReadResult::AllFiltered { header } => {
                assert_eq!(header.record_count, 3);
            }
            other => panic!("expected AllFiltered, got {other:?}"),
        }
    }

    #[test]
    fn read_since_min_lsn_zero_returns_records() {
        let mut writer = IntentLogWriter::new(1024 * 1024);
        for i in 0..4 {
            writer.append_frame(&make_frame(i, i + 100)).unwrap();
        }
        let sealed = writer.finish().unwrap().unwrap();

        let result = IntentLogReader::read_since(&sealed, 0);
        match result {
            FilteredReadResult::Records { records, .. } => {
                assert_eq!(records.len(), 3);
                assert_eq!(records[0].lsn, 1);
            }
            other => panic!("expected Records, got {other:?}"),
        }
    }

    #[test]
    fn read_since_truncated_segment_filters() {
        let mut writer = IntentLogWriter::new(1024 * 1024);
        for i in 0..5 {
            writer.append_frame(&make_frame(i, i + 100)).unwrap();
        }
        let mut sealed = writer.finish().unwrap().unwrap();
        sealed.truncate(sealed.len() - 64);

        let result = IntentLogReader::read_since(&sealed, 2);
        match result {
            FilteredReadResult::Records { records, .. } => {
                assert!(records.iter().all(|r| r.lsn > 2));
            }
            other => panic!("expected Records from truncated segment, got {other:?}"),
        }
    }

    #[test]
    fn scan_by_index_matches_sequential_scan() {
        let mut writer = IntentLogWriter::new(1024 * 1024);
        for i in 0..5 {
            writer.append_frame(&make_frame(i, i + 100)).unwrap();
        }
        let sealed = writer.finish().unwrap().unwrap();

        let header = SegmentHeader::decode(&sealed[..SEGMENT_HEADER_SIZE]).unwrap();
        let result = IntentLogReader::read_segment(&sealed);

        match result {
            SegmentReadResult::Complete { footer, .. } => {
                let by_index =
                    IntentLogReader::scan_records_by_index(&sealed, &footer.record_index).unwrap();

                // Sequential scan
                let mut seq_records = Vec::new();
                let mut pos = SEGMENT_HEADER_SIZE;
                for _ in 0..header.record_count {
                    let (rtype, payload, consumed) =
                        crate::segment::try_decode_record_entry(&sealed[pos..]).unwrap();
                    if consumed == 0 {
                        break;
                    }
                    let record = IntentLogRecord::decode(&payload).unwrap();
                    seq_records.push(SegmentRecord {
                        lsn: seq_records.len() as u64,
                        record_type: rtype,
                        record,
                    });
                    pos += consumed;
                }

                assert_eq!(by_index.len(), seq_records.len());
                for (a, b) in by_index.iter().zip(seq_records.iter()) {
                    assert_eq!(a.record, b.record);
                }
            }
            _ => panic!("expected Complete"),
        }
    }
}
