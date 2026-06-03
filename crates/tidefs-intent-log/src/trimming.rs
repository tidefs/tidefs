//! Intent-log segment trimming after TXG commit.
//!
//! After a transaction group commits, log segments whose entire LSN range
//! falls below the committed LSN are no longer needed for crash recovery
//! and can be deleted. This module provides the logic to identify which
//! segments are eligible for trimming.
//!
//! The caller is responsible for the actual file deletion; this module
//! only determines eligibility.

use crate::segment::SegmentHeader;

/// Returns the indices of segments that can be trimmed (deleted) because
/// their entire LSN range is below `committed_lsn`.
///
/// A segment is eligible when `segment_lsn_end > 0` (sealed) and
/// `segment_lsn_end < committed_lsn`. Open (unsealed) segments where
/// `segment_lsn_end == 0` are never eligible because they may still
/// receive records.
///
/// The returned indices refer to `segments` in input order, which should
/// be sorted by `segment_lsn_start` ascending.
pub fn segments_to_trim(segments: &[SegmentHeader], committed_lsn: u64) -> Vec<usize> {
    segments
        .iter()
        .enumerate()
        .filter_map(|(i, hdr)| {
            // Sealed segment whose entire LSN range is below committed_lsn
            if hdr.segment_lsn_end > 0 && hdr.segment_lsn_end < committed_lsn {
                Some(i)
            } else {
                None
            }
        })
        .collect()
}

/// Returns the LSN of the oldest record that must be retained.
///
/// This is `min(segment_lsn_start)` across all non-trimmable segments.
/// If all segments are trimmable, returns `committed_lsn` (nothing to
/// retain).
pub fn earliest_retained_lsn(segments: &[SegmentHeader], committed_lsn: u64) -> u64 {
    segments
        .iter()
        .filter(|hdr| hdr.segment_lsn_end == 0 || hdr.segment_lsn_end >= committed_lsn)
        .map(|hdr| hdr.segment_lsn_start)
        .min()
        .unwrap_or(committed_lsn)
}

/// Returns true if the segment is sealed (has `segment_lsn_end > 0`).
pub fn is_sealed(header: &SegmentHeader) -> bool {
    header.segment_lsn_end > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::SEGMENT_MAGIC;
    use crate::segment::SEGMENT_VERSION;

    fn make_header(lsn_start: u64, lsn_end: u64, record_count: u32) -> SegmentHeader {
        SegmentHeader {
            magic: SEGMENT_MAGIC,
            version: SEGMENT_VERSION,
            segment_lsn_start: lsn_start,
            segment_lsn_end: lsn_end,
            record_count,
        }
    }

    #[test]
    fn trim_all_sealed_below_committed() {
        let segments = vec![
            make_header(0, 9, 10),
            make_header(10, 19, 10),
            make_header(20, 29, 10),
        ];
        let to_trim = segments_to_trim(&segments, 30);
        assert_eq!(to_trim, vec![0, 1, 2]);
    }

    #[test]
    fn trim_none_below_committed() {
        let segments = vec![make_header(0, 9, 10), make_header(10, 19, 10)];
        let to_trim = segments_to_trim(&segments, 5);
        assert!(to_trim.is_empty());
    }

    #[test]
    fn trim_partial() {
        let segments = vec![
            make_header(0, 9, 10),
            make_header(10, 19, 10),
            make_header(20, 29, 10),
        ];
        let to_trim = segments_to_trim(&segments, 15);
        assert_eq!(to_trim, vec![0]); // only first segment fully below 15
    }

    #[test]
    fn open_segment_never_trimmed() {
        let segments = vec![
            make_header(0, 9, 10),   // sealed
            make_header(10, 0, 5),   // open (lsn_end == 0)
            make_header(20, 29, 10), // sealed
        ];
        let to_trim = segments_to_trim(&segments, 30);
        // Open segment is not trimmed even though committed_lsn > 10
        assert_eq!(to_trim, vec![0, 2]);
    }

    #[test]
    fn earliest_retained_lsn_with_open_segment() {
        let segments = vec![
            make_header(0, 9, 10),
            make_header(10, 0, 5), // open
            make_header(20, 29, 10),
        ];
        let earliest = earliest_retained_lsn(&segments, 30);
        // Open segment starts at 10, sealed at 20; min is 10
        assert_eq!(earliest, 10);
    }

    #[test]
    fn earliest_retained_lsn_all_trimmable() {
        let segments = vec![make_header(0, 9, 10), make_header(10, 19, 10)];
        let earliest = earliest_retained_lsn(&segments, 20);
        assert_eq!(earliest, 20); // falls back to committed_lsn
    }

    #[test]
    fn is_sealed_detects_open() {
        let sealed = make_header(0, 10, 5);
        let open = make_header(10, 0, 5);
        assert!(is_sealed(&sealed));
        assert!(!is_sealed(&open));
    }
}
