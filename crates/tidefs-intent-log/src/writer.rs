//! Intent-log segment writer with automatic rotation.
//!
//! [`IntentLogWriter`] accepts intent-log frames, encodes them into the
//! on-disk segment format, and automatically rotates to a new segment when
//! the configured maximum segment size is reached. The caller is responsible
//! for writing the returned segment bytes to durable storage.
//!
//! # Example
//!
//! ```ignore
//! let mut writer = IntentLogWriter::new(64 * 1024 * 1024);
//! for frame in frames {
//!     // Append the frame; writer auto-rotates when full
//!     if let Some(sealed_segment) = writer.append_frame(&frame).unwrap() {
//!         // Write sealed_segment to disk and fsync
//!     }
//! }
//! // Flush final partial segment
//! if let Some(final_segment) = writer.finish().unwrap() {
//!     // Write final_segment to disk and fsync
//! }
//! ```

use crate::segment::{
    encode_record_entry, record_entry_size, RecordIndexEntry, SegmentFooter, SegmentHeader,
    SEGMENT_HEADER_SIZE, SEGMENT_MAGIC, SEGMENT_VERSION,
};
use crate::{IntentLogError, IntentLogFrame};

/// Default maximum segment size (64 MiB).
pub const DEFAULT_MAX_SEGMENT_SIZE: u64 = crate::segment::DEFAULT_MAX_SEGMENT_SIZE;

/// Minimum viable segment size: header (64) + 1 minimal record (37) +
/// minimal footer (4 + 32 = 36) + room for 1 index entry (20) = 157.
/// Safety margin: 1024 bytes.
const MIN_SEGMENT_SIZE: u64 = 256;

/// A writer that appends intent-log frames to an on-disk segment,
/// automatically rotating when the segment reaches the configured maximum
/// size.
pub struct IntentLogWriter {
    max_segment_size: u64,
    /// Current segment buffer under construction.
    buf: Vec<u8>,
    /// LSN of the first record in the current segment.
    lsn_start: u64,
    /// LSN of the most recently appended record.
    lsn_end: u64,
    /// Number of records in the current segment.
    record_count: u32,
    /// Accumulated record index for the footer.
    index: Vec<RecordIndexEntry>,
    /// Whether any records have been written to the current segment.
    has_records: bool,
}

impl IntentLogWriter {
    /// Create a new writer that rotates segments at `max_segment_size`
    /// bytes.
    ///
    /// Panics if `max_segment_size` is less than [`MIN_SEGMENT_SIZE`].
    pub fn new(max_segment_size: u64) -> Self {
        assert!(
            max_segment_size >= MIN_SEGMENT_SIZE,
            "max_segment_size {max_segment_size} must be at least {MIN_SEGMENT_SIZE}"
        );
        Self {
            max_segment_size,
            buf: Vec::new(),
            lsn_start: 0,
            lsn_end: 0,
            record_count: 0,
            index: Vec::new(),
            has_records: false,
        }
    }

    /// Return the maximum segment size in bytes.
    pub fn max_segment_size(&self) -> u64 {
        self.max_segment_size
    }

    /// Return the number of records in the current (unsealed) segment.
    pub fn current_record_count(&self) -> u32 {
        self.record_count
    }

    /// Return the current segment byte size (including header reservation
    /// but excluding footer, which hasn't been written yet).
    pub fn current_segment_size(&self) -> u64 {
        if !self.has_records {
            0
        } else {
            self.buf.len() as u64
        }
    }

    /// Append a raw record to the segment.
    ///
    /// `lsn` is the global log sequence number for this record.
    /// `record_type` is the record discriminant byte.
    /// `payload` is the serialized record body.
    ///
    /// Returns `Ok(Some(sealed_segment_bytes))` if the current segment was
    /// sealed and a new one started. Returns `Ok(None)` if the record was
    /// appended without rotation.
    pub fn append(
        &mut self,
        lsn: u64,
        record_type: u8,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, IntentLogError> {
        let entry_size = record_entry_size(payload.len()) as u64;

        // Estimate footer size: 4 bytes count + N index entries + 32 checksum
        let future_footer_size = 4 + (self.index.len() as u64 + 1) * 20 + 32;

        // Check if this record would exceed max_segment_size
        if self.has_records
            && self.buf.len() as u64 + entry_size + future_footer_size > self.max_segment_size
        {
            // Seal current segment and start a new one
            let sealed = self.seal()?;
            self.start_new_segment(lsn);
            self.append_record(lsn, record_type, payload);
            Ok(Some(sealed))
        } else {
            if !self.has_records {
                self.start_new_segment(lsn);
            }
            self.append_record(lsn, record_type, payload);
            Ok(None)
        }
    }

    /// Append an [`IntentLogFrame`] to the segment.
    ///
    /// Convenience wrapper around [`append`]. Uses `frame.record_seq` as
    /// the LSN and the encoded record bytes as the payload.
    pub fn append_frame(
        &mut self,
        frame: &IntentLogFrame,
    ) -> Result<Option<Vec<u8>>, IntentLogError> {
        let payload = frame.record.encode();
        let record_type = if payload.is_empty() { 0 } else { payload[0] };
        self.append(frame.record_seq, record_type, &payload)
    }

    /// Seal and return the current segment, even if it's below
    /// `max_segment_size`.
    ///
    /// Returns `None` if no records have been written.
    pub fn finish(&mut self) -> Result<Option<Vec<u8>>, IntentLogError> {
        if !self.has_records {
            return Ok(None);
        }
        Ok(Some(self.seal()?))
    }

    /// Seals and returns the current segment, updating the header with
    /// final LSN range and record count, writing the footer, and computing
    /// all checksums.
    ///
    /// After this call, the writer is ready to start a new segment on the
    /// next `append`.
    fn seal(&mut self) -> Result<Vec<u8>, IntentLogError> {
        debug_assert!(self.has_records, "seal called with no records");
        debug_assert_eq!(
            self.record_count as usize,
            self.index.len(),
            "record_count mismatch"
        );

        // Build footer
        let footer = SegmentFooter {
            record_index: std::mem::take(&mut self.index),
        };
        let footer_bytes = footer.encode();

        // Update header fields
        let header = SegmentHeader {
            magic: SEGMENT_MAGIC,
            version: SEGMENT_VERSION,
            segment_lsn_start: self.lsn_start,
            segment_lsn_end: self.lsn_end,
            record_count: self.record_count,
        };
        let header_encoded = header.encode();

        // Write header and footer into the buffer
        self.buf[..SEGMENT_HEADER_SIZE].copy_from_slice(&header_encoded);
        self.buf.extend_from_slice(&footer_bytes);

        // Reset state
        self.has_records = false;
        self.record_count = 0;
        self.lsn_start = 0;
        self.lsn_end = 0;

        Ok(std::mem::take(&mut self.buf))
    }

    /// Initialize a new segment buffer with a zeroed header placeholder.
    fn start_new_segment(&mut self, first_lsn: u64) {
        debug_assert!(
            !self.has_records,
            "start_new_segment called with active segment"
        );

        self.buf = vec![0u8; SEGMENT_HEADER_SIZE];
        self.lsn_start = first_lsn;
        self.lsn_end = first_lsn;
        self.has_records = true;
    }

    /// Append a single record to the in-progress segment.
    fn append_record(&mut self, lsn: u64, record_type: u8, payload: &[u8]) {
        let offset = self.buf.len() as u64;
        let entry = encode_record_entry(record_type, payload);
        let entry_len = entry.len() as u32;

        self.buf.extend_from_slice(&entry);

        self.index.push(RecordIndexEntry {
            lsn,
            offset,
            length: entry_len,
        });

        self.lsn_end = lsn;
        self.record_count += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IntentLogRecord;

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
    fn single_record_in_segment() {
        let mut writer = IntentLogWriter::new(1024 * 1024);
        let frame = make_frame(0, 42);
        let result = writer.append_frame(&frame).unwrap();
        assert!(result.is_none(), "single record shouldn't trigger rotation");

        let sealed = writer.finish().unwrap().unwrap();
        // Should have header + record + footer
        assert!(sealed.len() >= SEGMENT_HEADER_SIZE + 37 + 36);

        // Validate header
        let header = SegmentHeader::decode(&sealed[..SEGMENT_HEADER_SIZE]).unwrap();
        assert_eq!(header.magic, SEGMENT_MAGIC);
        assert_eq!(header.version, SEGMENT_VERSION);
        assert_eq!(header.segment_lsn_start, 0);
        assert_eq!(header.segment_lsn_end, 0);
        assert_eq!(header.record_count, 1);
    }

    #[test]
    fn multiple_records_in_segment() {
        let mut writer = IntentLogWriter::new(1024 * 1024);
        for i in 0..5 {
            let frame = make_frame(i, i + 100);
            let result = writer.append_frame(&frame).unwrap();
            assert!(result.is_none());
        }

        let sealed = writer.finish().unwrap().unwrap();
        let header = SegmentHeader::decode(&sealed[..SEGMENT_HEADER_SIZE]).unwrap();
        assert_eq!(header.record_count, 5);
        assert_eq!(header.segment_lsn_start, 0);
        assert_eq!(header.segment_lsn_end, 4);
    }

    #[test]
    fn rotation_when_segment_full() {
        // Use a tiny max size to force rotation after ~2 records
        let record_size = record_entry_size(
            IntentLogRecord::Write {
                ino: 1,
                offset: 0,
                length: 0,
                data_hash: [0xAA; 32],
            }
            .encode()
            .len(),
        ) as u64;
        let footer_size = |n: u64| -> u64 { 4 + n * 20 + 32 };
        // Set max to hold exactly 2 records + footer
        let max_size = SEGMENT_HEADER_SIZE as u64 + 2 * record_size + footer_size(2);

        let mut writer = IntentLogWriter::new(max_size);
        let frame0 = make_frame(0, 1);
        let result = writer.append_frame(&frame0).unwrap();
        assert!(result.is_none());

        let frame1 = make_frame(1, 2);
        let result = writer.append_frame(&frame1).unwrap();
        assert!(result.is_none());

        // Third record should trigger rotation
        let frame2 = make_frame(2, 3);
        let result = writer.append_frame(&frame2).unwrap();
        assert!(result.is_some(), "third record should trigger rotation");

        let sealed1 = result.unwrap();
        let hdr1 = SegmentHeader::decode(&sealed1[..SEGMENT_HEADER_SIZE]).unwrap();
        assert_eq!(hdr1.record_count, 2);
        assert_eq!(hdr1.segment_lsn_start, 0);
        assert_eq!(hdr1.segment_lsn_end, 1);

        // The new segment should have the third record
        let sealed2 = writer.finish().unwrap().unwrap();
        let hdr2 = SegmentHeader::decode(&sealed2[..SEGMENT_HEADER_SIZE]).unwrap();
        assert_eq!(hdr2.record_count, 1);
        assert_eq!(hdr2.segment_lsn_start, 2);
        assert_eq!(hdr2.segment_lsn_end, 2);
    }

    #[test]
    fn finish_empty_writer_returns_none() {
        let mut writer = IntentLogWriter::new(1024 * 1024);
        assert!(writer.finish().unwrap().is_none());
    }

    #[test]
    fn record_checksums_are_valid() {
        let mut writer = IntentLogWriter::new(1024 * 1024);
        let frame = make_frame(0, 42);
        writer.append_frame(&frame).unwrap();
        let sealed = writer.finish().unwrap().unwrap();

        // Parse the segment and verify every record checksum
        let header = SegmentHeader::decode(&sealed[..SEGMENT_HEADER_SIZE]).unwrap();
        let mut offset = SEGMENT_HEADER_SIZE;

        for _ in 0..header.record_count {
            let (_rtype, _payload, consumed) =
                crate::segment::try_decode_record_entry(&sealed[offset..]).unwrap();
            assert!(consumed > 0, "record at offset {offset} should be valid");
            offset += consumed;
        }
    }

    #[test]
    fn large_record_near_segment_limit() {
        // Create a record that nearly fills the segment
        let large_payload = vec![0xBB; 4000];
        let record_overhead = record_entry_size(0) as u64; // 37
        let required = SEGMENT_HEADER_SIZE as u64 + record_overhead + 4000 + 4 + 20 + 32;
        let mut writer = IntentLogWriter::new(required);

        let rec = IntentLogRecord::Setattr {
            ino: 1,
            attr_mask: 0,
            attrs: [0; 64],
        };
        let _frame = IntentLogFrame::new(rec, 1, 0);

        // We can't use append_frame easily with a large payload since the
        // existing record types have fixed sizes. Use raw append.
        writer.append(0, 1, &large_payload).unwrap();
        let sealed = writer.finish().unwrap().unwrap();

        let header = SegmentHeader::decode(&sealed[..SEGMENT_HEADER_SIZE]).unwrap();
        assert_eq!(header.record_count, 1);
        assert_eq!(header.segment_lsn_start, 0);
        assert_eq!(header.segment_lsn_end, 0);
    }

    #[test]
    fn sealed_segment_footer_has_correct_index() {
        let mut writer = IntentLogWriter::new(1024 * 1024);
        for i in 0..3 {
            let frame = make_frame(i, i + 100);
            writer.append_frame(&frame).unwrap();
        }
        let sealed = writer.finish().unwrap().unwrap();

        // Parse footer
        let header = SegmentHeader::decode(&sealed[..SEGMENT_HEADER_SIZE]).unwrap();
        let records_end = {
            let mut pos = SEGMENT_HEADER_SIZE;
            for _ in 0..header.record_count {
                let (_, _, consumed) =
                    crate::segment::try_decode_record_entry(&sealed[pos..]).unwrap();
                pos += consumed;
            }
            pos
        };
        let footer = SegmentFooter::decode(&sealed[records_end..]).unwrap();
        assert_eq!(footer.record_index.len(), 3);
        assert_eq!(footer.record_index[0].lsn, 0);
        assert_eq!(footer.record_index[2].lsn, 2);
        // Each offset should be at least SEGMENT_HEADER_SIZE
        for entry in &footer.record_index {
            assert!(entry.offset >= SEGMENT_HEADER_SIZE as u64);
        }
    }
}
