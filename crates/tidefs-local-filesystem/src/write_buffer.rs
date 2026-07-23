// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::BTreeMap;
use std::ops::Bound;
use std::ops::Bound::{Excluded, Included, Unbounded};

/// Configuration for the write-buffer coalescing byte threshold.
#[derive(Debug, Clone)]
pub struct WriteBufferConfig {
    /// Flush foreground writes when total accumulated dirty bytes reaches this limit.
    pub flush_threshold_bytes: usize,
}

impl Default for WriteBufferConfig {
    fn default() -> Self {
        Self {
            flush_threshold_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Per-inode write coalescing buffer.
///
/// Accumulates small sequential writes and flushes them in fewer,
/// larger object-store operations when a foreground byte-count threshold
/// is crossed. Read-your-writes is preserved by serving dirty segments
/// directly.
#[derive(Debug, Clone)]
pub struct WriteBuffer {
    config: WriteBufferConfig,
    segments: BTreeMap<u64, Vec<u8>>,
    total_bytes: usize,
}

impl WriteBuffer {
    pub fn new(config: WriteBufferConfig) -> Self {
        Self {
            config,
            segments: BTreeMap::new(),
            total_bytes: 0,
        }
    }

    fn segment_end(offset: u64, data: &[u8]) -> u64 {
        offset.saturating_add(data.len() as u64)
    }

    fn first_segment_start_ending_at_or_after(&self, offset: u64) -> u64 {
        self.segments
            .range(..=offset)
            .next_back()
            .and_then(|(&start, data)| (Self::segment_end(start, data) >= offset).then_some(start))
            .unwrap_or(offset)
    }

    fn first_segment_start_ending_after(&self, offset: u64) -> u64 {
        self.segments
            .range(..=offset)
            .next_back()
            .and_then(|(&start, data)| (Self::segment_end(start, data) > offset).then_some(start))
            .unwrap_or(offset)
    }

    /// Ingest a write at the given byte offset.
    ///
    /// Contiguous or overlapping writes are merged into sorted dirty segments.
    /// Newer bytes overwrite older buffered bytes in the overlapping range.
    /// Zero-length writes are ignored.
    pub fn ingest(&mut self, buf: &[u8], offset: u64) -> usize {
        if buf.is_empty() {
            return 0;
        }

        let before_total = self.total_bytes;
        let write_end = offset.saturating_add(buf.len() as u64);
        let scan_start = self.first_segment_start_ending_at_or_after(offset);
        let mut merged_start = offset;
        let mut merged_end = write_end;
        let mut candidate_starts = Vec::new();
        let mut next_bound: Bound<u64> = Included(scan_start);

        loop {
            let next = self
                .segments
                .range((next_bound, Unbounded))
                .next()
                .map(|(&start, data)| (start, Self::segment_end(start, data)));
            let Some((segment_start, segment_end)) = next else {
                break;
            };
            if segment_start > merged_end {
                break;
            }

            candidate_starts.push(segment_start);
            merged_start = merged_start.min(segment_start);
            merged_end = merged_end.max(segment_end);
            next_bound = Excluded(segment_start);
        }

        if candidate_starts.is_empty() {
            self.segments.insert(offset, buf.to_vec());
            self.total_bytes = self.total_bytes.saturating_add(buf.len());
            return self.total_bytes.saturating_sub(before_total);
        }

        if candidate_starts.len() == 1 {
            let segment_start = candidate_starts[0];
            if segment_start <= offset {
                if let Some(data) = self.segments.get_mut(&segment_start) {
                    let segment_end = Self::segment_end(segment_start, data);
                    if offset <= segment_end {
                        let dst = (offset - segment_start) as usize;
                        let overlap_len = data.len().saturating_sub(dst).min(buf.len());
                        if overlap_len > 0 {
                            data[dst..dst + overlap_len].copy_from_slice(&buf[..overlap_len]);
                        }
                        if overlap_len < buf.len() {
                            let tail = &buf[overlap_len..];
                            data.extend_from_slice(tail);
                            self.total_bytes = self.total_bytes.saturating_add(tail.len());
                        }
                        return self.total_bytes.saturating_sub(before_total);
                    }
                }
            }
        }

        let merged_len = (merged_end - merged_start) as usize;
        let mut merged = vec![0_u8; merged_len];

        for segment_start in candidate_starts {
            let Some(data) = self.segments.remove(&segment_start) else {
                continue;
            };
            self.total_bytes = self.total_bytes.saturating_sub(data.len());
            let dst = (segment_start - merged_start) as usize;
            let dst_end = dst.saturating_add(data.len());
            merged[dst..dst_end].copy_from_slice(&data);
        }

        let write_dst = (offset - merged_start) as usize;
        merged[write_dst..write_dst + buf.len()].copy_from_slice(buf);
        self.total_bytes = self.total_bytes.saturating_add(merged.len());
        self.segments.insert(merged_start, merged);
        self.total_bytes.saturating_sub(before_total)
    }

    /// Return subranges of `[offset, offset + length)` not already dirty.
    pub(crate) fn unbuffered_ranges(&self, offset: u64, length: u64) -> Vec<(u64, u64)> {
        if length == 0 {
            return Vec::new();
        }

        let end = offset.saturating_add(length);
        let mut cursor = offset;
        let mut ranges = Vec::new();
        let start = self.first_segment_start_ending_after(offset);

        for (&segment_start, data) in self.segments.range(start..) {
            if cursor >= end || segment_start >= end {
                break;
            }
            let segment_end = Self::segment_end(segment_start, data);
            if segment_end <= cursor {
                continue;
            }

            if segment_start > cursor {
                let gap_end = segment_start.min(end);
                ranges.push((cursor, gap_end - cursor));
                cursor = gap_end;
            }
            cursor = cursor.max(segment_end.min(end));
        }

        if cursor < end {
            ranges.push((cursor, end - cursor));
        }
        ranges
    }

    /// Returns `true` when the foreground byte-count threshold is crossed.
    pub fn should_flush(&self) -> bool {
        !self.is_empty() && self.total_bytes >= self.config.flush_threshold_bytes
    }

    /// True when no dirty data is buffered.
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Total unique buffered dirty bytes.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.total_bytes
    }

    /// Total unique buffered dirty bytes.
    pub(crate) fn buffered_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Return the highest byte offset covered by any buffered segment
    /// (offset + length). Returns `None` when the buffer is empty.
    pub fn max_offset(&self) -> Option<u64> {
        self.segments
            .iter()
            .map(|(&offset, data)| Self::segment_end(offset, data))
            .max()
    }

    /// Drain all segments, returning `(offset, data)` pairs and resetting
    /// internal state.
    pub fn drain(&mut self) -> Vec<(u64, Vec<u8>)> {
        let result: Vec<_> = std::mem::take(&mut self.segments).into_iter().collect();
        self.total_bytes = 0;
        result
    }

    /// Drain one foreground writeback batch, leaving later dirty segments buffered.
    ///
    /// This is used by byte-threshold flushes. Explicit fences still use
    /// [`WriteBuffer::drain`] so fsync/truncate/unmount publish all pending bytes.
    pub fn drain_flush_batch(&mut self) -> Vec<(u64, Vec<u8>)> {
        if self.segments.is_empty() {
            return Vec::new();
        }

        let mut remaining = self.config.flush_threshold_bytes;
        if remaining == 0 {
            return self.drain();
        }

        let mut drained = Vec::new();
        while remaining > 0 && !self.segments.is_empty() {
            let Some((&offset, _)) = self.segments.iter().next() else {
                break;
            };
            let mut data = self
                .segments
                .remove(&offset)
                .expect("first segment key was present");
            if data.len() <= remaining {
                remaining -= data.len();
                self.total_bytes = self.total_bytes.saturating_sub(data.len());
                drained.push((offset, data));
                continue;
            }

            let split_len = remaining;
            let tail = data.split_off(split_len);
            let tail_offset = offset.saturating_add(split_len as u64);
            self.segments.insert(tail_offset, tail);
            self.total_bytes = self.total_bytes.saturating_sub(data.len());
            drained.push((offset, data));
            remaining = 0;
        }
        drained
    }

    /// Truncate buffered writes to at most `size` bytes.
    ///
    /// Removes segments whose offset is beyond `size`, and truncates any
    /// segment that straddles the size boundary.  Used by setattr(size)
    /// to prevent fsync from restoring data past a truncation point.
    pub fn truncate(&mut self, size: u64) -> usize {
        let before_total = self.total_bytes;
        self.segments.retain(|&offset, data| {
            if offset >= size {
                return false;
            }
            let seg_end = Self::segment_end(offset, data);
            if seg_end > size {
                let keep = (size - offset) as usize;
                data.truncate(keep);
            }
            true
        });
        self.total_bytes = self.segments.values().map(Vec::len).sum();
        before_total.saturating_sub(self.total_bytes)
    }

    /// Clear dirty bytes in `[offset, offset + length)`, preserving dirty
    /// prefix/suffix bytes that are outside the cleared range.
    pub fn clear_range(&mut self, offset: u64, length: u64) -> usize {
        if length == 0 || self.segments.is_empty() {
            return 0;
        }

        let end = offset.checked_add(length).unwrap_or(u64::MAX);
        let mut kept = BTreeMap::new();
        let mut cleared = 0usize;

        for (segment_start, data) in std::mem::take(&mut self.segments) {
            let segment_end = Self::segment_end(segment_start, &data);
            if segment_end <= offset || segment_start >= end {
                kept.insert(segment_start, data);
                continue;
            }

            let clear_start = segment_start.max(offset);
            let clear_end = segment_end.min(end);
            cleared = cleared.saturating_add((clear_end - clear_start) as usize);

            if segment_start < clear_start {
                let left_len = (clear_start - segment_start) as usize;
                kept.insert(segment_start, data[..left_len].to_vec());
            }

            if clear_end < segment_end {
                let right_start = (clear_end - segment_start) as usize;
                kept.insert(clear_end, data[right_start..].to_vec());
            }
        }

        self.segments = kept;
        self.total_bytes = self.segments.values().map(Vec::len).sum();
        cleared
    }

    /// Read buffered data overlapping `[read_offset, read_offset + read_len)`.
    ///
    /// Returns a byte vector covering the requested range. Gaps (ranges not
    /// covered by any segment) are filled with zeros. Returns `None` when
    /// no segment covers any part of the requested range.
    pub fn read_overlap(&self, read_offset: u64, read_len: usize) -> Option<Vec<u8>> {
        let read_end = read_offset.saturating_add(read_len as u64);
        let mut buf = vec![0u8; read_len];
        let mut any_hit = false;

        let start = self.first_segment_start_ending_after(read_offset);
        for (&segment_offset, data) in self.segments.range(start..) {
            if segment_offset >= read_end {
                break;
            }
            let seg_end = Self::segment_end(segment_offset, data);
            if segment_offset < read_end && seg_end > read_offset {
                any_hit = true;
                let copy_src_start = if segment_offset > read_offset {
                    0usize
                } else {
                    (read_offset - segment_offset) as usize
                };
                let copy_dst_start = if segment_offset > read_offset {
                    (segment_offset - read_offset) as usize
                } else {
                    0usize
                };
                let copy_src_end = if seg_end < read_end {
                    data.len()
                } else {
                    (read_end - segment_offset) as usize
                };
                let copy_len = copy_src_end - copy_src_start;
                let dst_slice = &mut buf[copy_dst_start..copy_dst_start + copy_len];
                dst_slice.copy_from_slice(&data[copy_src_start..copy_src_end]);
            }
        }

        if any_hit {
            Some(buf)
        } else {
            None
        }
    }

    /// Return true when any buffered segment intersects the requested range.
    pub fn overlaps_range(&self, read_offset: u64, read_len: u64) -> bool {
        if read_len == 0 {
            return false;
        }
        let read_end = read_offset.saturating_add(read_len);
        let start = self.first_segment_start_ending_after(read_offset);
        for (&segment_offset, data) in self.segments.range(start..) {
            if segment_offset >= read_end {
                return false;
            }
            let seg_end = Self::segment_end(segment_offset, data);
            if segment_offset < read_end && seg_end > read_offset {
                return true;
            }
        }
        false
    }

    /// Return true when dirty buffered bytes cover the whole requested range.
    pub fn contains_range(&self, read_offset: u64, read_len: u64) -> bool {
        if read_len == 0 {
            return true;
        }
        let Some(read_end) = read_offset.checked_add(read_len) else {
            return false;
        };
        let start = self.first_segment_start_ending_after(read_offset);
        let mut covered_until = read_offset;

        for (&segment_offset, data) in self.segments.range(start..) {
            if segment_offset > covered_until {
                return false;
            }
            let seg_end = Self::segment_end(segment_offset, data);
            if seg_end <= covered_until {
                continue;
            }
            covered_until = seg_end;
            if covered_until >= read_end {
                return true;
            }
        }

        false
    }

    /// Overlay dirty buffered bytes onto an existing read buffer.
    ///
    /// Returns `true` when at least one dirty segment intersected the requested
    /// range. Unlike `read_overlap`, this leaves non-dirty gaps untouched so
    /// callers can preserve bytes already loaded from the object store.
    pub fn overlay_range(&self, read_offset: u64, buf: &mut [u8]) -> bool {
        if buf.is_empty() {
            return false;
        }
        let read_end = read_offset.saturating_add(buf.len() as u64);
        let mut any_hit = false;

        let start = self.first_segment_start_ending_after(read_offset);
        for (&segment_offset, data) in self.segments.range(start..) {
            if segment_offset >= read_end {
                break;
            }
            let seg_end = Self::segment_end(segment_offset, data);
            if segment_offset < read_end && seg_end > read_offset {
                any_hit = true;
                let copy_src_start = if segment_offset > read_offset {
                    0usize
                } else {
                    (read_offset - segment_offset) as usize
                };
                let copy_dst_start = if segment_offset > read_offset {
                    (segment_offset - read_offset) as usize
                } else {
                    0usize
                };
                let copy_src_end = if seg_end < read_end {
                    data.len()
                } else {
                    (read_end - segment_offset) as usize
                };
                let copy_len = copy_src_end - copy_src_start;
                let dst_slice = &mut buf[copy_dst_start..copy_dst_start + copy_len];
                dst_slice.copy_from_slice(&data[copy_src_start..copy_src_end]);
            }
        }

        any_hit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> WriteBufferConfig {
        WriteBufferConfig {
            flush_threshold_bytes: 1024,
        }
    }

    #[test]
    fn default_threshold_matches_writeback_batch_policy() {
        let config = WriteBufferConfig::default();
        assert_eq!(config.flush_threshold_bytes, 8 * 1024 * 1024);
    }

    #[test]
    fn sequential_writes_coalesce_into_single_segment() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(b"hello ", 0);
        wb.ingest(b"world", 6);
        assert_eq!(wb.len(), 11);
        assert!(!wb.is_empty());

        let drained = wb.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, 0);
        assert_eq!(&drained[0].1, b"hello world");
        assert!(wb.is_empty());
        assert_eq!(wb.len(), 0);
    }

    #[test]
    fn single_write_below_threshold_no_flush() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(&[0u8; 512], 0);
        assert!(!wb.should_flush());
    }

    #[test]
    fn multiple_small_writes_below_threshold_no_flush() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(b"aaa", 0);
        wb.ingest(b"bbb", 3);
        wb.ingest(b"ccc", 6);
        assert_eq!(wb.len(), 9);
        assert!(!wb.should_flush());
    }

    #[test]
    fn byte_threshold_triggers_flush() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(&[0u8; 1023], 0);
        assert!(!wb.should_flush());
        wb.ingest(b"x", 1023);
        assert_eq!(wb.len(), 1024);
        assert!(wb.should_flush());
    }

    #[test]
    fn non_contiguous_writes_produce_separate_segments() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(b"aaaa", 0);
        wb.ingest(b"bbbb", 100);
        assert_eq!(wb.len(), 8);

        let drained = wb.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].0, 0);
        assert_eq!(&drained[0].1, b"aaaa");
        assert_eq!(drained[1].0, 100);
        assert_eq!(&drained[1].1, b"bbbb");
    }

    #[test]
    fn fragmented_sparse_writes_remain_sparse_and_ordered() {
        let mut wb = WriteBuffer::new(WriteBufferConfig {
            flush_threshold_bytes: 8 * 1024 * 1024,
        });
        let segment_count = 4096usize;
        let segment_len = 512usize;
        let stride = 4096u64;

        for index in (0..segment_count).rev() {
            let mut data = vec![0_u8; segment_len];
            data[..8].copy_from_slice(&(index as u64).to_le_bytes());
            wb.ingest(&data, index as u64 * stride);
        }

        assert_eq!(wb.len(), segment_count * segment_len);
        let drained = wb.drain();
        assert_eq!(drained.len(), segment_count);
        for (index, (offset, data)) in drained.iter().enumerate() {
            assert_eq!(*offset, index as u64 * stride);
            assert_eq!(data.len(), segment_len);
            assert_eq!(
                u64::from_le_bytes(data[..8].try_into().expect("marker width")),
                index as u64
            );
        }
    }

    #[test]
    fn gap_between_sequential_writes_splits_segments() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(b"first", 0);
        wb.ingest(b"second", 20);
        assert_eq!(wb.len(), 11);

        let drained = wb.drain();
        assert_eq!(drained.len(), 2);
    }

    #[test]
    fn overlapping_write_replaces_prior_bytes() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(b"hello", 0);
        wb.ingest(b"XX", 2);
        assert_eq!(wb.len(), 5);

        let drained = wb.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, 0);
        assert_eq!(&drained[0].1, b"heXXo");
    }

    #[test]
    fn clear_range_splits_overlapping_segment() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(b"abcdefghij", 10);

        assert_eq!(wb.clear_range(13, 4), 4);

        let drained = wb.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].0, 10);
        assert_eq!(&drained[0].1, b"abc");
        assert_eq!(drained[1].0, 17);
        assert_eq!(&drained[1].1, b"hij");
    }

    #[test]
    fn clear_range_removes_multiple_segments() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(b"aaaa", 0);
        wb.ingest(b"bbbb", 10);
        wb.ingest(b"cccc", 20);

        assert_eq!(wb.clear_range(8, 20), 8);

        let drained = wb.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, 0);
        assert_eq!(&drained[0].1, b"aaaa");
    }

    #[test]
    fn out_of_order_adjacent_writes_merge_sorted() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(b"BBBB", 8);
        wb.ingest(b"AAAA", 0);
        wb.ingest(b"CCCC", 4);

        let drained = wb.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, 0);
        assert_eq!(&drained[0].1, b"AAAACCCCBBBB");
    }

    #[test]
    fn sparse_markers_merge_with_full_page_writeback() {
        let mut wb = WriteBuffer::new(WriteBufferConfig {
            flush_threshold_bytes: 128 * 1024,
        });
        let page_size = 4096usize;
        let pages = 4usize;
        let pwrite_offset = 1024usize;
        let mmap_offset = 3072usize;
        let pwrite_marker = 0x1122_3344_5566_7788_u64.to_le_bytes();
        let mmap_marker = 0x8877_6655_4433_2211_u64.to_le_bytes();

        for page in 0..pages {
            let offset = (page * page_size + pwrite_offset) as u64;
            wb.ingest(&pwrite_marker, offset);
        }

        for page in 0..pages {
            let mut page_bytes = vec![0_u8; page_size];
            page_bytes[pwrite_offset..pwrite_offset + pwrite_marker.len()]
                .copy_from_slice(&pwrite_marker);
            page_bytes[mmap_offset..mmap_offset + mmap_marker.len()].copy_from_slice(&mmap_marker);
            wb.ingest(&page_bytes, (page * page_size) as u64);
        }

        assert_eq!(wb.len(), pages * page_size);
        let drained = wb.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, 0);
        assert_eq!(drained[0].1.len(), pages * page_size);
        for page in 0..pages {
            let base = page * page_size;
            assert_eq!(
                &drained[0].1[base + pwrite_offset..base + pwrite_offset + pwrite_marker.len()],
                &pwrite_marker
            );
            assert_eq!(
                &drained[0].1[base + mmap_offset..base + mmap_offset + mmap_marker.len()],
                &mmap_marker
            );
        }
    }

    #[test]
    fn batch_drain_leaves_future_sparse_markers_buffered() {
        let mut wb = WriteBuffer::new(WriteBufferConfig {
            flush_threshold_bytes: 8192,
        });
        let page_size = 4096usize;
        let pwrite_offset = 1024usize;
        let marker = 0xaabb_ccdd_eeff_0011_u64.to_le_bytes();

        for page in 0..4 {
            wb.ingest(&marker, (page * page_size + pwrite_offset) as u64);
        }
        for page in 0..2 {
            let mut page_bytes = vec![0_u8; page_size];
            page_bytes[pwrite_offset..pwrite_offset + marker.len()].copy_from_slice(&marker);
            wb.ingest(&page_bytes, (page * page_size) as u64);
        }

        assert!(wb.should_flush());
        let batch = wb.drain_flush_batch();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].0, 0);
        assert_eq!(batch[0].1.len(), 8192);
        assert_eq!(wb.len(), marker.len() * 2);

        let remaining = wb.drain();
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].0, (2 * page_size + pwrite_offset) as u64);
        assert_eq!(remaining[1].0, (3 * page_size + pwrite_offset) as u64);
    }

    #[test]
    fn batch_drain_splits_large_segment_at_threshold() {
        let mut wb = WriteBuffer::new(WriteBufferConfig {
            flush_threshold_bytes: 4,
        });

        wb.ingest(b"abcdefghij", 0);
        let batch = wb.drain_flush_batch();

        assert_eq!(batch, vec![(0, b"abcd".to_vec())]);
        assert_eq!(wb.len(), 6);
        assert_eq!(wb.drain(), vec![(4, b"efghij".to_vec())]);
    }

    #[test]
    fn empty_buffer_never_needs_flush() {
        let wb = WriteBuffer::new(test_config());
        assert!(!wb.should_flush());
    }

    #[test]
    fn drain_clears_state() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(b"data", 0);
        assert!(!wb.is_empty());
        assert_eq!(wb.len(), 4);

        let result = wb.drain();
        assert_eq!(result.len(), 1);

        assert!(wb.is_empty());
        assert_eq!(wb.len(), 0);
        assert!(!wb.should_flush());
    }

    #[test]
    fn drain_then_reingest_remains_below_byte_threshold() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(b"first", 0);
        let _ = wb.drain();
        wb.ingest(b"second", 0);
        assert!(!wb.should_flush());
    }

    #[test]
    fn zero_length_ingest_is_ignored() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(b"", 0);
        assert!(wb.is_empty());
        assert_eq!(wb.len(), 0);
        assert!(!wb.should_flush());
    }

    #[test]
    fn truncate_to_empty_clears_buffer() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(b"dirty", 0);
        wb.truncate(0);
        assert!(wb.is_empty());
        assert!(!wb.should_flush());
    }

    #[test]
    fn read_overlap_full_match() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(b"hello world", 0);
        let result = wb.read_overlap(0, 11);
        assert_eq!(result, Some(b"hello world".to_vec()));
    }

    #[test]
    fn read_overlap_partial_from_start() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(b"hello world", 0);
        let result = wb.read_overlap(0, 5);
        assert_eq!(result, Some(b"hello".to_vec()));
    }

    #[test]
    fn read_overlap_partial_from_middle() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(b"hello world", 0);
        let result = wb.read_overlap(6, 5);
        assert_eq!(result, Some(b"world".to_vec()));
    }

    #[test]
    fn read_overlap_across_segments() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(b"AAAA", 0);
        wb.ingest(b"BBBB", 10);
        let result = wb.read_overlap(2, 12);
        assert_eq!(result, Some(b"AA\x00\x00\x00\x00\x00\x00BBBB".to_vec()));
    }

    #[test]
    fn read_overlap_no_hit_returns_none() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(b"data", 100);
        let result = wb.read_overlap(0, 50);
        assert_eq!(result, None);
    }

    #[test]
    fn read_overlap_gap_filled_with_zero() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(b"AA", 0);
        let result = wb.read_overlap(0, 5);
        assert_eq!(result, Some(b"AA\x00\x00\x00".to_vec()));
    }

    #[test]
    fn contains_range_requires_full_dirty_coverage() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(b"abcdefghij", 0);
        assert!(wb.contains_range(0, 10));
        assert!(wb.contains_range(2, 5));
        assert!(wb.contains_range(4, 0));
        assert!(!wb.contains_range(0, 11));

        wb.clear_range(4, 2);
        assert!(wb.contains_range(0, 4));
        assert!(wb.contains_range(6, 4));
        assert!(!wb.contains_range(0, 10));
        assert!(!wb.contains_range(3, 4));
    }

    #[test]
    fn overlay_range_preserves_clean_gaps() {
        let mut wb = WriteBuffer::new(test_config());
        wb.ingest(b"dirty", 4);
        let mut base = b"abcdefghijkl".to_vec();

        assert!(wb.overlay_range(0, &mut base));

        assert_eq!(&base, b"abcddirtyjkl");
    }

    #[test]
    fn sequential_full_page_writeback_extends_one_segment() {
        let mut wb = WriteBuffer::new(WriteBufferConfig {
            flush_threshold_bytes: 8 * 1024 * 1024,
        });
        let page_size = 4096usize;
        let page_count = 1536usize;

        for page in 0..page_count {
            let mut page_bytes = vec![0_u8; page_size];
            page_bytes[..8].copy_from_slice(&(page as u64).to_le_bytes());
            wb.ingest(&page_bytes, (page * page_size) as u64);
        }

        assert_eq!(wb.len(), page_count * page_size);
        let drained = wb.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, 0);
        assert_eq!(drained[0].1.len(), page_count * page_size);
        for page in [0, 1, 511, 1024, 1535] {
            let offset = page * page_size;
            assert_eq!(
                u64::from_le_bytes(
                    drained[0].1[offset..offset + 8]
                        .try_into()
                        .expect("marker width"),
                ),
                page as u64
            );
        }
    }
}
