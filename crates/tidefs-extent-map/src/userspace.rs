// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Userspace implementation body included by the crate root when the `std`
// feature is enabled.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(dead_code)]
#![deny(unused_imports)]

//! V1 inline-list extent map implementing `ExtentMapOps`.
//!
//! `InlineExtentMap` provides the V1 (inline-list) extent map representation
//! for per-file byte-range-to-physical mapping. Entries are maintained as a
//! sorted, non-overlapping vector with at most `EXTENT_MAP_V1_MAX_ENTRIES`
//! (6) entries. Larger files use V2 (B-tree) representation.
//!
//! All mutation operations preserve the non-overlapping, sorted invariant.
//! The implementation is `#[forbid(unsafe_code)]` and targets correctness
//! over throughput — this is the simple, auditable baseline.
#[path = "allocator.rs"]
pub mod allocator;
#[path = "btree.rs"]
pub mod btree;
#[path = "multi_level.rs"]
pub mod multi_level;
#[path = "page_io.rs"]
pub mod page_io;
#[path = "polymorphic.rs"]
pub mod polymorphic;
#[path = "recordsize.rs"]
pub mod recordsize;

pub use polymorphic::{ExtentMapRepr, PolymorphicExtentMap, DEMOTE_THRESHOLD, PROMOTE_THRESHOLD};

pub use allocator::ExtentAllocator;
pub use tidefs_types_extent_map_core::ExtentMapEntryV2;
use tidefs_types_extent_map_core::{
    st_blocks_from_alloc_bytes, ExtentId, ExtentMapError, ExtentMapOps, ExtentMapV1, FiemapExtent,
    FreedExtent, LocatorId, RecordsizeProperty, DATASET_DEFAULT_RECORDSIZE,
    EXTENT_MAP_DEFAULT_RECORDSIZE, EXTENT_MAP_MAX_REFCOUNT, EXTENT_MAP_V1_MAX_ENTRIES,
};

/// Per-file recordsize policy controlling extent allocation boundaries.
///
/// When an optional `RecordsizePolicy` is active, the extent allocator
/// splits oversized write requests at recordsize-aligned boundaries so
/// that no single extent ever exceeds the effective recordsize. This is
/// the implementation-level enforcement for the design-sealed #3459
/// RECORDSIZE-P1 spec.
///
/// `None` (or omitting the policy entirely) preserves the existing
/// unconstrained behavior where a single extent may span an arbitrary
/// byte range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordsizePolicy {
    /// Fixed recordsize: every extent is at most `N` bytes, and extent
    /// boundaries are aligned to `N`-byte offsets. The last extent of a
    /// write may be shorter than `N`.
    Fixed(u64),
    /// Adaptive recordsize: extent sizes range between `min` and `max`,
    /// with alignment to `max` boundaries. The actual extent size will
    /// adapt dynamically once workload-signal integration (#3460) is
    /// available. For now, extents are split at `max` boundaries and
    /// `min` is a floor hint.
    Adaptive {
        /// Minimum extent size (floor hint for adaptive sizing).
        min: u64,
        /// Maximum extent size (splitting boundary).
        max: u64,
    },
}

impl Default for RecordsizePolicy {
    /// Returns `Fixed(EXTENT_MAP_DEFAULT_RECORDSIZE)` (4 KiB), the
    /// block-allocator default recordsize.
    fn default() -> Self {
        RecordsizePolicy::Fixed(EXTENT_MAP_DEFAULT_RECORDSIZE)
    }
}

impl RecordsizePolicy {
    /// Return the effective maximum extent size used for splitting
    /// oversized writes. For `Fixed`, this is the fixed size. For
    /// `Adaptive`, this is `max`.
    #[must_use]
    pub fn effective_max(&self) -> u64 {
        match self {
            RecordsizePolicy::Fixed(rs) => *rs,
            RecordsizePolicy::Adaptive { max, .. } => *max,
        }
    }

    /// Create a `RecordsizePolicy` from a resolved [`RecordsizeProperty`].
    ///
    /// The caller must resolve the property (via [`RecordsizeProperty::resolve`])
    /// before calling this method. `Default` maps to `Fixed(DATASET_DEFAULT_RECORDSIZE)`
    /// (128 KiB) and `Fixed(N)` maps to `Fixed(N)`.
    #[must_use]
    #[allow(clippy::match_wildcard_for_single_variants)]
    pub fn from_property(prop: RecordsizeProperty) -> Self {
        match prop {
            RecordsizeProperty::Default => RecordsizePolicy::Fixed(DATASET_DEFAULT_RECORDSIZE),
            RecordsizeProperty::Fixed(rs) => RecordsizePolicy::Fixed(rs),
            RecordsizeProperty::Inherit => RecordsizePolicy::Fixed(DATASET_DEFAULT_RECORDSIZE),
        }
    }
}

/// Split a logical write range into recordsize-aligned chunks so that no
/// single chunk exceeds `recordsize` bytes or crosses a `recordsize`-byte
/// boundary.
///
/// Returns a vector of `(offset, length)` pairs, each aligned to
/// `recordsize` and at most `recordsize` in length. If `recordsize` is 0,
/// returns a single chunk (no splitting).
#[must_use]
pub(crate) fn split_into_recordsize_chunks(
    offset: u64,
    length: u64,
    recordsize: u64,
) -> Vec<(u64, u64)> {
    if recordsize == 0 || length == 0 {
        return vec![(offset, length)];
    }
    let end = offset.saturating_add(length);
    let first_block = offset / recordsize;
    let last_block = end.saturating_sub(1) / recordsize;
    let mut chunks = Vec::with_capacity((last_block - first_block + 1) as usize);
    for block in first_block..=last_block {
        let block_start = block * recordsize;
        let block_end = block_start + recordsize;
        let chunk_start = offset.max(block_start);
        let chunk_end = end.min(block_end);
        chunks.push((chunk_start, chunk_end - chunk_start));
    }
    chunks
}

/// Concrete V1 inline-list extent map holding the header and entry vector.
///
/// Entries are always sorted by `logical_offset` and non-overlapping.
/// Maximum 6 entries (`EXTENT_MAP_V1_MAX_ENTRIES`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InlineExtentMap {
    /// Header: file_size, entry_count, alloc_bytes, version.
    pub header: ExtentMapV1,
    /// Sorted, non-overlapping extent entries.
    pub entries: Vec<ExtentMapEntryV2>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CheckedExtentRange {
    start: u64,
    end: u64,
}

impl CheckedExtentRange {
    fn new(start: u64, length: u64) -> Result<Self, ExtentMapError> {
        if length == 0 {
            return Err(ExtentMapError::InvalidRange);
        }

        let end = start
            .checked_add(length)
            .ok_or(ExtentMapError::InvalidRange)?;

        Ok(Self { start, end })
    }

    fn for_entry(entry: &ExtentMapEntryV2) -> Result<Self, ExtentMapError> {
        Self::new(entry.logical_offset, entry.length)
    }

    const fn intersects(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

impl InlineExtentMap {
    /// Create an empty V1 inline-list extent map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            header: ExtentMapV1::new(),
            entries: Vec::new(),
        }
    }

    /// Create from an existing header, with separate entries.
    #[must_use]
    pub fn from_parts(header: ExtentMapV1, entries: Vec<ExtentMapEntryV2>) -> Self {
        Self { header, entries }
    }

    /// Binary search for the index of the first entry whose end > offset.
    fn lower_bound(&self, offset: u64) -> usize {
        self.entries
            .binary_search_by(|e| {
                if e.end_offset() <= offset {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Greater
                }
            })
            .unwrap_err()
    }

    /// Repair alloc_bytes and entry_count from the entry vector.
    fn repair_stats(&mut self) {
        self.header.entry_count = self.entries.len() as u64;
        self.header.alloc_bytes = self
            .entries
            .iter()
            .filter(|e| e.extent_type().consumes_space())
            .map(|e| e.length)
            .sum();
    }
    /// Compute `st_blocks` per I6: `ceil(alloc_bytes / 512)`.
    #[must_use]
    pub fn st_blocks(&self) -> u64 {
        st_blocks_from_alloc_bytes(self.header.alloc_bytes)
    }
    /// Apply a single new extent entry, overwriting any existing entries it overlaps.
    /// Produces split fragments from partially-overlapped entries and removes
    /// fully-overlapped entries. Assumes the entry is valid (non-zero length).
    fn insert_single(&mut self, new_entry: &ExtentMapEntryV2) -> Result<(), ExtentMapError> {
        let new_range = CheckedExtentRange::for_entry(new_entry)?;
        let new_off = new_range.start;
        let new_end = new_range.end;

        let mut result: Vec<ExtentMapEntryV2> = Vec::with_capacity(self.entries.len() + 2);
        let mut inserted = false;

        for entry in &self.entries {
            let entry_range = CheckedExtentRange::for_entry(entry)?;
            if entry_range.end <= new_off {
                result.push(entry.clone());
            } else if entry.logical_offset >= new_end {
                if !inserted {
                    result.push(new_entry.clone());
                    inserted = true;
                }
                result.push(entry.clone());
            } else {
                if entry.logical_offset < new_off {
                    let mut before = entry.clone();
                    before.length = new_off - entry.logical_offset;
                    result.push(before);
                }
                if !inserted {
                    result.push(new_entry.clone());
                    inserted = true;
                }
                if entry_range.end > new_end {
                    let orig_end = entry_range.end;
                    let mut after = entry.clone();
                    after.logical_offset = new_end;
                    after.length = orig_end - new_end;
                    result.push(after);
                }
            }
        }

        if !inserted {
            result.push(new_entry.clone());
        }

        let merged = merge_adjacent(result);
        if merged.len() > EXTENT_MAP_V1_MAX_ENTRIES {
            return Err(ExtentMapError::MapFull);
        }

        self.entries = merged;
        Ok(())
    }
}
/// Format magic for inline extent map (V1).
pub const INLINE_EXTENT_MAP_MAGIC: &[u8; 4] = b"VX11";
/// Current inline format version.
pub const INLINE_EXTENT_MAP_VERSION: u8 = 1;

impl InlineExtentMap {
    /// Serialize the V1 inline extent map to a binary writer.
    ///
    /// Format:
    /// ```text
    /// magic:          4 bytes  "VX11"
    /// version:        1 byte   1
    /// flags:          1 byte   reserved
    /// entry_count:    4 bytes  number of extent entries
    /// entries:        entry_count x 81 bytes (ExtentMapEntryV2)
    /// ```
    pub fn serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<(), ExtentMapError> {
        writer
            .write_all(INLINE_EXTENT_MAP_MAGIC)
            .map_err(|_| ExtentMapError::Corrupt)?;
        writer
            .write_all(&[INLINE_EXTENT_MAP_VERSION, 0u8])
            .map_err(|_| ExtentMapError::Corrupt)?;

        let entry_count = self.entries.len() as u32;
        writer
            .write_all(&entry_count.to_le_bytes())
            .map_err(|_| ExtentMapError::Corrupt)?;

        for entry in &self.entries {
            write_entry_v2(writer, entry)?;
        }

        writer.flush().map_err(|_| ExtentMapError::Corrupt)?;
        Ok(())
    }

    /// Deserialize a V1 inline extent map from a binary reader.
    pub fn deserialize<R: std::io::Read>(reader: &mut R) -> Result<Self, ExtentMapError> {
        let mut magic = [0u8; 4];
        reader
            .read_exact(&mut magic)
            .map_err(|_| ExtentMapError::Corrupt)?;
        if &magic != INLINE_EXTENT_MAP_MAGIC {
            return Err(ExtentMapError::WrongVersion);
        }

        let mut version_flags = [0u8; 2];
        reader
            .read_exact(&mut version_flags)
            .map_err(|_| ExtentMapError::Corrupt)?;
        if version_flags[0] != INLINE_EXTENT_MAP_VERSION {
            return Err(ExtentMapError::WrongVersion);
        }

        let mut entry_count_buf = [0u8; 4];
        reader
            .read_exact(&mut entry_count_buf)
            .map_err(|_| ExtentMapError::Corrupt)?;
        let entry_count = u32::from_le_bytes(entry_count_buf) as usize;

        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            entries.push(read_entry_v2(reader)?);
        }

        let mut map = InlineExtentMap::new();
        if !entries.is_empty() {
            map.insert_extent(&entries)
                .map_err(|_| ExtentMapError::Corrupt)?;
        }
        map.validate().map_err(|_| ExtentMapError::Corrupt)?;
        Ok(map)
    }
}

impl ExtentMapOps for InlineExtentMap {
    fn lookup_range(
        &self,
        offset: u64,
        length: u64,
    ) -> Result<Vec<ExtentMapEntryV2>, ExtentMapError> {
        if length == 0 {
            return Err(ExtentMapError::InvalidRange);
        }
        let end = offset
            .checked_add(length)
            .ok_or(ExtentMapError::InvalidRange)?;

        let start_idx = self.lower_bound(offset);
        let mut result = Vec::new();
        for entry in &self.entries[start_idx..] {
            if entry.logical_offset >= end {
                break;
            }
            // Fast path: entry fully contained in query range.
            // Slower path: trim entry to query range if it extends beyond.
            if entry.logical_offset >= offset && entry.end_offset() <= end {
                result.push(entry.clone());
            } else {
                // Partial overlap — clip to query range.
                let clipped_offset = entry.logical_offset.max(offset);
                let clipped_end = entry.end_offset().min(end);
                let clipped_len = clipped_end - clipped_offset;
                let mut clipped = entry.clone();
                clipped.logical_offset = clipped_offset;
                clipped.length = clipped_len;
                result.push(clipped);
            }
        }
        Ok(result)
    }

    fn insert_extent(&mut self, entries: &[ExtentMapEntryV2]) -> Result<(), ExtentMapError> {
        if entries.is_empty() {
            return Ok(());
        }

        let checked_ranges: Vec<CheckedExtentRange> = entries
            .iter()
            .map(CheckedExtentRange::for_entry)
            .collect::<Result<_, _>>()?;

        for i in 0..entries.len() {
            for j in (i + 1)..entries.len() {
                if checked_ranges[i].intersects(checked_ranges[j]) {
                    return Err(ExtentMapError::OverlappingExtent);
                }
            }
        }

        // Apply each new entry one at a time so a single new entry that
        // overwrites multiple existing entries is handled correctly.
        let mut sorted: Vec<&ExtentMapEntryV2> = entries.iter().collect();
        sorted.sort_by_key(|e| e.logical_offset);

        let mut staged = self.clone();
        for new_entry in sorted {
            staged.insert_single(new_entry)?;
        }

        staged.repair_stats();

        let max_end = staged.entries.iter().try_fold(0, |max_end, entry| {
            let range = CheckedExtentRange::for_entry(entry)?;
            Ok::<u64, ExtentMapError>(max_end.max(range.end))
        })?;
        if max_end > staged.header.file_size {
            staged.header.file_size = max_end;
        }

        *self = staged;
        Ok(())
    }

    fn truncate(&mut self, new_size: u64) -> Result<Vec<FreedExtent>, ExtentMapError> {
        if new_size >= self.header.file_size {
            // Expanding truncate: add a hole to cover the new space, or do nothing.
            if new_size > self.header.file_size {
                self.header.file_size = new_size;
            }
            return Ok(Vec::new());
        }

        // Shrinking truncate: collect freed extents, then drop entries
        // entirely beyond new_size and trim the entry that straddles the boundary.
        let mut freed = Vec::new();
        for e in &self.entries {
            if e.logical_offset >= new_size {
                freed.push(FreedExtent::new(
                    e.logical_offset,
                    e.length,
                    e.locator_id,
                    e.extent_type(),
                ));
            } else if e.end_offset() > new_size {
                let freed_len = e.end_offset() - new_size;
                freed.push(FreedExtent::new(
                    new_size,
                    freed_len,
                    e.locator_id,
                    e.extent_type(),
                ));
            }
        }

        self.entries.retain(|e| e.logical_offset < new_size);
        if let Some(last) = self.entries.last_mut() {
            if last.end_offset() > new_size {
                last.length = new_size - last.logical_offset;
            }
        }

        self.header.file_size = new_size;
        self.repair_stats();
        Ok(freed)
    }

    fn punch_hole(&mut self, offset: u64, length: u64) -> Result<Vec<FreedExtent>, ExtentMapError> {
        if length == 0 {
            return Err(ExtentMapError::InvalidRange);
        }
        let end = offset
            .checked_add(length)
            .ok_or(ExtentMapError::InvalidRange)?;

        // Collect entries that intersect the punch range.
        let mut result: Vec<ExtentMapEntryV2> = Vec::new();
        let mut freed: Vec<FreedExtent> = Vec::new();
        for entry in &self.entries {
            if entry.end_offset() <= offset || entry.logical_offset >= end {
                // No overlap — keep as-is.
                result.push(entry.clone());
            } else {
                // Overlap — produce before/after fragments.
                if entry.logical_offset < offset {
                    let before_len = offset - entry.logical_offset;
                    let mut before = entry.clone();
                    before.length = before_len;
                    result.push(before);
                }
                if entry.end_offset() > end {
                    let after_offset = end;
                    let after_len = entry.end_offset() - end;
                    let mut after = entry.clone();
                    after.logical_offset = after_offset;
                    after.length = after_len;
                    result.push(after);
                }
                // The middle portion is the hole — dropped.
                // Record the freed portion.
                let freed_start = entry.logical_offset.max(offset);
                let freed_end = entry.end_offset().min(end);
                let freed_len = freed_end - freed_start;
                if freed_len > 0 {
                    freed.push(FreedExtent::new(
                        freed_start,
                        freed_len,
                        entry.locator_id,
                        entry.extent_type(),
                    ));
                }
            }
        }

        // Safety: remove any possible zero-length fragments before merging.
        result.retain(|e| e.length > 0);
        // Merge adjacent entries of same type.
        self.entries = merge_adjacent(result);

        // Extend file_size if hole is beyond current file.
        if end > self.header.file_size {
            self.header.file_size = end;
        }

        self.repair_stats();
        Ok(freed)
    }

    fn collapse_range(
        &mut self,
        offset: u64,
        length: u64,
    ) -> Result<Vec<FreedExtent>, ExtentMapError> {
        if length == 0 {
            return Ok(Vec::new());
        }
        let end = offset
            .checked_add(length)
            .ok_or(ExtentMapError::InvalidRange)?;
        if end > self.header.file_size {
            return Err(ExtentMapError::InvalidRange);
        }

        let (result, freed) = collapse_entries(&self.entries, offset, length)?;
        let merged = merge_adjacent(result);
        if merged.len() > EXTENT_MAP_V1_MAX_ENTRIES {
            return Err(ExtentMapError::MapFull);
        }

        self.entries = merged;
        self.header.file_size -= length;
        self.repair_stats();
        Ok(freed)
    }

    fn convert_unwritten_to_data(
        &mut self,
        offset: u64,
        length: u64,
        locator_id: LocatorId,
        checksum: [u8; 32],
        birth_commit_group: u64,
    ) -> Result<(), ExtentMapError> {
        if length == 0 {
            return Err(ExtentMapError::InvalidRange);
        }

        let end = offset
            .checked_add(length)
            .ok_or(ExtentMapError::InvalidRange)?;

        // Find UNWRITTEN entry that fully contains the range.
        let idx = self
            .entries
            .iter()
            .position(|e| e.is_unwritten() && e.logical_offset <= offset && e.end_offset() >= end);

        let idx = idx.ok_or(ExtentMapError::NotFound)?;
        let entry = &self.entries[idx];

        // Produce up to 3 fragments: before (UNWRITTEN), middle (DATA), after (UNWRITTEN).
        let mut new_entries: Vec<ExtentMapEntryV2> = Vec::new();

        // Copy entries before idx.
        new_entries.extend(self.entries[..idx].iter().cloned());

        if entry.logical_offset < offset {
            // Before fragment: UNWRITTEN
            let before_len = offset - entry.logical_offset;
            let mut before = entry.clone();
            before.length = before_len;
            new_entries.push(before);
        }

        // Middle: DATA
        new_entries.push(ExtentMapEntryV2::new_data(
            offset,
            length,
            locator_id,
            checksum,
            birth_commit_group,
        ));

        if entry.end_offset() > end {
            // After fragment: UNWRITTEN
            let after_offset = end;
            let after_len = entry.end_offset() - end;
            let mut after = entry.clone();
            after.logical_offset = after_offset;
            after.length = after_len;
            new_entries.push(after);
        }

        // Copy entries after idx.
        new_entries.extend(self.entries[idx + 1..].iter().cloned());

        self.entries = merge_adjacent(new_entries);
        self.repair_stats();

        // Extend file_size if needed.
        if end > self.header.file_size {
            self.header.file_size = end;
        }

        Ok(())
    }

    fn seek_data(&self, offset: u64) -> Option<(u64, u64)> {
        let idx = self.lower_bound(offset);
        for entry in &self.entries[idx..] {
            // Per tristate model: UNWRITTEN entries return zero on read but
            // are seekable data regions for SEEK_DATA (same as DATA).
            if entry.is_data() || entry.is_pending_data() || entry.is_unwritten() {
                let start = entry.logical_offset.max(offset);
                let remaining = entry.end_offset() - start;
                return Some((start, remaining));
            }
        }
        None
    }

    fn seek_hole(&self, offset: u64) -> Option<(u64, u64)> {
        let idx = self.lower_bound(offset);

        // Check for hole before the first entry.
        if idx == 0 {
            if let Some(first) = self.entries.first() {
                if offset < first.logical_offset {
                    let hole_start = offset;
                    let hole_end = first.logical_offset;
                    return Some((hole_start, hole_end - hole_start));
                }
            } else {
                // No entries — entire file is a hole.
                let remaining = self.header.file_size.saturating_sub(offset);
                if remaining > 0 {
                    return Some((offset, remaining));
                }
                return None;
            }
        }

        // Check gaps between entries.
        let start_from = if idx > 0 { idx - 1 } else { 0 };
        let mut cursor = offset;
        for (i, entry) in self.entries[start_from..].iter().enumerate() {
            let actual_idx = start_from + i;

            if cursor < entry.logical_offset {
                // Gap before this entry — it's a hole.
                return Some((cursor, entry.logical_offset - cursor));
            }

            // Per tristate model: UNWRITTEN is not a hole; skip past it
            // together with DATA entries.
            if entry.is_data() || entry.is_pending_data() || entry.is_unwritten() {
                // Skip past DATA and UNWRITTEN — neither is a hole.
                cursor = cursor.max(entry.end_offset());
            } else {
                // Neither DATA nor UNWRITTEN — treat as hole (should not happen with V2 entries).
                let start = cursor.max(entry.logical_offset);
                let remaining = entry.end_offset() - start;
                return Some((start, remaining));
            }

            // Check gap after this entry.
            if actual_idx + 1 < self.entries.len() {
                let next = &self.entries[actual_idx + 1];
                if cursor < next.logical_offset {
                    return Some((cursor, next.logical_offset - cursor));
                }
            }
        }

        // Past last entry.
        if cursor < self.header.file_size {
            return Some((cursor, self.header.file_size - cursor));
        }

        None
    }

    fn fallocate(
        &mut self,
        offset: u64,
        length: u64,
        keep_size: bool,
    ) -> Result<(), ExtentMapError> {
        if length == 0 {
            return Err(ExtentMapError::InvalidRange);
        }
        let end = offset
            .checked_add(length)
            .ok_or(ExtentMapError::InvalidRange)?;

        // Create an UNWRITTEN entry covering the range.
        let extent = ExtentMapEntryV2::new_unwritten(offset, length, 0);
        self.insert_single(&extent)?;

        // Extend file_size if not FALLOC_FL_KEEP_SIZE.
        if !keep_size {
            self.header.file_size = self.header.file_size.max(end);
        }

        self.repair_stats();
        Ok(())
    }

    fn zero_range(&mut self, offset: u64, length: u64) -> Result<Vec<FreedExtent>, ExtentMapError> {
        self.punch_hole(offset, length)
    }

    fn fiemap(&self, offset: u64, length: u64) -> Result<Vec<FiemapExtent>, ExtentMapError> {
        if length == 0 {
            return Err(ExtentMapError::InvalidRange);
        }
        let end = offset
            .checked_add(length)
            .ok_or(ExtentMapError::InvalidRange)?;

        let mut result: Vec<FiemapExtent> = Vec::new();
        let mut cursor = offset;

        for entry in &self.entries {
            if entry.logical_offset >= end {
                break;
            }
            let e_end = entry.end_offset();
            if e_end <= cursor {
                continue;
            }

            // Emit hole for gap before this entry.
            if entry.logical_offset > cursor {
                let hole_len = entry.logical_offset - cursor;
                result.push(FiemapExtent::new(
                    cursor,
                    0, // no physical mapping for holes
                    hole_len,
                    FiemapExtent::FLAG_UNKNOWN,
                ));
                cursor = entry.logical_offset;
            }

            // Emit this entry (clipped to query range).
            let clipped_start = cursor.max(entry.logical_offset);
            let clipped_end = e_end.min(end);
            let clipped_len = clipped_end - clipped_start;

            let flags = match entry.extent_type() {
                tidefs_types_extent_map_core::ExtentType::Hole => FiemapExtent::FLAG_UNKNOWN,
                tidefs_types_extent_map_core::ExtentType::Unwritten => {
                    FiemapExtent::FLAG_UNWRITTEN | FiemapExtent::FLAG_UNKNOWN
                }
                tidefs_types_extent_map_core::ExtentType::Data => 0,
            };

            result.push(FiemapExtent::new(
                clipped_start,
                entry.locator_id.0, // physical offset approximation
                clipped_len,
                flags,
            ));
            cursor = clipped_end;
        }

        // Emit trailing hole if any.
        if cursor < end {
            result.push(FiemapExtent::new(
                cursor,
                0,
                end - cursor,
                FiemapExtent::FLAG_UNKNOWN,
            ));
        }

        // Set FLAG_LAST on the final extent.
        if let Some(last) = result.last_mut() {
            last.fe_flags |= FiemapExtent::FLAG_LAST;
        }

        Ok(result)
    }

    fn validate(&self) -> Result<(), ExtentMapError> {
        if self.header.version != 1 {
            return Err(ExtentMapError::WrongVersion);
        }

        let count = self.entries.len();
        if count > EXTENT_MAP_V1_MAX_ENTRIES {
            return Err(ExtentMapError::MapFull);
        }

        // Check sorted + non-overlapping.
        for i in 0..count {
            let e = &self.entries[i];
            let range = CheckedExtentRange::for_entry(e).map_err(|_| ExtentMapError::Corrupt)?;
            if i > 0 {
                let prev = &self.entries[i - 1];
                let prev_range =
                    CheckedExtentRange::for_entry(prev).map_err(|_| ExtentMapError::Corrupt)?;
                if e.logical_offset < prev_range.end {
                    return Err(ExtentMapError::OverlappingExtent);
                }
                if e.logical_offset == prev_range.end
                    && e.extent_type() == prev.extent_type()
                    && e.locator_id == prev.locator_id
                    && e.checksum == prev.checksum
                {
                    // Adjacent entries of same type, locator, and checksum should have been merged.
                    return Err(ExtentMapError::Corrupt);
                }
            }
            if range.end > self.header.file_size && !e.is_unwritten() {
                return Err(ExtentMapError::Corrupt);
            }
        }

        // Check entry_count matches.
        let actual_count = self.entries.len() as u64;
        if self.header.entry_count != actual_count {
            return Err(ExtentMapError::Corrupt);
        }

        // Check alloc_bytes matches.
        let expected_alloc: u64 = self
            .entries
            .iter()
            .filter(|e| e.extent_type().consumes_space())
            .map(|e| e.length)
            .sum();
        if self.header.alloc_bytes != expected_alloc {
            return Err(ExtentMapError::Corrupt);
        }

        // I6: st_blocks derived from alloc_bytes (ceil(alloc_bytes / 512)).
        // Verified via st_blocks_from_alloc_bytes(); checked indirectly
        // through alloc_bytes correctness (I5).

        // I7: UNWRITTEN entries must have locator_id == NONE.
        // I8: DATA entries must have non-zero locator_id and non-zero checksum.
        // I9: DATA entries must be recordsize-aligned (default 4 KiB).
        //     Enforced on write path, not re-checked here.
        // I10: No explicit HOLE entries -- holes are implicit gaps.
        //      file_size must never be negative.
        for e in &self.entries {
            if e.is_unwritten() && e.locator_id.is_some() {
                return Err(ExtentMapError::Corrupt);
            }
            if e.is_data() {
                if e.locator_id.is_none() {
                    return Err(ExtentMapError::Corrupt);
                }
                // I8: checksum must be non-zero for DATA entries.
                if e.checksum == [0u8; 32] {
                    return Err(ExtentMapError::Corrupt);
                }
            }
            // I8b: PENDING_DATA entries must have a non-zero locator (they
            // own physical space) but are allowed to have a zero checksum
            // (not yet finalized) and zero birth_commit_group.
            if e.is_pending_data() {
                if e.locator_id.is_none() {
                    return Err(ExtentMapError::Corrupt);
                }
                // birth_commit_group must be zero until finalization.
                if e.birth_commit_group != 0 {
                    return Err(ExtentMapError::Corrupt);
                }
            }
            // I10: No explicit HOLE entries in the entry vector.
            if !e.is_data() && !e.is_unwritten() && !e.is_pending_data() {
                return Err(ExtentMapError::Corrupt);
            }
        }

        Ok(())
    }
}

/// Build the post-collapse entry list and freed ranges without mutating a map.
pub(crate) fn collapse_entries(
    entries: &[ExtentMapEntryV2],
    offset: u64,
    length: u64,
) -> Result<(Vec<ExtentMapEntryV2>, Vec<FreedExtent>), ExtentMapError> {
    if length == 0 {
        return Ok((entries.to_vec(), Vec::new()));
    }
    let end = offset
        .checked_add(length)
        .ok_or(ExtentMapError::InvalidRange)?;

    let mut result = Vec::with_capacity(entries.len() + 1);
    let mut freed = Vec::new();

    for entry in entries {
        let entry_end = entry.end_offset();
        if entry_end <= offset {
            result.push(entry.clone());
            continue;
        }
        if entry.logical_offset >= end {
            let mut shifted = entry.clone();
            shifted.logical_offset -= length;
            result.push(shifted);
            continue;
        }

        if entry.logical_offset < offset {
            let mut before = entry.clone();
            before.length = offset - entry.logical_offset;
            result.push(before);
        }

        let freed_start = entry.logical_offset.max(offset);
        let freed_end = entry_end.min(end);
        if freed_end > freed_start {
            freed.push(FreedExtent::new(
                freed_start,
                freed_end - freed_start,
                entry.locator_id,
                entry.extent_type(),
            ));
        }

        if entry_end > end {
            let mut after = entry.clone();
            after.logical_offset = offset;
            after.length = entry_end - end;
            result.push(after);
        }
    }

    result.retain(|entry| entry.length > 0);
    Ok((result, freed))
}

/// Invariant checks for a sorted, non-overlapping, no-zero-length extent list.
/// These fire in debug builds only and serve as a safety net after every
/// mutation that produces an extent list.
fn debug_assert_extent_invariants(entries: &[ExtentMapEntryV2]) {
    for i in 0..entries.len() {
        let e = &entries[i];
        debug_assert!(e.length > 0, "zero-length extent at index {i}");
        debug_assert!(
            e.end_offset() >= e.logical_offset,
            "overflow extent at index {i}: off={} len={}",
            e.logical_offset,
            e.length
        );
        if i > 0 {
            let prev = &entries[i - 1];
            debug_assert!(
                e.logical_offset >= prev.end_offset(),
                "extents overlapping or out of order at index {i}:                  prev=[{p_off}, {p_end}) cur=[{c_off}, {c_end})",
                p_off = prev.logical_offset,
                p_end = prev.end_offset(),
                c_off = e.logical_offset,
                c_end = e.end_offset()
            );
        }
    }
}

/// Merge adjacent entries of the same type, locator, and checksum.
fn merge_adjacent(entries: Vec<ExtentMapEntryV2>) -> Vec<ExtentMapEntryV2> {
    if entries.is_empty() {
        return entries;
    }

    let mut result: Vec<ExtentMapEntryV2> = Vec::with_capacity(entries.len());
    result.push(entries[0].clone());

    for entry in entries.into_iter().skip(1) {
        let last = result.last_mut().unwrap();
        if last.end_offset() == entry.logical_offset
            && last.extent_type() == entry.extent_type()
            && last.locator_id == entry.locator_id
            && last.checksum == entry.checksum
        {
            // Merge: extend the last entry.
            last.length += entry.length;
        } else {
            result.push(entry);
        }
    }

    debug_assert_extent_invariants(&result);
    result
}
// =========================================================================
// FreeSpaceTracker — ordered free-region tracking with coalescing
// =========================================================================

/// Tracks free (hole) regions for extent allocation queries.
///
/// Maintains a sorted, non-overlapping list of free byte ranges.
/// Updated incrementally: `carve` removes allocated ranges and
/// `release` returns freed ranges with automatic coalescing.
#[derive(Clone, Debug, Eq, PartialEq)]
struct FreeSpaceTracker {
    /// Sorted, non-overlapping (offset, length) pairs.
    regions: Vec<(u64, u64)>,
}

impl Default for FreeSpaceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl FreeSpaceTracker {
    /// Create a free tracker with the entire u64 address space free.
    fn new() -> Self {
        Self {
            regions: vec![(0, u64::MAX)],
        }
    }

    /// Return `true` if the given byte range is entirely free.
    fn is_free(&self, offset: u64, length: u64) -> bool {
        let end = offset.saturating_add(length);
        for &(free_off, free_len) in &self.regions {
            let free_end = free_off + free_len;
            if free_off <= offset && free_end >= end {
                return true;
            }
        }
        false
    }

    /// Carve out an allocated range from the free regions.
    ///
    /// Splits or removes the containing free region.
    fn carve(&mut self, offset: u64, length: u64) -> Result<(), ExtentMapError> {
        if length == 0 {
            return Err(ExtentMapError::InvalidRange);
        }
        let end = offset
            .checked_add(length)
            .ok_or(ExtentMapError::InvalidRange)?;

        for i in 0..self.regions.len() {
            let (free_off, free_len) = self.regions[i];
            let free_end = free_off + free_len;

            if free_off <= offset && free_end >= end {
                let mut new_regions: Vec<(u64, u64)> = Vec::with_capacity(self.regions.len() + 1);
                new_regions.extend_from_slice(&self.regions[..i]);

                if free_off < offset {
                    new_regions.push((free_off, offset - free_off));
                }
                if free_end > end {
                    new_regions.push((end, free_end - end));
                }

                new_regions.extend_from_slice(&self.regions[i + 1..]);
                self.regions = new_regions;
                return Ok(());
            }
        }

        Err(ExtentMapError::NotFound)
    }

    /// Return a freed range to the free pool, coalescing with adjacent regions.
    fn release(&mut self, offset: u64, length: u64) {
        if length == 0 {
            return;
        }

        let mut coalesced_start = offset;
        let mut coalesced_end = offset + length;
        let mut new_regions: Vec<(u64, u64)> = Vec::new();
        let mut inserted = false;

        for &(reg_off, reg_len) in &self.regions {
            let reg_end = reg_off + reg_len;

            if reg_end < coalesced_start {
                new_regions.push((reg_off, reg_len));
            } else if reg_off > coalesced_end {
                if !inserted {
                    new_regions.push((coalesced_start, coalesced_end - coalesced_start));
                    inserted = true;
                }
                new_regions.push((reg_off, reg_len));
            } else {
                coalesced_start = coalesced_start.min(reg_off);
                coalesced_end = coalesced_end.max(reg_end);
            }
        }

        if !inserted {
            new_regions.push((coalesced_start, coalesced_end - coalesced_start));
        }

        self.regions = new_regions;
    }

    /// Return the number of tracked free regions.
    fn len(&self) -> usize {
        self.regions.len()
    }
}

// =========================================================================
// ExtentMap — high-level allocation, free, lookup, persistence
// =========================================================================

/// High-level extent map with allocation, free, lookup, and persistence.
///
/// Wraps an inner [`PolymorphicExtentMap`] for physical storage and adds:
///
/// - Free-space tracking with coalescing (`FreeSpaceTracker`)
/// - [`ExtentId`]-based allocation and deallocation
/// - Single-offset lookup
/// - Binary serialization/deserialization for on-disk persistence
///
/// This is the primary runtime extent map that writeback (#3315),
/// CleanupJob (#3320), and reclaim (#3328) consumers integrate against.
///
/// # Allocation model
///
/// `allocate(offset, length)` creates an **UNWRITTEN** extent at the given
/// logical range and returns a unique [`ExtentId`].  The caller later
/// converts it to DATA via the inner map's `convert_unwritten_to_data`
/// once the storage layer provides a locator and checksum.
///
/// `free(extent_id)` punches a hole into the allocated range and returns
/// the space to the free pool with automatic coalescing.
#[derive(Clone, Debug)]
pub struct ExtentMap {
    inner: PolymorphicExtentMap,
    free_tracker: FreeSpaceTracker,
    next_extent_id: u64,
    id_to_offset: std::collections::BTreeMap<ExtentId, (u64, u64)>,
    refcounts: std::collections::BTreeMap<ExtentId, u32>,
    deferred_frees: std::collections::BTreeMap<ExtentId, u64>,
    /// Pool identifier for cross-pool reflink validation.
    /// `None` means pool validation is skipped (e.g. in tests).
    pool_id: Option<u64>,
}

impl Default for ExtentMap {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtentMap {
    /// Create an empty extent map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: PolymorphicExtentMap::new(),
            free_tracker: FreeSpaceTracker::new(),
            next_extent_id: 1,
            id_to_offset: std::collections::BTreeMap::new(),
            refcounts: std::collections::BTreeMap::new(),
            deferred_frees: std::collections::BTreeMap::new(),
            pool_id: None,
        }
    }

    /// Set the pool identifier for cross-pool reflink validation.
    pub fn set_pool_id(&mut self, pool_id: u64) {
        self.pool_id = Some(pool_id);
    }

    /// Return the pool identifier, if set.
    #[must_use]
    pub fn pool_id(&self) -> Option<u64> {
        self.pool_id
    }

    // -----------------------------------------------------------------
    // Allocation / free
    // -----------------------------------------------------------------

    /// Allocate a new UNWRITTEN extent from free space at `offset` + `length`.
    ///
    /// Returns a unique [`ExtentId`] for the new extent.
    ///
    /// # Errors
    ///
    /// - [`ExtentMapError::InvalidRange`] if `length == 0` or overflow.
    /// - [`ExtentMapError::NotFound`] if any part of the range overlaps an
    ///   already-allocated extent.
    pub fn allocate(&mut self, offset: u64, length: u64) -> Result<ExtentId, ExtentMapError> {
        if length == 0 {
            return Err(ExtentMapError::InvalidRange);
        }

        if !self.free_tracker.is_free(offset, length) {
            return Err(ExtentMapError::NotFound);
        }

        let entry = ExtentMapEntryV2::new_unwritten(offset, length, 0);
        self.inner.insert_extent(&[entry])?;

        let extent_id = ExtentId(self.next_extent_id);
        self.next_extent_id += 1;
        self.id_to_offset.insert(extent_id, (offset, length));
        self.refcounts.insert(extent_id, 1);

        self.free_tracker.carve(offset, length)?;

        Ok(extent_id)
    }

    /// Punch a hole over a byte range, splitting and removing extents as needed.
    ///
    /// Unlike [`free`](Self::free), this operates on arbitrary byte ranges
    /// and handles partial overlap correctly: partially covered extents are
    /// split into remaining fragments, fully covered extents are removed.
    ///
    /// `id_to_offset` entries are updated: affected extents may be split
    /// (new `ExtentId` for the trailing fragment) or removed entirely.
    pub fn punch_range(&mut self, offset: u64, length: u64) -> Result<(), ExtentMapError> {
        let end = offset
            .checked_add(length)
            .ok_or(ExtentMapError::InvalidRange)?;

        // Collect affected extent IDs and their ranges before mutation.
        let affected: Vec<(ExtentId, u64, u64)> = self
            .id_to_offset
            .iter()
            .filter(|(_eid, (off, elen))| *off < end && off + elen > offset)
            .map(|(eid, (off, elen))| (*eid, *off, *elen))
            .collect();

        // Delegate the actual extent-map tree mutation.
        self.inner.punch_hole(offset, length)?;

        // Update id_to_offset for each affected extent.
        for (eid, e_off, e_len) in affected {
            let e_end = e_off + e_len;

            if offset <= e_off && end >= e_end {
                // Fully covered: remove the ID entry.
                self.id_to_offset.remove(&eid);
                self.refcounts.remove(&eid);
                self.deferred_frees.remove(&eid);
            } else if offset <= e_off {
                // Punch removes the beginning.
                let new_len = e_end - end;
                self.id_to_offset.insert(eid, (end, new_len));
            } else if end >= e_end {
                // Punch removes the end.
                let new_len = offset - e_off;
                self.id_to_offset.insert(eid, (e_off, new_len));
            } else {
                // Punch is in the middle — split: eid stays for the before
                // fragment, new ID for the after fragment.
                let before_len = offset - e_off;
                let after_off = end;
                let after_len = e_end - end;

                self.id_to_offset.insert(eid, (e_off, before_len));

                let new_eid = ExtentId(self.next_extent_id);
                self.next_extent_id += 1;
                self.id_to_offset.insert(new_eid, (after_off, after_len));
                self.refcounts.insert(new_eid, 1);
            }
        }

        // Release the punched space in the free tracker.
        self.free_tracker.release(offset, length);

        Ok(())
    }

    /// Free an extent by [`ExtentId`], returning its space to the free pool.
    ///
    /// Coalesces adjacent free regions automatically.
    ///
    /// # Errors
    ///
    /// - [`ExtentMapError::NotFound`] if the `ExtentId` is unknown.
    pub fn free(&mut self, extent_id: ExtentId) -> Result<(), ExtentMapError> {
        let (offset, length) = *self
            .id_to_offset
            .get(&extent_id)
            .ok_or(ExtentMapError::NotFound)?;

        // Decrement refcount. If it reaches zero, proceed with actual
        // deallocation. Otherwise the extent is held by a snapshot and
        // deallocation is deferred.
        let released = self.extent_release(extent_id)?;

        if !released {
            self.deferred_frees.entry(extent_id).or_insert(0);
            return Ok(());
        }

        self.id_to_offset.remove(&extent_id);
        self.refcounts.remove(&extent_id);
        self.deferred_frees.remove(&extent_id);

        self.inner.punch_hole(offset, length)?;
        self.free_tracker.release(offset, length);

        Ok(())
    }

    // -----------------------------------------------------------------

    // -----------------------------------------------------------------
    // Reflink / clone_file
    // -----------------------------------------------------------------

    /// Clone all extents from a source [`ExtentMap`] into this one.
    ///
    /// This is the metadata-only reflink operation: no data is copied.
    /// Each source extent's refcount is incremented via [`extent_hold`],
    /// and the destination gets a refcount of 1 for each cloned extent.
    /// Both maps reference the same physical extents through the
    /// pool-wide [`ExtentId`].
    ///
    /// Validation is performed first (free-space check, refcount-overflow
    /// check). If any check fails, no mutation occurs on either map.
    ///
    /// # Errors
    ///
    /// - [`ExtentMapError::NotFound`] if the source has no extents.
    /// - [`ExtentMapError::OverlappingExtent`] if any source extent
    ///   overlaps an already-allocated region in the destination.
    /// - [`ExtentMapError::RefCountOverflow`] if any source extent's
    ///   refcount would overflow.
    pub fn clone_file(&mut self, source: &mut ExtentMap) -> Result<(), ExtentMapError> {
        // Collect source extents: (ExtentId, offset, length).
        let source_extents: Vec<(ExtentId, u64, u64)> = source
            .id_to_offset
            .iter()
            .map(|(eid, (off, len))| (*eid, *off, *len))
            .collect();

        if source_extents.is_empty() {
            return Err(ExtentMapError::NotFound);
        }

        // Phase 0: cross-pool validation.
        if let (Some(src_pool), Some(dst_pool)) = (source.pool_id, self.pool_id) {
            if src_pool != dst_pool {
                return Err(ExtentMapError::CrossPool);
            }
        }

        // Phase 1: validate free space in destination.
        for &(_eid, off, len) in &source_extents {
            if !self.free_tracker.is_free(off, len) {
                return Err(ExtentMapError::OverlappingExtent);
            }
        }

        // Phase 2: validate refcounts won't overflow in source.
        for &(eid, _, _) in &source_extents {
            let current = source.refcounts.get(&eid).copied().unwrap_or(1);
            if current >= EXTENT_MAP_MAX_REFCOUNT {
                return Err(ExtentMapError::RefCountOverflow);
            }
        }

        // Phase 3: hold all source extents.
        for &(eid, _, _) in &source_extents {
            source.extent_hold(eid)?;
        }

        // Phase 4: look up source entries and build cloned entries.
        let mut entries_to_insert: Vec<ExtentMapEntryV2> = Vec::with_capacity(source_extents.len());
        for &(_eid, off, len) in &source_extents {
            let entry = source.lookup(off).ok_or(ExtentMapError::NotFound)?;
            // Sanity: the looked-up entry must match the expected range.
            if entry.logical_offset != off || entry.length != len {
                return Err(ExtentMapError::Corrupt);
            }
            // Clone the entry preserving its original type and metadata.
            let cloned = if entry.is_pending_data() {
                ExtentMapEntryV2::new_pending_data(
                    entry.logical_offset,
                    entry.length,
                    entry.locator_id,
                )
            } else if entry.is_data() {
                ExtentMapEntryV2::new_data(
                    entry.logical_offset,
                    entry.length,
                    entry.locator_id,
                    entry.checksum,
                    entry.birth_commit_group,
                )
            } else {
                // Preserve UNWRITTEN (or any non-DATA) entries as-is.
                ExtentMapEntryV2::new_unwritten(
                    entry.logical_offset,
                    entry.length,
                    entry.birth_commit_group,
                )
            };
            entries_to_insert.push(cloned);
        }

        // Phase 5: insert into destination inner map.
        self.inner.insert_extent(&entries_to_insert)?;

        // Phase 6: update destination bookkeeping.
        for &(eid, off, len) in source_extents.iter() {
            self.id_to_offset.insert(eid, (off, len));
            self.refcounts.insert(eid, 1);
            self.free_tracker.carve(off, len)?;
            // Keep next_extent_id ahead of any imported ID.
            if eid.0 >= self.next_extent_id {
                self.next_extent_id = eid.0 + 1;
            }
        }

        // Update file_size if destination extents extend beyond current size.
        let max_end = entries_to_insert
            .iter()
            .map(|e| e.end_offset())
            .max()
            .unwrap_or(0);
        if max_end > self.inner.file_size() {
            let _ = self.inner.truncate(max_end);
        }

        Ok(())
    }

    // Lookup
    // -----------------------------------------------------------------

    /// Find the extent covering a single logical byte offset.
    ///
    /// Returns the **full** extent entry (not clipped). Returns `None`
    /// if the offset falls in a hole.
    #[must_use]
    pub fn lookup(&self, offset: u64) -> Option<ExtentMapEntryV2> {
        for (off, len) in self.id_to_offset.values() {
            if *off <= offset && offset < off + len {
                return self.inner.lookup_range(*off, *len).ok().and_then(|mut v| {
                    if v.is_empty() {
                        None
                    } else {
                        Some(v.remove(0))
                    }
                });
            }
        }
        None
    }

    /// Enumerate all extents intersecting a byte range.
    ///
    /// Delegates to the inner [`PolymorphicExtentMap::lookup_range`].
    pub fn lookup_range(
        &self,
        offset: u64,
        length: u64,
    ) -> Result<Vec<ExtentMapEntryV2>, ExtentMapError> {
        self.inner.lookup_range(offset, length)
    }

    /// Return the [`ExtentId`] for the extent starting at `offset`.
    ///
    /// Returns `None` if no extent starts exactly at `offset`.
    /// This enables callers to bridge range-based operations (punch,
    /// zero-range) into ID-based deallocation via [`free`](Self::free).
    #[must_use]
    pub fn extent_id_at(&self, offset: u64) -> Option<ExtentId> {
        for (eid, (off, _len)) in &self.id_to_offset {
            if *off == offset {
                return Some(*eid);
            }
        }
        None
    }

    // -----------------------------------------------------------------
    /// Return the [`ExtentId`] for the extent covering `offset`.
    ///
    /// Unlike [`extent_id_at`](Self::extent_id_at), this returns the ID
    /// even when `offset` is inside the extent (not just at its start).
    #[must_use]
    pub fn extent_id_covering(&self, offset: u64) -> Option<ExtentId> {
        for (eid, (off, len)) in &self.id_to_offset {
            if *off <= offset && offset < off + len {
                return Some(*eid);
            }
        }
        None
    }

    // Serialization / deserialization
    // -----------------------------------------------------------------

    /// Serialize the extent map to a binary writer.
    ///
    /// Format (little-endian):
    ///
    /// ```text
    /// magic:          4 bytes  "VXMP"
    /// version:        1 byte   3
    /// flags:          1 byte   reserved
    /// next_eid:       8 bytes  next ExtentId counter
    /// id_count:       4 bytes  number of ID mappings
    /// id_map:         id_count x 28 bytes  (eid:8, off:8, len:8, refcount:4)
    /// deferred_count: 4 bytes  number of deferred-free entries
    /// deferred_map:   deferred_count x 16 bytes  (eid:8, commit_group:8)
    /// inner:          variable  PolymorphicExtentMap serialized payload
    ///                  (format magic "VXPM", self-describing representation)
    /// ```
    pub fn serialize(&self, writer: &mut impl std::io::Write) -> Result<(), ExtentMapError> {
        writer
            .write_all(b"VXMP")
            .map_err(|_| ExtentMapError::Corrupt)?;
        writer
            .write_all(&[3u8, 0u8])
            .map_err(|_| ExtentMapError::Corrupt)?;

        writer
            .write_all(&self.next_extent_id.to_le_bytes())
            .map_err(|_| ExtentMapError::Corrupt)?;

        let id_count = self.id_to_offset.len() as u32;
        writer
            .write_all(&id_count.to_le_bytes())
            .map_err(|_| ExtentMapError::Corrupt)?;
        for (extent_id, (offset, length)) in &self.id_to_offset {
            let refcount = self.refcounts.get(extent_id).copied().unwrap_or(1);
            writer
                .write_all(&extent_id.0.to_le_bytes())
                .map_err(|_| ExtentMapError::Corrupt)?;
            writer
                .write_all(&offset.to_le_bytes())
                .map_err(|_| ExtentMapError::Corrupt)?;
            writer
                .write_all(&length.to_le_bytes())
                .map_err(|_| ExtentMapError::Corrupt)?;
            writer
                .write_all(&refcount.to_le_bytes())
                .map_err(|_| ExtentMapError::Corrupt)?;
        }

        let deferred_count = self.deferred_frees.len() as u32;
        writer
            .write_all(&deferred_count.to_le_bytes())
            .map_err(|_| ExtentMapError::Corrupt)?;
        for (extent_id, commit_group) in &self.deferred_frees {
            writer
                .write_all(&extent_id.0.to_le_bytes())
                .map_err(|_| ExtentMapError::Corrupt)?;
            writer
                .write_all(&commit_group.to_le_bytes())
                .map_err(|_| ExtentMapError::Corrupt)?;
        }

        // Delegate extent payload to the polymorphic inner map serializer.
        self.inner.serialize(writer)?;
        writer.flush().map_err(|_| ExtentMapError::Corrupt)?;
        Ok(())
    }

    /// Deserialize an extent map from a binary reader.
    pub fn deserialize(reader: &mut impl std::io::Read) -> Result<Self, ExtentMapError> {
        let mut magic = [0u8; 4];
        reader
            .read_exact(&mut magic)
            .map_err(|_| ExtentMapError::Corrupt)?;
        if &magic != b"VXMP" {
            return Err(ExtentMapError::WrongVersion);
        }

        let mut version_flags = [0u8; 2];
        reader
            .read_exact(&mut version_flags)
            .map_err(|_| ExtentMapError::Corrupt)?;
        let version = version_flags[0];
        if version != 1 && version != 2 && version != 3 {
            return Err(ExtentMapError::WrongVersion);
        }

        let mut next_id_buf = [0u8; 8];
        reader
            .read_exact(&mut next_id_buf)
            .map_err(|_| ExtentMapError::Corrupt)?;
        let next_extent_id = u64::from_le_bytes(next_id_buf);

        let mut id_count_buf = [0u8; 4];
        reader
            .read_exact(&mut id_count_buf)
            .map_err(|_| ExtentMapError::Corrupt)?;
        let id_count = u32::from_le_bytes(id_count_buf);

        let mut id_to_offset = std::collections::BTreeMap::new();
        let pool_id = None;
        let mut refcounts = std::collections::BTreeMap::new();

        if version == 1 {
            for _ in 0..id_count {
                let mut buf = [0u8; 24];
                reader
                    .read_exact(&mut buf)
                    .map_err(|_| ExtentMapError::Corrupt)?;
                let eid = u64::from_le_bytes(buf[0..8].try_into().unwrap());
                let off = u64::from_le_bytes(buf[8..16].try_into().unwrap());
                let len = u64::from_le_bytes(buf[16..24].try_into().unwrap());
                id_to_offset.insert(ExtentId(eid), (off, len));
                refcounts.insert(ExtentId(eid), 1);
            }
        } else {
            for _ in 0..id_count {
                let mut buf = [0u8; 28];
                reader
                    .read_exact(&mut buf)
                    .map_err(|_| ExtentMapError::Corrupt)?;
                let eid = u64::from_le_bytes(buf[0..8].try_into().unwrap());
                let off = u64::from_le_bytes(buf[8..16].try_into().unwrap());
                let len = u64::from_le_bytes(buf[16..24].try_into().unwrap());
                let rc = u32::from_le_bytes(buf[24..28].try_into().unwrap());
                id_to_offset.insert(ExtentId(eid), (off, len));
                refcounts.insert(ExtentId(eid), rc);
            }
        }

        let mut deferred_frees = std::collections::BTreeMap::new();
        if version >= 2 {
            let mut df_count_buf = [0u8; 4];
            reader
                .read_exact(&mut df_count_buf)
                .map_err(|_| ExtentMapError::Corrupt)?;
            let df_count = u32::from_le_bytes(df_count_buf);
            for _ in 0..df_count {
                let mut buf = [0u8; 16];
                reader
                    .read_exact(&mut buf)
                    .map_err(|_| ExtentMapError::Corrupt)?;
                let eid = u64::from_le_bytes(buf[0..8].try_into().unwrap());
                let commit_group = u64::from_le_bytes(buf[8..16].try_into().unwrap());
                deferred_frees.insert(ExtentId(eid), commit_group);
            }
        }

        let (inner, free_tracker) = if version == 3 {
            // V3: polymorphic inner map with self-describing representation.
            let inner = PolymorphicExtentMap::deserialize(reader)?;
            let mut free_tracker = FreeSpaceTracker::new();
            let entries = inner.lookup_range(0, u64::MAX).unwrap_or_default();
            for entry in &entries {
                let _ = free_tracker.carve(entry.logical_offset, entry.length);
            }
            (inner, free_tracker)
        } else {
            // V1/V2: flat entry list.
            let mut entry_count_buf = [0u8; 4];
            reader
                .read_exact(&mut entry_count_buf)
                .map_err(|_| ExtentMapError::Corrupt)?;
            let entry_count = u32::from_le_bytes(entry_count_buf);

            let mut entries: Vec<ExtentMapEntryV2> = Vec::with_capacity(entry_count as usize);
            for _ in 0..entry_count {
                entries.push(read_entry_v2(reader)?);
            }

            let mut inner = PolymorphicExtentMap::new();
            if !entries.is_empty() {
                inner
                    .insert_extent(&entries)
                    .map_err(|_| ExtentMapError::Corrupt)?;
            }

            let mut free_tracker = FreeSpaceTracker::new();
            for entry in &entries {
                let _ = free_tracker.carve(entry.logical_offset, entry.length);
            }
            (inner, free_tracker)
        };

        Ok(Self {
            inner,
            free_tracker,
            next_extent_id,
            id_to_offset,
            refcounts,
            deferred_frees,
            pool_id,
        })
    }

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------

    /// Return a reference to the inner [`PolymorphicExtentMap`].
    #[must_use]
    pub fn inner(&self) -> &PolymorphicExtentMap {
        &self.inner
    }

    /// Return a mutable reference to the inner [`PolymorphicExtentMap`].
    #[must_use]
    pub fn inner_mut(&mut self) -> &mut PolymorphicExtentMap {
        &mut self.inner
    }
    /// Defragment the extent map by merging adjacent extents with the
    /// same locator.
    ///
    /// Returns (extents_before, extents_after). The caller should
    /// mark the extent map dirty after calling this.
    #[must_use]
    pub fn defrag(&mut self) -> (u64, u64) {
        self.inner.defrag()
    }

    /// Refresh the free tracker from the current inner entries.
    pub fn refresh(&mut self) {
        self.free_tracker = FreeSpaceTracker::new();
        let mut carved_offsets: std::collections::BTreeSet<(u64, u64)> =
            std::collections::BTreeSet::new();
        for (off, len) in self.id_to_offset.values() {
            if carved_offsets.insert((*off, *len)) {
                let _ = self.free_tracker.carve(*off, *len);
            }
        }
    }

    /// Return the number of allocated (active) extents.
    #[must_use]
    pub fn extent_count(&self) -> usize {
        self.id_to_offset.len()
    }

    /// Increment the reference count for an extent.
    ///
    /// Used when a snapshot references an extent to prevent premature
    /// deallocation. Errors with [`ExtentMapError::RefCountOverflow`]
    /// when refcount would exceed [`EXTENT_MAP_MAX_REFCOUNT`].
    pub fn extent_hold(&mut self, extent_id: ExtentId) -> Result<(), ExtentMapError> {
        let rc = self
            .refcounts
            .get_mut(&extent_id)
            .ok_or(ExtentMapError::NotFound)?;
        if *rc >= EXTENT_MAP_MAX_REFCOUNT {
            return Err(ExtentMapError::RefCountOverflow);
        }
        *rc += 1;
        Ok(())
    }

    /// Decrement the reference count for an extent.
    ///
    /// Returns `true` if the refcount reached zero (caller may free
    /// the extent). Returns `false` if the extent is still held.
    pub fn extent_release(&mut self, extent_id: ExtentId) -> Result<bool, ExtentMapError> {
        let rc = self
            .refcounts
            .get_mut(&extent_id)
            .ok_or(ExtentMapError::NotFound)?;
        if *rc == 0 {
            return Ok(true);
        }
        *rc -= 1;
        Ok(*rc == 0)
    }

    /// Return the current reference count for an extent.
    ///
    /// Returns `None` if the extent ID is unknown.
    #[must_use]
    pub fn refcount(&self, extent_id: ExtentId) -> Option<u32> {
        self.refcounts.get(&extent_id).copied()
    }

    /// Drain deferred frees whose holding COMMIT_GROUP has closed.
    ///
    /// Iterates the deferred-free list and re-frees extents whose
    /// refcount has reached zero. Returns the count of freed extents.
    pub fn drain_deferred_frees(&mut self, closed_commit_group: u64) -> usize {
        let candidate_ids: Vec<ExtentId> = self
            .deferred_frees
            .iter()
            .filter(|(_, &commit_group)| commit_group <= closed_commit_group)
            .map(|(&id, _)| id)
            .collect();

        let mut freed_count = 0;
        for extent_id in candidate_ids {
            let rc = self.refcounts.get(&extent_id).copied().unwrap_or(0);
            if rc == 0 {
                if let Some((offset, length)) = self.id_to_offset.remove(&extent_id) {
                    self.refcounts.remove(&extent_id);
                    self.deferred_frees.remove(&extent_id);
                    if self.inner.punch_hole(offset, length).is_ok() {
                        self.free_tracker.release(offset, length);
                        freed_count += 1;
                    }
                }
            } else {
                self.deferred_frees.remove(&extent_id);
            }
        }
        freed_count
    }

    /// Return the number of tracked free regions.
    #[must_use]
    pub fn free_region_count(&self) -> usize {
        self.free_tracker.len()
    }

    /// Return the next [`ExtentId`] that will be assigned.
    #[must_use]
    pub fn next_extent_id(&self) -> ExtentId {
        ExtentId(self.next_extent_id)
    }

    /// Return the byte offset of the next data (DATA or UNWRITTEN) region
    /// at or after `offset`.
    ///
    /// Per POSIX SEEK_DATA semantics: returns the first byte of the next
    /// non-hole extent. UNWRITTEN extents are treated as data since they
    /// read back as zero.
    ///
    /// # Errors
    ///
    /// Returns [`ExtentMapError::NotFound`] (ENXIO) when no data region
    /// exists at or after `offset`.
    pub fn seek_data(&self, offset: u64) -> Result<u64, ExtentMapError> {
        match self.inner.seek_data(offset) {
            Some((start, _remaining)) => Ok(start),
            None => Err(ExtentMapError::NotFound),
        }
    }

    /// Return the byte offset of the next hole at or after `offset`.
    ///
    /// Per POSIX SEEK_HOLE semantics: returns the first byte of the next
    /// hole region. If no hole exists before the end of the file, returns
    /// the file size (EOF is always considered a hole).
    ///
    /// # Errors
    ///
    /// Returns [`ExtentMapError::NotFound`] (ENXIO) when `offset` is at or
    /// beyond the end of the file.
    pub fn seek_hole(&self, offset: u64) -> Result<u64, ExtentMapError> {
        match self.inner.seek_hole(offset) {
            Some((start, _remaining)) => Ok(start),
            None => {
                let fs = self.inner.file_size();
                if offset < fs {
                    Ok(fs)
                } else {
                    Err(ExtentMapError::NotFound)
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    // =========================================================================
}
// Serialization helpers for ExtentMapEntryV2
// =========================================================================

/// Write a single [`ExtentMapEntryV2`] in binary form (81 bytes).
pub(crate) fn write_entry_v2(
    writer: &mut impl std::io::Write,
    entry: &ExtentMapEntryV2,
) -> Result<(), ExtentMapError> {
    writer
        .write_all(&entry.logical_offset.to_le_bytes())
        .map_err(|_| ExtentMapError::Corrupt)?;
    writer
        .write_all(&entry.length.to_le_bytes())
        .map_err(|_| ExtentMapError::Corrupt)?;
    writer
        .write_all(&[entry.extent_kind])
        .map_err(|_| ExtentMapError::Corrupt)?;
    writer
        .write_all(&[entry.flags])
        .map_err(|_| ExtentMapError::Corrupt)?;
    writer
        .write_all(&entry.locator_id.0.to_le_bytes())
        .map_err(|_| ExtentMapError::Corrupt)?;
    writer
        .write_all(&entry.checksum)
        .map_err(|_| ExtentMapError::Corrupt)?;
    writer
        .write_all(&entry.birth_commit_group.to_le_bytes())
        .map_err(|_| ExtentMapError::Corrupt)?;
    writer
        .write_all(&entry.reserved)
        .map_err(|_| ExtentMapError::Corrupt)?;
    Ok(())
}

/// Read a single [`ExtentMapEntryV2`] from binary form (81 bytes).
pub(crate) fn read_entry_v2(
    reader: &mut impl std::io::Read,
) -> Result<ExtentMapEntryV2, ExtentMapError> {
    let mut buf8 = [0u8; 8];
    let mut checksum = [0u8; 32];
    let mut reserved = [0u8; 15];

    reader
        .read_exact(&mut buf8)
        .map_err(|_| ExtentMapError::Corrupt)?;
    let logical_offset = u64::from_le_bytes(buf8);

    reader
        .read_exact(&mut buf8)
        .map_err(|_| ExtentMapError::Corrupt)?;
    let length = u64::from_le_bytes(buf8);

    let mut kind_buf = [0u8; 1];
    reader
        .read_exact(&mut kind_buf)
        .map_err(|_| ExtentMapError::Corrupt)?;
    let extent_kind = kind_buf[0];

    let mut flags_buf = [0u8; 1];
    reader
        .read_exact(&mut flags_buf)
        .map_err(|_| ExtentMapError::Corrupt)?;
    let flags = flags_buf[0];

    reader
        .read_exact(&mut buf8)
        .map_err(|_| ExtentMapError::Corrupt)?;
    let locator_id = LocatorId(u64::from_le_bytes(buf8));

    reader
        .read_exact(&mut checksum)
        .map_err(|_| ExtentMapError::Corrupt)?;

    reader
        .read_exact(&mut buf8)
        .map_err(|_| ExtentMapError::Corrupt)?;
    let birth_commit_group = u64::from_le_bytes(buf8);

    reader
        .read_exact(&mut reserved)
        .map_err(|_| ExtentMapError::Corrupt)?;

    Ok(ExtentMapEntryV2 {
        logical_offset,
        length,
        extent_kind,
        flags,
        locator_id,
        checksum,
        birth_commit_group,
        reserved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_extent_map_core::{ExtentMapEntryV2, ExtentMapError, ExtentType};

    fn data(offset: u64, len: u64, locator: u64) -> ExtentMapEntryV2 {
        let mut csum = [0u8; 32];
        csum[0] = (locator & 0xFF) as u8;
        csum[1] = ((locator >> 8) & 0xFF) as u8;
        ExtentMapEntryV2::new_data(offset, len, LocatorId(locator), csum, 0)
    }

    fn unwritten(offset: u64, len: u64) -> ExtentMapEntryV2 {
        ExtentMapEntryV2::new_unwritten(offset, len, 0)
    }

    fn make_map(entries: &[ExtentMapEntryV2]) -> InlineExtentMap {
        let mut map = InlineExtentMap::new();
        if !entries.is_empty() {
            map.insert_extent(entries).unwrap();
        }
        map
    }

    #[test]
    fn empty_map_defaults() {
        let map = InlineExtentMap::new();
        assert!(map.entries.is_empty());
        assert_eq!(map.header.file_size, 0);
        assert_eq!(map.header.entry_count, 0);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_single_data() {
        let mut map = InlineExtentMap::new();
        map.insert_extent(&[data(0, 4096, 1)]).unwrap();
        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.header.file_size, 4096);
        assert_eq!(map.header.alloc_bytes, 4096);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_two_non_overlapping() {
        let mut map = InlineExtentMap::new();
        map.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2)])
            .unwrap();
        assert_eq!(map.entries.len(), 2);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_overwrite_existing() {
        let mut map = make_map(&[data(0, 8192, 1)]);
        // Overwrite middle portion.
        map.insert_extent(&[data(2048, 4096, 2)]).unwrap();
        assert_eq!(map.entries.len(), 3); // before, new, after
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 2048);
        assert_eq!(map.entries[1].logical_offset, 2048);
        assert_eq!(map.entries[1].length, 4096);
        assert_eq!(map.entries[2].logical_offset, 6144);
        assert_eq!(map.entries[2].length, 2048);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_middle_overwrite_preserves_tail_lookup_ranges() {
        let mut map = make_map(&[data(0, 16384, 11)]);

        map.insert_extent(&[data(4096, 8192, 22)]).unwrap();

        assert_eq!(
            map.entries,
            vec![
                data(0, 4096, 11),
                data(4096, 8192, 22),
                data(12288, 4096, 11),
            ]
        );
        assert_eq!(map.header.file_size, 16384);
        assert_eq!(map.header.alloc_bytes, 16384);

        let left_tail = map.lookup_range(1024, 2048).unwrap();
        assert_eq!(left_tail.len(), 1);
        assert_eq!(left_tail[0], data(1024, 2048, 11));

        let right_tail = map.lookup_range(13312, 1024).unwrap();
        assert_eq!(right_tail.len(), 1);
        assert_eq!(right_tail[0], data(13312, 1024, 11));

        let replacement = map.lookup_range(4096, 8192).unwrap();
        assert_eq!(replacement, vec![data(4096, 8192, 22)]);
        assert_eq!(map.seek_hole(0), None);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_overwrite_split_preserves_unaffected_extent_metadata() {
        let mut original = data(0, 16384, 31);
        original.flags = 5;
        original.birth_commit_group = 77;
        original.reserved[0] = 9;
        let replacement = data(4096, 8192, 44);
        let mut map = make_map(&[original.clone()]);

        map.insert_extent(&[replacement.clone()]).unwrap();

        let mut expected_prefix = original.clone();
        expected_prefix.length = 4096;
        let mut expected_suffix = original;
        expected_suffix.logical_offset = 12288;
        expected_suffix.length = 4096;
        assert_eq!(
            map.entries,
            vec![expected_prefix, replacement, expected_suffix]
        );
        assert_eq!(map.header.file_size, 16384);
        assert_eq!(map.header.entry_count, 3);
        assert_eq!(map.header.alloc_bytes, 16384);
        assert_eq!(map.seek_hole(0), None);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_merges_adjacent_same_type() {
        let mut map = InlineExtentMap::new();
        map.insert_extent(&[data(0, 4096, 1), data(4096, 4096, 1)])
            .unwrap();
        // Should merge into one 8192-byte entry.
        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 8192);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn adjacent_insert_extends_existing_left_boundary() {
        let mut map = make_map(&[data(4096, 4096, 7)]);

        map.insert_extent(&[data(0, 4096, 7)]).unwrap();

        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 8192);
        assert_eq!(map.entries[0].locator_id, LocatorId(7));
        assert_eq!(map.header.file_size, 8192);
        assert_eq!(map.header.alloc_bytes, 8192);
        assert_eq!(map.lookup_range(0, 8192).unwrap().len(), 1);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn adjacent_insert_extends_existing_right_boundary() {
        let mut map = make_map(&[data(0, 4096, 7)]);

        map.insert_extent(&[data(4096, 4096, 7)]).unwrap();

        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 8192);
        assert_eq!(map.entries[0].locator_id, LocatorId(7));
        assert_eq!(map.header.file_size, 8192);
        assert_eq!(map.header.alloc_bytes, 8192);
        assert_eq!(map.lookup_range(0, 8192).unwrap().len(), 1);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn adjacent_insert_bridges_two_existing_ranges() {
        let mut map = make_map(&[data(0, 4096, 7), data(8192, 4096, 7)]);

        map.insert_extent(&[data(4096, 4096, 7)]).unwrap();

        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 12288);
        assert_eq!(map.entries[0].locator_id, LocatorId(7));
        assert_eq!(map.header.file_size, 12288);
        assert_eq!(map.header.alloc_bytes, 12288);
        assert_eq!(map.lookup_range(0, 12288).unwrap().len(), 1);
        assert_eq!(map.seek_hole(0), None);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn adjacent_insert_preserves_distinct_ranges_across_holes() {
        let mut map = make_map(&[data(0, 4096, 7), data(12288, 4096, 7)]);

        map.insert_extent(&[data(8192, 4096, 7)]).unwrap();

        assert_eq!(map.entries.len(), 2);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 4096);
        assert_eq!(map.entries[1].logical_offset, 8192);
        assert_eq!(map.entries[1].length, 8192);
        assert_eq!(map.header.file_size, 16384);
        assert_eq!(map.header.alloc_bytes, 12288);
        assert_eq!(map.seek_hole(4096), Some((4096, 4096)));
        assert_eq!(map.seek_data(4096), Some((8192, 8192)));
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_map_full() {
        let mut map = InlineExtentMap::new();
        // Insert 6 non-merging entries — should succeed.
        for i in 0..6u64 {
            map.insert_extent(&[data(i * 4096 * 2, 4096, i + 1)])
                .unwrap();
        }
        assert_eq!(map.entries.len(), 6);
        let before = map.clone();

        // 7th entry should fail.
        let err = map.insert_extent(&[data(50000, 4096, 7)]).unwrap_err();
        assert_eq!(err, ExtentMapError::MapFull);
        assert_eq!(map, before);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_batch_map_full_rejects_without_partial_mutation() {
        let mut map = InlineExtentMap::new();
        for i in 0..5u64 {
            map.insert_extent(&[data(i * 4096 * 2, 4096, i + 1)])
                .unwrap();
        }
        let before = map.clone();

        let err = map
            .insert_extent(&[data(40960, 4096, 6), data(49152, 4096, 7)])
            .unwrap_err();

        assert_eq!(err, ExtentMapError::MapFull);
        assert_eq!(map, before);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_overlapping_batch_rejected() {
        let mut map = InlineExtentMap::new();
        let err = map
            .insert_extent(&[data(0, 8192, 1), data(4096, 4096, 2)])
            .unwrap_err();
        assert_eq!(err, ExtentMapError::OverlappingExtent);
    }

    #[test]
    fn insert_overflowing_extent_rejected() {
        let mut map = InlineExtentMap::new();
        let err = map.insert_extent(&[data(u64::MAX, 1, 1)]).unwrap_err();
        assert_eq!(err, ExtentMapError::InvalidRange);
        assert!(map.entries.is_empty());
        assert_eq!(map.header.file_size, 0);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_batch_rejects_overflow_before_mutation() {
        let mut map = make_map(&[data(0, 4096, 1)]);
        let before = map.clone();

        let err = map
            .insert_extent(&[data(4096, 4096, 2), data(u64::MAX, 1, 3)])
            .unwrap_err();

        assert_eq!(err, ExtentMapError::InvalidRange);
        assert_eq!(map, before);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_largest_valid_boundary_range() {
        let mut map = InlineExtentMap::new();

        map.insert_extent(&[data(u64::MAX - 4096, 4096, 1)])
            .unwrap();

        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].logical_offset, u64::MAX - 4096);
        assert_eq!(map.entries[0].length, 4096);
        assert_eq!(map.header.file_size, u64::MAX);
        assert_eq!(map.header.alloc_bytes, 4096);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn validate_overflowing_entry_is_corrupt() {
        let mut map = InlineExtentMap::new();
        map.entries = vec![data(u64::MAX, 1, 1)];
        map.header.file_size = u64::MAX;
        map.header.entry_count = 1;
        map.header.alloc_bytes = 1;

        let err = map.validate().unwrap_err();

        assert_eq!(err, ExtentMapError::Corrupt);
    }

    #[test]
    fn lookup_range_exact_match() {
        let map = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);
        let result = map.lookup_range(0, 4096).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].logical_offset, 0);
    }

    #[test]
    fn lookup_range_partial_overlap() {
        let map = make_map(&[data(0, 8192, 1)]);
        let result = map.lookup_range(2048, 4096).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].logical_offset, 2048);
        assert_eq!(result[0].length, 4096);
    }

    #[test]
    fn lookup_range_zero_length_rejected() {
        let map = InlineExtentMap::new();
        let err = map.lookup_range(0, 0).unwrap_err();
        assert_eq!(err, ExtentMapError::InvalidRange);
    }

    #[test]
    fn truncate_shrink() {
        let mut map = make_map(&[data(0, 8192, 1)]);
        let freed = map.truncate(4096).unwrap();
        assert_eq!(freed.len(), 1);
        assert_eq!(freed[0].logical_offset, 4096);
        assert_eq!(freed[0].length, 4096);
        assert_eq!(freed[0].extent_type, ExtentType::Data);
        assert_eq!(map.header.file_size, 4096);
        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].length, 4096);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn truncate_drop_entries() {
        let mut map = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);
        map.truncate(4096).unwrap();
        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn truncate_expand() {
        let mut map = make_map(&[data(0, 4096, 1)]);
        let freed = map.truncate(16384).unwrap();
        assert!(freed.is_empty());
        assert_eq!(map.header.file_size, 16384);
        assert_eq!(map.entries.len(), 1); // entries unchanged
        assert!(map.validate().is_ok());
    }

    #[test]
    fn truncate_empty() {
        let mut map = InlineExtentMap::new();
        let freed = map.truncate(0).unwrap();
        assert!(freed.is_empty());
        assert_eq!(map.header.file_size, 0);
        assert!(map.entries.is_empty());
        assert!(map.validate().is_ok());
    }

    #[test]
    fn truncate_to_zero() {
        let mut map = make_map(&[data(0, 8192, 1), data(16384, 4096, 2)]);
        let freed = map.truncate(0).unwrap();
        assert_eq!(freed.len(), 2);
        assert_eq!(freed[0].logical_offset, 0);
        assert_eq!(freed[0].length, 8192);
        assert_eq!(freed[0].extent_type, ExtentType::Data);
        assert_eq!(freed[1].logical_offset, 16384);
        assert_eq!(freed[1].length, 4096);
        assert_eq!(freed[1].extent_type, ExtentType::Data);
        assert_eq!(map.header.file_size, 0);
        assert!(map.entries.is_empty());
        assert!(map.validate().is_ok());
    }

    #[test]
    fn truncate_idempotent() {
        let mut map = make_map(&[data(0, 12288, 1)]);
        let freed1 = map.truncate(4096).unwrap();
        assert_eq!(freed1.len(), 1);
        assert_eq!(freed1[0].logical_offset, 4096);
        assert_eq!(freed1[0].length, 8192);
        assert_eq!(map.header.file_size, 4096);
        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].length, 4096);
        assert!(map.validate().is_ok());
        let freed2 = map.truncate(4096).unwrap();
        assert!(freed2.is_empty());
        assert_eq!(map.header.file_size, 4096);
        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].length, 4096);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn punch_hole_middle_of_data() {
        let mut map = make_map(&[data(0, 12288, 1)]);
        let freed = map.punch_hole(4096, 4096).unwrap();
        assert_eq!(freed.len(), 1);
        assert_eq!(freed[0].logical_offset, 4096);
        assert_eq!(freed[0].length, 4096);
        assert_eq!(freed[0].locator_id, LocatorId(1));
        assert_eq!(freed[0].extent_type, ExtentType::Data);
        assert_eq!(map.entries.len(), 2); // before and after, hole in middle
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 4096);
        assert!(map.entries[0].is_data());
        assert_eq!(map.entries[1].logical_offset, 8192);
        assert_eq!(map.entries[1].length, 4096);
        assert!(map.entries[1].is_data());
        assert!(map.validate().is_ok());
    }

    #[test]
    fn remove_split_hole_preserves_metadata_and_is_idempotent() {
        let mut original = data(0, 16384, 42);
        original.flags = 3;
        original.birth_commit_group = 99;
        original.reserved[0] = 7;
        let mut map = make_map(&[original.clone()]);

        let freed = map.punch_hole(4096, 8192).unwrap();

        assert_eq!(freed.len(), 1);
        assert_eq!(freed[0].logical_offset, 4096);
        assert_eq!(freed[0].length, 8192);
        assert_eq!(freed[0].locator_id, LocatorId(42));
        assert_eq!(freed[0].extent_type, ExtentType::Data);
        let mut expected_prefix = original.clone();
        expected_prefix.length = 4096;
        let mut expected_suffix = original;
        expected_suffix.logical_offset = 12288;
        expected_suffix.length = 4096;
        assert_eq!(map.entries, vec![expected_prefix, expected_suffix]);
        assert_eq!(map.header.file_size, 16384);
        assert_eq!(map.header.entry_count, 2);
        assert_eq!(map.header.alloc_bytes, 8192);
        assert!(map.validate().is_ok());

        let after_first_remove = map.clone();
        let repeated = map.punch_hole(4096, 8192).unwrap();

        assert!(repeated.is_empty());
        assert_eq!(map, after_first_remove);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn punch_hole_entire_entry() {
        let mut map = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);
        let freed = map.punch_hole(0, 4096).unwrap();
        assert_eq!(freed.len(), 1);
        assert_eq!(freed[0].logical_offset, 0);
        assert_eq!(freed[0].length, 4096);
        assert_eq!(freed[0].locator_id, LocatorId(1));
        assert_eq!(freed[0].extent_type, ExtentType::Data);
        assert_eq!(map.entries.len(), 1); // only second entry remains
        assert_eq!(map.entries[0].logical_offset, 8192);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn punch_hole_beyond_file_size() {
        let mut map = make_map(&[data(0, 4096, 1)]);
        let freed = map.punch_hole(8192, 4096).unwrap();
        assert!(freed.is_empty());
        assert_eq!(map.header.file_size, 12288);
        assert_eq!(map.entries.len(), 1); // original entry unchanged
        assert!(map.validate().is_ok());
    }

    #[test]
    fn punch_hole_multi_extent_reports_exact_freed_ranges() {
        let mut map = make_map(&[data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)]);
        let freed = map.punch_hole(2048, 14336).unwrap();
        assert_eq!(freed.len(), 2);
        assert_eq!(freed[0].logical_offset, 2048);
        assert_eq!(freed[0].length, 2048);
        assert_eq!(freed[0].locator_id, LocatorId(1));
        assert_eq!(freed[0].extent_type, ExtentType::Data);
        assert_eq!(freed[1].logical_offset, 8192);
        assert_eq!(freed[1].length, 4096);
        assert_eq!(freed[1].locator_id, LocatorId(2));
        assert_eq!(freed[1].extent_type, ExtentType::Data);
        assert_eq!(map.entries.len(), 2);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 2048);
        assert_eq!(map.entries[1].logical_offset, 16384);
        assert_eq!(map.entries[1].length, 4096);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn punch_hole_already_hole_reports_no_freed_ranges() {
        let mut map = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);
        let freed = map.punch_hole(4096, 4096).unwrap();
        assert!(freed.is_empty());
        assert_eq!(map.entries.len(), 2);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[1].logical_offset, 8192);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn zero_range_over_data_is_hole_backed() {
        let mut map = make_map(&[data(0, 12288, 1)]);
        let freed = map.zero_range(4096, 4096).unwrap();
        assert_eq!(freed.len(), 1);
        assert_eq!(freed[0].logical_offset, 4096);
        assert_eq!(freed[0].length, 4096);
        assert_eq!(freed[0].locator_id, LocatorId(1));
        assert_eq!(freed[0].extent_type, ExtentType::Data);
        assert_eq!(map.entries.len(), 2);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 4096);
        assert_eq!(map.entries[1].logical_offset, 8192);
        assert_eq!(map.entries[1].length, 4096);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn zero_range_over_hole_reports_no_freed_ranges() {
        let mut map = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);
        let freed = map.zero_range(4096, 4096).unwrap();
        assert!(freed.is_empty());
        assert_eq!(map.entries.len(), 2);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[1].logical_offset, 8192);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn collapse_range_zero_length_noop() {
        let mut map = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);
        let before = map.clone();

        let freed = map.collapse_range(4096, 0).unwrap();

        assert!(freed.is_empty());
        assert_eq!(map, before);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn collapse_range_full_single_extent() {
        let mut map = make_map(&[data(0, 4096, 1)]);

        let freed = map.collapse_range(0, 4096).unwrap();

        assert_eq!(freed.len(), 1);
        assert_eq!(freed[0].logical_offset, 0);
        assert_eq!(freed[0].length, 4096);
        assert_eq!(freed[0].locator_id, LocatorId(1));
        assert_eq!(freed[0].extent_type, ExtentType::Data);
        assert!(map.entries.is_empty());
        assert_eq!(map.header.file_size, 0);
        assert_eq!(map.header.alloc_bytes, 0);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn collapse_range_middle_single_extent_coalesces_shifted_tail() {
        let mut map = make_map(&[data(0, 12288, 1)]);

        let freed = map.collapse_range(4096, 4096).unwrap();

        assert_eq!(freed.len(), 1);
        assert_eq!(freed[0].logical_offset, 4096);
        assert_eq!(freed[0].length, 4096);
        assert_eq!(freed[0].locator_id, LocatorId(1));
        assert_eq!(freed[0].extent_type, ExtentType::Data);
        assert_eq!(map.entries, vec![data(0, 8192, 1)]);
        assert_eq!(map.header.file_size, 8192);
        assert_eq!(map.header.alloc_bytes, 8192);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn collapse_range_spanning_multiple_extents_frees_and_shifts_tail() {
        let mut map = make_map(&[data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)]);

        let freed = map.collapse_range(2048, 14336).unwrap();

        assert_eq!(freed.len(), 2);
        assert_eq!(freed[0].logical_offset, 2048);
        assert_eq!(freed[0].length, 2048);
        assert_eq!(freed[0].locator_id, LocatorId(1));
        assert_eq!(freed[1].logical_offset, 8192);
        assert_eq!(freed[1].length, 4096);
        assert_eq!(freed[1].locator_id, LocatorId(2));
        assert_eq!(map.entries, vec![data(0, 2048, 1), data(2048, 4096, 3)]);
        assert_eq!(map.header.file_size, 6144);
        assert_eq!(map.header.alloc_bytes, 6144);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn collapse_range_over_hole_shifts_subsequent_extent() {
        let mut map = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);

        let freed = map.collapse_range(4096, 4096).unwrap();

        assert!(freed.is_empty());
        assert_eq!(map.entries, vec![data(0, 4096, 1), data(4096, 4096, 2)]);
        assert_eq!(map.header.file_size, 8192);
        assert_eq!(map.header.alloc_bytes, 8192);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn collapse_range_beyond_file_size_rejected_without_mutation() {
        let mut map = make_map(&[data(0, 4096, 1)]);
        let before = map.clone();

        let err = map.collapse_range(2048, 4096).unwrap_err();

        assert_eq!(err, ExtentMapError::InvalidRange);
        assert_eq!(map, before);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn fallocate_extends_file_size_with_unwritten_extent() {
        let mut map = InlineExtentMap::new();
        map.fallocate(4096, 8192, false).unwrap();
        assert_eq!(map.header.file_size, 12288);
        assert_eq!(map.header.entry_count, 1);
        assert_eq!(map.header.alloc_bytes, 8192);
        assert_eq!(map.entries, vec![unwritten(4096, 8192)]);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn fallocate_keep_size_preserves_file_size() {
        let mut map = make_map(&[data(0, 4096, 1)]);
        map.fallocate(8192, 4096, true).unwrap();
        assert_eq!(map.header.file_size, 4096);
        assert_eq!(map.header.entry_count, 2);
        assert_eq!(map.header.alloc_bytes, 8192);
        assert_eq!(map.entries[1], unwritten(8192, 4096));
        assert!(map.validate().is_ok());
    }

    #[test]
    fn fallocate_rejects_zero_length() {
        let mut map = InlineExtentMap::new();
        let err = map.fallocate(0, 0, false).unwrap_err();
        assert_eq!(err, ExtentMapError::InvalidRange);
        assert_eq!(map.header.file_size, 0);
        assert!(map.entries.is_empty());
    }

    #[test]
    fn fallocate_rejects_offset_overflow() {
        let mut map = InlineExtentMap::new();
        let err = map.fallocate(u64::MAX, 1, false).unwrap_err();
        assert_eq!(err, ExtentMapError::InvalidRange);
        assert_eq!(map.header.file_size, 0);
        assert!(map.entries.is_empty());
    }

    #[test]
    fn fallocate_replaces_overlapping_data_with_unwritten() {
        let mut map = make_map(&[data(0, 12288, 1)]);
        map.fallocate(4096, 4096, false).unwrap();
        assert_eq!(map.header.file_size, 12288);
        assert_eq!(map.header.entry_count, 3);
        assert_eq!(map.header.alloc_bytes, 12288);
        assert_eq!(map.entries[0], data(0, 4096, 1));
        assert_eq!(map.entries[1], unwritten(4096, 4096));
        assert_eq!(map.entries[2], data(8192, 4096, 1));
        assert!(map.validate().is_ok());
    }

    #[test]
    fn convert_unwritten_to_data() {
        let mut map = make_map(&[unwritten(0, 4096)]);
        let checksum = [0xAB; 32];
        map.convert_unwritten_to_data(0, 2048, LocatorId(5), checksum, 10)
            .unwrap();
        assert_eq!(map.entries.len(), 2); // DATA + remaining UNWRITTEN
        assert!(map.entries[0].is_data());
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 2048);
        assert!(map.entries[1].is_unwritten());
        assert!(map.validate().is_ok());
    }

    #[test]
    fn convert_unwritten_full_entry() {
        let mut map = make_map(&[unwritten(0, 4096)]);
        let checksum = [0xCD; 32];
        map.convert_unwritten_to_data(0, 4096, LocatorId(7), checksum, 20)
            .unwrap();
        assert_eq!(map.entries.len(), 1);
        assert!(map.entries[0].is_data());
        assert!(map.validate().is_ok());
    }

    #[test]
    fn convert_unwritten_not_found() {
        let mut map = make_map(&[data(0, 4096, 1)]);
        let err = map
            .convert_unwritten_to_data(0, 2048, LocatorId(1), [0u8; 32], 0)
            .unwrap_err();
        assert_eq!(err, ExtentMapError::NotFound);
    }

    #[test]
    fn seek_data_finds_first() {
        let map = make_map(&[data(4096, 4096, 1), data(12288, 4096, 2)]);
        let result = map.seek_data(0);
        assert_eq!(result, Some((4096, 4096)));
    }

    #[test]
    fn seek_data_finds_unwritten() {
        let map = make_map(&[unwritten(0, 4096)]);
        let result = map.seek_data(0);
        // Per tristate model: UNWRITTEN is a seekable data region.
        assert_eq!(result, Some((0, 4096)));
    }

    #[test]
    fn seek_hole_between_entries() {
        let map = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);
        let result = map.seek_hole(0);
        assert_eq!(result, Some((4096, 4096)));
    }

    #[test]
    fn seek_hole_skips_unwritten() {
        let map = make_map(&[unwritten(0, 4096)]);
        let result = map.seek_hole(0);
        // Per tristate model: UNWRITTEN is not a hole; no hole in range.
        assert_eq!(result, None);
    }

    #[test]
    fn seek_hole_beyond_last_entry() {
        let map = make_map(&[data(0, 4096, 1)]);
        let mut map = map;
        map.header.file_size = 8192;
        let result = map.seek_hole(4096);
        assert_eq!(result, Some((4096, 4096)));
    }

    #[test]
    fn seek_data_from_mid_entry() {
        let map = make_map(&[data(0, 8192, 1), data(16384, 4096, 2)]);
        let result = map.seek_data(4096);
        assert_eq!(result, Some((4096, 4096))); // remaining of first entry
    }

    #[test]
    fn fiemap_single_entry() {
        let map = make_map(&[data(0, 4096, 1)]);
        let result = map.fiemap(0, 4096).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].fe_logical, 0);
        assert_eq!(result[0].fe_length, 4096);
        assert!(result[0].fe_flags & FiemapExtent::FLAG_LAST != 0);
    }

    #[test]
    fn fiemap_unwritten_flag() {
        let map = make_map(&[unwritten(0, 4096)]);
        let result = map.fiemap(0, 4096).unwrap();
        assert_eq!(result.len(), 1);
        // Per tristate model: UNWRITTEN has both FLAG_UNWRITTEN and FLAG_UNKNOWN.
        assert!(result[0].fe_flags & FiemapExtent::FLAG_UNWRITTEN != 0);
        assert!(result[0].fe_flags & FiemapExtent::FLAG_UNKNOWN != 0);
    }

    #[test]
    fn fiemap_partial_range() {
        let map = make_map(&[data(0, 8192, 1), data(16384, 4096, 2)]);
        // Query [2048, 14336): clips first entry to [2048,8192), then hole [8192,14336).
        let result = map.fiemap(2048, 12288).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].fe_logical, 2048);
        assert_eq!(result[0].fe_length, 6144);
        assert_eq!(result[0].fe_flags & FiemapExtent::FLAG_UNWRITTEN, 0);
        // Hole from 8192 to 14336.
        assert_eq!(result[1].fe_logical, 8192);
        assert_eq!(result[1].fe_length, 6144);
        assert!(result[1].fe_flags & FiemapExtent::FLAG_UNKNOWN != 0);
        assert!(result[1].fe_flags & FiemapExtent::FLAG_LAST != 0);
    }

    #[test]
    fn validate_wrong_version() {
        let mut map = InlineExtentMap::new();
        map.header.version = 2;
        let err = map.validate().unwrap_err();
        assert_eq!(err, ExtentMapError::WrongVersion);
    }

    #[test]
    fn validate_overlapping_rejected() {
        let mut map = InlineExtentMap::new();
        // Manually create overlapping state.
        map.entries = vec![data(0, 8192, 1), data(4096, 4096, 2)];
        map.header.file_size = 12288;
        map.header.entry_count = 2;
        let err = map.validate().unwrap_err();
        assert_eq!(err, ExtentMapError::OverlappingExtent);
    }

    #[test]
    fn validate_entry_count_mismatch() {
        let mut map = make_map(&[data(0, 4096, 1)]);
        map.header.entry_count = 99;
        let err = map.validate().unwrap_err();
        assert_eq!(err, ExtentMapError::Corrupt);
    }

    #[test]
    fn validate_alloc_bytes_mismatch() {
        let mut map = make_map(&[data(0, 4096, 1)]);
        map.header.alloc_bytes = 999;
        let err = map.validate().unwrap_err();
        assert_eq!(err, ExtentMapError::Corrupt);
    }

    #[test]
    fn validate_unmerged_adjacent() {
        let mut map = InlineExtentMap::new();
        // Two adjacent entries of same type, should have been merged.
        map.entries = vec![data(0, 4096, 1), data(4096, 4096, 1)];
        map.header.file_size = 8192;
        map.header.entry_count = 2;
        map.header.alloc_bytes = 8192;
        let err = map.validate().unwrap_err();
        assert_eq!(err, ExtentMapError::Corrupt);
    }

    #[test]
    fn insert_empty_batch_ok() {
        let mut map = InlineExtentMap::new();
        map.insert_extent(&[]).unwrap();
        assert!(map.entries.is_empty());
    }

    #[test]
    fn insert_zero_length_rejected() {
        let mut map = InlineExtentMap::new();
        let mut zero = data(0, 0, 1);
        zero.length = 0;
        let err = map.insert_extent(&[zero]).unwrap_err();
        assert_eq!(err, ExtentMapError::InvalidRange);
    }

    #[test]
    fn repair_stats_updates_counts() {
        let mut map = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);
        // Manually corrupt stats.
        map.header.entry_count = 0;
        map.header.alloc_bytes = 0;
        map.repair_stats();
        assert_eq!(map.header.entry_count, 2);
        assert_eq!(map.header.alloc_bytes, 8192);
    }

    #[test]
    fn from_parts_constructor() {
        let header = ExtentMapV1::new();
        let entries = vec![data(0, 4096, 1)];
        let map = InlineExtentMap::from_parts(header, entries);
        assert_eq!(map.entries.len(), 1);
    }

    #[test]
    fn roundtrip_insert_lookup() {
        let mut map = InlineExtentMap::new();
        let entries = [data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)];
        map.insert_extent(&entries).unwrap();
        assert!(map.validate().is_ok());

        // Lookup each entry and verify.
        for entry in &entries {
            let result = map
                .lookup_range(entry.logical_offset, entry.length)
                .unwrap();
            assert_eq!(result.len(), 1);
            assert_eq!(result[0].logical_offset, entry.logical_offset);
            assert_eq!(result[0].length, entry.length);
        }
    }

    #[test]
    fn insert_overwrite_and_merge() {
        let mut map = make_map(&[data(0, 4096, 1), data(8192, 4096, 1), data(16384, 4096, 1)]);
        // Insert data that bridges entries 1 and 2 with same locator.
        map.insert_extent(&[data(2048, 10240, 1)]).unwrap();
        // Result: [0,12288,1], [16384,4096,1] — 2 entries
        // [0,2048,1] + [2048,12288,1] merge because they are adjacent
        // with same type and locator; gap [12288,16384] prevents merge with third.
        assert_eq!(map.entries.len(), 2);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 12288);
        assert_eq!(map.entries[1].logical_offset, 16384);
        assert_eq!(map.entries[1].length, 4096);

        assert!(map.validate().is_ok());
    }

    #[test]
    fn sparse_overwrite_fills_adjacent_gap_and_merges_same_locator() {
        let mut map = make_map(&[data(0, 4096, 7), data(8192, 4096, 7)]);

        map.insert_extent(&[data(4096, 4096, 7)]).unwrap();

        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 12288);
        assert_eq!(map.entries[0].locator_id, LocatorId(7));
        assert_eq!(map.header.file_size, 12288);
        assert_eq!(map.header.alloc_bytes, 12288);
        assert_eq!(map.seek_data(0), Some((0, 12288)));
        assert_eq!(map.seek_hole(0), None);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn sparse_overwrite_across_hole_splits_existing_edges() {
        let mut map = make_map(&[data(0, 4096, 1), data(12288, 4096, 2)]);

        map.insert_extent(&[data(2048, 12288, 3)]).unwrap();

        assert_eq!(map.entries.len(), 3);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 2048);
        assert_eq!(map.entries[0].locator_id, LocatorId(1));
        assert_eq!(map.entries[1].logical_offset, 2048);
        assert_eq!(map.entries[1].length, 12288);
        assert_eq!(map.entries[1].locator_id, LocatorId(3));
        assert_eq!(map.entries[2].logical_offset, 14336);
        assert_eq!(map.entries[2].length, 2048);
        assert_eq!(map.entries[2].locator_id, LocatorId(2));
        assert_eq!(map.header.file_size, 16384);
        assert_eq!(map.header.alloc_bytes, 16384);
        assert_eq!(map.seek_hole(0), None);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn sparse_overwrite_inside_hole_preserves_surrounding_gaps() {
        let mut map = make_map(&[data(0, 4096, 1), data(16384, 4096, 2)]);

        map.insert_extent(&[data(8192, 4096, 3)]).unwrap();

        assert_eq!(map.entries.len(), 3);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 4096);
        assert_eq!(map.entries[1].logical_offset, 8192);
        assert_eq!(map.entries[1].length, 4096);
        assert_eq!(map.entries[2].logical_offset, 16384);
        assert_eq!(map.entries[2].length, 4096);
        assert_eq!(map.header.file_size, 20480);
        assert_eq!(map.header.alloc_bytes, 12288);
        assert_eq!(map.seek_hole(4096), Some((4096, 4096)));
        assert_eq!(map.seek_data(4096), Some((8192, 4096)));
        assert_eq!(map.seek_hole(12288), Some((12288, 4096)));
        assert!(map.validate().is_ok());
    }

    #[test]
    fn truncate_exact_boundary() {
        let mut map = make_map(&[data(0, 4096, 1), data(4096, 4096, 2)]);
        map.truncate(4096).unwrap();
        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 4096);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn punch_hole_no_op_on_empty() {
        let mut map = InlineExtentMap::new();
        map.header.file_size = 8192;
        map.punch_hole(0, 4096).unwrap();
        assert!(map.entries.is_empty());
        assert!(map.validate().is_ok());
    }

    #[test]
    fn convert_unwritten_partial_overlap_rejected() {
        let mut map = make_map(&[unwritten(0, 4096)]);
        // Range extends beyond UNWRITTEN entry.
        let err = map
            .convert_unwritten_to_data(2048, 4096, LocatorId(1), [0u8; 32], 0)
            .unwrap_err();
        assert_eq!(err, ExtentMapError::NotFound);
    }

    #[test]
    fn convert_unwritten_three_fragment_split() {
        let mut map = make_map(&[unwritten(0, 12288)]);
        let checksum = [0xAA; 32];
        map.convert_unwritten_to_data(4096, 4096, LocatorId(9), checksum, 1)
            .unwrap();
        assert_eq!(map.entries.len(), 3);
        assert!(map.entries[0].is_unwritten());
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 4096);
        assert!(map.entries[1].is_data());
        assert_eq!(map.entries[1].logical_offset, 4096);
        assert_eq!(map.entries[1].length, 4096);
        assert!(map.entries[2].is_unwritten());
        assert_eq!(map.entries[2].logical_offset, 8192);
        assert_eq!(map.entries[2].length, 4096);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn convert_unwritten_prefix_trim() {
        let mut map = make_map(&[unwritten(0, 8192)]);
        let checksum = [0xBB; 32];
        map.convert_unwritten_to_data(0, 2048, LocatorId(10), checksum, 2)
            .unwrap();
        assert_eq!(map.entries.len(), 2);
        assert!(map.entries[0].is_data());
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 2048);
        assert!(map.entries[1].is_unwritten());
        assert_eq!(map.entries[1].logical_offset, 2048);
        assert_eq!(map.entries[1].length, 6144);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn convert_unwritten_suffix_trim() {
        let mut map = make_map(&[unwritten(0, 8192)]);
        let checksum = [0xCC; 32];
        map.convert_unwritten_to_data(6144, 2048, LocatorId(11), checksum, 3)
            .unwrap();
        assert_eq!(map.entries.len(), 2);
        assert!(map.entries[0].is_unwritten());
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 6144);
        assert!(map.entries[1].is_data());
        assert_eq!(map.entries[1].logical_offset, 6144);
        assert_eq!(map.entries[1].length, 2048);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn convert_unwritten_multi_entry_span_rejected() {
        // Non-adjacent UNWRITTEN entries with a HOLE gap — merge_adjacent won't merge them.
        let mut map = make_map(&[unwritten(0, 4096), unwritten(8192, 4096)]);
        // Range [2048, 6144) spans HOLE gap — no single UNWRITTEN entry contains it.
        let err = map
            .convert_unwritten_to_data(2048, 4096, LocatorId(1), [0u8; 32], 0)
            .unwrap_err();
        assert_eq!(err, ExtentMapError::NotFound);
    }

    #[test]
    fn convert_unwritten_wrong_type() {
        let mut map = make_map(&[data(0, 4096, 1)]);
        let err = map
            .convert_unwritten_to_data(0, 2048, LocatorId(1), [0u8; 32], 0)
            .unwrap_err();
        assert_eq!(err, ExtentMapError::NotFound);
    }

    #[test]
    fn convert_unwritten_zero_length_rejected() {
        let mut map = make_map(&[unwritten(0, 4096)]);
        let err = map
            .convert_unwritten_to_data(0, 0, LocatorId(1), [0u8; 32], 0)
            .unwrap_err();
        assert_eq!(err, ExtentMapError::InvalidRange);
    }

    #[test]
    fn seek_data_past_file_size() {
        let map = make_map(&[data(0, 4096, 1)]);
        let result = map.seek_data(8192);
        assert_eq!(result, None);
    }

    // =====================================================================
    // ExtentMap allocate, free, lookup, persistence
    // =====================================================================

    #[test]
    fn extent_map_allocate_single() {
        let mut m = ExtentMap::new();
        let eid = m.allocate(0, 4096).unwrap();
        assert_eq!(eid, ExtentId(1));
        assert_eq!(m.extent_count(), 1);

        let entry = m.lookup(0).unwrap();
        assert!(entry.is_unwritten());
        assert_eq!(entry.logical_offset, 0);
        assert_eq!(entry.length, 4096);
    }

    #[test]
    fn extent_map_allocate_zero_length_rejected() {
        let mut m = ExtentMap::new();
        let err = m.allocate(0, 0).unwrap_err();
        assert_eq!(err, ExtentMapError::InvalidRange);
        assert_eq!(m.extent_count(), 0);
    }

    #[test]
    fn extent_map_allocate_overlapping_rejected() {
        let mut m = ExtentMap::new();
        m.allocate(0, 4096).unwrap();
        let err = m.allocate(2048, 4096).unwrap_err();
        assert_eq!(err, ExtentMapError::NotFound);
        let err = m.allocate(0, 4096).unwrap_err();
        assert_eq!(err, ExtentMapError::NotFound);
        let err = m.allocate(4095, 1).unwrap_err();
        assert_eq!(err, ExtentMapError::NotFound);
        assert_eq!(m.extent_count(), 1);
    }

    #[test]
    fn extent_map_allocate_adjacent_no_overlap() {
        let mut m = ExtentMap::new();
        m.allocate(0, 4096).unwrap();
        let eid = m.allocate(4096, 4096).unwrap();
        assert_eq!(eid, ExtentId(2));
        assert_eq!(m.extent_count(), 2);

        let e0 = m.lookup(0).unwrap();
        let e1 = m.lookup(4096).unwrap();
        assert!(e0.is_unwritten());
        assert!(e1.is_unwritten());
        assert_eq!(e0.length, 4096);
        assert_eq!(e1.length, 4096);
    }

    #[test]
    fn extent_map_free_single() {
        let mut m = ExtentMap::new();
        let eid = m.allocate(0, 4096).unwrap();
        m.free(eid).unwrap();
        assert_eq!(m.extent_count(), 0);
        assert!(m.lookup(0).is_none());
    }

    #[test]
    fn extent_map_free_unknown_id_rejected() {
        let mut m = ExtentMap::new();
        let err = m.free(ExtentId(999)).unwrap_err();
        assert_eq!(err, ExtentMapError::NotFound);
    }

    #[test]
    fn extent_map_double_free_rejected() {
        let mut m = ExtentMap::new();
        let eid = m.allocate(0, 4096).unwrap();
        m.free(eid).unwrap();
        let err = m.free(eid).unwrap_err();
        assert_eq!(err, ExtentMapError::NotFound);
    }

    #[test]
    fn extent_map_allocate_free_reallocate_cycle() {
        let mut m = ExtentMap::new();

        let _e1 = m.allocate(0, 4096).unwrap();
        let e2 = m.allocate(4096, 4096).unwrap();
        let _e3 = m.allocate(8192, 4096).unwrap();
        assert_eq!(m.extent_count(), 3);

        m.free(e2).unwrap();
        assert_eq!(m.extent_count(), 2);
        assert!(m.lookup(4096).is_none());

        let e4 = m.allocate(4096, 2048).unwrap();
        assert_eq!(e4, ExtentId(4));
        assert_eq!(m.extent_count(), 3);

        assert!(m.lookup(4096).is_some());
        assert!(m.lookup(6144).is_none());

        let _e5 = m.allocate(6144, 2048).unwrap();
        assert_eq!(m.extent_count(), 4);
    }

    #[test]
    fn extent_map_free_coalesces_adjacent() {
        let mut m = ExtentMap::new();
        let e1 = m.allocate(0, 4096).unwrap();
        let e2 = m.allocate(4096, 4096).unwrap();
        let e3 = m.allocate(8192, 4096).unwrap();

        m.free(e1).unwrap();
        m.free(e2).unwrap();
        m.free(e3).unwrap();

        assert_eq!(m.extent_count(), 0);
        assert!(m.free_region_count() >= 1);
    }

    #[test]
    fn extent_map_lookup_hole_returns_none() {
        let mut m = ExtentMap::new();
        m.allocate(4096, 4096).unwrap();

        assert!(m.lookup(0).is_none());
        assert!(m.lookup(4095).is_none());
        assert!(m.lookup(4096).is_some());
        assert!(m.lookup(8191).is_some());
        assert!(m.lookup(8192).is_none());
    }

    #[test]
    fn extent_map_lookup_exact_offset() {
        let mut m = ExtentMap::new();
        m.allocate(4096, 4096).unwrap();

        let entry = m.lookup(4096).unwrap();
        assert_eq!(entry.logical_offset, 4096);
        assert_eq!(entry.length, 4096);

        let entry = m.lookup(8191).unwrap();
        assert_eq!(entry.logical_offset, 4096);
        assert_eq!(entry.length, 4096);

        assert!(m.lookup(8192).is_none());
    }

    #[test]
    fn extent_map_lookup_multi_extent() {
        let mut m = ExtentMap::new();
        m.allocate(0, 4096).unwrap();
        m.allocate(8192, 4096).unwrap();

        assert!(m.lookup(0).is_some());
        assert!(m.lookup(4095).is_some());
        assert!(m.lookup(4096).is_none());
        assert!(m.lookup(8192).is_some());
        assert!(m.lookup(12287).is_some());
    }

    #[test]
    fn extent_map_lookup_range_across_boundaries() {
        let mut m = ExtentMap::new();
        m.allocate(0, 4096).unwrap();
        m.allocate(8192, 4096).unwrap();
        m.allocate(16384, 4096).unwrap();

        let r = m.lookup_range(0, 20480).unwrap();
        assert_eq!(r.len(), 3);

        let r = m.lookup_range(0, 4096).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].logical_offset, 0);
        assert_eq!(r[0].length, 4096);

        let r = m.lookup_range(0, 16384).unwrap();
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn extent_map_serialize_roundtrip_populated() {
        use std::io::Cursor;

        let mut m = ExtentMap::new();
        m.allocate(0, 4096).unwrap();
        m.allocate(4096, 4096).unwrap();
        m.allocate(16384, 8192).unwrap();

        let e0 = m.lookup(0).unwrap();
        assert_eq!(e0.logical_offset, 0);
        assert_eq!(e0.length, 4096);

        let mut buf = Vec::new();
        m.serialize(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let recon = ExtentMap::deserialize(&mut cursor).unwrap();

        assert_eq!(recon.extent_count(), 3);

        let r0 = recon.lookup(0).unwrap();
        assert_eq!(r0.logical_offset, 0);
        assert_eq!(r0.length, 4096);
        assert!(recon.lookup(4096).is_some());
        assert!(recon.lookup(8192).is_none());
        assert!(recon.lookup(16384).is_some());
        let r1 = recon.lookup(16384).unwrap();
        assert_eq!(r1.length, 8192);
    }

    #[test]
    fn extent_map_serialize_roundtrip_empty() {
        use std::io::Cursor;

        let m = ExtentMap::new();
        let mut buf = Vec::new();
        m.serialize(&mut buf).unwrap();
        assert!(!buf.is_empty());

        let mut cursor = Cursor::new(&buf);
        let recon = ExtentMap::deserialize(&mut cursor).unwrap();
        assert_eq!(recon.extent_count(), 0);
    }

    #[test]
    fn extent_map_serialize_wrong_magic_rejected() {
        use std::io::Cursor;

        let buf = b"BADC".to_vec();
        let mut cursor = Cursor::new(&buf);
        let err = ExtentMap::deserialize(&mut cursor).unwrap_err();
        assert_eq!(err, ExtentMapError::WrongVersion);
    }

    #[test]
    fn extent_map_serialize_wrong_version_rejected() {
        use std::io::Cursor;

        let buf = b"VXMP\x63\x00".to_vec();
        let mut cursor = Cursor::new(&buf);
        let err = ExtentMap::deserialize(&mut cursor).unwrap_err();
        assert_eq!(err, ExtentMapError::WrongVersion);
    }

    #[test]
    fn extent_map_serialize_truncated_data_rejected() {
        use std::io::Cursor;

        let mut m = ExtentMap::new();
        m.allocate(0, 4096).unwrap();
        let mut buf = Vec::new();
        m.serialize(&mut buf).unwrap();

        let half = buf.len() / 2;
        let mut cursor = Cursor::new(&buf[..half]);
        let err = ExtentMap::deserialize(&mut cursor).unwrap_err();
        assert_eq!(err, ExtentMapError::Corrupt);
    }

    #[test]
    fn extent_map_serialize_preserves_id_sequence() {
        use std::io::Cursor;

        let mut m = ExtentMap::new();
        m.allocate(0, 4096).unwrap();
        m.allocate(4096, 4096).unwrap();
        let _e3 = m.allocate(8192, 4096).unwrap();

        assert_eq!(m.next_extent_id(), ExtentId(4));

        let mut buf = Vec::new();
        m.serialize(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let recon = ExtentMap::deserialize(&mut cursor).unwrap();
        assert_eq!(recon.next_extent_id(), ExtentId(4));

        let mut recon2 = recon.clone();
        let e4 = recon2.allocate(12288, 4096).unwrap();
        assert_eq!(e4, ExtentId(4));
    }

    #[test]
    fn extent_map_v3_roundtrip_empty() {
        use std::io::Cursor;

        let m = ExtentMap::new();
        let mut buf = Vec::new();
        m.serialize(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let recon = ExtentMap::deserialize(&mut cursor).unwrap();
        assert_eq!(recon.extent_count(), 0);
        assert!(recon.lookup(0).is_none());
    }

    #[test]
    fn extent_map_v3_roundtrip_populated() {
        use std::io::Cursor;

        let mut m = ExtentMap::new();
        m.allocate(0, 4096).unwrap();
        m.allocate(8192, 8192).unwrap();
        assert_eq!(m.extent_count(), 2);

        let mut buf = Vec::new();
        m.serialize(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let recon = ExtentMap::deserialize(&mut cursor).unwrap();
        assert_eq!(recon.extent_count(), 2);
        assert!(recon.lookup(0).is_some());
        assert!(recon.lookup(8192).is_some());
        assert!(recon.lookup(4096).is_none());
    }

    #[test]
    fn extent_map_v3_preserves_inner_repr() {
        use std::io::Cursor;

        let mut m = ExtentMap::new();
        // Promote to BTree via many allocations.
        for i in 0..10u64 {
            m.allocate(i * 4096, 4096).unwrap();
        }
        // The inner repr should be BTree or MultiLevel (not Inline).
        let repr = m.inner().representation();
        assert!(repr != ExtentMapRepr::Inline);

        let mut buf = Vec::new();
        m.serialize(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let recon = ExtentMap::deserialize(&mut cursor).unwrap();
        // Inner repr preserved across v3 roundtrip.
        assert_eq!(recon.inner().representation(), repr);
        assert_eq!(recon.extent_count(), 10);
    }

    #[test]
    fn extent_map_v3_roundtrip_with_unwritten() {
        use std::io::Cursor;

        let mut m = ExtentMap::new();
        // Allocate then convert to data, then punch_hole via inner to create mixed entries.
        let _eid = m.allocate(0, 12288).unwrap();
        let cs = [0xCC; 32];
        m.inner_mut()
            .convert_unwritten_to_data(0, 12288, LocatorId(1), cs, 1)
            .unwrap();
        m.refresh();
        let _ = m.inner_mut().punch_hole(4096, 4096).unwrap();
        // punch_hole splits the extent entry but id count stays the same.

        let mut buf = Vec::new();
        m.serialize(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let recon = ExtentMap::deserialize(&mut cursor).unwrap();
        // Verify entries are intact.
        let entries = recon.lookup_range(0, 12288).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].is_data() || entries[0].is_unwritten());
        assert!(entries[1].is_data() || entries[1].is_unwritten());
    }

    #[test]
    fn extent_map_v3_roundtrip_refcounts_preserved() {
        use std::io::Cursor;

        let mut src = ExtentMap::new();
        let mut dst = ExtentMap::new();

        let e1 = src.allocate(0, 4096).unwrap();
        dst.clone_file(&mut src).unwrap();
        assert_eq!(src.refcount(e1), Some(2));
        assert_eq!(dst.refcount(e1), Some(1));

        let mut buf = Vec::new();
        src.serialize(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let recon = ExtentMap::deserialize(&mut cursor).unwrap();
        assert_eq!(recon.refcount(e1), Some(2));
    }

    #[test]
    fn extent_map_v3_roundtrip_deferred_frees_preserved() {
        use std::io::Cursor;

        let mut m = ExtentMap::new();
        let eid = m.allocate(0, 4096).unwrap();
        m.extent_hold(eid).unwrap();
        m.free(eid).unwrap();
        // Refcount was 2, now 1; free defers.
        assert_eq!(m.extent_count(), 1);
        assert_eq!(m.refcount(eid), Some(1));

        let mut buf = Vec::new();
        m.serialize(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let recon = ExtentMap::deserialize(&mut cursor).unwrap();
        assert_eq!(recon.extent_count(), 1);
        assert_eq!(recon.refcount(eid), Some(1));
    }

    #[test]
    fn extent_map_inner_convert_unwritten_to_data() {
        let mut m = ExtentMap::new();
        let eid = m.allocate(0, 4096).unwrap();

        let checksum = [0xCC; 32];
        m.inner_mut()
            .convert_unwritten_to_data(0, 4096, LocatorId(42), checksum, 1)
            .unwrap();
        m.refresh();

        let entry = m.lookup(0).unwrap();
        assert!(entry.is_data());
        assert_eq!(entry.locator_id, LocatorId(42));
        assert_eq!(entry.checksum, [0xCC; 32]);
        assert_eq!(entry.birth_commit_group, 1);

        m.free(eid).unwrap();
        assert!(m.lookup(0).is_none());
    }

    #[test]
    fn extent_map_new_defaults() {
        let m = ExtentMap::new();
        assert_eq!(m.extent_count(), 0);
        assert!(m.free_region_count() >= 1);
        assert_eq!(m.next_extent_id(), ExtentId(1));
        assert!(m.lookup(0).is_none());
    }

    // =====================================================================
    // Refcount tests — issue #3536
    // =====================================================================

    #[test]
    fn test_refcount_alloc_defaults_to_one() {
        let mut m = ExtentMap::new();
        let eid = m.allocate(0, 4096).unwrap();
        assert_eq!(m.refcount(eid), Some(1));
    }

    #[test]
    fn test_hold_increments_refcount() {
        let mut m = ExtentMap::new();
        let eid = m.allocate(0, 4096).unwrap();
        m.extent_hold(eid).unwrap();
        assert_eq!(m.refcount(eid), Some(2));
    }

    #[test]
    fn test_release_decrements_refcount() {
        let mut m = ExtentMap::new();
        let eid = m.allocate(0, 4096).unwrap();
        m.extent_hold(eid).unwrap();
        assert_eq!(m.refcount(eid), Some(2));
        m.extent_release(eid).unwrap();
        assert_eq!(m.refcount(eid), Some(1));
    }

    #[test]
    fn test_release_to_zero_returns_true() {
        let mut m = ExtentMap::new();
        let eid = m.allocate(0, 4096).unwrap();
        let is_zero = m.extent_release(eid).unwrap();
        assert!(is_zero);
        assert_eq!(m.refcount(eid), Some(0));
    }

    #[test]
    fn test_release_held_returns_false() {
        let mut m = ExtentMap::new();
        let eid = m.allocate(0, 4096).unwrap();
        m.extent_hold(eid).unwrap();
        let is_zero = m.extent_release(eid).unwrap();
        assert!(!is_zero);
        assert_eq!(m.refcount(eid), Some(1));
    }

    #[test]
    fn test_free_only_when_refcount_zero() {
        let mut m = ExtentMap::new();
        let eid = m.allocate(0, 4096).unwrap();
        // Hold the extent — free should be deferred.
        m.extent_hold(eid).unwrap();
        m.free(eid).unwrap();
        assert_eq!(m.extent_count(), 1); // still present
        assert!(m.lookup(0).is_some());

        // Release the hold — now refcount is 1, call free again to release.
        m.free(eid).unwrap();
        assert_eq!(m.extent_count(), 0); // fully freed
        assert!(m.lookup(0).is_none());
    }

    #[test]
    fn test_double_hold_does_not_overflow() {
        let mut m = ExtentMap::new();
        let eid = m.allocate(0, 4096).unwrap();

        // Manually set refcount to MAX_REFCOUNT via direct BTreeMap access,
        // since actually iterating 4 billion times would take forever.
        m.refcounts.insert(eid, EXTENT_MAP_MAX_REFCOUNT);

        // Hold should overflow.
        let err = m.extent_hold(eid).unwrap_err();
        assert_eq!(err, ExtentMapError::RefCountOverflow);
        assert_eq!(m.refcount(eid), Some(EXTENT_MAP_MAX_REFCOUNT));
    }

    #[test]
    fn test_format_migration_reads_old_extent_as_refcount_one() {
        // Write a v1-format extent map (no refcount field in id_map, 24-byte entries).
        let mut buf = Vec::new();
        buf.extend_from_slice(b"VXMP"); // magic
        buf.extend_from_slice(&[1u8, 0u8]); // version=1, flags=0
        buf.extend_from_slice(&2u64.to_le_bytes()); // next_eid = 2
        buf.extend_from_slice(&1u32.to_le_bytes()); // id_count = 1
                                                    // V1 id_map: (eid:8, off:8, len:8) = 24 bytes
        buf.extend_from_slice(&1u64.to_le_bytes()); // eid = 1
        buf.extend_from_slice(&0u64.to_le_bytes()); // off = 0
        buf.extend_from_slice(&4096u64.to_le_bytes()); // len = 4096
        buf.extend_from_slice(&1u32.to_le_bytes()); // entry_count = 1
                                                    // Write one entry (81 bytes): unwritten extent at 0.
        let entry = ExtentMapEntryV2::new_unwritten(0, 4096, 0);
        // Manually serialize the entry using the existing helper
        {
            use std::io::Write;
            let w = &mut buf;
            w.write_all(&entry.logical_offset.to_le_bytes()).unwrap();
            w.write_all(&entry.length.to_le_bytes()).unwrap();
            w.write_all(&[entry.extent_kind]).unwrap();
            w.write_all(&[entry.flags]).unwrap();
            w.write_all(&entry.locator_id.0.to_le_bytes()).unwrap();
            w.write_all(&entry.checksum).unwrap();
            w.write_all(&entry.birth_commit_group.to_le_bytes())
                .unwrap();
            w.write_all(&entry.reserved).unwrap();
        }

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = ExtentMap::deserialize(&mut cursor).unwrap();
        let eid = ExtentId(1);
        assert_eq!(recon.refcount(eid), Some(1));
        assert_eq!(recon.extent_count(), 1);
    }

    #[test]
    fn test_deferred_free_drained_after_commit_group_close() {
        let mut m = ExtentMap::new();
        let eid = m.allocate(0, 4096).unwrap();

        // Hold the extent and attempt free — should defer.
        m.extent_hold(eid).unwrap();
        m.free(eid).unwrap();
        assert_eq!(m.extent_count(), 1); // deferred, still present

        // Release the hold — refcount now 1.
        m.extent_release(eid).unwrap();

        // Drain deferred frees with closed_commit_group=0 (the deferred entry has commit_group=0).
        let freed = m.drain_deferred_frees(0);
        assert_eq!(freed, 1);
        assert_eq!(m.extent_count(), 0);
        assert!(m.lookup(0).is_none());
    }

    #[test]
    fn test_concurrent_hold_release_no_underflow() {
        use std::sync::Arc;
        use std::thread;

        let mut m = ExtentMap::new();
        let eid = m.allocate(0, 4096).unwrap();

        // Pre-hold to start at refcount=100 (99 holds since alloc starts at 1).
        for _ in 1..100 {
            m.extent_hold(eid).unwrap();
        }
        assert_eq!(m.refcount(eid), Some(100));

        let map = Arc::new(std::sync::Mutex::new(m));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let map = Arc::clone(&map);
            let h = thread::spawn(move || {
                for _ in 0..25 {
                    let mut guard = map.lock().unwrap();
                    guard.extent_hold(eid).unwrap();
                    guard.extent_release(eid).unwrap();
                }
            });
            handles.push(h);
        }

        for h in handles {
            h.join().unwrap();
        }

        let final_map = Arc::try_unwrap(map).unwrap().into_inner().unwrap();
        assert_eq!(final_map.refcount(eid), Some(100));
    }

    // =====================================================================
    // ExtentMap seek_data / seek_hole (Result<u64>) tests — #4660
    // =====================================================================

    #[test]
    fn extent_map_seek_data_single_extent_from_start() {
        let mut m = ExtentMap::new();
        m.allocate(0, 4096).unwrap();
        // Offset 0 is inside DATA → returns 0.
        assert_eq!(m.seek_data(0), Ok(0));
        // Offset 2048 is inside the same extent → returns 2048.
        assert_eq!(m.seek_data(2048), Ok(2048));
        // Offset 4096 is past the only extent → NotFound.
        assert_eq!(m.seek_data(4096), Err(ExtentMapError::NotFound));
    }

    #[test]
    fn extent_map_seek_data_multi_extent() {
        let mut m = ExtentMap::new();
        m.allocate(0, 4096).unwrap();
        m.allocate(8192, 4096).unwrap();
        // First extent starts at 0.
        assert_eq!(m.seek_data(0), Ok(0));
        // Hole [4096, 8192) — seek_data from 4096 skips to 8192.
        assert_eq!(m.seek_data(4096), Ok(8192));
        // Past last extent.
        assert_eq!(m.seek_data(12288), Err(ExtentMapError::NotFound));
    }

    #[test]
    fn extent_map_seek_data_fully_sparse() {
        let m = ExtentMap::new();
        // No entries — no data anywhere.
        assert_eq!(m.seek_data(0), Err(ExtentMapError::NotFound));
        assert_eq!(m.seek_data(4096), Err(ExtentMapError::NotFound));
    }

    #[test]
    fn extent_map_seek_data_fully_allocated() {
        let mut m = ExtentMap::new();
        m.allocate(0, 4096).unwrap();
        m.allocate(4096, 4096).unwrap();
        m.allocate(8192, 4096).unwrap();
        // Every byte is data.
        assert_eq!(m.seek_data(0), Ok(0));
        assert_eq!(m.seek_data(2048), Ok(2048));
        assert_eq!(m.seek_data(4096), Ok(4096));
        assert_eq!(m.seek_data(8192), Ok(8192));
        assert_eq!(m.seek_data(12287), Ok(12287));
        // Past end of all extents.
        assert_eq!(m.seek_data(12288), Err(ExtentMapError::NotFound));
    }

    #[test]
    fn extent_map_seek_hole_between_extents() {
        let mut m = ExtentMap::new();
        m.allocate(0, 4096).unwrap();
        m.allocate(8192, 4096).unwrap();
        // Offset 0 is data — next hole is at 4096.
        assert_eq!(m.seek_hole(0), Ok(4096));
        // Offset 4096 is a hole — returns itself.
        assert_eq!(m.seek_hole(4096), Ok(4096));
        // Offset 8192 is data — next hole is at 12288 (EOF).
        assert_eq!(m.seek_hole(8192), Ok(12288));
        // Offset 12288 is past all extents — NotFound (past EOF).
        assert_eq!(m.seek_hole(12288), Err(ExtentMapError::NotFound));
    }

    #[test]
    fn extent_map_seek_hole_fully_sparse() {
        let m = ExtentMap::new();
        // No entries, file_size=0 → seek_hole(0) returns NotFound (past EOF).
        assert_eq!(m.seek_hole(0), Err(ExtentMapError::NotFound));
    }

    #[test]
    fn extent_map_seek_hole_fully_allocated() {
        let mut m = ExtentMap::new();
        m.allocate(0, 4096).unwrap();
        m.allocate(4096, 4096).unwrap();
        // Fully allocated [0, 8192) — no holes before EOF.
        // SEEK_HOLE returns file_size (8192) when no hole found.
        assert_eq!(m.seek_hole(0), Ok(8192));
        assert_eq!(m.seek_hole(2048), Ok(8192));
        assert_eq!(m.seek_hole(4096), Ok(8192));
        // Past EOF.
        assert_eq!(m.seek_hole(8192), Err(ExtentMapError::NotFound));
    }

    #[test]
    fn extent_map_seek_data_past_eof() {
        let mut m = ExtentMap::new();
        m.allocate(0, 4096).unwrap();
        assert_eq!(m.seek_data(4096), Err(ExtentMapError::NotFound));
        assert_eq!(m.seek_data(8192), Err(ExtentMapError::NotFound));
    }

    #[test]
    fn extent_map_seek_hole_past_eof() {
        let mut m = ExtentMap::new();
        m.allocate(0, 4096).unwrap();
        assert_eq!(m.seek_hole(4096), Err(ExtentMapError::NotFound));
        assert_eq!(m.seek_hole(8192), Err(ExtentMapError::NotFound));
    }

    #[test]
    fn extent_map_seek_hole_leading_hole() {
        let mut m = ExtentMap::new();
        m.allocate(4096, 4096).unwrap();
        // Hole at [0, 4096), data at [4096, 8192).
        assert_eq!(m.seek_hole(0), Ok(0));
        assert_eq!(m.seek_hole(2048), Ok(2048));
        // Data region — hole at EOF (8192).
        assert_eq!(m.seek_hole(4096), Ok(8192));
    }

    // =====================================================================
    // clone_file tests — issue #3367
    // =====================================================================

    #[test]
    fn clone_file_copies_all_extents() {
        let mut src = ExtentMap::new();
        let mut dst = ExtentMap::new();

        let _e1 = src.allocate(0, 4096).unwrap();
        let _e2 = src.allocate(4096, 4096).unwrap();
        assert_eq!(src.extent_count(), 2);

        dst.clone_file(&mut src).unwrap();

        assert_eq!(dst.extent_count(), 2);
        assert!(dst.lookup(0).is_some());
        assert!(dst.lookup(4096).is_some());
    }

    #[test]
    fn clone_file_increments_source_refcount() {
        let mut src = ExtentMap::new();
        let mut dst = ExtentMap::new();

        let e1 = src.allocate(0, 4096).unwrap();
        assert_eq!(src.refcount(e1), Some(1));

        dst.clone_file(&mut src).unwrap();
        assert_eq!(src.refcount(e1), Some(2));
    }

    #[test]
    fn clone_file_sets_destination_refcount_to_one() {
        let mut src = ExtentMap::new();
        let mut dst = ExtentMap::new();

        let e1 = src.allocate(0, 4096).unwrap();

        dst.clone_file(&mut src).unwrap();
        assert_eq!(dst.refcount(e1), Some(1));
    }

    #[test]
    fn clone_file_source_refuses_empty() {
        let mut src = ExtentMap::new();
        let mut dst = ExtentMap::new();

        let err = dst.clone_file(&mut src).unwrap_err();
        assert_eq!(err, ExtentMapError::NotFound);
    }

    #[test]
    fn clone_file_refuses_overlapping_destination() {
        let mut src = ExtentMap::new();
        let mut dst = ExtentMap::new();

        src.allocate(0, 4096).unwrap();
        dst.allocate(0, 4096).unwrap();

        let err = dst.clone_file(&mut src).unwrap_err();
        assert_eq!(err, ExtentMapError::OverlappingExtent);
    }

    #[test]
    fn clone_file_refuses_partial_overlap() {
        let mut src = ExtentMap::new();
        let mut dst = ExtentMap::new();

        src.allocate(0, 8192).unwrap();
        dst.allocate(4096, 4096).unwrap();

        let err = dst.clone_file(&mut src).unwrap_err();
        assert_eq!(err, ExtentMapError::OverlappingExtent);
    }

    #[test]
    fn clone_file_allows_adjacent_no_overlap() {
        let mut src = ExtentMap::new();
        let mut dst = ExtentMap::new();

        // Allocate src first, then advance dst's ID counter to avoid collision.
        src.allocate(0, 4096).unwrap();
        dst.next_extent_id = src.next_extent_id + 100;
        dst.allocate(4096, 4096).unwrap();

        dst.clone_file(&mut src).unwrap();
        assert_eq!(dst.extent_count(), 2);
        assert!(dst.lookup(0).is_some());
        assert!(dst.lookup(4096).is_some());
    }

    #[test]
    fn multi_clone_refcount() {
        let mut src = ExtentMap::new();
        let mut dst_a = ExtentMap::new();
        let mut dst_b = ExtentMap::new();

        let e1 = src.allocate(0, 4096).unwrap();
        assert_eq!(src.refcount(e1), Some(1));

        dst_a.clone_file(&mut src).unwrap();
        assert_eq!(src.refcount(e1), Some(2));

        dst_b.clone_file(&mut src).unwrap();
        assert_eq!(src.refcount(e1), Some(3));
    }

    #[test]
    fn clone_then_unlink_source_refcount_one_file_still_live() {
        let mut src = ExtentMap::new();
        let mut dst = ExtentMap::new();

        let e1 = src.allocate(0, 4096).unwrap();
        dst.clone_file(&mut src).unwrap();

        // Source refcount is now 2 (original + clone).
        assert_eq!(src.refcount(e1), Some(2));

        // Free the source extent. Since refcount > 1, it should be deferred.
        src.free(e1).unwrap();
        assert_eq!(src.extent_count(), 1); // deferred, still present

        // Release the deferred hold and drain.
        src.extent_release(e1).unwrap();
        let freed = src.drain_deferred_frees(0);
        assert_eq!(freed, 1);

        // Source is now empty, but destination still has the extent.
        assert_eq!(src.extent_count(), 0);
        assert_eq!(dst.extent_count(), 1);
        assert!(dst.lookup(0).is_some());
        assert_eq!(dst.refcount(e1), Some(1));
    }

    #[test]
    fn clone_then_truncate_source() {
        let mut src = ExtentMap::new();
        let mut dst = ExtentMap::new();

        let e1 = src.allocate(0, 4096).unwrap();
        let e2 = src.allocate(4096, 4096).unwrap();
        dst.clone_file(&mut src).unwrap();

        assert_eq!(src.refcount(e1), Some(2));
        assert_eq!(src.refcount(e2), Some(2));

        // Free both source extents. Refcount is 2, so they are deferred.
        src.free(e1).unwrap();
        src.free(e2).unwrap();

        // Release and drain deferred frees.
        src.extent_release(e1).unwrap();
        src.extent_release(e2).unwrap();
        src.drain_deferred_frees(0);

        // Source extents are freed; destination still has both.
        assert_eq!(src.extent_count(), 0);
        assert_eq!(dst.extent_count(), 2);
        assert!(dst.lookup(0).is_some());
        assert!(dst.lookup(4096).is_some());
    }

    #[test]
    fn free_at_zero_refcount_removes_extent() {
        let mut m = ExtentMap::new();
        let eid = m.allocate(0, 4096).unwrap();
        assert_eq!(m.refcount(eid), Some(1));

        // Release to zero, then free.
        let is_zero = m.extent_release(eid).unwrap();
        assert!(is_zero);

        m.free(eid).unwrap();
        // After free, refcount=0 and extent is removed.
        assert_eq!(m.extent_count(), 0);
    }

    #[test]
    fn cross_pool_refusal() {
        let mut src = ExtentMap::new();
        let mut dst = ExtentMap::new();

        src.set_pool_id(1);
        dst.set_pool_id(2);

        src.allocate(0, 4096).unwrap();
        let err = dst.clone_file(&mut src).unwrap_err();
        assert_eq!(err, ExtentMapError::CrossPool);
    }

    #[test]
    fn same_pool_allowed() {
        let mut src = ExtentMap::new();
        let mut dst = ExtentMap::new();

        src.set_pool_id(7);
        dst.set_pool_id(7);

        src.allocate(0, 4096).unwrap();
        dst.clone_file(&mut src).unwrap();
        assert_eq!(dst.extent_count(), 1);
    }

    #[test]
    fn cross_pool_skips_when_one_has_no_pool_id() {
        let mut src = ExtentMap::new();
        let mut dst = ExtentMap::new();

        // Only source has pool_id; destination has none.
        src.set_pool_id(1);

        src.allocate(0, 4096).unwrap();
        dst.clone_file(&mut src).unwrap();
        assert_eq!(dst.extent_count(), 1);
    }

    #[test]
    fn clone_file_refcount_overflow_rejected() {
        let mut src = ExtentMap::new();
        let mut dst = ExtentMap::new();

        let eid = src.allocate(0, 4096).unwrap();
        // Manually set refcount to MAX_REFCOUNT.
        src.refcounts.insert(eid, EXTENT_MAP_MAX_REFCOUNT);

        let err = dst.clone_file(&mut src).unwrap_err();
        assert_eq!(err, ExtentMapError::RefCountOverflow);
        // Source should be unchanged.
        assert_eq!(src.refcount(eid), Some(EXTENT_MAP_MAX_REFCOUNT));
    }

    #[test]
    fn clone_file_preserves_locator_and_checksum() {
        let mut src = ExtentMap::new();
        let mut dst = ExtentMap::new();

        // Allocate and convert to DATA with a specific locator/checksum.
        let _eid = src.allocate(0, 4096).unwrap();
        let checksum = [0xAB; 32];
        src.inner_mut()
            .convert_unwritten_to_data(0, 4096, LocatorId(99), checksum, 42)
            .unwrap();
        src.refresh();

        dst.clone_file(&mut src).unwrap();

        let entry = dst.lookup(0).unwrap();
        assert!(entry.is_data());
        assert_eq!(entry.locator_id, LocatorId(99));
        assert_eq!(entry.checksum, [0xAB; 32]);
        assert_eq!(entry.birth_commit_group, 42);
        assert_eq!(entry.logical_offset, 0);
        assert_eq!(entry.length, 4096);
    }

    #[test]
    fn clone_file_multi_extent_refcounts_independent() {
        let mut src = ExtentMap::new();
        let mut dst = ExtentMap::new();

        let e1 = src.allocate(0, 4096).unwrap();
        let e2 = src.allocate(4096, 4096).unwrap();

        dst.clone_file(&mut src).unwrap();

        // Both extents should have refcount 2 in source.
        assert_eq!(src.refcount(e1), Some(2));
        assert_eq!(src.refcount(e2), Some(2));

        // Both extents should have refcount 1 in destination.
        assert_eq!(dst.refcount(e1), Some(1));
        assert_eq!(dst.refcount(e2), Some(1));
    }

    // -- InlineExtentMap serialize/deserialize tests --

    #[test]
    fn inline_serde_roundtrip_empty() {
        let map = InlineExtentMap::new();
        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();
        assert!(!buf.is_empty());

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = InlineExtentMap::deserialize(&mut cursor).unwrap();
        assert!(recon.entries.is_empty());
        assert_eq!(recon.header.entry_count, 0);
        assert!(recon.validate().is_ok());
    }

    #[test]
    fn inline_serde_roundtrip_populated() {
        let mut map = InlineExtentMap::new();
        map.insert_extent(&[
            ExtentMapEntryV2::new_data(0, 4096, LocatorId(1), [0xAA; 32], 1),
            ExtentMapEntryV2::new_data(8192, 4096, LocatorId(2), [0xBB; 32], 1),
        ])
        .unwrap();

        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = InlineExtentMap::deserialize(&mut cursor).unwrap();
        assert_eq!(recon.entries.len(), 2);
        assert_eq!(recon.entries[0].logical_offset, 0);
        assert_eq!(recon.entries[0].length, 4096);
        assert_eq!(recon.entries[1].logical_offset, 8192);
        assert_eq!(recon.entries[1].length, 4096);
        assert!(recon.validate().is_ok());
    }

    #[test]
    fn inline_serde_wrong_magic_rejected() {
        let buf = b"BADC".to_vec();
        let mut cursor = std::io::Cursor::new(&buf);
        let err = InlineExtentMap::deserialize(&mut cursor).unwrap_err();
        assert_eq!(err, ExtentMapError::WrongVersion);
    }

    #[test]
    fn inline_serde_wrong_version_rejected() {
        let buf = b"VX11\x63\x00".to_vec();
        let mut cursor = std::io::Cursor::new(&buf);
        let err = InlineExtentMap::deserialize(&mut cursor).unwrap_err();
        assert_eq!(err, ExtentMapError::WrongVersion);
    }

    #[test]
    fn inline_serde_truncated_data_rejected() {
        let mut map = InlineExtentMap::new();
        map.insert_extent(&[ExtentMapEntryV2::new_data(
            0,
            4096,
            LocatorId(1),
            [0u8; 32],
            0,
        )])
        .unwrap();
        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        let half = buf.len() / 2;
        let mut cursor = std::io::Cursor::new(&buf[..half]);
        let err = InlineExtentMap::deserialize(&mut cursor).unwrap_err();
        assert_eq!(err, ExtentMapError::Corrupt);
    }

    #[test]
    fn inline_serde_roundtrip_with_unwritten() {
        let mut map = InlineExtentMap::new();
        map.fallocate(0, 8192, false).unwrap();
        map.convert_unwritten_to_data(2048, 4096, LocatorId(5), [0xCC; 32], 1)
            .unwrap();

        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = InlineExtentMap::deserialize(&mut cursor).unwrap();
        assert_eq!(recon.entries.len(), 3);
        assert!(recon.validate().is_ok());
    }
    // =====================================================================
    // Boundary condition property tests — issue #5383
    // =====================================================================

    #[test]
    fn boundary_merge_adjacent_same_type_same_locator_same_checksum() {
        let mut map = make_map(&[data(0, 4096, 1), data(4096, 4096, 1)]);
        // Same locator (=same checksum via helper), same type → should merge.
        map.insert_single(&data(2048, 2048, 1)).unwrap();
        assert_eq!(
            map.entries.len(),
            1,
            "adjacent same-type same-locator extents must merge into one"
        );
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 8192);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn boundary_merge_adjacent_different_checksums_no_merge() {
        // data(0,4096,1) has checksum derived from locator=1,
        // data(4096,4096,2) has checksum derived from locator=2.
        // They are adjacent, same type, but different checksums → no merge.
        let map = make_map(&[data(0, 4096, 1), data(4096, 4096, 2)]);
        assert_eq!(
            map.entries.len(),
            2,
            "adjacent extents with different checksums must NOT merge"
        );
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 4096);
        assert_eq!(map.entries[1].logical_offset, 4096);
        assert_eq!(map.entries[1].length, 4096);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn boundary_merge_adjacent_different_types_no_merge() {
        let map = make_map(&[data(0, 4096, 1), unwritten(4096, 4096)]);
        assert_eq!(
            map.entries.len(),
            2,
            "adjacent extents of different types must NOT merge"
        );
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[1].logical_offset, 4096);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn punch_hole_exact_fit_removes_extent_entirely() {
        let mut map = make_map(&[data(0, 4096, 1)]);
        let freed = map.punch_hole(0, 4096).unwrap();
        assert_eq!(freed.len(), 1);
        assert_eq!(freed[0].logical_offset, 0);
        assert_eq!(freed[0].length, 4096);
        assert!(
            map.entries.is_empty(),
            "exact-fit punch_hole must remove the extent entirely"
        );
        assert!(map.validate().is_ok());
    }

    #[test]
    fn punch_hole_start_boundary_no_zero_length_fragment() {
        // Hole starts exactly at the extent start, so no "before" fragment.
        let mut map = make_map(&[data(0, 12288, 1)]);
        let freed = map.punch_hole(0, 4096).unwrap();
        assert_eq!(freed.len(), 1);
        assert_eq!(freed[0].logical_offset, 0);
        assert_eq!(freed[0].length, 4096);
        assert_eq!(
            map.entries.len(),
            1,
            "only the remaining tail fragment should exist"
        );
        assert_eq!(map.entries[0].logical_offset, 4096);
        assert_eq!(map.entries[0].length, 8192);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn punch_hole_end_boundary_no_zero_length_fragment() {
        // Hole ends exactly at the extent end, so no "after" fragment.
        let mut map = make_map(&[data(0, 12288, 1)]);
        let freed = map.punch_hole(8192, 4096).unwrap();
        assert_eq!(freed.len(), 1);
        assert_eq!(freed[0].logical_offset, 8192);
        assert_eq!(freed[0].length, 4096);
        assert_eq!(
            map.entries.len(),
            1,
            "only the remaining head fragment should exist"
        );
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 8192);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn punch_hole_superset_removes_multiple_extents() {
        let mut map = make_map(&[data(0, 4096, 1), data(4096, 4096, 2), data(8192, 4096, 3)]);
        // Hole [1024, 12288) — superset of all three extents with overhang.
        // Extents: [0,4096)@1, [4096,8192)@2, [8192,12288)@3.
        // Only [0,1024) from the first extent survives.
        let freed = map.punch_hole(1024, 11264).unwrap();
        assert_eq!(freed.len(), 3, "all three extents must be freed");
        assert_eq!(freed[0].logical_offset, 1024);
        assert_eq!(freed[0].length, 3072);
        assert_eq!(freed[1].logical_offset, 4096);
        assert_eq!(freed[1].length, 4096);
        assert_eq!(freed[2].logical_offset, 8192);
        assert_eq!(freed[2].length, 4096);
        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 1024);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn punch_hole_exact_boundary_middle_extent() {
        // Three extents, punch the middle one exactly.
        let mut map = make_map(&[data(0, 4096, 1), data(4096, 4096, 2), data(8192, 4096, 3)]);
        let freed = map.punch_hole(4096, 4096).unwrap();
        assert_eq!(freed.len(), 1);
        assert_eq!(freed[0].logical_offset, 4096);
        assert_eq!(freed[0].length, 4096);
        assert_eq!(
            map.entries.len(),
            2,
            "middle extent removed, edges preserved"
        );
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 4096);
        assert_eq!(map.entries[1].logical_offset, 8192);
        assert_eq!(map.entries[1].length, 4096);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn collapse_range_exact_fit_removes_and_shifts() {
        let mut map = make_map(&[data(0, 4096, 1), data(4096, 4096, 2), data(8192, 4096, 3)]);
        map.header.file_size = 12288;
        let freed = map.collapse_range(4096, 4096).unwrap();
        assert_eq!(freed.len(), 1);
        assert_eq!(freed[0].logical_offset, 4096);
        assert_eq!(freed[0].length, 4096);
        assert_eq!(map.entries.len(), 2);
        // Third extent should shift left by 4096.
        assert_eq!(map.entries[1].logical_offset, 4096);
        assert_eq!(map.entries[1].length, 4096);
        assert_eq!(map.header.file_size, 8192);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn collapse_range_boundary_no_zero_length_fragment() {
        let mut map = make_map(&[data(0, 12288, 1)]);
        map.header.file_size = 12288;
        // Collapse the first 4096 bytes exactly.
        let freed = map.collapse_range(0, 4096).unwrap();
        assert_eq!(freed.len(), 1);
        assert_eq!(map.entries.len(), 1);
        // Remaining extent should be [0, 8192) after shift.
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 8192);
        assert_eq!(map.header.file_size, 8192);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn collapse_range_end_boundary_no_zero_length_fragment() {
        let mut map = make_map(&[data(0, 12288, 1)]);
        map.header.file_size = 12288;
        // Collapse the last 4096 bytes exactly.
        let freed = map.collapse_range(8192, 4096).unwrap();
        assert_eq!(freed.len(), 1);
        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 8192);
        assert_eq!(map.header.file_size, 8192);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_adjacent_left_merges_with_same_type_same_checksum() {
        // Existing: [4096, 8192) with locator 1.
        // Insert:   [0, 4096) with locator 1 → same checksum, should merge.
        let mut map = make_map(&[data(4096, 4096, 1)]);
        map.insert_extent(&[data(0, 4096, 1)]).unwrap();
        assert_eq!(
            map.entries.len(),
            1,
            "adjacent insert with same type+locator must merge"
        );
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 8192);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_adjacent_right_merges_with_same_type_same_checksum() {
        let mut map = make_map(&[data(0, 4096, 1)]);
        map.insert_extent(&[data(4096, 4096, 1)]).unwrap();
        assert_eq!(
            map.entries.len(),
            1,
            "adjacent insert right must merge with same type+locator"
        );
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 8192);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_adjacent_different_checksums_no_merge() {
        let mut map = make_map(&[data(0, 4096, 1)]);
        // data(4096,4096,2) has different checksum → no merge.
        map.insert_extent(&[data(4096, 4096, 2)]).unwrap();
        assert_eq!(
            map.entries.len(),
            2,
            "adjacent insert with different checksum must NOT merge"
        );
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 4096);
        assert_eq!(map.entries[1].logical_offset, 4096);
        assert_eq!(map.entries[1].length, 4096);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_bridges_two_adjacent_same_type_extents() {
        // Two extents [0,4096) with loc=1 and [8192,4096) with loc=1,
        // insert [4096,4096) with loc=1 → all three merge.
        let mut map = make_map(&[data(0, 4096, 1), data(8192, 4096, 1)]);
        map.insert_extent(&[data(4096, 4096, 1)]).unwrap();
        assert_eq!(map.entries.len(), 1, "bridging insert must merge all three");
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 12288);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn zero_length_never_present_after_punch_hole_chain() {
        let mut map = make_map(&[data(0, 16384, 1)]);
        // Punch a series of holes that exactly align with extent boundaries.
        map.punch_hole(0, 4096).unwrap();
        map.punch_hole(4096, 4096).unwrap();
        map.punch_hole(8192, 4096).unwrap();
        map.punch_hole(12288, 4096).unwrap();
        assert!(map.entries.is_empty());
        // No zero-length entries survived.
        assert_eq!(map.header.entry_count, 0);
        assert_eq!(map.header.alloc_bytes, 0);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn zero_length_never_present_after_collapse_chain() {
        let mut map = make_map(&[data(0, 4096, 1), data(4096, 4096, 2)]);
        map.header.file_size = 8192;
        // Collapse each extent exactly.
        map.collapse_range(0, 4096).unwrap();
        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 4096);
        // Second collapse.
        map.collapse_range(0, 4096).unwrap();
        assert!(map.entries.is_empty());
        assert_eq!(map.header.entry_count, 0);
        assert_eq!(map.header.alloc_bytes, 0);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn truncate_exact_extent_boundary_no_zero_length() {
        let mut map = make_map(&[data(0, 4096, 1), data(4096, 4096, 2)]);
        // Truncate exactly at the boundary between the two extents.
        let freed = map.truncate(4096).unwrap();
        assert_eq!(freed.len(), 1);
        assert_eq!(freed[0].logical_offset, 4096);
        assert_eq!(freed[0].length, 4096);
        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 4096);
        assert_eq!(map.header.file_size, 4096);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn invariants_hold_after_mixed_operations() {
        let mut map = InlineExtentMap::new();
        // Allocate three extents with gaps.
        map.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)])
            .unwrap();
        assert_eq!(map.entries.len(), 3);
        // Punch hole exactly matching middle extent [8192, 12288).
        let freed = map.punch_hole(8192, 4096).unwrap();
        assert_eq!(freed.len(), 1);
        assert!(
            !map.entries.iter().any(|e| e.length == 0),
            "no zero-length extents after punch_hole"
        );
        assert_eq!(map.entries.len(), 2);
        // Insert filling the gap [4096, 8192) with same locator as first → merges.
        map.insert_extent(&[data(4096, 4096, 1)]).unwrap();
        // Should merge [0,4096) + [4096,8192) → [0,8192) since same locator+checksum.
        assert_eq!(map.entries.len(), 2);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 8192);
        // Collapse the merged first extent. Remaining extent [16384,4096) shifts left by 8192.
        map.header.file_size = 20480;
        let freed = map.collapse_range(0, 8192).unwrap();
        assert_eq!(freed.len(), 1);
        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].logical_offset, 8192);
        assert_eq!(map.entries[0].length, 4096);
        assert_eq!(map.header.file_size, 12288);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn punch_hole_in_middle_no_zero_length_fragments() {
        // Punch hole that aligns exactly with start and end of internal boundaries.
        let mut map = make_map(&[
            data(0, 4096, 1),
            data(4096, 4096, 2),
            data(8192, 4096, 3),
            data(12288, 4096, 4),
        ]);
        // Hole exactly covers the middle two extents: [4096, 12288).
        let freed = map.punch_hole(4096, 8192).unwrap();
        assert_eq!(freed.len(), 2);
        assert_eq!(map.entries.len(), 2);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 4096);
        assert_eq!(map.entries[1].logical_offset, 12288);
        assert_eq!(map.entries[1].length, 4096);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_at_exact_existing_boundary_splits_and_overwrites() {
        let mut map = make_map(&[data(0, 8192, 1)]);
        // Insert at exact middle boundary [4096, 4096) with different locator.
        map.insert_extent(&[data(4096, 4096, 2)]).unwrap();
        assert_eq!(map.entries.len(), 2);
        assert_eq!(map.entries[0].logical_offset, 0);
        assert_eq!(map.entries[0].length, 4096);
        assert_eq!(map.entries[1].logical_offset, 4096);
        assert_eq!(map.entries[1].length, 4096);
        assert!(map.validate().is_ok());
    }
}
