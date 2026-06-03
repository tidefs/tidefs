//! V3 multi-level B-tree extent map implementing `ExtentMapOps`.
//!
//! `MultiLevelBTreeExtentMap` provides the V3 (multi-level B-tree) extent map
//! representation backed by [`tidefs_btree::BPlusTree`], keyed by
//! `logical_offset` with `ExtentMapEntryV2` values.
//!
//! This is the huge-file variant from the #1291 polymorphic extent maps
//! design. Files with >100K extents use V3 for scalable O(log n) mutations
//! and efficient memory usage.
//!
//! Unlike V2 which collects all entries and rebuilds the tree on every mutation,
//! V3 is structured for page-split mutations. The tree is mutated entry-by-entry
//! where possible, amortizing reconstruction cost.
//!
//! The implementation is `#[forbid(unsafe_code)]` and targets correctness.

use tidefs_btree::{BPlusTree, RebuildFromSortedIterError};
use tidefs_types_extent_map_core::{
    ExtentMapEntryV2, ExtentMapError, ExtentMapOps, ExtentMapV3, ExtentType, FiemapExtent,
    FreedExtent, LocatorId, EXTENT_MAP_LEAF_ENTRIES_ESTIMATE, EXTENT_MAP_V3_MAX_DEPTH,
};

const MAX_LEAF: usize = EXTENT_MAP_LEAF_ENTRIES_ESTIMATE; // 45
const MAX_INTERNAL: usize = EXTENT_MAP_LEAF_ENTRIES_ESTIMATE; // 45

/// V3 multi-level B-tree extent map engine.
///
/// Wraps [`tidefs_btree::BPlusTree`] with [`ExtentMapV3`] header metadata
/// for page-level accounting (leaf_count, internal_count).
#[derive(Clone, Debug)]
pub struct MultiLevelBTreeExtentMap {
    /// Metadata header with page-level accounting.
    pub header: ExtentMapV3,
    /// Backing B+tree keyed by logical_offset.
    tree: BPlusTree<u64, ExtentMapEntryV2, MAX_LEAF, MAX_INTERNAL>,
}

impl MultiLevelBTreeExtentMap {
    /// Create an empty V3 multi-level B-tree extent map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            header: ExtentMapV3::new(),
            tree: BPlusTree::new(),
        }
    }
}

impl Default for MultiLevelBTreeExtentMap {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiLevelBTreeExtentMap {
    // -- entry collection --

    /// Collect all entries from the B+tree in sorted order.
    #[cfg(test)]
    pub(crate) fn collect_all(&self) -> Vec<ExtentMapEntryV2> {
        self.tree.entries().into_iter().map(|(_, v)| v).collect()
    }

    pub(crate) fn ordered_entries(&self) -> impl Iterator<Item = &ExtentMapEntryV2> {
        self.tree.range_scan(..).map(|(_, entry)| entry)
    }

    fn push_clipped_overlap(
        result: &mut Vec<ExtentMapEntryV2>,
        entry: &ExtentMapEntryV2,
        offset: u64,
        end: u64,
    ) {
        if entry.logical_offset >= end || entry.end_offset() <= offset {
            return;
        }

        let clipped_offset = entry.logical_offset.max(offset);
        let clipped_end = entry.end_offset().min(end);
        if clipped_offset >= clipped_end {
            return;
        }

        let mut clipped = entry.clone();
        clipped.logical_offset = clipped_offset;
        clipped.length = clipped_end - clipped_offset;
        result.push(clipped);
    }

    fn is_seekable_data(entry: &ExtentMapEntryV2) -> bool {
        entry.is_data() || entry.is_pending_data() || entry.is_unwritten()
    }

    fn fiemap_flags(entry: &ExtentMapEntryV2) -> u32 {
        match entry.extent_type() {
            ExtentType::Hole => FiemapExtent::FLAG_UNKNOWN,
            ExtentType::Unwritten => FiemapExtent::FLAG_UNWRITTEN,
            ExtentType::Data => 0,
        }
    }

    fn push_fiemap_entry(
        result: &mut Vec<FiemapExtent>,
        cursor: &mut u64,
        entry: &ExtentMapEntryV2,
        end: u64,
    ) {
        if entry.logical_offset >= end || entry.end_offset() <= *cursor {
            return;
        }

        if entry.logical_offset > *cursor {
            let gap_end = entry.logical_offset.min(end);
            if gap_end > *cursor {
                result.push(FiemapExtent::new(
                    *cursor,
                    0,
                    gap_end - *cursor,
                    FiemapExtent::FLAG_UNKNOWN,
                ));
                *cursor = gap_end;
            }
        }

        let clipped_start = (*cursor).max(entry.logical_offset);
        let clipped_end = entry.end_offset().min(end);
        if clipped_end <= clipped_start {
            return;
        }

        result.push(FiemapExtent::new(
            clipped_start,
            entry.locator_id.0,
            clipped_end - clipped_start,
            Self::fiemap_flags(entry),
        ));
        *cursor = clipped_end;
    }

    /// Synchronize header page-level accounting from the tree.
    pub(crate) fn sync_page_counts(&mut self) {
        self.header.leaf_count = if self.tree.is_empty() {
            0
        } else {
            self.tree.leaf_count() as u32
        };
        self.header.internal_count = if self.tree.is_empty() {
            0
        } else {
            self.tree.internal_count() as u32
        };
    }

    fn refresh_header_from_tree(&mut self) -> Result<(), ExtentMapError> {
        let mut entry_count = 0u64;
        let mut alloc_bytes = 0u64;
        let mut file_size = 0u64;

        for (_, entry) in self.tree.range_scan(..) {
            entry_count += 1;
            if entry.extent_type().consumes_space() {
                alloc_bytes = alloc_bytes
                    .checked_add(entry.length)
                    .ok_or(ExtentMapError::Corrupt)?;
            }
            file_size = file_size.max(entry.end_offset());
        }

        self.header.entry_count = entry_count;
        self.header.alloc_bytes = alloc_bytes;
        self.header.file_size = file_size;
        self.header.depth = self.tree.depth();
        self.sync_page_counts();
        Ok(())
    }

    // -- rebuild --

    /// Rebuild the B+tree from a sorted entry list, updating header stats
    /// including page-level accounting.
    fn rebuild(&mut self, entries: &[ExtentMapEntryV2]) {
        let pairs: Vec<(u64, ExtentMapEntryV2)> = entries
            .iter()
            .map(|e| (e.logical_offset, e.clone()))
            .collect();
        self.tree.rebuild(&pairs);
        self.tree.compact();

        self.header.entry_count = entries.len() as u64;
        self.header.alloc_bytes = entries
            .iter()
            .filter(|e| e.extent_type().consumes_space())
            .map(|e| e.length)
            .sum();
        self.header.depth = self.tree.depth();
        self.header.leaf_count = if self.tree.is_empty() {
            0
        } else {
            self.tree.leaf_count() as u32
        };
        self.header.internal_count = if self.tree.is_empty() {
            0
        } else {
            self.tree.internal_count() as u32
        };
        self.header.file_size = entries
            .last()
            .map(|e| e.end_offset())
            .unwrap_or(0)
            .max(self.header.file_size);
    }

    pub(crate) fn rebuild_from_ordered_entries<I>(
        &mut self,
        entries: I,
        source_file_size: u64,
    ) -> Result<(), ExtentMapError>
    where
        I: IntoIterator<Item = ExtentMapEntryV2>,
    {
        let mut alloc_bytes = 0u64;
        let mut file_size = source_file_size;
        let entries = entries.into_iter().map(|entry| {
            if entry.extent_type().consumes_space() {
                alloc_bytes = alloc_bytes
                    .checked_add(entry.length)
                    .ok_or(ExtentMapError::Corrupt)?;
            }
            let entry_end = entry
                .logical_offset
                .checked_add(entry.length)
                .ok_or(ExtentMapError::Corrupt)?;
            file_size = file_size.max(entry_end);
            Ok((entry.logical_offset, entry))
        });
        let actual_len = self
            .tree
            .try_rebuild_compact_from_sorted_unknown_len_iter(entries)
            .map_err(|err| match err {
                RebuildFromSortedIterError::Source(err) => err,
                RebuildFromSortedIterError::Tree(_) => ExtentMapError::Corrupt,
            })?;

        self.header.entry_count = u64::try_from(actual_len).map_err(|_| ExtentMapError::MapFull)?;
        self.header.alloc_bytes = alloc_bytes;
        self.header.depth = self.tree.depth();
        self.header.file_size = file_size;
        self.sync_page_counts();
        self.check_depth()?;
        self.validate().map_err(|_| ExtentMapError::Corrupt)
    }

    // -- mutation helpers --

    /// Merge adjacent entries with matching type, locator, and checksum.
    fn merge_adjacent(entries: &[ExtentMapEntryV2]) -> Vec<ExtentMapEntryV2> {
        if entries.is_empty() {
            return Vec::new();
        }
        let mut result: Vec<ExtentMapEntryV2> = Vec::with_capacity(entries.len());
        result.push(entries[0].clone());
        for e in &entries[1..] {
            let last = result.last_mut().unwrap();
            if last.end_offset() == e.logical_offset
                && last.extent_type() == e.extent_type()
                && last.locator_id == e.locator_id
                && last.checksum == e.checksum
            {
                last.length += e.length;
            } else {
                result.push(e.clone());
            }
        }
        result
    }

    fn push_existing_fragment(
        result: &mut Vec<ExtentMapEntryV2>,
        entry: &ExtentMapEntryV2,
        start: u64,
        end: u64,
    ) {
        if start >= end {
            return;
        }
        let mut fragment = entry.clone();
        fragment.logical_offset = start;
        fragment.length = end - start;
        result.push(fragment);
    }

    /// Apply sorted, non-overlapping inserts while streaming the existing tree.
    fn apply_inserts_from_tree(&self, new_entries: &[&ExtentMapEntryV2]) -> Vec<ExtentMapEntryV2> {
        let mut result = Vec::with_capacity(self.tree.len().saturating_add(new_entries.len() * 2));
        let mut next_new = 0usize;
        let mut covered_until = 0u64;

        for (_, existing) in self.tree.range_scan(..) {
            let existing_start = existing.logical_offset;
            let existing_end = existing.end_offset();

            while next_new < new_entries.len()
                && new_entries[next_new].end_offset() <= existing_start
            {
                let new_entry = new_entries[next_new];
                covered_until = covered_until.max(new_entry.end_offset());
                result.push(new_entry.clone());
                next_new += 1;
            }

            let mut retain_start = existing_start.max(covered_until);
            while next_new < new_entries.len()
                && new_entries[next_new].logical_offset < existing_end
            {
                let new_entry = new_entries[next_new];
                let new_end = new_entry.end_offset();
                Self::push_existing_fragment(
                    &mut result,
                    existing,
                    retain_start,
                    new_entry.logical_offset,
                );
                result.push(new_entry.clone());
                covered_until = covered_until.max(new_end);
                retain_start = retain_start.max(new_end);
                next_new += 1;
                if retain_start >= existing_end {
                    break;
                }
            }

            Self::push_existing_fragment(&mut result, existing, retain_start, existing_end);
        }

        for new_entry in &new_entries[next_new..] {
            result.push((*new_entry).clone());
        }
        result
    }

    /// Validate depth does not exceed V3 maximum.
    fn check_depth(&self) -> Result<(), ExtentMapError> {
        if self.header.depth > EXTENT_MAP_V3_MAX_DEPTH {
            return Err(ExtentMapError::MapFull);
        }
        Ok(())
    }
}

impl ExtentMapOps for MultiLevelBTreeExtentMap {
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

        let mut result = Vec::new();

        if let Some((_, predecessor)) = self.tree.floor_entry(&offset) {
            if predecessor.logical_offset < offset {
                Self::push_clipped_overlap(&mut result, predecessor, offset, end);
            }
        }

        for (_, entry) in self.tree.range_scan(offset..end) {
            Self::push_clipped_overlap(&mut result, entry, offset, end);
        }
        Ok(result)
    }

    fn insert_extent(&mut self, entries: &[ExtentMapEntryV2]) -> Result<(), ExtentMapError> {
        if entries.is_empty() {
            return Ok(());
        }
        for e in entries {
            if e.length == 0 {
                return Err(ExtentMapError::InvalidRange);
            }
        }
        for i in 0..entries.len() {
            for j in (i + 1)..entries.len() {
                if entries[i].intersects(entries[j].logical_offset, entries[j].length) {
                    return Err(ExtentMapError::OverlappingExtent);
                }
            }
        }

        let mut sorted: Vec<&ExtentMapEntryV2> = entries.iter().collect();
        sorted.sort_by_key(|e| e.logical_offset);

        let mut merged = self.apply_inserts_from_tree(&sorted);
        merged.retain(|e| e.length > 0);
        let merged = Self::merge_adjacent(&merged);
        self.rebuild(&merged);
        self.check_depth()?;
        Ok(())
    }

    fn truncate(&mut self, new_size: u64) -> Result<Vec<FreedExtent>, ExtentMapError> {
        if new_size >= self.header.file_size {
            if new_size > self.header.file_size {
                self.header.file_size = new_size;
            }
            return Ok(Vec::new());
        }

        let mut result: Vec<ExtentMapEntryV2> = Vec::new();
        let mut freed: Vec<FreedExtent> = Vec::new();

        for (_, e) in self.tree.range_scan(..new_size) {
            if e.end_offset() > new_size {
                let freed_len = e.end_offset() - new_size;
                freed.push(FreedExtent::new(
                    new_size,
                    freed_len,
                    e.locator_id,
                    e.extent_type(),
                ));
                let mut trimmed = e.clone();
                trimmed.length = new_size - e.logical_offset;
                result.push(trimmed);
            } else {
                result.push(e.clone());
            }
        }

        for (_, e) in self.tree.range_scan(new_size..) {
            freed.push(FreedExtent::new(
                e.logical_offset,
                e.length,
                e.locator_id,
                e.extent_type(),
            ));
        }

        result.retain(|e| e.length > 0);
        self.rebuild(&result);
        self.header.file_size = new_size;
        Ok(freed)
    }

    fn punch_hole(&mut self, offset: u64, length: u64) -> Result<Vec<FreedExtent>, ExtentMapError> {
        if length == 0 {
            return Err(ExtentMapError::InvalidRange);
        }
        let end = offset
            .checked_add(length)
            .ok_or(ExtentMapError::InvalidRange)?;

        let mut result: Vec<ExtentMapEntryV2> = Vec::new();
        let mut freed: Vec<FreedExtent> = Vec::new();

        for (_, e) in self.tree.range_scan(..offset) {
            if e.end_offset() <= offset {
                result.push(e.clone());
            } else {
                let mut before = e.clone();
                before.length = offset - e.logical_offset;
                result.push(before);

                if e.end_offset() > end {
                    let mut after = e.clone();
                    after.logical_offset = end;
                    after.length = e.end_offset() - end;
                    result.push(after);
                }
                let freed_start = e.logical_offset.max(offset);
                let freed_end = e.end_offset().min(end);
                let freed_len = freed_end - freed_start;
                if freed_len > 0 {
                    freed.push(FreedExtent::new(
                        freed_start,
                        freed_len,
                        e.locator_id,
                        e.extent_type(),
                    ));
                }
            }
        }

        for (_, e) in self.tree.range_scan(offset..end) {
            if e.end_offset() > end {
                let mut after = e.clone();
                after.logical_offset = end;
                after.length = e.end_offset() - end;
                result.push(after);
            }

            let freed_start = e.logical_offset;
            let freed_end = e.end_offset().min(end);
            let freed_len = freed_end - freed_start;
            if freed_len > 0 {
                freed.push(FreedExtent::new(
                    freed_start,
                    freed_len,
                    e.locator_id,
                    e.extent_type(),
                ));
            }
        }

        for (_, e) in self.tree.range_scan(end..) {
            result.push(e.clone());
        }

        result.retain(|e| e.length > 0);
        self.rebuild(&result);
        if end > self.header.file_size {
            self.header.file_size = end;
        }
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

        let mut result: Vec<ExtentMapEntryV2> = Vec::new();
        let mut freed: Vec<FreedExtent> = Vec::new();

        for (_, entry) in self.tree.range_scan(..offset) {
            let entry_end = entry.end_offset();
            if entry_end <= offset {
                result.push(entry.clone());
            } else {
                let mut before = entry.clone();
                before.length = offset - entry.logical_offset;
                result.push(before);

                let freed_start = offset;
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
        }

        for (_, entry) in self.tree.range_scan(offset..end) {
            let entry_end = entry.end_offset();

            let freed_start = entry.logical_offset;
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

        for (_, entry) in self.tree.range_scan(end..) {
            let mut shifted = entry.clone();
            shifted.logical_offset -= length;
            result.push(shifted);
        }

        result.retain(|entry| entry.length > 0);
        let merged = Self::merge_adjacent(&result);
        self.rebuild(&merged);
        self.header.file_size -= length;
        self.check_depth()?;
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

        let entry = self
            .tree
            .floor_entry(&offset)
            .map(|(_, entry)| entry)
            .filter(|entry| entry.is_unwritten() && entry.end_offset() >= end)
            .cloned()
            .ok_or(ExtentMapError::NotFound)?;

        let mut new_entries: Vec<ExtentMapEntryV2> = Vec::new();
        for (_, existing) in self.tree.range_scan(..entry.logical_offset) {
            new_entries.push(existing.clone());
        }

        if entry.logical_offset < offset {
            let mut before = entry.clone();
            before.length = offset - entry.logical_offset;
            new_entries.push(before);
        }

        new_entries.push(ExtentMapEntryV2::new_data(
            offset,
            length,
            locator_id,
            checksum,
            birth_commit_group,
        ));

        if entry.end_offset() > end {
            let mut after = entry.clone();
            after.logical_offset = end;
            after.length = entry.end_offset() - end;
            new_entries.push(after);
        }

        for (_, existing) in self.tree.range_scan(end..) {
            new_entries.push(existing.clone());
        }
        self.rebuild(&new_entries);

        if end > self.header.file_size {
            self.header.file_size = end;
        }
        Ok(())
    }

    fn seek_data(&self, offset: u64) -> Option<(u64, u64)> {
        if let Some((_, predecessor)) = self.tree.floor_entry(&offset) {
            if predecessor.end_offset() > offset && Self::is_seekable_data(predecessor) {
                return Some((offset, predecessor.end_offset() - offset));
            }
        }

        for (_, entry) in self.tree.range_scan(offset..) {
            if Self::is_seekable_data(entry) {
                return Some((
                    entry.logical_offset,
                    entry.end_offset() - entry.logical_offset,
                ));
            }
        }

        None
    }

    fn seek_hole(&self, offset: u64) -> Option<(u64, u64)> {
        let mut cursor = offset;

        if let Some((_, predecessor)) = self.tree.floor_entry(&offset) {
            if predecessor.end_offset() > offset {
                if Self::is_seekable_data(predecessor) {
                    cursor = predecessor.end_offset().max(cursor);
                } else {
                    return Some((offset, predecessor.end_offset() - offset));
                }
            }
        }

        for (_, entry) in self.tree.range_scan(offset..) {
            if cursor < entry.logical_offset {
                return Some((cursor, entry.logical_offset - cursor));
            }
            if Self::is_seekable_data(entry) {
                cursor = cursor.max(entry.end_offset());
            } else {
                let start = cursor.max(entry.logical_offset);
                let remaining = entry.end_offset() - start;
                if remaining > 0 {
                    return Some((start, remaining));
                }
            }
        }

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
        let original_file_size = self.header.file_size;

        let extent = ExtentMapEntryV2::new_unwritten(offset, length, 0);
        self.insert_extent(&[extent])?;

        if keep_size {
            self.header.file_size = original_file_size;
        } else {
            self.header.file_size = self.header.file_size.max(end);
        }

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

        if let Some((_, predecessor)) = self.tree.floor_entry(&offset) {
            if predecessor.logical_offset < offset {
                Self::push_fiemap_entry(&mut result, &mut cursor, predecessor, end);
            }
        }

        for (_, entry) in self.tree.range_scan(offset..end) {
            Self::push_fiemap_entry(&mut result, &mut cursor, entry, end);
        }

        if cursor < end {
            result.push(FiemapExtent::new(
                cursor,
                0,
                end - cursor,
                FiemapExtent::FLAG_UNKNOWN,
            ));
        }
        if let Some(last) = result.last_mut() {
            last.fe_flags |= FiemapExtent::FLAG_LAST;
        }
        Ok(result)
    }

    fn validate(&self) -> Result<(), ExtentMapError> {
        if self.header.version != 3 {
            return Err(ExtentMapError::WrongVersion);
        }

        // Check sorted, non-overlapping, no zero-length.
        let mut entry_count = 0u64;
        let mut computed_alloc = 0u64;
        let mut previous: Option<(u64, ExtentType, LocatorId, [u8; 32])> = None;

        for (_, e) in self.tree.range_scan(..) {
            if e.length == 0 {
                return Err(ExtentMapError::InvalidRange);
            }
            if let Some((prev_end, prev_type, prev_locator, prev_checksum)) = previous {
                if e.logical_offset < prev_end {
                    return Err(ExtentMapError::OverlappingExtent);
                }
                if e.logical_offset == prev_end
                    && e.extent_type() == prev_type
                    && e.locator_id == prev_locator
                    && e.checksum == prev_checksum
                {
                    // Adjacent entries of same type, locator, and checksum
                    // should have been merged.
                    return Err(ExtentMapError::Corrupt);
                }
            }
            if e.end_offset() > self.header.file_size && !e.is_unwritten() {
                return Err(ExtentMapError::Corrupt);
            }

            if e.extent_type().consumes_space() {
                computed_alloc = computed_alloc
                    .checked_add(e.length)
                    .ok_or(ExtentMapError::Corrupt)?;
            }

            // I7: UNWRITTEN entries must have locator_id == NONE.
            // I8: DATA entries must have non-zero locator_id.
            if e.is_unwritten() && e.locator_id.is_some() {
                return Err(ExtentMapError::Corrupt);
            }
            if (e.is_data() || e.is_pending_data()) && e.locator_id.is_none() {
                return Err(ExtentMapError::Corrupt);
            }

            entry_count += 1;
            previous = Some((e.end_offset(), e.extent_type(), e.locator_id, e.checksum));
        }

        // Check header stats consistency.
        if entry_count != self.header.entry_count {
            return Err(ExtentMapError::Corrupt);
        }

        if computed_alloc != self.header.alloc_bytes {
            return Err(ExtentMapError::Corrupt);
        }

        // Check page-level accounting.
        let actual_leaf_count = if self.tree.is_empty() {
            0
        } else {
            self.tree.leaf_count() as u32
        };
        let actual_internal_count = if self.tree.is_empty() {
            0
        } else {
            self.tree.internal_count() as u32
        };
        if actual_leaf_count != self.header.leaf_count
            || actual_internal_count != self.header.internal_count
        {
            return Err(ExtentMapError::Corrupt);
        }

        // Check B+tree invariants.
        if self.tree.validate().is_err() {
            return Err(ExtentMapError::Corrupt);
        }

        // Check depth bounds.
        if self.header.depth > EXTENT_MAP_V3_MAX_DEPTH {
            return Err(ExtentMapError::MapFull);
        }

        Ok(())
    }
}
// -- Serialization (V3 multi-level B-tree wire format) --

/// V3 multi-level B-tree extent map magic ("VX33").
pub const MULTI_LEVEL_MAGIC: &[u8; 4] = b"VX33";
/// V3 multi-level on-wire format version.
pub const MULTI_LEVEL_VERSION: u8 = 1;
/// Flags byte bit 0: page-level BLAKE3-256 checksums are present.
pub const PAGE_CHECKSUMS_FLAG: u8 = 0x01;

struct ChecksummedPageEntries<'a, R: std::io::Read> {
    reader: &'a mut R,
    remaining_pages: usize,
    current_entries: std::vec::IntoIter<ExtentMapEntryV2>,
}

impl<'a, R: std::io::Read> ChecksummedPageEntries<'a, R> {
    fn new(reader: &'a mut R, page_count: usize) -> Self {
        Self {
            reader,
            remaining_pages: page_count,
            current_entries: Vec::new().into_iter(),
        }
    }

    fn read_next_page(&mut self) -> Result<(), ExtentMapError> {
        let mut pec_buf = [0u8; 2];
        self.reader
            .read_exact(&mut pec_buf)
            .map_err(|_| ExtentMapError::Corrupt)?;
        let page_entry_count = u16::from_le_bytes(pec_buf) as usize;
        if page_entry_count == 0 || page_entry_count > MAX_LEAF {
            return Err(ExtentMapError::Corrupt);
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(&pec_buf);

        let mut page_entries = Vec::with_capacity(page_entry_count);
        for _ in 0..page_entry_count {
            let entry = crate::read_entry_v2(self.reader)?;
            let mut entry_buf = Vec::with_capacity(81);
            crate::write_entry_v2(&mut entry_buf, &entry)?;
            hasher.update(&entry_buf);
            page_entries.push(entry);
        }

        let expected = hasher.finalize();
        let mut stored_checksum = [0u8; 32];
        self.reader
            .read_exact(&mut stored_checksum)
            .map_err(|_| ExtentMapError::Corrupt)?;
        if stored_checksum != *expected.as_bytes() {
            return Err(ExtentMapError::Corrupt);
        }

        self.remaining_pages -= 1;
        self.current_entries = page_entries.into_iter();
        Ok(())
    }
}

impl<R: std::io::Read> Iterator for ChecksummedPageEntries<'_, R> {
    type Item = Result<(u64, ExtentMapEntryV2), ExtentMapError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(entry) = self.current_entries.next() {
                return Some(Ok((entry.logical_offset, entry)));
            }
            if self.remaining_pages == 0 {
                return None;
            }
            if let Err(err) = self.read_next_page() {
                self.remaining_pages = 0;
                return Some(Err(err));
            }
        }
    }
}

struct FlatEntries<'a, R: std::io::Read> {
    reader: &'a mut R,
    remaining_entries: usize,
}

impl<'a, R: std::io::Read> FlatEntries<'a, R> {
    fn new(reader: &'a mut R, entry_count: usize) -> Self {
        Self {
            reader,
            remaining_entries: entry_count,
        }
    }
}

impl<R: std::io::Read> Iterator for FlatEntries<'_, R> {
    type Item = Result<(u64, ExtentMapEntryV2), ExtentMapError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining_entries == 0 {
            return None;
        }
        self.remaining_entries -= 1;
        match crate::read_entry_v2(self.reader) {
            Ok(entry) => Some(Ok((entry.logical_offset, entry))),
            Err(err) => {
                self.remaining_entries = 0;
                Some(Err(err))
            }
        }
    }
}

impl MultiLevelBTreeExtentMap {
    fn write_serialized_page<W: std::io::Write>(
        writer: &mut W,
        page_buf: &mut [u8],
        page_entry_count: u16,
    ) -> Result<(), ExtentMapError> {
        page_buf[..2].copy_from_slice(&page_entry_count.to_le_bytes());
        let checksum = blake3::hash(page_buf);

        writer
            .write_all(&page_entry_count.to_le_bytes())
            .map_err(|_| ExtentMapError::Corrupt)?;
        writer
            .write_all(&page_buf[2..])
            .map_err(|_| ExtentMapError::Corrupt)?;
        writer
            .write_all(checksum.as_bytes())
            .map_err(|_| ExtentMapError::Corrupt)?;
        Ok(())
    }

    fn deserialize_from_entry_iter<I>(
        entry_count: usize,
        entries: I,
    ) -> Result<Self, ExtentMapError>
    where
        I: IntoIterator<Item = Result<(u64, ExtentMapEntryV2), ExtentMapError>>,
    {
        let mut map = MultiLevelBTreeExtentMap::new();
        map.tree
            .try_rebuild_compact_from_sorted_iter(entry_count, entries)
            .map_err(|err| match err {
                RebuildFromSortedIterError::Source(err) => err,
                RebuildFromSortedIterError::Tree(_) => ExtentMapError::Corrupt,
            })?;
        map.refresh_header_from_tree()?;
        map.validate().map_err(|_| ExtentMapError::Corrupt)?;
        Ok(map)
    }

    /// Serialize the V3 multi-level extent map to a binary writer.
    ///
    /// Entries are grouped into pages, checksummed with BLAKE3-256,
    /// and written with the PAGE_CHECKSUMS_FLAG (0x01) signalling
    /// that page-level checksums are present.
    pub fn serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<(), ExtentMapError> {
        writer
            .write_all(MULTI_LEVEL_MAGIC)
            .map_err(|_| ExtentMapError::Corrupt)?;
        writer
            .write_all(&[MULTI_LEVEL_VERSION, PAGE_CHECKSUMS_FLAG])
            .map_err(|_| ExtentMapError::Corrupt)?;

        let entry_count = u32::try_from(self.tree.len()).map_err(|_| ExtentMapError::MapFull)?;
        writer
            .write_all(&entry_count.to_le_bytes())
            .map_err(|_| ExtentMapError::Corrupt)?;

        // Write pages: each page holds at most MAX_LEAF entries + BLAKE3 checksum.
        let page_count = (entry_count as usize).div_ceil(MAX_LEAF) as u32;
        writer
            .write_all(&page_count.to_le_bytes())
            .map_err(|_| ExtentMapError::Corrupt)?;

        let mut page_buf = Vec::with_capacity(MAX_LEAF * 81 + 2);
        let mut page_entry_count = 0u16;
        page_buf.extend_from_slice(&0u16.to_le_bytes());

        for (_, entry) in self.tree.range_scan(..) {
            if page_entry_count == MAX_LEAF as u16 {
                Self::write_serialized_page(writer, &mut page_buf, page_entry_count)?;
                page_buf.clear();
                page_buf.extend_from_slice(&0u16.to_le_bytes());
                page_entry_count = 0;
            }

            crate::write_entry_v2(&mut page_buf, entry)?;
            page_entry_count += 1;
        }

        if page_entry_count > 0 {
            Self::write_serialized_page(writer, &mut page_buf, page_entry_count)?;
        }

        writer.flush().map_err(|_| ExtentMapError::Corrupt)?;
        Ok(())
    }

    /// Deserialize a V3 multi-level extent map from a binary reader.
    ///
    /// Supports two wire formats:
    /// - **Flat** (flags byte == 0x00): entries written sequentially, no checksums.
    /// - **Page-level checksummed** (flags byte & PAGE_CHECKSUMS_FLAG != 0):
    ///   pages written as  (u16 LE) + entries + BLAKE3-256 checksum.
    pub fn deserialize<R: std::io::Read>(reader: &mut R) -> Result<Self, ExtentMapError> {
        let mut magic = [0u8; 4];
        reader
            .read_exact(&mut magic)
            .map_err(|_| ExtentMapError::Corrupt)?;
        if &magic != MULTI_LEVEL_MAGIC {
            return Err(ExtentMapError::WrongVersion);
        }
        let mut version_flags = [0u8; 2];
        reader
            .read_exact(&mut version_flags)
            .map_err(|_| ExtentMapError::Corrupt)?;
        if version_flags[0] != MULTI_LEVEL_VERSION {
            return Err(ExtentMapError::WrongVersion);
        }
        let has_checksums = (version_flags[1] & PAGE_CHECKSUMS_FLAG) != 0;

        let mut entry_count_buf = [0u8; 4];
        reader
            .read_exact(&mut entry_count_buf)
            .map_err(|_| ExtentMapError::Corrupt)?;
        let entry_count = u32::from_le_bytes(entry_count_buf) as usize;

        if has_checksums {
            let mut page_count_buf = [0u8; 4];
            reader
                .read_exact(&mut page_count_buf)
                .map_err(|_| ExtentMapError::Corrupt)?;
            let page_count = u32::from_le_bytes(page_count_buf) as usize;

            let entries = ChecksummedPageEntries::new(reader, page_count);
            Self::deserialize_from_entry_iter(entry_count, entries)
        } else {
            // Legacy flat format: entries written sequentially, no checksums.
            let entries = FlatEntries::new(reader, entry_count);
            Self::deserialize_from_entry_iter(entry_count, entries)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_extent_map_core::ExtentMapEntryV2;

    fn data(off: u64, len: u64, loc: u64) -> ExtentMapEntryV2 {
        ExtentMapEntryV2::new_data(off, len, LocatorId(loc), [0u8; 32], 0)
    }

    fn unwritten(off: u64, len: u64) -> ExtentMapEntryV2 {
        ExtentMapEntryV2::new_unwritten(off, len, 0)
    }

    #[test]
    fn new_is_empty() {
        let m = MultiLevelBTreeExtentMap::new();
        assert!(m.header.is_empty());
        assert_eq!(m.header.version, 3);
        assert_eq!(m.header.depth, 2);
        assert_eq!(m.header.leaf_count, 0);
        assert_eq!(m.header.internal_count, 0);
    }

    #[test]
    fn insert_and_lookup() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2)])
            .unwrap();
        assert_eq!(m.header.entry_count, 2);
        assert!(m.validate().is_ok());

        let r = m.lookup_range(0, 4096).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].logical_offset, 0);

        let r = m.lookup_range(8192, 4096).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].logical_offset, 8192);

        // Hole in the gap
        let r = m.lookup_range(4096, 4096).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn lookup_range_late_small_window_uses_predecessor_and_bounded_scan() {
        let mut m = MultiLevelBTreeExtentMap::new();
        for i in 0..205u64 {
            m.insert_extent(&[data(i * 8192, 4096, i + 1)]).unwrap();
        }

        let start = 199 * 8192 + 2048;
        let next_extent = 200 * 8192;
        let result = m.lookup_range(start, 8192).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].logical_offset, start);
        assert_eq!(result[0].length, 2048);
        assert_eq!(result[0].locator_id, LocatorId(200));
        assert_eq!(result[1].logical_offset, next_extent);
        assert_eq!(result[1].length, 2048);
        assert_eq!(result[1].locator_id, LocatorId(201));

        let exact_late = m.lookup_range(next_extent, 4096).unwrap();
        assert_eq!(exact_late.len(), 1);
        assert_eq!(exact_late[0].logical_offset, next_extent);
        assert_eq!(exact_late[0].length, 4096);
        assert_eq!(exact_late[0].locator_id, LocatorId(201));
    }

    #[test]
    fn insert_overwrite_and_merge() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 1)])
            .unwrap();
        // Bridge the gap
        m.insert_extent(&[data(2048, 6144, 1)]).unwrap();
        // Should merge into one entry [0, 10240, 1]
        assert_eq!(m.header.entry_count, 1);
        assert_eq!(m.collect_all()[0].logical_offset, 0);
        assert_eq!(m.collect_all()[0].length, 12288);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn insert_late_fragmented_preserves_trim_and_merge() {
        let mut m = MultiLevelBTreeExtentMap::new();
        for i in 0..205u64 {
            let locator = if i == 198 || i == 201 { 900 } else { i + 1 };
            m.insert_extent(&[data(i * 8192, 4096, locator)]).unwrap();
        }

        let offset = 198 * 8192 + 2048;
        let end = 201 * 8192 + 2048;
        m.insert_extent(&[data(offset, end - offset, 900)]).unwrap();

        assert_eq!(m.header.entry_count, 202);
        assert_eq!(m.header.alloc_bytes, 205 * 4096 - 12_288 + (end - offset));
        assert_eq!(m.header.file_size, 204 * 8192 + 4096);

        let entries = m.collect_all();
        let merged = entries
            .iter()
            .find(|entry| entry.logical_offset == 198 * 8192)
            .unwrap();
        assert_eq!(merged.length, 3 * 8192 + 4096);
        assert_eq!(merged.locator_id, LocatorId(900));
        assert!(entries
            .iter()
            .all(|entry| entry.logical_offset != 199 * 8192));
        assert!(entries
            .iter()
            .all(|entry| entry.logical_offset != 200 * 8192));
        assert!(entries
            .iter()
            .all(|entry| entry.logical_offset != 201 * 8192));
        assert_eq!(
            m.lookup_range(202 * 8192, 4096).unwrap(),
            vec![data(202 * 8192, 4096, 203)]
        );
        assert!(m.validate().is_ok());
    }

    #[test]
    fn insert_batch_replaces_multiple_ranges_in_one_extent() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.insert_extent(&[data(0, 32768, 1)]).unwrap();

        m.insert_extent(&[data(4096, 4096, 2), data(16384, 4096, 3)])
            .unwrap();

        assert_eq!(
            m.collect_all(),
            vec![
                data(0, 4096, 1),
                data(4096, 4096, 2),
                data(8192, 8192, 1),
                data(16384, 4096, 3),
                data(20480, 12288, 1),
            ]
        );
        assert_eq!(m.header.entry_count, 5);
        assert_eq!(m.header.alloc_bytes, 32768);
        assert_eq!(m.header.file_size, 32768);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn truncate() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.insert_extent(&[data(0, 4096, 1), data(4096, 4096, 2)])
            .unwrap();
        m.truncate(4096).unwrap();
        assert_eq!(m.header.entry_count, 1);
        assert_eq!(m.collect_all()[0].logical_offset, 0);
        assert_eq!(m.collect_all()[0].length, 4096);
        assert_eq!(m.header.file_size, 4096);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn truncate_late_tail_preserves_trim_and_freed_types() {
        let mut m = MultiLevelBTreeExtentMap::new();
        for i in 0..205u64 {
            let offset = i * 8192;
            let entry = if i == 202 {
                unwritten(offset, 4096)
            } else {
                data(offset, 4096, i + 1)
            };
            m.insert_extent(&[entry]).unwrap();
        }

        let new_size = 199 * 8192 + 2048;
        let freed = m.truncate(new_size).unwrap();

        assert_eq!(freed.len(), 6);
        assert_eq!(freed[0].logical_offset, new_size);
        assert_eq!(freed[0].length, 2048);
        assert_eq!(freed[0].locator_id, LocatorId(200));
        assert_eq!(freed[0].extent_type, ExtentType::Data);
        assert_eq!(freed[3].logical_offset, 202 * 8192);
        assert_eq!(freed[3].length, 4096);
        assert_eq!(freed[3].extent_type, ExtentType::Unwritten);
        assert_eq!(freed[5].logical_offset, 204 * 8192);
        assert_eq!(freed[5].locator_id, LocatorId(205));

        assert_eq!(m.header.file_size, new_size);
        assert_eq!(m.header.entry_count, 200);
        assert_eq!(m.header.alloc_bytes, 199 * 4096 + 2048);

        let entries = m.collect_all();
        assert_eq!(entries.len(), 200);
        let last = entries.last().unwrap();
        assert_eq!(last.logical_offset, 199 * 8192);
        assert_eq!(last.length, 2048);
        assert_eq!(last.locator_id, LocatorId(200));
        assert!(m.lookup_range(new_size, 8192).unwrap().is_empty());
        assert!(m.validate().is_ok());
    }

    #[test]
    fn punch_hole_middle() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.insert_extent(&[data(0, 12288, 1)]).unwrap();
        let freed = m.punch_hole(4096, 4096).unwrap();
        assert_eq!(freed.len(), 1);
        assert_eq!(freed[0].logical_offset, 4096);
        assert_eq!(freed[0].length, 4096);
        assert_eq!(freed[0].locator_id, LocatorId(1));
        assert_eq!(freed[0].extent_type, ExtentType::Data);
        assert_eq!(m.header.entry_count, 2);
        let entries = m.collect_all();
        assert_eq!(entries[0].logical_offset, 0);
        assert_eq!(entries[0].length, 4096);
        assert_eq!(entries[1].logical_offset, 8192);
        assert_eq!(entries[1].length, 4096);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn punch_hole_full_removes() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.insert_extent(&[data(0, 4096, 1)]).unwrap();
        let freed = m.punch_hole(0, 4096).unwrap();
        assert_eq!(freed.len(), 1);
        assert_eq!(freed[0].logical_offset, 0);
        assert_eq!(freed[0].length, 4096);
        assert_eq!(freed[0].locator_id, LocatorId(1));
        assert_eq!(freed[0].extent_type, ExtentType::Data);
        assert_eq!(m.header.entry_count, 0);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn punch_hole_late_fragmented_preserves_trim_and_freed_types() {
        let mut m = MultiLevelBTreeExtentMap::new();
        for i in 0..205u64 {
            let offset = i * 8192;
            let entry = if i == 200 {
                unwritten(offset, 4096)
            } else {
                data(offset, 4096, i + 1)
            };
            m.insert_extent(&[entry]).unwrap();
        }

        let offset = 198 * 8192 + 2048;
        let end = 201 * 8192 + 2048;
        let freed = m.punch_hole(offset, end - offset).unwrap();

        assert_eq!(freed.len(), 4);
        assert_eq!(freed[0].logical_offset, offset);
        assert_eq!(freed[0].length, 2048);
        assert_eq!(freed[0].locator_id, LocatorId(199));
        assert_eq!(freed[0].extent_type, ExtentType::Data);
        assert_eq!(freed[1].logical_offset, 199 * 8192);
        assert_eq!(freed[1].length, 4096);
        assert_eq!(freed[1].locator_id, LocatorId(200));
        assert_eq!(freed[1].extent_type, ExtentType::Data);
        assert_eq!(freed[2].logical_offset, 200 * 8192);
        assert_eq!(freed[2].length, 4096);
        assert_eq!(freed[2].extent_type, ExtentType::Unwritten);
        assert_eq!(freed[3].logical_offset, 201 * 8192);
        assert_eq!(freed[3].length, 2048);
        assert_eq!(freed[3].locator_id, LocatorId(202));
        assert_eq!(freed[3].extent_type, ExtentType::Data);

        assert_eq!(m.header.entry_count, 203);
        assert_eq!(m.header.alloc_bytes, 202 * 4096);
        assert_eq!(m.header.file_size, 204 * 8192 + 4096);

        let entries = m.collect_all();
        assert_eq!(entries.len(), 203);
        let before = entries
            .iter()
            .find(|entry| entry.logical_offset == 198 * 8192)
            .unwrap();
        assert_eq!(before.length, 2048);
        assert_eq!(before.locator_id, LocatorId(199));
        assert!(entries
            .iter()
            .all(|entry| entry.logical_offset != 199 * 8192));
        assert!(entries
            .iter()
            .all(|entry| entry.logical_offset != 200 * 8192));
        let after = entries
            .iter()
            .find(|entry| entry.logical_offset == end)
            .unwrap();
        assert_eq!(after.length, 2048);
        assert_eq!(after.locator_id, LocatorId(202));
        assert!(m.lookup_range(offset, end - offset).unwrap().is_empty());
        assert!(m.validate().is_ok());
    }

    #[test]
    fn collapse_range_spanning_multiple_extents_frees_and_shifts_tail() {
        let mut map = MultiLevelBTreeExtentMap::new();
        map.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)])
            .unwrap();

        let freed = map.collapse_range(2048, 14336).unwrap();
        let entries = map.collect_all();

        assert_eq!(freed.len(), 2);
        assert_eq!(freed[0].logical_offset, 2048);
        assert_eq!(freed[0].length, 2048);
        assert_eq!(freed[0].locator_id, LocatorId(1));
        assert_eq!(freed[0].extent_type, ExtentType::Data);
        assert_eq!(freed[1].logical_offset, 8192);
        assert_eq!(freed[1].length, 4096);
        assert_eq!(freed[1].locator_id, LocatorId(2));
        assert_eq!(freed[1].extent_type, ExtentType::Data);
        assert_eq!(entries, vec![data(0, 2048, 1), data(2048, 4096, 3)]);
        assert_eq!(map.header.file_size, 6144);
        assert_eq!(map.header.alloc_bytes, 6144);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn collapse_range_late_fragmented_preserves_trim_and_shifted_suffix() {
        let mut map = MultiLevelBTreeExtentMap::new();
        for i in 0..205u64 {
            let offset = i * 8192;
            let entry = if i == 200 {
                unwritten(offset, 4096)
            } else {
                data(offset, 4096, i + 1)
            };
            map.insert_extent(&[entry]).unwrap();
        }

        let offset = 198 * 8192 + 2048;
        let end = 201 * 8192 + 2048;
        let length = end - offset;
        let freed = map.collapse_range(offset, length).unwrap();

        assert_eq!(freed.len(), 4);
        assert_eq!(freed[0].logical_offset, offset);
        assert_eq!(freed[0].length, 2048);
        assert_eq!(freed[0].locator_id, LocatorId(199));
        assert_eq!(freed[0].extent_type, ExtentType::Data);
        assert_eq!(freed[1].logical_offset, 199 * 8192);
        assert_eq!(freed[1].length, 4096);
        assert_eq!(freed[1].locator_id, LocatorId(200));
        assert_eq!(freed[1].extent_type, ExtentType::Data);
        assert_eq!(freed[2].logical_offset, 200 * 8192);
        assert_eq!(freed[2].length, 4096);
        assert_eq!(freed[2].extent_type, ExtentType::Unwritten);
        assert_eq!(freed[3].logical_offset, 201 * 8192);
        assert_eq!(freed[3].length, 2048);
        assert_eq!(freed[3].locator_id, LocatorId(202));
        assert_eq!(freed[3].extent_type, ExtentType::Data);

        assert_eq!(map.header.entry_count, 203);
        assert_eq!(map.header.alloc_bytes, 202 * 4096);
        assert_eq!(map.header.file_size, 201 * 8192 + 4096);

        let entries = map.collect_all();
        assert_eq!(entries.len(), 203);
        let before = entries
            .iter()
            .find(|entry| entry.logical_offset == 198 * 8192)
            .unwrap();
        assert_eq!(before.length, 2048);
        assert_eq!(before.locator_id, LocatorId(199));
        let collapsed_tail = entries
            .iter()
            .find(|entry| entry.logical_offset == offset)
            .unwrap();
        assert_eq!(collapsed_tail.length, 2048);
        assert_eq!(collapsed_tail.locator_id, LocatorId(202));
        let shifted_suffix = entries
            .iter()
            .find(|entry| entry.logical_offset == 199 * 8192)
            .unwrap();
        assert_eq!(shifted_suffix.length, 4096);
        assert_eq!(shifted_suffix.locator_id, LocatorId(203));
        assert!(map.validate().is_ok());
    }

    #[test]
    fn zero_range_over_data_is_hole_backed() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.insert_extent(&[data(0, 12288, 1)]).unwrap();
        let freed = m.zero_range(4096, 4096).unwrap();
        let entries = m.collect_all();
        assert_eq!(freed.len(), 1);
        assert_eq!(freed[0].logical_offset, 4096);
        assert_eq!(freed[0].length, 4096);
        assert_eq!(freed[0].locator_id, LocatorId(1));
        assert_eq!(freed[0].extent_type, ExtentType::Data);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].logical_offset, 0);
        assert_eq!(entries[0].length, 4096);
        assert_eq!(entries[1].logical_offset, 8192);
        assert_eq!(entries[1].length, 4096);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn zero_range_over_hole_reports_no_freed_ranges() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2)])
            .unwrap();
        let freed = m.zero_range(4096, 4096).unwrap();
        let entries = m.collect_all();
        assert!(freed.is_empty());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].logical_offset, 0);
        assert_eq!(entries[1].logical_offset, 8192);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn fallocate_extends_file_size_with_unwritten_extent() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.fallocate(4096, 8192, false).unwrap();
        let entries = m.collect_all();
        assert_eq!(m.header.file_size, 12288);
        assert_eq!(m.header.entry_count, 1);
        assert_eq!(m.header.alloc_bytes, 8192);
        assert_eq!(entries, vec![unwritten(4096, 8192)]);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn fallocate_keep_size_preserves_file_size() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.insert_extent(&[data(0, 4096, 1)]).unwrap();
        m.fallocate(8192, 4096, true).unwrap();
        let entries = m.collect_all();
        assert_eq!(m.header.file_size, 4096);
        assert_eq!(m.header.entry_count, 2);
        assert_eq!(m.header.alloc_bytes, 8192);
        assert_eq!(entries[1], unwritten(8192, 4096));
        assert!(m.validate().is_ok());
    }

    #[test]
    fn fallocate_rejects_zero_length() {
        let mut m = MultiLevelBTreeExtentMap::new();
        let err = m.fallocate(0, 0, false).unwrap_err();
        assert_eq!(err, ExtentMapError::InvalidRange);
        assert_eq!(m.header.file_size, 0);
        assert!(m.collect_all().is_empty());
    }

    #[test]
    fn fallocate_rejects_offset_overflow() {
        let mut m = MultiLevelBTreeExtentMap::new();
        let err = m.fallocate(u64::MAX, 1, false).unwrap_err();
        assert_eq!(err, ExtentMapError::InvalidRange);
        assert_eq!(m.header.file_size, 0);
        assert!(m.collect_all().is_empty());
    }

    #[test]
    fn fallocate_replaces_overlapping_data_with_unwritten() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.insert_extent(&[data(0, 12288, 1)]).unwrap();
        m.fallocate(4096, 4096, false).unwrap();
        let entries = m.collect_all();
        assert_eq!(m.header.file_size, 12288);
        assert_eq!(m.header.entry_count, 3);
        assert_eq!(m.header.alloc_bytes, 12288);
        assert_eq!(entries[0], data(0, 4096, 1));
        assert_eq!(entries[1], unwritten(4096, 4096));
        assert_eq!(entries[2], data(8192, 4096, 1));
        assert!(m.validate().is_ok());
    }

    #[test]
    fn convert_unwritten_to_data() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.insert_extent(&[unwritten(0, 8192)]).unwrap();
        let cs = [0xAA; 32];
        m.convert_unwritten_to_data(2048, 4096, LocatorId(5), cs, 1)
            .unwrap();
        let entries = m.collect_all();
        assert_eq!(entries.len(), 3);
        assert!(entries[0].is_unwritten());
        assert_eq!(entries[0].logical_offset, 0);
        assert_eq!(entries[0].length, 2048);
        assert!(entries[1].is_data());
        assert_eq!(entries[1].logical_offset, 2048);
        assert_eq!(entries[1].length, 4096);
        assert!(entries[2].is_unwritten());
        assert_eq!(entries[2].logical_offset, 6144);
        assert_eq!(entries[2].length, 2048);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn convert_unwritten_late_fragment_preserves_prefix_and_suffix() {
        let mut m = MultiLevelBTreeExtentMap::new();
        for i in 0..205u64 {
            let offset = i * 8192;
            let entry = if i == 199 {
                unwritten(offset, 8192)
            } else {
                data(offset, 4096, i + 1)
            };
            m.insert_extent(&[entry]).unwrap();
        }

        let convert_offset = 199 * 8192 + 2048;
        let checksum = [0xCC; 32];
        m.convert_unwritten_to_data(convert_offset, 4096, LocatorId(900), checksum, 77)
            .unwrap();

        let entries = m.collect_all();
        assert_eq!(m.header.entry_count, 207);
        assert_eq!(m.header.alloc_bytes, 206 * 4096);
        assert_eq!(entries.len(), 207);

        assert_eq!(entries[198], data(198 * 8192, 4096, 199));
        assert!(entries[199].is_unwritten());
        assert_eq!(entries[199].logical_offset, 199 * 8192);
        assert_eq!(entries[199].length, 2048);

        assert!(entries[200].is_data());
        assert_eq!(entries[200].logical_offset, convert_offset);
        assert_eq!(entries[200].length, 4096);
        assert_eq!(entries[200].locator_id, LocatorId(900));
        assert_eq!(entries[200].checksum, checksum);
        assert_eq!(entries[200].birth_commit_group, 77);

        assert!(entries[201].is_unwritten());
        assert_eq!(entries[201].logical_offset, convert_offset + 4096);
        assert_eq!(entries[201].length, 2048);
        assert_eq!(entries[202], data(200 * 8192, 4096, 201));
        assert!(m.validate().is_ok());
    }

    #[test]
    fn seek_data_and_hole() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 1)])
            .unwrap();

        // seek_data at 0 returns data
        let sd = m.seek_data(0);
        assert!(sd.is_some());
        assert_eq!(sd.unwrap().0, 0);

        // seek_data in hole skips to next data
        let sd = m.seek_data(4096);
        assert!(sd.is_some());
        assert_eq!(sd.unwrap().0, 8192);

        // seek_hole at 0: with gap, first hole is at 4096
        let sh = m.seek_hole(0);
        assert!(sh.is_some());
        assert_eq!(sh.unwrap().0, 4096);
    }

    #[test]
    fn seek_data_and_hole_treat_unwritten_as_data() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.insert_extent(&[unwritten(0, 4096)]).unwrap();
        m.header.file_size = 4096;

        assert_eq!(m.seek_data(0), Some((0, 4096)));
        assert_eq!(m.seek_hole(0), None);
    }

    #[test]
    fn seek_late_fragmented_window_uses_predecessor_and_bounded_scan() {
        let mut m = MultiLevelBTreeExtentMap::new();
        for i in 0..205u64 {
            m.insert_extent(&[data(i * 8192, 4096, i + 1)]).unwrap();
        }

        let current_extent = 199 * 8192;
        let inside_current = current_extent + 2048;
        let gap_after_current = current_extent + 4096;
        let next_extent = 200 * 8192;

        assert_eq!(m.seek_data(inside_current), Some((inside_current, 2048)));
        assert_eq!(m.seek_hole(inside_current), Some((gap_after_current, 4096)));
        assert_eq!(m.seek_data(gap_after_current), Some((next_extent, 4096)));
        assert_eq!(
            m.seek_hole(gap_after_current),
            Some((gap_after_current, 4096))
        );
    }

    #[test]
    fn fiemap_output() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2)])
            .unwrap();
        let result = m.fiemap(0, 16384).unwrap();
        assert!(!result.is_empty());
        // Last entry should have FLAG_LAST set
        assert_ne!(result.last().unwrap().fe_flags & FiemapExtent::FLAG_LAST, 0);
    }

    #[test]
    fn fiemap_late_window_includes_predecessor_gap_and_next_extent() {
        let mut m = MultiLevelBTreeExtentMap::new();
        for i in 0..205u64 {
            m.insert_extent(&[data(i * 8192, 4096, i + 1)]).unwrap();
        }

        let current_extent = 199 * 8192;
        let start = current_extent + 2048;
        let gap_after_current = current_extent + 4096;
        let next_extent = 200 * 8192;
        let result = m.fiemap(start, 8192).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].fe_logical, start);
        assert_eq!(result[0].fe_physical, 200);
        assert_eq!(result[0].fe_length, 2048);
        assert_eq!(result[0].fe_flags & FiemapExtent::FLAG_LAST, 0);

        assert_eq!(result[1].fe_logical, gap_after_current);
        assert_eq!(result[1].fe_physical, 0);
        assert_eq!(result[1].fe_length, 4096);
        assert_ne!(result[1].fe_flags & FiemapExtent::FLAG_UNKNOWN, 0);
        assert_eq!(result[1].fe_flags & FiemapExtent::FLAG_LAST, 0);

        assert_eq!(result[2].fe_logical, next_extent);
        assert_eq!(result[2].fe_physical, 201);
        assert_eq!(result[2].fe_length, 2048);
        assert_ne!(result[2].fe_flags & FiemapExtent::FLAG_LAST, 0);
    }

    #[test]
    fn validate_rejects_wrong_version() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.header.version = 2;
        assert_eq!(m.validate(), Err(ExtentMapError::WrongVersion));
    }

    #[test]
    fn validate_checks_page_counts() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.insert_extent(&[data(0, 4096, 1)]).unwrap();
        m.validate().unwrap();

        // Corrupt leaf_count
        m.header.leaf_count = 999;
        assert_eq!(m.validate(), Err(ExtentMapError::Corrupt));
    }

    #[test]
    fn depth_bound_checked() {
        let mut m = MultiLevelBTreeExtentMap::new();
        // Insert something so tree stats are consistent, then corrupt depth
        m.insert_extent(&[data(0, 4096, 1)]).unwrap();
        m.header.depth = EXTENT_MAP_V3_MAX_DEPTH + 1;
        assert_eq!(m.validate(), Err(ExtentMapError::MapFull));
    }

    #[test]
    fn large_insert_many_entries() {
        let mut m = MultiLevelBTreeExtentMap::new();
        let entries: Vec<ExtentMapEntryV2> = (0..200).map(|i| data(i * 4096, 4096, 1)).collect();
        m.insert_extent(&entries).unwrap();
        // 200 adjacent same-locator entries merge into 1 entry
        assert_eq!(m.header.entry_count, 1);
        // Adjacent same-locator entries should merge
        // 200 adjacent same-locator entries merge into 1
        assert_eq!(m.collect_all().len(), 1);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn insert_empty_is_noop() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.insert_extent(&[]).unwrap();
        assert_eq!(m.header.entry_count, 0);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn insert_zero_length_rejected() {
        let mut m = MultiLevelBTreeExtentMap::new();
        let err = m
            .insert_extent(&[ExtentMapEntryV2::new_data(0, 0, LocatorId(1), [0u8; 32], 0)])
            .unwrap_err();
        assert_eq!(err, ExtentMapError::InvalidRange);
    }

    #[test]
    fn insert_overlapping_rejected() {
        let mut m = MultiLevelBTreeExtentMap::new();
        let err = m
            .insert_extent(&[data(0, 8192, 1), data(4096, 4096, 2)])
            .unwrap_err();
        assert_eq!(err, ExtentMapError::OverlappingExtent);
    }

    #[test]
    fn lookup_zero_length_rejected() {
        let m = MultiLevelBTreeExtentMap::new();
        let err = m.lookup_range(0, 0).unwrap_err();
        assert_eq!(err, ExtentMapError::InvalidRange);
    }

    #[test]
    fn punch_hole_zero_length_rejected() {
        let mut m = MultiLevelBTreeExtentMap::new();
        let err = m.punch_hole(0, 0).unwrap_err();
        assert_eq!(err, ExtentMapError::InvalidRange);
    }

    #[test]
    fn convert_unwritten_not_found() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.insert_extent(&[data(0, 4096, 1)]).unwrap();
        let err = m
            .convert_unwritten_to_data(0, 2048, LocatorId(1), [0u8; 32], 0)
            .unwrap_err();
        assert_eq!(err, ExtentMapError::NotFound);
    }

    #[test]
    fn truncate_expand_does_not_remove() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.insert_extent(&[data(0, 4096, 1)]).unwrap();
        m.truncate(8192).unwrap();
        assert_eq!(m.header.file_size, 8192);
        assert_eq!(m.header.entry_count, 1);
    }

    #[test]
    fn seek_hole_past_file_size() {
        let mut m = MultiLevelBTreeExtentMap::new();
        m.insert_extent(&[data(0, 4096, 1)]).unwrap();
        let sh = m.seek_hole(8192);
        assert!(sh.is_none());
    }

    #[test]
    fn leaf_and_internal_counts_accurate() {
        let mut m = MultiLevelBTreeExtentMap::new();
        // Insert 500 distinct entries (non-adjacent, different locators)
        let entries: Vec<ExtentMapEntryV2> = (0..500)
            .map(|i| data(i * 8192, 4096, i % 100 + 1))
            .collect();
        m.insert_extent(&entries).unwrap();
        assert_eq!(m.header.entry_count, 500);
        // With 500 entries and MAX_LEAF=45, we expect >10 leaf pages
        assert!(m.header.leaf_count > 10);
        // Depth should be at least 2 (has internal nodes)
        assert!(m.header.depth >= 2);
        // internal_count should match actual
        let actual_internal = if m.tree.is_empty() {
            0
        } else {
            m.tree.internal_count()
        };
        assert_eq!(m.header.internal_count as usize, actual_internal);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn alloc_bytes_tracks_consuming_space() {
        let mut m = MultiLevelBTreeExtentMap::new();
        // HOLE entries don't consume space, DATA + UNWRITTEN do
        m.insert_extent(&[data(0, 4096, 1), unwritten(4096, 4096)])
            .unwrap();
        assert_eq!(m.header.alloc_bytes, 8192);
    }
}

#[cfg(test)]
mod serde_tests {
    use super::*;
    use tidefs_types_extent_map_core::ExtentMapEntryV2;

    fn data(off: u64, len: u64, loc: u64) -> ExtentMapEntryV2 {
        ExtentMapEntryV2::new_data(off, len, LocatorId(loc), [0u8; 32], 0)
    }

    fn checked_page_buffer(entries: &[ExtentMapEntryV2], declared_entry_count: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(MULTI_LEVEL_MAGIC);
        buf.extend_from_slice(&[MULTI_LEVEL_VERSION, PAGE_CHECKSUMS_FLAG]);
        buf.extend_from_slice(&declared_entry_count.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());

        let mut page_buf = Vec::new();
        page_buf.extend_from_slice(&0u16.to_le_bytes());
        for entry in entries {
            crate::write_entry_v2(&mut page_buf, entry).unwrap();
        }
        MultiLevelBTreeExtentMap::write_serialized_page(
            &mut buf,
            &mut page_buf,
            entries.len() as u16,
        )
        .unwrap();
        buf
    }

    #[test]
    fn serde_roundtrip_empty() {
        let map = MultiLevelBTreeExtentMap::new();
        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();
        assert!(!buf.is_empty());

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = MultiLevelBTreeExtentMap::deserialize(&mut cursor).unwrap();
        assert_eq!(recon.header.entry_count, 0);
        assert!(recon.collect_all().is_empty());
        assert!(recon.validate().is_ok());
    }

    #[test]
    fn serde_roundtrip_populated() {
        let mut map = MultiLevelBTreeExtentMap::new();
        for i in 0..10u64 {
            let e = data(i * 4096, 4096, i + 1);
            map.insert_extent(&[e]).unwrap();
        }

        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = MultiLevelBTreeExtentMap::deserialize(&mut cursor).unwrap();

        assert_eq!(recon.header.entry_count, 10);
        let orig = map.collect_all();
        let recon_entries = recon.collect_all();
        assert_eq!(orig.len(), recon_entries.len());
        for (a, b) in orig.iter().zip(recon_entries.iter()) {
            assert_eq!(a.logical_offset, b.logical_offset);
            assert_eq!(a.length, b.length);
        }
        assert!(recon.validate().is_ok());
    }

    #[test]
    fn serde_roundtrip_with_unwritten() {
        let mut map = MultiLevelBTreeExtentMap::new();
        map.fallocate(0, 16384, false).unwrap();
        map.convert_unwritten_to_data(4096, 8192, LocatorId(10), [0xAB; 32], 1)
            .unwrap();

        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = MultiLevelBTreeExtentMap::deserialize(&mut cursor).unwrap();

        let entries = recon.collect_all();
        assert_eq!(entries.len(), 3);
        assert!(recon.validate().is_ok());
    }

    #[test]
    fn serde_wrong_magic_rejected() {
        let buf = b"XXXX".to_vec();
        let mut cursor = std::io::Cursor::new(&buf);
        let err = MultiLevelBTreeExtentMap::deserialize(&mut cursor).unwrap_err();
        assert_eq!(err, ExtentMapError::WrongVersion);
    }

    #[test]
    fn serde_wrong_version_rejected() {
        let buf = b"VX33\x63\x00".to_vec();
        let mut cursor = std::io::Cursor::new(&buf);
        let err = MultiLevelBTreeExtentMap::deserialize(&mut cursor).unwrap_err();
        assert_eq!(err, ExtentMapError::WrongVersion);
    }

    #[test]
    fn serde_truncated_data_rejected() {
        let mut map = MultiLevelBTreeExtentMap::new();
        map.insert_extent(&[data(0, 4096, 1)]).unwrap();
        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        let half = buf.len() / 2;
        let mut cursor = std::io::Cursor::new(&buf[..half]);
        let err = MultiLevelBTreeExtentMap::deserialize(&mut cursor).unwrap_err();
        assert_eq!(err, ExtentMapError::Corrupt);
    }

    #[test]
    fn page_checksums_roundtrip_multi_page() {
        // 100 entries split across at least 3 pages (MAX_LEAF=45).
        let mut map = MultiLevelBTreeExtentMap::new();
        for i in 0..100u64 {
            map.insert_extent(&[data(i * 4096, 4096, i + 1)]).unwrap();
        }
        assert_eq!(map.header.entry_count, 100);

        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = MultiLevelBTreeExtentMap::deserialize(&mut cursor).unwrap();
        assert_eq!(recon.header.entry_count, 100);
        assert!(recon.validate().is_ok());
    }

    #[test]
    fn page_checksums_single_page() {
        let mut map = MultiLevelBTreeExtentMap::new();
        map.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2)])
            .unwrap();

        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = MultiLevelBTreeExtentMap::deserialize(&mut cursor).unwrap();
        assert_eq!(recon.header.entry_count, 2);
        assert!(recon.validate().is_ok());
    }

    #[test]
    fn page_checksums_corruption_detected() {
        let mut map = MultiLevelBTreeExtentMap::new();
        for i in 0..50u64 {
            map.insert_extent(&[data(i * 4096, 4096, i + 1)]).unwrap();
        }

        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        // Corrupt a byte in the middle of the entries (past header + first page).
        let corrupt_pos = buf.len() / 2;
        buf[corrupt_pos] ^= 0xFF;

        let mut cursor = std::io::Cursor::new(&buf);
        let err = MultiLevelBTreeExtentMap::deserialize(&mut cursor).unwrap_err();
        assert_eq!(err, ExtentMapError::Corrupt);
    }

    #[test]
    fn page_checksums_corrupt_checksum_byte_detected() {
        let mut map = MultiLevelBTreeExtentMap::new();
        map.insert_extent(&[data(0, 4096, 1)]).unwrap();

        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        // Flip a byte in the checksum (last 32 bytes).
        let cs_start = buf.len() - 32;
        buf[cs_start] ^= 0xFF;

        let mut cursor = std::io::Cursor::new(&buf);
        let err = MultiLevelBTreeExtentMap::deserialize(&mut cursor).unwrap_err();
        assert_eq!(err, ExtentMapError::Corrupt);
    }

    #[test]
    fn page_checksums_reject_out_of_order_entries() {
        let buf = checked_page_buffer(&[data(8192, 4096, 2), data(0, 4096, 1)], 2);

        let mut cursor = std::io::Cursor::new(&buf);
        let err = MultiLevelBTreeExtentMap::deserialize(&mut cursor).unwrap_err();

        assert_eq!(err, ExtentMapError::Corrupt);
    }

    #[test]
    fn page_checksums_reject_entry_count_mismatch() {
        let buf = checked_page_buffer(&[data(0, 4096, 1)], 2);

        let mut cursor = std::io::Cursor::new(&buf);
        let err = MultiLevelBTreeExtentMap::deserialize(&mut cursor).unwrap_err();

        assert_eq!(err, ExtentMapError::Corrupt);
    }

    #[test]
    fn page_checksums_exact_page_boundary() {
        // MAX_LEAF entries = exactly one full page.
        let mut map = MultiLevelBTreeExtentMap::new();
        for i in 0..MAX_LEAF as u64 {
            map.insert_extent(&[data(i * 4096, 4096, i + 1)]).unwrap();
        }
        assert_eq!(map.header.entry_count, MAX_LEAF as u64);

        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = MultiLevelBTreeExtentMap::deserialize(&mut cursor).unwrap();
        assert_eq!(recon.header.entry_count, MAX_LEAF as u64);
        assert!(recon.validate().is_ok());
    }

    #[test]
    fn page_checksums_exact_page_plus_one() {
        // MAX_LEAF + 1 entries = 2 pages (one full, one with 1 entry).
        let mut map = MultiLevelBTreeExtentMap::new();
        for i in 0..(MAX_LEAF as u64 + 1) {
            map.insert_extent(&[data(i * 4096, 4096, i + 1)]).unwrap();
        }

        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = MultiLevelBTreeExtentMap::deserialize(&mut cursor).unwrap();
        assert_eq!(recon.header.entry_count, MAX_LEAF as u64 + 1);
        assert!(recon.validate().is_ok());
    }
}
