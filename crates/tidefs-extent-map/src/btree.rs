// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! V2 B-tree extent map implementing `ExtentMapOps`.
//!
//! `BTreeExtentMap` provides the V2 (single B-tree) extent map
//! representation backed by [`tidefs_btree::BPlusTree`], keyed by
//! `logical_offset` with `ExtentMapEntryV2` values. Leaf pages hold up
//! to 45 entries.
//!
//! This is the medium-scale variant from the #1291 polymorphic extent maps
//! design. Tiny files use V1 inline-list; TiB-scale files will use V3
//! multi-level.
//!
//! Most mutation operations collect entries from the tree, apply the logical
//! mutation to the flat entry list, then rebuild the B+tree bottom-up. Insert,
//! truncate, punch-hole, collapse-range, and unwritten conversion stream the
//! source tree into the replacement list before rebuild, avoiding an extra
//! retained snapshot of the original entries.
//!
//! The implementation is `#[forbid(unsafe_code)]` and targets correctness.

use tidefs_btree::{BPlusTree, RebuildFromSortedIterError};
use tidefs_types_extent_map_core::{
    ExtentMapEntryV2, ExtentMapError, ExtentMapOps, ExtentMapV2, ExtentType, FiemapExtent,
    FreedExtent, LocatorId, EXTENT_MAP_LEAF_ENTRIES_ESTIMATE,
};

const MAX_LEAF: usize = EXTENT_MAP_LEAF_ENTRIES_ESTIMATE; // 45
const MAX_INTERNAL: usize = EXTENT_MAP_LEAF_ENTRIES_ESTIMATE; // 45

/// V2 B-tree extent map engine, backed by [`tidefs_btree::BPlusTree`].
#[derive(Clone, Debug)]
pub struct BTreeExtentMap {
    /// Metadata header: file_size, entry_count, alloc_bytes, version, depth.
    pub header: ExtentMapV2,
    /// Backing B+tree keyed by logical_offset.
    tree: BPlusTree<u64, ExtentMapEntryV2, MAX_LEAF, MAX_INTERNAL>,
}

impl BTreeExtentMap {
    /// Create an empty B-tree extent map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            header: ExtentMapV2::new(),
            tree: BPlusTree::new(),
        }
    }

    // -- entry collection helpers --

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
            tidefs_types_extent_map_core::ExtentType::Hole => FiemapExtent::FLAG_UNKNOWN,
            tidefs_types_extent_map_core::ExtentType::Unwritten => FiemapExtent::FLAG_UNWRITTEN,
            tidefs_types_extent_map_core::ExtentType::Data => 0,
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

    // -- rebuild --

    /// Rebuild the B+tree from a sorted entry list, updating header stats.
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
        self.validate().map_err(|_| ExtentMapError::Corrupt)
    }

    /// Rebuild the B+tree from a sorted entry list without compacting.
    ///
    /// Unlike [`rebuild`](Self::rebuild), this method skips the
    /// [`compact`](tidefs_btree::BPlusTree::compact) step, leaving
    /// under-full nodes visible for deferred maintenance through the
    /// [`BtreeCleanupQueue`].
    ///
    /// Use [`drain_underfull_nodes`](Self::drain_underfull_nodes) after
    /// this to collect entries for the cleanup queue.
    #[allow(dead_code)]
    fn rebuild_lazy(&mut self, entries: &[ExtentMapEntryV2]) {
        let pairs: Vec<(u64, ExtentMapEntryV2)> = entries
            .iter()
            .map(|e| (e.logical_offset, e.clone()))
            .collect();
        self.tree.rebuild(&pairs);

        self.header.entry_count = entries.len() as u64;
        self.header.alloc_bytes = entries
            .iter()
            .filter(|e| e.extent_type().consumes_space())
            .map(|e| e.length)
            .sum();
        self.header.depth = self.tree.depth();
        self.header.file_size = entries
            .last()
            .map(|e| e.end_offset())
            .unwrap_or(0)
            .max(self.header.file_size);
    }

    /// Collect under-full nodes from the backing B+tree for deferred
    /// maintenance.
    ///
    /// Returns [`UnderfullNodeInfo`] entries for all non-root nodes whose
    /// fill ratio is below 50%. The caller should convert these to
    /// [`BtreeCleanupEntry`] values and enqueue them in a
    /// [`BtreeCleanupQueue`].
    ///
    /// Use after [`rebuild_lazy`](Self::rebuild_lazy) or after deletions
    /// that may leave nodes under-full.
    #[must_use]
    pub fn drain_underfull_nodes(&self) -> Vec<tidefs_btree::UnderfullNodeInfo> {
        self.tree.underfull_nodes(0.5)
    }

    /// Compact the backing B+tree to restore minimum-fill invariants
    /// immediately. Equivalent to processing all pending deferred merge
    /// entries.
    ///
    /// Returns [`MergeStats`](tidefs_btree::MergeStats) reporting how many
    /// nodes were eliminated.
    pub fn compact_tree(&mut self) -> tidefs_btree::MergeStats {
        let before = self.tree.node_count() as u64;
        self.tree.compact();
        let after = self.tree.node_count() as u64;
        tidefs_btree::MergeStats {
            leaves_freed: 0, // leaf count may not decrease if only rebalancing
            total_nodes_freed: before.saturating_sub(after),
            fill_after: self.tree.fill_percent(),
            nodes_after: after,
        }
    }

    // -- mutation helpers --

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

    fn apply_inserts_from_tree(&self, new_entries: &[&ExtentMapEntryV2]) -> Vec<ExtentMapEntryV2> {
        let mut result = Vec::with_capacity(
            self.tree
                .len()
                .saturating_add(new_entries.len().saturating_mul(2)),
        );
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
}

impl ExtentMapOps for BTreeExtentMap {
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
            if e.length == 0 || e.logical_offset.checked_add(e.length).is_none() {
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
        Ok(())
    }

    fn truncate(&mut self, new_size: u64) -> Result<Vec<FreedExtent>, ExtentMapError> {
        if new_size >= self.header.file_size {
            if new_size > self.header.file_size {
                self.header.file_size = new_size;
            }
            return Ok(Vec::new());
        }

        let mut result: Vec<ExtentMapEntryV2> = Vec::with_capacity(self.tree.len());
        let mut freed = Vec::new();

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

        let mut result: Vec<ExtentMapEntryV2> = Vec::with_capacity(self.tree.len());
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

        let mut result: Vec<ExtentMapEntryV2> = Vec::with_capacity(self.tree.len());
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

        let mut new_entries: Vec<ExtentMapEntryV2> =
            Vec::with_capacity(self.tree.len().saturating_add(2));
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
            // Per tristate model: UNWRITTEN is not a hole; skip past it
            // together with DATA entries.
            if Self::is_seekable_data(entry) {
                cursor = cursor.max(entry.end_offset());
            } else {
                // HOLE type or other non-data/non-unwritten.
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
        if self.header.version != 2 {
            return Err(ExtentMapError::WrongVersion);
        }

        // Check sorted, non-overlapping, no zero-length.
        let mut actual_count = 0u64;
        let mut expected_alloc = 0u64;
        let mut previous: Option<(u64, ExtentType, LocatorId, [u8; 32])> = None;

        for (_, e) in self.tree.range_scan(..) {
            if e.length == 0 {
                return Err(ExtentMapError::Corrupt);
            }
            let entry_end = e
                .logical_offset
                .checked_add(e.length)
                .ok_or(ExtentMapError::Corrupt)?;

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
            if entry_end > self.header.file_size && !e.is_unwritten() {
                return Err(ExtentMapError::Corrupt);
            }

            if e.extent_type().consumes_space() {
                expected_alloc = expected_alloc
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

            actual_count = actual_count.checked_add(1).ok_or(ExtentMapError::Corrupt)?;
            previous = Some((entry_end, e.extent_type(), e.locator_id, e.checksum));
        }

        if self.header.entry_count != actual_count {
            return Err(ExtentMapError::Corrupt);
        }

        if self.header.alloc_bytes != expected_alloc {
            return Err(ExtentMapError::Corrupt);
        }

        // Delegate tree structure validation to tidefs-btree.
        self.tree.validate().map_err(|_| ExtentMapError::Corrupt)?;

        Ok(())
    }
}

// ------------------------------------------------------------------
// Persistence (extent-map V2 format)
// ------------------------------------------------------------------

/// Format magic for B-tree extent map.
pub const BTREE_EXTENT_MAP_MAGIC: &[u8; 4] = b"VX22";
/// Current format version.
pub const BTREE_EXTENT_MAP_VERSION: u8 = 2;

struct V2PageEntries<'a, R: std::io::Read> {
    reader: &'a mut R,
    remaining_pages: usize,
    current_entries: std::vec::IntoIter<ExtentMapEntryV2>,
}

impl<'a, R: std::io::Read> V2PageEntries<'a, R> {
    fn new(reader: &'a mut R, page_count: usize) -> Self {
        Self {
            reader,
            remaining_pages: page_count,
            current_entries: Vec::new().into_iter(),
        }
    }

    fn read_next_page(&mut self) -> Result<(), ExtentMapError> {
        let page_entries = crate::page_io::deserialize_leaf_page(self.reader)?;
        self.remaining_pages -= 1;
        self.current_entries = page_entries.into_iter();
        Ok(())
    }
}

impl<R: std::io::Read> Iterator for V2PageEntries<'_, R> {
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

impl BTreeExtentMap {
    /// Serialize the B-tree extent map to a binary writer.
    ///
    /// Format (version 2):
    /// ```text
    /// magic:          4 bytes  "VX22"
    /// version:        1 byte   2
    /// flags:          1 byte   reserved
    /// page_count:     4 bytes  number of 4096-byte pages
    /// pages:          page_count x 4096 bytes
    /// ```
    ///
    /// Each page is independently checksummed with BLAKE3.
    pub fn serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<(), ExtentMapError> {
        writer
            .write_all(BTREE_EXTENT_MAP_MAGIC)
            .map_err(|_| ExtentMapError::Corrupt)?;
        writer
            .write_all(&[BTREE_EXTENT_MAP_VERSION, 0u8])
            .map_err(|_| ExtentMapError::Corrupt)?;

        let max_per_page = crate::page_io::max_entries_per_page();
        // Always at least 1 page, even for empty maps.
        let page_count = self.tree.len().div_ceil(max_per_page).max(1);
        let page_count = u32::try_from(page_count).map_err(|_| ExtentMapError::MapFull)?;

        writer
            .write_all(&page_count.to_le_bytes())
            .map_err(|_| ExtentMapError::Corrupt)?;

        let mut page_entries = Vec::with_capacity(max_per_page);
        for (_, entry) in self.tree.range_scan(..) {
            page_entries.push(entry.clone());
            if page_entries.len() == max_per_page {
                crate::page_io::serialize_leaf_page(writer, &page_entries)?;
                page_entries.clear();
            }
        }

        if page_entries.is_empty() && self.tree.is_empty() {
            crate::page_io::serialize_leaf_page(writer, &[])?;
        } else if !page_entries.is_empty() {
            crate::page_io::serialize_leaf_page(writer, &page_entries)?;
        }

        writer.flush().map_err(|_| ExtentMapError::Corrupt)?;
        Ok(())
    }

    /// Deserialize a B-tree extent map from a binary reader.
    ///
    /// Accepts version 1 (flat entry, no checksums) and version 2
    /// (page-based with BLAKE3 checksums).
    pub fn deserialize<R: std::io::Read>(reader: &mut R) -> Result<Self, ExtentMapError> {
        let mut magic = [0u8; 4];
        reader
            .read_exact(&mut magic)
            .map_err(|_| ExtentMapError::Corrupt)?;
        if &magic != BTREE_EXTENT_MAP_MAGIC {
            return Err(ExtentMapError::WrongVersion);
        }

        let mut version_flags = [0u8; 2];
        reader
            .read_exact(&mut version_flags)
            .map_err(|_| ExtentMapError::Corrupt)?;
        let version = version_flags[0];
        if version != 1 && version != BTREE_EXTENT_MAP_VERSION {
            return Err(ExtentMapError::WrongVersion);
        }

        match version {
            1 => Self::deserialize_v1(reader),
            _ => Self::deserialize_v2(reader),
        }
    }

    /// Deserialize version 2 (page-based with BLAKE3 checksums).
    fn deserialize_v2<R: std::io::Read>(reader: &mut R) -> Result<Self, ExtentMapError> {
        let mut page_count_buf = [0u8; 4];
        reader
            .read_exact(&mut page_count_buf)
            .map_err(|_| ExtentMapError::Corrupt)?;
        let page_count = u32::from_le_bytes(page_count_buf) as usize;

        let mut map = BTreeExtentMap::new();
        let mut alloc_bytes = 0u64;
        let mut file_size = 0u64;
        let entries = V2PageEntries::new(reader, page_count).map(|entry| {
            let (key, entry) = entry?;
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
            Ok((key, entry))
        });
        let actual_len = map
            .tree
            .try_rebuild_compact_from_sorted_unknown_len_iter(entries)
            .map_err(|err| match err {
                RebuildFromSortedIterError::Source(err) => err,
                RebuildFromSortedIterError::Tree(_) => ExtentMapError::Corrupt,
            })?;

        map.header.entry_count = u64::try_from(actual_len).map_err(|_| ExtentMapError::MapFull)?;
        map.header.alloc_bytes = alloc_bytes;
        map.header.depth = map.tree.depth();
        map.header.file_size = file_size;
        map.validate().map_err(|_| ExtentMapError::Corrupt)?;
        Ok(map)
    }

    /// Deserialize version 1 (flat entry format, no page checksums).
    fn deserialize_v1<R: std::io::Read>(reader: &mut R) -> Result<Self, ExtentMapError> {
        let mut entry_count_buf = [0u8; 4];
        reader
            .read_exact(&mut entry_count_buf)
            .map_err(|_| ExtentMapError::Corrupt)?;
        let entry_count = u32::from_le_bytes(entry_count_buf) as usize;

        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let entry = crate::read_entry_v2(reader)?;
            entries.push(entry);
        }

        let mut map = BTreeExtentMap::new();
        if !entries.is_empty() {
            map.rebuild(&entries);
        }
        map.validate().map_err(|_| ExtentMapError::Corrupt)?;
        Ok(map)
    }
}

impl Default for BTreeExtentMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_extent_map_core::{
        ExtentMapEntryV2, ExtentMapError, ExtentType, FiemapExtent, LocatorId,
        EXTENT_MAP_DEFAULT_PAGE_SIZE,
    };

    fn data(off: u64, len: u64, loc: u64) -> ExtentMapEntryV2 {
        ExtentMapEntryV2::new_data(off, len, LocatorId(loc), [0u8; 32], 0)
    }

    fn unwritten(off: u64, len: u64) -> ExtentMapEntryV2 {
        ExtentMapEntryV2::new_unwritten(off, len, 0)
    }

    fn make_map(entries: &[ExtentMapEntryV2]) -> BTreeExtentMap {
        let mut map = BTreeExtentMap::new();
        if !entries.is_empty() {
            map.insert_extent(entries).unwrap();
        }
        map
    }

    #[test]
    fn empty_map_defaults() {
        let map = BTreeExtentMap::new();
        assert_eq!(map.header.file_size, 0);
        assert_eq!(map.header.entry_count, 0);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_single_data() {
        let mut map = BTreeExtentMap::new();
        map.insert_extent(&[data(0, 4096, 1)]).unwrap();
        assert_eq!(map.header.entry_count, 1);
        assert_eq!(map.header.file_size, 4096);
        assert_eq!(map.header.alloc_bytes, 4096);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_multiple_non_overlapping() {
        let mut map = BTreeExtentMap::new();
        map.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)])
            .unwrap();
        assert_eq!(map.header.entry_count, 3);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_merges_adjacent() {
        let mut map = BTreeExtentMap::new();
        map.insert_extent(&[data(0, 4096, 1), data(4096, 4096, 1)])
            .unwrap();
        assert_eq!(map.header.entry_count, 1);
        assert_eq!(map.collect_all().len(), 1);
        assert_eq!(map.collect_all()[0].length, 8192);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_overlapping_batch_rejected() {
        let mut map = BTreeExtentMap::new();
        let err = map
            .insert_extent(&[data(0, 8192, 1), data(4096, 4096, 2)])
            .unwrap_err();
        assert_eq!(err, ExtentMapError::OverlappingExtent);
    }

    #[test]
    fn insert_zero_length_rejected() {
        let mut map = BTreeExtentMap::new();
        let mut zero = data(0, 0, 1);
        zero.length = 0;
        let err = map.insert_extent(&[zero]).unwrap_err();
        assert_eq!(err, ExtentMapError::InvalidRange);
    }

    #[test]
    fn insert_overwrite_existing() {
        let mut map = make_map(&[data(0, 8192, 1)]);
        map.insert_extent(&[data(2048, 4096, 2)]).unwrap();
        assert_eq!(map.header.entry_count, 3);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_late_fragmented_preserves_trim_and_merge() {
        let mut map = BTreeExtentMap::new();
        for i in 0..205u64 {
            let locator = if i == 198 || i == 201 { 900 } else { i + 1 };
            map.insert_extent(&[data(i * 8192, 4096, locator)]).unwrap();
        }

        let offset = 198 * 8192 + 2048;
        let end = 201 * 8192 + 2048;
        map.insert_extent(&[data(offset, end - offset, 900)])
            .unwrap();

        assert_eq!(map.header.entry_count, 202);
        assert_eq!(map.header.alloc_bytes, 205 * 4096 - 12_288 + (end - offset));
        assert_eq!(map.header.file_size, 204 * 8192 + 4096);

        let entries = map.collect_all();
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
            map.lookup_range(202 * 8192, 4096).unwrap(),
            vec![data(202 * 8192, 4096, 203)]
        );
        assert!(map.validate().is_ok());
    }

    #[test]
    fn insert_batch_replaces_multiple_ranges_in_one_extent() {
        let mut map = BTreeExtentMap::new();
        map.insert_extent(&[data(0, 32768, 1)]).unwrap();

        map.insert_extent(&[data(4096, 4096, 2), data(16384, 4096, 3)])
            .unwrap();

        assert_eq!(
            map.collect_all(),
            vec![
                data(0, 4096, 1),
                data(4096, 4096, 2),
                data(8192, 8192, 1),
                data(16384, 4096, 3),
                data(20480, 12288, 1),
            ]
        );
        assert_eq!(map.header.entry_count, 5);
        assert_eq!(map.header.alloc_bytes, 32768);
        assert_eq!(map.header.file_size, 32768);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn page_split_at_threshold() {
        let mut map = BTreeExtentMap::new();
        for i in 0..46u64 {
            map.insert_extent(&[data(i * 8192, 4096, i + 1)]).unwrap();
        }
        assert_eq!(map.header.entry_count, 46);
        assert!(map.header.depth >= 2);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn many_entries_multi_level() {
        let mut map = BTreeExtentMap::new();
        for i in 0..250u64 {
            map.insert_extent(&[data(i * 8192, 4096, i + 1)]).unwrap();
        }
        assert_eq!(map.header.entry_count, 250);
        assert!(map.header.depth >= 2);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn lookup_range_exact() {
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
    fn lookup_range_across_leaves() {
        let mut map = BTreeExtentMap::new();
        for i in 0..50u64 {
            map.insert_extent(&[data(i * 4096, 4096, i + 1)]).unwrap();
        }
        let result = map.lookup_range(4096, 8192).unwrap();
        assert!(!result.is_empty());
        assert!(map.validate().is_ok());
    }

    #[test]
    fn lookup_range_includes_predecessor_spanning_offset() {
        let map = make_map(&[data(0, 8192, 1), data(16384, 4096, 2)]);

        let result = map.lookup_range(4096, 4096).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].logical_offset, 4096);
        assert_eq!(result[0].length, 4096);
        assert_eq!(result[0].locator_id, LocatorId(1));
    }

    #[test]
    fn lookup_range_late_small_window_uses_predecessor_and_bounded_scan() {
        let mut map = BTreeExtentMap::new();
        for i in 0..205u64 {
            map.insert_extent(&[data(i * 8192, 4096, i + 1)]).unwrap();
        }

        let start = 199 * 8192 + 2048;
        let next_extent = 200 * 8192;
        let result = map.lookup_range(start, 8192).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].logical_offset, start);
        assert_eq!(result[0].length, 2048);
        assert_eq!(result[0].locator_id, LocatorId(200));
        assert_eq!(result[1].logical_offset, next_extent);
        assert_eq!(result[1].length, 2048);
        assert_eq!(result[1].locator_id, LocatorId(201));

        let exact_late = map.lookup_range(next_extent, 4096).unwrap();
        assert_eq!(exact_late.len(), 1);
        assert_eq!(exact_late[0].logical_offset, next_extent);
        assert_eq!(exact_late[0].length, 4096);
        assert_eq!(exact_late[0].locator_id, LocatorId(201));
    }

    #[test]
    fn lookup_range_zero_length_rejected() {
        let map = BTreeExtentMap::new();
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
        assert!(map.validate().is_ok());
    }

    #[test]
    fn truncate_drop_entries() {
        let mut map = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);
        map.truncate(4096).unwrap();
        assert_eq!(map.header.entry_count, 1);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn truncate_expand() {
        let mut map = make_map(&[data(0, 4096, 1)]);
        let freed = map.truncate(16384).unwrap();
        assert!(freed.is_empty());
        assert_eq!(map.header.file_size, 16384);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn truncate_empty() {
        let mut map = BTreeExtentMap::new();
        let freed = map.truncate(0).unwrap();
        assert!(freed.is_empty());
        assert_eq!(map.header.file_size, 0);
        assert!(map.collect_all().is_empty());
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
        assert!(map.collect_all().is_empty());
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
        assert_eq!(map.header.entry_count, 1);
        assert_eq!(map.collect_all()[0].length, 4096);
        assert!(map.validate().is_ok());
        let freed2 = map.truncate(4096).unwrap();
        assert!(freed2.is_empty());
        assert_eq!(map.header.file_size, 4096);
        assert_eq!(map.header.entry_count, 1);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn truncate_late_tail_preserves_trim_and_freed_types() {
        let mut map = BTreeExtentMap::new();
        for i in 0..205u64 {
            let offset = i * 8192;
            let entry = if i == 202 {
                unwritten(offset, 4096)
            } else {
                data(offset, 4096, i + 1)
            };
            map.insert_extent(&[entry]).unwrap();
        }

        let new_size = 199 * 8192 + 2048;
        let freed = map.truncate(new_size).unwrap();

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

        assert_eq!(map.header.file_size, new_size);
        assert_eq!(map.header.entry_count, 200);
        assert_eq!(map.header.alloc_bytes, 199 * 4096 + 2048);

        let entries = map.collect_all();
        assert_eq!(entries.len(), 200);
        let last = entries.last().unwrap();
        assert_eq!(last.logical_offset, 199 * 8192);
        assert_eq!(last.length, 2048);
        assert_eq!(last.locator_id, LocatorId(200));
        assert!(map.lookup_range(new_size, 8192).unwrap().is_empty());
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
        assert_eq!(map.header.entry_count, 2);
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
        assert_eq!(map.header.entry_count, 1);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn punch_hole_beyond_file_size() {
        let mut map = make_map(&[data(0, 4096, 1)]);
        let freed = map.punch_hole(8192, 4096).unwrap();
        assert!(freed.is_empty());
        assert_eq!(map.header.file_size, 12288);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn punch_hole_multi_extent_reports_exact_freed_ranges() {
        let mut map = make_map(&[data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)]);
        let freed = map.punch_hole(2048, 14336).unwrap();
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
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].logical_offset, 0);
        assert_eq!(entries[0].length, 2048);
        assert_eq!(entries[1].logical_offset, 16384);
        assert_eq!(entries[1].length, 4096);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn punch_hole_already_hole_reports_no_freed_ranges() {
        let mut map = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);
        let freed = map.punch_hole(4096, 4096).unwrap();
        let entries = map.collect_all();
        assert!(freed.is_empty());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].logical_offset, 0);
        assert_eq!(entries[1].logical_offset, 8192);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn punch_hole_late_fragmented_preserves_trim_and_freed_types() {
        let entries: Vec<_> = (0..205u64)
            .map(|i| {
                let offset = i * 8192;
                if i == 200 {
                    unwritten(offset, 4096)
                } else {
                    data(offset, 4096, i + 1)
                }
            })
            .collect();
        let mut map = make_map(&entries);

        let offset = 198 * 8192 + 2048;
        let end = 201 * 8192 + 2048;
        let freed = map.punch_hole(offset, end - offset).unwrap();

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
        assert_eq!(map.header.file_size, 204 * 8192 + 4096);

        let entries = map.collect_all();
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
        assert!(map.lookup_range(offset, end - offset).unwrap().is_empty());
        assert!(map.validate().is_ok());
    }

    #[test]
    fn collapse_range_spanning_multiple_extents_frees_and_shifts_tail() {
        let mut map = make_map(&[data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)]);

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
        let entries: Vec<_> = (0..205u64)
            .map(|i| {
                let offset = i * 8192;
                if i == 200 {
                    unwritten(offset, 4096)
                } else {
                    data(offset, 4096, i + 1)
                }
            })
            .collect();
        let mut map = make_map(&entries);

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
        let mut map = make_map(&[data(0, 12288, 1)]);
        let freed = map.zero_range(4096, 4096).unwrap();
        let entries = map.collect_all();
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
        assert!(map.validate().is_ok());
    }

    #[test]
    fn zero_range_over_hole_reports_no_freed_ranges() {
        let mut map = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);
        let freed = map.zero_range(4096, 4096).unwrap();
        let entries = map.collect_all();
        assert!(freed.is_empty());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].logical_offset, 0);
        assert_eq!(entries[1].logical_offset, 8192);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn fallocate_extends_file_size_with_unwritten_extent() {
        let mut map = BTreeExtentMap::new();
        map.fallocate(4096, 8192, false).unwrap();
        let entries = map.collect_all();
        assert_eq!(map.header.file_size, 12288);
        assert_eq!(map.header.entry_count, 1);
        assert_eq!(map.header.alloc_bytes, 8192);
        assert_eq!(entries, vec![unwritten(4096, 8192)]);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn fallocate_keep_size_preserves_file_size() {
        let mut map = make_map(&[data(0, 4096, 1)]);
        map.fallocate(8192, 4096, true).unwrap();
        let entries = map.collect_all();
        assert_eq!(map.header.file_size, 4096);
        assert_eq!(map.header.entry_count, 2);
        assert_eq!(map.header.alloc_bytes, 8192);
        assert_eq!(entries[1], unwritten(8192, 4096));
        assert!(map.validate().is_ok());
    }

    #[test]
    fn fallocate_rejects_zero_length() {
        let mut map = BTreeExtentMap::new();
        let err = map.fallocate(0, 0, false).unwrap_err();
        assert_eq!(err, ExtentMapError::InvalidRange);
        assert_eq!(map.header.file_size, 0);
        assert!(map.collect_all().is_empty());
    }

    #[test]
    fn fallocate_rejects_offset_overflow() {
        let mut map = BTreeExtentMap::new();
        let err = map.fallocate(u64::MAX, 1, false).unwrap_err();
        assert_eq!(err, ExtentMapError::InvalidRange);
        assert_eq!(map.header.file_size, 0);
        assert!(map.collect_all().is_empty());
    }

    #[test]
    fn fallocate_replaces_overlapping_data_with_unwritten() {
        let mut map = make_map(&[data(0, 12288, 1)]);
        map.fallocate(4096, 4096, false).unwrap();
        let entries = map.collect_all();
        assert_eq!(map.header.file_size, 12288);
        assert_eq!(map.header.entry_count, 3);
        assert_eq!(map.header.alloc_bytes, 12288);
        assert_eq!(entries[0], data(0, 4096, 1));
        assert_eq!(entries[1], unwritten(4096, 4096));
        assert_eq!(entries[2], data(8192, 4096, 1));
        assert!(map.validate().is_ok());
    }

    #[test]
    fn convert_unwritten_to_data_partial() {
        let mut map = make_map(&[unwritten(0, 4096)]);
        let checksum = [0xAB; 32];
        map.convert_unwritten_to_data(0, 2048, LocatorId(5), checksum, 10)
            .unwrap();
        assert_eq!(map.header.entry_count, 2);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn convert_unwritten_to_data_full_entry() {
        let mut map = make_map(&[unwritten(0, 4096)]);
        let checksum = [0xCD; 32];
        map.convert_unwritten_to_data(0, 4096, LocatorId(7), checksum, 20)
            .unwrap();
        assert_eq!(map.header.entry_count, 1);
        assert!(map.collect_all()[0].is_data());
        assert!(map.validate().is_ok());
    }

    #[test]
    fn convert_unwritten_to_data_three_fragment() {
        let mut map = make_map(&[unwritten(0, 12288)]);
        let checksum = [0xAA; 32];
        map.convert_unwritten_to_data(4096, 4096, LocatorId(9), checksum, 1)
            .unwrap();
        assert_eq!(map.header.entry_count, 3);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn convert_unwritten_late_fragment_preserves_prefix_and_suffix() {
        let entries: Vec<_> = (0..205u64)
            .map(|i| {
                let offset = i * 8192;
                if i == 199 {
                    unwritten(offset, 8192)
                } else {
                    data(offset, 4096, i + 1)
                }
            })
            .collect();
        let mut map = make_map(&entries);

        let convert_offset = 199 * 8192 + 2048;
        let checksum = [0xCC; 32];
        map.convert_unwritten_to_data(convert_offset, 4096, LocatorId(900), checksum, 77)
            .unwrap();

        let entries = map.collect_all();
        assert_eq!(map.header.entry_count, 207);
        assert_eq!(map.header.alloc_bytes, 206 * 4096);
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
    fn convert_unwritten_zero_length_rejected() {
        let mut map = make_map(&[unwritten(0, 4096)]);
        let err = map
            .convert_unwritten_to_data(0, 0, LocatorId(1), [0u8; 32], 0)
            .unwrap_err();
        assert_eq!(err, ExtentMapError::InvalidRange);
    }

    #[test]
    fn seek_data_finds_first() {
        let map = make_map(&[data(4096, 4096, 1), data(12288, 4096, 2)]);
        let result = map.seek_data(0);
        assert_eq!(result, Some((4096, 4096)));
    }

    #[test]
    fn seek_data_finds_unwritten() {
        // Per tristate model: UNWRITTEN entries return zero on read but
        // are seekable data regions for SEEK_DATA.
        let map = make_map(&[unwritten(0, 4096)]);
        let result = map.seek_data(0);
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
        // Per tristate model: UNWRITTEN is not a hole; seek_hole
        // skips past it. File with only UNWRITTEN entries has no holes.
        let mut map = make_map(&[unwritten(0, 4096)]);
        map.header.file_size = 4096;
        let result = map.seek_hole(0);
        assert_eq!(result, None);
    }

    #[test]
    fn seek_hole_beyond_last_entry() {
        let mut map = make_map(&[data(0, 4096, 1)]);
        map.header.file_size = 8192;
        let result = map.seek_hole(4096);
        assert_eq!(result, Some((4096, 4096)));
    }

    #[test]
    fn seek_late_fragmented_window_uses_predecessor_and_bounded_scan() {
        let mut map = BTreeExtentMap::new();
        for i in 0..205u64 {
            map.insert_extent(&[data(i * 8192, 4096, i + 1)]).unwrap();
        }

        let current_extent = 199 * 8192;
        let inside_current = current_extent + 2048;
        let gap_after_current = current_extent + 4096;
        let next_extent = 200 * 8192;

        assert_eq!(map.seek_data(inside_current), Some((inside_current, 2048)));
        assert_eq!(
            map.seek_hole(inside_current),
            Some((gap_after_current, 4096))
        );
        assert_eq!(map.seek_data(gap_after_current), Some((next_extent, 4096)));
        assert_eq!(
            map.seek_hole(gap_after_current),
            Some((gap_after_current, 4096))
        );
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
        assert!(result[0].fe_flags & FiemapExtent::FLAG_UNWRITTEN != 0);
    }

    #[test]
    fn fiemap_partial_range() {
        let map = make_map(&[data(0, 8192, 1), data(16384, 4096, 2)]);
        let result = map.fiemap(2048, 12288).unwrap();
        assert!(!result.is_empty());
        assert!(result.last().unwrap().fe_flags & FiemapExtent::FLAG_LAST != 0);
    }

    #[test]
    fn fiemap_late_window_includes_predecessor_gap_and_next_extent() {
        let mut map = BTreeExtentMap::new();
        for i in 0..205u64 {
            map.insert_extent(&[data(i * 8192, 4096, i + 1)]).unwrap();
        }

        let current_extent = 199 * 8192;
        let start = current_extent + 2048;
        let gap_after_current = current_extent + 4096;
        let next_extent = 200 * 8192;
        let result = map.fiemap(start, 8192).unwrap();

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
    fn validate_wrong_version() {
        let mut map = BTreeExtentMap::new();
        map.header.version = 1;
        let err = map.validate().unwrap_err();
        assert_eq!(err, ExtentMapError::WrongVersion);
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
    fn validate_overlapping_rejected() {
        let mut map = BTreeExtentMap::new();
        // Rebuild with intentionally overlapping entries to test validation.
        map.rebuild(&[data(0, 8192, 1), data(4096, 4096, 2)]);
        let err = map.validate().unwrap_err();
        assert_eq!(err, ExtentMapError::OverlappingExtent);
    }

    #[test]
    fn validate_unmerged_adjacent_rejected() {
        let mut map = BTreeExtentMap::new();
        map.rebuild(&[data(0, 4096, 1), data(4096, 4096, 1)]);

        let err = map.validate().unwrap_err();

        assert_eq!(err, ExtentMapError::Corrupt);
    }

    #[test]
    fn validate_unwritten_with_locator_rejected() {
        let mut entry = unwritten(0, 4096);
        entry.locator_id = LocatorId(9);
        let mut map = BTreeExtentMap::new();
        map.rebuild(&[entry]);

        let err = map.validate().unwrap_err();

        assert_eq!(err, ExtentMapError::Corrupt);
    }

    #[test]
    fn validate_data_without_locator_rejected() {
        let mut entry = data(0, 4096, 1);
        entry.locator_id = LocatorId::NONE;
        let mut map = BTreeExtentMap::new();
        map.rebuild(&[entry]);

        let err = map.validate().unwrap_err();

        assert_eq!(err, ExtentMapError::Corrupt);
    }

    #[test]
    fn validate_overflowing_entry_rejected() {
        let entry = data(u64::MAX - 1, 2, 1);
        let mut map = BTreeExtentMap::new();
        map.tree.rebuild(&[(entry.logical_offset, entry.clone())]);
        map.header.entry_count = 1;
        map.header.alloc_bytes = entry.length;
        map.header.file_size = u64::MAX;

        let err = map.validate().unwrap_err();

        assert_eq!(err, ExtentMapError::Corrupt);
    }

    #[test]
    fn roundtrip_insert_lookup() {
        let mut map = BTreeExtentMap::new();
        let entries = [data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)];
        map.insert_extent(&entries).unwrap();
        assert!(map.validate().is_ok());
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
    fn insert_empty_batch_ok() {
        let mut map = BTreeExtentMap::new();
        map.insert_extent(&[]).unwrap();
        assert!(map.collect_all().is_empty());
    }

    #[test]
    fn insert_single_with_overwrite_and_merge() {
        let mut map = make_map(&[data(0, 4096, 1), data(8192, 4096, 1), data(16384, 4096, 1)]);
        map.insert_extent(&[data(2048, 10240, 1)]).unwrap();
        assert_eq!(map.header.entry_count, 2);
        assert_eq!(map.collect_all()[0].logical_offset, 0);
        assert_eq!(map.collect_all()[0].length, 12288);
        assert_eq!(map.collect_all()[1].logical_offset, 16384);
        assert_eq!(map.collect_all()[1].length, 4096);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn truncate_exact_boundary() {
        let mut map = make_map(&[data(0, 4096, 1), data(4096, 4096, 2)]);
        map.truncate(4096).unwrap();
        assert_eq!(map.header.entry_count, 1);
        assert_eq!(map.collect_all()[0].logical_offset, 0);
        assert_eq!(map.collect_all()[0].length, 4096);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn punch_hole_no_op_on_empty() {
        let mut map = BTreeExtentMap::new();
        map.header.file_size = 8192;
        map.punch_hole(0, 4096).unwrap();
        assert!(map.collect_all().is_empty());
        assert!(map.validate().is_ok());
    }

    #[test]
    fn convert_unwritten_partial_overlap_rejected() {
        let mut map = make_map(&[unwritten(0, 4096)]);
        let err = map
            .convert_unwritten_to_data(2048, 4096, LocatorId(1), [0u8; 32], 0)
            .unwrap_err();
        assert_eq!(err, ExtentMapError::NotFound);
    }

    #[test]
    fn convert_unwritten_prefix_trim() {
        let mut map = make_map(&[unwritten(0, 8192)]);
        let checksum = [0xBB; 32];
        map.convert_unwritten_to_data(0, 2048, LocatorId(10), checksum, 2)
            .unwrap();
        assert_eq!(map.header.entry_count, 2);
        assert!(map.collect_all()[0].is_data());
        assert!(map.collect_all()[1].is_unwritten());
        assert!(map.validate().is_ok());
    }

    #[test]
    fn convert_unwritten_suffix_trim() {
        let mut map = make_map(&[unwritten(0, 8192)]);
        let checksum = [0xCC; 32];
        map.convert_unwritten_to_data(6144, 2048, LocatorId(11), checksum, 3)
            .unwrap();
        assert_eq!(map.header.entry_count, 2);
        assert!(map.collect_all()[0].is_unwritten());
        assert!(map.collect_all()[1].is_data());
        assert!(map.validate().is_ok());
    }

    #[test]
    fn seek_data_from_mid_entry() {
        let map = make_map(&[data(0, 8192, 1), data(16384, 4096, 2)]);
        let result = map.seek_data(4096);
        assert_eq!(result, Some((4096, 4096)));
    }

    #[test]
    fn seek_hole_multi_level() {
        let mut map = BTreeExtentMap::new();
        for i in 0..50u64 {
            map.insert_extent(&[data(i * 8192, 4096, i + 1)]).unwrap();
        }
        let result = map.seek_hole(0);
        assert_eq!(result, Some((4096, 4096)));
    }

    // =====================================================================
    // Property tests: V1 (InlineExtentMap) vs V2 (BTreeExtentMap)
    //
    // V1 is limited to 6 entries and data-only extents. These tests keep
    // within V1 limits to directly compare behavior.  V2-only and
    // PolymorphicExtentMap tests exercise larger entry counts.
    // =====================================================================

    use crate::InlineExtentMap;

    /// Simple PRNG: SplitMix64 variant producing deterministic sequences.
    struct SplitMix64(u64);

    impl SplitMix64 {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            z ^ (z >> 31)
        }
    }

    #[test]
    fn property_v1_v2_identical_lookup_after_insert() {
        // Insert 5 data-only extents (within V1 max of 6).
        let mut v1 = InlineExtentMap::new();
        let mut v2 = BTreeExtentMap::new();
        let offsets = [0u64, 4096, 16384, 24576, 32768];
        for (i, off) in offsets.iter().enumerate() {
            let entry =
                ExtentMapEntryV2::new_data(*off, 4096, LocatorId(i as u64 + 1), [0u8; 32], 0);
            v1.insert_extent(&[entry.clone()]).unwrap();
            v2.insert_extent(&[entry]).unwrap();
        }
        // Lookup each extent start.
        for off in &offsets {
            let r1 = v1.lookup_range(*off, 4096).unwrap();
            let r2 = v2.lookup_range(*off, 4096).unwrap();
            assert_eq!(r1.len(), r2.len());
            assert_eq!(r1[0].logical_offset, r2[0].logical_offset);
            assert_eq!(r1[0].length, r2[0].length);
        }
        // Lookup across gaps.
        let r1 = v1.lookup_range(0, 36864).unwrap();
        let r2 = v2.lookup_range(0, 36864).unwrap();
        assert_eq!(r1.len(), r2.len());
        for (a, b) in r1.iter().zip(r2.iter()) {
            assert_eq!(a.logical_offset, b.logical_offset);
            assert_eq!(a.length, b.length);
        }
    }

    #[test]
    fn property_v1_v2_random_insert_punch_truncate_within_limits() {
        let mut v1: InlineExtentMap;
        let mut v2: BTreeExtentMap;
        let mut rng = SplitMix64(12345);

        // Keep entry count <= 5 so V1 doesn't overflow.
        for _round in 0..20 {
            // Clear and rebuild with 3-5 extents.
            v1 = InlineExtentMap::new();
            v2 = BTreeExtentMap::new();
            let n = 3 + (rng.next() % 3) as usize; // 3..5

            let mut used: Vec<u64> = Vec::new();
            for _ in 0..n {
                let off = (rng.next() % 50) * 4096;
                if used
                    .iter()
                    .any(|&o| (o..o + 4096).contains(&off) || (off..off + 4096).contains(&o))
                {
                    continue;
                }
                used.push(off);
                let e = ExtentMapEntryV2::new_data(off, 4096, LocatorId(1), [0u8; 32], 0);
                let _ = v1.insert_extent(&[e.clone()]);
                let _ = v2.insert_extent(&[e]);
            }

            // Verify lookups.
            for off in 0..(50 * 4096) {
                if off % 4096 != 0 {
                    continue;
                }
                let r1 = v1.lookup_range(off, 4096);
                let r2 = v2.lookup_range(off, 4096);
                assert_eq!(r1.is_ok(), r2.is_ok(), "lookup mismatch at offset {off}");
                if let (Ok(a), Ok(b)) = (&r1, &r2) {
                    assert_eq!(a.len(), b.len());
                    if a.len() == b.len() && !a.is_empty() {
                        assert_eq!(a[0].logical_offset, b[0].logical_offset);
                        assert_eq!(a[0].length, b[0].length);
                    }
                }
            }

            // Verify seek_data and seek_hole agree.
            for off in 0..(50 * 4096) {
                if off % 4096 != 0 {
                    continue;
                }
                let s1 = v1.seek_data(off);
                let s2 = v2.seek_data(off);
                assert_eq!(s1, s2, "seek_data mismatch at offset {off}");
                let h1 = v1.seek_hole(off);
                let h2 = v2.seek_hole(off);
                assert_eq!(h1, h2, "seek_hole mismatch at offset {off}");
            }
        }
    }

    #[test]
    fn property_v1_v2_punch_hole_consistency_within_limits() {
        let mut v1 = InlineExtentMap::new();
        let mut v2 = BTreeExtentMap::new();
        let mut rng = SplitMix64(999);

        // Build identical maps: 5 data extents at 8K boundaries.
        for i in 0..5u64 {
            let off = i * 8192;
            let e = ExtentMapEntryV2::new_data(off, 8192, LocatorId(i + 1), [0u8; 32], 0);
            v1.insert_extent(&[e.clone()]).unwrap();
            v2.insert_extent(&[e]).unwrap();
        }

        // Punch holes at random positions and compare.
        for _ in 0..30 {
            let off = (rng.next() % (5 * 8192)) & !0xFFF;
            let len = ((rng.next() % 4) + 1) * 4096;
            let r1 = v1.punch_hole(off, len);
            let r2 = v2.punch_hole(off, len);
            assert_eq!(r1.is_ok(), r2.is_ok(), "punch error mismatch");
            if let (Ok(f1), Ok(f2)) = (&r1, &r2) {
                assert_eq!(
                    f1.len(),
                    f2.len(),
                    "freed count mismatch for punch [{}, {})",
                    off,
                    off + len
                );
                for (a, b) in f1.iter().zip(f2.iter()) {
                    assert_eq!(a.logical_offset, b.logical_offset);
                    assert_eq!(a.length, b.length);
                    assert_eq!(a.extent_type, b.extent_type);
                }
            }
            // Verify all remaining entries via full scan.
            let all1 = v1.lookup_range(0, 5 * 8192).unwrap();
            let all2 = v2.lookup_range(0, 5 * 8192).unwrap();
            assert_eq!(all1.len(), all2.len());
            for (a, b) in all1.iter().zip(all2.iter()) {
                assert_eq!(a.logical_offset, b.logical_offset);
                assert_eq!(a.length, b.length);
                assert_eq!(a.extent_type(), b.extent_type());
            }
        }
    }

    #[test]
    fn property_v1_v2_truncate_consistency_within_limits() {
        let mut v1 = InlineExtentMap::new();
        let mut v2 = BTreeExtentMap::new();
        let mut rng = SplitMix64(7777);

        // Build identical maps: 5 data extents at 4K boundaries.
        for i in 0..5u64 {
            let off = i * 4096;
            let e = ExtentMapEntryV2::new_data(off, 4096, LocatorId(i + 1), [0u8; 32], 0);
            v1.insert_extent(&[e.clone()]).unwrap();
            v2.insert_extent(&[e]).unwrap();
        }

        // Truncate to various sizes.
        for _ in 0..20 {
            let new_size = (rng.next() % 6) * 4096; // 0..5*4096
            let r1 = v1.truncate(new_size);
            let r2 = v2.truncate(new_size);
            assert_eq!(r1.is_ok(), r2.is_ok(), "truncate to {new_size} mismatch");
            if let (Ok(f1), Ok(f2)) = (&r1, &r2) {
                assert_eq!(
                    f1.len(),
                    f2.len(),
                    "freed count mismatch for truncate to {new_size}"
                );
                for (a, b) in f1.iter().zip(f2.iter()) {
                    assert_eq!(a.logical_offset, b.logical_offset);
                    assert_eq!(a.length, b.length);
                    assert_eq!(a.extent_type, b.extent_type);
                }
            }
        }
    }

    #[test]
    fn property_v1_v2_iteration_and_seek_identical() {
        let mut v1 = InlineExtentMap::new();
        let mut v2 = BTreeExtentMap::new();

        let offsets = [0u64, 4096, 16384, 24576, 32768];
        for (i, off) in offsets.iter().enumerate() {
            let e = ExtentMapEntryV2::new_data(*off, 4096, LocatorId(i as u64 + 1), [0u8; 32], 0);
            v1.insert_extent(&[e.clone()]).unwrap();
            v2.insert_extent(&[e]).unwrap();
        }

        let all1 = v1.lookup_range(0, 36864).unwrap();
        let all2 = v2.lookup_range(0, 36864).unwrap();
        assert_eq!(all1.len(), all2.len());
        for (a, b) in all1.iter().zip(all2.iter()) {
            assert_eq!(a.logical_offset, b.logical_offset);
            assert_eq!(a.length, b.length);
        }

        for off in 0..37000u64 {
            if off % 4096 == 0 {
                let s1 = v1.seek_data(off);
                let s2 = v2.seek_data(off);
                assert_eq!(s1, s2, "seek_data mismatch at offset {off}");
                let h1 = v1.seek_hole(off);
                let h2 = v2.seek_hole(off);
                assert_eq!(h1, h2, "seek_hole mismatch at offset {off}");
            }
        }
    }

    #[test]
    fn property_v1_v2_fallocate_and_convert_unwritten() {
        let mut v1 = InlineExtentMap::new();
        let mut v2 = BTreeExtentMap::new();

        v1.fallocate(0, 16384, false).unwrap();
        v2.fallocate(0, 16384, false).unwrap();

        let checksum = [0xAB; 32];
        v1.convert_unwritten_to_data(4096, 8192, LocatorId(10), checksum, 1)
            .unwrap();
        v2.convert_unwritten_to_data(4096, 8192, LocatorId(10), checksum, 2)
            .unwrap();

        let all1 = v1.lookup_range(0, 16384).unwrap();
        let all2 = v2.lookup_range(0, 16384).unwrap();
        assert_eq!(all1.len(), all2.len());
        for (a, b) in all1.iter().zip(all2.iter()) {
            assert_eq!(a.logical_offset, b.logical_offset);
            assert_eq!(a.length, b.length);
            assert_eq!(a.extent_type(), b.extent_type());
        }

        // Per tristate model: UNWRITTEN is not a hole for SEEK_HOLE.
        // After converting middle to data, the remaining unwritten at
        // [0, 4096) and [12288, 16384) are NOT holes.
        // So seek_hole(0) should skip past all entries to end, returning None.
        let h1 = v1.seek_hole(0);
        let h2 = v2.seek_hole(0);
        assert_eq!(h1, h2);
    }

    // =====================================================================
    // V2-only scale tests (BTreeExtentMap with large entry counts)
    // =====================================================================

    #[test]
    fn property_v2_lookup_large_scale() {
        let mut map = BTreeExtentMap::new();
        // Insert 500 data extents.
        for i in 0..500u64 {
            let off = i * 4096;
            let e = ExtentMapEntryV2::new_data(off, 4096, LocatorId(i + 1), [0u8; 32], 0);
            map.insert_extent(&[e]).unwrap();
        }
        // Verify validate.
        assert!(map.validate().is_ok());
        // Point lookup at every 50th extent.
        for i in (0..500u64).step_by(50) {
            let r = map.lookup_range(i * 4096, 4096).unwrap();
            assert_eq!(r.len(), 1);
            assert_eq!(r[0].logical_offset, i * 4096);
            assert_eq!(r[0].length, 4096);
        }
        // Range lookup across many extents.
        let r = map.lookup_range(100 * 4096, 200 * 4096).unwrap();
        assert!(r.len() >= 100);
    }

    #[test]
    fn property_v2_insert_overwrite_large() {
        let mut map = BTreeExtentMap::new();
        // Insert sparse extents.
        for i in 0..100u64 {
            let off = i * 8192;
            let e = ExtentMapEntryV2::new_data(off, 4096, LocatorId(i + 1), [0u8; 32], 0);
            map.insert_extent(&[e]).unwrap();
        }
        assert_eq!(map.header.entry_count, 100);
        // Overwrite a range spanning 10 extents with one big extent.
        let big = ExtentMapEntryV2::new_data(10 * 8192, 10 * 8192, LocatorId(999), [0xAA; 32], 0);
        map.insert_extent(&[big]).unwrap();
        let r = map.lookup_range(10 * 8192, 10 * 8192).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].length, 10 * 8192);
        assert_eq!(r[0].locator_id, LocatorId(999));
        assert!(map.validate().is_ok());
    }

    #[test]
    fn property_v2_truncate_and_punch_large() {
        let mut map = BTreeExtentMap::new();
        for i in 0..200u64 {
            let off = i * 4096;
            let e = ExtentMapEntryV2::new_data(off, 4096, LocatorId(i + 1), [0u8; 32], 0);
            map.insert_extent(&[e]).unwrap();
        }
        // Truncate to half.
        let freed = map.truncate(100 * 4096).unwrap();
        assert!(!freed.is_empty());
        assert_eq!(map.header.entry_count, 100);
        assert!(map.validate().is_ok());
        // Punch a hole in the middle.
        let freed2 = map.punch_hole(50 * 4096, 10 * 4096).unwrap();
        assert!(!freed2.is_empty());
        assert!(map.validate().is_ok());
    }

    // =====================================================================
    // Delete/structure tests: tree shape after deletes
    // =====================================================================

    #[test]
    fn delete_via_truncate_collapses_multi_level_tree() {
        // Build a 3-level tree with 100 entries.
        let mut map = BTreeExtentMap::new();
        for i in 0..100u64 {
            let e = ExtentMapEntryV2::new_data(i * 4096, 4096, LocatorId(i + 1), [0u8; 32], 0);
            map.insert_extent(&[e]).unwrap();
        }
        assert!(map.header.depth >= 1, "depth: {}", map.header.depth);
        let leaves_before = map.tree.leaf_count();
        let internal_before = map.tree.internal_count();

        // Truncate to 4096 bytes: keep only first entry.
        let freed = map.truncate(4096).unwrap();
        assert!(!freed.is_empty());
        assert_eq!(map.header.entry_count, 1);
        assert_eq!(map.header.depth, 1);
        assert!(
            map.tree.leaf_count() < leaves_before,
            "leaf count should shrink after truncate; was {}, now {}",
            leaves_before,
            map.tree.leaf_count()
        );
        assert!(
            map.tree.internal_count() < internal_before,
            "internal count should shrink; was {}, now {}",
            internal_before,
            map.tree.internal_count()
        );
        assert!(map.validate().is_ok());
    }

    #[test]
    fn delete_via_punch_hole_reduces_leaf_count() {
        // Build a 2-level tree.
        let mut map = BTreeExtentMap::new();
        for i in 0..50u64 {
            let e = ExtentMapEntryV2::new_data(i * 4096, 4096, LocatorId(i + 1), [0u8; 32], 0);
            map.insert_extent(&[e]).unwrap();
        }
        assert!(map.header.depth >= 2);
        let leaves_before = map.tree.leaf_count();

        // Punch holes spanning most of the data range.
        for i in 10..40u64 {
            let freed = map.punch_hole(i * 4096, 4096).unwrap();
            // Each hole should free one extent.
            assert_eq!(freed.len(), 1, "punch at {} should free 1 extent", i * 4096);
        }

        // After removing 30 extents, tree should compact to fewer leaves.
        assert!(
            map.tree.leaf_count() < leaves_before,
            "leaf count should shrink: was {}, now {}",
            leaves_before,
            map.tree.leaf_count()
        );
        assert!(map.validate().is_ok());
    }

    #[test]
    fn delete_via_collapse_range_shifts_and_compacts() {
        let mut map = BTreeExtentMap::new();
        for i in 0..20u64 {
            let e = ExtentMapEntryV2::new_data(i * 4096, 4096, LocatorId(i + 1), [0u8; 32], 0);
            map.insert_extent(&[e]).unwrap();
        }
        let count_before = map.header.entry_count;
        let leaf_before = map.tree.leaf_count();

        // Collapse the middle range: removes entries and shifts tail left.
        let freed = map.collapse_range(4 * 4096, 8 * 4096).unwrap();
        assert!(!freed.is_empty());

        // Entry count should decrease.
        assert!(map.header.entry_count < count_before);
        // Tree should validate and potentially compact.
        assert!(map.tree.leaf_count() <= leaf_before);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn delete_all_to_empty_tree() {
        let mut map = BTreeExtentMap::new();
        for i in 0..50u64 {
            let e = ExtentMapEntryV2::new_data(i * 4096, 4096, LocatorId(i + 1), [0u8; 32], 0);
            map.insert_extent(&[e]).unwrap();
        }
        assert!(map.header.depth >= 2);

        // Truncate to zero.
        let freed = map.truncate(0).unwrap();
        assert!(!freed.is_empty());
        assert_eq!(map.header.entry_count, 0);
        assert_eq!(map.header.depth, 1);
        assert_eq!(map.tree.leaf_count(), 1); // empty root leaf
        assert_eq!(map.tree.internal_count(), 0);
        assert!(map.collect_all().is_empty());
        assert!(map.validate().is_ok());
    }

    #[test]
    fn delete_preserves_remaining_entries_correctly() {
        let mut map = BTreeExtentMap::new();
        for i in 0..100u64 {
            let e = ExtentMapEntryV2::new_data(i * 4096, 4096, LocatorId(i + 1), [0u8; 32], 0);
            map.insert_extent(&[e]).unwrap();
        }

        // Truncate to remove entries 50-99.
        let freed = map.truncate(50 * 4096).unwrap();
        assert_eq!(freed.len(), 50);

        // Verify each remaining entry is findable.
        for i in 0..50u64 {
            let r = map.lookup_range(i * 4096, 4096).unwrap();
            assert_eq!(r.len(), 1, "entry {i} should exist after truncate");
            assert_eq!(r[0].logical_offset, i * 4096);
            assert_eq!(r[0].length, 4096);
        }
        // Entries beyond the truncate point should be gone.
        assert!(map.lookup_range(50 * 4096, 4096).unwrap().is_empty());
        assert!(map.validate().is_ok());
    }

    #[test]
    fn cascading_delete_two_level_tree() {
        // Build a 2-level tree with 50 entries.
        let mut map = BTreeExtentMap::new();
        for i in 0..50u64 {
            let e = ExtentMapEntryV2::new_data(i * 4096, 4096, LocatorId(i + 1), [0u8; 32], 0);
            map.insert_extent(&[e]).unwrap();
        }
        assert!(
            map.header.depth >= 2,
            "expected >= 2-level tree, got depth {}",
            map.header.depth
        );

        // Punch a large middle range to remove entries spanning multiple leaves.
        let freed = map.punch_hole(10 * 4096, 30 * 4096).unwrap();
        assert!(!freed.is_empty());

        // After removing entries, tree should remain valid.
        assert!(map.validate().is_ok());

        // Verify remaining entries and tree compaction.
        let remaining = map.collect_all();
        assert_eq!(remaining.len(), map.header.entry_count as usize);
        assert_eq!(map.header.entry_count, 20); // 50 - 30 = 20 entries remaining
        assert!(map.tree.depth() <= 2);
    }

    #[test]
    fn repeated_truncate_shrink_expand_idempotent() {
        let mut map = BTreeExtentMap::new();
        for i in 0..30u64 {
            let e = ExtentMapEntryV2::new_data(i * 4096, 4096, LocatorId(i + 1), [0u8; 32], 0);
            map.insert_extent(&[e]).unwrap();
        }

        // Shrink -> expand -> shrink
        map.truncate(10 * 4096).unwrap();
        map.truncate(20 * 4096).unwrap(); // expand
        map.truncate(5 * 4096).unwrap(); // shrink again

        assert_eq!(map.header.entry_count, 5);
        assert!(map.validate().is_ok());
        assert_eq!(map.header.file_size, 5 * 4096);
    }

    // =====================================================================
    // Serialize/Deserialize tests
    // =====================================================================

    #[test]
    fn serde_roundtrip_empty() {
        let map = BTreeExtentMap::new();
        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();
        assert!(!buf.is_empty());

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = BTreeExtentMap::deserialize(&mut cursor).unwrap();
        assert_eq!(recon.header.entry_count, 0);
        assert!(recon.collect_all().is_empty());
        assert!(recon.validate().is_ok());
    }

    #[test]
    fn serde_roundtrip_populated() {
        let mut map = BTreeExtentMap::new();
        for i in 0..10u64 {
            let e = ExtentMapEntryV2::new_data(i * 4096, 4096, LocatorId(i + 1), [0u8; 32], 0);
            map.insert_extent(&[e]).unwrap();
        }

        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = BTreeExtentMap::deserialize(&mut cursor).unwrap();

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
        let mut map = BTreeExtentMap::new();
        map.fallocate(0, 16384, false).unwrap();
        map.convert_unwritten_to_data(4096, 8192, LocatorId(10), [0xAB; 32], 1)
            .unwrap();

        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = BTreeExtentMap::deserialize(&mut cursor).unwrap();

        let entries = recon.collect_all();
        assert_eq!(entries.len(), 3); // unwritten + data + unwritten
        assert!(recon.validate().is_ok());
    }

    #[test]
    fn serde_wrong_magic_rejected() {
        let buf = b"XXXX".to_vec();
        let mut cursor = std::io::Cursor::new(&buf);
        let err = BTreeExtentMap::deserialize(&mut cursor).unwrap_err();
        assert_eq!(err, ExtentMapError::WrongVersion);
    }

    #[test]
    fn serde_wrong_version_rejected() {
        let buf = b"VX22\x63\x00".to_vec();
        let mut cursor = std::io::Cursor::new(&buf);
        let err = BTreeExtentMap::deserialize(&mut cursor).unwrap_err();
        assert_eq!(err, ExtentMapError::WrongVersion);
    }

    #[test]
    fn serde_truncated_data_rejected() {
        let mut map = BTreeExtentMap::new();
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
        let err = BTreeExtentMap::deserialize(&mut cursor).unwrap_err();
        assert_eq!(err, ExtentMapError::Corrupt);
    }

    #[test]
    fn serde_large_roundtrip() {
        let mut map = BTreeExtentMap::new();
        for i in 0..200u64 {
            let e = ExtentMapEntryV2::new_data(i * 4096, 4096, LocatorId(i + 1), [0xAA; 32], 0);
            map.insert_extent(&[e]).unwrap();
        }
        assert!(map.header.depth >= 2);

        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = BTreeExtentMap::deserialize(&mut cursor).unwrap();

        assert_eq!(recon.header.entry_count, 200);
        assert_eq!(recon.header.file_size, 200 * 4096);
        assert!(recon.validate().is_ok());

        // Verify a few lookups.
        for i in [0, 50, 100, 150, 199] {
            let r = recon.lookup_range(i * 4096, 4096).unwrap();
            assert_eq!(r.len(), 1);
        }
    }

    #[test]
    fn serde_roundtrip_fragmented_multi_page_preserves_page_count_and_tail() {
        let max_per_page = crate::page_io::max_entries_per_page();
        let total = max_per_page * 5 + 7;
        let mut map = BTreeExtentMap::new();

        for i in 0..total as u64 {
            let offset = i * 8192;
            let entry = if i % 17 == 0 {
                unwritten(offset, 4096)
            } else {
                ExtentMapEntryV2::new_data(offset, 4096, LocatorId(i + 1), [i as u8; 32], i)
            };
            map.insert_extent(&[entry]).unwrap();
        }
        assert_eq!(map.header.entry_count, total as u64);

        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        let expected_pages = total.div_ceil(max_per_page);
        let serialized_pages = u32::from_le_bytes(buf[6..10].try_into().unwrap()) as usize;
        assert_eq!(serialized_pages, expected_pages);
        assert_eq!(
            buf.len(),
            10 + expected_pages * EXTENT_MAP_DEFAULT_PAGE_SIZE
        );

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = BTreeExtentMap::deserialize(&mut cursor).unwrap();

        assert_eq!(recon.header.entry_count, total as u64);
        assert!(recon.validate().is_ok());

        let unwritten_entry = recon.lookup_range(17 * 8192, 4096).unwrap();
        assert_eq!(unwritten_entry.len(), 1);
        assert!(unwritten_entry[0].is_unwritten());

        let tail_offset = (total as u64 - 1) * 8192;
        let tail = recon.lookup_range(tail_offset, 4096).unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].logical_offset, tail_offset);
        assert_eq!(tail[0].locator_id, LocatorId(total as u64));
    }

    #[test]
    fn serde_streamed_deserialize_rejects_out_of_order_page_entries() {
        let mut buf = Vec::new();
        buf.extend_from_slice(BTREE_EXTENT_MAP_MAGIC);
        buf.extend_from_slice(&[BTREE_EXTENT_MAP_VERSION, 0u8]);
        buf.extend_from_slice(&1u32.to_le_bytes());
        crate::page_io::serialize_leaf_page(&mut buf, &[data(4096, 4096, 2), data(0, 4096, 1)])
            .unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let err = BTreeExtentMap::deserialize(&mut cursor).unwrap_err();

        assert_eq!(err, ExtentMapError::Corrupt);
    }
    // ── rebuild_lazy + drain_underfull + compact_tree ──────────────

    #[test]
    fn rebuild_lazy_then_compact_restores_invariants() {
        let mut map = BTreeExtentMap::new();
        let mut entries: Vec<ExtentMapEntryV2> = Vec::new();
        for i in 0..200u64 {
            entries.push(data(i * 4096, 4096, 0));
        }
        map.insert_extent(&entries).unwrap();
        assert!(map.header.depth >= 1, "depth: {}", map.header.depth);

        // Punch holes to remove most extents
        map.punch_hole(0, 180 * 4096).unwrap();

        // Collect all and rebuild_lazy (non-compact)
        let remaining = map.collect_all();
        map.rebuild_lazy(&remaining);

        // Compact the tree
        let stats = map.compact_tree();
        // fill_after may be <0.5 for small trees where root is the only node;
        // root is exempt from minimum fill.
        assert!(stats.fill_after > 0.0);
    }

    #[test]
    fn drain_underfull_nodes_after_truncate_compact() {
        let mut map = BTreeExtentMap::new();
        let mut entries: Vec<ExtentMapEntryV2> = Vec::new();
        for i in 0..200u64 {
            entries.push(data(i * 4096, 4096, 0));
        }
        map.insert_extent(&entries).unwrap();

        // Truncate — existing truncate calls rebuild() which includes compact()
        map.truncate(20 * 4096).unwrap();
        // After truncate+compact, only 20 entries remain in <= 1 leaf (root),
        // so underfull_nodes returns empty (root exempt).
        let under = map.drain_underfull_nodes();
        assert!(under.is_empty());
    }

    #[test]
    fn drain_underfull_nodes_empty_on_small_map() {
        let mut map = BTreeExtentMap::new();
        map.insert_extent(&[data(0, 4096, 0)]).unwrap();
        let under = map.drain_underfull_nodes();
        assert!(under.is_empty());
    }
}
