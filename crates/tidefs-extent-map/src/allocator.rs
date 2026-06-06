//! Extent allocator primitives.
//!
//! `ExtentAllocator` manages physical extent allocation for the local
//! filesystem write path. Each `allocate_extent` call picks a physical
//! range, records the logical-to-physical mapping in a per-inode
//! [`PolymorphicExtentMap`], and returns an [`ExtentId`].
//!
//! The block allocator reference is a simplified counter-based model for
//! Phase 1; it will be replaced by `tidefs_spacemap_allocator` integration
//! under Review debt TFR-005.
//!
//! The implementation is `#[forbid(unsafe_code)]` and targets correctness.

use std::collections::BTreeMap;

use tidefs_types_extent_map_core::{
    ExtentId, ExtentLifecycleState, ExtentMapEntryV2, ExtentMapError, ExtentMapOps, LocatorId,
};

use tidefs_shard_group::{ExtentScan, IngestExtent, ReplicaLifecycle};

use crate::{split_into_recordsize_chunks, PolymorphicExtentMap, RecordsizePolicy};

/// Errors returned by the extent allocator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtentAllocError {
    /// No physical space available for a new extent.
    OutOfSpace,
    /// The requested logical offset or length is invalid.
    InvalidOffset,
    /// The extent was not found in the map.
    ExtentNotFound,
    /// The underlying extent map returned an error.
    MapError(ExtentMapError),
}

impl core::fmt::Display for ExtentAllocError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutOfSpace => write!(f, "no physical space available"),
            Self::InvalidOffset => write!(f, "invalid logical offset"),
            Self::ExtentNotFound => write!(f, "extent not found"),
            Self::MapError(e) => write!(f, "extent map error: {e}"),
        }
    }
}

impl std::error::Error for ExtentAllocError {}

impl From<ExtentMapError> for ExtentAllocError {
    fn from(e: ExtentMapError) -> Self {
        match e {
            ExtentMapError::InvalidRange => Self::InvalidOffset,
            ExtentMapError::NotFound => Self::ExtentNotFound,
            other => Self::MapError(other),
        }
    }
}

/// Phase-1 extent allocator with a simple counter-based block allocator.
///
/// Manages per-inode [`PolymorphicExtentMap`] instances, assigning monotonically
/// increasing [`LocatorId`] and [`ExtentId`] values to each allocated extent.
///
/// When the spacemap allocator integration lands, the `next_locator` counter
/// will be replaced by `SegmentFreeMap` queries.
#[derive(Clone, Debug, Default)]
pub struct ExtentAllocator {
    /// Per-inode (keyed by inode number) extent maps.
    maps: BTreeMap<u64, PolymorphicExtentMap>,
    /// Monotonically increasing extent id counter.
    next_extent_id: u64,
    /// Monotonically increasing locator id counter (physical address).
    next_locator: u64,
}

impl ExtentAllocator {
    /// Create an empty extent allocator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an allocator with a given initial locator offset (e.g. for
    /// test determinism or after recovery).
    #[must_use]
    pub fn with_initial_locator(initial_locator: u64) -> Self {
        Self {
            maps: BTreeMap::new(),
            next_extent_id: 0,
            next_locator: initial_locator,
        }
    }

    /// Allocate extents for `inode` at `logical_offset` with `length`.
    ///
    /// When `recordsize` is `None`, the entire range is allocated as a
    /// single extent (existing behavior). When a policy is active, the
    /// range is split at recordsize-aligned boundaries so that no single
    /// extent exceeds the effective recordsize.
    ///
    /// Returns the assigned [`ExtentId`] and [`LocatorId`] for each
    /// allocated chunk. The extent map entries are created with
    /// `KIND_PENDING_DATA` — the caller must call [`finalize_data_extent`]
    /// after content is written and hashed to promote the entry to
    /// finalized `KIND_DATA` with an authoritative checksum.
    pub fn allocate_extent(
        &mut self,
        inode: u64,
        logical_offset: u64,
        length: u64,
        recordsize: Option<RecordsizePolicy>,
    ) -> Result<Vec<(ExtentId, LocatorId)>, ExtentAllocError> {
        if length == 0 {
            return Err(ExtentAllocError::InvalidOffset);
        }

        let chunks = match recordsize {
            Some(ref policy) => {
                let rs = policy.effective_max();
                if rs == 0 {
                    vec![(logical_offset, length)]
                } else {
                    split_into_recordsize_chunks(logical_offset, length, rs)
                }
            }
            None => vec![(logical_offset, length)],
        };

        let mut results = Vec::with_capacity(chunks.len());
        for (chunk_offset, chunk_len) in chunks {
            let extent_id = ExtentId(self.next_extent_id);
            self.next_extent_id = self.next_extent_id.wrapping_add(1);

            let locator_id = LocatorId(self.next_locator);
            self.next_locator = self.next_locator.wrapping_add(chunk_len);

            let mut entry = ExtentMapEntryV2::new_pending_data(chunk_offset, chunk_len, locator_id);

            entry.set_ingest();

            let map = self.maps.entry(inode).or_default();
            map.insert_extent(&[entry])?;

            results.push((extent_id, locator_id));
        }

        Ok(results)
    }

    /// Allocate Unwritten extents for fallocate reservation.
    ///
    /// Like `allocate_extent` but creates entries with
    /// `ExtentType::Unwritten` instead of `ExtentType::Data`.
    /// Unwritten extents reserve space for future writes without
    /// writing zeros; reads return zero-filled content and writes
    /// convert the extent to Data.
    ///
    /// Recordsize-splitting semantics match `allocate_extent`.
    pub fn allocate_unwritten_extent(
        &mut self,
        inode: u64,
        logical_offset: u64,
        length: u64,
        recordsize: Option<RecordsizePolicy>,
        birth_commit_group: u64,
    ) -> Result<Vec<(ExtentId, LocatorId)>, ExtentAllocError> {
        if length == 0 {
            return Err(ExtentAllocError::InvalidOffset);
        }

        let chunks = match recordsize {
            Some(ref policy) => {
                let rs = policy.effective_max();
                if rs == 0 {
                    vec![(logical_offset, length)]
                } else {
                    split_into_recordsize_chunks(logical_offset, length, rs)
                }
            }
            None => vec![(logical_offset, length)],
        };

        let mut results = Vec::with_capacity(chunks.len());
        for (chunk_offset, chunk_len) in chunks {
            let extent_id = ExtentId(self.next_extent_id);
            self.next_extent_id = self.next_extent_id.wrapping_add(1);

            let locator_id = LocatorId(self.next_locator);
            self.next_locator = self.next_locator.wrapping_add(chunk_len);

            let entry =
                ExtentMapEntryV2::new_unwritten(chunk_offset, chunk_len, birth_commit_group);

            let map = self.maps.entry(inode).or_default();
            map.insert_extent(&[entry])?;

            results.push((extent_id, locator_id));
        }

        Ok(results)
    }

    /// Finalize pending-data extents for `inode` covering
    /// `[logical_offset, logical_offset + length)` by transitioning them to
    /// [`KIND_DATA`] with the supplied content checksum and birth commit group.
    ///
    /// Only entries whose `extent_kind` is [`KIND_PENDING_DATA`] are affected;
    /// already-finalized entries are left unchanged.  Returns the number of
    /// entries that were finalized.
    ///
    /// # Errors
    ///
    /// Returns [`ExtentAllocError::ExtentNotFound`] if `inode` has no extents
    /// or no entry covers the requested range.
    pub fn finalize_data_extent(
        &mut self,
        inode: u64,
        logical_offset: u64,
        length: u64,
        checksum: [u8; 32],
        birth_commit_group: u64,
    ) -> Result<usize, ExtentAllocError> {
        let map = self
            .maps
            .get_mut(&inode)
            .ok_or(ExtentAllocError::ExtentNotFound)?;

        let mut entries = map.entries_snapshot();
        let candidates: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                e.is_pending_data()
                    && e.logical_offset < logical_offset + length
                    && e.end_offset() > logical_offset
            })
            .map(|(i, _)| i)
            .collect();

        if candidates.is_empty() {
            return Err(ExtentAllocError::ExtentNotFound);
        }

        let count = candidates.len();
        for idx in candidates {
            entries[idx].finalize_data(checksum, birth_commit_group);
        }
        map.replace_entries_preserving_totals(&entries)?;

        Ok(count)
    }

    /// Look up extents for `inode` in the given logical range.
    ///
    /// Returns the list of [`ExtentMapEntryV2`] entries that intersect
    /// `[logical_offset, logical_offset + length)`, clipped to the query
    /// range.
    pub fn lookup_extents(
        &self,
        inode: u64,
        logical_offset: u64,
        length: u64,
    ) -> Vec<ExtentMapEntryV2> {
        let map = match self.maps.get(&inode) {
            Some(m) => m,
            None => return Vec::new(),
        };
        map.lookup_range(logical_offset, length).unwrap_or_default()
    }

    /// Find the next data byte offset at or after `offset` for `inode`.
    ///
    /// Delegates to the underlying [`PolymorphicExtentMap::seek_data`].
    /// Returns `Some((start, remaining))` if a DATA or UNWRITTEN extent
    /// exists at or after `offset`, or `None` if no data region is found.
    #[must_use]
    pub fn seek_data(&self, inode: u64, offset: u64) -> Option<(u64, u64)> {
        self.maps.get(&inode).and_then(|m| m.seek_data(offset))
    }

    /// Find the next hole byte offset at or after `offset` for `inode`.
    ///
    /// Delegates to the underlying [`PolymorphicExtentMap::seek_hole`].
    /// Returns `Some((start, remaining))` if a hole is found at or after
    /// `offset`, or `None` if no hole exists before EOF or `offset` is
    /// past EOF.
    #[must_use]
    pub fn seek_hole(&self, inode: u64, offset: u64) -> Option<(u64, u64)> {
        self.maps.get(&inode).and_then(|m| m.seek_hole(offset))
    }

    /// Free an extent by removing its mapping from the extent map.
    ///
    /// The physical blocks are returned to the free pool for reuse.
    pub fn free_extent(
        &mut self,
        inode: u64,
        logical_offset: u64,
        length: u64,
    ) -> Result<(), ExtentAllocError> {
        let map = self
            .maps
            .get_mut(&inode)
            .ok_or(ExtentAllocError::ExtentNotFound)?;

        let freed = map.punch_hole(logical_offset, length)?;
        if freed.is_empty() {
            return Err(ExtentAllocError::ExtentNotFound);
        }
        Ok(())
    }

    /// Resize an extent by freeing the old range and allocating a new one.
    ///
    /// This is a naive resize that frees the old range and allocates a new
    /// one. A production implementation would attempt in-place resize first.
    pub fn resize_extent(
        &mut self,
        inode: u64,
        logical_offset: u64,
        old_length: u64,
        new_length: u64,
    ) -> Result<Vec<(ExtentId, LocatorId)>, ExtentAllocError> {
        if new_length == 0 {
            return Err(ExtentAllocError::InvalidOffset);
        }
        self.free_extent(inode, logical_offset, old_length)?;
        self.allocate_extent(inode, logical_offset, new_length, None)
    }

    /// Return total number of extents across all inodes.
    #[must_use]
    pub fn total_extents(&self) -> usize {
        self.maps.values().map(|m| m.entry_count() as usize).sum()
    }

    /// Check whether a given inode has any extents.
    #[must_use]
    pub fn has_extents(&self, inode: u64) -> bool {
        self.maps.get(&inode).is_some_and(|m| m.entry_count() > 0)
    }

    /// Remove all extent state for an inode that has left the live namespace.
    pub fn remove_inode(&mut self, inode: u64) -> bool {
        self.maps.remove(&inode).is_some()
    }

    /// Return all extents currently in the INGEST lifecycle state
    /// (awaiting rebake to base placement). Each entry is paired with
    /// its owning inode number.
    ///
    /// This is the production query that feeds the rebake candidate
    /// scanner. Only `ExtentType::Data` extents with `FLAG_INGEST` set
    /// and `FLAG_BASE_COMPLETE` clear are returned.
    #[must_use]
    pub fn ingest_candidates(&self) -> Vec<(u64, ExtentMapEntryV2)> {
        let mut candidates = Vec::new();
        for (&inode, map) in self.maps.iter() {
            for entry in map.entries_snapshot() {
                if (entry.is_data() || entry.is_pending_data())
                    && entry.lifecycle_state() == ExtentLifecycleState::Ingest
                {
                    candidates.push((inode, entry));
                }
            }
        }
        candidates
    }

    /// Transition all ingest extents for `inode` within the given
    /// logical range to BASE_COMPLETE. Returns the count of extents
    /// actually transitioned.
    ///
    /// This is called after a successful rebake commit so the extent
    /// map reflects the durable base placement.
    pub fn mark_rebaked(&mut self, inode: u64, offset: u64, length: u64) -> usize {
        let map = match self.maps.get_mut(&inode) {
            Some(m) => m,
            None => return 0,
        };
        let mut count = 0;
        let mut entries = map.entries_snapshot();
        for entry in entries.iter_mut() {
            if (entry.is_data() || entry.is_pending_data())
                && entry.lifecycle_state() == ExtentLifecycleState::Ingest
                && entry.intersects(offset, length)
            {
                entry.set_base_complete();
                count += 1;
            }
        }
        if count > 0 {
            let _ = map.replace_entries_preserving_totals(&entries);
        }
        count
    }

    /// Count ingest extents, returning per-state totals for durability
    /// monitoring ("observable durability level and age/bytes/count").
    #[must_use]
    pub fn ingest_summary(&self) -> IngestSummary {
        let mut s = IngestSummary::default();
        for map in self.maps.values() {
            for entry in map.entries_snapshot() {
                s.total_extents = s.total_extents.saturating_add(1);
                s.total_bytes = s.total_bytes.saturating_add(entry.length);
                match entry.lifecycle_state() {
                    ExtentLifecycleState::Ingest => {
                        s.ingest_count = s.ingest_count.saturating_add(1);
                        s.ingest_bytes = s.ingest_bytes.saturating_add(entry.length);
                    }
                    ExtentLifecycleState::BaseComplete => {
                        s.base_complete_count = s.base_complete_count.saturating_add(1);
                    }
                    ExtentLifecycleState::Dead => {
                        s.dead_count = s.dead_count.saturating_add(1);
                    }
                    ExtentLifecycleState::Freed => {}
                }
            }
        }
        s
    }
}

impl ExtentScan for ExtentAllocator {
    fn list_rebake_candidates(&self) -> Result<Vec<IngestExtent>, String> {
        let candidates = self.ingest_candidates();
        candidates
            .into_iter()
            .map(|(_inode, entry)| {
                // On a single-node setup, INGEST extents are treated as
                // Replicated for rebake purposes: the data is already
                // durable on local storage and ready for base-shard
                // conversion without an explicit replication hop.
                Ok(IngestExtent {
                    extent_key: entry.locator_id.0,
                    dataset_id: 0, // single-node: no per-dataset tracking
                    data_size: entry.length,
                    lifecycle: ReplicaLifecycle::Replicated,
                })
            })
            .collect()
    }

    fn ingest_bytes_total(&self) -> Result<u64, String> {
        Ok(self.ingest_summary().ingest_bytes)
    }
}

/// Observable ingest state summary for durability monitoring.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IngestSummary {
    /// Total extent count across all lifecycle states.
    pub total_extents: u64,
    /// Total logical bytes across all extents.
    pub total_bytes: u64,
    /// Extents still awaiting rebake (INGEST flag).
    pub ingest_count: u64,
    /// Logical bytes in ingest state awaiting rebake.
    pub ingest_bytes: u64,
    /// Extents already rebaked to base placement (BASE_COMPLETE).
    pub base_complete_count: u64,
    /// Extents marked dead and awaiting reclamation.
    pub dead_count: u64,
}

impl IngestSummary {
    /// Fraction of extents still in ingest state (0.0-1.0).
    #[must_use]
    pub fn ingest_fraction(&self) -> f64 {
        if self.total_extents == 0 {
            return 0.0;
        }
        self.ingest_count as f64 / self.total_extents as f64
    }

    /// Returns true when no extents are awaiting rebake.
    #[must_use]
    pub const fn all_rebaked(&self) -> bool {
        self.ingest_count == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_then_lookup_returns_correct_physical_range() {
        let mut allocator = ExtentAllocator::new();

        let results = allocator
            .allocate_extent(1, 0, 4096, None)
            .expect("allocation should succeed");
        let (extent_id, locator_id) = results[0];

        // Verify ExtentId and LocatorId are assigned.
        assert_eq!(extent_id, ExtentId(0));
        assert_eq!(locator_id, LocatorId(0));

        // Look up the extent and verify physical mapping.
        let entries = allocator.lookup_extents(1, 0, 4096);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].logical_offset, 0);
        assert_eq!(entries[0].length, 4096);
        assert_eq!(entries[0].locator_id, LocatorId(0));
        assert!(entries[0].is_pending_data());
    }

    #[test]
    fn multiple_extents_per_file() {
        let mut allocator = ExtentAllocator::new();

        allocator.allocate_extent(1, 0, 4096, None).unwrap();
        allocator.allocate_extent(1, 16384, 4096, None).unwrap();
        allocator.allocate_extent(1, 32768, 8192, None).unwrap();

        // Lookup the middle extent specifically.
        let entries = allocator.lookup_extents(1, 16384, 4096);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].logical_offset, 16384);
        assert_eq!(entries[0].length, 4096);

        // Full scan across all three.
        let entries = allocator.lookup_extents(1, 0, 40960);
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn sparse_file_extents_scale_past_inline_limit() {
        let mut allocator = ExtentAllocator::new();
        let inode = 1;

        for i in 0..64 {
            allocator
                .allocate_extent(inode, i * 8192, 512, None)
                .expect("sparse allocation should scale past inline map size");
        }

        assert_eq!(allocator.total_extents(), 64);
        for i in 0..64 {
            let offset = i * 8192;
            let entries = allocator.lookup_extents(inode, offset, 512);
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].logical_offset, offset);
            assert_eq!(entries[0].length, 512);
            assert!(entries[0].is_pending_data());
        }
        assert_eq!(allocator.seek_data(inode, 4096), Some((8192, 512)));
        assert_eq!(allocator.seek_hole(inode, 0), Some((512, 7680)));

        allocator
            .finalize_data_extent(inode, 0, 64 * 8192, [0xA5; 32], 42)
            .expect("finalize sparse extents");
        let entries = allocator.lookup_extents(inode, 0, 64 * 8192);
        assert_eq!(entries.len(), 64);
        assert!(entries.iter().all(|entry| entry.is_data()));
    }

    #[test]
    fn free_then_lookup_returns_empty() {
        let mut allocator = ExtentAllocator::new();

        allocator.allocate_extent(1, 0, 4096, None).unwrap();
        allocator.free_extent(1, 0, 4096).unwrap();

        let entries = allocator.lookup_extents(1, 0, 4096);
        assert!(entries.is_empty());
    }

    #[test]
    fn allocate_zero_length_rejected() {
        let mut allocator = ExtentAllocator::new();
        let err = allocator.allocate_extent(1, 0, 0, None).unwrap_err();
        assert_eq!(err, ExtentAllocError::InvalidOffset);
    }

    #[test]
    fn free_nonexistent_inode_returns_error() {
        let mut allocator = ExtentAllocator::new();
        let err = allocator.free_extent(42, 0, 4096).unwrap_err();
        assert_eq!(err, ExtentAllocError::ExtentNotFound);
    }

    #[test]
    fn three_extents_sequential_locators() {
        let mut allocator = ExtentAllocator::with_initial_locator(100);

        let results = allocator.allocate_extent(1, 0, 4096, None).unwrap();
        let loc1 = results[0].1;
        let results = allocator.allocate_extent(1, 8192, 4096, None).unwrap();
        let loc2 = results[0].1;
        let results = allocator.allocate_extent(1, 16384, 8192, None).unwrap();
        let loc3 = results[0].1;

        assert_eq!(loc1, LocatorId(100));
        // locator advances by length: 100 + 4096 = 4196
        assert_eq!(loc2, LocatorId(4196));
        // 4196 + 4096 = 8292
        assert_eq!(loc3, LocatorId(8292));
    }

    #[test]
    fn inode_isolation() {
        let mut allocator = ExtentAllocator::new();

        allocator.allocate_extent(1, 0, 4096, None).unwrap();
        allocator.allocate_extent(2, 0, 8192, None).unwrap();

        assert!(allocator.has_extents(1));
        assert!(allocator.has_extents(2));
        assert!(!allocator.has_extents(3));

        let entries_inode1 = allocator.lookup_extents(1, 0, 4096);
        assert_eq!(entries_inode1.len(), 1);

        let entries_inode2 = allocator.lookup_extents(2, 0, 8192);
        assert_eq!(entries_inode2.len(), 1);

        // Inode 1 should not see inode 2's extents.
        let entries_inode1_full = allocator.lookup_extents(1, 0, 16384);
        assert_eq!(entries_inode1_full.len(), 1);
    }

    #[test]
    fn remove_inode_drops_all_extent_state_for_inode() {
        let mut allocator = ExtentAllocator::new();

        allocator.allocate_extent(1, 0, 4096, None).unwrap();
        allocator.allocate_extent(1, 8192, 4096, None).unwrap();
        allocator.allocate_extent(2, 0, 4096, None).unwrap();

        assert!(allocator.remove_inode(1));
        assert!(!allocator.has_extents(1));
        assert!(allocator.has_extents(2));
        assert!(!allocator.remove_inode(1));
    }

    #[test]
    fn resize_grow_and_shrink() {
        let mut allocator = ExtentAllocator::new();

        let results = allocator.allocate_extent(1, 0, 4096, None).unwrap();
        let loc1 = results[0].1;
        assert_eq!(loc1, LocatorId(0));

        // Resize from 4096 -> 12288 (grow).
        let results = allocator.resize_extent(1, 0, 4096, 12288).unwrap();
        let loc2 = results[0].1;
        assert_eq!(loc2, LocatorId(4096)); // after old extent's locator

        let entries = allocator.lookup_extents(1, 0, 12288);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].length, 12288);
    }

    // =====================================================================
    // RecordsizePolicy unit tests
    // =====================================================================

    #[test]
    fn recordsize_fixed_4096_splits_12k_write_into_3_extents() {
        let mut allocator = ExtentAllocator::new();
        let policy = RecordsizePolicy::Fixed(4096);

        let results = allocator
            .allocate_extent(1, 0, 12288, Some(policy))
            .expect("allocation should succeed");

        assert_eq!(
            results.len(),
            3,
            "12 KiB write at offset 0 with 4 KiB recordsize must produce 3 extents"
        );

        let entries = allocator.lookup_extents(1, 0, 16384);
        assert_eq!(entries.len(), 3);

        // Each extent must be <= 4096 bytes.
        for e in &entries {
            assert!(
                e.length <= 4096,
                "extent length {} exceeds recordsize 4096",
                e.length
            );
            assert!(e.is_pending_data());
        }
        assert_eq!(entries[0].logical_offset, 0);
        assert_eq!(entries[0].length, 4096);
        assert_eq!(entries[1].logical_offset, 4096);
        assert_eq!(entries[1].length, 4096);
        assert_eq!(entries[2].logical_offset, 8192);
        assert_eq!(entries[2].length, 4096);
    }

    #[test]
    fn recordsize_fixed_small_write_single_extent() {
        let mut allocator = ExtentAllocator::new();
        let policy = RecordsizePolicy::Fixed(4096);

        // Write 2048 bytes — fits within one recordsize block.
        let results = allocator
            .allocate_extent(1, 0, 2048, Some(policy))
            .expect("allocation should succeed");

        assert_eq!(results.len(), 1);
        let entries = allocator.lookup_extents(1, 0, 4096);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].length, 2048);
    }

    #[test]
    fn recordsize_fixed_unaligned_offset_splits_at_boundary() {
        let mut allocator = ExtentAllocator::new();
        let policy = RecordsizePolicy::Fixed(4096);

        // Write 8192 bytes starting at offset 1024 (unaligned).
        // Should split at offset 4096, producing chunks:
        //   [1024..4096) = 3072 bytes
        //   [4096..8192) = 4096 bytes
        //   [8192..9216) = 1024 bytes
        let results = allocator
            .allocate_extent(1, 1024, 8192, Some(policy))
            .expect("allocation should succeed");

        assert_eq!(
            results.len(),
            3,
            "unaligned write crossing 2 boundaries must produce 3 extents"
        );

        let entries = allocator.lookup_extents(1, 0, 16384);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].logical_offset, 1024);
        assert_eq!(entries[0].length, 3072);
        assert_eq!(entries[1].logical_offset, 4096);
        assert_eq!(entries[1].length, 4096);
        assert_eq!(entries[2].logical_offset, 8192);
        assert_eq!(entries[2].length, 1024);

        for e in &entries {
            assert!(e.length <= 4096);
            // Verify alignment: each extent's start and end must be within the
            // same recordsize block or exactly at its boundary.
            let start_block = e.logical_offset / 4096;
            let end_block = (e.logical_offset + e.length - 1) / 4096;
            assert_eq!(
                start_block, end_block,
                "extent at {} len {} crosses recordsize boundary",
                e.logical_offset, e.length
            );
        }
    }

    #[test]
    fn recordsize_adaptive_uses_max_for_splitting() {
        let mut allocator = ExtentAllocator::new();
        let policy = RecordsizePolicy::Adaptive {
            min: 1024,
            max: 8192,
        };

        // Write 20 KiB with Adaptive(max=8192) — should split at 8 KiB boundaries.
        let results = allocator
            .allocate_extent(1, 0, 20480, Some(policy))
            .expect("allocation should succeed");

        assert_eq!(
            results.len(),
            3,
            "20 KiB with 8 KiB recordsize = 3 extents (8+8+4)"
        );

        let entries = allocator.lookup_extents(1, 0, 24576);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].length, 8192);
        assert_eq!(entries[1].length, 8192);
        assert_eq!(entries[2].length, 4096);

        for e in &entries {
            assert!(
                e.length <= 8192,
                "extent length {} exceeds adaptive max 8192",
                e.length
            );
        }
    }

    #[test]
    fn recordsize_none_preserves_existing_behavior() {
        let mut allocator = ExtentAllocator::new();

        // Without recordsize, a 12 KiB write produces 1 extent.
        let results = allocator
            .allocate_extent(1, 0, 12288, None)
            .expect("allocation should succeed");

        assert_eq!(results.len(), 1);
        let entries = allocator.lookup_extents(1, 0, 16384);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].length, 12288);
    }

    #[test]
    fn recordsize_default_is_4kib() {
        let policy = RecordsizePolicy::default();
        assert_eq!(policy, RecordsizePolicy::Fixed(4096));
        assert_eq!(policy.effective_max(), 4096);
    }

    #[test]
    fn recordsize_effective_max_for_adaptive() {
        let policy = RecordsizePolicy::Adaptive {
            min: 512,
            max: 65536,
        };
        assert_eq!(policy.effective_max(), 65536);
    }

    #[test]
    fn recordsize_split_helper_aligned() {
        let chunks = crate::split_into_recordsize_chunks(0, 12288, 4096);
        assert_eq!(chunks, vec![(0, 4096), (4096, 4096), (8192, 4096)]);
    }

    #[test]
    fn recordsize_split_helper_unaligned() {
        let chunks = crate::split_into_recordsize_chunks(1024, 8192, 4096);
        assert_eq!(chunks, vec![(1024, 3072), (4096, 4096), (8192, 1024)]);
    }

    #[test]
    fn recordsize_split_helper_zero_recordsize_no_split() {
        let chunks = crate::split_into_recordsize_chunks(0, 10000, 0);
        assert_eq!(chunks, vec![(0, 10000)]);
    }

    #[test]
    fn recordsize_split_helper_zero_length() {
        let chunks = crate::split_into_recordsize_chunks(4096, 0, 4096);
        assert_eq!(chunks, vec![(4096, 0)]);
    }

    #[test]
    fn recordsize_split_helper_exact_boundary() {
        let chunks = crate::split_into_recordsize_chunks(4096, 4096, 4096);
        assert_eq!(chunks, vec![(4096, 4096)]);
    }

    // ── Lifecycle tests ──────────────────────────────────────

    #[test]
    fn new_data_extent_is_marked_ingest() {
        let mut allocator = ExtentAllocator::new();
        allocator.allocate_extent(1, 0, 4096, None).unwrap();

        let entries = allocator.lookup_extents(1, 0, 4096);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].lifecycle_state(), ExtentLifecycleState::Ingest);
        assert!((entries[0].flags & ExtentMapEntryV2::FLAG_INGEST) != 0);
    }

    #[test]
    fn unwritten_extents_are_not_ingest() {
        let mut allocator = ExtentAllocator::new();
        allocator
            .allocate_unwritten_extent(1, 0, 4096, None, 0)
            .unwrap();

        let summary = allocator.ingest_summary();
        assert_eq!(summary.ingest_count, 0);
        assert_eq!(summary.total_extents, 1);
    }

    #[test]
    fn ingest_summary_counts_correctly() {
        let mut allocator = ExtentAllocator::new();
        allocator.allocate_extent(1, 0, 4096, None).unwrap();
        allocator.allocate_extent(2, 0, 8192, None).unwrap();
        allocator.allocate_extent(1, 4096, 4096, None).unwrap();

        let summary = allocator.ingest_summary();
        assert_eq!(summary.total_extents, 3);
        assert_eq!(summary.ingest_count, 3);
        assert_eq!(summary.ingest_bytes, 4096 + 8192 + 4096);
        assert_eq!(summary.base_complete_count, 0);
        assert!(!summary.all_rebaked());
    }

    #[test]
    fn ingest_candidates_returns_only_data_ingest_extents() {
        let mut allocator = ExtentAllocator::new();
        allocator.allocate_extent(1, 0, 4096, None).unwrap();
        allocator.allocate_extent(2, 0, 8192, None).unwrap();
        // Unwritten should not appear in candidates.
        allocator
            .allocate_unwritten_extent(3, 0, 2048, None, 0)
            .unwrap();

        let candidates = allocator.ingest_candidates();
        assert_eq!(candidates.len(), 2);
        assert!(candidates
            .iter()
            .all(|(_, e)| e.is_data() || e.is_pending_data()));
        assert!(candidates
            .iter()
            .all(|(_, e)| e.lifecycle_state() == ExtentLifecycleState::Ingest));
    }

    #[test]
    fn mark_rebaked_transitions_to_base_complete() {
        let mut allocator = ExtentAllocator::new();
        allocator.allocate_extent(1, 0, 4096, None).unwrap();
        allocator.allocate_extent(1, 4096, 4096, None).unwrap();

        // Mark only the first extent.
        let count = allocator.mark_rebaked(1, 0, 4096);
        assert_eq!(count, 1);

        // First extent is now BaseComplete.
        let entries = allocator.lookup_extents(1, 0, 4096);
        assert_eq!(
            entries[0].lifecycle_state(),
            ExtentLifecycleState::BaseComplete
        );
        assert!((entries[0].flags & ExtentMapEntryV2::FLAG_BASE_COMPLETE) != 0);
        assert!((entries[0].flags & ExtentMapEntryV2::FLAG_INGEST) == 0);

        // Second extent is still Ingest.
        let entries = allocator.lookup_extents(1, 4096, 4096);
        assert_eq!(entries[0].lifecycle_state(), ExtentLifecycleState::Ingest);
    }

    #[test]
    fn after_rebake_summary_reflects_new_state() {
        let mut allocator = ExtentAllocator::new();
        allocator.allocate_extent(1, 0, 4096, None).unwrap();
        allocator.allocate_extent(1, 4096, 4096, None).unwrap();

        allocator.mark_rebaked(1, 0, 8192);

        let summary = allocator.ingest_summary();
        assert_eq!(summary.total_extents, 2);
        assert_eq!(summary.ingest_count, 0);
        assert_eq!(summary.base_complete_count, 2);
        assert!(summary.all_rebaked());
    }

    #[test]
    fn historic_extents_without_flags_are_base_complete() {
        // Simulate a pre-existing entry with no lifecycle flags set.
        let entry = ExtentMapEntryV2::new_data(0, 4096, LocatorId(100), [0u8; 32], 0);
        // No call to set_ingest() — flags are 0.
        assert_eq!(entry.lifecycle_state(), ExtentLifecycleState::BaseComplete);
    }

    #[test]
    fn unwritten_extent_stores_birth_commit_group() {
        let mut allocator = ExtentAllocator::new();
        let birth_txg = 42;
        allocator
            .allocate_unwritten_extent(1, 0, 4096, None, birth_txg)
            .unwrap();

        let entries = allocator.lookup_extents(1, 0, 4096);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_unwritten());
        assert_eq!(entries[0].birth_commit_group, 42);
    }
}
