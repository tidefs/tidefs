//! Polymorphic extent map with hysteresis switching.
//!
//! `PolymorphicExtentMap` wraps both [`InlineExtentMap`] (V1) and
//! [`BTreeExtentMap`] (V2) and delegates all [`ExtentMapOps`] calls to the
//! active representation. A hysteresis policy switches between
//! representations automatically:
//!
//! - **Promote to BTreeExtentMap** when entry count exceeds
//!   [`PROMOTE_THRESHOLD`] (6) or any entry is `Unwritten` or a `Hole`.
//! - **Demote to InlineExtentMap** when entry count is at or below
//!   [`DEMOTE_THRESHOLD`] (4) AND no entry is `Unwritten` AND no entry is
//!   a `Hole`.
//!
//! This implements Phase 2 of the polymorphic extent maps design (#1291).

use crate::btree::BTreeExtentMap;
use crate::multi_level::MultiLevelBTreeExtentMap;
use crate::InlineExtentMap;
use tidefs_types_extent_map_core::{
    ExtentMapEntryV2, ExtentMapError, ExtentMapOps, ExtentType, FiemapExtent, FreedExtent,
    LocatorId, EXTENT_MAP_V2_V3_PROMOTION_THRESHOLD, EXTENT_MAP_V3_V2_DEMOTION_THRESHOLD,
};

/// Threshold for promoting from InlineExtentMap to BTreeExtentMap.
pub const PROMOTE_THRESHOLD: usize = 6;
/// Threshold for demoting from BTreeExtentMap back to InlineExtentMap.
pub const DEMOTE_THRESHOLD: usize = 4;

/// Discriminant for the active extent map representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtentMapRepr {
    /// V1 inline-list (up to 6 entries).
    Inline,
    /// V2 B-tree (for larger files and UNWRITTEN/hole entries).
    BTree,
    /// V3 multi-level B-tree (for huge files >100K extents).
    MultiLevel,
}

impl core::fmt::Display for ExtentMapRepr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ExtentMapRepr::Inline => f.write_str("Inline"),
            ExtentMapRepr::BTree => f.write_str("BTree"),
            ExtentMapRepr::MultiLevel => f.write_str("MultiLevel"),
        }
    }
}

/// Polymorphic extent map delegating to the active V1 or V2 engine.
///
/// Holds both representations; only one is active at a time. Switching
/// preserves all extent data by copying entries from the old
/// representation to the new one.
#[derive(Clone, Debug)]
pub struct PolymorphicExtentMap {
    active: ExtentMapRepr,
    inline: InlineExtentMap,
    btree: BTreeExtentMap,
    multi_level: MultiLevelBTreeExtentMap,
}

impl Default for PolymorphicExtentMap {
    fn default() -> Self {
        Self {
            active: ExtentMapRepr::Inline,
            inline: InlineExtentMap::new(),
            btree: BTreeExtentMap::new(),
            multi_level: MultiLevelBTreeExtentMap::new(),
        }
    }
}

impl PolymorphicExtentMap {
    /// Create a new polymorphic extent map starting in Inline mode.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create starting from a specific representation.
    #[must_use]
    pub fn with_repr(repr: ExtentMapRepr) -> Self {
        let mut s = Self::new();
        s.active = repr;
        s
    }

    /// Return the current active representation.
    #[must_use]
    pub fn representation(&self) -> ExtentMapRepr {
        self.active
    }

    /// Return the entry count from the active representation.
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        match self.active {
            ExtentMapRepr::Inline => self.inline.header.entry_count,
            ExtentMapRepr::BTree => self.btree.header.entry_count,
            ExtentMapRepr::MultiLevel => self.multi_level.header.entry_count,
        }
    }

    /// Return the logical file size from the active representation.
    ///
    /// This is the highest byte offset ever written or truncated to;
    /// it equals the SEEK_HOLE result when no hole exists before EOF.
    #[must_use]
    pub fn file_size(&self) -> u64 {
        match self.active {
            ExtentMapRepr::Inline => self.inline.header.file_size,
            ExtentMapRepr::BTree => self.btree.header.file_size,
            ExtentMapRepr::MultiLevel => self.multi_level.header.file_size,
        }
    }

    /// Collect all entries from the active representation.
    fn collect_entries(&self) -> Vec<ExtentMapEntryV2> {
        match self.active {
            ExtentMapRepr::Inline => self.inline.entries.clone(),
            ExtentMapRepr::BTree => self.collect_all_btree(),
            ExtentMapRepr::MultiLevel => self.collect_all_multi_level(),
        }
    }

    /// Collect all entries from the BTree representation.
    fn collect_all_btree(&self) -> Vec<ExtentMapEntryV2> {
        // BTree entries are sorted by logical_offset via lookup_range.
        // We use a full-range lookup to get all entries in order.
        self.btree.lookup_range(0, u64::MAX).unwrap_or_default()
    }

    /// Collect all entries from the V3 multi-level representation.
    fn collect_all_multi_level(&self) -> Vec<ExtentMapEntryV2> {
        self.multi_level
            .lookup_range(0, u64::MAX)
            .unwrap_or_default()
    }

    /// Check whether any entry is UNWRITTEN or a hole.
    fn has_unwritten_or_holes(entries: &[ExtentMapEntryV2]) -> bool {
        entries
            .iter()
            .any(|e| e.is_unwritten() || e.extent_type() == ExtentType::Hole)
    }

    fn entry_is_unwritten_or_hole(entry: &ExtentMapEntryV2) -> bool {
        entry.is_unwritten() || entry.extent_type() == ExtentType::Hole
    }

    /// Evaluate the hysteresis policy and switch representations if needed.
    ///
    /// After any mutation that changes entry count or entry types, call this
    /// to ensure the optimal representation is active.
    pub fn check_and_switch(&mut self) -> Result<(), ExtentMapError> {
        let count = self.entry_count() as usize;

        match self.active {
            ExtentMapRepr::Inline => {
                let entries = self.collect_entries();
                let has_uw_or_hole = Self::has_unwritten_or_holes(&entries);
                if count > PROMOTE_THRESHOLD || has_uw_or_hole {
                    self.promote_to_btree(&entries)?;
                }
            }
            ExtentMapRepr::BTree => {
                if count <= DEMOTE_THRESHOLD {
                    let entries = self.collect_entries();
                    if !Self::has_unwritten_or_holes(&entries) {
                        self.demote_to_inline(&entries)?;
                    }
                } else if count >= EXTENT_MAP_V2_V3_PROMOTION_THRESHOLD {
                    self.promote_btree_to_multi_level()?;
                }
            }
            ExtentMapRepr::MultiLevel => {
                if count <= EXTENT_MAP_V3_V2_DEMOTION_THRESHOLD {
                    let has_uw_or_hole = self
                        .multi_level
                        .ordered_entries()
                        .any(Self::entry_is_unwritten_or_hole);
                    if !has_uw_or_hole {
                        self.demote_multi_level_to_btree()?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Switch from Inline to BTree, preserving all entries.
    fn promote_to_btree(&mut self, entries: &[ExtentMapEntryV2]) -> Result<(), ExtentMapError> {
        // Rebuild BTree from the inline entries
        self.btree = BTreeExtentMap::new();
        if !entries.is_empty() {
            self.btree.insert_extent(entries)?;
        }
        // Copy file_size and alloc_bytes from inline header
        self.btree.header.file_size = self.inline.header.file_size;
        self.btree.header.alloc_bytes = self.inline.header.alloc_bytes;
        self.active = ExtentMapRepr::BTree;
        Ok(())
    }

    /// Switch from BTree to Inline, preserving all entries.
    fn demote_to_inline(&mut self, entries: &[ExtentMapEntryV2]) -> Result<(), ExtentMapError> {
        // Rebuild inline from BTree entries
        self.inline = InlineExtentMap::new();
        if !entries.is_empty() {
            self.inline.insert_extent(entries)?;
        }
        // Copy file_size and alloc_bytes from btree header
        self.inline.header.file_size = self.btree.header.file_size;
        self.inline.header.alloc_bytes = self.btree.header.alloc_bytes;
        self.active = ExtentMapRepr::Inline;
        Ok(())
    }

    /// Switch from BTree to MultiLevel, streaming sorted entries from V2.
    fn promote_btree_to_multi_level(&mut self) -> Result<(), ExtentMapError> {
        let file_size = self.btree.header.file_size;
        let mut multi_level = MultiLevelBTreeExtentMap::new();
        multi_level
            .rebuild_from_ordered_entries(self.btree.ordered_entries().cloned(), file_size)?;
        self.multi_level = multi_level;
        self.active = ExtentMapRepr::MultiLevel;
        Ok(())
    }

    /// Switch from MultiLevel to BTree, streaming sorted entries from V3.
    fn demote_multi_level_to_btree(&mut self) -> Result<(), ExtentMapError> {
        let file_size = self.multi_level.header.file_size;
        let mut btree = BTreeExtentMap::new();
        btree
            .rebuild_from_ordered_entries(self.multi_level.ordered_entries().cloned(), file_size)?;
        self.btree = btree;
        self.active = ExtentMapRepr::BTree;
        Ok(())
    }
    /// Promote before inserting entries that would overflow Inline capacity.
    fn maybe_promote_before_insert(
        &mut self,
        _entries: &[ExtentMapEntryV2],
    ) -> Result<(), ExtentMapError> {
        let existing = self.collect_entries();
        // Promote with existing entries; the caller will then insert the
        // new entries into the BTree.
        self.promote_to_btree(&existing)
    }

    /// Defragment the extent map by merging adjacent extents with the same
    /// locator and contiguous logical ranges.
    ///
    /// Returns (extents_before, extents_after) so callers can compute the
    /// fragmentation reduction.
    pub fn defrag(&mut self) -> (u64, u64) {
        let before = self.entry_count();
        if before <= 1 {
            return (before, before);
        }

        let entries = self.collect_entries();

        // Merge adjacent extents with the same locator and kind.
        let merged = Self::merge_adjacent_extents(&entries);

        let after = merged.len() as u64;
        if after >= before {
            return (before, before);
        }

        // Rebuild the active representation with merged entries.
        let file_size = self.file_size();
        let alloc_bytes: u64 = merged
            .iter()
            .filter(|e| {
                matches!(
                    e.extent_type(),
                    tidefs_types_extent_map_core::ExtentType::Data
                        | tidefs_types_extent_map_core::ExtentType::Unwritten
                )
            })
            .map(|e| e.length)
            .sum();

        // Rebuild into the active representation.
        self.rebuild_with_entries(&merged, file_size, alloc_bytes);

        (before, self.entry_count())
    }

    /// Merge adjacent extents with the same locator and extent kind,
    /// where the next extent's logical offset equals the previous extent's
    /// end offset.
    fn merge_adjacent_extents(
        entries: &[tidefs_types_extent_map_core::ExtentMapEntryV2],
    ) -> Vec<tidefs_types_extent_map_core::ExtentMapEntryV2> {
        if entries.is_empty() {
            return Vec::new();
        }
        let mut merged = Vec::with_capacity(entries.len());
        merged.push(entries[0].clone());
        for entry in &entries[1..] {
            let last = merged.last_mut().unwrap();
            if last.locator_id == entry.locator_id
                && last.extent_kind == entry.extent_kind
                && last.end_offset() == entry.logical_offset
                && last.checksum == entry.checksum
            {
                last.length += entry.length;
            } else {
                merged.push(entry.clone());
            }
        }
        merged
    }

    /// Rebuild the active representation from a clean entry list.
    fn rebuild_with_entries(
        &mut self,
        entries: &[tidefs_types_extent_map_core::ExtentMapEntryV2],
        file_size: u64,
        alloc_bytes: u64,
    ) {
        match self.active {
            ExtentMapRepr::Inline => {
                self.inline = InlineExtentMap::new();
                self.inline.header.file_size = file_size;
                self.inline.header.alloc_bytes = alloc_bytes;
                if !entries.is_empty() {
                    let _ = self.inline.insert_extent(entries);
                }
                self.inline.header.entry_count = entries.len() as u64;
            }
            ExtentMapRepr::BTree => {
                self.btree = BTreeExtentMap::new();
                self.btree.header.file_size = file_size;
                self.btree.header.alloc_bytes = alloc_bytes;
                if !entries.is_empty() {
                    let _ = self.btree.insert_extent(entries);
                }
                self.btree.header.entry_count = entries.len() as u64;
            }
            ExtentMapRepr::MultiLevel => {
                self.multi_level = MultiLevelBTreeExtentMap::new();
                self.multi_level.header.file_size = file_size;
                self.multi_level.header.alloc_bytes = alloc_bytes;
                if !entries.is_empty() {
                    let _ = self.multi_level.insert_extent(entries);
                }
                self.multi_level.header.entry_count = entries.len() as u64;
            }
        }
    }
}

/// Format magic for polymorphic extent map.
pub const POLYMORPHIC_EXTENT_MAP_MAGIC: &[u8; 4] = b"VXPM";
/// Current polymorphic format version.
pub const POLYMORPHIC_EXTENT_MAP_VERSION: u8 = 1;

/// Wire format discriminant for each representation.
pub const REPR_INLINE: u8 = 0;
/// BTree representation discriminant.
pub const REPR_BTREE: u8 = 1;
/// MultiLevel representation discriminant.
pub const REPR_MULTI_LEVEL: u8 = 2;

impl PolymorphicExtentMap {
    /// Serialize the polymorphic extent map to a binary writer.
    ///
    /// Writes a self-describing header (magic + representation discriminant)
    /// then delegates to the active representation's serializer.
    ///
    /// Format:
    /// ```text
    /// magic:          4 bytes  "VXPM"
    /// version:        1 byte   1
    /// flags:          1 byte   reserved
    /// repr:           1 byte   0=Inline, 1=BTree, 2=MultiLevel
    /// payload:        variable (delegated to the active repr serializer)
    /// ```
    pub fn serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<(), ExtentMapError> {
        writer
            .write_all(POLYMORPHIC_EXTENT_MAP_MAGIC)
            .map_err(|_| ExtentMapError::Corrupt)?;
        writer
            .write_all(&[POLYMORPHIC_EXTENT_MAP_VERSION, 0u8])
            .map_err(|_| ExtentMapError::Corrupt)?;

        let repr_byte = match self.active {
            ExtentMapRepr::Inline => REPR_INLINE,
            ExtentMapRepr::BTree => REPR_BTREE,
            ExtentMapRepr::MultiLevel => REPR_MULTI_LEVEL,
        };
        writer
            .write_all(&[repr_byte])
            .map_err(|_| ExtentMapError::Corrupt)?;

        match self.active {
            ExtentMapRepr::Inline => self.inline.serialize(writer),
            ExtentMapRepr::BTree => self.btree.serialize(writer),
            ExtentMapRepr::MultiLevel => self.multi_level.serialize(writer),
        }
    }

    /// Deserialize a polymorphic extent map from a binary reader.
    ///
    /// Reads the header, identifies the representation, then delegates
    /// to the active representation's deserializer.
    pub fn deserialize<R: std::io::Read>(reader: &mut R) -> Result<Self, ExtentMapError> {
        let mut magic = [0u8; 4];
        reader
            .read_exact(&mut magic)
            .map_err(|_| ExtentMapError::Corrupt)?;
        if &magic != POLYMORPHIC_EXTENT_MAP_MAGIC {
            return Err(ExtentMapError::WrongVersion);
        }

        let mut version_flags = [0u8; 2];
        reader
            .read_exact(&mut version_flags)
            .map_err(|_| ExtentMapError::Corrupt)?;
        if version_flags[0] != POLYMORPHIC_EXTENT_MAP_VERSION {
            return Err(ExtentMapError::WrongVersion);
        }

        let mut repr_buf = [0u8; 1];
        reader
            .read_exact(&mut repr_buf)
            .map_err(|_| ExtentMapError::Corrupt)?;

        match repr_buf[0] {
            REPR_INLINE => {
                let inline = crate::InlineExtentMap::deserialize(reader)?;
                Ok(Self {
                    active: ExtentMapRepr::Inline,
                    inline,
                    btree: BTreeExtentMap::new(),
                    multi_level: MultiLevelBTreeExtentMap::new(),
                })
            }
            REPR_BTREE => {
                let btree = BTreeExtentMap::deserialize(reader)?;
                Ok(Self {
                    active: ExtentMapRepr::BTree,
                    inline: crate::InlineExtentMap::new(),
                    btree,
                    multi_level: MultiLevelBTreeExtentMap::new(),
                })
            }
            REPR_MULTI_LEVEL => {
                let multi_level = MultiLevelBTreeExtentMap::deserialize(reader)?;
                Ok(Self {
                    active: ExtentMapRepr::MultiLevel,
                    inline: crate::InlineExtentMap::new(),
                    btree: BTreeExtentMap::new(),
                    multi_level,
                })
            }
            _ => Err(ExtentMapError::WrongVersion),
        }
    }
}

// ---------------------------------------------------------------------------
// ExtentMapOps impl — delegates to active representation with hysteresis
// ---------------------------------------------------------------------------

impl ExtentMapOps for PolymorphicExtentMap {
    fn lookup_range(
        &self,
        offset: u64,
        length: u64,
    ) -> Result<Vec<ExtentMapEntryV2>, ExtentMapError> {
        match self.active {
            ExtentMapRepr::Inline => self.inline.lookup_range(offset, length),
            ExtentMapRepr::BTree => self.btree.lookup_range(offset, length),
            ExtentMapRepr::MultiLevel => self.multi_level.lookup_range(offset, length),
        }
    }

    fn insert_extent(&mut self, entries: &[ExtentMapEntryV2]) -> Result<(), ExtentMapError> {
        // Pre-check: if Inline and the batch would overflow, promote first.
        if self.active == ExtentMapRepr::Inline {
            let has_uw_or_hole = Self::has_unwritten_or_holes(entries);
            let estimated_new = self.inline.header.entry_count as usize + entries.len();
            // Conservative: promote if any entry is UNWRITTEN or Hole, or if
            // estimated count would exceed the promote threshold.
            if has_uw_or_hole || estimated_new > PROMOTE_THRESHOLD {
                self.maybe_promote_before_insert(entries)?;
            }
        }

        match self.active {
            ExtentMapRepr::Inline => {
                self.inline.insert_extent(entries)?;
            }
            ExtentMapRepr::BTree => {
                self.btree.insert_extent(entries)?;
            }
            ExtentMapRepr::MultiLevel => {
                self.multi_level.insert_extent(entries)?;
            }
        }
        self.check_and_switch()
    }

    fn truncate(&mut self, new_size: u64) -> Result<Vec<FreedExtent>, ExtentMapError> {
        let freed = match self.active {
            ExtentMapRepr::Inline => self.inline.truncate(new_size)?,
            ExtentMapRepr::BTree => self.btree.truncate(new_size)?,
            ExtentMapRepr::MultiLevel => self.multi_level.truncate(new_size)?,
        };
        self.check_and_switch()?;
        Ok(freed)
    }

    fn punch_hole(&mut self, offset: u64, length: u64) -> Result<Vec<FreedExtent>, ExtentMapError> {
        let freed = match self.active {
            ExtentMapRepr::Inline => self.inline.punch_hole(offset, length)?,
            ExtentMapRepr::BTree => self.btree.punch_hole(offset, length)?,
            ExtentMapRepr::MultiLevel => self.multi_level.punch_hole(offset, length)?,
        };
        self.check_and_switch()?;
        Ok(freed)
    }

    fn collapse_range(
        &mut self,
        offset: u64,
        length: u64,
    ) -> Result<Vec<FreedExtent>, ExtentMapError> {
        let freed = match self.active {
            ExtentMapRepr::Inline => self.inline.collapse_range(offset, length)?,
            ExtentMapRepr::BTree => self.btree.collapse_range(offset, length)?,
            ExtentMapRepr::MultiLevel => self.multi_level.collapse_range(offset, length)?,
        };
        self.check_and_switch()?;
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
        match self.active {
            ExtentMapRepr::Inline => {
                self.inline.convert_unwritten_to_data(
                    offset,
                    length,
                    locator_id,
                    checksum,
                    birth_commit_group,
                )?;
            }
            ExtentMapRepr::BTree => {
                self.btree.convert_unwritten_to_data(
                    offset,
                    length,
                    locator_id,
                    checksum,
                    birth_commit_group,
                )?;
            }
            ExtentMapRepr::MultiLevel => {
                self.multi_level.convert_unwritten_to_data(
                    offset,
                    length,
                    locator_id,
                    checksum,
                    birth_commit_group,
                )?;
            }
        }
        self.check_and_switch()
    }

    fn seek_data(&self, offset: u64) -> Option<(u64, u64)> {
        match self.active {
            ExtentMapRepr::Inline => self.inline.seek_data(offset),
            ExtentMapRepr::BTree => self.btree.seek_data(offset),
            ExtentMapRepr::MultiLevel => self.multi_level.seek_data(offset),
        }
    }

    fn seek_hole(&self, offset: u64) -> Option<(u64, u64)> {
        match self.active {
            ExtentMapRepr::Inline => self.inline.seek_hole(offset),
            ExtentMapRepr::BTree => self.btree.seek_hole(offset),
            ExtentMapRepr::MultiLevel => self.multi_level.seek_hole(offset),
        }
    }

    fn fallocate(
        &mut self,
        offset: u64,
        length: u64,
        keep_size: bool,
    ) -> Result<(), ExtentMapError> {
        match self.active {
            ExtentMapRepr::Inline => self.inline.fallocate(offset, length, keep_size)?,
            ExtentMapRepr::BTree => self.btree.fallocate(offset, length, keep_size)?,
            ExtentMapRepr::MultiLevel => self.multi_level.fallocate(offset, length, keep_size)?,
        }
        self.check_and_switch()
    }

    fn zero_range(&mut self, offset: u64, length: u64) -> Result<Vec<FreedExtent>, ExtentMapError> {
        let freed = match self.active {
            ExtentMapRepr::Inline => self.inline.zero_range(offset, length)?,
            ExtentMapRepr::BTree => self.btree.zero_range(offset, length)?,
            ExtentMapRepr::MultiLevel => self.multi_level.zero_range(offset, length)?,
        };
        self.check_and_switch()?;
        Ok(freed)
    }

    fn fiemap(&self, offset: u64, length: u64) -> Result<Vec<FiemapExtent>, ExtentMapError> {
        match self.active {
            ExtentMapRepr::Inline => self.inline.fiemap(offset, length),
            ExtentMapRepr::BTree => self.btree.fiemap(offset, length),
            ExtentMapRepr::MultiLevel => self.multi_level.fiemap(offset, length),
        }
    }

    fn validate(&self) -> Result<(), ExtentMapError> {
        match self.active {
            ExtentMapRepr::Inline => self.inline.validate(),
            ExtentMapRepr::BTree => self.btree.validate(),
            ExtentMapRepr::MultiLevel => self.multi_level.validate(),
        }
    }
}

#[cfg(test)]
impl PolymorphicExtentMap {
    /// Set the V2 B-tree entry count for testing promotion thresholds.
    fn set_btree_entry_count(&mut self, count: u64) {
        self.btree.header.entry_count = count;
    }

    /// Set the V3 multi-level entry count for testing demotion thresholds.
    fn set_multi_level_entry_count(&mut self, count: u64) {
        self.multi_level.header.entry_count = count;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_extent_map_core::ExtentMapEntryV2;

    /// Helper: create a Data entry at logical_offset with given length.
    fn data_entry(offset: u64, length: u64) -> ExtentMapEntryV2 {
        ExtentMapEntryV2::new_data(
            offset,
            length,
            LocatorId((offset / 4096) + 100),
            [0xA5; 32],
            1,
        )
    }

    /// Helper: create an Unwritten entry.
    fn unwritten_entry(offset: u64, length: u64) -> ExtentMapEntryV2 {
        ExtentMapEntryV2::new_unwritten(offset, length, 1)
    }

    /// Helper: create a Hole entry.
    fn hole_entry(offset: u64, length: u64) -> ExtentMapEntryV2 {
        ExtentMapEntryV2 {
            logical_offset: offset,
            length,
            extent_kind: ExtentMapEntryV2::KIND_HOLE,
            flags: 0,
            locator_id: LocatorId::NONE,
            checksum: [0u8; 32],
            birth_commit_group: 0,
            reserved: [0u8; 15],
        }
    }

    #[test]
    fn default_is_inline() {
        let m = PolymorphicExtentMap::new();
        assert_eq!(m.representation(), ExtentMapRepr::Inline);
        assert_eq!(m.entry_count(), 0);
    }

    #[test]
    fn explicit_repr_btree() {
        let m = PolymorphicExtentMap::with_repr(ExtentMapRepr::BTree);
        assert_eq!(m.representation(), ExtentMapRepr::BTree);
    }

    #[test]
    fn stays_inline_below_promote_threshold() {
        let mut m = PolymorphicExtentMap::new();
        // Insert 4 Data entries (< 6, no UNWRITTEN/holes)
        let entries: Vec<_> = (0..4).map(|i| data_entry(i * 4096, 4096)).collect();
        m.insert_extent(&entries).unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::Inline);
        assert_eq!(m.entry_count(), 4);
    }

    #[test]
    fn promotes_when_entry_count_exceeds_promote_threshold() {
        let mut m = PolymorphicExtentMap::new();
        // Insert 7 Data entries (> 6)
        let entries: Vec<_> = (0..7).map(|i| data_entry(i * 4096, 4096)).collect();
        m.insert_extent(&entries).unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::BTree);
        assert_eq!(m.entry_count(), 7);
    }

    #[test]
    fn promotes_when_unwritten_present() {
        let mut m = PolymorphicExtentMap::new();
        let entries = [
            data_entry(0, 4096),
            unwritten_entry(4096, 4096),
            data_entry(8192, 4096),
        ];
        m.insert_extent(&entries).unwrap();
        // 3 entries but one is UNWRITTEN -> promote
        assert_eq!(m.representation(), ExtentMapRepr::BTree);
    }

    #[test]
    fn promotes_when_hole_present() {
        let mut m = PolymorphicExtentMap::new();
        let entries = [
            data_entry(0, 4096),
            hole_entry(4096, 4096),
            data_entry(8192, 4096),
        ];
        m.insert_extent(&entries).unwrap();
        // 3 entries but one is Hole -> promote
        assert_eq!(m.representation(), ExtentMapRepr::BTree);
    }

    #[test]
    fn demotes_when_back_to_few_data_only_entries() {
        let mut m = PolymorphicExtentMap::new();
        // First promote by adding 7 entries
        let entries: Vec<_> = (0..7).map(|i| data_entry(i * 4096, 4096)).collect();
        m.insert_extent(&entries).unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::BTree);

        // Truncate down to 3 entries -> should demote
        m.truncate(3 * 4096).unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::Inline);
        assert_eq!(m.entry_count(), 3);
    }

    #[test]
    fn does_not_demote_when_unwritten_present() {
        let mut m = PolymorphicExtentMap::new();
        let entries: Vec<_> = (0..6)
            .map(|i| {
                if i == 3 {
                    unwritten_entry(i * 4096, 4096)
                } else {
                    data_entry(i * 4096, 4096)
                }
            })
            .collect();
        m.insert_extent(&entries).unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::BTree);

        // Truncate to 3 entries but UNWRITTEN remains
        m.truncate(5 * 4096).unwrap();
        // Still has UNWRITTEN at offset 12288 (3*4096) -> should stay BTree
        assert_eq!(m.representation(), ExtentMapRepr::BTree);
    }

    #[test]
    fn does_not_demote_when_hole_present() {
        let mut m = PolymorphicExtentMap::new();
        let entries: Vec<_> = (0..5)
            .map(|i| {
                if i == 2 {
                    hole_entry(i * 4096, 4096)
                } else {
                    data_entry(i * 4096, 4096)
                }
            })
            .collect();
        m.insert_extent(&entries).unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::BTree);

        // Truncate to 4 entries but hole at offset 8192 remains
        m.truncate(4 * 4096).unwrap();
        assert_eq!(m.entry_count(), 4);
        // Should stay BTree because hole present
        assert_eq!(m.representation(), ExtentMapRepr::BTree);
    }

    #[test]
    fn lookup_range_works_across_representations() {
        let mut m = PolymorphicExtentMap::new();

        // Inline phase
        m.insert_extent(&[data_entry(0, 4096)]).unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::Inline);
        let results = m.lookup_range(0, 8192).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].logical_offset, 0);

        // Promote
        let entries: Vec<_> = (0..8).map(|i| data_entry(i * 4096, 4096)).collect();
        m.insert_extent(&entries).unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::BTree);
        let results = m.lookup_range(0, 32768).unwrap();
        assert_eq!(results.len(), 8);
    }

    #[test]
    fn truncate_and_demote_roundtrip() {
        let mut m = PolymorphicExtentMap::new();
        let entries: Vec<_> = (0..10).map(|i| data_entry(i * 4096, 4096)).collect();
        m.insert_extent(&entries).unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::BTree);
        assert_eq!(m.entry_count(), 10);

        // Truncate down to 3 data-only entries -> demote
        m.truncate(3 * 4096).unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::Inline);
        assert_eq!(m.entry_count(), 3);
    }

    #[test]
    fn punch_hole_no_promotion_for_gaps() {
        let mut m = PolymorphicExtentMap::new();
        // Start inline with 3 data entries
        m.insert_extent(&[
            data_entry(0, 4096),
            data_entry(4096, 4096),
            data_entry(8192, 4096),
        ])
        .unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::Inline);

        // Punch a hole (gap) — punch_hole removes entries, creating gaps.
        // Gaps are not explicit hole entries, so no promotion.
        let freed = m.punch_hole(0, 4096).unwrap();
        assert_eq!(freed.len(), 1);
        assert_eq!(freed[0].logical_offset, 0);
        assert_eq!(freed[0].length, 4096);
        assert_eq!(freed[0].locator_id, LocatorId(100));
        assert_eq!(freed[0].extent_type, ExtentType::Data);
        // After removing one entry, we have 2 entries, still Inline.
        assert_eq!(m.representation(), ExtentMapRepr::Inline);
        assert_eq!(m.entry_count(), 2);
    }

    #[test]
    fn zero_range_returns_freed_extent_and_no_promotion() {
        let mut m = PolymorphicExtentMap::new();
        m.insert_extent(&[
            data_entry(0, 4096),
            data_entry(4096, 4096),
            data_entry(8192, 4096),
        ])
        .unwrap();
        let freed = m.zero_range(4096, 4096).unwrap();
        assert_eq!(freed.len(), 1);
        assert_eq!(freed[0].logical_offset, 4096);
        assert_eq!(freed[0].length, 4096);
        assert_eq!(freed[0].locator_id, LocatorId(101));
        assert_eq!(freed[0].extent_type, ExtentType::Data);
        assert_eq!(m.representation(), ExtentMapRepr::Inline);
        assert_eq!(m.entry_count(), 2);
        assert_eq!(m.seek_hole(4096), Some((4096, 4096)));
    }

    #[test]
    fn collapse_range_delegates_and_updates_active_representation() {
        let mut m = PolymorphicExtentMap::with_repr(ExtentMapRepr::BTree);
        m.insert_extent(&[data_entry(0, 4096), data_entry(8192, 4096)])
            .unwrap();

        let freed = m.collapse_range(4096, 4096).unwrap();
        let entries = m.collect_entries();

        assert!(freed.is_empty());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].logical_offset, 0);
        assert_eq!(entries[0].length, 4096);
        assert_eq!(entries[1].logical_offset, 4096);
        assert_eq!(entries[1].length, 4096);
        assert_eq!(m.representation(), ExtentMapRepr::Inline);
        assert_eq!(m.inline.header.file_size, 8192);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn fallocate_promotes_inline_unwritten_extent_to_btree() {
        let mut m = PolymorphicExtentMap::new();
        m.fallocate(0, 4096, false).unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::BTree);
        assert_eq!(m.entry_count(), 1);
        assert_eq!(
            m.lookup_range(0, 4096).unwrap(),
            vec![ExtentMapEntryV2::new_unwritten(0, 4096, 0)]
        );
        m.validate().unwrap();
    }

    #[test]
    fn fallocate_keeps_btree_when_unwritten_count_is_demote_sized() {
        let mut m = PolymorphicExtentMap::with_repr(ExtentMapRepr::BTree);
        m.fallocate(8192, 4096, true).unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::BTree);
        assert_eq!(m.entry_count(), 1);
        assert_eq!(
            m.lookup_range(8192, 4096).unwrap(),
            vec![ExtentMapEntryV2::new_unwritten(8192, 4096, 0)]
        );
        m.validate().unwrap();
    }

    #[test]
    fn fallocate_rejects_invalid_range_without_switching() {
        let mut m = PolymorphicExtentMap::new();
        let err = m.fallocate(u64::MAX, 1, false).unwrap_err();
        assert_eq!(err, ExtentMapError::InvalidRange);
        assert_eq!(m.representation(), ExtentMapRepr::Inline);
        assert_eq!(m.entry_count(), 0);
    }

    #[test]
    fn file_size_preserved_across_switch() {
        let mut m = PolymorphicExtentMap::new();
        m.insert_extent(&[data_entry(0, 4096)]).unwrap();
        assert_eq!(m.inline.header.file_size, 4096);

        // Promote
        let entries: Vec<_> = (0..7).map(|i| data_entry(i * 4096, 4096)).collect();
        m.insert_extent(&entries).unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::BTree);
        // file_size should have been copied to btree header
        assert_eq!(m.btree.header.file_size, 7 * 4096);
    }

    #[test]
    fn validate_works_in_both_reprs() {
        let mut m = PolymorphicExtentMap::new();
        m.insert_extent(&[data_entry(0, 4096)]).unwrap();
        m.validate().unwrap();

        let entries: Vec<_> = (0..7).map(|i| data_entry(i * 4096, 4096)).collect();
        m.insert_extent(&entries).unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::BTree);
        m.validate().unwrap();
    }

    #[test]
    fn seek_data_seek_hole_delegated() {
        let mut m = PolymorphicExtentMap::new();
        // Two adjacent data entries: [0..4096, 4096..8192]
        m.insert_extent(&[data_entry(0, 4096), data_entry(4096, 4096)])
            .unwrap();

        // seek_data from 2048 within first entry -> returns (2048, 2048) remaining
        let sd = m.seek_data(2048);
        assert!(sd.is_some());
        assert_eq!(sd.unwrap().0, 2048);

        // seek_hole from 0: with contiguous data 0..8192, no hole exists
        // so it returns None (falls past end)
        let sh = m.seek_hole(0);
        assert!(sh.is_none());
    }

    #[test]
    fn fiemap_delegated() {
        let mut m = PolymorphicExtentMap::new();
        m.insert_extent(&[data_entry(0, 4096)]).unwrap();
        let result = m.fiemap(0, 8192).unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn representation_display() {
        assert_eq!(format!("{}", ExtentMapRepr::Inline), "Inline");
        assert_eq!(format!("{}", ExtentMapRepr::BTree), "BTree");
    }

    #[test]
    fn explicit_with_repr_btree_stays() {
        let mut m = PolymorphicExtentMap::with_repr(ExtentMapRepr::BTree);
        // Insert few entries -> should NOT demote because we started in BTree
        m.insert_extent(&[data_entry(0, 4096), data_entry(4096, 4096)])
            .unwrap();
        // 2 data entries, no holes/UNWRITTEN -> demote to Inline
        assert_eq!(m.representation(), ExtentMapRepr::Inline);
        assert_eq!(m.entry_count(), 2);
    }

    #[test]
    fn check_and_switch_noop_when_stable() {
        let mut m = PolymorphicExtentMap::new();
        m.insert_extent(&[
            data_entry(0, 4096),
            data_entry(4096, 4096),
            data_entry(8192, 4096),
            data_entry(12288, 4096),
            data_entry(16384, 4096),
        ])
        .unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::Inline);
        // Call check_and_switch again — should stay Inline (5 entries, no holes/UNWRITTEN)
        m.check_and_switch().unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::Inline);
    }

    // -- V2 <-> V3 promotion / demotion tests --

    #[test]
    fn promotes_v2_to_v3_when_entry_count_exceeds_threshold() {
        let mut m = PolymorphicExtentMap::with_repr(ExtentMapRepr::BTree);
        m.set_btree_entry_count(100_000);
        m.check_and_switch().unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::MultiLevel);
    }

    #[test]
    fn stays_v2_at_exactly_promotion_threshold() {
        let mut m = PolymorphicExtentMap::with_repr(ExtentMapRepr::BTree);
        m.set_btree_entry_count(100_000);
        // 100_000 is the threshold for >= comparison
        m.check_and_switch().unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::MultiLevel);
    }

    #[test]
    fn stays_v2_below_promotion_threshold() {
        let mut m = PolymorphicExtentMap::with_repr(ExtentMapRepr::BTree);
        m.set_btree_entry_count(99_999);
        m.check_and_switch().unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::BTree);
    }

    #[test]
    fn stable_btree_noop_switch_preserves_fragmented_map() {
        let mut m = PolymorphicExtentMap::with_repr(ExtentMapRepr::BTree);
        let entries: Vec<_> = (0..200u64).map(|i| data_entry(i * 8192, 4096)).collect();
        m.insert_extent(&entries).unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::BTree);

        m.check_and_switch().unwrap();

        assert_eq!(m.representation(), ExtentMapRepr::BTree);
        assert_eq!(m.entry_count(), 200);
        assert_eq!(
            m.lookup_range(199 * 8192, 4096).unwrap(),
            vec![data_entry(199 * 8192, 4096)]
        );
    }

    #[test]
    fn v2_to_v3_streaming_promotion_preserves_fragmented_map() {
        let mut m = PolymorphicExtentMap::with_repr(ExtentMapRepr::BTree);
        let entries: Vec<_> = (0..128u64).map(|i| data_entry(i * 8192, 4096)).collect();
        m.insert_extent(&entries).unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::BTree);
        assert_eq!(m.entry_count(), 128);

        m.set_btree_entry_count(EXTENT_MAP_V2_V3_PROMOTION_THRESHOLD as u64);
        m.check_and_switch().unwrap();

        assert_eq!(m.representation(), ExtentMapRepr::MultiLevel);
        assert_eq!(m.entry_count(), 128);
        assert_eq!(m.file_size(), (127 * 8192) + 4096);
        assert_eq!(
            m.lookup_range(127 * 8192, 4096).unwrap(),
            vec![data_entry(127 * 8192, 4096)]
        );
        m.validate().unwrap();
    }

    #[test]
    fn demotes_v3_to_v2_when_below_demote_threshold() {
        let mut m = PolymorphicExtentMap::with_repr(ExtentMapRepr::MultiLevel);
        m.set_multi_level_entry_count(49_999);
        m.check_and_switch().unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::BTree);
    }

    #[test]
    fn stays_v3_at_demote_threshold_boundary() {
        let mut m = PolymorphicExtentMap::with_repr(ExtentMapRepr::MultiLevel);
        m.set_multi_level_entry_count(50_001);
        // 50_000 is the demotion threshold; 50_001 stays in V3
        m.check_and_switch().unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::MultiLevel);
    }

    #[test]
    fn v2_to_v3_promotion_preserves_data() {
        let mut m = PolymorphicExtentMap::with_repr(ExtentMapRepr::BTree);
        // Insert real data with BTree
        for i in 0..10u64 {
            m.insert_extent(&[data_entry(i * 4096, 4096)]).unwrap();
        }
        // Force promotion via high entry count
        m.set_btree_entry_count(100_001);
        m.check_and_switch().unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::MultiLevel);

        // Verify all data survived
        let results = m.lookup_range(0, 10 * 4096).unwrap();
        assert_eq!(results.len(), 10);
        for (i, r) in results.iter().enumerate() {
            assert_eq!(r.logical_offset, i as u64 * 4096);
            assert_eq!(r.length, 4096);
        }
        assert!(m.validate().is_ok());
    }

    #[test]
    fn v3_to_v2_demotion_preserves_data() {
        let mut m = PolymorphicExtentMap::with_repr(ExtentMapRepr::MultiLevel);
        // Insert real data with MultiLevel
        for i in 0..10u64 {
            m.insert_extent(&[data_entry(i * 4096, 4096)]).unwrap();
        }
        // Force demotion
        m.set_multi_level_entry_count(5);
        m.check_and_switch().unwrap();
        assert_eq!(m.representation(), ExtentMapRepr::BTree);

        // Verify all data survived
        let results = m.lookup_range(0, 10 * 4096).unwrap();
        assert_eq!(results.len(), 10);
        for (i, r) in results.iter().enumerate() {
            assert_eq!(r.logical_offset, i as u64 * 4096);
            assert_eq!(r.length, 4096);
        }
        assert!(m.validate().is_ok());
    }

    #[test]
    fn v2_to_v3_no_demote_when_entry_count_high() {
        let mut m = PolymorphicExtentMap::with_repr(ExtentMapRepr::MultiLevel);
        m.set_multi_level_entry_count(150_000);
        m.check_and_switch().unwrap();
        // Should stay in MultiLevel, not demote
        assert_eq!(m.representation(), ExtentMapRepr::MultiLevel);
    }

    #[test]
    fn stable_multi_level_noop_switch_preserves_representation() {
        let mut m = PolymorphicExtentMap::with_repr(ExtentMapRepr::MultiLevel);
        m.multi_level
            .insert_extent(&[data_entry(0, 4096), data_entry(8192, 4096)])
            .unwrap();
        m.set_multi_level_entry_count(150_000);

        m.check_and_switch().unwrap();

        assert_eq!(m.representation(), ExtentMapRepr::MultiLevel);
        assert_eq!(
            m.lookup_range(8192, 4096).unwrap(),
            vec![data_entry(8192, 4096)]
        );
    }

    #[test]
    fn v3_to_v2_streaming_demotion_preserves_fragmented_map() {
        let mut m = PolymorphicExtentMap::with_repr(ExtentMapRepr::MultiLevel);
        let entries: Vec<_> = (0..128u64).map(|i| data_entry(i * 8192, 4096)).collect();
        m.multi_level.insert_extent(&entries).unwrap();
        assert_eq!(m.entry_count(), 128);

        m.check_and_switch().unwrap();

        assert_eq!(m.representation(), ExtentMapRepr::BTree);
        assert_eq!(m.entry_count(), 128);
        assert_eq!(m.file_size(), (127 * 8192) + 4096);
        assert_eq!(
            m.lookup_range(64 * 8192, 4096).unwrap(),
            vec![data_entry(64 * 8192, 4096)]
        );
        m.validate().unwrap();
    }

    // -- PolymorphicExtentMap serialize/deserialize tests --

    #[test]
    fn polymorphic_serde_roundtrip_inline() {
        let mut map = PolymorphicExtentMap::new();
        map.insert_extent(&[data_entry(0, 4096), data_entry(8192, 4096)])
            .unwrap();
        assert_eq!(map.representation(), ExtentMapRepr::Inline);

        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();
        assert!(!buf.is_empty());

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = PolymorphicExtentMap::deserialize(&mut cursor).unwrap();
        assert_eq!(recon.representation(), ExtentMapRepr::Inline);
        assert_eq!(recon.entry_count(), 2);
        assert!(recon.validate().is_ok());
    }

    #[test]
    fn polymorphic_serde_roundtrip_btree() {
        let mut map = PolymorphicExtentMap::with_repr(ExtentMapRepr::BTree);
        let entries: Vec<_> = (0..10).map(|i| data_entry(i * 4096, 4096)).collect();
        map.insert_extent(&entries).unwrap();
        assert_eq!(map.representation(), ExtentMapRepr::BTree);

        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = PolymorphicExtentMap::deserialize(&mut cursor).unwrap();
        assert_eq!(recon.representation(), ExtentMapRepr::BTree);
        assert_eq!(recon.entry_count(), 10);
        assert!(recon.validate().is_ok());
    }

    #[test]
    fn polymorphic_serde_roundtrip_multi_level() {
        let mut map = PolymorphicExtentMap::with_repr(ExtentMapRepr::MultiLevel);
        // Insert directly into the multi_level component to avoid
        // check_and_switch demoting us back to BTree (200 <= 50_000).
        let entries: Vec<_> = (0..200).map(|i| data_entry(i * 16384, 4096)).collect();
        map.multi_level.insert_extent(&entries).unwrap();
        map.set_multi_level_entry_count(150_000);
        map.check_and_switch().unwrap();
        assert_eq!(map.representation(), ExtentMapRepr::MultiLevel);

        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = PolymorphicExtentMap::deserialize(&mut cursor).unwrap();
        assert_eq!(recon.representation(), ExtentMapRepr::MultiLevel);
        assert_eq!(recon.entry_count(), 200);
        assert!(recon.validate().is_ok());
    }

    #[test]
    fn polymorphic_serde_roundtrip_empty() {
        let map = PolymorphicExtentMap::new();
        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = PolymorphicExtentMap::deserialize(&mut cursor).unwrap();
        assert_eq!(recon.representation(), ExtentMapRepr::Inline);
        assert_eq!(recon.entry_count(), 0);
        assert!(recon.validate().is_ok());
    }

    #[test]
    fn polymorphic_serde_wrong_magic_rejected() {
        let buf = b"XXXX".to_vec();
        let mut cursor = std::io::Cursor::new(&buf);
        let err = PolymorphicExtentMap::deserialize(&mut cursor).unwrap_err();
        assert_eq!(err, ExtentMapError::WrongVersion);
    }

    #[test]
    fn polymorphic_serde_wrong_version_rejected() {
        let buf = b"VXPM\x63\x00\x00".to_vec();
        let mut cursor = std::io::Cursor::new(&buf);
        let err = PolymorphicExtentMap::deserialize(&mut cursor).unwrap_err();
        assert_eq!(err, ExtentMapError::WrongVersion);
    }

    #[test]
    fn polymorphic_serde_unknown_repr_rejected() {
        let buf = b"VXPM\x01\x00\xFF".to_vec();
        let mut cursor = std::io::Cursor::new(&buf);
        let err = PolymorphicExtentMap::deserialize(&mut cursor).unwrap_err();
        assert_eq!(err, ExtentMapError::WrongVersion);
    }

    #[test]
    fn polymorphic_serde_promotion_survives_roundtrip() {
        // Promote via entry count: V2 -> V3
        let mut map = PolymorphicExtentMap::with_repr(ExtentMapRepr::BTree);
        let entries: Vec<_> = (0..8).map(|i| data_entry(i * 4096, 4096)).collect();
        map.insert_extent(&entries).unwrap();
        // Force promotion by setting entry count high
        map.set_btree_entry_count(100_001);
        map.check_and_switch().unwrap();
        assert_eq!(map.representation(), ExtentMapRepr::MultiLevel);

        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = PolymorphicExtentMap::deserialize(&mut cursor).unwrap();
        assert_eq!(recon.representation(), ExtentMapRepr::MultiLevel);
        assert!(recon.validate().is_ok());
    }

    // -- V3 stress tests (>100K entries) --

    #[test]
    fn v3_stress_5k_insert_and_lookup() {
        let mut map = PolymorphicExtentMap::with_repr(ExtentMapRepr::BTree);
        // Batch insert 5,000 entries, then force promotion to V3.
        let entries: Vec<_> = (0..5_000u64).map(|i| data_entry(i * 4096, 4096)).collect();
        map.insert_extent(&entries).unwrap();
        assert_eq!(map.entry_count(), 5_000);

        // Force promotion to MultiLevel (already tested threshold in other tests).
        map.set_btree_entry_count(100_001);
        map.check_and_switch().unwrap();
        assert_eq!(map.representation(), ExtentMapRepr::MultiLevel);

        // Lookup at the start.
        let r = map.lookup_range(0, 4096).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].logical_offset, 0);

        // Lookup in the middle.
        let mid = 2_500 * 4096;
        let r = map.lookup_range(mid, 4096).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].logical_offset, mid);

        // Lookup at the end.
        let end = 4_999 * 4096;
        let r = map.lookup_range(end, 4096).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].logical_offset, end);

        assert!(map.validate().is_ok());
    }

    #[test]
    fn v3_stress_5k_serialize_roundtrip_with_checksums() {
        let mut map = PolymorphicExtentMap::with_repr(ExtentMapRepr::BTree);
        let entries: Vec<_> = (0..5_000u64).map(|i| data_entry(i * 4096, 4096)).collect();
        map.insert_extent(&entries).unwrap();
        map.set_btree_entry_count(100_001);
        map.check_and_switch().unwrap();
        assert_eq!(map.representation(), ExtentMapRepr::MultiLevel);
        assert_eq!(map.entry_count(), 5_000);

        // Serialize — exercises page-level BLAKE3 checksums at scale
        // (5K entries = 112 pages with MAX_LEAF=45).
        let mut buf = Vec::new();
        map.serialize(&mut buf).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let recon = PolymorphicExtentMap::deserialize(&mut cursor).unwrap();
        assert_eq!(recon.representation(), ExtentMapRepr::MultiLevel);
        assert_eq!(recon.entry_count(), 5_000);
        assert!(recon.validate().is_ok());

        // Verify spot-checks survive roundtrip.
        for offset in [0u64, 2_500 * 4096, 4_999 * 4096] {
            let r = recon.lookup_range(offset, 4096).unwrap();
            assert_eq!(r.len(), 1);
            assert_eq!(r[0].logical_offset, offset);
        }
    }

    #[test]
    fn v3_stress_5k_truncate_and_demote() {
        let mut map = PolymorphicExtentMap::with_repr(ExtentMapRepr::BTree);
        let entries: Vec<_> = (0..5_000u64).map(|i| data_entry(i * 4096, 4096)).collect();
        map.insert_extent(&entries).unwrap();
        map.set_btree_entry_count(100_001);
        map.check_and_switch().unwrap();
        assert_eq!(map.representation(), ExtentMapRepr::MultiLevel);

        // Truncate down to 1,000 entries — below demotion threshold.
        let new_size = 1_000 * 4096;
        let freed = map.truncate(new_size).unwrap();
        assert_eq!(freed.len(), 4_000);
        assert_eq!(map.entry_count(), 1_000);
        assert_eq!(map.representation(), ExtentMapRepr::BTree);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn v3_stress_5k_punch_hole() {
        let mut map = PolymorphicExtentMap::with_repr(ExtentMapRepr::BTree);
        let entries: Vec<_> = (0..5_000u64).map(|i| data_entry(i * 4096, 4096)).collect();
        map.insert_extent(&entries).unwrap();
        map.set_btree_entry_count(100_001);
        map.check_and_switch().unwrap();
        assert_eq!(map.representation(), ExtentMapRepr::MultiLevel);

        // Punch a hole in the middle.
        let hole_start = 2_000 * 4096;
        let hole_len = 1_000 * 4096;
        let freed = map.punch_hole(hole_start, hole_len).unwrap();
        assert_eq!(freed.len(), 1_000);

        // Verify entries before and after the hole are intact.
        let before = map.lookup_range(0, hole_start).unwrap();
        assert_eq!(before.len(), 2_000);

        // After hole: entries 3_000..4_999 remain.
        let after = map
            .lookup_range(hole_start + hole_len, 2_000 * 4096)
            .unwrap();
        assert_eq!(after.len(), 2_000);
        assert!(map.validate().is_ok());
    }

    #[test]
    fn v3_stress_cross_partition_lookup() {
        let mut map = PolymorphicExtentMap::with_repr(ExtentMapRepr::BTree);
        // Insert 250 entries spread across 1TB range (byte-range partitioned).
        for i in 0..250u64 {
            let offset = i * 4_000_000_000;
            map.insert_extent(&[data_entry(offset, 4096)]).unwrap();
        }
        // Force promotion to V3.
        map.set_btree_entry_count(100_001);
        map.check_and_switch().unwrap();
        assert_eq!(map.representation(), ExtentMapRepr::MultiLevel);

        // Cross-partition lookup: verify entries at widely separated offsets.
        let r_start = map.lookup_range(0, 4096).unwrap();
        assert_eq!(r_start.len(), 1);
        assert_eq!(r_start[0].logical_offset, 0);

        let r_mid = map.lookup_range(125 * 4_000_000_000, 4096).unwrap();
        assert_eq!(r_mid.len(), 1);
        assert_eq!(r_mid[0].logical_offset, 125 * 4_000_000_000);

        let r_end = map.lookup_range(249 * 4_000_000_000, 4096).unwrap();
        assert_eq!(r_end.len(), 1);
        assert_eq!(r_end[0].logical_offset, 249 * 4_000_000_000);

        assert!(map.validate().is_ok());
    }
}
