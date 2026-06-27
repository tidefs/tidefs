// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Authority type definitions for locator tables (originally from
//! tidefs-types-locator-table-core, now merged into locator-table).
//!
//! Provides ReplicaHealth, ShardPlacement, ReplicaPlacement, locator_flags,
//! ExtentLocatorValueV1, ExtentLocatorTable, LocatorTablePageHeader,
//! LocatorTableError, and the LocatorTableOps trait.

pub use tidefs_types_extent_map_core::LocatorId;

use core::fmt;

pub const LOCATOR_TABLE_SPEC: &str = "tidefs-locator-table-v1-design-1285";
pub const LOCATOR_TABLE_PAGE_MAGIC: [u8; 4] = [b'L', b'O', b'C', b'T'];
pub const LOCATOR_TABLE_DEFAULT_PAGE_SIZE: usize = 4096;
pub const LOCATOR_VALUE_V1_FIXED_SIZE: usize = 122;
pub const LOCATOR_TABLE_PAGE_HEADER_SIZE: usize = 54;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ReplicaHealth {
    Online = 0,
    Degraded = 1,
    Offline = 2,
    Retired = 3,
    Corrupt = 4,
}

impl ReplicaHealth {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ReplicaHealth::Online => "online",
            ReplicaHealth::Degraded => "degraded",
            ReplicaHealth::Offline => "offline",
            ReplicaHealth::Retired => "retired",
            ReplicaHealth::Corrupt => "corrupt",
        }
    }
    #[must_use]
    pub const fn is_readable(self) -> bool {
        matches!(self, ReplicaHealth::Online | ReplicaHealth::Degraded)
    }
}

impl fmt::Display for ReplicaHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShardPlacement {
    pub shard_index: u16,
    pub segment_id: u64,
    pub grain_offset: u64,
    pub grain_count: u64,
}

impl ShardPlacement {
    #[must_use]
    pub const fn new(
        shard_index: u16,
        segment_id: u64,
        grain_offset: u64,
        grain_count: u64,
    ) -> Self {
        Self {
            shard_index,
            segment_id,
            grain_offset,
            grain_count,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicaPlacement {
    pub node_id: u64,
    pub device_id: u64,
    pub shard_placements: std::vec::Vec<ShardPlacement>,
    pub health: ReplicaHealth,
}

impl ReplicaPlacement {
    #[must_use]
    pub fn new_unsharded(
        node_id: u64,
        device_id: u64,
        segment_id: u64,
        grain_offset: u64,
        grain_count: u64,
    ) -> Self {
        let placements = vec![ShardPlacement::new(
            0,
            segment_id,
            grain_offset,
            grain_count,
        )];
        Self {
            node_id,
            device_id,
            shard_placements: placements,
            health: ReplicaHealth::Online,
        }
    }
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.health.is_readable()
    }
    #[must_use]
    pub fn total_grains(&self) -> u64 {
        self.shard_placements.iter().map(|s| s.grain_count).sum()
    }
}

pub mod locator_flags {
    pub const SHARDED: u64 = 0x0001;
    pub const ERASURE_CODED: u64 = 0x0002;
    pub const COMPRESSED: u64 = 0x0004;
    pub const ENCRYPTED: u64 = 0x0008;
    pub const DEDUP_ELIGIBLE: u64 = 0x0010;
    pub const CLONE_TARGET: u64 = 0x0020;
    pub const DEADLIST: u64 = 0x0040;
    pub const INLINE_PAYLOAD: u64 = 0x0080;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtentLocatorValueV1 {
    pub locator_id: LocatorId,
    pub locator_rev: u64,
    pub flags: u64,
    pub shard_count: u16,
    pub replica_count: u8,
    pub replica_placement: std::vec::Vec<ReplicaPlacement>,
    pub checksum_profile_id: u8,
    pub compression: u8,
    pub extent_flags: u8,
    pub created_commit_group: u64,
    pub payload_digest: [u8; 32],
    pub payload_bytes: u64,
    pub on_media_bytes: u64,
    pub reserved: [u8; 11],
}

impl ExtentLocatorValueV1 {
    #[must_use]
    pub fn new(
        locator_id: LocatorId,
        locator_rev: u64,
        created_commit_group: u64,
        payload_digest: [u8; 32],
        payload_bytes: u64,
    ) -> Self {
        Self {
            locator_id,
            locator_rev,
            flags: 0,
            shard_count: 1,
            replica_count: 0,
            replica_placement: std::vec::Vec::new(),
            checksum_profile_id: 0,
            compression: 0,
            extent_flags: 0,
            created_commit_group,
            payload_digest,
            payload_bytes,
            on_media_bytes: payload_bytes,
            reserved: [0u8; 11],
        }
    }
    #[must_use]
    pub const fn is_sharded(&self) -> bool {
        (self.flags & locator_flags::SHARDED) != 0
    }
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        (self.flags & locator_flags::COMPRESSED) != 0
    }
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        (self.flags & locator_flags::ENCRYPTED) != 0
    }
    pub fn set_flag(&mut self, flag: u64) {
        self.flags |= flag;
    }
    pub fn clear_flag(&mut self, flag: u64) {
        self.flags &= !flag;
    }
    pub fn add_replica(&mut self, placement: ReplicaPlacement) {
        self.replica_placement.push(placement);
        self.replica_count = self.replica_placement.len() as u8;
    }
    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        if self.on_media_bytes == 0 || !self.is_compressed() {
            return 1.0;
        }
        self.payload_bytes as f64 / self.on_media_bytes as f64
    }
}

impl fmt::Display for ExtentLocatorValueV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExtentLocatorValueV1(id={} rev={} replicas={})",
            self.locator_id, self.locator_rev, self.replica_count
        )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExtentLocatorTable {
    pub root: LocatorId,
    pub generation: u64,
    pub schema_version: u8,
}

impl ExtentLocatorTable {
    pub const CURRENT_SCHEMA_VERSION: u8 = 1;
    #[must_use]
    pub const fn new() -> Self {
        Self {
            root: LocatorId::NONE,
            generation: 0,
            schema_version: Self::CURRENT_SCHEMA_VERSION,
        }
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.root.is_none()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocatorTablePageHeader {
    pub magic: [u8; 4],
    pub page_kind: u8,
    pub entry_count: u16,
    pub level: u8,
    pub checksum: [u8; 32],
    pub reserved: [u8; 14],
}

impl LocatorTablePageHeader {
    #[must_use]
    pub const fn new_leaf() -> Self {
        Self {
            magic: LOCATOR_TABLE_PAGE_MAGIC,
            page_kind: 0,
            entry_count: 0,
            level: 0,
            checksum: [0u8; 32],
            reserved: [0u8; 14],
        }
    }
    #[must_use]
    pub const fn new_internal(level: u8) -> Self {
        Self {
            magic: LOCATOR_TABLE_PAGE_MAGIC,
            page_kind: 1,
            entry_count: 0,
            level,
            checksum: [0u8; 32],
            reserved: [0u8; 14],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocatorTableError {
    NotFound,
    InvalidLocatorId,
    Corrupt,
    WrongSchemaVersion,
    AllocationFailed,
    RelocationNoop,
    RefcountUnderflow,
    StillReferenced,
}

impl fmt::Display for LocatorTableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LocatorTableError::NotFound => f.write_str("locator not found"),
            LocatorTableError::InvalidLocatorId => f.write_str("invalid locator id"),
            LocatorTableError::Corrupt => f.write_str("locator table page corrupt"),
            LocatorTableError::WrongSchemaVersion => f.write_str("unsupported schema version"),
            LocatorTableError::AllocationFailed => f.write_str("allocation failed"),
            LocatorTableError::RelocationNoop => f.write_str("relocation no-op"),
            LocatorTableError::RefcountUnderflow => f.write_str("refcount underflow"),
            LocatorTableError::StillReferenced => f.write_str("locator still referenced"),
        }
    }
}

pub trait LocatorTableOps {
    fn resolve(&self, locator_id: LocatorId) -> Result<ExtentLocatorValueV1, LocatorTableError>;
    fn allocate(
        &mut self,
        payload_bytes: u64,
        payload_digest: [u8; 32],
        replica_placement: std::vec::Vec<ReplicaPlacement>,
        created_commit_group: u64,
    ) -> Result<ExtentLocatorValueV1, LocatorTableError>;
    fn relocate(
        &mut self,
        old_locator_id: LocatorId,
        new_replica_placement: std::vec::Vec<ReplicaPlacement>,
    ) -> Result<ExtentLocatorValueV1, LocatorTableError>;
    fn relocate_value(
        &mut self,
        old_locator_id: LocatorId,
        mut new_value: ExtentLocatorValueV1,
    ) -> Result<ExtentLocatorValueV1, LocatorTableError> {
        let relocated = self.relocate(old_locator_id, new_value.replica_placement.clone())?;
        new_value.locator_id = relocated.locator_id;
        new_value.locator_rev = relocated.locator_rev;
        new_value.created_commit_group = relocated.created_commit_group;
        Ok(new_value)
    }
    fn retire(&mut self, locator_id: LocatorId) -> Result<(), LocatorTableError>;
    fn batch_resolve(
        &self,
        locator_ids: &[LocatorId],
    ) -> std::vec::Vec<(LocatorId, ExtentLocatorValueV1)>;
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::format;

    #[test]
    fn replica_health_readable() {
        assert!(ReplicaHealth::Online.is_readable());
        assert!(ReplicaHealth::Degraded.is_readable());
        assert!(!ReplicaHealth::Offline.is_readable());
    }

    #[test]
    fn replica_health_display() {
        assert_eq!(ReplicaHealth::Online.as_str(), "online");
    }

    #[test]
    fn shard_placement_new() {
        let sp = ShardPlacement::new(0, 1, 100, 256);
        assert_eq!(sp.shard_index, 0);
        assert_eq!(sp.segment_id, 1);
    }

    #[test]
    fn replica_unsharded() {
        let rp = ReplicaPlacement::new_unsharded(10, 20, 30, 0, 1024);
        assert_eq!(rp.node_id, 10);
        assert_eq!(rp.device_id, 20);
        assert!(rp.is_readable());
        assert_eq!(rp.total_grains(), 1024);
    }

    #[test]
    fn locator_value_new() {
        let digest = [0xBBu8; 32];
        let lv = ExtentLocatorValueV1::new(LocatorId(42), 1, 100, digest, 4096);
        assert_eq!(lv.locator_id, LocatorId(42));
        assert_eq!(lv.payload_bytes, 4096);
        assert!(!lv.is_compressed());
    }

    #[test]
    fn locator_value_flags() {
        let mut lv = ExtentLocatorValueV1::new(LocatorId(1), 0, 0, [0u8; 32], 8192);
        lv.set_flag(locator_flags::COMPRESSED);
        assert!(lv.is_compressed());
        lv.clear_flag(locator_flags::COMPRESSED);
        assert!(!lv.is_compressed());
    }

    #[test]
    fn locator_value_replicas() {
        let mut lv = ExtentLocatorValueV1::new(LocatorId(1), 0, 0, [0u8; 32], 4096);
        assert_eq!(lv.replica_count, 0);
        lv.add_replica(ReplicaPlacement::new_unsharded(1, 1, 1, 0, 1024));
        assert_eq!(lv.replica_count, 1);
    }

    #[test]
    fn locator_value_compression_ratio() {
        let mut lv = ExtentLocatorValueV1::new(LocatorId(1), 0, 0, [0u8; 32], 4096);
        assert!((lv.compression_ratio() - 1.0).abs() < f64::EPSILON);
        lv.set_flag(locator_flags::COMPRESSED);
        lv.on_media_bytes = 2048;
        assert!((lv.compression_ratio() - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn locator_table_defaults() {
        let t = ExtentLocatorTable::new();
        assert!(t.is_empty());
        assert_eq!(t.schema_version, ExtentLocatorTable::CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn locator_page_header_leaf() {
        let hdr = LocatorTablePageHeader::new_leaf();
        assert_eq!(hdr.magic, LOCATOR_TABLE_PAGE_MAGIC);
        assert_eq!(hdr.page_kind, 0);
    }

    #[test]
    fn locator_error_display() {
        assert_eq!(
            format!("{}", LocatorTableError::NotFound),
            "locator not found"
        );
    }

    #[test]
    fn reexports_from_extent_map_core() {
        let id = LocatorId(42);
        assert!(id.is_some());
    }

    #[test]
    fn locator_flag_values_distinct() {
        let flags: [u64; 8] = [
            locator_flags::SHARDED,
            locator_flags::ERASURE_CODED,
            locator_flags::COMPRESSED,
            locator_flags::ENCRYPTED,
            locator_flags::DEDUP_ELIGIBLE,
            locator_flags::CLONE_TARGET,
            locator_flags::DEADLIST,
            locator_flags::INLINE_PAYLOAD,
        ];
        for i in 0..flags.len() {
            for j in (i + 1)..flags.len() {
                assert_ne!(flags[i], flags[j], "flags {i} and {j} collide");
            }
        }
    }
}
