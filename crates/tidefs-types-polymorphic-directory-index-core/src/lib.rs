// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Authority type definitions for the polymorphic directory index.
//!
//! Implements the type registry from
//! [`docs/POLYMORPHIC_DIRECTORY_INDEX_DESIGN.md`] with two canonical
//! directory representations (`DirMicroListV1` inline O(n) and
//! `DirBtreeRootV1` external B+tree O(log n)), switching thresholds
//! with hysteresis, tagged 64-bit readdir cookies, and dataset-level
//! `DatasetDirPolicy`.
//!
//! This crate covers Phase 1 (types + cookie encoding + threshold logic)
//! of the design spec. The B+tree implementation and migration engine
//! are tracked by Review debt TFR-002/TFR-013.
//!
//! The `alloc` feature gates types that require heap allocation
//! (`DirMicroListV1`, `DirMicroEntry`, `DirBtreeLeafEntry`,
//! `DirBtreeInternalEntry`). Fixed-size types (`DirBtreeRootV1`,
//! `DirCookie`, `DatasetDirPolicy`, `DirStorageKind`, `LocatorId`)
//! are always available.
//!
//! [`docs/POLYMORPHIC_DIRECTORY_INDEX_DESIGN.md`]:
//! https://forgejo/forgeadmin/tidefs/docs/POLYMORPHIC_DIRECTORY_INDEX_DESIGN.md

use core::fmt;

#[cfg(feature = "alloc")]
extern crate alloc;

// ---------------------------------------------------------------------------
// LocatorId — placeholder for the storage engine's object pointer
// ---------------------------------------------------------------------------

/// On-media locator for an independently-stored object (e.g. a B-tree page).
///
/// This is a placeholder newtype; the actual layout is defined in the
/// storage engine layer (#1285).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct LocatorId(pub u64);

impl LocatorId {
    /// Sentinel value for an unset/null locator.
    pub const EMPTY: LocatorId = LocatorId(0);

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for LocatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LocatorId({})", self.0)
    }
}

// ---------------------------------------------------------------------------
// DirStorageKind — discriminator byte for directory representation
// ---------------------------------------------------------------------------

/// Identifies which directory representation (`DirStorage` variant) is
/// stored in the directory inode's content payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct DirStorageKind(pub u8);

impl DirStorageKind {
    /// Directory uses `DirMicroListV1` (inline flat list).
    pub const MICRO_LIST: DirStorageKind = DirStorageKind(0);
    /// Directory uses `DirBtreeRootV1` (external B+tree).
    pub const BTREE: DirStorageKind = DirStorageKind(1);

    /// Decode from a wire byte.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(DirStorageKind::MICRO_LIST),
            1 => Some(DirStorageKind::BTREE),
            _ => None,
        }
    }

    /// Encode to a wire byte.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self.0
    }

    /// Returns `true` if this is the micro-list representation.
    #[must_use]
    pub const fn is_micro_list(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if this is the B-tree representation.
    #[must_use]
    pub const fn is_btree(self) -> bool {
        self.0 == 1
    }
}

impl fmt::Display for DirStorageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => f.write_str("MicroList"),
            1 => f.write_str("BTree"),
            _ => f.write_str("Unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// DirBtreeRootV1 — external B+tree directory root (O(log n))
// ---------------------------------------------------------------------------

/// Magic bytes for `DirBtreeRootV1`.
pub const DIR_BTREE_ROOT_MAGIC: &[u8; 4] = b"DIRB";
/// Magic bytes for `DirBtreePageHeader`.
pub const DIR_BTREE_PAGE_MAGIC: &[u8; 4] = b"DIRP";

/// B+tree root stored as the directory inode's content payload when
/// `dir_storage_kind == 1`.
///
/// Total fixed size: 4 + 8 + 8 + 8 + 8 + 8 + 1 + 1 + 6 = 60 bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DirBtreeRootV1 {
    /// Magic: `b"DIRB"`.
    pub magic: [u8; 4],
    /// Owning directory inode id.
    pub directory_inode_id: u64,
    /// Monotonic version for invalidation.
    pub directory_version: u64,
    /// Total entries across all leaf pages.
    pub entry_count: u64,
    /// Sum of all entry name lengths (for threshold checks).
    pub total_name_bytes: u64,
    /// Points to the B+tree root page in the locator table.
    pub root_page_locator: LocatorId,
    /// Depth: 0 = single leaf, 1+ = internal levels.
    pub depth: u8,
    /// Bit 0: has_subdirs; bits 1-7: reserved.
    pub flags: u8,
    /// Reserved for alignment / future use.
    pub reserved: [u8; 6],
}

impl DirBtreeRootV1 {
    /// Total fixed size in bytes (= 60).
    pub const FIXED_SIZE: usize = 60;

    /// Create a new root with the given parameters.
    #[must_use]
    pub const fn new(
        directory_inode_id: u64,
        directory_version: u64,
        root_page_locator: LocatorId,
    ) -> Self {
        DirBtreeRootV1 {
            magic: *DIR_BTREE_ROOT_MAGIC,
            directory_inode_id,
            directory_version,
            entry_count: 0,
            total_name_bytes: 0,
            root_page_locator,
            depth: 0,
            flags: 0,
            reserved: [0u8; 6],
        }
    }

    /// Returns `true` if the magic bytes are valid.
    #[must_use]
    pub const fn is_valid_magic(&self) -> bool {
        self.magic[0] == b'D'
            && self.magic[1] == b'I'
            && self.magic[2] == b'R'
            && self.magic[3] == b'B'
    }

    /// Returns `true` if the `has_subdirs` flag is set.
    #[must_use]
    pub const fn has_subdirs(&self) -> bool {
        self.flags & 0x01 != 0
    }
}

// ---------------------------------------------------------------------------
// DirBtreePageHeader — common header for all B+tree pages
// ---------------------------------------------------------------------------

/// Page kind discriminator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct DirBtreePageKind(pub u8);

impl DirBtreePageKind {
    /// Leaf page.
    pub const LEAF: DirBtreePageKind = DirBtreePageKind(0);
    /// Internal (non-leaf) page.
    pub const INTERNAL: DirBtreePageKind = DirBtreePageKind(1);

    /// Decode from wire byte.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::LEAF),
            1 => Some(Self::INTERNAL),
            _ => None,
        }
    }

    /// Encode to wire byte.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self.0
    }
}

/// Common header for every B+tree page.
///
/// Total fixed size: 4 + 1 + 2 + 1 + 14 + 32 = 54 bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DirBtreePageHeader {
    /// Magic: `b"DIRP"`.
    pub magic: [u8; 4],
    /// 0 = leaf, 1 = internal.
    pub page_kind: u8,
    /// Number of entries in the page.
    pub entry_count: u16,
    /// 0 = leaf, 1+ = internal level.
    pub level: u8,
    /// Reserved for alignment / future use.
    pub reserved: [u8; 14],
    /// BLAKE3-256 checksum over the full page content.
    pub checksum: [u8; 32],
}

impl DirBtreePageHeader {
    /// Total fixed size in bytes (= 54).
    pub const FIXED_SIZE: usize = 54;

    /// Create a new page header.
    #[must_use]
    pub const fn new(page_kind: DirBtreePageKind, entry_count: u16, level: u8) -> Self {
        DirBtreePageHeader {
            magic: *DIR_BTREE_PAGE_MAGIC,
            page_kind: page_kind.to_u8(),
            entry_count,
            level,
            reserved: [0u8; 14],
            checksum: [0u8; 32],
        }
    }

    /// Returns `true` if the magic bytes are valid.
    #[must_use]
    pub const fn is_valid_magic(&self) -> bool {
        self.magic[0] == b'D'
            && self.magic[1] == b'I'
            && self.magic[2] == b'R'
            && self.magic[3] == b'P'
    }
}

// ===========================================================================
// Variable-length types (gated behind `alloc` feature)
// ===========================================================================

/// A single entry in a `DirMicroListV1`.
///
/// Fixed per-entry overhead: 4 + 8 + 8 + 4 = 24 bytes + `name_len`.
#[cfg(any(test, feature = "alloc"))]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DirMicroEntry {
    /// Length of `name` in bytes.
    pub name_len: u32,
    /// Target inode id.
    pub inode_id: u64,
    /// Inode generation number (for stale-handle detection).
    pub generation: u64,
    /// `NodeKind` encoded as u32 (0=Dir, 1=File, 2=Symlink, …).
    pub kind: u32,
    /// Entry name (opaque bytes; no null terminator required).
    pub name: alloc::vec::Vec<u8>,
}

#[cfg(any(test, feature = "alloc"))]
impl DirMicroEntry {
    /// Fixed per-entry overhead in bytes (= 24).
    pub const FIXED_OVERHEAD: usize = 24;

    /// Total on-wire size of this entry.
    #[must_use]
    pub fn wire_size(&self) -> usize {
        Self::FIXED_OVERHEAD + self.name.len()
    }
}

/// Inline micro-list directory representation.
///
/// Stored directly as the directory inode's content payload when
/// `dir_storage_kind == 0`. All entries are scanned linearly for
/// `lookup` — acceptable for n <= 50.
#[cfg(any(test, feature = "alloc"))]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DirMicroListV1 {
    /// Owning directory inode id.
    pub directory_inode_id: u64,
    /// Monotonic version for invalidation (bumped on every mutation).
    pub directory_version: u64,
    /// Number of entries.
    pub entry_count: u64,
    /// Sum of all entry name lengths (for threshold checks).
    pub total_name_bytes: u64,
    /// Bit 0: has_subdirs; bits 1-7: reserved.
    pub flags: u8,
    /// Reserved for alignment / future use.
    pub reserved: [u8; 7],
    /// Variable-length entry array.
    pub entries: alloc::vec::Vec<DirMicroEntry>,
}

#[cfg(any(test, feature = "alloc"))]
impl DirMicroListV1 {
    /// Header size (inode_id + version + count + name_bytes + flags + reserved).
    pub const HEADER_SIZE: usize = 8 + 8 + 8 + 8 + 1 + 7;

    /// Returns `true` if the `has_subdirs` flag is set.
    #[must_use]
    pub const fn has_subdirs(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Set the `has_subdirs` flag.
    pub fn set_has_subdirs(&mut self, v: bool) {
        if v {
            self.flags |= 0x01;
        } else {
            self.flags &= !0x01;
        }
    }

    /// Total name bytes computed from the entries list.
    #[must_use]
    pub fn compute_total_name_bytes(&self) -> u64 {
        self.entries.iter().map(|e| e.name.len() as u64).sum()
    }
}

/// Entry in a B+tree leaf page, keyed by `BLAKE3-64(name)`.
///
/// Fixed per-entry overhead: 8 + 2 + 8 + 8 + 4 + 1 + 1 = 32 bytes + name_len.
#[cfg(any(test, feature = "alloc"))]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DirBtreeLeafEntry {
    /// Primary key: BLAKE3-64 hash of the entry name.
    pub name_hash: u64,
    /// Length of `name` in bytes.
    pub name_len: u16,
    /// Target inode id.
    pub inode_id: u64,
    /// Inode generation number.
    pub generation: u64,
    /// `NodeKind` encoded as u32.
    pub kind: u32,
    /// Per-entry flags (reserved).
    pub flags: u8,
    /// Reserved for alignment.
    pub reserved: [u8; 1],
    /// Full entry name (stored for collision verification and readdir).
    pub name: alloc::vec::Vec<u8>,
}

#[cfg(any(test, feature = "alloc"))]
impl DirBtreeLeafEntry {
    /// Fixed per-entry overhead in bytes (= 32).
    pub const FIXED_OVERHEAD: usize = 32;

    /// Total on-wire size of this entry.
    #[must_use]
    pub fn wire_size(&self) -> usize {
        Self::FIXED_OVERHEAD + self.name.len()
    }
}

/// Entry in a B+tree internal page, defining a key range separator.
///
/// The `separator_hash` is the maximum hash in the child subtree. The
/// preceding child pointer (implicit in page layout) leads to entries
/// with hashes <= `separator_hash`.
///
/// Fixed overhead: 8 + 2 + name_len + 8 = 26 bytes + name_len.
#[cfg(any(test, feature = "alloc"))]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DirBtreeInternalEntry {
    /// Maximum BLAKE3-64 hash in the child subtree.
    pub separator_hash: u64,
    /// Length of the separator name in bytes.
    pub separator_name_len: u16,
    /// Separator name for collision disambiguation.
    pub separator_name: alloc::vec::Vec<u8>,
    /// Locator of the child B+tree page.
    pub child_page_locator: LocatorId,
}

#[cfg(any(test, feature = "alloc"))]
impl DirBtreeInternalEntry {
    /// Fixed per-entry overhead in bytes (= 26).
    pub const FIXED_OVERHEAD: usize = 26;

    /// Total on-wire size of this entry.
    #[must_use]
    pub fn wire_size(&self) -> usize {
        Self::FIXED_OVERHEAD + self.separator_name.len()
    }
}

/// Canonical tagged union of directory representations.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum DirStorage {
    /// Inline micro-list (n <= ~50).
    #[cfg(any(test, feature = "alloc"))]
    MicroList(DirMicroListV1),
    /// External B+tree (any size, O(log n)).
    BTree(DirBtreeRootV1),
}

impl DirStorage {
    /// Returns the `DirStorageKind` for this variant.
    #[must_use]
    pub const fn kind(&self) -> DirStorageKind {
        match self {
            #[cfg(any(test, feature = "alloc"))]
            DirStorage::MicroList(_) => DirStorageKind::MICRO_LIST,
            DirStorage::BTree(_) => DirStorageKind::BTREE,
        }
    }

    /// Returns the entry count, regardless of representation.
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        match self {
            #[cfg(any(test, feature = "alloc"))]
            DirStorage::MicroList(m) => m.entry_count,
            DirStorage::BTree(b) => b.entry_count,
        }
    }

    /// Returns the total name bytes, regardless of representation.
    #[must_use]
    pub fn total_name_bytes(&self) -> u64 {
        match self {
            #[cfg(any(test, feature = "alloc"))]
            DirStorage::MicroList(m) => m.total_name_bytes,
            DirStorage::BTree(b) => b.total_name_bytes,
        }
    }

    /// Returns the directory version.
    #[must_use]
    pub const fn directory_version(&self) -> u64 {
        match self {
            #[cfg(any(test, feature = "alloc"))]
            DirStorage::MicroList(m) => m.directory_version,
            DirStorage::BTree(b) => b.directory_version,
        }
    }
}

// ---------------------------------------------------------------------------
// DatasetDirPolicy — per-dataset switching thresholds
// ---------------------------------------------------------------------------

/// Dataset-level policy controlling directory representation switching.
///
/// Stored in the dataset superblock. Changing thresholds takes effect on
/// the next directory mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DatasetDirPolicy {
    /// Maximum entries before B-tree is considered (default 50).
    pub dir_micro_max_entries: u16,
    /// Maximum total name bytes before B-tree is considered (default 2048).
    pub dir_micro_max_name_bytes: u32,
    /// Maximum entries before B-tree can downshift to micro-list (default 20).
    pub dir_btree_downshift_entries: u16,
    /// Maximum name bytes before B-tree can downshift (default 1024).
    pub dir_btree_downshift_name_bytes: u32,
}

impl DatasetDirPolicy {
    /// Sensible defaults for a general-purpose dataset.
    pub const DEFAULT: DatasetDirPolicy = DatasetDirPolicy {
        dir_micro_max_entries: 50,
        dir_micro_max_name_bytes: 2048,
        dir_btree_downshift_entries: 20,
        dir_btree_downshift_name_bytes: 1024,
    };

    /// Returns `true` if a directory with the given count and name bytes
    /// should use the B-tree representation.
    #[must_use]
    pub const fn should_use_btree(&self, count: u64, name_bytes: u64) -> bool {
        count > self.dir_micro_max_entries as u64
            || name_bytes > self.dir_micro_max_name_bytes as u64
    }

    /// Returns `true` if a B-tree directory should downshift to micro-list
    /// (hysteresis: stricter thresholds for downshifting).
    #[must_use]
    pub const fn should_use_micro_from_btree(&self, count: u64, name_bytes: u64) -> bool {
        count <= self.dir_btree_downshift_entries as u64
            && name_bytes <= self.dir_btree_downshift_name_bytes as u64
    }
}

impl Default for DatasetDirPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

// ---------------------------------------------------------------------------
// Convenience free functions for switching thresholds
// ---------------------------------------------------------------------------

/// Returns `true` if a directory should use B-tree representation at the
/// default thresholds.
///
/// Equivalent to `DatasetDirPolicy::DEFAULT.should_use_btree(count, name_bytes)`.
#[must_use]
pub const fn should_use_btree(count: u64, name_bytes: u64) -> bool {
    count > 50 || name_bytes > 2048
}

/// Returns `true` if a B-tree directory should downshift to micro-list at
/// the default thresholds (hysteresis).
#[must_use]
pub const fn should_use_micro_from_btree(count: u64, name_bytes: u64) -> bool {
    count <= 20 && name_bytes <= 1024
}

// ---------------------------------------------------------------------------
// DirCookie — tagged 64-bit readdir cookie surviving representation changes
// ---------------------------------------------------------------------------

/// Tagged 64-bit readdir cookie.
///
/// Encoding: `(kind << 63) | payload`
///
/// - `kind = 0` (MicroList): payload = `entry_index` (0-based u31).
/// - `kind = 1` (BTree): payload = `(page_index << 16) | entry_index`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct DirCookie(pub u64);

impl DirCookie {
    /// Cookie representing "start from the beginning".
    pub const START: DirCookie = DirCookie(0);

    /// Bit position of the kind tag.
    const KIND_BIT: u64 = 63;

    /// Mask for extracting the payload (bits 0..62).
    const PAYLOAD_MASK: u64 = (1u64 << 63) - 1;

    /// Encode a micro-list cookie from an entry index.
    ///
    /// `entry_index` is 0-based, capped at `u31::MAX` (2^31 - 1).
    #[must_use]
    pub const fn encode_micro(entry_index: u32) -> u64 {
        entry_index as u64 & Self::PAYLOAD_MASK
    }

    /// Encode a B-tree cookie from a page index and entry index.
    ///
    /// `page_index` occupies bits 16..62, `entry_index` occupies bits 0..15.
    #[must_use]
    pub const fn encode_btree(page_index: u16, entry_index: u16) -> u64 {
        let payload = ((page_index as u64) << 16) | (entry_index as u64);
        (1u64 << Self::KIND_BIT) | (payload & Self::PAYLOAD_MASK)
    }

    /// Returns the cookie's kind (`0` = MicroList, `1` = BTree).
    #[must_use]
    pub const fn kind(self) -> u8 {
        ((self.0 >> Self::KIND_BIT) & 1) as u8
    }

    /// Returns the raw payload (bits 0..62).
    #[must_use]
    pub const fn payload(self) -> u64 {
        self.0 & Self::PAYLOAD_MASK
    }

    /// Returns `true` if this is a micro-list cookie.
    #[must_use]
    pub const fn is_micro(self) -> bool {
        self.kind() == 0
    }

    /// Returns `true` if this is a B-tree cookie.
    #[must_use]
    pub const fn is_btree(self) -> bool {
        self.kind() == 1
    }

    /// Decode as a micro-list cookie, returning the entry index.
    #[must_use]
    pub const fn as_micro_entry_index(self) -> Option<u32> {
        if self.is_micro() {
            Some(self.payload() as u32)
        } else {
            None
        }
    }

    /// Decode as a B-tree cookie, returning `(page_index, entry_index)`.
    #[must_use]
    pub const fn as_btree_indices(self) -> Option<(u16, u16)> {
        if self.is_btree() {
            let p = self.payload();
            Some(((p >> 16) as u16, (p & 0xFFFF) as u16))
        } else {
            None
        }
    }
}

impl fmt::Display for DirCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_micro() {
            write!(f, "DirCookie(Micro, index={})", self.payload())
        } else if let Some((page, entry)) = self.as_btree_indices() {
            write!(f, "DirCookie(BTree, page={page}, entry={entry})")
        } else {
            write!(f, "DirCookie(BTree, raw={})", self.payload())
        }
    }
}

// ---------------------------------------------------------------------------
// Canonical feature name constant
// ---------------------------------------------------------------------------

/// Canonical feature name for the polymorphic directory index.
pub const FEATURE_POLYMORPHIC_DIR_INDEX: &str = "org.tidefs:polymorphic_dir_index";

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- DirStorageKind -----------------------------------------------------

    #[test]
    fn dir_storage_kind_roundtrip() {
        for k in [DirStorageKind::MICRO_LIST, DirStorageKind::BTREE] {
            let byte = k.to_u8();
            let decoded = DirStorageKind::from_u8(byte);
            assert_eq!(decoded, Some(k));
        }
    }

    #[test]
    fn dir_storage_kind_invalid_byte() {
        assert_eq!(DirStorageKind::from_u8(2), None);
        assert_eq!(DirStorageKind::from_u8(255), None);
    }

    #[test]
    fn dir_storage_kind_is_micro_list() {
        assert!(DirStorageKind::MICRO_LIST.is_micro_list());
        assert!(!DirStorageKind::BTREE.is_micro_list());
    }

    #[test]
    fn dir_storage_kind_is_btree() {
        assert!(!DirStorageKind::MICRO_LIST.is_btree());
        assert!(DirStorageKind::BTREE.is_btree());
    }

    #[test]
    fn dir_storage_kind_display() {
        assert_eq!(DirStorageKind::MICRO_LIST.to_string(), "MicroList");
        assert_eq!(DirStorageKind::BTREE.to_string(), "BTree");
    }

    // -- LocatorId ----------------------------------------------------------

    #[test]
    fn locator_id_empty() {
        assert!(LocatorId::EMPTY.is_empty());
        assert!(!LocatorId(42).is_empty());
    }

    // -- DirMicroListV1 / DirMicroEntry ------------------------------------

    #[test]
    fn micro_entry_wire_size() {
        let entry = DirMicroEntry {
            name_len: 8,
            inode_id: 1,
            generation: 0,
            kind: 0,
            name: b"testfile".to_vec(),
        };
        assert_eq!(entry.wire_size(), 24 + 8);
    }

    #[test]
    fn micro_list_has_subdirs() {
        let mut list = DirMicroListV1 {
            directory_inode_id: 1,
            directory_version: 0,
            entry_count: 0,
            total_name_bytes: 0,
            flags: 0,
            reserved: [0u8; 7],
            entries: Vec::new(),
        };
        assert!(!list.has_subdirs());
        list.set_has_subdirs(true);
        assert!(list.has_subdirs());
        list.set_has_subdirs(false);
        assert!(!list.has_subdirs());
    }

    #[test]
    fn micro_list_total_name_bytes_computation() {
        let e1 = DirMicroEntry {
            name_len: 4,
            inode_id: 1,
            generation: 0,
            kind: 0,
            name: b"file".to_vec(),
        };
        let e2 = DirMicroEntry {
            name_len: 8,
            inode_id: 2,
            generation: 0,
            kind: 0,
            name: b"testfile".to_vec(),
        };
        let list = DirMicroListV1 {
            directory_inode_id: 1,
            directory_version: 0,
            entry_count: 2,
            total_name_bytes: 0,
            flags: 0,
            reserved: [0u8; 7],
            entries: vec![e1, e2],
        };
        assert_eq!(list.compute_total_name_bytes(), 12);
    }

    // -- DirBtreeRootV1 -----------------------------------------------------

    #[test]
    fn btree_root_fixed_size() {
        assert_eq!(DirBtreeRootV1::FIXED_SIZE, 60);
    }

    #[test]
    fn btree_root_valid_magic() {
        let root = DirBtreeRootV1::new(1, 0, LocatorId(42));
        assert!(root.is_valid_magic());
    }

    #[test]
    fn btree_root_invalid_magic() {
        let mut root = DirBtreeRootV1::new(1, 0, LocatorId(42));
        root.magic[0] = b'X';
        assert!(!root.is_valid_magic());
    }

    #[test]
    fn btree_root_defaults() {
        let root = DirBtreeRootV1::new(7, 3, LocatorId(100));
        assert_eq!(root.directory_inode_id, 7);
        assert_eq!(root.directory_version, 3);
        assert_eq!(root.entry_count, 0);
        assert_eq!(root.total_name_bytes, 0);
        assert_eq!(root.depth, 0);
        assert_eq!(root.flags, 0);
    }

    #[test]
    fn btree_root_has_subdirs() {
        let mut root = DirBtreeRootV1::new(1, 0, LocatorId(42));
        assert!(!root.has_subdirs());
        root.flags |= 0x01;
        assert!(root.has_subdirs());
    }

    // -- DirBtreePageHeader -------------------------------------------------

    #[test]
    fn page_header_fixed_size() {
        assert_eq!(DirBtreePageHeader::FIXED_SIZE, 54);
    }

    #[test]
    fn page_header_valid_magic() {
        let h = DirBtreePageHeader::new(DirBtreePageKind::LEAF, 5, 0);
        assert!(h.is_valid_magic());
    }

    #[test]
    fn page_header_invalid_magic() {
        let mut h = DirBtreePageHeader::new(DirBtreePageKind::LEAF, 5, 0);
        h.magic[0] = b'X';
        assert!(!h.is_valid_magic());
    }

    #[test]
    fn page_header_leaf_and_internal() {
        let leaf = DirBtreePageHeader::new(DirBtreePageKind::LEAF, 10, 0);
        assert_eq!(leaf.page_kind, 0);
        assert_eq!(leaf.entry_count, 10);
        assert_eq!(leaf.level, 0);

        let internal = DirBtreePageHeader::new(DirBtreePageKind::INTERNAL, 120, 2);
        assert_eq!(internal.page_kind, 1);
        assert_eq!(internal.entry_count, 120);
        assert_eq!(internal.level, 2);
    }

    // -- DirBtreePageKind ---------------------------------------------------

    #[test]
    fn page_kind_roundtrip() {
        for k in [DirBtreePageKind::LEAF, DirBtreePageKind::INTERNAL] {
            let byte = k.to_u8();
            let decoded = DirBtreePageKind::from_u8(byte);
            assert_eq!(decoded, Some(k));
        }
    }

    #[test]
    fn page_kind_invalid() {
        assert_eq!(DirBtreePageKind::from_u8(2), None);
        assert_eq!(DirBtreePageKind::from_u8(255), None);
    }

    // -- DirBtreeLeafEntry -------------------------------------------------

    #[test]
    fn leaf_entry_wire_size() {
        let entry = DirBtreeLeafEntry {
            name_hash: 0xDEADBEEF,
            name_len: 6,
            inode_id: 1,
            generation: 0,
            kind: 1,
            flags: 0,
            reserved: [0],
            name: b"myfile".to_vec(),
        };
        assert_eq!(entry.wire_size(), 32 + 6);
    }

    // -- DirBtreeInternalEntry ---------------------------------------------

    #[test]
    fn internal_entry_wire_size() {
        let entry = DirBtreeInternalEntry {
            separator_hash: 0xABCD,
            separator_name_len: 4,
            separator_name: b"test".to_vec(),
            child_page_locator: LocatorId(42),
        };
        assert_eq!(entry.wire_size(), 26 + 4);
    }

    // -- DirStorage ---------------------------------------------------------

    #[test]
    fn dir_storage_kind_micro() {
        let list = DirMicroListV1 {
            directory_inode_id: 1,
            directory_version: 0,
            entry_count: 3,
            total_name_bytes: 30,
            flags: 0,
            reserved: [0u8; 7],
            entries: Vec::new(),
        };
        let storage = DirStorage::MicroList(list);
        assert_eq!(storage.kind(), DirStorageKind::MICRO_LIST);
        assert_eq!(storage.entry_count(), 3);
        assert_eq!(storage.total_name_bytes(), 30);
    }

    #[test]
    fn dir_storage_kind_btree() {
        let root = DirBtreeRootV1 {
            magic: *DIR_BTREE_ROOT_MAGIC,
            directory_inode_id: 5,
            directory_version: 2,
            entry_count: 500,
            total_name_bytes: 4000,
            root_page_locator: LocatorId(10),
            depth: 2,
            flags: 0,
            reserved: [0u8; 6],
        };
        let storage = DirStorage::BTree(root);
        assert_eq!(storage.kind(), DirStorageKind::BTREE);
        assert_eq!(storage.entry_count(), 500);
        assert_eq!(storage.total_name_bytes(), 4000);
    }

    #[test]
    fn dir_storage_directory_version() {
        let list = DirMicroListV1 {
            directory_inode_id: 99,
            directory_version: 42,
            entry_count: 0,
            total_name_bytes: 0,
            flags: 0,
            reserved: [0u8; 7],
            entries: Vec::new(),
        };
        assert_eq!(DirStorage::MicroList(list).directory_version(), 42);
    }

    // -- DatasetDirPolicy --------------------------------------------------

    #[test]
    fn default_policy_values() {
        let p = DatasetDirPolicy::DEFAULT;
        assert_eq!(p.dir_micro_max_entries, 50);
        assert_eq!(p.dir_micro_max_name_bytes, 2048);
        assert_eq!(p.dir_btree_downshift_entries, 20);
        assert_eq!(p.dir_btree_downshift_name_bytes, 1024);
    }

    #[test]
    fn policy_should_use_btree_count_threshold() {
        let p = DatasetDirPolicy::DEFAULT;
        assert!(!p.should_use_btree(50, 0));
        assert!(p.should_use_btree(51, 0));
    }

    #[test]
    fn policy_should_use_btree_name_bytes_threshold() {
        let p = DatasetDirPolicy::DEFAULT;
        assert!(!p.should_use_btree(1, 2048));
        assert!(p.should_use_btree(1, 2049));
    }

    #[test]
    fn policy_should_use_btree_both_ok() {
        let p = DatasetDirPolicy::DEFAULT;
        assert!(!p.should_use_btree(10, 100));
        assert!(p.should_use_btree(51, 100));
        assert!(p.should_use_btree(10, 3000));
    }

    #[test]
    fn policy_should_use_micro_from_btree_both_ok() {
        let p = DatasetDirPolicy::DEFAULT;
        assert!(p.should_use_micro_from_btree(20, 1024));
        assert!(p.should_use_micro_from_btree(5, 100));
    }

    #[test]
    fn policy_should_use_micro_from_btree_count_too_high() {
        let p = DatasetDirPolicy::DEFAULT;
        assert!(!p.should_use_micro_from_btree(21, 100));
    }

    #[test]
    fn policy_should_use_micro_from_btree_name_bytes_too_high() {
        let p = DatasetDirPolicy::DEFAULT;
        assert!(!p.should_use_micro_from_btree(10, 1025));
    }

    #[test]
    fn policy_hysteresis_band() {
        let p = DatasetDirPolicy::DEFAULT;
        assert!(!p.should_use_btree(30, 100));
        assert!(!p.should_use_micro_from_btree(30, 100));
    }

    #[test]
    fn policy_custom_thresholds() {
        let p = DatasetDirPolicy {
            dir_micro_max_entries: 100,
            dir_micro_max_name_bytes: 4096,
            dir_btree_downshift_entries: 40,
            dir_btree_downshift_name_bytes: 2048,
        };
        assert!(!p.should_use_btree(100, 4096));
        assert!(p.should_use_btree(101, 0));
        assert!(p.should_use_micro_from_btree(40, 2048));
        assert!(!p.should_use_micro_from_btree(41, 100));
    }

    // -- Convenience free functions ----------------------------------------

    #[test]
    fn free_should_use_btree() {
        assert!(!should_use_btree(50, 2048));
        assert!(should_use_btree(51, 0));
        assert!(should_use_btree(0, 2049));
    }

    #[test]
    fn free_should_use_micro_from_btree() {
        assert!(should_use_micro_from_btree(20, 1024));
        assert!(should_use_micro_from_btree(0, 0));
        assert!(!should_use_micro_from_btree(21, 0));
        assert!(!should_use_micro_from_btree(0, 1025));
    }

    // -- DirCookie ----------------------------------------------------------

    #[test]
    fn cookie_encode_micro_roundtrip() {
        let raw = DirCookie::encode_micro(5);
        let c = DirCookie(raw);
        assert!(c.is_micro());
        assert!(!c.is_btree());
        assert_eq!(c.as_micro_entry_index(), Some(5));
        assert_eq!(c.as_btree_indices(), None);
    }

    #[test]
    fn cookie_encode_btree_roundtrip() {
        let raw = DirCookie::encode_btree(3, 7);
        let c = DirCookie(raw);
        assert!(c.is_btree());
        assert!(!c.is_micro());
        assert_eq!(c.as_micro_entry_index(), None);
        assert_eq!(c.as_btree_indices(), Some((3, 7)));
    }

    #[test]
    fn cookie_encode_micro_zero() {
        let c = DirCookie(DirCookie::encode_micro(0));
        assert!(c.is_micro());
        assert_eq!(c.as_micro_entry_index(), Some(0));
    }

    #[test]
    fn cookie_encode_btree_zero() {
        let c = DirCookie(DirCookie::encode_btree(0, 0));
        assert!(c.is_btree());
        assert_eq!(c.as_btree_indices(), Some((0, 0)));
    }

    #[test]
    fn cookie_start_is_micro_zero() {
        assert_eq!(DirCookie::START.0, 0);
        assert!(DirCookie::START.is_micro());
        assert_eq!(DirCookie::START.as_micro_entry_index(), Some(0));
    }

    #[test]
    fn cookie_encode_btree_large_page_index() {
        let c = DirCookie(DirCookie::encode_btree(u16::MAX, u16::MAX));
        assert!(c.is_btree());
        assert_eq!(c.as_btree_indices(), Some((u16::MAX, u16::MAX)));
    }

    #[test]
    fn cookie_encode_micro_large_index() {
        let c = DirCookie(DirCookie::encode_micro(42_000));
        assert!(c.is_micro());
        assert_eq!(c.as_micro_entry_index(), Some(42_000));
    }

    #[test]
    fn cookie_kind_discrimination() {
        assert_eq!(DirCookie::START.kind(), 0);
        assert_eq!(DirCookie(DirCookie::encode_micro(999)).kind(), 0);
        assert_eq!(DirCookie(DirCookie::encode_btree(0, 0)).kind(), 1);
        assert_eq!(DirCookie(DirCookie::encode_btree(100, 200)).kind(), 1);
    }

    #[test]
    fn cookie_display() {
        let c0 = DirCookie::START;
        assert!(c0.to_string().contains("Micro"));
        assert!(c0.to_string().contains("index=0"));

        let c1 = DirCookie(DirCookie::encode_btree(5, 12));
        assert!(c1.to_string().contains("BTree"));
        assert!(c1.to_string().contains("page=5"));
        assert!(c1.to_string().contains("entry=12"));
    }

    #[test]
    fn cookie_encode_micro_at_boundary() {
        let raw = DirCookie::encode_micro(u32::MAX);
        let c = DirCookie(raw);
        assert!(c.is_micro());
        assert_eq!(c.as_micro_entry_index(), Some(u32::MAX));
    }

    // -- Feature name constant ---------------------------------------------

    #[test]
    fn feature_name_constant_correct() {
        assert_eq!(
            FEATURE_POLYMORPHIC_DIR_INDEX,
            "org.tidefs:polymorphic_dir_index"
        );
    }

    // -- Magic constants ----------------------------------------------------

    #[test]
    fn dir_btree_root_magic_is_dirb() {
        assert_eq!(DIR_BTREE_ROOT_MAGIC, b"DIRB");
    }

    #[test]
    fn dir_btree_page_magic_is_dirp() {
        assert_eq!(DIR_BTREE_PAGE_MAGIC, b"DIRP");
    }
}
