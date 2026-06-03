#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Authority type definitions for the polymorphic xattr storage.
//!
//! Implements the type registry from
//! [`docs/POLYMORPHIC_XATTR_STORAGE_DESIGN.md`] with two canonical
//! xattr representations (`XattrBundleV1` inline O(n) and
//! `XattrBtreeRootV1` external B+tree O(log n)), switching thresholds
//! with hysteresis, and dataset-level `DatasetXattrPolicy`.
//!
//! This crate covers Phase 1 (types + threshold logic + magic validation)
//! of the design spec. The B+tree implementation and migration engine
//! are tracked by Review debt TFR-002/TFR-013.
//!
//! The `alloc` feature gates types that require heap allocation
//! (`XattrBundleV1`, `XattrInlineEntry`, `XattrBtreeLeafEntry`,
//! `XattrBtreeInternalEntry`). Fixed-size types (`XattrBtreeRootV1`,
//! `XattrBtreePageHeader`, `DatasetXattrPolicy`, `XattrStorageKind`,
//! `LocatorId`) are always available.
//!
//! [`docs/POLYMORPHIC_XATTR_STORAGE_DESIGN.md`]:
//! https://forgejo/forgeadmin/tidefs/docs/POLYMORPHIC_XATTR_STORAGE_DESIGN.md

use core::fmt;

#[cfg(feature = "alloc")]
extern crate alloc;

// ---------------------------------------------------------------------------
// BLAKE3-256 checksum type
// ---------------------------------------------------------------------------

/// A 32-byte BLAKE3-256 checksum.
pub type Blake3Checksum = [u8; 32];

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
// XattrStorageKind — discriminator byte for xattr representation
// ---------------------------------------------------------------------------

/// Identifies which xattr representation (`XattrStorage` variant) is
/// stored in the inode's xattr payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct XattrStorageKind(pub u8);

impl XattrStorageKind {
    /// Xattrs stored inline as `XattrBundleV1`.
    pub const INLINE: XattrStorageKind = XattrStorageKind(0);
    /// Xattrs stored externally as B+tree with `XattrBtreeRootV1`.
    pub const EXTERNAL: XattrStorageKind = XattrStorageKind(1);

    /// Decode from a wire byte. Returns `None` for unknown values.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(XattrStorageKind::INLINE),
            1 => Some(XattrStorageKind::EXTERNAL),
            _ => None,
        }
    }

    /// Encode to a wire byte.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self.0
    }

    /// Returns `true` if this is the inline representation.
    #[must_use]
    pub const fn is_inline(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if this is the external B-tree representation.
    #[must_use]
    pub const fn is_external(self) -> bool {
        self.0 == 1
    }
}

impl fmt::Display for XattrStorageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => f.write_str("Inline"),
            1 => f.write_str("External"),
            _ => f.write_str("Unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// Magic bytes
// ---------------------------------------------------------------------------

/// Magic bytes for `XattrBundleV1`.
pub const XATTR_BUNDLE_MAGIC: &[u8; 4] = b"XATB";
/// Magic bytes for `XattrBtreeRootV1`.
pub const XATTR_BTREE_ROOT_MAGIC: &[u8; 4] = b"XATR";
/// Magic bytes for `XattrBtreePageHeader`.
pub const XATTR_BTREE_PAGE_MAGIC: &[u8; 4] = b"XATP";

// ---------------------------------------------------------------------------
// XattrBundleV1 — inline xattr storage (O(n))
// ---------------------------------------------------------------------------

/// Inline xattr storage record embedded in the inode TLV tail.
///
/// Fixed-size prefix: 4 + 2 + 4 + 1 + 5 = 16 bytes, followed by
/// variable-length `entry_count` entries.
///
/// Requires `alloc` feature for heap allocation of the `entries` vector.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XattrBundleV1 {
    /// Magic: `b"XATB"`.
    pub magic: [u8; 4],
    /// Number of (name, value) pairs.
    pub entry_count: u16,
    /// Sum of all value lengths (for threshold checks).
    pub total_value_bytes: u32,
    /// Bit 0: contains_acl, bits 1-7: reserved.
    pub flags: u8,
    /// Reserved for alignment / future use.
    pub reserved: [u8; 5],
    /// Variable-length entries; length == entry_count.
    pub entries: alloc::vec::Vec<XattrInlineEntry>,
}

#[cfg(feature = "alloc")]
impl XattrBundleV1 {
    /// Fixed prefix size in bytes (= 16).
    pub const FIXED_PREFIX_SIZE: usize = 16;

    /// Create a new empty bundle.
    #[must_use]
    pub const fn new(flags: u8) -> Self {
        XattrBundleV1 {
            magic: *XATTR_BUNDLE_MAGIC,
            entry_count: 0,
            total_value_bytes: 0,
            flags: flags & 0x01,
            reserved: [0u8; 5],
            entries: alloc::vec::Vec::new(),
        }
    }

    /// Returns `true` if the magic bytes are valid.
    #[must_use]
    pub fn is_valid_magic(&self) -> bool {
        self.magic == *XATTR_BUNDLE_MAGIC
    }

    /// Returns `true` if the `contains_acl` flag is set.
    #[must_use]
    pub fn contains_acl(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Returns the total number of xattr entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entry_count as usize
    }

    /// Returns `true` if the bundle is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    /// Add an entry to the bundle, updating totals.
    pub fn add_entry(&mut self, name: alloc::vec::Vec<u8>, value: alloc::vec::Vec<u8>) {
        let value_len = value.len() as u32;
        self.total_value_bytes += value_len;
        self.entry_count += 1;
        self.entries.push(XattrInlineEntry {
            name_len: name.len() as u16,
            value_len,
            name,
            value,
        });
    }
}

/// A single (name, value) pair within an `XattrBundleV1`.
///
/// Fixed per-entry overhead: 2 + 4 = 6 bytes + name_len + value_len.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XattrInlineEntry {
    /// Length of the name in bytes.
    pub name_len: u16,
    /// Length of the value in bytes.
    pub value_len: u32,
    /// Name bytes (opaque, e.g. `"user.myattr"`).
    pub name: alloc::vec::Vec<u8>,
    /// Value bytes (opaque).
    pub value: alloc::vec::Vec<u8>,
}

#[cfg(feature = "alloc")]
impl XattrInlineEntry {
    /// Fixed per-entry overhead in bytes (= 6).
    pub const FIXED_OVERHEAD: usize = 6;

    /// Create a new entry.
    #[must_use]
    pub fn new(name: alloc::vec::Vec<u8>, value: alloc::vec::Vec<u8>) -> Self {
        let name_len = name.len() as u16;
        let value_len = value.len() as u32;
        XattrInlineEntry {
            name_len,
            value_len,
            name,
            value,
        }
    }
}

// ---------------------------------------------------------------------------
// XattrBtreeRootV1 — external B+tree xattr root (O(log n))
// ---------------------------------------------------------------------------

/// B+tree root stored as the inode's xattr payload when
/// `xattr_storage_kind == 1`.
///
/// Total fixed size: 4 + 8 + 8 + 8 + 1 + 1 + 6 = 36 bytes (+ padding = 40).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct XattrBtreeRootV1 {
    /// Magic: `b"XATR"`.
    pub magic: [u8; 4],
    /// Total xattr count across all leaf pages.
    pub entry_count: u64,
    /// Sum of all value lengths (for threshold checks).
    pub total_value_bytes: u64,
    /// Points to the B+tree root page in the locator table.
    pub root_page_locator: LocatorId,
    /// Depth: 0 = single leaf, 1+ = internal levels.
    pub depth: u8,
    /// Bit 0: contains_acl, bits 1-7: reserved.
    pub flags: u8,
    /// Reserved for alignment / future use.
    pub reserved: [u8; 6],
}

impl XattrBtreeRootV1 {
    /// Total fixed size in bytes (= 44).
    pub const FIXED_SIZE: usize = 40;

    /// Create a new root with the given parameters.
    #[must_use]
    pub const fn new(
        entry_count: u64,
        total_value_bytes: u64,
        root_page_locator: LocatorId,
    ) -> Self {
        XattrBtreeRootV1 {
            magic: *XATTR_BTREE_ROOT_MAGIC,
            entry_count,
            total_value_bytes,
            root_page_locator,
            depth: 0,
            flags: 0,
            reserved: [0u8; 6],
        }
    }

    /// Returns `true` if the magic bytes are valid.
    #[must_use]
    pub const fn is_valid_magic(&self) -> bool {
        self.magic[0] == b'X'
            && self.magic[1] == b'A'
            && self.magic[2] == b'T'
            && self.magic[3] == b'R'
    }

    /// Returns `true` if the `contains_acl` flag is set.
    #[must_use]
    pub const fn contains_acl(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Returns `true` if the tree is empty (no entries).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entry_count == 0
    }
}

// ---------------------------------------------------------------------------
// XattrBtreePageHeader — common header for all B+tree pages
// ---------------------------------------------------------------------------

/// Page kind discriminator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct XattrBtreePageKind(pub u8);

impl XattrBtreePageKind {
    /// Leaf page.
    pub const LEAF: XattrBtreePageKind = XattrBtreePageKind(0);
    /// Internal (non-leaf) page.
    pub const INTERNAL: XattrBtreePageKind = XattrBtreePageKind(1);

    /// Decode from a wire byte.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(XattrBtreePageKind::LEAF),
            1 => Some(XattrBtreePageKind::INTERNAL),
            _ => None,
        }
    }

    /// Encode to a wire byte.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self.0
    }

    /// Returns `true` if this is a leaf page.
    #[must_use]
    pub const fn is_leaf(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if this is an internal page.
    #[must_use]
    pub const fn is_internal(self) -> bool {
        self.0 == 1
    }
}

impl fmt::Display for XattrBtreePageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => f.write_str("Leaf"),
            1 => f.write_str("Internal"),
            _ => f.write_str("Unknown"),
        }
    }
}

/// Common header for all xattr B+tree pages (leaf and internal).
///
/// Total fixed size: 4 + 1 + 2 + 1 + 32 + 14 = 54 bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct XattrBtreePageHeader {
    /// Magic: `b"XATP"`.
    pub magic: [u8; 4],
    /// Discriminator: 0 = leaf, 1 = internal.
    pub page_kind: XattrBtreePageKind,
    /// Number of entries in this page.
    pub entry_count: u16,
    /// Level: 0 = leaf, 1+ = internal.
    pub level: u8,
    /// BLAKE3-256 checksum over the page content.
    pub checksum: Blake3Checksum,
    /// Reserved for alignment / future use.
    pub reserved: [u8; 14],
}

impl XattrBtreePageHeader {
    /// Total fixed size in bytes (= 54).
    pub const FIXED_SIZE: usize = 54;

    /// Create a new header with the given page kind, level, and checksum.
    #[must_use]
    pub const fn new(page_kind: XattrBtreePageKind, level: u8, checksum: Blake3Checksum) -> Self {
        XattrBtreePageHeader {
            magic: *XATTR_BTREE_PAGE_MAGIC,
            page_kind,
            entry_count: 0,
            level,
            checksum,
            reserved: [0u8; 14],
        }
    }

    /// Returns `true` if the magic bytes are valid.
    #[must_use]
    pub const fn is_valid_magic(&self) -> bool {
        self.magic[0] == b'X'
            && self.magic[1] == b'A'
            && self.magic[2] == b'T'
            && self.magic[3] == b'P'
    }
}

// ---------------------------------------------------------------------------
// XattrBtreeLeafEntry — leaf page entry
// ---------------------------------------------------------------------------

/// A single (name, value) entry in a leaf page of the xattr B+tree.
///
/// Fixed per-entry overhead: 2 + 4 + 1 + 1 = 8 bytes + name_len + value_len.
///
/// Requires `alloc` feature.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XattrBtreeLeafEntry {
    /// Length of the name in bytes.
    pub name_len: u16,
    /// Length of the value in bytes.
    pub value_len: u32,
    /// Per-xattr flags (e.g., bit 0: trusted namespace).
    pub flags: u8,
    /// Reserved for alignment.
    pub reserved: u8,
    /// Name bytes (opaque).
    pub name: alloc::vec::Vec<u8>,
    /// Value bytes (opaque).
    pub value: alloc::vec::Vec<u8>,
}

#[cfg(feature = "alloc")]
impl XattrBtreeLeafEntry {
    /// Fixed per-entry overhead in bytes (= 8).
    pub const FIXED_OVERHEAD: usize = 8;

    /// Create a new leaf entry.
    #[must_use]
    pub fn new(name: alloc::vec::Vec<u8>, value: alloc::vec::Vec<u8>, flags: u8) -> Self {
        let name_len = name.len() as u16;
        let value_len = value.len() as u32;
        XattrBtreeLeafEntry {
            name_len,
            value_len,
            flags,
            reserved: 0,
            name,
            value,
        }
    }
}

// ---------------------------------------------------------------------------
// XattrBtreeInternalEntry — internal page entry (separator + child pointer)
// ---------------------------------------------------------------------------

/// A separator entry in an internal page of the xattr B+tree.
///
/// Fixed overhead: 2 + name_len + 16 = 18 bytes + name_len.
///
/// Requires `alloc` feature.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XattrBtreeInternalEntry {
    /// Length of the separator name in bytes.
    pub name_len: u16,
    /// Separator key (prefix of child subtree).
    pub name: alloc::vec::Vec<u8>,
    /// Points to the child page in the locator table.
    pub child_page_locator: LocatorId,
}

#[cfg(feature = "alloc")]
impl XattrBtreeInternalEntry {
    /// Fixed per-entry overhead in bytes (= 18), excluding name_len.
    pub const FIXED_OVERHEAD: usize = 18;

    /// Create a new internal entry.
    #[must_use]
    pub fn new(name: alloc::vec::Vec<u8>, child_page_locator: LocatorId) -> Self {
        let name_len = name.len() as u16;
        XattrBtreeInternalEntry {
            name_len,
            name,
            child_page_locator,
        }
    }
}

// ---------------------------------------------------------------------------
// XattrStorage — tagged union of the two canonical representations
// ---------------------------------------------------------------------------

/// The xattr storage representation for a single inode.
///
/// Exactly one variant is active at any time, determined by
/// `XattrStorageKind` in the inode record.
///
/// Requires `alloc` feature.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum XattrStorage {
    /// Inline storage via `XattrBundleV1` (count <= threshold, bytes <= threshold).
    Inline(XattrBundleV1),
    /// External storage via B+tree rooted at `XattrBtreeRootV1`.
    External(XattrBtreeRootV1),
}

#[cfg(feature = "alloc")]
impl XattrStorage {
    /// Returns the storage kind discriminator.
    #[must_use]
    pub fn kind(&self) -> XattrStorageKind {
        match self {
            XattrStorage::Inline(_) => XattrStorageKind::INLINE,
            XattrStorage::External(_) => XattrStorageKind::EXTERNAL,
        }
    }

    /// Returns the total entry count regardless of representation.
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        match self {
            XattrStorage::Inline(bundle) => bundle.entry_count as u64,
            XattrStorage::External(root) => root.entry_count,
        }
    }

    /// Returns the total value bytes regardless of representation.
    #[must_use]
    pub fn total_value_bytes(&self) -> u64 {
        match self {
            XattrStorage::Inline(bundle) => bundle.total_value_bytes as u64,
            XattrStorage::External(root) => root.total_value_bytes,
        }
    }

    /// Returns `true` if the `contains_acl` hint is set.
    #[must_use]
    pub fn contains_acl(&self) -> bool {
        match self {
            XattrStorage::Inline(bundle) => bundle.contains_acl(),
            XattrStorage::External(root) => root.contains_acl(),
        }
    }
}

// ---------------------------------------------------------------------------
// DatasetXattrPolicy — dataset-level switching thresholds
// ---------------------------------------------------------------------------

/// Dataset-level xattr storage policy governing inline <-> tree transitions.
///
/// Stored in the dataset superblock. Changing thresholds on an existing
/// dataset takes effect on the next xattr mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DatasetXattrPolicy {
    /// Maximum inline entries before the B-tree is considered.
    pub xattr_inline_max_count: u16,
    /// Maximum total inline value bytes before the B-tree is considered.
    pub xattr_inline_max_bytes: u32,
    /// Maximum entries before tree can downshift to inline (hysteresis).
    pub xattr_tree_downshift_count: u16,
    /// Maximum total value bytes before tree can downshift to inline (hysteresis).
    pub xattr_tree_downshift_bytes: u32,
}

impl DatasetXattrPolicy {
    /// Sensible defaults for general-purpose datasets.
    pub const DEFAULT: DatasetXattrPolicy = DatasetXattrPolicy {
        xattr_inline_max_count: 16,
        xattr_inline_max_bytes: 4096,
        xattr_tree_downshift_count: 8,
        xattr_tree_downshift_bytes: 2048,
    };

    /// Create a new policy with explicit thresholds.
    #[must_use]
    pub const fn new(
        inline_max_count: u16,
        inline_max_bytes: u32,
        downshift_count: u16,
        downshift_bytes: u32,
    ) -> Self {
        DatasetXattrPolicy {
            xattr_inline_max_count: inline_max_count,
            xattr_inline_max_bytes: inline_max_bytes,
            xattr_tree_downshift_count: downshift_count,
            xattr_tree_downshift_bytes: downshift_bytes,
        }
    }
}

// ---------------------------------------------------------------------------
// Switching threshold logic
// ---------------------------------------------------------------------------

/// Returns `true` if xattr storage should use the B-tree representation
/// based on the current count and total value bytes.
///
/// The switch is triggered when **either** threshold is exceeded:
/// `count > inline_max_count OR total_bytes > inline_max_bytes`.
#[must_use]
pub const fn should_use_tree(
    count: u64,
    total_value_bytes: u64,
    policy: &DatasetXattrPolicy,
) -> bool {
    count > policy.xattr_inline_max_count as u64
        || total_value_bytes > policy.xattr_inline_max_bytes as u64
}

/// Returns `true` if xattr storage should switch from the B-tree back to
/// inline representation based on the current count and total value bytes.
///
/// The downshift requires **both** thresholds to be met:
/// `count <= downshift_count AND total_bytes <= downshift_bytes`.
///
/// This hysteresis prevents oscillation at the boundary.
#[must_use]
pub const fn should_use_inline_from_tree(
    count: u64,
    total_value_bytes: u64,
    policy: &DatasetXattrPolicy,
) -> bool {
    count <= policy.xattr_tree_downshift_count as u64
        && total_value_bytes <= policy.xattr_tree_downshift_bytes as u64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- XattrStorageKind --

    #[test]
    fn storage_kind_constants() {
        assert_eq!(XattrStorageKind::INLINE.to_u8(), 0);
        assert_eq!(XattrStorageKind::EXTERNAL.to_u8(), 1);
        assert!(XattrStorageKind::INLINE.is_inline());
        assert!(!XattrStorageKind::INLINE.is_external());
        assert!(XattrStorageKind::EXTERNAL.is_external());
        assert!(!XattrStorageKind::EXTERNAL.is_inline());
    }

    #[test]
    fn storage_kind_from_u8_roundtrip() {
        for v in [0u8, 1u8] {
            let kind = XattrStorageKind::from_u8(v).unwrap();
            assert_eq!(kind.to_u8(), v);
        }
    }

    #[test]
    fn storage_kind_from_u8_invalid() {
        assert!(XattrStorageKind::from_u8(2).is_none());
        assert!(XattrStorageKind::from_u8(255).is_none());
    }

    // -- Magic bytes --

    #[test]
    fn magic_bytes_match_spec() {
        assert_eq!(XATTR_BUNDLE_MAGIC, b"XATB");
        assert_eq!(XATTR_BTREE_ROOT_MAGIC, b"XATR");
        assert_eq!(XATTR_BTREE_PAGE_MAGIC, b"XATP");
    }

    // -- LocatorId --

    #[test]
    fn locator_id_empty() {
        assert!(LocatorId::EMPTY.is_empty());
        assert!(!LocatorId(42).is_empty());
    }

    // -- XattrBundleV1 --

    #[cfg(feature = "alloc")]
    #[test]
    fn bundle_new_empty() {
        let b = XattrBundleV1::new(0);
        assert!(b.is_valid_magic());
        assert_eq!(b.entry_count, 0);
        assert_eq!(b.total_value_bytes, 0);
        assert!(b.is_empty());
        assert_eq!(b.len(), 0);
        assert!(!b.contains_acl());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn bundle_contains_acl_flag() {
        let b = XattrBundleV1::new(0x01);
        assert!(b.contains_acl());
        let b2 = XattrBundleV1::new(0x03);
        assert!(b2.contains_acl()); // only bit 0 matters
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn bundle_add_entry() {
        let mut b = XattrBundleV1::new(0);
        b.add_entry(alloc::vec![b'u', b'x'], alloc::vec![1, 2, 3]);
        assert_eq!(b.entry_count, 1);
        assert_eq!(b.total_value_bytes, 3);
        assert!(!b.is_empty());
        assert_eq!(b.len(), 1);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn bundle_add_multiple_entries() {
        let mut b = XattrBundleV1::new(0x01);
        b.add_entry(alloc::vec![b'a'], alloc::vec![1, 2]);
        b.add_entry(alloc::vec![b'b', b'b'], alloc::vec![3, 4, 5, 6]);
        assert_eq!(b.entry_count, 2);
        assert_eq!(b.total_value_bytes, 6);
        assert_eq!(b.len(), 2);
    }

    // -- XattrInlineEntry --

    #[cfg(feature = "alloc")]
    #[test]
    fn inline_entry_construction() {
        let e = XattrInlineEntry::new(alloc::vec![b'k', b'e', b'y'], alloc::vec![b'v', b'a', b'l']);
        assert_eq!(e.name_len, 3);
        assert_eq!(e.value_len, 3);
    }

    // -- XattrBtreeRootV1 --

    #[test]
    fn btree_root_new() {
        let root = XattrBtreeRootV1::new(100, 5000, LocatorId(42));
        assert!(root.is_valid_magic());
        assert_eq!(root.entry_count, 100);
        assert_eq!(root.total_value_bytes, 5000);
        assert_eq!(root.root_page_locator, LocatorId(42));
        assert_eq!(root.depth, 0);
        assert!(!root.contains_acl());
        assert!(!root.is_empty());
    }

    #[test]
    fn btree_root_size() {
        assert_eq!(core::mem::size_of::<XattrBtreeRootV1>(), 40);
    }

    #[test]
    fn btree_root_empty() {
        let root = XattrBtreeRootV1::new(0, 0, LocatorId::EMPTY);
        assert!(root.is_empty());
    }

    // -- XattrBtreePageHeader --

    #[test]
    fn page_header_new() {
        let csum: Blake3Checksum = [0xAB; 32];
        let hdr = XattrBtreePageHeader::new(XattrBtreePageKind::LEAF, 0, csum);
        assert!(hdr.is_valid_magic());
        assert_eq!(hdr.page_kind.to_u8(), 0);
        assert_eq!(hdr.level, 0);
        assert_eq!(hdr.checksum, csum);
    }

    #[test]
    fn page_header_size() {
        assert_eq!(core::mem::size_of::<XattrBtreePageHeader>(), 54);
    }

    // -- XattrBtreePageKind --

    #[test]
    fn page_kind_consts() {
        assert!(XattrBtreePageKind::LEAF.is_leaf());
        assert!(!XattrBtreePageKind::LEAF.is_internal());
        assert!(XattrBtreePageKind::INTERNAL.is_internal());
        assert!(!XattrBtreePageKind::INTERNAL.is_leaf());
    }

    #[test]
    fn page_kind_roundtrip() {
        for v in [0u8, 1u8] {
            let kind = XattrBtreePageKind::from_u8(v).unwrap();
            assert_eq!(kind.to_u8(), v);
        }
    }

    #[test]
    fn page_kind_invalid() {
        assert!(XattrBtreePageKind::from_u8(2).is_none());
    }

    // -- XattrBtreeLeafEntry --

    #[cfg(feature = "alloc")]
    #[test]
    fn leaf_entry_construction() {
        let e = XattrBtreeLeafEntry::new(alloc::vec![b'x'], alloc::vec![b'y'], 0x02);
        assert_eq!(e.name_len, 1);
        assert_eq!(e.value_len, 1);
        assert_eq!(e.flags, 0x02);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn leaf_entry_fixed_overhead() {
        assert_eq!(XattrBtreeLeafEntry::FIXED_OVERHEAD, 8);
    }

    // -- XattrBtreeInternalEntry --

    #[cfg(feature = "alloc")]
    #[test]
    fn internal_entry_construction() {
        let e = XattrBtreeInternalEntry::new(alloc::vec![b's', b'e', b'p'], LocatorId(99));
        assert_eq!(e.name_len, 3);
        assert_eq!(e.child_page_locator, LocatorId(99));
    }

    // -- XattrStorage --

    #[cfg(feature = "alloc")]
    #[test]
    fn storage_inline_kind() {
        let b = XattrBundleV1::new(0);
        let s = XattrStorage::Inline(b);
        assert_eq!(s.kind(), XattrStorageKind::INLINE);
        assert_eq!(s.entry_count(), 0);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn storage_external_kind() {
        let r = XattrBtreeRootV1::new(42, 100, LocatorId(7));
        let s = XattrStorage::External(r);
        assert_eq!(s.kind(), XattrStorageKind::EXTERNAL);
        assert_eq!(s.entry_count(), 42);
    }

    // -- DatasetXattrPolicy --

    #[test]
    fn policy_defaults() {
        let p = DatasetXattrPolicy::DEFAULT;
        assert_eq!(p.xattr_inline_max_count, 16);
        assert_eq!(p.xattr_inline_max_bytes, 4096);
        assert_eq!(p.xattr_tree_downshift_count, 8);
        assert_eq!(p.xattr_tree_downshift_bytes, 2048);
    }

    #[test]
    fn policy_custom() {
        let p = DatasetXattrPolicy::new(32, 8192, 12, 3072);
        assert_eq!(p.xattr_inline_max_count, 32);
        assert_eq!(p.xattr_inline_max_bytes, 8192);
        assert_eq!(p.xattr_tree_downshift_count, 12);
        assert_eq!(p.xattr_tree_downshift_bytes, 3072);
    }

    // -- Switching threshold logic --

    #[test]
    fn should_use_tree_exceeds_count() {
        let p = DatasetXattrPolicy::DEFAULT;
        assert!(should_use_tree(17, 0, &p));
    }

    #[test]
    fn should_use_tree_exceeds_bytes() {
        let p = DatasetXattrPolicy::DEFAULT;
        assert!(should_use_tree(1, 4097, &p));
    }

    #[test]
    fn should_use_tree_within_bounds() {
        let p = DatasetXattrPolicy::DEFAULT;
        assert!(!should_use_tree(16, 4096, &p));
        assert!(!should_use_tree(0, 0, &p));
        assert!(!should_use_tree(10, 2000, &p));
    }

    #[test]
    fn should_use_inline_from_tree_hysteresis() {
        let p = DatasetXattrPolicy::DEFAULT;
        // In the band 9-16, tree -> inline refuses
        assert!(!should_use_inline_from_tree(9, 1000, &p));
        assert!(!should_use_inline_from_tree(16, 4096, &p));
        // Below the downshift thresholds
        assert!(should_use_inline_from_tree(8, 1000, &p));
        assert!(should_use_inline_from_tree(0, 0, &p));
        // Bytes exceed even if count is low
        assert!(!should_use_inline_from_tree(3, 3000, &p));
    }

    #[test]
    fn oscillation_prevention_band() {
        let p = DatasetXattrPolicy::DEFAULT;
        // At 17 entries, inline -> tree IS required (17 > 16)
        assert!(should_use_tree(17, 0, &p));
        // At 9 entries, inline -> tree refuses (9 <= 16)
        assert!(!should_use_tree(9, 0, &p));
        // And tree -> inline also refuses (9 > 8, hysteresis)
        assert!(!should_use_inline_from_tree(9, 0, &p));
        // Both transitions block in band 9-16: no oscillation possible
    }
}
