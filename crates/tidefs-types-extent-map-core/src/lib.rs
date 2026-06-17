#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use core::fmt;

pub const EXTENT_MAP_SPEC: &str = "tidefs-extent-map-v1-design-1285";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ExtentId(pub u64);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ExtentRev(pub u64);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct LocatorId(pub u64);

impl LocatorId {
    pub const NONE: LocatorId = LocatorId(0);
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }
    #[must_use]
    pub const fn is_some(self) -> bool {
        self.0 != 0
    }
}

impl fmt::Display for ExtentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

impl fmt::Display for LocatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct LocatorTableId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ExtentType {
    Hole = 0,
    Unwritten = 1,
    Data = 2,
}

impl ExtentType {
    #[must_use]
    pub const fn consumes_space(self) -> bool {
        matches!(self, ExtentType::Unwritten | ExtentType::Data)
    }
    #[must_use]
    pub const fn reads_zero(self) -> bool {
        matches!(self, ExtentType::Hole | ExtentType::Unwritten)
    }
    #[must_use]
    pub const fn is_data(self) -> bool {
        matches!(self, ExtentType::Data)
    }
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ExtentType::Hole => "hole",
            ExtentType::Unwritten => "unwritten",
            ExtentType::Data => "data",
        }
    }
}

/// Canonical tristate extent classification (HOLE/UNWRITTEN/DATA).
/// Alias for [`ExtentType`]; `ExtentState` is the preferred FEATURE_MATRIX name.
pub type ExtentState = ExtentType;
impl fmt::Display for ExtentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtentLifecycleState {
    Ingest,
    BaseComplete,
    Dead,
    Freed,
}

impl ExtentLifecycleState {
    #[must_use]
    pub const fn state_name(self) -> &'static str {
        match self {
            ExtentLifecycleState::Ingest => "ingest",
            ExtentLifecycleState::BaseComplete => "base_complete",
            ExtentLifecycleState::Dead => "dead",
            ExtentLifecycleState::Freed => "freed",
        }
    }
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, ExtentLifecycleState::Freed)
    }
    #[must_use]
    pub const fn is_readable(self) -> bool {
        matches!(
            self,
            ExtentLifecycleState::BaseComplete | ExtentLifecycleState::Dead
        )
    }
}

impl fmt::Display for ExtentLifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.state_name())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalExtentRef {
    pub segment_id: u64,
    pub grain_offset: u64,
    pub grain_count: u64,
}

impl PhysicalExtentRef {
    #[must_use]
    pub const fn new(segment_id: u64, grain_offset: u64, grain_count: u64) -> Self {
        Self {
            segment_id,
            grain_offset,
            grain_count,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtentMapEntryV1 {
    pub logical_offset: u64,
    pub length: u64,
    pub extent_type: ExtentType,
    pub physical: Option<PhysicalExtentRef>,
    pub committed_commit_group: u64,
    pub payload_digest: [u8; 32],
    pub compression: u8,
    pub encrypted: bool,
    pub extent_id: ExtentId,
    pub reserved: [u8; 6],
}

impl ExtentMapEntryV1 {
    #[must_use]
    pub const fn new_hole(logical_offset: u64, length: u64) -> Self {
        Self {
            logical_offset,
            length,
            extent_type: ExtentType::Hole,
            physical: None,
            committed_commit_group: 0,
            payload_digest: [0u8; 32],
            compression: 0,
            encrypted: false,
            extent_id: ExtentId(0),
            reserved: [0u8; 6],
        }
    }
    #[must_use]
    pub const fn byte_range(&self) -> core::ops::Range<u64> {
        self.logical_offset..self.logical_offset + self.length
    }
    #[must_use]
    pub const fn intersects(&self, offset: u64, len: u64) -> bool {
        let end = match self.logical_offset.checked_add(self.length) {
            Some(v) => v,
            None => return false,
        };
        let other_end = match offset.checked_add(len) {
            Some(v) => v,
            None => return false,
        };
        self.logical_offset < other_end && offset < end
    }
    #[must_use]
    pub const fn is_hole(&self) -> bool {
        matches!(self.extent_type, ExtentType::Hole)
    }
    #[must_use]
    pub const fn end_offset(&self) -> u64 {
        self.logical_offset + self.length
    }
}

impl fmt::Display for ExtentMapEntryV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExtentMapEntryV1(off={} len={} type={})",
            self.logical_offset, self.length, self.extent_type
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtentMapEntryV2 {
    pub logical_offset: u64,
    pub length: u64,
    pub extent_kind: u8,
    pub flags: u8,
    pub locator_id: LocatorId,
    pub checksum: [u8; 32],
    pub birth_commit_group: u64,
    pub reserved: [u8; 15],
}

impl ExtentMapEntryV2 {
    pub const KIND_DATA: u8 = 0;
    pub const KIND_UNWRITTEN: u8 = 1;

    /// A data extent whose content checksum and birth commit group are not yet
    /// final.  Reads must treat these ranges as containing real data (they
    /// consume space and are seekable), but scrub/rebuild/relocation must not
    /// treat the zero checksum as verified content integrity.
    pub const KIND_PENDING_DATA: u8 = 2;

    /// Explicit hole extent.  Used in test helpers and for polymorphic map
    /// hole entries.  Not stored in production extent maps (holes are
    /// implicit gaps).
    pub const KIND_HOLE: u8 = 3;

    #[must_use]
    pub fn new_data(
        logical_offset: u64,
        length: u64,
        locator_id: LocatorId,
        checksum: [u8; 32],
        birth_commit_group: u64,
    ) -> Self {
        Self {
            logical_offset,
            length,
            extent_kind: Self::KIND_DATA,
            flags: 0,
            locator_id,
            checksum,
            birth_commit_group,
            reserved: [0u8; 15],
        }
    }

    /// Create a pending-data extent whose checksum and birth commit group
    /// are placeholders to be finalized by [`finalize_data`] after content
    /// is written and hashed.
    #[must_use]
    pub fn new_pending_data(logical_offset: u64, length: u64, locator_id: LocatorId) -> Self {
        Self {
            logical_offset,
            length,
            extent_kind: Self::KIND_PENDING_DATA,
            flags: 0,
            locator_id,
            checksum: [0u8; 32],
            birth_commit_group: 0,
            reserved: [0u8; 15],
        }
    }

    /// Finalize a pending-data extent into a verified [`KIND_DATA`] entry.
    ///
    /// # Panics
    /// Panics if `self` is not [`KIND_PENDING_DATA`].
    pub fn finalize_data(&mut self, checksum: [u8; 32], birth_commit_group: u64) {
        assert_eq!(self.extent_kind, Self::KIND_PENDING_DATA);
        self.extent_kind = Self::KIND_DATA;
        self.checksum = checksum;
        self.birth_commit_group = birth_commit_group;
    }

    #[must_use]
    pub fn new_unwritten(logical_offset: u64, length: u64, birth_commit_group: u64) -> Self {
        Self {
            logical_offset,
            length,
            extent_kind: Self::KIND_UNWRITTEN,
            flags: 0,
            locator_id: LocatorId::NONE,
            checksum: [0u8; 32],
            birth_commit_group,
            reserved: [0u8; 15],
        }
    }

    #[must_use]
    pub const fn byte_range(&self) -> core::ops::Range<u64> {
        self.logical_offset..self.logical_offset + self.length
    }

    #[must_use]
    pub const fn intersects(&self, offset: u64, len: u64) -> bool {
        let end = match self.logical_offset.checked_add(self.length) {
            Some(v) => v,
            None => return false,
        };
        let other_end = match offset.checked_add(len) {
            Some(v) => v,
            None => return false,
        };
        self.logical_offset < other_end && offset < end
    }

    #[must_use]
    pub const fn is_data(&self) -> bool {
        self.extent_kind == Self::KIND_DATA
    }
    #[must_use]
    pub const fn is_unwritten(&self) -> bool {
        self.extent_kind == Self::KIND_UNWRITTEN
    }
    /// Returns `true` when this extent carries a data payload whose checksum
    /// has not yet been finalized (allocation-time placeholder).
    #[must_use]
    pub const fn is_pending_data(&self) -> bool {
        self.extent_kind == Self::KIND_PENDING_DATA
    }
    /// Returns `true` when this extent is finalized and carries an
    /// authoritative content checksum.
    #[must_use]
    pub const fn is_finalized_data(&self) -> bool {
        self.extent_kind == Self::KIND_DATA
    }

    #[must_use]
    pub const fn extent_type(&self) -> ExtentType {
        match self.extent_kind {
            Self::KIND_DATA => ExtentType::Data,
            Self::KIND_PENDING_DATA => ExtentType::Data,
            Self::KIND_UNWRITTEN => ExtentType::Unwritten,
            Self::KIND_HOLE => ExtentType::Hole,
            _ => ExtentType::Hole,
        }
    }

    #[must_use]
    pub const fn end_offset(&self) -> u64 {
        self.logical_offset + self.length
    }
    #[must_use]
    pub const fn dedup_eligible(&self) -> bool {
        (self.flags & 0x01) != 0
    }
    pub fn set_dedup_eligible(&mut self, eligible: bool) {
        if eligible {
            self.flags |= 0x01;
        } else {
            self.flags &= !0x01;
        }
    }
    #[must_use]
    pub const fn compression_hint(&self) -> u8 {
        (self.flags >> 1) & 0x03
    }
    pub fn set_compression_hint(&mut self, hint: u8) {
        self.flags = (self.flags & 0xF9) | ((hint & 0x03) << 1);
    }

    // ── Lifecycle flags (bits 3-4) ─────────────────────────────

    /// Extent was created by a live write and has not yet been
    /// rebaked to base placement (INGEST state).
    pub const FLAG_INGEST: u8 = 0x08;

    /// Extent has been fully rebaked into durable base placement
    /// (BASE_COMPLETE state).
    pub const FLAG_BASE_COMPLETE: u8 = 0x10;

    /// Return the current [`ExtentLifecycleState`] derived from flags.
    #[must_use]
    pub const fn lifecycle_state(&self) -> ExtentLifecycleState {
        if (self.flags & Self::FLAG_BASE_COMPLETE) != 0 {
            ExtentLifecycleState::BaseComplete
        } else if (self.flags & Self::FLAG_INGEST) != 0 {
            ExtentLifecycleState::Ingest
        } else {
            // Historic extents without flags: treat as BaseComplete.
            ExtentLifecycleState::BaseComplete
        }
    }

    /// Mark this extent as ingest (write-path creation).
    pub fn set_ingest(&mut self) {
        self.flags |= Self::FLAG_INGEST;
    }

    /// Transition from INGEST to BASE_COMPLETE (rebake completion).
    pub fn set_base_complete(&mut self) {
        self.flags = (self.flags & !Self::FLAG_INGEST) | Self::FLAG_BASE_COMPLETE;
    }

    // ── Transform verification ─────────────────────────────

    /// Store a [`TransformVerification`] token in the reserved bytes.
    ///
    /// Uses reserved[0..1] for the algorithm byte and reserved[1..9]
    /// for uncompressed_len (LE).  The remaining reserved bytes are
    /// unchanged.
    pub fn set_transform_verification(&mut self, algorithm: u8, uncompressed_len: u64) {
        self.reserved[0] = algorithm;
        self.reserved[1..9].copy_from_slice(&uncompressed_len.to_le_bytes());
    }

    /// Decode the [`TransformVerification`] token from reserved bytes.
    ///
    /// Returns `None` when the reserved bytes are all zero (no transform
    /// verification was stored).
    pub fn transform_verification(&self) -> Option<(u8, u64)> {
        let algorithm = self.reserved[0];
        let uncompressed_len = u64::from_le_bytes(self.reserved[1..9].try_into().unwrap());
        if algorithm == 0 && uncompressed_len == 0 {
            return None;
        }
        // Validate algorithm byte range.
        if algorithm > 2 {
            return None;
        }
        Some((algorithm, uncompressed_len))
    }

    /// True when this entry carries a transform verification token.
    #[must_use]
    pub fn has_transform_verification(&self) -> bool {
        self.transform_verification().is_some()
    }
}

impl fmt::Display for ExtentMapEntryV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExtentMapEntryV2(off={} len={} kind={} locator={})",
            self.logical_offset, self.length, self.extent_kind, self.locator_id
        )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExtentMapV1 {
    pub root: Option<u64>,
    pub entry_count: u64,
    pub alloc_bytes: u64,
    pub file_size: u64,
    pub version: u8,
}

impl ExtentMapV1 {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            root: None,
            entry_count: 0,
            alloc_bytes: 0,
            file_size: 0,
            version: 1,
        }
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entry_count == 0
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExtentMapV2 {
    pub root_page_locator: LocatorId,
    pub entry_count: u64,
    pub alloc_bytes: u64,
    pub file_size: u64,
    pub depth: u8,
    pub flags: u8,
    pub version: u8,
    pub reserved: [u8; 5],
}

impl ExtentMapV2 {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            root_page_locator: LocatorId::NONE,
            entry_count: 0,
            alloc_bytes: 0,
            file_size: 0,
            depth: 0,
            flags: 0,
            version: 2,
            reserved: [0u8; 5],
        }
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entry_count == 0
    }
    #[must_use]
    pub const fn is_large_file(&self) -> bool {
        (self.flags & 0x01) != 0
    }
    pub fn set_large_file(&mut self) {
        self.flags |= 0x01;
    }
}

/// V3 multi-level B-tree extent map header (56 bytes).
///
/// Phase 2 of polymorphic extent maps (#1291). Extends [`ExtentMapV2`] with
/// page-level accounting for multi-level B-tree representation.
///
/// Total: 8+8+8+8+1+1+4+4+1+13 = 56 bytes
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExtentMapV3 {
    pub root_page_locator: LocatorId,
    pub entry_count: u64,
    pub alloc_bytes: u64,
    pub file_size: u64,
    pub depth: u8,
    pub flags: u8,
    pub leaf_count: u32,
    pub internal_count: u32,
    pub version: u8,
    pub reserved: [u8; 13],
}

impl ExtentMapV3 {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            root_page_locator: LocatorId::NONE,
            entry_count: 0,
            alloc_bytes: 0,
            file_size: 0,
            depth: 2,
            flags: 0,
            leaf_count: 0,
            internal_count: 0,
            version: 3,
            reserved: [0u8; 13],
        }
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    /// Returns `true` if the migrating flag is set.
    #[must_use]
    pub const fn is_migrating(&self) -> bool {
        (self.flags & 0x01) != 0
    }

    /// Sets the migrating flag.
    pub fn set_migrating(&mut self) {
        self.flags |= 0x01;
    }

    /// Clears the migrating flag.
    pub fn clear_migrating(&mut self) {
        self.flags &= !0x01;
    }

    /// Returns `true` if the large_file flag is set.
    #[must_use]
    pub const fn is_large_file(&self) -> bool {
        (self.flags & 0x02) != 0
    }

    /// Sets the large_file flag.
    pub fn set_large_file(&mut self) {
        self.flags |= 0x02;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtentMapError {
    NotFound,
    InvalidRange,
    OverlappingExtent,
    Corrupt,
    WrongVersion,
    MapFull,
    InvalidExtentType,
    /// Feature flag not enabled for V3 promotion.
    V3NotEnabled,
    /// Refcount overflow — extent has reached MAX_REFCOUNT.
    RefCountOverflow,
    /// Cross-pool reflink refused — source and destination are in different pools.
    CrossPool,
}

impl fmt::Display for ExtentMapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtentMapError::NotFound => f.write_str("extent not found"),
            ExtentMapError::InvalidRange => f.write_str("invalid byte range"),
            ExtentMapError::OverlappingExtent => f.write_str("overlapping extent"),
            ExtentMapError::Corrupt => f.write_str("extent map page corrupt"),
            ExtentMapError::WrongVersion => f.write_str("unsupported extent map version"),
            ExtentMapError::MapFull => f.write_str("extent map full"),
            ExtentMapError::InvalidExtentType => f.write_str("invalid extent type for operation"),
            ExtentMapError::V3NotEnabled => f.write_str("V3 extent map not enabled"),
            ExtentMapError::RefCountOverflow => f.write_str("refcount overflow"),
            ExtentMapError::CrossPool => f.write_str("cross-pool reflink refused"),
        }
    }
}

/// Describes a byte range freed by truncate, punch_hole, zero_range, or collapse_range.
///
/// Includes the original logical range and enough tracking fields
/// so deferred cleanup can reclaim objects or adjust accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreedExtent {
    /// Logical byte offset where the freed range started.
    pub logical_offset: u64,
    /// Length of the freed range in bytes.
    pub length: u64,
    /// Object locator for DATA extents; `LocatorId::NONE` for HOLE.
    pub locator_id: LocatorId,
    /// Original extent type before freeing.
    pub extent_type: ExtentType,
}

impl FreedExtent {
    /// Create a new `FreedExtent`.
    #[must_use]
    pub const fn new(
        logical_offset: u64,
        length: u64,
        locator_id: LocatorId,
        extent_type: ExtentType,
    ) -> Self {
        Self {
            logical_offset,
            length,
            locator_id,
            extent_type,
        }
    }
}

pub trait ExtentMapOps {
    fn lookup_range(
        &self,
        offset: u64,
        length: u64,
    ) -> Result<alloc::vec::Vec<ExtentMapEntryV2>, ExtentMapError>;
    fn insert_extent(&mut self, entries: &[ExtentMapEntryV2]) -> Result<(), ExtentMapError>;
    fn truncate(&mut self, new_size: u64) -> Result<alloc::vec::Vec<FreedExtent>, ExtentMapError>;
    fn punch_hole(
        &mut self,
        offset: u64,
        length: u64,
    ) -> Result<alloc::vec::Vec<FreedExtent>, ExtentMapError>;
    fn collapse_range(
        &mut self,
        _offset: u64,
        _length: u64,
    ) -> Result<alloc::vec::Vec<FreedExtent>, ExtentMapError> {
        Err(ExtentMapError::InvalidExtentType)
    }
    fn convert_unwritten_to_data(
        &mut self,
        offset: u64,
        length: u64,
        locator_id: LocatorId,
        checksum: [u8; 32],
        birth_commit_group: u64,
    ) -> Result<(), ExtentMapError>;
    fn seek_data(&self, offset: u64) -> Option<(u64, u64)>;
    fn seek_hole(&self, offset: u64) -> Option<(u64, u64)>;
    fn fallocate(
        &mut self,
        offset: u64,
        length: u64,
        keep_size: bool,
    ) -> Result<(), ExtentMapError>;
    fn zero_range(
        &mut self,
        offset: u64,
        length: u64,
    ) -> Result<alloc::vec::Vec<FreedExtent>, ExtentMapError>;
    fn fiemap(
        &self,
        offset: u64,
        length: u64,
    ) -> Result<alloc::vec::Vec<FiemapExtent>, ExtentMapError>;
    fn validate(&self) -> Result<(), ExtentMapError>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FiemapExtent {
    pub fe_logical: u64,
    pub fe_physical: u64,
    pub fe_length: u64,
    pub fe_flags: u32,
}

impl FiemapExtent {
    pub const FLAG_LAST: u32 = 0x0000_0001;
    pub const FLAG_UNKNOWN: u32 = 0x0000_0002;
    pub const FLAG_DELALLOC: u32 = 0x0000_0004;
    pub const FLAG_ENCODED: u32 = 0x0000_0008;
    pub const FLAG_DATA_ENCRYPTED: u32 = 0x0000_0080;
    pub const FLAG_NOT_ALIGNED: u32 = 0x0000_0100;
    pub const FLAG_DATA_INLINE: u32 = 0x0000_0200;
    pub const FLAG_DATA_TAIL: u32 = 0x0000_0400;
    pub const FLAG_UNWRITTEN: u32 = 0x0000_0800;
    pub const FLAG_MERGED: u32 = 0x0000_1000;
    pub const FLAG_SHARED: u32 = 0x0000_2000;

    #[must_use]
    pub const fn new(fe_logical: u64, fe_physical: u64, fe_length: u64, fe_flags: u32) -> Self {
        Self {
            fe_logical,
            fe_physical,
            fe_length,
            fe_flags,
        }
    }
}

pub const EXTENT_MAP_PAGE_MAGIC: [u8; 4] = [b'E', b'X', b'M', b'P'];
pub const EXTENT_MAP_DEFAULT_PAGE_SIZE: usize = 4096;
pub const EXTENT_MAP_LEAF_ENTRIES_ESTIMATE: usize = 45;
pub const EXTENT_MAP_V1_MAX_ENTRIES: usize = 6;
pub const EXTENT_MAP_PAGE_HEADER_SIZE: usize = 54;
pub const EXTENT_MAP_ENTRY_V2_SIZE: usize = 89;

/// Default recordsize alignment for DATA entries (4 KiB).
pub const EXTENT_MAP_DEFAULT_RECORDSIZE: u64 = 4096;

/// Maximum allowed refcount for an extent (u32::MAX - 1 safety margin).
pub const EXTENT_MAP_MAX_REFCOUNT: u32 = u32::MAX - 1;
/// Pool-wide per-extent reference count for reflink sharing.
///
/// Each clone_file operation increments the refcount; each unlink/truncate
/// that frees the extent decrements it. When the refcount reaches zero the
/// extent payload may be reclaimed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ExtentIdRefCount(pub u32);

impl ExtentIdRefCount {
    /// Sentinel for "unreferenced" (freeable).
    pub const ZERO: Self = Self(0);

    /// Create a new refcount at the given value.
    #[must_use]
    pub const fn new(count: u32) -> Self {
        Self(count)
    }

    /// Returns true when the refcount is zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// Compute `st_blocks` from `alloc_bytes` per I6: `ceil(alloc_bytes / 512)`.
#[must_use]
pub const fn st_blocks_from_alloc_bytes(alloc_bytes: u64) -> u64 {
    alloc_bytes.div_ceil(512)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtentMapPageHeader {
    pub magic: [u8; 4],
    pub page_kind: u8,
    pub entry_count: u16,
    pub level: u8,
    pub checksum: [u8; 32],
    pub reserved: [u8; 14],
}

impl ExtentMapPageHeader {
    #[must_use]
    pub const fn new_leaf() -> Self {
        Self {
            magic: EXTENT_MAP_PAGE_MAGIC,
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
            magic: EXTENT_MAP_PAGE_MAGIC,
            page_kind: 1,
            entry_count: 0,
            level,
            checksum: [0u8; 32],
            reserved: [0u8; 14],
        }
    }
}

/// Entry-count threshold for promotion from V2 to V3.
pub const EXTENT_MAP_V2_V3_PROMOTION_THRESHOLD: usize = 100_000;

/// Entry-count threshold for demotion from V3 to V2 (2× hysteresis).
pub const EXTENT_MAP_V3_V2_DEMOTION_THRESHOLD: usize = 50_000;

/// Maximum tree depth for V3 multi-level B-trees.
pub const EXTENT_MAP_V3_MAX_DEPTH: u8 = 6;

// ---------------------------------------------------------------------------
// RecordsizeProperty — per-dataset recordsize configuration
// ---------------------------------------------------------------------------

/// The default recordsize for a newly-created dataset with no explicit
/// policy override (128 KiB).
pub const DATASET_DEFAULT_RECORDSIZE: u64 = 131_072;

/// Per-dataset recordsize property.
///
/// This is the dataset-level configuration value for the recordsize
/// policy. It supports three modes:
///
/// - `Default`: use the TideFS default (128 KiB).
/// - `Fixed(N)`: force a specific recordsize for all writes to this
///   dataset.
/// - `Inherit`: inherit the parent dataset's resolved recordsize at
///   mount/open time. If there is no parent, equivalent to `Default`.
///
/// The property is stored alongside other dataset configuration
/// (pool, compression, encryption, etc.) and is resolved at dataset
/// open time via [`RecordsizeProperty::resolve`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RecordsizeProperty {
    /// Use the TideFS dataset default recordsize (128 KiB).
    #[default]
    Default,
    /// Force a specific recordsize in bytes.
    Fixed(u64),
    /// Inherit the parent dataset's recordsize. Falls back to
    /// `Default` when there is no parent.
    Inherit,
}

impl RecordsizeProperty {
    /// Resolve this property against an optional inherited value.
    ///
    /// - `Inherit` uses `inherited`, then falls back to `Default`.
    /// - `Fixed` and `Default` ignore `inherited`.
    ///
    /// Returns the effective [`RecordsizeProperty`] after inheritance.
    #[must_use]
    pub fn resolve(self, inherited: Option<RecordsizeProperty>) -> RecordsizeProperty {
        match self {
            RecordsizeProperty::Inherit => match inherited {
                Some(parent) => parent.resolve(None),
                None => RecordsizeProperty::Default,
            },
            RecordsizeProperty::Fixed(_) | RecordsizeProperty::Default => self,
        }
    }

    /// The effective maximum extent size in bytes implied by this property.
    ///
    /// Returns `None` for `Inherit` (caller must resolve first).
    #[must_use]
    pub fn effective_max(self) -> Option<u64> {
        match self {
            RecordsizeProperty::Default => Some(DATASET_DEFAULT_RECORDSIZE),
            RecordsizeProperty::Fixed(rs) => Some(rs.max(EXTENT_MAP_DEFAULT_RECORDSIZE)),
            RecordsizeProperty::Inherit => None,
        }
    }
}
#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::format;

    #[test]
    fn extent_type_consumes_space() {
        assert!(!ExtentType::Hole.consumes_space());
        assert!(ExtentType::Unwritten.consumes_space());
        assert!(ExtentType::Data.consumes_space());
    }

    #[test]
    fn extent_type_reads_zero() {
        assert!(ExtentType::Hole.reads_zero());
        assert!(ExtentType::Unwritten.reads_zero());
        assert!(!ExtentType::Data.reads_zero());
    }

    #[test]
    fn extent_type_display() {
        assert_eq!(ExtentType::Hole.as_str(), "hole");
        assert_eq!(ExtentType::Unwritten.as_str(), "unwritten");
        assert_eq!(ExtentType::Data.as_str(), "data");
    }

    #[test]
    fn lifecycle_terminal_state() {
        assert!(!ExtentLifecycleState::Ingest.is_terminal());
        assert!(!ExtentLifecycleState::BaseComplete.is_terminal());
        assert!(!ExtentLifecycleState::Dead.is_terminal());
        assert!(ExtentLifecycleState::Freed.is_terminal());
    }

    #[test]
    fn lifecycle_readable() {
        assert!(!ExtentLifecycleState::Ingest.is_readable());
        assert!(ExtentLifecycleState::BaseComplete.is_readable());
        assert!(ExtentLifecycleState::Dead.is_readable());
        assert!(!ExtentLifecycleState::Freed.is_readable());
    }

    #[test]
    fn lifecycle_state_name() {
        assert_eq!(ExtentLifecycleState::Ingest.state_name(), "ingest");
        assert_eq!(
            ExtentLifecycleState::BaseComplete.state_name(),
            "base_complete"
        );
        assert_eq!(ExtentLifecycleState::Dead.state_name(), "dead");
        assert_eq!(ExtentLifecycleState::Freed.state_name(), "freed");
    }

    #[test]
    fn locator_id_none_sentinel() {
        assert_eq!(LocatorId::NONE, LocatorId(0));
        assert!(LocatorId::NONE.is_none());
        assert!(!LocatorId::NONE.is_some());
        assert!(LocatorId(1).is_some());
    }

    #[test]
    fn locator_id_display() {
        assert_eq!(format!("{}", LocatorId(0xABCD)), "000000000000abcd");
    }

    #[test]
    fn v1_hole_sentinel() {
        let hole = ExtentMapEntryV1::new_hole(0, 4096);
        assert!(hole.is_hole());
        assert_eq!(hole.length, 4096);
        assert!(hole.physical.is_none());
    }

    #[test]
    fn v1_byte_range() {
        let entry = ExtentMapEntryV1 {
            logical_offset: 4096,
            length: 8192,
            extent_type: ExtentType::Data,
            physical: Some(PhysicalExtentRef::new(1, 0, 2)),
            committed_commit_group: 42,
            payload_digest: [0u8; 32],
            compression: 0,
            encrypted: false,
            extent_id: ExtentId(1),
            reserved: [0u8; 6],
        };
        assert_eq!(entry.byte_range(), 4096..12288);
        assert_eq!(entry.end_offset(), 12288);
    }

    #[test]
    fn v1_intersects() {
        let entry = ExtentMapEntryV1 {
            logical_offset: 4096,
            length: 4096,
            extent_type: ExtentType::Data,
            physical: Some(PhysicalExtentRef::new(1, 0, 1)),
            committed_commit_group: 0,
            payload_digest: [0u8; 32],
            compression: 0,
            encrypted: false,
            extent_id: ExtentId(1),
            reserved: [0u8; 6],
        };
        assert!(entry.intersects(4096, 4096));
        assert!(entry.intersects(0, 8192));
        assert!(entry.intersects(8191, 2));
        assert!(!entry.intersects(0, 4096));
        assert!(!entry.intersects(8192, 4096));
    }

    #[test]
    fn v2_data_entry() {
        let checksum = [0xAAu8; 32];
        let entry = ExtentMapEntryV2::new_data(0, 4096, LocatorId(42), checksum, 100);
        assert!(entry.is_data());
        assert!(!entry.is_unwritten());
        assert_eq!(entry.extent_type(), ExtentType::Data);
    }

    #[test]
    fn v2_unwritten_entry() {
        let entry = ExtentMapEntryV2::new_unwritten(4096, 8192, 100);
        assert!(entry.is_unwritten());
        assert_eq!(entry.extent_type(), ExtentType::Unwritten);
        assert_eq!(entry.locator_id, LocatorId::NONE);
    }

    #[test]
    fn v2_intersects() {
        let entry = ExtentMapEntryV2::new_data(8192, 4096, LocatorId(1), [0u8; 32], 0);
        assert!(entry.intersects(8192, 4096));
        assert!(entry.intersects(0, 16384));
        assert!(!entry.intersects(0, 8192));
        assert!(!entry.intersects(12288, 4096));
    }

    #[test]
    fn v2_flags_dedup() {
        let mut entry = ExtentMapEntryV2::new_data(0, 4096, LocatorId(1), [0u8; 32], 0);
        assert!(!entry.dedup_eligible());
        entry.set_dedup_eligible(true);
        assert!(entry.dedup_eligible());
        entry.set_dedup_eligible(false);
        assert!(!entry.dedup_eligible());
    }

    #[test]
    fn v2_flags_compression_hint() {
        let mut entry = ExtentMapEntryV2::new_data(0, 4096, LocatorId(1), [0u8; 32], 0);
        assert_eq!(entry.compression_hint(), 0);
        entry.set_compression_hint(2);
        assert_eq!(entry.compression_hint(), 2);
        assert_eq!(entry.flags, 0x04);
    }

    #[test]
    fn v1_map_defaults() {
        let map = ExtentMapV1::new();
        assert!(map.is_empty());
        assert_eq!(map.version, 1);
    }

    #[test]
    fn v2_map_defaults() {
        let map = ExtentMapV2::new();
        assert!(map.is_empty());
        assert_eq!(map.version, 2);
        assert_eq!(map.root_page_locator, LocatorId::NONE);
        assert!(!map.is_large_file());
    }

    #[test]
    fn v2_large_file_flag() {
        let mut map = ExtentMapV2::new();
        map.set_large_file();
        assert!(map.is_large_file());
    }

    #[test]
    fn extent_map_error_display() {
        assert_eq!(format!("{}", ExtentMapError::NotFound), "extent not found");
        assert_eq!(
            format!("{}", ExtentMapError::OverlappingExtent),
            "overlapping extent"
        );
    }

    #[test]
    fn fiemap_extent_construction() {
        let fe = FiemapExtent::new(0, 1024, 4096, FiemapExtent::FLAG_LAST);
        assert_eq!(fe.fe_logical, 0);
        assert_eq!(fe.fe_physical, 1024);
        assert_eq!(fe.fe_length, 4096);
    }

    #[test]
    fn page_header_leaf() {
        let hdr = ExtentMapPageHeader::new_leaf();
        assert_eq!(hdr.magic, EXTENT_MAP_PAGE_MAGIC);
        assert_eq!(hdr.page_kind, 0);
        assert_eq!(hdr.level, 0);
    }

    #[test]
    fn page_header_internal() {
        let hdr = ExtentMapPageHeader::new_internal(2);
        assert_eq!(hdr.page_kind, 1);
        assert_eq!(hdr.level, 2);
    }

    #[test]
    fn entry_v2_size_matches_design_doc() {
        assert_eq!(EXTENT_MAP_ENTRY_V2_SIZE, 89);
    }
    #[test]
    fn page_header_size_matches_design_doc() {
        assert_eq!(EXTENT_MAP_PAGE_HEADER_SIZE, 54);
    }
    #[test]
    fn leaf_entries_estimate_reasonable() {
        let usable = EXTENT_MAP_DEFAULT_PAGE_SIZE - EXTENT_MAP_PAGE_HEADER_SIZE;
        let entries = usable / EXTENT_MAP_ENTRY_V2_SIZE;
        assert_eq!(entries, 45);
        assert_eq!(EXTENT_MAP_LEAF_ENTRIES_ESTIMATE, entries);
    }

    #[test]
    fn v3_map_defaults() {
        let map = ExtentMapV3::new();
        assert!(map.is_empty());
        assert_eq!(map.version, 3);
        assert_eq!(map.depth, 2);
        assert!(!map.is_migrating());
        assert!(!map.is_large_file());
    }

    #[test]
    fn v3_flags_migrating() {
        let mut map = ExtentMapV3::new();
        assert!(!map.is_migrating());
        map.set_migrating();
        assert!(map.is_migrating());
        map.clear_migrating();
        assert!(!map.is_migrating());
    }

    #[test]
    fn v3_flags_large_file() {
        let mut map = ExtentMapV3::new();
        map.set_large_file();
        assert!(map.is_large_file());
    }

    #[test]
    fn v3_header_size_is_56() {
        use core::mem::size_of;
        assert_eq!(size_of::<ExtentMapV3>(), 56);
    }

    #[test]
    fn v3_constants_match_design_doc() {
        assert_eq!(EXTENT_MAP_V2_V3_PROMOTION_THRESHOLD, 100_000);
        assert_eq!(EXTENT_MAP_V3_V2_DEMOTION_THRESHOLD, 50_000);
        assert_eq!(EXTENT_MAP_V3_MAX_DEPTH, 6);
    }

    #[test]
    fn v3_not_enabled_error_display() {
        assert_eq!(
            format!("{}", ExtentMapError::V3NotEnabled),
            "V3 extent map not enabled"
        );
    }
    // -- RecordsizeProperty tests --

    #[test]
    fn recordsize_property_default_is_default_variant() {
        let p = RecordsizeProperty::default();
        assert_eq!(p, RecordsizeProperty::Default);
    }

    #[test]
    fn recordsize_property_default_effective_max() {
        assert_eq!(
            RecordsizeProperty::Default.effective_max(),
            Some(DATASET_DEFAULT_RECORDSIZE)
        );
    }

    #[test]
    fn recordsize_property_fixed_effective_max() {
        assert_eq!(
            RecordsizeProperty::Fixed(65536).effective_max(),
            Some(65536)
        );
    }

    #[test]
    fn recordsize_property_fixed_clamped_to_min() {
        // Fixed values below EXTENT_MAP_DEFAULT_RECORDSIZE are clamped up.
        assert_eq!(
            RecordsizeProperty::Fixed(512).effective_max(),
            Some(EXTENT_MAP_DEFAULT_RECORDSIZE)
        );
    }

    #[test]
    fn recordsize_property_inherit_effective_max_none() {
        assert_eq!(RecordsizeProperty::Inherit.effective_max(), None);
    }

    #[test]
    fn recordsize_property_resolve_default_ignores_inherited() {
        let resolved = RecordsizeProperty::Default.resolve(Some(RecordsizeProperty::Fixed(65536)));
        assert_eq!(resolved, RecordsizeProperty::Default);
    }

    #[test]
    fn recordsize_property_resolve_fixed_ignores_inherited() {
        let resolved =
            RecordsizeProperty::Fixed(32768).resolve(Some(RecordsizeProperty::Fixed(65536)));
        assert_eq!(resolved, RecordsizeProperty::Fixed(32768));
    }

    #[test]
    fn recordsize_property_resolve_inherit_uses_parent() {
        let resolved = RecordsizeProperty::Inherit.resolve(Some(RecordsizeProperty::Fixed(65536)));
        assert_eq!(resolved, RecordsizeProperty::Fixed(65536));
    }

    #[test]
    fn recordsize_property_resolve_inherit_falls_back_to_default() {
        let resolved = RecordsizeProperty::Inherit.resolve(None);
        assert_eq!(resolved, RecordsizeProperty::Default);
    }

    #[test]
    fn recordsize_property_resolve_nested_inherit() {
        // Grandchild inherits from child which inherits from parent.
        let parent = RecordsizeProperty::Fixed(1_048_576);
        let child = RecordsizeProperty::Inherit.resolve(Some(parent));
        let grandchild = RecordsizeProperty::Inherit.resolve(Some(child));
        assert_eq!(grandchild, RecordsizeProperty::Fixed(1_048_576));
    }

    // ── Transform verification ───────────────────────────────────────

    #[test]
    fn entry_set_and_get_transform_verification() {
        let mut entry = ExtentMapEntryV2::new_data(0, 4096, LocatorId(1), [0xAB; 32], 1);
        entry.set_transform_verification(0x01, 4096); // zstd, 4096 bytes
        let (algo, len) = entry.transform_verification().unwrap();
        assert_eq!(algo, 0x01);
        assert_eq!(len, 4096);
        assert!(entry.has_transform_verification());
    }

    #[test]
    fn entry_transform_verification_defaults_to_none() {
        let entry = ExtentMapEntryV2::new_data(0, 4096, LocatorId(1), [0xAB; 32], 1);
        assert!(entry.transform_verification().is_none());
        assert!(!entry.has_transform_verification());
    }

    #[test]
    fn entry_transform_verification_rejects_invalid_algorithm() {
        let mut entry = ExtentMapEntryV2::new_data(0, 4096, LocatorId(1), [0xAB; 32], 1);
        entry.set_transform_verification(0xFF, 100);
        assert!(entry.transform_verification().is_none());
    }

    #[test]
    fn entry_transform_verification_zero_algorithm_and_len_is_none() {
        let entry = ExtentMapEntryV2::new_data(0, 4096, LocatorId(1), [0xAB; 32], 1);
        // Reserved bytes are all zero by default -> None
        assert!(entry.transform_verification().is_none());
    }

    #[test]
    fn entry_transform_verification_large_uncompressed_len() {
        let mut entry = ExtentMapEntryV2::new_data(0, 4096, LocatorId(1), [0xAB; 32], 1);
        let large_len = 1u64 << 40; // 1 TiB
        entry.set_transform_verification(0x01, large_len);
        let (_algo, len) = entry.transform_verification().unwrap();
        assert_eq!(len, large_len);
    }

    #[test]
    fn entry_transform_verification_roundtrip_through_reserved_bytes() {
        let mut entry = ExtentMapEntryV2::new_data(0, 4096, LocatorId(1), [0xAB; 32], 1);
        // Simulate what happens when reserved bytes are manually set
        entry.reserved[0] = 0x02; // lz4
        entry.reserved[1..9].copy_from_slice(&5000u64.to_le_bytes());
        let (algo, len) = entry.transform_verification().unwrap();
        assert_eq!(algo, 0x02);
        assert_eq!(len, 5000);
    }

    #[test]
    fn entry_set_transform_verification_preserves_unused_reserved() {
        let mut entry = ExtentMapEntryV2::new_data(0, 4096, LocatorId(1), [0xAB; 32], 1);
        // Set some data in the unused portion of reserved
        entry.reserved[9] = 0xCC;
        entry.reserved[10] = 0xDD;
        entry.set_transform_verification(0x01, 2048);
        assert_eq!(entry.reserved[9], 0xCC);
        assert_eq!(entry.reserved[10], 0xDD);
    }

    #[test]
    fn entry_pending_data_carries_transform_verification() {
        let mut entry = ExtentMapEntryV2::new_pending_data(0, 8192, LocatorId(2));
        assert!(!entry.has_transform_verification());
        entry.set_transform_verification(0x01, 8192);
        assert!(entry.has_transform_verification());
    }
}
