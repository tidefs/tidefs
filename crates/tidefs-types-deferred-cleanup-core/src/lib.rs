// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! Authority type definitions for deferred cleanup work queues.
//!
//! Implements Phase 1 of the deferred cleanup design from
//! [`docs/design/deferred-cleanup-work-queues.md`] with three core types:
//!
//! - [`WorkItemKind`] — discriminant enum: UnlinkFree, TruncateFree,
//!   RmdirFree, RenameOverwrite, SnapDelete, PunchHoleFree
//! - [`CleanupWorkItemV1`] — fixed-size 128-byte on-media record
//!   persisting a deferred cleanup operation for background reclamation
//! - [`WorkItemFlags`] — bitfield wrapper for the flags byte: is_complete
//!   and reserved bits
//!
//! Byte decoding in this crate is format validation only.  A successfully
//! decoded work item is syntactically valid v1 input; it is not proof that a
//! cleanup queue replay, cleanup job, or reclaim operation has run correctly.
//!
//! ## Design principle
//!
//! POSIX unlink, truncate, and rmdir on large files create a fundamental
//! tension: the caller expects O(1) syscall latency, but the filesystem
//! must eventually reclaim potentially millions of extents.  This crate
//! defines the bounded-size work item (128 bytes) that decouples
//! synchronous syscall metadata work from unbounded background iteration.
//!
//! ## Comparison to ZFS / Ceph
//!
//! - **ZFS**: `zfs_rmdir` and `zfs_znode_delete` perform a synchronous
//!   `dmu_free_long_range` that blocks the caller for O(extents) time.
//!   On a 10 TiB file with 128 KiB recordsize, `rm` can hang for minutes.
//!   TideFS enqueues a 128-byte `CleanupWorkItemV1` in O(1) and returns.
//! - **Ceph**: CephFS MDS blocks during unlink of large files similarly.
//!   There is no deferred work-queue abstraction; space accounting and
//!   reclamation are coupled directly to the metadata operation.
//!
//! [`docs/design/deferred-cleanup-work-queues.md`]:
//!     https://forgejo/forgeadmin/tidefs/docs/design/deferred-cleanup-work-queues.md

use core::fmt;

extern crate alloc;

pub use tidefs_types_dataset_feature_flags_core::BtreeRootPointer;

// Design spec reference.
pub const DEFERRED_CLEANUP_SPEC: &str = "tidefs-deferred-cleanup-v1-design-1619";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic bytes prefixing every `CleanupWorkItemV1` on-media record:
/// `b"CLNWITEM"`.
pub const WORK_ITEM_MAGIC: [u8; 8] = *b"CLNWITEM";

/// Total on-media size of `CleanupWorkItemV1` in bytes.
pub const WORK_ITEM_SIZE: usize = 128;

/// Current on-media version for `CleanupWorkItemV1` records.
///
/// The v1 record bytes do not store this value directly.  Callers that wrap
/// work items in a versioned container must pass the container version to
/// [`CleanupWorkItemV1::from_versioned_bytes`] before treating bytes as v1.
pub const WORK_ITEM_VERSION: u8 = 1;

/// Size of the opaque cursor field for resumable extent-map iteration.
pub const CURSOR_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// WorkItemKind
// ---------------------------------------------------------------------------

/// The kind of deferred cleanup operation persisted in a
/// [`CleanupWorkItemV1`].
///
/// On-media encoding: `u8` (values below).  The discriminants are stable;
/// never reorder or remove variants without a format version bump.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(u8)]
pub enum WorkItemKind {
    /// Unlink of last link to an inode (nlink → 0).
    /// Frees all extents belonging to the inode.
    #[default]
    UnlinkFree = 0,

    /// Truncate to a smaller size.
    /// Frees extents beyond the new EOF.
    TruncateFree = 1,

    /// Rmdir of an empty directory.
    /// Frees directory block extents.
    RmdirFree = 2,

    /// Rename that overwrites an existing target.
    /// Frees the overwritten target's extents.
    RenameOverwrite = 3,

    /// Snapshot deletion.
    /// Frees extents unique to the deleted snapshot.
    SnapDelete = 4,

    /// Punch hole (`fallocate FALLOC_FL_PUNCH_HOLE`).
    /// Frees extents within the punched range.
    PunchHoleFree = 5,
}

impl WorkItemKind {
    /// Number of defined variants.
    pub const COUNT: usize = 6;

    /// Stable name string for logging and diagnostic output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            WorkItemKind::UnlinkFree => "unlink_free",
            WorkItemKind::TruncateFree => "truncate_free",
            WorkItemKind::RmdirFree => "rmdir_free",
            WorkItemKind::RenameOverwrite => "rename_overwrite",
            WorkItemKind::SnapDelete => "snap_delete",
            WorkItemKind::PunchHoleFree => "punch_hole_free",
        }
    }

    /// Returns `true` if this kind results in the inode being fully removed
    /// (all extents freed, inode itself eligible for tombstone compaction).
    #[must_use]
    pub const fn is_inode_destroying(self) -> bool {
        matches!(self, WorkItemKind::UnlinkFree)
    }

    /// Returns `true` if this kind is associated with a namespace operation
    /// (unlink, truncate, rmdir, rename-overwrite) vs. a snapshot or
    /// explicit hole-punch operation.
    #[must_use]
    pub const fn is_namespace_op(self) -> bool {
        matches!(
            self,
            WorkItemKind::UnlinkFree
                | WorkItemKind::TruncateFree
                | WorkItemKind::RmdirFree
                | WorkItemKind::RenameOverwrite
        )
    }
}

impl fmt::Display for WorkItemKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<WorkItemKind> for u8 {
    fn from(kind: WorkItemKind) -> u8 {
        kind as u8
    }
}

impl TryFrom<u8> for WorkItemKind {
    type Error = WorkItemKindError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(WorkItemKind::UnlinkFree),
            1 => Ok(WorkItemKind::TruncateFree),
            2 => Ok(WorkItemKind::RmdirFree),
            3 => Ok(WorkItemKind::RenameOverwrite),
            4 => Ok(WorkItemKind::SnapDelete),
            5 => Ok(WorkItemKind::PunchHoleFree),
            other => Err(WorkItemKindError::new(other)),
        }
    }
}

/// Error returned when deserialising an unknown `WorkItemKind` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkItemKindError {
    pub raw_value: u8,
}

impl WorkItemKindError {
    pub const fn new(raw_value: u8) -> Self {
        Self { raw_value }
    }
}

impl fmt::Display for WorkItemKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown WorkItemKind: {}", self.raw_value)
    }
}

// ---------------------------------------------------------------------------
// WorkItemFlags
// ---------------------------------------------------------------------------

/// Bitfield wrapper for the flags byte in [`CleanupWorkItemV1`].
///
/// Layout:
/// - bit 0: `is_complete` — set when the background job finishes processing
/// - bits 1–7: reserved (must be zero on write and decode)
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WorkItemFlags(u8);

impl WorkItemFlags {
    /// No flags set — item is still pending.
    pub const PENDING: Self = WorkItemFlags(0);

    /// Item has been fully processed; eligible for deletion from the
    /// cleanup B+tree.
    pub const COMPLETE: Self = WorkItemFlags(1);

    /// Returns `true` if the item is marked complete.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        (self.0 & 1) != 0
    }

    /// Mark this work item as complete.
    pub fn set_complete(&mut self) {
        self.0 |= 1;
    }

    /// Returns the raw `u8` for on-media serialisation.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Construct from a raw `u8`.  Reserved bits are preserved (must be
    /// zero on write).
    #[must_use]
    pub const fn from_u8(raw: u8) -> Self {
        WorkItemFlags(raw)
    }

    /// Returns `true` if no reserved bits are set — used for validation
    /// before persisting new items.
    #[must_use]
    pub const fn validate_reserved_bits(self) -> bool {
        (self.0 & !1u8) == 0
    }
}

impl fmt::Display for WorkItemFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_complete() {
            f.write_str("complete")
        } else {
            f.write_str("pending")
        }
    }
}

// ---------------------------------------------------------------------------
// CleanupWorkItemDecodeError
// ---------------------------------------------------------------------------

/// Error returned when decoding a `CleanupWorkItemV1` byte record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupWorkItemDecodeError {
    /// The byte slice is not exactly [`WORK_ITEM_SIZE`] bytes.
    InvalidLength { expected: usize, actual: usize },
    /// The enclosing work-item record version is not supported by this crate.
    UnsupportedVersion { version: u8, supported: u8 },
    /// The magic bytes do not match [`WORK_ITEM_MAGIC`].
    InvalidMagic { actual: [u8; 8] },
    /// The kind byte does not name a known [`WorkItemKind`].
    UnknownKind { raw: u8 },
    /// The padding reserved next to the root pointer is non-zero.
    NonZeroRootReserved { bytes: [u8; 8] },
    /// The reserved flag bits are non-zero.
    NonZeroFlagReservedBits { raw: u8 },
    /// The trailing reserved bytes are non-zero.
    NonZeroReserved { bytes: [u8; 6] },
}

impl fmt::Display for CleanupWorkItemDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CleanupWorkItemDecodeError::InvalidLength { expected, actual } => write!(
                f,
                "cleanup work item length mismatch: expected {expected} bytes, got {actual}"
            ),
            CleanupWorkItemDecodeError::UnsupportedVersion { version, supported } => write!(
                f,
                "unsupported cleanup work item version {version}; supported version is {supported}"
            ),
            CleanupWorkItemDecodeError::InvalidMagic { actual } => {
                write!(f, "invalid cleanup work item magic: {actual:?}")
            }
            CleanupWorkItemDecodeError::UnknownKind { raw } => {
                write!(f, "unknown cleanup work item kind: {raw}")
            }
            CleanupWorkItemDecodeError::NonZeroRootReserved { bytes } => {
                write!(
                    f,
                    "cleanup work item root reserved bytes are non-zero: {bytes:?}"
                )
            }
            CleanupWorkItemDecodeError::NonZeroFlagReservedBits { raw } => write!(
                f,
                "cleanup work item flag reserved bits are non-zero: {raw:#04x}"
            ),
            CleanupWorkItemDecodeError::NonZeroReserved { bytes } => {
                write!(
                    f,
                    "cleanup work item reserved bytes are non-zero: {bytes:?}"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CleanupWorkItemV1
// ---------------------------------------------------------------------------

/// A deferred cleanup operation persisted at syscall time and processed
/// by the background `CleanupJob` implementing `IncrementalJob` (#1239).
///
/// ## On-media layout (128 bytes, fixed-size)
///
/// ```text
/// [0..8)    magic: b"CLNWITEM"
/// [8..16)   inode_id: u64 BE
/// [16]      kind: WorkItemKind as u8
/// [17..25)  created_commit_group: u64 BE
/// [25..33)  extent_map_root: BtreeRootPointer.0 u64 BE
/// [33..41)  root reserved: [u8; 8]
/// [41..105) cursor: [u8; 64] — opaque cursor state
/// [105..113) bytes_to_free_estimate: u64 BE
/// [113..121) extents_processed: u64 BE
/// [121]      flags: u8
/// [122..128) reserved: [u8; 6]
/// ```
///
/// The magic field enables integrity checks: any record not starting with
/// `b"CLNWITEM"` is corrupt or misaligned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupWorkItemV1 {
    /// Magic identifier: must equal [`WORK_ITEM_MAGIC`].
    pub magic: [u8; 8],

    /// Inode owning the extents to be freed.
    pub inode_id: u64,

    /// Kind of deferred operation.
    pub kind: WorkItemKind,

    /// CommitGroup in which this work item was enqueued.
    pub created_commit_group: u64,

    /// Snapshot of the extent-map root pointer at enqueue time.
    /// The background job walks this frozen root; the live extent map
    /// is updated independently by the synchronous phase.
    pub extent_map_root: BtreeRootPointer,

    /// Opaque cursor state for resumable extent-map iteration.
    /// Zero-filled when the work item is first enqueued; updated by
    /// the background job after each bounded batch.
    pub cursor: [u8; CURSOR_SIZE],

    /// Estimated bytes to free, populated from extent-map subtree
    /// summary at enqueue time.  Used for space-accounting decisions
    /// (e.g. safety reserve relaxation when large reclaim is in-flight).
    pub bytes_to_free_estimate: u64,

    /// Running count of extents processed so far across all batches.
    pub extents_processed: u64,

    /// Flags byte (bit 0: is_complete).
    pub flags: WorkItemFlags,

    /// Reserved: zero-filled on creation.
    pub reserved: [u8; 6],
}

impl CleanupWorkItemV1 {
    /// Create a new pending work item with the given parameters.
    ///
    /// The `created_commit_group` should be set to the commit_group in which the namespace
    /// operation (unlink/truncate/etc.) was committed.
    #[must_use]
    pub fn new(
        inode_id: u64,
        kind: WorkItemKind,
        created_commit_group: u64,
        extent_map_root: BtreeRootPointer,
        bytes_to_free_estimate: u64,
    ) -> Self {
        Self {
            magic: WORK_ITEM_MAGIC,
            inode_id,
            kind,
            created_commit_group,
            extent_map_root,
            cursor: [0u8; CURSOR_SIZE],
            bytes_to_free_estimate,
            extents_processed: 0,
            flags: WorkItemFlags::PENDING,
            reserved: [0u8; 6],
        }
    }

    /// Returns `true` if the magic field matches the expected value.
    #[must_use]
    pub fn validate_magic(&self) -> bool {
        self.magic == WORK_ITEM_MAGIC
    }

    /// Returns `true` if this work item has been fully processed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.flags.is_complete()
    }

    /// Mark this work item as complete — all extents have been reclaimed.
    pub fn mark_complete(&mut self) {
        self.flags.set_complete();
    }

    /// Returns `true` if the reserved fields are zero (on-media invariant).
    #[must_use]
    pub fn validate_reserved(&self) -> bool {
        self.flags.validate_reserved_bits() && self.reserved == [0u8; 6]
    }

    /// Returns `true` if all invariants hold for a newly created (not yet
    /// processed) work item.
    #[must_use]
    pub fn validate_new(&self) -> bool {
        self.validate_magic()
            && self.extents_processed == 0
            && self.flags == WorkItemFlags::PENDING
            && self.validate_reserved()
    }

    /// Serialize this work item to the fixed-size v1 on-media record.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; WORK_ITEM_SIZE] {
        let mut bytes = [0u8; WORK_ITEM_SIZE];
        bytes[0..8].copy_from_slice(&self.magic);
        bytes[8..16].copy_from_slice(&self.inode_id.to_be_bytes());
        bytes[16] = u8::from(self.kind);
        bytes[17..25].copy_from_slice(&self.created_commit_group.to_be_bytes());
        bytes[25..33].copy_from_slice(&self.extent_map_root.0.to_be_bytes());
        bytes[41..105].copy_from_slice(&self.cursor);
        bytes[105..113].copy_from_slice(&self.bytes_to_free_estimate.to_be_bytes());
        bytes[113..121].copy_from_slice(&self.extents_processed.to_be_bytes());
        bytes[121] = self.flags.as_u8();
        bytes[122..128].copy_from_slice(&self.reserved);
        bytes
    }

    /// Decode an implicit v1 work item byte record.
    ///
    /// This is format validation only; success does not prove cleanup queue
    /// replay, cleanup scheduling, or reclaim behavior.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CleanupWorkItemDecodeError> {
        Self::from_versioned_bytes(WORK_ITEM_VERSION, bytes)
    }

    /// Decode a work item byte record from an enclosing versioned container.
    ///
    /// Only [`WORK_ITEM_VERSION`] is accepted.  No legacy fallback or
    /// downgrade path is attempted for unsupported versions.
    pub fn from_versioned_bytes(
        version: u8,
        bytes: &[u8],
    ) -> Result<Self, CleanupWorkItemDecodeError> {
        if version != WORK_ITEM_VERSION {
            return Err(CleanupWorkItemDecodeError::UnsupportedVersion {
                version,
                supported: WORK_ITEM_VERSION,
            });
        }
        if bytes.len() != WORK_ITEM_SIZE {
            return Err(CleanupWorkItemDecodeError::InvalidLength {
                expected: WORK_ITEM_SIZE,
                actual: bytes.len(),
            });
        }

        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[0..8]);
        if magic != WORK_ITEM_MAGIC {
            return Err(CleanupWorkItemDecodeError::InvalidMagic { actual: magic });
        }

        let kind = WorkItemKind::try_from(bytes[16])
            .map_err(|_| CleanupWorkItemDecodeError::UnknownKind { raw: bytes[16] })?;

        let mut root_reserved = [0u8; 8];
        root_reserved.copy_from_slice(&bytes[33..41]);
        if root_reserved != [0u8; 8] {
            return Err(CleanupWorkItemDecodeError::NonZeroRootReserved {
                bytes: root_reserved,
            });
        }

        let flags = WorkItemFlags::from_u8(bytes[121]);
        if !flags.validate_reserved_bits() {
            return Err(CleanupWorkItemDecodeError::NonZeroFlagReservedBits { raw: bytes[121] });
        }

        let mut reserved = [0u8; 6];
        reserved.copy_from_slice(&bytes[122..128]);
        if reserved != [0u8; 6] {
            return Err(CleanupWorkItemDecodeError::NonZeroReserved { bytes: reserved });
        }

        let mut cursor = [0u8; CURSOR_SIZE];
        cursor.copy_from_slice(&bytes[41..105]);

        Ok(Self {
            magic,
            inode_id: read_u64_be(bytes, 8),
            kind,
            created_commit_group: read_u64_be(bytes, 17),
            extent_map_root: BtreeRootPointer(read_u64_be(bytes, 25)),
            cursor,
            bytes_to_free_estimate: read_u64_be(bytes, 105),
            extents_processed: read_u64_be(bytes, 113),
            flags,
            reserved,
        })
    }
}

fn read_u64_be(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

impl Default for CleanupWorkItemV1 {
    fn default() -> Self {
        Self {
            magic: WORK_ITEM_MAGIC,
            inode_id: 0,
            kind: WorkItemKind::default(),
            created_commit_group: 0,
            extent_map_root: BtreeRootPointer::EMPTY,
            cursor: [0u8; CURSOR_SIZE],
            bytes_to_free_estimate: 0,
            extents_processed: 0,
            flags: WorkItemFlags::PENDING,
            reserved: [0u8; 6],
        }
    }
}

impl fmt::Display for CleanupWorkItemV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CleanupWorkItem(inode={} kind={} commit_group={} estimate={} processed={} {})",
            self.inode_id,
            self.kind,
            self.created_commit_group,
            self.bytes_to_free_estimate,
            self.extents_processed,
            self.flags
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    // ── WorkItemKind ──────────────────────────────────────────────────

    #[test]
    fn work_item_kind_count() {
        assert_eq!(WorkItemKind::COUNT, 6);
    }

    #[test]
    fn work_item_kind_as_str() {
        assert_eq!(WorkItemKind::UnlinkFree.as_str(), "unlink_free");
        assert_eq!(WorkItemKind::TruncateFree.as_str(), "truncate_free");
        assert_eq!(WorkItemKind::RmdirFree.as_str(), "rmdir_free");
        assert_eq!(WorkItemKind::RenameOverwrite.as_str(), "rename_overwrite");
        assert_eq!(WorkItemKind::SnapDelete.as_str(), "snap_delete");
        assert_eq!(WorkItemKind::PunchHoleFree.as_str(), "punch_hole_free");
    }

    #[test]
    fn work_item_kind_display() {
        assert_eq!(format!("{}", WorkItemKind::UnlinkFree), "unlink_free");
        assert_eq!(format!("{}", WorkItemKind::TruncateFree), "truncate_free");
    }

    #[test]
    fn work_item_kind_is_inode_destroying() {
        assert!(WorkItemKind::UnlinkFree.is_inode_destroying());
        assert!(!WorkItemKind::TruncateFree.is_inode_destroying());
        assert!(!WorkItemKind::RmdirFree.is_inode_destroying());
        assert!(!WorkItemKind::RenameOverwrite.is_inode_destroying());
        assert!(!WorkItemKind::SnapDelete.is_inode_destroying());
        assert!(!WorkItemKind::PunchHoleFree.is_inode_destroying());
    }

    #[test]
    fn work_item_kind_is_namespace_op() {
        assert!(WorkItemKind::UnlinkFree.is_namespace_op());
        assert!(WorkItemKind::TruncateFree.is_namespace_op());
        assert!(WorkItemKind::RmdirFree.is_namespace_op());
        assert!(WorkItemKind::RenameOverwrite.is_namespace_op());
        assert!(!WorkItemKind::SnapDelete.is_namespace_op());
        assert!(!WorkItemKind::PunchHoleFree.is_namespace_op());
    }

    #[test]
    fn work_item_kind_roundtrip_u8() {
        for raw in 0u8..6 {
            let kind = WorkItemKind::try_from(raw).unwrap();
            assert_eq!(u8::from(kind), raw);
        }
    }

    #[test]
    fn work_item_kind_invalid_u8() {
        assert!(WorkItemKind::try_from(6).is_err());
        assert!(WorkItemKind::try_from(255).is_err());
    }

    #[test]
    fn work_item_kind_error_display() {
        let err = WorkItemKindError::new(99);
        let s = format!("{err}");
        assert!(s.contains("99"));
        assert!(s.contains("unknown WorkItemKind"));
    }

    #[test]
    fn work_item_kind_default() {
        assert_eq!(WorkItemKind::default(), WorkItemKind::UnlinkFree);
    }

    // ── WorkItemFlags ─────────────────────────────────────────────────

    #[test]
    fn work_item_flags_pending() {
        let f = WorkItemFlags::PENDING;
        assert!(!f.is_complete());
        assert!(f.validate_reserved_bits());
        assert_eq!(f.as_u8(), 0);
    }

    #[test]
    fn work_item_flags_complete() {
        let f = WorkItemFlags::COMPLETE;
        assert!(f.is_complete());
        assert_eq!(f.as_u8(), 1);
    }

    #[test]
    fn work_item_flags_set_complete() {
        let mut f = WorkItemFlags::PENDING;
        f.set_complete();
        assert!(f.is_complete());
        assert_eq!(f.as_u8(), 1);
    }

    #[test]
    fn work_item_flags_display() {
        assert_eq!(format!("{}", WorkItemFlags::PENDING), "pending");
        assert_eq!(format!("{}", WorkItemFlags::COMPLETE), "complete");
    }

    #[test]
    fn work_item_flags_reserved_bits() {
        assert!(WorkItemFlags::PENDING.validate_reserved_bits());
        assert!(WorkItemFlags::COMPLETE.validate_reserved_bits());
        assert!(!WorkItemFlags::from_u8(0xFF).validate_reserved_bits());
        assert!(!WorkItemFlags::from_u8(0x02).validate_reserved_bits());
    }

    #[test]
    fn work_item_flags_roundtrip() {
        for raw in [0u8, 1, 0, 1] {
            let f = WorkItemFlags::from_u8(raw);
            assert_eq!(f.as_u8(), raw);
        }
    }

    // ── CleanupWorkItemV1 ─────────────────────────────────────────────

    #[test]
    fn cleanup_work_item_new() {
        let root = BtreeRootPointer(42);
        let item = CleanupWorkItemV1::new(100, WorkItemKind::UnlinkFree, 10, root, 4096);
        assert_eq!(item.magic, WORK_ITEM_MAGIC);
        assert_eq!(item.inode_id, 100);
        assert_eq!(item.kind, WorkItemKind::UnlinkFree);
        assert_eq!(item.created_commit_group, 10);
        assert_eq!(item.extent_map_root, BtreeRootPointer(42));
        assert_eq!(item.bytes_to_free_estimate, 4096);
        assert_eq!(item.extents_processed, 0);
        assert!(!item.is_complete());
        assert!(item.validate_new());
    }

    #[test]
    fn cleanup_work_item_valid_v1_roundtrips_unchanged() {
        for kind in [
            WorkItemKind::UnlinkFree,
            WorkItemKind::TruncateFree,
            WorkItemKind::RmdirFree,
            WorkItemKind::RenameOverwrite,
            WorkItemKind::SnapDelete,
            WorkItemKind::PunchHoleFree,
        ] {
            let mut item = CleanupWorkItemV1::new(100, kind, 10, BtreeRootPointer(42), 4096);
            item.cursor[0] = u8::from(kind);
            item.cursor[63] = 0xA5;
            item.extents_processed = 3;
            item.mark_complete();

            let bytes = item.to_bytes();
            let decoded = CleanupWorkItemV1::from_bytes(&bytes).unwrap();

            assert_eq!(decoded, item);
            assert_eq!(decoded.to_bytes(), bytes);
        }
    }

    #[test]
    fn cleanup_work_item_decode_rejects_unsupported_version() {
        let item = CleanupWorkItemV1::default();
        let bytes = item.to_bytes();

        assert_eq!(
            CleanupWorkItemV1::from_versioned_bytes(2, &bytes),
            Err(CleanupWorkItemDecodeError::UnsupportedVersion {
                version: 2,
                supported: WORK_ITEM_VERSION,
            })
        );
    }

    #[test]
    fn cleanup_work_item_decode_rejects_malformed_length() {
        let item = CleanupWorkItemV1::default();
        let bytes = item.to_bytes();

        assert_eq!(
            CleanupWorkItemV1::from_bytes(&bytes[..WORK_ITEM_SIZE - 1]),
            Err(CleanupWorkItemDecodeError::InvalidLength {
                expected: WORK_ITEM_SIZE,
                actual: WORK_ITEM_SIZE - 1,
            })
        );
    }

    #[test]
    fn cleanup_work_item_decode_rejects_invalid_magic() {
        let item = CleanupWorkItemV1::default();
        let mut bytes = item.to_bytes();
        bytes[0..8].copy_from_slice(b"BADITEM!");

        assert_eq!(
            CleanupWorkItemV1::from_bytes(&bytes),
            Err(CleanupWorkItemDecodeError::InvalidMagic {
                actual: *b"BADITEM!",
            })
        );
    }

    #[test]
    fn cleanup_work_item_decode_rejects_unknown_kind() {
        let item = CleanupWorkItemV1::default();
        let mut bytes = item.to_bytes();
        bytes[16] = 99;

        assert_eq!(
            CleanupWorkItemV1::from_bytes(&bytes),
            Err(CleanupWorkItemDecodeError::UnknownKind { raw: 99 })
        );
    }

    #[test]
    fn cleanup_work_item_decode_rejects_root_reserved_drift() {
        let item = CleanupWorkItemV1::default();
        let mut bytes = item.to_bytes();
        bytes[40] = 0x80;

        assert_eq!(
            CleanupWorkItemV1::from_bytes(&bytes),
            Err(CleanupWorkItemDecodeError::NonZeroRootReserved {
                bytes: [0, 0, 0, 0, 0, 0, 0, 0x80],
            })
        );
    }

    #[test]
    fn cleanup_work_item_decode_rejects_flag_reserved_drift() {
        let item = CleanupWorkItemV1::default();
        let mut bytes = item.to_bytes();
        bytes[121] = 0x02;

        assert_eq!(
            CleanupWorkItemV1::from_bytes(&bytes),
            Err(CleanupWorkItemDecodeError::NonZeroFlagReservedBits { raw: 0x02 })
        );
    }

    #[test]
    fn cleanup_work_item_decode_rejects_trailing_reserved_drift() {
        let item = CleanupWorkItemV1::default();
        let mut bytes = item.to_bytes();
        bytes[122] = 0x01;

        assert_eq!(
            CleanupWorkItemV1::from_bytes(&bytes),
            Err(CleanupWorkItemDecodeError::NonZeroReserved {
                bytes: [1, 0, 0, 0, 0, 0],
            })
        );
    }

    #[test]
    fn cleanup_work_item_validate_magic() {
        let mut item =
            CleanupWorkItemV1::new(1, WorkItemKind::TruncateFree, 2, BtreeRootPointer::EMPTY, 0);
        assert!(item.validate_magic());

        // Corrupt magic
        item.magic[0] = 0;
        assert!(!item.validate_magic());
    }

    #[test]
    fn cleanup_work_item_mark_complete() {
        let mut item = CleanupWorkItemV1::new(
            1,
            WorkItemKind::TruncateFree,
            1,
            BtreeRootPointer::EMPTY,
            100,
        );
        assert!(!item.is_complete());
        item.mark_complete();
        assert!(item.is_complete());
    }

    #[test]
    fn cleanup_work_item_validate_reserved() {
        let mut item = CleanupWorkItemV1::default();
        assert!(item.validate_reserved());

        // Set a reserved bit in flags
        item.flags = WorkItemFlags::from_u8(0x02);
        assert!(!item.validate_reserved());

        // Reset flags, corrupt reserved bytes
        item.flags = WorkItemFlags::PENDING;
        item.reserved[5] = 0xFF;
        assert!(!item.validate_reserved());
    }

    #[test]
    fn cleanup_work_item_validate_new_rejects_partial() {
        let mut item =
            CleanupWorkItemV1::new(1, WorkItemKind::UnlinkFree, 1, BtreeRootPointer::EMPTY, 0);
        assert!(item.validate_new());

        // Non-zero extents_processed fails validate_new
        item.extents_processed = 5;
        assert!(!item.validate_new());

        // Complete flag fails validate_new
        item.extents_processed = 0;
        item.mark_complete();
        assert!(!item.validate_new());
    }

    #[test]
    fn cleanup_work_item_default() {
        let item = CleanupWorkItemV1::default();
        assert_eq!(item.magic, WORK_ITEM_MAGIC);
        assert_eq!(item.inode_id, 0);
        assert_eq!(item.kind, WorkItemKind::UnlinkFree);
        assert_eq!(item.created_commit_group, 0);
        assert_eq!(item.extent_map_root, BtreeRootPointer::EMPTY);
        assert_eq!(item.cursor, [0u8; CURSOR_SIZE]);
        assert_eq!(item.bytes_to_free_estimate, 0);
        assert_eq!(item.extents_processed, 0);
        assert_eq!(item.flags, WorkItemFlags::PENDING);
        assert_eq!(item.reserved, [0u8; 6]);
    }

    #[test]
    fn cleanup_work_item_display() {
        let item = CleanupWorkItemV1::new(
            42,
            WorkItemKind::TruncateFree,
            5,
            BtreeRootPointer::EMPTY,
            8192,
        );
        let s = format!("{item}");
        assert!(s.contains("CleanupWorkItem"));
        assert!(s.contains("inode=42"));
        assert!(s.contains("truncate_free"));
        assert!(s.contains("commit_group=5"));
        assert!(s.contains("estimate=8192"));
    }

    // ── Constants ────────────────────────────────────────────────────

    #[test]
    fn magic_is_eight_bytes() {
        assert_eq!(WORK_ITEM_MAGIC.len(), 8);
        assert_eq!(&WORK_ITEM_MAGIC, b"CLNWITEM");
    }

    #[test]
    fn work_item_size_matches_design_doc() {
        assert_eq!(WORK_ITEM_SIZE, 128);
    }

    // ── Size assertions (compile-time guarantee for on-media layout) ─

    #[test]
    fn cleanup_work_item_v1_is_128_bytes() {
        // 8 (magic) + 8 (inode_id) + 1 (kind) + 8 (created_commit_group)
        // + 8 (extent_map_root) + 8 (root reserved) + 64 (cursor) + 8 (estimate)
        // + 8 (extents_processed) + 1 (flags) + 6 (reserved)
        // = 128 bytes. In memory, alignment may differ; this test verifies the
        // on-media field sizes sum correctly.
        let field_sum: usize = 8 + 8 + 1 + 8 + 8 + 8 + 64 + 8 + 8 + 1 + 6;
        assert_eq!(field_sum, WORK_ITEM_SIZE);
    }

    // ── Edge cases ────────────────────────────────────────────────────

    #[test]
    fn cleanup_work_item_max_values() {
        let item = CleanupWorkItemV1::new(
            u64::MAX,
            WorkItemKind::PunchHoleFree,
            u64::MAX,
            BtreeRootPointer(u64::MAX),
            u64::MAX,
        );
        assert!(item.validate_magic());
        assert_eq!(item.inode_id, u64::MAX);
        assert_eq!(item.bytes_to_free_estimate, u64::MAX);
    }

    #[test]
    fn cleanup_work_item_cursor_is_writable() {
        let mut item = CleanupWorkItemV1::default();
        item.cursor[0] = 0xAB;
        item.cursor[63] = 0xCD;
        assert_eq!(item.cursor[0], 0xAB);
        assert_eq!(item.cursor[63], 0xCD);
    }

    #[test]
    fn all_kinds_can_be_constructed() {
        for kind in [
            WorkItemKind::UnlinkFree,
            WorkItemKind::TruncateFree,
            WorkItemKind::RmdirFree,
            WorkItemKind::RenameOverwrite,
            WorkItemKind::SnapDelete,
            WorkItemKind::PunchHoleFree,
        ] {
            let item = CleanupWorkItemV1::new(1, kind, 1, BtreeRootPointer::EMPTY, 0);
            assert_eq!(item.kind, kind);
            assert!(item.validate_new());
        }
    }
}
