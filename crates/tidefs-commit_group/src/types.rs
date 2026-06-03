//! Core types for the TideFS transaction group subsystem.
//!
//! Defines `CommitGroupId`, dirty-tracking primitives, accumulator operation
//! queues, and the error type shared across all commit_group modules.

#[cfg(not(feature = "std"))]
use alloc::string::String;
use core::fmt;
use core::ops::{BitOr, Range};

/// Monotonically increasing transaction group identifier.
///
/// Starts at 1 on mount. Zero means "no open commit_group."
/// Persisted in the commit_group journal header and superblock.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CommitGroupId(pub u64);

impl CommitGroupId {
    /// The nil / unset commit_group id.
    pub const NIL: Self = Self(0);

    /// The first valid commit_group id assigned after mount.
    pub const FIRST: Self = Self(1);

    /// Returns `true` if this is a valid (non-zero) commit_group id.
    #[must_use]
    pub fn is_valid(self) -> bool {
        self.0 > 0
    }

    /// Advance to the next sequential commit_group id.
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl fmt::Display for CommitGroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "commit_group-{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// DirtyRange — a single dirty byte range on an inode
// ---------------------------------------------------------------------------

/// Describes a dirty byte range for a specific inode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirtyRange {
    /// Inode number.
    pub ino: u64,
    /// Byte offset of the dirty region.
    pub offset: u64,
    /// Length of the dirty region in bytes.
    pub len: u64,
}

impl DirtyRange {
    /// Create a new dirty range.
    #[must_use]
    pub fn new(ino: u64, offset: u64, len: u64) -> Self {
        Self { ino, offset, len }
    }

    /// The exclusive end of this range.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.len)
    }

    /// Convert to a `Range<u64>`.
    #[must_use]
    pub fn as_range(&self) -> Range<u64> {
        self.offset..self.end()
    }
}

// ---------------------------------------------------------------------------
// DirtyMetaFlags — bitflags for dirty metadata on an inode
// ---------------------------------------------------------------------------

/// Per-inode dirty-metadata flags tracked by the `DirtyTracker`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirtyMetaFlags(u8);

impl DirtyMetaFlags {
    /// No flags set.
    pub const NONE: Self = Self(0);

    /// `st_size` (file size) is dirty.
    pub const SIZE: Self = Self(1 << 0);
    /// `st_mtime` is dirty.
    pub const MTIME: Self = Self(1 << 1);
    /// `st_ctime` is dirty.
    pub const CTIME: Self = Self(1 << 2);
    /// Extended attributes are dirty.
    pub const XATTRS: Self = Self(1 << 3);

    /// Returns `true` if all bits in `other` are set.
    #[must_use]
    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns `true` if any bit is set.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if at least one dirty flag is set.
    #[must_use]
    pub fn is_dirty(self) -> bool {
        self.0 != 0
    }

    /// Insert (set) the given flags.
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// Remove (clear) the given flags.
    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }

    /// Clear all flags.
    pub fn clear(&mut self) {
        self.0 = 0;
    }
}

// ---------------------------------------------------------------------------
// BitOr for DirtyMetaFlags (allows `flag_a | flag_b`)
// ---------------------------------------------------------------------------

impl BitOr for DirtyMetaFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

// ---------------------------------------------------------------------------
// RootPointer — identifies a committed filesystem root
// ---------------------------------------------------------------------------

/// Identifies a committed filesystem root via its commit-group id and an
/// opaque handle into the object store.
///
/// The root pointer is atomically swapped during the commit phase: readers
/// see either the old root or the new root, never a partial state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootPointer {
    /// The commit group at which this root was committed.
    pub commit_group_id: CommitGroupId,
    /// Opaque handle to the root object (e.g. journal record key).
    pub root_handle: u64,
}

impl RootPointer {
    /// The nil root pointer — no committed root.
    pub const NIL: Self = Self {
        commit_group_id: CommitGroupId::NIL,
        root_handle: 0,
    };

    /// Create a new root pointer.
    #[must_use]
    pub fn new(commit_group_id: CommitGroupId, root_handle: u64) -> Self {
        Self {
            commit_group_id,
            root_handle,
        }
    }

    /// Returns `true` if this root pointer identifies a valid committed root.
    #[must_use]
    pub fn is_valid(self) -> bool {
        self.commit_group_id.is_valid()
    }
}

// ---------------------------------------------------------------------------
// CommitGroupPhase — two-phase state machine for the write pipeline
// ---------------------------------------------------------------------------

/// Two-phase lifecycle of a write pipeline commit group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitGroupPhase {
    /// Accepting writes.
    Open,
    /// Prepare in progress (validating, reserving resources).
    Preparing,
    /// Prepare succeeded; ready to commit.
    Prepared,
    /// Commit succeeded (journal written, root pointer swapped).
    Committed,
    /// Prepare failed, commit failed, or group was discarded.
    Aborted,
}

// ---------------------------------------------------------------------------
// CommitGroupState — lifecycle of a transaction group
// ---------------------------------------------------------------------------

/// Lifecycle state of a transaction group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitGroupState {
    /// Accumulating writes and metadata mutations.
    Open,
    /// Commit in progress; new writes are queued into the *next* commit_group.
    Committing,
    /// All data written to object store; extent pointers swapped; journal
    /// record durable. Any fsync waiters can be woken.
    Committed,
    /// `syncfs` / `fsync` barrier has confirmed durability for this commit_group.
    Synced,
}

// ---------------------------------------------------------------------------
// CommitGroupError — error type for the commit_group subsystem
// ---------------------------------------------------------------------------

/// Errors produced by the transaction group subsystem.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitGroupError {
    /// The object store rejected a put operation.
    StorePutFailed {
        /// Inode number.
        ino: u64,
        /// Byte offset of the write.
        offset: u64,
        /// Human-readable reason.
        reason: String,
    },
    /// The object store rejected a delete operation.
    StoreDeleteFailed {
        /// Object key that could not be deleted.
        key: String,
        /// Human-readable reason.
        reason: String,
    },
    /// The extent map operation failed.
    ExtentMapFailed {
        /// Inode number.
        ino: u64,
        /// Human-readable reason.
        reason: String,
    },
    /// An inode was unlinked while it had dirty writes.
    UnlinkWithDirtyWrites {
        /// Inode number.
        ino: u64,
    },
    /// The commit_group accumulator is empty — nothing to commit.
    EmptyCommitGroup,
    /// Recovery found a torn / incomplete commit_group that could not be replayed.
    RecoveryFailed {
        /// The commit_group id that failed recovery.
        commit_group_id: CommitGroupId,
        /// Human-readable reason.
        reason: String,
    },
    /// General I/O error.
    #[cfg(feature = "std")]
    Io(std::io::ErrorKind),
    /// Prepare phase failed (e.g., empty writes, validation failure).
    PrepareFailed {
        /// Human-readable reason.
        reason: String,
    },
    /// Commit phase rejected (e.g., group not in Prepared phase).
    CommitPhaseRejected {
        /// Human-readable reason.
        reason: String,
    },
}

impl fmt::Display for CommitGroupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StorePutFailed {
                ino,
                offset,
                reason,
            } => {
                write!(
                    f,
                    "store put failed for ino {ino} at offset {offset}: {reason}"
                )
            }
            Self::StoreDeleteFailed { key, reason } => {
                write!(f, "store delete failed for key {key}: {reason}")
            }
            Self::ExtentMapFailed { ino, reason } => {
                write!(f, "extent map operation failed for ino {ino}: {reason}")
            }
            Self::UnlinkWithDirtyWrites { ino } => {
                write!(f, "inode {ino} has dirty writes and cannot be unlinked")
            }
            Self::EmptyCommitGroup => write!(f, "commit_group accumulator is empty"),
            Self::RecoveryFailed {
                commit_group_id,
                reason,
            } => {
                write!(f, "recovery failed for {commit_group_id}: {reason}")
            }
            Self::PrepareFailed { reason } => {
                write!(f, "prepare failed: {reason}")
            }
            Self::CommitPhaseRejected { reason } => {
                write!(f, "commit phase rejected: {reason}")
            }
            #[cfg(feature = "std")]
            Self::Io(kind) => write!(f, "I/O error: {kind:?}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CommitGroupError {}
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ==================================================================
    // CommitGroupId
    // ==================================================================

    #[test]
    fn commit_group_id_nil_is_zero() {
        assert_eq!(CommitGroupId::NIL.0, 0);
        assert!(!CommitGroupId::NIL.is_valid());
    }

    #[test]
    fn commit_group_id_first_is_one() {
        assert_eq!(CommitGroupId::FIRST.0, 1);
        assert!(CommitGroupId::FIRST.is_valid());
    }

    #[test]
    fn commit_group_id_is_valid() {
        assert!(!CommitGroupId(0).is_valid());
        assert!(CommitGroupId(1).is_valid());
        assert!(CommitGroupId(u64::MAX).is_valid());
    }

    #[test]
    fn commit_group_id_next() {
        assert_eq!(CommitGroupId(0).next(), CommitGroupId(1));
        assert_eq!(CommitGroupId(1).next(), CommitGroupId(2));
        assert_eq!(CommitGroupId(42).next(), CommitGroupId(43));
        assert_eq!(CommitGroupId(u64::MAX).next(), CommitGroupId(u64::MAX));
    }

    #[test]
    fn commit_group_id_display() {
        assert_eq!(format!("{}", CommitGroupId(0)), "commit_group-0");
        assert_eq!(format!("{}", CommitGroupId(5)), "commit_group-5");
        assert_eq!(format!("{}", CommitGroupId(42)), "commit_group-42");
    }

    #[test]
    fn commit_group_id_ordering() {
        assert!(CommitGroupId(1) < CommitGroupId(2));
        assert!(CommitGroupId(2) > CommitGroupId(1));
        assert!(CommitGroupId(1) <= CommitGroupId(1));
        assert!(CommitGroupId(1) >= CommitGroupId(1));
    }

    #[test]
    fn commit_group_id_eq_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(CommitGroupId(1));
        set.insert(CommitGroupId(1));
        assert_eq!(set.len(), 1);
        set.insert(CommitGroupId(2));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn commit_group_id_default_is_nil() {
        assert_eq!(CommitGroupId::default(), CommitGroupId::NIL);
    }

    #[test]
    fn commit_group_id_clone_is_equal() {
        let id = CommitGroupId(7);
        assert_eq!(id, id.clone());
    }

    // ==================================================================
    // DirtyRange
    // ==================================================================

    #[test]
    fn dirty_range_new() {
        let dr = DirtyRange::new(42, 0, 4096);
        assert_eq!(dr.ino, 42);
        assert_eq!(dr.offset, 0);
        assert_eq!(dr.len, 4096);
    }

    #[test]
    fn dirty_range_end() {
        assert_eq!(DirtyRange::new(1, 0, 4096).end(), 4096);
        assert_eq!(DirtyRange::new(1, 100, 200).end(), 300);
        assert_eq!(DirtyRange::new(1, u64::MAX - 100, 200).end(), u64::MAX);
    }

    #[test]
    fn dirty_range_as_range() {
        let dr = DirtyRange::new(1, 100, 200);
        assert_eq!(dr.as_range(), 100..300);
    }

    #[test]
    fn dirty_range_zero_length() {
        let dr = DirtyRange::new(1, 100, 0);
        assert_eq!(dr.end(), 100);
        assert_eq!(dr.as_range(), 100..100);
    }

    // ==================================================================
    // DirtyMetaFlags
    // ==================================================================

    #[test]
    fn dirty_meta_flags_none_is_zero() {
        assert!(!DirtyMetaFlags::NONE.is_dirty());
        assert!(DirtyMetaFlags::NONE.is_empty());
    }

    #[test]
    fn dirty_meta_flags_single_flag() {
        let f = DirtyMetaFlags::SIZE;
        assert!(f.is_dirty());
        assert!(!f.is_empty());
        assert!(f.contains(DirtyMetaFlags::SIZE));
        assert!(!f.contains(DirtyMetaFlags::MTIME));
    }

    #[test]
    fn dirty_meta_flags_combined() {
        let f = DirtyMetaFlags::SIZE | DirtyMetaFlags::MTIME;
        assert!(f.contains(DirtyMetaFlags::SIZE));
        assert!(f.contains(DirtyMetaFlags::MTIME));
        assert!(!f.contains(DirtyMetaFlags::CTIME));
        assert!(!f.contains(DirtyMetaFlags::XATTRS));
    }

    #[test]
    fn dirty_meta_flags_insert() {
        let mut f = DirtyMetaFlags::NONE;
        f.insert(DirtyMetaFlags::SIZE);
        assert!(f.contains(DirtyMetaFlags::SIZE));
        f.insert(DirtyMetaFlags::MTIME);
        assert!(f.contains(DirtyMetaFlags::SIZE | DirtyMetaFlags::MTIME));
    }

    #[test]
    fn dirty_meta_flags_remove() {
        let mut f = DirtyMetaFlags::SIZE | DirtyMetaFlags::MTIME;
        f.remove(DirtyMetaFlags::SIZE);
        assert!(!f.contains(DirtyMetaFlags::SIZE));
        assert!(f.contains(DirtyMetaFlags::MTIME));
    }

    #[test]
    fn dirty_meta_flags_clear() {
        let mut f = DirtyMetaFlags::SIZE | DirtyMetaFlags::MTIME | DirtyMetaFlags::CTIME;
        f.clear();
        assert!(f.is_empty());
        assert!(!f.is_dirty());
    }

    #[test]
    fn dirty_meta_flags_all_four_independent() {
        let all = DirtyMetaFlags::SIZE
            | DirtyMetaFlags::MTIME
            | DirtyMetaFlags::CTIME
            | DirtyMetaFlags::XATTRS;
        assert!(all.contains(DirtyMetaFlags::SIZE));
        assert!(all.contains(DirtyMetaFlags::MTIME));
        assert!(all.contains(DirtyMetaFlags::CTIME));
        assert!(all.contains(DirtyMetaFlags::XATTRS));
    }

    #[test]
    fn dirty_meta_flags_subset_contains() {
        let f = DirtyMetaFlags::SIZE | DirtyMetaFlags::MTIME | DirtyMetaFlags::CTIME;
        assert!(f.contains(DirtyMetaFlags::SIZE));
        assert!(f.contains(DirtyMetaFlags::SIZE | DirtyMetaFlags::MTIME));
        assert!(!f.contains(DirtyMetaFlags::SIZE | DirtyMetaFlags::XATTRS));
    }

    // ==================================================================
    // RootPointer
    // ==================================================================

    #[test]
    fn root_pointer_nil() {
        assert!(!RootPointer::NIL.is_valid());
        assert_eq!(RootPointer::NIL.commit_group_id, CommitGroupId::NIL);
        assert_eq!(RootPointer::NIL.root_handle, 0);
    }

    #[test]
    fn root_pointer_valid() {
        let rp = RootPointer::new(CommitGroupId(3), 42);
        assert!(rp.is_valid());
    }

    #[test]
    fn root_pointer_invalid_when_commit_group_id_nil() {
        let rp = RootPointer::new(CommitGroupId::NIL, 99);
        assert!(!rp.is_valid());
    }

    #[test]
    fn root_pointer_equality() {
        let a = RootPointer::new(CommitGroupId(1), 42);
        let b = RootPointer::new(CommitGroupId(1), 42);
        let c = RootPointer::new(CommitGroupId(1), 43);
        let d = RootPointer::new(CommitGroupId(2), 42);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    // ==================================================================
    // CommitGroupPhase
    // ==================================================================

    #[test]
    fn commit_group_phase_discriminants_are_distinct() {
        let phases = [
            CommitGroupPhase::Open,
            CommitGroupPhase::Preparing,
            CommitGroupPhase::Prepared,
            CommitGroupPhase::Committed,
            CommitGroupPhase::Aborted,
        ];
        for i in 0..phases.len() {
            for j in 0..phases.len() {
                if i == j {
                    assert_eq!(phases[i], phases[j]);
                } else {
                    assert_ne!(phases[i], phases[j]);
                }
            }
        }
    }

    // ==================================================================
    // CommitGroupState
    // ==================================================================

    #[test]
    fn commit_group_state_discriminants_are_distinct() {
        let states = [
            CommitGroupState::Open,
            CommitGroupState::Committing,
            CommitGroupState::Committed,
            CommitGroupState::Synced,
        ];
        for i in 0..states.len() {
            for j in 0..states.len() {
                if i == j {
                    assert_eq!(states[i], states[j]);
                } else {
                    assert_ne!(states[i], states[j]);
                }
            }
        }
    }

    // ==================================================================
    // CommitGroupError
    // ==================================================================

    #[test]
    fn commit_group_error_is_std_error() {
        fn _assert_error<T: std::error::Error>() {}
        _assert_error::<CommitGroupError>();
    }

    #[test]
    fn commit_group_error_display_all_variants() {
        let e = CommitGroupError::StorePutFailed {
            ino: 1,
            offset: 4096,
            reason: "disk full".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("1"));
        assert!(s.contains("4096"));
        assert!(s.contains("disk full"));

        let e = CommitGroupError::StoreDeleteFailed {
            key: "obj-42".into(),
            reason: "not found".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("obj-42"));
        assert!(s.contains("not found"));

        let e = CommitGroupError::ExtentMapFailed {
            ino: 7,
            reason: "corrupt".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("7"));
        assert!(s.contains("corrupt"));

        let e = CommitGroupError::UnlinkWithDirtyWrites { ino: 99 };
        let s = format!("{e}");
        assert!(s.contains("99"));
        assert!(s.contains("dirty writes"));

        let e = CommitGroupError::EmptyCommitGroup;
        assert_eq!(format!("{e}"), "commit_group accumulator is empty");

        let e = CommitGroupError::RecoveryFailed {
            commit_group_id: CommitGroupId(5),
            reason: "torn".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("commit_group-5"));
        assert!(s.contains("torn"));

        let e = CommitGroupError::PrepareFailed {
            reason: "validation".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("prepare failed"));
        assert!(s.contains("validation"));

        let e = CommitGroupError::CommitPhaseRejected {
            reason: "not prepared".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("commit phase rejected"));
        assert!(s.contains("not prepared"));

        let e = CommitGroupError::Io(std::io::ErrorKind::PermissionDenied);
        let s = format!("{e}");
        assert!(s.contains("I/O error"));
        assert!(s.contains("PermissionDenied"));
    }

    #[test]
    fn commit_group_error_clone_and_eq() {
        let e1 = CommitGroupError::EmptyCommitGroup;
        let e2 = e1.clone();
        assert_eq!(e1, e2);

        let e3 = CommitGroupError::UnlinkWithDirtyWrites { ino: 42 };
        let e4 = CommitGroupError::UnlinkWithDirtyWrites { ino: 42 };
        assert_eq!(e3, e4);

        let e5 = CommitGroupError::UnlinkWithDirtyWrites { ino: 43 };
        assert_ne!(e3, e5);
    }
}
