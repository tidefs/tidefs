// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Authority type definitions for the space accounting model.
//!
//! Implements the source-owned logical vs physical space accounting type model
//! with six core types:
//!
//! - [`DatasetSpaceCountersV1`] — per-dataset logical space counters
//! - [`SpaceDelta`] — per-operation delta accumulator, committed atomically
//!   within a single commit_group
//! - [`SpaceDomainId`] — groups clones and origin into a shared accounting
//!   domain for correct statfs reporting
//! - [`PoolPhysicalCountersV1`] — pool-scoped physical space counters
//!   derived from the allocator and cleaner
//! - [`SnapshotSpaceRecord`] — per-snapshot deadlist metadata for O(1)
//!   pinned-snapshot-byte accounting
//! - [`SpaceDomainCounters`] — domain-level aggregated counters for
//!   statfs integration
//!
//! # Comparison to ZFS / Ceph
//!
//! - **ZFS**: `USED`/`AVAIL` in `zfs list` without explicit logical/physical
//!   coupling; snapshot space tracked via periodic scans producing stale
//!   results. This design provides O(1) deadlist accounting and explicit
//!   coupling between logical ENOSPC decisions and physical allocator state.
//! - **Ceph**: RADOS pool statistics (`ceph df`) are aggregate and don't
//!   distinguish logical from physical space or track snapshot-pinned bytes
//!   separately.  This design provides per-dataset granularity with
//!   SpaceDomainId for correct clone-family statfs.
#[cfg(all(not(test), feature = "alloc"))]
use alloc::vec::Vec;
use core::fmt;

#[cfg(all(not(test), feature = "alloc"))]
extern crate alloc;

// ---------------------------------------------------------------------------
// SpaceDomainId — clone-family grouping
// ---------------------------------------------------------------------------

/// Groups a set of datasets that share blocks (clones + origin) into one
/// accounting domain.
///
/// All clones of a given origin belong to the same domain.  `statfs()` and
/// quota enforcement operate at domain level to prevent double-counting
/// shared blocks.
///
/// A value of `0` is reserved for "no domain" (datasets with no clone
/// relationship).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct SpaceDomainId(pub u64);

impl SpaceDomainId {
    /// Sentinel for datasets not in any clone family.
    pub const NONE: Self = SpaceDomainId(0);

    /// Returns `true` if this is a real domain (non-zero).
    #[must_use]
    pub const fn is_some(self) -> bool {
        self.0 != 0
    }

    /// Returns `true` if this is the sentinel.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }
}

impl Default for SpaceDomainId {
    fn default() -> Self {
        Self::NONE
    }
}

impl fmt::Display for SpaceDomainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "domain:{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// DatasetSpaceCountersV1 — per-dataset logical space
// ---------------------------------------------------------------------------

/// Per-dataset logical space counters.
///
/// Stored in each dataset record's TLV extension area and updated atomically
/// within a commit_group.  These counters drive ENOSPC decisions via the derived
/// [`logical_avail_bytes`](DatasetSpaceCountersV1::logical_avail_bytes).
///
/// ## Field semantics
///
/// | Field | Meaning |
/// |---|---|
/// | `logical_used_bytes` | Unique live bytes reachable from any live root |
/// | `pinned_snapshot_bytes` | Subset pinned by snapshot deadlists (O(1)) |
/// | `reserved_bytes` | Space reserved via `fallocate` (UNWRITTEN extents) |
/// | `orphan_bytes` | Space held by `nlink==0` inodes that are still open |
/// | `quota_bytes` | Hard quota; 0 means no quota |
/// | `slop_bytes` | Non-user-allocatable safety headroom |
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DatasetSpaceCountersV1 {
    pub logical_used_bytes: u64,
    pub physical_used_bytes: u64,
    pub pinned_snapshot_bytes: u64,
    pub reserved_bytes: u64,
    pub orphan_bytes: u64,
    pub quota_bytes: u64,
    pub slop_bytes: u64,
    pub quota_soft_limit: u64,
}

impl DatasetSpaceCountersV1 {
    // ── Derived values ────────────────────────────────────────────────

    /// Total allocated logical bytes (used + reserved + orphan).
    #[must_use]
    pub const fn logical_alloc_bytes(self) -> u64 {
        self.logical_used_bytes
            .saturating_add(self.reserved_bytes)
            .saturating_add(self.orphan_bytes)
    }

    /// Total bytes consumed by this dataset for admission and statfs.
    ///
    /// Returns `logical_used_bytes + reserved_bytes + orphan_bytes`.
    /// Does **not** include `pinned_snapshot_bytes` — snapshot-pinned
    /// bytes are a subset of `logical_used_bytes` already and must not
    /// reduce POSIX statfs `f_bfree` / `f_bavail` or gate ENOSPC.
    /// See issues #638 and #649.
    #[must_use]
    pub const fn total_consumed_bytes(self) -> u64 {
        self.logical_alloc_bytes()
    }

    /// Available logical bytes considering quota and slop.
    ///
    /// When `quota_bytes == 0` the caller must supply a physical-capacity
    /// fallback via [`logical_avail_bytes_with_phys_capacity`].
    ///
    /// [`logical_avail_bytes_with_phys_capacity`]:
    ///     DatasetSpaceCountersV1::logical_avail_bytes_with_phys_capacity
    #[must_use]
    pub const fn logical_avail_bytes(self) -> u64 {
        if self.quota_bytes == 0 {
            // No quota: caller should use logical_avail_bytes_with_phys_capacity.
            // Return max as a sentinel (no quota-enforced limit).
            u64::MAX
        } else {
            let ceiling = self.quota_bytes.saturating_sub(self.slop_bytes);
            let alloc = self.logical_alloc_bytes();
            ceiling.saturating_sub(alloc)
        }
    }

    /// Available logical bytes with an explicit physical-capacity bound.
    ///
    /// Used when `quota_bytes == 0` — the pool's physical capacity acts
    /// as the soft ceiling.
    #[must_use]
    pub const fn logical_avail_bytes_with_phys_capacity(self, phys_capacity_bytes: u64) -> u64 {
        let ceiling = if self.quota_bytes == 0 {
            phys_capacity_bytes
        } else {
            // Quota takes precedence over physical capacity.
            let q = self.quota_bytes.saturating_sub(self.slop_bytes);
            if q < phys_capacity_bytes {
                q
            } else {
                phys_capacity_bytes
            }
        };
        let alloc = self.logical_alloc_bytes();
        ceiling.saturating_sub(alloc)
    }

    // ── Validation ────────────────────────────────────────────────────

    /// Returns `true` if all counters are internally consistent.
    ///
    /// Consistency rules:
    /// - `pinned_snapshot_bytes <= logical_used_bytes` (snapshots can't pin
    ///   more bytes than exist)
    /// - `slop_bytes <= quota_bytes` when quota is set
    #[must_use = "callers must check for InconsistentCounters errors"]
    pub fn validate(&self) -> Result<(), SpaceAccountingError> {
        if self.pinned_snapshot_bytes > self.logical_used_bytes {
            return Err(SpaceAccountingError::InconsistentCounters {
                reason: "pinned_snapshot_bytes exceeds logical_used_bytes",
            });
        }
        if self.quota_bytes > 0 && self.slop_bytes > self.quota_bytes {
            return Err(SpaceAccountingError::InconsistentCounters {
                reason: "slop_bytes exceeds quota_bytes",
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SpaceDelta — per-operation accumulator
// ---------------------------------------------------------------------------

/// Per-operation space delta, accumulated during a commit_group and committed
/// atomically.
///
/// Each mutating operation produces a `SpaceDelta`.  Before commit, all
/// deltas are summed and validated against the current counters for
/// underflow and quota-ceiling violations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SpaceDelta {
    /// + for new writes, − for truncate/free.
    pub logical_used_delta: i64,
    /// + for fallocate, − for write-into-unwritten or punch.
    pub reserved_delta: i64,
    /// + for unlink-while-open, − for final close.
    pub orphan_delta: i64,
    /// + for snapshot create, − for snapshot destroy.
    pub pinned_snapshot_delta: i64,
}

impl SpaceDelta {
    /// Zero delta — no space change.
    pub const ZERO: Self = SpaceDelta {
        logical_used_delta: 0,
        reserved_delta: 0,
        orphan_delta: 0,
        pinned_snapshot_delta: 0,
    };

    /// Create a delta for a new data write of `bytes`.
    #[must_use]
    pub const fn new_write(bytes: u64) -> Self {
        SpaceDelta {
            logical_used_delta: bytes as i64,
            ..SpaceDelta::ZERO
        }
    }

    /// Create a delta for a `fallocate` reservation.
    #[must_use]
    pub const fn new_reservation(bytes: u64) -> Self {
        SpaceDelta {
            reserved_delta: bytes as i64,
            ..SpaceDelta::ZERO
        }
    }

    /// Create a delta for write-into-unwritten: converts reservation to
    /// used bytes (no net logical change — the bytes were already
    /// counted as reserved).
    #[must_use]
    pub const fn new_write_into_unwritten(bytes: u64) -> Self {
        SpaceDelta {
            reserved_delta: -(bytes as i64),
            ..SpaceDelta::ZERO
        }
    }

    /// Create a delta for freeing data (truncate, punch, unlink).
    #[must_use]
    pub const fn new_free(bytes: u64) -> Self {
        SpaceDelta {
            logical_used_delta: -(bytes as i64),
            ..SpaceDelta::ZERO
        }
    }

    /// Create a delta for orphan-while-open.
    #[must_use]
    pub const fn new_orphan_acquire(bytes: u64) -> Self {
        SpaceDelta {
            orphan_delta: bytes as i64,
            ..SpaceDelta::ZERO
        }
    }

    /// Create a delta for final close of an orphan (space freed).
    #[must_use]
    pub const fn new_orphan_release(bytes: u64) -> Self {
        SpaceDelta {
            orphan_delta: -(bytes as i64),
            ..SpaceDelta::ZERO
        }
    }

    /// Delta for snapshot creation: pins live bytes into the deadlist.
    #[must_use]
    pub const fn new_snapshot_create(bytes: u64) -> Self {
        SpaceDelta {
            pinned_snapshot_delta: bytes as i64,
            ..SpaceDelta::ZERO
        }
    }

    /// Delta for snapshot destroy: releases deadlist-pinned bytes.
    #[must_use]
    pub const fn new_snapshot_destroy(bytes: u64) -> Self {
        SpaceDelta {
            pinned_snapshot_delta: -(bytes as i64),
            ..SpaceDelta::ZERO
        }
    }

    /// Accumulate another delta into this one (commutative add).
    pub fn accumulate(&mut self, other: SpaceDelta) {
        self.logical_used_delta = self
            .logical_used_delta
            .saturating_add(other.logical_used_delta);
        self.reserved_delta = self.reserved_delta.saturating_add(other.reserved_delta);
        self.orphan_delta = self.orphan_delta.saturating_add(other.orphan_delta);
        self.pinned_snapshot_delta = self
            .pinned_snapshot_delta
            .saturating_add(other.pinned_snapshot_delta);
    }

    /// Returns `true` if this delta is zero in all fields.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.logical_used_delta == 0
            && self.reserved_delta == 0
            && self.orphan_delta == 0
            && self.pinned_snapshot_delta == 0
    }

    /// Create a delta for punch hole: frees data bytes and releases
    /// UNWRITTEN reservations within the punched range.
    #[must_use]
    pub const fn new_punch_hole(len: u64, reservation_bytes: u64) -> Self {
        SpaceDelta {
            logical_used_delta: -(len as i64),
            reserved_delta: -(reservation_bytes as i64),
            ..SpaceDelta::ZERO
        }
    }
}

impl core::ops::Add for SpaceDelta {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut out = self;
        out.accumulate(rhs);
        out
    }
}

impl core::ops::AddAssign for SpaceDelta {
    fn add_assign(&mut self, rhs: Self) {
        self.accumulate(rhs);
    }
}

// ---------------------------------------------------------------------------
// PoolPhysicalCountersV1 — pool-scoped physical space
// ---------------------------------------------------------------------------

/// Pool-scoped physical space counters, derived from the allocator and
/// cleaner.
///
/// These are *not* per-dataset; they reflect the pool's aggregate physical
/// state.  The coupling rule (§4.2) separates logical ENOSPC from physical
/// blocking/throttling.
///
/// Mounted capacity authority consumes a narrower projection of these fields:
/// only `phys_total_bytes` is an admissible lower-layer capacity ceiling.
/// `phys_free_bytes`, `phys_free_segments`, `phys_reclaimable_bytes`, and
/// `phys_tail_reserved_segments` remain physical-pool pressure and observation
/// inputs, not mounted statfs or write-admission availability claims. Use
/// [`mounted_authority_projection`](Self::mounted_authority_projection) before
/// feeding these counters into mounted `CapacityAuthority` / `SpaceAccounting`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PoolPhysicalCountersV1 {
    /// Immediately allocatable segments (from `SegmentFreeMap`).
    pub phys_free_segments: u64,
    /// `phys_free_segments * SEG_BYTES`.
    pub phys_free_bytes: u64,
    /// Dead bytes in older segments awaiting cleaning.
    pub phys_reclaimable_bytes: u64,
    /// Reserve for cleaner + metadata forward progress.
    pub phys_tail_reserved_segments: u64,
    /// Total pool capacity in segments.
    pub phys_total_segments: u64,
    /// `phys_total_segments * SEG_BYTES`.
    pub phys_total_bytes: u64,
}

impl PoolPhysicalCountersV1 {
    /// Build the physical-pool projection admissible to mounted capacity.
    ///
    /// The mounted authority admits only `phys_total_bytes` from a lower
    /// physical-pool report. Free, reclaimable, and cleaner-watermark fields
    /// can be stale or producer-specific, so this projection recomputes mounted
    /// free-space fields from committed logical consumption. A missing total
    /// capacity (`phys_total_bytes == 0`) therefore fails closed as zero mounted
    /// capacity.
    ///
    /// `phys_free_bytes` in the returned value intentionally carries the
    /// absolute mounted capacity ceiling because `SpaceAccounting` consumes
    /// that field as its physical-capacity bound. The committed counters
    /// provide the consumed side of the mounted statfs/admission calculation.
    #[must_use]
    pub const fn mounted_authority_projection(
        self,
        committed_consumed_bytes: u64,
        block_size_bytes: u64,
    ) -> Self {
        Self::mounted_authority_from_capacity(
            self.phys_total_bytes,
            committed_consumed_bytes,
            block_size_bytes,
        )
    }

    /// Build a mounted capacity projection from an admitted total-capacity
    /// byte ceiling.
    #[must_use]
    pub const fn mounted_authority_from_capacity(
        capacity_ceiling_bytes: u64,
        committed_consumed_bytes: u64,
        block_size_bytes: u64,
    ) -> Self {
        let consumed = if committed_consumed_bytes > capacity_ceiling_bytes {
            capacity_ceiling_bytes
        } else {
            committed_consumed_bytes
        };
        let free_bytes = capacity_ceiling_bytes.saturating_sub(consumed);
        let total_segments = if block_size_bytes == 0 {
            0
        } else {
            capacity_ceiling_bytes / block_size_bytes
        };
        let free_segments = if block_size_bytes == 0 {
            0
        } else {
            free_bytes / block_size_bytes
        };

        PoolPhysicalCountersV1 {
            phys_free_segments: free_segments,
            phys_free_bytes: capacity_ceiling_bytes,
            phys_reclaimable_bytes: 0,
            phys_tail_reserved_segments: 0,
            phys_total_segments: total_segments,
            phys_total_bytes: capacity_ceiling_bytes,
        }
    }

    /// Physical capacity (total minus tail reserve).
    #[must_use]
    pub const fn phys_usable_segments(self) -> u64 {
        self.phys_total_segments
            .saturating_sub(self.phys_tail_reserved_segments)
    }

    /// Physical utilisation ratio [0.0, 1.0] as a fixed-point value
    /// (multiplied by 1_000_000 for 6 decimal places).
    #[must_use]
    pub const fn phys_utilisation_ppm(self) -> u64 {
        if self.phys_total_segments == 0 {
            return 0;
        }
        let used = self
            .phys_total_segments
            .saturating_sub(self.phys_free_segments);
        // Saturating mul to avoid overflow on huge pools.
        (used as u128)
            .saturating_mul(1_000_000)
            .saturating_div(self.phys_total_segments as u128) as u64
    }

    /// Returns `true` if writes should be blocked/throttled due to
    /// physical space pressure.
    #[must_use]
    pub const fn should_block_writes(self, min_free_segments: u64) -> bool {
        self.phys_free_segments < min_free_segments
    }
}

// ---------------------------------------------------------------------------
// SnapshotSpaceRecord — per-snapshot deadlist metadata
// ---------------------------------------------------------------------------

/// Per-snapshot deadlist metadata for O(1) pinned-byte accounting.
///
/// Stored alongside each snapshot dataset record.  The deadlist B+tree
/// tracks extent IDs exclusively pinned by this snapshot; `deadlist_bytes`
/// provides O(1) observability without scanning the tree.
///
/// ## Comparison to ZFS
///
/// ZFS tracks snapshot space via `usedbysnapshots` which requires periodic
/// scanning and can be stale by minutes/hours under heavy write load.
/// This record enables O(1) deadlist-byte queries — the counter is updated
/// atomically with extent allocations and freed-block routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotSpaceRecord {
    /// CommitGroup at which the snapshot was created.
    pub snap_commit_group: u64,
    /// Root pointer of the deadlist B+tree (0 = empty).
    pub deadlist_root_ptr: u64,
    /// Total bytes pinned by this snapshot's deadlist — O(1) observability.
    pub deadlist_bytes: u64,
    /// Number of extent IDs in the deadlist — O(1) observability.
    pub deadlist_count: u64,
    /// Snapshot lifecycle state.
    pub state: SnapshotState,
    /// CommitGroup at which destroy started (0 if ACTIVE).
    pub destroy_commit_group: u64,
}

impl Default for SnapshotSpaceRecord {
    fn default() -> Self {
        Self {
            snap_commit_group: 0,
            deadlist_root_ptr: 0,
            deadlist_bytes: 0,
            deadlist_count: 0,
            state: SnapshotState::Active,
            destroy_commit_group: 0,
        }
    }
}
impl SnapshotSpaceRecord {
    /// Returns `true` if the snapshot is active (accepting new pinned extents).
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, SnapshotState::Active)
    }

    /// Returns `true` if the snapshot is being destroyed.
    #[must_use]
    pub const fn is_destroying(&self) -> bool {
        matches!(self.state, SnapshotState::Destroying)
    }

    /// O(1) read of pinned bytes.
    #[must_use]
    pub const fn bytes_pinned(&self) -> u64 {
        self.deadlist_bytes
    }

    /// Add a pinned extent to the deadlist (O(1)).
    ///
    /// Called when a block's refcount drops to 1 and a live snapshot
    /// references it.  The extent becomes exclusively pinned by this
    /// snapshot.
    ///
    /// Returns `Err` if the snapshot is already DESTROYING.
    pub fn add_deadlist_extent(&mut self, bytes: u64) -> Result<(), SpaceAccountingError> {
        if !self.is_active() {
            return Err(SpaceAccountingError::InvalidArgument);
        }
        self.deadlist_bytes = self.deadlist_bytes.saturating_add(bytes);
        self.deadlist_count = self.deadlist_count.saturating_add(1);
        Ok(())
    }

    /// Remove a pinned extent from the deadlist (O(1)).
    ///
    /// Called when a snapshot is destroyed and its exclusively pinned
    /// extents are freed.
    ///
    /// Returns `Err(SpaceAccountingError::CounterUnderflow)` on underflow.
    pub fn remove_deadlist_extent(&mut self, bytes: u64) -> Result<(), SpaceAccountingError> {
        if bytes > self.deadlist_bytes {
            return Err(SpaceAccountingError::CounterUnderflow {
                counter_name: "deadlist_bytes",
                current_value: self.deadlist_bytes,
                delta: -(bytes as i64),
            });
        }
        self.deadlist_bytes -= bytes;
        self.deadlist_count = self.deadlist_count.saturating_sub(1);
        Ok(())
    }

    /// Mark the snapshot as destroying — no new extents enter this deadlist.
    ///
    /// Records the commit_group at which destroy started.
    pub fn mark_destroying(&mut self, commit_group: u64) {
        self.state = SnapshotState::Destroying;
        self.destroy_commit_group = commit_group;
    }

    /// Compute the [`SpaceDelta`] needed for creating this snapshot.
    ///
    /// Snapshot creation pins currently-live bytes into the deadlist.
    /// Callers should accumulate this delta into the dataset space counters
    /// via [`apply_space_delta`].
    #[must_use]
    pub const fn to_snapshot_create_delta(&self) -> SpaceDelta {
        SpaceDelta::new_snapshot_create(self.deadlist_bytes)
    }

    /// Compute the [`SpaceDelta`] needed for destroying this snapshot.
    ///
    /// Snapshot destroy releases deadlist-pinned bytes back to the dataset.
    /// Callers should accumulate this delta into the dataset space counters
    /// via [`apply_space_delta`].
    #[must_use]
    pub const fn to_snapshot_destroy_delta(&self) -> SpaceDelta {
        SpaceDelta::new_snapshot_destroy(self.deadlist_bytes)
    }
}

/// Lifecycle state of a snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum SnapshotState {
    /// Normal operation; deadlist accepts new pinned extents.
    #[default]
    Active,
    /// Destroy in progress; no new extents enter this deadlist.
    Destroying,
}

impl SnapshotState {
    /// Returns `true` if the snapshot is in the Active state.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, SnapshotState::Active)
    }

    /// Returns `true` if the snapshot is in the Destroying state.
    #[must_use]
    pub const fn is_destroying(self) -> bool {
        matches!(self, SnapshotState::Destroying)
    }
}
// ---------------------------------------------------------------------------
// SpaceDomainCounters — domain-level aggregation
// ---------------------------------------------------------------------------

/// Aggregated counters for a space domain (clone family).
///
/// `statfs()` reports domain-level counters, not per-dataset counters,
/// to prevent double-counting shared blocks across clones.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SpaceDomainCounters {
    /// Sum of `logical_used_bytes` across all datasets in the domain.
    pub domain_logical_used_bytes: u64,
    /// Sum of `pinned_snapshot_bytes` across all snapshots in the domain.
    pub domain_pinned_snapshot_bytes: u64,
    /// Sum of `reserved_bytes` across all datasets.
    pub domain_reserved_bytes: u64,
    /// Sum of `orphan_bytes` across all datasets.
    pub domain_orphan_bytes: u64,
    /// Domain-level hard quota (0 = none).
    pub domain_quota_bytes: u64,
}

impl SpaceDomainCounters {
    /// Total allocated bytes in the domain.
    #[must_use]
    pub const fn domain_alloc_bytes(self) -> u64 {
        self.domain_logical_used_bytes
            .saturating_add(self.domain_reserved_bytes)
            .saturating_add(self.domain_orphan_bytes)
    }
}

// ---------------------------------------------------------------------------
// MutationOp — operation-type-aware admission control
// ---------------------------------------------------------------------------

/// Filesystem mutation operation with a known worst-case byte delta.
///
/// Each variant carries the parameters needed to compute its
/// [`worst_case_byte_delta`](MutationOp::worst_case_byte_delta).  Callers
/// pass a `MutationOp` through [`admission_check_for_op`] before acquiring
/// space, so the admission gate can distinguish reservation-heavy ops
/// (fallocate) from free-space ops (truncate, unlink, punch hole) for
/// correct quota and physical-capacity enforcement.
///
/// ## Comparison to ZFS / Ceph
///
/// - **ZFS**: `object_store_tx_hold_write` estimates space per-operation but does
///   not expose a typed mutation enum; quota enforcement is post-hoc
///   against DSL dataset properties.  TideFS makes the operation type
///   explicit at the admission gate so worst-case deltas are visible
///   before any allocator state is touched.
/// - **Ceph**: OSD `do_op` path has no per-operation space budgeting;
///   ENOSPC surfaces late at the ObjectStore layer.  TideFS budgets
///   per operation at the VFS boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationOp {
    /// New data write (or overwrite).  Worst case: all bytes are new.
    Write { offset: u64, len: u64 },
    /// `fallocate(FALLOC_FL_KEEP_SIZE)`.  Reserves UNWRITTEN extents.
    Fallocate { offset: u64, len: u64 },
    /// Truncate to a new size.
    Truncate { new_size: u64, old_size: u64 },
    /// Unlink (nlink → 0).  Space freed is the file size.
    Unlink { file_size: u64 },
    /// Clone / reflink.  No new logical space consumed.
    Clone,
    /// `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)`.
    /// Releases data bytes and UNWRITTEN reservations in the range.
    PunchHole {
        offset: u64,
        len: u64,
        /// Bytes of the punched range that were UNWRITTEN reservations.
        reservation_bytes: u64,
    },
}

impl MutationOp {
    /// Worst-case byte delta for admission control.
    /// Positive = consumed, negative = freed, zero = neutral.
    #[must_use]
    pub const fn worst_case_byte_delta(self) -> i64 {
        match self {
            Self::Write { len, .. } => len as i64,
            Self::Fallocate { len, .. } => len as i64,
            Self::Truncate { new_size, old_size } => {
                if new_size < old_size {
                    -((old_size - new_size) as i64)
                } else {
                    (new_size - old_size) as i64
                }
            }
            Self::Unlink { file_size } => -(file_size as i64),
            Self::Clone => 0,
            Self::PunchHole { len, .. } => -(len as i64),
        }
    }

    /// Returns `true` if this is a space reservation (`Fallocate`).
    #[must_use]
    pub const fn is_reservation(self) -> bool {
        matches!(self, Self::Fallocate { .. })
    }

    /// Returns `true` if this operation frees space (negative delta).
    #[must_use]
    pub const fn is_freeing(self) -> bool {
        self.worst_case_byte_delta() < 0
    }

    /// Human-readable operation label for trace/logging.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Write { .. } => "write",
            Self::Fallocate { .. } => "fallocate",
            Self::Truncate { .. } => "truncate",
            Self::Unlink { .. } => "unlink",
            Self::Clone => "clone",
            Self::PunchHole { .. } => "punch_hole",
        }
    }

    /// Returns the `SpaceDelta` for this operation.
    /// Callers validate/apply through [`apply_space_delta`].
    #[must_use]
    pub const fn to_space_delta(self) -> SpaceDelta {
        match self {
            Self::Write { len, .. } => SpaceDelta::new_write(len),
            Self::Fallocate { len, .. } => SpaceDelta::new_reservation(len),
            Self::Truncate { new_size, old_size } => {
                if new_size < old_size {
                    SpaceDelta::new_free(old_size - new_size)
                } else {
                    SpaceDelta::new_write(new_size - old_size)
                }
            }
            Self::Unlink { file_size } => SpaceDelta::new_free(file_size),
            Self::Clone => SpaceDelta::ZERO,
            Self::PunchHole {
                offset: _,
                len,
                reservation_bytes,
            } => SpaceDelta::new_punch_hole(len, reservation_bytes),
        }
    }
}

// ---------------------------------------------------------------------------
// Admission control
// ---------------------------------------------------------------------------

/// Outcome of an admission check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionResult {
    /// Operation is admitted; enough space is available.
    Allowed,
    /// Refused: the operation would exceed the quota ceiling.
    QuotaExceeded {
        quota_bytes: u64,
        current_alloc_bytes: u64,
        needed_bytes: u64,
    },
    /// Refused: the operation would exceed physical capacity.
    PhysicalCapacityExceeded {
        phys_avail_bytes: u64,
        needed_bytes: u64,
    },
}

/// Check whether an operation with a given byte delta can be admitted.
///
/// Returns [`AdmissionResult::Allowed`] if the operation fits within quota
/// and physical capacity, or a refusal variant otherwise.
///
/// This is the canonical admission gate — every mutating operation must
/// pass through it before acquiring space.
#[must_use]
pub fn admission_check(
    counters: &DatasetSpaceCountersV1,
    phys_capacity_bytes: u64,
    needed_bytes: u64,
) -> AdmissionResult {
    let current_consumed = counters.total_consumed_bytes();
    let projected = current_consumed.saturating_add(needed_bytes);

    // Quota check.
    if counters.quota_bytes > 0 {
        let ceiling = counters.quota_bytes.saturating_sub(counters.slop_bytes);
        if projected > ceiling {
            return AdmissionResult::QuotaExceeded {
                quota_bytes: counters.quota_bytes,
                current_alloc_bytes: current_consumed,
                needed_bytes,
            };
        }
    }

    // Physical capacity check.
    if projected > phys_capacity_bytes {
        return AdmissionResult::PhysicalCapacityExceeded {
            phys_avail_bytes: phys_capacity_bytes.saturating_sub(current_consumed),
            needed_bytes,
        };
    }

    AdmissionResult::Allowed
}

/// Check whether a [`MutationOp`] can be admitted.
///
/// Wraps [`admission_check`] with operation-type awareness:
/// - Freespace ops (truncate, unlink, punch hole) skip quota/physical
///   gating \u2014 freeing space is always allowed.
/// - Reservation ops (fallocate) are checked against quota with the
///   operation\'s worst-case delta.
/// - Write ops check both quota and physical capacity.
///
/// This is the preferred admission gate at the VFS layer \u2014 it encodes
/// the operation semantics into the check rather than requiring callers
/// to pre-compute worst-case deltas.
#[must_use]
pub fn admission_check_for_op(
    counters: &DatasetSpaceCountersV1,
    phys_capacity_bytes: u64,
    op: MutationOp,
) -> AdmissionResult {
    // Freeing ops are always allowed.
    if op.is_freeing() {
        return AdmissionResult::Allowed;
    }

    let needed = op.worst_case_byte_delta().max(0) as u64;
    admission_check(counters, phys_capacity_bytes, needed)
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by space accounting operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpaceAccountingError {
    /// A counter underflow was detected (e.g. freeing more bytes than
    /// allocated).
    CounterUnderflow {
        counter_name: &'static str,
        current_value: u64,
        delta: i64,
    },
    /// Counters are internally inconsistent.
    InconsistentCounters { reason: &'static str },
    /// Quota ceiling would be exceeded.
    QuotaExceeded {
        quota_bytes: u64,
        requested_bytes: u64,
        available_bytes: u64,
    },
    /// A domain with this ID already exists in the registry.
    DomainAlreadyExists { domain_id: SpaceDomainId },
    /// The requested domain was not found in the registry.
    DomainNotFound { domain_id: SpaceDomainId },
    /// An invalid argument was passed (e.g. NONE domain id).
    InvalidArgument,
}

impl fmt::Display for SpaceAccountingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CounterUnderflow {
                counter_name,
                current_value,
                delta,
            } => write!(
                f,
                "space accounting counter underflow: {counter_name} = {current_value}, delta = {delta}"
            ),
            Self::InconsistentCounters { reason } => {
                write!(f, "inconsistent space accounting counters: {reason}")
            }
            Self::QuotaExceeded {
                quota_bytes,
                requested_bytes,
                available_bytes,
            } => write!(
                f,
                "quota exceeded: quota={quota_bytes}, requested={requested_bytes}, available={available_bytes}"
            ),
            Self::DomainAlreadyExists { domain_id } => {
                write!(f, "domain already exists: {domain_id}")
            }
            Self::DomainNotFound { domain_id } => {
                write!(f, "domain not found: {domain_id}")
            }
            Self::InvalidArgument => {
                write!(f, "invalid argument")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Counter application with validation
// ---------------------------------------------------------------------------

/// Apply a [`SpaceDelta`] to [`DatasetSpaceCountersV1`] with full
/// validation.
///
/// Returns an error on underflow or quota-ceiling violation.  The counters
/// are only mutated if validation passes.
pub fn apply_space_delta(
    counters: &mut DatasetSpaceCountersV1,
    delta: SpaceDelta,
    phys_capacity_bytes: u64,
) -> Result<(), SpaceAccountingError> {
    // Check for underflow on each counter.
    if delta.logical_used_delta < 0 {
        let abs = (-delta.logical_used_delta) as u64;
        if abs > counters.logical_used_bytes {
            return Err(SpaceAccountingError::CounterUnderflow {
                counter_name: "logical_used_bytes",
                current_value: counters.logical_used_bytes,
                delta: delta.logical_used_delta,
            });
        }
    }
    if delta.reserved_delta < 0 {
        let abs = (-delta.reserved_delta) as u64;
        if abs > counters.reserved_bytes {
            return Err(SpaceAccountingError::CounterUnderflow {
                counter_name: "reserved_bytes",
                current_value: counters.reserved_bytes,
                delta: delta.reserved_delta,
            });
        }
    }
    if delta.orphan_delta < 0 {
        let abs = (-delta.orphan_delta) as u64;
        if abs > counters.orphan_bytes {
            return Err(SpaceAccountingError::CounterUnderflow {
                counter_name: "orphan_bytes",
                current_value: counters.orphan_bytes,
                delta: delta.orphan_delta,
            });
        }
    }
    if delta.pinned_snapshot_delta < 0 {
        let abs = (-delta.pinned_snapshot_delta) as u64;
        if abs > counters.pinned_snapshot_bytes {
            return Err(SpaceAccountingError::CounterUnderflow {
                counter_name: "pinned_snapshot_bytes",
                current_value: counters.pinned_snapshot_bytes,
                delta: delta.pinned_snapshot_delta,
            });
        }
    }

    let apply_counter = |counter: u64, delta: i64| -> u64 {
        if delta >= 0 {
            counter.saturating_add(delta as u64)
        } else {
            counter.saturating_sub((-delta) as u64)
        }
    };
    let projected_logical_used =
        apply_counter(counters.logical_used_bytes, delta.logical_used_delta);
    let projected_reserved = apply_counter(counters.reserved_bytes, delta.reserved_delta);
    let projected_orphan = apply_counter(counters.orphan_bytes, delta.orphan_delta);
    let _projected_pinned_snapshot =
        apply_counter(counters.pinned_snapshot_bytes, delta.pinned_snapshot_delta);
    let projected_logical_alloc = projected_logical_used
        .saturating_add(projected_reserved)
        .saturating_add(projected_orphan);
    // pinned_snapshot_bytes is a subset of logical_used_bytes (#638, #649);
    // do not include it in projected_total_consumed for quota/ENOSPC gating.
    let projected_total_consumed = projected_logical_alloc;

    // Check quota ceiling (projected). Pure frees must be allowed even when
    // the current counters are already over a ceiling; otherwise cleanup cannot
    // recover an overcommitted dataset.
    // needed bytes for quota/capacity gating: pinned_snapshot_delta is
    // excluded because snapshot-pinned bytes are a subset of logical_used
    // and must not gate ENOSPC (#638, #649).
    let needed = delta.logical_used_delta.max(0) as u64
        + delta.reserved_delta.max(0) as u64
        + delta.orphan_delta.max(0) as u64;
    if needed > 0 && counters.quota_bytes > 0 {
        let ceiling = counters.quota_bytes.saturating_sub(counters.slop_bytes);
        if projected_total_consumed > ceiling {
            return Err(SpaceAccountingError::QuotaExceeded {
                quota_bytes: counters.quota_bytes,
                requested_bytes: needed,
                available_bytes: ceiling.saturating_sub(counters.total_consumed_bytes()),
            });
        }
    }

    // Physical capacity ceiling.
    if needed > 0 && projected_total_consumed > phys_capacity_bytes {
        return Err(SpaceAccountingError::QuotaExceeded {
            quota_bytes: phys_capacity_bytes,
            requested_bytes: needed,
            available_bytes: phys_capacity_bytes.saturating_sub(counters.total_consumed_bytes()),
        });
    }

    // All checks passed — apply deltas.
    counters.logical_used_bytes = (counters.logical_used_bytes as i64)
        .saturating_add(delta.logical_used_delta)
        .max(0) as u64;
    counters.reserved_bytes = (counters.reserved_bytes as i64)
        .saturating_add(delta.reserved_delta)
        .max(0) as u64;
    counters.orphan_bytes = (counters.orphan_bytes as i64)
        .saturating_add(delta.orphan_delta)
        .max(0) as u64;
    counters.pinned_snapshot_bytes = (counters.pinned_snapshot_bytes as i64)
        .saturating_add(delta.pinned_snapshot_delta)
        .max(0) as u64;

    Ok(())
}

// ---------------------------------------------------------------------------
// DatasetSpaceUsage — BLAKE3-authenticated persistent record
// ---------------------------------------------------------------------------

/// BLAKE3-authenticated persistent per-dataset space usage record.
///
/// This is the on-disk format written through the segment write pipeline.
/// The checksum covers all preceding fields and is verified on read.
///
/// # Layout (72 bytes on disk)
///
/// | Offset | Size | Field |
/// |---|---|---|
/// | 0 | 16 | dataset_id |
/// | 16 | 8 | bytes_used (LE) |
/// | 24 | 8 | bytes_reserved (LE) |
/// | 32 | 8 | commit_group (LE) |
/// | 40 | 32 | checksum (BLAKE3-256) |
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatasetSpaceUsage {
    /// Stable dataset identifier (UUID bytes).
    pub dataset_id: [u8; 16],
    /// Committed bytes consumed by live data in this dataset.
    pub bytes_used: u64,
    /// Bytes reserved via fallocate / UNWRITTEN extents.
    pub bytes_reserved: u64,
    /// Transaction group at which this record was written.
    pub commit_group: u64,
    /// BLAKE3-256 checksum of the preceding 40 bytes.
    pub checksum: [u8; 32],
}

impl DatasetSpaceUsage {
    /// On-disk size in bytes.
    pub const ENCODED_SIZE: usize = 72;

    /// Create a new record with a computed BLAKE3 checksum.
    #[must_use]
    pub fn new(
        dataset_id: [u8; 16],
        bytes_used: u64,
        bytes_reserved: u64,
        commit_group: u64,
    ) -> Self {
        let mut rec = Self {
            dataset_id,
            bytes_used,
            bytes_reserved,
            commit_group,
            checksum: [0u8; 32],
        };
        rec.checksum = rec.compute_checksum();
        rec
    }

    /// Compute the BLAKE3-256 checksum over all fields except checksum.
    #[must_use]
    pub fn compute_checksum(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.dataset_id);
        hasher.update(&self.bytes_used.to_le_bytes());
        hasher.update(&self.bytes_reserved.to_le_bytes());
        hasher.update(&self.commit_group.to_le_bytes());
        hasher.finalize().into()
    }

    /// Verify that the stored checksum matches a fresh computation.
    #[must_use]
    pub fn verify(&self) -> bool {
        self.checksum == self.compute_checksum()
    }

    /// Serialize to a fixed-size 72-byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::ENCODED_SIZE] {
        let mut buf = [0u8; Self::ENCODED_SIZE];
        buf[..16].copy_from_slice(&self.dataset_id);
        buf[16..24].copy_from_slice(&self.bytes_used.to_le_bytes());
        buf[24..32].copy_from_slice(&self.bytes_reserved.to_le_bytes());
        buf[32..40].copy_from_slice(&self.commit_group.to_le_bytes());
        buf[40..72].copy_from_slice(&self.checksum);
        buf
    }

    /// Deserialize from a 72-byte slice. Returns None on length mismatch
    /// or checksum verification failure.
    #[must_use]
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::ENCODED_SIZE {
            return None;
        }
        let mut dataset_id = [0u8; 16];
        dataset_id.copy_from_slice(&buf[..16]);
        let bytes_used = u64::from_le_bytes(buf[16..24].try_into().ok()?);
        let bytes_reserved = u64::from_le_bytes(buf[24..32].try_into().ok()?);
        let commit_group = u64::from_le_bytes(buf[32..40].try_into().ok()?);
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&buf[40..72]);
        let rec = Self {
            dataset_id,
            bytes_used,
            bytes_reserved,
            commit_group,
            checksum,
        };
        if rec.verify() {
            Some(rec)
        } else {
            None
        }
    }

    /// Serialize to a Vec<u8> (requires alloc).
    #[cfg(any(test, feature = "alloc"))]
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── SpaceDomainId ──────────────────────────────────────────────────

    #[test]
    fn space_domain_id_none() {
        assert!(SpaceDomainId::NONE.is_none());
        assert!(!SpaceDomainId::NONE.is_some());
        assert_eq!(SpaceDomainId::default(), SpaceDomainId::NONE);
    }

    #[test]
    fn space_domain_id_some() {
        let d = SpaceDomainId(42);
        assert!(d.is_some());
        assert!(!d.is_none());
    }

    // ── DatasetSpaceCountersV1 ─────────────────────────────────────────

    #[test]
    fn logical_alloc_bytes_sums_correctly() {
        let c = DatasetSpaceCountersV1 {
            logical_used_bytes: 100,
            reserved_bytes: 50,
            orphan_bytes: 10,
            ..Default::default()
        };
        assert_eq!(c.logical_alloc_bytes(), 160);
    }

    #[test]
    fn logical_avail_bytes_with_quota() {
        let c = DatasetSpaceCountersV1 {
            logical_used_bytes: 60,
            quota_bytes: 100,
            slop_bytes: 10,
            ..Default::default()
        };
        // ceiling = 100 - 10 = 90, alloc = 60, avail = 30
        assert_eq!(c.logical_avail_bytes(), 30);
    }

    #[test]
    fn logical_avail_bytes_quota_exhausted() {
        let c = DatasetSpaceCountersV1 {
            logical_used_bytes: 95,
            quota_bytes: 100,
            slop_bytes: 0,
            ..Default::default()
        };
        assert_eq!(c.logical_avail_bytes(), 5);
    }

    #[test]
    fn logical_avail_bytes_quota_full() {
        let c = DatasetSpaceCountersV1 {
            logical_used_bytes: 100,
            quota_bytes: 100,
            ..Default::default()
        };
        assert_eq!(c.logical_avail_bytes(), 0);
    }

    #[test]
    fn logical_avail_bytes_no_quota_returns_max() {
        let c = DatasetSpaceCountersV1 {
            logical_used_bytes: 1000,
            ..Default::default()
        };
        assert_eq!(c.logical_avail_bytes(), u64::MAX);
    }

    #[test]
    fn logical_avail_bytes_with_phys_capacity() {
        let c = DatasetSpaceCountersV1 {
            logical_used_bytes: 500,
            ..Default::default()
        };
        // No quota, phys capacity = 1000, so avail = 500
        assert_eq!(c.logical_avail_bytes_with_phys_capacity(1000), 500);
    }

    #[test]
    fn logical_avail_bytes_quota_takes_precedence_over_phys() {
        let c = DatasetSpaceCountersV1 {
            logical_used_bytes: 50,
            quota_bytes: 80,
            ..Default::default()
        };
        // quota ceiling = 80, phys = 1000 → quota is lower, avail = 30
        assert_eq!(c.logical_avail_bytes_with_phys_capacity(1000), 30);
    }

    #[test]
    fn validate_consistent_counters() {
        let c = DatasetSpaceCountersV1 {
            logical_used_bytes: 100,
            pinned_snapshot_bytes: 50,
            ..Default::default()
        };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn validate_pinned_exceeds_used() {
        let c = DatasetSpaceCountersV1 {
            logical_used_bytes: 50,
            pinned_snapshot_bytes: 100,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_slop_exceeds_quota() {
        let c = DatasetSpaceCountersV1 {
            quota_bytes: 100,
            slop_bytes: 200,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    // ── SpaceDelta ────────────────────────────────────────────────────

    #[test]
    fn space_delta_new_write() {
        let d = SpaceDelta::new_write(4096);
        assert_eq!(d.logical_used_delta, 4096);
        assert_eq!(d.reserved_delta, 0);
        assert_eq!(d.orphan_delta, 0);
        assert_eq!(d.pinned_snapshot_delta, 0);
    }

    #[test]
    fn space_delta_new_reservation() {
        let d = SpaceDelta::new_reservation(8192);
        assert_eq!(d.logical_used_delta, 0);
        assert_eq!(d.reserved_delta, 8192);
    }

    #[test]
    fn space_delta_write_into_unwritten() {
        let d = SpaceDelta::new_write_into_unwritten(4096);
        assert_eq!(d.reserved_delta, -4096);
        assert_eq!(d.logical_used_delta, 0); // no net change
    }

    #[test]
    fn space_delta_new_free() {
        let d = SpaceDelta::new_free(4096);
        assert_eq!(d.logical_used_delta, -4096);
    }

    #[test]
    fn space_delta_accumulate() {
        let mut d = SpaceDelta::new_write(1024);
        d.accumulate(SpaceDelta::new_reservation(512));
        assert_eq!(d.logical_used_delta, 1024);
        assert_eq!(d.reserved_delta, 512);
    }

    #[test]
    fn space_delta_add_operator() {
        let d1 = SpaceDelta::new_write(100);
        let d2 = SpaceDelta::new_reservation(50);
        let d3 = d1 + d2;
        assert_eq!(d3.logical_used_delta, 100);
        assert_eq!(d3.reserved_delta, 50);
    }

    #[test]
    fn space_delta_is_zero() {
        assert!(SpaceDelta::ZERO.is_zero());
        assert!(!SpaceDelta::new_write(1).is_zero());
    }

    #[test]
    fn space_delta_new_snapshot_create() {
        let d = SpaceDelta::new_snapshot_create(4096);
        assert_eq!(d.logical_used_delta, 0);
        assert_eq!(d.reserved_delta, 0);
        assert_eq!(d.orphan_delta, 0);
        assert_eq!(d.pinned_snapshot_delta, 4096);
    }

    #[test]
    fn space_delta_new_snapshot_destroy() {
        let d = SpaceDelta::new_snapshot_destroy(4096);
        assert_eq!(d.logical_used_delta, 0);
        assert_eq!(d.reserved_delta, 0);
        assert_eq!(d.orphan_delta, 0);
        assert_eq!(d.pinned_snapshot_delta, -4096);
    }

    // ── PoolPhysicalCountersV1 ─────────────────────────────────────────

    #[test]
    fn phys_usable_segments_excludes_reserve() {
        let c = PoolPhysicalCountersV1 {
            phys_total_segments: 1000,
            phys_tail_reserved_segments: 10,
            ..Default::default()
        };
        assert_eq!(c.phys_usable_segments(), 990);
    }

    #[test]
    fn phys_utilisation_ppm_half() {
        let c = PoolPhysicalCountersV1 {
            phys_total_segments: 1000,
            phys_free_segments: 500,
            ..Default::default()
        };
        assert_eq!(c.phys_utilisation_ppm(), 500_000);
    }

    #[test]
    fn phys_utilisation_ppm_full() {
        let c = PoolPhysicalCountersV1 {
            phys_total_segments: 1000,
            phys_free_segments: 0,
            ..Default::default()
        };
        assert_eq!(c.phys_utilisation_ppm(), 1_000_000);
    }

    #[test]
    fn phys_utilisation_ppm_empty() {
        let c = PoolPhysicalCountersV1 {
            phys_total_segments: 1000,
            phys_free_segments: 1000,
            ..Default::default()
        };
        assert_eq!(c.phys_utilisation_ppm(), 0);
    }

    #[test]
    fn should_block_writes_below_min() {
        let c = PoolPhysicalCountersV1 {
            phys_free_segments: 5,
            ..Default::default()
        };
        assert!(c.should_block_writes(10));
    }

    #[test]
    fn should_not_block_writes_above_min() {
        let c = PoolPhysicalCountersV1 {
            phys_free_segments: 15,
            ..Default::default()
        };
        assert!(!c.should_block_writes(10));
    }

    #[test]
    fn mounted_physical_pool_input_admits_only_total_capacity() {
        let total = 128 * 4096;
        let consumed = 32 * 4096;
        let stale_pool = PoolPhysicalCountersV1 {
            phys_free_segments: u64::MAX,
            phys_free_bytes: u64::MAX,
            phys_reclaimable_bytes: u64::MAX,
            phys_tail_reserved_segments: u64::MAX,
            phys_total_segments: 1,
            phys_total_bytes: total,
        };

        let projected = stale_pool.mounted_authority_projection(consumed, 4096);

        assert_eq!(projected.phys_total_bytes, total);
        assert_eq!(projected.phys_total_segments, 128);
        assert_eq!(projected.phys_free_segments, 96);
        assert_eq!(projected.phys_free_bytes, total);
        assert_eq!(projected.phys_reclaimable_bytes, 0);
        assert_eq!(projected.phys_tail_reserved_segments, 0);
    }

    #[test]
    fn mounted_physical_pool_input_missing_total_fails_closed() {
        let stale_pool = PoolPhysicalCountersV1 {
            phys_free_segments: u64::MAX,
            phys_free_bytes: u64::MAX,
            phys_reclaimable_bytes: u64::MAX,
            ..Default::default()
        };

        let projected = stale_pool.mounted_authority_projection(4096, 4096);

        assert_eq!(projected.phys_total_bytes, 0);
        assert_eq!(projected.phys_total_segments, 0);
        assert_eq!(projected.phys_free_segments, 0);
        assert_eq!(projected.phys_free_bytes, 0);
        assert!(projected.should_block_writes(1));
    }

    // ── Admission control ──────────────────────────────────────────────

    #[test]
    fn admission_allowed() {
        let counters = DatasetSpaceCountersV1 {
            logical_used_bytes: 50,
            quota_bytes: 200,
            ..Default::default()
        };
        let result = admission_check(&counters, 1000, 30);
        assert_eq!(result, AdmissionResult::Allowed);
    }

    #[test]
    fn admission_quota_exceeded() {
        let counters = DatasetSpaceCountersV1 {
            logical_used_bytes: 90,
            quota_bytes: 100,
            ..Default::default()
        };
        let result = admission_check(&counters, 1000, 20);
        assert!(matches!(result, AdmissionResult::QuotaExceeded { .. }));
    }

    #[test]
    fn admission_physical_capacity_exceeded() {
        let counters = DatasetSpaceCountersV1 {
            logical_used_bytes: 900,
            ..Default::default()
        };
        let result = admission_check(&counters, 1000, 200);
        assert!(matches!(
            result,
            AdmissionResult::PhysicalCapacityExceeded { .. }
        ));
    }

    #[test]
    fn admission_exactly_at_quota_boundary() {
        let counters = DatasetSpaceCountersV1 {
            logical_used_bytes: 100,
            quota_bytes: 100,
            ..Default::default()
        };
        // projected = 100 + 0 = 100, ceiling = 100 - 0 = 100, so allowed
        let result = admission_check(&counters, 1000, 0);
        assert_eq!(result, AdmissionResult::Allowed);
    }

    // ── apply_space_delta ──────────────────────────────────────────────

    #[test]
    fn apply_delta_success() {
        let mut counters = DatasetSpaceCountersV1 {
            logical_used_bytes: 100,
            quota_bytes: 500,
            ..Default::default()
        };
        let delta = SpaceDelta::new_write(50);
        assert!(apply_space_delta(&mut counters, delta, 1000).is_ok());
        assert_eq!(counters.logical_used_bytes, 150);
    }

    #[test]
    fn apply_delta_underflow_rejected() {
        let mut counters = DatasetSpaceCountersV1 {
            logical_used_bytes: 10,
            ..Default::default()
        };
        let delta = SpaceDelta::new_free(50);
        let err = apply_space_delta(&mut counters, delta, 1000).unwrap_err();
        assert!(matches!(err, SpaceAccountingError::CounterUnderflow { .. }));
        // Counters must be unchanged.
        assert_eq!(counters.logical_used_bytes, 10);
    }

    #[test]
    fn apply_delta_quota_exceeded() {
        let mut counters = DatasetSpaceCountersV1 {
            logical_used_bytes: 90,
            quota_bytes: 100,
            ..Default::default()
        };
        let delta = SpaceDelta::new_write(20);
        let err = apply_space_delta(&mut counters, delta, 1000).unwrap_err();
        assert!(matches!(err, SpaceAccountingError::QuotaExceeded { .. }));
        assert_eq!(counters.logical_used_bytes, 90); // unchanged
    }

    #[test]
    fn apply_delta_phys_capacity_exceeded() {
        let mut counters = DatasetSpaceCountersV1 {
            logical_used_bytes: 950,
            ..Default::default()
        };
        let delta = SpaceDelta::new_write(100);
        let err = apply_space_delta(&mut counters, delta, 1000).unwrap_err();
        assert!(matches!(err, SpaceAccountingError::QuotaExceeded { .. }));
    }

    #[test]
    fn apply_delta_allows_free_when_currently_over_capacity() {
        let mut counters = DatasetSpaceCountersV1 {
            logical_used_bytes: 1_200,
            ..Default::default()
        };
        assert!(apply_space_delta(&mut counters, SpaceDelta::new_free(200), 1_000).is_ok());
        assert_eq!(counters.logical_used_bytes, 1_000);
    }

    #[test]
    fn apply_delta_frees_then_writes() {
        let mut counters = DatasetSpaceCountersV1 {
            logical_used_bytes: 100,
            ..Default::default()
        };
        // Free 50, then write 30: net -20 logical_used
        let delta = SpaceDelta::new_free(50);
        assert!(apply_space_delta(&mut counters, delta, 1000).is_ok());
        assert_eq!(counters.logical_used_bytes, 50);

        let delta2 = SpaceDelta::new_write(30);
        assert!(apply_space_delta(&mut counters, delta2, 1000).is_ok());
        assert_eq!(counters.logical_used_bytes, 80);
    }

    #[test]
    fn apply_delta_reservation_flow() {
        let mut counters = DatasetSpaceCountersV1 {
            reserved_bytes: 0,
            ..Default::default()
        };
        // Reserve 100 bytes via fallocate
        assert!(apply_space_delta(&mut counters, SpaceDelta::new_reservation(100), 1000).is_ok());
        assert_eq!(counters.reserved_bytes, 100);
        assert_eq!(counters.logical_alloc_bytes(), 100);

        // Write into the reserved region — no net logical change
        assert!(apply_space_delta(
            &mut counters,
            SpaceDelta::new_write_into_unwritten(60),
            1000
        )
        .is_ok());
        assert_eq!(counters.reserved_bytes, 40);
        assert_eq!(counters.logical_alloc_bytes(), 40);
    }

    #[test]
    fn apply_delta_orphan_flow() {
        let mut counters = DatasetSpaceCountersV1::default();
        // unlink while still open → orphan
        assert!(
            apply_space_delta(&mut counters, SpaceDelta::new_orphan_acquire(200), u64::MAX).is_ok()
        );
        assert_eq!(counters.orphan_bytes, 200);

        // final close → release orphan
        assert!(
            apply_space_delta(&mut counters, SpaceDelta::new_orphan_release(200), u64::MAX).is_ok()
        );
        assert_eq!(counters.orphan_bytes, 0);
    }

    // ── SnapshotSpaceRecord ────────────────────────────────────────────

    #[test]
    fn snapshot_space_record_default() {
        let r = SnapshotSpaceRecord::default();
        assert_eq!(r.snap_commit_group, 0);
        assert_eq!(r.deadlist_bytes, 0);
        assert_eq!(r.deadlist_count, 0);
        assert_eq!(r.state, SnapshotState::Active);
        assert_eq!(r.destroy_commit_group, 0);
    }

    #[test]
    fn snapshot_state_is_active() {
        assert!(SnapshotState::Active.is_active());
        assert!(!SnapshotState::Active.is_destroying());
    }

    #[test]
    fn snapshot_state_is_destroying() {
        assert!(SnapshotState::Destroying.is_destroying());
        assert!(!SnapshotState::Destroying.is_active());
    }

    #[test]
    fn snapshot_space_record_is_active_default() {
        let r = SnapshotSpaceRecord::default();
        assert!(r.is_active());
        assert!(!r.is_destroying());
        assert_eq!(r.bytes_pinned(), 0);
    }

    #[test]
    fn snapshot_space_record_is_destroying_after_mark() {
        let mut r = SnapshotSpaceRecord::default();
        r.mark_destroying(42);
        assert!(r.is_destroying());
        assert!(!r.is_active());
        assert_eq!(r.destroy_commit_group, 42);
    }

    #[test]
    fn snapshot_space_record_add_extent_works() {
        let mut r = SnapshotSpaceRecord::default();
        assert!(r.add_deadlist_extent(4096).is_ok());
        assert_eq!(r.bytes_pinned(), 4096);
        assert_eq!(r.deadlist_count, 1);
    }

    #[test]
    fn snapshot_space_record_add_extent_blocked_when_destroying() {
        let mut r = SnapshotSpaceRecord::default();
        r.mark_destroying(10);
        let err = r.add_deadlist_extent(4096).unwrap_err();
        assert!(matches!(err, SpaceAccountingError::InvalidArgument));
    }

    #[test]
    fn snapshot_space_record_remove_extent_works() {
        let mut r = SnapshotSpaceRecord::default();
        r.add_deadlist_extent(8192).unwrap();
        assert!(r.remove_deadlist_extent(4096).is_ok());
        assert_eq!(r.bytes_pinned(), 4096);
        assert_eq!(r.deadlist_count, 0); // saturating_sub from 1
    }

    #[test]
    fn snapshot_space_record_remove_extent_underflow() {
        let mut r = SnapshotSpaceRecord::default();
        r.add_deadlist_extent(4096).unwrap();
        let err = r.remove_deadlist_extent(8192).unwrap_err();
        assert!(matches!(err, SpaceAccountingError::CounterUnderflow { .. }));
    }

    #[test]
    fn snapshot_space_record_multiple_extents() {
        let mut r = SnapshotSpaceRecord::default();
        for _ in 0..5 {
            r.add_deadlist_extent(1024).unwrap();
        }
        assert_eq!(r.bytes_pinned(), 5120);
        assert_eq!(r.deadlist_count, 5);
    }

    #[test]
    fn snapshot_space_record_to_create_delta() {
        let mut r = SnapshotSpaceRecord::default();
        r.add_deadlist_extent(4096).unwrap();
        let d = r.to_snapshot_create_delta();
        assert_eq!(d.pinned_snapshot_delta, 4096);
    }

    #[test]
    fn snapshot_space_record_to_destroy_delta() {
        let mut r = SnapshotSpaceRecord::default();
        r.add_deadlist_extent(8192).unwrap();
        let d = r.to_snapshot_destroy_delta();
        assert_eq!(d.pinned_snapshot_delta, -8192);
    }

    #[test]
    fn snapshot_space_record_mark_destroying_different_commit_group() {
        let mut r = SnapshotSpaceRecord::default();
        r.mark_destroying(100);
        assert!(r.is_destroying());
        assert_eq!(r.destroy_commit_group, 100);
        r.mark_destroying(200);
        assert_eq!(r.destroy_commit_group, 200);
    }
    // ── SpaceDomainCounters ────────────────────────────────────────────

    #[test]
    fn domain_counters_alloc_bytes() {
        let d = SpaceDomainCounters {
            domain_logical_used_bytes: 100,
            domain_reserved_bytes: 50,
            domain_orphan_bytes: 10,
            ..Default::default()
        };
        assert_eq!(d.domain_alloc_bytes(), 160);
    }

    // ── Display impls ──────────────────────────────────────────────────

    #[test]
    fn display_space_domain_id() {
        assert_eq!(format!("{}", SpaceDomainId(7)), "domain:7");
    }

    #[test]
    fn display_error_underflow() {
        let e = SpaceAccountingError::CounterUnderflow {
            counter_name: "logical_used_bytes",
            current_value: 10,
            delta: -50,
        };
        let s = format!("{e}");
        assert!(s.contains("underflow"));
        assert!(s.contains("logical_used_bytes"));
        assert!(s.contains("10"));
        assert!(s.contains("-50"));
    }

    #[test]
    fn display_error_inconsistent() {
        let e = SpaceAccountingError::InconsistentCounters {
            reason: "test reason",
        };
        assert!(format!("{e}").contains("test reason"));
    }

    #[test]
    fn display_error_quota() {
        let e = SpaceAccountingError::QuotaExceeded {
            quota_bytes: 100,
            requested_bytes: 50,
            available_bytes: 10,
        };
        let s = format!("{e}");
        assert!(s.contains("100"));
        assert!(s.contains("50"));
        assert!(s.contains("10"));
    }

    // ── Saturation edge cases ─────────────────────────────────────────

    #[test]
    fn huge_counters_no_overflow() {
        let c = DatasetSpaceCountersV1 {
            logical_used_bytes: u64::MAX,
            reserved_bytes: 1,
            ..Default::default()
        };
        // saturating_add keeps us at u64::MAX
        assert_eq!(c.logical_alloc_bytes(), u64::MAX);
    }

    #[test]
    fn phys_utilisation_zero_segments() {
        let c = PoolPhysicalCountersV1::default();
        assert_eq!(c.phys_utilisation_ppm(), 0);
    }

    #[test]
    fn delta_accumulate_saturating() {
        let mut d = SpaceDelta {
            logical_used_delta: i64::MAX,
            ..SpaceDelta::ZERO
        };
        d.accumulate(SpaceDelta {
            logical_used_delta: 1,
            ..SpaceDelta::ZERO
        });
        // Saturating add keeps it at i64::MAX; actual value depends on platform
        assert_eq!(d.logical_used_delta, i64::MAX);
    }
}

// ── MutationOp ─────────────────────────────────────────────────────

#[test]
fn mutation_op_write_delta() {
    let op = MutationOp::Write {
        offset: 0,
        len: 4096,
    };
    assert_eq!(op.worst_case_byte_delta(), 4096);
    assert!(!op.is_reservation());
    assert!(!op.is_freeing());
    assert_eq!(op.label(), "write");
    let delta = op.to_space_delta();
    assert_eq!(delta.logical_used_delta, 4096);
    assert_eq!(delta.reserved_delta, 0);
}

#[test]
fn mutation_op_fallocate_is_reservation() {
    let op = MutationOp::Fallocate {
        offset: 0,
        len: 65536,
    };
    assert_eq!(op.worst_case_byte_delta(), 65536);
    assert!(op.is_reservation());
    assert!(!op.is_freeing());
    assert_eq!(op.label(), "fallocate");
    let delta = op.to_space_delta();
    assert_eq!(delta.logical_used_delta, 0);
    assert_eq!(delta.reserved_delta, 65536);
}

#[test]
fn mutation_op_truncate_shrink() {
    let op = MutationOp::Truncate {
        new_size: 100,
        old_size: 10000,
    };
    assert_eq!(op.worst_case_byte_delta(), -9900);
    assert!(!op.is_reservation());
    assert!(op.is_freeing());
    let delta = op.to_space_delta();
    assert_eq!(delta.logical_used_delta, -9900);
}

#[test]
fn mutation_op_truncate_grow() {
    let op = MutationOp::Truncate {
        new_size: 5000,
        old_size: 1000,
    };
    assert_eq!(op.worst_case_byte_delta(), 4000);
    assert!(!op.is_freeing());
    let delta = op.to_space_delta();
    assert_eq!(delta.logical_used_delta, 4000);
}

#[test]
fn mutation_op_unlink_frees() {
    let op = MutationOp::Unlink { file_size: 8192 };
    assert_eq!(op.worst_case_byte_delta(), -8192);
    assert!(op.is_freeing());
    let delta = op.to_space_delta();
    assert_eq!(delta.logical_used_delta, -8192);
}

#[test]
fn mutation_op_clone_neutral() {
    let op = MutationOp::Clone;
    assert_eq!(op.worst_case_byte_delta(), 0);
    assert!(!op.is_freeing());
    assert_eq!(op.label(), "clone");
    let delta = op.to_space_delta();
    assert!(delta.is_zero());
}

#[test]
fn mutation_op_punch_hole_frees_data_and_reservations() {
    let op = MutationOp::PunchHole {
        offset: 0,
        len: 4096,
        reservation_bytes: 1024,
    };
    assert_eq!(op.worst_case_byte_delta(), -4096);
    assert!(op.is_freeing());
    assert_eq!(op.label(), "punch_hole");
    let delta = op.to_space_delta();
    assert_eq!(delta.logical_used_delta, -4096);
    assert_eq!(delta.reserved_delta, -1024);
}

#[test]
fn mutation_op_punch_hole_no_reservations() {
    let op = MutationOp::PunchHole {
        offset: 4096,
        len: 2048,
        reservation_bytes: 0,
    };
    let delta = op.to_space_delta();
    assert_eq!(delta.logical_used_delta, -2048);
    assert_eq!(delta.reserved_delta, 0);
}

// ── admission_check_for_op ─────────────────────────────────────────

#[test]
fn admission_for_op_allows_freeing() {
    let counters = DatasetSpaceCountersV1 {
        logical_used_bytes: 900,
        quota_bytes: 1000,
        ..Default::default()
    };
    let op = MutationOp::Truncate {
        new_size: 100,
        old_size: 900,
    };
    assert_eq!(
        admission_check_for_op(&counters, 2000, op),
        AdmissionResult::Allowed
    );
}

#[test]
fn admission_for_op_blocks_write_over_quota() {
    let counters = DatasetSpaceCountersV1 {
        logical_used_bytes: 900,
        quota_bytes: 1000,
        ..Default::default()
    };
    let op = MutationOp::Write {
        offset: 0,
        len: 200,
    };
    assert_eq!(
        admission_check_for_op(&counters, 2000, op),
        AdmissionResult::QuotaExceeded {
            quota_bytes: 1000,
            current_alloc_bytes: 900,
            needed_bytes: 200
        }
    );
}

#[test]
fn admission_for_op_blocks_fallocate_over_quota() {
    let counters = DatasetSpaceCountersV1 {
        logical_used_bytes: 0,
        reserved_bytes: 900,
        quota_bytes: 1000,
        ..Default::default()
    };
    let op = MutationOp::Fallocate {
        offset: 0,
        len: 200,
    };
    assert_eq!(
        admission_check_for_op(&counters, 2000, op),
        AdmissionResult::QuotaExceeded {
            quota_bytes: 1000,
            current_alloc_bytes: 900,
            needed_bytes: 200
        }
    );
}

#[test]
fn admission_for_op_allows_unlink_when_over_quota() {
    let counters = DatasetSpaceCountersV1 {
        logical_used_bytes: 1000,
        quota_bytes: 1000,
        ..Default::default()
    };
    let op = MutationOp::Unlink { file_size: 400 };
    assert_eq!(
        admission_check_for_op(&counters, 2000, op),
        AdmissionResult::Allowed
    );
}

#[test]
fn admission_for_op_allows_punch_hole() {
    let counters = DatasetSpaceCountersV1 {
        logical_used_bytes: 1000,
        reserved_bytes: 0,
        quota_bytes: 1000,
        ..Default::default()
    };
    let op = MutationOp::PunchHole {
        offset: 0,
        len: 100,
        reservation_bytes: 0,
    };
    assert_eq!(
        admission_check_for_op(&counters, 2000, op),
        AdmissionResult::Allowed
    );
}

// ── punch hole delta ───────────────────────────────────────────────

#[test]
fn delta_new_punch_hole_releases_both() {
    let d = SpaceDelta::new_punch_hole(4096, 1024);
    assert_eq!(d.logical_used_delta, -4096);
    assert_eq!(d.reserved_delta, -1024);
    assert_eq!(d.orphan_delta, 0);
    assert_eq!(d.pinned_snapshot_delta, 0);
    assert!(!d.is_zero());
}

#[test]
fn delta_new_punch_hole_no_reservations() {
    let d = SpaceDelta::new_punch_hole(2048, 0);
    assert_eq!(d.logical_used_delta, -2048);
    assert_eq!(d.reserved_delta, 0);
}

// ── DatasetSpaceUsage ─────────────────────────────────────────────────

#[test]
fn dataset_space_usage_round_trip() {
    let did = [1u8; 16];
    let rec = DatasetSpaceUsage::new(did, 4096, 1024, 42);
    assert!(rec.verify());
    let bytes = rec.to_bytes();
    assert_eq!(bytes.len(), DatasetSpaceUsage::ENCODED_SIZE);
    let rec2 = DatasetSpaceUsage::from_bytes(&bytes).unwrap();
    assert_eq!(rec, rec2);
}

#[test]
fn dataset_space_usage_checksum_detects_corruption() {
    let did = [2u8; 16];
    let rec = DatasetSpaceUsage::new(did, 8192, 0, 7);
    let mut bytes = rec.to_bytes();
    // Flip a bit in the bytes_used field (byte 16)
    bytes[16] ^= 1;
    assert!(DatasetSpaceUsage::from_bytes(&bytes).is_none());
}

#[test]
fn dataset_space_usage_from_bytes_short_input() {
    let short = [0u8; 40];
    assert!(DatasetSpaceUsage::from_bytes(&short).is_none());
}

#[test]
fn dataset_space_usage_new_fields_set() {
    let did = [3u8; 16];
    let rec = DatasetSpaceUsage::new(did, 100, 200, 5);
    assert_eq!(rec.dataset_id, did);
    assert_eq!(rec.bytes_used, 100);
    assert_eq!(rec.bytes_reserved, 200);
    assert_eq!(rec.commit_group, 5);
    assert!(rec.verify());
}

#[test]
fn dataset_space_usage_to_vec_round_trip() {
    let did = [4u8; 16];
    let rec = DatasetSpaceUsage::new(did, 1024 * 1024, 0, 99);
    let vec = rec.to_vec();
    assert_eq!(vec.len(), DatasetSpaceUsage::ENCODED_SIZE);
    let rec2 = DatasetSpaceUsage::from_bytes(&vec).unwrap();
    assert_eq!(rec, rec2);
}

#[test]
fn dataset_space_usage_zero_values() {
    let did = [0u8; 16];
    let rec = DatasetSpaceUsage::new(did, 0, 0, 0);
    assert!(rec.verify());
    let bytes = rec.to_bytes();
    let rec2 = DatasetSpaceUsage::from_bytes(&bytes).unwrap();
    assert_eq!(rec2.bytes_used, 0);
    assert_eq!(rec2.bytes_reserved, 0);
    assert_eq!(rec2.commit_group, 0);
}

#[test]
fn dataset_space_usage_max_values() {
    let did = [0xff; 16];
    let rec = DatasetSpaceUsage::new(did, u64::MAX, u64::MAX, u64::MAX);
    assert!(rec.verify());
    let bytes = rec.to_bytes();
    let rec2 = DatasetSpaceUsage::from_bytes(&bytes).unwrap();
    assert_eq!(rec2.bytes_used, u64::MAX);
    assert_eq!(rec2.bytes_reserved, u64::MAX);
    assert_eq!(rec2.commit_group, u64::MAX);
}
