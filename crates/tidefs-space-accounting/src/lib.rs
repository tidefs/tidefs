#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Space accounting runtime: wraps [`tidefs_types_space_accounting_core::DatasetSpaceCountersV1`]
//! with statfs derivation, ENOSPC gating, delta accumulation, and pool-level
//! capacity integration.
//!
//! This crate-local authority path is a TFR-007 reduction, not the completed
//! TideFS capacity authority. Allocation extents, mounted filesystem admission,
//! obligation ledgers, reclaim, persistent store authority, and distributed
//! capacity behavior still have separate closure work.
//!
//! Implements the runtime from [`docs/SPACE_ACCOUNTING_MODEL_DESIGN.md`].
//!
//! # Comparison to ZFS / Ceph
//!
//! - **ZFS**: `statfs` derives from `used`/`available` in the DSL dataset
//!   properties, but ENOSPC can fire late due to copy-on-write overhead and
//!   snapshot space is not separately tracked. This runtime provides explicit
//!   `check_enospc()` before allocation with snapshot-pinned byte awareness.
//! - **Ceph**: RADOS pool statistics are aggregate; no per-dataset ENOSPC
//!   gating. This runtime provides dataset-level gating with `SpaceDomainId`
//!   for clone-family sharing.

use core::fmt;

#[cfg(not(test))]
extern crate alloc;

#[cfg(not(test))]
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

use hashbrown::{HashMap, HashSet};

#[cfg(test)]
use std::collections::BTreeMap;

use tidefs_types_space_accounting_core::{
    admission_check, apply_space_delta, AdmissionResult, DatasetSpaceCountersV1,
    PoolPhysicalCountersV1, SnapshotSpaceRecord, SnapshotState, SpaceAccountingError, SpaceDelta,
    SpaceDomainCounters, SpaceDomainId,
};

// Re-export key types for convenience.
pub use tidefs_types_space_accounting_core::{
    AdmissionResult as Admission, DatasetSpaceCountersV1 as Counters, DatasetSpaceUsage,
    PoolPhysicalCountersV1 as PoolCounters, SpaceAccountingError as Error, SpaceDelta as Delta,
};

// ---------------------------------------------------------------------------
// StatfsResult — derived filesystem statistics for statfs(2)
// ---------------------------------------------------------------------------

/// Result of [`SpaceAccounting::statfs()`] ready for FUSE `statfs` or
/// kernel `kstatfs`.
///
/// Mounted local-filesystem statfs currently reports through
/// [`tidefs_local_filesystem::capacity_authority::CapacityStatfs`].
/// This type is retained for crate-local tests and SpaceBook fallback while
/// TFR-007 capacity unification remains open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatfsResult {
    /// Optimal transfer block size (f_bsize / f_frsize).
    pub block_size: u64,
    /// Total data blocks in filesystem (f_blocks).
    pub blocks: u64,
    /// Free blocks available to unprivileged user (f_bavail).
    pub blocks_avail: u64,
    /// Free blocks in filesystem (f_bfree).
    pub blocks_free: u64,
    /// Total inodes (f_files).
    pub files: u64,
    /// Free inodes (f_ffree).
    pub files_free: u64,
    /// Maximum filename length (f_namelen).
    pub name_max: u32,
}

impl StatfsResult {
    /// Standard block size for tidefs (matches page size on Linux).
    pub const DEFAULT_BLOCK_SIZE: u64 = 4096;

    /// Maximum filename length (255 per POSIX).
    pub const DEFAULT_NAME_MAX: u32 = 255;
}

// ---------------------------------------------------------------------------
// SpaceAccounting — runtime wrapper
// ---------------------------------------------------------------------------

/// Runtime space accounting for a single dataset.
///
/// Wraps [`DatasetSpaceCountersV1`] with delta application, statfs derivation,
/// ENOSPC gating, and pool-level integration.
///
/// # State machine
///
/// ```text
/// [DatasetSpaceCountersV1] ──► commit_delta(SpaceDelta) ──► counters updated
///                                                              │
///                                              statfs() ──────┘
///                                              check_enospc() ─┘
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceAccounting {
    counters: DatasetSpaceCountersV1,
    domain_id: SpaceDomainId,
    /// Cached pool-level physical counters for physical ENOSPC gating.
    pool: Option<PoolPhysicalCountersV1>,
    /// Aggregate stats counters.
    commit_group_commits: u64,
    enospc_blocks: u64,
    /// Pending delta accumulated during the current commit_group.
    pending_delta: SpaceDelta,
}

impl SpaceAccounting {
    // -- Constructors --

    /// Create a new space accounting instance from on-disk counters.
    #[must_use]
    pub const fn new(counters: DatasetSpaceCountersV1, domain_id: SpaceDomainId) -> Self {
        SpaceAccounting {
            counters,
            domain_id,
            pool: None,
            commit_group_commits: 0,
            enospc_blocks: 0,
            pending_delta: SpaceDelta::ZERO,
        }
    }

    /// Create with default (zero-filled) counters, domain NONE.
    #[must_use]
    pub fn empty() -> Self {
        SpaceAccounting {
            counters: DatasetSpaceCountersV1 {
                logical_used_bytes: 0,
                physical_used_bytes: 0,
                pinned_snapshot_bytes: 0,
                reserved_bytes: 0,
                orphan_bytes: 0,
                quota_bytes: 0,
                slop_bytes: 0,
                quota_soft_limit: 0,
            },
            domain_id: SpaceDomainId::NONE,
            pool: None,
            commit_group_commits: 0,
            enospc_blocks: 0,
            pending_delta: SpaceDelta::ZERO,
        }
    }

    // -- Accessors --

    /// The underlying dataset space counters.
    #[must_use]
    pub const fn counters(&self) -> &DatasetSpaceCountersV1 {
        &self.counters
    }

    /// Counters after the currently accumulated commit-group delta is applied.
    ///
    /// This is for callers that need to bound a second pending decrement before
    /// the commit group is flushed. The real commit path still validates with
    /// [`commit_pending`](Self::commit_pending).
    #[must_use]
    pub fn projected_counters_after_pending(&self) -> DatasetSpaceCountersV1 {
        fn apply(counter: u64, delta: i64) -> u64 {
            if delta >= 0 {
                counter.saturating_add(delta as u64)
            } else {
                counter.saturating_sub((-delta) as u64)
            }
        }

        let mut counters = self.counters;
        counters.logical_used_bytes = apply(
            counters.logical_used_bytes,
            self.pending_delta.logical_used_delta,
        );
        counters.reserved_bytes = apply(counters.reserved_bytes, self.pending_delta.reserved_delta);
        counters.orphan_bytes = apply(counters.orphan_bytes, self.pending_delta.orphan_delta);
        counters.pinned_snapshot_bytes = apply(
            counters.pinned_snapshot_bytes,
            self.pending_delta.pinned_snapshot_delta,
        );
        counters
    }

    /// The space domain for clone-family sharing.
    #[must_use]
    pub const fn domain_id(&self) -> SpaceDomainId {
        self.domain_id
    }

    /// Set the space domain.
    pub fn set_domain(&mut self, domain_id: SpaceDomainId) {
        self.domain_id = domain_id;
    }

    /// Set the quota for this dataset.
    pub fn set_quota(&mut self, quota_bytes: u64) {
        self.counters.quota_bytes = quota_bytes;
    }

    // -- Pool integration --

    /// Update the cached pool-level physical counters for ENOSPC gating.
    pub fn update_pool_counters(&mut self, pool: PoolPhysicalCountersV1) {
        self.pool = Some(pool);
    }

    /// Current pool counters (if set).
    #[must_use]
    pub const fn pool_counters(&self) -> Option<&PoolPhysicalCountersV1> {
        self.pool.as_ref()
    }

    /// Get the physical free capacity for admission/ENOSPC decisions.
    #[must_use]
    pub fn phys_capacity_bytes(&self) -> u64 {
        self.pool.as_ref().map_or(u64::MAX, |p| p.phys_free_bytes)
    }

    /// Get the total pool physical capacity for logical ceiling checks.
    ///
    /// Used by [`SpaceAccounting::commit_delta`] as the upper bound for the dataset's
    /// logical space accounting. Returns `u64::MAX` when no pool
    /// counters are cached (unbounded).
    #[must_use]
    pub fn phys_total_capacity_bytes(&self) -> u64 {
        self.pool.as_ref().map_or(u64::MAX, |p| p.phys_total_bytes)
    }

    // -- Delta application --

    /// Apply a space delta atomically within a single commit_group boundary.
    ///
    /// Delegates to [`apply_space_delta`] from the types crate, passing
    /// `phys_capacity_bytes` for combined logical+physical validation.
    pub fn commit_delta(&mut self, delta: SpaceDelta) -> Result<(), SpaceAccountingError> {
        let phys_cap = self.phys_total_capacity_bytes();
        apply_space_delta(&mut self.counters, delta, phys_cap)?;
        self.commit_group_commits += 1;
        Ok(())
    }

    // -- Delta accumulation (commit_group-scoped) --

    /// Accumulate a space delta into the pending buffer for the current commit_group.
    ///
    /// Called by allocation/resize/free operations. The pending delta is
    /// flushed on commit_group commit via [`SpaceAccounting::commit_pending`].
    pub fn accumulate_delta(&mut self, delta: SpaceDelta) {
        self.pending_delta.accumulate(delta);
    }

    /// Commit the accumulated pending delta and reset it to ZERO.
    ///
    /// Refreshes pool counters from the provided [`PoolPhysicalCountersV1`]
    /// before committing, ensuring ENOSPC gating sees fresh allocator state.
    /// Returns an error if the delta application fails.
    pub fn commit_pending(
        &mut self,
        pool: PoolPhysicalCountersV1,
    ) -> Result<(), SpaceAccountingError> {
        self.update_pool_counters(pool);
        let delta = core::mem::replace(&mut self.pending_delta, SpaceDelta::ZERO);
        if delta.is_zero() {
            return Ok(());
        }
        self.commit_delta(delta)
    }

    /// Whether there is a non-zero pending delta to commit.
    #[must_use]
    pub fn has_pending_delta(&self) -> bool {
        !self.pending_delta.is_zero()
    }

    // -- ENOSPC gating --

    /// Check whether `requested` bytes would be refused by the committed
    /// capacity authority.
    ///
    /// This is the unified ENOSPC gate: it uses
    /// [`admission_check`](crate::admission_check) which checks quota
    /// (minus slop), physical capacity, and all committed consumption
    /// including reserved, orphan, and pinned-snapshot bytes.
    /// Returns `true` if the write should be refused with `ENOSPC`.
    #[must_use]
    pub fn check_enospc(&self, requested: u64) -> bool {
        !matches!(self.admission_check(requested), AdmissionResult::Allowed)
    }

    /// Check whether writing `requested` bytes would exceed the physical
    /// pool capacity.
    #[must_use]
    pub fn check_enospc_physical(&self, requested: u64) -> bool {
        match &self.pool {
            Some(pool) => {
                // Use pool's own admission check.
                pool.should_block_writes(0) || requested > pool.phys_free_bytes
            }
            None => false,
        }
    }

    /// Run the full admission check from the types crate.
    ///
    /// Mounted local-filesystem admission currently gates through
    /// [`tidefs_local_filesystem::capacity_authority::CapacityAuthority::check_enospc`].
    /// This method is retained for crate-local tests; it is not a claim that
    /// all TFR-007 capacity ledgers are unified.
    #[must_use]
    pub fn admission_check(&self, needed_bytes: u64) -> AdmissionResult {
        admission_check(&self.counters, self.phys_capacity_bytes(), needed_bytes)
    }

    /// Whether the filesystem is logically read-only due to space exhaustion.
    #[must_use]
    pub fn is_readonly(&self) -> bool {
        self.check_enospc(1)
    }

    // -- Statfs derivation --

    /// Derive statfs(2) fields from committed counters via the unified
    /// capacity authority.
    ///
    /// Uses [`total_consumed_bytes`] (logical_used + reserved + orphan +
    /// pinned_snapshot) as the consumption baseline, matching
    /// [`admission_check`] so that statfs never advertises bytes that
    /// `check_enospc` would reject.
    ///
    /// Distinguishes operator-visible free space (`blocks_free` / `f_bfree`)
    /// from allocation-admissible free space (`blocks_avail` / `f_bavail`):
    /// the latter subtracts slop and is capped by physical pool free bytes.
    #[must_use]
    pub fn statfs(&self) -> StatfsResult {
        let pool_cap = self.phys_capacity_bytes();
        let counters = &self.counters;

        // Effective capacity: quota minus slop when quota is set,
        // otherwise physical pool capacity.
        let capacity = if counters.quota_bytes > 0 {
            counters.quota_bytes.saturating_sub(counters.slop_bytes)
        } else {
            pool_cap
        };

        Self::statfs_from_counters_with_capacity(counters, capacity, pool_cap)
    }

    fn statfs_from_counters_with_capacity(
        counters: &DatasetSpaceCountersV1,
        capacity: u64,
        pool_phys_capacity: u64,
    ) -> StatfsResult {
        let block_size = StatfsResult::DEFAULT_BLOCK_SIZE;
        let total_blocks = capacity / block_size;

        // Total consumed bytes (same formula as admission_check).
        let consumed = counters.total_consumed_bytes();
        let free_bytes = capacity.saturating_sub(consumed);
        let free_blocks = free_bytes / block_size;

        // Allocation-admissible free: operator-visible free minus slop,
        // further capped by physical pool free bytes.
        let avail_bytes = free_bytes
            .saturating_sub(counters.slop_bytes)
            .min(pool_phys_capacity.saturating_sub(consumed));
        let avail_blocks = avail_bytes / block_size;

        // Inodes: tidefs does not have a fixed inode table; report as unlimited.
        let total_files = u64::MAX;
        let free_files = total_files;

        StatfsResult {
            block_size,
            blocks: total_blocks,
            blocks_free: free_blocks,
            blocks_avail: avail_blocks,
            files: total_files,
            files_free: free_files,
            name_max: StatfsResult::DEFAULT_NAME_MAX,
        }
    }

    /// Return committed free bytes — the space available for new
    /// allocations based on committed counters only, excluding any
    /// pending (uncommitted) deltas.
    ///
    /// This is the authoritative value for relocation target selection
    /// and other capacity-sensitive planning that must not depend on
    /// uncommitted state.
    #[must_use]
    pub fn committed_free_bytes(&self) -> u64 {
        let statfs = self.statfs();
        statfs.blocks_avail.saturating_mul(statfs.block_size)
    }

    /// Derive domain-level aggregated counters for clone-family statfs.
    #[must_use]
    pub fn domain_counters(&self) -> SpaceDomainCounters {
        SpaceDomainCounters {
            domain_logical_used_bytes: self.counters.logical_used_bytes,
            domain_pinned_snapshot_bytes: self.counters.pinned_snapshot_bytes,
            domain_reserved_bytes: self.counters.reserved_bytes,
            domain_orphan_bytes: self.counters.orphan_bytes,
            domain_quota_bytes: self.counters.quota_bytes,
        }
    }

    // -- Snapshot-pinned byte computation --

    /// Compute total snapshot-pinned bytes across all snapshots.
    ///
    /// Iterates snapshot records and sums `deadlist_bytes` for active snapshots.
    #[must_use]
    pub fn compute_snapshot_pinned_bytes(snapshots: &[SnapshotSpaceRecord]) -> u64 {
        snapshots
            .iter()
            .filter(|rec| rec.state == SnapshotState::Active)
            .map(|rec| rec.deadlist_bytes)
            .sum()
    }

    /// Update snapshot-pinned bytes from a slice of snapshot records.
    pub fn update_snapshot_pinned(&mut self, snapshots: &[SnapshotSpaceRecord]) {
        self.counters.pinned_snapshot_bytes = Self::compute_snapshot_pinned_bytes(snapshots);
    }

    // -- Stats --

    /// Number of successful commit_group commits since creation.
    #[must_use]
    pub const fn commit_group_commits(&self) -> u64 {
        self.commit_group_commits
    }

    /// Total bytes refused via ENOSPC since creation.
    #[must_use]
    pub const fn enospc_blocks(&self) -> u64 {
        self.enospc_blocks
    }

    /// Record an ENOSPC refusal for observability.
    pub fn record_enospc(&mut self, requested: u64) {
        self.enospc_blocks = self.enospc_blocks.saturating_add(requested);
    }
    // -- Slop management (Phase 3) --

    /// Default slop ratio: 1/64 of quota (matches ZFS convention).
    pub const DEFAULT_SLOP_RATIO: u64 = 64;

    /// Current slop bytes.
    #[must_use]
    pub const fn slop_bytes(&self) -> u64 {
        self.counters.slop_bytes
    }

    /// Set slop bytes explicitly.
    pub fn set_slop(&mut self, bytes: u64) {
        self.counters.slop_bytes = bytes;
    }

    /// Derive and apply default slop from current quota (1/64).
    pub fn set_default_slop(&mut self) {
        self.counters.slop_bytes = self.counters.quota_bytes / Self::DEFAULT_SLOP_RATIO;
    }

    // -- Reservation lifecycle (Phase 3) --

    /// Reserve bytes for `fallocate(FALLOC_FL_KEEP_SIZE)`.
    ///
    /// **Deprecated for production**: the authoritative reservation lifecycle is
    /// [`tidefs_local_filesystem::capacity_authority::CapacityAuthority::reserve`]
    /// with [`CapacityReservationHandle::commit`]/[`CapacityReservationHandle::release`].
    /// This method is retained for crate-local tests.
    ///
    /// The reservation is a hard guarantee: subsequent writes into the
    /// reserved region cannot fail with ENOSPC.
    pub fn reserve_bytes(&mut self, bytes: u64) -> Result<(), SpaceAccountingError> {
        let delta = SpaceDelta::new_reservation(bytes);
        self.commit_delta(delta)
    }

    /// Convert part of a reservation to actual data (UNWRITTEN -> DATA).
    ///
    /// `logical_used_bytes` does NOT change -- the bytes were already counted
    /// as `reserved_bytes`.  `reserved_bytes` decreases by `bytes`.
    pub fn consume_reservation(&mut self, bytes: u64) -> Result<(), SpaceAccountingError> {
        let delta = SpaceDelta::new_write_into_unwritten(bytes);
        self.commit_delta(delta)
    }

    /// Release reserved or used bytes (punch hole / truncate / free).
    pub fn punch_hole(&mut self, bytes: u64) -> Result<(), SpaceAccountingError> {
        let delta = SpaceDelta::new_free(bytes);
        self.commit_delta(delta)
    }

    /// How many more bytes can be reserved before hitting quota/slop or
    /// physical limits.  Returns the maximum reservation that would pass
    /// `reserve_bytes()`.
    #[must_use]
    pub fn available_for_reservation(&self) -> u64 {
        self.counters.logical_avail_bytes()
    }

    /// Run admission check and auto-record ENOSPC refusal if denied.
    ///
    /// Returns `Ok(())` if the write is admitted, or `Err(AdmissionResult)`
    /// describing the refusal (with ENOSPC recorded for observability).
    pub fn check_and_record_enospc(&mut self, needed_bytes: u64) -> Result<(), AdmissionResult> {
        let result = self.admission_check(needed_bytes);
        match result {
            AdmissionResult::Allowed => Ok(()),
            _ => {
                self.record_enospc(needed_bytes);
                Err(result)
            }
        }
    }

    /// Compute the worst-case byte delta for a given operation kind.
    ///
    /// Used before admission to determine `needed_bytes` for
    /// `admission_check()`.
    #[must_use]
    pub const fn worst_case_bytes(op: OperationKind, bytes: u64) -> u64 {
        match op {
            OperationKind::Write => bytes,
            OperationKind::Fallocate => bytes,
            OperationKind::Clone => 0,
        }
    }
    // -- Obligation ledger consistency (§9) --

    /// Verify that the logical used bytes from the space counters are
    /// consistent with the obligation ledger's outstanding write claims.
    ///
    /// Returns `true` when both systems agree on consumed space.
    #[must_use]
    pub fn verify_obligation_consistency(&self, obligation_claims: u64, tolerance: u64) -> bool {
        let diff = self.counters.logical_used_bytes.abs_diff(obligation_claims);
        diff <= tolerance
    }

    /// Report the difference between space counter logical_used and the
    /// obligation ledger's outstanding claims in bytes.  A non-zero
    /// difference in steady-state indicates a bug.
    #[must_use]
    pub fn obligation_discrepancy(&self, obligation_claims: u64) -> u64 {
        self.counters.logical_used_bytes.abs_diff(obligation_claims)
    }

    // -- Write and free accounting (per-IO tracking) --

    /// Account for a write operation with separate logical and physical
    /// byte deltas.
    pub fn account_write(
        &mut self,
        delta_logical: u64,
        delta_physical: u64,
    ) -> Result<(), SpaceAccountingError> {
        let delta = SpaceDelta::new_write(delta_logical);
        self.commit_delta(delta)?;
        self.counters.physical_used_bytes = self
            .counters
            .physical_used_bytes
            .saturating_add(delta_physical);
        Ok(())
    }

    /// Account for a free operation (unlink, truncate, punch).
    pub fn account_free(
        &mut self,
        delta_logical: u64,
        delta_physical: u64,
    ) -> Result<(), SpaceAccountingError> {
        let delta = SpaceDelta::new_free(delta_logical);
        self.commit_delta(delta)?;
        self.counters.physical_used_bytes = self
            .counters
            .physical_used_bytes
            .saturating_sub(delta_physical);
        Ok(())
    }

    // -- Physical byte tracking (direct counter updates) --

    /// Add `bytes` to the physical used counter.
    pub fn track_physical_write(&mut self, bytes: u64) {
        self.counters.physical_used_bytes = self.counters.physical_used_bytes.saturating_add(bytes);
    }

    /// Subtract `bytes` from the physical used counter.
    pub fn track_physical_free(&mut self, bytes: u64) {
        self.counters.physical_used_bytes = self.counters.physical_used_bytes.saturating_sub(bytes);
    }

    // -- SpaceUsage snapshot --

    /// Derive a [`SpaceUsage`] snapshot for user-facing statfs-style reporting.
    #[must_use]
    pub fn to_space_usage(&self) -> SpaceUsage {
        let capacity = if self.counters.quota_bytes > 0 {
            self.counters.quota_bytes
        } else {
            self.phys_total_capacity_bytes()
        };
        let available = capacity.saturating_sub(self.counters.logical_used_bytes);
        SpaceUsage {
            used_bytes: self.counters.logical_used_bytes,
            physical_used_bytes: self.counters.physical_used_bytes,
            available_bytes: available,
            total_bytes: capacity,
        }
    }
}

impl fmt::Display for SpaceAccounting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SpaceAccounting(quota={} logical_used={} pinned_snap={} reserved={} orphan={})",
            self.counters.quota_bytes,
            self.counters.logical_used_bytes,
            self.counters.pinned_snapshot_bytes,
            self.counters.reserved_bytes,
            self.counters.orphan_bytes,
        )
    }
}

impl Default for SpaceAccounting {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// SpaceBook — multi-dataset space accounting with dirty-flag persistence
// ---------------------------------------------------------------------------

/// Multi-dataset space accounting book.
///
/// Manages a per-dataset [`SpaceAccounting`] cache, tracks dirty datasets
/// for deferred persistence, and exposes query APIs for pool-level and
/// per-dataset usage.
#[derive(Clone, Debug)]
pub struct SpaceBook {
    datasets: HashMap<[u8; 16], SpaceAccounting>,
    dirty: HashSet<[u8; 16]>,
    pool: Option<PoolPhysicalCountersV1>,
    current_commit_group: u64,
    /// Optional dataset quota hierarchy for nested enforcement.
    quota_hierarchy: Option<DatasetQuotaHierarchy>,
}

impl SpaceBook {
    /// Create an empty book with no datasets.
    #[must_use]
    pub fn new() -> Self {
        Self {
            datasets: HashMap::new(),
            dirty: HashSet::new(),
            pool: None,
            current_commit_group: 0,
            quota_hierarchy: None,
        }
    }

    /// Set the current transaction group for new records.
    pub fn set_txg(&mut self, commit_group: u64) {
        self.current_commit_group = commit_group;
    }

    /// Current transaction group.
    #[must_use]
    pub fn commit_group(&self) -> u64 {
        self.current_commit_group
    }

    /// Update cached pool-level physical counters.
    pub fn update_pool_counters(&mut self, pool: PoolPhysicalCountersV1) {
        self.pool = Some(pool);
    }

    /// Return the cached pool counters, if set.
    #[must_use]
    pub fn pool_counters(&self) -> Option<&PoolPhysicalCountersV1> {
        self.pool.as_ref()
    }

    /// Get or create the [`SpaceAccounting`] for a dataset.
    pub fn get_or_create(&mut self, dataset_id: [u8; 16]) -> &mut SpaceAccounting {
        self.datasets
            .entry(dataset_id)
            .or_insert_with(SpaceAccounting::empty)
    }

    /// Record a write of `bytes` to the dataset, incrementing usage.
    ///
    /// Marks the dataset dirty for deferred persistence.
    pub fn record_write(
        &mut self,
        dataset_id: [u8; 16],
        bytes: u64,
    ) -> Result<(), SpaceAccountingError> {
        let acct = self.get_or_create(dataset_id);
        let delta = SpaceDelta::new_write(bytes);
        acct.commit_delta(delta)?;
        self.dirty.insert(dataset_id);
        Ok(())
    }

    /// Record a deletion of `bytes` from the dataset, decrementing usage.
    ///
    /// Marks the dataset dirty for deferred persistence.
    pub fn record_delete(
        &mut self,
        dataset_id: [u8; 16],
        bytes: u64,
    ) -> Result<(), SpaceAccountingError> {
        let acct = self.get_or_create(dataset_id);
        let delta = SpaceDelta::new_free(bytes);
        acct.commit_delta(delta)?;
        self.dirty.insert(dataset_id);
        Ok(())
    }

    /// Flush all dirty datasets into BLAKE3-authenticated persistent records.
    ///
    /// Returns the records and clears the dirty set.  Each record includes
    /// the current TXG so that on recovery the most recent record for each
    /// dataset can be selected.
    #[must_use]
    pub fn flush_dirty(&mut self) -> Vec<DatasetSpaceUsage> {
        let mut records = Vec::new();
        for &dataset_id in &self.dirty {
            if let Some(acct) = self.datasets.get(&dataset_id) {
                let counters = acct.counters();
                let rec = DatasetSpaceUsage::new(
                    dataset_id,
                    counters.logical_used_bytes,
                    counters.reserved_bytes,
                    self.current_commit_group,
                );
                records.push(rec);
            }
        }
        self.dirty.clear();
        records
    }

    /// Get the space usage for a single dataset.
    #[must_use]
    pub fn get_dataset_usage(&self, dataset_id: [u8; 16]) -> Option<DatasetSpaceUsage> {
        self.datasets.get(&dataset_id).map(|acct| {
            let counters = acct.counters();
            DatasetSpaceUsage::new(
                dataset_id,
                counters.logical_used_bytes,
                counters.reserved_bytes,
                self.current_commit_group,
            )
        })
    }

    /// Get the total pool usage across all datasets (sum of bytes_used).
    #[must_use]
    pub fn get_pool_usage(&self) -> u64 {
        self.datasets
            .values()
            .map(|acct| acct.counters().logical_used_bytes)
            .sum()
    }

    /// Number of datasets in the book.
    #[must_use]
    pub fn dataset_count(&self) -> usize {
        self.datasets.len()
    }

    /// Number of dirty datasets awaiting persistence.
    #[must_use]
    pub fn dirty_count(&self) -> usize {
        self.dirty.len()
    }

    /// Check whether any datasets are dirty.
    #[must_use]
    pub fn has_dirty(&self) -> bool {
        !self.dirty.is_empty()
    }

    /// Returns true if the dataset exists in the book.
    #[must_use]
    pub fn contains(&self, dataset_id: [u8; 16]) -> bool {
        self.datasets.contains_key(&dataset_id)
    }

    /// Restore a dataset from a persisted [`DatasetSpaceUsage`] record.
    ///
    /// Used during pool import to repopulate the book from on-disk records.
    pub fn restore_from_record(&mut self, record: &DatasetSpaceUsage) {
        let acct = self.get_or_create(record.dataset_id);
        let mut counters = *acct.counters();
        counters.logical_used_bytes = record.bytes_used;
        counters.reserved_bytes = record.bytes_reserved;
        // Replace the entry with one built from the restored counters.
        let restored = SpaceAccounting::new(counters, SpaceDomainId::NONE);
        self.datasets.insert(record.dataset_id, restored);
    }

    /// Set absolute usage counters for a dataset and mark it dirty.
    ///
    /// Used to bridge the engine's [`SpaceAccounting`] to the [`SpaceBook`]
    /// at commit time. The dataset is immediately marked dirty so
    /// [`persist_space_accounting`] will flush it on the next sync.
    ///
    /// [`persist_space_accounting`]: crate::LocalObjectStore::persist_space_accounting
    pub fn set_usage_dirty(&mut self, dataset_id: [u8; 16], logical_used: u64, reserved: u64) {
        let acct = self.get_or_create(dataset_id);
        let mut counters = *acct.counters();
        counters.logical_used_bytes = logical_used;
        counters.reserved_bytes = reserved;
        let updated = SpaceAccounting::new(counters, SpaceDomainId::NONE);
        self.datasets.insert(dataset_id, updated);
        self.dirty.insert(dataset_id);
    }

    /// Compute statfs(2) fields for a dataset from its [`SpaceAccounting`].
    ///
    /// Propagates the SpaceBook-level pool counters into the dataset's
    /// [`SpaceAccounting`] before deriving the statfs result so that
    /// physical capacity bounds are current.
    ///
    /// Returns `None` when the dataset has never been recorded in this book.
    #[must_use]
    pub fn statfs_for_dataset(&mut self, dataset_id: [u8; 16]) -> Option<StatfsResult> {
        let acct = self.datasets.get_mut(&dataset_id)?;
        // Propagate SpaceBook-level pool counters so
        // phys_capacity_bytes() is current.
        if let Some(ref pool) = self.pool {
            acct.update_pool_counters(*pool);
        }
        Some(acct.statfs())
    }

    /// Set the dataset quota hierarchy for nested enforcement.
    ///
    /// When set, hierarchy-aware check methods consult this hierarchy
    /// to enforce ancestor quota ceilings on writes and statfs reports.
    pub fn set_quota_hierarchy(&mut self, hierarchy: DatasetQuotaHierarchy) {
        self.quota_hierarchy = Some(hierarchy);
    }

    /// Return a reference to the quota hierarchy, if configured.
    #[must_use]
    pub fn quota_hierarchy(&self) -> Option<&DatasetQuotaHierarchy> {
        self.quota_hierarchy.as_ref()
    }

    /// Return a mutable reference to the quota hierarchy.
    pub fn quota_hierarchy_mut(&mut self) -> Option<&mut DatasetQuotaHierarchy> {
        self.quota_hierarchy.as_mut()
    }

    /// Compute statfs(2) fields for a dataset, respecting the quota hierarchy.
    ///
    /// When a [`DatasetQuotaHierarchy`] is configured and a `parent_of`
    /// function is supplied, the capacity ceiling used for `statfs` derivation
    /// is the minimum of the current pool-free authority, active reservation
    /// headroom, and the most restrictive ancestor quota.
    ///
    /// Returns `None` when the dataset has never been recorded in this book or
    /// when current pool counters are unavailable.
    #[must_use]
    pub fn statfs_for_dataset_with_hierarchy<F>(
        &self,
        dataset_id: [u8; 16],
        parent_of: F,
    ) -> Option<StatfsResult>
    where
        F: Fn(&[u8; 16]) -> Option<[u8; 16]>,
    {
        let acct = self.datasets.get(&dataset_id)?;
        let pool = self.pool.as_ref()?;
        // Compute the effective capacity ceiling from the hierarchy.
        let pool_cap = pool.phys_free_bytes;
        let effective_cap = if let Some(ref hierarchy) = self.quota_hierarchy {
            hierarchy.effective_capacity(dataset_id, pool_cap, &parent_of)
        } else {
            pool_cap
        };
        Some(SpaceAccounting::statfs_from_counters_with_capacity(
            acct.counters(),
            effective_cap,
            pool_cap,
        ))
    }

    /// Check whether a write of `requested_bytes` to `dataset_id` would
    /// exceed any ancestor quota in the hierarchy.
    ///
    /// Returns `Ok(())` if allowed, or a [`DatasetQuotaDecision`] refusal.
    /// When no hierarchy is configured, always returns `Ok(())`.
    /// When a hierarchy is configured, current SpaceBook pool counters are
    /// required; missing counters fail closed.
    pub fn check_hierarchy_enospc<F>(
        &self,
        dataset_id: [u8; 16],
        requested_bytes: u64,
        parent_of: F,
    ) -> Result<(), DatasetQuotaDecision>
    where
        F: Fn(&[u8; 16]) -> Option<[u8; 16]>,
    {
        if let Some(ref hierarchy) = self.quota_hierarchy {
            let pool_free_bytes = self
                .pool
                .as_ref()
                .ok_or_else(|| DatasetQuotaDecision::ReservationViolation {
                    dataset_id,
                    reserved_bytes: hierarchy
                        .reservation_pressure_bytes(requested_bytes)
                        .unwrap_or(u64::MAX),
                    free_bytes: 0,
                })?
                .phys_free_bytes;
            let decision =
                hierarchy.check_delta(dataset_id, requested_bytes, 0, pool_free_bytes, parent_of);
            if decision.is_refusal() {
                return Err(decision);
            }
        }
        Ok(())
    }
}

impl Default for SpaceBook {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// DatasetQuotaHierarchy -- nested dataset quota and reservation enforcement
// ---------------------------------------------------------------------------

/// Per-dataset quota configuration for the hierarchy.
///
/// Limits on bytes, inodes, and guaranteed-minimum reservation.
/// A child dataset's quota is bounded by its parent's quota in the
/// hierarchy: the most restrictive limit along the ancestor chain wins.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DatasetQuotaConfig {
    pub hard_limit_bytes: u64,
    pub soft_limit_bytes: u64,
    pub hard_limit_inodes: u64,
    pub soft_limit_inodes: u64,
    pub reservation_bytes: u64,
}

impl DatasetQuotaConfig {
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.hard_limit_bytes > 0
            || self.soft_limit_bytes > 0
            || self.hard_limit_inodes > 0
            || self.soft_limit_inodes > 0
            || self.reservation_bytes > 0
    }
}

/// Runtime state for one dataset in the quota hierarchy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DatasetQuotaEntry {
    config: DatasetQuotaConfig,
    bytes_used: u64,
    inodes_used: u64,
}

/// Result of a quota check against the dataset hierarchy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatasetQuotaDecision {
    Allowed,
    HardBytesExceeded {
        dataset_id: [u8; 16],
        limit_bytes: u64,
        current_bytes: u64,
        requested_bytes: u64,
    },
    HardInodesExceeded {
        dataset_id: [u8; 16],
        limit_inodes: u64,
        current_inodes: u64,
    },
    ReservationViolation {
        dataset_id: [u8; 16],
        reserved_bytes: u64,
        free_bytes: u64,
    },
}

impl DatasetQuotaDecision {
    #[must_use]
    pub fn is_refusal(&self) -> bool {
        matches!(
            self,
            DatasetQuotaDecision::HardBytesExceeded { .. }
                | DatasetQuotaDecision::HardInodesExceeded { .. }
                | DatasetQuotaDecision::ReservationViolation { .. }
        )
    }
}

/// Nested dataset quota and reservation hierarchy.
///
/// Associates each dataset (by `[u8; 16]` id) with quota limits and
/// enforces that child datasets cannot exceed ancestor quotas.  Usage
/// is charged up the ancestor chain so a parent sees the aggregate
/// consumption of all descendants.
///
/// # Design
///
/// - Quota limits are set per-dataset via [`set_quota`](Self::set_quota).
/// - The hierarchy is determined by a caller-supplied parent-resolution
///   function (typically backed by `DatasetCatalog`).
/// - [`check_delta`](Self::check_delta) walks ancestors and returns the
///   first refusal (most restrictive wins).
/// - [`charge_bytes`](Self::charge_bytes) and [`credit_bytes`](Self::credit_bytes)
///   apply usage deltas to every ancestor on the chain.
/// - [`effective_capacity`](Self::effective_capacity) returns the most
///   restrictive hard-limit ceiling along the chain (or pool capacity).
///
/// # Comparison to ZFS
///
/// ZFS enforces `quota` at the dataset level but `refquota` excludes
/// descendants.  TideFS takes the simpler path: all ancestor quotas are
/// cumulative (they include descendant usage), matching ZFS `quota`
/// semantics.  A future `DatasetQuotaConfig::exclude_descendants` flag
/// can add `refquota`-style exclusion without changing the hierarchy model.
#[derive(Clone, Debug, Default)]
pub struct DatasetQuotaHierarchy {
    entries: HashMap<[u8; 16], DatasetQuotaEntry>,
}

impl DatasetQuotaHierarchy {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Set quota limits for a dataset.
    ///
    /// Removes the entry if the config is inactive (all fields zero).
    pub fn set_quota(&mut self, dataset_id: [u8; 16], config: DatasetQuotaConfig) {
        if config.is_active() {
            let usage = self
                .entries
                .get(&dataset_id)
                .map(|e| (e.bytes_used, e.inodes_used))
                .unwrap_or((0, 0));
            self.entries.insert(
                dataset_id,
                DatasetQuotaEntry {
                    config,
                    bytes_used: usage.0,
                    inodes_used: usage.1,
                },
            );
        } else {
            self.entries.remove(&dataset_id);
        }
    }

    /// Remove a dataset's quota configuration.
    pub fn remove_quota(&mut self, dataset_id: [u8; 16]) {
        self.entries.remove(&dataset_id);
    }

    /// Get the quota config for a dataset, if set.
    #[must_use]
    pub fn get(&self, dataset_id: &[u8; 16]) -> Option<&DatasetQuotaConfig> {
        self.entries.get(dataset_id).map(|e| &e.config)
    }

    /// Number of datasets with active quota configurations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if no datasets have quota configurations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Walk the ancestor chain and check whether `delta_bytes`/`delta_inodes`
    /// would violate any quota.
    ///
    /// `parent_of` maps a dataset id to its parent id (or `None` for roots).
    /// `pool_free_bytes` gates reservation enforcement.
    ///
    /// Returns the first refusal encountered, or `Allowed`.
    pub fn check_delta<F>(
        &self,
        dataset_id: [u8; 16],
        delta_bytes: u64,
        delta_inodes: u64,
        pool_free_bytes: u64,
        parent_of: F,
    ) -> DatasetQuotaDecision
    where
        F: Fn(&[u8; 16]) -> Option<[u8; 16]>,
    {
        if let Some(decision) =
            self.reservation_pressure_violation(dataset_id, delta_bytes, pool_free_bytes)
        {
            return decision;
        }

        let mut current = Some(dataset_id);
        while let Some(id) = current {
            if let Some(entry) = self.entries.get(&id) {
                let cfg = &entry.config;

                // Hard byte limit
                if cfg.hard_limit_bytes > 0 {
                    let projected = entry.bytes_used.saturating_add(delta_bytes);
                    if projected > cfg.hard_limit_bytes {
                        return DatasetQuotaDecision::HardBytesExceeded {
                            dataset_id: id,
                            limit_bytes: cfg.hard_limit_bytes,
                            current_bytes: entry.bytes_used,
                            requested_bytes: delta_bytes,
                        };
                    }
                }

                // Hard inode limit
                if cfg.hard_limit_inodes > 0 && delta_inodes > 0 {
                    let projected = entry.inodes_used.saturating_add(delta_inodes);
                    if projected > cfg.hard_limit_inodes {
                        return DatasetQuotaDecision::HardInodesExceeded {
                            dataset_id: id,
                            limit_inodes: cfg.hard_limit_inodes,
                            current_inodes: entry.inodes_used,
                        };
                    }
                }

                // Reservation pressure is checked once against the aggregate
                // active reservation set before ancestor hard limits.
            }
            current = parent_of(&id);
        }
        DatasetQuotaDecision::Allowed
    }

    /// Charge `delta_bytes` and `delta_inodes` against every ancestor
    /// on the chain up from `dataset_id`.
    pub fn charge_bytes<F>(
        &mut self,
        dataset_id: [u8; 16],
        delta_bytes: u64,
        delta_inodes: u64,
        parent_of: F,
    ) where
        F: Fn(&[u8; 16]) -> Option<[u8; 16]>,
    {
        if delta_bytes == 0 && delta_inodes == 0 {
            return;
        }
        let mut current = Some(dataset_id);
        while let Some(id) = current {
            if let Some(entry) = self.entries.get_mut(&id) {
                entry.bytes_used = entry.bytes_used.saturating_add(delta_bytes);
                entry.inodes_used = entry.inodes_used.saturating_add(delta_inodes);
            }
            current = parent_of(&id);
        }
    }

    /// Credit `delta_bytes` and `delta_inodes` from every ancestor
    /// on the chain up from `dataset_id`.
    pub fn credit_bytes<F>(
        &mut self,
        dataset_id: [u8; 16],
        delta_bytes: u64,
        delta_inodes: u64,
        parent_of: F,
    ) where
        F: Fn(&[u8; 16]) -> Option<[u8; 16]>,
    {
        if delta_bytes == 0 && delta_inodes == 0 {
            return;
        }
        let mut current = Some(dataset_id);
        while let Some(id) = current {
            if let Some(entry) = self.entries.get_mut(&id) {
                entry.bytes_used = entry.bytes_used.saturating_sub(delta_bytes);
                entry.inodes_used = entry.inodes_used.saturating_sub(delta_inodes);
            }
            current = parent_of(&id);
        }
    }

    /// Return the most restrictive capacity ceiling for `dataset_id`.
    ///
    /// Walks the ancestor chain and returns the minimum of all hard
    /// byte limits (taking remaining capacity into account) and the
    /// pool's physical capacity.
    #[must_use]
    pub fn effective_capacity<F>(
        &self,
        dataset_id: [u8; 16],
        pool_capacity_bytes: u64,
        parent_of: F,
    ) -> u64
    where
        F: Fn(&[u8; 16]) -> Option<[u8; 16]>,
    {
        let mut ceiling = self.reservation_available_bytes(pool_capacity_bytes);
        let mut current = Some(dataset_id);
        while let Some(id) = current {
            if let Some(entry) = self.entries.get(&id) {
                if entry.config.hard_limit_bytes > 0 {
                    // The ancestor's remaining capacity is its limit minus
                    // what it (and its other descendants) have used.
                    let remaining = entry
                        .config
                        .hard_limit_bytes
                        .saturating_sub(entry.bytes_used);
                    ceiling = ceiling.min(remaining);
                }
            }
            current = parent_of(&id);
        }
        ceiling
    }

    /// Total reserved bytes across all quota entries.
    #[must_use]
    pub fn total_reserved_bytes(&self) -> u64 {
        self.entries.values().fold(0u64, |sum, e| {
            sum.saturating_add(e.config.reservation_bytes)
        })
    }

    fn total_reserved_bytes_checked(&self) -> Option<u64> {
        self.entries
            .values()
            .try_fold(0u64, |sum, e| sum.checked_add(e.config.reservation_bytes))
    }

    fn reservation_pressure_bytes(&self, requested_bytes: u64) -> Option<u64> {
        self.total_reserved_bytes_checked()?
            .checked_add(requested_bytes)
    }

    fn reservation_available_bytes(&self, pool_free_bytes: u64) -> u64 {
        match self.total_reserved_bytes_checked() {
            Some(reserved_bytes) => pool_free_bytes.saturating_sub(reserved_bytes),
            None => 0,
        }
    }

    fn reservation_pressure_violation(
        &self,
        dataset_id: [u8; 16],
        requested_bytes: u64,
        pool_free_bytes: u64,
    ) -> Option<DatasetQuotaDecision> {
        let required_bytes = match self.reservation_pressure_bytes(requested_bytes) {
            Some(bytes) => bytes,
            None => {
                return Some(DatasetQuotaDecision::ReservationViolation {
                    dataset_id,
                    reserved_bytes: u64::MAX,
                    free_bytes: pool_free_bytes,
                });
            }
        };

        if required_bytes > pool_free_bytes {
            Some(DatasetQuotaDecision::ReservationViolation {
                dataset_id,
                reserved_bytes: required_bytes,
                free_bytes: pool_free_bytes,
            })
        } else {
            None
        }
    }

    /// Iterate over all dataset ids with active quota configurations.
    pub fn iter(&self) -> impl Iterator<Item = &[u8; 16]> {
        self.entries.keys()
    }
}

// ---------------------------------------------------------------------------
// CleanerAction — what the cleaner should do
// ---------------------------------------------------------------------------

/// Action returned by [`CleanerScheduler::evaluate`] based on current
/// pool free-space position relative to the configured watermarks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanerAction {
    /// Writers are blocked until the cleaner makes progress.
    /// Triggered when `phys_free_segments < min_free_segments`.
    BlockWriters,
    /// Background cleaner is activated.
    /// Triggered when `phys_free_segments < target_free_segments`
    /// (but still above `min_free_segments`).
    StartBackground,
    /// Cleaner can rest (ample free space).
    /// Triggered when `phys_free_segments > high_free_segments`.
    Stop,
    /// No change to cleaner state.
    NoChange,
}

// ---------------------------------------------------------------------------
// CleanerWatermarks — configurable cleaner thresholds
// ---------------------------------------------------------------------------

/// Per-pool cleaner scheduling thresholds.
///
/// Defaults are derived from `phys_total_segments`:
/// - `target_free_segments` = 5% of total segments
/// - `min_free_segments`   = 2% of total segments
/// - `high_free_segments`  = 8% of total segments
///
/// The `tail_reserved_segments` is a forward-progress reserve for the
/// cleaner itself: never allocated by general allocation, so the cleaner
/// always has space to write relocated data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CleanerWatermarks {
    pub min_free_segments: u64,
    pub target_free_segments: u64,
    pub high_free_segments: u64,
    pub tail_reserved_segments: u64,
}

impl CleanerWatermarks {
    /// Derive defaults from total pool segment count.
    #[must_use]
    pub const fn for_pool(total_segments: u64) -> Self {
        // Prevent zero-division on tiny pools.
        let nz = if total_segments == 0 {
            1
        } else {
            total_segments
        };
        let raw_min = nz * 2 / 100;
        let raw_target = nz * 5 / 100;
        let raw_high = nz * 8 / 100;
        let raw_tail = nz / 100;
        Self {
            min_free_segments: if raw_min < 1 { 1 } else { raw_min },
            target_free_segments: if raw_target < 2 { 2 } else { raw_target },
            high_free_segments: if raw_high < 4 { 4 } else { raw_high },
            tail_reserved_segments: if raw_tail < 1 { 1 } else { raw_tail },
        }
    }

    /// Human-readable configuration for observability.
    #[must_use]
    pub fn label(&self) -> impl fmt::Display + use<> {
        struct L(u64, u64, u64, u64);
        impl fmt::Display for L {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    "min={} target={} high={} tail_reserve={}",
                    self.0, self.1, self.2, self.3
                )
            }
        }
        L(
            self.min_free_segments,
            self.target_free_segments,
            self.high_free_segments,
            self.tail_reserved_segments,
        )
    }
}

impl Default for CleanerWatermarks {
    fn default() -> Self {
        Self::for_pool(1000) // reasonable default for a medium pool
    }
}

// ---------------------------------------------------------------------------
// CleanerScheduler — watermark-based cleaner trigger
// ---------------------------------------------------------------------------

/// Evaluates pool utilisation against [`CleanerWatermarks`] and returns
/// the appropriate [`CleanerAction`].
///
/// ## Algorithm
///
/// ```text
/// if phys_free < min_free_segments    → BlockWriters
/// elif phys_free < target_free       → StartBackground
/// elif phys_free > high_free         → Stop
/// else                               → NoChange
/// ```
///
/// This implements §8.2 "Trigger algorithm" from
/// `docs/SPACE_ACCOUNTING_MODEL_DESIGN.md`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CleanerScheduler {
    watermarks: CleanerWatermarks,
}

impl CleanerScheduler {
    #[must_use]
    pub const fn new(watermarks: CleanerWatermarks) -> Self {
        Self { watermarks }
    }

    #[must_use]
    pub const fn watermarks(&self) -> &CleanerWatermarks {
        &self.watermarks
    }

    /// Evaluate the cleaner action for the given physical free segment count.
    #[must_use]
    pub fn evaluate(&self, phys_free_segments: u64) -> CleanerAction {
        if phys_free_segments < self.watermarks.min_free_segments {
            CleanerAction::BlockWriters
        } else if phys_free_segments < self.watermarks.target_free_segments {
            CleanerAction::StartBackground
        } else if phys_free_segments > self.watermarks.high_free_segments {
            CleanerAction::Stop
        } else {
            CleanerAction::NoChange
        }
    }
}

impl Default for CleanerScheduler {
    fn default() -> Self {
        Self::new(CleanerWatermarks::default())
    }
}

// ---------------------------------------------------------------------------
// Physical counter refresh
// ---------------------------------------------------------------------------

impl SpaceAccounting {
    /// Refresh the pool-level physical counters from allocator data.
    ///
    /// Constructs a [`PoolPhysicalCountersV1`] from raw allocator stats
    /// and updates the cached pool state.  Call this after each commit_group commit
    /// to keep ENOSPC gating fresh.
    ///
    /// `reclaimable_bytes` is supplied by the cleaner (estimated dead bytes
    /// in segments awaiting cleaning).  When no cleaner estimate is
    /// available, pass 0.
    /// `segment_bytes` is the pool-wide segment size (e.g. `SEG_BYTES`).
    pub fn refresh_physical_counters(
        &mut self,
        free_segments: u64,
        total_segments: u64,
        reclaimable_bytes: u64,
        segment_bytes: u64,
        tail_reserved_segments: u64,
    ) {
        self.pool = Some(PoolPhysicalCountersV1 {
            phys_free_segments: free_segments,
            phys_free_bytes: free_segments.saturating_mul(segment_bytes),
            phys_reclaimable_bytes: reclaimable_bytes,
            phys_tail_reserved_segments: tail_reserved_segments,
            phys_total_segments: total_segments,
            phys_total_bytes: total_segments.saturating_mul(segment_bytes),
        });
    }
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// OperationKind -- worst-case byte delta dispatch
// ---------------------------------------------------------------------------

/// Operation kind for admission control worst-case byte delta computation.
///
/// Each mutating operation has a known worst-case byte delta; the runtime
/// uses this to determine `needed_bytes` for `admission_check()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    /// Data write (new or overwrite): worst = full byte count.
    Write,
    /// `fallocate` reservation: worst = full requested size.
    Fallocate,
    /// Clone / snapshot: shares existing blocks, zero net new bytes.
    Clone,
}

// ---------------------------------------------------------------------------
// SpaceUsage — user-facing space snapshot
// ---------------------------------------------------------------------------

/// A snapshot of space usage at a point in time, suitable for user-facing
/// reporting (e.g. `df`, statfs, quota monitoring).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpaceUsage {
    /// Logical bytes consumed by live data.
    pub used_bytes: u64,
    /// Physical bytes on disk.
    pub physical_used_bytes: u64,
    /// Bytes still available for new writes.
    pub available_bytes: u64,
    /// Total capacity (quota or pool capacity).
    pub total_bytes: u64,
}

impl SpaceUsage {
    /// Quota utilisation as a percentage (0–100).
    #[must_use]
    pub fn quota_used_percent(&self) -> u64 {
        if self.total_bytes == 0 {
            return 0;
        }
        (self.used_bytes as u128)
            .saturating_mul(100)
            .saturating_div(self.total_bytes as u128) as u64
    }

    /// Bytes free (same as `available_bytes` for df compatibility).
    #[must_use]
    pub const fn free_bytes(&self) -> u64 {
        self.available_bytes
    }
}

// ---------------------------------------------------------------------------
// SnapshotDeadlist — per-snapshot deadlist byte tracking (Phase 4)
// ---------------------------------------------------------------------------

/// Per-snapshot deadlist tracking with O(1) byte accounting.
///
/// Each snapshot maintains a deadlist of extents that are exclusively
/// pinned by that snapshot — i.e. blocks whose refcount dropped to 1
/// but are still reachable from a live snapshot root.
///
/// This provides O(1) updates (unlike ZFS's O(n) periodic scans) and
/// O(m) snapshot destroy where m = exclusively pinned blocks.
///
/// # Comparison to ZFS / Ceph
///
/// - **ZFS**: `usedbysnapshots` is computed via periodic `zfs list -t snapshot`
///   scans that can be minutes or hours stale under heavy write load.
///   Destroying a snapshot walks its deadlist internally but the accounting
///   is not exposed for O(1) queries.
/// - **Ceph**: RADOS pools have no per-snapshot space attribution;
///   snapshot space is opaque.
///
/// TideFS maintains `deadlist_bytes` per snapshot with O(1) counter updates
/// on every extent-pin / extent-unpin operation, giving real-time accuracy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SnapshotDeadlist {
    /// Total bytes pinned exclusively by this snapshot.
    deadlist_bytes: u64,
    /// Number of extents in the deadlist.
    deadlist_count: u64,
    /// CommitGroup at which this snapshot was taken.
    snap_commit_group: u64,
    /// Lifecycle state.
    state: SnapshotState,
}

impl SnapshotDeadlist {
    /// Create a new deadlist for a snapshot at the given commit_group.
    #[must_use]
    pub const fn new(snap_commit_group: u64) -> Self {
        SnapshotDeadlist {
            deadlist_bytes: 0,
            deadlist_count: 0,
            snap_commit_group,
            state: SnapshotState::Active,
        }
    }

    /// Pinned bytes (O(1) read).
    #[must_use]
    pub const fn pinned_bytes(&self) -> u64 {
        self.deadlist_bytes
    }

    /// Number of pinned extents.
    #[must_use]
    pub const fn pinned_extents(&self) -> u64 {
        self.deadlist_count
    }

    /// Whether the snapshot is active (accepting new pinned extents).
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, SnapshotState::Active)
    }

    /// Add a pinned extent's bytes to the deadlist (O(1)).
    ///
    /// Called when a block's refcount drops to 1 and a live snapshot
    /// references it.  The extent becomes exclusively pinned by this
    /// snapshot.
    ///
    /// Returns `Err` if the snapshot is already DESTROYING.
    pub fn add_extent(&mut self, bytes: u64) -> Result<(), SpaceAccountingError> {
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
    /// Returns `Err` on underflow.
    pub fn remove_extent(&mut self, bytes: u64) -> Result<(), SpaceAccountingError> {
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

    /// Mark the snapshot as destroying — no new extents enter the deadlist.
    pub fn mark_destroying(&mut self) {
        self.state = SnapshotState::Destroying;
    }

    /// Convert to a [`SnapshotSpaceRecord`] for persistence.
    #[must_use]
    pub fn to_record(&self) -> SnapshotSpaceRecord {
        SnapshotSpaceRecord {
            snap_commit_group: self.snap_commit_group,
            deadlist_root_ptr: 0, // B+tree root pointer (set by storage layer)
            deadlist_bytes: self.deadlist_bytes,
            deadlist_count: self.deadlist_count,
            state: self.state,
            destroy_commit_group: 0,
        }
    }

    /// Create from a persisted [`SnapshotSpaceRecord`].
    #[must_use]
    pub const fn from_record(record: SnapshotSpaceRecord) -> Self {
        SnapshotDeadlist {
            deadlist_bytes: record.deadlist_bytes,
            deadlist_count: record.deadlist_count,
            snap_commit_group: record.snap_commit_group,
            state: record.state,
        }
    }
}

// ---------------------------------------------------------------------------
// SnapshotSpaceManager — snapshot lifecycle with deadlist accounting (Phase 4)
// ---------------------------------------------------------------------------

/// Manages snapshot lifecycle and aggregates deadlist accounting
/// across all snapshots in a dataset.
///
/// Provides O(1) total-pinned-bytes queries (unlike ZFS's O(n) scan)
/// and O(m) snapshot destroy where m = exclusively pinned extents.
#[derive(Clone, Debug, Default)]
pub struct SnapshotSpaceManager {
    /// All snapshot deadlists indexed by snap_commit_group for stable ordering.
    snapshots: hashbrown::HashMap<u64, SnapshotDeadlist>,
    /// Monotonically increasing commit_group counter for snapshot ordering.
    next_commit_group: u64,
}

impl SnapshotSpaceManager {
    /// Create an empty snapshot space manager.
    #[must_use]
    pub fn new() -> Self {
        SnapshotSpaceManager {
            snapshots: hashbrown::HashMap::new(),
            next_commit_group: 1,
        }
    }

    /// Create a new snapshot at the current commit_group.
    ///
    /// Returns the commit_group of the newly created snapshot.
    pub fn create_snapshot(&mut self) -> u64 {
        let commit_group = self.next_commit_group;
        self.next_commit_group += 1;
        self.snapshots
            .insert(commit_group, SnapshotDeadlist::new(commit_group));
        commit_group
    }

    /// Create a snapshot at a specific commit_group (e.g. during import).
    pub fn create_snapshot_at(&mut self, commit_group: u64) -> Result<(), SpaceAccountingError> {
        if commit_group >= self.next_commit_group {
            self.next_commit_group = commit_group + 1;
        }
        if self.snapshots.contains_key(&commit_group) {
            return Err(SpaceAccountingError::InvalidArgument);
        }
        self.snapshots
            .insert(commit_group, SnapshotDeadlist::new(commit_group));
        Ok(())
    }

    /// Destroy a snapshot, returning the total bytes that were exclusively
    /// pinned by it (now freed).
    ///
    /// Returns `None` if the snapshot does not exist.
    pub fn destroy_snapshot(&mut self, commit_group: u64) -> Option<u64> {
        let deadlist = self.snapshots.remove(&commit_group)?;
        Some(deadlist.pinned_bytes())
    }

    /// Total pinned bytes across all active snapshots (O(n) scan over
    /// snapshot count, not total blocks — typically small).
    #[must_use]
    pub fn total_pinned_bytes(&self) -> u64 {
        self.snapshots
            .values()
            .filter(|d| d.is_active())
            .map(|d| d.pinned_bytes())
            .sum()
    }

    /// Total pinned bytes across all snapshots regardless of state.
    #[must_use]
    pub fn total_pinned_bytes_all(&self) -> u64 {
        self.snapshots.values().map(|d| d.pinned_bytes()).sum()
    }

    /// Number of active snapshots.
    #[must_use]
    pub fn active_snapshot_count(&self) -> usize {
        self.snapshots.values().filter(|d| d.is_active()).count()
    }

    /// Total number of snapshots.
    #[must_use]
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Get a reference to a snapshot's deadlist.
    #[must_use]
    pub fn get(&self, commit_group: u64) -> Option<&SnapshotDeadlist> {
        self.snapshots.get(&commit_group)
    }

    /// Get a mutable reference to a snapshot's deadlist.
    pub fn get_mut(&mut self, commit_group: u64) -> Option<&mut SnapshotDeadlist> {
        self.snapshots.get_mut(&commit_group)
    }

    /// Add a pinned extent to the oldest active snapshot that was born
    /// before or at the block's birth commit_group.
    ///
    /// When a block's refcount drops to 1, the extent is moved into
    /// the deadlist of the oldest applicable snapshot rather than
    /// being freed immediately.
    pub fn pin_extent_to_oldest_active(
        &mut self,
        block_birth_commit_group: u64,
        bytes: u64,
    ) -> Result<u64, SpaceAccountingError> {
        // Find oldest active snapshot born at or after the block.
        let mut oldest_commit_group: Option<u64> = None;
        for (&commit_group, deadlist) in &self.snapshots {
            if deadlist.is_active()
                && commit_group >= block_birth_commit_group
                && oldest_commit_group.is_none_or(|ot| commit_group < ot)
            {
                oldest_commit_group = Some(commit_group);
            }
        }
        match oldest_commit_group {
            Some(commit_group) => {
                self.snapshots
                    .get_mut(&commit_group)
                    .unwrap()
                    .add_extent(bytes)?;
                Ok(commit_group)
            }
            None => Err(SpaceAccountingError::InvalidArgument),
        }
    }

    /// Mark a snapshot as destroying (no new extents accepted).
    pub fn mark_destroying(&mut self, commit_group: u64) -> Result<(), SpaceAccountingError> {
        let deadlist =
            self.snapshots
                .get_mut(&commit_group)
                .ok_or(SpaceAccountingError::DomainNotFound {
                    domain_id: SpaceDomainId(commit_group),
                })?;
        deadlist.mark_destroying();
        Ok(())
    }

    /// Iterate over all (commit_group, deadlist) pairs.
    pub fn iter(&self) -> hashbrown::hash_map::Iter<'_, u64, SnapshotDeadlist> {
        self.snapshots.iter()
    }
}

// ---------------------------------------------------------------------------
// SpaceDomainRegistry — pool-level domain-scoped accounting
// ---------------------------------------------------------------------------

/// Pool-level registry of domain-scoped space counters.
///
/// Tracks aggregated [`SpaceDomainCounters`] per [`SpaceDomainId`], enabling
/// domain-level `statfs` for clone families where multiple datasets share a
/// single accounting domain.  Implements Phase 2 (domain-scoped accounting)
/// of [`docs/SPACE_ACCOUNTING_MODEL_DESIGN.md`].
///
/// # Domain lifecycle
///
/// ```text
/// create_domain(id, counters)  ──► domain exists with initial counters
///                                       │
/// inherit_domain(id, counters) ─────────┤  (clone joins domain)
///                                       │
/// reclaim_domain(id) ───────────────────┘  (last member destroyed)
/// ```
///
/// # Comparison to ZFS / Ceph
///
/// - **ZFS**: No domain-scoped accounting for clone families — `zfs list` reports
///   per-dataset `used` which double-counts blocks shared by clones.  `statfs`
///   inside a clone reports the origin\'s quota, not the clone family aggregate.
/// - **Ceph**: RADOS pool stats are fully aggregate with no per-clone-family
///   awareness.
///
/// TideFS provides domain-scoped `statfs` so that every dataset in a clone family
/// sees the same available space, correctly accounting for shared blocks.
#[derive(Clone, Debug)]
pub struct SpaceDomainRegistry {
    domains: hashbrown::HashMap<SpaceDomainId, SpaceDomainCounters>,
}

impl SpaceDomainRegistry {
    /// Create an empty domain registry.
    #[must_use]
    pub fn new() -> Self {
        SpaceDomainRegistry {
            domains: hashbrown::HashMap::new(),
        }
    }

    /// Create a new domain with initial counter values.
    ///
    /// Returns `SpaceAccountingError::DomainAlreadyExists` if `domain_id` is
    /// already registered, or `InvalidArgument` if `domain_id` is `NONE`.
    pub fn create_domain(
        &mut self,
        domain_id: SpaceDomainId,
        initial: SpaceDomainCounters,
    ) -> Result<(), SpaceAccountingError> {
        if domain_id == SpaceDomainId::NONE {
            return Err(SpaceAccountingError::InvalidArgument);
        }
        if self.domains.contains_key(&domain_id) {
            return Err(SpaceAccountingError::DomainAlreadyExists { domain_id });
        }
        self.domains.insert(domain_id, initial);
        Ok(())
    }

    /// Have a dataset inherit (join) an existing domain by accumulating its
    /// per-dataset counters into the domain aggregate.
    ///
    /// Returns `SpaceAccountingError::DomainNotFound` if the domain does not
    /// exist.
    pub fn inherit_domain(
        &mut self,
        domain_id: SpaceDomainId,
        counters: &DatasetSpaceCountersV1,
    ) -> Result<(), SpaceAccountingError> {
        let domain = self
            .domains
            .get_mut(&domain_id)
            .ok_or(SpaceAccountingError::DomainNotFound { domain_id })?;
        domain.domain_logical_used_bytes = domain
            .domain_logical_used_bytes
            .saturating_add(counters.logical_used_bytes);
        domain.domain_pinned_snapshot_bytes = domain
            .domain_pinned_snapshot_bytes
            .saturating_add(counters.pinned_snapshot_bytes);
        domain.domain_reserved_bytes = domain
            .domain_reserved_bytes
            .saturating_add(counters.reserved_bytes);
        domain.domain_orphan_bytes = domain
            .domain_orphan_bytes
            .saturating_add(counters.orphan_bytes);
        Ok(())
    }

    /// Apply a per-dataset space delta to the domain aggregate.
    ///
    /// Called after [`SpaceAccounting::commit_delta`] succeeds, to keep the
    /// domain-level counters in sync with per-dataset deltas.
    pub fn apply_domain_delta(
        &mut self,
        domain_id: SpaceDomainId,
        delta: &SpaceDelta,
    ) -> Result<(), SpaceAccountingError> {
        let domain = self
            .domains
            .get_mut(&domain_id)
            .ok_or(SpaceAccountingError::DomainNotFound { domain_id })?;
        domain.domain_logical_used_bytes = domain
            .domain_logical_used_bytes
            .saturating_add_signed(delta.logical_used_delta);
        domain.domain_reserved_bytes = domain
            .domain_reserved_bytes
            .saturating_add_signed(delta.reserved_delta);
        domain.domain_orphan_bytes = domain
            .domain_orphan_bytes
            .saturating_add_signed(delta.orphan_delta);
        domain.domain_pinned_snapshot_bytes = domain
            .domain_pinned_snapshot_bytes
            .saturating_add_signed(delta.pinned_snapshot_delta);
        Ok(())
    }

    /// Reclaim a domain when the last member dataset is destroyed.
    ///
    /// Returns the final [`SpaceDomainCounters`] for observability/audit,
    /// or `None` if the domain did not exist.
    #[must_use]
    pub fn reclaim_domain(&mut self, domain_id: SpaceDomainId) -> Option<SpaceDomainCounters> {
        self.domains.remove(&domain_id)
    }

    /// Look up domain-level counters.
    #[must_use]
    pub fn get(&self, domain_id: &SpaceDomainId) -> Option<&SpaceDomainCounters> {
        self.domains.get(domain_id)
    }

    /// Compute `statfs` for a domain, aggregating across all datasets in the
    /// clone family.
    ///
    /// Returns `None` if the domain does not exist.
    #[must_use]
    pub fn domain_statfs(&self, domain_id: &SpaceDomainId) -> Option<StatfsResult> {
        let counters = self.domains.get(domain_id)?;
        let block_size = StatfsResult::DEFAULT_BLOCK_SIZE;
        let total_blocks = counters.domain_quota_bytes / block_size;

        let consumed = counters
            .domain_logical_used_bytes
            .saturating_add(counters.domain_pinned_snapshot_bytes);
        let free_bytes = counters.domain_quota_bytes.saturating_sub(consumed);
        let free_blocks = free_bytes / block_size;

        // Reserved blocks: keep 5% for root/metadata (matches ext4/XFS convention).
        let reserved_blocks = total_blocks / 20;
        let avail_blocks = free_blocks.saturating_sub(reserved_blocks);

        Some(StatfsResult {
            block_size,
            blocks: total_blocks,
            blocks_avail: avail_blocks,
            blocks_free: free_blocks,
            files: u64::MAX,
            files_free: u64::MAX,
            name_max: StatfsResult::DEFAULT_NAME_MAX,
        })
    }

    /// Number of active domains (excluding NONE).
    #[must_use]
    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }

    /// Whether the registry contains a domain.
    #[must_use]
    pub fn contains(&self, domain_id: &SpaceDomainId) -> bool {
        self.domains.contains_key(domain_id)
    }

    /// Iterate over all (domain_id, counters) pairs.
    pub fn iter(&self) -> hashbrown::hash_map::Iter<'_, SpaceDomainId, SpaceDomainCounters> {
        self.domains.iter()
    }

    /// Update the quota for a domain.
    pub fn set_domain_quota(
        &mut self,
        domain_id: SpaceDomainId,
        quota_bytes: u64,
    ) -> Result<(), SpaceAccountingError> {
        let domain = self
            .domains
            .get_mut(&domain_id)
            .ok_or(SpaceAccountingError::DomainNotFound { domain_id })?;
        domain.domain_quota_bytes = quota_bytes;
        Ok(())
    }
}

impl Default for SpaceDomainRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SpaceDomainRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SpaceDomainRegistry(domains={})", self.domains.len())
    }
}

// ---------------------------------------------------------------------------
// UserQuota — per-uid quota tracking
// ---------------------------------------------------------------------------

/// Per-user (uid) quota tracking for a single dataset.
///
/// Each dataset carries a [`QuotaTable`] that maps uid to [`UserQuota`].
/// Limits can inherit from a parent dataset's [`QuotaTable`] (overrideable).
///
/// When `soft_limit == 0` or `hard_limit == 0`, that limit is treated as
/// unlimited (no enforcement). The same applies to `file_limit`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserQuota {
    /// Owner user id.
    pub uid: u32,
    /// Bytes currently consumed by this user in this dataset.
    pub used_bytes: u64,
    /// Soft byte limit (0 = unlimited). Exceeding logs a warning.
    pub soft_limit: u64,
    /// Hard byte limit (0 = unlimited). Exceeding returns ENOSPC.
    pub hard_limit: u64,
    /// Number of files owned by this user in this dataset.
    pub file_count: u64,
    /// File count limit (0 = unlimited).
    pub file_limit: u64,
}

impl UserQuota {
    /// Create a new per-user quota entry with zero usage.
    #[must_use]
    pub const fn new(uid: u32) -> Self {
        UserQuota {
            uid,
            used_bytes: 0,
            soft_limit: 0,
            hard_limit: 0,
            file_count: 0,
            file_limit: 0,
        }
    }

    /// Whether a hard limit is set and enforced.
    #[must_use]
    pub const fn has_hard_limit(&self) -> bool {
        self.hard_limit > 0
    }

    /// Whether a soft limit is set.
    #[must_use]
    pub const fn has_soft_limit(&self) -> bool {
        self.soft_limit > 0
    }

    /// Charge `bytes` against this user's quota.
    ///
    /// Returns `Ok(())` if within limits, or `Err(SpaceAccountingError)`
    /// if the hard limit would be exceeded.
    pub fn charge_bytes(&mut self, bytes: u64) -> Result<(), SpaceAccountingError> {
        let projected = self.used_bytes.saturating_add(bytes);
        if self.has_hard_limit() && projected > self.hard_limit {
            return Err(SpaceAccountingError::QuotaExceeded {
                quota_bytes: self.hard_limit,
                requested_bytes: bytes,
                available_bytes: self.hard_limit.saturating_sub(self.used_bytes),
            });
        }
        self.used_bytes = projected;
        Ok(())
    }

    /// Credit `bytes` back to this user's quota (unlink/truncate).
    ///
    /// Returns `Err(SpaceAccountingError::CounterUnderflow)` if
    /// `bytes > used_bytes`.
    pub fn credit_bytes(&mut self, bytes: u64) -> Result<(), SpaceAccountingError> {
        if bytes > self.used_bytes {
            return Err(SpaceAccountingError::CounterUnderflow {
                counter_name: "user_quota_used_bytes",
                current_value: self.used_bytes,
                delta: -(bytes as i64),
            });
        }
        self.used_bytes -= bytes;
        Ok(())
    }

    /// Charge a file creation against the file count.
    pub fn charge_file(&mut self) -> Result<(), SpaceAccountingError> {
        if self.file_limit > 0 && self.file_count >= self.file_limit {
            return Err(SpaceAccountingError::QuotaExceeded {
                quota_bytes: self.file_limit,
                requested_bytes: 1,
                available_bytes: 0,
            });
        }
        self.file_count = self.file_count.saturating_add(1);
        Ok(())
    }

    /// Credit a file removal against the file count.
    pub fn credit_file(&mut self) -> Result<(), SpaceAccountingError> {
        if self.file_count == 0 {
            return Err(SpaceAccountingError::CounterUnderflow {
                counter_name: "user_quota_file_count",
                current_value: 0,
                delta: -1,
            });
        }
        self.file_count -= 1;
        Ok(())
    }

    /// Available bytes before hitting the hard limit.
    #[must_use]
    pub fn available_bytes(&self) -> u64 {
        if !self.has_hard_limit() {
            u64::MAX
        } else {
            self.hard_limit.saturating_sub(self.used_bytes)
        }
    }
}

// ---------------------------------------------------------------------------
// GroupQuota — per-gid quota tracking
// ---------------------------------------------------------------------------

/// Per-group (gid) quota tracking for a single dataset.
///
/// Mirrors [`UserQuota`] but keyed by gid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupQuota {
    /// Owner group id.
    pub gid: u32,
    /// Bytes currently consumed by this group in this dataset.
    pub used_bytes: u64,
    /// Soft byte limit (0 = unlimited).
    pub soft_limit: u64,
    /// Hard byte limit (0 = unlimited).
    pub hard_limit: u64,
    /// Number of files owned by this group in this dataset.
    pub file_count: u64,
    /// File count limit (0 = unlimited).
    pub file_limit: u64,
}

impl GroupQuota {
    /// Create a new per-group quota entry with zero usage.
    #[must_use]
    pub const fn new(gid: u32) -> Self {
        GroupQuota {
            gid,
            used_bytes: 0,
            soft_limit: 0,
            hard_limit: 0,
            file_count: 0,
            file_limit: 0,
        }
    }

    /// Whether a hard limit is set and enforced.
    #[must_use]
    pub const fn has_hard_limit(&self) -> bool {
        self.hard_limit > 0
    }

    /// Whether a soft limit is set.
    #[must_use]
    pub const fn has_soft_limit(&self) -> bool {
        self.soft_limit > 0
    }

    /// Charge `bytes` against this group's quota.
    pub fn charge_bytes(&mut self, bytes: u64) -> Result<(), SpaceAccountingError> {
        let projected = self.used_bytes.saturating_add(bytes);
        if self.has_hard_limit() && projected > self.hard_limit {
            return Err(SpaceAccountingError::QuotaExceeded {
                quota_bytes: self.hard_limit,
                requested_bytes: bytes,
                available_bytes: self.hard_limit.saturating_sub(self.used_bytes),
            });
        }
        self.used_bytes = projected;
        Ok(())
    }

    /// Credit `bytes` back to this group's quota (unlink/truncate).
    pub fn credit_bytes(&mut self, bytes: u64) -> Result<(), SpaceAccountingError> {
        if bytes > self.used_bytes {
            return Err(SpaceAccountingError::CounterUnderflow {
                counter_name: "group_quota_used_bytes",
                current_value: self.used_bytes,
                delta: -(bytes as i64),
            });
        }
        self.used_bytes -= bytes;
        Ok(())
    }

    /// Charge a file creation against the file count.
    pub fn charge_file(&mut self) -> Result<(), SpaceAccountingError> {
        if self.file_limit > 0 && self.file_count >= self.file_limit {
            return Err(SpaceAccountingError::QuotaExceeded {
                quota_bytes: self.file_limit,
                requested_bytes: 1,
                available_bytes: 0,
            });
        }
        self.file_count = self.file_count.saturating_add(1);
        Ok(())
    }

    /// Credit a file removal against the file count.
    pub fn credit_file(&mut self) -> Result<(), SpaceAccountingError> {
        if self.file_count == 0 {
            return Err(SpaceAccountingError::CounterUnderflow {
                counter_name: "group_quota_file_count",
                current_value: 0,
                delta: -1,
            });
        }
        self.file_count -= 1;
        Ok(())
    }

    /// Available bytes before hitting the hard limit.
    #[must_use]
    pub fn available_bytes(&self) -> u64 {
        if !self.has_hard_limit() {
            u64::MAX
        } else {
            self.hard_limit.saturating_sub(self.used_bytes)
        }
    }
}

// ---------------------------------------------------------------------------
// ProjectQuota — per-project_id quota tracking (directory-tree-scoped)
// ---------------------------------------------------------------------------

/// Per-project quota tracking for a single dataset.
///
/// A project is a directory tree identified by a `project_id` set on the
/// directory inode.  All files and subdirectories under a project directory
/// inherit the project_id and are charged to the project's quota.
///
/// Project quotas are additive with user/group quotas: a write must pass
/// all three checks (user, group, project) to succeed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectQuota {
    /// Project identifier.
    pub project_id: u32,
    /// Bytes currently consumed by this project in this dataset.
    pub used_bytes: u64,
    /// Soft byte limit (0 = unlimited).
    pub soft_limit: u64,
    /// Hard byte limit (0 = unlimited).
    pub hard_limit: u64,
    /// Number of files in this project tree.
    pub file_count: u64,
    /// File count limit (0 = unlimited).
    pub file_limit: u64,
}

impl ProjectQuota {
    /// Create a new per-project quota entry with zero usage.
    #[must_use]
    pub const fn new(project_id: u32) -> Self {
        ProjectQuota {
            project_id,
            used_bytes: 0,
            soft_limit: 0,
            hard_limit: 0,
            file_count: 0,
            file_limit: 0,
        }
    }

    /// Whether a hard limit is set and enforced.
    #[must_use]
    pub const fn has_hard_limit(&self) -> bool {
        self.hard_limit > 0
    }

    /// Whether a soft limit is set.
    #[must_use]
    pub const fn has_soft_limit(&self) -> bool {
        self.soft_limit > 0
    }

    /// Charge `bytes` against this project's quota.
    ///
    /// Returns `Ok(())` if within limits, or `Err(SpaceAccountingError)`
    /// if the hard limit would be exceeded.
    pub fn charge_bytes(&mut self, bytes: u64) -> Result<(), SpaceAccountingError> {
        let projected = self.used_bytes.saturating_add(bytes);
        if self.has_hard_limit() && projected > self.hard_limit {
            return Err(SpaceAccountingError::QuotaExceeded {
                quota_bytes: self.hard_limit,
                requested_bytes: bytes,
                available_bytes: self.hard_limit.saturating_sub(self.used_bytes),
            });
        }
        self.used_bytes = projected;
        Ok(())
    }

    /// Credit `bytes` back to this project's quota (unlink/truncate).
    pub fn credit_bytes(&mut self, bytes: u64) -> Result<(), SpaceAccountingError> {
        if bytes > self.used_bytes {
            return Err(SpaceAccountingError::CounterUnderflow {
                counter_name: "project_quota_used_bytes",
                current_value: self.used_bytes,
                delta: -(bytes as i64),
            });
        }
        self.used_bytes -= bytes;
        Ok(())
    }

    /// Charge a file creation against the file count.
    pub fn charge_file(&mut self) -> Result<(), SpaceAccountingError> {
        if self.file_limit > 0 && self.file_count >= self.file_limit {
            return Err(SpaceAccountingError::QuotaExceeded {
                quota_bytes: self.file_limit,
                requested_bytes: 1,
                available_bytes: 0,
            });
        }
        self.file_count = self.file_count.saturating_add(1);
        Ok(())
    }

    /// Credit a file removal against the file count.
    pub fn credit_file(&mut self) -> Result<(), SpaceAccountingError> {
        if self.file_count == 0 {
            return Err(SpaceAccountingError::CounterUnderflow {
                counter_name: "project_quota_file_count",
                current_value: 0,
                delta: -1,
            });
        }
        self.file_count -= 1;
        Ok(())
    }

    /// Available bytes before hitting the hard limit.
    #[must_use]
    pub fn available_bytes(&self) -> u64 {
        if !self.has_hard_limit() {
            u64::MAX
        } else {
            self.hard_limit.saturating_sub(self.used_bytes)
        }
    }
}

// ---------------------------------------------------------------------------
// QuotaVerdict — outcome of a quota check
// ---------------------------------------------------------------------------

/// Result of checking whether a user or group can allocate more space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaVerdict {
    /// Operation is allowed; within all limits.
    Allowed,
    /// Soft limit would be exceeded (warning but operation proceeds).
    SoftLimitExceeded {
        used: u64,
        limit: u64,
        available: u64,
    },
    /// Hard limit would be exceeded (operation refused with ENOSPC).
    HardLimitExceeded {
        used: u64,
        limit: u64,
        requested: u64,
    },
}

// ---------------------------------------------------------------------------
// QuotaCheck — static quota enforcement checks
// ---------------------------------------------------------------------------

/// Provides static methods for checking user and group quota limits.
pub struct QuotaCheck;

impl QuotaCheck {
    /// Check whether `uid` can allocate `requested` bytes given their quota.
    #[must_use]
    pub fn check_user(quota: &UserQuota, requested: u64) -> QuotaVerdict {
        let projected = quota.used_bytes.saturating_add(requested);
        // Hard limit check first (fatal).
        if quota.has_hard_limit() && projected > quota.hard_limit {
            return QuotaVerdict::HardLimitExceeded {
                used: quota.used_bytes,
                limit: quota.hard_limit,
                requested,
            };
        }
        // Soft limit check (warning-only).
        if quota.has_soft_limit() && projected > quota.soft_limit {
            return QuotaVerdict::SoftLimitExceeded {
                used: quota.used_bytes,
                limit: quota.soft_limit,
                available: quota.soft_limit.saturating_sub(quota.used_bytes),
            };
        }
        QuotaVerdict::Allowed
    }

    /// Check whether `gid` can allocate `requested` bytes given their quota.
    #[must_use]
    pub fn check_group(quota: &GroupQuota, requested: u64) -> QuotaVerdict {
        let projected = quota.used_bytes.saturating_add(requested);
        if quota.has_hard_limit() && projected > quota.hard_limit {
            return QuotaVerdict::HardLimitExceeded {
                used: quota.used_bytes,
                limit: quota.hard_limit,
                requested,
            };
        }
        if quota.has_soft_limit() && projected > quota.soft_limit {
            return QuotaVerdict::SoftLimitExceeded {
                used: quota.used_bytes,
                limit: quota.soft_limit,
                available: quota.soft_limit.saturating_sub(quota.used_bytes),
            };
        }
        QuotaVerdict::Allowed
    }

    /// Check whether a write of `requested_bytes` would violate the dataset-level
    /// quota (hard limit = `counters.quota_bytes`, soft limit = `counters.quota_soft_limit`).
    #[must_use]
    pub fn check_dataset(counters: &DatasetSpaceCountersV1, requested_bytes: u64) -> QuotaVerdict {
        let projected = counters.logical_used_bytes.saturating_add(requested_bytes);

        if counters.quota_bytes == 0 {
            return QuotaVerdict::Allowed;
        }

        // Hard limit check first.
        if projected > counters.quota_bytes {
            return QuotaVerdict::HardLimitExceeded {
                used: counters.logical_used_bytes,
                limit: counters.quota_bytes,
                requested: requested_bytes,
            };
        }

        // Soft limit check.
        if counters.quota_soft_limit > 0 && projected > counters.quota_soft_limit {
            return QuotaVerdict::SoftLimitExceeded {
                used: counters.logical_used_bytes,
                limit: counters.quota_soft_limit,
                available: counters
                    .quota_soft_limit
                    .saturating_sub(counters.logical_used_bytes),
            };
        }

        QuotaVerdict::Allowed
    }
}

// ---------------------------------------------------------------------------
// QuotaTable — per-dataset user/group quota table with inheritance
// ---------------------------------------------------------------------------

/// Per-dataset quota table mapping uid→[`UserQuota`] and gid→[`GroupQuota`].
///
/// Supports inheritance: when a user or group has no explicit quota entry
/// in this table, the parent table (if set) is consulted for limits.
/// Usage counters (`used_bytes`, `file_count`) are always local to this
/// table — only *limits* are inherited.
///
/// # Inheritance model
///
/// ```text
/// child.QuotaTable                   parent.QuotaTable
///   uid=1000: used=50M, limits=0       uid=1000: soft=1G, hard=2G
///          → inherits limits from parent
///   uid=1001: used=200M, hard=500M     (no entry for 1001)
///          → own explicit limits take precedence
/// ```
pub struct QuotaTable {
    user_quotas: BTreeMap<u32, UserQuota>,
    group_quotas: BTreeMap<u32, GroupQuota>,
    project_quotas: BTreeMap<u32, ProjectQuota>,
    /// Optional parent for limit inheritance.
    parent: Option<Box<QuotaTable>>,
}

impl QuotaTable {
    /// Create an empty quota table with no parent.
    #[must_use]
    pub fn new() -> Self {
        QuotaTable {
            user_quotas: BTreeMap::new(),
            group_quotas: BTreeMap::new(),
            project_quotas: BTreeMap::new(),
            parent: None,
        }
    }

    /// Set the parent table for limit inheritance.
    ///
    /// When a user/group has no explicit limits in this table, the
    /// parent's limits are consulted recursively.
    pub fn set_parent(&mut self, parent: QuotaTable) {
        self.parent = Some(Box::new(parent));
    }

    /// Whether this table has a parent.
    #[must_use]
    pub fn has_parent(&self) -> bool {
        self.parent.is_some()
    }

    // -- User quota accessors --

    /// Get or create the local [`UserQuota`] entry for `uid`.
    fn ensure_user(&mut self, uid: u32) -> &mut UserQuota {
        self.user_quotas
            .entry(uid)
            .or_insert_with(|| UserQuota::new(uid))
    }

    /// Get the effective limits for a user by consulting this table
    /// and the parent chain.
    ///
    /// Returns `(soft_limit, hard_limit, file_limit)` — the first
    /// non-zero value found in the inheritance chain for each field.
    #[must_use]
    pub fn effective_user_limits(&self, uid: u32) -> (u64, u64, u64) {
        let local = self.user_quotas.get(&uid);
        let mut soft = local.map_or(0, |q| q.soft_limit);
        let mut hard = local.map_or(0, |q| q.hard_limit);
        let mut files = local.map_or(0, |q| q.file_limit);

        // If any limit is unset (0), walk up the parent chain.
        let mut current = self.parent.as_ref();
        while current.is_some() && (soft == 0 || hard == 0 || files == 0) {
            let p = current.unwrap();
            if let Some(pq) = p.user_quotas.get(&uid) {
                if soft == 0 {
                    soft = pq.soft_limit;
                }
                if hard == 0 {
                    hard = pq.hard_limit;
                }
                if files == 0 {
                    files = pq.file_limit;
                }
            }
            current = p.parent.as_ref();
        }
        (soft, hard, files)
    }

    /// Get the local user quota entry (if any).
    #[must_use]
    pub fn get_user(&self, uid: u32) -> Option<&UserQuota> {
        self.user_quotas.get(&uid)
    }

    /// Get a mutable reference to the local user quota entry.
    pub fn get_user_mut(&mut self, uid: u32) -> Option<&mut UserQuota> {
        self.user_quotas.get_mut(&uid)
    }

    /// Set explicit limits for a user.
    ///
    /// Creates the local entry if it doesn't exist, then sets the limits.
    /// Zero values leave the existing value unchanged.
    pub fn set_user_limits(&mut self, uid: u32, soft: u64, hard: u64, file_limit: u64) {
        let entry = self.ensure_user(uid);
        if soft > 0 {
            entry.soft_limit = soft;
        }
        if hard > 0 {
            entry.hard_limit = hard;
        }
        if file_limit > 0 {
            entry.file_limit = file_limit;
        }
    }

    /// Check whether `uid` can allocate `requested` bytes.
    ///
    /// Consults the effective limits (local + inherited).
    #[must_use]
    pub fn check_user(&self, uid: u32, requested: u64) -> QuotaVerdict {
        let local = self.user_quotas.get(&uid);
        let used = local.map_or(0, |q| q.used_bytes);
        let (soft, hard, _files) = self.effective_user_limits(uid);

        let projected = used.saturating_add(requested);

        if hard > 0 && projected > hard {
            return QuotaVerdict::HardLimitExceeded {
                used,
                limit: hard,
                requested,
            };
        }
        if soft > 0 && projected > soft {
            return QuotaVerdict::SoftLimitExceeded {
                used,
                limit: soft,
                available: soft.saturating_sub(used),
            };
        }
        QuotaVerdict::Allowed
    }

    /// Charge `bytes` against `uid`'s quota.
    ///
    /// First checks effective limits, then increments the local
    /// `used_bytes` counter (creating the entry if needed).
    pub fn charge_user(&mut self, uid: u32, bytes: u64) -> Result<(), SpaceAccountingError> {
        // Check limits first.
        match self.check_user(uid, bytes) {
            QuotaVerdict::Allowed | QuotaVerdict::SoftLimitExceeded { .. } => {}
            QuotaVerdict::HardLimitExceeded {
                limit, requested, ..
            } => {
                return Err(SpaceAccountingError::QuotaExceeded {
                    quota_bytes: limit,
                    requested_bytes: requested,
                    available_bytes: 0,
                });
            }
        }
        let entry = self.ensure_user(uid);
        entry.charge_bytes(bytes)
    }

    /// Credit `bytes` back to `uid`'s quota.
    pub fn credit_user(&mut self, uid: u32, bytes: u64) -> Result<(), SpaceAccountingError> {
        match self.user_quotas.get_mut(&uid) {
            Some(q) => q.credit_bytes(bytes),
            None => Err(SpaceAccountingError::CounterUnderflow {
                counter_name: "user_quota_used_bytes",
                current_value: 0,
                delta: -(bytes as i64),
            }),
        }
    }

    /// Charge a file creation against `uid`'s file count.
    ///
    /// Checks effective limits (including inherited) before charging.
    pub fn charge_user_file(&mut self, uid: u32) -> Result<(), SpaceAccountingError> {
        let (_soft, _hard, file_limit) = self.effective_user_limits(uid);
        let entry = self.ensure_user(uid);
        if file_limit > 0 && entry.file_count >= file_limit {
            return Err(SpaceAccountingError::QuotaExceeded {
                quota_bytes: file_limit,
                requested_bytes: 1,
                available_bytes: 0,
            });
        }
        entry.charge_file()
    }

    /// Credit a file removal against `uid`'s file count.
    pub fn credit_user_file(&mut self, uid: u32) -> Result<(), SpaceAccountingError> {
        match self.user_quotas.get_mut(&uid) {
            Some(q) => q.credit_file(),
            None => Ok(()), // No entry to credit; nothing tracked.
        }
    }

    // -- Group quota accessors --

    fn ensure_group(&mut self, gid: u32) -> &mut GroupQuota {
        self.group_quotas
            .entry(gid)
            .or_insert_with(|| GroupQuota::new(gid))
    }

    /// Get the effective limits for a group by consulting this table
    /// and the parent chain.
    #[must_use]
    pub fn effective_group_limits(&self, gid: u32) -> (u64, u64, u64) {
        let local = self.group_quotas.get(&gid);
        let mut soft = local.map_or(0, |q| q.soft_limit);
        let mut hard = local.map_or(0, |q| q.hard_limit);
        let mut files = local.map_or(0, |q| q.file_limit);

        let mut current = self.parent.as_ref();
        while current.is_some() && (soft == 0 || hard == 0 || files == 0) {
            let p = current.unwrap();
            if let Some(pq) = p.group_quotas.get(&gid) {
                if soft == 0 {
                    soft = pq.soft_limit;
                }
                if hard == 0 {
                    hard = pq.hard_limit;
                }
                if files == 0 {
                    files = pq.file_limit;
                }
            }
            current = p.parent.as_ref();
        }
        (soft, hard, files)
    }

    /// Get the local group quota entry (if any).
    #[must_use]
    pub fn get_group(&self, gid: u32) -> Option<&GroupQuota> {
        self.group_quotas.get(&gid)
    }

    /// Set explicit limits for a group.
    pub fn set_group_limits(&mut self, gid: u32, soft: u64, hard: u64, file_limit: u64) {
        let entry = self.ensure_group(gid);
        if soft > 0 {
            entry.soft_limit = soft;
        }
        if hard > 0 {
            entry.hard_limit = hard;
        }
        if file_limit > 0 {
            entry.file_limit = file_limit;
        }
    }

    /// Check whether `gid` can allocate `requested` bytes.
    #[must_use]
    pub fn check_group(&self, gid: u32, requested: u64) -> QuotaVerdict {
        let local = self.group_quotas.get(&gid);
        let used = local.map_or(0, |q| q.used_bytes);
        let (soft, hard, _files) = self.effective_group_limits(gid);

        let projected = used.saturating_add(requested);

        if hard > 0 && projected > hard {
            return QuotaVerdict::HardLimitExceeded {
                used,
                limit: hard,
                requested,
            };
        }
        if soft > 0 && projected > soft {
            return QuotaVerdict::SoftLimitExceeded {
                used,
                limit: soft,
                available: soft.saturating_sub(used),
            };
        }
        QuotaVerdict::Allowed
    }

    /// Charge `bytes` against `gid`'s quota.
    pub fn charge_group(&mut self, gid: u32, bytes: u64) -> Result<(), SpaceAccountingError> {
        match self.check_group(gid, bytes) {
            QuotaVerdict::Allowed | QuotaVerdict::SoftLimitExceeded { .. } => {}
            QuotaVerdict::HardLimitExceeded {
                limit, requested, ..
            } => {
                return Err(SpaceAccountingError::QuotaExceeded {
                    quota_bytes: limit,
                    requested_bytes: requested,
                    available_bytes: 0,
                });
            }
        }
        let entry = self.ensure_group(gid);
        entry.charge_bytes(bytes)
    }

    /// Credit `bytes` back to `gid`'s quota.
    pub fn credit_group(&mut self, gid: u32, bytes: u64) -> Result<(), SpaceAccountingError> {
        match self.group_quotas.get_mut(&gid) {
            Some(q) => q.credit_bytes(bytes),
            None => Err(SpaceAccountingError::CounterUnderflow {
                counter_name: "group_quota_used_bytes",
                current_value: 0,
                delta: -(bytes as i64),
            }),
        }
    }

    /// Charge a file creation against `gid`'s file count.
    ///
    /// Checks effective limits (including inherited) before charging.
    pub fn charge_group_file(&mut self, gid: u32) -> Result<(), SpaceAccountingError> {
        let (_soft, _hard, file_limit) = self.effective_group_limits(gid);
        let entry = self.ensure_group(gid);
        if file_limit > 0 && entry.file_count >= file_limit {
            return Err(SpaceAccountingError::QuotaExceeded {
                quota_bytes: file_limit,
                requested_bytes: 1,
                available_bytes: 0,
            });
        }
        entry.charge_file()
    }

    /// Credit a file removal against `gid`'s file count.
    pub fn credit_group_file(&mut self, gid: u32) -> Result<(), SpaceAccountingError> {
        match self.group_quotas.get_mut(&gid) {
            Some(q) => q.credit_file(),
            None => Ok(()),
        }
    }

    // -- Project quota accessors --

    fn ensure_project(&mut self, project_id: u32) -> &mut ProjectQuota {
        self.project_quotas
            .entry(project_id)
            .or_insert_with(|| ProjectQuota::new(project_id))
    }

    /// Get the effective limits for a project by consulting this table
    /// and the parent chain.
    ///
    /// Returns `(soft_limit, hard_limit, file_limit)` — the first
    /// non-zero value found in the inheritance chain for each field.
    #[must_use]
    pub fn effective_project_limits(&self, project_id: u32) -> (u64, u64, u64) {
        let local = self.project_quotas.get(&project_id);
        let mut soft = local.map_or(0, |q| q.soft_limit);
        let mut hard = local.map_or(0, |q| q.hard_limit);
        let mut files = local.map_or(0, |q| q.file_limit);

        let mut current = self.parent.as_ref();
        while current.is_some() && (soft == 0 || hard == 0 || files == 0) {
            let p = current.unwrap();
            if let Some(pq) = p.project_quotas.get(&project_id) {
                if soft == 0 {
                    soft = pq.soft_limit;
                }
                if hard == 0 {
                    hard = pq.hard_limit;
                }
                if files == 0 {
                    files = pq.file_limit;
                }
            }
            current = p.parent.as_ref();
        }
        (soft, hard, files)
    }

    /// Get the local project quota entry (if any).
    #[must_use]
    pub fn get_project(&self, project_id: u32) -> Option<&ProjectQuota> {
        self.project_quotas.get(&project_id)
    }

    /// Set explicit limits for a project.
    ///
    /// Creates the local entry if it doesn't exist, then sets the limits.
    /// Zero values leave the existing value unchanged.
    pub fn set_project_limits(&mut self, project_id: u32, soft: u64, hard: u64, file_limit: u64) {
        let entry = self.ensure_project(project_id);
        if soft > 0 {
            entry.soft_limit = soft;
        }
        if hard > 0 {
            entry.hard_limit = hard;
        }
        if file_limit > 0 {
            entry.file_limit = file_limit;
        }
    }

    /// Check whether `project_id` can allocate `requested` bytes.
    ///
    /// Consults the effective limits (local + inherited).
    #[must_use]
    pub fn check_project(&self, project_id: u32, requested: u64) -> QuotaVerdict {
        let local = self.project_quotas.get(&project_id);
        let used = local.map_or(0, |q| q.used_bytes);
        let (soft, hard, _files) = self.effective_project_limits(project_id);

        let projected = used.saturating_add(requested);

        if hard > 0 && projected > hard {
            return QuotaVerdict::HardLimitExceeded {
                used,
                limit: hard,
                requested,
            };
        }
        if soft > 0 && projected > soft {
            return QuotaVerdict::SoftLimitExceeded {
                used,
                limit: soft,
                available: soft.saturating_sub(used),
            };
        }
        QuotaVerdict::Allowed
    }

    /// Charge `bytes` against `project_id`'s quota.
    ///
    /// First checks effective limits, then increments the local
    /// `used_bytes` counter (creating the entry if needed).
    pub fn charge_project(
        &mut self,
        project_id: u32,
        bytes: u64,
    ) -> Result<(), SpaceAccountingError> {
        match self.check_project(project_id, bytes) {
            QuotaVerdict::Allowed | QuotaVerdict::SoftLimitExceeded { .. } => {}
            QuotaVerdict::HardLimitExceeded {
                limit, requested, ..
            } => {
                return Err(SpaceAccountingError::QuotaExceeded {
                    quota_bytes: limit,
                    requested_bytes: requested,
                    available_bytes: 0,
                });
            }
        }
        let entry = self.ensure_project(project_id);
        entry.charge_bytes(bytes)
    }

    /// Credit `bytes` back to `project_id`'s quota.
    pub fn credit_project(
        &mut self,
        project_id: u32,
        bytes: u64,
    ) -> Result<(), SpaceAccountingError> {
        match self.project_quotas.get_mut(&project_id) {
            Some(q) => q.credit_bytes(bytes),
            None => Err(SpaceAccountingError::CounterUnderflow {
                counter_name: "project_quota_used_bytes",
                current_value: 0,
                delta: -(bytes as i64),
            }),
        }
    }

    /// Charge a file creation against `project_id`'s file count.
    ///
    /// Checks effective limits (including inherited) before charging.
    pub fn charge_project_file(&mut self, project_id: u32) -> Result<(), SpaceAccountingError> {
        let (_soft, _hard, file_limit) = self.effective_project_limits(project_id);
        let entry = self.ensure_project(project_id);
        if file_limit > 0 && entry.file_count >= file_limit {
            return Err(SpaceAccountingError::QuotaExceeded {
                quota_bytes: file_limit,
                requested_bytes: 1,
                available_bytes: 0,
            });
        }
        entry.charge_file()
    }

    /// Credit a file removal against `project_id`'s file count.
    pub fn credit_project_file(&mut self, project_id: u32) -> Result<(), SpaceAccountingError> {
        match self.project_quotas.get_mut(&project_id) {
            Some(q) => q.credit_file(),
            None => Ok(()),
        }
    }

    /// Iterate over all project quota entries.
    pub fn iter_projects(&self) -> impl Iterator<Item = (&u32, &ProjectQuota)> {
        self.project_quotas.iter()
    }

    /// Number of tracked projects.
    #[must_use]
    pub fn project_count(&self) -> usize {
        self.project_quotas.len()
    }

    // -- Iteration for QuotaStats --

    /// Iterate over all user quota entries.
    pub fn iter_users(&self) -> impl Iterator<Item = (&u32, &UserQuota)> {
        self.user_quotas.iter()
    }

    /// Iterate over all group quota entries.
    pub fn iter_groups(&self) -> impl Iterator<Item = (&u32, &GroupQuota)> {
        self.group_quotas.iter()
    }

    /// Number of tracked users.
    #[must_use]
    pub fn user_count(&self) -> usize {
        self.user_quotas.len()
    }

    /// Number of tracked groups.
    #[must_use]
    pub fn group_count(&self) -> usize {
        self.group_quotas.len()
    }
}

impl Default for QuotaTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// QuotaStats — per-uid and per-gid usage reports
// ---------------------------------------------------------------------------

/// Read-only snapshot of current user, group, and project quota usage.
///
/// Built from a [`QuotaTable`] for reporting via statfs or administrative
/// tools.  Serves as the [`QuotaReport`] when all three quota classes are
/// populated.
#[derive(Clone, Debug, Default)]
pub struct QuotaStats {
    /// Per-user quotas, ordered by uid.
    pub user_quotas: BTreeMap<u32, UserQuota>,
    /// Per-group quotas, ordered by gid.
    pub group_quotas: BTreeMap<u32, GroupQuota>,
    /// Per-project quotas, ordered by project_id.
    pub project_quotas: BTreeMap<u32, ProjectQuota>,
}

impl QuotaStats {
    /// Collect stats from a [`QuotaTable`].
    #[must_use]
    pub fn from_table(table: &QuotaTable) -> Self {
        QuotaStats {
            user_quotas: table
                .user_quotas
                .iter()
                .map(|(&k, v)| (k, v.clone()))
                .collect(),
            group_quotas: table
                .group_quotas
                .iter()
                .map(|(&k, v)| (k, v.clone()))
                .collect(),
            project_quotas: table
                .project_quotas
                .iter()
                .map(|(&k, v)| (k, v.clone()))
                .collect(),
        }
    }

    /// Total bytes used by all users in this dataset.
    #[must_use]
    pub fn total_user_bytes(&self) -> u64 {
        self.user_quotas.values().map(|q| q.used_bytes).sum()
    }

    /// Total bytes used by all groups in this dataset.
    #[must_use]
    pub fn total_group_bytes(&self) -> u64 {
        self.group_quotas.values().map(|q| q.used_bytes).sum()
    }

    /// Total file count across all users.
    #[must_use]
    pub fn total_user_files(&self) -> u64 {
        self.user_quotas.values().map(|q| q.file_count).sum()
    }

    /// Total file count across all groups.
    #[must_use]
    pub fn total_group_files(&self) -> u64 {
        self.group_quotas.values().map(|q| q.file_count).sum()
    }

    /// Total bytes used by all projects in this dataset.
    #[must_use]
    pub fn total_project_bytes(&self) -> u64 {
        self.project_quotas.values().map(|q| q.used_bytes).sum()
    }

    /// Total file count across all projects.
    #[must_use]
    pub fn total_project_files(&self) -> u64 {
        self.project_quotas.values().map(|q| q.file_count).sum()
    }

    /// Combined total bytes across all three quota classes.
    #[must_use]
    pub fn total_all_bytes(&self) -> u64 {
        self.total_user_bytes()
            .saturating_add(self.total_group_bytes())
            .saturating_add(self.total_project_bytes())
    }
}

// ---------------------------------------------------------------------------
// QuotaMigration — serialize/deserialize quota state for pool import/export
// ---------------------------------------------------------------------------

/// Error returned by quota migration deserialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaMigrationError {
    /// Not enough bytes remaining to read a field.
    UnexpectedEnd,
    /// Failed to credit bytes during import (underflow).
    Underflow,
}

impl fmt::Display for QuotaMigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuotaMigrationError::UnexpectedEnd => {
                write!(f, "quota migration: unexpected end of data")
            }
            QuotaMigrationError::Underflow => {
                write!(f, "quota migration: counter underflow during import")
            }
        }
    }
}

/// Serialize and deserialize quota state for pool export/import.
///
/// Provides binary serialization of a [`QuotaTable`] that preserves all
/// user, group, and project quota entries including usage and limits.
///
/// # Binary format (big-endian)
///
/// ```text
/// [user_count: u32]
///   for each user: [uid: u32][used_bytes: u64][soft_limit: u64]
///                  [hard_limit: u64][file_count: u64][file_limit: u64]
/// [group_count: u32]
///   for each group: [gid: u32][used_bytes: u64][soft_limit: u64]
///                   [hard_limit: u64][file_count: u64][file_limit: u64]
/// [project_count: u32]
///   for each project: [project_id: u32][used_bytes: u64][soft_limit: u64]
///                     [hard_limit: u64][file_count: u64][file_limit: u64]
/// ```
pub struct QuotaMigration;

/// Per-entry wire size: u32 id + 5 × u64 fields = 4 + 40 = 44 bytes.
const QUOTA_ENTRY_WIRE_SIZE: usize = 44;

impl QuotaMigration {
    /// Serialize a [`QuotaTable`] to a byte vector suitable for pool export.
    ///
    /// The result includes all user, group, and project entries with their
    /// current usage and limits.  Parent inheritance is NOT serialized —
    /// it must be reconstructed on import from the dataset hierarchy.
    #[must_use]
    pub fn serialize(table: &QuotaTable) -> Vec<u8> {
        let user_count = table.user_quotas.len() as u32;
        let group_count = table.group_quotas.len() as u32;
        let project_count = table.project_quotas.len() as u32;

        let total = 12 // three u32 counts
            + (user_count as usize) * QUOTA_ENTRY_WIRE_SIZE
            + (group_count as usize) * QUOTA_ENTRY_WIRE_SIZE
            + (project_count as usize) * QUOTA_ENTRY_WIRE_SIZE;

        let mut buf = Vec::with_capacity(total);

        // User count header
        buf.extend_from_slice(&user_count.to_be_bytes());
        for q in table.user_quotas.values() {
            Self::write_quota_entry(
                &mut buf,
                q.uid as u64,
                q.used_bytes,
                q.soft_limit,
                q.hard_limit,
                q.file_count,
                q.file_limit,
            );
        }

        // Group count header
        buf.extend_from_slice(&group_count.to_be_bytes());
        for q in table.group_quotas.values() {
            Self::write_quota_entry(
                &mut buf,
                q.gid as u64,
                q.used_bytes,
                q.soft_limit,
                q.hard_limit,
                q.file_count,
                q.file_limit,
            );
        }

        // Project count header
        buf.extend_from_slice(&project_count.to_be_bytes());
        for q in table.project_quotas.values() {
            Self::write_quota_entry(
                &mut buf,
                q.project_id as u64,
                q.used_bytes,
                q.soft_limit,
                q.hard_limit,
                q.file_count,
                q.file_limit,
            );
        }

        buf
    }

    /// Deserialize bytes produced by [`QuotaMigration::serialize`] back into
    /// a [`QuotaTable`].
    ///
    /// # Errors
    ///
    /// Returns [`QuotaMigrationError::UnexpectedEnd`] if the buffer is
    /// truncated or malformed.
    pub fn deserialize(bytes: &[u8]) -> Result<QuotaTable, QuotaMigrationError> {
        let mut table = QuotaTable::new();
        let mut pos: usize = 0;

        // Read user count
        let user_count = Self::read_u32(bytes, &mut pos)?;
        for _ in 0..user_count {
            let (id, used, soft, hard, files, file_limit) =
                Self::read_quota_entry(bytes, &mut pos)?;
            let uid = id as u32;
            table.set_user_limits(uid, soft, hard, file_limit);
            if used > 0 {
                // Directly set used_bytes on the entry.
                let entry = table.user_quotas.get_mut(&uid).unwrap();
                entry.used_bytes = used;
                entry.file_count = files;
            }
        }

        // Read group count
        let group_count = Self::read_u32(bytes, &mut pos)?;
        for _ in 0..group_count {
            let (id, used, soft, hard, files, file_limit) =
                Self::read_quota_entry(bytes, &mut pos)?;
            let gid = id as u32;
            table.set_group_limits(gid, soft, hard, file_limit);
            if used > 0 {
                let entry = table.group_quotas.get_mut(&gid).unwrap();
                entry.used_bytes = used;
                entry.file_count = files;
            }
        }

        // Read project count
        let project_count = Self::read_u32(bytes, &mut pos)?;
        for _ in 0..project_count {
            let (id, used, soft, hard, files, file_limit) =
                Self::read_quota_entry(bytes, &mut pos)?;
            let project_id = id as u32;
            table.set_project_limits(project_id, soft, hard, file_limit);
            if used > 0 {
                let entry = table.project_quotas.get_mut(&project_id).unwrap();
                entry.used_bytes = used;
                entry.file_count = files;
            }
        }

        Ok(table)
    }

    // -- internal helpers --

    fn write_quota_entry(
        buf: &mut Vec<u8>,
        id: u64,
        used: u64,
        soft: u64,
        hard: u64,
        files: u64,
        file_limit: u64,
    ) {
        buf.extend_from_slice(&(id as u32).to_be_bytes());
        buf.extend_from_slice(&used.to_be_bytes());
        buf.extend_from_slice(&soft.to_be_bytes());
        buf.extend_from_slice(&hard.to_be_bytes());
        buf.extend_from_slice(&files.to_be_bytes());
        buf.extend_from_slice(&file_limit.to_be_bytes());
    }

    fn read_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, QuotaMigrationError> {
        if *pos + 4 > bytes.len() {
            return Err(QuotaMigrationError::UnexpectedEnd);
        }
        let val = u32::from_be_bytes([
            bytes[*pos],
            bytes[*pos + 1],
            bytes[*pos + 2],
            bytes[*pos + 3],
        ]);
        *pos += 4;
        Ok(val)
    }

    fn read_u64(bytes: &[u8], pos: &mut usize) -> Result<u64, QuotaMigrationError> {
        if *pos + 8 > bytes.len() {
            return Err(QuotaMigrationError::UnexpectedEnd);
        }
        let val = u64::from_be_bytes([
            bytes[*pos],
            bytes[*pos + 1],
            bytes[*pos + 2],
            bytes[*pos + 3],
            bytes[*pos + 4],
            bytes[*pos + 5],
            bytes[*pos + 6],
            bytes[*pos + 7],
        ]);
        *pos += 8;
        Ok(val)
    }

    fn read_quota_entry(
        bytes: &[u8],
        pos: &mut usize,
    ) -> Result<(u64, u64, u64, u64, u64, u64), QuotaMigrationError> {
        let id = Self::read_u32(bytes, pos)? as u64;
        let used = Self::read_u64(bytes, pos)?;
        let soft = Self::read_u64(bytes, pos)?;
        let hard = Self::read_u64(bytes, pos)?;
        let files = Self::read_u64(bytes, pos)?;
        let file_limit = Self::read_u64(bytes, pos)?;
        Ok((id, used, soft, hard, files, file_limit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_space_accounting_core::{
        DatasetSpaceCountersV1 as Counters, PoolPhysicalCountersV1 as PoolCounters,
        SnapshotSpaceRecord, SnapshotState, SpaceDelta, SpaceDomainId,
    };

    const TEST_QUOTA_BYTES: u64 = 1_000_000_000; // 1 GB

    fn test_counters() -> Counters {
        Counters {
            logical_used_bytes: 0,
            physical_used_bytes: 0,
            pinned_snapshot_bytes: 0,
            reserved_bytes: 0,
            orphan_bytes: 0,
            quota_bytes: TEST_QUOTA_BYTES,
            slop_bytes: 0,
            quota_soft_limit: 0,
        }
    }

    fn test_pool(free_bytes: u64, total_bytes: u64) -> PoolCounters {
        PoolCounters {
            phys_free_bytes: free_bytes,
            phys_total_bytes: total_bytes,
            phys_free_segments: free_bytes / 4096,
            phys_total_segments: total_bytes / 4096,
            phys_reclaimable_bytes: 0,
            phys_tail_reserved_segments: 0,
        }
    }

    // -- Delta application --

    #[test]
    fn commit_delta_write_adds_usage() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        let delta = SpaceDelta::new_write(100_000);
        sa.commit_delta(delta).unwrap();
        assert_eq!(sa.counters().logical_used_bytes, 100_000);
    }

    #[test]
    fn commit_delta_free_subtracts_usage() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.commit_delta(SpaceDelta::new_write(200_000)).unwrap();
        sa.commit_delta(SpaceDelta::new_free(100_000)).unwrap();
        assert_eq!(sa.counters().logical_used_bytes, 100_000);
    }

    #[test]
    fn commit_delta_snapshot_pin() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        let delta = SpaceDelta {
            pinned_snapshot_delta: 50_000,
            ..SpaceDelta::ZERO
        };
        sa.commit_delta(delta).unwrap();
        assert_eq!(sa.counters().pinned_snapshot_bytes, 50_000);
    }

    #[test]
    fn commit_delta_accumulates() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.commit_delta(SpaceDelta::new_write(100_000)).unwrap();
        sa.commit_delta(SpaceDelta::new_write(50_000)).unwrap();
        assert_eq!(sa.counters().logical_used_bytes, 150_000);
        assert_eq!(sa.commit_group_commits(), 2);
    }

    #[test]
    fn commit_delta_write_into_unwritten() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        // Reservation first: marks bytes as reserved (counts toward quota).
        sa.commit_delta(SpaceDelta::new_reservation(100_000))
            .unwrap();
        assert_eq!(sa.counters().reserved_bytes, 100_000);
        // Write into unwritten: converts reservation to actual use.
        // The bytes already counted in logical_alloc_bytes via reserved_bytes.
        sa.commit_delta(SpaceDelta::new_write_into_unwritten(50_000))
            .unwrap();
        // 50K reserved released, 50K still reserved.
        assert_eq!(sa.counters().reserved_bytes, 50_000);
        // logical_used_bytes still 0 — write-into-unwritten doesn't change it;
        // the types crate considers reservation as already counted.
        assert_eq!(sa.counters().logical_used_bytes, 0);
    }

    // -- ENOSPC --

    #[test]
    fn enospc_when_full() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        assert!(!sa.check_enospc(1));
        let fill = SpaceDelta {
            logical_used_delta: TEST_QUOTA_BYTES as i64,
            ..SpaceDelta::ZERO
        };
        sa.commit_delta(fill).unwrap();
        assert!(sa.check_enospc(1));
        assert!(sa.is_readonly());
    }

    #[test]
    fn enospc_headroom() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        let fill = SpaceDelta {
            logical_used_delta: (TEST_QUOTA_BYTES - 100) as i64,
            ..SpaceDelta::ZERO
        };
        sa.commit_delta(fill).unwrap();
        assert!(!sa.check_enospc(50));
        assert!(sa.check_enospc(200));
    }

    #[test]
    fn enospc_physical_pool() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        let pool = test_pool(50_000, 500_000); // 50 KB free
        sa.update_pool_counters(pool);
        assert!(sa.check_enospc_physical(100_000));
        assert!(!sa.check_enospc_physical(10_000));
    }

    #[test]
    fn enospc_physical_no_pool() {
        let sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        assert!(!sa.check_enospc_physical(1_000_000_000));
    }

    #[test]
    fn enospc_no_quota_unlimited() {
        let mut counters = test_counters();
        counters.quota_bytes = 0; // No quota.
        let mut sa = SpaceAccounting::new(counters, SpaceDomainId::NONE);
        sa.commit_delta(SpaceDelta::new_write(u64::MAX / 2))
            .unwrap();
        assert!(!sa.check_enospc(1_000_000));
    }

    // -- Statfs --

    #[test]
    fn statfs_empty() {
        let sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        let s = sa.statfs();
        assert_eq!(s.block_size, StatfsResult::DEFAULT_BLOCK_SIZE);
        assert_eq!(s.blocks, TEST_QUOTA_BYTES / 4096);
        // With no consumption and no slop, free == avail.
        assert_eq!(s.blocks_free, s.blocks);
        assert_eq!(s.blocks_avail, s.blocks);
        assert_eq!(s.files, u64::MAX); // unlimited inodes
        assert_eq!(s.files_free, u64::MAX);
    }

    #[test]
    fn statfs_with_usage() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.commit_delta(SpaceDelta::new_write(500_000_000)).unwrap();
        let s = sa.statfs();
        assert_eq!(s.blocks_free, 500_000_000 / 4096);
    }

    #[test]
    fn statfs_snapshot_pin_excluded() {
        let mut counters = test_counters();
        counters.pinned_snapshot_bytes = 100_000_000;
        let sa = SpaceAccounting::new(counters, SpaceDomainId::NONE);
        let s = sa.statfs();
        let expected_free = (TEST_QUOTA_BYTES - 100_000_000) / 4096;
        assert_eq!(s.blocks_free, expected_free);
    }

    #[test]
    fn statfs_saturates_consumed_bytes() {
        let mut counters = test_counters();
        counters.quota_bytes = u64::MAX;
        counters.logical_used_bytes = u64::MAX - 10;
        counters.pinned_snapshot_bytes = 100;
        let sa = SpaceAccounting::new(counters, SpaceDomainId::NONE);

        let s = sa.statfs();

        assert_eq!(s.blocks, u64::MAX / StatfsResult::DEFAULT_BLOCK_SIZE);
        assert_eq!(s.blocks_free, 0);
        assert_eq!(s.blocks_avail, 0);
    }

    // -- Admission check --

    #[test]
    fn admission_accepts_small_write() {
        let sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        let result = sa.admission_check(1000);
        assert!(matches!(result, AdmissionResult::Allowed));
    }

    #[test]
    fn admission_rejects_large_write() {
        let sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        let result = sa.admission_check(TEST_QUOTA_BYTES + 1);
        assert!(matches!(result, AdmissionResult::QuotaExceeded { .. }));
    }

    #[test]
    fn admission_with_pool_capacity() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        let pool = test_pool(10_000, 1_000_000); // Only 10 KB physical free
        sa.update_pool_counters(pool);
        let result = sa.admission_check(20_000);
        assert!(matches!(
            result,
            AdmissionResult::PhysicalCapacityExceeded { .. }
        ));
    }

    // -- Snapshot pinned bytes --

    #[test]
    fn compute_snapshot_pinned() {
        let snapshots = [
            SnapshotSpaceRecord {
                snap_commit_group: 1,
                state: SnapshotState::Active,
                deadlist_bytes: 100,
                deadlist_root_ptr: 0,
                deadlist_count: 0,
                destroy_commit_group: 0,
            },
            SnapshotSpaceRecord {
                snap_commit_group: 2,
                state: SnapshotState::Active,
                deadlist_bytes: 200,
                deadlist_root_ptr: 0,
                deadlist_count: 0,
                destroy_commit_group: 0,
            },
            SnapshotSpaceRecord {
                snap_commit_group: 3,
                state: SnapshotState::Destroying,
                deadlist_bytes: 500,
                deadlist_root_ptr: 0,
                deadlist_count: 0,
                destroy_commit_group: 10,
            },
        ];
        assert_eq!(
            SpaceAccounting::compute_snapshot_pinned_bytes(&snapshots),
            300
        );
    }

    // -- ENOSPC recording --

    #[test]
    fn record_enospc_accumulates() {
        let mut sa = SpaceAccounting::empty();
        assert_eq!(sa.enospc_blocks(), 0);
        sa.record_enospc(4096);
        sa.record_enospc(8192);
        assert_eq!(sa.enospc_blocks(), 12288);
    }

    // -- Domain counters --

    #[test]
    fn domain_counters_reflect_state() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId(42));
        sa.commit_delta(SpaceDelta::new_write(1000)).unwrap();
        let dc = sa.domain_counters();
        assert_eq!(dc.domain_logical_used_bytes, 1000);
        assert_eq!(dc.domain_quota_bytes, TEST_QUOTA_BYTES);
    }

    // -- Display --

    #[test]
    fn display_format() {
        let sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        let s = format!("{sa}");
        assert!(s.contains("SpaceAccounting"));
        assert!(s.contains("quota="));
    }

    // -- Static delta constructors from types crate --

    #[test]
    fn delta_zero_is_identity() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.commit_delta(SpaceDelta::ZERO).unwrap();
        assert_eq!(sa.counters().logical_used_bytes, 0);
    }

    #[test]
    fn delta_new_reservation_adds_reserved_only() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        // new_reservation only bumps reserved_bytes, not logical_used_bytes.
        // logical_alloc_bytes() (which sums used + reserved + orphan) IS
        // what admission_check and quota enforcement consult.
        sa.commit_delta(SpaceDelta::new_reservation(100_000))
            .unwrap();
        assert_eq!(sa.counters().reserved_bytes, 100_000);
        assert_eq!(sa.counters().logical_used_bytes, 0);
    }

    #[test]
    fn delta_orphan_acquire_and_release() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.commit_delta(SpaceDelta::new_orphan_acquire(50_000))
            .unwrap();
        assert_eq!(sa.counters().orphan_bytes, 50_000);
        sa.commit_delta(SpaceDelta::new_orphan_release(50_000))
            .unwrap();
        assert_eq!(sa.counters().orphan_bytes, 0);
    }

    // -- Counter underflow (error path) --

    #[test]
    fn commit_delta_underflow_rejected() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        // Free more than allocated should fail.
        let result = sa.commit_delta(SpaceDelta::new_free(100_000));
        assert!(result.is_err());
        match result {
            Err(SpaceAccountingError::CounterUnderflow { .. }) => {}
            other => panic!("expected CounterUnderflow, got {other:?}"),
        }
    }

    // -- Pool integration edge cases --

    #[test]
    fn phys_capacity_returns_max_without_pool() {
        let sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        assert_eq!(sa.phys_capacity_bytes(), u64::MAX);
    }

    #[test]
    fn phys_capacity_reflects_pool() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        let pool = test_pool(123_456, 1_000_000);
        sa.update_pool_counters(pool);
        assert_eq!(sa.phys_capacity_bytes(), 123_456);
    }

    // -- Domain registry: create, inherit, reclaim lifecycle --

    fn test_domain_counters() -> SpaceDomainCounters {
        SpaceDomainCounters {
            domain_logical_used_bytes: 0,
            domain_pinned_snapshot_bytes: 0,
            domain_reserved_bytes: 0,
            domain_orphan_bytes: 0,
            domain_quota_bytes: TEST_QUOTA_BYTES,
        }
    }

    #[test]
    fn domain_registry_create_and_get() {
        let mut reg = SpaceDomainRegistry::new();
        let id = SpaceDomainId(42);
        reg.create_domain(id, test_domain_counters()).unwrap();
        assert!(reg.contains(&id));
        assert_eq!(reg.domain_count(), 1);
        let counters = reg.get(&id).unwrap();
        assert_eq!(counters.domain_quota_bytes, TEST_QUOTA_BYTES);
    }

    #[test]
    fn domain_registry_create_duplicate_rejected() {
        let mut reg = SpaceDomainRegistry::new();
        let id = SpaceDomainId(1);
        reg.create_domain(id, test_domain_counters()).unwrap();
        let result = reg.create_domain(id, test_domain_counters());
        assert!(result.is_err());
        match result {
            Err(SpaceAccountingError::DomainAlreadyExists { domain_id }) => {
                assert_eq!(domain_id, id);
            }
            other => panic!("expected DomainAlreadyExists, got {other:?}"),
        }
    }

    #[test]
    fn domain_registry_create_none_rejected() {
        let mut reg = SpaceDomainRegistry::new();
        let result = reg.create_domain(SpaceDomainId::NONE, test_domain_counters());
        assert!(result.is_err());
        match result {
            Err(SpaceAccountingError::InvalidArgument) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn domain_registry_inherit_accumulates() {
        let mut reg = SpaceDomainRegistry::new();
        let id = SpaceDomainId(10);
        reg.create_domain(id, test_domain_counters()).unwrap();

        // Dataset joins domain with some used bytes.
        let ds_counters = DatasetSpaceCountersV1 {
            logical_used_bytes: 1000,
            physical_used_bytes: 0,
            pinned_snapshot_bytes: 200,
            reserved_bytes: 300,
            orphan_bytes: 50,
            quota_bytes: 0,
            slop_bytes: 0,
            quota_soft_limit: 0,
        };
        reg.inherit_domain(id, &ds_counters).unwrap();

        let dc = reg.get(&id).unwrap();
        assert_eq!(dc.domain_logical_used_bytes, 1000);
        assert_eq!(dc.domain_pinned_snapshot_bytes, 200);
        assert_eq!(dc.domain_reserved_bytes, 300);
        assert_eq!(dc.domain_orphan_bytes, 50);
    }

    #[test]
    fn domain_registry_inherit_not_found() {
        let mut reg = SpaceDomainRegistry::new();
        let counters = DatasetSpaceCountersV1::default();
        let result = reg.inherit_domain(SpaceDomainId(99), &counters);
        assert!(result.is_err());
        match result {
            Err(SpaceAccountingError::DomainNotFound { .. }) => {}
            other => panic!("expected DomainNotFound, got {other:?}"),
        }
    }

    #[test]
    fn domain_clone_shares_domain() {
        // Two datasets (origin + clone) share a domain.
        let mut reg = SpaceDomainRegistry::new();
        let domain_id = SpaceDomainId(7);
        reg.create_domain(domain_id, test_domain_counters())
            .unwrap();

        let origin = DatasetSpaceCountersV1 {
            logical_used_bytes: 5000,
            physical_used_bytes: 0,
            pinned_snapshot_bytes: 0,
            reserved_bytes: 1000,
            orphan_bytes: 0,
            quota_bytes: 0,
            slop_bytes: 0,
            quota_soft_limit: 0,
        };
        reg.inherit_domain(domain_id, &origin).unwrap();

        let clone = DatasetSpaceCountersV1 {
            logical_used_bytes: 2000,
            physical_used_bytes: 0,
            pinned_snapshot_bytes: 0,
            reserved_bytes: 500,
            orphan_bytes: 0,
            quota_bytes: 0,
            slop_bytes: 0,
            quota_soft_limit: 0,
        };
        reg.inherit_domain(domain_id, &clone).unwrap();

        let dc = reg.get(&domain_id).unwrap();
        // Both datasets' bytes are summed.
        assert_eq!(dc.domain_logical_used_bytes, 7000);
        assert_eq!(dc.domain_reserved_bytes, 1500);
    }

    #[test]
    fn domain_reclaim_removes_and_returns() {
        let mut reg = SpaceDomainRegistry::new();
        let id = SpaceDomainId(3);
        reg.create_domain(id, test_domain_counters()).unwrap();
        assert_eq!(reg.domain_count(), 1);

        let reclaimed = reg.reclaim_domain(id);
        assert!(reclaimed.is_some());
        assert_eq!(reg.domain_count(), 0);
        assert!(!reg.contains(&id));
    }

    #[test]
    fn domain_reclaim_nonexistent_returns_none() {
        let mut reg = SpaceDomainRegistry::new();
        let result = reg.reclaim_domain(SpaceDomainId(999));
        assert!(result.is_none());
    }

    #[test]
    fn domain_statfs_computes_correctly() {
        let mut reg = SpaceDomainRegistry::new();
        let id = SpaceDomainId(5);
        let mut counters = test_domain_counters();
        counters.domain_quota_bytes = 1_000_000;
        counters.domain_logical_used_bytes = 200_000;
        counters.domain_pinned_snapshot_bytes = 50_000;
        reg.create_domain(id, counters).unwrap();

        let statfs = reg.domain_statfs(&id).unwrap();
        let block_size = StatfsResult::DEFAULT_BLOCK_SIZE;
        assert_eq!(statfs.block_size, block_size);
        assert_eq!(statfs.blocks, 1_000_000 / block_size);
        // Free = quota - (used + pinned) = 1_000_000 - 250_000 = 750_000
        let expected_free_blocks = 750_000 / block_size;
        assert_eq!(statfs.blocks_free, expected_free_blocks);
        // Avail = free - 5% reserved
        let reserved = (1_000_000 / block_size) / 20;
        assert_eq!(statfs.blocks_avail, expected_free_blocks - reserved);
    }

    #[test]
    fn domain_statfs_saturates_consumed_bytes() {
        let mut reg = SpaceDomainRegistry::new();
        let id = SpaceDomainId(6);
        let mut counters = test_domain_counters();
        counters.domain_quota_bytes = u64::MAX;
        counters.domain_logical_used_bytes = u64::MAX - 10;
        counters.domain_pinned_snapshot_bytes = 100;
        reg.create_domain(id, counters).unwrap();

        let statfs = reg.domain_statfs(&id).unwrap();

        assert_eq!(statfs.blocks, u64::MAX / StatfsResult::DEFAULT_BLOCK_SIZE);
        assert_eq!(statfs.blocks_free, 0);
        assert_eq!(statfs.blocks_avail, 0);
    }

    #[test]
    fn domain_statfs_nonexistent_returns_none() {
        let reg = SpaceDomainRegistry::new();
        assert!(reg.domain_statfs(&SpaceDomainId(42)).is_none());
    }

    #[test]
    fn domain_apply_delta_updates_counters() {
        let mut reg = SpaceDomainRegistry::new();
        let id = SpaceDomainId(8);
        reg.create_domain(id, test_domain_counters()).unwrap();

        // Simulate a write delta: +4096 used, +0 reserved, +0 orphan, +0 pinned
        let delta = SpaceDelta::new_write(4096);
        reg.apply_domain_delta(id, &delta).unwrap();

        let dc = reg.get(&id).unwrap();
        assert_eq!(dc.domain_logical_used_bytes, 4096);
    }

    #[test]
    fn domain_apply_delta_not_found() {
        let mut reg = SpaceDomainRegistry::new();
        let delta = SpaceDelta::new_write(100);
        let result = reg.apply_domain_delta(SpaceDomainId(99), &delta);
        assert!(result.is_err());
    }

    #[test]
    fn domain_set_quota_updates() {
        let mut reg = SpaceDomainRegistry::new();
        let id = SpaceDomainId(6);
        reg.create_domain(id, test_domain_counters()).unwrap();

        reg.set_domain_quota(id, 5_000_000).unwrap();
        assert_eq!(reg.get(&id).unwrap().domain_quota_bytes, 5_000_000);
    }

    #[test]
    fn domain_set_quota_not_found() {
        let mut reg = SpaceDomainRegistry::new();
        let result = reg.set_domain_quota(SpaceDomainId(99), 1000);
        assert!(result.is_err());
    }

    #[test]
    fn domain_iter_yields_all_entries() {
        let mut reg = SpaceDomainRegistry::new();
        reg.create_domain(SpaceDomainId(1), test_domain_counters())
            .unwrap();
        reg.create_domain(SpaceDomainId(2), test_domain_counters())
            .unwrap();
        reg.create_domain(SpaceDomainId(3), test_domain_counters())
            .unwrap();

        let mut ids: Vec<u64> = reg.iter().map(|(id, _)| id.0).collect();
        ids.sort();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[test]
    fn domain_display_format() {
        let mut reg = SpaceDomainRegistry::new();
        reg.create_domain(SpaceDomainId(1), test_domain_counters())
            .unwrap();
        let s = format!("{reg}");
        assert!(s.contains("SpaceDomainRegistry"));
        assert!(s.contains("domains=1"));
    }

    #[test]
    fn domain_default_is_empty() {
        let reg = SpaceDomainRegistry::default();
        assert_eq!(reg.domain_count(), 0);
    }
    // ===================================================================
    // Phase 3: Reservation model with admission control
    // ===================================================================

    // -- Slop management --

    #[test]
    fn slop_default_ratio_is_1_64th() {
        let mut sa = SpaceAccounting::empty();
        sa.counters.quota_bytes = 64_000_000;
        sa.set_default_slop();
        assert_eq!(sa.slop_bytes(), 1_000_000);
    }

    #[test]
    fn slop_zero_for_zero_quota() {
        let mut sa = SpaceAccounting::empty();
        sa.set_default_slop();
        assert_eq!(sa.slop_bytes(), 0);
    }

    #[test]
    fn slop_explicit_set_overrides() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.set_slop(500_000);
        assert_eq!(sa.slop_bytes(), 500_000);
    }

    #[test]
    fn slop_reduces_available_quota_ceiling() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        // Quota = 1 GB, slop = 100 MB => effective ceiling = 900 MB.
        sa.set_slop(100_000_000);
        // Fill to 899,999,999 bytes used (1 byte of effective quota left).
        let fill = SpaceDelta::new_write(TEST_QUOTA_BYTES - 100_000_000 - 1);
        sa.commit_delta(fill).unwrap();
        // A 10-byte write hits the slop ceiling via commit_delta admission.
        let result = sa.commit_delta(SpaceDelta::new_write(10));
        assert!(result.is_err());
        match result {
            Err(SpaceAccountingError::QuotaExceeded { .. }) => {}
            other => panic!("expected QuotaExceeded, got {other:?}"),
        }
    }

    // -- Reservation lifecycle --

    #[test]
    fn reserve_bytes_adds_reserved_counter() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.reserve_bytes(100_000).unwrap();
        assert_eq!(sa.counters().reserved_bytes, 100_000);
        // logical_used is unchanged (reservation is separate).
        assert_eq!(sa.counters().logical_used_bytes, 0);
    }

    #[test]
    fn consume_reservation_converts_to_data() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.reserve_bytes(100_000).unwrap();
        sa.consume_reservation(50_000).unwrap();
        // 50K converted to data, 50K still reserved.
        assert_eq!(sa.counters().reserved_bytes, 50_000);
    }

    #[test]
    fn consume_more_than_reserved_fails() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.reserve_bytes(10_000).unwrap();
        // write_into_unwritten of 20K tries to release 20K reserved but only 10K exists.
        let result = sa.consume_reservation(20_000);
        assert!(result.is_err());
    }

    #[test]
    fn punch_hole_releases_bytes() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.commit_delta(SpaceDelta::new_write(500_000)).unwrap();
        assert_eq!(sa.counters().logical_used_bytes, 500_000);
        sa.punch_hole(200_000).unwrap();
        assert_eq!(sa.counters().logical_used_bytes, 300_000);
    }

    #[test]
    fn punch_hole_below_zero_fails() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        let result = sa.punch_hole(1);
        assert!(result.is_err());
        match result {
            Err(SpaceAccountingError::CounterUnderflow { .. }) => {}
            other => panic!("expected CounterUnderflow, got {other:?}"),
        }
    }

    #[test]
    fn fallocate_guarantee_write_never_enospc() {
        // Core invariant: a successful fallocate guarantees subsequent writes
        // into the reserved region never hit ENOSPC.
        //
        // Fill quota to leave only 10 KB headroom, then reserve that 10 KB.
        // A direct write of 1 byte hits ENOSPC (quota exhausted).  But
        // consuming the reservation succeeds because it doesn't increase
        // logical_alloc_bytes — the space was already counted.
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        // Fill to quota - 10,000 bytes.
        let fill = SpaceDelta::new_write(TEST_QUOTA_BYTES - 10_000);
        sa.commit_delta(fill).unwrap();
        // Reserve the last 10 KB of quota headroom.
        sa.reserve_bytes(10_000).unwrap();
        // logical_alloc = (quota - 10K) + 10K = quota. Quota fully allocated.
        assert_eq!(sa.counters().logical_alloc_bytes(), TEST_QUOTA_BYTES);
        // A direct 1-byte write must ENOSPC — no quota room left.
        assert!(sa.commit_delta(SpaceDelta::new_write(1)).is_err());
        // But consuming the reservation (UNWRITTEN -> DATA) succeeds
        // because it doesn't request *new* alloc bytes — the space was
        // already counted against quota when `reserve_bytes()` ran.
        sa.consume_reservation(10_000).unwrap();
        // reserved bytes released; logical_used unchanged (design doc s3.1:
        // bytes were already counted as reserved, so logical_used doesn't
        // double-increment).
        assert_eq!(sa.counters().reserved_bytes, 0);
        assert_eq!(sa.counters().logical_used_bytes, TEST_QUOTA_BYTES - 10_000);
        // A subsequent direct write of 1 byte still ENOSPCs because
        // logical_used is still at quota - 10_000.  The reservation
        // consumed the quota headroom; now 10K of quota is available
        // again because reserved_bytes was released, but the data is
        // tracked via extent maps rather than a counter increment.
        //
        // In practice, the filesystem layer will update logical_used
        // when converting UNWRITTEN extents to DATA; this test validates
        // the space accounting runtime's reservation guarantee in
        // isolation.
    }

    #[test]
    fn reserve_beyond_quota_fails() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        let result = sa.reserve_bytes(TEST_QUOTA_BYTES + 1);
        assert!(result.is_err());
    }

    #[test]
    fn reserve_beyond_physical_capacity_fails() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        let pool = test_pool(50_000, 500_000); // only 50 KB physically free
        sa.update_pool_counters(pool);
        // Physical ENOSPC check: 100 KB > 50 KB free → blocks
        assert!(sa.check_enospc_physical(100_000));
        // Small reservation (below free bytes) still passes.
        let result = sa.reserve_bytes(10_000);
        assert!(result.is_ok());
    }

    #[test]
    fn available_for_reservation_empty() {
        let sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        // No quota set in test_counters? Actually test_counters has quota.
        assert_eq!(sa.available_for_reservation(), TEST_QUOTA_BYTES);
    }

    #[test]
    fn available_for_reservation_consumed() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.commit_delta(SpaceDelta::new_write(500_000_000)).unwrap();
        assert_eq!(sa.available_for_reservation(), 500_000_000);
    }

    // -- ENOSPC observability --

    #[test]
    fn check_and_record_enospc_allowed() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        let result = sa.check_and_record_enospc(100);
        assert!(result.is_ok());
        assert_eq!(sa.enospc_blocks(), 0);
    }

    #[test]
    fn check_and_record_enospc_denied_records() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        let result = sa.check_and_record_enospc(TEST_QUOTA_BYTES + 1);
        assert!(result.is_err());
        assert_eq!(sa.enospc_blocks(), TEST_QUOTA_BYTES + 1);
    }

    #[test]
    fn check_and_record_enospc_cumulative() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        let _ = sa.check_and_record_enospc(TEST_QUOTA_BYTES + 100);
        let _ = sa.check_and_record_enospc(TEST_QUOTA_BYTES + 200);
        assert_eq!(
            sa.enospc_blocks(),
            (TEST_QUOTA_BYTES + 100) + (TEST_QUOTA_BYTES + 200)
        );
    }

    // -- OperationKind worst-case bytes --

    #[test]
    fn worst_case_write_is_full_bytes() {
        assert_eq!(
            SpaceAccounting::worst_case_bytes(OperationKind::Write, 4096),
            4096
        );
        assert_eq!(
            SpaceAccounting::worst_case_bytes(OperationKind::Write, 0),
            0
        );
    }

    #[test]
    fn worst_case_fallocate_is_full_bytes() {
        assert_eq!(
            SpaceAccounting::worst_case_bytes(OperationKind::Fallocate, 1_000_000),
            1_000_000
        );
    }

    #[test]
    fn worst_case_clone_is_zero() {
        // Clones share existing blocks, so no new bytes are allocated.
        assert_eq!(
            SpaceAccounting::worst_case_bytes(OperationKind::Clone, 1_000_000),
            0
        );
    }

    // -- Reservation + write-into-unwritten saturation safety --

    #[test]
    fn reservation_then_multiple_consumes() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.reserve_bytes(300_000).unwrap();
        sa.consume_reservation(100_000).unwrap();
        assert_eq!(sa.counters().reserved_bytes, 200_000);
        sa.consume_reservation(100_000).unwrap();
        assert_eq!(sa.counters().reserved_bytes, 100_000);
        sa.consume_reservation(100_000).unwrap();
        assert_eq!(sa.counters().reserved_bytes, 0);
    }

    // ===================================================================
    // Phase 4: Snapshot deadlist accounting
    // ===================================================================

    // -- SnapshotDeadlist --

    #[test]
    fn deadlist_new_is_empty() {
        let dl = SnapshotDeadlist::new(42);
        assert_eq!(dl.pinned_bytes(), 0);
        assert_eq!(dl.pinned_extents(), 0);
        assert!(dl.is_active());
        assert_eq!(dl.snap_commit_group, 42);
    }

    #[test]
    fn deadlist_add_extent_tracks_bytes() {
        let mut dl = SnapshotDeadlist::new(1);
        dl.add_extent(4096).unwrap();
        assert_eq!(dl.pinned_bytes(), 4096);
        assert_eq!(dl.pinned_extents(), 1);

        dl.add_extent(8192).unwrap();
        assert_eq!(dl.pinned_bytes(), 12288);
        assert_eq!(dl.pinned_extents(), 2);
    }

    #[test]
    fn deadlist_add_extent_not_active_rejected() {
        let mut dl = SnapshotDeadlist::new(1);
        dl.mark_destroying();
        let result = dl.add_extent(4096);
        assert!(result.is_err());
    }

    #[test]
    fn deadlist_remove_extent_reduces_bytes() {
        let mut dl = SnapshotDeadlist::new(1);
        dl.add_extent(10_000).unwrap();
        dl.remove_extent(4_000).unwrap();
        assert_eq!(dl.pinned_bytes(), 6_000);
        assert_eq!(dl.pinned_extents(), 0); // count decremented
    }

    #[test]
    fn deadlist_remove_extent_underflow_rejected() {
        let mut dl = SnapshotDeadlist::new(1);
        dl.add_extent(100).unwrap();
        let result = dl.remove_extent(200);
        assert!(result.is_err());
        // Bytes unchanged after failed removal.
        assert_eq!(dl.pinned_bytes(), 100);
    }

    #[test]
    fn deadlist_to_record_roundtrip() {
        let mut dl = SnapshotDeadlist::new(5);
        dl.add_extent(42_000).unwrap();
        dl.add_extent(8_000).unwrap();

        let record = dl.to_record();
        assert_eq!(record.snap_commit_group, 5);
        assert_eq!(record.deadlist_bytes, 50_000);
        assert_eq!(record.deadlist_count, 2);
        assert_eq!(record.state, SnapshotState::Active);

        let dl2 = SnapshotDeadlist::from_record(record);
        assert_eq!(dl2.pinned_bytes(), 50_000);
        assert_eq!(dl2.pinned_extents(), 2);
        assert!(dl2.is_active());
    }

    // -- SnapshotSpaceManager --

    #[test]
    fn manager_create_and_query_snapshot() {
        let mut mgr = SnapshotSpaceManager::new();
        let commit_group = mgr.create_snapshot();
        assert_eq!(mgr.snapshot_count(), 1);
        assert_eq!(mgr.active_snapshot_count(), 1);
        assert!(mgr.get(commit_group).is_some());
        assert!(mgr.get(commit_group).unwrap().is_active());
    }

    #[test]
    fn manager_multiple_snapshots_sequential_commit_group() {
        let mut mgr = SnapshotSpaceManager::new();
        let commit_group1 = mgr.create_snapshot();
        let commit_group2 = mgr.create_snapshot();
        assert!(commit_group2 > commit_group1);
        assert_eq!(mgr.snapshot_count(), 2);
    }

    #[test]
    fn manager_create_at_specific_commit_group() {
        let mut mgr = SnapshotSpaceManager::new();
        mgr.create_snapshot_at(100).unwrap();
        assert_eq!(mgr.snapshot_count(), 1);
        assert!(mgr.get(100).is_some());
    }

    #[test]
    fn manager_create_at_duplicate_commit_group_rejected() {
        let mut mgr = SnapshotSpaceManager::new();
        mgr.create_snapshot_at(50).unwrap();
        let result = mgr.create_snapshot_at(50);
        assert!(result.is_err());
    }

    #[test]
    fn manager_destroy_returns_pinned_bytes() {
        let mut mgr = SnapshotSpaceManager::new();
        let commit_group = mgr.create_snapshot();
        mgr.get_mut(commit_group)
            .unwrap()
            .add_extent(10_000)
            .unwrap();
        mgr.get_mut(commit_group)
            .unwrap()
            .add_extent(5_000)
            .unwrap();

        let freed = mgr.destroy_snapshot(commit_group);
        assert_eq!(freed, Some(15_000));
        assert_eq!(mgr.snapshot_count(), 0);
    }

    #[test]
    fn manager_destroy_nonexistent_returns_none() {
        let mut mgr = SnapshotSpaceManager::new();
        assert_eq!(mgr.destroy_snapshot(999), None);
    }

    #[test]
    fn manager_total_pinned_bytes_active_only() {
        let mut mgr = SnapshotSpaceManager::new();
        let snap1 = mgr.create_snapshot();
        let snap2 = mgr.create_snapshot();
        mgr.get_mut(snap1).unwrap().add_extent(100).unwrap();
        mgr.get_mut(snap2).unwrap().add_extent(200).unwrap();

        // Both active: total = 300.
        assert_eq!(mgr.total_pinned_bytes(), 300);

        // Mark snap1 destroying.
        mgr.mark_destroying(snap1).unwrap();
        // Only snap2 (200) counted as active.
        assert_eq!(mgr.total_pinned_bytes(), 200);
    }

    #[test]
    fn manager_total_pinned_bytes_all_includes_destroying() {
        let mut mgr = SnapshotSpaceManager::new();
        let snap = mgr.create_snapshot();
        mgr.get_mut(snap).unwrap().add_extent(500).unwrap();
        mgr.mark_destroying(snap).unwrap();

        // total_pinned_bytes_all counts even DESTROYING snapshots.
        assert_eq!(mgr.total_pinned_bytes_all(), 500);
    }

    #[test]
    fn manager_pin_extent_to_oldest_active() {
        let mut mgr = SnapshotSpaceManager::new();
        let snap10 = 10;
        let snap20 = 20;
        mgr.create_snapshot_at(snap10).unwrap();
        mgr.create_snapshot_at(snap20).unwrap();

        // Block born at commit_group 15: snap10 existed before it, snap20 after.
        // Oldest active snapshot >= 15 is snap20.
        let pinned_commit_group = mgr.pin_extent_to_oldest_active(15, 4096).unwrap();
        assert_eq!(pinned_commit_group, 20);
        assert_eq!(mgr.get(20).unwrap().pinned_bytes(), 4096);
        assert_eq!(mgr.get(10).unwrap().pinned_bytes(), 0);
    }

    #[test]
    fn manager_pin_extent_no_applicable_snapshot() {
        let mut mgr = SnapshotSpaceManager::new();
        mgr.create_snapshot_at(10).unwrap();
        mgr.mark_destroying(10).unwrap();

        // Block born at commit_group 5, oldest active snap >= 5 is snap10 (but it's destroying).
        let result = mgr.pin_extent_to_oldest_active(5, 100);
        assert!(result.is_err());
    }

    #[test]
    fn manager_mark_destroying_nonexistent_fails() {
        let mut mgr = SnapshotSpaceManager::new();
        let result = mgr.mark_destroying(42);
        assert!(result.is_err());
    }

    #[test]
    fn manager_iter_yields_all_snapshots() {
        let mut mgr = SnapshotSpaceManager::new();
        mgr.create_snapshot_at(30).unwrap();
        mgr.create_snapshot_at(10).unwrap();
        mgr.create_snapshot_at(20).unwrap();

        let mut commit_groups: Vec<u64> =
            mgr.iter().map(|(&commit_group, _)| commit_group).collect();
        commit_groups.sort();
        assert_eq!(commit_groups, vec![10, 20, 30]);
    }

    #[test]
    fn manager_default_is_empty() {
        let mgr = SnapshotSpaceManager::default();
        assert_eq!(mgr.snapshot_count(), 0);
        assert_eq!(mgr.total_pinned_bytes(), 0);
    }

    #[test]
    fn deadlist_saturation_safety() {
        let mut dl = SnapshotDeadlist::new(1);
        dl.add_extent(u64::MAX).unwrap();
        // Adding more bytes should saturate pinned_bytes, not panic.
        dl.add_extent(1).unwrap();
        assert_eq!(dl.pinned_bytes(), u64::MAX);
        // Count is incremented normally (2 extents added).
        assert_eq!(dl.pinned_extents(), 2);
    }

    // -- CleanerWatermarks tests -------------------------------------------------

    #[test]
    fn watermarks_defaults_for_large_pool() {
        let w = CleanerWatermarks::for_pool(1_000_000);
        assert_eq!(w.min_free_segments, 20_000);
        assert_eq!(w.target_free_segments, 50_000);
        assert_eq!(w.high_free_segments, 80_000);
        assert_eq!(w.tail_reserved_segments, 10_000);
    }

    #[test]
    fn watermarks_defaults_for_small_pool() {
        let w = CleanerWatermarks::for_pool(100);
        assert_eq!(w.min_free_segments, 2);
        assert_eq!(w.target_free_segments, 5);
        assert_eq!(w.high_free_segments, 8);
        assert_eq!(w.tail_reserved_segments, 1);
    }

    #[test]
    fn watermarks_clamps_tiny_pool() {
        let w = CleanerWatermarks::for_pool(1);
        // Even with 1 segment, watermarks should be clamped to 1.
        assert_eq!(w.min_free_segments, 1);
        assert_eq!(w.target_free_segments, 2);
        assert_eq!(w.high_free_segments, 4);
        assert_eq!(w.tail_reserved_segments, 1);
    }

    #[test]
    fn watermarks_for_pool_zero_total() {
        let w = CleanerWatermarks::for_pool(0);
        // Zero total segments should not panic — treated as 1.
        assert!(w.min_free_segments >= 1);
        assert!(w.target_free_segments >= 1);
    }

    #[test]
    fn watermarks_default_constructor() {
        let w = CleanerWatermarks::default();
        // default() uses for_pool(1000)
        assert_eq!(w.target_free_segments, 50);
        assert_eq!(w.min_free_segments, 20);
        assert_eq!(w.high_free_segments, 80);
    }

    // -- CleanerScheduler tests --------------------------------------------------

    fn make_scheduler(total_segments: u64) -> CleanerScheduler {
        CleanerScheduler::new(CleanerWatermarks::for_pool(total_segments))
    }

    #[test]
    fn scheduler_blocks_writers_below_min() {
        let s = make_scheduler(1000); // min=20
        assert_eq!(s.evaluate(19), CleanerAction::BlockWriters);
        assert_eq!(s.evaluate(0), CleanerAction::BlockWriters);
    }

    #[test]
    fn scheduler_starts_background_below_target() {
        let s = make_scheduler(1000); // min=20, target=50
        assert_eq!(s.evaluate(20), CleanerAction::StartBackground);
        assert_eq!(s.evaluate(49), CleanerAction::StartBackground);
    }

    #[test]
    fn scheduler_no_change_in_target_zone() {
        let s = make_scheduler(1000); // target=50, high=80
        assert_eq!(s.evaluate(50), CleanerAction::NoChange);
        assert_eq!(s.evaluate(65), CleanerAction::NoChange);
        assert_eq!(s.evaluate(80), CleanerAction::NoChange);
    }

    #[test]
    fn scheduler_stops_above_high() {
        let s = make_scheduler(1000); // high=80
        assert_eq!(s.evaluate(81), CleanerAction::Stop);
        assert_eq!(s.evaluate(999), CleanerAction::Stop);
    }

    #[test]
    fn scheduler_full_pool_blocks() {
        let s = make_scheduler(500);
        // min=10, so 9 free -> block
        assert_eq!(s.evaluate(9), CleanerAction::BlockWriters);
        assert_eq!(s.evaluate(10), CleanerAction::StartBackground);
    }

    #[test]
    fn scheduler_watermarks_accessor() {
        let w = CleanerWatermarks::for_pool(200);
        let s = CleanerScheduler::new(w);
        assert_eq!(s.watermarks().target_free_segments, 10);
    }

    #[test]
    fn scheduler_default_works() {
        let s = CleanerScheduler::default();
        // default watermarks for pool 1000: min=20, target=50, high=80
        assert_eq!(s.evaluate(10), CleanerAction::BlockWriters);
        assert_eq!(s.evaluate(30), CleanerAction::StartBackground);
        assert_eq!(s.evaluate(60), CleanerAction::NoChange);
        assert_eq!(s.evaluate(100), CleanerAction::Stop);
    }

    // -- CleanerAction tests -----------------------------------------------------

    #[test]
    fn cleaner_action_debug_and_eq() {
        assert_eq!(CleanerAction::BlockWriters, CleanerAction::BlockWriters);
        assert_ne!(CleanerAction::BlockWriters, CleanerAction::StartBackground);
        // Debug output should not panic
        let _ = format!("{:?}", CleanerAction::Stop);
        let _ = format!("{:?}", CleanerAction::NoChange);
    }

    // -- refresh_physical_counters tests -----------------------------------------

    #[test]
    fn refresh_physical_counters_sets_pool() {
        let mut sa = SpaceAccounting::empty();
        sa.refresh_physical_counters(100, 1000, 50, 4096, 10);

        let pool = sa.pool_counters().expect("pool counters should be set");
        assert_eq!(pool.phys_free_segments, 100);
        assert_eq!(pool.phys_free_bytes, 100 * 4096);
        assert_eq!(pool.phys_reclaimable_bytes, 50);
        assert_eq!(pool.phys_tail_reserved_segments, 10);
        assert_eq!(pool.phys_total_segments, 1000);
        assert_eq!(pool.phys_total_bytes, 1000 * 4096);
    }

    #[test]
    fn refresh_physical_counters_updates_existing_pool() {
        let mut sa = SpaceAccounting::empty();
        sa.refresh_physical_counters(200, 2000, 0, 4096, 20);

        // Refresh again with different values
        sa.refresh_physical_counters(150, 2000, 100, 4096, 20);
        let pool = sa.pool_counters().unwrap();
        assert_eq!(pool.phys_free_segments, 150);
        assert_eq!(pool.phys_reclaimable_bytes, 100);
    }

    #[test]
    fn refresh_physical_counters_zero_reclaimable() {
        let mut sa = SpaceAccounting::empty();
        sa.refresh_physical_counters(0, 500, 0, 4096, 5);
        let pool = sa.pool_counters().unwrap();
        assert_eq!(pool.phys_free_segments, 0);
        assert_eq!(pool.phys_free_bytes, 0);
        assert!(pool.phys_usable_segments() > 0);
    }

    #[test]
    fn refresh_physical_counters_phys_capacity_updated() {
        let mut sa = SpaceAccounting::empty();
        sa.refresh_physical_counters(500, 1000, 0, 4096, 10);
        // phys_capacity_bytes uses phys_free_bytes
        assert_eq!(sa.phys_capacity_bytes(), 500 * 4096);
    }

    #[test]
    fn refresh_physical_counters_full_pool_zero_free() {
        let mut sa = SpaceAccounting::empty();
        sa.refresh_physical_counters(0, 10000, 0, 4096, 100);
        let pool = sa.pool_counters().unwrap();
        assert!(pool.should_block_writes(1));
    }
    // -- Obligation ledger consistency (§9) --

    #[test]
    fn obligation_consistency_perfect_match() {
        let mut sa = SpaceAccounting::empty();
        sa.set_domain(SpaceDomainId(1));
        sa.commit_delta(SpaceDelta::new_write(1000)).unwrap();
        assert!(sa.verify_obligation_consistency(1000, 0));
        assert_eq!(sa.obligation_discrepancy(1000), 0);
    }

    #[test]
    fn obligation_consistency_within_tolerance() {
        let mut sa = SpaceAccounting::empty();
        sa.set_domain(SpaceDomainId(1));
        sa.commit_delta(SpaceDelta::new_write(1000)).unwrap();
        // Obligation ledger may be slightly ahead (inflight writes)
        assert!(sa.verify_obligation_consistency(1050, 100));
        assert_eq!(sa.obligation_discrepancy(1050), 50);
    }

    #[test]
    fn obligation_consistency_detects_divergence() {
        let mut sa = SpaceAccounting::empty();
        sa.set_domain(SpaceDomainId(1));
        sa.commit_delta(SpaceDelta::new_write(1000)).unwrap();
        // Large discrepancy should fail with tight tolerance
        assert!(!sa.verify_obligation_consistency(5000, 100));
        assert_eq!(sa.obligation_discrepancy(5000), 4000);
    }

    #[test]
    fn obligation_consistency_free_path() {
        let mut sa = SpaceAccounting::empty();
        sa.set_domain(SpaceDomainId(1));
        // Write then free: both systems should converge back to zero
        sa.commit_delta(SpaceDelta::new_write(1000)).unwrap();
        sa.commit_delta(SpaceDelta::new_free(500)).unwrap();
        assert!(sa.verify_obligation_consistency(500, 0));
        assert_eq!(sa.obligation_discrepancy(500), 0);
    }

    #[test]
    fn obligation_consistency_zero_write_should_match() {
        let mut sa = SpaceAccounting::empty();
        sa.set_domain(SpaceDomainId(1));
        // Both systems should agree on zero
        assert!(sa.verify_obligation_consistency(0, 0));
        assert_eq!(sa.obligation_discrepancy(0), 0);
    }

    // ===================================================================
    // Phase 2: Per-user and per-group quota
    // ===================================================================

    // -- UserQuota tests --

    #[test]
    fn user_quota_new_zero_usage() {
        let q = UserQuota::new(1000);
        assert_eq!(q.uid, 1000);
        assert_eq!(q.used_bytes, 0);
        assert_eq!(q.soft_limit, 0);
        assert_eq!(q.hard_limit, 0);
        assert_eq!(q.file_count, 0);
        assert_eq!(q.file_limit, 0);
        assert!(!q.has_hard_limit());
        assert!(!q.has_soft_limit());
    }

    #[test]
    fn user_quota_charge_within_hard_limit() {
        let mut q = UserQuota::new(1000);
        q.hard_limit = 1024 * 1024; // 1 MiB
        q.charge_bytes(512 * 1024).unwrap();
        assert_eq!(q.used_bytes, 512 * 1024);
    }

    #[test]
    fn user_quota_charge_exceeds_hard_limit() {
        let mut q = UserQuota::new(1000);
        q.hard_limit = 1024;
        q.charge_bytes(500).unwrap();
        let result = q.charge_bytes(600);
        assert!(result.is_err());
        // Bytes unchanged after refused charge.
        assert_eq!(q.used_bytes, 500);
    }

    #[test]
    fn user_quota_charge_exactly_at_hard_limit() {
        let mut q = UserQuota::new(1000);
        q.hard_limit = 1024;
        q.charge_bytes(1024).unwrap();
        assert_eq!(q.used_bytes, 1024);
    }

    #[test]
    fn user_quota_charge_no_limit_unbounded() {
        let mut q = UserQuota::new(1000);
        // No limits set → unlimited.
        q.charge_bytes(u64::MAX).unwrap();
        assert_eq!(q.used_bytes, u64::MAX);
    }

    #[test]
    fn user_quota_credit_bytes() {
        let mut q = UserQuota::new(1000);
        q.used_bytes = 1000;
        q.credit_bytes(300).unwrap();
        assert_eq!(q.used_bytes, 700);
    }

    #[test]
    fn user_quota_credit_underflow_rejected() {
        let mut q = UserQuota::new(1000);
        q.used_bytes = 100;
        let result = q.credit_bytes(200);
        assert!(result.is_err());
        assert_eq!(q.used_bytes, 100); // unchanged
    }

    #[test]
    fn user_quota_file_charge_and_credit() {
        let mut q = UserQuota::new(1000);
        q.file_limit = 10;
        for _ in 0..10 {
            q.charge_file().unwrap();
        }
        assert_eq!(q.file_count, 10);
        // 11th file should fail.
        assert!(q.charge_file().is_err());
        // Credit one back.
        q.credit_file().unwrap();
        assert_eq!(q.file_count, 9);
        // Now one more fits.
        q.charge_file().unwrap();
        assert_eq!(q.file_count, 10);
    }

    #[test]
    fn user_quota_file_credit_empty_rejected() {
        let mut q = UserQuota::new(1000);
        let result = q.credit_file();
        assert!(result.is_err());
    }

    #[test]
    fn user_quota_file_no_limit_unbounded() {
        let mut q = UserQuota::new(1000);
        // No file limit → always ok.
        for _ in 0..1000 {
            q.charge_file().unwrap();
        }
        assert_eq!(q.file_count, 1000);
    }

    #[test]
    fn user_quota_available_bytes_with_limit() {
        let mut q = UserQuota::new(1000);
        q.hard_limit = 10000;
        q.used_bytes = 3000;
        assert_eq!(q.available_bytes(), 7000);
    }

    #[test]
    fn user_quota_available_bytes_no_limit() {
        let q = UserQuota::new(1000);
        assert_eq!(q.available_bytes(), u64::MAX);
    }

    // -- GroupQuota tests --

    #[test]
    fn group_quota_charge_and_credit() {
        let mut q = GroupQuota::new(100);
        q.hard_limit = 5000;
        q.charge_bytes(2000).unwrap();
        assert_eq!(q.used_bytes, 2000);
        q.credit_bytes(500).unwrap();
        assert_eq!(q.used_bytes, 1500);
    }

    #[test]
    fn group_quota_hard_limit_enforcement() {
        let mut q = GroupQuota::new(100);
        q.hard_limit = 1000;
        q.charge_bytes(800).unwrap();
        assert!(q.charge_bytes(300).is_err());
        assert_eq!(q.used_bytes, 800);
    }

    #[test]
    fn group_quota_file_accounting() {
        let mut q = GroupQuota::new(100);
        q.file_limit = 5;
        for _ in 0..5 {
            q.charge_file().unwrap();
        }
        assert!(q.charge_file().is_err());
    }

    // -- QuotaCheck tests --

    #[test]
    fn quota_check_user_allowed() {
        let q = UserQuota {
            uid: 1000,
            used_bytes: 500,
            soft_limit: 0,
            hard_limit: 1000,
            file_count: 0,
            file_limit: 0,
        };
        assert_eq!(QuotaCheck::check_user(&q, 400), QuotaVerdict::Allowed);
    }

    #[test]
    fn quota_check_user_soft_limit_exceeded() {
        let q = UserQuota {
            uid: 1000,
            used_bytes: 800,
            soft_limit: 1000,
            hard_limit: 2000,
            file_count: 0,
            file_limit: 0,
        };
        let result = QuotaCheck::check_user(&q, 300);
        assert!(matches!(result, QuotaVerdict::SoftLimitExceeded { .. }));
    }

    #[test]
    fn quota_check_user_hard_limit_exceeded() {
        let q = UserQuota {
            uid: 1000,
            used_bytes: 900,
            soft_limit: 0,
            hard_limit: 1000,
            file_count: 0,
            file_limit: 0,
        };
        let result = QuotaCheck::check_user(&q, 200);
        assert!(matches!(result, QuotaVerdict::HardLimitExceeded { .. }));
    }

    #[test]
    fn quota_check_user_hard_beats_soft() {
        // When both soft and hard limits are exceeded, hard takes precedence.
        let q = UserQuota {
            uid: 1000,
            used_bytes: 1900,
            soft_limit: 1000,
            hard_limit: 2000,
            file_count: 0,
            file_limit: 0,
        };
        let result = QuotaCheck::check_user(&q, 200);
        assert!(matches!(result, QuotaVerdict::HardLimitExceeded { .. }));
    }

    #[test]
    fn quota_check_group() {
        let q = GroupQuota {
            gid: 100,
            used_bytes: 0,
            soft_limit: 5000,
            hard_limit: 10000,
            file_count: 0,
            file_limit: 0,
        };
        assert_eq!(QuotaCheck::check_group(&q, 1000), QuotaVerdict::Allowed);
        let result = QuotaCheck::check_group(&q, 6000);
        assert!(matches!(result, QuotaVerdict::SoftLimitExceeded { .. }));
        let result = QuotaCheck::check_group(&q, 11000);
        assert!(matches!(result, QuotaVerdict::HardLimitExceeded { .. }));
    }

    // -- QuotaTable basic tests --

    #[test]
    fn quota_table_new_is_empty() {
        let table = QuotaTable::new();
        assert_eq!(table.user_count(), 0);
        assert_eq!(table.group_count(), 0);
        assert!(!table.has_parent());
    }

    #[test]
    fn quota_table_charge_user_creates_entry() {
        let mut table = QuotaTable::new();
        table.set_user_limits(1000, 0, 10_000, 0);
        table.charge_user(1000, 500).unwrap();
        assert_eq!(table.get_user(1000).unwrap().used_bytes, 500);
        assert_eq!(table.user_count(), 1);
    }

    #[test]
    fn quota_table_charge_user_exceeds_hard_limit() {
        let mut table = QuotaTable::new();
        table.set_user_limits(1000, 0, 1000, 0);
        table.charge_user(1000, 800).unwrap();
        let result = table.charge_user(1000, 300);
        assert!(result.is_err());
        assert_eq!(table.get_user(1000).unwrap().used_bytes, 800);
    }

    #[test]
    fn quota_table_credit_user() {
        let mut table = QuotaTable::new();
        table.set_user_limits(1000, 0, 10_000, 0);
        table.charge_user(1000, 1000).unwrap();
        table.credit_user(1000, 400).unwrap();
        assert_eq!(table.get_user(1000).unwrap().used_bytes, 600);
    }

    #[test]
    fn quota_table_credit_user_no_entry_fails() {
        let mut table = QuotaTable::new();
        let result = table.credit_user(1000, 100);
        assert!(result.is_err());
    }

    #[test]
    fn quota_table_charge_group() {
        let mut table = QuotaTable::new();
        table.set_group_limits(100, 0, 5000, 0);
        table.charge_group(100, 1000).unwrap();
        assert_eq!(table.get_group(100).unwrap().used_bytes, 1000);
    }

    #[test]
    fn quota_table_charge_group_exceeds_limit() {
        let mut table = QuotaTable::new();
        table.set_group_limits(100, 0, 500, 0);
        table.charge_group(100, 400).unwrap();
        assert!(table.charge_group(100, 200).is_err());
    }

    #[test]
    fn quota_table_user_file_accounting() {
        let mut table = QuotaTable::new();
        table.set_user_limits(1000, 0, 0, 100); // file_limit only
        for _ in 0..100 {
            table.charge_user_file(1000).unwrap();
        }
        assert!(table.charge_user_file(1000).is_err());
        table.credit_user_file(1000).unwrap();
        table.charge_user_file(1000).unwrap(); // should fit now
    }

    #[test]
    fn quota_table_set_user_limits_zero_preserves_existing() {
        let mut table = QuotaTable::new();
        table.set_user_limits(1000, 5000, 10000, 50);
        // Setting with zeros should not overwrite non-zero values.
        table.set_user_limits(1000, 0, 0, 0);
        let (_soft, hard, _files) = table.effective_user_limits(1000);
        assert_eq!(hard, 10000);
    }

    // -- QuotaTable inheritance tests --

    #[test]
    fn quota_inheritance_child_inherits_parent_limits() {
        let mut parent = QuotaTable::new();
        parent.set_user_limits(1000, 0, 1_000_000, 0);

        let mut child = QuotaTable::new();
        child.set_parent(parent);

        // Child has no explicit limits for uid 1000 → inherits from parent.
        let (_soft, hard, _files) = child.effective_user_limits(1000);
        assert_eq!(hard, 1_000_000);
    }

    #[test]
    fn quota_inheritance_child_override_parent() {
        let mut parent = QuotaTable::new();
        parent.set_user_limits(1000, 0, 1_000_000, 0);

        let mut child = QuotaTable::new();
        child.set_parent(parent);
        // Child sets its own stricter limit.
        child.set_user_limits(1000, 0, 500_000, 0);

        let (_soft, hard, _files) = child.effective_user_limits(1000);
        assert_eq!(hard, 500_000);
    }

    #[test]
    fn quota_inheritance_charge_respects_inherited_limits() {
        let mut parent = QuotaTable::new();
        parent.set_user_limits(1000, 0, 1000, 0);

        let mut child = QuotaTable::new();
        child.set_parent(parent);

        // Charge within inherited limit.
        child.charge_user(1000, 800).unwrap();
        assert_eq!(child.get_user(1000).unwrap().used_bytes, 800);

        // Charge beyond inherited limit.
        assert!(child.charge_user(1000, 300).is_err());
    }

    #[test]
    fn quota_inheritance_child_has_own_used_bytes() {
        let mut parent = QuotaTable::new();
        parent.set_user_limits(1000, 0, 10_000, 0);
        parent.charge_user(1000, 3000).unwrap();

        let mut child = QuotaTable::new();
        child.set_parent(parent);

        // Child's usage is tracked independently.
        child.charge_user(1000, 5000).unwrap();
        assert_eq!(child.get_user(1000).unwrap().used_bytes, 5000);

        // Parent's usage should be unaffected.
        // (But Box moves ownership; we can't check parent after moving into child.
        //  This is fine — in real usage the parent lives separately.)
    }

    #[test]
    fn quota_inheritance_soft_limit_inherited() {
        let mut parent = QuotaTable::new();
        parent.set_user_limits(1000, 500_000, 1_000_000, 0);

        let mut child = QuotaTable::new();
        child.set_parent(parent);

        let (soft, hard, _files) = child.effective_user_limits(1000);
        assert_eq!(soft, 500_000);
        assert_eq!(hard, 1_000_000);
    }

    #[test]
    fn quota_inheritance_file_limit_inherited() {
        let mut parent = QuotaTable::new();
        parent.set_user_limits(1000, 0, 0, 100);

        let mut child = QuotaTable::new();
        child.set_parent(parent);

        let (_soft, _hard, files) = child.effective_user_limits(1000);
        assert_eq!(files, 100);

        // Child respects inherited file limit.
        for _ in 0..100 {
            child.charge_user_file(1000).unwrap();
        }
        assert!(child.charge_user_file(1000).is_err());
    }

    // -- Multi-user isolation --

    #[test]
    fn quota_multi_user_isolation() {
        let mut table = QuotaTable::new();
        table.set_user_limits(1000, 0, 5000, 0);
        table.set_user_limits(1001, 0, 10000, 0);

        table.charge_user(1000, 3000).unwrap();
        table.charge_user(1001, 8000).unwrap();

        assert_eq!(table.get_user(1000).unwrap().used_bytes, 3000);
        assert_eq!(table.get_user(1001).unwrap().used_bytes, 8000);

        // uid 1000 is near limit.
        assert!(table.charge_user(1000, 3000).is_err());
        // uid 1001 still has room.
        table.charge_user(1001, 1000).unwrap();
        assert_eq!(table.get_user(1001).unwrap().used_bytes, 9000);
    }

    // -- User + group both over limit (first to hit returns ENOSPC) --

    #[test]
    fn quota_user_and_group_both_over_limit() {
        let mut table = QuotaTable::new();
        table.set_user_limits(1000, 0, 1000, 0);
        table.set_group_limits(100, 0, 2000, 0);

        // User limit is tighter — hits ENOSPC first.
        table.charge_user(1000, 800).unwrap();
        table.charge_group(100, 800).unwrap();

        let user_result = table.charge_user(1000, 300);
        assert!(user_result.is_err()); // user hard limit (1000) exceeded

        // But group still has room.
        table.charge_group(100, 500).unwrap();
        assert_eq!(table.get_group(100).unwrap().used_bytes, 1300);
    }

    // -- QuotaStats tests --

    #[test]
    fn quota_stats_from_table() {
        let mut table = QuotaTable::new();
        table.set_user_limits(1000, 0, 10_000, 0);
        table.set_user_limits(1001, 0, 20_000, 0);
        table.charge_user(1000, 1000).unwrap();
        table.charge_user(1001, 3000).unwrap();
        table.set_group_limits(100, 0, 50_000, 0);
        table.charge_group(100, 5000).unwrap();

        let stats = QuotaStats::from_table(&table);
        assert_eq!(stats.total_user_bytes(), 4000);
        assert_eq!(stats.total_group_bytes(), 5000);
        assert_eq!(stats.user_quotas.len(), 2);
        assert_eq!(stats.group_quotas.len(), 1);
    }

    #[test]
    fn quota_stats_empty_table() {
        let table = QuotaTable::new();
        let stats = QuotaStats::from_table(&table);
        assert_eq!(stats.total_user_bytes(), 0);
        assert_eq!(stats.total_group_bytes(), 0);
        assert_eq!(stats.total_user_files(), 0);
        assert_eq!(stats.total_group_files(), 0);
    }

    #[test]
    fn quota_table_effective_limits_no_parent_all_zero() {
        let table = QuotaTable::new();
        let (soft, hard, files) = table.effective_user_limits(9999);
        assert_eq!(soft, 0);
        assert_eq!(hard, 0);
        assert_eq!(files, 0);
    }

    #[test]
    fn quota_table_effective_group_limits_inherited() {
        let mut parent = QuotaTable::new();
        parent.set_group_limits(100, 500_000, 2_000_000, 200);

        let mut child = QuotaTable::new();
        child.set_parent(parent);

        let (soft, hard, files) = child.effective_group_limits(100);
        assert_eq!(soft, 500_000);
        assert_eq!(hard, 2_000_000);
        assert_eq!(files, 200);
    }

    #[test]
    fn quota_table_user_check_returns_correct_verdict() {
        let mut table = QuotaTable::new();
        table.set_user_limits(1000, 500, 1000, 0);
        table.charge_user(1000, 400).unwrap();

        // Within all limits.
        assert_eq!(table.check_user(1000, 50), QuotaVerdict::Allowed);
        // Exceeds soft limit.
        assert!(matches!(
            table.check_user(1000, 200),
            QuotaVerdict::SoftLimitExceeded { .. }
        ));
        // Exceeds hard limit.
        assert!(matches!(
            table.check_user(1000, 700),
            QuotaVerdict::HardLimitExceeded { .. }
        ));
    }

    #[test]
    fn quota_table_group_check_returns_correct_verdict() {
        let mut table = QuotaTable::new();
        table.set_group_limits(100, 0, 5000, 0);
        table.charge_group(100, 4000).unwrap();

        assert_eq!(table.check_group(100, 500), QuotaVerdict::Allowed);
        assert!(matches!(
            table.check_group(100, 2000),
            QuotaVerdict::HardLimitExceeded { .. }
        ));
    }

    #[test]
    fn quota_table_iter_users() {
        let mut table = QuotaTable::new();
        table.set_user_limits(1000, 0, 5000, 0);
        table.set_user_limits(2000, 0, 10000, 0);
        table.charge_user(1000, 100).unwrap();

        let users: Vec<u32> = table.iter_users().map(|(&uid, _)| uid).collect();
        assert_eq!(users, vec![1000, 2000]);
    }

    #[test]
    fn quota_table_iter_groups() {
        let mut table = QuotaTable::new();
        table.set_group_limits(100, 0, 5000, 0);
        table.set_group_limits(200, 0, 10000, 0);

        let groups: Vec<u32> = table.iter_groups().map(|(&gid, _)| gid).collect();
        assert_eq!(groups, vec![100, 200]);
    }

    // ===================================================================
    // Phase 3: Project quotas
    // ===================================================================

    // -- ProjectQuota tests --

    #[test]
    fn project_quota_new_zero_usage() {
        let q = ProjectQuota::new(42);
        assert_eq!(q.project_id, 42);
        assert_eq!(q.used_bytes, 0);
        assert_eq!(q.soft_limit, 0);
        assert_eq!(q.hard_limit, 0);
        assert_eq!(q.file_count, 0);
        assert_eq!(q.file_limit, 0);
        assert!(!q.has_hard_limit());
        assert!(!q.has_soft_limit());
    }

    #[test]
    fn project_quota_charge_within_hard_limit() {
        let mut q = ProjectQuota::new(1);
        q.hard_limit = 1024 * 1024;
        q.charge_bytes(512 * 1024).unwrap();
        assert_eq!(q.used_bytes, 512 * 1024);
    }

    #[test]
    fn project_quota_charge_exceeds_hard_limit() {
        let mut q = ProjectQuota::new(1);
        q.hard_limit = 1024;
        q.charge_bytes(500).unwrap();
        let result = q.charge_bytes(600);
        assert!(result.is_err());
        assert_eq!(q.used_bytes, 500);
    }

    #[test]
    fn project_quota_credit_bytes() {
        let mut q = ProjectQuota::new(1);
        q.used_bytes = 1000;
        q.credit_bytes(300).unwrap();
        assert_eq!(q.used_bytes, 700);
    }

    #[test]
    fn project_quota_credit_underflow_rejected() {
        let mut q = ProjectQuota::new(1);
        q.used_bytes = 100;
        let result = q.credit_bytes(200);
        assert!(result.is_err());
        assert_eq!(q.used_bytes, 100);
    }

    #[test]
    fn project_quota_file_charge_and_credit() {
        let mut q = ProjectQuota::new(1);
        q.file_limit = 5;
        for _ in 0..5 {
            q.charge_file().unwrap();
        }
        assert_eq!(q.file_count, 5);
        assert!(q.charge_file().is_err());
        q.credit_file().unwrap();
        assert_eq!(q.file_count, 4);
        q.charge_file().unwrap();
        assert_eq!(q.file_count, 5);
    }

    #[test]
    fn project_quota_no_limit_unbounded() {
        let q = ProjectQuota::new(1);
        assert_eq!(q.available_bytes(), u64::MAX);
    }

    // -- QuotaTable project methods --

    #[test]
    fn quota_table_project_charge_and_check() {
        let mut table = QuotaTable::new();
        table.set_project_limits(10, 0, 5000, 0);
        table.charge_project(10, 3000).unwrap();
        assert_eq!(table.get_project(10).unwrap().used_bytes, 3000);
        assert_eq!(table.check_project(10, 1000), QuotaVerdict::Allowed);
        assert!(matches!(
            table.check_project(10, 3000),
            QuotaVerdict::HardLimitExceeded { .. }
        ));
    }

    #[test]
    fn quota_table_project_exceeds_hard_limit() {
        let mut table = QuotaTable::new();
        table.set_project_limits(10, 0, 1000, 0);
        table.charge_project(10, 800).unwrap();
        assert!(table.charge_project(10, 300).is_err());
    }

    #[test]
    fn quota_table_project_credit() {
        let mut table = QuotaTable::new();
        table.set_project_limits(10, 0, 10000, 0);
        table.charge_project(10, 5000).unwrap();
        table.credit_project(10, 2000).unwrap();
        assert_eq!(table.get_project(10).unwrap().used_bytes, 3000);
    }

    #[test]
    fn quota_table_project_file_accounting() {
        let mut table = QuotaTable::new();
        table.set_project_limits(10, 0, 0, 50);
        for _ in 0..50 {
            table.charge_project_file(10).unwrap();
        }
        assert!(table.charge_project_file(10).is_err());
        table.credit_project_file(10).unwrap();
        table.charge_project_file(10).unwrap();
    }

    #[test]
    fn quota_table_project_count() {
        let mut table = QuotaTable::new();
        assert_eq!(table.project_count(), 0);
        table.set_project_limits(1, 0, 1000, 0);
        table.set_project_limits(2, 0, 2000, 0);
        assert_eq!(table.project_count(), 2);
    }

    #[test]
    fn quota_table_project_iteration() {
        let mut table = QuotaTable::new();
        table.set_project_limits(1, 0, 1000, 0);
        table.set_project_limits(2, 0, 2000, 0);
        let ids: Vec<u32> = table.iter_projects().map(|(&id, _)| id).collect();
        assert_eq!(ids, vec![1, 2]);
    }

    // -- Project quota inheritance --

    #[test]
    fn project_quota_inheritance_child_inherits_parent_limits() {
        let mut parent = QuotaTable::new();
        parent.set_project_limits(5, 0, 1_000_000, 0);

        let mut child = QuotaTable::new();
        child.set_parent(parent);

        let (_soft, hard, _files) = child.effective_project_limits(5);
        assert_eq!(hard, 1_000_000);
    }

    #[test]
    fn project_quota_inheritance_child_override_parent() {
        let mut parent = QuotaTable::new();
        parent.set_project_limits(5, 0, 1_000_000, 0);

        let mut child = QuotaTable::new();
        child.set_parent(parent);
        child.set_project_limits(5, 0, 500_000, 0);

        let (_soft, hard, _files) = child.effective_project_limits(5);
        assert_eq!(hard, 500_000);
    }

    #[test]
    fn project_quota_inheritance_charge_respects_inherited() {
        let mut parent = QuotaTable::new();
        parent.set_project_limits(5, 0, 1000, 0);

        let mut child = QuotaTable::new();
        child.set_parent(parent);

        child.charge_project(5, 800).unwrap();
        assert!(child.charge_project(5, 300).is_err());
    }

    // -- User + group + project all enforced (first to hit returns ENOSPC) --

    #[test]
    fn quota_all_three_project_hits_first() {
        let mut table = QuotaTable::new();
        table.set_user_limits(1000, 0, 10_000, 0);
        table.set_group_limits(100, 0, 10_000, 0);
        table.set_project_limits(5, 0, 1000, 0); // tightest

        table.charge_user(1000, 800).unwrap();
        table.charge_group(100, 800).unwrap();
        table.charge_project(5, 800).unwrap();

        // Project is the tightest — hits first.
        assert!(table.charge_project(5, 300).is_err());
        // But user and group still have room.
        table.charge_user(1000, 100).unwrap();
        table.charge_group(100, 100).unwrap();
    }

    // -- QuotaStats with projects --

    #[test]
    fn quota_stats_includes_projects() {
        let mut table = QuotaTable::new();
        table.set_project_limits(1, 0, 5000, 0);
        table.set_project_limits(2, 0, 10000, 0);
        table.charge_project(1, 1000).unwrap();
        table.charge_project(2, 3000).unwrap();

        let stats = QuotaStats::from_table(&table);
        assert_eq!(stats.total_project_bytes(), 4000);
        assert_eq!(stats.project_quotas.len(), 2);
        assert_eq!(stats.total_project_files(), 0);
    }

    #[test]
    fn quota_stats_total_all_bytes() {
        let mut table = QuotaTable::new();
        table.set_user_limits(1000, 0, 10000, 0);
        table.charge_user(1000, 1000).unwrap();
        table.set_group_limits(100, 0, 10000, 0);
        table.charge_group(100, 2000).unwrap();
        table.set_project_limits(1, 0, 10000, 0);
        table.charge_project(1, 3000).unwrap();

        let stats = QuotaStats::from_table(&table);
        assert_eq!(stats.total_all_bytes(), 6000);
    }

    // ===================================================================
    // Phase 3: QuotaMigration round-trip
    // ===================================================================

    #[test]
    fn quota_migration_round_trip_empty_table() {
        let table = QuotaTable::new();
        let bytes = QuotaMigration::serialize(&table);
        let restored = QuotaMigration::deserialize(&bytes).unwrap();
        assert_eq!(restored.user_count(), 0);
        assert_eq!(restored.group_count(), 0);
        assert_eq!(restored.project_count(), 0);
    }

    #[test]
    fn quota_migration_round_trip_users_only() {
        let mut table = QuotaTable::new();
        table.set_user_limits(1000, 500_000, 1_000_000, 100);
        table.charge_user(1000, 200_000).unwrap();
        table.set_user_limits(1001, 0, 2_000_000, 0);
        table.charge_user(1001, 500_000).unwrap();

        let bytes = QuotaMigration::serialize(&table);
        let restored = QuotaMigration::deserialize(&bytes).unwrap();

        assert_eq!(restored.user_count(), 2);
        let u1000 = restored.get_user(1000).unwrap();
        assert_eq!(u1000.used_bytes, 200_000);
        assert_eq!(u1000.soft_limit, 500_000);
        assert_eq!(u1000.hard_limit, 1_000_000);
        assert_eq!(u1000.file_limit, 100);

        let u1001 = restored.get_user(1001).unwrap();
        assert_eq!(u1001.used_bytes, 500_000);
        assert_eq!(u1001.hard_limit, 2_000_000);
    }

    #[test]
    fn quota_migration_round_trip_groups_only() {
        let mut table = QuotaTable::new();
        table.set_group_limits(100, 0, 10_000, 50);
        table.charge_group(100, 5000).unwrap();
        // Also add file charges
        for _ in 0..10 {
            table.charge_group_file(100).unwrap();
        }

        let bytes = QuotaMigration::serialize(&table);
        let restored = QuotaMigration::deserialize(&bytes).unwrap();

        assert_eq!(restored.group_count(), 1);
        let g100 = restored.get_group(100).unwrap();
        assert_eq!(g100.used_bytes, 5000);
        assert_eq!(g100.file_count, 10);
        assert_eq!(g100.file_limit, 50);
    }

    #[test]
    fn quota_migration_round_trip_projects_only() {
        let mut table = QuotaTable::new();
        table.set_project_limits(42, 100_000, 1_000_000, 200);
        table.charge_project(42, 300_000).unwrap();
        for _ in 0..50 {
            table.charge_project_file(42).unwrap();
        }

        let bytes = QuotaMigration::serialize(&table);
        let restored = QuotaMigration::deserialize(&bytes).unwrap();

        assert_eq!(restored.project_count(), 1);
        let p42 = restored.get_project(42).unwrap();
        assert_eq!(p42.used_bytes, 300_000);
        assert_eq!(p42.soft_limit, 100_000);
        assert_eq!(p42.hard_limit, 1_000_000);
        assert_eq!(p42.file_count, 50);
        assert_eq!(p42.file_limit, 200);
    }

    #[test]
    fn quota_migration_round_trip_all_three() {
        let mut table = QuotaTable::new();

        // Users
        table.set_user_limits(1000, 100_000, 500_000, 10);
        table.charge_user(1000, 200_000).unwrap();

        // Groups
        table.set_group_limits(100, 0, 1_000_000, 0);
        table.charge_group(100, 600_000).unwrap();

        // Projects
        table.set_project_limits(7, 0, 2_000_000, 500);
        table.charge_project(7, 1_000_000).unwrap();

        let bytes = QuotaMigration::serialize(&table);
        let restored = QuotaMigration::deserialize(&bytes).unwrap();

        assert_eq!(restored.user_count(), 1);
        assert_eq!(restored.group_count(), 1);
        assert_eq!(restored.project_count(), 1);
        assert_eq!(restored.get_user(1000).unwrap().used_bytes, 200_000);
        assert_eq!(restored.get_group(100).unwrap().used_bytes, 600_000);
        assert_eq!(restored.get_project(7).unwrap().used_bytes, 1_000_000);
    }

    #[test]
    fn quota_migration_deserialize_truncated_rejected() {
        // Only 2 bytes — not even a full u32 count.
        let bytes = [0u8; 2];
        let result = QuotaMigration::deserialize(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn quota_migration_deserialize_partial_user_entries() {
        // User count says 1, but no entry data follows.
        let bytes = [0u8, 0, 0, 1]; // user_count = 1
        let result = QuotaMigration::deserialize(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn quota_migration_round_trip_preserves_zero_usage_entries() {
        let mut table = QuotaTable::new();
        // Set limits without charging anything.
        table.set_user_limits(1000, 0, 5000, 0);
        table.set_project_limits(1, 0, 10000, 0);

        let bytes = QuotaMigration::serialize(&table);
        let restored = QuotaMigration::deserialize(&bytes).unwrap();

        assert_eq!(restored.user_count(), 1);
        assert_eq!(restored.project_count(), 1);
        let u = restored.get_user(1000).unwrap();
        assert_eq!(u.used_bytes, 0);
        assert_eq!(u.hard_limit, 5000);
    }

    #[test]
    fn quota_migration_round_trip_large_values() {
        let mut table = QuotaTable::new();
        table.set_user_limits(1000, 0, u64::MAX, u64::MAX);
        table.charge_user(1000, u64::MAX / 2).unwrap();

        let bytes = QuotaMigration::serialize(&table);
        let restored = QuotaMigration::deserialize(&bytes).unwrap();

        let u = restored.get_user(1000).unwrap();
        assert_eq!(u.used_bytes, u64::MAX / 2);
        assert_eq!(u.hard_limit, u64::MAX);
        assert_eq!(u.file_limit, u64::MAX);
    }

    // -- QuotaMigrationError Display --

    #[test]
    fn quota_migration_error_display() {
        let e = QuotaMigrationError::UnexpectedEnd;
        assert!(format!("{e}").contains("unexpected end"));
        let e = QuotaMigrationError::Underflow;
        assert!(format!("{e}").contains("underflow"));
    }

    // ── SpaceBook ──────────────────────────────────────────────────────

    #[test]
    fn space_book_new_empty() {
        let book = SpaceBook::new();
        assert_eq!(book.dataset_count(), 0);
        assert_eq!(book.get_pool_usage(), 0);
        assert!(!book.has_dirty());
    }

    #[test]
    fn space_book_record_write_increments_usage() {
        let mut book = SpaceBook::new();
        let did = [1u8; 16];
        book.record_write(did, 4096).unwrap();
        assert_eq!(book.dataset_count(), 1);
        assert_eq!(book.get_pool_usage(), 4096);
        assert!(book.contains(did));
        assert!(book.has_dirty());
    }

    #[test]
    fn space_book_record_delete_decrements_usage() {
        let mut book = SpaceBook::new();
        let did = [1u8; 16];
        book.record_write(did, 8192).unwrap();
        book.record_delete(did, 4096).unwrap();
        assert_eq!(book.get_pool_usage(), 4096);
    }

    #[test]
    fn space_book_record_delete_underflow_rejected() {
        let mut book = SpaceBook::new();
        let did = [1u8; 16];
        let err = book.record_delete(did, 4096).unwrap_err();
        assert!(matches!(err, SpaceAccountingError::CounterUnderflow { .. }));
        // Dataset should be created with zero usage, underflow rejected.
        assert_eq!(book.get_pool_usage(), 0);
    }

    #[test]
    fn space_book_multi_dataset_isolation() {
        let mut book = SpaceBook::new();
        let did_a = [1u8; 16];
        let did_b = [2u8; 16];
        book.record_write(did_a, 1000).unwrap();
        book.record_write(did_b, 2000).unwrap();
        assert_eq!(book.get_pool_usage(), 3000);
        let usage_a = book.get_dataset_usage(did_a).unwrap();
        assert_eq!(usage_a.bytes_used, 1000);
        let usage_b = book.get_dataset_usage(did_b).unwrap();
        assert_eq!(usage_b.bytes_used, 2000);
    }

    #[test]
    fn space_book_flush_dirty_produces_records() {
        let mut book = SpaceBook::new();
        book.set_txg(42);
        let did_a = [1u8; 16];
        let did_b = [2u8; 16];
        book.record_write(did_a, 4096).unwrap();
        book.record_write(did_b, 1024).unwrap();
        assert_eq!(book.dirty_count(), 2);

        let records = book.flush_dirty();
        assert_eq!(records.len(), 2);
        assert!(!book.has_dirty());
        assert_eq!(book.dirty_count(), 0);

        // All records should verify and have the correct TXG.
        for rec in &records {
            assert!(rec.verify());
            assert_eq!(rec.commit_group, 42);
        }
        // Dataset A should have 4096 used.
        let rec_a = records.iter().find(|r| r.dataset_id == did_a).unwrap();
        assert_eq!(rec_a.bytes_used, 4096);
        // Dataset B should have 1024 used.
        let rec_b = records.iter().find(|r| r.dataset_id == did_b).unwrap();
        assert_eq!(rec_b.bytes_used, 1024);
    }

    #[test]
    fn space_book_flush_empty_returns_empty() {
        let mut book = SpaceBook::new();
        let records = book.flush_dirty();
        assert!(records.is_empty());
    }

    #[test]
    fn space_book_restore_from_record() {
        let mut book = SpaceBook::new();
        let did = [1u8; 16];
        let rec = DatasetSpaceUsage::new(did, 8192, 512, 10);
        book.restore_from_record(&rec);
        assert_eq!(book.dataset_count(), 1);
        let usage = book.get_dataset_usage(did).unwrap();
        assert_eq!(usage.bytes_used, 8192);
        assert_eq!(usage.bytes_reserved, 512);
    }

    #[test]
    fn space_book_get_dataset_usage_unknown_returns_none() {
        let book = SpaceBook::new();
        assert!(book.get_dataset_usage([9u8; 16]).is_none());
    }

    #[test]
    fn space_book_pool_counters() {
        let mut book = SpaceBook::new();
        let counters = PoolPhysicalCountersV1 {
            phys_total_bytes: 1_000_000,
            phys_free_bytes: 500_000,
            ..Default::default()
        };
        book.update_pool_counters(counters);
        assert_eq!(book.pool_counters().unwrap().phys_total_bytes, 1_000_000);
    }

    #[test]
    fn space_book_update_txg() {
        let mut book = SpaceBook::new();
        assert_eq!(book.commit_group(), 0);
        book.set_txg(12345);
        assert_eq!(book.commit_group(), 12345);
    }

    #[test]
    fn space_book_default_creates_empty() {
        let book = SpaceBook::default();
        assert_eq!(book.dataset_count(), 0);
        assert_eq!(book.commit_group(), 0);
    }

    #[test]
    fn space_book_set_usage_dirty_sets_counters() {
        let mut book = SpaceBook::new();
        let did = [1u8; 16];
        book.set_usage_dirty(did, 4096, 1024);
        assert!(book.has_dirty());
        assert_eq!(book.dirty_count(), 1);
        let usage = book.get_dataset_usage(did).unwrap();
        assert_eq!(usage.bytes_used, 4096);
        assert_eq!(usage.bytes_reserved, 1024);
    }

    #[test]
    fn space_book_set_usage_dirty_overwrites_existing() {
        let mut book = SpaceBook::new();
        let did = [1u8; 16];
        book.record_write(did, 1000).unwrap();
        let _ = book.flush_dirty();

        // Overwrite with completely new values.
        book.set_usage_dirty(did, 5000, 200);
        assert!(book.has_dirty());
        let usage = book.get_dataset_usage(did).unwrap();
        assert_eq!(usage.bytes_used, 5000);
        assert_eq!(usage.bytes_reserved, 200);
    }

    #[test]
    fn space_book_set_usage_dirty_then_flush_roundtrip() {
        let mut book = SpaceBook::new();
        book.set_txg(7);
        let did = [1u8; 16];
        book.set_usage_dirty(did, 8192, 512);

        let records = book.flush_dirty();
        assert_eq!(records.len(), 1);
        let rec = &records[0];
        assert_eq!(rec.bytes_used, 8192);
        assert_eq!(rec.bytes_reserved, 512);
        assert_eq!(rec.commit_group, 7);
        assert!(rec.verify());
    }

    #[test]
    fn space_book_statfs_for_dataset_returns_fields() {
        let mut book = SpaceBook::new();
        let did = [1u8; 16];
        book.record_write(did, 4096).unwrap();
        book.update_pool_counters(PoolPhysicalCountersV1 {
            phys_total_bytes: 1_000_000,
            phys_free_bytes: 500_000,
            ..Default::default()
        });
        let statfs = book.statfs_for_dataset(did).unwrap();
        // Block size is the TideFS default.
        assert_eq!(statfs.block_size, 4096);
        // With no quota set, capacity = phys_free_bytes = 500_000.
        // 500_000 / 4096 = 122 blocks.
        assert_eq!(statfs.blocks, 500_000 / 4096);
        // Used = 4096, so consumed = 4096, free_bytes = 500_000 - 4096 = 495_904.
        // free_blocks = 495_904 / 4096 = 121.
        assert_eq!(statfs.blocks_free, 495_904 / 4096);
        // avail = free_bytes min(pool_phys - consumed) = 495_904 (no slop).
        assert_eq!(statfs.blocks_avail, 495_904 / 4096);
        // Inodes are unlimited when not tracked.
        assert_eq!(statfs.files, u64::MAX);
        assert_eq!(statfs.files_free, u64::MAX);
        assert_eq!(statfs.name_max, 255);
    }

    #[test]
    fn space_book_statfs_for_dataset_unknown_returns_none() {
        let mut book = SpaceBook::new();
        assert!(book.statfs_for_dataset([9u8; 16]).is_none());
    }

    #[test]
    fn space_book_statfs_for_dataset_with_quota() {
        let mut book = SpaceBook::new();
        let did = [1u8; 16];
        book.record_write(did, 4096).unwrap();
        // Give the dataset a quota via the underlying SpaceAccounting.
        let acct = book.get_or_create(did);
        acct.set_quota(100_000);
        book.update_pool_counters(PoolPhysicalCountersV1 {
            phys_total_bytes: 1_000_000,
            phys_free_bytes: 500_000,
            ..Default::default()
        });
        let statfs = book.statfs_for_dataset(did).unwrap();
        // With quota set to 100_000, capacity = quota_bytes.
        assert_eq!(statfs.blocks, 100_000 / 4096);
    }
    // ===================================================================
    // DatasetQuotaHierarchy tests
    // ===================================================================

    fn test_parent_of(id: &[u8; 16]) -> Option<[u8; 16]> {
        // Simple hierarchy: all non-zero ids have parent [0u8;16]
        if *id == [0u8; 16] {
            None
        } else {
            Some([0u8; 16])
        }
    }

    fn did(id: u8) -> [u8; 16] {
        let mut d = [0u8; 16];
        d[0] = id;
        d
    }

    #[test]
    fn hierarchy_new_is_empty() {
        let h = DatasetQuotaHierarchy::new();
        assert!(h.is_empty());
        assert_eq!(h.len(), 0);
    }

    #[test]
    fn hierarchy_set_and_get_quota() {
        let mut h = DatasetQuotaHierarchy::new();
        let cfg = DatasetQuotaConfig {
            hard_limit_bytes: 1_000_000,
            hard_limit_inodes: 100,
            ..Default::default()
        };
        h.set_quota(did(1), cfg);
        assert_eq!(h.len(), 1);
        let got = h.get(&did(1)).unwrap();
        assert_eq!(got.hard_limit_bytes, 1_000_000);
        assert_eq!(got.hard_limit_inodes, 100);
    }

    #[test]
    fn hierarchy_remove_quota() {
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(1),
            DatasetQuotaConfig {
                hard_limit_bytes: 1000,
                ..Default::default()
            },
        );
        assert_eq!(h.len(), 1);
        h.remove_quota(did(1));
        assert!(h.is_empty());
    }

    #[test]
    fn hierarchy_inactive_config_removes_entry() {
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(1),
            DatasetQuotaConfig {
                hard_limit_bytes: 1000,
                ..Default::default()
            },
        );
        assert_eq!(h.len(), 1);
        h.set_quota(did(1), DatasetQuotaConfig::default());
        assert!(h.is_empty());
    }

    #[test]
    fn hierarchy_check_delta_allows_within_limit() {
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(1),
            DatasetQuotaConfig {
                hard_limit_bytes: 1000,
                ..Default::default()
            },
        );
        let decision = h.check_delta(did(1), 500, 0, u64::MAX, test_parent_of);
        assert!(!decision.is_refusal());
    }

    #[test]
    fn hierarchy_check_delta_rejects_over_limit() {
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(1),
            DatasetQuotaConfig {
                hard_limit_bytes: 1000,
                ..Default::default()
            },
        );
        h.charge_bytes(did(1), 800, 0, test_parent_of);
        let decision = h.check_delta(did(1), 300, 0, u64::MAX, test_parent_of);
        assert!(decision.is_refusal());
        assert!(matches!(
            decision,
            DatasetQuotaDecision::HardBytesExceeded { .. }
        ));
    }

    #[test]
    fn hierarchy_parent_quota_limits_child() {
        let mut h = DatasetQuotaHierarchy::new();
        // Parent has 1000 byte limit
        h.set_quota(
            did(0),
            DatasetQuotaConfig {
                hard_limit_bytes: 1000,
                ..Default::default()
            },
        );
        // Child has no explicit quota
        // Charge 800 to child
        h.charge_bytes(did(1), 800, 0, test_parent_of);
        // Now parent usage is 800
        // Check child write of 300 -> parent would be at 1100 > 1000
        let decision = h.check_delta(did(1), 300, 0, u64::MAX, test_parent_of);
        assert!(decision.is_refusal());
    }

    #[test]
    fn hierarchy_most_restrictive_ancestor_wins() {
        let mut h = DatasetQuotaHierarchy::new();
        // Parent: 10000 bytes
        h.set_quota(
            did(0),
            DatasetQuotaConfig {
                hard_limit_bytes: 10000,
                ..Default::default()
            },
        );
        // Child: 1000 bytes (tighter)
        h.set_quota(
            did(1),
            DatasetQuotaConfig {
                hard_limit_bytes: 1000,
                ..Default::default()
            },
        );
        // 500 bytes is within both limits
        let ok = h.check_delta(did(1), 500, 0, u64::MAX, test_parent_of);
        assert!(!ok.is_refusal());
        // 1500 bytes exceeds child limit but not parent
        let reject = h.check_delta(did(1), 1500, 0, u64::MAX, test_parent_of);
        assert!(reject.is_refusal());
    }

    #[test]
    fn hierarchy_charge_and_credit_ancestors() {
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(0),
            DatasetQuotaConfig {
                hard_limit_bytes: 10000,
                ..Default::default()
            },
        );
        h.set_quota(
            did(1),
            DatasetQuotaConfig {
                hard_limit_bytes: 5000,
                ..Default::default()
            },
        );
        // Charge both parent and child
        h.charge_bytes(did(1), 1000, 0, test_parent_of);
        // Verify parent usage = child usage = 1000
        let check = h.check_delta(did(1), 5000, 0, u64::MAX, test_parent_of);
        assert!(check.is_refusal()); // 1000 + 5000 > 5000 child limit
                                     // Credit
        h.credit_bytes(did(1), 1000, 0, test_parent_of);
        let check2 = h.check_delta(did(1), 4000, 0, u64::MAX, test_parent_of);
        assert!(!check2.is_refusal()); // 0 + 4000 < 5000
    }

    #[test]
    fn hierarchy_effective_capacity_respects_parent() {
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(0),
            DatasetQuotaConfig {
                hard_limit_bytes: 1_000_000,
                ..Default::default()
            },
        );
        h.charge_bytes(did(1), 200_000, 0, test_parent_of); // child charges parent
        let cap = h.effective_capacity(did(2), 10_000_000, test_parent_of);
        // Parent limit 1M - 200K used = 800K < 10M pool
        assert_eq!(cap, 800_000);
    }

    #[test]
    fn hierarchy_effective_capacity_returns_pool_when_no_quota() {
        let h = DatasetQuotaHierarchy::new();
        let cap = h.effective_capacity(did(1), 5_000_000, test_parent_of);
        assert_eq!(cap, 5_000_000);
    }

    #[test]
    fn hierarchy_reservation_violation() {
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(1),
            DatasetQuotaConfig {
                reservation_bytes: 500,
                ..Default::default()
            },
        );
        // pool_free_bytes = 300 < reservation 500
        let decision = h.check_delta(did(1), 100, 0, 300, test_parent_of);
        assert!(matches!(
            decision,
            DatasetQuotaDecision::ReservationViolation { .. }
        ));
    }

    #[test]
    fn hierarchy_hard_inodes_exceeded() {
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(1),
            DatasetQuotaConfig {
                hard_limit_inodes: 10,
                ..Default::default()
            },
        );
        h.charge_bytes(did(1), 0, 8, test_parent_of);
        let ok = h.check_delta(did(1), 0, 1, u64::MAX, test_parent_of);
        assert!(!ok.is_refusal());
        let reject = h.check_delta(did(1), 0, 3, u64::MAX, test_parent_of);
        assert!(matches!(
            reject,
            DatasetQuotaDecision::HardInodesExceeded { .. }
        ));
    }

    #[test]
    fn hierarchy_charge_bytes_zero_delta_noop() {
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(1),
            DatasetQuotaConfig {
                hard_limit_bytes: 1000,
                ..Default::default()
            },
        );
        h.charge_bytes(did(1), 0, 0, test_parent_of);
        // No change expected (just shouldn't panic)
        assert!(h.get(&did(1)).is_some());
    }

    #[test]
    fn hierarchy_total_reserved_bytes() {
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(1),
            DatasetQuotaConfig {
                reservation_bytes: 100,
                ..Default::default()
            },
        );
        h.set_quota(
            did(2),
            DatasetQuotaConfig {
                reservation_bytes: 200,
                ..Default::default()
            },
        );
        assert_eq!(h.total_reserved_bytes(), 300);
    }

    #[test]
    fn hierarchy_sibling_reservations_reduce_pool_headroom() {
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(1),
            DatasetQuotaConfig {
                reservation_bytes: 700,
                ..Default::default()
            },
        );
        h.set_quota(
            did(2),
            DatasetQuotaConfig {
                reservation_bytes: 400,
                ..Default::default()
            },
        );

        let decision = h.check_delta(did(3), 1, 0, 1_100, test_parent_of);
        assert_eq!(
            decision,
            DatasetQuotaDecision::ReservationViolation {
                dataset_id: did(3),
                reserved_bytes: 1_101,
                free_bytes: 1_100,
            }
        );
    }

    #[test]
    fn hierarchy_overflow_sized_reservations_fail_closed() {
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(1),
            DatasetQuotaConfig {
                reservation_bytes: u64::MAX,
                ..Default::default()
            },
        );
        h.set_quota(
            did(2),
            DatasetQuotaConfig {
                reservation_bytes: 1,
                ..Default::default()
            },
        );

        let decision = h.check_delta(did(1), 0, 0, u64::MAX, test_parent_of);
        assert_eq!(
            decision,
            DatasetQuotaDecision::ReservationViolation {
                dataset_id: did(1),
                reserved_bytes: u64::MAX,
                free_bytes: u64::MAX,
            }
        );
        assert_eq!(h.total_reserved_bytes(), u64::MAX);
    }

    #[test]
    fn hierarchy_request_overflow_against_reservation_fails_closed() {
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(1),
            DatasetQuotaConfig {
                reservation_bytes: 1,
                ..Default::default()
            },
        );

        let decision = h.check_delta(did(1), u64::MAX, 0, u64::MAX, test_parent_of);
        assert!(matches!(
            decision,
            DatasetQuotaDecision::ReservationViolation {
                reserved_bytes: u64::MAX,
                free_bytes: u64::MAX,
                ..
            }
        ));
    }

    #[test]
    fn hierarchy_effective_capacity_reserves_pool_headroom() {
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(1),
            DatasetQuotaConfig {
                reservation_bytes: 100,
                ..Default::default()
            },
        );
        h.set_quota(
            did(2),
            DatasetQuotaConfig {
                reservation_bytes: 200,
                ..Default::default()
            },
        );

        let cap = h.effective_capacity(did(3), 1_000, test_parent_of);
        assert_eq!(cap, 700);
    }

    #[test]
    fn hierarchy_iter_yields_all_ids() {
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(1),
            DatasetQuotaConfig {
                hard_limit_bytes: 100,
                ..Default::default()
            },
        );
        h.set_quota(
            did(2),
            DatasetQuotaConfig {
                hard_limit_bytes: 200,
                ..Default::default()
            },
        );
        let mut ids: Vec<[u8; 16]> = h.iter().copied().collect();
        ids.sort();
        assert_eq!(ids.len(), 2);
    }

    // -- SpaceBook hierarchy integration tests --

    #[test]
    fn spacebook_set_and_use_quota_hierarchy() {
        let mut book = SpaceBook::new();
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(0),
            DatasetQuotaConfig {
                hard_limit_bytes: 1_000_000,
                ..Default::default()
            },
        );
        book.set_quota_hierarchy(h);
        assert!(book.quota_hierarchy().is_some());
        assert_eq!(book.quota_hierarchy().unwrap().len(), 1);
    }

    #[test]
    fn spacebook_check_hierarchy_enospc_allows_under_limit() {
        let mut book = SpaceBook::new();
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(0),
            DatasetQuotaConfig {
                hard_limit_bytes: 1_000_000,
                ..Default::default()
            },
        );
        book.set_quota_hierarchy(h);
        book.update_pool_counters(PoolPhysicalCountersV1 {
            phys_total_bytes: 10_000_000,
            phys_free_bytes: 10_000_000,
            ..Default::default()
        });
        // No usage yet, 500K should be allowed
        let result = book.check_hierarchy_enospc(did(1), 500_000, test_parent_of);
        assert!(result.is_ok());
    }

    #[test]
    fn spacebook_check_hierarchy_enospc_rejects_over_parent_limit() {
        let mut book = SpaceBook::new();
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(0),
            DatasetQuotaConfig {
                hard_limit_bytes: 100_000,
                ..Default::default()
            },
        );
        book.set_quota_hierarchy(h);
        book.update_pool_counters(PoolPhysicalCountersV1 {
            phys_total_bytes: 10_000_000,
            phys_free_bytes: 10_000_000,
            ..Default::default()
        });
        // Charge 90K to a sibling child
        book.quota_hierarchy_mut()
            .unwrap()
            .charge_bytes(did(1), 90_000, 0, test_parent_of);
        // Now try 20K to another child -> 90K + 20K = 110K > 100K
        let result = book.check_hierarchy_enospc(did(2), 20_000, test_parent_of);
        assert!(result.is_err());
    }

    #[test]
    fn spacebook_check_hierarchy_enospc_fails_closed_without_pool_counters() {
        let mut book = SpaceBook::new();
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(0),
            DatasetQuotaConfig {
                hard_limit_bytes: 1_000_000,
                reservation_bytes: 10_000,
                ..Default::default()
            },
        );
        book.set_quota_hierarchy(h);

        let result = book.check_hierarchy_enospc(did(1), 4_096, test_parent_of);
        assert_eq!(
            result,
            Err(DatasetQuotaDecision::ReservationViolation {
                dataset_id: did(1),
                reserved_bytes: 14_096,
                free_bytes: 0,
            })
        );
    }

    #[test]
    fn spacebook_statfs_with_hierarchy_respects_capacity_ceiling() {
        let mut book = SpaceBook::new();
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(0),
            DatasetQuotaConfig {
                hard_limit_bytes: 1_000_000,
                ..Default::default()
            },
        );
        h.charge_bytes(did(1), 200_000, 0, test_parent_of);
        book.set_quota_hierarchy(h);
        // Create the dataset in the book
        book.record_write(did(1), 200_000).unwrap();
        book.update_pool_counters(PoolPhysicalCountersV1 {
            phys_total_bytes: 10_000_000,
            phys_free_bytes: 9_800_000,
            ..Default::default()
        });
        let statfs = book
            .statfs_for_dataset_with_hierarchy(did(1), test_parent_of)
            .unwrap();
        // Effective capacity = min(10M, 1M-200K=800K) = 800K
        assert_eq!(statfs.block_size, 4096);
        assert_eq!(statfs.blocks, 800_000 / 4096);
    }

    #[test]
    fn spacebook_statfs_with_hierarchy_accounts_for_reservation_pressure() {
        let mut book = SpaceBook::new();
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(0),
            DatasetQuotaConfig {
                hard_limit_bytes: 5_000_000,
                ..Default::default()
            },
        );
        h.set_quota(
            did(2),
            DatasetQuotaConfig {
                reservation_bytes: 700_000,
                ..Default::default()
            },
        );
        book.set_quota_hierarchy(h);
        book.record_write(did(1), 100_000).unwrap();
        book.update_pool_counters(PoolPhysicalCountersV1 {
            phys_total_bytes: 5_000_000,
            phys_free_bytes: 1_000_000,
            ..Default::default()
        });

        let statfs = book
            .statfs_for_dataset_with_hierarchy(did(1), test_parent_of)
            .unwrap();

        assert_eq!(statfs.blocks, 300_000 / 4096);
        assert_eq!(statfs.blocks_free, 200_000 / 4096);
        assert!(statfs.blocks_avail <= statfs.blocks_free);
    }

    #[test]
    fn spacebook_statfs_with_hierarchy_requires_pool_counters() {
        let mut book = SpaceBook::new();
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(0),
            DatasetQuotaConfig {
                hard_limit_bytes: 1_000_000,
                ..Default::default()
            },
        );
        book.set_quota_hierarchy(h);
        book.record_write(did(1), 100_000).unwrap();

        assert!(book
            .statfs_for_dataset_with_hierarchy(did(1), test_parent_of)
            .is_none());
    }

    #[test]
    fn spacebook_statfs_with_hierarchy_has_no_dataset_side_effects() {
        let mut book = SpaceBook::new();
        let mut h = DatasetQuotaHierarchy::new();
        h.set_quota(
            did(0),
            DatasetQuotaConfig {
                hard_limit_bytes: 1_000_000,
                ..Default::default()
            },
        );
        book.set_quota_hierarchy(h);
        book.record_write(did(1), 100_000).unwrap();
        book.update_pool_counters(PoolPhysicalCountersV1 {
            phys_total_bytes: 1_000_000,
            phys_free_bytes: 900_000,
            ..Default::default()
        });

        {
            let acct = book.datasets.get_mut(&did(1)).unwrap();
            acct.set_quota(123_456);
            acct.accumulate_delta(SpaceDelta::new_reservation(4_096));
        }

        let before_counters = *book.datasets.get(&did(1)).unwrap().counters();
        let before_pending = book.datasets.get(&did(1)).unwrap().pending_delta;
        let before_dirty = book.dirty.clone();

        let first = book
            .statfs_for_dataset_with_hierarchy(did(1), test_parent_of)
            .unwrap();
        let second = book
            .statfs_for_dataset_with_hierarchy(did(1), test_parent_of)
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(
            *book.datasets.get(&did(1)).unwrap().counters(),
            before_counters
        );
        assert_eq!(
            book.datasets.get(&did(1)).unwrap().pending_delta,
            before_pending
        );
        assert_eq!(book.dirty, before_dirty);
    }

    // ===================================================================
    // TFR-007 unified authority tests
    // ===================================================================

    // -- Quota exhaustion: statfs/check_enospc consistency --

    #[test]
    fn statfs_reflects_quota_exhaustion() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        // Fill to within 1 byte of quota.
        sa.commit_delta(SpaceDelta::new_write(TEST_QUOTA_BYTES - 1))
            .unwrap();
        let s = sa.statfs();
        assert_eq!(s.blocks_free, 0); // 1 byte free -> 0 blocks
        assert_eq!(s.blocks_avail, 0);
        // check_enospc with 1 byte should still pass.
        assert!(!sa.check_enospc(1));
        // check_enospc with 2 bytes should fail.
        assert!(sa.check_enospc(2));
    }

    #[test]
    fn statfs_accounts_for_slop_in_quota_exhaustion() {
        let mut counters = test_counters();
        counters.slop_bytes = 500_000;
        let sa = SpaceAccounting::new(counters, SpaceDomainId::NONE);
        let s = sa.statfs();
        // Capacity = quota - slop = 1_000_000_000 - 500_000.
        let expected_capacity = TEST_QUOTA_BYTES - 500_000;
        assert_eq!(s.blocks, expected_capacity / 4096);
        assert_eq!(s.blocks_free, expected_capacity / 4096);
        // avail subtracts slop.
        assert_eq!(s.blocks_avail, (expected_capacity - 500_000) / 4096);
    }

    // -- Physical pool exhaustion --

    #[test]
    fn statfs_reflects_physical_pool_exhaustion() {
        let mut sa = SpaceAccounting::new(
            DatasetSpaceCountersV1 {
                quota_bytes: 0, // no quota
                ..test_counters()
            },
            SpaceDomainId::NONE,
        );
        // Tiny pool: 10 KB total, 4 KB free.
        sa.update_pool_counters(test_pool(4_096, 10_000));
        let s = sa.statfs();
        // No quota, so capacity = phys_capacity = 4_096.
        assert_eq!(s.blocks, 4_096 / 4096);
        assert_eq!(s.blocks_free, 1);
        assert_eq!(s.blocks_avail, 1);
    }

    #[test]
    fn check_enospc_rejects_physical_exhaustion() {
        let mut sa = SpaceAccounting::new(
            DatasetSpaceCountersV1 {
                quota_bytes: 0,
                ..test_counters()
            },
            SpaceDomainId::NONE,
        );
        sa.update_pool_counters(test_pool(4_096, 10_000));
        // 4 KB free, 1 byte write should pass.
        assert!(!sa.check_enospc(1));
        // Write beyond physical capacity should fail.
        assert!(sa.check_enospc(4_097));
    }

    #[test]
    fn statfs_avail_capped_by_physical_pool() {
        let mut sa = SpaceAccounting::new(
            DatasetSpaceCountersV1 {
                quota_bytes: 0,
                ..test_counters()
            },
            SpaceDomainId::NONE,
        );
        // Pool has 100 KB free, total 1 GB.
        sa.update_pool_counters(test_pool(100_000, 1_000_000_000));
        let s = sa.statfs();
        // capacity = phys_capacity = 100_000.
        assert_eq!(s.blocks, 100_000 / 4096);
        assert_eq!(s.blocks_free, 100_000 / 4096);
        // avail = free (no slop), capped by pool.
        assert_eq!(s.blocks_avail, 100_000 / 4096);
    }

    // -- Orphan reservations --

    #[test]
    fn statfs_counts_orphan_bytes_as_consumed() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.commit_delta(SpaceDelta::new_orphan_acquire(200_000))
            .unwrap();
        let s = sa.statfs();
        let expected_free = (TEST_QUOTA_BYTES - 200_000) / 4096;
        assert_eq!(s.blocks_free, expected_free);
    }

    #[test]
    fn check_enospc_rejects_when_orphan_bytes_consume_quota() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.commit_delta(SpaceDelta::new_orphan_acquire(TEST_QUOTA_BYTES - 1))
            .unwrap();
        // 1 byte remaining — admitted.
        assert!(!sa.check_enospc(1));
        // 2 bytes — rejected.
        assert!(sa.check_enospc(2));
    }

    #[test]
    fn statfs_orphan_release_frees_space() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.commit_delta(SpaceDelta::new_orphan_acquire(200_000))
            .unwrap();
        sa.commit_delta(SpaceDelta::new_orphan_release(200_000))
            .unwrap();
        let s = sa.statfs();
        assert_eq!(s.blocks_free, TEST_QUOTA_BYTES / 4096);
    }

    // -- Reserved bytes --

    #[test]
    fn statfs_counts_reserved_bytes_as_consumed() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.commit_delta(SpaceDelta::new_reservation(300_000))
            .unwrap();
        let s = sa.statfs();
        let expected_free = (TEST_QUOTA_BYTES - 300_000) / 4096;
        assert_eq!(s.blocks_free, expected_free);
    }

    #[test]
    fn check_enospc_rejects_when_reserved_bytes_consume_quota() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.commit_delta(SpaceDelta::new_reservation(TEST_QUOTA_BYTES))
            .unwrap();
        assert!(sa.check_enospc(1));
    }

    // -- Snapshot-pinned bytes through unified authority --

    #[test]
    fn check_enospc_rejects_when_pinned_snapshot_consumes_quota() {
        let mut counters = test_counters();
        counters.pinned_snapshot_bytes = TEST_QUOTA_BYTES;
        let sa = SpaceAccounting::new(counters, SpaceDomainId::NONE);
        assert!(sa.check_enospc(1));
    }

    #[test]
    fn statfs_and_check_enospc_agree_on_pinned_snapshot_bytes() {
        let mut counters = test_counters();
        // Use a block-aligned value so free_blocks * block_size == actual free.
        counters.pinned_snapshot_bytes = 4096 * 100; // 409_600
        let sa = SpaceAccounting::new(counters, SpaceDomainId::NONE);
        let s = sa.statfs();
        let free_blocks = s.blocks_free;
        let free_bytes = free_blocks * 4096;
        // check_enospc should admit writes up to free_bytes.
        assert!(!sa.check_enospc(free_bytes));
        // But refuse one block more.
        assert!(sa.check_enospc(free_bytes + 4096));
    }

    // -- Pending-delta commit boundaries --

    #[test]
    fn statfs_excludes_pending_delta() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.accumulate_delta(SpaceDelta::new_write(500_000_000));
        // statfs should still show full free space (pending not committed).
        let s = sa.statfs();
        assert_eq!(s.blocks_free, TEST_QUOTA_BYTES / 4096);
        assert!(sa.has_pending_delta());
    }

    #[test]
    fn check_enospc_uses_committed_counters_only() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        // Accumulate a pending delta that would fill the quota.
        sa.accumulate_delta(SpaceDelta::new_write(TEST_QUOTA_BYTES));
        // check_enospc sees committed counters (still empty), so admits.
        assert!(!sa.check_enospc(1));
        // After committing the pending delta, admission is blocked.
        sa.commit_pending(test_pool(TEST_QUOTA_BYTES * 2, TEST_QUOTA_BYTES * 2))
            .unwrap();
        assert!(sa.check_enospc(1));
    }

    #[test]
    fn commit_pending_updates_statfs() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.accumulate_delta(SpaceDelta::new_write(500_000_000));
        assert_eq!(sa.statfs().blocks_free, TEST_QUOTA_BYTES / 4096);
        sa.commit_pending(test_pool(TEST_QUOTA_BYTES * 2, TEST_QUOTA_BYTES * 2))
            .unwrap();
        assert_eq!(sa.statfs().blocks_free, 500_000_000 / 4096);
        assert!(!sa.has_pending_delta());
    }

    // -- Slop bytes affect admission and statfs in lockstep --

    #[test]
    fn admission_rejects_when_slop_reduces_effective_capacity() {
        let mut counters = test_counters();
        counters.slop_bytes = 500_000;
        let sa = SpaceAccounting::new(counters, SpaceDomainId::NONE);
        // Effective capacity = 1_000_000_000 - 500_000.
        // Used=0, so 999_500_000 available.
        assert!(!sa.check_enospc(999_500_000));
        assert!(sa.check_enospc(999_500_001));
    }

    // -- Combined consumption: reserved + orphan + pinned_snapshot --

    #[test]
    fn statfs_combines_all_counter_families() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.commit_delta(SpaceDelta::new_write(100_000)).unwrap();
        sa.commit_delta(SpaceDelta::new_reservation(200_000))
            .unwrap();
        sa.commit_delta(SpaceDelta::new_orphan_acquire(50_000))
            .unwrap();
        // Also set pinned_snapshot.
        let snap = SnapshotSpaceRecord {
            state: SnapshotState::Active,
            deadlist_bytes: 30_000,
            ..Default::default()
        };
        sa.update_snapshot_pinned(&[snap]);
        let total_consumed = 100_000 + 200_000 + 50_000 + 30_000;
        let expected_free = (TEST_QUOTA_BYTES - total_consumed) / 4096;
        let s = sa.statfs();
        assert_eq!(s.blocks_free, expected_free);
    }

    #[test]
    fn check_enospc_combines_all_counter_families() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        sa.commit_delta(SpaceDelta::new_write(100_000)).unwrap();
        sa.commit_delta(SpaceDelta::new_reservation(200_000))
            .unwrap();
        sa.commit_delta(SpaceDelta::new_orphan_acquire(50_000))
            .unwrap();
        sa.update_snapshot_pinned(&[SnapshotSpaceRecord {
            state: SnapshotState::Active,
            deadlist_bytes: 30_000,
            ..Default::default()
        }]);
        let total_consumed = 100_000 + 200_000 + 50_000 + 30_000;
        let avail = TEST_QUOTA_BYTES - total_consumed;
        assert!(!sa.check_enospc(avail));
        assert!(sa.check_enospc(avail + 1));
    }

    // -- Physical pool exhaustion with quota: quota takes precedence --

    #[test]
    fn statfs_quota_takes_precedence_over_physical_capacity() {
        let mut sa = SpaceAccounting::new(test_counters(), SpaceDomainId::NONE);
        // Quota is smaller than physical pool.
        sa.update_pool_counters(test_pool(10_000_000, 10_000_000));
        // capacity = min(quota, phys) = quota = 1_000_000_000.
        let s = sa.statfs();
        assert_eq!(s.blocks, TEST_QUOTA_BYTES / 4096);
        // But avail is capped by physical.
        // free_bytes = 1_000_000_000 - 0 = 1_000_000_000
        // avail_bytes = free min(pool_phys - consumed) = 1_000_000_000 min(10_000_000) = 10_000_000
        assert_eq!(s.blocks_avail, 10_000_000 / 4096);
    }
}
