// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Production capacity authority for mounted capacity decisions.
//!
//! Reconstructed from committed-root state and pool geometry during mount
//! recovery. Serves as the authoritative derivation source for FUSE statfs
//! (via [`LocalFileSystem::statfs`]), kernel VFS statfs, object-store
//! allocation, dataset quotas, block trim/discard, and ENOSPC enforcement.
//!
//! This authority is the mounted-filesystem facade over the committed
//! `tidefs-space-accounting` counters plus transient in-flight holds.
//! `SpaceBook` remains active for per-dataset write/delete auto-update
//! tracking and persistence, but mounted ENOSPC and statfs decisions flow
//! through [`tidefs_space_accounting::SpaceAccounting`] through this facade.
//!
//! # Relationship to existing layers
//!
//! - [`tidefs_block_allocator::BlockAllocator`]: tracks individual block
//!   allocations; the authority derives used-bytes from committed extent
//!   allocations plus reserved blocks.
//! - [`tidefs_local_object_store::pool::PoolCapacityStats`][]: pool-level
//!   capacity snapshot; the authority uses total capacity bytes from the
//!   pool and reconciles with allocator-level counters.
//! - [`tidefs_space_accounting::SpaceAccounting`]: dataset-level logical
//!   space tracking for per-dataset commit/rollback lifecycle. The authority
//!   synchronizes the mounted filesystem view with this committed path and
//!   delegates ENOSPC/statfs derivation to it.
//! - [`tidefs_posix_filesystem_adapter_capacity::CapacityFacade`]:
//!   retired adapter-local capacity bridge; removed from the production mount
//!   and admission path as of #5938 and quarantined behind `#[cfg(test)]` as
//!   of #6155.  Mounted FUSE statfs now derives block counters directly from
//!   this authority through the engine, and no adapter-local reservation
//!   lifecycle runs alongside the engine path.
//!
//! # Single-Authority Chain
//!
//! Mounted statfs and write admission derive from this documented facade.
//! The chain below records the current runtime boundary: committed counters
//! live in `SpaceAccounting`; transient reservations live here; allocator
//! reports, `SpaceBook`, and physical pool counters are inputs, persistence,
//! or projections rather than independent mounted availability authorities.
//!
//! ```text
//! CapacityAuthority (single production source)
//! ├── statfs (FUSE + POSIX)
//! │   via LocalFileSystem::statfs() and derive_statfs()
//! │   Wire: fuse_statfs::engine_statfs(), LocalFileSystem::statvfs()
//! │
//! ├── ENOSPC gating (write, create, mkdir, truncate, fallocate)
//! │   via check_enospc()
//! │   Wire: LocalFileSystem write/create/mkdir/truncate paths
//! │
//! ├── Block accounting (record_allocation, record_free)
//! │   Wire: LocalFileSystem write, truncate, unlink, punch_hole paths
//! │
//! ├── Quota physical pool free bytes
//! │   via pool_free_bytes_for_quota() -> capacity_authority.free_bytes()
//! │   Wire: quota_table.check_delta(..., pool_free) at every mutation point
//! │
//! ├── Pool physical counters (PoolPhysicalCountersV1)
//! │   via mounted_authority_projection() -> capacity_authority
//! │   Wire: statfs() refresh and commit_space_delta() persistence
//! │   Contract: only phys_total_bytes is an admitted mounted capacity input;
//! │   physical free/reclaimable/watermark fields are lower-layer observations.
//! │
//! └── Transaction rollback
//!     via snapshot_for_rollback() / restore_from_snapshot()
//!     Wire: LocalFileSystem transaction commit/abort paths
//! ```
//!
//! ## Retired Dual-Query Paths
//!
//! The former local fallback arithmetic path is retired; statfs uses
//! [`CapacityAuthority::derive_statfs`], which delegates to
//! [`tidefs_space_accounting::SpaceAccounting::statfs`].
//! The former FUSE adapter `CapacityFacade` is quarantined behind
//! `#[cfg(test)]` and excluded from the production mount path. The
//! `pool_free_bytes_for_quota()` path previously queried the allocator
//! report independently of the authority; the capacity-authority audit routes it
//! through [`CapacityAuthority::free_bytes`]. Runtime TFR-007 follow-ups still
//! track the remaining projection and persistence bridges. The
//! `derive_pool_physical_counters()` path previously mixed
//! `allocator_policy.content_capacity_bytes` with allocator free reports.
//! Mounted refresh now consumes the sanitized
//! `PoolPhysicalCountersV1::mounted_authority_projection()`: the lower
//! physical-pool report may bound `phys_total_bytes`, while mounted free bytes
//! and admission remain derived from committed accounting plus transient holds.

//! # Production Call Graph
//!
//! ## Construction (mount / recovery)
//!
//! ```text
//! LocalFileSystem::open()
//!   -> pool_stats + allocator_policy
//!   -> CapacityAuthority::from_committed_accounting(total, accounting, block_size, root_reserve)
//!   -> stored as engine.capacity_authority field
//! ```
//!
//! ## Statfs -- FUSE (engine trait path)
//!
//! ```text
//! VfsEngineStatFs::statfs()                        [vfs_engine_impl.rs]
//!   -> fuse_statfs::engine_statfs()                [fuse_statfs.rs]
//!     -> LocalFileSystem::statfs()                 [lib.rs]
//!       -> CapacityAuthority::set_total_bytes()     (live pool total)
//!       -> CapacityAuthority::derive_statfs()       (block counters)
//!       -> quota/effective-capacity clamp           (FUSE StatFs source)
//! ```
//!
//! ## Statfs -- POSIX statvfs
//!
//! ```text
//! LocalFileSystem::statvfs()                       [statfs.rs]
//!   -> CapacityAuthority::derive_statfs()
//! ```
//!
//! ## ENOSPC Gating (write, truncate, create, mkdir)
//!
//! ```text
//! LocalFileSystem write/create/truncate/mkdir      [lib.rs]
//!   -> CapacityAuthority::check_enospc(requested_bytes)
//!   -> on success: CapacityAuthority::record_allocation(bytes)
//! ```
//!
//! ## Free Accounting (truncate down, unlink, rmdir, punch hole)
//!
//! ```text
//! LocalFileSystem truncate/unlink/rmdir/punch_hole [lib.rs]
//!   -> CapacityAuthority::record_free(bytes)
//! ```
//!
//! ## Admission Watermark (writeback gate)
//!
//! ```text
//! LocalFileSystem::check_write_admission()         [lib.rs]
//!   -> delegates to tidefs_local_object_store DeviceIoClass
//!   (CapacityAuthority not directly used for this gate)
//! ```

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::RwLock;

use tidefs_space_accounting::{SpaceAccounting, StatfsResult};
use tidefs_types_space_accounting_core::{
    AdmissionResult, DatasetSpaceCountersV1, PoolPhysicalCountersV1, SpaceDomainId,
};
use tidefs_types_vfs_core::Errno;

/// POSIX errno constants (no libc dependency).
const ENOSPC: u16 = 28;

// ── CapacityAuthority ───────────────────────────────────────────────────

/// Mounted authority facade for filesystem capacity decisions.
///
/// The committed view is stored as `SpaceAccounting`. Atomic counters expose
/// the mounted transient projection needed by the FUSE dispatch path,
/// mount/recovery path, and background services. The authority is initialized
/// during mount recovery and lives for the lifetime of the filesystem.
#[derive(Debug)]
pub struct CapacityAuthority {
    total_bytes: AtomicU64,
    used_bytes: AtomicU64,
    reserved_bytes: AtomicU64,
    pending_bytes: AtomicU64,
    block_size: AtomicU32,
    root_reserve_bytes: AtomicU64,
    committed_accounting: RwLock<SpaceAccounting>,
}

impl CapacityAuthority {
    /// Create an authority seeded with pool geometry and committed usage.
    ///
    /// `total_bytes` is the pool's total capacity; `used_bytes` is the
    /// sum of all committed extent allocations. Both must be <= `total_bytes`.
    /// `block_size` is the statfs reporting block size, normally 4096 bytes.
    /// `root_reserve_bytes` is the number of bytes reserved for the
    /// root user (unprivileged callers see reduced availability).
    #[must_use]
    pub fn new(
        total_bytes: u64,
        used_bytes: u64,
        block_size: u32,
        root_reserve_bytes: u64,
    ) -> Self {
        // Never panic on live pools: treat inconsistent geometry/usage as a
        // mount-time consistency error and clamp to a conservative safe value.
        //
        // This mismatch can happen after crash-recovery, evolving pool-geometry
        // interpretation, or partial import of older pools. The correct
        // behaviour is fail-closed with ENOSPC-style semantics, not a daemon
        // abort that drops the mount.
        let used_bytes = used_bytes.min(total_bytes);
        assert!(block_size > 0, "block_size must be positive");
        let committed_accounting = Self::accounting_from_geometry(total_bytes, used_bytes);
        Self {
            total_bytes: AtomicU64::new(total_bytes),
            used_bytes: AtomicU64::new(used_bytes),
            reserved_bytes: AtomicU64::new(0),
            pending_bytes: AtomicU64::new(0),
            block_size: AtomicU32::new(block_size),
            root_reserve_bytes: AtomicU64::new(root_reserve_bytes),
            committed_accounting: RwLock::new(committed_accounting),
        }
    }

    /// Create an authority from a pool capacity snapshot.
    #[must_use]
    pub fn from_pool_stats(
        total_capacity_bytes: u64,
        used_bytes: u64,
        block_size: u32,
        root_reserve_bytes: u64,
    ) -> Self {
        Self::new(
            total_capacity_bytes,
            used_bytes,
            block_size,
            root_reserve_bytes,
        )
    }

    /// Create an authority from the mounted filesystem's committed
    /// `tidefs-space-accounting` state.
    #[must_use]
    pub fn from_committed_accounting(
        total_capacity_bytes: u64,
        accounting: &SpaceAccounting,
        block_size: u32,
        root_reserve_bytes: u64,
    ) -> Self {
        assert!(block_size > 0, "block_size must be positive");
        let consumed = accounting.counters().total_consumed_bytes();
        let mut committed = accounting.clone();
        committed.update_pool_counters(Self::pool_counters_for_capacity(
            total_capacity_bytes,
            consumed,
        ));
        Self {
            total_bytes: AtomicU64::new(total_capacity_bytes),
            used_bytes: AtomicU64::new(consumed.min(total_capacity_bytes)),
            reserved_bytes: AtomicU64::new(0),
            pending_bytes: AtomicU64::new(0),
            block_size: AtomicU32::new(block_size),
            root_reserve_bytes: AtomicU64::new(root_reserve_bytes),
            committed_accounting: RwLock::new(committed),
        }
    }

    fn accounting_from_geometry(total_bytes: u64, used_bytes: u64) -> SpaceAccounting {
        let counters = DatasetSpaceCountersV1 {
            logical_used_bytes: used_bytes.min(total_bytes),
            quota_bytes: total_bytes,
            ..DatasetSpaceCountersV1::default()
        };
        let mut accounting = SpaceAccounting::new(counters, SpaceDomainId::NONE);
        accounting.update_pool_counters(Self::pool_counters_for_capacity(total_bytes, used_bytes));
        accounting
    }

    fn pool_counters_for_capacity(total_bytes: u64, consumed_bytes: u64) -> PoolPhysicalCountersV1 {
        PoolPhysicalCountersV1::mounted_authority_from_capacity(
            total_bytes,
            consumed_bytes,
            StatfsResult::DEFAULT_BLOCK_SIZE,
        )
    }

    /// Refresh the committed accounting mirror without changing the local
    /// transient reservation ledger.
    pub(crate) fn refresh_committed_accounting(
        &self,
        accounting: &SpaceAccounting,
        pool: PoolPhysicalCountersV1,
    ) {
        let mut committed = accounting.clone();
        let consumed = committed.counters().total_consumed_bytes();
        let mounted_pool =
            pool.mounted_authority_projection(consumed, StatfsResult::DEFAULT_BLOCK_SIZE);
        let total = mounted_pool.phys_total_bytes;
        committed.update_pool_counters(mounted_pool);
        self.total_bytes.store(total, Ordering::Release);
        self.used_bytes
            .store(consumed.min(total), Ordering::Release);
        *self
            .committed_accounting
            .write()
            .expect("capacity committed accounting lock poisoned") = committed;
    }

    /// Refresh the committed accounting mirror after a commit boundary and
    /// clear transient bytes that are now part of committed counters.
    pub(crate) fn refresh_committed_accounting_after_commit(
        &self,
        accounting: &SpaceAccounting,
        pool: PoolPhysicalCountersV1,
    ) {
        self.refresh_committed_accounting(accounting, pool);
        self.pending_bytes.store(0, Ordering::Release);
        self.reserved_bytes.store(0, Ordering::Release);
    }

    /// Set the root-reserve byte count.
    #[cfg(test)]
    pub(crate) fn set_root_reserve_bytes(&self, bytes: u64) {
        self.root_reserve_bytes.store(bytes, Ordering::Release);
    }

    /// Update the total pool capacity in bytes.
    ///
    /// Called when the allocator policy is resized so statfs-derived
    /// block counts reflect the new configured ceiling.
    #[cfg(test)]
    pub(crate) fn set_total_bytes(&self, bytes: u64) {
        self.total_bytes.store(bytes, Ordering::Release);
        let mut accounting = self
            .committed_accounting
            .write()
            .expect("capacity committed accounting lock poisoned");
        let consumed = accounting.counters().total_consumed_bytes();
        accounting.update_pool_counters(Self::pool_counters_for_capacity(bytes, consumed));
    }

    // ── Block accounting ────────────────────────────────────────────

    /// Record a committed allocation of `bytes` bytes.
    #[cfg(test)]
    pub(crate) fn record_allocation(&self, bytes: u64) {
        self.used_bytes.fetch_add(bytes, Ordering::Release);
        self.pending_bytes.fetch_add(bytes, Ordering::Release);
    }

    /// Record the freeing of `bytes` bytes from committed state.
    pub(crate) fn record_free(&self, bytes: u64) {
        self.used_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                Some(used.saturating_sub(bytes))
            })
            .ok();
        self.pending_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                Some(pending.saturating_sub(bytes))
            })
            .ok();
    }

    // ── Reservation lifecycle ───────────────────────────────────────

    /// Reserve `bytes` bytes for an in-flight operation.
    ///
    /// Returns `Err(ENOSPC)` if the reservation would exceed available
    /// free space. A zero-byte reservation is valid and returns an inert
    /// handle.
    ///
    /// Production: callers reserve bytes before performing an allocation,
    /// then call [`CapacityReservationHandle::commit`] on success or
    /// [`CapacityReservationHandle::release`] on failure. This replaces the
    /// former fragmented reservation paths in `SpaceAccounting` and
    /// `BlockAllocator::QuotaTable`.
    pub(crate) fn reserve(&self, bytes: u64) -> Result<CapacityReservationHandle, Errno> {
        if bytes == 0 {
            return Ok(CapacityReservationHandle {
                authority: self,
                bytes: 0,
                resolved: false,
            });
        }
        self.check_enospc(bytes)?;
        self.reserved_bytes.fetch_add(bytes, Ordering::Release);
        Ok(CapacityReservationHandle {
            authority: self,
            bytes,
            resolved: false,
        })
    }

    /// Reserve `bytes` for a rewrite that will replace already materialized
    /// content. Admission checks only the net new bytes, while the full
    /// reservation stays held until the rewrite commits and releases the
    /// replaced content.
    pub(crate) fn reserve_with_replacement_credit(
        &self,
        bytes: u64,
        replacement_credit_bytes: u64,
    ) -> Result<CapacityReservationHandle, Errno> {
        if bytes == 0 {
            return self.reserve(0);
        }
        let net_new_bytes = bytes.saturating_sub(replacement_credit_bytes);
        self.check_enospc(net_new_bytes)?;
        self.reserved_bytes.fetch_add(bytes, Ordering::Release);
        Ok(CapacityReservationHandle {
            authority: self,
            bytes,
            resolved: false,
        })
    }

    fn commit_reservation(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.reserved_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |r| {
                Some(r.saturating_sub(bytes))
            })
            .ok();
        self.used_bytes.fetch_add(bytes, Ordering::Release);
        self.pending_bytes.fetch_add(bytes, Ordering::Release);
    }

    fn release_reservation(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.reserved_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |r| {
                Some(r.saturating_sub(bytes))
            })
            .ok();
    }

    // ── ENOSPC gating ───────────────────────────────────────────────

    /// Check whether `requested_bytes` can be accommodated.
    ///
    /// Delegates to the committed `tidefs-space-accounting` admission path.
    /// Transient mounted reservations are passed as additional requested
    /// bytes so concurrent local operations cannot overcommit the committed
    /// counters.
    pub fn check_enospc(&self, requested_bytes: u64) -> Result<(), Errno> {
        if requested_bytes == 0 {
            return Ok(());
        }
        // This caller-neutral admission path uses the same unprivileged
        // availability boundary reported by available_bytes() and statfs.
        let held_bytes = self
            .transient_held_bytes()
            .saturating_add(self.root_reserve_bytes());
        let needed_bytes = requested_bytes.saturating_add(held_bytes);
        let accounting = self
            .committed_accounting
            .read()
            .expect("capacity committed accounting lock poisoned");
        match accounting.admission_check(needed_bytes) {
            AdmissionResult::Allowed => Ok(()),
            AdmissionResult::QuotaExceeded { .. }
            | AdmissionResult::PhysicalCapacityExceeded { .. } => Err(Errno(ENOSPC)),
        }
    }

    /// Record pending bytes in the write pipeline.
    #[cfg(test)]
    pub(crate) fn record_pending(&self, bytes: u64) {
        self.pending_bytes.fetch_add(bytes, Ordering::Release);
    }

    /// Clear pending bytes after they have been resolved.
    #[cfg(test)]
    pub(crate) fn clear_pending(&self, bytes: u64) {
        self.pending_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |p| {
                Some(p.saturating_sub(bytes))
            })
            .ok();
    }

    // ── Statfs derivation ───────────────────────────────────────────

    fn transient_held_bytes(&self) -> u64 {
        self.reserved_bytes().saturating_add(self.pending_bytes())
    }

    fn blocks_after_transient_hold(blocks: u64, block_size: u64, held_bytes: u64) -> u64 {
        if block_size == 0 {
            return 0;
        }
        blocks.saturating_mul(block_size).saturating_sub(held_bytes) / block_size
    }

    /// Derive filesystem block counters suitable for statfs/statvfs.
    #[must_use]
    pub fn derive_statfs(
        &self,
        inode_total: u64,
        inode_free: u64,
        name_max: u32,
    ) -> CapacityStatfs {
        let statfs = self
            .committed_accounting
            .read()
            .expect("capacity committed accounting lock poisoned")
            .statfs();
        let block_size = u32::try_from(statfs.block_size).unwrap_or(u32::MAX);
        let held_bytes = self.transient_held_bytes();
        let free_blocks =
            Self::blocks_after_transient_hold(statfs.blocks_free, statfs.block_size, held_bytes);
        let avail_blocks =
            Self::blocks_after_transient_hold(statfs.blocks_avail, statfs.block_size, held_bytes);
        let reserve_blocks = if statfs.block_size == 0 {
            0
        } else {
            self.root_reserve_bytes() / statfs.block_size
        };

        CapacityStatfs {
            total_blocks: statfs.blocks,
            free_blocks,
            avail_blocks: avail_blocks.saturating_sub(reserve_blocks),
            total_inodes: inode_total,
            free_inodes: inode_free,
            block_size,
            name_max,
        }
    }

    // ── Accessors ───────────────────────────────────────────────────

    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn used_bytes(&self) -> u64 {
        self.used_bytes.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn pending_bytes(&self) -> u64 {
        self.pending_bytes.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn root_reserve_bytes(&self) -> u64 {
        self.root_reserve_bytes.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn free_bytes(&self) -> u64 {
        let statfs = self
            .committed_accounting
            .read()
            .expect("capacity committed accounting lock poisoned")
            .statfs();
        statfs
            .blocks_free
            .saturating_mul(statfs.block_size)
            .saturating_sub(self.transient_held_bytes())
    }

    #[must_use]
    pub fn available_bytes(&self) -> u64 {
        let statfs = self
            .committed_accounting
            .read()
            .expect("capacity committed accounting lock poisoned")
            .statfs();
        statfs
            .blocks_avail
            .saturating_mul(statfs.block_size)
            .saturating_sub(self.transient_held_bytes())
            .saturating_sub(self.root_reserve_bytes())
    }

    #[must_use]
    pub fn block_size(&self) -> u32 {
        self.block_size.load(Ordering::Acquire)
    }

    // ── Block rounding helpers ──────────────────────────────────────

    /// Round a byte count up to the authority's block size.
    ///
    /// Returns `Ok(0)` for zero bytes.  Returns `Err(EIO)` if the
    /// authority's block size is zero (broken runtime configuration).
    pub fn blocks_for_bytes(&self, bytes: u64) -> Result<u64, Errno> {
        if bytes == 0 {
            return Ok(0);
        }
        let bs = u64::from(self.block_size());
        if bs == 0 {
            return Err(Errno::EIO);
        }
        let full_blocks = bytes / bs;
        let partial_block = u64::from(bytes % bs != 0);
        Ok(full_blocks + partial_block)
    }

    /// Compute the number of additional blocks required for a file-size
    /// transition, rounded up to the authority's block size.
    ///
    /// Returns `Ok(0)` when `requested_size <= current_size` (no growth).
    pub fn growth_blocks_for_size_change(
        &self,
        current_size: u64,
        requested_size: u64,
    ) -> Result<u64, Errno> {
        if requested_size <= current_size {
            return Ok(0);
        }
        let current_blocks = self.blocks_for_bytes(current_size)?;
        let requested_blocks = self.blocks_for_bytes(requested_size)?;
        Ok(requested_blocks.saturating_sub(current_blocks))
    }

    // ── Transaction rollback snapshot/restore ──────────────────────────

    /// Capture a snapshot of the authority counters for transaction rollback.
    #[must_use]
    pub(crate) fn snapshot_for_rollback(&self) -> CapacityAuthoritySnapshot {
        CapacityAuthoritySnapshot {
            used_bytes: self.used_bytes.load(Ordering::Acquire),
            reserved_bytes: self.reserved_bytes(),
            pending_bytes: self.pending_bytes(),
            committed_accounting: self
                .committed_accounting
                .read()
                .expect("capacity committed accounting lock poisoned")
                .clone(),
        }
    }

    /// Restore authority counters to a previously captured snapshot.
    pub(crate) fn restore_from_snapshot(&self, snapshot: &CapacityAuthoritySnapshot) {
        self.used_bytes
            .store(snapshot.used_bytes, Ordering::Release);
        self.reserved_bytes
            .store(snapshot.reserved_bytes, Ordering::Release);
        self.pending_bytes
            .store(snapshot.pending_bytes, Ordering::Release);
        *self
            .committed_accounting
            .write()
            .expect("capacity committed accounting lock poisoned") =
            snapshot.committed_accounting.clone();
    }
}

/// Snapshot of capacity counters captured at transaction start
/// for restoration on rollback.
#[derive(Clone, Debug)]
pub(crate) struct CapacityAuthoritySnapshot {
    pub used_bytes: u64,
    pub reserved_bytes: u64,
    pub pending_bytes: u64,
    pub committed_accounting: SpaceAccounting,
}

// ── CapacityStatfs ───────────────────────────────────────────────────────

/// Block and inode counters derived from the capacity authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CapacityStatfs {
    pub total_blocks: u64,
    pub free_blocks: u64,
    pub avail_blocks: u64,
    pub total_inodes: u64,
    pub free_inodes: u64,
    pub block_size: u32,
    pub name_max: u32,
}

// ── CapacityReservationHandle ────────────────────────────────────────────

/// A held reservation of bytes against the capacity authority.
///
/// Dropping an unresolved handle releases the reservation automatically.
///
/// Production: this handle owns a capacity reservation. Call [`commit`] to
/// convert the reservation to a committed allocation, or [`release`] to
/// return the bytes to the free pool. Dropping without committing or releasing
/// auto-releases.
#[derive(Debug)]
pub struct CapacityReservationHandle<'a> {
    authority: &'a CapacityAuthority,
    bytes: u64,
    resolved: bool,
}

impl<'a> CapacityReservationHandle<'a> {
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn commit(mut self) {
        self.commit_inner();
        self.resolved = true;
    }

    pub fn release(mut self) {
        self.release_inner();
        self.resolved = true;
    }

    fn commit_inner(&mut self) {
        if self.resolved {
            return;
        }
        self.authority.commit_reservation(self.bytes);
    }

    fn release_inner(&mut self) {
        if self.resolved {
            return;
        }
        self.authority.release_reservation(self.bytes);
    }
}

impl<'a> Drop for CapacityReservationHandle<'a> {
    fn drop(&mut self) {
        if !self.resolved {
            self.release_inner();
            self.resolved = true;
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn authority(total_mb: u64, used_mb: u64) -> CapacityAuthority {
        let block_size: u32 = 4096;
        let total = total_mb * 1024 * 1024;
        let used = used_mb * 1024 * 1024;
        CapacityAuthority::new(total, used, block_size, 0)
    }

    fn authority_with_reserve(
        total_mb: u64,
        used_mb: u64,
        reserve_blocks: u64,
    ) -> CapacityAuthority {
        let block_size: u32 = 4096;
        let total = total_mb * 1024 * 1024;
        let used = used_mb * 1024 * 1024;
        let root_reserve = reserve_blocks * u64::from(block_size);
        CapacityAuthority::new(total, used, block_size, root_reserve)
    }

    #[test]
    fn new_has_positive_block_size() {
        let a = authority(100, 0);
        assert_eq!(a.block_size(), 4096);
        assert_eq!(a.total_bytes(), 100 * 1024 * 1024);
        assert_eq!(a.used_bytes(), 0);
        assert_eq!(a.reserved_bytes(), 0);
    }

    #[test]
    fn new_clamps_used_when_exceeds_total() {
        // The constructor clamps used_bytes to total_bytes instead of
        // panicking, because this mismatch can occur legitimately after
        // crash recovery or pool-geometry reinterpretation.
        let a = CapacityAuthority::new(100, 200, 4096, 0);
        assert_eq!(a.used_bytes(), 100);
        assert_eq!(a.total_bytes(), 100);
    }

    #[test]
    #[should_panic(expected = "block_size must be positive")]
    fn new_rejects_zero_block_size() {
        let _ = CapacityAuthority::new(100, 0, 0, 0);
    }

    #[test]
    fn new_at_exact_capacity() {
        let a = CapacityAuthority::new(4096, 4096, 4096, 0);
        assert_eq!(a.free_bytes(), 0);
        assert_eq!(a.available_bytes(), 0);
    }

    #[test]
    fn record_allocation_tracks_pending_against_committed_free_bytes() {
        let a = authority(100, 0);
        assert_eq!(a.free_bytes(), 100 * 1024 * 1024);
        a.record_allocation(1024 * 1024);
        assert_eq!(a.used_bytes(), 1024 * 1024);
        assert_eq!(a.pending_bytes(), 1024 * 1024);
        assert_eq!(a.free_bytes(), 99 * 1024 * 1024);
    }

    #[test]
    fn record_free_restores_capacity() {
        let a = authority(100, 10);
        assert_eq!(a.free_bytes(), 90 * 1024 * 1024);
        a.record_free(5 * 1024 * 1024);
        assert_eq!(a.used_bytes(), 5 * 1024 * 1024);
        assert_eq!(a.free_bytes(), 90 * 1024 * 1024);
    }

    #[test]
    fn record_free_clamps_at_zero() {
        let a = authority(100, 0);
        a.record_free(1024 * 1024);
        assert_eq!(a.used_bytes(), 0);
        assert_eq!(a.free_bytes(), 100 * 1024 * 1024);
    }

    #[test]
    fn roundtrip_alloc_free_is_identity() {
        let a = authority(100, 0);
        a.record_allocation(4096);
        assert_eq!(a.used_bytes(), 4096);
        a.record_free(4096);
        assert_eq!(a.used_bytes(), 0);
        assert_eq!(a.free_bytes(), 100 * 1024 * 1024);
    }

    #[test]
    fn reserve_holds_bytes() {
        let a = authority(100, 0);
        let h = a.reserve(4096).expect("reserve 1 block");
        assert_eq!(h.bytes(), 4096);
        assert_eq!(a.reserved_bytes(), 4096);
        assert_eq!(a.free_bytes(), (100 * 1024 * 1024) - 4096);
        h.release();
        assert_eq!(a.reserved_bytes(), 0);
        assert_eq!(a.free_bytes(), 100 * 1024 * 1024);
    }

    #[test]
    fn reserve_commit_moves_to_used() {
        let a = authority(100, 0);
        let h = a.reserve(8192).expect("reserve 2 blocks");
        assert_eq!(a.reserved_bytes(), 8192);
        assert_eq!(a.used_bytes(), 0);
        h.commit();
        assert_eq!(a.reserved_bytes(), 0);
        assert_eq!(a.used_bytes(), 8192);
        assert_eq!(a.pending_bytes(), 8192);
        assert_eq!(a.free_bytes(), (100 * 1024 * 1024) - 8192);
    }

    #[test]
    fn reserve_enospc_when_exhausted() {
        let a = authority(1, 1);
        assert_eq!(a.reserve(1).unwrap_err(), Errno(ENOSPC));
        assert_eq!(a.reserved_bytes(), 0);
    }

    #[test]
    fn zero_byte_reservation_is_inert() {
        let a = authority(100, 0);
        let h = a.reserve(0).expect("zero reserve");
        assert_eq!(h.bytes(), 0);
        assert_eq!(a.reserved_bytes(), 0);
        h.commit();
        assert_eq!(a.used_bytes(), 0);
    }

    #[test]
    fn drop_releases_unreserved_reservation() {
        let a = authority(100, 0);
        {
            let _h = a.reserve(4096).expect("reserve");
            assert_eq!(a.reserved_bytes(), 4096);
        }
        assert_eq!(a.reserved_bytes(), 0);
    }

    #[test]
    fn check_enospc_allows_within_limit() {
        let a = authority(100, 0);
        assert!(a.check_enospc(50 * 1024 * 1024).is_ok());
        assert!(a.check_enospc(100 * 1024 * 1024).is_ok());
    }

    #[test]
    fn check_enospc_rejects_over_capacity() {
        let a = authority(100, 0);
        assert_eq!(
            a.check_enospc(101 * 1024 * 1024).unwrap_err(),
            Errno(ENOSPC)
        );
    }

    #[test]
    fn check_enospc_rejects_when_reserved() {
        let a = authority(100, 80);
        let _h = a.reserve(15 * 1024 * 1024).expect("reserve 15");
        assert!(a.check_enospc(5 * 1024 * 1024).is_ok());
        assert_eq!(a.check_enospc(6 * 1024 * 1024).unwrap_err(), Errno(ENOSPC));
    }

    #[test]
    fn check_enospc_respects_root_reserve() {
        let a = authority_with_reserve(1, 0, 1);
        let available = (1024 * 1024) - 4096;
        assert!(a.check_enospc(available).is_ok());
        assert_eq!(a.check_enospc(available + 1), Err(Errno(ENOSPC)));
    }

    #[test]
    fn check_enospc_when_request_exceeds_total() {
        let a = authority(1, 0);
        assert_eq!(a.check_enospc(2 * 1024 * 1024).unwrap_err(), Errno(ENOSPC));
    }

    #[test]
    fn check_enospc_zero_bytes_always_ok() {
        let a = authority(1, 1);
        assert!(a.check_enospc(0).is_ok());
    }

    #[test]
    fn pending_tracks_inflight() {
        let a = authority(100, 0);
        a.record_pending(4096);
        assert_eq!(a.pending_bytes(), 4096);
        a.clear_pending(4096);
        assert_eq!(a.pending_bytes(), 0);
    }

    #[test]
    fn clear_pending_clamps_at_zero() {
        let a = authority(100, 0);
        a.clear_pending(4096);
        assert_eq!(a.pending_bytes(), 0);
    }

    #[test]
    fn root_reserve_reduces_available_but_not_free() {
        let a = authority_with_reserve(100, 0, 50);
        assert_eq!(a.free_bytes(), 100 * 1024 * 1024);
        assert_eq!(a.available_bytes(), (100 * 1024 * 1024) - (50 * 4096));
    }

    #[test]
    fn set_root_reserve_updates_available() {
        let a = authority(100, 0);
        assert_eq!(a.available_bytes(), 100 * 1024 * 1024);
        a.set_root_reserve_bytes(50 * 4096);
        assert_eq!(a.available_bytes(), (100 * 1024 * 1024) - (50 * 4096));
    }

    #[test]
    fn root_reserve_saturates_when_exceeds_free() {
        let a = authority_with_reserve(1, 0, 1000);
        assert_eq!(a.available_bytes(), 0);
    }

    #[test]
    fn derive_statfs_empty_pool() {
        let a = authority(100, 0);
        let s = a.derive_statfs(1000, 1000, 255);
        let bs = u64::from(a.block_size());
        let expected_blocks = (100u64 * 1024 * 1024) / bs;
        assert_eq!(s.total_blocks, expected_blocks);
        assert_eq!(s.free_blocks, expected_blocks);
        assert_eq!(s.avail_blocks, expected_blocks);
        assert_eq!(s.total_inodes, 1000);
        assert_eq!(s.free_inodes, 1000);
        assert_eq!(s.block_size, 4096);
        assert_eq!(s.name_max, 255);
    }

    #[test]
    fn derive_statfs_with_used_and_reserved() {
        let a = authority(100, 50);
        let _h = a.reserve(10 * 1024 * 1024).expect("reserve 10 MiB");
        let s = a.derive_statfs(500, 400, 255);
        let bs = u64::from(a.block_size());
        assert_eq!(s.total_blocks, (100u64 * 1024 * 1024) / bs);
        assert_eq!(s.free_blocks, (40u64 * 1024 * 1024) / bs);
        assert_eq!(s.avail_blocks, (40u64 * 1024 * 1024) / bs);
        assert_eq!(s.total_inodes, 500);
        assert_eq!(s.free_inodes, 400);
    }

    #[test]
    fn derive_statfs_with_root_reserve() {
        let a = authority_with_reserve(100, 0, 50);
        let s = a.derive_statfs(1000, 900, 255);
        let bs = u64::from(a.block_size());
        assert_eq!(s.free_blocks, (100u64 * 1024 * 1024) / bs);
        assert_eq!(s.avail_blocks, ((100u64 * 1024 * 1024) - (50 * bs)) / bs);
    }

    #[test]
    fn derive_statfs_uses_committed_space_accounting_consumption() {
        let block_size: u32 = 4096;
        let total = 100 * 1024 * 1024;
        let counters = DatasetSpaceCountersV1 {
            logical_used_bytes: 10 * 1024 * 1024,
            reserved_bytes: 5 * 1024 * 1024,
            orphan_bytes: 3 * 1024 * 1024,
            // pinned_snapshot_bytes is a subset of logical_used (#638, #649)
            // and is excluded from total_consumed_bytes.
            pinned_snapshot_bytes: 2 * 1024 * 1024,
            quota_bytes: total,
            ..DatasetSpaceCountersV1::default()
        };
        let accounting = SpaceAccounting::new(counters, SpaceDomainId::NONE);
        let a = CapacityAuthority::from_committed_accounting(total, &accounting, block_size, 0);

        let s = a.derive_statfs(1000, 900, 255);

        // consumed = logical_used + reserved + orphan (excludes pinned_snapshot).
        let consumed = 18 * 1024 * 1024;
        assert_eq!(s.free_blocks, (total - consumed) / u64::from(block_size));
        assert!(a.check_enospc(total - consumed).is_ok());
        assert_eq!(a.check_enospc(total - consumed + 1), Err(Errno(ENOSPC)));
    }

    #[test]
    fn refresh_committed_accounting_preserves_capacity_ceiling() {
        let block_size: u32 = 4096;
        let total = 100 * 1024 * 1024;
        let used = 25 * 1024 * 1024;
        let counters = DatasetSpaceCountersV1 {
            logical_used_bytes: used,
            ..DatasetSpaceCountersV1::default()
        };
        let accounting = SpaceAccounting::new(counters, SpaceDomainId::NONE);
        let a = CapacityAuthority::new(total, 0, block_size, 0);
        let pool_snapshot = PoolPhysicalCountersV1 {
            phys_free_segments: (total - used) / u64::from(block_size),
            phys_free_bytes: total - used,
            phys_reclaimable_bytes: 0,
            phys_tail_reserved_segments: 0,
            phys_total_segments: total / u64::from(block_size),
            phys_total_bytes: total,
        };

        a.refresh_committed_accounting(&accounting, pool_snapshot);

        let s = a.derive_statfs(1000, 900, 255);
        assert_eq!(a.free_bytes(), total - used);
        assert_eq!(s.free_blocks, (total - used) / u64::from(block_size));
        assert!(a.check_enospc(total - used).is_ok());
        assert_eq!(a.check_enospc(total - used + 1), Err(Errno(ENOSPC)));
    }

    #[test]
    fn mounted_physical_pool_input_rejects_stale_free_claim() {
        let block_size: u32 = 4096;
        let total = 100 * 1024 * 1024;
        let used = 80 * 1024 * 1024;
        let counters = DatasetSpaceCountersV1 {
            logical_used_bytes: used,
            ..DatasetSpaceCountersV1::default()
        };
        let accounting = SpaceAccounting::new(counters, SpaceDomainId::NONE);
        let a = CapacityAuthority::new(total, 0, block_size, 0);
        let stale_pool_snapshot = PoolPhysicalCountersV1 {
            phys_free_segments: u64::MAX,
            phys_free_bytes: u64::MAX,
            phys_reclaimable_bytes: u64::MAX,
            phys_tail_reserved_segments: u64::MAX,
            phys_total_segments: 1,
            phys_total_bytes: total,
        };

        a.refresh_committed_accounting(&accounting, stale_pool_snapshot);

        let free = total - used;
        let s = a.derive_statfs(1000, 900, 255);
        assert_eq!(a.free_bytes(), free);
        assert_eq!(a.available_bytes(), free);
        assert_eq!(s.free_blocks, free / u64::from(block_size));
        assert!(a.check_enospc(free).is_ok());
        assert_eq!(a.check_enospc(free + 1), Err(Errno(ENOSPC)));
    }

    #[test]
    fn mounted_physical_pool_input_missing_total_fails_closed() {
        let block_size: u32 = 4096;
        let accounting =
            SpaceAccounting::new(DatasetSpaceCountersV1::default(), SpaceDomainId::NONE);
        let a = CapacityAuthority::new(100 * 1024 * 1024, 0, block_size, 0);
        let missing_total_snapshot = PoolPhysicalCountersV1 {
            phys_free_segments: u64::MAX,
            phys_free_bytes: u64::MAX,
            phys_reclaimable_bytes: u64::MAX,
            phys_total_segments: u64::MAX,
            phys_total_bytes: 0,
            phys_tail_reserved_segments: 0,
        };

        a.refresh_committed_accounting(&accounting, missing_total_snapshot);

        let s = a.derive_statfs(1000, 900, 255);
        assert_eq!(a.total_bytes(), 0);
        assert_eq!(a.free_bytes(), 0);
        assert_eq!(a.available_bytes(), 0);
        assert_eq!(s.total_blocks, 0);
        assert_eq!(s.free_blocks, 0);
        assert_eq!(s.avail_blocks, 0);
        assert_eq!(a.check_enospc(1), Err(Errno(ENOSPC)));
    }

    #[test]
    fn derive_statfs_zero_total() {
        let a = CapacityAuthority::new(0, 0, 4096, 0);
        let s = a.derive_statfs(0, 0, 255);
        assert_eq!(s.total_blocks, 0);
        assert_eq!(s.free_blocks, 0);
        assert_eq!(s.avail_blocks, 0);
    }

    #[test]
    fn derive_statfs_is_idempotent() {
        let a = authority(100, 30);
        let _h = a.reserve(5 * 1024 * 1024).expect("reserve");
        let s1 = a.derive_statfs(500, 400, 255);
        let s2 = a.derive_statfs(500, 400, 255);
        assert_eq!(s1, s2);
    }

    #[test]
    fn transient_reservations_reduce_visible_free_bytes() {
        let a = authority(100, 40);
        let free_before = a.free_bytes();
        let _h = a.reserve(10 * 1024 * 1024).expect("reserve");
        assert_eq!(a.free_bytes(), free_before - (10 * 1024 * 1024));
        assert!(a.check_enospc(50 * 1024 * 1024).is_ok());
        assert_eq!(a.check_enospc(51 * 1024 * 1024), Err(Errno(ENOSPC)));
    }

    #[test]
    fn available_never_exceeds_free() {
        let a = authority_with_reserve(100, 10, 50);
        assert!(a.available_bytes() <= a.free_bytes());
    }

    #[test]
    fn from_pool_stats_preserves_geometry() {
        let a = CapacityAuthority::from_pool_stats(1024 * 1024 * 1024, 512 * 1024 * 1024, 4096, 0);
        assert_eq!(a.total_bytes(), 1024 * 1024 * 1024);
        assert_eq!(a.used_bytes(), 512 * 1024 * 1024);
        assert_eq!(a.block_size(), 4096);
        assert_eq!(a.reserved_bytes(), 0);
    }

    #[test]
    fn concurrent_allocation_thread_safety() {
        use std::sync::Arc;
        let a = Arc::new(authority(10000, 0));
        let mut handles = Vec::new();
        for _ in 0..10 {
            let a = Arc::clone(&a);
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    a.record_allocation(4096);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(a.used_bytes(), 10 * 1000 * 4096);
    }

    // ── ENOSPC reservation lifecycle ───────────────────────────────

    #[test]
    fn reserve_at_capacity_limit_returns_enospc() {
        // Fill the authority to exactly 100% capacity.
        let a = authority(100, 100);
        // Any reservation must fail.
        assert_eq!(a.reserve(1).unwrap_err(), Errno(ENOSPC));
        assert_eq!(a.reserve(4096).unwrap_err(), Errno(ENOSPC));
        // Used bytes unchanged by failed reservation.
        assert_eq!(a.used_bytes(), 100 * 1024 * 1024);
        assert_eq!(a.reserved_bytes(), 0);
    }

    #[test]
    fn reserve_at_capacity_minus_one_block_fills_capacity() {
        let a = authority(10, 0); // 10 MiB total
                                  // Hold all but one block in transient pending bytes.
        let h = a.reserve(10 * 1024 * 1024 - 4096).expect("fill nearly all");
        h.commit();
        assert_eq!(a.free_bytes(), 4096);
        // Reserve the last block.
        let handle = a.reserve(4096).expect("last block reserve");
        assert_eq!(a.reserved_bytes(), 4096);
        assert_eq!(a.available_bytes(), 0);
        // Additional reservation must fail.
        assert_eq!(a.reserve(4096).unwrap_err(), Errno(ENOSPC));
        // Commit the reservation — pool is now full.
        handle.commit();
        assert_eq!(a.used_bytes(), 10 * 1024 * 1024);
        assert_eq!(a.reserved_bytes(), 0);
        assert_eq!(a.pending_bytes(), 10 * 1024 * 1024);
        assert_eq!(a.free_bytes(), 0);
    }

    #[test]
    fn record_free_after_reservation_restores_availability() {
        let a = authority_with_reserve(100, 50, 0);
        let avail_before = a.available_bytes();

        // Reserve and commit 10 MiB.
        let handle = a.reserve(10 * 1024 * 1024).expect("reserve");
        handle.commit();
        assert_eq!(a.available_bytes(), avail_before - 10 * 1024 * 1024);

        // Free the same amount — capacity returns.
        a.record_free(10 * 1024 * 1024);
        assert_eq!(a.available_bytes(), avail_before);
    }

    #[test]
    fn drop_uncommitted_reservation_releases_bytes() {
        let a = authority(100, 50);
        let free_before = a.free_bytes();

        // Reserve within a scope; handle drops at end.
        {
            let _handle = a.reserve(5 * 1024 * 1024).expect("reserve");
            assert_eq!(a.reserved_bytes(), 5 * 1024 * 1024);
        }
        // After drop, reserved bytes are released.
        assert_eq!(a.reserved_bytes(), 0);
        assert_eq!(a.free_bytes(), free_before);
    }

    #[test]
    fn truncate_frees_capacity_deterministically() {
        let a = authority(100, 80);
        // Simulate a truncate that frees 20 MiB.
        a.record_allocation(20 * 1024 * 1024);
        assert_eq!(a.used_bytes(), 100 * 1024 * 1024);
        assert_eq!(a.free_bytes(), 0);

        // Free 20 MiB — capacity returns exactly.
        a.record_free(20 * 1024 * 1024);
        assert_eq!(a.used_bytes(), 80 * 1024 * 1024);
        assert_eq!(a.free_bytes(), 20 * 1024 * 1024);
    }

    #[test]
    fn enospc_is_deterministic_at_capacity_boundary() {
        // Prove that the capacity boundary is a hard gate: no overcommit.
        let a = authority(100, 100);
        for _ in 0..100 {
            assert_eq!(a.reserve(1).unwrap_err(), Errno(ENOSPC));
        }
        // Used/reserved/free all stable after repeated attempts.
        assert_eq!(a.used_bytes(), 100 * 1024 * 1024);
        assert_eq!(a.reserved_bytes(), 0);
        assert_eq!(a.free_bytes(), 0);
    }

    #[test]
    fn remove_after_write_frees_capacity() {
        let a = authority(100, 40);
        let free_before = a.free_bytes();

        // Simulate write: reserve + commit.
        let handle = a.reserve(10 * 1024 * 1024).expect("reserve");
        handle.commit();
        assert_eq!(a.free_bytes(), free_before - 10 * 1024 * 1024);

        // Simulate removal (unlink): free the bytes.
        a.record_free(10 * 1024 * 1024);
        assert_eq!(a.free_bytes(), free_before);
    }
}
