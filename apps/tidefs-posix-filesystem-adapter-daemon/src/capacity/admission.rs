// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Capacity admission helpers for POSIX size growth and metadata reservations.

use tidefs_block_allocator::AllocError;
use tidefs_types_vfs_core::{Errno, InodeId};

use super::CapacityFacade;

/// Result of a successful capacity admission check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionResult {
    /// Current logical file size before the operation.
    pub current_size: u64,
    /// Requested logical file size after the operation.
    pub requested_size: u64,
    /// Number of additional allocator blocks needed.
    pub required_blocks: u64,
    /// Number of blocks available to unprivileged users at admission time.
    pub available_blocks: u64,
}

/// Held adapter-local capacity reservation.
///
/// Dropping an unresolved reservation releases it, so error paths do not leak
/// statfs-visible availability or quota reservations.
#[derive(Debug)]
pub struct CapacityReservation {
    capacity: CapacityFacade,
    inode: Option<InodeId>,
    admitted: AdmissionResult,
    resolved: bool,
}

impl CapacityReservation {
    fn new(capacity: &CapacityFacade, inode: Option<InodeId>, admitted: AdmissionResult) -> Self {
        capacity.hold_reserved_blocks(admitted.required_blocks);
        Self {
            capacity: capacity.clone(),
            inode,
            admitted,
            resolved: false,
        }
    }

    #[must_use]
    pub const fn admitted(&self) -> AdmissionResult {
        self.admitted
    }

    #[must_use]
    pub const fn required_blocks(&self) -> u64 {
        self.admitted.required_blocks
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
        if self.resolved || self.required_blocks() == 0 {
            return;
        }
        if let Some(inode) = self.inode {
            self.capacity
                .allocator()
                .commit(inode, self.required_blocks());
        }
        self.capacity.commit_reserved_blocks(self.required_blocks());
    }

    fn release_inner(&mut self) {
        if self.resolved || self.required_blocks() == 0 {
            return;
        }
        if let Some(inode) = self.inode {
            self.capacity
                .allocator()
                .release(inode, self.required_blocks());
        }
        self.capacity
            .release_reserved_blocks(self.required_blocks());
    }
}

impl Drop for CapacityReservation {
    fn drop(&mut self) {
        if !self.resolved {
            self.release_inner();
            self.resolved = true;
        }
    }
}

/// Map allocator errors to adapter-facing POSIX errno values.
#[must_use]
pub const fn errno_for_alloc_error(error: AllocError) -> Errno {
    match error {
        AllocError::NoSpace | AllocError::QuotaExceeded => Errno::ENOSPC,
        AllocError::AlignmentViolation
        | AllocError::MisalignedOffset
        | AllocError::InvalidDeviceTopology => Errno::EINVAL,
        AllocError::Io
        | AllocError::MixedDeviceTopology
        | AllocError::DeviceNotRegistered
        | AllocError::DeviceAlreadyRegistered
        | AllocError::AlignmentImpossible => Errno::EIO,
    }
}

/// Round a byte count up to allocator blocks.
///
/// Returns `EIO` for a zero block size because that indicates a broken runtime
/// configuration rather than caller-visible capacity exhaustion.
pub fn blocks_for_bytes(bytes: u64, block_size: u32) -> Result<u64, Errno> {
    if bytes == 0 {
        return Ok(0);
    }
    if block_size == 0 {
        return Err(Errno::EIO);
    }

    let block_size = u64::from(block_size);
    let full_blocks = bytes / block_size;
    let partial_block = u64::from(bytes % block_size != 0);
    Ok(full_blocks + partial_block)
}

/// Compute additional allocator blocks needed for a file-size transition.
pub fn growth_blocks_for_size_change(
    current_size: u64,
    requested_size: u64,
    block_size: u32,
) -> Result<u64, Errno> {
    if requested_size <= current_size {
        return Ok(0);
    }

    let current_blocks = blocks_for_bytes(current_size, block_size)?;
    let requested_blocks = blocks_for_bytes(requested_size, block_size)?;
    Ok(requested_blocks.saturating_sub(current_blocks))
}

/// Admit logical size growth against a capacity facade without mutating quota state.
pub fn admit_size_growth(
    capacity: &CapacityFacade,
    current_size: u64,
    requested_size: u64,
) -> Result<AdmissionResult, Errno> {
    let statfs = capacity.statfs();
    let required_blocks =
        growth_blocks_for_size_change(current_size, requested_size, capacity.block_size())?;

    if required_blocks > statfs.bavail {
        return Err(Errno::ENOSPC);
    }

    Ok(AdmissionResult {
        current_size,
        requested_size,
        required_blocks,
        available_blocks: statfs.bavail,
    })
}

/// Admit and reserve logical size growth for an inode.
///
/// This checks global available blocks first, then delegates quota admission to
/// the allocator's public `reserve` API. The function does not allocate blocks.
pub fn reserve_size_growth(
    capacity: &CapacityFacade,
    inode: InodeId,
    current_size: u64,
    requested_size: u64,
) -> Result<AdmissionResult, Errno> {
    let admitted = admit_size_growth(capacity, current_size, requested_size)?;
    if admitted.required_blocks == 0 {
        return Ok(admitted);
    }

    capacity
        .allocator()
        .reserve(inode, admitted.required_blocks)
        .map_err(errno_for_alloc_error)?;
    Ok(admitted)
}

/// Reserve logical size growth and return a lifecycle handle.
pub fn reserve_size_growth_lifecycle(
    capacity: &CapacityFacade,
    inode: InodeId,
    current_size: u64,
    requested_size: u64,
) -> Result<CapacityReservation, Errno> {
    let admitted = reserve_size_growth(capacity, inode, current_size, requested_size)?;
    Ok(CapacityReservation::new(capacity, Some(inode), admitted))
}

/// Admit a fixed metadata reservation measured in bytes.
pub fn admit_metadata_reservation(
    capacity: &CapacityFacade,
    metadata_bytes: u64,
) -> Result<AdmissionResult, Errno> {
    let statfs = capacity.statfs();
    let required_blocks = blocks_for_bytes(metadata_bytes, capacity.block_size())?;

    if required_blocks > statfs.bavail {
        return Err(Errno::ENOSPC);
    }

    Ok(AdmissionResult {
        current_size: 0,
        requested_size: metadata_bytes,
        required_blocks,
        available_blocks: statfs.bavail,
    })
}

/// Reserve fixed metadata growth and return a lifecycle handle.
pub fn reserve_metadata_reservation(
    capacity: &CapacityFacade,
    metadata_bytes: u64,
) -> Result<CapacityReservation, Errno> {
    let admitted = admit_metadata_reservation(capacity, metadata_bytes)?;
    Ok(CapacityReservation::new(capacity, None, admitted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_block_allocator::{BlockAllocator, Region};

    fn allocator(blocks: u64) -> BlockAllocator {
        BlockAllocator::new(
            blocks,
            4096,
            Region::new(0, BlockAllocator::required_bitmap_bytes(blocks)),
        )
    }

    fn facade(blocks: u64) -> CapacityFacade {
        CapacityFacade::new(allocator(blocks))
    }

    #[test]
    fn bytes_to_blocks_rounds_zero_and_boundaries() {
        assert_eq!(blocks_for_bytes(0, 4096), Ok(0));
        assert_eq!(blocks_for_bytes(1, 4096), Ok(1));
        assert_eq!(blocks_for_bytes(4096, 4096), Ok(1));
        assert_eq!(blocks_for_bytes(4097, 4096), Ok(2));
    }

    #[test]
    fn bytes_to_blocks_handles_large_values_without_overflow() {
        assert_eq!(blocks_for_bytes(u64::MAX, 4096), Ok((u64::MAX / 4096) + 1));
    }

    #[test]
    fn zero_block_size_maps_to_eio() {
        assert_eq!(blocks_for_bytes(1, 0), Err(Errno::EIO));
    }

    #[test]
    fn growth_blocks_only_count_new_rounded_blocks() {
        assert_eq!(growth_blocks_for_size_change(0, 0, 4096), Ok(0));
        assert_eq!(growth_blocks_for_size_change(1, 4096, 4096), Ok(0));
        assert_eq!(growth_blocks_for_size_change(4096, 4097, 4096), Ok(1));
        assert_eq!(growth_blocks_for_size_change(9000, 1000, 4096), Ok(0));
    }

    #[test]
    fn admits_growth_when_available() {
        let capacity = facade(8);
        let admitted = admit_size_growth(&capacity, 0, 8192).unwrap();
        assert_eq!(admitted.required_blocks, 2);
        assert_eq!(admitted.available_blocks, 8);
    }

    #[test]
    fn admitted_size_growth_preserves_transition_fields() {
        let capacity = facade(8);
        let admitted = admit_size_growth(&capacity, 1024, 8193).unwrap();

        assert_eq!(
            admitted,
            AdmissionResult {
                current_size: 1024,
                requested_size: 8193,
                required_blocks: 2,
                available_blocks: 8,
            }
        );
        assert_eq!(capacity.reserved_blocks(), 0);
        assert_eq!(capacity.committed_blocks(), 0);
        assert_eq!(capacity.statfs().bavail, 8);
    }

    #[test]
    fn statfs_counts_partial_size_growth_as_full_blocks() {
        let capacity = facade(3);
        let inode = InodeId::new(7);
        let reservation =
            reserve_size_growth_lifecycle(&capacity, inode, 0, 4097).expect("reserve");

        assert_eq!(reservation.required_blocks(), 2);
        let reserved = capacity.statfs();
        assert_eq!(reserved.blocks, 3);
        assert_eq!(reserved.bfree, 1);
        assert_eq!(reserved.bavail, 1);
        assert_eq!(
            admit_metadata_reservation(&capacity, 4097),
            Err(Errno::ENOSPC)
        );

        reservation.release();
        let released = capacity.statfs();
        assert_eq!(released.bfree, 3);
        assert_eq!(released.bavail, 3);
    }

    #[test]
    fn denied_capacity_maps_to_enospc() {
        let capacity = facade(2);
        assert_eq!(admit_size_growth(&capacity, 0, 12288), Err(Errno::ENOSPC));
    }

    #[test]
    fn quota_denied_reservation_maps_to_enospc() {
        let alloc = allocator(8);
        let inode = InodeId::new(7);
        alloc.set_quota_limit(inode, 1);
        let capacity = CapacityFacade::new(alloc);

        assert_eq!(
            reserve_size_growth(&capacity, inode, 0, 8192),
            Err(Errno::ENOSPC)
        );
    }

    #[test]
    fn lifecycle_reserve_commit_moves_blocks_to_committed() {
        let capacity = facade(8);
        let inode = InodeId::new(7);
        let reservation =
            reserve_size_growth_lifecycle(&capacity, inode, 0, 8192).expect("reserve");

        assert_eq!(reservation.required_blocks(), 2);
        assert_eq!(capacity.reserved_blocks(), 2);
        assert_eq!(capacity.statfs().bavail, 6);
        assert_eq!(capacity.allocator().quota_counts(inode), (2, 0));

        reservation.commit();
        assert_eq!(capacity.reserved_blocks(), 0);
        assert_eq!(capacity.committed_blocks(), 2);
        assert_eq!(capacity.statfs().bavail, 6);
        assert_eq!(capacity.allocator().quota_counts(inode), (0, 2));
    }

    #[test]
    fn zero_growth_lifecycle_is_noop_for_commit_and_release() {
        let capacity = facade(8);
        let inode = InodeId::new(7);

        let commit_reservation =
            reserve_size_growth_lifecycle(&capacity, inode, 4096, 4096).expect("reserve");
        assert_eq!(commit_reservation.required_blocks(), 0);
        assert_eq!(
            commit_reservation.admitted(),
            AdmissionResult {
                current_size: 4096,
                requested_size: 4096,
                required_blocks: 0,
                available_blocks: 8,
            }
        );
        assert_eq!(capacity.reserved_blocks(), 0);
        assert_eq!(capacity.committed_blocks(), 0);
        assert_eq!(capacity.allocator().quota_counts(inode), (0, 0));

        commit_reservation.commit();
        assert_eq!(capacity.reserved_blocks(), 0);
        assert_eq!(capacity.committed_blocks(), 0);
        assert_eq!(capacity.statfs().bavail, 8);
        assert_eq!(capacity.allocator().quota_counts(inode), (0, 0));

        let release_reservation =
            reserve_size_growth_lifecycle(&capacity, inode, 8192, 4096).expect("reserve");
        assert_eq!(release_reservation.required_blocks(), 0);

        release_reservation.release();
        assert_eq!(capacity.reserved_blocks(), 0);
        assert_eq!(capacity.committed_blocks(), 0);
        assert_eq!(capacity.statfs().bavail, 8);
        assert_eq!(capacity.allocator().quota_counts(inode), (0, 0));
    }

    #[test]
    fn committed_over_release_does_not_inflate_capacity_or_block_reuse() {
        let capacity = facade(4);
        let inode = InodeId::new(7);
        let reservation =
            reserve_size_growth_lifecycle(&capacity, inode, 0, 8192).expect("reserve");
        reservation.commit();

        let committed = capacity.statfs();
        assert_eq!(capacity.reserved_blocks(), 0);
        assert_eq!(capacity.committed_blocks(), 2);
        assert_eq!(committed.bfree, 2);
        assert_eq!(committed.bavail, 2);

        let over_release = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            capacity.release_committed_blocks(3);
        }));
        assert!(over_release.is_err());
        assert_eq!(capacity.reserved_blocks(), 0);
        assert_eq!(capacity.committed_blocks(), 2);
        assert_eq!(capacity.statfs(), committed);

        let later_inode = InodeId::new(8);
        let later_reservation =
            reserve_size_growth_lifecycle(&capacity, later_inode, 0, 4096).expect("reserve");
        assert_eq!(capacity.reserved_blocks(), 1);
        assert_eq!(capacity.committed_blocks(), 2);
        assert_eq!(capacity.statfs().bavail, 1);
        assert_eq!(capacity.allocator().quota_counts(later_inode), (1, 0));

        later_reservation.release();
        assert_eq!(capacity.reserved_blocks(), 0);
        assert_eq!(capacity.committed_blocks(), 2);
        assert_eq!(capacity.statfs(), committed);
    }

    #[test]
    fn lifecycle_reserve_release_restores_capacity() {
        let capacity = facade(8);
        let inode = InodeId::new(7);
        let reservation =
            reserve_size_growth_lifecycle(&capacity, inode, 0, 8192).expect("reserve");

        reservation.release();
        assert_eq!(capacity.reserved_blocks(), 0);
        assert_eq!(capacity.committed_blocks(), 0);
        assert_eq!(capacity.statfs().bavail, 8);
        assert_eq!(capacity.allocator().quota_counts(inode), (0, 0));
    }

    #[test]
    fn lifecycle_drop_releases_unresolved_reservation() {
        let capacity = facade(8);
        let inode = InodeId::new(7);
        {
            let _reservation =
                reserve_size_growth_lifecycle(&capacity, inode, 0, 4096).expect("reserve");
            assert_eq!(capacity.reserved_blocks(), 1);
            assert_eq!(capacity.statfs().bavail, 7);
        }

        assert_eq!(capacity.reserved_blocks(), 0);
        assert_eq!(capacity.statfs().bavail, 8);
        assert_eq!(capacity.allocator().quota_counts(inode), (0, 0));
    }

    #[test]
    fn errno_nospace_and_quota_exceeded_map_to_enospc() {
        assert_eq!(errno_for_alloc_error(AllocError::NoSpace), Errno::ENOSPC);
        assert_eq!(
            errno_for_alloc_error(AllocError::QuotaExceeded),
            Errno::ENOSPC
        );
    }

    #[test]
    fn errno_alignment_and_invalid_topology_map_to_einval() {
        assert_eq!(
            errno_for_alloc_error(AllocError::AlignmentViolation),
            Errno::EINVAL
        );
        assert_eq!(
            errno_for_alloc_error(AllocError::MisalignedOffset),
            Errno::EINVAL
        );
        assert_eq!(
            errno_for_alloc_error(AllocError::InvalidDeviceTopology),
            Errno::EINVAL
        );
    }

    #[test]
    fn errno_device_and_io_variants_map_to_eio() {
        assert_eq!(errno_for_alloc_error(AllocError::Io), Errno::EIO);
        assert_eq!(
            errno_for_alloc_error(AllocError::MixedDeviceTopology),
            Errno::EIO
        );
        assert_eq!(
            errno_for_alloc_error(AllocError::DeviceNotRegistered),
            Errno::EIO
        );
        assert_eq!(
            errno_for_alloc_error(AllocError::DeviceAlreadyRegistered),
            Errno::EIO
        );
        assert_eq!(
            errno_for_alloc_error(AllocError::AlignmentImpossible),
            Errno::EIO
        );
    }

    #[test]
    fn metadata_reservation_uses_same_rounding() {
        let capacity = facade(8);
        let admitted = admit_metadata_reservation(&capacity, 4097).unwrap();
        assert_eq!(admitted.required_blocks, 2);
        assert_eq!(admitted.available_blocks, 8);
    }

    #[test]
    fn metadata_lifecycle_reserve_commit_tracks_without_inode_quota() {
        let capacity = facade(8);
        let reservation = reserve_metadata_reservation(&capacity, 4097).expect("reserve metadata");

        assert_eq!(reservation.required_blocks(), 2);
        assert_eq!(capacity.reserved_blocks(), 2);
        assert_eq!(capacity.statfs().bavail, 6);

        reservation.commit();
        assert_eq!(capacity.reserved_blocks(), 0);
        assert_eq!(capacity.committed_blocks(), 2);
        assert_eq!(capacity.statfs().bavail, 6);
    }

    #[test]
    fn metadata_lifecycle_release_restores_capacity_without_inode_quota() {
        let capacity = facade(8);
        let unrelated_inode = InodeId::new(7);
        let reservation = reserve_metadata_reservation(&capacity, 4097).expect("reserve metadata");

        assert_eq!(reservation.required_blocks(), 2);
        assert_eq!(capacity.reserved_blocks(), 2);
        assert_eq!(capacity.committed_blocks(), 0);
        assert_eq!(capacity.statfs().bavail, 6);
        assert_eq!(capacity.allocator().quota_counts(unrelated_inode), (0, 0));

        reservation.release();
        assert_eq!(capacity.reserved_blocks(), 0);
        assert_eq!(capacity.committed_blocks(), 0);
        assert_eq!(capacity.statfs().bavail, 8);
        assert_eq!(capacity.allocator().quota_counts(unrelated_inode), (0, 0));
    }

    #[test]
    fn metadata_lifecycle_drop_releases_unresolved_reservation() {
        let capacity = facade(8);
        {
            let _reservation =
                reserve_metadata_reservation(&capacity, 4097).expect("reserve metadata");
            assert_eq!(capacity.reserved_blocks(), 2);
            assert_eq!(capacity.statfs().bavail, 6);
        }

        assert_eq!(capacity.reserved_blocks(), 0);
        assert_eq!(capacity.committed_blocks(), 0);
        assert_eq!(capacity.statfs().bavail, 8);
    }

    // ── Drop-after-commit does not leak a second release ───────────────

    #[test]
    fn drop_after_commit_does_not_double_release() {
        let capacity = facade(8);
        let inode = InodeId::new(1);
        let reservation =
            reserve_size_growth_lifecycle(&capacity, inode, 0, 4096).expect("reserve");
        assert_eq!(capacity.reserved_blocks(), 1);

        reservation.commit();
        assert_eq!(capacity.reserved_blocks(), 0);
        assert_eq!(capacity.committed_blocks(), 1);

        // Create a second reservation, commit it, then drop — must not
        // release already-committed blocks.
        let r2 = reserve_size_growth_lifecycle(&capacity, inode, 4096, 8192).expect("reserve");
        assert_eq!(capacity.reserved_blocks(), 1);
        r2.commit();
        assert_eq!(capacity.reserved_blocks(), 0);
        assert_eq!(capacity.committed_blocks(), 2);

        // Create a reservation and let it drop without commit — only the
        // reserved (not the committed) blocks should be released.
        {
            let _r3 =
                reserve_size_growth_lifecycle(&capacity, inode, 8192, 12288).expect("reserve");
            assert_eq!(capacity.reserved_blocks(), 1);
        }
        // Drop released the 1 reserved block; committed blocks unchanged.
        assert_eq!(capacity.reserved_blocks(), 0);
        assert_eq!(capacity.committed_blocks(), 2);
        assert_eq!(capacity.statfs().bavail, 6); // 8 - 2 committed
    }

    // ── Drop-after-release is harmless (resolved guard) ─────────────────

    #[test]
    fn drop_after_release_does_not_double_release() {
        let capacity = facade(8);
        let inode = InodeId::new(2);

        // Reserve, release, then drop a second reservation to confirm
        // `release` sets resolved=true and Drop does not double-release.
        let r1 = reserve_size_growth_lifecycle(&capacity, inode, 0, 4096).expect("reserve");
        assert_eq!(capacity.reserved_blocks(), 1);
        r1.release();
        assert_eq!(capacity.reserved_blocks(), 0);
        assert_eq!(capacity.statfs().bavail, 8);

        // Now reserve again, commit the second one, and make sure the
        // first release didn't corrupt state.
        let r2 = reserve_size_growth_lifecycle(&capacity, inode, 0, 8192).expect("reserve");
        assert_eq!(capacity.reserved_blocks(), 2);
        r2.commit();
        assert_eq!(capacity.reserved_blocks(), 0);
        assert_eq!(capacity.committed_blocks(), 2);
        assert_eq!(capacity.statfs().bavail, 6);
    }

    // ── errno_for_alloc_error: every variant returns expected errno ─────

    #[test]
    fn errno_for_alloc_error_all_variants() {
        use tidefs_block_allocator::AllocError;
        // ENOSPC group
        assert_eq!(errno_for_alloc_error(AllocError::NoSpace), Errno::ENOSPC);
        assert_eq!(
            errno_for_alloc_error(AllocError::QuotaExceeded),
            Errno::ENOSPC
        );
        // EINVAL group
        assert_eq!(
            errno_for_alloc_error(AllocError::AlignmentViolation),
            Errno::EINVAL
        );
        assert_eq!(
            errno_for_alloc_error(AllocError::MisalignedOffset),
            Errno::EINVAL
        );
        assert_eq!(
            errno_for_alloc_error(AllocError::InvalidDeviceTopology),
            Errno::EINVAL
        );
        // EIO group
        assert_eq!(errno_for_alloc_error(AllocError::Io), Errno::EIO);
        assert_eq!(
            errno_for_alloc_error(AllocError::MixedDeviceTopology),
            Errno::EIO
        );
        assert_eq!(
            errno_for_alloc_error(AllocError::DeviceNotRegistered),
            Errno::EIO
        );
        assert_eq!(
            errno_for_alloc_error(AllocError::DeviceAlreadyRegistered),
            Errno::EIO
        );
        assert_eq!(
            errno_for_alloc_error(AllocError::AlignmentImpossible),
            Errno::EIO
        );
    }

    // ── blocks_for_bytes with non-4096 block sizes ──────────────────────

    #[test]
    fn blocks_for_bytes_various_block_sizes() {
        // 512-byte blocks
        assert_eq!(blocks_for_bytes(0, 512), Ok(0));
        assert_eq!(blocks_for_bytes(1, 512), Ok(1));
        assert_eq!(blocks_for_bytes(512, 512), Ok(1));
        assert_eq!(blocks_for_bytes(513, 512), Ok(2));
        // 1024-byte blocks
        assert_eq!(blocks_for_bytes(1024, 1024), Ok(1));
        assert_eq!(blocks_for_bytes(1025, 1024), Ok(2));
        // 8192-byte blocks
        assert_eq!(blocks_for_bytes(8192, 8192), Ok(1));
        assert_eq!(blocks_for_bytes(8193, 8192), Ok(2));
        // Large value at 512-byte granularity
        assert_eq!(blocks_for_bytes(1_048_576, 512), Ok(1_048_576 / 512));
    }

    // ── growth_blocks_for_size_change matches manual computation ────────

    #[test]
    fn growth_blocks_round_trips_through_blocks_for_bytes() {
        let bs: u32 = 4096;
        let cases: &[(u64, u64)] = &[
            (0, 4096),
            (4096, 8192),
            (0, 1),
            (1, 4097),
            (4095, 4096),
            (4096, 12288),
            (0, 0),
        ];
        for &(current, requested) in cases {
            let growth = growth_blocks_for_size_change(current, requested, bs).unwrap();
            let cur_blocks = blocks_for_bytes(current, bs).unwrap();
            let req_blocks = blocks_for_bytes(requested, bs).unwrap();
            assert_eq!(
                growth,
                req_blocks.saturating_sub(cur_blocks),
                "growth_blocks_for_size_change({current}, {requested}, {bs})"
            );
        }
    }

    // ── AdmissionResult preserved inside CapacityReservation ────────────

    #[test]
    fn admission_result_preserved_in_reservation() {
        let capacity = facade(16);
        let inode = InodeId::new(42);
        let admitted = admit_size_growth(&capacity, 1024, 5120).expect("admit");
        let reservation =
            reserve_size_growth_lifecycle(&capacity, inode, 1024, 5120).expect("reserve");

        assert_eq!(reservation.admitted(), admitted);
        assert_eq!(reservation.required_blocks(), admitted.required_blocks);
        assert_eq!(reservation.admitted().current_size, 1024);
        assert_eq!(reservation.admitted().requested_size, 5120);
    }

    // ── Zero-byte blocks_for_bytes invariant ────────────────────────────

    #[test]
    fn zero_bytes_blocks_for_bytes_any_block_size() {
        for bs in [512_u32, 1024, 2048, 4096, 8192, 65536] {
            assert_eq!(
                blocks_for_bytes(0, bs),
                Ok(0),
                "blocks_for_bytes(0, {bs}) must be 0"
            );
        }
        // Zero block size with zero bytes: no error (early return).
        assert_eq!(blocks_for_bytes(0, 0), Ok(0));
    }

    // ── Metadata reservation drop-after-commit idempotency ──────────────

    #[test]
    fn metadata_drop_after_commit_does_not_release() {
        let capacity = facade(8);
        let r = reserve_metadata_reservation(&capacity, 8192).expect("reserve metadata");
        assert_eq!(capacity.reserved_blocks(), 2);

        r.commit();
        assert_eq!(capacity.reserved_blocks(), 0);
        assert_eq!(capacity.committed_blocks(), 2);
    }

    // ── Zero-delta admit returns zero required blocks ───────────────────

    #[test]
    fn admit_size_growth_zero_delta_returns_zero_blocks() {
        let capacity = facade(8);
        let result = admit_size_growth(&capacity, 4096, 4096).unwrap();
        assert_eq!(result.required_blocks, 0);
        assert_eq!(result.current_size, 4096);
        assert_eq!(result.requested_size, 4096);
        assert_eq!(result.available_blocks, 8);
    }

    // ── Reservation accessor matches original admission ─────────────────

    #[test]
    fn reservation_admitted_accessor_matches_original() {
        let capacity = facade(16);
        let inode = InodeId::new(99);
        let reservation =
            reserve_size_growth_lifecycle(&capacity, inode, 0, 16384).expect("reserve");

        let a = reservation.admitted();
        assert_eq!(a.current_size, 0);
        assert_eq!(a.requested_size, 16384);
        assert_eq!(a.required_blocks, 4);
        assert_eq!(a.available_blocks, 16);
        // required_blocks() accessor matches admitted.required_blocks
        assert_eq!(reservation.required_blocks(), a.required_blocks);
    }

    #[test]
    fn cross_inode_commit_and_release_are_independent() {
        let capacity = facade(8);
        let inode_a = InodeId::new(7);
        let inode_b = InodeId::new(8);

        let r_a = reserve_size_growth_lifecycle(&capacity, inode_a, 0, 4096).expect("r_a");
        assert_eq!(r_a.required_blocks(), 1);
        r_a.commit();
        assert_eq!(capacity.committed_blocks(), 1);

        let r_b = reserve_size_growth_lifecycle(&capacity, inode_b, 0, 12288).expect("r_b");
        assert_eq!(r_b.required_blocks(), 3);
        assert_eq!(capacity.reserved_blocks(), 3);
        assert_eq!(capacity.committed_blocks(), 1);
        assert_eq!(capacity.allocator().quota_counts(inode_a), (0, 1));
        assert_eq!(capacity.allocator().quota_counts(inode_b), (3, 0));

        r_b.release();
        assert_eq!(capacity.reserved_blocks(), 0);
        assert_eq!(capacity.committed_blocks(), 1);
        assert_eq!(capacity.allocator().quota_counts(inode_b), (0, 0));
        assert_eq!(capacity.allocator().quota_counts(inode_a), (0, 1));
    }

    #[test]
    fn zero_delta_admit_size_growth_preserves_input_sizes() {
        let capacity = facade(8);
        let result = admit_size_growth(&capacity, 4096, 4096).expect("zero delta");
        assert_eq!(result.current_size, 4096);
        assert_eq!(result.requested_size, 4096);
        assert_eq!(result.required_blocks, 0);
        assert_eq!(result.available_blocks, 8);
    }

    #[test]
    fn growth_blocks_for_size_change_no_change_returns_zero() {
        assert_eq!(growth_blocks_for_size_change(4096, 4096, 4096), Ok(0));
        assert_eq!(growth_blocks_for_size_change(0, 0, 4096), Ok(0));
        assert_eq!(growth_blocks_for_size_change(8192, 0, 4096), Ok(0));
    }

    #[test]
    fn metadata_zero_bytes_admits_zero_blocks() {
        let capacity = facade(8);
        let result = admit_metadata_reservation(&capacity, 0).expect("zero metadata");
        assert_eq!(result.required_blocks, 0);
        assert_eq!(result.requested_size, 0);
        assert_eq!(result.available_blocks, 8);
    }
}
