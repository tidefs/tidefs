// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Commit-group fenced allocation tests.

use tidefs_block_allocator::{
    AllocError, BlockAllocator, CommitGroupEpochFence, CommitGroupId, Region,
};

fn region(block_count: u64) -> Region {
    Region::new(0, BlockAllocator::required_bitmap_bytes(block_count))
}

fn fence(n: u64) -> CommitGroupEpochFence {
    CommitGroupEpochFence::new(n, CommitGroupId(n))
}

#[test]
fn allocation_reservation_is_fenced_by_commit_group_epoch() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    let first = fence(1);
    let second = fence(2);

    let reservation = ba.reserve_allocation(first, 8).unwrap();
    assert_eq!(reservation.epoch_fence(), first);
    assert_eq!(reservation.len(), 8);
    assert_eq!(ba.pending_allocation_count(), 8);
    assert_eq!(ba.free_count(), 56);

    ba.free(reservation.blocks());
    assert_eq!(ba.pending_allocation_count(), 8);
    assert_eq!(ba.free_count(), 56);

    let competing = ba.reserve_allocation(second, 56).unwrap();
    assert!(competing
        .blocks()
        .iter()
        .all(|block| !reservation.blocks().contains(block)));
    assert_eq!(
        ba.reserve_allocation(second, 1).unwrap_err(),
        AllocError::NoSpace
    );

    let delta = ba.mark_commit_group_durable(first).unwrap();
    assert_eq!(delta.allocations, 8);
    assert_eq!(delta.frees, 0);
    assert_eq!(ba.pending_allocation_count(), 56);

    let delta = ba.abort_commit_group(second).unwrap();
    assert_eq!(delta.allocations, 56);
    assert_eq!(ba.free_count(), 56);
}

#[test]
fn block_reuse_is_blocked_until_freeing_commit_group_is_durable() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    let freeing_epoch = fence(10);
    let next_epoch = fence(11);

    let original = ba.alloc_contiguous(1).unwrap();
    let pending_free = ba.free_on_commit(freeing_epoch, &original).unwrap();
    assert_eq!(pending_free.blocks(), original.as_slice());
    assert_eq!(ba.pending_free_count(), 1);
    assert_eq!(ba.free_count(), 63);

    let all_other_blocks = ba.reserve_allocation(next_epoch, 63).unwrap();
    assert!(all_other_blocks
        .blocks()
        .iter()
        .all(|block| !original.contains(block)));
    assert_eq!(
        ba.reserve_allocation(next_epoch, 1).unwrap_err(),
        AllocError::NoSpace
    );

    let delta = ba.mark_commit_group_durable(freeing_epoch).unwrap();
    assert_eq!(delta.frees, 1);
    assert_eq!(ba.pending_free_count(), 0);
    assert_eq!(ba.free_count(), 1);

    let reused = ba.reserve_allocation(next_epoch, 1).unwrap();
    assert_eq!(reused.blocks(), original.as_slice());
}

#[test]
fn pending_free_space_is_reported_only_after_commit_group_durability() {
    let ba = BlockAllocator::new(128, 4096, region(128));
    let epoch = fence(20);
    let blocks = ba.alloc_any(12).unwrap();

    let before = ba.allocator_statfs();
    assert_eq!(before.f_bfree, 116);

    let pending = ba.free_on_commit(epoch, &blocks).unwrap();
    assert_eq!(pending.len(), 12);
    let while_pending = ba.allocator_statfs();
    assert_eq!(while_pending.f_bfree, 116);
    assert_eq!(while_pending.f_bavail, 116);
    assert_eq!(ba.free_count(), 116);

    let delta = ba.mark_commit_group_durable(epoch).unwrap();
    assert_eq!(delta.frees, 12);
    let after = ba.allocator_statfs();
    assert_eq!(after.f_bfree, 128);
    assert_eq!(after.f_bavail, 128);
}

#[test]
fn abort_releases_allocations_and_cancels_pending_frees() {
    let ba = BlockAllocator::new(32, 4096, region(32));
    let epoch = fence(30);

    let committed = ba.alloc_contiguous(4).unwrap();
    let pending_alloc = ba.reserve_allocation(epoch, 6).unwrap();
    let pending_free = ba.free_on_commit(epoch, &committed).unwrap();
    assert_eq!(pending_alloc.len(), 6);
    assert_eq!(pending_free.len(), 4);
    assert_eq!(ba.free_count(), 22);

    let delta = ba.abort_commit_group(epoch).unwrap();
    assert_eq!(delta.allocations, 6);
    assert_eq!(delta.frees, 4);
    assert_eq!(ba.pending_allocation_count(), 0);
    assert_eq!(ba.pending_free_count(), 0);

    assert_eq!(ba.free_count(), 28);
    let still_used = ba.reserve_allocation(fence(31), 28).unwrap();
    assert!(still_used
        .blocks()
        .iter()
        .all(|block| !committed.contains(block)));
}

#[test]
fn pending_free_conflict_leaves_prior_state_recoverable() {
    let ba = BlockAllocator::new(16, 4096, region(16));
    let first_epoch = fence(40);
    let second_epoch = fence(41);

    let in_flight = ba.reserve_allocation(first_epoch, 1).unwrap();
    let committed = ba.alloc_contiguous(1).unwrap();
    assert_eq!(ba.free_count(), 14);

    assert_eq!(
        ba.free_on_commit(second_epoch, &[committed[0], in_flight.blocks()[0]])
            .unwrap_err(),
        AllocError::CommitGroupConflict
    );
    assert_eq!(ba.pending_free_count(), 0);

    ba.free(&committed);
    assert_eq!(ba.free_count(), 15);

    let delta = ba.abort_commit_group(first_epoch).unwrap();
    assert_eq!(delta.allocations, 1);
    assert_eq!(delta.frees, 0);
    assert_eq!(ba.free_count(), 16);
}

#[test]
fn pending_free_owner_blocks_other_commit_groups() {
    let ba = BlockAllocator::new(16, 4096, region(16));
    let first_epoch = fence(50);
    let second_epoch = fence(51);

    let block = ba.alloc_contiguous(1).unwrap();
    let first = ba.free_on_commit(first_epoch, &block).unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(ba.pending_free_count(), 1);

    assert_eq!(
        ba.free_on_commit(second_epoch, &block).unwrap_err(),
        AllocError::CommitGroupConflict
    );
    assert_eq!(ba.pending_free_count(), 1);

    let delta = ba.mark_commit_group_durable(first_epoch).unwrap();
    assert_eq!(delta.frees, 1);
    assert_eq!(ba.free_count(), 16);
}

#[test]
fn release_allocation_cancels_matching_pending_free() {
    let ba = BlockAllocator::new(8, 4096, region(8));
    let epoch = fence(60);
    let next_epoch = fence(61);

    let reservation = ba.reserve_allocation(epoch, 1).unwrap();
    let block = reservation.blocks()[0];
    let pending_free = ba.free_on_commit(epoch, &[block]).unwrap();
    assert_eq!(pending_free.len(), 1);
    assert_eq!(ba.pending_allocation_count(), 1);
    assert_eq!(ba.pending_free_count(), 1);

    let delta = ba.release_allocation(reservation).unwrap();
    assert_eq!(delta.allocations, 1);
    assert_eq!(delta.frees, 1);
    assert_eq!(ba.pending_allocation_count(), 0);
    assert_eq!(ba.pending_free_count(), 0);
    assert_eq!(ba.free_count(), 8);

    let all_blocks = ba.reserve_allocation(next_epoch, 8).unwrap();
    assert!(all_blocks.blocks().contains(&block));
    let durable = ba.mark_commit_group_durable(epoch).unwrap();
    assert_eq!(durable.allocations, 0);
    assert_eq!(durable.frees, 0);
    assert_eq!(ba.free_count(), 0);
}
