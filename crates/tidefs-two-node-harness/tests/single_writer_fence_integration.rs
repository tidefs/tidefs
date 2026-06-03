//! Two-node harness integration test for single-writer fencing across
//! membership transitions and partitions.
//!
//! ## Scenario
//!
//! Node 1 acts as the active writer holding a lease. After a simulated
//! partition (Node 1 becomes minority-side), the single-writer fence
//! rejects Node 1's writes and Node 2 can become the new writer.
//! After the partition heals, Node 1's stale-writer attempts are
//! rejected until it catches up with the new epoch.
//!
//! ## Validation
//!
//! Exercises the SingleWriterFence integration of SplitBrainGuard,
//! MembershipEpochFence, and FencingWatchdog to prove:
//! 1. Connected state: single writer accepted
//! 2. Minority side: single writer fenced
//! 3. Epoch transition: stale writer rejected
//! 4. Liveness fence: individually fenced writer rejected

use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_membership_live::epoch_coordinator::EpochView;
use tidefs_membership_live::epoch_fence::MembershipEpochFence;
use tidefs_membership_live::fencing_watchdog::FencingWatchdog;
use tidefs_partition_runtime::single_writer_fence::SingleWriterFence;
use tidefs_partition_runtime::split_brain_guard::SplitBrainGuard;
use tidefs_partition_runtime::types::{PartitionFence, PartitionState};

fn mid(id: u64) -> MemberId {
    MemberId::new(id)
}

fn make_connected_fence(writer_id: u64, epoch: u64, roster: &[u64]) -> SingleWriterFence {
    let guard = SplitBrainGuard::new(mid(writer_id), EpochId::new(epoch), 2);
    let epoch_fence = MembershipEpochFence::new();

    let view = EpochView::new(
        EpochId::new(epoch),
        roster.iter().map(|n| MemberId::new(*n)).collect(),
        1000,
    );
    epoch_fence.update_from_view(&view);

    let watchdog = FencingWatchdog::new();

    SingleWriterFence::new(guard, epoch_fence, watchdog, mid(writer_id))
}

// -----------------------------------------------------------------------
// Test 1: Connected cluster accepts single writer
// -----------------------------------------------------------------------

#[test]
fn connected_cluster_accepts_single_writer() {
    let mut fence = make_connected_fence(1, 1, &[1, 2, 3]);

    assert!(fence.evaluate());
    assert!(fence.can_accept_writes());
    assert!(!fence.is_fenced());
    assert!(fence.can_grant_leases());
    assert!(fence.can_commit_publications());
    assert!(fence.can_mint_receipts());
}

// -----------------------------------------------------------------------
// Test 2: Stale writer rejected after roster removal (membership transition)
// -----------------------------------------------------------------------

#[test]
fn stale_writer_rejected_after_roster_removal() {
    let mut fence = make_connected_fence(2, 1, &[1, 2, 3]);

    // Writer is initially accepted.
    assert!(fence.evaluate());
    assert!(fence.can_accept_writes());

    // Simulate a membership transition: writer 2 is evicted.
    let new_view = EpochView::new(EpochId::new(2), vec![mid(1), mid(3)], 2000);
    fence.epoch_fence().update_from_view(&new_view);

    // Writer 2 is now stale.
    assert!(!fence.evaluate());
    assert!(fence.is_fenced());
    assert!(!fence.can_accept_writes());
    assert!(!fence.can_grant_leases());
    assert!(fence.fenced_since().is_some());
}

// -----------------------------------------------------------------------
// Test 3: Minority-side writer is fenced during partition
// -----------------------------------------------------------------------

#[test]
fn minority_side_writer_is_fenced() {
    let mut fence = make_connected_fence(1, 1, &[1, 2, 3, 4]);

    // Initially accepted.
    assert!(fence.evaluate());
    assert!(fence.can_accept_writes());

    // Simulate partition: nodes 1+2 minority, nodes 3+4 have quorum.
    fence.guard_mut().partition_state = PartitionState::MinorityFenced {
        quorum_side_voter_count: 2,
        since_millis: 100,
    };
    fence.guard_mut().fence = PartitionFence::raise_all();

    assert!(!fence.evaluate());
    assert!(fence.is_fenced());
    assert!(!fence.can_accept_writes());
    assert!(!fence.can_grant_leases());
    assert!(!fence.can_commit_publications());
    assert!(!fence.can_mint_receipts());
    assert!(!fence.authority_homes_valid());
}

// -----------------------------------------------------------------------
// Test 4: Quorum-side writer continues writing during partition
// -----------------------------------------------------------------------

#[test]
fn quorum_side_writer_continues_writing() {
    let mut fence = make_connected_fence(2, 1, &[1, 2, 3, 4]);

    fence.guard_mut().partition_state = PartitionState::QuorumSideActive {
        minority_members: vec![mid(1)],
        new_epoch: EpochId::new(2),
        since_millis: 100,
    };

    assert!(fence.evaluate());
    assert!(fence.can_accept_writes());
    assert!(!fence.is_fenced());
}

// -----------------------------------------------------------------------
// Test 5: Individually fenced writer (liveness watchdog) rejected
// -----------------------------------------------------------------------

#[test]
fn individually_fenced_writer_is_rejected() {
    let mut fence = make_connected_fence(1, 1, &[1, 2, 3]);

    assert!(fence.evaluate());

    // Fencing watchdog fences node 1.
    fence.watchdog_mut().manual_fence(mid(1), 1).unwrap();
    assert!(fence.watchdog().is_fenced(mid(1)));

    assert!(!fence.evaluate());
    assert!(fence.is_fenced());
    assert!(!fence.can_accept_writes());
}

// -----------------------------------------------------------------------
// Test 6: Partition heal restores write capability
// -----------------------------------------------------------------------

#[test]
fn partition_heal_restores_write_capability() {
    let mut fence = make_connected_fence(1, 1, &[1, 2, 3, 4]);

    // Fence: minority side.
    fence.guard_mut().partition_state = PartitionState::MinorityFenced {
        quorum_side_voter_count: 2,
        since_millis: 100,
    };
    fence.guard_mut().fence = PartitionFence::raise_all();
    assert!(!fence.evaluate());
    assert!(fence.is_fenced());

    // Heal.
    fence.guard_mut().partition_state = PartitionState::Connected;
    fence.guard_mut().fence = PartitionFence::default();

    assert!(fence.evaluate());
    assert!(!fence.is_fenced());
    assert!(fence.can_accept_writes());
    assert!(fence.can_grant_leases());
    assert!(fence.can_commit_publications());
    assert!(fence.authority_homes_valid());
}

// -----------------------------------------------------------------------
// Test 7: Ambiguous split rejects both sides
// -----------------------------------------------------------------------

#[test]
fn ambiguous_split_rejects_both_sides() {
    let mut fence = make_connected_fence(1, 1, &[1, 2, 3, 4]);

    fence.guard_mut().partition_state = PartitionState::AmbiguousHalted {
        sides: vec![vec![mid(1), mid(2)], vec![mid(3), mid(4)]],
        since_millis: 100,
    };

    assert!(!fence.evaluate());
    assert!(fence.is_fenced());
    assert!(!fence.can_accept_writes());
    assert!(!fence.can_grant_leases());
    assert!(!fence.can_commit_publications());
}

// -----------------------------------------------------------------------
// Test 8: Epoch transition accepts new writer, rejects stale
// -----------------------------------------------------------------------

#[test]
fn epoch_transition_accepts_new_writer_rejects_stale() {
    // Node 1 is writer in epoch 1.
    let mut fence_old = make_connected_fence(1, 1, &[1, 2, 3]);
    assert!(fence_old.evaluate());

    // Node 2 becomes writer in epoch 2.
    let mut fence_new = make_connected_fence(2, 2, &[1, 2, 3]);
    assert!(fence_new.evaluate());

    // After epoch transition, both are still in roster.
    let view2 = EpochView::new(EpochId::new(2), vec![mid(1), mid(2), mid(3)], 2000);
    fence_old.epoch_fence().update_from_view(&view2);
    assert!(fence_old.evaluate());

    // Now remove node 1 from roster at epoch 3.
    let view3 = EpochView::new(EpochId::new(3), vec![mid(2), mid(3)], 3000);
    fence_old.epoch_fence().update_from_view(&view3);
    assert!(!fence_old.evaluate());

    // Node 2 is still accepted.
    fence_new.epoch_fence().update_from_view(&view3);
    assert!(fence_new.evaluate());
}

// -----------------------------------------------------------------------
// Test 9: Fenced_since transitions through fence/heal cycles
// -----------------------------------------------------------------------

#[test]
fn fenced_since_transitions_through_cycles() {
    let mut fence = make_connected_fence(1, 1, &[1, 2, 3]);

    assert!(fence.evaluate());
    assert!(fence.fenced_since().is_none());

    // Fence by minority partition.
    fence.guard_mut().partition_state = PartitionState::MinorityFenced {
        quorum_side_voter_count: 2,
        since_millis: 100,
    };
    fence.guard_mut().fence = PartitionFence::raise_all();
    assert!(!fence.evaluate());
    let fenced_at = fence.fenced_since();
    assert!(fenced_at.is_some());

    // Heal.
    fence.guard_mut().partition_state = PartitionState::Connected;
    fence.guard_mut().fence = PartitionFence::default();
    assert!(fence.evaluate());
    assert!(fence.fenced_since().is_none());

    // Re-fence by roster removal.
    let view = EpochView::new(EpochId::new(2), vec![mid(2), mid(3)], 2000);
    fence.epoch_fence().update_from_view(&view);
    assert!(!fence.evaluate());
    let second_fenced_at = fence.fenced_since();
    assert!(second_fenced_at.is_some());
    assert!(second_fenced_at.unwrap() >= fenced_at.unwrap());
}

// -----------------------------------------------------------------------
// Test 10: Last evaluated timestamp advances
// -----------------------------------------------------------------------

#[test]
fn last_evaluated_at_advances() {
    let mut fence = make_connected_fence(1, 1, &[1, 2]);

    let t1 = fence.last_evaluated_at();
    assert!(fence.evaluate());
    let t2 = fence.last_evaluated_at();
    assert!(t2 >= t1);

    assert!(fence.evaluate());
    let t3 = fence.last_evaluated_at();
    assert!(t3 >= t2);
}
