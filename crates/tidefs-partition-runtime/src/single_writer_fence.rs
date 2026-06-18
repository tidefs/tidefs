// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! SingleWriterFence: unified write-safety guard integrating partition
//! awareness, epoch fencing, and liveness-based peer fencing.
//!
//! ## Problem
//!
//! TideFS has three independent fencing mechanisms:
//!
//! 1. SplitBrainGuard — partition-side awareness: minority-side nodes
//!    freeze writes during a split.
//! 2. MembershipEpochFence — inbound message fencing: rejects messages
//!    from peers not in the current roster or carrying stale epochs.
//! 3. FencingWatchdog — liveness-based fencing: fences unresponsive
//!    peers and validates fence tokens on rejoin.
//!
//! These three mechanisms operate independently. No single component answers
//! the question "can this writer accept writes right now?" across all three
//! dimensions.
//!
//! ## Solution
//!
//! SingleWriterFence combines the three fencing primitives into a single
//! decision point:
//!
//! - can_accept_writes() — true only when the node is on the quorum side
//!   (or fully connected), not individually fenced by the watchdog, and the
//!   epoch is current.
//! - can_grant_leases() — stricter: requires can_accept_writes + the
//!   fence's lease authority is not frozen.
//! - can_commit_publications() — requires can_accept_writes + publication
//!   path is not frozen.
//!
//! ## Integration
//!
//! The SingleWriterFence is the recommended write-safety check for any
//! code path that performs durable writes, including the FUSE daemon,
//! ublk daemon, quorum-write protocol, and kernel-mode writeback.

use crate::split_brain_guard::SplitBrainGuard;
use crate::types::{now_millis, PartitionState};
use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_membership_live::epoch_fence::MembershipEpochFence;
use tidefs_membership_live::fencing_watchdog::FencingWatchdog;

// ---------------------------------------------------------------------------
// SingleWriterFence
// ---------------------------------------------------------------------------

/// Unified single-writer fence: answers "can this writer accept writes?"
/// by integrating partition-state, epoch-fence, and liveness-fence checks.
///
/// # Decision order
///
/// 1. **Partition state** (SplitBrainGuard): if the node is on the minority
///    side of a partition or in an ambiguous halt, writes are rejected
///    immediately. This is the fastest path — no epoch or watchdog checks
///    are needed.
/// 2. **Epoch fence** (MembershipEpochFence): the writer's epoch must be
///    current. A writer carrying a stale epoch is rejected even if
///    connected.
/// 3. **Liveness fence** (FencingWatchdog): the writer must not have been
///    individually fenced by the watchdog. A fenced peer cannot write even
///    if the partition state says connected.
pub struct SingleWriterFence {
    /// The split-brain guard for partition-state awareness.
    guard: SplitBrainGuard,
    /// The membership epoch fence for roster/epoch checks.
    epoch_fence: MembershipEpochFence,
    /// The fencing watchdog for liveness-based fencing.
    watchdog: FencingWatchdog,
    /// My node ID for self-fencing checks.
    my_id: MemberId,
    /// When the fence was last evaluated.
    last_evaluated_at_millis: u64,
    /// When the fence transitioned to fenced state (for staleness tracking).
    fenced_since_millis: Option<u64>,
    /// Whether writes are currently accepted.
    writes_accepted: bool,
}

impl SingleWriterFence {
    /// Create a new single-writer fence from the three fencing primitives.
    #[must_use]
    pub fn new(
        guard: SplitBrainGuard,
        epoch_fence: MembershipEpochFence,
        watchdog: FencingWatchdog,
        my_id: MemberId,
    ) -> Self {
        let writes_accepted = guard.can_accept_writes() && !watchdog.is_fenced(my_id);

        Self {
            guard,
            epoch_fence,
            watchdog,
            my_id,
            last_evaluated_at_millis: now_millis(),
            fenced_since_millis: None,
            writes_accepted,
        }
    }

    /// Evaluate whether this writer can accept writes.
    ///
    /// Called on every tick or before a write batch. Updates internal
    /// state and returns the decision.
    #[must_use]
    pub fn evaluate(&mut self) -> bool {
        let now = now_millis();
        self.last_evaluated_at_millis = now;

        // 1. Partition state: must be connected or quorum side.
        if !self.guard.can_accept_writes() {
            self.transition_to_fenced(now);
            return false;
        }

        // 2. Epoch fence: myself must be in the current roster.
        if !self.epoch_fence.contains(self.my_id) {
            self.transition_to_fenced(now);
            return false;
        }

        // 3. Liveness fence: I must not be individually fenced.
        if self.watchdog.is_fenced(self.my_id) {
            self.transition_to_fenced(now);
            return false;
        }

        self.transition_to_unfenced(now);
        true
    }

    /// Query the current write-acceptance state without re-evaluating.
    #[must_use]
    pub fn can_accept_writes(&self) -> bool {
        self.writes_accepted
    }

    /// Whether this writer can grant leases.
    #[must_use]
    pub fn can_grant_leases(&self) -> bool {
        self.writes_accepted && self.guard.can_grant_leases()
    }

    /// Whether this writer can commit publications.
    #[must_use]
    pub fn can_commit_publications(&self) -> bool {
        self.writes_accepted && self.guard.can_commit_publications()
    }

    /// Whether this writer can mint receipts.
    #[must_use]
    pub fn can_mint_receipts(&self) -> bool {
        self.writes_accepted && self.guard.can_mint_receipts()
    }

    /// Whether authority homes are valid (not invalidated by partition).
    #[must_use]
    pub fn authority_homes_valid(&self) -> bool {
        self.guard.authority_homes_valid()
    }

    /// The epoch of the membership fence.
    #[must_use]
    pub fn fence_epoch(&self) -> EpochId {
        self.epoch_fence.current_epoch()
    }

    /// The current partition state.
    #[must_use]
    pub fn partition_state(&self) -> &PartitionState {
        &self.guard.partition_state
    }

    /// Whether this writer is currently fenced (by any mechanism).
    #[must_use]
    pub fn is_fenced(&self) -> bool {
        !self.writes_accepted
    }

    /// When the fence last transitioned to fenced state.
    #[must_use]
    pub fn fenced_since(&self) -> Option<u64> {
        self.fenced_since_millis
    }

    /// When the fence was last evaluated.
    #[must_use]
    pub fn last_evaluated_at(&self) -> u64 {
        self.last_evaluated_at_millis
    }

    /// Get a reference to the underlying SplitBrainGuard.
    #[must_use]
    pub fn guard(&self) -> &SplitBrainGuard {
        &self.guard
    }
    /// Get a mutable reference to the underlying SplitBrainGuard.
    /// For test harness manipulation of partition state.
    pub fn guard_mut(&mut self) -> &mut SplitBrainGuard {
        &mut self.guard
    }

    /// Get a reference to the underlying MembershipEpochFence.
    #[must_use]
    pub fn epoch_fence(&self) -> &MembershipEpochFence {
        &self.epoch_fence
    }

    /// Get the underlying fencing watchdog.
    #[must_use]
    pub fn watchdog(&self) -> &FencingWatchdog {
        &self.watchdog
    }

    /// Get a mutable reference to the fencing watchdog.
    pub fn watchdog_mut(&mut self) -> &mut FencingWatchdog {
        &mut self.watchdog
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn transition_to_fenced(&mut self, now: u64) {
        if self.writes_accepted {
            self.fenced_since_millis = Some(now);
        }
        self.writes_accepted = false;
    }

    fn transition_to_unfenced(&mut self, _now: u64) {
        if !self.writes_accepted {
            self.fenced_since_millis = None;
        }
        self.writes_accepted = true;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::{EpochId, MemberId};
    use tidefs_membership_live::epoch_fence::MembershipEpochFence;
    use tidefs_membership_live::fencing_watchdog::FencingWatchdog;

    fn mid(id: u64) -> MemberId {
        MemberId::new(id)
    }

    fn make_fence(writer_id: u64, epoch: u64, roster: &[u64]) -> SingleWriterFence {
        let guard = SplitBrainGuard::new(mid(writer_id), EpochId::new(epoch), 2);
        let epoch_fence = MembershipEpochFence::new();

        let view = tidefs_membership_live::epoch_coordinator::EpochView::new(
            EpochId::new(epoch),
            roster.iter().map(|n| MemberId::new(*n)).collect(),
            1000,
        );
        epoch_fence.update_from_view(&view);

        let watchdog = FencingWatchdog::new();

        SingleWriterFence::new(guard, epoch_fence, watchdog, mid(writer_id))
    }

    #[test]
    fn accepts_writes_when_connected_in_roster_not_fenced() {
        let mut fence = make_fence(1, 1, &[1, 2, 3]);
        assert!(fence.evaluate());
        assert!(fence.can_accept_writes());
        assert!(!fence.is_fenced());
        assert!(fence.fenced_since().is_none());
    }

    #[test]
    fn rejects_writes_when_minority_side() {
        let mut fence = make_fence(1, 1, &[1, 2, 3]);

        fence.guard.partition_state = PartitionState::MinorityFenced {
            quorum_side_voter_count: 3,
            since_millis: 100,
        };

        assert!(!fence.evaluate());
        assert!(!fence.can_accept_writes());
        assert!(fence.is_fenced());
        assert!(fence.fenced_since().is_some());
    }

    #[test]
    fn rejects_writes_when_ambiguous() {
        let mut fence = make_fence(1, 1, &[1, 2, 3, 4]);

        fence.guard.partition_state = PartitionState::AmbiguousHalted {
            sides: vec![vec![mid(1), mid(2)], vec![mid(3), mid(4)]],
            since_millis: 100,
        };

        assert!(!fence.evaluate());
        assert!(!fence.can_accept_writes());
    }

    #[test]
    fn rejects_writes_when_not_in_roster() {
        let mut fence = make_fence(5, 1, &[1, 2, 3]);
        assert!(!fence.evaluate());
        assert!(!fence.can_accept_writes());
        assert!(fence.is_fenced());
    }

    #[test]
    fn rejects_writes_when_individually_fenced() {
        let mut fence = make_fence(1, 1, &[1, 2, 3]);

        let token = fence.watchdog_mut().manual_fence(mid(1), 1).unwrap();
        assert!(fence.watchdog().is_fenced(mid(1)));

        assert!(!fence.evaluate());
        assert!(!fence.can_accept_writes());
        assert!(fence.is_fenced());

        fence.watchdog_mut().clear_fence(mid(1), token).unwrap();
        assert!(!fence.watchdog().is_fenced(mid(1)));

        assert!(fence.evaluate());
        assert!(fence.can_accept_writes());
    }

    #[test]
    fn fenced_since_tracks_transition_timing() {
        let mut fence = make_fence(2, 1, &[1, 2, 3]);
        assert!(fence.evaluate());
        assert!(fence.fenced_since().is_none());

        let new_view = tidefs_membership_live::epoch_coordinator::EpochView::new(
            EpochId::new(1),
            vec![mid(1), mid(3)],
            2000,
        );
        fence.epoch_fence.update_from_view(&new_view);

        assert!(!fence.evaluate());
        assert!(fence.is_fenced());
        assert!(fence.fenced_since().is_some());

        let rejoin_view = tidefs_membership_live::epoch_coordinator::EpochView::new(
            EpochId::new(1),
            vec![mid(1), mid(2), mid(3)],
            3000,
        );
        fence.epoch_fence.update_from_view(&rejoin_view);

        assert!(fence.evaluate());
        assert!(fence.fenced_since().is_none());
    }

    #[test]
    fn can_grant_leases_is_false_when_fenced() {
        let mut fence = make_fence(1, 1, &[1, 2, 3]);
        assert!(fence.can_grant_leases());

        fence.guard.partition_state = PartitionState::MinorityFenced {
            quorum_side_voter_count: 2,
            since_millis: 100,
        };
        let _ = fence.evaluate();
        assert!(!fence.can_grant_leases());
    }

    #[test]
    fn can_commit_publications_is_false_when_fenced() {
        let mut fence = make_fence(1, 1, &[1, 2, 3]);
        assert!(fence.can_commit_publications());

        fence.guard.partition_state = PartitionState::MinorityFenced {
            quorum_side_voter_count: 2,
            since_millis: 100,
        };
        let _ = fence.evaluate();
        assert!(!fence.can_commit_publications());
    }

    #[test]
    fn can_mint_receipts_is_false_when_fenced() {
        let mut fence = make_fence(1, 1, &[1, 2, 3]);
        assert!(fence.can_mint_receipts());

        fence.guard.partition_state = PartitionState::MinorityFenced {
            quorum_side_voter_count: 2,
            since_millis: 100,
        };
        let _ = fence.evaluate();
        assert!(!fence.can_mint_receipts());
    }

    #[test]
    fn empty_roster_rejects_writes() {
        let mut fence = make_fence(1, 0, &[]);
        assert!(!fence.evaluate());
        assert!(!fence.can_accept_writes());
    }

    #[test]
    fn quorum_side_accepts_writes() {
        let mut fence = make_fence(1, 5, &[1, 2, 3, 4]);

        fence.guard.partition_state = PartitionState::QuorumSideActive {
            minority_members: vec![mid(4)],
            new_epoch: EpochId::new(6),
            since_millis: 100,
        };

        assert!(fence.evaluate());
        assert!(fence.can_accept_writes());
        assert!(!fence.is_fenced());
    }

    #[test]
    fn healing_state_may_reject_writes() {
        let mut fence = make_fence(1, 5, &[1, 2, 3, 4]);

        fence.guard.partition_state = PartitionState::Healing {
            joint_epoch: EpochId::new(7),
            rejoining_members: vec![mid(4)],
            since_millis: 200,
        };

        assert!(!fence.evaluate());
    }

    #[test]
    fn accessors_return_expected_values() {
        let mut fence = make_fence(3, 7, &[1, 2, 3]);
        assert!(fence.evaluate());

        assert_eq!(fence.fence_epoch(), EpochId::new(7));
        assert_eq!(*fence.partition_state(), PartitionState::Connected);
        assert!(fence.last_evaluated_at() > 0);
        assert!(fence.authority_homes_valid());
    }

    #[test]
    fn fenced_then_healed_transitions_back() {
        let mut fence = make_fence(1, 1, &[1, 2, 3]);

        fence.guard.partition_state = PartitionState::MinorityFenced {
            quorum_side_voter_count: 2,
            since_millis: 100,
        };
        assert!(!fence.evaluate());
        assert!(fence.is_fenced());
        assert!(fence.fenced_since().is_some());

        fence.guard.partition_state = PartitionState::Connected;
        fence.guard.fence = crate::types::PartitionFence::default();
        assert!(fence.evaluate());
        assert!(!fence.is_fenced());
        assert!(fence.fenced_since().is_none());
    }
}
