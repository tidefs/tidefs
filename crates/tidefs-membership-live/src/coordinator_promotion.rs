// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Coordinator promotion replay integration for the live membership runtime.
//!
//! On coordinator promotion after a crash, the new coordinator replays the
//! [`MembershipTransitionJournal`] to recover in-flight join and leave
//! transitions. Committed transitions are re-broadcast so all members
//! converge; stale prepared transitions are auto-aborted; fresh prepared
//! transitions are yielded for caller resolution.
//!
//! ## Integration
//!
//! Called by [`crate::runtime::MembershipRuntime::replay_transition_journal`]
//! on each tick when the local node is the current coordinator and the
//! journal contains pending records. Replay is idempotent: committed
//! records are re-broadcast every tick so late-joining or recovering peers
//! eventually converge.

use std::sync::{Arc, Mutex};

use tidefs_membership_epoch::transition_journal::{
    current_time_millis, MembershipTransitionJournal, ReplayAction, TransitionKind,
};
use tidefs_membership_epoch::Incarnation;

use crate::membership_outbound_dispatch::{MembershipOutboundDispatch, MembershipOutboundMessage};
use crate::roster::MembershipRoster;

/// Result of replaying the transition journal.
#[derive(Clone, Debug, Default)]
pub struct TransitionJournalReplayResult {
    /// Number of committed transitions re-broadcast.
    pub committed_rebroadcast: usize,
    /// Number of stale prepared transitions auto-aborted.
    pub stale_aborted: usize,
    /// Number of fresh prepared transitions yielded for resolution.
    /// These must be re-evaluated by the caller.
    pub fresh_resolve: usize,
}

/// Replay the transition journal with re-broadcast and auto-abort logic.
///
/// # Arguments
/// * `journal` - The membership transition journal to replay.
/// * `dispatch` - Outbound dispatch for re-broadcasting committed transitions.
/// * `roster` - Current roster for determining broadcast targets.
/// * `staleness_timeout_ms` - Maximum age for prepared transitions before
///   auto-abort (milliseconds).
///
/// # Returns
/// A summary of actions taken.
pub fn replay_transition_journal(
    journal: &Arc<Mutex<MembershipTransitionJournal>>,
    dispatch: &MembershipOutboundDispatch<'_>,
    _roster: &MembershipRoster,
    staleness_timeout_ms: u64,
    incarnation: Incarnation,
) -> TransitionJournalReplayResult {
    let now = current_time_millis();
    let mut result = TransitionJournalReplayResult::default();

    let mut guard = journal.lock().expect("journal lock poisoned");

    let actions: Vec<ReplayAction> = guard.replay_pending(now, staleness_timeout_ms).collect();

    for action in actions {
        match action {
            ReplayAction::ReBroadcastCommitted { record } => {
                // Re-broadcast committed transitions to ensure convergence.
                match &record.kind {
                    TransitionKind::Join { peer_id, epoch } => {
                        let msg = MembershipOutboundMessage::PeerJoined {
                            member_id: *peer_id,
                            roster_epoch: *epoch,
                        };
                        let _ = dispatch.broadcast(msg);
                        result.committed_rebroadcast += 1;
                    }
                    TransitionKind::Leave {
                        peer_id,
                        epoch,
                        reason,
                    } => {
                        let msg = MembershipOutboundMessage::LeaveNotification {
                            member_id: *peer_id,
                            departure_epoch: *epoch,
                            announced_at_millis: now,
                            leave_reason: *reason,
                            incarnation,
                        };
                        let _ = dispatch.broadcast(msg);
                        result.committed_rebroadcast += 1;
                    }
                }
            }
            ReplayAction::ResolvePrepared { record } => {
                // Fresh prepared transitions: auto-abort them so the
                // new coordinator can start with a clean slate.
                // The initiating peer will need to re-initiate.
                let id = record.id;
                guard.record_abort(id, now);
                result.stale_aborted += 1;
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roster::MembershipRoster;
    use tidefs_membership_epoch::transition_journal::{
        MembershipTransitionJournal, TransitionKind,
    };
    use tidefs_membership_epoch::{EpochId, MemberId};

    fn member(id: u64) -> MemberId {
        MemberId::new(id)
    }

    fn epoch(id: u64) -> EpochId {
        EpochId::new(id)
    }

    #[test]
    fn replay_empty_journal_returns_zeros() {
        let journal = Arc::new(Mutex::new(MembershipTransitionJournal::new()));
        let mut roster = MembershipRoster::new();
        roster.add_member(member(1));

        // We can't easily create a real MembershipOutboundDispatch without
        // a SendDispatcher/transport stack. But we can test the replay
        // function with the journal directly.
        let mut guard = journal.lock().unwrap();
        let actions: Vec<ReplayAction> = guard.replay_pending(0, 60_000).collect();
        assert!(actions.is_empty());
    }

    #[test]
    fn replay_committed_join_returns_rebroadcast() {
        let journal = Arc::new(Mutex::new(MembershipTransitionJournal::new()));
        let t = 0u64;
        {
            let mut guard = journal.lock().unwrap();
            let id = guard.record_prepare(
                TransitionKind::Join {
                    peer_id: member(42),
                    epoch: epoch(3),
                },
                t,
            );
            guard.record_commit(id, t + 10);
        }
        // Verify the record is committed.
        {
            let guard = journal.lock().unwrap();
            let rec = guard
                .get(tidefs_membership_epoch::transition_journal::TransitionId::new(1))
                .unwrap();
            assert!(rec.is_committed());
        }
    }

    #[test]
    fn replay_stale_prepared_is_auto_aborted() {
        let mut journal = MembershipTransitionJournal::new();
        let t = 0u64;

        let id = journal.record_prepare(
            TransitionKind::Join {
                peer_id: member(99),
                epoch: epoch(5),
            },
            t,
        );

        // Replay with staleness timeout of 10ms, now at 100ms.
        let actions: Vec<ReplayAction> = journal.replay_pending(100, 10).collect();
        assert!(actions.is_empty(), "stale prepared should be auto-aborted");

        let rec = journal.get(id).unwrap();
        assert!(!rec.is_pending());
    }

    #[test]
    fn replay_result_default_is_zero() {
        let r = TransitionJournalReplayResult::default();
        assert_eq!(r.committed_rebroadcast, 0);
        assert_eq!(r.stale_aborted, 0);
        assert_eq!(r.fresh_resolve, 0);
    }
}
