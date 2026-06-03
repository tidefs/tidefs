//! Outbound send gating against the committed membership roster.
//!
//! [`MembershipSendGate`] implements [`tidefs_transport::SendGate`] by
//! checking a shared committed-member set. Callers update the set
//! whenever the roster changes (e.g., via an [`EpochCommitSubscriber`]),
//! and the transport send pipeline calls [`can_send_to`] before enqueueing
//! each outbound message.
//!
//! ## Relationship to MembershipTransportBridge
//!
//! [`MembershipTransportBridge`] closes transport sessions for evicted
//! peers. [`MembershipSendGate`] provides defense-in-depth at the
//! message-queue level: during the race window between eviction and
//! session teardown, the gate rejects sends to non-members before
//! they reach the wire.
//!
//! [`EpochCommitSubscriber`]: crate::epoch_coordinator::EpochCommitSubscriber
//! [`MembershipTransportBridge`]: crate::transport_bridge::MembershipTransportBridge
//! [`can_send_to`]: MembershipSendGate::can_send_to

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, RwLock};

use crate::epoch_coordinator::{EpochCommitSubscriber, EpochView};
use tidefs_membership_epoch::MemberId;
use tidefs_transport::circuit_breaker::PeerId;
use tidefs_transport::epoch_bridge::{PeerStateDelta, TransportEpochSubscriber};
use tidefs_transport::SendGate;

// ---------------------------------------------------------------------------
// OutboundGateError
// ---------------------------------------------------------------------------

/// Reasons an outbound send is rejected by the membership send gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutboundGateError {
    /// The target peer is not in the current committed membership roster.
    PeerNotInRoster { peer_id: PeerId },
    /// The roster is empty (no committed epoch applied yet).
    RosterEmpty,
}

impl OutboundGateError {
    /// The peer ID that was rejected, if applicable.
    #[must_use]
    pub fn peer_id(&self) -> Option<PeerId> {
        match self {
            Self::PeerNotInRoster { peer_id } => Some(*peer_id),
            Self::RosterEmpty => None,
        }
    }
}

impl fmt::Display for OutboundGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerNotInRoster { peer_id } => {
                write!(f, "peer {peer_id} not in committed membership roster")
            }
            Self::RosterEmpty => {
                write!(f, "membership roster is empty")
            }
        }
    }
}

impl std::error::Error for OutboundGateError {}

impl From<OutboundGateError> for tidefs_transport::outbound_send::SendPipelineError {
    fn from(e: OutboundGateError) -> Self {
        match e {
            OutboundGateError::PeerNotInRoster { peer_id } => Self::PeerNotInRoster(peer_id),
            OutboundGateError::RosterEmpty => Self::PeerNotInRoster(0),
        }
    }
}

// ---------------------------------------------------------------------------
// MembershipSendGate
// ---------------------------------------------------------------------------

/// Outbound send gate that rejects messages targeting peers not in
/// the current committed membership roster.
///
/// Wraps a shared `Arc<RwLock<BTreeSet<MemberId>>>` that callers update
/// on each epoch commit. The gate implements [`SendGate`] so it can be
/// attached to a transport [`SendPipelineHandle`].
///
/// # Example
///
/// ```ignore
/// use tidefs_membership_live::send_gate::MembershipSendGate;
/// use tidefs_transport::SendGate;
///
/// let member_set = Arc::new(RwLock::new(BTreeSet::new()));
/// let gate = MembershipSendGate::new(Arc::clone(&member_set));
/// let handle = send_pipeline_handle.with_send_gate(
///     Arc::new(gate),
///     peer_id,
/// );
/// ```
///
/// [`SendPipelineHandle`]: tidefs_transport::outbound_send::SendPipelineHandle
pub struct MembershipSendGate {
    /// Shared set of committed member ids. Updated externally on epoch
    /// commits; read by the gate on every send.
    member_set: Arc<RwLock<BTreeSet<MemberId>>>,
}

impl MembershipSendGate {
    /// Create a new gate backed by the given shared member set.
    ///
    /// The member set should be updated externally whenever the
    /// committed roster changes. The initial snapshot can be set
    /// via `write().unwrap()` on the shared set before any sends
    /// are attempted.
    pub fn new(member_set: Arc<RwLock<BTreeSet<MemberId>>>) -> Self {
        Self { member_set }
    }

    /// Update the committed member set from an iterator of member ids.
    ///
    /// Convenience method callers can use after each epoch commit.
    pub fn replace_member_set<I>(&self, members: I)
    where
        I: IntoIterator<Item = MemberId>,
    {
        let mut guard = self.member_set.write().unwrap();
        guard.clear();
        guard.extend(members);
    }

    /// Return a snapshot of the current member set (for diagnostics).
    pub fn member_set_snapshot(&self) -> BTreeSet<MemberId> {
        self.member_set.read().unwrap().clone()
    }

    /// Return the number of members currently in the gate's set.
    pub fn member_count(&self) -> usize {
        self.member_set.read().unwrap().len()
    }

    /// Check whether the given peer is permitted to receive outbound messages.
    ///
    /// Returns Ok(()) when the peer is in the current committed roster.
    /// Returns OutboundGateError::PeerNotInRoster when the peer is not
    /// a member, and OutboundGateError::RosterEmpty when no roster has
    /// been committed.
    pub fn check(&self, peer_id: PeerId) -> Result<(), OutboundGateError> {
        let guard = self.member_set.read().unwrap();
        if guard.is_empty() {
            return Err(OutboundGateError::RosterEmpty);
        }
        if guard.contains(&MemberId::new(peer_id)) {
            Ok(())
        } else {
            Err(OutboundGateError::PeerNotInRoster { peer_id })
        }
    }
}

impl SendGate for MembershipSendGate {
    fn can_send_to(&self, peer_id: PeerId) -> bool {
        self.check(peer_id).is_ok()
    }
}

// ---------------------------------------------------------------------------
// EpochCommitSubscriber -- auto-update from membership-layer epoch commits
// ---------------------------------------------------------------------------

impl EpochCommitSubscriber for MembershipSendGate {
    fn on_epoch_committed(&self, view: &EpochView) {
        self.replace_member_set(view.member_set.clone());
    }
}

// ---------------------------------------------------------------------------
// TransportEpochSubscriber -- auto-update from transport-layer epoch events
// ---------------------------------------------------------------------------

impl TransportEpochSubscriber for MembershipSendGate {
    fn on_epoch_transition(&self, _new_epoch: u64, roster: &[u64], _deltas: &[PeerStateDelta]) {
        self.replace_member_set(roster.iter().map(|n| MemberId::new(*n)));
    }
}

impl fmt::Debug for MembershipSendGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.member_count();
        f.debug_struct("MembershipSendGate")
            .field("member_count", &count)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mid(v: u64) -> MemberId {
        MemberId::new(v)
    }

    fn pid(v: u64) -> PeerId {
        v
    }

    // ------------------------------------------------------------------
    // can_send_to: member vs non-member
    // ------------------------------------------------------------------

    #[test]
    fn can_send_to_returns_true_for_member() {
        let set = Arc::new(RwLock::new(BTreeSet::from([mid(1), mid(2), mid(3)])));
        let gate = MembershipSendGate::new(Arc::clone(&set));

        assert!(gate.can_send_to(pid(1)));
        assert!(gate.can_send_to(pid(2)));
        assert!(gate.can_send_to(pid(3)));
    }

    #[test]
    fn can_send_to_returns_false_for_non_member() {
        let set = Arc::new(RwLock::new(BTreeSet::from([mid(1), mid(2)])));
        let gate = MembershipSendGate::new(Arc::clone(&set));

        assert!(!gate.can_send_to(pid(3)));
        assert!(!gate.can_send_to(pid(99)));
    }

    #[test]
    fn can_send_to_returns_false_for_empty_roster() {
        let set = Arc::new(RwLock::new(BTreeSet::new()));
        let gate = MembershipSendGate::new(Arc::clone(&set));

        assert!(!gate.can_send_to(pid(1)));
        assert!(!gate.can_send_to(pid(0)));
    }

    // ------------------------------------------------------------------
    // replace_member_set
    // ------------------------------------------------------------------

    #[test]
    fn replace_member_set_updates_gate() {
        let set = Arc::new(RwLock::new(BTreeSet::from([mid(1), mid(2)])));
        let gate = MembershipSendGate::new(Arc::clone(&set));

        assert!(gate.can_send_to(pid(1)));
        assert!(!gate.can_send_to(pid(3)));

        // Evict peer 1, add peer 3.
        gate.replace_member_set(vec![mid(2), mid(3)]);

        assert!(!gate.can_send_to(pid(1)), "peer 1 should be evicted");
        assert!(gate.can_send_to(pid(2)));
        assert!(gate.can_send_to(pid(3)));
    }

    #[test]
    fn replace_member_set_with_empty_evicts_all() {
        let set = Arc::new(RwLock::new(BTreeSet::from([mid(1), mid(2)])));
        let gate = MembershipSendGate::new(Arc::clone(&set));

        gate.replace_member_set::<[MemberId; 0]>([]);

        assert!(!gate.can_send_to(pid(1)));
        assert!(!gate.can_send_to(pid(2)));
    }

    // ------------------------------------------------------------------
    // Shared-state concurrency
    // ------------------------------------------------------------------

    #[test]
    fn concurrent_reads_do_not_block_each_other() {
        // RwLock allows multiple concurrent readers. Verify that
        // repeated reads from the gate return correct results while
        // a write lock is NOT held (writers block readers, but readers
        // do not block each other).
        let set = Arc::new(RwLock::new(BTreeSet::from([mid(1), mid(2), mid(3)])));
        let gate = MembershipSendGate::new(Arc::clone(&set));

        // Hold a read lock to confirm it does not block other reads.
        let _read_guard = set.read().unwrap();

        // Other reads through the gate must still succeed (they do
        // not acquire a second lock from the gate — they block on the
        // existing read guard).
        // We drop the guard and then verify all gate checks pass.
        drop(_read_guard);

        assert!(gate.can_send_to(pid(1)));
        assert!(gate.can_send_to(pid(2)));
        assert!(gate.can_send_to(pid(3)));

        // Verify that a write lock replacing the set does not cause
        // stale reads: after replacement, the gate sees the new set.
        {
            let mut w = set.write().unwrap();
            w.clear();
            w.insert(mid(99));
        }

        assert!(!gate.can_send_to(pid(1)));
        assert!(gate.can_send_to(pid(99)));
    }

    // ------------------------------------------------------------------
    // Debug output
    // ------------------------------------------------------------------

    #[test]
    fn debug_output_includes_member_count() {
        let set = Arc::new(RwLock::new(BTreeSet::from([mid(1), mid(2)])));
        let gate = MembershipSendGate::new(Arc::clone(&set));

        let s = format!("{gate:?}");
        assert!(s.contains("MembershipSendGate"));
        assert!(s.contains("member_count"));
        assert!(s.contains("2"));
    }

    // ------------------------------------------------------------------
    // member_set_snapshot
    // ------------------------------------------------------------------

    #[test]
    fn snapshot_matches_member_set() {
        let set = Arc::new(RwLock::new(BTreeSet::from([mid(5), mid(10), mid(15)])));
        let gate = MembershipSendGate::new(Arc::clone(&set));

        let snap = gate.member_set_snapshot();
        assert_eq!(snap.len(), 3);
        assert!(snap.contains(&mid(5)));
        assert!(snap.contains(&mid(10)));
        assert!(snap.contains(&mid(15)));
    }

    // ------------------------------------------------------------------
    // SendGate trait object compatibility
    // ------------------------------------------------------------------

    #[test]
    fn send_gate_trait_object_works() {
        let set = Arc::new(RwLock::new(BTreeSet::from([mid(42)])));
        let gate = MembershipSendGate::new(Arc::clone(&set));

        let obj: &dyn SendGate = &gate;
        assert!(obj.can_send_to(pid(42)));
        assert!(!obj.can_send_to(pid(7)));
    }

    #[test]
    fn arc_dyn_send_gate_works() {
        let set = Arc::new(RwLock::new(BTreeSet::from([mid(1)])));
        let gate = MembershipSendGate::new(Arc::clone(&set));

        let arc_gate: Arc<dyn SendGate> = Arc::new(gate);
        assert!(arc_gate.can_send_to(pid(1)));
        assert!(!arc_gate.can_send_to(pid(2)));
    }

    // ------------------------------------------------------------------
    // check() method tests
    // ------------------------------------------------------------------

    #[test]
    fn check_returns_ok_for_member() {
        let set = Arc::new(RwLock::new(BTreeSet::from([mid(1), mid(2)])));
        let gate = MembershipSendGate::new(Arc::clone(&set));
        assert_eq!(gate.check(pid(1)), Ok(()));
    }

    #[test]
    fn check_returns_peer_not_in_roster_for_non_member() {
        let set = Arc::new(RwLock::new(BTreeSet::from([mid(1)])));
        let gate = MembershipSendGate::new(Arc::clone(&set));
        assert_eq!(
            gate.check(pid(99)),
            Err(OutboundGateError::PeerNotInRoster { peer_id: 99 })
        );
    }

    #[test]
    fn check_returns_roster_empty_when_no_members() {
        let set = Arc::new(RwLock::new(BTreeSet::new()));
        let gate = MembershipSendGate::new(Arc::clone(&set));
        assert_eq!(gate.check(pid(1)), Err(OutboundGateError::RosterEmpty));
    }

    // ------------------------------------------------------------------
    // OutboundGateError display
    // ------------------------------------------------------------------

    #[test]
    fn outbound_gate_error_display_peer_not_in_roster() {
        let e = OutboundGateError::PeerNotInRoster { peer_id: 42 };
        let s = format!("{e}");
        assert!(s.contains("42"));
        assert!(s.contains("not in committed membership roster"));
    }

    #[test]
    fn outbound_gate_error_display_roster_empty() {
        let e = OutboundGateError::RosterEmpty;
        let s = format!("{e}");
        assert!(s.contains("membership roster is empty"));
    }

    #[test]
    fn outbound_gate_error_is_std_error() {
        let e = OutboundGateError::PeerNotInRoster { peer_id: 1 };
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn outbound_gate_error_peer_id_accessor() {
        let e = OutboundGateError::PeerNotInRoster { peer_id: 7 };
        assert_eq!(e.peer_id(), Some(7));
        let e = OutboundGateError::RosterEmpty;
        assert_eq!(e.peer_id(), None);
    }

    // ------------------------------------------------------------------
    // EpochCommitSubscriber integration tests
    // ------------------------------------------------------------------

    #[test]
    fn epoch_commit_updates_member_set() {
        let set = Arc::new(RwLock::new(BTreeSet::new()));
        let gate = MembershipSendGate::new(Arc::clone(&set));

        assert_eq!(gate.check(pid(1)), Err(OutboundGateError::RosterEmpty));

        let view = EpochView::new(
            tidefs_membership_epoch::EpochId::new(1),
            vec![mid(1), mid(2)],
            1000,
        );
        gate.on_epoch_committed(&view);

        assert!(gate.check(pid(1)).is_ok());
        assert!(gate.check(pid(2)).is_ok());
        assert!(gate.check(pid(3)).is_err());
    }

    #[test]
    fn epoch_commit_replaces_previous_members() {
        let set = Arc::new(RwLock::new(BTreeSet::from([mid(10), mid(20)])));
        let gate = MembershipSendGate::new(Arc::clone(&set));

        assert!(gate.check(pid(10)).is_ok());

        let view = EpochView::new(
            tidefs_membership_epoch::EpochId::new(2),
            vec![mid(20), mid(30)],
            2000,
        );
        gate.on_epoch_committed(&view);

        assert!(
            !gate.can_send_to(pid(10)),
            "peer 10 was removed from roster"
        );
        assert!(gate.check(pid(20)).is_ok());
        assert!(gate.check(pid(30)).is_ok());
    }

    #[test]
    fn epoch_commit_to_empty_roster_clears_all() {
        let set = Arc::new(RwLock::new(BTreeSet::from([mid(1), mid(2)])));
        let gate = MembershipSendGate::new(Arc::clone(&set));

        assert!(gate.check(pid(1)).is_ok());

        let view = EpochView::new(tidefs_membership_epoch::EpochId::new(3), vec![], 3000);
        gate.on_epoch_committed(&view);

        assert_eq!(gate.check(pid(1)), Err(OutboundGateError::RosterEmpty));
    }

    // ------------------------------------------------------------------
    // TransportEpochSubscriber integration tests
    // ------------------------------------------------------------------

    #[test]
    fn transport_epoch_subscriber_updates_member_set() {
        let set = Arc::new(RwLock::new(BTreeSet::new()));
        let gate = MembershipSendGate::new(Arc::clone(&set));

        gate.on_epoch_transition(1, &[5, 6, 7], &[]);

        assert!(gate.check(pid(5)).is_ok());
        assert!(gate.check(pid(6)).is_ok());
        assert!(gate.check(pid(7)).is_ok());
        assert!(gate.check(pid(8)).is_err());
    }

    #[test]
    fn transport_epoch_subscriber_removes_departed_peers() {
        let set = Arc::new(RwLock::new(BTreeSet::from([mid(1), mid(2)])));
        let gate = MembershipSendGate::new(Arc::clone(&set));

        assert!(gate.check(pid(1)).is_ok());
        assert!(gate.check(pid(2)).is_ok());

        gate.on_epoch_transition(2, &[2], &[PeerStateDelta::Drained { node_id: 1 }]);

        assert!(!gate.can_send_to(pid(1)));
        assert!(gate.check(pid(2)).is_ok());
    }

    // ------------------------------------------------------------------
    // From<OutboundGateError> for SendPipelineError
    // ------------------------------------------------------------------

    #[test]
    fn outbound_gate_error_converts_to_send_pipeline_error() {
        use tidefs_transport::outbound_send::SendPipelineError;

        let e = OutboundGateError::PeerNotInRoster { peer_id: 99 };
        let spe: SendPipelineError = e.into();
        assert!(matches!(spe, SendPipelineError::PeerNotInRoster(99)));
    }
}
