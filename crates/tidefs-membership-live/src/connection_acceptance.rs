// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Connection acceptance bridge: wires the PeerReconnectHandshake into the
//! membership runtime so known-peer reconnects deliver epoch state and
//! re-bind transport sessions to roster entries.
//!
//! [`ConnectionAcceptor`] integrates the [`PeerReconnectHandshake`] with the
//! [`EpochCommitBus`]. On each epoch commit, the acceptor updates the cached
//! roster. The transport admission path calls [`accept_connection`] to
//! distinguish known-peer reconnects from new joins.
//!
//! # Integration
//!
//! 1. Create a `ConnectionAcceptor` with a shared `SessionAcceptor`.
//! 2. Register it as an `EpochCommitSubscriber` on the `EpochCommitBus`.
//! 3. Call `set_peer_return_callback` on `handshake()` to notify the epoch
//!    coordinator when known peers return.
//! 4. On each inbound transport connection (after identity verification),
//!    call `accept_connection` with the peer's identity.
//! 5. On `Known`, deliver the returned `ReconnectStatePushMessage` to the
//!    reconnecting peer.

use std::sync::RwLock;

use tidefs_membership_epoch::epoch_commit_subscriber::{
    CommittedRoster, EpochCommitNotification, EpochCommitSubscriber,
};
use tidefs_membership_epoch::session_binding::SessionAcceptor;
use tidefs_membership_types::MemberIdentity;

use crate::reconnect_handshake::{PeerReconnectHandshake, PeerReconnectOutcome, ReconnectError};

use crate::epoch_coordinator;

type RosterUpdateHook = Box<dyn Fn(&CommittedRoster) + Send + Sync>;

/// Bridges [`PeerReconnectHandshake`] into the live membership runtime.
///
/// Holds the handshake and a cached committed roster. Subscribes to
/// [`EpochCommitBus`] so the roster stays synchronized across epoch
/// transitions.
pub struct ConnectionAcceptor {
    handshake: PeerReconnectHandshake,
    current_roster: RwLock<Option<CommittedRoster>>,
    roster_update_hook: RwLock<Option<RosterUpdateHook>>,
}

impl ConnectionAcceptor {
    #[must_use]
    pub fn new(acceptor: std::sync::Arc<RwLock<SessionAcceptor>>) -> Self {
        Self {
            handshake: PeerReconnectHandshake::new(acceptor),
            current_roster: RwLock::new(None),
            roster_update_hook: RwLock::new(None),
        }
    }

    /// Process an inbound transport connection for a peer.
    ///
    /// Consults the current committed roster to distinguish known-peer
    /// reconnects from unknown peers.
    ///
    /// # Returns
    /// * `Known { push_message }` — peer is known; deliver push message.
    /// * `Unknown` — peer is not in roster; fall through to join.
    /// * `AlreadyBound { .. }` — session duplicate; reject.
    pub fn accept_connection(
        &self,
        peer_id: u64,
        session_id: u64,
        identity: MemberIdentity,
    ) -> Result<PeerReconnectOutcome, ReconnectError> {
        let roster_guard = self.current_roster.read().expect("roster lock poisoned");
        match roster_guard.as_ref() {
            Some(roster) => self
                .handshake
                .accept_reconnect_with_roster(peer_id, session_id, identity, roster),
            None => self
                .handshake
                .accept_reconnect(peer_id, session_id, identity),
        }
    }

    /// Return the current committed roster snapshot, if known.
    #[must_use]
    pub fn current_roster(&self) -> Option<CommittedRoster> {
        self.current_roster
            .read()
            .expect("roster lock poisoned")
            .clone()
    }

    /// Return a reference to the underlying handshake.
    /// Use `handshake.set_peer_return_callback(...)` to wire the
    /// epoch-coordinator notification.
    #[must_use]
    pub fn handshake(&self) -> &PeerReconnectHandshake {
        &self.handshake
    }

    /// Set a callback invoked whenever the cached roster is updated from
    /// either the EpochCommitBus or the EpochAdvanceCoordinator.
    ///
    /// Use this to propagate roster changes to downstream consumers like
    /// PeerJoinHandshake::update_roster.
    pub fn set_roster_update_hook<F: Fn(&CommittedRoster) + Send + Sync + 'static>(&self, hook: F) {
        *self.roster_update_hook.write().expect("hook lock poisoned") = Some(Box::new(hook));
    }

    /// Internal: set the cached roster and fire the update hook.
    fn apply_roster_update(&self, roster: CommittedRoster) {
        let hook = self.roster_update_hook.read().expect("hook lock poisoned");
        if let Some(ref h) = *hook {
            h(&roster);
        }
        *self.current_roster.write().expect("roster lock poisoned") = Some(roster);
    }
}

impl EpochCommitSubscriber for ConnectionAcceptor {
    fn on_epoch_committed(&self, notification: &EpochCommitNotification) {
        let roster = CommittedRoster {
            epoch: notification.epoch,
            member_ids: notification.member_ids.clone(),
            roster_hash: notification.roster_hash,
        };
        self.apply_roster_update(roster);
    }
}

// ── EpochCommitSubscriber (crate::epoch_coordinator) for EpochAdvanceCoordinator ──

impl epoch_coordinator::EpochCommitSubscriber for ConnectionAcceptor {
    fn on_epoch_committed(&self, view: &epoch_coordinator::EpochView) {
        let member_ids: Vec<u64> = view.member_set.iter().map(|m| m.0).collect();
        let roster = CommittedRoster::new(view.epoch_number, member_ids);
        self.apply_roster_update(roster);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::RwLock as StdRwLock;
    use std::sync::{Arc as StdArc, Mutex};

    use tidefs_membership_epoch::epoch_commit_subscriber::{
        CommittedRoster, EpochCommitNotification,
    };
    use tidefs_membership_epoch::session_binding::{RosterSessionRegistry, SessionAcceptor};
    use tidefs_membership_epoch::EpochId;
    use tidefs_membership_types::MemberIdentity;

    fn mk_id(node: u64, epoch: u64) -> MemberIdentity {
        MemberIdentity::new(node, epoch)
    }
    fn mk_roster(epoch: u64, ids: Vec<u64>) -> CommittedRoster {
        CommittedRoster::new(EpochId(epoch), ids)
    }

    fn make_acceptor_with_roster(epoch: u64, members: &[u64]) -> ConnectionAcceptor {
        let reg = StdArc::new(StdRwLock::new(RosterSessionRegistry::new()));
        let mut sess = SessionAcceptor::new(StdArc::clone(&reg));
        sess.update_roster(epoch, members);
        let ca = ConnectionAcceptor::new(std::sync::Arc::new(StdRwLock::new(sess)));
        *ca.current_roster.write().unwrap() = Some(mk_roster(epoch, members.to_vec()));
        ca
    }

    #[test]
    fn known_peer_returns_push_message() {
        let ca = make_acceptor_with_roster(5, &[10, 20, 30]);
        let o = ca.accept_connection(20, 100, mk_id(20, 5)).unwrap();
        match o {
            PeerReconnectOutcome::Known { push_message } => {
                assert_eq!(push_message.target_peer_id, 20);
                assert_eq!(push_message.roster.epoch, EpochId(5));
            }
            other => panic!("expected Known, got {other:?}"),
        }
    }

    #[test]
    fn unknown_peer_returns_unknown() {
        let ca = make_acceptor_with_roster(5, &[10, 20]);
        let o = ca.accept_connection(99, 100, mk_id(99, 5)).unwrap();
        assert_eq!(o, PeerReconnectOutcome::Unknown);
    }

    #[test]
    fn already_bound_rejected() {
        let ca = make_acceptor_with_roster(5, &[10, 20, 30]);
        let _ = ca.accept_connection(20, 100, mk_id(20, 5)).unwrap();
        let o2 = ca.accept_connection(20, 100, mk_id(20, 5)).unwrap();
        assert_eq!(
            o2,
            PeerReconnectOutcome::AlreadyBound {
                existing_session_id: 100
            }
        );
    }

    #[test]
    fn empty_roster_falls_back_to_acceptor() {
        let reg = StdArc::new(StdRwLock::new(RosterSessionRegistry::new()));
        let mut sess = SessionAcceptor::new(StdArc::clone(&reg));
        sess.update_roster(3, &[1, 2, 3]);
        let ca = ConnectionAcceptor::new(std::sync::Arc::new(StdRwLock::new(sess)));
        let o = ca.accept_connection(2, 100, mk_id(2, 5)).unwrap();
        assert!(matches!(o, PeerReconnectOutcome::Known { .. }));
    }

    #[test]
    fn epoch_commit_updates_roster() {
        let reg = StdArc::new(StdRwLock::new(RosterSessionRegistry::new()));
        let sess = SessionAcceptor::new(StdArc::clone(&reg));
        let ca = ConnectionAcceptor::new(std::sync::Arc::new(StdRwLock::new(sess)));

        assert!(ca.current_roster().is_none());

        ca.on_epoch_committed(&EpochCommitNotification {
            epoch: EpochId(7),
            roster_hash: mk_roster(7, vec![10, 20]).roster_hash,
            member_ids: vec![10, 20],
            commit_index: 1,
            catalog_delta_bytes: None,
        });

        let r = ca.current_roster().unwrap();
        assert_eq!(r.epoch, EpochId(7));
        assert_eq!(r.member_ids, vec![10, 20]);
    }

    #[test]
    fn peer_return_callback_fires() {
        let ca = make_acceptor_with_roster(5, &[10, 20, 30]);
        let calls = StdArc::new(Mutex::new(Vec::new()));
        let c2 = calls.clone();
        ca.handshake().set_peer_return_callback(move |pid, epoch| {
            c2.lock().unwrap().push((pid, epoch));
        });

        let _ = ca.accept_connection(20, 100, mk_id(20, 5)).unwrap();
        let c = calls.lock().unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0], (20, 5));
    }

    #[test]
    fn handshake_accessible() {
        let ca = make_acceptor_with_roster(5, &[10, 20]);
        assert_eq!(ca.handshake().current_push_seq(), 0);
        let _ = ca.accept_connection(10, 100, mk_id(10, 5)).unwrap();
        assert_eq!(ca.handshake().current_push_seq(), 1);
    }
}
