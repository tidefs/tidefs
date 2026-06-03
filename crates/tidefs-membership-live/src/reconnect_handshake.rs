//! Peer-reconnect handshake bridging transport connection establishment to
//! committed-epoch state delivery and session re-binding.
//!
//! When a known peer reconnects after disconnect or crash, the handshake
//! delivers the current committed epoch via a [`ReconnectStatePushMessage`]
//! and re-binds the transport session to the existing roster entry. This
//! fills the gap between initial node-join (unknown peers) and post-commit
//! roster push (passive synchronization).
//!
//! # Integration
//!
//! 1. Transport establishes a connection and verifies the peer identity.
//! 2. The transport acceptance path calls
//!    [`PeerReconnectHandshake::accept_reconnect_with_roster`] with the
//!    peer id, session id, identity, and committed roster.
//! 3. If the peer is in the roster, the handshake registers the session
//!    binding and returns a [`ReconnectStatePushMessage`].
//! 4. If the peer is not in the roster, returns [`PeerReconnectOutcome::Unknown`]
//!    and the caller should fall through to the node-join handshake.
//! 5. The caller delivers the [`ReconnectStatePushMessage`] to the peer
//!    and invokes the [`PeerReturnCallback`] to notify the epoch coordinator.

use std::sync::{Arc, RwLock};

use tidefs_membership_epoch::epoch_commit_subscriber::CommittedRoster;
use tidefs_membership_epoch::session_binding::{SessionAcceptor, SessionBindingError};
use tidefs_membership_epoch::EpochId;
use tidefs_membership_types::MemberIdentity;
use tidefs_transport::reconnect_state_push::ReconnectStatePushMessage;

// ---------------------------------------------------------------------------
// PeerReconnectOutcome
// ---------------------------------------------------------------------------

/// Result of a peer-reconnect attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerReconnectOutcome {
    /// Known roster member — deliver the push message and invoke callback.
    Known {
        push_message: ReconnectStatePushMessage,
    },
    /// Not in the committed roster — fall through to join handshake.
    Unknown,
    /// Already bound — duplicate connection, reject.
    AlreadyBound { existing_session_id: u64 },
}

// ---------------------------------------------------------------------------
// ReconnectError
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconnectError {
    BindingFailed(SessionBindingError),
}

impl std::fmt::Display for ReconnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BindingFailed(e) => write!(f, "session binding failed: {e}"),
        }
    }
}

impl std::error::Error for ReconnectError {}

// ---------------------------------------------------------------------------
// PeerReconnectHandshake
// ---------------------------------------------------------------------------

type PeerReturnCallback = Box<dyn Fn(u64, u64) + Send + Sync>;

/// Manages peer-reconnect handshake on the acceptor side.
pub struct PeerReconnectHandshake {
    acceptor: Arc<RwLock<SessionAcceptor>>,
    push_seq: RwLock<u64>,
    /// Callback invoked when a known peer reconnects successfully.
    on_peer_return: RwLock<Option<PeerReturnCallback>>,
}

impl PeerReconnectHandshake {
    #[must_use]
    pub fn new(acceptor: Arc<RwLock<SessionAcceptor>>) -> Self {
        Self {
            acceptor,
            push_seq: RwLock::new(0),
            on_peer_return: RwLock::new(None),
        }
    }

    /// Set the callback invoked when a known peer reconnects successfully.
    /// The callback receives (peer_id, epoch).
    pub fn set_peer_return_callback<F: Fn(u64, u64) + Send + Sync + 'static>(&self, cb: F) {
        *self.on_peer_return.write().expect("lock poisoned") = Some(Box::new(cb));
    }

    /// Process a reconnect with an explicitly provided committed roster.
    ///
    /// # Arguments
    /// * `peer_id` - Node ID of the connecting peer.
    /// * `session_id` - Transport-level session identifier.
    /// * `identity` - Verified [`MemberIdentity`] of the peer.
    /// * `committed_roster` - Current committed roster snapshot.
    ///
    /// # Returns
    /// * `Known { push_message }` — peer is a known member; deliver the
    ///   push message to the peer.
    /// * `Unknown` — peer is not in the roster; fall through to join.
    /// * `AlreadyBound` — session already bound; reject duplicate.
    pub fn accept_reconnect_with_roster(
        &self,
        peer_id: u64,
        session_id: u64,
        identity: MemberIdentity,
        committed_roster: &CommittedRoster,
    ) -> Result<PeerReconnectOutcome, ReconnectError> {
        let acceptor = self.acceptor.read().expect("SessionAcceptor lock poisoned");

        // Peer must be in the roster to qualify as a reconnect (not a new join).
        if !committed_roster.contains(peer_id) {
            return Ok(PeerReconnectOutcome::Unknown);
        }

        // Reject duplicate session binding.
        if acceptor.lookup(session_id).is_some() {
            return Ok(PeerReconnectOutcome::AlreadyBound {
                existing_session_id: session_id,
            });
        }

        drop(acceptor);

        // Register the session binding.
        match self
            .acceptor
            .read()
            .expect("SessionAcceptor lock poisoned")
            .accept(session_id, identity)
        {
            Ok(()) => {
                let push_seq = {
                    let mut seq = self.push_seq.write().expect("push_seq lock poisoned");
                    *seq += 1;
                    *seq
                };

                let epoch = committed_roster.epoch.0;
                let push_message = ReconnectStatePushMessage::new(
                    push_seq,
                    committed_roster.clone(),
                    peer_id,
                    epoch,
                );

                // Notify the epoch coordinator of the peer's return.
                if let Some(cb) = self.on_peer_return.read().expect("lock poisoned").as_ref() {
                    cb(peer_id, epoch);
                }

                Ok(PeerReconnectOutcome::Known { push_message })
            }
            Err(SessionBindingError::MemberNotInRoster { .. }) => Ok(PeerReconnectOutcome::Unknown),
            Err(e) => Err(ReconnectError::BindingFailed(e)),
        }
    }

    /// Simpler variant: uses the acceptor's own roster state.
    /// Prefer [`accept_reconnect_with_roster`] in production.
    pub fn accept_reconnect(
        &self,
        peer_id: u64,
        session_id: u64,
        identity: MemberIdentity,
    ) -> Result<PeerReconnectOutcome, ReconnectError> {
        let acceptor = self.acceptor.read().expect("SessionAcceptor lock poisoned");

        if acceptor.lookup(session_id).is_some() {
            return Ok(PeerReconnectOutcome::AlreadyBound {
                existing_session_id: session_id,
            });
        }

        drop(acceptor);

        match self
            .acceptor
            .read()
            .expect("SessionAcceptor lock poisoned")
            .accept(session_id, identity)
        {
            Ok(()) => {
                let push_seq = {
                    let mut seq = self.push_seq.write().expect("push_seq lock poisoned");
                    *seq += 1;
                    *seq
                };

                let acceptor = self.acceptor.read().expect("SessionAcceptor lock poisoned");
                let epoch = acceptor.current_epoch();

                let roster = CommittedRoster::new(EpochId(epoch), vec![peer_id]);

                let push_message = ReconnectStatePushMessage::new(push_seq, roster, peer_id, epoch);

                if let Some(cb) = self.on_peer_return.read().expect("lock poisoned").as_ref() {
                    cb(peer_id, epoch);
                }

                Ok(PeerReconnectOutcome::Known { push_message })
            }
            Err(SessionBindingError::MemberNotInRoster { .. }) => Ok(PeerReconnectOutcome::Unknown),
            Err(e) => Err(ReconnectError::BindingFailed(e)),
        }
    }

    #[must_use]
    pub fn current_push_seq(&self) -> u64 {
        *self.push_seq.read().expect("push_seq lock poisoned")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::RwLock as StdRwLock;

    use tidefs_membership_epoch::epoch_commit_subscriber::CommittedRoster;
    use tidefs_membership_epoch::session_binding::{RosterSessionRegistry, SessionAcceptor};
    use tidefs_membership_epoch::EpochId;
    use tidefs_membership_types::MemberIdentity;

    fn mk_roster(epoch: u64, ids: Vec<u64>) -> CommittedRoster {
        CommittedRoster::new(EpochId(epoch), ids)
    }
    fn mk_id(node: u64, epoch: u64) -> MemberIdentity {
        MemberIdentity::new(node, epoch)
    }

    fn mk_handshake(epoch: u64, members: &[u64]) -> PeerReconnectHandshake {
        let reg = Arc::new(StdRwLock::new(RosterSessionRegistry::new()));
        let mut acceptor = SessionAcceptor::new(Arc::clone(&reg));
        acceptor.update_roster(epoch, members);
        PeerReconnectHandshake::new(Arc::new(StdRwLock::new(acceptor)))
    }

    #[test]
    fn known_peer_delivers_push() {
        let hs = mk_handshake(5, &[10, 20, 30]);
        let r = mk_roster(5, vec![10, 20, 30]);
        let o = hs
            .accept_reconnect_with_roster(20, 100, mk_id(20, 5), &r)
            .unwrap();
        match o {
            PeerReconnectOutcome::Known { push_message } => {
                assert_eq!(push_message.target_peer_id, 20);
                assert_eq!(push_message.push_seq, 1);
            }
            other => panic!("expected Known, got {other:?}"),
        }
    }

    #[test]
    fn known_peer_binds_session() {
        let hs = mk_handshake(5, &[10, 20]);
        let _ = hs
            .accept_reconnect_with_roster(10, 200, mk_id(10, 5), &mk_roster(5, vec![10, 20]))
            .unwrap();
        assert!(hs.acceptor.read().unwrap().lookup(200).is_some());
    }

    #[test]
    fn unknown_peer() {
        let hs = mk_handshake(5, &[10, 20]);
        let o = hs
            .accept_reconnect_with_roster(99, 300, mk_id(99, 5), &mk_roster(5, vec![10, 20]))
            .unwrap();
        assert_eq!(o, PeerReconnectOutcome::Unknown);
    }

    #[test]
    fn already_bound() {
        let hs = mk_handshake(5, &[10, 20, 30]);
        let r = mk_roster(5, vec![10, 20, 30]);
        let _ = hs
            .accept_reconnect_with_roster(20, 100, mk_id(20, 5), &r)
            .unwrap();
        let o = hs
            .accept_reconnect_with_roster(20, 100, mk_id(20, 5), &r)
            .unwrap();
        assert_eq!(
            o,
            PeerReconnectOutcome::AlreadyBound {
                existing_session_id: 100
            }
        );
    }

    #[test]
    fn stale_epoch_rejected() {
        let hs = mk_handshake(5, &[10, 20]);
        let r = mk_roster(5, vec![10, 20]);
        assert!(hs
            .accept_reconnect_with_roster(10, 100, mk_id(10, 3), &r)
            .is_err());
    }

    #[test]
    fn push_seq_monotonic() {
        let hs = mk_handshake(3, &[1, 2, 3, 4, 5]);
        let r = mk_roster(3, vec![1, 2, 3, 4, 5]);
        let mut seqs = vec![];
        for i in 1..=3u64 {
            let o = hs
                .accept_reconnect_with_roster(i, i * 100, mk_id(i, 3), &r)
                .unwrap();
            if let PeerReconnectOutcome::Known { push_message } = o {
                seqs.push(push_message.push_seq);
            }
        }
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    #[test]
    fn empty_roster() {
        let hs = mk_handshake(0, &[]);
        let o = hs
            .accept_reconnect_with_roster(1, 100, mk_id(1, 0), &mk_roster(0, vec![]))
            .unwrap();
        assert_eq!(o, PeerReconnectOutcome::Unknown);
    }

    #[test]
    fn peer_return_callback_fires() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let c2 = calls.clone();
        let hs = mk_handshake(5, &[10, 20, 30]);
        hs.set_peer_return_callback(move |peer_id, epoch| {
            c2.lock().unwrap().push((peer_id, epoch));
        });
        let r = mk_roster(5, vec![10, 20, 30]);
        let o = hs
            .accept_reconnect_with_roster(20, 100, mk_id(20, 5), &r)
            .unwrap();
        assert!(matches!(o, PeerReconnectOutcome::Known { .. }));
        let c = calls.lock().unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0], (20, 5));
    }

    #[test]
    fn peer_return_callback_not_fired_for_unknown() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let c2 = calls.clone();
        let hs = mk_handshake(5, &[10, 20]);
        hs.set_peer_return_callback(move |peer_id, epoch| {
            c2.lock().unwrap().push((peer_id, epoch));
        });
        let _ = hs
            .accept_reconnect_with_roster(99, 100, mk_id(99, 5), &mk_roster(5, vec![10, 20]))
            .unwrap();
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn target_in_roster_is_true() {
        let hs = mk_handshake(5, &[10, 20, 30]);
        let r = mk_roster(5, vec![10, 20, 30]);
        let o = hs
            .accept_reconnect_with_roster(20, 100, mk_id(20, 5), &r)
            .unwrap();
        if let PeerReconnectOutcome::Known { push_message } = o {
            assert!(push_message.target_in_roster());
        } else {
            panic!("expected Known");
        }
    }

    #[test]
    fn accept_reconnect_known_peer() {
        let hs = mk_handshake(3, &[1, 2, 3]);
        let o = hs.accept_reconnect(2, 100, mk_id(2, 5)).unwrap();
        assert!(matches!(o, PeerReconnectOutcome::Known { .. }));
    }

    #[test]
    fn accept_reconnect_unknown_peer() {
        let hs = mk_handshake(3, &[1, 2, 3]);
        let o = hs.accept_reconnect(99, 100, mk_id(99, 5)).unwrap();
        assert_eq!(o, PeerReconnectOutcome::Unknown);
    }
}
