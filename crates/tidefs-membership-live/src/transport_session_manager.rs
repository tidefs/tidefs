//! Production [`TransportSessionManager`] implementation bridging to
//! `tidefs_transport::Transport`.
//!
//! [`TransportBridgeManager`] wraps a shared `Arc<Mutex<Transport>>` and
//! implements [`crate::transport_bridge::TransportSessionManager`] so
//! that membership roster additions trigger proactive transport session
//! establishment and roster removals trigger session teardown.
//!
//! # Architecture
//!
//! - `register_peer(peer_id, addresses)`: adds the peer to the transport
//!   cohort graph and initiates an outbound `connect()` + `perform_handshake()`.
//!   On success, the session is recorded for later lookup and teardown.
//!   On failure, the peer is still registered in the cohort graph (if
//!   addresses were provided) so inbound sessions are still accepted.
//!
//! - `close_peer_sessions(peer_id)`: looks up all sessions for the peer
//!   and calls `close_session()` with `SessionCloseReason::PeerRemoved`.
//!   A graceful drain is attempted first, then the session is closed.
//!
//! # Thread-safety
//!
//! `Transport` is not `Sync`, so the inner `Mutex<Transport>` requires
//! external synchronization. `TransportBridgeManager` is `Send + Sync`
//! because all access goes through the `Mutex`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tidefs_membership_epoch::MemberId;
use tidefs_transport::addr::TransportAddr;
use tidefs_transport::{NodeInfo, SessionCloseReason, SessionId, Transport};

use crate::journal_sync_trigger::JournalSyncTrigger;
use crate::transport_bridge::TransportSessionManager;

/// Production implementation of [`TransportSessionManager`] that delegates
/// to `tidefs_transport::Transport`.
pub struct TransportBridgeManager {
    transport: Arc<Mutex<Transport>>,
    /// Local session registry: peer_id -> session_ids.
    sessions: Mutex<BTreeMap<MemberId, Vec<SessionId>>>,
    /// Optional journal sync trigger fired after successful session establishment.
    journal_sync_trigger: Mutex<Option<JournalSyncTrigger>>,
}

impl TransportBridgeManager {
    /// Create a new bridge manager wrapping the given transport.
    #[must_use]
    pub fn new(transport: Arc<Mutex<Transport>>) -> Self {
        Self {
            transport,
            sessions: Mutex::new(BTreeMap::new()),
            journal_sync_trigger: Mutex::new(None),
        }
    }

    /// Number of active sessions tracked.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions
            .lock()
            .unwrap()
            .values()
            .map(|v| v.len())
            .sum()
    }

    /// Whether a session is tracked for the given peer.
    #[must_use]
    pub fn has_peer(&self, peer_id: MemberId) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .get(&peer_id)
            .is_some_and(|v| !v.is_empty())
    }

    /// Set a journal sync trigger to fire after successful session establishment.
    ///
    /// When set, the trigger is called from `register_peer` after a transport
    /// session is established, pushing batched transition journal entries to
    /// the newly-connected peer so it can catch up on roster changes.
    pub fn set_journal_sync_trigger(&self, trigger: JournalSyncTrigger) {
        let mut guard = self.journal_sync_trigger.lock().unwrap();
        *guard = Some(trigger);
    }

    /// Remove the journal sync trigger.
    pub fn clear_journal_sync_trigger(&self) {
        let mut guard = self.journal_sync_trigger.lock().unwrap();
        *guard = None;
    }
}

impl TransportSessionManager for TransportBridgeManager {
    fn register_peer(&self, peer_id: MemberId, addresses: Vec<TransportAddr>) {
        let peer_node_id = peer_id.0;

        let session_id = {
            let mut transport = self.transport.lock().unwrap();

            // Register the peer in the cohort graph so connect() can find it.
            if !addresses.is_empty() {
                transport.add_node(NodeInfo::new(peer_node_id, addresses, 0));
            }

            // Proactive outbound connect.
            match transport.connect(peer_node_id) {
                Ok(sid) => {
                    // Perform handshake to complete establishment.
                    if let Err(e) = transport.perform_handshake(sid) {
                        eprintln!(
                            "transport_session_manager: handshake failed for peer {peer_node_id} session {sid}: {e}"
                        );
                        let _ = transport.close_session(sid, SessionCloseReason::TransportError);
                        return;
                    }
                    sid
                }
                Err(e) => {
                    eprintln!(
                        "transport_session_manager: connect failed for peer {peer_node_id}: {e}"
                    );
                    // Peer is still registered in cohort graph if addresses were
                    // provided, so inbound sessions can still be accepted.
                    return;
                }
            }
        }; // transport lock dropped

        // Record session for later teardown.
        {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.entry(peer_id).or_default().push(session_id);
        }

        // Fire journal sync trigger if configured
        {
            let trigger_guard = self.journal_sync_trigger.lock().unwrap();
            if let Some(ref trigger) = *trigger_guard {
                trigger.push_to_peer(peer_id);
            }
        }

        eprintln!(
            "transport_session_manager: established session {session_id} to peer {peer_node_id}"
        );
    }

    fn close_peer_sessions(&self, peer_id: MemberId) {
        let session_ids: Vec<SessionId> = {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.remove(&peer_id).unwrap_or_default()
        };

        if session_ids.is_empty() {
            return;
        }

        let mut transport = self.transport.lock().unwrap();
        for sid in &session_ids {
            // close_session with PeerRemoved internally drains pending
            // messages before closing; no separate drain call needed.
            if let Err(e) = transport.close_session(*sid, SessionCloseReason::PeerRemoved) {
                eprintln!(
                    "transport_session_manager: close_session failed for peer {} session {}: {}",
                    peer_id.0, sid, e
                );
            }
        }

        eprintln!(
            "transport_session_manager: closed {} sessions for peer {}",
            session_ids.len(),
            peer_id.0
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use tidefs_transport::Transport;

    fn mid(v: u64) -> MemberId {
        MemberId::new(v)
    }

    fn sid(v: u64) -> SessionId {
        SessionId(v)
    }

    fn make_manager() -> TransportBridgeManager {
        let transport = Transport::new(1);
        TransportBridgeManager::new(Arc::new(Mutex::new(transport)))
    }

    #[test]
    fn new_manager_has_no_sessions() {
        let mgr = make_manager();
        assert_eq!(mgr.session_count(), 0);
        assert!(!mgr.has_peer(mid(2)));
    }

    #[test]
    fn register_peer_without_addresses_is_noop() {
        let mgr = make_manager();
        mgr.register_peer(mid(2), vec![]);
        // No addresses -> peer not in cohort graph -> connect fails.
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn close_peer_sessions_unknown_peer_is_noop() {
        let mgr = make_manager();
        mgr.close_peer_sessions(mid(99));
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn session_count_after_manual_inserts() {
        let mgr = make_manager();
        {
            let mut sessions = mgr.sessions.lock().unwrap();
            sessions.insert(mid(2), vec![sid(100)]);
            sessions.insert(mid(3), vec![sid(200), sid(201)]);
        }
        assert_eq!(mgr.session_count(), 3);
        assert!(mgr.has_peer(mid(2)));
        assert!(mgr.has_peer(mid(3)));
        assert!(!mgr.has_peer(mid(4)));
    }

    #[test]
    fn close_peer_sessions_removes_tracking() {
        let mgr = make_manager();
        {
            let mut sessions = mgr.sessions.lock().unwrap();
            sessions.insert(mid(2), vec![sid(100)]);
        }
        assert!(mgr.has_peer(mid(2)));
        mgr.close_peer_sessions(mid(2));
        assert!(!mgr.has_peer(mid(2)));
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn multiple_sessions_per_peer() {
        let mgr = make_manager();
        {
            let mut sessions = mgr.sessions.lock().unwrap();
            sessions.insert(mid(5), vec![sid(10), sid(20), sid(30)]);
        }
        assert_eq!(mgr.session_count(), 3);
        mgr.close_peer_sessions(mid(5));
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn concurrent_peers_independent() {
        let mgr = make_manager();
        {
            let mut sessions = mgr.sessions.lock().unwrap();
            sessions.insert(mid(1), vec![sid(100)]);
            sessions.insert(mid(2), vec![sid(200)]);
            sessions.insert(mid(3), vec![sid(300), sid(301)]);
        }
        mgr.close_peer_sessions(mid(2));
        assert!(!mgr.has_peer(mid(2)));
        assert!(mgr.has_peer(mid(1)));
        assert!(mgr.has_peer(mid(3)));
    }

    #[test]
    fn is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TransportBridgeManager>();
    }
}
