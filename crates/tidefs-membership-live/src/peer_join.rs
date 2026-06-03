//! First-time peer-join transport handshake with epoch-state bootstrap
//! and roster-inclusion queuing.
//!
//! [`PeerJoinHandshake`] bridges first-time transport connections to the
//! membership roster. When a peer connects that is not yet in the committed
//! roster, the handshake verifies the peer identity, pushes the current
//! committed epoch view via a [`JoinStatePushMessage`], registers a session
//! binding, and queues the peer for roster inclusion in the next epoch
//! proposal.
//!
//! This closes the gap between raw transport connection acceptance and
//! roster membership. It is the first-time-join complement to:
//! - [`crate::reconnect_handshake::PeerReconnectHandshake`] (reconnect
//!   of known peers)
//! - [`crate::peer_add_connector::PeerAddConnector`] (adds peers on epoch
//!   commit)
//! - [`crate::peer_eviction::EvictionExecutor`] (removes peers on epoch
//!   commit)
//!
//! # Architecture
//!
//! 1. Transport accepts a new connection and verifies the peer identity.
//! 2. The transport acceptance path calls
//!    [`PeerJoinHandshake::join_accept`] with the peer id, session id,
//!    and verified identity.
//! 3. If the peer is already in the roster → [`PeerJoinOutcome::AlreadyRostered`].
//! 4. If the session is already bound → [`PeerJoinOutcome::DuplicateSession`].
//! 5. Otherwise: register the session binding, create a
//!    [`JoinStatePushMessage`] with the current committed roster, queue
//!    the peer for roster inclusion, and return
//!    [`PeerJoinOutcome::Accepted`].
//! 6. The [`JoinQueue`] is drained by the epoch-proposal constructor to
//!    include the new peers in the next roster.
//!
//! # Integration
//!
//! ```ignore
//! use tidefs_membership_live::peer_join::{PeerJoinHandshake, PeerJoinOutcome};
//!
//! let handshake = PeerJoinHandshake::new(registry.clone());
//!
//! // Register for roster updates via the ConnectionAcceptor's
//! // EpochCommitSubscriber or direct roster update.
//! handshake.update_roster(committed_roster);
//!
//! match handshake.join_accept(peer_id, session_id, identity) {
//!     PeerJoinOutcome::Accepted { push_message } => {
//!         // Deliver push_message to the joining peer over transport.
//!     }
//!     PeerJoinOutcome::AlreadyRostered => {
//!         // Fall through to reconnect handshake.
//!     }
//!     PeerJoinOutcome::DuplicateSession { .. } => {
//!         // Reject duplicate connection.
//!     }
//!     PeerJoinOutcome::Rejected { reason } => {
//!         // Identity verification or policy rejection.
//!     }
//! }
//! ```

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, RwLock};

use tidefs_membership_epoch::epoch_commit_subscriber::CommittedRoster;
use tidefs_membership_epoch::session_binding::{RosterSessionRegistry, SessionBindingError};
use tidefs_membership_epoch::transition_journal::{MembershipTransitionJournal, TransitionKind};
use tidefs_membership_types::MemberIdentity;
use tidefs_transport::join_state_push::JoinStatePushMessage;

// ---------------------------------------------------------------------------
// PeerJoinOutcome
// ---------------------------------------------------------------------------

/// Result of a first-time peer-join attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerJoinOutcome {
    /// Join accepted — deliver the push message to the joining peer and
    /// add the peer to the next epoch proposal via the join queue.
    Accepted {
        /// The join-state push message to deliver to the peer.
        push_message: JoinStatePushMessage,
    },
    /// Peer is already in the committed roster — fall through to the
    /// reconnect handshake path.
    AlreadyRostered,
    /// Session with this ID is already bound — reject duplicate.
    DuplicateSession {
        /// The session ID that is already bound.
        existing_session_id: u64,
    },
    /// Identity or policy rejection.
    Rejected {
        /// Human-readable reason for rejection.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// JoinQueue
// ---------------------------------------------------------------------------

/// Drains queued peer node IDs for inclusion in the next epoch proposal.
///
/// [`PeerJoinHandshake`] pushes peers into the queue when a join is
/// accepted. The epoch-proposal constructor drains the queue to include
/// the new peers in the roster.
#[derive(Debug, Default)]
pub struct JoinQueue {
    queue: RwLock<VecDeque<u64>>,
}

impl JoinQueue {
    /// Create an empty join queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            queue: RwLock::new(VecDeque::new()),
        }
    }

    /// Push a peer onto the queue for roster inclusion.
    pub fn push(&self, peer_id: u64) {
        self.queue
            .write()
            .expect("join queue lock poisoned")
            .push_back(peer_id);
    }

    /// Drain all queued peers in FIFO order.
    ///
    /// Returns the set of peer IDs that have been accepted since the last
    /// drain. These should be included in the next epoch proposal.
    pub fn drain(&self) -> Vec<u64> {
        let mut q = self.queue.write().expect("join queue lock poisoned");
        q.drain(..).collect()
    }

    /// Number of peers currently queued.
    #[must_use]
    pub fn queued_count(&self) -> usize {
        self.queue.read().expect("join queue lock poisoned").len()
    }

    /// Whether the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queued_count() == 0
    }
}

// ---------------------------------------------------------------------------
// PeerJoinHandshake
// ---------------------------------------------------------------------------

type PeerJoinedCallback = Box<dyn Fn(u64) + Send + Sync>;

/// Manages first-time peer-join handshake on the acceptor side.
///
/// Accepts transport connections from peers not yet in the committed roster,
/// verifies their identity, pushes the current committed epoch state, registers
/// a session binding, and queues the peer for roster inclusion.
pub struct PeerJoinHandshake {
    /// Shared session registry for registering new session bindings.
    registry: Arc<RwLock<RosterSessionRegistry>>,
    /// Monotonic push sequence number for join-state push messages.
    push_seq: RwLock<u64>,
    /// Queue of peers awaiting roster inclusion.
    join_queue: JoinQueue,
    /// Cached committed roster for identity verification and push-message
    /// construction.
    current_roster: RwLock<Option<CommittedRoster>>,
    /// Callback invoked when a peer is accepted for join.
    on_peer_joined: RwLock<Option<PeerJoinedCallback>>,
    /// Optional transition journal for coordinator crash-recovery replay.
    journal: Option<Arc<Mutex<MembershipTransitionJournal>>>,
}

impl PeerJoinHandshake {
    /// Create a new join handshake.
    ///
    /// `registry` — the shared [`RosterSessionRegistry`] used to register
    ///   session bindings for joining peers.
    #[must_use]
    pub fn new(registry: Arc<RwLock<RosterSessionRegistry>>) -> Self {
        Self {
            registry,
            push_seq: RwLock::new(0),
            join_queue: JoinQueue::new(),
            current_roster: RwLock::new(None),
            on_peer_joined: RwLock::new(None),
            journal: None,
        }
    }

    /// Set the callback invoked when a peer is accepted for join.
    ///
    /// The callback receives the joining peer's node ID. Use this to notify
    /// the epoch coordinator or transport layer of the new peer.
    pub fn set_peer_joined_callback<F: Fn(u64) + Send + Sync + 'static>(&self, cb: F) {
        *self.on_peer_joined.write().expect("lock poisoned") = Some(Box::new(cb));
    }

    /// Update the cached committed roster.
    ///
    /// Call this when the epoch advances so that new join attempts receive
    /// the current roster state.
    pub fn update_roster(&self, roster: CommittedRoster) {
        *self.current_roster.write().expect("lock poisoned") = Some(roster);
    }

    /// Set the transition journal for crash-recovery recording.
    pub fn set_journal(&mut self, journal: Arc<Mutex<MembershipTransitionJournal>>) {
        self.journal = Some(journal);
    }

    /// Process a first-time peer-join attempt.
    ///
    /// # Arguments
    /// * `peer_id` — Node ID of the joining peer.
    /// * `session_id` — Transport-level session identifier.
    /// * `identity` — Verified [`MemberIdentity`] of the peer.
    ///
    /// # Returns
    /// * `Accepted { push_message }` — peer accepted; deliver the push
    ///   message to the peer.
    /// * `AlreadyRostered` — peer is already in the committed roster;
    ///   use the reconnect handshake path instead.
    /// * `DuplicateSession` — session ID is already bound; reject.
    /// * `Rejected` — identity verification or policy rejection.
    pub fn join_accept(
        &self,
        peer_id: u64,
        session_id: u64,
        identity: MemberIdentity,
    ) -> PeerJoinOutcome {
        use tidefs_membership_epoch::transition_journal::current_time_millis;
        use tidefs_membership_epoch::{EpochId, MemberId};

        let now_millis = current_time_millis();
        let member_id = MemberId::new(peer_id);

        // Determine the current epoch from the roster.
        let roster_guard = self.current_roster.read().expect("roster lock poisoned");
        let current_epoch = roster_guard
            .as_ref()
            .map(|r| r.epoch)
            .unwrap_or(EpochId::ZERO);
        // Journal prepare: record join intent before any side effects.
        let journal_id = self.journal.as_ref().map(|j| {
            j.lock().expect("journal lock poisoned").record_prepare(
                TransitionKind::Join {
                    peer_id: member_id,
                    epoch: current_epoch,
                },
                now_millis,
            )
        });

        // 1. Check if already in roster → AlreadyRostered
        if let Some(ref roster) = *roster_guard {
            if roster.contains(peer_id) {
                self.abort_journal(journal_id, now_millis);
                return PeerJoinOutcome::AlreadyRostered;
            }
        }

        // 2. Register session binding directly with the registry.
        {
            let mut reg = self.registry.write().expect("registry lock poisoned");
            match reg.register(session_id, identity) {
                Ok(()) => {}
                Err(SessionBindingError::DuplicateSession { .. }) => {
                    self.abort_journal(journal_id, now_millis);
                    return PeerJoinOutcome::DuplicateSession {
                        existing_session_id: session_id,
                    };
                }
                Err(e) => {
                    self.abort_journal(journal_id, now_millis);
                    return PeerJoinOutcome::Rejected {
                        reason: format!("session registration failed: {e}"),
                    };
                }
            }
        }
        drop(roster_guard);

        // 3. Create JoinStatePushMessage
        let roster_snap = self.current_roster.read().expect("roster lock poisoned");
        let push_message = if let Some(ref roster) = *roster_snap {
            let mut seq = self.push_seq.write().expect("push_seq lock poisoned");
            *seq += 1;
            JoinStatePushMessage::new(*seq, roster.clone(), peer_id)
        } else {
            let mut seq = self.push_seq.write().expect("push_seq lock poisoned");
            *seq += 1;
            let empty_roster = CommittedRoster::new(EpochId::ZERO, vec![]);
            JoinStatePushMessage::new(*seq, empty_roster, peer_id)
        };
        drop(roster_snap);

        // 4. Queue peer for roster inclusion
        self.join_queue.push(peer_id);

        // 5. Fire callback
        if let Some(cb) = self.on_peer_joined.read().expect("lock poisoned").as_ref() {
            cb(peer_id);
        }

        self.commit_journal(journal_id, now_millis);
        PeerJoinOutcome::Accepted { push_message }
    }

    /// Explicitly reject a join attempt without registering a session.
    ///
    /// Use this when a join policy check fails before session registration.
    #[must_use]
    pub fn join_reject(&self, reason: String) -> PeerJoinOutcome {
        PeerJoinOutcome::Rejected { reason }
    }

    // ── Private journal helpers ──────────────────────────────────────

    fn abort_journal(
        &self,
        id: Option<tidefs_membership_epoch::transition_journal::TransitionId>,
        now_millis: u64,
    ) {
        if let (Some(id), Some(ref j)) = (id, &self.journal) {
            let mut guard = j.lock().expect("journal lock poisoned");
            guard.record_abort(id, now_millis);
        }
    }

    fn commit_journal(
        &self,
        id: Option<tidefs_membership_epoch::transition_journal::TransitionId>,
        now_millis: u64,
    ) {
        if let (Some(id), Some(ref j)) = (id, &self.journal) {
            let mut guard = j.lock().expect("journal lock poisoned");
            guard.record_commit(id, now_millis);
        }
    }

    /// Return a reference to the join queue for draining by the epoch
    /// proposal constructor.
    #[must_use]
    pub fn join_queue(&self) -> &JoinQueue {
        &self.join_queue
    }

    /// Current push sequence number.
    #[must_use]
    pub fn current_push_seq(&self) -> u64 {
        *self.push_seq.read().expect("push_seq lock poisoned")
    }

    /// Return the current cached roster, if any.
    #[must_use]
    pub fn current_roster_snapshot(&self) -> Option<CommittedRoster> {
        self.current_roster.read().expect("lock poisoned").clone()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc as StdArc;
    use std::sync::Mutex;

    use tidefs_membership_epoch::epoch_commit_subscriber::CommittedRoster;
    use tidefs_membership_epoch::session_binding::RosterSessionRegistry;
    use tidefs_membership_epoch::EpochId;
    use tidefs_membership_types::MemberIdentity;

    fn mk_id(node: u64, epoch: u64) -> MemberIdentity {
        MemberIdentity::new(node, epoch)
    }

    fn mk_roster(epoch: u64, ids: Vec<u64>) -> CommittedRoster {
        CommittedRoster::new(EpochId(epoch), ids)
    }

    fn make_handshake_with_roster(epoch: u64, members: &[u64]) -> PeerJoinHandshake {
        let reg = Arc::new(std::sync::RwLock::new(RosterSessionRegistry::new()));
        let hs = PeerJoinHandshake::new(Arc::clone(&reg));
        hs.update_roster(mk_roster(epoch, members.to_vec()));
        hs
    }

    // ------------------------------------------------------------------
    // Happy path: peer joins successfully
    // ------------------------------------------------------------------

    #[test]
    fn new_peer_accepted_and_push_message_created() {
        let reg = Arc::new(std::sync::RwLock::new(RosterSessionRegistry::new()));
        let hs = PeerJoinHandshake::new(Arc::clone(&reg));
        hs.update_roster(mk_roster(5, vec![10, 20, 30]));

        let outcome = hs.join_accept(99, 100, mk_id(99, 5));

        match outcome {
            PeerJoinOutcome::Accepted { push_message } => {
                assert_eq!(push_message.joining_peer_id, 99);
                assert_eq!(push_message.push_seq, 1);
                assert_eq!(push_message.roster.member_ids, vec![10, 20, 30]);
                assert_eq!(push_message.roster.epoch, EpochId(5));
            }
            other => panic!("expected Accepted, got {other:?}"),
        }

        // Peer is in the join queue
        assert_eq!(hs.join_queue().queued_count(), 1);
        let drained = hs.join_queue().drain();
        assert_eq!(drained, vec![99]);
        assert!(hs.join_queue().is_empty());
    }

    #[test]
    fn session_binding_registered_after_join() {
        let reg = Arc::new(std::sync::RwLock::new(RosterSessionRegistry::new()));
        let hs = PeerJoinHandshake::new(Arc::clone(&reg));
        hs.update_roster(mk_roster(3, vec![1, 2, 3]));

        let _ = hs.join_accept(99, 200, mk_id(99, 3));

        let registry = reg.read().unwrap();
        let identity = registry.lookup(200);
        assert!(identity.is_some());
        assert_eq!(identity.unwrap().node_id, 99);
    }

    // ------------------------------------------------------------------
    // AlreadyRostered: peer is in the committed roster
    // ------------------------------------------------------------------

    #[test]
    fn already_rostered_peer_rejected() {
        let hs = make_handshake_with_roster(5, &[10, 20, 30]);

        let outcome = hs.join_accept(20, 100, mk_id(20, 5));
        assert_eq!(outcome, PeerJoinOutcome::AlreadyRostered);
        assert!(hs.join_queue().is_empty());
    }

    // ------------------------------------------------------------------
    // DuplicateSession: session ID already bound
    // ------------------------------------------------------------------

    #[test]
    fn duplicate_session_rejected() {
        let reg = Arc::new(std::sync::RwLock::new(RosterSessionRegistry::new()));
        let hs = PeerJoinHandshake::new(Arc::clone(&reg));
        hs.update_roster(mk_roster(3, vec![1, 2]));

        // First join succeeds
        let outcome1 = hs.join_accept(99, 100, mk_id(99, 3));
        assert!(matches!(outcome1, PeerJoinOutcome::Accepted { .. }));

        // Second join with same session ID is rejected
        let outcome2 = hs.join_accept(88, 100, mk_id(88, 3));
        assert_eq!(
            outcome2,
            PeerJoinOutcome::DuplicateSession {
                existing_session_id: 100
            }
        );
    }

    // ------------------------------------------------------------------
    // No roster: joins still accepted with empty roster push
    // ------------------------------------------------------------------

    #[test]
    fn join_before_roster_available() {
        let reg = Arc::new(std::sync::RwLock::new(RosterSessionRegistry::new()));
        let hs = PeerJoinHandshake::new(Arc::clone(&reg));

        let outcome = hs.join_accept(42, 100, mk_id(42, 0));

        match outcome {
            PeerJoinOutcome::Accepted { push_message } => {
                assert_eq!(push_message.joining_peer_id, 42);
                assert!(push_message.roster.member_ids.is_empty());
                assert_eq!(push_message.roster.epoch, EpochId(0));
            }
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // Join queue: push and drain semantics
    // ------------------------------------------------------------------

    #[test]
    fn join_queue_fifo_order() {
        let jq = JoinQueue::new();
        assert!(jq.is_empty());
        assert_eq!(jq.queued_count(), 0);

        jq.push(10);
        jq.push(20);
        jq.push(30);
        assert_eq!(jq.queued_count(), 3);

        let drained = jq.drain();
        assert_eq!(drained, vec![10, 20, 30]);
        assert!(jq.is_empty());
    }

    #[test]
    fn join_queue_multiple_drains() {
        let jq = JoinQueue::new();

        jq.push(1);
        jq.push(2);
        assert_eq!(jq.drain(), vec![1, 2]);
        assert!(jq.is_empty());

        jq.push(3);
        jq.push(4);
        jq.push(5);
        assert_eq!(jq.drain(), vec![3, 4, 5]);
        assert!(jq.is_empty());
    }

    #[test]
    fn join_queue_drain_empty() {
        let jq = JoinQueue::new();
        assert!(jq.drain().is_empty());
    }

    #[test]
    fn multiple_peers_queue_correctly() {
        let reg = Arc::new(std::sync::RwLock::new(RosterSessionRegistry::new()));
        let hs = PeerJoinHandshake::new(Arc::clone(&reg));
        hs.update_roster(mk_roster(1, vec![1]));

        // Accept three peers
        for (peer_id, session_id) in &[(10u64, 100u64), (20u64, 101u64), (30u64, 102u64)] {
            let outcome = hs.join_accept(*peer_id, *session_id, mk_id(*peer_id, 1));
            assert!(matches!(outcome, PeerJoinOutcome::Accepted { .. }));
        }

        assert_eq!(hs.join_queue().queued_count(), 3);
        let drained = hs.join_queue().drain();
        assert_eq!(drained, vec![10, 20, 30]);
    }

    // ------------------------------------------------------------------
    // Push sequence: monotonic
    // ------------------------------------------------------------------

    #[test]
    fn push_seq_is_monotonic() {
        let reg = Arc::new(std::sync::RwLock::new(RosterSessionRegistry::new()));
        let hs = PeerJoinHandshake::new(Arc::clone(&reg));
        hs.update_roster(mk_roster(1, vec![1]));

        let mut seqs = Vec::new();
        for i in 0..5u64 {
            let outcome = hs.join_accept(100 + i, 200 + i, mk_id(100 + i, 1));
            match outcome {
                PeerJoinOutcome::Accepted { push_message } => {
                    seqs.push(push_message.push_seq);
                }
                other => panic!("unexpected {other:?}"),
            }
        }

        assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
        assert_eq!(hs.current_push_seq(), 5);
    }

    // ------------------------------------------------------------------
    // Callback
    // ------------------------------------------------------------------

    #[test]
    fn peer_joined_callback_fires() {
        let reg = Arc::new(std::sync::RwLock::new(RosterSessionRegistry::new()));
        let hs = PeerJoinHandshake::new(Arc::clone(&reg));
        hs.update_roster(mk_roster(1, vec![1]));

        let calls = StdArc::new(Mutex::new(Vec::new()));
        let c2 = StdArc::clone(&calls);
        hs.set_peer_joined_callback(move |peer_id| {
            c2.lock().unwrap().push(peer_id);
        });

        let _ = hs.join_accept(42, 100, mk_id(42, 1));
        let _ = hs.join_accept(43, 101, mk_id(43, 1));

        let c = calls.lock().unwrap();
        assert_eq!(*c, vec![42, 43]);
    }

    #[test]
    fn callback_not_fired_for_already_rostered() {
        let hs = make_handshake_with_roster(5, &[10, 20, 30]);

        let calls = StdArc::new(Mutex::new(Vec::new()));
        let c2 = StdArc::clone(&calls);
        hs.set_peer_joined_callback(move |peer_id| {
            c2.lock().unwrap().push(peer_id);
        });

        let _ = hs.join_accept(20, 100, mk_id(20, 5));
        assert!(calls.lock().unwrap().is_empty());
    }

    // ------------------------------------------------------------------
    // join_reject
    // ------------------------------------------------------------------

    #[test]
    fn explicit_join_reject() {
        let hs = make_handshake_with_roster(5, &[10, 20]);
        let outcome = hs.join_reject("policy denied".into());
        assert_eq!(
            outcome,
            PeerJoinOutcome::Rejected {
                reason: "policy denied".into()
            }
        );
    }

    // ------------------------------------------------------------------
    // Roster update
    // ------------------------------------------------------------------

    #[test]
    fn roster_update_changes_roster_snapshot() {
        let hs = make_handshake_with_roster(1, &[1]);

        assert_eq!(hs.current_roster_snapshot().unwrap().member_ids, vec![1]);

        hs.update_roster(mk_roster(2, vec![1, 2, 3]));
        assert_eq!(
            hs.current_roster_snapshot().unwrap().member_ids,
            vec![1, 2, 3]
        );
    }

    #[test]
    fn peer_in_updated_roster_is_already_rostered() {
        let hs = make_handshake_with_roster(1, &[1]);

        // Peer 99 not in initial roster → accepted
        let o1 = hs.join_accept(99, 100, mk_id(99, 1));
        assert!(matches!(o1, PeerJoinOutcome::Accepted { .. }));
        assert_eq!(hs.join_queue().queued_count(), 1);
        hs.join_queue().drain();

        // Update roster to include 99
        hs.update_roster(mk_roster(2, vec![1, 99]));

        // Now 99 is already rostered
        let o2 = hs.join_accept(99, 200, mk_id(99, 2));
        assert_eq!(o2, PeerJoinOutcome::AlreadyRostered);
    }

    // ------------------------------------------------------------------
    // JoinStatePushMessage round-trip through transport wire format
    // ------------------------------------------------------------------

    #[test]
    fn join_state_push_message_roundtrip() {
        let roster = mk_roster(7, vec![10, 20, 30, 40]);
        let msg = JoinStatePushMessage::new(3, roster.clone(), 99);
        let encoded = msg.encode();
        let decoded = JoinStatePushMessage::decode(&encoded).unwrap();

        assert_eq!(decoded.push_seq, 3);
        assert_eq!(decoded.roster.member_ids, vec![10, 20, 30, 40]);
        assert_eq!(decoded.roster.epoch, EpochId(7));
        assert_eq!(decoded.roster.roster_hash, roster.roster_hash);
        assert_eq!(decoded.joining_peer_id, 99);
    }

    #[test]
    fn join_state_push_message_joining_peer_not_in_roster() {
        let roster = mk_roster(3, vec![1, 2, 3]);
        let msg = JoinStatePushMessage::new(1, roster, 99);
        assert!(!msg.joining_peer_in_roster());
    }

    // ------------------------------------------------------------------
    // PeerJoinOutcome traits
    // ------------------------------------------------------------------

    #[test]
    fn peer_join_outcome_eq() {
        let r = mk_roster(1, vec![1]);
        let msg1 = JoinStatePushMessage::new(1, r.clone(), 99);
        let msg2 = JoinStatePushMessage::new(1, r.clone(), 99);

        let a1 = PeerJoinOutcome::Accepted { push_message: msg1 };
        let a2 = PeerJoinOutcome::Accepted { push_message: msg2 };
        assert_eq!(a1, a2);

        assert_eq!(
            PeerJoinOutcome::AlreadyRostered,
            PeerJoinOutcome::AlreadyRostered
        );
        assert_ne!(
            PeerJoinOutcome::AlreadyRostered,
            PeerJoinOutcome::DuplicateSession {
                existing_session_id: 100
            }
        );
    }

    #[test]
    fn peer_join_outcome_debug() {
        let outcome = PeerJoinOutcome::Rejected {
            reason: "no".into(),
        };
        let s = format!("{outcome:?}");
        assert!(s.contains("no"));
    }
}
