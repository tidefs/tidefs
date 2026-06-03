//! First-time peer-join integration test through the deterministic
//! two-node transport harness.
//!
//! Node B (acceptor) runs a PeerJoinHandshake. Node A (new peer) connects
//! via the loopback transport and the join handshake delivers a
//! JoinStatePushMessage with the committed roster. After acceptance,
//! Node B's JoinQueue drains the new peer for the next proposal cycle.

use crate::TwoNodeHarness;
use std::sync::Arc;
use tidefs_membership_epoch::epoch_commit_subscriber::CommittedRoster;
use tidefs_membership_epoch::session_binding::RosterSessionRegistry;
use tidefs_membership_epoch::EpochId;
use tidefs_membership_live::peer_join::{PeerJoinHandshake, PeerJoinOutcome};
use tidefs_membership_types::MemberIdentity;
use tidefs_transport::join_state_push::JoinStatePushMessage;

// ── PeerJoinScenario ─────────────────────────────────────────────────────

/// A scenario that wires a PeerJoinHandshake into the acceptor side (Node B)
/// of the two-node harness and validates the first-time join path.
pub struct PeerJoinScenario {
    pub harness: TwoNodeHarness,
    /// The join handshake running on Node B (acceptor side, node_id=2).
    pub join_handshake: PeerJoinHandshake,
    /// Shared session registry used by the handshake.
    _registry: Arc<std::sync::RwLock<RosterSessionRegistry>>,
}

impl PeerJoinScenario {
    /// Create a new scenario with the given PRNG seed.
    pub fn new(seed: u64) -> Self {
        let harness = TwoNodeHarness::new(seed);

        let registry = Arc::new(std::sync::RwLock::new(RosterSessionRegistry::new()));
        let join_handshake = PeerJoinHandshake::new(Arc::clone(&registry));

        // Seed the handshake with an initial roster so Node A (id=1)
        // is NOT in it — making it a first-time join candidate.
        let initial_roster = CommittedRoster::new(EpochId(3), vec![2, 3, 4]); // node 1 is absent
        join_handshake.update_roster(initial_roster);

        Self {
            harness,
            join_handshake,
            _registry: registry,
        }
    }

    /// Establish the transport session between Node A and Node B.
    pub fn establish(&mut self) -> Result<(), String> {
        self.harness.establish_session()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Happy path: Node A (new peer) connects, join accepted, JoinStatePushMessage
    /// delivered with correct roster contents.
    #[test]
    fn fresh_peer_join_accepted_with_push_message() {
        let mut scenario = PeerJoinScenario::new(42);
        scenario.establish().expect("session establish");

        // Node A's identity (peer_id=1, epoch=3 matching roster epoch)
        let identity = MemberIdentity::new(1, 3);

        // Node B accepts the join — Node A is NOT in roster {2,3,4}
        let outcome = scenario.join_handshake.join_accept(
            1,   // peer_id = Node A
            100, // session_id
            identity,
        );

        match outcome {
            PeerJoinOutcome::Accepted { push_message } => {
                // Verify the push message carries the correct roster
                assert_eq!(push_message.joining_peer_id, 1);
                assert_eq!(push_message.push_seq, 1);
                assert_eq!(push_message.roster.epoch, EpochId(3));
                assert_eq!(push_message.roster.member_ids, vec![2, 3, 4]);
                // Node A should NOT be in the roster yet (queued for next epoch)
                assert!(!push_message.joining_peer_in_roster());

                // Verify wire-format round-trip
                let encoded = push_message.encode();
                let decoded =
                    JoinStatePushMessage::decode(&encoded).expect("decode JoinStatePushMessage");
                assert_eq!(decoded, push_message);
            }
            other => panic!("expected Accepted, got {other:?}"),
        }

        // Node B's join queue should contain peer 1, not the handshake's
        // internal queue — we verify the handshake's join_queue() instead.
        let drained: Vec<u64> = scenario.join_handshake.join_queue().drain();
        assert_eq!(drained, vec![1]);
        assert!(scenario.join_handshake.join_queue().is_empty());
    }

    /// Duplicate session rejection: same session ID used twice.
    #[test]
    fn duplicate_session_rejected() {
        let mut scenario = PeerJoinScenario::new(43);
        scenario.establish().expect("session establish");

        let identity = MemberIdentity::new(1, 3);

        // First join succeeds
        let o1 = scenario.join_handshake.join_accept(1, 100, identity);
        assert!(matches!(o1, PeerJoinOutcome::Accepted { .. }));

        // Second join with same session ID rejected
        let o2 = scenario
            .join_handshake
            .join_accept(5, 100, MemberIdentity::new(5, 3));
        assert!(matches!(
            o2,
            PeerJoinOutcome::DuplicateSession {
                existing_session_id: 100
            }
        ));

        // Drain queue — only peer 1 should be present
        let drained = scenario.join_handshake.join_queue().drain();
        assert_eq!(drained, vec![1]);
    }

    /// Peer already in the roster returns AlreadyRostered.
    #[test]
    fn already_rostered_peer_rejected() {
        let mut scenario = PeerJoinScenario::new(44);
        scenario.establish().expect("session establish");

        // Node 2 is in the roster {2,3,4}
        let outcome = scenario
            .join_handshake
            .join_accept(2, 100, MemberIdentity::new(2, 3));
        assert_eq!(outcome, PeerJoinOutcome::AlreadyRostered);
        assert!(scenario.join_handshake.join_queue().is_empty());
    }

    /// Multiple first-time peers queue in FIFO order.
    #[test]
    fn multiple_fresh_peers_queue_fifo() {
        let mut scenario = PeerJoinScenario::new(45);
        scenario.establish().expect("session establish");

        for (peer_id, session_id) in &[(1u64, 100u64), (5u64, 101u64), (6u64, 102u64)] {
            let outcome = scenario.join_handshake.join_accept(
                *peer_id,
                *session_id,
                MemberIdentity::new(*peer_id, 3),
            );
            assert!(
                matches!(outcome, PeerJoinOutcome::Accepted { .. }),
                "peer {peer_id} should be accepted"
            );
        }

        let drained = scenario.join_handshake.join_queue().drain();
        assert_eq!(drained, vec![1, 5, 6]);
    }

    /// Push sequence is monotonic across multiple joins.
    #[test]
    fn push_seq_monotonic_across_joins() {
        let mut scenario = PeerJoinScenario::new(46);
        scenario.establish().expect("session establish");

        let mut seqs = Vec::new();
        for i in 0..5u64 {
            let peer_id = 10 + i;
            let outcome = scenario.join_handshake.join_accept(
                peer_id,
                200 + i,
                MemberIdentity::new(peer_id, 3),
            );
            match outcome {
                PeerJoinOutcome::Accepted { push_message } => {
                    seqs.push(push_message.push_seq);
                    // Verify each push message encodes/decodes correctly
                    let enc = push_message.encode();
                    let dec = JoinStatePushMessage::decode(&enc).unwrap();
                    assert_eq!(dec.push_seq, push_message.push_seq);
                    assert_eq!(dec.joining_peer_id, peer_id);
                }
                other => panic!("unexpected {other:?} for peer {peer_id}"),
            }
        }

        assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
    }

    /// Roster update changes subsequent join behavior:
    /// a peer that was unknown becomes AlreadyRostered after update.
    #[test]
    fn roster_update_changes_peer_status() {
        let mut scenario = PeerJoinScenario::new(47);
        scenario.establish().expect("session establish");

        // Peer 99 is not in roster → accepted
        let o1 = scenario
            .join_handshake
            .join_accept(99, 100, MemberIdentity::new(99, 3));
        assert!(matches!(o1, PeerJoinOutcome::Accepted { .. }));
        scenario.join_handshake.join_queue().drain(); // clear

        // Update roster to include 99
        let new_roster = CommittedRoster::new(EpochId(4), vec![2, 3, 4, 99]);
        scenario.join_handshake.update_roster(new_roster);

        // Now 99 is already rostered
        let o2 = scenario
            .join_handshake
            .join_accept(99, 200, MemberIdentity::new(99, 4));
        assert_eq!(o2, PeerJoinOutcome::AlreadyRostered);
    }

    /// JoinStatePushMessage for a peer not in roster has joining_peer_in_roster=false.
    #[test]
    fn push_message_joining_peer_not_in_roster() {
        let mut scenario = PeerJoinScenario::new(48);
        scenario.establish().expect("session establish");

        let outcome = scenario
            .join_handshake
            .join_accept(99, 100, MemberIdentity::new(99, 3));
        match outcome {
            PeerJoinOutcome::Accepted { push_message } => {
                assert!(!push_message.joining_peer_in_roster());
            }
            other => panic!("expected Accepted, got {other:?}"),
        }
    }
}
