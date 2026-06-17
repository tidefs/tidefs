//! Two-node harness integration test for deterministic membership lease
//! transitions. Exercises the full lease lifecycle — acquire, renew,
//! release — across two simulated nodes using the deterministic loopback
//! transport harness.
//!
//! ## Scenario
//!
//! Node 1 acts as the lease holder; Node 2 acts as the lease authority.
//! The harness exchanges encoded [`tidefs_cluster::MembershipLeaseMessage`]
//! values through the deterministic loopback transport.
//!
//! ## BLAKE3 integrity
//!
//! All messages carry BLAKE3 digests verified during decode. The lease
//! state machine digests are recorded before and after the full cycle to
//! provide deterministic validation.

use blake3::Hasher;
use tidefs_cluster::{
    AcquireRequest, LeaseAuthority, LeaseState, LeaseStateMachine, MembershipLeaseMessage,
    ReleaseRequest, RenewRequest,
};
use tidefs_membership_epoch::{EpochId, NodeIdentity};
use tidefs_two_node_harness::TwoNodeHarness;

fn epoch(id: u64) -> EpochId {
    EpochId(id)
}

// ── Helpers ──────────────────────────────────────────────────────────

fn encode_msg(msg: &MembershipLeaseMessage) -> (Vec<u8>, [u8; 32]) {
    let encoded = msg.encode().expect("encode");
    let mut h = Hasher::new();
    h.update(&encoded);
    let digest: [u8; 32] = h.finalize().into();
    (encoded, digest)
}

fn decode_msg(data: &[u8]) -> MembershipLeaseMessage {
    MembershipLeaseMessage::decode(data).expect("decode")
}

/// Drain all pending messages for a node from the harness.
fn drain_msgs(h: &mut TwoNodeHarness, from_a: bool) -> Vec<Vec<u8>> {
    if from_a {
        let mut out = Vec::new();
        while let Some(msg) = h.node_a.transport.recv() {
            out.push(msg.payload);
        }
        h.node_a.received.clear();
        out
    } else {
        let mut out = Vec::new();
        while let Some(msg) = h.node_b.transport.recv() {
            out.push(msg.payload);
        }
        h.node_b.received.clear();
        out
    }
}

fn send_a_to_b(h: &mut TwoNodeHarness, payload: Vec<u8>) {
    h.node_a.transport.send(NodeIdentity::new(2), 0, payload);
}

fn send_b_to_a(h: &mut TwoNodeHarness, payload: Vec<u8>) {
    h.node_b.transport.send(NodeIdentity::new(1), 0, payload);
}

// ── Full lifecycle test ──────────────────────────────────────────────

#[test]
fn two_node_lease_acquire_renew_release_cycle() {
    let mut h = TwoNodeHarness::new(42);
    h.establish_session().expect("session establish");

    let mut authority = LeaseAuthority::new(epoch(1));
    let mut sm_node1 = LeaseStateMachine::new(1, epoch(1));

    let digest_initial_sm = sm_node1.state_digest();

    // ── Phase 1: Acquire ──────────────────────────────────────────

    sm_node1
        .acquire(epoch(1), 30_000, 0, 100, 0)
        .expect("acquire");
    assert_eq!(sm_node1.state(), LeaseState::Acquiring);
    let digest_acquiring = sm_node1.state_digest();
    assert_ne!(digest_acquiring, digest_initial_sm);

    let acquire_msg = MembershipLeaseMessage::Acquire(AcquireRequest {
        node_id: 1,
        epoch: epoch(1),
        slot: 0,
        lease_term_ms: 30_000,
        request_id: 100,
    });
    let (encoded, _digest) = encode_msg(&acquire_msg);

    send_a_to_b(&mut h, encoded);
    h.tick();

    // Node 2 receives and processes as authority
    let msgs_b = drain_msgs(&mut h, false);
    assert_eq!(msgs_b.len(), 1, "node 2 should receive acquire request");
    let decoded = decode_msg(&msgs_b[0]);

    let lease_id = match &decoded {
        MembershipLeaseMessage::Acquire(req) => {
            let outcome = authority.handle_acquire(req);
            match outcome {
                tidefs_cluster::AcquireOutcome::Ack(ack) => {
                    let ack_msg = MembershipLeaseMessage::AcquireAck(ack.clone());
                    let (encoded_ack, _) = encode_msg(&ack_msg);
                    send_b_to_a(&mut h, encoded_ack);
                    h.tick();
                    ack.lease_id
                }
                tidefs_cluster::AcquireOutcome::Nack(nack) => {
                    panic!("acquire denied: {}", nack.reason);
                }
            }
        }
        _ => panic!("expected Acquire, got {decoded:?}"),
    };
    assert_eq!(lease_id, 1);
    assert!(authority.is_slot_occupied(0));

    // Node 1 receives ack and transitions to Held
    let msgs_a = drain_msgs(&mut h, true);
    assert_eq!(msgs_a.len(), 1, "node 1 should receive acquire ack");
    let decoded_ack = decode_msg(&msgs_a[0]);
    match &decoded_ack {
        MembershipLeaseMessage::AcquireAck(_ack) => {
            sm_node1.grant().expect("grant");
        }
        _ => panic!("expected AcquireAck, got {decoded_ack:?}"),
    }
    assert_eq!(sm_node1.state(), LeaseState::Held);
    let digest_held = sm_node1.state_digest();
    assert_ne!(digest_held, digest_acquiring);

    // ── Phase 2: Renew ────────────────────────────────────────────

    sm_node1.renew(epoch(1), 10_000).expect("renew");
    assert_eq!(sm_node1.state(), LeaseState::Renewing);
    let digest_renewing = sm_node1.state_digest();
    assert_ne!(digest_renewing, digest_held);

    let renew_msg = MembershipLeaseMessage::Renew(RenewRequest {
        node_id: 1,
        lease_id,
        epoch: epoch(1),
    });
    let (encoded_renew, _) = encode_msg(&renew_msg);

    send_a_to_b(&mut h, encoded_renew);
    h.tick();

    let msgs_b = drain_msgs(&mut h, false);
    assert_eq!(msgs_b.len(), 1);
    let decoded_renew = decode_msg(&msgs_b[0]);
    match &decoded_renew {
        MembershipLeaseMessage::Renew(req) => {
            let outcome = authority.handle_renew(req, 60_000);
            match outcome {
                tidefs_cluster::RenewOutcome::Ack(ack) => {
                    let ack_msg = MembershipLeaseMessage::RenewAck(ack);
                    let (encoded_ack, _) = encode_msg(&ack_msg);
                    send_b_to_a(&mut h, encoded_ack);
                    h.tick();
                }
                tidefs_cluster::RenewOutcome::Nack(nack) => {
                    panic!("renew denied: {}", nack.reason);
                }
            }
        }
        _ => panic!("expected Renew, got {decoded_renew:?}"),
    }

    let msgs_a = drain_msgs(&mut h, true);
    assert_eq!(msgs_a.len(), 1);
    let decoded_renew_ack = decode_msg(&msgs_a[0]);
    match &decoded_renew_ack {
        MembershipLeaseMessage::RenewAck(_) => {
            sm_node1.renew_ack().expect("renew_ack");
        }
        _ => panic!("expected RenewAck, got {decoded_renew_ack:?}"),
    }
    assert_eq!(sm_node1.state(), LeaseState::Held);

    // ── Phase 3: Release ──────────────────────────────────────────

    sm_node1.release().expect("release");
    assert_eq!(sm_node1.state(), LeaseState::Released);
    assert!(sm_node1.lease().is_none());
    let digest_released = sm_node1.state_digest();
    assert_ne!(digest_released, digest_held);

    let release_msg = MembershipLeaseMessage::Release(ReleaseRequest {
        node_id: 1,
        lease_id,
        epoch: epoch(1),
    });
    let (encoded_release, _) = encode_msg(&release_msg);

    send_a_to_b(&mut h, encoded_release);
    h.tick();

    let msgs_b = drain_msgs(&mut h, false);
    assert_eq!(msgs_b.len(), 1);
    let decoded_release = decode_msg(&msgs_b[0]);
    match &decoded_release {
        MembershipLeaseMessage::Release(req) => {
            let ack = authority.handle_release(req);
            let ack_msg = MembershipLeaseMessage::ReleaseAck(ack);
            let (encoded_ack, _) = encode_msg(&ack_msg);
            send_b_to_a(&mut h, encoded_ack);
            h.tick();
        }
        _ => panic!("expected Release, got {decoded_release:?}"),
    }
    assert!(!authority.is_slot_occupied(0));

    let msgs_a = drain_msgs(&mut h, true);
    assert_eq!(msgs_a.len(), 1);
    let decoded_rel_ack = decode_msg(&msgs_a[0]);
    assert!(matches!(
        decoded_rel_ack,
        MembershipLeaseMessage::ReleaseAck(_)
    ));

    // ── Verify digest chain ──────────────────────────────────────
    let digests = [
        digest_initial_sm,
        digest_acquiring,
        digest_held,
        digest_renewing,
        digest_released,
    ];
    for i in 0..digests.len() {
        for j in (i + 1)..digests.len() {
            assert_ne!(
                digests[i], digests[j],
                "digests at indices {i} and {j} must differ"
            );
        }
    }

    h.teardown();
}

// ── Two-node lease slot contention test ─────────────────────────────

#[test]
fn two_node_slot_contention_first_wins() {
    let mut h = TwoNodeHarness::new(99);
    h.establish_session().expect("session establish");

    let mut authority = LeaseAuthority::new(epoch(1));

    let acquire1 = MembershipLeaseMessage::Acquire(AcquireRequest {
        node_id: 1,
        epoch: epoch(1),
        slot: 0,
        lease_term_ms: 30_000,
        request_id: 1,
    });
    let (enc1, _) = encode_msg(&acquire1);
    send_a_to_b(&mut h, enc1);
    h.tick();

    let msgs = drain_msgs(&mut h, false);
    let decoded = decode_msg(&msgs[0]);
    match &decoded {
        MembershipLeaseMessage::Acquire(req) => {
            let outcome = authority.handle_acquire(req);
            assert!(
                matches!(outcome, tidefs_cluster::AcquireOutcome::Ack(_)),
                "node 1 should get ack"
            );
        }
        _ => panic!("expected Acquire"),
    }

    let acquire2 = MembershipLeaseMessage::Acquire(AcquireRequest {
        node_id: 2,
        epoch: epoch(1),
        slot: 0,
        lease_term_ms: 30_000,
        request_id: 2,
    });
    let (enc2, _) = encode_msg(&acquire2);
    send_a_to_b(&mut h, enc2);
    h.tick();

    let msgs = drain_msgs(&mut h, false);
    let decoded = decode_msg(&msgs[0]);
    match &decoded {
        MembershipLeaseMessage::Acquire(req) => {
            let outcome = authority.handle_acquire(req);
            assert!(
                matches!(outcome, tidefs_cluster::AcquireOutcome::Nack(_)),
                "node 2 should get nack for occupied slot"
            );
        }
        _ => panic!("expected Acquire"),
    }

    assert!(authority.is_slot_occupied(0));
    assert_eq!(authority.slot_owner(0), Some(1));

    h.teardown();
}

// ── Two-node epoch boundary renegotiation test ──────────────────────

#[test]
fn two_node_epoch_transition_expires_lease() {
    let mut sm = LeaseStateMachine::new(1, epoch(1));

    sm.acquire(epoch(1), 30_000, 0, 100, 0).expect("acquire");
    sm.grant().expect("grant");
    assert_eq!(sm.state(), LeaseState::Held);

    sm.on_epoch_transition(epoch(2));
    assert_eq!(sm.state(), LeaseState::Expiring);

    sm.acquire(epoch(2), 30_000, 0, 200, 0).expect("reacquire");
    assert_eq!(sm.state(), LeaseState::Acquiring);
    sm.grant().expect("grant");
    assert_eq!(sm.state(), LeaseState::Held);
    assert_eq!(sm.current_epoch(), epoch(2));
}

// ── Protocol message integrity across nodes ─────────────────────────

#[test]
fn two_node_protocol_message_integrity() {
    let mut h = TwoNodeHarness::new(42);
    h.establish_session().expect("session establish");

    let msg = MembershipLeaseMessage::Acquire(AcquireRequest {
        node_id: 1,
        epoch: epoch(5),
        slot: 0,
        lease_term_ms: 30_000,
        request_id: 42,
    });
    let (encoded, expected_digest) = encode_msg(&msg);

    send_a_to_b(&mut h, encoded);
    h.tick();

    let msgs = drain_msgs(&mut h, false);
    assert_eq!(msgs.len(), 1);

    let mut h2 = Hasher::new();
    h2.update(&msgs[0]);
    let received_digest: [u8; 32] = h2.finalize().into();
    assert_eq!(received_digest, expected_digest);

    let decoded = decode_msg(&msgs[0]);
    assert_eq!(decoded, msg);

    h.teardown();
}

// ── Deterministic replay test ───────────────────────────────────────

#[test]
fn two_node_lease_cycle_deterministic_replay() {
    fn run_cycle(seed: u64) -> [u8; 32] {
        let mut h = TwoNodeHarness::new(seed);
        h.establish_session().expect("session establish");

        let mut sm = LeaseStateMachine::new(1, epoch(1));
        sm.acquire(epoch(1), 30_000, 0, 100, 0).expect("acquire");
        sm.grant().expect("grant");
        sm.release().expect("release");

        h.teardown();
        sm.state_digest()
    }

    let d1 = run_cycle(42);
    let d2 = run_cycle(42);
    assert_eq!(
        d1, d2,
        "deterministic replay must produce identical digests"
    );
}

// ── LeaseAuthority server-side replay test ──────────────────────────

#[test]
fn authority_replay_deterministic() {
    fn run_authority(seed: u64) -> (u64, usize) {
        let _ = seed;
        let mut auth = LeaseAuthority::new(epoch(1));
        let req = AcquireRequest {
            node_id: 10,
            epoch: epoch(1),
            slot: 0,
            lease_term_ms: 30_000,
            request_id: 1,
        };
        let outcome = auth.handle_acquire(&req);
        let lease_id = match outcome {
            tidefs_cluster::AcquireOutcome::Ack(ack) => ack.lease_id,
            _ => panic!("expected ack"),
        };
        (lease_id, auth.occupied_count())
    }

    let (l1, c1) = run_authority(42);
    let (l2, c2) = run_authority(42);
    assert_eq!(l1, l2);
    assert_eq!(c1, c2);
}

// ── Reconnect epoch gating integration with membership lease ─────────

#[test]
fn reconnect_admission_rejects_stale_epoch_after_lease_advances() {
    use std::collections::BTreeSet;
    use tidefs_transport::epoch_fence::{check_reconnect_admission, ReconnectAdmission};

    // Simulate: a peer held a lease at epoch 1, then membership advanced
    // to epoch 3. A reconnect from epoch 1 should be rejected as stale.
    let roster: BTreeSet<u64> = [1, 2, 3].into();
    let result = check_reconnect_admission(&roster, 3, 1, 1);
    assert_eq!(
        result,
        ReconnectAdmission::StaleEpoch {
            claimed_epoch: 1,
            current_epoch: 3,
        }
    );
}

#[test]
fn reconnect_admission_rejects_departed_peer_after_lease_release() {
    use std::collections::BTreeSet;
    use tidefs_transport::epoch_fence::{check_reconnect_admission, ReconnectAdmission};

    // Simulate: peer 4 released its lease and departed. The roster
    // no longer includes peer 4. A reconnect from peer 4 should be
    // rejected as not-in-roster.
    let roster: BTreeSet<u64> = [1, 2, 3].into();
    let result = check_reconnect_admission(&roster, 5, 4, 5);
    assert_eq!(result, ReconnectAdmission::NotInRoster { peer_id: 4 });
}

#[test]
fn reconnect_admission_accepts_current_epoch_after_lease_renewal() {
    use std::collections::BTreeSet;
    use tidefs_transport::epoch_fence::{check_reconnect_admission, ReconnectAdmission};

    // Peer 2 renewed its lease. Current roster includes peer 2 at epoch 7.
    // A reconnect from peer 2 at epoch 7 should be admitted.
    let roster: BTreeSet<u64> = [1, 2, 3].into();
    let result = check_reconnect_admission(&roster, 7, 2, 7);
    assert_eq!(result, ReconnectAdmission::Admitted);
}
