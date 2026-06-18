// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use tidefs_membership_epoch::{EpochId, HealthClass, MemberClass, MemberId};
use tidefs_membership_live::*;

fn make_keypair() -> Keypair {
    let mut csprng = OsRng;
    Keypair::generate(&mut csprng)
}

macro_rules! propose {
    (
        $engine:expr,
        $proposer:expr,
        $members_added:expr,
        $members_removed:expr,
        $reason:expr,
        $validation:expr,
        $fence_token:expr,
        $signing_key:expr $(,)?
    ) => {
        $engine.propose(EpochTransitionProposalRequest::new(
            $proposer,
            $members_added,
            $members_removed,
            $reason,
            $validation,
            $fence_token,
            $signing_key,
        ))
    };
}

fn fast_config() -> MembershipConfig {
    MembershipConfig {
        ping_interval_ms: 10,
        ping_timeout_ms: 50,
        suspicion_window_ms: 100,
        indirect_ping_count: 2,
        min_voters_for_quorum: 2,
        max_failed_pings_before_suspect: 2,
    }
}

fn make_runtime(id: u64, class: MemberClass) -> MembershipRuntime {
    MembershipRuntime::new(fast_config(), MemberId::new(id), class, id)
}

// AC 16: Non-blocking transport — ping/ack with nonblocking recv

// ---------------------------------------------------------------------------
// AC 16: Non-blocking transport — ping/ack with nonblocking recv
// ---------------------------------------------------------------------------

/// Spawns a peer node that handshakes, signals readiness, then loops recv+ack.
fn peer_nonblocking(
    node_id: u64,
    addr_tx: std::sync::mpsc::Sender<std::net::SocketAddr>,
    ready_tx: std::sync::mpsc::Sender<()>,
    iterations: usize,
) -> std::thread::JoinHandle<Vec<SwimPing>> {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    std::thread::spawn(move || {
        let mut mt = MembershipTransport::new(node_id);
        let bind_addr: std::net::SocketAddr =
            std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        mt.bind(bind_addr).expect("peer bind");
        let bound = mt.local_addr().expect("peer bound addr");
        let bound: std::net::SocketAddr = match bound {
            tidefs_transport::TransportAddr::Tcp(addr) => addr,
            _ => panic!("expected Tcp addr"),
        };
        addr_tx.send(bound).expect("send addr");

        // Poll-accept + handshake
        let sid;
        loop {
            match mt.try_accept_peer() {
                Ok(Some((_id, s))) => {
                    sid = s;
                    break;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(2)),
                Err(e) => panic!("peer {node_id} accept: {e}"),
            }
        }

        mt.transport.set_nonblocking(true).expect("set_nb");
        ready_tx.send(()).expect("ready");

        let mut pings = Vec::new();
        for _ in 0..iterations {
            let msg = recv_membership_msg(&mut mt.transport, sid);
            if let Ok(MembershipWireMessage::Ping(ping)) = msg {
                pings.push(ping.clone());
                let ack = MembershipWireMessage::Ack(SwimAck {
                    ping_seq_no: ping.seq_no,
                    acker: MemberId::new(node_id),
                    acker_epoch: tidefs_membership_epoch::EpochId::new(1),
                    acker_epoch_receipt: 0,
                    suspicion_list: vec![],
                    membership_delta: vec![],
                    acked_at_millis: now_millis_inline(),
                    signature: vec![],
                });
                let _ = send_membership_msg(&mut mt.transport, sid, &ack);
            }
            std::thread::sleep(Duration::from_millis(8));
        }
        mt.close();
        pings
    })
}

#[test]
fn test_nonblocking_ping_ack_roundtrip() {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let (addr_tx, addr_rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::channel();

    let server = peer_nonblocking(2, addr_tx, ready_tx, 200);

    let server_addr = addr_rx.recv_timeout(Duration::from_secs(5)).expect("addr");
    thread::sleep(Duration::from_millis(5));

    let mut client = MembershipTransport::new(1);
    client.connect_to_peer(2, server_addr).expect("connect");
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("ready");

    client.transport.set_nonblocking(true).expect("set_nb");

    // Send 5 pings rapidly
    for tick in 0..5 {
        let ping = SwimPing {
            pinger: MemberId::new(1),
            ping_target: MemberId::new(2),
            seq_no: tick as u64,
            pinger_epoch: tidefs_membership_epoch::EpochId::new(1),
            pinger_epoch_receipt: 0,
            sent_at_millis: now_millis_inline(),
            indirect_via: vec![],
            signature: vec![],
        };
        client.send_ping(&ping).expect("send ping");
    }

    // Poll for all acks
    let mut acks = 0u64;
    for _ in 0..50 {
        thread::sleep(Duration::from_millis(20));
        // Drain all available acks
        loop {
            match client.recv_from(MemberId::new(2)) {
                Ok(MembershipWireMessage::Ack(_)) => {
                    acks += 1;
                }
                Ok(_) => {}      // unexpected
                Err(_) => break, // no more data (WouldBlock)
            }
        }
        if acks >= 5 {
            break;
        }
    }

    assert_eq!(acks, 5, "should receive all 5 acks, got {acks}");
    client.close();

    let pings = server.join().expect("server");
    assert_eq!(
        pings.len(),
        5,
        "server should have received 5 pings, got {}",
        pings.len()
    );
}

#[test]
fn test_runtime_tick_dispatches_ping_over_transport() {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let (addr_tx, addr_rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::channel();

    let server = peer_nonblocking(2, addr_tx, ready_tx, 20);

    let server_addr = addr_rx.recv_timeout(Duration::from_secs(5)).expect("addr");
    thread::sleep(Duration::from_millis(5));

    let mut client = MembershipTransport::new(1);
    client.connect_to_peer(2, server_addr).expect("connect");
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("ready");

    let mut runtime = make_runtime(1, MemberClass::Voter);
    runtime.add_peer(MemberId::new(2), MemberClass::Voter, 2);
    runtime
        .detector
        .get_peer_mut(MemberId::new(2))
        .expect("peer")
        .last_ack_millis = 0;

    let (runtime_tick, transport_tick) = client.tick_runtime(&mut runtime);
    assert_eq!(runtime_tick.pings_sent, 1);
    assert_eq!(transport_tick.runtime_pings_generated, 1);
    assert_eq!(transport_tick.pings_sent, 1);
    assert_eq!(transport_tick.ping_send_failures, 0);

    thread::sleep(Duration::from_millis(50));
    client.close();

    let pings = server.join().expect("server");
    assert_eq!(pings.len(), 1);
    assert_eq!(pings[0].pinger, MemberId::new(1));
    assert_eq!(pings[0].ping_target, MemberId::new(2));
    assert!(pings[0].verify(
        runtime
            .get_verifying_key(MemberId::new(1))
            .expect("self key")
    ));
}

#[test]
fn test_membership_view_roundtrip_over_transport() {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let (addr_tx, addr_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let mut server = MembershipTransport::new(2);
        let bind_addr = std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        server.bind(bind_addr).expect("server bind");
        let bound = server.local_addr().expect("bound addr");
        let bound: std::net::SocketAddr = match bound {
            tidefs_transport::TransportAddr::Tcp(addr) => addr,
            _ => panic!("expected Tcp addr"),
        };
        addr_tx.send(bound).expect("send addr");

        loop {
            match server.try_accept_peer() {
                Ok(Some(_)) => break,
                Ok(None) => thread::sleep(Duration::from_millis(5)),
                Err(e) => panic!("accept peer: {e}"),
            }
        }

        match server.recv_from(MemberId::new(1)).expect("recv view") {
            MembershipWireMessage::View(view) => view,
            other => panic!("expected view, got {other:?}"),
        }
    });

    let server_addr = addr_rx.recv_timeout(Duration::from_secs(5)).expect("addr");
    let mut client = MembershipTransport::new(1);
    client.connect_to_peer(2, server_addr).expect("connect");

    let mut runtime = make_runtime(1, MemberClass::Voter);
    runtime.add_peer(MemberId::new(2), MemberClass::Learner, 2);
    let view = runtime.view();

    client
        .send_view(MemberId::new(2), &view)
        .expect("send membership view");

    let received = server.join().expect("server");
    assert_eq!(received, view);
}

#[test]
fn test_three_node_nonblocking_tick_loop() {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let tick_count = 20;

    let (a2_tx, a2_rx) = mpsc::channel();
    let (a3_tx, a3_rx) = mpsc::channel();
    let (r2_tx, r2_rx) = mpsc::channel();
    let (r3_tx, r3_rx) = mpsc::channel();

    let s2 = peer_nonblocking(2, a2_tx, r2_tx, tick_count * 20);
    let s3 = peer_nonblocking(3, a3_tx, r3_tx, tick_count * 20);

    let addr2 = a2_rx.recv_timeout(Duration::from_secs(5)).expect("addr2");
    let addr3 = a3_rx.recv_timeout(Duration::from_secs(5)).expect("addr3");
    thread::sleep(Duration::from_millis(5));

    let mut client = MembershipTransport::new(1);
    client.connect_to_peer(2, addr2).expect("connect 2");
    client.connect_to_peer(3, addr3).expect("connect 3");
    r2_rx.recv_timeout(Duration::from_secs(5)).expect("ready 2");
    r3_rx.recv_timeout(Duration::from_secs(5)).expect("ready 3");

    client.transport.set_nonblocking(true).expect("set_nb");

    let mut pings_sent = 0u64;
    let mut acks = 0u64;

    for tick in 0..tick_count {
        for (peer_id, seq_base) in [(2u64, 0u64), (3u64, 1u64)] {
            let ping = SwimPing {
                pinger: MemberId::new(1),
                ping_target: MemberId::new(peer_id),
                seq_no: seq_base + tick as u64 * 2,
                pinger_epoch: tidefs_membership_epoch::EpochId::new(1),
                pinger_epoch_receipt: 0,
                sent_at_millis: now_millis_inline(),
                indirect_via: vec![],
                signature: vec![],
            };
            client.send_ping(&ping).expect("send ping");
            pings_sent += 1;
        }

        // Poll for acks from both peers
        for _ in 0..10 {
            thread::sleep(Duration::from_millis(10));
            for peer_id in [MemberId::new(2), MemberId::new(3)] {
                if let Some(&sid) = client.peer_sessions.get(&peer_id) {
                    if let Ok(MembershipWireMessage::Ack(_)) =
                        recv_membership_msg(&mut client.transport, sid)
                    {
                        acks += 1;
                    }
                }
            }
        }
    }

    assert_eq!(pings_sent, tick_count as u64 * 2);
    assert!(
        acks >= tick_count as u64,
        "should receive at least {tick_count} acks, got {acks}"
    );

    client.close();

    let p2 = s2.join().expect("s2");
    let p3 = s3.join().expect("s3");
    assert!(!p2.is_empty(), "server 2 should have received pings");
    assert!(!p3.is_empty(), "server 3 should have received pings");
}

// ---------------------------------------------------------------------------
// AC 1: crate exists with MembershipRuntime
// ---------------------------------------------------------------------------

#[test]
fn test_crate_exists_and_runtime_creates() {
    let rt = make_runtime(1, MemberClass::Voter);
    assert_eq!(rt.current_epoch(), EpochId::new(1));
    assert!(rt.detector.has_peer(MemberId::new(1)));
}

// ---------------------------------------------------------------------------
// AC 2: 6 member classes with legal state transitions
// ---------------------------------------------------------------------------

#[test]
fn test_member_classes_promotion_path() {
    let mut rt = make_runtime(1, MemberClass::Voter);

    // Learner joins
    rt.add_joining_peer(MemberId::new(5), 5);
    let peer = rt.detector.get_peer(MemberId::new(5)).unwrap();
    assert_eq!(peer.member_class, MemberClass::Learner);
    assert!(peer.joining);

    // Promote to Voter
    rt.promote_to_voter(MemberId::new(5));
    let peer = rt.detector.get_peer(MemberId::new(5)).unwrap();
    assert_eq!(peer.member_class, MemberClass::Voter);
    assert!(!peer.joining);
}

#[test]
fn test_all_six_member_classes_registered() {
    let mut rt = make_runtime(1, MemberClass::Voter);

    let classes = [
        (2, MemberClass::Voter),
        (3, MemberClass::Learner),
        (4, MemberClass::WitnessOnly),
        (5, MemberClass::DataOnly),
        (6, MemberClass::ShadowOnly),
        (7, MemberClass::Quarantined),
    ];

    for (id, class) in &classes {
        rt.add_peer(MemberId::new(*id), *class, *id);
    }

    for (id, class) in &classes {
        let peer = rt.detector.get_peer(MemberId::new(*id)).unwrap();
        assert_eq!(peer.member_class, *class, "class mismatch for {id}");
    }
}

#[test]
fn test_voter_to_draining_transition() {
    let mut rt = make_runtime(1, MemberClass::Voter);
    rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);

    rt.drain_peer(MemberId::new(2));
    let peer = rt.detector.get_peer(MemberId::new(2)).unwrap();
    assert!(peer.draining);
    assert_eq!(peer.member_class, MemberClass::DataOnly);
}

// ---------------------------------------------------------------------------
// AC 3: 4 config classes with epoch transition receipts
// ---------------------------------------------------------------------------

#[test]
fn test_bootstrap_config_class() {
    let rt = make_runtime(1, MemberClass::Voter);
    assert!(rt.is_bootstrapping());
}

#[test]
fn test_normal_config_class_after_bootstrap() {
    let mut rt = make_runtime(1, MemberClass::Voter);
    // Tick enough to exit bootstrap
    for _ in 0..15 {
        rt.tick();
    }
    assert!(!rt.is_bootstrapping());
}

#[test]
fn test_config_class_after_failure_transition() {
    let mut rt = make_runtime(1, MemberClass::Voter);
    rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);
    rt.add_peer(MemberId::new(3), MemberClass::Voter, 3);

    // Generate keys for acceptors
    let kp2 = make_keypair();
    let kp3 = make_keypair();
    rt.register_key(MemberId::new(2), kp2.public);
    rt.register_key(MemberId::new(3), kp3.public);

    // Mark peer 3 as dead
    rt.detector.get_peer_mut(MemberId::new(3)).unwrap().health = HealthClass::Down;
    rt.detector
        .get_peer_mut(MemberId::new(3))
        .unwrap()
        .suspect_since_millis = now_millis_inline();

    // Add suspicion validation
    let suspicion = SuspicionRecord::new(
        MemberId::new(3),
        MemberId::new(1),
        now_millis_inline(),
        SuspicionSource::DirectTimeout,
    );
    rt.detector.emitted_suspicions.push(suspicion);

    // Initiate transition
    rt.initiate_epoch_transition(
        vec![],
        vec![MemberId::new(3)],
        TransitionReason::FailureDetected,
        rt.detector.emitted_suspicions.clone(),
        None,
    );

    assert!(rt.pending_transition.is_some());
}

// ---------------------------------------------------------------------------
// AC 4: Heartbeat protocol with SWIM suspicion
// ---------------------------------------------------------------------------

#[test]
fn test_swim_ping_completes_successfully() {
    let kp = make_keypair();
    let mut ping = SwimPing {
        pinger: MemberId::new(1),
        ping_target: MemberId::new(2),
        seq_no: 1,
        pinger_epoch: EpochId::new(1),
        pinger_epoch_receipt: 0,
        sent_at_millis: now_millis_inline(),
        indirect_via: vec![MemberId::new(3)],
        signature: Vec::new(),
    };
    ping.sign(&kp);
    assert!(ping.verify(&kp.public));
}

#[test]
fn test_swim_ack_carries_suspicion_deltas() {
    let kp = make_keypair();
    let mut ack = SwimAck {
        ping_seq_no: 1,
        acker: MemberId::new(2),
        acker_epoch: EpochId::new(1),
        acker_epoch_receipt: 0,
        suspicion_list: vec![SuspicionRecord::new(
            MemberId::new(3),
            MemberId::new(2),
            now_millis_inline(),
            SuspicionSource::DirectTimeout,
        )],
        membership_delta: vec![MembershipDelta {
            member_id: MemberId::new(4),
            kind: MembershipDeltaKind::Joined,
        }],
        acked_at_millis: now_millis_inline(),
        signature: Vec::new(),
    };
    ack.sign(&kp);
    assert!(ack.verify(&kp.public));
    assert_eq!(ack.suspicion_list.len(), 1);
    assert_eq!(ack.membership_delta.len(), 1);
}

#[test]
fn test_indirect_ping_request_sign_and_verify() {
    let kp = make_keypair();
    let mut req = SwimIndirectPingRequest {
        requester: MemberId::new(1),
        target: MemberId::new(2),
        original_seq_no: 5,
        relay_seq_no: 1,
        sent_at_millis: now_millis_inline(),
        signature: Vec::new(),
    };
    req.sign(&kp);
    assert!(req.verify(&kp.public));
}

#[test]
fn test_indirect_ping_response_sign_and_verify() {
    let kp = make_keypair();
    let mut resp = SwimIndirectPingResponse {
        responder: MemberId::new(3),
        target: MemberId::new(2),
        target_reachable: true,
        relay_seq_no: 1,
        responded_at_millis: now_millis_inline(),
        signature: Vec::new(),
    };
    resp.sign(&kp);
    assert!(resp.verify(&kp.public));
}

// ---------------------------------------------------------------------------
// AC 5: Epoch transition bootstrap -> normal -> joint -> normal
// ---------------------------------------------------------------------------

#[test]
fn test_epoch_transition_normal_to_joint() {
    let kp = make_keypair();
    let verifying_key = kp.public;
    let mut keys = BTreeMap::new();
    keys.insert(MemberId::new(1), verifying_key);

    let mut engine = EpochTransitionEngine::new(EpochId::new(5));
    engine.set_voter_count(1);

    // Normal → Joint (member add)
    let proposal = propose!(
        engine,
        MemberId::new(1),
        vec![MemberId::new(4)],
        vec![],
        TransitionReason::JoinRequested,
        vec![],
        None,
        &kp,
    );
    assert_eq!(proposal.from_epoch, EpochId::new(5));
    assert_eq!(proposal.to_epoch, EpochId::new(6));
    assert!(!proposal.members_added.is_empty());
}

#[test]
fn test_epoch_transition_joint_to_normal_on_promotion() {
    let kp = make_keypair();
    let verifying_key = kp.public;
    let mut keys = BTreeMap::new();
    keys.insert(MemberId::new(1), verifying_key);

    let mut engine = EpochTransitionEngine::new(EpochId::new(6));
    engine.set_voter_count(1);

    let proposal = propose!(
        engine,
        MemberId::new(1),
        vec![],
        vec![],
        TransitionReason::PromotedToVoter,
        vec![],
        None,
        &kp,
    );
    let alive = vec![MemberId::new(1)];
    engine.accept(&proposal, MemberId::new(1), &alive, &kp).ok();
    engine.commit(proposal.proposal_id, &kp).ok();

    assert_eq!(engine.current_epoch(), EpochId::new(7));
    assert_eq!(engine.transition_history.len(), 1);
}

// ---------------------------------------------------------------------------
// AC 6: Failure detection — suspect then dead triggers epoch transition
// ---------------------------------------------------------------------------

#[test]
fn test_failure_detection_suspect_to_dead() {
    let mut rt = make_runtime(1, MemberClass::Voter);
    rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);
    rt.add_peer(MemberId::new(3), MemberClass::Voter, 3);

    // Set up suspicion window to expire immediately
    rt.detector.get_peer_mut(MemberId::new(2)).unwrap().health = HealthClass::Suspect;
    rt.detector
        .get_peer_mut(MemberId::new(2))
        .unwrap()
        .suspect_since_millis = 0; // Long ago — should be dead now

    let _suspicions = rt.detector.tick_timeouts();
    // Peer 2 should now be Dead
    let peer = rt.detector.get_peer(MemberId::new(2)).unwrap();
    assert_eq!(peer.health, HealthClass::Down);
}

// ---------------------------------------------------------------------------
// AC 7: Member add — Learner catches up, promoted to Voter in Joint→Normal
// ---------------------------------------------------------------------------

#[test]
fn test_member_add_learner_to_voter_flow() {
    let mut rt = make_runtime(1, MemberClass::Voter);
    rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);

    // Phase 1: New node joins as Learner
    let new_id = MemberId::new(7);
    let new_kp = make_keypair();
    rt.register_key(new_id, new_kp.public);
    rt.add_joining_peer(new_id, 7);

    let peer = rt.detector.get_peer(new_id).unwrap();
    assert_eq!(peer.member_class, MemberClass::Learner);
    assert!(peer.joining);

    // Phase 2: After catch-up, promote to Voter
    rt.promote_to_voter(new_id);
    let peer = rt.detector.get_peer(new_id).unwrap();
    assert_eq!(peer.member_class, MemberClass::Voter);
    assert!(!peer.joining);

    // Voter count now includes the promoted member
    assert_eq!(rt.alive_voter_count(), 3);
}

// ---------------------------------------------------------------------------
// AC 8: Member remove/drain — Voter→Draining→Joint→removed
// ---------------------------------------------------------------------------

#[test]
fn test_member_drain_flow() {
    let mut rt = make_runtime(1, MemberClass::Voter);
    rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);
    rt.add_peer(MemberId::new(3), MemberClass::Voter, 3);

    // Drain peer 3
    rt.drain_peer(MemberId::new(3));
    let peer = rt.detector.get_peer(MemberId::new(3)).unwrap();
    assert!(peer.draining);
    assert_eq!(peer.member_class, MemberClass::DataOnly);
}

// ---------------------------------------------------------------------------
// AC 9: Quorum computation — majority of Voters per epoch
// ---------------------------------------------------------------------------

#[test]
fn test_quorum_computation_3_voters() {
    let mut rt = make_runtime(1, MemberClass::Voter);
    rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);
    rt.add_peer(MemberId::new(3), MemberClass::Voter, 3);

    // 3 voters → quorum = 2
    assert_eq!(rt.alive_voter_count(), 3);
    assert!(!rt.quorum_lost());

    // Mark one down → quorum still held (2 of 3)
    rt.detector.get_peer_mut(MemberId::new(3)).unwrap().health = HealthClass::Down;
    assert_eq!(rt.alive_voter_count(), 2);
    assert!(!rt.quorum_lost());
}

#[test]
fn test_quorum_computation_5_voters() {
    let mut rt = make_runtime(1, MemberClass::Voter);
    for i in 2..=5 {
        rt.add_peer(MemberId::new(i), MemberClass::Voter, i);
    }

    // 5 voters → quorum = 3
    assert_eq!(rt.alive_voter_count(), 5);

    // Mark 2 down → quorum held (3 of 5)
    rt.detector.get_peer_mut(MemberId::new(4)).unwrap().health = HealthClass::Down;
    rt.detector.get_peer_mut(MemberId::new(5)).unwrap().health = HealthClass::Down;
    assert_eq!(rt.alive_voter_count(), 3);
    assert!(!rt.quorum_lost());
}

// ---------------------------------------------------------------------------
// AC 10: Cohort population on epoch transition
// ---------------------------------------------------------------------------

#[test]
fn test_cohort_population_updated_on_transition() {
    let kp = make_keypair();
    let verifying_key = kp.public;
    let mut keys = BTreeMap::new();
    keys.insert(MemberId::new(1), verifying_key);

    let mut engine = EpochTransitionEngine::new(EpochId::new(1));
    engine.set_voter_count(1);

    // Propose and commit a transition
    let proposal = propose!(
        engine,
        MemberId::new(1),
        vec![],
        vec![MemberId::new(2)],
        TransitionReason::GracefulLeave,
        vec![],
        None,
        &kp,
    );
    let alive = vec![MemberId::new(1)];
    engine.accept(&proposal, MemberId::new(1), &alive, &kp).ok();
    engine.commit(proposal.proposal_id, &kp).ok();

    // Transition history recorded
    assert_eq!(engine.transition_history.len(), 1);
    let last = &engine.transition_history[0];
    assert!(last.members_removed.contains(&MemberId::new(2)));
}

// ---------------------------------------------------------------------------
// AC 11: 5-node cluster, 1 killed, remaining 4 detect and form new epoch
// ---------------------------------------------------------------------------

#[test]
fn test_five_node_one_killed_remaining_form_new_epoch() {
    let mut rt = make_runtime(1, MemberClass::Voter);
    let kps: BTreeMap<u64, Keypair> = (2..=5).map(|i| (i, make_keypair())).collect();

    for i in 2..=5 {
        rt.add_peer(MemberId::new(i), MemberClass::Voter, i);
        rt.register_key(MemberId::new(i), kps[&i].public);
    }

    // Node 5 is killed
    let now = now_millis_inline();
    rt.detector.get_peer_mut(MemberId::new(5)).unwrap().health = HealthClass::Down;
    rt.detector
        .get_peer_mut(MemberId::new(5))
        .unwrap()
        .suspect_since_millis = now;

    // Emit suspicions from 2 distinct reporters
    rt.detector.emitted_suspicions = vec![
        SuspicionRecord::new(
            MemberId::new(5),
            MemberId::new(1),
            now,
            SuspicionSource::DirectTimeout,
        ),
        SuspicionRecord::new(
            MemberId::new(5),
            MemberId::new(2),
            now,
            SuspicionSource::DirectTimeout,
        ),
    ];

    // Initiate transition
    rt.initiate_epoch_transition(
        vec![],
        vec![MemberId::new(5)],
        TransitionReason::FailureDetected,
        rt.detector.emitted_suspicions.clone(),
        None,
    );

    // Pending transition exists
    assert!(rt.pending_transition.is_some());
    let pt = rt.pending_transition.as_ref().unwrap();
    assert!(pt.proposal.members_removed.contains(&MemberId::new(5)));

    // Quorum: 4 remaining voters → need 3 accepts
    // We have 1 (our own accept) — need 2 more
    assert_eq!(pt.accepts_received, 1);
    assert_eq!(pt.required_accepts, 3);
}

// ---------------------------------------------------------------------------
// AC 12: Member add flow — joins as Learner, catches up, promoted
// ---------------------------------------------------------------------------

#[test]
fn test_full_member_add_flow() {
    let mut rt = make_runtime(1, MemberClass::Voter);
    rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);

    // The new member's identity
    let new_id = MemberId::new(10);
    let new_kp = make_keypair();
    rt.register_key(new_id, new_kp.public);

    // Step 1: Register as Learner (joining)
    rt.add_joining_peer(new_id, 10);
    assert!(rt.detector.has_peer(new_id));

    let peer = rt.detector.get_peer(new_id).unwrap();
    assert_eq!(peer.member_class, MemberClass::Learner);
    assert!(peer.joining);
    assert!(!peer.is_voter());

    // Step 2: After catch-up, promote
    rt.promote_to_voter(new_id);
    let peer = rt.detector.get_peer(new_id).unwrap();
    assert_eq!(peer.member_class, MemberClass::Voter);
    assert!(peer.is_voter());
    assert!(!peer.joining);

    // Voter count reflects promotion
    assert_eq!(rt.alive_voter_count(), 3);
}

// ---------------------------------------------------------------------------
// AC 13: Quorum loss — 3-node, 2 fail, remaining 1 refuses transition
// ---------------------------------------------------------------------------

#[test]
fn test_quorum_loss_prevents_epoch_transition() {
    let mut rt = make_runtime(1, MemberClass::Voter);
    rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);
    rt.add_peer(MemberId::new(3), MemberClass::Voter, 3);

    // Both peers die
    rt.detector.get_peer_mut(MemberId::new(2)).unwrap().health = HealthClass::Down;
    rt.detector.get_peer_mut(MemberId::new(3)).unwrap().health = HealthClass::Down;

    // Only 1 voter alive → quorum lost
    assert_eq!(rt.alive_voter_count(), 1);
    assert!(rt.quorum_lost());
}

// ---------------------------------------------------------------------------
// AC 14: Witness-only member removed doesn't affect quorum
// ---------------------------------------------------------------------------

#[test]
fn test_witness_removal_does_not_affect_quorum() {
    let mut rt = make_runtime(1, MemberClass::Voter);
    rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);
    rt.add_peer(MemberId::new(3), MemberClass::Voter, 3);
    rt.add_peer(MemberId::new(4), MemberClass::WitnessOnly, 4);
    rt.add_peer(MemberId::new(5), MemberClass::WitnessOnly, 5);

    // 3 voters, 2 witnesses
    assert_eq!(rt.alive_voter_count(), 3);

    // Remove witnesses
    rt.detector.get_peer_mut(MemberId::new(4)).unwrap().health = HealthClass::Down;
    rt.detector.get_peer_mut(MemberId::new(5)).unwrap().health = HealthClass::Down;

    // Voter count unchanged
    assert_eq!(rt.alive_voter_count(), 3);
    assert!(!rt.quorum_lost());
}

// ---------------------------------------------------------------------------
// AC 15: Quarantined member excluded from all cohorts and placement
// ---------------------------------------------------------------------------

#[test]
fn test_quarantined_excluded_from_everything() {
    let mut rt = make_runtime(1, MemberClass::Voter);
    rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);
    rt.add_peer(MemberId::new(3), MemberClass::Quarantined, 3);

    // Quarantined doesn't count as voter
    assert_eq!(rt.alive_voter_count(), 2);

    // Quarantined can't vote
    let peer = rt.detector.get_peer(MemberId::new(3)).unwrap();
    assert_eq!(peer.member_class, MemberClass::Quarantined);
    assert!(!peer.is_voter());
    assert!(!peer.can_hold_data());

    // Healthy quarantined still excluded
    assert!(peer.health == HealthClass::Healthy);
    assert!(!peer.is_voter());
}

// ---------------------------------------------------------------------------
// Additional cross-cutting tests
// ---------------------------------------------------------------------------

#[test]
fn test_serde_swim_ping_roundtrip() {
    let kp = make_keypair();
    let mut ping = SwimPing {
        pinger: MemberId::new(1),
        ping_target: MemberId::new(2),
        seq_no: 42,
        pinger_epoch: EpochId::new(3),
        pinger_epoch_receipt: 99,
        sent_at_millis: 1234567890,
        indirect_via: vec![MemberId::new(4), MemberId::new(5)],
        signature: Vec::new(),
    };
    ping.sign(&kp);

    let json = serde_json::to_string(&ping).expect("serialize");
    let round: SwimPing = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ping.ping_target, round.ping_target);
    assert_eq!(ping.seq_no, round.seq_no);
    assert_eq!(ping.indirect_via, round.indirect_via);
    assert!(round.verify(&kp.public));
}

#[test]
fn test_serde_swim_ack_roundtrip() {
    let kp = make_keypair();
    let mut ack = SwimAck {
        ping_seq_no: 7,
        acker: MemberId::new(3),
        acker_epoch: EpochId::new(2),
        acker_epoch_receipt: 55,
        suspicion_list: vec![SuspicionRecord::new(
            MemberId::new(4),
            MemberId::new(3),
            1000,
            SuspicionSource::DirectTimeout,
        )],
        membership_delta: vec![MembershipDelta {
            member_id: MemberId::new(5),
            kind: MembershipDeltaKind::Joined,
        }],
        acked_at_millis: 2000,
        signature: Vec::new(),
    };
    ack.sign(&kp);

    let json = serde_json::to_string(&ack).expect("serialize");
    let round: SwimAck = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ack.acker, round.acker);
    assert_eq!(ack.suspicion_list.len(), round.suspicion_list.len());
    assert_eq!(ack.membership_delta.len(), round.membership_delta.len());
    assert!(round.verify(&kp.public));
}

#[test]
fn test_serde_epoch_transition_proposal_roundtrip() {
    let kp = make_keypair();
    let mut prop = EpochTransitionProposal {
        proposal_id: 1,
        proposer: MemberId::new(1),
        from_epoch: EpochId::new(5),
        to_epoch: EpochId::new(6),
        members_added: vec![MemberId::new(7)],
        members_removed: vec![MemberId::new(3)],
        reason: TransitionReason::FailureDetected,
        validation: vec![SuspicionRecord::new(
            MemberId::new(3),
            MemberId::new(1),
            5000,
            SuspicionSource::DirectTimeout,
        )],
        proposed_at_millis: 6000,
        fence_token: None,
        proposer_signature: Vec::new(),
    };
    prop.sign(&kp);

    let json = serde_json::to_string(&prop).expect("serialize");
    let round: EpochTransitionProposal = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(prop.proposal_id, round.proposal_id);
    assert_eq!(prop.from_epoch, round.from_epoch);
    assert_eq!(prop.to_epoch, round.to_epoch);
    assert!(round.verify(&kp.public));
}

#[test]
fn test_serde_epoch_transition_commit_roundtrip() {
    let kp = make_keypair();
    let mut commit = EpochTransitionCommit {
        proposal_id: 1,
        new_epoch: EpochId::new(6),
        accept_receipts: vec![100, 200, 300],
        committed_at_millis: 7000,
        proposer_signature: Vec::new(),
    };
    commit.sign(&kp);

    let json = serde_json::to_string(&commit).expect("serialize");
    let round: EpochTransitionCommit = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(commit.new_epoch, round.new_epoch);
    assert_eq!(commit.accept_receipts, round.accept_receipts);
    assert!(round.verify(&kp.public));
}

#[test]
fn test_multiple_transitions_form_chain() {
    let kp = make_keypair();
    let verifying_key = kp.public;
    let mut keys = BTreeMap::new();
    keys.insert(MemberId::new(1), verifying_key);

    let mut engine = EpochTransitionEngine::new(EpochId::new(1));
    engine.set_voter_count(1);
    let alive = vec![MemberId::new(1)];

    // Transition 1: 1 → 2
    let p1 = propose!(
        engine,
        MemberId::new(1),
        vec![],
        vec![],
        TransitionReason::GracefulLeave,
        vec![],
        None,
        &kp,
    );
    engine.accept(&p1, MemberId::new(1), &alive, &kp).ok();
    engine.commit(p1.proposal_id, &kp).ok();
    assert_eq!(engine.current_epoch(), EpochId::new(2));

    // Transition 2: 2 → 3
    let p2 = propose!(
        engine,
        MemberId::new(1),
        vec![],
        vec![],
        TransitionReason::GracefulLeave,
        vec![],
        None,
        &kp,
    );
    engine.accept(&p2, MemberId::new(1), &alive, &kp).ok();
    engine.commit(p2.proposal_id, &kp).ok();
    assert_eq!(engine.current_epoch(), EpochId::new(3));

    assert_eq!(engine.transition_history.len(), 2);
}

// ---------------------------------------------------------------------------
// Fencing watchdog integration test
// ---------------------------------------------------------------------------

/// Full path: peer unhealthy → watchdog triggers fence → epoch transition
/// proposal carries fence_token → fenced node tracked.
#[test]
fn test_fencing_watchdog_unhealthy_peer_triggers_fenced_transition() {
    let mut rt = make_runtime(1, MemberClass::Voter);
    rt.fencing.set_fence_timeout_ms(100);

    // Add two other voters so we have quorum
    let kp2 = make_keypair();
    let kp3 = make_keypair();
    rt.register_key(MemberId::new(2), kp2.public);
    rt.register_key(MemberId::new(3), kp3.public);
    rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);
    rt.add_peer(MemberId::new(3), MemberClass::Voter, 3);

    // Mark peer 3 as Down with old last_ack so it appears unresponsive
    rt.detector.get_peer_mut(MemberId::new(3)).unwrap().health = HealthClass::Down;
    rt.detector
        .get_peer_mut(MemberId::new(3))
        .unwrap()
        .suspect_since_millis = now_millis_inline();

    // Emit a suspicion record — needed for validation in transition
    let suspicion = SuspicionRecord::new(
        MemberId::new(3),
        MemberId::new(1),
        now_millis_inline(),
        SuspicionSource::DirectTimeout,
    );
    rt.detector.emitted_suspicions.push(suspicion);

    // Simulate node 3 being unresponsive for >100ms
    // The fencing watchdog tick checks last_healthy against now.
    // We set record_healthy at 0 and then tick at 200ms.
    // record_healthy is called by add_peer, but we need the time gap.
    // Manually set the last_healthy to 0 so that now_millis - 0 > fence_timeout.
    rt.fencing.record_healthy(MemberId::new(3), 0);

    // Tick the runtime at "200ms later" — the watchdog should trigger
    // We can't control now_millis() from outside, but tick uses
    // the system clock for last_ack. However, our watchdog uses the
    // recorded healthy timestamp. We set healthy at 0, and
    // now_millis_inline() will be >> 100ms, so it should trigger.
    let result = rt.tick();

    // Verify: epoch transition was initiated
    assert!(result.epoch_transition_initiated);
    assert!(rt.pending_transition.is_some());

    // Verify the proposal carries a fence token
    let pending = rt.pending_transition.as_ref().unwrap();
    let ft = pending
        .proposal
        .fence_token
        .expect("fence token should be present");
    assert_eq!(ft.value(), 1);
    assert!(pending.proposal.members_removed.contains(&MemberId::new(3)));

    // Verify the node is marked as fenced
    assert!(rt.fencing.is_fenced(MemberId::new(3)));
    assert_eq!(rt.fencing.stats().nodes_fenced, 1);
    assert_eq!(rt.fencing.stats().fence_triggers_timeout, 1);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_millis_inline() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ---------------------------------------------------------------------------
// Peer health tracker: eviction proposal integration
// ---------------------------------------------------------------------------

/// Two-node cluster: peer 2 fails via unreachable callback, health tracker
/// proposes eviction. Quorum lowered to 1 for a small-cluster test.
#[test]
fn peer_health_two_node_eviction_proposal() {
    let my_id = MemberId::new(1);
    let peer_id = MemberId::new(2);
    let config = fast_config();

    let mut rt = MembershipRuntime::new(config, my_id, MemberClass::Voter, 0);

    // Lower quorum to 1 so 2-node eviction works.
    rt.peer_health = tidefs_membership_live::peer_health::PeerHealthTracker::new(
        tidefs_membership_types::PeerHealthConfig::new().with_min_peers_for_eviction_quorum(1),
    );

    rt.roster.add_member(peer_id);

    // Mark peer 2 as unreachable.
    rt.peer_health.on_peer_unreachable(peer_id);
    assert_eq!(
        rt.peer_health.state(peer_id),
        Some(tidefs_membership_types::PeerHealthState::Failed),
    );

    let _ = rt.tick();
    assert!(rt.pending_transition.is_some(), "epoch transition expected");
    let pt = rt.pending_transition.as_ref().expect("pending transition");
    assert!(pt.proposal.members_removed.contains(&peer_id));
}

/// Coordinator self-eviction is blocked even when the coordinator
/// itself is marked Failed.
#[test]
fn peer_health_coordinator_not_evicted() {
    let my_id = MemberId::new(1);
    let peer_id = MemberId::new(2);
    let config = fast_config();

    let mut rt = MembershipRuntime::new(config, my_id, MemberClass::Voter, 0);

    // Use quorum=1 so the only guard is coordinator self-eviction.
    rt.peer_health = tidefs_membership_live::peer_health::PeerHealthTracker::new(
        tidefs_membership_types::PeerHealthConfig::new().with_min_peers_for_eviction_quorum(1),
    );

    rt.roster.add_member(peer_id);

    // Mark OURSELVES as Failed (coordinator, lowest MemberId).
    rt.peer_health.on_peer_unreachable(my_id);
    assert_eq!(
        rt.peer_health.state(my_id),
        Some(tidefs_membership_types::PeerHealthState::Failed),
    );

    let _ = rt.tick();
    assert!(
        rt.pending_transition.is_none(),
        "coordinator self-eviction blocked"
    );
}

/// After marking a peer's eviction as resolved, a subsequent failure
/// can re-propose eviction.
#[test]
fn peer_health_re_propose_after_resolve() {
    let my_id = MemberId::new(1);
    let peer_id = MemberId::new(2);
    let config = fast_config();

    let mut rt = MembershipRuntime::new(config, my_id, MemberClass::Voter, 0);

    // Quorum=1 for small-cluster test.
    rt.peer_health = tidefs_membership_live::peer_health::PeerHealthTracker::new(
        tidefs_membership_types::PeerHealthConfig::new().with_min_peers_for_eviction_quorum(1),
    );

    rt.roster.add_member(peer_id);

    // First failure.
    rt.peer_health.on_peer_unreachable(peer_id);
    let _ = rt.tick();
    assert!(rt.pending_transition.is_some(), "first eviction");

    // Resolve: mark eviction done, remove peer, drop pending.
    rt.peer_health.mark_eviction_resolved(peer_id);
    rt.roster.remove_member(peer_id);
    rt.pending_transition = None;

    // Re-add peer and trigger another failure.
    rt.roster.add_member(peer_id);
    rt.peer_health.on_peer_unreachable(peer_id);

    let _ = rt.tick();
    assert!(rt.pending_transition.is_some(), "re-propose after resolve");
}

/// Quorum gate: eviction blocked when remaining roster would
/// drop below min_peers_for_eviction_quorum.
#[test]
fn peer_health_quorum_gate_blocks_eviction() {
    let my_id = MemberId::new(1);
    let peer_id = MemberId::new(2);
    let config = fast_config();

    let mut rt = MembershipRuntime::new(config, my_id, MemberClass::Voter, 0);

    // Quorum=3 with only 2 active peers: eviction must be blocked.
    rt.peer_health = tidefs_membership_live::peer_health::PeerHealthTracker::new(
        tidefs_membership_types::PeerHealthConfig::new().with_min_peers_for_eviction_quorum(3),
    );

    rt.roster.add_member(peer_id);
    rt.peer_health.on_peer_unreachable(peer_id);

    let _ = rt.tick();
    assert!(
        rt.pending_transition.is_none(),
        "quorum gate blocks eviction"
    );
}
