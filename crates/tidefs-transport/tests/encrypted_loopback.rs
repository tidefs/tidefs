// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests: parameter-negotiation token exchange and
//! ChaCha20-Poly1305 session cipher correctness over deterministic
//! loopback transport.
use std::cell::RefCell;
use std::rc::Rc;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tidefs_membership_epoch::{EpochMemberSet, NodeIdentity};
use tidefs_transport::backend::TransportBackendKind;
use tidefs_transport::harness::{
    DeterministicMessageScheduler, LoopbackTransport, SchedulerConfig, SimNode,
};
use tidefs_transport::session::handshake::{
    ClientHandshake, HandshakeFrame, HandshakeState, ServerHandshake,
};
use tidefs_transport::session::Session;
use tidefs_transport::session_cipher::{
    CipherError, Direction, SessionKeyMaterial, TransportSessionCipher,
};
use tidefs_transport::types::{FamilyVersion, NodeIdentityPublic, SessionId};
use tidefs_types_transport_session::EndpointFamily;

fn make_scheduler() -> Rc<RefCell<DeterministicMessageScheduler>> {
    Rc::new(RefCell::new(DeterministicMessageScheduler::new(
        SchedulerConfig::deterministic(42),
    )))
}

fn nid(id: u64) -> NodeIdentity {
    NodeIdentity::new(id)
}

fn test_identity(seed: u64) -> NodeIdentityPublic {
    let mut state = seed.wrapping_mul(0x9E3779B97F4A7C15);
    state ^= state >> 30;
    state = state.wrapping_mul(0xBF58476D1CE4E5B9);
    state ^= state >> 27;
    state = state.wrapping_mul(0x94D049BB133111EB);
    state ^= state >> 31;
    let mut key_bytes = [0u8; 32];
    for byte in &mut key_bytes {
        state = state.wrapping_mul(0x9E3779B97F4A7C15);
        state ^= state >> 30;
        state = state.wrapping_mul(0xBF58476D1CE4E5B9);
        state ^= state >> 27;
        *byte = (state >> 24) as u8;
    }
    let secret = ed25519_dalek::SecretKey::from_bytes(&key_bytes).expect("valid secret key");
    let public = ed25519_dalek::PublicKey::from(&secret);
    NodeIdentityPublic {
        node_id: seed,
        verifying_key_bytes: public.to_bytes(),
        attested_at_millis: 0,
        identity_version: 1,
        self_signature: Vec::new(),
    }
}

fn make_sim_node(node_id: u64, scheduler: Rc<RefCell<DeterministicMessageScheduler>>) -> SimNode {
    let identity = nid(node_id);
    scheduler.borrow_mut().register_node(identity);
    let transport = LoopbackTransport::new(identity, Rc::clone(&scheduler));
    let members = EpochMemberSet::new(vec![identity]);
    SimNode::new(identity, transport, members)
}

struct RawKeyMaterial([u8; 32]);
impl SessionKeyMaterial for RawKeyMaterial {
    fn shared_secret(&self) -> &[u8; 32] {
        &self.0
    }
}

#[test]
fn handshake_negotiation_token_exchange() {
    let sched = make_scheduler();
    sched.borrow_mut().register_nodes([nid(1), nid(2)]);

    let _client_node = make_sim_node(1, Rc::clone(&sched));
    let _server_node = make_sim_node(2, Rc::clone(&sched));

    let client_id = test_identity(1);
    let server_id = test_identity(2);

    let (mut client_hs, client_hello) = ClientHandshake::initiate(
        1,
        client_id.clone(),
        vec![FamilyVersion::new(1, 1, 0)],
        1,
        42,
    )
    .expect("client initiate");

    let client_hello_frame = HandshakeFrame::ClientHello(client_hello.clone())
        .encode()
        .expect("encode ClientHello");
    sched
        .borrow_mut()
        .send(nid(1), nid(2), 42, client_hello_frame, 0);
    sched.borrow_mut().tick();

    let server_msg = sched
        .borrow_mut()
        .recv(nid(2))
        .expect("server recv ClientHello");
    let received_hello = match HandshakeFrame::decode(&server_msg.payload).unwrap() {
        HandshakeFrame::ClientHello(h) => h,
        other => panic!("expected ClientHello, got {other:?}"),
    };

    let (mut server_hs, server_hello, server_finished) = ServerHandshake::respond(
        received_hello,
        2,
        server_id.clone(),
        vec![FamilyVersion::new(1, 1, 0)],
        1,
        42,
    )
    .expect("server respond");

    let sh_frame = HandshakeFrame::ServerHello(server_hello.clone())
        .encode()
        .unwrap();
    let sf_frame = HandshakeFrame::ServerVerify(server_finished.clone())
        .encode()
        .unwrap();
    sched.borrow_mut().send(nid(2), nid(1), 42, sh_frame, 0);
    sched.borrow_mut().send(nid(2), nid(1), 42, sf_frame, 1);
    sched.borrow_mut().tick();

    let msg1 = sched
        .borrow_mut()
        .recv(nid(1))
        .expect("client recv ServerHello");
    let sh = match HandshakeFrame::decode(&msg1.payload).unwrap() {
        HandshakeFrame::ServerHello(h) => h,
        other => panic!("expected ServerHello, got {other:?}"),
    };
    let msg2 = sched
        .borrow_mut()
        .recv(nid(1))
        .expect("client recv ServerVerify");
    let sf = match HandshakeFrame::decode(&msg2.payload).unwrap() {
        HandshakeFrame::ServerVerify(f) => f,
        other => panic!("expected ServerVerify, got {other:?}"),
    };

    let client_finished = client_hs
        .handle_server_hello(sh, sf)
        .expect("client handle server hello");
    let cf_frame = HandshakeFrame::ClientVerify(client_finished.clone())
        .encode()
        .unwrap();
    sched.borrow_mut().send(nid(1), nid(2), 42, cf_frame, 1);
    sched.borrow_mut().tick();

    let msg3 = sched
        .borrow_mut()
        .recv(nid(2))
        .expect("server recv ClientVerify");
    let cf = match HandshakeFrame::decode(&msg3.payload).unwrap() {
        HandshakeFrame::ClientVerify(f) => f,
        other => panic!("expected ClientVerify, got {other:?}"),
    };

    let server_complete = server_hs
        .handle_client_finished(cf, client_hello)
        .expect("server handle client finished");
    let client_complete = match client_hs.state() {
        HandshakeState::Complete(c) => c,
        other => panic!("expected Complete, got {other:?}"),
    };

    assert_eq!(
        client_complete.negotiation_token,
        server_complete.negotiation_token
    );

    // Negotiation tokens match, confirming both peers computed the same transcript.
    // The negotiation token is NOT an encryption key; it is a public transcript
    // agreement token. Real session encryption keys come from tidefs-auth.
    assert_ne!(client_complete.negotiation_token, [0u8; 32]);
}

#[test]
fn encrypted_loopback_tamper_rejected() {
    let key = [0x42u8; 32];
    // Use fresh instances so no prior nonce state interferes.
    let mut alice =
        TransportSessionCipher::new(&RawKeyMaterial(key), Direction::InitiatorToResponder);
    let mut bob =
        TransportSessionCipher::new(&RawKeyMaterial(key), Direction::InitiatorToResponder);
    let mut tampered = alice.seal(b"secret").unwrap();
    // Flip a byte in the ciphertext (past the 12-byte nonce).
    tampered[13] ^= 0x01;
    assert!(matches!(
        bob.open(&tampered),
        Err(CipherError::AeadOpenFailed)
    ));
}

#[test]
fn encrypted_loopback_session_isolation() {
    let mut alice = TransportSessionCipher::new(
        &RawKeyMaterial([0xAAu8; 32]),
        Direction::InitiatorToResponder,
    );
    let mut bob = TransportSessionCipher::new(
        &RawKeyMaterial([0xBBu8; 32]),
        Direction::InitiatorToResponder,
    );
    let sealed = alice.seal(b"for alice only").unwrap();
    assert!(matches!(
        bob.open(&sealed),
        Err(CipherError::AeadOpenFailed)
    ));
}

#[test]
fn encrypted_loopback_nonce_replay_rejected() {
    let key = [0x77u8; 32];
    let mut alice =
        TransportSessionCipher::new(&RawKeyMaterial(key), Direction::InitiatorToResponder);
    let mut bob =
        TransportSessionCipher::new(&RawKeyMaterial(key), Direction::InitiatorToResponder);
    let sealed = alice.seal(b"first").unwrap();
    bob.open(&sealed).unwrap();
    assert!(matches!(
        bob.open(&sealed),
        Err(CipherError::NonceReuse { .. })
    ));
}

#[test]
fn session_init_ciphers_and_seal_open() {
    // Test that the Session struct stores ciphers correctly and that
    // outbound sealing works. Self-open is not expected to work because
    // outbound and inbound ciphers use different HKDF direction tags.
    let addr = tidefs_transport::TransportAddr::Tcp(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        8000,
    ));
    let mut session = Session::new(
        SessionId::new(1),
        10,
        20,
        addr.clone(),
        EndpointFamily::LocalEmbed,
        TransportBackendKind::Tcp,
    );
    assert!(!session.has_ciphers());
    session.init_ciphers_from_key(&[0x13u8; 32], true);
    assert!(session.has_ciphers());

    // Sealing should succeed
    let _sealed = session.seal_message(b"session encryption").unwrap();

    // Opening with the same session's inbound cipher should fail
    // because outbound and inbound use different HKDF directions.
    let result = session.open_message(&_sealed);
    assert!(
        result.is_err(),
        "inbound cipher should not decrypt outbound cipher's output on single session"
    );
}

#[test]
fn session_init_ciphers_cross_direction() {
    let addr = tidefs_transport::TransportAddr::Tcp(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        8001,
    ));
    let mut init = Session::new(
        SessionId::new(1),
        10,
        20,
        addr.clone(),
        EndpointFamily::LocalEmbed,
        TransportBackendKind::Tcp,
    );
    let mut resp = Session::new(
        SessionId::new(2),
        20,
        10,
        addr,
        EndpointFamily::LocalEmbed,
        TransportBackendKind::Tcp,
    );
    init.init_ciphers_from_key(&[0x24u8; 32], true);
    resp.init_ciphers_from_key(&[0x24u8; 32], false);

    let sealed = init.seal_message(b"hello").unwrap();
    assert_eq!(resp.open_message(&sealed).unwrap(), b"hello");

    let sealed2 = resp.seal_message(b"world").unwrap();
    assert_eq!(init.open_message(&sealed2).unwrap(), b"world");
}
