//! Transport-level integration test for lease wire protocol dispatch.
//!
//! Spawns two TCP transport sessions, sends a `LeaseRequest` from one,
//! verifies a `LeaseGrant` arrives on the other, exercising the full
//! encode → transport envelope → decode flow through real TCP loopback.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread;
use std::time::Duration;
use tidefs_lease::types::{LeaseClass, LeaseDomain};
use tidefs_lease::wire::{
    LeaseGrantPayload, LeaseReleasePayload, LeaseRenewPayload, LeaseRequestPayload,
    LeaseRevokePayload, LeaseWireMessage, RevokeReason,
};
use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_transport::{
    decode_lease_message, encode_lease_message, NodeInfo, SessionCloseReason, SessionId, Transport,
    TransportError,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn listening_transport(node_id: u64) -> (Transport, tidefs_transport::TransportAddr) {
    let mut transport = Transport::new(node_id);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    transport
        .bind(tidefs_transport::TransportAddr::Tcp(addr))
        .expect("bind");
    let bound_addr = transport.bind_addr.clone().expect("bind_addr");
    (transport, bound_addr)
}

fn blocking_accept(transport: &mut Transport) -> SessionId {
    for _ in 0..50 {
        match transport.accept_incoming() {
            Ok(sid) => return sid,
            Err(TransportError::Generic(ref e)) if e.contains("no pending connections") => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("accept error: {e}"),
        }
    }
    panic!("timeout waiting for incoming connection");
}

fn make_request() -> LeaseWireMessage {
    LeaseWireMessage::Request(LeaseRequestPayload {
        request_id: 42,
        lease_class: LeaseClass::Exclusive,
        domain: LeaseDomain::Inode {
            dataset_id: 1,
            ino: 100,
        },
        holder_id: MemberId(7),
        term_millis: 30_000,
        epoch: EpochId(5),
    })
}

fn make_grant() -> LeaseWireMessage {
    use tidefs_lease::types::LeaseGrant;
    let grant = LeaseGrant::request(
        99,
        LeaseClass::Exclusive,
        LeaseDomain::Inode {
            dataset_id: 1,
            ino: 100,
        },
        MemberId(7),
        0u64,
        30_000,
        1_000_000,
        EpochId(5),
        1,
        3,
        5,
    );
    LeaseWireMessage::Grant(LeaseGrantPayload {
        request_id: 42,
        grant,
    })
}

// ---------------------------------------------------------------------------
// Lease dispatch integration tests
// ---------------------------------------------------------------------------

/// Full lease request-response round-trip over two TCP sessions.
#[test]
fn lease_request_grant_roundtrip_over_transport() {
    let (mut server, server_addr) = listening_transport(1);
    let mut client = Transport::new(2);

    server.add_node(NodeInfo::new(2, vec![server_addr.clone()], 0));
    client.add_node(NodeInfo::new(1, vec![server_addr], 0));

    let request = make_request();
    let expected_grant = make_grant();

    let request_clone = request.clone();
    let grant_clone = expected_grant.clone();

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);
        server.perform_handshake(sid).expect("server handshake");

        // Receive LeaseRequest from client
        let raw = server.recv_message(sid).expect("server recv");
        let decoded = decode_lease_message(&raw).expect("server decode");
        assert_eq!(
            decoded, request_clone,
            "server received unexpected lease message"
        );

        // Send LeaseGrant back
        let encoded = encode_lease_message(&grant_clone).expect("server encode");
        server.send_message(sid, &encoded).expect("server send");

        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = client.connect(1).expect("connect");
    client.perform_handshake(sid).expect("client handshake");

    // Send LeaseRequest
    let encoded = encode_lease_message(&request).expect("client encode");
    client.send_message(sid, &encoded).expect("client send");

    // Receive LeaseGrant
    let raw = client.recv_message(sid).expect("client recv");
    let decoded = decode_lease_message(&raw).expect("client decode");
    assert_eq!(
        decoded, expected_grant,
        "client received unexpected lease grant"
    );

    client
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .ok();
    server_handle.join().expect("server thread");
}

/// Multi-message exchange: Request, Renew, Release over a single session.
#[test]
fn lease_multi_message_exchange_over_transport() {
    let (mut server, server_addr) = listening_transport(1);
    let mut client = Transport::new(2);

    server.add_node(NodeInfo::new(2, vec![server_addr.clone()], 0));
    client.add_node(NodeInfo::new(1, vec![server_addr], 0));

    let request = make_request();
    let renew = LeaseWireMessage::Renew(LeaseRenewPayload {
        lease_id: 99,
        holder_id: MemberId(7),
        epoch: EpochId(5),
    });
    let release = LeaseWireMessage::Release(LeaseReleasePayload {
        lease_id: 99,
        holder_id: MemberId(7),
        epoch: EpochId(5),
    });

    // Clone for server thread
    let request_srv = request.clone();
    let renew_srv = renew.clone();
    let release_srv = release.clone();

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);
        server.perform_handshake(sid).expect("server handshake");

        // Receive Request
        let raw = server.recv_message(sid).expect("server recv req");
        let decoded = decode_lease_message(&raw).expect("server decode req");
        assert_eq!(decoded, request_srv);

        // Receive Renew
        let raw = server.recv_message(sid).expect("server recv renew");
        let decoded = decode_lease_message(&raw).expect("server decode renew");
        assert_eq!(decoded, renew_srv);

        // Receive Release
        let raw = server.recv_message(sid).expect("server recv release");
        let decoded = decode_lease_message(&raw).expect("server decode release");
        assert_eq!(decoded, release_srv);

        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = client.connect(1).expect("connect");
    client.perform_handshake(sid).expect("client handshake");

    // Send Request
    client
        .send_message(sid, &encode_lease_message(&request).expect("encode"))
        .expect("send req");

    // Send Renew
    client
        .send_message(sid, &encode_lease_message(&renew).expect("encode"))
        .expect("send renew");

    // Send Release
    client
        .send_message(sid, &encode_lease_message(&release).expect("encode"))
        .expect("send release");

    client
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .ok();
    server_handle.join().expect("server thread");
}

/// Revoke message round-trip.
#[test]
fn lease_revoke_roundtrip_over_transport() {
    let (mut server, server_addr) = listening_transport(1);
    let mut client = Transport::new(2);

    server.add_node(NodeInfo::new(2, vec![server_addr.clone()], 0));
    client.add_node(NodeInfo::new(1, vec![server_addr], 0));

    let revoke = LeaseWireMessage::Revoke(LeaseRevokePayload {
        lease_id: 55,
        epoch: EpochId(3),
        reason: RevokeReason::Fencing,
    });
    let revoke_srv = revoke.clone();

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);
        server.perform_handshake(sid).expect("server handshake");

        let raw = server.recv_message(sid).expect("server recv");
        let decoded = decode_lease_message(&raw).expect("server decode");
        assert_eq!(decoded, revoke_srv);

        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = client.connect(1).expect("connect");
    client.perform_handshake(sid).expect("client handshake");

    client
        .send_message(sid, &encode_lease_message(&revoke).expect("encode"))
        .expect("send");

    thread::sleep(Duration::from_millis(100));
    client
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .ok();
    server_handle.join().expect("server thread");
}

/// Verify that garbage bytes on the transport are rejected at the lease decode layer.
#[test]
fn lease_decode_rejects_transport_garbage() {
    let (mut server, server_addr) = listening_transport(1);
    let mut client = Transport::new(2);

    server.add_node(NodeInfo::new(2, vec![server_addr.clone()], 0));
    client.add_node(NodeInfo::new(1, vec![server_addr], 0));

    let garbage = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
    let garbage_srv = garbage.clone();

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);
        server.perform_handshake(sid).expect("server handshake");

        let raw = server.recv_message(sid).expect("server recv");
        assert_eq!(raw, garbage_srv);
        let result = decode_lease_message(&raw);
        assert!(result.is_err(), "should reject garbage bytes");

        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = client.connect(1).expect("connect");
    client.perform_handshake(sid).expect("client handshake");

    client.send_message(sid, &garbage).expect("send garbage");

    thread::sleep(Duration::from_millis(100));
    client
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .ok();
    server_handle.join().expect("server thread");
}
