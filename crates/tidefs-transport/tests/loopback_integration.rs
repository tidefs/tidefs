//! Integration test: loopback backend with Transport stack.
//!
//! Validates that `LoopbackTransportBackend` and `LoopbackConnectionPair`
//! correctly implement the `TransportBackend` and `ConnectionLike` traits,
//! making them compatible as drop-in backends for the full Transport/Session
//! stack.
//!
//! Full session handshake + framed message exchange over loopback is
//! exercised by the deterministic `LoopbackNetwork` harness (see
//! `harness::tests` and `membership-live::loopback_protocol_tests`).

#![cfg(feature = "loopback")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tidefs_transport::loopback_v2::{LoopbackConnectionPair, LoopbackTransportBackend};
use tidefs_transport::{
    backend::{ConnectionLike, TransportBackend, TransportBackendKind},
    NodeInfo, SessionCloseReason, SessionState, Transport,
};

fn make_node_info(node_id: u64, addrs: Vec<tidefs_transport::TransportAddr>) -> NodeInfo {
    NodeInfo::new(node_id, addrs, 0)
}

#[test]
fn loopback_connection_pair_framed_transport_envelope_exchange() {
    let mut pair = LoopbackConnectionPair::new();

    let envelope = b"VEFS\x01\x00\x00\x00\x00\x00\x00\x00framed payload from A";
    pair.initiator.write_frame(envelope).expect("write");
    let received = pair.responder.read_frame().expect("read");
    assert_eq!(received, envelope);

    let response = b"VEFS\x01\x00\x00\x00\x00\x00\x00\x00framed response from B";
    pair.responder.write_frame(response).expect("write");
    let received = pair.initiator.read_frame().expect("read");
    assert_eq!(received, response);
}

#[test]
fn loopback_transport_backend_connect_and_accept() {
    let (mut client_backend, mut server_backend) = LoopbackTransportBackend::new_shared_pair();

    let loopback = tidefs_transport::TransportAddr::Tcp(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        0,
    ));
    let peer = make_node_info(2, vec![loopback]);

    let mut client_conn = client_backend.connect(&peer).expect("connect");
    let (mut server_conn, _addr) = server_backend.accept().expect("accept");

    client_conn
        .write_frame(b"client to server")
        .expect("client write");
    let msg = server_conn.read_frame().expect("server read");
    assert_eq!(msg, b"client to server");

    server_conn
        .write_frame(b"server to client")
        .expect("server write");
    let msg = client_conn.read_frame().expect("client read");
    assert_eq!(msg, b"server to client");

    client_conn.close();
    server_conn.close();
}

#[test]
fn loopback_transport_backend_transport_connect() {
    let backend = Box::new(LoopbackTransportBackend::new());
    let mut transport = Transport::with_backend(1, backend);

    let loopback = tidefs_transport::TransportAddr::Tcp(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        0,
    ));
    transport.add_node(make_node_info(2, vec![loopback]));

    let sid = transport.connect(2).expect("connect");

    let session = transport
        .sessions
        .get(&sid)
        .expect("session")
        .lock()
        .unwrap();

    let is_connecting = matches!(session.state, SessionState::Connecting { .. });
    let local = session.local_node;
    let peer = session.peer_node;
    let kind = session.backend_kind;
    drop(session);

    assert!(is_connecting);
    assert_eq!(local, 1);
    assert_eq!(peer, 2);
    assert_eq!(
        kind,
        TransportBackendKind::Tcp,
        "loopback backend reports as Tcp"
    );

    transport
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .ok();
}
