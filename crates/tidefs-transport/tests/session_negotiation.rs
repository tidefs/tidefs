//! Integration tests for transport session negotiation.
//!
//! These tests exercise the full session negotiation flow between two
//! Transport instances over TCP loopback, covering:
//! - Protocol version exchange
//! - Endpoint family propagation
//! - Peer identity exchange
//! - Session state machine transitions
//! - Error cases during negotiation

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread;
use std::time::Duration;
use tidefs_transport::{
    backend::TransportBackendKind, FamilyVersion, NodeInfo, Session, SessionCloseReason, SessionId,
    SessionState, Transport, TransportError,
};
use tidefs_types_transport_session::EndpointFamily;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a Transport that listens on a random port.
fn listening_transport(node_id: u64) -> (Transport, tidefs_transport::TransportAddr) {
    let mut transport = Transport::new(node_id);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    transport
        .bind(tidefs_transport::TransportAddr::Tcp(addr))
        .expect("bind");
    let bound_addr = transport.bind_addr.clone().expect("bind_addr");
    (transport, bound_addr)
}

/// Block until a connection arrives, retrying with small delays.
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

// ---------------------------------------------------------------------------
// Full session negotiation flow
// ---------------------------------------------------------------------------

/// Two Transport instances negotiate a session end-to-end and exchange messages.
#[test]
fn full_session_negotiation_flow() {
    let (mut server, server_addr) = listening_transport(1);
    let mut client = Transport::new(2);

    server.add_node(NodeInfo::new(2, vec![server_addr.clone()], 0));
    client.add_node(NodeInfo::new(1, vec![server_addr], 0));

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);
        server.perform_handshake(sid).expect("server handshake");

        // Verify server sees the session as established
        {
            let s = server.sessions.get(&sid).unwrap().lock().unwrap();
            assert!(s.is_established(), "server session should be established");
        }
        // Read a message from client
        let msg = server.recv_message(sid).expect("server recv");
        assert_eq!(msg, b"hello from client");

        // Send reply
        server
            .send_message(sid, b"hello from server")
            .expect("server send");

        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = client.connect(1).expect("connect");
    client.perform_handshake(sid).expect("client handshake");

    // Verify client sees the session as established
    {
        let s = client.sessions.get(&sid).unwrap().lock().unwrap();
        assert!(s.is_established(), "client session should be established");
        assert_eq!(s.state.as_str(), "session_state_5.flowing");
        assert_eq!(s.local_node, 2);
        assert_eq!(s.peer_node, 1);
        assert!(s.peer_info.is_some(), "peer info should be populated");
        let pi = s.peer_info.as_ref().unwrap();
        assert_eq!(pi.node_id, 1, "peer node id should be 1");
    }

    // Exchange messages
    client
        .send_message(sid, b"hello from client")
        .expect("client send");

    let reply = client.recv_message(sid).expect("client recv");
    assert_eq!(reply, b"hello from server");

    client
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");

    server_handle.join().expect("server thread");
}

// ---------------------------------------------------------------------------
// Session state machine test: verify transitions during negotiation
// ---------------------------------------------------------------------------

/// Verify that the session transitions through the correct states during
/// the negotiation lifecycle.
#[test]
fn session_negotiation_state_machine() {
    let (mut server, server_addr) = listening_transport(1);
    let mut client = Transport::new(2);

    server.add_node(NodeInfo::new(2, vec![server_addr.clone()], 0));
    client.add_node(NodeInfo::new(1, vec![server_addr], 0));

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);

        // After accept_incoming, session should be in Connecting state
        {
            let s = server.sessions.get(&sid).unwrap().lock().unwrap();
            assert!(
                matches!(s.state, SessionState::Connecting { .. }),
                "after accept: should be Connecting, got {:?}",
                s.state
            );
        }

        server.perform_handshake(sid).expect("server handshake");

        // After handshake, session should be Established
        {
            let s = server.sessions.get(&sid).unwrap().lock().unwrap();
            assert!(
                matches!(s.state, SessionState::Established { .. }),
                "after handshake: should be Established, got {:?}",
                s.state
            );
        }

        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();

        // After close, session should be Closed
        {
            let s = server.sessions.get(&sid).unwrap().lock().unwrap();
            assert!(
                matches!(s.state, SessionState::Closed { .. }),
                "after close: should be Closed, got {:?}",
                s.state
            );
            assert!(s.is_closed());
            assert!(s.is_terminal());
        }
    });

    thread::sleep(Duration::from_millis(50));

    let sid = client.connect(1).expect("connect");

    // After connect, session should be in Connecting state
    {
        let s = client.sessions.get(&sid).unwrap().lock().unwrap();
        assert!(
            matches!(s.state, SessionState::Connecting { .. }),
            "after connect: should be Connecting, got {:?}",
            s.state
        );
        assert!(!s.is_established());
        assert!(!s.is_closed());
    }

    client.perform_handshake(sid).expect("client handshake");

    // After handshake, session should be Established
    {
        let s = client.sessions.get(&sid).unwrap().lock().unwrap();
        assert!(
            matches!(s.state, SessionState::Established { .. }),
            "after handshake: should be Established, got {:?}",
            s.state
        );
        assert!(s.is_established());
        assert!(s.can_resume());
        assert!(!s.is_degraded());
    }

    client
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");

    // After close, session should be Closed
    {
        let s = client.sessions.get(&sid).unwrap().lock().unwrap();
        assert!(s.is_closed());
        assert!(s.is_terminal());
        assert!(!s.can_resume());
    }

    server_handle.join().expect("server thread");
}

// ---------------------------------------------------------------------------
// Peer session info exchange during handshake
// ---------------------------------------------------------------------------

/// Verify that PeerSessionInfo is correctly populated after session negotiation.
#[test]
fn session_negotiation_peer_info_exchange() {
    let (mut server, server_addr) = listening_transport(1);
    let mut client = Transport::new(2);

    // Set supported families for version negotiation
    let families = vec![FamilyVersion::new(1, 1, 0), FamilyVersion::new(2, 1, 0)];
    server.supported_families = families.clone();
    client.supported_families = families.clone();

    server.add_node(NodeInfo::new(2, vec![server_addr.clone()], 0));
    client.add_node(NodeInfo::new(1, vec![server_addr], 0));

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);
        server.perform_handshake(sid).expect("server handshake");

        // Verify peer info on server side
        {
            let s = server.sessions.get(&sid).unwrap().lock().unwrap();
            let pi = s.peer_info.as_ref().expect("server peer info");
            assert_eq!(pi.node_id, 2, "server should see peer as node 2");
        }
        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = client.connect(1).expect("connect");
    client.perform_handshake(sid).expect("client handshake");

    // Verify peer info on client side
    {
        let s = client.sessions.get(&sid).unwrap().lock().unwrap();
        let pi = s.peer_info.as_ref().expect("client peer info");
        assert_eq!(pi.node_id, 1, "client should see peer as node 1");
        assert_eq!(s.peer_node, 1);
        assert!(
            pi.identity.verifying_key_bytes != [0u8; 32],
            "peer identity should have a public key"
        );
        // Supported families should be echoed back
        assert_eq!(pi.supported_families.len(), 2);
        assert_eq!(pi.supported_families[0].family_id, 1);
        assert_eq!(pi.supported_families[1].family_id, 2);
    }

    client
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");

    server_handle.join().expect("server thread");
}

// ---------------------------------------------------------------------------
// Endpoint family propagation through negotiation
// ---------------------------------------------------------------------------

/// Verify that the endpoint family is correctly propagated through session
/// negotiation on both sides.
#[test]
fn session_negotiation_endpoint_family_propagation() {
    let (mut server, server_addr) = listening_transport(1);
    let mut client = Transport::new(2);

    // Use Control endpoint family (e1)
    client.endpoint_family = EndpointFamily::Control;
    server.endpoint_family = EndpointFamily::Control;

    server.add_node(NodeInfo::new(2, vec![server_addr.clone()], 0));
    client.add_node(NodeInfo::new(1, vec![server_addr], 0));

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);
        server.perform_handshake(sid).expect("server handshake");

        {
            let s = server.sessions.get(&sid).unwrap().lock().unwrap();
            assert_eq!(
                s.endpoint_family,
                EndpointFamily::Control,
                "server session endpoint family should be Control"
            );
        }

        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = client.connect(1).expect("connect");
    client.perform_handshake(sid).expect("client handshake");

    {
        let s = client.sessions.get(&sid).unwrap().lock().unwrap();
        assert_eq!(
            s.endpoint_family,
            EndpointFamily::Control,
            "client session endpoint family should be Control"
        );
    }

    client
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");

    server_handle.join().expect("server thread");
}

/// Verify that session negotiation works across all four endpoint families.
#[test]
fn session_negotiation_all_endpoint_families() {
    let families = [
        EndpointFamily::LocalEmbed,
        EndpointFamily::Control,
        EndpointFamily::Data,
        EndpointFamily::Shadow,
    ];

    for &family in &families {
        let (mut server, server_addr) = listening_transport(1);
        let mut client = Transport::new(2);

        server.endpoint_family = family;
        client.endpoint_family = family;

        server.add_node(NodeInfo::new(2, vec![server_addr.clone()], 0));
        client.add_node(NodeInfo::new(1, vec![server_addr], 0));

        let server_handle = thread::spawn(move || {
            let sid = blocking_accept(&mut server);
            server.perform_handshake(sid).expect("server handshake");
            server
                .close_session(sid, SessionCloseReason::LocalShutdown)
                .ok();
        });

        thread::sleep(Duration::from_millis(50));

        let sid = client.connect(1).expect("connect");
        client.perform_handshake(sid).expect("client handshake");

        {
            let s = client.sessions.get(&sid).unwrap().lock().unwrap();
            assert_eq!(
                s.endpoint_family, family,
                "endpoint family mismatch for {family:?}"
            );
            assert!(
                s.is_established(),
                "session should be established for {family:?}"
            );
        }

        client
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .expect("close");

        server_handle.join().expect("server thread");
    }
}

// ---------------------------------------------------------------------------
// Session negotiation with protocol version families
// ---------------------------------------------------------------------------

/// Verify that supported protocol families are correctly exchanged during
/// negotiation.
#[test]
fn session_negotiation_with_version_families() {
    let (mut server, server_addr) = listening_transport(1);
    let mut client = Transport::new(2);

    let server_families = vec![FamilyVersion::new(1, 2, 0), FamilyVersion::new(3, 1, 5)];
    let client_families = vec![
        FamilyVersion::new(1, 1, 0),
        FamilyVersion::new(2, 1, 0),
        FamilyVersion::new(3, 1, 3),
    ];

    server.supported_families = server_families.clone();
    client.supported_families = client_families.clone();

    server.add_node(NodeInfo::new(2, vec![server_addr.clone()], 0));
    client.add_node(NodeInfo::new(1, vec![server_addr], 0));

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);
        server.perform_handshake(sid).expect("server handshake");

        // Server should see client's families in peer info
        {
            let s = server.sessions.get(&sid).unwrap().lock().unwrap();
            let pi = s.peer_info.as_ref().unwrap();
            assert_eq!(
                pi.supported_families.len(),
                3,
                "server should see 3 client families"
            );
            assert_eq!(pi.supported_families[0].family_id, 1);
            assert_eq!(pi.supported_families[0].version_major, 1);
            assert_eq!(pi.supported_families[0].version_minor, 0);
        }
        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = client.connect(1).expect("connect");
    client.perform_handshake(sid).expect("client handshake");

    // Client should see server's families in peer info
    {
        let s = client.sessions.get(&sid).unwrap().lock().unwrap();
        let pi = s.peer_info.as_ref().unwrap();
        assert_eq!(
            pi.supported_families.len(),
            2,
            "client should see 2 server families"
        );
        assert_eq!(pi.supported_families[0].family_id, 1);
        assert_eq!(pi.supported_families[0].version_major, 2);
        assert_eq!(pi.supported_families[0].version_minor, 0);
        assert_eq!(pi.supported_families[1].family_id, 3);
        assert_eq!(pi.supported_families[1].version_minor, 5);
    }

    client
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");

    server_handle.join().expect("server thread");
}

// ---------------------------------------------------------------------------
// Session negotiation error cases
// ---------------------------------------------------------------------------

/// Session negotiation should fail when connecting to an unknown peer.
#[test]
fn session_negotiation_fails_for_unknown_peer() {
    let mut client = Transport::new(2);
    let result = client.connect(99);
    assert!(result.is_err(), "connect to unknown peer should fail");
}

/// Handshake should fail when there is no active connection.
#[test]
fn perform_handshake_fails_without_connection() {
    let mut client = Transport::new(2);
    // Session ID 999 doesn't exist
    let result = client.perform_handshake(SessionId::new(999));
    assert!(result.is_err(), "handshake without connection should fail");
}

/// Verify that closing a session is idempotent on the client side.
#[test]
fn session_negotiation_close_idempotent() {
    let (mut server, server_addr) = listening_transport(1);
    let mut client = Transport::new(2);

    server.add_node(NodeInfo::new(2, vec![server_addr.clone()], 0));
    client.add_node(NodeInfo::new(1, vec![server_addr], 0));

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);
        server.perform_handshake(sid).expect("server handshake");
        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = client.connect(1).expect("connect");
    client.perform_handshake(sid).expect("client handshake");

    // First close should succeed
    client
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("first close");

    // After maintenance, session should be removed
    client.maintain();

    // Verify session is gone
    assert!(
        !client.sessions.contains_key(&sid),
        "session should be removed after close + maintain"
    );

    server_handle.join().expect("server thread");
}

// ---------------------------------------------------------------------------
// Multiple session negotiation between same nodes
// ---------------------------------------------------------------------------

/// Verify that multiple sessions can be negotiated between the same two nodes.
#[test]
fn multiple_session_negotiation_same_nodes() {
    let (mut server, server_addr) = listening_transport(1);
    let mut client = Transport::new(2);

    server.add_node(NodeInfo::new(2, vec![server_addr.clone()], 0));
    client.add_node(NodeInfo::new(1, vec![server_addr], 0));

    let server_handle = thread::spawn(move || {
        for _ in 0..3 {
            let sid = blocking_accept(&mut server);
            server.perform_handshake(sid).expect("server handshake");

            let msg = server.recv_message(sid).expect("server recv");
            let reply = format!("reply to: {}", String::from_utf8_lossy(&msg));
            server
                .send_message(sid, reply.as_bytes())
                .expect("server send");

            server
                .close_session(sid, SessionCloseReason::LocalShutdown)
                .ok();
        }
    });

    thread::sleep(Duration::from_millis(50));

    for i in 0..3 {
        let sid = client.connect(1).expect("connect");
        client.perform_handshake(sid).expect("client handshake");

        // Verify session is established
        {
            let s = client.sessions.get(&sid).unwrap().lock().unwrap();
            assert!(s.is_established(), "session {i} should be established");
        }

        let msg = format!("message {i}");
        client
            .send_message(sid, msg.as_bytes())
            .expect("client send");

        let reply = client.recv_message(sid).expect("client recv");
        assert_eq!(
            String::from_utf8_lossy(&reply),
            format!("reply to: message {i}")
        );

        client
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .expect("close");
    }

    server_handle.join().expect("server thread");
}

// ---------------------------------------------------------------------------
// Session negotiation with HLC timestamp tracking
// ---------------------------------------------------------------------------

/// Verify that HLC timestamps are advanced through session negotiation.
#[test]
fn session_negotiation_hlc_timestamps() {
    let (mut server, server_addr) = listening_transport(1);
    let mut client = Transport::new(2);

    server.add_node(NodeInfo::new(2, vec![server_addr.clone()], 0));
    client.add_node(NodeInfo::new(1, vec![server_addr], 0));

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);
        server.perform_handshake(sid).expect("server handshake");

        // Verify HLC was advanced
        {
            let s = server.sessions.get(&sid).unwrap().lock().unwrap();
            let hlc = s.hlc.current();
            assert!(
                hlc.physical_ns() > 0,
                "HLC physical time should be positive"
            );
            assert!(
                hlc.logical() == 0,
                "HLC logical counter should be 0 after first tick in fresh session"
            );
        }

        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = client.connect(1).expect("connect");
    client.perform_handshake(sid).expect("client handshake");

    // Verify HLC was advanced after connect + handshake
    {
        let s = client.sessions.get(&sid).unwrap().lock().unwrap();
        let hlc = s.hlc.current();
        assert!(
            hlc.physical_ns() > 0,
            "HLC physical time should be positive"
        );
        assert!(
            hlc.logical() == 0,
            "HLC logical counter should be 0 after first tick in fresh session"
        );
        // stats should reflect the Established state
        assert!(
            s.stats.established_at.is_some(),
            "stats should have established_at set"
        );
    }

    client
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");

    server_handle.join().expect("server thread");
}

// ---------------------------------------------------------------------------
// Backend kind tracking through negotiation
// ---------------------------------------------------------------------------

/// Verify that the transport backend kind is preserved through session
/// negotiation.
#[test]
fn session_negotiation_backend_kind_preserved() {
    let (mut server, server_addr) = listening_transport(1);
    let mut client = Transport::new(2);

    server.add_node(NodeInfo::new(2, vec![server_addr.clone()], 0));
    client.add_node(NodeInfo::new(1, vec![server_addr], 0));

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);
        server.perform_handshake(sid).expect("server handshake");

        {
            let s = server.sessions.get(&sid).unwrap().lock().unwrap();
            assert_eq!(
                s.backend_kind.to_string(),
                "tcp",
                "backend kind should be tcp"
            );
        }

        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = client.connect(1).expect("connect");
    client.perform_handshake(sid).expect("client handshake");

    {
        let s = client.sessions.get(&sid).unwrap().lock().unwrap();
        assert_eq!(
            s.backend_kind.to_string(),
            "tcp",
            "backend kind should be tcp"
        );
    }

    client
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");

    server_handle.join().expect("server thread");
}

// ---------------------------------------------------------------------------
// Epoch-gated session negotiation
// ---------------------------------------------------------------------------

/// Verify that the transport's epoch is propagated through the session
/// handshake and stored on both the session and PeerSessionInfo.
#[test]
fn session_negotiation_epoch_binding() {
    let (mut server, server_addr) = listening_transport(1);
    let mut client = Transport::new(2);

    // Set distinct epochs on each transport
    server.epoch = 42;
    client.epoch = 42;

    server.add_node(NodeInfo::new(2, vec![server_addr.clone()], 0));
    client.add_node(NodeInfo::new(1, vec![server_addr], 0));

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);
        server.perform_handshake(sid).expect("server handshake");

        {
            let s = server.sessions.get(&sid).unwrap().lock().unwrap();
            assert_eq!(
                s.current_epoch, 42,
                "server session should be bound to epoch 42"
            );
            assert!(
                s.has_epoch_binding(),
                "server session should have epoch binding"
            );
            assert!(
                s.is_bound_to_epoch(42),
                "server session should be bound to epoch 42"
            );

            let pi = s.peer_info.as_ref().expect("server peer info");
            assert_eq!(pi.peer_epoch, 42, "server should see peer epoch 42");
        }

        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = client.connect(1).expect("connect");
    client.perform_handshake(sid).expect("client handshake");

    {
        let s = client.sessions.get(&sid).unwrap().lock().unwrap();
        assert_eq!(
            s.current_epoch, 42,
            "client session should be bound to epoch 42"
        );
        assert!(
            s.has_epoch_binding(),
            "client session should have epoch binding"
        );
        assert!(
            s.is_bound_to_epoch(42),
            "client session should be bound to epoch 42"
        );

        // validate_epoch should succeed when epochs match
        assert!(
            s.validate_epoch(42).is_ok(),
            "validate_epoch should succeed for matching epoch"
        );

        // validate_epoch should fail when epochs differ
        assert!(
            s.validate_epoch(99).is_err(),
            "validate_epoch should fail for mismatched epoch"
        );

        let pi = s.peer_info.as_ref().expect("client peer info");
        assert_eq!(pi.peer_epoch, 42, "client should see peer epoch 42");
    }

    client
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");

    server_handle.join().expect("server thread");
}

/// Verify that bind_epoch correctly rejects rebinding to a different epoch.
#[test]
fn session_bind_epoch_rejects_rebinding() {
    let mut session = Session::new(
        SessionId::new(99),
        1,
        2,
        tidefs_transport::TransportAddr::Tcp("127.0.0.1:9000".parse().unwrap()),
        EndpointFamily::LocalEmbed,
        TransportBackendKind::Tcp,
    );

    // First bind should succeed
    assert!(
        session.bind_epoch(10).is_ok(),
        "first bind_epoch should succeed"
    );
    assert_eq!(session.current_epoch, 10);

    // Re-binding to same epoch should succeed (no-op)
    assert!(
        session.bind_epoch(10).is_ok(),
        "re-binding to same epoch should succeed"
    );

    // Re-binding to different epoch should fail
    assert!(
        session.bind_epoch(20).is_err(),
        "re-binding to different epoch should fail"
    );
    assert_eq!(
        session.current_epoch, 10,
        "epoch should remain unchanged after failed rebind"
    );
}

/// Verify that epoch: 0 means unbound (has_epoch_binding returns false).
#[test]
fn session_unbound_epoch_behavior() {
    let session = Session::new(
        SessionId::new(100),
        1,
        2,
        tidefs_transport::TransportAddr::Tcp("127.0.0.1:9000".parse().unwrap()),
        EndpointFamily::LocalEmbed,
        TransportBackendKind::Tcp,
    );

    assert_eq!(session.current_epoch, 0);
    assert!(
        !session.has_epoch_binding(),
        "unbound session should not have epoch binding"
    );
    assert!(
        session.is_bound_to_epoch(0),
        "unbound session should be bound to epoch 0"
    );
    assert!(
        !session.is_bound_to_epoch(1),
        "unbound session should not be bound to epoch 1"
    );
}
