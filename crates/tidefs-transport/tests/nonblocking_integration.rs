// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Non-blocking I/O integration tests for the Transport layer.
//!
//! These tests verify that the Transport correctly handles non-blocking I/O
//! via `set_nonblocking(true)`, propagating `TransportError::WouldBlock`
//! through `recv_message` and `recv_envelope`, and that multi-node tick-loop
//! exchanges function correctly without blocking or spurious epoch bumps.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;
use tidefs_transport::{NodeInfo, SessionCloseReason, SessionId, Transport, TransportError};

/// Poll `accept_incoming` with short sleeps until a connection arrives or we
/// give up. The TcpTransport listener is non-blocking, so we must poll.
fn blocking_accept(transport: &mut Transport) -> SessionId {
    for _ in 0..200 {
        match transport.accept_incoming() {
            Ok(sid) => return sid,
            Err(TransportError::Generic(ref e)) if e.contains("no pending connections") => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("accept error: {e}"),
        }
    }
    panic!("timeout waiting for incoming connection after 2 seconds");
}

/// Retry `recv_message` with microsecond-level sleep on `WouldBlock`.
/// Panics if the error is anything other than `WouldBlock` or if we
/// exhaust all attempts.
fn nb_recv(transport: &mut Transport, sid: SessionId, timeout_ms: u64) -> Vec<u8> {
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        match transport.recv_message(sid) {
            Ok(data) => return data,
            Err(TransportError::WouldBlock(_)) => {
                if std::time::Instant::now() > deadline {
                    panic!("nb_recv timed out after {timeout_ms}ms");
                }
                thread::sleep(Duration::from_micros(200));
            }
            Err(e) => panic!("unexpected recv error: {e:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Simplest test: one pair, handshake, enable NB, single ping-pong
// ---------------------------------------------------------------------------

#[test]
fn one_pair_nonblocking_ping_pong() {
    let mut server = Transport::new(1);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    server
        .bind(tidefs_transport::TransportAddr::Tcp(addr))
        .expect("bind");
    let bound = server.bind_addr.clone().expect("bind_addr");

    server.add_node(NodeInfo::new(2, vec![bound.clone()], 0));
    let mut client = Transport::new(2);
    client.add_node(NodeInfo::new(1, vec![bound], 0));

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);
        server.perform_handshake(sid).expect("hs");
        server.set_nonblocking(true).expect("nb");

        let msg = nb_recv(&mut server, sid, 5000);
        server.send_message(sid, &msg).expect("echo");
        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(30));

    let sid = client.connect(1).expect("connect");
    client.perform_handshake(sid).expect("hs");
    client.set_nonblocking(true).expect("nb");

    client.send_message(sid, b"hello").expect("send");
    let echo = nb_recv(&mut client, sid, 5000);
    assert_eq!(echo, b"hello");

    client
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .ok();
    server_handle.join().expect("server");
}

// ---------------------------------------------------------------------------
// WouldBlock on recv_message when no data available after handshake
// ---------------------------------------------------------------------------

#[test]
fn recv_message_returns_would_block_when_no_data() {
    let mut server = Transport::new(1);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    server
        .bind(tidefs_transport::TransportAddr::Tcp(addr))
        .expect("bind");
    let bound = server.bind_addr.clone().expect("bind_addr");

    server.add_node(NodeInfo::new(2, vec![bound.clone()], 0));
    let mut client = Transport::new(2);
    client.add_node(NodeInfo::new(1, vec![bound], 0));

    let barrier = Arc::new(Barrier::new(2));
    let barrier_s = Arc::clone(&barrier);

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);
        server.perform_handshake(sid).expect("hs");
        server.set_nonblocking(true).expect("nb");
        barrier_s.wait();
        // Idle: hold the connection open without sending data
        thread::sleep(Duration::from_millis(600));
        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(30));

    let sid = client.connect(1).expect("connect");
    client.perform_handshake(sid).expect("hs");
    client.set_nonblocking(true).expect("nb");

    barrier.wait(); // server is now idle

    // recv_message should return WouldBlock immediately
    let result = client.recv_message(sid);
    assert!(
        matches!(result, Err(TransportError::WouldBlock(_))),
        "Expected WouldBlock, got: {result:?}"
    );

    client
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .ok();
    server_handle.join().expect("server");
}

// ---------------------------------------------------------------------------
// recv_envelope WouldBlock propagation
// ---------------------------------------------------------------------------

#[test]
fn recv_envelope_returns_would_block_when_no_data() {
    let mut server = Transport::new(1);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    server
        .bind(tidefs_transport::TransportAddr::Tcp(addr))
        .expect("bind");
    let bound = server.bind_addr.clone().expect("bind_addr");

    server.add_node(NodeInfo::new(2, vec![bound.clone()], 0));
    let mut client = Transport::new(2);
    client.add_node(NodeInfo::new(1, vec![bound], 0));

    let barrier = Arc::new(Barrier::new(2));
    let barrier_s = Arc::clone(&barrier);

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);
        server.perform_handshake(sid).expect("hs");
        server.set_nonblocking(true).expect("nb");
        barrier_s.wait();
        thread::sleep(Duration::from_millis(600));
        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(30));

    let sid = client.connect(1).expect("connect");
    client.perform_handshake(sid).expect("hs");
    client.set_nonblocking(true).expect("nb");

    barrier.wait();

    let result = client.recv_envelope(sid);
    assert!(
        matches!(result, Err(TransportError::WouldBlock(_))),
        "Expected WouldBlock from recv_envelope, got: {result:?}"
    );

    client
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .ok();
    server_handle.join().expect("server");
}

// ---------------------------------------------------------------------------
// Non-blocking can be toggled on/off
// ---------------------------------------------------------------------------

#[test]
fn nonblocking_can_be_toggled() {
    let mut server = Transport::new(1);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    server
        .bind(tidefs_transport::TransportAddr::Tcp(addr))
        .expect("bind");
    let bound = server.bind_addr.clone().expect("bind_addr");

    server.add_node(NodeInfo::new(2, vec![bound.clone()], 0));
    let mut client = Transport::new(2);
    client.add_node(NodeInfo::new(1, vec![bound], 0));

    let barrier = Arc::new(Barrier::new(2));
    let barrier_s = Arc::clone(&barrier);

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);
        server.perform_handshake(sid).expect("hs");
        server.set_nonblocking(true).expect("nb");
        barrier_s.wait();
        thread::sleep(Duration::from_millis(600));
        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(30));

    let sid = client.connect(1).expect("connect");
    client.perform_handshake(sid).expect("hs");

    // 1. Enable nonblocking → WouldBlock expected
    client.set_nonblocking(true).expect("enable");
    barrier.wait();

    let r1 = client.recv_message(sid);
    assert!(matches!(r1, Err(TransportError::WouldBlock(_))));

    // 2. Disable nonblocking → read will block until server closes conn
    client.set_nonblocking(false).expect("disable");
    let r2 = client.recv_message(sid);
    assert!(
        !matches!(r2, Err(TransportError::WouldBlock(_))),
        "Should not get WouldBlock after disabling nonblocking"
    );

    client
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .ok();
    server_handle.join().expect("server");
}

// ---------------------------------------------------------------------------
// Two-node bidirectional echo tick loop with non-blocking I/O
// ---------------------------------------------------------------------------

#[test]
fn two_node_nonblocking_tick_loop() {
    let mut server = Transport::new(1).with_epoch(1);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    server
        .bind(tidefs_transport::TransportAddr::Tcp(addr))
        .expect("bind");
    let bound = server.bind_addr.clone().expect("bind_addr");

    server.add_node(NodeInfo::new(2, vec![bound.clone()], 0));
    let mut client = Transport::new(2).with_epoch(1);
    client.add_node(NodeInfo::new(1, vec![bound], 0));

    let barrier = Arc::new(Barrier::new(2));
    let barrier_s = Arc::clone(&barrier);

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);
        server.perform_handshake(sid).expect("hs");
        server.set_nonblocking(true).expect("nb");

        barrier_s.wait();

        for tick in 0..10 {
            let data = nb_recv(&mut server, sid, 5000);
            let expected = format!("ping-{tick}");
            assert_eq!(
                data,
                expected.as_bytes(),
                "tick {tick}: bad ping from client"
            );
            server.send_message(sid, &data).expect("echo");
        }

        assert_eq!(server.epoch, 1);
        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(30));

    let sid = client.connect(1).expect("connect");
    client.perform_handshake(sid).expect("hs");
    client.set_nonblocking(true).expect("nb");

    barrier.wait();

    for tick in 0..10 {
        let ping = format!("ping-{tick}");
        client.send_message(sid, ping.as_bytes()).expect("send");
        let echo = nb_recv(&mut client, sid, 2000);
        assert_eq!(echo, ping.as_bytes(), "tick {tick}: bad echo");
    }

    assert_eq!(client.epoch, 1);
    client
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .ok();
    server_handle.join().expect("server");
}

// ---------------------------------------------------------------------------
// 3-node split-phase handshake + 20-tick non-blocking exchange
// ---------------------------------------------------------------------------

#[test]
fn three_node_nonblocking_tick_loop() {
    // Create 3 nodes
    let mut node_a = Transport::new(1).with_epoch(1);
    let mut node_b = Transport::new(2).with_epoch(1);
    let mut node_c = Transport::new(3).with_epoch(1);

    // Node A listens; B and C connect to A
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    node_a
        .bind(tidefs_transport::TransportAddr::Tcp(addr))
        .expect("bind");
    let bound_a = node_a.bind_addr.clone().expect("bind_addr");

    node_a.add_node(NodeInfo::new(2, vec![bound_a.clone()], 0));
    node_a.add_node(NodeInfo::new(3, vec![bound_a.clone()], 0));
    node_b.add_node(NodeInfo::new(1, vec![bound_a.clone()], 0));
    node_c.add_node(NodeInfo::new(1, vec![bound_a], 0));

    // Phase 1: split handshake
    let phase1_barrier = Arc::new(Barrier::new(3));
    let p1_s = Arc::clone(&phase1_barrier);

    let server_handle = thread::spawn(move || {
        // Handshake with B
        let sid_b = blocking_accept(&mut node_a);
        node_a.perform_handshake(sid_b).expect("hs_b");
        // Handshake with C
        let sid_c = blocking_accept(&mut node_a);
        node_a.perform_handshake(sid_c).expect("hs_c");

        node_a.set_nonblocking(true).expect("nb_A");
        p1_s.wait(); // sync: all handshakes done

        // Phase 2: 20-tick exchange
        for tick in 0..20 {
            let b_data = nb_recv(&mut node_a, sid_b, 2000);
            let expected_b = format!("b-ping-{tick}");
            assert_eq!(b_data, expected_b.as_bytes(), "tick {tick}: A<->B");

            let c_data = nb_recv(&mut node_a, sid_c, 2000);
            let expected_c = format!("c-ping-{tick}");
            assert_eq!(c_data, expected_c.as_bytes(), "tick {tick}: A<->C");

            node_a.send_message(sid_b, &b_data).expect("echo_b");
            node_a.send_message(sid_c, &c_data).expect("echo_c");
        }

        assert_eq!(node_a.epoch, 1);
        node_a
            .close_session(sid_b, SessionCloseReason::LocalShutdown)
            .ok();
        node_a
            .close_session(sid_c, SessionCloseReason::LocalShutdown)
            .ok();
    });

    let p1_b = Arc::clone(&phase1_barrier);
    let b_handle = thread::spawn(move || {
        thread::sleep(Duration::from_millis(30));
        let sid = node_b.connect(1).expect("connect_b");
        node_b.perform_handshake(sid).expect("hs_b");
        node_b.set_nonblocking(true).expect("nb_B");
        p1_b.wait();

        for tick in 0..20 {
            let ping = format!("b-ping-{tick}");
            node_b.send_message(sid, ping.as_bytes()).expect("send");
            let echo = nb_recv(&mut node_b, sid, 2000);
            assert_eq!(echo, ping.as_bytes(), "tick {tick}: B echo");
        }

        assert_eq!(node_b.epoch, 1);
        node_b
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    let p1_c = Arc::clone(&phase1_barrier);
    let c_handle = thread::spawn(move || {
        thread::sleep(Duration::from_millis(60)); // longer delay so B connects first
        let sid = node_c.connect(1).expect("connect_c");
        node_c.perform_handshake(sid).expect("hs_c");
        node_c.set_nonblocking(true).expect("nb_C");
        p1_c.wait();

        for tick in 0..20 {
            let ping = format!("c-ping-{tick}");
            node_c.send_message(sid, ping.as_bytes()).expect("send");
            let echo = nb_recv(&mut node_c, sid, 2000);
            assert_eq!(echo, ping.as_bytes(), "tick {tick}: C echo");
        }

        assert_eq!(node_c.epoch, 1);
        node_c
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    server_handle.join().expect("server");
    b_handle.join().expect("B");
    c_handle.join().expect("C");
}
