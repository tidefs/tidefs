// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;
use tidefs_transport::{NodeInfo, SessionCloseReason, Transport, TransportError};

fn blocking_accept(transport: &mut Transport) -> tidefs_transport::SessionId {
    for _ in 0..200 {
        match transport.accept_incoming() {
            Ok(sid) => return sid,
            Err(TransportError::Generic(ref e)) if e.contains("no pending connections") => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("accept error: {e}"),
        }
    }
    panic!("timeout");
}

/// Transport-on-Transport: blocking mode — should work
#[test]
fn transport_on_transport_blocking_works() {
    let mut server = Transport::new(1);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    server
        .bind(tidefs_transport::TransportAddr::Tcp(addr))
        .unwrap();
    let bound = server.bind_addr.clone().unwrap();
    server.add_node(NodeInfo::new(2, vec![bound.clone()], 0));

    let mut client = Transport::new(2);
    client.add_node(NodeInfo::new(1, vec![bound], 0));

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);
        server.perform_handshake(sid).unwrap();
        // Blocking recv (no set_nonblocking)
        let data = server.recv_message(sid).unwrap();
        server.send_message(sid, &data).unwrap();
        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(30));

    let sid = client.connect(1).unwrap();
    client.perform_handshake(sid).unwrap();
    client.send_message(sid, b"hello").unwrap();
    let echo = client.recv_message(sid).unwrap();
    assert_eq!(echo, b"hello");
    client
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .ok();
    server_handle.join().unwrap();
}

/// Transport-on-Transport with nonblocking after handshake
#[test]
fn transport_on_transport_nonblocking_works() {
    let mut server = Transport::new(1);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    server
        .bind(tidefs_transport::TransportAddr::Tcp(addr))
        .unwrap();
    let bound = server.bind_addr.clone().unwrap();
    server.add_node(NodeInfo::new(2, vec![bound.clone()], 0));

    let mut client = Transport::new(2);
    client.add_node(NodeInfo::new(1, vec![bound], 0));

    let barrier = Arc::new(Barrier::new(2));
    let barrier_s = Arc::clone(&barrier);

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);
        server.perform_handshake(sid).unwrap();
        server.set_nonblocking(true).unwrap();
        barrier_s.wait();

        // Polled recv with WouldBlock handling
        for _ in 0..500 {
            match server.recv_message(sid) {
                Ok(data) => {
                    server.send_message(sid, &data).unwrap();
                    break;
                }
                Err(TransportError::WouldBlock(_)) => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("unexpected: {e:?}"),
            }
        }
        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(30));

    let sid = client.connect(1).unwrap();
    client.perform_handshake(sid).unwrap();
    client.set_nonblocking(true).unwrap();
    barrier.wait();

    client.send_message(sid, b"hello").unwrap();

    // Polled recv
    let mut echo = None;
    for _ in 0..500 {
        match client.recv_message(sid) {
            Ok(data) => {
                echo = Some(data);
                break;
            }
            Err(TransportError::WouldBlock(_)) => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("unexpected: {e:?}"),
        }
    }
    assert_eq!(echo.unwrap(), b"hello");
    client
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .ok();
    server_handle.join().unwrap();
}
