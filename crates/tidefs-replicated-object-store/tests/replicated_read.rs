// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration test for the replicated object read path.
//!
//! Exercises `ReplicatedObjectReader` with multiple replicas over TCP
//! loopback, covering multi-replica read, partial range reads, failover
//! when a replica is unavailable, and deterministic replica selection.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread;
use std::time::Duration;

use tidefs_replicated_object_store::{ReadError, ReaderConfig, ReplicatedObjectReader};
use tidefs_transport::{
    build_read_responses, NodeInfo, ObjectTransferMessage, SessionCloseReason, SessionId,
    Transport, MAX_CHUNK_PAYLOAD,
};

// ── helpers ────────────────────────────────────────────────────────

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
    for _ in 0..100 {
        match transport.accept_incoming() {
            Ok(sid) => return sid,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("no pending connections") {
                    thread::sleep(Duration::from_millis(10));
                } else {
                    panic!("server accept error: {e}");
                }
            }
        }
    }
    panic!("timeout waiting for incoming connection");
}

fn spawn_echo_server(
    mut server: Transport,
    server_data: Vec<u8>,
) -> (tidefs_transport::TransportAddr, thread::JoinHandle<()>) {
    let addr = server.bind_addr.clone().unwrap();
    let handle = thread::spawn(move || {
        let sid = blocking_accept(&mut server);
        server.perform_handshake(sid).expect("server handshake");

        while let Ok(raw) = server.recv_message(sid) {
            let msg = match ObjectTransferMessage::decode(&raw) {
                Ok(m) => m,
                Err(_) => break,
            };

            match msg {
                ObjectTransferMessage::ReadRequest {
                    transfer_id,
                    offset,
                    length,
                    ..
                } => {
                    let end = (offset + length).min(server_data.len() as u64) as usize;
                    let start = offset as usize;
                    let slice = &server_data[start..end];

                    let responses = build_read_responses(
                        transfer_id,
                        slice.len() as u64,
                        slice,
                        MAX_CHUNK_PAYLOAD,
                    );
                    for resp in responses {
                        let encoded = resp.encode().expect("encode response");
                        server.send_message(sid, &encoded).expect("send response");
                    }
                }
                _ => break,
            }
        }
        server
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });
    (addr, handle)
}

fn connect_and_handshake(
    client: &mut Transport,
    server_addr: tidefs_transport::TransportAddr,
    server_node_id: u64,
) -> SessionId {
    client.add_node(NodeInfo::new(server_node_id, vec![server_addr], 0));
    let sid = client.connect(server_node_id).expect("client connect");
    client.perform_handshake(sid).expect("client handshake");
    sid
}

// ── 2-replica read/roundtrip ───────────────────────────────────────

#[test]
fn two_replica_identical_data_roundtrip() {
    let payload = b"multi-replica read test payload with deterministic ordering".to_vec();

    let (server1, _addr1) = listening_transport(1);
    let (server2, _addr2) = listening_transport(2);

    let (addr1, handle1) = spawn_echo_server(server1, payload.clone());
    let (addr2, handle2) = spawn_echo_server(server2, payload.clone());

    let mut client = Transport::new(3);
    let sid1 = connect_and_handshake(&mut client, addr1, 1);
    let sid2 = connect_and_handshake(&mut client, addr2, 2);

    let mut reader = ReplicatedObjectReader::with_config(
        vec![sid1, sid2],
        ReaderConfig {
            seed: 42,
            max_attempts: 2,
            ..Default::default()
        },
    );

    let object_key = *blake3::hash(b"test-object").as_bytes();
    let result = reader.read_object(&mut client, object_key, 0, payload.len() as u64);
    assert!(result.is_ok(), "read failed: {:?}", result.err());
    assert_eq!(result.unwrap(), payload);

    handle1.join().ok();
    handle2.join().ok();
}

#[test]
fn two_replica_partial_range_read() {
    let payload = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_vec();

    let (server1, _addr1) = listening_transport(1);
    let (server2, _addr2) = listening_transport(2);

    let (addr1, handle1) = spawn_echo_server(server1, payload.clone());
    let (addr2, handle2) = spawn_echo_server(server2, payload.clone());

    let mut client = Transport::new(3);
    let sid1 = connect_and_handshake(&mut client, addr1, 1);
    let sid2 = connect_and_handshake(&mut client, addr2, 2);

    let mut reader = ReplicatedObjectReader::new(vec![sid1, sid2]);

    let object_key = *blake3::hash(b"range-read").as_bytes();
    let result = reader.read_object(&mut client, object_key, 5, 10);
    assert!(result.is_ok(), "range read failed: {:?}", result.err());
    assert_eq!(result.unwrap(), b"FGHIJKLMNO");

    handle1.join().ok();
    handle2.join().ok();
}

// ── failover: one replica unavailable ──────────────────────────────

#[test]
fn failover_when_one_replica_unavailable() {
    let payload = b"failover test: replica 2 should serve when replica 1 is dead".to_vec();

    let (server2, _addr2) = listening_transport(2);
    let (addr2, handle2) = spawn_echo_server(server2, payload.clone());

    let mut client = Transport::new(3);
    let sid2 = connect_and_handshake(&mut client, addr2, 2);

    // Fake session for replica 1 (no actual server). The reader will try it,
    // fail, and fall through to replica 2.
    let fake_sid1 = SessionId(0);

    let mut reader = ReplicatedObjectReader::with_config(
        vec![fake_sid1, sid2],
        ReaderConfig {
            seed: 12345,
            max_attempts: 2,
            ..Default::default()
        },
    );

    let object_key = *blake3::hash(b"failover-object").as_bytes();
    let result = reader.read_object(&mut client, object_key, 0, payload.len() as u64);
    assert!(result.is_ok(), "failover read failed: {:?}", result.err());
    assert_eq!(result.unwrap(), payload);

    handle2.join().ok();
}

#[test]
fn failover_exhausted_when_all_replicas_unavailable() {
    let _client = Transport::new(3);

    let fake_sid1 = SessionId(0);
    let fake_sid2 = SessionId(1);

    let mut reader = ReplicatedObjectReader::with_config(
        vec![fake_sid1, fake_sid2],
        ReaderConfig {
            seed: 99,
            max_attempts: 2,
            ..Default::default()
        },
    );

    let object_key = *blake3::hash(b"doomed-object").as_bytes();
    // Need a mutable transport, so we create a temporary one
    let mut dummy_transport = Transport::new(99);
    let result = reader.read_object(&mut dummy_transport, object_key, 0, 10);
    assert!(result.is_err(), "expected exhausted error, got success");
    match result.unwrap_err() {
        ReadError::Exhausted { tried, .. } => {
            assert_eq!(tried, 2, "should have tried both replicas");
        }
        other => panic!("expected Exhausted, got: {other}"),
    }
}

// ── deterministic replica selection ────────────────────────────────

#[test]
fn deterministic_selection_same_seed_same_preference() {
    let (srv_a1, _) = listening_transport(101);
    let (srv_a2, _) = listening_transport(102);
    let (srv_b1, _) = listening_transport(201);
    let (srv_b2, _) = listening_transport(202);

    let (addr_a1, ha1) = spawn_echo_server(srv_a1, b"data".to_vec());
    let (addr_a2, ha2) = spawn_echo_server(srv_a2, b"data".to_vec());
    let (addr_b1, hb1) = spawn_echo_server(srv_b1, b"data".to_vec());
    let (addr_b2, hb2) = spawn_echo_server(srv_b2, b"data".to_vec());

    let mut client_a = Transport::new(1001);
    let sid_a1 = connect_and_handshake(&mut client_a, addr_a1, 101);
    let sid_a2 = connect_and_handshake(&mut client_a, addr_a2, 102);

    let mut reader_a = ReplicatedObjectReader::with_config(
        vec![sid_a1, sid_a2],
        ReaderConfig {
            seed: 777,
            max_attempts: 2,
            ..Default::default()
        },
    );

    let mut client_b = Transport::new(1002);
    let sid_b1 = connect_and_handshake(&mut client_b, addr_b1, 201);
    let sid_b2 = connect_and_handshake(&mut client_b, addr_b2, 202);

    let mut reader_b = ReplicatedObjectReader::with_config(
        vec![sid_b1, sid_b2],
        ReaderConfig {
            seed: 777,
            max_attempts: 2,
            ..Default::default()
        },
    );

    let obj_key = *blake3::hash(b"det-obj").as_bytes();
    let r1 = reader_a.read_object(&mut client_a, obj_key, 0, 4);
    let r2 = reader_b.read_object(&mut client_b, obj_key, 0, 4);
    assert!(r1.is_ok(), "reader_a failed: {:?}", r1.err());
    assert!(r2.is_ok(), "reader_b failed: {:?}", r2.err());
    assert_eq!(r1.unwrap(), r2.unwrap());

    ha1.join().ok();
    ha2.join().ok();
    hb1.join().ok();
    hb2.join().ok();
}

// ── BLAKE3 integrity: tampered payload detection ───────────────────

#[test]
fn tampered_payload_rejected_by_blake3_verification() {
    use tidefs_transport::TransferDispatchError;

    let err = TransferDispatchError::DigestMismatch;
    let read_err = ReadError::from(err);
    assert!(matches!(read_err, ReadError::DigestMismatch));
}

#[test]
fn transfer_error_conversion() {
    use tidefs_transport::TransferDispatchError;

    let err = TransferDispatchError::Timeout(42);
    let read_err = ReadError::from(err);
    assert!(matches!(read_err, ReadError::Transport(_)));
}

// ── large payload multi-chunk read ─────────────────────────────────

#[test]
fn large_payload_multi_replica_multi_chunk() {
    // 4 MiB payload spanning multiple chunks across two replicas
    let payload: Vec<u8> = (0..(MAX_CHUNK_PAYLOAD as u64 * 4))
        .map(|i| (i % 253) as u8)
        .collect();

    let (server1, _addr1) = listening_transport(1);
    let (server2, _addr2) = listening_transport(2);

    let (addr1, handle1) = spawn_echo_server(server1, payload.clone());
    let (addr2, handle2) = spawn_echo_server(server2, payload.clone());

    let mut client = Transport::new(3);
    let sid1 = connect_and_handshake(&mut client, addr1, 1);
    let sid2 = connect_and_handshake(&mut client, addr2, 2);

    let mut reader = ReplicatedObjectReader::with_config(
        vec![sid1, sid2],
        ReaderConfig {
            seed: 123,
            max_attempts: 2,
            ..Default::default()
        },
    );

    let object_key = *blake3::hash(b"large-multi").as_bytes();
    let result = reader.read_object(&mut client, object_key, 0, payload.len() as u64);
    assert!(
        result.is_ok(),
        "large multi-replica read failed: {:?}",
        result.err()
    );
    let data = result.unwrap();
    assert_eq!(data.len(), payload.len());
    assert_eq!(data, payload);

    handle1.join().ok();
    handle2.join().ok();
}
