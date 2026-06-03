//! Integration test: two TransportReplicatedStore instances performing
//! a full write-then-read roundtrip over transport sessions.
//!
//! One store acts as the data owner (writes data locally, then serves
//! ObjectTransfer read requests). The other store connects as a client,
//! performs a degraded read via `ReplicatedObjectReader`, and verifies
//! BLAKE3-integrity-checked data.

use std::thread;
use std::time::Duration;

use tidefs_replicated_object_store::{
    ReadError, ReplicatedObjectReader, TransportReplicatedStore, TransportReplicatedStoreConfig,
};
use tidefs_transport::{NodeInfo, ObjectTransferMessage, SessionCloseReason};

// ── two-instance write-then-read roundtrip ─────────────────────────

#[test]
fn two_store_write_then_read_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let server_path = tmp.path().join("server");
    let client_path = tmp.path().join("client");
    std::fs::create_dir(&server_path).unwrap();
    std::fs::create_dir(&client_path).unwrap();

    let mut server = TransportReplicatedStore::open(
        &server_path,
        1,
        TransportReplicatedStoreConfig {
            enable_degraded_reads: true,
            ..Default::default()
        },
    )
    .unwrap();

    server
        .put_named("roundtrip-object", b"roundtrip-payload-v1")
        .unwrap();
    server.sync_all().unwrap();
    let server_addr = server.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let sid = loop {
            match server.transport_mut().accept_incoming() {
                Ok(sid) => break sid,
                Err(e) => {
                    if e.to_string().contains("no pending connections") {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    panic!("server accept error: {e}");
                }
            }
        };
        server
            .transport_mut()
            .perform_handshake(sid)
            .expect("server handshake");
        let mut count = 0usize;
        while server.handle_read_request(sid).is_ok() {
            count += 1;
        }
        server
            .transport_mut()
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
        assert!(
            count >= 1,
            "server should have handled at least 1 request, got {count}"
        );
    });

    let mut client = TransportReplicatedStore::open(
        &client_path,
        2,
        TransportReplicatedStoreConfig {
            enable_degraded_reads: true,
            ..Default::default()
        },
    )
    .unwrap();

    client
        .transport_mut()
        .add_node(NodeInfo::new(1, vec![server_addr], 0));
    let data_sid = client
        .transport_mut()
        .connect(1)
        .expect("client connect to server");
    client
        .transport_mut()
        .perform_handshake(data_sid)
        .expect("client handshake");

    let mut reader = ReplicatedObjectReader::from_replica_sessions(vec![(1, data_sid)]);
    let object_key =
        *tidefs_local_object_store::ObjectKey::from_name(b"roundtrip-object").as_bytes();
    let result = reader.read_object(client.transport_mut(), object_key, 0, u64::MAX);
    assert!(result.is_ok(), "read failed: {:?}", result.err());
    assert_eq!(result.unwrap(), b"roundtrip-payload-v1".to_vec());

    client
        .transport_mut()
        .close_session(data_sid, SessionCloseReason::LocalShutdown)
        .ok();
    server_handle.join().ok();
    drop(tmp);
}

// ── not found: failed read, not empty-object success ────────────────

#[test]
fn read_object_not_found_is_not_successful() {
    let tmp = tempfile::tempdir().unwrap();
    let server_path = tmp.path().join("server");
    let client_path = tmp.path().join("client");
    std::fs::create_dir(&server_path).unwrap();
    std::fs::create_dir(&client_path).unwrap();

    // Server with NO data written (empty store)
    let mut server = TransportReplicatedStore::open(
        &server_path,
        1,
        TransportReplicatedStoreConfig {
            enable_degraded_reads: true,
            ..Default::default()
        },
    )
    .unwrap();

    let server_addr = server.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let sid = loop {
            match server.transport_mut().accept_incoming() {
                Ok(sid) => break sid,
                Err(e) => {
                    if e.to_string().contains("no pending connections") {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    panic!("server accept error: {e}");
                }
            }
        };
        server
            .transport_mut()
            .perform_handshake(sid)
            .expect("server handshake");
        let result = server.handle_read_request(sid);
        server
            .transport_mut()
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
        assert!(
            result.is_err(),
            "missing object must not be served as an empty payload"
        );
    });

    let mut client = TransportReplicatedStore::open(
        &client_path,
        2,
        TransportReplicatedStoreConfig {
            enable_degraded_reads: true,
            ..Default::default()
        },
    )
    .unwrap();

    client
        .transport_mut()
        .add_node(NodeInfo::new(1, vec![server_addr], 0));
    let data_sid = client.transport_mut().connect(1).expect("client connect");
    client
        .transport_mut()
        .perform_handshake(data_sid)
        .expect("client handshake");

    let mut reader = ReplicatedObjectReader::from_replica_sessions(vec![(1, data_sid)]);

    // Read a key that was never written. Missing data is not the same thing
    // as a stored zero-length object, so the reader must not return Ok([]).
    let object_key = *tidefs_local_object_store::ObjectKey::from_name(b"no-such-object").as_bytes();
    let result = reader.read_object(client.transport_mut(), object_key, 0, u64::MAX);
    assert!(
        result.is_err(),
        "not-found read must fail, got: {:?}",
        result.ok()
    );
    match result.unwrap_err() {
        ReadError::Exhausted { tried, .. } => assert_eq!(tried, 1),
        other => panic!("expected Exhausted for not-found read, got: {other}"),
    }

    client
        .transport_mut()
        .close_session(data_sid, SessionCloseReason::LocalShutdown)
        .ok();
    server_handle.join().ok();
    drop(tmp);
}

// ── BLAKE3 digest mismatch: end-to-end ─────────────────────────────

/// A custom server that sends a ReadResponse with a deliberately
/// incorrect payload digest (tampered).
fn spawn_tampered_server(
    mut server: TransportReplicatedStore,
) -> (tidefs_transport::TransportAddr, thread::JoinHandle<()>) {
    let addr = server.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let sid = loop {
            match server.transport_mut().accept_incoming() {
                Ok(sid) => break sid,
                Err(e) => {
                    if e.to_string().contains("no pending connections") {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    panic!("tampered server accept error: {e}");
                }
            }
        };
        server
            .transport_mut()
            .perform_handshake(sid)
            .expect("tampered server handshake");

        // Receive the ReadRequest
        let raw = server
            .transport_mut()
            .recv_message(sid)
            .expect("recv read request");
        let msg = ObjectTransferMessage::decode(&raw).expect("decode read request");

        if let ObjectTransferMessage::ReadRequest { transfer_id, .. } = msg {
            // Construct a ReadResponse with correct payload but WRONG digest
            let payload = b"tampered-data".to_vec();
            let wrong_digest = [0xBAu8; 32]; // deliberately wrong

            let tampered = ObjectTransferMessage::ReadResponse {
                transfer_id,
                chunk_index: 0,
                total_chunks: 1,
                total_size: payload.len() as u64,
                payload,
                payload_digest: wrong_digest,
            };
            let encoded = tampered.encode().expect("encode tampered response");
            server
                .transport_mut()
                .send_message(sid, &encoded)
                .expect("send tampered response");
        }

        server
            .transport_mut()
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });
    (addr, handle)
}

#[test]
fn blake3_digest_mismatch_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let server_path = tmp.path().join("tampered-server");
    let client_path = tmp.path().join("tampered-client");
    std::fs::create_dir(&server_path).unwrap();
    std::fs::create_dir(&client_path).unwrap();

    let server = TransportReplicatedStore::open(
        &server_path,
        1,
        TransportReplicatedStoreConfig {
            enable_degraded_reads: true,
            ..Default::default()
        },
    )
    .unwrap();

    let (addr, server_handle) = spawn_tampered_server(server);

    let mut client = TransportReplicatedStore::open(
        &client_path,
        2,
        TransportReplicatedStoreConfig {
            enable_degraded_reads: true,
            ..Default::default()
        },
    )
    .unwrap();

    client
        .transport_mut()
        .add_node(NodeInfo::new(1, vec![addr], 0));
    let data_sid = client.transport_mut().connect(1).expect("client connect");
    client
        .transport_mut()
        .perform_handshake(data_sid)
        .expect("client handshake");

    let mut reader = ReplicatedObjectReader::from_replica_sessions(vec![(1, data_sid)]);

    // Read any key — the tampered server ignores the key and sends back
    // a ReadResponse with a wrong digest
    let object_key = *tidefs_local_object_store::ObjectKey::from_name(b"any-key").as_bytes();
    let result = reader.read_object(client.transport_mut(), object_key, 0, 1024);

    // With one replica and a tampered response, we expect:
    // 1. try_read_from → dispatch_read_request (ok) → recv_read_response
    //    → verify_payload fails with DigestMismatch → ReadError::DigestMismatch
    // 2. No more replicas → Exhausted with last_error = "...digest mismatch..."
    assert!(
        result.is_err(),
        "tampered digest should fail, got: {:?}",
        result.ok()
    );
    match result.unwrap_err() {
        ReadError::Exhausted { tried, last_error } => {
            assert_eq!(tried, 1, "should have tried the only replica");
            assert!(
                last_error.contains("digest mismatch") || last_error.contains("DigestMismatch"),
                "last_error should mention digest mismatch, got: {last_error}"
            );
        }
        other => panic!("expected Exhausted, got: {other}"),
    }

    client
        .transport_mut()
        .close_session(data_sid, SessionCloseReason::LocalShutdown)
        .ok();
    server_handle.join().ok();
    drop(tmp);
}

// ── timeout/exhaustion: all replicas unreachable ───────────────────

#[test]
fn all_replicas_unreachable_returns_exhausted() {
    // Fake session IDs — no actual servers to respond.
    let fake_sid1 = tidefs_transport::SessionId(999_999);
    let fake_sid2 = tidefs_transport::SessionId(999_998);

    let mut reader =
        ReplicatedObjectReader::from_replica_sessions(vec![(1, fake_sid1), (2, fake_sid2)]);

    let object_key = *tidefs_local_object_store::ObjectKey::from_name(b"unreachable").as_bytes();

    // A standalone transport with no connections — send_message on
    // a fake session ID will fail immediately.
    let mut transport = tidefs_transport::Transport::new(99);
    let result = reader.read_object(&mut transport, object_key, 0, 1024);

    assert!(result.is_err(), "unreachable replicas should fail");
    match result.unwrap_err() {
        ReadError::Exhausted { tried, .. } => {
            // 2 replicas, so max_attempts is min(3, 2) = 2
            assert_eq!(tried, 2, "should have tried both replicas");
        }
        other => panic!("expected Exhausted, got: {other}"),
    }
}
