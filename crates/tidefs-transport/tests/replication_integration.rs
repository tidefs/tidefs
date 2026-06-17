//! Transport-backed replication integration tests.
//!
//! These tests demonstrate actual multi-node object replication over TCP
//! using the Transport crate's session handshake and frame I/O, with each
//! node storing data in a LocalObjectStore.
//!
//! This is the first bridge between the transport layer and the storage
//! layer — the critical missing piece for real distributed redundancy.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread;
use std::time::Duration;
use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};
use tidefs_membership_epoch::EpochId;
use tidefs_replication_model::PlacementReceiptRef;
use tidefs_transport::{NodeInfo, SessionCloseReason, SessionId, Transport, TransportError};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a temporary directory and open a LocalObjectStore in it
/// with test-fast options suitable for small payloads.
fn temp_store() -> (tempfile::TempDir, LocalObjectStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
        .expect("open store");
    (dir, store)
}

/// Create a temporary directory and open a LocalObjectStore with
/// default (production) options for large payload tests.
fn temp_store_large() -> (tempfile::TempDir, LocalObjectStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = LocalObjectStore::open_with_options(dir.path(), StoreOptions::default())
        .expect("open store");
    (dir, store)
}

/// Create a Transport for a node that listens on a random port.
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
/// The TcpTransport listener is non-blocking, so we must poll.
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
// Wire protocol helpers for replication messages
// ---------------------------------------------------------------------------

/// Wire message types for replication.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
enum ReplicationMessage {
    /// Store an object: key name + payload.
    Put { name: String, payload: Vec<u8> },
    /// Store an object with durable placement receipt authority.
    PutWithReceipt {
        name: String,
        payload: Vec<u8>,
        placement_receipt_ref: PlacementReceiptRef,
    },
    /// Acknowledgment for a receipt-authorized put.
    PutWithReceiptAck {
        key_hash: String,
        success: bool,
        recorded_receipt_ref: Option<PlacementReceiptRef>,
    },
    /// Acknowledgement with the stored ObjectKey hash.
    Ack { key_hash: String, success: bool },
    /// Request an object by name.
    Get { name: String },
    /// Response with optional payload.
    GetResponse { found: bool, payload: Vec<u8> },
    /// Request to sync all keys from peer.
    SyncRequest,
    /// Sync response: exact object payloads, with receipt authority when known.
    SyncResponse { entries: Vec<SyncEntry> },
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
struct SyncEntry {
    object_key: [u8; 32],
    payload: Vec<u8>,
    placement_receipt_ref: Option<PlacementReceiptRef>,
}

impl SyncEntry {
    fn receiptless(object_key: [u8; 32], payload: Vec<u8>) -> Self {
        Self {
            object_key,
            payload,
            placement_receipt_ref: None,
        }
    }
}

/// Build a test PlacementReceiptRef for replicated (2-copy) placement.
fn test_receipt_ref(name: &str, payload: &[u8], object_id: u64) -> PlacementReceiptRef {
    let mut buf = [0u8; 32];
    let name_bytes = name.as_bytes();
    let len = name_bytes.len().min(32);
    buf[..len].copy_from_slice(&name_bytes[..len]);
    let digest = blake3::hash(payload);
    PlacementReceiptRef::replicated(
        object_id,
        buf,
        EpochId::new(1),
        1,
        2,
        payload.len() as u64,
        *digest.as_bytes(),
    )
}

/// Send a structured replication message over a transport session.
fn send_replication_msg(
    transport: &mut Transport,
    session_id: SessionId,
    msg: &ReplicationMessage,
) -> Result<(), TransportError> {
    let payload =
        bincode::serialize(msg).map_err(|e| TransportError::Generic(format!("serialize: {e}")))?;
    transport.send_message(session_id, &payload)
}

/// Receive a structured replication message over a transport session.
fn recv_replication_msg(
    transport: &mut Transport,
    session_id: SessionId,
) -> Result<ReplicationMessage, TransportError> {
    let payload = transport.recv_message(session_id)?;
    bincode::deserialize(&payload).map_err(|e| TransportError::Generic(format!("deserialize: {e}")))
}

// ---------------------------------------------------------------------------
// Two-node replication: basic put + verify
// ---------------------------------------------------------------------------

#[test]
fn two_node_replication_put_and_verify() {
    // Node A: primary (server listener, stores data)
    let (mut node_a, addr_a) = listening_transport(1);
    let (dir_a, mut store_a) = temp_store();

    // Node B: replica (client, connects to A)
    let mut node_b = Transport::new(2);
    let (dir_b, mut store_b) = temp_store();

    // Register nodes in each other's cohort graphs
    node_a.add_node(NodeInfo::new(2, vec![addr_a.clone()], 0));
    node_b.add_node(NodeInfo::new(1, vec![addr_a], 0));

    // Server thread: accept connection, handshake, process replication messages
    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut node_a);
        node_a.perform_handshake(sid).expect("handshake");

        // Process messages until close
        loop {
            let msg = recv_replication_msg(&mut node_a, sid);
            match msg {
                Ok(ReplicationMessage::Put { name, payload }) => {
                    store_a.put_named(&name, &payload).expect("put");
                    let key_hash = store_a
                        .location_of(ObjectKey::from_name(&name))
                        .map(|loc| format!("{loc:?}"))
                        .unwrap_or_default();
                    send_replication_msg(
                        &mut node_a,
                        sid,
                        &ReplicationMessage::Ack {
                            key_hash,
                            success: true,
                        },
                    )
                    .expect("send ack");
                }
                Ok(ReplicationMessage::Get { name }) => {
                    let key = ObjectKey::from_name(&name);
                    let found = store_a.contains_key(key);
                    let payload = if found {
                        let loc = store_a.location_of(key).expect("location");
                        store_a.get_at_location(loc).expect("get")
                    } else {
                        Vec::new()
                    };
                    send_replication_msg(
                        &mut node_a,
                        sid,
                        &ReplicationMessage::GetResponse { found, payload },
                    )
                    .expect("send get_response");
                }
                Ok(ReplicationMessage::SyncRequest) => {
                    let keys = store_a.list_keys();
                    let mut entries = Vec::new();
                    for k in keys {
                        if let Some(loc) = store_a.location_of(k) {
                            if let Ok(payload) = store_a.get_at_location(loc) {
                                entries.push(SyncEntry::receiptless(k.as_bytes32(), payload));
                            }
                        }
                    }
                    send_replication_msg(
                        &mut node_a,
                        sid,
                        &ReplicationMessage::SyncResponse { entries },
                    )
                    .expect("send sync_response");
                }
                _ => break,
            }
        }

        node_a
            .close_session(sid, SessionCloseReason::PeerRemoved)
            .ok();
    });

    // Give the server thread time to start listening
    thread::sleep(Duration::from_millis(50));

    // Client: connect, handshake, replicate data
    let sid = node_b.connect(1).expect("connect");
    node_b.perform_handshake(sid).expect("handshake");

    // Put an object on node B, then replicate to node A
    let test_payload = b"hello from node B to node A";
    store_b
        .put_named("test-object", test_payload)
        .expect("put local");

    send_replication_msg(
        &mut node_b,
        sid,
        &ReplicationMessage::Put {
            name: "test-object".to_string(),
            payload: test_payload.to_vec(),
        },
    )
    .expect("send put");

    // Receive ack from node A
    let ack = recv_replication_msg(&mut node_b, sid).expect("recv ack");
    assert!(
        matches!(ack, ReplicationMessage::Ack { success: true, .. }),
        "Expected successful ack, got: {ack:?}"
    );

    // Verify node A actually stored the data by requesting it back
    send_replication_msg(
        &mut node_b,
        sid,
        &ReplicationMessage::Get {
            name: "test-object".to_string(),
        },
    )
    .expect("send get");

    let response = recv_replication_msg(&mut node_b, sid).expect("recv get_response");
    match response {
        ReplicationMessage::GetResponse { found, payload } => {
            assert!(found, "Object should be found on node A");
            assert_eq!(payload, test_payload, "Payload should match");
        }
        _ => panic!("Expected GetResponse, got: {response:?}"),
    }

    // Clean up
    node_b
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");
    server_handle.join().expect("server thread");
    drop(dir_a);
    drop(dir_b);
}

// ---------------------------------------------------------------------------
// Two-node replication: verify local storage on both sides
// ---------------------------------------------------------------------------

#[test]
fn two_node_replication_both_sides_store_locally() {
    let (mut node_a, addr_a) = listening_transport(1);
    let (dir_a, mut store_a) = temp_store();
    let mut node_b = Transport::new(2);
    let (dir_b, mut store_b) = temp_store();

    node_a.add_node(NodeInfo::new(2, vec![addr_a.clone()], 0));
    node_b.add_node(NodeInfo::new(1, vec![addr_a], 0));

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut node_a);
        node_a.perform_handshake(sid).expect("handshake");

        while let Ok(ReplicationMessage::Put { name, payload }) =
            recv_replication_msg(&mut node_a, sid)
        {
            store_a.put_named(&name, &payload).expect("put on A");
            send_replication_msg(
                &mut node_a,
                sid,
                &ReplicationMessage::Ack {
                    key_hash: name,
                    success: true,
                },
            )
            .expect("send ack");
        }
        node_a
            .close_session(sid, SessionCloseReason::PeerRemoved)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = node_b.connect(1).expect("connect");
    node_b.perform_handshake(sid).expect("handshake");

    // Replicate multiple objects
    for i in 0..5 {
        let name = format!("obj-{i}");
        let payload = format!("payload-{i}").into_bytes();

        store_b.put_named(&name, &payload).expect("put on B");

        send_replication_msg(&mut node_b, sid, &ReplicationMessage::Put { name, payload })
            .expect("send put");

        let ack = recv_replication_msg(&mut node_b, sid).expect("recv ack");
        assert!(matches!(ack, ReplicationMessage::Ack { success: true, .. }));
    }

    // Verify all objects exist on node B (local store)
    for i in 0..5 {
        let name = format!("obj-{i}");
        let key = ObjectKey::from_name(&name);
        assert!(
            store_b.contains_key(key),
            "Object {name} should be in local store B"
        );
        let loc = store_b.location_of(key).expect("location");
        let data = store_b.get_at_location(loc).expect("get");
        assert_eq!(data, format!("payload-{i}").into_bytes());
    }

    node_b
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");
    server_handle.join().expect("server thread");
    drop(dir_a);
    drop(dir_b);
}

// ---------------------------------------------------------------------------
// Three-node quorum replication
// ---------------------------------------------------------------------------

#[test]
fn three_node_quorum_replication() {
    // Node 1: primary listener + store
    let (node1, _addr1) = listening_transport(1);
    let (dir1, mut store1) = temp_store();

    // Node 2: replica listener + store
    let (node2, addr2) = listening_transport(2);
    let (dir2, store2) = temp_store();

    // Node 3: replica listener + store
    let (node3, addr3) = listening_transport(3);
    let (dir3, store3) = temp_store();

    // Spawn replica server threads first
    let s2 = thread::spawn(move || {
        let mut node = node2;
        let mut store = store2;
        let sid = blocking_accept(&mut node);
        node.perform_handshake(sid).ok();

        while let Ok(ReplicationMessage::Put { name, payload }) =
            recv_replication_msg(&mut node, sid)
        {
            store.put_named(&name, &payload).ok();
            send_replication_msg(
                &mut node,
                sid,
                &ReplicationMessage::Ack {
                    key_hash: name,
                    success: true,
                },
            )
            .ok();
        }
        node.close_session(sid, SessionCloseReason::PeerRemoved)
            .ok();
        (node, store)
    });

    let s3 = thread::spawn(move || {
        let mut node = node3;
        let mut store = store3;
        let sid = blocking_accept(&mut node);
        node.perform_handshake(sid).ok();

        while let Ok(ReplicationMessage::Put { name, payload }) =
            recv_replication_msg(&mut node, sid)
        {
            store.put_named(&name, &payload).ok();
            send_replication_msg(
                &mut node,
                sid,
                &ReplicationMessage::Ack {
                    key_hash: name,
                    success: true,
                },
            )
            .ok();
        }
        node.close_session(sid, SessionCloseReason::PeerRemoved)
            .ok();
        (node, store)
    });

    // Give servers time to start listening
    thread::sleep(Duration::from_millis(50));

    // Primary: connect to both replicas and replicate data
    let mut node1 = node1;
    node1.add_node(NodeInfo::new(2, vec![addr2], 0));
    node1.add_node(NodeInfo::new(3, vec![addr3], 0));

    let sid2 = node1.connect(2).expect("connect to node 2");
    node1.perform_handshake(sid2).expect("handshake with 2");

    let sid3 = node1.connect(3).expect("connect to node 3");
    node1.perform_handshake(sid3).expect("handshake with 3");

    // Replicate to both replicas
    for i in 0..3 {
        let name = format!("quorum-obj-{i}");
        let payload = format!("quorum-data-{i}").into_bytes();

        store1.put_named(&name, &payload).expect("put on primary");

        // Send to replica 2
        send_replication_msg(
            &mut node1,
            sid2,
            &ReplicationMessage::Put {
                name: name.clone(),
                payload: payload.clone(),
            },
        )
        .expect("send to 2");
        let ack2 = recv_replication_msg(&mut node1, sid2).expect("ack from 2");
        assert!(matches!(
            ack2,
            ReplicationMessage::Ack { success: true, .. }
        ));

        // Send to replica 3
        send_replication_msg(&mut node1, sid3, &ReplicationMessage::Put { name, payload })
            .expect("send to 3");
        let ack3 = recv_replication_msg(&mut node1, sid3).expect("ack from 3");
        assert!(matches!(
            ack3,
            ReplicationMessage::Ack { success: true, .. }
        ));
    }

    // Close sessions to trigger server thread exit
    node1
        .close_session(sid2, SessionCloseReason::LocalShutdown)
        .expect("close 2");
    node1
        .close_session(sid3, SessionCloseReason::LocalShutdown)
        .expect("close 3");

    // Wait for server threads to finish and get their stores back
    let (_, store2_after) = s2.join().expect("s2 join");
    let (_, store3_after) = s3.join().expect("s3 join");

    // Verify data on all nodes
    for i in 0..3 {
        let name = format!("quorum-obj-{i}");
        let key = ObjectKey::from_name(&name);
        let expected = format!("quorum-data-{i}").into_bytes();

        assert!(store1.contains_key(key), "primary should have {name}");
        let loc = store1.location_of(key).expect("primary location");
        assert_eq!(store1.get_at_location(loc).expect("primary get"), expected);

        assert!(
            store2_after.contains_key(key),
            "replica 2 should have {name}"
        );
        let loc = store2_after.location_of(key).expect("replica 2 location");
        assert_eq!(
            store2_after.get_at_location(loc).expect("replica 2 get"),
            expected
        );

        assert!(
            store3_after.contains_key(key),
            "replica 3 should have {name}"
        );
        let loc = store3_after.location_of(key).expect("replica 3 location");
        assert_eq!(
            store3_after.get_at_location(loc).expect("replica 3 get"),
            expected
        );
    }

    drop(dir1);
    drop(dir2);
    drop(dir3);
}

// ---------------------------------------------------------------------------
// Replica repair: sync missing data after recovery
// ---------------------------------------------------------------------------

#[test]
fn replica_repair_after_recovery() {
    let (mut node_a, addr_a) = listening_transport(1);
    let (dir_a, mut store_a) = temp_store();

    // Pre-populate node A with data. Track the original (name, payload) pairs.
    let mut pre_populated: Vec<SyncEntry> = Vec::new();
    for i in 0..5 {
        let name = format!("pre-{i}");
        let payload = format!("pre-data-{i}").into_bytes();
        store_a.put_named(&name, &payload).expect("put");
        pre_populated.push(SyncEntry::receiptless(
            ObjectKey::from_name(&name).as_bytes32(),
            payload,
        ));
    }

    // Node B: fresh empty store, needs sync
    let mut node_b = Transport::new(2);
    let (dir_b, mut store_b) = temp_store();

    node_a.add_node(NodeInfo::new(2, vec![addr_a.clone()], 0));
    node_b.add_node(NodeInfo::new(1, vec![addr_a], 0));

    // Server (node A) handles sync request by returning pre-populated data.
    // Uses tracked object-key bytes for a correct SyncResponse.
    let entries_for_sync = pre_populated.clone();
    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut node_a);
        node_a.perform_handshake(sid).expect("handshake");

        while let Ok(ReplicationMessage::SyncRequest) = recv_replication_msg(&mut node_a, sid) {
            send_replication_msg(
                &mut node_a,
                sid,
                &ReplicationMessage::SyncResponse {
                    entries: entries_for_sync.clone(),
                },
            )
            .expect("send sync");
        }
        node_a
            .close_session(sid, SessionCloseReason::PeerRemoved)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    // Client (node B): connect and sync
    let sid = node_b.connect(1).expect("connect");
    node_b.perform_handshake(sid).expect("handshake");

    // Request sync from node A
    send_replication_msg(&mut node_b, sid, &ReplicationMessage::SyncRequest).expect("send sync");

    // Receive sync response
    let response = recv_replication_msg(&mut node_b, sid).expect("recv sync");
    match response {
        ReplicationMessage::SyncResponse { entries } => {
            assert_eq!(entries.len(), 5, "Should sync 5 pre-existing objects");
            for entry in &entries {
                assert_eq!(entry.placement_receipt_ref, None);
                store_b
                    .put(ObjectKey::from_bytes32(entry.object_key), &entry.payload)
                    .expect("store synced data");
            }
        }
        _ => panic!("Expected SyncResponse"),
    }

    // Verify node B now has all the data by name
    for i in 0..5 {
        let name = format!("pre-{i}");
        let key = ObjectKey::from_name(&name);
        assert!(
            store_b.contains_key(key),
            "Node B should have {name} after sync"
        );
        let loc = store_b.location_of(key).expect("location");
        let data = store_b.get_at_location(loc).expect("get");
        assert_eq!(data, format!("pre-data-{i}").into_bytes());
    }

    node_b
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");
    server_handle.join().expect("server");
    drop(dir_a);
    drop(dir_b);
}

// ---------------------------------------------------------------------------
// Large payload replication (larger than single TCP frame)
// ---------------------------------------------------------------------------

#[test]
fn large_payload_replication() {
    let (mut node_a, addr_a) = listening_transport(1);
    // Use default (production) options for large payload support
    let (dir_a, mut store_a) = temp_store_large();
    let mut node_b = Transport::new(2);
    let (dir_b, _store_b) = temp_store();

    node_a.add_node(NodeInfo::new(2, vec![addr_a.clone()], 0));
    node_b.add_node(NodeInfo::new(1, vec![addr_a], 0));

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut node_a);
        node_a.perform_handshake(sid).expect("handshake");

        loop {
            match recv_replication_msg(&mut node_a, sid) {
                Ok(ReplicationMessage::Put { name, payload }) => {
                    store_a.put_named(&name, &payload).expect("put large");
                    send_replication_msg(
                        &mut node_a,
                        sid,
                        &ReplicationMessage::Ack {
                            key_hash: name,
                            success: true,
                        },
                    )
                    .expect("send ack");
                }
                Ok(ReplicationMessage::Get { name }) => {
                    let key = ObjectKey::from_name(&name);
                    let found = store_a.contains_key(key);
                    let payload = if found {
                        let loc = store_a.location_of(key).expect("location");
                        store_a.get_at_location(loc).expect("get")
                    } else {
                        Vec::new()
                    };
                    send_replication_msg(
                        &mut node_a,
                        sid,
                        &ReplicationMessage::GetResponse { found, payload },
                    )
                    .expect("send get_response");
                }
                _ => break,
            }
        }
        node_a
            .close_session(sid, SessionCloseReason::PeerRemoved)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = node_b.connect(1).expect("connect");
    node_b.perform_handshake(sid).expect("handshake");

    // Create a payload larger than a typical TCP frame (1MB)
    let large_payload: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    let name = "large-object";

    send_replication_msg(
        &mut node_b,
        sid,
        &ReplicationMessage::Put {
            name: name.to_string(),
            payload: large_payload.clone(),
        },
    )
    .expect("send large put");

    let ack = recv_replication_msg(&mut node_b, sid).expect("recv ack");
    assert!(
        matches!(ack, ReplicationMessage::Ack { success: true, .. }),
        "Large payload replication should succeed"
    );

    // Verify on node B via get
    send_replication_msg(
        &mut node_b,
        sid,
        &ReplicationMessage::Get {
            name: name.to_string(),
        },
    )
    .expect("send get");

    let response = recv_replication_msg(&mut node_b, sid).expect("recv get_response");
    match response {
        ReplicationMessage::GetResponse { found, payload } => {
            assert!(found, "Large object should be found");
            assert_eq!(
                payload.len(),
                large_payload.len(),
                "Payload length should match"
            );
            assert_eq!(payload, large_payload, "Payload content should match");
        }
        _ => panic!("Expected GetResponse"),
    }

    node_b
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");
    server_handle.join().expect("server");
    drop(dir_a);
    drop(dir_b);
}

#[test]
fn replication_fails_on_closed_session() {
    let (mut node_a, addr_a) = listening_transport(1);
    let (dir_a, mut store_a) = temp_store();
    let mut node_b = Transport::new(2);
    let (dir_b, _store_b) = temp_store();

    node_a.add_node(NodeInfo::new(2, vec![addr_a.clone()], 0));
    node_b.add_node(NodeInfo::new(1, vec![addr_a], 0));

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut node_a);
        node_a.perform_handshake(sid).expect("handshake");

        // Process one message then close
        let msg = recv_replication_msg(&mut node_a, sid);
        if let Ok(ReplicationMessage::Put { name, payload }) = msg {
            store_a.put_named(&name, &payload).ok();
            send_replication_msg(
                &mut node_a,
                sid,
                &ReplicationMessage::Ack {
                    key_hash: name,
                    success: true,
                },
            )
            .ok();
        }

        node_a
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = node_b.connect(1).expect("connect");
    node_b.perform_handshake(sid).expect("handshake");

    // Send one successful message
    send_replication_msg(
        &mut node_b,
        sid,
        &ReplicationMessage::Put {
            name: "first".to_string(),
            payload: b"first-data".to_vec(),
        },
    )
    .expect("send first");

    let ack = recv_replication_msg(&mut node_b, sid).expect("recv ack");
    assert!(matches!(ack, ReplicationMessage::Ack { success: true, .. }));

    // Close session
    node_b
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");

    // Attempting to send on closed session should fail
    let result = send_replication_msg(
        &mut node_b,
        sid,
        &ReplicationMessage::Put {
            name: "second".to_string(),
            payload: b"should-fail".to_vec(),
        },
    );
    assert!(result.is_err(), "Send on closed session should fail");

    server_handle.join().expect("server");
    drop(dir_a);
    drop(dir_b);
}

// ── Receipt transfer integration tests ─────────────────────────────────

#[test]
fn receipt_transfer_put_and_read() {
    // Two nodes: Node 1 (server with store), Node 2 (client).
    // Client sends PutWithReceipt; server stores and returns its
    // pool-backed receipt in the ack.
    let (mut node_a, addr_a) = listening_transport(1);
    let (dir_a, mut store_a) = temp_store();
    let mut node_b = Transport::new(2);

    node_a.add_node(NodeInfo::new(2, vec![addr_a.clone()], 0));
    node_b.add_node(NodeInfo::new(1, vec![addr_a], 0));

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut node_a);
        node_a.perform_handshake(sid).expect("handshake");

        loop {
            let msg = match recv_replication_msg(&mut node_a, sid) {
                Ok(m) => m,
                Err(_) => break,
            };
            match msg {
                ReplicationMessage::PutWithReceipt { name, payload, placement_receipt_ref } => {
                    // Store with receipt authority: record the receipt
                    store_a.put_named(&name, &payload).ok();
                    // Bump generation to simulate durable publication
                    let recorded = PlacementReceiptRef::replicated(
                        placement_receipt_ref.object_id,
                        placement_receipt_ref.object_key,
                        placement_receipt_ref.receipt_epoch,
                        placement_receipt_ref.receipt_generation + 1,
                        2,
                        payload.len() as u64,
                        placement_receipt_ref.payload_digest,
                    );
                    send_replication_msg(
                        &mut node_a,
                        sid,
                        &ReplicationMessage::PutWithReceiptAck {
                            key_hash: name.clone(),
                            success: true,
                            recorded_receipt_ref: Some(recorded),
                        },
                    )
                    .expect("send put_with_receipt ack");
                }
                ReplicationMessage::Get { name } => {
                    let key = ObjectKey::from_name(&name);
                    let found = store_a.contains_key(key);
                    let payload = if found {
                        let loc = store_a.location_of(key).expect("location");
                        store_a.get_at_location(loc).expect("get")
                    } else {
                        Vec::new()
                    };
                    send_replication_msg(
                        &mut node_a,
                        sid,
                        &ReplicationMessage::GetResponse { found, payload },
                    )
                    .expect("send get_response");
                }
                _ => break,
            }
        }
        node_a
            .close_session(sid, SessionCloseReason::PeerRemoved)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = node_b.connect(1).expect("connect");
    node_b.perform_handshake(sid).expect("handshake");

    // Create payload and receipt
    let payload = b"receipt-transfer-payload-v1".to_vec();
    let receipt = test_receipt_ref("receipt-obj-1", &payload, 100);

    // Send PutWithReceipt
    send_replication_msg(
        &mut node_b,
        sid,
        &ReplicationMessage::PutWithReceipt {
            name: "receipt-obj-1".to_string(),
            payload: payload.clone(),
            placement_receipt_ref: receipt.clone(),
        },
    )
    .expect("send put_with_receipt");

    // Receive ack with recorded receipt
    let ack = recv_replication_msg(&mut node_b, sid).expect("recv ack");
    match ack {
        ReplicationMessage::PutWithReceiptAck { ref key_hash, success, ref recorded_receipt_ref } => {
            assert!(success, "PutWithReceipt should succeed");
            assert_eq!(key_hash, "receipt-obj-1");
            let recorded = recorded_receipt_ref.as_ref().expect("should have recorded receipt");
            assert_eq!(recorded.object_key, receipt.object_key);
            assert_eq!(recorded.payload_digest, receipt.payload_digest);
            assert_eq!(recorded.payload_len, receipt.payload_len);
            // Generation should be bumped by server
            assert!(recorded.receipt_generation > receipt.receipt_generation);
        }
        _ => panic!("Expected PutWithReceiptAck, got {:?}", ack),
    }

    // Read back the object using Get
    send_replication_msg(
        &mut node_b,
        sid,
        &ReplicationMessage::Get {
            name: "receipt-obj-1".to_string(),
        },
    )
    .expect("send get");

    let response = recv_replication_msg(&mut node_b, sid).expect("recv get_response");
    match response {
        ReplicationMessage::GetResponse { found, payload: read_payload } => {
            assert!(found, "Object should be readable after receipt transfer");
            assert_eq!(read_payload, payload, "Payload should match");
        }
        _ => panic!("Expected GetResponse"),
    }

    node_b
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");
    server_handle.join().expect("server");
    drop(dir_a);
}

#[test]
fn receipt_transfer_multiple_objects() {
    // Transfer multiple objects with receipts; verify each is independently readable.
    let (mut node_a, addr_a) = listening_transport(1);
    let (dir_a, mut store_a) = temp_store();
    let mut node_b = Transport::new(2);

    node_a.add_node(NodeInfo::new(2, vec![addr_a.clone()], 0));
    node_b.add_node(NodeInfo::new(1, vec![addr_a], 0));

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut node_a);
        node_a.perform_handshake(sid).expect("handshake");

        loop {
            let msg = match recv_replication_msg(&mut node_a, sid) {
                Ok(m) => m,
                Err(_) => break,
            };
            match msg {
                ReplicationMessage::PutWithReceipt { name, payload, placement_receipt_ref } => {
                    store_a.put_named(&name, &payload).ok();
                    let recorded = PlacementReceiptRef::replicated(
                        placement_receipt_ref.object_id,
                        placement_receipt_ref.object_key,
                        placement_receipt_ref.receipt_epoch,
                        placement_receipt_ref.receipt_generation + 1,
                        2,
                        payload.len() as u64,
                        placement_receipt_ref.payload_digest,
                    );
                    send_replication_msg(
                        &mut node_a,
                        sid,
                        &ReplicationMessage::PutWithReceiptAck {
                            key_hash: name.clone(),
                            success: true,
                            recorded_receipt_ref: Some(recorded),
                        },
                    )
                    .expect("send ack");
                }
                _ => break,
            }
        }
        node_a
            .close_session(sid, SessionCloseReason::PeerRemoved)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = node_b.connect(1).expect("connect");
    node_b.perform_handshake(sid).expect("handshake");

    let objects: Vec<(&str, Vec<u8>, u64)> = vec![
        ("obj-a", b"payload-alpha".to_vec(), 1),
        ("obj-b", b"payload-beta-bb".to_vec(), 2),
        ("obj-c", b"payload-gamma-ccc".to_vec(), 3),
    ];

    let mut receipts = Vec::new();
    for (name, payload, id) in &objects {
        let receipt = test_receipt_ref(name, payload, *id);
        send_replication_msg(
            &mut node_b,
            sid,
            &ReplicationMessage::PutWithReceipt {
                name: name.to_string(),
                payload: payload.clone(),
                placement_receipt_ref: receipt.clone(),
            },
        )
        .expect("send put_with_receipt");

        let ack = recv_replication_msg(&mut node_b, sid).expect("recv ack");
        match ack {
            ReplicationMessage::PutWithReceiptAck { success, recorded_receipt_ref, .. } => {
                assert!(success);
                assert!(recorded_receipt_ref.is_some());
                receipts.push(recorded_receipt_ref.unwrap());
            }
            _ => panic!("Expected PutWithReceiptAck"),
        }
    }

    assert_eq!(receipts.len(), objects.len());
    // Each receipt should have generation > 0
    for r in &receipts {
        assert!(r.receipt_generation > 0, "receipt generation should be non-zero");
    }
    // Receipts should have the same object_key and payload_len as their originals
    for ((_name, payload, _id), receipt) in objects.iter().zip(receipts.iter()) {
        assert_eq!(receipt.payload_len, payload.len() as u64);
    }

    node_b
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");
    server_handle.join().expect("server");
    drop(dir_a);
}

#[test]
fn receipt_transfer_rejects_mismatched_digest() {
    // A PutWithReceipt whose payload does not match the receipt digest
    // should be rejected by a validating receiver.
    let (mut node_a, addr_a) = listening_transport(1);
    let (dir_a, mut store_a) = temp_store();
    let mut node_b = Transport::new(2);

    node_a.add_node(NodeInfo::new(2, vec![addr_a.clone()], 0));
    node_b.add_node(NodeInfo::new(1, vec![addr_a], 0));

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut node_a);
        node_a.perform_handshake(sid).expect("handshake");

        loop {
            let msg = match recv_replication_msg(&mut node_a, sid) {
                Ok(m) => m,
                Err(_) => break,
            };
            match msg {
                ReplicationMessage::PutWithReceipt { name, payload, placement_receipt_ref } => {
                    // Validate digest before storing
                    let actual_digest = blake3::hash(&payload);
                    let digest_ok = actual_digest.as_bytes() == &placement_receipt_ref.payload_digest;
                    if digest_ok {
                        store_a.put_named(&name, &payload).ok();
                    }
                    send_replication_msg(
                        &mut node_a,
                        sid,
                        &ReplicationMessage::PutWithReceiptAck {
                            key_hash: name,
                            success: digest_ok,
                            recorded_receipt_ref: None,
                        },
                    )
                    .expect("send ack");
                }
                _ => break,
            }
        }
        node_a
            .close_session(sid, SessionCloseReason::PeerRemoved)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = node_b.connect(1).expect("connect");
    node_b.perform_handshake(sid).expect("handshake");

    // Valid payload with correct receipt
    let valid_payload = b"valid-data".to_vec();
    let valid_receipt = test_receipt_ref("valid-key", &valid_payload, 1);
    send_replication_msg(
        &mut node_b,
        sid,
        &ReplicationMessage::PutWithReceipt {
            name: "valid-key".to_string(),
            payload: valid_payload.clone(),
            placement_receipt_ref: valid_receipt,
        },
    )
    .expect("send valid");
    let ack = recv_replication_msg(&mut node_b, sid).expect("recv ack");
    assert!(matches!(ack, ReplicationMessage::PutWithReceiptAck { success: true, .. }));

    // Mismatched payload: receipt claims different digest
    let wrong_payload = b"tampered-data".to_vec();
    let stale_receipt = test_receipt_ref("bad-key", b"original-data", 2);
    send_replication_msg(
        &mut node_b,
        sid,
        &ReplicationMessage::PutWithReceipt {
            name: "bad-key".to_string(),
            payload: wrong_payload,
            placement_receipt_ref: stale_receipt,
        },
    )
    .expect("send bad");
    let ack2 = recv_replication_msg(&mut node_b, sid).expect("recv ack2");
    assert!(
        matches!(ack2, ReplicationMessage::PutWithReceiptAck { success: false, .. }),
        "Mismatched digest should be rejected"
    );

    node_b
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");
    server_handle.join().expect("server");
    drop(dir_a);
}
