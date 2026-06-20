// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration test for remote segment fetch over real TCP transport.
//!
//! Spawns two Transport instances communicating over TCP loopback,
//! writes an object into a LocalObjectStore on "node A", sends a
//! SegmentFetchRequest from "node B" via send_segment_fetch, processes
//! the request on node A, sends back a SegmentFetchResponse, and
//! verifies structural response integrity and byte equality on node B.
//!
//! This exercises the full segment fetch message dispatch pipeline:
//!   encode (magic SF01) → send → recv → decode → store lookup →
//!   encode (magic SF02) -> send -> recv -> decode -> verify

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread;
use std::time::Duration;
use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};
use tidefs_membership_epoch::EpochId;
use tidefs_replication_model::PlacementReceiptRef;
use tidefs_transport::{
    recv_segment_fetch, recv_segment_fetch_response, send_segment_fetch,
    send_segment_fetch_response, NodeInfo, SegmentFetchRequest, SegmentFetchResponse,
    SessionCloseReason, SessionId, Transport, TransportError,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn temp_store() -> (tempfile::TempDir, LocalObjectStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
        .expect("open store");
    (dir, store)
}

fn receipt_ref(object_id: u64, object_key: [u8; 32]) -> PlacementReceiptRef {
    PlacementReceiptRef::replicated(
        object_id,
        object_key,
        EpochId::new(12),
        5,
        2,
        32,
        [0xC1; 32],
    )
}

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

// ---------------------------------------------------------------------------
// Segment fetch integration tests
// ---------------------------------------------------------------------------

/// Full segment fetch request-response round-trip over two TCP sessions.
#[test]
fn segment_fetch_request_response_over_transport() {
    // ── Node A (server): listens, holds the data ──
    let (mut node_a, addr_a) = listening_transport(1);
    let (_dir_a, mut store_a) = temp_store();

    // ── Node B (client): connects, sends fetch requests ──
    let mut node_b = Transport::new(2);

    node_a.add_node(NodeInfo::new(2, vec![addr_a.clone()], 0));
    node_b.add_node(NodeInfo::new(1, vec![addr_a], 0));

    // Write some test data into node A's store.
    // The object is keyed by the LE bytes of object_id so the responder
    // can find it from the SegmentFetchRequest.object_id field.
    let object_id: u64 = 42;
    let full_payload = b"Hello from node A -- this is segment fetch test data spanning multiple bytes for offset slicing!".to_vec();
    store_a
        .put(ObjectKey::from_name(object_id.to_le_bytes()), &full_payload)
        .expect("put on A");

    let segment_offset: u64 = 10;
    let segment_length: u64 = 25;
    let expected_segment = &full_payload[10..35];

    // ── Server thread: accept, handshake, handle segment fetch request ──
    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut node_a);
        node_a.perform_handshake(sid).expect("server handshake");

        // Receive SegmentFetchRequest from client
        let request =
            recv_segment_fetch(&mut node_a, sid).expect("server recv segment fetch request");
        assert_eq!(request.object_id, object_id);
        assert_eq!(request.segment_offset, segment_offset);
        assert_eq!(request.segment_length, segment_length);

        // Look up the object in the local store
        let key = ObjectKey::from_name(object_id.to_le_bytes());
        let full = store_a
            .get(key)
            .expect("store get")
            .expect("object must exist");

        // Slice out the requested segment
        let start = request.segment_offset as usize;
        let end = start.saturating_add(request.segment_length as usize);
        let slice_end = end.min(full.len());
        let segment = full[start..slice_end].to_vec();
        let actual_len = segment.len() as u64;

        // Build and send SegmentFetchResponse with structural integrity
        let response = SegmentFetchResponse::new(
            request.object_id,
            request.segment_offset,
            actual_len,
            segment,
        );
        send_segment_fetch_response(&mut node_a, sid, &response)
            .expect("server send segment fetch response");

        node_a
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    // Give the server thread time to start listening
    thread::sleep(Duration::from_millis(50));

    // ── Client: connect, send segment fetch request, verify response ──
    let sid = node_b.connect(1).expect("connect");
    node_b.perform_handshake(sid).expect("client handshake");

    // Build and send the request
    let request = SegmentFetchRequest::new(object_id, segment_offset, segment_length);
    send_segment_fetch(&mut node_b, sid, &request).expect("client send segment fetch request");

    // Receive the response with structural verification
    let response =
        recv_segment_fetch_response(&mut node_b, sid).expect("client recv segment fetch response");

    // Verify the response matches expectations
    assert_eq!(response.object_id, object_id);
    assert_eq!(response.segment_offset, segment_offset);
    assert_eq!(response.payload, expected_segment);
    assert_eq!(response.segment_length, expected_segment.len() as u64);

    // Transport session boundary provides per-message integrity

    node_b
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");
    server_handle.join().expect("server thread");
}

#[test]
fn segment_fetch_preserves_receipt_ref_over_transport() {
    let (mut node_a, addr_a) = listening_transport(13);
    let mut node_b = Transport::new(14);

    node_a.add_node(NodeInfo::new(14, vec![addr_a.clone()], 0));
    node_b.add_node(NodeInfo::new(13, vec![addr_a], 0));

    let receipt = receipt_ref(1234, [0xD3; 32]);

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut node_a);
        node_a.perform_handshake(sid).expect("server handshake");

        let request = recv_segment_fetch(&mut node_a, sid).expect("server recv");
        assert_eq!(request.object_id, receipt.object_id);
        assert_eq!(request.placement_receipt_ref, Some(receipt));
        assert_eq!(request.non_synthetic_receipt_ref(), Some(receipt));
        assert_eq!(request.segment_offset, 3);
        assert_eq!(request.segment_length, 4);

        let response = SegmentFetchResponse::new(
            request.object_id,
            request.segment_offset,
            4,
            b"pong".to_vec(),
        );
        send_segment_fetch_response(&mut node_a, sid, &response).expect("send");
        node_a
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = node_b.connect(13).expect("connect");
    node_b.perform_handshake(sid).expect("client handshake");

    let request = SegmentFetchRequest::with_placement_receipt_ref(receipt, 3, 4);
    send_segment_fetch(&mut node_b, sid, &request).expect("client send");
    let response = recv_segment_fetch_response(&mut node_b, sid).expect("client recv");
    assert_eq!(response.object_id, receipt.object_id);
    assert_eq!(response.payload, b"pong".to_vec());

    node_b
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");
    server_handle.join().expect("server");
}

/// Segment fetch with empty payload (zero-length segment).
#[test]
fn segment_fetch_empty_payload() {
    let (mut node_a, addr_a) = listening_transport(3);
    let (_dir_a, mut store_a) = temp_store();
    let mut node_b = Transport::new(4);

    node_a.add_node(NodeInfo::new(4, vec![addr_a.clone()], 0));
    node_b.add_node(NodeInfo::new(3, vec![addr_a], 0));

    let object_id: u64 = 99;
    let full_payload = b"some data".to_vec();
    store_a
        .put(ObjectKey::from_name(object_id.to_le_bytes()), &full_payload)
        .expect("put");

    // Request an empty segment (offset at end, length 0)
    let segment_offset = full_payload.len() as u64;
    let segment_length = 0u64;

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut node_a);
        node_a.perform_handshake(sid).expect("server handshake");

        let request = recv_segment_fetch(&mut node_a, sid).expect("server recv");
        let key = ObjectKey::from_name(object_id.to_le_bytes());
        let full = store_a.get(key).expect("get").unwrap_or_default();

        let start = request.segment_offset as usize;
        let end = start.saturating_add(request.segment_length as usize);
        let slice_end = end.min(full.len());
        let segment = full[start..slice_end].to_vec();
        let actual_len = segment.len() as u64;

        let response = SegmentFetchResponse::new(
            request.object_id,
            request.segment_offset,
            actual_len,
            segment,
        );
        send_segment_fetch_response(&mut node_a, sid, &response).expect("send");
        node_a
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = node_b.connect(3).expect("connect");
    node_b.perform_handshake(sid).expect("handshake");

    let request = SegmentFetchRequest::new(object_id, segment_offset, segment_length);
    send_segment_fetch(&mut node_b, sid, &request).expect("send");

    let response = recv_segment_fetch_response(&mut node_b, sid).expect("recv");
    assert!(response.payload.is_empty());
    assert_eq!(response.segment_length, 0);
    // transport session provides per-message integrity

    node_b
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");
    server_handle.join().expect("server");
}

/// Response-shape rejection: tamper with the payload length in-flight.
#[test]
fn segment_fetch_length_mismatch_rejected() {
    let (mut node_a, addr_a) = listening_transport(5);
    let (_dir_a, mut store_a) = temp_store();
    let mut node_b = Transport::new(6);

    node_a.add_node(NodeInfo::new(6, vec![addr_a.clone()], 0));
    node_b.add_node(NodeInfo::new(5, vec![addr_a], 0));

    let object_id: u64 = 77;
    let full_payload = b"data that will be corrupted in transit".to_vec();
    store_a
        .put(ObjectKey::from_name(object_id.to_le_bytes()), &full_payload)
        .expect("put");

    // Server builds a valid response, but simulates a wire peer sending a
    // tampered payload that no longer matches the encoded segment length.
    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut node_a);
        node_a.perform_handshake(sid).expect("server handshake");

        let request = recv_segment_fetch(&mut node_a, sid).expect("server recv");

        // Build a correct response, then tamper with the payload before
        // encoding so the response shape no longer matches.
        let mut response = SegmentFetchResponse::new(
            request.object_id,
            request.segment_offset,
            5,
            b"valid".to_vec(),
        );

        // Tamper with the payload after constructor validation.
        response.payload = b"BAD!".to_vec();
        // NOTE: segment_length still says 5 but payload is now 4 bytes.

        // Encode and send the tampered response anyway
        send_segment_fetch_response(&mut node_a, sid, &response).expect("send tampered response");

        node_a
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = node_b.connect(5).expect("connect");
    node_b.perform_handshake(sid).expect("handshake");

    let request = SegmentFetchRequest::new(object_id, 0, 5);
    send_segment_fetch(&mut node_b, sid, &request).expect("send");

    // The response should fail structural verification.
    let result = recv_segment_fetch_response(&mut node_b, sid);
    assert!(result.is_err(), "tampered response must be rejected");
    assert!(
        result.unwrap_err().to_string().contains("length mismatch"),
        "error should mention length mismatch"
    );

    node_b
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");
    server_handle.join().expect("server");
}

/// Segment fetch request with magic prefix: incorrect magic is rejected.
#[test]
fn segment_fetch_bad_magic_rejected() {
    let (mut node_a, addr_a) = listening_transport(7);
    let mut node_b = Transport::new(8);

    node_a.add_node(NodeInfo::new(8, vec![addr_a.clone()], 0));
    node_b.add_node(NodeInfo::new(7, vec![addr_a], 0));

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut node_a);
        node_a.perform_handshake(sid).expect("server handshake");

        // Receive the raw message (should fail SF01 magic check)
        let raw = node_a.recv_message(sid).expect("server recv raw");
        let result = SegmentFetchRequest::decode(&raw);
        assert!(result.is_err(), "decode with bad magic must fail");

        node_a
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = node_b.connect(7).expect("connect");
    node_b.perform_handshake(sid).expect("handshake");

    // Send raw bytes that don't start with SF01 magic
    let bad_bytes = b"BAD MAGIC PREFIX -- not a segment fetch request".to_vec();
    node_b
        .send_message(sid, &bad_bytes)
        .expect("send bad bytes");

    server_handle.join().expect("server");
    node_b
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");
}
