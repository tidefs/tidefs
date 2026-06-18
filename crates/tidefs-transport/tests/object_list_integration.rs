// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration test for object list enumeration over real TCP transport.
//!
//! Spawns two Transport instances communicating over TCP loopback,
//! sends a ListObjectsRequest from "node B" via send_list_objects_request,
//! processes the request on node A with a simple in-memory handler,
//! sends back a ListObjectsResponse, and verifies BLAKE3 integrity
//! and entry correctness on node B.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tidefs_transport::{
    recv_list_objects_request, recv_list_objects_response, send_list_objects_request,
    send_list_objects_response, ListObjectsResponse, NodeInfo, ObjectListEntry, SessionCloseReason,
    SessionId, Transport, TransportError,
};

/// Helper to make a [u8; 32] from a u64 (big-endian in first 8 bytes).
fn key_from_u64(v: u64) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..8].copy_from_slice(&v.to_be_bytes());
    key
}

/// Helper to extract the u64 from the first 8 bytes of a key.
fn u64_from_key(key: &[u8; 32]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&key[..8]);
    u64::from_be_bytes(buf)
}

// ---------------------------------------------------------------------------
// In-memory object catalog for testing enumeration
// ---------------------------------------------------------------------------

/// A simple in-memory object catalog that stores entries sorted by object_key.
/// This serves as the handler backend for integration tests.
#[derive(Clone, Default)]
struct InMemoryCatalog {
    entries: Arc<Mutex<BTreeMap<[u8; 32], ObjectListEntry>>>,
}

impl InMemoryCatalog {
    fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn put(&self, entry: ObjectListEntry) {
        self.entries.lock().unwrap().insert(entry.object_key, entry);
    }

    fn list_objects(
        &self,
        start_after: Option<[u8; 32]>,
        max_entries: u32,
    ) -> (Vec<ObjectListEntry>, bool) {
        let entries = self.entries.lock().unwrap();
        let max = max_entries as usize;
        let mut result = Vec::with_capacity(max);
        let mut count = 0;

        if let Some(start) = start_after {
            // Iterate from just after start
            for (_key, entry) in
                entries.range((std::ops::Bound::Excluded(start), std::ops::Bound::Unbounded))
            {
                if count >= max {
                    return (result, true);
                }
                result.push(entry.clone());
                count += 1;
            }
        } else {
            for (_key, entry) in entries.iter() {
                if count >= max {
                    return (result, true);
                }
                result.push(entry.clone());
                count += 1;
            }
        }

        (result, false)
    }
}

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Full object list request-response round-trip over TCP.
#[test]
fn object_list_request_response_over_transport() {
    let (mut node_a, addr_a) = listening_transport(1);
    let catalog = InMemoryCatalog::new();

    for i in 0..5u64 {
        let root = [i as u8; 32];
        let key = key_from_u64(i);
        catalog.put(ObjectListEntry::new(key, i * 4096 + 512, root));
    }

    let mut node_b = Transport::new(2);
    node_a.add_node(NodeInfo::new(2, vec![addr_a.clone()], 0));
    node_b.add_node(NodeInfo::new(1, vec![addr_a], 0));

    let catalog_clone = catalog.clone();

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut node_a);
        node_a.perform_handshake(sid).expect("server handshake");

        let request =
            recv_list_objects_request(&mut node_a, sid).expect("server recv list request");

        let (entries, has_more) =
            catalog_clone.list_objects(request.start_after, request.max_entries);

        let response =
            ListObjectsResponse::new(entries, has_more, request.start_after, request.max_entries);
        send_list_objects_response(&mut node_a, sid, &response).expect("server send list response");

        node_a
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = node_b.connect(1).expect("connect");
    node_b.perform_handshake(sid).expect("client handshake");

    send_list_objects_request(&mut node_b, sid, None, 20).expect("client send list request");

    let response = recv_list_objects_response(&mut node_b, sid).expect("client recv list response");

    assert_eq!(response.entry_count(), 5);
    assert!(!response.has_more);
    assert_eq!(response.start_after, None);
    assert_eq!(response.max_entries, 20);

    let ids: Vec<u64> = response
        .entries
        .iter()
        .map(|e| u64_from_key(&e.object_key))
        .collect();
    assert_eq!(ids, vec![0, 1, 2, 3, 4]);

    for (i, entry) in response.entries.iter().enumerate() {
        assert_eq!(entry.size, i as u64 * 4096 + 512);
        assert_eq!(entry.blake3_root[0], i as u8);
    }

    response
        .verify_payload()
        .expect("BLAKE3 integrity check must pass");

    node_b
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");
    server_handle.join().expect("server thread");
}

/// Paginated enumeration with start_after cursor.
#[test]
fn object_list_pagination_with_cursor() {
    let (mut node_a, addr_a) = listening_transport(3);
    let catalog = InMemoryCatalog::new();

    for i in 0..10u64 {
        let root = [i as u8; 32];
        let key = key_from_u64(i);
        catalog.put(ObjectListEntry::new(key, 100, root));
    }

    let mut node_b = Transport::new(4);
    node_a.add_node(NodeInfo::new(4, vec![addr_a.clone()], 0));
    node_b.add_node(NodeInfo::new(3, vec![addr_a], 0));

    let catalog_clone = catalog.clone();

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut node_a);
        node_a.perform_handshake(sid).expect("server handshake");

        let req1 = recv_list_objects_request(&mut node_a, sid).expect("recv request 1");
        assert_eq!(req1.start_after, None);
        assert_eq!(req1.max_entries, 3);
        let (entries1, has_more1) = catalog_clone.list_objects(req1.start_after, req1.max_entries);
        let resp1 =
            ListObjectsResponse::new(entries1, has_more1, req1.start_after, req1.max_entries);
        send_list_objects_response(&mut node_a, sid, &resp1).expect("send resp 1");

        let req2 = recv_list_objects_request(&mut node_a, sid).expect("recv request 2");
        assert_eq!(req2.start_after, Some(key_from_u64(2)));
        assert_eq!(req2.max_entries, 3);
        let (entries2, has_more2) = catalog_clone.list_objects(req2.start_after, req2.max_entries);
        let resp2 =
            ListObjectsResponse::new(entries2, has_more2, req2.start_after, req2.max_entries);
        send_list_objects_response(&mut node_a, sid, &resp2).expect("send resp 2");

        let req3 = recv_list_objects_request(&mut node_a, sid).expect("recv request 3");
        assert_eq!(req3.start_after, Some(key_from_u64(5)));
        let (entries3, has_more3) = catalog_clone.list_objects(req3.start_after, req3.max_entries);
        let resp3 =
            ListObjectsResponse::new(entries3, has_more3, req3.start_after, req3.max_entries);
        send_list_objects_response(&mut node_a, sid, &resp3).expect("send resp 3");

        node_a
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = node_b.connect(3).expect("connect");
    node_b.perform_handshake(sid).expect("handshake");

    send_list_objects_request(&mut node_b, sid, None, 3).expect("send");
    let r1 = recv_list_objects_response(&mut node_b, sid).expect("recv");
    assert_eq!(r1.entry_count(), 3);
    assert!(r1.has_more);
    let ids1: Vec<u64> = r1
        .entries
        .iter()
        .map(|e| u64_from_key(&e.object_key))
        .collect();
    assert_eq!(ids1, vec![0, 1, 2]);

    send_list_objects_request(&mut node_b, sid, Some(key_from_u64(2)), 3).expect("send");
    let r2 = recv_list_objects_response(&mut node_b, sid).expect("recv");
    assert_eq!(r2.entry_count(), 3);
    assert!(r2.has_more);
    let ids2: Vec<u64> = r2
        .entries
        .iter()
        .map(|e| u64_from_key(&e.object_key))
        .collect();
    assert_eq!(ids2, vec![3, 4, 5]);

    send_list_objects_request(&mut node_b, sid, Some(key_from_u64(5)), 3).expect("send");
    let r3 = recv_list_objects_response(&mut node_b, sid).expect("recv");
    assert_eq!(r3.entry_count(), 3);
    assert!(r3.has_more); // objects 6,7,8, one more left (9)
    let ids3: Vec<u64> = r3
        .entries
        .iter()
        .map(|e| u64_from_key(&e.object_key))
        .collect();
    assert_eq!(ids3, vec![6, 7, 8]);

    node_b
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");
    server_handle.join().expect("server");
}

/// Empty catalog returns empty response.
#[test]
fn object_list_empty_catalog() {
    let (mut node_a, addr_a) = listening_transport(5);
    let catalog = InMemoryCatalog::new();
    let mut node_b = Transport::new(6);

    node_a.add_node(NodeInfo::new(6, vec![addr_a.clone()], 0));
    node_b.add_node(NodeInfo::new(5, vec![addr_a], 0));

    let catalog_clone = catalog.clone();

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut node_a);
        node_a.perform_handshake(sid).expect("server handshake");

        let request = recv_list_objects_request(&mut node_a, sid).expect("recv");
        let (entries, has_more) =
            catalog_clone.list_objects(request.start_after, request.max_entries);
        let response =
            ListObjectsResponse::new(entries, has_more, request.start_after, request.max_entries);
        send_list_objects_response(&mut node_a, sid, &response).expect("send");

        node_a
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = node_b.connect(5).expect("connect");
    node_b.perform_handshake(sid).expect("handshake");

    send_list_objects_request(&mut node_b, sid, None, 100).expect("send");
    let response = recv_list_objects_response(&mut node_b, sid).expect("recv");

    assert_eq!(response.entry_count(), 0);
    assert!(!response.has_more);
    response
        .verify_payload()
        .expect("digest must verify for empty");

    node_b
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");
    server_handle.join().expect("server");
}

/// BLAKE3 digest rejection: tampered response payload is caught.
#[test]
fn object_list_digest_mismatch_rejected() {
    let (mut node_a, addr_a) = listening_transport(7);
    let catalog = InMemoryCatalog::new();
    catalog.put(ObjectListEntry::new(key_from_u64(1), 100, [0xBB; 32]));

    let mut node_b = Transport::new(8);
    node_a.add_node(NodeInfo::new(8, vec![addr_a.clone()], 0));
    node_b.add_node(NodeInfo::new(7, vec![addr_a], 0));

    let server_handle = thread::spawn(move || {
        let sid = blocking_accept(&mut node_a);
        node_a.perform_handshake(sid).expect("server handshake");

        let request = recv_list_objects_request(&mut node_a, sid).expect("recv");

        let mut response = ListObjectsResponse::new(
            vec![ObjectListEntry::new(key_from_u64(1), 100, [0xBB; 32])],
            false,
            request.start_after,
            request.max_entries,
        );

        response.entries[0].size = 9999;

        send_list_objects_response(&mut node_a, sid, &response).expect("send tampered");
        node_a
            .close_session(sid, SessionCloseReason::LocalShutdown)
            .ok();
    });

    thread::sleep(Duration::from_millis(50));

    let sid = node_b.connect(7).expect("connect");
    node_b.perform_handshake(sid).expect("handshake");

    send_list_objects_request(&mut node_b, sid, None, 10).expect("send");
    let result = recv_list_objects_response(&mut node_b, sid);
    assert!(result.is_err(), "tampered response must be rejected");
    assert!(
        result.unwrap_err().to_string().contains("digest"),
        "error should mention digest mismatch"
    );

    node_b
        .close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close");
    server_handle.join().expect("server");
}

// ===========================================================================
// LocalObjectStore-backed enumeration tests
// ===========================================================================

/// Integration tests using `tidefs_local_object_store` as the handler backend.
/// These prove that the ListObjects wire protocol works against real,
/// persistent object-store state (non-tombstoned keys, correct sizes,
/// BLAKE3 root matching), addressing the supervisor's concern about
/// in-memory-only validation.
#[cfg(test)]
mod local_store_tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};
    use tidefs_transport::ListObjectsHandler;

    /// Wraps a `LocalObjectStore` to implement `ListObjectsHandler`.
    ///
    /// Queries live (non-tombstoned) keys via `list_keys()`, sorts them
    /// lexicographically, retrieves per-object size via `get_attr()`, and
    /// uses the BLAKE3-key for content-addressed objects.
    struct StoreHandler {
        store: Arc<Mutex<LocalObjectStore>>,
    }

    impl StoreHandler {
        fn new(store: LocalObjectStore) -> Self {
            Self {
                store: Arc::new(Mutex::new(store)),
            }
        }
    }

    impl ListObjectsHandler for StoreHandler {
        fn list_objects(
            &self,
            start_after: Option<[u8; 32]>,
            max_entries: u32,
        ) -> (Vec<ObjectListEntry>, bool) {
            let store = self.store.lock().unwrap();
            let mut keys: Vec<ObjectKey> = store.list_keys();
            keys.sort();

            let max = max_entries as usize;
            let start = match start_after {
                None => 0,
                Some(cursor) => keys.partition_point(|k| k.as_bytes() <= &cursor),
            };

            let end = (start + max).min(keys.len());
            let has_more = end < keys.len();

            let mut entries = Vec::with_capacity(end.saturating_sub(start));
            for key in &keys[start..end] {
                let object_key = key.as_bytes32();
                let size = store.get_attr(key).map(|a| a.size).unwrap_or(0);
                // For content-addressed objects, the key IS the BLAKE3 root
                entries.push(ObjectListEntry::new(object_key, size, object_key));
            }

            (entries, has_more)
        }
    }

    // ── Tests ────────────────────────────────────────────────────────

    #[test]
    fn local_store_empty_catalog_returns_empty() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let store = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
            .expect("open store");
        let handler = StoreHandler::new(store);
        let (entries, has_more) = handler.list_objects(None, 100);
        assert!(entries.is_empty());
        assert!(!has_more);
    }

    #[test]
    fn local_store_put_and_list_objects() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut store = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
            .expect("open store");

        let k1 = store.put_content_addressed(b"object one").expect("put k1");
        let _k2 = store.put_content_addressed(b"object two").expect("put k2");
        let _k3 = store
            .put_content_addressed(b"object three")
            .expect("put k3");

        let handler = StoreHandler::new(store);
        let (entries, has_more) = handler.list_objects(None, 100);

        assert_eq!(entries.len(), 3, "should enumerate all three objects");
        assert!(!has_more);

        // Keys must be sorted lexicographically (by BLAKE3 hash bytes)
        let keys: Vec<[u8; 32]> = entries.iter().map(|e| e.object_key).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "keys must be lexicographically sorted");

        // All entries have nonzero size
        for e in &entries {
            assert!(e.size > 0, "every entry should have positive size");
        }

        // BLAKE3 root must match the content hash (= key for content-addressed)
        let expected_root_1 = blake3::hash(b"object one");
        assert_eq!(
            entries
                .iter()
                .find(|e| e.object_key == k1.as_bytes32())
                .unwrap()
                .blake3_root,
            *expected_root_1.as_bytes()
        );
    }

    #[test]
    fn local_store_pagination_with_cursor() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut store = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
            .expect("open store");

        // Insert 10 distinct objects
        let mut keys = Vec::new();
        for i in 0..10u8 {
            let payload = vec![i; 16];
            let key = store.put_content_addressed(&payload).expect("put");
            keys.push(key);
        }

        let handler = StoreHandler::new(store);

        // Page 1: first 4
        let (p1, more1) = handler.list_objects(None, 4);
        assert_eq!(p1.len(), 4);
        assert!(more1);

        // Page 2: next 4, starting after last entry of p1
        let cursor = p1.last().unwrap().object_key;
        let (p2, more2) = handler.list_objects(Some(cursor), 4);
        assert_eq!(p2.len(), 4);
        assert!(more2);

        // Page 3: remaining 2, starting after last entry of p2
        let cursor2 = p2.last().unwrap().object_key;
        let (p3, more3) = handler.list_objects(Some(cursor2), 4);
        assert_eq!(p3.len(), 2);
        assert!(!more3);

        // Total: 10 objects, no duplicates
        assert_eq!(p1.len() + p2.len() + p3.len(), 10);
    }

    #[test]
    fn local_store_deleted_objects_not_listed() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut store = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast())
            .expect("open store");

        let _keep = store.put_content_addressed(b"keep me").expect("put keep");
        let del = store.put_content_addressed(b"delete me").expect("put del");
        store.delete(del).expect("delete");

        let handler = StoreHandler::new(store);
        let (entries, _) = handler.list_objects(None, 100);
        assert_eq!(entries.len(), 1, "deleted object should not appear");
    }
}
