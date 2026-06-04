//! Integration test: storage node server + client roundtrip.
//!
//! Starts a storage node on a random port in a background thread,
//! then exercises put/get/delete/list/stats via client::request().

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tidefs_membership_epoch::{MemberClass, MemberId};
use tidefs_membership_live::MembershipTransport;
use tidefs_storage_node::client;
use tidefs_storage_node::protocol::Frame;
use tidefs_storage_node::server::{MembershipPeerConfig, StorageNode, StorageNodeConfig};

/// Pick a free port on localhost by briefly binding and dropping.
fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind for port pick");
    l.local_addr().expect("local_addr").port()
}

/// Build isolated store paths under a temp directory.
fn scratch_store_paths(label: &str, count: usize) -> Vec<PathBuf> {
    let base = std::env::temp_dir().join(format!("tidefs-int-{label}"));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("create scratch dir");
    (0..count).map(|i| base.join(format!("rep{i}"))).collect()
}

struct TestServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TestServer {
    fn spawn(node_id: u64, store_paths: Vec<PathBuf>) -> Self {
        let port = pick_port();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let config = StorageNodeConfig {
            bind_addr: addr,
            node_id,
            store_paths,
            fs_root: None,
            root_auth_key: None,
            member_class: None,
            failure_domain: None,
            membership_bind_addr: None,
            membership_peers: vec![],
            replica_peers: vec![],
            pool_device_path: None,
            pool_lock_dir: None,
            node_identity: None,
            authority: None,
            ready_file: None,
            drain_timeout_secs: 30,
            cluster_lease_config: None,
            membership_checkpoint_dir: None,
            rdma: false,
            carrier_policy: None,
        };

        let mut node = StorageNode::start(config).expect("start server");
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                match node.serve_one() {
                    Ok(()) => {}
                    Err(e) => {
                        if !stop_clone.load(Ordering::Relaxed) {
                            eprintln!("[test-server] serve_one: {e}");
                        }
                    }
                }
            }
            drop(node);
        });

        // Give server a moment to bind and start accepting
        thread::sleep(Duration::from_millis(50));

        TestServer {
            addr,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            // Give the server a moment to notice the stop flag
            let _ = h.join();
        }
    }
}

#[test]
fn storage_node_start_dials_configured_membership_peer() {
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();

    let peer = thread::spawn(move || {
        let mut peer_transport = MembershipTransport::new(2);
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        peer_transport.bind(bind_addr).expect("membership bind");
        addr_tx
            .send(peer_transport.local_addr().expect("membership addr"))
            .expect("send membership addr");

        loop {
            match peer_transport.try_accept_peer() {
                Ok(Some((peer_id, _))) => {
                    accepted_tx.send(peer_id).expect("send accepted peer");
                    break;
                }
                Ok(None) => thread::sleep(Duration::from_millis(5)),
                Err(e) => panic!("accept membership peer: {e}"),
            }
        }
    });

    let peer_addr = addr_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("membership peer addr");
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_port());
    let config = StorageNodeConfig {
        bind_addr,
        node_id: 1,
        authority: None,
        store_paths: scratch_store_paths("membership-peer", 1),
        fs_root: None,
        root_auth_key: None,
        member_class: Some(MemberClass::Voter),
        failure_domain: Some(1),
        membership_bind_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
        membership_peers: vec![MembershipPeerConfig {
            node_id: 2,
            addr: peer_addr.as_socket_addr().expect("TCP transport addr"),
            member_class: MemberClass::Voter,
            failure_domain: 2,
        }],
        replica_peers: vec![],
        pool_device_path: None,
        pool_lock_dir: None,
        node_identity: None,
        ready_file: None,
        drain_timeout_secs: 30,
        cluster_lease_config: None,
        membership_checkpoint_dir: None,
        rdma: false,
        carrier_policy: None,
    };

    let node = StorageNode::start(config).expect("start storage node with membership peer");
    let accepted_peer = accepted_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("accepted membership peer");
    assert_eq!(accepted_peer, 1);
    assert!(node.membership_transport_handle().is_some());

    let view = node.membership_view();
    let peer_node = view
        .nodes
        .iter()
        .find(|node| node.member_id == MemberId::new(2))
        .expect("peer in membership view");
    assert_eq!(peer_node.member_class, MemberClass::Voter);
    assert_eq!(peer_node.failure_domain, 2);

    drop(node);
    peer.join().expect("membership peer thread");
}

#[test]
fn storage_node_membership_loop_accepts_inbound_peer() {
    let node2_config = StorageNodeConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_port()),
        node_id: 2,
        authority: None,
        store_paths: scratch_store_paths("membership-loop-node2", 1),
        fs_root: None,
        root_auth_key: None,
        member_class: Some(MemberClass::Voter),
        failure_domain: Some(2),
        membership_bind_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
        membership_peers: vec![],
        replica_peers: vec![],
        pool_device_path: None,
        pool_lock_dir: None,
        node_identity: None,
        ready_file: None,
        drain_timeout_secs: 30,
        cluster_lease_config: None,
        membership_checkpoint_dir: None,
        rdma: false,
        carrier_policy: None,
    };
    let node2 = StorageNode::start(node2_config).expect("start node2");
    let node2_membership_addr = node2
        .membership_transport_handle()
        .expect("node2 membership transport")
        .lock()
        .unwrap()
        .local_addr()
        .expect("node2 membership addr");

    let node1_config = StorageNodeConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_port()),
        node_id: 1,
        authority: None,
        store_paths: scratch_store_paths("membership-loop-node1", 1),
        fs_root: None,
        root_auth_key: None,
        member_class: Some(MemberClass::Voter),
        failure_domain: Some(1),
        membership_bind_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
        membership_peers: vec![MembershipPeerConfig {
            node_id: 2,
            addr: node2_membership_addr
                .as_socket_addr()
                .expect("TCP transport addr"),
            member_class: MemberClass::Voter,
            failure_domain: 2,
        }],
        replica_peers: vec![],
        pool_device_path: None,
        pool_lock_dir: None,
        node_identity: None,
        ready_file: None,
        drain_timeout_secs: 30,
        cluster_lease_config: None,
        membership_checkpoint_dir: None,
        rdma: false,
        carrier_policy: None,
    };
    let node1 = StorageNode::start(node1_config).expect("start node1");

    let node2_observed_node1 = (0..40).any(|_| {
        if node2
            .membership_view()
            .nodes
            .iter()
            .any(|node| node.member_id == MemberId::new(1))
        {
            true
        } else {
            thread::sleep(Duration::from_millis(25));
            false
        }
    });

    assert!(
        node2_observed_node1,
        "node2 background membership loop should accept and register node1"
    );

    drop(node1);
    drop(node2);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn put_and_get_roundtrip() {
    let server = TestServer::spawn(1, scratch_store_paths("putget", 1));

    let key = b"greeting";
    let value = b"hello world";

    // PUT
    let resp = client::request(
        2, // client node_id
        1, // server node_id
        server.addr,
        Frame::Put {
            key: key.to_vec(),
            value: value.to_vec(),
        },
        false,
    )
    .expect("put request");
    assert_eq!(resp, Frame::Ok, "expected Ok, got {resp:?}");

    // GET — must return the value
    let resp = client::request(2, 1, server.addr, Frame::Get { key: key.to_vec() }, false)
        .expect("get request");
    assert_eq!(
        resp,
        Frame::GetResponse {
            value: value.to_vec()
        },
        "expected GetResponse, got {resp:?}"
    );
}

#[test]
fn get_missing_key_returns_error() {
    let server = TestServer::spawn(1, scratch_store_paths("getmiss", 1));

    let resp = client::request(
        2,
        1,
        server.addr,
        Frame::Get {
            key: b"nope".to_vec(),
        },
        false,
    )
    .expect("get request");
    assert!(
        matches!(resp, Frame::Error { .. }),
        "expected Error, got {resp:?}"
    );
}

#[test]
fn delete_roundtrip() {
    let server = TestServer::spawn(1, scratch_store_paths("del", 1));

    let key = b"ephemeral";

    // PUT first
    let resp = client::request(
        2,
        1,
        server.addr,
        Frame::Put {
            key: key.to_vec(),
            value: b"x".to_vec(),
        },
        false,
    )
    .expect("put");
    assert_eq!(resp, Frame::Ok);

    // DELETE
    let resp = client::request(
        2,
        1,
        server.addr,
        Frame::Delete { key: key.to_vec() },
        false,
    )
    .expect("del");
    assert_eq!(resp, Frame::DeleteResponse { existed: true });

    // DELETE again — should report not existed
    let resp = client::request(
        2,
        1,
        server.addr,
        Frame::Delete { key: key.to_vec() },
        false,
    )
    .expect("del");
    assert_eq!(resp, Frame::DeleteResponse { existed: false });
}

#[test]
fn list_keys() {
    let server = TestServer::spawn(1, scratch_store_paths("list", 1));

    // PUT a few keys
    for k in &["alpha", "beta", "gamma"] {
        let resp = client::request(
            2,
            1,
            server.addr,
            Frame::Put {
                key: k.as_bytes().to_vec(),
                value: b"v".to_vec(),
            },
            false,
        )
        .expect("put");
        assert_eq!(resp, Frame::Ok);
    }

    let resp = client::request(2, 1, server.addr, Frame::List, false).expect("list");
    match resp {
        Frame::ListResponse { keys } => {
            let mut sorted: Vec<Vec<u8>> = keys
                .iter()
                .map(|k| k[..32].to_vec()) // ObjectKey is 32 bytes
                .collect();
            sorted.sort();
            assert_eq!(sorted.len(), 3, "expected 3 keys, got {keys:?}");
        }
        other => panic!("expected ListResponse, got {other:?}"),
    }
}

#[test]
fn stats_returns_json() {
    let server = TestServer::spawn(1, scratch_store_paths("stats", 1));

    let resp = client::request(2, 1, server.addr, Frame::Stats, false).expect("stats");
    match resp {
        Frame::StatsResponse { json } => {
            assert!(
                json.contains("object_count"),
                "missing object_count in: {json}"
            );
            assert!(
                json.contains("bytes_written"),
                "missing bytes_written in: {json}"
            );
        }
        other => panic!("expected StatsResponse, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// SEND / RECEIVE end-to-end via server transport
// ---------------------------------------------------------------------------

use tidefs_local_filesystem::{self as vfs, ChangedRecordExport, RootAuthenticationKey};
use tidefs_local_object_store::StoreOptions;

#[test]
fn send_receive_full_roundtrip_via_server() {
    let auth_key = RootAuthenticationKey::demo_key();

    // ── Phase 1: create a source filesystem with data ──
    let source_dir = tempfile::tempdir().expect("source tempdir");
    let mut source = vfs::LocalFileSystem::open_with_root_authentication_key(
        source_dir.path(),
        StoreOptions::default(),
        auth_key,
    )
    .expect("open source");

    source.create_dir("/data", 0o755).expect("mkdir /data");

    let file1_data: Vec<u8> = vec![0xAB; 4096];
    source
        .create_file("/data/file1.bin", 0o644)
        .expect("create file1");
    source
        .write_file("/data/file1.bin", 0, &file1_data)
        .expect("write file1");

    let file2_data: Vec<u8> = vec![0xCD; 8192];
    source
        .create_file("/data/file2.bin", 0o644)
        .expect("create file2");
    source
        .write_file("/data/file2.bin", 0, &file2_data)
        .expect("write file2");

    source.sync_all().expect("sync source");
    drop(source);

    // ── Phase 2: spawn server pointing at the source, send full export ──
    let source_store = scratch_store_paths("sendrecv-src", 1);
    let port = pick_port();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

    let config = StorageNodeConfig {
        bind_addr: addr,
        node_id: 1,
        authority: None,
        store_paths: source_store,
        fs_root: Some(source_dir.path().to_path_buf()),
        root_auth_key: Some(auth_key),
        member_class: None,
        failure_domain: None,
        membership_bind_addr: None,
        membership_peers: vec![],
        replica_peers: vec![],
        pool_device_path: None,
        pool_lock_dir: None,
        node_identity: None,
        ready_file: None,
        drain_timeout_secs: 30,
        cluster_lease_config: None,
        membership_checkpoint_dir: None,
        rdma: false,
        carrier_policy: None,
    };

    let mut node = StorageNode::start(config).expect("start sendrecv server");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);

    let handle = thread::spawn(move || {
        while !stop_clone.load(Ordering::Relaxed) {
            match node.serve_one() {
                Ok(()) => {}
                Err(e) => {
                    if !stop_clone.load(Ordering::Relaxed) {
                        eprintln!("[sendrecv-server] serve_one: {e}");
                    }
                }
            }
        }
        drop(node);
    });
    thread::sleep(Duration::from_millis(50));

    let resp =
        client::request(2, 1, addr, Frame::Send { key: vec![] }, false).expect("send request");
    let export = match resp {
        Frame::SendResponse { export } => export,
        Frame::Error { message } => panic!("send error: {message}"),
        other => panic!("expected SendResponse, got {other:?}"),
    };
    assert!(!export.is_empty(), "export should not be empty");

    // Shut down server.
    stop.store(true, Ordering::Relaxed);
    drop(handle);

    // ── Phase 3: receive into a fresh (non-existent) target directory ──
    let target_parent = tempfile::tempdir().expect("target parent");
    let target_path = target_parent.path().join("target-fs");

    let decoded = ChangedRecordExport::decode(&export).expect("decode export");
    let report =
        vfs::LocalFileSystem::receive_changed_records_into_empty_root_with_root_authentication_key(
            &target_path,
            StoreOptions::default(),
            &decoded,
            auth_key,
        )
        .expect("receive into target");

    assert!(
        report.imported_records > 0,
        "should import records, got {}",
        report.imported_records
    );
    assert!(
        report.imported_payload_bytes > 0,
        "should import payload, got {}",
        report.imported_payload_bytes
    );
    // stream_version is 1 for full exports, 2 for incremental.
    assert_eq!(report.stream_version, 1);
    assert!(report.staging_validated_before_publish);
    assert!(report.destination_root_reauthentication);

    // ── Phase 4: verify received data matches source ──
    let target = vfs::LocalFileSystem::open_with_root_authentication_key(
        &target_path,
        StoreOptions::default(),
        auth_key,
    )
    .expect("open target fs");

    assert_eq!(
        target.read_file("/data/file1.bin").expect("read file1"),
        file1_data
    );
    assert_eq!(
        target.read_file("/data/file2.bin").expect("read file2"),
        file2_data
    );
}

#[test]
fn health_check_returns_not_imported_when_no_pool_configured() {
    let server = TestServer::spawn(1, scratch_store_paths("health", 1));

    // Send a HealthCheck frame and verify response.
    let resp = client::request(2, 1, server.addr, Frame::HealthCheck, false)
        .expect("health check request");
    match resp {
        Frame::HealthCheckResponse {
            node_identity,
            pool_state,
            uptime_secs,
            ..
        } => {
            assert!(
                node_identity.contains("node-1") || node_identity.contains("node-"),
                "node_identity should contain node id: {node_identity}"
            );
            // No pool_device_path configured, so pool is not-imported.
            assert_eq!(pool_state, "not-imported");
            // Uptime should be small (test runs quickly).
            assert!(uptime_secs < 10, "uptime too large: {uptime_secs}");
        }
        other => panic!("expected HealthCheckResponse, got {other:?}"),
    }
}

#[test]
fn health_check_roundtrip_via_client() {
    let server = TestServer::spawn(1, scratch_store_paths("health2", 1));

    let resp = client::request(2, 1, server.addr, Frame::HealthCheck, false)
        .expect("health check request");

    // Encode/decode roundtrip the response.
    let encoded = tidefs_storage_node::protocol::encode(&resp);
    let decoded = tidefs_storage_node::protocol::decode(&encoded);
    assert_eq!(decoded, Some(resp));
}

// ---------------------------------------------------------------------------
// Health check with pool device integration test
// ---------------------------------------------------------------------------

use std::io::{Seek, SeekFrom, Write};
use tidefs_types_pool_label_core::{
    encode_label, seal_label, PoolLabelV1, POOL_LABEL_SIZE, POOL_LABEL_V1_EXT_WIRE_SIZE,
};

/// Write a valid TideFS pool label to a file, padded to POOL_LABEL_SIZE.
fn write_pool_label_to_file(file: &mut std::fs::File, pool_name: &str) {
    let label = PoolLabelV1::new([0xAAu8; 16], [0x01u8; 16], pool_name);
    let sealed = seal_label(label).expect("seal pool label");
    let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
    encode_label(&sealed, &mut buf).expect("encode pool label");
    file.seek(SeekFrom::Start(0)).expect("seek");
    file.write_all(&buf).expect("write label");
    let padding = vec![0u8; POOL_LABEL_SIZE - POOL_LABEL_V1_EXT_WIRE_SIZE];
    file.write_all(&padding).expect("write padding");
    file.flush().expect("flush");
}

#[test]
fn health_check_returns_imported_when_pool_imported() {
    // Create a temp file with a valid pool label.
    let dir = tempfile::tempdir().expect("tempdir");
    let pool_path = dir.path().join("test-pool-device0");
    {
        let mut f = std::fs::File::create(&pool_path).expect("create pool file");
        write_pool_label_to_file(&mut f, "healthpool");
    }

    let lock_dir = dir.path().join("locks");
    let port = pick_port();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

    let config = StorageNodeConfig {
        bind_addr: addr,
        node_id: 1,
        authority: None,
        store_paths: scratch_store_paths("health-imported", 1),
        fs_root: None,
        root_auth_key: None,
        member_class: None,
        failure_domain: None,
        membership_bind_addr: None,
        membership_peers: vec![],
        replica_peers: vec![],
        pool_device_path: Some(pool_path),
        pool_lock_dir: Some(lock_dir),
        node_identity: Some("health-node-1".into()),
        ready_file: None,
        drain_timeout_secs: 30,
        cluster_lease_config: None,
        membership_checkpoint_dir: None,
        rdma: false,
        carrier_policy: None,
    };

    let mut node = StorageNode::start(config).expect("start server");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);

    let handle = thread::spawn(move || {
        while !stop_clone.load(Ordering::Relaxed) {
            match node.serve_one() {
                Ok(()) => {}
                Err(e) => {
                    if !stop_clone.load(Ordering::Relaxed) {
                        eprintln!("[health-pool-server] serve_one: {e}");
                    }
                }
            }
        }
        drop(node);
    });
    thread::sleep(Duration::from_millis(50));

    let resp =
        client::request(2, 1, addr, Frame::HealthCheck, false).expect("health check request");
    match resp {
        Frame::HealthCheckResponse {
            node_identity,
            pool_state,
            uptime_secs,
            ..
        } => {
            assert_eq!(node_identity, "health-node-1");
            assert_eq!(pool_state, "imported");
            assert!(uptime_secs < 10, "uptime too large: {uptime_secs}");
        }
        other => panic!("expected HealthCheckResponse, got {other:?}"),
    }

    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
}

#[test]
fn live_backend_health_check_discloses_tcp_backend() {
    // Start a storage node with a live TCP backend authority.
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_port());
    let store_paths = scratch_store_paths("live-backend", 1);

    let authority = tidefs_storage_node::authority_spine::RuntimeAuthority::build(
        tidefs_membership_live::BackendDisclosure::Tcp(bind_addr),
        1u64,
        Some(MemberClass::Voter),
        Some(1u64),
        1u8,
    )
    .expect("build authority");

    let config = StorageNodeConfig {
        bind_addr,
        node_id: 1,
        store_paths,
        fs_root: None,
        root_auth_key: None,
        member_class: None,
        failure_domain: None,
        membership_bind_addr: None,
        membership_peers: vec![],
        replica_peers: vec![],
        pool_device_path: None,
        pool_lock_dir: None,
        node_identity: Some("live-node-1".into()),
        authority: Some(authority),
        ready_file: None,
        drain_timeout_secs: 30,
        cluster_lease_config: None,
        membership_checkpoint_dir: None,
        rdma: false,
        carrier_policy: None,
    };

    let mut node = StorageNode::start(config).expect("start live server");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);

    let handle = thread::spawn(move || {
        while !stop_clone.load(Ordering::Relaxed) {
            match node.serve_one() {
                Ok(()) => {}
                Err(e) => {
                    if !stop_clone.load(Ordering::Relaxed) {
                        eprintln!("[live-test] serve_one: {e}");
                    }
                }
            }
        }
    });

    thread::sleep(Duration::from_millis(50));

    // Health check should disclose the TCP backend
    let resp =
        client::request(2, 1, bind_addr, Frame::HealthCheck, false).expect("health check request");
    match resp {
        Frame::HealthCheckResponse {
            node_identity,
            pool_state,
            uptime_secs: _,
            backend,
            ..
        } => {
            assert_eq!(node_identity, "live-node-1");
            assert_eq!(pool_state, "not-imported");
            assert!(
                backend.contains("tcp"),
                "backend should disclose TCP: {backend}"
            );
        }
        other => panic!("expected HealthCheckResponse, got {other:?}"),
    }

    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
}

#[test]
fn live_backend_put_get_stats_discloses_transport_fields() {
    // Start a storage node with a live TCP backend (TransportReplicatedStore
    // with no replicas). PUT/GET through the client verifies the data path
    // works through the transport-backed store, and STATS includes backend
    // disclosure plus transport-backed fields (committed_writes, bytes_written,
    // object_count, degraded_writes, degraded_reads).

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_port());
    let store_paths = scratch_store_paths("live-putget", 1);

    let authority = tidefs_storage_node::authority_spine::RuntimeAuthority::build(
        tidefs_membership_live::BackendDisclosure::Tcp(addr),
        1u64,
        Some(MemberClass::Voter),
        Some(1u64),
        1u8,
    )
    .expect("build authority");

    let config = StorageNodeConfig {
        bind_addr: addr,
        node_id: 1,
        store_paths,
        fs_root: None,
        root_auth_key: None,
        member_class: None,
        failure_domain: None,
        membership_bind_addr: None,
        membership_peers: vec![],
        replica_peers: vec![],
        pool_device_path: None,
        pool_lock_dir: None,
        node_identity: Some("live-putget".into()),
        authority: Some(authority),
        ready_file: None,
        drain_timeout_secs: 30,
        cluster_lease_config: None,
        membership_checkpoint_dir: None,
        rdma: false,
        carrier_policy: None,
    };

    let mut node = StorageNode::start(config).expect("start live server");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        while !stop_clone.load(Ordering::Relaxed) {
            match node.serve_one() {
                Ok(()) => {}
                Err(e) => {
                    if !stop_clone.load(Ordering::Relaxed) {
                        eprintln!("[live-putget] serve_one: {e}");
                    }
                }
            }
        }
    });

    thread::sleep(Duration::from_millis(50));

    // ── PUT ─────────────────────────────────────────────────────────
    let key = b"live-key";
    let value = b"transport-backed-value";
    let resp = client::request(
        2,
        1,
        addr,
        Frame::Put {
            key: key.to_vec(),
            value: value.to_vec(),
        },
        false,
    )
    .expect("put request");
    assert!(
        matches!(resp, Frame::Ok),
        "PUT should return Ok, got {resp:?}"
    );

    // ── GET ─────────────────────────────────────────────────────────
    let resp =
        client::request(2, 1, addr, Frame::Get { key: key.to_vec() }, false).expect("get request");
    match resp {
        Frame::GetResponse { value: got } => {
            assert_eq!(got, value, "GET should return the put value");
        }
        Frame::Error { message } => {
            panic!("GET returned error: {message}");
        }
        other => panic!("expected GetResponse, got {other:?}"),
    }

    // ── STATS: verify backend disclosure and transport fields ────────
    let resp = client::request(2, 1, addr, Frame::Stats, false).expect("stats request");
    match resp {
        Frame::StatsResponse { json } => {
            let stats: serde_json::Value = serde_json::from_str(&json).expect("stats JSON parse");
            // Backend disclosure
            assert!(
                stats["backend"].as_str().is_some_and(|b| b.contains("tcp")),
                "stats backend should disclose TCP: {json}"
            );
            // Transport-backed fields populated by TransportReplicatedStore
            assert!(
                stats.get("object_count").is_some(),
                "stats should have object_count: {json}"
            );
            assert!(
                stats.get("committed_writes").is_some(),
                "stats should have committed_writes: {json}"
            );
            assert!(
                stats.get("bytes_written").is_some(),
                "stats should have bytes_written: {json}"
            );
        }
        other => panic!("expected StatsResponse, got {other:?}"),
    }

    // ── DELETE ──────────────────────────────────────────────────────
    let resp = client::request(2, 1, addr, Frame::Delete { key: key.to_vec() }, false)
        .expect("delete request");
    match resp {
        Frame::DeleteResponse { existed } => {
            assert!(existed, "DELETE should report existed=true");
        }
        Frame::Error { message } => {
            panic!("DELETE returned error: {message}");
        }
        other => panic!("expected DeleteResponse, got {other:?}"),
    }

    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
}

#[test]
fn config_file_live_backend_uses_transport_store() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_port());
    let dir = tempfile::tempdir().expect("tempdir");
    let store_path = dir.path().join("store0");
    let config_path = dir.path().join("node.json");
    std::fs::write(
        &config_path,
        format!(
            r#"{{
  "node_id": 1,
  "bind": "{addr}",
  "store_paths": ["{}"],
  "member_class": "voter",
  "failure_domain": 1,
  "replication_factor": 1
}}"#,
            store_path.display()
        ),
    )
    .expect("write config");

    let config = StorageNodeConfig::from_json_file(&config_path).expect("load config");
    let authority = config
        .authority
        .as_ref()
        .expect("config should preserve authority");
    assert!(authority.is_live());

    let mut node = StorageNode::start(config).expect("start config-backed live server");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        while !stop_clone.load(Ordering::Relaxed) {
            match node.serve_one() {
                Ok(()) => {}
                Err(e) => {
                    if !stop_clone.load(Ordering::Relaxed) {
                        eprintln!("[config-live-putget] serve_one: {e}");
                    }
                }
            }
        }
    });

    thread::sleep(Duration::from_millis(50));

    let key = b"config-live-key";
    let value = b"config-live-value";
    let resp = client::request(
        2,
        1,
        addr,
        Frame::Put {
            key: key.to_vec(),
            value: value.to_vec(),
        },
        false,
    )
    .expect("put request");
    assert!(matches!(resp, Frame::Ok), "PUT should return Ok: {resp:?}");

    let resp = client::request(2, 1, addr, Frame::Stats, false).expect("stats request");
    match resp {
        Frame::StatsResponse { json } => {
            let stats: serde_json::Value = serde_json::from_str(&json).expect("stats JSON parse");
            assert!(
                stats["backend"].as_str().is_some_and(|b| b.contains("tcp")),
                "stats backend should disclose TCP: {json}"
            );
            assert!(
                stats.get("failed_writes").is_some(),
                "transport-backed stats should include failed_writes: {json}"
            );
            assert!(
                stats.get("degraded_reads").is_some(),
                "transport-backed stats should include degraded_reads: {json}"
            );
            assert!(
                stats.get("replica_healthy").is_none(),
                "config live path should not expose local-store replica_healthy: {json}"
            );
        }
        other => panic!("expected StatsResponse, got {other:?}"),
    }

    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
}

// ---------------------------------------------------------------------------
// Multi-process distributed replication: transport-backed replication data path
// ---------------------------------------------------------------------------
//
// Proves that a storage-node with a live TCP backend handles inbound
// ReplicationMessage protocol from a connected TransportReplicatedStore peer.
// This is the missing inbound half of the transport-backed replication path.

#[test]
fn live_backend_replication_message_roundtrip() {
    use tidefs_transport::{
        recv_replication_msg, send_replication_msg, NodeInfo, ReplicationMessage,
        SessionCloseReason, Transport, TransportAddr,
    };

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_port());
    let store_paths = scratch_store_paths("live-repl-msg", 1);

    let authority = tidefs_storage_node::authority_spine::RuntimeAuthority::build(
        tidefs_membership_live::BackendDisclosure::Tcp(addr),
        1u64,
        Some(MemberClass::Voter),
        Some(1u64),
        1u8,
    )
    .expect("build authority");

    let config = StorageNodeConfig {
        bind_addr: addr,
        node_id: 1,
        store_paths,
        fs_root: None,
        root_auth_key: None,
        member_class: None,
        failure_domain: None,
        membership_bind_addr: None,
        membership_peers: vec![],
        replica_peers: vec![],
        pool_device_path: None,
        pool_lock_dir: None,
        node_identity: Some("repl-node-1".into()),
        authority: Some(authority),
        ready_file: None,
        drain_timeout_secs: 30,
        cluster_lease_config: None,
        membership_checkpoint_dir: None,
        rdma: false,
        carrier_policy: None,
    };

    let mut node = StorageNode::start(config).expect("start storage node");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        while !stop_clone.load(Ordering::Relaxed) {
            match node.serve_one() {
                Ok(()) => {}
                Err(e) => {
                    if !stop_clone.load(Ordering::Relaxed) {
                        eprintln!("[repl-test] serve_one: {e}");
                    }
                }
            }
        }
    });

    thread::sleep(Duration::from_millis(50));

    // Peer node (node_id=2) connects to the storage-node and sends
    // ReplicationMessage protocol frames to exercise the inbound handler.
    let mut peer = Transport::new(2);
    peer.add_node(NodeInfo::new(1, vec![TransportAddr::Tcp(addr)], 0));

    let sid = peer.connect(1).expect("peer connect");
    peer.perform_handshake(sid).expect("peer handshake");

    // ── Put via ReplicationMessage ──
    let put_msg = ReplicationMessage::Put {
        name: "repl-obj-1".to_string(),
        payload: b"distributed-data".to_vec(),
    };
    send_replication_msg(&mut peer, sid, &put_msg).expect("send put");
    let ack = recv_replication_msg(&mut peer, sid).expect("recv ack");
    assert!(
        matches!(&ack, ReplicationMessage::Ack { success: true, .. }),
        "expected successful Ack, got {ack:?}"
    );

    // ── Get via ReplicationMessage ──
    let get_msg = ReplicationMessage::Get {
        name: "repl-obj-1".to_string(),
    };
    send_replication_msg(&mut peer, sid, &get_msg).expect("send get");
    let get_resp = recv_replication_msg(&mut peer, sid).expect("recv get_response");
    match &get_resp {
        ReplicationMessage::GetResponse { found, payload } => {
            assert!(found, "object should be found");
            assert_eq!(payload, b"distributed-data", "payload should match");
        }
        other => panic!("expected GetResponse, got {other:?}"),
    }

    // ── Delete via ReplicationMessage ──
    let del_msg = ReplicationMessage::Delete {
        name: "repl-obj-1".to_string(),
        generation: 0,
    };
    send_replication_msg(&mut peer, sid, &del_msg).expect("send delete");
    let del_ack = recv_replication_msg(&mut peer, sid).expect("recv delete ack");
    assert!(
        matches!(
            &del_ack,
            ReplicationMessage::DeleteAck { deleted: true, .. }
        ),
        "expected DeleteAck with deleted=true, got {del_ack:?}"
    );

    // ── Get after delete should return not found ──
    let get_msg2 = ReplicationMessage::Get {
        name: "repl-obj-1".to_string(),
    };
    send_replication_msg(&mut peer, sid, &get_msg2).expect("send get after delete");
    let get_resp2 = recv_replication_msg(&mut peer, sid).expect("recv get_response after delete");
    match &get_resp2 {
        ReplicationMessage::GetResponse { found, .. } => {
            assert!(!found, "object should not be found after delete");
        }
        other => panic!("expected GetResponse, got {other:?}"),
    }

    // ── Clean up ──
    peer.close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close peer session");
    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
}

// ---------------------------------------------------------------------------
// Cross-verification: Frame protocol and ReplicationMessage protocol share
// the same underlying store. Data written via one path is readable via the other.
// ---------------------------------------------------------------------------

#[test]
fn live_backend_frame_and_replication_protocol_share_store() {
    use tidefs_transport::{
        recv_replication_msg, send_replication_msg, NodeInfo, ReplicationMessage,
        SessionCloseReason, Transport, TransportAddr,
    };

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_port());
    let store_paths = scratch_store_paths("cross-verify", 1);

    let authority = tidefs_storage_node::authority_spine::RuntimeAuthority::build(
        tidefs_membership_live::BackendDisclosure::Tcp(addr),
        1u64,
        Some(MemberClass::Voter),
        Some(1u64),
        1u8,
    )
    .expect("build authority");

    let config = StorageNodeConfig {
        bind_addr: addr,
        node_id: 1,
        store_paths,
        fs_root: None,
        root_auth_key: None,
        member_class: None,
        failure_domain: None,
        membership_bind_addr: None,
        membership_peers: vec![],
        replica_peers: vec![],
        pool_device_path: None,
        pool_lock_dir: None,
        node_identity: Some("cross-verify".into()),
        authority: Some(authority),
        ready_file: None,
        drain_timeout_secs: 30,
        cluster_lease_config: None,
        membership_checkpoint_dir: None,
        rdma: false,
        carrier_policy: None,
    };

    let mut node = StorageNode::start(config).expect("start storage node");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        while !stop_clone.load(Ordering::Relaxed) {
            match node.serve_one() {
                Ok(()) => {}
                Err(e) => {
                    if !stop_clone.load(Ordering::Relaxed) {
                        eprintln!("[cross-verify] serve_one: {e}");
                    }
                }
            }
        }
    });

    thread::sleep(Duration::from_millis(50));

    // ── Test 1: Frame PUT → ReplicationMessage GET ───────────────────
    let frame_key = b"frame-put-repl-get";
    let frame_value = b"via-frame-protocol";
    let resp = client::request(
        2,
        1,
        addr,
        Frame::Put {
            key: frame_key.to_vec(),
            value: frame_value.to_vec(),
        },
        false,
    )
    .expect("frame put");
    assert!(matches!(resp, Frame::Ok), "Frame PUT should succeed");

    // Read back via ReplicationMessage
    let mut peer = Transport::new(3);
    peer.add_node(NodeInfo::new(1, vec![TransportAddr::Tcp(addr)], 0));
    let sid = peer.connect(1).expect("peer connect");
    peer.perform_handshake(sid).expect("peer handshake");

    let get_msg = ReplicationMessage::Get {
        name: String::from_utf8_lossy(frame_key).to_string(),
    };
    send_replication_msg(&mut peer, sid, &get_msg).expect("send repl get");
    let get_resp = recv_replication_msg(&mut peer, sid).expect("recv repl get_response");
    match &get_resp {
        ReplicationMessage::GetResponse { found, payload } => {
            assert!(
                found,
                "Frame-written object should be readable via ReplicationMessage"
            );
            assert_eq!(
                payload, frame_value,
                "payload should match across protocols"
            );
        }
        other => panic!("expected GetResponse, got {other:?}"),
    }

    peer.close_session(sid, SessionCloseReason::LocalShutdown)
        .expect("close peer session");

    // ── Test 2: ReplicationMessage PUT → Frame GET ───────────────────
    let repl_key = b"repl-put-frame-get";
    let repl_value = b"via-replication-message";
    let mut peer2 = Transport::new(4);
    peer2.add_node(NodeInfo::new(1, vec![TransportAddr::Tcp(addr)], 0));
    let sid2 = peer2.connect(1).expect("peer2 connect");
    peer2.perform_handshake(sid2).expect("peer2 handshake");

    let put_msg = ReplicationMessage::Put {
        name: String::from_utf8_lossy(repl_key).to_string(),
        payload: repl_value.to_vec(),
    };
    send_replication_msg(&mut peer2, sid2, &put_msg).expect("send repl put");
    let ack = recv_replication_msg(&mut peer2, sid2).expect("recv repl ack");
    assert!(
        matches!(&ack, ReplicationMessage::Ack { success: true, .. }),
        "ReplicationMessage PUT should succeed"
    );

    peer2
        .close_session(sid2, SessionCloseReason::LocalShutdown)
        .expect("close peer2 session");

    // Read back via Frame protocol
    let resp = client::request(
        2,
        1,
        addr,
        Frame::Get {
            key: repl_key.to_vec(),
        },
        false,
    )
    .expect("frame get");
    match resp {
        Frame::GetResponse { value } => {
            assert_eq!(
                value, repl_value,
                "ReplicationMessage-written object should be readable via Frame protocol"
            );
        }
        other => panic!("expected GetResponse, got {other:?}"),
    }

    // ── Clean up ──
    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
}

// ---------------------------------------------------------------------------
// Multi-node distributed fan-out: Frame operations route through replica
// quorum fan-out, proving remote receipt, readback, and delete propagation.
// ---------------------------------------------------------------------------
//
// Starts two storage-node instances (different ports, isolated store paths).
// The primary connects to the replica as a membership peer via
// TransportReplicatedStore. Client Frame PUT/GET/DELETE issued to the primary
// are fanned out to the replica. The test verifies remote receipt/readback and
// delete propagation via Frame GET on the replica, then verifies quorum
// accounting via STATS.
//
// Key: the replica retains the data, proving the primary's fan-out path works
// end-to-end through TransportReplicatedStore. This closes the gap where
// Frame handlers used to call *_local for TransportBacked instead of
// *_named fan-out methods.

#[test]
fn live_backend_frame_fanout_to_replica_readback_and_delete() {
    use std::net::TcpListener;

    // ── Ports and paths ─────────────────────────────────────────────
    let primary_port = {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind primary port");
        l.local_addr().expect("local_addr").port()
    };
    let replica_port = {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind replica port");
        l.local_addr().expect("local_addr").port()
    };
    let replica_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), replica_port);
    let primary_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), primary_port);

    let replica_paths = scratch_store_paths("fanout-replica", 1);
    let primary_paths = scratch_store_paths("fanout-primary", 1);

    // ── Replica node (starts first so primary can connect) ──────────
    let replica_authority = tidefs_storage_node::authority_spine::RuntimeAuthority::build(
        tidefs_membership_live::BackendDisclosure::Tcp(replica_addr),
        20u64,
        Some(MemberClass::Voter),
        Some(20u64),
        2u8, // rf=2 → quorum=2, total_targets=2
    )
    .expect("build replica authority");

    let replica_config = StorageNodeConfig {
        bind_addr: replica_addr,
        node_id: 20,
        store_paths: replica_paths,
        fs_root: None,
        root_auth_key: None,
        member_class: None,
        failure_domain: None,
        membership_bind_addr: None,
        membership_peers: vec![], // replica has no peers
        replica_peers: vec![],
        pool_device_path: None,
        pool_lock_dir: None,
        node_identity: Some("fanout-replica".into()),
        authority: Some(replica_authority),
        ready_file: None,
        drain_timeout_secs: 30,
        cluster_lease_config: None,
        membership_checkpoint_dir: None,
        rdma: false,
        carrier_policy: None,
    };

    let mut replica_node = StorageNode::start(replica_config).expect("start replica");
    let replica_stop = Arc::new(AtomicBool::new(false));
    let replica_stop_clone = Arc::clone(&replica_stop);
    let replica_handle = thread::spawn(move || {
        while !replica_stop_clone.load(Ordering::Relaxed) {
            match replica_node.serve_one() {
                Ok(()) => {}
                Err(e) => {
                    if !replica_stop_clone.load(Ordering::Relaxed) {
                        eprintln!("[fanout-replica] serve_one: {e}");
                    }
                }
            }
        }
    });

    // Give the replica time to start listening
    thread::sleep(Duration::from_millis(200));

    // ── Primary node (connects to replica during start) ─────────────
    let primary_authority = tidefs_storage_node::authority_spine::RuntimeAuthority::build(
        tidefs_membership_live::BackendDisclosure::Tcp(primary_addr),
        10u64,
        Some(MemberClass::Voter),
        Some(10u64),
        2u8, // rf=2, write_quorum=(2/2)+1=2, total_targets=1+1=2
    )
    .expect("build primary authority");

    let primary_config = StorageNodeConfig {
        bind_addr: primary_addr,
        node_id: 10,
        store_paths: primary_paths,
        fs_root: None,
        root_auth_key: None,
        member_class: None,
        failure_domain: None,
        membership_bind_addr: None,
        membership_peers: vec![MembershipPeerConfig {
            node_id: 20,
            addr: replica_addr,
            member_class: MemberClass::Voter,
            failure_domain: 20,
        }],
        replica_peers: vec![],
        pool_device_path: None,
        pool_lock_dir: None,
        node_identity: Some("fanout-primary".into()),
        authority: Some(primary_authority),
        ready_file: None,
        drain_timeout_secs: 30,
        cluster_lease_config: None,
        membership_checkpoint_dir: None,
        rdma: false,
        carrier_policy: None,
    };

    // start() blocks until connect_replica to the replica completes
    let mut primary_node = StorageNode::start(primary_config).expect("start primary");
    let primary_stop = Arc::new(AtomicBool::new(false));
    let primary_stop_clone = Arc::clone(&primary_stop);
    let primary_handle = thread::spawn(move || {
        while !primary_stop_clone.load(Ordering::Relaxed) {
            match primary_node.serve_one() {
                Ok(()) => {}
                Err(e) => {
                    if !primary_stop_clone.load(Ordering::Relaxed) {
                        eprintln!("[fanout-primary] serve_one: {e}");
                    }
                }
            }
        }
    });

    // Give both nodes time to stabilise sessions
    thread::sleep(Duration::from_millis(200));

    // ── PUT via Frame to primary, verify on replica ─────────────────
    let key = b"fanout-key";
    let value = b"fanout-value-from-client";

    let resp = client::request(
        99,
        10,
        primary_addr,
        Frame::Put {
            key: key.to_vec(),
            value: value.to_vec(),
        },
        false,
    )
    .expect("put request to primary");
    assert!(
        matches!(resp, Frame::Ok),
        "primary PUT should return Ok (fan-out to replica), got {resp:?}"
    );

    // Give replication a moment to propagate
    thread::sleep(Duration::from_millis(50));

    // Read back from replica via Frame GET (proves fan-out worked)
    let resp = client::request(
        98,
        20,
        replica_addr,
        Frame::Get { key: key.to_vec() },
        false,
    )
    .expect("get request to replica");
    match resp {
        Frame::GetResponse { value: got } => {
            assert_eq!(got, value, "replica GET should return the fan-out value");
        }
        Frame::Error { message } => {
            panic!("replica GET returned error: {message}");
        }
        other => panic!("expected GetResponse from replica, got {other:?}"),
    }

    // ── GET via Frame to primary (local-primary path) ───────────────
    let resp = client::request(
        97,
        10,
        primary_addr,
        Frame::Get { key: key.to_vec() },
        false,
    )
    .expect("get request to primary");
    match resp {
        Frame::GetResponse { value: got } => {
            assert_eq!(got, value, "primary GET should return the local value");
        }
        Frame::Error { message } => {
            panic!("primary GET returned error: {message}");
        }
        other => panic!("expected GetResponse from primary, got {other:?}"),
    }

    // ── STATS on primary: verify quorum accounting ─────────────────
    let resp = client::request(96, 10, primary_addr, Frame::Stats, false).expect("stats request");
    match resp {
        Frame::StatsResponse { json } => {
            let stats: serde_json::Value = serde_json::from_str(&json).expect("stats JSON parse");
            let backend = stats["backend"].as_str().unwrap_or("");
            assert!(
                backend.contains("tcp"),
                "stats backend should disclose TCP: {json}"
            );
            assert!(
                stats.get("object_count").is_some(),
                "stats should have object_count"
            );
            assert!(
                stats.get("committed_writes").is_some(),
                "stats should have committed_writes"
            );
            let committed: i64 = stats["committed_writes"].as_i64().unwrap_or(-1);
            assert!(
                committed >= 1,
                "should have at least 1 committed write, got {committed}: {json}"
            );
            eprintln!("[fanout-test] primary stats (post-PUT): {json}");
        }
        other => panic!("expected StatsResponse from primary, got {other:?}"),
    }

    // ── DELETE via Frame to primary, verify on replica ─────────────
    let resp = client::request(
        99,
        10,
        primary_addr,
        Frame::Delete { key: key.to_vec() },
        false,
    )
    .expect("delete request to primary");
    match resp {
        Frame::DeleteResponse { existed } => {
            assert!(existed, "primary DELETE should report existed=true");
        }
        Frame::Error { message } => {
            panic!("primary DELETE returned error: {message}");
        }
        other => panic!("expected DeleteResponse from primary, got {other:?}"),
    }

    // Give delete time to propagate
    thread::sleep(Duration::from_millis(50));

    // Verify deletion on replica
    let resp = client::request(
        98,
        20,
        replica_addr,
        Frame::Get { key: key.to_vec() },
        false,
    )
    .expect("get request to replica after delete");
    match resp {
        Frame::GetResponse { .. } => {
            panic!("replica GET after delete should not find the key");
        }
        Frame::Error { message } => {
            assert!(
                message.contains("not found"),
                "replica GET after delete should return 'not found': {message}"
            );
        }
        other => panic!("expected Error from replica after delete, got {other:?}"),
    }

    // ── STATS on replica: verify backend disclosure ─────────────────
    let resp = client::request(95, 20, replica_addr, Frame::Stats, false)
        .expect("stats request on replica");
    match resp {
        Frame::StatsResponse { json } => {
            let stats: serde_json::Value =
                serde_json::from_str(&json).expect("replica stats JSON parse");
            let backend = stats["backend"].as_str().unwrap_or("");
            assert!(
                backend.contains("tcp"),
                "replica stats backend should disclose TCP: {json}"
            );
            eprintln!("[fanout-test] replica stats: {json}");
        }
        other => panic!("expected StatsResponse from replica, got {other:?}"),
    }

    // ── Cleanup ─────────────────────────────────────────────────────
    primary_stop.store(true, Ordering::Relaxed);
    replica_stop.store(true, Ordering::Relaxed);
    let _ = primary_handle.join();
    let _ = replica_handle.join();
}

#[test]
fn two_node_send_receive_committed_root_replication_and_recovery() {
    let auth_key = RootAuthenticationKey::demo_key();
    let primary_fs_dir = tempfile::tempdir().expect("primary fs dir");
    let replica_parent_dir = tempfile::tempdir().expect("replica parent dir");
    let replica_fs_root = replica_parent_dir.path().join("received-root");

    // Phase 1: create source filesystem with data.
    {
        let mut source = vfs::LocalFileSystem::open_with_root_authentication_key(
            primary_fs_dir.path(),
            StoreOptions::default(),
            auth_key,
        )
        .expect("open source");

        source.create_dir("/data", 0o755).expect("mkdir /data");

        let file_data: Vec<u8> = vec![0x5A; 8192];
        source
            .create_file("/data/test.bin", 0o644)
            .expect("create file");
        source
            .write_file("/data/test.bin", 0, &file_data)
            .expect("write file");
        source.commit().expect("commit");
        source.sync_all().expect("sync");
    }

    // Phase 2: start primary and replica servers.
    let primary_addr = {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind primary");
        SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            l.local_addr().unwrap().port(),
        )
    };
    let replica_addr = {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind replica");
        SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            l.local_addr().unwrap().port(),
        )
    };

    let primary_store = scratch_store_paths("sendrecv-pri", 1);
    let replica_store = scratch_store_paths("sendrecv-rep", 1);

    // Primary config (has a live filesystem to send from).
    let primary_config = StorageNodeConfig {
        bind_addr: primary_addr,
        node_id: 1,
        store_paths: primary_store,
        fs_root: Some(primary_fs_dir.path().to_path_buf()),
        root_auth_key: Some(auth_key),
        authority: None,
        member_class: None,
        failure_domain: None,
        membership_bind_addr: None,
        membership_peers: vec![],
        replica_peers: vec![],
        pool_device_path: None,
        pool_lock_dir: None,
        node_identity: Some("primary-sendrecv".into()),
        ready_file: None,
        drain_timeout_secs: 30,
        cluster_lease_config: None,
        rdma: false,
        carrier_policy: None,
        membership_checkpoint_dir: None,
    };
    let mut primary_node = StorageNode::start(primary_config).expect("start primary");
    let primary_stop = Arc::new(AtomicBool::new(false));
    let primary_stop_c = Arc::clone(&primary_stop);
    let primary_handle = thread::spawn(move || {
        while !primary_stop_c.load(Ordering::Relaxed) {
            let _ = primary_node.serve_one();
        }
    });

    // Replica config (fresh empty directory to receive into).
    let replica_config = StorageNodeConfig {
        bind_addr: replica_addr,
        node_id: 2,
        store_paths: replica_store,
        fs_root: Some(replica_fs_root.clone()),
        root_auth_key: Some(auth_key),
        authority: None,
        member_class: None,
        failure_domain: None,
        membership_bind_addr: None,
        membership_peers: vec![],
        replica_peers: vec![],
        pool_device_path: None,
        pool_lock_dir: None,
        node_identity: Some("replica-sendrecv".into()),
        ready_file: None,
        drain_timeout_secs: 30,
        cluster_lease_config: None,
        rdma: false,
        carrier_policy: None,
        membership_checkpoint_dir: None,
    };
    let mut replica_node = StorageNode::start(replica_config).expect("start replica");
    let replica_stop = Arc::new(AtomicBool::new(false));
    let replica_stop_c = Arc::clone(&replica_stop);
    let replica_handle = thread::spawn(move || {
        while !replica_stop_c.load(Ordering::Relaxed) {
            let _ = replica_node.serve_one();
        }
    });
    thread::sleep(Duration::from_millis(100));

    // Phase 3: Send from primary, Receive on replica.
    let resp = client::request(10, 1, primary_addr, Frame::Send { key: vec![] }, false)
        .expect("send request");
    let export = match resp {
        Frame::SendResponse { export } => export,
        Frame::Error { message } => panic!("send error: {message}"),
        other => panic!("expected SendResponse, got {other:?}"),
    };
    assert!(!export.is_empty(), "export should not be empty");

    let auth_key_bytes = auth_key.as_bytes32().to_vec();
    let resp = client::request(
        20,
        2,
        replica_addr,
        Frame::Receive {
            export,
            root_authentication_key: auth_key_bytes,
        },
        false,
    )
    .expect("receive request");
    match resp {
        Frame::ReceiveResponse { report_json } => {
            let report: serde_json::Value =
                serde_json::from_str(&report_json).expect("receive report JSON");
            let imported = report["imported_records"].as_u64().unwrap_or(0);
            assert!(imported > 0, "receive should import records: {report_json}");
            let roots = report["imported_roots"].as_u64().unwrap_or(0);
            assert!(
                roots >= 1,
                "receive should import committed root: {report_json}"
            );
        }
        Frame::Error { message } => panic!("receive error: {message}"),
        other => panic!("expected ReceiveResponse, got {other:?}"),
    }

    // Phase 4: verify replica data independently.
    let replica_fs = vfs::LocalFileSystem::open_with_root_authentication_key(
        &replica_fs_root,
        StoreOptions::default(),
        auth_key,
    )
    .expect("open replica fs");
    let got = replica_fs
        .read_file("/data/test.bin")
        .expect("read file on replica");
    assert_eq!(got, vec![0x5A; 8192], "replica must have correct data");

    // Phase 5: audit recovery on replica proves committed-root present.
    let audit = vfs::audit_recovery_with_root_authentication_key(
        &replica_fs_root,
        StoreOptions::default(),
        auth_key,
    )
    .expect("audit replica recovery");
    assert!(
        !audit.valid_committed_roots.is_empty(),
        "replica must have at least 1 valid committed root: {}",
        audit.valid_committed_roots.len()
    );

    // Cleanup.
    primary_stop.store(true, Ordering::Relaxed);
    replica_stop.store(true, Ordering::Relaxed);
    let _ = primary_handle.join();
    let _ = replica_handle.join();
}
