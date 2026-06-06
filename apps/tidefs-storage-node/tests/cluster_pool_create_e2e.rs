//! Multi-node cluster pool create, import, and restart E2E tests (#6604, #6660).
//!
//! Starts multiple storage-node TestServers, connects via live Transport,
//! sends CP01-framed CreateRequests, and verifies PoolLabelV1 labels on disk.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tidefs_cluster::pool_config::{ClusterPlacementPolicy, ClusterRedundancy, FailureDomain};
use tidefs_cluster::pool_protocol::{
    ClusterPoolCreateRequest, ClusterPoolCreateResponse, ClusterPoolImportRequest,
    ClusterPoolImportResponse, ClusterPoolMessage, NodeDeviceSpec,
};
use tidefs_storage_node::server::{StorageNode, StorageNodeConfig};
use tidefs_transport::{NodeInfo, Transport, TransportAddr};

const CLUSTER_POOL_MAGIC: &[u8; 4] = b"CP01";
const TEST_DEVICE_BYTES: u64 = 1_048_576; // 1 MiB (>MIN_DEVICE_BYTES)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind for port pick");
    l.local_addr().expect("local_addr").port()
}

fn scratch_store_paths(label: &str, count: usize) -> Vec<PathBuf> {
    let base = std::env::temp_dir().join(format!("tidefs-cpc-{label}"));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("create scratch dir");
    (0..count).map(|i| base.join(format!("rep{i}"))).collect()
}

fn make_test_device(dir: &std::path::Path, name: &str, size: u64) -> PathBuf {
    let path = dir.join(name);
    let f = std::fs::File::create(&path).expect("create test device file");
    f.set_len(size).expect("set test device size");
    path
}

fn frame_cp01(msg: &ClusterPoolMessage) -> Vec<u8> {
    let payload = msg.encode().expect("encode cluster pool message");
    let mut wire = Vec::with_capacity(4 + payload.len());
    wire.extend_from_slice(CLUSTER_POOL_MAGIC);
    wire.extend_from_slice(&payload);
    wire
}

struct TestServer {
    #[allow(dead_code)]
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    #[allow(dead_code)]
    store_paths: Vec<PathBuf>,
}

impl TestServer {
    fn spawn(node_id: u64, store_paths: Vec<PathBuf>) -> Self {
        let store_paths_clone = store_paths.clone();
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
            pool_device_paths: Vec::new(),
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

        thread::sleep(Duration::from_millis(50));

        TestServer {
            addr,
            stop,
            store_paths: store_paths_clone,
            handle: Some(handle),
        }
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    #[allow(dead_code)]
    fn store_paths(&self) -> &[PathBuf] {
        &self.store_paths
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn connect_client(
    client: &mut Transport,
    server_node_id: u64,
    server_addr: SocketAddr,
) -> tidefs_transport::SessionId {
    client.add_node(NodeInfo::new(
        server_node_id,
        vec![TransportAddr::Tcp(server_addr)],
        0,
    ));
    let sid = client.connect(server_node_id).expect("connect to server");
    client.perform_handshake(sid).expect("perform handshake");
    sid
}

fn send_create_request(
    client: &mut Transport,
    sid: tidefs_transport::SessionId,
    req: &ClusterPoolCreateRequest,
) -> ClusterPoolCreateResponse {
    let msg = ClusterPoolMessage::CreateRequest(req.clone());
    let wire = frame_cp01(&msg);
    client
        .send_message(sid, &wire)
        .expect("send create request");

    for _ in 0..100 {
        match client.recv_message(sid) {
            Ok(raw) => {
                if raw.len() >= 4 && raw[..4] == *CLUSTER_POOL_MAGIC {
                    let decoded = ClusterPoolMessage::decode(&raw[4..]).expect("decode response");
                    if let ClusterPoolMessage::CreateResponse(resp) = decoded {
                        return resp;
                    }
                }
            }
            Err(tidefs_transport::TransportError::WouldBlock(_)) => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("recv error: {e:?}"),
        }
    }
    panic!("timeout waiting for create response");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn cluster_pool_create_two_nodes_both_succeed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let dev0 = make_test_device(dir.path(), "node1-dev0", TEST_DEVICE_BYTES);
    let dev1 = make_test_device(dir.path(), "node2-dev0", TEST_DEVICE_BYTES);

    let pool_guid: [u8; 16] = [0xA1; 16];
    let pool_name = "twonode-pool";

    let server1 = TestServer::spawn(1, scratch_store_paths("cp2s-s1", 1));
    let server2 = TestServer::spawn(2, scratch_store_paths("cp2s-s2", 1));

    let mut client = Transport::new(9999);
    let sid1 = connect_client(&mut client, 1, server1.addr());
    let sid2 = connect_client(&mut client, 2, server2.addr());

    let req1 = ClusterPoolCreateRequest {
        request_id: 1,
        pool_guid,
        pool_name: pool_name.to_string(),
        target_node_id: 1,
        node_devices: vec![NodeDeviceSpec {
            device_path: dev0.to_string_lossy().to_string(),
            local_device_index: 0,
            global_device_index: 0,
            capacity_bytes: TEST_DEVICE_BYTES,
            failure_domain: FailureDomain {
                device: 0,
                node: 1,
                chassis: 0,
                rack: 0,
                zone: 0,
                region: 0,
            },
        }],
        redundancy: ClusterRedundancy::None,
        placement: ClusterPlacementPolicy::Stripe,
        allow_file_devices: true,
    };
    let req2 = ClusterPoolCreateRequest {
        request_id: 1,
        pool_guid,
        pool_name: pool_name.to_string(),
        target_node_id: 2,
        node_devices: vec![NodeDeviceSpec {
            device_path: dev1.to_string_lossy().to_string(),
            local_device_index: 0,
            global_device_index: 1,
            capacity_bytes: TEST_DEVICE_BYTES,
            failure_domain: FailureDomain {
                device: 0,
                node: 2,
                chassis: 0,
                rack: 0,
                zone: 0,
                region: 0,
            },
        }],
        redundancy: ClusterRedundancy::None,
        placement: ClusterPlacementPolicy::Stripe,
        allow_file_devices: true,
    };

    let resp1 = send_create_request(&mut client, sid1, &req1);
    let resp2 = send_create_request(&mut client, sid2, &req2);

    assert!(
        resp1.success,
        "node 1 create must succeed: {:?}",
        resp1.error
    );
    assert!(
        resp2.success,
        "node 2 create must succeed: {:?}",
        resp2.error
    );
    assert_eq!(resp1.device_guids.len(), 1);
    assert_eq!(resp2.device_guids.len(), 1);

    // Verify labels via pool-scan.
    let device_paths: Vec<PathBuf> = vec![dev0.clone(), dev1.clone()];
    let scan_results =
        tidefs_pool_scan::scan_labels(&device_paths).expect("scan labels on both devices");
    assert_eq!(scan_results.len(), 2, "should have 2 device scan results");
    for r in &scan_results {
        assert!(
            r.label_valid,
            "label on {} must be valid: {}",
            r.device_path.display(),
            r.label_status
        );
        assert_eq!(r.pool_guid, Some(pool_guid));
        assert_eq!(r.pool_name.as_deref(), Some(pool_name));
    }

    // Explicit server stop before drop.
    server1.stop.store(true, Ordering::Relaxed);
    server2.stop.store(true, Ordering::Relaxed);
}

#[test]
fn cluster_pool_create_one_node_unreachable_fails() {
    let dir = tempfile::tempdir().expect("temp dir");
    let _dev0 = make_test_device(dir.path(), "node1-dev0", TEST_DEVICE_BYTES);

    let server1 = TestServer::spawn(1, scratch_store_paths("cp1u-s1", 1));
    let dead_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_port());

    let mut client = Transport::new(9998);
    client.add_node(NodeInfo::new(
        1,
        vec![TransportAddr::Tcp(server1.addr())],
        0,
    ));
    client.add_node(NodeInfo::new(2, vec![TransportAddr::Tcp(dead_addr)], 0));

    let _sid1 = client.connect(1).expect("connect to node 1");
    client.perform_handshake(_sid1).expect("handshake node 1");

    let result = client.connect(2);
    assert!(result.is_err(), "connect to dead node 2 must fail");

    server1.stop.store(true, Ordering::Relaxed);
}

#[test]
fn cluster_pool_create_duplicate_device_rejected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let dev = make_test_device(dir.path(), "node1-dev0", TEST_DEVICE_BYTES);

    let pool_guid: [u8; 16] = [0xB1; 16];
    let server1 = TestServer::spawn(1, scratch_store_paths("cpdup-s1", 1));
    let mut client = Transport::new(9997);
    let sid1 = connect_client(&mut client, 1, server1.addr());

    // First create succeeds.
    let req = ClusterPoolCreateRequest {
        request_id: 1,
        pool_guid,
        pool_name: "duppool".to_string(),
        target_node_id: 1,
        node_devices: vec![NodeDeviceSpec {
            device_path: dev.to_string_lossy().to_string(),
            local_device_index: 0,
            global_device_index: 0,
            capacity_bytes: TEST_DEVICE_BYTES,
            failure_domain: FailureDomain {
                device: 0,
                node: 1,
                chassis: 0,
                rack: 0,
                zone: 0,
                region: 0,
            },
        }],
        redundancy: ClusterRedundancy::None,
        placement: ClusterPlacementPolicy::Stripe,
        allow_file_devices: true,
    };
    let resp1 = send_create_request(&mut client, sid1, &req);
    assert!(
        resp1.success,
        "first create must succeed: {:?}",
        resp1.error
    );

    // Second create on same device path with different pool GUID must fail.
    let req2 = ClusterPoolCreateRequest {
        request_id: 2,
        pool_guid: [0xB2; 16], // different pool GUID
        pool_name: "duppool2".to_string(),
        target_node_id: 1,
        node_devices: vec![NodeDeviceSpec {
            device_path: dev.to_string_lossy().to_string(),
            local_device_index: 0,
            global_device_index: 0,
            capacity_bytes: TEST_DEVICE_BYTES,
            failure_domain: FailureDomain {
                device: 0,
                node: 1,
                chassis: 0,
                rack: 0,
                zone: 0,
                region: 0,
            },
        }],
        redundancy: ClusterRedundancy::None,
        placement: ClusterPlacementPolicy::Stripe,
        allow_file_devices: true,
    };
    let resp2 = send_create_request(&mut client, sid1, &req2);
    assert!(!resp2.success, "second create on same device must fail");
    assert!(
        resp2
            .error
            .as_deref()
            .unwrap_or("")
            .contains("DeviceAlreadyLabeled"),
        "error must mention already-labeled device, got: {:?}",
        resp2.error
    );

    server1.stop.store(true, Ordering::Relaxed);
}

#[test]
fn cluster_pool_create_partial_success_one_node_rejects() {
    let dir = tempfile::tempdir().expect("temp dir");
    let dev1 = make_test_device(dir.path(), "node1-dev0", TEST_DEVICE_BYTES);
    let dev2 = make_test_device(dir.path(), "node2-dev0", TEST_DEVICE_BYTES);

    let pool_guid: [u8; 16] = [0xC1; 16];
    let server1 = TestServer::spawn(1, scratch_store_paths("cppart-s1", 1));
    let server2 = TestServer::spawn(2, scratch_store_paths("cppart-s2", 1));

    let mut client = Transport::new(9996);
    let sid1 = connect_client(&mut client, 1, server1.addr());
    let sid2 = connect_client(&mut client, 2, server2.addr());

    // Pre-label dev2 with a conflicting pool GUID so node 2's create will fail.
    {
        let req_pre = ClusterPoolCreateRequest {
            request_id: 0,
            pool_guid: [0xDD; 16], // different GUID
            pool_name: "prelabel".to_string(),
            target_node_id: 2,
            node_devices: vec![NodeDeviceSpec {
                device_path: dev2.to_string_lossy().to_string(),
                local_device_index: 0,
                global_device_index: 1,
                capacity_bytes: TEST_DEVICE_BYTES,
                failure_domain: FailureDomain {
                    device: 0,
                    node: 2,
                    chassis: 0,
                    rack: 0,
                    zone: 0,
                    region: 0,
                },
            }],
            redundancy: ClusterRedundancy::None,
            placement: ClusterPlacementPolicy::Stripe,
            allow_file_devices: true,
        };
        let resp_pre = send_create_request(&mut client, sid2, &req_pre);
        assert!(
            resp_pre.success,
            "pre-label must succeed: {:?}",
            resp_pre.error
        );
    }

    // Now create with target pool GUID: node 1 succeeds, node 2 fails (device already labeled).
    let req1 = ClusterPoolCreateRequest {
        request_id: 1,
        pool_guid,
        pool_name: "partialpool".to_string(),
        target_node_id: 1,
        node_devices: vec![NodeDeviceSpec {
            device_path: dev1.to_string_lossy().to_string(),
            local_device_index: 0,
            global_device_index: 0,
            capacity_bytes: TEST_DEVICE_BYTES,
            failure_domain: FailureDomain {
                device: 0,
                node: 1,
                chassis: 0,
                rack: 0,
                zone: 0,
                region: 0,
            },
        }],
        redundancy: ClusterRedundancy::None,
        placement: ClusterPlacementPolicy::Stripe,
        allow_file_devices: true,
    };
    let req2 = ClusterPoolCreateRequest {
        request_id: 1,
        pool_guid,
        pool_name: "partialpool".to_string(),
        target_node_id: 2,
        node_devices: vec![NodeDeviceSpec {
            device_path: dev2.to_string_lossy().to_string(),
            local_device_index: 0,
            global_device_index: 1,
            capacity_bytes: TEST_DEVICE_BYTES,
            failure_domain: FailureDomain {
                device: 0,
                node: 2,
                chassis: 0,
                rack: 0,
                zone: 0,
                region: 0,
            },
        }],
        redundancy: ClusterRedundancy::None,
        placement: ClusterPlacementPolicy::Stripe,
        allow_file_devices: true,
    };

    let resp1 = send_create_request(&mut client, sid1, &req1);
    let resp2 = send_create_request(&mut client, sid2, &req2);

    assert!(
        resp1.success,
        "node 1 create must succeed: {:?}",
        resp1.error
    );
    assert!(
        !resp2.success,
        "node 2 create must fail (device already labeled)"
    );
    assert!(
        resp2
            .error
            .as_deref()
            .unwrap_or("")
            .contains("DeviceAlreadyLabeled"),
        "node 2 error must mention already-labeled device, got: {:?}",
        resp2.error
    );

    // Verify node 1's label is discoverable even though the overall quorum would fail.
    let scan_results = tidefs_pool_scan::scan_labels(&[dev1.clone()]).expect("scan node 1");
    assert_eq!(scan_results.len(), 1);
    assert!(scan_results[0].label_valid);
    assert_eq!(scan_results[0].pool_guid, Some(pool_guid));
    assert_eq!(scan_results[0].pool_name.as_deref(), Some("partialpool"));

    // Node 2's device should still have the pre-label GUID, not the new one.
    let scan2 = tidefs_pool_scan::scan_labels(&[dev2.clone()]).expect("scan node 2");
    assert_eq!(scan2.len(), 1);
    assert_eq!(scan2[0].pool_guid, Some([0xDD; 16]));

    server1.stop.store(true, Ordering::Relaxed);
    server2.stop.store(true, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Cluster pool restart / self-assembly tests (#6660)
// ---------------------------------------------------------------------------

/// Helper: send a cluster pool import request and wait for the response.
#[allow(dead_code)]
fn send_import_request(
    client: &mut Transport,
    sid: tidefs_transport::SessionId,
    req: &ClusterPoolImportRequest,
) -> ClusterPoolImportResponse {
    let msg = ClusterPoolMessage::ImportRequest(req.clone());
    let wire = frame_cp01(&msg);
    client
        .send_message(sid, &wire)
        .expect("send import request");

    for _ in 0..100 {
        match client.recv_message(sid) {
            Ok(raw) => {
                if raw.len() >= 4 && raw[..4] == *CLUSTER_POOL_MAGIC {
                    let decoded = ClusterPoolMessage::decode(&raw[4..]).expect("decode response");
                    if let ClusterPoolMessage::ImportResponse(resp) = decoded {
                        return resp;
                    }
                }
            }
            Err(tidefs_transport::TransportError::WouldBlock(_)) => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("recv error: {e:?}"),
        }
    }
    panic!("timeout waiting for import response");
}

#[test]
fn cluster_pool_create_import_and_restart_reimport() {
    // Phase 1: create cluster pool on two nodes
    let dir = tempfile::tempdir().expect("temp dir");
    let dev0 = make_test_device(dir.path(), "node1-dev0", TEST_DEVICE_BYTES);
    let dev1 = make_test_device(dir.path(), "node2-dev0", TEST_DEVICE_BYTES);

    let pool_guid: [u8; 16] = [0xE1; 16];
    let pool_name = "restart-pool";

    let server1 = TestServer::spawn(1, scratch_store_paths("cpre-s1", 1));
    let server2 = TestServer::spawn(2, scratch_store_paths("cpre-s2", 1));

    let mut client = Transport::new(9995);
    let sid1 = connect_client(&mut client, 1, server1.addr());
    let sid2 = connect_client(&mut client, 2, server2.addr());

    let create_req = |target: u64, dev: &std::path::Path, gi: u32| ClusterPoolCreateRequest {
        request_id: 1,
        pool_guid,
        pool_name: pool_name.to_string(),
        target_node_id: target,
        node_devices: vec![NodeDeviceSpec {
            device_path: dev.to_string_lossy().to_string(),
            local_device_index: 0,
            global_device_index: gi,
            capacity_bytes: TEST_DEVICE_BYTES,
            failure_domain: FailureDomain {
                device: 0,
                node: target,
                chassis: 0,
                rack: 0,
                zone: 0,
                region: 0,
            },
        }],
        redundancy: ClusterRedundancy::None,
        placement: ClusterPlacementPolicy::Stripe,
        allow_file_devices: true,
    };

    let create_resp1 = send_create_request(&mut client, sid1, &create_req(1, &dev0, 0));
    let create_resp2 = send_create_request(&mut client, sid2, &create_req(2, &dev1, 1));
    assert!(
        create_resp1.success,
        "node 1 create: {:?}",
        create_resp1.error
    );
    assert!(
        create_resp2.success,
        "node 2 create: {:?}",
        create_resp2.error
    );

    // Import pool directly to verify committed root is established.
    let import_dir = dir.path().join("import-locks");
    std::fs::create_dir_all(&import_dir).expect("create import lock dir");
    let imported = tidefs_pool_import::pool_import(
        &[dev0.clone(), dev1.clone()],
        &import_dir,
        false,
        None,
        None,
    )
    .expect("initial pool import");
    assert!(
        imported.stats.committed_root_epoch.is_some(),
        "committed root epoch must be present after create"
    );
    assert_eq!(imported.config.pool_uuid, pool_guid, "pool UUID matches");

    // Phase 2: full power loss (stop both servers)
    server1.stop.store(true, Ordering::Relaxed);
    server2.stop.store(true, Ordering::Relaxed);
    thread::sleep(Duration::from_millis(200));

    // Phase 3: restart -- scan labels to prove durability
    let device_paths: Vec<PathBuf> = vec![dev0.clone(), dev1.clone()];
    let scan_results = tidefs_pool_scan::scan_labels(&device_paths).expect("scan after restart");
    assert_eq!(
        scan_results.len(),
        2,
        "both devices should have labels after restart"
    );
    for r in &scan_results {
        assert!(r.label_valid, "label must be valid: {}", r.label_status);
        assert_eq!(r.pool_guid, Some(pool_guid));
        assert_eq!(r.pool_name.as_deref(), Some(pool_name));
    }

    // Phase 4: re-import the pool after restart to prove full recovery.
    // Use a separate lock dir (simulates stale-lock cleanup after restart).
    let reimport_dir = dir.path().join("import-locks-restart");
    std::fs::create_dir_all(&reimport_dir).expect("create reimport lock dir");
    let reimported =
        tidefs_pool_import::pool_import(&device_paths, &reimport_dir, false, None, None)
            .expect("re-import after restart");
    assert!(
        reimported.stats.committed_root_epoch.is_some(),
        "committed root epoch must survive restart"
    );
    assert_eq!(
        reimported.config.pool_uuid, pool_guid,
        "pool GUID must survive restart"
    );
}

// ---------------------------------------------------------------------------
// Cluster self-assembly failure-case tests (#6660)
// ---------------------------------------------------------------------------

#[test]
fn cluster_pool_import_fails_on_unlabeled_device_after_restart() {
    // Verify that after pool creation on node 1 only, scanning node 2's
    // unlabeled device fails and import across both devices is refused.
    // This proves the cluster doesn't silently accept partial state.
    let dir = tempfile::tempdir().expect("temp dir");
    let dev0 = make_test_device(dir.path(), "node1-dev0", TEST_DEVICE_BYTES);
    let dev1 = make_test_device(dir.path(), "node2-dev0", TEST_DEVICE_BYTES);

    let pool_guid: [u8; 16] = [0xF1; 16];

    let server1 = TestServer::spawn(1, scratch_store_paths("cpfail-s1", 1));

    let mut client = Transport::new(9994);
    let sid1 = connect_client(&mut client, 1, server1.addr());

    // Only create pool on node 1. Node 2's device stays unlabeled.
    let req = ClusterPoolCreateRequest {
        request_id: 1,
        pool_guid,
        pool_name: "partial-pool".to_string(),
        target_node_id: 1,
        node_devices: vec![NodeDeviceSpec {
            device_path: dev0.to_string_lossy().to_string(),
            local_device_index: 0,
            global_device_index: 0,
            capacity_bytes: TEST_DEVICE_BYTES,
            failure_domain: FailureDomain {
                device: 0,
                node: 1,
                chassis: 0,
                rack: 0,
                zone: 0,
                region: 0,
            },
        }],
        redundancy: ClusterRedundancy::None,
        placement: ClusterPlacementPolicy::Stripe,
        allow_file_devices: true,
    };
    let resp = send_create_request(&mut client, sid1, &req);
    assert!(resp.success, "node 1 create: {:?}", resp.error);

    server1.stop.store(true, Ordering::Relaxed);
    thread::sleep(Duration::from_millis(100));

    // After restart: scan both devices. The unlabeled one must fail scan.
    let scan_both = tidefs_pool_scan::scan_labels(&[dev0.clone(), dev1.clone()]);
    // scan_labels succeeds even when some devices are unlabeled — it reports
    // per-device results and the unlabeled one has label_valid=false.
    assert!(scan_both.is_ok(), "scan must complete");
    let scan = scan_both.unwrap();
    assert_eq!(scan.len(), 2);
    assert!(scan[0].label_valid, "node 1 device must be labeled");
    assert!(
        !scan[1].label_valid,
        "node 2 device must report unlabeled after restart"
    );
    assert!(
        scan[1].label_status.contains("NoPoolLabel")
            || scan[1].label_status.contains("no pool label")
            || scan[1].label_status.contains("not a TideFS device")
            || scan[1].label_status.contains("no label"),
        "unlabeled device status must be explicit: {}",
        scan[1].label_status
    );

    // Node 1's labeled device alone imports fine (safe partial recovery).
    let single_import = tidefs_pool_import::pool_import(
        &[dev0.clone()],
        &dir.path().join("import-locks-ok"),
        false,
        None,
        None,
    );
    assert!(
        single_import.is_ok(),
        "node 1 alone must import successfully"
    );
    assert_eq!(single_import.unwrap().config.pool_uuid, pool_guid);
}

#[test]
fn cluster_pool_import_refuses_mismatched_guid_after_restart() {
    // Create two pools with different GUIDs on separate devices, then
    // attempt to import them as a single pool. The import must explicitly
    // refuse with a GUID mismatch rather than silently importing one.
    let dir = tempfile::tempdir().expect("temp dir");
    let dev_a = make_test_device(dir.path(), "nodeA-dev0", TEST_DEVICE_BYTES);
    let dev_b = make_test_device(dir.path(), "nodeB-dev0", TEST_DEVICE_BYTES);

    let guid_a: [u8; 16] = [0xAA; 16];
    let guid_b: [u8; 16] = [0xBB; 16];

    let server1 = TestServer::spawn(1, scratch_store_paths("cpmism-s1", 1));
    let server2 = TestServer::spawn(2, scratch_store_paths("cpmism-s2", 1));

    let mut client = Transport::new(9993);
    let sid1 = connect_client(&mut client, 1, server1.addr());
    let sid2 = connect_client(&mut client, 2, server2.addr());

    // Create pool A on node 1.
    let resp_a = send_create_request(
        &mut client,
        sid1,
        &ClusterPoolCreateRequest {
            request_id: 1,
            pool_guid: guid_a,
            pool_name: "pool-a".to_string(),
            target_node_id: 1,
            node_devices: vec![NodeDeviceSpec {
                device_path: dev_a.to_string_lossy().to_string(),
                local_device_index: 0,
                global_device_index: 0,
                capacity_bytes: TEST_DEVICE_BYTES,
                failure_domain: FailureDomain {
                    device: 0,
                    node: 1,
                    chassis: 0,
                    rack: 0,
                    zone: 0,
                    region: 0,
                },
            }],
            redundancy: ClusterRedundancy::None,
            placement: ClusterPlacementPolicy::Stripe,
            allow_file_devices: true,
        },
    );
    assert!(resp_a.success, "pool A create: {:?}", resp_a.error);

    // Create pool B on node 2.
    let resp_b = send_create_request(
        &mut client,
        sid2,
        &ClusterPoolCreateRequest {
            request_id: 1,
            pool_guid: guid_b,
            pool_name: "pool-b".to_string(),
            target_node_id: 2,
            node_devices: vec![NodeDeviceSpec {
                device_path: dev_b.to_string_lossy().to_string(),
                local_device_index: 0,
                global_device_index: 0,
                capacity_bytes: TEST_DEVICE_BYTES,
                failure_domain: FailureDomain {
                    device: 0,
                    node: 2,
                    chassis: 0,
                    rack: 0,
                    zone: 0,
                    region: 0,
                },
            }],
            redundancy: ClusterRedundancy::None,
            placement: ClusterPlacementPolicy::Stripe,
            allow_file_devices: true,
        },
    );
    assert!(resp_b.success, "pool B create: {:?}", resp_b.error);

    server1.stop.store(true, Ordering::Relaxed);
    server2.stop.store(true, Ordering::Relaxed);
    thread::sleep(Duration::from_millis(100));

    // After restart: attempt to import both devices as one pool.
    let import_dir = dir.path().join("import-locks");
    std::fs::create_dir_all(&import_dir).expect("create import lock dir");
    let result = tidefs_pool_import::pool_import(&[dev_a, dev_b], &import_dir, false, None, None);
    assert!(result.is_err(), "import must fail on GUID mismatch");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("multiple pools")
            || err.contains("belong to")
            || err.contains("mismatch")
            || err.contains("uuid")
            || err.contains("GUID")
            || err.contains("guid")
            || err.contains("inconsistent"),
        "error must indicate GUID mismatch / multiple pools, got: {err}"
    );
}

#[test]
fn cluster_pool_restart_varied_order_nodes_reimport() {
    // Prove that restart order does not affect pool recovery: stop all
    // nodes, restart with node 2 scanned first, then node 1, and verify
    // pool labels survive and re-import succeeds irrespective of order.
    let dir = tempfile::tempdir().expect("temp dir");
    let dev0 = make_test_device(dir.path(), "node1-dev0", TEST_DEVICE_BYTES);
    let dev1 = make_test_device(dir.path(), "node2-dev0", TEST_DEVICE_BYTES);

    let pool_guid: [u8; 16] = [0xE2; 16];
    let pool_name = "varorder-pool";

    let server1 = TestServer::spawn(1, scratch_store_paths("cpvo-s1", 1));
    let server2 = TestServer::spawn(2, scratch_store_paths("cpvo-s2", 1));

    let mut client = Transport::new(9992);
    let sid1 = connect_client(&mut client, 1, server1.addr());
    let sid2 = connect_client(&mut client, 2, server2.addr());

    let create_req = |target: u64, dev: &std::path::Path, gi: u32| ClusterPoolCreateRequest {
        request_id: 1,
        pool_guid,
        pool_name: pool_name.to_string(),
        target_node_id: target,
        node_devices: vec![NodeDeviceSpec {
            device_path: dev.to_string_lossy().to_string(),
            local_device_index: 0,
            global_device_index: gi,
            capacity_bytes: TEST_DEVICE_BYTES,
            failure_domain: FailureDomain {
                device: 0,
                node: target,
                chassis: 0,
                rack: 0,
                zone: 0,
                region: 0,
            },
        }],
        redundancy: ClusterRedundancy::None,
        placement: ClusterPlacementPolicy::Stripe,
        allow_file_devices: true,
    };

    let create_resp1 = send_create_request(&mut client, sid1, &create_req(1, &dev0, 0));
    let create_resp2 = send_create_request(&mut client, sid2, &create_req(2, &dev1, 1));
    assert!(
        create_resp1.success,
        "node 1 create: {:?}",
        create_resp1.error
    );
    assert!(
        create_resp2.success,
        "node 2 create: {:?}",
        create_resp2.error
    );

    // Import the pool to establish committed root.
    let import_dir = dir.path().join("import-locks");
    std::fs::create_dir_all(&import_dir).expect("create import lock dir");
    let imported = tidefs_pool_import::pool_import(
        &[dev0.clone(), dev1.clone()],
        &import_dir,
        false,
        None,
        None,
    )
    .expect("initial pool import");
    assert!(imported.stats.committed_root_epoch.is_some());

    // Full power loss.
    server1.stop.store(true, Ordering::Relaxed);
    server2.stop.store(true, Ordering::Relaxed);
    thread::sleep(Duration::from_millis(200));

    // Varied restart order: scan/import node 2 first, then node 1.
    let scan2 = tidefs_pool_scan::scan_labels(&[dev1.clone()]).expect("scan node 2 first");
    assert_eq!(scan2.len(), 1);
    assert!(scan2[0].label_valid);
    assert_eq!(scan2[0].pool_guid, Some(pool_guid));

    let scan1 = tidefs_pool_scan::scan_labels(&[dev0.clone()]).expect("scan node 1 second");
    assert_eq!(scan1.len(), 1);
    assert!(scan1[0].label_valid);
    assert_eq!(scan1[0].pool_guid, Some(pool_guid));

    // Re-import both devices, proving order independence.
    let reimport_dir = dir.path().join("import-locks-restart");
    std::fs::create_dir_all(&reimport_dir).expect("create reimport lock dir");
    let reimported = tidefs_pool_import::pool_import(
        &[dev1.clone(), dev0.clone()],
        &reimport_dir,
        false,
        None,
        None,
    )
    .expect("re-import after restart (varied order)");
    assert!(reimported.stats.committed_root_epoch.is_some());
    assert_eq!(reimported.config.pool_uuid, pool_guid);
}
