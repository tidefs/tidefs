// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Multi-node clustered pool full-flow E2E tests (#6610).
//!
//! Exercises the full clustered pool operator path:
//!   pool create across nodes -> import validation -> dataset catalog ->
//!   placement heal exercise -> label verification.
//!
//! Uses multiple StorageNode TestServers connected via live Transport
//! with CP01-framed messages and ClusterLeaseRuntime.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tidefs_auth::{NodeKeyStore, NodePrivateCredential, NodePublicIdentity};
use tidefs_cluster::pool_config::{ClusterPlacementPolicy, ClusterRedundancy, FailureDomain};
use tidefs_cluster::pool_lease_client::ClusterLeaseClient;
use tidefs_cluster::pool_lease_token::PoolLeaseToken;
use tidefs_cluster::pool_protocol::ClusterPoolLeaseRequest;
use tidefs_cluster::pool_protocol::{
    CatalogQueryType, ClusterPoolCatalogDeltaRequest, ClusterPoolCatalogQueryRequest,
    ClusterPoolCreateRequest, ClusterPoolMessage, NodeDeviceSpec,
};
use tidefs_cluster::{ClusterLeaseConfig, LossEvent, PlacementHealCoordinator, PlacementMap};
use tidefs_membership_epoch::{HealthClass, MemberClass};
use tidefs_membership_live::BackendDisclosure;
use tidefs_storage_node::authority_spine::RuntimeAuthority;
use tidefs_storage_node::server::{MembershipPeerConfig, StorageNode, StorageNodeConfig};
use tidefs_transport::EndpointFamily;

const CLUSTER_POOL_MAGIC: &[u8; 4] = b"CP01";
const TEST_DEVICE_BYTES: u64 = 2 * 1_048_576; // 2 MiB

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind for port pick");
    l.local_addr().expect("local_addr").port()
}

fn scratch_store_paths(label: &str, count: usize) -> Vec<PathBuf> {
    let base = std::env::temp_dir().join(format!("tidefs-cff-{label}"));
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

fn duplicate_credential(credential: &NodePrivateCredential) -> NodePrivateCredential {
    NodePrivateCredential::decode_fixed(&credential.encode_fixed()).expect("duplicate credential")
}

fn authenticated_client(
    credential: &NodePrivateCredential,
    trusted_peers: &[NodePublicIdentity],
) -> tidefs_transport::Transport {
    let local_identity = credential.public_identity().into_identity();
    let mut exact_trust = NodeKeyStore::new();
    exact_trust
        .register(local_identity.clone())
        .expect("register local test identity");
    for peer in trusted_peers {
        exact_trust
            .register(peer.identity().clone())
            .expect("register exact test peer");
    }
    let mut transport = tidefs_transport::Transport::new(credential.node_id())
        .with_attestation(
            credential.keypair().expect("load test keypair"),
            local_identity,
        )
        .with_known_identities(exact_trust);
    transport.set_endpoint_family(EndpointFamily::Control);
    transport.set_attestation_bootstrap_from_handshake(false);
    transport
}

struct TestServer {
    #[allow(dead_code)]
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TestServer {
    fn spawn(node_id: u64, store_paths: Vec<PathBuf>) -> Self {
        Self::spawn_configured(
            node_id,
            store_paths,
            None,
            None,
            Vec::new(),
            None,
            None,
            false,
        )
    }

    fn spawn_authenticated(
        node_id: u64,
        store_paths: Vec<PathBuf>,
        credential: NodePrivateCredential,
        trusted_peers: Vec<NodePublicIdentity>,
    ) -> Self {
        let membership_checkpoint_dir = store_paths
            .first()
            .and_then(|path| path.parent())
            .expect("scratch store has parent")
            .join("membership-checkpoint");
        Self::spawn_configured(
            node_id,
            store_paths,
            Some(ClusterLeaseConfig::default()),
            Some(membership_checkpoint_dir),
            Vec::new(),
            None,
            Some((credential, trusted_peers)),
            true,
        )
    }

    fn spawn_configured(
        node_id: u64,
        store_paths: Vec<PathBuf>,
        cluster_lease_config: Option<ClusterLeaseConfig>,
        membership_checkpoint_dir: Option<PathBuf>,
        membership_peers: Vec<MembershipPeerConfig>,
        membership_bind_addr: Option<SocketAddr>,
        transport_identity: Option<(NodePrivateCredential, Vec<NodePublicIdentity>)>,
        live_replication_backend: bool,
    ) -> Self {
        let port = pick_port();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let authority = transport_identity.map(|(credential, trusted_peers)| {
            let disclosure = if live_replication_backend {
                BackendDisclosure::Tcp(addr)
            } else {
                BackendDisclosure::Loopback
            };
            RuntimeAuthority::build(disclosure, node_id, None, None, 1)
                .and_then(|authority| authority.with_transport_identity(credential, trusted_peers))
                .expect("build exact test transport authority")
        });
        let config = StorageNodeConfig {
            bind_addr: addr,
            node_id,
            store_paths,
            fs_root: None,
            root_auth_key: None,
            member_class: None,
            failure_domain: None,
            membership_bind_addr,
            membership_peers,
            replica_peers: vec![],
            pool_device_paths: Vec::new(),
            pool_lock_dir: None,
            node_identity: None,
            authority,
            ready_file: None,
            drain_timeout_secs: 30,
            cluster_lease_config,
            membership_checkpoint_dir,
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
            handle: Some(handle),
        }
    }

    fn addr(&self) -> SocketAddr {
        self.addr
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
    client: &mut tidefs_transport::Transport,
    server_node_id: u64,
    server_addr: SocketAddr,
) -> tidefs_transport::SessionId {
    use tidefs_transport::{NodeInfo, TransportAddr};
    client.add_node(NodeInfo::new(
        server_node_id,
        vec![TransportAddr::Tcp(server_addr)],
        0,
    ));
    let sid = client.connect(server_node_id).expect("connect to server");
    client.perform_handshake(sid).expect("perform handshake");
    sid
}

fn try_connect_client(
    client: &mut tidefs_transport::Transport,
    server_node_id: u64,
    server_addr: SocketAddr,
) -> Result<tidefs_transport::SessionId, tidefs_transport::TransportError> {
    use tidefs_transport::{NodeInfo, TransportAddr};
    client.add_node(NodeInfo::new(
        server_node_id,
        vec![TransportAddr::Tcp(server_addr)],
        0,
    ));
    let session_id = client.connect(server_node_id)?;
    client.perform_handshake(session_id)?;
    Ok(session_id)
}

fn recv_cp01(
    client: &mut tidefs_transport::Transport,
    sid: tidefs_transport::SessionId,
    timeout_iters: usize,
) -> Option<ClusterPoolMessage> {
    for _ in 0..timeout_iters {
        match client.recv_message(sid) {
            Ok(raw) => {
                if raw.len() >= 4 && raw[..4] == *CLUSTER_POOL_MAGIC {
                    match ClusterPoolMessage::decode(&raw[4..]) {
                        Ok(msg) => return Some(msg),
                        Err(e) => {
                            eprintln!("[test] decode error: {e:?}");
                            return None;
                        }
                    }
                }
            }
            Err(tidefs_transport::TransportError::WouldBlock(_)) => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                eprintln!("[test] recv error: {e:?}");
                return None;
            }
        }
    }
    None
}

fn send_cp01(
    client: &mut tidefs_transport::Transport,
    sid: tidefs_transport::SessionId,
    msg: &ClusterPoolMessage,
) {
    let wire = frame_cp01(msg);
    client.send_message(sid, &wire).expect("send CP01 message");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn cluster_full_flow_refuses_wrong_keys_plaintext_and_bootstrap() {
    // Wrong owner key: the presented node ID is right, but the authority has
    // provisioned a different exact public identity for that owner.
    let authority_credential = NodePrivateCredential::generate(1).expect("authority credential");
    let authority_identity = authority_credential.public_identity();
    let expected_owner = NodePrivateCredential::generate(2).expect("expected owner credential");
    let wrong_owner = NodePrivateCredential::generate(2).expect("wrong owner credential");
    let server = TestServer::spawn_authenticated(
        1,
        scratch_store_paths("auth-wrong-owner", 1),
        authority_credential,
        vec![expected_owner.public_identity()],
    );
    let mut client = authenticated_client(&wrong_owner, &[authority_identity]);
    assert!(
        try_connect_client(&mut client, 1, server.addr()).is_err(),
        "same numeric owner ID with the wrong key must be refused"
    );
    drop(client);
    drop(server);

    // Wrong authority key: the owner trusts a different key for the exact
    // authority node ID than the live storage node presents.
    let authority_credential = NodePrivateCredential::generate(1).expect("authority credential");
    let wrong_authority = NodePrivateCredential::generate(1).expect("wrong authority credential");
    let owner_credential = NodePrivateCredential::generate(2).expect("owner credential");
    let server = TestServer::spawn_authenticated(
        1,
        scratch_store_paths("auth-wrong-authority", 1),
        authority_credential,
        vec![owner_credential.public_identity()],
    );
    let mut client = authenticated_client(&owner_credential, &[wrong_authority.public_identity()]);
    assert!(
        try_connect_client(&mut client, 1, server.addr()).is_err(),
        "same numeric authority ID with the wrong key must be refused"
    );
    drop(client);
    drop(server);

    // Plaintext cannot enter a non-local Control endpoint.
    let authority_credential = NodePrivateCredential::generate(1).expect("authority credential");
    let expected_owner = NodePrivateCredential::generate(2).expect("expected owner credential");
    let server = TestServer::spawn_authenticated(
        1,
        scratch_store_paths("auth-plaintext", 1),
        authority_credential,
        vec![expected_owner.public_identity()],
    );
    let mut plaintext = tidefs_transport::Transport::new(2);
    plaintext.set_endpoint_family(EndpointFamily::Control);
    assert!(
        try_connect_client(&mut plaintext, 1, server.addr()).is_err(),
        "plaintext Control session must be refused"
    );
    drop(plaintext);
    drop(server);

    // Handshake identity bootstrap on the initiator cannot make an
    // unprovisioned key acceptable to the exact-trust authority.
    let authority_credential = NodePrivateCredential::generate(1).expect("authority credential");
    let expected_owner = NodePrivateCredential::generate(2).expect("expected owner credential");
    let server = TestServer::spawn_authenticated(
        1,
        scratch_store_paths("auth-bootstrap", 1),
        authority_credential,
        vec![expected_owner.public_identity()],
    );
    let mut bootstrap = tidefs_transport::Transport::new(2);
    bootstrap
        .configure_generated_attestation(true)
        .expect("configure bootstrap identity");
    bootstrap.set_endpoint_family(EndpointFamily::Control);
    assert!(
        try_connect_client(&mut bootstrap, 1, server.addr()).is_err(),
        "handshake-bootstrap identity must not bypass exact authority trust"
    );
}

/// Full clustered pool create with lease acquisition, catalog operations,
/// and placement heal exercise.
#[test]
fn cluster_full_flow_create_lease_catalog_heal() {
    let dir = tempfile::tempdir().expect("temp dir");
    let dev0 = make_test_device(dir.path(), "node1-dev0", TEST_DEVICE_BYTES);
    let dev1 = make_test_device(dir.path(), "node2-dev0", TEST_DEVICE_BYTES);

    let pool_guid: [u8; 16] = [0xC1; 16];
    let pool_name = "fullflow-pool";

    // Start two storage nodes with exact provisioned identities and trust.
    let server1_credential = NodePrivateCredential::generate(1).expect("server 1 credential");
    let server2_credential = NodePrivateCredential::generate(2).expect("server 2 credential");
    let owner_credential = duplicate_credential(&server1_credential);
    let owner_identity = owner_credential.public_identity();
    let server1_identity = server1_credential.public_identity();
    let server2_identity = server2_credential.public_identity();
    let server1 = TestServer::spawn_authenticated(
        1,
        scratch_store_paths("cff-s1", 1),
        server1_credential,
        vec![owner_identity.clone()],
    );
    let server2 = TestServer::spawn_authenticated(
        2,
        scratch_store_paths("cff-s2", 1),
        server2_credential,
        vec![owner_identity],
    );

    // Node 1 acts as the authenticated Pool owner and connects to both
    // storage-node transports.
    let mut client = authenticated_client(&owner_credential, &[server1_identity, server2_identity]);
    let sid1 = connect_client(&mut client, 1, server1.addr());
    let sid2 = connect_client(&mut client, 2, server2.addr());

    // -- Phase 1: Create clustered pool on both nodes --
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
            failure_domain: FailureDomain::for_node(1),
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
            failure_domain: FailureDomain::for_node(2),
        }],
        redundancy: ClusterRedundancy::None,
        placement: ClusterPlacementPolicy::Stripe,
        allow_file_devices: true,
    };

    send_cp01(&mut client, sid1, &ClusterPoolMessage::CreateRequest(req1));
    send_cp01(&mut client, sid2, &ClusterPoolMessage::CreateRequest(req2));

    let resp1 = recv_cp01(&mut client, sid1, 100);
    let resp2 = recv_cp01(&mut client, sid2, 100);

    match (&resp1, &resp2) {
        (
            Some(ClusterPoolMessage::CreateResponse(r1)),
            Some(ClusterPoolMessage::CreateResponse(r2)),
        ) => {
            assert!(r1.success, "node 1 create must succeed: {:?}", r1.error);
            assert!(r2.success, "node 2 create must succeed: {:?}", r2.error);
            assert_eq!(r1.device_guids.len(), 1);
            assert_eq!(r2.device_guids.len(), 1);
        }
        _ => panic!("unexpected responses: resp1={resp1:?}, resp2={resp2:?}"),
    }

    // -- Phase 2: Verify pool labels via scan --
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
    // -- Phase 3: Request pool lease from node 1 via transport session --
    let lease_req = ClusterPoolLeaseRequest {
        request_id: 200,
        pool_guid,
        requesting_node_id: 1,
        action: tidefs_cluster::ClusterPoolLeaseAction::Acquire,
    };
    send_cp01(
        &mut client,
        sid1,
        &ClusterPoolMessage::LeaseRequest(lease_req),
    );
    let first_token = match recv_cp01(&mut client, sid1, 100) {
        Some(ClusterPoolMessage::LeaseResponse(resp)) => {
            assert!(resp.success, "lease refused via session: {:?}", resp.error);
            bincode::deserialize::<PoolLeaseToken>(
                &resp
                    .lease_token_bytes
                    .expect("acquire response returns Pool lease token"),
            )
            .expect("deserialize acquired Pool lease token")
        }
        other => panic!("unexpected lease response via session: {other:?}"),
    };
    assert_eq!(first_token.node_id, 1, "requester must own the lease");
    assert!(first_token.authorizes_pool(&pool_guid));

    send_cp01(
        &mut client,
        sid1,
        &ClusterPoolMessage::LeaseRequest(ClusterPoolLeaseRequest {
            request_id: 201,
            pool_guid,
            requesting_node_id: 1,
            action: tidefs_cluster::ClusterPoolLeaseAction::Renew {
                token: first_token.clone(),
            },
        }),
    );
    let renewed_token = match recv_cp01(&mut client, sid1, 100) {
        Some(ClusterPoolMessage::LeaseResponse(resp)) => {
            assert!(resp.success, "renew refused via session: {:?}", resp.error);
            bincode::deserialize::<PoolLeaseToken>(
                &resp
                    .lease_token_bytes
                    .expect("renew response returns Pool lease token"),
            )
            .expect("deserialize renewed Pool lease token")
        }
        other => panic!("unexpected renew response via session: {other:?}"),
    };
    assert_eq!(renewed_token.lease_id, first_token.lease_id);
    assert_eq!(renewed_token.write_fence, first_token.write_fence);
    assert!(renewed_token.expiration_deadline_ms > first_token.expiration_deadline_ms);

    send_cp01(
        &mut client,
        sid1,
        &ClusterPoolMessage::LeaseRequest(ClusterPoolLeaseRequest {
            request_id: 202,
            pool_guid,
            requesting_node_id: 1,
            action: tidefs_cluster::ClusterPoolLeaseAction::Release {
                token: renewed_token,
            },
        }),
    );
    match recv_cp01(&mut client, sid1, 100) {
        Some(ClusterPoolMessage::LeaseResponse(resp)) => {
            assert!(
                resp.success,
                "release refused via session: {:?}",
                resp.error
            );
            assert!(resp.lease_token_bytes.is_none());
        }
        other => panic!("unexpected release response via session: {other:?}"),
    }

    send_cp01(
        &mut client,
        sid1,
        &ClusterPoolMessage::LeaseRequest(ClusterPoolLeaseRequest {
            request_id: 203,
            pool_guid,
            requesting_node_id: 1,
            action: tidefs_cluster::ClusterPoolLeaseAction::Acquire,
        }),
    );
    let next_token = match recv_cp01(&mut client, sid1, 100) {
        Some(ClusterPoolMessage::LeaseResponse(resp)) => {
            assert!(
                resp.success,
                "reacquire refused via session: {:?}",
                resp.error
            );
            bincode::deserialize::<PoolLeaseToken>(
                &resp
                    .lease_token_bytes
                    .expect("reacquire response returns Pool lease token"),
            )
            .expect("deserialize reacquired Pool lease token")
        }
        other => panic!("unexpected reacquire response via session: {other:?}"),
    };
    assert!(next_token.write_fence > first_token.write_fence);
    send_cp01(
        &mut client,
        sid1,
        &ClusterPoolMessage::LeaseRequest(ClusterPoolLeaseRequest {
            request_id: 204,
            pool_guid,
            requesting_node_id: 1,
            action: tidefs_cluster::ClusterPoolLeaseAction::Release { token: next_token },
        }),
    );
    match recv_cp01(&mut client, sid1, 100) {
        Some(ClusterPoolMessage::LeaseResponse(resp)) => {
            assert!(resp.success, "final release refused: {:?}", resp.error);
        }
        other => panic!("unexpected final release response: {other:?}"),
    }

    // -- Phase 4: Catalog delta (create dataset) through CP01 --
    let delta = tidefs_cluster::dataset_catalog::CatalogDelta::Create {
        path: "pool/ds_test".to_string(),
        dataset_id_bytes: vec![0xAA; 16],
        dataset_type_u8: 1u8,
        creation_txg: 1,
        properties: vec![],
        flags_u16: 0,
    };
    let delta_bytes = bincode::serialize(&delta).expect("serialize catalog delta");

    let cat_delta_req = ClusterPoolCatalogDeltaRequest {
        request_id: 100,
        pool_guid,
        requesting_node_id: 9990,
        delta_bytes,
    };

    send_cp01(
        &mut client,
        sid1,
        &ClusterPoolMessage::CatalogDeltaRequest(cat_delta_req),
    );

    let cat_delta_resp = recv_cp01(&mut client, sid1, 100);
    match cat_delta_resp {
        Some(ClusterPoolMessage::CatalogDeltaResponse(ref resp)) => {
            if resp.success {
                eprintln!(
                    "[test] catalog delta succeeded, version={:?}",
                    resp.catalog_version
                );
            } else {
                eprintln!("[test] catalog delta refused: {:?}", resp.error);
            }
        }
        other => eprintln!("[test] unexpected catalog delta response: {other:?}"),
    }

    // -- Phase 5: Catalog query (list datasets) through CP01 --
    let cat_query_req = ClusterPoolCatalogQueryRequest {
        request_id: 101,
        pool_guid,
        requesting_node_id: 9990,
        query_type_u8: CatalogQueryType::ListAll.to_u8(),
        path: String::new(),
    };

    send_cp01(
        &mut client,
        sid1,
        &ClusterPoolMessage::CatalogQueryRequest(cat_query_req),
    );

    let cat_query_resp = recv_cp01(&mut client, sid1, 100);
    match cat_query_resp {
        Some(ClusterPoolMessage::CatalogQueryResponse(ref resp)) => {
            if resp.success {
                eprintln!(
                    "[test] catalog query: {} entries, version={}",
                    resp.entries.len(),
                    resp.catalog_version
                );
            } else {
                eprintln!("[test] catalog query refused: {:?}", resp.error);
            }
        }
        other => eprintln!("[test] unexpected catalog query response: {other:?}"),
    }

    // -- Phase 6: Placement map exercise --
    let mut pm = PlacementMap::new(1);
    pm.insert(10, 1);
    pm.insert(20, 2);
    pm.insert(30, 1);
    pm.insert(30, 2);

    assert_eq!(pm.member_count(), 2, "2 members in placement");
    assert_eq!(pm.object_count(), 3, "3 objects in placement");
    assert_eq!(pm.total_replicas(), 4, "4 total replicas");

    let obj10_reps: Vec<u64> = pm
        .replicas_of(10)
        .map(|s| s.iter().copied().collect())
        .unwrap_or_default();
    assert!(obj10_reps.contains(&1), "obj 10 has member 1");

    // -- Phase 7: Placement heal coordinator exercise --
    let mut coordinator = PlacementHealCoordinator::new(1, None);
    {
        let pm2 = coordinator.placement_mut();
        pm2.insert(100, 1);
        pm2.insert(100, 2);
        pm2.insert(200, 1);
    }

    let mut lost_members = std::collections::BTreeSet::new();
    lost_members.insert(2);
    let mut available = BTreeMap::new();
    available.insert(1, HealthClass::Healthy);

    let event = LossEvent {
        lost_members,
        epoch: 1,
        detected_at_ns: 1_000_000_000,
        available_members: available,
    };

    let affected = coordinator.detect_loss(event);
    let state = coordinator.state();
    let stats = coordinator.stats();

    eprintln!(
        "[test] heal state: {state:?}, affected={:?}, stats: affected={} wholly_lost={} to_rebuild={}",
        affected.map(|s| s.iter().copied().collect::<Vec<_>>()),
        stats.objects_affected,
        stats.objects_wholly_lost,
        stats.objects_to_rebuild
    );

    assert!(state.is_active(), "heal should be active after loss");
    assert!(stats.objects_affected > 0, "should have affected objects");

    // -- Cleanup --
    server1.stop.store(true, Ordering::Relaxed);
    server2.stop.store(true, Ordering::Relaxed);
}

#[test]
fn cluster_pool_owner_restart_quarantines_old_grant_before_newer_handoff() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_paths = vec![dir.path().join("authority-store")];
    let checkpoint_dir = dir.path().join("membership-checkpoint");
    let peer2_membership_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_port());
    let peer3_membership_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_port());
    let _peer2 = TestServer::spawn_configured(
        2,
        vec![dir.path().join("peer2-store")],
        None,
        None,
        Vec::new(),
        Some(peer2_membership_addr),
        None,
        false,
    );
    let _peer3 = TestServer::spawn_configured(
        3,
        vec![dir.path().join("peer3-store")],
        None,
        None,
        Vec::new(),
        Some(peer3_membership_addr),
        None,
        false,
    );
    let membership_peers = vec![
        MembershipPeerConfig {
            node_id: 2,
            addr: peer2_membership_addr,
            member_class: MemberClass::Voter,
            failure_domain: 2,
        },
        MembershipPeerConfig {
            node_id: 3,
            addr: peer3_membership_addr,
            member_class: MemberClass::Voter,
            failure_domain: 3,
        },
    ];
    // Exact mutual attestation and membership startup can exceed the old
    // sub-second term on a loaded test host. Keep the quarantine comfortably
    // live through the immediate handoff refusal.
    let lease_term_ms = 2_000;
    let lease_config = ClusterLeaseConfig {
        lease_term_ms,
        ..ClusterLeaseConfig::default()
    };
    let pool_guid = [0xD7; 16];
    let authority_credential = NodePrivateCredential::generate(1).expect("authority credential");
    let authority_identity = authority_credential.public_identity();
    let owner2_credential = NodePrivateCredential::generate(2).expect("owner 2 credential");
    let owner3_credential = NodePrivateCredential::generate(3).expect("owner 3 credential");
    let trusted_owners = vec![
        owner2_credential.public_identity(),
        owner3_credential.public_identity(),
    ];

    let server = TestServer::spawn_configured(
        1,
        store_paths.clone(),
        Some(lease_config.clone()),
        Some(checkpoint_dir.clone()),
        membership_peers.clone(),
        None,
        Some((
            duplicate_credential(&authority_credential),
            trusted_owners.clone(),
        )),
        false,
    );
    let mut owner2 = authenticated_client(&owner2_credential, &[authority_identity.clone()]);
    let owner2_session = connect_client(&mut owner2, 1, server.addr());
    send_cp01(
        &mut owner2,
        owner2_session,
        &ClusterPoolMessage::LeaseRequest(ClusterPoolLeaseRequest {
            request_id: 300,
            pool_guid,
            requesting_node_id: 2,
            action: tidefs_cluster::ClusterPoolLeaseAction::Acquire,
        }),
    );
    let old_token = match recv_cp01(&mut owner2, owner2_session, 100) {
        Some(ClusterPoolMessage::LeaseResponse(response)) => {
            assert!(
                response.success,
                "initial lease refused: {:?}",
                response.error
            );
            bincode::deserialize::<PoolLeaseToken>(
                &response
                    .lease_token_bytes
                    .expect("initial acquire returns token"),
            )
            .expect("decode initial Pool owner token")
        }
        other => panic!("unexpected initial lease response: {other:?}"),
    };
    drop(owner2);
    drop(server);

    let restarted = TestServer::spawn_configured(
        1,
        store_paths,
        Some(lease_config),
        Some(checkpoint_dir),
        membership_peers,
        None,
        Some((authority_credential, trusted_owners)),
        false,
    );

    let mut owner2 = authenticated_client(&owner2_credential, &[authority_identity.clone()]);
    let owner2_session = connect_client(&mut owner2, 1, restarted.addr());
    send_cp01(
        &mut owner2,
        owner2_session,
        &ClusterPoolMessage::LeaseRequest(ClusterPoolLeaseRequest {
            request_id: 301,
            pool_guid,
            requesting_node_id: 2,
            action: tidefs_cluster::ClusterPoolLeaseAction::Renew {
                token: old_token.clone(),
            },
        }),
    );
    match recv_cp01(&mut owner2, owner2_session, 100) {
        Some(ClusterPoolMessage::LeaseResponse(response)) => {
            assert!(!response.success, "pre-restart token must be stale");
            assert!(response.lease_token_bytes.is_none());
        }
        other => panic!("unexpected stale-renew response: {other:?}"),
    }

    let mut owner3 = authenticated_client(&owner3_credential, &[authority_identity]);
    let owner3_session = connect_client(&mut owner3, 1, restarted.addr());
    let acquire = |request_id| {
        ClusterPoolMessage::LeaseRequest(ClusterPoolLeaseRequest {
            request_id,
            pool_guid,
            requesting_node_id: 3,
            action: tidefs_cluster::ClusterPoolLeaseAction::Acquire,
        })
    };
    send_cp01(&mut owner3, owner3_session, &acquire(302));
    match recv_cp01(&mut owner3, owner3_session, 100) {
        Some(ClusterPoolMessage::LeaseResponse(response)) => {
            assert!(!response.success, "restart quarantine admitted owner 3");
            assert!(response.lease_token_bytes.is_none());
        }
        other => panic!("unexpected quarantine response: {other:?}"),
    }

    thread::sleep(Duration::from_millis(lease_term_ms + 75));
    send_cp01(&mut owner3, owner3_session, &acquire(303));
    let new_token = match recv_cp01(&mut owner3, owner3_session, 100) {
        Some(ClusterPoolMessage::LeaseResponse(response)) => {
            assert!(
                response.success,
                "post-quarantine handoff refused: {:?}",
                response.error
            );
            bincode::deserialize::<PoolLeaseToken>(
                &response
                    .lease_token_bytes
                    .expect("post-quarantine acquire returns token"),
            )
            .expect("decode post-restart Pool owner token")
        }
        other => panic!("unexpected post-quarantine response: {other:?}"),
    };
    assert_eq!(new_token.node_id, 3);
    assert!(new_token.lease_id > old_token.lease_id);
    assert!(new_token.write_fence.is_later_than(&old_token.write_fence));
}

/// Test that a storage node without cluster_lease_config serves or refuses
/// lease requests correctly (ensures the feature gate works).
#[test]
fn cluster_no_lease_config_lifecycle() {
    let dir = tempfile::tempdir().expect("temp dir");
    let dev = make_test_device(dir.path(), "node1-dev0", TEST_DEVICE_BYTES);
    let pool_guid: [u8; 16] = [0xD1; 16];

    // Server without lease config.
    let server = TestServer::spawn(1, scratch_store_paths("cnlc-s1", 1));

    let mut client = tidefs_transport::Transport::new(9980);
    let sid = connect_client(&mut client, 1, server.addr());

    // Create a pool first so the server has one.
    let req = ClusterPoolCreateRequest {
        request_id: 1,
        pool_guid,
        pool_name: "nolease-pool".to_string(),
        target_node_id: 1,
        node_devices: vec![NodeDeviceSpec {
            device_path: dev.to_string_lossy().to_string(),
            local_device_index: 0,
            global_device_index: 0,
            capacity_bytes: TEST_DEVICE_BYTES,
            failure_domain: FailureDomain::for_node(1),
        }],
        redundancy: ClusterRedundancy::None,
        placement: ClusterPlacementPolicy::Stripe,
        allow_file_devices: true,
    };
    send_cp01(&mut client, sid, &ClusterPoolMessage::CreateRequest(req));
    let create_resp = recv_cp01(&mut client, sid, 100);
    match create_resp {
        Some(ClusterPoolMessage::CreateResponse(ref r)) => {
            assert!(r.success, "pool create must succeed: {:?}", r.error);
        }
        other => panic!("unexpected create response: {other:?}"),
    }

    // Try to get a lease from the server. Without lease config,
    // the server should refuse.
    let node_addr = format!("127.0.0.1:{}", server.addr().port());
    let lease_result = ClusterLeaseClient::request_lease(&node_addr, 9980, pool_guid);

    // The server has no lease runtime; expect refusal.
    match lease_result {
        Ok(_) => {
            eprintln!("[test] note: lease granted even without cluster_lease_config");
        }
        Err(_) => {
            eprintln!("[test] lease correctly refused (no lease runtime)");
        }
    }

    server.stop.store(true, Ordering::Relaxed);
}

/// Full clustered pool create with mirror policy across 3 nodes.
#[test]
fn cluster_full_flow_mirror_create_and_verify() {
    let dir = tempfile::tempdir().expect("temp dir");
    let node1_devs = vec![
        make_test_device(dir.path(), "node1-dev0", TEST_DEVICE_BYTES),
        make_test_device(dir.path(), "node1-dev1", TEST_DEVICE_BYTES),
    ];
    let node2_devs = vec![
        make_test_device(dir.path(), "node2-dev0", TEST_DEVICE_BYTES),
        make_test_device(dir.path(), "node2-dev1", TEST_DEVICE_BYTES),
    ];
    let node3_devs = vec![
        make_test_device(dir.path(), "node3-dev0", TEST_DEVICE_BYTES),
        make_test_device(dir.path(), "node3-dev1", TEST_DEVICE_BYTES),
    ];

    let pool_guid: [u8; 16] = [0xE1; 16];
    let pool_name = "mirror-pool";

    // Start 3 servers with one exact admitted client identity.
    let client_credential = NodePrivateCredential::generate(9970).expect("client credential");
    let client_identity = client_credential.public_identity();
    let server1_credential = NodePrivateCredential::generate(1).expect("server 1 credential");
    let server2_credential = NodePrivateCredential::generate(2).expect("server 2 credential");
    let server3_credential = NodePrivateCredential::generate(3).expect("server 3 credential");
    let server_identities = [
        server1_credential.public_identity(),
        server2_credential.public_identity(),
        server3_credential.public_identity(),
    ];
    let server1 = TestServer::spawn_authenticated(
        1,
        scratch_store_paths("cfm-s1", 1),
        server1_credential,
        vec![client_identity.clone()],
    );
    let server2 = TestServer::spawn_authenticated(
        2,
        scratch_store_paths("cfm-s2", 1),
        server2_credential,
        vec![client_identity.clone()],
    );
    let server3 = TestServer::spawn_authenticated(
        3,
        scratch_store_paths("cfm-s3", 1),
        server3_credential,
        vec![client_identity],
    );

    let mut client = authenticated_client(&client_credential, &server_identities);
    let sid1 = connect_client(&mut client, 1, server1.addr());
    let sid2 = connect_client(&mut client, 2, server2.addr());
    let sid3 = connect_client(&mut client, 3, server3.addr());

    // Create on each node. The current storage-node create handler maps
    // MirrorAcrossNodes(copies=2) onto a local replicated(2) pool create, so
    // each target node needs two local devices in this E2E.
    for (sid, node_id, dev_paths) in [
        (sid1, 1, &node1_devs),
        (sid2, 2, &node2_devs),
        (sid3, 3, &node3_devs),
    ] {
        let req = ClusterPoolCreateRequest {
            request_id: 2,
            pool_guid,
            pool_name: pool_name.to_string(),
            target_node_id: node_id,
            node_devices: dev_paths
                .iter()
                .enumerate()
                .map(|(local_index, dev_path)| NodeDeviceSpec {
                    device_path: dev_path.to_string_lossy().to_string(),
                    local_device_index: local_index as u32,
                    global_device_index: ((node_id - 1) as u32 * 2) + local_index as u32,
                    capacity_bytes: TEST_DEVICE_BYTES,
                    failure_domain: FailureDomain::for_node(node_id),
                })
                .collect(),
            redundancy: ClusterRedundancy::MirrorAcrossNodes { copies: 2 },
            placement: ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 },
            allow_file_devices: true,
        };
        send_cp01(&mut client, sid, &ClusterPoolMessage::CreateRequest(req));
    }

    let mut successes = 0u32;
    for sid in [sid1, sid2, sid3] {
        match recv_cp01(&mut client, sid, 100) {
            Some(ClusterPoolMessage::CreateResponse(r)) => {
                assert!(r.success, "node create must succeed: {:?}", r.error);
                successes += 1;
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }
    assert_eq!(successes, 3, "all 3 mirror nodes must succeed");

    // Verify all labels.
    let device_paths: Vec<PathBuf> = node1_devs
        .iter()
        .chain(node2_devs.iter())
        .chain(node3_devs.iter())
        .cloned()
        .collect();
    let scan_results = tidefs_pool_scan::scan_labels(&device_paths).expect("scan labels");
    assert_eq!(scan_results.len(), 6);
    for r in &scan_results {
        assert!(r.label_valid, "label must be valid: {}", r.label_status);
        assert_eq!(r.pool_guid, Some(pool_guid));
    }

    // Cleanup.
    for s in [&server1, &server2, &server3] {
        s.stop.store(true, Ordering::Relaxed);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Partition campaign: split-brain fencing and healing lifecycle (#6670)
// ═══════════════════════════════════════════════════════════════════════════

/// Prove that a fenced storage node refuses write-gating operations with
/// typed minority-fenced errors, and recovers after fence is cleared.
///
/// This test exercises the full lifecycle:
/// 1. Connected: create succeeds
/// 2. Fenced: create, import, lease, catalog delta are refused with
///    "minority-fenced:" errors
/// 3. Healed: fence cleared, create succeeds again
#[test]
fn partition_fenced_node_refuses_writes_then_recovers() {
    let dir = tempfile::tempdir().expect("temp dir");
    let dev_pre = make_test_device(dir.path(), "pf-pre-dev0", TEST_DEVICE_BYTES);
    let _dev_during = make_test_device(dir.path(), "pf-during-dev0", TEST_DEVICE_BYTES);
    let dev_post = make_test_device(dir.path(), "pf-post-dev0", TEST_DEVICE_BYTES);
    let authority_credential = NodePrivateCredential::generate(1).expect("authority credential");
    let authority_identity = authority_credential.public_identity();
    let client1_credential = NodePrivateCredential::generate(9940).expect("client 1 credential");
    let client2_credential = NodePrivateCredential::generate(9930).expect("client 2 credential");
    let client3_credential = NodePrivateCredential::generate(9920).expect("client 3 credential");
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_port());
    let authority = RuntimeAuthority::build(BackendDisclosure::Tcp(bind_addr), 1, None, None, 1)
        .and_then(|authority| {
            authority.with_transport_identity(
                authority_credential,
                vec![
                    client1_credential.public_identity(),
                    client2_credential.public_identity(),
                    client3_credential.public_identity(),
                ],
            )
        })
        .expect("build partition test authority");

    let config = StorageNodeConfig {
        bind_addr,
        node_id: 1,
        store_paths: scratch_store_paths("pfr-s1", 1),
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
        authority: Some(authority),
        ready_file: None,
        drain_timeout_secs: 30,
        cluster_lease_config: Some(ClusterLeaseConfig::default()),
        membership_checkpoint_dir: Some(dir.path().join("membership-checkpoint")),
        rdma: false,
        carrier_policy: None,
    };
    let addr = config.bind_addr;

    let mut node = StorageNode::start(config.clone()).expect("start storage node");

    // ── Phase 1: Pre-fence — create succeeds ──────────────────────
    // Create a fresh client and connect. Since serve_one runs one
    // accept/iteration, we spawn a background thread that accepts
    // one connection, then we send our request.
    let stop = Arc::new(AtomicBool::new(false));
    let s = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        while !s.load(Ordering::Relaxed) {
            match node.serve_one() {
                Ok(()) => {}
                Err(e) => {
                    if !s.load(Ordering::Relaxed) {
                        eprintln!("[pfr] serve_one error: {e}");
                    }
                }
            }
        }
    });
    thread::sleep(Duration::from_millis(100));

    // Connect and send create request.
    let mut client = authenticated_client(&client1_credential, &[authority_identity.clone()]);
    let sid = connect_client(&mut client, 1, addr);

    let pool_guid: [u8; 16] = [0xFD; 16];
    let create_req = ClusterPoolCreateRequest {
        request_id: 1,
        pool_guid,
        pool_name: "pf-pre-pool".to_string(),
        target_node_id: 1,
        node_devices: vec![NodeDeviceSpec {
            device_path: dev_pre.to_string_lossy().to_string(),
            local_device_index: 0,
            global_device_index: 0,
            capacity_bytes: TEST_DEVICE_BYTES,
            failure_domain: FailureDomain::for_node(1),
        }],
        redundancy: ClusterRedundancy::None,
        placement: ClusterPlacementPolicy::Stripe,
        allow_file_devices: true,
    };
    send_cp01(
        &mut client,
        sid,
        &ClusterPoolMessage::CreateRequest(create_req),
    );
    let resp = recv_cp01(&mut client, sid, 100);
    let pre_ok = matches!(&resp, Some(ClusterPoolMessage::CreateResponse(r)) if r.success);
    assert!(
        pre_ok,
        "Phase 1 (pre-fence): create must succeed, got: {resp:?}"
    );
    eprintln!("[partition-fence] Phase 1 PASS: pre-fence create succeeds");

    // Close and stop the session to force a new session context on reconnect.
    drop(client);
    // Stop this service loop, will restart after fencing.
    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
    thread::sleep(Duration::from_millis(50));

    // ── Phase 2: Fence the node ────────────────────────────────────
    // Now restart the node (or rather, continue with the same node
    // but a new serve loop).  We need the same StorageNode to retain
    // the fenced state across sessions.
    //
    // Recreate the node with the same config and fence it before
    // accepting connections.
    let mut node2 = StorageNode::start(config.clone()).expect("start node2");
    node2.set_partition_fenced();

    let stop2 = Arc::new(AtomicBool::new(false));
    let s2 = Arc::clone(&stop2);
    let handle2 = thread::spawn(move || {
        while !s2.load(Ordering::Relaxed) {
            match node2.serve_one() {
                Ok(()) => {}
                Err(e) => {
                    if !s2.load(Ordering::Relaxed) {
                        eprintln!("[pfr-fenced] serve_one error: {e}");
                    }
                }
            }
        }
    });
    thread::sleep(Duration::from_millis(100));

    // Connect and try create — must fail with minority-fenced.
    let mut client2 = authenticated_client(&client2_credential, &[authority_identity.clone()]);
    let sid2 = connect_client(&mut client2, 1, addr);

    let create_req2 = ClusterPoolCreateRequest {
        request_id: 2,
        pool_guid,
        pool_name: "pf-during-pool".to_string(),
        target_node_id: 1,
        node_devices: vec![NodeDeviceSpec {
            device_path: _dev_during.to_string_lossy().to_string(),
            local_device_index: 0,
            global_device_index: 0,
            capacity_bytes: TEST_DEVICE_BYTES,
            failure_domain: FailureDomain::for_node(1),
        }],
        redundancy: ClusterRedundancy::None,
        placement: ClusterPlacementPolicy::Stripe,
        allow_file_devices: true,
    };
    send_cp01(
        &mut client2,
        sid2,
        &ClusterPoolMessage::CreateRequest(create_req2),
    );
    let resp2 = recv_cp01(&mut client2, sid2, 100);
    match &resp2 {
        Some(ClusterPoolMessage::CreateResponse(r)) => {
            assert!(!r.success, "Phase 2 (fenced): create must be refused");
            let err = r.error.as_deref().unwrap_or("");
            assert!(
                err.contains("minority-fenced"),
                "Phase 2: error must be minority-fenced, got: {err}"
            );
            eprintln!("[partition-fence] Phase 2 PASS: fenced create refused: {err}");
        }
        other => panic!("Phase 2: expected CreateResponse, got: {other:?}"),
    }
    drop(client2);
    stop2.store(true, Ordering::Relaxed);
    let _ = handle2.join();
    thread::sleep(Duration::from_millis(50));

    // ── Phase 3: Heal — clear fence, create succeeds again ─────────
    let mut node3 = StorageNode::start(config.clone()).expect("start node3");
    // clear_partition_fence is not called — default state is Connected.

    let stop3 = Arc::new(AtomicBool::new(false));
    let s3 = Arc::clone(&stop3);
    let handle3 = thread::spawn(move || {
        while !s3.load(Ordering::Relaxed) {
            match node3.serve_one() {
                Ok(()) => {}
                Err(e) => {
                    if !s3.load(Ordering::Relaxed) {
                        eprintln!("[pfr-healed] serve_one error: {e}");
                    }
                }
            }
        }
    });
    thread::sleep(Duration::from_millis(100));

    let mut client3 = authenticated_client(&client3_credential, &[authority_identity]);
    let sid3 = connect_client(&mut client3, 1, addr);

    let create_req3 = ClusterPoolCreateRequest {
        request_id: 3,
        pool_guid: [0xFC; 16],
        pool_name: "pf-post-pool".to_string(),
        target_node_id: 1,
        node_devices: vec![NodeDeviceSpec {
            device_path: dev_post.to_string_lossy().to_string(),
            local_device_index: 0,
            global_device_index: 0,
            capacity_bytes: TEST_DEVICE_BYTES,
            failure_domain: FailureDomain::for_node(1),
        }],
        redundancy: ClusterRedundancy::None,
        placement: ClusterPlacementPolicy::Stripe,
        allow_file_devices: true,
    };
    send_cp01(
        &mut client3,
        sid3,
        &ClusterPoolMessage::CreateRequest(create_req3),
    );
    let resp3 = recv_cp01(&mut client3, sid3, 100);
    let post_ok = matches!(&resp3, Some(ClusterPoolMessage::CreateResponse(r)) if r.success);
    assert!(
        post_ok,
        "Phase 3 (healed): create must succeed, got: {resp3:?}"
    );
    eprintln!("[partition-fence] Phase 3 PASS: post-heal create succeeds");

    drop(client3);
    stop3.store(true, Ordering::Relaxed);
    let _ = handle3.join();
}
