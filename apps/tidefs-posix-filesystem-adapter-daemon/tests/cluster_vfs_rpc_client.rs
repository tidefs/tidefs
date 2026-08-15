// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg(feature = "cluster")]

use std::fs::{self, File};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tidefs_auth::{
    NodeKeyStore, NodePrivateCredential, NodePublicIdentity, NODE_PRIVATE_CREDENTIAL_WIRE_SIZE,
    NODE_PUBLIC_IDENTITY_WIRE_SIZE,
};
use tidefs_dataset_lifecycle::{DatasetFlags, DatasetId as LifecycleDatasetId, SyncGuarantee};
use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    LocalFileSystemOpenConfig, LocalStorageAllocatorPolicy, RootAuthenticationKey,
};
use tidefs_local_object_store::pool::PoolRedundancyPolicy;
use tidefs_posix_filesystem_adapter_daemon::cluster_vfs_rpc_client::{
    ClusterVfsRpcClient, ClusterVfsRpcClientConfig, ClusterVfsRpcClientError,
};
use tidefs_posix_filesystem_adapter_daemon::cluster_vfs_rpc_owner::{
    ClusterVfsRpcOwnerConfig, ClusterVfsRpcOwnerHandle, ClusterVfsRpcWriterFence,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;
use tidefs_recovery_loop::RecoveryPolicy;
use tidefs_transport::{
    EndpointFamily, NodeInfo, SessionId, Transport, TransportAddr, TransportError,
};
use tidefs_types_vfs_core::{Errno, RequestCtx, ROOT_INODE_ID};
use tidefs_vfs_engine::dispatch::VfsDispatchEngineBridge;
use tidefs_vfs_rpc::DatasetId;

const OWNER_NODE: u64 = 2;
const CLIENT_NODE: u64 = 1;
const CLIENT_B_NODE: u64 = 3;
const WRITER_TERM: u64 = 77;
const WRITER_EPOCH: u64 = 9;
const POOL_GUID: [u8; 16] = [0x49; 16];

struct ProvisionedIdentity {
    credential_bytes: [u8; NODE_PRIVATE_CREDENTIAL_WIRE_SIZE],
    public_bytes: [u8; NODE_PUBLIC_IDENTITY_WIRE_SIZE],
}

impl Drop for ProvisionedIdentity {
    fn drop(&mut self) {
        self.credential_bytes.fill(0);
    }
}

impl ProvisionedIdentity {
    fn new(node_id: u64) -> Self {
        let credential = NodePrivateCredential::generate(node_id).expect("provision test identity");
        Self {
            credential_bytes: credential.encode_fixed(),
            public_bytes: credential.public_identity().encode_fixed(),
        }
    }

    fn credential(&self) -> Arc<NodePrivateCredential> {
        Arc::new(self.private_credential())
    }

    fn private_credential(&self) -> NodePrivateCredential {
        NodePrivateCredential::decode_fixed(&self.credential_bytes)
            .expect("decode provisioned test credential")
    }

    fn public_identity(&self) -> NodePublicIdentity {
        NodePublicIdentity::decode_fixed(&self.public_bytes)
            .expect("decode provisioned test public identity")
    }
}

fn connect(
    owner_addr: SocketAddr,
    client_identity: &ProvisionedIdentity,
    owner_identity: &ProvisionedIdentity,
) -> (Transport, SessionId) {
    connect_result(owner_addr, client_identity, owner_identity)
        .expect("authenticate exact provisioned owner transport")
}

fn connect_result(
    owner_addr: SocketAddr,
    client_identity: &ProvisionedIdentity,
    owner_identity: &ProvisionedIdentity,
) -> Result<(Transport, SessionId), TransportError> {
    let credential = client_identity.credential();
    let local_public = credential.public_identity().into_identity();
    let mut known_identities = NodeKeyStore::new();
    known_identities
        .register(local_public.clone())
        .expect("register local test identity");
    known_identities
        .register(owner_identity.public_identity().into_identity())
        .expect("register exact owner test identity");
    let mut transport = Transport::new(CLIENT_NODE)
        .with_attestation(
            credential.keypair().expect("load test credential"),
            local_public,
        )
        .with_known_identities(known_identities)
        .with_epoch(WRITER_EPOCH);
    transport.set_endpoint_family(EndpointFamily::Control);
    transport.set_attestation_bootstrap_from_handshake(false);
    transport.add_node(NodeInfo::new(
        OWNER_NODE,
        vec![TransportAddr::Tcp(owner_addr)],
        0,
    ));
    let session_id = transport.connect(OWNER_NODE)?;
    transport.perform_handshake(session_id)?;
    assert!(transport.session_has_authenticated_confidentiality(session_id));
    Ok((transport, session_id))
}

fn request_ctx() -> RequestCtx {
    RequestCtx {
        uid: 0,
        gid: 4242,
        pid: 9191,
        umask: 0o027,
        groups: vec![4242, 4343],
    }
}

#[test]
fn connector_refuses_owner_epoch_movement_before_authority() {
    let owner_identity = ProvisionedIdentity::new(OWNER_NODE);
    let client_identity = ProvisionedIdentity::new(CLIENT_NODE);
    let owner_credential = owner_identity.credential();
    let owner_public = owner_credential.public_identity().into_identity();
    let mut known_identities = NodeKeyStore::new();
    known_identities
        .register(owner_public.clone())
        .expect("register owner identity");
    known_identities
        .register(client_identity.public_identity().into_identity())
        .expect("register client identity");
    let mut owner = Transport::new(OWNER_NODE)
        .with_attestation(
            owner_credential.keypair().expect("load owner keypair"),
            owner_public,
        )
        .with_known_identities(known_identities)
        .with_epoch(WRITER_EPOCH);
    owner.set_endpoint_family(EndpointFamily::Control);
    owner.set_attestation_bootstrap_from_handshake(false);
    owner
        .bind(TransportAddr::Tcp("127.0.0.1:0".parse().unwrap()))
        .expect("bind epoch-moving owner");
    let owner_addr = match owner.bind_addr {
        Some(TransportAddr::Tcp(addr)) => addr,
        _ => panic!("owner must publish its TCP address"),
    };

    let owner_handle = std::thread::spawn(move || {
        let accept = |transport: &mut Transport| {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match transport.accept_incoming() {
                    Ok(session_id) => break session_id,
                    Err(TransportError::Generic(message))
                        if message == "no pending connections" =>
                    {
                        assert!(Instant::now() < deadline, "owner accept timed out");
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("owner accept failed: {error}"),
                }
            }
        };

        let discovery = accept(&mut owner);
        assert!(matches!(
            owner.perform_handshake(discovery),
            Err(TransportError::AttestedEpochMismatch {
                proposed_epoch: 0,
                required_epoch: WRITER_EPOCH,
                ..
            })
        ));
        owner.epoch = WRITER_EPOCH + 1;
        let retry = accept(&mut owner);
        assert!(matches!(
            owner.perform_handshake(retry),
            Err(TransportError::AttestedEpochMismatch {
                proposed_epoch: WRITER_EPOCH,
                required_epoch,
                ..
            }) if required_epoch == WRITER_EPOCH + 1
        ));
    });

    match ClusterVfsRpcClient::connect(ClusterVfsRpcClientConfig::new(
        owner_addr,
        POOL_GUID,
        client_identity.private_credential(),
        owner_identity.public_identity(),
    )) {
        Err(ClusterVfsRpcClientError::EpochMoved {
            authenticated_peer,
            attempted_epoch,
            required_epoch,
        }) => {
            assert_eq!(authenticated_peer, OWNER_NODE);
            assert_eq!(attempted_epoch, WRITER_EPOCH);
            assert_eq!(required_epoch, WRITER_EPOCH + 1);
        }
        Err(other) => panic!("unexpected epoch-movement refusal: {other}"),
        Ok(_) => panic!("epoch movement must fail before client construction"),
    }
    owner_handle.join().expect("epoch-moving owner thread");
}

#[test]
fn two_authenticated_adapter_engines_share_pool_owner_and_isolate_session_failure() {
    let owner_identity = ProvisionedIdentity::new(OWNER_NODE);
    let client_identity = ProvisionedIdentity::new(CLIENT_NODE);
    let client_b_identity = ProvisionedIdentity::new(CLIENT_B_NODE);
    let root = tempfile::tempdir().expect("create persistent test root");
    let metadata_dir = root.path().join("metadata");
    let member = root.path().join("member.img");
    fs::create_dir_all(&metadata_dir).expect("create Pool metadata directory");
    File::create(&member)
        .expect("create regular-file Pool member")
        .set_len(32 * 1024 * 1024)
        .expect("size regular-file Pool member");

    let mut root_filesystem = LocalFileSystem::open_with_block_devices_and_recovery_policy(
        &metadata_dir,
        std::slice::from_ref(&member),
        "tidefs-vfs-rpc-client",
        PoolRedundancyPolicy::default(),
        StoreOptions::default(),
        RootAuthenticationKey::demo_key(),
        RecoveryPolicy::default(),
    )
    .expect("open regular-file Pool-backed root filesystem");
    let canonical_dataset_id = LifecycleDatasetId::from_bytes([0x49; 16]);
    root_filesystem
        .create_filesystem_dataset(
            "clustered",
            canonical_dataset_id,
            Vec::new(),
            DatasetFlags::default_create(),
            SyncGuarantee::Local,
        )
        .expect("publish nonzero clustered filesystem dataset identity");
    drop(root_filesystem);

    let filesystem = LocalFileSystem::open_named_pool_filesystem_dataset_with_allocator_policy_and_root_authentication_key(
        &metadata_dir,
        "tidefs-vfs-rpc-client",
        PoolRedundancyPolicy::default(),
        "clustered",
        LocalFileSystemOpenConfig {
            options: StoreOptions::default(),
            allocator_policy: LocalStorageAllocatorPolicy::default(),
            root_authentication_key: RootAuthenticationKey::demo_key(),
            encryption: None,
            compression: None,
            log_device_device_path: None,
            recovery_policy: RecoveryPolicy::default(),
            block_devices: Some(std::slice::from_ref(&member)),
        },
    )
    .expect("open exact named Pool-backed filesystem dataset");
    assert_eq!(filesystem.pool_topology_status().present_members, 1);
    assert_eq!(
        filesystem.mounted_dataset_id(),
        *canonical_dataset_id.as_bytes()
    );
    let dataset_id = DatasetId::new(u128::from_le_bytes(filesystem.mounted_dataset_id()));
    let owner_adapter = FuseVfsAdapter::new(Box::new(VfsLocalFileSystem::new(filesystem)))
        .expect("create exact Pool-backed owner adapter");
    let shutdown = Arc::new(AtomicBool::new(false));
    let writer_fence = Arc::new(Mutex::new(ClusterVfsRpcWriterFence::new(
        OWNER_NODE,
        WRITER_TERM,
        WRITER_EPOCH,
    )));
    let mut owner = ClusterVfsRpcOwnerHandle::start(ClusterVfsRpcOwnerConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        OWNER_NODE,
        owner_identity.credential(),
        vec![
            client_identity.public_identity(),
            client_b_identity.public_identity(),
        ],
        POOL_GUID,
        dataset_id,
        Arc::clone(&writer_fence),
        owner_adapter.engine_handle(),
        Arc::clone(&shutdown),
    ))
    .expect("start Pool-backed VFS_RPC owner");

    let client = ClusterVfsRpcClient::connect(ClusterVfsRpcClientConfig::new(
        owner.bound_addr(),
        POOL_GUID,
        client_identity.private_credential(),
        owner_identity.public_identity(),
    ))
    .expect("discover owner epoch and construct admitted cluster VFS_RPC client");
    let remote_adapter = FuseVfsAdapter::new(Box::new(VfsDispatchEngineBridge::new(client)))
        .expect("construct FUSE adapter over authenticated cluster VFS_RPC");
    let remote_engine = remote_adapter.engine_handle();
    let ctx = request_ctx();

    let expected = b"Pool receipts reached through the adapter-held remote engine";
    let created_inode = {
        let engine = remote_engine.lock().expect("lock remote adapter engine");
        let root_inode = engine.get_root_inode(&ctx).expect("remote typed GetRoot");
        assert_eq!(root_inode, ROOT_INODE_ID);

        let (created, created_handle) = engine
            .create(root_inode, b"remote-file", 0o777, libc::O_RDWR as u32, &ctx)
            .expect("create file through remote adapter engine");
        assert_eq!(created.posix.mode & 0o777, 0o750);
        assert_eq!(created.posix.uid, ctx.uid);
        assert_eq!(created.posix.gid, ctx.gid);
        assert_eq!(
            engine
                .create_excl(root_inode, b"exclusive", 0o600, libc::O_RDWR as u32, &ctx)
                .unwrap_err(),
            Errno::ENOSYS
        );

        let looked_up = engine
            .lookup(root_inode, b"remote-file", &ctx)
            .expect("lookup file through remote adapter engine");
        assert_eq!(looked_up.inode_id, created.inode_id);
        assert_eq!(
            engine
                .getattr(created.inode_id, Some(&created_handle), &ctx)
                .expect("getattr through remote adapter engine")
                .inode_id,
            created.inode_id
        );

        assert_eq!(
            engine
                .write(&created_handle, 0, expected, &ctx)
                .expect("write through remote adapter engine"),
            expected.len() as u32
        );
        engine
            .flush(&created_handle, &ctx)
            .expect("flush through remote adapter engine");
        engine
            .fsync(&created_handle, false, &ctx)
            .expect("fsync through remote adapter engine");
        engine
            .release(&created_handle)
            .expect("release created remote handle");

        let reopened = engine
            .open(created.inode_id, libc::O_RDONLY as u32, &ctx)
            .expect("open file through remote adapter engine");
        assert_eq!(
            engine
                .read(&reopened, 0, expected.len() as u32, &ctx)
                .expect("read through remote adapter engine"),
            expected
        );
        engine
            .release(&reopened)
            .expect("release reopened remote handle");
        assert!(engine.statfs(&ctx).expect("remote statfs").block_size > 0);

        created.inode_id
    };

    let client_b = ClusterVfsRpcClient::connect(ClusterVfsRpcClientConfig::new(
        owner.bound_addr(),
        POOL_GUID,
        client_b_identity.private_credential(),
        owner_identity.public_identity(),
    ))
    .expect("connect second independently authenticated cluster VFS_RPC client");
    let remote_adapter_b = FuseVfsAdapter::new(Box::new(VfsDispatchEngineBridge::new(client_b)))
        .expect("construct second FUSE adapter over authenticated cluster VFS_RPC");
    let remote_engine_b = remote_adapter_b.engine_handle();
    let peer_b_suffix = b"; peer B committed this suffix";
    let directory_inode = {
        let engine = remote_engine_b
            .lock()
            .expect("lock second remote adapter engine");
        let root_inode = engine
            .get_root_inode(&ctx)
            .expect("second peer typed GetRoot");
        let found = engine
            .lookup(root_inode, b"remote-file", &ctx)
            .expect("second peer observes first peer namespace commit");
        assert_eq!(found.inode_id, created_inode);
        let handle = engine
            .open(created_inode, libc::O_RDWR as u32, &ctx)
            .expect("second peer opens first peer file");
        assert_eq!(
            engine
                .read(&handle, 0, expected.len() as u32, &ctx)
                .expect("second peer reads first peer data"),
            expected
        );
        assert_eq!(
            engine
                .write(&handle, expected.len() as u64, peer_b_suffix, &ctx)
                .expect("second peer mutates first peer file"),
            peer_b_suffix.len() as u32
        );
        engine
            .fsync(&handle, false, &ctx)
            .expect("second peer commits its mutation");
        engine
            .release(&handle)
            .expect("second peer releases shared file");

        let directory = engine
            .mkdir(root_inode, b"remote-dir", 0o777, &ctx)
            .expect("second peer creates shared directory");
        engine
            .rename(
                root_inode,
                b"remote-file",
                directory.inode_id,
                b"renamed",
                0,
                &ctx,
            )
            .expect("second peer renames first peer file");

        directory.inode_id
    };

    let untrusted_same_node = ProvisionedIdentity::new(CLIENT_NODE);
    assert!(
        ClusterVfsRpcClient::connect(ClusterVfsRpcClientConfig::new(
            owner.bound_addr(),
            POOL_GUID,
            untrusted_same_node.private_credential(),
            owner_identity.public_identity(),
        ))
        .is_err(),
        "a different key for an admitted numeric peer ID must fail the live handshake"
    );
    owner
        .check_health()
        .expect("untrusted peer refusal must not kill the owner");

    {
        let engine = remote_engine.lock().expect("relock first remote engine");
        let root_inode = engine
            .get_root_inode(&ctx)
            .expect("first peer remains usable after second and untrusted connections");
        let directory = engine
            .lookup(root_inode, b"remote-dir", &ctx)
            .expect("first peer observes second peer directory mutation");
        assert_eq!(directory.inode_id, directory_inode);
        let renamed = engine
            .lookup(directory_inode, b"renamed", &ctx)
            .expect("first peer observes second peer rename");
        assert_eq!(renamed.inode_id, created_inode);
        let reopened = engine
            .open(created_inode, libc::O_RDONLY as u32, &ctx)
            .expect("first peer reopens second peer mutation");
        let combined = [expected.as_slice(), peer_b_suffix.as_slice()].concat();
        assert_eq!(
            engine
                .read(&reopened, 0, combined.len() as u32, &ctx)
                .expect("first peer reads second peer mutation"),
            combined
        );
        engine
            .release(&reopened)
            .expect("first peer releases reopened shared file");
        let linked = engine
            .link(created_inode, directory_inode, b"hard-link", &ctx)
            .expect("hard-link through remote adapter engine");
        assert_eq!(linked.inode_id, created_inode);
        assert_eq!(
            engine
                .lookup(directory_inode, b"renamed", &ctx)
                .expect("lookup renamed remote file")
                .inode_id,
            created_inode
        );
        assert_eq!(
            engine
                .lookup(directory_inode, b"hard-link", &ctx)
                .expect("lookup remote hard link")
                .inode_id,
            created_inode
        );
        engine
            .unlink(directory_inode, b"renamed", &ctx)
            .expect("unlink renamed remote file");
        assert_eq!(
            engine
                .lookup(directory_inode, b"renamed", &ctx)
                .unwrap_err(),
            Errno::ENOENT
        );
        engine
            .unlink(directory_inode, b"hard-link", &ctx)
            .expect("unlink remote hard link");
        engine
            .rmdir(root_inode, b"remote-dir", &ctx)
            .expect("rmdir through remote adapter engine");

        *writer_fence.lock().expect("lock writer fence") =
            ClusterVfsRpcWriterFence::new(OWNER_NODE, WRITER_TERM + 1, WRITER_EPOCH);
        assert_eq!(engine.get_root_inode(&ctx).unwrap_err(), Errno::ESTALE);
        *writer_fence.lock().expect("lock writer fence") =
            ClusterVfsRpcWriterFence::new(OWNER_NODE, WRITER_TERM, WRITER_EPOCH + 1);
        assert_eq!(engine.get_root_inode(&ctx).unwrap_err(), Errno::ESTALE);
        *writer_fence.lock().expect("lock writer fence") =
            ClusterVfsRpcWriterFence::new(OWNER_NODE, WRITER_TERM, WRITER_EPOCH);
    }

    assert_eq!(
        remote_engine_b
            .lock()
            .expect("relock second remote engine")
            .get_root_inode(&ctx)
            .expect("second peer remains usable after first peer activity"),
        ROOT_INODE_ID
    );

    drop(remote_engine);
    drop(remote_adapter);
    drop(remote_engine_b);
    drop(remote_adapter_b);
    owner
        .stop()
        .expect("stop primary Pool-backed VFS_RPC owner");

    let mut owner = ClusterVfsRpcOwnerHandle::start(ClusterVfsRpcOwnerConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        OWNER_NODE,
        owner_identity.credential(),
        vec![client_identity.public_identity()],
        POOL_GUID,
        dataset_id,
        Arc::clone(&writer_fence),
        owner_adapter.engine_handle(),
        Arc::clone(&shutdown),
    ))
    .expect("restart Pool-backed VFS_RPC owner with fresh session authority");

    match ClusterVfsRpcClient::connect(ClusterVfsRpcClientConfig::new(
        owner.bound_addr(),
        [0x50; 16],
        client_identity.private_credential(),
        owner_identity.public_identity(),
    )) {
        Err(ClusterVfsRpcClientError::WrongPool { expected, found }) => {
            assert_eq!(expected, [0x50; 16]);
            assert_eq!(found, POOL_GUID);
        }
        Err(other) => panic!("unexpected wrong-Pool refusal: {other}"),
        Ok(_) => panic!("wrong expected Pool must fail closed"),
    }

    let (wrong_session_transport, _actual_session) =
        connect(owner.bound_addr(), &client_identity, &owner_identity);
    let missing_session = SessionId::new(u64::MAX);
    match ClusterVfsRpcClient::new(wrong_session_transport, missing_session, POOL_GUID) {
        Err(ClusterVfsRpcClientError::MissingSession(found)) => {
            assert_eq!(found, missing_session);
        }
        Err(other) => panic!("unexpected wrong-session refusal: {other}"),
        Ok(_) => panic!("unknown transport session must fail closed"),
    }

    let unavailable_addr = owner.bound_addr();
    owner.stop().expect("stop Pool-backed VFS_RPC owner");
    assert!(
        ClusterVfsRpcClient::connect(ClusterVfsRpcClientConfig::new(
            unavailable_addr,
            POOL_GUID,
            client_identity.private_credential(),
            owner_identity.public_identity(),
        ))
        .is_err(),
        "an unavailable owner must fail before constructing a client"
    );
    assert!(!shutdown.load(Ordering::Acquire));
    drop(owner_adapter);
}
