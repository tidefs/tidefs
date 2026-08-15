// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg(feature = "cluster")]

use std::fs::{self, File};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

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
use tidefs_lock_service::{DatasetMountIdentity, EpochId, MemberId};
use tidefs_posix_filesystem_adapter_daemon::cluster_vfs_rpc_client::{
    ClusterVfsRpcClient, ClusterVfsRpcClientError,
};
use tidefs_posix_filesystem_adapter_daemon::cluster_vfs_rpc_owner::{
    ClusterVfsRpcOwnerConfig, ClusterVfsRpcOwnerHandle, ClusterVfsRpcWriterFence,
};
use tidefs_posix_filesystem_adapter_daemon::clustered_mount::{
    ClusteredPosixAuthoritySnapshot, ClusteredPosixMountRuntime,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;
use tidefs_recovery_loop::RecoveryPolicy;
use tidefs_transport::{
    EndpointFamily, NodeInfo, SessionId, Transport, TransportAddr, TransportError,
};
use tidefs_types_vfs_core::{Errno, RequestCtx, ROOT_INODE_ID};
use tidefs_vfs_engine::dispatch::VfsDispatchEngineBridge;
use tidefs_vfs_engine::VfsEngine;
use tidefs_vfs_rpc::DatasetId;

const OWNER_NODE: u64 = 2;
const CLIENT_NODE: u64 = 1;
const WRITER_TERM: u64 = 77;
const WRITER_EPOCH: u64 = 9;

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
        Arc::new(
            NodePrivateCredential::decode_fixed(&self.credential_bytes)
                .expect("decode provisioned test credential"),
        )
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

fn runtime(
    dataset_id: DatasetId,
    writer: u64,
    term: u64,
    epoch: u64,
) -> ClusteredPosixMountRuntime {
    ClusteredPosixMountRuntime::open_committed_mount(
        DatasetMountIdentity::new(11, 12, epoch),
        ClusteredPosixAuthoritySnapshot {
            current_epoch: EpochId::new(epoch),
            current_term: term,
            lock_leader: MemberId::new(OWNER_NODE),
            vfs_dataset_id: dataset_id,
            vfs_writer: MemberId::new(writer),
            admission_generation: 1,
        },
    )
    .expect("admit committed clustered mount authority")
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

fn assert_get_root_refused(
    owner_addr: SocketAddr,
    authority: ClusteredPosixMountRuntime,
    expected: Errno,
    client_identity: &ProvisionedIdentity,
    owner_identity: &ProvisionedIdentity,
) {
    let (transport, session_id) = connect(owner_addr, client_identity, owner_identity);
    let client = ClusterVfsRpcClient::new(transport, session_id, authority)
        .expect("construct authenticated cluster VFS_RPC client");
    let bridge = VfsDispatchEngineBridge::new(client);

    assert_eq!(bridge.get_root_inode(&request_ctx()).unwrap_err(), expected);
    bridge
        .dispatch_ref()
        .close()
        .expect("close refused cluster VFS_RPC client");
}

#[test]
fn adapter_engine_drives_pool_owner_and_refuses_stale_authority() {
    let owner_identity = ProvisionedIdentity::new(OWNER_NODE);
    let client_identity = ProvisionedIdentity::new(CLIENT_NODE);
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
        CLIENT_NODE,
        owner_identity.credential(),
        client_identity.public_identity(),
        dataset_id,
        Arc::clone(&writer_fence),
        owner_adapter.engine_handle(),
        Arc::clone(&shutdown),
    ))
    .expect("start Pool-backed VFS_RPC owner");

    let (transport, session_id) = connect(owner.bound_addr(), &client_identity, &owner_identity);
    let client = ClusterVfsRpcClient::new(
        transport,
        session_id,
        runtime(dataset_id, OWNER_NODE, WRITER_TERM, WRITER_EPOCH),
    )
    .expect("construct admitted cluster VFS_RPC client");
    let remote_adapter = FuseVfsAdapter::new(Box::new(VfsDispatchEngineBridge::new(client)))
        .expect("construct FUSE adapter over authenticated cluster VFS_RPC");
    let remote_engine = remote_adapter.engine_handle();
    let ctx = request_ctx();

    {
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

        let expected = b"Pool receipts reached through the adapter-held remote engine";
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

        *writer_fence.lock().expect("lock writer fence") =
            ClusterVfsRpcWriterFence::new(OWNER_NODE, WRITER_TERM + 1, WRITER_EPOCH);
        assert_eq!(engine.get_root_inode(&ctx).unwrap_err(), Errno::ESTALE);
        *writer_fence.lock().expect("lock writer fence") =
            ClusterVfsRpcWriterFence::new(OWNER_NODE, WRITER_TERM, WRITER_EPOCH + 1);
        assert_eq!(engine.get_root_inode(&ctx).unwrap_err(), Errno::ESTALE);
        *writer_fence.lock().expect("lock writer fence") =
            ClusterVfsRpcWriterFence::new(OWNER_NODE, WRITER_TERM, WRITER_EPOCH);
    }

    drop(remote_engine);
    drop(remote_adapter);
    owner
        .stop()
        .expect("stop primary Pool-backed VFS_RPC owner");

    let mut owner = ClusterVfsRpcOwnerHandle::start(ClusterVfsRpcOwnerConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        OWNER_NODE,
        CLIENT_NODE,
        owner_identity.credential(),
        client_identity.public_identity(),
        dataset_id,
        Arc::clone(&writer_fence),
        owner_adapter.engine_handle(),
        Arc::clone(&shutdown),
    ))
    .expect("restart Pool-backed VFS_RPC owner with fresh session authority");

    let untrusted_same_node = ProvisionedIdentity::new(CLIENT_NODE);
    assert!(
        connect_result(owner.bound_addr(), &untrusted_same_node, &owner_identity,).is_err(),
        "a different key for the admitted numeric peer ID must fail the real handshake"
    );
    owner
        .check_health()
        .expect("owner must remain healthy after refusing the untrusted key");
    owner
        .stop()
        .expect("stop owner after the deliberate authentication refusal");
    let mut owner = ClusterVfsRpcOwnerHandle::start(ClusterVfsRpcOwnerConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        OWNER_NODE,
        CLIENT_NODE,
        owner_identity.credential(),
        client_identity.public_identity(),
        dataset_id,
        Arc::clone(&writer_fence),
        owner_adapter.engine_handle(),
        Arc::clone(&shutdown),
    ))
    .expect("restart exact-trust owner after the negative handshake proof");

    assert_get_root_refused(
        owner.bound_addr(),
        runtime(
            DatasetId::new(if dataset_id.0 == 1 { 2 } else { 1 }),
            OWNER_NODE,
            WRITER_TERM,
            WRITER_EPOCH,
        ),
        Errno::ESTALE,
        &client_identity,
        &owner_identity,
    );

    let (wrong_writer_transport, wrong_writer_session) =
        connect(owner.bound_addr(), &client_identity, &owner_identity);
    match ClusterVfsRpcClient::new(
        wrong_writer_transport,
        wrong_writer_session,
        runtime(dataset_id, OWNER_NODE + 1, WRITER_TERM, WRITER_EPOCH),
    ) {
        Err(ClusterVfsRpcClientError::WrongPeer {
            expected_writer,
            authenticated_peer,
        }) => {
            assert_eq!(expected_writer, OWNER_NODE + 1);
            assert_eq!(authenticated_peer, OWNER_NODE);
        }
        Err(other) => panic!("unexpected wrong-writer refusal: {other}"),
        Ok(_) => panic!("wrong VFS writer must fail closed"),
    }

    let (wrong_session_transport, _actual_session) =
        connect(owner.bound_addr(), &client_identity, &owner_identity);
    let missing_session = SessionId::new(u64::MAX);
    match ClusterVfsRpcClient::new(
        wrong_session_transport,
        missing_session,
        runtime(dataset_id, OWNER_NODE, WRITER_TERM, WRITER_EPOCH),
    ) {
        Err(ClusterVfsRpcClientError::MissingSession(found)) => {
            assert_eq!(found, missing_session);
        }
        Err(other) => panic!("unexpected wrong-session refusal: {other}"),
        Ok(_) => panic!("unknown transport session must fail closed"),
    }

    owner.stop().expect("stop Pool-backed VFS_RPC owner");
    assert!(!shutdown.load(Ordering::Acquire));
    drop(owner_adapter);
}
