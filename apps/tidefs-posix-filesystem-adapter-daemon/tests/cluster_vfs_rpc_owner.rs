// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg(feature = "cluster")]

use std::fs::{self, File};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

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
use tidefs_posix_filesystem_adapter_daemon::cluster_vfs_rpc_owner::{
    ClusterVfsRpcOwnerConfig, ClusterVfsRpcOwnerHandle, ClusterVfsRpcWriterFence,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;
use tidefs_recovery_loop::RecoveryPolicy;
use tidefs_transport::{
    ControlServiceFrame, EndpointFamily, NodeInfo, SessionId, Transport, TransportAddr,
    TransportSessionSet,
};
use tidefs_types_vfs_core::{Errno, ROOT_INODE_ID};
use tidefs_vfs_rpc::transport_adapter::{
    VfsRpcEnvelopeContext, VfsRpcInboundFrame, VfsRpcTransportAdapter, VfsRpcTransportAdapterConfig,
};
use tidefs_vfs_rpc::{
    DatasetId, InlineOrBulk, OpId, PeerId, VfsRpcCredentials, VfsRpcRequest, VfsRpcRequestPayload,
    VfsRpcResponse, VfsRpcResponsePayload, VfsRpcTransportFrame, REQ_FLAG_BULK_PENDING,
};

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

struct RpcClient {
    transport: Transport,
    session_id: SessionId,
    adapter: VfsRpcTransportAdapter,
    dataset_id: DatasetId,
    next_op_id: u64,
    next_sequence: u64,
}

impl RpcClient {
    fn connect(
        local_node: u64,
        owner_addr: SocketAddr,
        dataset_id: DatasetId,
        local_identity: &ProvisionedIdentity,
        owner_identity: &ProvisionedIdentity,
    ) -> Self {
        let credential = local_identity.credential();
        assert_eq!(credential.node_id(), local_node);
        let local_public = credential.public_identity().into_identity();
        let mut known_identities = NodeKeyStore::new();
        known_identities
            .register(local_public.clone())
            .expect("register local test identity");
        known_identities
            .register(owner_identity.public_identity().into_identity())
            .expect("register exact owner test identity");
        let mut transport = Transport::new(local_node)
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
        let session_id = transport
            .connect(OWNER_NODE)
            .expect("connect owner transport");
        transport
            .perform_handshake(session_id)
            .expect("authenticate owner transport");
        assert!(transport.session_has_authenticated_confidentiality(session_id));

        let mut sessions = TransportSessionSet::new();
        sessions.add_binding_with_epoch(OWNER_NODE, session_id, WRITER_EPOCH);
        sessions.mark_healthy(session_id);
        Self {
            transport,
            session_id,
            adapter: VfsRpcTransportAdapter::new(VfsRpcTransportAdapterConfig::default(), sessions),
            dataset_id,
            next_op_id: 1,
            next_sequence: 0,
        }
    }

    fn credentials() -> Option<VfsRpcCredentials> {
        Some(VfsRpcCredentials::root(PeerId(CLIENT_NODE)))
    }

    fn envelope_context(&mut self) -> VfsRpcEnvelopeContext {
        let context = VfsRpcEnvelopeContext {
            cohort_id: tidefs_transport::TransportCohortId::new(1),
            sequence_number: self.next_sequence,
            ack_floor: 0,
            visibility_class: tidefs_transport::VisibilityClass::Internal,
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        context
    }

    fn new_request(
        &mut self,
        term: u64,
        epoch: u64,
        flags: u16,
        payload: VfsRpcRequestPayload,
        credentials: Option<VfsRpcCredentials>,
    ) -> VfsRpcRequest {
        let op_id = OpId::new(self.next_op_id);
        self.next_op_id = self.next_op_id.saturating_add(1);
        VfsRpcRequest::new(
            op_id,
            OWNER_NODE,
            self.dataset_id,
            term,
            epoch,
            flags,
            payload,
            credentials,
        )
        .expect("encode VFS_RPC request")
    }

    fn round_trip(&mut self, request: &VfsRpcRequest) -> VfsRpcResponse {
        let context = self.envelope_context();
        let mut outbound = self
            .adapter
            .begin_request(PeerId(OWNER_NODE), request, Instant::now(), context)
            .expect("wrap VFS_RPC request");
        self.transport
            .send_envelope(&mut outbound.envelope, &outbound.payload)
            .expect("send VFS_RPC envelope");
        let (envelope, payload) = self
            .transport
            .recv_envelope(self.session_id)
            .expect("receive VFS_RPC response envelope");
        match self
            .adapter
            .unwrap_inbound(Instant::now(), &envelope, &payload)
            .expect("unwrap VFS_RPC response")
        {
            VfsRpcInboundFrame::Response { response, .. } => response,
            VfsRpcInboundFrame::Request { .. } => panic!("client received an owner request"),
        }
    }

    fn raw_bulk_round_trip(&mut self, request: &VfsRpcRequest) -> VfsRpcResponse {
        let placeholder = VfsRpcRequest::new(
            request.header.op_id,
            request.header.writer_node,
            request.header.dataset_id,
            request.header.term,
            request.header.epoch,
            0,
            VfsRpcRequestPayload::Write {
                handle: match &request.payload {
                    VfsRpcRequestPayload::Write { handle, .. } => handle.clone(),
                    _ => panic!("BULK refusal probe must be a WRITE"),
                },
                offset: 0,
                data: InlineOrBulk::Inline(Vec::new()),
            },
            Self::credentials(),
        )
        .expect("encode inline correlation placeholder");
        let context = self.envelope_context();
        let mut outbound = self
            .adapter
            .begin_request(PeerId(OWNER_NODE), &placeholder, Instant::now(), context)
            .expect("register BULK refusal correlation");
        let rpc_frame = VfsRpcTransportFrame::from_request(request).expect("encode BULK request");
        let raw_payload =
            ControlServiceFrame::new(rpc_frame.service_id, rpc_frame.message_type, rpc_frame.body)
                .encode()
                .expect("encode BULK Control service frame");
        self.transport
            .send_envelope(&mut outbound.envelope, &raw_payload)
            .expect("send unsupported BULK request");
        let (envelope, payload) = self
            .transport
            .recv_envelope(self.session_id)
            .expect("receive explicit BULK refusal");
        match self
            .adapter
            .unwrap_inbound(Instant::now(), &envelope, &payload)
            .expect("unwrap explicit BULK refusal")
        {
            VfsRpcInboundFrame::Response { response, .. } => response,
            VfsRpcInboundFrame::Request { .. } => panic!("client received an owner request"),
        }
    }
}

#[test]
fn pool_backed_owner_serves_inline_and_refuses_unowned_bulk() {
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
        "tidefs-vfs-rpc-owner",
        PoolRedundancyPolicy::default(),
        StoreOptions::default(),
        RootAuthenticationKey::demo_key(),
        RecoveryPolicy::default(),
    )
    .expect("open regular-file Pool-backed filesystem");
    let canonical_dataset_id = LifecycleDatasetId::from_bytes([0x48; 16]);
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
        "tidefs-vfs-rpc-owner",
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
    let topology = filesystem.pool_topology_status();
    assert_eq!(topology.present_members, 1);
    let dataset_id = DatasetId::new(u128::from_le_bytes(filesystem.mounted_dataset_id()));
    let adapter = FuseVfsAdapter::new(Box::new(VfsLocalFileSystem::new(filesystem)))
        .expect("create exact Pool-backed FUSE adapter");
    let engine = adapter.engine_handle();
    let shutdown = Arc::new(AtomicBool::new(false));
    let writer_fence = Arc::new(Mutex::new(ClusterVfsRpcWriterFence::new(
        OWNER_NODE,
        WRITER_TERM,
        WRITER_EPOCH,
    )));
    let zero_dataset = ClusterVfsRpcOwnerConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        OWNER_NODE,
        CLIENT_NODE,
        owner_identity.credential(),
        client_identity.public_identity(),
        DatasetId::new(0),
        Arc::clone(&writer_fence),
        Arc::clone(&engine),
        Arc::clone(&shutdown),
    );
    match ClusterVfsRpcOwnerHandle::start(zero_dataset) {
        Err(error) => assert_eq!(error, "cluster VFS_RPC dataset identity must be nonzero"),
        Ok(mut unexpected_owner) => {
            let _ = unexpected_owner.stop();
            panic!("zero VFS dataset identity must fail closed");
        }
    }
    let mut owner = ClusterVfsRpcOwnerHandle::start(ClusterVfsRpcOwnerConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        OWNER_NODE,
        CLIENT_NODE,
        owner_identity.credential(),
        client_identity.public_identity(),
        dataset_id,
        writer_fence,
        engine,
        Arc::clone(&shutdown),
    ))
    .expect("start Pool-backed VFS_RPC owner");
    let mut client = RpcClient::connect(
        CLIENT_NODE,
        owner.bound_addr(),
        dataset_id,
        &client_identity,
        &owner_identity,
    );

    let create = client.new_request(
        WRITER_TERM,
        WRITER_EPOCH,
        0,
        VfsRpcRequestPayload::Create {
            parent: ROOT_INODE_ID,
            name: b"remote-file".to_vec(),
            mode: 0o644,
            flags: libc::O_RDWR as u32,
        },
        RpcClient::credentials(),
    );
    let create_response = client.round_trip(&create);
    assert_eq!(create_response.header.errno, Errno::SUCCESS);
    let (inode, handle) = match create_response.payload {
        VfsRpcResponsePayload::Created { inode, handle, .. } => (inode, handle),
        payload => panic!("unexpected create response: {payload:?}"),
    };

    let lookup = client.new_request(
        WRITER_TERM,
        WRITER_EPOCH,
        0,
        VfsRpcRequestPayload::Lookup {
            parent: ROOT_INODE_ID,
            name: b"remote-file".to_vec(),
        },
        RpcClient::credentials(),
    );
    let lookup_response = client.round_trip(&lookup);
    assert_eq!(lookup_response.header.errno, Errno::SUCCESS);
    assert!(matches!(
        lookup_response.payload,
        VfsRpcResponsePayload::Lookup { inode: found, .. } if found == inode
    ));

    let expected = b"Pool receipts reached through authenticated inline VFS_RPC".to_vec();
    let write = client.new_request(
        WRITER_TERM,
        WRITER_EPOCH,
        0,
        VfsRpcRequestPayload::Write {
            handle: handle.clone(),
            offset: 0,
            data: InlineOrBulk::Inline(expected.clone()),
        },
        RpcClient::credentials(),
    );
    let write_response = client.round_trip(&write);
    assert_eq!(write_response.header.errno, Errno::SUCCESS);
    assert_eq!(
        write_response.payload,
        VfsRpcResponsePayload::BytesWritten(expected.len() as u64)
    );

    let fsync = client.new_request(
        WRITER_TERM,
        WRITER_EPOCH,
        0,
        VfsRpcRequestPayload::Fsync {
            handle: handle.clone(),
            datasync: false,
        },
        RpcClient::credentials(),
    );
    let fsync_response = client.round_trip(&fsync);
    assert_eq!(fsync_response.header.errno, Errno::SUCCESS);

    let read = client.new_request(
        WRITER_TERM,
        WRITER_EPOCH,
        0,
        VfsRpcRequestPayload::Read {
            handle: handle.clone(),
            offset: 0,
            length: expected.len() as u64,
        },
        RpcClient::credentials(),
    );
    let read_response = client.round_trip(&read);
    assert_eq!(read_response.header.errno, Errno::SUCCESS);
    assert_eq!(
        read_response.payload,
        VfsRpcResponsePayload::Data(InlineOrBulk::Inline(expected.clone()))
    );

    for (term, epoch) in [
        (WRITER_TERM - 1, WRITER_EPOCH),
        (WRITER_TERM, WRITER_EPOCH - 1),
    ] {
        let stale = client.new_request(
            term,
            epoch,
            0,
            VfsRpcRequestPayload::Write {
                handle: handle.clone(),
                offset: 0,
                data: InlineOrBulk::Inline(b"stale".to_vec()),
            },
            RpcClient::credentials(),
        );
        assert_eq!(client.round_trip(&stale).header.errno, Errno::ESTALE);
    }

    let bulk = client.new_request(
        WRITER_TERM,
        WRITER_EPOCH,
        REQ_FLAG_BULK_PENDING,
        VfsRpcRequestPayload::Write {
            handle: handle.clone(),
            offset: 0,
            data: InlineOrBulk::Bulk {
                token: [0x5a; 32],
                len: 4096,
            },
        },
        RpcClient::credentials(),
    );
    assert_eq!(
        client.raw_bulk_round_trip(&bulk).header.errno,
        Errno::EOPNOTSUPP
    );

    let mismatched_credentials = client.new_request(
        WRITER_TERM,
        WRITER_EPOCH,
        0,
        VfsRpcRequestPayload::Lookup {
            parent: ROOT_INODE_ID,
            name: b"remote-file".to_vec(),
        },
        Some(VfsRpcCredentials::root(PeerId(99))),
    );
    let context = client.envelope_context();
    let mut outbound = client
        .adapter
        .begin_request(
            PeerId(OWNER_NODE),
            &mismatched_credentials,
            Instant::now(),
            context,
        )
        .expect("wrap credential mismatch request");
    client
        .transport
        .send_envelope(&mut outbound.envelope, &outbound.payload)
        .expect("send credential mismatch request");
    assert!(
        client.transport.recv_envelope(client.session_id).is_err(),
        "the owner must close a transport whose VFS_RPC credentials name another peer"
    );

    owner.stop().expect("stop Pool-backed VFS_RPC owner");
    assert!(!shutdown.load(Ordering::Acquire));
}
