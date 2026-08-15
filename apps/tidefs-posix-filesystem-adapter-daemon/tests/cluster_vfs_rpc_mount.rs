// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg(feature = "cluster")]

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tidefs_auth::{
    NodeKeyStore, NodePrivateCredential, NodePublicIdentity, NODE_PRIVATE_CREDENTIAL_WIRE_SIZE,
    NODE_PUBLIC_IDENTITY_WIRE_SIZE,
};
use tidefs_cluster::{ClusterPoolMessage, ClusterPoolOwnerObservationResponse};
use tidefs_dataset_lifecycle::{DatasetFlags, DatasetId as LifecycleDatasetId, SyncGuarantee};
use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem,
    ExternalMutationDeadline, LocalFileSystem, LocalFileSystemOpenConfig,
    LocalStorageAllocatorPolicy, RootAuthenticationKey,
};
use tidefs_local_object_store::pool::PoolRedundancyPolicy;
use tidefs_posix_filesystem_adapter_daemon::cluster_vfs_rpc_client::ClusterVfsRpcOwnerCandidate;
use tidefs_posix_filesystem_adapter_daemon::cluster_vfs_rpc_owner::{
    ClusterVfsRpcOwnerConfig, ClusterVfsRpcOwnerHandle, ClusterVfsRpcWriterFence,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;
use tidefs_posix_filesystem_adapter_daemon::{run_cluster_vfs_rpc_mount, ClusterVfsRpcMountConfig};
use tidefs_recovery_loop::RecoveryPolicy;
use tidefs_transport::{EndpointFamily, SessionId, Transport, TransportAddr, TransportError};
use tidefs_vfs_rpc::DatasetId;

const OWNER_NODE: u64 = 62;
const SUCCESSOR_NODE: u64 = 64;
const CLIENT_NODE: u64 = 63;
const AUTHORITY_NODE: u64 = 65;
const WRITER_TERM: u64 = 81;
const WRITER_EPOCH: u64 = 14;
const POOL_GUID: [u8; 16] = [0x62; 16];

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

    fn credential(&self) -> NodePrivateCredential {
        NodePrivateCredential::decode_fixed(&self.credential_bytes)
            .expect("decode provisioned test credential")
    }

    fn public_identity(&self) -> NodePublicIdentity {
        NodePublicIdentity::decode_fixed(&self.public_bytes)
            .expect("decode provisioned test public identity")
    }
}

fn accept_session(transport: &mut Transport) -> SessionId {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        match transport.accept_incoming() {
            Ok(session_id) => return session_id,
            Err(TransportError::Generic(message)) if message == "no pending connections" => {
                assert!(Instant::now() < deadline, "authority accept timed out");
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("authority accept failed: {error}"),
        }
    }
}

fn spawn_owner_observation_authority(
    authority_identity: &ProvisionedIdentity,
    client_identity: &ProvisionedIdentity,
    observations: Vec<(u64, u64, u64)>,
) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    let credential = Arc::new(authority_identity.credential());
    let authority_public = credential.public_identity().into_identity();
    let mut known_identities = NodeKeyStore::new();
    known_identities
        .register(authority_public.clone())
        .expect("register mount authority identity");
    known_identities
        .register(client_identity.public_identity().into_identity())
        .expect("register mount client identity");
    let mut authority = Transport::new(AUTHORITY_NODE)
        .with_attestation(
            credential.keypair().expect("load mount authority keypair"),
            authority_public,
        )
        .with_known_identities(known_identities);
    authority.set_endpoint_family(EndpointFamily::Control);
    authority.set_attestation_bootstrap_from_handshake(false);
    authority
        .bind(TransportAddr::Tcp("127.0.0.1:0".parse().unwrap()))
        .expect("bind mount authority");
    let address = match authority.bind_addr {
        Some(TransportAddr::Tcp(address)) => address,
        _ => panic!("mount authority must publish TCP address"),
    };
    let handle = thread::spawn(move || {
        for (owner_node_id, writer_term, membership_epoch) in observations {
            let session_id = accept_session(&mut authority);
            authority
                .perform_handshake(session_id)
                .expect("authenticate mount owner observer");
            let deadline = Instant::now() + Duration::from_secs(10);
            let raw = loop {
                match authority.recv_message(session_id) {
                    Ok(raw) => break raw,
                    Err(TransportError::WouldBlock(_)) => {
                        assert!(Instant::now() < deadline, "mount observation timed out");
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("receive mount observation: {error}"),
                }
            };
            assert_eq!(&raw[..4], b"CP01");
            let request = ClusterPoolMessage::decode(&raw[4..]).expect("decode mount observation");
            let ClusterPoolMessage::OwnerObservationRequest(request) = request else {
                panic!("expected mount owner observation request");
            };
            assert_eq!(request.pool_guid, POOL_GUID);
            assert_eq!(request.requesting_node_id, CLIENT_NODE);
            let response =
                ClusterPoolMessage::OwnerObservationResponse(ClusterPoolOwnerObservationResponse {
                    request_id: request.request_id,
                    node_id: AUTHORITY_NODE,
                    pool_guid: POOL_GUID,
                    success: true,
                    owner_node_id: Some(owner_node_id),
                    membership_epoch: Some(membership_epoch),
                    write_fence_generation: Some(writer_term),
                    lease_remaining_ms: Some(60_000),
                    error: None,
                })
                .encode()
                .expect("encode mount observation");
            let mut wire = Vec::with_capacity(4 + response.len());
            wire.extend_from_slice(b"CP01");
            wire.extend_from_slice(&response);
            authority
                .send_message(session_id, &wire)
                .expect("send mount observation");
        }
    });
    (address, handle)
}

fn mount_is_present(mountpoint: &Path) -> bool {
    fs::read_to_string("/proc/self/mountinfo").is_ok_and(|mountinfo| {
        mountinfo.lines().any(|line| {
            line.split_whitespace()
                .nth(4)
                .is_some_and(|path| Path::new(path) == mountpoint)
        })
    })
}

#[test]
fn authenticated_remote_client_mount_exposes_real_fuse_path() {
    if !std::path::Path::new("/dev/fuse").exists() {
        eprintln!("skipping authenticated remote mount: /dev/fuse is unavailable");
        return;
    }

    let owner_identity = ProvisionedIdentity::new(OWNER_NODE);
    let successor_identity = ProvisionedIdentity::new(SUCCESSOR_NODE);
    let client_identity = ProvisionedIdentity::new(CLIENT_NODE);
    let authority_identity = ProvisionedIdentity::new(AUTHORITY_NODE);
    let successor_listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("reserve successor VFS_RPC endpoint");
    let successor_addr = successor_listener
        .local_addr()
        .expect("read reserved successor endpoint");
    let root = tempfile::tempdir().expect("create persistent test root");
    let metadata_dir = root.path().join("metadata");
    let member = root.path().join("member.img");
    let mountpoint = root.path().join("mount");
    fs::create_dir_all(&metadata_dir).expect("create Pool metadata directory");
    File::create(&member)
        .expect("create regular-file Pool member")
        .set_len(32 * 1024 * 1024)
        .expect("size regular-file Pool member");

    let mut root_filesystem = LocalFileSystem::open_with_block_devices_and_recovery_policy(
        &metadata_dir,
        std::slice::from_ref(&member),
        "tidefs-vfs-rpc-mount",
        PoolRedundancyPolicy::default(),
        StoreOptions::default(),
        RootAuthenticationKey::demo_key(),
        RecoveryPolicy::default(),
    )
    .expect("open regular-file Pool-backed root filesystem");
    let canonical_dataset_id = LifecycleDatasetId::from_bytes([0x62; 16]);
    root_filesystem
        .create_filesystem_dataset(
            "clustered",
            canonical_dataset_id,
            Vec::new(),
            DatasetFlags::default_create(),
            SyncGuarantee::Local,
        )
        .expect("publish clustered filesystem dataset");
    drop(root_filesystem);

    let filesystem = LocalFileSystem::open_named_pool_filesystem_dataset_with_allocator_policy_and_root_authentication_key(
        &metadata_dir,
        "tidefs-vfs-rpc-mount",
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
    .expect("open exact Pool-backed filesystem dataset");
    let dataset_id = DatasetId::new(u128::from_le_bytes(filesystem.mounted_dataset_id()));
    let owner_adapter = FuseVfsAdapter::new(Box::new(VfsLocalFileSystem::new(filesystem)))
        .expect("create Pool-backed owner adapter");
    let shutdown = Arc::new(AtomicBool::new(false));
    let writer_fence = Arc::new(Mutex::new(ClusterVfsRpcWriterFence::new(
        OWNER_NODE,
        WRITER_TERM,
        WRITER_EPOCH,
    )));
    let initial_authority_deadline = Instant::now() + Duration::from_secs(20);
    let authority_deadline = ExternalMutationDeadline::new_until(initial_authority_deadline);
    let mut owner = ClusterVfsRpcOwnerHandle::start(ClusterVfsRpcOwnerConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        OWNER_NODE,
        Arc::new(owner_identity.credential()),
        vec![client_identity.public_identity()],
        POOL_GUID,
        dataset_id,
        writer_fence,
        authority_deadline.clone(),
        owner_adapter.engine_handle(),
        Arc::clone(&shutdown),
    ))
    .expect("start Pool-backed VFS_RPC owner");

    let (authority_addr, authority_thread) = spawn_owner_observation_authority(
        &authority_identity,
        &client_identity,
        vec![
            (OWNER_NODE, WRITER_TERM, WRITER_EPOCH),
            (SUCCESSOR_NODE, WRITER_TERM + 1, WRITER_EPOCH),
        ],
    );

    let mount_config = ClusterVfsRpcMountConfig::new(
        mountpoint.clone(),
        authority_addr,
        POOL_GUID,
        client_identity.credential(),
        authority_identity.public_identity(),
        vec![
            ClusterVfsRpcOwnerCandidate::new(successor_addr, successor_identity.public_identity()),
            ClusterVfsRpcOwnerCandidate::new(owner.bound_addr(), owner_identity.public_identity()),
        ],
    );
    let mount_thread = thread::spawn(move || run_cluster_vfs_rpc_mount(mount_config));
    let mount_start_deadline = Instant::now() + Duration::from_secs(10);
    while !mount_is_present(&mountpoint) {
        if mount_thread.is_finished() {
            let result = mount_thread
                .join()
                .expect("cluster VFS_RPC mount thread must not panic");
            panic!("cluster VFS_RPC mount exited during startup: {result:?}");
        }
        assert!(
            Instant::now() < mount_start_deadline,
            "cluster VFS_RPC mount did not appear before its startup deadline"
        );
        thread::sleep(Duration::from_millis(10));
    }
    authority_deadline.renew_until(initial_authority_deadline + Duration::from_secs(5));

    let file_path = mountpoint.join("remote-file");
    let expected = b"real FUSE path reached the authenticated remote Pool owner";
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("create through real remote mount");
    file.write_all(expected)
        .expect("write through real remote mount");
    file.flush().expect("flush through real remote mount");
    file.sync_all().expect("fsync through real remote mount");
    drop(file);

    let mut found = Vec::new();
    File::open(&file_path)
        .expect("reopen through real remote mount")
        .read_to_end(&mut found)
        .expect("read through real remote mount");
    assert_eq!(found, expected);

    let path = CString::new(mountpoint.as_os_str().as_bytes()).expect("mountpoint C string");
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::statvfs(path.as_ptr(), &mut stat) }, 0);
    assert!(stat.f_bsize > 0, "remote statfs must report a block size");

    let directory = mountpoint.join("remote-dir");
    let renamed = directory.join("renamed");
    let hard_link = directory.join("hard-link");
    fs::create_dir(&directory).expect("mkdir through real remote mount");
    fs::rename(&file_path, &renamed).expect("rename through real remote mount");
    fs::hard_link(&renamed, &hard_link).expect("hard-link through real remote mount");
    assert_eq!(
        fs::read(&renamed).expect("read renamed remote file"),
        expected
    );
    assert_eq!(
        fs::read(&hard_link).expect("read remote hard link"),
        expected
    );
    fs::remove_file(&renamed).expect("unlink renamed remote file");
    assert_eq!(
        fs::read(&hard_link).expect("hard link survives first unlink"),
        expected
    );
    fs::remove_file(&hard_link).expect("unlink remote hard link");
    fs::remove_dir(&directory).expect("rmdir through real remote mount");
    let successor_visible = b"fresh authority observation reached the higher-fence successor";
    let successor_file = mountpoint.join("successor-visible");
    let mut file = File::create(&successor_file).expect("create successor-visible file");
    file.write_all(successor_visible)
        .expect("write successor-visible file");
    file.sync_all().expect("commit successor-visible file");
    drop(file);

    while Instant::now() <= initial_authority_deadline + Duration::from_millis(20) {
        assert!(
            !mount_thread.is_finished(),
            "renewable owner mount exited before the original authority deadline"
        );
        thread::sleep(Duration::from_millis(10));
    }
    fs::metadata(&mountpoint).expect("serve mounted metadata past the original authority deadline");

    authority_deadline.fence();
    let idle_unmount_deadline = initial_authority_deadline + Duration::from_secs(9);
    while !mount_thread.is_finished() && Instant::now() < idle_unmount_deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        mount_thread.is_finished(),
        "idle clustered FUSE run loop did not expire and unmount the stale frontend"
    );
    let mount_error = mount_thread
        .join()
        .expect("cluster VFS_RPC mount thread must not panic")
        .expect_err("expired owner authority must fail the clustered mount run loop");
    assert!(
        mount_error.contains("owner authority lost or expired")
            && mount_error.contains("stale frontend unmounted"),
        "unexpected stale-mount error: {mount_error}"
    );
    assert!(
        !mount_is_present(&mountpoint),
        "authority-expired clustered FUSE frontend must be unmounted"
    );
    let owner_error = owner
        .stop()
        .expect_err("expired owner deadline must stop the owner service");
    assert!(owner_error.contains("mutation authority deadline has expired"));
    assert!(shutdown.load(Ordering::Acquire));

    drop(successor_listener);
    let successor_shutdown = Arc::new(AtomicBool::new(false));
    let successor_deadline =
        ExternalMutationDeadline::new_until(Instant::now() + Duration::from_secs(6));
    let successor_fence = Arc::new(Mutex::new(ClusterVfsRpcWriterFence::new(
        SUCCESSOR_NODE,
        WRITER_TERM + 1,
        WRITER_EPOCH,
    )));
    let mut successor = ClusterVfsRpcOwnerHandle::start(ClusterVfsRpcOwnerConfig::new(
        successor_addr,
        SUCCESSOR_NODE,
        Arc::new(successor_identity.credential()),
        vec![client_identity.public_identity()],
        POOL_GUID,
        dataset_id,
        successor_fence,
        successor_deadline.clone(),
        owner_adapter.engine_handle(),
        Arc::clone(&successor_shutdown),
    ))
    .expect("start higher-fence successor VFS_RPC owner");

    let successor_mountpoint = root.path().join("successor-mount");
    let successor_config = ClusterVfsRpcMountConfig::new(
        successor_mountpoint.clone(),
        authority_addr,
        POOL_GUID,
        client_identity.credential(),
        authority_identity.public_identity(),
        vec![
            ClusterVfsRpcOwnerCandidate::new(owner.bound_addr(), owner_identity.public_identity()),
            ClusterVfsRpcOwnerCandidate::new(
                successor.bound_addr(),
                successor_identity.public_identity(),
            ),
        ],
    );
    let successor_mount_thread = thread::spawn(move || run_cluster_vfs_rpc_mount(successor_config));
    let successor_mount_deadline = Instant::now() + Duration::from_secs(10);
    while !mount_is_present(&successor_mountpoint) {
        if successor_mount_thread.is_finished() {
            let result = successor_mount_thread
                .join()
                .expect("successor mount thread must not panic");
            panic!("higher-fence successor mount exited during startup: {result:?}");
        }
        assert!(
            Instant::now() < successor_mount_deadline,
            "higher-fence successor mount did not appear"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        fs::read(successor_mountpoint.join("successor-visible"))
            .expect("read committed data through authority-selected successor"),
        successor_visible
    );

    successor_deadline.fence();
    let successor_unmount_deadline = Instant::now() + Duration::from_secs(8);
    while !successor_mount_thread.is_finished() && Instant::now() < successor_unmount_deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        successor_mount_thread.is_finished(),
        "higher-fence successor frontend did not expire"
    );
    successor_mount_thread
        .join()
        .expect("successor mount thread must not panic")
        .expect_err("fenced successor authority must unmount the fresh frontend");
    let successor_error = successor
        .stop()
        .expect_err("fenced successor must stop with expired authority");
    assert!(successor_error.contains("mutation authority deadline has expired"));
    assert!(successor_shutdown.load(Ordering::Acquire));
    authority_thread
        .join()
        .expect("owner observation authority thread");
    drop(owner_adapter);
}
