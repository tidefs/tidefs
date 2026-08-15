// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg(feature = "cluster")]

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tidefs_auth::{
    NodePrivateCredential, NodePublicIdentity, NODE_PRIVATE_CREDENTIAL_WIRE_SIZE,
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
use tidefs_posix_filesystem_adapter_daemon::{
    start_cluster_vfs_rpc_mount, ClusterVfsRpcMountConfig,
};
use tidefs_recovery_loop::RecoveryPolicy;
use tidefs_vfs_rpc::DatasetId;

const OWNER_NODE: u64 = 62;
const CLIENT_NODE: u64 = 63;
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

#[test]
fn authenticated_remote_client_mount_exposes_real_fuse_path() {
    if !std::path::Path::new("/dev/fuse").exists() {
        eprintln!("skipping authenticated remote mount: /dev/fuse is unavailable");
        return;
    }

    let owner_identity = ProvisionedIdentity::new(OWNER_NODE);
    let client_identity = ProvisionedIdentity::new(CLIENT_NODE);
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
    let mut owner = ClusterVfsRpcOwnerHandle::start(ClusterVfsRpcOwnerConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        OWNER_NODE,
        CLIENT_NODE,
        Arc::new(owner_identity.credential()),
        client_identity.public_identity(),
        POOL_GUID,
        dataset_id,
        writer_fence,
        owner_adapter.engine_handle(),
        Arc::clone(&shutdown),
    ))
    .expect("start Pool-backed VFS_RPC owner");

    let mut mount = start_cluster_vfs_rpc_mount(ClusterVfsRpcMountConfig::new(
        mountpoint.clone(),
        owner.bound_addr(),
        POOL_GUID,
        client_identity.credential(),
        owner_identity.public_identity(),
    ))
    .expect("mount authenticated remote Pool through FUSE");
    assert_eq!(mount.mountpoint(), mountpoint);

    let file_path = mountpoint.join("remote-file");
    let expected = b"real FUSE path reached the authenticated remote Pool owner";
    let mut file = OpenOptions::new()
        .create(true)
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

    mount.stop();
    owner.stop().expect("stop Pool-backed VFS_RPC owner");
    assert!(!shutdown.load(Ordering::Acquire));
    drop(owner_adapter);
}
