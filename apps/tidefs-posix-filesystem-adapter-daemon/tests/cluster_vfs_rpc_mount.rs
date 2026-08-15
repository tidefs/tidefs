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
    NodePrivateCredential, NodePublicIdentity, NODE_PRIVATE_CREDENTIAL_WIRE_SIZE,
    NODE_PUBLIC_IDENTITY_WIRE_SIZE,
};
use tidefs_dataset_lifecycle::{DatasetFlags, DatasetId as LifecycleDatasetId, SyncGuarantee};
use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem,
    ExternalMutationDeadline, LocalFileSystem, LocalFileSystemOpenConfig,
    LocalStorageAllocatorPolicy, RootAuthenticationKey,
};
use tidefs_local_object_store::pool::PoolRedundancyPolicy;
use tidefs_posix_filesystem_adapter_daemon::cluster_vfs_rpc_owner::{
    ClusterVfsRpcOwnerConfig, ClusterVfsRpcOwnerHandle, ClusterVfsRpcWriterFence,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;
use tidefs_posix_filesystem_adapter_daemon::{run_cluster_vfs_rpc_mount, ClusterVfsRpcMountConfig};
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
    let initial_authority_deadline = Instant::now() + Duration::from_secs(12);
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

    let mount_config = ClusterVfsRpcMountConfig::new(
        mountpoint.clone(),
        owner.bound_addr(),
        POOL_GUID,
        client_identity.credential(),
        owner_identity.public_identity(),
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
    authority_deadline.renew_until(initial_authority_deadline + Duration::from_secs(3));

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

    while Instant::now() <= initial_authority_deadline + Duration::from_millis(20) {
        assert!(
            !mount_thread.is_finished(),
            "renewable owner mount exited before the original authority deadline"
        );
        thread::sleep(Duration::from_millis(10));
    }
    fs::metadata(&mountpoint).expect("serve mounted metadata past the original authority deadline");

    authority_deadline.fence();
    let idle_unmount_deadline = initial_authority_deadline + Duration::from_secs(5);
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
    drop(owner_adapter);
}
