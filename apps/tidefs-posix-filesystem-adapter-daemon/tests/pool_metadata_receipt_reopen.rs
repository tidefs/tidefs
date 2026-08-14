// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Real FUSE recovery through mirrored Pool transaction-metadata receipts.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, transaction_manifest_object_key,
    transaction_superblock_object_key, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_local_object_store::pool::{
    Pool, PoolConfig, PoolProperties, PoolRedundancyPolicy, PoolTopologyStatus,
};
use tidefs_local_object_store::{
    DeviceBacking, DeviceClass, DeviceConfig, DeviceKind, DeviceMediaClass,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;
use tidefs_recovery_loop::RecoveryPolicy;

fn unique_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "tidefs-pool-metadata-receipt-reopen-{}-{nanos}",
        std::process::id()
    ))
}

fn device_config(path: PathBuf) -> DeviceConfig {
    DeviceConfig {
        media_class: DeviceMediaClass::Ssd,
        path: path.clone(),
        backing: DeviceBacking::RegularFileDev,
        class: DeviceClass::Data,
        kind: DeviceKind::Block { path },
        encryption: None,
        compression: None,
    }
}

fn open_fuse_session(
    metadata_dir: &Path,
    devices: &[PathBuf],
    mountpoint: &Path,
    redundancy_policy: PoolRedundancyPolicy,
    read_only: bool,
) -> (fuser::BackgroundSession, PoolTopologyStatus) {
    let recovery_policy = if read_only {
        RecoveryPolicy::ReadOnly
    } else {
        RecoveryPolicy::default()
    };
    let filesystem = LocalFileSystem::open_with_block_devices_and_recovery_policy(
        metadata_dir,
        devices,
        "tidefs",
        redundancy_policy,
        StoreOptions::default(),
        RootAuthenticationKey::demo_key(),
        recovery_policy,
    )
    .expect("open mirrored filesystem for FUSE");
    let topology = filesystem.pool_topology_status();
    let engine = VfsLocalFileSystem::new(filesystem);
    let engine = if read_only {
        engine.with_read_only()
    } else {
        engine
    };
    let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create FUSE VFS adapter");
    let access = if read_only {
        fuser::MountOption::RO
    } else {
        fuser::MountOption::RW
    };
    let session = fuser::spawn_mount2(
        adapter,
        mountpoint,
        &[
            fuser::MountOption::FSName("tidefs-pool-metadata-receipt".to_string()),
            access,
            fuser::MountOption::NoDev,
            fuser::MountOption::NoSuid,
            fuser::MountOption::Subtype("tidefs".to_string()),
        ],
    )
    .expect("mount mirrored filesystem through FUSE");
    (session, topology)
}

#[test]
fn fuse_remount_survives_primary_transaction_metadata_loss() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("SKIP: /dev/fuse not available");
        return;
    }

    let root = unique_root();
    let metadata_dir = root.join("metadata");
    let mountpoint = root.join("mnt");
    let devices = vec![root.join("member-0.img"), root.join("member-1.img")];
    fs::create_dir_all(&metadata_dir).expect("create Pool metadata directory");
    fs::create_dir_all(&mountpoint).expect("create FUSE mountpoint");
    for device in &devices {
        File::create(device)
            .expect("create regular-file Pool member")
            .set_len(16 * 1024 * 1024)
            .expect("size regular-file Pool member");
    }

    let redundancy_policy = PoolRedundancyPolicy::replicated(2);
    let payload = b"real FUSE bytes recovered through surviving Pool metadata receipts";
    let (session, _) = open_fuse_session(
        &metadata_dir,
        &devices,
        &mountpoint,
        redundancy_policy,
        false,
    );
    let mounted_file = mountpoint.join("survivor");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&mounted_file)
            .expect("create file through FUSE");
        file.write_all(payload).expect("write file through FUSE");
    }
    File::open(&mounted_file)
        .expect("reopen mounted file for fsync")
        .sync_all()
        .expect("fsync mounted file");
    drop(session);
    std::thread::sleep(Duration::from_millis(100));

    let config = PoolConfig {
        name: "tidefs".to_string(),
        root_path: metadata_dir.clone(),
        devices: devices.iter().cloned().map(device_config).collect(),
    };
    let properties = PoolProperties {
        redundancy_policy,
        ..PoolProperties::default()
    };
    let mut pool = Pool::open(config, properties, &StoreOptions::default())
        .expect("open Pool to stage primary member metadata loss");
    let mut removed = 0_u64;
    for transaction_id in 1..=256 {
        for key in [
            transaction_superblock_object_key(transaction_id),
            transaction_manifest_object_key(transaction_id),
        ] {
            if pool
                .raw_primary_store_mut()
                .delete(key)
                .expect("remove primary transaction object copy")
            {
                removed += 1;
            }
        }
    }
    assert!(
        removed >= 2,
        "the primary member must have carried a committed superblock and manifest"
    );
    pool.sync_all().expect("sync primary member metadata loss");
    drop(pool);

    let (session, _) = open_fuse_session(
        &metadata_dir,
        &devices,
        &mountpoint,
        redundancy_policy,
        false,
    );
    let mut read_back = Vec::new();
    File::open(&mounted_file)
        .expect("open file after mirrored Pool remount")
        .read_to_end(&mut read_back)
        .expect("read file after mirrored Pool remount");
    assert_eq!(read_back, payload);

    drop(session);
    std::thread::sleep(Duration::from_millis(100));
    fs::remove_dir_all(&root).expect("remove completed FUSE test fixture");
}

#[test]
fn fuse_read_only_remount_survives_physically_absent_member() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("SKIP: /dev/fuse not available");
        return;
    }

    let root = unique_root();
    let metadata_dir = root.join("metadata");
    let mountpoint = root.join("mnt");
    let devices = vec![root.join("member-0.img"), root.join("member-1.img")];
    fs::create_dir_all(&metadata_dir).expect("create Pool metadata directory");
    fs::create_dir_all(&mountpoint).expect("create FUSE mountpoint");
    for device in &devices {
        File::create(device)
            .expect("create regular-file Pool member")
            .set_len(16 * 1024 * 1024)
            .expect("size regular-file Pool member");
    }

    let redundancy_policy = PoolRedundancyPolicy::replicated(2);
    let payload = b"committed FUSE bytes recovered while member zero is physically absent";
    let (session, _) = open_fuse_session(
        &metadata_dir,
        &devices,
        &mountpoint,
        redundancy_policy,
        false,
    );
    let mounted_file = mountpoint.join("degraded-survivor");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&mounted_file)
            .expect("create file through replicated FUSE mount");
        file.write_all(payload)
            .expect("write file through replicated FUSE mount");
    }
    File::open(&mounted_file)
        .expect("reopen replicated mounted file for fsync")
        .sync_all()
        .expect("fsync replicated mounted file");
    drop(session);
    std::thread::sleep(Duration::from_millis(100));

    let offline_member = root.join("offline-member-0.img");
    fs::rename(&devices[0], &offline_member).expect("make member zero physically absent");
    assert!(!devices[0].exists());
    let surviving_devices = vec![devices[1].clone()];
    let (session, topology) = open_fuse_session(
        &metadata_dir,
        &surviving_devices,
        &mountpoint,
        redundancy_policy,
        true,
    );
    assert_eq!(topology.expected_members, 2);
    assert_eq!(topology.present_members, 1);
    assert_eq!(topology.missing_members, 1);
    assert!(topology.read_only);
    assert_eq!(topology.members.len(), 2);
    assert_eq!(topology.members[0].device_index, 0);
    assert!(!topology.members[0].present);
    assert_eq!(topology.members[1].device_index, 1);
    assert!(topology.members[1].present);
    assert_ne!(
        topology.members[0].device_guid, topology.members[1].device_guid,
        "the absent member must retain its own durable identity"
    );
    let mut read_back = Vec::new();
    File::open(&mounted_file)
        .expect("open committed file through degraded read-only FUSE mount")
        .read_to_end(&mut read_back)
        .expect("read committed file through degraded read-only FUSE mount");
    assert_eq!(read_back, payload);

    drop(session);
    std::thread::sleep(Duration::from_millis(100));
    fs::remove_dir_all(&root).expect("remove completed degraded FUSE test fixture");
}
