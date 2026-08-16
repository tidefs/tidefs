// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

use std::fs::OpenOptions;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tidefs_block_volume_adapter_daemon::storage_backend::{
    BackendError, BlockVolumeStorageBackend, PoolVolumeBackend,
};
use tidefs_block_volume_adapter_daemon::DataQueueWorker;
use tidefs_cluster::{ClusterLeaseGrant, ClusterLeaseSession, EpochId, PoolLeaseToken, WriteFence};
use tidefs_dataset_lifecycle::{DatasetFlags, DatasetId, SyncGuarantee};
use tidefs_local_filesystem::{PoolDatasetOwner, RootAuthenticationKey, SharedPoolDatasetOwner};
use tidefs_local_object_store::{PoolRedundancyPolicy, StoreOptions};
use tidefs_pool_runtime::PoolRuntime;
use tidefs_ublk_abi::{UblkSrvIoDesc, UBLK_IO_OP_FLUSH, UBLK_IO_OP_READ, UBLK_IO_OP_WRITE};

fn runtime(dir: &tempfile::TempDir) -> (PoolRuntime, std::path::PathBuf) {
    let device = dir.path().join("device.img");
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&device)
        .expect("create device")
        .set_len(64 * 1024 * 1024)
        .expect("size device");
    let runtime = PoolRuntime::open_block_devices(
        dir.path(),
        std::slice::from_ref(&device),
        "tank",
        PoolRedundancyPolicy::default(),
        &StoreOptions::default(),
    )
    .expect("open Pool runtime");
    (runtime, device)
}

fn create_volume(runtime: &mut PoolRuntime, name: &str, identity_byte: u8) {
    runtime
        .create_volume(
            name,
            DatasetId::from_bytes([identity_byte; 16]),
            4 * 1024 * 1024,
            Vec::new(),
            DatasetFlags::NONE,
            SyncGuarantee::Local,
        )
        .expect("create Pool volume");
}

fn clustered_lease(runtime: &PoolRuntime, pool_guid: [u8; 16]) -> PoolLeaseToken {
    assert_eq!(runtime.pool().pool_guid(), pool_guid);
    PoolLeaseToken::new(
        7,
        pool_guid,
        EpochId(3),
        11,
        0,
        WriteFence::new(EpochId(3), 5),
        60_000,
    )
}

#[derive(Debug)]
struct MockLeaseSession {
    events: Arc<Mutex<Vec<&'static str>>>,
    fail_renewal: bool,
}

impl ClusterLeaseSession for MockLeaseSession {
    fn renew(&mut self, token: &PoolLeaseToken) -> Result<ClusterLeaseGrant, String> {
        self.events.lock().unwrap().push("renew");
        if self.fail_renewal {
            return Err("injected authority loss".to_string());
        }
        let mut renewed = token.clone();
        renewed.expiration_deadline_ms += 60_000;
        Ok(ClusterLeaseGrant {
            token: renewed,
            valid_until: Instant::now() + Duration::from_secs(60),
        })
    }

    fn release(&mut self, _token: &PoolLeaseToken) -> Result<(), String> {
        self.events.lock().unwrap().push("release");
        Ok(())
    }
}

fn renewable_grant(token: PoolLeaseToken) -> ClusterLeaseGrant {
    ClusterLeaseGrant {
        token,
        valid_until: Instant::now() + Duration::from_millis(300),
    }
}

fn descriptor(op: u8, start_sector: u64, sector_count: u32, address: u64) -> UblkSrvIoDesc {
    UblkSrvIoDesc {
        op_flags: u32::from(op),
        count_or_zones: sector_count,
        start_sector,
        addr: address,
    }
}

#[test]
fn pool_volume_backend_flushes_and_reopens_committed_data() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut runtime, device) = runtime(&dir);
    create_volume(&mut runtime, "vol", 1);

    let mut backend = PoolVolumeBackend::open_standalone(runtime, "vol", false)
        .expect("open Pool volume backend");
    backend
        .write_blocks(2, &[0x5a; 4096], 4096)
        .expect("write volume block");
    backend.flush().expect("flush volume");
    drop(backend);

    let runtime = PoolRuntime::open_block_devices(
        dir.path(),
        &[device],
        "tank",
        PoolRedundancyPolicy::default(),
        &StoreOptions::default(),
    )
    .expect("reopen Pool runtime");
    let backend = PoolVolumeBackend::open_standalone(runtime, "vol", false)
        .expect("reopen Pool volume backend");
    let read = backend
        .read_blocks(2, 1, 4096)
        .expect("read reopened volume block");
    assert_eq!(read.payload.expect("read payload"), vec![0x5a; 4096]);
}

#[test]
fn mounted_pool_volume_backend_uses_shared_owner_and_preserves_mutation_fence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut owner = PoolDatasetOwner::open_with_root_authentication_key(
        dir.path(),
        StoreOptions::default(),
        RootAuthenticationKey::demo_key(),
    )
    .expect("open mounted Pool owner");
    owner
        .create_volume_dataset(
            "vol",
            DatasetId::from_bytes([14; 16]),
            4 * 1024 * 1024,
            Vec::new(),
            DatasetFlags::NONE,
            SyncGuarantee::Local,
        )
        .expect("create mounted Pool volume");
    let shared_owner = SharedPoolDatasetOwner::new(owner);
    let mut backend = PoolVolumeBackend::open_mounted(shared_owner.clone(), "vol", false)
        .expect("open mounted Pool volume backend");

    backend
        .write_blocks(2, &[0x6d; 4096], 4096)
        .expect("write through mounted Pool owner");
    backend.flush().expect("flush through mounted Pool owner");
    {
        let owner = shared_owner.borrow();
        let volume = owner
            .pool_runtime()
            .open_volume("vol")
            .expect("open volume through the same Pool runtime");
        assert_eq!(
            volume
                .read_blocks(owner.pool_runtime(), 2, 1)
                .expect("read committed mounted volume bytes"),
            vec![0x6d; 4096]
        );
    }

    shared_owner
        .borrow_mut()
        .fence_external_mutation_authority();
    let read = backend
        .read_blocks(2, 1, 4096)
        .expect("the mutation fence must not hide committed reads");
    assert_eq!(read.payload.expect("read payload"), vec![0x6d; 4096]);
    assert!(matches!(
        backend.write_blocks(3, &[0x7e; 4096], 4096),
        Err(BackendError::Other(message)) if message.contains("reopen")
    ));
    assert!(matches!(
        backend.write_zeroes(2, 1, 4096),
        Err(BackendError::Other(message)) if message.contains("reopen")
    ));
    assert!(matches!(
        backend.flush(),
        Err(BackendError::Other(message)) if message.contains("reopen")
    ));
}

#[test]
fn clustered_pool_volume_backend_fences_every_io_operation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut runtime, _device) = runtime(&dir);
    create_volume(&mut runtime, "vol", 8);
    let pool_guid = runtime.pool().pool_guid();
    let lease = clustered_lease(&runtime, pool_guid);
    let mut backend = PoolVolumeBackend::open_clustered(
        runtime,
        "vol",
        false,
        lease.clone(),
        Instant::now() + Duration::from_secs(60),
    )
    .expect("open clustered Pool volume backend");

    backend
        .write_blocks(0, &[0x58; 4096], 4096)
        .expect("stage predecessor write");
    backend
        .fence_clustered_authority()
        .expect("fence clustered authority");

    assert!(matches!(
        backend.read_blocks(0, 1, 4096),
        Err(BackendError::ClusterAuthorityExpired)
    ));
    assert!(matches!(
        backend.write_blocks(1, &[0x59; 4096], 4096),
        Err(BackendError::ClusterAuthorityExpired)
    ));
    assert!(matches!(
        backend.flush(),
        Err(BackendError::ClusterAuthorityExpired)
    ));
    assert!(matches!(
        backend.discard_blocks(0, 1, 4096),
        Err(BackendError::ClusterAuthorityExpired)
    ));
    assert!(matches!(
        backend.write_zeroes(0, 1, 4096),
        Err(BackendError::ClusterAuthorityExpired)
    ));
    let mut captured_renewal = lease;
    captured_renewal.expiration_deadline_ms += 60_000;
    assert!(matches!(
        backend
            .renew_clustered_authority(captured_renewal, Instant::now() + Duration::from_secs(60),),
        Err(BackendError::ClusterAuthorityExpired)
    ));
}

#[test]
fn clustered_pool_volume_backend_refuses_wrong_pool_lease() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut runtime, _device) = runtime(&dir);
    create_volume(&mut runtime, "vol", 9);
    let wrong_guid = [0x99; 16];
    let lease = PoolLeaseToken::new(
        7,
        wrong_guid,
        EpochId(3),
        11,
        0,
        WriteFence::new(EpochId(3), 5),
        60_000,
    );

    assert!(matches!(
        PoolVolumeBackend::open_clustered(
            runtime,
            "vol",
            false,
            lease,
            Instant::now() + Duration::from_secs(60),
        ),
        Err(BackendError::InvalidClusterAuthority(
            "lease Pool GUID does not match the opened Pool"
        ))
    ));
}

#[test]
fn clustered_pool_volume_backend_renews_only_the_same_extended_grant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut runtime, _device) = runtime(&dir);
    create_volume(&mut runtime, "vol", 10);
    let pool_guid = runtime.pool().pool_guid();
    let lease = clustered_lease(&runtime, pool_guid);
    let initial_valid_until = Instant::now() + Duration::from_secs(60);
    let mut backend = PoolVolumeBackend::open_clustered(
        runtime,
        "vol",
        false,
        lease.clone(),
        initial_valid_until,
    )
    .expect("open clustered Pool volume backend");

    assert!(matches!(
        backend.renew_clustered_authority(
            lease.clone(),
            initial_valid_until + Duration::from_secs(60),
        ),
        Err(BackendError::InvalidClusterAuthority(
            "renewal does not extend the same writer lease and fence"
        ))
    ));

    let mut wrong_slot = lease.clone();
    wrong_slot.slot += 1;
    wrong_slot.expiration_deadline_ms += 60_000;
    assert!(matches!(
        backend
            .renew_clustered_authority(wrong_slot, initial_valid_until + Duration::from_secs(60),),
        Err(BackendError::InvalidClusterAuthority(
            "renewal does not extend the same writer lease and fence"
        ))
    ));

    let mut renewed = lease;
    renewed.expiration_deadline_ms += 60_000;
    backend
        .renew_clustered_authority(renewed, initial_valid_until + Duration::from_secs(60))
        .expect("renew the same committed owner lease");
    backend
        .read_blocks(0, 1, 4096)
        .expect("renewed authority keeps the backend live");
}

#[test]
fn clustered_pool_volume_live_carrier_renews_and_release_fences() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut runtime, _device) = runtime(&dir);
    create_volume(&mut runtime, "vol", 11);
    let pool_guid = runtime.pool().pool_guid();
    let lease = clustered_lease(&runtime, pool_guid);
    let events = Arc::new(Mutex::new(Vec::new()));
    let session = MockLeaseSession {
        events: Arc::clone(&events),
        fail_renewal: false,
    };
    let mut backend = PoolVolumeBackend::open_renewable_clustered(
        runtime,
        "vol",
        false,
        renewable_grant(lease),
        Box::new(session),
    )
    .expect("open renewable clustered backend");

    std::thread::sleep(Duration::from_millis(180));
    backend
        .maintain_writer_authority()
        .expect("renew live writer authority");
    backend
        .write_blocks(0, &[0x61; 4096], 4096)
        .expect("write after renewal");
    backend.flush().expect("flush after renewal");
    backend
        .release_clustered_authority()
        .expect("release after carrier stop");

    assert_eq!(*events.lock().unwrap(), vec!["renew", "release"]);
    assert!(matches!(
        backend.read_blocks(0, 1, 4096),
        Err(BackendError::ClusterAuthorityExpired)
    ));
}

#[test]
fn clustered_pool_volume_renewal_loss_fences_before_teardown_release() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut runtime, _device) = runtime(&dir);
    create_volume(&mut runtime, "vol", 12);
    let pool_guid = runtime.pool().pool_guid();
    let lease = clustered_lease(&runtime, pool_guid);
    let events = Arc::new(Mutex::new(Vec::new()));
    let session = MockLeaseSession {
        events: Arc::clone(&events),
        fail_renewal: true,
    };
    let mut backend = PoolVolumeBackend::open_renewable_clustered(
        runtime,
        "vol",
        false,
        renewable_grant(lease),
        Box::new(session),
    )
    .expect("open renewable clustered backend");

    std::thread::sleep(Duration::from_millis(180));
    let error = backend.maintain_writer_authority().unwrap_err();
    assert!(error.to_string().contains("injected authority loss"));
    assert!(matches!(
        backend.write_blocks(0, &[0x62; 4096], 4096),
        Err(BackendError::ClusterAuthorityExpired)
    ));
    backend
        .release_clustered_authority()
        .expect("release fenced predecessor lease during teardown");
    assert_eq!(*events.lock().unwrap(), vec!["renew", "release"]);
}

#[test]
fn higher_fence_successor_reopens_released_clustered_volume() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut runtime, device) = runtime(&dir);
    create_volume(&mut runtime, "vol", 13);
    let pool_guid = runtime.pool().pool_guid();
    let predecessor = clustered_lease(&runtime, pool_guid);
    let predecessor_events = Arc::new(Mutex::new(Vec::new()));
    let mut backend = PoolVolumeBackend::open_renewable_clustered(
        runtime,
        "vol",
        false,
        renewable_grant(predecessor.clone()),
        Box::new(MockLeaseSession {
            events: Arc::clone(&predecessor_events),
            fail_renewal: false,
        }),
    )
    .expect("open predecessor");
    backend
        .write_blocks(2, &[0x6a; 4096], 4096)
        .expect("write predecessor bytes");
    backend.flush().expect("commit predecessor bytes");
    backend
        .release_clustered_authority()
        .expect("release predecessor");
    drop(backend);

    let runtime = PoolRuntime::open_block_devices(
        dir.path(),
        &[device],
        "tank",
        PoolRedundancyPolicy::default(),
        &StoreOptions::default(),
    )
    .expect("reopen Pool for successor");
    let mut successor = predecessor;
    successor.node_id = 8;
    successor.lease_id += 1;
    successor.write_fence = WriteFence::new(successor.epoch, 6);
    successor.expiration_deadline_ms += 60_000;
    let successor_events = Arc::new(Mutex::new(Vec::new()));
    let mut backend = PoolVolumeBackend::open_renewable_clustered(
        runtime,
        "vol",
        false,
        renewable_grant(successor),
        Box::new(MockLeaseSession {
            events: Arc::clone(&successor_events),
            fail_renewal: false,
        }),
    )
    .expect("open higher-fence successor");
    let read = backend
        .read_blocks(2, 1, 4096)
        .expect("successor reads committed predecessor bytes");
    assert_eq!(read.payload.unwrap(), vec![0x6a; 4096]);
    backend
        .release_clustered_authority()
        .expect("release successor");
    assert_eq!(*predecessor_events.lock().unwrap(), vec!["release"]);
    assert_eq!(*successor_events.lock().unwrap(), vec!["release"]);
}

#[test]
fn worker_dispatches_io_through_named_pool_volume() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut runtime, _device) = runtime(&dir);
    create_volume(&mut runtime, "vol", 2);
    let mut backend = PoolVolumeBackend::open_standalone(runtime, "vol", false)
        .expect("open Pool volume backend");
    let mut worker = DataQueueWorker::new(0, backend.geometry());

    let payload = [0xa5; 4096];
    let write = descriptor(UBLK_IO_OP_WRITE, 8, 8, 0x1000);
    worker
        .process_one_with_buffers(&mut backend, 1, &write, None, Some(&payload))
        .expect("dispatch write");
    let flush = descriptor(UBLK_IO_OP_FLUSH, 0, 0, 0);
    worker
        .process_one(&mut backend, 2, &flush)
        .expect("dispatch flush");

    let mut read_buffer = [0; 4096];
    let read = descriptor(UBLK_IO_OP_READ, 8, 8, 0x2000);
    worker
        .process_one_with_buffers(&mut backend, 3, &read, Some(&mut read_buffer), None)
        .expect("dispatch read");
    assert_eq!(read_buffer, payload);
}

#[test]
fn read_only_pool_volume_backend_refuses_every_mutation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut runtime, _device) = runtime(&dir);
    create_volume(&mut runtime, "vol", 5);
    let mut backend = PoolVolumeBackend::open_standalone(runtime, "vol", true)
        .expect("open read-only Pool volume backend");

    assert!(backend.is_read_only());
    assert!(matches!(
        backend.write_blocks(0, &[0x5a; 4096], 4096),
        Err(BackendError::ReadOnly)
    ));
    assert!(matches!(backend.flush(), Err(BackendError::ReadOnly)));
    assert!(matches!(
        backend.discard_blocks(0, 1, 4096),
        Err(BackendError::ReadOnly)
    ));
    assert!(matches!(
        backend.write_zeroes(0, 1, 4096),
        Err(BackendError::ReadOnly)
    ));

    let read = backend
        .read_blocks(0, 1, 4096)
        .expect("read-only backend must still read");
    assert_eq!(read.payload.expect("read payload"), vec![0; 4096]);
}

#[test]
fn named_pool_volumes_do_not_alias() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut runtime, _device) = runtime(&dir);
    create_volume(&mut runtime, "first", 3);
    create_volume(&mut runtime, "second", 4);

    let mut first = runtime.open_volume("first").expect("open first volume");
    let mut second = runtime.open_volume("second").expect("open second volume");
    first
        .write_blocks(&runtime, 0, &[0x11; 4096])
        .expect("write first volume");
    second
        .write_blocks(&runtime, 0, &[0x22; 4096])
        .expect("write second volume");
    first.flush(&mut runtime).expect("flush first volume");
    second.flush(&mut runtime).expect("flush second volume");

    assert_eq!(
        first.read_blocks(&runtime, 0, 1).expect("read first"),
        vec![0x11; 4096]
    );
    assert_eq!(
        second.read_blocks(&runtime, 0, 1).expect("read second"),
        vec![0x22; 4096]
    );
}
