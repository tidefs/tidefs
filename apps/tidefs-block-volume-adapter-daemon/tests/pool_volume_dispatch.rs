// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

use std::fs::OpenOptions;

use tidefs_block_volume_adapter_daemon::storage_backend::{
    BackendError, BlockVolumeStorageBackend, PoolVolumeBackend,
};
use tidefs_block_volume_adapter_daemon::DataQueueWorker;
use tidefs_dataset_lifecycle::{DatasetFlags, DatasetId, SyncGuarantee};
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
