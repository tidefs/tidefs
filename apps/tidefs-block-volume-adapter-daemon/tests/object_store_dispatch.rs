// Integration tests for ublk read/write dispatch through the
// BlockVolumeObjectStoreBackend to the LocalObjectStore.
//
// Exercises: single-block write-then-read round-trip, multi-block
// sequential I/O, unwritten-blocks-return-zeroes, and error-path
// dispatch to a missing store directory.
//
// Gate: BLOCK_VOLUME_UBLK_DATA_QUEUE_WORKER_GATE_OW_301Z

use tidefs_block_volume_adapter_core::{
    BlockVolumeCompletionClass, BlockVolumeGeometryRecord, BlockVolumeId,
};
use tidefs_block_volume_adapter_daemon::storage_backend::{
    BackendError, BlockVolumeObjectStoreBackend, BlockVolumeStorageBackend,
};
use tidefs_block_volume_adapter_daemon::ublk_control_open::data_queue_worker::{
    DataQueueWorker, DataQueueWorkerError,
};
use tidefs_block_volume_adapter_daemon::ublk_io::{io_desc, DEMO_BUFFER_ADDR};
use tidefs_block_volume_adapter_daemon::LINUX_SECTOR_SIZE_BYTES;
use tidefs_ublk_abi::{UblkSrvIoDesc, UBLK_IO_OP_READ, UBLK_IO_OP_WRITE};

const BLOCK_SIZE_BYTES: usize = 4096;
const SECTORS_PER_BLOCK: u32 = (BLOCK_SIZE_BYTES / LINUX_SECTOR_SIZE_BYTES) as u32;

fn read_desc(block: usize) -> UblkSrvIoDesc {
    io_desc(
        UBLK_IO_OP_READ,
        0,
        (block * SECTORS_PER_BLOCK as usize) as u64,
        SECTORS_PER_BLOCK,
        DEMO_BUFFER_ADDR,
    )
}

fn write_desc(block: usize) -> UblkSrvIoDesc {
    io_desc(
        UBLK_IO_OP_WRITE,
        0,
        (block * SECTORS_PER_BLOCK as usize) as u64,
        SECTORS_PER_BLOCK,
        DEMO_BUFFER_ADDR + 4096,
    )
}

fn test_geometry() -> BlockVolumeGeometryRecord {
    BlockVolumeGeometryRecord::new(BlockVolumeId::new(301_600), BLOCK_SIZE_BYTES, 64, 1)
}

// ── 1. Write-then-read round-trip through object store ────────────────

#[test]
fn object_store_write_then_read_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let geometry = test_geometry();
    let mut backend = BlockVolumeObjectStoreBackend::open(dir.path(), geometry)
        .expect("open object store backend");
    let mut worker = DataQueueWorker::new(0, geometry);

    let write_payload = [0xABu8; BLOCK_SIZE_BYTES];
    let desc = write_desc(0);

    let result = worker
        .process_one_with_buffers(&mut backend, 1, &desc, None, Some(&write_payload))
        .expect("write dispatch");

    assert_eq!(
        result.completion_class,
        BlockVolumeCompletionClass::Completed
    );
    assert_eq!(result.io_cmd.result, BLOCK_SIZE_BYTES as i32);
    assert_eq!(result.io_cmd.tag, 1);

    // Read back block 0
    let mut read_buf = vec![0u8; BLOCK_SIZE_BYTES];
    let read_result = worker
        .process_one_with_buffers(&mut backend, 2, &read_desc(0), Some(&mut read_buf), None)
        .expect("read dispatch");

    assert_eq!(
        read_result.completion_class,
        BlockVolumeCompletionClass::Completed
    );
    assert_eq!(&read_buf[..], &write_payload[..]);
}

// ── 2. Multi-block write and read ─────────────────────────────────────

#[test]
fn object_store_multi_block_write_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let geometry = test_geometry();
    let mut backend = BlockVolumeObjectStoreBackend::open(dir.path(), geometry)
        .expect("open object store backend");
    let mut worker = DataQueueWorker::new(0, geometry);

    // Write blocks 0, 2, 5 with distinct patterns
    let patterns: Vec<(usize, u8)> = vec![(0, 0x11), (2, 0x22), (5, 0x55)];
    for &(block, byte) in &patterns {
        let payload = vec![byte; BLOCK_SIZE_BYTES];
        worker
            .process_one_with_buffers(
                &mut backend,
                block as u16,
                &write_desc(block),
                None,
                Some(&payload),
            )
            .expect("write dispatch");
    }

    // Read back each pattern and verify
    for &(block, byte) in &patterns {
        let mut buf = vec![0u8; BLOCK_SIZE_BYTES];
        worker
            .process_one_with_buffers(
                &mut backend,
                block as u16,
                &read_desc(block),
                Some(&mut buf),
                None,
            )
            .expect("read dispatch");
        assert!(
            buf.iter().all(|&b| b == byte),
            "block {block}: expected all 0x{byte:02x}"
        );
    }

    // Unwritten block should read as zeroes
    let mut buf = vec![0xFFu8; BLOCK_SIZE_BYTES];
    worker
        .process_one_with_buffers(&mut backend, 99, &read_desc(3), Some(&mut buf), None)
        .expect("read dispatch");
    assert!(
        buf.iter().all(|&b| b == 0),
        "unwritten block should be zeroes"
    );
}

// ── 3. Error-path: object store with a file blocking segments dir ───

#[test]
fn object_store_file_blocking_segments_dir_returns_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let geometry = test_geometry();

    // Create a regular file at the expected segments directory path.
    // LocalObjectStore::open creates a "segments" subdirectory; if a file
    // already exists there, mkdir should fail.
    let segments_path = dir.path().join("segments");
    std::fs::write(&segments_path, b"blocking file").expect("write blocking file");

    match BlockVolumeObjectStoreBackend::open(dir.path(), geometry) {
        Ok(_) => panic!("opening with blocking segments file should fail"),
        Err(BackendError::Other(msg)) => {
            assert!(
                msg.contains("open object store") || msg.contains("create_dir"),
                "unexpected error: {msg}"
            );
        }
        Err(other) => panic!("expected BackendError::Other, got {other:?}"),
    }
}

// ── 4. Read beyond geometry bounds returns OOB refusal ────────────────

#[test]
fn object_store_read_out_of_bounds_returns_refusal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let geometry = test_geometry(); // 64 blocks
    let mut backend = BlockVolumeObjectStoreBackend::open(dir.path(), geometry)
        .expect("open object store backend");
    let mut worker = DataQueueWorker::new(0, geometry);

    // Block 64 is out of bounds (0-indexed, 64 blocks total)
    let mut buf = vec![0u8; BLOCK_SIZE_BYTES];
    let oob_desc = read_desc(64);
    let result = worker.process_one_with_buffers(&mut backend, 1, &oob_desc, Some(&mut buf), None);

    match result {
        Ok(entry) => {
            assert_eq!(
                entry.completion_class,
                BlockVolumeCompletionClass::RefusedOutOfBounds
            );
        }
        Err(DataQueueWorkerError::OutOfRange) => {
            // Also acceptable: the worker may refuse before dispatch
        }
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}

// ── 5. Uncached read across the object store backend ──────────────────

#[test]
fn object_store_backend_read_write_trait_direct() {
    let dir = tempfile::tempdir().expect("tempdir");
    let geometry = test_geometry();
    let mut backend = BlockVolumeObjectStoreBackend::open(dir.path(), geometry)
        .expect("open object store backend");

    // Write blocks directly through the trait
    let payload_a = vec![0xCAu8; BLOCK_SIZE_BYTES * 2]; // 2 blocks
    let write_result = backend
        .write_blocks(10, &payload_a, BLOCK_SIZE_BYTES)
        .expect("trait write_blocks");
    assert_eq!(
        write_result.completion_class,
        BlockVolumeCompletionClass::Completed
    );

    // Read back
    let read_result = backend
        .read_blocks(10, 2, BLOCK_SIZE_BYTES)
        .expect("trait read_blocks");
    assert_eq!(
        read_result.completion_class,
        BlockVolumeCompletionClass::Completed
    );
    assert_eq!(read_result.payload.as_deref(), Some(&payload_a[..]));

    // Read unwritten block region
    let empty_result = backend
        .read_blocks(20, 1, BLOCK_SIZE_BYTES)
        .expect("trait read_blocks of unwritten block");
    assert_eq!(
        empty_result.completion_class,
        BlockVolumeCompletionClass::Completed
    );
    let empty_payload = empty_result.payload.expect("payload should be present");
    assert_eq!(empty_payload.len(), BLOCK_SIZE_BYTES);
    assert!(empty_payload.iter().all(|&b| b == 0));
}
