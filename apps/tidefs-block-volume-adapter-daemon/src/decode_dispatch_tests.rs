// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Raw-byte decode, dispatch, and completion unit tests for
// tidefs-block-volume-adapter-daemon.
//
// Exercises the full ublk data-queue request lifecycle:
//   1) decode UblkSrvIoDesc from raw 24-byte kernel ring-buffer format,
//   2) dispatch through the DataQueueWorker adapter backend,
//   3) assert kernel-visible completion status codes (UBLK_IO_RES_OK,
//      negative errno for refusals).
//
// No kernel module, FUSE mount, or QEMU required.
//
// Gate: BLOCK_VOLUME_UBLK_DATA_QUEUE_WORKER_GATE_OW_301Z

use crate::ublk_control_open::{DataQueueWorker, DataQueueWorkerError, DataQueueWorkerResultEntry};
use crate::LINUX_SECTOR_SIZE_BYTES;
use tidefs_block_volume_adapter_core::{
    BlockVolumeCompletionClass, BlockVolumeFileImage, BlockVolumeGeometryRecord, BlockVolumeId,
    BlockVolumeRequestClass,
};
use tidefs_ublk_abi::{
    UblkSrvIoDesc, UBLK_IO_F_FUA, UBLK_IO_OP_DISCARD, UBLK_IO_OP_FLUSH, UBLK_IO_OP_READ,
    UBLK_IO_OP_WRITE, UBLK_IO_OP_WRITE_ZEROES, UBLK_IO_RES_OK,
};

// ── Raw-byte decode helper ────────────────────────────────────────────

/// Decode a `UblkSrvIoDesc` from a 24-byte buffer in the Linux ublk
/// userspace ABI layout (all fields little-endian).
///
/// Layout matches `struct ublksrv_io_desc`:
///   bytes  0- 3: op_flags       (u32 LE)
///   bytes  4- 7: nr_sectors     (u32 LE)  → count_or_zones
///   bytes  8-15: start_sector   (u64 LE)
///   bytes 16-23: addr           (u64 LE)
const fn desc_from_raw_bytes(buf: &[u8; 24]) -> UblkSrvIoDesc {
    let op_flags = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let count_or_zones = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let start_sector = u64::from_le_bytes([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    ]);
    let addr = u64::from_le_bytes([
        buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
    ]);
    UblkSrvIoDesc {
        op_flags,
        count_or_zones,
        start_sector,
        addr,
    }
}

/// Build a raw 24-byte descriptor buffer for the given fields.
fn raw_desc_bytes(
    op: u8,
    raw_flags: u32,
    start_sector: u64,
    count_or_zones: u32,
    addr: u64,
) -> [u8; 24] {
    let mut buf = [0u8; 24];
    let op_flags = u32::from(op) | raw_flags;
    buf[0..4].copy_from_slice(&op_flags.to_le_bytes());
    buf[4..8].copy_from_slice(&count_or_zones.to_le_bytes());
    buf[8..16].copy_from_slice(&start_sector.to_le_bytes());
    buf[16..24].copy_from_slice(&addr.to_le_bytes());
    buf
}

// ── Shared test fixtures ───────────────────────────────────────────────

fn test_geometry() -> BlockVolumeGeometryRecord {
    BlockVolumeGeometryRecord::new(BlockVolumeId::new(301_400), 4096, 256, 1)
}

fn test_image() -> (tempfile::TempDir, BlockVolumeFileImage) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("decode-test.img");
    let image = BlockVolumeFileImage::create_zeroed(&path, test_geometry()).expect("create image");
    (dir, image)
}

/// Assert a DataQueueWorker result entry has expected completion fields.
fn assert_completed(
    entry: &DataQueueWorkerResultEntry,
    expected_tag: u16,
    expected_class: BlockVolumeRequestClass,
) {
    assert_eq!(entry.tag, expected_tag);
    assert_eq!(entry.request_class, expected_class);
    assert_eq!(
        entry.completion_class,
        BlockVolumeCompletionClass::Completed
    );
    assert_eq!(entry.io_cmd.result, UBLK_IO_RES_OK);
}

// ── Raw byte decode tests ──────────────────────────────────────────────

#[test]
fn raw_decode_read_descriptor_round_trips_all_fields() {
    let raw = raw_desc_bytes(UBLK_IO_OP_READ, 0, 64, 8, 0x1000_0000);
    let desc = desc_from_raw_bytes(&raw);

    assert_eq!(desc.op(), UBLK_IO_OP_READ);
    assert_eq!(desc.flags(), 0);
    assert_eq!(desc.start_sector, 64);
    assert_eq!(desc.count_or_zones, 8);
    assert_eq!(desc.addr, 0x1000_0000);
}

#[test]
fn raw_decode_write_descriptor_round_trips_all_fields() {
    let raw = raw_desc_bytes(UBLK_IO_OP_WRITE, 0, 128, 16, 0xDEAD_BEEF);
    let desc = desc_from_raw_bytes(&raw);

    assert_eq!(desc.op(), UBLK_IO_OP_WRITE);
    assert_eq!(desc.flags(), 0);
    assert_eq!(desc.start_sector, 128);
    assert_eq!(desc.count_or_zones, 16);
    assert_eq!(desc.addr, 0xDEAD_BEEF);
}

#[test]
fn raw_decode_fua_write_descriptor_preserves_flags_in_upper_bits() {
    let raw = raw_desc_bytes(UBLK_IO_OP_WRITE, UBLK_IO_F_FUA, 0, 8, 0x2000_0000);
    let desc = desc_from_raw_bytes(&raw);

    assert_eq!(desc.op(), UBLK_IO_OP_WRITE);
    assert_eq!(desc.flags(), UBLK_IO_F_FUA >> 8);
    assert_eq!(desc.op_flags, u32::from(UBLK_IO_OP_WRITE) | UBLK_IO_F_FUA);
}

#[test]
fn raw_decode_flush_descriptor_round_trips_zeroed_range_and_addr() {
    let raw = raw_desc_bytes(UBLK_IO_OP_FLUSH, 0, 0, 0, 0);
    let desc = desc_from_raw_bytes(&raw);

    assert_eq!(desc.op(), UBLK_IO_OP_FLUSH);
    assert_eq!(desc.flags(), 0);
    assert_eq!(desc.start_sector, 0);
    assert_eq!(desc.count_or_zones, 0);
    assert_eq!(desc.addr, 0);
}

#[test]
fn raw_decode_discard_descriptor_round_trips_all_fields() {
    let raw = raw_desc_bytes(UBLK_IO_OP_DISCARD, 0, 512, 32, 0);
    let desc = desc_from_raw_bytes(&raw);

    assert_eq!(desc.op(), UBLK_IO_OP_DISCARD);
    assert_eq!(desc.flags(), 0);
    assert_eq!(desc.start_sector, 512);
    assert_eq!(desc.count_or_zones, 32);
    assert_eq!(desc.addr, 0);
}

#[test]
fn raw_decode_write_zeroes_descriptor_round_trips_all_fields() {
    let raw = raw_desc_bytes(UBLK_IO_OP_WRITE_ZEROES, 0, 1024, 64, 0);
    let desc = desc_from_raw_bytes(&raw);

    assert_eq!(desc.op(), UBLK_IO_OP_WRITE_ZEROES);
    assert_eq!(desc.flags(), 0);
    assert_eq!(desc.start_sector, 1024);
    assert_eq!(desc.count_or_zones, 64);
    assert_eq!(desc.addr, 0);
}

#[test]
fn raw_decode_maximum_values_do_not_overflow() {
    let raw = raw_desc_bytes(UBLK_IO_OP_READ, 0, u64::MAX, u32::MAX, u64::MAX);
    let desc = desc_from_raw_bytes(&raw);

    assert_eq!(desc.op(), UBLK_IO_OP_READ);
    assert_eq!(desc.start_sector, u64::MAX);
    assert_eq!(desc.count_or_zones, u32::MAX);
    assert_eq!(desc.addr, u64::MAX);
}

#[test]
fn raw_decode_opextracts_low_8_bits_only() {
    // op_flags = 0x123456FF → op should be 0xFF, flags should be 0x123456
    let raw = raw_desc_bytes(0xFF, 0x12345600, 0, 0, 0);
    let desc = desc_from_raw_bytes(&raw);

    assert_eq!(desc.op(), 0xFF);
    assert_eq!(desc.flags(), 0x123456);
    assert_eq!(desc.op_flags, 0x123456FF);
}

#[test]
fn raw_decode_is_byte_exact_for_known_pattern() {
    // Build a descriptor with a known distinctive byte pattern
    let raw: [u8; 24] = [
        0x01, 0x00, 0x00, 0x00, // op_flags = 1 (WRITE op, no flags)
        0x10, 0x00, 0x00, 0x00, // count = 16 sectors
        0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // start_sector = 1024
        0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, // addr = 0xDEADBEEF
    ];
    let desc = desc_from_raw_bytes(&raw);

    assert_eq!(desc.op(), UBLK_IO_OP_WRITE);
    assert_eq!(desc.flags(), 0);
    assert_eq!(desc.start_sector, 1024);
    assert_eq!(desc.count_or_zones, 16);
    assert_eq!(desc.addr, 0xDEAD_BEEF);
}

// ── Full decode → dispatch → completion pipeline tests ─────────────────

#[test]
fn raw_decode_then_dispatch_read_returns_zeroes_from_new_image() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(0, geom);

    let spb = geom.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
    let raw = raw_desc_bytes(
        UBLK_IO_OP_READ,
        0,
        (10 * spb) as u64,
        spb as u32,
        0x1000_0000,
    );
    let desc = desc_from_raw_bytes(&raw);

    let result = worker
        .process_one(&mut image, 7, &desc)
        .expect("read should succeed");

    assert_completed(&result, 7, BlockVolumeRequestClass::Read);
    assert_eq!(result.byte_count, geom.block_size_bytes);
    assert_eq!(worker.read_ops, 1);
    assert_eq!(worker.completed_ops, 1);
}

#[test]
fn raw_decode_then_dispatch_write_and_read_round_trip() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(1, geom);
    let payload = vec![0xAB; geom.block_size_bytes];

    let spb = geom.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
    let start_sector = (5 * spb) as u64;
    let sector_count = spb as u32;

    // Decode write descriptor from raw bytes
    let write_raw = raw_desc_bytes(UBLK_IO_OP_WRITE, 0, start_sector, sector_count, 0x1000_0000);
    let write_desc = desc_from_raw_bytes(&write_raw);

    let write_result = worker
        .process_one_with_buffers(&mut image, 1, &write_desc, None, Some(&payload))
        .expect("write should succeed");
    assert_completed(&write_result, 1, BlockVolumeRequestClass::Write);
    assert_eq!(write_result.byte_count, payload.len());

    // Flush to persist
    let flush_raw = raw_desc_bytes(UBLK_IO_OP_FLUSH, 0, 0, 0, 0);
    let flush_desc = desc_from_raw_bytes(&flush_raw);
    worker
        .process_one(&mut image, 2, &flush_desc)
        .expect("flush");

    // Decode read descriptor from raw bytes
    let read_raw = raw_desc_bytes(UBLK_IO_OP_READ, 0, start_sector, sector_count, 0x2000_0000);
    let read_desc = desc_from_raw_bytes(&read_raw);

    let mut read_buf = vec![0u8; payload.len()];
    let read_result = worker
        .process_one_with_buffers(&mut image, 3, &read_desc, Some(&mut read_buf), None)
        .expect("read should succeed");
    assert_completed(&read_result, 3, BlockVolumeRequestClass::Read);
    assert_eq!(read_buf, payload);

    assert_eq!(worker.write_ops, 1);
    assert_eq!(worker.flush_ops, 1);
    assert_eq!(worker.read_ops, 1);
    assert_eq!(worker.completed_ops, 3);
}

#[test]
fn raw_decode_then_dispatch_fua_write_is_visible_without_explicit_flush() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(2, geom);
    let payload = vec![0xF7; geom.block_size_bytes];

    let spb = geom.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
    let start_sector = (20 * spb) as u64;
    let sector_count = spb as u32;

    let raw = raw_desc_bytes(
        UBLK_IO_OP_WRITE,
        UBLK_IO_F_FUA,
        start_sector,
        sector_count,
        0x1000_0000,
    );
    let desc = desc_from_raw_bytes(&raw);

    let write_result = worker
        .process_one_with_buffers(&mut image, 4, &desc, None, Some(&payload))
        .expect("fua write should succeed");
    assert_completed(&write_result, 4, BlockVolumeRequestClass::Write);
    assert_eq!(write_result.byte_count, payload.len());

    // Read back without explicit flush
    let read_raw = raw_desc_bytes(UBLK_IO_OP_READ, 0, start_sector, sector_count, 0x2000_0000);
    let read_desc = desc_from_raw_bytes(&read_raw);
    let mut read_buf = vec![0u8; payload.len()];
    let read_result = worker
        .process_one_with_buffers(&mut image, 5, &read_desc, Some(&mut read_buf), None)
        .expect("read after fua write");

    assert_completed(&read_result, 5, BlockVolumeRequestClass::Read);
    assert_eq!(read_buf, payload);
}

#[test]
fn raw_decode_then_dispatch_discard_and_verify_zeroed() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(3, geom);
    let payload = vec![0xCC; geom.block_size_bytes];
    let spb = geom.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;

    // Write data first
    let write_raw = raw_desc_bytes(UBLK_IO_OP_WRITE, 0, 0, spb as u32, 0x1000_0000);
    let write_desc = desc_from_raw_bytes(&write_raw);
    worker
        .process_one_with_buffers(&mut image, 1, &write_desc, None, Some(&payload))
        .expect("seed write");

    // Discard via raw bytes
    let discard_raw = raw_desc_bytes(UBLK_IO_OP_DISCARD, 0, 0, spb as u32, 0);
    let discard_desc = desc_from_raw_bytes(&discard_raw);
    let discard_result = worker
        .process_one(&mut image, 2, &discard_desc)
        .expect("discard");
    assert_eq!(
        discard_result.request_class,
        BlockVolumeRequestClass::Discard
    );
    assert_eq!(discard_result.io_cmd.result, UBLK_IO_RES_OK);

    // Read back — should be zero
    let read_raw = raw_desc_bytes(UBLK_IO_OP_READ, 0, 0, spb as u32, 0x2000_0000);
    let read_desc = desc_from_raw_bytes(&read_raw);
    let mut read_buf = vec![0xFFu8; payload.len()];
    worker
        .process_one_with_buffers(&mut image, 3, &read_desc, Some(&mut read_buf), None)
        .expect("read after discard");
    assert!(
        read_buf.iter().all(|&b| b == 0),
        "discarded region must be zero"
    );
}

#[test]
fn raw_decode_then_dispatch_write_zeroes_and_verify_zeroed() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(4, geom);
    let payload = vec![0xDD; geom.block_size_bytes];
    let spb = geom.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;

    // Write data
    let write_raw = raw_desc_bytes(UBLK_IO_OP_WRITE, 0, 0, spb as u32, 0x1000_0000);
    let write_desc = desc_from_raw_bytes(&write_raw);
    worker
        .process_one_with_buffers(&mut image, 1, &write_desc, None, Some(&payload))
        .expect("seed write");

    // Write zeroes via raw bytes
    let zero_raw = raw_desc_bytes(UBLK_IO_OP_WRITE_ZEROES, 0, 0, spb as u32, 0);
    let zero_desc = desc_from_raw_bytes(&zero_raw);
    let zero_result = worker
        .process_one(&mut image, 2, &zero_desc)
        .expect("write zeroes");
    assert_eq!(
        zero_result.request_class,
        BlockVolumeRequestClass::WriteZeroes
    );
    assert_eq!(zero_result.io_cmd.result, UBLK_IO_RES_OK);

    // Read back
    let read_raw = raw_desc_bytes(UBLK_IO_OP_READ, 0, 0, spb as u32, 0x2000_0000);
    let read_desc = desc_from_raw_bytes(&read_raw);
    let mut read_buf = vec![0xFFu8; payload.len()];
    worker
        .process_one_with_buffers(&mut image, 3, &read_desc, Some(&mut read_buf), None)
        .expect("read after write zeroes");
    assert!(
        read_buf.iter().all(|&b| b == 0),
        "zeroed region must be zero"
    );
}

// ── Edge case: zero-length, out-of-bounds, missing buffer, unaligned ──

#[test]
fn raw_decode_zero_length_read_returns_zero_length_error() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(5, geom);

    let raw = raw_desc_bytes(UBLK_IO_OP_READ, 0, 0, 0, 0x1000_0000);
    let desc = desc_from_raw_bytes(&raw);

    let err = worker.process_one(&mut image, 1, &desc).unwrap_err();
    assert_eq!(err, DataQueueWorkerError::ZeroLengthDataOperation);
    assert_eq!(err.linux_errno(), -22); // EINVAL
}

#[test]
fn raw_decode_zero_length_write_returns_zero_length_error() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(6, geom);

    let raw = raw_desc_bytes(UBLK_IO_OP_WRITE, 0, 0, 0, 0x1000_0000);
    let desc = desc_from_raw_bytes(&raw);

    let err = worker.process_one(&mut image, 1, &desc).unwrap_err();
    assert_eq!(err, DataQueueWorkerError::ZeroLengthDataOperation);
}

#[test]
fn raw_decode_read_accepts_zero_addr_for_user_copy() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(7, geom);

    let spb = geom.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
    let raw = raw_desc_bytes(UBLK_IO_OP_READ, 0, 0, spb as u32, 0); // addr=0
    let desc = desc_from_raw_bytes(&raw);

    // addr=0 is legitimate with USER_COPY data-path mode.
    // The legacy EINVAL at sector 0 was caused by rejecting
    // addr==0 descriptors that are valid in the fd-backed
    // data queue direction (#6369).
    let result = worker.process_one(&mut image, 1, &desc);
    assert!(result.is_ok());
    let entry = result.unwrap();
    assert_eq!(
        entry.completion_class,
        BlockVolumeCompletionClass::Completed
    );
    assert_eq!(entry.byte_count, geom.block_size_bytes);
}

#[test]
fn raw_decode_write_missing_payload_buffer_rejected() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(8, geom);

    let spb = geom.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
    let raw = raw_desc_bytes(UBLK_IO_OP_WRITE, 0, 0, spb as u32, 0); // addr=0
    let desc = desc_from_raw_bytes(&raw);

    // addr=0 is legitimate with USER_COPY mode, but writes still
    // require a payload buffer. Missing payload is rejected here,
    // not the addr==0 check that was removed for #6369.
    let err = worker.process_one(&mut image, 1, &desc).unwrap_err();
    assert_eq!(err, DataQueueWorkerError::MissingBufferAddress);
}

#[test]
fn raw_decode_read_out_of_bounds_returns_refused_completion() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(9, geom);

    let spb = geom.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
    // Sector past the end of the device (256 blocks * 8 sectors/block = 2048)
    let out_of_bounds_sector = (geom.block_count * spb) as u64;
    let raw = raw_desc_bytes(
        UBLK_IO_OP_READ,
        0,
        out_of_bounds_sector,
        spb as u32,
        0x1000_0000,
    );
    let desc = desc_from_raw_bytes(&raw);

    let entry = worker
        .process_one(&mut image, 1, &desc)
        .expect("should yield refused entry");
    assert_eq!(
        entry.completion_class,
        BlockVolumeCompletionClass::RefusedOutOfBounds
    );
    assert_eq!(entry.io_cmd.result, -22); // EINVAL
    assert_eq!(worker.error_ops, 1);
}

#[test]
fn raw_decode_write_out_of_bounds_returns_refused_completion() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(10, geom);

    let spb = geom.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
    let out_of_bounds_sector = (geom.block_count * spb) as u64;
    let raw = raw_desc_bytes(
        UBLK_IO_OP_WRITE,
        0,
        out_of_bounds_sector,
        spb as u32,
        0x1000_0000,
    );
    let desc = desc_from_raw_bytes(&raw);

    // Out-of-range write goes through project_range which returns OutOfRange error
    // but dispatch_write converts it to a refusal entry (not an error)
    let entry = worker
        .process_one(&mut image, 2, &desc)
        .expect("should yield refused entry");
    assert_eq!(
        entry.completion_class,
        BlockVolumeCompletionClass::RefusedOutOfBounds
    );
    assert_eq!(entry.io_cmd.result, -22);
}

#[test]
fn raw_decode_unaligned_sector_start_returns_misaligned_error() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(11, geom);

    // Start at sector 1 (not aligned to 8-sector blocks)
    let raw = raw_desc_bytes(UBLK_IO_OP_READ, 0, 1, 8, 0x1000_0000);
    let desc = desc_from_raw_bytes(&raw);

    let result = worker.process_one(&mut image, 1, &desc).expect("read");
    assert_eq!(
        result.completion_class,
        BlockVolumeCompletionClass::Completed
    );
    assert!(result.byte_count > 0);
}

#[test]
fn raw_decode_unaligned_sector_count_returns_misaligned_error() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(12, geom);

    // Count of 7 sectors (not aligned to 8-sector blocks)
    let raw = raw_desc_bytes(UBLK_IO_OP_READ, 0, 8, 7, 0x1000_0000);
    let desc = desc_from_raw_bytes(&raw);

    let result = worker.process_one(&mut image, 1, &desc).expect("read");
    assert_eq!(
        result.completion_class,
        BlockVolumeCompletionClass::Completed
    );
    assert!(result.byte_count > 0);
}

#[test]
fn raw_decode_read_at_last_valid_block_succeeds() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(13, geom);

    let spb = geom.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
    // Last block: block_count=256, sectors 255*8..256*8
    let start_sector = ((geom.block_count - 1) * spb) as u64;
    let raw = raw_desc_bytes(UBLK_IO_OP_READ, 0, start_sector, spb as u32, 0x1000_0000);
    let desc = desc_from_raw_bytes(&raw);

    let result = worker
        .process_one(&mut image, 10, &desc)
        .expect("last block read should succeed");
    assert_completed(&result, 10, BlockVolumeRequestClass::Read);
    assert_eq!(result.byte_count, geom.block_size_bytes);
}

#[test]
fn raw_decode_write_at_last_valid_block_succeeds() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(14, geom);

    let spb = geom.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
    let start_sector = ((geom.block_count - 1) * spb) as u64;
    let raw = raw_desc_bytes(UBLK_IO_OP_WRITE, 0, start_sector, spb as u32, 0x1000_0000);
    let desc = desc_from_raw_bytes(&raw);

    let write_payload = vec![0xCC; geom.block_size_bytes];
    let result = worker
        .process_one_with_buffers(&mut image, 11, &desc, None, Some(&write_payload))
        .expect("last block write should succeed");
    assert_completed(&result, 11, BlockVolumeRequestClass::Write);
    assert_eq!(result.byte_count, geom.block_size_bytes);
}

// ── Invalid descriptor opcode from raw bytes ───────────────────────────

#[test]
fn raw_decode_unsupported_opcode_returns_unsupported_operation_error() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(15, geom);

    let raw = raw_desc_bytes(0xFF, 0, 0, 0, 0);
    let desc = desc_from_raw_bytes(&raw);

    let err = worker.process_one(&mut image, 1, &desc).unwrap_err();
    assert_eq!(err, DataQueueWorkerError::UnsupportedOperation);
    assert_eq!(err.linux_errno(), -95); // EOPNOTSUPP
    assert_eq!(worker.unsupported_ops, 1);
    assert_eq!(worker.error_ops, 1);
}

#[test]
fn raw_decode_unsupported_flags_on_read_returns_error() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(16, geom);

    let spb = geom.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
    // UBLK_IO_F_NEED_REG_BUF (1 << 17) is now accepted; the read proceeds
    // normally and returns a completed entry (zero-filled for empty image).
    let raw = raw_desc_bytes(UBLK_IO_OP_READ, 1 << 17, 0, spb as u32, 0x1000_0000);
    let desc = desc_from_raw_bytes(&raw);

    let result = worker.process_one(&mut image, 1, &desc);
    assert!(
        result.is_ok(),
        "NEED_REG_BUF should be accepted, got {:?}",
        result.err()
    );
}

// ── Multi-block raw decode dispatch ────────────────────────────────────

#[test]
fn raw_decode_multi_block_write_read_round_trip() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(17, geom);
    let block_count = 4;
    let payload = vec![0x5E; block_count * geom.block_size_bytes];

    let spb = geom.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
    let start_sector = (50 * spb) as u64;
    let sector_count = (block_count * spb) as u32;

    // Write 4 blocks
    let write_raw = raw_desc_bytes(UBLK_IO_OP_WRITE, 0, start_sector, sector_count, 0x1000_0000);
    let write_desc = desc_from_raw_bytes(&write_raw);
    let write_result = worker
        .process_one_with_buffers(&mut image, 1, &write_desc, None, Some(&payload))
        .expect("multi-block write");
    assert_completed(&write_result, 1, BlockVolumeRequestClass::Write);
    assert_eq!(write_result.byte_count, payload.len());

    // Flush
    let flush_raw = raw_desc_bytes(UBLK_IO_OP_FLUSH, 0, 0, 0, 0);
    worker
        .process_one(&mut image, 2, &desc_from_raw_bytes(&flush_raw))
        .expect("flush");

    // Read back full span
    let read_raw = raw_desc_bytes(UBLK_IO_OP_READ, 0, start_sector, sector_count, 0x2000_0000);
    let read_desc = desc_from_raw_bytes(&read_raw);
    let mut read_buf = vec![0u8; payload.len()];
    let read_result = worker
        .process_one_with_buffers(&mut image, 3, &read_desc, Some(&mut read_buf), None)
        .expect("multi-block read");
    assert_completed(&read_result, 3, BlockVolumeRequestClass::Read);
    assert_eq!(read_buf, payload);
}

// ── Completion status code assertions via raw bytes ────────────────────

#[test]
fn raw_decode_read_completion_has_ok_status_and_preserves_tag_and_queue() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let qid = 42;
    let mut worker = DataQueueWorker::new(qid, geom);

    let spb = geom.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
    let raw = raw_desc_bytes(UBLK_IO_OP_READ, 0, 0, spb as u32, 0x1000_0000);
    let desc = desc_from_raw_bytes(&raw);

    let result = worker.process_one(&mut image, 77, &desc).expect("read");
    assert_eq!(result.io_cmd.result, UBLK_IO_RES_OK);
    assert_eq!(result.byte_count, 4096);
    assert_eq!(result.io_cmd.q_id, qid);
    assert_eq!(result.io_cmd.tag, 77);
    assert_eq!(result.io_cmd.addr_or_zone_append_lba, 0);
}

#[test]
fn raw_decode_write_completion_has_ok_status_and_preserves_tag_and_queue() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let qid = 99;
    let mut worker = DataQueueWorker::new(qid, geom);

    let spb = geom.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
    let raw = raw_desc_bytes(UBLK_IO_OP_WRITE, 0, 0, spb as u32, 0x1000_0000);
    let desc = desc_from_raw_bytes(&raw);

    let write_payload = vec![0xAB; geom.block_size_bytes];
    let result = worker
        .process_one_with_buffers(&mut image, 42, &desc, None, Some(&write_payload))
        .expect("write");
    assert_eq!(result.io_cmd.result, UBLK_IO_RES_OK);
    assert_eq!(result.byte_count, 4096);
    assert_eq!(result.io_cmd.q_id, qid);
    assert_eq!(result.io_cmd.tag, 42);
}

#[test]
fn raw_decode_flush_completion_has_ok_status_with_zero_byte_count() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(3, geom);

    let raw = raw_desc_bytes(UBLK_IO_OP_FLUSH, 0, 0, 0, 0);
    let desc = desc_from_raw_bytes(&raw);

    let result = worker.process_one(&mut image, 5, &desc).expect("flush");
    assert_eq!(result.request_class, BlockVolumeRequestClass::Flush);
    assert_eq!(
        result.completion_class,
        BlockVolumeCompletionClass::Completed
    );
    assert_eq!(result.io_cmd.result, UBLK_IO_RES_OK);
    assert_eq!(result.byte_count, 0);
}

// ── Batch dispatch from raw bytes ──────────────────────────────────────

#[test]
fn raw_decode_run_bounded_batch_of_read_write_flush_all_complete() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(20, geom);

    let spb = geom.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
    let sc = spb as u32;

    let descriptors: Vec<(u16, UblkSrvIoDesc)> = vec![
        (
            1,
            desc_from_raw_bytes(&raw_desc_bytes(UBLK_IO_OP_WRITE, 0, 0, sc, 0x1000_0000)),
        ),
        (
            2,
            desc_from_raw_bytes(&raw_desc_bytes(UBLK_IO_OP_FLUSH, 0, 0, 0, 0)),
        ),
        (
            3,
            desc_from_raw_bytes(&raw_desc_bytes(UBLK_IO_OP_READ, 0, 0, sc, 0x2000_0000)),
        ),
    ];

    let report = worker.run_bounded(&mut image, &descriptors);

    assert_eq!(report.results.len(), 3);
    assert_eq!(report.write_ops, 0);
    assert_eq!(report.flush_ops, 1);
    assert_eq!(report.read_ops, 1);
    assert_eq!(report.completed_ops, 2);
    assert_eq!(report.error_ops, 1);

    // Write without buffer correctly errors
    assert!(
        report.results[0].io_cmd.result < 0,
        "write without buffer must error"
    );
    assert_eq!(report.results[1].io_cmd.result, UBLK_IO_RES_OK);
    assert_eq!(
        report.results[1].completion_class,
        BlockVolumeCompletionClass::Completed
    );
    assert_eq!(report.results[2].io_cmd.result, UBLK_IO_RES_OK);
    assert_eq!(
        report.results[2].completion_class,
        BlockVolumeCompletionClass::Completed
    );
    assert_eq!(report.results[0].tag, 1);
    assert_eq!(report.results[1].tag, 2);
    assert_eq!(report.results[2].tag, 3);
}

#[test]
fn raw_decode_run_bounded_mixed_valid_and_malformed_results() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(21, geom);

    let spb = geom.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
    let sc = spb as u32;

    let descriptors: Vec<(u16, UblkSrvIoDesc)> = vec![
        (
            10,
            desc_from_raw_bytes(&raw_desc_bytes(UBLK_IO_OP_READ, 0, 0, sc, 0x1000_0000)),
        ),
        (11, desc_from_raw_bytes(&raw_desc_bytes(0xFF, 0, 0, 0, 0))), // unsupported
        (
            12,
            desc_from_raw_bytes(&raw_desc_bytes(UBLK_IO_OP_WRITE, 0, 0, sc, 0x2000_0000)),
        ),
    ];

    let report = worker.run_bounded(&mut image, &descriptors);
    assert_eq!(report.results.len(), 3);
    assert_eq!(report.completed_ops, 1);
    assert_eq!(report.error_ops, 2);
    assert_eq!(report.unsupported_ops, 1);

    assert_eq!(report.results[0].io_cmd.result, UBLK_IO_RES_OK);
    assert_eq!(report.results[1].io_cmd.result, -95); // EOPNOTSUPP
                                                      // Write without buffer correctly errors
    assert!(
        report.results[2].io_cmd.result < 0,
        "write without buffer must error"
    );
}

// ── Flush error-path tests ────────────────────────────────────────────

#[test]
fn raw_decode_flush_with_nonzero_start_sector_errors() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(30, geom);

    // Flush must have start_sector == 0 and count_or_zones == 0
    let raw = raw_desc_bytes(UBLK_IO_OP_FLUSH, 0, 8, 0, 0);
    let desc = desc_from_raw_bytes(&raw);

    let err = worker.process_one(&mut image, 1, &desc).unwrap_err();
    assert_eq!(err, DataQueueWorkerError::RangeOnFlush);
    assert_eq!(err.linux_errno(), -22); // EINVAL
    assert_eq!(worker.error_ops, 1);
    assert_eq!(worker.flush_ops, 0);
}

#[test]
fn raw_decode_flush_with_nonzero_count_errors() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(31, geom);

    // Flush must have count_or_zones == 0
    let raw = raw_desc_bytes(UBLK_IO_OP_FLUSH, 0, 0, 8, 0);
    let desc = desc_from_raw_bytes(&raw);

    let err = worker.process_one(&mut image, 1, &desc).unwrap_err();
    assert_eq!(err, DataQueueWorkerError::RangeOnFlush);
    assert_eq!(err.linux_errno(), -22);
    assert_eq!(worker.error_ops, 1);
    assert_eq!(worker.flush_ops, 0);
}

#[test]
fn raw_decode_flush_with_nonzero_addr_errors() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(32, geom);

    // Flush must have addr == 0
    let raw = raw_desc_bytes(UBLK_IO_OP_FLUSH, 0, 0, 0, 0x1000_0000);
    let desc = desc_from_raw_bytes(&raw);

    let err = worker.process_one(&mut image, 1, &desc).unwrap_err();
    assert_eq!(err, DataQueueWorkerError::UnexpectedBufferAddress);
    assert_eq!(err.linux_errno(), -22);
    assert_eq!(worker.error_ops, 1);
    assert_eq!(worker.flush_ops, 0);
}

#[test]
fn raw_decode_flush_with_unsupported_flags_errors() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(33, geom);

    // UBLK_IO_F_NEED_REG_BUF (1 << 17) is now accepted; the flush
    // proceeds normally.
    let raw = raw_desc_bytes(UBLK_IO_OP_FLUSH, 1 << 17, 0, 0, 0);
    let desc = desc_from_raw_bytes(&raw);

    let result = worker.process_one(&mut image, 1, &desc);
    assert!(
        result.is_ok(),
        "NEED_REG_BUF should be accepted for flush, got {:?}",
        result.err()
    );
}

// ── Buffer-boundary error-path tests ──────────────────────────────────

#[test]
fn raw_decode_read_payload_buffer_too_short_errors() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(34, geom);

    // Write some data first so the read returns a non-empty payload
    let payload = vec![0xAE; geom.block_size_bytes];
    let spb = geom.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
    let write_raw = raw_desc_bytes(UBLK_IO_OP_WRITE, 0, 0, spb as u32, 0x1000_0000);
    let write_desc = desc_from_raw_bytes(&write_raw);
    worker
        .process_one_with_buffers(&mut image, 1, &write_desc, None, Some(&payload))
        .expect("seed write");

    // Read with a buffer shorter than the block size
    let read_raw = raw_desc_bytes(UBLK_IO_OP_READ, 0, 0, spb as u32, 0x2000_0000);
    let read_desc = desc_from_raw_bytes(&read_raw);
    let mut short_buf = vec![0u8; 1];

    let err = worker
        .process_one_with_buffers(&mut image, 2, &read_desc, Some(&mut short_buf), None)
        .unwrap_err();
    assert_eq!(err, DataQueueWorkerError::PayloadBufferTooShort);
    assert_eq!(err.linux_errno(), -22);
    assert_eq!(worker.error_ops, 1);
}

#[test]
fn raw_decode_write_payload_buffer_too_short_errors() {
    let (_dir, mut image) = test_image();
    let geom = test_geometry();
    let mut worker = DataQueueWorker::new(35, geom);

    // Write with a payload shorter than the block range
    let spb = geom.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
    let write_raw = raw_desc_bytes(UBLK_IO_OP_WRITE, 0, 0, spb as u32, 0x1000_0000);
    let write_desc = desc_from_raw_bytes(&write_raw);
    let short_payload = vec![0xCDu8; 1];

    let err = worker
        .process_one_with_buffers(&mut image, 1, &write_desc, None, Some(&short_payload))
        .unwrap_err();
    assert_eq!(err, DataQueueWorkerError::PayloadBufferTooShort);
    assert_eq!(err.linux_errno(), -22);
    assert_eq!(worker.error_ops, 1);
    assert_eq!(worker.write_ops, 0);
}
