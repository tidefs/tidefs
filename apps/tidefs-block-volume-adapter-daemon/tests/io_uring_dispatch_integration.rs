// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests for the io_uring dispatch path: create a tempfile
//! backing store, open a UblkIoUringDispatcher, submit read/write/flush ops,
//! reap completions via reap_ublk_completions(), and assert byte-level
//! correctness and accumulator counters.
//!
//! Gate: BLOCK_VOLUME_UBLK_IO_URING_DISPATCH_GATE_OW_301M

use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use tempfile::tempfile;

use tidefs_block_volume_adapter_core::{BlockVolumeGeometryRecord, BlockVolumeId};
use tidefs_block_volume_adapter_daemon::ublk_completion::reap_ublk_completions;
use tidefs_block_volume_adapter_daemon::ublk_io::{
    dispatch_ublk_io_descriptor, io_desc, UblkIoDispatchError,
};
use tidefs_block_volume_adapter_daemon::ublk_io_uring::UblkIoUringDispatcher;
use tidefs_ublk_abi::{UblkSrvIoDesc, UBLK_IO_OP_FLUSH, UBLK_IO_OP_READ, UBLK_IO_RES_OK};

const BLOCK_SIZE: usize = 4096;
const SECTORS_PER_BLOCK: u32 = (BLOCK_SIZE / 512) as u32;

fn geometry(block_count: usize) -> BlockVolumeGeometryRecord {
    BlockVolumeGeometryRecord::new(BlockVolumeId::new(9001), BLOCK_SIZE, block_count, 1)
}

fn create_tempfile_fd(size_bytes: usize) -> (std::fs::File, RawFd) {
    let mut f = tempfile().expect("tempfile");
    f.set_len(size_bytes as u64).expect("ftruncate");
    f.flush().expect("flush");
    let fd = f.as_raw_fd();
    (f, fd)
}

fn read_desc(block: usize) -> UblkSrvIoDesc {
    io_desc(
        UBLK_IO_OP_READ,
        0,
        (block * SECTORS_PER_BLOCK as usize) as u64,
        SECTORS_PER_BLOCK,
        0x2000_0000,
    )
}

// ── 1. Dispatcher setup ──────────────────────────────────────────────

#[test]
fn dispatcher_new_with_tempfile_fd_succeeds() {
    let (_f, fd) = create_tempfile_fd(BLOCK_SIZE * 16);
    let dispatcher = UblkIoUringDispatcher::new(fd);
    assert!(
        dispatcher.is_ok(),
        "dispatcher new should succeed with valid fd"
    );
}

#[test]
fn dispatcher_starts_with_zero_counters() {
    let (_f, fd) = create_tempfile_fd(BLOCK_SIZE * 16);
    let d = UblkIoUringDispatcher::new(fd).expect("dispatcher");
    assert_eq!(d.bytes_read, 0);
    assert_eq!(d.bytes_written, 0);
    assert_eq!(d.completed_ops, 0);
    assert_eq!(d.error_ops, 0);
    assert_eq!(d.read_ops, 0);
    assert_eq!(d.write_ops, 0);
    assert_eq!(d.flush_ops, 0);
}

// ── 2. write_at + read_at round-trip ─────────────────────────────────

#[test]
fn write_then_read_single_block_roundtrip() {
    let (_f, fd) = create_tempfile_fd(BLOCK_SIZE * 16);
    let mut d = UblkIoUringDispatcher::new(fd).expect("dispatcher");

    let payload: Vec<u8> = (0..BLOCK_SIZE).map(|i| (i % 251) as u8).collect();
    let mut read_buf = vec![0u8; BLOCK_SIZE];

    d.write_at(0, &payload).expect("write_at block 0");
    assert_eq!(d.write_ops, 1);
    assert_eq!(d.bytes_written, BLOCK_SIZE as u64);

    d.flush().expect("flush");
    assert_eq!(d.flush_ops, 1);

    d.read_at(0, &mut read_buf).expect("read_at block 0");
    assert_eq!(d.read_ops, 1);
    assert_eq!(d.bytes_read, BLOCK_SIZE as u64);

    assert_eq!(&read_buf[..], &payload[..]);
    assert_eq!(d.completed_ops, 3);
    assert_eq!(d.error_ops, 0);
}

// ── 3. dispatch_ublk_io_descriptor read path ─────────────────────────

#[test]
fn dispatch_descriptor_read_returns_correct_data() {
    let (_f, fd) = create_tempfile_fd(BLOCK_SIZE * 16);
    let mut d = UblkIoUringDispatcher::new(fd).expect("dispatcher");
    let geo = geometry(16);

    let wpayload: Vec<u8> = (0..BLOCK_SIZE).map(|i| (i % 256) as u8).collect();
    let mut rbuf = vec![0u8; BLOCK_SIZE];

    // Write data at block 1 via the blocking API
    d.write_at(BLOCK_SIZE as u64, &wpayload).expect("write");
    d.flush().expect("flush");

    // Read via dispatch_ublk_io_descriptor
    let n = dispatch_ublk_io_descriptor(&mut d, read_desc(1), geo, Some(&mut rbuf))
        .expect("read dispatch");

    assert_eq!(n, BLOCK_SIZE);
    assert_eq!(&rbuf[..], &wpayload[..]);
    assert_eq!(d.read_ops, 1);
    assert_eq!(d.bytes_read, BLOCK_SIZE as u64);
}

// ── 4. Batch submit + reap using submit and submit_and_wait ──────────

#[test]
fn batch_submit_write_flush_reap_counters() {
    let (_f, fd) = create_tempfile_fd(BLOCK_SIZE * 16);
    let mut d = UblkIoUringDispatcher::new(fd).expect("dispatcher");

    let wpayload: Vec<u8> = (0..BLOCK_SIZE).map(|i| (i % 253) as u8).collect();

    // Submit write + flush as a batch, reap via reap_completions
    d.submit_write(BLOCK_SIZE as u64, &wpayload)
        .expect("submit_write");
    d.submit_flush().expect("submit_flush");

    d.submit_and_wait(2).expect("submit_and_wait");

    let results = d.reap_completions();
    assert_eq!(results.len(), 2, "expected 2 completions, got {results:?}");

    assert_eq!(d.write_ops, 1);
    assert_eq!(d.flush_ops, 1);
    assert_eq!(d.completed_ops, 2);
    assert_eq!(d.error_ops, 0);
    assert_eq!(d.bytes_written, BLOCK_SIZE as u64);

    // Verify durability: read back synchronously
    let mut rbuf = vec![0u8; BLOCK_SIZE];
    d.read_at(BLOCK_SIZE as u64, &mut rbuf).expect("read_at");
    assert_eq!(&rbuf[..], &wpayload[..]);
}

// ── 5. reap_ublk_completions returns correct UblkSrvIoCmd ────────────

#[test]
fn reap_ublk_completions_returns_correct_ublk_cmds() {
    let (_f, fd) = create_tempfile_fd(BLOCK_SIZE * 16);
    let mut d = UblkIoUringDispatcher::new(fd).expect("dispatcher");

    let wpayload: Vec<u8> = (b'A'..=b'Z').cycle().take(BLOCK_SIZE).collect();

    // Use blocking path for data, then batch+reap for completion verification
    d.write_at(0, &wpayload).expect("write_at");
    d.flush().expect("flush");

    // Submit another flush and read in batch, then reap via ublk path
    d.submit_flush().expect("submit_flush");
    let mut rbuf = vec![0u8; BLOCK_SIZE];
    d.submit_read(0, &mut rbuf).expect("submit_read");

    d.submit_and_wait(2).expect("submit_and_wait");

    let cmds = reap_ublk_completions(&mut d, 7);
    assert_eq!(cmds.len(), 2, "expected 2 ublk cmds, got {cmds:?}");

    for cmd in &cmds {
        assert_eq!(cmd.q_id, 7);
        assert_eq!(cmd.result, UBLK_IO_RES_OK);
    }

    assert_eq!(&rbuf[..], &wpayload[..]);
    assert_eq!(d.read_ops, 1);
    assert_eq!(d.flush_ops, 2);
    assert_eq!(d.write_ops, 1);
}

// ── 6. Flush-only reap ───────────────────────────────────────────────

#[test]
fn flush_only_reap_returns_ok() {
    let (_f, fd) = create_tempfile_fd(BLOCK_SIZE * 16);
    let mut d = UblkIoUringDispatcher::new(fd).expect("dispatcher");

    d.submit_flush().expect("submit_flush");
    d.submit_and_wait(1).expect("submit_and_wait");

    let cmds = reap_ublk_completions(&mut d, 0);
    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0].result, UBLK_IO_RES_OK);
    assert_eq!(d.flush_ops, 1);
    assert_eq!(d.completed_ops, 1);
    assert_eq!(d.error_ops, 0);
}

// ── 7. Multi-block writes verify counters ────────────────────────────

#[test]
fn multi_block_writes_then_reads_verify_counters() {
    let (_f, fd) = create_tempfile_fd(BLOCK_SIZE * 16);
    let mut d = UblkIoUringDispatcher::new(fd).expect("dispatcher");

    let payload_a: Vec<u8> = vec![0xAA; BLOCK_SIZE];
    let payload_b: Vec<u8> = vec![0xBB; BLOCK_SIZE];
    let mut rbuf_a = vec![0u8; BLOCK_SIZE];
    let mut rbuf_b = vec![0u8; BLOCK_SIZE];

    d.write_at(0, &payload_a).expect("write block 0");
    d.write_at(BLOCK_SIZE as u64 * 2, &payload_b)
        .expect("write block 2");
    d.flush().expect("flush");

    assert_eq!(d.write_ops, 2);
    assert_eq!(d.bytes_written, (BLOCK_SIZE * 2) as u64);

    d.read_at(0, &mut rbuf_a).expect("read block 0");
    assert_eq!(&rbuf_a[..], &payload_a[..]);

    d.read_at(BLOCK_SIZE as u64, &mut rbuf_b)
        .expect("read block 1");
    assert_eq!(&rbuf_b[..], &vec![0u8; BLOCK_SIZE][..]);

    let mut rbuf_c = vec![0u8; BLOCK_SIZE];
    d.read_at(BLOCK_SIZE as u64 * 2, &mut rbuf_c)
        .expect("read block 2");
    assert_eq!(&rbuf_c[..], &payload_b[..]);

    assert_eq!(d.read_ops, 3);
    assert_eq!(d.bytes_read, (BLOCK_SIZE * 3) as u64);
    assert_eq!(d.completed_ops, 6); // 2 writes + 1 flush + 3 reads
    assert_eq!(d.error_ops, 0);
}

// ── 8. Discard and write_zeroes via dispatcher ────────────────────────

#[test]
fn discard_and_write_zeroes_ops_update_counters() {
    let (_f, fd) = create_tempfile_fd(BLOCK_SIZE * 16);
    let mut d = UblkIoUringDispatcher::new(fd).expect("dispatcher");

    let payload: Vec<u8> = vec![0xCC; BLOCK_SIZE * 4];
    d.write_at(0, &payload).expect("write");
    d.flush().expect("flush");

    // Discard first two blocks
    d.discard_at(0, (BLOCK_SIZE * 2) as u64).expect("discard");
    assert_eq!(d.discard_ops, 1);

    // Write-zeroes on block 2
    d.write_zeroes_at((BLOCK_SIZE * 2) as u64, BLOCK_SIZE as u64)
        .expect("write_zeroes");
    assert_eq!(d.write_zeroes_ops, 1);

    assert_eq!(d.completed_ops, 4); // write + flush + discard + zeroes
    assert_eq!(d.error_ops, 0);

    // Read discarded blocks — should complete without error
    let mut rbuf = vec![0xFFu8; BLOCK_SIZE];
    d.read_at(0, &mut rbuf).expect("read");
    assert_eq!(d.read_ops, 1);
}

// ── 9. dispatch_ublk_io_descriptor error paths ────────────────────────

#[test]
fn dispatch_descriptor_rejects_out_of_range() {
    let (_f, fd) = create_tempfile_fd(BLOCK_SIZE * 4);
    let mut d = UblkIoUringDispatcher::new(fd).expect("dispatcher");
    let geo = geometry(4);
    let mut buf = vec![0u8; BLOCK_SIZE];

    let result = dispatch_ublk_io_descriptor(&mut d, read_desc(10), geo, Some(&mut buf));
    assert!(result.is_err(), "out-of-range read should fail");
    match result.unwrap_err() {
        UblkIoDispatchError::OutOfRange => {}
        e => panic!("expected OutOfRange, got {e:?}"),
    }
}

#[test]
fn dispatch_descriptor_rejects_unaligned() {
    let (_f, fd) = create_tempfile_fd(BLOCK_SIZE * 4);
    let mut d = UblkIoUringDispatcher::new(fd).expect("dispatcher");
    let geo = geometry(4);
    let mut buf = vec![0u8; BLOCK_SIZE];

    let desc = io_desc(UBLK_IO_OP_READ, 0, 1, 8, 0x2000_0000);
    let result = dispatch_ublk_io_descriptor(&mut d, desc, geo, Some(&mut buf));
    assert!(result.is_err(), "unaligned read should fail");
    match result.unwrap_err() {
        UblkIoDispatchError::SectorRangeNotBlockAligned => {}
        e => panic!("expected SectorRangeNotBlockAligned, got {e:?}"),
    }
}

#[test]
fn dispatch_descriptor_rejects_flush_with_range() {
    let (_f, fd) = create_tempfile_fd(BLOCK_SIZE * 4);
    let mut d = UblkIoUringDispatcher::new(fd).expect("dispatcher");
    let geo = geometry(4);

    let desc = io_desc(UBLK_IO_OP_FLUSH, 0, 8, 0, 0);
    let result = dispatch_ublk_io_descriptor(&mut d, desc, geo, None);
    assert!(result.is_err(), "flush with range should fail");
    match result.unwrap_err() {
        UblkIoDispatchError::RangeOnFlush => {}
        e => panic!("expected RangeOnFlush, got {e:?}"),
    }
}
