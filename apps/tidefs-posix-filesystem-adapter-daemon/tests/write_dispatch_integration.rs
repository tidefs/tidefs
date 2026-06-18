// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Write-dispatch integration tests for the FUSE daemon.
//!
//! Validates the FUSE write dispatch path within a single mount session:
//! data written through the mount is immediately visible via the same file
//! handle. Reopen visibility depends on fsync durability (fuse-fsync-durability
//! milestone, not yet reached).
//!
//! Run with:
//!   cargo test -p tidefs-posix-filesystem-adapter-daemon -- write_dispatch_integration

mod fuse_mount_harness;

use fuse_mount_harness::{create_read_write, patterned_bytes, MountedVfs};
use std::io::{Read, Seek, SeekFrom, Write};
use std::{fs, thread};

macro_rules! require_fuse {
    () => {
        if !fuse_mount_harness::fuse_available() {
            eprintln!("SKIP: /dev/fuse not available");
            return;
        }
    };
}

fn assert_all_zero(bytes: &[u8]) {
    assert!(bytes.iter().all(|b| *b == 0), "expected all-zero bytes");
}

fn pwrite(file: &mut fs::File, buf: &[u8], offset: u64) {
    file.seek(SeekFrom::Start(offset))
        .expect("seek to write offset");
    file.write_all(buf).expect("write at offset");
}

fn pread(file: &mut fs::File, offset: u64, len: usize) -> Vec<u8> {
    file.seek(SeekFrom::Start(offset))
        .expect("seek to read offset");
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).expect("read at offset");
    buf
}

// ===========================================================================
// Group 1: Basic write-and-read-back (same handle)
// ===========================================================================

#[test]
fn write_read_roundtrip_single_block() {
    require_fuse!();
    let mnt = MountedVfs::new("wd-single", &["single.bin"], &[]);
    let path = mnt.path("/single.bin");
    let payload = patterned_bytes(4 * 1024);
    let mut file = create_read_write(&path);
    file.write_all(&payload).expect("write 4 KiB");
    file.flush().expect("flush");
    assert_eq!(pread(&mut file, 0, payload.len()), payload);
}

#[test]
fn write_read_roundtrip_multi_block() {
    require_fuse!();
    let mnt = MountedVfs::new("wd-multi", &["multi.bin"], &[]);
    let path = mnt.path("/multi.bin");
    let payload = patterned_bytes(64 * 1024);
    let mut file = create_read_write(&path);
    file.write_all(&payload).expect("write 64 KiB");
    file.flush().expect("flush");
    assert_eq!(pread(&mut file, 0, payload.len()), payload);
}

#[test]
fn write_read_roundtrip_unaligned() {
    require_fuse!();
    let mnt = MountedVfs::new("wd-unaligned", &["unaligned.bin"], &[]);
    let path = mnt.path("/unaligned.bin");
    let payload = patterned_bytes(4097);
    let mut file = create_read_write(&path);
    file.write_all(&payload).expect("write 4097 bytes");
    file.flush().expect("flush");
    assert_eq!(file.metadata().expect("metadata").len(), 4097);
    assert_eq!(pread(&mut file, 0, 4097), payload);
    assert_eq!(pread(&mut file, 0, 1), &payload[..1]);
    assert_eq!(pread(&mut file, 2048, 1), &payload[2048..2049]);
    assert_eq!(pread(&mut file, 4096, 1), &payload[4096..]);
}

#[test]
fn write_read_zero_length_noop() {
    require_fuse!();
    let mnt = MountedVfs::new("wd-zero", &["zero.bin"], &[]);
    let path = mnt.path("/zero.bin");
    let mut file = create_read_write(&path);
    file.write_all(&[]).expect("write zero-length");
    file.flush().expect("flush");
    assert_eq!(file.metadata().expect("metadata").len(), 0);
    let mut buf = Vec::new();
    file.seek(SeekFrom::Start(0)).expect("seek to 0");
    file.read_to_end(&mut buf).expect("read to end");
    assert!(buf.is_empty());
}

#[test]
fn write_past_eof_creates_sparse_hole() {
    require_fuse!();
    let mnt = MountedVfs::new("wd-sparse", &["hole.bin"], &[]);
    let path = mnt.path("/hole.bin");
    let tail = b"tail data after hole";
    let hole_off = 32 * 1024_u64;
    let mut file = create_read_write(&path);
    pwrite(&mut file, tail, hole_off);
    file.flush().expect("flush sparse write");
    assert_eq!(
        file.metadata().expect("metadata").len(),
        hole_off + tail.len() as u64
    );
    assert_all_zero(&pread(&mut file, 0, hole_off as usize));
    assert_eq!(pread(&mut file, hole_off, tail.len()), tail);
}

// ===========================================================================
// Group 2: Sequential writes (buffer coalescing)
// ===========================================================================

#[test]
fn sequential_small_writes_result_visible() {
    require_fuse!();
    let mnt = MountedVfs::new("wd-coalesce", &["coalesce.bin"], &[]);
    let path = mnt.path("/coalesce.bin");
    let mut file = create_read_write(&path);
    for i in 0..8_u64 {
        let chunk: Vec<u8> = (0..1024)
            .map(|j| ((i * 1024 + j) as u8).wrapping_mul(7))
            .collect();
        file.write_all(&chunk).expect("write chunk");
    }
    file.flush().expect("flush coalesced writes");
    assert_eq!(file.metadata().expect("metadata").len(), 8 * 1024);
    let readback = pread(&mut file, 0, 8 * 1024);
    let expected: Vec<u8> = (0..8192_u64).map(|j| (j as u8).wrapping_mul(7)).collect();
    assert_eq!(readback, expected, "sequential write content mismatch");
}

#[test]
fn interleaved_writes_preserve_regions() {
    require_fuse!();
    let mnt = MountedVfs::new("wd-interleave", &["interleave.bin"], &[]);
    let path = mnt.path("/interleave.bin");
    let mut file = create_read_write(&path);
    file.seek(SeekFrom::Start(0)).expect("seek");
    file.write_all(&[b'A'; 512]).expect("write A");
    file.seek(SeekFrom::Start(2048)).expect("seek");
    file.write_all(&[b'B'; 512]).expect("write B");
    file.seek(SeekFrom::Start(512)).expect("seek");
    file.write_all(&[b'C'; 512]).expect("write C");
    file.flush().expect("flush interleaved");
    assert!(pread(&mut file, 0, 512).iter().all(|b| *b == b'A'));
    assert!(pread(&mut file, 512, 512).iter().all(|b| *b == b'C'));
    assert_all_zero(&pread(&mut file, 1024, 1024));
    assert!(pread(&mut file, 2048, 512).iter().all(|b| *b == b'B'));
}

// ===========================================================================
// Group 3: Flush threshold behaviour
// ===========================================================================

#[test]
fn write_below_block_size_visible_after_flush() {
    require_fuse!();
    let mnt = MountedVfs::new("wd-below", &["below.bin"], &[]);
    let path = mnt.path("/below.bin");
    let payload = patterned_bytes(512);
    let mut file = create_read_write(&path);
    file.write_all(&payload).expect("write");
    file.flush().expect("flush");
    assert_eq!(pread(&mut file, 0, 512), payload);
}

#[test]
fn write_exactly_one_block_flushes_correctly() {
    require_fuse!();
    let mnt = MountedVfs::new("wd-oneblock", &["oneblock.bin"], &[]);
    let path = mnt.path("/oneblock.bin");
    let payload = patterned_bytes(4 * 1024);
    let mut file = create_read_write(&path);
    file.write_all(&payload).expect("write one block");
    file.flush().expect("flush");
    assert_eq!(file.metadata().expect("metadata").len(), 4096);
    assert_eq!(pread(&mut file, 0, 4096), payload);
}

#[test]
fn write_multiple_blocks_in_single_call() {
    require_fuse!();
    let mnt = MountedVfs::new("wd-multiflush", &["multiflush.bin"], &[]);
    let path = mnt.path("/multiflush.bin");
    let payload = patterned_bytes(256 * 1024);
    let mut file = create_read_write(&path);
    file.write_all(&payload).expect("write 256 KiB");
    file.flush().expect("flush");
    assert_eq!(pread(&mut file, 0, 4096), &payload[..4096]);
    let start: u64 = 252 * 1024;
    assert_eq!(
        pread(&mut file, start, 4096),
        &payload[start as usize..start as usize + 4096]
    );
    assert_eq!(file.metadata().expect("metadata").len(), 256 * 1024);
}

// ===========================================================================
// Group 4: Concurrent write isolation
// ===========================================================================

#[test]
fn concurrent_non_overlapping_writes_preserve_regions() {
    require_fuse!();
    let mnt = MountedVfs::new("wd-concurrent", &["concurrent.bin"], &[]);
    let path = mnt.path("/concurrent.bin");
    let mut file = create_read_write(&path);
    file.write_all(&vec![0u8; 24 * 1024]).expect("pre-size");
    file.flush().expect("flush pre-size");

    let p1 = path.clone();
    let region_a: Vec<u8> = (0..8 * 1024).map(|i| (i as u8).wrapping_mul(7)).collect();
    let ra = region_a.clone();
    let t1 = thread::spawn(move || {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .open(&p1)
            .expect("open t1");
        f.seek(SeekFrom::Start(0)).expect("seek t1");
        f.write_all(&ra).expect("write A");
        f.flush().expect("flush A");
    });
    let p2 = path.clone();
    let region_c: Vec<u8> = (0..8 * 1024).map(|i| (i as u8).wrapping_mul(13)).collect();
    let rc = region_c.clone();
    let t2 = thread::spawn(move || {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .open(&p2)
            .expect("open t2");
        f.seek(SeekFrom::Start(16 * 1024)).expect("seek t2");
        f.write_all(&rc).expect("write C");
        f.flush().expect("flush C");
    });
    t1.join().expect("thread 1");
    t2.join().expect("thread 2");

    let readback = pread(&mut file, 0, 24 * 1024);
    assert_eq!(readback[0..8 * 1024], region_a[..], "region A mismatch");
    assert_all_zero(&readback[8 * 1024..16 * 1024]);
    assert_eq!(
        readback[16 * 1024..24 * 1024],
        region_c[..],
        "region C mismatch"
    );
}

// ===========================================================================
// Group 5: Overwrite within session
// ===========================================================================

#[test]
fn overwrite_replaces_existing_data_in_session() {
    require_fuse!();
    let mnt = MountedVfs::new("wd-overwrite", &["overwrite.bin"], &[]);
    let path = mnt.path("/overwrite.bin");
    let block_a = patterned_bytes(4 * 1024);
    let block_b = patterned_bytes(8 * 1024);
    let mut file = create_read_write(&path);
    pwrite(&mut file, &block_a, 0);
    file.flush().expect("flush A");
    pwrite(&mut file, &block_b, 0);
    file.flush().expect("flush B");
    let readback = pread(&mut file, 0, 8 * 1024);
    assert_eq!(readback, block_b, "overwrite should replace block A with B");
    assert_eq!(file.metadata().expect("metadata").len(), 8 * 1024);
}

#[test]
fn partial_overwrite_preserves_trailing_data() {
    require_fuse!();
    let mnt = MountedVfs::new("wd-partial-ow", &["partial.bin"], &[]);
    let path = mnt.path("/partial.bin");
    let mut file = create_read_write(&path);
    file.write_all(&[b'A'; 16]).expect("write initial");
    file.flush().expect("flush initial");
    file.seek(SeekFrom::Start(4)).expect("seek to 4");
    file.write_all(&[b'B'; 8]).expect("overwrite middle");
    file.flush().expect("flush partial overwrite");
    let readback = pread(&mut file, 0, 16);
    let expected: Vec<u8> = [b'A'; 4]
        .iter()
        .chain([b'B'; 8].iter())
        .chain([b'A'; 4].iter())
        .copied()
        .collect();
    assert_eq!(readback, expected);
}

// ===========================================================================
// Group 6: Append pattern
// ===========================================================================

#[test]
fn append_chunks_accumulate_in_order() {
    require_fuse!();
    let mnt = MountedVfs::new("wd-append", &["append.bin"], &[]);
    let path = mnt.path("/append.bin");
    {
        let _file = create_read_write(&path);
    }
    let chunks: Vec<Vec<u8>> = (0..8)
        .map(|i| {
            let base = (i * 17) as u8;
            (0..1024).map(|j| base.wrapping_add(j as u8)).collect()
        })
        .collect();
    let mut file = fs::OpenOptions::new()
        .read(true)
        .append(true)
        .open(&path)
        .expect("open for read+append");
    for chunk in &chunks {
        file.write_all(chunk).expect("append chunk");
    }
    file.flush().expect("flush appended");
    file.seek(SeekFrom::Start(0)).expect("seek to 0");
    let mut readback = Vec::new();
    file.read_to_end(&mut readback).expect("read appended");
    let expected: Vec<u8> = chunks.iter().flatten().copied().collect();
    assert_eq!(readback.len(), expected.len());
    assert_eq!(readback, expected, "appended content mismatch");
}

#[test]
fn append_then_overwrite_middle_leaves_append_intact() {
    require_fuse!();
    let mnt = MountedVfs::new("wd-append-ow", &["append-ow.bin"], &[]);
    let path = mnt.path("/append-ow.bin");
    // Single read+write handle: write initial data, overwrite middle, verify.
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .expect("open read+write");
    let full = patterned_bytes(4096);
    file.write_all(&full).expect("write 4096 bytes");
    file.flush().expect("flush write");
    assert_eq!(file.metadata().expect("metadata").len(), 4096);
    file.seek(SeekFrom::Start(512)).expect("seek middle");
    file.write_all(&[b'X'; 512]).expect("overwrite middle");
    file.flush().expect("flush overwrite");
    let readback = pread(&mut file, 0, 4096);
    assert_eq!(
        readback[0..512],
        full[0..512],
        "prefix intact after overwrite"
    );
    assert!(
        readback[512..1024].iter().all(|b| *b == b'X'),
        "overwritten range should be X"
    );
    assert_eq!(
        readback[1024..4096],
        full[1024..4096],
        "suffix intact after overwrite"
    );
}

// ===========================================================================
// Close-then-reopen preserves write (same-handle verification)
// ===========================================================================

#[test]
fn write_close_reopen_read_preserves_bytes() {
    require_fuse!();
    let mnt = MountedVfs::new("wd-reopen", &["reopen.bin"], &[]);
    let path = mnt.path("/reopen.bin");
    let payload = patterned_bytes(16384);
    let mut file = create_read_write(&path);
    file.write_all(&payload).expect("write before close");
    file.flush().expect("flush before close");
    let readback = pread(&mut file, 0, payload.len());
    assert_eq!(readback, payload, "same-handle readback mismatch");
    assert_eq!(readback.len(), 16384);
}
